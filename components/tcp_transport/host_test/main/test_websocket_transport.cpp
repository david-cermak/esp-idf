/*
 * SPDX-FileCopyrightText: 2024-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <memory>
#include <string>
#include <type_traits>
#include <array>
#include <vector>
#include <netinet/in.h>
#include <netdb.h>
#include "fmt/core.h"
#include "fmt/ranges.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_all.hpp>
#include "esp_transport.h"
#include "esp_transport_tcp.h"
#include "esp_transport_ws.h"

#define WS_BUFFER_SIZE CONFIG_WS_BUFFER_SIZE

extern "C" {
#include "Mockmock_transport.h"
#include "Mocknetdb.h"
#include "Mockesp_timer.h"
#include "Mockesp_tls_crypto.h"

    int lwip_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen) {
        return 1;
    }

    ssize_t lwip_recv(int s, void *mem, size_t len, int flags) {
        return WS_BUFFER_SIZE;
    }

    ssize_t lwip_send(int s, const void *data, size_t size, int flags) {
        return size;
    }

    // Provide actual implementations for crypto functions instead of using mocks
    int esp_crypto_sha1(const unsigned char *input, size_t ilen, unsigned char output[20]) {
        // Pre-calculated SHA1 of "x3JJHMbDL1EzLkh9GBhXDw==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        unsigned char expected_sha1[20] = {
            0x1D, 0x29, 0xAB, 0x73, 0x4B, 0x0C, 0x95, 0x85, 0x24, 0x00,
            0x69, 0xA6, 0xE4, 0xE3, 0xE9, 0x1B, 0x61, 0xDA, 0x19, 0x69
        };
        if (output) {
            memcpy(output, expected_sha1, 20);
        }
        return 0;
    }

    int esp_crypto_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
                                  const unsigned char *src, size_t slen) {
        // This function is called twice:
        // 1. To encode random 16 bytes -> client key "x3JJHMbDL1EzLkh9GBhXDw=="
        // 2. To encode SHA1 hash (20 bytes) -> expected accept key "HSmrc0sMlYUkAGmm5OPpG2HaGWk="

        if (slen == 16) {
            // First call: encoding random bytes to client key
            const char* client_key = "x3JJHMbDL1EzLkh9GBhXDw==";
            size_t key_len = strlen(client_key);
            if (dst && dlen > key_len) {
                memcpy(dst, client_key, key_len + 1);
                if (olen) {
                    *olen = key_len;
                }
            }
        } else if (slen == 20) {
            // Second call: encoding SHA1 hash to expected accept key
            const char* accept_key = "HSmrc0sMlYUkAGmm5OPpG2HaGWk=";
            size_t key_len = strlen(accept_key);
            if (dst && dlen > key_len) {
                memcpy(dst, accept_key, key_len + 1);
                if (olen) {
                    *olen = key_len;
                }
            }
        }
        return 0;
    }
}

using unique_transport = std::unique_ptr<std::remove_pointer_t<esp_transport_handle_t>, decltype(&esp_transport_destroy)>;

namespace {

std::string make_request() {
    const std::string sec_websocket_key = "x3JJHMbDL1EzLkh9GBhXDw=="; // Use a fixed key for testing
    std::string request;

    request.append("GET / HTTP/1.1\r\n");
    request.append("Connection: Upgrade\r\n");
    request.append("Host: localhost:8080\r\n");
    request.append("User-Agent: ESP32 Websocket Client\r\n");
    request.append("Upgrade: websocket\r\n");
    request.append("Sec-WebSocket-Version: 13\r\n");
    request.append("Sec-WebSocket-Key: ").append(sec_websocket_key).append("\r\n");
    request.append("\r\n");

    return request;
}

std::string make_response() {
    char response[WS_BUFFER_SIZE];
    // Expected server key calculated from client key "x3JJHMbDL1EzLkh9GBhXDw==" + magic string
    // SHA1("x3JJHMbDL1EzLkh9GBhXDw==258EAFA5-E914-47DA-95CA-C5AB0DC85B11") base64 encoded
    const char* expected_accept_key = "HSmrc0sMlYUkAGmm5OPpG2HaGWk=";
    int response_length = snprintf(response, WS_BUFFER_SIZE,
                                   "HTTP/1.1 101 Switching Protocols\r\n"
                                   "Upgrade: websocket\r\n"
                                   "Connection: Upgrade\r\n"
                                   "Sec-WebSocket-Accept: %s\r\n"
                                   "\r\n", expected_accept_key);
    // WebSocket frame header
    unsigned char ws_frame_header[] = {0x81, 0x04}; // First byte: FIN, RSV1-3, and opcode; Second byte: payload length
    unsigned char ws_payload[] = {'T', 'e', 's', 't'}; // Example payload

    // Append the WebSocket frame header to the HTTP response
    std::memcpy(response + response_length, ws_frame_header, sizeof(ws_frame_header));
    response_length += sizeof(ws_frame_header);

    // Append the payload to the HTTP response
    std::memcpy(response + response_length, ws_payload, sizeof(ws_payload));
    response_length += sizeof(ws_payload);
    return std::string(response, response_length);
}

// Callback function for mock_write
int mock_write_callback(esp_transport_handle_t transport, const char *request_sent, int len, int timeout_ms, int num_call) {
    // Assertions to validate the parameters
    assert(transport != nullptr); // Ensure the transport handle is not null
    assert(request_sent != nullptr); // Ensure the request_sent pointer is not null
    assert(len > 0); // Ensure the length of the request is greater than zero
    assert(timeout_ms > 0); // Ensure the timeout is greater than zero
    assert(num_call >= 0); // Ensure the number of calls is non-negative

    // Create a string from the request_sent data
    std::string sent_request(request_sent, len);

    // Generate the expected request
    std::string expected_request = make_request();

    return len;
}

// Callbacks for mocked poll_reed and read functions
int mock_poll_read_callback(esp_transport_handle_t t, int timeout_ms, int num_call)
{
    if (num_call) {
        return 0;
    }
    return 1;
}

int mock_valid_read_callback(esp_transport_handle_t transport, char *buffer, int len, int timeout_ms, int num_call)
{
    std::string websocket_response = make_response();
    std::memcpy(buffer, websocket_response.data(), websocket_response.size());
    return websocket_response.size();
}

// Callback function for mock_read
int mock_valid_read_fragmented_callback(esp_transport_handle_t t, char *buffer, int len, int timeout_ms, int num_call)
{
    static int offset = 0;
    static bool reset_on_next_call = false;

    // Reset offset when starting a new read sequence
    if (reset_on_next_call && buffer != nullptr) {
        offset = 0;
        reset_on_next_call = false;
    }

    std::string websocket_response = make_response();
    if (buffer == nullptr) {
        bool has_more = offset < websocket_response.size();
        if (!has_more) {
            reset_on_next_call = true;  // Prepare for next test
        }
        return has_more ? 1 : 0;
    }
    int read_size = 1;
    if (offset >= websocket_response.size()) {
        reset_on_next_call = true;
        return 0;
    }
    std::memcpy(buffer, websocket_response.data() + offset, read_size);
    offset += read_size;
    return read_size;
}

int mock_valid_poll_read_fragmented_callback(esp_transport_handle_t t, int timeout_ms, int num_call)
{
    return mock_valid_read_fragmented_callback(t, nullptr, 0, 0, 0);
}

std::string make_handshake_response(const char *status_line = "HTTP/1.1 101 Switching Protocols",
                                    const char *accept_key = "HSmrc0sMlYUkAGmm5OPpG2HaGWk=",
                                    const char *extra_headers = "")
{
    return fmt::format("{}\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: {}\r\n"
                       "{}"
                       "\r\n",
                       status_line, accept_key, extra_headers);
}

std::string make_ws_frame(uint8_t first_byte, const std::string &payload, bool masked = false)
{
    std::string frame;
    frame.push_back(static_cast<char>(first_byte));
    const size_t len = payload.size();
    uint8_t mask_bit = masked ? 0x80 : 0x00;
    if (len <= 125) {
        frame.push_back(static_cast<char>(mask_bit | len));
    } else if (len < 65536) {
        frame.push_back(static_cast<char>(mask_bit | 126));
        frame.push_back(static_cast<char>((len >> 8) & 0xFF));
        frame.push_back(static_cast<char>(len & 0xFF));
    } else {
        frame.push_back(static_cast<char>(mask_bit | 127));
        for (int i = 7; i >= 0; --i) {
            frame.push_back(static_cast<char>((len >> (8 * i)) & 0xFF));
        }
    }
    std::array<char, 4> mask_key = {0x11, 0x22, 0x33, 0x44};
    if (masked) {
        frame.append(mask_key.data(), mask_key.size());
        for (size_t i = 0; i < payload.size(); ++i) {
            frame.push_back(static_cast<char>(payload[i] ^ mask_key[i % 4]));
        }
    } else {
        frame.append(payload);
    }
    return frame;
}

void install_parent_ignored_mocks()
{
    mock_destroy_IgnoreAndReturn(ESP_OK);
    mock_close_IgnoreAndReturn(0);
    mock_poll_write_IgnoreAndReturn(1);
}

struct CapturedWrites {
    std::vector<std::string> chunks;
};

// Capture used by post-connect write stubs.
CapturedWrites g_writes;

int capture_all_writes(esp_transport_handle_t, const char *data, int len, int timeout_ms, int)
{
    REQUIRE(data != nullptr);
    REQUIRE(len > 0);
    REQUIRE(timeout_ms > 0);
    g_writes.chunks.emplace_back(data, data + len);
    return len;
}

struct ScriptedReads {
    std::vector<std::string> chunks;
    size_t index = 0;
    size_t offset = 0;
};

ScriptedReads g_reads;

int scripted_read_callback(esp_transport_handle_t, char *buffer, int len, int, int)
{
    if (g_reads.index >= g_reads.chunks.size()) {
        return 0;
    }
    const auto &chunk = g_reads.chunks[g_reads.index];
    const size_t remaining = chunk.size() - g_reads.offset;
    if (remaining == 0) {
        g_reads.index++;
        g_reads.offset = 0;
        if (g_reads.index >= g_reads.chunks.size()) {
            return 0;
        }
        return scripted_read_callback(nullptr, buffer, len, 0, 0);
    }
    const int to_copy = static_cast<int>(std::min(remaining, static_cast<size_t>(len)));
    std::memcpy(buffer, chunk.data() + g_reads.offset, to_copy);
    g_reads.offset += static_cast<size_t>(to_copy);
    if (g_reads.offset >= chunk.size()) {
        g_reads.index++;
        g_reads.offset = 0;
    }
    return to_copy;
}

int always_ready_poll_read(esp_transport_handle_t, int, int)
{
    return 1;
}

}

TEST_CASE("WebSocket Transport Connection", "[success]")
{
    constexpr static auto timeout = 50;
    constexpr static auto port = 8080;
    constexpr static auto host = "localhost";
    install_parent_ignored_mocks();
    // Initialize the parent handle
    unique_transport parent_handle{esp_transport_init(), esp_transport_destroy};
    REQUIRE(parent_handle);

    // Set mock functions for parent handle
    esp_transport_set_func(parent_handle.get(), mock_connect, mock_read, mock_write, mock_close, mock_poll_read, mock_poll_write, mock_destroy);

    unique_transport websocket_transport{esp_transport_ws_init(parent_handle.get()), esp_transport_destroy};
    REQUIRE(websocket_transport);

    // Allocate buffer for response header
    constexpr size_t response_header_len = 1024;
    std::vector<char> response_header_buffer(response_header_len);
    esp_transport_ws_config_t ws_config = {
        .ws_path = "/",
        .sub_protocol = nullptr,
        .user_agent = nullptr,
        .headers = nullptr,
        .header_hook = NULL,
        .header_user_context = NULL,
        .auth = nullptr,
        .response_headers = response_header_buffer.data(),
        .response_headers_len = response_header_len,
        .propagate_control_frames = false,
    };
    REQUIRE(esp_transport_ws_set_config(websocket_transport.get(), &ws_config) == ESP_OK);

    fmt::print("Attempting to connect to WebSocket\n");

    // Set the callback function for mock_write
    mock_write_Stub(mock_write_callback);
    mock_connect_ExpectAndReturn(parent_handle.get(), host, port, timeout, ESP_OK);

    SECTION("Happy flow") {
        // Set the callback function for mock_read
        mock_read_Stub(mock_valid_read_callback);
        mock_poll_read_Stub(mock_poll_read_callback);

        REQUIRE(esp_transport_connect(websocket_transport.get(), host, port, timeout) == 0);

        // Verify the response header was stored correctly
        std::string expected_header = make_response();
        REQUIRE(std::string(response_header_buffer.data()) == expected_header);

        char buffer[WS_BUFFER_SIZE];
        int read_len = 0;
        read_len = esp_transport_read(websocket_transport.get(), &buffer[read_len], WS_BUFFER_SIZE - read_len, timeout);

        fmt::print("Read result: {}\n", read_len);
        REQUIRE(read_len > 0);  // Ensure data is read

        std::string response(buffer, read_len);
        REQUIRE(response == "Test");
    }

    SECTION("Happy flow with fragmented reads byte by byte") {
        // Set the callback function for mock_read
        mock_read_Stub(mock_valid_read_fragmented_callback);
        mock_poll_read_Stub(mock_valid_poll_read_fragmented_callback);

        REQUIRE(esp_transport_connect(websocket_transport.get(), host, port, timeout) == 0);

        // Verify the response header was stored correctly
        std::string expected_header = "HTTP/1.1 101 Switching Protocols\r\n"
                                      "Upgrade: websocket\r\n"
                                      "Connection: Upgrade\r\n"
                                      "Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=\r\n"
                                      "\r\n";
        REQUIRE(std::string(response_header_buffer.data()) == expected_header);
        char buffer[WS_BUFFER_SIZE];
        int read_len = 0;
        int partial_read;
        while ((partial_read = esp_transport_read(websocket_transport.get(), &buffer[read_len], WS_BUFFER_SIZE - read_len, timeout)) > 0 ) {
            read_len+= partial_read;
        }
        fmt::print("Read result: {}\n", read_len);
        REQUIRE(read_len > 0);  // Ensure data is read

        std::string response(buffer, read_len);
        REQUIRE(response == "Test");
    }

    SECTION("Happy flow with smaller response header") {
        // Set the response header length to a size that's smaller than the full response
        // but still large enough to find the header delimiter
        ws_config.response_headers_len = 130;  // Large enough for the header but smaller than full response
        REQUIRE(esp_transport_ws_set_config(websocket_transport.get(), &ws_config) == ESP_OK);

        // Set the callback function for mock_read
        mock_read_Stub(mock_valid_read_callback);
        mock_poll_read_Stub(mock_poll_read_callback);

        // Create a marker to check that the value after the end of the response header buffer is not overwritten
        std::string expected_full_response = make_response();
        char marker = 0x42;  // Use a distinctive marker value
        response_header_buffer[ws_config.response_headers_len] = marker;

        REQUIRE(esp_transport_connect(websocket_transport.get(), host, port, timeout) == 0);

        // Verify the response header was stored correctly and truncated at the header boundary
        std::string expected_header = "HTTP/1.1 101 Switching Protocols\r\n"
                                      "Upgrade: websocket\r\n"
                                      "Connection: Upgrade\r\n"
                                      "Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=\r\n"
                                      "\r\n";

        REQUIRE(std::string(response_header_buffer.data()) == expected_header);
        // Verify the marker after the buffer wasn't overwritten
        REQUIRE(response_header_buffer[ws_config.response_headers_len] == marker);
    }

    SECTION("Poll read with buffered data") {
        // Set the callback function for mock_read
        mock_read_Stub(mock_valid_read_callback);

        static int parent_poll_calls = 0;
        parent_poll_calls = 0;

        // Verify poll_read is not called when buffer has data
        mock_poll_read_Stub([](esp_transport_handle_t t, int timeout_ms, int num_call){
            parent_poll_calls++;
            return 0;
        });

        REQUIRE(esp_transport_connect(websocket_transport.get(), host, port, timeout) == 0);

        // buffer should contain "Test" (4 bytes)
        // ws_poll_read should return 1 because buffer is not empty
        REQUIRE(esp_transport_poll_read(websocket_transport.get(), timeout) == 1);
        REQUIRE(parent_poll_calls == 0);

        // Read the data to empty the buffer
        char buffer[10];
        int read_len = esp_transport_read(websocket_transport.get(), buffer, sizeof(buffer), timeout);
        REQUIRE(read_len == 4);

        // Now buffer is empty, ws_poll_read should call parent poll
        esp_transport_poll_read(websocket_transport.get(), timeout);
        REQUIRE(parent_poll_calls == 1);
    }
}

TEST_CASE("WebSocket Transport Connection", "[failure]")
{
    constexpr static auto timeout = 50;
    constexpr static auto port = 8080;
    constexpr static auto host = "localhost";
    install_parent_ignored_mocks();
    // Initialize the parent handle
    unique_transport parent_handle{esp_transport_init(), esp_transport_destroy};
    REQUIRE(parent_handle);

    // Set mock functions for parent handle
    esp_transport_set_func(parent_handle.get(), mock_connect, mock_read, mock_write, mock_close, mock_poll_read, mock_poll_write, mock_destroy);

    unique_transport websocket_transport{esp_transport_ws_init(parent_handle.get()), esp_transport_destroy};
    REQUIRE(websocket_transport);

    // Allocate buffer for response header
    constexpr size_t response_header_len = 1024;
    std::vector<char> response_header_buffer(response_header_len);
    esp_transport_ws_config_t ws_config = {
        .ws_path = "/",
        .sub_protocol = nullptr,
        .user_agent = nullptr,
        .headers = nullptr,
        .header_hook = NULL,
        .header_user_context = NULL,
        .auth = nullptr,
        .response_headers = response_header_buffer.data(),
        .response_headers_len = response_header_len,
        .propagate_control_frames = false,
    };
    REQUIRE(esp_transport_ws_set_config(websocket_transport.get(), &ws_config) == ESP_OK);

    fmt::print("Attempting to connect to WebSocket\n");

    // Set the callback function for mock_write
    mock_write_Stub(mock_write_callback);
    mock_connect_ExpectAndReturn(parent_handle.get(), host, port, timeout, ESP_OK);

    SECTION("ws connect fails (0 len response)") {
        // Set the callback function for mock_read
        mock_read_Stub([](esp_transport_handle_t h, char *buf, int len, int tout, int n) {
            return 0;
        });
        mock_poll_read_Stub(mock_poll_read_callback);

        // check that the connect() function fails
        REQUIRE(esp_transport_connect(websocket_transport.get(), host, port, timeout) != 0);

        // Verify the response header is empty
        REQUIRE(std::string(response_header_buffer.data()) == "");
    }

    SECTION("ws connect fails (invalid response)") {
        // Set the callback function for mock_read
        mock_read_Stub([](esp_transport_handle_t h, char *buf, int len, int tout, int n) {
            int resp_len = len / 2;
            std::memset(buf, '?', resp_len);
            return resp_len;
        });
        mock_poll_read_Stub(mock_poll_read_callback);

        // check that the connect() function fails
        REQUIRE(esp_transport_connect(websocket_transport.get(), host, port, timeout) != 0);

        // Verify the response header is empty
        REQUIRE(std::string(response_header_buffer.data()) == "");
    }

    SECTION("ws connect fails (big response)") {
        // Set the callback function for mock_read
        mock_read_Stub([](esp_transport_handle_t h, char *buf, int len, int tout, int n) {
            return WS_BUFFER_SIZE;
        });
        mock_poll_read_Stub(mock_poll_read_callback);

        // check that the connect() function fails
        REQUIRE(esp_transport_connect(websocket_transport.get(), host, port, timeout) != 0);

        // Verify the response header is empty
        REQUIRE(std::string(response_header_buffer.data()) == "");
    }

    SECTION("ws connect fails (buffer full, no delimiter)") {
        // Mock read to fill buffer with non-delimiter data
        mock_read_Stub([](esp_transport_handle_t h, char *buf, int len, int tout, int n) {
             if (len > 0) {
                 memset(buf, 'A', len);
             }
             return len;
        });
        mock_poll_read_Stub(mock_poll_read_callback);

        REQUIRE(esp_transport_connect(websocket_transport.get(), host, port, timeout) == -1);
    }

    SECTION("ws connect succeeds (response header buffer too small for handshake verification)") {
        // Set a very small response header buffer
        ws_config.response_headers_len = 50;
        REQUIRE(esp_transport_ws_set_config(websocket_transport.get(), &ws_config) == ESP_OK);

        // Set the callback function for mock_read
        mock_read_Stub(mock_valid_read_callback);
        mock_poll_read_Stub(mock_poll_read_callback);

        // Connect should now succeed even with small user buffer
        REQUIRE(esp_transport_connect(websocket_transport.get(), host, port, timeout) == 0);
    }
}

TEST_CASE("WebSocket config, write, control frames and getters", "[ws][coverage]")
{
    constexpr auto timeout = 50;
    constexpr auto port = 8080;
    constexpr auto host = "localhost";
    install_parent_ignored_mocks();

    unique_transport parent_handle{esp_transport_init(), esp_transport_destroy};
    REQUIRE(parent_handle);
    esp_transport_set_func(parent_handle.get(), mock_connect, mock_read, mock_write, mock_close,
                           mock_poll_read, mock_poll_write, mock_destroy);

    unique_transport ws{esp_transport_ws_init(parent_handle.get()), esp_transport_destroy};
    REQUIRE(ws);

    auto connect_with_response = [&](const std::string &response) {
        g_reads = {};
        g_reads.chunks.push_back(response);
        g_writes = {};
        mock_write_Stub(capture_all_writes);
        mock_read_Stub(scripted_read_callback);
        mock_poll_read_Stub(always_ready_poll_read);
        mock_connect_ExpectAndReturn(parent_handle.get(), host, port, timeout, ESP_OK);
        REQUIRE(esp_transport_connect(ws.get(), host, port, timeout) == 0);
        REQUIRE_FALSE(g_writes.chunks.empty());
    };

    SECTION("config headers appear in upgrade request") {
        std::vector<std::string> hook_lines;
        auto hook = [](void *ctx, const char *line, int line_len) {
            auto *out = static_cast<std::vector<std::string> *>(ctx);
            out->emplace_back(line, line + line_len);
        };

        esp_transport_ws_config_t cfg = {};
        cfg.ws_path = "/chat";
        cfg.sub_protocol = "mqtt";
        cfg.user_agent = "host-test-agent";
        cfg.headers = "X-Custom: 1\r\n";
        cfg.auth = "Bearer token";
        cfg.header_hook = hook;
        cfg.header_user_context = &hook_lines;
        REQUIRE(esp_transport_ws_set_config(ws.get(), &cfg) == ESP_OK);

        // Also exercise public setters (strdup / replace paths)
        esp_transport_ws_set_path(ws.get(), "/chat2");
        REQUIRE(esp_transport_ws_set_subprotocol(ws.get(), "mqtt") == ESP_OK);
        REQUIRE(esp_transport_ws_set_user_agent(ws.get(), "host-test-agent") == ESP_OK);
        REQUIRE(esp_transport_ws_set_headers(ws.get(), "X-Custom: 1\r\n") == ESP_OK);
        REQUIRE(esp_transport_ws_set_auth(ws.get(), "Bearer token") == ESP_OK);
        REQUIRE(esp_transport_ws_set_header_hook(ws.get(), hook, &hook_lines) == ESP_OK);

        connect_with_response(make_handshake_response());
        const std::string &req = g_writes.chunks.front();
        REQUIRE_THAT(req, Catch::Matchers::ContainsSubstring("GET /chat2 HTTP/1.1"));
        REQUIRE_THAT(req, Catch::Matchers::ContainsSubstring("Sec-WebSocket-Protocol: mqtt"));
        REQUIRE_THAT(req, Catch::Matchers::ContainsSubstring("User-Agent: host-test-agent"));
        REQUIRE_THAT(req, Catch::Matchers::ContainsSubstring("Authorization: Bearer token"));
        REQUIRE_THAT(req, Catch::Matchers::ContainsSubstring("X-Custom: 1"));
        REQUIRE(esp_transport_ws_get_upgrade_request_status(ws.get()) == 101);
        REQUIRE_FALSE(hook_lines.empty());
    }

    SECTION("binary write, ping write, send_raw and poll_write/close") {
        connect_with_response(make_handshake_response());
        g_writes = {};

        std::string payload(200, 'A'); // exercises 16-bit length branch
        REQUIRE(esp_transport_write(ws.get(), payload.data(), static_cast<int>(payload.size()), timeout) ==
                static_cast<int>(payload.size()));
        REQUIRE(g_writes.chunks.size() >= 2);
        REQUIRE((static_cast<uint8_t>(g_writes.chunks[0][0]) & 0x0F) == 0x02); // BINARY
        REQUIRE((static_cast<uint8_t>(g_writes.chunks[0][1]) & 0x7F) == 126);

        g_writes = {};
        REQUIRE(esp_transport_write(ws.get(), "", 0, timeout) == 0); // PING
        REQUIRE_FALSE(g_writes.chunks.empty());
        REQUIRE(static_cast<uint8_t>(g_writes.chunks[0][0]) == 0x89); // FIN|PING

        g_writes = {};
        const char text[] = "hi";
        REQUIRE(esp_transport_ws_send_raw(ws.get(),
                                         static_cast<ws_transport_opcodes_t>(WS_TRANSPORT_OPCODES_TEXT | WS_TRANSPORT_OPCODES_FIN),
                                         text, 2, timeout) == 2);
        REQUIRE_FALSE(g_writes.chunks.empty());
        REQUIRE((static_cast<uint8_t>(g_writes.chunks[0][0]) & 0x0F) == 0x01);

        REQUIRE(esp_transport_ws_send_raw(nullptr, WS_TRANSPORT_OPCODES_TEXT, text, 2, timeout) == ESP_ERR_INVALID_ARG);
        REQUIRE(esp_transport_poll_write(ws.get(), timeout) == 1);
        REQUIRE(esp_transport_close(ws.get()) == 0);
        // Parent has no TLS socket; still covers the ws wrapper.
        REQUIRE(esp_transport_ws_poll_connection_closed(ws.get(), timeout) == -1);
    }

    SECTION("read getters after data frame") {
        auto response = make_handshake_response() + make_ws_frame(0x81, "Hi"); // FIN|TEXT
        connect_with_response(response);

        char buf[8] = {};
        REQUIRE(esp_transport_read(ws.get(), buf, sizeof(buf), timeout) == 2);
        REQUIRE(std::string(buf, 2) == "Hi");
        REQUIRE(esp_transport_ws_get_fin_flag(ws.get()) == true);
        REQUIRE(esp_transport_ws_get_read_opcode(ws.get()) == WS_TRANSPORT_OPCODES_TEXT);
        REQUIRE(esp_transport_ws_get_read_payload_len(ws.get()) == 2);
    }

    SECTION("read 16-bit length data frame") {
        std::string payload(200, 'B');
        auto response = make_handshake_response() + make_ws_frame(0x82, payload); // FIN|BINARY
        connect_with_response(response);
        std::vector<char> buf(payload.size());
        REQUIRE(esp_transport_read(ws.get(), buf.data(), static_cast<int>(buf.size()), timeout) ==
                static_cast<int>(payload.size()));
        REQUIRE(std::string(buf.begin(), buf.end()) == payload);
        REQUIRE(esp_transport_ws_get_read_payload_len(ws.get()) == static_cast<int>(payload.size()));
    }

    SECTION("auto-handle PING with PONG reply") {
        connect_with_response(make_handshake_response());
        g_reads = {};
        g_reads.chunks.push_back(make_ws_frame(0x89, "ping")); // FIN|PING
        g_writes = {};
        mock_read_Stub(scripted_read_callback);

        char buf[16] = {};
        // propagate_control_frames=false (default): handled internally, returns 0
        REQUIRE(esp_transport_read(ws.get(), buf, sizeof(buf), timeout) == 0);
        REQUIRE_FALSE(g_writes.chunks.empty());
        REQUIRE(static_cast<uint8_t>(g_writes.chunks[0][0]) == 0x8A); // FIN|PONG
    }

    SECTION("auto-handle PONG") {
        connect_with_response(make_handshake_response());
        g_reads = {};
        g_reads.chunks.push_back(make_ws_frame(0x8A, "")); // FIN|PONG
        mock_read_Stub(scripted_read_callback);
        char buf[8] = {};
        REQUIRE(esp_transport_read(ws.get(), buf, sizeof(buf), timeout) == 0);
    }

    SECTION("auto-handle CLOSE echoes close frame") {
        connect_with_response(make_handshake_response());
        g_reads = {};
        uint16_t code = htons(1000);
        std::string payload(reinterpret_cast<char *>(&code), sizeof(code));
        g_reads.chunks.push_back(make_ws_frame(0x88, payload)); // FIN|CLOSE
        g_writes = {};
        mock_read_Stub(scripted_read_callback);
        char buf[16] = {};
        // poll_connection_closed fails without a real socket -> -1, but CLOSE echo is sent
        REQUIRE(esp_transport_read(ws.get(), buf, sizeof(buf), timeout) == -1);
        REQUIRE_FALSE(g_writes.chunks.empty());
        REQUIRE(static_cast<uint8_t>(g_writes.chunks[0][0]) == 0x88);
    }

    SECTION("propagate control frames to reader") {
        esp_transport_ws_config_t cfg = {};
        cfg.propagate_control_frames = true;
        REQUIRE(esp_transport_ws_set_config(ws.get(), &cfg) == ESP_OK);

        connect_with_response(make_handshake_response());
        g_reads = {};
        g_reads.chunks.push_back(make_ws_frame(0x89, "xyz")); // FIN|PING
        mock_read_Stub(scripted_read_callback);

        char buf[8] = {};
        REQUIRE(esp_transport_read(ws.get(), buf, sizeof(buf), timeout) == 3);
        REQUIRE(std::string(buf, 3) == "xyz");
        REQUIRE(esp_transport_ws_get_read_opcode(ws.get()) == WS_TRANSPORT_OPCODES_PING);
    }

    SECTION("payload transport handle and get_socket wrappers") {
        connect_with_response(make_handshake_response());
        // Resets remaining bytes via payload-transport helper used by some clients
        REQUIRE(esp_transport_get_payload_transport_handle(ws.get()) == parent_handle.get());
        // Parent mock has no _get_socket -> -1, but covers ws_get_socket path
        REQUIRE(esp_transport_get_socket(ws.get()) == -1);
    }
}

TEST_CASE("WebSocket connect edge cases", "[ws][coverage][failure]")
{
    constexpr auto timeout = 50;
    constexpr auto port = 8080;
    constexpr auto host = "localhost";
    install_parent_ignored_mocks();

    unique_transport parent_handle{esp_transport_init(), esp_transport_destroy};
    REQUIRE(parent_handle);
    esp_transport_set_func(parent_handle.get(), mock_connect, mock_read, mock_write, mock_close,
                           mock_poll_read, mock_poll_write, mock_destroy);
    unique_transport ws{esp_transport_ws_init(parent_handle.get()), esp_transport_destroy};
    REQUIRE(ws);

    mock_write_Stub(capture_all_writes);
    mock_poll_read_Stub(always_ready_poll_read);

    SECTION("parent connect failure") {
        mock_connect_ExpectAndReturn(parent_handle.get(), host, port, timeout, -1);
        REQUIRE(esp_transport_connect(ws.get(), host, port, timeout) == -1);
    }

    SECTION("invalid accept key") {
        g_reads = {};
        g_reads.chunks.push_back(make_handshake_response("HTTP/1.1 101 Switching Protocols", "not-a-valid-key========"));
        mock_read_Stub(scripted_read_callback);
        mock_connect_ExpectAndReturn(parent_handle.get(), host, port, timeout, ESP_OK);
        REQUIRE(esp_transport_connect(ws.get(), host, port, timeout) == -1);
    }

    SECTION("missing accept key") {
        g_reads = {};
        g_reads.chunks.push_back("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n");
        mock_read_Stub(scripted_read_callback);
        mock_connect_ExpectAndReturn(parent_handle.get(), host, port, timeout, ESP_OK);
        REQUIRE(esp_transport_connect(ws.get(), host, port, timeout) == -1);
    }

    SECTION("duplicate accept key") {
        g_reads = {};
        g_reads.chunks.push_back(
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=\r\n"
            "Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=\r\n"
            "\r\n");
        mock_read_Stub(scripted_read_callback);
        mock_connect_ExpectAndReturn(parent_handle.get(), host, port, timeout, ESP_OK);
        REQUIRE(esp_transport_connect(ws.get(), host, port, timeout) == -1);
    }

    SECTION("HTTP redirect with Location") {
        g_reads = {};
        g_reads.chunks.push_back(
            "HTTP/1.1 302 Found\r\n"
            "Location: wss://example.com/redirect\r\n"
            "\r\n");
        mock_read_Stub(scripted_read_callback);
        mock_connect_ExpectAndReturn(parent_handle.get(), host, port, timeout, ESP_OK);
        REQUIRE(esp_transport_connect(ws.get(), host, port, timeout) == 302);
        REQUIRE(esp_transport_ws_get_upgrade_request_status(ws.get()) == 302);
        REQUIRE(std::string(esp_transport_ws_get_redir_uri(ws.get())) == "wss://example.com/redirect");
    }

    SECTION("HTTP redirect without Location") {
        g_reads = {};
        g_reads.chunks.push_back("HTTP/1.1 301 Moved Permanently\r\n\r\n");
        mock_read_Stub(scripted_read_callback);
        mock_connect_ExpectAndReturn(parent_handle.get(), host, port, timeout, ESP_OK);
        REQUIRE(esp_transport_connect(ws.get(), host, port, timeout) == -1);
    }

    SECTION("null ws init parent") {
        REQUIRE(esp_transport_ws_init(nullptr) == nullptr);
    }

    SECTION("clearable setter NULLs") {
        REQUIRE(esp_transport_ws_set_subprotocol(ws.get(), "x") == ESP_OK);
        REQUIRE(esp_transport_ws_set_subprotocol(ws.get(), nullptr) == ESP_OK);
        REQUIRE(esp_transport_ws_set_user_agent(ws.get(), "y") == ESP_OK);
        REQUIRE(esp_transport_ws_set_user_agent(ws.get(), nullptr) == ESP_OK);
        REQUIRE(esp_transport_ws_set_headers(ws.get(), "H: 1\r\n") == ESP_OK);
        REQUIRE(esp_transport_ws_set_headers(ws.get(), nullptr) == ESP_OK);
        REQUIRE(esp_transport_ws_set_auth(ws.get(), "a") == ESP_OK);
        REQUIRE(esp_transport_ws_set_auth(ws.get(), nullptr) == ESP_OK);
        REQUIRE(esp_transport_ws_set_subprotocol(nullptr, "x") == ESP_ERR_INVALID_ARG);
        REQUIRE(esp_transport_ws_set_header_hook(nullptr, nullptr, nullptr) == ESP_ERR_INVALID_ARG);
        REQUIRE(esp_transport_ws_get_redir_uri(nullptr) == nullptr);
    }
}
