| Supported Targets | Linux |
| ----------------- | ----- |

# Description

Host-side unit tests for `tcp_transport` (Catch2 + CMock). Focus areas:

- **WebSocket** (`transport_ws.c`) — connect/read/write/control frames/config
- **SOCKS proxy** (`transport_socks_proxy.c`)

## Current status (host tests)

| Metric | Value |
|--------|--------|
| Result | All tests passed |
| `transport_ws.c` line coverage | ~**78%** (was ~40%) |
| `transport_ws.c` functions | **35/35** exercised |
| Mull mutation score (WS, local) | ~**55%** (232 mutants; see below) |

Coverage and Mull details / backlog: [`PLAN.md`](PLAN.md).

# Build

```bash
# Use a matching IDF env for this tree (v6.2-class). Preview target required for linux.
idf.py --preview set-target linux
idf.py --preview build
```

# Run

```bash
ASAN_OPTIONS=detect_leaks=0 ./build/host_tcp_transport_test.elf
# WebSocket-only:
ASAN_OPTIONS=detect_leaks=0 ./build/host_tcp_transport_test.elf '[ws]'
```

Catch2 filters and reporters work as usual (`--list-tests`, etc.).

# Mutation testing with Mull (optional, local only)

**Not part of CI.** Mull is an optional local tool to judge *test quality* (would a small code change make a test fail?). Same idea as mDNS host unit tests.

### Prerequisites (local)

- `clang-18`, `mull-runner-18`, `/usr/lib/mull-ir-frontend-18`
- IDF env exported for this tree

### Run

```bash
./scripts/run_mull.sh
```

This builds (or reuses) `build_mull/`, instruments **only** `transport_ws.c` with Mull, runs the host suite, and writes:

| Output | Use |
|--------|-----|
| `mull_reports/tcp_transport_ws.sqlite` | Full DB |
| `mull_reports/tcp_transport_ws_survivors.txt` | **IDE-clickable** survivor list |

Open the `.txt` in the terminal and click paths like:

```text
/home/.../components/tcp_transport/transport_ws.c:424:20: warning: surviving mutant [cxx_lt_to_le] -> '<=' [-Wmull-survivor]
```

Re-export without re-running Mull:

```bash
./scripts/export_mull_survivors.sh
```

Config: [`mull.yml`](mull.yml) (scopes mutants to `transport_ws.c`).

### Demo: killing a survivor with a sharper assertion

Mull reported this survivor after the coverage push:

```text
transport_ws.c:422:13: warning: surviving mutant [cxx_le_to_lt] -> '<' [-Wmull-survivor]
```

Production code (`_ws_write`):

```c
if (len <= 125) {
    ws_header[header_len++] = (uint8_t)(len | mask_flag);
} else if (len < 65536) {
    /* 16-bit length form */
```

Mutating `<=` to `<` means a **125-byte** payload takes the 16-bit path (length byte `126`) instead of the short form. Line coverage already hit nearby writes (e.g. 200 bytes), but nothing asserted the **boundary**.

**Fix** (in `test_websocket_transport.cpp`): write exactly 125 bytes and assert the short header:

```c
// hdr size 6 = 2-byte header + 4-byte mask; length field must be 125 (not 126)
REQUIRE(hdr.size() == 6);
REQUIRE((static_cast<uint8_t>(hdr[1]) & 0x7F) == 125);
```

**Result after re-running Mull:**

| | Before assertion | After assertion |
|--|------------------|-----------------|
| Survivor at `422:13` `cxx_le_to_lt` | **survived** | **killed** (absent from `*_survivors.txt`) |
| Surviving mutants (WS) | 105 | **104** |
| Mutation score | 54.7% | **55.2%** |

That is the intended Mull loop: find a meaningful survivor → tighten an assertion (or add a case) → confirm it disappears from the clickable report.
