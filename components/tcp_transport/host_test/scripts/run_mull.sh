#!/usr/bin/env bash
# PoC mutation-testing for tcp_transport host tests (websocket / transport_ws.c).
#
# Unlike mdns (standalone CMake + clang everywhere), this IDF Catch2 host_test
# is built with gcc. We overlay a clang-18 + Mull IR frontend compile of
# transport_ws.c only, then relink and run mull-runner.
#
# Prerequisites:
#   - IDF env (see PLAN.md): export.sh for this tree / matching Python venv
#   - clang-18, mull-runner-18, /usr/lib/mull-ir-frontend-18
#   - Existing or freshly built build_mull/ (gcc baseline)
#
# Usage (from host_test/):
#   ./scripts/run_mull.sh
#   MULL_CONSOLE=1 ./scripts/run_mull.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT}/build_mull"
LLVM_MAJOR="${MULL_LLVM_MAJOR:-18}"
FRONTEND="${MULL_IR_FRONTEND:-/usr/lib/mull-ir-frontend-${LLVM_MAJOR}}"
RUNNER="${MULL_RUNNER:-mull-runner-${LLVM_MAJOR}}"
CC_BIN="${CC:-clang-${LLVM_MAJOR}}"

if [[ -z "${IDF_PATH:-}" ]]; then
    echo "IDF_PATH not set; source export.sh first" >&2
    exit 1
fi
if [[ ! -f "${FRONTEND}" ]]; then
    echo "Mull IR frontend not found at ${FRONTEND}" >&2
    exit 1
fi
if ! command -v "${RUNNER}" >/dev/null 2>&1; then
    echo "mull-runner not found (${RUNNER})" >&2
    exit 1
fi
if ! command -v "${CC_BIN}" >/dev/null 2>&1; then
    echo "Compiler not found (${CC_BIN})" >&2
    exit 1
fi

cd "${ROOT}"

# Do not inherit gcov flags from a prior coverage session in this shell.
unset EXTRA_CFLAGS EXTRA_CXXFLAGS EXTRA_CPPFLAGS || true

# Baseline gcc build (no global Mull plugin — that breaks mbedtls under clang).
if [[ ! -x "${BUILD_DIR}/host_tcp_transport_test.elf" ]]; then
    idf.py --preview -B "${BUILD_DIR}" set-target linux
    idf.py --preview -B "${BUILD_DIR}" build
fi

# Ensure compile_commands.json exists for flag extraction
if [[ ! -f "${BUILD_DIR}/compile_commands.json" ]]; then
    cmake -B "${BUILD_DIR}" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >/dev/null
fi

python3 - <<PY
import json, shlex, subprocess, sys
from pathlib import Path

build = Path("${BUILD_DIR}")
frontend = "${FRONTEND}"
cc_bin = "${CC_BIN}"

cmds = json.loads((build / "compile_commands.json").read_text())
entry = next(c for c in cmds if c.get("file", "").endswith("transport_ws.c"))
parts = shlex.split(entry["command"])
if "configdep" in parts[0]:
    parts = parts[1:]
parts[0] = cc_bin
drop = {
    "-Wno-old-style-declaration",
    "-fno-tree-switch-conversion",
    "-fstrict-volatile-bitfields",
}
parts = [p for p in parts if p not in drop]
parts = ["-O0" if p in ("-Og", "-Os", "-O2", "-O3") else p for p in parts]
parts = [parts[0], f"-fpass-plugin={frontend}", "-grecord-command-line", "-fno-omit-frame-pointer", *parts[1:]]

r = subprocess.run(parts, cwd=entry["directory"])
if r.returncode:
    sys.exit(r.returncode)

subprocess.check_call(
    ["ar", "rcs", "esp-idf/tcp_transport/libtcp_transport.a",
     "esp-idf/tcp_transport/CMakeFiles/__idf_tcp_transport.dir/transport_ws.c.o"],
    cwd=build,
)
link = subprocess.check_output(
    ["ninja", "-C", str(build), "-t", "commands", "host_tcp_transport_test.elf"],
    text=True,
)
link_cmd = [l for l in link.splitlines() if l.strip()][-1]
r = subprocess.run(link_cmd, shell=True, cwd=build)
sys.exit(r.returncode)
PY

ELF="${BUILD_DIR}/host_tcp_transport_test.elf"
export MULL_CONFIG="${ROOT}/mull.yml"
REPORT_DIR="${ROOT}/mull_reports"
mkdir -p "${REPORT_DIR}"
REPORT_NAME="tcp_transport_ws"

# Fresh report each run (sqlite reporter appends otherwise).
rm -f "${REPORT_DIR}/${REPORT_NAME}.sqlite" \
      "${REPORT_DIR}/${REPORT_NAME}_survivors.txt"

REPORTERS=(--reporters SQLite)
if [[ "${MULL_CONSOLE:-0}" == "1" ]]; then
    REPORTERS+=(--reporters IDE)
fi

# Run the full Catch2 suite. Filtering to WebSocket* alone currently trips a
# CMock mock_destroy expectation (test isolation); mutants are still scoped to
# transport_ws.c via mull.yml includePaths.
"${RUNNER}" --allow-surviving \
    "${REPORTERS[@]}" \
    --report-dir "${REPORT_DIR}" \
    --report-name "${REPORT_NAME}" \
    "${ELF}"

# IDE-clickable survivor list (path:line:col: warning: ...)
"${ROOT}/scripts/export_mull_survivors.sh" \
    "${REPORT_DIR}/${REPORT_NAME}.sqlite" \
    "${REPORT_DIR}/${REPORT_NAME}_survivors.txt"

echo
echo "Report: ${REPORT_DIR}/${REPORT_NAME}.sqlite"
echo "Survivors (clickable): ${REPORT_DIR}/${REPORT_NAME}_survivors.txt"
echo "  (open/tail that file in the IDE terminal to jump to locations)"
