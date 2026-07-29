#!/usr/bin/env bash
# Export Mull SQLite survivors as clang/IDE-style diagnostics (path:line:col: ...).
# Cursor / VS Code treat these as clickable links in the terminal.
#
# Usage:
#   ./scripts/export_mull_survivors.sh
#   ./scripts/export_mull_survivors.sh mull_reports/tcp_transport_ws.sqlite
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB="${1:-${ROOT}/mull_reports/tcp_transport_ws.sqlite}"
OUT="${2:-${ROOT}/mull_reports/tcp_transport_ws_survivors.txt}"

if [[ ! -f "${DB}" ]]; then
    echo "SQLite report not found: ${DB}" >&2
    exit 1
fi

python3 - "${DB}" "${OUT}" <<'PY'
import sqlite3
import sys
from pathlib import Path

db_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
con = sqlite3.connect(db_path)
rows = con.execute(
    """
    SELECT filename, line_number, column_number, mutator, mutation_replacement, execution_status
    FROM mutant
    WHERE execution_status = 2
    ORDER BY filename, line_number, column_number, mutator
    """
).fetchall()
total = con.execute("SELECT COUNT(*) FROM mutant").fetchone()[0]
killed = con.execute("SELECT COUNT(*) FROM mutant WHERE execution_status <> 2").fetchone()[0]
survived = len(rows)
score = 100.0 * killed / total if total else 0.0

lines = [
    f"# Mull survivors for {db_path.name}",
    f"# total={total} survived={survived} killed={killed} mutation_score={score:.1f}%",
    f"# format: file:line:col: warning: surviving mutant [mutator] -> replacement",
    "#",
]
for filename, line, col, mutator, replacement, _ in rows:
    # Prefer absolute paths so IDE click-through works from any cwd.
    path = filename or "<unknown>"
    line = line or 0
    col = col or 1
    repl = (replacement or "").replace("\n", "\\n")
    lines.append(
        f"{path}:{line}:{col}: warning: surviving mutant [{mutator}] -> '{repl}' [-Wmull-survivor]"
    )
lines.append("#")
lines.append(f"# end ({survived} survivors)")

out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"Wrote {out_path} ({survived} survivors, score {score:.1f}%)")
PY
