#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
source "$ROOT/scripts/env.sh"
export GOMAXPROCS="${GOMAXPROCS:-1}" RUN_SCALABILITY=1
RUNS="${RUNS:-3}"
[[ "$RUNS" == 1 || "$RUNS" == 3 ]] || { echo 'RUNS must be 1 (smoke test) or 3 (confidence intervals)' >&2; exit 1; }
DEST="$ROOT/results/scalability-$(date +%Y%m%d-%H%M%S)";mkdir -p "$DEST"
PIN=(); if [[ -n "${CPU_INDEX:-}" ]]; then PIN=(taskset -c "$CPU_INDEX"); fi
{ date -Is; go version; uname -a; command -v lscpu >/dev/null && lscpu; } > "$DEST/environment.txt"
(cd "$ROOT/schemes/SPEAR" && go test -c -o "$DEST/SPEAR.test" ./protocol)
for ((r=1;r<=RUNS;r++)); do
 "${PIN[@]}" "$DEST/SPEAR.test" -test.run '^Test(Access|Witness)Scalability$' -test.v -test.timeout=45m > "$DEST/SPEAR-run$r.log" 2>&1
 echo "SPEAR scalability process $r complete"
done
python3 "$ROOT/scripts/analyze.py" "$DEST"
echo "Results: $DEST"
