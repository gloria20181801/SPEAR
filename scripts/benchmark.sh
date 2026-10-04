#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
source "$ROOT/scripts/env.sh"
export GOMAXPROCS="${GOMAXPROCS:-1}" RUN_PERFORMANCE=1
RUNS="${RUNS:-3}"
[[ "$RUNS" == 1 || "$RUNS" == 3 ]] || { echo 'RUNS must be 1 (smoke test) or 3 (confidence intervals)' >&2; exit 1; }
DEST="$ROOT/results/benchmark-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$DEST"
PIN=(); if [[ -n "${CPU_INDEX:-}" ]]; then PIN=(taskset -c "$CPU_INDEX"); fi
{ date -Is; go version; uname -a; command -v lscpu >/dev/null && lscpu; } > "$DEST/environment.txt"
for scheme in SPEAR AAKA PKTSIN AnFRA MECSTIN; do
 target=.; [[ "$scheme" == SPEAR ]] && target=./protocol
 (cd "$ROOT/schemes/$scheme" && go test -c -o "$DEST/$scheme.test" "$target")
 for ((r=1;r<=RUNS;r++)); do
  "${PIN[@]}" "$DEST/$scheme.test" -test.run '^Test(Performance|RolePerformance)$' -test.v -test.timeout=30m > "$DEST/$scheme-run$r.log" 2>&1
  echo "$scheme benchmark process $r complete"
 done
done
python3 "$ROOT/scripts/analyze.py" "$DEST"
echo "Results: $DEST"
