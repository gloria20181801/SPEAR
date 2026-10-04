#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
source "$ROOT/scripts/env.sh"
export GOMAXPROCS="${GOMAXPROCS:-1}"
for scheme in SPEAR AAKA PKTSIN AnFRA MECSTIN; do
 echo "== $scheme correctness =="
 (cd "$ROOT/schemes/$scheme" && go test ./... -count=1 -timeout=5m)
done
echo '== SPEAR end-to-end demo =='
(cd "$ROOT/schemes/SPEAR" && go run ./cmd/demo)
