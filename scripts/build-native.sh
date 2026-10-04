#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
PIN=e4c8bbe4af0013e00244c661836f3a3676f21024
SRC="$ROOT/.deps/mcl-src"
PREFIX="$ROOT/.deps/native"
mkdir -p "$ROOT/.deps"
if [[ ! -d "$SRC/.git" ]]; then
  git clone "${MCL_SOURCE_REPO:-https://github.com/herumi/mcl.git}" "$SRC"
fi
# Never build an arbitrary tip or silently overwrite modified sources.
if [[ -n "$(git -C "$SRC" status --porcelain --untracked-files=no)" ]]; then
  echo 'Native source has tracked modifications; use a fresh artifact directory.' >&2; exit 1
fi
git -C "$SRC" checkout --detach "$PIN"
test "$(git -C "$SRC" rev-parse HEAD)" = "$PIN"
cmake -S "$SRC" -B "$ROOT/.deps/mcl-build" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" -DMCL_FP_BIT=384 -DMCL_FR_BIT=256 \
  -DMCL_BUILD_TESTING=OFF -DMCL_BUILD_SAMPLE=OFF
cmake --build "$ROOT/.deps/mcl-build" --parallel "${BUILD_JOBS:-2}"
cmake --install "$ROOT/.deps/mcl-build"
# The pinned historical Go binding asks for the old split-library name;
# this native revision includes those C entry points in libmcl itself.
LIB="$PREFIX/lib"
if [[ ! -f "$LIB/libmcl.so" && -f "$PREFIX/lib64/libmcl.so" ]]; then LIB="$PREFIX/lib64"; fi
ln -sfn libmcl.so "$LIB/libmclbn384_256.so"
printf '%s\n' "$PIN" > "$PREFIX/MCL_REVISION"
echo 'Native build complete. Run: source scripts/env.sh'
