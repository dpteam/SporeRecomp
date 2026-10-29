#!/usr/bin/env bash
# SporeRecomp cross-build for aarch64 (muOS / RG 35 XX H).
#
#   ./build.sh            build for aarch64 (default)
#   ./build.sh host       build for the host (x86-64) — used by the differential tests
#
# Requires: aarch64-linux-gnu-g++ (Debian: g++-aarch64-linux-gnu)
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${1:-aarch64}"
OUT="build/$TARGET"
mkdir -p "$OUT"

if [ "$TARGET" = "host" ]; then
  CXX="${CXX:-g++}"
  CXXFLAGS="-std=c++20 -O2 -g -Isrc -DSPORE_HOST_BUILD=1"
  JOBS=$(nproc)
else
  CXX="${CXX:-aarch64-linux-gnu-g++}"
  CXXFLAGS="-std=c++20 -O2 -g -Isrc"
  JOBS=$(nproc)
fi

GEN=$(ls recomp/gen/funcs_*.cpp 2>/dev/null || true)
if [ -z "$GEN" ]; then
  echo "error: no generated code. run: python tools/lift.py" >&2
  exit 1
fi
SRC=$(ls src/*.cpp src/rt/*.cpp 2>/dev/null)

echo "[build] $TARGET: $(echo "$SRC" | wc -w) runtime files, $(echo "$GEN" | wc -w) generated chunks"

# Compile everything in parallel; -pipe keeps the intermediate off disk.
OBJS=()
compile() {
  local src="$1" obj="$2"
  $CXX $CXXFLAGS -Irecomp/gen -c -o "$obj" "$src"
}
export -f compile
export CXX CXXFLAGS

printf '%s\n' $SRC $GEN | xargs -P "$JOBS" -I{} bash -c '
  src="{}"
  base=$(basename "${src%.cpp}")
  compile "$src" "'"$OUT"'/$base.o"
'

OBJS=$(ls "$OUT"/*.o)
# Static libstdc++/libgcc: muOS images differ in their C++ runtime, glibc 2.44 here.
if [ "$TARGET" != "host" ]; then
  $CXX $CXXFLAGS -o "$OUT/spore" $OBJS -static-libstdc++ -static-libgcc
else
  $CXX $CXXFLAGS -o "$OUT/spore" $OBJS
fi
echo "[build] wrote $OUT/spore"
ls -la "$OUT/spore"
