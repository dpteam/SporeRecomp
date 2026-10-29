#!/usr/bin/env bash
# SporeRecomp cross-build for aarch64 (muOS / RG 35 XX H).
#
#   ./build.sh            build for aarch64 (default)
#   ./build.sh host       build for the host (x86-64) — used by the differential tests
#   ./build.sh aarch64 -f force a full rebuild
#
# Incremental: an object is rebuilt only when its source (or a header) is newer.
set -uo pipefail
cd "$(dirname "$0")"

TARGET="${1:-aarch64}"
FORCE=0
[ "${2:-}" = "-f" ] && FORCE=1
OUT="build/$TARGET"
mkdir -p "$OUT"

if [ "$TARGET" = "host" ]; then
  CXX="${CXX:-g++}"
  CXXFLAGS="-std=c++20 -O2 -g -Isrc -Irecomp/gen -DSPORE_HOST_BUILD=1"
  GENFLAGS="-std=c++20 -O1 -g -Isrc -Irecomp/gen -DSPORE_HOST_BUILD=1"
else
  CXX="${CXX:-aarch64-linux-gnu-g++}"
  CXXFLAGS="-std=c++20 -O2 -g -Isrc -Irecomp/gen"
  # The lifted code is long, straight-line and branch-predictable: -O1 gives the same
  # performance as -O2 for it and compiles roughly twice as fast. No -g: debug info for four
  # million instructions costs hundreds of MB of object files and slows every link.
  #
  # SR_OPT=-O0 builds the generated code with no optimisation: about three times faster to
  # compile, and slow at runtime. Use it when iterating on "does it boot", not for testing
  # performance.
  GENFLAGS="-std=c++20 ${SR_OPT:--O1} -Isrc -Irecomp/gen"
fi
# Default to a modest job count: on a thermally limited machine 32 parallel compilers fight
# for the same power budget and finish later than 12 would. Override with SR_JOBS=32.
JOBS="${SR_JOBS:-12}"

GEN=$(ls recomp/gen/funcs_*.cpp 2>/dev/null || true)
if [ -z "$GEN" ]; then
  echo "error: no generated code. run: python tools/lift.py" >&2
  exit 1
fi
SRC=$(ls src/*.cpp src/rt/*.cpp src/rt/win32/*.cpp src/rt/d3d9/*.cpp 2>/dev/null)

# Newest header mtime: any object older than this is stale.
NEWEST_HDR=$(ls -t src/rt/*.h src/rt/*/*.h recomp/gen/protos.h 2>/dev/null | head -1)

needs_build() {
  local obj="$1" src="$2"
  [ "$FORCE" = "1" ] && return 0
  [ -f "$obj" ] || return 0
  [ "$src" -nt "$obj" ] && return 0
  [ -n "$NEWEST_HDR" ] && [ "$NEWEST_HDR" -nt "$obj" ] && return 0
  return 1
}

compile_one() {
  local src="$1" obj="$2"
  if needs_build "$obj" "$src"; then
    local flags="$CXXFLAGS"
    case "$src" in
      recomp/gen/*|*/gen/funcs_*) flags="$GENFLAGS" ;;
    esac
    if ! $CXX $flags -c -o "$obj" "$src" 2> "$obj.err"; then
      echo "=== FAILED: $src"
      head -20 "$obj.err"
      return 1
    fi
    rm -f "$obj.err"
  fi
  return 0
}
export -f compile_one needs_build
export CXX CXXFLAGS GENFLAGS FORCE NEWEST_HDR

echo "[build] $TARGET: $(echo "$SRC" | wc -w) runtime + $(echo "$GEN" | wc -w) generated"

TOTAL=0
TODO=()
for f in $SRC $GEN; do
  TOTAL=$((TOTAL + 1))
  base=$(basename "${f%.cpp}")
  obj="$OUT/$base.o"
  if needs_build "$obj" "$f"; then TODO+=("$f"); fi
done
  echo "[build] ${#TODO[@]} files to compile, $((TOTAL - ${#TODO[@]})) up to date"

if [ ${#TODO[@]} -gt 0 ]; then
  printf '%s\n' "${TODO[@]}" | xargs -P "$JOBS" -I{} bash -c '
    src="{}"
    base=$(basename "${src%.cpp}")
    compile_one "$src" "'"$OUT"'/$base.o" || exit 255
  ' || { echo "[build] compile failed"; exit 1; }
fi

LDFLAGS=""
if [ "$TARGET" != "host" ]; then
  LDFLAGS="-static-libstdc++ -static-libgcc"
fi
$CXX $CXXFLAGS -o "$OUT/spore" "$OUT"/*.o $LDFLAGS || { echo "[build] link failed"; exit 1; }
echo "[build] wrote $OUT/spore"
ls -la "$OUT/spore"
