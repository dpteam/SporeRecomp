#!/usr/bin/env bash
# SporeRecomp cross-build for aarch64 (muOS / RG 35 XX H) or the host.
#
#   ./build.sh                 aarch64 build
#   ./build.sh host            host build (x86-64, for the differential tests)
#   ./build.sh aarch64 -f      force a full rebuild
#   SR_OPT=-O0 ./build.sh      compile the generated code unoptimised (fast build, slow game)
#   SR_JOBS=32 ./build.sh      more parallel compilers (default 12)
#
# Incremental: an object is rebuilt only when its source, or a header, is newer.
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
  # million instructions costs hundreds of MB and slows every link.
  GENFLAGS="-std=c++20 ${SR_OPT:--O1} -Isrc -Irecomp/gen"
fi

# On a thermally limited machine many parallel compilers fight for the same power budget and
# finish later than a moderate number would.
JOBS="${SR_JOBS:-12}"

GEN_FILES=$(ls recomp/gen/funcs_*.cpp recomp/gen/table.cpp 2>/dev/null || true)
if [ -z "$GEN_FILES" ]; then
  echo "error: no generated code — run: python tools/lift.py" >&2
  exit 1
fi
SRC_FILES=$(ls src/*.cpp src/rt/*.cpp src/rt/win32/*.cpp src/rt/d3d9/*.cpp 2>/dev/null)

# Newest header: any object older than this is stale.
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
  local src="$1" obj="$2" flags="$3"
  if needs_build "$obj" "$src"; then
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

N_RT=$(echo "$SRC_FILES" | wc -w)
N_GEN=$(echo "$GEN_FILES" | wc -w)
echo "[build] $TARGET: $N_RT runtime + $N_GEN generated sources"

# Collect the files that need compiling, with the flags each one wants.
TODO_LIST=""
TODO_COUNT=0
for f in $SRC_FILES; do
  obj="$OUT/$(basename "${f%.cpp}").o"
  if needs_build "$obj" "$f"; then
    TODO_LIST="$TODO_LIST$f|$obj|$CXXFLAGS"$'\n'
    TODO_COUNT=$((TODO_COUNT + 1))
  fi
done
for f in $GEN_FILES; do
  obj="$OUT/$(basename "${f%.cpp}").o"
  if needs_build "$obj" "$f"; then
    TODO_LIST="$TODO_LIST$f|$obj|$GENFLAGS"$'\n'
    TODO_COUNT=$((TODO_COUNT + 1))
  fi
done
echo "[build] $TODO_COUNT to compile, $((N_RT + N_GEN - TODO_COUNT)) up to date, $JOBS jobs"

if [ "$TODO_COUNT" -gt 0 ]; then
  printf '%s' "$TODO_LIST" | xargs -P "$JOBS" -I{} bash -c '
    IFS="|" read -r src obj flags <<< "{}"
    compile_one "$src" "$obj" "$flags" || exit 255
  ' || { echo "[build] compile failed"; exit 1; }
fi

LDFLAGS=""
if [ "$TARGET" != "host" ]; then
  LDFLAGS="-static-libstdc++ -static-libgcc"
fi
$CXX $CXXFLAGS -o "$OUT/spore" "$OUT"/*.o $LDFLAGS || { echo "[build] link failed"; exit 1; }
echo "[build] wrote $OUT/spore"
ls -la "$OUT/spore"
