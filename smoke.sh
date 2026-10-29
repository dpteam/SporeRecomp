#!/usr/bin/env bash
# Smoke-test the aarch64 binary under qemu-aarch64, without a device.
#
#   ./smoke.sh                 run with the reference exe, 30 s timeout
#   ./smoke.sh -t 120          longer timeout
#   ./smoke.sh -e path/to.exe  different guest executable
#
# This catches everything that does not need a GPU or the panel: PE loading, import binding,
# CRT startup, the boot ladder and the first guest calls. It is the fastest feedback loop
# available, so it runs before every deploy.
set -uo pipefail
cd "$(dirname "$0")"

TIMEOUT=30
EXE="refs/SporeBin/SporeApp.exe.unpacked.exe"
while getopts "t:e:" opt; do
  case "$opt" in
    t) TIMEOUT="$OPTARG" ;;
    e) EXE="$OPTARG" ;;
    *) echo "usage: $0 [-t seconds] [-e exe]" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

BIN="build/aarch64/spore"
[ -f "$BIN" ] || { echo "missing $BIN — run ./build.sh aarch64" >&2; exit 1; }
[ -f "$EXE" ] || { echo "missing guest exe $EXE" >&2; exit 1; }

STAGE="${SR_STAGE:-/tmp/spore-smoke}"
rm -rf "$STAGE" && mkdir -p "$STAGE/gamedata"
cp "$EXE" "$STAGE/gamedata/SporeApp.exe"
cp "$BIN" "$STAGE/spore"
chmod +x "$STAGE/spore"

cd "$STAGE"
# The cross toolchain's dynamic loader is not at the path qemu looks for by default; point it
# at the aarch64 sysroot explicitly.
SYSROOT=/usr/aarch64-linux-gnu
echo "[smoke] qemu-aarch64, ${TIMEOUT}s timeout, guest exe $(stat -c%s gamedata/SporeApp.exe) bytes"
QEMU_ARGS="-cpu max"
[ -d "$SYSROOT/lib" ] && QEMU_ARGS="$QEMU_ARGS -L $SYSROOT"
timeout "$TIMEOUT" qemu-aarch64-static $QEMU_ARGS ./spore gamedata "$@" > qemu.log 2>&1
RC=$?
echo "[smoke] exit $RC $([ $RC -eq 124 ] && echo '(timeout — the guest was still running)')"
echo "[smoke] --- stdout/stderr ---"
head -20 qemu.log
echo "[smoke] --- log.txt (first 60) ---"
if [ -f log.txt ]; then
  head -60 log.txt
  echo "[smoke] --- log.txt (last 30) ---"
  tail -30 log.txt
  echo "[smoke] $(wc -l < log.txt) lines, $(grep -c 'UNSUPPORTED' log.txt || true) unsupported instructions"
else
  echo "(no log.txt)"
fi
