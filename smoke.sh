#!/bin/bash
# Smoke-test the aarch64 binary under qemu-user, without a device.
#
#   ./smoke.sh                 run against refs/SporeBin/SporeApp.exe.unpacked.exe
#   ./smoke.sh --timeout 30    give up after 30 s (default 120)
#
# Checks: the binary loads, the PE parses, imports bind, and the guest reaches its entry
# point. Prints the log tail and the exit code. This is the fastest feedback loop we have;
# the device is only needed for anything that touches the GPU or the panel.
set -uo pipefail
cd "$(dirname "$0")"

TIMEOUT=120
[ "${1:-}" = "--timeout" ] && TIMEOUT="${2:-120}"

BIN="build/aarch64/spore"
[ -f "$BIN" ] || { echo "missing $BIN; run ./build.sh aarch64" >&2; exit 1; }

# Stage a game directory with just the executable: the boot ladder should get past the PE
# load and CRT startup without any assets.
STAGE="${SR_STAGE:-/tmp/spore-smoke}"
rm -rf "$STAGE" && mkdir -p "$STAGE/gamedata"
cp refs/SporeBin/SporeApp.exe.unpacked.exe "$STAGE/gamedata/SporeApp.exe"
cp "$BIN" "$STAGE/spore"

cd "$STAGE"
echo "=== running under qemu-aarch64 (timeout ${TIMEOUT}s)"
timeout "$TIMEOUT" qemu-aarch64-static -cpu max ./spore gamedata > run.log 2>&1
RC=$?
echo "=== exit code: $RC  (124 = timed out, which usually means the guest kept running)"
echo "=== log ($(wc -l < run.log) lines)"
if [ -f log.txt ]; then
  head -40 log.txt
  echo "  ..."
  tail -25 log.txt
else
  tail -40 run.log
fi
