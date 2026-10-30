#!/bin/bash
# Run the host build under gdb and capture the crash with a full backtrace.
#
# This is the fast loop: the lifted code is plain C++, so it debugs natively on x86-64 in
# seconds instead of a 40-minute cross build plus qemu.
#
#   ./debug.sh                 run and print the backtrace
#   ./debug.sh -b ADDR         break at a guest address (hex), print state there
#   ./debug.sh -w SYMBOL       watch a host symbol
set -uo pipefail
cd /mnt/e/_DPT_Projects_E/_Harness/SporeRecomp || exit 1

BIN=build/host/spore
[ -f "$BIN" ] || { echo "missing $BIN; run: CXX=g++ ./build.sh host"; exit 1; }

STAGE=/mnt/e/_DPT_Projects_E/_Harness/SporeRecomp/build/debug
DATA=/mnt/e/_DPT_Projects_E/_Harness/OpenSpore/refs/_Also/SporeGames/SporeRetail

# Stage inside WSL's own filesystem: a Linux symlink to the game data cannot be represented on
# the Windows drive (Explorer shows it as a 0-byte file), and /tmp avoids that entirely.
STAGE=/tmp/spore-debug
rm -rf "$STAGE" && mkdir -p "$STAGE/gamedata"
cp refs/SporeBin/SporeApp.exe.unpacked.exe "$STAGE/gamedata/SporeApp.exe"
cp "$BIN" "$STAGE/spore"
[ -d "$DATA/Data" ] && ln -sfn "$DATA/Data" "$STAGE/gamedata/Data"

CMDS=$(mktemp)
{
  echo "set pagination off"
  echo "set confirm off"
  echo "handle SIGPIPE nostop noprint pass"
  echo "run $STAGE/gamedata"
  echo "echo \n===== BACKTRACE =====\n"
  echo "bt 30"
  echo "echo \n===== FRAMES =====\n"
  echo "info frame"
  echo "echo \n===== REGISTERS (host) =====\n"
  echo "info registers rip rsp rbp"
  echo "quit"
} > "$CMDS"

cd "$STAGE"
timeout "${DEBUG_TIMEOUT:-300}" gdb -q -batch -x "$CMDS" ./spore 2>&1
RC=$?
rm -f "$CMDS"
exit $RC
