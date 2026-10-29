#!/bin/bash
# Deploy to the RG 35 XX H over SSH, run it, and fetch the log back.
#
#   ./deploy.sh            push the binary, run for 60 s, fetch log.txt
#   ./deploy.sh push       push the binary only
#   ./deploy.sh log        fetch log.txt only
#   ./deploy.sh data       push the game data (4 GB, once)
#
# Device: muOS 2606, 192.168.1.216, root/root. Override with SPORE_DEVICE / SPORE_USER /
# SPORE_PASS / SPORE_DEST.
set -uo pipefail
cd "$(dirname "$0")"

DEVICE="${SPORE_DEVICE:-192.168.1.216}"
USER_="${SPORE_USER:-root}"
PASS="${SPORE_PASS:-root}"
DEST="${SPORE_DEST:-/roms/ports/spore}"
LOCAL_DATA="${SPORE_DATA:-../OpenSpore/refs/_Also/SporeGames/SporeRetail}"
HOSTKEY="${SPORE_HOSTKEY:-SHA256:4MdwKe7R5EeTwFzupXResk+HaBBa9n9MGznS4m5eY9k}"
RUNTIME="${SPORE_RUNTIME:-60}"

ssh_run() { plink -ssh -batch -hostkey "$HOSTKEY" -pw "$PASS" "$USER_@$DEVICE" "$@"; }
scp_put() { pscp -batch -hostkey "$HOSTKEY" -pw "$PASS" "$1" "$USER_@$DEVICE:$2"; }
scp_get() { pscp -batch -hostkey "$HOSTKEY" -pw "$PASS" "$USER_@$DEVICE:$1" "$2"; }

case "${1:-run}" in
  push)
    ssh_run "mkdir -p $DEST/gamedata"
    scp_put build/aarch64/spore "$DEST/spore"
    ssh_run "chmod +x $DEST/spore && ls -la $DEST/spore && free -m | head -2"
    ;;
  log)
    scp_get "$DEST/log.txt" ./device-log.txt && { wc -l device-log.txt; tail -60 device-log.txt; }
    ;;
  data)
    echo "[deploy] pushing game data from $LOCAL_DATA (this is ~4 GB and takes a while)"
    ssh_run "mkdir -p $DEST/gamedata"
    pscp -batch -hostkey "$HOSTKEY" -pw "$PASS" -r "$LOCAL_DATA/Data" "$USER_@$DEVICE:$DEST/gamedata/"
    ssh_run "ls $DEST/gamedata/Data | head -10"
    ;;
  run)
    ssh_run "mkdir -p $DEST/gamedata"
    scp_put build/aarch64/spore "$DEST/spore"
    ssh_run "chmod +x $DEST/spore && ls -la $DEST/spore"
    echo "[deploy] running for ${RUNTIME}s"
    ssh_run "cd $DEST && rm -f log.txt && timeout $RUNTIME ./spore gamedata 2>&1 | head -120"
    echo "[deploy] fetching log"
    scp_get "$DEST/log.txt" ./device-log.txt 2>/dev/null && {
      echo "[deploy] $(wc -l < device-log.txt) log lines"
      head -30 device-log.txt
      echo "..."
      tail -40 device-log.txt
    }
    ;;
esac
