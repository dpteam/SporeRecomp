#!/bin/bash
# Deploy to the RG 35 XX H over SSH and run it, then fetch the log back.
#
#   ./deploy.sh              push binary + run
#   ./deploy.sh push         push only
#   ./deploy.sh log          fetch log.txt only
#
# The device is muOS 2606 on 192.168.1.216 (root/root). Game data is expected in
# $DEST/gamedata; it is only pushed when it is not there yet (it is ~4 GB).
set -uo pipefail
cd "$(dirname "$0")"

DEVICE="${SPORE_DEVICE:-192.168.1.216}"
USER_="${SPORE_USER:-root}"
PASS="${SPORE_PASS:-root}"
DEST="${SPORE_DEST:-/roms/ports/spore}"
LOCAL_DATA="${SPORE_DATA:-E:/_DPT_Projects_E/_Harness/OpenSpore/refs/_Also/SporeGames/SporeRetail}"
HOSTKEY="SHA256:4MdwKe7R5EeTwFzupXResk+HaBBa9n9MGznS4m5eY9k"

ssh_run() {
  plink -ssh -batch -hostkey "$HOSTKEY" -pw "$PASS" "$USER_@$DEVICE" "$@"
}
scp_put() {
  pscp -batch -hostkey "$HOSTKEY" -pw "$PASS" "$1" "$USER_@$DEVICE:$2"
}
scp_get() {
  pscp -batch -hostkey "$HOSTKEY" -pw "$PASS" "$USER_@$DEVICE:$1" "$2"
}

case "${1:-run}" in
  push)
    ssh_run "mkdir -p $DEST/gamedata"
    scp_put build/aarch64/spore "$DEST/spore"
    ssh_run "chmod +x $DEST/spore && ls -la $DEST/spore"
    ;;
  log)
    scp_get "$DEST/log.txt" ./device-log.txt && tail -60 ./device-log.txt
    ;;
  data)
    # Push the game data. Slow (4 GB) and only needed once.
    ssh_run "mkdir -p $DEST/gamedata"
    pscp -batch -hostkey "$HOSTKEY" -pw "$PASS" -r "$LOCAL_DATA/Data" "$USER_@$DEVICE:$DEST/gamedata/"
    ssh_run "ls $DEST/gamedata/Data | head"
    ;;
  *)
    ssh_run "mkdir -p $DEST/gamedata"
    scp_put build/aarch64/spore "$DEST/spore"
    ssh_run "chmod +x $DEST/spore"
    echo "=== running (Ctrl-C to stop; the log is on the device)"
    ssh_run "cd $DEST && rm -f log.txt && timeout 60 ./spore gamedata 2>&1 | head -100"
    echo "=== fetching log"
    scp_get "$DEST/log.txt" ./device-log.txt 2>/dev/null && tail -80 ./device-log.txt
    ;;
esac
