#!/bin/bash
# Inspect the guest state at the free-list crash under gdb.
set -uo pipefail
cd /mnt/e/_DPT_Projects_E/_Harness/SporeRecomp/build/debug || exit 1
CMD=/mnt/c/Users/DartPower/AppData/Local/Temp/gdb1.txt
# Break on the faulting block: sub_009275f4 is the mid-entry for that address if it exists;
# otherwise break on the store that faults.
timeout 200 gdb -q -batch -x "$CMD" ./spore 2>&1 | tail -40
