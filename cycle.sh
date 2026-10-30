#!/bin/bash
# Full regeneration + build + smoke test, in the right order.
#
#   ./cycle.sh              lift, build (-O0), smoke
#   ./cycle.sh --opt        lift, build (-O1), smoke
#   ./cycle.sh --no-lift    build + smoke only (runtime-only changes)
set -uo pipefail
cd /mnt/e/_DPT_Projects_E/_Harness/SporeRecomp || exit 1

OPT="${SR_OPT:--O0}"
LIFT=1
for arg in "$@"; do
  case "$arg" in
    --no-lift) LIFT=0 ;;
    --opt) OPT="-O1" ;;
  esac
done

export PYTHONIOENCODING=utf-8

# The lifter needs capstone, which is installed in the Windows Python. Run it through the
# interop path when we are inside WSL, and natively otherwise.
if grep -qi microsoft /proc/version 2>/dev/null; then
  PY="/mnt/c/Python311/python.exe"
else
  PY="${PY:-python3}"
fi

if [ "$LIFT" = "1" ]; then
  echo "=== lift ($PY)"
  "$PY" tools/lift.py | tail -3 || exit 1
  "$PY" tools/gen_import_table.py | tail -1 || exit 1
  echo "=== generated-code checks"
  "$PY" tools/check_labels.py | tail -3 || exit 1
fi

echo "=== build (generated code: $OPT)"
# Stale object files from a previous lift are a link error (duplicate definitions), so the
# object directory is cleared whenever the generated code changed.
if [ "$LIFT" = "1" ]; then
  rm -rf build/aarch64
fi
SR_OPT="$OPT" SR_JOBS="${SR_JOBS:-16}" ./build.sh aarch64 | tail -4 || exit 1

echo "=== smoke"
./smoke.sh -t "${SMOKE_TIMEOUT:-60}" 2>&1 | head -40
