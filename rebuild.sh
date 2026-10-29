#!/usr/bin/env bash
# Full regeneration pipeline: census -> lift -> import table -> build.
#
#   ./rebuild.sh              regenerate everything and build for aarch64
#   ./rebuild.sh --lift-only  skip the census (reuse analysis/census/)
#
# The census step is the slow one (linear sweep of 16.5 MB of code); once
# analysis/census/sweep.pkl exists it is reused.
set -euo pipefail
cd "$(dirname "$0")"
PY="${PY:-python3}"
export PYTHONIOENCODING=utf-8

LIFT_ONLY=0
[ "${1:-}" = "--lift-only" ] && LIFT_ONLY=1

if [ "$LIFT_ONLY" = "0" ]; then
  echo "=== 1/4 census"
  $PY tools/census.py
else
  echo "=== 1/4 census (skipped)"
fi

echo "=== 2/4 lift"
$PY tools/lift.py

echo "=== 3/4 import table"
$PY tools/gen_import_table.py

echo "=== 4/4 build"
./build.sh "${TARGET:-aarch64}"

echo "=== done: build/${TARGET:-aarch64}/spore"
