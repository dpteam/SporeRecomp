#!/usr/bin/env bash
# Syntax-check every hand-written runtime source (fast; no code generation).
set -uo pipefail
cd "$(dirname "$0")"
CXX="${CXX:-aarch64-linux-gnu-g++}"
fail=0
for f in src/main.cpp src/rt/*.cpp src/rt/win32/*.cpp; do
  out=$($CXX -std=c++20 -O1 -Isrc -Irecomp/gen -fsyntax-only "$f" 2>&1)
  if [ -n "$out" ]; then
    echo "=== $f"
    echo "$out" | head -15
    fail=1
  fi
done
if [ $fail -eq 0 ]; then echo "[check] all runtime sources compile"; fi
exit $fail
