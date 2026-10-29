#!/usr/bin/env bash
# Build inside the WSL ext4 filesystem instead of over the 9p mount.
#
# /mnt/e is a Windows drive mounted through 9p: reading 240 MB of generated C++ and writing
# 227 object files through it is an order of magnitude slower than on ext4. This script
# mirrors the tree into /tmp, builds there, and copies the binary back.
#
#   ./wslbuild.sh            aarch64 build
#   ./wslbuild.sh host       host build (for the differential tests)
set -euo pipefail
cd "$(dirname "$0")"
TARGET="${1:-aarch64}"
WORK="${SR_WORK:-/tmp/sporebuild}"

mkdir -p "$WORK"
# Mirror only what the build needs; rsync -a keeps mtimes so incremental builds work.
rsync -a --delete src/ "$WORK/src/"
rsync -a --delete recomp/gen/ "$WORK/gen/"
cp build.sh check.sh "$WORK/"

cd "$WORK"
mkdir -p build
# Reuse the object directory from a previous run in this work dir.
[ -d "build/$TARGET" ] || mkdir -p "build/$TARGET"

echo "[wslbuild] building $TARGET in $WORK"
./build.sh "$TARGET" ${2:-}

OUT="$OLDPWD/build/$TARGET"
mkdir -p "$OUT"
cp "$WORK/build/$TARGET/spore" "$OUT/spore"
echo "[wslbuild] copied to build/$TARGET/spore"
