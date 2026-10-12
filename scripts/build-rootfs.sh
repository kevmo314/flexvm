#!/usr/bin/env bash
# Builds artifacts/rootfs.ext4: the base image plus flexvm-init as /sbin/flexvm-init.
# The image is attached read-only over virtio-pmem and mounted with DAX, so every VM
# on a host shares one copy of the root filesystem in the host page cache.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -p flexvm-init --target x86_64-unknown-linux-gnu

work=$root/build/rootfs
sudo rm -rf "$work"
sudo unsquashfs -q -d "$work" artifacts/base.squashfs
sudo install -m 755 target/x86_64-unknown-linux-gnu/release/flexvm-init "$work/sbin/flexvm-init"

# Size to the content plus headroom, rounded up to 2 MiB as virtio-pmem requires.
kib=$(sudo du -sk "$work" | cut -f1)
mib=$(( (kib * 12 / 10 / 1024 + 64 + 1) / 2 * 2 ))
rm -f artifacts/rootfs.ext4
truncate -s "${mib}M" artifacts/rootfs.ext4
sudo mkfs.ext4 -q -b 4096 -d "$work" -L flexroot artifacts/rootfs.ext4
sudo chown "$(id -u):$(id -g)" artifacts/rootfs.ext4
sudo rm -rf "$work"
ls -lh artifacts/rootfs.ext4
