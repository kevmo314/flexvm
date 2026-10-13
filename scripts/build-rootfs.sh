#!/usr/bin/env bash
# Builds artifacts/rootfs-<hash>.ext4: the base image plus flexvm-init as /sbin/flexvm-init,
# and points the artifacts/rootfs.ext4 symlink at it. Images are never rewritten:
# templates pin the file they were built from, so rebuilding is safe while VMs run.
# The image is attached read-only over virtio-pmem and mounted with DAX, so every VM
# on a host shares one copy of the root filesystem in the host page cache.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -p flexvm-init --target x86_64-unknown-linux-gnu
# Also injected into templates built from container images (flexvm template --image).
install -m 755 target/x86_64-unknown-linux-gnu/release/flexvm-init artifacts/flexvm-init

work=$root/build/rootfs
sudo rm -rf "$work"
sudo unsquashfs -q -d "$work" artifacts/base.squashfs
sudo install -m 755 target/x86_64-unknown-linux-gnu/release/flexvm-init "$work/sbin/flexvm-init"

# Size to the content plus headroom, rounded up to 2 MiB as virtio-pmem requires.
kib=$(sudo du -sk "$work" | cut -f1)
mib=$(( (kib * 12 / 10 / 1024 + 64 + 1) / 2 * 2 ))
tmp=artifacts/.rootfs.$$.ext4
trap 'rm -f "$tmp"' EXIT
truncate -s "${mib}M" "$tmp"
# Fixed UUID, hash seed and timestamps, so the same inputs give the same image.
sudo E2FSPROGS_FAKE_TIME=1 mkfs.ext4 -q -b 4096 -d "$work" -L flexroot \
  -U 00000000-0000-4000-8000-000000000001 -E hash_seed=00000000-0000-4000-8000-000000000002 "$tmp"
sudo chown "$(id -u):$(id -g)" "$tmp"
sudo rm -rf "$work"
out=artifacts/rootfs-$(sha256sum "$tmp" | cut -c1-12).ext4
mv "$tmp" "$out"
ln -sfn "$(basename "$out")" artifacts/.rootfs.link && mv -T artifacts/.rootfs.link artifacts/rootfs.ext4
ls -lh "$out"
