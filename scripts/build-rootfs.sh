#!/usr/bin/env bash
# Builds STATE/artifacts/rootfs-<hash>.ext4: the base image (scripts/fetch.sh) plus flexvm-init
# as /sbin/flexvm-init, and points the rootfs.ext4 symlink beside it at it. Images are never rewritten:
# templates pin the file they were built from, so rebuilding is safe while VMs run.
# The image is attached read-only over virtio-pmem and mounted with DAX, so every VM
# on a host shares one copy of the root filesystem in the host page cache.
# usage: build-rootfs.sh [--state DIR (/var/lib/flexvm)]
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
state=/var/lib/flexvm
if [ "${1:-}" = --state ]; then state=$2; fi
out=$state/artifacts
cd "$root"
# A fixed default: a commit that leaves the image inputs alone keeps the same rootfs hash.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}

target=${CARGO_TARGET_DIR:-$root/target}
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -p flexvm-init --target x86_64-unknown-linux-gnu
# Also injected into templates built from container images (flexvm template --image).
sudo install -D -m 755 "$target"/x86_64-unknown-linux-gnu/release/flexvm-init "$out/flexvm-init"

work=$root/build/rootfs
sudo rm -rf "$work"
mkdir -p "$(dirname "$work")"
sudo unsquashfs -q -d "$work" "$out/base.squashfs"
sudo install -m 755 "$target"/x86_64-unknown-linux-gnu/release/flexvm-init "$work/sbin/flexvm-init"

# Size to the content plus headroom, rounded up to 2 MiB as virtio-pmem requires.
kib=$(sudo du -sk "$work" | cut -f1)
mib=$(( (kib * 12 / 10 / 1024 + 64 + 1) / 2 * 2 ))
tmp=$root/build/rootfs.$$.ext4
trap 'rm -f "$tmp"' EXIT
truncate -s "${mib}M" "$tmp"
# mkfs copies source timestamps, including the freshly installed init and directories.
# Do not follow symlinks: normalize the links themselves and stay inside the work tree.
sudo find "$work" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
# Fixed UUID, hash seed and timestamps, so the same inputs give the same image.
sudo E2FSPROGS_FAKE_TIME=1 mkfs.ext4 -q -b 4096 -d "$work" -L flexroot \
  -U 00000000-0000-4000-8000-000000000001 -E hash_seed=00000000-0000-4000-8000-000000000002 "$tmp"
# Older e2fsprogs (including CI's) copies ctimes without clamping them to an epoch.
# touch cannot set ctime, so normalize it in the image, including on symlinks.
sudo find "$work" -printf '%P\0' | while IFS= read -r -d '' path; do
  if [[ $path == *$'\n'* ]]; then
    echo "Cannot normalize an image path containing a newline" >&2
    exit 1
  fi
  # debugfs quotes a literal double quote by doubling it; backslashes are literal.
  path=${path//\"/\"\"}
  printf 'set_inode_field "/%s" ctime @%s\n' "$path" "$SOURCE_DATE_EPOCH"
done | sudo E2FSPROGS_FAKE_TIME=1 debugfs -w -f - "$tmp" > /dev/null
sudo chown "$(id -u):$(id -g)" "$tmp"
sudo rm -rf "$work"
img=rootfs-$(sha256sum "$tmp" | cut -c1-12).ext4
[ -e "$out/$img" ] || { sudo install -m 644 "$tmp" "$out/.$img" && sudo mv -T "$out/.$img" "$out/$img"; }
sudo ln -sfn "$img" "$out/.rootfs.link" && sudo mv -T "$out/.rootfs.link" "$out/rootfs.ext4"
ls -lh "$out/$img"
