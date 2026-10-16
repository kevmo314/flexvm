#!/usr/bin/env bash
# Downloads Firecracker, a guest kernel and a base rootfs into STATE/artifacts.
# usage: fetch.sh [--state DIR (/var/lib/flexvm)] [--urls]
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
state=/var/lib/flexvm
if [ "${1:-}" = --state ]; then state=$(realpath -m "$2"); shift 2; fi
# shellcheck source=versions.sh
source "$root/scripts/versions.sh"
CI_VERSION=${CI_VERSION:-v1.15}
KERNEL=${KERNEL:-vmlinux-6.1.155}
ARCH=x86_64
CI=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/$CI_VERSION/$ARCH

FC_URL=https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-$ARCH.tgz

# --urls: print what would be fetched, as `NAME URL` lines (CI keys its caches on them).
if [ "${1:-}" = --urls ]; then
  printf '%s %s\n' firecracker "$FC_URL" vmlinux "$CI/$KERNEL" base.squashfs "$CI/ubuntu-24.04.squashfs"
  exit 0
fi

out=$state/artifacts
sudo mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A download into $work, checked against its pinned SHA256.
download() {
  local target=$work/$1 url=$2 checksum
  checksum=$(awk -v url="$url" '$2 == url {print $1}' "$root/scripts/checksums.sha256")
  if [[ ! $checksum =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "No pinned SHA256 for $url; update scripts/checksums.sha256" >&2
    return 1
  fi
  curl -fsSL -o "$target" "$url"
  if ! printf '%s  %s\n' "$checksum" "$target" | sha256sum --check --status; then
    echo "SHA256 mismatch for $url" >&2
    return 1
  fi
}

# Installed beside its final path, then renamed into place: an interrupted
# install never leaves a short file there for later runs to take as fetched.
place() {
  sudo install -m "$1" "$2" "$out/.$3.tmp"
  sudo mv -T "$out/.$3.tmp" "$out/$3"
}

if ! sudo test -x "$out/firecracker"; then
  echo "fetching firecracker $FC_VERSION"
  download firecracker.tgz "$FC_URL"
  tar xzf "$work/firecracker.tgz" -C "$work"
  place 755 "$work/release-$FC_VERSION-$ARCH/firecracker-$FC_VERSION-$ARCH" firecracker
fi

if ! sudo test -f "$out/vmlinux"; then
  echo "fetching $KERNEL"
  download vmlinux "$CI/$KERNEL"
  place 644 "$work/vmlinux" vmlinux
fi

if ! sudo test -f "$out/base.squashfs"; then
  echo "fetching ubuntu-24.04 rootfs"
  download base.squashfs "$CI/ubuntu-24.04.squashfs"
  place 644 "$work/base.squashfs" base.squashfs
fi

sudo ls -lh "$out"
