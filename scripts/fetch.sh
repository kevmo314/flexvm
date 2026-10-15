#!/usr/bin/env bash
# Downloads Firecracker, a guest kernel and a base rootfs into ./artifacts.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
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

out=$root/artifacts
mkdir -p "$out"
cd "$out"

temps=()
trap 'rm -rf -- "${temps[@]}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

download() {
  local target=$1 url=$2 tmp checksum
  checksum=$(awk -v url="$url" '$2 == url {print $1}' "$root/scripts/checksums.sha256")
  if [[ ! $checksum =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "No pinned SHA256 for $url; update scripts/checksums.sha256" >&2
    return 1
  fi
  tmp=$(mktemp "$target.XXXXXX")
  temps+=("$tmp")
  curl -fsSL -o "$tmp" "$url"
  if ! printf '%s  %s\n' "$checksum" "$tmp" | sha256sum --check --status; then
    echo "SHA256 mismatch for $url" >&2
    return 1
  fi
  mv -f "$tmp" "$target"
}

if [ ! -x firecracker ]; then
  echo "fetching firecracker $FC_VERSION"
  tmp=$(mktemp -d ./firecracker.XXXXXX)
  temps+=("$tmp")
  download "$tmp/firecracker.tgz" "$FC_URL"
  tar xzf "$tmp/firecracker.tgz" -C "$tmp"
  mv "$tmp/release-$FC_VERSION-$ARCH/firecracker-$FC_VERSION-$ARCH" firecracker
fi

if [ ! -f vmlinux ]; then
  echo "fetching $KERNEL"
  download vmlinux "$CI/$KERNEL"
fi

if [ ! -f base.squashfs ]; then
  echo "fetching ubuntu-24.04 rootfs"
  download base.squashfs "$CI/ubuntu-24.04.squashfs"
fi

ls -lh "$out"
