#!/usr/bin/env bash
# Downloads Firecracker, a guest kernel and a base rootfs into ./artifacts.
set -euo pipefail

FC_VERSION=${FC_VERSION:-v1.17.0}
CI_VERSION=${CI_VERSION:-v1.15}
KERNEL=${KERNEL:-vmlinux-6.1.155}
ARCH=x86_64
CI=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/$CI_VERSION/$ARCH

root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/artifacts
mkdir -p "$out"
cd "$out"

temps=()
trap 'rm -rf -- "${temps[@]}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

download() {
  local target=$1 url=$2 tmp
  tmp=$(mktemp "./$target.XXXXXX")
  temps+=("$tmp")
  curl -fsSL -o "$tmp" "$url"
  mv -f "$tmp" "$target"
}

if [ ! -x firecracker ]; then
  echo "fetching firecracker $FC_VERSION"
  tmp=$(mktemp -d ./firecracker.XXXXXX)
  temps+=("$tmp")
  curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-$ARCH.tgz" | tar xz -C "$tmp"
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
