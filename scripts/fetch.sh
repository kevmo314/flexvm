#!/usr/bin/env bash
# Downloads Firecracker, a guest kernel and a base rootfs into STATE/artifacts. Once scripts/checksums.sha256
# pins the flexvm artifacts release (scripts/versions.sh), Firecracker (patched) and the kernel come from it;
# until then, the kernel comes from Firecracker's CI bucket and Firecracker is the stock release. flexvm itself
# downloads the release's on first use; this is for fetching ahead (an offline host, say: --state a directory
# to copy over).
# usage: fetch.sh [--state DIR (/var/lib/flexvm)] [--urls | --kernel (the kernel only)]
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
state=/var/lib/flexvm
if [ "${1:-}" = --state ]; then state=$(realpath -m "$2"); shift 2; fi
# shellcheck source=versions.sh
source "$root/scripts/versions.sh"

# The pinned SHA256 of a URL.
pinned() {
  local checksum
  checksum=$(awk -v url="$1" '$2 == url {print $1}' "$root/scripts/checksums.sha256")
  if [[ ! $checksum =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "No pinned SHA256 for $1; update scripts/checksums.sha256" >&2
    return 1
  fi
  echo "$checksum"
}

if pinned "$ARTIFACTS_URL/firecracker" > /dev/null 2>&1; then
  FC_URL=$ARTIFACTS_URL/firecracker
else
  FC_URL=https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-$ARCH.tgz
fi
KERNEL_URL=$CI/$KERNEL
if pinned "$ARTIFACTS_URL/vmlinux" > /dev/null 2>&1; then KERNEL_URL=$ARTIFACTS_URL/vmlinux; fi

# --urls: print what would be fetched, as `NAME URL` lines (CI keys its caches on them).
if [ "${1:-}" = --urls ]; then
  printf '%s %s\n' firecracker "$FC_URL" vmlinux "$KERNEL_URL" base.squashfs "$CI/ubuntu-24.04.squashfs"
  exit 0
fi
only_kernel=
if [ "${1:-}" = --kernel ]; then only_kernel=1; fi

out=$state/artifacts
sudo mkdir -p "$out"
work=$(mktemp -d)
placing=
trap 'rm -rf -- "$work"; [ -z "$placing" ] || sudo rm -f -- "$placing"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A download into $work, checked against its pinned SHA256.
download() {
  local target=$work/$1 url=$2 checksum
  checksum=$(pinned "$url") || return 1
  curl -fsSL -o "$target" "$url"
  if ! printf '%s  %s\n' "$checksum" "$target" | sha256sum --check --status; then
    echo "SHA256 mismatch for $url" >&2
    return 1
  fi
}

# Whether $out/NAME is there and matches URL's pinned SHA256; one that does
# not (cut short by an older fetch, say) is fetched again.
fetched() {
  local checksum
  checksum=$(pinned "$2") || return 1
  sudo test -f "$out/$1" || return 1
  if ! printf '%s  %s\n' "$checksum" "$out/$1" | sudo sha256sum --check --status; then
    echo "$out/$1 does not match its pinned SHA256; fetching it again"
    return 1
  fi
}

# Installed to a temporary file of this run's own beside its final path, then
# renamed into place: an interrupted install never leaves a short file there,
# and concurrent fetches never rename each other's.
place() {
  placing=$(sudo mktemp -p "$out" ".$3.XXXXXX")
  sudo install -m "$1" "$2" "$placing"
  sudo mv -T "$placing" "$out/$3"
  placing=
}

if [ -z "$only_kernel" ] && ! sudo test -x "$out/firecracker"; then
  echo "fetching firecracker from $FC_URL"
  if [[ $FC_URL == *.tgz ]]; then
    download firecracker.tgz "$FC_URL"
    tar xzf "$work/firecracker.tgz" -C "$work"
    place 755 "$work/release-$FC_VERSION-$ARCH/firecracker-$FC_VERSION-$ARCH" firecracker
  else
    download firecracker "$FC_URL"
    place 755 "$work/firecracker" firecracker
  fi
fi

if ! fetched vmlinux "$KERNEL_URL"; then
  echo "fetching $KERNEL from $KERNEL_URL"
  download vmlinux "$KERNEL_URL"
  place 644 "$work/vmlinux" vmlinux
fi

if [ -z "$only_kernel" ] && ! fetched base.squashfs "$CI/ubuntu-24.04.squashfs"; then
  echo "fetching ubuntu-24.04 rootfs"
  download base.squashfs "$CI/ubuntu-24.04.squashfs"
  place 644 "$work/base.squashfs" base.squashfs
fi

sudo ls -lh "$out"
