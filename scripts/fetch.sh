#!/usr/bin/env bash
# Downloads Firecracker, a guest kernel and a base rootfs into STATE/artifacts. Once scripts/checksums.sha256
# pins the flexvm artifacts release (scripts/versions.sh), Firecracker (patched) and the kernel come from it;
# until then, the kernel comes from Firecracker's CI bucket and Firecracker is the stock release. flexvm itself
# downloads the release's on first use; this is for fetching ahead (an offline host, say: --state a directory
# to copy over).
# usage: fetch.sh [--state DIR (${FLEXVM_STATE_DIR:-/var/lib/flexvm})] [--urls | --kernel (the kernel only)]
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
state=$(realpath -m "${FLEXVM_STATE_DIR:-/var/lib/flexvm}")
mode=
while (( $# )); do
  case "$1" in
    --state)
      if (( $# < 2 )) || [[ $2 == --* ]]; then echo '--state needs a directory' >&2; exit 2; fi
      state=$(realpath -m "$2")
      shift 2
      ;;
    --urls|--kernel)
      if [ -n "$mode" ]; then echo 'choose only one of --urls or --kernel' >&2; exit 2; fi
      mode=$1
      shift
      ;;
    *) echo 'usage: fetch.sh [--state DIR] [--urls | --kernel]' >&2; exit 2 ;;
  esac
done
# shellcheck source=versions.sh
source "$root/scripts/versions.sh"

if pinned "$ARTIFACTS_URL/firecracker" > /dev/null; then
  FC_URL=$ARTIFACTS_URL/firecracker
else
  [ "$?" = 2 ] || exit 1
  FC_URL=https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-$ARCH.tgz
fi
KERNEL_URL=$CI/$KERNEL
if pinned "$ARTIFACTS_URL/vmlinux" > /dev/null; then
  KERNEL_URL=$ARTIFACTS_URL/vmlinux
else
  [ "$?" = 2 ] || exit 1
fi

# --urls: print what would be fetched, as `NAME URL` lines (CI keys its caches on them).
if [ "$mode" = --urls ]; then
  printf '%s %s\n' firecracker "$FC_URL" vmlinux "$KERNEL_URL" base.squashfs "$CI/ubuntu-24.04.squashfs"
  exit 0
fi
only_kernel=
if [ "$mode" = --kernel ]; then only_kernel=1; fi

out=$state/artifacts
sudo mkdir -p "$out"
work= placing=
trap 'rm -rf -- "$work"; [ -z "$placing" ] || sudo rm -f -- "$placing"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
work=$(mktemp -d)

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
# Recorded after installation in NAME.sha256: a build pinning no release goes by the record alone.
place() {
  local checksum
  placing=$(sudo mktemp -p "$out" ".$3.XXXXXX")
  sudo install -m "$1" "$2" "$placing"
  checksum=$(sudo sha256sum "$placing" | cut -d' ' -f1)
  sudo mv -T "$placing" "$out/$3"
  placing=
  record "$3" "$checksum" "$4"
}

# NAME.sha256: SHA256, which was checked against URL's pin.
record() {
  placing=$(sudo mktemp -p "$out" ".$1.sha256.XXXXXX")
  printf '%s  fetched by scripts/fetch.sh, checked against the pin of %s\n' "$2" "$3" | sudo tee "$placing" > /dev/null
  sudo chmod 644 "$placing"
  sudo mv -T "$placing" "$out/$1.sha256"
  placing=
}

# A local build is kept only if its record checks; an unrecorded stock binary is fetched and verified again.
firecracker_fetched() {
  if [[ $FC_URL != *.tgz ]]; then fetched firecracker "$FC_URL"; return; fi
  local checksum
  checksum=$(sudo awk 'NR == 1 {print $1}' "$out/firecracker.sha256" 2> /dev/null) || checksum=
  if ! [[ $checksum =~ ^[[:xdigit:]]{64}$ ]] || ! printf '%s  %s\n' "$checksum" "$out/firecracker" | sudo sha256sum --check --status; then
    echo "$out/firecracker is not recorded in firecracker.sha256; fetching it again"
    return 1
  fi
}

if [ -z "$only_kernel" ]; then
  # Serialize the check and install with local builds, including their checksum records.
  sudo touch "$out/.firecracker.lock"
  sudo chmod 644 "$out/.firecracker.lock"
  exec {lock}< "$out/.firecracker.lock"
  flock -x "$lock"
  if sudo test -x "$out/firecracker" && firecracker_fetched; then
    # A raw release asset was checked just now, even if fetched before records were kept.
    if [[ $FC_URL != *.tgz ]]; then record firecracker "$(pinned "$FC_URL")" "$FC_URL"; fi
  else
    echo "fetching firecracker from $FC_URL"
    if [[ $FC_URL == *.tgz ]]; then
      download firecracker.tgz "$FC_URL"
      tar xzf "$work/firecracker.tgz" -C "$work"
      place 755 "$work/release-$FC_VERSION-$ARCH/firecracker-$FC_VERSION-$ARCH" firecracker "$FC_URL"
    else
      download firecracker "$FC_URL"
      place 755 "$work/firecracker" firecracker "$FC_URL"
    fi
  fi
  exec {lock}<&-
fi

if ! fetched vmlinux "$KERNEL_URL"; then
  echo "fetching $KERNEL from $KERNEL_URL"
  download vmlinux "$KERNEL_URL"
  place 644 "$work/vmlinux" vmlinux "$KERNEL_URL"
else
  # Checked just now (and perhaps fetched before records were kept).
  record vmlinux "$(pinned "$KERNEL_URL")" "$KERNEL_URL"
fi

if [ -z "$only_kernel" ] && ! fetched base.squashfs "$CI/ubuntu-24.04.squashfs"; then
  echo "fetching ubuntu-24.04 rootfs"
  download base.squashfs "$CI/ubuntu-24.04.squashfs"
  place 644 "$work/base.squashfs" base.squashfs "$CI/ubuntu-24.04.squashfs"
fi

sudo ls -lh "$out"
