#!/usr/bin/env bash
# Builds Firecracker with the flexvm patches into STATE/artifacts/firecracker.
# usage: build-firecracker.sh [--state DIR (/var/lib/flexvm)]
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
state=/var/lib/flexvm
if [ "${1:-}" = --state ]; then state=$(realpath -m "$2"); fi
# shellcheck source=versions.sh
source "$root/scripts/versions.sh"
src=${FC_SRC:-$root/build/firecracker-src}
stamp=$src/.flexvm-patched
patches=$(cd "$root/firecracker" && sha256sum -- *.patch)
# The checkout is redone when the version, the commit, a patch or this script changes.
patched=$(printf '%s %s\n%s\n%s\n' "$FC_VERSION" "$FC_COMMIT" "$patches" "$(sha256sum < "$root/scripts/build-firecracker.sh")")

# FC_VERSION's tag must still name FC_COMMIT: a moved tag fails the build instead of changing what it builds.
checked_out() {
  local head
  head=$(git -C "$src" rev-parse HEAD)
  if [ "$head" != "$FC_COMMIT" ]; then
    echo "$src is at $head, not FC_COMMIT $FC_COMMIT (scripts/versions.sh): has the $FC_VERSION tag moved?" >&2
    return 1
  fi
}

if [ ! -f "$stamp" ] || [ "$(cat "$stamp")" != "$patched" ]; then
  # Only replace our own checkout; a user-supplied FC_SRC is never deleted.
  if [ -n "${FC_SRC:-}" ] && [ -e "$src" ]; then
    echo "$src is not a $FC_VERSION tree patched by this script; remove it or unset FC_SRC" >&2
    exit 1
  fi
  rm -rf -- "$src"
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$FC_VERSION" https://github.com/firecracker-microvm/firecracker.git "$src"
  checked_out
  for p in "$root"/firecracker/*.patch; do
    patch -d "$src" -p1 < "$p"
  done
  printf '%s\n' "$patched" > "$stamp"
fi
checked_out

# musl-gcc does not search the system kernel headers; expose only those.
kh=$root/build/musl-kheaders
mkdir -p "$kh"
ln -sfn /usr/include/linux "$kh/linux"
ln -sfn /usr/include/asm-generic "$kh/asm-generic"
ln -sfn /usr/include/x86_64-linux-gnu/asm "$kh/asm"
export CFLAGS_x86_64_unknown_linux_musl="-idirafter $kh"

cd "$src"
# Where cargo puts the build: the environment overrides Firecracker's own
# .cargo/config.toml, so the binary is taken from the directory passed, never
# a stale one left in build/cargo_target.
target=${CARGO_TARGET_DIR:-${CARGO_BUILD_TARGET_DIR:-build/cargo_target}}
cargo build --release --target x86_64-unknown-linux-musl --target-dir "$target" -p firecracker
# Installed to temporary files beside their final paths, then renamed into place: a concurrent start never runs a
# half-copied binary, and an interrupted install never leaves a short one there. firecracker.custom records the build
# as this host's own: flexvm refuses a Firecracker there that is neither the pinned release's nor recorded.
built=$target/x86_64-unknown-linux-musl/release/firecracker
out=$state/artifacts
sudo mkdir -p "$out"
placing=$(sudo mktemp -p "$out" .firecracker.XXXXXX)
recording=$(sudo mktemp -p "$out" .firecracker.custom.XXXXXX)
trap 'sudo rm -f -- "$placing" "$recording"' EXIT
sudo install -m 755 "$built" "$placing"
printf '%s  built by scripts/build-firecracker.sh (%s %s, patches %s)\n' "$(sha256sum < "$built" | cut -d' ' -f1)" "$FC_VERSION" \
  "$FC_COMMIT" "$(cd "$root/firecracker" && cat -- *.patch | sha256sum | cut -c1-16)" | sudo tee "$recording" > /dev/null
sudo chmod 644 "$recording"
sudo mv -T "$recording" "$out/firecracker.custom"
sudo mv -T "$placing" "$out/firecracker"
trap - EXIT
"$target"/x86_64-unknown-linux-musl/release/firecracker --version
