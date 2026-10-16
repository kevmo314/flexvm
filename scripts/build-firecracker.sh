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
patched=$(printf '%s\n%s\n' "$FC_VERSION" "$patches")

if [ ! -f "$stamp" ] || [ "$(cat "$stamp")" != "$patched" ]; then
  # Only replace our own checkout; a user-supplied FC_SRC is never deleted.
  if [ -n "${FC_SRC:-}" ] && [ -e "$src" ]; then
    echo "$src is not a $FC_VERSION tree patched by this script; remove it or unset FC_SRC" >&2
    exit 1
  fi
  rm -rf -- "$src"
  git clone -q --depth 1 --branch "$FC_VERSION" https://github.com/firecracker-microvm/firecracker.git "$src"
  for p in "$root"/firecracker/*.patch; do
    patch -d "$src" -p1 < "$p"
  done
  printf '%s\n' "$patched" > "$stamp"
fi

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
sudo install -D -m 755 "$target"/x86_64-unknown-linux-musl/release/firecracker "$state/artifacts/firecracker"
"$target"/x86_64-unknown-linux-musl/release/firecracker --version
