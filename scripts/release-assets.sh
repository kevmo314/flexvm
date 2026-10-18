#!/usr/bin/env bash
# The artifacts release's build recipe: .github/workflows/release.yml runs this on a fresh runner to build the
# assets into OUT, using STATE as a scratch state directory. release.yml, this file and the scripts it runs are
# hashed into the release's inputs.txt (scripts/pin-artifacts.sh --inputs), so a change to how a release is built
# needs a new ARTIFACTS_TAG, as a change to what it is built from does.
# usage: release-assets.sh STATE OUT
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
state=$(realpath -m "$1")
out=$(realpath -m "$2")

# Firecracker builds with the toolchain its own rust-toolchain.toml (at FC_COMMIT) pins; rustup installs it.
sudo apt-get update -q
sudo apt-get install -y -q --no-install-recommends musl-tools libseccomp-dev
"$root/scripts/build-firecracker.sh" --state "$state"
# The kernel is re-hosted, not built: the pinned upstream one.
"$root/scripts/fetch.sh" --state "$state" --kernel

mkdir -p "$out"
install -m 755 "$state/artifacts/firecracker" "$out/firecracker"
install -m 644 "$state/artifacts/vmlinux" "$out/vmlinux"
"$root/scripts/pin-artifacts.sh" --inputs > "$out/inputs.txt"
(cd "$out" && sha256sum firecracker vmlinux inputs.txt > SHA256SUMS)
"$out/firecracker" --version
cat "$out/inputs.txt" "$out/SHA256SUMS"
