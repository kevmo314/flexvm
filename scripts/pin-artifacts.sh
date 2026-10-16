#!/usr/bin/env bash
# The prebuilt artifacts release (ARTIFACTS_TAG in scripts/versions.sh, built by .github/workflows/release.yml).
# usage: pin-artifacts.sh            downloads the release's assets, verifies their build provenance (release.yml at
#                                    the release's tag, attested by GitHub; needs gh), checks they were built from
#                                    this checkout's inputs, and pins them in scripts/checksums.sha256 (commit it).
#                                    Nothing downloaded is ever run.
#        pin-artifacts.sh --inputs   prints what a release is built from (the release's inputs.txt)
#        pin-artifacts.sh --check    fails unless every asset of ARTIFACTS_TAG is pinned and the release was built
#                                    from this checkout's inputs
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=versions.sh
source "$root/scripts/versions.sh"
checksums=$root/scripts/checksums.sha256
REPO=kevmo314/flexvm
ASSETS=(firecracker vmlinux inputs.txt)

# The pinned SHA256 of a URL, if any.
pinned() {
  awk -v url="$1" '$2 == url {print $1}' "$checksums"
}

# Firecracker's version and patches, and the kernel, by content.
inputs() {
  local kernel
  kernel=$(pinned "$CI/$KERNEL")
  if [[ ! $kernel =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "No pinned SHA256 for $CI/$KERNEL in scripts/checksums.sha256" >&2
    return 1
  fi
  printf 'firecracker %s %s\n' "$FC_VERSION" "$ARCH"
  (cd "$root/firecracker" && sha256sum -- *.patch)
  printf 'vmlinux %s %s\n' "$kernel" "$KERNEL"
}

case "${1:-}" in
  --inputs)
    inputs
    exit 0
    ;;
  --check)
    for asset in "${ASSETS[@]}"; do
      if [[ ! $(pinned "$ARTIFACTS_URL/$asset") =~ ^[[:xdigit:]]{64}$ ]]; then
        echo "$ARTIFACTS_URL/$asset is not pinned in scripts/checksums.sha256: flexvm builds from this checkout download nothing (run scripts/pin-artifacts.sh once the release exists)" >&2
        exit 1
      fi
    done
    want=$(pinned "$ARTIFACTS_URL/inputs.txt")
    if [ "$(inputs | sha256sum | cut -d' ' -f1)" != "$want" ]; then
      echo "The pinned release $ARTIFACTS_TAG was built from other Firecracker patches, version or kernel than this checkout's: bump ARTIFACTS_TAG in scripts/versions.sh, push the new tag, and run scripts/pin-artifacts.sh" >&2
      exit 1
    fi
    echo "$ARTIFACTS_TAG matches this checkout's inputs"
    exit 0
    ;;
  "") ;;
  *)
    echo "usage: pin-artifacts.sh [--inputs | --check]" >&2
    exit 2
    ;;
esac

command -v gh > /dev/null || { echo "pinning needs gh (GitHub CLI) to verify the assets' build provenance" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
for asset in "${ASSETS[@]}"; do
  echo "downloading $ARTIFACTS_URL/$asset"
  # Never executable: nothing downloaded here is run.
  curl -fsSL -o "$work/$asset" "$ARTIFACTS_URL/$asset"
  chmod 644 "$work/$asset"
done
# Each asset must have been built by this repository's release workflow, from this tag, on a GitHub-hosted runner.
for asset in "${ASSETS[@]}"; do
  echo "verifying the build provenance of $asset"
  gh attestation verify "$work/$asset" --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release.yml" \
    --source-ref "refs/tags/$ARTIFACTS_TAG" --deny-self-hosted-runners > /dev/null
done
if ! inputs | cmp -s - "$work/inputs.txt"; then
  echo "$ARTIFACTS_TAG was built from other inputs than this checkout's:" >&2
  inputs | diff - "$work/inputs.txt" >&2 || true
  exit 1
fi
# The kernel is re-hosted, not built: it must be the pinned upstream one.
if [ "$(sha256sum < "$work/vmlinux" | cut -d' ' -f1)" != "$(pinned "$CI/$KERNEL")" ]; then
  echo "$ARTIFACTS_URL/vmlinux is not the pinned $CI/$KERNEL" >&2
  exit 1
fi
# What Firecracker is, from the attested inputs.txt (never by running it).
head -1 "$work/inputs.txt"

# This release's lines replace any it had; other lines stay.
{
  awk -v base="$ARTIFACTS_URL/" 'index($2, base) != 1' "$checksums"
  for asset in "${ASSETS[@]}"; do
    printf '%s %s\n' "$(sha256sum < "$work/$asset" | cut -d' ' -f1)" "$ARTIFACTS_URL/$asset"
  done
} > "$work/checksums"
cat "$work/checksums" > "$checksums"
echo "pinned $ARTIFACTS_TAG in scripts/checksums.sha256; commit it"
