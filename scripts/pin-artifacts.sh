#!/usr/bin/env bash
# The prebuilt artifacts release (ARTIFACTS_TAG in scripts/versions.sh, built by .github/workflows/release.yml).
# usage: pin-artifacts.sh            downloads the release's assets, verifies their build provenance (release.yml at
#                                    the release's tag, whose commit must be in this checkout's history, attested by
#                                    GitHub; needs gh), checks they were built from this checkout's inputs, and pins
#                                    them in scripts/checksums.sha256 (commit it). Nothing downloaded is ever run.
#        pin-artifacts.sh --inputs   prints what a release is built from (the release's inputs.txt): Firecracker's
#                                    version, commit and patches, the build recipe and runner image, and the kernel
#        pin-artifacts.sh --check    whether ARTIFACTS_TAG is pinned and was built from this checkout's inputs; exits
#                                    0 if so; 1 if it is stale (pinned, or released, from other inputs: bump
#                                    ARTIFACTS_TAG) or its pins are broken; 3 if it is pending (not pinned yet, and
#                                    not released from other inputs) since the commit that named it, less than
#                                    RELEASE_WINDOW_HOURS ago; 4 if pending for longer (or for how long is unknown).
#                                    CI fails on 1 everywhere and on 4 on main (RELEASING in README.md).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=versions.sh
source "$root/scripts/versions.sh"
checksums=$root/scripts/checksums.sha256
REPO=kevmo314/flexvm
ASSETS=(firecracker vmlinux inputs.txt)
# How long main may name an unpinned ARTIFACTS_TAG: tag, release and pin take well under an hour.
RELEASE_WINDOW_HOURS=24

# The pinned SHA256 of a URL, if any.
pinned() {
  awk -v url="$1" '$2 == url {print $1}' "$checksums"
}

# What a release is built from, by content: Firecracker's version, the commit its tag names and the patches; the
# recipe (scripts/release-assets.sh, which build-firecracker.sh does the build for) and the runner image release.yml
# runs it on; and the kernel.
inputs() {
  local kernel runner
  kernel=$(pinned "$CI/$KERNEL")
  if [[ ! $kernel =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "No pinned SHA256 for $CI/$KERNEL in scripts/checksums.sha256" >&2
    return 1
  fi
  runner=$(awk '$1 == "runs-on:" {print $2}' "$root/.github/workflows/release.yml")
  if [[ ! $runner =~ ^[[:alnum:].-]+$ ]]; then
    echo "release.yml must have one runs-on: line, naming a runner image" >&2
    return 1
  fi
  printf 'firecracker %s %s\n' "$FC_VERSION" "$ARCH"
  printf 'commit %s\n' "$FC_COMMIT"
  (cd "$root/firecracker" && sha256sum -- *.patch)
  (cd "$root" && sha256sum scripts/release-assets.sh scripts/build-firecracker.sh)
  printf 'runner %s\n' "$runner"
  printf 'vmlinux %s %s\n' "$kernel" "$KERNEL"
}

# Not pinned yet: stale if the release exists and was built from other inputs, else pending, for how long since
# the commit that named ARTIFACTS_TAG.
pending() {
  local released since age
  released=$(curl -fsSL --max-time 30 "$ARTIFACTS_URL/inputs.txt" 2> /dev/null) || released=
  if [ -n "$released" ] && [ "$released" != "$(inputs)" ]; then
    echo "$ARTIFACTS_TAG is released, but from other inputs than this checkout's: bump ARTIFACTS_TAG in scripts/versions.sh (RELEASING in README.md)" >&2
    inputs | diff - <(printf '%s\n' "$released") >&2 || true
    return 1
  fi
  if [ -n "$released" ]; then
    echo "$ARTIFACTS_TAG is released from this checkout's inputs but not pinned yet: run scripts/pin-artifacts.sh and commit it" >&2
  else
    echo "$ARTIFACTS_TAG is not released yet: push its tag at the commit on main that names it, then run scripts/pin-artifacts.sh (RELEASING in README.md)" >&2
  fi
  if [ "$(git -C "$root" rev-parse --is-shallow-repository 2> /dev/null)" != false ]; then
    echo "for how long is unknown: this is not a full clone" >&2
    return 4
  fi
  since=$(git -C "$root" log -1 --format=%ct -G '^ARTIFACTS_TAG=' -- scripts/versions.sh)
  age=$(( ($(date +%s) - ${since:-0}) / 3600 ))
  echo "pending for ${age} h (the window is ${RELEASE_WINDOW_HOURS} h)" >&2
  if [ "$age" -ge "$RELEASE_WINDOW_HOURS" ]; then return 4; fi
  return 3
}

case "${1:-}" in
  --inputs)
    inputs
    exit 0
    ;;
  --check)
    pins=0
    for asset in "${ASSETS[@]}"; do
      if [[ $(pinned "$ARTIFACTS_URL/$asset") =~ ^[[:xdigit:]]{64}$ ]]; then pins=$((pins + 1)); fi
    done
    if [ "$pins" = 0 ]; then
      status=0
      pending || status=$?
      exit "$status"
    fi
    if [ "$pins" != "${#ASSETS[@]}" ]; then
      echo "scripts/checksums.sha256 pins only some of $ARTIFACTS_TAG's assets (${ASSETS[*]}): run scripts/pin-artifacts.sh" >&2
      exit 1
    fi
    want=$(pinned "$ARTIFACTS_URL/inputs.txt")
    if [ "$(inputs | sha256sum | cut -d' ' -f1)" != "$want" ]; then
      echo "The pinned release $ARTIFACTS_TAG was built from other inputs than this checkout's (scripts/pin-artifacts.sh --inputs): bump ARTIFACTS_TAG in scripts/versions.sh in the same change (RELEASING in README.md)" >&2
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
# The commit the tag names must be in this checkout's history (reviewed, on main): a tag pushed at any other commit
# would have run that commit's release.yml, recipe and patches, and written its own inputs.txt.
tagged=$(git ls-remote "https://github.com/$REPO.git" "refs/tags/$ARTIFACTS_TAG^{}" "refs/tags/$ARTIFACTS_TAG" |
  awk -v t="refs/tags/$ARTIFACTS_TAG" '$2 == t "^{}" {p = $1} $2 == t {l = $1} END {print (p != "" ? p : l)}')
if [[ ! $tagged =~ ^[[:xdigit:]]{40}$ ]]; then
  echo "no tag $ARTIFACTS_TAG in $REPO" >&2
  exit 1
fi
if ! git -C "$root" merge-base --is-ancestor "$tagged" HEAD 2> /dev/null; then
  echo "$ARTIFACTS_TAG names $tagged, which is not in this checkout's history (fetch main, or the tag is not main's)" >&2
  exit 1
fi
# Each asset must have been built by this repository's release workflow, from this tag at that commit, on a
# GitHub-hosted runner.
for asset in "${ASSETS[@]}"; do
  echo "verifying the build provenance of $asset"
  gh attestation verify "$work/$asset" --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release.yml" \
    --source-ref "refs/tags/$ARTIFACTS_TAG" --source-digest "$tagged" --deny-self-hosted-runners > /dev/null
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
