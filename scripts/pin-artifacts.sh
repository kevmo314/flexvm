#!/usr/bin/env bash
# The semver prebuilt artifacts release (vMAJOR.MINOR.PATCH; ARTIFACTS_TAG in scripts/versions.sh, built by .github/workflows/release.yml).
# usage: pin-artifacts.sh            downloads the release's assets, verifies their build provenance (release.yml at
#                                    the release's tag, whose commit must be in this checkout's history, attested by
#                                    GitHub; needs gh), checks they were built from this checkout's inputs, and pins
#                                    them in scripts/checksums.sha256 (commit it). Nothing downloaded is ever run.
#        pin-artifacts.sh --inputs   prints what a release is built from (the release's inputs.txt): Firecracker's
#                                    version, commit and patches, the build recipe (release.yml and the scripts it
#                                    runs), and the kernel
#        pin-artifacts.sh --check    whether ARTIFACTS_TAG is pinned and was built from this checkout's inputs; exits
#                                    0 if so; 1 if it is stale (pinned, or tagged at a commit, with other inputs:
#                                    bump ARTIFACTS_TAG), its pins are broken, or the tag cannot be looked up; 3 if
#                                    it is pending (not pinned yet, and not tagged at other inputs) since it came to
#                                    name it on this branch less than RELEASE_WINDOW_HOURS ago; 4 if pending for
#                                    longer (or for how long is unknown).
#                                    CI fails on 1 everywhere and on 4 on main (RELEASING in README.md).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=versions.sh
source "$root/scripts/versions.sh"
if ! [[ $ARTIFACTS_TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ARTIFACTS_TAG must use vMAJOR.MINOR.PATCH (e.g. v0.2.0), not $ARTIFACTS_TAG" >&2
  exit 1
fi
checksums=$root/scripts/checksums.sha256
REPO=numerataz/flexvm
ASSETS=(firecracker vmlinux inputs.txt)
# How long main may name an unpinned ARTIFACTS_TAG: tag, release and pin take well under an hour.
RELEASE_WINDOW_HOURS=24

# What a release is built from, by content: Firecracker's version, the commit its tag names and the patches; the
# recipe (release.yml, which runs scripts/release-assets.sh, which runs build-firecracker.sh and fetch.sh); and the
# kernel.
inputs() {
  local kernel
  kernel=$(pinned "$CI/$KERNEL") || return 1
  # Each failure returns explicitly: callers test this in conditions, where errexit is off.
  printf 'firecracker %s %s\n' "$FC_VERSION" "$ARCH" || return 1
  printf 'commit %s\n' "$FC_COMMIT" || return 1
  (cd "$root/firecracker" && sha256sum -- *.patch) || return 1
  (cd "$root" && sha256sum .github/workflows/release.yml scripts/release-assets.sh scripts/build-firecracker.sh scripts/fetch.sh scripts/versions.sh) || return 1
  printf 'vmlinux %s %s\n' "$kernel" "$KERNEL"
}

# The commit ARTIFACTS_TAG names upstream; returns 2 if there is no such tag, 1 if that cannot be told.
tag_commit() {
  local refs status=0
  refs=$(git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=30 ls-remote --exit-code "https://github.com/$REPO.git" "refs/tags/$ARTIFACTS_TAG" "refs/tags/$ARTIFACTS_TAG^{}") || status=$?
  if [ "$status" = 2 ]; then return 2; fi
  if [ "$status" != 0 ]; then
    echo "cannot tell whether $REPO has a tag $ARTIFACTS_TAG (git ls-remote failed)" >&2
    return 1
  fi
  awk -v t="refs/tags/$ARTIFACTS_TAG" '$2 == t "^{}" {p = $1} $2 == t {l = $1} END {print (p != "" ? p : l)}' <<< "$refs"
}

# The tag's commit must be in this checkout's history (reviewed, on main): a tag pushed at any other commit would
# run that commit's release.yml, recipe and patches, and write its own inputs.txt.
in_history() {
  if [[ ! $1 =~ ^[[:xdigit:]]{40}$ ]] || ! git -C "$root" merge-base --is-ancestor "$1" HEAD 2> /dev/null; then
    echo "$ARTIFACTS_TAG names ${1:-nothing}, which is not in this checkout's history (fetch main, or the tag is not main's)" >&2
    return 1
  fi
}

# Not pinned yet. Stale if the tag exists at a commit with other inputs (its release is, or will be, built from
# them); else pending, for how long since ARTIFACTS_TAG came to name it on this branch (its first-parent history:
# when a pull request merged, not when its commit was written).
pending() (
  local ours=$1 tagged status=0 since age tree= theirs
  trap 'rm -rf -- "$tree"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  tagged=$(tag_commit) || status=$?
  if [ "$status" = 1 ]; then return 1; fi
  if [ "$status" = 0 ]; then
    in_history "$tagged" || return 1
    tree=$(mktemp -d)
    if ! { git -C "$root" archive "$tagged" .github scripts firecracker | tar -x -C "$tree"; } ||
      ! theirs=$("$tree/scripts/pin-artifacts.sh" --inputs); then
      echo "cannot tell what $ARTIFACTS_TAG at $tagged is built from" >&2
      return 1
    fi
    if [ "$theirs" != "$ours" ]; then
      echo "$ARTIFACTS_TAG is tagged at $tagged, whose inputs differ from this checkout's: bump ARTIFACTS_TAG in scripts/versions.sh (RELEASING in README.md)" >&2
      diff <(printf '%s\n' "$theirs") <(printf '%s\n' "$ours") >&2 || true
      return 1
    fi
    echo "$ARTIFACTS_TAG is tagged at $tagged, with this checkout's inputs, but not pinned yet: once release.yml has published it, run scripts/pin-artifacts.sh and commit it" >&2
  else
    echo "$ARTIFACTS_TAG is not tagged yet: push its tag at the commit on main that names it, then run scripts/pin-artifacts.sh (RELEASING in README.md)" >&2
  fi
  if [ "$(git -C "$root" rev-parse --is-shallow-repository 2> /dev/null)" != false ]; then
    echo "for how long is unknown: this is not a full clone" >&2
    return 4
  fi
  since=$(git -C "$root" log --first-parent --diff-merges=first-parent -s -1 --format=%ct -G '^ARTIFACTS_TAG=' -- scripts/versions.sh)
  age=$(( ($(date +%s) - ${since:-0}) / 3600 ))
  echo "pending for ${age} h (the window is ${RELEASE_WINDOW_HOURS} h)" >&2
  if [ "$age" -ge "$RELEASE_WINDOW_HOURS" ]; then return 4; fi
  return 3
)

case "${1:-}" in
  --inputs)
    inputs
    exit 0
    ;;
  --check)
    # This checkout's inputs must be well-formed whatever the release's state.
    ours=$(inputs) || exit 1
    # The crates' versions are the tag's, without its v.
    for manifest in flexvm/Cargo.toml guest/Cargo.toml; do
      version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/$manifest" | head -1)
      if [ "v$version" != "$ARTIFACTS_TAG" ]; then
        echo "$manifest has version ${version:-none}, not ${ARTIFACTS_TAG#v} (ARTIFACTS_TAG $ARTIFACTS_TAG): bump it with the tag (RELEASING in README.md)" >&2
        exit 1
      fi
    done
    pins=0
    for asset in "${ASSETS[@]}"; do
      if pinned "$ARTIFACTS_URL/$asset" > /dev/null; then
        pins=$((pins + 1))
      else
        [ "$?" = 2 ] || exit 1
      fi
    done
    if [ "$pins" = 0 ]; then
      status=0
      pending "$ours" || status=$?
      exit "$status"
    fi
    if [ "$pins" != "${#ASSETS[@]}" ]; then
      echo "scripts/checksums.sha256 pins only some of $ARTIFACTS_TAG's assets (${ASSETS[*]}): run scripts/pin-artifacts.sh" >&2
      exit 1
    fi
    want=$(pinned "$ARTIFACTS_URL/inputs.txt")
    if [ "$(printf '%s\n' "$ours" | sha256sum | cut -d' ' -f1)" != "$want" ]; then
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
work='' placing=''
trap 'rm -rf -- "$work"; rm -f -- "$placing"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
work=$(mktemp -d)
for asset in "${ASSETS[@]}"; do
  echo "downloading $ARTIFACTS_URL/$asset"
  # Never executable: nothing downloaded here is run.
  curl -fsSL -o "$work/$asset" "$ARTIFACTS_URL/$asset"
  chmod 644 "$work/$asset"
done
status=0
tagged=$(tag_commit) || status=$?
if [ "$status" = 2 ]; then echo "no tag $ARTIFACTS_TAG in $REPO" >&2; fi
if [ "$status" != 0 ]; then exit 1; fi
in_history "$tagged"
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
# Rename on the same filesystem: a failed write leaves the old pins intact.
placing=$(mktemp "${checksums}.XXXXXX")
cat "$work/checksums" > "$placing"
chmod --reference="$checksums" "$placing"
mv -T "$placing" "$checksums"
placing=
echo "pinned $ARTIFACTS_TAG in scripts/checksums.sha256; commit it"
