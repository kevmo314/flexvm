#!/usr/bin/env bash
# Shared versions; callers may override them in the environment.
FC_VERSION=${FC_VERSION:-v1.17.0}
# The guest kernel, from Firecracker's CI bucket.
CI_VERSION=${CI_VERSION:-v1.15}
KERNEL=${KERNEL:-vmlinux-6.1.155}
ARCH=x86_64
CI=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/$CI_VERSION/$ARCH
# The kevmo314/flexvm release holding the prebuilt patched Firecracker and that guest kernel, which flexvm
# downloads on first use (build.rs reads this line). .github/workflows/release.yml builds it when its tag is
# pushed; flexvm and fetch.sh download from it only once scripts/checksums.sha256 pins its assets
# (scripts/pin-artifacts.sh writes those lines). Cut a new tag whenever firecracker/*.patch, FC_VERSION or
# the kernel change: a release's assets never change.
ARTIFACTS_TAG=${ARTIFACTS_TAG:-artifacts-2}
ARTIFACTS_URL=https://github.com/kevmo314/flexvm/releases/download/$ARTIFACTS_TAG
