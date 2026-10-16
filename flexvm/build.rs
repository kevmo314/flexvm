//! Builds flexvm-init (the guest crate) for the guest and hands its path to `include_bytes!`, and reads the
//! prebuilt artifacts release flexvm downloads from: its tag (scripts/versions.sh) and the sha256 pinned for
//! each asset (scripts/checksums.sha256).

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository whose releases hold the prebuilt artifacts.
const REPO: &str = "kevmo314/flexvm";
/// The assets flexvm downloads, and the `rustc-env` each one's pin goes in.
const ASSETS: [(&str, &str); 2] = [("firecracker", "FLEXVM_PIN_FIRECRACKER"), ("vmlinux", "FLEXVM_PIN_VMLINUX")];

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.parent().unwrap().to_path_buf();
    pins(&root);
    init(&root);
}

/// `NAME=${NAME:-value}` (or `NAME=value`) in a shell file: its default.
fn shell_default(text: &str, name: &str) -> Option<String> {
    let value = text.lines().find_map(|l| l.trim().strip_prefix(name)?.strip_prefix('='))?;
    let value = match value.strip_prefix(&format!("${{{name}:-")) {
        Some(v) => v.strip_suffix('}')?,
        None => value,
    };
    Some(value.trim_matches('"').to_string())
}

fn pins(root: &Path) {
    let versions = root.join("scripts/versions.sh");
    let checksums = root.join("scripts/checksums.sha256");
    println!("cargo:rerun-if-changed={}", versions.display());
    println!("cargo:rerun-if-changed={}", checksums.display());
    let versions = std::fs::read_to_string(&versions).expect("scripts/versions.sh");
    let tag = shell_default(&versions, "ARTIFACTS_TAG").expect("ARTIFACTS_TAG in scripts/versions.sh");
    assert!(!tag.is_empty() && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)), "bad ARTIFACTS_TAG {tag:?}");
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");
    println!("cargo:rustc-env=FLEXVM_ARTIFACTS_BASE={base}");
    let checksums = std::fs::read_to_string(&checksums).expect("scripts/checksums.sha256");
    for (asset, var) in ASSETS {
        let url = format!("{base}/{asset}");
        let found: Vec<&str> = checksums.lines().filter_map(|l| l.split_once(' ').filter(|(_, u)| u.trim() == url).map(|(h, _)| h)).collect();
        match found[..] {
            [] => {}
            [hash] if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) => {
                println!("cargo:rustc-env={var}={}", hash.to_ascii_lowercase())
            }
            _ => panic!("scripts/checksums.sha256 must pin {url} once, by its sha256"),
        }
    }
}

/// flexvm-init, static (it runs in any image), built by a cargo of its own into OUT_DIR: release, whatever this
/// build's profile, and without this build's flags or wrappers (clippy's included). `FLEXVM_INIT` names a
/// prebuilt one instead.
fn init(root: &Path) {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let dest = out.join("flexvm-init");
    println!("cargo:rerun-if-env-changed=FLEXVM_INIT");
    if let Some(prebuilt) = std::env::var_os("FLEXVM_INIT") {
        println!("cargo:rerun-if-changed={}", Path::new(&prebuilt).display());
        std::fs::copy(&prebuilt, &dest).unwrap_or_else(|e| panic!("FLEXVM_INIT={}: {e}", Path::new(&prebuilt).display()));
        return;
    }
    for input in ["guest/src", "guest/Cargo.toml", "Cargo.lock", "Cargo.toml"] {
        println!("cargo:rerun-if-changed={}", root.join(input).display());
    }
    let target = "x86_64-unknown-linux-gnu";
    let target_dir = out.join("init-target");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(root)
        .args(["build", "--release", "--locked", "-p", "flexvm-init", "--target", target, "--target-dir"])
        .arg(&target_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", "-Ctarget-feature=+crt-static");
    for var in
        ["RUSTFLAGS", "RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_RUSTFLAGS", "CLIPPY_ARGS", "CARGO_PRIMARY_PACKAGE"]
    {
        cmd.env_remove(var);
    }
    // Its output is never this script's: cargo would read a `cargo:` line in it as a directive.
    cmd.stdout(std::io::stderr().as_fd().try_clone_to_owned().expect("stderr"));
    let status = cmd.status().expect("running cargo to build flexvm-init");
    assert!(status.success(), "building flexvm-init failed ({status}); set FLEXVM_INIT to a prebuilt static flexvm-init to skip it");
    let built = target_dir.join(target).join("release/flexvm-init");
    // Copied, not linked: OUT_DIR's file stays what this build embedded.
    std::fs::copy(&built, &dest).unwrap_or_else(|e| panic!("{}: {e}", built.display()));
}
