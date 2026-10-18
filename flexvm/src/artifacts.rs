//! The prebuilt patched Firecracker and guest kernel: on first use, a missing `STATE/artifacts/firecracker` or
//! `vmlinux` is downloaded from the release scripts/versions.sh names (`ARTIFACTS_TAG`), checked against the sha256
//! scripts/checksums.sha256 pins for it (build.rs), and renamed into place. A file already there is used as it is:
//! one built with the scripts, or copied in for an offline host; it is checked against the pin, and one that differs
//! is used with a warning (a host's own build never matches it). Every host that migrates VMs to another needs
//! byte-identical Firecracker; hosts built from the same pins get it.

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::bail;
use crate::util::{sync_dir, Result};

/// flexvm-init (guest/), static, as build.rs built it: PID 1 and the guest agent, written into every image template.
pub static INIT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/flexvm-init"));

/// A release asset flexvm can download.
pub struct Asset {
    /// Its name in the release and in `STATE/artifacts`.
    pub name: &'static str,
    /// Its pinned sha256 (hex), if this build pins the release's.
    sha256: Option<&'static str>,
    mode: u32,
    /// How to build or fetch one by hand.
    by_hand: &'static str,
}

pub const FIRECRACKER: Asset =
    Asset { name: "firecracker", sha256: option_env!("FLEXVM_PIN_FIRECRACKER"), mode: 0o755, by_hand: "scripts/build-firecracker.sh" };
pub const KERNEL: Asset = Asset { name: "vmlinux", sha256: option_env!("FLEXVM_PIN_VMLINUX"), mode: 0o644, by_hand: "scripts/fetch.sh" };

/// The release the assets come from; `FLEXVM_ARTIFACTS_URL` names a mirror holding the same files (they are checked
/// against the same pins).
fn base() -> String {
    std::env::var("FLEXVM_ARTIFACTS_URL").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| env!("FLEXVM_ARTIFACTS_BASE").into())
}

/// The largest asset accepted, and the size its transfer deadline is reckoned for.
const MAX_SIZE: u64 = 256 << 20;
/// A download's part left this long is a killed download's.
const STALE_PART: Duration = Duration::from_secs(3600);

/// Each `(path, asset)` whose path is missing is downloaded to it.
pub fn ensure(want: &[(&Path, &Asset)]) -> Result<()> {
    // Unit tests never reach the network: as if this build pinned nothing.
    let pinned = |a: &Asset| if cfg!(test) { None } else { a.sha256 };
    for (path, asset) in want {
        ensure_one(path, asset, pinned(asset), &base())?;
    }
    Ok(())
}

fn ensure_one(path: &Path, asset: &Asset, sha256: Option<&str>, base: &str) -> Result<()> {
    if path.exists() {
        if let Some(sha256) = sha256 {
            match pinned_file(path, sha256) {
                Ok(None) => {}
                Ok(Some(got)) => crate::log!(
                    "flexvm: warning: {} is not the pinned {} ({got}, pinned sha256:{sha256}): using it as it is (one built or copied \
                     by hand?); remove it to download the pinned one",
                    path.display(),
                    asset.name
                ),
                Err(e) => crate::log!("flexvm: warning: {}: cannot check it against its pinned sha256: {e}", path.display()),
            }
        }
        return Ok(());
    }
    let Some(sha256) = sha256 else {
        bail!(
            "{}: missing, and this flexvm build pins no prebuilt {} to download (build or fetch one: {}, or copy one there)",
            path.display(),
            asset.name,
            asset.by_hand
        );
    };
    let url = format!("{}/{}", base.trim_end_matches('/'), asset.name);
    crate::log!("flexvm: downloading {} (sha256 {sha256}) from {url}", asset.name);
    fetch(&url, sha256, path, asset.mode).map_err(|e| {
        format!(
            "{}: missing, and downloading it failed: {e}. Offline, copy a file with sha256 {sha256} there (from a host that has it, \
             or from {url}), set FLEXVM_ARTIFACTS_URL to a mirror, or build your own: {}",
            path.display(),
            asset.by_hand
        )
    })?;
    crate::log!("flexvm: installed {}", path.display());
    Ok(())
}

/// `None` if the file at `path` has the pinned sha256, or the digest it has instead.
fn pinned_file(path: &Path, sha256: &str) -> Result<Option<String>> {
    let mut f = crate::image::Hashed::new(File::open(path)?);
    std::io::copy(&mut f, &mut std::io::sink())?;
    let got = f.digest();
    Ok((got.strip_prefix("sha256:") != Some(sha256)).then_some(got))
}

/// `url` into `path`, written to a part of its own beside it and renamed over it once its sha256 checks: a
/// concurrent download renames identical bytes, and a killed one leaves only its part (removed by a later one).
fn fetch(url: &str, sha256: &str, path: &Path, mode: u32) -> Result<()> {
    let dir = path.parent().ok_or("no directory")?;
    std::fs::create_dir_all(dir)?;
    let name = path.file_name().ok_or("no file name")?.to_string_lossy().into_owned();
    sweep_parts(dir, &name);
    let part = dir.join(format!(".{name}.part{}", crate::util::random_hex(8)?));
    let res = (|| {
        let mut f = File::options().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(&part)?;
        let mut body = crate::image::Hashed::new(std::io::Read::take(crate::image::download(url, MAX_SIZE)?.into_reader(), MAX_SIZE + 1));
        std::io::copy(&mut body, &mut f)?;
        if body.n > MAX_SIZE {
            bail!("{url} is larger than {} MiB", MAX_SIZE >> 20);
        }
        let got = body.digest();
        if got.strip_prefix("sha256:") != Some(sha256) {
            bail!("{url} has {got}, not the pinned sha256:{sha256}");
        }
        f.flush()?;
        f.sync_all()?;
        std::fs::rename(&part, path)?;
        Ok(sync_dir(dir)?)
    })();
    let _ = std::fs::remove_file(&part);
    res
}

/// Parts of `name` older than `STALE_PART`.
fn sweep_parts(dir: &Path, name: &str) {
    let prefix = format!(".{name}.part");
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let stale =
            entry.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| SystemTime::now().duration_since(t).ok()).is_some_and(|age| age > STALE_PART);
        if stale && entry.file_name().to_str().and_then(|n| n.strip_prefix(&prefix)).is_some_and(crate::util::is_nonce) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;

    /// Serves `body` at `/asset` and a redirect to it at `/moved/asset`, `n` times.
    fn serve(body: &'static [u8], n: usize) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in l.incoming().take(n) {
                let mut s = stream.unwrap();
                let mut line = String::new();
                let mut r = BufReader::new(s.try_clone().unwrap());
                r.read_line(&mut line).unwrap();
                while r.read_line(&mut String::new()).unwrap() > 2 {}
                let reply = if line.starts_with("GET /moved/") {
                    format!("HTTP/1.1 302 Found\r\nlocation: /{}\r\ncontent-length: 0\r\n\r\n", line.split('/').nth(2).unwrap().split(' ').next().unwrap())
                } else if line.starts_with("GET /asset ") || line.starts_with("GET /firecracker ") {
                    format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len())
                } else {
                    "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".into()
                };
                s.write_all(reply.as_bytes()).unwrap();
                if reply.starts_with("HTTP/1.1 200") {
                    s.write_all(body).unwrap();
                }
            }
        });
        format!("http://{addr}")
    }

    fn hex(data: &[u8]) -> String {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(data))
    }

    #[test]
    fn a_missing_asset_is_downloaded_through_redirects_and_checked() {
        let dir = crate::test_util::TempDir::new("artifacts");
        let path = dir.join("artifacts/firecracker");
        let base = serve(b"patched firecracker", 2);
        ensure_one(&path, &FIRECRACKER, Some(&hex(b"patched firecracker")), &format!("{base}/moved")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"patched firecracker");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o755);
        // There now: never fetched again (the server is gone), whatever its content (one that differs from the pin is
        // used with a warning).
        std::fs::write(&path, b"built by hand").unwrap();
        ensure_one(&path, &FIRECRACKER, Some(&hex(b"other")), "http://127.0.0.1:1").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"built by hand");
        assert_eq!(std::fs::read_dir(dir.join("artifacts")).unwrap().count(), 1);
    }

    #[test]
    fn a_download_that_does_not_match_its_pin_is_never_installed() {
        let dir = crate::test_util::TempDir::new("artifacts-bad");
        let path = dir.join("firecracker");
        let base = serve(b"tampered", 1);
        let error = ensure_one(&path, &FIRECRACKER, Some(&hex(b"patched firecracker")), &base).unwrap_err().to_string();
        assert!(error.contains("not the pinned sha256"), "{error}");
        assert!(error.contains("scripts/build-firecracker.sh"), "{error}");
        assert!(!path.exists());
        // Nothing left beside it either.
        assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
    }

    #[test]
    fn an_existing_file_is_checked_against_its_pin() {
        let dir = crate::test_util::TempDir::new("artifacts-existing");
        let path = dir.join("firecracker");
        std::fs::write(&path, b"patched firecracker").unwrap();
        assert_eq!(pinned_file(&path, &hex(b"patched firecracker")).unwrap(), None);
        // Cut short, or built by hand: its own digest.
        std::fs::write(&path, b"patched").unwrap();
        assert_eq!(pinned_file(&path, &hex(b"patched firecracker")).unwrap(), Some(format!("sha256:{}", hex(b"patched"))));
        assert!(pinned_file(&dir.join("missing"), &hex(b"x")).is_err());
    }

    #[test]
    fn without_a_pin_the_error_says_how_to_supply_it() {
        let dir = crate::test_util::TempDir::new("artifacts-unpinned");
        let path = dir.join("vmlinux");
        let error = ensure_one(&path, &KERNEL, None, "http://127.0.0.1:1").unwrap_err().to_string();
        assert!(error.starts_with(&format!("{}: missing", path.display())), "{error}");
        assert!(error.contains("scripts/fetch.sh"), "{error}");
    }

    #[test]
    fn stale_parts_are_swept() {
        let dir = crate::test_util::TempDir::new("artifacts-parts");
        let old = dir.join(".vmlinux.part0123456789abcdef");
        let fresh = dir.join(".vmlinux.partfedcba9876543210");
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&fresh, b"x").unwrap();
        File::options().write(true).open(&old).unwrap().set_modified(SystemTime::now() - 2 * STALE_PART).unwrap();
        sweep_parts(&dir, "vmlinux");
        assert!(!old.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn embedded_init_is_a_static_executable() {
        assert_eq!(&INIT[..4], b"\x7fELF");
        // No program interpreter (PT_INTERP): it runs in any image.
        let at = |o: usize, n: usize| INIT[o..o + n].iter().rev().fold(0usize, |v, b| v << 8 | *b as usize);
        let (phoff, phentsize, phnum) = (at(0x20, 8), at(0x36, 2), at(0x38, 2));
        assert!(phnum > 0);
        assert!((0..phnum).all(|i| at(phoff + i * phentsize, 4) != 3));
    }
}
