//! The prebuilt patched Firecracker and guest kernel: on first use, a missing `STATE/artifacts/firecracker` or
//! `vmlinux` is downloaded from the release scripts/versions.sh names (`ARTIFACTS_TAG`), checked against the sha256
//! scripts/checksums.sha256 pins for it (build.rs), and renamed into place. A file already there must match the pin,
//! and a VM process checks its Firecracker against it too (`check_pinned`).
//! Only a build without a pin accepts a recorded file, built with the scripts or copied in for an offline host: `NAME.sha256`
//! beside it holds the sha256 of a file the scripts built or verified (scripts/build-firecracker.sh and fetch.sh
//! write it), which is all a build pinning no release can go by. Anything else (a corrupted or replaced download, a
//! copy cut short, an older release's) is refused, never run. Every host that
//! migrates VMs to another needs byte-identical Firecracker; hosts built from the same pins get it.

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::bail;
use crate::template::Stamp;
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
        return check_existing(path, asset, sha256);
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

/// A VM process's Firecracker must be the pinned one too: `ensure` checks only when a template is built, so after
/// an upgrade to a build pinning another release, the old binary would go on running every VM of an old template
/// (and their migrations fail on hosts with the pinned one). Its sha256 is cached in the run directory by the
/// file's stat, as compat caches its identity, so only a changed file is hashed again.
pub fn check_pinned(path: &Path, asset: &Asset) -> Result<()> {
    match if cfg!(test) { None } else { asset.sha256 } {
        Some(pin) => check_pinned_with(path, asset, pin, crate::host::run_dir()),
        None => Ok(()),
    }
}

fn check_pinned_with(path: &Path, asset: &Asset, pin: &str, run: Option<&Path>) -> Result<()> {
    let stamp = || -> Result<Stamp> { Ok(Stamp::of(&std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?)) };
    let before = stamp()?;
    let cache = format!("{}.pinned.json", asset.name);
    let cached = run.and_then(|d| std::fs::read(d.join(&cache)).ok()).and_then(|b| serde_json::from_slice::<(Stamp, String)>(&b).ok());
    if cached.is_some_and(|(s, p)| s == before && p == pin) {
        return Ok(());
    }
    check_existing(path, asset, Some(pin))?;
    // Cached only if the file hashed was the one stat-ed.
    if let Some(run) = run.filter(|_| stamp().is_ok_and(|after| after == before)) {
        let _ = crate::util::write_file(run, &cache, &serde_json::to_vec(&(before, pin))?, false);
    }
    Ok(())
}

/// Where the sha256 (hex) of a file the scripts built or verified at `path` is recorded: the first word of a line.
fn record_path(path: &Path) -> std::path::PathBuf {
    let mut record = path.as_os_str().to_owned();
    record.push(".sha256");
    record.into()
}

/// The file already at `path` must match the pin; only without a pin does `record_path` count.
fn check_existing(path: &Path, asset: &Asset, sha256: Option<&str>) -> Result<()> {
    let got = (|| -> Result<String> {
        let mut f = crate::image::Hashed::new(File::open(path)?);
        std::io::copy(&mut f, &mut std::io::sink())?;
        Ok(f.digest().trim_start_matches("sha256:").to_string())
    })()
    .map_err(|e| format!("{}: cannot check its sha256: {e}", path.display()))?;
    if let Some(pin) = sha256 {
        if got == pin {
            return Ok(());
        }
        bail!(
            "{}: not the pinned {} (sha256 {got}, pinned {pin}: from another release, or built here), so it is not run. \
             Remove it to download the pinned one, then pull templates built with it again.",
            path.display(),
            asset.name
        );
    }
    let record = record_path(path);
    let recorded = std::fs::read_to_string(&record).unwrap_or_default();
    if recorded.lines().any(|l| l.split_whitespace().next() == Some(got.as_str())) {
        return Ok(());
    }
    bail!(
        "{}: sha256 {got}, and this flexvm build pins no {} release to check it against, and {} does not record it, \
         so it is not run. If it is a file of your own, record it ({} does): \
         sha256sum {} > {}",
        path.display(),
        asset.name,
        record.display(),
        asset.by_hand,
        path.display(),
        record.display()
    )
}

/// `url` into `path`, written to a part of its own beside it and renamed over it once its sha256 checks: a
/// concurrent download renames identical bytes, and a killed one leaves only its part (removed by a later one).
fn fetch(url: &str, sha256: &str, path: &Path, mode: u32) -> Result<()> {
    let dir = path.parent().ok_or("no directory")?;
    std::fs::create_dir_all(dir)?;
    let name = path.file_name().ok_or("no file name")?.to_string_lossy().into_owned();
    sweep_parts(dir, &name);
    sweep_parts(dir, &format!("{name}.sha256"));
    let nonce = crate::util::random_hex(8)?;
    let part = dir.join(format!(".{name}.part{nonce}"));
    let record_part = dir.join(format!(".{name}.sha256.part{nonce}"));
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
        // A build pinning no release can also run what this one checked.
        let mut r = File::options().write(true).create_new(true).mode(0o644).custom_flags(libc::O_NOFOLLOW).open(&record_part)?;
        writeln!(r, "{sha256}  downloaded by flexvm from {url}")?;
        r.sync_all()?;
        std::fs::rename(&part, path)?;
        std::fs::rename(&record_part, record_path(path))?;
        Ok(sync_dir(dir)?)
    })();
    let _ = std::fs::remove_file(&part);
    let _ = std::fs::remove_file(&record_part);
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
        // Recorded beside it, so a build pinning nothing runs it too.
        let record = std::fs::read_to_string(dir.join("artifacts/firecracker.sha256")).unwrap();
        assert!(record.starts_with(&format!("{}  downloaded by flexvm from ", hex(b"patched firecracker"))), "{record}");
        // There now: never fetched again (the server is gone).
        ensure_one(&path, &FIRECRACKER, Some(&hex(b"patched firecracker")), "http://127.0.0.1:1").unwrap();
        ensure_one(&path, &FIRECRACKER, None, "http://127.0.0.1:1").unwrap();
        assert_eq!(std::fs::read_dir(dir.join("artifacts")).unwrap().count(), 2);
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
    fn a_recorded_download_is_refused_after_the_pin_changes() {
        let dir = crate::test_util::TempDir::new("artifacts-upgrade");
        let path = dir.join("firecracker");
        let old = hex(b"old release");
        std::fs::write(&path, b"old release").unwrap();
        std::fs::write(record_path(&path), format!("{old}  downloaded by flexvm from an older release\n")).unwrap();
        ensure_one(&path, &FIRECRACKER, Some(&old), "http://127.0.0.1:1").unwrap();
        let pin = hex(b"new release");
        let error = ensure_one(&path, &FIRECRACKER, Some(&pin), "http://127.0.0.1:1").unwrap_err().to_string();
        assert!(error.contains(&format!("sha256 {old}, pinned {pin}")), "{error}");
        assert!(!error.contains("record it"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), b"old release");
        ensure_one(&path, &FIRECRACKER, None, "http://127.0.0.1:1").unwrap();
    }

    #[test]
    fn a_vm_runs_only_the_pinned_firecracker_and_caches_the_check_by_stat() {
        let dir = crate::test_util::TempDir::new("artifacts-run");
        let run = dir.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let path = dir.join("firecracker");
        let (old, pin) = (hex(b"old release"), hex(b"new release"));
        std::fs::write(&path, b"old release").unwrap();
        std::fs::write(record_path(&path), format!("{old}  downloaded by flexvm from an older release\n")).unwrap();
        let error = check_pinned_with(&path, &FIRECRACKER, &pin, Some(&run)).unwrap_err().to_string();
        assert!(error.contains(&format!("sha256 {old}, pinned {pin}")) && error.contains("Remove it"), "{error}");
        assert!(!run.join("firecracker.pinned.json").exists());
        // The pinned one: checked once, then trusted while its stat is unchanged.
        std::fs::write(dir.join("new"), b"new release").unwrap();
        std::fs::rename(dir.join("new"), &path).unwrap();
        check_pinned_with(&path, &FIRECRACKER, &pin, Some(&run)).unwrap();
        assert!(run.join("firecracker.pinned.json").exists());
        check_pinned_with(&path, &FIRECRACKER, &pin, Some(&run)).unwrap();
        // The cache names the pin it checked: another one checks again.
        assert!(check_pinned_with(&path, &FIRECRACKER, &old, Some(&run)).is_err());
        // Replaced (a new inode): hashed again, and refused.
        std::fs::write(dir.join("new"), b"old release").unwrap();
        std::fs::rename(dir.join("new"), &path).unwrap();
        assert!(check_pinned_with(&path, &FIRECRACKER, &pin, Some(&run)).is_err());
        // No run directory: checked every time.
        assert!(check_pinned_with(&path, &FIRECRACKER, &pin, None).is_err());
        check_pinned_with(&path, &FIRECRACKER, &old, None).unwrap();
    }

    #[test]
    fn a_matching_pin_needs_no_matching_record() {
        let dir = crate::test_util::TempDir::new("artifacts-pinned");
        let path = dir.join("firecracker");
        std::fs::write(&path, b"pinned release").unwrap();
        std::fs::write(record_path(&path), format!("{}  old release\n", hex(b"old release"))).unwrap();
        check_existing(&path, &FIRECRACKER, Some(&hex(b"pinned release"))).unwrap();
        assert!(check_existing(&path, &FIRECRACKER, None).is_err());
    }

    #[test]
    fn an_existing_file_must_match_its_pin_or_without_one_its_record() {
        let dir = crate::test_util::TempDir::new("artifacts-existing");
        let path = dir.join("firecracker");
        let record = dir.join("firecracker.sha256");
        let pin = hex(b"patched firecracker");
        let check = |pin: Option<&str>| ensure_one(&path, &FIRECRACKER, pin, "http://127.0.0.1:1");
        std::fs::write(&path, b"patched firecracker").unwrap();
        check(Some(&pin)).unwrap();
        // A build pinning nothing can only go by the record.
        let error = check(None).unwrap_err().to_string();
        assert!(error.contains("pins no firecracker release") && error.contains("firecracker.sha256"), "{error}");
        // Cut short, replaced, or built by hand and not recorded: refused, never downloaded over.
        std::fs::write(&path, b"patched").unwrap();
        let error = check(Some(&pin)).unwrap_err().to_string();
        assert!(error.contains("not the pinned firecracker") && error.contains(&hex(b"patched")), "{error}");
        assert!(error.contains("Remove it to download the pinned one"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), b"patched");
        // A record counts only without a pin, and must match the file.
        std::fs::write(&record, format!("{}  firecracker\n", hex(b"other"))).unwrap();
        assert!(check(Some(&pin)).is_err());
        assert!(check(None).is_err());
        std::fs::write(&record, format!("{}  firecracker\n", hex(b"patched"))).unwrap();
        assert!(check(Some(&pin)).is_err());
        check(None).unwrap();
        // Unreadable: refused, not trusted.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let error = check(None).unwrap_err().to_string();
        assert!(error.contains("cannot check its sha256"), "{error}");
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
