//! Image selection and disk maintenance. Destructive work uses the same locks as pulls and VMs.
use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use serde_json::Value;

use crate::template::Paths;
use crate::util::Result;
use crate::{bail, output, Args};

#[derive(Default)]
pub struct Filters {
    references: Vec<String>,
    dangling: Option<bool>,
}

impl Filters {
    pub fn parse(filters: &[String]) -> Result<Self> {
        let mut out = Self::default();
        for filter in filters {
            match filter.split_once('=') {
                Some(("reference", pattern)) if !pattern.is_empty() => out.references.push(pattern.into()),
                Some(("dangling", value @ ("true" | "false"))) => {
                    let value = value == "true";
                    if out.dangling.is_some_and(|old| old != value) {
                        bail!("conflicting dangling filters");
                    }
                    out.dangling = Some(value);
                }
                _ => bail!("bad image filter {filter:?}: use reference=PATTERN or dangling=true|false"),
            }
        }
        Ok(out)
    }

    pub fn matches(&self, image: &Value) -> bool {
        let name = image["name"].as_str();
        self.dangling.is_none_or(|v| v == name.is_none())
            && (self.references.is_empty()
                || name.is_some_and(|n| {
                    let Ok(reference) = crate::image::Reference::from_template_name(n) else { return false };
                    let mut names = vec![reference.familiar(), reference.familiar_repository(), reference.to_string()];
                    if reference.registry == "registry-1.docker.io" {
                        let sep = if reference.is_digest() { '@' } else { ':' };
                        names.push(format!("docker.io/{}{sep}{}", reference.repository, reference.reference));
                        names.push(format!("docker.io/{}", reference.repository));
                    }
                    self.references.iter().any(|p| names.iter().any(|name| glob(p, name)))
                }))
    }
}

/// Shell-style `*`, `?` and bracket patterns, with `/` treated like any other character.
fn glob(pattern: &str, value: &str) -> bool {
    let (Ok(pattern), Ok(value)) = (std::ffi::CString::new(pattern), std::ffi::CString::new(value)) else { return false };
    unsafe { libc::fnmatch(pattern.as_ptr(), value.as_ptr(), 0) == 0 }
}

/// Allocated bytes, counting each inode once and never following symlinks.
fn disk_usage(path: &Path, seen: &mut BTreeSet<(u64, u64)>) -> Result<u64> {
    let meta = match path.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        m => m?,
    };
    if !seen.insert((meta.dev(), meta.ino())) {
        return Ok(0);
    }
    let mut size = meta.blocks() * 512;
    if meta.is_dir() {
        for entry in entries(std::fs::read_dir(path))? {
            size += disk_usage(&entry?.path(), seen)?;
        }
    }
    Ok(size)
}

/// A directory removed after metadata was read has no remaining children to count.
fn entries(result: std::io::Result<std::fs::ReadDir>) -> std::io::Result<impl Iterator<Item = std::io::Result<std::fs::DirEntry>>> {
    match result {
        Ok(entries) => Ok(Some(entries).into_iter().flatten()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None.into_iter().flatten()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
fn usage(path: &Path) -> Result<u64> {
    disk_usage(path, &mut BTreeSet::new())
}

fn confirm(force: bool, what: &str) -> Result<()> {
    if force {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("prune asks first, on a terminal; -f prunes without asking");
    }
    output(format_args!("This removes {what}. Continue? [y/N] "))?;
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        bail!("prune cancelled");
    }
    Ok(())
}

/// `system df`, and `image prune` / `system prune`: unnamed generations no VM here uses (as `rmi ID`
/// removes them), and for `system`, failed and lost VM records and the layer blob cache too.
pub fn system(args: &Args, operation: &str) -> Result<()> {
    let system = args.positional.first().is_some_and(|c| c == "system");
    if operation == "prune" {
        confirm(args.has("force"), if system { "unused <none> images, failed and lost VM records and the layer blob cache" } else { "unused <none> images" })?;
    }
    let host = crate::open_host(args)?;
    let paths = Paths::new(&host.state);
    if operation == "df" {
        let mut seen = BTreeSet::new();
        output(format_args!("{:<16} {:>16}\n", "TYPE", "ALLOCATED BYTES"))?;
        for (kind, path) in [
            ("Images", paths.images.join("rootfs")),
            ("Templates", paths.templates.clone()),
            ("Blobs", paths.images.join("blobs")),
            ("VMs", host.run.join("vms")),
            ("Checkpoints", host.state.join("suspended")),
        ] {
            output(format_args!("{kind:<16} {:>16}\n", disk_usage(&path, &mut seen)?))?;
        }
        return Ok(());
    }
    let total = || -> Result<u64> {
        let mut seen = BTreeSet::new();
        Ok(disk_usage(&paths.images, &mut seen)? + disk_usage(&paths.templates, &mut seen)? + disk_usage(&host.run.join("vms"), &mut seen)?)
    };
    let before = total()?;
    if system {
        for vm in crate::vms(&host) {
            if matches!(vm["state"].as_str(), Some("failed" | "lost")) {
                let name = vm["name"].as_str().ok_or("VM record has no name")?;
                if prune_vm_record(&host, name)? {
                    output(format_args!("Deleted VM record: {name}\n"))?;
                }
            }
        }
    }
    for removed in crate::template::prune(&paths, &|| host.template_users())? {
        crate::print(removed)?;
    }
    if system {
        prune_blobs(&paths)?;
    }
    output(format_args!("Total reclaimed space: {} bytes\n", before.saturating_sub(total()?)))
}

fn prune_vm_record(host: &crate::host::Host, name: &str) -> Result<bool> {
    // Hold the name while rechecking: a VM may have been recreated since
    // the list was read. Only remove these records, preserving checkpoints
    // and migration records even if either appeared meanwhile.
    let _name = match crate::host::lock_path(&host.vms(name, "lock")?, libc::LOCK_EX | libc::LOCK_NB) {
        Ok(lock) => lock,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if host.is_suspended(name) || host.has_record(name, "moved") {
        return Ok(false);
    }
    for ext in ["failed", "lost"] {
        match std::fs::remove_file(host.vms(name, ext)?) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            r => r?,
        }
    }
    Ok(true)
}

fn prune_blobs(paths: &Paths) -> Result<()> {
    if !paths.images.exists() {
        return Ok(());
    }
    // A pull holds this shared from source resolution through template publication.
    let parent = crate::host::Directory::open(&paths.images)?;
    let key = crate::host::keyed("image-cache", &parent.stat()?, "");
    let Some(_lock) = crate::host::try_lock_at(crate::host::host_locks()?, &key)? else {
        return output(format_args!("Blob cache is in use by a pull; kept\n"));
    };
    // Neither cache subdirectory may redirect deletion through a symlink. Keep both
    // open so replacement of a directory cannot redirect the rest of the pass.
    let open = |path: &Path| std::fs::File::options().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path);
    let blobs = match open(&parent.path.join("blobs")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        r => r?,
    };
    let blobs_path = std::path::PathBuf::from(format!("/proc/self/fd/{}", blobs.as_raw_fd()));
    let sha256 = match open(&blobs_path.join("sha256")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        r => r?,
    };
    let dir = std::path::PathBuf::from(format!("/proc/self/fd/{}", sha256.as_raw_fd()));
    let entries = std::fs::read_dir(&dir)?;
    // Templates use extracted root filesystems, never the downloaded layer/config blobs.
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type()?.is_file() && name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
            std::fs::remove_file(entry.path())?;
            output(format_args!("Deleted blob: sha256:{name}\n"))?;
        }
    }
    crate::util::sync_dir(&dir)?;
    Ok(())
}

pub fn version(paths: &Paths) -> Result<()> {
    output(format_args!("flexvm {}\ngit commit: {}\nartifacts: {}\n", env!("CARGO_PKG_VERSION"), env!("FLEXVM_GIT_COMMIT"), env!("FLEXVM_ARTIFACTS_BASE")))?;
    for (name, path, pin) in
        [("firecracker", &paths.firecracker, option_env!("FLEXVM_PIN_FIRECRACKER")), ("kernel", &paths.kernel, option_env!("FLEXVM_PIN_VMLINUX"))]
    {
        output(format_args!(
            "{name}: {} ({})\n  pinned sha256: {}\n",
            path.display(),
            if path.is_file() { "installed" } else { "missing" },
            pin.unwrap_or("unavailable")
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn disappearing_directory_has_no_children() {
        let root = crate::test_util::TempDir::new("usage-removed");
        let path = root.join("directory");
        std::fs::create_dir(&path).unwrap();
        assert!(path.symlink_metadata().unwrap().is_dir());
        std::fs::remove_dir(&path).unwrap();
        assert_eq!(entries(std::fs::read_dir(&path)).unwrap().count(), 0);
        assert_eq!(usage(&path).unwrap(), 0);
        assert!(entries(Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))).is_err());
    }

    #[test]
    fn filters_validate_and_combine() {
        let filters = |f: &[&str]| Filters::parse(&f.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let named = json!({"name": "ghcr.io+org+app:v1"});
        let dangling = json!({"name": null});
        assert!(filters(&["reference=ghcr.io/*:v?", "dangling=false"]).unwrap().matches(&named));
        assert!(filters(&["reference=other:*", "reference=ghcr.io/*"]).unwrap().matches(&named));
        assert!(!filters(&["reference=*"]).unwrap().matches(&dangling));
        assert!(filters(&["dangling=true"]).unwrap().matches(&dangling));
        assert!(filters(&["reference=ghcr.io/org/app"]).unwrap().matches(&named));
        assert!(filters(&["reference=docker.io/library/nginx:*"]).unwrap().matches(&json!({"name": "nginx"})));
        for bad in ["x=y", "reference=", "dangling=yes", "dangling", "reference"] {
            assert!(filters(&[bad]).is_err());
        }
        assert!(filters(&["dangling=true", "dangling=false"]).is_err());
    }

    #[test]
    fn failed_record_prune_preserves_checkpoints_and_live_names() {
        let root = crate::test_util::TempDir::new("prune-records");
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        std::fs::write(host.vms("failed", "failed").unwrap(), b"failed").unwrap();
        assert!(prune_vm_record(&host, "failed").unwrap());
        assert!(!host.vms("failed", "failed").unwrap().exists());
        let held = host.take_name("held", false).unwrap();
        std::fs::write(host.vms("held", "lost").unwrap(), b"lost").unwrap();
        assert!(!prune_vm_record(&host, "held").unwrap());
        assert!(host.vms("held", "lost").unwrap().exists());
        drop(held);
        let suspended = host.suspended("stopped").unwrap();
        std::fs::create_dir(&suspended).unwrap();
        std::fs::write(suspended.join("manifest.json"), b"checkpoint").unwrap();
        std::fs::write(host.vms("stopped", "failed").unwrap(), b"stale").unwrap();
        assert!(!prune_vm_record(&host, "stopped").unwrap());
        assert!(suspended.join("manifest.json").exists());
        std::fs::write(host.vms("moved", "moved").unwrap(), b"peer").unwrap();
        assert!(!prune_vm_record(&host, "moved").unwrap());
        assert!(host.vms("moved", "moved").unwrap().exists());
    }

    #[test]
    fn blob_prune_skips_active_pulls_and_never_follows_links() {
        let root = crate::test_util::TempDir::new("prune-blobs");
        let paths = Paths::new(&root);
        let blobs = paths.images.join("blobs/sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        let digest = "a".repeat(64);
        std::fs::write(blobs.join(&digest), b"download cache").unwrap();
        let outside = root.join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, blobs.join("b".repeat(64))).unwrap();
        std::fs::write(blobs.join("download.part"), b"incomplete").unwrap();
        let parent = crate::host::Directory::open(&paths.images).unwrap();
        let key = crate::host::keyed("image-cache", &parent.stat().unwrap(), "");
        let held = crate::host::lock_at(crate::host::host_locks().unwrap(), &key, libc::LOCK_SH).unwrap();
        prune_blobs(&paths).unwrap();
        assert!(blobs.join(&digest).exists());
        drop(held);
        prune_blobs(&paths).unwrap();
        assert!(!blobs.join(&digest).exists());
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        assert!(blobs.join("download.part").exists());
        std::fs::rename(&blobs, root.join("saved-blobs")).unwrap();
        std::os::unix::fs::symlink(root.join("saved-blobs"), &blobs).unwrap();
        assert!(prune_blobs(&paths).is_err());
    }

    #[test]
    fn disk_usage_counts_hardlinks_once_and_does_not_follow_links() {
        let dir = crate::test_util::TempDir::new("df");
        std::fs::write(dir.join("a"), [1; 8192]).unwrap();
        std::fs::hard_link(dir.join("a"), dir.join("b")).unwrap();
        std::os::unix::fs::symlink("/", dir.join("link")).unwrap();
        let expected = dir.symlink_metadata().unwrap().blocks() * 512 + dir.join("a").metadata().unwrap().blocks() * 512;
        assert_eq!(usage(&dir).unwrap(), expected);
        assert_eq!(usage(&dir.join("absent")).unwrap(), 0);
    }
}
