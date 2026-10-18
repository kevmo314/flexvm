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
pub(crate) fn disk_usage(path: &Path, seen: &mut BTreeSet<(u64, u64)>) -> Result<u64> {
    let meta = match path.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        m => m?,
    };
    if !seen.insert((meta.dev(), meta.ino())) {
        return Ok(0);
    }
    let mut size = meta.blocks() * 512;
    if meta.is_dir() {
        // Removed since (a pull's cleanup, a template sweep): nothing left in it.
        match std::fs::read_dir(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            entries => {
                for entry in entries? {
                    size += disk_usage(&entry?.path(), seen)?;
                }
            }
        }
    }
    Ok(size)
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
        // Checkpoints: stored ones (`checkpoint::store`) and stopped VMs'.
        for (kind, dirs) in [
            ("Images", vec![paths.images.join("rootfs")]),
            ("Templates", vec![paths.templates.clone()]),
            ("Blobs", vec![paths.images.join("blobs")]),
            ("VMs", vec![host.run.join("vms")]),
            ("Checkpoints", vec![crate::checkpoint::store::dir(&host.state), host.state.join("suspended")]),
        ] {
            let bytes = dirs.iter().map(|d| disk_usage(d, &mut seen)).sum::<Result<u64>>()?;
            output(format_args!("{kind:<16} {bytes:>16}\n"))?;
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
    for removed in crate::template::prune(&paths, None, &|| host.template_users())? {
        crate::print(removed)?;
    }
    if system {
        prune_blobs(&paths)?;
    }
    output(format_args!("Total reclaimed space: {} bytes\n", before.saturating_sub(total()?)))
}

/// Their `--format` fields.
const CHECKPOINT_FIELDS: crate::containers::Fields = &[
    ("Name", "name"),
    ("ID", "id"),
    ("VM", "vm"),
    ("Template", "template"),
    ("TemplateID", "template_id"),
    ("Parent", "parent"),
    ("Size", "size"),
    ("Created", "created"),
];

/// `checkpoint ls|rm|prune` (`checkpoint create` is the VM's).
pub fn checkpoints(args: &Args, operation: &str) -> Result<()> {
    use crate::checkpoint::store;
    let host = crate::open_host(args)?;
    let removed = match operation {
        "ls" => return list_checkpoints(&host, args),
        "rm" => store::remove(&host.state, &args.names()[1..], args.has("force"))?,
        _ => {
            let before = args.get("older-than").map(|d| -> Result<u64> {
                let age = crate::util::parse_age(d).ok_or_else(|| format!("bad --older-than {d:?}: give a number and s, m, h or d (24h)"))?;
                let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
                Ok(since.saturating_sub(age).as_millis() as u64)
            });
            let before = before.transpose()?;
            let older = args.get("older-than").map_or(String::new(), |d| format!(" older than {d}"));
            confirm(args.has("force"), &format!("every stored checkpoint{older} that no other kept builds on"))?;
            store::prune(&host.state, before)?
        }
    };
    removed.into_iter().try_for_each(crate::print)
}

fn list_checkpoints(host: &crate::host::Host, args: &Args) -> Result<()> {
    let format = args.get("format").filter(|f| f.trim() != "table").map(|f| crate::containers::Format::parse_with(f, CHECKPOINT_FIELDS)).transpose()?;
    let mut filters = vec![];
    for f in args.all("filter") {
        match f.split_once('=') {
            Some((k @ ("name" | "vm" | "template"), v)) if !v.is_empty() => filters.push((k.to_string(), v.to_string())),
            _ => bail!("bad checkpoint filter {f:?}: use name=PART, vm=NAME or template=IMAGE|ID"),
        }
    }
    let s = |v: &Value, k: &str| v[k].as_str().unwrap_or_default().to_string();
    let matches = |v: &Value, k: &str, want: &str| match k {
        "name" => s(v, "name").contains(want),
        "vm" => s(v, "vm") == want,
        _ => crate::template::name_of(want).is_ok_and(|n| n == s(v, "template")) || (want.len() >= 4 && s(v, "template_id").starts_with(want)),
    };
    let templates = crate::template::images(&Paths::new(&host.state)).unwrap_or_default();
    let mut rows = crate::checkpoint::store::rows(&host.state, &templates);
    // A key again: either value.
    rows.retain(|v| filters.iter().all(|(k, _)| filters.iter().any(|(k2, want)| k2 == k && matches(v, k, want))));
    if args.has("quiet") {
        return rows.iter().try_for_each(|v| output(format_args!("{}\n", s(v, "id"))));
    }
    if let Some(f) = format {
        return output(format_args!("{}", f.render(&rows)?));
    }
    let row = |c: [&str; 7]| output(format_args!("{:<24} {:<16} {:<24} {:<40} {:<24} {:>8} {}\n", c[0], c[1], c[2], c[3], c[4], c[5], c[6]));
    row(["NAME", "ID", "VM", "TEMPLATE", "PARENT", "SIZE MiB", "CREATED"])?;
    for v in &rows {
        let image = v["template"].as_str().map_or("<none>".into(), crate::template::image_of);
        let template = format!("{image} ({})", &s(v, "template_id")[..s(v, "template_id").len().min(8)]);
        let size = (v["size"].as_u64().unwrap_or(0) >> 20).to_string();
        let name = v["name"].as_str().unwrap_or("<none>");
        row([name, &s(v, "id"), &s(v, "vm"), &template, &s(v, "parent"), &size, &crate::ago(v["created"].as_u64())])?;
    }
    Ok(())
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
