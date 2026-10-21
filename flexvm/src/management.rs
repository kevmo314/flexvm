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

/// `disk_usage` of a directory `system df` or prune reports on, followed if it is a link
/// (`templates` or `images` linked to another state's).
fn root_usage(path: &Path, seen: &mut BTreeSet<(u64, u64)>) -> Result<u64> {
    match std::fs::canonicalize(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        r => disk_usage(&r?, seen),
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
        // Checkpoints: stored ones (`checkpoint::store`) and stopped VMs'.
        for (kind, dirs) in [
            ("Images", vec![paths.images.join("rootfs")]),
            ("Templates", vec![paths.templates.clone()]),
            ("Blobs", vec![paths.images.join("blobs")]),
            ("VMs", vec![host.run.join("vms")]),
            ("Checkpoints", vec![crate::checkpoint::store::dir(&host.state), host.state.join("suspended")]),
        ] {
            let bytes = dirs.iter().map(|d| root_usage(d, &mut seen)).sum::<Result<u64>>()?;
            output(format_args!("{kind:<16} {bytes:>16}\n"))?;
        }
        return Ok(());
    }
    let total = || -> Result<u64> {
        let mut seen = BTreeSet::new();
        Ok(root_usage(&paths.images, &mut seen)? + root_usage(&paths.templates, &mut seen)? + root_usage(&host.run.join("vms"), &mut seen)?)
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
    for removed in crate::template::prune(&paths, None, &|| host.template_users(), args.has("force-shared"))? {
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
    ("Names", "names"),
    ("Directory", "directory"),
    ("ID", "id"),
    ("VM", "vm"),
    ("Template", "template"),
    ("TemplateID", "template_id"),
    ("Parent", "parent"),
    ("Size", "size"),
    ("Created", "created"),
    ("Error", "error"),
];

/// `checkpoint ls|rm|prune` (`checkpoint create` is the VM's).
pub fn checkpoints(args: &Args, operation: &str) -> Result<()> {
    use crate::checkpoint::store;
    let host = crate::open_host(args)?;
    let removed = match operation {
        "ls" => return list_checkpoints(&host, args),
        "save" => return save_checkpoint(&host, args),
        "load" => return load_checkpoint(&host, args),
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

/// `checkpoint save NAME|ID [-o FILE]`: to stdout (never a terminal), or to FILE once whole.
fn save_checkpoint(host: &crate::host::Host, args: &Args) -> Result<()> {
    use crate::checkpoint::export;
    let what = args.names().get(1).cloned().unwrap_or_default();
    let paths = Paths::new(&host.state);
    let Some(file) = args.get("output") else {
        if std::io::stdout().is_terminal() {
            bail!("checkpoint save writes a tar: redirect stdout, or give -o FILE");
        }
        let mut out = std::io::BufWriter::with_capacity(1 << 20, std::io::stdout().lock());
        let saved = export::save(&host.state, &paths, &what, &mut out)?;
        out.flush()?;
        // Stdout is the tar: what `load --sha256` takes goes to stderr.
        let _ = writeln!(
            std::io::stderr(),
            "flexvm: saved checkpoint {} (sha256 {})",
            saved["saved"].as_str().unwrap_or(""),
            saved["sha256"].as_str().unwrap_or("")
        );
        return Ok(());
    };
    crate::print(save_checkpoint_file(Path::new(file), |out| export::save(&host.state, &paths, &what, out))?)
}

fn save_checkpoint_file(path: &Path, write: impl FnOnce(&mut dyn Write) -> Result<Value>) -> Result<Value> {
    use sha2::Digest;
    let base = path.file_name().ok_or_else(|| format!("bad -o {:?}: give a file", path.display()))?;
    let dir = crate::host::Directory::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?;
    let key = crate::host::keyed("checkpoint-export", &dir.stat()?, &format!("-{:x}", sha2::Sha256::digest(base.as_encoded_bytes())));
    let Some(_lock) = crate::host::try_lock_at(crate::host::host_locks()?, &key)? else {
        bail!("{}: another checkpoint save to it is in progress", path.display());
    };
    let tmp = dir.path.join(format!(".{}.flexvm-partial", base.to_string_lossy()));
    let partial = || path.with_file_name(format!(".{}.flexvm-partial", base.to_string_lossy())).display().to_string();
    // The key's flock excludes live exports; a fixed name lets the next save reclaim an interrupted one.
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        r => r.map_err(|e| format!("{}: {e}", partial()))?,
    }
    let f = std::fs::File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", partial()))?;
    let written = (|| {
        let mut out = std::io::BufWriter::with_capacity(1 << 20, &f);
        let saved = write(&mut out)?;
        out.flush()?;
        drop(out);
        f.sync_all()?;
        std::fs::rename(&tmp, dir.path.join(base)).map_err(|e| format!("{}: {e}", path.display()))?;
        crate::util::sync_dir(&dir.path)?;
        Ok(saved)
    })();
    let _ = std::fs::remove_file(&tmp);
    written
}

/// `checkpoint load [-i FILE|DIR] [--name NAME]`: a save from stdin (never a terminal) or FILE, or a checkpoint directory.
fn load_checkpoint(host: &crate::host::Host, args: &Args) -> Result<()> {
    use crate::checkpoint::export;
    let (paths, name, sha256) = (Paths::new(&host.state), args.get("name"), args.get("sha256"));
    let loaded = match args.get("input") {
        Some(dir) if std::path::Path::new(dir).is_dir() => export::load_dir(&host.state, &paths, std::path::Path::new(dir), name, sha256)?,
        Some(file) => {
            let f = std::fs::File::open(file).map_err(|e| format!("{file}: {e}"))?;
            export::load(&host.state, &paths, &mut std::io::BufReader::with_capacity(1 << 20, f), name, sha256, &|| host.template_users())?
        }
        None => {
            if std::io::stdin().is_terminal() {
                bail!("checkpoint load reads a save from stdin, not a terminal (or give -i FILE|DIR)");
            }
            export::load(&host.state, &paths, &mut std::io::BufReader::with_capacity(1 << 20, std::io::stdin().lock()), name, sha256, &|| {
                host.template_users()
            })?
        }
    };
    crate::print(loaded)
}

fn checkpoint_name_matches(row: &Value, want: &str) -> bool {
    row["names"].as_array().is_some_and(|names| names.iter().any(|name| name.as_str() == Some(want)))
}

fn checkpoint_names(row: &Value) -> String {
    row["names"].as_array().map(|names| names.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default()
}

fn format_checkpoints(format: &crate::containers::Format, mut rows: Vec<Value>) -> Result<String> {
    if !matches!(format, crate::containers::Format::Json) {
        for v in rows.iter().filter(|v| v["id"].is_null()) {
            drop(writeln!(std::io::stderr(), "flexvm: warning: {}: {}", v["directory"].as_str().unwrap_or_default(), v["error"].as_str().unwrap_or_default()));
        }
        rows.retain(|v| !v["id"].is_null());
        for v in &mut rows {
            v["names"] = checkpoint_names(v).into();
        }
    }
    format.render(&rows)
}

fn list_checkpoints(host: &crate::host::Host, args: &Args) -> Result<()> {
    let format = args.get("format").filter(|f| f.trim() != "table").map(|f| crate::containers::Format::parse_with(f, CHECKPOINT_FIELDS)).transpose()?;
    let mut filters = vec![];
    for f in args.all("filter") {
        match f.split_once('=') {
            Some((k @ ("name" | "vm" | "template"), v)) if !v.is_empty() => filters.push((k.to_string(), v.to_string())),
            _ => bail!("bad checkpoint filter {f:?}: use name=NAME, vm=NAME or template=IMAGE|ID"),
        }
    }
    let s = |v: &Value, k: &str| v[k].as_str().unwrap_or_default().to_string();
    let matches = |v: &Value, k: &str, want: &str| match k {
        "name" => checkpoint_name_matches(v, want),
        "vm" => s(v, "vm") == want,
        _ => crate::template::name_of(want).is_ok_and(|n| n == s(v, "template")) || (want.len() >= 4 && s(v, "template_id").starts_with(want)),
    };
    let templates = crate::template::images(&Paths::new(&host.state)).unwrap_or_default();
    let mut rows = crate::checkpoint::store::rows(&host.state, &templates);
    // A key again: either value. A listing error (no id) stays: what it hid may match.
    rows.retain(|v| v["id"].is_null() || filters.iter().all(|(k, _)| filters.iter().any(|(k2, want)| k2 == k && matches(v, k, want))));
    if args.has("quiet") {
        for v in &rows {
            match v["id"].as_str() {
                Some(id) => output(format_args!("{id}\n"))?,
                None => drop(writeln!(std::io::stderr(), "flexvm: warning: {}: {}", s(v, "directory"), s(v, "error"))),
            }
        }
        return Ok(());
    }
    if let Some(f) = format {
        return output(format_args!("{}", format_checkpoints(&f, rows)?));
    }
    let row = |c: [&str; 7]| output(format_args!("{:<24} {:<16} {:<24} {:<40} {:<24} {:>8} {}\n", c[0], c[1], c[2], c[3], c[4], c[5], c[6]));
    row(["NAME", "ID", "VM", "TEMPLATE", "PARENT", "SIZE MiB", "CREATED"])?;
    for v in &rows {
        if v["id"].is_null() {
            output(format_args!("  {}: {}\n", s(v, "directory"), s(v, "error")))?;
            continue;
        }
        let image = v["template"].as_str().map_or("<none>".into(), crate::template::image_of);
        let template = format!("{image} ({})", &s(v, "template_id")[..s(v, "template_id").len().min(8)]);
        let size = (v["size"].as_u64().unwrap_or(0) >> 20).to_string();
        let names = checkpoint_names(v);
        let name = if names.is_empty() { "<none>" } else { &names };
        // Kept, and blocking rm and prune until removed (`store::readable_or_removed`).
        if let Some(error) = v["error"].as_str() {
            row([name, &s(v, "id"), "<unreadable>", "", "", "", ""])?;
            output(format_args!("  {error}\n"))?;
            continue;
        }
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
        let hex = |n: &str| n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit());
        if entry.file_type()?.is_file() && hex(&name) {
            std::fs::remove_file(entry.path())?;
            output(format_args!("Deleted blob: sha256:{name}\n"))?;
        } else if name.strip_suffix(".verified").is_some_and(hex) {
            // A blob's verification stamp (`image::registry::verified_stamp`) goes with it.
            std::fs::remove_file(entry.path())?;
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
    fn checkpoint_file_reclaims_stale_partial_and_excludes_live_exports() {
        let dir = crate::test_util::TempDir::new("checkpoint-export");
        let path = dir.join("save.tar");
        let partial = dir.join(".save.tar.flexvm-partial");
        std::fs::write(&partial, b"interrupted").unwrap();
        let saved = save_checkpoint_file(&path, |out| {
            let live = save_checkpoint_file(&path, |_| panic!("another export is live")).unwrap_err().to_string();
            assert!(live.contains("in progress"), "{live}");
            assert!(partial.exists());
            out.write_all(b"complete")?;
            Ok(json!({"saved": true}))
        })
        .unwrap();
        assert_eq!(saved, json!({"saved": true}));
        assert_eq!(std::fs::read(&path).unwrap(), b"complete");
        assert!(!partial.exists());
        assert!(save_checkpoint_file(&path, |out| {
            out.write_all(b"failed")?;
            bail!("injected failure")
        })
        .is_err());
        assert!(!partial.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"complete");
    }

    #[test]
    fn checkpoint_name_filters_match_each_whole_name_and_formats_keep_both_fields() {
        let row = json!({"name": "a", "names": ["a", "web-server"], "id": "0123456789abcdef"});
        assert!(checkpoint_name_matches(&row, "a"));
        assert!(checkpoint_name_matches(&row, "web-server"));
        for name in ["web", "server", "a, web-server", ""] {
            assert!(!checkpoint_name_matches(&row, name));
        }
        let format = crate::containers::Format::parse_with("{{.Name}}|{{.Names}}", CHECKPOINT_FIELDS).unwrap();
        let error = json!({"directory": "/state/checkpoints/names", "error": "injected listing error"});
        assert_eq!(format_checkpoints(&format, vec![row.clone(), error.clone()]).unwrap(), "a|a, web-server\n");
        let json = format_checkpoints(&crate::containers::Format::Json, vec![row.clone(), error.clone()]).unwrap();
        let parsed: Vec<Value> = json.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(parsed, [row, error]);
        assert!(!checkpoint_name_matches(&json!({"names": []}), "a"));
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
        std::fs::write(blobs.join(format!("{digest}.verified")), b"stamp").unwrap();
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
        assert!(!blobs.join(format!("{digest}.verified")).exists(), "a blob's stamp goes with it");
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
        // A linked root (`templates` linked to another state's) is followed; links under it are not.
        let state = crate::test_util::TempDir::new("df-linked");
        std::os::unix::fs::symlink(&*dir, state.join("templates")).unwrap();
        assert_eq!(root_usage(&state.join("templates"), &mut BTreeSet::new()).unwrap(), expected);
        assert_eq!(root_usage(&state.join("absent"), &mut BTreeSet::new()).unwrap(), 0);
    }
}
