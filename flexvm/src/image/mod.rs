//! Templates from container images: read-only ext4 root filesystems cached by digest
//! (`blobs/sha256/<hex>`, `rootfs/<key>.ext4`), attached in place, so deleting one breaks its templates.

pub mod auth;
mod reference;
mod registry;
mod source;
mod unpack;
#[path = "../../../guest/src/user.rs"]
mod user;

use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bail;
use crate::guest;
use crate::host::{flock, Flock};
use crate::template::interrupted;
use crate::util::{cpath, is_nonce, random_hex, stat_at};
use crate::util::{ms, rename_noreplace, run_until, sync_dir, Result};
pub use reference::Reference;
pub use registry::download;
use registry::sha256_hex;
pub use unpack::Hashed;
pub use unpack::Limits;
use unpack::{check, open_at, Root};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta {
    pub source: String,
    /// Manifest digest (the config digest for a legacy `docker save`).
    pub digest: String,
    pub config_digest: String,
    pub app_conf: String,
    pub argv: Vec<String>,
    /// Started before the snapshot (true) or on every `run` (false).
    pub warm: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<Ready>,
    #[serde(skip)]
    pub ready_timeout: Duration,
}

impl ImageMeta {
    /// Whether the image has an entrypoint or command to start: one without idles.
    pub fn has_app(&self) -> bool {
        !self.argv.is_empty()
    }

    /// Started at `run` (not before the snapshot, as `--warm` does).
    pub fn starts_at_run(&self) -> bool {
        self.has_app() && !self.warm
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ready {
    Port(u16),
    Cmd(String),
}

/// Serialized fields are part of the cache key.
#[derive(Debug, Default, Serialize)]
pub struct Options {
    /// Not in the key: the same image by another name is the same image.
    #[serde(skip)]
    pub image: String,
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: Vec<String>,
    pub workdir: Option<String>,
    pub user: Option<String>,
    #[serde(skip)]
    pub warm: bool,
    #[serde(skip)]
    pub ready: Option<Ready>,
    #[serde(skip)]
    pub ready_timeout: Duration,
    #[serde(skip)]
    pub limits: Limits,
    #[serde(skip)]
    pub staging: PathBuf,
}

/// `--entrypoint` / `--cmd`: a JSON array, or words split on whitespace.
pub fn parse_argv(s: &str) -> Result<Vec<String>> {
    if s.trim_start().starts_with('[') {
        return Ok(serde_json::from_str(s).map_err(|e| format!("bad JSON argv {s:?}: {e}"))?);
    }
    Ok(s.split_whitespace().map(String::from).collect())
}

struct App {
    argv: Vec<String>,
    env: Vec<String>,
    workdir: String,
    user: String,
    ports: Vec<u16>,
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|s| s.as_str().map(String::from)).collect()
}

fn env_key(kv: &str) -> &str {
    kv.split('=').next().unwrap_or("")
}

fn app_config(config: &Value, o: &Options) -> Result<App> {
    let c = &config["config"];
    // As with `docker run --entrypoint`, a new entrypoint drops the image's command.
    let entrypoint = o.entrypoint.clone().unwrap_or_else(|| strings(&c["Entrypoint"]));
    let cmd = match (&o.cmd, &o.entrypoint) {
        (Some(cmd), _) => cmd.clone(),
        (None, Some(_)) => vec![],
        (None, None) => strings(&c["Cmd"]),
    };
    // None: no app; its VMs idle until told what to run (`exec`, `run -- CMD`).
    let argv: Vec<String> = entrypoint.into_iter().chain(cmd).collect();
    let mut env = strings(&c["Env"]);
    for kv in &o.env {
        env.retain(|e| env_key(e) != env_key(kv));
        env.push(kv.clone());
    }
    let mut ports: Vec<u16> = c["ExposedPorts"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(k, _)| k.strip_suffix("/tcp").or((!k.contains('/')).then_some(k.as_str()))?.parse().ok())
        .collect();
    ports.sort();
    Ok(App {
        argv,
        env,
        workdir: o.workdir.clone().or_else(|| c["WorkingDir"].as_str().map(String::from)).filter(|w| !w.is_empty()).unwrap_or("/".into()),
        user: o.user.clone().or_else(|| c["User"].as_str().map(String::from)).unwrap_or_default(),
        ports,
    })
}

/// `init` is flexvm-init's path, or the one built into flexvm (`artifacts::INIT`) for `None`.
/// The root filesystem comes reserved (`Cached::reserved`): hold it until the template is published.
pub fn prepare(cache: &Path, init: Option<&Path>, o: &Options) -> Result<(PathBuf, ImageMeta, Flock, crate::host::HeldLock)> {
    private_dir(cache, Path::new(""))?;
    let cache_dir = crate::host::Directory::open(cache)?;
    let key = crate::host::keyed("image-cache", &cache_dir.stat()?, "");
    let _cache_lock = crate::host::lock_at(crate::host::host_locks()?, &key, libc::LOCK_SH)?;
    let img = source::resolve(cache, &o.image, &o.limits)?;
    let config: Value = serde_json::from_slice(&img.config)?;
    let (os, arch) = (config["os"].as_str().unwrap_or("linux"), config["architecture"].as_str().unwrap_or("amd64"));
    if os != "linux" || arch != "amd64" {
        bail!("image is {os}/{arch}; only linux/amd64 is supported");
    }
    let app = app_config(&config, o)?;
    if o.warm && app.argv.is_empty() {
        bail!("--warm needs an app: the image has no entrypoint or command; pass --entrypoint or --cmd");
    }
    let ready = match (&o.ready, o.warm) {
        (Some(r), _) => Some(r.clone()),
        (None, true) => match app.ports.first() {
            Some(&p) => Some(Ready::Port(p)),
            None => bail!("--warm needs --ready-port or --ready-cmd: the image exposes no TCP port"),
        },
        (None, false) => None,
    };
    let init_bytes = match init {
        Some(init) => std::fs::read(init).map_err(|e| format!("flexvm-init at {init:?}: {e}"))?,
        None => crate::artifacts::INIT.to_vec(),
    };
    // Rebuild older cached images that lost the image root's metadata.
    let key = json!({
        "v": 4, "config": img.config_digest, "diff_ids": img.diff_ids,
        "init": sha256_hex(&init_bytes), "options": o,
    });
    let key = sha256_hex(key.to_string().as_bytes());
    let cached = cache.join("rootfs").join(format!("{}.ext4", &key["sha256:".len()..]));
    // Killed builds' trees go even if this one is cached (a build sweeps again as it starts).
    if let Some(staging) = o.staging.is_dir().then(|| staging_dir(&o.staging).ok()).flatten() {
        sweep_staging(&staging)?;
    }
    let cached = cached_rootfs(
        &cached,
        |tmp| {
            img.download_layers()?;
            build_rootfs(&o.staging, &img, &app, &init_bytes, tmp, &o.limits)
        },
        sync_dir,
    )?;
    let meta = ImageMeta {
        source: o.image.clone(),
        digest: img.digest,
        config_digest: img.config_digest,
        app_conf: cached.conf,
        argv: app.argv,
        warm: o.warm,
        ready,
        ready_timeout: o.ready_timeout,
    };
    Ok((cached.path, meta, cached.reserved, _cache_lock))
}

pub fn warm_up(vsock: &Path, meta: &ImageMeta) -> Result<()> {
    warm_up_until(vsock, meta, interrupted)
}

fn warm_up_until(vsock: &Path, meta: &ImageMeta, stop: impl Fn() -> Result<()> + Sync) -> Result<()> {
    let start = Instant::now();
    guest::start_app(vsock, "")?;
    loop {
        stop()?;
        let left = meta.ready_timeout.saturating_sub(start.elapsed());
        let ready = match &meta.ready {
            Some(Ready::Port(p)) => guest::probe(vsock, *p, &stop)?,
            Some(Ready::Cmd(c)) => guest::check(vsock, c, left.max(Duration::from_millis(100)), &stop)?,
            None => true,
        };
        // Ready counts only for a running app; a check that ends past the deadline still counts.
        let status = guest::app_status(vsock)?;
        let running = status.starts_with("running ");
        if ready && running {
            crate::log!("image: app ready after {} ms", ms(start.elapsed()));
            return Ok(());
        }
        if !running || start.elapsed() > meta.ready_timeout {
            let logs = read_logs(vsock, Instant::now() + LOGS_TIMEOUT, &stop)?;
            let tail = String::from_utf8_lossy(&logs[logs.len().saturating_sub(4096)..]).into_owned();
            bail!("app not ready ({:?}) after {} ms, status {status}; its output:\n{tail}", meta.ready, ms(start.elapsed()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The guest keeps 1 MiB of app output: far less than this takes to send.
const LOGS_TIMEOUT: Duration = Duration::from_secs(30);

/// All by `deadline`, and given up once `stop` fails: an image's app can stream output without end.
fn read_logs(vsock: &Path, deadline: Instant, stop: impl Fn() -> Result<()>) -> Result<Vec<u8>> {
    const KEEP: usize = 64 << 10;
    let s = guest::start_logs(crate::util::connect_unix(vsock, guest::TIMEOUT)?, 0, false, guest::TIMEOUT)?;
    let mut r = crate::util::By { s, at: deadline };
    let mut out = Vec::new();
    loop {
        stop()?;
        let Some((kind, data)) = guest::read_frame(&mut r).map_err(|e| format!("reading the app's output: {e}"))? else { break };
        if kind == guest::FRAME_MSG {
            return Ok(out);
        }
        out.extend_from_slice(&data);
        if out.len() > 2 * KEEP {
            out.drain(..out.len() - KEEP);
        }
    }
    bail!("guest closed the connection while sending logs")
}

/// Takes `lock` (`how`: shared or exclusive) once its holders let go, unless `stop` fails
/// first (an interrupted build).
fn wait_lock(lock: &File, how: i32, stop: impl Fn() -> Result<()>) -> Result<()> {
    loop {
        stop()?;
        match flock(lock, how | libc::LOCK_NB) {
            Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => std::thread::sleep(Duration::from_millis(100)),
            res => return Ok(res?),
        }
    }
}

fn entry_complete(cached: &Path) -> bool {
    ["ext4", "conf", "ok"].iter().all(|ext| cached.with_extension(ext).is_file())
}

/// A cache entry as `cached_rootfs` hands it out: its root filesystem, its `.conf` as read under the
/// key's lock, and its use lock held shared (taken under the key's lock too), so `remove_rootfs`
/// leaves it until this is dropped: a pull holds it until its template is published.
pub struct Cached {
    pub path: PathBuf,
    pub conf: String,
    pub reserved: Flock,
}

/// Holds a per-key lock through the cache check, build, publication and reservation.
fn cached_rootfs(cached: &Path, build: impl FnOnce(&Path) -> Result<String>, sync: impl Fn(&Path) -> std::io::Result<()>) -> Result<Cached> {
    let dir = cached.parent().unwrap();
    // Entries handed out must survive a crash right after the first build, whoever made the directories.
    // All work is in the directory as opened here, which the locks are keyed by: made private as reached
    // through no symlink, or else as it is.
    let (pinned, private) = match private_dir(dir.parent().unwrap_or(Path::new("")), Path::new(dir.file_name().ok_or("no image cache directory name")?))? {
        Some(fd) => (crate::host::Directory::from_fd(fd), true),
        None => (crate::host::Directory::open(dir)?, false),
    };
    let (original, cached) = (cached, pinned.path.join(cached.file_name().unwrap()));
    let (cached, dir) = (cached.as_path(), pinned.path.as_path());
    sweep_temporaries(&pinned)?;
    // Unlinked while held (`host::HeldLock`).
    let _lock = crate::host::lock_at_with(crate::host::host_locks()?, &key_lock(&pinned, cached)?, |file| {
        wait_lock(file, libc::LOCK_EX, interrupted).map_err(std::io::Error::other)
    })?;
    let marked = match std::fs::symlink_metadata(cached.with_extension("ok")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        res => res.map(|_| true)?,
    };
    if entry_complete(cached) {
        for ext in ["ext4", "conf", "ok"] {
            private_file(private.then_some(&pinned.fd), &cached.with_extension(ext))?;
        }
        // A previous publisher may have failed its fsync after renaming .ok.
        sync(dir)?;
        crate::log!("image: root filesystem cached at {}", original.display());
    } else if marked {
        // Once marked, templates may use the entry: never rebuild it in place.
        bail!(
            "image cache entry {} is marked complete but has missing files; templates may use it, \
             so remove its .ext4, .conf and .ok files (and those templates) to rebuild it",
            original.display()
        );
    } else {
        // Never handed out without its marker, so a crashed build's leftovers can go.
        remove_leftovers(cached)?;
        let tmp = cached.with_extension(format!("tmp{}", random_hex(8)?));
        let res = build(&tmp).and_then(|conf| {
            interrupted()?;
            publish_rootfs(&tmp, cached, &conf, &sync)
        });
        let _ = std::fs::remove_file(&tmp);
        res?;
    }
    // Under the key's lock, which `remove_rootfs` takes first: nothing removes it in between.
    let st = crate::util::fstat(File::open(cached)?.as_raw_fd())?;
    let reserved = crate::host::shared_at(&crate::host::host_locks()?, &crate::host::use_lock(&st))?;
    let conf = std::fs::read_to_string(cached.with_extension("conf"))?;
    // Through the descriptor: the locked directory's path now, wherever it was moved.
    Ok(Cached { path: std::fs::canonicalize(cached)?, conf, reserved })
}

/// What `remove_rootfs` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Removal {
    Removed,
    /// Not in the cache (gone already, or never one of its entries): nothing to do.
    Absent,
    /// A pull checks, builds or holds it (its key's lock or its use lock): asked again later.
    InUse,
}

/// Removes the cache entry `rootfs` (a `rootfs/KEY.ext4` of `cache`) under its key's lock, its
/// marker first, so a build that waits for the lock builds it again. The caller knows no template
/// uses it. Neither lock is waited for: a pull holding either is one of its users (`Removal::InUse`).
pub fn remove_rootfs(cache: &Path, rootfs: &Path) -> Result<Removal> {
    let dir = cache.join("rootfs");
    let (Ok(dir), Some(parent)) = (std::fs::canonicalize(&dir), rootfs.parent()) else { return Ok(Removal::Absent) };
    if std::fs::canonicalize(parent).ok().as_deref() != Some(dir.as_path()) || rootfs.extension() != Some("ext4".as_ref()) {
        return Ok(Removal::Absent);
    }
    let pinned = crate::host::Directory::open(&dir)?;
    let cached = pinned.path.join(rootfs.file_name().unwrap());
    let key = key_lock(&pinned, &cached)?;
    let Some(_lock) = crate::host::try_lock_at(crate::host::host_locks()?, &key)? else { return Ok(Removal::InUse) };
    let st = match File::open(&cached) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Removal::Absent),
        f => crate::util::fstat(f?.as_raw_fd())?,
    };
    // Kept while a pull builds a template of it (`Cached::reserved`).
    let Some(_use) = crate::host::try_lock_at(crate::host::host_locks()?, &crate::host::use_lock(&st))? else { return Ok(Removal::InUse) };
    for ext in ["ok", "ext4", "conf"] {
        match std::fs::remove_file(cached.with_extension(ext)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            r => r?,
        }
        if ext == "ok" {
            sync_dir(&pinned.path)?;
        }
    }
    sync_dir(&pinned.path)?;
    Ok(Removal::Removed)
}

/// A key's lock's name in the host's lock directory (`host::host_locks`): by its
/// directory's (dev, inode), which other users may be able to write, and `KEY.lock`.
fn key_lock(dir: &crate::host::Directory, cached: &Path) -> std::io::Result<String> {
    Ok(crate::host::keyed("image", &dir.stat()?, &format!("-{}", cached.with_extension("lock").file_name().unwrap_or_default().to_string_lossy())))
}

/// Whether `ext` (after a key's `.`) names a build's temporary: `tmp{nonce}` or `part{nonce}`.
fn temporary(ext: &[u8]) -> bool {
    ext.starts_with(b"tmp") || ext.starts_with(b"part")
}

/// Removes temporaries that builds killed meanwhile left under other keys: a key's files are
/// only written under its lock, so with the lock free they are dead.
fn sweep_temporaries(pinned: &crate::host::Directory) -> Result<()> {
    let dir = pinned.path.as_path();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(dot) = name.as_bytes().iter().position(|&b| b == b'.') else { continue };
        let (stem, ext) = (&name.as_bytes()[..dot], &name.as_bytes()[dot + 1..]);
        if !temporary(ext) {
            continue;
        }
        let lock = key_lock(pinned, &dir.join(std::ffi::OsStr::from_bytes(stem)))?;
        let held = match crate::host::lock_at(crate::host::host_locks()?, &lock, libc::LOCK_EX | libc::LOCK_NB) {
            Ok(held) => held,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        };
        crate::log!("image: removing {}, left by a build that did not finish", entry.path().display());
        let _ = std::fs::remove_file(entry.path());
        drop(held);
    }
    Ok(())
}

fn remove_leftovers(cached: &Path) -> Result<()> {
    let dir = cached.parent().unwrap();
    let stem = cached.file_stem().unwrap().as_bytes();
    let mut removed = false;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(ext) = name.as_bytes().strip_prefix(stem).and_then(|r| r.strip_prefix(b".")) else { continue };
        if ext == b"ext4" || ext == b"conf" || temporary(ext) {
            crate::log!("image: removing {} left by an interrupted build", entry.path().display());
            std::fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        sync_dir(dir)?;
    }
    Ok(())
}

/// Publishes immutable files, the completion marker last, never replacing one: the caller's
/// per-key lock leaves no competing publisher, so anything already there is a stray.
fn publish_rootfs(tmp: &Path, cached: &Path, conf: &str, sync: impl Fn(&Path) -> std::io::Result<()>) -> Result<()> {
    // This build's own new file (the builder may have made it with the umask's mode).
    let f = std::os::unix::fs::OpenOptionsExt::custom_flags(File::options().read(true), libc::O_NOFOLLOW).open(tmp)?;
    make_private(&f, 0o600)?;
    f.sync_all()?;
    let dir = cached.parent().unwrap();
    let published = rename_noreplace(tmp, cached)? && publish(&cached.with_extension("conf"), bytes(conf.as_bytes()))? && {
        sync(dir)?;
        publish(&cached.with_extension("ok"), bytes(b""))?
    };
    if !published {
        bail!("image cache entry {} already exists: refusing to replace it", cached.display());
    }
    Ok(sync(dir)?)
}

/// Writes `path` durably via a temporary, never replacing it; false if another publisher won.
pub(super) fn publish(path: &Path, write: impl FnOnce(&mut File) -> Result<()>) -> Result<bool> {
    install(path, write, rename_noreplace)
}

/// As `publish`, but replacing `path`: for content-addressed files that `write` verifies.
pub(super) fn replace(path: &Path, write: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
    install(path, write, |tmp, path| std::fs::rename(tmp, path))
}

/// Parts are made in `dir` under this lock, in the host's lock directory by `dir`'s (dev, inode).
pub(super) fn publish_lock(dir: &crate::host::Directory) -> std::io::Result<File> {
    crate::host::open_lock(&crate::host::host_locks()?, crate::host::keyed("publish", &dir.stat()?, "").as_ref())
}

fn install<T>(path: &Path, write: impl FnOnce(&mut File) -> Result<()>, rename: impl FnOnce(&Path, &Path) -> std::io::Result<T>) -> Result<T> {
    use std::os::unix::fs::OpenOptionsExt;
    // In the directory the publication lock is keyed by, whatever its path names meanwhile.
    let pinned = crate::host::Directory::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?;
    let path = pinned.path.join(path.file_name().ok_or("no file name")?);
    let tmp = path.with_extension(format!("part{}", random_hex(8)?));
    let dir = publish_lock(&pinned)?;
    // Every lock is let go explicitly (`Flock`), not by close: a child another thread forks
    // shares the descriptor until it execs, and would hold the lock on after we return.
    // A part is created and locked under the private publication lock, so
    // `registry::sweep_parts` takes one it can lock for dead.
    let (mut f, part) = {
        let _dir = Flock::new(dir, libc::LOCK_EX)?;
        let f = File::options().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
        // A clone shares the open file, and so the lock.
        let part = f.try_clone().and_then(|c| Flock::new(c, libc::LOCK_EX)).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })?;
        (f, part)
    };
    let res = (|| {
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        write(&mut f)?;
        f.sync_all()?;
        Ok(rename(&tmp, &path)?)
    })();
    // The name is ours alone: gone if renamed, else a failed write's.
    let _ = std::fs::remove_file(&tmp);
    drop(part);
    res
}

/// The cache is private (directories 0700, files 0600), entries made by older versions (0755 and 0644)
/// included, without changing ownership. `cache` (`STATE/images`) is canonicalized, so a symlink there
/// still works; below it, every component is reached through a descriptor that follows no symlink, and a
/// symlink there is left as it is, its contents never touched. Modes change only if they differ: a chmod
/// moves the ctime that template stamps include, and every template using a root filesystem would rehash it.
///
/// Makes `rel` below `cache` (created if missing) and each directory on the way private: `cache` itself
/// only for an empty `rel`. The directory, or None if a symlink was on the way.
fn private_dir(cache: &Path, rel: &Path) -> Result<Option<OwnedFd>> {
    let named = |e: std::io::Error| format!("{}: {e}", cache.join(rel).display());
    let cache = if cache.as_os_str().is_empty() { Path::new(".") } else { cache };
    crate::util::create_dir_durably(cache, 0o700)?;
    let root = std::fs::canonicalize(cache).map_err(named)?;
    let mut fd = crate::util::openat(libc::AT_FDCWD, &cpath(&root)?, libc::O_RDONLY | libc::O_DIRECTORY).map_err(named)?;
    if rel.as_os_str().is_empty() {
        make_private(&fd, 0o700).map_err(named)?;
    }
    for c in rel.components() {
        let std::path::Component::Normal(name) = c else { bail!("{}: not a path below the image cache", rel.display()) };
        let name = cpath(Path::new(name))?;
        let open = |dir: &OwnedFd| crate::util::openat(dir.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW);
        let mut res = open(&fd);
        if res.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            // Made in the directory as reached; a concurrent pull may make it first.
            match crate::util::check(unsafe { libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o700) }) {
                Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(named(e).into()),
                _ => res = open(&fd),
            }
        }
        fd = match res {
            // A symlink: nothing is made under it, and what is there already is synced as found.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => {
                let path = cache.join(rel);
                if path.is_dir() {
                    crate::util::create_dir_durably(&path, 0o700)?;
                }
                return Ok(None);
            }
            res => res.map_err(named)?,
        };
        make_private(&fd, 0o700).map_err(named)?;
    }
    // Entries handed out must survive a crash, whoever made the directories.
    crate::util::sync_ancestors_fd(fd.as_raw_fd()).map_err(named)?;
    Ok(Some(fd))
}

/// `blobs/sha256` (for `blobs`) and the directories above it, as `private_dir` makes them.
fn private_blobs(blobs: &Path) -> Result<Option<OwnedFd>> {
    let name = blobs.file_name().ok_or("no blob directory name")?;
    private_dir(blobs.parent().unwrap_or(Path::new("")), &Path::new(name).join("sha256"))
}

/// The cache file `path` opened for reading, never through a symlink nor blocking on a FIFO: made private
/// through `dir`, its directory as `private_dir` returned it, or left as it is for None.
fn private_file(dir: Option<&OwnedFd>, path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let f = match dir {
        Some(dir) => File::from(crate::util::openat(dir.as_raw_fd(), &cpath(Path::new(path.file_name().ok_or("no file name")?))?, flags)?),
        None => File::options().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?,
    };
    if !f.metadata()?.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if dir.is_some() {
        make_private(&f, 0o600).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(f)
}

fn make_private(fd: &impl AsRawFd, mode: u32) -> std::io::Result<()> {
    if crate::util::fstat(fd.as_raw_fd())?.st_mode & 0o7777 != mode {
        crate::util::check(unsafe { libc::fchmod(fd.as_raw_fd(), mode) })?;
    }
    Ok(())
}

fn bytes(data: &[u8]) -> impl FnOnce(&mut File) -> Result<()> + '_ {
    move |f| Ok(f.write_all(data)?)
}

/// Creates a new file, replacing a stale one but never writing through a symlink.
fn create_new(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    Ok(std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)?)
}

/// Only root may change what `path` names (sticky directories excepted).
fn check_ancestry(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    for dir in path.ancestors() {
        let m = std::fs::symlink_metadata(dir)?;
        let writable = m.mode() & 0o022 != 0 && m.mode() & libc::S_ISVTX == 0;
        if m.uid() != 0 || writable || m.file_type().is_symlink() {
            bail!(
                "image staging directory {}: {} must be root-owned and not writable by others \
                 (choose another --state)",
                path.display(),
                dir.display()
            );
        }
    }
    Ok(())
}

/// The private 0700 staging directory, so no other user can reach the setuid
/// binaries and device nodes an unpacked image carries, or swap the directory.
fn staging_dir(path: &Path) -> Result<OwnedFd> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    let path = std::fs::canonicalize(path)?;
    check_ancestry(&path)?;
    let fd = open_at(libc::AT_FDCWD, &cpath(&path)?, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
    if !stat_at(fd.as_raw_fd(), c"").is_some_and(|st| st.st_uid == 0 && st.st_mode & libc::S_IFMT == libc::S_IFDIR) {
        bail!("{} is not a root-owned directory", path.display());
    }
    check(unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) }, "chmod", &path)?;
    Ok(fd)
}

/// The staging directory's `.lock`: held shared while a build makes its tree and lock,
/// exclusive while one sweeps, so a tree seen then without a held lock is dead.
fn staging_lock(staging: &OwnedFd) -> Result<File> {
    Ok(open_at(staging.as_raw_fd(), c".lock", libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW)?.into())
}

/// A build's unpacked tree, `rootfs-{nonce}` in the staging directory, flocked through
/// `rootfs-{nonce}.lock` beside it (mkfs would copy one inside). Both go when it is dropped;
/// a killed build's go at the next build (`sweep_staging`).
struct Work<'a> {
    staging: &'a OwnedFd,
    name: String,
    lock: File,
}

impl<'a> Work<'a> {
    fn new(staging: &'a OwnedFd) -> Result<Work<'a>> {
        sweep_staging(staging)?;
        // Behind a sweep, which may be removing a huge tree: an interrupt still ends the wait.
        let lock = staging_lock(staging)?;
        wait_lock(&lock, libc::LOCK_SH, interrupted)?;
        let _l = Flock::new(lock, libc::LOCK_SH | libc::LOCK_NB)?;
        let name = format!("rootfs-{}", random_hex(8)?);
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
        let lock: File = open_at(staging.as_raw_fd(), &cpath(Path::new(&format!("{name}.lock")))?, flags)?.into();
        flock(&lock, libc::LOCK_EX)?;
        Ok(Work { staging, name, lock })
    }
}

impl Drop for Work<'_> {
    fn drop(&mut self) {
        let fd = self.staging.as_raw_fd();
        for name in [self.name.clone(), format!("{}.lock", self.name)] {
            if let Err(e) = cpath(Path::new(&name)).and_then(|n| unpack::remove_at(fd, &n)) {
                crate::log!("image: removing staging {name}: {e}");
            }
        }
        let _ = flock(&self.lock, libc::LOCK_UN);
    }
}

/// Removes the trees (and locks) of builds that are gone: their lock free or missing. Best
/// effort: skipped while another build sweeps (or makes its tree), never waited for.
fn sweep_staging(staging: &OwnedFd) -> Result<()> {
    let _l = match Flock::new(staging_lock(staging)?, libc::LOCK_EX | libc::LOCK_NB) {
        Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => return Ok(()),
        res => res?,
    };
    let fd = staging.as_raw_fd();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{fd}"))? {
        interrupted()?;
        let name = entry?.file_name();
        let Some(id) = name.to_str().and_then(|n| n.strip_prefix("rootfs-")) else { continue };
        let id = id.strip_suffix(".lock").unwrap_or(id);
        if !is_nonce(id) {
            continue;
        }
        let lock = cpath(Path::new(&format!("rootfs-{id}.lock")))?;
        if !open_at(fd, &lock, libc::O_RDONLY | libc::O_NOFOLLOW).is_ok_and(|f| Flock::new(File::from(f), libc::LOCK_EX | libc::LOCK_NB).is_err()) {
            crate::log!("image: removing staging {}, left by a build that did not finish", name.to_string_lossy());
            if let Err(e) = unpack::remove_at(fd, &cpath(Path::new(&name))?) {
                crate::log!("image: removing staging {}: {e}", name.to_string_lossy());
            }
        }
    }
    Ok(())
}

fn build_rootfs(staging: &Path, img: &source::Image, app: &App, init: &[u8], dest: &Path, limits: &Limits) -> Result<String> {
    let staging = staging_dir(staging)?;
    let work = Work::new(&staging)?;
    let name = &work.name;
    let cname = cpath(Path::new(name))?;
    // Everything relative to the staging fd, never through its path again.
    let attempt = || {
        check(unsafe { libc::mkdirat(staging.as_raw_fd(), cname.as_ptr(), 0o755) }, "mkdir", Path::new(name))?;
        let res = (|| {
            let work = unpack::open_dir_at(staging.as_raw_fd(), &cname)?;
            // mkdirat applied the umask.
            check(unsafe { libc::fchmod(work.as_raw_fd(), 0o755) }, "chmod", Path::new(name))?;
            let path = PathBuf::from(format!("/proc/{}/fd/{}/{name}", std::process::id(), staging.as_raw_fd()));
            let mut root = Root::from_fd(work, *limits);
            unpack_layers(&mut root, img)?;
            let conf = inject(&mut root, app, init)?;
            root.restore_root_metadata()?;
            interrupted()?;
            mkfs(&path, root.entries, dest)?;
            Ok(conf)
        })();
        // Before a retry; otherwise `work` removes it.
        if res.is_err() {
            if let Err(e) = unpack::remove_at(staging.as_raw_fd(), &cname) {
                crate::log!("image: removing staging {name}: {e}");
            }
        }
        res
    };
    // Cached blobs are read once, as they are unpacked: one found corrupt is
    // evicted, and the unpack starts over with it downloaded (and checked)
    // again; at most once per layer, however many turn out corrupt.
    retry_evicted(&img.layers, attempt)
}

fn retry_evicted<T>(layers: &[source::Layer], mut attempt: impl FnMut() -> Result<T>) -> Result<T> {
    let mut retried = vec![false; layers.len()];
    loop {
        match attempt() {
            Err(e) if interrupted().is_ok() => {
                let evicted: Vec<_> = layers.iter().enumerate().filter(|(_, l)| l.src.evicted()).map(|(i, _)| i).collect();
                if evicted.is_empty() || evicted.iter().any(|&i| retried[i]) {
                    return Err(e);
                }
                for i in evicted {
                    retried[i] = true;
                }
                crate::log!("image: {e}; downloading it again");
            }
            res => return res,
        }
    }
}

/// Checks each blob against its descriptor and its contents against the config's diff_ids.
fn unpack_layers(root: &mut Root, img: &source::Image) -> Result<()> {
    for (i, layer) in img.layers.iter().enumerate() {
        interrupted()?;
        crate::log!("image: applying layer {}/{} {}", i + 1, img.layers.len(), layer.name());
        let what = |e| format!("layer {}: {e}", layer.name());
        let mut blob = layer.open().map_err(what)?;
        let applied = unpack::decompress(&mut blob).and_then(|r| root.apply_layer(r));
        // A corrupt blob usually breaks unpacking too: report its digest first.
        layer.verify(blob).map_err(what)?;
        let diff_id = applied.map_err(what)?;
        if diff_id != img.diff_ids[i] {
            bail!("layer {} unpacks to {diff_id}, the image config says {}", layer.name(), img.diff_ids[i]);
        }
    }
    Ok(())
}

pub fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n")
}

fn inject(root: &mut Root, app: &App, init: &[u8]) -> Result<String> {
    for (dir, mode) in [("proc", 0o555), ("sys", 0o555), ("dev", 0o755), ("run", 0o755), ("tmp", 0o1777), ("mnt", 0o755), ("root", 0o700), ("sbin", 0o755)] {
        root.ensure_dir(dir, mode)?;
    }
    root.write_file("sbin/flexvm-init", init, 0o755)?;
    root.write_file("etc/hosts", b"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\tflexvm\n", 0o644)?;
    // Docker bind-mounts its own; images usually ship none, or a symlink into /run.
    if !root.is_file("etc/resolv.conf") {
        root.write_file("etc/resolv.conf", b"", 0o644)?;
    }
    let workdir = app.workdir.trim_start_matches('/');
    if !workdir.is_empty() {
        root.ensure_dir(workdir, 0o755)?;
    }
    let (uid, gid, home, groups) = resolve_user(root, &app.user)?;
    let mut env = app.env.clone();
    for (k, v) in [("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"), ("HOME", &home)] {
        if !env.iter().any(|e| env_key(e) == k) {
            env.push(format!("{k}={v}"));
        }
    }
    let mut conf: String = app.argv.iter().map(|a| format!("arg {}\n", escape(a))).chain(env.iter().map(|e| format!("env {}\n", escape(e)))).collect();
    conf += &format!("cwd {}\nuid {uid}\ngid {gid}\n", escape(&app.workdir));
    conf += &format!("groups {}\n", groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(" "));
    root.secure_dir("etc/flexvm", 0o755)?;
    root.write_file("etc/flexvm/app.conf", conf.as_bytes(), 0o644)?;
    Ok(conf)
}

/// Resolves an image `User` against the image's own /etc/passwd and /etc/group.
fn resolve_user(root: &Root, user: &str) -> Result<(u32, u32, String, Vec<u32>)> {
    let passwd = root.read("etc/passwd").unwrap_or_default();
    let group = root.read("etc/group").unwrap_or_default();
    Ok(self::user::resolve_user(user, &String::from_utf8_lossy(&passwd), &String::from_utf8_lossy(&group))?)
}

/// ext4 needs blocks for directory entries and symlinks too long for their inode (60 bytes).
/// Staging filesystems may report no allocated blocks for these, so `du` alone is insufficient.
fn ext4_extra_kib(dir: &Path) -> Result<u64> {
    let mut dirs = vec![dir.to_path_buf()];
    let mut kib = 0;
    while let Some(dir) = dirs.pop() {
        let mut bytes = 24u64; // `.` and `..`, including their entry headers.
        for entry in std::fs::read_dir(dir)? {
            interrupted()?;
            let entry = entry?;
            // Each entry has an 8-byte header and a name rounded up to 4 bytes.
            bytes += 8 + (entry.file_name().as_bytes().len() as u64).div_ceil(4) * 4;
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                dirs.push(entry.path());
            } else if metadata.is_symlink() && metadata.len() >= 60 {
                kib += 4;
            }
        }
        // Leave room for directory indexing and block tails as well as the entries.
        kib += (bytes * 2).div_ceil(4096) * 4;
    }
    Ok(kib)
}

/// Sized to content and 256-byte inodes plus headroom, rounded up to 2 MiB as virtio-pmem requires.
fn mkfs(dir: &Path, entries: u64, dest: &Path) -> Result<()> {
    let du = run_until(Command::new("du").arg("-sk").arg(dir), interrupted)?;
    let kib: u64 = String::from_utf8_lossy(&du.stdout).split_whitespace().next().and_then(|s| s.parse().ok()).ok_or("du failed")?;
    let kib = kib + ext4_extra_kib(dir)?;
    let inodes = entries * 12 / 10 + 4096;
    let mib = ((kib + inodes / 4) * 12 / 10 / 1024 + 64).div_ceil(2) * 2;
    // mkfs writes through our descriptor, so the name cannot be swapped for a symlink.
    let image = create_new(dest)?;
    image.set_len(mib << 20)?;
    let meta = std::fs::metadata(dir)?;
    // root_owner is in every mke2fs we support; root_perms only since e2fsprogs 1.47.1.
    let root = format!("root_owner={}:{}", meta.uid(), meta.gid());
    let image_path = format!("/proc/{}/fd/{}", std::process::id(), image.as_raw_fd());
    let mut cmd = Command::new("mkfs.ext4");
    cmd.args(["-q", "-F", "-b", "4096", "-I", "256", "-L", "flexroot", "-N", &inodes.to_string(), "-d"]);
    cmd.arg(dir).args(["-E", &root]).arg(&image_path);
    let out = run_until(&mut cmd, interrupted).map_err(|e| format!("mkfs.ext4: {e}"))?;
    if !out.status.success() {
        bail!("mkfs.ext4 failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    // Root xattrs come with -d (from 1.45.7); its mode and mtime are set here, as older mke2fs can't.
    for (field, value) in [("mode", format!("0{:o}", libc::S_IFDIR | (meta.mode() & 0o7777))), ("mtime", format!("@{}", meta.mtime()))] {
        let out = run_until(Command::new("debugfs").args(["-w", "-R", &format!("set_inode_field / {field} {value}"), &image_path]), interrupted)?;
        // debugfs also reports command errors on stderr with a successful exit status.
        let errors = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() || errors.lines().any(|line| !line.starts_with("debugfs ")) {
            bail!("debugfs setting root {field} failed: {}", errors.trim());
        }
    }
    crate::log!("image: root filesystem built ({mib} MiB, {entries} entries)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, FileExt, MetadataExt};
    use unpack::tests::{layer, tmpdir};

    fn read(p: impl AsRef<Path>) -> String {
        std::fs::read_to_string(p).unwrap()
    }

    #[test]
    fn warm_readiness_requires_a_running_app_before_the_deadline() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;

        for (status, timeout, ok) in [
            ("exited 0", Duration::from_secs(5), false),
            ("idle", Duration::from_secs(5), false),
            ("running 1", Duration::ZERO, true),
            ("running 1", Duration::from_secs(5), true),
        ] {
            let dir = tmpdir("warm-status");
            let path = dir.join("vsock");
            let listener = UnixListener::bind(&path).unwrap();
            let meta = ImageMeta {
                source: String::new(),
                digest: String::new(),
                config_digest: String::new(),
                app_conf: String::new(),
                argv: vec![],
                warm: true,
                ready: Some(Ready::Cmd("true".into())),
                ready_timeout: timeout,
            };
            std::thread::scope(|scope| {
                let server = scope.spawn(|| {
                    for request in 0..if ok { 3 } else { 4 } {
                        let (stream, _) = listener.accept().unwrap();
                        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        let mut r = BufReader::new(stream);
                        let mut line = String::new();
                        r.read_line(&mut line).unwrap();
                        assert_eq!(line, format!("CONNECT {}\n", guest::PORT));
                        line.clear();
                        r.read_line(&mut line).unwrap();
                        let reply = match request {
                            0 => {
                                assert_eq!(line, "APP\n");
                                "ok 1"
                            }
                            1 => {
                                assert!(line.starts_with("CHECK "));
                                "ok"
                            }
                            2 => {
                                assert_eq!(line, "APPSTATUS\n");
                                status
                            }
                            _ => {
                                assert!(line.starts_with("LOGS "));
                                "done"
                            }
                        };
                        r.get_mut().write_all(b"OK 1\n").unwrap();
                        if request == 3 {
                            guest::write_frame(r.get_mut(), guest::FRAME_STDOUT, b"app output").unwrap();
                        }
                        guest::write_frame(r.get_mut(), guest::FRAME_MSG, reply.as_bytes()).unwrap();
                    }
                });
                let result = warm_up_until(&path, &meta, || Ok(()));
                if ok {
                    result.unwrap();
                } else {
                    let e = result.unwrap_err().to_string();
                    assert!(e.contains(status) && e.contains("app output"), "{e}");
                }
                server.join().unwrap();
            });
        }
    }

    #[test]
    fn warm_readiness_is_cancelled_during_handshake_and_partial_replies() {
        use std::io::{BufRead, BufReader, Read};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicBool, Ordering};

        for ready in [Ready::Port(8080), Ready::Cmd("sleep 120".into())] {
            for partial in [b"".as_slice(), b"OK 1\n\x04", b"OK 1\n\x04\x02\x00\x00\x00o"] {
                let dir = tmpdir("warm-cancel");
                let path = dir.join("vsock");
                let listener = UnixListener::bind(&path).unwrap();
                let stopped = AtomicBool::new(false);
                let meta = ImageMeta {
                    source: String::new(),
                    digest: String::new(),
                    config_digest: String::new(),
                    app_conf: String::new(),
                    argv: vec![],
                    warm: true,
                    ready: Some(ready.clone()),
                    ready_timeout: Duration::from_secs(120),
                };
                std::thread::scope(|scope| {
                    let server = scope.spawn(|| {
                        for app in [true, false] {
                            let (stream, _) = listener.accept().unwrap();
                            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                            let mut r = BufReader::new(stream);
                            let mut line = String::new();
                            r.read_line(&mut line).unwrap();
                            assert_eq!(line, format!("CONNECT {}\n", guest::PORT));
                            line.clear();
                            r.read_line(&mut line).unwrap();
                            if app {
                                assert_eq!(line, "APP\n");
                                r.get_mut().write_all(b"OK 1\n").unwrap();
                                guest::write_frame(r.get_mut(), guest::FRAME_MSG, b"ok 1").unwrap();
                            } else {
                                assert!(line.starts_with("PROBE 8080") || line.starts_with("CHECK "));
                                r.get_mut().write_all(partial).unwrap();
                                std::thread::sleep(Duration::from_millis(100));
                                stopped.store(true, Ordering::Relaxed);
                                assert_eq!(r.read(&mut [0]).unwrap(), 0, "cancellation closes the request");
                            }
                        }
                    });
                    let start = Instant::now();
                    let stop = || if stopped.load(Ordering::Relaxed) { Err("interrupted".into()) } else { Ok(()) };
                    assert_eq!(warm_up_until(&path, &meta, stop).unwrap_err().to_string(), "interrupted");
                    assert!(start.elapsed() < Duration::from_secs(2));
                    server.join().unwrap();
                });
            }
        }
    }

    #[test]
    fn endless_app_output_is_read_by_a_deadline_and_until_stopped() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // An app's output that never ends: frames keep coming, never the closing status.
        let endless = |listener: &UnixListener| {
            let (stream, _) = listener.accept().unwrap();
            let mut r = BufReader::new(stream);
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            line.clear();
            r.read_line(&mut line).unwrap();
            assert_eq!(line, "LOGS 0 0\n");
            r.get_mut().write_all(b"OK 1\n").unwrap();
            while guest::write_frame(r.get_mut(), guest::FRAME_STDOUT, &[b'x'; 4096]).is_ok() {}
        };
        let dir = tmpdir("endless-logs");
        let path = dir.join("vsock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| endless(&listener));
            let start = Instant::now();
            let e = read_logs(&path, Instant::now() + Duration::from_millis(300), || Ok(())).unwrap_err();
            assert!(e.to_string().contains("deadline passed"), "{e}");
            assert!(start.elapsed() < Duration::from_secs(3), "{:?}", start.elapsed());
            server.join().unwrap();

            let server = scope.spawn(|| endless(&listener));
            let checks = AtomicUsize::new(0);
            let stop = || if checks.fetch_add(1, Ordering::Relaxed) >= 100 { Err("interrupted".into()) } else { Ok(()) };
            let e = read_logs(&path, Instant::now() + Duration::from_secs(60), stop).unwrap_err();
            assert_eq!(e.to_string(), "interrupted");
            server.join().unwrap();
        });
    }

    #[test]
    fn ext4_estimate_counts_directory_and_long_symlink_blocks() {
        let dir = tmpdir("ext4-blocks");
        assert_eq!(ext4_extra_kib(&dir).unwrap(), 4);
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("file"), b"contents").unwrap();
        symlink("a", dir.join("directory-link")).unwrap();
        symlink("x".repeat(59), dir.join("inline-link")).unwrap();
        assert_eq!(ext4_extra_kib(&dir).unwrap(), 12);
        symlink("x".repeat(60), dir.join("block-link")).unwrap();
        symlink("x".repeat(100), dir.join("a/b/long-link")).unwrap();
        assert_eq!(ext4_extra_kib(&dir).unwrap(), 20);
    }

    #[test]
    fn ext4_estimate_counts_large_directory_blocks() {
        let dir = tmpdir("ext4-large-dir");
        for i in 0..100 {
            std::fs::write(dir.join(format!("{i:0255}")), b"").unwrap();
        }
        // 24 bytes for dot entries, 264 per long name, doubled for headroom.
        assert_eq!(ext4_extra_kib(&dir).unwrap(), 52);
    }

    #[test]
    fn layer_root_metadata_survives_ext4_build() {
        let dir = tmpdir("root-metadata");
        let staging = dir.join("root");
        std::fs::create_dir(&staging).unwrap();
        let mut root = Root::open(&staging, Limits::default()).unwrap();
        // Exercise 1000:1000 as root or the usual developer user; other users use their own IDs.
        let uid = if unsafe { libc::geteuid() } == 0 { 1000 } else { unsafe { libc::geteuid() } };
        let gid = if unsafe { libc::geteuid() } == 0 { 1000 } else { unsafe { libc::getegid() } };
        for (path, mode, mtime, note) in [("./", 0o750, 1234567890, "first"), (".", 0o770, 1234567891, "middle"), ("/", 0o700, 1234567892, "last")] {
            let mut layer = tar::Builder::new(Vec::new());
            let acl = |mask| {
                let mut acl = 2u32.to_le_bytes().to_vec();
                for (tag, perm, id) in [(1u16, 7u16, u32::MAX), (2, 5, uid), (4, 5, u32::MAX), (16, mask, u32::MAX), (32, 0, u32::MAX)] {
                    acl.extend_from_slice(&tag.to_le_bytes());
                    acl.extend_from_slice(&perm.to_le_bytes());
                    acl.extend_from_slice(&id.to_le_bytes());
                }
                acl
            };
            let (access, default) = (acl((mode >> 3) as u16 & 7), acl(5));
            layer
                .append_pax_extensions([
                    ("SCHILY.xattr.user.note", note.as_bytes()),
                    ("SCHILY.xattr.system.posix_acl_access", access.as_slice()),
                    ("SCHILY.xattr.system.posix_acl_default", default.as_slice()),
                ])
                .unwrap();
            let mut h = tar::Header::new_ustar();
            // The tar builder refuses absolute paths, so spell the root header verbatim.
            h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
            h.set_entry_type(tar::EntryType::Directory);
            h.set_mode(mode);
            h.set_uid(uid as u64);
            h.set_gid(gid as u64);
            h.set_mtime(mtime);
            h.set_size(0);
            h.set_cksum();
            layer.get_mut().extend_from_slice(h.as_bytes());
            layer.get_mut().extend_from_slice(&unpack::tests::layer(&[("child", 'f', "data")]));
            root.apply_layer(layer.into_inner().unwrap().as_slice()).unwrap();
            let expected = (uid, gid, mode, mtime as i64);
            let metadata = || {
                let meta = std::fs::metadata(&staging).unwrap();
                (meta.uid(), meta.gid(), meta.mode() & 0o7777, meta.mtime())
            };
            assert_eq!(metadata(), expected);
            // A layer without a root entry keeps the previous layer's root metadata.
            root.apply_layer(unpack::tests::layer(&[("later", 'f', "data")]).as_slice()).unwrap();
            assert_eq!(metadata(), expected);
            // Injection must not change the final root timestamp either.
            root.write_file("injected", b"init", 0o755).unwrap();
            root.restore_root_metadata().unwrap();
            assert_eq!(metadata(), expected);
            let dest = dir.join(format!("{note}.ext4"));
            mkfs(&staging, root.entries, &dest).unwrap();
            // debugfs's root edits keep the inode checksum valid.
            let fsck = Command::new("e2fsck").arg("-fn").arg(&dest).output().unwrap();
            assert!(fsck.status.success(), "{}", String::from_utf8_lossy(&fsck.stdout));
            let out = Command::new("debugfs").args(["-R", "stat /"]).arg(&dest).output().unwrap();
            assert!(out.status.success());
            let stat = String::from_utf8(out.stdout).unwrap();
            assert!(stat.contains(&format!("Mode:  {mode:04o}")), "{stat}");
            assert!(stat.contains(&format!("User: {uid:5}   Group: {gid:5}")), "{stat}");
            assert!(stat.contains(&format!("mtime: 0x{mtime:08x}")), "{stat}");
            assert!(stat.contains("system.posix_acl_default"), "{stat}");
            assert!(stat.contains("system.posix_acl_access"), "{stat}");
            assert!(stat.contains(&format!("user.note ({}) = \"{note}\"", note.len())), "{stat}");
        }
    }

    #[test]
    fn mkfs_has_room_for_inode_heavy_images() {
        let dir = tmpdir("mkfs-inodes");
        let root = dir.join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("empty"), b"").unwrap();
        symlink("empty", root.join("link")).unwrap();
        let dest = dir.join("root.ext4");
        // Request the inode budget of a million-entry tree without creating it.
        mkfs(&root, 1_000_000, &dest).unwrap();
        let mut superblock = [0u8; 256];
        File::open(&dest).unwrap().read_exact_at(&mut superblock, 1024).unwrap();
        assert_eq!(&superblock[56..58], &0xef53u16.to_le_bytes());
        assert!(u32::from_le_bytes(superblock[..4].try_into().unwrap()) >= 1_204_096);
        assert_eq!(u16::from_le_bytes(superblock[88..90].try_into().unwrap()), 256);
        assert_eq!(std::fs::metadata(&dest).unwrap().len() % (2 << 20), 0);
    }

    /// Names in `dir` a build writes before renaming: `.tmp{nonce}` and `.part{nonce}`.
    fn temporaries(dir: &Path) -> Vec<String> {
        let names = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned());
        names.filter(|n| n.contains(".tmp") || n.contains(".part")).collect()
    }

    #[test]
    fn cache_permissions_are_private_on_publish_and_reuse() {
        use std::os::unix::fs::MetadataExt;
        let d = tmpdir("cache-private");
        let cache = d.join("images");
        private_dir(&cache, Path::new("")).unwrap();
        let cached = cache.join("rootfs/key.ext4");
        cached_rootfs(&cached, build("private"), sync_dir).unwrap();
        let owner = std::fs::metadata(&cached).unwrap().uid();
        for legacy in [false, true] {
            if legacy {
                for dir in [&cache, cached.parent().unwrap()] {
                    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
                }
                for ext in ["ext4", "conf", "ok"] {
                    std::fs::set_permissions(cached.with_extension(ext), std::fs::Permissions::from_mode(0o644)).unwrap();
                }
                private_dir(&cache, Path::new("")).unwrap();
                cached_rootfs(&cached, never, sync_dir).unwrap();
            }
            for dir in [&cache, cached.parent().unwrap()] {
                let m = std::fs::metadata(dir).unwrap();
                assert_eq!((m.mode() & 0o777, m.uid()), (0o700, owner));
            }
            for ext in ["ext4", "conf", "ok"] {
                let m = std::fs::metadata(cached.with_extension(ext)).unwrap();
                assert_eq!((m.mode() & 0o777, m.uid()), (0o600, owner));
            }
        }
        // Already private: reuse leaves the ctime that template stamps include.
        let stamp = |p: &Path| std::fs::metadata(p).map(|m| (m.ctime(), m.ctime_nsec())).unwrap();
        let before = stamp(&cached);
        std::thread::sleep(Duration::from_millis(20));
        private_dir(&cache, Path::new("")).unwrap();
        cached_rootfs(&cached, never, sync_dir).unwrap();
        assert_eq!(stamp(&cached), before);
    }

    #[test]
    fn cache_permissions_never_follow_symlinks() {
        use std::os::unix::fs::MetadataExt;
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().mode() & 0o777;
        let d = tmpdir("cache-private-links");
        // STATE/images may be a symlink: its target is the cache, made private.
        let real = d.join("real-images");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cache = d.join("images");
        std::os::unix::fs::symlink(&real, &cache).unwrap();
        // Below it, a symlinked component is left alone, and so is everything under it.
        let outside = d.join("outside");
        std::fs::create_dir_all(outside.join("sha256")).unwrap();
        std::os::unix::fs::symlink(&outside, real.join("blobs")).unwrap();
        let digest = sha256_hex(b"blob");
        let blob = registry::blob_path(&cache.join("blobs"), &digest).unwrap();
        std::fs::write(&blob, b"blob").unwrap();
        let rootfs = d.join("outside-rootfs");
        std::fs::create_dir(&rootfs).unwrap();
        std::os::unix::fs::symlink(&rootfs, real.join("rootfs")).unwrap();
        let cached = cache.join("rootfs/key.ext4");
        cached_rootfs(&cached, build("linked"), sync_dir).unwrap();
        for p in [&outside, &outside.join("sha256"), &rootfs] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        for p in [blob.clone(), rootfs.join("key.ext4"), rootfs.join("key.conf"), rootfs.join("key.ok")] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        private_dir(&cache, Path::new("")).unwrap();
        let registry = std::sync::Arc::new(registry::Registry::new(Reference::parse("localhost/test").unwrap()));
        let (mut reader, _) = source::Blob::Cached { blobs: cache.join("blobs"), registry, digest, size: 4 }.open().unwrap();
        let mut data = Vec::new();
        reader.read_to_end(&mut data).unwrap();
        assert_eq!(data, b"blob");
        cached_rootfs(&cached, never, sync_dir).unwrap();

        assert_eq!(mode(&real), 0o700);
        for p in [&outside, &outside.join("sha256"), &rootfs] {
            assert_eq!(mode(p), 0o755, "{}", p.display());
        }
        for p in [blob, rootfs.join("key.ext4"), rootfs.join("key.conf"), rootfs.join("key.ok")] {
            assert_eq!(mode(&p), 0o644, "{}", p.display());
        }
        // Nothing is made under a symlink: a linked blob directory without `sha256` stays without one.
        let empty = d.join("outside-empty");
        std::fs::create_dir(&empty).unwrap();
        let other = d.join("other-images");
        std::fs::create_dir(&other).unwrap();
        std::os::unix::fs::symlink(&empty, other.join("blobs")).unwrap();
        assert!(private_blobs(&other.join("blobs")).unwrap().is_none());
        assert!(!empty.join("sha256").exists());
        // Missing directories are made private, through the walk.
        let fresh = d.join("fresh");
        assert!(private_blobs(&fresh.join("blobs")).unwrap().is_some());
        for p in [fresh.join("blobs"), fresh.join("blobs/sha256")] {
            assert_eq!(mode(&p), 0o700, "{}", p.display());
        }
        // A symlinked file is refused, its target untouched.
        let file = d.join("file");
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&file, real.join("file-link")).unwrap();
        let dir = private_dir(&cache, Path::new("")).unwrap();
        assert!(private_file(dir.as_ref(), &cache.join("file-link")).is_err());
        assert!(private_file(None, &cache.join("file-link")).is_err());
        assert_eq!(mode(&file), 0o644);
    }

    #[test]
    fn each_evicted_layer_gets_one_retry() {
        let d = tmpdir("layer-retry");
        let layers: Vec<_> = (0..3)
            .map(|i| {
                let digest = sha256_hex(&[i]);
                let path = registry::blob_path(&d, &digest).unwrap();
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, [i]).unwrap();
                source::Layer {
                    src: source::Blob::Cached {
                        blobs: d.to_path_buf(),
                        registry: std::sync::Arc::new(registry::Registry::new(Reference::parse("localhost/test").unwrap())),
                        digest: digest.clone(),
                        size: 1,
                    },
                    digest: Some(digest),
                    size: Some(1),
                }
            })
            .collect();
        let mut calls = 0;
        let result: Result<()> = retry_evicted(&layers, || {
            calls += 1;
            if calls <= layers.len() {
                if calls > 1 {
                    std::fs::write(registry::blob_path(&d, layers[calls - 2].digest.as_ref().unwrap())?, b"fixed")?;
                }
                std::fs::remove_file(registry::blob_path(&d, layers[calls - 1].digest.as_ref().unwrap())?)?;
                bail!("corrupt layer");
            }
            bail!("download failed");
        });
        assert_eq!(calls, layers.len() + 1);
        assert!(result.unwrap_err().to_string().contains("download failed"));
        let mut calls = 0;
        let result: Result<()> = retry_evicted(&layers, || {
            calls += 1;
            bail!("download failed");
        });
        assert!(result.is_err());
        assert_eq!(calls, 2, "a missing blob must not consume other layers' retries");
    }

    #[test]
    fn install_uses_the_directory_opened_before_the_writer_runs() {
        let root = tmpdir("install-swap");
        let dir = root.join("cache");
        let moved = root.join("old");
        std::fs::create_dir(&dir).unwrap();
        replace(&dir.join("blob"), |f| {
            std::fs::rename(&dir, &moved)?;
            std::fs::create_dir(&dir)?;
            Ok(f.write_all(b"pinned")?)
        })
        .unwrap();
        assert!(!dir.join("blob").exists());
        assert_eq!(read(moved.join("blob")), "pinned");
        assert!(temporaries(&moved).is_empty());
    }

    fn lock_of(cached: &Path) -> String {
        key_lock(&crate::host::Directory::open(cached.parent().unwrap()).unwrap(), cached).unwrap()
    }

    #[test]
    fn cache_returns_the_locked_directorys_entry_when_its_path_is_replaced_and_removes_its_lock() {
        let root = tmpdir("cache-swap");
        let dir = root.join("cache");
        let moved = root.join("old");
        std::fs::create_dir(&dir).unwrap();
        let cached = dir.join("key.ext4");
        let lock_name = lock_of(&cached);
        let result = cached_rootfs(
            &cached,
            |tmp| {
                std::fs::rename(&dir, &moved)?;
                std::fs::create_dir(&dir)?;
                build("pinned")(tmp)
            },
            sync_dir,
        );
        assert_eq!(result.unwrap().path, std::fs::canonicalize(moved.join("key.ext4")).unwrap());
        assert!(!cached.exists());
        assert_eq!(read(moved.join("key.ext4")), "pinned image");
        assert!(crate::host::existing_lock(&crate::host::host_locks().unwrap(), lock_name.as_ref()).is_err());
    }

    #[test]
    fn install_leaves_no_part_and_never_touches_anothers() {
        let dir = tmpdir("install");
        let path = dir.join("blob");
        let theirs = dir.join("blob.part0123456789abcdef");
        std::fs::write(&theirs, "theirs").unwrap();
        replace(&path, bytes(b"ours")).unwrap();
        assert_eq!(read(&path), "ours");
        assert!(replace(&path, |_| Err("failed".into())).is_err());
        assert_eq!(read(&path), "ours");
        assert_eq!(read(&theirs), "theirs");
        std::fs::remove_file(&theirs).unwrap();
        assert!(temporaries(&dir).is_empty());
    }

    #[test]
    fn install_lets_go_of_its_locks_though_a_child_shares_them() {
        let dir = tmpdir("install-unlock");
        let path = dir.join("blob");
        let mut shared = Vec::new();
        replace(&path, |f| {
            // As a child forked meanwhile by another thread would, until it execs.
            shared.push(f.try_clone()?);
            Ok(f.write_all(b"ours")?)
        })
        .unwrap();
        // The renamed part and the private publication lock are both released.
        flock(&File::open(&path).unwrap(), libc::LOCK_EX | libc::LOCK_NB).expect("the part's lock is let go");
        flock(&publish_lock(&crate::host::Directory::open(&dir).unwrap()).unwrap(), libc::LOCK_EX | libc::LOCK_NB).expect("the publication lock is let go");
        drop(shared);
    }

    fn nonces(n: usize) -> Vec<String> {
        (0..n).map(|_| random_hex(8).unwrap()).collect()
    }

    #[test]
    fn lock_waits_end_when_interrupted() {
        let d = tmpdir("lock-wait");
        let open = || File::options().write(true).create(true).truncate(false).open(d.join("key.lock")).unwrap();
        let (held, waiting) = (open(), open());
        flock(&held, libc::LOCK_EX).unwrap();
        let calls = std::cell::Cell::new(0);
        let start = Instant::now();
        let stop = || match calls.replace(calls.get() + 1) {
            3 => Err("interrupted".into()),
            _ => Ok(()),
        };
        assert_eq!(wait_lock(&waiting, libc::LOCK_EX, stop).unwrap_err().to_string(), "interrupted");
        assert!(start.elapsed() < Duration::from_secs(5));
        // Unlocked, not only closed: a child another test forks meanwhile shares the lock until it execs.
        flock(&held, libc::LOCK_UN).unwrap();
        wait_lock(&waiting, libc::LOCK_EX, || Ok(())).unwrap();
        flock(&waiting, libc::LOCK_UN).unwrap();
    }

    #[test]
    fn sweeps_never_wait_and_builds_wait_only_until_interrupted() {
        let d = tmpdir("staging-busy");
        let staging = open_at(libc::AT_FDCWD, &cpath(&d).unwrap(), libc::O_RDONLY | libc::O_DIRECTORY).unwrap();
        let dead = format!("rootfs-{}", random_hex(8).unwrap());
        std::fs::create_dir(d.join(&dead)).unwrap();
        // Another build sweeping.
        let sweeping = staging_lock(&staging).unwrap();
        flock(&sweeping, libc::LOCK_EX).unwrap();
        let start = Instant::now();
        sweep_staging(&staging).unwrap();
        assert!(d.join(&dead).exists(), "skipped, not waited for");
        let waiting = staging_lock(&staging).unwrap();
        let stop = || match start.elapsed() > Duration::from_millis(300) {
            true => Err("interrupted".into()),
            false => Ok(()),
        };
        assert_eq!(wait_lock(&waiting, libc::LOCK_SH, stop).unwrap_err().to_string(), "interrupted");
        assert!(start.elapsed() < Duration::from_secs(5));
        // Unlocked, not only closed: a child another test forks meanwhile shares the lock until it execs.
        flock(&sweeping, libc::LOCK_UN).unwrap();
        sweep_staging(&staging).unwrap();
        assert!(!d.join(&dead).exists());
    }

    #[test]
    fn killed_builds_staging_is_swept() {
        let d = tmpdir("staging-sweep");
        let staging = open_at(libc::AT_FDCWD, &cpath(&d).unwrap(), libc::O_RDONLY | libc::O_DIRECTORY).unwrap();
        let n = nonces(4);
        let (dead, live, unlocked, lone) = (&n[0], &n[1], &n[2], &n[3]);
        for id in [dead, live, unlocked] {
            std::fs::create_dir_all(d.join(format!("rootfs-{id}/usr/bin"))).unwrap();
            std::fs::write(d.join(format!("rootfs-{id}/usr/bin/sh")), "sh").unwrap();
        }
        for id in [dead, live, lone] {
            std::fs::write(d.join(format!("rootfs-{id}.lock")), "").unwrap();
        }
        let held = File::open(d.join(format!("rootfs-{live}.lock"))).unwrap();
        flock(&held, libc::LOCK_EX).unwrap();
        // Named by pid by older builds: no lock says whose (pids are per namespace, and reused), so kept.
        let (gone, running) = ("rootfs-2147483647".to_string(), format!("rootfs-{}", std::process::id()));
        for name in [&gone, &running, &"other".to_string()] {
            std::fs::create_dir(d.join(name)).unwrap();
        }
        let names = || {
            let mut v: Vec<String> = std::fs::read_dir(&*d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            v.sort();
            v
        };
        let mut want = vec![".lock".to_string(), "other".into(), format!("rootfs-{live}"), format!("rootfs-{live}.lock"), running.clone(), gone.clone()];
        want.sort();
        {
            let work = Work::new(&staging).unwrap();
            assert!(d.join(format!("{}.lock", work.name)).exists());
            let mut with_ours = want.clone();
            with_ours.push(format!("{}.lock", work.name));
            with_ours.sort();
            assert_eq!(names(), with_ours);
            std::fs::create_dir(d.join(&work.name)).unwrap();
            std::fs::write(d.join(&work.name).join("f"), "").unwrap();
        }
        assert_eq!(names(), want);
        // Unlocked, not only closed: a child another test forks meanwhile shares the lock until it execs.
        flock(&held, libc::LOCK_UN).unwrap();
        drop(held);
        sweep_staging(&staging).unwrap();
        want.retain(|n| !n.contains(live.as_str()));
        assert_eq!(names(), want);
    }

    #[test]
    fn explicit_user_group_excludes_supplementary_memberships() {
        let dir = tmpdir("user-groups");
        std::fs::create_dir(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/passwd"), "app:x:1000:1000::/home/app:/bin/sh\n").unwrap();
        std::fs::write(dir.join("etc/group"), "app:x:1000:app\nshadow:x:42:app\nrestricted:x:2000:\nshadow-alias:x:42:app\n").unwrap();
        let root = Root::open(&dir, Limits::default()).unwrap();
        for user in ["app", "1000", "app:", "1000:"] {
            assert_eq!(resolve_user(&root, user).unwrap(), (1000, 1000, "/home/app".into(), vec![1000, 42]));
        }
        for user in ["app:restricted", "app:2000", "1000:restricted", "1000:2000"] {
            assert_eq!(resolve_user(&root, user).unwrap(), (1000, 2000, "/home/app".into(), vec![2000]));
        }
        assert_eq!(resolve_user(&root, "app:app").unwrap().3, [1000]);
        assert_eq!(resolve_user(&root, "9999:2000").unwrap(), (9999, 2000, "/".into(), vec![2000]));
        std::fs::remove_file(dir.join("etc/group")).unwrap();
        let root = Root::open(&dir, Limits::default()).unwrap();
        assert_eq!(resolve_user(&root, "app").unwrap().3, [1000]);
        assert_eq!(resolve_user(&root, "app:2000").unwrap().3, [2000]);
        assert!(resolve_user(&root, "app:restricted").is_err());
    }

    /// Injection takes /etc/flexvm and app.conf from an image user who owns them, as `owner`.
    fn secure_config_directory(app_owned: bool, owner: (u32, u32)) {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmpdir("secure-conf");
        let conf_dir = dir.join("etc/flexvm");
        std::fs::create_dir_all(&conf_dir).unwrap();
        let conf_path = conf_dir.join("app.conf");
        std::fs::write(&conf_path, "attacker config").unwrap();
        if app_owned {
            std::os::unix::fs::chown(&conf_dir, Some(1000), Some(1000)).unwrap();
            std::os::unix::fs::chown(&conf_path, Some(1000), Some(1000)).unwrap();
        }
        std::fs::set_permissions(&conf_dir, std::fs::Permissions::from_mode(0o2777)).unwrap();
        std::fs::set_permissions(&conf_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let app = app_config(&json!({"config": {"Cmd": ["/bin/app"], "User": "1000:1000"}}), &Options::default()).unwrap();
        let mut root = Root::open(&dir, Limits::default()).unwrap();
        let conf = inject(&mut root, &app, b"init").unwrap();
        for (path, mode) in [(&conf_dir, 0o755), (&conf_path, 0o644)] {
            let meta = std::fs::metadata(path).unwrap();
            assert_eq!((meta.uid(), meta.gid(), meta.mode() & 0o7777), (owner.0, owner.1, mode));
        }
        assert_eq!(read(&conf_path), conf);
        assert!(conf.contains("\nuid 1000\ngid 1000\ngroups 1000\n"));
    }

    #[test]
    fn injection_secures_existing_config_directory() {
        secure_config_directory(false, unsafe { (libc::geteuid(), libc::getegid()) });
    }

    /// Needs root: `sudo cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn injection_secures_existing_app_owned_config_directory() {
        secure_config_directory(true, (0, 0));
    }

    #[test]
    fn image_config_preserves_carriage_returns_through_injection() {
        let config = json!({"config": {
            "Entrypoint": ["/bin/app\r"], "Cmd": ["\r", " a\r\nb\\r \t\r", ""],
            "Env": ["FOO=bar\r", "EMPTY=", "CR=\r"], "WorkingDir": "/srv\r",
        }});
        let app = app_config(&config, &Options::default()).unwrap();
        assert_eq!(app.argv, ["/bin/app\r", "\r", " a\r\nb\\r \t\r", ""]);
        assert_eq!(app.env, ["FOO=bar\r", "EMPTY=", "CR=\r"]);
        assert_eq!(app.workdir, "/srv\r");
        let dir = tmpdir("conf-cr");
        let mut root = Root::open(&dir, Limits::default()).unwrap();
        let conf = inject(&mut root, &app, b"init").unwrap();
        assert!(conf.starts_with("arg /bin/app\r\narg \r\narg  a\r\\nb\\\\r \t\r\narg \nenv FOO=bar\r\nenv EMPTY=\nenv CR=\r\n"));
        assert!(conf.contains("\ncwd /srv\r\n"));
        assert_eq!(root.read("etc/flexvm/app.conf").unwrap(), conf.as_bytes());
    }

    #[test]
    fn overrides() {
        let config = json!({"config": {
            "Entrypoint": ["/docker-entrypoint.sh"], "Cmd": ["nginx", "-g", "daemon off;"],
            "Env": ["PATH=/bin", "A=1"], "ExposedPorts": {"443/tcp": {}, "80/tcp": {}, "53/udp": {}},
        }});
        let app = app_config(&config, &Options::default()).unwrap();
        assert_eq!(app.argv, ["/docker-entrypoint.sh", "nginx", "-g", "daemon off;"]);
        assert_eq!(app.ports, [80, 443]);
        assert_eq!(app.workdir, "/");
        let o = Options { cmd: Some(vec!["x".into()]), env: vec!["A=2".into()], ..Default::default() };
        let app = app_config(&config, &o).unwrap();
        assert_eq!(app.argv, ["/docker-entrypoint.sh", "x"]);
        assert_eq!(app.env, ["PATH=/bin", "A=2"]);
        let o = Options { entrypoint: Some(vec!["/bin/sh".into()]), ..Default::default() };
        assert_eq!(app_config(&config, &o).unwrap().argv, ["/bin/sh"]);
        // No app: its VMs idle.
        assert!(app_config(&json!({"config": {}}), &Options::default()).unwrap().argv.is_empty());
        assert_eq!(parse_argv(r#"["a b", "c"]"#).unwrap(), ["a b", "c"]);
        assert_eq!(parse_argv("python3 -m http.server").unwrap(), ["python3", "-m", "http.server"]);
    }

    #[test]
    fn cache_directories_are_created_durably_and_errors_name_them() {
        let d = tmpdir("durable");
        crate::util::create_dir_durably(&d.join("images/rootfs"), 0o777).unwrap();
        assert!(d.join("images/rootfs").is_dir());
        let e = sync_dir(&d.join("missing")).unwrap_err().to_string();
        assert!(e.contains(&d.join("missing").display().to_string()), "{e}");
        std::fs::write(d.join("file"), b"").unwrap();
        let e = crate::util::create_dir_durably(&d.join("file/x"), 0o777).unwrap_err().to_string();
        assert!(e.contains("file/x"), "{e}");
    }

    fn config(layer: &[u8]) -> String {
        json!({"architecture": "amd64", "os": "linux", "config": {"Cmd": ["/x"]}, "rootfs": {"type": "layers", "diff_ids": [sha256_hex(layer)]}}).to_string()
    }

    fn fetch(src: &Path, limits: &Limits) -> Result<source::Image> {
        source::resolve(Path::new("/nonexistent"), src.to_str().unwrap(), limits)
    }

    fn unpack(src: &Path, out: &Path) -> Result<String> {
        let img = fetch(src, &Limits::default())?;
        std::fs::create_dir_all(out).unwrap();
        unpack_layers(&mut Root::open(out, Limits::default())?, &img)?;
        Ok(read(out.join("a")))
    }

    #[test]
    fn docker_save_layers_must_match_the_config_diff_ids() {
        let (good, evil) = (layer(&[("a", 'f', "good")]), layer(&[("a", 'f', "evil")]));
        for (i, held) in [&good, &evil].into_iter().enumerate() {
            let d = tmpdir(&format!("diffid{i}"));
            std::fs::create_dir(d.join("l")).unwrap();
            std::fs::write(d.join("config.json"), config(&good)).unwrap();
            std::fs::write(d.join("l/layer.tar"), held).unwrap();
            std::fs::write(d.join("manifest.json"), r#"[{"Config": "config.json", "Layers": ["l/../l/layer.tar"]}]"#).unwrap();
            match unpack(&d, &d.join("out")) {
                Ok(a) => assert_eq!((i, a.as_str()), (0, "good")),
                Err(e) => assert!(i == 1 && e.to_string().contains("the image config says"), "{e}"),
            }
        }
        let d = tmpdir("archive");
        let tar = layer(&[
            ("config.json", 'f', &config(&good)),
            ("l/layer.tar", 'f', std::str::from_utf8(&good).unwrap()),
            ("l/link.tar", 'l', "./layer.tar"),
            ("manifest.json", 'f', r#"[{"Config": "config.json", "Layers": ["l/link.tar"]}]"#),
        ]);
        std::fs::write(d.join("img.tar"), tar).unwrap();
        assert_eq!(unpack(&d.join("img.tar"), &d.join("out")).unwrap(), "good");
        let e = fetch(&d.join("img.tar"), &Limits { entries: 2, ..Limits::default() }).err().unwrap().to_string();
        assert!(e.contains("--max-entries"), "{e}");
    }

    #[test]
    fn docker_save_directory_links_stay_inside() {
        let d = tmpdir("docker-links");
        let saved = d.join("saved");
        std::fs::create_dir_all(saved.join("original")).unwrap();
        std::fs::create_dir(saved.join("dedup")).unwrap();
        let tar = layer(&[("a", 'f', "good")]);
        std::fs::write(saved.join("config.json"), config(&tar)).unwrap();
        std::fs::write(saved.join("original/layer.tar"), &tar).unwrap();
        std::fs::write(saved.join("manifest.json"), r#"[{"Config": "config.json", "Layers": ["dedup/layer.tar"]}]"#).unwrap();
        let link = saved.join("dedup/layer.tar");
        symlink("../original/layer.tar", &link).unwrap();
        // Also accept a symlink naming the docker-save directory itself.
        symlink(&saved, d.join("alias")).unwrap();
        assert_eq!(unpack(&d.join("alias"), &d.join("out")).unwrap(), "good");
        std::fs::remove_file(&link).unwrap();
        symlink(saved.join("original/layer.tar"), &link).unwrap();
        assert_eq!(unpack(&saved, &d.join("absolute-out")).unwrap(), "good");

        // Prefix siblings, absolute targets and links through directories must not escape.
        let outside = d.join("saved-other");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("layer.tar"), &tar).unwrap();
        symlink(&outside, saved.join("escape")).unwrap();
        for target in [PathBuf::from("../../saved-other/layer.tar"), outside.join("layer.tar"), PathBuf::from("../escape/layer.tar")] {
            std::fs::remove_file(&link).unwrap();
            symlink(target, &link).unwrap();
            let err = fetch(&saved, &Limits::default()).err().unwrap().to_string();
            assert!(err.contains("escapes image directory"), "{err}");
        }
    }

    fn oci_layout(dir: &Path, layer: &[u8]) -> (String, String) {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(layer).unwrap();
        let blob = gz.finish().unwrap();
        let config = config(layer);
        let put = |data: &[u8]| {
            let d = sha256_hex(data);
            let p = registry::blob_path(&dir.join("blobs"), &d).unwrap();
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, data).unwrap();
            d
        };
        let (cd, ld) = (put(config.as_bytes()), put(&blob));
        let manifest = json!({"schemaVersion": 2, "config": {"digest": cd, "size": config.len()}, "layers": [{"digest": ld, "size": blob.len()}]}).to_string();
        let md = put(manifest.as_bytes());
        std::fs::write(dir.join("index.json"), json!({"manifests": [{"digest": md, "size": manifest.len()}]}).to_string()).unwrap();
        (cd, ld)
    }

    #[test]
    fn local_blobs_are_verified() {
        let layer = layer(&[("a", 'f', "data")]);
        let d = tmpdir("oci-ok");
        oci_layout(&d, &layer);
        assert_eq!(unpack(&d, &d.join("out")).unwrap(), "data");
        let tiny = Limits { download: 10, ..Limits::default() };
        assert!(fetch(&d, &tiny).err().unwrap().to_string().contains("download limit"));

        // A changed gzip mtime keeps the layer valid but fails its compressed digest.
        let d = tmpdir("oci-layer");
        let (_, ld) = oci_layout(&d, &layer);
        let p = registry::blob_path(&d.join("blobs"), &ld).unwrap();
        let mut b = std::fs::read(&p).unwrap();
        b[4] ^= 0xff;
        std::fs::write(&p, &b).unwrap();
        let e = unpack(&d, &d.join("out")).unwrap_err().to_string();
        assert!(e.contains("has digest"), "{e}");
        assert_eq!(read(d.join("out/a")), "data");
        let cached = d.join("cache/key.ext4");
        let e = cached_rootfs(
            &cached,
            |_| {
                unpack(&d, &d.join("staging"))?;
                panic!("a corrupt layer must fail before building the rootfs");
            },
            sync_dir,
        );
        assert!(e.err().unwrap().to_string().contains("has digest"));
        assert!(["ext4", "conf", "ok"].iter().all(|e| !cached.with_extension(e).exists()));

        let d = tmpdir("oci-config");
        let (cd, _) = oci_layout(&d, &layer);
        let p = registry::blob_path(&d.join("blobs"), &cd).unwrap();
        std::fs::write(&p, read(&p).replace("/x", "/y")).unwrap();
        assert!(fetch(&d, &Limits::default()).is_err());
    }

    #[test]
    fn cached_documents_are_verified() {
        let d = tmpdir("cached-doc");
        let p = d.join("config");
        let digest = sha256_hex(b"{}");
        std::fs::write(&p, b"{}").unwrap();
        assert!(source::read_verified(&p, File::open(&p).unwrap(), 2, &digest).is_ok());
        assert!(source::read_verified(&p, File::open(&p).unwrap(), 3, &digest).is_err());
        // Read as opened: what the path names afterwards is never read.
        let opened = File::open(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"[]").unwrap();
        assert_eq!(source::read_verified(&p, opened, 2, &digest).unwrap(), b"{}");
        std::fs::write(&p, b"[]").unwrap();
        assert!(source::read_verified(&p, File::open(&p).unwrap(), 2, &digest).is_err());
        let max = unpack::MAX_DOCUMENT + 1;
        std::fs::write(&p, vec![b' '; max as usize]).unwrap();
        assert!(source::read_verified(&p, File::open(&p).unwrap(), max, &digest).is_err());
    }

    #[test]
    fn staging_needs_a_root_only_ancestry() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("ancestry");
        std::fs::set_permissions(&*d, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(check_ancestry(&d).unwrap_err().to_string().contains("must be root-owned"));
        std::fs::set_permissions(&*d, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink("/", d.join("link")).unwrap();
        assert!(check_ancestry(&d.join("link")).is_err());
    }

    fn build(what: &'static str) -> impl FnOnce(&Path) -> Result<String> {
        move |tmp| {
            std::fs::write(tmp, format!("{what} image"))?;
            Ok(format!("{what} config"))
        }
    }

    fn never(_: &Path) -> Result<String> {
        panic!("must reuse the cached entry, not build")
    }

    #[test]
    fn publication_never_replaces_or_follows() {
        let d = tmpdir("noreplace");
        let victim = d.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        symlink(&victim, d.join("x")).unwrap();
        assert!(!publish(&d.join("x"), bytes(b"new")).unwrap());
        assert_eq!(read(&victim), "keep");
        assert!(std::fs::symlink_metadata(d.join("x")).unwrap().file_type().is_symlink());

        let (cached, tmp) = (d.join("key.ext4"), d.join("build"));
        std::fs::write(&tmp, "first image").unwrap();
        publish_rootfs(&tmp, &cached, "first config", sync_dir).unwrap();
        let inode = std::fs::metadata(&cached).unwrap().ino();
        std::fs::write(&tmp, "second image").unwrap();
        assert!(publish_rootfs(&tmp, &cached, "second config", sync_dir).is_err());
        assert_eq!(std::fs::metadata(&cached).unwrap().ino(), inode);
        assert_eq!(read(&cached), "first image");
        assert!(!publish(&cached.with_extension("conf"), bytes(b"second config")).unwrap());
        assert!(!publish(&cached.with_extension("ok"), bytes(b"replacement marker")).unwrap());
        assert_eq!(read(cached.with_extension("conf")), "first config");
        assert_eq!(read(cached.with_extension("ok")), "");
        // An existing image without its marker cannot be reused.
        std::fs::remove_file(cached.with_extension("ok")).unwrap();
        assert!(publish_rootfs(&tmp, &cached, "second config", sync_dir).is_err());
        assert!(!cached.with_extension("ok").exists());
        // Nor can an existing config: no marker is published for it.
        let cached = d.join("other.ext4");
        std::fs::write(cached.with_extension("conf"), "existing config").unwrap();
        assert!(publish_rootfs(&tmp, &cached, "new config", sync_dir).is_err());
        assert_eq!(read(cached.with_extension("conf")), "existing config");
        assert!(!cached.with_extension("ok").exists());
    }

    #[test]
    fn rootfs_cache_hit_resolves_config_without_downloading_layers() {
        use std::io::{BufRead, BufReader};
        let d = tmpdir("rootfs-no-download");
        let config = config(b"missing layer");
        let cd = sha256_hex(config.as_bytes());
        let ld = sha256_hex(b"missing compressed layer");
        let manifest = json!({"schemaVersion": 2, "config": {"digest": cd, "size": config.len()}, "layers": [{"digest": ld, "size": 24}]}).to_string();
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let image = format!("{}/test", server.local_addr().unwrap());
        let config_body = config.clone();
        let serving = std::thread::spawn(move || {
            for body in [manifest, config_body] {
                let (mut socket, _) = server.accept().unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                assert!(!request.contains(&ld), "a rootfs cache hit requested a layer");
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            }
            // Further requests fail: the layer is absent locally and remotely.
        });
        let init = d.join("init");
        std::fs::write(&init, b"init").unwrap();
        let o = Options { image, ..Options::default() };
        let config_value: Value = serde_json::from_str(&config).unwrap();
        let key = json!({"v": 4, "config": cd, "diff_ids": config_value["rootfs"]["diff_ids"], "init": sha256_hex(b"init"), "options": o});
        let key = sha256_hex(key.to_string().as_bytes());
        let cached = d.join("rootfs").join(format!("{}.ext4", &key[7..]));
        cached_rootfs(&cached, build("cached"), sync_dir).unwrap();
        let (path, meta, _reserved, _cache_lock) = prepare(&d, Some(&init), &o).unwrap();
        serving.join().unwrap();
        assert_eq!(read(path), "cached image");
        assert_eq!(meta.app_conf, "cached config");
    }

    #[test]
    fn cache_reuses_the_entry_by_its_canonical_path() {
        let d = tmpdir("reuse");
        std::fs::create_dir(d.join("real")).unwrap();
        symlink(d.join("real"), d.join("alias")).unwrap();
        let cached = d.join("alias/key.ext4");
        let path = cached_rootfs(&cached, build("first"), sync_dir).unwrap().path;
        assert_eq!(path, std::fs::canonicalize(d.join("real/key.ext4")).unwrap());
        assert_eq!(read(&path), "first image");
        assert_eq!(read(path.with_extension("conf")), "first config");
        assert!(temporaries(&d.join("real")).is_empty());
        assert_eq!(cached_rootfs(&cached, never, sync_dir).unwrap().path, path);
        std::fs::remove_file(path.with_extension("conf")).unwrap();
        assert!(cached_rootfs(&cached, never, sync_dir).is_err());
        assert_eq!(read(&path), "first image");
    }

    #[test]
    fn cache_durability_failure_is_retried_before_reuse() {
        let d = tmpdir("durability");
        let cached = d.join("key.ext4");
        let fail_after_marker = |dir: &Path| {
            assert_eq!(std::fs::metadata(dir)?.ino(), std::fs::metadata(&*d)?.ino());
            if cached.with_extension("ok").exists() {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            sync_dir(dir)
        };
        assert!(cached_rootfs(&cached, build("first"), fail_after_marker).is_err());
        assert!(entry_complete(&cached));
        let inode = std::fs::metadata(&cached).unwrap().ino();
        // A cache hit must retry that fsync, and still refuse on failure.
        assert!(cached_rootfs(&cached, never, fail_after_marker).is_err());
        let path = cached_rootfs(&cached, never, sync_dir).unwrap().path;
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        std::fs::remove_file(cached.with_extension("conf")).unwrap();
        assert!(cached_rootfs(&cached, never, sync_dir).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    }

    #[test]
    fn removed_rootfs_goes_marker_first_and_only_from_the_cache() {
        let root = crate::test_util::TempDir::new("rmi-rootfs");
        let dir = root.join("images/rootfs");
        std::fs::create_dir_all(&dir).unwrap();
        for ext in ["ext4", "conf", "ok"] {
            std::fs::write(dir.join(format!("k.{ext}")), ext).unwrap();
        }
        std::fs::write(root.join("k.ext4"), "elsewhere").unwrap();
        let images = root.join("images");
        assert_eq!(remove_rootfs(&images, &root.join("k.ext4")).unwrap(), Removal::Absent);
        assert_eq!(remove_rootfs(&images, &dir.join("k.conf")).unwrap(), Removal::Absent);
        assert!(root.join("k.ext4").exists() && entry_complete(&dir.join("k.ext4")));
        // A pull building a template of it holds it until it is published.
        let building = cached_rootfs(&dir.join("k.ext4"), never, sync_dir).unwrap();
        assert_eq!(building.conf, "conf");
        assert_eq!(remove_rootfs(&images, &dir.join("k.ext4")).unwrap(), Removal::InUse);
        assert!(entry_complete(&dir.join("k.ext4")));
        drop(building);
        // One checking or building it holds its key's lock: not waited for.
        let pinned = crate::host::Directory::open(&dir).unwrap();
        let key = crate::host::lock_at(crate::host::host_locks().unwrap(), &key_lock(&pinned, &pinned.path.join("k.ext4")).unwrap(), libc::LOCK_EX).unwrap();
        assert_eq!(remove_rootfs(&images, &dir.join("k.ext4")).unwrap(), Removal::InUse);
        drop(key);
        assert_eq!(remove_rootfs(&images, &dir.join("k.ext4")).unwrap(), Removal::Removed);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(remove_rootfs(&images, &dir.join("k.ext4")).unwrap(), Removal::Absent);
    }

    /// #631: an rmi between the cache check and reading `.conf` (or reserving) made the pull fail.
    /// Both are under the key's lock now: every pull racing removals gets an intact, reserved entry.
    ///
    /// #810: a remover never pausing held the key's lock nearly always (its lock file made and
    /// unlinked each time, slow on a disk), and a pull takes it by polling every 100 ms: pulls
    /// starved for many minutes. The remover is in `remove_rootfs` a tenth of the time at most.
    #[test]
    fn a_pull_racing_removals_always_gets_a_reserved_entry() {
        use crate::test_util::JoinWithin;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        use std::sync::Arc;
        /// Ends the remover however the test ends, so a failure leaves nothing spinning.
        struct Stop(Arc<AtomicBool>);
        impl Drop for Stop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let root = crate::test_util::TempDir::new("rmi-pull-race");
        let (images, cached) = (root.join("images"), root.join("images/rootfs/k.ext4"));
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        let (stop, tries, removed) = (Stop(Arc::new(AtomicBool::new(false))), Arc::new(AtomicU32::new(0)), Arc::new(AtomicU32::new(0)));
        let remover = {
            let (stop, tries, removed, images, cached) = (stop.0.clone(), tries.clone(), removed.clone(), images.clone(), cached.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let start = Instant::now();
                    if remove_rootfs(&images, &cached).unwrap() == Removal::Removed {
                        removed.fetch_add(1, Ordering::SeqCst);
                    }
                    tries.fetch_add(1, Ordering::SeqCst);
                    let rest = Instant::now() + start.elapsed() * 9;
                    while !stop.load(Ordering::SeqCst) && Instant::now() < rest {
                        std::thread::sleep(Duration::from_millis(10).min(rest.saturating_duration_since(Instant::now())));
                    }
                }
            })
        };
        let pulls = {
            let (tries, removed, images) = (tries.clone(), removed.clone(), images.clone());
            std::thread::spawn(move || {
                // Called under the pull's key lock, after its cache check (and in a publication): refused there.
                let sync = |dir: &Path| {
                    assert_eq!(remove_rootfs(&images, &cached).unwrap(), Removal::InUse);
                    sync_dir(dir)
                };
                // A time budget (a slow disk slows the remover tenfold), but past one removal at least.
                let until = Instant::now() + Duration::from_secs(5);
                let mut round = 0;
                while round < 300 && (Instant::now() < until || removed.load(Ordering::SeqCst) == 0) {
                    let got = cached_rootfs(&cached, build("built"), sync).unwrap();
                    assert_eq!(got.conf, "built config");
                    assert_eq!(remove_rootfs(&images, &cached).unwrap(), Removal::InUse);
                    assert_eq!(read(&got.path), "built image");
                    drop(got);
                    // Every other round, a removal tried wholly after the entry is let go.
                    if round % 2 == 0 {
                        let from = tries.load(Ordering::SeqCst);
                        while tries.load(Ordering::SeqCst) < from + 2 {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    }
                    round += 1;
                }
            })
        };
        pulls.join_within().unwrap();
        drop(stop);
        remover.join_within().unwrap();
        assert!(removed.load(Ordering::SeqCst) > 0, "the remover never got in: the race was not exercised");
    }

    #[test]
    fn interrupted_publication_is_rebuilt() {
        let d = tmpdir("interrupted");
        let cached = d.join("key.ext4");
        // A build killed after the rootfs rename, mid-way through the config.
        // Under other keys too: one whose build still runs (its lock held), two whose builds are gone.
        let files = [("key.ext4", "half published"), ("key.part123", "partial"), ("key.tmp456", "abandoned"), ("other.tmp789", "other key")];
        let more = [("other.lock", ""), ("gone.lock", ""), ("gone.tmp0123456789abcdef", "dead"), ("nolock.part0123456789abcdef", "dead")];
        let locks = crate::host::host_locks().unwrap();
        for (name, data) in files.into_iter().chain(more) {
            match name.strip_suffix(".lock") {
                Some(key) => drop(crate::host::open_lock(&locks, lock_of(&d.join(key)).as_ref()).unwrap()),
                None => std::fs::write(d.join(name), data).unwrap(),
            }
        }
        let held = crate::host::existing_lock(&locks, lock_of(&d.join("other")).as_ref()).unwrap();
        flock(&held, libc::LOCK_EX).unwrap();
        let old = File::open(&cached).unwrap();
        let path = cached_rootfs(&cached, build("rebuilt"), sync_dir).unwrap().path;
        assert_eq!(read(&path), "rebuilt image");
        assert_eq!(read(path.with_extension("conf")), "rebuilt config");
        assert!(path.with_extension("ok").exists());
        assert_ne!(old.metadata().unwrap().ino(), std::fs::metadata(&path).unwrap().ino());
        assert_eq!(std::io::read_to_string(old).unwrap(), "half published");
        assert!(!d.join("key.part123").exists() && !d.join("key.tmp456").exists());
        assert!(d.join("other.tmp789").exists());
        assert_eq!(temporaries(&d), ["other.tmp789"]);
        flock(&held, libc::LOCK_UN).unwrap();
    }

    #[test]
    fn concurrent_cache_builds_wait_and_reuse() {
        use std::sync::mpsc;
        let d = tmpdir("cache-lock");
        let cached = d.join("key.ext4");
        let ((building, started), (release, wait)) = (mpsc::channel(), mpsc::channel());
        let first_path = cached.clone();
        let first = std::thread::spawn(move || {
            cached_rootfs(
                &first_path,
                |tmp| {
                    building.send(()).unwrap();
                    wait.recv().unwrap();
                    assert!(!first_path.with_extension("ok").exists());
                    build("first")(tmp)
                },
                sync_dir,
            )
            .unwrap()
            .path
        });
        started.recv().unwrap();
        let lock = crate::host::existing_lock(&crate::host::host_locks().unwrap(), lock_of(&cached).as_ref()).unwrap();
        assert_eq!(flock(&lock, libc::LOCK_EX | libc::LOCK_NB).unwrap_err().raw_os_error(), Some(libc::EWOULDBLOCK));
        let second_path = cached.clone();
        let second = std::thread::spawn(move || cached_rootfs(&second_path, never, sync_dir).unwrap().path);
        release.send(()).unwrap();
        assert_eq!(first.join().unwrap(), second.join().unwrap());
        assert_eq!(read(&cached), "first image");
    }
}
