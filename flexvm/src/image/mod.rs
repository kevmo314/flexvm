//! Templates from container images: read-only ext4 root filesystems cached by digest
//! (`blobs/sha256/<hex>`, `rootfs/<key>.ext4`), attached in place, so deleting one breaks its templates.

mod reference;
mod registry;
mod source;
mod unpack;

use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
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
    let argv: Vec<String> = entrypoint.into_iter().chain(cmd).collect();
    if argv.is_empty() {
        bail!("the image has no entrypoint or command; pass --entrypoint or --cmd");
    }
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
pub fn prepare(cache: &Path, init: Option<&Path>, o: &Options) -> Result<(PathBuf, ImageMeta)> {
    let img = source::resolve(cache, &o.image, &o.limits)?;
    let config: Value = serde_json::from_slice(&img.config)?;
    let (os, arch) = (config["os"].as_str().unwrap_or("linux"), config["architecture"].as_str().unwrap_or("amd64"));
    if os != "linux" || arch != "amd64" {
        bail!("image is {os}/{arch}; only linux/amd64 is supported");
    }
    let app = app_config(&config, o)?;
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
    // Rebuild older cached images with Docker's explicit-group semantics and protected app config.
    let key = json!({
        "v": 3, "config": img.config_digest, "diff_ids": img.diff_ids,
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
    let app_conf = std::fs::read_to_string(cached.with_extension("conf"))?;
    let meta = ImageMeta {
        source: o.image.clone(),
        digest: img.digest,
        config_digest: img.config_digest,
        app_conf,
        argv: app.argv,
        warm: o.warm,
        ready,
        ready_timeout: o.ready_timeout,
    };
    Ok((cached, meta))
}

pub fn warm_up(vsock: &Path, meta: &ImageMeta) -> Result<()> {
    let start = Instant::now();
    guest::start_app(vsock)?;
    loop {
        let left = meta.ready_timeout.saturating_sub(start.elapsed());
        let ready = match &meta.ready {
            Some(Ready::Port(p)) => guest::probe(vsock, *p)?,
            Some(Ready::Cmd(c)) => guest::check(vsock, c, left.max(Duration::from_millis(100)))?,
            None => true,
        };
        if ready {
            crate::log!("image: app ready after {} ms", ms(start.elapsed()));
            return Ok(());
        }
        let status = guest::app_status(vsock)?;
        if status.starts_with("exited") || start.elapsed() > meta.ready_timeout {
            let logs = read_logs(vsock)?;
            let tail = String::from_utf8_lossy(&logs[logs.len().saturating_sub(4096)..]).into_owned();
            bail!("app not ready ({:?}) after {} ms, status {status}; its output:\n{tail}", meta.ready, ms(start.elapsed()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read_logs(vsock: &Path) -> Result<Vec<u8>> {
    const KEEP: usize = 64 << 10;
    let mut r = guest::start_logs(crate::util::connect_unix(vsock, guest::TIMEOUT)?, 0, false, guest::TIMEOUT)?;
    let mut out = Vec::new();
    while let Some((kind, data)) = guest::read_frame(&mut r)? {
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

/// Holds a per-key lock through the cache check, build and publication.
fn cached_rootfs(cached: &Path, build: impl FnOnce(&Path) -> Result<String>, sync: impl Fn(&Path) -> std::io::Result<()>) -> Result<PathBuf> {
    let dir = cached.parent().unwrap();
    // Entries handed out must survive a crash right after the first build, whoever made the directories.
    crate::util::create_dir_durably(dir, 0o777)?;
    // All work is in the directory as opened here, which the locks are keyed by.
    let pinned = crate::host::Directory::open(dir)?;
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
    // Through the descriptor: the locked directory's path now, wherever it was moved.
    Ok(std::fs::canonicalize(cached)?)
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
    File::open(tmp)?.sync_all()?;
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
        write(&mut f)?;
        f.sync_all()?;
        Ok(rename(&tmp, &path)?)
    })();
    // The name is ours alone: gone if renamed, else a failed write's.
    let _ = std::fs::remove_file(&tmp);
    drop(part);
    if res.is_ok() {
        // Published data remains readable; only temporary parts are ever flocked.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    res
}

fn bytes(data: &[u8]) -> impl FnOnce(&mut File) -> Result<()> + '_ {
    move |f| Ok(f.write_all(data)?)
}

/// Creates a new file, replacing a stale one but never writing through a symlink.
fn create_new(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    Ok(std::fs::OpenOptions::new().write(true).create_new(true).custom_flags(libc::O_NOFOLLOW).open(path)?)
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
    let mut tries = img.layers.len();
    loop {
        match attempt() {
            Err(e) if tries > 0 && img.layers.iter().any(|l| l.src.evicted()) && interrupted().is_ok() => {
                crate::log!("image: {e}; downloading it again");
                tries -= 1;
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

fn escape(s: &str) -> String {
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
    for (k, v) in [("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"), ("HOME", &home), ("HOSTNAME", "flexvm")] {
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
    let rows = |p| -> Vec<Vec<String>> {
        let text = String::from_utf8_lossy(&root.read(p).unwrap_or_default()).into_owned();
        text.lines().filter(|l| !l.starts_with('#')).map(|l| l.split(':').map(String::from).collect::<Vec<_>>()).filter(|f| f.len() >= 3).collect()
    };
    let (passwd, group) = (rows("etc/passwd"), rows("etc/group"));
    // As in Docker, `user:` names no group.
    let (u, g) = user.split_once(':').map_or((user, None), |(u, g)| (u, Some(g).filter(|g| !g.is_empty())));
    let u = if u.is_empty() { "0" } else { u };
    let entry = passwd.iter().find(|f| f[0] == u || (u.parse::<u32>().is_ok() && f[2] == u));
    let uid: u32 = match (u.parse(), entry) {
        (Ok(n), _) => n,
        (Err(_), Some(f)) => f[2].parse().map_err(|_| format!("bad uid for {u} in /etc/passwd"))?,
        (Err(_), None) => bail!("user {u:?} is not in the image's /etc/passwd"),
    };
    let home = entry.and_then(|f| f.get(5)).filter(|h| !h.is_empty()).cloned().unwrap_or("/".into());
    let gid: u32 = match g {
        Some(g) => match g.parse() {
            Ok(n) => n,
            Err(_) => group.iter().find(|f| f[0] == g).and_then(|f| f[2].parse().ok()).ok_or(format!("group {g:?} is not in the image's /etc/group"))?,
        },
        None => entry.and_then(|f| f.get(3)?.parse().ok()).unwrap_or(0),
    };
    let mut groups = vec![gid];
    if g.is_none() {
        let member = |f: &&Vec<String>| entry.is_some_and(|e| f.get(3).is_some_and(|m| m.split(',').any(|m| *m == e[0])));
        for n in group.iter().filter(member).filter_map(|f| f[2].parse().ok()) {
            if !groups.contains(&n) {
                groups.push(n);
            }
        }
    }
    Ok((uid, gid, home, groups))
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
    let mut cmd = Command::new("mkfs.ext4");
    cmd.args(["-q", "-F", "-b", "4096", "-I", "256", "-L", "flexroot", "-N", &inodes.to_string(), "-d"]);
    cmd.arg(dir).arg(format!("/proc/{}/fd/{}", std::process::id(), image.as_raw_fd()));
    let out = run_until(&mut cmd, interrupted).map_err(|e| format!("mkfs.ext4: {e}"))?;
    if !out.status.success() {
        bail!("mkfs.ext4 failed: {}", String::from_utf8_lossy(&out.stderr).trim());
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
        assert_eq!(result.unwrap(), std::fs::canonicalize(moved.join("key.ext4")).unwrap());
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
        assert!(app_config(&json!({"config": {}}), &Options::default()).is_err());
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
        assert!(e.unwrap_err().to_string().contains("has digest"));
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
        assert!(source::read_verified(&p, 2, &digest).is_ok());
        assert!(source::read_verified(&p, 3, &digest).is_err());
        std::fs::write(&p, b"[]").unwrap();
        assert!(source::read_verified(&p, 2, &digest).is_err());
        let max = unpack::MAX_DOCUMENT + 1;
        std::fs::write(&p, vec![b' '; max as usize]).unwrap();
        assert!(source::read_verified(&p, max, &digest).is_err());
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
        let key = json!({"v": 3, "config": cd, "diff_ids": config_value["rootfs"]["diff_ids"], "init": sha256_hex(b"init"), "options": o});
        let key = sha256_hex(key.to_string().as_bytes());
        let cached = d.join("rootfs").join(format!("{}.ext4", &key[7..]));
        cached_rootfs(&cached, build("cached"), sync_dir).unwrap();
        let (path, meta) = prepare(&d, Some(&init), &o).unwrap();
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
        let path = cached_rootfs(&cached, build("first"), sync_dir).unwrap();
        assert_eq!(path, std::fs::canonicalize(d.join("real/key.ext4")).unwrap());
        assert_eq!(read(&path), "first image");
        assert_eq!(read(path.with_extension("conf")), "first config");
        assert!(temporaries(&d.join("real")).is_empty());
        assert_eq!(cached_rootfs(&cached, never, sync_dir).unwrap(), path);
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
        let path = cached_rootfs(&cached, never, sync_dir).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        std::fs::remove_file(cached.with_extension("conf")).unwrap();
        assert!(cached_rootfs(&cached, never, sync_dir).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
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
        let path = cached_rootfs(&cached, build("rebuilt"), sync_dir).unwrap();
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
        });
        started.recv().unwrap();
        let lock = crate::host::existing_lock(&crate::host::host_locks().unwrap(), lock_of(&cached).as_ref()).unwrap();
        assert_eq!(flock(&lock, libc::LOCK_EX | libc::LOCK_NB).unwrap_err().raw_os_error(), Some(libc::EWOULDBLOCK));
        let second_path = cached.clone();
        let second = std::thread::spawn(move || cached_rootfs(&second_path, never, sync_dir).unwrap());
        release.send(()).unwrap();
        assert_eq!(first.join().unwrap(), second.join().unwrap());
        assert_eq!(read(&cached), "first image");
    }
}
