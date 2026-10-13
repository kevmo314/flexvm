//! Templates from container images: fetch an image (registry, `docker save`
//! or OCI archive, OCI layout directory), apply its layers, add flexvm-init
//! and the app's config, and write a read-only ext4 root filesystem.
//!
//! Everything is cached by digest under the cache directory:
//! `blobs/sha256/<hex>` for registry blobs and `rootfs/<key>.ext4` for built
//! filesystems, where the key covers the image config digest, the
//! flexvm-init binary and the overrides. Templates attach the cached
//! filesystem in place (it is never rewritten), so every template of one
//! image shares one copy in the page cache; deleting it breaks them.

pub mod reference;
mod registry;
mod source;
mod unpack;

use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bail;
use crate::guest;
use crate::util::{ms, Result};
use registry::sha256_hex;
pub use unpack::Limits;
#[cfg(test)]
use unpack::MAX_DOCUMENT;
use registry::sync_dir;
use unpack::Root;

/// What a template records about its image; part of its metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta {
    /// The reference or path the template was built from.
    pub source: String,
    /// Digest of the image manifest (for a legacy `docker save` archive,
    /// which has none, the config digest).
    pub digest: String,
    pub config_digest: String,
    /// `/etc/flexvm/app.conf` as written into the root filesystem.
    pub app_conf: String,
    /// What flexvm-init runs: entrypoint followed by command.
    pub argv: Vec<String>,
    /// Started before the snapshot (true) or on every `run` (false).
    pub warm: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<Ready>,
    /// How long a warm template's app may take to become ready.
    #[serde(skip)]
    pub ready_timeout: Duration,
}

/// When a warm template's app counts as ready to snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ready {
    /// Something accepts TCP connections on 127.0.0.1:port in the guest.
    Port(u16),
    /// A shell command in the guest exits 0.
    Cmd(String),
}

#[derive(Debug, Default, Serialize)]
pub struct Options {
    /// Not part of the cache key: the same image by another name is the same image.
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
    /// Where layers are unpacked; see `staging_dir`.
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

/// The image config's fields we use, with overrides applied.
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
        let key = kv.split('=').next().unwrap_or("");
        env.retain(|e| e.split('=').next() != Some(key));
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

/// Builds (or finds in the cache) the root filesystem for `o.image` and
/// returns its path. `init` is the static flexvm-init binary.
pub fn prepare(cache: &Path, init: &Path, o: &Options) -> Result<(PathBuf, ImageMeta)> {
    let img = source::fetch(cache, &o.image, &o.limits)?;
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
    let init_bytes = std::fs::read(init).map_err(|e| format!("flexvm-init at {init:?}: {e} (run scripts/build-rootfs.sh)"))?;
    // The config pins the uncompressed layers (diff_ids, each checked while
    // unpacking); they are in the key explicitly too.
    let key = sha256_hex(
        json!({
            "v": 2, "config": img.config_digest, "diff_ids": img.diff_ids,
            "init": sha256_hex(&init_bytes), "options": o,
        })
        .to_string()
        .as_bytes(),
    );
    let rootfs_dir = cache.join("rootfs");
    let cached = rootfs_dir.join(format!("{}.ext4", &key["sha256:".len()..]));
    let cached = cached_rootfs(&cached, |tmp| build_rootfs(&o.staging, &img, &app, &init_bytes, tmp, &o.limits))?;
    let conf_path = cached.with_extension("conf");
    let app_conf = std::fs::read_to_string(&conf_path)?;
    Ok((cached, ImageMeta {
        source: o.image.clone(),
        digest: img.digest,
        config_digest: img.config_digest,
        app_conf,
        argv: app.argv,
        warm: o.warm,
        ready,
        ready_timeout: o.ready_timeout,
    }))
}

/// Warm templates: starts the app in the template VM and waits until it is
/// ready, so the snapshot holds a running app.
pub fn warm_up(vsock: &Path, meta: &ImageMeta) -> Result<()> {
    let start = Instant::now();
    guest::start_app(vsock)?;
    loop {
        let left = meta.ready_timeout.saturating_sub(start.elapsed());
        let ready = match &meta.ready {
            Some(Ready::Port(p)) => guest::probe(vsock, *p)?,
            // Killed in the guest if it outlives the deadline; output discarded.
            Some(Ready::Cmd(c)) => guest::check(vsock, c, left.max(Duration::from_millis(100)))?,
            None => true,
        };
        if ready {
            eprintln!("image: app ready after {} ms", ms(start.elapsed()));
            return Ok(());
        }
        let status = guest::app_status(vsock)?;
        if status.starts_with("exited") || start.elapsed() > meta.ready_timeout {
            let (logs, _) = read_logs(vsock)?;
            let tail = String::from_utf8_lossy(&logs[logs.len().saturating_sub(4096)..]).into_owned();
            bail!("app not ready ({:?}) after {} ms, status {status}; its output:\n{tail}", meta.ready, ms(start.elapsed()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The last 64 KiB of the app's buffered output, and its final status line.
pub fn read_logs(vsock: &Path) -> Result<(Vec<u8>, String)> {
    const KEEP: usize = 64 << 10;
    let mut r = guest::start_logs(crate::util::connect_unix(vsock, guest::TIMEOUT)?, 0, false, guest::TIMEOUT)?;
    let mut out = Vec::new();
    while let Some((kind, data)) = guest::read_frame(&mut r)? {
        match kind {
            guest::FRAME_MSG => return Ok((out, String::from_utf8_lossy(&data).into_owned())),
            _ => {
                out.extend_from_slice(&data);
                if out.len() > 2 * KEEP {
                    out.drain(..out.len() - KEEP);
                }
            }
        }
    }
    bail!("guest closed the connection while sending logs")
}

fn entry_complete(cached: &Path) -> bool {
    cached.is_file() && cached.with_extension("conf").is_file() && cached.with_extension("ok").is_file()
}

fn require_complete(cached: &Path) -> Result<()> {
    if !entry_complete(cached) {
        bail!("incomplete image cache entry {}: refusing to replace it", cached.display());
    }
    Ok(())
}

fn flock(f: &File, op: libc::c_int) -> std::io::Result<()> {
    loop {
        if unsafe { libc::flock(f.as_raw_fd(), op) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Holds a stable per-key lock through the cache check, build and publication.
fn cached_rootfs(cached: &Path, build: impl FnOnce(&Path) -> Result<String>) -> Result<PathBuf> {
    cached_rootfs_with_sync(cached, build, sync_dir)
}

fn cached_rootfs_with_sync(cached: &Path, build: impl FnOnce(&Path) -> Result<String>, sync: impl Fn(&Path) -> Result<()>) -> Result<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = cached.parent().unwrap();
    std::fs::create_dir_all(dir)?;
    // Never unlink the lock: waiters must all lock the same inode.
    let lock = File::options().write(true).create(true).truncate(false).custom_flags(libc::O_NOFOLLOW).open(cached.with_extension("lock"))?;
    if let Err(e) = flock(&lock, libc::LOCK_EX | libc::LOCK_NB) {
        if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(e.into());
        }
        eprintln!("image: waiting for another build of {}", cached.display());
        flock(&lock, libc::LOCK_EX)?;
    }
    let ok = cached.with_extension("ok");
    let marked = match std::fs::symlink_metadata(&ok) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    if entry_complete(cached) {
        // A previous publisher may have failed its fsync after renaming .ok.
        // File contents were synced before rename; confirm the names too.
        sync(dir)?;
        eprintln!("image: root filesystem cached at {}", cached.display());
    } else if marked {
        // Once marked, templates may use the entry: never rebuild it in place.
        bail!(
            "image cache entry {} is marked complete but has missing files; templates may use it, \
             so remove its .ext4, .conf and .ok files (and those templates) to rebuild it",
            cached.display()
        );
    } else {
        // Without its marker the entry was never handed out (prepare returns
        // only once the marker is durable, and publishers hold this lock), so
        // a crashed build's leftovers can go. Unlinking never alters a file
        // anything still has open.
        remove_leftovers(cached)?;
        let tmp = cached.with_extension(format!("tmp{}", std::process::id()));
        let res = build(&tmp).and_then(|conf| publish_rootfs(&tmp, cached, &conf, &sync));
        let _ = std::fs::remove_file(&tmp);
        res?;
    }
    Ok(std::fs::canonicalize(cached)?)
}

/// Removes an unmarked entry's files and its crashed builds' temporaries;
/// only called with the entry's lock held and its `.ok` absent.
fn remove_leftovers(cached: &Path) -> Result<()> {
    let dir = cached.parent().unwrap();
    let stem = cached.file_stem().unwrap().as_bytes();
    let mut removed = false;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(ext) = name.as_bytes().strip_prefix(stem).and_then(|r| r.strip_prefix(b".")) else { continue };
        if ext == b"ext4" || ext == b"conf" || ext.starts_with(b"tmp") || ext.starts_with(b"part") {
            eprintln!("image: removing {} left by an interrupted build", entry.path().display());
            std::fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        sync_dir(dir)?;
    }
    Ok(())
}

/// Publishes immutable files, with the completion marker last. A competing
/// publisher's entry may only be reused once all three files are durable.
fn publish_rootfs(tmp: &Path, cached: &Path, conf: &str, sync: impl Fn(&Path) -> Result<()>) -> Result<()> {
    File::open(tmp)?.sync_all()?;
    let dir = cached.parent().unwrap();
    if !rename_noreplace(tmp, cached)? || !publish(&cached.with_extension("conf"), conf.as_bytes())? {
        require_complete(cached)?;
    } else {
        // The image and its config are durable before the marker says so.
        sync(dir)?;
        if !publish(&cached.with_extension("ok"), b"")? {
            require_complete(cached)?;
        }
    }
    // Even a complete collision winner may still need its marker synced.
    // On failure leave it intact, but do not hand it out to this build.
    sync(dir)
}

/// Returns false on EEXIST, leaving the existing file untouched.
fn rename_noreplace(tmp: &Path, path: &Path) -> Result<bool> {
    let src = CString::new(tmp.as_os_str().as_bytes()).map_err(|_| "NUL in path")?;
    let dest = CString::new(path.as_os_str().as_bytes()).map_err(|_| "NUL in path")?;
    if unsafe { libc::renameat2(libc::AT_FDCWD, src.as_ptr(), libc::AT_FDCWD, dest.as_ptr(), libc::RENAME_NOREPLACE) } == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EEXIST) {
        return Ok(false);
    }
    Err(e.into())
}

/// Writes `path` durably without replacing it; discards the temporary file
/// if another publisher got there first.
fn publish(path: &Path, data: &[u8]) -> Result<bool> {
    let tmp = path.with_extension(format!("part{}", std::process::id()));
    let res = (|| {
        let mut f = create_new(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        rename_noreplace(&tmp, path)
    })();
    let _ = std::fs::remove_file(&tmp);
    res
}

/// Creates a new file, replacing a stale one but never writing through a
/// symlink someone else put in the cache.
pub(crate) fn create_new(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    Ok(std::fs::OpenOptions::new().write(true).create_new(true).custom_flags(libc::O_NOFOLLOW).open(path)?)
}

/// Default for `--image-staging`.
pub const STAGING: &str = "/var/lib/flexvm/staging";

/// Checks that only root can change what `path` names: it and every
/// ancestor must be root-owned and not group/other writable (sticky
/// directories excepted, where others cannot move root's entries).
fn check_ancestry(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    for dir in path.ancestors() {
        let m = std::fs::symlink_metadata(dir)?;
        let writable = m.mode() & 0o022 != 0 && m.mode() & libc::S_ISVTX == 0;
        if m.uid() != 0 || writable || m.file_type().is_symlink() {
            bail!(
                "image staging directory {}: {} must be root-owned and not writable by others \
                 (choose another with --image-staging)",
                path.display(),
                dir.display()
            );
        }
    }
    Ok(())
}

/// The private staging directory where layers are unpacked: root-owned,
/// 0700, with an ancestry only root can change, opened without following
/// symlinks. No other user can reach the setuid binaries, device nodes or
/// capabilities an image carries while they sit unpacked on the host, or
/// swap the directory underneath the build.
fn staging_dir(path: &Path) -> Result<OwnedFd> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    let path = std::fs::canonicalize(path)?;
    check_ancestry(&path)?;
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| "NUL in path")?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        bail!("open {}: {}", path.display(), std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 || st.st_uid != 0 || st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        bail!("{} is not a root-owned directory", path.display());
    }
    if unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) } != 0 {
        bail!("chmod {}: {}", path.display(), std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// Unpacks the image, checking every layer, into `dest` (an ext4 image).
/// Returns the app.conf it wrote.
fn build_rootfs(staging: &Path, img: &source::Image, app: &App, init: &[u8], dest: &Path, limits: &Limits) -> Result<String> {
    let staging = staging_dir(staging)?;
    let name = CString::new(format!("rootfs-{}", std::process::id())).unwrap();
    // Everything relative to the staging fd, never through its path again.
    unpack::remove_at(staging.as_raw_fd(), &name, 0)?;
    if unsafe { libc::mkdirat(staging.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
        bail!("mkdir in staging: {}", std::io::Error::last_os_error());
    }
    let res = (|| {
        let work = unpack::open_dir_at(staging.as_raw_fd(), &name)?;
        // mkdirat applied the umask.
        if unsafe { libc::fchmod(work.as_raw_fd(), 0o755) } != 0 {
            bail!("chmod staging: {}", std::io::Error::last_os_error());
        }
        // mkfs.ext4 and du reach the same directory through our fd.
        let path = PathBuf::from(format!("/proc/{}/fd/{}/{}", std::process::id(), staging.as_raw_fd(), name.to_str().unwrap()));
        let mut root = Root::from_fd(work, *limits);
        unpack_layers(&mut root, img)?;
        let conf = inject(&mut root, app, init)?;
        mkfs(&path, root.entries, dest)?;
        Ok(conf)
    })();
    let _ = unpack::remove_at(staging.as_raw_fd(), &name, 0);
    res
}

/// Applies the image's layers in order, checking each blob against its
/// descriptor and its uncompressed contents against the config's
/// diff_ids as it goes.
fn unpack_layers(root: &mut Root, img: &source::Image) -> Result<()> {
    for (i, layer) in img.layers.iter().enumerate() {
        eprintln!("image: applying layer {}/{} {}", i + 1, img.layers.len(), layer.name());
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

/// Adds what flexvm-init needs to boot and run the app: its mount points,
/// itself, `/etc/flexvm/app.conf`, and sensible `/etc/hosts` and `/etc/resolv.conf`.
fn inject(root: &mut Root, app: &App, init: &[u8]) -> Result<String> {
    for (dir, mode) in [
        ("proc", 0o555),
        ("sys", 0o555),
        ("dev", 0o755),
        ("run", 0o755),
        ("tmp", 0o1777),
        ("mnt", 0o755),
        ("root", 0o700),
        ("etc/flexvm", 0o755),
        ("sbin", 0o755),
    ] {
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
    let has = |env: &[String], k: &str| env.iter().any(|e| e.split('=').next() == Some(k));
    if !has(&env, "PATH") {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }
    if !has(&env, "HOME") {
        env.push(format!("HOME={home}"));
    }
    if !has(&env, "HOSTNAME") {
        env.push("HOSTNAME=flexvm".into());
    }
    let mut conf = String::new();
    for a in &app.argv {
        conf += &format!("arg {}\n", escape(a));
    }
    for e in &env {
        conf += &format!("env {}\n", escape(e));
    }
    conf += &format!("cwd {}\nuid {uid}\ngid {gid}\n", escape(&app.workdir));
    conf += &format!("groups {}\n", groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(" "));
    root.write_file("etc/flexvm/app.conf", conf.as_bytes(), 0o644)?;
    Ok(conf)
}

/// Resolves an image `User` (`name`, `uid`, `name:group`, `uid:gid`) against
/// the image's own /etc/passwd and /etc/group.
fn resolve_user(root: &Root, user: &str) -> Result<(u32, u32, String, Vec<u32>)> {
    let read = |p| String::from_utf8_lossy(&root.read(p).unwrap_or_default()).into_owned();
    let (passwd, group) = (read("etc/passwd"), read("etc/group"));
    let rows = |text: &str| -> Vec<Vec<String>> {
        text.lines().filter(|l| !l.starts_with('#')).map(|l| l.split(':').map(String::from).collect()).filter(|f: &Vec<String>| f.len() >= 3).collect()
    };
    let (passwd, group) = (rows(&passwd), rows(&group));
    let (u, g) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
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
            Err(_) => group
                .iter()
                .find(|f| f[0] == g)
                .and_then(|f| f[2].parse().ok())
                .ok_or(format!("group {g:?} is not in the image's /etc/group"))?,
        },
        None => entry.and_then(|f| f.get(3)?.parse().ok()).unwrap_or(0),
    };
    let mut groups = vec![gid];
    if let Some(name) = entry.map(|f| f[0].clone()) {
        for f in &group {
            if f.get(3).is_some_and(|m| m.split(',').any(|m| m == name)) {
                if let Ok(n) = f[2].parse() {
                    if !groups.contains(&n) {
                        groups.push(n);
                    }
                }
            }
        }
    }
    Ok((uid, gid, home, groups))
}

/// Writes `dir` into a new ext4 image at `dest`, sized to its content plus
/// headroom and rounded up to 2 MiB as virtio-pmem requires.
fn mkfs(dir: &Path, entries: u64, dest: &Path) -> Result<()> {
    let du = Command::new("du").arg("-sk").arg(dir).output()?;
    let kib: u64 = String::from_utf8_lossy(&du.stdout).split_whitespace().next().and_then(|s| s.parse().ok()).ok_or("du failed")?;
    let mib = (kib * 12 / 10 / 1024 + 64).div_ceil(2) * 2;
    let inodes = entries * 12 / 10 + 4096;
    // mkfs writes through our descriptor, so the name cannot be swapped for a symlink.
    let image = create_new(dest)?;
    image.set_len(mib << 20)?;
    let out = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-b", "4096", "-L", "flexroot", "-N", &inodes.to_string(), "-d"])
        .arg(dir)
        .arg(format!("/proc/{}/fd/{}", std::process::id(), image.as_raw_fd()))
        .output()
        .map_err(|e| format!("mkfs.ext4: {e}"))?;
    if !out.status.success() {
        bail!("mkfs.ext4 failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    eprintln!("image: root filesystem built ({mib} MiB, {entries} entries)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("flexvm-img-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let (uid, gid) = unsafe { (libc::getuid() as u64, libc::getgid() as u64) };
        for (path, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_uid(uid);
            h.set_gid(gid);
            h.set_mode(0o644);
            h.set_size(data.len() as u64);
            b.append_data(&mut h, path, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    /// A legacy `docker save` directory whose config claims `claimed` as the
    /// layer's diff_id while the layer file holds `layer`.
    fn docker_save(dir: &Path, claimed: &[u8], layer: &[u8]) {
        let config = json!({"architecture": "amd64", "os": "linux", "config": {"Cmd": ["/x"]},
            "rootfs": {"type": "layers", "diff_ids": [sha256_hex(claimed)]}});
        std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
        std::fs::write(dir.join("layer.tar"), layer).unwrap();
        std::fs::write(dir.join("manifest.json"), json!([{"Config": "config.json", "Layers": ["layer.tar"]}]).to_string()).unwrap();
    }

    fn unpack_dir(src: &Path) -> Result<PathBuf> {
        let img = source::fetch(Path::new("/nonexistent"), src.to_str().unwrap(), &Limits::default())?;
        let out = src.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let mut root = Root::open(&out, Limits::default())?;
        unpack_layers(&mut root, &img)?;
        Ok(out)
    }

    #[test]
    fn layers_must_match_the_config_diff_ids() {
        let good = tar_of(&[("a", b"good")]);
        let evil = tar_of(&[("a", b"evil")]);
        let d = tmpdir("diffid-ok");
        docker_save(&d, &good, &good);
        assert_eq!(std::fs::read(unpack_dir(&d).unwrap().join("a")).unwrap(), b"good");
        // Same config (so same cache key before this fix), different layer: refused.
        let d2 = tmpdir("diffid-bad");
        docker_save(&d2, &good, &evil);
        let e = unpack_dir(&d2).unwrap_err().to_string();
        assert!(e.contains("the image config says"), "{e}");
        std::fs::remove_dir_all(&d).unwrap();
        std::fs::remove_dir_all(&d2).unwrap();
    }

    /// An OCI layout with one gzip'd layer; returns the config and layer digests.
    fn oci_layout(dir: &Path, layer: &[u8]) -> (String, String) {
        use std::io::Write as _;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(layer).unwrap();
        let blob = gz.finish().unwrap();
        let config = json!({"architecture": "amd64", "os": "linux", "config": {"Cmd": ["/x"]},
            "rootfs": {"type": "layers", "diff_ids": [sha256_hex(layer)]}}).to_string();
        let put = |data: &[u8]| {
            let d = sha256_hex(data);
            let p = registry::blob_path(&dir.join("blobs"), &d).unwrap();
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, data).unwrap();
            d
        };
        let (cd, ld) = (put(config.as_bytes()), put(&blob));
        let manifest = json!({"schemaVersion": 2, "config": {"digest": cd, "size": config.len()},
            "layers": [{"digest": ld, "size": blob.len()}]}).to_string();
        let md = put(manifest.as_bytes());
        std::fs::write(dir.join("index.json"), json!({"manifests": [{"digest": md, "size": manifest.len()}]}).to_string()).unwrap();
        (cd, ld)
    }

    #[test]
    fn local_blobs_are_verified() {
        let layer = tar_of(&[("a", b"data")]);
        let d = tmpdir("oci-ok");
        oci_layout(&d, &layer);
        assert_eq!(std::fs::read(unpack_dir(&d).unwrap().join("a")).unwrap(), b"data");

        // A changed gzip header keeps the layer valid but fails its compressed digest.
        let d2 = tmpdir("oci-layer");
        let (_, ld) = oci_layout(&d2, &layer);
        let p = registry::blob_path(&d2.join("blobs"), &ld).unwrap();
        let mut b = std::fs::read(&p).unwrap();
        b[4] ^= 0xff; // gzip mtime is not part of the uncompressed stream
        std::fs::write(&p, &b).unwrap();
        let e = unpack_dir(&d2).unwrap_err().to_string();
        assert!(e.contains("has digest"), "{e}");
        assert_eq!(std::fs::read(d2.join("out/a")).unwrap(), b"data");
        let cached = d2.join("cache/key.ext4");
        let staging = d2.join("staging");
        let img = source::fetch(Path::new("/nonexistent"), d2.to_str().unwrap(), &Limits::default()).unwrap();
        let e = cached_rootfs(&cached, |_| {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
            let mut root = Root::open(&staging, Limits::default())?;
            let res = unpack_layers(&mut root, &img);
            assert_eq!(std::fs::read(staging.join("a")).unwrap(), b"data");
            std::fs::remove_dir_all(&staging)?;
            res?;
            panic!("a corrupt layer must fail before building the rootfs");
        }).unwrap_err().to_string();
        assert!(!staging.exists());
        assert!(e.contains("has digest"), "{e}");
        for path in [&cached, &cached.with_extension("conf"), &cached.with_extension("ok")] {
            assert!(!path.exists(), "{} was published", path.display());
        }

        // A tampered config is refused outright.
        let d3 = tmpdir("oci-config");
        let (cd, _) = oci_layout(&d3, &layer);
        let p = registry::blob_path(&d3.join("blobs"), &cd).unwrap();
        std::fs::write(&p, std::fs::read_to_string(&p).unwrap().replace("/x", "/y")).unwrap();
        assert!(source::fetch(Path::new("/nonexistent"), d3.to_str().unwrap(), &Limits::default()).is_err());
        for d in [d, d2, d3] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn download_budget_is_checked_up_front() {
        let d = tmpdir("budget");
        oci_layout(&d, &tar_of(&[("a", &[0u8; 100_000])]));
        let tiny = Limits { download: 10, ..Limits::default() };
        let e = source::fetch(Path::new("/nonexistent"), d.to_str().unwrap(), &tiny).err().unwrap().to_string();
        assert!(e.contains("download limit"), "{e}");
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn staging_needs_a_root_only_ancestry() {
        use std::os::unix::fs::PermissionsExt;
        // Whoever runs it (root or not, with / root-owned or not): a group
        // writable directory and a symlink never qualify.
        let d = tmpdir("ancestry");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(check_ancestry(&d).unwrap_err().to_string().contains("must be root-owned"));
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("/", d.join("link")).unwrap();
        assert!(check_ancestry(&d.join("link")).is_err());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn cache_writes_never_follow_symlinks() {
        let d = tmpdir("nofollow");
        let victim = d.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, d.join(format!("x.part{}", std::process::id()))).unwrap();
        std::os::unix::fs::symlink(&victim, d.join("x")).unwrap();
        assert!(!publish(&d.join("x"), b"new").unwrap());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert!(std::fs::symlink_metadata(d.join("x")).unwrap().file_type().is_symlink());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn cache_publication_never_replaces_files() {
        use std::os::unix::fs::MetadataExt;
        let d = tmpdir("noreplace");
        let cached = d.join("key.ext4");
        let tmp = d.join("build");
        std::fs::write(&tmp, "first image").unwrap();
        publish_rootfs(&tmp, &cached, "first config", sync_dir).unwrap();
        let inode = std::fs::metadata(&cached).unwrap().ino();
        std::fs::write(&tmp, "second image").unwrap();
        publish_rootfs(&tmp, &cached, "second config", sync_dir).unwrap();
        assert_eq!(std::fs::metadata(&cached).unwrap().ino(), inode);
        assert_eq!(std::fs::read_to_string(&cached).unwrap(), "first image");
        assert!(!publish(&cached.with_extension("conf"), b"second config").unwrap());
        assert!(!publish(&cached.with_extension("ok"), b"replacement marker").unwrap());
        assert_eq!(std::fs::read_to_string(cached.with_extension("conf")).unwrap(), "first config");
        assert_eq!(std::fs::read(cached.with_extension("ok")).unwrap(), b"");
        // An existing image without its completion marker cannot be reused.
        std::fs::remove_file(cached.with_extension("ok")).unwrap();
        assert!(publish_rootfs(&tmp, &cached, "second config", sync_dir).is_err());
        assert!(!cached.with_extension("ok").exists());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn cache_reuses_the_winning_entry_and_canonical_path() {
        let d = tmpdir("reuse");
        let real = d.join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, d.join("alias")).unwrap();
        let cached = d.join("alias/key.ext4");
        let path = cached_rootfs(&cached, |tmp| {
            std::fs::write(tmp, "loser image")?;
            // Simulate a publisher that did not participate in the lock.
            let winner = d.join("winner");
            std::fs::write(&winner, "winner image")?;
            publish_rootfs(&winner, &cached, "winner config", sync_dir)?;
            Ok("loser config".into())
        }).unwrap();
        assert_eq!(path, std::fs::canonicalize(real.join("key.ext4")).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "winner image");
        assert_eq!(std::fs::read_to_string(path.with_extension("conf")).unwrap(), "winner config");
        assert!(!cached.with_extension(format!("tmp{}", std::process::id())).exists());
        assert_eq!(cached_rootfs(&cached, |_| panic!("cache hit must not build")).unwrap(), path);
        // Marked complete but missing a file: templates may use it, never rebuild.
        std::fs::remove_file(path.with_extension("conf")).unwrap();
        assert!(cached_rootfs(&cached, |_| panic!("marked entry must not be rebuilt")).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "winner image");
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn cache_durability_failure_is_retried_before_reuse() {
        use std::os::unix::fs::MetadataExt;
        let d = tmpdir("durability");
        let cached = d.join("key.ext4");
        let fail_after_marker = |dir: &Path| {
            assert_eq!(dir, d);
            if cached.with_extension("ok").exists() {
                return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
            }
            sync_dir(dir)
        };
        // Publication reaches the marker rename, but must not return a path.
        assert!(cached_rootfs_with_sync(&cached, |tmp| {
            std::fs::write(tmp, "image")?;
            Ok("config".into())
        }, fail_after_marker).is_err());
        assert!(entry_complete(&cached));
        let inode = std::fs::metadata(&cached).unwrap().ino();
        // A cache hit must retry that fsync, and still refuse on failure.
        assert!(cached_rootfs_with_sync(&cached, |_| panic!("must not rebuild"), fail_after_marker).is_err());
        assert!(entry_complete(&cached));
        let path = cached_rootfs_with_sync(&cached, |_| panic!("must not rebuild"), |dir| {
            assert_eq!(dir, d);
            sync_dir(dir)
        }).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        // Once handed out, even a damaged marked entry cannot be cleaned up.
        std::fs::remove_file(cached.with_extension("conf")).unwrap();
        assert!(cached_rootfs(&cached, |_| panic!("must not rebuild")).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn collision_reuse_requires_durability() {
        let d = tmpdir("collision-durability");
        let cached = d.join("key.ext4");
        assert!(cached_rootfs_with_sync(&cached, |tmp| {
            std::fs::write(tmp, "loser image")?;
            let winner = d.join("winner");
            std::fs::write(&winner, "winner image")?;
            publish_rootfs(&winner, &cached, "winner config", sync_dir)?;
            Ok("loser config".into())
        }, |dir| {
            assert_eq!(dir, d);
            Err(std::io::Error::from_raw_os_error(libc::EIO).into())
        }).is_err());
        assert_eq!(std::fs::read_to_string(&cached).unwrap(), "winner image");
        assert!(entry_complete(&cached));
        assert!(cached_rootfs(&cached, |_| panic!("must reuse winner")).is_ok());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn interrupted_publication_is_rebuilt() {
        use std::os::unix::fs::MetadataExt;
        let d = tmpdir("interrupted");
        let cached = d.join("key.ext4");
        // A build killed after the rootfs rename, mid-way through the config.
        std::fs::write(&cached, "half published").unwrap();
        std::fs::write(d.join("key.part123"), "partial config").unwrap();
        std::fs::write(d.join("key.tmp456"), "abandoned build").unwrap();
        std::fs::write(d.join("other.tmp789"), "another key's build").unwrap();
        let old = std::fs::File::open(&cached).unwrap();
        let path = cached_rootfs(&cached, |tmp| {
            std::fs::write(tmp, "rebuilt image")?;
            Ok("rebuilt config".into())
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "rebuilt image");
        assert_eq!(std::fs::read_to_string(path.with_extension("conf")).unwrap(), "rebuilt config");
        assert!(path.with_extension("ok").exists());
        // The old file was unlinked, not rewritten.
        assert_ne!(old.metadata().unwrap().ino(), std::fs::metadata(&path).unwrap().ino());
        assert_eq!(std::io::read_to_string(old).unwrap(), "half published");
        assert!(!d.join("key.part123").exists() && !d.join("key.tmp456").exists());
        assert!(d.join("other.tmp789").exists());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn config_collision_does_not_publish_a_completion_marker() {
        let d = tmpdir("conf-collision");
        let cached = d.join("key.ext4");
        let tmp = d.join("build");
        std::fs::write(&tmp, "image").unwrap();
        std::fs::write(cached.with_extension("conf"), "existing config").unwrap();
        assert!(publish_rootfs(&tmp, &cached, "new config", sync_dir).is_err());
        assert_eq!(std::fs::read_to_string(cached.with_extension("conf")).unwrap(), "existing config");
        assert!(!cached.with_extension("ok").exists());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn concurrent_cache_builds_wait_and_reuse() {
        use std::sync::mpsc;
        let d = tmpdir("cache-lock");
        let cached = d.join("key.ext4");
        let (building, started) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let first_path = cached.clone();
        let first = std::thread::spawn(move || cached_rootfs(&first_path, |tmp| {
            building.send(()).unwrap();
            wait.recv().unwrap();
            assert!(!first_path.with_extension("ok").exists());
            std::fs::write(tmp, "first image")?;
            Ok("first config".into())
        }).unwrap());
        started.recv().unwrap();
        let lock = File::options().write(true).open(cached.with_extension("lock")).unwrap();
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EWOULDBLOCK));
        let second_path = cached.clone();
        let second = std::thread::spawn(move || cached_rootfs(&second_path, |_| panic!("waiter must reuse the first build")).unwrap());
        release.send(()).unwrap();
        assert_eq!(first.join().unwrap(), second.join().unwrap());
        assert_eq!(std::fs::read_to_string(&cached).unwrap(), "first image");
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn cached_documents_are_verified() {
        let d = tmpdir("cached-doc");
        let p = d.join("config");
        std::fs::write(&p, b"{}").unwrap();
        let digest = sha256_hex(b"{}");
        assert!(source::read_verified(&p, 2, &digest).is_ok());
        assert!(source::read_verified(&p, 3, &digest).is_err());
        std::fs::write(&p, b"[]").unwrap();
        assert!(source::read_verified(&p, 2, &digest).is_err());
        std::fs::write(&p, vec![b' '; (MAX_DOCUMENT + 1) as usize]).unwrap();
        assert!(source::read_verified(&p, MAX_DOCUMENT + 1, &digest).is_err());
        std::fs::remove_dir_all(d).unwrap();
    }
}
