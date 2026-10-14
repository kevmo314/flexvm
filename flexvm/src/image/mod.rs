//! Templates from container images, as read-only ext4 root filesystems cached
//! by digest (`blobs/sha256/<hex>`, `rootfs/<key>.ext4`). Templates attach the
//! cached filesystem in place, so deleting it breaks them.

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
use crate::util::{ms, Result};
use registry::{sha256_hex, sync_dir};
pub use unpack::Limits;
use unpack::{check, cpath, open_at, stat_at, Root};

/// What a template records about its image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta {
    /// The reference or path the template was built from.
    pub source: String,
    /// Manifest digest (the config digest for a legacy `docker save`).
    pub digest: String,
    pub config_digest: String,
    /// `/etc/flexvm/app.conf` as written into the root filesystem.
    pub app_conf: String,
    /// Entrypoint followed by command.
    pub argv: Vec<String>,
    /// Started before the snapshot (true) or on every `run` (false).
    pub warm: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<Ready>,
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

/// Builds (or finds in the cache) the root filesystem for `o.image`.
/// `init` is the static flexvm-init binary.
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
    let key = json!({
        "v": 2, "config": img.config_digest, "diff_ids": img.diff_ids,
        "init": sha256_hex(&init_bytes), "options": o,
    });
    let key = sha256_hex(key.to_string().as_bytes());
    let cached = cache.join("rootfs").join(format!("{}.ext4", &key["sha256:".len()..]));
    let cached = cached_rootfs(&cached, |tmp| build_rootfs(&o.staging, &img, &app, &init_bytes, tmp, &o.limits), sync_dir)?;
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

/// Starts the app in a warm template's VM and waits until it is ready.
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
            eprintln!("image: app ready after {} ms", ms(start.elapsed()));
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

/// At least the last 64 KiB of the app's buffered output.
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

fn entry_complete(cached: &Path) -> bool {
    ["ext4", "conf", "ok"].iter().all(|ext| cached.with_extension(ext).is_file())
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

/// Holds a per-key lock through the cache check, build and publication.
fn cached_rootfs(cached: &Path, build: impl FnOnce(&Path) -> Result<String>, sync: impl Fn(&Path) -> Result<()>) -> Result<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = cached.parent().unwrap();
    // Entries handed out must survive a crash right after the first build.
    crate::util::create_dir_durably(dir)?;
    // Never unlink the lock: waiters must all lock the same inode.
    let lock = File::options().write(true).create(true).truncate(false).custom_flags(libc::O_NOFOLLOW).open(cached.with_extension("lock"))?;
    if let Err(e) = flock(&lock, libc::LOCK_EX | libc::LOCK_NB) {
        if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(e.into());
        }
        eprintln!("image: waiting for another build of {}", cached.display());
        flock(&lock, libc::LOCK_EX)?;
    }
    let marked = match std::fs::symlink_metadata(cached.with_extension("ok")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        res => res.map(|_| true)?,
    };
    if entry_complete(cached) {
        // A previous publisher may have failed its fsync after renaming .ok.
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
        // Never handed out without its marker, so a crashed build's leftovers can go.
        remove_leftovers(cached)?;
        let tmp = cached.with_extension(format!("tmp{}", std::process::id()));
        let res = build(&tmp).and_then(|conf| publish_rootfs(&tmp, cached, &conf, &sync));
        let _ = std::fs::remove_file(&tmp);
        res?;
    }
    Ok(std::fs::canonicalize(cached)?)
}

/// Unlinks an unmarked entry's files and its crashed builds' temporaries.
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

/// Publishes immutable files, the completion marker last. A competing
/// publisher's entry is only reused once all three files are durable.
fn publish_rootfs(tmp: &Path, cached: &Path, conf: &str, sync: impl Fn(&Path) -> Result<()>) -> Result<()> {
    File::open(tmp)?.sync_all()?;
    let dir = cached.parent().unwrap();
    let won = rename_noreplace(tmp, cached)? && publish(&cached.with_extension("conf"), bytes(conf.as_bytes()))? && {
        sync(dir)?;
        publish(&cached.with_extension("ok"), bytes(b""))?
    };
    if !won && !entry_complete(cached) {
        bail!("incomplete image cache entry {}: refusing to replace it", cached.display());
    }
    // Even a collision winner may still need its marker synced.
    sync(dir)
}

/// Returns false on EEXIST, leaving the existing file untouched.
fn rename_noreplace(tmp: &Path, path: &Path) -> Result<bool> {
    let (src, dest) = (cpath(tmp)?, cpath(path)?);
    if unsafe { libc::renameat2(libc::AT_FDCWD, src.as_ptr(), libc::AT_FDCWD, dest.as_ptr(), libc::RENAME_NOREPLACE) } == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EEXIST) => Ok(false),
        _ => Err(e.into()),
    }
}

/// Writes `path` durably through a temporary file, never replacing it;
/// false if another publisher got there first.
pub(super) fn publish(path: &Path, write: impl FnOnce(&mut File) -> Result<()>) -> Result<bool> {
    let tmp = path.with_extension(format!("part{}", std::process::id()));
    let res = (|| {
        let mut f = create_new(&tmp)?;
        write(&mut f)?;
        f.sync_all()?;
        rename_noreplace(&tmp, path)
    })();
    let _ = std::fs::remove_file(&tmp);
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

/// Default for `--image-staging`.
pub const STAGING: &str = "/var/lib/flexvm/staging";

/// Checks that only root can change what `path` names: it and every ancestor
/// are root-owned and not group/other writable (sticky directories excepted).
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

/// Unpacks the image into `dest` (an ext4 image); returns the app.conf it wrote.
fn build_rootfs(staging: &Path, img: &source::Image, app: &App, init: &[u8], dest: &Path, limits: &Limits) -> Result<String> {
    let staging = staging_dir(staging)?;
    let name = format!("rootfs-{}", std::process::id());
    let cname = cpath(Path::new(&name))?;
    // Everything relative to the staging fd, never through its path again.
    unpack::remove_at(staging.as_raw_fd(), &cname, 0)?;
    check(unsafe { libc::mkdirat(staging.as_raw_fd(), cname.as_ptr(), 0o755) }, "mkdir", Path::new(&name))?;
    let res = (|| {
        let work = unpack::open_dir_at(staging.as_raw_fd(), &cname)?;
        // mkdirat applied the umask.
        check(unsafe { libc::fchmod(work.as_raw_fd(), 0o755) }, "chmod", Path::new(&name))?;
        // mkfs.ext4 and du reach the same directory through our fd.
        let path = PathBuf::from(format!("/proc/{}/fd/{}/{name}", std::process::id(), staging.as_raw_fd()));
        let mut root = Root::from_fd(work, *limits);
        unpack_layers(&mut root, img)?;
        let conf = inject(&mut root, app, init)?;
        mkfs(&path, root.entries, dest)?;
        Ok(conf)
    })();
    let _ = unpack::remove_at(staging.as_raw_fd(), &cname, 0);
    res
}

/// Applies the layers in order, checking each blob against its descriptor
/// and its uncompressed contents against the config's diff_ids.
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

/// Adds flexvm-init, its mount points, `/etc/flexvm/app.conf`, `/etc/hosts`
/// and `/etc/resolv.conf`.
fn inject(root: &mut Root, app: &App, init: &[u8]) -> Result<String> {
    for (dir, mode) in [("proc", 0o555), ("sys", 0o555), ("dev", 0o755), ("run", 0o755), ("tmp", 0o1777), ("mnt", 0o755), ("root", 0o700), ("etc/flexvm", 0o755), ("sbin", 0o755)] {
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
    root.write_file("etc/flexvm/app.conf", conf.as_bytes(), 0o644)?;
    Ok(conf)
}

/// Resolves an image `User` (`name`, `uid`, `name:group`, `uid:gid`) against
/// the image's own /etc/passwd and /etc/group.
fn resolve_user(root: &Root, user: &str) -> Result<(u32, u32, String, Vec<u32>)> {
    let rows = |p| -> Vec<Vec<String>> {
        let text = String::from_utf8_lossy(&root.read(p).unwrap_or_default()).into_owned();
        text.lines().filter(|l| !l.starts_with('#')).map(|l| l.split(':').map(String::from).collect::<Vec<_>>()).filter(|f| f.len() >= 3).collect()
    };
    let (passwd, group) = (rows("etc/passwd"), rows("etc/group"));
    let (u, g) = user.split_once(':').map_or((user, None), |(u, g)| (u, Some(g)));
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
    let member = |f: &&Vec<String>| entry.is_some_and(|e| f.get(3).is_some_and(|m| m.split(',').any(|m| *m == e[0])));
    for n in group.iter().filter(member).filter_map(|f| f[2].parse().ok()) {
        if !groups.contains(&n) {
            groups.push(n);
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
    use std::os::unix::fs::{symlink, MetadataExt};
    use unpack::tests::{layer, tmpdir};

    fn read(p: impl AsRef<Path>) -> String {
        std::fs::read_to_string(p).unwrap()
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
        crate::util::create_dir_durably(&d.join("images/rootfs")).unwrap();
        assert!(d.join("images/rootfs").is_dir());
        let e = sync_dir(&d.join("missing")).unwrap_err().to_string();
        assert!(e.contains(&d.join("missing").display().to_string()), "{e}");
        std::fs::write(d.join("file"), b"").unwrap();
        let e = crate::util::create_dir_durably(&d.join("file/x")).unwrap_err().to_string();
        assert!(e.contains("file/x"), "{e}");
    }

    /// An image config whose one layer has `layer`'s diff_id.
    fn config(layer: &[u8]) -> String {
        json!({"architecture": "amd64", "os": "linux", "config": {"Cmd": ["/x"]}, "rootfs": {"type": "layers", "diff_ids": [sha256_hex(layer)]}}).to_string()
    }

    fn fetch(src: &Path, limits: &Limits) -> Result<source::Image> {
        source::fetch(Path::new("/nonexistent"), src.to_str().unwrap(), limits)
    }

    /// Unpacks `src` into `out`, returning `out/a`.
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
            // A directory whose config claims `good` while the layer file holds `held`.
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
        // The same as a tarball, naming its layer through a symlink.
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

    /// An OCI layout with one gzip'd layer; returns the config and layer digests.
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
        // So nothing is published.
        let cached = d.join("cache/key.ext4");
        let e = cached_rootfs(&cached, |_| {
            unpack(&d, &d.join("staging"))?;
            panic!("a corrupt layer must fail before building the rootfs");
        }, sync_dir);
        assert!(e.unwrap_err().to_string().contains("has digest"));
        assert!(["ext4", "conf", "ok"].iter().all(|e| !cached.with_extension(e).exists()));

        // A tampered config is refused outright.
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
        // Whoever runs it: a group writable directory and a symlink never qualify.
        let d = tmpdir("ancestry");
        std::fs::set_permissions(&*d, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(check_ancestry(&d).unwrap_err().to_string().contains("must be root-owned"));
        std::fs::set_permissions(&*d, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink("/", d.join("link")).unwrap();
        assert!(check_ancestry(&d.join("link")).is_err());
    }

    /// A build writing "`what` image" and returning "`what` config".
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
        // Neither through a planted temporary nor a planted target.
        let victim = d.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        symlink(&victim, d.join(format!("x.part{}", std::process::id()))).unwrap();
        symlink(&victim, d.join("x")).unwrap();
        assert!(!publish(&d.join("x"), bytes(b"new")).unwrap());
        assert_eq!(read(&victim), "keep");
        assert!(std::fs::symlink_metadata(d.join("x")).unwrap().file_type().is_symlink());

        let (cached, tmp) = (d.join("key.ext4"), d.join("build"));
        std::fs::write(&tmp, "first image").unwrap();
        publish_rootfs(&tmp, &cached, "first config", sync_dir).unwrap();
        let inode = std::fs::metadata(&cached).unwrap().ino();
        std::fs::write(&tmp, "second image").unwrap();
        publish_rootfs(&tmp, &cached, "second config", sync_dir).unwrap();
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

    /// A build that loses to a publisher that did not take the lock.
    fn losing_build(d: &Path, cached: &Path) -> impl FnOnce(&Path) -> Result<String> {
        let (winner, cached) = (d.join("winner"), cached.to_path_buf());
        move |tmp| {
            std::fs::write(&winner, "winner image")?;
            publish_rootfs(&winner, &cached, "winner config", sync_dir)?;
            build("loser")(tmp)
        }
    }

    #[test]
    fn cache_reuses_the_winning_entry_and_canonical_path() {
        let d = tmpdir("reuse");
        std::fs::create_dir(d.join("real")).unwrap();
        symlink(d.join("real"), d.join("alias")).unwrap();
        let cached = d.join("alias/key.ext4");
        let path = cached_rootfs(&cached, losing_build(&d, &cached), sync_dir).unwrap();
        assert_eq!(path, std::fs::canonicalize(d.join("real/key.ext4")).unwrap());
        assert_eq!(read(&path), "winner image");
        assert_eq!(read(path.with_extension("conf")), "winner config");
        assert!(!cached.with_extension(format!("tmp{}", std::process::id())).exists());
        assert_eq!(cached_rootfs(&cached, never, sync_dir).unwrap(), path);
        // Marked complete but missing a file: templates may use it, never rebuild.
        std::fs::remove_file(path.with_extension("conf")).unwrap();
        assert!(cached_rootfs(&cached, never, sync_dir).is_err());
        assert_eq!(read(&path), "winner image");

        // Reusing a collision winner needs its directory synced too.
        let cached = d.join("key2.ext4");
        let eio = |_: &Path| Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        assert!(cached_rootfs(&cached, losing_build(&d, &cached), eio).is_err());
        assert!(entry_complete(&cached));
        assert!(cached_rootfs(&cached, never, sync_dir).is_ok());
    }

    #[test]
    fn cache_durability_failure_is_retried_before_reuse() {
        let d = tmpdir("durability");
        let cached = d.join("key.ext4");
        let fail_after_marker = |dir: &Path| {
            assert_eq!(dir, &*d);
            if cached.with_extension("ok").exists() {
                return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
            }
            sync_dir(dir)
        };
        // Publication reaches the marker rename, but must not return a path.
        assert!(cached_rootfs(&cached, build("first"), fail_after_marker).is_err());
        assert!(entry_complete(&cached));
        let inode = std::fs::metadata(&cached).unwrap().ino();
        // A cache hit must retry that fsync, and still refuse on failure.
        assert!(cached_rootfs(&cached, never, fail_after_marker).is_err());
        let path = cached_rootfs(&cached, never, sync_dir).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        // Once handed out, even a damaged marked entry cannot be cleaned up.
        std::fs::remove_file(cached.with_extension("conf")).unwrap();
        assert!(cached_rootfs(&cached, never, sync_dir).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    }

    #[test]
    fn interrupted_publication_is_rebuilt() {
        let d = tmpdir("interrupted");
        let cached = d.join("key.ext4");
        // A build killed after the rootfs rename, mid-way through the config.
        for (name, data) in [("key.ext4", "half published"), ("key.part123", "partial"), ("key.tmp456", "abandoned"), ("other.tmp789", "other key")] {
            std::fs::write(d.join(name), data).unwrap();
        }
        let old = File::open(&cached).unwrap();
        let path = cached_rootfs(&cached, build("rebuilt"), sync_dir).unwrap();
        assert_eq!(read(&path), "rebuilt image");
        assert_eq!(read(path.with_extension("conf")), "rebuilt config");
        assert!(path.with_extension("ok").exists());
        // The old file was unlinked, not rewritten.
        assert_ne!(old.metadata().unwrap().ino(), std::fs::metadata(&path).unwrap().ino());
        assert_eq!(std::io::read_to_string(old).unwrap(), "half published");
        assert!(!d.join("key.part123").exists() && !d.join("key.tmp456").exists());
        assert!(d.join("other.tmp789").exists());
    }

    #[test]
    fn concurrent_cache_builds_wait_and_reuse() {
        use std::sync::mpsc;
        let d = tmpdir("cache-lock");
        let cached = d.join("key.ext4");
        let ((building, started), (release, wait)) = (mpsc::channel(), mpsc::channel());
        let first_path = cached.clone();
        let first = std::thread::spawn(move || {
            cached_rootfs(&first_path, |tmp| {
                building.send(()).unwrap();
                wait.recv().unwrap();
                assert!(!first_path.with_extension("ok").exists());
                build("first")(tmp)
            }, sync_dir)
            .unwrap()
        });
        started.recv().unwrap();
        let lock = File::options().write(true).open(cached.with_extension("lock")).unwrap();
        assert_eq!(flock(&lock, libc::LOCK_EX | libc::LOCK_NB).unwrap_err().raw_os_error(), Some(libc::EWOULDBLOCK));
        let second_path = cached.clone();
        let second = std::thread::spawn(move || cached_rootfs(&second_path, never, sync_dir).unwrap());
        release.send(()).unwrap();
        assert_eq!(first.join().unwrap(), second.join().unwrap());
        assert_eq!(read(&cached), "first image");
    }
}
