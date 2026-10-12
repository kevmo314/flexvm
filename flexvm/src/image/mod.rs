//! Templates from container images: fetch an image (registry, `docker save`
//! or OCI archive, OCI layout directory), apply its layers, add flexvm-init
//! and the app's config, and write a read-only ext4 root filesystem.
//!
//! Everything is cached by digest under the cache directory:
//! `blobs/sha256/<hex>` for registry blobs and `rootfs/<key>.ext4` for built
//! filesystems, where the key covers the image config digest, the
//! flexvm-init binary and the overrides.

pub mod reference;
mod registry;
mod source;
mod unpack;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bail;
use crate::guest;
use crate::util::{ms, Result};
use registry::sha256_hex;
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
/// links it to `out`. `init` is the static flexvm-init binary.
pub fn prepare(cache: &Path, init: &Path, o: &Options, out: &Path) -> Result<ImageMeta> {
    let img = source::fetch(cache, &o.image)?;
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
    let key = sha256_hex(
        json!({"v": 1, "config": img.config_digest, "init": sha256_hex(&init_bytes), "options": o}).to_string().as_bytes(),
    );
    let cached = cache.join("rootfs").join(format!("{}.ext4", &key["sha256:".len()..]));
    if cached.exists() {
        eprintln!("image: root filesystem cached at {}", cached.display());
    } else {
        build_rootfs(cache, &img, &app, &init_bytes, &cached)?;
    }
    // A hard link shares one inode, and so one page cache, between templates.
    let tmp = out.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    if std::fs::hard_link(&cached, &tmp).is_err() {
        std::fs::copy(&cached, &tmp)?;
    }
    std::fs::rename(&tmp, out)?;
    Ok(ImageMeta {
        source: o.image.clone(),
        digest: img.digest,
        config_digest: img.config_digest,
        argv: app.argv,
        warm: o.warm,
        ready,
        ready_timeout: o.ready_timeout,
    })
}

/// Warm templates: starts the app in the template VM and waits until it is
/// ready, so the snapshot holds a running app.
pub fn warm_up(vsock: &Path, meta: &ImageMeta) -> Result<()> {
    let start = Instant::now();
    guest::start_app(vsock)?;
    loop {
        let ready = match &meta.ready {
            Some(Ready::Port(p)) => guest::probe(vsock, *p)?,
            Some(Ready::Cmd(c)) => guest::exec(vsock, c)?.0 == 0,
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

/// The app's buffered output and its final status line.
pub fn read_logs(vsock: &Path) -> Result<(Vec<u8>, String)> {
    let mut r = guest::start_logs(vsock, 0, false)?;
    let mut out = Vec::new();
    while let Some((kind, data)) = guest::read_frame(&mut r)? {
        match kind {
            guest::FRAME_MSG => return Ok((out, String::from_utf8_lossy(&data).into_owned())),
            _ => out.extend_from_slice(&data),
        }
    }
    bail!("guest closed the connection while sending logs")
}

fn build_rootfs(cache: &Path, img: &source::Image, app: &App, init: &[u8], dest: &Path) -> Result<()> {
    let work = cache.join("tmp").join(format!("rootfs-{}", std::process::id()));
    if work.exists() {
        std::fs::remove_dir_all(&work)?;
    }
    std::fs::create_dir_all(&work)?;
    let res = (|| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o755))?;
        let mut root = Root::open(&work)?;
        for (i, layer) in img.layers.iter().enumerate() {
            eprintln!("image: applying layer {}/{} {}", i + 1, img.layers.len(), layer.name());
            root.apply_layer(unpack::decompress(layer.open()?)?).map_err(|e| format!("layer {}: {e}", layer.name()))?;
        }
        inject(&mut root, app, init)?;
        mkfs(&work, root.entries, dest)
    })();
    let _ = std::fs::remove_dir_all(&work);
    res
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n")
}

/// Adds what flexvm-init needs to boot and run the app: its mount points,
/// itself, `/etc/flexvm/app.conf`, and sensible `/etc/hosts` and `/etc/resolv.conf`.
fn inject(root: &mut Root, app: &App, init: &[u8]) -> Result<()> {
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
    root.write_file("etc/flexvm/app.conf", conf.as_bytes(), 0o644)
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
    std::fs::create_dir_all(dest.parent().unwrap())?;
    let tmp: PathBuf = dest.with_extension(format!("tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::fs::File::create(&tmp)?.set_len(mib << 20)?;
    let out = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-b", "4096", "-L", "flexroot", "-N", &inodes.to_string(), "-d"])
        .arg(dir)
        .arg(&tmp)
        .output()
        .map_err(|e| format!("mkfs.ext4: {e}"))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        bail!("mkfs.ext4 failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    std::fs::rename(&tmp, dest)?;
    eprintln!("image: root filesystem {} ({mib} MiB, {entries} entries)", dest.display());
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
}
