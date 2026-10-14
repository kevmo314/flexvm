//! Garbage collection beyond what dead processes hold (`host::collect_garbage`):
//! logs on the run directory's tmpfs, `NAME.moved` markers, standby sockets
//! and template load sets. `sweep` runs as a VM process starts and, through
//! `periodic`, about every `EVERY` on a host with a listener or any VM
//! process, whether or not VMs start.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::host::{flock, Host};

/// A log is trimmed once past this, to its last `LOG_KEEP` bytes.
pub const LOG_CAP: u64 = 8 << 20;
pub const LOG_KEEP: u64 = 2 << 20;
/// What a trimmed log starts with.
const TRIMMED: &[u8] = b"[flexvm: earlier output dropped]\n";

/// How often `periodic` sweeps (some process on the host does).
const EVERY: Duration = Duration::from_secs(30);
/// An arrival's log, unlocked, is its dead arrival's only after this: the
/// listener creates it a moment before locking it.
const ARRIVAL_GRACE: Duration = Duration::from_secs(5);
/// How long `NAME.moved` keeps telling `ls` and `exec` where a VM went.
const MOVED_TTL: Duration = Duration::from_secs(3600);
/// A log of a name with nothing left here (no VM, suspended VM, failed or
/// moved record) goes once unwritten this long.
const ORPHAN_LOG_TTL: Duration = Duration::from_secs(3600);

/// Prefix of an arrival's log until it is accepted (`listen::incoming`).
pub const ARRIVAL_LOG: &str = ".incoming-";

/// Every `EVERY` (give or take, so the processes on a host take turns),
/// a sweep if no process on the host swept since.
pub fn periodic(host: Host, templates: Option<PathBuf>) {
    std::thread::spawn(move || loop {
        let jitter = Duration::from_millis(std::process::id() as u64 % 5000);
        std::thread::sleep(EVERY + jitter);
        let stamp = host.run.join(".gc");
        let recent = age(&stamp).is_some_and(|a| a < EVERY);
        if !recent {
            let _ = std::fs::write(&stamp, b"");
            sweep(&host, templates.as_deref());
        }
    });
}

/// Everything collectable now. Sweeps are one at a time (`RUN/.gc.lock`);
/// one already under way is not repeated.
pub fn sweep(host: &Host, templates: Option<&Path>) {
    let Ok(lock) = File::create(host.run.join(".gc.lock")) else { return };
    if flock(&lock, libc::LOCK_EX | libc::LOCK_NB).is_err() {
        return;
    }
    let cfg = host.config_now();
    crate::host::collect_garbage(&host.run, &cfg.prefix);
    vm_files(host);
    for e in std::fs::read_dir(host.run.join("standby")).into_iter().flatten().flatten() {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            let _ = trim(&e.path().join("standby.log"), LOG_CAP, LOG_KEEP);
            standby_sockets(&e.path());
        }
    }
    if let Some(t) = templates {
        load_sets(host, t);
    }
    host.retire_migrations();
}

fn age(path: &Path) -> Option<Duration> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| SystemTime::now().duration_since(t).ok())
}

/// Logs in `RUN/vms`: capped; a dead arrival's removed; one whose name has
/// nothing left here removed once quiet. Old `.moved` markers.
fn vm_files(host: &Host) {
    let files = || {
        std::fs::read_dir(host.run.join("vms")).into_iter().flatten().flatten().filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())))
    };
    // Markers first: a log is kept for its VM's.
    for (file, path) in files() {
        let Some(name) = file.strip_suffix(".moved").filter(|_| !file.starts_with('.')) else { continue };
        if age(&path).is_some_and(|a| a > MOVED_TTL) && host.name_locked(name) == Some(false) {
            let _ = std::fs::remove_file(&path);
        }
    }
    for (file, path) in files() {
        if file.starts_with(ARRIVAL_LOG) && file.ends_with(".log") {
            if age(&path).is_some_and(|a| a > ARRIVAL_GRACE) && unlocked(&path) {
                let _ = std::fs::remove_file(&path);
            }
            continue;
        }
        if file.starts_with('.') {
            continue;
        }
        let Some(name) = file.strip_suffix(".log") else { continue };
        let _ = trim(&path, LOG_CAP, LOG_KEEP);
        let orphan = host.name_locked(name) == Some(false)
            && !host.suspended(name).exists()
            && !["failed", "moved"].iter().any(|ext| host.vms(name, ext).exists());
        if orphan && age(&path).is_some_and(|a| a > ORPHAN_LOG_TTL) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Whether no process holds a lock on `path` (an arrival holds its log's for life).
fn unlocked(path: &Path) -> bool {
    File::open(path).is_ok_and(|f| flock(&f, libc::LOCK_EX | libc::LOCK_NB).is_ok())
}

/// `KEY.PID.sock` of a standby VM whose `PID.lock` nobody holds: it bound
/// the socket holding the lock, so it is gone (SIGKILLed: it removes both otherwise).
fn standby_sockets(dir: &Path) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let Some(pid) = n.strip_suffix(".sock").and_then(|s| s.rsplit_once('.')).map(|(_, pid)| pid.to_string()) else { continue };
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let lock = dir.join(format!("{pid}.lock"));
        let free = match File::open(&lock) {
            Ok(f) => flock(&f, libc::LOCK_SH | libc::LOCK_NB).is_ok(),
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        };
        if free {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// `.loadset-ID` of a generation no template name points to and no VM
/// here runs. Nothing is removed if any template cannot be read.
fn load_sets(host: &Host, templates: &Path) {
    let Some(mut keep) = current_ids(templates) else { return };
    keep.extend(host.entries().into_iter().map(|e| e.template_id));
    for e in std::fs::read_dir(host.run.join("standby")).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.strip_prefix(".loadset-").is_some_and(|id| !keep.iter().any(|k| k == id)) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The generation ids template names point to now; None if one cannot be read.
fn current_ids(templates: &Path) -> Option<Vec<String>> {
    let mut ids = Vec::new();
    for e in std::fs::read_dir(templates).ok()? {
        let e = e.ok()?;
        if e.file_name().to_string_lossy().starts_with('.') || !e.path().is_dir() {
            continue;
        }
        let meta = std::fs::read(e.path().join("meta.json")).ok()?;
        ids.push(serde_json::from_slice::<serde_json::Value>(&meta).ok()?["id"].as_str().unwrap_or_default().to_string());
    }
    Some(ids)
}

/// Keeps a log's last `keep` bytes (from a line's start) once it is past
/// `cap`, in place: its writers append (O_APPEND), so they go on at the new
/// end. Output written while it trims may be lost. Whether it trimmed.
pub fn trim(path: &Path, cap: u64, keep: u64) -> std::io::Result<bool> {
    let f = File::options().read(true).write(true).open(path)?;
    let len = f.metadata()?.len();
    if len <= cap {
        return Ok(false);
    }
    let from = len - keep.min(len);
    let mut tail = vec![0u8; (len - from) as usize];
    f.read_exact_at(&mut tail, from)?;
    let start = match tail.iter().position(|&b| b == b'\n') {
        Some(i) if i + 1 < tail.len() => i + 1,
        _ => 0,
    };
    let mut out = Vec::with_capacity(TRIMMED.len() + tail.len() - start);
    out.extend_from_slice(TRIMMED);
    out.extend_from_slice(&tail[start..]);
    // What was appended meanwhile, once.
    let now = f.metadata()?.len();
    if now > len {
        let mut more = vec![0u8; (now - len) as usize];
        f.read_exact_at(&mut more, len)?;
        out.extend_from_slice(&more);
    }
    f.write_all_at(&out, 0)?;
    f.set_len(out.len() as u64)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("flexvm-gc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_log_past_its_cap_keeps_its_last_lines_and_its_writers() {
        let d = dir("trim");
        let path = d.join("vm.log");
        let mut w = File::options().create(true).append(true).open(&path).unwrap();
        for i in 0..1000 {
            writeln!(w, "line {i:04} {}", "x".repeat(40)).unwrap();
        }
        assert!(!trim(&path, 1 << 20, 4096).unwrap(), "under the cap: left alone");
        assert!(trim(&path, 10_000, 4096).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("[flexvm: earlier output dropped]\nline "), "{}", &text[..80]);
        assert!(text.len() <= 4096 + TRIMMED.len() && text.ends_with(&format!("line 0999 {}\n", "x".repeat(40))));
        // The writer appends at the new end, not past a hole.
        writeln!(w, "after").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with("x\nafter\n") && !text.contains('\0'));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_dead_standbys_socket_goes_a_live_ones_stays() {
        let d = dir("socks");
        let held = File::create(d.join("1.lock")).unwrap();
        flock(&held, libc::LOCK_EX).unwrap();
        File::create(d.join("2.lock")).unwrap();
        for s in ["key.1.sock", "key.2.sock", "key.3.sock", "key.x.sock", "1.lock"] {
            File::create(d.join(s)).unwrap();
        }
        standby_sockets(&d);
        let left = |n: &str| d.join(n).exists();
        assert!(left("key.1.sock"), "its standby holds its lock");
        assert!(!left("key.2.sock") && !left("key.3.sock"), "lock free or gone");
        assert!(left("key.x.sock") && left("2.lock"));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn load_sets_of_generations_nothing_uses_go() {
        let d = dir("loadsets");
        let host = Host::open(&d.join("state"), &d.join("run")).unwrap();
        let t = d.join("templates");
        let meta = |id: &str| {
            let g = t.join(".gen").join(id);
            std::fs::create_dir_all(&g).unwrap();
            std::fs::write(g.join("meta.json"), serde_json::json!({"vcpus": 1, "id": id}).to_string()).unwrap();
        };
        meta("new");
        meta("old");
        std::os::unix::fs::symlink(".gen/new", t.join("small")).unwrap();
        let set = |id: &str| host.run.join("standby").join(format!(".loadset-{id}"));
        for id in ["new", "old"] {
            std::fs::write(set(id), b"[]").unwrap();
        }
        load_sets(&host, &t);
        assert!(set("new").exists() && !set("old").exists());
        // A template that cannot be read: nothing is taken for unused.
        std::fs::write(set("old"), b"[]").unwrap();
        std::fs::create_dir_all(t.join("broken")).unwrap();
        load_sets(&host, &t);
        assert!(set("old").exists());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn dead_arrivals_logs_and_old_markers_go() {
        let d = dir("vmfiles");
        let host = Host::open(&d.join("state"), &d.join("run")).unwrap();
        let old = SystemTime::now() - Duration::from_secs(7200);
        let at = |n: &str, t: SystemTime| {
            let p = host.run.join("vms").join(n);
            File::create(&p).unwrap().set_modified(t).unwrap();
            p
        };
        let dead = at(".incoming-1-0.log", old);
        let fresh = at(".incoming-1-1.log", SystemTime::now());
        let live = at(".incoming-1-2.log", old);
        let held = File::open(&live).unwrap();
        flock(&held, libc::LOCK_SH).unwrap();
        let moved = at("gone.moved", old);
        let recent_moved = at("web.moved", SystemTime::now());
        let orphan = at("gone.log", old);
        let kept_by_moved = at("web.log", old);
        let quiet = at("new.log", SystemTime::now());
        let failed_log = at("bad.log", old);
        at("bad.failed", old);
        vm_files(&host);
        assert!(!dead.exists() && fresh.exists() && live.exists(), "arrivals");
        assert!(!moved.exists() && recent_moved.exists(), "markers");
        assert!(!orphan.exists() && kept_by_moved.exists() && quiet.exists() && failed_log.exists(), "logs");
        std::fs::remove_dir_all(d).unwrap();
    }
}
