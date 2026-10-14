//! Garbage collection beyond what dead processes hold (`Host::collect_garbage`):
//! logs on the run directory's tmpfs, `NAME.moved` markers and standby
//! sockets. `sweep` runs as a VM process starts and, through `periodic`,
//! about every `EVERY` on a host with a listener or any VM process, whether
//! or not VMs start. Logs are capped by their writers (`util::output`).

use std::fs::File;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::host::{flock, Host};

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
pub fn periodic(host: Host) {
    std::thread::spawn(move || loop {
        let jitter = Duration::from_millis(std::process::id() as u64 % 5000);
        std::thread::sleep(EVERY + jitter);
        let stamp = host.run.join(".gc");
        let recent = age(&stamp).is_some_and(|a| a < EVERY);
        if !recent {
            let _ = std::fs::write(&stamp, b"");
            sweep(&host);
        }
    });
}

/// Everything collectable now. Sweeps are one at a time (`RUN/.gc.lock`);
/// one already under way is not repeated.
pub fn sweep(host: &Host) {
    let Ok(lock) = File::create(host.run.join(".gc.lock")) else { return };
    if flock(&lock, libc::LOCK_EX | libc::LOCK_NB).is_err() {
        return;
    }
    if let Err(e) = host.collect_garbage() {
        eprintln!("garbage collection: {e}");
    }
    vm_files(host);
    for e in std::fs::read_dir(host.run.join("standby")).into_iter().flatten().flatten() {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            standby_sockets(&e.path());
        }
    }
    host.retire_migrations();
}

fn age(path: &Path) -> Option<Duration> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| SystemTime::now().duration_since(t).ok())
}

/// The name a log in `RUN/vms` is of (`NAME.log`, or its predecessor `NAME.log.1`).
fn log_name(file: &str) -> Option<&str> {
    file.strip_suffix(".log").or_else(|| file.strip_suffix(".log.1")).filter(|n| !n.starts_with('.'))
}

/// In `RUN/vms`: a dead arrival's log; the logs of a name with nothing left
/// here, once quiet; old `.moved` markers.
fn vm_files(host: &Host) {
    let files = || {
        std::fs::read_dir(host.run.join("vms")).into_iter().flatten().flatten().filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())))
    };
    // Markers first: a log is kept for its VM's.
    for (file, path) in files() {
        let Some(name) = file.strip_suffix(".moved").filter(|_| !file.starts_with('.')) else { continue };
        if age(&path).is_some_and(|a| a > MOVED_TTL) && host.holder_gone(name) {
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
        let Some(name) = log_name(&file) else { continue };
        let quiet = || age(&path).is_some_and(|a| a > ORPHAN_LOG_TTL);
        if !quiet() {
            continue;
        }
        // Decided and removed holding the logs lock: a start opens its log
        // holding it too (shared) and marks it written (`main::log_file`), so
        // a log being opened is never quiet here. Busy: left for the next sweep.
        let Ok(_logs) = host.logs_lock(libc::LOCK_EX | libc::LOCK_NB) else { return };
        let orphan = host.holder_gone(name) && !host.suspended(name).exists() && !["failed", "moved"].iter().any(|ext| host.vms(name, ext).exists());
        if orphan && quiet() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("flexvm-gc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
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

    fn store_holder(host: &Host, name: &str, id: &crate::host::Ident) {
        crate::host::store(&host.vms(name, "lock"), id, false).unwrap();
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
        let orphan_prev = at("gone.log.1", old);
        let kept_by_moved = at("web.log", old);
        let quiet = at("new.log", SystemTime::now());
        let failed_log = at("bad.log", old);
        at("bad.failed", old);
        // A start opening a log holds the logs lock: no log is decided on meanwhile.
        let opening = host.logs_lock(libc::LOCK_SH).unwrap();
        vm_files(&host);
        assert!(orphan.exists(), "kept while a log is being opened");
        drop(opening);
        // A name whose holder lives keeps its log, however quiet.
        let live_name = at("held.log", old);
        store_holder(&host, "held", &crate::host::Ident::me());
        let dead_name = at("dead.log", old);
        store_holder(&host, "dead", &crate::host::Ident { pid: 999_999_940, start: 1, boot: crate::host::boot_id().into() });
        vm_files(&host);
        assert!(live_name.exists() && !dead_name.exists(), "by the name's holder");
        assert!(!dead.exists() && fresh.exists() && live.exists(), "arrivals");
        assert!(!moved.exists() && recent_moved.exists(), "markers");
        assert!(!orphan.exists() && !orphan_prev.exists() && kept_by_moved.exists() && quiet.exists() && failed_log.exists(), "logs");
        std::fs::remove_dir_all(d).unwrap();
    }
}
