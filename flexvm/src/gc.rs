//! Garbage collection beyond what dead processes hold (`Host::collect_garbage`):
//! logs on the run directory's tmpfs, `NAME.moved` markers and standby
//! sockets. `sweep` runs about every `EVERY` on a host with a listener or
//! any VM process (as one starts, then through `periodic`), whether or not
//! VMs start. Logs are capped by their writers (`util::output`).

use std::fs::File;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::host::{boot_id, flock, Host, Ident, Liveness};
use crate::util::locked;

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
        sweep_due(&host);
    });
}

/// A sweep if no process on the host swept within `EVERY`.
pub fn sweep_due(host: &Host) {
    let stamp = host.run.join(".gc");
    if age(&stamp).is_none_or(|a| a >= EVERY) {
        let _ = std::fs::write(&stamp, b"");
        sweep(host);
    }
}

/// Local cleanup and network retirement have separate nonblocking locks, so
/// slow sources cannot keep other processes from cleaning up local files.
pub fn sweep(host: &Host) {
    local_cleanup(host);
    host.retire_migrations();
    host.settle_owed();
}

/// Local sweeps are one at a time (`RUN/.gc.lock`).
fn local_cleanup(host: &Host) {
    let Ok(lock) = File::create(host.run.join(".gc.lock")) else { return };
    if flock(&lock, libc::LOCK_EX | libc::LOCK_NB).is_err() {
        return;
    }
    if let Err(e) = host.collect_garbage() {
        crate::log!("garbage collection: {e}");
    }
    vm_files(host);
    for e in std::fs::read_dir(host.run.join("standby")).into_iter().flatten().flatten() {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            standby_sockets(&e.path());
        }
    }
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
    let files = || std::fs::read_dir(host.run.join("vms")).into_iter().flatten().flatten().filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())));
    // Markers first: a log is kept for its VM's.
    for (file, path) in files() {
        let Some(name) = file.strip_suffix(".moved").filter(|_| !file.starts_with('.')) else { continue };
        if age(&path).is_some_and(|a| a > MOVED_TTL) && host.holder_gone(name) {
            let _ = std::fs::remove_file(&path);
        }
    }
    // A start opens and marks its log holding this lock shared; busy logs wait for the next sweep.
    let logs = host.logs_lock(libc::LOCK_EX | libc::LOCK_NB).ok();
    for (file, path) in files() {
        if file.starts_with(ARRIVAL_LOG) && file.ends_with(".log") {
            if age(&path).is_some_and(|a| a > ARRIVAL_GRACE) && locked(&path, libc::LOCK_EX) == Some(false) {
                let _ = std::fs::remove_file(&path);
            }
            continue;
        }
        let Some(name) = log_name(&file) else { continue };
        if logs.is_none() || age(&path).is_none_or(|a| a <= ORPHAN_LOG_TTL) {
            continue;
        }
        let orphan = host.holder_gone(name) && !host.suspended(name).exists() && !["failed", "moved"].iter().any(|ext| host.vms(name, ext).exists());
        if orphan {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// `KEY.PID-START.sock` and `PID-START.claim` of standbys whose locks are gone,
/// and `.PID-START.lock` (a lock not yet in place, unlocked at first) of standbys gone.
fn standby_sockets(dir: &Path) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let (claim, tmp) = (n.strip_suffix(".claim"), n.strip_prefix('.').and_then(|n| n.strip_suffix(".lock")));
        let Some(id) = claim.or(tmp).or_else(|| n.strip_suffix(".sock").and_then(|s| s.rsplit_once('.')).map(|(_, id)| id)) else { continue };
        let Some((pid, start)) = id.split_once('-') else { continue };
        if [pid, start].iter().any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit())) {
            continue;
        }
        let free = match (tmp, pid.parse(), start.parse()) {
            (Some(_), Ok(pid), Ok(start)) => Ident { pid, start, boot: boot_id().into() }.liveness() == Liveness::Gone,
            (Some(_), ..) => false,
            _ => match File::open(dir.join(format!("{id}.lock"))) {
                Ok(f) => flock(&f, libc::LOCK_SH | libc::LOCK_NB).is_ok(),
                Err(e) => e.kind() == std::io::ErrorKind::NotFound,
            },
        };
        if free && (claim.is_none() || locked(&e.path(), libc::LOCK_EX) == Some(false)) {
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
        let held = File::create(d.join("1-1.lock")).unwrap();
        flock(&held, libc::LOCK_EX).unwrap();
        File::create(d.join("2-1.lock")).unwrap();
        let claiming = File::create(d.join("4-1.claim")).unwrap();
        flock(&claiming, libc::LOCK_EX).unwrap();
        for s in ["key.1-1.sock", "key.1-2.sock", "key.2-1.sock", "key.3-1.sock", "key.x.sock", "1-1.lock", "3-1.claim", "5-6.claim", "5-7.claim"] {
            File::create(d.join(s)).unwrap();
        }
        let other = File::create(d.join("5-7.lock")).unwrap();
        flock(&other, libc::LOCK_EX).unwrap();
        // Lock files not yet renamed in place: a dead process's goes, a live one's stays, locked or not.
        let mine = format!(".{}.lock", Ident::me().key());
        for s in [".999999999-1.lock", &mine] {
            File::create(d.join(s)).unwrap();
        }
        standby_sockets(&d);
        let left = |n: &str| d.join(n).exists();
        assert!(left("key.1-1.sock"), "its standby holds its lock");
        assert!(left("4-1.claim") && left("5-7.claim"), "a claim marker of a standby still here stays");
        assert!(!left("3-1.claim") && !left("5-6.claim"), "one unlocked goes once its lock is gone or names another process");
        assert!(!left("key.1-2.sock"), "a reused pid keeps only its own socket");
        assert!(!left("key.2-1.sock") && !left("key.3-1.sock"), "lock free or gone");
        assert!(left("key.x.sock") && left("2-1.lock"));
        assert!(!left(".999999999-1.lock") && left(&mine));
        std::fs::remove_dir_all(d).unwrap();
    }

    fn store_holder(host: &Host, name: &str, id: &crate::host::Ident) {
        crate::host::store(&host.vms(name, "lock"), id, false).unwrap();
    }

    #[test]
    fn busy_retirement_does_not_block_local_cleanup() {
        let d = dir("retire-lock");
        let host = Host::open(&d.join("state"), &d.join("run")).unwrap();
        let retirement = File::create(host.run.join(".retire.lock")).unwrap();
        flock(&retirement, libc::LOCK_EX | libc::LOCK_NB).unwrap();
        let marker = host.vms("gone", "moved");
        File::create(&marker).unwrap().set_modified(SystemTime::now() - MOVED_TTL - Duration::from_secs(1)).unwrap();
        sweep(&host);
        assert!(!marker.exists());
        let gc = File::open(host.run.join(".gc.lock")).unwrap();
        flock(&gc, libc::LOCK_EX | libc::LOCK_NB).unwrap();
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
        // The logs lock is busy while another test's child, forked but not yet exec'd, still has
        // it open (its fd inherited for that moment): busy is left for the next sweep, so sweep
        // until it was free once.
        for _ in 0..200 {
            vm_files(&host);
            if !dead_name.exists() && !orphan.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(live_name.exists() && !dead_name.exists(), "by the name's holder");
        assert!(!dead.exists() && fresh.exists() && live.exists(), "arrivals");
        assert!(!moved.exists() && recent_moved.exists(), "markers");
        assert!(!orphan.exists() && !orphan_prev.exists() && kept_by_moved.exists() && quiet.exists() && failed_log.exists(), "logs");
        std::fs::remove_dir_all(d).unwrap();
    }
}
