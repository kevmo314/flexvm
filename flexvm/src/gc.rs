//! Garbage collection beyond what dead processes hold (`Host::collect_garbage`):
//! logs on the run directory's tmpfs, `NAME.moved` markers and standby
//! sockets. `sweep` runs once a boot as the host is first opened (`after_boot`), and about every `EVERY` on a host with a listener or
//! any VM process (as one starts, then through `periodic`), whether or not
//! VMs start. Logs are capped by their writers (`util::output`).

use std::fs::File;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::bail;
use crate::host::{boot_id, probe, Flock, Host, Ident, Liveness};
use crate::util::{locked, Result};

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

/// A load set unused this long goes; one still wanted is learned again at its next load.
pub const LOADSET_TTL: Duration = Duration::from_secs(24 * 3600);

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

/// Until this boot's recovery is complete, every opener of the host as root: `Host::after_boot`,
/// which records the VMs lost in the reboot for `ls`, withdraws what they held and puts back the
/// routes to peers' VMs. With `rest`, then the forwarding settings flexvm needs and `recover`; the
/// recovery is marked complete (`Host::mark_recovered`) only after all of it, and only if each
/// step succeeded (delivery and settlement are retried from their records by every sweep). VM
/// processes and template builds pass false and leave it to a full pass. Returns whether it ran,
/// or an error if local recovery, forwarding setup or recording completion failed.
pub fn after_boot(host: &Host, rest: bool) -> Result<bool> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(false);
    }
    let Some(local) = host.after_boot()? else { return Ok(false) };
    if !rest {
        if !local {
            bail!("local boot recovery incomplete; see earlier errors");
        }
        return Ok(true);
    }
    let forwarding = crate::net::ip_forward();
    if let Some(dev) = host.config_now().announce_dev() {
        crate::net::proxy_arp(&dev);
    }
    recover(host);
    forwarding?;
    if !local {
        bail!("local boot recovery incomplete; see earlier errors");
    }
    host.mark_recovered()?;
    Ok(true)
}

/// Listener startup and explicit recovery always sweep and refill, even if boot recovery
/// failed before reaching that step (for example, opening the host lock).
pub fn recover_after_boot(host: &Host) -> Result<()> {
    let result = after_boot(host, true);
    if !matches!(result, Ok(true)) {
        recover(host);
    }
    result.map(|_| ())
}

/// One foreground warning per host and boot, without suppressing recovery retries.
pub fn first_boot_warning(host: &Host, boot: &str) -> Result<bool> {
    use std::io::{Read, Seek, Write};
    if boot.is_empty() {
        return Ok(true);
    }
    let mut file = crate::host::private_file(&crate::host::locks(&host.run).join("boot-warning"))?;
    let _lock = Flock::new(file.try_clone()?, libc::LOCK_EX)?;
    let mut previous = String::new();
    file.read_to_string(&mut previous)?;
    if previous == boot {
        return Ok(false);
    }
    file.rewind()?;
    file.set_len(0)?;
    file.write_all(boot.as_bytes())?;
    Ok(true)
}

/// A sweep now (the peers told of withdrawals, interrupted migrations settled and retired) and
/// each template's standby VMs refilled: `flexvm recover`, a listener as it starts, the first
/// command after a boot.
pub fn recover(host: &Host) {
    let _ = std::fs::write(host.run.join(".gc"), b"");
    sweep(host);
    crate::standby::refill_round(host);
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
    // Its own nonblocking lock: a peer that is down holds up no local cleanup.
    host.deliver_withdrawals();
    host.retire_migrations();
    host.settle_owed();
}

/// Local sweeps are one at a time (`RUN/.gc.lock`).
pub fn local_cleanup(host: &Host) {
    let Ok(lock) = crate::host::private_file(&crate::host::locks(&host.run).join("gc")) else { return };
    let Ok(_lock) = Flock::new(lock, libc::LOCK_EX | libc::LOCK_NB) else { return };
    if let Err(e) = host.collect_garbage() {
        crate::log!("garbage collection: {e}");
    }
    vm_files(host);
    orphan_log_locks(&host.run.join("vms"));
    for e in std::fs::read_dir(host.run.join("standby")).into_iter().flatten().flatten() {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            standby_sockets(&e.path());
            orphan_log_locks(&e.path());
        }
    }
    load_sets(&host.run.join("standby"));
}

/// `.loadset-ID` (`standby::save_load_set`) neither read nor written for `LOADSET_TTL`:
/// a rebuilt template's old ones, say. By age, not by whether generation ID exists: a
/// run directory may serve several templates directories, and this sweep knows none.
fn load_sets(dir: &Path) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if e.file_name().to_string_lossy().starts_with(".loadset-") && age(&e.path()).is_some_and(|a| a > LOADSET_TTL) {
            let _ = std::fs::remove_file(e.path());
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
            // Its lock is made first, so one missing is an arrival's that ended.
            let lock = crate::host::locks(&host.run.join("vms")).join(&file);
            if age(&path).is_some_and(|a| a > ARRIVAL_GRACE) && locked(&lock, libc::LOCK_EX) != Some(true) {
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_file(&lock);
            }
            continue;
        }
        let Some(name) = log_name(&file) else { continue };
        if logs.is_none() || age(&path).is_none_or(|a| a <= ORPHAN_LOG_TTL) {
            continue;
        }
        // Not a VM's name: never one of its logs.
        let Ok(suspended) = host.suspended(name) else { continue };
        let orphan =
            host.holder_gone(name) && !suspended.exists() && !["failed", "moved", "lost"].iter().any(|ext| host.vms(name, ext).is_ok_and(|p| p.exists()));
        if orphan {
            // Its writers' lock goes after (`orphan_log_locks`).
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Writers' locks (`output::log_lock`) in `dir` with neither log there, removed while held:
/// a writer that opened one before checks after locking that it is still the name's.
fn orphan_log_locks(dir: &Path) {
    for entry in std::fs::read_dir(crate::host::locks(dir)).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|n| n.ends_with(".log") && !n.starts_with('.')) else { continue };
        let log = dir.join(name);
        let Ok(lock) = crate::host::lock_path(&entry.path(), libc::LOCK_EX | libc::LOCK_NB) else { continue };
        let Ok(_held) = Flock::new(lock, libc::LOCK_EX | libc::LOCK_NB) else { continue };
        if !log.exists() && !log.with_extension("log.1").exists() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// `PID.sock`, and in `.locks`, `PID-START.claim` and `PID-START.take` (a claimer's) of standbys
/// whose locks are gone, and `.PID-START.lock` (a lock not yet in place, unlocked at first) of standbys gone.
fn standby_sockets(dir: &Path) {
    let locks = crate::host::locks(dir);
    // Held while a standby replaces its socket (`standby::serve`): a reused pid's new socket is seen with its lock held.
    // Not waited for: a standby stopped holding it would stall every sweep.
    let Ok(_publish) = crate::host::private_file(&locks.join("publish")).and_then(|f| Flock::new(f, libc::LOCK_EX | libc::LOCK_NB)) else { return };
    for e in [dir, &locks].iter().flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten()) {
        let n = e.file_name().to_string_lossy().into_owned();
        let claim = n.strip_suffix(".claim").or_else(|| n.strip_suffix(".take"));
        let tmp = n.strip_prefix('.').and_then(|n| n.strip_suffix(".lock"));
        let socket_id = n.strip_suffix(".sock").and_then(|s| s.parse().ok()).map(|pid| Ident::of(pid).map(|id| id.key()).unwrap_or_else(|| format!("{pid}-0")));
        let Some(id) = claim.or(tmp).or(socket_id.as_deref()) else {
            continue;
        };
        let Some((pid, start)) = id.split_once('-') else { continue };
        if [pid, start].iter().any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit())) {
            continue;
        }
        let free = match (tmp, pid.parse(), start.parse()) {
            (Some(_), Ok(pid), Ok(start)) => Ident { pid, start, boot: boot_id().into() }.liveness() == Liveness::Gone,
            (Some(_), ..) => false,
            _ => match File::open(locks.join(format!("{id}.lock"))) {
                Ok(f) => probe(&f, libc::LOCK_SH).is_ok(),
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
    use crate::host::flock;

    fn dir(tag: &str) -> crate::test_util::TempDir {
        crate::test_util::TempDir::new(&format!("gc-{tag}"))
    }

    #[test]
    fn foreground_boot_warning_is_once_per_boot() {
        let d = dir("boot-warning");
        let host = Host::open(&d.join("state"), &d.join("run")).unwrap();
        assert!(first_boot_warning(&host, "boot-1").unwrap());
        assert!(!first_boot_warning(&host, "boot-1").unwrap());
        let reopened = Host::open(&host.state, &host.run).unwrap();
        assert!(!first_boot_warning(&reopened, "boot-1").unwrap());
        assert!(first_boot_warning(&reopened, "b2").unwrap());
        assert!(!first_boot_warning(&host, "b2").unwrap());
        std::thread::scope(|scope| {
            let warnings: Vec<_> = (0..8).map(|_| scope.spawn(|| first_boot_warning(&host, "boot-3").unwrap())).collect();
            assert_eq!(warnings.into_iter().map(|warning| warning.join().unwrap()).filter(|&first| first).count(), 1);
        });
    }

    #[test]
    fn initial_recovery_sweeps_even_when_the_host_lock_cannot_open() {
        let d = dir("boot-lock-error");
        let host = Host::open(&d.join("state"), &d.join("run")).unwrap();
        let lock = host.lock_file();
        let _ = std::fs::remove_file(&lock);
        std::fs::create_dir(&lock).unwrap();
        assert!(!host.run.join(".gc").exists());
        let result = recover_after_boot(&host);
        if unsafe { libc::geteuid() } == 0 {
            assert!(result.is_err(), "root must report the failed boot recovery");
        } else {
            assert!(result.is_ok(), "non-root skips boot recovery");
        }
        assert!(host.run.join(".gc").exists(), "the initial sweep still ran");
        assert!(!host.run.join(".boot").exists(), "failed recovery is retried");
    }

    #[test]
    fn a_dead_standbys_socket_goes_a_live_ones_stays() {
        let d = dir("socks");
        let l = crate::host::locks(&d);
        crate::host::private_dir(&l).unwrap();
        let held = File::create(l.join("1-1.lock")).unwrap();
        flock(&held, libc::LOCK_EX).unwrap();
        File::create(l.join("2-1.lock")).unwrap();
        let claiming = File::create(l.join("4-1.claim")).unwrap();
        flock(&claiming, libc::LOCK_EX).unwrap();
        for s in ["1-1.lock", "3-1.claim", "5-6.claim", "5-7.claim", "3-1.take", "5-7.take"] {
            File::create(l.join(s)).unwrap();
        }
        let other = File::create(l.join("5-7.lock")).unwrap();
        flock(&other, libc::LOCK_EX).unwrap();
        // Lock files not yet renamed in place: a dead process's goes, a live one's stays, locked or not.
        let mine = format!(".{}.lock", Ident::me().key());
        for s in [".999999999-1.lock", &mine] {
            File::create(l.join(s)).unwrap();
        }
        let me = Ident::me();
        let live_lock = File::create(l.join(format!("{}.lock", me.key()))).unwrap();
        flock(&live_lock, libc::LOCK_EX).unwrap();
        let live_sock = format!("{}.sock", me.pid);
        File::create(d.join(&live_sock)).unwrap();
        File::create(d.join("999999990.sock")).unwrap();
        standby_sockets(&d);
        let left = |n: &str| d.join(n).exists() || l.join(n).exists();
        assert!(left(&live_sock));
        assert!(!left("999999990.sock"));
        assert!(left("4-1.claim") && left("5-7.claim"), "a claim marker of a standby still here stays");
        assert!(!left("3-1.claim") && !left("5-6.claim"), "one unlocked goes once its lock is gone or names another process");
        assert!(!left("3-1.take") && left("5-7.take"), "a claimer's marker goes with its standby");
        assert!(left("2-1.lock"));
        assert!(!left(".999999999-1.lock") && left(&mine));
    }

    /// A sweep skips the dir while a standby replaces its socket under its `.locks/publish` (one stopped there stalls no
    /// sweep), sweeps it once free, and keeps that lock file.
    #[test]
    fn socket_sweep_skips_a_standby_publishing() {
        let d = dir("publish");
        File::create(d.join("999999990.sock")).unwrap();
        let publishing = crate::host::private_file(&crate::host::locks(&d).join("publish")).unwrap();
        flock(&publishing, libc::LOCK_EX).unwrap();
        standby_sockets(&d);
        assert!(d.join("999999990.sock").exists(), "skipped, not waited for");
        flock(&publishing, libc::LOCK_UN).unwrap();
        standby_sockets(&d);
        assert!(!d.join("999999990.sock").exists() && crate::host::locks(&d).join("publish").exists());
    }

    #[test]
    fn load_sets_unused_for_a_day_go() {
        let d = dir("loadsets");
        let old = SystemTime::now() - LOADSET_TTL - Duration::from_secs(60);
        for (f, t) in [(".loadset-ab12", SystemTime::now()), (".loadset-cd34", old), ("default", old)] {
            File::create(d.join(f)).unwrap().set_modified(t).unwrap();
        }
        load_sets(&d);
        assert!(d.join(".loadset-ab12").exists() && !d.join(".loadset-cd34").exists() && d.join("default").exists());
    }

    fn store_holder(host: &Host, name: &str, id: &crate::host::Ident) {
        crate::host::store(&host.vms(name, "lock").unwrap(), id, false).unwrap();
    }

    #[test]
    fn busy_retirement_does_not_block_local_cleanup() {
        let d = dir("retire-lock");
        let host = Host::open(&d.join("state"), &d.join("run")).unwrap();
        let retirement = crate::host::private_file(&crate::host::locks(&host.run).join("retire")).unwrap();
        flock(&retirement, libc::LOCK_EX | libc::LOCK_NB).unwrap();
        let marker = host.vms("gone", "moved").unwrap();
        File::create(&marker).unwrap().set_modified(SystemTime::now() - MOVED_TTL - Duration::from_secs(1)).unwrap();
        sweep(&host);
        assert!(!marker.exists());
        // Let go explicitly: another test's child, forked but not yet exec'd, may share it.
        let gc = File::open(crate::host::locks(&host.run).join("gc")).unwrap();
        assert!(flock(&gc, libc::LOCK_EX | libc::LOCK_NB).is_ok(), "the sweep let go of its lock");
    }

    #[test]
    fn suspended_vms_keep_both_logs_until_the_snapshot_goes() {
        let d = dir("suspended-logs");
        let host = Host::open(&d.join("state"), &d.join("run")).unwrap();
        std::fs::create_dir_all(host.suspended("sleeping").unwrap()).unwrap();
        let logs = [host.vms("sleeping", "log").unwrap(), host.vms("sleeping", "log.1").unwrap()];
        for path in &logs {
            File::create(path).unwrap().set_modified(SystemTime::now() - ORPHAN_LOG_TTL - Duration::from_secs(60)).unwrap();
        }
        vm_files(&host);
        assert!(logs.iter().all(|p| p.exists()), "a suspended VM has no live holder but keeps its logs");
        std::fs::remove_dir_all(host.suspended("sleeping").unwrap()).unwrap();
        vm_files(&host);
        assert!(logs.iter().all(|p| !p.exists()), "without its snapshot the old logs are orphaned");
    }

    #[test]
    fn orphan_standby_log_locks_are_removed_only_while_free_and_without_logs() {
        let d = crate::test_util::TempDir::new("standby-log-locks");
        let log = d.join("standby.log");
        let path = crate::util::output::log_lock(&log).unwrap();
        let lock = crate::host::lock_path(&path, libc::LOCK_EX).unwrap();
        let held = Flock::new(lock, libc::LOCK_EX).unwrap();
        orphan_log_locks(&d);
        assert!(path.exists());
        drop(held);
        std::fs::write(log.with_extension("log.1"), b"previous").unwrap();
        orphan_log_locks(&d);
        assert!(path.exists(), "a rotated log still needs its writer lock");
        std::fs::remove_file(log.with_extension("log.1")).unwrap();
        orphan_log_locks(&d);
        assert!(!path.exists());
    }

    /// An orphaned log and its writers' lock go together, even with a waiter open,
    /// which must retry on the replacement lock before rotating.
    #[test]
    fn a_logs_writer_lock_is_removed_with_the_log() {
        let d = dir("writer-lock");
        let host = Host::open(&d.join("state"), &d.join("run")).unwrap();
        let log = host.vms("gone", "log").unwrap();
        assert!(crate::util::output::append_capped(&log, b"x\n", 1 << 20));
        File::options().append(true).open(&log).unwrap().set_modified(SystemTime::now() - ORPHAN_LOG_TTL - Duration::from_secs(60)).unwrap();
        let lock = crate::util::output::log_lock(&log).unwrap();
        let writer = File::open(&lock).unwrap();
        vm_files(&host);
        orphan_log_locks(&host.run.join("vms"));
        assert!(!log.exists() && !lock.exists(), "the log and its lock go");
        use std::os::unix::fs::MetadataExt;
        assert!(crate::util::output::append_capped(&log, b"new\n", 1 << 20));
        assert_ne!(writer.metadata().unwrap().ino(), std::fs::metadata(&lock).unwrap().ino());
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
        let held = crate::host::private_file(&crate::host::locks(&host.run.join("vms")).join(".incoming-1-2.log")).unwrap();
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
        // Free at once though another test's child, forked but not yet exec'd, shares the
        // logs lock's open file: dropping it let go explicitly.
        vm_files(&host);
        assert!(live_name.exists() && !dead_name.exists(), "by the name's holder");
        assert!(!dead.exists() && fresh.exists() && live.exists(), "arrivals");
        assert!(!moved.exists() && recent_moved.exists(), "markers");
        assert!(!orphan.exists() && !orphan_prev.exists() && kept_by_moved.exists() && quiet.exists() && failed_log.exists(), "logs");
    }
}
