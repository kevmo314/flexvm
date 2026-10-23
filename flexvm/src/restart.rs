//! Restart policies (`run -d --restart POLICY`, `app::Restart`), without a daemon. A background VM's app
//! exits; if its policy runs it again, its process writes its exited record with when (`Exited::restart_due`)
//! and leaves a worker of its own behind (`flexvm restart-due NAME`, in a session and cgroup of its own, as a
//! VM process is) that waits out the backoff and `start`s the record, as `flexvm start` of an exited VM does.
//! A `start`, `rm` or run of the name meanwhile takes the record first, and the worker finds nothing to do.
//!
//! A reboot loses the VMs that ran, and their exited records with the run directory: a VM with a policy keeps
//! what runs it again in the state directory too (`STATE/restart/NAME.json`, an exited record), while it runs
//! or waits for its restart. The first full recovery after a boot (`gc::after_boot`) runs those it lost again,
//! and `always`'s stopped ones too (`Restart::after_boot`), from that record.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::app::Exited;
use crate::host::Host;
use crate::util::Result;

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn kept_dir(host: &Host) -> PathBuf {
    host.state.join("restart")
}

fn kept_path(host: &Host, name: &str) -> Result<PathBuf> {
    crate::host::check_name(name)?;
    Ok(kept_dir(host).join(format!("{name}.json")))
}

/// What runs `name` again after a reboot (`rec`, an exited record without its status), kept in the state directory.
pub fn keep(host: &Host, name: &str, rec: &Exited) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(kept_dir(host))?;
    crate::host::store_private(&kept_path(host, name)?, rec, true)
}

pub fn forget(host: &Host, name: &str) {
    if let Ok(p) = kept_path(host, name) {
        let _ = std::fs::remove_file(p);
    }
}

/// An exit of the app of `rec`'s VM, after it ran for `ran`: whether its policy runs it again, its record
/// then counting the restart and saying when (`restart_due`).
pub fn on_exit(rec: &mut Exited, ran: Duration) -> bool {
    let Some(r) = rec.spec.restart.as_mut() else { return false };
    match r.next(rec.status, ran) {
        Some(delay) => {
            rec.restart_due = Some(now_ms() + delay.as_millis() as u64);
            true
        }
        None => false,
    }
}

/// Leaves `restart-due NAME` behind, detached (it outlives the VM process that schedules it), its output to the
/// VM's log.
pub fn schedule(host: &Host, name: &str) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let log = match host.vms(name, "log").and_then(|p| Ok(std::fs::OpenOptions::new().append(true).custom_flags(libc::O_NOFOLLOW).open(p)?)) {
        Ok(f) => f,
        Err(_) => std::fs::OpenOptions::new().write(true).open("/dev/null")?,
    };
    let args = ["--state".as_ref(), host.state.as_os_str(), "--run".as_ref(), host.run.as_os_str(), "restart-due".as_ref(), "--".as_ref(), name.as_ref()];
    let null = std::fs::File::open("/dev/null")?;
    crate::util::spawn_self(&args, &log, null.as_raw_fd(), &[])?;
    Ok(())
}

/// The exited record of `name` whose restart is due at `due`, if it is still that one.
fn pending(host: &Host, name: &str) -> Option<Exited> {
    let rec = Exited::read(&host.vms(name, "exited").ok()?).ok()?;
    rec.restart_due.is_some().then_some(rec)
}

/// How long the process that scheduled a restart may take to let its name go.
const LET_GO: Duration = Duration::from_secs(60);

/// `restart-due NAME`: once the VM process that scheduled it is gone and its backoff is out, `start`s the exited
/// record (`start`, as `flexvm start NAME` does), if it is still the one whose restart is due. A start that fails
/// (its template removed, the host short of memory) is tried again later, its backoff doubled, for as long as
/// the record waits.
pub fn due(host: &Host, name: &str, start: impl Fn(&str) -> Result<()>) -> Result<()> {
    let until = Instant::now() + LET_GO;
    while host.alive(name) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut retry = crate::app::FIRST_BACKOFF;
    loop {
        let Some(rec) = pending(host, name) else { return Ok(()) };
        let at = rec.restart_due.unwrap_or(0);
        let wait = Duration::from_millis(at.saturating_sub(now_ms()));
        if !wait.is_zero() {
            std::thread::sleep(wait);
            continue;
        }
        // Another process holds the name (a start by hand, or a run of it): it is that one's now.
        if host.alive(name) {
            return Ok(());
        }
        crate::info!("vm {name}: restarting ({})", rec.spec.restart.as_ref().map(|r| format!("{r}, restart {}", r.count)).unwrap_or_default());
        match start(name) {
            Ok(()) => return Ok(()),
            Err(e) => {
                // Unless it was started, stopped, removed or run again meanwhile: then that is what holds.
                match pending(host, name) {
                    Some(mut r) if r.restart_due == Some(at) && !host.alive(name) => {
                        retry = (retry * 2).min(crate::app::MAX_BACKOFF);
                        crate::log!("vm {name}: restart failed: {e}; trying again in {} ms", retry.as_millis());
                        r.restart_due = Some(now_ms() + retry.as_millis() as u64);
                        crate::host::store_private(&host.vms(name, "exited")?, &r, true)?;
                    }
                    _ => return Ok(()),
                }
            }
        }
    }
}

/// `stop` of a VM whose restart is due: it is not run again (as docker's stop ends a restart loop), and is left
/// exited. False if none was due.
pub fn cancel(host: &Host, name: &str) -> Result<bool> {
    let Some(mut rec) = pending(host, name) else { return Ok(false) };
    rec.restart_due = None;
    crate::host::store_private(&host.vms(name, "exited")?, &rec, true)?;
    forget(host, name);
    Ok(true)
}

/// After a boot (the first full recovery): the VMs the reboot lost that their policies run again, from what
/// they kept (`keep`), as exited records whose restarts are due now; and `always`'s stopped ones, started.
/// Records of VMs no longer anywhere go.
pub fn after_boot(host: &Host) {
    stopped(host);
    for e in std::fs::read_dir(kept_dir(host)).into_iter().flatten().flatten() {
        let file = e.file_name().to_string_lossy().into_owned();
        let Some(name) = file.strip_suffix(".json").filter(|n| !n.starts_with('.')) else { continue };
        if let Err(err) = boot_one(host, name) {
            crate::log!("after boot: restarting vm {name}: {err}");
        }
    }
}

fn boot_one(host: &Host, name: &str) -> Result<()> {
    let mut rec: Exited = match crate::host::load(&kept_path(host, name)?)? {
        Some(r) => r,
        None => return Ok(()),
    };
    let Some(policy) = rec.spec.restart.clone() else {
        forget(host, name);
        return Ok(());
    };
    if host.alive(name) {
        return Ok(());
    }
    // Stopped since (its spec is its checkpoint's now): `stopped`'s.
    if host.is_suspended(name) {
        forget(host, name);
        return Ok(());
    }
    let lost = host.has_record(name, "lost");
    // An exited record (one written since the boot) is its own, as is a VM gone without a trace of it here.
    if !lost || !policy.after_boot(false) || host.has_record(name, "exited") {
        if !lost && !host.has_record(name, "exited") {
            forget(host, name);
        }
        return Ok(());
    }
    rec.status = crate::vmproc::DIED;
    rec.restart_due = Some(now_ms());
    rec.at = now_ms() / 1000;
    crate::host::store_private(&host.vms(name, "exited")?, &rec, true)?;
    // The loss is told by the restart now: its lost record would refuse the name to it.
    let _ = std::fs::remove_file(host.vms(name, "lost")?);
    schedule(host, name)
}

/// The VMs stopped by hand (on disk, which a reboot keeps) whose policy is `always`: started, as docker starts
/// them when its daemon does.
fn stopped(host: &Host) {
    for e in std::fs::read_dir(host.state.join("suspended")).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || !host.is_suspended(&name) || host.alive(&name) {
            continue;
        }
        let spec = crate::lifecycle::read_spec(&e.path()).ok();
        if spec.and_then(|s| s.restart).is_some_and(|r| r.after_boot(true)) {
            if let Err(err) = schedule_start(host, &name) {
                crate::log!("after boot: starting vm {name}: {err}");
            }
        }
    }
}

/// A stopped VM's start, from a worker of its own (it may take as long as a resume takes).
fn schedule_start(host: &Host, name: &str) -> Result<()> {
    use std::os::fd::AsRawFd;
    let args = ["--state".as_ref(), host.state.as_os_str(), "--run".as_ref(), host.run.as_os_str(), "start".as_ref(), "--".as_ref(), name.as_ref()];
    let null = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null")?;
    crate::util::spawn_self(&args, &null, null.as_raw_fd(), &[])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{Restart, RunSpec};

    fn rec(status: i32, restart: &str) -> Exited {
        Exited::new(status, "t".into(), None, Default::default(), RunSpec { restart: Restart::parse(restart).unwrap(), ..Default::default() }, 1)
    }

    #[test]
    fn an_exit_is_restarted_as_its_policy_says() {
        let mut r = rec(1, "on-failure:1");
        assert!(on_exit(&mut r, Duration::ZERO));
        let due = r.restart_due.unwrap();
        assert!(due >= now_ms() && due <= now_ms() + 100, "{due}");
        assert_eq!(r.spec.restart.as_ref().unwrap().count, 1);
        r.restart_due = None;
        assert!(!on_exit(&mut r, Duration::ZERO), "its one restart taken");
        assert!(!on_exit(&mut rec(0, "on-failure"), Duration::ZERO), "a success");
        assert!(on_exit(&mut rec(0, "always"), Duration::ZERO));
        assert!(!on_exit(&mut rec(3, "no"), Duration::ZERO));
    }

    #[test]
    fn a_due_restart_starts_its_record_once() {
        let dir = crate::test_util::TempDir::new("restart-due");
        let host = Host::open(&dir.join("state"), &dir.join("run")).unwrap();
        let mut r = rec(1, "always");
        assert!(on_exit(&mut r, Duration::ZERO));
        crate::host::store_private(&host.vms("job", "exited").unwrap(), &r, true).unwrap();
        let started = std::sync::Mutex::new(Vec::new());
        due(&host, "job", |n| {
            started.lock().unwrap().push(n.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(*started.lock().unwrap(), ["job"]);
        // A failed start is tried again, its record rescheduled; gone (removed meanwhile), nothing more.
        let tries = std::sync::atomic::AtomicUsize::new(0);
        due(&host, "job", |_| {
            if tries.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                return Err("no memory".into());
            }
            std::fs::remove_file(host.vms("job", "exited").unwrap()).unwrap();
            Err("no vm".into())
        })
        .unwrap();
        assert_eq!(tries.load(std::sync::atomic::Ordering::SeqCst), 2);
        // A stop meanwhile: no record whose restart is due, nothing to start.
        let mut r = rec(1, "always");
        assert!(on_exit(&mut r, Duration::ZERO));
        crate::host::store_private(&host.vms("job", "exited").unwrap(), &r, true).unwrap();
        assert!(cancel(&host, "job").unwrap() && !cancel(&host, "job").unwrap());
        due(&host, "job", |_| panic!("not due")).unwrap();
        assert_eq!(Exited::read(&host.vms("job", "exited").unwrap()).unwrap().restart_due, None, "left exited");
    }

    #[test]
    fn a_reboot_runs_again_what_it_lost() {
        let dir = crate::test_util::TempDir::new("restart-boot");
        let host = Host::open(&dir.join("state"), &dir.join("run")).unwrap();
        keep(&host, "gone", &rec(0, "always")).unwrap();
        keep(&host, "failing", &rec(0, "on-failure")).unwrap();
        keep(&host, "ended", &rec(0, "always")).unwrap();
        crate::host::store_private(&host.vms("ended", "exited").unwrap(), &rec(0, "always"), true).unwrap();
        // A name with nothing left of it here: its record goes. One that ended since: its record is its own.
        boot_one(&host, "gone").unwrap();
        boot_one(&host, "ended").unwrap();
        assert!(!kept_path(&host, "gone").unwrap().exists() && kept_path(&host, "ended").unwrap().exists());
        // Lost to the reboot (its worker not spawned here, so on-failure's, which restarts only a failure: as one).
        std::fs::write(host.vms("failing", "lost").unwrap(), "rebooted").unwrap();
        let r: Exited = crate::host::load(&kept_path(&host, "failing").unwrap()).unwrap().unwrap();
        assert!(r.spec.restart.as_ref().unwrap().after_boot(false), "a reboot's loss is no stop");
    }
}
