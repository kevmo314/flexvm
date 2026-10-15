//! A VM's host memory limit: `memory.high` on its Firecracker's cgroup, at
//! the memory admitted for it against the host's reserve plus Firecracker's
//! own overhead. Plugged memory costs nothing until the guest touches it, so
//! the admitted size grows with use, a step at a time, each step admitted
//! first; a guest the host refuses is throttled at its mark (never killed:
//! `memory.high`, not `memory.max`) and counts as starved, so the host moves
//! it. It never exceeds the guest's own size (boot memory plus plugged): past
//! that the guest has to grow, raising it first, or reclaim.
//!
//! The pager's installs (UFFDIO_COPY) are charged to this cgroup but made by
//! the VM process, whose own cgroup the kernel throttles them by, so a pull
//! or a checkpoint's copy never waits on this mark. Firecracker's own threads
//! do: a migration or checkpoint lifts the mark while it pauses the VM.
//!
//! Starts are admitted here too (`allowance`): what the VM brings or pages
//! in, and a step. `mark` is a leaf lock, never held across admission (the
//! host lock), which callers may hold around `restore`.

use std::io::{Read, Seek};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::host::Host;
use crate::template::STEP_MIB;

/// How long `lift` waits for throttled threads: the kernel's longest
/// throttling sleep (2 s) and some.
const THROTTLE_MAX: Duration = Duration::from_millis(2500);

/// Firecracker's own memory (VMM, KVM page tables, page cache it reads) on
/// top of the guest's.
fn overhead(mib: u64) -> u64 {
    64 + mib / 64
}

/// What a VM starting with `need` MiB in it, or still to page in, is admitted.
pub fn allowance(need: u64) -> u64 {
    need + step(need)
}

/// How much more is admitted at a time: a quarter of what the VM has, 256 MiB to 2 GiB.
fn step(mib: u64) -> u64 {
    (mib / 4).clamp(256, 2048).div_ceil(STEP_MIB) * STEP_MIB
}

#[derive(Default)]
struct Mark {
    /// MiB; 0 until the VM starts.
    admitted: u64,
    /// The guest's size: boot memory plus plugged.
    cap: u64,
    /// While a migration or checkpoint pauses the VM.
    lifted: bool,
}

pub struct Limit {
    cgroup: Option<PathBuf>,
    mark: Mutex<Mark>,
    /// Throttled: at its mark and refused more.
    pub throttled: AtomicBool,
}

impl Limit {
    pub fn new(cgroup: Option<PathBuf>) -> Limit {
        Limit { cgroup, mark: Mutex::new(Mark::default()), throttled: AtomicBool::new(false) }
    }

    /// MiB charged to the VM's cgroup.
    pub fn used(&self) -> Option<u64> {
        let cg = self.cgroup.as_ref()?;
        Some(std::fs::read_to_string(cg.join("memory.current")).ok()?.trim().parse::<u64>().ok()? >> 20)
    }

    pub fn admitted(&self) -> u64 {
        self.mark.lock().unwrap().admitted
    }

    fn write(&self, m: &Mark) {
        let Some(cg) = &self.cgroup else { return };
        let high = match m.lifted || m.admitted == 0 {
            true => "max".to_string(),
            false => ((m.admitted + overhead(m.admitted)) << 20).to_string(),
        };
        if let Err(e) = std::fs::write(cg.join("memory.high"), high) {
            crate::log!("{}: setting memory.high: {e}", cg.display());
        }
    }

    /// Once the VM runs here: what its start was admitted (MiB), up to the
    /// guest's size. Above it from the start, the VM is throttled until a
    /// step is admitted. The cgroup may still be being made (`Spawner::take`).
    pub fn start(&self, admitted: u64, cap: u64) {
        let Some(cg) = &self.cgroup else { return };
        let made = Instant::now();
        while !cg.join("memory.high").exists() && made.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut m = self.mark.lock().unwrap();
        m.cap = cap;
        m.admitted = admitted.min(cap);
        self.write(&m);
    }

    /// Usage within half a step of the mark: admit a step and raise it.
    /// False if the host refused (the VM stays throttled).
    pub fn grow(&self, host: &Host) -> bool {
        let Some(used) = self.used() else { return true };
        let more = {
            let m = self.mark.lock().unwrap();
            let s = step(m.admitted);
            match m.lifted || m.admitted == 0 || m.admitted >= m.cap || used + s / 2 < m.admitted + overhead(m.admitted) {
                true => 0,
                false => (m.admitted + s).min(m.cap) - m.admitted,
            }
        };
        if more == 0 {
            self.throttled.store(false, Ordering::SeqCst);
            return true;
        }
        // Admitted without `mark` held; another raise meanwhile only adds to it.
        // An error is no refusal: the mark stays, and the VM is not throttled for it.
        let id = match host.grant(more, None) {
            Ok(Some(id)) => id,
            Ok(None) => {
                self.throttled.store(true, Ordering::SeqCst);
                return false;
            }
            Err(e) => {
                crate::log!("admitting {more} MiB: {e}");
                return false;
            }
        };
        let mut m = self.mark.lock().unwrap();
        // Lifted meanwhile (a migration or checkpoint pauses it): nothing to raise, the grant goes back.
        if m.lifted {
            drop(m);
            host.refund(id);
            return true;
        }
        m.admitted = (m.admitted + more).min(m.cap.max(m.admitted));
        self.write(&m);
        drop(m);
        self.throttled.store(false, Ordering::SeqCst);
        true
    }

    /// Before a grow to `cap` MiB, of which `charge` was admitted.
    pub fn plug(&self, cap: u64, charge: u64) {
        let mut m = self.mark.lock().unwrap();
        m.cap = m.cap.max(cap);
        if m.admitted > 0 {
            m.admitted = (m.admitted + charge).min(m.cap);
            self.write(&m);
        }
    }

    /// Once a shrink to `cap` MiB settled: never below what the VM uses, so
    /// lowering it never makes the kernel reclaim.
    pub fn settled(&self, cap: u64) {
        let used = self.used();
        let mut m = self.mark.lock().unwrap();
        m.cap = cap;
        let floor = used.map_or(cap, |u| u.saturating_sub(overhead(u)) + STEP_MIB);
        let new = m.admitted.min(cap.max(floor));
        if new < m.admitted {
            m.admitted = new;
            self.write(&m);
        }
    }

    /// Off until the guard goes (or `restore`): Firecracker's threads
    /// throttled at the mark would hold up the pause and the snapshot. A
    /// thread already throttled sleeps on (up to 2 s): waited for here (up
    /// to `THROTTLE_MAX`, 2.5 s), so the pause does not.
    pub fn lift(&self, firecracker: Option<u32>) -> Lifted<'_> {
        let mut m = self.mark.lock().unwrap();
        m.lifted = true;
        self.write(&m);
        drop(m);
        let throttled = |pid: u32| {
            let tasks = std::fs::read_dir(format!("/proc/{pid}/task")).into_iter().flatten().flatten();
            tasks.into_iter().any(|t| std::fs::read_to_string(t.path().join("wchan")).is_ok_and(|w| w.contains("handle_over_high")))
        };
        let since = Instant::now();
        while firecracker.is_some_and(throttled) && since.elapsed() < THROTTLE_MAX {
            std::thread::sleep(Duration::from_millis(5));
        }
        Lifted(self)
    }

    pub fn restore(&self) {
        let mut m = self.mark.lock().unwrap();
        if std::mem::take(&mut m.lifted) {
            self.write(&m);
        }
    }

    /// Raises the mark as the VM nears it, at once (the cgroup's `high`
    /// events) or within `tick`, while `live`; only while `running` (not
    /// throttled otherwise: nothing is asked for it).
    pub fn watch(&self, host: &Host, tick: Duration, live: impl Fn() -> bool, running: impl Fn() -> bool) {
        let Some(cg) = &self.cgroup else { return };
        let mut events = std::fs::File::open(cg.join("memory.events")).ok();
        while live() {
            wait_event(events.as_mut(), tick);
            if !running() {
                self.throttled.store(false, Ordering::SeqCst);
                std::thread::sleep(tick);
                continue;
            }
            // Throttling raises an event every 10 ms; refused, no use asking again at each.
            std::thread::sleep(if self.grow(host) { Duration::from_millis(20) } else { tick });
        }
    }
}

/// Waits until the cgroup file changes (POLLPRI) or `tick` passes.
fn wait_event(f: Option<&mut std::fs::File>, tick: Duration) {
    let Some(f) = f else { return std::thread::sleep(tick) };
    // Reading it rearms the notification.
    let mut buf = String::new();
    let _ = f.rewind().and_then(|()| f.read_to_string(&mut buf));
    let mut pfd = libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLPRI, revents: 0 };
    unsafe { libc::poll(&mut pfd, 1, tick.as_millis() as i32) };
}

pub struct Lifted<'a>(&'a Limit);

impl Drop for Lifted<'_> {
    fn drop(&mut self) {
        self.0.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A cgroup's memory files in a plain directory.
    fn cgroup(tag: &str) -> (Limit, PathBuf, Host) {
        let base = std::env::temp_dir().join(format!("flexvm-limit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cg = base.join("cg");
        std::fs::create_dir_all(&cg).unwrap();
        for f in ["memory.high", "memory.events"] {
            std::fs::write(cg.join(f), "max\n").unwrap();
        }
        let mut host = Host::open(&base.join("state"), &base.join("run")).unwrap();
        host.cfg.reserve_mib = 0;
        (Limit::new(Some(cg.clone())), cg, host)
    }

    fn set(cg: &Path, used_mib: u64) {
        std::fs::write(cg.join("memory.current"), format!("{}\n", used_mib << 20)).unwrap();
    }

    fn high(cg: &Path) -> Option<u64> {
        std::fs::read_to_string(cg.join("memory.high")).unwrap().trim().parse::<u64>().ok().map(|b| b >> 20)
    }

    #[test]
    fn the_mark_follows_admitted_memory() {
        let (l, cg, mut host) = cgroup("follow");
        set(&cg, 20);
        // What it holds and still pages in, and a step.
        l.start(allowance(100), 1000);
        assert_eq!((l.admitted(), high(&cg)), (100 + 256, Some(356 + overhead(356))));
        // Far from the mark: nothing; near it, a step more.
        assert!(l.grow(&host) && l.admitted() == 356);
        set(&cg, 356 + overhead(356) - 100);
        assert!(l.grow(&host) && l.admitted() == 612);
        // Refused: stays, throttled.
        set(&cg, 612 + overhead(612));
        host.cfg.reserve_mib = u64::MAX / 4;
        assert!(!l.grow(&host) && l.admitted() == 612 && l.throttled.load(Ordering::SeqCst));
        host.cfg.reserve_mib = 0;
        assert!(l.grow(&host) && l.admitted() == 868 && !l.throttled.load(Ordering::SeqCst));
        // Never past the guest's size; a plug raises both by what it was charged.
        set(&cg, 2000);
        assert!(l.grow(&host) && l.admitted() == 1000);
        l.plug(3000, 512);
        assert_eq!((l.admitted(), high(&cg)), (1512, Some(1512 + overhead(1512))));
        // A settled shrink lowers it, never below what is in use.
        set(&cg, 900);
        l.settled(1200);
        assert_eq!(l.admitted(), 1200);
        l.settled(500);
        assert_eq!(l.admitted(), 900 - overhead(900) + STEP_MIB);
        // Lifted while a migration or checkpoint pauses the VM, then back.
        let lifted = l.lift(None);
        assert_eq!(high(&cg), None);
        // Nothing is admitted for it meanwhile (no phantom grant), nor is it throttled.
        let was = l.admitted();
        set(&cg, was + overhead(was));
        host.cfg.reserve_mib = u64::MAX / 4;
        assert!(l.grow(&host) && l.admitted() == was && !l.throttled.load(Ordering::SeqCst));
        host.cfg.reserve_mib = 0;
        drop(lifted);
        assert_eq!(high(&cg), Some(l.admitted() + overhead(l.admitted())));
    }

    /// A migration's rollback holds the host lock while it resumes the VM
    /// (`restore`); the watcher admitting meanwhile must not hold `mark`.
    #[test]
    fn admission_never_holds_the_mark() {
        let (l, cg, host) = cgroup("order");
        l.start(512, 5000);
        set(&cg, 512 + overhead(512));
        let held = host.lock().unwrap();
        let (l, host) = (&l, &host);
        std::thread::scope(|sc| {
            let grower = sc.spawn(|| l.grow(host));
            std::thread::sleep(Duration::from_millis(100));
            let (tx, rx) = std::sync::mpsc::channel();
            sc.spawn(move || {
                let lifted = l.lift(None);
                drop(lifted);
                let _ = tx.send(());
            });
            assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok(), "restore waited for admission");
            drop(held);
            assert!(grower.join().unwrap());
        });
        assert_eq!(l.admitted(), 512 + step(512));
    }

    /// Lifted while the watcher's admission waits: nothing is raised, and the grant goes back.
    #[test]
    fn a_mark_lifted_during_admission_is_not_raised() {
        let (l, cg, host) = cgroup("lifted");
        l.start(512, 5000);
        set(&cg, 512 + overhead(512));
        let held = host.lock().unwrap();
        let (l, host) = (&l, &host);
        std::thread::scope(|sc| {
            let grower = sc.spawn(|| l.grow(host));
            std::thread::sleep(Duration::from_millis(100));
            let lifted = l.lift(None);
            drop(held);
            assert!(grower.join().unwrap());
            assert_eq!(l.admitted(), 512);
            let grants: Vec<(u64, u64, u64)> = crate::host::load(&host.grants()).unwrap().unwrap_or_default();
            assert!(grants.is_empty(), "{grants:?}");
            drop(lifted);
        });
        assert_eq!(high(&cg), Some(512 + overhead(512)));
    }

    #[test]
    fn steps_scale_with_the_vm() {
        assert_eq!((step(0), step(1024), step(4096), step(100_000)), (256, 256, 1024, 2048));
        assert_eq!(step(1500), 384);
    }
}
