//! Requests that the VM processes release the memory they keep for their next checkpoint (#648, #677). It is not
//! admitted like a guest's, so before admission refuses a grant, or eviction or the standby pool reacts to the host
//! running short, every VM process lets its kept memory go and MemAvailable is read again: kept memory never causes a
//! refusal or an eviction then.
//!
//! A request is a number in `RUN/.locks/release-BOOT`, raised under the host lock; each VM process looks every
//! `POLL` and, once it has released, writes the number it answered to its own file in `RUN/.locks/released-BOOT/`
//! (named by its `Ident::key`). A requester waits for those that still run (not one stopped: it cannot answer), and
//! removes the files of those proven gone. Debits of what they released are not retired: they age out
//! (`Host::recent_debits`), so kept memory taken lately may count a little while longer. The room that memory grows
//! within is not here: each take is checked and debited under the host lock, and populated after it
//! (`Host::take_room`).
//!
//! VM processes started by a flexvm before #677 keep its mapped `memory-v2-BOOT` room, which neither sees these
//! takes nor answers these requests, and those started before #691 their own `room-debits-BOOT` ledger: after an
//! upgrade, restart or migrate them; until then the reserve may be overcommitted.

use crate::host::{load, locks, store, Host, Ident, Liveness};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long a release request waits for the VM processes to answer.
pub const RELEASE_WAIT: Duration = Duration::from_millis(200);

/// How long after a release request another one is not made: the memory kept went back then, and callers queued on
/// the host lock would each wait again.
const RELEASE_GAP_MS: u64 = 1000;

/// How often a VM process looks for a request: within `RELEASE_WAIT`, with time left to release. A look costs about
/// 6 us (and a wakeup): well under 1 ms of CPU a second per VM process.
const POLL: Duration = Duration::from_millis(100);

#[cfg(test)]
thread_local! {
    /// `RELEASE_WAIT` and `POLL` on this test's thread, once set (`pin_release`): a loaded machine can take longer
    /// than the real ones to schedule a serving thread.
    static PINNED: std::cell::Cell<(Option<Duration>, Option<Duration>)> = const { std::cell::Cell::new((None, None)) };
}

/// Sets, on this test's thread, how long a release request waits (`RELEASE_WAIT`) and how often `serve` looks (`POLL`).
#[cfg(test)]
pub(crate) fn pin_release(wait: Option<Duration>, poll: Option<Duration>) {
    PINNED.with(|p| p.set((wait, poll)));
}

fn release_wait() -> Duration {
    #[cfg(test)]
    if let Some(w) = PINNED.with(|p| p.get().0) {
        return w;
    }
    RELEASE_WAIT
}

fn poll() -> Duration {
    #[cfg(test)]
    if let Some(p) = PINNED.with(|p| p.get().1) {
        return p;
    }
    POLL
}

/// The last request: its number and when it started (boottime ms).
fn request(run: &Path) -> PathBuf {
    locks(run).join(format!("release-{}", crate::host::boot_id()))
}

/// Each answering process's file: the number of the last request it answered.
fn answers(run: &Path) -> PathBuf {
    locks(run).join(format!("released-{}", crate::host::boot_id()))
}

fn last(run: &Path) -> Option<(u64, u64)> {
    load(&request(run)).ok().flatten()
}

/// Answers release requests for the life of this process, calling `release` for each (one at a time). It joins as it
/// starts: requests made before have no kept memory of its to ask for, and none waits on it before it can answer.
/// Returns at once if it cannot join.
pub fn serve(run: &Path, release: impl Fn()) {
    let dir = answers(run);
    if let Err(e) = crate::host::private_dir(&dir) {
        crate::log!("hostmem: {}: {e}: memory kept for checkpoints is not released on request", dir.display());
        return;
    }
    // Its PID namespace in the name too (`ns_key`): another's of the same pid and start time is not it.
    let mine = dir.join(Ident::me().ns_key());
    let mut answered = last(run).map_or(0, |r| r.0);
    loop {
        if let Err(e) = store(&mine, &answered, false) {
            crate::log!("hostmem: {e}: requests do not wait for this process");
        }
        loop {
            std::thread::sleep(poll());
            // Unreadable: as no new request (the next one replaces it).
            if let Some((n, _)) = last(run).filter(|r| r.0 != answered) {
                release();
                answered = n;
                break;
            }
        }
    }
}

/// Asks every VM process of `host` to release the memory it keeps for its next checkpoint, and waits until each that
/// runs has, up to `RELEASE_WAIT` (or `deadline`, if sooner). Reuses a request made within `RELEASE_GAP_MS`.
/// For a caller that checks again on its next tick (a VM's controller, a standby): it waits for the host lock up to
/// `deadline`, or `RELEASE_WAIT` without one, so a stuck lock holder never holds its tick up.
/// Callers read MemAvailable again after it whatever it found: some may have answered.
pub fn release_kept(host: &Host, deadline: Option<Instant>) {
    release(host, Some(deadline.unwrap_or_else(|| Instant::now() + release_wait())), deadline);
}

/// `release_kept` for admission, before it refuses a grant: it waits for the host lock as admission itself does, up
/// to `deadline` (without one, until it has it), so lock contention alone never refuses a grant (#1081). The
/// response wait starts after taking the lock.
pub fn release_kept_admitting(host: &Host, deadline: Option<Instant>) {
    release(host, deadline, deadline);
}

fn release(host: &Host, lock: Option<Instant>, deadline: Option<Instant>) {
    if let Some((n, by)) = ask(host, lock, deadline) {
        wait(&host.run, n, by);
    }
}

/// Raises the request's number under the host lock (waited for up to `lock`, if any), or returns the existing number
/// within `RELEASE_GAP_MS` with its remaining wait, so joining callers share its deadline. None if the lock or write fails.
fn ask(host: &Host, lock: Option<Instant>, deadline: Option<Instant>) -> Option<(u64, Instant)> {
    let _l = host.lock_by(lock).ok()?;
    let (n, at) = last(&host.run).unwrap_or_default();
    let when = Instant::now();
    let now = crate::host::boottime_ms();
    // A fresh request gets a full poll interval plus time to release, even after waiting for the lock.
    let by = deadline.map_or(when + release_wait(), |d| d.min(when + release_wait()));
    let until = |at| {
        let left = release_wait().saturating_sub(Duration::from_millis(now.wrapping_sub(at)));
        by.min(when + left)
    };
    if at != 0 && now.wrapping_sub(at) < RELEASE_GAP_MS {
        return Some((n, until(at)));
    }
    let path = request(&host.run);
    match crate::host::private_dir(&locks(&host.run)).map_err(Into::into).and_then(|()| store(&path, &(n + 1, now), false)) {
        Ok(()) => Some((n + 1, until(now))),
        Err(e) => {
            crate::log!("hostmem: cannot ask for kept memory back: {e}");
            None
        }
    }
}

/// Waits until every process that answers requests has answered `n` or a later one, or `by`. Not for one stopped (it
/// cannot answer); the files of those proven gone are removed. Whether every one answered.
fn wait(run: &Path, n: u64, by: Instant) -> bool {
    let Ok(entries) = std::fs::read_dir(answers(run)) else { return true };
    let mut members = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(id) = Ident::from_key(&name) {
            members.push((e.path(), id));
        }
    }
    let mut all = true;
    loop {
        members.retain(|(path, id)| {
            if load::<u64>(path).ok().flatten().is_some_and(|a| a >= n) {
                return false;
            }
            match id.liveness() {
                Liveness::Gone => {
                    let _ = std::fs::remove_file(path);
                    false
                }
                // By its pid here: one of another PID namespace has another (`local_pid`).
                Liveness::Alive if id.local_pid().ok().flatten().is_some_and(stopped) => {
                    all = false;
                    false
                }
                _ => true,
            }
        });
        if members.is_empty() {
            break;
        }
        let left = by.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        std::thread::sleep(left.min(Duration::from_millis(10)));
    }
    all
}

/// Whether `pid` is stopped (or traced): it cannot answer then.
fn stopped(pid: u32) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    stat.rsplit_once(')').is_some_and(|(_, rest)| rest.trim_start().starts_with(['T', 't']))
}

#[cfg(test)]
pub(crate) fn forget_release(run: &Path) {
    let (n, _) = last(run).unwrap_or_default();
    store(&request(run), &(n, 0u64), false).unwrap();
}

#[cfg(test)]
pub(crate) fn joined(run: &Path) -> bool {
    answers(run).join(Ident::me().ns_key()).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn member(run: &Path, id: &Ident, answered: u64) {
        crate::host::private_dir(&answers(run)).unwrap();
        store(&answers(run).join(id.ns_key()), &answered, false).unwrap();
    }

    #[test]
    fn a_release_request_waits_for_every_member_to_release() {
        let (dir, h) = crate::host::tests::host("hostmem");
        let run = h.run.clone();
        crate::host::pin_clock(crate::host::boottime_ms());
        // Long: other tests hold the host lock (one for the process) for a while on a loaded machine.
        let now = || Instant::now() + Duration::from_secs(30);
        // Nobody to ask: answered at once.
        let n = ask(&h, Some(now()), Some(now())).unwrap().0;
        let t = Instant::now();
        assert!(wait(&run, n, now()));
        assert!(t.elapsed() < Duration::from_secs(1));
        let released = Arc::new(AtomicUsize::new(0));
        let (r, served) = (released.clone(), run.clone());
        std::thread::spawn(move || {
            serve(&served, || {
                std::thread::sleep(Duration::from_millis(20));
                r.fetch_add(1, Ordering::SeqCst);
            })
        });
        let t = Instant::now();
        while !joined(&run) {
            assert!(t.elapsed() < Duration::from_secs(5), "joined");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(released.load(Ordering::SeqCst), 0, "a request made before it joined is not its");
        // Waits for the release (a poll and 20 ms), not for the deadline.
        forget_release(&run);
        let n = ask(&h, Some(now()), Some(now())).unwrap().0;
        let repeated = ask(&h, Some(now()), Some(now())).expect("a caller within the gap must still wait for outstanding answers").0;
        assert_eq!(repeated, n);
        let t = Instant::now();
        assert!(wait(&run, repeated, Instant::now() + Duration::from_secs(10)));
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        assert_eq!(released.load(Ordering::SeqCst), 1);
        // Within a second of the last: reuse the answered request without asking again.
        assert_eq!(ask(&h, Some(now()), Some(now())).map(|r| r.0), Some(n));
        forget_release(&run);
        let n = ask(&h, Some(now()), Some(now())).unwrap().0;
        assert!(wait(&run, n, now()));
        assert_eq!(released.load(Ordering::SeqCst), 2);
        // A member that runs and does not answer: given up on at the deadline, and it stays a member.
        let mut child = crate::test_util::ChildGuard(std::process::Command::new("sleep").arg("30").spawn().unwrap());
        let pid = child.id();
        let silent = Ident::of(pid).unwrap();
        member(&run, &silent, 0);
        forget_release(&run);
        let n = ask(&h, Some(now()), Some(now())).unwrap().0;
        let t = Instant::now();
        assert!(!wait(&run, n, Instant::now() + Duration::from_millis(50)), "the silent one did not answer");
        assert!(t.elapsed() < Duration::from_secs(2));
        assert!(answers(&run).join(silent.ns_key()).exists());
        // Stopped: it cannot answer, so it is not waited for (but it stays a member).
        unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
        let t = Instant::now();
        while !stopped(pid) {
            assert!(t.elapsed() < Duration::from_secs(5), "stopped");
            std::thread::sleep(Duration::from_millis(1));
        }
        let t = Instant::now();
        assert!(!wait(&run, n, now()), "not every one answered");
        assert!(t.elapsed() < Duration::from_secs(1), "not waited for");
        assert!(answers(&run).join(silent.ns_key()).exists());
        // Gone: not waited for, and its file removed. Its pid may be another's by now: still gone (its start differs).
        let _ = child.kill();
        let _ = child.wait();
        let gone = Ident { pid: (1 << 22) - 2, start: 1, boot: silent.boot.clone(), ns: None };
        member(&run, &gone, 0);
        let t = Instant::now();
        assert!(wait(&run, n, now()));
        assert!(t.elapsed() < Duration::from_secs(1));
        assert!(!answers(&run).join(gone.ns_key()).exists() && !answers(&run).join(silent.ns_key()).exists(), "pruned");
        drop(dir);
    }

    #[test]
    fn a_fresh_request_without_a_deadline_gets_its_wait_after_the_host_lock() {
        let (_dir, h) = crate::host::tests::host("hostmem-lock-wait");
        let lock = h.lock().unwrap();
        let other = h.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            tx.send(()).unwrap();
            ask(&other, None, None).unwrap()
        });
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        std::thread::sleep(RELEASE_WAIT + POLL);
        let before = crate::host::boottime_ms();
        let when = Instant::now();
        drop(lock);
        let (_, by) = waiter.join().unwrap();
        assert!(last(&h.run).unwrap().1 >= before, "stamped after taking the lock");
        assert!(by >= when + RELEASE_WAIT, "lock contention does not consume the release wait");
        assert!(RELEASE_WAIT >= POLL + Duration::from_millis(50));
    }

    #[test]
    fn the_callers_deadline_bounds_the_host_lock_wait() {
        let (_dir, h) = crate::host::tests::host("hostmem-lock-deadline");
        let _lock = h.lock().unwrap();
        let other = h.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let by = Some(Instant::now() + RELEASE_WAIT);
            tx.send(ask(&other, by, by)).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap().is_none());
        waiter.join().unwrap();
        assert_eq!(last(&h.run), None, "no request made after the caller gave up");
    }

    #[test]
    fn a_tick_without_a_deadline_gives_up_on_a_held_host_lock() {
        let (_dir, h) = crate::host::tests::host("hostmem-lock-tick");
        let _lock = h.lock().unwrap();
        let other = h.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            release_kept(&other, None);
            tx.send(()).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(5)).expect("a controller's tick is not held up by the host lock");
        waiter.join().unwrap();
        assert_eq!(last(&h.run), None, "no request made after it gave up");
    }

    #[test]
    fn requests_within_the_gap_reuse_the_outstanding_number() {
        let (_dir, h) = crate::host::tests::host("hostmem-gap");
        let by = Instant::now() + Duration::from_secs(30);
        let at = 10_000;
        crate::host::pin_clock(at);
        member(&h.run, &Ident::me(), 0);
        let n = ask(&h, Some(by), Some(by)).unwrap().0;
        crate::host::pin_clock(at + RELEASE_GAP_MS - 1);
        assert_eq!(ask(&h, Some(by), Some(by)).map(|r| r.0), Some(n));
        assert_eq!(last(&h.run), Some((n, at)), "reusing a request does not extend its gap");
        assert!(!wait(&h.run, n, Instant::now()), "the outstanding answer is still required");
        member(&h.run, &Ident::me(), n);
        assert!(wait(&h.run, ask(&h, Some(by), Some(by)).unwrap().0, by));
        crate::host::pin_clock(at + RELEASE_GAP_MS);
        assert_eq!(ask(&h, Some(by), Some(by)).map(|r| r.0), Some(n + 1), "a fresh request at the gap boundary");
    }

    #[test]
    fn joining_a_request_shares_its_remaining_wait() {
        let (_dir, h) = crate::host::tests::host("hostmem-deadline");
        let at = 10_000;
        crate::host::pin_clock(at);
        let by = Instant::now() + Duration::from_secs(30);
        let (n, first) = ask(&h, Some(by), Some(by)).unwrap();
        assert!(first <= Instant::now() + RELEASE_WAIT);
        crate::host::pin_clock(at + 150);
        let before = Instant::now();
        let (same, shared) = ask(&h, Some(by), Some(by)).unwrap();
        assert_eq!(same, n);
        assert!(shared >= before + Duration::from_millis(50));
        assert!(shared <= Instant::now() + Duration::from_millis(50));
        crate::host::pin_clock(at + 200);
        let (same, expired) = ask(&h, Some(by), Some(by)).unwrap();
        assert_eq!(same, n);
        assert!(expired <= Instant::now(), "joining an expired request does not wait again");
        crate::host::pin_clock(at + 100);
        pin_release(Some(Duration::from_secs(30)), None);
        let sooner = Instant::now() + Duration::from_secs(10);
        assert_eq!(ask(&h, Some(sooner), Some(sooner)).unwrap().1, sooner);
    }

    /// A request's number only grows (it is raised under the host lock), so an answer to a later one answers it too.
    #[test]
    fn requests_are_numbered_in_order() {
        // Keep request and answer files private to this test, including when hostmem tests run in parallel.
        let (_dir, h) = crate::host::tests::host("hostmem-order");
        let by = Instant::now() + Duration::from_secs(30);
        let at = 10_000;
        crate::host::pin_clock(at);
        let a = ask(&h, Some(by), Some(by)).unwrap().0;
        crate::host::pin_clock(at + RELEASE_GAP_MS);
        let b = ask(&h, Some(by), Some(by)).unwrap().0;
        assert_eq!(b, a + 1);
        member(&h.run, &Ident::me(), b);
        assert!(wait(&h.run, a, Instant::now()), "a later answer answers it without waiting");
    }
}
