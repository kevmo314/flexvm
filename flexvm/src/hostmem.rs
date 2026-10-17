//! Requests that the VM processes release the memory they keep for their next checkpoint (#648, #677). It is not
//! admitted like a guest's, so before admission refuses a grant, or eviction or the standby pool reacts to the host
//! running short, every VM process lets its kept memory go and MemAvailable is read again: kept memory never causes a
//! refusal or an eviction then.
//!
//! A request is a number in `RUN/.locks/release-BOOT`, raised under the host lock; each VM process looks every
//! `POLL` and, once it has released, writes the number it answered to its own file in `RUN/.locks/released-BOOT/`
//! (named by its `Ident::key`), with when it released and whether no copy was running then. A requester waits for
//! those that still run (not one stopped: it cannot answer), and removes the files of those proven gone. Then it
//! retires the debits of each that had no copy running (`Host::retire_debits`, #691): what they covered is unmapped.
//! The room that memory grows within is not here: each take is checked and debited under the host lock, and
//! populated after it (`Host::take_room`).

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

/// How long a requester whose wait used its deadline may still wait for the host lock to retire debits.
const RETIRE_WAIT: Duration = Duration::from_millis(50);

/// How often a VM process looks for a request: within `RELEASE_WAIT`, with time left to release. A look costs about
/// 6 us (and a wakeup): well under 1 ms of CPU a second per VM process.
const POLL: Duration = Duration::from_millis(100);

/// A process's answer: the number of the request, when it released (boottime ms), and whether no copy was running
/// then (all it took from the room was unmapped, or is with its copy gone).
type Answer = (u64, u64, bool);

/// The last request: its number and when it was made (boottime ms).
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

/// Answers release requests for the life of this process, calling `release` for each (one at a time), which says
/// whether no copy was running. It joins as it starts: requests made before have no kept memory of its to ask for,
/// and none waits on it before it can answer. Returns at once if it cannot join.
pub fn serve(run: &Path, release: impl Fn() -> bool) {
    let dir = answers(run);
    if let Err(e) = crate::host::private_dir(&dir) {
        crate::log!("hostmem: {}: {e}: memory kept for checkpoints is not released on request", dir.display());
        return;
    }
    let mine = dir.join(Ident::me().key());
    let mut answered: Answer = (last(run).map_or(0, |r| r.0), 0, false);
    loop {
        if let Err(e) = store(&mine, &answered, false) {
            crate::log!("hostmem: {e}: requests do not wait for this process");
        }
        loop {
            std::thread::sleep(POLL);
            // Unreadable: as no new request (the next one replaces it).
            if let Some((n, _)) = last(run).filter(|r| r.0 != answered.0) {
                let at = crate::host::boottime_ms();
                answered = (n, at, release());
                break;
            }
        }
    }
}

/// Asks every VM process of `host` to release the memory it keeps for its next checkpoint, and waits until each that
/// runs has, up to `RELEASE_WAIT` (or `deadline`, if sooner); not if a request was made within `RELEASE_GAP_MS`.
/// Callers read MemAvailable again after it whatever it found: some may have answered.
pub fn release_kept(host: &Host, deadline: Option<Instant>) {
    let by = Instant::now() + RELEASE_WAIT;
    let by = deadline.map_or(by, |d| d.min(by));
    if let Some(n) = ask(host, by) {
        let (_, released) = wait(&host.run, n, by);
        host.retire_debits(&released, by.max(Instant::now() + RETIRE_WAIT));
    }
}

/// Raises the request's number, under the host lock (each request's is new): None if one was made within
/// `RELEASE_GAP_MS`, or it cannot be.
fn ask(host: &Host, by: Instant) -> Option<u64> {
    let _l = host.lock_by(Some(by)).ok()?;
    let (n, at) = last(&host.run).unwrap_or_default();
    let now = crate::host::boottime_ms();
    if at != 0 && now.wrapping_sub(at) < RELEASE_GAP_MS {
        return None;
    }
    let path = request(&host.run);
    match crate::host::private_dir(&locks(&host.run)).map_err(Into::into).and_then(|()| store(&path, &(n + 1, now), false)) {
        Ok(()) => Some(n + 1),
        Err(e) => {
            crate::log!("hostmem: cannot ask for kept memory back: {e}");
            None
        }
    }
}

/// Waits until every process that answers requests has answered `n` or a later one, or `by`. Not for one stopped (it
/// cannot answer); the files of those proven gone are removed. Whether every one answered, and those that had no copy
/// running, with when they released.
fn wait(run: &Path, n: u64, by: Instant) -> (bool, Vec<(Ident, u64)>) {
    let Ok(entries) = std::fs::read_dir(answers(run)) else { return (true, Vec::new()) };
    let (mut all, mut released) = (true, Vec::new());
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(id) =
            name.split_once('-').and_then(|(p, s)| Some(Ident { pid: p.parse().ok()?, start: s.parse().ok()?, boot: crate::host::boot_id().into() }))
        else {
            continue;
        };
        loop {
            if let Some((_, at, idle)) = load::<Answer>(&e.path()).ok().flatten().filter(|a| a.0 >= n) {
                if idle {
                    released.push((id.clone(), at));
                }
                break;
            }
            match id.liveness() {
                Liveness::Gone => {
                    let _ = std::fs::remove_file(e.path());
                    break;
                }
                Liveness::Alive if stopped(id.pid) => {
                    all = false;
                    break;
                }
                _ if Instant::now() >= by => {
                    all = false;
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    }
    (all, released)
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
    answers(run).join(Ident::me().key()).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn member(run: &Path, id: &Ident, answered: u64) {
        crate::host::private_dir(&answers(run)).unwrap();
        store(&answers(run).join(id.key()), &(answered, 0u64, false), false).unwrap();
    }

    #[test]
    fn a_release_request_waits_for_every_member_to_release() {
        let (dir, h) = crate::host::tests::host("hostmem");
        let run = h.run.clone();
        crate::host::pin_clock(crate::host::boottime_ms());
        // Long: other tests hold the host lock (one for the process) for a while on a loaded machine.
        let now = || Instant::now() + Duration::from_secs(30);
        // Nobody to ask: answered at once.
        let n = ask(&h, now()).unwrap();
        let t = Instant::now();
        assert!(wait(&run, n, now()).0);
        assert!(t.elapsed() < Duration::from_secs(1));
        let released = Arc::new(AtomicUsize::new(0));
        let (r, served) = (released.clone(), run.clone());
        std::thread::spawn(move || {
            serve(&served, || {
                std::thread::sleep(Duration::from_millis(20));
                r.fetch_add(1, Ordering::SeqCst);
                false
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
        let n = ask(&h, now()).unwrap();
        let t = Instant::now();
        assert!(wait(&run, n, Instant::now() + Duration::from_secs(10)).0);
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        assert_eq!(released.load(Ordering::SeqCst), 1);
        // Within a second of the last: not asked again.
        assert_eq!(ask(&h, now()), None);
        forget_release(&run);
        let n = ask(&h, now()).unwrap();
        assert!(wait(&run, n, now()).0);
        assert_eq!(released.load(Ordering::SeqCst), 2);
        // A member that runs and does not answer: given up on at the deadline, and it stays a member.
        let mut child = crate::test_util::ChildGuard(std::process::Command::new("sleep").arg("30").spawn().unwrap());
        let pid = child.id();
        let silent = Ident::of(pid).unwrap();
        member(&run, &silent, 0);
        forget_release(&run);
        let n = ask(&h, now()).unwrap();
        let t = Instant::now();
        assert!(!wait(&run, n, Instant::now() + Duration::from_millis(50)).0, "the silent one did not answer");
        assert!(t.elapsed() < Duration::from_secs(2));
        assert!(answers(&run).join(silent.key()).exists());
        // Stopped: it cannot answer, so it is not waited for (but it stays a member).
        unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
        let t = Instant::now();
        while !stopped(pid) {
            assert!(t.elapsed() < Duration::from_secs(5), "stopped");
            std::thread::sleep(Duration::from_millis(1));
        }
        let t = Instant::now();
        assert!(!wait(&run, n, now()).0, "not every one answered");
        assert!(t.elapsed() < Duration::from_secs(1), "not waited for");
        assert!(answers(&run).join(silent.key()).exists());
        // Gone: not waited for, and its file removed. Its pid may be another's by now: still gone (its start differs).
        let _ = child.kill();
        let _ = child.wait();
        let gone = Ident { pid: (1 << 22) - 2, start: 1, boot: silent.boot.clone() };
        member(&run, &gone, 0);
        let t = Instant::now();
        assert!(wait(&run, n, now()).0);
        assert!(t.elapsed() < Duration::from_secs(1));
        assert!(!answers(&run).join(gone.key()).exists() && !answers(&run).join(silent.key()).exists(), "pruned");
        drop(dir);
    }

    /// A request's number only grows (it is raised under the host lock), so an answer to a later one answers it too.
    #[test]
    fn requests_are_numbered_in_order() {
        let (_dir, h) = crate::host::tests::host("hostmem-order");
        let by = Instant::now() + Duration::from_secs(5);
        let a = ask(&h, by).unwrap();
        forget_release(&h.run);
        let b = ask(&h, by).unwrap();
        assert_eq!(b, a + 1);
        member(&h.run, &Ident::me(), b);
        assert!(wait(&h.run, a, by).0, "a later answer answers it");
    }
}
