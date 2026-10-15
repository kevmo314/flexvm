//! Copy-on-write capture of a running VM's memory for a checkpoint.
//!
//! The VM is paused only to save its vCPU and device state and to arm
//! userfaultfd write protection; it then runs on while the checkpoint writer
//! copies the pages it had at the pause. Every page to save starts PENDING
//! and write-protected:
//!
//!   PENDING  -> READING  -> CLEAN     a writer claims it and reads it out of
//!                                      Firecracker (the guest cannot have
//!                                      written it: it is still protected)
//!   PENDING  -> RESCUING -> RESCUED   the guest (or KVM, or a device) wrote
//!                                      it first: the fault handler copies it
//!                                      out and only then unprotects it
//!   RESCUED  -> CLEAN                 a writer takes the copy
//!   HELD     -> CLEAN                 a hot page, copied during the pause
//!                                      and left unprotected (`Cow::hold`,
//!                                      see `uffd::hot`): a writer takes the
//!                                      copy
//!
//! Writers never unprotect anything: pages stay protected after the copy, so
//! the next write to each marks it dirty for an incremental checkpoint (see
//! `Pager::freeze`). HELD pages are unprotected, and dirty from the pause on. A write fault on a page being READ parks until the
//! reader has saved it, which wakes the event thread (`wait_for`).
//!
//! Rescued copies are kept in memory up to a budget; past it (once the writers
//! have started), a fault on a PENDING page asks the writers to take that
//! page's unit next and waits for them instead.
//!
//! Discards: the kernel zaps a page right after the pager reads the REMOVE
//! event, so the pager never reads one while pages are PENDING. It probes
//! for a queued REMOVE before each read (`Pager::remove_queued`) and lets the
//! writers finish first (`drain`); if they make no progress for a while, or a
//! REMOVE slips in between the probe and the read, the checkpoint is
//! invalidated instead of saving wrong contents.

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::checkpoint::GuestPages;
use crate::uffd::{zeroed_atomics, Held, Runs, REMOTE};
use crate::util::{Result, PAGE_SIZE};

pub const CLEAN: u8 = 0;
pub const PENDING: u8 = 1;
pub const READING: u8 = 2;
pub const RESCUING: u8 = 3;
pub const RESCUED: u8 = 4;
pub const HELD: u8 = 5;

/// Rescued copies kept in memory before faults wait for the writers.
const BUDGET_MIB: usize = 256;
/// The least budget until the writers have started: the faults of the resume, which comes first, must not wait for
/// them. It touches a few pages (vCPU clocks, virtio rings).
const PRE_WRITER_MIB: usize = 64;
/// How long a drain waits for the writers to make any progress.
const DRAIN_STALL: Duration = Duration::from_secs(1);

#[derive(Default)]
pub struct Stats {
    /// Write-protect faults while the copy ran.
    pub faults: AtomicU64,
    /// Faults that saved pages first, and the pages they saved.
    pub rescues: AtomicU64,
    pub rescued_pages: AtomicU64,
    pub rescue_ns: AtomicU64,
    pub rescue_max_ns: AtomicU64,
    /// Rescues that failed, giving their pages back, and pages a writer then read itself.
    pub rescue_failures: AtomicU64,
    pub given_back: AtomicU64,
    /// Faults that waited for a writer (over budget, or the page was being read), once each however often retried.
    pub retries: AtomicU64,
    /// Discards held back until the copy was done, and for how long in all.
    pub drains: AtomicU64,
    pub drain_ns: AtomicU64,
    /// Pages copied into memory while a discard was held back.
    pub held_pages: AtomicU64,
}

pub struct Cow {
    states: Vec<AtomicU8>,
    left: AtomicUsize,
    rescued: Mutex<HashMap<usize, Box<[u8]>>>,
    rescued_bytes: AtomicUsize,
    /// Pages copied during the pause (HELD).
    held: OnceLock<Arc<Held>>,
    budget: usize,
    /// Pages faults are waiting on, for the writers to take first.
    wanted: Mutex<VecDeque<usize>>,
    /// Bumped as pages are saved; drains wait on it.
    progress: (Mutex<u64>, Condvar),
    /// The event thread's eventfd (`set_waker`); the pages faults wait for a writer to save (`wait_for`), and whether
    /// there are any (read without the lock).
    waker: OnceLock<OwnedFd>,
    waits: Mutex<Vec<usize>>,
    fault_waits: AtomicBool,
    stopped: AtomicBool,
    /// Whether a writer has started reading pages (`CowPages::read`).
    writing: AtomicBool,
    error: Mutex<Option<String>>,
    started: Instant,
    /// The pages to save, as `[first, end)` runs.
    runs: Vec<(usize, usize)>,
    pub stats: Stats,
}

impl Cow {
    /// Copy-on-write for the REMOTE pages of `runs`, in a guest of `total` pages.
    pub fn new(total: usize, runs: &Runs) -> Cow {
        // CLEAN is 0: a zeroed allocation is lazily backed by the kernel.
        let states: Vec<AtomicU8> = zeroed_atomics(total);
        let runs: Vec<(usize, usize)> = runs.iter().filter(|r| r.2 == REMOTE).map(|r| (r.0 as usize, (r.0 + r.1) as usize)).collect();
        runs.iter().flat_map(|&(a, b)| &states[a..b]).for_each(|s| s.store(PENDING, Ordering::Relaxed));
        let budget = std::env::var("FLEXVM_COW_BUDGET_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(BUDGET_MIB) << 20;
        Cow {
            states,
            left: AtomicUsize::new(runs.iter().map(|(a, b)| b - a).sum()),
            rescued: Mutex::new(HashMap::new()),
            rescued_bytes: AtomicUsize::new(0),
            held: OnceLock::new(),
            budget,
            wanted: Mutex::new(VecDeque::new()),
            progress: (Mutex::new(0), Condvar::new()),
            waker: OnceLock::new(),
            waits: Mutex::new(Vec::new()),
            fault_waits: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            writing: AtomicBool::new(false),
            error: Mutex::new(None),
            started: Instant::now(),
            runs,
            stats: Stats::default(),
        }
    }

    /// The pages to save, as `[first, end)` runs.
    pub fn runs(&self) -> &[(usize, usize)] {
        &self.runs
    }

    pub fn state(&self, page: usize) -> u8 {
        self.states.get(page).map_or(CLEAN, |s| s.load(Ordering::SeqCst))
    }

    pub fn claim(&self, page: usize, from: u8, to: u8) -> bool {
        self.states.get(page).is_some_and(|s| s.compare_exchange(from, to, Ordering::SeqCst, Ordering::SeqCst).is_ok())
    }

    fn set(&self, page: usize, state: u8) {
        self.states[page].store(state, Ordering::SeqCst)
    }

    /// Whether the writers have started, so may claim pages under a fault.
    pub fn writing(&self) -> bool {
        self.writing.load(Ordering::SeqCst)
    }

    /// Whether faults still have to save pages before letting writes through.
    pub fn active(&self) -> bool {
        !self.stopped.load(Ordering::SeqCst)
    }

    /// Fails unless the copy is still `active`, with why it stopped.
    fn check_active(&self) -> Result<()> {
        if !self.active() {
            crate::bail!("the checkpoint copy stopped: {}", self.error().unwrap_or_else(|| "the vm is gone".into()));
        }
        Ok(())
    }

    /// Pages whose pause-time contents exist only in the guest page.
    pub fn left(&self) -> usize {
        self.left.load(Ordering::SeqCst)
    }

    /// `n` pages of `first..end` were saved (their states set already).
    fn saved(&self, first: usize, end: usize, n: usize) {
        self.left.fetch_sub(n, Ordering::SeqCst);
        *self.progress.0.lock().unwrap() += n as u64;
        self.progress.1.notify_all();
        self.settled(first, end);
    }

    /// The states of pages `first..end` changed (set already): wakes the event thread if a fault waits on one of them.
    fn settled(&self, first: usize, end: usize) {
        if !self.fault_waits.load(Ordering::SeqCst) {
            return;
        }
        let mut waits = self.waits.lock().unwrap();
        let before = waits.len();
        waits.retain(|p| !(first..end).contains(p));
        self.fault_waits.store(!waits.is_empty(), Ordering::SeqCst);
        if waits.len() < before {
            drop(waits);
            self.wake();
        }
    }

    /// Wakes the event thread through `fd` (an eventfd it polls) when a fault waits for a writer.
    pub fn set_waker(&self, fd: OwnedFd) {
        let _ = self.waker.set(fd);
    }

    fn wake(&self) {
        if let Some(fd) = self.waker.get() {
            unsafe { libc::write(fd.as_raw_fd(), (&1u64 as *const u64).cast(), 8) };
        }
    }

    /// A fault on `page`, which it saw in state `seen` (READING, or PENDING while over budget), waits for a writer to
    /// save it, parked: the event thread is woken once a writer has saved it or given it back, or the copy stops. At
    /// once if any of that happened already, or the reason to wait is gone (no longer over budget): the fault is
    /// retried then. No wakeup is lost: a writer (or `stop`) changes the state before it looks at the flag, and this
    /// sets the flag (with the page listed) before it looks at the state.
    pub fn wait_for(&self, page: usize, seen: u8) {
        {
            let mut waits = self.waits.lock().unwrap();
            if !waits.contains(&page) {
                waits.push(page);
            }
            self.fault_waits.store(true, Ordering::SeqCst);
        }
        let still = match self.state(page) {
            s if s != seen => false,
            READING | RESCUING => true,
            PENDING => self.over_budget(),
            _ => false,
        };
        if !still || !self.active() {
            self.wake();
        }
    }

    /// Whether rescued copies fill the budget, so faults wait for the writers rather than save more. At least
    /// `PRE_WRITER_MIB` before the writers have started: the faults of the resume would wait for writers that start
    /// only after it.
    pub fn over_budget(&self) -> bool {
        let budget = if self.writing() { self.budget } else { self.budget.max(PRE_WRITER_MIB << 20) };
        self.rescued_bytes.load(Ordering::SeqCst) >= budget
    }

    /// Keeps the pause-time copies of pages claimed RESCUING in `first..end`.
    pub fn rescue_many(&self, first: usize, end: usize, pages: impl IntoIterator<Item = (usize, Box<[u8]>)>) {
        let mut rescued = self.rescued.lock().unwrap();
        let (mut n, mut bytes) = (0, 0);
        for (page, copy) in pages {
            bytes += copy.len();
            rescued.insert(page, copy);
            self.set(page, RESCUED);
            n += 1;
        }
        self.rescued_bytes.fetch_add(bytes, Ordering::SeqCst);
        drop(rescued);
        self.saved(first, end, n);
    }

    /// The pause-time contents of pages to save, copied during the pause: the writers take them from there. (Once.)
    pub fn hold(&self, held: Arc<Held>) {
        let n = held.pages().iter().filter(|&&p| self.claim(p, PENDING, HELD)).count();
        self.left.fetch_sub(n, Ordering::SeqCst);
        let _ = self.held.set(held);
    }

    /// Gives back a claim the fault handler could not complete.
    pub fn unclaim(&self, page: usize) {
        self.set(page, PENDING);
        self.settled(page, page + 1);
    }

    /// A fault waits on `page`: writers take its unit next.
    pub fn want(&self, page: usize) {
        let mut wanted = self.wanted.lock().unwrap();
        if !wanted.contains(&page) {
            wanted.push_back(page);
        }
    }

    /// The checkpoint cannot be trusted any more: say why (the first reason
    /// sticks) and stop the copy, so no fault reads a page out of the guest
    /// for it again (a discarded one would fault back to the event thread).
    pub fn invalidate(&self, why: &str) {
        let mut e = self.error.lock().unwrap();
        if e.is_none() {
            crate::log!("uffd: checkpoint copy invalidated: {why}");
            *e = Some(why.into());
        }
        drop(e);
        self.stop();
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    /// Ends the copy (done or given up): faults stop saving, copies still
    /// held are dropped, and faults waiting for a writer are retried.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.rescued.lock().unwrap().clear();
        self.progress.1.notify_all();
        self.settled(0, usize::MAX);
    }

    /// Waits until every page is saved, the copy stops, or the writers stall.
    /// Returns whether everything was saved.
    pub fn drain(&self) -> bool {
        let start = Instant::now();
        self.stats.drains.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.progress.0.lock().unwrap();
        let mut seen = (*guard, Instant::now());
        let done = loop {
            if self.left() == 0 {
                break true;
            }
            if !self.active() || seen.1.elapsed() >= DRAIN_STALL {
                break false;
            }
            guard = self.progress.1.wait_timeout(guard, Duration::from_millis(50)).unwrap().0;
            if *guard != seen.0 {
                seen = (*guard, Instant::now());
            }
        };
        self.stats.drain_ns.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        done
    }

    pub fn report(&self) -> Value {
        let s = &self.stats;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let rescues = get(&s.rescues);
        json!({
            "faults": get(&s.faults),
            "rescues": rescues,
            "rescued_mib": (get(&s.rescued_pages) * PAGE_SIZE as u64) as f64 / (1 << 20) as f64,
            "rescue_avg_us": if rescues > 0 { get(&s.rescue_ns) as f64 / rescues as f64 / 1e3 } else { 0.0 },
            "rescue_max_us": get(&s.rescue_max_ns) as f64 / 1e3,
            "rescue_failures": get(&s.rescue_failures),
            "given_back": get(&s.given_back),
            "retries": get(&s.retries),
            "discards_held": get(&s.drains),
            "discards_held_ms": get(&s.drain_ns) as f64 / 1e6,
            "saved_while_held_mib": (get(&s.held_pages) * PAGE_SIZE as u64) >> 20,
            "running_ms": self.started.elapsed().as_secs_f64() * 1e3,
        })
    }
}

/// The checkpoint writer's view of guest memory during a copy-on-write
/// checkpoint: pause-time contents, read out of the guest or taken from
/// what faults rescued.
pub struct CowPages<'a> {
    pub guest: &'a dyn GuestPages,
    pub cow: &'a Cow,
    /// Test faults `ckpt_slow` and `ckpt_crawl`: how long to wait over each unit,
    /// asked before each one, so a copy goes on at full speed once they are disarmed.
    pub slow: fn() -> Duration,
}

impl GuestPages for CowPages<'_> {
    fn region_end(&self, page: usize) -> Option<usize> {
        self.guest.region_end(page)
    }

    fn read(&self, page: usize, buf: &mut [u8]) -> Result<()> {
        let cow = self.cow;
        cow.writing.store(true, Ordering::SeqCst);
        std::thread::sleep((self.slow)());
        cow.check_active()?;
        let n = buf.len() / PAGE_SIZE;
        let mine: Vec<bool> = (0..n).map(|i| cow.claim(page + i, PENDING, READING)).collect();
        // Runs of pages claimed here, read straight out of the guest.
        for (i, j) in crate::uffd::runs_where(0, n, |i| mine[i]) {
            if let Err(e) = self.guest.read(page + i, &mut buf[i * PAGE_SIZE..j * PAGE_SIZE]) {
                // All of them, the runs read already too: none is saved, and a fault may wait on any.
                (0..n).filter(|&k| mine[k]).for_each(|k| cow.set(page + k, PENDING));
                cow.settled(page, page + n);
                return Err(e);
            }
        }
        (0..n).filter(|&k| mine[k]).for_each(|k| cow.set(page + k, CLEAN));
        cow.saved(page, page + n, mine.iter().filter(|&&m| m).count());
        // The rest were copied during the pause, or a fault saved them first (or is saving them right now).
        'copies: for k in (0..n).filter(|&k| !mine[k]) {
            let p = page + k;
            if cow.state(p) == HELD {
                let Some(bytes) = cow.held.get().and_then(|h| h.get(p)) else { crate::bail!("page {p}: held copy missing") };
                buf[k * PAGE_SIZE..(k + 1) * PAGE_SIZE].copy_from_slice(bytes);
                cow.set(p, CLEAN);
                continue;
            }
            loop {
                cow.check_active()?;
                match cow.state(p) {
                    RESCUED => break,
                    RESCUING => std::thread::yield_now(),
                    PENDING => {
                        if cow.claim(p, PENDING, READING) {
                            if let Err(e) = self.guest.read(p, &mut buf[k * PAGE_SIZE..(k + 1) * PAGE_SIZE]) {
                                cow.unclaim(p);
                                return Err(e);
                            }
                            cow.set(p, CLEAN);
                            cow.saved(p, p + 1, 1);
                            cow.stats.given_back.fetch_add(1, Ordering::Relaxed);
                            continue 'copies;
                        }
                    }
                    s => crate::bail!("page {p} is in copy state {s}, not saved"),
                }
            }
            // A copy that stops (abort, kill) drops the rescued copies under
            // the writers: that is the stop, not a lost page.
            let Some(bytes) = cow.rescued.lock().unwrap().remove(&p) else {
                cow.check_active()?;
                crate::bail!("page {p}: rescued copy missing");
            };
            cow.rescued_bytes.fetch_sub(bytes.len(), Ordering::SeqCst);
            buf[k * PAGE_SIZE..(k + 1) * PAGE_SIZE].copy_from_slice(&bytes);
            cow.set(p, CLEAN);
        }
        Ok(())
    }

    fn wanted(&self) -> Option<usize> {
        self.cow.wanted.lock().unwrap().pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Guest memory whose pages change under the writer, as a running VM's do.
    struct Live {
        pages: StdMutex<Vec<u8>>,
    }

    impl GuestPages for Live {
        fn region_end(&self, _page: usize) -> Option<usize> {
            Some(self.pages.lock().unwrap().len() / PAGE_SIZE)
        }

        fn read(&self, page: usize, buf: &mut [u8]) -> Result<()> {
            let p = self.pages.lock().unwrap();
            buf.copy_from_slice(&p[page * PAGE_SIZE..page * PAGE_SIZE + buf.len()]);
            Ok(())
        }
    }

    #[test]
    fn writes_after_the_pause_never_reach_the_copy() {
        let n = 64;
        let live = Live { pages: StdMutex::new((0..n * PAGE_SIZE).map(|i| (i / PAGE_SIZE) as u8).collect()) };
        let cow = Cow::new(n, &vec![(0, 40, REMOTE), (40, 4, crate::uffd::ZERO)]);
        assert_eq!(cow.left(), 40);
        // A fault on page 3 saves it before the guest overwrites it.
        assert!(cow.claim(3, PENDING, RESCUING));
        cow.rescue_many(3, 4, [(3, vec![3u8; PAGE_SIZE].into())]);
        live.pages.lock().unwrap()[3 * PAGE_SIZE..4 * PAGE_SIZE].fill(0xee);
        // Page 5 is being saved by a fault while the writer gets there.
        assert!(cow.claim(5, PENDING, RESCUING));
        assert!(!cow.claim(5, PENDING, READING), "one saver per page");
        let pages = CowPages { guest: &live, cow: &cow, slow: || Duration::ZERO };
        let mut buf = vec![0u8; 8 * PAGE_SIZE];
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                cow.rescue_many(5, 6, [(5, vec![5u8; PAGE_SIZE].into())]);
            });
            pages.read(0, &mut buf).unwrap();
        });
        for (i, p) in buf.chunks(PAGE_SIZE).enumerate() {
            assert!(p.iter().all(|&b| b == i as u8), "page {i} has its pause-time contents");
        }
        assert_eq!(cow.left(), 32);
        assert!(cow.rescued.lock().unwrap().is_empty(), "rescued copies are dropped once written");
        assert_eq!(cow.state(3), CLEAN);
        // Faults wait on pages; writers take those units first.
        cow.want(30);
        cow.want(30);
        assert_eq!(pages.wanted(), Some(30));
        assert_eq!(pages.wanted(), None);
        assert_eq!(cow.state(8), PENDING);
        // An invalidated copy stops: faults no longer save pages for it, and
        // its writer fails, saying why, instead of writing guesses.
        cow.invalidate("page 8 was discarded before it was saved");
        assert!(!cow.active());
        assert!(pages.read(8, &mut buf[..PAGE_SIZE]).unwrap_err().to_string().contains("page 8 was discarded"));
    }

    #[test]
    fn failed_rescue_is_read_by_the_writer() {
        struct Retry<'a> {
            gate: &'a Gate,
            cow: &'a Cow,
            fail: bool,
        }
        impl GuestPages for Retry<'_> {
            fn region_end(&self, _page: usize) -> Option<usize> {
                Some(2)
            }
            fn read(&self, page: usize, buf: &mut [u8]) -> Result<()> {
                if page == 0 {
                    return self.gate.read(page, buf);
                }
                assert_eq!(self.cow.state(page), READING);
                if self.fail {
                    crate::bail!("retry unreadable");
                }
                buf.fill(7);
                Ok(())
            }
        }
        for fail in [false, true] {
            let cow = Cow::new(2, &vec![(0, 2, REMOTE)]);
            assert!(cow.claim(1, PENDING, RESCUING));
            let gate = Gate { entered: std::sync::Barrier::new(2), go: std::sync::Barrier::new(2) };
            let guest = Retry { gate: &gate, cow: &cow, fail };
            let pages = CowPages { guest: &guest, cow: &cow, slow: || Duration::ZERO };
            let mut buf = vec![0; 2 * PAGE_SIZE];
            let result = std::thread::scope(|s| {
                let writer = s.spawn(|| pages.read(0, &mut buf));
                gate.entered.wait();
                // The writer already lost its initial claim to the rescue. A failed rescue
                // gives it back without unprotecting it, so the pause-time bytes remain.
                cow.unclaim(1);
                gate.go.wait();
                writer.join().unwrap()
            });
            if fail {
                assert!(result.unwrap_err().to_string().contains("retry unreadable"));
                assert_eq!(cow.state(1), PENDING);
                assert_eq!(cow.left(), 1);
            } else {
                result.unwrap();
                assert!(buf[PAGE_SIZE..].iter().all(|&b| b == 7));
                assert_eq!(cow.state(1), CLEAN);
                assert_eq!(cow.left(), 0);
            }
        }
    }

    #[test]
    fn batched_rescue_keeps_each_pause_time_copy() {
        let cow = Cow::new(6, &vec![(0, 6, REMOTE)]);
        let live = Live { pages: StdMutex::new((0..6 * PAGE_SIZE).map(|i| (i / PAGE_SIZE) as u8).collect()) };
        use std::os::fd::FromRawFd;
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(fd >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        cow.set_waker(fd.try_clone().unwrap());
        let claimed = [1, 3, 4];
        for p in claimed {
            assert!(cow.claim(p, PENDING, RESCUING));
        }
        cow.wait_for(1, RESCUING);
        cow.wait_for(4, RESCUING);
        cow.rescue_many(1, 5, claimed.map(|p| (p, vec![p as u8; PAGE_SIZE].into())));
        let mut wakes = 0u64;
        assert_eq!(unsafe { libc::read(fd.as_raw_fd(), (&mut wakes as *mut u64).cast(), 8) }, 8);
        assert_eq!(wakes, 1, "one wake for the whole batch");
        assert!(cow.waits.lock().unwrap().is_empty());
        assert_eq!(cow.left(), 3);
        assert_eq!(*cow.progress.0.lock().unwrap(), 3);
        assert_eq!(cow.rescued_bytes.load(Ordering::SeqCst), 3 * PAGE_SIZE);
        for p in 0..6 {
            assert_eq!(cow.state(p), if claimed.contains(&p) { RESCUED } else { PENDING });
        }
        for p in claimed {
            live.pages.lock().unwrap()[p * PAGE_SIZE..(p + 1) * PAGE_SIZE].fill(0xee);
        }
        let pages = CowPages { guest: &live, cow: &cow, slow: || Duration::ZERO };
        let mut buf = vec![0; 6 * PAGE_SIZE];
        pages.read(0, &mut buf).unwrap();
        for (p, bytes) in buf.chunks(PAGE_SIZE).enumerate() {
            assert!(bytes.iter().all(|&b| b == p as u8));
            assert_eq!(cow.state(p), CLEAN);
        }
        assert_eq!(cow.left(), 0);
        assert_eq!(*cow.progress.0.lock().unwrap(), 6);
        assert_eq!(cow.rescued_bytes.load(Ordering::SeqCst), 0);
        assert!(cow.rescued.lock().unwrap().is_empty());
    }

    /// Guest memory whose reads stop half way until the test lets them go.
    struct Gate {
        entered: std::sync::Barrier,
        go: std::sync::Barrier,
    }

    impl GuestPages for Gate {
        fn region_end(&self, _page: usize) -> Option<usize> {
            Some(64)
        }

        fn read(&self, _page: usize, buf: &mut [u8]) -> Result<()> {
            self.entered.wait();
            self.go.wait();
            buf.fill(0);
            Ok(())
        }
    }

    /// A writer that finds the rescued copy of a page gone: because the copy
    /// was stopped under it (it says why, `aborted`), or, while the copy is
    /// still active, an integrity error.
    #[test]
    fn rescued_copy_dropped_under_the_writer() {
        for abort in [true, false] {
            let cow = Cow::new(64, &vec![(0, 2, REMOTE)]);
            // Page 1 was rescued by a fault; the writer reads page 0 itself.
            assert!(cow.claim(1, PENDING, RESCUING));
            cow.rescue_many(1, 2, [(1, vec![1u8; PAGE_SIZE].into())]);
            let gate = Gate { entered: std::sync::Barrier::new(2), go: std::sync::Barrier::new(2) };
            let pages = CowPages { guest: &gate, cow: &cow, slow: || Duration::ZERO };
            let mut buf = vec![0u8; 2 * PAGE_SIZE];
            let e = std::thread::scope(|s| {
                let w = s.spawn(|| pages.read(0, &mut buf));
                gate.entered.wait();
                // The writer is inside its read of page 0, past its check
                // that the copy is active.
                if abort {
                    cow.invalidate("the copy was aborted");
                } else {
                    cow.rescued.lock().unwrap().remove(&1);
                }
                gate.go.wait();
                w.join().unwrap().unwrap_err().to_string()
            });
            match abort {
                true => assert!(e.contains("aborted"), "{e}"),
                false => assert!(e.contains("rescued copy missing"), "{e}"),
            }
        }
    }

    /// A fault waiting for a writer (`wait_for`) is woken through the waker once a writer saves its page or gives it
    /// back, or the copy stops, or at once if any of that happened before it waited; nothing wakes it while the page is
    /// still being read, or for other pages saved meanwhile.
    #[test]
    fn faults_waiting_for_a_writer_are_woken() {
        use std::os::fd::FromRawFd;
        let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(efd >= 0);
        let efd = unsafe { OwnedFd::from_raw_fd(efd) };
        let woken = || {
            let mut n = 0u64;
            unsafe { libc::read(efd.as_raw_fd(), (&mut n as *mut u64).cast(), 8) == 8 }
        };
        let mut cow = Cow::new(8, &vec![(0, 8, REMOTE)]);
        cow.budget = 0;
        cow.set_waker(efd.try_clone().unwrap());
        assert!(cow.claim(1, PENDING, READING));
        cow.wait_for(1, READING);
        assert!(!woken(), "page 1 is still being read");
        assert!(cow.claim(2, PENDING, READING));
        cow.set(2, CLEAN);
        cow.saved(2, 3, 1);
        assert!(!woken(), "saving another page does not wake it");
        cow.set(1, CLEAN);
        cow.saved(1, 2, 1);
        assert!(woken(), "saving it wakes the fault");
        cow.saved(0, 8, 0);
        assert!(!woken(), "once: nothing waits any more");
        cow.wait_for(1, READING);
        assert!(woken(), "page 1 is done with already");
        // Before the writers start, the budget is at least `PRE_WRITER_MIB`: a fault on a pending page saves it itself.
        assert!(!cow.over_budget());
        cow.wait_for(4, PENDING);
        assert!(woken(), "no reason to wait before the writers start");
        cow.rescued_bytes.store(PRE_WRITER_MIB << 20, Ordering::SeqCst);
        assert!(cow.over_budget(), "bounded before the writers start too");
        cow.rescued_bytes.store(0, Ordering::SeqCst);
        cow.writing.store(true, Ordering::SeqCst);
        assert!(cow.over_budget());
        // A writer whose read fails gives its pages back, which wakes faults waiting on them.
        let fail = Fail;
        let pages = CowPages { guest: &fail, cow: &cow, slow: || Duration::ZERO };
        cow.wait_for(4, PENDING);
        assert!(!woken(), "page 4 is wanted while over budget");
        assert!(pages.read(3, &mut vec![0u8; 2 * PAGE_SIZE]).is_err());
        assert_eq!((cow.state(3), cow.state(4)), (PENDING, PENDING), "given back");
        assert!(woken(), "giving page 4 back wakes the fault");
        // Given back before the fault that saw it being read waits: woken at once all the same.
        assert!(cow.claim(5, PENDING, READING));
        cow.unclaim(5);
        cow.wait_for(5, READING);
        assert!(woken(), "page 5 was given back before the wait");
        // The copy stopping wakes a fault waiting on a page nobody will save now; and one that waits after the stop.
        assert!(cow.claim(6, PENDING, READING));
        cow.wait_for(6, READING);
        assert!(!woken());
        cow.stop();
        assert!(woken(), "the stop wakes the fault");
        cow.wait_for(6, READING);
        assert!(woken(), "the copy stopped before the wait");
    }

    /// Guest memory that cannot be read.
    struct Fail;

    impl GuestPages for Fail {
        fn region_end(&self, _page: usize) -> Option<usize> {
            Some(64)
        }

        fn read(&self, _page: usize, _buf: &mut [u8]) -> Result<()> {
            crate::bail!("unreadable")
        }
    }

    /// Pages copied during the pause (HELD) are written from that copy, whatever the guest writes since; no fault or
    /// writer claims them, and the copy has that many fewer left.
    #[test]
    fn held_pages_are_written_from_their_copy() {
        let n = 16;
        let live = Live { pages: StdMutex::new(vec![0xee; n * PAGE_SIZE]) };
        let cow = Cow::new(n, &vec![(0, 8, REMOTE)]);
        // Page 9 is held but not to save (left out of a delta): it stays as it was.
        cow.hold(Arc::new(Held::of(&[(2, 2), (3, 3), (9, 9)])));
        assert_eq!(cow.left(), 6);
        assert_eq!((cow.state(2), cow.state(9)), (HELD, CLEAN));
        assert!(!cow.claim(2, PENDING, RESCUING) && !cow.claim(3, PENDING, READING));
        let pages = CowPages { guest: &live, cow: &cow, slow: || Duration::ZERO };
        let mut buf = vec![0u8; 8 * PAGE_SIZE];
        pages.read(0, &mut buf).unwrap();
        for (i, p) in buf.chunks(PAGE_SIZE).enumerate() {
            let want = if i == 2 || i == 3 { i as u8 } else { 0xee };
            assert!(p.iter().all(|&b| b == want), "page {i}");
        }
        assert_eq!(cow.left(), 0);
        assert_eq!(cow.state(2), CLEAN);
    }

    #[test]
    fn drain_waits_for_the_writers() {
        let cow = Cow::new(4, &vec![(0, 2, REMOTE)]);
        std::thread::scope(|s| {
            s.spawn(|| {
                for p in 0..2 {
                    std::thread::sleep(Duration::from_millis(30));
                    assert!(cow.claim(p, PENDING, READING));
                    cow.set(p, CLEAN);
                    cow.saved(p, p + 1, 1);
                }
            });
            assert!(cow.drain());
        });
        assert_eq!(cow.left(), 0);
    }
}
