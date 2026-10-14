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
//!
//! Writers never unprotect anything: pages stay protected after the copy, so
//! the next write to each marks it dirty for an incremental checkpoint (see
//! `Pager::freeze`). A write fault on a page being READ waits for the reader.
//!
//! Rescued copies are kept in memory up to a budget; past it, a fault on a
//! PENDING page asks the writers to take that page's unit next and waits for
//! them instead.
//!
//! Discards: the kernel zaps a page right after the pager reads the REMOVE
//! event, so the pager never reads one while pages are PENDING. It probes
//! for a queued REMOVE before each read (UFFDIO_WRITEPROTECT fails with EAGAIN
//! while one is queued) and lets the writers finish first (`drain`); if they
//! make no progress for a while, or a REMOVE slips in between the probe and
//! the read, the checkpoint is invalidated instead of saving wrong contents.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::checkpoint::GuestPages;
use crate::uffd::{zeroed_atomics, Runs, REMOTE};
use crate::util::{Result, PAGE_SIZE};

pub const CLEAN: u8 = 0;
pub const PENDING: u8 = 1;
pub const READING: u8 = 2;
pub const RESCUING: u8 = 3;
pub const RESCUED: u8 = 4;

/// Rescued copies kept in memory before faults wait for the writers.
const BUDGET_MIB: usize = 256;
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
    /// Retries waiting for a writer (over budget, or the page was being read).
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
    budget: usize,
    /// Pages faults are waiting on, for the writers to take first.
    wanted: Mutex<VecDeque<usize>>,
    /// Bumped as pages are saved; drains wait on it.
    progress: (Mutex<u64>, Condvar),
    /// Where to look for an unsaved page to probe with.
    hint: AtomicUsize,
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
            budget,
            wanted: Mutex::new(VecDeque::new()),
            progress: (Mutex::new(0), Condvar::new()),
            hint: AtomicUsize::new(runs.first().map_or(0, |r| r.0)),
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

    fn saved(&self, n: usize) {
        self.left.fetch_sub(n, Ordering::SeqCst);
        *self.progress.0.lock().unwrap() += n as u64;
        self.progress.1.notify_all();
    }

    pub fn over_budget(&self) -> bool {
        self.rescued_bytes.load(Ordering::SeqCst) >= self.budget
    }

    /// Keeps `bytes`, the pause-time contents of `page` (claimed RESCUING).
    pub fn rescue(&self, page: usize, bytes: Box<[u8]>) {
        self.rescued_bytes.fetch_add(bytes.len(), Ordering::SeqCst);
        self.rescued.lock().unwrap().insert(page, bytes);
        self.set(page, RESCUED);
        self.saved(1);
    }

    /// Gives back a claim the fault handler could not complete.
    pub fn unclaim(&self, page: usize) {
        self.set(page, PENDING);
    }

    /// A fault waits on `page`: writers take its unit next.
    pub fn want(&self, page: usize) {
        let mut wanted = self.wanted.lock().unwrap();
        if !wanted.contains(&page) {
            wanted.push_back(page);
        }
    }

    /// Some page that is still protected because it is not saved yet.
    pub fn unsaved_page(&self) -> Option<usize> {
        if self.left() == 0 {
            return None;
        }
        let n = self.states.len();
        let hint = self.hint.load(Ordering::Relaxed).min(n);
        let found = (hint..n).chain(0..hint).find(|&p| matches!(self.state(p), PENDING | READING))?;
        self.hint.store(found, Ordering::Relaxed);
        Some(found)
    }

    /// The checkpoint cannot be trusted any more: say why (the first reason
    /// sticks) and stop the copy, so no fault reads a page out of the guest
    /// for it again (a discarded one would fault back to the event thread).
    pub fn invalidate(&self, why: &str) {
        let mut e = self.error.lock().unwrap();
        if e.is_none() {
            eprintln!("uffd: checkpoint copy invalidated: {why}");
            *e = Some(why.into());
        }
        drop(e);
        self.stop();
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    /// Ends the copy (done or given up): faults stop saving, and copies still
    /// held are dropped.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.rescued.lock().unwrap().clear();
        self.progress.1.notify_all();
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
        if !cow.writing.load(Ordering::Relaxed) {
            cow.writing.store(true, Ordering::SeqCst);
        }
        std::thread::sleep((self.slow)());
        cow.check_active()?;
        let n = buf.len() / PAGE_SIZE;
        let mine: Vec<bool> = (0..n).map(|i| cow.claim(page + i, PENDING, READING)).collect();
        // Runs of pages claimed here, read straight out of the guest.
        for (i, j) in crate::uffd::runs_where(0, n, |i| mine[i]) {
            if let Err(e) = self.guest.read(page + i, &mut buf[i * PAGE_SIZE..j * PAGE_SIZE]) {
                (i..n).filter(|&k| mine[k]).for_each(|k| cow.set(page + k, PENDING));
                return Err(e);
            }
        }
        (0..n).filter(|&k| mine[k]).for_each(|k| cow.set(page + k, CLEAN));
        cow.saved(mine.iter().filter(|&&m| m).count());
        // The rest a fault saved first (or is saving right now).
        for k in (0..n).filter(|&k| !mine[k]) {
            let p = page + k;
            loop {
                match cow.state(p) {
                    RESCUED => break,
                    RESCUING => std::thread::yield_now(),
                    s => crate::bail!("page {p} is in copy state {s}, not saved"),
                }
                cow.check_active()?;
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
        cow.rescue(3, vec![3u8; PAGE_SIZE].into());
        live.pages.lock().unwrap()[3 * PAGE_SIZE..4 * PAGE_SIZE].fill(0xee);
        // Page 5 is being saved by a fault while the writer gets there.
        assert!(cow.claim(5, PENDING, RESCUING));
        assert!(!cow.claim(5, PENDING, READING), "one saver per page");
        let pages = CowPages { guest: &live, cow: &cow, slow: || Duration::ZERO };
        let mut buf = vec![0u8; 8 * PAGE_SIZE];
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                cow.rescue(5, vec![5u8; PAGE_SIZE].into());
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
        assert_eq!(cow.report()["retries"], 0, "queueing pages does not count fault retries");
        assert_eq!(pages.wanted(), Some(30));
        assert_eq!(pages.wanted(), None);
        assert_eq!(cow.unsaved_page(), Some(8));
        // An invalidated copy stops: faults no longer save pages for it, and
        // its writer fails, saying why, instead of writing guesses.
        cow.invalidate("page 8 was discarded before it was saved");
        assert!(!cow.active());
        assert!(pages.read(8, &mut buf[..PAGE_SIZE]).unwrap_err().to_string().contains("page 8 was discarded"));
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
            cow.rescue(1, vec![1u8; PAGE_SIZE].into());
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

    #[test]
    fn drain_waits_for_the_writers() {
        let cow = Cow::new(4, &vec![(0, 2, REMOTE)]);
        std::thread::scope(|s| {
            s.spawn(|| {
                for p in 0..2 {
                    std::thread::sleep(Duration::from_millis(30));
                    assert!(cow.claim(p, PENDING, READING));
                    cow.set(p, CLEAN);
                    cow.saved(1);
                }
            });
            assert!(cow.drain());
        });
        assert_eq!(cow.left(), 0);
        assert_eq!(cow.unsaved_page(), None);
    }
}
