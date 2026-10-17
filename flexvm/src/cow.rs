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
//! page's unit next and waits for them instead. Their memory (`Slots`) is
//! kept for the next copy, as much as this one used at once, up to the
//! budget: faulting in fresh memory costs a rescue more than the copy.
//!
//! Discards: the kernel zaps a page right after the pager reads the REMOVE
//! event, so the pager never reads one while pages are PENDING. It probes
//! for a queued REMOVE before each read (`Pager::remove_queued`) and lets the
//! writers finish first (`drain`); if they make no progress for a while, or a
//! REMOVE slips in between the probe and the read, the checkpoint is
//! invalidated instead of saving wrong contents.

use std::collections::VecDeque;
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
    /// Faults whose page a writer claimed after the fault checked it (#88): retried once the writer was done.
    pub writer_claimed: AtomicU64,
    /// Discards held back until the copy was done, and for how long in all.
    pub drains: AtomicU64,
    pub drain_ns: AtomicU64,
    /// Pages copied into memory while a discard was held back.
    pub held_pages: AtomicU64,
}

pub struct Cow {
    states: Vec<AtomicU8>,
    left: AtomicUsize,
    /// Where each RESCUED page's copy is (a slot of `slots`), 0 for none.
    rescued: Index,
    slots: Slots,
    /// Where `slots` go when the copy is dropped, for the next one.
    home: Option<Arc<Mutex<Option<Slots>>>>,
    rescued_bytes: AtomicUsize,
    /// Pages copied during the pause (HELD).
    held: OnceLock<Arc<Held>>,
    budget: usize,
    /// Pages faults are waiting on, for the writers to take first.
    wanted: Mutex<VecDeque<usize>>,
    /// Bumped as pages are saved; drains wait on it.
    progress: (Mutex<u64>, Condvar),
    #[cfg(test)]
    notifications: AtomicUsize,
    /// The event thread's eventfd (`set_waker`); the pages faults wait for a writer to save (`wait_for`), and whether
    /// there are any (read without the lock).
    waker: OnceLock<OwnedFd>,
    waits: Mutex<Vec<usize>>,
    fault_waits: AtomicBool,
    stopped: AtomicBool,
    /// Whether a writer has started reading pages (`CowPages::read`).
    writing: AtomicBool,
    /// Times a writer waited for a rescue to settle (`wait_rescued`), for test fault `ckpt_rescue_fail`: counted only
    /// while it is armed (`count_rescue_waits`).
    rescue_waits: AtomicU64,
    count_waits: bool,
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
        Cow {
            states,
            left: AtomicUsize::new(runs.iter().map(|(a, b)| b - a).sum()),
            rescued: Index::new(total),
            slots: Slots::default(),
            home: None,
            rescued_bytes: AtomicUsize::new(0),
            held: OnceLock::new(),
            budget: BUDGET_MIB << 20,
            wanted: Mutex::new(VecDeque::new()),
            progress: (Mutex::new(0), Condvar::new()),
            #[cfg(test)]
            notifications: AtomicUsize::new(0),
            waker: OnceLock::new(),
            waits: Mutex::new(Vec::new()),
            fault_waits: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            writing: AtomicBool::new(false),
            rescue_waits: AtomicU64::new(0),
            count_waits: false,
            error: Mutex::new(None),
            started: Instant::now(),
            runs,
            stats: Stats::default(),
        }
    }

    /// Rescues write into the memory `home` holds from the last copy, if any, and hand it back there, trimmed to what
    /// this copy used at most, once it is dropped: memory faulted in fresh costs a rescue several times what copying
    /// into it does here (#630), and a guest that wrote much during one copy tends to again. It grows only within
    /// `room`.
    pub fn keep_slots(mut self, home: Arc<Mutex<Option<Slots>>>, room: Room) -> Cow {
        if let Some(s) = home.lock().unwrap().take() {
            self.slots = s;
        }
        self.slots.room = room;
        self.home = Some(home);
        self
    }

    /// Counts the times writers wait for a rescue to settle (`rescue_waits`), for test fault `ckpt_rescue_fail`.
    pub fn count_rescue_waits(mut self, on: bool) -> Cow {
        self.count_waits = on;
        self
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

    pub fn rescue_waits(&self) -> u64 {
        self.rescue_waits.load(Ordering::SeqCst)
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

    /// Wakes the drain and writers parked on a rescue (`wait_rescued`), under the lock they check under.
    fn notify(&self) {
        #[cfg(test)]
        self.notifications.fetch_add(1, Ordering::SeqCst);
        drop(self.progress.0.lock().unwrap());
        self.progress.1.notify_all();
    }

    /// Parks a writer while `page` is RESCUING, until the rescue keeps its copy, gives it back, or the copy stops. No
    /// wakeup is lost: each of those changes the state (or stops) before it notifies under `progress`'s lock.
    fn wait_rescued(&self, page: usize) {
        if self.count_waits {
            self.rescue_waits.fetch_add(1, Ordering::SeqCst);
        }
        let g = self.progress.0.lock().unwrap();
        drop(self.progress.1.wait_while(g, |_| self.active() && self.state(page) == RESCUING).unwrap());
    }

    /// The states of pages `first..end` changed (set already): wakes the event thread if a fault waits on one of them.
    fn settled(&self, first: usize, end: usize) {
        self.settled_where(|p| (first..end).contains(&p));
    }

    fn settled_where(&self, changed: impl Fn(usize) -> bool) {
        if !self.fault_waits.load(Ordering::SeqCst) {
            return;
        }
        let mut waits = self.waits.lock().unwrap();
        let before = waits.len();
        waits.retain(|&p| !changed(p));
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
    /// Also while there is memory for no whole block (`SLOT_CHUNK`) of copies: no free slots, and the host has no room
    /// for more (`Room`).
    pub fn over_budget(&self) -> bool {
        let budget = if self.writing() { self.budget } else { self.budget.max(PRE_WRITER_MIB << 20) };
        self.rescued_bytes.load(Ordering::SeqCst) >= budget || !self.slots.can_take(SLOT_CHUNK / PAGE_SIZE, self.unbounded())
    }

    /// Before the writers have started, rescue memory grows past the host's room up to `PRE_WRITER_MIB`: the faults of
    /// the resume must not wait for them.
    fn unbounded(&self) -> bool {
        !self.writing() && self.slots.mapped_bytes() < PRE_WRITER_MIB << 20
    }

    /// Memory for `n` pages' copies: slots for `rescue_many`, or back with `give_slots`. None if there are not that many
    /// free and the host has no room for more.
    pub fn take_slots(&self, n: usize) -> std::io::Result<Option<Vec<Slot>>> {
        self.slots.take(n, self.unbounded())
    }

    pub fn give_slots(&self, slots: Vec<Slot>) {
        self.slots.give(slots)
    }

    /// Keeps the pause-time copies of pages claimed RESCUING in `first..end`, each in its slot (`take_slots`).
    pub fn rescue_many(&self, first: usize, end: usize, pages: impl IntoIterator<Item = (usize, Slot)>) {
        let mut n = 0;
        for (page, slot) in pages {
            // Before the state: a writer that sees RESCUED finds the copy.
            self.rescued[page].store(slot.0 as u64, Ordering::SeqCst);
            self.set(page, RESCUED);
            n += 1;
        }
        self.rescued_bytes.fetch_add(n * PAGE_SIZE, Ordering::SeqCst);
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
        self.unclaim_many(&[page]);
    }

    /// Gives back failed rescue claims, waking writers and the event thread once.
    pub fn unclaim_many(&self, pages: &[usize]) {
        pages.iter().for_each(|&p| self.set(p, PENDING));
        self.notify();
        self.settled_where(|p| pages.contains(&p));
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
        // Their memory goes with the copy (`Slots`): a writer may be reading one still.
        self.notify();
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
            "writer_claimed": get(&s.writer_claimed),
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
        // Slots of rescued copies taken here, reused once copied (on every return).
        let mut done = Done(&cow.slots, Vec::new());
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
                    RESCUING => cow.wait_rescued(p),
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
            let slot = match cow.rescued[p].swap(0, Ordering::SeqCst) {
                0 => {
                    cow.check_active()?;
                    crate::bail!("page {p}: rescued copy missing");
                }
                a => Slot(a as usize),
            };
            cow.rescued_bytes.fetch_sub(PAGE_SIZE, Ordering::SeqCst);
            buf[k * PAGE_SIZE..(k + 1) * PAGE_SIZE].copy_from_slice(slot.bytes());
            done.1.push(slot);
            cow.set(p, CLEAN);
        }
        Ok(())
    }

    fn wanted(&self) -> Option<usize> {
        self.cow.wanted.lock().unwrap().pop_front()
    }
}

impl Drop for Cow {
    fn drop(&mut self) {
        if let Some(home) = self.home.take() {
            let mut slots = std::mem::take(&mut self.slots);
            slots.trim();
            *home.lock().unwrap() = Some(slots);
        }
    }
}

/// A word a page, mapped on its own: zero until written, backed only where written, and set up in no time whatever
/// the guest's size. A heap allocation this large can be zeroed by hand (malloc's mmap threshold grows past the size
/// of what was freed last), which took up to 4 ms of a checkpoint's pause at 4 GiB.
struct Index(&'static [AtomicU64]);

impl Index {
    fn new(n: usize) -> Index {
        let len = (n * 8).max(1);
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE, -1, 0)
        };
        assert!(p != libc::MAP_FAILED, "mapping a copy index: {}", std::io::Error::last_os_error());
        Index(unsafe { std::slice::from_raw_parts(p.cast::<AtomicU64>(), n) })
    }
}

impl std::ops::Deref for Index {
    type Target = [AtomicU64];
    fn deref(&self) -> &[AtomicU64] {
        self.0
    }
}

impl Drop for Index {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.0.as_ptr() as *mut _, (self.0.len() * 8).max(1)) };
    }
}

/// Slots a writer copied out, given back when it is done.
struct Done<'a>(&'a Slots, Vec<Slot>);

impl Drop for Done<'_> {
    fn drop(&mut self) {
        self.0.give(std::mem::take(&mut self.1));
    }
}

/// Memory for one page's rescued copy, in `Slots`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot(usize);

impl Slot {
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.0 as *mut u8
    }

    /// Its contents. Only while it holds a copy: no one writes it then.
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0 as *const u8, PAGE_SIZE) }
    }
}

/// Rescued copies' memory, a page a slot, in chunks of `SLOT_CHUNK` faulted in whole when mapped (huge pages where the
/// kernel gives them): a rescue writes into memory that is there already, where a page fault on fresh memory costs
/// several µs here, more than copying the page (#630). Slots the writers are done with are reused. Unmapped only with
/// the copy (`Cow` dropped), so a writer never reads memory a stop took away.
#[derive(Default)]
pub struct Slots {
    /// The chunks mapped, and the slots of them free.
    inner: Mutex<SlotsInner>,
    /// How many chunks, read without the lock.
    mapped: AtomicUsize,
    room: Room,
    /// Slots taken and not given back, and the most at once.
    used: AtomicUsize,
    peak: AtomicUsize,
}

#[derive(Default)]
struct SlotsInner {
    chunks: Vec<usize>,
    free: Vec<Slot>,
}

const SLOT_CHUNK: usize = 2 << 20;
const MADV_POPULATE_WRITE: libc::c_int = 23;

/// What host memory rescue memory, hot pages' memory and writer buffers may still take, in MiB: what is available above
/// the host's reserve and the memory admission has granted and guests have yet to touch, as last read (`refresh`,
/// about every second), less what was taken since. One for the host, shared by its VM processes once `attach`ed
/// (`hostmem`), so VMs copying at once share it. Unknown (as it starts): no bound. That memory is not admitted like a
/// guest's (its copy would wait), so it keeps out of the reserve instead.
///
/// One word: the room (0 for no bound, else 1 more than it), what was taken since the last refresh, and the refresh's
/// epoch. A refresh reads MemAvailable, which shows memory taken before it once it is populated: it takes off again
/// what was taken since the refresh before (taken and not populated yet, or counted twice until the next), and no
/// more. Memory given back counts only within the epoch it was taken in: from the next refresh on MemAvailable shows it.
#[derive(Clone, Default)]
pub struct Room(Arc<RoomCell>);

#[derive(Default)]
struct RoomCell {
    local: AtomicU64,
    host: OnceLock<&'static crate::hostmem::Shared>,
}

/// When `Room` was taken from, to give back within (`Room::give`).
pub type Epoch = u16;

const FIELD: u64 = (1 << 24) - 1;
/// How often a host's room is refreshed, by whichever VM process comes first.
const REFRESH_GAP_MS: u64 = 900;

fn room_field(w: u64) -> u64 {
    w & FIELD
}

fn recent(w: u64) -> u64 {
    (w >> 24) & FIELD
}

fn epoch(w: u64) -> Epoch {
    (w >> 48) as Epoch
}

fn pack(epoch: Epoch, recent: u64, room: u64) -> u64 {
    (epoch as u64) << 48 | recent.min(FIELD) << 24 | room
}

/// The room field for `mib` (u64::MAX: no bound).
fn room_of(mib: u64) -> u64 {
    if mib == u64::MAX {
        0
    } else {
        mib.min(FIELD - 1) + 1
    }
}

impl Room {
    /// From now on the host's room (`hostmem`), shared with every VM process. Once; what was taken before is not
    /// counted there (the next refresh shows it).
    pub fn attach(&self, host: &'static crate::hostmem::Shared) {
        let _ = self.0.host.set(host);
    }

    fn word(&self) -> &AtomicU64 {
        self.0.host.get().map_or(&self.0.local, |h| &h.room)
    }

    /// Sets it to `mib` (u64::MAX: no bound), forgetting what was taken.
    #[cfg(test)]
    pub fn set(&self, mib: u64) {
        let _ = self.word().fetch_update(Ordering::SeqCst, Ordering::SeqCst, |w| Some(pack(epoch(w).wrapping_add(1), 0, room_of(mib))));
    }

    /// From what is available now (`mib`, read only for a refresh; None: unknown, no bound), less what was taken since
    /// the last refresh. The host's at most every `REFRESH_GAP_MS`: whichever process comes first refreshes it.
    pub fn refresh(&self, mib: impl FnOnce() -> Option<u64>) {
        if let Some(h) = self.0.host.get() {
            let (now, last) = (crate::host::boottime_ms(), h.stamp.load(Ordering::SeqCst));
            if now.wrapping_sub(last) < REFRESH_GAP_MS || h.stamp.compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                return;
            }
        }
        let mib = mib();
        let _ = self.word().fetch_update(Ordering::SeqCst, Ordering::SeqCst, |w| {
            Some(pack(epoch(w).wrapping_add(1), 0, mib.map_or(0, |m| room_of(m.saturating_sub(recent(w))))))
        });
    }

    pub fn get(&self) -> u64 {
        match room_field(self.word().load(Ordering::SeqCst)) {
            0 => u64::MAX,
            r => r - 1,
        }
    }

    /// Takes `mib` of it, if there is that much: when, to give it back (`give`).
    pub fn take(&self, mib: u64) -> Option<Epoch> {
        let mut at = 0;
        self.word()
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |w| {
                at = epoch(w);
                match room_field(w) {
                    0 => Some(w),
                    r if r - 1 < mib => None,
                    r => Some(pack(at, recent(w) + mib, r - mib)),
                }
            })
            .ok()
            .map(|_| at)
    }

    /// Gives back `mib` taken from it `at` (its memory is unmapped again, or never was): unless it was refreshed since,
    /// which counted it already.
    pub fn give(&self, mib: u64, at: Epoch) {
        let _ = self.word().fetch_update(Ordering::SeqCst, Ordering::SeqCst, |w| {
            let r = room_field(w);
            (epoch(w) == at && r != 0).then(|| pack(at, recent(w).saturating_sub(mib), (r + mib.min(FIELD)).min(FIELD)))
        });
    }
}

const CHUNK_MIB: u64 = (SLOT_CHUNK >> 20) as u64;

/// The MiB of chunks to map for `n` slots with `free` of them free.
fn short_mib(n: usize, free: usize) -> u64 {
    n.saturating_sub(free).div_ceil(SLOT_CHUNK / PAGE_SIZE) as u64 * CHUNK_MIB
}

impl Slots {
    /// Whether `take` would give `n` slots now: free ones, or room to map more (or `unbounded`).
    fn can_take(&self, n: usize, unbounded: bool) -> bool {
        let short = short_mib(n, self.inner.lock().unwrap().free.len());
        short == 0 || unbounded || self.room.get() >= short
    }

    pub fn mapped_bytes(&self) -> usize {
        self.mapped.load(Ordering::Relaxed) * SLOT_CHUNK
    }

    /// `n` slots, ascending where they come from a new chunk. None if there are not that many free and the host has no
    /// `room` to map more (but for `unbounded`): nothing is taken then.
    fn take(&self, n: usize, unbounded: bool) -> std::io::Result<Option<Vec<Slot>>> {
        let mut inner = self.inner.lock().unwrap();
        let short = short_mib(n, inner.free.len());
        if short > 0 && !unbounded && self.room.take(short).is_none() {
            return Ok(None);
        }
        while inner.free.len() < n {
            let c = map_chunk()?;
            inner.chunks.push(c);
            self.mapped.fetch_add(1, Ordering::Relaxed);
            // Descending: they are taken from the end.
            inner.free.extend((0..SLOT_CHUNK / PAGE_SIZE).rev().map(|i| Slot(c + i * PAGE_SIZE)));
        }
        let at = inner.free.len() - n;
        let mut out = inner.free.split_off(at);
        out.reverse();
        let used = self.used.fetch_add(n, Ordering::Relaxed) + n;
        self.peak.fetch_max(used, Ordering::Relaxed);
        Ok(Some(out))
    }

    fn give(&self, slots: Vec<Slot>) {
        if !slots.is_empty() {
            self.used.fetch_sub(slots.len(), Ordering::Relaxed);
            self.inner.lock().unwrap().free.extend(slots);
        }
    }

    /// Once nothing uses any slot (the copy is gone): keeps as many chunks as were in use at most at once, up to the
    /// budget of rescued copies (a held-back discard rescues past it, `Pager::save_rest`), none while the host has no
    /// room (under its reserve), every slot free, and forgets that most.
    fn trim(&mut self) {
        let inner = self.inner.get_mut().unwrap();
        let cap = if self.room.get() == 0 { 0 } else { (BUDGET_MIB << 20) / SLOT_CHUNK };
        let keep = self.peak.get_mut().div_ceil(SLOT_CHUNK / PAGE_SIZE).min(inner.chunks.len()).min(cap);
        for &c in &inner.chunks[keep..] {
            unsafe { libc::munmap(c as *mut _, SLOT_CHUNK) };
        }
        inner.chunks.truncate(keep);
        *self.mapped.get_mut() = keep;
        inner.free.clear();
        let chunks = &inner.chunks;
        inner.free.extend(chunks.iter().rev().flat_map(|&c| (0..SLOT_CHUNK / PAGE_SIZE).rev().map(move |i| Slot(c + i * PAGE_SIZE))));
        (*self.used.get_mut(), *self.peak.get_mut()) = (0, 0);
    }

    #[cfg(test)]
    fn mapped(&self) -> usize {
        self.mapped_bytes() / PAGE_SIZE
    }
}

impl Drop for Slots {
    fn drop(&mut self) {
        for &c in self.inner.get_mut().unwrap().chunks.iter() {
            unsafe { libc::munmap(c as *mut _, SLOT_CHUNK) };
        }
    }
}

/// `SLOT_CHUNK` of anonymous memory, aligned to it (so it can be a huge page) and populated.
fn map_chunk() -> std::io::Result<usize> {
    let len = 2 * SLOT_CHUNK;
    let p = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
    if p == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    let (start, end) = (p as usize, p as usize + len);
    let c = start.next_multiple_of(SLOT_CHUNK);
    unsafe {
        if c > start {
            libc::munmap(start as *mut _, c - start);
        }
        if end > c + SLOT_CHUNK {
            libc::munmap((c + SLOT_CHUNK) as *mut _, end - c - SLOT_CHUNK);
        }
        libc::madvise(c as *mut _, SLOT_CHUNK, libc::MADV_HUGEPAGE);
        if libc::madvise(c as *mut _, SLOT_CHUNK, MADV_POPULATE_WRITE) != 0 {
            (0..SLOT_CHUNK).step_by(PAGE_SIZE).for_each(|o| ((c + o) as *mut u8).write_volatile(0));
        }
    }
    Ok(c)
}

#[cfg(test)]
impl Cow {
    /// As once a writer has started reading pages.
    pub fn start_writing(&self) {
        self.writing.store(true, Ordering::SeqCst);
    }

    /// The pages faults asked the writers for, first first.
    pub fn wanted_pages(&self) -> Vec<usize> {
        self.wanted.lock().unwrap().iter().copied().collect()
    }

    /// Rescued copies held now.
    pub fn rescued_mib(&self) -> f64 {
        self.rescued_bytes.load(Ordering::SeqCst) as f64 / (1 << 20) as f64
    }

    /// `rescue_many` from copies in hand.
    pub fn rescue_copies(&self, first: usize, end: usize, pages: impl IntoIterator<Item = (usize, Box<[u8]>)>) {
        let pages: Vec<(usize, Box<[u8]>)> = pages.into_iter().collect();
        let slots = self.take_slots(pages.len()).unwrap().unwrap();
        for ((_, copy), slot) in pages.iter().zip(&slots) {
            unsafe { std::ptr::copy_nonoverlapping(copy.as_ptr(), slot.as_mut_ptr(), PAGE_SIZE) };
        }
        self.rescue_many(first, end, pages.iter().map(|p| p.0).zip(slots));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// VM processes copying at once share the host's room (#648): one's take is the others' too, so together they
    /// never take more than there is.
    #[test]
    fn the_host_room_is_shared_by_its_vm_processes() {
        let dir = crate::test_util::TempDir::new("room");
        let host = crate::hostmem::at(&dir).unwrap();
        let (a, b) = (Room::default(), Room::default());
        a.attach(host);
        b.attach(host);
        // Unknown until refreshed: no bound, and nothing debited.
        assert_eq!(a.get(), u64::MAX);
        assert!(a.take(1 << 30).is_some());
        assert_eq!(b.get(), u64::MAX);
        let due = || host.stamp.store(crate::host::boottime_ms().wrapping_sub(REFRESH_GAP_MS), Ordering::SeqCst);
        due();
        a.refresh(|| Some(100));
        assert_eq!(b.get(), 100);
        // Refreshed by whichever process comes first, at most every REFRESH_GAP_MS for the host.
        b.refresh(|| panic!("not due: MemAvailable is not read"));
        assert!(a.take(60).is_some());
        assert!(b.take(60).is_none(), "taken by the other already");
        let at = b.take(40).unwrap();
        assert_eq!(a.get(), 0);
        b.give(40, at);
        assert_eq!(a.get(), 40, "given back within its epoch");
        // A refresh takes off what was taken since the one before (it may not show in MemAvailable yet)...
        due();
        b.refresh(|| Some(100));
        assert_eq!(a.get(), 40);
        // ...and no more after the next, by which it does.
        due();
        b.refresh(|| Some(100));
        assert_eq!(a.get(), 100);
        // Given back once refreshed: MemAvailable shows it freed, so it is not counted twice.
        let at = a.take(10).unwrap();
        due();
        a.refresh(|| Some(50));
        a.give(10, at);
        assert_eq!(b.get(), 40);
        // A process not attached keeps its own.
        let own = Room::default();
        own.set(5);
        assert_eq!((own.get(), a.get()), (5, 40));
        assert!(own.take(5).is_some() && own.take(1).is_none());
    }

    /// A non-blocking eventfd, for a waker.
    fn eventfd() -> OwnedFd {
        use std::os::fd::FromRawFd;
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(fd >= 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    /// The wakes `fd` counted since last read; none if it was not woken.
    fn wakes(fd: &OwnedFd) -> Option<u64> {
        let mut n = 0u64;
        (unsafe { libc::read(fd.as_raw_fd(), (&mut n as *mut u64).cast(), 8) } == 8).then_some(n)
    }

    #[test]
    fn unclaim_many_wakes_once() {
        let fd = eventfd();
        let cow = Arc::new(Cow::new(8, &vec![(0, 8, REMOTE)]));
        cow.set_waker(fd.try_clone().unwrap());
        for p in [1, 3, 5] {
            assert!(cow.claim(p, PENDING, RESCUING));
            cow.wait_for(p, RESCUING);
        }
        let writers: Vec<_> = [1, 5]
            .into_iter()
            .map(|p| {
                let cow = cow.clone();
                std::thread::spawn(move || cow.wait_rescued(p))
            })
            .collect();
        cow.unclaim_many(&[1, 5]);
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(cow.notifications.load(Ordering::SeqCst), 1);
        assert_eq!((cow.state(1), cow.state(3), cow.state(5)), (PENDING, RESCUING, PENDING));
        assert_eq!(*cow.waits.lock().unwrap(), [3]);
        assert_eq!(wakes(&fd), Some(1), "one event-thread wake for the whole batch");
    }

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
        cow.rescue_copies(3, 4, [(3, vec![3u8; PAGE_SIZE].into())]);
        live.pages.lock().unwrap()[3 * PAGE_SIZE..4 * PAGE_SIZE].fill(0xee);
        // Page 5 is being saved by a fault while the writer gets there.
        assert!(cow.claim(5, PENDING, RESCUING));
        assert!(!cow.claim(5, PENDING, READING), "one saver per page");
        let pages = CowPages { guest: &live, cow: &cow, slow: || Duration::ZERO };
        let mut buf = vec![0u8; 8 * PAGE_SIZE];
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                cow.rescue_copies(5, 6, [(5, vec![5u8; PAGE_SIZE].into())]);
            });
            pages.read(0, &mut buf).unwrap();
        });
        for (i, p) in buf.chunks(PAGE_SIZE).enumerate() {
            assert!(p.iter().all(|&b| b == i as u8), "page {i} has its pause-time contents");
        }
        assert_eq!(cow.left(), 32);
        assert_eq!(cow.rescued_bytes.load(Ordering::SeqCst), 0, "rescued copies are dropped once written");
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

    /// A writer that meets a page RESCUING parks until the rescue keeps its copy, gives it back, or the copy stops.
    #[test]
    fn writer_parked_on_a_rescue_wakes() {
        for end in ["rescued", "unclaimed", "stopped"] {
            let cow = Cow::new(1, &vec![(0, 1, REMOTE)]);
            let live = Live { pages: StdMutex::new(vec![9u8; PAGE_SIZE]) };
            assert!(cow.claim(0, PENDING, RESCUING));
            let pages = CowPages { guest: &live, cow: &cow, slow: || Duration::ZERO };
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::scope(|s| {
                s.spawn(|| {
                    let mut buf = vec![0u8; PAGE_SIZE];
                    let r = pages.read(0, &mut buf).map(|()| buf[0]);
                    tx.send(r.map_err(|e| e.to_string())).unwrap();
                });
                assert!(rx.recv_timeout(Duration::from_millis(100)).is_err(), "{end}: the writer waits for the rescue");
                match end {
                    "rescued" => cow.rescue_copies(0, 1, [(0, vec![1u8; PAGE_SIZE].into())]),
                    "unclaimed" => cow.unclaim(0),
                    _ => cow.stop(),
                }
                let r = rx.recv_timeout(Duration::from_secs(5)).expect("the writer is woken");
                match end {
                    "rescued" => assert_eq!(r, Ok(1), "the rescued copy"),
                    "unclaimed" => assert_eq!(r, Ok(9), "read by the writer itself"),
                    _ => assert!(r.unwrap_err().contains("stopped")),
                }
            });
        }
    }

    #[test]
    fn batched_rescue_keeps_each_pause_time_copy() {
        let cow = Cow::new(6, &vec![(0, 6, REMOTE)]);
        let live = Live { pages: StdMutex::new((0..6 * PAGE_SIZE).map(|i| (i / PAGE_SIZE) as u8).collect()) };
        let fd = eventfd();
        cow.set_waker(fd.try_clone().unwrap());
        let claimed = [1, 3, 4];
        for p in claimed {
            assert!(cow.claim(p, PENDING, RESCUING));
        }
        cow.wait_for(1, RESCUING);
        cow.wait_for(4, RESCUING);
        cow.rescue_copies(1, 5, claimed.map(|p| (p, vec![p as u8; PAGE_SIZE].into())));
        assert_eq!(wakes(&fd), Some(1), "one wake for the whole batch");
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
        assert_eq!(cow.rescued_bytes.load(Ordering::SeqCst), 0);
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

    /// Rescue memory is reused, and kept for the next copy as much of it as one used at most at once.
    #[test]
    fn rescue_memory_is_reused_and_kept_by_peak_use() {
        let home = Arc::new(Mutex::new(None));
        let per = SLOT_CHUNK / PAGE_SIZE;
        {
            let cow = Cow::new(4, &vec![(0, 4, REMOTE)]).keep_slots(home.clone(), Room::default());
            let a = cow.take_slots(per + 1).unwrap().unwrap();
            assert_eq!(cow.slots.mapped(), 2 * per);
            assert!(a.windows(2).take(per - 1).all(|w| w[1].0 == w[0].0 + PAGE_SIZE), "ascending within a chunk");
            cow.give_slots(a);
            let b = cow.take_slots(2 * per).unwrap().unwrap();
            assert_eq!(cow.slots.mapped(), 2 * per, "freed slots reused");
            cow.give_slots(b);
            // Taken and never given back (a copy that failed): still free for the next copy.
            let _lost = cow.take_slots(3).unwrap().unwrap();
        }
        assert_eq!(home.lock().unwrap().as_ref().unwrap().mapped(), 2 * per);
        {
            let cow = Cow::new(4, &vec![(0, 4, REMOTE)]).keep_slots(home.clone(), Room::default());
            assert!(home.lock().unwrap().is_none(), "one copy at a time uses it");
            let a = cow.take_slots(2 * per).unwrap().unwrap();
            assert_eq!(cow.slots.mapped(), 2 * per, "all of it free again");
            cow.give_slots(a);
            let a = cow.take_slots(1).unwrap().unwrap();
            cow.give_slots(a);
        }
        // This copy used both chunks at once: kept.
        assert_eq!(home.lock().unwrap().as_ref().unwrap().mapped(), 2 * per);
        {
            let cow = Cow::new(4, &vec![(0, 4, REMOTE)]).keep_slots(home.clone(), Room::default());
            let a = cow.take_slots(10).unwrap().unwrap();
            cow.give_slots(a);
        }
        assert_eq!(home.lock().unwrap().as_ref().unwrap().mapped(), per, "trimmed to the last copy's peak");
        {
            let _idle = Cow::new(4, &vec![(0, 4, REMOTE)]).keep_slots(home.clone(), Room::default());
        }
        assert_eq!(home.lock().unwrap().as_ref().unwrap().mapped(), 0, "an idle copy keeps none");
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
            cow.rescue_copies(1, 2, [(1, vec![1u8; PAGE_SIZE].into())]);
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
                    cow.rescued[1].swap(0, Ordering::SeqCst);
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
        let efd = eventfd();
        let woken = || wakes(&efd).is_some();
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
