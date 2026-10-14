//! Userfaultfd pager for Firecracker guest memory.
//!
//! Every page of guest memory is in one of a few states, so a VM can be backed
//! by any mix of a shared template image, zero pages and pages still living on
//! its origin:
//!
//!   BASE      -> copied from the template memory file (holes map the zero page)
//!   ZERO      -> discarded by the guest (balloon / virtio-mem); maps the zero page
//!   REMOTE    -> fetched from the migration source's page server, or the page
//!                file of a checkpoint being restored
//!   INFLIGHT  -> claimed by one installer; its UFFDIO_COPY wakes any waiters
//!   DISCARDED -> INFLIGHT, but a REMOVE hit it; its installer must not publish it
//!   PRESENT   -> populated in this VM, the only copy is inside Firecracker
//!
//! A page leaves BASE, ZERO or REMOTE only by being claimed; its claimant
//! installs it and then settles it, so an install that raced a REMOVE never
//! overwrites the newer state (see `Pages`). PRESENT pages are read out of the
//! paused Firecracker with process_vm_readv when this host is a migration source.
//!
//! Write tracking: once a VM has been checkpointed while running, its memory is
//! also registered for write-protect faults (no UFFDIO_API feature needed), and
//! every populated page is protected at each checkpoint's pause. Write faults,
//! installs and discards mark pages dirty, so the next checkpoint can save only
//! those, and a running VM's checkpoint saves pages before the guest overwrites
//! them (see `cow`).

use std::collections::VecDeque;
use std::io::{self, IoSliceMut, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock, RwLockWriteGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::bail;
use crate::checkpoint::PageFile;
use crate::cow::{Cow, PENDING, READING, RESCUING};
use crate::template::Template;
use crate::util::{Result, PAGE_SIZE};

pub const BASE: u8 = 0;
pub const PRESENT: u8 = 1;
pub const ZERO: u8 = 2;
pub const REMOTE: u8 = 3;
pub const INFLIGHT: u8 = 4;
pub const DISCARDED: u8 = 5;

/// Pages copied per sequential template fault (see `Pager::template_next`).
pub const FAULT_AROUND: usize = 16;
/// Pages claimed per prefetch copy; faults on them wait for it.
const PREFETCH_RUN: usize = 256;
const REMOTE_FAULT_RUN: usize = 64;
const PULL_RUN: usize = 256;
const PULL_THREADS: usize = 4;
/// Threads fetching pages for faults, each with its own connection.
const FAULT_FETCHERS: usize = 8;
/// Fetched pages are installed as they arrive: the first at once, then at
/// least this many at a time.
const STREAM_RUN: usize = 16;
/// Why a pager stopped whose Firecracker unmapped guest memory or exited.
const GONE: &str = "firecracker unmapped guest memory";
/// How long Firecracker has, once it unmapped guest memory, to exit or answer
/// the request that failed, before the pager kills it.
const UNMAPPED_GRACE: Duration = Duration::from_secs(2);
/// Largest read a page server serves: the largest any pager asks for.
pub const MAX_FETCH: usize = PULL_RUN * PAGE_SIZE;
const _: () = assert!(REMOTE_FAULT_RUN <= PULL_RUN && PREFETCH_RUN <= PULL_RUN);
/// How long a page-server connection may idle while its VM is still a
/// migration source; a client that comes back later just reconnects.
const SERVE_IDLE: Duration = Duration::from_secs(600);
const SERVE_WRITE: Duration = Duration::from_secs(30);
/// How long a fault may keep failing (other than EAGAIN) before the pager gives up.
const FAULT_TIMEOUT: Duration = Duration::from_secs(1);
/// How long the migration source may stay unreachable before the pager gives up.
const SOURCE_TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_MIN: Duration = Duration::from_millis(10);
const BACKOFF_MAX: Duration = Duration::from_secs(1);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// From linux/userfaultfd.h.
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
const UFFD_EVENT_REMOVE: u8 = 0x15;
const UFFD_PAGEFAULT_FLAG_WP: u64 = 2;
const UFFDIO_REGISTER: libc::c_ulong = 0xC020_AA00;
const UFFDIO_WAKE: libc::c_ulong = 0x8010_AA02;
const UFFDIO_COPY: libc::c_ulong = 0xC028_AA03;
const UFFDIO_ZEROPAGE: libc::c_ulong = 0xC020_AA04;
const UFFDIO_WRITEPROTECT: libc::c_ulong = 0xC018_AA06;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
const UFFDIO_REGISTER_MODE_WP: u64 = 2;
const UFFDIO_WRITEPROTECT_MODE_WP: u64 = 1;
const UFFDIO_COPY_MODE_WP: u64 = 2;
/// Pages a write-protect fault unprotects (and saves first, during a copy).
const WP_BLOCK: usize = 16;
/// Merge protect ranges across gaps up to this many pages: one more protect
/// call costs about as much as the kernel walking this many populated pages
/// (about 19 µs a call, 70-90 ms per GiB populated, here).
const PROTECT_GAP: usize = 64;
/// Up to this many ranges in a region are protected one by one without
/// looking further; past it, see `Pager::freeze`.
const PROTECT_RUNS: usize = 256;
/// Threads copying unsaved pages into memory while a discard is held back.
const SAVE_REST_THREADS: usize = 8;
/// Pages write-protected per call while the VM runs (2 MiB).
const ARM_CHUNK: usize = 512;

static ZEROES: [u8; PAGE_SIZE] = [0; PAGE_SIZE];

/// One guest memory region, as Firecracker describes it in the UFFD handshake.
#[derive(Debug, Clone, Deserialize)]
pub struct Mapping {
    pub base_host_virt_addr: u64,
    pub size: usize,
    pub offset: u64,
}

impl Mapping {
    /// Its pages, as `[first, end)`.
    fn span(&self) -> (usize, usize) {
        (self.offset as usize / PAGE_SIZE, (self.offset as usize + self.size) / PAGE_SIZE)
    }
}

/// Initial page states for a VM migrating in: runs of `[first_page, count, state]`.
pub type Runs = Vec<(u64, u64, u8)>;

/// Where an incoming VM's remote pages live: the source daemon, the VM's
/// name there and the migration that moves it.
#[derive(Debug, Clone)]
pub struct Source {
    pub addr: String,
    pub vm: String,
    pub mig: u64,
    /// The source's guest memory regions as `(offset, size)`; the target's
    /// must be the same, or the page map would not cover the saved state.
    pub regions: Vec<(u64, u64)>,
}

/// Where a VM's REMOTE pages come from.
#[derive(Clone)]
pub enum Origin {
    /// The paused source of an incoming migration.
    Peer(Source),
    /// The page file of a checkpoint on this host, its reads verified against
    /// the block checksums; a failed read is fatal.
    File(Arc<PageFile>),
}

fn os(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

/// The page state machine. Installers claim pages (-> INFLIGHT), populate
/// them and settle them; a REMOVE on a claimed page turns it DISCARDED, and
/// its installer then skips it.
///
/// No data copy can land in a page after a REMOVE of it: the kernel fails
/// copies with EAGAIN while a REMOVE event is queued, the event is read and
/// applied under `events` held exclusively, and installers hold it shared from
/// checking a page's state until they have settled it. After that a removed
/// page is ZERO, which only ever gets zero-filled.
///
/// The kernel zaps the range only after the event is read, though, and not
/// under any lock of ours, so a page can still go missing after it settled
/// PRESENT (say a zero-fill that hit EEXIST on the old mapping just before the
/// zap). That can only happen to a page the guest gave back, so a fault on a
/// PRESENT page zero-fills it if it is missing.
#[derive(Default)]
pub struct Pages {
    states: Vec<AtomicU8>,
    /// One bit per `CHUNK` pages: set once any of them may have left BASE,
    /// so scans skip untouched stretches without reading (and faulting in)
    /// their part of `states`.
    touched: Vec<AtomicU64>,
    events: RwLock<()>,
    /// One bit per page: its contents may have changed since the last
    /// checkpoint's pause (written after a write-protect fault, installed, or
    /// discarded). See `Pager::freeze`.
    dirty: Vec<AtomicU64>,
    /// Set while faults wait for claimed pages to settle: installers then
    /// signal `wake` (an eventfd the event thread polls) when they settle any.
    waiting: AtomicBool,
    wake: OnceLock<OwnedFd>,
    /// Bumped (and `read_cv` notified) each time the event thread has read
    /// and applied events: an install that hit EAGAIN, because a REMOVE was
    /// queued, waits for that rather than polling.
    read_gen: AtomicU64,
    read_lock: Mutex<()>,
    read_cv: Condvar,
    pub install_eagain: AtomicU64,
    /// Pages faults wait on, and when a copy into them woke the faulting
    /// threads: what their latency counts to (`FaultStats`).
    parked: Mutex<Vec<(usize, Option<Instant>)>>,
    /// REMOTE pages whose install failed and that are not in yet, with since
    /// when: whoever claims them next inherits the deadline.
    failing: Mutex<Vec<(usize, Instant)>>,
    failing_len: AtomicUsize,
}

/// Pages per `touched` bit: one page of `states`.
const CHUNK: usize = 4096;

impl Pages {
    pub fn new(n: usize) -> Pages {
        // BASE is 0, so a zeroed allocation (lazily backed by the kernel) is the initial state.
        let states = unsafe { std::mem::transmute::<Vec<u8>, Vec<AtomicU8>>(vec![0u8; n]) };
        let dirty = unsafe { std::mem::transmute::<Vec<u64>, Vec<AtomicU64>>(vec![0u64; n.div_ceil(64)]) };
        let touched = (0..n.div_ceil(CHUNK * 64)).map(|_| AtomicU64::new(0)).collect();
        Pages { states, touched, dirty, ..Pages::default() }
    }

    /// A fault read at `read` waits for `page` to be installed.
    fn park(&self, page: usize, read: Instant) {
        let mut parked = self.parked.lock().unwrap();
        match parked.iter_mut().find(|(p, _)| *p == page) {
            Some((_, woke)) => {
                if woke.is_some_and(|t| t < read) {
                    *woke = None;
                }
            }
            None => parked.push((page, None)),
        }
    }

    /// When a copy woke a fault read at `read` that waited for `page`, if one did.
    fn unpark(&self, page: usize, read: Instant) -> Option<Instant> {
        let mut parked = self.parked.lock().unwrap();
        let i = parked.iter().position(|(p, _)| *p == page)?;
        parked.swap_remove(i).1.filter(|&t| t >= read)
    }

    /// Pages `first..first + n` were just copied in, which woke whoever waited on them.
    fn woke(&self, first: usize, n: usize) {
        if !self.waiting.load(Ordering::SeqCst) {
            return;
        }
        let mut parked = self.parked.lock().unwrap();
        let now = Instant::now();
        for (_, woke) in parked.iter_mut().filter(|(p, w)| (first..first + n).contains(p) && w.is_none()) {
            *woke = Some(now);
        }
    }

    /// Tells a waiting event thread that claimed pages settled.
    fn settled(&self) {
        if let Some(fd) = self.wake.get().filter(|_| self.waiting.load(Ordering::SeqCst)) {
            unsafe { libc::write(fd.as_raw_fd(), (&1u64 as *const u64).cast(), 8) };
        }
    }

    /// The event thread has read and applied events.
    fn events_read(&self) {
        self.read_gen.fetch_add(1, Ordering::SeqCst);
        let _guard = self.read_lock.lock().unwrap();
        self.read_cv.notify_all();
    }

    /// After an install hit EAGAIN (a REMOVE is queued, and the kernel fails
    /// copies until the event thread has read it): waits until events were
    /// read since `seen` (`read_gen` before the copy), or if they were
    /// already, briefly, for the kernel to finish with them.
    fn wait_events_read(&self, seen: u64) {
        self.install_eagain.fetch_add(1, Ordering::Relaxed);
        if self.read_gen.load(Ordering::SeqCst) != seen {
            thread::sleep(Duration::from_micros(20));
            return;
        }
        let guard = self.read_lock.lock().unwrap();
        // Bounded: the event thread may itself be waiting for something.
        let _ = self.read_cv.wait_timeout_while(guard, Duration::from_millis(1), |_| self.read_gen.load(Ordering::SeqCst) == seen);
    }

    pub fn mark_dirty(&self, page: usize) {
        if let Some(w) = self.dirty.get(page / 64) {
            w.fetch_or(1 << (page % 64), Ordering::SeqCst);
        }
    }

    /// The dirty bits, cleared with `take`.
    fn dirty_bits(&self, take: bool) -> Vec<u64> {
        self.dirty.iter().map(|w| if take { w.swap(0, Ordering::SeqCst) } else { w.load(Ordering::SeqCst) }).collect()
    }

    /// Marks dirty again what `dirty_bits` took.
    fn restore_dirty(&self, bits: &[u64]) {
        for (w, &b) in self.dirty.iter().zip(bits) {
            w.fetch_or(b, Ordering::SeqCst);
        }
    }

    pub fn get(&self, page: usize) -> u8 {
        self.states[page].load(Ordering::SeqCst)
    }

    fn set(&self, page: usize, state: u8) {
        self.touch(page);
        self.states[page].store(state, Ordering::SeqCst)
    }

    /// Marks `page`'s chunk before its state leaves BASE.
    fn touch(&self, page: usize) {
        let c = page / CHUNK;
        let bit = 1u64 << (c % 64);
        if self.touched[c / 64].load(Ordering::Relaxed) & bit == 0 {
            self.touched[c / 64].fetch_or(bit, Ordering::SeqCst);
        }
    }

    fn touched(&self, page: usize) -> bool {
        let c = page / CHUNK;
        self.touched[c / 64].load(Ordering::SeqCst) & (1 << (c % 64)) != 0
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// The first page in `[from, end)` not in `state`, or `end`. For BASE,
    /// skips chunks that never left it without reading them: a VM's map is
    /// mostly BASE (the unplugged virtio-mem region alone is millions of
    /// pages), and a migration scans it with the VM paused.
    pub fn next_not(&self, state: u8, mut from: usize, end: usize) -> usize {
        let end = end.min(self.states.len());
        while from < end {
            if state == BASE && from % CHUNK == 0 && !self.touched(from) {
                from += CHUNK;
                continue;
            }
            if self.states[from].load(Ordering::Relaxed) != state {
                return from;
            }
            from += 1;
        }
        end
    }

    /// The pages in `[from, end)` not in state BASE, in order.
    fn not_base(&self, from: usize, end: usize) -> impl Iterator<Item = usize> + '_ {
        let end = end.min(self.states.len());
        let next = move |i: usize| Some(self.next_not(BASE, i, end)).filter(|&i| i < end);
        std::iter::successors(next(from), move |&i| next(i + 1))
    }

    /// The first page in `[from, end)` in `state` (not BASE), or `end`.
    pub fn next_in(&self, state: u8, from: usize, end: usize) -> usize {
        self.not_base(from, end).find(|&i| self.states[i].load(Ordering::Relaxed) == state).unwrap_or(end.min(self.len()))
    }

    /// How many pages in `[from, end)` are in `state` (not BASE).
    pub fn count(&self, state: u8, from: usize, end: usize) -> usize {
        self.not_base(from, end).filter(|&i| self.states[i].load(Ordering::Relaxed) == state).count()
    }

    /// Held while reading and applying uffd events; required by `discard`.
    pub fn removing(&self) -> RwLockWriteGuard<'_, ()> {
        self.events.write().unwrap()
    }

    /// Claims up to `max` consecutive pages from `first` that are in state
    /// `from` and pass `ok`. Returns how many it claimed.
    pub fn claim(&self, first: usize, max: usize, from: u8, ok: impl Fn(usize) -> bool) -> usize {
        let mut n = 0;
        while n < max && first + n < self.states.len() && ok(first + n) {
            if from == BASE {
                self.touch(first + n);
            }
            if self.states[first + n].compare_exchange(from, INFLIGHT, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                break;
            }
            n += 1;
        }
        n
    }

    /// Applies a REMOVE of `page`. Returns whether it resolved a REMOTE page.
    pub fn discard(&self, _removing: &RwLockWriteGuard<'_, ()>, page: usize) -> bool {
        self.touch(page);
        let claimed = |s| s == INFLIGHT || s == DISCARDED;
        let old = self.states[page].fetch_update(Ordering::SeqCst, Ordering::SeqCst, |s| Some(if claimed(s) { DISCARDED } else { ZERO }));
        self.mark_dirty(page);
        if !claimed(old.unwrap()) {
            self.forget_failure(page);
        }
        old == Ok(REMOTE)
    }

    /// Claimed REMOTE `page` failed to install: notes since when, unless it
    /// already kept failing. Only while it is claimed, so never after it was
    /// resolved.
    fn note_failure(&self, page: usize) {
        let mut failing = self.failing.lock().unwrap();
        if !failing.iter().any(|(p, _)| *p == page) {
            failing.push((page, Instant::now()));
            self.failing_len.store(failing.len(), Ordering::SeqCst);
        }
    }

    /// `page` is in (or gone): it no longer keeps failing.
    fn forget_failure(&self, page: usize) {
        if self.failing_len.load(Ordering::SeqCst) > 0 {
            let mut failing = self.failing.lock().unwrap();
            failing.retain(|(p, _)| *p != page);
            self.failing_len.store(failing.len(), Ordering::SeqCst);
        }
    }

    /// Since when some page of `first..first + n` has kept failing to install.
    pub fn failing_since(&self, first: usize, n: usize) -> Option<Instant> {
        if self.failing_len.load(Ordering::SeqCst) == 0 {
            return None;
        }
        let failing = self.failing.lock().unwrap();
        failing.iter().filter(|(p, _)| (first..first + n).contains(p)).map(|(_, t)| *t).min()
    }

    /// Settles claimed `page`, claimed from state `from`. Returns whether a
    /// REMOTE page got resolved, for the pager's count of pages to pull.
    fn settle(&self, page: usize, populated: bool, from: u8) -> bool {
        let old = self.states[page]
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |s| {
                Some(match (s, populated) {
                    (_, true) => PRESENT,
                    (DISCARDED, false) => ZERO,
                    (_, false) => from,
                })
            })
            .unwrap();
        debug_assert!(old == INFLIGHT || (old == DISCARDED && !populated), "settling page {page} in state {old}");
        if populated {
            // Installed writable: it may change without a fault from now on.
            self.mark_dirty(page);
        }
        if populated || old == DISCARDED {
            self.forget_failure(page);
        }
        from == REMOTE && (populated || old == DISCARDED)
    }

    /// Gives back claimed pages without installing them.
    pub fn release(&self, first: usize, n: usize, from: u8) -> usize {
        let resolved = (first..first + n).filter(|&p| self.settle(p, false, from)).count();
        self.settled();
        resolved
    }

    /// Installs claimed pages `[first, first + n)` with `populate(page, count)`,
    /// which returns how many pages from `page` it populated (UFFDIO_COPY may
    /// stop part way) and wakes their waiters. Pages discarded before their
    /// copy are skipped; EEXIST counts as populated. EAGAIN is retried until
    /// `stop` is set, or without `stop` ends the install. Unfinished pages are
    /// given back. Returns the REMOTE pages resolved and the error, if any.
    pub fn install(
        &self,
        first: usize,
        n: usize,
        from: u8,
        stop: Option<&AtomicBool>,
        mut populate: impl FnMut(usize, usize) -> io::Result<usize>,
    ) -> (usize, io::Result<()>) {
        let (end, mut resolved, mut i) = (first + n, 0, first);
        while i < end {
            let installing = self.events.read().unwrap();
            if self.get(i) == DISCARDED {
                resolved += self.settle(i, false, from) as usize;
                i += 1;
                continue;
            }
            let m = (i + 1..end).find(|&p| self.get(p) != INFLIGHT).unwrap_or(end) - i;
            let gen = self.read_gen.load(Ordering::SeqCst);
            match populate(i, m) {
                Ok(done) => {
                    let done = done.clamp(1, m);
                    self.woke(i, done);
                    resolved += (i..i + done).filter(|&p| self.settle(p, true, from)).count();
                    i += done;
                }
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    resolved += self.settle(i, true, from) as usize;
                    i += 1;
                }
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) && stop.is_some_and(|s| !s.load(Ordering::SeqCst)) => {
                    drop(installing);
                    self.wait_events_read(gen)
                }
                Err(e) => {
                    if from == REMOTE {
                        self.note_failure(i);
                    }
                    return (resolved + self.release(i, end - i, from), Err(e));
                }
            }
        }
        self.settled();
        (resolved, Ok(()))
    }

    /// Fetches claimed REMOTE pages `first..first + n` with `fetch` (into
    /// `buf`) and installs them as they arrive with `populate(page, count,
    /// data)` (as `install` does): the first one as soon as it is in, as a
    /// fault waits for it, then at least `STREAM_RUN` at a time, so that a
    /// fault on any of them waits only for its part of the transfer. A failed
    /// fetch is tried again, for what has yet to arrive, while `retry` says
    /// so. Pages it does not install are given back. Returns the REMOTE pages
    /// resolved, and the error that stopped it.
    #[allow(clippy::too_many_arguments)]
    fn fetch_install(
        &self,
        first: usize,
        n: usize,
        buf: &mut [u8],
        fetch: &mut FetchAny<'_>,
        stop: &AtomicBool,
        retry: &mut dyn FnMut(&io::Error) -> bool,
        mut populate: impl FnMut(usize, usize, &[u8]) -> io::Result<usize>,
    ) -> (usize, std::result::Result<(), Failed>) {
        // Installs pages `from..to` (counted from `first`) out of `data`,
        // which holds them from page `base` on.
        let mut install = |from: usize, to: usize, data: &[u8], base: usize| {
            let src = |p: usize, c: usize| &data[(p - first - base) * PAGE_SIZE..(p - first - base + c) * PAGE_SIZE];
            self.install(first + from, to - from, REMOTE, Some(stop), |p, c| populate(p, c, src(p, c)))
        };
        // Pages from `first` installed (or given back by a failed install).
        let (mut done, mut resolved) = (0, 0);
        let mut failed: Option<io::Error> = None;
        loop {
            let base = done;
            let fetched = fetch(((first + base) * PAGE_SIZE) as u64, &mut buf[base * PAGE_SIZE..n * PAGE_SIZE], stop, &mut |data| {
                let ready = base + data.len() / PAGE_SIZE;
                if failed.is_none() && ready > done && (done == 0 || ready - done >= STREAM_RUN) {
                    let (r, res) = install(done, ready, data, base);
                    resolved += r;
                    failed = res.err();
                    done = ready;
                }
                // A failed install stops the fetch at once: what is still to
                // come would only be given back.
                failed.is_none()
            });
            match fetched {
                _ if failed.is_some() => break,
                Ok(()) => {
                    if done < n {
                        let (r, res) = install(done, n, &buf[..n * PAGE_SIZE], 0);
                        resolved += r;
                        failed = res.err();
                        done = n;
                    }
                    break;
                }
                Err(e) if done < n && retry(&e) => {}
                Err(e) => return (resolved + self.release(first + done, n - done, REMOTE), Err(Failed::Fetch(e))),
            }
        }
        match failed {
            None => (resolved, Ok(())),
            Some(e) => (resolved + self.release(first + done, n - done, REMOTE), Err(Failed::Install(e))),
        }
    }
}

/// Fault service latency kinds: faults served from the template, zero or a
/// present page; that had their run fetched from the origin; that waited for
/// another installer; write-protect faults. Then not faults: fetching and
/// installing each fault's run, each background pull run, how long a fault's
/// run waited for a fetcher, and until its first page went in.
const KINDS: [&str; 8] = ["local", "remote", "wait", "wp", "fetch", "pull", "queued", "first"];
const LOCAL: usize = 0;
const FETCHED: usize = 1;
const WAITED: usize = 2;
const WP: usize = 3;
const FETCH: usize = 4;
const PULL: usize = 5;
const QUEUED: usize = 6;
const FIRST: usize = 7;
/// Histogram buckets per doubling of latency: 1 << SUB_BITS.
const SUB_BITS: u32 = 2;
const BUCKETS: usize = 40 << SUB_BITS;

/// How long faults took to serve, from reading the event to resolving it,
/// per kind: counts, sums and a log-scale histogram (19% resolution).
pub struct FaultStats {
    kinds: [Kind; KINDS.len()],
}

struct Kind {
    sum_ns: AtomicU64,
    max_ns: AtomicU64,
    hist: [AtomicU64; BUCKETS],
}

impl FaultStats {
    fn new() -> FaultStats {
        let kind = || Kind { sum_ns: AtomicU64::new(0), max_ns: AtomicU64::new(0), hist: std::array::from_fn(|_| AtomicU64::new(0)) };
        FaultStats { kinds: std::array::from_fn(|_| kind()) }
    }

    fn record(&self, kind: usize, took: Duration) {
        let ns = (took.as_nanos() as u64).max(1);
        let k = &self.kinds[kind];
        k.sum_ns.fetch_add(ns, Ordering::Relaxed);
        k.max_ns.fetch_max(ns, Ordering::Relaxed);
        k.hist[bucket(ns)].fetch_add(1, Ordering::Relaxed);
    }

    /// Per kind: how many, their total and p50/p90/p99/max, in µs.
    pub fn report(&self) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        for (name, k) in KINDS.iter().zip(&self.kinds) {
            let hist: Vec<u64> = k.hist.iter().map(|h| h.load(Ordering::Relaxed)).collect();
            let count: u64 = hist.iter().sum();
            let pct = |p: u64| {
                let rank = (count * p).div_ceil(100).max(1);
                let mut seen = 0;
                let i = hist.iter().position(|&h| {
                    seen += h;
                    seen >= rank
                });
                i.map_or(0.0, |i| bucket_floor(i) as f64 / 1e3)
            };
            let v = serde_json::json!({
                "count": count,
                "sum_ms": k.sum_ns.load(Ordering::Relaxed) as f64 / 1e6,
                "p50_us": pct(50), "p90_us": pct(90), "p99_us": pct(99),
                "max_us": k.max_ns.load(Ordering::Relaxed) as f64 / 1e3,
            });
            out.insert(name.to_string(), v);
        }
        out.into()
    }
}

/// The histogram bucket of `ns`: four per power of two (anything under
/// 4 ns counts as 4).
fn bucket(ns: u64) -> usize {
    let ns = ns.max(1 << SUB_BITS);
    let log = 63 - ns.leading_zeros();
    let frac = (ns >> (log - SUB_BITS)) & ((1 << SUB_BITS) - 1);
    (((log as usize) << SUB_BITS) + frac as usize).min(BUCKETS - 1)
}

/// The smallest latency in bucket `i`, in nanoseconds.
fn bucket_floor(i: usize) -> u64 {
    let (log, frac) = (i as u32 >> SUB_BITS, (i as u64) & ((1 << SUB_BITS) - 1));
    (((1u64 << SUB_BITS) + frac) << log) >> SUB_BITS
}

/// A fault the event thread has yet to resolve.
struct Pending {
    addr: u64,
    flags: u64,
    read: Instant,
    /// Its kind (`KINDS`), when known before it is resolved: it waited for
    /// another installer, or had its run fetched.
    kind: Option<usize>,
    /// Waiting for claimed pages to settle, which wakes the event thread;
    /// otherwise retried every millisecond.
    parked: bool,
    /// When it first failed other than with EAGAIN.
    since: Option<Instant>,
}

/// Why `Pages::fetch_install` stopped.
enum Failed {
    Fetch(io::Error),
    Install(io::Error),
}

/// What became of a fault the event thread looked at.
enum Served {
    /// Resolved, as this kind (`KINDS`).
    Done(usize),
    /// Its page is claimed by another installer.
    Waiting,
    /// Its run was claimed and handed to a fetcher.
    Fetching,
}

pub struct Pager {
    base: Arc<Template>,
    mappings: OnceLock<Vec<Mapping>>,
    pages: OnceLock<Pages>,
    uffd: OnceLock<OwnedFd>,
    /// Firecracker pid, for reading its memory (`read_guest`, `populated`,
    /// `unmapped`). Firecracker is reaped only after the pager has stopped
    /// (`Vm::kill`), so it is not reused meanwhile; and each read by pid is
    /// believed only if Firecracker had not exited after it (`exited`).
    pid: AtomicU32,
    /// Firecracker as a pidfd, so killing it never hits a reused pid.
    pidfd: OnceLock<OwnedFd>,
    remote: Mutex<Option<Link>>,
    /// The checkpoint page file REMOTE pages come from, when restoring one.
    /// Let go once the last REMOTE page has settled (see `pulled`), so a
    /// deleted checkpoint's disk space comes back while the VM runs on.
    file: Mutex<Option<Arc<PageFile>>>,
    /// The VM's REMOTE pages came from a checkpoint file (not a peer).
    from_file: AtomicBool,
    discards: AtomicU64,
    remote_left: AtomicUsize,
    pull_started: OnceLock<Instant>,
    pull_finished: OnceLock<Instant>,
    /// Signalled when Firecracker connects, the pull finishes or the pager stops.
    done: (Mutex<()>, Condvar),
    /// Set by the checkpoint barrier: no new prefetch.
    quiesce: AtomicBool,
    /// The page after the last template fault. Only a fault there (a
    /// sequential scan) copies `FAULT_AROUND` pages: strided reads, like the
    /// guest walking the page structs of its free memory, would otherwise
    /// pull in sixteen times what they touch.
    template_next: AtomicUsize,
    failed: OnceLock<String>,
    stop: AtomicBool,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    /// Memory is registered for write-protect faults and write tracking is on.
    tracking: AtomicBool,
    registered_wp: AtomicBool,
    /// The copy-on-write state of a checkpoint whose pages are being written.
    cow: Mutex<Option<Arc<Cow>>>,
    /// Held while handling a fault and while a checkpoint freezes memory, so
    /// a fault read before the freeze cannot unprotect a page after it.
    wp: Mutex<()>,
    /// Firecracker's /proc/PID/pagemap, to tell populated pages apart.
    pagemap: OnceLock<std::fs::File>,
    /// Test fault: the next freeze fails to re-protect pages.
    pub fail_protect: AtomicBool,
    /// Test fault: write faults during a copy dawdle before claiming pages.
    pub wp_race: AtomicBool,
    /// Test fault: copies of fault-fetched runs past their first page fail once more.
    pub tail_fail: AtomicU32,
    /// Test fault: from then on every copy of a fault-fetched run fails
    /// (ENOMEM), and the pullers wait.
    pub stuck_from: Mutex<Option<Instant>>,
    /// Initial page states and their origin, applied when Firecracker
    /// connects (see `seed`).
    initial: Mutex<Option<(Runs, Origin)>>,
    /// Signalled by `seed` and `stop`, for a handshake waiting for the seed.
    seeded: Condvar,
    /// Firecracker connects before the page states are known (a prepared
    /// load, see `expect_seed`): the handshake waits for `seed`.
    awaiting_seed: AtomicBool,
    /// Learning the template's load set (`learn_load_set`): faults go into
    /// it until `loaded`, and the working-set prefetch waits until then.
    learning: AtomicBool,
    /// The prefetch, held back until `loaded` while learning: (loaded, due).
    prefetch: Mutex<(bool, bool)>,
    pub fault_stats: FaultStats,
    /// Runs of REMOTE pages faults claimed, for the fetchers (`fetch_faults`).
    demand: (Mutex<VecDeque<Job>>, Condvar),
}

/// What `Pager::freeze` captured for a checkpoint.
pub struct Frozen {
    /// Page states for the writer: REMOTE pages are saved from the guest,
    /// ZERO pages are discarded, BASE pages (incremental only) are the template's.
    pub runs: Runs,
    /// Copy-on-write state, when the VM is to run on during the write.
    pub cow: Option<Arc<Cow>>,
    /// Pages dirtied since the previous checkpoint's pause.
    pub dirty: usize,
    /// The dirty bits taken, which a checkpoint that fails gives back
    /// (`Pager::unfreeze`).
    taken: Vec<u64>,
    pub protected: usize,
    pub protect: Duration,
}

impl Pager {
    /// Listens on `sock` for Firecracker's UFFD handshake and serves faults in
    /// the background. `initial` seeds page states for an incoming migration
    /// or a checkpoint restore, with where their REMOTE pages come from; it
    /// can also be given later, with `seed`, until Firecracker connects.
    pub fn start(sock: &Path, base: Arc<Template>, initial: Option<(Runs, Origin)>) -> Result<Arc<Pager>> {
        crate::socket::check(sock)?;
        let _ = std::fs::remove_file(sock);
        let listener = UnixListener::bind(sock)?;
        // Polled, so a Firecracker that never connects cannot hold the thread forever.
        listener.set_nonblocking(true)?;
        let pager = Arc::new(Pager {
            base,
            mappings: OnceLock::new(),
            pages: OnceLock::new(),
            uffd: OnceLock::new(),
            pid: AtomicU32::new(0),
            pidfd: OnceLock::new(),
            remote: Mutex::new(None),
            file: Mutex::new(None),
            from_file: AtomicBool::new(false),
            discards: AtomicU64::new(0),
            remote_left: AtomicUsize::new(0),
            pull_started: OnceLock::new(),
            pull_finished: OnceLock::new(),
            done: (Mutex::new(()), Condvar::new()),
            quiesce: AtomicBool::new(false),
            template_next: AtomicUsize::new(usize::MAX),
            failed: OnceLock::new(),
            stop: AtomicBool::new(false),
            thread: Mutex::new(None),
            tracking: AtomicBool::new(false),
            registered_wp: AtomicBool::new(false),
            cow: Mutex::new(None),
            wp: Mutex::new(()),
            pagemap: OnceLock::new(),
            fail_protect: AtomicBool::new(false),
            wp_race: AtomicBool::new(false),
            tail_fail: AtomicU32::new(0),
            stuck_from: Mutex::new(None),
            initial: Mutex::new(initial),
            seeded: Condvar::new(),
            awaiting_seed: AtomicBool::new(false),
            learning: AtomicBool::new(false),
            prefetch: Mutex::new((false, false)),
            fault_stats: FaultStats::new(),
            demand: (Mutex::new(VecDeque::new()), Condvar::new()),
        });
        let p = pager.clone();
        let thread = thread::Builder::new().name("uffd".into()).spawn(move || {
            match p.handshake(&listener) {
                // Alongside fault handling: Firecracker itself touches guest
                // memory while restoring devices and must not wait behind it.
                Ok(prefetch) => p.start_prefetch(false, prefetch),
                Err(e) => return p.fail(format!("uffd handshake failed: {e}")),
            }
            p.serve();
        })?;
        *pager.thread.lock().unwrap() = Some(thread);
        Ok(pager)
    }

    /// Starts the working-set prefetch once it is `due` and, while learning
    /// the load set, the snapshot is `loaded`.
    fn start_prefetch(self: &Arc<Self>, loaded: bool, due: bool) {
        let mut state = self.prefetch.lock().unwrap();
        state.0 |= loaded;
        state.1 |= due;
        if state.1 && (state.0 || !self.learning.load(Ordering::SeqCst)) {
            state.1 = false;
            let p = self.clone();
            thread::spawn(move || p.prefetch());
        }
    }

    /// Waits for the pager thread to finish, after `stop` (or Firecracker's exit).
    pub fn join(&self) {
        let thread = self.thread.lock().unwrap().take();
        if let Some(t) = thread.filter(|t| t.thread().id() != thread::current().id()) {
            let _ = t.join();
        }
    }

    /// Sets the initial page states and their origin, for a pager started
    /// without them. Only before Firecracker loads a snapshot.
    pub fn seed(&self, runs: Runs, origin: Origin) -> Result<()> {
        if self.pages.get().is_some() || self.initial.lock().unwrap().is_some() {
            bail!("pager already seeded");
        }
        *self.initial.lock().unwrap() = Some((runs, origin));
        self.seeded.notify_all();
        Ok(())
    }

    /// Firecracker will connect before `seed` (it prepares the load ahead of
    /// the vmstate, touching no guest memory until the load itself): the
    /// handshake then waits for the seed (or `stop`).
    pub fn expect_seed(&self, yes: bool) {
        self.awaiting_seed.store(yes, Ordering::SeqCst);
    }

    /// Records the pages the coming snapshot load faults on into the
    /// template's load set (see `Template::load_set`), holding the working-set
    /// prefetch back until `loaded` so that it does not hide them. For loads
    /// off the critical path (the hot pool's). Call before the load.
    pub fn learn_load_set(&self) {
        self.learning.store(true, Ordering::SeqCst);
    }

    /// The snapshot load is done (or failed): stops learning and lets a
    /// held-back prefetch go.
    pub fn loaded(self: &Arc<Self>) {
        self.learning.store(false, Ordering::SeqCst);
        self.start_prefetch(true, false);
    }

    /// Takes over Firecracker's userfaultfd. Returns whether to prefetch the working set.
    fn handshake(&self, listener: &UnixListener) -> Result<bool> {
        let start = Instant::now();
        let waiting = |what: &str| -> Result<()> {
            if self.stop.load(Ordering::SeqCst) {
                bail!("stopped before Firecracker {what}");
            }
            if start.elapsed() > HANDSHAKE_TIMEOUT {
                bail!("Firecracker never {what} within {HANDSHAKE_TIMEOUT:?}");
            }
            Ok(())
        };
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    waiting("connected")?;
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(e.into()),
            }
        };
        let mut pfd = libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        while unsafe { libc::poll(&mut pfd, 1, 10) } <= 0 {
            waiting("sent its handshake")?;
        }
        stream.set_nonblocking(false)?;
        let (body, fd) = recv_with_fd(stream.as_raw_fd())?;
        let mappings: Vec<Mapping> = serde_json::from_slice(&body)?;
        let total = mappings.iter().map(|m| m.offset as usize + m.size).max().unwrap_or(0) / PAGE_SIZE;
        let pages = Pages::new(total);
        let initial = {
            // No deadline of its own: the migration's protocol deadline drops
            // the prepared VM, which stops the pager.
            let mut initial = self.initial.lock().unwrap();
            while initial.is_none() && self.awaiting_seed.load(Ordering::SeqCst) {
                if self.stop.load(Ordering::SeqCst) {
                    bail!("stopped before the page states arrived");
                }
                initial = self.seeded.wait(initial).unwrap();
            }
            initial.take()
        };
        if let Some((runs, origin)) = initial {
            if let Origin::Peer(source) = &origin {
                let ours = regions(&mappings);
                if source.regions != ours {
                    bail!("guest memory regions {ours:?} differ from the source's {:?}", source.regions);
                }
            }
            let _ = self.pull_started.set(Instant::now());
            let remote = remote_pages(&runs, total)?;
            for (first, count, state) in runs {
                (first as usize..(first + count) as usize).for_each(|p| pages.set(p, state));
            }
            self.remote_left.store(remote, Ordering::SeqCst);
            match origin {
                Origin::Peer(source) => {
                    // Connect now: the restore itself faults on remote pages.
                    let mut link = Link::new(source);
                    link.client = PageClient::connect(&link.source).ok();
                    *self.remote.lock().unwrap() = Some(link);
                }
                Origin::File(file) => {
                    self.from_file.store(true, Ordering::SeqCst);
                    // Nothing to read from it (all BASE or ZERO): not kept.
                    if remote > 0 {
                        *self.file.lock().unwrap() = Some(file);
                    }
                }
            }
        }
        // A checkpoint restore prefetches the template's working set too: the
        // pages the checkpoint left BASE are still the template's.
        let fresh = self.remote_left() == 0 || self.from_file.load(Ordering::SeqCst);
        let _ = self.mappings.set(mappings);
        let _ = self.pages.set(pages);
        let _ = self.uffd.set(fd);
        if self.remote_left() == 0 && self.pull_started.get().is_some() {
            let _ = self.pull_finished.set(Instant::now());
        }
        self.notify();
        Ok(fresh && !self.base.working_set.is_empty())
    }

    /// Copies the template's recorded working set in up front, while the
    /// vCPUs are still being restored, instead of one fault at a time.
    fn prefetch(&self) {
        let pages = self.pages();
        for (mut i, end) in self.chunks(self.working_set(0, 1), PREFETCH_RUN) {
            while i < end && !self.quiesce.load(Ordering::SeqCst) {
                // Holes were zero at snapshot time (mostly free memory the guest
                // allocates again); map them too, or each one costs a fault.
                let data = self.base.has_data(i);
                let n = pages.claim(i, end - i, BASE, |p| self.base.has_data(p) == data);
                if n > 0 {
                    let src = |p: usize, c: usize| data.then(|| self.base.pages(p, c));
                    let _ = pages.install(i, n, BASE, None, |p, c| self.populate(p, c, src(p, c)));
                }
                i += n.max(1);
            }
        }
    }

    /// Runs of pages populated so far, as `(first_page, count)`.
    pub fn present_runs(&self) -> Vec<(u64, u64)> {
        let pages = self.pages();
        runs_where(0, pages.len(), |p| pages.get(p) == PRESENT).map(|(a, b)| (a as u64, (b - a) as u64)).collect()
    }

    /// Installs REMOTE pages whose contents came along with the vmstate (one
    /// `PAGE_SIZE` slice of `data` per page of `list`), once Firecracker has
    /// connected: the load would otherwise fault on them one round trip at a
    /// time. Runs alongside the load; a page a fault or puller claimed first
    /// is waited for (by `deadline`), so all of them are in when it returns.
    /// Returns how many it installed.
    pub fn preload(&self, list: &[u64], data: &[u8], deadline: Instant) -> Result<usize> {
        if data.len() != list.len() * PAGE_SIZE {
            bail!("preload of {} pages has {} bytes", list.len(), data.len());
        }
        while self.wait_ready(Duration::from_millis(10)).is_err() {
            if self.stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
                bail!("the pager stopped or Firecracker never connected");
            }
        }
        let pages = self.pages();
        let mut installed = 0;
        for (&page, src) in list.iter().zip(data.chunks_exact(PAGE_SIZE)) {
            let page = page as usize;
            if page >= pages.len() {
                continue;
            }
            // Done once the page is no longer REMOTE nor being installed by
            // someone else (whose fetch may fail and give it back).
            loop {
                if let Some(why) = self.failed() {
                    bail!("the pager failed: {why}");
                }
                match pages.get(page) {
                    REMOTE if pages.claim(page, 1, REMOTE, |_| true) == 1 => {
                        let (resolved, res) = pages.install(page, 1, REMOTE, None, |p, c| self.populate(p, c, Some(src)));
                        self.pulled(resolved);
                        installed += resolved;
                        match res {
                            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {}
                            r => break r?,
                        }
                    }
                    REMOTE | INFLIGHT | DISCARDED => {}
                    _ => break,
                }
                if self.stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
                    bail!("page {page} still being installed at the deadline");
                }
                thread::sleep(Duration::from_micros(50));
            }
        }
        if let Some(why) = self.failed() {
            bail!("the pager failed: {why}");
        }
        Ok(installed)
    }

    /// Waits (up to `timeout`) for `cond`, checked again whenever Firecracker
    /// connects, the pull finishes or the pager stops. False if the pager
    /// stopped or time ran out first.
    fn wait_for(&self, timeout: Option<Duration>, cond: impl Fn() -> bool) -> bool {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut guard = self.done.0.lock().unwrap();
        loop {
            if cond() {
                return true;
            }
            let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            if self.stop.load(Ordering::SeqCst) || left.is_some_and(|l| l.is_zero()) {
                return false;
            }
            guard = match left {
                Some(left) => self.done.1.wait_timeout(guard, left).unwrap().0,
                None => self.done.1.wait(guard).unwrap(),
            };
        }
    }

    /// Blocks until Firecracker has handed over its userfaultfd.
    pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
        if !self.wait_for(Some(timeout), || self.uffd.get().is_some()) {
            bail!("firecracker never connected to the uffd socket");
        }
        Ok(())
    }

    /// Blocks until every remote page has arrived (true), or the pager has
    /// stopped or failed, or `timeout` passed, first (false).
    pub fn wait_pulled(&self, timeout: Option<Duration>) -> bool {
        self.wait_for(timeout, || self.remote_left() == 0)
    }

    /// How long an incoming migration took to pull every remote page, once done.
    pub fn pull_time(&self) -> Option<Duration> {
        Some(self.pull_finished.get()?.duration_since(*self.pull_started.get()?))
    }

    /// Counts `n` remote pages as resolved. With the last one, lets go of the
    /// checkpoint file: every claim on a REMOTE page has settled (a claimed
    /// page counts until its claimant settles it), so nothing reads it any
    /// more but those already reading, through clones of their own.
    fn pulled(&self, n: usize) {
        if n > 0 && self.remote_left.fetch_sub(n, Ordering::SeqCst) == n {
            drop(self.file.lock().unwrap().take());
            let _ = self.pull_finished.set(Instant::now());
            self.notify();
        }
    }

    /// Wakes whoever waits on `done` or for fault runs: Firecracker
    /// connected, the pull finished or the pager stopped. Fault fetchers end
    /// once the pull is done, letting go of the file too.
    fn notify(&self) {
        drop(self.done.0.lock().unwrap());
        self.done.1.notify_all();
        drop(self.demand.0.lock().unwrap());
        self.demand.1.notify_all();
    }

    /// The guest's memory size in pages, once Firecracker has connected.
    pub fn total_pages(&self) -> usize {
        self.pages().len()
    }

    /// The first page past the guest memory region holding `page`.
    pub fn region_end(&self, page: usize) -> Option<usize> {
        self.locate((page * PAGE_SIZE) as u64).map(|m| m.span().1)
    }

    /// Names the Firecracker this pager serves; required before it loads a
    /// snapshot, so a failing pager can always kill it.
    pub fn set_pid(&self, pid: u32) -> Result<()> {
        self.pid.store(pid, Ordering::SeqCst);
        let fd = crate::util::pidfd_open(pid).map_err(|e| format!("pidfd_open({pid}): {e}"))?;
        let _ = self.pidfd.set(fd);
        Ok(())
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // Also ends a prefetch still running (e.g. for a drained hot pool's VM).
        self.quiesce.store(true, Ordering::SeqCst);
        self.notify();
        let _initial = self.initial.lock().unwrap();
        self.seeded.notify_all();
    }

    /// Gives up on the VM's memory: unless it was stopped on purpose, records
    /// why and kills Firecracker, whose vCPUs (or snapshot load) may be
    /// blocked on pages that will never come.
    fn fail(&self, why: String) {
        if !self.stop.load(Ordering::SeqCst) {
            eprintln!("uffd: {why}; killing the vm");
            let _ = self.failed.set(why);
            match self.pidfd.get().map(crate::util::pidfd_kill) {
                Some(Ok(())) => {}
                Some(Err(e)) => eprintln!("uffd: cannot kill firecracker: {e}"),
                None => eprintln!("uffd: no firecracker to kill"),
            }
        }
        self.stop();
    }

    /// Whether `e`, from a uffd call on `n` pages from `page`, means that
    /// nothing at all is mapped there in Firecracker any more (or it is
    /// gone): ENOENT outside a registered VMA, ESRCH once its memory is gone.
    /// ENOENT also comes across a VMA boundary, e.g. into an unplugged
    /// virtio-mem slot, where memory is still mapped: that is not this.
    fn unmapped(&self, e: &io::Error, page: usize, n: usize) -> bool {
        let Some((addr, _)) = self.host_addr(page).filter(|_| matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))) else {
            return false;
        };
        let pid = self.pid.load(Ordering::SeqCst);
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else { return true };
        if self.exited() {
            return true;
        }
        let end = addr + (n * PAGE_SIZE) as u64;
        !maps.lines().any(|l| {
            let (a, b) = l.split_whitespace().next().unwrap_or("").split_once('-').unwrap_or(("", ""));
            match (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) {
                (Ok(a), Ok(b)) => a < end && b > addr,
                _ => false,
            }
        })
    }

    /// Gives up on guest memory that Firecracker has unmapped: it is most
    /// likely tearing down a load that failed, and about to answer the load
    /// request with why. Like `fail`, but Firecracker gets `UNMAPPED_GRACE`
    /// to do that (or exit) before it is killed.
    fn gone(&self) {
        // Once, though every puller runs into it.
        if !self.stop.load(Ordering::SeqCst) && self.failed.set(GONE.into()).is_ok() {
            eprintln!("uffd: firecracker unmapped guest memory; killing it unless it exits within {UNMAPPED_GRACE:?}");
            if let Some(fd) = self.pidfd.get().and_then(|fd| fd.try_clone().ok()) {
                thread::spawn(move || {
                    if !crate::util::pidfd_wait(&fd, UNMAPPED_GRACE).unwrap_or(false) {
                        let _ = crate::util::pidfd_kill(&fd);
                    }
                });
            }
        }
        self.stop();
    }

    /// SIGKILLs the Firecracker through its pidfd, without waiting for
    /// anything (such as a call holding the VM's API lock).
    pub fn kill_firecracker(&self) {
        if let Some(fd) = self.pidfd.get() {
            let _ = crate::util::pidfd_kill(fd);
        }
    }

    /// Test fault `kill_prepared`: Firecracker was killed; treat it as gone.
    pub fn firecracker_gone(&self) {
        self.gone();
    }

    /// Whether the pager gave up on pages for its own reasons (the source,
    /// the checkpoint file), rather than because Firecracker went away.
    pub fn lost_pages(&self) -> bool {
        self.failed().is_some_and(|why| why != GONE)
    }

    /// Why the pager gave up, if it did. The VM cannot make progress then.
    pub fn failed(&self) -> Option<&str> {
        self.failed.get().map(|s| s.as_str())
    }

    /// REMOVE events applied so far (balloon and virtio-mem discards).
    pub fn discards(&self) -> u64 {
        self.discards.load(Ordering::SeqCst)
    }

    /// Installs that found a REMOVE queued and waited for it to be read.
    pub fn install_eagain(&self) -> u64 {
        self.pages().install_eagain.load(Ordering::Relaxed)
    }

    /// Whether pages are still to come from a migration source.
    pub fn pulling_from_peer(&self) -> bool {
        self.remote_left() > 0 && !self.from_file.load(Ordering::SeqCst)
    }

    pub fn remote_left(&self) -> usize {
        self.remote_left.load(Ordering::SeqCst)
    }

    /// Guest memory regions as `(offset, size)`, in Firecracker's order.
    pub fn regions(&self) -> Vec<(u64, u64)> {
        regions(self.mappings())
    }

    fn mappings(&self) -> &[Mapping] {
        self.mappings.get().map(|m| m.as_slice()).unwrap_or(&[])
    }

    fn pages(&self) -> &Pages {
        static EMPTY: OnceLock<Pages> = OnceLock::new();
        self.pages.get().unwrap_or_else(|| EMPTY.get_or_init(Pages::default))
    }

    /// The active checkpoint copy, if any.
    fn cow(&self) -> Option<Arc<Cow>> {
        self.cow.lock().unwrap().clone().filter(|c| c.active())
    }

    pub fn census(&self) -> [usize; 6] {
        let mut c = [0usize; 6];
        let pages = self.pages();
        (0..pages.len()).for_each(|i| c[pages.get(i) as usize] += 1);
        c
    }

    /// Checkpoint barrier, for a paused VM: stops prefetching, waits for
    /// REMOVE events already read to be applied and for in-flight installs to
    /// settle, then exports page states that match the saved device state.
    /// A page installed behind the scan only gains the contents its old state
    /// already implied (template or zero), as the paused guest cannot write it.
    ///
    /// The export is the run-length encoded page states a migration target
    /// needs: PRESENT pages become REMOTE there, ZERO stays ZERO and BASE is
    /// implied.
    pub fn quiesce_export(&self) -> Result<Runs> {
        self.quiesce.store(true, Ordering::SeqCst);
        drop(self.pages().removing());
        let start = Instant::now();
        let mut runs: Runs = Vec::new();
        let pages = self.pages();
        for m in self.mappings() {
            let (first, end) = m.span();
            let mut i = pages.next_not(BASE, first, end);
            while i < end {
                let mut s = pages.get(i);
                while (s == INFLIGHT || s == DISCARDED) && start.elapsed() < Duration::from_secs(1) {
                    thread::sleep(Duration::from_micros(20));
                    s = pages.get(i);
                }
                let (raw, s) = match s {
                    PRESENT => (PRESENT, REMOTE),
                    ZERO => (ZERO, ZERO),
                    // Given back by an installer meanwhile.
                    BASE => {
                        i = pages.next_not(BASE, i + 1, end);
                        continue;
                    }
                    s => bail!("page {i} is still in state {s}; the VM is mid-migration"),
                };
                let n = (pages.next_not(raw, i + 1, end) - i) as u64;
                match runs.last_mut() {
                    Some((f, c, st)) if *st == s && *f + *c == i as u64 => *c += n,
                    _ => runs.push((i as u64, n, s)),
                }
                i = pages.next_not(BASE, i + n as usize, end);
            }
        }
        Ok(runs)
    }

    fn locate(&self, offset: u64) -> Option<&Mapping> {
        self.mappings().iter().find(|m| offset >= m.offset && offset < m.offset + m.size as u64)
    }

    fn host_addr(&self, page: usize) -> Option<(u64, &Mapping)> {
        let off = (page * PAGE_SIZE) as u64;
        let m = self.locate(off)?;
        Some((m.base_host_virt_addr + (off - m.offset), m))
    }

    pub fn read_guest(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let Some(m) = self.locate(offset) else { bail!("offset {offset:#x} outside guest memory") };
        if offset + buf.len() as u64 > m.offset + m.size as u64 {
            bail!("read crosses a region boundary");
        }
        let local = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let remote = libc::iovec { iov_base: (m.base_host_virt_addr + (offset - m.offset)) as *mut _, iov_len: buf.len() };
        let pid = self.pid.load(Ordering::SeqCst) as libc::pid_t;
        if unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) } != buf.len() as isize {
            bail!("process_vm_readv: {}", io::Error::last_os_error());
        }
        if self.exited() {
            bail!("firecracker exited");
        }
        Ok(())
    }

    /// Whether Firecracker has exited (or was never named): what was just
    /// read by its pid may then be another process's.
    fn exited(&self) -> bool {
        self.pidfd.get().is_none_or(|fd| crate::util::pidfd_wait(fd, Duration::ZERO).unwrap_or(true))
    }

    fn serve(self: Arc<Self>) {
        if self.remote_left() > 0 {
            self.clone().spawn_pullers();
        }
        let fd = self.uffd.get().unwrap().as_raw_fd();
        let pages = self.pages();
        // Installers wake this thread through it when faults wait on them.
        let wake = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if wake < 0 {
            return self.fail(format!("eventfd: {}", io::Error::last_os_error()));
        }
        let _ = pages.wake.set(unsafe { OwnedFd::from_raw_fd(wake) });
        let mut pending: VecDeque<Pending> = VecDeque::new();
        let mut buf = [0u8; 32 * 64];
        while !self.stop.load(Ordering::SeqCst) {
            let mut pfd = [
                libc::pollfd { fd, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: wake, events: libc::POLLIN, revents: 0 },
            ];
            // Faults waiting for another installer are woken by it; others
            // (EAGAIN, errors) are retried every millisecond. The timeout
            // also bounds a missed wakeup.
            let timeout = if pending.iter().all(|p| p.parked) { 100 } else { 1 };
            if unsafe { libc::poll(pfd.as_mut_ptr(), 2, timeout) } < 0 {
                continue;
            }
            // Test fault `uffd_err`: the uffd turns blocking, which the kernel reports as POLLERR.
            if pfd[0].revents == 0 && crate::host::fault("uffd_err") {
                unsafe { libc::fcntl(fd, libc::F_SETFL, libc::fcntl(fd, libc::F_GETFL) & !libc::O_NONBLOCK) };
            }
            if pfd[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return self.fail(format!("the userfaultfd cannot be polled (revents {:#x})", pfd[0].revents));
            }
            if pfd[1].revents & libc::POLLIN != 0 {
                unsafe { libc::read(wake, (&mut 0u64 as *mut u64).cast(), 8) };
            }
            if pfd[0].revents & libc::POLLIN != 0 {
                // A REMOVE the kernel acts on as soon as it is read must not
                // hit pages a checkpoint copy has yet to save: let it finish.
                if let Some(cow) = self.cow().filter(|c| self.remove_queued(c)) {
                    self.save_rest(&cow);
                    if !cow.drain() {
                        cow.invalidate("a discard was held back while the copy made no progress");
                    }
                }
                let removing = pages.removing();
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                for msg in buf[..n.max(0) as usize].chunks_exact(32) {
                    let a = u64::from_ne_bytes(msg[8..16].try_into().unwrap());
                    let b = u64::from_ne_bytes(msg[16..24].try_into().unwrap());
                    match msg[0] {
                        UFFD_EVENT_PAGEFAULT => {
                            if let Some((page, _)) = self.page_of(b).filter(|_| self.learning.load(Ordering::Relaxed)) {
                                self.base.note_load_fault(page as u64);
                            }
                            pending.push_back(Pending { addr: b, flags: a, read: Instant::now(), kind: None, parked: false, since: None })
                        }
                        UFFD_EVENT_REMOVE => self.discard(&removing, a, b),
                        _ => {}
                    }
                }
                drop(removing);
                pages.events_read();
            }
            // Before the faults look at page states: an installer that
            // settles a page after that sees it set, and wakes this thread.
            pages.waiting.store(!pending.is_empty(), Ordering::SeqCst);
            // Faults that hit EAGAIN are retried once the events ahead of them
            // are drained; other errors (say ENOMEM) for a while: a dropped
            // fault would block its vCPU forever.
            for _ in 0..pending.len() {
                let mut p = pending.pop_front().unwrap();
                let page = self.page_of(p.addr).map(|(page, _)| page);
                match self.fault(p.addr, p.flags) {
                    Ok(Served::Done(kind)) => {
                        // A fault that waited was resolved by the copy that woke its thread.
                        let woke = page.filter(|_| p.kind.is_some()).and_then(|page| pages.unpark(page, p.read));
                        let kind = if kind == WP { WP } else { p.kind.unwrap_or(kind) };
                        self.fault_stats.record(kind, woke.unwrap_or_else(Instant::now) - p.read);
                        continue;
                    }
                    Ok(served) => {
                        p.parked = true;
                        match served {
                            Served::Fetching => p.kind = Some(FETCHED),
                            _ => _ = p.kind.get_or_insert(WAITED),
                        }
                        if let Some(page) = page {
                            pages.park(page, p.read);
                        }
                    }
                    Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => p.parked = false,
                    // Firecracker unmapped guest memory (tearing down a failed load, or exiting).
                    Err(e) if page.is_some_and(|page| self.unmapped(&e, page, 1)) => return self.gone(),
                    Err(e) if fatal(&e) => return self.fail(e.to_string()),
                    Err(e) => {
                        p.parked = false;
                        match p.since {
                            None => {
                                eprintln!("uffd: fault at {:#x}: {e}; retrying", p.addr);
                                p.since = Some(Instant::now());
                            }
                            Some(t) if t.elapsed() < FAULT_TIMEOUT => {}
                            Some(_) => return self.fail(format!("fault at {:#x}: {e}", p.addr)),
                        }
                    }
                }
                pending.push_back(p);
            }
            if pending.is_empty() {
                pages.waiting.store(false, Ordering::SeqCst);
                pages.parked.lock().unwrap().clear();
            }
        }
    }

    fn page_of(&self, addr: u64) -> Option<(usize, &Mapping)> {
        let m = self.mappings().iter().find(|m| addr >= m.base_host_virt_addr && addr < m.base_host_virt_addr + m.size as u64)?;
        Some((((addr - m.base_host_virt_addr + m.offset) as usize) / PAGE_SIZE, m))
    }

    fn discard(&self, removing: &RwLockWriteGuard<'_, ()>, start: u64, end: u64) {
        self.discards.fetch_add(1, Ordering::SeqCst);
        let cow = self.cow();
        let mut resolved = 0;
        for a in (start & !(PAGE_SIZE as u64 - 1)..end).step_by(PAGE_SIZE) {
            if let Some((p, _)) = self.page_of(a) {
                if let Some(cow) = cow.as_ref().filter(|c| matches!(c.state(p), PENDING | READING | RESCUING)) {
                    cow.invalidate(&format!("page {p} was discarded before it was saved"));
                }
                resolved += self.pages().discard(removing, p) as usize;
            }
        }
        self.pulled(resolved);
    }

    /// Serves a fault, without waiting for the network or disk: a REMOTE
    /// page's run goes to a fetcher (`fetch_faults`), and the fault waits.
    fn fault(&self, addr: u64, flags: u64) -> io::Result<Served> {
        let Some((page, m)) = self.page_of(addr) else {
            return Err(io::Error::other("fault outside guest memory"));
        };
        let _wp = self.wp.lock().unwrap();
        if flags & UFFD_PAGEFAULT_FLAG_WP != 0 {
            return self.wp_fault(page, m).map(|()| Served::Done(WP));
        }
        // Runs stay within a 2 MiB chunk: Firecracker keeps unplugged
        // virtio-mem slots PROT_NONE, which splits the region into VMAs at
        // slot boundaries, and a uffd copy across a VMA end fails (ENOENT).
        let chunk = (2 << 20) / PAGE_SIZE;
        let region_left = (m.span().1 - page).min(chunk - (page - m.span().0) % chunk);
        let pages = self.pages();
        match pages.get(page) {
            // Normally a fault that raced the install; if the page is really
            // missing, a REMOVE zapped it after it settled (see `Pages`).
            // Missing at a checkpoint's pause too, so zero then: if the copy
            // has yet to save it, keep it protected until it has.
            PRESENT => {
                let unsaved = self.cow().is_some_and(|c| matches!(c.state(page), PENDING | READING));
                let res = match unsaved {
                    true => self.copy(page, 1, &ZEROES, UFFDIO_COPY_MODE_WP),
                    false => self.populate(page, 1, None),
                };
                match res {
                    Err(e) if e.raw_os_error() == Some(libc::EEXIST) => self.wake(page)?,
                    Err(e) => return Err(e),
                    Ok(_) if !unsaved => pages.mark_dirty(page),
                    Ok(_) => {}
                }
                Ok(Served::Done(LOCAL))
            }
            // Someone else is installing it: their copy wakes the faulting
            // thread, and their settling this thread, to finish the fault.
            INFLIGHT | DISCARDED => Ok(Served::Waiting),
            REMOTE => {
                let n = pages.claim(page, REMOTE_FAULT_RUN.min(region_left), REMOTE, |_| true);
                if n == 0 {
                    return Err(os(libc::EAGAIN));
                }
                self.demand.0.lock().unwrap().push_back((page, n, Instant::now()));
                self.demand.1.notify_one();
                Ok(Served::Fetching)
            }
            state => {
                // BASE or ZERO: serve a run of neighbours with the same source.
                let from_template = state == BASE && self.base.has_data(page);
                let same = |p: usize| state == ZERO || self.base.has_data(p) == from_template;
                let sequential = !from_template || self.template_next.load(Ordering::Relaxed) == page;
                let around = if sequential { FAULT_AROUND } else { 1 };
                let n = pages.claim(page, around.min(region_left), state, same);
                if n == 0 {
                    return Err(os(libc::EAGAIN));
                }
                if from_template {
                    self.template_next.store(page + n, Ordering::Relaxed);
                }
                let src = |p: usize, c: usize| from_template.then(|| self.base.pages(p, c));
                pages.install(page, n, state, None, |p, c| self.populate(p, c, src(p, c))).1.map(|()| Served::Done(LOCAL))
            }
        }
    }

    /// A write to a write-protected page. During a checkpoint copy, saves the
    /// pages of its block that the copy has not saved yet; then unprotects
    /// the block (except pages still to be saved by a writer) and marks it
    /// dirty.
    fn wp_fault(&self, page: usize, m: &Mapping) -> io::Result<()> {
        let block = page - page % WP_BLOCK;
        let (first, end) = (block.max(m.span().0), (block + WP_BLOCK).min(m.span().1));
        let cow = self.cow();
        if let Some(cow) = &cow {
            cow.stats.faults.fetch_add(1, Ordering::Relaxed);
            if cow.state(page) == READING {
                cow.stats.deferred.fetch_add(1, Ordering::Relaxed);
                return Err(os(libc::EAGAIN));
            }
            // Test fault `ckpt_wp_race`: a writer claims the faulting page
            // right here (#88): have the writers take it next, and wait.
            if self.wp_race.load(Ordering::Relaxed) && cow.state(page) == PENDING {
                cow.want(page);
                let t = Instant::now();
                while cow.state(page) == PENDING && t.elapsed() < Duration::from_millis(50) {
                    thread::sleep(Duration::from_micros(100));
                }
            }
            // Over budget, nothing more is copied here: unsaved pages of the
            // block stay protected, and the writers take them first.
            if cow.over_budget() {
                let unsaved: Vec<usize> = (first..end).filter(|&p| cow.state(p) == PENDING).collect();
                unsaved.iter().for_each(|&p| cow.want(p));
                if unsaved.contains(&page) {
                    return Err(os(libc::EAGAIN));
                }
            }
            let start = Instant::now();
            let rescued = if cow.over_budget() { 0 } else { self.rescue(cow, first, end)? };
            if rescued > 0 {
                let ns = start.elapsed().as_nanos() as u64;
                let s = &cow.stats;
                s.rescues.fetch_add(1, Ordering::Relaxed);
                s.rescued_pages.fetch_add(rescued as u64, Ordering::Relaxed);
                s.rescue_ns.fetch_add(ns, Ordering::Relaxed);
                s.rescue_max_ns.fetch_max(ns, Ordering::Relaxed);
            }
        }
        // Unprotect what may change now, in runs around pages still protected for the copy.
        let keep = |p: usize| cow.as_ref().is_some_and(|c| matches!(c.state(p), PENDING | READING | RESCUING));
        // Whether this call unprotected the faulting page, which wakes it.
        let mut woken = false;
        for (p, q) in runs_where(first, end, |p| !keep(p)) {
            (p..q).for_each(|d| self.pages().mark_dirty(d));
            self.writeprotect(p, q - p, false)?;
            woken |= (p..q).contains(&page);
        }
        // Test fault `ckpt_wp_race`: the writer that claimed the page is
        // done with it before the fault is settled.
        if self.wp_race.load(Ordering::Relaxed) && !woken {
            let t = Instant::now();
            while keep(page) && t.elapsed() < Duration::from_millis(50) {
                thread::sleep(Duration::from_micros(100));
            }
        }
        // A writer claimed the faulting page itself (PENDING -> READING)
        // after the check above, so it stayed protected, and nothing else
        // wakes the fault (writers never unprotect, even once they are done
        // with it): retry it, and unprotect it then.
        if !woken {
            if let Some(cow) = &cow {
                cow.stats.deferred.fetch_add(1, Ordering::Relaxed);
            }
            return Err(os(libc::EAGAIN));
        }
        Ok(())
    }

    /// Saves the pages of `first..end` (within one region) that the copy has
    /// yet to save out of the guest into `cow`. Returns how many. Never reads
    /// a page that may be missing, which would fault back to the event
    /// thread: only pages the pagemap shows populated are read (a missing
    /// one was missing, so zero, at the pause).
    fn rescue(&self, cow: &Cow, first: usize, end: usize) -> io::Result<usize> {
        let claimed: Vec<usize> = (first..end).filter(|&p| cow.claim(p, PENDING, RESCUING)).collect();
        if claimed.is_empty() {
            return Ok(0);
        }
        let mut buf = vec![0u8; (end - first) * PAGE_SIZE];
        let read = self.populated(first, end - first).and_then(|present| {
            for (a, b) in runs_where(first, end, |p| present[p - first] && claimed.binary_search(&p).is_ok()) {
                let dst = &mut buf[(a - first) * PAGE_SIZE..(b - first) * PAGE_SIZE];
                self.read_guest((a * PAGE_SIZE) as u64, dst).map_err(|e| io::Error::other(e.to_string()))?;
            }
            Ok(())
        });
        if let Err(e) = read {
            claimed.iter().for_each(|&p| cow.unclaim(p));
            return Err(e);
        }
        for &p in &claimed {
            cow.rescue(p, buf[(p - first) * PAGE_SIZE..(p - first + 1) * PAGE_SIZE].into());
        }
        Ok(claimed.len())
    }

    /// Which of `n` pages from `page` are populated (or swapped out) in Firecracker.
    fn populated(&self, page: usize, n: usize) -> io::Result<Vec<bool>> {
        let f = match self.pagemap.get() {
            Some(f) => f,
            None => {
                // Bound to the memory of the process it was opened for.
                let f = std::fs::File::open(format!("/proc/{}/pagemap", self.pid.load(Ordering::SeqCst)))?;
                if self.exited() {
                    return Err(io::Error::other("firecracker exited"));
                }
                self.pagemap.get_or_init(|| f)
            }
        };
        let mut raw = vec![0u8; n * 8];
        std::os::unix::fs::FileExt::read_exact_at(f, &mut raw, self.addr(page)? / PAGE_SIZE as u64 * 8)?;
        Ok(raw.chunks(8).map(|e| u64::from_le_bytes(e.try_into().unwrap()) & (3 << 62) != 0).collect())
    }

    /// While a REMOVE is held back (and with it every fault, as the kernel
    /// refuses our ioctls until it is read): copies the pages the checkpoint
    /// has yet to save into memory with several threads, so the guest waits
    /// for memory bandwidth rather than for the disk. Only if they fit in a
    /// quarter of the host's available memory; else the writers finish.
    fn save_rest(&self, cow: &Cow) {
        let avail = crate::util::proc_kb("/proc/meminfo", "MemAvailable").unwrap_or(0) as usize;
        if cow.left() * PAGE_SIZE > avail / 4 {
            return;
        }
        let threads = thread::available_parallelism().map_or(1, |n| n.get()).clamp(1, SAVE_REST_THREADS);
        // Only the runs to save (not every page of guest memory: a VM's
        // unplugged virtio-mem region alone is millions), within a region.
        let chunks: Vec<(usize, usize)> = self.chunks(cow.runs().iter().copied(), PREFETCH_RUN).collect();
        let next = AtomicUsize::new(0);
        thread::scope(|s| {
            for _ in 0..threads {
                // Fewer threads if they cannot be had; the writers do the rest.
                let spawned = thread::Builder::new().spawn_scoped(s, || loop {
                    let Some(&(first, end)) = chunks.get(next.fetch_add(1, Ordering::Relaxed)) else { return };
                    if cow.left() == 0 || !cow.active() {
                        return;
                    }
                    if let Ok(n) = self.rescue(cow, first, end) {
                        cow.stats.held_pages.fetch_add(n as u64, Ordering::Relaxed);
                    }
                });
                if spawned.is_err() {
                    break;
                }
            }
        });
    }

    /// Whether a REMOVE event is queued (the kernel then fails our ioctls
    /// with EAGAIN until it is read). Probes by protecting a page the copy
    /// has yet to save, which is protected already, so changes nothing.
    fn remove_queued(&self, cow: &Cow) -> bool {
        let Some(p) = cow.unsaved_page() else { return false };
        matches!(self.writeprotect(p, 1, true), Err(e) if e.raw_os_error() == Some(libc::EAGAIN))
    }

    /// Turns write tracking on, while the VM runs: registers guest memory for
    /// write-protect faults (once) and protects all of it, so the pause of
    /// the checkpoint that follows only re-protects what changed meanwhile.
    pub fn arm_tracking(&self) -> Result<Duration> {
        let start = Instant::now();
        if self.tracking() {
            return Ok(Duration::ZERO);
        }
        if !self.registered_wp.load(Ordering::SeqCst) {
            for m in self.mappings() {
                // struct uffdio_register: range, mode, ioctls (out).
                let mut r = [m.base_host_virt_addr, m.size as u64, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP, 0];
                if let Err(e) = self.ioctl(UFFDIO_REGISTER, &mut r) {
                    bail!("registering guest memory for write-protect faults: {e}");
                }
            }
            self.registered_wp.store(true, Ordering::SeqCst);
        }
        // Dirty from here on; then protect. A page written before its turn
        // to be protected is protected afterwards all the same. Under the
        // fault lock: a fault already marking and unprotecting a block
        // finishes both first, so it never unprotects one whose mark this
        // reset cleared. (Not held while protecting: the serve thread must
        // be free to read events, or a queued REMOVE would fail the calls.)
        {
            let _wp = self.wp.lock().unwrap();
            self.pages().dirty_bits(true);
            self.tracking.store(true, Ordering::SeqCst);
        }
        // In chunks: while the kernel changes a range, KVM retries guest
        // faults anywhere in it, so one call over a whole region would stall
        // the vCPUs for as long as it takes.
        self.protect(self.chunks(ALL, ARM_CHUNK), None)?;
        Ok(start.elapsed())
    }

    /// Write-protects `ranges`, retrying for a while each one a queued REMOVE
    /// fails. For a freeze, which took the dirty bits `taken`, a failure gives
    /// them back: every page must stay protected or dirty. Either way it turns
    /// tracking off, so everything is protected again next time. Returns how
    /// many ranges it protected.
    fn protect(&self, ranges: impl IntoIterator<Item = (usize, usize)>, taken: Option<&[u64]>) -> Result<usize> {
        let mut n = 0;
        for (first, end) in ranges {
            let start = Instant::now();
            let res = match taken.is_some() && self.fail_protect.swap(false, Ordering::SeqCst) {
                true => Err(io::Error::other("injected fault")),
                false => loop {
                    match self.writeprotect(first, end - first, true) {
                        Err(e) if e.raw_os_error() == Some(libc::EAGAIN) && start.elapsed() < Duration::from_secs(2) => {
                            thread::sleep(Duration::from_micros(200))
                        }
                        r => break r,
                    }
                },
            };
            if let Err(e) = res {
                self.pages().restore_dirty(taken.unwrap_or_default());
                self.tracking.store(false, Ordering::SeqCst);
                bail!("write-protecting guest memory: {e}");
            }
            n += 1;
        }
        Ok(n)
    }

    pub fn tracking(&self) -> bool {
        self.tracking.load(Ordering::SeqCst)
    }

    /// Pages dirtied since the last checkpoint's pause.
    pub fn dirty_count(&self) -> usize {
        self.pages().dirty.iter().map(|w| w.load(Ordering::Relaxed).count_ones() as usize).sum()
    }

    /// Captures memory for a checkpoint of the paused VM, after
    /// `quiesce_export` gave `runs`: takes the pages dirtied since the last
    /// checkpoint's pause (starting a new interval), picks the pages to write
    /// (all populated ones, or with `incremental` only the dirty ones, plus
    /// explicit runs for dirty pages now discarded or the template's), and
    /// with `cow` arms copy-on-write for them so the VM can run on: whatever
    /// was unprotected since the last pause is write-protected again first.
    pub fn freeze(&self, runs: &Runs, incremental: bool, cow: bool) -> Result<Frozen> {
        let _wp = self.wp.lock().unwrap();
        if (cow || incremental) && !self.tracking() {
            bail!("write tracking is off");
        }
        let pages = self.pages();
        // A VM that stays paused for the write (and is then killed) keeps its
        // dirty pages: if the checkpoint fails and it runs on, they still
        // tell what is unprotected. One that runs on starts a new interval.
        let dirty = pages.dirty_bits(cow);
        let ndirty = dirty.iter().map(|w| w.count_ones() as usize).sum();
        // Set bits in ascending page order.
        let dirty_pages = || {
            dirty.iter().enumerate().flat_map(|(w, &bits)| {
                std::iter::successors((bits != 0).then_some(bits), |b| Some(b & (b - 1)).filter(|&b| b != 0))
                    .map(move |b| w * 64 + b.trailing_zeros() as usize)
            })
        };
        let start = Instant::now();
        let mut protected = 0;
        // Everything populated was protected at the last pause (or when
        // tracking began); since then only dirty pages were unprotected.
        for m in self.mappings().iter().filter(|_| cow) {
            let (from, to) = m.span();
            let mut ranges: Vec<(usize, usize)> = Vec::new();
            for p in dirty_pages().filter(|&p| p >= from && p < to && pages.get(p) == PRESENT) {
                match ranges.last_mut() {
                    Some((_, e)) if p <= *e + PROTECT_GAP => *e = p + 1,
                    _ => ranges.push((p, p + 1)),
                }
            }
            // Range by range, so that the pause grows with what was written
            // rather than with what is populated; unless the calls would cost
            // more than walking every populated page of the region once (the
            // writes covered most of it).
            if ranges.len() > PROTECT_RUNS && ranges.len() * PROTECT_GAP > pages.count(PRESENT, from, to) {
                ranges = vec![(from, to)];
            }
            protected += self.protect(ranges, Some(&dirty))?;
        }
        let protect = start.elapsed();
        let out = match incremental {
            false => runs.clone(),
            true => {
                // Pages not dirty keep what the previous checkpoint has.
                let mut out: Runs = Vec::new();
                for p in dirty_pages().take_while(|&p| p < pages.len()) {
                    let r = runs.partition_point(|r| r.0 <= p as u64);
                    let st = match r.checked_sub(1).map(|r| runs[r]) {
                        Some((f, n, s)) if (p as u64) < f + n => s,
                        _ => BASE,
                    };
                    match out.last_mut() {
                        Some((f, n, s)) if *s == st && *f + *n == p as u64 => *n += 1,
                        _ => out.push((p as u64, 1, st)),
                    }
                }
                out
            }
        };
        let cow = cow.then(|| Arc::new(Cow::new(pages.len(), &out)));
        *self.cow.lock().unwrap() = cow.clone();
        let taken = if cow.is_some() { dirty } else { Vec::new() };
        Ok(Frozen { runs: out, cow, dirty: ndirty, taken, protected, protect })
    }

    /// Undoes `freeze` for a checkpoint that failed: stops its copy and marks
    /// dirty again what it took, so the previous checkpoint is still the base
    /// of the next delta. Pages the freeze protected stay protected until
    /// written, which marks them dirty, so nothing is lost either way.
    pub fn unfreeze(&self, frozen: &Frozen) {
        self.end_copy();
        let _wp = self.wp.lock().unwrap();
        self.pages().restore_dirty(&frozen.taken);
    }

    /// Ends a checkpoint copy, finished or not. Pages stay protected for tracking.
    pub fn end_copy(&self) {
        if let Some(cow) = self.cow.lock().unwrap().take() {
            cow.stop();
        }
    }

    /// Stops a checkpoint copy in progress (its checkpoint fails).
    pub fn abort_copy(&self) {
        if let Some(cow) = self.cow.lock().unwrap().as_ref() {
            cow.invalidate("the copy was aborted");
        }
    }

    pub fn copying(&self) -> bool {
        self.cow.lock().unwrap().is_some()
    }

    /// The running checkpoint copy's counters (for fault tests).
    pub fn copy_stats(&self) -> Option<serde_json::Value> {
        self.cow.lock().unwrap().as_ref().map(|c| c.report())
    }

    /// The canonical hash of guest memory as it is now (for a paused VM; a
    /// test hook): see `checkpoint::Canon`.
    pub fn content_hash(&self) -> Result<String> {
        let pages = self.pages();
        let mut canon = crate::checkpoint::Canon::new(&self.base);
        let mut buf = vec![0u8; 256 * PAGE_SIZE];
        for (first, end) in self.chunks(ALL, 256) {
            for (a, b) in runs_where(first, end, |p| pages.get(p) == PRESENT) {
                self.read_guest((a * PAGE_SIZE) as u64, &mut buf[(a - first) * PAGE_SIZE..(b - first) * PAGE_SIZE])?;
            }
            for p in first..end {
                match pages.get(p) {
                    BASE => {}
                    ZERO => canon.page(p, &[]),
                    PRESENT => canon.page(p, &buf[(p - first) * PAGE_SIZE..(p - first + 1) * PAGE_SIZE]),
                    s => bail!("page {p} is in state {s}"),
                }
            }
        }
        Ok(canon.finish())
    }

    /// A uffd ioctl, `arg` being its struct (all 64-bit words).
    fn ioctl(&self, req: libc::c_ulong, arg: &mut [u64]) -> io::Result<()> {
        match unsafe { libc::ioctl(self.uffd.get().unwrap().as_raw_fd(), req, arg.as_mut_ptr()) } {
            0.. => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Where `page` is mapped in Firecracker.
    fn addr(&self, page: usize) -> io::Result<u64> {
        self.host_addr(page).map(|(a, _)| a).ok_or_else(|| io::Error::other("bad page"))
    }

    /// Populates up to `n` pages starting at `page`, from `src` or with
    /// zeroes, and wakes their waiters. Returns how many it populated: the
    /// kernel stops early (reporting progress) at a page that already exists.
    fn populate(&self, page: usize, n: usize, src: Option<&[u8]>) -> io::Result<usize> {
        match src {
            Some(src) => self.copy(page, n, src, 0),
            // struct uffdio_zeropage: range, mode, zeropage (out).
            None => self.progress(UFFDIO_ZEROPAGE, n, &mut [self.addr(page)?, (n * PAGE_SIZE) as u64, 0, 0]),
        }
    }

    /// `populate` from `src`, with UFFDIO_COPY `mode`.
    fn copy(&self, page: usize, n: usize, src: &[u8], mode: u64) -> io::Result<usize> {
        // struct uffdio_copy: dst, src, len, mode, copy (out).
        self.progress(UFFDIO_COPY, n, &mut [self.addr(page)?, src.as_ptr() as u64, (n * PAGE_SIZE) as u64, mode, 0])
    }

    /// Runs a populating ioctl on `n` pages whose struct ends with the bytes done.
    fn progress(&self, req: libc::c_ulong, n: usize, arg: &mut [u64]) -> io::Result<usize> {
        match self.ioctl(req, arg) {
            Ok(()) => Ok(n),
            Err(e) => match (arg[arg.len() - 1] as i64).max(0) as usize / PAGE_SIZE {
                0 => Err(e),
                done => Ok(done),
            },
        }
    }

    /// Write-protects (or unprotects, waking writers waiting on them) `n` pages from `page`.
    fn writeprotect(&self, page: usize, n: usize, protect: bool) -> io::Result<()> {
        // struct uffdio_writeprotect: range, mode.
        let mode = if protect { UFFDIO_WRITEPROTECT_MODE_WP } else { 0 };
        self.ioctl(UFFDIO_WRITEPROTECT, &mut [self.addr(page)?, (n * PAGE_SIZE) as u64, mode])
    }

    fn wake(&self, page: usize) -> io::Result<()> {
        self.ioctl(UFFDIO_WAKE, &mut [self.addr(page)?, PAGE_SIZE as u64])
    }

    /// Starts the threads that fetch pages for faults (`fetch_faults`) and
    /// that pull every REMOTE page in the background (`pull`), so the source
    /// can let go (or, restoring a checkpoint, the VM no longer needs its file).
    fn spawn_pullers(self: Arc<Self>) {
        let file = self.file.lock().unwrap().clone();
        // Released already: every page is in.
        if file.is_none() && self.from_file.load(Ordering::SeqCst) {
            return;
        }
        // The connection made for the snapshot load goes to a fault fetcher.
        let mut link = self.remote.lock().unwrap().take();
        let source = link.as_ref().map(|l| l.source.clone());
        for i in 0..FAULT_FETCHERS + PULL_THREADS {
            let (p, puller) = (self.clone(), i >= FAULT_FETCHERS);
            // Reads from the checkpoint file (evicting what it read, for a
            // puller) or over a source connection of its own.
            let mut fetch: Box<Fetch> = match (file.clone(), &source) {
                (Some(file), _) => Box::new(move |off, buf, _, _| file.read(off as usize / PAGE_SIZE, buf, puller)),
                (None, Some(source)) => {
                    let mut link = link.take().unwrap_or_else(|| Link::new(source.clone()));
                    // A fault waits for the first page of its run: ask for it first.
                    let head = if puller { 0 } else { PAGE_SIZE };
                    Box::new(move |off, buf, stop, progress| link.fetch(off, buf, stop, head, progress))
                }
                (None, None) => return self.fail("remote pages but nowhere to pull them from".into()),
            };
            let file = file.clone();
            thread::spawn(move || match puller {
                false => p.fetch_faults(&mut fetch),
                true => p.pull(i - FAULT_FETCHERS, file, &mut fetch),
            });
        }
    }

    /// Fetches and installs the runs faults claimed (`demand`), so that the
    /// event thread never waits for the network or disk. The faulting thread
    /// is woken by the copy, the event thread by the pages settling.
    fn fetch_faults(&self, fetch: &mut Fetch) {
        let mut buf = vec![0u8; REMOTE_FAULT_RUN * PAGE_SIZE];
        let pages = self.pages();
        loop {
            let (page, n, queued) = {
                let mut jobs = self.demand.0.lock().unwrap();
                loop {
                    if self.stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Some(job) = jobs.pop_front() {
                        break job;
                    }
                    // Claimed pages count as left until they settle, so with
                    // none left no fault can queue another run.
                    if self.remote_left() == 0 {
                        return;
                    }
                    jobs = self.demand.1.wait_timeout(jobs, Duration::from_millis(100)).unwrap().0;
                }
            };
            self.fault_stats.record(QUEUED, queued.elapsed());
            // Pages that have kept failing past the deadline, however they
            // were queued again: give up now rather than after one more try.
            if pages.failing_since(page, n).is_some_and(|t| t.elapsed() >= FAULT_TIMEOUT) {
                return self.fail(format!("installing pages {page}+{n} for a fault kept failing for {FAULT_TIMEOUT:?}"));
            }
            let started = Instant::now();
            // A link waits out a source outage itself (until it gives up,
            // which is fatal); other errors are retried for a while.
            let mut retry = |e: &io::Error| {
                let again = !fatal(e) && !self.stop.load(Ordering::SeqCst) && started.elapsed() < FAULT_TIMEOUT;
                if again {
                    eprintln!("uffd: fetching pages {page}+{n} for a fault: {e}; retrying");
                    thread::sleep(BACKOFF_MIN);
                }
                again
            };
            // Test fault `fetch_tail_enomem`: once the pullers are past this
            // run, a copy of its tail fails as if memory were short.
            let tail_fail = self.tail_fail.load(Ordering::SeqCst) > 0;
            let mut held = false;
            let mut fetch = |off: u64, buf: &mut [u8], stop: &AtomicBool, progress: &mut dyn FnMut(&[u8]) -> bool| {
                fetch(off, buf, stop, &mut |data: &[u8]| {
                    if tail_fail && !held && data.len() > PAGE_SIZE {
                        held = true;
                        let t = Instant::now();
                        while self.remote_left() > n && t.elapsed() < Duration::from_secs(5) {
                            thread::sleep(Duration::from_millis(1));
                        }
                    }
                    progress(data)
                })
            };
            let mut first = true;
            let stuck = *self.stuck_from.lock().unwrap();
            let res = self.install_claimed(page, n, &mut buf, &mut fetch, &mut retry, |p, c, src| {
                if tail_fail && p != page && self.tail_fail.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |k| k.checked_sub(1)).is_ok() {
                    return Err(os(libc::ENOMEM));
                }
                // Test fault `fetch_enomem_stuck`.
                if stuck.is_some_and(|t| Instant::now() >= t) {
                    return Err(os(libc::ENOMEM));
                }
                let r = self.populate(p, c, Some(src));
                if std::mem::take(&mut first) {
                    self.fault_stats.record(FIRST, queued.elapsed());
                }
                r
            });
            self.fault_stats.record(FETCH, started.elapsed());
            match res {
                Ok(()) => {}
                Err(Failed::Fetch(_)) if self.stop.load(Ordering::SeqCst) => {}
                Err(Failed::Fetch(e)) => return self.fail(format!("fetching pages for a fault: {e}")),
                Err(Failed::Install(e)) if self.unmapped(&e, page, n) => return self.gone(),
                Err(Failed::Install(e)) => {
                    // Since when these pages have kept failing to install,
                    // whoever claimed them (this requeue, or a fault that got
                    // to them first): noted per page as it failed, so that no
                    // claim starts the deadline over.
                    let since = pages.failing_since(page, n).unwrap_or_else(Instant::now);
                    if since.elapsed() >= FAULT_TIMEOUT {
                        return self.fail(format!("installing pages for a fault: {e}"));
                    }
                    eprintln!("uffd: installing pages {page}+{n} for a fault: {e}; retrying");
                    // What went back to REMOTE may have no fault waiting on it
                    // any more (the faulting page went in first) and the
                    // pullers may be past it: queue it again, with its failure
                    // history, so it is not stranded.
                    thread::sleep(BACKOFF_MIN);
                    let mut jobs = self.demand.0.lock().unwrap();
                    let mut i = page;
                    while i < page + n {
                        match pages.claim(i, page + n - i, REMOTE, |_| true) {
                            0 => i += 1,
                            k => {
                                jobs.push_back((i, k, Instant::now()));
                                i += k;
                            }
                        }
                    }
                    self.demand.1.notify_one();
                }
            }
        }
    }

    /// `Pages::fetch_install`, counting the REMOTE pages resolved. A fetch
    /// that failed once every page was resolved anyway (discarded meanwhile)
    /// is no failure.
    fn install_claimed(
        &self,
        first: usize,
        n: usize,
        buf: &mut [u8],
        fetch: &mut FetchAny<'_>,
        retry: &mut dyn FnMut(&io::Error) -> bool,
        populate: impl FnMut(usize, usize, &[u8]) -> io::Result<usize>,
    ) -> std::result::Result<(), Failed> {
        let (resolved, res) = self.pages().fetch_install(first, n, buf, fetch, &self.stop, retry, populate);
        self.pulled(resolved);
        match res {
            Err(Failed::Fetch(_)) if resolved == n => Ok(()),
            r => r,
        }
    }

    /// Background puller `t` of `PULL_THREADS`: pulls its share of the REMOTE
    /// pages, a run at a time. `fetch` holds the file (if any) too: let go as
    /// the thread ends, as soon as nothing is left to pull.
    fn pull(&self, t: usize, file: Option<Arc<PageFile>>, fetch: &mut Fetch) {
        // A checkpoint's pages come off local disk: the ones in the
        // template's working set first, as the guest needs them soonest.
        let first = self.chunks(self.working_set(t, PULL_THREADS).filter(|_| file.is_some()), usize::MAX);
        let all = self.chunks(ALL, PULL_RUN).skip(t).step_by(PULL_THREADS);
        let mut buf = vec![0u8; PULL_RUN * PAGE_SIZE];
        let pages = self.pages();
        for (mut i, end) in first.chain(all) {
            while i < end && !self.stop.load(Ordering::SeqCst) && self.remote_left() > 0 {
                // Test fault `fetch_enomem_stuck`: only faults fetch pages.
                while self.stuck_from.lock().unwrap().is_some() && !self.stop.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(10));
                }
                let n = pages.claim(i, (end - i).min(PULL_RUN), REMOTE, |_| true);
                if n == 0 {
                    // On to the next REMOTE page, skipping untouched stretches.
                    i = pages.next_in(REMOTE, i + 1, end);
                    continue;
                }
                let started = Instant::now();
                let res = self.install_claimed(i, n, &mut buf, fetch, &mut |_| false, |p, c, src| self.populate(p, c, Some(src)));
                self.fault_stats.record(PULL, started.elapsed());
                match res {
                    Ok(()) => i += n,
                    Err(Failed::Install(e)) if self.unmapped(&e, i, n) => return self.gone(),
                    Err(Failed::Fetch(e) | Failed::Install(e)) => return self.fail(format!("background pull {t} failed: {e}")),
                }
            }
        }
        if let Some(file) = file.filter(|_| self.remote_left() == 0) {
            file.drop_cache();
        }
    }

    /// Every `step`th range of the template's working set from range `skip`, as `[first, end)`.
    fn working_set(&self, skip: usize, step: usize) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.base.working_set.iter().skip(skip).step_by(step).map(|&(f, n)| (f as usize, (f + n) as usize))
    }

    /// `ranges` (as `[first, end)`) cut at region ends and into pieces of at most `max` pages.
    fn chunks<'a>(&'a self, ranges: impl IntoIterator<Item = (usize, usize)> + 'a, max: usize) -> impl Iterator<Item = (usize, usize)> + 'a {
        ranges.into_iter().flat_map(move |(a, b)| {
            self.mappings().iter().flat_map(move |m| {
                let (from, to) = (a.max(m.span().0), b.min(m.span().1));
                (from..to).step_by(max).map(move |c| (c, c.saturating_add(max).min(to)))
            })
        })
    }
}

/// A page-server connection to the migration source that reconnects with
/// backoff, and gives up once the source has been unreachable for
/// `SOURCE_TIMEOUT`.
struct Link {
    source: Source,
    client: Option<PageClient>,
    /// When the current outage began.
    down: Option<Instant>,
    retry_at: Instant,
    backoff: Duration,
}

impl Link {
    fn new(source: Source) -> Link {
        Link { source, client: None, down: None, retry_at: Instant::now(), backoff: BACKOFF_MIN }
    }

    /// Reads guest memory at `offset` from the source, reporting `progress`
    /// as `PageClient::fetch` does (from the start again after a reconnect).
    /// Waiting to reconnect, it sleeps until `stop` is set. Fails with
    /// TimedOut once the outage is too long.
    fn fetch(&mut self, offset: u64, buf: &mut [u8], stop: &AtomicBool, head: usize, progress: &mut dyn FnMut(&[u8]) -> bool) -> io::Result<()> {
        loop {
            if self.client.is_none() {
                if stop.load(Ordering::SeqCst) {
                    return Err(io::Error::other("pager stopped"));
                }
                thread::sleep(self.retry_at.saturating_duration_since(Instant::now()));
                match PageClient::connect(&self.source) {
                    Ok(c) => self.client = Some(c),
                    Err(e) => {
                        self.lost(e)?;
                        continue;
                    }
                }
            }
            match self.client.as_mut().unwrap().fetch(offset, buf, head, progress) {
                Ok(()) => {
                    self.down = None;
                    self.backoff = BACKOFF_MIN;
                    return Ok(());
                }
                Err(e) => {
                    self.client = None;
                    // Stopped by the caller: the source is fine.
                    if e.get_ref().is_some_and(|e| e.is::<Cancelled>()) {
                        return Err(e);
                    }
                    self.lost(e)?;
                }
            }
        }
    }

    /// Schedules a reconnect after `e`, or gives up.
    fn lost(&mut self, e: io::Error) -> io::Result<()> {
        let since = *self.down.get_or_insert_with(Instant::now);
        if since.elapsed() >= SOURCE_TIMEOUT {
            let why = format!("migration source {} unreachable for {:?}: {e}", self.source.addr, since.elapsed());
            return Err(io::Error::new(io::ErrorKind::TimedOut, why));
        }
        if self.backoff == BACKOFF_MIN {
            eprintln!("uffd: page fetch from {} failed, reconnecting: {e}", self.source.addr);
        }
        self.retry_at = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
        Ok(())
    }
}

/// Whether a migration source serves pages at all: fetches `page`, retrying
/// as a pager would (for up to `SOURCE_TIMEOUT`, and not past `deadline`).
pub fn probe(source: &Source, page: u64, deadline: Instant) -> io::Result<()> {
    let give_up = deadline.min(Instant::now() + SOURCE_TIMEOUT);
    let mut backoff = BACKOFF_MIN;
    // One attempt: connecting, the request and every read by `give_up`.
    let once = || {
        let left = give_up.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline passed"));
        }
        let s = crate::util::connect(&source.addr, left)?;
        s.set_nodelay(true)?;
        let mut client = PageClient::new(crate::util::By { s, at: give_up }, source)?;
        client.fetch(page * PAGE_SIZE as u64, &mut [0u8; PAGE_SIZE], 0, &mut |_| true)
    };
    loop {
        let e = match once() {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        if Instant::now() + backoff >= give_up {
            return Err(io::Error::new(io::ErrorKind::TimedOut, format!("no page from {} in time: {e}", source.addr)));
        }
        thread::sleep(backoff);
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// Client for a migration source's page server.
pub struct PageClient<S = TcpStream> {
    stream: S,
    /// Whether the server's answer to the `pages` request has been read: it
    /// is read along with the first reply, so connecting costs no round trip.
    acked: bool,
}

impl PageClient {
    pub fn connect(source: &Source) -> io::Result<Self> {
        let stream = crate::util::connect(&source.addr, Duration::from_millis(500))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        PageClient::new(stream, source)
    }
}

impl<S: Read + Write> PageClient<S> {
    fn new(mut stream: S, source: &Source) -> io::Result<Self> {
        let mut hello = serde_json::to_vec(&serde_json::json!({"op": "pages", "name": source.vm, "mig": source.mig}))?;
        hello.push(b'\n');
        stream.write_all(&hello)?;
        Ok(PageClient { stream, acked: false })
    }

    /// Reads guest memory at `offset` into `buf`, calling `progress` with
    /// what has arrived so far as it does. With `head` (bytes, less than
    /// `buf`), the first `head` bytes are asked for on their own, ahead of
    /// the rest: the server reads and sends them without waiting to read
    /// the rest out of guest memory.
    pub fn fetch(&mut self, offset: u64, buf: &mut [u8], head: usize, progress: &mut dyn FnMut(&[u8]) -> bool) -> io::Result<()> {
        let parts = match head {
            h if h > 0 && h < buf.len() => vec![(0, h), (h, buf.len())],
            _ => vec![(0, buf.len())],
        };
        let mut req = Vec::with_capacity(12 * parts.len());
        for &(a, b) in &parts {
            req.extend_from_slice(&(offset + a as u64).to_le_bytes());
            req.extend_from_slice(&((b - a) as u32).to_le_bytes());
        }
        self.stream.write_all(&req)?;
        if !self.acked {
            self.read_ack()?;
            self.acked = true;
        }
        for (a, b) in parts {
            let mut status = [0u8; 1];
            self.stream.read_exact(&mut status)?;
            if status[0] != 0 {
                return Err(io::Error::other("page server could not read guest memory"));
            }
            let mut filled = a;
            while filled < b {
                match self.stream.read(&mut buf[filled..b]) {
                    Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    Ok(n) => {
                        filled += n;
                        if !progress(&buf[..filled]) {
                            return Err(io::Error::other(Cancelled));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// Reads the page server's answer to the `pages` request: one JSON line,
    /// `{"ok": true}` before the binary protocol, or why it refuses (then it
    /// hangs up). Read a byte at a time, so nothing after it is consumed.
    fn read_ack(&mut self) -> io::Result<()> {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        while b[0] != b'\n' {
            if line.len() >= 4096 {
                return Err(io::Error::other("page server sent an overlong answer"));
            }
            if self.stream.read(&mut b)? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "page server hung up before answering"));
            }
            line.push(b[0]);
        }
        let v: serde_json::Value = serde_json::from_slice(&line).map_err(|e| io::Error::other(format!("page server answer: {e}")))?;
        if v["ok"] != serde_json::json!(true) {
            let why = v["error"].as_str().unwrap_or("no reason given");
            return Err(io::Error::other(format!("page server refused: {why}")));
        }
        Ok(())
    }
}

/// A fetch its caller stopped part way (`progress` said so); what was left
/// of the reply is unread, so the connection goes.
#[derive(Debug)]
struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("fetch cancelled")
    }
}

impl std::error::Error for Cancelled {}

/// Serves page reads for `pager` on an accepted page-server connection
/// (already answered `ok`), until the client hangs up, sits idle for
/// `SERVE_IDLE`, asks for more than `MAX_FETCH`, or `stop()` says to drop
/// it. `stop` is asked before every request and every second meanwhile, so
/// a connection ends soon after its VM stops being a migration source.
/// `conn` is the socket under `stream`, for its timeouts.
pub fn serve_pages(pager: &Pager, conn: &TcpStream, mut stream: impl Read + Write, stop: impl Fn() -> bool) -> io::Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(1)))?;
    conn.set_write_timeout(Some(SERVE_WRITE))?;
    let mut req = [0u8; 12];
    let mut buf = Vec::new();
    while read_request(&mut stream, &mut req, &stop) && !stop() {
        let offset = u64::from_le_bytes(req[..8].try_into().unwrap());
        let len = u32::from_le_bytes(req[8..].try_into().unwrap()) as usize;
        if len > MAX_FETCH {
            eprintln!("page server: refusing a {len}-byte read (at most {MAX_FETCH}); dropping the connection");
            return stream.write_all(&[1]);
        }
        // The status byte, then the pages: sent with one write.
        buf.resize(1 + len, 0);
        buf[0] = 0;
        match pager.read_guest(offset, &mut buf[1..]) {
            Ok(()) => stream.write_all(&buf)?,
            Err(e) => {
                eprintln!("page server: {e}");
                stream.write_all(&[1])?;
            }
        }
    }
    Ok(())
}

/// Reads one 12-byte request through the socket's 1 s read timeout. False
/// when the client hung up or the connection should end (`stop`, or idle
/// for `SERVE_IDLE`).
fn read_request(stream: &mut impl Read, req: &mut [u8; 12], stop: &impl Fn() -> bool) -> bool {
    let since = Instant::now();
    let mut n = 0;
    while n < req.len() {
        match stream.read(&mut req[n..]) {
            Ok(0) => return false,
            Ok(k) => n += k,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if stop() || since.elapsed() >= SERVE_IDLE {
                    return false;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

/// The pages of `wanted` (sorted) that `runs` make REMOTE on a target.
pub fn remote_among(runs: &Runs, wanted: impl IntoIterator<Item = u64>) -> Vec<u64> {
    let mut remote: Vec<(u64, u64)> = runs.iter().filter(|r| r.2 == REMOTE).map(|r| (r.0, r.0 + r.1)).collect();
    remote.sort_unstable();
    let is_remote = |&p: &u64| remote.get(remote.partition_point(|r| r.1 <= p)).is_some_and(|r| r.0 <= p);
    wanted.into_iter().filter(is_remote).collect()
}

const ALL: [(usize, usize); 1] = [(0, usize::MAX)];

/// The maximal runs `[a, b)` within `[first, end)` of pages that pass `f`
/// (asked once per page).
pub(crate) fn runs_where(first: usize, end: usize, f: impl Fn(usize) -> bool) -> impl Iterator<Item = (usize, usize)> {
    let mut p = first;
    std::iter::from_fn(move || {
        let a = (p..end).find(|&i| f(i))?;
        p = (a + 1..end).find(|&i| !f(i)).unwrap_or(end);
        Some((a, p))
    })
}

/// Reads guest memory at an offset from wherever REMOTE pages come from,
/// reporting what has arrived as it does (see `PageClient::fetch`; a file
/// read reports nothing).
type Fetch = dyn FnMut(u64, &mut [u8], &AtomicBool, &mut dyn FnMut(&[u8]) -> bool) -> io::Result<()> + Send;
/// `Fetch`, borrowed and not necessarily `Send`.
type FetchAny<'a> = dyn FnMut(u64, &mut [u8], &AtomicBool, &mut dyn FnMut(&[u8]) -> bool) -> io::Result<()> + 'a;
/// A run of REMOTE pages a fault claimed, `(first, count)`, and when it was queued.
type Job = (usize, usize, Instant);

/// Errors after which the pager gives up on the VM: its migration source has
/// been gone too long, or its checkpoint file is unreadable or corrupt.
fn fatal(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::InvalidData)
}

fn regions(mappings: &[Mapping]) -> Vec<(u64, u64)> {
    mappings.iter().map(|m| (m.offset, m.size as u64)).collect()
}

/// Checks page runs from a migration source (ascending, disjoint, in bounds,
/// and only states a source exports) and counts their REMOTE pages.
fn remote_pages(runs: &Runs, total: usize) -> Result<usize> {
    let (mut next, mut remote) = (0, 0);
    for &(first, count, state) in runs {
        match first.checked_add(count) {
            Some(end) if first >= next && count > 0 && end <= total as u64 && (state == REMOTE || state == ZERO) => {
                next = end;
                if state == REMOTE {
                    remote += count as usize;
                }
            }
            _ => bail!("bad page run {:?}", (first, count, state)),
        }
    }
    Ok(remote)
}

/// Receives Firecracker's handshake: a JSON body plus the uffd over SCM_RIGHTS.
fn recv_with_fd(sock: RawFd) -> Result<(Vec<u8>, OwnedFd)> {
    let mut body = vec![0u8; 64 * 1024];
    let mut cmsg = [0u8; 64];
    let mut iov = [IoSliceMut::new(&mut body)];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr().cast();
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = cmsg.len();
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n <= 0 {
        bail!("recvmsg: {}", io::Error::last_os_error());
    }
    let c = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if c.is_null() || unsafe { (*c).cmsg_type } != libc::SCM_RIGHTS {
        bail!("handshake carried no file descriptor");
    }
    let fd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const RawFd) };
    body.truncate(n as usize);
    Ok((body, unsafe { OwnedFd::from_raw_fd(fd) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pages(states: &[u8]) -> Pages {
        let p = Pages::new(states.len());
        for (i, &s) in states.iter().enumerate() {
            p.set(i, s);
        }
        p
    }

    fn states(p: &Pages) -> Vec<u8> {
        (0..p.len()).map(|i| p.get(i)).collect()
    }

    fn discard(p: &Pages, page: usize) -> bool {
        p.discard(&p.removing(), page)
    }

    /// Streamed installs under random interleavings: the fetch delivers its
    /// run in random pieces and may fail part way (and be retried, or not),
    /// REMOVEs land while it is on the wire, copies stop part way, hit
    /// EEXIST, EAGAIN or fail. Every page ends settled, installed pages get
    /// their own contents, and every REMOTE page is counted resolved once.
    #[test]
    fn streamed_installs_add_up() {
        let seed = AtomicU64::new(0x2545_f491_4f6c_dd1d);
        let rand = |n: usize| {
            let mut s = seed.load(Ordering::Relaxed);
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            seed.store(s, Ordering::Relaxed);
            (s % n as u64) as usize
        };
        let stop = AtomicBool::new(false);
        let mut fetches = 0;
        for _ in 0..1000 {
            let p = pages(&[REMOTE; 64]);
            let mut resolved = 0;
            for _ in 0..20 {
                let first = rand(64);
                if rand(4) == 0 {
                    resolved += discard(&p, first) as usize;
                    continue;
                }
                let n = p.claim(first, 1 + rand(48), REMOTE, |_| true);
                if n == 0 {
                    continue;
                }
                let (fails, retries) = (rand(3), rand(2) == 0);
                let (mut attempts, mut discarded) = (0, 0);
                let mut fetch = |off: u64, buf: &mut [u8], _: &AtomicBool, progress: &mut dyn FnMut(&[u8]) -> bool| -> io::Result<()> {
                    attempts += 1;
                    let start = off as usize / PAGE_SIZE;
                    assert!(start >= first && start + buf.len() / PAGE_SIZE == first + n, "refetches what has yet to arrive");
                    let mut filled = 0;
                    while filled < buf.len() {
                        let k = (1 + rand(3 * PAGE_SIZE)).min(buf.len() - filled);
                        for (i, b) in buf[filled..filled + k].iter_mut().enumerate() {
                            *b = (start + (filled + i) / PAGE_SIZE) as u8;
                        }
                        filled += k;
                        if rand(8) == 0 {
                            discarded += discard(&p, first + rand(n)) as usize;
                        }
                        if attempts <= fails && rand(4) == 0 {
                            return Err(os(libc::ECONNRESET));
                        }
                        if !progress(&buf[..filled]) {
                            return Err(io::Error::other(Cancelled));
                        }
                    }
                    Ok(())
                };
                let mut retry = |_: &io::Error| retries;
                let (r, _) = p.fetch_install(first, n, &mut vec![0u8; n * PAGE_SIZE], &mut fetch, &stop, &mut retry, |pg, c, src| {
                    assert!(src.len() >= c * PAGE_SIZE);
                    for i in 0..c {
                        assert!(src[i * PAGE_SIZE..(i + 1) * PAGE_SIZE].iter().all(|&b| b == (pg + i) as u8), "page {} gets its own data", pg + i);
                    }
                    match rand(10) {
                        0 => Err(os(libc::EEXIST)),
                        1 => {
                            // A REMOVE is queued; the event thread reads it.
                            p.read_gen.fetch_add(1, Ordering::SeqCst);
                            Err(os(libc::EAGAIN))
                        }
                        2 => Err(os(libc::EIO)),
                        _ => Ok(1 + rand(c)),
                    }
                });
                // Only pages a failed install gave back can be REMOTE again by then.
                resolved += discarded;
                resolved += r;
                fetches += 1;
            }
            let s = states(&p);
            assert!(s.iter().all(|&s| s != INFLIGHT && s != DISCARDED), "{s:?}");
            assert_eq!(resolved, 64 - s.iter().filter(|&&s| s == REMOTE).count());
            // Failure history is kept only for pages still to come.
            let failing = p.failing.lock().unwrap();
            assert!(failing.iter().all(|&(pg, _)| s[pg] == REMOTE), "{failing:?} {s:?}");
            assert_eq!(p.failing_len.load(Ordering::SeqCst), failing.len());
        }
        assert!(fetches > 5000);
    }

    /// A page that fails to install is remembered (with when it first
    /// failed) until it goes in or is discarded, however it gets claimed
    /// again; its neighbours that did go in are not.
    #[test]
    fn failure_history_follows_the_pages() {
        let p = pages(&[REMOTE; 8]);
        let enomem = |fail: usize| move |pg: usize, c: usize| if (pg..pg + c).contains(&fail) { if pg == fail { Err(os(libc::ENOMEM)) } else { Ok(fail - pg) } } else { Ok(c) };
        p.claim(0, 4, REMOTE, |_| true);
        assert!(p.install(0, 4, REMOTE, None, enomem(2)).1.is_err());
        assert_eq!(states(&p)[..4], [PRESENT, PRESENT, REMOTE, REMOTE]);
        let first = p.failing_since(0, 8).expect("page 2 noted");
        assert_eq!(p.failing_since(0, 2), None, "pages that went in are not");
        assert_eq!(p.failing_since(3, 1), None, "nor ones given back unattempted");
        // Claimed again (by anyone) and failing again: the first time sticks.
        thread::sleep(Duration::from_millis(5));
        p.claim(2, 2, REMOTE, |_| true);
        assert!(p.install(2, 2, REMOTE, None, enomem(2)).1.is_err());
        assert_eq!(p.failing_since(2, 1), Some(first));
        // In at last: forgotten.
        p.claim(2, 2, REMOTE, |_| true);
        assert!(p.install(2, 2, REMOTE, None, |_, c| Ok(c)).1.is_ok());
        assert_eq!(p.failing_since(0, 8), None);
        assert_eq!(p.failing_len.load(Ordering::SeqCst), 0);
        // Discarded instead, while given back or while claimed: forgotten too.
        for claimed in [false, true] {
            let p = pages(&[REMOTE; 2]);
            p.claim(0, 2, REMOTE, |_| true);
            assert!(p.install(0, 2, REMOTE, None, enomem(0)).1.is_err());
            assert!(p.failing_since(0, 1).is_some());
            if claimed {
                p.claim(0, 1, REMOTE, |_| true);
            }
            discard(&p, 0);
            if claimed {
                assert!(p.install(0, 1, REMOTE, None, |_, _| panic!("discarded")).1.is_ok());
            }
            assert_eq!(p.failing_since(0, 2), None, "claimed {claimed}");
            assert_eq!(p.failing_len.load(Ordering::SeqCst), 0);
        }
    }

    /// A streamed install that fails stops the fetch at once.
    #[test]
    fn failed_install_cancels_the_fetch() {
        let p = pages(&[REMOTE; 64]);
        p.claim(0, 64, REMOTE, |_| true);
        let mut delivered = 0;
        let mut fetch = |_: u64, buf: &mut [u8], _: &AtomicBool, progress: &mut dyn FnMut(&[u8]) -> bool| -> io::Result<()> {
            for k in 1..=buf.len() / PAGE_SIZE {
                delivered = k;
                if !progress(&buf[..k * PAGE_SIZE]) {
                    return Err(io::Error::other(Cancelled));
                }
            }
            Ok(())
        };
        let stop = AtomicBool::new(false);
        let (resolved, res) = p.fetch_install(0, 64, &mut vec![0u8; 64 * PAGE_SIZE], &mut fetch, &stop, &mut |_| true, |pg, _, _| match pg {
            0 => Ok(1),
            _ => Err(os(libc::ENOMEM)),
        });
        assert!(matches!(res, Err(Failed::Install(_))));
        assert_eq!(resolved, 1);
        assert_eq!(delivered, 1 + STREAM_RUN, "stopped as soon as the second install failed");
        assert!(states(&p)[1..].iter().all(|&s| s == REMOTE));
        assert!(p.failing_since(1, 1).is_some());
    }

    /// Faults waiting on claimed pages are woken when they settle, whether
    /// installed, given back or discarded; with none waiting, nobody is.
    #[test]
    fn settling_wakes_waiting_faults() {
        let p = pages(&[REMOTE; 8]);
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(fd >= 0);
        p.wake.set(unsafe { OwnedFd::from_raw_fd(fd) }).unwrap();
        let woken = || {
            let mut n = 0u64;
            unsafe { libc::read(fd, (&mut n as *mut u64).cast(), 8) == 8 }
        };
        p.claim(0, 2, REMOTE, |_| true);
        assert!(p.install(0, 2, REMOTE, None, |_, n| Ok(n)).1.is_ok());
        assert!(!woken(), "nobody waits");
        p.waiting.store(true, Ordering::SeqCst);
        p.claim(2, 2, REMOTE, |_| true);
        assert!(p.install(2, 2, REMOTE, None, |_, n| Ok(n)).1.is_ok());
        assert!(woken(), "installed");
        p.claim(4, 2, REMOTE, |_| true);
        p.release(4, 2, REMOTE);
        assert!(woken(), "given back");
        p.claim(6, 2, REMOTE, |_| true);
        discard(&p, 6);
        discard(&p, 7);
        assert!(p.install(6, 2, REMOTE, None, |_, _| panic!("discarded pages are not copied")).1.is_ok());
        assert!(woken(), "discarded while claimed");
        assert!(!woken());
        assert_eq!(states(&p), [PRESENT, PRESENT, PRESENT, PRESENT, REMOTE, REMOTE, ZERO, ZERO]);
    }

    /// An install that hits EAGAIN (a REMOVE is queued) waits for the event
    /// thread to read events, then copies again.
    #[test]
    fn eagain_waits_for_events_read() {
        let p = pages(&[REMOTE; 2]);
        p.claim(0, 2, REMOTE, |_| true);
        let stop = AtomicBool::new(false);
        let mut calls = 0;
        thread::scope(|s| {
            s.spawn(|| {
                thread::sleep(Duration::from_millis(20));
                discard(&p, 1);
                p.events_read();
            });
            let (resolved, res) = p.install(0, 2, REMOTE, Some(&stop), |_, n| {
                calls += 1;
                match p.read_gen.load(Ordering::SeqCst) {
                    0 => Err(os(libc::EAGAIN)),
                    _ => Ok(n),
                }
            });
            assert!(res.is_ok());
            assert_eq!(resolved, 2);
        });
        assert!(calls >= 2);
        assert!(p.install_eagain.load(Ordering::SeqCst) >= 1);
        assert_eq!(states(&p), [PRESENT, ZERO]);
    }

    /// A fetch with a head asks for it on its own, pipelined ahead of the
    /// rest, and reports the head as soon as it is in.
    #[test]
    fn fetch_asks_for_the_head_first() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut r = io::BufReader::new(s.try_clone().unwrap());
            let mut hello = String::new();
            io::BufRead::read_line(&mut r, &mut hello).unwrap();
            let mut reqs = [0u8; 24];
            r.read_exact(&mut reqs).unwrap();
            let req = |i: usize| {
                let q = &reqs[i * 12..(i + 1) * 12];
                (u64::from_le_bytes(q[..8].try_into().unwrap()), u32::from_le_bytes(q[8..].try_into().unwrap()))
            };
            assert_eq!((req(0), req(1)), ((8192, 4096), (12288, 3 * 4096)));
            let mut s = s;
            s.write_all(b"{\"ok\": true}\n").unwrap();
            s.write_all(&[&[0u8][..], &[1u8; 4096]].concat()).unwrap();
            thread::sleep(Duration::from_millis(50));
            s.write_all(&[&[0u8][..], &[2u8; 3 * 4096]].concat()).unwrap();
        });
        let source = Source { addr, vm: "v".into(), mig: 1, regions: Vec::new() };
        let mut c = PageClient::connect(&source).unwrap();
        let mut buf = vec![0u8; 4 * PAGE_SIZE];
        let start = Instant::now();
        let mut head_at = None;
        c.fetch(8192, &mut buf, PAGE_SIZE, &mut |data| {
            if data.len() >= PAGE_SIZE && head_at.is_none() {
                head_at = Some(start.elapsed());
            }
            true
        })
        .unwrap();
        assert!(head_at.unwrap() < Duration::from_millis(40), "head reported before the rest arrived");
        assert!(buf[..PAGE_SIZE].iter().all(|&b| b == 1) && buf[PAGE_SIZE..].iter().all(|&b| b == 2));
        server.join().unwrap();
    }

    #[test]
    fn fault_latency_buckets() {
        for ns in [4u64, 5, 7, 8, 15, 16, 17, 100, 999, 1000, 123_456, 10_000_000_000] {
            let b = bucket(ns);
            assert!(bucket_floor(b) <= ns && ns < bucket_floor(b + 1), "{ns}: bucket {b} [{}, {})", bucket_floor(b), bucket_floor(b + 1));
        }
        let s = FaultStats::new();
        for us in 1..=100 {
            s.record(FETCHED, Duration::from_micros(us));
        }
        s.record(WAITED, Duration::from_millis(3));
        let r = s.report();
        assert_eq!(r["remote"]["count"], 100);
        let p50 = r["remote"]["p50_us"].as_f64().unwrap();
        assert!((40.0..=50.0).contains(&p50), "{p50}");
        assert_eq!(r["remote"]["max_us"], 100.0);
        assert_eq!(r["wait"]["count"], 1);
        assert_eq!(r["local"]["count"], 0);
        assert_eq!(r["local"]["p99_us"], 0.0);
    }

    #[test]
    fn remote_among_picks_remote_pages() {
        let runs: Runs = vec![(10, 5, REMOTE), (15, 2, ZERO), (100, 1, REMOTE), (3, 2, REMOTE)];
        assert_eq!(remote_among(&runs, [0, 3, 4, 5, 9, 10, 14, 15, 16, 99, 100, 101]), vec![3, 4, 10, 14, 100]);
        assert!(remote_among(&Vec::new(), [1, 2]).is_empty());
    }

    #[test]
    fn next_not_base_finds_every_state() {
        let mut st = vec![BASE; 300];
        for &i in &[0usize, 7, 8, 9, 63, 64, 65, 130, 299] {
            st[i] = PRESENT;
        }
        let p = pages(&st);
        for from in 0..300 {
            for end in from..=300 {
                let want = (from..end).find(|&i| st[i] != BASE).unwrap_or(end);
                assert_eq!(p.next_not(BASE, from, end), want, "from {from} end {end}");
            }
        }
        assert_eq!(p.next_not(BASE, 10, 1000), 63);
        for from in 0..300 {
            for end in from..=300 {
                let want = (from..end).find(|&i| st[i] != PRESENT).unwrap_or(end);
                assert_eq!(p.next_not(PRESENT, from, end), want, "PRESENT from {from} end {end}");
                assert_eq!(p.count(PRESENT, from, end), st[from..end].iter().filter(|&&s| s == PRESENT).count());
                assert_eq!(p.next_in(PRESENT, from, end), (from..end).find(|&i| st[i] == PRESENT).unwrap_or(end));
            }
        }

        // Untouched chunks are skipped without reading them.
        let p = Pages::new(3 * CHUNK + 5);
        assert_eq!(p.next_not(BASE, 0, p.len()), p.len());
        p.set(2 * CHUNK + 7, ZERO);
        assert_eq!(p.next_not(BASE, 0, p.len()), 2 * CHUNK + 7);
        assert_eq!(p.claim(CHUNK + 3, 2, BASE, |_| true), 2);
        assert_eq!(p.next_not(BASE, 0, p.len()), CHUNK + 3);
        assert_eq!(p.next_not(BASE, CHUNK + 5, p.len()), 2 * CHUNK + 7);
    }

    #[test]
    fn claimed_pages_have_one_installer() {
        let p = pages(&[REMOTE, REMOTE, BASE, REMOTE]);
        assert_eq!(p.claim(0, 8, REMOTE, |_| true), 2);
        assert_eq!(p.claim(0, 8, REMOTE, |_| true), 0);
        assert_eq!(p.claim(3, 8, REMOTE, |i| i != 3), 0);
        let mut calls = Vec::new();
        let (resolved, res) = p.install(0, 2, REMOTE, None, |i, n| {
            calls.push((i, n));
            Ok(n)
        });
        assert!(res.is_ok());
        assert_eq!((resolved, calls), (2, vec![(0, 2)]));
        assert_eq!(states(&p), [PRESENT, PRESENT, BASE, REMOTE]);
    }

    #[test]
    fn remove_during_fetch_skips_the_copy() {
        // A REMOVE lands while the pages are on the wire: the installer must
        // not copy stale bytes into the discarded page or mark it PRESENT.
        let p = pages(&[REMOTE; 4]);
        p.claim(0, 4, REMOTE, |_| true);
        assert!(!discard(&p, 1), "the installer accounts for claimed pages");
        let mut calls = Vec::new();
        let (resolved, res) = p.install(0, 4, REMOTE, None, |i, n| {
            calls.push((i, n));
            Ok(n)
        });
        assert!(res.is_ok());
        assert_eq!(calls, [(0, 1), (2, 2)]);
        assert_eq!(states(&p), [PRESENT, ZERO, PRESENT, PRESENT]);
        assert_eq!(resolved, 4);
    }

    #[test]
    fn remove_during_copy_waits_for_settle() {
        // A REMOVE read while a copy is in progress is applied only after the
        // copy has settled (and so before the kernel zaps the range): the page
        // ends ZERO, never PRESENT without its data.
        let p = pages(&[REMOTE; 2]);
        p.claim(0, 2, REMOTE, |_| true);
        let removed = AtomicBool::new(false);
        thread::scope(|scope| {
            let (resolved, res) = p.install(0, 2, REMOTE, None, |_, n| {
                scope.spawn(|| {
                    discard(&p, 1);
                    removed.store(true, Ordering::SeqCst);
                });
                thread::sleep(Duration::from_millis(50));
                assert!(!removed.load(Ordering::SeqCst), "REMOVE applied mid-copy");
                Ok(n)
            });
            assert!(res.is_ok());
            assert_eq!(resolved, 2);
        });
        assert!(removed.load(Ordering::SeqCst));
        assert_eq!(states(&p), [PRESENT, ZERO]);
    }

    #[test]
    fn failed_fetch_gives_pages_back() {
        let p = pages(&[REMOTE; 3]);
        p.claim(0, 3, REMOTE, |_| true);
        discard(&p, 2);
        assert_eq!(p.release(0, 3, REMOTE), 1);
        assert_eq!(states(&p), [REMOTE, REMOTE, ZERO]);
        assert_eq!(p.claim(0, 3, REMOTE, |_| true), 2);
    }

    #[test]
    fn partial_copies_and_errors() {
        // UFFDIO_COPY stops after two pages, the next one already exists, then EIO.
        let p = pages(&[REMOTE; 6]);
        p.claim(0, 6, REMOTE, |_| true);
        let mut script = vec![Ok(2), Err(os(libc::EEXIST)), Err(os(libc::EIO))].into_iter();
        let (resolved, res) = p.install(0, 6, REMOTE, None, |_, _| script.next().unwrap());
        assert_eq!(res.unwrap_err().raw_os_error(), Some(libc::EIO));
        assert_eq!(states(&p), [PRESENT, PRESENT, PRESENT, REMOTE, REMOTE, REMOTE]);
        assert_eq!(resolved, 3);
    }

    #[test]
    fn eagain_retries_only_with_a_stop_flag() {
        let p = pages(&[BASE; 2]);
        p.claim(0, 2, BASE, |_| true);
        let (_, res) = p.install(0, 2, BASE, None, |_, _| Err(os(libc::EAGAIN)));
        assert_eq!(res.unwrap_err().raw_os_error(), Some(libc::EAGAIN));
        assert_eq!(states(&p), [BASE, BASE]);

        let stop = AtomicBool::new(false);
        p.claim(0, 2, BASE, |_| true);
        let mut script = vec![Err(os(libc::EAGAIN)), Ok(2)].into_iter();
        let (resolved, res) = p.install(0, 2, BASE, Some(&stop), |_, _| script.next().unwrap());
        assert!(res.is_ok());
        assert_eq!((states(&p), resolved), (vec![PRESENT, PRESENT], 0));
    }

    #[test]
    fn prefetch_racing_remove() {
        let p = pages(&[BASE; 3]);
        p.claim(0, 3, BASE, |_| true);
        assert_eq!(p.claim(0, 3, BASE, |_| true), 0, "a fault waits for the prefetch");
        discard(&p, 0);
        let (_, res) = p.install(0, 3, BASE, None, |i, n| {
            assert_eq!((i, n), (1, 2));
            Ok(n)
        });
        assert!(res.is_ok());
        assert_eq!(states(&p), [ZERO, PRESENT, PRESENT]);
        // A discarded page whose neighbours fail to copy ends ZERO, not BASE.
        let p = pages(&[BASE; 2]);
        p.claim(0, 2, BASE, |_| true);
        discard(&p, 0);
        let (_, res) = p.install(0, 2, BASE, None, |_, _| Err(os(libc::ENOMEM)));
        assert!(res.is_err());
        assert_eq!(states(&p), [ZERO, BASE]);
    }

    #[test]
    fn incoming_runs_are_validated() {
        assert_eq!(remote_pages(&vec![(0, 2, REMOTE), (2, 3, ZERO), (8, 2, REMOTE)], 10).unwrap(), 4);
        for bad in [
            vec![(0, 2, REMOTE), (1, 2, REMOTE)],
            vec![(4, 2, REMOTE), (0, 2, REMOTE)],
            vec![(9, 2, REMOTE)],
            vec![(u64::MAX, 2, REMOTE)],
            vec![(0, 0, REMOTE)],
            vec![(0, 1, INFLIGHT)],
            vec![(0, 1, DISCARDED)],
            vec![(0, 1, PRESENT)],
        ] {
            assert!(remote_pages(&bad, 10).is_err(), "{bad:?}");
        }
    }

    /// Random interleavings of claims, REMOVEs (including while a claim's
    /// fetch is in flight), partial copies, errors and failed fetches: no page
    /// stays claimed and every REMOTE page is counted as resolved exactly once.
    #[test]
    fn remote_accounting_adds_up() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rand = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        for _ in 0..200 {
            let p = pages(&[REMOTE; 64]);
            let mut resolved = 0;
            for _ in 0..200 {
                let first = rand(64);
                if rand(4) == 0 {
                    resolved += discard(&p, first) as usize;
                    continue;
                }
                let n = p.claim(first, 1 + rand(16), REMOTE, |_| true);
                if n == 0 {
                    continue;
                }
                if rand(4) == 0 {
                    resolved += p.release(first, n, REMOTE);
                    continue;
                }
                for _ in 0..rand(3) {
                    assert!(!discard(&p, first + rand(n)));
                }
                let mut script = Vec::new();
                for _ in 0..8 {
                    script.push((rand(5), rand(64)));
                }
                let mut script = script.into_iter();
                let (r, _) = p.install(first, n, REMOTE, None, |_, m| {
                    let (outcome, k) = script.next().unwrap_or((4, 0));
                    match outcome {
                        0 => Err(os(libc::EEXIST)),
                        1 => Err(os(libc::EAGAIN)),
                        2 => Err(os(libc::EIO)),
                        _ => Ok(1 + k % m),
                    }
                });
                resolved += r;
            }
            let s = states(&p);
            assert!(s.iter().all(|&s| s != INFLIGHT && s != DISCARDED), "{s:?}");
            assert_eq!(resolved, 64 - s.iter().filter(|&&s| s == REMOTE).count());
        }
    }
}
