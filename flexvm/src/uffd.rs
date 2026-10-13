//! Userfaultfd pager for Firecracker guest memory.
//!
//! Every page of guest memory is in one of a few states. Faults are resolved
//! according to that state, so a VM can be backed by any mix of a shared
//! template image, zero pages and pages still living on a migration source.
//!
//!   BASE      -> copied from the template memory file (holes map the zero page)
//!   ZERO      -> discarded by the guest (balloon / virtio-mem); maps the zero page
//!   REMOTE    -> fetched from the VM's origin: the migration source's page
//!                server, or the page file of a checkpoint being restored
//!   INFLIGHT  -> claimed by one installer; its UFFDIO_COPY wakes any waiters
//!   DISCARDED -> INFLIGHT, but a REMOVE hit it; its installer must not publish it
//!   PRESENT   -> populated in this VM, the only copy is inside Firecracker
//!
//! A page leaves BASE, ZERO or REMOTE only by being claimed. Its claimant
//! installs it and then settles it, so an install that raced a REMOVE never
//! overwrites the newer state (see `Pages`).
//!
//! The pager also reads PRESENT pages out of the (paused) Firecracker process
//! with process_vm_readv so this host can act as a migration source.
//!
//! Write tracking: once a VM has been checkpointed while running, its memory
//! is also registered for write-protect faults on Firecracker's userfaultfd
//! (no feature has to be negotiated for that at UFFDIO_API time), and every
//! populated page is protected at each checkpoint's pause. A write fault
//! unprotects a block of pages and marks them dirty; so do installs and
//! discards. The next checkpoint can then save only the dirty pages, and a
//! checkpoint of a running VM saves pages before the guest overwrites them
//! (see `cow`).

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

/// Pages copied per fault from the template, to cut down on round trips.
const FAULT_AROUND: usize = 16;
/// Pages claimed per prefetch copy; faults on them wait for it.
const PREFETCH_RUN: usize = 256;
/// Pages fetched per remote fault.
const REMOTE_FAULT_RUN: usize = 64;
/// Pages per background pull request.
const PULL_RUN: usize = 256;
const PULL_THREADS: usize = 4;
/// Why a pager stopped whose Firecracker unmapped guest memory or exited.
const GONE: &str = "firecracker unmapped guest memory";

/// How long Firecracker has, once it unmapped guest memory, to exit or
/// answer the request that failed, before the pager kills it.
const UNMAPPED_GRACE: Duration = Duration::from_secs(2);

/// How long a fault may keep failing (other than EAGAIN) before the pager gives up.
const FAULT_TIMEOUT: Duration = Duration::from_secs(1);
/// How long the migration source may stay unreachable before the pager gives up.
const SOURCE_TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_MIN: Duration = Duration::from_millis(10);
const BACKOFF_MAX: Duration = Duration::from_secs(1);

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
/// Merge protect ranges across gaps up to this many pages; past this many
/// ranges in a region, protect the whole region at once.
const PROTECT_GAP: usize = 64;
const PROTECT_RUNS: usize = 256;
/// Threads copying unsaved pages into memory while a discard is held back.
const SAVE_REST_THREADS: usize = 8;
/// Pages write-protected per call while the VM runs (2 MiB).
const ARM_CHUNK: usize = 512;

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
struct UffdioCopy {
    dst: u64,
    src: u64,
    len: u64,
    mode: u64,
    copy: i64,
}

#[repr(C)]
struct UffdioZeropage {
    range: UffdioRange,
    mode: u64,
    zeropage: i64,
}

#[repr(C)]
struct UffdioRegister {
    range: UffdioRange,
    mode: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdioWriteprotect {
    range: UffdioRange,
    mode: u64,
}

/// One guest memory region, as Firecracker describes it in the UFFD handshake.
#[derive(Debug, Clone, Deserialize)]
pub struct Mapping {
    pub base_host_virt_addr: u64,
    pub size: usize,
    pub offset: u64,
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
}

/// Where a VM's REMOTE pages come from.
#[derive(Clone)]
pub enum Origin {
    /// The paused source of an incoming migration.
    Peer(Source),
    /// The page file of a checkpoint on this host. Reads are verified
    /// against the checkpoint's block checksums; a failed read is fatal.
    File(Arc<PageFile>),
}

fn eagain() -> io::Error {
    io::Error::from_raw_os_error(libc::EAGAIN)
}

/// The page state machine. Installers claim pages (-> INFLIGHT), populate
/// them and settle them; a REMOVE on a claimed page turns it DISCARDED, and
/// its installer then skips it. Settling returns whether a REMOTE page got
/// resolved, for the pager's count of pages still to pull.
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
pub struct Pages {
    states: Vec<AtomicU8>,
    /// One bit per `CHUNK` pages: set once any of them may have left BASE.
    /// Lets a scan skip untouched stretches without reading (and faulting
    /// in) their part of `states`.
    touched: Vec<AtomicU64>,
    events: RwLock<()>,
    /// One bit per page: its contents may have changed since the last
    /// checkpoint's pause (written after a write-protect fault, installed,
    /// or discarded). See `Pager::freeze`.
    dirty: Vec<AtomicU64>,
}

/// Pages per `touched` bit: one page of `states`.
const CHUNK: usize = 4096;

impl Pages {
    pub fn new(n: usize) -> Pages {
        // BASE is 0, so a zeroed allocation (lazily backed by the kernel) is the initial state.
        let states = unsafe { std::mem::transmute::<Vec<u8>, Vec<AtomicU8>>(vec![0u8; n]) };
        let dirty = unsafe { std::mem::transmute::<Vec<u64>, Vec<AtomicU64>>(vec![0u64; n.div_ceil(64)]) };
        let touched = (0..n.div_ceil(CHUNK * 64)).map(|_| AtomicU64::new(0)).collect();
        Pages { states, touched, events: RwLock::new(()), dirty }
    }

    pub fn mark_dirty(&self, page: usize) {
        if let Some(w) = self.dirty.get(page / 64) {
            w.fetch_or(1 << (page % 64), Ordering::SeqCst);
        }
    }

    /// The dirty bits, cleared.
    fn take_dirty(&self) -> Vec<u64> {
        self.dirty.iter().map(|w| w.swap(0, Ordering::SeqCst)).collect()
    }

    /// The dirty bits, left as they are.
    fn read_dirty(&self) -> Vec<u64> {
        self.dirty.iter().map(|w| w.load(Ordering::SeqCst)).collect()
    }

    /// Marks dirty again what `take_dirty` returned.
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

    /// The first page in `[from, end)` not in state BASE, or `end`. Skips
    /// chunks no state in which ever left BASE without reading them: a VM's
    /// map is mostly BASE (the unplugged virtio-mem region alone is millions
    /// of pages), and a migration scans it with the VM paused.
    pub fn next_not_base(&self, from: usize, end: usize) -> usize {
        self.next_not(BASE, from, end)
    }

    /// The first page in `[from, end)` not in `state`, or `end`. States are
    /// only ever read as the byte atomics they are written as.
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

    /// Held while reading and applying uffd events; required by `discard`.
    pub fn removing(&self) -> RwLockWriteGuard<'_, ()> {
        self.events.write().unwrap()
    }

    /// Claims up to `max` consecutive pages from `first` that are in state
    /// `from` and pass `ok`. Returns how many it claimed.
    pub fn claim(&self, first: usize, max: usize, from: u8, ok: impl Fn(usize) -> bool) -> usize {
        let mut n = 0;
        while n < max
            && first + n < self.states.len()
            && ok(first + n)
            && (from != BASE || {
                self.touch(first + n);
                true
            })
            && self.states[first + n].compare_exchange(from, INFLIGHT, Ordering::SeqCst, Ordering::SeqCst).is_ok()
        {
            n += 1;
        }
        n
    }

    /// Applies a REMOVE of `page`. Returns whether it resolved a REMOTE page.
    pub fn discard(&self, _removing: &RwLockWriteGuard<'_, ()>, page: usize) -> bool {
        self.touch(page);
        let old = self.states[page]
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |s| {
                Some(if s == INFLIGHT || s == DISCARDED { DISCARDED } else { ZERO })
            })
            .unwrap();
        self.mark_dirty(page);
        old == REMOTE
    }

    /// Settles claimed `page`, claimed from state `from`.
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
        from == REMOTE && (populated || old == DISCARDED)
    }

    /// Gives back claimed pages without installing them.
    pub fn release(&self, first: usize, n: usize, from: u8) -> usize {
        (first..first + n).filter(|&p| self.settle(p, false, from)).count()
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
            let mut m = 1;
            while i + m < end && self.get(i + m) == INFLIGHT {
                m += 1;
            }
            match populate(i, m) {
                Ok(done) => {
                    let done = done.clamp(1, m);
                    resolved += (i..i + done).filter(|&p| self.settle(p, true, from)).count();
                    i += done;
                }
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    resolved += self.settle(i, true, from) as usize;
                    i += 1;
                }
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) && stop.is_some_and(|s| !s.load(Ordering::SeqCst)) => {
                    // A REMOVE is queued: let the event thread read it.
                    drop(installing);
                    thread::sleep(Duration::from_micros(200))
                }
                Err(e) => return (resolved + self.release(i, end - i, from), Err(e)),
            }
        }
        (resolved, Ok(()))
    }
}

/// How long a Firecracker has to connect to its pager once started.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Pager {
    base: Arc<Template>,
    mappings: OnceLock<Vec<Mapping>>,
    pages: OnceLock<Pages>,
    uffd: OnceLock<OwnedFd>,
    ready: (Mutex<bool>, Condvar),
    /// Firecracker pid, for reading pages out when acting as a migration source.
    pid: AtomicU32,
    /// Firecracker as a pidfd, so killing it never hits a reused pid.
    pidfd: OnceLock<OwnedFd>,
    remote: Mutex<Option<Link>>,
    /// The checkpoint page file REMOTE pages come from, when restoring one.
    file: OnceLock<Arc<PageFile>>,
    discards: AtomicU64,
    remote_left: AtomicUsize,
    pull_started: OnceLock<Instant>,
    pull_finished: OnceLock<Instant>,
    /// Signalled when the pull finishes or the pager stops.
    done: (Mutex<()>, Condvar),
    /// Set by the checkpoint barrier: no new prefetch.
    quiesce: AtomicBool,
    failed: OnceLock<String>,
    stop: AtomicBool,
    /// The fault-serving thread, joined by `join`.
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
    /// Ranges write-protected, and how long that took.
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
            ready: (Mutex::new(false), Condvar::new()),
            pid: AtomicU32::new(0),
            pidfd: OnceLock::new(),
            remote: Mutex::new(None),
            file: OnceLock::new(),
            discards: AtomicU64::new(0),
            remote_left: AtomicUsize::new(0),
            pull_started: OnceLock::new(),
            pull_finished: OnceLock::new(),
            done: (Mutex::new(()), Condvar::new()),
            quiesce: AtomicBool::new(false),
            failed: OnceLock::new(),
            stop: AtomicBool::new(false),
            thread: Mutex::new(None),
            tracking: AtomicBool::new(false),
            registered_wp: AtomicBool::new(false),
            cow: Mutex::new(None),
            wp: Mutex::new(()),
            pagemap: OnceLock::new(),
            fail_protect: AtomicBool::new(false),
            initial: Mutex::new(initial),
            seeded: Condvar::new(),
            awaiting_seed: AtomicBool::new(false),
            learning: AtomicBool::new(false),
            prefetch: Mutex::new((false, false)),
        });
        let p = pager.clone();
        let thread = thread::Builder::new().name("uffd".into()).spawn(move || {
            let prefetch = match p.handshake(&listener) {
                Ok(prefetch) => prefetch,
                Err(e) => return p.fail(format!("uffd handshake failed: {e}")),
            };
            // Prefetch alongside fault handling: Firecracker itself touches guest
            // memory while restoring devices and must not wait behind it.
            if prefetch {
                let mut state = p.prefetch.lock().unwrap();
                match p.learning.load(Ordering::SeqCst) && !state.0 {
                    true => state.1 = true,
                    false => {
                        let p = p.clone();
                        thread::spawn(move || p.prefetch());
                    }
                }
            }
            p.serve();
        })?;
        *pager.thread.lock().unwrap() = Some(thread);
        Ok(pager)
    }

    /// Waits for the pager thread to finish, after `stop` (or Firecracker's exit).
    pub fn join(&self) {
        let thread = self.thread.lock().unwrap().take();
        if let Some(t) = thread.filter(|t| t.thread().id() != thread::current().id()) {
            let _ = t.join();
        }
    }

    /// Sets the initial page states and where their REMOTE pages come from,
    /// for a pager started without them. Only before Firecracker loads a
    /// snapshot.
    pub fn seed(&self, runs: Runs, origin: Origin) -> Result<()> {
        if self.pages.get().is_some() || self.initial.lock().unwrap().is_some() {
            bail!("pager already seeded");
        }
        *self.initial.lock().unwrap() = Some((runs, origin));
        self.seeded.notify_all();
        Ok(())
    }

    /// Firecracker will connect before `seed` (it prepares the load ahead of
    /// the vmstate): the handshake then waits for the seed (or `stop`)
    /// before it serves a fault. Firecracker touches no
    /// guest memory until the load itself.
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
        let mut state = self.prefetch.lock().unwrap();
        state.0 = true;
        if std::mem::take(&mut state.1) {
            let p = self.clone();
            thread::spawn(move || p.prefetch());
        }
    }

    /// Takes over Firecracker's userfaultfd. Returns whether to prefetch the working set.
    fn handshake(&self, listener: &UnixListener) -> Result<bool> {
        let start = Instant::now();
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if self.stop.load(Ordering::SeqCst) {
                        bail!("stopped before Firecracker connected");
                    }
                    if start.elapsed() > HANDSHAKE_TIMEOUT {
                        bail!("Firecracker did not connect within {HANDSHAKE_TIMEOUT:?}");
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(e.into()),
            }
        };
        // The same deadline and stop for the handshake message itself.
        loop {
            let mut pfd = libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            if unsafe { libc::poll(&mut pfd, 1, 10) } > 0 {
                break;
            }
            if self.stop.load(Ordering::SeqCst) {
                bail!("stopped before Firecracker sent its handshake");
            }
            if start.elapsed() > HANDSHAKE_TIMEOUT {
                bail!("Firecracker sent no handshake within {HANDSHAKE_TIMEOUT:?}");
            }
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
            let _ = self.pull_started.set(Instant::now());
            let remote = remote_pages(&runs, total)?;
            for (first, count, state) in runs {
                for p in first as usize..(first + count) as usize {
                    pages.set(p, state);
                }
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
                    let _ = self.file.set(file);
                }
            }
        }
        // A checkpoint restore prefetches the template's working set too: the
        // pages the checkpoint left BASE are still the template's.
        let fresh = self.remote_left() == 0 || self.file.get().is_some();
        let _ = self.mappings.set(mappings);
        let _ = self.pages.set(pages);
        let _ = self.uffd.set(fd);
        if self.remote_left() == 0 && self.pull_started.get().is_some() {
            let _ = self.pull_finished.set(Instant::now());
        }
        *self.ready.0.lock().unwrap() = true;
        self.ready.1.notify_all();
        Ok(fresh && !self.base.working_set.is_empty())
    }

    /// Copies the template's recorded working set in up front, while the
    /// vCPUs are still being restored, instead of one fault at a time.
    fn prefetch(&self) {
        let pages = self.pages();
        for &(first, count) in &self.base.working_set {
            let (mut i, end) = (first as usize, ((first + count) as usize).min(pages.len()));
            while i < end && !self.quiesce.load(Ordering::SeqCst) {
                // Holes were zero at snapshot time (mostly free memory the guest
                // allocates again); map them too, or each one costs a fault.
                let data = self.base.has_data(i);
                let region_end = self.locate((i * PAGE_SIZE) as u64).map_or(i + 1, |m| (m.offset as usize + m.size) / PAGE_SIZE);
                let max = PREFETCH_RUN.min(end.min(region_end) - i);
                let n = pages.claim(i, max, BASE, |p| self.base.has_data(p) == data);
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
        let mut runs: Vec<(u64, u64)> = Vec::new();
        let pages = self.pages();
        for i in 0..pages.len() {
            if pages.get(i) != PRESENT {
                continue;
            }
            match runs.last_mut() {
                Some((f, n)) if *f + *n == i as u64 => *n += 1,
                _ => runs.push((i as u64, 1)),
            }
        }
        runs
    }

    /// Installs REMOTE pages whose contents came along with the vmstate (one
    /// `PAGE_SIZE` slice of `data` per page of `list`), once Firecracker has
    /// connected (and the page states are set): the load would otherwise
    /// fault on them one round trip at a time. Runs alongside the load; a
    /// page a fault or puller claimed first is waited for (by `deadline`),
    /// so all of them are in when it returns. Returns how many it installed.
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
            // someone else (a fault or a puller, whose fetch may fail and
            // give it back): when this returns, every listed page is in.
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

    /// Blocks until Firecracker has handed over its userfaultfd.
    pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let guard = self.ready.0.lock().unwrap();
        let (guard, _) = self.ready.1.wait_timeout_while(guard, timeout, |r| !*r).unwrap();
        if !*guard {
            bail!("firecracker never connected to the uffd socket");
        }
        Ok(())
    }

    /// How long an incoming migration took to pull every remote page, once done.
    pub fn pull_time(&self) -> Option<Duration> {
        Some(self.pull_finished.get()?.duration_since(*self.pull_started.get()?))
    }

    /// Counts `n` remote pages as resolved.
    fn pulled(&self, n: usize) {
        if n > 0 && self.remote_left.fetch_sub(n, Ordering::SeqCst) == n {
            let _ = self.pull_finished.set(Instant::now());
            self.notify();
        }
    }

    /// Blocks until every remote page has arrived (true), or the pager has
    /// stopped or failed first (false).
    pub fn wait_pulled(&self) -> bool {
        let mut guard = self.done.0.lock().unwrap();
        loop {
            if self.remote_left() == 0 {
                return true;
            }
            if self.stop.load(Ordering::SeqCst) {
                return false;
            }
            guard = self.done.1.wait(guard).unwrap();
        }
    }

    /// `wait_pulled`, giving up (false) after `timeout`.
    pub fn wait_pulled_for(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut guard = self.done.0.lock().unwrap();
        loop {
            if self.remote_left() == 0 {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if self.stop.load(Ordering::SeqCst) || left.is_zero() {
                return false;
            }
            guard = self.done.1.wait_timeout(guard, left).unwrap().0;
        }
    }

    /// The guest's memory size in pages, once Firecracker has connected.
    pub fn total_pages(&self) -> usize {
        self.pages().len()
    }

    /// The first page past the guest memory region holding `page`.
    pub fn region_end(&self, page: usize) -> Option<usize> {
        self.locate((page * PAGE_SIZE) as u64).map(|m| (m.offset as usize + m.size) / PAGE_SIZE)
    }

    fn notify(&self) {
        let _guard = self.done.0.lock().unwrap();
        self.done.1.notify_all();
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

    /// Whether nothing at all is mapped at `addr..addr + len` in Firecracker
    /// any more (or it is gone). A uffd copy also fails with ENOENT across a
    /// VMA boundary, e.g. into an unplugged virtio-mem slot, where memory is
    /// still mapped: that is not this.
    fn unmapped(&self, addr: u64, len: usize) -> bool {
        let pid = self.pid.load(Ordering::SeqCst);
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else { return true };
        let end = addr + len as u64;
        !maps.lines().any(|l| {
            let range = l.split_whitespace().next().unwrap_or("");
            let (a, b) = range.split_once('-').unwrap_or(("", ""));
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

    /// Whether pages are still to come from a migration source.
    pub fn pulling_from_peer(&self) -> bool {
        self.remote_left() > 0 && self.file.get().is_none()
    }

    pub fn remote_left(&self) -> usize {
        self.remote_left.load(Ordering::SeqCst)
    }

    fn mappings(&self) -> &[Mapping] {
        self.mappings.get().map(|m| m.as_slice()).unwrap_or(&[])
    }

    fn pages(&self) -> &Pages {
        static EMPTY: Pages = Pages { states: Vec::new(), touched: Vec::new(), events: RwLock::new(()), dirty: Vec::new() };
        self.pages.get().unwrap_or(&EMPTY)
    }

    fn fd(&self) -> RawFd {
        self.uffd.get().unwrap().as_raw_fd()
    }

    /// Counts pages per state.
    pub fn census(&self) -> [usize; 6] {
        let mut c = [0usize; 6];
        let pages = self.pages();
        for i in 0..pages.len() {
            c[pages.get(i) as usize] += 1;
        }
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
            let first = m.offset as usize / PAGE_SIZE;
            let end = first + m.size / PAGE_SIZE;
            let mut i = pages.next_not_base(first, end);
            while i < end {
                let p = &pages.states[i];
                let mut s = p.load(Ordering::SeqCst);
                while (s == INFLIGHT || s == DISCARDED) && start.elapsed() < Duration::from_secs(1) {
                    thread::sleep(Duration::from_micros(20));
                    s = p.load(Ordering::SeqCst);
                }
                let (raw, s) = match s {
                    PRESENT => (PRESENT, REMOTE),
                    ZERO => (ZERO, ZERO),
                    BASE => {
                        i = pages.next_not_base(i + 1, end);
                        continue;
                    }
                    s => bail!("page {i} is still in state {s}; the VM is mid-migration"),
                };
                // The rest of a stretch in the same state, eight at a time.
                let n = (pages.next_not(raw, i + 1, end) - i) as u64;
                match runs.last_mut() {
                    Some((f, c, st)) if *st == s && *f + *c == i as u64 => *c += n,
                    _ => runs.push((i as u64, n, s)),
                }
                i = pages.next_not_base(i + n as usize, end);
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

    /// Reads guest memory at `offset` out of the Firecracker process.
    pub fn read_guest(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let Some(m) = self.locate(offset) else { bail!("offset {offset:#x} outside guest memory") };
        if offset + buf.len() as u64 > m.offset + m.size as u64 {
            bail!("read crosses a region boundary");
        }
        let local = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let remote = libc::iovec {
            iov_base: (m.base_host_virt_addr + (offset - m.offset)) as *mut _,
            iov_len: buf.len(),
        };
        let pid = self.pid.load(Ordering::SeqCst) as libc::pid_t;
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n != buf.len() as isize {
            bail!("process_vm_readv: {}", io::Error::last_os_error());
        }
        Ok(())
    }

    fn serve(self: Arc<Self>) {
        if self.remote_left() > 0 {
            self.clone().spawn_pullers();
        }
        let fd = self.fd();
        // Faults to retry (address, flags), with when they first failed other than with EAGAIN.
        let mut pending: VecDeque<(u64, u64, Option<Instant>)> = VecDeque::new();
        let mut buf = [0u8; 32 * 64];
        while !self.stop.load(Ordering::SeqCst) {
            let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            let timeout = if pending.is_empty() { 100 } else { 1 };
            if unsafe { libc::poll(&mut pfd, 1, timeout) } < 0 {
                continue;
            }
            if pfd.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                break;
            }
            if pfd.revents & libc::POLLIN != 0 {
                // A REMOVE the kernel acts on as soon as it is read must not
                // hit pages a checkpoint copy has yet to save: let it finish.
                let cow = self.cow.lock().unwrap().clone();
                if let Some(cow) = cow.filter(|c| c.active()) {
                    if self.remove_queued(&cow) {
                        self.save_rest(&cow);
                        if !cow.drain() {
                            cow.invalidate("a discard was held back while the copy made no progress");
                        }
                    }
                }
                let removing = self.pages().removing();
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    for msg in buf[..n as usize].chunks_exact(32) {
                        let a = u64::from_ne_bytes(msg[8..16].try_into().unwrap());
                        let b = u64::from_ne_bytes(msg[16..24].try_into().unwrap());
                        match msg[0] {
                            UFFD_EVENT_PAGEFAULT => {
                                if self.learning.load(Ordering::Relaxed) {
                                    if let Some((page, _)) = self.page_of(b) {
                                        self.base.note_load_fault(page as u64);
                                    }
                                }
                                pending.push_back((b, a, None))
                            }
                            UFFD_EVENT_REMOVE => self.discard(&removing, a, b),
                            _ => {}
                        }
                    }
                }
            }
            // Retry faults that hit EAGAIN once the events ahead of them are drained.
            // Other errors (say ENOMEM) are retried for a while: a dropped
            // fault would block its vCPU forever.
            for _ in 0..pending.len() {
                let (addr, flags, since) = pending.pop_front().unwrap();
                match self.fault(addr, flags) {
                    Ok(()) => {}
                    Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => pending.push_back((addr, flags, since)),
                    // Firecracker unmapped guest memory (tearing down a failed load, or exiting).
                    Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) && self.unmapped(addr, PAGE_SIZE) => {
                        return self.gone()
                    }
                    Err(e) if fatal(&e) => return self.fail(e.to_string()),
                    Err(e) => match since {
                        None => {
                            eprintln!("uffd: fault at {addr:#x}: {e}; retrying");
                            pending.push_back((addr, flags, Some(Instant::now())));
                        }
                        Some(t) if t.elapsed() < FAULT_TIMEOUT => pending.push_back((addr, flags, since)),
                        Some(_) => return self.fail(format!("fault at {addr:#x}: {e}")),
                    },
                }
            }
        }
    }

    fn page_of(&self, addr: u64) -> Option<(usize, &Mapping)> {
        let m = self
            .mappings()
            .iter()
            .find(|m| addr >= m.base_host_virt_addr && addr < m.base_host_virt_addr + m.size as u64)?;
        Some((((addr - m.base_host_virt_addr + m.offset) as usize) / PAGE_SIZE, m))
    }

    fn discard(&self, removing: &RwLockWriteGuard<'_, ()>, start: u64, end: u64) {
        self.discards.fetch_add(1, Ordering::SeqCst);
        let cow = self.cow.lock().unwrap().clone().filter(|c| c.active());
        let (mut a, mut resolved) = (start & !(PAGE_SIZE as u64 - 1), 0);
        while a < end {
            if let Some((p, _)) = self.page_of(a) {
                if let Some(cow) = cow.as_ref().filter(|c| matches!(c.state(p), PENDING | READING | RESCUING)) {
                    cow.invalidate(&format!("page {p} was discarded before it was saved"));
                }
                resolved += self.pages().discard(removing, p) as usize;
            }
            a += PAGE_SIZE as u64;
        }
        self.pulled(resolved);
    }

    fn fault(&self, addr: u64, flags: u64) -> io::Result<()> {
        let Some((page, m)) = self.page_of(addr) else {
            return Err(io::Error::other("fault outside guest memory"));
        };
        let _wp = self.wp.lock().unwrap();
        if flags & UFFD_PAGEFAULT_FLAG_WP != 0 {
            return self.wp_fault(page, m);
        }
        // Runs stay within a 2 MiB chunk: Firecracker keeps unplugged
        // virtio-mem slots PROT_NONE, which splits the region into VMAs at
        // slot boundaries, and a uffd copy across a VMA end fails (ENOENT).
        let chunk = (2 << 20) / PAGE_SIZE;
        let region_left = ((m.offset as usize + m.size) / PAGE_SIZE - page).min(chunk - (page - m.offset as usize / PAGE_SIZE) % chunk);
        let pages = self.pages();
        match pages.get(page) {
            // Normally a fault that raced the install; if the page is really
            // missing, a REMOVE zapped it after it settled (see `Pages`).
            PRESENT => {
                // Missing at a checkpoint's pause too, so zero then: if the
                // copy has yet to save it, keep it protected until it has.
                let cow = self.cow.lock().unwrap().clone().filter(|c| c.active());
                let unsaved = cow.is_some_and(|c| matches!(c.state(page), PENDING | READING));
                let res = match unsaved {
                    true => self.copy_zero_protected(page),
                    false => self.populate(page, 1, None),
                };
                match res {
                    Err(e) if e.raw_os_error() == Some(libc::EEXIST) => self.wake(page, 1),
                    r => {
                        if r.is_ok() && !unsaved {
                            pages.mark_dirty(page);
                        }
                        r.map(drop)
                    }
                }
            }
            // Someone else is installing it; retry until it lands (their copy wakes us).
            INFLIGHT | DISCARDED => Err(eagain()),
            REMOTE => {
                let n = pages.claim(page, REMOTE_FAULT_RUN.min(region_left), REMOTE, |_| true);
                if n == 0 {
                    return Err(eagain());
                }
                let mut buf = vec![0u8; n * PAGE_SIZE];
                let fetched = match self.file.get() {
                    Some(file) => file.read(page, &mut buf, false),
                    None => match self.remote.lock().unwrap().as_mut() {
                        Some(link) => link.fetch((page * PAGE_SIZE) as u64, &mut buf, None),
                        None => Err(io::Error::other("no migration source")),
                    },
                };
                if let Err(e) = fetched {
                    let resolved = pages.release(page, n, REMOTE);
                    self.pulled(resolved);
                    // All discarded meanwhile: nothing left to fetch, serve the fault again.
                    return Err(if resolved == n { eagain() } else { e });
                }
                let src = |p: usize, c: usize| &buf[(p - page) * PAGE_SIZE..(p - page + c) * PAGE_SIZE];
                let (resolved, res) = pages.install(page, n, REMOTE, None, |p, c| self.populate(p, c, Some(src(p, c))));
                self.pulled(resolved);
                res
            }
            state => {
                // BASE or ZERO: serve a run of neighbours with the same source.
                let from_template = state == BASE && self.base.has_data(page);
                let same = |p: usize| state == ZERO || self.base.has_data(p) == from_template;
                let n = pages.claim(page, FAULT_AROUND.min(region_left), state, same);
                if n == 0 {
                    return Err(eagain());
                }
                let src = |p: usize, c: usize| from_template.then(|| self.base.pages(p, c));
                pages.install(page, n, state, None, |p, c| self.populate(p, c, src(p, c))).1
            }
        }
    }

    /// A write to a write-protected page. During a checkpoint copy, saves the
    /// pages of its block that the copy has not saved yet; then unprotects
    /// the block (except pages still to be saved by a writer) and marks it
    /// dirty. Never reads a page that may be missing, which would fault back
    /// to this thread: only pages the pagemap shows populated are read (a
    /// missing one was missing, so zero, at the pause).
    fn wp_fault(&self, page: usize, m: &Mapping) -> io::Result<()> {
        let (region_first, region_end) = (m.offset as usize / PAGE_SIZE, (m.offset as usize + m.size) / PAGE_SIZE);
        let block = page - page % WP_BLOCK;
        let (first, end) = (block.max(region_first), (block + WP_BLOCK).min(region_end));
        let cow = self.cow.lock().unwrap().clone().filter(|c| c.active());
        if let Some(cow) = &cow {
            cow.stats.faults.fetch_add(1, Ordering::Relaxed);
            if cow.state(page) == READING {
                cow.stats.deferred.fetch_add(1, Ordering::Relaxed);
                return Err(eagain());
            }
            // Over budget, nothing more is copied here: unsaved pages of the
            // block stay protected, and the writers take them first.
            if cow.over_budget() {
                let unsaved: Vec<usize> = (first..end).filter(|&p| cow.state(p) == PENDING).collect();
                unsaved.iter().for_each(|&p| cow.want(p));
                if unsaved.contains(&page) {
                    return Err(eagain());
                }
            }
            let start = Instant::now();
            let claimed: Vec<usize> = match cow.over_budget() {
                true => Vec::new(),
                false => (first..end).filter(|&p| cow.claim(p, PENDING, RESCUING)).collect(),
            };
            if !claimed.is_empty() {
                if let Err(e) = self.rescue(cow, first, end, &claimed) {
                    claimed.iter().for_each(|&p| cow.unclaim(p));
                    return Err(e);
                }
                let ns = start.elapsed().as_nanos() as u64;
                let s = &cow.stats;
                s.rescues.fetch_add(1, Ordering::Relaxed);
                s.rescued_pages.fetch_add(claimed.len() as u64, Ordering::Relaxed);
                s.rescue_ns.fetch_add(ns, Ordering::Relaxed);
                s.rescue_max_ns.fetch_max(ns, Ordering::Relaxed);
            }
        }
        // Unprotect what may change now, in runs around pages still protected for the copy.
        let keep = |p: usize| cow.as_ref().is_some_and(|c| matches!(c.state(p), PENDING | READING | RESCUING));
        let mut p = first;
        while p < end {
            if keep(p) {
                p += 1;
                continue;
            }
            let mut q = p + 1;
            while q < end && !keep(q) {
                q += 1;
            }
            (p..q).for_each(|d| self.pages().mark_dirty(d));
            self.writeprotect(p, q - p, false)?;
            p = q;
        }
        Ok(())
    }

    /// Copies the `claimed` pages (RESCUING, within `first..end` of one
    /// region) out of the guest into the copy-on-write state.
    fn rescue(&self, cow: &Cow, first: usize, end: usize, claimed: &[usize]) -> io::Result<()> {
        let present = self.populated(first, end - first)?;
        let mut buf = vec![0u8; (end - first) * PAGE_SIZE];
        let mut i = 0;
        while i < claimed.len() {
            let mut j = i + 1;
            while j < claimed.len() && claimed[j] == claimed[j - 1] + 1 && present[claimed[j] - first] == present[claimed[i] - first] {
                j += 1;
            }
            let (a, b) = (claimed[i] - first, claimed[j - 1] + 1 - first);
            if present[a] {
                let off = (claimed[i] * PAGE_SIZE) as u64;
                self.read_guest(off, &mut buf[a * PAGE_SIZE..b * PAGE_SIZE]).map_err(|e| io::Error::other(e.to_string()))?;
            }
            i = j;
        }
        for &p in claimed {
            cow.rescue(p, buf[(p - first) * PAGE_SIZE..(p - first + 1) * PAGE_SIZE].into());
        }
        Ok(())
    }

    /// Which of `n` pages from `page` are populated (or swapped out) in Firecracker.
    fn populated(&self, page: usize, n: usize) -> io::Result<Vec<bool>> {
        let f = match self.pagemap.get() {
            Some(f) => f,
            None => {
                let f = std::fs::File::open(format!("/proc/{}/pagemap", self.pid.load(Ordering::SeqCst)))?;
                let _ = self.pagemap.set(f);
                self.pagemap.get().unwrap()
            }
        };
        let (addr, _) = self.host_addr(page).ok_or_else(|| io::Error::other("bad page"))?;
        let mut raw = vec![0u8; n * 8];
        std::os::unix::fs::FileExt::read_exact_at(f, &mut raw, addr / PAGE_SIZE as u64 * 8)?;
        Ok(raw.chunks(8).map(|e| u64::from_le_bytes(e.try_into().unwrap()) & (3 << 62) != 0).collect())
    }

    /// Installs a zero page that stays write-protected.
    fn copy_zero_protected(&self, page: usize) -> io::Result<usize> {
        static ZEROES: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
        let (dst, _) = self.host_addr(page).ok_or_else(|| io::Error::other("bad page"))?;
        let mut c = UffdioCopy { dst, src: ZEROES.as_ptr() as u64, len: PAGE_SIZE as u64, mode: UFFDIO_COPY_MODE_WP, copy: 0 };
        if unsafe { libc::ioctl(self.fd(), UFFDIO_COPY, &mut c) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(1)
    }

    /// Write-protects (or unprotects, waking writers waiting on them) `n` pages from `page`.
    fn writeprotect(&self, page: usize, n: usize, protect: bool) -> io::Result<()> {
        let (start, _) = self.host_addr(page).ok_or_else(|| io::Error::other("bad page"))?;
        let mode = if protect { UFFDIO_WRITEPROTECT_MODE_WP } else { 0 };
        let mut wp = UffdioWriteprotect { range: UffdioRange { start, len: (n * PAGE_SIZE) as u64 }, mode };
        if unsafe { libc::ioctl(self.fd(), UFFDIO_WRITEPROTECT, &mut wp) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `writeprotect`, retrying for a while if a REMOVE is queued.
    fn writeprotect_retry(&self, page: usize, n: usize, protect: bool) -> io::Result<()> {
        let start = Instant::now();
        loop {
            match self.writeprotect(page, n, protect) {
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) && start.elapsed() < Duration::from_secs(2) => {
                    thread::sleep(Duration::from_micros(200))
                }
                r => return r,
            }
        }
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
        let chunks: Vec<(usize, usize)> = self
            .mappings()
            .iter()
            .flat_map(|m| {
                let (from, to) = (m.offset as usize / PAGE_SIZE, (m.offset as usize + m.size) / PAGE_SIZE);
                (from..to).step_by(PREFETCH_RUN).map(move |c| (c, (c + PREFETCH_RUN).min(to)))
            })
            .collect();
        let next = AtomicUsize::new(0);
        thread::scope(|s| {
            for _ in 0..threads {
                // Fewer threads if they cannot be had; the writers do the rest.
                let spawned = thread::Builder::new().spawn_scoped(s, || loop {
                    let Some(&(first, end)) = chunks.get(next.fetch_add(1, Ordering::Relaxed)) else { return };
                    if cow.left() == 0 || !cow.active() {
                        return;
                    }
                    let claimed: Vec<usize> = (first..end).filter(|&p| cow.claim(p, PENDING, RESCUING)).collect();
                    match claimed.is_empty() || self.rescue(cow, first, end, &claimed).is_ok() {
                        true => _ = cow.stats.held_pages.fetch_add(claimed.len() as u64, Ordering::Relaxed),
                        false => claimed.iter().for_each(|&p| cow.unclaim(p)),
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
        if self.tracking.load(Ordering::SeqCst) {
            return Ok(Duration::ZERO);
        }
        if !self.registered_wp.load(Ordering::SeqCst) {
            for m in self.mappings() {
                let range = UffdioRange { start: m.base_host_virt_addr, len: m.size as u64 };
                let mut r = UffdioRegister { range, mode: UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP, ioctls: 0 };
                if unsafe { libc::ioctl(self.fd(), UFFDIO_REGISTER, &mut r) } < 0 {
                    bail!("registering guest memory for write-protect faults: {}", io::Error::last_os_error());
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
            self.pages().take_dirty();
            self.tracking.store(true, Ordering::SeqCst);
        }
        // In chunks: while the kernel changes a range, KVM retries guest
        // faults anywhere in it, so one call over a whole region would stall
        // the vCPUs for as long as it takes.
        for m in self.mappings() {
            let (mut p, end) = (m.offset as usize / PAGE_SIZE, (m.offset as usize + m.size) / PAGE_SIZE);
            while p < end {
                let n = ARM_CHUNK.min(end - p);
                if let Err(e) = self.writeprotect_retry(p, n, true) {
                    self.tracking.store(false, Ordering::SeqCst);
                    bail!("write-protecting guest memory: {e}");
                }
                p += n;
            }
        }
        Ok(start.elapsed())
    }

    /// Whether write tracking is on (see `arm_tracking`).
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
        let dirty = match cow {
            true => pages.take_dirty(),
            false => pages.read_dirty(),
        };
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
        if cow {
            // Everything populated was protected at the last pause (or when
            // tracking began); since then only dirty pages were unprotected.
            for m in self.mappings() {
                let (from, to) = (m.offset as usize / PAGE_SIZE, (m.offset as usize + m.size) / PAGE_SIZE);
                let mut ranges: Vec<(usize, usize)> = Vec::new();
                for p in dirty_pages().filter(|&p| p >= from && p < to && pages.get(p) == PRESENT) {
                    match ranges.last_mut() {
                        Some((_, e)) if p <= *e + PROTECT_GAP => *e = p + 1,
                        _ => ranges.push((p, p + 1)),
                    }
                }
                if ranges.len() > PROTECT_RUNS {
                    ranges = vec![(from, to)];
                }
                for (s, e) in ranges {
                    let res = match self.fail_protect.swap(false, Ordering::SeqCst) {
                        true => Err(io::Error::other("injected fault")),
                        false => self.writeprotect_retry(s, e - s, true),
                    };
                    if let Err(e) = res {
                        // Every page must stay protected or dirty: give the
                        // bits back, and protect everything again next time.
                        pages.restore_dirty(&dirty);
                        self.tracking.store(false, Ordering::SeqCst);
                        bail!("write-protecting guest memory: {e}");
                    }
                    protected += 1;
                }
            }
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
            cow.stop();
        }
    }

    /// Whether a checkpoint copy is in progress.
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
        for m in self.mappings() {
            let (mut p, end) = (m.offset as usize / PAGE_SIZE, (m.offset as usize + m.size) / PAGE_SIZE);
            while p < end {
                match pages.get(p) {
                    BASE => p += 1,
                    ZERO => {
                        canon.page(p, &buf[..0]);
                        p += 1;
                    }
                    PRESENT => {
                        let mut q = p + 1;
                        while q < end && q - p < 256 && pages.get(q) == PRESENT {
                            q += 1;
                        }
                        let b = &mut buf[..(q - p) * PAGE_SIZE];
                        self.read_guest((p * PAGE_SIZE) as u64, b)?;
                        for (i, page) in b.chunks(PAGE_SIZE).enumerate() {
                            canon.page(p + i, page);
                        }
                        buf[..(q - p) * PAGE_SIZE].fill(0);
                        p = q;
                    }
                    s => bail!("page {p} is in state {s}"),
                }
            }
        }
        Ok(canon.finish())
    }

    /// Populates up to `n` pages starting at `page`, from `src` or with
    /// zeroes, and wakes their waiters. Returns how many it populated: the
    /// kernel stops early (reporting progress) at a page that already exists.
    fn populate(&self, page: usize, n: usize, src: Option<&[u8]>) -> io::Result<usize> {
        let (dst, _) = self.host_addr(page).ok_or_else(|| io::Error::other("bad page"))?;
        let len = (n * PAGE_SIZE) as u64;
        let (rc, progress) = match src {
            Some(src) => {
                let mut c = UffdioCopy { dst, src: src.as_ptr() as u64, len, mode: 0, copy: 0 };
                (unsafe { libc::ioctl(self.fd(), UFFDIO_COPY, &mut c) }, c.copy)
            }
            None => {
                let mut z = UffdioZeropage { range: UffdioRange { start: dst, len }, mode: 0, zeropage: 0 };
                (unsafe { libc::ioctl(self.fd(), UFFDIO_ZEROPAGE, &mut z) }, z.zeropage)
            }
        };
        if rc == 0 {
            return Ok(n);
        }
        let err = io::Error::last_os_error();
        match progress.max(0) as usize / PAGE_SIZE {
            0 => Err(err),
            done => Ok(done),
        }
    }

    fn wake(&self, page: usize, n: usize) -> io::Result<()> {
        let (start, _) = self.host_addr(page).ok_or_else(|| io::Error::other("bad page"))?;
        let mut r = UffdioRange { start, len: (n * PAGE_SIZE) as u64 };
        if unsafe { libc::ioctl(self.fd(), UFFDIO_WAKE, &mut r) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Pulls every REMOTE page in the background so the source can let go
    /// (or, restoring a checkpoint, so the VM no longer needs its file).
    fn spawn_pullers(self: Arc<Self>) {
        let file = self.file.get().cloned();
        let source = self.remote.lock().unwrap().as_ref().map(|l| l.source.clone());
        for t in 0..PULL_THREADS {
            let p = self.clone();
            let file = file.clone();
            let mut fetch: Box<Fetch> = match (&file, &source) {
                (Some(file), _) => {
                    let file = file.clone();
                    Box::new(move |off, buf, _| file.read(off as usize / PAGE_SIZE, buf, true))
                }
                (None, Some(source)) => {
                    let mut link = Link::new(source.clone());
                    Box::new(move |off, buf, stop| link.fetch(off, buf, Some(stop)))
                }
                (None, None) => return self.fail("remote pages but nowhere to pull them from".into()),
            };
            thread::spawn(move || {
                // A checkpoint's pages come off local disk: the ones in the
                // template's working set first, as the guest needs them soonest.
                let pulled = match file.is_some() {
                    true => p.pull_working_set(t, &mut fetch),
                    false => Ok(()),
                };
                match pulled.and_then(|()| p.pull(t, &mut fetch)) {
                    Err(e) if unmapped(&e) => return p.gone(),
                    Err(e) => return p.fail(format!("background pull {t} failed: {e}")),
                    Ok(()) => {}
                }
                if let Some(file) = file.filter(|_| p.remote_left() == 0) {
                    file.drop_cache();
                }
            });
        }
    }

    /// Pulls the REMOTE pages of every `PULL_THREADS`th range of the
    /// template's working set, starting at range `stripe`.
    fn pull_working_set(&self, stripe: usize, fetch: &mut Fetch) -> io::Result<()> {
        let mut buf = vec![0u8; PULL_RUN * PAGE_SIZE];
        for &(first, count) in self.base.working_set.iter().skip(stripe).step_by(PULL_THREADS) {
            let (first, end) = (first as usize, (first + count) as usize);
            for m in self.mappings() {
                let (from, to) = (m.offset as usize / PAGE_SIZE, (m.offset as usize + m.size) / PAGE_SIZE);
                let (mut i, end) = (first.max(from), end.min(to));
                while i < end && !self.stop.load(Ordering::SeqCst) {
                    i = self.pull_run(i, end, &mut buf, fetch)?;
                }
            }
        }
        Ok(())
    }

    fn pull(&self, stripe: usize, fetch: &mut Fetch) -> io::Result<()> {
        let mut buf = vec![0u8; PULL_RUN * PAGE_SIZE];
        for m in self.mappings() {
            let first = m.offset as usize / PAGE_SIZE;
            let end = first + m.size / PAGE_SIZE;
            let mut chunk = first + stripe * PULL_RUN;
            while chunk < end && !self.stop.load(Ordering::SeqCst) {
                let chunk_end = (chunk + PULL_RUN).min(end);
                let mut i = chunk;
                while i < chunk_end {
                    i = self.pull_run(i, chunk_end, &mut buf, fetch)?;
                }
                chunk += PULL_THREADS * PULL_RUN;
            }
        }
        Ok(())
    }

    /// Pulls the REMOTE pages from `i` on (up to `end`, within one region)
    /// that it can claim in one go. Returns where to go on from.
    fn pull_run(&self, i: usize, end: usize, buf: &mut [u8], fetch: &mut Fetch) -> io::Result<usize> {
        let pages = self.pages();
        let n = pages.claim(i, (end - i).min(buf.len() / PAGE_SIZE), REMOTE, |_| true);
        if n == 0 {
            return Ok(i + 1);
        }
        let b = &mut buf[..n * PAGE_SIZE];
        if let Err(e) = fetch((i * PAGE_SIZE) as u64, b, &self.stop) {
            let resolved = pages.release(i, n, REMOTE);
            self.pulled(resolved);
            if resolved < n {
                return Err(e);
            }
            // All discarded meanwhile.
            return Ok(i + n);
        }
        let src = |p: usize, c: usize| &b[(p - i) * PAGE_SIZE..(p - i + c) * PAGE_SIZE];
        let (resolved, res) = pages.install(i, n, REMOTE, Some(&self.stop), |p, c| self.populate(p, c, Some(src(p, c))));
        self.pulled(resolved);
        res.map_err(|e| match e.raw_os_error() {
            Some(libc::ENOENT | libc::ESRCH) if self.host_addr(i).is_some_and(|(a, _)| self.unmapped(a, n * PAGE_SIZE)) => {
                io::Error::other(Unmapped)
            }
            _ => e,
        })?;
        Ok(i + n)
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

    /// Reads guest memory at `offset` from the source. Waiting to reconnect,
    /// it sleeps until `stop` is set, or without `stop` fails with EAGAIN.
    /// Fails with TimedOut once the outage is too long.
    fn fetch(&mut self, offset: u64, buf: &mut [u8], stop: Option<&AtomicBool>) -> io::Result<()> {
        loop {
            if self.client.is_none() {
                let wait = self.retry_at.saturating_duration_since(Instant::now());
                match stop {
                    Some(s) if s.load(Ordering::SeqCst) => return Err(io::Error::other("pager stopped")),
                    Some(_) => thread::sleep(wait),
                    None if !wait.is_zero() => return Err(eagain()),
                    None => {}
                }
                match PageClient::connect(&self.source) {
                    Ok(c) => self.client = Some(c),
                    Err(e) => {
                        self.lost(e)?;
                        continue;
                    }
                }
            }
            match self.client.as_mut().unwrap().fetch(offset, buf) {
                Ok(()) => {
                    self.down = None;
                    self.backoff = BACKOFF_MIN;
                    return Ok(());
                }
                Err(e) => {
                    self.client = None;
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

/// Fetches `page` from a migration source's page server, retrying as a
/// pager would (for up to `SOURCE_TIMEOUT`, and not past `deadline`):
/// whether it serves pages at all.
pub fn probe(source: &Source, page: u64, deadline: Instant) -> io::Result<()> {
    let give_up = deadline.min(Instant::now() + SOURCE_TIMEOUT);
    let mut backoff = BACKOFF_MIN;
    loop {
        let e = match probe_once(source, page, give_up) {
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

/// One `probe` attempt: connecting, the request and every read by `at`.
fn probe_once(source: &Source, page: u64, at: Instant) -> io::Result<()> {
    let left = at.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline passed"));
    }
    let s = crate::util::connect(&source.addr, left)?;
    s.set_nodelay(true)?;
    let mut s = crate::util::By { s, at };
    let mut req = serde_json::to_vec(&serde_json::json!({"op": "pages", "name": source.vm, "mig": source.mig}))?;
    req.push(b'\n');
    req.extend_from_slice(&(page * PAGE_SIZE as u64).to_le_bytes());
    req.extend_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
    s.write_all(&req)?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status)?;
    if status[0] != 0 {
        return Err(io::Error::other("page server could not read guest memory"));
    }
    s.read_exact(&mut vec![0u8; PAGE_SIZE])
}

/// Client for a migration source's page server.
pub struct PageClient {
    stream: TcpStream,
}

impl PageClient {
    pub fn connect(source: &Source) -> io::Result<Self> {
        let mut stream = crate::util::connect(&source.addr, Duration::from_millis(500))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let hello = serde_json::json!({"op": "pages", "name": source.vm, "mig": source.mig});
        let mut hello = serde_json::to_vec(&hello)?;
        hello.push(b'\n');
        stream.write_all(&hello)?;
        Ok(PageClient { stream })
    }

    pub fn fetch(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut req = [0u8; 12];
        req[..8].copy_from_slice(&offset.to_le_bytes());
        req[8..].copy_from_slice(&(buf.len() as u32).to_le_bytes());
        self.stream.write_all(&req)?;
        let mut status = [0u8; 1];
        self.stream.read_exact(&mut status)?;
        if status[0] != 0 {
            return Err(io::Error::other("page server could not read guest memory"));
        }
        self.stream.read_exact(buf)
    }
}

/// Serves page reads for `pager` on an accepted page-server connection,
/// until the client hangs up or `down()` says to drop it.
pub fn serve_pages(pager: &Pager, mut stream: impl Read + Write, down: impl Fn() -> bool) -> io::Result<()> {
    let mut req = [0u8; 12];
    let mut buf = Vec::new();
    loop {
        if stream.read_exact(&mut req).is_err() || down() {
            return Ok(());
        }
        let offset = u64::from_le_bytes(req[..8].try_into().unwrap());
        let len = u32::from_le_bytes(req[8..].try_into().unwrap()) as usize;
        buf.resize(len, 0);
        match pager.read_guest(offset, &mut buf) {
            Ok(()) => {
                stream.write_all(&[0])?;
                stream.write_all(&buf)?;
            }
            Err(e) => {
                eprintln!("page server: {e}");
                stream.write_all(&[1])?;
            }
        }
    }
}

/// The pages of `wanted` (sorted) that `runs` make REMOTE on a target.
pub fn remote_among(runs: &Runs, wanted: impl IntoIterator<Item = u64>) -> Vec<u64> {
    let mut remote: Vec<(u64, u64)> = runs.iter().filter(|r| r.2 == REMOTE).map(|r| (r.0, r.0 + r.1)).collect();
    remote.sort_unstable();
    wanted
        .into_iter()
        .filter(|&p| {
            let i = remote.partition_point(|r| r.1 <= p);
            remote.get(i).is_some_and(|r| r.0 <= p)
        })
        .collect()
}

/// Reads guest memory at an offset from wherever a puller pulls it.
type Fetch = dyn FnMut(u64, &mut [u8], &AtomicBool) -> io::Result<()> + Send;

/// A background pull could not install pages because their range is no
/// longer mapped in Firecracker at all (UFFDIO_COPY and UFFDIO_ZEROPAGE fail
/// with ENOENT outside a registered VMA, ESRCH once its memory is gone; see
/// `Pager::unmapped`).
#[derive(Debug)]
struct Unmapped;

impl std::fmt::Display for Unmapped {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("guest memory is no longer mapped")
    }
}

impl std::error::Error for Unmapped {}

fn unmapped(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|e| e.is::<Unmapped>())
}

/// Errors after which the pager gives up on the VM: its migration source has
/// been gone too long, or its checkpoint file is unreadable or corrupt.
fn fatal(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::InvalidData)
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

    fn os(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    fn discard(p: &Pages, page: usize) -> bool {
        p.discard(&p.removing(), page)
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
                assert_eq!(p.next_not_base(from, end), want, "from {from} end {end}");
            }
        }
        assert_eq!(p.next_not_base(10, 1000), 63);
        for from in 0..300 {
            for end in from..=300 {
                let want = (from..end).find(|&i| st[i] != PRESENT).unwrap_or(end);
                assert_eq!(p.next_not(PRESENT, from, end), want, "PRESENT from {from} end {end}");
            }
        }

        // Untouched chunks are skipped without reading them.
        let p = Pages::new(3 * CHUNK + 5);
        assert_eq!(p.next_not_base(0, p.len()), p.len());
        p.set(2 * CHUNK + 7, ZERO);
        assert_eq!(p.next_not_base(0, p.len()), 2 * CHUNK + 7);
        assert_eq!(p.claim(CHUNK + 3, 2, BASE, |_| true), 2);
        assert_eq!(p.next_not_base(0, p.len()), CHUNK + 3);
        assert_eq!(p.next_not_base(CHUNK + 5, p.len()), 2 * CHUNK + 7);
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
