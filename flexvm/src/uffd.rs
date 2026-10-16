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
//!
//! Page states, claims and bitmaps live in `pages`; `event` handles faults, `fetch` services their remote runs, and
//! `pull` brings the rest in, and `collapse` turns what was paged in into huge pages afterwards. `server` reads the
//! paused source, and `wp` handles write tracking and COW.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::bail;
use crate::checkpoint::PageFile;
use crate::cow::Cow;
use crate::template::Template;
use crate::util::{Result, PAGE_SIZE};

mod collapse;
mod event;
mod fetch;
mod hot;
mod pages;
mod pull;
mod server;
#[cfg(test)]
mod tests;
mod wp;

pub use event::FaultStats;
pub use fetch::probe;
use fetch::{Lane, Link};
pub use hot::Held;
pub(crate) use pages::zeroed_atomics;
pub use pages::{Pages, BASE, DISCARDED, INFLIGHT, PRESENT, REMOTE, ZERO};
pub use server::{admit, serve_pages};
pub use wp::Frozen;

pub const MAX_PRELOAD: usize = 4096;

/// `Pager::prefetching`.
const DUE: u8 = 1;
const RUNNING: u8 = 2;

/// Pages copied per sequential template fault (see `Pager::template_next`).
pub const FAULT_AROUND: usize = 16;
/// Pages claimed per prefetch copy; faults on them wait for it.
const PREFETCH_RUN: usize = 256;
const REMOTE_FAULT_RUN: usize = 64;
const PULL_RUN: usize = 256;
/// Threads fetching pages for faults, each with its own connection.
const FAULT_FETCHERS: usize = 8;
/// How long Firecracker has, once it unmapped guest memory, to exit or answer the request that failed, before the pager
/// kills it.
const UNMAPPED_GRACE: Duration = Duration::from_secs(2);
/// Largest read a page server serves: the largest any pager asks for.
pub const MAX_FETCH: usize = PULL_RUN * PAGE_SIZE;
const _: () = assert!(REMOTE_FAULT_RUN <= PULL_RUN && PREFETCH_RUN <= PULL_RUN);
/// How long a fault may keep failing (other than EAGAIN) before the pager gives up.
const FAULT_TIMEOUT: Duration = Duration::from_secs(1);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// From linux/userfaultfd.h.
const UFFDIO_COPY: libc::c_ulong = 0xC028_AA03;
const UFFDIO_ZEROPAGE: libc::c_ulong = 0xC020_AA04;
const UFFDIO_COPY_MODE_WP: u64 = 2;
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
        (self.offset as usize / PAGE_SIZE, (self.offset as usize).saturating_add(self.size) / PAGE_SIZE)
    }
}

/// Initial page states for a VM migrating in: runs of `[first_page, count, state]`.
pub type Runs = Vec<(u64, u64, u8)>;

/// The migration source VM process, reached through its peer listener.
#[derive(Debug, Clone)]
pub struct Source {
    pub addr: String,
    pub vm: String,
    pub mig: u64,
    /// Source `(offset, size)` regions; the target must match to cover the saved state.
    pub regions: Vec<(u64, u64)>,
}

/// Where a VM's REMOTE pages come from.
#[derive(Clone)]
pub enum Origin {
    /// The paused source of an incoming migration.
    Peer(Source),
    /// The page file of a checkpoint on this host, its reads verified against the block checksums; a failed read is
    /// fatal.
    File(Arc<PageFile>),
}

fn os(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

/// Why a pager gave up on guest memory.
enum PagerFailure {
    /// Firecracker unmapped guest memory or exited.
    Gone,
    /// Pages could not be had (the source, the checkpoint file): why.
    Lost(String),
}

/// The working-set prefetch and load-set learning (`learn_load_set`): while learning, faults go into the load set, and
/// a prefetch that comes due before the snapshot is loaded is held back until it is.
#[derive(Default)]
struct PrefetchState {
    learning: bool,
    loaded: bool,
    due: bool,
}

impl PrefetchState {
    fn learning(&self) -> bool {
        self.learning
    }

    fn learn(&mut self) {
        self.learning = true;
    }

    fn request(&mut self, loaded: bool, due: bool) -> bool {
        self.loaded |= loaded;
        self.learning &= !loaded;
        self.due |= due;
        let start = self.due && (self.loaded || !self.learning);
        self.due &= !start;
        start
    }
}

pub struct Pager {
    base: Arc<Template>,
    runtime: Runtime,
    pub fault_stats: FaultStats,
    /// Runs of REMOTE pages faults claimed, per fault fetcher (`fetch_faults`).
    lanes: [Lane; FAULT_FETCHERS],
    /// Pages `[next, end)` past the latest REMOTE fault, which the pullers take before going on with their share
    /// (`steered`).
    steer: Mutex<(usize, usize)>,
    /// What the pass collapsing paged-in memory into huge pages did, once done (see `collapse`).
    collapse_report: Mutex<Option<collapse::CollapseReport>>,
    /// Held across each collapse call, so `hold_collapse` can wait one out; signalled when the hold is lifted or the
    /// pager stops.
    collapse_gate: (Mutex<collapse::Gate>, Condvar),
}

// Kept contiguous so runtime resources retain their field drop order.
#[derive(Default)]
pub struct Runtime {
    mappings: OnceLock<Vec<Mapping>>,
    pages: OnceLock<Pages>,
    uffd: OnceLock<OwnedFd>,
    /// Firecracker pid. Reaped only after the pager stops (`Vm::kill`), so it cannot be reused during reads; every read
    /// by pid is checked against `exited` afterward.
    pid: AtomicU32,
    /// Firecracker as a pidfd, so killing it never hits a reused pid.
    pidfd: OnceLock<OwnedFd>,
    remote: Mutex<Option<Link>>,
    /// Checkpoint file held until the last REMOTE page settles (`pulled`), so deletion frees its disk space.
    file: Mutex<Option<Arc<PageFile>>>,
    /// The VM's REMOTE pages came from a checkpoint file (not a peer).
    from_file: AtomicBool,
    discards: AtomicU64,
    remote_left: AtomicUsize,
    pull_started: OnceLock<Instant>,
    pull_finished: OnceLock<Instant>,
    /// Signalled when Firecracker connects, the pull finishes or the pager stops.
    done: (Mutex<()>, Condvar),
    /// Set by the checkpoint barrier: no new prefetch, and the collapse pass ends; cleared if a migration aborts
    /// (`unquiesce`).
    quiesce: AtomicBool,
    /// The working-set prefetch ended for `quiesce` before it was done.
    prefetch_cut: AtomicBool,
    /// The page after the last template fault: only sequential template reads copy `FAULT_AROUND` pages, avoiding
    /// sixteenfold amplification for strided reads of guest page structs.
    template_next: AtomicUsize,
    /// The working-set prefetch: 0, `DUE` or `RUNNING` (its pages still to come).
    prefetching: AtomicU8,
    failed: OnceLock<PagerFailure>,
    stop: AtomicBool,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    /// Memory is registered for write-protect faults and write tracking is on.
    tracking: AtomicBool,
    registered_wp: AtomicBool,
    /// The copy-on-write state of a checkpoint whose pages are being written.
    cow: Mutex<Option<Arc<Cow>>>,
    /// Held while handling a fault and while a checkpoint freezes memory, so a fault read before the freeze cannot
    /// unprotect a page after it.
    wp: Mutex<()>,
    /// Firecracker's /proc/PID/pagemap, to tell populated pages apart.
    pagemap: OnceLock<std::fs::File>,
    /// Memory for the next checkpoint's hot pages, and the hot pages of the last one, while it is the delta base (see
    /// `hot`).
    hot_spare: Mutex<Option<hot::Buf>>,
    hot_prev: Mutex<Option<Arc<Held>>>,
    /// The dirty bits of the interval before the last pause, and the hot pages it left unprotected (bitmaps).
    hot_dirty: Mutex<Vec<u64>>,
    hot_kept: Mutex<Vec<u64>>,
    /// Test fault: the next freeze fails to re-protect pages.
    pub fail_protect: AtomicBool,
    /// Test fault: write faults during a copy dawdle before claiming pages.
    pub wp_race: AtomicBool,
    /// Test fault: every other rescue during a copy fails after its claim, once a writer may be waiting on the page.
    pub rescue_fail: AtomicBool,
    rescue_tries: AtomicU32,
    /// Test fault: copies of fault-fetched runs past their first page fail once more. 2: armed, and the
    /// pullers wait until a fault has taken a run (then 1), so a fault, not a puller, meets the failure.
    pub tail_fail: AtomicU32,
    /// Test fault: from then on every copy of a fault-fetched run fails (ENOMEM), and the pullers wait.
    pub stuck_from: Mutex<Option<Instant>>,
    /// Test fault: this many background pull copies fail (ENOMEM), one after another.
    pub pull_fail: AtomicU32,
    /// Initial page states and their origin, applied when Firecracker connects (see `seed`).
    initial: Mutex<Option<(Runs, Origin)>>,
    /// Signalled by `seed` and `stop`, for a handshake waiting for the seed.
    seeded: Condvar,
    /// Firecracker connects before the page states are known (a prepared load, see `expect_seed`): the handshake waits
    /// for `seed`.
    awaiting_seed: AtomicBool,
    prefetch: Mutex<PrefetchState>,
}

impl std::ops::Deref for Pager {
    type Target = Runtime;
    fn deref(&self) -> &Runtime {
        &self.runtime
    }
}

impl Pager {
    /// Listens on `sock` for Firecracker's UFFD handshake and serves faults in the background. `initial` seeds page
    /// states for an incoming migration or a checkpoint restore, with where their REMOTE pages come from; it can also
    /// be given later, with `seed`, until Firecracker connects.
    pub fn start(sock: &Path, base: Arc<Template>, initial: Option<(Runs, Origin)>) -> Result<Arc<Pager>> {
        crate::socket::check(sock)?;
        let _ = std::fs::remove_file(sock);
        let listener = UnixListener::bind(sock)?;
        // Polled, so a Firecracker that never connects cannot hold the thread forever.
        listener.set_nonblocking(true)?;
        let pager = Arc::new(Pager {
            base,
            runtime: Runtime { template_next: AtomicUsize::new(usize::MAX), initial: Mutex::new(initial), ..Runtime::default() },
            fault_stats: FaultStats::new(),
            lanes: Default::default(),
            steer: Mutex::new((0, 0)),
            collapse_report: Mutex::new(None),
            collapse_gate: Default::default(),
        });
        let p = pager.clone();
        let thread = thread::Builder::new().name("uffd".into()).spawn(move || {
            let handshake = p.handshake(&listener);
            drop(listener);
            match handshake {
                // Alongside fault handling: Firecracker itself touches guest memory while restoring devices and must
                // not wait behind it.
                Ok(prefetch) => {
                    p.prefetching.store(if prefetch { DUE } else { 0 }, Ordering::SeqCst);
                    p.start_prefetch(false, prefetch)
                }
                Err(e) => return p.fail(format!("uffd handshake failed: {e}")),
            }
            p.serve();
        })?;
        *pager.thread.lock().unwrap() = Some(thread);
        Ok(pager)
    }

    /// Starts the working-set prefetch once it is `due` and, while learning the load set, the snapshot is `loaded`.
    fn start_prefetch(self: &Arc<Self>, loaded: bool, due: bool) {
        if self.prefetch.lock().unwrap().request(loaded, due) {
            self.prefetching.store(RUNNING, Ordering::SeqCst);
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

    /// Sets the initial page states and their origin, for a pager started without them. Only before Firecracker loads a
    /// snapshot.
    pub fn seed(&self, runs: Runs, origin: Origin) -> Result<()> {
        let mut initial = self.initial.lock().unwrap();
        if self.pages.get().is_some() || initial.is_some() {
            bail!("pager already seeded");
        }
        *initial = Some((runs, origin));
        self.seeded.notify_all();
        Ok(())
    }

    /// Firecracker will connect before `seed` (it prepares the load ahead of the vmstate, touching no guest memory
    /// until the load itself): the handshake then waits for the seed (or `stop`).
    pub fn expect_seed(&self, yes: bool) {
        self.awaiting_seed.store(yes, Ordering::SeqCst);
    }

    /// Records the pages the coming snapshot load faults on into the template's load set (see `Template::load_set`),
    /// holding the working-set prefetch back until `loaded` so that it does not hide them. For loads off the critical
    /// path (a standby VM's). Call before the load.
    pub fn learn_load_set(&self) {
        self.prefetch.lock().unwrap().learn();
    }

    /// The snapshot load is done (or failed): stops learning and lets a held-back prefetch go.
    pub fn loaded(self: &Arc<Self>) {
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
                    // Bounded, to notice a stop.
                    let _ = crate::util::readable(listener, Duration::from_millis(10));
                }
                Err(e) => return Err(e.into()),
            }
        };
        while !crate::util::readable(&stream, Duration::from_millis(10)).unwrap_or(false) {
            waiting("sent its handshake")?;
        }
        stream.set_nonblocking(false)?;
        let (body, fd) = recv_with_fd(stream.as_raw_fd())?;
        let mappings: Vec<Mapping> = serde_json::from_slice(&body)?;
        let total = mappings.iter().map(|m| m.offset as usize + m.size).max().unwrap_or(0) / PAGE_SIZE;
        let mut pages = Pages::new(total);
        let initial = {
            // No deadline of its own: the migration's protocol deadline drops the prepared VM, which stops the pager.
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
            let remote = remote_pages(&runs, &mappings)?;
            for (first, count, state) in runs {
                pages.fill(first as usize, count as usize, state);
            }
            self.remote_left.store(remote, Ordering::SeqCst);
            match origin {
                Origin::Peer(source) => {
                    // Connect now: the restore itself faults on remote pages.
                    let mut link = Link::new(source);
                    link.client = link.connect().ok();
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
        // A checkpoint restore prefetches the template's working set too: the pages the checkpoint left BASE are still
        // the template's.
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

    /// Copies the template's recorded working set in up front, while the vCPUs are still being restored, instead of one
    /// fault at a time.
    fn prefetch(&self) {
        while self.prefetch_pass() {
            self.prefetching.store(RUNNING, Ordering::SeqCst);
        }
        self.notify();
    }

    /// One prefetch pass; true if it was cut short by `quiesce` but an abort has cleared that meanwhile and left it to
    /// this to go on (`unquiesce` takes `prefetch_cut` only once it is published).
    fn prefetch_pass(&self) -> bool {
        let pages = self.pages();
        let mut cut = false;
        for (mut i, end) in self.chunks(self.working_set(0, 1), PREFETCH_RUN) {
            while i < end {
                if self.quiesce.load(Ordering::SeqCst) {
                    cut = true;
                    break;
                }
                // Holes were zero at snapshot time (mostly free memory the guest allocates again); map them too, or
                // each one costs a fault.
                let data = self.base.has_data(i);
                let n = pages.claim(i, end - i, BASE, |p| self.base.has_data(p) == data);
                if n > 0 {
                    let src = |p: usize, c: usize| data.then(|| self.base.pages(p, c));
                    let _ = pages.install(i, n, BASE, None, |p, c| self.populate(p, c, src(p, c)));
                }
                i += n.max(1);
            }
        }
        // Done (for now) first, so a prefetch `unquiesce` starts again is not counted as done.
        self.prefetching.store(0, Ordering::SeqCst);
        let cut = cut && !self.stop.load(Ordering::SeqCst);
        self.prefetch_cut.store(cut, Ordering::SeqCst);
        // Whichever of this and `unquiesce` takes the cut back goes on.
        cut && !self.quiesce.load(Ordering::SeqCst) && self.prefetch_cut.swap(false, Ordering::SeqCst)
    }

    /// Runs of pages populated so far, as `(first_page, count)`.
    pub fn present_runs(&self) -> Vec<(u64, u64)> {
        let (pages, mut p) = (self.pages(), 0);
        std::iter::from_fn(|| {
            let a = pages.next_in(PRESENT, p, pages.len());
            p = pages.next_not(PRESENT, a, pages.len());
            (a < p).then_some((a as u64, (p - a) as u64))
        })
        .collect()
    }

    /// Installs REMOTE pages whose contents came along with the vmstate (one `PAGE_SIZE` slice of `data` per page of
    /// `list`), once Firecracker has connected: the load would otherwise fault on them one round trip at a time. Runs
    /// alongside the load; a page a fault or puller claimed first is waited for (by `deadline`), so all of them are in
    /// when it returns. Returns how many it installed.
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
        for (index, n) in page_runs(list, self.mappings()) {
            let (mut index, end) = (index, index + n);
            while index < end {
                let page = list[index] as usize;
                if let Some(why) = self.failed() {
                    bail!("the pager failed: {why}");
                }
                // Wait for other installers too: they may fail and return REMOTE.
                match pages.states.get(page).map(|s| s.load(Ordering::SeqCst)) {
                    Some(REMOTE) => {
                        let n = pages.claim(page, end - index, REMOTE, |_| true);
                        if n > 0 {
                            let gen = pages.read_gen.load(Ordering::SeqCst);
                            let src = |p: usize, c: usize| &data[(index + p - page) * PAGE_SIZE..(index + p - page + c) * PAGE_SIZE];
                            let (resolved, res) = pages.install(page, n, REMOTE, None, |p, c| self.populate(p, c, Some(src(p, c))));
                            self.pulled(resolved);
                            installed += resolved;
                            match res {
                                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => pages.wait_events_read(gen),
                                r => {
                                    r?;
                                    index += n;
                                    continue;
                                }
                            }
                        }
                    }
                    Some(INFLIGHT | DISCARDED) => {}
                    _ => {
                        index += 1;
                        continue;
                    }
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

    /// Waits (up to `timeout`) for `cond`, checked again whenever Firecracker connects, the pull finishes or the pager
    /// stops. False if the pager stopped or time ran out first.
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

    /// Blocks until every remote page has arrived (true), or the pager has stopped or failed, or `timeout` passed,
    /// first (false).
    pub fn wait_pulled(&self, timeout: Option<Duration>) -> bool {
        self.wait_for(timeout, || self.remote_left() == 0)
    }

    /// `wait_pulled(None)`, and for a working-set prefetch that runs (one never started does not hold it up), telling
    /// `tick` every `every` meanwhile how many MiB are still to come: remote pages, and the working set while due.
    pub fn wait_pulled_every(&self, every: Duration, mut tick: impl FnMut(u64)) -> bool {
        while !self.wait_for(Some(every), || self.remote_left() == 0 && self.prefetching.load(Ordering::SeqCst) != RUNNING) {
            if self.stop.load(Ordering::SeqCst) {
                return false;
            }
            let ws = if self.prefetching.load(Ordering::SeqCst) > 0 { self.base.working_set_mib() } else { 0 };
            tick((self.remote_left() as u64 * PAGE_SIZE as u64).div_ceil(1 << 20) + ws);
        }
        true
    }

    /// How long an incoming migration took to pull every remote page, once done.
    pub fn pull_time(&self) -> Option<Duration> {
        Some(self.pull_finished.get()?.duration_since(*self.pull_started.get()?))
    }

    /// Counts `n` remote pages as resolved. With the last one, lets go of the checkpoint file: every claim on a REMOTE
    /// page has settled (a claimed page counts until its claimant settles it), so nothing reads it any more but those
    /// already reading, through clones of their own.
    fn pulled(&self, n: usize) {
        if n > 0 && self.remote_left.fetch_sub(n, Ordering::SeqCst) == n {
            // Off the calling thread, which may be the one serving faults: it walks the whole chain's page cache. Only a
            // filesystem without O_DIRECT left anything there.
            if let Some(file) = self.file.lock().unwrap().take().filter(|f| f.buffered()) {
                std::thread::spawn(move || file.drop_cache());
            }
            let _ = self.pull_finished.set(Instant::now());
            self.notify();
        }
    }

    /// Wakes whoever waits on `done` or for fault runs: Firecracker connected, the pull finished or the pager stopped.
    /// Fault fetchers end once the pull is done, letting go of the file too.
    fn notify(&self) {
        drop(self.done.0.lock().unwrap());
        self.done.1.notify_all();
        for lane in &self.lanes {
            drop(lane.q.lock().unwrap());
            lane.cv.notify_all();
        }
    }

    /// The guest's memory size in pages, once Firecracker has connected.
    pub fn total_pages(&self) -> usize {
        self.pages().len()
    }

    /// The first page past the guest memory region holding `page`.
    pub fn region_end(&self, page: usize) -> Option<usize> {
        self.locate((page * PAGE_SIZE) as u64).map(|m| m.span().1)
    }

    /// Names the Firecracker this pager serves; required before it loads a snapshot, so a failing pager can always kill
    /// it.
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
        self.wake_collapse();
        let _initial = self.initial.lock().unwrap();
        self.seeded.notify_all();
    }

    /// A migration aborted, or a checkpoint ended with the VM still here: undoes `quiesce_export`, starting again the
    /// working-set prefetch and the collapse pass if it cut them short.
    pub fn unquiesce(self: &Arc<Self>) {
        if self.stop.load(Ordering::SeqCst) || !self.quiesce.swap(false, Ordering::SeqCst) {
            return;
        }
        if self.prefetch_cut.swap(false, Ordering::SeqCst) {
            self.prefetching.store(RUNNING, Ordering::SeqCst);
            let p = self.clone();
            thread::spawn(move || p.prefetch());
        }
        if self.collapse_quiesced() {
            let p = self.clone();
            thread::spawn(move || p.collapse());
        }
    }

    /// Gives up on the VM's memory: unless it was stopped on purpose, records why and kills Firecracker, whose vCPUs
    /// (or snapshot load) may be blocked on pages that will never come.
    fn fail(&self, why: String) {
        if !self.stop.load(Ordering::SeqCst) {
            crate::log!("uffd: {why}; killing the vm");
            let _ = self.failed.set(PagerFailure::Lost(why));
            match self.pidfd.get().map(crate::util::pidfd_kill) {
                Some(Ok(())) => {}
                Some(Err(e)) => crate::log!("uffd: cannot kill firecracker: {e}"),
                None => crate::log!("uffd: no firecracker to kill"),
            }
        }
        self.stop();
    }

    /// Whether `e`, from a uffd call on `n` pages from `page`, means that nothing at all is mapped there in Firecracker
    /// any more (or it is gone): ENOENT outside a registered VMA, ESRCH once its memory is gone. ENOENT also comes
    /// across a VMA boundary, e.g. into an unplugged virtio-mem slot, where memory is still mapped: that is not this.
    fn unmapped(&self, e: &io::Error, page: usize, n: usize) -> bool {
        let Some((addr, _)) = self.host_addr((page * PAGE_SIZE) as u64).filter(|_| matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))) else {
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

    /// Gives up on guest memory that Firecracker has unmapped: it is most likely tearing down a load that failed, and
    /// about to answer the load request with why. Like `fail`, but Firecracker gets `UNMAPPED_GRACE` to do that (or
    /// exit) before it is killed.
    fn gone(&self) {
        // Once, though every puller runs into it.
        if !self.stop.load(Ordering::SeqCst) && self.failed.set(PagerFailure::Gone).is_ok() {
            crate::log!("uffd: firecracker unmapped guest memory; killing it unless it exits within {UNMAPPED_GRACE:?}");
            if let Some(fd) = self.pidfd.get().and_then(|fd| fd.try_clone().ok()) {
                thread::spawn(move || {
                    if !crate::util::readable(&fd, UNMAPPED_GRACE).unwrap_or(false) {
                        let _ = crate::util::pidfd_kill(&fd);
                    }
                });
            }
        }
        self.stop();
    }

    /// SIGKILLs the Firecracker through its pidfd, without waiting for anything (such as a call holding the VM's API
    /// lock).
    pub fn kill_firecracker(&self) {
        if let Some(fd) = self.pidfd.get() {
            let _ = crate::util::pidfd_kill(fd);
        }
    }

    /// Test fault `kill_prepared`: kills Firecracker (left unreaped, see `pid`) and treats it as gone.
    pub fn firecracker_gone(&self) {
        self.kill_firecracker();
        if let Some(fd) = self.pidfd.get() {
            let _ = crate::util::readable(fd, Duration::from_secs(5));
        }
        self.gone();
    }

    /// Whether the pager gave up on pages for its own reasons (the source, the checkpoint file), rather than because
    /// Firecracker went away.
    pub fn lost_pages(&self) -> bool {
        matches!(self.failed.get(), Some(PagerFailure::Lost(_)))
    }

    /// Why the pager gave up, if it did. The VM cannot make progress then.
    pub fn failed(&self) -> Option<&str> {
        self.failed.get().map(|s| match s {
            PagerFailure::Gone => "firecracker unmapped guest memory",
            PagerFailure::Lost(why) => why.as_str(),
        })
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

    /// Guest memory regions as `(offset, size, host address in Firecracker)` (for tests that inspect its mappings).
    pub fn host_regions(&self) -> Vec<(u64, u64, u64)> {
        self.mappings().iter().map(|m| (m.offset, m.size as u64, m.base_host_virt_addr)).collect()
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
        c[BASE as usize] = pages.len();
        for i in pages.not_base(0, pages.len()) {
            c[BASE as usize] -= 1;
            c[pages.get(i) as usize] += 1;
        }
        c
    }

    /// Checkpoint barrier, for a paused VM: stops prefetching, waits for REMOVE events already read to be applied and
    /// for in-flight installs to settle, then exports page states that match the saved device state. A page installed
    /// behind the scan only gains the contents its old state already implied (template or zero), as the paused guest
    /// cannot write it.
    ///
    /// The export is the run-length encoded page states a migration target needs: PRESENT pages become REMOTE there,
    /// ZERO stays ZERO and BASE is implied.
    pub fn quiesce_export(&self) -> Result<Runs> {
        self.quiesce.store(true, Ordering::SeqCst);
        // A pass held asleep (the VM paused) sees it now, not at the next resume.
        self.wake_collapse();
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

    fn host_addr(&self, offset: u64) -> Option<(u64, &Mapping)> {
        let m = self.locate(offset)?;
        Some((m.base_host_virt_addr + (offset - m.offset), m))
    }

    /// The canonical hash of guest memory as it is now (for a paused VM; a test hook): see `checkpoint::Canon`.
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
        self.host_addr((page * PAGE_SIZE) as u64).map(|(a, _)| a).ok_or_else(|| io::Error::other("bad page"))
    }

    /// Populates up to `n` pages starting at `page`, from `src` or with zeroes, and wakes their waiters. Returns how
    /// many it populated: the kernel stops early (reporting progress) at a page that already exists.
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

/// The pages of `wanted` (sorted) that `runs` make REMOTE on a target.
pub fn remote_among(runs: &Runs, wanted: impl IntoIterator<Item = u64>) -> Vec<u64> {
    let mut remote: Vec<(u64, u64)> = runs.iter().filter(|r| r.2 == REMOTE).map(|r| (r.0, r.0.saturating_add(r.1))).collect();
    remote.sort_unstable();
    let is_remote = |&p: &u64| remote.get(remote.partition_point(|r| r.1 <= p)).is_some_and(|r| r.0 <= p);
    wanted.into_iter().filter(is_remote).collect()
}

/// Runs of consecutive pages in `list`, as `(index, count)`, each within one region's 2 MiB chunk: a uffd copy (or a
/// read) never crosses a VMA end (see `Pager::fault`). A page outside every region is a run of its own. Every run has
/// at least one page, whatever `list` holds, so this always ends.
fn page_runs<'a>(list: &'a [u64], mappings: &'a [Mapping]) -> impl Iterator<Item = (usize, usize)> + 'a {
    let mut i = 0;
    std::iter::from_fn(move || {
        let first = *list.get(i)?;
        let region = usize::try_from(first).ok().and_then(|f| mappings.iter().map(Mapping::span).find(|&(a, b)| (a..b).contains(&f)).map(|s| (f, s)));
        let end = match region {
            Some((f, (a, b))) => b.min(f.saturating_add(ARM_CHUNK - (f - a) % ARM_CHUNK)) as u64,
            None => first.saturating_add(1),
        };
        let n = list[i..].iter().zip(first..end).take_while(|(&p, q)| p == *q).count().max(1);
        i += n;
        Some((i - n, n))
    })
}

/// Checks what a migration source sent before the target uses any of it: its page runs (as `remote_pages` does) against
/// the guest memory regions it named, which the pager later holds to Firecracker's, and its preload list, which must be
/// ascending, without repeats, and only of pages the runs make REMOTE (as the source picks them, `remote_among`).
pub fn check_incoming(runs: &Runs, preload: &[u64], regions: &[(u64, u64)]) -> Result<()> {
    if preload.len() > MAX_PRELOAD {
        bail!("{} pages to preload, more than {MAX_PRELOAD}", preload.len());
    }
    let mappings: Vec<Mapping> = regions.iter().map(|&(offset, size)| Mapping { base_host_virt_addr: 0, size: size as usize, offset }).collect();
    remote_pages(runs, &mappings)?;
    if let Some(w) = preload.windows(2).find(|w| w[0] >= w[1]) {
        bail!("preload list out of order: page {} before {}", w[0], w[1]);
    }
    let remote = remote_among(runs, preload.iter().copied());
    if let Some(p) = preload.get(remote.iter().zip(preload).take_while(|(a, b)| a == b).count()) {
        bail!("preload page {p} is not a remote page");
    }
    Ok(())
}

const ALL: [(usize, usize); 1] = [(0, usize::MAX)];

/// The maximal runs `[a, b)` within `[first, end)` of pages that pass `f` (asked once per page).
pub(crate) fn runs_where(first: usize, end: usize, f: impl Fn(usize) -> bool) -> impl Iterator<Item = (usize, usize)> {
    let mut p = first;
    std::iter::from_fn(move || {
        let a = (p..end).find(|&i| f(i))?;
        p = (a + 1..end).find(|&i| !f(i)).unwrap_or(end);
        Some((a, p))
    })
}

fn regions(mappings: &[Mapping]) -> Vec<(u64, u64)> {
    mappings.iter().map(|m| (m.offset, m.size as u64)).collect()
}

/// Checks page runs from a migration source or checkpoint (ascending, disjoint, each inside guest memory, and only
/// states a source exports) and counts their REMOTE pages. A run in a gap between regions would never be pulled (the
/// pullers walk the regions), so the source would never be released.
fn remote_pages(runs: &Runs, mappings: &[Mapping]) -> Result<usize> {
    // The regions' pages, adjacent ones merged: a run may cross from one into the next.
    let mut spans: Vec<(u64, u64)> = mappings.iter().map(|m| m.span()).map(|(a, b)| (a as u64, b as u64)).filter(|s| s.0 < s.1).collect();
    spans.sort_unstable();
    spans.dedup_by(|b, a| {
        let merge = b.0 <= a.1;
        if merge {
            a.1 = a.1.max(b.1);
        }
        merge
    });
    let inside = |first: u64, end: u64| spans.get(spans.partition_point(|s| s.1 <= first)).is_some_and(|s| s.0 <= first && end <= s.1);
    let (mut next, mut remote) = (0, 0);
    for &(first, count, state) in runs {
        match first.checked_add(count) {
            Some(end) if first >= next && count > 0 && inside(first, end) && (state == REMOTE || state == ZERO) => {
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
    let (n, fds) = crate::util::recvmsg_fds(sock, &mut body)?;
    let fd = fds.into_iter().next().ok_or("handshake carried no file descriptor")?;
    body.truncate(n);
    Ok((body, fd))
}
