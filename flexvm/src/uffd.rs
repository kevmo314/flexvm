//! Userfaultfd pager for Firecracker guest memory.
//!
//! Every page of guest memory is in one of a few states. Faults are resolved
//! according to that state, so a VM can be backed by any mix of a shared
//! template image, zero pages and pages still living on a migration source.
//!
//!   BASE      -> copied from the template memory file (holes map the zero page)
//!   ZERO      -> discarded by the guest (balloon / virtio-mem); maps the zero page
//!   REMOTE    -> fetched from the migration source's page server
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

use std::collections::VecDeque;
use std::io::{self, IoSliceMut, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock, RwLockWriteGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::bail;
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
/// How long a fault may keep failing (other than EAGAIN) before the pager gives up.
const FAULT_TIMEOUT: Duration = Duration::from_secs(1);
/// How long the migration source may stay unreachable before the pager gives up.
const SOURCE_TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_MIN: Duration = Duration::from_millis(10);
const BACKOFF_MAX: Duration = Duration::from_secs(1);

// From linux/userfaultfd.h.
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
const UFFD_EVENT_REMOVE: u8 = 0x15;
const UFFDIO_WAKE: libc::c_ulong = 0x8010_AA02;
const UFFDIO_COPY: libc::c_ulong = 0xC028_AA03;
const UFFDIO_ZEROPAGE: libc::c_ulong = 0xC020_AA04;

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
    events: RwLock<()>,
}

impl Pages {
    pub fn new(n: usize) -> Pages {
        // BASE is 0, so a zeroed allocation (lazily backed by the kernel) is the initial state.
        let states = unsafe { std::mem::transmute::<Vec<u8>, Vec<AtomicU8>>(vec![0u8; n]) };
        Pages { states, events: RwLock::new(()) }
    }

    pub fn get(&self, page: usize) -> u8 {
        self.states[page].load(Ordering::SeqCst)
    }

    fn set(&self, page: usize, state: u8) {
        self.states[page].store(state, Ordering::SeqCst)
    }

    pub fn len(&self) -> usize {
        self.states.len()
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
            && self.states[first + n].compare_exchange(from, INFLIGHT, Ordering::SeqCst, Ordering::SeqCst).is_ok()
        {
            n += 1;
        }
        n
    }

    /// Applies a REMOVE of `page`. Returns whether it resolved a REMOTE page.
    pub fn discard(&self, _removing: &RwLockWriteGuard<'_, ()>, page: usize) -> bool {
        let old = self.states[page]
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |s| {
                Some(if s == INFLIGHT || s == DISCARDED { DISCARDED } else { ZERO })
            })
            .unwrap();
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
    remote_left: AtomicUsize,
    pull_started: OnceLock<Instant>,
    pull_finished: OnceLock<Instant>,
    /// Signalled when the pull finishes or the pager stops.
    done: (Mutex<()>, Condvar),
    /// Set by the checkpoint barrier: no new prefetch.
    quiesce: AtomicBool,
    failed: OnceLock<String>,
    stop: AtomicBool,
}

impl Pager {
    /// Listens on `sock` for Firecracker's UFFD handshake and serves faults in
    /// the background. `initial` seeds page states for an incoming migration.
    pub fn start(sock: &Path, base: Arc<Template>, initial: Option<(Runs, Source)>) -> Result<Arc<Pager>> {
        let _ = std::fs::remove_file(sock);
        let listener = UnixListener::bind(sock)?;
        let pager = Arc::new(Pager {
            base,
            mappings: OnceLock::new(),
            pages: OnceLock::new(),
            uffd: OnceLock::new(),
            ready: (Mutex::new(false), Condvar::new()),
            pid: AtomicU32::new(0),
            pidfd: OnceLock::new(),
            remote: Mutex::new(None),
            remote_left: AtomicUsize::new(0),
            pull_started: OnceLock::new(),
            pull_finished: OnceLock::new(),
            done: (Mutex::new(()), Condvar::new()),
            quiesce: AtomicBool::new(false),
            failed: OnceLock::new(),
            stop: AtomicBool::new(false),
        });
        let p = pager.clone();
        thread::Builder::new().name("uffd".into()).spawn(move || {
            let prefetch = match p.handshake(&listener, initial) {
                Ok(prefetch) => prefetch,
                Err(e) => return p.fail(format!("uffd handshake failed: {e}")),
            };
            // Prefetch alongside fault handling: Firecracker itself touches guest
            // memory while restoring devices and must not wait behind it.
            if prefetch {
                let p = p.clone();
                thread::spawn(move || p.prefetch());
            }
            p.serve();
        })?;
        Ok(pager)
    }

    /// Takes over Firecracker's userfaultfd. Returns whether to prefetch the working set.
    fn handshake(&self, listener: &UnixListener, initial: Option<(Runs, Source)>) -> Result<bool> {
        let (stream, _) = listener.accept()?;
        let (body, fd) = recv_with_fd(stream.as_raw_fd())?;
        let mappings: Vec<Mapping> = serde_json::from_slice(&body)?;
        let total = mappings.iter().map(|m| m.offset as usize + m.size).max().unwrap_or(0) / PAGE_SIZE;
        let pages = Pages::new(total);
        if let Some((runs, source)) = initial {
            let _ = self.pull_started.set(Instant::now());
            let remote = remote_pages(&runs, total)?;
            for (first, count, state) in runs {
                for p in first as usize..(first + count) as usize {
                    pages.set(p, state);
                }
            }
            self.remote_left.store(remote, Ordering::SeqCst);
            // Connect now: the restore itself faults on remote pages.
            let mut link = Link::new(source);
            link.client = PageClient::connect(&link.source).ok();
            *self.remote.lock().unwrap() = Some(link);
        }
        let fresh = self.remote_left() == 0;
        let _ = self.mappings.set(mappings);
        let _ = self.pages.set(pages);
        let _ = self.uffd.set(fd);
        if fresh && self.pull_started.get().is_some() {
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
        self.notify();
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

    /// Why the pager gave up, if it did. The VM cannot make progress then.
    pub fn failed(&self) -> Option<&str> {
        self.failed.get().map(|s| s.as_str())
    }

    pub fn remote_left(&self) -> usize {
        self.remote_left.load(Ordering::SeqCst)
    }

    fn mappings(&self) -> &[Mapping] {
        self.mappings.get().map(|m| m.as_slice()).unwrap_or(&[])
    }

    fn pages(&self) -> &Pages {
        static EMPTY: Pages = Pages { states: Vec::new(), events: RwLock::new(()) };
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
            for (i, p) in pages.states[first..first + m.size / PAGE_SIZE].iter().enumerate() {
                let mut s = p.load(Ordering::Relaxed);
                if s == BASE {
                    continue;
                }
                let i = first + i;
                while (s == INFLIGHT || s == DISCARDED) && start.elapsed() < Duration::from_secs(1) {
                    thread::sleep(Duration::from_micros(20));
                    s = p.load(Ordering::SeqCst);
                }
                let s = match s {
                    PRESENT => REMOTE,
                    ZERO => ZERO,
                    BASE => continue,
                    s => bail!("page {i} is still in state {s}; the VM is mid-migration"),
                };
                match runs.last_mut() {
                    Some((f, n, st)) if *st == s && *f + *n == i as u64 => *n += 1,
                    _ => runs.push((i as u64, 1, s)),
                }
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
        // Faults to retry, with when they first failed other than with EAGAIN.
        let mut pending: VecDeque<(u64, Option<Instant>)> = VecDeque::new();
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
                let removing = self.pages().removing();
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    for msg in buf[..n as usize].chunks_exact(32) {
                        let a = u64::from_ne_bytes(msg[8..16].try_into().unwrap());
                        let b = u64::from_ne_bytes(msg[16..24].try_into().unwrap());
                        match msg[0] {
                            UFFD_EVENT_PAGEFAULT => pending.push_back((b, None)),
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
                let (addr, since) = pending.pop_front().unwrap();
                match self.fault(addr) {
                    Ok(()) => {}
                    Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => pending.push_back((addr, since)),
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => return self.fail(e.to_string()),
                    Err(e) => match since {
                        None => {
                            eprintln!("uffd: fault at {addr:#x}: {e}; retrying");
                            pending.push_back((addr, Some(Instant::now())));
                        }
                        Some(t) if t.elapsed() < FAULT_TIMEOUT => pending.push_back((addr, since)),
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
        let (mut a, mut resolved) = (start & !(PAGE_SIZE as u64 - 1), 0);
        while a < end {
            if let Some((p, _)) = self.page_of(a) {
                resolved += self.pages().discard(removing, p) as usize;
            }
            a += PAGE_SIZE as u64;
        }
        self.pulled(resolved);
    }

    fn fault(&self, addr: u64) -> io::Result<()> {
        let Some((page, m)) = self.page_of(addr) else {
            return Err(io::Error::other("fault outside guest memory"));
        };
        let region_left = (m.offset as usize + m.size) / PAGE_SIZE - page;
        let pages = self.pages();
        match pages.get(page) {
            // Normally a fault that raced the install; if the page is really
            // missing, a REMOVE zapped it after it settled (see `Pages`).
            PRESENT => match self.populate(page, 1, None) {
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => self.wake(page, 1),
                r => r.map(drop),
            },
            // Someone else is installing it; retry until it lands (their copy wakes us).
            INFLIGHT | DISCARDED => Err(eagain()),
            REMOTE => {
                let n = pages.claim(page, REMOTE_FAULT_RUN.min(region_left), REMOTE, |_| true);
                if n == 0 {
                    return Err(eagain());
                }
                let mut buf = vec![0u8; n * PAGE_SIZE];
                let fetched = match self.remote.lock().unwrap().as_mut() {
                    Some(link) => link.fetch((page * PAGE_SIZE) as u64, &mut buf, None),
                    None => Err(io::Error::other("no migration source")),
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

    /// Pulls every REMOTE page in the background so the source can let go.
    fn spawn_pullers(self: Arc<Self>) {
        let source = self.remote.lock().unwrap().as_ref().unwrap().source.clone();
        for t in 0..PULL_THREADS {
            let p = self.clone();
            let link = Link::new(source.clone());
            thread::spawn(move || {
                if let Err(e) = p.pull(t, link) {
                    p.fail(format!("background pull {t} failed: {e}"));
                }
            });
        }
    }

    fn pull(&self, stripe: usize, mut link: Link) -> io::Result<()> {
        let pages = self.pages();
        let mut buf = vec![0u8; PULL_RUN * PAGE_SIZE];
        for m in self.mappings() {
            let first = m.offset as usize / PAGE_SIZE;
            let end = first + m.size / PAGE_SIZE;
            let mut chunk = first + stripe * PULL_RUN;
            while chunk < end && !self.stop.load(Ordering::SeqCst) {
                let chunk_end = (chunk + PULL_RUN).min(end);
                let mut i = chunk;
                while i < chunk_end {
                    let n = pages.claim(i, chunk_end - i, REMOTE, |_| true);
                    if n == 0 {
                        i += 1;
                        continue;
                    }
                    let b = &mut buf[..n * PAGE_SIZE];
                    if let Err(e) = link.fetch((i * PAGE_SIZE) as u64, b, Some(&self.stop)) {
                        let resolved = pages.release(i, n, REMOTE);
                        self.pulled(resolved);
                        if resolved < n {
                            return Err(e);
                        }
                        // All discarded meanwhile.
                        i += n;
                        continue;
                    }
                    let src = |p: usize, c: usize| &b[(p - i) * PAGE_SIZE..(p - i + c) * PAGE_SIZE];
                    let (resolved, res) =
                        pages.install(i, n, REMOTE, Some(&self.stop), |p, c| self.populate(p, c, Some(src(p, c))));
                    self.pulled(resolved);
                    res?;
                    i += n;
                }
                chunk += PULL_THREADS * PULL_RUN;
            }
        }
        Ok(())
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
