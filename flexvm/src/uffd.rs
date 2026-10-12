//! Userfaultfd pager for Firecracker guest memory.
//!
//! Every page of guest memory is in one of a few states. Faults are resolved
//! according to that state, so a VM can be backed by any mix of a shared
//! template image, zero pages and pages still living on a migration source.
//!
//!   BASE     -> copied from the template memory file (holes map the zero page)
//!   ZERO     -> discarded by the guest (balloon / virtio-mem); maps the zero page
//!   REMOTE   -> fetched from the migration source's page server
//!   INFLIGHT -> a fetch is in progress; its UFFDIO_COPY wakes any waiters
//!   PRESENT  -> populated in this VM, the only copy is inside Firecracker
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
use std::sync::{Arc, Condvar, Mutex, OnceLock};
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

/// Pages copied per fault from the template, to cut down on round trips.
const FAULT_AROUND: usize = 16;
/// Pages fetched per remote fault.
const REMOTE_FAULT_RUN: usize = 64;
/// Pages per background pull request.
const PULL_RUN: usize = 256;
const PULL_THREADS: usize = 4;
/// Threads copying the working set in when it is installed in huge pages.
const PREFETCH_THREADS: usize = 4;

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
    /// Host page size backing the region: 4 KiB, or 2 MiB for hugetlbfs.
    #[serde(default = "small_page")]
    pub page_size: usize,
}

fn small_page() -> usize {
    PAGE_SIZE
}

/// Chunk states when guest memory is backed by huge pages.
const CHUNK_EMPTY: u8 = 0;
const CHUNK_INFLIGHT: u8 = 1;
const CHUNK_PRESENT: u8 = 2;

/// Initial page states for a VM migrating in: runs of `[first_page, count, state]`.
pub type Runs = Vec<(u64, u64, u8)>;

pub struct Pager {
    base: Arc<Template>,
    mappings: OnceLock<Vec<Mapping>>,
    pages: OnceLock<Vec<AtomicU8>>,
    /// 4 KiB pages per host page: 1, or 512 with 2 MiB huge pages. Huge pages
    /// are installed whole, so their state is tracked per chunk as well.
    gran: OnceLock<usize>,
    chunks: OnceLock<Vec<AtomicU8>>,
    uffd: OnceLock<OwnedFd>,
    ready: (Mutex<bool>, Condvar),
    /// Firecracker pid, for reading pages out when acting as a migration source.
    pid: AtomicU32,
    remote: Mutex<Option<PageClient>>,
    remote_left: AtomicUsize,
    pull_started: OnceLock<Instant>,
    pull_finished: OnceLock<Instant>,
    stop: AtomicBool,
    /// Page-fault events received from the userfaultfd.
    pub faults: AtomicUsize,
}

impl Pager {
    /// Listens on `sock` for Firecracker's UFFD handshake and serves faults in
    /// the background. `initial` seeds page states for an incoming migration.
    pub fn start(sock: &Path, base: Arc<Template>, initial: Option<(Runs, String, String)>) -> Result<Arc<Pager>> {
        let _ = std::fs::remove_file(sock);
        let listener = UnixListener::bind(sock)?;
        let pager = Arc::new(Pager {
            base,
            mappings: OnceLock::new(),
            pages: OnceLock::new(),
            gran: OnceLock::new(),
            chunks: OnceLock::new(),
            uffd: OnceLock::new(),
            ready: (Mutex::new(false), Condvar::new()),
            pid: AtomicU32::new(0),
            remote: Mutex::new(None),
            remote_left: AtomicUsize::new(0),
            pull_started: OnceLock::new(),
            pull_finished: OnceLock::new(),
            stop: AtomicBool::new(false),
            faults: AtomicUsize::new(0),
        });
        let p = pager.clone();
        thread::Builder::new().name("uffd".into()).spawn(move || {
            let prefetch = match p.handshake(&listener, initial) {
                Ok(prefetch) => prefetch,
                Err(e) => {
                    eprintln!("uffd handshake failed: {e}");
                    return;
                }
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
    fn handshake(&self, listener: &UnixListener, initial: Option<(Runs, String, String)>) -> Result<bool> {
        let (stream, _) = listener.accept()?;
        let (body, fd) = recv_with_fd(stream.as_raw_fd())?;
        let mappings: Vec<Mapping> = serde_json::from_slice(&body)?;
        let total = mappings.iter().map(|m| m.offset as usize + m.size).max().unwrap_or(0) / PAGE_SIZE;
        // BASE is 0, so a zeroed allocation (lazily backed by the kernel) is the initial state.
        let pages: Vec<AtomicU8> = unsafe { std::mem::transmute::<Vec<u8>, Vec<AtomicU8>>(vec![0u8; total]) };
        if let Some((runs, addr, vm)) = initial {
            let _ = self.pull_started.set(Instant::now());
            let mut remote = 0;
            for (first, count, state) in runs {
                for p in &pages[first as usize..(first + count) as usize] {
                    p.store(state, Ordering::Relaxed);
                }
                if state == REMOTE {
                    remote += count as usize;
                }
            }
            self.remote_left.store(remote, Ordering::SeqCst);
            *self.remote.lock().unwrap() = Some(PageClient::connect(&addr, &vm)?);
        }
        let fresh = self.remote_left() == 0;
        let gran = mappings.iter().map(|m| m.page_size).max().unwrap_or(PAGE_SIZE).max(PAGE_SIZE) / PAGE_SIZE;
        let _ = self.gran.set(gran);
        let chunks = if gran > 1 { (0..total.div_ceil(gran)).map(|_| AtomicU8::new(CHUNK_EMPTY)).collect() } else { Vec::new() };
        let _ = self.chunks.set(chunks);
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
        if self.gran() > 1 {
            return self.prefetch_chunks();
        }
        let pages = self.pages();
        for &(first, count) in &self.base.working_set {
            let (mut i, end) = (first as usize, ((first + count) as usize).min(pages.len()));
            while i < end {
                if pages[i].load(Ordering::SeqCst) != BASE {
                    i += 1;
                    continue;
                }
                // Holes were zero at snapshot time (mostly free memory the guest
                // allocates again); map them too, or each one costs a fault.
                let data = self.base.has_data(i);
                let region_end = self.locate((i * PAGE_SIZE) as u64).map_or(i + 1, |m| (m.offset as usize + m.size) / PAGE_SIZE);
                let mut n = 1;
                while i + n < end.min(region_end)
                    && self.base.has_data(i + n) == data
                    && pages[i + n].load(Ordering::SeqCst) == BASE
                {
                    n += 1;
                }
                let _ = self.install(i, n, data.then(|| self.base.pages(i, n)));
                i += n;
            }
        }
    }

    /// Runs of pages populated so far, as `(first_page, count)`.
    pub fn present_runs(&self) -> Vec<(u64, u64)> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for (i, p) in self.pages().iter().enumerate() {
            if p.load(Ordering::Relaxed) != PRESENT {
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
        if self.remote_left.fetch_sub(n, Ordering::SeqCst) == n {
            let _ = self.pull_finished.set(Instant::now());
        }
    }

    pub fn set_pid(&self, pid: u32) {
        self.pid.store(pid, Ordering::SeqCst);
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn remote_left(&self) -> usize {
        self.remote_left.load(Ordering::SeqCst)
    }

    fn mappings(&self) -> &[Mapping] {
        self.mappings.get().map(|m| m.as_slice()).unwrap_or(&[])
    }

    fn pages(&self) -> &[AtomicU8] {
        self.pages.get().map(|p| p.as_slice()).unwrap_or(&[])
    }

    fn fd(&self) -> RawFd {
        self.uffd.get().unwrap().as_raw_fd()
    }

    /// Counts pages per state.
    pub fn census(&self) -> [usize; 5] {
        let mut c = [0usize; 5];
        for p in self.pages() {
            c[p.load(Ordering::Relaxed) as usize] += 1;
        }
        c
    }

    /// Run-length encodes the page states a migration target needs: PRESENT
    /// pages become REMOTE there, ZERO stays ZERO and BASE is implied.
    pub fn export_runs(&self) -> Result<Runs> {
        let mut runs: Runs = Vec::new();
        for m in self.mappings() {
            let first = m.offset as usize / PAGE_SIZE;
            for i in first..first + m.size / PAGE_SIZE {
                let s = match self.pages()[i].load(Ordering::Relaxed) {
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
        let mut pending: VecDeque<u64> = VecDeque::new();
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
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    for msg in buf[..n as usize].chunks_exact(32) {
                        let a = u64::from_ne_bytes(msg[8..16].try_into().unwrap());
                        let b = u64::from_ne_bytes(msg[16..24].try_into().unwrap());
                        match msg[0] {
                            UFFD_EVENT_PAGEFAULT => {
                                self.faults.fetch_add(1, Ordering::Relaxed);
                                pending.push_back(b)
                            }
                            UFFD_EVENT_REMOVE => self.discard(a, b),
                            _ => {}
                        }
                    }
                }
            }
            // Retry faults that hit EAGAIN once the events ahead of them are drained.
            for _ in 0..pending.len() {
                let addr = pending.pop_front().unwrap();
                match self.fault(addr) {
                    Ok(()) => {}
                    Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => pending.push_back(addr),
                    Err(e) => eprintln!("uffd: fault at {addr:#x}: {e}"),
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

    fn discard(&self, start: u64, end: u64) {
        if self.gran() > 1 {
            return self.discard_chunks(start, end);
        }
        let mut a = start & !(PAGE_SIZE as u64 - 1);
        while a < end {
            if let Some((p, _)) = self.page_of(a) {
                if self.pages()[p].swap(ZERO, Ordering::SeqCst) == REMOTE {
                    self.pulled(1);
                }
            }
            a += PAGE_SIZE as u64;
        }
    }

    fn fault(&self, addr: u64) -> io::Result<()> {
        let Some((page, m)) = self.page_of(addr) else {
            return Err(io::Error::other("fault outside guest memory"));
        };
        if self.gran() > 1 {
            return self.fault_chunk(page / self.gran());
        }
        let region_end = (m.offset as usize + m.size) / PAGE_SIZE;
        let pages = self.pages();
        match pages[page].load(Ordering::SeqCst) {
            PRESENT => self.wake(page, 1),
            // Someone else is fetching it; retry until it lands (their copy wakes us).
            INFLIGHT => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
            REMOTE => {
                let mut n = 0;
                while n < REMOTE_FAULT_RUN
                    && page + n < region_end
                    && pages[page + n]
                        .compare_exchange(REMOTE, INFLIGHT, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                {
                    n += 1;
                }
                if n == 0 {
                    return Ok(());
                }
                let mut buf = vec![0u8; n * PAGE_SIZE];
                let mut client = self.remote.lock().unwrap();
                let res = client
                    .as_mut()
                    .ok_or_else(|| io::Error::other("no migration source"))
                    .and_then(|c| c.fetch((page * PAGE_SIZE) as u64, &mut buf));
                drop(client);
                if let Err(e) = res {
                    for p in &pages[page..page + n] {
                        p.store(REMOTE, Ordering::SeqCst);
                    }
                    return Err(e);
                }
                self.install(page, n, Some(&buf))?;
                self.pulled(n);
                Ok(())
            }
            state => {
                // BASE or ZERO: serve a run of neighbours with the same source.
                let from_template = state == BASE && self.base.has_data(page);
                let mut n = 1;
                while n < FAULT_AROUND && page + n < region_end {
                    let s = pages[page + n].load(Ordering::SeqCst);
                    let same = match s {
                        BASE => self.base.has_data(page + n) == from_template,
                        ZERO => !from_template,
                        _ => false,
                    };
                    if !same {
                        break;
                    }
                    n += 1;
                }
                if from_template {
                    self.install(page, n, Some(self.base.pages(page, n)))
                } else {
                    self.install(page, n, None)
                }
            }
        }
    }

    /// Populates `n` pages starting at `page`, from `src` or with zeroes, and
    /// marks them PRESENT. Pages that are already populated are skipped.
    fn install(&self, page: usize, n: usize, src: Option<&[u8]>) -> io::Result<()> {
        let res = self.populate(page, n, src);
        let res = match res {
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                // Part of the run was already there; go page by page.
                let mut r = Ok(());
                for i in 0..n {
                    match self.populate(page + i, 1, src.map(|s| &s[i * PAGE_SIZE..(i + 1) * PAGE_SIZE])) {
                        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
                        Err(e) => r = Err(e),
                        Ok(()) => {}
                    }
                }
                r
            }
            r => r,
        };
        if res.is_ok() {
            for p in &self.pages()[page..page + n] {
                p.store(PRESENT, Ordering::SeqCst);
            }
        }
        res
    }

    fn populate(&self, page: usize, n: usize, src: Option<&[u8]>) -> io::Result<()> {
        let (dst, _) = self.host_addr(page).ok_or_else(|| io::Error::other("bad page"))?;
        let len = (n * PAGE_SIZE) as u64;
        let rc = match src {
            Some(src) => {
                let mut c = UffdioCopy { dst, src: src.as_ptr() as u64, len, mode: 0, copy: 0 };
                unsafe { libc::ioctl(self.fd(), UFFDIO_COPY, &mut c) }
            }
            None => {
                let mut z = UffdioZeropage { range: UffdioRange { start: dst, len }, mode: 0, zeropage: 0 };
                unsafe { libc::ioctl(self.fd(), UFFDIO_ZEROPAGE, &mut z) }
            }
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
        let (addr, vm) = {
            let g = self.remote.lock().unwrap();
            let c = g.as_ref().unwrap();
            (c.addr.clone(), c.vm.clone())
        };
        for t in 0..PULL_THREADS {
            let p = self.clone();
            let (addr, vm) = (addr.clone(), vm.clone());
            thread::spawn(move || {
                if let Err(e) = p.pull(t, &addr, &vm) {
                    eprintln!("uffd: background pull {t} failed: {e}");
                }
            });
        }
    }

    fn pull(&self, stripe: usize, addr: &str, vm: &str) -> io::Result<()> {
        let mut client = PageClient::connect(addr, vm)?;
        if self.gran() > 1 {
            return self.pull_chunks(stripe, &mut client);
        }
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
                    if pages[i].compare_exchange(REMOTE, INFLIGHT, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                        i += 1;
                        continue;
                    }
                    let mut n = 1;
                    while i + n < chunk_end
                        && pages[i + n]
                            .compare_exchange(REMOTE, INFLIGHT, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                    {
                        n += 1;
                    }
                    let b = &mut buf[..n * PAGE_SIZE];
                    if let Err(e) = client.fetch((i * PAGE_SIZE) as u64, b) {
                        for p in &pages[i..i + n] {
                            p.store(REMOTE, Ordering::SeqCst);
                        }
                        return Err(e);
                    }
                    loop {
                        match self.install(i, n, Some(b)) {
                            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                                thread::sleep(Duration::from_micros(200))
                            }
                            r => break r?,
                        }
                    }
                    self.pulled(n);
                    i += n;
                }
                chunk += PULL_THREADS * PULL_RUN;
            }
        }
        Ok(())
    }
}

/// Huge pages: guest memory is installed a whole host page (chunk) at a
/// time, so a chunk is filled from all of its pages' sources at once.
impl Pager {
    fn gran(&self) -> usize {
        self.gran.get().copied().unwrap_or(1)
    }

    fn chunks(&self) -> &[AtomicU8] {
        self.chunks.get().map(|c| c.as_slice()).unwrap_or(&[])
    }

    /// Claims an empty chunk for filling; returns the state it was in.
    fn claim(&self, chunk: usize) -> u8 {
        match self.chunks()[chunk].compare_exchange(CHUNK_EMPTY, CHUNK_INFLIGHT, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(s) | Err(s) => s,
        }
    }

    fn fault_chunk(&self, chunk: usize) -> io::Result<()> {
        match self.claim(chunk) {
            CHUNK_EMPTY => self.fill(chunk, None),
            CHUNK_PRESENT => self.wake(chunk * self.gran(), self.gran()),
            _ => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
        }
    }

    /// Fills a claimed chunk from the template, zeroes and the migration
    /// source (`client`, or the shared fault client) with one UFFDIO_COPY.
    fn fill(&self, chunk: usize, client: Option<&mut PageClient>) -> io::Result<()> {
        thread_local! {
            static BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
        }
        let gran = self.gran();
        let pages = self.pages();
        let first = chunk * gran;
        let n = gran.min(pages.len() - first);
        let res = BUF.with(|buf| -> io::Result<usize> {
            let mut buf = buf.borrow_mut();
            buf.resize(n * PAGE_SIZE, 0);
            let mut client = client;
            let mut remote = 0;
            let mut i = 0;
            while i < n {
                let s = pages[first + i].load(Ordering::SeqCst);
                let data = s == BASE && self.base.has_data(first + i);
                let mut j = i + 1;
                while j < n && {
                    let t = pages[first + j].load(Ordering::SeqCst);
                    if s == REMOTE { t == REMOTE } else { t != REMOTE && (t == BASE && self.base.has_data(first + j)) == data }
                } {
                    j += 1;
                }
                let dst = &mut buf[i * PAGE_SIZE..j * PAGE_SIZE];
                if s == REMOTE {
                    let off = ((first + i) * PAGE_SIZE) as u64;
                    match client.as_deref_mut() {
                        Some(c) => c.fetch(off, dst)?,
                        None => {
                            let mut g = self.remote.lock().unwrap();
                            g.as_mut().ok_or_else(|| io::Error::other("no migration source"))?.fetch(off, dst)?
                        }
                    }
                    remote += j - i;
                } else if data {
                    dst.copy_from_slice(self.base.pages(first + i, j - i));
                } else {
                    dst.fill(0);
                }
                i = j;
            }
            match self.populate(first, n, Some(&buf)) {
                Err(e) if e.raw_os_error() != Some(libc::EEXIST) => Err(e),
                _ => Ok(remote),
            }
        });
        match res {
            Ok(remote) => {
                for p in &pages[first..first + n] {
                    p.store(PRESENT, Ordering::SeqCst);
                }
                self.chunks()[chunk].store(CHUNK_PRESENT, Ordering::SeqCst);
                if remote > 0 {
                    self.pulled(remote);
                }
                Ok(())
            }
            Err(e) => {
                self.chunks()[chunk].store(CHUNK_EMPTY, Ordering::SeqCst);
                Err(e)
            }
        }
    }

    /// Fills every chunk the working set touches, on a few threads.
    fn prefetch_chunks(&self) {
        let gran = self.gran();
        let mut want: Vec<usize> = Vec::new();
        for &(first, count) in &self.base.working_set {
            for c in first as usize / gran..=(first + count - 1) as usize / gran {
                if want.last() != Some(&c) {
                    want.push(c);
                }
            }
        }
        want.dedup();
        let next = AtomicUsize::new(0);
        thread::scope(|s| {
            for _ in 0..PREFETCH_THREADS {
                s.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(&c) = want.get(i) else { return };
                    if c < self.chunks().len() && self.claim(c) == CHUNK_EMPTY {
                        let _ = self.fill(c, None);
                    }
                });
            }
        });
    }

    /// Only whole huge pages can be discarded.
    fn discard_chunks(&self, start: u64, end: u64) {
        let gran = self.gran();
        let huge = (gran * PAGE_SIZE) as u64;
        let mut a = start.next_multiple_of(huge);
        while a + huge <= end {
            if let Some((p, _)) = self.page_of(a) {
                let c = p / gran;
                for q in &self.pages()[c * gran..(c + 1) * gran] {
                    if q.swap(ZERO, Ordering::SeqCst) == REMOTE {
                        self.pulled(1);
                    }
                }
                self.chunks()[c].store(CHUNK_EMPTY, Ordering::SeqCst);
            }
            a += huge;
        }
    }

    fn pull_chunks(&self, stripe: usize, client: &mut PageClient) -> io::Result<()> {
        let gran = self.gran();
        let pages = self.pages();
        while self.remote_left() > 0 && !self.stop.load(Ordering::SeqCst) {
            for c in (stripe..self.chunks().len()).step_by(PULL_THREADS) {
                if self.stop.load(Ordering::SeqCst) {
                    break;
                }
                let end = ((c + 1) * gran).min(pages.len());
                if !pages[c * gran..end].iter().any(|p| p.load(Ordering::Relaxed) == REMOTE) {
                    continue;
                }
                while self.claim(c) == CHUNK_EMPTY {
                    match self.fill(c, Some(client)) {
                        Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => thread::sleep(Duration::from_micros(200)),
                        r => {
                            r?;
                            break;
                        }
                    }
                }
            }
            if self.remote_left() > 0 {
                thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }
}

/// Client for a migration source's page server.
pub struct PageClient {
    addr: String,
    vm: String,
    stream: TcpStream,
}

impl PageClient {
    pub fn connect(addr: &str, vm: &str) -> io::Result<Self> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        let mut hello = serde_json::to_vec(&serde_json::json!({"op": "pages", "name": vm}))?;
        hello.push(b'\n');
        stream.write_all(&hello)?;
        Ok(PageClient { addr: addr.into(), vm: vm.into(), stream })
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

/// Serves page reads for `pager` on an accepted page-server connection.
pub fn serve_pages(pager: &Pager, mut stream: impl Read + Write) -> io::Result<()> {
    let mut req = [0u8; 12];
    let mut buf = Vec::new();
    loop {
        if stream.read_exact(&mut req).is_err() {
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
