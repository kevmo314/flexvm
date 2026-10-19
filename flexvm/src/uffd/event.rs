use super::fetch::fatal;
use super::{
    os, Mapping, Pager, BASE, DISCARDED, FAULT_AROUND, FAULT_TIMEOUT, INFLIGHT, PAGE_SIZE, PRESENT, PULL_RUN, REMOTE, REMOTE_FAULT_RUN, UFFDIO_COPY_MODE_WP,
    ZERO, ZEROES,
};
use crate::cow::{Cow, PENDING, READING, RESCUING};
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLockWriteGuard};
use std::time::{Duration, Instant};

/// Pages past a REMOTE fault's run that the pullers take next (32 MiB): the guest tends to read on from where it
/// faulted.
const STEER_AHEAD: usize = 32 * PULL_RUN;
const UFFD_PAGEFAULT_FLAG_WP: u64 = 2;
const UFFD_EVENT_REMOVE: u8 = 0x15;
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;

/// Fault service latency kinds: faults served from the template, zero or a present page; that had their run fetched
/// from the origin; that waited for another installer; write-protect faults. Then not faults: fetching and installing
/// each fault's run, each background pull run, how long a fault's run waited for its fetcher to get to it (its request
/// is out meanwhile), and until its first page went in.
pub(super) const KINDS: [&str; 8] = ["local", "remote", "wait", "wp", "fetch", "pull", "queued", "first"];
pub(super) const LOCAL: usize = 0;
pub(super) const FETCHED: usize = 1;
pub(super) const WAITED: usize = 2;
pub(super) const WP: usize = 3;
pub(super) const FETCH: usize = 4;
pub(super) const PULL: usize = 5;
pub(super) const QUEUED: usize = 6;
pub(super) const FIRST: usize = 7;
/// Histogram buckets per doubling of latency: 1 << SUB_BITS.
const SUB_BITS: u32 = 2;
const BUCKETS: usize = 40 << SUB_BITS;

/// How long faults took to serve, from reading the event to resolving it, per kind: counts, sums and a log-scale
/// histogram (19% resolution).
pub struct FaultStats {
    kinds: [Kind; KINDS.len()],
}

struct Kind {
    sum_ns: AtomicU64,
    max_ns: AtomicU64,
    hist: [AtomicU64; BUCKETS],
}

impl FaultStats {
    pub(super) fn new() -> FaultStats {
        let kind = || Kind { sum_ns: AtomicU64::new(0), max_ns: AtomicU64::new(0), hist: std::array::from_fn(|_| AtomicU64::new(0)) };
        FaultStats { kinds: std::array::from_fn(|_| kind()) }
    }

    pub(super) fn record(&self, kind: usize, took: Duration) {
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

/// The histogram bucket of `ns`: four per power of two (anything under 4 ns counts as 4).
pub(super) fn bucket(ns: u64) -> usize {
    let ns = ns.max(1 << SUB_BITS);
    let log = 63 - ns.leading_zeros();
    let frac = (ns >> (log - SUB_BITS)) & ((1 << SUB_BITS) - 1);
    (((log as usize) << SUB_BITS) + frac as usize).min(BUCKETS - 1)
}

/// The smallest latency in bucket `i`, in nanoseconds.
pub(super) fn bucket_floor(i: usize) -> u64 {
    let (log, frac) = (i as u32 >> SUB_BITS, (i as u64) & ((1 << SUB_BITS) - 1));
    (((1u64 << SUB_BITS) + frac) << log) >> SUB_BITS
}

/// A fault the event thread has yet to resolve.
struct Pending {
    addr: u64,
    flags: u64,
    read: Instant,
    /// Its kind (`KINDS`), when known before it is resolved: it waited for another installer, or had its run fetched.
    kind: Option<usize>,
    /// Waiting for claimed pages to settle, which wakes the event thread; otherwise retried every millisecond.
    parked: bool,
    /// Served before, and waited for a writer: a write fault and its wait each count once, however often retried.
    tried: bool,
    waited: bool,
    /// When it first failed other than with EAGAIN.
    since: Option<Instant>,
}

/// What became of a fault the event thread looked at.
pub(super) enum Served {
    /// Resolved, as this kind (`KINDS`).
    Done(usize),
    /// Its page is claimed by another installer.
    Waiting,
    /// Its run was claimed and handed to a fetcher.
    Fetching,
    /// A write to a page this checkpoint copy has yet to save, which waits for a writer to save it (`Cow::wait_for`).
    Writer(Arc<Cow>),
}

impl Pager {
    pub(super) fn serve(self: Arc<Self>) {
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
            let mut pfd = [libc::pollfd { fd, events: libc::POLLIN, revents: 0 }, libc::pollfd { fd: wake, events: libc::POLLIN, revents: 0 }];
            // Faults waiting for another installer or a checkpoint writer are woken by it; others (EAGAIN, errors) are
            // retried every millisecond. The timeout also bounds a missed wakeup.
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
                // A REMOVE the kernel acts on as soon as it is read must not hit pages a checkpoint copy has yet to
                // save: let it finish.
                if let Some(cow) = self.cow().filter(|c| self.remove_queued(c)) {
                    self.save_rest(&cow);
                    if !cow.drain() {
                        cow.invalidate("a discard was held back while the copy made no progress");
                    }
                }
                let removing = pages.removing();
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                let learning = self.prefetch.lock().unwrap().learning();
                let mut resolved = 0;
                for msg in buf[..n.max(0) as usize].chunks_exact(32) {
                    let a = u64::from_ne_bytes(msg[8..16].try_into().unwrap());
                    let b = u64::from_ne_bytes(msg[16..24].try_into().unwrap());
                    match msg[0] {
                        UFFD_EVENT_PAGEFAULT => {
                            if let Some((page, _)) = self.page_of(b).filter(|_| learning) {
                                self.base.note_load_fault(page as u64);
                            }
                            pending.push_back(Pending {
                                addr: b,
                                flags: a,
                                read: Instant::now(),
                                kind: None,
                                parked: false,
                                tried: false,
                                waited: false,
                                since: None,
                            })
                        }
                        UFFD_EVENT_REMOVE => resolved += self.discard(&removing, a, b),
                        _ => {}
                    }
                }
                drop(removing);
                pages.events_read();
                self.pulled(resolved);
            }
            // Start bounded template reads for the whole batch before the first UFFDIO_COPY can wait on disk.
            // No wp/events/prefetch lock is held here; retries do not issue the hint again, nor do faults in the run
            // just hinted (about 0.6 µs a call with the page cache warm).
            let mut hinted = 0..0;
            for p in pending.iter().filter(|p| !p.tried && p.flags & UFFD_PAGEFAULT_FLAG_WP == 0) {
                if !self.page_of(p.addr).is_some_and(|(page, _)| hinted.contains(&page)) {
                    hinted = self.readahead_template(p.addr);
                }
            }
            // Before the faults look at page states: an installer that settles a page after that sees it set, and wakes
            // this thread.
            pages.waiting.store(!pending.is_empty(), Ordering::SeqCst);
            // Faults that hit EAGAIN are retried once the events ahead of them are drained; other errors (say ENOMEM)
            // for a while: a dropped fault would block its vCPU forever.
            for _ in 0..pending.len() {
                let mut p = pending.pop_front().unwrap();
                let page = self.page_of(p.addr).map(|(page, _)| page);
                let served = self.fault(p.addr, p.flags, p.kind.is_some(), !p.tried);
                p.tried = true;
                match served {
                    Ok(Served::Done(kind)) => {
                        // A fault that waited was resolved by the copy that woke its thread.
                        let woke = page.filter(|_| p.kind.is_some()).and_then(|page| pages.unpark(page, p.read));
                        let kind = if kind == WP { WP } else { p.kind.unwrap_or(kind) };
                        self.fault_stats.record(kind, woke.unwrap_or_else(Instant::now) - p.read);
                        continue;
                    }
                    // Woken through the copy's waker (`Cow::wait_for`), and retried until a writer saves its page: one wait.
                    Ok(Served::Writer(cow)) => {
                        cow.stats.retries.fetch_add(!p.waited as u64, Ordering::Relaxed);
                        (p.waited, p.parked) = (true, true);
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
                                crate::log!("uffd: fault at {:#x}: {e}; retrying", p.addr);
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

    /// Applies a REMOVE of `[start, end)`, a mapping at a time.
    fn discard(&self, removing: &RwLockWriteGuard<'_, ()>, start: u64, end: u64) -> usize {
        self.discards.fetch_add(1, Ordering::SeqCst);
        let cow = self.cow();
        let (mut a, mut resolved) = (start & !(PAGE_SIZE as u64 - 1), 0);
        while a < end {
            let Some((first, m)) = self.page_of(a) else {
                a += PAGE_SIZE as u64;
                continue;
            };
            let n = ((end.min(m.base_host_virt_addr + m.size as u64) - a) as usize).div_ceil(PAGE_SIZE);
            if let Some((cow, p)) = cow.as_ref().and_then(|c| Some((c, (first..first + n).find(|&p| matches!(c.state(p), PENDING | READING | RESCUING))?))) {
                cow.invalidate(&format!("page {p} was discarded before it was saved"));
            }
            resolved += self.pages().discard(removing, first, first + n);
            a += (n * PAGE_SIZE) as u64;
        }
        resolved
    }

    /// Best-effort, at most 64 KiB per new BASE fault, stopping at holes, other states and the region end.
    /// WILLNEED starts page-cache I/O without touching the mapping or changing guest page states. It can overlap
    /// reads for queued faults and nearby future faults; UFFDIO_COPY still waits if their data is not ready.
    /// Returns the pages hinted.
    fn readahead_template(&self, addr: u64) -> std::ops::Range<usize> {
        let Some((page, m)) = self.page_of(addr) else { return 0..0 };
        let n = self.pages().base_run(page, FAULT_AROUND.min(m.span().1 - page), |p| self.base.has_data(p));
        self.base.willneed(page, n);
        page..page + n
    }

    /// Prepare before wp, without claiming: freeze still sees the old state until the install settles under wp.
    pub(super) fn prepare_fault_template(&self, page: usize, limit: usize) -> usize {
        let around = if self.template_next.load(Ordering::Relaxed) == page { FAULT_AROUND } else { 1 };
        let n = self.pages().base_run(page, around.min(limit), |p| self.base.has_data(p));
        self.base.prefault(page, n);
        n
    }

    /// Serves a fault: REMOTE reads go to fetchers, while BASE copies can wait for template disk I/O.
    fn fault(&self, addr: u64, flags: u64, waiting: bool, first: bool) -> io::Result<Served> {
        let Some((page, m)) = self.page_of(addr) else {
            return Err(io::Error::other("fault outside guest memory"));
        };
        // Runs stay within a 2 MiB chunk: Firecracker keeps unplugged virtio-mem slots PROT_NONE, which splits the
        // region into VMAs at slot boundaries, and a uffd copy across a VMA end fails (ENOENT).
        let chunk = (2 << 20) / PAGE_SIZE;
        let region_left = (m.span().1 - page).min(chunk - (page - m.span().0) % chunk);
        let prepared = if flags & UFFD_PAGEFAULT_FLAG_WP == 0 { self.prepare_fault_template(page, region_left) } else { 0 };
        let _wp = self.wp.lock().unwrap();
        if flags & UFFD_PAGEFAULT_FLAG_WP != 0 {
            return self.wp_fault(page, m, first);
        }
        let pages = self.pages();
        match pages.get(page) {
            // Its install already woke this fault; a REMOVE since then would have made it ZERO.
            PRESENT if waiting => Ok(Served::Done(LOCAL)),
            // Normally a fault that raced the install; if the page is really missing, a REMOVE zapped it after it
            // settled (see `Pages`). Missing at a checkpoint's pause too, so zero then: if the copy has yet to save it,
            // keep it protected until it has.
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
            // Someone else is installing it: their copy wakes the faulting thread, and their settling this thread, to
            // finish the fault.
            INFLIGHT | DISCARDED => Ok(Served::Waiting),
            REMOTE => {
                let n = pages.claim(page, REMOTE_FAULT_RUN.min(region_left), REMOTE, |_| true);
                if n == 0 {
                    return Err(os(libc::EAGAIN));
                }
                self.queue_fault((page, n, Instant::now()));
                // The pullers go on from there.
                *self.steer.lock().unwrap() = (page + n, (page + n + STEER_AHEAD).min(m.span().1));
                Ok(Served::Fetching)
            }
            state => {
                // BASE or ZERO: serve a run of neighbours with the same source.
                let from_template = state == BASE && self.base.has_data(page);
                let same = |p: usize| state == ZERO || self.base.has_data(p) == from_template;
                // Recheck after preparation; only copy template pages whose source was faulted in outside wp.
                let around = if from_template { prepared } else { FAULT_AROUND };
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
}
