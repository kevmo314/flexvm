use super::{os, runs_where, Mapping, Pager, Runs, ALL, ARM_CHUNK, BASE, PREFETCH_RUN, PRESENT};
use crate::bail;
use crate::cow::{Cow, PENDING, READING, RESCUING};
use crate::util::{Result, PAGE_SIZE};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Threads copying unsaved pages into memory while a discard is held back.
const SAVE_REST_THREADS: usize = 8;

/// Up to this many ranges in a region are protected one by one without looking further; past it, see `Pager::freeze`.
const PROTECT_RUNS: usize = 256;

/// Merge protect ranges across gaps up to this many pages: one more protect call costs about as much as the kernel
/// walking this many populated pages (about 19 µs a call, 70-90 ms per GiB populated, here).
const PROTECT_GAP: usize = 64;

/// Pages a write-protect fault unprotects (and saves first, during a copy).
const WP_BLOCK: usize = 16;
const UFFDIO_WRITEPROTECT_MODE_WP: u64 = 1;
const UFFDIO_REGISTER_MODE_WP: u64 = 2;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
const UFFDIO_WRITEPROTECT: libc::c_ulong = 0xC018_AA06;
const UFFDIO_WAKE: libc::c_ulong = 0x8010_AA02;
const UFFDIO_REGISTER: libc::c_ulong = 0xC020_AA00;

/// What `Pager::freeze` captured for a checkpoint.
pub struct Frozen {
    /// Page states for the writer: REMOTE pages are saved from the guest, ZERO pages are discarded, BASE pages
    /// (incremental only) are the template's.
    pub runs: Runs,
    /// Copy-on-write state, when the VM is to run on during the write.
    pub cow: Option<Arc<Cow>>,
    /// Pages dirtied since the previous checkpoint's pause.
    pub dirty: usize,
    /// The dirty bits taken, which a checkpoint that fails gives back (`Pager::unfreeze`).
    taken: Vec<u64>,
    pub protected: usize,
    pub protect: Duration,
}

impl Pager {
    /// A write to a write-protected page. During a checkpoint copy, saves the pages of its block that the copy has not
    /// saved yet; then unprotects the block (except pages still to be saved by a writer) and marks it dirty.
    pub(super) fn wp_fault(&self, page: usize, m: &Mapping) -> io::Result<()> {
        let block = page - page % WP_BLOCK;
        let (first, end) = (block.max(m.span().0), (block + WP_BLOCK).min(m.span().1));
        let cow = self.cow();
        if let Some(cow) = &cow {
            cow.stats.faults.fetch_add(1, Ordering::Relaxed);
            if cow.state(page) == READING {
                cow.stats.retries.fetch_add(1, Ordering::Relaxed);
                return Err(os(libc::EAGAIN));
            }
            // Test fault `ckpt_wp_race`: a writer claims the faulting page right here (#88): have the writers take it
            // next, and wait.
            if self.wp_race.load(Ordering::Relaxed) && cow.state(page) == PENDING {
                cow.want(page);
                let t = Instant::now();
                while cow.state(page) == PENDING && t.elapsed() < Duration::from_millis(50) {
                    thread::sleep(Duration::from_micros(100));
                }
            }
            // Over budget, nothing more is copied here: unsaved pages of the block stay protected, and the writers take
            // them first.
            if cow.over_budget() {
                let unsaved: Vec<usize> = (first..end).filter(|&p| cow.state(p) == PENDING).collect();
                unsaved.iter().for_each(|&p| cow.want(p));
                if unsaved.contains(&page) {
                    cow.stats.retries.fetch_add(1, Ordering::Relaxed);
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
        // Test fault `ckpt_wp_race`: the writer that claimed the page is done with it before the fault is settled.
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
                cow.stats.retries.fetch_add(1, Ordering::Relaxed);
            }
            return Err(os(libc::EAGAIN));
        }
        Ok(())
    }

    /// Saves the pages of `first..end` (within one region) that the copy has yet to save out of the guest into `cow`.
    /// Returns how many. Never reads a page that may be missing, which would fault back to the event thread: only pages
    /// the pagemap shows populated are read (a missing one was missing, so zero, at the pause).
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

    /// While a REMOVE is held back (and with it every fault, as the kernel refuses our ioctls until it is read): copies
    /// the pages the checkpoint has yet to save into memory with several threads, so the guest waits for memory
    /// bandwidth rather than for the disk. Only if they fit in a quarter of the host's available memory; else the
    /// writers finish.
    pub(super) fn save_rest(&self, cow: &Cow) {
        let avail = crate::util::proc_kb("/proc/meminfo", "MemAvailable").unwrap_or(0) as usize;
        if cow.left() * PAGE_SIZE > avail / 4 {
            return;
        }
        let threads = thread::available_parallelism().map_or(1, |n| n.get()).clamp(1, SAVE_REST_THREADS);
        // Only the runs to save (not every page of guest memory: a VM's unplugged virtio-mem region alone is millions),
        // within a region.
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

    /// Whether a REMOVE event is queued (the kernel then fails our ioctls with EAGAIN until it is read). Probes by
    /// protecting a page the copy has yet to save, which is protected already, so changes nothing.
    pub(super) fn remove_queued(&self, cow: &Cow) -> bool {
        let Some(p) = cow.unsaved_page() else { return false };
        matches!(self.writeprotect(p, 1, true), Err(e) if e.raw_os_error() == Some(libc::EAGAIN))
    }

    /// Turns write tracking on, while the VM runs: registers guest memory for write-protect faults (once) and protects
    /// all of it, so the pause of the checkpoint that follows only re-protects what changed meanwhile.
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
        // Dirty from here on; then protect. A page written before its turn to be protected is protected afterwards all
        // the same. Under the fault lock: a fault already marking and unprotecting a block finishes both first, so it
        // never unprotects one whose mark this reset cleared. (Not held while protecting: the serve thread must be free
        // to read events, or a queued REMOVE would fail the calls.)
        {
            let _wp = self.wp.lock().unwrap();
            self.pages().dirty_bits(true);
            self.tracking.store(true, Ordering::SeqCst);
        }
        // In chunks: while the kernel changes a range, KVM retries guest faults anywhere in it, so one call over a
        // whole region would stall the vCPUs for as long as it takes.
        self.protect(self.chunks(ALL, ARM_CHUNK), None)?;
        Ok(start.elapsed())
    }

    /// Write-protects `ranges`, retrying for a while each one a queued REMOVE fails. For a freeze, which took the dirty
    /// bits `taken`, a failure gives them back: every page must stay protected or dirty. Either way it turns tracking
    /// off, so everything is protected again next time. Returns how many ranges it protected.
    fn protect(&self, ranges: impl IntoIterator<Item = (usize, usize)>, taken: Option<&[u64]>) -> Result<usize> {
        let mut n = 0;
        for (first, end) in ranges {
            let start = Instant::now();
            let res = match taken.is_some() && self.fail_protect.swap(false, Ordering::SeqCst) {
                true => Err(io::Error::other("injected fault")),
                false => loop {
                    let gen = self.pages().read_gen.load(Ordering::SeqCst);
                    match self.writeprotect(first, end - first, true) {
                        Err(e) if e.raw_os_error() == Some(libc::EAGAIN) && start.elapsed() < Duration::from_secs(2) => self.pages().wait_events_read(gen),
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

    /// Captures memory for a checkpoint of the paused VM, after `quiesce_export` gave `runs`: takes the pages dirtied
    /// since the last checkpoint's pause (starting a new interval), picks the pages to write (all populated ones, or
    /// with `incremental` only the dirty ones, plus explicit runs for dirty pages now discarded or the template's), and
    /// with `cow` arms copy-on-write for them so the VM can run on: whatever was unprotected since the last pause is
    /// write-protected again first.
    pub fn freeze(&self, runs: &Runs, incremental: bool, cow: bool) -> Result<Frozen> {
        let _wp = self.wp.lock().unwrap();
        if (cow || incremental) && !self.tracking() {
            bail!("write tracking is off");
        }
        let pages = self.pages();
        // A VM that stays paused for the write (and is then killed) keeps its dirty pages: if the checkpoint fails and
        // it runs on, they still tell what is unprotected. One that runs on starts a new interval.
        let dirty = pages.dirty_bits(cow);
        let ndirty = dirty.iter().map(|w| w.count_ones() as usize).sum();
        // Set bits in ascending page order.
        let dirty_pages = || {
            dirty.iter().enumerate().flat_map(|(w, &bits)| {
                std::iter::successors((bits != 0).then_some(bits), |b| Some(b & (b - 1)).filter(|&b| b != 0)).map(move |b| w * 64 + b.trailing_zeros() as usize)
            })
        };
        let start = Instant::now();
        let mut protected = 0;
        // Everything populated was protected at the last pause (or when tracking began); since then only dirty pages
        // were unprotected.
        for m in self.mappings().iter().filter(|_| cow) {
            let (from, to) = m.span();
            let mut ranges: Vec<(usize, usize)> = Vec::new();
            for p in dirty_pages().filter(|&p| p >= from && p < to && pages.get(p) == PRESENT) {
                match ranges.last_mut() {
                    Some((_, e)) if p <= *e + PROTECT_GAP => *e = p + 1,
                    _ => ranges.push((p, p + 1)),
                }
            }
            // Range by range, so that the pause grows with what was written rather than with what is populated; unless
            // the calls would cost more than walking every populated page of the region once (the writes covered most
            // of it).
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

    /// Undoes `freeze` for a checkpoint that failed: stops its copy and marks dirty again what it took, so the previous
    /// checkpoint is still the base of the next delta. Pages the freeze protected stay protected until written, which
    /// marks them dirty, so nothing is lost either way.
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
}

impl Pager {
    /// Write-protects (or unprotects, waking writers waiting on them) `n` pages from `page`.
    pub(super) fn writeprotect(&self, page: usize, n: usize, protect: bool) -> io::Result<()> {
        // struct uffdio_writeprotect: range, mode.
        let mode = if protect { UFFDIO_WRITEPROTECT_MODE_WP } else { 0 };
        self.ioctl(UFFDIO_WRITEPROTECT, &mut [self.addr(page)?, (n * PAGE_SIZE) as u64, mode])
    }

    pub(super) fn wake(&self, page: usize) -> io::Result<()> {
        self.ioctl(UFFDIO_WAKE, &mut [self.addr(page)?, PAGE_SIZE as u64])
    }
}
