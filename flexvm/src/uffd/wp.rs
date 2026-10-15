use super::event::{Served, WP};
use super::hot::Held;
use super::pages::set_bits;
use super::{Mapping, Pager, Runs, ALL, ARM_CHUNK, BASE, PREFETCH_RUN, PRESENT};
use crate::bail;
use crate::cow::{Cow, PENDING, READING, RESCUING};
use crate::util::{Result, PAGE_SIZE};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Threads copying unsaved pages into memory while a discard is held back.
const SAVE_REST_THREADS: usize = 8;

/// Merge protect ranges across gaps up to this many pages: a write-protect fault unprotects aligned blocks of up to a
/// chunk (see `WP_SIZES`), so this keeps a chunk written all over to a call or two (about 6-9 µs a call here).
const PROTECT_GAP: usize = 64;

/// Past this many protect ranges in a region, they are merged across gaps 4 times as wide until they fit: 4096 calls
/// cost 25-37 ms of pause, more than protecting a whole populated GiB in one call (3-23 ms here, #281), and a GiB merged
/// at `PROTECT_GAP` stays below it. So only a larger region written in pages scattered all over pays the refaults that
/// merging causes, and its pause stays bounded. Not across kept hot pages, though: a region ends with up to one more
/// range than it has runs of kept pages, if that is more (hot pages need not be consecutive, so up to one more than
/// `FLEXVM_HOT_MIB` holds pages: 16,385 at its default).
pub(super) const PROTECT_MAX: usize = 4096;

/// Pages a write-protect fault unprotects (and saves first, during a copy), at the least.
const WP_BLOCK: usize = 16;
/// Writes cluster: a guest that writes a page of a 2 MiB chunk tends to write much of it soon, and again after the next
/// pause. Each write-protect fault in a chunk unprotects 4 times as many pages as the one before it there since the
/// last pause (16, 64, 256, then all 512), so a chunk written all over faults 4 times rather than 32, while a page
/// written alone still unprotects (and marks dirty) 16. A chunk's first fault starts from half as many pages as it had
/// dirty in the interval before (so one written all over faults twice; one written less since shrinks back). Each
/// fault costs the guest far more than unprotecting more pages: every unprotect makes KVM drop its mappings of the
/// range and flush the vCPUs' TLBs, about 30-40 µs a call here, against well under 0.1 µs a page.
const WP_CHUNK: usize = 512;
const WP_SIZES: [usize; 4] = [WP_BLOCK, 4 * WP_BLOCK, 16 * WP_BLOCK, WP_CHUNK];
/// Pages of its block a fault saves itself during a copy, at most: every other fault waits meanwhile. The rest of the
/// block stays protected until a writer (or a later fault) saves it.
const WP_SAVE: usize = 4 * WP_BLOCK;
/// Pagemap bits: the page is present, swapped out, write-protected by userfaultfd.
const PM_PRESENT: u64 = 1 << 63;
const PM_SWAP: u64 = 1 << 62;
const PM_UFFD_WP: u64 = 1 << 57;
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
    /// The hot pages copied during the pause (see `hot`), how many of them stay unprotected, how many were unchanged
    /// since the last checkpoint, and how long that took.
    pub held: Option<Arc<Held>>,
    pub hot: usize,
    pub hot_time: Duration,
    pub hot_unchanged: usize,
    /// The last checkpoint's hot pages, whose memory the next one takes once this one ends (`Pager::recycle`).
    prev: Mutex<Option<Arc<Held>>>,
}

impl Pager {
    /// A write to a write-protected page. During a checkpoint copy, saves the pages around it (`WP_SAVE`) that the
    /// copy has not saved yet; then unprotects the pages of its block (`wp_block`) around it that need not stay
    /// protected for the copy, and marks them dirty. Unless it must wait for a writer to save the page first
    /// (`Served::Writer`).
    pub(super) fn wp_fault(&self, page: usize, m: &Mapping, first: bool) -> io::Result<Served> {
        let cow = self.cow();
        // On its `first` try only: a fault is retried after errors, and on every pass of the event loop while it waits.
        cow.iter().for_each(|c| _ = c.stats.faults.fetch_add(first as u64, Ordering::Relaxed));
        // Already unprotected: by the fault of another thread (each one that writes it queues one, and the first
        // unprotect wakes them all), or one on a page of the same block. Its thread may still wait, if it faulted after
        // that unprotect woke the others but before the page table changed: wake it, which costs nothing like an
        // unprotect (which makes KVM drop its mappings of the range and flush the vCPUs' TLBs). Only an optimization:
        // a failure to read the pagemap leaves it to the unprotect.
        if self.pagemap(page, 1).is_ok_and(|e| e[0] & PM_PRESENT != 0 && e[0] & PM_UFFD_WP == 0) {
            return self.wake(page).map(|()| Served::Done(WP));
        }
        if let Some(cow) = cow.as_ref().filter(|c| c.state(page) == READING) {
            cow.wait_for(page, READING);
            return Ok(Served::Writer(cow.clone()));
        }
        // Over budget, nothing more is copied here, and only the least block is unprotected.
        let over = cow.as_ref().is_some_and(|c| c.over_budget());
        let (first, end) = self.wp_block(page, m, !over);
        if let Some(cow) = &cow {
            // Test fault `ckpt_wp_race`: a writer claims the faulting page right here (#88).
            self.wp_race(cow, page, &[PENDING]);
            // Over budget, nothing more is copied here: unsaved pages of the block stay protected, and the writers take
            // them first.
            if over {
                let unsaved: Vec<usize> = (first..end).filter(|&p| cow.state(p) == PENDING).collect();
                unsaved.iter().for_each(|&p| cow.want(p));
                if unsaved.contains(&page) {
                    cow.wait_for(page, PENDING);
                    return Ok(Served::Writer(cow.clone()));
                }
            }
            let start = Instant::now();
            let save = first + (page - first) / WP_SAVE * WP_SAVE;
            let rescued = if over { 0 } else { self.rescue(cow, save, (save + WP_SAVE).min(end))? };
            if rescued > 0 {
                let ns = start.elapsed().as_nanos() as u64;
                let s = &cow.stats;
                s.rescues.fetch_add(1, Ordering::Relaxed);
                s.rescued_pages.fetch_add(rescued as u64, Ordering::Relaxed);
                s.rescue_ns.fetch_add(ns, Ordering::Relaxed);
                s.rescue_max_ns.fetch_max(ns, Ordering::Relaxed);
            }
        }
        // Unprotect what may change now: the run of pages around the faulting one that need not stay protected for the
        // copy (saved, here or before), within its block, but for pages at its ends already unprotected since the last
        // pause (a range costs by its size as well as by the call). One call: more would cost more than the faults
        // they spare.
        let keep = |p: usize| cow.as_ref().is_some_and(|c| matches!(c.state(p), PENDING | READING | RESCUING));
        let Some(cow) = cow.as_ref().filter(|_| keep(page)) else {
            let (mut p, mut q) = (page, page + 1);
            while p > first && !keep(p - 1) {
                p -= 1;
            }
            while q < end && !keep(q) {
                q += 1;
            }
            while p < page && self.pages().is_dirty(p) {
                p += 1;
            }
            while q - 1 > page && self.pages().is_dirty(q - 1) {
                q -= 1;
            }
            (p..q).for_each(|d| self.pages().mark_dirty(d));
            self.writeprotect(p, q - p, false)?;
            return Ok(Served::Done(WP));
        };
        // A writer claimed the faulting page itself (PENDING -> READING) after the check above, so it stayed protected,
        // and nothing else wakes the fault (writers never unprotect, even once they are done with it): retry it once the
        // writer is done, and unprotect it then. (Only with a copy: nothing is kept protected without one.)
        // Test fault `ckpt_wp_race`: the writer that claimed the page is done with it before the fault is settled.
        self.wp_race(cow, page, &[PENDING, READING, RESCUING]);
        cow.wait_for(page, cow.state(page));
        Ok(Served::Writer(cow.clone()))
    }

    /// Test fault `ckpt_wp_race`, once the writers run (before, nothing can claim a page, and the faults of the resume
    /// would only stall): has them take `page` next if pending, and waits up to 50 ms while it is in one of `states`.
    fn wp_race(&self, cow: &Cow, page: usize, states: &[u8]) {
        if !self.wp_race.load(Ordering::Relaxed) || !cow.writing() {
            return;
        }
        if cow.state(page) == PENDING {
            cow.want(page);
        }
        let t = Instant::now();
        while states.contains(&cow.state(page)) && t.elapsed() < Duration::from_millis(50) {
            thread::sleep(Duration::from_micros(100));
        }
    }

    /// The pages a write fault on `page` unprotects: an aligned block of its 2 MiB chunk within its region, the larger
    /// the more of the chunk is dirty since the last pause (see `WP_CHUNK`), unless not to `grow`.
    fn wp_block(&self, page: usize, m: &Mapping, grow: bool) -> (usize, usize) {
        let (from, to) = m.span();
        let at = page - from;
        let size = match grow {
            true => {
                let chunk = from + at - at % WP_CHUNK;
                let (dirty, before) = (&self.pages().dirty, self.hot_dirty.lock().unwrap());
                // Hot pages kept unprotected are dirty from the pause on whether written or not.
                let kept = self.hot_kept.lock().unwrap();
                // Its pages dirty now and in the interval before the last pause. Regions are whole MiB: whole words.
                let (mut n, mut was) = (0, 0);
                for w in chunk / 64..(chunk + WP_CHUNK).min(to) / 64 {
                    let k = kept.get(w).copied().unwrap_or(0);
                    n += (dirty.get(w).map_or(0, |d| d.load(Ordering::Relaxed)) & !k).count_ones() as usize;
                    was += (before.get(w).copied().unwrap_or(0) & !k).count_ones() as usize;
                }
                let start = WP_SIZES.into_iter().rev().find(|&s| s <= was / 2).unwrap_or(WP_BLOCK);
                WP_SIZES.into_iter().find(|&s| s > 2 * n).unwrap_or(WP_CHUNK).max(start)
            }
            false => WP_BLOCK,
        };
        let first = from + at - at % size;
        (first, (first + size).min(to))
    }

    /// Saves the pages of `first..end` (within one region) that the copy has yet to save out of the guest into `cow`.
    /// Returns how many. Never reads a page that may be missing, which would fault back to the event thread: only pages
    /// the pagemap shows populated are read (a missing one was missing, so zero, at the pause).
    fn rescue(&self, cow: &Cow, first: usize, end: usize) -> io::Result<usize> {
        let claimed: Vec<usize> = (first..end).filter(|&p| cow.claim(p, PENDING, RESCUING)).collect();
        if claimed.is_empty() {
            return Ok(0);
        }
        let mut pages: Vec<Box<[u8]>> = claimed.iter().map(|_| vec![0u8; PAGE_SIZE].into_boxed_slice()).collect();
        let read = self.pagemap(first, end - first).and_then(|map| {
            // Runs of claimed populated pages, each read with one call into the pages' own buffers.
            let mut i = 0;
            while i < claimed.len() {
                if map[claimed[i] - first] & (PM_PRESENT | PM_SWAP) == 0 {
                    i += 1;
                    continue;
                }
                let mut j = i + 1;
                while j < claimed.len() && j - i < 1024 && claimed[j] == claimed[j - 1] + 1 && map[claimed[j] - first] & (PM_PRESENT | PM_SWAP) != 0 {
                    j += 1;
                }
                self.read_pages(claimed[i], &mut pages[i..j])?;
                i = j;
            }
            Ok(())
        });
        if let Err(e) = read {
            claimed.iter().for_each(|&p| cow.unclaim(p));
            return Err(e);
        }
        for (&p, bytes) in claimed.iter().zip(pages) {
            cow.rescue(p, bytes);
        }
        Ok(claimed.len())
    }

    /// Reads consecutive guest pages from `page` out of Firecracker, a page into each buffer of `pages`.
    fn read_pages(&self, page: usize, pages: &mut [Box<[u8]>]) -> io::Result<()> {
        let local: Vec<libc::iovec> = pages.iter_mut().map(|b| libc::iovec { iov_base: b.as_mut_ptr().cast(), iov_len: PAGE_SIZE }).collect();
        self.read_at((page * PAGE_SIZE) as u64, &local)
    }

    /// The pagemap entries of `n` pages from `page` in Firecracker (`PM_*` bits).
    fn pagemap(&self, page: usize, n: usize) -> io::Result<Vec<u64>> {
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
        Ok(raw.chunks(8).map(|e| u64::from_le_bytes(e.try_into().unwrap())).collect())
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
        let threads = crate::util::host_cpus().min(SAVE_REST_THREADS);
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

    /// Whether a REMOVE event is queued while the copy has pages to save (the kernel then fails our ioctls with EAGAIN
    /// until it is read). Probes with an empty range: the kernel looks for a queued event before it looks at the range
    /// (which it then refuses, EINVAL), so the probe changes nothing, and costs no more than the call; protecting a page
    /// would make KVM drop its mapping and flush the vCPUs' TLBs.
    pub(super) fn remove_queued(&self, cow: &Cow) -> bool {
        let Some(m) = self.mappings().first().filter(|_| cow.left() > 0) else { return false };
        matches!(self.ioctl(UFFDIO_WRITEPROTECT, &mut [m.base_host_virt_addr, 0, UFFDIO_WRITEPROTECT_MODE_WP]), Err(e) if e.raw_os_error() == Some(libc::EAGAIN))
    }

    /// Turns write tracking on, while the VM runs: registers guest memory for write-protect faults (once) and protects
    /// all of it, so the pause of the checkpoint that follows only re-protects what changed meanwhile.
    pub fn arm_tracking(&self) -> Result<Duration> {
        let start = Instant::now();
        if self.tracking() {
            return Ok(Duration::ZERO);
        }
        if !self.registered_wp.load(Ordering::SeqCst) {
            // No collapse in flight while memory becomes write-protectable, and none after: the pass looks at
            // `registered_wp` under this gate before each call.
            let _collapse = self.collapse_barrier();
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
        // No delta base now, nor hot pages.
        *self.hot_prev.lock().unwrap() = None;
        self.hot_dirty.lock().unwrap().clear();
        self.hot_kept.lock().unwrap().clear();
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
        // Hot pages (see `hot`), copied first, outside the fault lock.
        let start = Instant::now();
        let mut hot = if cow && self.tracking() { self.copy_hot() } else { None };
        let hot_time = start.elapsed();
        let _wp = self.wp.lock().unwrap();
        if (cow || incremental) && !self.tracking() {
            bail!("write tracking is off");
        }
        let pages = self.pages();
        // A VM that stays paused for the write (and is then killed) keeps its dirty pages: if the checkpoint fails and
        // it runs on, they still tell what is unprotected. One that runs on starts a new interval.
        let dirty = pages.dirty_bits(cow);
        let ndirty = dirty.iter().map(|w| w.count_ones() as usize).sum();
        // Hot pages stay unprotected unless their block did not change since the last checkpoint.
        let prev = hot.as_mut().and_then(|h| h.prev.take());
        let hot_unchanged = hot.as_ref().map_or(0, |h| h.unchanged.len());
        // Ascending.
        let kept: Vec<usize> = hot.iter().flat_map(|h| h.held.pages().iter().copied().filter(|&p| h.keeps(p))).collect();
        // Only populated ones: a page discarded since must be in a delta, as zero.
        let unchanged = |p: usize| hot.as_ref().is_some_and(|h| h.unchanged(p)) && pages.get(p) == PRESENT;
        let start = Instant::now();
        let mut protected = 0;
        // Everything populated was protected at the last pause (or when tracking began); since then only dirty pages
        // were unprotected.
        for m in self.mappings().iter().filter(|_| cow) {
            let (from, to) = m.span();
            // Range by range, not the whole region: a protect makes KVM drop its mappings of everything in the range
            // (see `WP_CHUNK`), so the guest would refault every page it uses there, clean ones too, after the resume.
            // That costs far more than the calls it spares (#281).
            let dirty_here = set_bits(&dirty).filter(|&p| p >= from && p < to && pages.get(p) == PRESENT && kept.binary_search(&p).is_err());
            protected += self.protect(protect_ranges(dirty_here, &kept), Some(&dirty))?;
        }
        let protect = start.elapsed();
        let out = match incremental {
            false => runs.clone(),
            true => {
                // Pages not dirty keep what the previous checkpoint has, and so do hot pages unchanged since.
                let mut out: Runs = Vec::new();
                for p in set_bits(&dirty).take_while(|&p| p < pages.len()).filter(|&p| !unchanged(p)) {
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
        if cow {
            let mut bits = vec![0u64; dirty.len()];
            kept.iter().for_each(|&p| bits[p / 64] |= 1 << (p % 64));
            *self.hot_kept.lock().unwrap() = bits;
            *self.hot_dirty.lock().unwrap() = dirty.clone();
        }
        let cow = cow.then(|| {
            let c = Cow::new(pages.len(), &out);
            hot.iter().for_each(|h| c.hold(h.held.clone()));
            Arc::new(c)
        });
        // Unprotected, so dirty from the pause on.
        let held = hot.as_ref().map(|h| {
            kept.iter().for_each(|&p| pages.mark_dirty(p));
            (kept.len(), h.held.clone())
        });
        // Faults that wait for the writers are retried as soon as they save pages.
        if let (Some(c), Some(fd)) = (&cow, pages.wake.get().and_then(|fd| fd.try_clone().ok())) {
            c.set_waker(fd);
        }
        *self.cow.lock().unwrap() = cow.clone();
        let taken = if cow.is_some() { dirty } else { Vec::new() };
        let (hot, held) = held.map_or((0, None), |(n, h)| (n, Some(h)));
        Ok(Frozen { runs: out, cow, dirty: ndirty, taken, protected, protect, held, hot, hot_time, hot_unchanged, prev: Mutex::new(prev) })
    }

    /// Undoes `freeze` for a checkpoint that failed: stops its copy and marks dirty again what it took, so the previous
    /// checkpoint is still the base of the next delta. Pages the freeze protected stay protected until written, which
    /// marks them dirty, so nothing is lost either way.
    pub fn unfreeze(&self, frozen: &Frozen) {
        self.end_copy();
        self.recycle(frozen.prev.lock().unwrap().take());
        let _wp = self.wp.lock().unwrap();
        self.pages().restore_dirty(&frozen.taken);
    }

    /// Ends the copy of a checkpoint that was taken: it is the delta base now, so its hot pages are what the next one
    /// compares its own with.
    pub fn commit_copy(&self, frozen: &Frozen) {
        self.end_copy();
        *self.hot_prev.lock().unwrap() = frozen.held.clone();
        self.recycle(frozen.prev.lock().unwrap().take());
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

/// The ranges that protect `pages` (ascending): merged across gaps of up to `PROTECT_GAP` pages, wider ones while there
/// are more than `PROTECT_MAX`, never across a page of `kept` (ascending).
pub(super) fn protect_ranges(pages: impl Iterator<Item = usize>, kept: &[usize]) -> Vec<(usize, usize)> {
    // Whether `(p, q)` joins `last`, extending it: within `gap` pages of it, no kept page between. `k` walks `kept`
    // along with the ranges, so a pass costs as many steps as there are ranges and kept pages.
    let joins = |last: &mut (usize, usize), (p, q): (usize, usize), gap: usize, k: &mut usize| {
        while kept.get(*k).is_some_and(|&x| x < last.1) {
            *k += 1;
        }
        let joins = p <= last.1 + gap && kept.get(*k).is_none_or(|&x| x >= p);
        if joins {
            last.1 = q;
        }
        joins
    };
    let (mut gap, mut k) = (PROTECT_GAP, 0);
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for p in pages {
        if !ranges.last_mut().is_some_and(|l| joins(l, (p, p + 1), gap, &mut k)) {
            ranges.push((p, p + 1));
        }
    }
    let span = ranges.first().zip(ranges.last()).map_or(0, |(f, l)| l.1 - f.0);
    while ranges.len() > PROTECT_MAX && gap < span {
        // In place: ranges only shrink in number.
        (gap, k) = (gap * 4, 0);
        let mut n = 0;
        for i in 0..ranges.len() {
            let r = ranges[i];
            if n == 0 || !joins(&mut ranges[n - 1], r, gap, &mut k) {
                ranges[n] = r;
                n += 1;
            }
        }
        ranges.truncate(n);
    }
    ranges
}
