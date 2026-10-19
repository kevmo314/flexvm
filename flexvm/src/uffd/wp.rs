use super::event::{Served, WP};
use super::hot::Held;
use super::pages::DirtyBits;
use super::{Mapping, Pager, Runs, ALL, ARM_CHUNK, BASE, PREFETCH_RUN, PRESENT};
use crate::bail;
use crate::cow::{Cow, Slot, PENDING, READING, RESCUING};
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
/// `HOT_MIB` holds pages: 16,385).
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
    taken: Arc<DirtyBits>,
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
    /// Only a failed hot read may restore `prev`, and only to the same delta base.
    prev_generation: Option<u64>,
}

impl Pager {
    /// A write to a write-protected page. During a checkpoint copy, saves the pages of its block (`wp_block`) that the
    /// copy has not saved yet, all of them: a fault costs the guest about 50 µs besides its rescue here (KVM's exit and
    /// refault, waking this thread and the vCPU), and the block is sized by how much of its chunk the guest writes,
    /// against about 1 µs a page to copy. Rescuing 64 pages a fault at most lost a heavy writer twice as much (#630).
    /// Then unprotects the pages of its block (`wp_block`) around it that need not stay
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
        let (mut first, mut end) = self.wp_block(page, m, !over);
        if let Some(cow) = &cow {
            // Test fault `ckpt_wp_race`: a writer claims the faulting page right here (#88).
            self.wp_race(cow, page, &[PENDING]);
            let start = Instant::now();
            let least = || self.wp_block(page, m, false);
            let Some((rescued, block)) = rescue_or_want(cow, page, over, (first, end), least, |f, e| self.rescue(cow, f, e))? else {
                return Ok(Served::Writer(cow.clone()));
            };
            (first, end) = block;
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
        cow.stats.writer_claimed.fetch_add(1, Ordering::Relaxed);
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
                    let k = kept.get(&w).copied().unwrap_or(0);
                    n += (dirty.get(w).map_or(0, |d| d.load(Ordering::Relaxed)) & !k).count_ones() as usize;
                    was += (before.bits.get(w).copied().unwrap_or(0) & !k).count_ones() as usize;
                }
                let start = WP_SIZES.into_iter().rev().find(|&s| s <= was / 2).unwrap_or(WP_BLOCK);
                WP_SIZES.into_iter().find(|&s| s > 2 * n).unwrap_or(WP_CHUNK).max(start)
            }
            false => WP_BLOCK,
        };
        block_at(page, (from, to), size)
    }

    /// Saves the pages of `first..end` (within one region) that the copy has yet to save out of the guest into `cow`.
    /// Returns how many, None if there is no memory for their copies now (`Room`). Never reads a page that may be
    /// missing, which would fault back to the event thread: only pages the pagemap shows populated are read (a missing
    /// one was missing, so zero, at the pause).
    fn rescue(&self, cow: &Cow, first: usize, end: usize) -> io::Result<Option<usize>> {
        let map = |claimed: &[usize]| self.rescue_fail(cow, claimed).and_then(|()| self.pagemap(first, end - first));
        rescue_block(cow, first, end, map, |p, local| self.read_at((p * PAGE_SIZE) as u64, local))
    }

    /// Test fault `ckpt_rescue_fail`, once the writers run: every other rescue fails after its claim, with a writer
    /// asked to take its first page meanwhile, so that the writer finds the page RESCUING and then given back. Until a
    /// writer has (in this copy), the failure waits for one to (up to 200 ms: `ckpt_slow` writers sleep 50 ms before
    /// each unit, which a fixed 5 ms caught only by chance, never on a slow host); then 5 ms.
    fn rescue_fail(&self, cow: &Cow, claimed: &[usize]) -> io::Result<()> {
        if !self.rescue_fail.load(Ordering::Relaxed) || !cow.writing() || self.rescue_tries.fetch_add(1, Ordering::Relaxed) % 2 == 1 {
            return Ok(());
        }
        cow.want(claimed[0]);
        let (start, wait) = (Instant::now(), if cow.rescue_waits() == 0 { 200 } else { 5 });
        while start.elapsed() < Duration::from_millis(wait) && !(wait > 5 && cow.rescue_waits() > 0) {
            thread::sleep(Duration::from_micros(200));
        }
        Err(io::Error::other("injected fault: rescue failed"))
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
                    if let Ok(Some(n)) = self.rescue(cow, first, end) {
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
                self.ioctl(UFFDIO_REGISTER, &mut r).map_err(|e| format!("registering guest memory for write-protect faults: {e}"))?;
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
        {
            let mut prev = self.hot_prev.lock().unwrap();
            prev.0 = prev.0.checked_add(1).unwrap();
            prev.1 = None;
        }
        *self.hot_dirty.lock().unwrap() = Arc::default();
        self.hot_kept.lock().unwrap().clear();
        // In chunks: while the kernel changes a range, KVM retries guest faults anywhere in it, so one call over a
        // whole region would stall the vCPUs for as long as it takes.
        self.protect(self.chunks(ALL, ARM_CHUNK), None)?;
        Ok(start.elapsed())
    }

    /// Write-protects `ranges`, retrying for a while each one a queued REMOVE fails. For a freeze, which took the dirty
    /// bits `taken`, a failure gives them back: every page must stay protected or dirty. Either way it turns tracking
    /// off, so everything is protected again next time. Returns how many ranges it protected.
    fn protect(&self, ranges: impl IntoIterator<Item = (usize, usize)>, taken: Option<&DirtyBits>) -> Result<usize> {
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
                if let Some(taken) = taken {
                    self.pages().restore_dirty(taken);
                }
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
        self.pages().dirty_count()
    }

    /// Captures memory for a checkpoint of the paused VM, after `quiesce_export` gave `runs`: takes the pages dirtied
    /// since the last checkpoint's pause (starting a new interval), picks the pages to write (all populated ones, or
    /// with `incremental` only the dirty ones, plus explicit runs for dirty pages now discarded or the template's), and
    /// with `cow` arms copy-on-write for them so the VM can run on: whatever was unprotected since the last pause is
    /// write-protected again first.
    pub fn freeze(&self, runs: &Runs, incremental: bool, cow: bool) -> Result<Frozen> {
        // Hot pages (see `hot`), copied first, outside the fault lock.
        let start = Instant::now();
        let (mut hot, prev_generation, prev) = match if cow && self.tracking() { self.copy_hot() } else { Ok(None) } {
            Ok(hot) => (hot, None, None),
            Err((generation, prev)) => (None, Some(generation), prev),
        };
        let hot_time = start.elapsed();
        let _wp = self.wp.lock().unwrap();
        if (cow || incremental) && !self.tracking() {
            self.recycle_hot(hot);
            self.recycle(prev);
            bail!("write tracking is off");
        }
        let pages = self.pages();
        // A VM that stays paused for the write (and is then killed) keeps its dirty pages: if the checkpoint fails and
        // it runs on, they still tell what is unprotected. One that runs on starts a new interval.
        let dirty = Arc::new(pages.dirty_bits(cow));
        let ndirty = dirty.count();
        // Hot pages stay unprotected unless their block did not change since the last checkpoint.
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
            let dirty_here = dirty.pages(from, to).filter(|&p| pages.get(p) == PRESENT && kept.binary_search(&p).is_err());
            match self.protect(protect_ranges(dirty_here, &kept), Some(&dirty)) {
                Ok(n) => protected += n,
                Err(e) => {
                    self.recycle_hot(hot);
                    self.recycle(prev);
                    return Err(e);
                }
            }
        }
        let protect = start.elapsed();
        let out = match incremental {
            false => runs.clone(),
            true => {
                // Pages not dirty keep what the previous checkpoint has, and so do hot pages unchanged since.
                let mut out: Runs = Vec::new();
                for p in dirty.pages(0, pages.len()).filter(|&p| !unchanged(p)) {
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
            let mut bits = std::collections::BTreeMap::new();
            kept.iter().for_each(|&p| *bits.entry(p / 64).or_insert(0) |= 1u64 << (p % 64));
            // Only copied pages stay unprotected and are marked dirty again below before resume. The sparse map
            // merely excludes those pages from the fault-growth heuristic; it does not replace dirty tracking.
            *self.hot_kept.lock().unwrap() = bits;
            // Share the immutable snapshot instead of copying it during the pause. Frozen retains the same bits
            // for rollback; writes after the take accumulate separately in Pages::dirty, so none can be lost.
            *self.hot_dirty.lock().unwrap() = dirty.clone();
        }
        let cow = cow.then(|| {
            let c = Cow::new(pages.len(), &out)
                .keep_slots(self.slot_spare.clone(), self.mem_room.clone())
                .count_rescue_waits(self.rescue_fail.load(Ordering::Relaxed));
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
        let taken = if cow.is_some() { dirty } else { Arc::default() };
        let prev = prev.or_else(|| hot.as_mut().and_then(|h| h.prev.take()));
        let (hot, held) = held.map_or((0, None), |(n, h)| (n, Some(h)));
        Ok(Frozen { runs: out, cow, dirty: ndirty, taken, protected, protect, held, hot, hot_time, hot_unchanged, prev: Mutex::new(prev), prev_generation })
    }

    /// Undoes `freeze` for a checkpoint that failed: stops its copy and marks dirty again what it took, so the previous
    /// checkpoint is still the base of the next delta. Pages the freeze protected stay protected until written, which
    /// marks them dirty, so nothing is lost either way. A freeze whose hot read failed gives the last checkpoint's hot
    /// pages back for comparison, unless the delta base changed meanwhile (its generation moved on) or tracking is off.
    pub fn unfreeze(&self, frozen: &Frozen) {
        self.end_copy();
        let _wp = self.wp.lock().unwrap();
        self.pages().restore_dirty(&frozen.taken);
        let mut prev = frozen.prev.lock().unwrap().take();
        {
            let mut base = self.hot_prev.lock().unwrap();
            if self.tracking() && frozen.prev_generation == Some(base.0) && base.1.is_none() {
                base.1 = prev.take();
            }
        }
        self.recycle(prev);
    }

    /// Ends the copy of a checkpoint that was taken: it is the delta base now, so its hot pages are what the next one
    /// compares its own with.
    pub fn commit_copy(&self, frozen: &Frozen) {
        self.end_copy();
        {
            let mut prev = self.hot_prev.lock().unwrap();
            prev.0 = prev.0.checked_add(1).unwrap();
            prev.1 = frozen.held.clone();
        }
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

/// The aligned block of `size` pages of the region `span` holding `page`, cut short at the region's end. Aligned within
/// the region: a region starts at any whole MiB of guest memory.
fn block_at(page: usize, (from, to): (usize, usize), size: usize) -> (usize, usize) {
    let at = page - from;
    let first = from + at - at % size;
    (first, (first + size).min(to))
}

/// For a fault on `page`, rescues its `block` with `rescue` unless `over` budget. Over budget, or without memory for
/// the copies (`rescue` gives None; on the `least` block then), nothing more is copied here: the unsaved pages of the
/// block stay protected, and the writers take them first. None if the fault waits for them (its page is one); else the
/// pages rescued and the block to unprotect around `page`.
fn rescue_or_want(
    cow: &Cow,
    page: usize,
    over: bool,
    block: (usize, usize),
    least: impl FnOnce() -> (usize, usize),
    rescue: impl FnOnce(usize, usize) -> io::Result<Option<usize>>,
) -> io::Result<Option<(usize, (usize, usize))>> {
    let (first, end) = match over {
        true => block,
        false => match rescue(block.0, block.1)? {
            Some(n) => return Ok(Some((n, block))),
            None => least(),
        },
    };
    let unsaved: Vec<usize> = (first..end).filter(|&p| cow.state(p) == PENDING).collect();
    unsaved.iter().for_each(|&p| cow.want(p));
    if unsaved.contains(&page) {
        cow.wait_for(page, PENDING);
        return Ok(None);
    }
    Ok(Some((0, (first, end))))
}

/// `Pager::rescue` of `first..end`, with `map` giving their pagemap entries (once it has claimed the pages it gets),
/// and `read` (see `fill_slots`). None if there is no memory for their copies now.
fn rescue_block(
    cow: &Cow,
    first: usize,
    end: usize,
    map: impl FnOnce(&[usize]) -> io::Result<Vec<u64>>,
    read: impl FnMut(usize, &[libc::iovec]) -> io::Result<()>,
) -> io::Result<Option<usize>> {
    // Only pages no one saved or is saving: a writer may hold some (READING), or have saved them, or they are hot.
    let claimed: Vec<usize> = (first..end).filter(|&p| cow.claim(p, PENDING, RESCUING)).collect();
    if claimed.is_empty() {
        return Ok(Some(0));
    }
    let slots = match cow.take_slots(claimed.len()) {
        Ok(Some(s)) => s,
        // No memory for them now (`Room`): they stay protected for the writers, and the fault asks for them and waits
        // as over budget (`Cow::over_budget` says so too now).
        Ok(None) => {
            cow.unclaim_many(&claimed);
            return Ok(None);
        }
        Err(e) => {
            cow.stats.rescue_failures.fetch_add(1, Ordering::Relaxed);
            cow.unclaim_many(&claimed);
            return Err(e);
        }
    };
    let filled = map(&claimed).and_then(|map| fill_slots(&claimed, &slots, |p| map[p - first] & (PM_PRESENT | PM_SWAP) != 0, read));
    if let Err(e) = filled {
        cow.stats.rescue_failures.fetch_add(1, Ordering::Relaxed);
        cow.give_slots(slots);
        cow.unclaim_many(&claimed);
        return Err(e);
    }
    cow.rescue_many(first, end, claimed.iter().copied().zip(slots));
    Ok(Some(claimed.len()))
}

/// Fills `slots[i]` with the pause-time contents of page `claimed[i]` (ascending): runs of consecutive `present` pages
/// with one `read` each (a page, and where its run goes: slots next to each other in one piece), the others with zeroes
/// (missing at the pause, and the slot may hold an old copy). One thread: reads on more at once took longer here.
fn fill_slots(
    claimed: &[usize],
    slots: &[Slot],
    present: impl Fn(usize) -> bool,
    mut read: impl FnMut(usize, &[libc::iovec]) -> io::Result<()>,
) -> io::Result<()> {
    assert_eq!(claimed.len(), slots.len());
    // One for every run: a run's slots are mostly next to each other, so it rarely grows.
    let mut local: Vec<libc::iovec> = Vec::new();
    let mut i = 0;
    while i < claimed.len() {
        if !present(claimed[i]) {
            unsafe { std::ptr::write_bytes(slots[i].as_mut_ptr(), 0, PAGE_SIZE) };
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < claimed.len() && j - i < 1024 && claimed[j] == claimed[j - 1] + 1 && present(claimed[j]) {
            j += 1;
        }
        local.clear();
        for s in &slots[i..j] {
            match local.last_mut() {
                Some(v) if v.iov_base as usize + v.iov_len == s.as_mut_ptr() as usize => v.iov_len += PAGE_SIZE,
                _ => local.push(libc::iovec { iov_base: s.as_mut_ptr().cast(), iov_len: PAGE_SIZE }),
            }
        }
        read(claimed[i], &local)?;
        i = j;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uffd::pages::{Pages, CHUNK};
    use crate::uffd::{FaultStats, Runtime, ZERO};

    /// Guest memory for rescues: page `p` filled with `p + 1` (mod 256), unless absent.
    fn guest_read(mem: &[u8]) -> impl Fn(usize, &[libc::iovec]) -> io::Result<()> + Sync + '_ {
        move |p, local| {
            let mut at = p * PAGE_SIZE;
            for v in local {
                unsafe { std::ptr::copy_nonoverlapping(mem[at..].as_ptr(), v.iov_base.cast::<u8>(), v.iov_len) };
                at += v.iov_len;
            }
            Ok(())
        }
    }

    /// Page `p` filled with `p + 1` (mod 256).
    fn guest_mem(n: usize) -> Vec<u8> {
        (0..n * PAGE_SIZE).map(|i| ((i / PAGE_SIZE) as u8).wrapping_add(1)).collect()
    }

    #[test]
    fn slots_fill_by_runs_and_zero_absent_pages() {
        let cow = Cow::new(16, &vec![(0, 16, crate::uffd::REMOTE)]);
        let mem = guest_mem(16);
        // Slots used before hold old copies: an absent page's must not show through.
        let old = cow.take_slots(5).unwrap().unwrap();
        old.iter().for_each(|s| unsafe { std::ptr::write_bytes(s.as_mut_ptr(), 0xee, PAGE_SIZE) });
        cow.give_slots(old);
        let slots = cow.take_slots(5).unwrap().unwrap();
        let claimed = [3, 4, 5, 9, 10];
        let reads = Mutex::new(Vec::new());
        let read = guest_read(&mem);
        fill_slots(
            &claimed,
            &slots,
            |p| p != 4,
            |p, local| {
                reads.lock().unwrap().push((p, local.iter().map(|v| v.iov_len / PAGE_SIZE).collect::<Vec<_>>()));
                read(p, local)
            },
        )
        .unwrap();
        let reads = reads.into_inner().unwrap();
        // A call per run of present pages; slots next to each other go as one piece.
        assert_eq!(reads.len(), 3);
        assert_eq!(reads[0].0, 3);
        assert_eq!(reads[1].0, 5);
        assert_eq!((reads[2].0, reads[2].1.iter().sum::<usize>()), (9, 2));
        for (&p, s) in claimed.iter().zip(&slots) {
            let want = if p == 4 { 0 } else { (p as u8).wrapping_add(1) };
            assert!(unsafe { std::slice::from_raw_parts(s.as_mut_ptr(), PAGE_SIZE) }.iter().all(|&b| b == want), "page {p}");
        }
        cow.give_slots(slots);
    }

    #[test]
    fn a_rescue_saves_each_unsaved_page_of_its_block_once() {
        use crate::cow::{CowPages, CLEAN, HELD, RESCUED};
        let n = 64;
        let mut mem = guest_mem(n);
        let cow = Cow::new(n, &vec![(0, 40, crate::uffd::REMOTE), (40, 4, crate::uffd::ZERO)]);
        // Partly saved already: page 1 by a writer, page 2 is hot (copied during the pause), and a writer is reading
        // page 3 right now.
        assert!(cow.claim(1, PENDING, READING));
        assert!(cow.claim(1, READING, CLEAN));
        cow.hold(Arc::new(Held::of(&[(2, 3)])));
        assert!(cow.claim(3, PENDING, READING));
        let left = cow.left();
        // Page 6 was missing at the pause: zero.
        let map = |_: &[usize]| Ok((0..16).map(|i| if i == 6 { 0 } else { PM_PRESENT }).collect());
        assert_eq!(rescue_block(&cow, 0, 16, map, guest_read(&mem)).unwrap(), Some(13));
        assert_eq!(cow.left(), left - 13);
        assert!([0, 4, 5, 6, 15].iter().all(|&p| cow.state(p) == RESCUED));
        assert_eq!((cow.state(1), cow.state(2), cow.state(3)), (CLEAN, HELD, READING));
        // Another fault on the block saves nothing again; the block's end is the next one's start.
        assert_eq!(rescue_block(&cow, 0, 16, |_| panic!("nothing to read"), |_, _| panic!()).unwrap(), Some(0));
        assert_eq!(rescue_block(&cow, 16, 18, |_| Ok(vec![PM_PRESENT; 2]), guest_read(&mem)).unwrap(), Some(2));
        // A failed read gives its pages and slots back.
        let fail = |_: usize, _: &[libc::iovec]| Err(io::Error::other("gone"));
        assert!(rescue_block(&cow, 18, 24, |_| Ok(vec![PM_PRESENT; 6]), fail).is_err());
        assert!((18..24).all(|p| cow.state(p) == PENDING));
        assert_eq!(cow.left(), left - 15);
        // The guest writes on; the writer gets the pause-time contents.
        mem.iter_mut().for_each(|b| *b = 0xaa);
        assert!(cow.claim(3, READING, CLEAN));
        struct Mem(Vec<u8>);
        impl crate::checkpoint::GuestPages for Mem {
            fn region_end(&self, _: usize) -> Option<usize> {
                Some(64)
            }
            fn read(&self, page: usize, buf: &mut [u8]) -> crate::util::Result<()> {
                buf.copy_from_slice(&self.0[page * PAGE_SIZE..page * PAGE_SIZE + buf.len()]);
                Ok(())
            }
        }
        let guest = Mem(guest_mem(n));
        let pages = CowPages { guest: &guest, cow: &cow, slow: || Duration::ZERO };
        // Not pages 1 and 3: the writer saved them before (the claims above stand for it).
        for (a, b) in [(0, 1), (2, 3), (4, 24)] {
            let mut buf = vec![0u8; (b - a) * PAGE_SIZE];
            crate::checkpoint::GuestPages::read(&pages, a, &mut buf).unwrap();
            for (p, page) in (a..b).zip(buf.chunks(PAGE_SIZE)) {
                let want = match p {
                    2 => 3,
                    6 => 0,
                    _ => (p as u8).wrapping_add(1),
                };
                assert!(page.iter().all(|&b| b == want), "page {p}");
            }
        }
        assert!((0..24).all(|p| cow.state(p) == CLEAN));
    }

    #[test]
    fn rescues_racing_the_writer_save_every_page_once() {
        use crate::cow::{CowPages, CLEAN};
        struct Mem(Vec<u8>);
        impl crate::checkpoint::GuestPages for Mem {
            fn region_end(&self, _: usize) -> Option<usize> {
                None
            }
            fn read(&self, page: usize, buf: &mut [u8]) -> crate::util::Result<()> {
                buf.copy_from_slice(&self.0[page * PAGE_SIZE..page * PAGE_SIZE + buf.len()]);
                Ok(())
            }
        }
        let n = 4096;
        let guest = Mem(guest_mem(n));
        for round in 0..4 {
            let cow = Cow::new(n, &vec![(0, n as u64, crate::uffd::REMOTE)]);
            let pages = CowPages { guest: &guest, cow: &cow, slow: || Duration::ZERO };
            let out = Mutex::new(vec![0u8; n * PAGE_SIZE]);
            let rescued = AtomicUsize::new(0);
            // Save one unit before rescuing, then wait for a rescue before reading on: both paths must run.
            crate::checkpoint::GuestPages::read(&pages, 0, &mut out.lock().unwrap()[..32 * PAGE_SIZE]).unwrap();
            thread::scope(|s| {
                s.spawn(|| {
                    // Blocks of all sizes, all over, from the end down: they meet the writer's units at every offset.
                    let mut x = 0x9e37_79b9_u64 + round;
                    for i in 0..400 {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        let size = [4, 16, 64, 512][i % 4];
                        let page = n - 1 - (x as usize % n) / 2 - i * 4 % (n / 2);
                        let first = page - page % size;
                        let map = |_: &[usize]| Ok(vec![PM_PRESENT; size]);
                        rescued.fetch_add(rescue_block(&cow, first, (first + size).min(n), map, guest_read(&guest.0)).unwrap().unwrap(), Ordering::Relaxed);
                    }
                });
                let start = Instant::now();
                while rescued.load(Ordering::Relaxed) == 0 {
                    assert!(start.elapsed() < Duration::from_secs(5), "some pages rescued before reading on");
                    thread::sleep(Duration::from_millis(1));
                }
                for unit in (32..n).step_by(32) {
                    let mut buf = vec![0u8; 32 * PAGE_SIZE];
                    crate::checkpoint::GuestPages::read(&pages, unit, &mut buf).unwrap();
                    out.lock().unwrap()[unit * PAGE_SIZE..(unit + 32) * PAGE_SIZE].copy_from_slice(&buf);
                }
            });
            assert_eq!(cow.left(), 0);
            assert!((0..n).all(|p| cow.state(p) == CLEAN));
            assert!(out.into_inner().unwrap() == guest.0, "every page as at the pause");
            assert!(rescued.into_inner() > 0, "some pages rescued");
            assert_eq!(cow.rescued_mib(), 0.0);
        }
    }

    #[test]
    fn no_room_for_rescue_memory_leaves_pages_to_the_writers() {
        use crate::cow::{CowPages, Room, CLEAN};
        let n = 2048;
        let mem = guest_mem(n);
        let room = Room::default();
        let cow = Cow::new(n, &vec![(0, n as u64, crate::uffd::REMOTE)]).keep_slots(Arc::new(Mutex::new(None)), room.clone());
        // Writing: rescue memory grows only within the room, 2 MiB a chunk.
        struct Mem<'a>(&'a [u8]);
        impl crate::checkpoint::GuestPages for Mem<'_> {
            fn region_end(&self, _: usize) -> Option<usize> {
                None
            }
            fn read(&self, page: usize, buf: &mut [u8]) -> crate::util::Result<()> {
                buf.copy_from_slice(&self.0[page * PAGE_SIZE..page * PAGE_SIZE + buf.len()]);
                Ok(())
            }
        }
        let guest = Mem(&mem);
        let pages = CowPages { guest: &guest, cow: &cow, slow: || Duration::ZERO };
        crate::checkpoint::GuestPages::read(&pages, 0, &mut vec![0u8; PAGE_SIZE]).unwrap();
        room.set(3);
        assert!(!cow.over_budget());
        let present = |c: &[usize]| Ok(vec![PM_PRESENT; c.len().max(512)]);
        assert_eq!(rescue_block(&cow, 512, 1024, present, guest_read(&mem)).unwrap(), Some(512));
        assert_eq!(room.get(), 1, "a chunk taken out of the room");
        // No room for another chunk: the pages stay unsaved (and protected) for the writers; nothing fails.
        assert!(cow.over_budget(), "faults wait for the writers");
        let left = cow.left();
        assert_eq!(rescue_block(&cow, 1024, 1536, present, |_, _| panic!("nothing read")).unwrap(), None, "no room");
        assert_eq!(cow.left(), left);
        assert!((1024..1536).all(|p| cow.state(p) == PENDING));
        // Once the writer takes the copies, their slots serve the next rescue without more room.
        let mut buf = vec![0u8; 512 * PAGE_SIZE];
        crate::checkpoint::GuestPages::read(&pages, 512, &mut buf).unwrap();
        assert!(buf == mem[512 * PAGE_SIZE..1024 * PAGE_SIZE]);
        assert!(!cow.over_budget());
        assert_eq!(rescue_block(&cow, 1024, 1536, present, guest_read(&mem)).unwrap(), Some(512));
        assert_eq!(room.get(), 1);
        crate::checkpoint::GuestPages::read(&pages, 1024, &mut buf).unwrap();
        assert!(buf == mem[1024 * PAGE_SIZE..1536 * PAGE_SIZE]);
        assert!((0..1).chain(512..1536).all(|p| cow.state(p) == CLEAN));
        assert!((1..512).all(|p| cow.state(p) == PENDING));
        // Before the writers start, the faults of the resume rescue past the room, up to `PRE_WRITER_MIB`.
        let early = Cow::new(n, &vec![(0, n as u64, crate::uffd::REMOTE)]).keep_slots(Arc::new(Mutex::new(None)), Room::default());
        let none = Room::default();
        none.set(0);
        let early = early.keep_slots(Arc::new(Mutex::new(None)), none);
        assert!(!early.over_budget());
        assert_eq!(rescue_block(&early, 0, 512, present, guest_read(&mem)).unwrap(), Some(512));
    }

    /// A fault whose rescue finds no memory for its copies (the room went between `over_budget` and the take, as the
    /// host's is shared) asks the writers for the unsaved pages of its least block and waits for them, as over budget:
    /// not for the writers to reach them in order (#648).
    #[test]
    fn a_fault_without_room_for_its_copies_asks_the_writers_for_its_pages() {
        use crate::cow::Room;
        let n = 2048;
        let mem = guest_mem(n);
        let room = Room::default();
        let cow = Cow::new(n, &vec![(0, n as u64, crate::uffd::REMOTE)]).keep_slots(Arc::new(Mutex::new(None)), room.clone());
        cow.start_writing();
        room.set(0);
        let present = |c: &[usize]| Ok(vec![PM_PRESENT; c.len().max(512)]);
        let rescue = |f, e| rescue_block(&cow, f, e, present, |_, _| panic!("nothing read"));
        assert_eq!(rescue_or_want(&cow, 700, false, (512, 1024), || (688, 704), rescue).unwrap(), None, "the fault waits");
        assert_eq!(cow.wanted_pages(), (688..704).collect::<Vec<_>>(), "the least block, asked for");
        assert!((512..1024).all(|p| cow.state(p) == PENDING));
        // Its page saved already: nothing to wait for, the least block unprotected around it.
        cow.claim(720, PENDING, READING);
        let rescue = |f, e| rescue_block(&cow, f, e, present, |_, _| panic!("nothing read"));
        assert_eq!(rescue_or_want(&cow, 720, false, (512, 1024), || (720, 736), rescue).unwrap(), Some((0, (720, 736))));
        // With room, the whole block is rescued and nothing asked for.
        room.set(10);
        let cow = Cow::new(n, &vec![(0, n as u64, crate::uffd::REMOTE)]).keep_slots(Arc::new(Mutex::new(None)), room.clone());
        cow.start_writing();
        let rescue = |f, e| rescue_block(&cow, f, e, present, guest_read(&mem));
        assert_eq!(rescue_or_want(&cow, 700, false, (512, 1024), || panic!("not the least"), rescue).unwrap(), Some((512, (512, 1024))));
        assert!(cow.wanted_pages().is_empty());
    }

    fn test_pager(n: usize) -> (crate::test_util::TempDir, Pager) {
        let dir = crate::test_util::TempDir::new("host-memory");
        std::fs::write(
            dir.join("meta.json"),
            serde_json::to_vec(&serde_json::json!({
                "compatibility": {"cpu": "test", "tsc_khz": 2000000, "tsc_control": false,
                    "msrs": [], "firecracker": "test", "features": {}, "xsave": {}},
                "vcpus": 1, "mem_mib": 1, "max_mib": 64, "plugged_mib": 0,
                "kernel": "/k", "rootfs": "/r", "id": "a", "components": {}
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::File::create(dir.join("mem")).unwrap().set_len(PAGE_SIZE as u64).unwrap();
        let pager = Pager {
            base: crate::template::Template::open_dir("test", dir.to_path_buf()).unwrap(),
            runtime: Runtime {
                pages: Pages::new(n).into(),
                mappings: vec![Mapping { offset: 0, size: n * PAGE_SIZE, base_host_virt_addr: 0 }].into(),
                tracking: true.into(),
                ..Runtime::default()
            },
            fault_stats: FaultStats::new(),
            lanes: Default::default(),
            steer: Mutex::new((0, 0)),
            collapse_report: Mutex::new(None),
            collapse_gate: Default::default(),
        };
        (dir, pager)
    }

    #[test]
    fn template_readahead_stays_within_the_mapping() {
        // The template maps one page: hints past its end are clamped, not a panic or a stray madvise.
        let (_dir, pager) = test_pager(4096);
        pager.base.willneed(0, 16);
        pager.base.willneed(1, 16);
        pager.base.willneed(usize::MAX / PAGE_SIZE, 16);
        pager.base.prefault(0, 0);
        pager.base.prefault(0, 16);
        pager.base.prefault(1, 16);
        pager.base.prefault(usize::MAX, usize::MAX);
        assert!(pager.base.pages(0, 1).iter().all(|&b| b == 0));
    }

    #[test]
    fn template_prefault_populates_the_source_mapping() {
        use std::os::unix::fs::FileExt;

        let (_dir, pager) = test_pager(1);
        let ptr = pager.base.pages(0, 1).as_ptr() as *mut libc::c_void;
        // Older kernels only support the asynchronous fallback.
        if unsafe { libc::madvise(ptr, PAGE_SIZE, libc::MADV_POPULATE_READ) } != 0 {
            return;
        }
        assert_eq!(unsafe { libc::madvise(ptr, PAGE_SIZE, libc::MADV_DONTNEED) }, 0);
        let map = std::fs::File::open("/proc/self/pagemap").unwrap();
        let present = || {
            let mut entry = [0; 8];
            map.read_exact_at(&mut entry, ptr as u64 / PAGE_SIZE as u64 * 8).unwrap();
            u64::from_ne_bytes(entry) & PM_PRESENT != 0
        };
        assert!(!present());
        pager.base.prefault(0, 1);
        assert!(present(), "the copy must not be the first access to the source");
    }

    #[test]
    fn failed_hot_copy_and_freeze_recycle_memory() {
        let (_dir, mut pager) = test_pager(4096);
        // No process at pid 0: a hot candidate's read fails without a VM or a userfaultfd.
        pager.runtime.pages.get_mut().unwrap().fill(1, 1, PRESENT);
        pager.pages().mark_dirty(1);
        *pager.hot_dirty.lock().unwrap() = Arc::new(pager.pages().dirty_bits(false));
        pager.prepare_hot();
        pager.hot_prev.lock().unwrap().1 = Some(Arc::new(Held::of(&[(1, 42)])));
        let Err((_, prev)) = pager.copy_hot() else { panic!("read should fail") };
        pager.recycle(prev);
        assert!(pager.hot_spare.lock().unwrap().is_some(), "failed read recycles its allocation");
        assert!(pager.hot_prev.lock().unwrap().1.is_none(), "failed copy invalidates comparisons");

        // No hot candidates now: the hot copy succeeds without a read, but protecting the dirty page fails.
        *pager.hot_dirty.lock().unwrap() = Arc::default();
        *pager.hot_spare.lock().unwrap() = None;
        pager.hot_prev.lock().unwrap().1 = Some(Arc::new(Held::of(&[(1, 42)])));
        pager.prepare_hot();
        pager.fail_protect.store(true, Ordering::SeqCst);
        assert!(pager.freeze(&vec![], true, true).is_err());
        assert!(pager.hot_spare.lock().unwrap().is_some(), "failed freeze recycles its allocation");
        assert!(pager.hot_prev.lock().unwrap().1.is_none());
        assert!(pager.pages().is_dirty(1), "failed freeze restores dirty bits");

        // If the new snapshot is still shared, recycle the previous snapshot instead.
        pager.tracking.store(true, Ordering::SeqCst);
        pager.prepare_hot();
        pager.hot_prev.lock().unwrap().1 = Some(Arc::new(Held::of(&[(1, 42)])));
        let hot = pager.copy_hot().ok().flatten().unwrap();
        let _shared = hot.held.clone();
        pager.recycle_hot(Some(hot));
        assert!(pager.hot_spare.lock().unwrap().is_some(), "previous snapshot can become the spare");
    }

    // Exercise the failed read and rollback without write-protect ioctls: a paused-only freeze supplies Frozen,
    // then we give it the dirty bits and previous snapshot a keep-running freeze would retain after that read.
    fn failed_hot_read(pager: &mut Pager) -> (Frozen, Arc<Held>) {
        pager.runtime.pages.get_mut().unwrap().fill(1, 1, PRESENT);
        pager.pages().mark_dirty(1);
        *pager.hot_dirty.lock().unwrap() = Arc::new(pager.pages().dirty_bits(false));
        pager.prepare_hot();
        let held = Arc::new(Held::of(&[(1, 42)]));
        pager.hot_prev.lock().unwrap().1 = Some(held.clone());
        let Err((generation, prev)) = pager.copy_hot() else { panic!("read should fail") };
        let mut frozen = pager.freeze(&vec![], true, false).unwrap();
        frozen.taken = Arc::new(pager.pages().dirty_bits(true));
        frozen.prev = Mutex::new(prev);
        frozen.prev_generation = Some(generation);
        (frozen, held)
    }

    #[test]
    fn failed_hot_read_unfreeze_restores_previous_snapshot() {
        let (_dir, mut pager) = test_pager(4096);
        let (frozen, held) = failed_hot_read(&mut pager);
        assert!(pager.hot_prev.lock().unwrap().1.is_none());
        assert!(!pager.pages().is_dirty(1));
        pager.pages().mark_dirty(2);
        pager.unfreeze(&frozen);
        assert!(pager.pages().is_dirty(1) && pager.pages().is_dirty(2));
        assert!(Arc::ptr_eq(pager.hot_prev.lock().unwrap().1.as_ref().unwrap(), &held));
        // Repeated rollback cannot take the restored snapshot away.
        pager.unfreeze(&frozen);
        assert!(Arc::ptr_eq(pager.hot_prev.lock().unwrap().1.as_ref().unwrap(), &held));
    }

    #[test]
    fn failed_hot_read_unfreeze_rejects_a_changed_base() {
        for with_hot in [false, true] {
            let (_dir, mut pager) = test_pager(4096);
            let (frozen, _held) = failed_hot_read(&mut pager);
            let mut later = pager.freeze(&vec![], true, false).unwrap();
            later.held = with_hot.then(|| Arc::new(Held::of(&[(1, 99)])));
            pager.commit_copy(&later);
            pager.unfreeze(&frozen);
            let prev = pager.hot_prev.lock().unwrap();
            match &later.held {
                Some(held) => assert!(Arc::ptr_eq(prev.1.as_ref().unwrap(), held)),
                None => assert!(prev.1.is_none(), "a commit without hot pages also changes the base"),
            }
        }
    }

    #[test]
    fn failed_hot_read_unfreeze_rejects_disabled_tracking_and_released_memory() {
        for release in [false, true] {
            let (_dir, mut pager) = test_pager(4096);
            let (frozen, _held) = failed_hot_read(&mut pager);
            if release {
                pager.release_kept();
            } else {
                pager.tracking.store(false, Ordering::SeqCst);
            }
            pager.unfreeze(&frozen);
            assert!(pager.hot_prev.lock().unwrap().1.is_none());
        }
    }

    #[test]
    fn successful_hot_read_unfreeze_still_recycles_previous_snapshot() {
        let (_dir, pager) = test_pager(4096);
        pager.prepare_hot();
        pager.hot_prev.lock().unwrap().1 = Some(Arc::new(Held::of(&[(1, 42)])));
        let frozen = pager.freeze(&vec![], true, true).unwrap();
        assert!(frozen.held.is_some());
        pager.unfreeze(&frozen);
        assert!(pager.hot_prev.lock().unwrap().1.is_none());
    }

    #[test]
    fn memory_kept_for_the_next_checkpoint_goes_back_when_the_host_is_short() {
        let n = 4096;
        let (_dir, pager) = test_pager(n);
        // A copy that rescued pages leaves their memory for the next one; so does a checkpoint its hot pages'.
        let keep = || {
            let cow = Cow::new(n, &vec![]).keep_slots(pager.slot_spare.clone(), pager.mem_room.clone());
            let s = cow.take_slots(3).unwrap().unwrap();
            cow.give_slots(s);
        };
        keep();
        pager.prepare_hot();
        let kept = || (pager.slot_spare.lock().unwrap().as_ref().map_or(0, |s| s.mapped_bytes()), pager.hot_spare.lock().unwrap().is_some());
        assert_eq!(kept(), (2 << 20, true));
        pager.host_memory(|| Some(1000), false);
        assert_eq!(kept(), (2 << 20, true), "kept while there is room");
        pager.host_memory(|| Some(0), true);
        assert_eq!(kept(), (0, false), "released when short");
        // The last checkpoint's hot pages go too (#691): the next compares with none.
        keep();
        pager.hot_prev.lock().unwrap().1 = Some(Arc::new(Held::of(&[(2, 3)])));
        pager.release_kept();
        assert!(pager.hot_prev.lock().unwrap().1.is_none() && kept() == (0, false));
        // Under the reserve: no hot pages' memory, and a copy keeps none of its rescue memory.
        pager.mem_room.set(0);
        pager.prepare_hot();
        keep();
        assert_eq!(kept(), (0, false));
        // No bound.
        pager.mem_room.set(u64::MAX);
        pager.prepare_hot();
        assert!(kept().1);
    }

    #[test]
    fn blocks_stay_in_their_region() {
        // Aligned within the region, which starts at 1 MiB (256 pages) here, not 2 MiB.
        assert_eq!(block_at(700, (256, 1280), 512), (256, 768));
        assert_eq!(block_at(800, (256, 1280), 512), (768, 1280));
        assert_eq!(block_at(800, (256, 1280), 16), (800, 816));
        // Cut short by the region's end; the next region's first block starts at its own start.
        assert_eq!(block_at(1030, (768, 1040), 512), (768, 1040));
        assert_eq!(block_at(1039, (1024, 1040), 16), (1024, 1040));
        assert_eq!(block_at(1040, (1040, 2064), 512), (1040, 1552));
    }

    #[test]
    fn freeze_reads_only_touched_snapshot_chunks() {
        let dir = crate::test_util::TempDir::new("freeze-sparse");
        std::fs::write(
            dir.join("meta.json"),
            serde_json::to_vec(&serde_json::json!({
                "compatibility": {"cpu": "test", "tsc_khz": 2000000, "tsc_control": false,
                    "msrs": [], "firecracker": "test", "features": {}, "xsave": {}},
                "vcpus": 1, "mem_mib": 1, "max_mib": 48128, "plugged_mib": 0,
                "kernel": "/k", "rootfs": "/r", "id": "a", "components": {}
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::File::create(dir.join("mem")).unwrap().set_len(PAGE_SIZE as u64).unwrap();
        let base = crate::template::Template::open_dir("test", dir.to_path_buf()).unwrap();
        for incremental in [false, true] {
            // A template sized for a 47 GiB host plus a partial final chunk. No guest process or UFFD is needed: BASE and
            // ZERO pages must be counted and saved in deltas, but need no write-protect ioctl.
            let n = (47 << 30) / PAGE_SIZE + 1;
            let last = n - 1;
            let mut pages = Pages::new(n);
            pages.fill(CHUNK + 9, 1, ZERO);
            for p in [7, CHUNK + 9, last] {
                pages.mark_dirty(p);
            }
            let pager = Pager {
                base: base.clone(),
                runtime: Runtime {
                    pages: pages.into(),
                    mappings: [(0, 2 * CHUNK), (2 * CHUNK, last), (last, n)]
                        .map(|(from, to)| Mapping { offset: (from * PAGE_SIZE) as u64, size: (to - from) * PAGE_SIZE, base_host_virt_addr: 0 })
                        .to_vec()
                        .into(),
                    tracking: true.into(),
                    ..Runtime::default()
                },
                fault_stats: FaultStats::new(),
                lanes: Default::default(),
                steer: Mutex::new((0, 0)),
                collapse_report: Mutex::new(None),
                collapse_gate: Default::default(),
            };
            let runs = vec![(CHUNK as u64 + 9, 1, ZERO)];
            let frozen = pager.freeze(&runs, incremental, true).unwrap();
            assert_eq!(frozen.dirty, 3);
            assert_eq!(frozen.protected, 0);
            assert_eq!(frozen.runs, if incremental { vec![(7, 1, BASE), (CHUNK as u64 + 9, 1, ZERO), (last as u64, 1, BASE)] } else { runs });
            // One count, one pass over the mappings, and (for a delta) one incremental scan. Only the two full
            // touched chunks and the single word in the partial final chunk may be read by each pass.
            assert_eq!(frozen.taken.visited.load(Ordering::Relaxed), (2 + incremental as usize) * (2 * (CHUNK / 64) + 1));
            assert_eq!(pager.dirty_count(), 0);
            pager.pages().mark_dirty(8);
            pager.unfreeze(&frozen);
            assert_eq!(pager.pages().dirty_bits(false).pages(0, n).collect::<Vec<_>>(), [7, 8, CHUNK + 9, last]);
        }
    }
}
