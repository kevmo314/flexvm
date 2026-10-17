//! Hot pages at a keep-running checkpoint's pause (#235).
//!
//! Write-protecting a page makes KVM drop its mapping of it, and so does each unprotect: the guest then faults on
//! every page it touches after the resume, reads too, and a write fault waits for the pager to save the page,
//! unprotect it (another drop, and a TLB flush on every vCPU) and wake it. For pages the guest writes again in every
//! interval, that costs it far more than copying them out while it is paused.
//!
//! So the freeze (`copy_hot`) first copies the pages dirtied both since the last pause and in the interval before it,
//! into memory allocated before the pause (`prepare_hot`), and hands them to the writer as saved (`Cow::hold`), up to
//! `HOT_MIB`, preferring those copied last time too, then lower page numbers. They stay unprotected, and count as dirty again from the pause on:
//! the next checkpoint copies them again. That one compares them with what this one saved: pages that did not change are left out of an incremental
//! checkpoint (their contents at the pause are byte for byte what the last checkpoint has), and protected again where a
//! whole block of them did not (`HOT_BLOCK`). The copies are kept for that comparison only once their checkpoint is
//! the delta base (`commit_copy`); any other end drops them, and the next checkpoint leaves none out. A VM taking
//! keep-running checkpoints holds up to twice `HOT_MIB` for this: the last checkpoint's copies and the memory for the
//! next one's.

use super::{Mapping, Pager, PRESENT};
use crate::bail;
use crate::util::{Result, PAGE_SIZE};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// Hot pages copied during a pause, at most: about 0.5 µs a
/// page here, so up to 8 ms more pause, against 1.5 µs or more a page of guest time through faults.
const HOT_MIB: usize = 64;
/// Threads copying hot pages during the pause.
const HOT_THREADS: usize = 4;
/// Pages read with one call, at most.
const HOT_RUN: usize = 256;
/// Hot pages stay unprotected (or are protected again) by aligned blocks of this many: one with any page changed stays
/// so whole. A guest's pages are scattered in its memory, so changed ones have unchanged ones all around; protecting
/// those would cost a protect call (and a TLB flush) for each gap, and a fault (with another) whenever the guest writes
/// near there again, against well under a microsecond a page to copy them. Smaller blocks here copied as much, kept
/// fewer pages unprotected, and faulted three times as often.
const HOT_BLOCK: usize = 64;
const MADV_POPULATE_WRITE: libc::c_int = 23;

/// Anonymous memory, populated when allocated, so that filling it during a pause takes no page faults (several
/// microseconds each here).
pub struct Buf {
    ptr: *mut u8,
    len: usize,
}

// Plain memory: shared read-only once filled, and filled only through disjoint ranges.
unsafe impl Send for Buf {}
unsafe impl Sync for Buf {}

impl Buf {
    fn new(pages: usize) -> io::Result<Buf> {
        let len = pages.max(1) * PAGE_SIZE;
        let ptr = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let buf = Buf { ptr: ptr.cast(), len };
        unsafe {
            if libc::madvise(ptr, len, MADV_POPULATE_WRITE) != 0 {
                (0..len).step_by(PAGE_SIZE).for_each(|o| buf.ptr.add(o).write_volatile(0));
            }
        }
        Ok(buf)
    }

    fn pages(&self) -> usize {
        self.len / PAGE_SIZE
    }

    fn page(&self, i: usize) -> &[u8] {
        assert!(i < self.pages());
        unsafe { std::slice::from_raw_parts(self.ptr.add(i * PAGE_SIZE), PAGE_SIZE) }
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

/// The contents of a checkpoint's hot pages at its pause.
pub struct Held {
    /// Ascending; page `pages[i]` is at `buf.page(i)`.
    pages: Vec<usize>,
    buf: Buf,
}

impl Held {
    pub fn pages(&self) -> &[usize] {
        &self.pages
    }

    pub fn get(&self, page: usize) -> Option<&[u8]> {
        self.pages.binary_search(&page).ok().map(|i| self.buf.page(i))
    }
}

/// What `copy` copied: the hot pages, those of them found unchanged since the last checkpoint, and the blocks
/// (`HOT_BLOCK`) with any page changed (or not known not to be) since then (all ascending); and the last checkpoint's.
pub struct Hot {
    pub held: Arc<Held>,
    pub unchanged: Vec<usize>,
    changed: Vec<usize>,
    pub prev: Option<Arc<Held>>,
}

impl Hot {
    /// Whether `page` stays unprotected: copied, in a block that changed.
    pub fn keeps(&self, page: usize) -> bool {
        self.held.pages.binary_search(&page).is_ok() && self.changed.binary_search(&(page / HOT_BLOCK)).is_ok()
    }

    pub fn unchanged(&self, page: usize) -> bool {
        self.unchanged.binary_search(&page).is_ok()
    }
}

impl Pager {
    /// Before a keep-running checkpoint pauses the VM: allocates the memory its hot pages are copied into, twice what
    /// is dirty now (it grows until the pause), capped at `HOT_MIB`. Without it, the pause protects every dirty page.
    pub fn prepare_hot(&self) {
        if !self.tracking() {
            return;
        }
        let want = (self.dirty_count() * 2 + 1024).min(HOT_MIB << 20 >> 12);
        let mut spare = self.hot_spare.lock().unwrap();
        if spare.as_ref().is_some_and(|b| b.pages() >= want) {
            return;
        }
        *spare = None;
        // Not into the host's reserve (see `host_memory`): the pause protects these pages instead.
        if self.mem_room.take(((want * PAGE_SIZE) >> 20) as u64 + 1).is_none() {
            crate::log!("uffd: no room for hot pages ({want} pages): the host is near its reserve");
            return;
        }
        match Buf::new(want) {
            Ok(b) => *spare = Some(b),
            Err(e) => crate::log!("uffd: no memory for hot pages ({want} pages): {e}"),
        }
    }

    /// For the freeze of a keep-running checkpoint, the VM paused and its state saved (saving device state writes
    /// guest memory): copies its hot pages into what `prepare_hot` allocated, comparing them with the last checkpoint's
    /// if that is the delta base. None if there is nothing to copy them into, or the copy failed: the freeze protects
    /// every dirty page then. Not under the fault lock: a read that faulted would wait for a fault handler.
    pub(super) fn copy_hot(&self) -> Option<Hot> {
        let buf = self.hot_spare.lock().unwrap().take()?;
        // Written in two intervals in a row: one written once (a file being written, say) is better left to the writers.
        let before = self.hot_dirty.lock().unwrap().clone();
        // This is only a candidate scan: it clears no dirty bits. Freeze later takes the authoritative snapshot
        // under the fault lock and protects every dirty page not copied here, including intervening writes.
        let pages = self.pages();
        let spans: Vec<(usize, usize)> = self.mappings().iter().map(|m| m.span()).collect();
        let eligible = |p: usize| pages.get(p) == PRESENT && spans.iter().any(|&(a, b)| (a..b).contains(&p));
        // Taken: unless this checkpoint is taken, the next one has nothing to compare with.
        let prev = self.hot_prev.lock().unwrap().take();
        let hot_before = |p: usize| before.bits.get(p / 64).is_some_and(|w| w >> (p % 64) & 1 != 0);
        let candidate = |p: usize| pages.is_dirty(p) && hot_before(p) && eligible(p);
        let hot = select_hot(pages.hot_pages(&before.bits), prev.as_ref().map_or(&[], |h| h.pages()), candidate, buf.pages());
        let read = |p: usize, dst: &mut [u8]| self.read_at((p * PAGE_SIZE) as u64, &[libc::iovec { iov_base: dst.as_mut_ptr().cast(), iov_len: dst.len() }]);
        copy(buf, prev, hot, |p| next_to(self.mappings(), p), read).inspect_err(|e| crate::log!("uffd: hot pages not copied, protecting them: {e}")).ok()
    }

    /// The VM process's memory controller, every second: `room` gives what host memory is left above its reserve and
    /// the grants guests have yet to touch (MiB; None if unknown), which rescue memory and hot pages' memory grow
    /// within, as they are not admitted like a guest's (`cow::Room`, the host's once attached); and while the host is
    /// `short` (under its eviction mark, or this VM starved) the memory kept for the next checkpoint (both of those)
    /// goes back. A copy running on keeps what it has until it ends.
    pub fn host_memory(&self, room: impl FnOnce() -> Option<u64>, short: bool) {
        self.mem_room.refresh(room);
        if short {
            self.release_kept();
        }
    }

    /// Releases the memory kept for the next checkpoint: rescue memory and hot pages' (a request from another
    /// process, `hostmem`, or the host is short).
    pub fn release_kept(&self) {
        let slots = self.slot_spare.lock().unwrap().take();
        let hot = self.hot_spare.lock().unwrap().take();
        if slots.as_ref().is_some_and(|s| s.mapped_bytes() > 0) || hot.is_some() {
            crate::log!("uffd: the host is short of memory: memory kept for the next checkpoint released");
        }
    }

    /// The memory of hot pages no checkpoint needs any more is the next one's (`prepare_hot`), unless it has larger.
    pub(super) fn recycle(&self, held: Option<Arc<Held>>) {
        if let Some(Held { buf, .. }) = held.and_then(|h| Arc::try_unwrap(h).ok()) {
            self.recycle_buf(buf);
        }
    }

    fn recycle_buf(&self, buf: Buf) {
        let mut spare = self.hot_spare.lock().unwrap();
        if spare.as_ref().is_none_or(|b| b.pages() < buf.pages()) {
            *spare = Some(buf);
        }
    }
}

/// Candidates examined per hot page wanted (`select_hot`).
const SCAN_BUDGET: usize = 16;

/// Keeps up to `cap` of the ascending `candidates`, preferring pages copied last time too (dirty in at least three
/// intervals; `prev`, ascending, checked with `candidate`), then lower page numbers. Bounded by the cap, not by how many
/// candidates there are: examines at most `SCAN_BUDGET * cap` candidates, ineligible ones (discarded or unmapped)
/// included, so it may copy fewer. It runs during the pause, and a large guest can have millions. Returns ascending pages for
/// copying runs and binary searches. Bitmap words without candidates are still skipped by the iterator.
fn select_hot(candidates: impl Iterator<Item = usize>, prev: &[usize], candidate: impl Fn(usize) -> bool, cap: usize) -> Vec<usize> {
    let mut hot: Vec<usize> = prev.iter().copied().take(cap).filter(|&p| candidate(p)).collect();
    let mut j = 0;
    let others = candidates
        .take(SCAN_BUDGET * cap)
        .filter(|&p| candidate(p))
        .filter(|&p| {
            j += prev[j..].partition_point(|&q| q < p);
            prev.get(j) != Some(&p)
        })
        .take(cap - hot.len());
    hot.extend(others);
    // Two ascending runs: a stable sort merges them in linear time.
    hot.sort();
    hot
}

/// Whether page `p`'s memory follows that of page `p - 1` in the same region (a read stays within one).
fn next_to(mappings: &[Mapping], p: usize) -> bool {
    let off = (p * PAGE_SIZE) as u64;
    mappings.iter().any(|m| off > m.offset && off < m.offset + m.size as u64)
}

/// Copies the pages `hot` (ascending, at most as many as `buf` holds) into `buf` with several threads, with `read` (a
/// page, and room for it and those after it), reading runs of pages whose memory is `next_to` that of the one before
/// with one call each; and finds which are as `prev` has them.
fn copy(
    buf: Buf,
    prev: Option<Arc<Held>>,
    hot: Vec<usize>,
    next_to: impl Fn(usize) -> bool,
    read: impl Fn(usize, &mut [u8]) -> io::Result<()> + Sync,
) -> Result<Hot> {
    assert!(hot.len() <= buf.pages());
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for i in 0..hot.len() {
        match runs.last_mut() {
            Some((a, b)) if *b - *a < HOT_RUN && hot[i] == hot[i - 1] + 1 && next_to(hot[i]) => *b = i + 1,
            _ => runs.push((i, i + 1)),
        }
    }
    let next = AtomicUsize::new(0);
    let unchanged = Mutex::new(Vec::new());
    let failed = Mutex::new(None);
    let work = || loop {
        let Some(&(a, b)) = runs.get(next.fetch_add(1, Ordering::Relaxed)) else { return };
        // Each run is taken once: its part of `buf` is written by this thread only.
        let dst = unsafe { std::slice::from_raw_parts_mut(buf.ptr.add(a * PAGE_SIZE), (b - a) * PAGE_SIZE) };
        if let Err(e) = read(hot[a], dst) {
            *failed.lock().unwrap() = Some(e);
            return;
        }
        // Only until a page of the block is found changed: the rest of it stays unprotected anyway, and counts as
        // changed (it is saved again, which is never wrong).
        let mut same = Vec::new();
        let mut changed = None;
        for (i, &p) in hot.iter().enumerate().take(b).skip(a) {
            if changed == Some(p / HOT_BLOCK) {
                continue;
            }
            match prev.as_ref().and_then(|h| h.get(p)).is_some_and(|old| old == buf.page(i)) {
                true => same.push(p),
                false => changed = Some(p / HOT_BLOCK),
            }
        }
        unchanged.lock().unwrap().extend(same);
    };
    let threads = HOT_THREADS.min(crate::util::host_cpus()).min(runs.len().div_ceil(8));
    thread::scope(|s| {
        for _ in 1..threads {
            // Fewer threads if they cannot be had: this one copies too.
            if thread::Builder::new().spawn_scoped(s, work).is_err() {
                break;
            }
        }
        work();
    });
    if let Some(e) = failed.into_inner().unwrap() {
        bail!("copying hot pages: {e}");
    }
    let mut unchanged = unchanged.into_inner().unwrap();
    unchanged.sort_unstable();
    let mut changed: Vec<usize> = hot.iter().filter(|p| unchanged.binary_search(p).is_err()).map(|p| p / HOT_BLOCK).collect();
    changed.dedup();
    Ok(Hot { held: Arc::new(Held { pages: hot, buf }), unchanged, changed, prev })
}

#[cfg(test)]
impl Held {
    /// Pages with the given contents.
    pub fn of(pages: &[(usize, u8)]) -> Held {
        let buf = Buf::new(pages.len()).unwrap();
        for (i, &(_, b)) in pages.iter().enumerate() {
            unsafe { std::ptr::write_bytes(buf.ptr.add(i * PAGE_SIZE), b, PAGE_SIZE) };
        }
        Held { pages: pages.iter().map(|&(p, _)| p).collect(), buf }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_scan_bounds_ineligible_candidates() {
        let visited = std::cell::Cell::new(0);
        let candidates = (0..1_000_000).inspect(|_| visited.set(visited.get() + 1));
        // Discarded or unmapped pages still count against the scan budget; previous copies get priority.
        let hot = select_hot(candidates, &[100, 101], |p| p >= 62 && p != 101, 4);
        assert_eq!(hot, [62, 63, 100]);
        assert_eq!(visited.get(), 64);
        // A long run of discarded low pages no longer exhausts the old 4x budget.
        assert_eq!(select_hot(0..100, &[], |p| p >= 20, 4), [20, 21, 22, 23]);
        assert!(select_hot((0..).inspect(|_| panic!("zero budget scanned")), &[], |_| true, 0).is_empty());
    }

    #[test]
    fn hot_pages_over_cap_keep_previous_hot_pages_first() {
        let cap = HOT_MIB << 20 >> 12;
        let pages = super::super::pages::Pages::new(cap + 3);
        for p in 0..cap + 3 {
            pages.mark_dirty(p);
        }
        let before = pages.dirty_bits(false);
        let prev = [cap - 1, cap, cap + 1];
        let all = |_| true;
        let hot = select_hot(pages.hot_pages(&before.bits), &prev, all, cap);
        assert_eq!(hot.len(), cap);
        assert_eq!(&hot[..cap - 3], &(0..cap - 3).collect::<Vec<_>>());
        assert_eq!(&hot[cap - 3..], &prev);
        assert_eq!(select_hot(pages.hot_pages(&before.bits), &[], all, cap), (0..cap).collect::<Vec<_>>());
        // Pages copied last time that are no candidates now are not taken, and leave room for others.
        let hot = select_hot(pages.hot_pages(&before.bits), &[1, cap + 1, cap + 9], |p| p != cap + 9, cap);
        assert_eq!(hot, (0..cap - 1).chain([cap + 1]).collect::<Vec<_>>());
        // Under the cap, every candidate.
        assert_eq!(select_hot([3, 5, 9].into_iter(), &[5, 7], |p| p != 7, 4), [3, 5, 9]);
        assert_eq!(select_hot([3, 5, 9].into_iter(), &[9], all, 2), [3, 9]);
    }

    /// A guest of `n` pages, each filled with its own byte.
    fn guest(n: usize) -> Vec<u8> {
        (0..n * PAGE_SIZE).map(|i| (i / PAGE_SIZE) as u8).collect()
    }

    fn copy_of(mem: &[u8], prev: Option<Arc<Held>>, hot: Vec<usize>, reads: &Mutex<Vec<(usize, usize)>>) -> Hot {
        let read = |p: usize, dst: &mut [u8]| {
            reads.lock().unwrap().push((p, dst.len() / PAGE_SIZE));
            dst.copy_from_slice(&mem[p * PAGE_SIZE..p * PAGE_SIZE + dst.len()]);
            Ok(())
        };
        // Page 70 starts another region.
        copy(Buf::new(hot.len()).unwrap(), prev, hot, |p| p != 70, read).unwrap()
    }

    #[test]
    fn hot_pages_are_copied_and_compared_exactly() {
        let mut mem = guest(256);
        let reads = Mutex::new(Vec::new());
        let hot = vec![3, 4, 5, 69, 70, 71, 200];
        let first = copy_of(&mem, None, hot.clone(), &reads);
        for &p in &hot {
            assert_eq!(first.held.get(p).unwrap(), &mem[p * PAGE_SIZE..(p + 1) * PAGE_SIZE], "page {p} copied");
        }
        assert!(first.held.get(6).is_none());
        let mut runs = reads.into_inner().unwrap();
        runs.sort();
        assert_eq!(runs, [(3, 3), (69, 1), (70, 2), (200, 1)], "a call per run, none across regions");
        assert!(first.unchanged.is_empty(), "nothing to compare with: all changed");
        assert!(hot.iter().all(|&p| first.keeps(p)));
        // Next time: page 4 changed in one byte, page 69 was rewritten with what it had; 70, 71 and 200 changed, and
        // page 64's block has a page copied for the first time.
        mem[4 * PAGE_SIZE + 100] ^= 1;
        mem[70 * PAGE_SIZE..72 * PAGE_SIZE].fill(0xaa);
        mem[200 * PAGE_SIZE] = 1;
        let next = copy_of(&mem, Some(first.held.clone()), vec![3, 4, 5, 64, 69, 70, 71, 200], &Mutex::new(Vec::new()));
        // Page 5 is as it was too, but past a changed page of its block in the same run: not compared, saved again.
        assert_eq!(next.unchanged, [3, 69]);
        assert!(next.unchanged(3) && !next.unchanged(4) && !next.unchanged(5) && !next.unchanged(64));
        // Blocks of 64: 0..64 has page 4 changed, so 3 and 5 stay unprotected too; 64..128 has 64, 70 and 71.
        assert!([3, 4, 5, 64, 69, 70, 71, 200].iter().all(|&p| next.keeps(p)));
        assert!(!next.keeps(6), "only copied pages");
        assert!(Arc::ptr_eq(next.prev.as_ref().unwrap(), &first.held));
        // A block whose copied pages are all as before is protected again.
        let last = copy_of(&mem, Some(next.held.clone()), vec![3, 5, 200], &Mutex::new(Vec::new()));
        assert_eq!(last.unchanged, [3, 5, 200]);
        assert!(!last.keeps(3) && !last.keeps(5) && !last.keeps(200));
    }

    #[test]
    fn hot_runs_stop_at_region_ends() {
        // Two regions next to each other in guest and host memory alike.
        let regions = [
            Mapping { base_host_virt_addr: 0, offset: 0, size: 512 * PAGE_SIZE },
            Mapping { base_host_virt_addr: (512 * PAGE_SIZE) as u64, offset: (512 * PAGE_SIZE) as u64, size: 512 * PAGE_SIZE },
        ];
        assert!(next_to(&regions, 511) && next_to(&regions, 513));
        assert!(!next_to(&regions, 0) && !next_to(&regions, 512) && !next_to(&regions, 1024));
        let reads = Mutex::new(Vec::new());
        let read = |p: usize, dst: &mut [u8]| {
            reads.lock().unwrap().push((p, dst.len() / PAGE_SIZE));
            Ok(())
        };
        copy(Buf::new(4).unwrap(), None, vec![510, 511, 512, 513], |p| next_to(&regions, p), read).unwrap();
        let mut runs = reads.into_inner().unwrap();
        runs.sort();
        assert_eq!(runs, [(510, 2), (512, 2)]);
    }

    #[test]
    fn a_failed_read_copies_nothing() {
        let read = |p: usize, _: &mut [u8]| if p == 9 { Err(io::Error::other("gone")) } else { Ok(()) };
        assert!(copy(Buf::new(4).unwrap(), None, vec![1, 2, 9, 30], |_| true, read).is_err());
    }
}
