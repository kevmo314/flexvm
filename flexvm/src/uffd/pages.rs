use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock, RwLock, RwLockWriteGuard};
use std::thread;
use std::time::{Duration, Instant};

mod sealed {
    pub trait ZeroAtomic {}
    impl ZeroAtomic for super::AtomicU8 {}
    impl ZeroAtomic for super::AtomicU64 {}
}

/// The set bits of `words` (a bit a page), in ascending page order.
pub(super) fn set_bits(words: &[u64]) -> impl Iterator<Item = usize> + '_ {
    words.iter().enumerate().flat_map(|(w, &bits)| {
        std::iter::successors((bits != 0).then_some(bits), |b| Some(b & (b - 1)).filter(|&b| b != 0)).map(move |b| w * 64 + b.trailing_zeros() as usize)
    })
}

/// A dirty snapshot and the touched word ranges copied into it. Untouched words stay lazily zeroed: scans must use
/// these ranges rather than read (and fault in) the whole guest bitmap.
#[derive(Default)]
pub(super) struct DirtyBits {
    pub bits: Vec<u64>,
    chunks: Vec<Range<usize>>,
    /// Words exposed to snapshot scans, for the freeze regression's bound on bitmap reads.
    #[cfg(test)]
    pub visited: AtomicUsize,
}

impl DirtyBits {
    /// Touched words intersecting the page range, with their absolute word offsets. Includes boundary words; callers
    /// enumerating pages must filter their bits to the exact page range.
    fn words(&self, from: usize, to: usize) -> impl Iterator<Item = (usize, &[u64])> {
        let (first, end) = (from / 64, to.div_ceil(64));
        self.chunks.iter().filter(move |_| from < to).skip_while(move |r| r.end <= first).take_while(move |r| r.start < end).map(move |r| {
            let (a, b) = (r.start.max(first), r.end.min(end));
            #[cfg(test)]
            self.visited.fetch_add(b - a, Ordering::Relaxed);
            (a, &self.bits[a..b])
        })
    }

    pub fn count(&self) -> usize {
        self.words(0, self.bits.len() * 64).flat_map(|(_, words)| words).map(|w| w.count_ones() as usize).sum()
    }

    /// Set pages in the range, ascending even across skipped chunks.
    pub fn pages(&self, from: usize, to: usize) -> impl Iterator<Item = usize> + '_ {
        self.words(from, to).flat_map(|(at, words)| set_bits(words).map(move |p| at * 64 + p)).filter(move |&p| p >= from && p < to)
    }
}

/// Zeroed atomic storage, lazily backed by the kernel, with each type's alignment.
pub(crate) fn zeroed_atomics<T: sealed::ZeroAtomic>(n: usize) -> Vec<T> {
    if n == 0 {
        return Vec::new();
    }
    let layout = std::alloc::Layout::array::<T>(n).expect("atomic array too large");
    // Only AtomicU8 and AtomicU64 implement the sealed trait; zero is valid for both, and the allocation's layout is
    // exactly that of Vec<T>.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<T>();
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Vec::from_raw_parts(ptr, n, n)
    }
}

pub const BASE: u8 = 0; // Template (holes are zero).
pub const PRESENT: u8 = 1; // Installed in Firecracker.
pub const ZERO: u8 = 2; // Discarded by the guest.
pub const REMOTE: u8 = 3; // Migration source or checkpoint file.
pub const INFLIGHT: u8 = 4; // Claimed by one installer.
/// The most pages one copy installs while holding `events`.
const COPY_RUN: usize = 32;
pub const DISCARDED: u8 = 5; // REMOVE hit a claim; never install stale bytes.

/// The page state machine. Installers claim pages (-> INFLIGHT), populate them and settle them; a REMOVE on a claimed
/// page turns it DISCARDED, and its installer then skips it.
///
/// No data copy can land in a page after a REMOVE of it: the kernel fails copies with EAGAIN while a REMOVE event is
/// queued, the event is read and applied under `events` held exclusively, and installers hold it shared from checking a
/// page's state until they have settled it. After that a removed page is ZERO, which only ever gets zero-filled.
///
/// The kernel zaps the range only after the event is read, though, and not under any lock of ours, so a page can still
/// go missing after it settled PRESENT (say a zero-fill that hit EEXIST on the old mapping just before the zap). That
/// can only happen to a page the guest gave back, so a fault on a PRESENT page zero-fills it if it is missing.
#[derive(Default)]
pub struct Pages {
    pub(super) states: Vec<AtomicU8>,
    /// One bit per `CHUNK` pages: set once any of them may have left BASE or been marked dirty, so scans skip untouched
    /// stretches without reading (and faulting in) their part of `states`.
    touched: Vec<AtomicU64>,
    events: RwLock<()>,
    /// One bit per page: its contents may have changed since the last checkpoint's pause (written after a write-protect
    /// fault, installed, or discarded). See `Pager::freeze`.
    pub(super) dirty: Vec<AtomicU64>,
    /// Set while faults wait for claimed pages to settle: installers then signal `wake` (an eventfd the event thread
    /// polls) when they settle any.
    pub(super) waiting: AtomicBool,
    pub(super) wake: OnceLock<OwnedFd>,
    /// Bumped (and `read_cv` notified) each time the event thread has read and applied events: an install that hit
    /// EAGAIN, because a REMOVE was queued, waits for that rather than polling.
    pub(super) read_gen: AtomicU64,
    read_lock: Mutex<()>,
    read_cv: Condvar,
    pub install_eagain: AtomicU64,
    /// Pages faults wait on, and when a copy into them woke the faulting threads: what their latency counts to
    /// (`FaultStats`).
    pub(super) parked: Mutex<Vec<(usize, Option<Instant>)>>,
    /// REMOTE pages whose install failed and that are not in yet, with since when: whoever claims them next inherits
    /// the deadline.
    pub(super) failing: Mutex<Vec<(usize, Instant)>>,
    pub(super) failing_len: AtomicUsize,
    /// BASE and REMOTE pages whose install found them already mapped (EEXIST), with the state they were claimed from
    /// (at most `PRESET_KEPT`; `preset_more` counts the rest): see `Pager::foreign_pages`.
    pub(super) preset: Mutex<Vec<(usize, u8)>>,
    pub(super) preset_more: AtomicUsize,
}

/// How many `Pages::preset` pages are kept.
pub(super) const PRESET_KEPT: usize = 1024;
/// How many of them are logged.
const PRESET_LOGGED: usize = 4;

/// Pages per `touched` bit: one page of `states`.
pub(super) const CHUNK: usize = 4096;

impl Pages {
    pub fn new(n: usize) -> Pages {
        // BASE is 0, so a zeroed allocation (lazily backed by the kernel) is the initial state.
        let states = zeroed_atomics(n);
        let dirty = zeroed_atomics(n.div_ceil(64));
        let touched = (0..n.div_ceil(CHUNK * 64)).map(|_| AtomicU64::new(0)).collect();
        Pages { states, touched, dirty, ..Pages::default() }
    }

    /// A fault read at `read` waits for `page` to be installed.
    pub(super) fn park(&self, page: usize, read: Instant) {
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
    pub(super) fn unpark(&self, page: usize, read: Instant) -> Option<Instant> {
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
    pub(super) fn events_read(&self) {
        self.read_gen.fetch_add(1, Ordering::SeqCst);
        let _guard = self.read_lock.lock().unwrap();
        self.read_cv.notify_all();
    }

    /// After a copy or protect hit EAGAIN (a REMOVE is queued, and the kernel fails copies until the event thread has
    /// read it): waits until events were read since `seen` (`read_gen` before the copy), or if they were already,
    /// briefly, for the kernel to finish with them.
    pub(super) fn wait_events_read(&self, seen: u64) {
        if self.read_gen.load(Ordering::SeqCst) != seen {
            thread::sleep(Duration::from_micros(20));
            return;
        }
        let guard = self.read_lock.lock().unwrap();
        // Bounded: the event thread may itself be waiting for something.
        let _ = self.read_cv.wait_timeout_while(guard, Duration::from_millis(1), |_| self.read_gen.load(Ordering::SeqCst) == seen);
    }

    /// Marks `page` dirty, and its chunk touched first, which `dirty_bits` relies on.
    pub fn mark_dirty(&self, page: usize) {
        if let Some(w) = self.dirty.get(page / 64) {
            self.touch(page);
            w.fetch_or(1 << (page % 64), Ordering::SeqCst);
        }
    }

    pub fn is_dirty(&self, page: usize) -> bool {
        self.dirty.get(page / 64).is_some_and(|w| w.load(Ordering::Relaxed) >> (page % 64) & 1 != 0)
    }

    /// The touched chunks' dirty words, each run with the index of its first: only chunks marked touched (see
    /// `mark_dirty`) can have any set.
    fn dirty_chunks(&self) -> impl Iterator<Item = (usize, &[AtomicU64])> {
        self.dirty.chunks(CHUNK / 64).enumerate().filter(|&(c, _)| self.touched(c * CHUNK)).map(|(c, words)| (c * (CHUNK / 64), words))
    }

    /// Pages dirty now and before, reading only touched chunks and allocating no intersection bitmap.
    pub(super) fn hot_pages<'a>(&'a self, before: &'a [u64]) -> impl Iterator<Item = usize> + 'a {
        self.dirty_chunks().flat_map(move |(at, words)| {
            words.iter().enumerate().flat_map(move |(i, w)| {
                let bits = w.load(Ordering::SeqCst) & before.get(at + i).copied().unwrap_or(0);
                std::iter::successors((bits != 0).then_some(bits), |b| Some(b & (b - 1)).filter(|&b| b != 0))
                    .map(move |b| (at + i) * 64 + b.trailing_zeros() as usize)
            })
        })
    }

    pub(super) fn dirty_count(&self) -> usize {
        self.dirty_chunks().flat_map(|(_, words)| words).map(|w| w.load(Ordering::Relaxed).count_ones() as usize).sum()
    }

    /// The dirty bits, cleared with `take`.
    pub(super) fn dirty_bits(&self, take: bool) -> DirtyBits {
        let mut bits = vec![0; self.dirty.len()];
        let mut chunks = Vec::new();
        for (at, words) in self.dirty_chunks() {
            chunks.push(at..at + words.len());
            for (b, w) in bits[at..at + words.len()].iter_mut().zip(words) {
                *b = if take { w.swap(0, Ordering::SeqCst) } else { w.load(Ordering::SeqCst) };
            }
        }
        // mark_dirty touches its chunk before publishing a dirty bit, and touched bits are never cleared. Thus no
        // dirty page in this snapshot can lie outside these ranges, including installed, discarded and kept hot pages.
        DirtyBits {
            bits,
            chunks,
            #[cfg(test)]
            visited: AtomicUsize::new(0),
        }
    }

    /// Marks dirty again what `dirty_bits` took.
    pub(super) fn restore_dirty(&self, bits: &DirtyBits) {
        for (at, words) in bits.words(0, self.len()) {
            for (w, &b) in self.dirty[at..at + words.len()].iter().zip(words) {
                if b != 0 {
                    w.fetch_or(b, Ordering::SeqCst);
                }
            }
        }
    }

    /// A bounded run worth reading ahead from the template. Only a hint: states may change after this scan.
    pub(super) fn base_run(&self, first: usize, n: usize, has_data: impl Fn(usize) -> bool) -> usize {
        (first..first.saturating_add(n).min(self.len())).take_while(|&p| self.get(p) == BASE && has_data(p)).count()
    }

    pub fn get(&self, page: usize) -> u8 {
        self.states[page].load(Ordering::SeqCst)
    }

    /// Seeds pages `[first, first + n)` with `state` before the map is shared: plain stores (a memset), and each chunk's
    /// `touched` bit once, instead of an atomic store and touch per page. Out-of-bounds pages are ignored.
    pub(super) fn fill(&mut self, first: usize, n: usize, state: u8) {
        let end = first.saturating_add(n).min(self.states.len());
        if first >= end {
            return;
        }
        // Exclusive access: no other thread can see these atomics, so writing them as plain bytes (AtomicU8 has u8's
        // layout) races with nothing.
        let states = unsafe { std::slice::from_raw_parts_mut(self.states.as_mut_ptr().cast::<u8>(), self.states.len()) };
        states[first..end].fill(state);
        for c in first / CHUNK..=(end - 1) / CHUNK {
            *self.touched[c / 64].get_mut() |= 1 << (c % 64);
        }
    }

    /// Marks `page`'s chunk before its state leaves BASE.
    fn touch(&self, page: usize) {
        let c = page / CHUNK;
        let bit = 1u64 << (c % 64);
        if self.touched[c / 64].load(Ordering::Relaxed) & bit == 0 {
            self.touched[c / 64].fetch_or(bit, Ordering::SeqCst);
        }
    }

    pub(super) fn touched(&self, page: usize) -> bool {
        let c = page / CHUNK;
        self.touched[c / 64].load(Ordering::SeqCst) & (1 << (c % 64)) != 0
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// The first page in `[from, end)` not in `state`, or `end`. For BASE, skips chunks that never left it without
    /// reading them: a VM's map is mostly BASE (the unplugged virtio-mem region alone is millions of pages), and a
    /// migration scans it with the VM paused.
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
    pub(super) fn not_base(&self, from: usize, end: usize) -> impl Iterator<Item = usize> + '_ {
        let end = end.min(self.states.len());
        let next = move |i: usize| Some(self.next_not(BASE, i, end)).filter(|&i| i < end);
        std::iter::successors(next(from), move |&i| next(i + 1))
    }

    /// The first page in `[from, end)` in `state` (not BASE), or `end`.
    pub fn next_in(&self, state: u8, from: usize, end: usize) -> usize {
        self.not_base(from, end).find(|&i| self.states[i].load(Ordering::Relaxed) == state).unwrap_or(end.min(self.len()))
    }

    /// Held while reading and applying uffd events; required by `discard`.
    pub fn removing(&self) -> RwLockWriteGuard<'_, ()> {
        self.events.write().unwrap()
    }

    /// Claims up to `max` consecutive pages from `first` that are in state `from` and pass `ok`. Returns how many it
    /// claimed.
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

    /// Applies a REMOVE of pages `[first, end)`, a dirty word at a time (its chunk touched first, as `mark_dirty`).
    /// Returns how many REMOTE pages it resolved.
    pub fn discard(&self, _removing: &RwLockWriteGuard<'_, ()>, mut first: usize, end: usize) -> usize {
        let (end, mut resolved) = (end.min(self.len()), 0);
        let claimed = |s| s == INFLIGHT || s == DISCARDED;
        while first < end {
            let word = end.min((first / 64 + 1) * 64);
            self.touch(first);
            for page in first..word {
                let old = self.states[page].fetch_update(Ordering::SeqCst, Ordering::SeqCst, |s| Some(if claimed(s) { DISCARDED } else { ZERO }));
                if !claimed(old.unwrap()) {
                    self.forget_failure(page);
                }
                resolved += (old == Ok(REMOTE)) as usize;
            }
            self.dirty[first / 64].fetch_or((u64::MAX >> (64 - (word - first))) << (first % 64), Ordering::SeqCst);
            first = word;
        }
        resolved
    }

    /// Claimed `page` (from `from`) turned out to be mapped already: no install of ours put it there.
    fn note_preset(&self, page: usize, from: u8) {
        let mut preset = self.preset.lock().unwrap();
        // The first few of a VM's: enough to show the mechanism (#949) when it recurs.
        if preset.len() < PRESET_LOGGED {
            crate::log!(
                "uffd: page {page:#x} (guest memory offset {:#x}, claimed {}) was already mapped in firecracker: not installed by the pager",
                page * crate::util::PAGE_SIZE,
                if from == REMOTE { "REMOTE" } else { "BASE" }
            );
        }
        match preset.len() < PRESET_KEPT {
            true => preset.push((page, from)),
            false => _ = self.preset_more.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Claimed REMOTE `page` failed to install: notes since when, unless it already kept failing. Only while it is
    /// claimed, so never after it was resolved.
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

    /// Settles claimed `page`, claimed from state `from`. Returns whether a REMOTE page got resolved, for the pager's
    /// count of pages to pull.
    fn settle(&self, page: usize, populated: bool, from: u8) -> bool {
        if populated {
            // Installed writable: publish dirty before PRESENT, which lets quiesce_export finish and freeze take it.
            self.mark_dirty(page);
        }
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

    /// Installs claimed pages `[first, first + n)` with `populate(page, count)`, which returns how many pages from
    /// `page` it populated (UFFDIO_COPY may stop part way) and wakes their waiters. Pages discarded before their copy
    /// are skipped; EEXIST counts as populated. EAGAIN is retried until `stop` says to, or without `stop` ends the
    /// install. Unfinished pages are given back. Returns the REMOTE pages resolved and the error, if any.
    pub fn install(
        &self,
        first: usize,
        n: usize,
        from: u8,
        stop: Option<&dyn Fn() -> bool>,
        populate: impl FnMut(usize, usize) -> io::Result<usize>,
    ) -> (usize, io::Result<()>) {
        self.install_prepared(first, n, from, stop, None, populate)
    }

    /// `install`, calling `prepare(page, count)` on each copy's pages before taking `events` for it (once per page),
    /// e.g. to fault a copy's source in without holding up the event thread.
    pub fn install_prepared(
        &self,
        first: usize,
        n: usize,
        from: u8,
        stop: Option<&dyn Fn() -> bool>,
        prepare: Option<&dyn Fn(usize, usize)>,
        mut populate: impl FnMut(usize, usize) -> io::Result<usize>,
    ) -> (usize, io::Result<()>) {
        let (end, mut resolved, mut i, mut prepared) = (first + n, 0, first, first);
        while i < end {
            // Bound the copy while holding events: REMOVE and fault batches need its write lock.
            let copy_end = end.min(i + COPY_RUN);
            if let Some(prepare) = prepare.filter(|_| prepared < copy_end) {
                let from = prepared.max(i);
                prepare(from, copy_end - from);
                prepared = copy_end;
            }
            let installing = self.events.read().unwrap();
            if self.get(i) == DISCARDED {
                resolved += self.settle(i, false, from) as usize;
                i += 1;
                continue;
            }
            let m = (i + 1..copy_end).find(|&p| self.get(p) != INFLIGHT).unwrap_or(copy_end) - i;
            let gen = self.read_gen.load(Ordering::SeqCst);
            match populate(i, m) {
                Ok(done) => {
                    let done = done.clamp(1, m);
                    self.woke(i, done);
                    resolved += (i..i + done).filter(|&p| self.settle(p, true, from)).count();
                    i += done;
                }
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    if from == BASE || from == REMOTE {
                        self.note_preset(i, from);
                    }
                    resolved += self.settle(i, true, from) as usize;
                    i += 1;
                }
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) && stop.is_some_and(|s| !s()) => {
                    drop(installing);
                    self.install_eagain.fetch_add(1, Ordering::Relaxed);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_scans_clip_regions_and_skip_untouched_words() {
        for n in [0, 1, CHUNK, 3 * CHUNK + 1] {
            let pages = Pages::new(n);
            for p in [0, 63, 64, CHUNK - 1, CHUNK, n.saturating_sub(1)] {
                if p < n {
                    pages.mark_dirty(p);
                }
            }
            for take in [false, true] {
                let mut dirty = pages.dirty_bits(take);
                let expected: Vec<_> = set_bits(&dirty.bits).collect();
                // Even nonzero untouched words must never be read by snapshot consumers.
                for (i, w) in dirty.bits.iter_mut().enumerate() {
                    if !pages.touched(i * 64) {
                        *w = u64::MAX;
                    }
                }
                assert_eq!(dirty.count(), expected.len());
                for (from, to) in [(0, n), (1, n), (63, 65), (CHUNK + 1, 2 * CHUNK), (n, n), (65, 63)] {
                    assert_eq!(dirty.pages(from, to).collect::<Vec<_>>(), expected.iter().copied().filter(|&p| p >= from && p < to).collect::<Vec<_>>());
                }
            }
        }
    }

    #[test]
    #[ignore = "manual freeze bitmap microbenchmark; run with --release --ignored --nocapture"]
    fn freeze_bitmap_benchmark() {
        use std::hint::black_box;

        let pages = Pages::new((47 << 30) / crate::util::PAGE_SIZE);
        for p in [7, CHUNK + 9, pages.len() - 1] {
            pages.mark_dirty(p);
        }
        let regions = [(0, 128 << 8), (128 << 8, pages.len())];
        let start = Instant::now();
        for _ in 0..200 {
            let dirty = pages.dirty_bits(false);
            let count: usize = black_box(&dirty.bits).iter().map(|w| w.count_ones() as usize).sum();
            let protect: Vec<_> = regions.iter().flat_map(|&(from, to)| set_bits(&dirty.bits[from / 64..to.div_ceil(64)]).map(move |p| from + p)).collect();
            let incremental: Vec<_> = set_bits(&dirty.bits).collect();
            black_box((count, protect, incremental));
        }
        let full = start.elapsed();
        let start = Instant::now();
        for _ in 0..200 {
            let dirty = pages.dirty_bits(false);
            let count = black_box(&dirty).count();
            let protect: Vec<_> = regions.iter().flat_map(|&(from, to)| dirty.pages(from, to)).collect();
            let incremental: Vec<_> = dirty.pages(0, pages.len()).collect();
            black_box((count, protect, incremental));
        }
        println!(
            "47 GiB, three touched chunks, snapshot + count + region scans + incremental scan: full {:?}, touched {:?} per pause",
            full / 200,
            start.elapsed() / 200
        );
    }

    #[test]
    fn hot_scan_reads_only_touched_chunks() {
        // The 47 GiB template, with just three chunks touched, including a partial final chunk.
        let pages = Pages::new((47 << 30) / crate::util::PAGE_SIZE + 1);
        let last = pages.len() - 1;
        for p in [7, CHUNK + 9, last] {
            pages.mark_dirty(p);
        }
        let before = pages.dirty_bits(true);
        for p in [7, 8, last] {
            pages.mark_dirty(p);
        }
        assert_eq!(pages.hot_pages(&before.bits).collect::<Vec<_>>(), [7, last]);
        assert!(pages.hot_pages(&[]).next().is_none());
        assert_eq!(pages.dirty_count(), 3, "candidate scanning must not consume dirty bits");
        pages.restore_dirty(&before);
        assert_eq!(pages.dirty_bits(false).pages(0, pages.len()).collect::<Vec<_>>(), [7, 8, CHUNK + 9, last], "rollback retains writes after the snapshot");
        // Bound the words read by the hot scan independently of the template's maximum size.
        let scanned: usize = pages.dirty_chunks().map(|(_, words)| words.len()).sum();
        assert_eq!(scanned, 2 * (CHUNK / 64) + 1);
        assert!(scanned * 1000 < pages.dirty.len());
        // Poison untouched chunks: they must never enter the intersection, even with matching previous bits.
        for (_, w) in pages.dirty.iter().enumerate().filter(|&(i, _)| !pages.touched(i * 64)) {
            w.store(u64::MAX, Ordering::SeqCst);
        }
        assert_eq!(pages.hot_pages(&vec![u64::MAX; pages.dirty.len()]).collect::<Vec<_>>(), [7, 8, CHUNK + 9, last]);
    }

    #[test]
    #[ignore = "manual pause bitmap microbenchmark; run with --release --ignored --nocapture"]
    fn pause_bitmap_benchmark() {
        use std::hint::black_box;
        use std::sync::Arc;

        let pages = Pages::new((47 << 30) / crate::util::PAGE_SIZE);
        for p in [7, CHUNK + 9, pages.len() - 1] {
            pages.mark_dirty(p);
        }
        let before = Mutex::new(Arc::new(pages.dirty_bits(false)));
        let start = Instant::now();
        for _ in 0..100 {
            // The previous pause's whole-guest clones, intersection and kept bitmap allocation.
            let before = before.lock().unwrap().bits.clone();
            let intersect: Vec<u64> = pages.dirty_bits(false).bits.iter().zip(&before).map(|(a, b)| a & b).collect();
            let hot: Vec<_> = set_bits(&intersect).collect();
            let dirty = pages.dirty_bits(false).bits;
            let next = dirty.clone();
            let mut kept = vec![0u64; dirty.len()];
            hot.iter().for_each(|&p| kept[p / 64] |= 1 << (p % 64));
            black_box((hot, dirty, next, kept));
        }
        let old = start.elapsed();
        let start = Instant::now();
        for _ in 0..100 {
            let before = before.lock().unwrap();
            let hot: Vec<_> = pages.hot_pages(&before.bits).collect();
            let dirty = Arc::new(pages.dirty_bits(false));
            let mut kept = std::collections::BTreeMap::new();
            hot.iter().for_each(|&p| *kept.entry(p / 64).or_insert(0) |= 1u64 << (p % 64));
            black_box((hot, dirty.clone(), dirty, kept));
        }
        println!("47 GiB, three touched chunks, bitmap bookkeeping per pause: old {:?}, new {:?}", old / 100, start.elapsed() / 100);
    }

    #[test]
    #[ignore = "manual REMOVE microbenchmark; run with --release --ignored --nocapture"]
    fn remove_benchmark() {
        // A 128 MiB unplug of installed pages, as the event thread applies it with the events write lock held.
        let (first, n) = (1 << 18, (128 << 20) / crate::util::PAGE_SIZE);
        let mut pages = Pages::new(1 << 20);
        let start = Instant::now();
        for _ in 0..50 {
            pages.fill(first, n, PRESENT);
            let removing = pages.removing();
            assert_eq!(std::hint::black_box(pages.discard(&removing, first, first + n)), 0);
        }
        println!("128 MiB REMOVE: {:?} per event", start.elapsed() / 50);
    }

    #[test]
    fn template_readahead_is_bounded_and_skips_other_sources() {
        let mut pages = Pages::new(32);
        assert_eq!(pages.base_run(0, 16, |_| true), 16);
        assert_eq!(pages.base_run(30, 16, |_| true), 2);
        assert_eq!(pages.base_run(0, 16, |p| p < 3), 3);
        for state in [PRESENT, ZERO, REMOTE, INFLIGHT, DISCARDED] {
            pages.fill(4, 1, state);
            assert_eq!(pages.base_run(0, 16, |_| true), 4);
            assert_eq!(pages.base_run(4, 16, |_| true), 0);
        }
        assert_eq!(pages.get(0), BASE, "readahead never claims or installs pages");
    }

    #[test]
    fn install_uses_full_capped_runs() {
        let mut pages = Pages::new(513);
        pages.fill(0, 513, REMOTE);
        assert_eq!(pages.claim(0, 513, REMOTE, |_| true), 513);
        let mut copies = Vec::new();
        let (resolved, result) = pages.install(0, 513, REMOTE, None, |p, count| {
            copies.push((p, count));
            Ok(count)
        });
        result.unwrap();
        assert_eq!(resolved, 513);
        assert_eq!(copies, (0..513).step_by(32).map(|p| (p, (513 - p).min(32))).collect::<Vec<_>>());
    }

    #[test]
    fn install_prepares_each_copy_once_before_taking_events() {
        for n in [1, 31, 33, 256] {
            let mut pages = Pages::new(n);
            pages.fill(0, n, REMOTE);
            assert_eq!(pages.claim(0, n, REMOTE, |_| true), n);
            {
                let removing = pages.removing();
                pages.discard(&removing, n / 2, n / 2 + 1);
            }
            let prepared = std::cell::RefCell::new(Vec::new());
            let prepare = |p: usize, c: usize| {
                // Not under `events`: a writer could take it meanwhile.
                drop(pages.events.try_write().expect("prepare runs without events held"));
                assert!((1..=COPY_RUN).contains(&c));
                prepared.borrow_mut().push((p, c));
            };
            let (resolved, result) = pages.install_prepared(0, n, REMOTE, None, Some(&prepare), |p, count| {
                let ready = prepared.borrow().last().map_or(0, |&(a, c)| a + c);
                assert!(p + count <= ready, "copy of {p}+{count} before its source was prepared ({ready})");
                Ok(count.min(17))
            });
            result.unwrap();
            assert_eq!(resolved, n);
            let ranges = prepared.into_inner();
            assert_eq!(ranges.iter().map(|r| r.1).sum::<usize>(), n, "each page once");
            assert!(ranges.windows(2).all(|w| w[0].0 + w[0].1 == w[1].0), "in order, contiguous: {ranges:?}");
        }
    }

    #[test]
    fn install_caps_copies_and_settles_partial_and_discarded_pages() {
        for n in [1, 31, 32, 33, 256, 512] {
            let mut pages = Pages::new(n);
            pages.fill(0, n, REMOTE);
            assert_eq!(pages.claim(0, n, REMOTE, |_| true), n);
            {
                let removing = pages.removing();
                pages.discard(&removing, n / 2, n / 2 + 1);
            }
            let mut copied = 0;
            let (resolved, result) = pages.install(0, n, REMOTE, None, |p, count| {
                assert!((1..=32).contains(&count));
                assert!(!(p..p + count).contains(&(n / 2)));
                let done = count.min(17);
                copied += done;
                Ok(done)
            });
            result.unwrap();
            assert_eq!(resolved, n);
            assert_eq!(copied, n - 1);
            for p in 0..n {
                assert_eq!(pages.get(p), if p == n / 2 { ZERO } else { PRESENT });
            }
        }
    }

    #[test]
    fn present_publishes_dirty() {
        for from in [BASE, ZERO, REMOTE] {
            let mut pages = Pages::new(8192);
            pages.fill(0, pages.len(), from);
            assert_eq!(pages.claim(0, pages.len(), from, |_| true), pages.len());
            thread::scope(|s| {
                s.spawn(|| {
                    for p in 0..pages.len() {
                        while pages.get(p) != PRESENT {
                            std::hint::spin_loop();
                        }
                        assert!(pages.touched(p));
                        assert_ne!(pages.dirty[p / 64].load(Ordering::SeqCst) & (1 << (p % 64)), 0);
                    }
                });
                let (resolved, result) =
                    pages.install(0, pages.len(), from, None, |p, _| if p % 2 == 0 { Ok(1) } else { Err(io::Error::from_raw_os_error(libc::EEXIST)) });
                result.unwrap();
                assert_eq!(resolved, if from == REMOTE { pages.len() } else { 0 });
            });
            assert!(pages.dirty_bits(true).bits.iter().all(|&bits| bits == u64::MAX));
        }
    }
}
