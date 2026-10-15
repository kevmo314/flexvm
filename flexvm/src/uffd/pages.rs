use std::io;
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
}

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

    pub(super) fn dirty_count(&self) -> usize {
        self.dirty_chunks().flat_map(|(_, words)| words).map(|w| w.load(Ordering::Relaxed).count_ones() as usize).sum()
    }

    /// The dirty bits, cleared with `take`.
    pub(super) fn dirty_bits(&self, take: bool) -> Vec<u64> {
        let mut bits = vec![0; self.dirty.len()];
        for (at, words) in self.dirty_chunks() {
            for (b, w) in bits[at..at + words.len()].iter_mut().zip(words) {
                *b = if take { w.swap(0, Ordering::SeqCst) } else { w.load(Ordering::SeqCst) };
            }
        }
        bits
    }

    /// Marks dirty again what `dirty_bits` took.
    pub(super) fn restore_dirty(&self, bits: &[u64]) {
        for (w, &b) in self.dirty.iter().zip(bits) {
            if b != 0 {
                w.fetch_or(b, Ordering::SeqCst);
            }
        }
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

    /// Applies a REMOVE of `page`. Returns whether it resolved a REMOTE page.
    pub fn discard(&self, _removing: &RwLockWriteGuard<'_, ()>, page: usize) -> bool {
        self.touch(page);
        let claimed = |s| s == INFLIGHT || s == DISCARDED;
        let old = self.states[page].fetch_update(Ordering::SeqCst, Ordering::SeqCst, |s| Some(if claimed(s) { DISCARDED } else { ZERO }));
        self.mark_dirty(page);
        if !claimed(old.unwrap()) {
            self.forget_failure(page);
        }
        old == Ok(REMOTE)
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
    /// are skipped; EEXIST counts as populated. EAGAIN is retried until `stop` is set, or without `stop` ends the
    /// install. Unfinished pages are given back. Returns the REMOTE pages resolved and the error, if any.
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
            let m = (i + 1..end).find(|&p| self.get(p) != INFLIGHT).unwrap_or(end) - i;
            let gen = self.read_gen.load(Ordering::SeqCst);
            match populate(i, m) {
                Ok(done) => {
                    let done = done.clamp(1, m);
                    self.woke(i, done);
                    resolved += (i..i + done).filter(|&p| self.settle(p, true, from)).count();
                    i += done;
                }
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    resolved += self.settle(i, true, from) as usize;
                    i += 1;
                }
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) && stop.is_some_and(|s| !s.load(Ordering::SeqCst)) => {
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
            assert!(pages.dirty_bits(true).iter().all(|&bits| bits == u64::MAX));
        }
    }
}
