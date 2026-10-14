//! Huge pages for guest memory paged in by a migration or a checkpoint restore (#141).
//!
//! Every page the pager installs is a 4 KiB page, so KVM maps the guest's memory 4 KiB at a time, one exit per page the
//! guest touches. After a migration nothing is mapped in KVM yet, and the guest's first pass over its memory pays for
//! every page: 1 s for 500 MiB under nested virtualization, against 50 ms once mapped. Once the pull is done, a
//! background pass collapses each 2 MiB chunk whose pages are all PRESENT into a transparent huge page
//! (`process_madvise(MADV_COLLAPSE)` on Firecracker), which KVM then maps with one 2 MiB entry.
//!
//! The kernel only collapses a chunk of a userfaultfd-registered range whose 512 pages are all mapped, none of them the
//! zero page and none write-protected, and checks again under the mmap write lock before it copies anything. So a
//! collapse never fills a missing page behind the pager's back nor drops a write protection a checkpoint relies on.
//! Contents stay the same, so page states do not change. A discard of a whole chunk (free page reporting and virtio-mem
//! work in 2 MiB blocks or more) frees the huge page; a smaller one splits it, and still raises a REMOVE and later a
//! missing fault as before. Write-protecting a huge page protects it whole; unprotecting part of it splits it.
//!
//! Each call first drains every host CPU's LRU caches (`lru_add_drain_all`), interrupting every other VM's vCPUs, so
//! consecutive collapsible chunks go in one call (`BATCH`, #191). The kernel goes on past some failed chunks but stops
//! at others (a zero page among the 512): a batch that fails is split in halves and each tried again, down to single
//! chunks, so one chunk that cannot collapse costs a few calls more and does not hold back the rest of its batch.

use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{Pager, ARM_CHUNK, PAGE_SIZE, PRESENT};

/// From linux/mman.h (asm-generic).
const MADV_COLLAPSE: libc::c_int = 25;
/// Chunks per call at most: one LRU drain on every CPU for up to 32 MiB, and a pause waits out at most one call.
const BATCH: usize = 16;
/// Calls that all fail with EINVAL before the pass concludes that the kernel cannot collapse here (THP disabled, or a
/// kernel before 6.1).
const EINVAL_GIVE_UP: usize = 16;
/// No huge page to be had (ENOMEM, a fragmented host): the pass waits before going on, from this long, twice as long
/// after each such call in a row up to `ENOMEM_BACKOFF_MAX` (time for compaction), and gives up after `ENOMEM_GIVE_UP`
/// in a row (about 7 s of waiting).
const ENOMEM_BACKOFF: Duration = Duration::from_millis(100);
const ENOMEM_BACKOFF_MAX: Duration = Duration::from_secs(2);
const ENOMEM_GIVE_UP: usize = 8;
/// Why a pass ends at a checkpoint or migration; one that aborts (`Pager::unquiesce`) starts it again.
pub(super) const QUIESCED: &str = "checkpoint or migration";

/// The collapse pass's gate, under `Pager::collapse_gate`'s mutex, which the pass holds across each call.
#[derive(Default)]
pub(super) struct Gate {
    /// The VM is (about to be) paused: no call starts until it is cleared (`hold_collapse`).
    held: bool,
    /// A pass is running.
    running: bool,
}

/// What the collapse pass did, for `debug VM status`.
#[derive(Default, Clone)]
pub struct CollapseReport {
    /// Chunks entirely PRESENT, so tried.
    pub tried: usize,
    pub collapsed: usize,
    /// `process_madvise` calls made for them.
    pub calls: usize,
    /// Time spent in the kernel collapsing, and the CPU time of it: the rest is waiting (mostly for every CPU to drain
    /// its LRU caches, once per call).
    pub busy: Duration,
    pub cpu: Duration,
    pub wall: Duration,
    pub done: bool,
    /// Why the pass ended early, if it did.
    pub stopped: Option<String>,
}

impl CollapseReport {
    pub fn json(&self) -> Value {
        json!({
            "tried": self.tried,
            "collapsed": self.collapsed,
            "calls": self.calls,
            "busy_ms": crate::util::ms(self.busy),
            "cpu_ms": crate::util::ms(self.cpu),
            "wall_ms": crate::util::ms(self.wall),
            "done": self.done,
            "stopped": self.stopped,
        })
    }
}

/// What to do after a call.
#[derive(Debug, PartialEq)]
enum Next {
    Go,
    /// Wait this long first.
    Backoff(Duration),
    Stop(String),
}

/// The calls of one pass: runs of up to `BATCH` chunks (`first page`, chunks), split when a call fails.
#[derive(Default)]
struct Batches {
    todo: Vec<(usize, usize)>,
    collapsed: usize,
    einval: usize,
    enomem: usize,
}

impl Batches {
    fn pop(&mut self) -> Option<(usize, usize)> {
        self.todo.pop()
    }

    /// Tries `[first, first + n)` again as two halves, the first half next; a single chunk is left as it is.
    fn split(&mut self, first: usize, n: usize) {
        if n > 1 {
            let h = n / 2;
            self.todo.push((first + h * ARM_CHUNK, n - h));
            self.todo.push((first, h));
        }
    }

    /// The call on `n` chunks from `first` returned `res` (an errno on failure).
    fn done(&mut self, first: usize, n: usize, res: Result<(), i32>) -> Next {
        match res {
            Ok(()) => {
                self.collapsed += n;
                self.enomem = 0;
            }
            // A zero page or a page missing again (EBUSY), or one being migrated (EAGAIN): not every chunk collapsed.
            Err(libc::EBUSY | libc::EAGAIN) => self.split(first, n),
            Err(libc::EINVAL) if self.collapsed > 0 || self.einval < EINVAL_GIVE_UP => {
                self.einval += 1;
                self.split(first, n);
            }
            // Usually passing: what did not collapse is tried once more after a while (a single chunk is skipped).
            Err(libc::ENOMEM) => {
                self.enomem += 1;
                if self.enomem >= ENOMEM_GIVE_UP {
                    return Next::Stop(format!("{} (no huge page to be had, {ENOMEM_GIVE_UP} times in a row)", io::Error::from_raw_os_error(libc::ENOMEM)));
                }
                self.split(first, n);
                return Next::Backoff((ENOMEM_BACKOFF * (1 << (self.enomem - 1))).min(ENOMEM_BACKOFF_MAX));
            }
            Err(e) => return Next::Stop(io::Error::from_raw_os_error(e).to_string()),
        }
        Next::Go
    }
}

impl Pager {
    /// Starts the collapse pass for when every REMOTE page has arrived (unless test fault `no_collapse` is on then).
    pub(super) fn collapse_when_pulled(self: &Arc<Self>) {
        let p = self.clone();
        thread::spawn(move || {
            if p.wait_pulled(None) && !crate::host::fault("no_collapse") {
                p.collapse();
            }
        });
    }

    /// The collapse pass: runs of collapsible chunks, `BATCH` at most per call, using at most half a core: after each
    /// call it sleeps as long as the call took (mostly waiting for other CPUs to drain their caches, work this thread's
    /// CPU time does not show). Ends early when the pager stops, a checkpoint or migration starts (`quiesce`), or write
    /// tracking is armed (the kernel refuses write-protected chunks). Once only, unless it ended for `QUIESCED`.
    pub(super) fn collapse(&self) {
        let Some(pidfd) = self.pidfd.get() else { return };
        {
            let mut g = self.collapse_gate.0.lock().unwrap();
            let mut report = self.collapse_report.lock().unwrap();
            if g.running || report.as_ref().is_some_and(|r| r.stopped.as_deref() != Some(QUIESCED)) {
                return;
            }
            // Until this pass ends, there is no report: as before the first.
            *report = None;
            g.running = true;
        }
        let started = Instant::now();
        let cpu0 = thread_cpu();
        let mut report = CollapseReport::default();
        let mut b = Batches::default();
        let pages = self.pages();
        let full = |p: usize, n: usize| pages.next_not(PRESENT, p, p + n * ARM_CHUNK) == p + n * ARM_CHUNK;
        'regions: for m in self.mappings() {
            let (first, end) = m.span();
            // The first page whose host address starts a 2 MiB chunk.
            let skew = (m.base_host_virt_addr as usize / PAGE_SIZE) % ARM_CHUNK;
            let mut p = first + (ARM_CHUNK - skew) % ARM_CHUNK;
            while p + ARM_CHUNK <= end {
                let mut n = 0;
                while n < BATCH && p + (n + 1) * ARM_CHUNK <= end && full(p + n * ARM_CHUNK, 1) {
                    n += 1;
                }
                if n == 0 {
                    p += ARM_CHUNK;
                    continue;
                }
                report.tried += n;
                b.todo.push((p, n));
                p += n * ARM_CHUNK;
                while let Some((c, n)) = b.pop() {
                    let gate = match self.collapse_turn() {
                        Ok(g) => g,
                        Err(why) => {
                            report.stopped = Some(why.into());
                            break 'regions;
                        }
                    };
                    // Paused meanwhile, a chunk may have been discarded (the kernel would refuse it too).
                    if !full(c, n) {
                        drop(gate);
                        b.split(c, n);
                        continue;
                    }
                    let t = Instant::now();
                    let res = self.collapse_chunks(pidfd.as_raw_fd(), c, n);
                    drop(gate);
                    let took = t.elapsed();
                    report.calls += 1;
                    report.busy += took;
                    match b.done(c, n, res.map_err(|e| e.raw_os_error().unwrap_or(0))) {
                        Next::Go => thread::sleep(took),
                        Next::Backoff(d) => self.collapse_pause(took.max(d)),
                        Next::Stop(why) => {
                            report.stopped = Some(why);
                            break 'regions;
                        }
                    }
                }
            }
        }
        report.collapsed = b.collapsed;
        report.wall = started.elapsed();
        report.cpu = thread_cpu().saturating_sub(cpu0);
        report.done = true;
        if report.tried > 0 {
            eprintln!(
                "uffd: collapsed {} of {} fully paged-in 2 MiB chunks into huge pages in {} calls, {:.0} ms ({:.0} ms in the kernel, {:.0} ms CPU){}",
                report.collapsed,
                report.tried,
                report.calls,
                crate::util::ms(report.wall),
                crate::util::ms(report.busy),
                crate::util::ms(report.cpu),
                report.stopped.as_deref().map(|s| format!("; stopped: {s}")).unwrap_or_default(),
            );
        }
        let mut g = self.collapse_gate.0.lock().unwrap();
        *self.collapse_report.lock().unwrap() = Some(report);
        g.running = false;
    }

    /// Waits while the pass is held (paused, or about to be), until it may make a call (holding the gate meanwhile),
    /// or must end: for the halt that follows a checkpoint or migration, when it resumes or the pager stops.
    fn collapse_turn(&self) -> Result<MutexGuard<'_, Gate>, &'static str> {
        let mut g = self.collapse_gate.0.lock().unwrap();
        loop {
            if let Some(why) = self.collapse_halt() {
                return Err(why);
            }
            if !g.held {
                return Ok(g);
            }
            g = self.collapse_gate.1.wait(g).unwrap();
        }
    }

    /// Sleeps `d`, or less if the pager stops.
    fn collapse_pause(&self, d: Duration) {
        let g = self.collapse_gate.0.lock().unwrap();
        let _ = self.collapse_gate.1.wait_timeout_while(g, d, |_| !self.stop.load(Ordering::SeqCst));
    }

    fn collapse_halt(&self) -> Option<&'static str> {
        if self.stop.load(Ordering::SeqCst) {
            Some("pager stopped")
        } else if self.quiesce.load(Ordering::SeqCst) {
            Some(QUIESCED)
        } else if self.registered_wp.load(Ordering::SeqCst) {
            Some("write tracking")
        } else {
            None
        }
    }

    /// `MADV_COLLAPSE` on the `n` 2 MiB chunks of Firecracker's memory from `page`: Ok only if all of them are huge
    /// pages now.
    fn collapse_chunks(&self, pidfd: libc::c_int, page: usize, n: usize) -> io::Result<()> {
        let iov = libc::iovec { iov_base: self.addr(page)? as *mut libc::c_void, iov_len: n * ARM_CHUNK * PAGE_SIZE };
        match unsafe { libc::syscall(libc::SYS_process_madvise, pidfd, &iov as *const libc::iovec, 1, MADV_COLLAPSE, 0) } {
            r if r == iov.iov_len as libc::c_long => Ok(()),
            r if r >= 0 => Err(io::Error::from_raw_os_error(libc::EBUSY)),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Holds the collapse pass off (`true`), waiting out a collapse in flight, or lets it go on (`false`). Before any
    /// pause: a collapse takes the mmap write lock and may compact memory, which a pause must not wait behind. A
    /// checkpoint or migration then ends the pass (`quiesce`).
    pub fn hold_collapse(&self, hold: bool) {
        self.collapse_gate.0.lock().unwrap().held = hold;
        if !hold {
            self.collapse_gate.1.notify_all();
        }
    }

    /// Waits out a collapse call in flight and keeps any from starting until dropped.
    pub(super) fn collapse_barrier(&self) -> MutexGuard<'_, Gate> {
        self.collapse_gate.0.lock().unwrap()
    }

    /// Wakes a held pass, to see that the pager stopped.
    pub(super) fn wake_collapse(&self) {
        drop(self.collapse_gate.0.lock().unwrap());
        self.collapse_gate.1.notify_all();
    }

    /// Whether a pass ended for a checkpoint or migration (and none runs), with the gate held so none starts meanwhile.
    pub(super) fn collapse_quiesced(&self) -> bool {
        let g = self.collapse_gate.0.lock().unwrap();
        !g.running && self.collapse_report.lock().unwrap().as_ref().is_some_and(|r| r.stopped.as_deref() == Some(QUIESCED))
    }

    /// What the collapse pass did, once it ran.
    pub fn collapse_report(&self) -> Option<Value> {
        self.collapse_report.lock().unwrap().as_ref().map(CollapseReport::json)
    }
}

/// This thread's CPU time so far.
fn thread_cpu() -> Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `Batches` over `n` chunks from page 0, `fails` saying which chunks a call fails at (with which errno); a
    /// call fails with the errno of the first failing chunk in it. Returns the calls made, as (first chunk, chunks).
    fn drive(n: usize, fails: impl Fn(usize) -> Option<i32>) -> (Vec<(usize, usize)>, Batches, Vec<Next>) {
        let mut b = Batches::default();
        b.todo.push((0, n));
        let (mut calls, mut nexts) = (Vec::new(), Vec::new());
        while let Some((p, n)) = b.pop() {
            let c = p / ARM_CHUNK;
            calls.push((c, n));
            let res = (c..c + n).find_map(&fails).map_or(Ok(()), Err);
            match b.done(p, n, res) {
                Next::Go => {}
                Next::Stop(why) => {
                    nexts.push(Next::Stop(why));
                    break;
                }
                next => nexts.push(next),
            }
        }
        (calls, b, nexts)
    }

    #[test]
    fn a_batch_collapses_in_one_call() {
        let (calls, b, nexts) = drive(BATCH, |_| None);
        assert_eq!(calls, [(0, BATCH)]);
        assert_eq!((b.collapsed, nexts), (BATCH, vec![]));
    }

    #[test]
    fn a_chunk_that_cannot_collapse_is_bisected_out() {
        let (calls, b, _) = drive(16, |c| (c == 5).then_some(libc::EBUSY));
        assert_eq!(b.collapsed, 15);
        // 1 + 2 per level: every chunk but 5 collapses, in 9 calls rather than 16.
        assert_eq!(calls, [(0, 16), (0, 8), (0, 4), (4, 4), (4, 2), (4, 1), (5, 1), (6, 2), (8, 8)]);
    }

    #[test]
    fn einval_gives_up_only_when_nothing_ever_collapsed() {
        let (calls, b, nexts) = drive(4, |_| Some(libc::EINVAL));
        assert_eq!((b.collapsed, calls.len()), (0, 7));
        assert!(nexts.is_empty());
        let mut b = Batches { einval: EINVAL_GIVE_UP, ..Default::default() };
        assert!(matches!(b.done(0, 1, Err(libc::EINVAL)), Next::Stop(_)));
        b.collapsed = 1;
        assert_eq!(b.done(0, 1, Err(libc::EINVAL)), Next::Go);
    }

    #[test]
    fn enomem_backs_off_and_gives_up_only_in_a_row() {
        let mut b = Batches::default();
        let ms = |n| Next::Backoff(Duration::from_millis(n));
        let waits = [100, 200, 400, 800, 1600, 2000, 2000];
        for &w in &waits {
            assert_eq!(b.done(0, 2, Err(libc::ENOMEM)), ms(w));
        }
        assert_eq!(b.done(0, 1, Ok(())), Next::Go);
        for &w in &waits {
            assert_eq!(b.done(0, 1, Err(libc::ENOMEM)), ms(w));
        }
        assert!(matches!(b.done(0, 1, Err(libc::ENOMEM)), Next::Stop(_)));
        // A failed batch is retried in halves.
        let (calls, b, nexts) = drive(2, |c| (c == 0).then_some(libc::ENOMEM));
        assert_eq!((calls, b.collapsed, nexts), (vec![(0, 2), (0, 1), (1, 1)], 1, vec![ms(100), ms(200)]));
    }

    #[test]
    fn other_errors_end_the_pass() {
        let (calls, _, nexts) = drive(8, |c| (c == 3).then_some(libc::EPERM));
        assert_eq!(calls, [(0, 8)]);
        assert!(matches!(&nexts[..], [Next::Stop(_)]));
    }
}
