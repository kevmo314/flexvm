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

use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{Pager, ARM_CHUNK, PAGE_SIZE, PRESENT};

/// From linux/mman.h (asm-generic).
const MADV_COLLAPSE: libc::c_int = 25;
/// Calls that all fail with EINVAL before the pass concludes that the kernel cannot collapse here (THP disabled, or a
/// kernel before 6.1).
const EINVAL_GIVE_UP: usize = 16;

/// What the collapse pass did, for `debug VM status`.
#[derive(Default, Clone)]
pub struct CollapseReport {
    /// Chunks entirely PRESENT, so tried.
    pub tried: usize,
    pub collapsed: usize,
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
            "busy_ms": crate::util::ms(self.busy),
            "cpu_ms": crate::util::ms(self.cpu),
            "wall_ms": crate::util::ms(self.wall),
            "done": self.done,
            "stopped": self.stopped,
        })
    }
}

impl Pager {
    /// Starts the collapse pass for when every REMOTE page has arrived.
    pub(super) fn collapse_when_pulled(self: &Arc<Self>) {
        let p = self.clone();
        thread::spawn(move || {
            if p.wait_pulled(None) {
                p.collapse();
            }
        });
    }

    /// The collapse pass, once: chunk by chunk, using at most half a core (after each collapse it sleeps as long as
    /// that took CPU; most of a call is waiting for other CPUs).
    /// Ends early when the pager stops, a checkpoint or migration starts (`quiesce`), or write tracking is armed (the
    /// kernel refuses write-protected chunks).
    fn collapse(&self) {
        let Some(pidfd) = self.pidfd.get() else { return };
        let started = Instant::now();
        let cpu0 = thread_cpu();
        let mut report = CollapseReport::default();
        let pages = self.pages();
        let mut einval = 0;
        'regions: for m in self.mappings() {
            let (first, end) = m.span();
            // The first page whose host address starts a 2 MiB chunk.
            let skew = (m.base_host_virt_addr as usize / PAGE_SIZE) % ARM_CHUNK;
            let mut p = first + (ARM_CHUNK - skew) % ARM_CHUNK;
            while p + ARM_CHUNK <= end {
                if let Some(why) = self.collapse_halt() {
                    report.stopped = Some(why.into());
                    break 'regions;
                }
                if pages.next_not(PRESENT, p, p + ARM_CHUNK) == p + ARM_CHUNK {
                    let (t, cpu) = (Instant::now(), thread_cpu());
                    let res = self.collapse_chunk(pidfd.as_raw_fd(), p);
                    let took = t.elapsed();
                    report.tried += 1;
                    report.busy += took;
                    match res.map_err(|e| e.raw_os_error().unwrap_or(0)) {
                        Ok(()) => report.collapsed += 1,
                        // A zero page or a page missing again (EBUSY), or one being migrated (EAGAIN): not this chunk.
                        Err(libc::EBUSY | libc::EAGAIN) => {}
                        Err(libc::EINVAL) if report.collapsed > 0 || einval < EINVAL_GIVE_UP => einval += 1,
                        Err(e) => {
                            report.stopped = Some(io::Error::from_raw_os_error(e).to_string());
                            break 'regions;
                        }
                    }
                    // At most half a core.
                    thread::sleep(thread_cpu().saturating_sub(cpu));
                }
                p += ARM_CHUNK;
            }
        }
        report.wall = started.elapsed();
        report.cpu = thread_cpu().saturating_sub(cpu0);
        report.done = true;
        if report.tried > 0 {
            eprintln!(
                "uffd: collapsed {} of {} fully paged-in 2 MiB chunks into huge pages in {:.0} ms ({:.0} ms in the kernel, {:.0} ms CPU){}",
                report.collapsed,
                report.tried,
                crate::util::ms(report.wall),
                crate::util::ms(report.busy),
                crate::util::ms(report.cpu),
                report.stopped.as_deref().map(|s| format!("; stopped: {s}")).unwrap_or_default(),
            );
        }
        *self.collapse_report.lock().unwrap() = Some(report);
    }

    fn collapse_halt(&self) -> Option<&'static str> {
        if self.stop.load(Ordering::SeqCst) {
            Some("pager stopped")
        } else if self.quiesce.load(Ordering::SeqCst) {
            Some("checkpoint or migration")
        } else if self.registered_wp.load(Ordering::SeqCst) {
            Some("write tracking")
        } else {
            None
        }
    }

    /// `MADV_COLLAPSE` on the 2 MiB chunk of Firecracker's memory starting at `page`.
    fn collapse_chunk(&self, pidfd: libc::c_int, page: usize) -> io::Result<()> {
        let iov = libc::iovec { iov_base: self.addr(page)? as *mut libc::c_void, iov_len: ARM_CHUNK * PAGE_SIZE };
        match unsafe { libc::syscall(libc::SYS_process_madvise, pidfd, &iov as *const libc::iovec, 1, MADV_COLLAPSE, 0) } {
            n if n == iov.iov_len as libc::c_long => Ok(()),
            n if n >= 0 => Err(io::Error::from_raw_os_error(libc::EBUSY)),
            _ => Err(io::Error::last_os_error()),
        }
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
