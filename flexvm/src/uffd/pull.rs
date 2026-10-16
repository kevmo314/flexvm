use super::event::PULL;
use super::fetch::{Failed, Fetch, FetchFailure, Link};
use super::{os, Pager, ALL, FAULT_FETCHERS, PAGE_SIZE, PULL_RUN, REMOTE};
use crate::checkpoint::{aligned, as_bytes, PageFile};
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Steered runs a puller takes, at most, before each run of its own share.
const STEER_BURST: usize = 4;
const PULL_THREADS: usize = 4;

impl Pager {
    /// Starts the threads that fetch pages for faults (`fetch_faults`) and that pull every REMOTE page in the
    /// background (`pull`), so the source can let go (or, restoring a checkpoint, the VM no longer needs its file).
    pub(super) fn spawn_pullers(self: Arc<Self>) {
        let file = self.file.lock().unwrap().clone();
        // Released already: every page is in.
        if file.is_none() && self.from_file.load(Ordering::SeqCst) {
            return;
        }
        let p = self.clone();
        thread::spawn(move || {
            if p.wait_pulled(None) {
                p.collapse();
            }
        });
        // The connection made for the snapshot load goes to a fault fetcher.
        let mut link = self.remote.lock().unwrap().take();
        let source = link.as_ref().map(|l| l.source.clone());
        for i in 0..FAULT_FETCHERS + PULL_THREADS {
            let (p, puller) = (self.clone(), i >= FAULT_FETCHERS);
            // Reads from the checkpoint file (directly, or evicting what it read for a puller where that is buffered) or
            // over a source connection of its own.
            let mut fetch: Box<Fetch> = match (file.clone(), &source) {
                (Some(file), _) => Box::new(move |off, buf, _, _| {
                    file.read(off as usize / PAGE_SIZE, buf, puller).map_err(|e| io::Error::new(e.kind(), FetchFailure::Checkpoint(e)))
                }),
                (None, Some(source)) if puller => {
                    let mut link = Link::new(source.clone());
                    Box::new(move |off, buf, stop, progress| link.fetch_with(None, off, buf, stop, progress))
                }
                (None, Some(source)) => {
                    let mut link = link.take().unwrap_or_else(|| Link::new(source.clone()));
                    let p = self.clone();
                    Box::new(move |off, buf, stop, progress| link.fetch_with(Some(&p.lanes[i]), off, buf, stop, progress))
                }
                (None, None) => return self.fail("remote pages but nowhere to pull them from".into()),
            };
            let file = file.clone();
            thread::spawn(move || match puller {
                false => {
                    p.fetch_faults(&p.lanes[i], &mut fetch);
                    // Its connection, else left in CLOSE_WAIT for the VM's life.
                    p.lanes[i].detach();
                }
                true => p.pull(i - FAULT_FETCHERS, file, &mut fetch),
            });
        }
    }

    /// Background puller `t` of `PULL_THREADS`: pulls its share of the REMOTE pages, a run at a time, and before each
    /// run, the pages past the latest REMOTE fault (`steered`). `fetch` holds the file (if any) too: let go as the
    /// thread ends, as soon as nothing is left to pull.
    fn pull(&self, t: usize, file: Option<Arc<PageFile>>, fetch: &mut Fetch) {
        // A checkpoint's pages come off local disk: the ones in the template's working set first, as the guest needs
        // them soonest.
        let first = self.chunks(self.working_set(t, PULL_THREADS).filter(|_| file.is_some()), PULL_RUN);
        let all = self.chunks(ALL, PULL_RUN).skip(t).step_by(PULL_THREADS);
        let mut storage = match aligned(PULL_RUN) {
            Ok(buf) => buf,
            Err(e) => return self.fail(format!("allocating background pull buffer: {e}")),
        };
        let buf = as_bytes(&mut storage);
        for (i, end) in first.chain(all) {
            if !self.pulling() {
                break;
            }
            // At most `STEER_BURST` runs before each of its own, so faults that keep coming never hold the rest of the
            // pull back for long.
            for (a, b) in std::iter::from_fn(|| self.steered()).take(STEER_BURST) {
                if !self.pull_range(t, a, b, buf, fetch) {
                    return;
                }
            }
            if !self.pull_range(t, i, end, buf, fetch) {
                return;
            }
        }
    }

    fn pulling(&self) -> bool {
        !self.stop.load(Ordering::SeqCst) && self.remote_left() > 0
    }

    /// The next run of up to `PULL_RUN` pages past the latest REMOTE fault (`steer`), as `[first, end)`, within one of
    /// the 2 MiB chunks runs keep to (see `fault`): regions start on whole MiB.
    fn steered(&self) -> Option<(usize, usize)> {
        let mut steer = self.steer.lock().unwrap();
        let (a, end) = *steer;
        if a >= end {
            return None;
        }
        let b = end.min((a / PULL_RUN + 1) * PULL_RUN);
        steer.0 = b;
        Some((a, b))
    }

    /// Pulls the REMOTE pages of `[i, end)`. False if the pager gave up.
    fn pull_range(&self, t: usize, mut i: usize, end: usize, buf: &mut [u8], fetch: &mut Fetch) -> bool {
        let pages = self.pages();
        while i < end && self.pulling() {
            // Test faults `fetch_enomem_stuck` (only faults fetch pages) and `fetch_tail_enomem` (until a fault took a run).
            while (self.stuck_from.lock().unwrap().is_some() || self.tail_fail.load(Ordering::SeqCst) == 2) && !self.stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
            let n = pages.claim(i, (end - i).min(PULL_RUN), REMOTE, |_| true);
            if n == 0 {
                // On to the next REMOTE page, skipping untouched stretches.
                i = pages.next_in(REMOTE, i + 1, end);
                continue;
            }
            let started = Instant::now();
            // A source that is slow, not gone: on with the rest of the run.
            let res = self.install_claimed(i, n, buf, fetch, |p, c, src| {
                // Test fault `pull_enomem`.
                if self.pull_fail.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |k| k.checked_sub(1)).is_ok() {
                    return Err(os(libc::ENOMEM));
                }
                self.populate(p, c, Some(src))
            });
            self.fault_stats.record(PULL, started.elapsed());
            match res {
                Ok(()) => i += n,
                Err(Failed::Install(e)) if self.unmapped(&e, i, n) => {
                    self.gone();
                    return false;
                }
                Err(Failed::Install(e)) => {
                    if !self.install_retry(i, n, &e, &format!("background pull {t}: installing pages {i}+{n}")) {
                        return false;
                    }
                }
                Err(Failed::Fetch(e)) => {
                    self.fail(format!("background pull {t} failed: {e}"));
                    return false;
                }
            }
        }
        true
    }
}
