use super::event::PULL;
use super::fetch::{connect_ahead, Failed, Fetch, FetchFailure, Lane, Link, STREAM_RUN};
use super::{os, Pager, ALL, FAULT_FETCHERS, PAGE_SIZE, PULL_RUN, PULL_THREADS, REMOTE};
use crate::checkpoint::{Buf, PageFile};
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Steered runs a puller takes, at most, before each run of its own share.
const STEER_BURST: usize = 4;
/// Runs a puller has queued from a migration source, their requests out: it installs the oldest as the next is on its
/// way, so its connection does not sit idle a round trip per run.
const PULL_DEPTH: usize = 2;

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
        if !self.pulling() {
            return;
        }
        // The handshake's link goes to a fault fetcher; each worker connects on its own thread.
        let mut link = self.remote.lock().unwrap().take();
        let source = link.as_ref().map(|l| l.source.clone());
        for i in 0..FAULT_FETCHERS + PULL_THREADS {
            let (p, puller) = (self.clone(), i >= FAULT_FETCHERS);
            // Reads from the checkpoint file (directly, or evicting what it read for a puller where that is buffered) or
            // over a source connection of its own.
            let mut fetch: Box<Fetch> = match (file.clone(), &source) {
                (Some(file), _) => Box::new(move |off, buf, stop, progress| {
                    read_file(off, buf, stop, progress, |page, buf| {
                        file.read(page, buf, puller).map_err(|e| io::Error::new(e.kind(), FetchFailure::Checkpoint(e)))
                    })
                }),
                (None, Some(source)) => {
                    let mut link = link.take().filter(|_| !puller).unwrap_or_else(|| Link::new(source.clone()));
                    let p = self.clone();
                    Box::new(move |off, buf, stop, progress| {
                        // Test gate `fetch_connect_gate`: the last fault fetcher's connect ahead (on a link of its own)
                        // waits until the test lets it; no fault runs go to it meanwhile (`queue_fault`).
                        if i == FAULT_FETCHERS - 1 && buf.is_empty() {
                            crate::host::hold("fetch_connect_gate");
                        }
                        link.fetch_with(Some(&p.lanes[i]), off, buf, &|| stop.load(Ordering::SeqCst) || p.remote_left() == 0, progress)
                    })
                }
                (None, None) => return self.fail("remote pages but nowhere to pull them from".into()),
            };
            let file = file.clone();
            thread::spawn(move || {
                match puller {
                    false => p.fetch_faults(&p.lanes[i], &mut fetch),
                    true => p.pull(i - FAULT_FETCHERS, file, &mut fetch, &p.lanes[i]),
                }
                // Its connection, else left in CLOSE_WAIT for the VM's life.
                p.lanes[i].detach();
            });
        }
    }

    /// Background puller `t` of `PULL_THREADS`: pulls its share of the REMOTE pages, a run at a time, and before each
    /// run, the pages past the latest REMOTE fault (`steered`). Its runs queue on `lane` (see `PULL_DEPTH`). `fetch`
    /// holds the file (if any) too: let go as the thread ends, as soon as nothing is left to pull.
    fn pull(&self, t: usize, file: Option<Arc<PageFile>>, fetch: &mut Fetch, lane: &Lane) {
        // Test gate `pull_gate`: the background pull starts only once the test lets it (faults fetch meanwhile).
        crate::host::hold("pull_gate");
        // A checkpoint's pages come off local disk: the ones in the template's working set first, as the guest needs
        // them soonest. One read at a time: a run claimed ahead would only keep a fault on it waiting.
        let depth = if file.is_some() { 1 } else { PULL_DEPTH };
        let first = self.chunks(self.working_set(t, PULL_THREADS).filter(|_| file.is_some()), PULL_RUN);
        let all = self.chunks(ALL, PULL_RUN).skip(t).step_by(PULL_THREADS);
        let mut storage = match Buf::plain(PULL_RUN) {
            Ok(buf) => buf,
            Err(e) => return self.fail(format!("allocating background pull buffer: {e}")),
        };
        let buf = storage.bytes();
        // Connects ahead (nothing to read), so each run's request goes out as it is queued; a failure shows again later.
        if file.is_none() {
            let _ = connect_ahead(fetch, &self.stop, || self.pulling());
        }
        let mut ok = true;
        for (i, end) in first.chain(all) {
            if !ok || !self.pulling() {
                break;
            }
            // At most `STEER_BURST` runs before each of its own, so faults that keep coming never hold the rest of the
            // pull back for long.
            for (a, b) in std::iter::from_fn(|| self.steered()).take(STEER_BURST) {
                ok = ok && self.pull_range(t, a, b, depth, buf, fetch, lane);
            }
            ok = ok && self.pull_range(t, i, end, depth, buf, fetch, lane);
        }
        while ok && lane.front().1 > 0 {
            ok = self.pull_next(t, buf, fetch, lane);
        }
        // Runs still queued as the pager gave up go back.
        while let (Some((i, n, _)), _) = lane.front() {
            lane.pop();
            self.pulled(self.pages().release(i, n, REMOTE));
        }
    }

    pub(super) fn pulling(&self) -> bool {
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

    /// Claims the REMOTE pages of `[i, end)` a run at a time and queues them on `lane`, pulling the oldest whenever
    /// `depth` are. False if the pager gave up.
    #[allow(clippy::too_many_arguments)]
    fn pull_range(&self, t: usize, mut i: usize, end: usize, depth: usize, buf: &mut [u8], fetch: &mut Fetch, lane: &Lane) -> bool {
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
            lane.push((i, n, Instant::now()));
            i += n;
            while lane.front().1 >= depth {
                if !self.pull_next(t, buf, fetch, lane) {
                    return false;
                }
            }
        }
        true
    }

    /// Fetches and installs the oldest run queued on `lane`. False if the pager gave up.
    fn pull_next(&self, t: usize, buf: &mut [u8], fetch: &mut Fetch, lane: &Lane) -> bool {
        let (Some((i, n, _)), _) = lane.front() else { return true };
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
        lane.pop();
        match res {
            Ok(()) => true,
            Err(Failed::Install(e)) if self.unmapped(&e, i, n) => {
                self.gone();
                false
            }
            Err(Failed::Install(e)) => {
                if !self.install_retry(i, n, &e, &format!("background pull {t}: installing pages {i}+{n}")) {
                    return false;
                }
                // What went back to REMOTE goes to the back of the queue.
                self.reclaim(i, n, |job| lane.push(job));
                true
            }
            Err(Failed::Fetch(e)) => {
                self.fail(format!("background pull {t} failed: {e}"));
                false
            }
        }
    }
}

/// Publish each disk chunk through the same progress callback as a streamed reply: the run's first `STREAM_RUN` pages,
/// then the rest. The head is where a fault lands (a steered run starts just past the latest fault); a read per
/// `STREAM_RUN` pages, one at a time, made a 256-page run take ~2.5x as long. A stop between chunks is
/// `FetchFailure::Cancelled`, as for a source, not a (fatal) checkpoint error.
fn read_file(
    off: u64,
    buf: &mut [u8],
    stop: &std::sync::atomic::AtomicBool,
    progress: &mut dyn FnMut(&[u8]) -> bool,
    mut read: impl FnMut(usize, &mut [u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        if stop.load(Ordering::SeqCst) {
            return Err(io::Error::other(FetchFailure::Cancelled));
        }
        let end = if done == 0 { (STREAM_RUN * PAGE_SIZE).min(buf.len()) } else { buf.len() };
        read((off as usize + done) / PAGE_SIZE, &mut buf[done..end])?;
        done = end;
        if !progress(&buf[..done]) {
            return Err(io::Error::other(FetchFailure::Cancelled));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{Pages, INFLIGHT, PRESENT};
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn file_chunks_settle_before_the_next_read() {
        for fail in [false, true] {
            let (first, n) = (7, 2 * STREAM_RUN + 3);
            let mut pages = Pages::new(first + n);
            pages.fill(first, n, REMOTE);
            assert_eq!(pages.claim(first, n, REMOTE, |_| true), n);
            let stop = AtomicBool::new(false);
            let mut reads = 0;
            let mut fetch = |off, buf: &mut [u8], stop: &AtomicBool, progress: &mut dyn FnMut(&[u8]) -> bool| {
                read_file(off, buf, stop, progress, |page, out| {
                    assert!((first..page).all(|p| pages.get(p) == PRESENT), "earlier chunks settled before this read");
                    assert!((page..first + n).all(|p| pages.get(p) == INFLIGHT));
                    reads += 1;
                    if fail && reads == 2 {
                        return Err(os(libc::EIO));
                    }
                    for (i, chunk) in out.chunks_mut(PAGE_SIZE).enumerate() {
                        chunk.fill((page + i) as u8);
                    }
                    Ok(())
                })
            };
            let (resolved, result) = pages.fetch_install(first, n, &mut vec![0; n * PAGE_SIZE], &mut fetch, &stop, &mut |_| false, |page, count, data| {
                for (i, chunk) in data.chunks(PAGE_SIZE).enumerate() {
                    assert!(chunk.iter().all(|&b| b == (page + i) as u8));
                }
                Ok(count)
            });
            let done = if fail { STREAM_RUN } else { n };
            assert_eq!(resolved, done);
            assert_eq!(result.is_err(), fail);
            assert!((first..first + done).all(|p| pages.get(p) == PRESENT));
            assert!((first + done..first + n).all(|p| pages.get(p) == REMOTE));
        }
    }

    #[test]
    fn file_read_stops_between_chunks() {
        for stop_before in [false, true] {
            let stop = AtomicBool::new(stop_before);
            let mut reads = 0;
            let result = read_file(0, &mut vec![0; PULL_RUN * PAGE_SIZE], &stop, &mut |_| false, |_, _| {
                reads += 1;
                Ok(())
            });
            let e = result.unwrap_err();
            assert!(matches!(super::super::fetch::fetch_failure(&e), Some(FetchFailure::Cancelled)));
            assert!(!super::super::fetch::fatal(&e));
            assert_eq!(reads, usize::from(!stop_before));
        }
    }
}
