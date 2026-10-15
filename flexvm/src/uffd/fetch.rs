use super::event::{FETCH, FIRST, QUEUED};
use super::{os, Pager, Pages, Source, FAULT_TIMEOUT, PAGE_SIZE, REMOTE, REMOTE_FAULT_RUN};
use std::collections::VecDeque;
use std::io::{self, IoSliceMut, Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How long the migration source may stay unreachable before the pager gives up.
const SOURCE_TIMEOUT: Duration = Duration::from_secs(10);

/// Fetched pages are installed as they arrive: the first at once, then at least this many at a time.
pub(super) const STREAM_RUN: usize = 16;
const BACKOFF_MAX: Duration = Duration::from_secs(1);
pub(super) const BACKOFF_MIN: Duration = Duration::from_millis(10);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// How long one page request may take, writing it and reading its reply, before its connection is given up as lost (and
/// the pager reconnects).
const FETCH_DEADLINE: Duration = if cfg!(test) { Duration::from_millis(300) } else { Duration::from_secs(5) };

/// Why `Pages::fetch_install` stopped.
pub(super) enum Failed {
    Fetch(io::Error),
    Install(io::Error),
}

impl Pages {
    /// Fetches claimed REMOTE pages `first..first + n` with `fetch` (into `buf`) and installs them as they arrive with
    /// `populate(page, count, data)` (as `install` does): the first one as soon as it is in, as a fault waits for it,
    /// then at least `STREAM_RUN` at a time, so that a fault on any of them waits only for its part of the transfer. A
    /// failed fetch is tried again, for what has yet to arrive, while `retry` says so. Pages it does not install are
    /// given back. Returns the REMOTE pages resolved, and the error that stopped it.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn fetch_install(
        &self,
        first: usize,
        n: usize,
        buf: &mut [u8],
        fetch: &mut FetchAny<'_>,
        stop: &AtomicBool,
        retry: &mut dyn FnMut(&io::Error) -> bool,
        mut populate: impl FnMut(usize, usize, &[u8]) -> io::Result<usize>,
    ) -> (usize, std::result::Result<(), Failed>) {
        // Installs pages `from..to` (counted from `first`) out of `data`, which holds them from page `base` on.
        let mut install = |from: usize, to: usize, data: &[u8], base: usize| {
            let src = |p: usize, c: usize| &data[(p - first - base) * PAGE_SIZE..(p - first - base + c) * PAGE_SIZE];
            self.install(first + from, to - from, REMOTE, Some(stop), |p, c| populate(p, c, src(p, c)))
        };
        // Pages from `first` installed (or given back by a failed install).
        let (mut done, mut resolved) = (0, 0);
        let mut failed: Option<io::Error> = None;
        loop {
            let base = done;
            // Pages from `first` in `buf`, installed or not.
            let mut arrived = base;
            let fetched = fetch(((first + base) * PAGE_SIZE) as u64, &mut buf[base * PAGE_SIZE..n * PAGE_SIZE], stop, &mut |data| {
                let ready = base + data.len() / PAGE_SIZE;
                arrived = ready;
                if failed.is_none() && ready > done && (done == 0 || ready - done >= STREAM_RUN) {
                    let (r, res) = install(done, ready, data, base);
                    resolved += r;
                    failed = res.err();
                    done = ready;
                }
                // After a failed install, the rest of the reply is read and dropped rather than cut short: the
                // connection then serves the retry (cutting it would reconnect on every retry, as memory is short).
                // Only a stop cuts it.
                failed.is_none() || !stop.load(Ordering::SeqCst)
            });
            match fetched {
                _ if failed.is_some() => break,
                Ok(()) => {
                    if done < n {
                        let (r, res) = install(done, n, &buf[..n * PAGE_SIZE], 0);
                        resolved += r;
                        failed = res.err();
                        done = n;
                    }
                    break;
                }
                Err(e) if done < n && retry(&e) => {
                    // What did arrive goes in, so the next try asks only for the rest.
                    if arrived > done {
                        let (r, res) = install(done, arrived, &buf[..n * PAGE_SIZE], 0);
                        resolved += r;
                        done = arrived;
                        if let Err(e) = res {
                            failed = Some(e);
                            break;
                        }
                    }
                }
                Err(e) => return (resolved + self.release(first + done, n - done, REMOTE), Err(Failed::Fetch(e))),
            }
        }
        match failed {
            None => (resolved, Ok(())),
            Some(e) => (resolved + self.release(first + done, n - done, REMOTE), Err(Failed::Install(e))),
        }
    }
}

impl Pager {
    /// Only a partial fetch is retried: a link waits out a source outage itself, and its other errors are final.
    pub(super) fn retry_fetch(&self, e: &io::Error) -> bool {
        partial(e) && !self.stop.load(Ordering::SeqCst)
    }

    /// Failure history stays with the pages, whoever claimed them, so no retry starts the deadline over.
    pub(super) fn install_retry(&self, page: usize, n: usize, e: &io::Error, what: &str) -> bool {
        let since = self.pages().failing_since(page, n).unwrap_or_else(Instant::now);
        if since.elapsed() >= FAULT_TIMEOUT {
            self.fail(format!("{what}: {e}"));
            return false;
        }
        crate::log!("uffd: {what}: {e}; retrying");
        thread::sleep(BACKOFF_MIN);
        true
    }

    /// Queues a run of REMOTE pages a fault claimed for the fault fetcher with the fewest runs queued (see `Lane`),
    /// passing over one busy writing requests.
    pub(super) fn queue_fault(&self, job: Job) {
        let queued = |l: &Lane| l.q.try_lock().map_or(usize::MAX, |q| q.jobs.len());
        let lane = self.lanes.iter().min_by_key(|l| queued(l)).unwrap();
        lane.push(job);
    }

    /// Fetches and installs the runs faults claimed (`lane`), so that the event thread never waits for the network or
    /// disk. The faulting thread is woken by the copy, the event thread by the pages settling.
    pub(super) fn fetch_faults(&self, lane: &Lane, fetch: &mut Fetch) {
        let mut buf = vec![0u8; REMOTE_FAULT_RUN * PAGE_SIZE];
        let pages = self.pages();
        // Connects ahead of the first fault (nothing to read).
        if let Err(e) = fetch(0, &mut [], &self.stop, &mut |_| true) {
            if !self.stop.load(Ordering::SeqCst) {
                return self.fail(format!("fetching pages for faults: {e}"));
            }
        }
        loop {
            let (page, n, queued) = {
                let mut q = lane.q.lock().unwrap();
                loop {
                    if self.stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Some(front) = q.jobs.front() {
                        break front.job;
                    }
                    // Claimed pages count as left until they settle, so with none left no fault can queue another run.
                    if self.remote_left() == 0 {
                        return;
                    }
                    q = lane.cv.wait_timeout(q, Duration::from_millis(100)).unwrap().0;
                }
            };
            self.fault_stats.record(QUEUED, queued.elapsed());
            // Pages that have kept failing past the deadline, however they were queued again: give up now rather than
            // after one more try.
            if pages.failing_since(page, n).is_some_and(|t| t.elapsed() >= FAULT_TIMEOUT) {
                return self.fail(format!("installing pages {page}+{n} for a fault kept failing for {FAULT_TIMEOUT:?}"));
            }
            let started = Instant::now();
            // Test fault `fetch_tail_enomem`: once the pullers are past this run, a copy of its tail fails as if memory
            // were short.
            let tail_fail = self.tail_fail.load(Ordering::SeqCst) > 0;
            let mut held = false;
            let mut fetch = |off: u64, buf: &mut [u8], stop: &AtomicBool, progress: &mut dyn FnMut(&[u8]) -> bool| {
                fetch(off, buf, stop, &mut |data: &[u8]| {
                    if tail_fail && !held && data.len() > PAGE_SIZE {
                        held = true;
                        let t = Instant::now();
                        while self.remote_left() > n && t.elapsed() < Duration::from_secs(5) {
                            thread::sleep(Duration::from_millis(1));
                        }
                    }
                    progress(data)
                })
            };
            let mut first = true;
            let stuck = *self.stuck_from.lock().unwrap();
            let res = self.install_claimed(page, n, &mut buf, &mut fetch, |p, c, src| {
                if tail_fail && p != page && self.tail_fail.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |k| k.checked_sub(1)).is_ok() {
                    return Err(os(libc::ENOMEM));
                }
                // Test fault `fetch_enomem_stuck`.
                if stuck.is_some_and(|t| Instant::now() >= t) {
                    return Err(os(libc::ENOMEM));
                }
                let r = self.populate(p, c, Some(src));
                if std::mem::take(&mut first) {
                    self.fault_stats.record(FIRST, queued.elapsed());
                }
                r
            });
            self.fault_stats.record(FETCH, started.elapsed());
            lane.pop();
            match res {
                Ok(()) => {}
                Err(Failed::Fetch(_)) if self.stop.load(Ordering::SeqCst) => {}
                Err(Failed::Fetch(e)) => return self.fail(format!("fetching pages for a fault: {e}")),
                Err(Failed::Install(e)) if self.unmapped(&e, page, n) => return self.gone(),
                Err(Failed::Install(e)) => {
                    if !self.install_retry(page, n, &e, &format!("installing pages {page}+{n} for a fault")) {
                        return;
                    }
                    // What went back to REMOTE may have no fault waiting on it any more (the faulting page went in
                    // first) and the pullers may be past it: queue it again, with its failure history, so it is not
                    // stranded.
                    let mut i = page;
                    while i < page + n {
                        match pages.claim(i, page + n - i, REMOTE, |_| true) {
                            0 => i += 1,
                            k => {
                                self.queue_fault((i, k, Instant::now()));
                                i += k;
                            }
                        }
                    }
                }
            }
        }
    }

    /// `Pages::fetch_install`, counting the REMOTE pages resolved. A fetch that failed once every page was resolved
    /// anyway (discarded meanwhile) is no failure.
    pub(super) fn install_claimed(
        &self,
        first: usize,
        n: usize,
        buf: &mut [u8],
        fetch: &mut FetchAny<'_>,
        populate: impl FnMut(usize, usize, &[u8]) -> io::Result<usize>,
    ) -> std::result::Result<(), Failed> {
        let (resolved, res) = self.pages().fetch_install(first, n, buf, fetch, &self.stop, &mut |e| self.retry_fetch(e), populate);
        self.pulled(resolved);
        match res {
            Err(Failed::Fetch(_)) if resolved == n => Ok(()),
            r => r,
        }
    }
}

/// A fault fetcher's queue: the runs faults claimed (`Job`s), oldest first, which it fetches in order. From a migration
/// source, each run's request goes out on the fetcher's connection as it is queued (`push`, by the event thread), so it
/// is on its way before the fetcher wakes, and behind replies still arriving: requests are pipelined, and replies come
/// in their order.
#[derive(Default)]
pub(super) struct Lane {
    pub(super) q: Mutex<LaneQueue>,
    pub(super) cv: Condvar,
}

#[derive(Default)]
pub(super) struct LaneQueue {
    jobs: VecDeque<Queued>,
    /// The fetcher's connection, while it has one, to write requests on.
    conn: Option<TcpStream>,
    /// How many jobs, from the front, have their request out on `conn`.
    pub(super) sent: usize,
    /// The fetcher is writing requests on `conn` (see `Lane::flush`).
    writing: bool,
}

struct Queued {
    job: Job,
    /// What its request asks for, `(offset, len)`: the run, or what is left of it to fetch again.
    req: (u64, usize),
}

impl Lane {
    /// Queues `job`, writing its request now if the connection takes it without blocking; otherwise the fetcher writes
    /// it.
    pub(super) fn push(&self, job: Job) {
        let mut q = self.q.lock().unwrap();
        let req = ((job.0 * PAGE_SIZE) as u64, job.1 * PAGE_SIZE);
        q.jobs.push_back(Queued { job, req });
        if !q.writing && q.sent + 1 == q.jobs.len() {
            if let Some(conn) = &q.conn {
                let (buf, len) = request(req.0, req.1, PAGE_SIZE);
                let n = unsafe { libc::send(conn.as_raw_fd(), buf.as_ptr().cast(), len, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
                match n {
                    n if n == len as isize => q.sent += 1,
                    n if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock => {}
                    // Part of a request, or the connection failed: the fetcher reconnects and asks again.
                    _ => {
                        let _ = conn.shutdown(std::net::Shutdown::Both);
                        q.conn = None;
                    }
                }
            }
        }
        self.cv.notify_one();
    }

    /// The fetcher is done with the front job.
    pub(super) fn pop(&self) {
        let mut q = self.q.lock().unwrap();
        q.jobs.pop_front();
        q.sent = q.sent.saturating_sub(1);
    }

    /// Takes `conn` for requests, and writes those not out yet. Before reading the reply to `req`, the front job's:
    /// fails if its request was out asking for something else (the connection must go). Every write ends by `at`, the
    /// deadline of the fetcher's attempt.
    fn flush(&self, conn: &TcpStream, req: Option<(u64, usize)>, at: Instant) -> io::Result<()> {
        let mut q = self.q.lock().unwrap();
        if q.conn.is_none() {
            q.conn = Some(conn.try_clone()?);
            q.sent = 0;
        }
        if let Some((front, req)) = q.jobs.front_mut().zip(req).filter(|(f, req)| f.req != *req) {
            front.req = req;
            if q.sent > 0 {
                return Err(io::Error::other("refetching part of a run"));
            }
        }
        // Written without holding `q`, so that queueing (the event thread) never waits for a write; it writes nothing
        // meanwhile (`writing`), which keeps requests in order.
        while q.sent < q.jobs.len() {
            let mut out = Vec::new();
            for j in q.jobs.range(q.sent..) {
                let (buf, len) = request(j.req.0, j.req.1, PAGE_SIZE);
                out.extend_from_slice(&buf[..len]);
            }
            let upto = q.jobs.len();
            q.writing = true;
            drop(q);
            let res = crate::util::By { s: conn, at }.write_all(&out);
            q = self.q.lock().unwrap();
            q.writing = false;
            res?;
            q.sent = upto;
        }
        Ok(())
    }

    /// The fetcher's connection is gone: requests go out again on the next.
    pub(super) fn detach(&self) {
        let mut q = self.q.lock().unwrap();
        q.conn = None;
        q.sent = 0;
    }
}

/// A page-server connection to the migration source that reconnects with backoff, and gives up once the source has been
/// unreachable for `SOURCE_TIMEOUT`.
pub(super) struct Link {
    pub(super) source: Source,
    pub(super) client: Option<PageClient>,
    addrs: SourceAddrs,
    /// When the current outage began.
    down: Option<Instant>,
    retry_at: Instant,
    backoff: Duration,
}

impl Link {
    pub(super) fn new(source: Source) -> Link {
        Link { source, client: None, addrs: SourceAddrs::default(), down: None, retry_at: Instant::now(), backoff: BACKOFF_MIN }
    }

    pub(super) fn connect(&mut self) -> io::Result<PageClient> {
        let at = Instant::now() + CONNECT_TIMEOUT;
        let stream = self.addrs.connect(&self.source.addr, at)?;
        PageClient::new(stream, &self.source, at)
    }

    /// Reads guest memory, optionally from `lane`'s queued request. Reconnects until stopped or the outage is too long.
    pub(super) fn fetch_with(
        &mut self,
        lane: Option<&Lane>,
        offset: u64,
        buf: &mut [u8],
        stop: &AtomicBool,
        progress: &mut dyn FnMut(&[u8]) -> bool,
    ) -> io::Result<()> {
        // A fault waits for the first page of its run: it is asked for first.
        let head = if lane.is_some() { PAGE_SIZE } else { 0 };
        loop {
            let Some(client) = self.client.as_mut() else {
                if stop.load(Ordering::SeqCst) {
                    return Err(io::Error::other("pager stopped"));
                }
                thread::sleep(self.retry_at.saturating_duration_since(Instant::now()));
                match self.connect() {
                    Ok(c) => self.client = Some(c),
                    Err(e) => self.lost(e)?,
                }
                continue;
            };
            let at = Instant::now() + FETCH_DEADLINE;
            let mut got = 0;
            let mut counted = |data: &[u8]| {
                got = data.len();
                progress(data)
            };
            let res = match lane {
                Some(lane) if buf.is_empty() => lane.flush(&client.stream.s.s, None, at),
                Some(lane) => lane.flush(&client.stream.s.s, Some((offset, buf.len())), at).and_then(|()| client.recv(buf, head, &mut counted, at)),
                None => client.fetch(offset, buf, head, &mut counted, at),
            };
            match res {
                Ok(()) => {
                    self.down = None;
                    self.backoff = BACKOFF_MIN;
                    return Ok(());
                }
                Err(e) => {
                    self.client = None;
                    if let Some(lane) = lane {
                        lane.detach();
                    }
                    // Stopped by the caller: the source is fine.
                    if matches!(fetch_failure(&e), Some(FetchFailure::Cancelled)) {
                        return Err(e);
                    }
                    // Pages kept arriving, just not all in time: the source is alive, and the caller asks for the rest
                    // (`partial`).
                    if got >= PAGE_SIZE {
                        self.down = None;
                        self.backoff = BACKOFF_MIN;
                        self.retry_at = Instant::now();
                        return Err(io::Error::other(FetchFailure::Partial(e.to_string())));
                    }
                    self.lost(e)?;
                }
            }
        }
    }

    /// Schedules a reconnect after `e`, or gives up.
    pub(super) fn lost(&mut self, e: io::Error) -> io::Result<()> {
        let since = *self.down.get_or_insert_with(Instant::now);
        if since.elapsed() >= SOURCE_TIMEOUT {
            let why = format!("migration source {} unreachable for {:?}: {e}", self.source.addr, since.elapsed());
            return Err(io::Error::new(io::ErrorKind::TimedOut, FetchFailure::SourceLost(why)));
        }
        if self.backoff == BACKOFF_MIN {
            crate::log!("uffd: page fetch from {} failed, reconnecting: {e}", self.source.addr);
        }
        self.retry_at = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
        Ok(())
    }
}

/// Whether a migration source serves pages at all: fetches `page`, retrying as a pager would (for up to
/// `SOURCE_TIMEOUT`, and not past `deadline`).
pub fn probe(source: &Source, page: u64, deadline: Instant) -> io::Result<()> {
    let mut addrs = SourceAddrs::default();
    probe_with_connect(source, page, deadline, |addr, timeout| addrs.connect(addr, Instant::now() + timeout))
}

/// The source's addresses, looked up once: reconnects need no lookup, which a stalled resolver could hold past
/// `SOURCE_TIMEOUT`. After a connect to them fails, the next one looks them up again (a source whose name now
/// resolves elsewhere), with half its time, and keeps the old ones if that lookup fails.
#[derive(Default)]
struct SourceAddrs {
    addrs: Vec<std::net::SocketAddr>,
    stale: bool,
}

impl SourceAddrs {
    fn connect(&mut self, name: &str, at: Instant) -> io::Result<TcpStream> {
        if self.addrs.is_empty() {
            self.addrs = crate::util::resolve(name, at)?;
        } else if std::mem::take(&mut self.stale) {
            let now = Instant::now();
            if let Ok(addrs) = crate::util::resolve(name, now + at.saturating_duration_since(now) / 2) {
                self.addrs = addrs;
            }
        }
        let s = crate::util::connect_addrs(&self.addrs, at).inspect_err(|_| self.stale = true)?;
        s.set_nodelay(true)?;
        Ok(s)
    }
}

fn probe_with_connect<S: crate::util::Timed>(
    source: &Source,
    page: u64,
    deadline: Instant,
    mut connect: impl FnMut(&str, Duration) -> io::Result<S>,
) -> io::Result<()> {
    let give_up = deadline.min(Instant::now() + SOURCE_TIMEOUT);
    let mut backoff = BACKOFF_MIN;
    // Bound connects separately so SYN retries cannot consume the whole outage
    // budget. The request and every read still share the overall deadline.
    let mut once = || {
        let left = give_up.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline passed"));
        }
        let s = connect(&source.addr, left.min(CONNECT_TIMEOUT))?;
        let mut client = PageClient::new(s, source, give_up)?;
        client.fetch(page * PAGE_SIZE as u64, &mut [0u8; PAGE_SIZE], 0, &mut |_| true, give_up)
    };
    loop {
        let e = match once() {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        if Instant::now() + backoff >= give_up {
            return Err(io::Error::new(io::ErrorKind::TimedOut, format!("no page from {} in time: {e}", source.addr)));
        }
        thread::sleep(backoff);
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// The request for `len` bytes of guest memory at `offset`: with `head` (bytes, less than `len`), the first `head`
/// bytes are asked for on their own, ahead of the rest, so the server reads and sends them without waiting to read the
/// rest out of guest memory. Returns it and its length.
fn request(offset: u64, len: usize, head: usize) -> ([u8; 24], usize) {
    let mut req = [0u8; 24];
    for (i, (a, b)) in parts(len, head).enumerate() {
        req[i * 12..i * 12 + 8].copy_from_slice(&(offset + a as u64).to_le_bytes());
        req[i * 12 + 8..i * 12 + 12].copy_from_slice(&((b - a) as u32).to_le_bytes());
    }
    (req, 12 * parts(len, head).count())
}

/// The byte ranges `request` asks for, each answered on its own.
fn parts(len: usize, head: usize) -> impl Iterator<Item = (usize, usize)> {
    let split = head > 0 && head < len;
    let first = if split { head } else { len };
    std::iter::once((0, first)).chain(split.then_some((head, len)))
}

/// Client for a migration source's page server. Every write and read of a request ends by the deadline it is given,
/// however slowly the server trickles.
pub struct PageClient<S = TcpStream> {
    stream: crate::util::By<crate::util::ReadTimeoutCache<S>>,
    /// Whether the server's answer to the `pages` request has been read: it is read along with the first reply, so
    /// connecting costs no round trip.
    acked: bool,
}

impl PageClient {
    #[cfg(test)]
    pub fn connect(source: &Source) -> io::Result<Self> {
        Link::new(source.clone()).connect()
    }
}

impl<S: crate::util::Timed> PageClient<S> {
    pub(super) fn new(stream: S, source: &Source, at: Instant) -> io::Result<Self> {
        let mut hello = serde_json::to_vec(&serde_json::json!({"op": "pages", "name": source.vm, "mig": source.mig}))?;
        hello.push(b'\n');
        let mut stream = crate::util::By { s: crate::util::ReadTimeoutCache::new(stream), at };
        stream.write_all(&hello)?;
        Ok(PageClient { stream, acked: false })
    }

    /// Reads guest memory at `offset` into `buf` by `at`, calling `progress` with what has arrived so far as it does,
    /// the first `head` bytes asked for on their own (see `request`).
    pub fn fetch(&mut self, offset: u64, buf: &mut [u8], head: usize, progress: &mut dyn FnMut(&[u8]) -> bool, at: Instant) -> io::Result<()> {
        let (req, len) = request(offset, buf.len(), head);
        self.stream.at = at;
        self.stream.write_all(&req[..len])?;
        self.recv(buf, head, progress, at)
    }

    /// Reads the reply to a request (`request(_, buf.len(), head)`) into `buf` by `at`, as `fetch` does.
    fn recv(&mut self, buf: &mut [u8], head: usize, progress: &mut dyn FnMut(&[u8]) -> bool, at: Instant) -> io::Result<()> {
        self.stream.at = at;
        if !self.acked {
            self.read_ack()?;
            self.acked = true;
        }
        for (a, b) in parts(buf.len(), head) {
            // The status byte is read along with the first of the data, in one read. After a failed status the
            // connection is dropped, so whatever followed it in `buf` goes unreported.
            let (mut status_read, mut filled) = (false, a);
            while !status_read || filled < b {
                let mut status = [0u8; 1];
                let res = match status_read {
                    false => self.stream.read_vectored(&mut [IoSliceMut::new(&mut status), IoSliceMut::new(&mut buf[filled..b])]),
                    true => self.stream.read(&mut buf[filled..b]),
                };
                let mut n = match res {
                    Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                if !status_read {
                    if status[0] != 0 {
                        return Err(io::Error::other("page server could not read guest memory"));
                    }
                    status_read = true;
                    n -= 1;
                }
                if n > 0 {
                    filled += n;
                    if !progress(&buf[..filled]) {
                        return Err(io::Error::other(FetchFailure::Cancelled));
                    }
                }
            }
        }
        Ok(())
    }

    /// Reads the page server's answer to the `pages` request: one JSON line, `{"ok": true}` before the binary protocol,
    /// or why it refuses (then it hangs up). Read a byte at a time, so nothing after it is consumed.
    fn read_ack(&mut self) -> io::Result<()> {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        while b[0] != b'\n' {
            if line.len() >= 4096 {
                return Err(io::Error::other("page server sent an overlong answer"));
            }
            if self.stream.read(&mut b)? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "page server hung up before answering"));
            }
            line.push(b[0]);
        }
        let v: serde_json::Value = serde_json::from_slice(&line).map_err(|e| io::Error::other(format!("page server answer: {e}")))?;
        if v["ok"] != serde_json::json!(true) {
            let why = v["error"].as_str().unwrap_or("no reason given");
            return Err(io::Error::other(format!("page server refused: {why}")));
        }
        Ok(())
    }
}

/// Fetch outcomes carried through the public client's `io::Result` API.
#[derive(Debug)]
pub(super) enum FetchFailure {
    /// A fetch its caller stopped part way (`progress` said so, as the pager stops); what was left of the reply is
    /// unread, so the connection goes.
    Cancelled,
    /// A fetch that delivered pages, but not all of them, before its connection failed (say, past its deadline from a
    /// slow source): the caller fetches the rest (see `Pages::fetch_install`).
    Partial(String),
    /// The migration source has been unreachable for `SOURCE_TIMEOUT` (fatal).
    SourceLost(String),
    /// A read of the checkpoint page file failed or did not match its checksums (fatal).
    Checkpoint(io::Error),
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("fetch cancelled"),
            Self::Partial(why) => write!(f, "fetch cut short after some pages arrived: {why}"),
            Self::SourceLost(why) => f.write_str(why),
            Self::Checkpoint(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for FetchFailure {}

fn fetch_failure(e: &io::Error) -> Option<&FetchFailure> {
    e.get_ref()?.downcast_ref()
}

pub(super) fn partial(e: &io::Error) -> bool {
    matches!(fetch_failure(e), Some(FetchFailure::Partial(_)))
}

/// Reads guest memory at an offset from wherever REMOTE pages come from, reporting what has arrived as it does (see
/// `PageClient::fetch`; a file read reports nothing).
pub(super) type Fetch = dyn FnMut(u64, &mut [u8], &AtomicBool, &mut dyn FnMut(&[u8]) -> bool) -> io::Result<()> + Send;
/// `Fetch`, borrowed and not necessarily `Send`.
type FetchAny<'a> = dyn FnMut(u64, &mut [u8], &AtomicBool, &mut dyn FnMut(&[u8]) -> bool) -> io::Result<()> + 'a;
/// A run of REMOTE pages a fault claimed, `(first, count)`, and when it was queued.
type Job = (usize, usize, Instant);

/// Errors after which the pager gives up on the VM: its migration source has been gone too long, or its checkpoint file
/// is unreadable or corrupt.
pub(super) fn fatal(e: &io::Error) -> bool {
    matches!(fetch_failure(e), Some(FetchFailure::SourceLost(_) | FetchFailure::Checkpoint(_)))
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    #[test]
    fn source_addresses_are_kept_and_looked_up_again_only_after_a_failed_connect() {
        let at = || Instant::now() + Duration::from_secs(2);
        let (one, two) = (std::net::TcpListener::bind("127.0.0.1:0").unwrap(), std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        let (one_addr, two_addr) = (one.local_addr().unwrap(), two.local_addr().unwrap());
        let mut addrs = SourceAddrs::default();
        addrs.connect(&one_addr.to_string(), at()).unwrap();
        // Connected: a reconnect looks nothing up (this name would fail).
        addrs.connect("invalid address", at()).unwrap();
        drop(one);
        assert!(addrs.connect("invalid address", at()).is_err());
        // Its lookup fails: the old addresses are tried again.
        assert!(addrs.connect("invalid address", at()).is_err());
        assert_eq!(addrs.addrs, vec![one_addr]);
        // The name now resolves elsewhere.
        addrs.connect(&two_addr.to_string(), at()).unwrap();
        assert_eq!(addrs.addrs, vec![two_addr]);
    }

    struct Reply(io::Cursor<Vec<u8>>);

    impl Read for Reply {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for Reply {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl crate::util::Timed for Reply {
        fn read_timeout(&self, _: Duration) -> io::Result<()> {
            Ok(())
        }
        fn write_timeout(&self, _: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_connect_attempts_survive_a_three_second_outage() {
        let source = Source { addr: "source".into(), vm: "v".into(), mig: 1, regions: Vec::new() };
        let start = Instant::now();
        let mut attempts = 0;
        probe_with_connect(&source, 2, start + SOURCE_TIMEOUT, |_, timeout| {
            assert!(timeout <= CONNECT_TIMEOUT, "a connect must not consume the outage budget");
            attempts += 1;
            if start.elapsed() < Duration::from_secs(3) {
                // Model a blackholed SYN consuming its entire per-attempt timeout.
                thread::sleep(timeout);
                Err(io::Error::new(io::ErrorKind::TimedOut, "source temporarily unreachable"))
            } else {
                let mut reply = b"{\"ok\": true}\n".to_vec();
                reply.extend_from_slice(&[0u8; PAGE_SIZE + 1]);
                Ok(Reply(io::Cursor::new(reply)))
            }
        })
        .unwrap();
        assert!(attempts > 1);
        assert!(start.elapsed() < SOURCE_TIMEOUT);
    }

    #[test]
    fn connects_are_bounded_by_the_remaining_deadline() {
        let source = Source { addr: "unused".into(), vm: "v".into(), mig: 1, regions: Vec::new() };
        let budget = Duration::from_millis(70);
        let start = Instant::now();
        let mut attempts = 0;
        let err = probe_with_connect::<Reply>(&source, 0, start + budget, |_, timeout| {
            attempts += 1;
            assert!(timeout <= budget);
            thread::sleep(timeout);
            Err(io::Error::new(io::ErrorKind::TimedOut, "source unreachable"))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(attempts, 1);
        assert!(start.elapsed() < CONNECT_TIMEOUT);

        let err = probe_with_connect::<Reply>(&source, 0, Instant::now(), |_, _| panic!("connecting after the deadline")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
