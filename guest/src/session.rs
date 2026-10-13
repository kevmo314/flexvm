//! Resumable command output. Socket writers never hold the process pumps' lock.
//!
//! Limits: at most `MAX_LIVE` sessions are live (running, or finished and not yet
//! closed by their client); a further `SESSION` fails with an explicit error.
//! Closed sessions leave a small tombstone (id and time) so a delayed retry of
//! their `SESSION` cannot run the command again; tombstones have their own,
//! larger cap. Each live session's ring keeps `BASE` bytes and grows towards
//! `CAPACITY` only out of a shared pool, so all of them together retain at most
//! `MAX_LIVE * BASE + POOL` bytes of output.
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::{spawn, wait_pid, write_frame, Statuses, FRAME_EXIT, FRAME_MSG, FRAME_STDERR, FRAME_STDOUT};

const CAPACITY: usize = 4 * 1024 * 1024;
const MAX_CHUNKS: usize = 4096;
const READ_SIZE: usize = 16 * 1024;
const MAX_LIVE: usize = 64;
const MAX_TOMBSTONES: usize = 4096;
/// Output every live session may keep without drawing on the pool.
const BASE: usize = 128 * 1024;
/// Shared by all rings for growth beyond `BASE`, in `STEP`s.
const POOL: usize = 64 * 1024 * 1024 - MAX_LIVE * BASE;
const STEP: usize = 256 * 1024;
const RETENTION: Duration = Duration::from_secs(300);
/// How long output keeps waiting for a dropped client (the CLI retries for 30 s).
const GRACE: Duration = Duration::from_secs(30);
/// A finished session whose client has been gone this long will not be resumed
/// (the CLI gives up 30 s after its last frame): it becomes a tombstone.
const ABANDONED: Duration = Duration::from_secs(60);
pub const FRAME_LOST: u8 = 5;

type Session = Arc<(Mutex<Output>, Condvar)>;
pub type Sessions = Arc<Mutex<Table>>;

pub struct Table {
    live: HashMap<String, Entry>,
    /// Closed (or abandoned) session ids, and when they were closed.
    closed: HashMap<String, Instant>,
    pool: Arc<AtomicUsize>,
}

impl Default for Table {
    fn default() -> Table {
        Table { live: HashMap::new(), closed: HashMap::new(), pool: Arc::new(AtomicUsize::new(POOL)) }
    }
}

struct Entry {
    /// Identifies the command, so a retried SESSION is recognised without keeping
    /// up to a megabyte of it around; IDs are random, so this is only a check.
    command: (usize, u64),
    output: Session,
}

fn fingerprint(command: &[u8]) -> (usize, u64) {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    command.hash(&mut h);
    (command.len(), h.finish())
}

impl Table {
    /// Turns a live session into a tombstone, freeing its output.
    fn close(&mut self, id: &str) {
        if let Some(entry) = self.live.remove(id) {
            let mut output = entry.output.0.lock().unwrap();
            output.closed = true;
            output.chunks = VecDeque::new();
            output.start = output.end;
            output.reservation.release();
            drop(output);
            entry.output.1.notify_all();
            self.closed.insert(id.to_string(), Instant::now());
        }
    }

    /// Closes finished sessions whose client went away and did not come back.
    fn reclaim(&mut self) {
        let abandoned: Vec<String> = self
            .live
            .iter()
            .filter(|(_, entry)| {
                let output = entry.output.0.lock().unwrap();
                output.exit.is_some() && output.readers == 0 && output.detached.is_some_and(|t| t.elapsed() >= ABANDONED)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in abandoned {
            self.close(&id);
        }
    }

    fn admit(&mut self) -> io::Result<()> {
        if self.live.len() >= MAX_LIVE {
            self.reclaim();
        }
        if self.live.len() >= MAX_LIVE {
            return Err(io::Error::other(format!(
                "too many sessions: {MAX_LIVE} commands are running or awaiting their client"
            )));
        }
        if self.closed.len() >= MAX_TOMBSTONES {
            // The oldest tombstone's client acknowledged its exit long ago; only a
            // badly delayed retry of its creation could still arrive.
            let oldest = self.closed.iter().min_by_key(|(_, at)| **at).map(|(id, at)| (id.clone(), *at));
            match oldest {
                Some((id, at)) if at.elapsed() >= GRACE => {
                    self.closed.remove(&id);
                }
                _ => return Err(io::Error::other("too many sessions finished in the last 30 s")),
            }
        }
        Ok(())
    }
}

struct Chunk {
    kind: u8,
    offset: u64,
    data: Vec<u8>,
}

/// Bytes a ring holds beyond `BASE`, taken from the table's pool and given
/// back when the session is closed or its output dropped, whichever is first.
#[derive(Default)]
struct Reservation {
    pool: Option<Arc<AtomicUsize>>,
    bytes: usize,
}

impl Reservation {
    /// Tries to make room for `need` bytes; growth is best effort.
    fn grow(&mut self, need: usize) {
        let Some(pool) = &self.pool else { return };
        let have = BASE + self.bytes;
        if need <= have || have >= CAPACITY {
            return;
        }
        let want = need.div_ceil(STEP).saturating_mul(STEP).min(CAPACITY) - have;
        if let Ok(avail) = pool.fetch_update(Ordering::AcqRel, Ordering::Acquire, |a| Some(a - a.min(want))) {
            self.bytes += avail.min(want);
        }
    }

    fn release(&mut self) {
        if let Some(pool) = &self.pool {
            pool.fetch_add(std::mem::take(&mut self.bytes), Ordering::AcqRel);
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Default)]
struct Output {
    chunks: VecDeque<Chunk>,
    start: u64,
    end: u64,
    exit: Option<(i32, Instant)>,
    closed: bool,
    // While a client is attached, or recently was, output waits for it instead of
    // overwriting what it has not been sent; half the ring is slack for bytes in flight.
    readers: usize,
    sent: u64,
    detached: Option<Instant>,
    reservation: Reservation,
}

impl Output {
    fn capacity(&self) -> usize {
        BASE + self.reservation.bytes
    }

    /// Appends output, then drops the oldest so at most `capacity` bytes remain;
    /// the chunks hold exactly `end - start` bytes.
    fn push(&mut self, kind: u8, data: &[u8], capacity: usize) {
        self.chunks.push_back(Chunk { kind, offset: self.end, data: data.to_vec() });
        self.end += data.len() as u64;
        // Bound metadata too, even when a command produces many one-byte reads.
        while self.chunks.len() > MAX_CHUNKS {
            self.chunks.pop_front();
        }
        let keep = self.end.saturating_sub(capacity as u64);
        while let Some(chunk) = self.chunks.front_mut() {
            let end = chunk.offset + chunk.data.len() as u64;
            if end <= keep {
                self.chunks.pop_front();
            } else {
                if chunk.offset < keep {
                    chunk.data.drain(..(keep - chunk.offset) as usize);
                    chunk.data.shrink_to_fit();
                    chunk.offset = keep;
                }
                break;
            }
        }
        self.start = self.chunks.front().map_or(self.end, |c| c.offset);
    }

    fn read(&self, offset: u64) -> Option<(u8, Vec<u8>)> {
        self.chunks.iter().find(|c| c.offset + c.data.len() as u64 > offset).map(|c| {
            let mut data = offset.to_le_bytes().to_vec();
            data.extend_from_slice(&c.data[(offset - c.offset) as usize..]);
            (c.kind, data)
        })
    }
}

pub enum Request<'a> {
    Start { id: &'a str, len: usize },
    Attach { id: &'a str, offset: u64 },
    Close { id: &'a str },
}

pub fn parse(line: &str) -> io::Result<Request<'_>> {
    let parts: Vec<_> = line.split_whitespace().collect();
    let id = parts.get(1).copied().unwrap_or("");
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(io::Error::other("bad session id"));
    }
    match parts.as_slice() {
        ["SESSION", _, len] => {
            let len = len.parse::<usize>().map_err(|_| io::Error::other("bad command length"))?;
            if len > 1024 * 1024 {
                return Err(io::Error::other("command too large"));
            }
            Ok(Request::Start { id, len })
        }
        ["ATTACH", _, offset] => {
            Ok(Request::Attach { id, offset: offset.parse().map_err(|_| io::Error::other("bad offset"))? })
        }
        ["CLOSE", _] => Ok(Request::Close { id }),
        _ => Err(io::Error::other("bad session request")),
    }
}

/// Runs every minute: abandoned sessions become tombstones, which expire.
pub fn cleanup(sessions: &Sessions) {
    let mut table = sessions.lock().unwrap();
    table.reclaim();
    table.closed.retain(|_, at| at.elapsed() < RETENTION);
}

/// Request errors are reported as a message frame; write errors just end the stream,
/// since a frame may have been cut short and anything after it would corrupt it.
pub fn handle(mut w: impl Write, r: impl Read, line: &str, sessions: &Sessions, statuses: &Statuses) -> io::Result<()> {
    match open(r, line, sessions, statuses) {
        Ok(Some((id, offset, output))) => {
            let result = write_frame(&mut w, FRAME_MSG, id.as_bytes()).and_then(|_| drain(&mut w, &output, offset));
            let mut ring = output.0.lock().unwrap();
            ring.readers -= 1;
            ring.detached = Some(Instant::now());
            drop(ring);
            output.1.notify_all();
            result
        }
        Ok(None) => write_frame(&mut w, FRAME_MSG, b"closed"),
        Err(e) => fail(&mut w, e),
    }
}

fn fail(w: &mut impl Write, e: impl std::fmt::Display) -> io::Result<()> {
    write_frame(w, FRAME_MSG, format!("error: {e}").as_bytes())
}

fn open<'a>(mut r: impl Read, line: &'a str, sessions: &Sessions, statuses: &Statuses) -> io::Result<Option<(&'a str, u64, Session)>> {
    Ok(Some(match parse(line)? {
        Request::Start { id, len } => {
            let mut command = vec![0; len];
            r.read_exact(&mut command)?;
            let fingerprint = fingerprint(&command);
            // Serialize lookup and spawn: retrying a lost creation reply cannot spawn twice.
            let mut table = sessions.lock().unwrap();
            if table.closed.contains_key(id) {
                return Err(io::Error::other("session closed"));
            }
            let output = if let Some(entry) = table.live.get(id) {
                if entry.command != fingerprint {
                    return Err(io::Error::other("session id already used for another command"));
                }
                attach(&entry.output, 0)
            } else {
                table.admit()?;
                let command_text = std::str::from_utf8(&command).map_err(io::Error::other)?;
                let reservation = Reservation { pool: Some(table.pool.clone()), bytes: 0 };
                let output = Arc::new((Mutex::new(Output { readers: 1, reservation, ..Default::default() }), Condvar::new()));
                // Start the pump first: if no thread can be had, nothing has run yet.
                let (tx, rx) = mpsc::sync_channel::<Child>(1);
                let (pumped, statuses_) = (output.clone(), statuses.clone());
                thread::Builder::new()
                    .spawn(move || {
                        if let Ok(child) = rx.recv() {
                            run(child, pumped, &statuses_);
                        }
                    })
                    .map_err(|e| io::Error::new(e.kind(), format!("cannot start session thread: {e}")))?;
                let child = spawn(
                    Command::new("/bin/sh")
                        .args(["-c", command_text])
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped()),
                    statuses,
                    true,
                )
                // Minimal images (distroless, scratch) have no shell.
                .map_err(|e| io::Error::new(e.kind(), format!("cannot run /bin/sh: {e} (does the image have a shell?)")))?;
                table.live.insert(id.to_string(), Entry { command: fingerprint, output: output.clone() });
                // The pump thread holds the receiver until it gets this.
                let _ = tx.send(child);
                output
            };
            (id, 0, output)
        }
        Request::Attach { id, offset } => {
            let table = sessions.lock().unwrap();
            if table.closed.contains_key(id) {
                return Err(io::Error::other("session closed"));
            }
            (id, offset, attach(&table.live.get(id).ok_or_else(|| io::Error::other("unknown session"))?.output, offset))
        }
        Request::Close { id } => {
            let mut table = sessions.lock().unwrap();
            // Closing again (a retried acknowledgement) is fine.
            if table.closed.contains_key(id) {
                return Ok(None);
            }
            let entry = table.live.get(id).ok_or_else(|| io::Error::other("unknown session"))?;
            if entry.output.0.lock().unwrap().exit.is_none() {
                return Err(io::Error::other("session still running"));
            }
            table.close(id);
            return Ok(None);
        }
    }))
}

fn attach(output: &Session, offset: u64) -> Session {
    let mut ring = output.0.lock().unwrap();
    ring.readers += 1;
    ring.sent = offset;
    output.clone()
}

/// Copies the command's stdout and stderr into its ring, then records its exit.
fn run(mut child: Child, output: Session, statuses: &Statuses) {
    let pid = child.id() as i32;
    let mut streams: Vec<(File, u8)> = [
        child.stdout.take().map(|s| (File::from(OwnedFd::from(s)), FRAME_STDOUT)),
        child.stderr.take().map(|s| (File::from(OwnedFd::from(s)), FRAME_STDERR)),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut buf = [0; READ_SIZE];
    while !streams.is_empty() {
        let mut fds: Vec<libc::pollfd> =
            streams.iter().map(|(f, _)| libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLIN, revents: 0 }).collect();
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        for i in (0..fds.len()).rev() {
            if fds[i].revents == 0 {
                continue;
            }
            match streams[i].0.read(&mut buf) {
                Ok(0) => drop(streams.remove(i)),
                Ok(n) => deliver(&output, streams[i].1, &buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => drop(streams.remove(i)),
            }
        }
    }
    drop(streams);
    let code = wait_pid(statuses, pid);
    output.0.lock().unwrap().exit = Some((code, Instant::now()));
    output.1.notify_all();
}

fn deliver(output: &Session, kind: u8, data: &[u8]) {
    let mut ring = output.0.lock().unwrap();
    let need = (ring.end - ring.start) as usize + data.len();
    ring.reservation.grow(need);
    while ring.end.saturating_sub(ring.sent) >= ring.capacity() as u64 / 2
        && (ring.readers > 0 || ring.detached.is_some_and(|t| t.elapsed() < GRACE))
    {
        ring = output.1.wait_timeout(ring, Duration::from_secs(1)).unwrap().0;
    }
    let capacity = ring.capacity();
    ring.push(kind, data, capacity);
    drop(ring);
    output.1.notify_all();
}

fn drain(w: &mut impl Write, output: &Session, mut offset: u64) -> io::Result<()> {
    loop {
        let (kind, data) = {
            let ring = output.0.lock().unwrap();
            if ring.closed {
                drop(ring);
                return fail(w, "session closed");
            }
            if offset > ring.end {
                drop(ring);
                return fail(w, "offset past output end");
            }
            if offset < ring.start {
                (FRAME_LOST, ring.start.to_le_bytes().to_vec())
            } else if let Some(frame) = ring.read(offset) {
                frame
            } else if let Some((code, _)) = ring.exit {
                let mut data = offset.to_le_bytes().to_vec();
                data.extend_from_slice(&code.to_le_bytes());
                (FRAME_EXIT, data)
            } else {
                let (guard, timeout) = output.1.wait_timeout(ring, Duration::from_secs(1)).unwrap();
                drop(guard);
                if !timeout.timed_out() {
                    continue;
                }
                (FRAME_MSG, b"waiting".to_vec())
            }
        };
        write_frame(w, kind, &data)?;
        match kind {
            FRAME_STDOUT | FRAME_STDERR => {
                offset += (data.len() - 8) as u64;
                output.0.lock().unwrap().sent = offset;
                output.1.notify_all();
            }
            FRAME_EXIT | FRAME_LOST => return Ok(()),
            _ => {}
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn finished(table: &mut Table, id: &str, detached: Option<Instant>) -> Session {
        let reservation = Reservation { pool: Some(table.pool.clone()), bytes: 0 };
        let output = Arc::new((Mutex::new(Output {
            exit: Some((0, Instant::now())), detached, reservation, ..Default::default()
        }), Condvar::new()));
        table.live.insert(id.to_string(), Entry { command: fingerprint(b"true"), output: output.clone() });
        output
    }

    fn statuses() -> Statuses {
        Arc::new((Mutex::new(HashMap::new()), Condvar::new()))
    }

    #[test]
    fn closed_sessions_do_not_count_against_the_live_limit() {
        let sessions = Sessions::default();
        let statuses = statuses();
        // Many more sequential commands than the live limit, each acknowledged.
        for i in 0..MAX_LIVE * 3 {
            let mut table = sessions.lock().unwrap();
            table.admit().unwrap();
            finished(&mut table, &i.to_string(), None);
            drop(table);
            handle(Vec::new(), io::empty(), &format!("CLOSE {i}"), &sessions, &statuses).unwrap();
        }
        let table = sessions.lock().unwrap();
        assert!(table.live.is_empty());
        assert_eq!(table.closed.len(), MAX_LIVE * 3);
        drop(table);
        // Tombstones keep their ids from running again and acknowledge again.
        let mut wire = Vec::new();
        handle(&mut wire, &b"true"[..], "SESSION 0 4", &sessions, &statuses).unwrap();
        assert!(wire.ends_with(b"error: session closed"));
        wire.clear();
        handle(&mut wire, io::empty(), "ATTACH 0 0", &sessions, &statuses).unwrap();
        assert!(wire.ends_with(b"error: session closed"));
        wire.clear();
        handle(&mut wire, io::empty(), "CLOSE 0", &sessions, &statuses).unwrap();
        assert!(wire.ends_with(b"closed"));
        assert!(statuses.0.lock().unwrap().is_empty());
    }

    #[test]
    fn live_limit_is_explicit_and_abandoned_sessions_are_reclaimed() {
        let mut table = Table::default();
        let mut outputs = Vec::new();
        for i in 0..MAX_LIVE {
            table.admit().unwrap();
            // Still attached, or detached only just now: the client may come back.
            outputs.push(finished(&mut table, &i.to_string(), Some(Instant::now())));
        }
        let err = table.admit().unwrap_err().to_string();
        assert!(err.contains("too many sessions"), "{err}");
        assert_eq!(table.live.len(), MAX_LIVE);
        outputs[3].0.lock().unwrap().detached = Some(Instant::now() - ABANDONED);
        outputs[4].0.lock().unwrap().readers = 1;
        outputs[4].0.lock().unwrap().detached = Some(Instant::now() - ABANDONED);
        table.admit().unwrap();
        assert!(!table.live.contains_key("3") && table.closed.contains_key("3"));
        assert!(outputs[3].0.lock().unwrap().closed);
        assert!(table.live.contains_key("4"), "an attached reader keeps its session");
        // A running session is never reclaimed.
        outputs[5].0.lock().unwrap().exit = None;
        outputs[5].0.lock().unwrap().detached = Some(Instant::now() - ABANDONED);
        table.reclaim();
        assert!(table.live.contains_key("5"));
    }

    #[test]
    fn tombstones_are_bounded_and_expire() {
        let mut table = Table::default();
        let old = Instant::now() - GRACE;
        for i in 0..MAX_TOMBSTONES {
            table.closed.insert(i.to_string(), if i == 7 { old - Duration::from_secs(1) } else { old });
        }
        table.admit().unwrap();
        assert_eq!(table.closed.len(), MAX_TOMBSTONES - 1);
        assert!(!table.closed.contains_key("7"), "the oldest tombstone goes first");
        table.closed.insert("new".into(), Instant::now());
        for at in table.closed.values_mut() {
            *at = Instant::now();
        }
        let err = table.admit().unwrap_err().to_string();
        assert!(err.contains("finished in the last"), "{err}");
        let sessions = Arc::new(Mutex::new(table));
        sessions.lock().unwrap().closed.values_mut().for_each(|at| *at = Instant::now() - RETENTION);
        sessions.lock().unwrap().closed.insert("recent".into(), Instant::now());
        cleanup(&sessions);
        assert_eq!(sessions.lock().unwrap().closed.keys().collect::<Vec<_>>(), ["recent"]);
    }

    #[test]
    fn ring_memory_comes_from_the_pool_and_returns() {
        let mut table = Table::default();
        let big = vec![b'x'; READ_SIZE];
        let mut outputs = Vec::new();
        for i in 0..MAX_LIVE {
            table.admit().unwrap();
            let output = finished(&mut table, &i.to_string(), None);
            output.0.lock().unwrap().exit = None;
            for _ in 0..2 * CAPACITY / READ_SIZE {
                deliver(&output, FRAME_STDOUT, &big);
            }
            let ring = output.0.lock().unwrap();
            assert_eq!(ring.chunks.iter().map(|c| c.data.capacity()).sum::<usize>() as u64, ring.end - ring.start);
            assert!((ring.end - ring.start) as usize <= ring.capacity());
            drop(ring);
            outputs.push(output);
        }
        assert_eq!(table.pool.load(Ordering::Acquire), 0);
        let retained: usize = outputs.iter().map(|o| { let r = o.0.lock().unwrap(); (r.end - r.start) as usize }).sum();
        assert!(retained <= MAX_LIVE * BASE + POOL, "{retained}");
        let full = outputs.iter().filter(|o| o.0.lock().unwrap().capacity() == CAPACITY).count();
        assert!(full > 0 && full < MAX_LIVE);
        assert!(outputs.iter().all(|o| o.0.lock().unwrap().capacity() >= BASE));
        // Closing and dropping both return what was taken, exactly once.
        outputs[0].0.lock().unwrap().exit = Some((0, Instant::now()));
        table.close("0");
        table.close("0");
        let freed = table.pool.load(Ordering::Acquire);
        assert_eq!(freed, CAPACITY - BASE);
        table.live.clear();
        drop(outputs);
        assert_eq!(table.pool.load(Ordering::Acquire), POOL);
    }

    #[test]
    fn attached_reader_applies_backpressure() {
        let table = Table::default();
        let reservation = Reservation { pool: Some(table.pool.clone()), bytes: 0 };
        let output = Arc::new((Mutex::new(Output { readers: 1, reservation, ..Default::default() }), Condvar::new()));
        let pumped = {
            let output = output.clone();
            thread::spawn(move || {
                for _ in 0..2 * CAPACITY / READ_SIZE {
                    deliver(&output, FRAME_STDOUT, &[b'x'; READ_SIZE]);
                }
            })
        };
        let ring = output.0.lock().unwrap();
        let (ring, _) = output.1.wait_timeout_while(ring, Duration::from_secs(2), |r| r.end < CAPACITY as u64 / 2).unwrap();
        drop(ring);
        thread::sleep(Duration::from_millis(50));
        let ring = output.0.lock().unwrap();
        assert_eq!(ring.start, 0, "attached reader's unsent output was overwritten");
        assert!(ring.end <= CAPACITY as u64 / 2 + READ_SIZE as u64);
        drop(ring);
        output.0.lock().unwrap().readers = 0;
        output.1.notify_all();
        pumped.join().unwrap();
        assert_eq!(output.0.lock().unwrap().start, CAPACITY as u64);
    }

    #[test]
    fn lost_creation_reply_does_not_spawn_twice() {
        struct Disconnected;
        impl Write for Disconnected {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let sessions = Sessions::default();
        let statuses = statuses();
        let command = b"printf hello; printf err >&2; exit 7";
        let line = format!("SESSION retry {}", command.len());
        assert!(handle(Disconnected, command.as_slice(), &line, &sessions, &statuses).is_err());
        // Simulate PID 1's reaper, without leaving a reaper thread in the test process.
        let pid = *statuses.0.lock().unwrap().keys().next().unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        statuses.0.lock().unwrap().insert(pid, Some(libc::WEXITSTATUS(status)));
        statuses.1.notify_all();
        let output = sessions.lock().unwrap().live["retry"].output.clone();
        let ring = output.0.lock().unwrap();
        let (ring, timeout) = output.1.wait_timeout_while(ring, Duration::from_secs(2), |r| r.exit.is_none()).unwrap();
        assert!(!timeout.timed_out());
        assert_eq!(ring.end, 8);
        drop(ring);
        let mut wire = Vec::new();
        handle(&mut wire, command.as_slice(), &line, &sessions, &statuses).unwrap();
        assert_eq!(wire[0], FRAME_MSG);
        assert!(statuses.0.lock().unwrap().is_empty(), "retry registered a second process");
        assert_eq!(sessions.lock().unwrap().live.len(), 1);
        let mut wire = Vec::new();
        handle(&mut wire, &b"false"[..], "SESSION retry 5", &sessions, &statuses).unwrap();
        assert!(wire.ends_with(b"error: session id already used for another command"));
        handle(Vec::new(), io::empty(), "CLOSE retry", &sessions, &statuses).unwrap();
        assert!(output.0.lock().unwrap().chunks.is_empty());
        let mut wire = Vec::new();
        handle(&mut wire, command.as_slice(), &line, &sessions, &statuses).unwrap();
        assert!(wire.ends_with(b"error: session closed"));
        assert!(statuses.0.lock().unwrap().is_empty());
        cleanup(&sessions);
        assert!(sessions.lock().unwrap().closed.contains_key("retry"), "closed ID must remain a tombstone");
        sessions.lock().unwrap().closed.insert("retry".into(), Instant::now() - RETENTION);
        cleanup(&sessions);
        assert!(sessions.lock().unwrap().closed.is_empty());
    }

    #[test]
        fn ring_offsets_and_overflow() {
        let mut ring = Output::default();
        ring.push(FRAME_STDOUT, b"abc", 5);
        ring.push(FRAME_STDERR, b"defg", 5);
        assert_eq!((ring.start, ring.end), (2, 7));
        assert_eq!(ring.read(2), Some((FRAME_STDOUT, [2u64.to_le_bytes().as_slice(), b"c"].concat())));
        assert_eq!(ring.read(5), Some((FRAME_STDERR, [5u64.to_le_bytes().as_slice(), b"fg"].concat())));
        assert!(ring.read(7).is_none());
        ring.push(FRAME_STDOUT, b"0123456789", 5);
        assert_eq!((ring.start, ring.end), (12, 17));
        assert_eq!(&ring.read(12).unwrap().1[8..], b"56789");
        let mut tiny = Output::default();
        for _ in 0..MAX_CHUNKS + 1 {
            tiny.push(FRAME_STDOUT, b"x", CAPACITY);
        }
        assert_eq!(tiny.chunks.len(), MAX_CHUNKS);
        assert_eq!(tiny.start, 1);
    }

    #[test]
    fn writer_does_not_hold_ring_lock() {
        struct Writer {
            output: Session,
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                assert!(self.output.0.try_lock().is_ok());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut ring = Output::default();
        ring.push(FRAME_STDOUT, b"hello", CAPACITY);
        ring.exit = Some((0, Instant::now()));
        let output = Arc::new((Mutex::new(ring), Condvar::new()));
        drain(&mut Writer { output: output.clone() }, &output, 0).unwrap();
    }

    #[test]
    fn requests() {
        assert!(matches!(parse("SESSION abc 3\n").unwrap(), Request::Start { id: "abc", len: 3 }));
        assert!(matches!(parse("ATTACH abc 42").unwrap(), Request::Attach { offset: 42, .. }));
        assert!(matches!(parse("CLOSE abc").unwrap(), Request::Close { .. }));
        for bad in [
            "SESSION 3",
            "SESSION abc -1",
            "SESSION abc 1048577",
            "ATTACH abc -1",
            "ATTACH abc 1 extra",
            "CLOSE",
            "CLOSE a/b",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn loss_and_exit_are_explicit_and_retained() {
        let mut ring = Output::default();
        ring.push(FRAME_STDOUT, b"abcdef", 3);
        ring.exit = Some((7, Instant::now()));
        let output = Arc::new((Mutex::new(ring), Condvar::new()));
        let mut wire = Vec::new();
        drain(&mut wire, &output, 0).unwrap();
        assert_eq!(wire[0], FRAME_LOST);
        assert_eq!(&wire[5..], &3u64.to_le_bytes());
        for _ in 0..2 {
            wire.clear();
            drain(&mut wire, &output, 6).unwrap();
            assert_eq!(wire[0], FRAME_EXIT);
            assert_eq!(&wire[5..13], &6u64.to_le_bytes());
            assert_eq!(&wire[13..], &7i32.to_le_bytes());
        }
        wire.clear();
        drain(&mut wire, &output, 7).unwrap();
        assert!(wire.ends_with(b"error: offset past output end"));
    }
}
