//! Resumable commands: `SESSION <id> <len>` (then `len` bytes of shell command), `ATTACH <id> <offset>`,
//! `CLOSE <id>`. Output frames start with their stream offset (u64 LE); the exit frame is offset plus code.
//! The command runs in a process group of its own; its exit is the shell's, recorded once output stops or
//! `DRAIN` after the shell exits; background processes that keep its pipes open run on, their later output
//! read and dropped (by one thread, for at most `MAX_DISCARDED` pipes: past that, a job's next write gets
//! SIGPIPE). Closing a session whose shell has not exited kills its process group (not processes that
//! left it with setsid or setpgid: that would take a cgroup per session); closing an unknown one cancels it, so
//! a start still in flight never runs.
//! At most `MAX_LIVE` sessions are live; closed ones leave a tombstone so a delayed `SESSION` retry cannot
//! rerun the command. Rings keep `BASE` bytes and grow towards `CAPACITY` from a shared pool: at most
//! `MAX_LIVE * BASE + POOL` (plus a partial `BLOCK` each). One attachment per session; a new one shuts the
//! old one down. Output waits for it rather than overwrite unsent bytes; writers never hold the ring lock.
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::hash::{BuildHasher, BuildHasherDefault};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::proto::{valid_session_id, FRAME_EXIT, FRAME_LOST, FRAME_MSG, FRAME_STDERR, FRAME_STDOUT, MAX_BODY};
use crate::{fail, msg, spawn_watched, wait_pid, write_frame, Statuses};

const CAPACITY: usize = 4 * 1024 * 1024;
const MAX_CHUNKS: usize = 4096;
/// Consecutive output of one kind is coalesced into chunks of up to this size.
const BLOCK: usize = 16 * 1024;
const MAX_LIVE: usize = 64;
const MAX_TOMBSTONES: usize = 4096;
/// Ids closed before their start arrived; the oldest go first.
const MAX_CANCELLED: usize = 1024;
const BASE: usize = 128 * 1024;
const POOL: usize = 64 * 1024 * 1024 - MAX_LIVE * BASE;
const STEP: usize = 256 * 1024;
const RETENTION: Duration = Duration::from_secs(300);
/// How long output keeps waiting for a dropped client (the CLI retries for 30 s).
const GRACE: Duration = Duration::from_secs(30);
/// A finished session whose client has been gone this long (the CLI gives up after 30 s) becomes a tombstone.
const ABANDONED: Duration = Duration::from_secs(60);
/// Output still read after the shell exits, as for the app.
const DRAIN: Duration = Duration::from_secs(2);

type Session = Arc<(Mutex<Output>, Condvar)>;
pub type Sessions = Arc<Mutex<Table>>;

fn session(output: Output) -> Session {
    Arc::new((Mutex::new(output), Condvar::new()))
}

pub struct Table {
    live: HashMap<String, Entry>,
    closed: HashMap<String, Instant>,
    cancelled: HashMap<String, Instant>,
    pool: Arc<AtomicUsize>,
}

impl Default for Table {
    fn default() -> Table {
        Table { live: HashMap::new(), closed: HashMap::new(), cancelled: HashMap::new(), pool: Arc::new(AtomicUsize::new(POOL)) }
    }
}

struct Entry {
    /// Recognises a retried SESSION without keeping the command; ids are random, so this is only a check.
    command: (usize, u64),
    output: Session,
    /// The command's process group (its shell's pid).
    group: i32,
}

fn fingerprint(command: &[u8]) -> (usize, u64) {
    (command.len(), BuildHasherDefault::<std::collections::hash_map::DefaultHasher>::default().hash_one(command))
}

impl Table {
    fn new_output(&self) -> Output {
        Output { reservation: Reservation { pool: Some(self.pool.clone()), bytes: 0 }, ..Default::default() }
    }

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

    fn ended(&self, id: &str) -> bool {
        self.closed.contains_key(id) || self.cancelled.contains_key(id)
    }

    fn cancel(&mut self, id: &str) {
        if self.cancelled.len() >= MAX_CANCELLED {
            if let Some(oldest) = self.cancelled.iter().min_by_key(|(_, at)| **at).map(|(id, _)| id.clone()) {
                self.cancelled.remove(&oldest);
            }
        }
        self.cancelled.insert(id.to_string(), Instant::now());
    }

    fn reclaim(&mut self) {
        let abandoned: Vec<String> = self
            .live
            .iter()
            .filter_map(|(id, entry)| {
                let o = entry.output.0.lock().unwrap();
                (o.exit.is_some() && o.attached.is_none() && o.detached.is_some_and(|t| t.elapsed() >= ABANDONED)).then(|| id.clone())
            })
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
            return Err(io::Error::other(format!("too many sessions: {MAX_LIVE} commands are running or awaiting their client")));
        }
        if self.closed.len() >= MAX_TOMBSTONES {
            // Only a badly delayed retry of the oldest one's creation could still arrive.
            match self.closed.iter().min_by_key(|(_, at)| **at).map(|(id, at)| (id.clone(), *at)) {
                Some((id, at)) if at.elapsed() >= GRACE => drop(self.closed.remove(&id)),
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

/// Pool bytes beyond `BASE`, given back on close or drop, whichever is first.
#[derive(Default)]
struct Reservation {
    pool: Option<Arc<AtomicUsize>>,
    bytes: usize,
}

impl Reservation {
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

struct Attachment {
    id: u64,
    /// A duplicate of the connection, to shut it down when it is replaced.
    conn: Option<File>,
}

#[derive(Default)]
pub(crate) struct Output {
    chunks: VecDeque<Chunk>,
    pub(crate) start: u64,
    pub(crate) end: u64,
    exit: Option<i32>,
    closed: bool,
    attached: Option<Attachment>,
    attachments: u64,
    /// The attachment's cursor: everything before it has been sent.
    sent: u64,
    detached: Option<Instant>,
    reservation: Reservation,
}

impl Output {
    fn capacity(&self) -> usize {
        BASE + self.reservation.bytes
    }

    fn chunks_from(&self, offset: u64) -> usize {
        self.chunks.len() - self.chunks.partition_point(|c| c.offset + c.data.len() as u64 <= offset)
    }

    /// Whether output must wait for the (just) attached client; half the ring is slack for bytes in flight.
    fn must_wait(&self) -> bool {
        let unsent = self.end.saturating_sub(self.sent) >= self.capacity() as u64 / 2 || self.chunks_from(self.sent) >= MAX_CHUNKS / 2;
        unsent && (self.attached.is_some() || self.detached.is_some_and(|t| t.elapsed() < GRACE))
    }

    /// Appends, then drops the oldest to fit `capacity` and `MAX_CHUNKS`. Same-kind output joins the
    /// last chunk up to `BLOCK`; only the newest chunk has spare allocation.
    pub(crate) fn push(&mut self, kind: u8, data: &[u8], capacity: usize) {
        match self.chunks.back_mut() {
            Some(last) if last.kind == kind && last.data.len() + data.len() <= BLOCK => last.data.extend_from_slice(data),
            last => {
                if let Some(last) = last {
                    last.data.shrink_to_fit();
                }
                let mut block = Vec::with_capacity(BLOCK.max(data.len()));
                block.extend_from_slice(data);
                self.chunks.push_back(Chunk { kind, offset: self.end, data: block });
            }
        }
        self.end += data.len() as u64;
        while self.chunks.len() > MAX_CHUNKS {
            self.chunks.pop_front();
        }
        let keep = self.end.saturating_sub(capacity as u64);
        while let Some(chunk) = self.chunks.front_mut() {
            if chunk.offset + chunk.data.len() as u64 <= keep {
                self.chunks.pop_front();
                continue;
            }
            if chunk.offset < keep {
                chunk.data.drain(..(keep - chunk.offset) as usize);
                chunk.data.shrink_to_fit();
                chunk.offset = keep;
            }
            break;
        }
        self.start = self.chunks.front().map_or(self.end, |c| c.offset);
    }

    pub(crate) fn read_chunk(&self, offset: u64) -> Option<(u8, &[u8])> {
        let c = self.chunks.get(self.chunks.len() - self.chunks_from(offset))?;
        Some((c.kind, &c.data[(offset - c.offset) as usize..]))
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
    if !valid_session_id(id) {
        return Err(io::Error::other("bad session id"));
    }
    match parts.as_slice() {
        ["SESSION", _, len] => match len.parse::<usize>() {
            Ok(len) if len <= MAX_BODY => Ok(Request::Start { id, len }),
            _ => Err(io::Error::other("bad command length")),
        },
        ["ATTACH", _, offset] => Ok(Request::Attach { id, offset: offset.parse().map_err(|_| io::Error::other("bad offset"))? }),
        ["CLOSE", _] => Ok(Request::Close { id }),
        _ => Err(io::Error::other("bad session request")),
    }
}

pub fn cleanup(sessions: &Sessions) {
    let mut table = sessions.lock().unwrap();
    table.reclaim();
    table.closed.retain(|_, at| at.elapsed() < RETENTION);
    table.cancelled.retain(|_, at| at.elapsed() < RETENTION);
}

/// Request errors become a message frame; write errors just end the stream (a frame may be cut short).
/// `conn` duplicates `w`'s connection so a later attachment can shut it down.
pub fn handle(mut w: impl Write, body: &[u8], conn: Option<File>, line: &str, sessions: &Sessions, statuses: &Statuses) -> io::Result<()> {
    match open(body, conn, line, sessions, statuses) {
        Ok(Some((id, offset, (output, me)))) => {
            let result = msg(&mut w, id).and_then(|_| drain(&mut w, &output, offset, me));
            let mut ring = output.0.lock().unwrap();
            // A replaced attachment leaves the session to its successor.
            if ring.attached.as_ref().is_some_and(|a| a.id == me) {
                ring.attached = None;
                ring.detached = Some(Instant::now());
            }
            drop(ring);
            output.1.notify_all();
            result
        }
        Ok(None) => msg(&mut w, "closed"),
        Err(e) => fail(&mut w, e),
    }
}

type Attached = (Session, u64);

fn open<'a>(body: &[u8], conn: Option<File>, line: &'a str, sessions: &Sessions, statuses: &Statuses) -> io::Result<Option<(&'a str, u64, Attached)>> {
    let gone = || io::Error::other("session closed");
    let unknown = || io::Error::other("unknown session");
    Ok(Some(match parse(line)? {
        Request::Start { id, len } => {
            let command = body.get(..len).ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            let fingerprint = fingerprint(command);
            // Lookup and spawn under one lock: a retried creation cannot spawn twice.
            let mut table = sessions.lock().unwrap();
            if table.ended(id) {
                return Err(gone());
            }
            if let Some(entry) = table.live.get(id) {
                if entry.command != fingerprint {
                    return Err(io::Error::other("session id already used for another command"));
                }
                return Ok(Some((id, 0, attach(&entry.output, 0, conn))));
            }
            table.admit()?;
            let command = std::str::from_utf8(command).map_err(io::Error::other)?;
            let output = session(table.new_output());
            // Start the pump first: if no thread can be had, nothing has run yet.
            let (tx, rx) = mpsc::sync_channel::<(Child, Option<OwnedFd>)>(1);
            let (pumped, statuses_) = (output.clone(), statuses.clone());
            thread::Builder::new()
                .spawn(move || {
                    if let Ok((mut child, exited)) = rx.recv() {
                        let rest = crate::pump_until(child.stdout.take(), child.stderr.take(), exited, DRAIN, |kind, data| deliver(&pumped, kind, data));
                        // Closed, they would kill a background process's next write with SIGPIPE.
                        crate::discard(rest);
                        pumped.0.lock().unwrap().exit = wait_pid(&statuses_, child.id() as i32, None);
                        pumped.1.notify_all();
                    }
                })
                .map_err(|e| io::Error::new(e.kind(), format!("cannot start session thread: {e}")))?;
            let mut cmd = Command::new("/bin/sh");
            cmd.args(["-c", command]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
            if let Some(work) = crate::mem::work_procs() {
                crate::mem::enter(&mut cmd, work, false);
            }
            // Minimal images (distroless, scratch) have no shell.
            let (child, exited) = spawn_watched(&mut cmd, statuses, true)
                .map_err(|e| io::Error::new(e.kind(), format!("cannot run /bin/sh: {e} (does the image have a shell?)")))?;
            table.live.insert(id.to_string(), Entry { command: fingerprint, output: output.clone(), group: child.id() as i32 });
            // Attached before any output, so none is overwritten before it is sent.
            let attached = attach(&output, 0, conn);
            let _ = tx.send((child, exited));
            (id, 0, attached)
        }
        Request::Attach { id, offset } => {
            let table = sessions.lock().unwrap();
            if table.ended(id) {
                return Err(gone());
            }
            (id, offset, attach(&table.live.get(id).ok_or_else(unknown)?.output, offset, conn))
        }
        Request::Close { id } => {
            let mut table = sessions.lock().unwrap();
            // Closing again (a retried acknowledgement) is fine.
            match table.live.get(id) {
                // Only while its shell is unreaped (under the reaper's lock) is the group surely the
                // command's: an emptied group's id may be reused. An exited shell's jobs run on.
                Some(entry) => {
                    let reaped = statuses.0.lock().unwrap();
                    if entry.group > 0 && matches!(reaped.get(&entry.group), Some(None)) {
                        unsafe { libc::kill(-entry.group, libc::SIGKILL) };
                    }
                }
                // A start still in flight (a client interrupted at once) must not run.
                None if !table.ended(id) => table.cancel(id),
                None => {}
            }
            table.close(id);
            return Ok(None);
        }
    }))
}

/// Makes `conn` the only attachment, streaming from `offset`; shuts down the one it replaces.
fn attach(output: &Session, offset: u64, conn: Option<File>) -> Attached {
    let mut ring = output.0.lock().unwrap();
    ring.attachments += 1;
    let id = ring.attachments;
    let previous = ring.attached.replace(Attachment { id, conn });
    ring.sent = offset.clamp(ring.start, ring.end);
    drop(ring);
    output.1.notify_all();
    // Unblocks its handler even mid-write to a stalled client; it then exits.
    if let Some(conn) = previous.and_then(|p| p.conn) {
        unsafe { libc::shutdown(conn.as_raw_fd(), libc::SHUT_RDWR) };
    }
    (output.clone(), id)
}

/// Returns how long it waited for the client.
fn deliver(output: &Session, kind: u8, data: &[u8]) -> Duration {
    let mut ring = output.0.lock().unwrap();
    if ring.closed {
        return Duration::ZERO;
    }
    let need = (ring.end - ring.start) as usize + data.len();
    ring.reservation.grow(need);
    let start = Instant::now();
    while ring.must_wait() && !ring.closed {
        ring = output.1.wait_timeout(ring, Duration::from_secs(1)).unwrap().0;
    }
    let waited = start.elapsed();
    if !ring.closed {
        let capacity = ring.capacity();
        ring.push(kind, data, capacity);
    }
    drop(ring);
    output.1.notify_all();
    waited
}

fn drain(w: &mut impl Write, output: &Session, mut offset: u64, me: u64) -> io::Result<()> {
    loop {
        let (kind, data) = {
            let ring = output.0.lock().unwrap();
            if ring.attached.as_ref().is_none_or(|a| a.id != me) {
                // Replaced; the newer attachment owns the cursor now.
                return Ok(());
            }
            let error = if ring.closed { Some("session closed") } else { (offset > ring.end).then_some("offset past output end") };
            if let Some(e) = error {
                drop(ring);
                return fail(w, e);
            }
            if offset < ring.start {
                (FRAME_LOST, ring.start.to_le_bytes().to_vec())
            } else if let Some((kind, data)) = ring.read_chunk(offset) {
                (kind, [&offset.to_le_bytes()[..], data].concat())
            } else if let Some(code) = ring.exit {
                (FRAME_EXIT, [offset.to_le_bytes().as_slice(), &code.to_le_bytes()].concat())
            } else {
                let timeout = output.1.wait_timeout(ring, Duration::from_secs(1)).unwrap().1;
                if !timeout.timed_out() {
                    continue;
                }
                (FRAME_MSG, b"waiting".to_vec())
            }
        };
        write_frame(&mut *w, kind, &data)?;
        match kind {
            FRAME_STDOUT | FRAME_STDERR => {
                offset += (data.len() - 8) as u64;
                let mut ring = output.0.lock().unwrap();
                if ring.attached.as_ref().is_some_and(|a| a.id == me) {
                    ring.sent = offset.clamp(ring.start, ring.end);
                }
                drop(ring);
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
    use std::os::unix::net::UnixStream;

    fn live(table: &mut Table, id: &str, output: Output) -> Session {
        let output = session(Output { reservation: table.new_output().reservation, ..output });
        table.live.insert(id.to_string(), Entry { command: fingerprint(b"true"), output: output.clone(), group: 0 });
        output
    }

    fn finished(table: &mut Table, id: &str, detached: Option<Instant>) -> Session {
        live(table, id, Output { exit: Some(0), detached, ..Default::default() })
    }

    fn attached(ring: Output) -> Session {
        session(Output { attached: Some(Attachment { id: 1, conn: None }), ..ring })
    }

    fn statuses() -> Statuses {
        Arc::new((Mutex::new(HashMap::new()), Condvar::new()))
    }

    fn request(sessions: &Sessions, statuses: &Statuses, line: &str, body: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        handle(&mut wire, body, None, line, sessions, statuses).unwrap();
        wire
    }

    /// Pumps `n` reads of `data` (alternating kinds if `kinds`); returns once they are all in, or once the
    /// ring holds them up: output must wait, with the reservation its next read would grow already grown (so
    /// it is waiting, or will be). Not once 100 ms pass without progress: on a loaded machine the pump may not
    /// have started by then (#294).
    fn pump(output: &Session, n: usize, data: &'static [u8], kinds: bool) -> thread::JoinHandle<()> {
        let pumped = output.clone();
        let t = thread::spawn(move || {
            for i in 0..n {
                deliver(&pumped, if kinds && i % 2 == 1 { FRAME_STDERR } else { FRAME_STDOUT }, data);
            }
        });
        let give_up = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            let mut ring = output.0.lock().unwrap();
            let need = (ring.end - ring.start) as usize + data.len();
            ring.reservation.grow(need);
            if ring.must_wait() || t.is_finished() || std::time::Instant::now() >= give_up {
                return t;
            }
            drop(ring);
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn detach_and_join(output: &Session, t: thread::JoinHandle<()>) {
        output.0.lock().unwrap().attached = None;
        output.1.notify_all();
        t.join().unwrap();
    }

    #[test]
    fn attachment_cursor_is_clamped_to_retained_output() {
        let output = session(Output { start: 100, end: 200, ..Default::default() });
        for (offset, expected) in [(0, 100), (150, 150), (300, 200)] {
            attach(&output, offset, None);
            assert_eq!(output.0.lock().unwrap().sent, expected);
        }
    }

    #[test]
    fn closed_sessions_leave_tombstones_outside_the_live_limit() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        for i in 0..MAX_LIVE * 3 {
            let mut table = sessions.lock().unwrap();
            table.admit().unwrap();
            finished(&mut table, &i.to_string(), None);
            drop(table);
            assert!(request(&sessions, &statuses, &format!("CLOSE {i}"), b"").ends_with(b"closed"));
        }
        let table = sessions.lock().unwrap();
        assert!(table.live.is_empty() && table.closed.len() == MAX_LIVE * 3);
        drop(table);
        // Tombstones keep their ids from running again and acknowledge again.
        for (line, body, reply) in [
            ("SESSION 0 4", &b"true"[..], &b"error: session closed"[..]),
            ("ATTACH 0 0", b"", b"error: session closed"),
            ("CLOSE 0", b"", b"closed"),
            ("ATTACH nope 0", b"", b"error: unknown session"),
            // An interrupted client's start may still be in flight: it must never run.
            ("CLOSE nope", b"", b"closed"),
            ("SESSION nope 4", b"true", b"error: session closed"),
        ] {
            assert!(request(&sessions, &statuses, line, body).ends_with(reply), "{line}");
        }
        assert!(statuses.0.lock().unwrap().is_empty());
    }

    #[test]
    fn live_limit_is_explicit_and_abandoned_sessions_are_reclaimed() {
        let mut table = Table::default();
        let outputs: Vec<_> = (0..MAX_LIVE)
            .map(|i| {
                table.admit().unwrap();
                finished(&mut table, &i.to_string(), Some(Instant::now()))
            })
            .collect();
        assert!(table.admit().unwrap_err().to_string().contains("too many sessions"));
        let old = Some(Instant::now() - ABANDONED);
        outputs[3].0.lock().unwrap().detached = old;
        let mut o4 = outputs[4].0.lock().unwrap();
        (o4.attached, o4.detached) = (Some(Attachment { id: 1, conn: None }), old);
        drop(o4);
        table.admit().unwrap();
        assert!(!table.live.contains_key("3") && table.closed.contains_key("3"));
        assert!(outputs[3].0.lock().unwrap().closed);
        assert!(table.live.contains_key("4"), "an attached reader keeps its session");
        // A running session is never reclaimed.
        let mut o5 = outputs[5].0.lock().unwrap();
        (o5.exit, o5.detached) = (None, old);
        drop(o5);
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
        table.closed.values_mut().for_each(|at| *at = Instant::now());
        assert!(table.admit().unwrap_err().to_string().contains("finished in the last"));
        table.closed.values_mut().for_each(|at| *at = Instant::now() - RETENTION);
        table.closed.insert("recent".into(), Instant::now());
        let sessions = Arc::new(Mutex::new(table));
        cleanup(&sessions);
        assert_eq!(sessions.lock().unwrap().closed.keys().collect::<Vec<_>>(), ["recent"]);
    }

    #[test]
    fn ring_memory_comes_from_the_pool_and_returns() {
        let mut table = Table::default();
        let outputs: Vec<_> = (0..MAX_LIVE)
            .map(|i| {
                table.admit().unwrap();
                let output = live(&mut table, &i.to_string(), Output::default());
                for _ in 0..2 * CAPACITY / BLOCK {
                    deliver(&output, FRAME_STDOUT, &[b'x'; BLOCK]);
                }
                let ring = output.0.lock().unwrap();
                assert_eq!(ring.chunks.iter().map(|c| c.data.capacity()).sum::<usize>() as u64, ring.end - ring.start);
                assert!((ring.end - ring.start) as usize <= ring.capacity());
                drop(ring);
                output
            })
            .collect();
        assert_eq!(table.pool.load(Ordering::Acquire), 0);
        let retained: usize = outputs
            .iter()
            .map(|o| {
                let r = o.0.lock().unwrap();
                (r.end - r.start) as usize
            })
            .sum();
        assert!(retained <= MAX_LIVE * BASE + POOL, "{retained}");
        let full = outputs.iter().filter(|o| o.0.lock().unwrap().capacity() == CAPACITY).count();
        assert!(full > 0 && full < MAX_LIVE);
        assert!(outputs.iter().all(|o| o.0.lock().unwrap().capacity() >= BASE));
        // Closing and dropping both return what was taken, exactly once.
        table.close("0");
        table.close("0");
        assert_eq!(table.pool.load(Ordering::Acquire), CAPACITY - BASE);
        table.live.clear();
        drop(outputs);
        assert_eq!(table.pool.load(Ordering::Acquire), POOL);
    }

    #[test]
    fn attached_readers_apply_backpressure_instead_of_evicting() {
        let table = Table::default();
        let output = attached(table.new_output());
        let t = pump(&output, 2 * CAPACITY / BLOCK, &[b'x'; BLOCK], false);
        let ring = output.0.lock().unwrap();
        assert_eq!(ring.start, 0, "attached reader's unsent output was overwritten");
        assert!(ring.end > 0 && ring.end <= CAPACITY as u64 / 2 + BLOCK as u64, "{}", ring.end);
        drop(ring);
        detach_and_join(&output, t);
        assert_eq!(output.0.lock().unwrap().start, CAPACITY as u64);
        // Same-kind one-byte reads coalesce and wait at the byte threshold; alternating kinds at half the chunk limit.
        for (n, kinds, end, chunks) in [(BASE, false, BASE as u64 / 2, BASE / 2 / BLOCK), (MAX_CHUNKS * 2, true, MAX_CHUNKS as u64 / 2, MAX_CHUNKS / 2)] {
            let output = attached(Output::default());
            let t = pump(&output, n, b"x", kinds);
            let ring = output.0.lock().unwrap();
            assert_eq!((ring.start, ring.end), (0, end), "unsent output was evicted");
            assert!(ring.chunks.len() <= chunks);
            drop(ring);
            // Detaching (with no grace period) lets output continue and wrap.
            detach_and_join(&output, t);
            assert!(output.0.lock().unwrap().chunks.len() <= MAX_CHUNKS);
        }
    }

    /// Reaps `pid` as PID 1's reaper would, without leaving a reaper thread in the test process.
    fn reap(statuses: &Statuses, pid: i32) -> i32 {
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 128 + libc::WTERMSIG(status) };
        statuses.0.lock().unwrap().insert(pid, Some(code));
        statuses.1.notify_all();
        status
    }

    fn start(sessions: &Sessions, statuses: &Statuses, id: &str, command: &[u8]) -> (Session, i32) {
        let disconnected = UnixStream::pair().unwrap().0;
        let _ = handle(disconnected, command, None, &format!("SESSION {id} {}", command.len()), sessions, statuses);
        let table = sessions.lock().unwrap();
        (table.live[id].output.clone(), table.live[id].group)
    }

    #[test]
    fn exit_is_recorded_while_a_background_process_holds_the_output() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let (output, group) = start(&sessions, &statuses, "bg", b"echo hi; sleep 100 & exit 3");
        let status = reap(&statuses, group);
        let ring = output.0.lock().unwrap();
        let (ring, timeout) = output.1.wait_timeout_while(ring, DRAIN * 3, |r| r.exit.is_none()).unwrap();
        assert!(!timeout.timed_out(), "exit never recorded");
        assert_eq!((ring.end, ring.exit, libc::WEXITSTATUS(status)), (3, Some(3), 3));
        drop(ring);
        // Finished: closing leaves the background process alone.
        assert!(request(&sessions, &statuses, "CLOSE bg", b"").ends_with(b"closed"));
        assert_eq!(unsafe { libc::kill(-group, 0) }, 0, "the background process was killed");
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }

    #[test]
    fn closing_a_running_session_kills_its_process_group() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let (output, group) = start(&sessions, &statuses, "run", b"sleep 100 & sleep 100");
        assert!(request(&sessions, &statuses, "CLOSE run", b"").ends_with(b"closed"));
        assert!(sessions.lock().unwrap().closed.contains_key("run"));
        let status = reap(&statuses, group);
        assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL);
        // The background sleep went with it: the group empties.
        let gone = Instant::now() + Duration::from_secs(5);
        while unsafe { libc::kill(-group, 0) } == 0 {
            assert!(Instant::now() < gone, "the background process survived");
            let mut status = 0;
            unsafe { libc::waitpid(-group, &mut status, libc::WNOHANG) };
            thread::sleep(Duration::from_millis(10));
        }
        let ring = output.0.lock().unwrap();
        assert!(output.1.wait_timeout_while(ring, DRAIN * 3, |r| r.exit.is_none()).unwrap().0.exit.is_some());
    }

    #[test]
    fn closing_after_the_shell_exited_signals_nothing() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let (output, group) = start(&sessions, &statuses, "late", b"sleep 100 & exit 0");
        reap(&statuses, group);
        // Still draining (the sleep holds the pipes), but the group may be anyone's by now.
        assert!(output.0.lock().unwrap().exit.is_none());
        assert!(request(&sessions, &statuses, "CLOSE late", b"").ends_with(b"closed"));
        thread::sleep(Duration::from_millis(100));
        assert_eq!(unsafe { libc::kill(-group, 0) }, 0, "an exited shell's group was signalled");
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }

    #[test]
    fn background_output_after_the_drain_is_dropped_not_refused() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let marker = std::env::temp_dir().join(format!("flexvm-discard-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let command = format!("(sleep 3; echo late; echo late >&2; echo survived > {}) & exit 0", marker.display());
        let (output, group) = start(&sessions, &statuses, "drop", command.as_bytes());
        reap(&statuses, group);
        let ring = output.0.lock().unwrap();
        let (ring, timeout) = output.1.wait_timeout_while(ring, DRAIN * 3, |r| r.exit.is_none()).unwrap();
        assert!(!timeout.timed_out() && ring.end == 0, "exit {:?}, {} bytes", ring.exit, ring.end);
        drop(ring);
        // A closed pipe would have killed it with SIGPIPE at its first echo.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() {
            assert!(Instant::now() < deadline, "the background process died writing its output");
            thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(output.0.lock().unwrap().end, 0, "output after the exit was kept");
        std::fs::remove_file(&marker).unwrap();
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }

    #[test]
    fn cancelled_ids_are_capped_and_leave_admission_alone() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        for i in 0..MAX_CANCELLED * 2 {
            assert!(request(&sessions, &statuses, &format!("CLOSE c{i}"), b"").ends_with(b"closed"));
        }
        let mut table = sessions.lock().unwrap();
        assert_eq!((table.cancelled.len(), table.closed.len()), (MAX_CANCELLED, 0));
        table.admit().unwrap();
        drop(table);
        let last = format!("c{}", MAX_CANCELLED * 2 - 1);
        assert!(request(&sessions, &statuses, &format!("SESSION {last} 4"), b"true").ends_with(b"session closed"));
        assert!(request(&sessions, &statuses, &format!("ATTACH {last} 0"), b"").ends_with(b"session closed"));
    }

    #[test]
    fn lost_creation_reply_does_not_spawn_twice() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let command = b"printf hello; printf err >&2; exit 7";
        let line = format!("SESSION retry {}", command.len());
        // The client is gone before the reply.
        let disconnected = UnixStream::pair().unwrap().0;
        assert!(handle(disconnected, command, None, &line, &sessions, &statuses).is_err());
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
        assert_eq!((ring.end, ring.exit), (8, Some(7)));
        drop(ring);
        assert_eq!(request(&sessions, &statuses, &line, command)[0], FRAME_MSG);
        assert!(statuses.0.lock().unwrap().is_empty(), "retry registered a second process");
        assert_eq!(sessions.lock().unwrap().live.len(), 1);
        assert!(request(&sessions, &statuses, "SESSION retry 5", b"false").ends_with(b"error: session id already used for another command"));
        request(&sessions, &statuses, "CLOSE retry", b"");
        assert!(output.0.lock().unwrap().chunks.is_empty());
        assert!(request(&sessions, &statuses, &line, command).ends_with(b"error: session closed"));
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
        assert_eq!(ring.read_chunk(2), Some((FRAME_STDOUT, &b"c"[..])));
        assert_eq!(ring.read_chunk(5), Some((FRAME_STDERR, &b"fg"[..])));
        assert!(ring.read_chunk(7).is_none());
        ring.push(FRAME_STDOUT, b"0123456789", 5);
        assert_eq!((ring.start, ring.end), (12, 17));
        assert_eq!(ring.read_chunk(12), Some((FRAME_STDOUT, &b"56789"[..])));
        let mut tiny = Output::default();
        for _ in 0..BLOCK + 1 {
            tiny.push(FRAME_STDOUT, b"x", CAPACITY);
        }
        assert_eq!(tiny.chunks.iter().map(|c| c.data.len()).collect::<Vec<_>>(), [BLOCK, 1]);
        assert_eq!(tiny.read_chunk(BLOCK as u64 - 1), Some((FRAME_STDOUT, &b"x"[..])));
        tiny.push(FRAME_STDERR, b"y", CAPACITY);
        assert_eq!(tiny.chunks.len(), 3);
        assert_eq!(tiny.read_chunk(BLOCK as u64 + 1), Some((FRAME_STDERR, &b"y"[..])));
        let mut tiny = Output::default();
        for i in 0..MAX_CHUNKS + 1 {
            tiny.push(if i % 2 == 0 { FRAME_STDOUT } else { FRAME_STDERR }, b"x", CAPACITY);
        }
        assert_eq!((tiny.chunks.len(), tiny.start), (MAX_CHUNKS, 1));
        let n = MAX_CHUNKS as u64;
        assert_eq!([0, n, n + 1].map(|o| tiny.chunks_from(o)), [MAX_CHUNKS, 1, 0]);
    }

    #[test]
    fn a_new_attachment_replaces_the_previous_one() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let output = live(&mut sessions.lock().unwrap(), "s", Output::default());
        let total = 64 * BLOCK as u64;
        output.0.lock().unwrap().push(FRAME_STDOUT, &vec![b'x'; total as usize], CAPACITY);
        let attach = |offset: u64| {
            let (conn, peer) = UnixStream::pair().unwrap();
            let dup = File::from(std::os::fd::OwnedFd::from(conn.try_clone().unwrap()));
            let (sessions, statuses) = (sessions.clone(), statuses.clone());
            (thread::spawn(move || handle(conn, b"", Some(dup), &format!("ATTACH s {offset}"), &sessions, &statuses)), peer)
        };
        // The first client reads nothing, so its handler blocks writing to it.
        let (first, first_peer) = attach(0);
        thread::sleep(Duration::from_millis(200));
        assert!(!first.is_finished());
        let (handlers, peers): (Vec<_>, Vec<_>) = (0..50).map(attach).unzip();
        let deadline = Instant::now() + Duration::from_secs(5);
        while handlers.iter().filter(|h| !h.is_finished()).count() > 1 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(first.is_finished(), "a blocked writer was not shut down");
        assert_eq!(handlers.iter().filter(|h| !h.is_finished()).count(), 1, "more than one live attachment");
        let survivor = handlers.iter().position(|h| !h.is_finished()).unwrap();
        let ring = output.0.lock().unwrap();
        assert!(ring.attachments == 51 && ring.attached.is_some());
        drop(ring);
        drop(first_peer);
        // The survivor streams from its own offset, without gaps, to the exit.
        output.0.lock().unwrap().exit = Some(0);
        output.1.notify_all();
        let mut r = &peers[survivor];
        let mut sent = survivor as u64;
        loop {
            let mut hdr = [0u8; 5];
            std::io::Read::read_exact(&mut r, &mut hdr).unwrap();
            let mut payload = vec![0; u32::from_le_bytes(hdr[1..].try_into().unwrap()) as usize];
            std::io::Read::read_exact(&mut r, &mut payload).unwrap();
            if hdr[0] != FRAME_MSG {
                assert_eq!(u64::from_le_bytes(payload[..8].try_into().unwrap()), sent);
            }
            match hdr[0] {
                FRAME_STDOUT => sent += payload.len() as u64 - 8,
                FRAME_EXIT => break,
                _ => {}
            }
        }
        assert_eq!(sent, total);
        for h in handlers.into_iter().chain([first]) {
            let _ = h.join().unwrap();
        }
        let ring = output.0.lock().unwrap();
        assert!(ring.attached.is_none() && ring.detached.is_some());
    }

    #[test]
    fn writer_does_not_hold_ring_lock() {
        struct Writer(Session);
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                assert!(self.0 .0.try_lock().is_ok());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut ring = Output { exit: Some(0), ..Default::default() };
        ring.push(FRAME_STDOUT, b"hello", CAPACITY);
        let output = attached(ring);
        drain(&mut Writer(output.clone()), &output, 0, 1).unwrap();
    }

    #[test]
    fn requests() {
        assert!(matches!(parse("SESSION abc 3\n").unwrap(), Request::Start { id: "abc", len: 3 }));
        assert!(matches!(parse("ATTACH abc 42").unwrap(), Request::Attach { offset: 42, .. }));
        assert!(matches!(parse("CLOSE abc").unwrap(), Request::Close { .. }));
        for bad in ["SESSION 3", "SESSION abc -1", "SESSION abc 1048577", "ATTACH abc -1", "ATTACH abc 1 extra", "CLOSE", "CLOSE a/b", "EXEC 3"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn loss_and_exit_are_explicit_and_retained() {
        let mut ring = Output { exit: Some(7), ..Default::default() };
        ring.push(FRAME_STDOUT, b"abcdef", 3);
        let output = attached(ring);
        let drained = |offset| {
            let mut wire = Vec::new();
            drain(&mut wire, &output, offset, 1).unwrap();
            wire
        };
        assert_eq!(drained(0), [&[FRAME_LOST, 8, 0, 0, 0][..], &3u64.to_le_bytes()].concat());
        for _ in 0..2 {
            assert_eq!(drained(6), [&[FRAME_EXIT, 12, 0, 0, 0][..], &6u64.to_le_bytes(), &7i32.to_le_bytes()].concat());
        }
        assert!(drained(7).ends_with(b"error: offset past output end"));
        output.0.lock().unwrap().closed = true;
        assert!(drained(6).ends_with(b"error: session closed"));
    }
}
