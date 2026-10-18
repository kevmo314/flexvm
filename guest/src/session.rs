//! Resumable commands: `SESSION <id> <len>` (then `len` bytes of shell command), `ARGV <id> <len>` (JSON argv and options), `ATTACH <id> <offset>`,
//! `CLOSE <id>`. Output frames start with their stream offset (u64 LE); the exit frame is offset plus code.
//! After an exit, the client may send SESSION_DONE on the attachment, within `ACK_WAIT`, to release the
//! session; without that acknowledgement the exit stays available for reattachment.
//! The command runs in a process group of its own; its exit is the shell's, recorded once output stops or
//! `DRAIN` after the shell exits; background processes that keep its pipes open run on, their later output
//! read and dropped (by one thread, for at most `MAX_DISCARDED` pipes: past that, a job's next write gets
//! SIGPIPE). Closing a session whose shell has not exited kills its process group (not processes that
//! left it with setsid or setpgid: that would take a cgroup per session); closing an unknown one cancels it, so
//! a start still in flight never runs. Sessions whose client is gone are closed in time, running ones too.
//! At most `MAX_LIVE` sessions are running or still sending their output; sessions whose exit was sent
//! but not acknowledged (a slow reader acknowledges late) do not count towards that, but towards
//! `MAX_UNACKNOWLEDGED` of their own, past which the oldest is closed. Closed ones leave a tombstone so a
//! delayed `SESSION` retry cannot rerun the command. Rings keep `BASE` bytes and grow towards `CAPACITY`
//! from a shared pool; an unacknowledged session's output is all from the pool (the oldest such are
//! closed to make room for it): at most `MAX_LIVE * BASE + POOL` (plus a partial `BLOCK` each).
//! One attachment per session; a new one shuts the old one down. Output waits for it rather than
//! overwrite unsent bytes; writers never hold the ring lock.
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::hash::{BuildHasher, BuildHasherDefault};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::proto::{frame, valid_session_id, FRAME_EXIT, FRAME_LOST, FRAME_MSG, FRAME_STDERR, FRAME_STDOUT, MAX_BODY, SESSION_DONE};
use crate::{fail, kill_running, msg, spawn_watched, wait_exit, Statuses};

const CAPACITY: usize = 4 * 1024 * 1024;
const MAX_CHUNKS: usize = 4096;
/// Consecutive output of one kind is coalesced into chunks of up to this size.
const BLOCK: usize = 16 * 1024;
const MAX_LIVE: usize = 64;
const MAX_UNACKNOWLEDGED: usize = 192;
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
/// A running one's is closed (its command killed) after this long: its client was killed, say, or
/// gave up reattaching. Both count only time the guest ran (`awake`): a CLI keeps retrying through
/// a pause of any length.
const ABANDONED_RUNNING: Duration = Duration::from_secs(600);
/// Test-only: overrides `ABANDONED_RUNNING` (seconds), and sweeps every second, so that e2e tests
/// need not wait 10 minutes and a sweep always comes right after a resume.
const ABANDONED_RUNNING_KNOB: &str = "/run/flexvm-test-abandoned-running-secs";
/// How often the awake clock ticks, and the most one tick adds.
const TICK: Duration = Duration::from_secs(1);
const MAX_TICK: Duration = Duration::from_secs(2);
/// How long a handler waits for SESSION_DONE after sending the exit.
const ACK_WAIT: Duration = Duration::from_secs(2);

/// Milliseconds the guest has run since `start_clock`. A plain pause stops the vCPUs but not the
/// TSC, so CLOCK_MONOTONIC (and `Instant`) jump by the paused time on resume; this counts it as one
/// tick of at most `MAX_TICK`. A starved ticker only makes it slow, never fast.
static AWAKE_MS: AtomicU64 = AtomicU64::new(0);
/// Orders sent exits, oldest first.
static DELIVERIES: AtomicU64 = AtomicU64::new(0);

pub fn start_clock() {
    thread::spawn(|| {
        let mut last = Instant::now();
        loop {
            thread::sleep(TICK);
            let now = Instant::now();
            AWAKE_MS.fetch_add(tick(now - last).as_millis() as u64, Ordering::Relaxed);
            last = now;
        }
    });
}

/// What one tick that took `elapsed` adds to the awake clock.
fn tick(elapsed: Duration) -> Duration {
    elapsed.min(MAX_TICK)
}

fn awake() -> Duration {
    Duration::from_millis(AWAKE_MS.load(Ordering::Relaxed))
}

/// `ABANDONED_RUNNING_KNOB` (seconds) as `cleanup` last read it; `u64::MAX` while it is not set.
static KNOB: AtomicU64 = AtomicU64::new(u64::MAX);

/// Reads the knob file: by `cleanup` only, once a sweep, outside the sessions lock.
fn read_knob() -> Option<Duration> {
    let secs = std::fs::read_to_string(ABANDONED_RUNNING_KNOB).ok().and_then(|s| s.trim().parse::<u64>().ok()).filter(|&s| s != u64::MAX);
    KNOB.store(secs.unwrap_or(u64::MAX), Ordering::Relaxed);
    secs.map(Duration::from_secs)
}

fn knob() -> Option<Duration> {
    Some(KNOB.load(Ordering::Relaxed)).filter(|&s| s != u64::MAX).map(Duration::from_secs)
}

/// How long the sweeper sleeps between `cleanup`s.
pub fn sweep_every() -> Duration {
    knob().map_or(Duration::from_secs(60), |_| Duration::from_secs(1))
}
/// Output still read after the shell exits, as for the app.
pub(crate) const DRAIN: Duration = Duration::from_secs(2);

type Session = Arc<(Mutex<Output>, Condvar)>;
pub type Sessions = Arc<Mutex<Table>>;

fn session(output: Output) -> Session {
    Arc::new((Mutex::new(output), Condvar::new()))
}

pub struct Table {
    live: HashMap<String, Entry>,
    closed: HashMap<String, Duration>,
    cancelled: HashMap<String, Duration>,
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
    /// The shell's token in `Statuses`: after the shell is reaped its pid may be another child's.
    token: u64,
}

fn fingerprint(command: &[u8]) -> (usize, u64) {
    (command.len(), BuildHasherDefault::<std::collections::hash_map::DefaultHasher>::default().hash_one(command))
}

impl Table {
    fn new_output(&self) -> Output {
        Output { reservation: Reservation { pool: Some(self.pool.clone()), bytes: 0 }, ..Default::default() }
    }

    /// Kills the command's process group first if its shell is still running (`kill`).
    fn close(&mut self, id: &str, kill: Option<&Statuses>) {
        if let Some(entry) = self.live.remove(id) {
            // Only while its own shell is unreaped (the token, under the reaper's lock) is the group
            // surely the command's. An exited shell's jobs run on.
            if let Some(statuses) = kill {
                kill_running(statuses, entry.group, entry.token, true, libc::SIGKILL);
            }
            let mut output = entry.output.0.lock().unwrap();
            output.closed = true;
            output.chunks = VecDeque::new();
            output.start = output.end;
            output.reservation.release();
            let attached = output.attached.as_mut().and_then(|a| a.conn.take());
            drop(output);
            entry.output.1.notify_all();
            // Unblocks its handler even mid-write to a stalled client, as a new attachment would.
            if let Some(conn) = attached {
                unsafe { libc::shutdown(conn.as_raw_fd(), libc::SHUT_RDWR) };
            }
            self.closed.insert(id.to_string(), awake());
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
        self.cancelled.insert(id.to_string(), awake());
    }

    /// Closes sessions whose client is gone: finished ones after `ABANDONED`, running ones (killing
    /// their command) after `ABANDONED_RUNNING`.
    fn reclaim(&mut self, statuses: &Statuses) {
        self.reclaim_after(statuses, knob().unwrap_or(ABANDONED_RUNNING), awake());
    }

    /// `now` is on the awake clock.
    fn reclaim_after(&mut self, statuses: &Statuses, running_after: Duration, now: Duration) {
        let abandoned: Vec<String> = self
            .live
            .iter()
            .filter_map(|(id, entry)| {
                let o = entry.output.0.lock().unwrap();
                let after = if o.exit.is_some() { ABANDONED } else { running_after };
                ((!o.detached || o.exit.is_some()) && o.attached.is_none() && o.gone.is_some_and(|t| now.saturating_sub(t) >= after)).then(|| id.clone())
            })
            .collect();
        for id in abandoned {
            self.close(&id, Some(statuses));
        }
    }

    /// Sessions whose exit was sent but not acknowledged, oldest first.
    fn unacknowledged(&self) -> Vec<(u64, String)> {
        let mut found: Vec<_> = self.live.iter().filter_map(|(id, e)| e.output.0.lock().unwrap().delivered.map(|at| (at, id.clone()))).collect();
        found.sort();
        found
    }

    fn unacknowledged_count(&self) -> usize {
        self.live.values().filter(|e| e.output.0.lock().unwrap().delivered.is_some()).count()
    }

    /// Sessions running or still sending their output.
    fn running(&self) -> usize {
        self.live.len() - self.unacknowledged_count()
    }

    /// The exit went out on attachment `me`: unless a newer attachment has taken over, the session
    /// stops counting towards `MAX_LIVE`. All of its output then comes from the pool, the oldest
    /// unacknowledged sessions closed to make room; if even that is not enough, it keeps counting.
    fn delivered(&mut self, output: &Session, me: u64) {
        {
            let mut o = output.0.lock().unwrap();
            if o.closed || o.attached.as_ref().is_none_or(|a| a.id != me) {
                return;
            }
            o.delivered = Some(DELIVERIES.fetch_add(1, Ordering::Relaxed));
        }
        loop {
            let mut o = output.0.lock().unwrap();
            let retained = (o.end - o.start) as usize;
            if o.reservation.fit(retained) {
                break;
            }
            drop(o);
            let older = self.unacknowledged().into_iter().map(|(_, id)| id).find(|id| !Arc::ptr_eq(&self.live[id].output, output));
            match older {
                Some(id) => self.close(&id, None),
                None => return output.0.lock().unwrap().delivered = None,
            }
        }
        self.trim_unacknowledged();
    }

    fn trim_unacknowledged(&mut self) {
        let unacknowledged = self.unacknowledged();
        for (_, id) in &unacknowledged[..unacknowledged.len().saturating_sub(MAX_UNACKNOWLEDGED)] {
            self.close(id, None);
        }
    }

    fn admit(&mut self, statuses: &Statuses) -> io::Result<()> {
        // Detached exits also retain their start acknowledgement for a retry, within the same bound.
        self.trim_unacknowledged();
        if self.running() >= MAX_LIVE {
            self.reclaim(statuses);
            if self.running() >= MAX_LIVE {
                return Err(io::Error::other(format!("too many sessions: {MAX_LIVE} commands are running or awaiting their client")));
            }
        }
        if self.closed.len() >= MAX_TOMBSTONES {
            // Only a badly delayed retry of the oldest one's creation could still arrive.
            match self.closed.iter().min_by_key(|(_, at)| **at).map(|(id, at)| (id.clone(), *at)) {
                Some((id, at)) if awake().saturating_sub(at) >= GRACE => drop(self.closed.remove(&id)),
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

    /// Holds exactly `need` bytes from the pool, giving back any more, or (all or nothing) taking what
    /// is missing; false if the pool has too little.
    fn fit(&mut self, need: usize) -> bool {
        let Some(pool) = &self.pool else { return true };
        if self.bytes >= need {
            pool.fetch_add(self.bytes - need, Ordering::AcqRel);
            self.bytes = need;
            return true;
        }
        let want = need - self.bytes;
        let taken = pool.fetch_update(Ordering::AcqRel, Ordering::Acquire, |a| a.checked_sub(want)).is_ok();
        if taken {
            self.bytes = need;
        }
        taken
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
    /// When it was detached, on the awake clock.
    gone: Option<Duration>,
    /// The current attachment was sent the exit, unacknowledged (in `DELIVERIES`' order).
    delivered: Option<u64>,
    reservation: Reservation,
    detached: bool,
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
        unsent && (self.attached.is_some() || self.gone.is_some_and(|t| awake().saturating_sub(t) < GRACE))
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
    Start { id: &'a str, len: usize, argv: bool },
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
        [verb @ ("SESSION" | "ARGV"), _, len] => match len.parse::<usize>() {
            Ok(len) if len <= MAX_BODY => Ok(Request::Start { id, len, argv: *verb == "ARGV" }),
            _ => Err(io::Error::other("bad command length")),
        },
        ["ATTACH", _, offset] => Ok(Request::Attach { id, offset: offset.parse().map_err(|_| io::Error::other("bad offset"))? }),
        ["CLOSE", _] => Ok(Request::Close { id }),
        _ => Err(io::Error::other("bad session request")),
    }
}

/// `SESSIONS`' reply: how many sessions are live, and how many of those are exited and unacknowledged.
pub fn counts(sessions: &Sessions) -> String {
    let table = sessions.lock().unwrap();
    format!("ok {} {}", table.live.len(), table.unacknowledged_count())
}

pub fn cleanup(sessions: &Sessions, statuses: &Statuses) {
    let running_after = read_knob().unwrap_or(ABANDONED_RUNNING);
    let mut table = sessions.lock().unwrap();
    table.reclaim_after(statuses, running_after, awake());
    let now = awake();
    table.closed.retain(|_, at| now.saturating_sub(*at) < RETENTION);
    table.cancelled.retain(|_, at| now.saturating_sub(*at) < RETENTION);
}

/// Request errors become a message frame; write errors just end the stream (a frame may be cut short).
/// `conn` duplicates `w`'s connection so a later attachment can shut it down.
pub fn handle(mut w: impl Write, body: &[u8], conn: Option<File>, line: &str, sessions: &Sessions, statuses: &Statuses) -> io::Result<()> {
    match open(body, conn, line, sessions, statuses) {
        Ok(Some((id, offset, (output, me)))) => {
            if output.0.lock().unwrap().detached {
                return msg(&mut w, id);
            }
            let result = msg(&mut w, id).and_then(|_| drain(&mut w, &output, offset, me));
            if matches!(result, Ok(true)) {
                sessions.lock().unwrap().delivered(&output, me);
            }
            // Without an acknowledgement (a lost exit, or a client keeping the session), a retry still finds the exit.
            let acknowledged = matches!(result, Ok(true)) && acknowledge(&output, me);
            let mut table = sessions.lock().unwrap();
            let mut ring = output.0.lock().unwrap();
            // A replaced attachment leaves the session to its successor.
            if ring.attached.as_ref().is_some_and(|a| a.id == me) {
                ring.attached = None;
                ring.gone = Some(awake());
            }
            let close = acknowledged && ring.attached.is_none() && ring.attachments == me;
            drop(ring);
            if close {
                table.close(id, None);
            }
            drop(table);
            output.1.notify_all();
            result.map(|_| ())
        }
        Ok(None) => msg(&mut w, "closed"),
        Err(e) => fail(&mut w, e),
    }
}

type Attached = (Session, u64);

/// The refusal of a command that cannot be run, carrying the status its client exits with.
pub(crate) fn cannot_run(code: i32, e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{e}{}{code}", crate::proto::EXIT_STATUS))
}

fn argv_command(argv: &[String]) -> io::Result<Command> {
    let program = argv.first().filter(|s| !s.is_empty()).ok_or_else(|| io::Error::other("exec needs CMD"))?;
    if argv.iter().any(|s| s.contains('\0')) {
        return Err(io::Error::other("command contains a nul byte"));
    }
    let mut cmd = Command::new(program);
    cmd.args(&argv[1..]);
    Ok(cmd)
}

/// The fd the shell sources the command from; dash takes only single-digit fds in redirections.
const SCRIPT_FD: i32 = 9;

/// Sources the command from a memfd: argv caps one argument at 128 KiB (MAX_ARG_STRLEN), the
/// request body at 1 MiB. `.` opens the file afresh (dash and busybox ash keep that fd cloexec,
/// bash reads it whole and closes it), so the script's first act closes the inherited fd and
/// nothing the command starts holds it. The prefix shares the first line, keeping line numbers.
fn shell_command(command: &str) -> io::Result<Command> {
    if command.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "command contains a nul byte"));
    }
    // Cloexec from creation, so no other thread's child inherits it while it is open here.
    let fd = unsafe { libc::memfd_create(c"flexvm-session".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut script = unsafe { File::from_raw_fd(fd) };
    script.write_all(format!("exec {SCRIPT_FD}<&-; ").as_bytes())?;
    script.write_all(command.as_bytes())?;
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", &format!(". /proc/self/fd/{SCRIPT_FD}")]);
    // Runs after std has set up stdio, so fd 9 can be taken; dup2 leaves the copy inheritable.
    unsafe {
        cmd.pre_exec(move || {
            let fd = script.as_raw_fd();
            let ok = if fd == SCRIPT_FD { libc::fcntl(fd, libc::F_SETFD, 0) } else { libc::dup2(fd, SCRIPT_FD) };
            if ok < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(cmd)
}

fn open<'a>(body: &[u8], conn: Option<File>, line: &'a str, sessions: &Sessions, statuses: &Statuses) -> io::Result<Option<(&'a str, u64, Attached)>> {
    let gone = || io::Error::other("session closed");
    let unknown = || io::Error::other("unknown session");
    Ok(Some(match parse(line)? {
        Request::Start { id, len, argv } => {
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
            table.admit(statuses)?;
            let command = std::str::from_utf8(command).map_err(io::Error::other)?;
            let spec = argv.then(|| crate::proto::Exec::decode(command).map_err(io::Error::other)).transpose()?;
            let mut cmd = match &spec {
                Some(spec) => argv_command(&spec.argv)?,
                None => shell_command(command)?,
            };
            let detached = spec.as_ref().is_some_and(|s| s.detach);
            let output = session(Output { detached, gone: detached.then(awake), ..table.new_output() });
            // Start the pump first: if no thread can be had, nothing has run yet.
            let (tx, rx) = mpsc::sync_channel::<(Child, Option<OwnedFd>, u64)>(1);
            let (pumped, statuses_) = (output.clone(), statuses.clone());
            thread::Builder::new()
                .spawn(move || {
                    if let Ok((mut child, exited, token)) = rx.recv() {
                        let rest = crate::pump_until(child.stdout.take(), child.stderr.take(), exited, DRAIN, |kind, data| deliver(&pumped, kind, data));
                        // Closed, they would kill a background process's next write with SIGPIPE.
                        crate::discard(rest);
                        // By token: the pid may be another child's by now, however long the client took.
                        let exit = wait_exit(&statuses_, token, None);
                        let mut ring = pumped.0.lock().unwrap();
                        ring.exit = exit;
                        if ring.detached {
                            ring.delivered = Some(DELIVERIES.fetch_add(1, Ordering::Relaxed));
                            ring.gone = Some(awake());
                        }
                        drop(ring);
                        pumped.1.notify_all();
                    }
                })
                .map_err(|e| io::Error::new(e.kind(), format!("cannot start session thread: {e}")))?;
            cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
            if let Some(work) = crate::mem::work_procs() {
                crate::mem::enter(&mut cmd, work, false);
            }
            if let Some(spec) = &spec {
                crate::app::configure_exec(&mut cmd, &spec.env, spec.workdir.as_deref(), spec.user.as_deref())?;
            }
            // argv commands also work in images without a shell.
            let (child, exited, token) = spawn_watched(&mut cmd, statuses, true).map_err(|e| {
                let program = cmd.get_program().to_string_lossy().into_owned();
                match (&spec, e.kind()) {
                    // The directory was checked: not found is the program (or its interpreter).
                    (Some(_), io::ErrorKind::NotFound) => cannot_run(127, format!("cannot run {program}: {e}")),
                    (Some(_), _) => cannot_run(126, format!("cannot run {program}: {e}")),
                    (None, kind) => {
                        let hint = if kind == io::ErrorKind::NotFound { " (does the image have a shell?)" } else { "" };
                        io::Error::new(kind, format!("cannot run /bin/sh: {e}{hint}"))
                    }
                }
            })?;
            table.live.insert(id.to_string(), Entry { command: fingerprint, output: output.clone(), group: child.id() as i32, token });
            // Attached before any output, so none is overwritten before it is sent.
            let attached = attach(&output, 0, conn);
            let _ = tx.send((child, exited, token));
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
            // A start still in flight (a client interrupted at once) must not run. Closing again
            // (a retried acknowledgement) is fine.
            if !table.live.contains_key(id) && !table.ended(id) {
                table.cancel(id);
            }
            table.close(id, Some(statuses));
            return Ok(None);
        }
    }))
}

/// Makes `conn` the only attachment, streaming from `offset`; shuts down the one it replaces.
fn attach(output: &Session, offset: u64, conn: Option<File>) -> Attached {
    let mut ring = output.0.lock().unwrap();
    if ring.detached {
        return (output.clone(), 0);
    }
    ring.attachments += 1;
    let id = ring.attachments;
    let previous = ring.attached.replace(Attachment { id, conn });
    // Its exit is not sent until this attachment sends it.
    ring.delivered = None;
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
    if ring.closed || ring.detached {
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

/// SESSION_DONE from the client on attachment `me`, within `ACK_WAIT` of its exit frame (a newer attachment
/// shuts it down). A client acknowledges once it wrote all output out: a slow reader's comes too late.
fn acknowledge(output: &Session, me: u64) -> bool {
    let conn = output.0.lock().unwrap().attached.as_ref().filter(|a| a.id == me).and_then(|a| a.conn.as_ref()).and_then(|c| c.try_clone().ok());
    let Some(mut conn) = conn else { return false };
    let mut ready = libc::pollfd { fd: conn.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let mut ack = [0];
    (unsafe { libc::poll(&mut ready, 1, ACK_WAIT.as_millis() as i32) }) > 0 && conn.read(&mut ack).is_ok_and(|n| n == 1) && ack[0] == SESSION_DONE
}

fn drain(w: &mut impl Write, output: &Session, mut offset: u64, me: u64) -> io::Result<bool> {
    loop {
        let data = {
            let ring = output.0.lock().unwrap();
            if ring.attached.as_ref().is_none_or(|a| a.id != me) {
                // Replaced; the newer attachment owns the cursor now.
                return Ok(false);
            }
            let error = if ring.closed { Some("session closed") } else { (offset > ring.end).then_some("offset past output end") };
            if let Some(e) = error {
                drop(ring);
                return fail(w, e).map(|_| false);
            }
            if offset < ring.start {
                frame(FRAME_LOST, &[&ring.start.to_le_bytes()])
            } else if let Some((kind, data)) = ring.read_chunk(offset) {
                frame(kind, &[&offset.to_le_bytes(), data])
            } else if let Some(code) = ring.exit {
                frame(FRAME_EXIT, &[&offset.to_le_bytes(), &code.to_le_bytes()])
            } else {
                let timeout = output.1.wait_timeout(ring, Duration::from_secs(1)).unwrap().1;
                if !timeout.timed_out() {
                    continue;
                }
                frame(FRAME_MSG, &[b"waiting"])
            }
        };
        w.write_all(&data)?;
        match data[0] {
            FRAME_STDOUT | FRAME_STDERR => {
                offset += (data.len() - 5 - 8) as u64;
                let mut ring = output.0.lock().unwrap();
                if ring.attached.as_ref().is_some_and(|a| a.id == me) {
                    ring.sent = offset.clamp(ring.start, ring.end);
                }
                drop(ring);
                output.1.notify_all();
            }
            FRAME_EXIT | FRAME_LOST => return Ok(data[0] == FRAME_EXIT),
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
        table.live.insert(id.to_string(), Entry { command: fingerprint(b"true"), output: output.clone(), group: 0, token: 0 });
        output
    }

    /// `gone`: when its client left, on the awake clock.
    fn finished(table: &mut Table, id: &str, gone: Option<Duration>) -> Session {
        live(table, id, Output { exit: Some(0), gone, ..Default::default() })
    }

    fn attached(ring: Output) -> Session {
        session(Output { attached: Some(Attachment { id: 1, conn: None }), ..ring })
    }

    fn statuses() -> Statuses {
        Statuses::default()
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

    /// Runs the calling test, by its full `name`, in a child process with `env` set: true in that child.
    /// Isolated so advancing the clock cannot expire other tests' sessions.
    fn in_child(env: &str, name: &str) -> bool {
        if std::env::var_os(env).is_some() {
            return true;
        }
        assert!(Command::new(std::env::current_exe().unwrap()).args(["--exact", name]).env(env, "1").status().unwrap().success());
        false
    }

    fn set_clock(at: Duration) {
        AWAKE_MS.store(at.as_millis() as u64, Ordering::Relaxed);
    }

    /// Waits for every process in `group` to be gone, reaping them as PID 1 would.
    fn wait_group_gone(group: i32, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while unsafe { libc::kill(-group, 0) } == 0 {
            assert!(Instant::now() < deadline, "{what}");
            unsafe { libc::waitpid(-group, std::ptr::null_mut(), libc::WNOHANG) };
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Starts a handler for `line` on a new connection; returns it and the client's end.
    fn handler(sessions: &Sessions, statuses: &Statuses, line: String) -> (thread::JoinHandle<io::Result<()>>, UnixStream) {
        let (conn, peer) = UnixStream::pair().unwrap();
        let dup = File::from(OwnedFd::from(conn.try_clone().unwrap()));
        let (sessions, statuses) = (sessions.clone(), statuses.clone());
        (thread::spawn(move || handle(conn, b"", Some(dup), &line, &sessions, &statuses)), peer)
    }

    fn detach_and_join(output: &Session, t: thread::JoinHandle<()>) {
        output.0.lock().unwrap().attached = None;
        output.1.notify_all();
        t.join().unwrap();
    }

    #[test]
    fn argv_runs_without_a_shell_and_preserves_literal_arguments() {
        let words = ["/usr/bin/printf", "%s\n", "a b", "", "$HOME", "x; echo wrong", "'quoted'"].map(String::from);
        let output = argv_command(&words).unwrap().output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"a b\n\n$HOME\nx; echo wrong\n'quoted'\n");
        assert!(argv_command(&[]).is_err());
        assert!(argv_command(&["".into()]).is_err());
        assert!(argv_command(&["true".into(), "\0".into()]).is_err());
        assert!(matches!(parse("ARGV abc 10").unwrap(), Request::Start { argv: true, len: 10, .. }));
        assert!(parse("ARGV abc 1048577").is_err());
    }

    #[test]
    fn detached_start_retries_acknowledge_without_attaching_or_respawning() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let body = br#"{"argv":["sleep","100"],"detach":true}"#;
        let output = live(&mut sessions.lock().unwrap(), "detached", Output { detached: true, ..Default::default() });
        sessions.lock().unwrap().live.get_mut("detached").unwrap().command = fingerprint(body);
        let line = format!("ARGV detached {}", body.len());
        for _ in 0..2 {
            let reply = request(&sessions, &statuses, &line, body);
            assert_eq!(reply, frame(FRAME_MSG, &[b"detached"]));
            assert!(output.0.lock().unwrap().attached.is_none());
        }
        output.0.lock().unwrap().exit = Some(0);
        assert_eq!(request(&sessions, &statuses, &line, body), frame(FRAME_MSG, &[b"detached"]));
        assert_eq!(sessions.lock().unwrap().live.len(), 1);
    }

    #[test]
    fn detached_output_never_blocks_and_running_jobs_are_not_abandoned() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let output = live(&mut sessions.lock().unwrap(), "detached", Output::default());
        {
            let mut ring = output.0.lock().unwrap();
            ring.detached = true;
            ring.gone = Some(Duration::ZERO);
        }
        assert_eq!(deliver(&output, FRAME_STDOUT, &vec![0; CAPACITY]), Duration::ZERO);
        assert_eq!(output.0.lock().unwrap().end, 0);
        sessions.lock().unwrap().reclaim_after(&statuses, Duration::from_secs(1), Duration::from_secs(1000));
        assert!(sessions.lock().unwrap().live.contains_key("detached"));
        output.0.lock().unwrap().exit = Some(0);
        sessions.lock().unwrap().reclaim_after(&statuses, Duration::from_secs(1), Duration::from_secs(1000));
        assert!(!sessions.lock().unwrap().live.contains_key("detached"));
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
            table.admit(&statuses).unwrap();
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
        let (mut table, st) = (Table::default(), statuses());
        // Clients left at awake time ABANDONED, but 3's and 4's at 0; it is now ABANDONED.
        let outputs: Vec<_> = (0..MAX_LIVE)
            .map(|i| {
                table.admit(&st).unwrap();
                finished(&mut table, &i.to_string(), Some(if i == 3 || i == 4 { Duration::ZERO } else { ABANDONED }))
            })
            .collect();
        assert!(table.admit(&st).unwrap_err().to_string().contains("too many sessions"));
        outputs[4].0.lock().unwrap().attached = Some(Attachment { id: 1, conn: None });
        table.reclaim_after(&st, ABANDONED_RUNNING, ABANDONED);
        table.admit(&st).unwrap();
        assert!(!table.live.contains_key("3") && table.closed.contains_key("3"));
        assert!(outputs[3].0.lock().unwrap().closed);
        assert!(table.live.contains_key("4"), "an attached reader keeps its session");
        assert_eq!(table.live.len(), MAX_LIVE - 1);
        // A running session's client gets longer.
        let mut o5 = outputs[5].0.lock().unwrap();
        (o5.exit, o5.gone) = (None, Some(Duration::ZERO));
        drop(o5);
        table.reclaim_after(&st, ABANDONED * 2, ABANDONED * 2 - Duration::from_millis(1));
        assert!(table.live.contains_key("5"));
        table.reclaim_after(&st, ABANDONED * 2, ABANDONED * 2);
        assert!(!table.live.contains_key("5") && table.closed.contains_key("5"));
    }

    #[test]
    fn a_pause_counts_as_one_short_tick() {
        assert_eq!(tick(Duration::from_millis(1003)), Duration::from_millis(1003));
        // Resumed after 20 minutes paused: the TSC (and so Instant) counted them all.
        assert_eq!(tick(Duration::from_secs(1200)), MAX_TICK);
        let (mut table, st) = (Table::default(), statuses());
        let o = live(&mut table, "s", Output { gone: Some(Duration::ZERO), ..Default::default() });
        // Detached a second before the pause, reattaching a second after it.
        let now = TICK + tick(Duration::from_secs(1200)) + TICK;
        table.reclaim_after(&st, Duration::from_secs(8), now);
        assert!(table.live.contains_key("s") && !o.0.lock().unwrap().closed, "a pause expired a running session");
    }

    #[test]
    fn output_grace_uses_the_awake_clock() {
        if !in_child("FLEXVM_GRACE_TEST", "session::tests::output_grace_uses_the_awake_clock") {
            return;
        }
        let gone = GRACE * 2;
        set_clock(gone);
        let mut ring = Output { end: BASE as u64 / 2, gone: Some(gone), ..Default::default() };
        assert!(ring.must_wait());
        // A 20-minute pause adds only one short tick, leaving the client its grace.
        set_clock(gone + tick(Duration::from_secs(1200)));
        assert!(ring.must_wait());
        set_clock(gone + GRACE - Duration::from_millis(1));
        assert!(ring.must_wait());
        set_clock(gone + GRACE);
        assert!(!ring.must_wait());
        ring.attached = Some(Attachment { id: 1, conn: None });
        assert!(ring.must_wait());
    }

    #[test]
    fn abandoned_running_sessions_are_killed_and_reclaimed() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let after = Duration::from_millis(300);
        // Their clients are gone at once (`start`'s connection is closed).
        let (gone, group) = start(&sessions, &statuses, "gone", b"sleep 100 & sleep 100");
        let (kept, kept_group) = start(&sessions, &statuses, "kept", b"sleep 100");
        // Detached at awake time 0 (the clock does not run in tests).
        assert_eq!(gone.0.lock().unwrap().gone, Some(Duration::ZERO));
        sessions.lock().unwrap().reclaim_after(&statuses, after, after - Duration::from_millis(1));
        assert!(sessions.lock().unwrap().live.contains_key("gone"), "reclaimed before its client had long to come back");
        // A client came back to this one.
        attach(&kept, 0, None);
        sessions.lock().unwrap().reclaim_after(&statuses, after, after);
        let table = sessions.lock().unwrap();
        assert!(!table.live.contains_key("gone") && table.closed.contains_key("gone"));
        assert!(table.live.contains_key("kept"), "an attached session was reclaimed");
        drop(table);
        assert!(gone.0.lock().unwrap().closed);
        let status = reap(&statuses, group);
        assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL);
        wait_group_gone(group, "the abandoned command's background process survived");
        assert!(request(&sessions, &statuses, "CLOSE kept", b"").ends_with(b"closed"));
        reap(&statuses, kept_group);
        let ring = kept.0.lock().unwrap();
        assert!(kept.1.wait_timeout_while(ring, DRAIN * 3, |r| r.exit.is_none()).unwrap().0.exit.is_some());
    }

    #[test]
    fn exit_is_kept_by_token_when_the_pid_is_reused_while_the_pump_waits() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        // Half the ring, then more: with its client away but within GRACE, the pump waits for it
        // before taking the rest, and the shell exits meanwhile (the rest fits the pipe).
        let (output, group) = start(&sessions, &statuses, "slow", b"head -c 65536 /dev/zero; sleep 0.5; echo more; exit 3");
        let status = reap(&statuses, group);
        assert_eq!(libc::WEXITSTATUS(status), 3);
        thread::sleep(Duration::from_millis(100));
        let ring = output.0.lock().unwrap();
        assert!(ring.exit.is_none() && ring.end == 65536, "the pump did not wait: {} bytes", ring.end);
        drop(ring);
        let newer = u64::MAX;
        let mut children = statuses.0.lock().unwrap();
        // An orphan reaped under the old pid is not ours; a newer child that got the pid has its own token.
        assert!(!children.reaped(group, 77));
        children.running.insert(group, newer);
        assert!(children.reaped(group, 9));
        drop(children);
        statuses.1.notify_all();
        // The client gave up: output goes on.
        output.0.lock().unwrap().gone = None;
        output.1.notify_all();
        let ring = output.0.lock().unwrap();
        let (ring, timeout) = output.1.wait_timeout_while(ring, DRAIN * 5, |r| r.exit.is_none()).unwrap();
        assert!(!timeout.timed_out(), "the pump never got its exit");
        assert_eq!((ring.exit, ring.end), (Some(3), 65536 + 5));
        drop(ring);
        assert_eq!(wait_exit(&statuses, newer, Some(Instant::now())), Some(9), "the newer child's status was taken");
        assert!(statuses.0.lock().unwrap().is_empty());
    }

    #[test]
    fn closing_shuts_down_a_stalled_attachment() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let output = live(&mut sessions.lock().unwrap(), "s", Output::default());
        output.0.lock().unwrap().push(FRAME_STDOUT, &vec![b'x'; 64 * BLOCK], CAPACITY);
        let (handler, _peer) = handler(&sessions, &statuses, "ATTACH s 0".into());
        // The client reads nothing, so its handler blocks writing to it.
        thread::sleep(Duration::from_millis(200));
        assert!(!handler.is_finished());
        assert!(request(&sessions, &statuses, "CLOSE s", b"").ends_with(b"closed"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !handler.is_finished() {
            assert!(Instant::now() < deadline, "a writer blocked on a stalled client outlived its session");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn tombstone_expiry_uses_the_awake_clock() {
        if !in_child("FLEXVM_TOMBSTONE_TEST", "session::tests::tombstone_expiry_uses_the_awake_clock") {
            return;
        }
        let mut table = Table::default();
        let statuses = statuses();
        let old = RETENTION * 2;
        set_clock(old);
        live(&mut table, "closed", Output::default());
        table.close("closed", None);
        assert_eq!(table.closed.remove("closed"), Some(old));
        for i in 0..MAX_TOMBSTONES {
            table.closed.insert(i.to_string(), if i == 7 { old - Duration::from_secs(1) } else { old });
        }
        // A 20-minute pause adds only one short tick, leaving the tombstones their grace.
        set_clock(old + tick(Duration::from_secs(1200)));
        assert!(table.admit(&statuses).is_err());
        set_clock(old + GRACE - Duration::from_secs(1) - Duration::from_millis(1));
        assert!(table.admit(&statuses).is_err());
        set_clock(old + GRACE - Duration::from_secs(1));
        table.admit(&statuses).unwrap();
        assert_eq!(table.closed.len(), MAX_TOMBSTONES - 1);
        assert!(!table.closed.contains_key("7"), "the oldest tombstone goes first");
        table.closed.insert("new".into(), awake());
        table.closed.values_mut().for_each(|at| *at = awake());
        assert!(table.admit(&statuses).unwrap_err().to_string().contains("finished in the last"));
        table.closed.values_mut().for_each(|at| *at = old);
        let sessions = Arc::new(Mutex::new(table));
        set_clock(old + GRACE + tick(Duration::from_secs(1200)));
        cleanup(&sessions, &statuses);
        assert_eq!(sessions.lock().unwrap().closed.len(), MAX_TOMBSTONES);
        assert!(request(&sessions, &statuses, "ATTACH 0 0", b"").ends_with(b"error: session closed"));
        set_clock(old + RETENTION - Duration::from_millis(1));
        cleanup(&sessions, &statuses);
        assert_eq!(sessions.lock().unwrap().closed.len(), MAX_TOMBSTONES);
        sessions.lock().unwrap().closed.insert("recent".into(), awake());
        set_clock(old + RETENTION);
        cleanup(&sessions, &statuses);
        assert_eq!(sessions.lock().unwrap().closed.keys().collect::<Vec<_>>(), ["recent"]);
        // Cancelled IDs keep their retention across a pause too.
        let cancelled = old + RETENTION;
        sessions.lock().unwrap().cancel("cancelled");
        set_clock(cancelled + tick(Duration::from_secs(1200)));
        cleanup(&sessions, &statuses);
        assert!(request(&sessions, &statuses, "SESSION cancelled 4", b"true").ends_with(b"session closed"));
        set_clock(cancelled + RETENTION);
        cleanup(&sessions, &statuses);
        assert!(sessions.lock().unwrap().cancelled.is_empty());
    }

    #[test]
    fn ring_memory_comes_from_the_pool_and_returns() {
        let mut table = Table::default();
        let outputs: Vec<_> = (0..MAX_LIVE)
            .map(|i| {
                table.admit(&statuses()).unwrap();
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
        table.close("0", None);
        table.close("0", None);
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
        assert!(statuses.0.lock().unwrap().reaped(pid, code));
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
    fn a_512_kib_command_preserves_stdin_and_exit_status() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let mut command = String::from("if read -r line; then exit 99; fi; printf '%s' \"$0\"\n#");
        let tail = "\nprintf ' done'; exit 7";
        command.extend(std::iter::repeat_n('x', 512 * 1024 - command.len() - tail.len()));
        command.push_str(tail);
        assert_eq!(command.len(), 512 * 1024);
        let (output, group) = start(&sessions, &statuses, "large", command.as_bytes());
        let status = reap(&statuses, group);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 7);
        let ring = output.0.lock().unwrap();
        let (ring, timeout) = output.1.wait_timeout_while(ring, DRAIN * 3, |r| r.exit.is_none()).unwrap();
        assert!(!timeout.timed_out(), "exit never recorded");
        assert_eq!(ring.exit, Some(7));
        assert_eq!(ring.read_chunk(0), Some((FRAME_STDOUT, &b"/bin/sh done"[..])));
    }

    /// Neither the shell's fd 9 nor any process the command starts keeps the script's memfd.
    #[test]
    fn the_script_fd_is_not_inherited() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let command = b"[ -e /proc/$$/fd/9 ] && exit 3; /bin/sh -c 'for f in /proc/self/fd/*; do case $(readlink $f) in *flexvm-session*) exit 4;; esac; done'; printf line=$LINENO";
        let (output, group) = start(&sessions, &statuses, "fds", command);
        let status = reap(&statuses, group);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        let ring = output.0.lock().unwrap();
        let (ring, _) = output.1.wait_timeout_while(ring, DRAIN * 3, |r| r.exit.is_none()).unwrap();
        // dash leaves LINENO unset in a sourced file; bash and ash give 1, the prefix sharing the line.
        assert!(matches!(ring.read_chunk(0), Some((FRAME_STDOUT, b"line=" | b"line=1"))), "{:?}", ring.read_chunk(0));
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
        wait_group_gone(group, "the background process survived");
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
    fn closing_after_pid_reuse_spares_the_new_process() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let (output, group) = start(&sessions, &statuses, "old", b"exit 0");
        reap(&statuses, group);
        let ring = output.0.lock().unwrap();
        assert!(output.1.wait_timeout_while(ring, DRAIN * 3, |r| r.exit.is_none()).unwrap().0.exit.is_some());
        // A new command, unreaped, in a group of its own, takes the finished shell's pid.
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("100").process_group(0);
        let (victim, _, token) = spawn_watched(&mut cmd, &statuses, false).unwrap();
        let pid = victim.id() as i32;
        let old = sessions.lock().unwrap().live["old"].token;
        assert_ne!(old, token);
        sessions.lock().unwrap().live.get_mut("old").unwrap().group = pid;
        assert_eq!(statuses.0.lock().unwrap().running[&pid], token);
        assert!(request(&sessions, &statuses, "CLOSE old", b"").ends_with(b"closed"));
        thread::sleep(Duration::from_millis(100));
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) }, 0, "the new process was killed");
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        reap(&statuses, pid);
    }

    #[test]
    fn background_output_after_the_drain_is_dropped_not_refused() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let _dir = crate::test_util::TempDir::new("discard");
        let marker = _dir.join("fixture");
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
        table.admit(&statuses).unwrap();
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
        let pid = *statuses.0.lock().unwrap().running.keys().next().unwrap();
        reap(&statuses, pid);
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
        cleanup(&sessions, &statuses);
        assert!(sessions.lock().unwrap().closed.contains_key("retry"), "closed ID must remain a tombstone");
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

    fn read_to_exit(peer: &mut UnixStream) {
        let (exit, mut wire) = (frame(FRAME_EXIT, &[&0u64.to_le_bytes()[..], &0i32.to_le_bytes()]), Vec::new());
        while !wire.ends_with(&exit) {
            let mut buf = [0; 4096];
            let n = peer.read(&mut buf).unwrap();
            assert!(n > 0, "closed before its exit");
            wire.extend_from_slice(&buf[..n]);
        }
    }

    #[test]
    fn only_an_acknowledged_exit_releases_the_session() {
        for acknowledge in [false, true] {
            let (sessions, statuses) = (Sessions::default(), statuses());
            let output = finished(&mut sessions.lock().unwrap(), "done", None);
            let (handler, mut peer) = handler(&sessions, &statuses, "ATTACH done 0".into());
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            // The stream stays open after the exit (vsock passes no half-close on), for the acknowledgement.
            read_to_exit(&mut peer);
            if acknowledge {
                peer.write_all(&[SESSION_DONE]).unwrap();
            }
            drop(peer);
            handler.join().unwrap().unwrap();
            let table = sessions.lock().unwrap();
            assert_eq!(table.closed.contains_key("done"), acknowledge);
            assert_eq!(table.live.contains_key("done"), !acknowledge);
            assert_eq!(output.0.lock().unwrap().closed, acknowledge);
            drop(table);
            let retry = request(&sessions, &statuses, "ATTACH done 0", b"");
            if acknowledge {
                assert!(retry.ends_with(b"session closed"));
            } else {
                assert!(retry.ends_with(&[&0u64.to_le_bytes()[..], &0i32.to_le_bytes()].concat()));
            }
        }
    }

    #[test]
    fn an_exit_acknowledgement_cannot_close_a_newer_attachment() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let output = finished(&mut sessions.lock().unwrap(), "done", None);
        let (handler, mut peer) = handler(&sessions, &statuses, "ATTACH done 0".into());
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        read_to_exit(&mut peer);
        // Replace the old attachment while its acknowledgement is in flight.
        attach(&output, 0, None);
        let _ = peer.write_all(&[SESSION_DONE]);
        handler.join().unwrap().unwrap();
        assert!(sessions.lock().unwrap().live.contains_key("done"));
        let ring = output.0.lock().unwrap();
        assert!(!ring.closed);
        assert!(ring.delivered.is_none(), "the newer attachment was not sent the exit");
    }

    /// Attaches a client to `id` and reads to its exit, leaving the acknowledgement to the caller; returns
    /// once the guest counts the exit as sent.
    fn attach_to_exit(sessions: &Sessions, statuses: &Statuses, id: &str) -> (thread::JoinHandle<io::Result<()>>, UnixStream) {
        let output = sessions.lock().unwrap().live[id].output.clone();
        let (handler, mut peer) = handler(sessions, statuses, format!("ATTACH {id} 0"));
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        read_to_exit(&mut peer);
        let deadline = Instant::now() + Duration::from_secs(5);
        while output.0.lock().unwrap().delivered.is_none() && !output.0.lock().unwrap().closed {
            assert!(Instant::now() < deadline, "the exit was never counted as sent");
            thread::sleep(Duration::from_millis(1));
        }
        (handler, peer)
    }

    #[test]
    fn a_stalled_acknowledgement_leaves_the_exit_for_a_reattach() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        finished(&mut sessions.lock().unwrap(), "slow", None);
        let (handler, mut peer) = attach_to_exit(&sessions, &statuses, "slow");
        // The client writes its output out for seconds before it acknowledges: the handler gave up on it
        // and let go of its connection.
        thread::sleep(ACK_WAIT + Duration::from_secs(2));
        assert!(handler.is_finished());
        handler.join().unwrap().unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        let _ = peer.write_all(&[SESSION_DONE]);
        assert_eq!(counts(&sessions), "ok 1 1");
        // The exit is still there for a reattach.
        let retry = request(&sessions, &statuses, "ATTACH slow 0", b"");
        assert!(retry.ends_with(&[&0u64.to_le_bytes()[..], &0i32.to_le_bytes()].concat()));
    }

    #[test]
    fn unacknowledged_exits_never_keep_new_sessions_out() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let n = MAX_LIVE + MAX_UNACKNOWLEDGED + 5;
        // Clients that read their exit and stay silent, more of them than both limits together.
        let clients: Vec<_> = (0..n)
            .map(|i| {
                let mut table = sessions.lock().unwrap();
                table.admit(&statuses).unwrap_or_else(|e| panic!("session {i} refused: {e}"));
                finished(&mut table, &i.to_string(), None);
                drop(table);
                attach_to_exit(&sessions, &statuses, &i.to_string())
            })
            .collect();
        let table = sessions.lock().unwrap();
        assert_eq!(table.unacknowledged_count(), MAX_UNACKNOWLEDGED);
        assert_eq!(table.running(), 0);
        // The oldest made room.
        assert!((0..5).all(|i| table.closed.contains_key(&i.to_string())));
        drop(table);
        let t = Instant::now();
        for (handler, peer) in clients {
            handler.join().unwrap().unwrap();
            drop(peer);
        }
        assert!(t.elapsed() < ACK_WAIT + Duration::from_secs(3), "handlers held on for {:?}", t.elapsed());
        // Running sessions still have their limit.
        let mut table = sessions.lock().unwrap();
        for i in 0..MAX_LIVE {
            live(&mut table, &format!("running{i}"), Output::default());
        }
        assert!(table.admit(&statuses).unwrap_err().to_string().contains("too many sessions"));
    }

    #[test]
    fn an_unacknowledged_sessions_output_comes_from_the_pool() {
        let mut table = Table::default();
        let with_output = |table: &mut Table, id: &str| {
            let o = live(table, id, Output { exit: Some(0), attached: Some(Attachment { id: 1, conn: None }), ..Default::default() });
            o.0.lock().unwrap().push(FRAME_STDOUT, &vec![b'x'; BASE], BASE);
            o
        };
        table.pool.store(BASE, Ordering::SeqCst);
        let first = with_output(&mut table, "first");
        table.delivered(&first, 1);
        assert!(first.0.lock().unwrap().delivered.is_some() && table.pool.load(Ordering::SeqCst) == 0);
        // The pool is empty: the older one makes room.
        let second = with_output(&mut table, "second");
        table.delivered(&second, 1);
        assert!(table.closed.contains_key("first") && second.0.lock().unwrap().delivered.is_some());
        // An exit sent on a replaced attachment changes nothing.
        let third = with_output(&mut table, "third");
        table.delivered(&third, 2);
        assert!(third.0.lock().unwrap().delivered.is_none(), "delivered on an attachment it no longer has");
        table.delivered(&third, 1);
        assert!(table.closed.contains_key("second") && third.0.lock().unwrap().delivered.is_some());
        table.close("third", None);
        assert_eq!(table.pool.load(Ordering::SeqCst), BASE);
        // With nothing older to close, it keeps counting as running.
        table.pool.store(0, Ordering::SeqCst);
        let lone = with_output(&mut table, "lone");
        table.delivered(&lone, 1);
        assert!(lone.0.lock().unwrap().delivered.is_none() && table.running() == 1);
    }

    #[test]
    fn a_new_attachment_replaces_the_previous_one() {
        let (sessions, statuses) = (Sessions::default(), statuses());
        let output = live(&mut sessions.lock().unwrap(), "s", Output::default());
        let total = 64 * BLOCK as u64;
        output.0.lock().unwrap().push(FRAME_STDOUT, &vec![b'x'; total as usize], CAPACITY);
        let attach = |offset: u64| handler(&sessions, &statuses, format!("ATTACH s {offset}"));
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
        assert!(ring.attached.is_none() && ring.gone.is_some());
    }

    #[test]
    fn writer_sends_whole_frames_without_holding_ring_lock() {
        struct Writer(Session, usize);
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                assert!(self.0 .0.try_lock().is_ok());
                assert_eq!(bytes.len(), 5 + u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize);
                self.1 += 1;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut ring = Output { exit: Some(0), ..Default::default() };
        ring.push(FRAME_STDOUT, b"hello", CAPACITY);
        let output = attached(ring);
        let mut writer = Writer(output.clone(), 0);
        drain(&mut writer, &output, 0, 1).unwrap();
        assert_eq!(writer.1, 2);
    }

    #[test]
    fn requests() {
        assert!(matches!(parse("SESSION abc 3\n").unwrap(), Request::Start { id: "abc", len: 3, argv: false }));
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
