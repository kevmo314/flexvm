use std::ffi::{CStr, CString};
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => { return Err(format!($($arg)*).into()) };
}

/// Selects an injected result without evaluating the operation when the fault is armed.
#[macro_export]
macro_rules! fault_result {
    ($fault:expr => $injected:expr; $operation:expr) => {
        if $fault {
            $injected
        } else {
            $operation
        }
    };
}

/// Checks one syscall result without retrying, capturing errno before formatting its name.
#[macro_export]
macro_rules! syscall_check {
    ($failed:expr, $($name:tt)*) => {
        if $failed {
            let error = std::io::Error::last_os_error();
            $crate::bail!("{}: {error}", format_args!($($name)*));
        }
    };
}

/// Queues an error or warning for the VM log and stderr without blocking (`log_line`).
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        let mut line = format!($($arg)*);
        line.push('\n');
        $crate::util::log_line(line);
    }};
}

/// Informational diagnostics stay in the VM log; verbose mode also shows them on stderr.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        $crate::util::info_line(format!("{}\n", format_args!($($arg)*)));
    }};
}

static VERBOSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Returns what it was (as set, not `FLEXVM_LOG`), for a caller to put back.
pub fn set_verbose(verbose: bool) -> bool {
    VERBOSE.swap(verbose, Ordering::Relaxed)
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed) || std::env::var("FLEXVM_LOG").is_ok_and(|v| v == "debug")
}

pub fn info_line(mut line: String) {
    cap_line(&mut line, LOG_LINE_MAX);
    if log_writer().is_none_or(|tx| tx.try_send(LogMsg::Info(line)).is_err()) {
        LOG_DROPPED.fetch_add(1, Ordering::SeqCst);
    }
}

/// Lines dropped since the log writer last got through (`log_line`).
static LOG_DROPPED: AtomicUsize = AtomicUsize::new(0);
static WRITER: OnceLock<std::sync::mpsc::SyncSender<LogMsg>> = OnceLock::new();

/// A longer log line (a peer's error, say) is cut to this, its note of the cut included.
const LOG_LINE_MAX: usize = 16 << 10;

/// What the log writer is handed: a line, or a flush that it acknowledges
/// once every line handed to it before is written.
enum LogMsg {
    Line(String),
    Info(String),
    Flush(std::sync::mpsc::Sender<()>),
}

/// Hands `line` to this process's log writer, a thread that writes each line
/// to its log and stderr (so lines from other processes sharing the pipe
/// don't interleave with it), ignoring write errors. A stalled stderr never
/// blocks the caller, who may hold the host lock or a pager's state: past
/// 1024 queued lines a line is dropped, and the writer reports how many when
/// it next gets through. Lines from one thread keep their order.
pub fn log_line(mut line: String) {
    cap_line(&mut line, LOG_LINE_MAX);
    if log_writer().is_none_or(|tx| tx.try_send(LogMsg::Line(line)).is_err()) {
        LOG_DROPPED.fetch_add(1, Ordering::SeqCst);
    }
}

/// Logs `text` under `head` as consecutive lines of at most `LOG_CHUNK` bytes each, cut at newlines where it can, so
/// none is capped (`LOG_LINE_MAX`) and all of it, its end too, is kept.
pub fn log_long(head: &str, text: &str) {
    log_line(format!("{head}\n"));
    for chunk in log_chunks(text, LOG_CHUNK) {
        let mut line = chunk.to_string();
        if !line.ends_with('\n') {
            line.push('\n');
        }
        log_line(line);
    }
}

const LOG_CHUNK: usize = 8 << 10;
const _: () = assert!(LOG_CHUNK < LOG_LINE_MAX);

/// `text` in order, in pieces of at most `max` bytes, each ending at a newline unless one line is longer than `max`
/// (then cut on a character boundary).
fn log_chunks(mut text: &str, max: usize) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        if text.is_empty() {
            return None;
        }
        let mut end = text.len().min(max);
        if end < text.len() {
            // A character longer than `max` goes whole.
            let cut = (1..=end).rev().find(|&i| text.is_char_boundary(i)).unwrap_or_else(|| (end..).find(|&i| text.is_char_boundary(i)).unwrap());
            end = text[..cut].rfind('\n').map_or(cut, |i| i + 1);
        }
        let (chunk, rest) = text.split_at(end);
        text = rest;
        Some(chunk)
    })
}

/// Cuts `line` to at most `max` bytes, a note of the cut included, on a character boundary.
fn cap_line(line: &mut String, max: usize) {
    if line.len() > max {
        let note = |gone: usize| format!("... ({gone} bytes cut)\n");
        // What is cut is at most the whole line: its note is no longer than that one's.
        let room = max.saturating_sub(note(line.len()).len());
        let cut = (0..=room).rev().find(|&i| line.is_char_boundary(i)).unwrap_or(0);
        let gone = line.len() - cut;
        line.truncate(cut);
        line.push_str(&note(gone));
    }
}

/// The log writer, started on first use. A thread that cannot be started
/// is tried again at most once a second: until then lines are dropped, as for
/// a full queue. Only a start is waited for, never stderr.
fn log_writer() -> Option<&'static std::sync::mpsc::SyncSender<LogMsg>> {
    use std::sync::mpsc::sync_channel;
    static TRIED: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    if let Some(tx) = WRITER.get() {
        return Some(tx);
    }
    let mut tried = TRIED.lock().unwrap_or_else(|e| e.into_inner());
    if WRITER.get().is_none() && !tried.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
        *tried = Some(Instant::now());
        let (tx, rx) = sync_channel::<LogMsg>(1024);
        let writer = move || {
            write_logs(rx, |line, info| {
                let dropped = LOG_DROPPED.swap(0, Ordering::SeqCst);
                if dropped > 0 {
                    output::diagnostic(format!("flexvm: {dropped} log lines dropped: stderr was blocked\n").as_bytes(), false);
                }
                output::diagnostic(line.as_bytes(), info);
            })
        };
        // Started with every signal blocked, so that a signal for the process
        // (that `block_signals`' callers wait for) is never handed to it.
        unsafe {
            let (mut all, mut old): (libc::sigset_t, libc::sigset_t) = (std::mem::zeroed(), std::mem::zeroed());
            libc::sigfillset(&mut all);
            libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut old);
            let started = std::thread::Builder::new().name("log".into()).spawn(writer);
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
            if started.is_ok() {
                let _ = WRITER.set(tx);
            }
        }
    }
    WRITER.get()
}

/// The sink finishes each line before a later flush is acknowledged.
fn write_logs(rx: std::sync::mpsc::Receiver<LogMsg>, mut write: impl FnMut(&str, bool)) {
    for msg in rx {
        match msg {
            LogMsg::Line(line) => write(&line, false),
            LogMsg::Info(line) => write(&line, true),
            LogMsg::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

/// Waits up to `timeout` for every line handed to the log writer before this
/// call to be written, before the process exits: a flush goes through the
/// queue behind them, and a stalled stderr does not hold the exit up past it.
pub fn flush_log(timeout: Duration) {
    flush_log_by(Instant::now() + timeout);
}

/// Queues a final diagnostic (cut to the line cap if `capped`: a panic's
/// backtrace is not) and flushes it within one exit deadline. Unlike ordinary
/// `log!` calls, this may wait for room in the queue.
pub fn log_final(mut line: String, capped: bool) {
    if capped {
        cap_line(&mut line, LOG_LINE_MAX);
    }
    let deadline = Instant::now() + LOG_FLUSH;
    if !log_writer().is_some_and(|tx| send_log_by(tx, LogMsg::Line(line), deadline)) {
        LOG_DROPPED.fetch_add(1, Ordering::SeqCst);
    }
    flush_log_by(deadline);
}

fn flush_log_by(deadline: Instant) {
    // No writer: every line so far was dropped. Do not start one just to flush.
    let Some(tx) = WRITER.get() else { return };
    flush_log_to(tx, deadline);
}

fn flush_log_to(tx: &std::sync::mpsc::SyncSender<LogMsg>, deadline: Instant) {
    let (done, acked) = std::sync::mpsc::channel();
    if send_log_by(tx, LogMsg::Flush(done), deadline) {
        let _ = acked.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    }
}

fn send_log_by(tx: &std::sync::mpsc::SyncSender<LogMsg>, mut msg: LogMsg, deadline: Instant) -> bool {
    use std::sync::mpsc::TrySendError;
    loop {
        match tx.try_send(msg) {
            Ok(()) => return true,
            Err(TrySendError::Full(m)) if Instant::now() < deadline => {
                msg = m;
                std::thread::sleep(Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())));
            }
            Err(_) => return false,
        }
    }
}

/// Takes the first of `sigs` on a thread of its own, with them unblocked there so a second ends
/// the process at once; `raise_signal` there ends it as the default action would (a
/// supervisor sees the same signal), once the queued log lines are written. Inherited ignored
/// signals keep their disposition and are never blocked here (a blocked one would be queued).
/// Called before any other thread that does not block them is started.
pub fn on_signal(sigs: &[i32], action: impl FnOnce(i32) + Send + 'static) {
    let sigs: Vec<_> = sigs
        .iter()
        .copied()
        .filter(|&sig| unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigaction(sig, std::ptr::null(), &mut action) == 0 && action.sa_sigaction != libc::SIG_IGN
        })
        .collect();
    if sigs.is_empty() {
        return;
    }
    let set = block_signals(&sigs);
    std::thread::spawn(move || {
        let sig = wait_signal(&set);
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
        action(sig);
    });
}

/// Ends by the signal's default action, after flushing queued diagnostics.
pub fn raise_signal(sig: i32) -> ! {
    flush_log(LOG_FLUSH);
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        let set = block_signals(&[sig]);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(sig);
    }
    std::process::exit(128 + sig)
}

/// How long an exiting process waits for its queued log lines (`flush_log`).
pub const LOG_FLUSH: Duration = Duration::from_millis(300);

/// Exits with `code` once the queued log lines are written (`flush_log`).
pub fn exit(code: i32) -> ! {
    flush_log(LOG_FLUSH);
    std::process::exit(code)
}

/// One bounded counter slot, released on drop.
pub struct Slot(&'static AtomicUsize);

impl Slot {
    pub fn take(count: &'static AtomicUsize, max: usize) -> Option<Self> {
        count.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < max).then_some(n + 1)).ok().map(|_| Self(count))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub const PAGE_SIZE: usize = 4096;

/// Anonymous writable memory, unmapped on drop. Nonzero alignment also requests huge pages.
pub struct Mmap {
    ptr: *mut u8,
    len: usize,
}

// Owned memory, shared read-only once filled; callers write only through disjoint ranges.
unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

#[cfg(test)]
thread_local! {
    /// Tests: the next populate on this thread finds the kernel cannot (as before 5.14).
    pub static FAIL_POPULATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl Mmap {
    /// `len` bytes at a multiple of `align` (0: anywhere), initially unpopulated.
    pub fn new(len: usize, align: usize) -> io::Result<Self> {
        let full = len + align;
        let raw = unsafe { libc::mmap(std::ptr::null_mut(), full, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let raw = raw as usize;
        let start = if align == 0 { raw } else { raw.next_multiple_of(align) };
        unsafe {
            if start > raw {
                libc::munmap(raw as *mut _, start - raw);
            }
            if raw + full > start + len {
                libc::munmap((start + len) as *mut _, raw + full - start - len);
            }
            if align != 0 {
                // Only a hint: without it the mapping is ordinary pages.
                libc::madvise(start as *mut _, len, libc::MADV_HUGEPAGE);
            }
        }
        Ok(Self { ptr: start as *mut u8, len })
    }

    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Faults in every page for writing; any madvise failure falls back to per-page writes.
    /// Exclusive: the fallback writes, so it must not race another user.
    pub fn populate(&mut self) {
        const MADV_POPULATE_WRITE: libc::c_int = 23;
        #[cfg(test)]
        let fail = FAIL_POPULATE.with(|f| f.replace(false));
        #[cfg(not(test))]
        let fail = false;
        if fail || unsafe { libc::madvise(self.ptr.cast(), self.len, MADV_POPULATE_WRITE) } != 0 {
            (0..self.len).step_by(PAGE_SIZE).for_each(|o| unsafe { self.ptr.add(o).write_volatile(0) });
        }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

pub fn send_json(w: &mut impl Write, v: &impl serde::Serialize) -> io::Result<()> {
    let mut buf = serde_json::to_vec(v)?;
    buf.push(b'\n');
    w.write_all(&buf)?;
    w.flush()
}

/// Room for an exec command of the guest's 1 MiB limit even when escaping inflates it.
pub const MAX_LINE: u64 = 8 << 20;

/// None on EOF.
pub fn recv_json(r: &mut impl BufRead) -> Result<Option<serde_json::Value>> {
    recv_json_max(r, MAX_LINE)
}

pub fn recv_json_max<T: serde::de::DeserializeOwned>(r: &mut impl BufRead, max: u64) -> Result<Option<T>> {
    Ok(match recv_line_max(r, max)? {
        Some(line) => Some(serde_json::from_str(&line)?),
        None => None,
    })
}

/// One line of at most `max` bytes; None on EOF.
pub fn recv_line_max(r: &mut impl BufRead, max: u64) -> Result<Option<String>> {
    let mut line = String::new();
    if r.take(max).read_line(&mut line)? == 0 {
        return Ok(None);
    }
    if line.len() as u64 == max && !line.ends_with('\n') {
        bail!("JSON line exceeds limit of {max} bytes");
    }
    Ok(Some(line))
}

pub fn cname(name: &str) -> CString {
    CString::new(name).expect("no NUL in file names")
}

pub fn check(rc: libc::c_int) -> io::Result<()> {
    (rc >= 0).then_some(()).ok_or_else(io::Error::last_os_error)
}

/// Opens `name` in `dir` with close-on-exec; callers choose whether to follow symlinks.
pub fn openat(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
    check(fd)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn open_dir_at(dir: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    openat(dir, name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)
}

pub fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

pub fn cpath(p: &Path) -> Result<CString> {
    Ok(CString::new(p.as_os_str().as_bytes()).map_err(|_| format!("NUL in path {p:?}"))?)
}

pub fn stat_at(dir: RawFd, name: &CStr) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) };
    (rc == 0).then_some(st)
}

/// Retries on EINTR; a negative return is the OS error.
pub fn eintr<T: Copy + Default + PartialOrd>(mut f: impl FnMut() -> T) -> io::Result<T> {
    loop {
        let n = f();
        if n >= T::default() {
            return Ok(n);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Whether a nonblocking flock fails; `None` if the file cannot be opened.
pub fn locked(path: &Path, how: i32) -> Option<bool> {
    std::fs::File::open(path).ok().map(|f| crate::host::probe(&f, how).is_err())
}

/// Calls `f` every `every` until it succeeds or `timeout` has passed.
pub fn retry<T>(timeout: Duration, every: Duration, mut f: impl FnMut() -> Result<T>) -> Result<T> {
    let start = Instant::now();
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) if start.elapsed() >= timeout => return Err(e),
            Err(_) => std::thread::sleep(every),
        }
    }
}

type Addrs = Vec<std::net::SocketAddr>;

/// Lookups under way at once, process-wide: each is a thread that DNS/NSS may hold indefinitely.
const DNS_WORKERS: usize = 4;
/// How long a finished lookup's addresses answer again: one that ended after its callers
/// gave up (a slow resolver) still serves the next.
const DNS_RECENT: Duration = Duration::from_secs(5);

/// One lookup per name at a time, joined by every caller that wants that name, so a name that
/// hangs holds one worker however often it is asked for. A worker stuck in getaddrinfo keeps
/// its slot until it returns; callers wait for one, or the name's lookup, until their deadline.
pub struct Resolver {
    lookups: std::sync::Mutex<Lookups>,
    changed: std::sync::Condvar,
}

struct Lookups {
    all: Vec<Lookup>,
    workers: usize,
    next: u64,
}

struct Lookup {
    name: String,
    id: u64,
    /// When it ended, and how.
    done: Option<(Instant, Answer)>,
}

type Answer = std::result::Result<Addrs, (io::ErrorKind, String)>;

impl Resolver {
    const fn new() -> Self {
        Resolver { lookups: std::sync::Mutex::new(Lookups { all: Vec::new(), workers: 0, next: 0 }), changed: std::sync::Condvar::new() }
    }
}

static DNS: Resolver = Resolver::new();

/// HOST:PORT's addresses by `at`; an IP literal resolves at once.
pub fn resolve(addr: &str, at: Instant) -> io::Result<Addrs> {
    resolve_with(addr, at, &DNS, false, |addr| lookup(&addr))
}

/// `resolve`, giving up on the wait as soon as `stop` fails (checked every `STOP_POLL`).
pub fn resolve_until(addr: &str, at: Instant, stop: &dyn Fn() -> io::Result<()>) -> io::Result<Addrs> {
    resolve_stoppable(addr, at, &DNS, false, Some(stop), |addr| lookup(&addr))
}

/// How often a stoppable wait checks its stop.
const STOP_POLL: Duration = Duration::from_millis(100);

/// Resolves a stale address without reusing a finished answer; still joins a lookup under way.
pub fn resolve_fresh(addr: &str, at: Instant) -> io::Result<Addrs> {
    resolve_with(addr, at, &DNS, true, |addr| lookup(&addr))
}

/// HOST:PORT's addresses, as the system resolver gives them now (it may block indefinitely). Test hook: with test
/// faults on (`host::fault`), `RUN/hosts.json` ({"HOST:PORT": ["IP:PORT", ...]}) answers for the names it lists.
pub fn lookup(addr: &str) -> io::Result<Addrs> {
    use std::net::ToSocketAddrs;
    if let Some(addrs) = crate::host::faults_on().then(test_hosts).flatten().and_then(|mut h| h.remove(addr)) {
        return Ok(addrs);
    }
    addr.to_socket_addrs().map(Iterator::collect)
}

/// `RUN/hosts.json`, only as a regular file (no symlink) owned by root or this process's user and writable by no
/// one else: it decides which addresses are peers.
fn test_hosts() -> Option<std::collections::HashMap<String, Addrs>> {
    let f = trusted_file(&crate::host::run_dir()?.join("hosts.json"))?;
    serde_json::from_reader(io::BufReader::new(f).take(1 << 20)).ok()
}

/// `path` opened, if it is a regular file (not through a symlink) owned by root or this process's user and writable
/// by no one else.
pub fn trusted_file(path: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file() || !crate::host::guarded(m.uid(), m.mode(), false) {
        crate::log!("{}: ignored: not a regular file owned by root or this user, writable by no one else", path.display());
        return None;
    }
    Some(f)
}

fn resolve_with(
    addr: &str,
    at: Instant,
    dns: &'static Resolver,
    fresh: bool,
    lookup: impl FnOnce(String) -> io::Result<Addrs> + Send + 'static,
) -> io::Result<Addrs> {
    resolve_stoppable(addr, at, dns, fresh, None, lookup)
}

fn resolve_stoppable(
    addr: &str,
    at: Instant,
    dns: &'static Resolver,
    fresh: bool,
    stop: Option<&dyn Fn() -> io::Result<()>>,
    lookup: impl FnOnce(String) -> io::Result<Addrs> + Send + 'static,
) -> io::Result<Addrs> {
    let fail = |kind, why: &str| io::Error::new(kind, format!("DNS lookup of {addr}: {why}"));
    // An IP literal needs no lookup, so no time: answered even past the deadline.
    if let Ok(addr) = addr.parse() {
        return Ok(vec![addr]);
    }
    By { s: (), at }.left().map_err(|_| fail(io::ErrorKind::TimedOut, "deadline passed"))?;
    let mut lookup = Some(lookup);
    let mut mine = None;
    let mut l = dns.lookups.lock().unwrap();
    loop {
        l.all.retain(|k| k.done.as_ref().is_none_or(|(t, _)| t.elapsed() < DNS_RECENT));
        // A caller keeps to the lookup it joined: a fresh one starts beside it, never taking its answer away.
        let found = match mine {
            Some(id) => l.all.iter().position(|k| k.id == id),
            None => l.all.iter().rposition(|k| k.name == addr),
        };
        match found.map(|i| (l.all[i].id, &l.all[i].done)) {
            Some((id, None)) => mine = Some(id),
            Some((id, Some((_, res)))) if mine == Some(id) || (!fresh && res.is_ok()) => {
                return res.clone().map_err(|(kind, why)| fail(kind, &why));
            }
            // Failed before this caller asked, or a stale address needs a fresh answer: try again.
            _ => match lookup.take() {
                Some(f) if l.workers < DNS_WORKERS => {
                    let id = l.next;
                    l.next += 1;
                    let name = addr.to_owned();
                    std::thread::Builder::new().name("dns".into()).spawn(move || {
                        let res = f(name.clone())
                            .and_then(|a| if a.is_empty() { Err(io::Error::other("no address")) } else { Ok(a) })
                            .map_err(|e| (e.kind(), e.to_string()));
                        let mut l = dns.lookups.lock().unwrap();
                        l.workers -= 1;
                        if let Some(k) = l.all.iter_mut().find(|k| k.id == id) {
                            k.done = Some((Instant::now(), res));
                        }
                        dns.changed.notify_all();
                    })?;
                    l.workers += 1;
                    l.all.push(Lookup { name: addr.to_owned(), id, done: None });
                    mine = Some(id);
                }
                Some(f) => lookup = Some(f),
                None => return Err(fail(io::ErrorKind::Other, "its lookup was replaced")),
            },
        }
        let left = By { s: (), at }.left().map_err(|_| match mine {
            Some(_) => fail(io::ErrorKind::TimedOut, "not answered by the deadline"),
            None => fail(io::ErrorKind::TimedOut, &format!("all {DNS_WORKERS} DNS workers stayed busy until the deadline")),
        })?;
        if let Some(stop) = stop {
            stop()?;
        }
        l = dns.changed.wait_timeout(l, if stop.is_some() { left.min(STOP_POLL) } else { left }).unwrap().0;
    }
}

/// Splits the remaining time across addresses so a blackholed one cannot use it all.
pub fn connect_addrs(addrs: &[std::net::SocketAddr], at: Instant) -> io::Result<std::net::TcpStream> {
    let mut last = io::Error::other("no resolved address");
    for (i, a) in addrs.iter().enumerate() {
        let left = By { s: (), at }.left()?;
        match std::net::TcpStream::connect_timeout(a, left / (addrs.len() - i) as u32) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Fail before starting Firecracker when KVM is unavailable.
pub fn check_kvm() -> Result<()> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|e| format!("/dev/kvm: {e} (enable virtualization or nested virtualization; load kvm_intel/kvm_amd)"))?;
    Ok(())
}

/// Looks `addr` up and sends `req` and reads its answer, all by `at`, connecting within `wait` of that;
/// any failure names `addr`. The stream stays open for whatever follows.
pub fn rpc(addr: &str, wait: Duration, at: Instant, req: &serde_json::Value) -> Result<(std::net::TcpStream, serde_json::Value)> {
    (|| -> Result<_> {
        let addrs = resolve(addr, at)?;
        let s = connect_addrs(&addrs, at.min(Instant::now() + wait)).map_err(|e| io::Error::new(e.kind(), peer_connect_error(e)))?;
        send_json(&mut By { s: &s, at }, req)?;
        let reply = recv_json(&mut io::BufReader::new(By { s: &s, at }))?;
        Ok((s, answer(reply, "it", "refused")?))
    })()
    .map_err(|e| match e.downcast_ref::<io::Error>() {
        // Keep timeouts recognizable to callers that can retry idempotent requests.
        Some(io) => io::Error::new(io.kind(), format!("{addr}: {e}")).into(),
        None => format!("{addr}: {e}").into(),
    })
}

fn peer_connect_error(e: io::Error) -> String {
    let hint = if e.kind() == io::ErrorKind::ConnectionRefused { "; is flexvm listen running there?" } else { "" };
    format!("{e}{hint}")
}

pub fn reply(result: &Result<serde_json::Value>) -> serde_json::Value {
    result.as_ref().map_or_else(|e| serde_json::json!({"ok": false, "error": e.to_string()}), |v| serde_json::json!({"ok": true, "result": v}))
}

pub fn answer(reply: Option<serde_json::Value>, who: &str, fallback: &str) -> Result<serde_json::Value> {
    let reply = reply.ok_or_else(|| format!("{who} hung up"))?;
    if reply["ok"] != true {
        bail!("{}", reply["error"].as_str().unwrap_or(fallback));
    }
    Ok(reply["result"].clone())
}

pub trait Timed: Read {
    fn read_timeout(&self, t: Duration) -> io::Result<()>;
    fn write_timeout(&self, t: Duration) -> io::Result<()>;
}

macro_rules! timed {
    ($($t:ty),*) => {$(
        impl Timed for $t {
            fn read_timeout(&self, t: Duration) -> io::Result<()> {
                self.set_read_timeout(Some(t))
            }
            fn write_timeout(&self, t: Duration) -> io::Result<()> {
                self.set_write_timeout(Some(t))
            }
        }
    )*};
}
timed!(std::net::TcpStream, &std::net::TcpStream, UnixStream, &UnixStream);

impl<S: Timed> Timed for &mut S {
    fn read_timeout(&self, t: Duration) -> io::Result<()> {
        (**self).read_timeout(t)
    }
    fn write_timeout(&self, t: Duration) -> io::Result<()> {
        (**self).write_timeout(t)
    }
}

impl<S: Timed> Timed for io::BufReader<S> {
    fn read_timeout(&self, t: Duration) -> io::Result<()> {
        self.get_ref().read_timeout(t)
    }
    fn write_timeout(&self, t: Duration) -> io::Result<()> {
        self.get_ref().write_timeout(t)
    }
}

/// A socket for `By` that sets its read timeout a sixteenth short of `By`'s deadline and again only once it would end a
/// read past the deadline or more than an eighth before it: a page client's many small reads skip nearly every
/// setsockopt, and none waits past its deadline. Its read timeout must be set through it alone.
pub struct ReadTimeoutCache<S> {
    pub s: S,
    timeout: std::cell::Cell<Option<Duration>>,
}

impl<S> ReadTimeoutCache<S> {
    pub fn new(s: S) -> Self {
        ReadTimeoutCache { s, timeout: std::cell::Cell::new(None) }
    }
}

impl<S: Timed> Timed for ReadTimeoutCache<S> {
    fn read_timeout(&self, left: Duration) -> io::Result<()> {
        // Never past the deadline: set a little short of it, and kept while it still ends by it.
        if self.timeout.get().is_some_and(|t| t <= left && left - t <= left / 8) {
            return Ok(());
        }
        let t = (left - left / 16).max(Duration::from_millis(1)).min(left);
        self.timeout.set(None);
        self.s.read_timeout(t)?;
        self.timeout.set(Some(t));
        Ok(())
    }
    fn write_timeout(&self, t: Duration) -> io::Result<()> {
        self.s.write_timeout(t)
    }
}

impl<S: Read> Read for ReadTimeoutCache<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.s.read(buf)
    }
    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.s.read_vectored(bufs)
    }
}

impl<S: Write> Write for ReadTimeoutCache<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.s.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.s.flush()
    }
}

/// Every read and write (each partial one) ends by `at`, however slowly the peer trickles.
pub struct By<S> {
    pub s: S,
    pub at: Instant,
}

impl<S> By<S> {
    pub(crate) fn left(&self) -> io::Result<Duration> {
        match self.at.saturating_duration_since(Instant::now()) {
            d if d.is_zero() => Err(io::Error::new(io::ErrorKind::TimedOut, "deadline passed")),
            d => Ok(d),
        }
    }
}

fn timed_out(e: io::Error) -> io::Error {
    match e.kind() {
        io::ErrorKind::WouldBlock => io::Error::new(io::ErrorKind::TimedOut, "deadline passed"),
        _ => e,
    }
}

/// Runs `op` on `s` under a socket timeout of what is left until `at`, and again while that timeout (counted in
/// kernel ticks) fires before `at` (#963).
fn until<S, T>(s: &mut S, at: Instant, set: fn(&S, Duration) -> io::Result<()>, mut op: impl FnMut(&mut S) -> io::Result<T>) -> io::Result<T> {
    loop {
        set(s, By { s: (), at }.left()?)?;
        match op(s) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            r => return r,
        }
    }
}

impl<S: Timed> Read for By<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        until(&mut self.s, self.at, S::read_timeout, |s| s.read(buf))
    }
    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        until(&mut self.s, self.at, S::read_timeout, |s| s.read_vectored(bufs))
    }
}

impl<S: Timed + BufRead> BufRead for By<S> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        // fill_buf's borrow can't leave a retry loop, so wait until it has data (or fails) and take it again.
        until(&mut self.s, self.at, S::read_timeout, |s| s.fill_buf().map(drop))?;
        self.s.fill_buf()
    }
    fn consume(&mut self, n: usize) {
        self.s.consume(n);
    }
}

impl<S: Timed + Write> Write for By<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        until(&mut self.s, self.at, S::write_timeout, |s| s.write(buf))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.s.flush()
    }
}

/// `By` with a deadline that moves with what it carries: `grace` from when it was made, plus a second for each
/// `rate` bytes read or written through it. A transfer of any size that keeps that pace runs to its end; one that
/// stalls or trickles below it still ends (a template push, #824).
pub struct Paced<S> {
    pub s: S,
    start: Instant,
    grace: Duration,
    rate: u64,
    /// The bytes read and written so far.
    pub moved: u64,
}

impl<S> Paced<S> {
    pub fn new(s: S, grace: Duration, rate: u64) -> Self {
        Paced { s, start: Instant::now(), grace, rate: rate.max(1), moved: 0 }
    }

    /// Its deadline now.
    pub fn at(&self) -> Instant {
        let nanos = self.moved as u128 * 1_000_000_000 / self.rate as u128;
        self.start + self.grace + Duration::from_nanos(nanos.min(u64::MAX as u128) as u64)
    }
}

impl<S: Timed> Read for Paced<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let at = self.at();
        let n = until(&mut self.s, at, S::read_timeout, |s| s.read(buf))?;
        self.moved += n as u64;
        Ok(n)
    }
}

impl<S: Timed + Write> Write for Paced<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let at = self.at();
        let n = until(&mut self.s, at, S::write_timeout, |s| s.write(buf))?;
        self.moved += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.s.flush()
    }
}

/// Connects within `timeout`: a blocking connect waits while the listener's backlog is full.
pub fn connect_unix(path: &std::path::Path, timeout: Duration) -> io::Result<UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    let deadline = Instant::now() + timeout;
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    crate::socket::check(path)?;
    for (d, s) in sa.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    let fd = eintr(|| unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) })?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    // A non-blocking unix connect fails with EAGAIN while the backlog is full.
    while unsafe { libc::connect(fd.as_raw_fd(), &sa as *const _ as *const libc::sockaddr, len) } < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EAGAIN) || Instant::now() >= deadline {
            return Err(e);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let s = UnixStream::from(fd);
    s.set_nonblocking(false)?;
    Ok(s)
}

/// Connects to `path` and sends `line` (and `fds`), both by `at`.
pub fn send_unix(path: &std::path::Path, line: &[u8], fds: &[RawFd], at: Instant) -> io::Result<UnixStream> {
    let s = connect_unix(path, By { s: (), at }.left()?)?;
    send_with_fds(&s, line, fds, at)?;
    Ok(s)
}

/// The pid of the process that made the socket `s` is connected to (for a listener's, the one that listened).
pub fn peer_pid(s: &UnixStream) -> io::Result<u32> {
    Ok(peer_cred(s)?.pid as u32)
}

pub fn peer_cred(s: &UnixStream) -> io::Result<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred)
}

pub fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    let fd = eintr(|| unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

pub fn pidfd_signal(pidfd: &OwnedFd, sig: i32) -> io::Result<()> {
    eintr(|| unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), sig, std::ptr::null::<libc::siginfo_t>(), 0) }).map(drop)
}

pub fn pidfd_kill(pidfd: &OwnedFd) -> io::Result<()> {
    pidfd_signal(pidfd, libc::SIGKILL).or_else(|e| if e.raw_os_error() == Some(libc::ESRCH) { Ok(()) } else { Err(e) })
}

/// Whether `fd` has input (or hung up) within `timeout`.
pub fn readable(fd: &impl AsRawFd, timeout: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let end = Instant::now() + timeout;
    let left = || end.saturating_duration_since(Instant::now()).as_millis().min(i32::MAX as u128) as i32;
    Ok(eintr(|| unsafe { libc::poll(&mut pfd, 1, left()) })? > 0)
}

/// Whether the peer has hung up (or reset), without waiting; what it sent but was not read yet
/// does not count.
pub fn hung_up(fd: &impl AsRawFd) -> bool {
    let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLRDHUP, revents: 0 };
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    n > 0 && pfd.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0
}

/// Waits until the peer of `fd` hangs up (or resets); what it sends meanwhile is left unread.
pub fn wait_hung_up(fd: &impl AsRawFd) {
    let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLRDHUP, revents: 0 };
    loop {
        match eintr(|| unsafe { libc::poll(&mut pfd, 1, -1) }) {
            Ok(n) if n > 0 && pfd.revents != 0 => return,
            Ok(_) => {}
            // Out of memory, say: not a hang-up.
            Err(_) => std::thread::sleep(Duration::from_secs(1)),
        }
    }
}

/// This process's cgroup2 directory, resolved in its own cgroup and mount namespaces.
pub fn my_cgroup() -> Option<OwnedFd> {
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return None;
    }
    let mine = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let cg = mine.lines().find_map(|l| l.strip_prefix("0::"))?;
    let dir = cgroup_dir(cg)?;
    let fd = openat(libc::AT_FDCWD, &CString::new(dir.as_os_str().as_bytes()).ok()?, libc::O_PATH | libc::O_DIRECTORY).ok()?;
    // In a cgroup namespace without its own cgroup2 mount (`unshare -C`), the path names another
    // cgroup (the host's root, for "/"): none is sent rather than that one.
    in_cgroup(&fd, std::process::id()).ok()?.then_some(fd)
}

/// Whether `pid` (in this process's pid namespace) is listed in the `cgroup.procs` of cgroup directory `cg`.
fn in_cgroup(cg: &impl AsRawFd, pid: u32) -> io::Result<bool> {
    let mut procs = String::new();
    std::fs::File::from(openat(cg.as_raw_fd(), c"cgroup.procs", libc::O_RDONLY | libc::O_NOFOLLOW)?).read_to_string(&mut procs)?;
    Ok(procs.lines().any(|l| l.trim().parse() == Ok(pid)))
}

/// A cgroup2 path: None unless absolute, of plain components.
fn cgroup_dir(cg: &str) -> Option<std::path::PathBuf> {
    let rel = cg.strip_prefix('/')?.trim_end_matches('/');
    let plain = |c: &str| !c.is_empty() && c != "." && c != ".." && !c.contains(['\0', '\n']);
    if !rel.is_empty() && !rel.split('/').all(plain) {
        return None;
    }
    Some(Path::new("/sys/fs/cgroup").join(rel))
}

/// Moves this process (all its threads) into cgroup directory `cg`, a claimer's, only if the
/// claimer (`pid`, its `pidfd` opened when it connected) is in it: one it passed may name any.
pub fn join_cgroup(cg: &impl AsRawFd, pid: u32, pidfd: &OwnedFd) -> io::Result<()> {
    // Where it goes back to if the claimer leaves `cg` during the move: opened before it.
    let mine = std::fs::read_to_string("/proc/self/cgroup")?;
    let prev = mine
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .and_then(cgroup_dir)
        .and_then(|d| CString::new(d.as_os_str().as_bytes()).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "this process's own cgroup is not known, so it could not go back"))?;
    let prev = openat(libc::AT_FDCWD, &prev, libc::O_PATH | libc::O_DIRECTORY)?;
    join_checked(cg, &prev, pid, pidfd, || ())
}

/// `join_cgroup` from `prev`, this process's cgroup; `moved` runs between its move and the recheck.
fn join_checked(cg: &impl AsRawFd, prev: &impl AsRawFd, pid: u32, pidfd: &OwnedFd, moved: impl FnOnce()) -> io::Result<()> {
    // Alive after the read: the pid listed is still the claimer's, not a reuse.
    let claimers = || Ok::<_, io::Error>(in_cgroup(cg, pid)? && pidfd_signal(pidfd, 0).is_ok());
    if !claimers()? {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the cgroup passed is not the claimer's"));
    }
    let into = |d: &dyn AsRawFd| {
        let procs = openat(d.as_raw_fd(), c"cgroup.procs", libc::O_WRONLY | libc::O_NOFOLLOW)?;
        std::fs::File::from(procs).write_all(std::process::id().to_string().as_bytes())
    };
    into(cg)?;
    moved();
    // The claimer may have moved itself out between the check and the move: then it was not
    // its cgroup this joined, and it goes back.
    if claimers().unwrap_or(false) {
        return Ok(());
    }
    let back = into(prev).map_or_else(|e| format!("; and going back failed: {e}"), |()| ", so it went back".into());
    Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("the claimer left the cgroup passed during the move{back}")))
}

/// After a failed `accept`: one worth retrying at once (interrupted, the
/// peer gone) returns; anything else (out of fds) waits rather than spins.
pub fn accept_failed(what: &str, e: &io::Error) {
    if !matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted) {
        crate::log!("{what}: accept: {e}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1e5).round() / 100.0
}

/// Back-to-back phase timings that sum to the total.
pub struct Phases {
    start: Instant,
    last: Instant,
    marks: serde_json::Map<String, serde_json::Value>,
}

impl Phases {
    pub fn new() -> Phases {
        let now = Instant::now();
        Phases { start: now, last: now, marks: serde_json::Map::new() }
    }

    pub fn mark(&mut self, name: &str) -> Duration {
        let now = Instant::now();
        let d = now - self.last;
        self.last = now;
        self.marks.insert(name.into(), ms(d).into());
        d
    }

    pub fn total(&self) -> Duration {
        self.last - self.start
    }

    pub fn json(&self) -> serde_json::Value {
        let mut marks = self.marks.clone();
        marks.insert("total".into(), ms(self.total()).into());
        marks.into()
    }
}

/// A `Key: value kB` field from a /proc style file, in bytes.
/// A count of seconds, minutes, hours or days: `90s`, `30m`, `24h`, `7d`.
pub fn parse_age(s: &str) -> Option<std::time::Duration> {
    let unit = match s.chars().last()? {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return None,
    };
    s[..s.len() - 1].parse::<u64>().ok()?.checked_mul(unit).map(std::time::Duration::from_secs)
}

pub fn proc_kb(path: &str, key: &str) -> Option<u64> {
    let s = std::fs::read_to_string(path).ok()?;
    s.lines()
        .find(|l| l.starts_with(key) && l[key.len()..].starts_with(':'))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|kb| kb * 1024)
}

pub fn host_cpus() -> usize {
    static CPUS: OnceLock<usize> = OnceLock::new();
    *CPUS.get_or_init(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    open_dir(dir).and_then(|d| d.sync_all()).map_err(|e| io::Error::new(e.kind(), format!("fsync of directory {}: {e}", dir.display())))
}

/// Never blocks opening a FIFO put in its place.
fn open_dir(dir: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::File::options().read(true).custom_flags(libc::O_DIRECTORY).open(dir)
}

/// In one walk, by (dev, ino): directories synced, and links followed (with their directory,
/// which a relative target resolves from: a hard-linked symlink may be in several).
type Seen = std::collections::HashSet<((u64, u64), Option<(u64, u64)>)>;

/// Syncs every directory above `dir` up to `/`, and the one holding each symlink its path or a
/// link's target resolves through. Run when publishing in `dir`: an existing directory may have
/// been made by a process that died before syncing it.
fn sync_ancestors(dir: &Path) -> io::Result<()> {
    let mut dirs = Vec::new();
    sync_ancestors_with(dir, &mut Seen::new(), &mut |d| d.try_clone().map(|d| dirs.push(d)))?;
    sync_dirs_with(&dirs, &std::fs::File::sync_all)
}

/// As `sync_ancestors`, from a pinned directory: never by a path, which may since name another.
pub fn sync_ancestors_fd(dir: RawFd) -> io::Result<()> {
    sync_ancestors_fd_with(dir, &std::fs::File::sync_all)
}

fn sync_ancestors_fd_with(dir: RawFd, sync: &(impl Fn(&std::fs::File) -> io::Result<()> + Sync)) -> io::Result<()> {
    let mut dirs = Vec::new();
    walk_up(dir, &mut Seen::new(), &mut |d| d.try_clone().map(|d| dirs.push(d)))?;
    sync_dirs_with(&dirs, sync)
}

/// Entries must already exist, with no dependency between these syncs. Pin all
/// directories first, deduplicated by the walk; join every sync before returning.
fn sync_dirs_with(dirs: &[std::fs::File], sync: &(impl Fn(&std::fs::File) -> io::Result<()> + Sync)) -> io::Result<()> {
    let next = AtomicUsize::new(0);
    let work = || {
        let mut result = Ok(());
        while let Some(dir) = dirs.get(next.fetch_add(1, Ordering::Relaxed)) {
            result = result.and(sync(dir));
        }
        result
    };
    std::thread::scope(|s| {
        // I/O can overlap even on one CPU. Bound threads for deep paths; if a
        // spawn fails, this thread and any helpers still drain all the work.
        let helpers: Vec<_> = (1..dirs.len().min(8)).map_while(|_| std::thread::Builder::new().spawn_scoped(s, work).ok()).collect();
        let here = work();
        helpers.into_iter().fold(here, |result, h| result.and(h.join().unwrap_or_else(|_| Err(io::Error::other("directory fsync thread panicked")))))
    })
}

fn sync_ancestors_with(dir: &Path, seen: &mut Seen, sync: &mut impl FnMut(&std::fs::File) -> io::Result<()>) -> io::Result<()> {
    let named = |e: io::Error| io::Error::new(e.kind(), format!("fsync of the directories above {}: {e}", dir.display()));
    let dir = std::path::absolute(dir).map_err(named)?;
    sync_links(&dir, seen, sync).map_err(named)?;
    walk_up(open_dir(&dir).map_err(named)?.as_raw_fd(), seen, sync).map_err(named)
}

/// Every directory prefix and its physical ancestors, then the links in each link's target.
fn sync_links(path: &Path, seen: &mut Seen, sync: &mut impl FnMut(&std::fs::File) -> io::Result<()>) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    for prefix in path.ancestors().skip(1) {
        let dir = open_dir(prefix)?;
        if seen.insert((dir_id(dir.as_raw_fd())?, None)) {
            sync(&dir)?;
            walk_up(dir.as_raw_fd(), seen, sync)?;
        }
    }
    for (link, m) in path.ancestors().filter_map(|p| Some((p, std::fs::symlink_metadata(p).ok().filter(|m| m.is_symlink())?))) {
        let at = link.parent().unwrap_or(Path::new("/"));
        let holder = open_dir(at)?;
        let holder_id = dir_id(holder.as_raw_fd())?;
        // Each link once, which ends a loop of them.
        if !seen.insert(((m.dev(), m.ino()), Some(holder_id))) {
            continue;
        }
        if seen.insert((holder_id, None)) {
            sync(&holder)?;
            walk_up(holder.as_raw_fd(), seen, sync)?;
        }
        sync_links(&at.join(std::fs::read_link(link)?), seen, sync)?;
    }
    Ok(())
}

/// Syncs the directories above `dir` by "..", up to the root (its own ".."), stopping at one in `seen`.
fn walk_up(dir: RawFd, seen: &mut Seen, sync: &mut impl FnMut(&std::fs::File) -> io::Result<()>) -> io::Result<()> {
    let (mut cur, mut id) = (None::<std::fs::File>, dir_id(dir)?);
    loop {
        let fd = cur.as_ref().map_or(dir, |f| f.as_raw_fd());
        let up = unsafe { libc::openat(fd, c"..".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        check(up)?;
        let up = unsafe { std::fs::File::from_raw_fd(up) };
        let up_id = dir_id(up.as_raw_fd())?;
        if up_id == id || !seen.insert((up_id, None)) {
            return Ok(());
        }
        sync(&up)?;
        (cur, id) = (Some(up), up_id);
    }
}

fn dir_id(fd: RawFd) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    // Borrowed, never closed here.
    let f = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    f.metadata().map(|m| (m.dev(), m.ino()))
}

/// Removes `path` if it is there, then fsyncs its directory.
pub fn unlink_durably(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
        _ => sync_dir(path.parent().unwrap_or(Path::new("."))),
    }
}

/// The soft RLIMIT_NOFILE this process had before `raise_nofile`, plus one (0: never raised).
static NOFILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Raises the soft open-file limit to the hard one (a VM process's forwards hold two descriptors a
/// connection). Children spawned through `unblock_signals_in` or `spawn_self_child` get the limit this process had back:
/// some programs close every descriptor up to it, or `select` on them.
pub fn raise_nofile() {
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 || limit.rlim_cur >= limit.rlim_max {
            return;
        }
        let was = limit.rlim_cur;
        limit.rlim_cur = limit.rlim_max;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
            crate::log!("raising the open file limit: {}", io::Error::last_os_error());
            return;
        }
        NOFILE.store(was.saturating_add(1), std::sync::atomic::Ordering::SeqCst);
    }
}

/// In a child before exec: the soft open-file limit back to what `raise_nofile` found.
fn restore_nofile() -> io::Result<()> {
    let was = NOFILE.load(std::sync::atomic::Ordering::SeqCst);
    if was == 0 {
        return Ok(());
    }
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        check(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit))?;
        limit.rlim_cur = (was - 1).min(limit.rlim_max);
        check(libc::setrlimit(libc::RLIMIT_NOFILE, &limit))
    }
}

/// Clears the signal mask of `cmd`'s child, which exec keeps: a spawner that blocks signals to
/// wait for them itself (`block_signals`) would otherwise pass them on blocked. Its soft open-file
/// limit is the one this process started with too (`raise_nofile`); terminal stop signals
/// ignored by a VM process get their default dispositions back.
pub fn unblock_signals_in(cmd: &mut std::process::Command) -> &mut std::process::Command {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            let mut none: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut none);
            check(libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut()))?;
            default_stop_signals()?;
            restore_nofile()
        })
    }
}

/// In a child before exec: SIGTTOU and SIGTTIN, which a VM process ignores (and exec would
/// keep ignored), back to their defaults.
fn default_stop_signals() -> io::Result<()> {
    for sig in [libc::SIGTTOU, libc::SIGTTIN] {
        if unsafe { libc::signal(sig, libc::SIG_DFL) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Runs `cmd` with its output captured, its signals unblocked, polling `stop`: once that fails,
/// the child is killed and reaped and its error returned (also when the child exited failing
/// meanwhile, as a Ctrl-C to the process group does).
pub fn run_until(cmd: &mut std::process::Command, stop: impl Fn() -> Result<()>) -> Result<std::process::Output> {
    use std::process::Stdio;
    let mut child = unblock_signals_in(cmd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let drain = |r: Option<Box<dyn io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            r.map(|mut r| r.read_to_end(&mut buf));
            buf
        })
    };
    let (out, err) = (drain(child.stdout.take().map(|r| Box::new(r) as _)), drain(child.stderr.take().map(|r| Box::new(r) as _)));
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if let Err(e) = stop() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    if !status.success() {
        stop()?;
    }
    Ok(std::process::Output { status, stdout: out.join().unwrap_or_default(), stderr: err.join().unwrap_or_default() })
}

/// `n` random bytes, hex-encoded.
pub fn random_hex(n: usize) -> io::Result<String> {
    let mut random = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        filled += eintr(|| unsafe { libc::getrandom(random[filled..].as_mut_ptr().cast(), n - filled, 0) })? as usize;
    }
    Ok(random.iter().map(|b| format!("{b:02x}")).collect())
}

/// Whether `s` is a temporary-name nonce (8 random bytes, hex-encoded).
pub fn is_nonce(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// False if `path` exists.
pub fn rename_noreplace(tmp: &Path, path: &Path) -> io::Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let (src, dest) = (std::ffi::CString::new(tmp.as_os_str().as_bytes())?, std::ffi::CString::new(path.as_os_str().as_bytes())?);
    match eintr(|| unsafe { libc::renameat2(libc::AT_FDCWD, src.as_ptr(), libc::AT_FDCWD, dest.as_ptr(), libc::RENAME_NOREPLACE) }) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        res => res.map(|_| true),
    }
}

/// Characters of the boot id in `write_tag`.
pub const BOOT_TAG: usize = 8;

/// What names this process in `write_file`'s temporary files: `PID-START-BOOT-NS` (its start time,
/// the first `BOOT_TAG` characters of the boot id and its PID namespace, `host::pid_ns`), so a sweep
/// tells a dead writer's from a live one that got its pid, in this boot or after a reboot
/// (`host::write_debris_of`), and writers in other PID namespaces with the same pid and start time
/// (in a directory they share, a templates directory say) never write to one file (#1084). Without a
/// PID namespace to name, `PID-START-BOOT`; a bare PID if the start time or boot id cannot be read.
pub fn write_tag() -> String {
    static TAG: std::sync::Mutex<Option<(u32, String)>> = std::sync::Mutex::new(None);
    let pid = std::process::id();
    let mut t = TAG.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, tag)) = t.as_ref().filter(|(p, _)| *p == pid) {
        return tag.clone();
    }
    let boot = crate::host::boot_id().get(..BOOT_TAG).filter(|b| !b.contains('-'));
    let tag = match (crate::host::starttime(pid), boot, crate::host::pid_ns()) {
        (Some(start), Some(boot), Some(ns)) => format!("{pid}-{start}-{boot}-{ns}"),
        (Some(start), Some(boot), None) => format!("{pid}-{start}-{boot}"),
        _ => return pid.to_string(),
    };
    *t = Some((pid, tag.clone()));
    tag
}

/// Durably: the file is fsynced before the rename, its directory after.
pub fn write_file(dir: &Path, name: &str, data: &[u8], durable: bool) -> io::Result<()> {
    write_file_mode(dir, name, data, durable, 0o644)
}

/// Like `write_file`, with a creation mode; 0600 also secures a reused temporary file.
pub fn write_file_mode(dir: &Path, name: &str, data: &[u8], durable: bool, mode: u32) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.{}.tmp", write_tag()));
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::File::options().write(true).create(true).truncate(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
    let res = (|| {
        if mode == 0o600 {
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        f.write_all(data)?;
        if durable {
            f.sync_all()?;
        }
        std::fs::rename(&tmp, dir.join(name))
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res?;
    if durable {
        sync_dir(dir)
    } else {
        Ok(())
    }
}

/// Creates `dir` and its parents with `mode`, then `sync_ancestors`, existing or not.
pub fn create_dir_durably(dir: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let named = |e: io::Error| io::Error::new(e.kind(), format!("creating {}: {e}", dir.display()));
    std::fs::DirBuilder::new().recursive(true).mode(mode).create(dir).map_err(named)?;
    sync_ancestors(dir)
}

/// Sent by `at`.
pub fn send_with_fds(s: &UnixStream, line: &[u8], fds: &[RawFd], at: Instant) -> io::Result<()> {
    let mut iov = libc::iovec { iov_base: line.as_ptr() as *mut libc::c_void, iov_len: line.len() };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    let mut cbuf = vec![0u64; space.div_ceil(std::mem::size_of::<u64>())];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as _;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c) as *mut RawFd, fds.len());
        }
    }
    s.set_write_timeout(Some(By { s: (), at }.left()?))?;
    let n = eintr(|| unsafe { libc::sendmsg(s.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) }).map_err(timed_out)? as usize;
    By { s, at }.write_all(&line[n..])
}

/// The peer must send nothing after the line until it has an answer. `ready` is
/// called before each read: an error ends the wait.
pub fn recv_with_fds(s: &UnixStream, max: usize, mut ready: impl FnMut() -> io::Result<()>) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut line = Vec::new();
    let mut fds = Vec::new();
    let mut buf = [0u8; 4096];
    while !line.ends_with(b"\n") {
        if line.len() > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request line too long"));
        }
        ready()?;
        let (n, received) = recvmsg_fds(s.as_raw_fd(), &mut buf)?;
        fds.extend(received);
        if n == 0 {
            break;
        }
        line.extend_from_slice(&buf[..n]);
    }
    Ok((line, fds))
}

/// Receives one message and owns all SCM_RIGHTS descriptors, closing them on error.
pub fn recvmsg_fds(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut fds = Vec::new();
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let mut cbuf = [0u64; 32];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
    let n = eintr(|| unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) })?;
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let n = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
                let data = libc::CMSG_DATA(c) as *const RawFd;
                for i in 0..n {
                    fds.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ancillary fds truncated"));
    }
    Ok((n as usize, fds))
}

/// Also in threads started afterwards, so only `wait_signal` sees them.
pub fn block_signals(sigs: &[i32]) -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &s in sigs {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    }
}

/// Pending for the process (or this thread), blocked and not yet taken.
pub fn signal_pending(sig: i32) -> bool {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigpending(&mut set) == 0 && libc::sigismember(&set, sig) == 1
    }
}

/// Readable while one of `set` (blocked) is pending; `take_signal` takes it.
pub fn signal_fd(set: &libc::sigset_t) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::signalfd(-1, set, libc::SFD_CLOEXEC) };
    check(fd)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// One of `set` if pending, without waiting.
pub fn take_signal(set: &libc::sigset_t) -> Option<i32> {
    let now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let sig = unsafe { libc::sigtimedwait(set, std::ptr::null_mut(), &now) };
    (sig > 0).then_some(sig)
}

pub fn wait_signal(set: &libc::sigset_t) -> i32 {
    let mut sig = 0;
    while unsafe { libc::sigwait(set, &mut sig) } != 0 {}
    sig
}

/// A VM process in the background, with `fd3` as its fd 3: it outlives the
/// caller, so it is in a session of its own and, where flexvm's cgroup tree
/// is available, a cgroup of its own (`flexvm/vm-PID-START-NS`, `scope`), out of
/// reach of whatever stops the caller's: a systemd unit's restart or stop
/// (`KillMode=control-group`), logind's `KillUserProcesses`.
pub fn spawn_self<S: AsRef<std::ffi::OsStr>>(args: &[S], log: &std::fs::File, fd3: RawFd, env: &[(&str, &str)]) -> io::Result<()> {
    start_reaper()?;
    reap_later(spawn_self_child(args, log, fd3, None, None, env)?, None);
    Ok(())
}

/// Like `spawn_self`, but the caller owns termination and reaping (`reap_later`).
/// `fd4` and `fd5`, if any, are the child's fd 4 and 5 as well.
pub fn spawn_self_child<S: AsRef<std::ffi::OsStr>>(
    args: &[S],
    log: &std::fs::File,
    fd3: RawFd,
    fd4: Option<RawFd>,
    fd5: Option<RawFd>,
    env: &[(&str, &str)],
) -> io::Result<std::process::Child> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    let cgroups = crate::vmproc::cgroup_root().map(|r| r.join("vm-").as_os_str().as_bytes().to_vec());
    // Read before the fork: the child is in this PID namespace too, and reads nothing it would allocate for.
    let ns = crate::host::pid_ns();
    let mut cmd = std::process::Command::new("/proc/self/exe");
    cmd.args(args).envs(env.iter().copied()).stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log.try_clone()?);
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            if let Some(prefix) = &cgroups {
                if !own_start().is_some_and(|start| scope(prefix, libc::getpid() as u32, start, ns)) {
                    let warn = b"flexvm: WARNING: no cgroup of its own: stopping the caller's cgroup stops this vm\n";
                    libc::write(2, warn.as_ptr().cast(), warn.len());
                }
            }
            // Copied out of the way first: they may be fd 3 now, and fd3 fd 4 or 5.
            let aside = |fd: Option<RawFd>| -> io::Result<Option<RawFd>> {
                match fd {
                    Some(fd) => {
                        let k = libc::fcntl(fd, libc::F_DUPFD, 10);
                        check(k)?;
                        Ok(Some(k))
                    }
                    None => Ok(None),
                }
            };
            // A VM process's raised limit is its own: a flexvm child raises its own if it needs to.
            restore_nofile()?;
            default_stop_signals()?;
            let (fd4, fd5) = (aside(fd4)?, aside(fd5)?);
            // dup2 onto itself would leave it close-on-exec.
            let moved = if fd3 == 3 { libc::fcntl(3, libc::F_SETFD, 0) } else { libc::dup2(fd3, 3) };
            check(moved)?;
            for (k, to) in [(fd4, 4), (fd5, 5)] {
                if let Some(k) = k {
                    check(libc::dup2(k, to))?;
                    libc::close(k);
                }
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// A child `reap_later` waits for, and what it holds meanwhile.
struct Reaping {
    child: std::process::Child,
    /// None (pidfd_open failed): tried every `REAP_POLL` instead.
    pidfd: Option<OwnedFd>,
    /// Dropped once `.0` reads ready (written to, or closed by every holder, its process ended
    /// with it) or the child is reaped, whichever is first.
    hold: Option<(OwnedFd, Box<dyn Send>)>,
}

#[cfg(test)]
thread_local! {
    /// `start_reaper` fails on this thread.
    pub static NO_REAPER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

static REAPING: std::sync::Mutex<Vec<Reaping>> = std::sync::Mutex::new(Vec::new());
const REAP_POLL: Duration = Duration::from_secs(1);

/// The shared reaper's wake-up fd, started if it is not yet: called before a child is
/// spawned for `reap_later`, so one that cannot be reaped is never started.
pub fn start_reaper() -> io::Result<RawFd> {
    #[cfg(test)]
    if NO_REAPER.with(|n| n.get()) {
        return Err(io::Error::other("no reaper (test)"));
    }

    static WAKE: std::sync::Mutex<Option<OwnedFd>> = std::sync::Mutex::new(None);
    let mut wake = WAKE.lock().unwrap();
    if let Some(fd) = &*wake {
        return Ok(fd.as_raw_fd());
    }
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    check(fd)?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let raw = fd.as_raw_fd();
    // Never closed: the thread polls it for good.
    std::thread::Builder::new().name("reaper".into()).spawn(move || reaper(raw))?;
    *wake = Some(fd);
    Ok(raw)
}

/// Reaps `child` once it exits, from one thread shared by all the process's children rather
/// than one each; drops `hold`'s value then, or once its fd reads ready if sooner. Its
/// spawner called `start_reaper` first.
pub fn reap_later(child: std::process::Child, hold: Option<(OwnedFd, Box<dyn Send>)>) {
    let pidfd = pidfd_open(child.id()).ok();
    REAPING.lock().unwrap().push(Reaping { child, pidfd, hold });
    match start_reaper() {
        Ok(wake) => {
            let one = 1u64;
            unsafe { libc::write(wake, (&one as *const u64).cast(), 8) };
        }
        // Not reached after a `start_reaper` that succeeded.
        Err(e) => crate::log!("reaping children: {e}"),
    }
}

/// The fds to poll: the wake-up's, then each entry's real ones only, with (entry, whether
/// it is its hold) for each; and whether some entry has no pidfd (it is tried on a timer).
fn reap_fds(wake: RawFd, r: &[Reaping]) -> (Vec<libc::pollfd>, Vec<(usize, bool)>, bool) {
    let pfd = |fd: RawFd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let (mut fds, mut whose) = (vec![pfd(wake)], vec![]);
    for (i, e) in r.iter().enumerate() {
        for (fd, hold) in [(e.pidfd.as_ref(), false), (e.hold.as_ref().map(|h| &h.0), true)] {
            if let Some(fd) = fd {
                fds.push(pfd(fd.as_raw_fd()));
                whose.push((i, hold));
            }
        }
    }
    (fds, whose, r.iter().any(|e| e.pidfd.is_none()))
}

fn reaper(wake: RawFd) {
    loop {
        // Entries are only appended meanwhile, and removed only here: `whose` stays right.
        let (mut fds, whose, timer) = reap_fds(wake, &REAPING.lock().unwrap());
        let timeout = if timer { REAP_POLL.as_millis() as i32 } else { -1 };
        let polled = eintr(|| unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) });
        if let Err(e) = &polled {
            crate::log!("reaping children: poll: {e}; trying each");
            std::thread::sleep(REAP_POLL);
        }
        if fds[0].revents != 0 {
            let mut n = 0u64;
            unsafe { libc::read(wake, (&mut n as *mut u64).cast(), 8) };
        }
        let mut r = REAPING.lock().unwrap();
        let mut exited = vec![polled.is_err(); r.len()];
        for (f, &(i, hold)) in fds[1..].iter().zip(&whose) {
            match (f.revents != 0, hold) {
                (false, _) => {}
                (true, true) => r[i].hold = None,
                (true, false) => exited[i] = true,
            }
        }
        let mut i = 0;
        r.retain_mut(|e| {
            let tried = exited.get(i).copied().unwrap_or(false) || e.pidfd.is_none();
            i += 1;
            // Kept unless waited for (or never to be: an error).
            !tried || matches!(e.child.try_wait(), Ok(None))
        });
    }
}

/// `PREFIX` `PID` `-` `START` (`-` `NS` with a PID namespace) `SUFFIX` NUL in `buf`, without
/// allocating (after fork); false if it does not fit.
fn scope_path(buf: &mut [u8], prefix: &[u8], pid: u32, start: u64, ns: Option<u64>, suffix: &[u8]) -> bool {
    fn digits(mut n: u64, out: &mut [u8; 20]) -> &[u8] {
        let mut i = out.len();
        loop {
            i -= 1;
            out[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                return &out[i..];
            }
        }
    }
    let (mut p, mut s, mut n) = ([0u8; 20], [0u8; 20], [0u8; 20]);
    let (dash, ns): (&[u8], &[u8]) = match ns {
        Some(ns) => (b"-", digits(ns, &mut n)),
        None => (b"", b""),
    };
    let parts: [&[u8]; 7] = [prefix, digits(pid as u64, &mut p), b"-", digits(start, &mut s), dash, ns, suffix];
    let len: usize = parts.iter().map(|p| p.len()).sum();
    if len + 1 > buf.len() || prefix.contains(&0) {
        return false;
    }
    let mut at = 0;
    for p in parts {
        buf[at..at + p.len()].copy_from_slice(p);
        at += p.len();
    }
    buf[at] = 0;
    true
}

/// A process's start time from its `/proc/PID/stat` text (field 22).
fn stat_start(stat: &[u8]) -> Option<u64> {
    let close = stat.iter().rposition(|&b| b == b')')?;
    let field = stat[close + 1..].split(|&b| b == b' ').filter(|f| !f.is_empty()).nth(19)?;
    let mut n: u64 = 0;
    for &b in field {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(n)
}

/// This process's start time, without allocating.
fn own_start() -> Option<u64> {
    let mut buf = [0u8; 1024];
    unsafe {
        let fd = libc::open(c"/proc/self/stat".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return None;
        }
        let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
        libc::close(fd);
        stat_start(&buf[..usize::try_from(n).ok()?])
    }
}

/// Moves this process into a new cgroup `PREFIX` `pid-start-ns`, named after
/// this instance and its PID namespace `ns` (`host::pid_ns`, read before the fork), so that
/// a host in another PID namespace sharing the cgroup tree never judges it by its pid
/// (`host::sweep_scope`, #1084): never one a dead process left (one that exists is
/// refused, not joined). Only system calls: it runs between fork and exec.
/// Garbage collection removes empty ones, so one removed between its
/// making and its joining is made again.
fn scope(prefix: &[u8], pid: u32, start: u64, ns: Option<u64>) -> bool {
    let mut path = [0u8; 512];
    let errno = || unsafe { *libc::__errno_location() };
    for _ in 0..3 {
        unsafe {
            if !scope_path(&mut path, prefix, pid, start, ns, b"") || libc::mkdir(path.as_ptr().cast(), 0o755) != 0 {
                return false;
            }
            if !scope_path(&mut path, prefix, pid, start, ns, b"/cgroup.procs") {
                return false;
            }
            let fd = libc::open(path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                if errno() == libc::ENOENT {
                    continue;
                }
                return false;
            }
            // "0": the writing process.
            let ok = libc::write(fd, b"0".as_ptr().cast(), 1) == 1;
            let e = errno();
            libc::close(fd);
            if ok {
                return true;
            }
            if e != libc::ENOENT && e != libc::ENODEV {
                return false;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_paced_deadline_moves_with_the_bytes() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut w = Paced::new(&a, Duration::from_millis(300), 1000);
        let first = w.at();
        w.write_all(&[1; 500]).unwrap();
        assert_eq!(w.at() - first, Duration::from_millis(500));
        let mut r = Paced::new(&b, Duration::from_millis(300), 1000);
        let started = Instant::now();
        r.read_exact(&mut [0; 500]).unwrap();
        // Nothing more comes: it times out at its deadline, the grace and the pace of what came.
        let e = r.read(&mut [0; 1]).unwrap_err();
        assert!(e.kind() == io::ErrorKind::TimedOut && started.elapsed() >= Duration::from_millis(790), "{e} after {:?}", started.elapsed());
    }
    use crate::test_util::{JoinWithin, WAIT};

    #[test]
    fn a_claimer_cgroup_is_an_absolute_path_of_plain_components() {
        let dir = |cg| cgroup_dir(cg).map(|p| p.display().to_string());
        assert_eq!(dir("/").as_deref(), Some("/sys/fs/cgroup/"));
        assert_eq!(dir("/system.slice/ci.service").as_deref(), Some("/sys/fs/cgroup/system.slice/ci.service"));
        for bad in ["", "system.slice", "/a/../b", "/..", "/a//b", "/./a", "/a\nb"] {
            assert_eq!(dir(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_cgroup_fd_survives_passing_and_path_replacement() {
        let root = crate::test_util::TempDir::new("claim-cgroup");
        let dir = root.join("cgroup");
        std::fs::create_dir(&dir).unwrap();
        let me = std::process::id();
        let pidfd = pidfd_open(me).unwrap();
        // Its own cgroup, gone back to if the claimer leaves (a fake: never this process's real one).
        std::fs::create_dir(root.join("prev")).unwrap();
        let prev = openat(libc::AT_FDCWD, &CString::new(root.join("prev").as_os_str().as_bytes()).unwrap(), libc::O_PATH | libc::O_DIRECTORY).unwrap();
        let join = |cg: &OwnedFd| join_checked(cg, &prev, me, &pidfd, || ());
        // Listed, as the claimer is in its own cgroup.
        std::fs::write(dir.join("cgroup.procs"), format!("{me}\n1\n")).unwrap();
        let cg = openat(libc::AT_FDCWD, &CString::new(dir.as_os_str().as_bytes()).unwrap(), libc::O_PATH | libc::O_DIRECTORY).unwrap();
        assert_ne!(unsafe { libc::fcntl(cg.as_raw_fd(), libc::F_GETFL) } & libc::O_PATH, 0);
        let (a, b) = UnixStream::pair().unwrap();
        send_with_fds(&a, b"claim\n", &[1, 2, cg.as_raw_fd()], Instant::now() + Duration::from_secs(5)).unwrap();
        let (_, fds) = recv_with_fds(&b, 1024, || Ok(())).unwrap();
        assert_eq!(fds.len(), 3);
        drop(cg);
        std::fs::rename(&dir, root.join("original")).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("cgroup.procs"), format!("{me}\nunrelated")).unwrap();
        join(&fds[2]).unwrap();
        assert!(std::fs::read_to_string(root.join("original/cgroup.procs")).unwrap().starts_with(&me.to_string()));
        assert_eq!(std::fs::read_to_string(dir.join("cgroup.procs")).unwrap(), format!("{me}\nunrelated"));
        // A cgroup the claimer is not in (one it opened elsewhere, or by a path not its own) is refused.
        std::fs::write(root.join("original/cgroup.procs"), b"1\n").unwrap();
        assert!(join(&fds[2]).is_err());
        assert_eq!(std::fs::read(root.join("original/cgroup.procs")).unwrap(), b"1\n");
        // A directory without cgroup.procs is not populated, nor is a symlink followed.
        std::fs::remove_file(root.join("original/cgroup.procs")).unwrap();
        assert!(join(&fds[2]).is_err());
        std::os::unix::fs::symlink(dir.join("cgroup.procs"), root.join("original/cgroup.procs")).unwrap();
        assert!(join(&fds[2]).is_err());
        assert_eq!(std::fs::read_to_string(dir.join("cgroup.procs")).unwrap(), format!("{me}\nunrelated"));
    }

    #[test]
    fn a_claimer_that_leaves_its_cgroup_during_the_move_sends_this_process_back() {
        let root = crate::test_util::TempDir::new("claim-cgroup-recheck");
        let (a, prev) = (root.join("a"), root.join("prev"));
        let me = std::process::id();
        let pidfd = pidfd_open(me).unwrap();
        let open = |d: &Path| {
            std::fs::create_dir(d).unwrap();
            openat(libc::AT_FDCWD, &CString::new(d.as_os_str().as_bytes()).unwrap(), libc::O_PATH | libc::O_DIRECTORY).unwrap()
        };
        let (cg, back) = (open(&a), open(&prev));
        let listed = format!("{me}\n");
        std::fs::write(prev.join("cgroup.procs"), b"").unwrap();
        // Still there after the move: joined, and nothing written back.
        std::fs::write(a.join("cgroup.procs"), &listed).unwrap();
        join_checked(&cg, &back, me, &pidfd, || ()).unwrap();
        assert_eq!(std::fs::read(prev.join("cgroup.procs")).unwrap(), b"");
        // Gone from it once this process moved in: back to where it was.
        let e = join_checked(&cg, &back, me, &pidfd, || std::fs::write(a.join("cgroup.procs"), b"1\n").unwrap()).unwrap_err();
        assert!(e.to_string().contains("so it went back"), "{e}");
        assert_eq!(std::fs::read_to_string(prev.join("cgroup.procs")).unwrap(), me.to_string());
    }

    #[test]
    fn a_hang_up_ends_the_wait_and_input_does_not() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            wait_hung_up(&a);
            tx.send(()).unwrap();
        });
        std::io::Write::write_all(&mut &b, b"{\"exit\":0}\n").unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "input is not a hang-up");
        drop(b);
        rx.recv_timeout(Duration::from_secs(5)).expect("the hang-up ends the wait");
    }

    #[test]
    fn fault_results_evaluate_only_the_selected_branch() {
        let calls = std::cell::Cell::new(0);
        for armed in [true, false] {
            let result: Result<()> = crate::fault_result!(armed => Err("injected".into()); {
                calls.set(calls.get() + 1);
                Ok(())
            });
            assert_eq!(result.is_err(), armed);
        }
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn syscall_checks_capture_errno_before_the_name_and_do_not_retry() {
        let calls = std::cell::Cell::new(0);
        let operation = || -> Result<()> {
            crate::syscall_check!(
                {
                    calls.set(calls.get() + 1);
                    unsafe { *libc::__errno_location() = libc::EINTR };
                    true
                },
                "{}",
                {
                    unsafe { *libc::__errno_location() = libc::EINVAL };
                    "interrupted"
                }
            );
            Ok(())
        };
        assert_eq!(operation().unwrap_err().to_string(), format!("interrupted: {}", io::Error::from_raw_os_error(libc::EINTR)));
        assert_eq!(calls.get(), 1);
    }

    fn within(t: Duration, cond: impl Fn() -> bool) -> bool {
        let end = Instant::now() + t;
        while !cond() {
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    #[test]
    fn the_reaper_polls_only_real_fds() {
        struct Children(Vec<Reaping>);
        impl Drop for Children {
            fn drop(&mut self) {
                for entry in self.0.drain(..) {
                    drop(crate::test_util::ChildGuard(entry.child));
                }
            }
        }
        let entry = |pidfd: bool, hold: bool| {
            let fd = || OwnedFd::from(UnixStream::pair().unwrap().0);
            let pidfd = pidfd.then(fd);
            let hold = hold.then(|| (fd(), Box::new(()) as Box<dyn Send>));
            let child = std::process::Command::new("true").spawn().unwrap();
            Reaping { child, pidfd, hold }
        };
        // Those without fds add nothing to the poll (no -1 placeholders), then one with both.
        let mut r = Children(Vec::new());
        for _ in 0..3 {
            r.0.push(entry(false, false));
        }
        r.0.push(entry(true, true));
        let (fds, whose, timer) = reap_fds(-5, &r.0);
        assert_eq!(fds.len(), 3);
        assert!(fds[1..].iter().all(|f| f.fd >= 0));
        assert_eq!(whose, [(3, false), (3, true)]);
        assert!(timer, "one without a pidfd is tried on a timer");
    }

    #[test]
    fn reaper_failure_is_injected_even_after_the_shared_reaper_started() {
        start_reaper().unwrap();
        NO_REAPER.with(|disabled| disabled.set(true));
        let result = start_reaper();
        NO_REAPER.with(|disabled| disabled.set(false));
        assert_eq!(result.unwrap_err().to_string(), "no reaper (test)");
    }

    #[test]
    fn a_reaped_child_holds_its_slot_only_until_it_says_so_and_is_reaped_once_it_exits() {
        static HELD: AtomicUsize = AtomicUsize::new(0);
        let gone = |pid: u32| !Path::new(&format!("/proc/{pid}")).exists();
        let (done, mut told) = UnixStream::pair().unwrap();
        let slot = Slot::take(&HELD, 1).unwrap();
        let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        reap_later(child, Some((done.into(), Box::new(slot))));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::sleep(Duration::from_millis(100));
            assert!(Slot::take(&HELD, 1).is_none(), "held while the child has not said");
            // Signal explicitly: a concurrent fork may still hold another copy of `told`.
            told.write_all(b"done").unwrap();
            assert!(within(Duration::from_secs(5), || HELD.load(Ordering::SeqCst) == 0), "let go once told");
            assert!(!gone(pid), "the child runs on");
        }));
        // Keep the production reaper as the sole waiter, including after a panic.
        // Holding its mutex prevents the pid from being reused before the kill.
        {
            let mut reaping = REAPING.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(child) = reaping.iter_mut().find(|e| e.child.id() == pid) {
                let _ = child.child.kill();
            }
        }
        drop(told);
        let reaped = within(Duration::from_secs(5), || gone(pid));
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
        assert!(reaped, "reaped once it exited");
        // One that ends without saying lets go too, whoever else holds its fd.
        let (done, told) = UnixStream::pair().unwrap();
        let slot = Slot::take(&HELD, 1).unwrap();
        let child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        reap_later(child, Some((done.into(), Box::new(slot))));
        assert!(within(Duration::from_secs(5), || HELD.load(Ordering::SeqCst) == 0 && gone(pid)));
        drop(told);
    }

    #[test]
    fn only_a_trusted_file_is_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_util::TempDir::new("trusted");
        let (file, link) = (dir.join("hosts.json"), dir.join("link.json"));
        std::fs::write(&file, b"{}").unwrap();
        let mode = |m| std::fs::set_permissions(&file, std::fs::Permissions::from_mode(m)).unwrap();
        mode(0o644);
        assert!(trusted_file(&file).is_some());
        mode(0o664);
        assert!(trusted_file(&file).is_none(), "group-writable");
        mode(0o646);
        assert!(trusted_file(&file).is_none(), "world-writable");
        mode(0o600);
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(trusted_file(&link).is_none(), "through a symlink");
        assert!(trusted_file(&dir).is_none(), "not a regular file");
    }
    use std::os::unix::fs::PermissionsExt;

    fn workers(dns: &Resolver) -> usize {
        dns.lookups.lock().unwrap().workers
    }

    /// A lookup that blocks until released.
    fn held() -> (std::sync::mpsc::Sender<Addrs>, impl FnOnce(String) -> io::Result<Addrs> + Send + 'static) {
        let (release, wait) = std::sync::mpsc::channel::<Addrs>();
        (release, move |_| Ok(wait.recv().unwrap_or_default()))
    }

    #[test]
    fn a_hung_name_holds_one_worker_however_often_it_is_asked_for() {
        static DNS: Resolver = Resolver::new();
        let (release, lookup) = held();
        let start = Instant::now();
        let err = resolve_with("hung.example:80", start + Duration::from_millis(30), &DNS, false, lookup).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("hung.example:80"), "{err}");
        for fresh in [false, true].into_iter().cycle().take(8) {
            let err = resolve_with("hung.example:80", Instant::now() + Duration::from_millis(10), &DNS, fresh, |_| panic!("joins the lookup under way"));
            assert_eq!(err.unwrap_err().kind(), io::ErrorKind::TimedOut);
        }
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(workers(&DNS), 1, "timing out must not release a stuck worker's slot");
        // It ends after every caller gave up: the next one gets its answer, with no new lookup.
        let addr: std::net::SocketAddr = "10.0.0.1:80".parse().unwrap();
        release.send(vec![addr]).unwrap();
        let got = resolve_with("hung.example:80", Instant::now() + Duration::from_secs(5), &DNS, false, |_| panic!("answered recently"));
        assert_eq!(got.unwrap(), vec![addr]);
        assert_eq!(workers(&DNS), 0);
    }

    #[test]
    fn a_stopped_wait_for_a_hung_name_ends_promptly() {
        static DNS: Resolver = Resolver::new();
        let (release, lookup) = held();
        let (start, checks) = (Instant::now(), std::sync::atomic::AtomicU32::new(0));
        let stop = || match checks.fetch_add(1, std::sync::atomic::Ordering::Relaxed) {
            0..3 => Ok(()),
            _ => Err(io::Error::other("stopped")),
        };
        let err = resolve_stoppable("hung.example:80", start + Duration::from_secs(3600), &DNS, false, Some(&stop), lookup).unwrap_err();
        assert_eq!(err.to_string(), "stopped");
        assert!(start.elapsed() < Duration::from_secs(2));
        release.send(Vec::new()).unwrap();
    }

    #[test]
    fn busy_workers_hold_other_names_until_one_frees_or_the_deadline() {
        static DNS: Resolver = Resolver::new();
        let mut releases = Vec::new();
        for i in 0..DNS_WORKERS {
            let (release, lookup) = held();
            releases.push(release);
            let at = Instant::now() + Duration::from_millis(10);
            assert!(resolve_with(&format!("hung{i}.example:80"), at, &DNS, false, lookup).is_err());
        }
        assert_eq!(workers(&DNS), DNS_WORKERS);
        for fresh in [false, true] {
            let err = resolve_with("next.example:80", Instant::now() + Duration::from_millis(30), &DNS, fresh, |_| panic!("no free worker"));
            let err = err.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert!(err.to_string().contains("busy"), "{err}");
        }
        // IP literals need no worker.
        for addr in ["127.0.0.1:80", "[::1]:443"] {
            let got = resolve_with(addr, Instant::now() + Duration::from_secs(5), &DNS, false, |_| panic!("an IP literal is not looked up"));
            assert_eq!(got.unwrap(), vec![addr.parse::<std::net::SocketAddr>().unwrap()]);
        }
        // A caller waits for a worker, rather than failing while every one is busy.
        let first = releases.remove(0);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            first.send(Vec::new()).unwrap();
        });
        let addr: std::net::SocketAddr = "10.0.0.2:80".parse().unwrap();
        let got = resolve_with("next.example:80", Instant::now() + Duration::from_secs(5), &DNS, false, move |_| Ok(vec![addr]));
        assert_eq!(got.unwrap(), vec![addr]);
        drop(releases);
        let at = Instant::now() + Duration::from_secs(1);
        while workers(&DNS) != 0 {
            assert!(Instant::now() < at, "finished workers must release their slots");
            std::thread::yield_now();
        }
    }

    #[test]
    fn a_fresh_lookup_skips_the_recent_answer() {
        static DNS: Resolver = Resolver::new();
        let at = || Instant::now() + Duration::from_secs(5);
        let old = "10.0.0.1:80".parse::<std::net::SocketAddr>().unwrap();
        let new = "10.0.0.2:80".parse::<std::net::SocketAddr>().unwrap();
        let name = "moved.example:80";
        assert_eq!(resolve_with(name, at(), &DNS, false, move |_| Ok(vec![old])).unwrap(), vec![old]);
        assert_eq!(resolve_with(name, at(), &DNS, false, |_| panic!("answered recently")).unwrap(), vec![old]);
        assert_eq!(resolve_with(name, at(), &DNS, true, move |_| Ok(vec![new])).unwrap(), vec![new]);
        assert_eq!(resolve_with(name, at(), &DNS, false, |_| panic!("fresh answer is cached")).unwrap(), vec![new]);
    }

    #[test]
    fn a_fresh_lookup_leaves_a_waiter_its_answer() {
        static DNS: Resolver = Resolver::new();
        let name = "moved.example:80";
        let (old, new): (std::net::SocketAddr, std::net::SocketAddr) = ("10.0.0.1:80".parse().unwrap(), "10.0.0.2:80".parse().unwrap());
        let (go, hung) = std::sync::mpsc::channel::<()>();
        let at = Instant::now() + Duration::from_secs(2);
        let waiter = std::thread::spawn(move || resolve_with(name, at, &DNS, false, move |_| hung.recv().map(|()| Vec::new()).map_err(io::Error::other)));
        while DNS.lookups.lock().unwrap().all.is_empty() {
            std::thread::sleep(Duration::from_millis(1));
        }
        // Its answer is in, its caller not woken yet, when a fresh lookup of the name starts (and hangs).
        DNS.lookups.lock().unwrap().all[0].done = Some((Instant::now(), Ok(vec![old])));
        let fresh = resolve_with(name, Instant::now() + Duration::from_millis(50), &DNS, true, move |_| {
            std::thread::sleep(Duration::from_secs(3));
            Ok(vec![new])
        });
        assert_eq!(fresh.unwrap_err().kind(), io::ErrorKind::TimedOut);
        DNS.changed.notify_all();
        assert_eq!(waiter.join().unwrap().unwrap(), vec![old], "the waiter still gets the answer it waited for");
        drop(go);
    }

    #[test]
    fn a_failed_lookup_reaches_its_callers_and_is_not_kept() {
        static DNS: Resolver = Resolver::new();
        let at = || Instant::now() + Duration::from_secs(5);
        let err = resolve_with("gone.example:80", at(), &DNS, false, |_| Err(io::Error::new(io::ErrorKind::NotFound, "no such name")));
        let err = err.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("gone.example:80") && err.to_string().contains("no such name"), "{err}");
        let err = resolve_with("gone.example:80", at(), &DNS, false, |_| Ok(Vec::new())).unwrap_err();
        assert!(err.to_string().contains("no address"), "{err}");
        let addr: std::net::SocketAddr = "10.0.0.3:80".parse().unwrap();
        assert_eq!(resolve_with("gone.example:80", at(), &DNS, false, move |_| Ok(vec![addr])).unwrap(), vec![addr]);
    }

    #[test]
    fn expired_dns_deadline_does_not_start_a_lookup() {
        static DNS: Resolver = Resolver::new();
        let err = resolve_with("unused.example:80", Instant::now(), &DNS, false, |_| panic!("deadline passed")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(workers(&DNS), 0);
        // An IP literal is answered all the same: a slow name before it in a list that shares one
        // deadline must not make a literal address after it unknown.
        for addr in ["192.0.2.9:7070", "[2001:db8::1]:7070"] {
            let got = resolve_with(addr, Instant::now(), &DNS, false, |_| panic!("an IP literal is not looked up")).unwrap();
            assert_eq!(got, vec![addr.parse::<std::net::SocketAddr>().unwrap()]);
        }
    }

    #[test]
    fn failed_write_file_removes_its_temp_file() {
        let dir = crate::test_util::TempDir::new("write-file");
        std::fs::create_dir_all(dir.join("dest")).unwrap();
        assert!(write_file(&dir, "dest", b"data", true).is_err());
        assert!(!dir.join(format!(".dest.{}.tmp", write_tag())).exists());
    }

    #[test]
    fn read_timeout_is_set_again_only_when_it_drifts() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let c = ReadTimeoutCache::new(a);
        let ms = Duration::from_millis;
        let now = || c.s.read_timeout().unwrap().unwrap();
        c.read_timeout(ms(1000)).unwrap();
        let set = now();
        assert!(set < ms(1000) && set >= ms(930), "{set:?}");
        // Still ends a read by the deadline, not much before it: kept.
        c.read_timeout(ms(990)).unwrap();
        assert_eq!(now(), set);
        // Would end it past the deadline, or well before it: set again, never past it.
        c.read_timeout(ms(900)).unwrap();
        assert!(now() <= ms(900), "{:?}", now());
        c.read_timeout(ms(2000)).unwrap();
        assert!(now() <= ms(2000) && now() > ms(1800), "{:?}", now());
        // Reads (vectored too) pass through.
        b.write_all(b"xyz").unwrap();
        let mut by = By { s: c, at: Instant::now() + ms(1000) };
        let (mut x, mut yz) = ([0u8; 1], [0u8; 2]);
        assert_eq!(by.read_vectored(&mut [io::IoSliceMut::new(&mut x), io::IoSliceMut::new(&mut yz)]).unwrap(), 3);
        assert_eq!((&x, &yz), (b"x", b"yz"));
    }

    #[test]
    fn refused_peer_connection_suggests_listen_and_peer_settings() {
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        let expected = format!("{refused}; is flexvm listen running there?");
        assert_eq!(peer_connect_error(refused), expected);
        let timeout = io::Error::from(io::ErrorKind::TimedOut);
        let expected = timeout.to_string();
        assert_eq!(peer_connect_error(timeout), expected);
    }

    #[test]
    fn rpc_names_the_peer_and_a_trickled_reply_cannot_outlast_its_deadline() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            recv_json(&mut io::BufReader::new(&c)).unwrap();
            send_json(&mut &c, &serde_json::json!({"ok": false, "error": "no room"})).unwrap();
            let (c, _) = l.accept().unwrap();
            while (&c).write_all(b" ").is_ok() {
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let wait = Duration::from_secs(1);
        let e = rpc(&addr, wait, Instant::now() + wait, &serde_json::json!({})).unwrap_err();
        assert_eq!(e.to_string(), format!("{addr}: no room"));
        let start = Instant::now();
        let e = rpc(&addr, wait, start + Duration::from_millis(200), &serde_json::json!({})).unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(5) && e.to_string() == format!("{addr}: deadline passed"), "{e}");
        assert_eq!(e.downcast_ref::<io::Error>().unwrap().kind(), io::ErrorKind::TimedOut);
        server.join().unwrap();
    }

    #[test]
    fn a_scope_is_named_and_joined_without_allocating() {
        let mut buf = [0u8; 80];
        let text = |buf: &[u8]| std::ffi::CStr::from_bytes_until_nul(buf).unwrap().to_bytes().to_vec();
        assert!(scope_path(&mut buf, b"/sys/fs/cgroup/flexvm/vm-", 4194304, 1234567, None, b"/cgroup.procs"));
        assert_eq!(text(&buf), b"/sys/fs/cgroup/flexvm/vm-4194304-1234567/cgroup.procs");
        // Named with its PID namespace (#1084).
        assert!(scope_path(&mut buf, b"/sys/fs/cgroup/flexvm/vm-", 4194304, 1234567, Some(4026531836), b"/cgroup.procs"));
        assert_eq!(text(&buf), b"/sys/fs/cgroup/flexvm/vm-4194304-1234567-4026531836/cgroup.procs");
        assert!(scope_path(&mut buf, b"vm-", 0, 0, None, b""));
        assert_eq!(text(&buf), b"vm-0-0");
        assert!(scope_path(&mut buf, b"vm-", 0, 0, Some(0), b""));
        assert_eq!(text(&buf), b"vm-0-0-0");
        assert!(scope_path(&mut buf, b"vm-", u32::MAX, u64::MAX, Some(u64::MAX), b""));
        assert_eq!(text(&buf), format!("vm-{}-{}-{}", u32::MAX, u64::MAX, u64::MAX).as_bytes());
        assert!(!scope_path(&mut [0u8; 8], b"vm-", 123, 4, None, b""), "no room for the NUL");
        assert!(!scope_path(&mut [0u8; 10], b"vm-", 1, 2, Some(345), b""), "nor for the namespace");
        assert!(scope_path(&mut [0u8; 11], b"vm-", 1, 2, Some(345), b""));
        assert!(!scope_path(&mut buf, b"v\0m-", 1, 1, None, b""));
        // Named after this instance: its start time as /proc says.
        assert_eq!(own_start(), crate::host::starttime(std::process::id()));
        assert_eq!(stat_start(b"9 (a) b) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 1"), Some(777), "a ')' in the name");
        assert_eq!(stat_start(b"9 (a) S 1"), None);
        // In a plain directory standing in for the cgroup tree.
        let root = crate::test_util::TempDir::new("scope");
        let prefix = root.join("vm-");
        let prefix = prefix.as_os_str().as_encoded_bytes();
        assert!(!scope(prefix, 7, 9, None), "made, but no cgroup.procs to join");
        assert!(root.join("vm-7-9").is_dir());
        // One that exists (say a dead process's, its pid now reused) is never joined.
        std::fs::write(root.join("vm-7-9/cgroup.procs"), b"").unwrap();
        assert!(!scope(prefix, 7, 9, None));
        assert_eq!(std::fs::read(root.join("vm-7-9/cgroup.procs")).unwrap(), b"");
        // Another PID namespace's namesake (the same pid and start time there) is another cgroup.
        assert!(!scope(prefix, 7, 9, Some(11)));
        assert!(root.join("vm-7-9-11").is_dir() && !root.join("vm-7-9-11/cgroup.procs").exists());
    }

    #[test]
    fn children_restore_terminal_stop_dispositions() {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("grep");
        cmd.args(["SigIgn", "/proc/self/status"]);
        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGTTOU, libc::SIG_IGN);
                libc::signal(libc::SIGTTIN, libc::SIG_IGN);
                Ok(())
            });
        }
        let out = unblock_signals_in(&mut cmd).output().unwrap();
        assert!(out.status.success());
        let ignored = String::from_utf8(out.stdout).unwrap();
        let mask = u64::from_str_radix(ignored.split_whitespace().nth(1).unwrap(), 16).unwrap();
        for sig in [libc::SIGTTOU, libc::SIGTTIN] {
            assert_eq!(mask & (1 << (sig - 1)), 0);
        }
    }

    #[test]
    fn children_run_with_signals_unblocked_and_stop_when_asked() {
        // Blocked in this thread only, which the child's mask is copied from.
        let set = unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                libc::sigaddset(&mut set, s);
            }
            assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()), 0);
            set
        };
        let out = run_until(std::process::Command::new("grep").args(["SigBlk", "/proc/self/status"]), || Ok(()));
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
        assert_eq!(String::from_utf8(out.unwrap().stdout).unwrap().trim(), "SigBlk:\t0000000000000000");

        let start = std::time::Instant::now();
        let stop = || match start.elapsed() > std::time::Duration::from_millis(200) {
            true => Err("interrupted".into()),
            false => Ok(()),
        };
        let err = run_until(std::process::Command::new("sleep").arg("30"), stop).unwrap_err();
        assert_eq!(err.to_string(), "interrupted");
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        // A child that fails once stopped reports the stop, not its own failure.
        assert_eq!(run_until(&mut std::process::Command::new("false"), || Err("interrupted".into())).unwrap_err().to_string(), "interrupted");
        assert!(!run_until(&mut std::process::Command::new("false"), || Ok(())).unwrap().status.success());
    }

    #[test]
    fn signal_cleanup_ends_by_the_original_signal() {
        use std::os::unix::process::ExitStatusExt;
        const CHILD: &str = "FLEXVM_TEST_SIGNAL_CLEANUP";
        if let Ok(sig) = std::env::var(CHILD) {
            let sig = sig.parse::<i32>().unwrap();
            unsafe { libc::signal(sig, libc::SIG_DFL) };
            on_signal(&[sig], |sig| {
                let mut mask = unsafe { std::mem::zeroed() };
                unsafe {
                    libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask);
                    assert_eq!(libc::sigismember(&mask, sig), 0);
                    // Re-raising must restore the default action even after a disposition changed.
                    libc::signal(sig, libc::SIG_IGN);
                }
                raise_signal(sig);
            });
            unsafe { libc::kill(libc::getpid(), sig) };
            loop {
                std::thread::park();
            }
        }
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "util::tests::signal_cleanup_ends_by_the_original_signal"])
                .env(CHILD, sig.to_string())
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(sig), "{status}");
        }
    }

    #[test]
    fn a_raised_open_file_limit_is_not_passed_on() {
        const CHILD: &str = "FLEXVM_TEST_NOFILE";
        let soft = || unsafe {
            let mut limit: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            (limit.rlim_cur, limit.rlim_max)
        };
        if std::env::var_os(CHILD).is_none() {
            use std::os::unix::process::CommandExt;
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args(["--exact", "util::tests::a_raised_open_file_limit_is_not_passed_on"]).env(CHILD, "1");
            // Started below its hard limit, as under most service managers.
            unsafe {
                cmd.pre_exec(|| {
                    let mut limit: libc::rlimit = std::mem::zeroed();
                    check(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit))?;
                    limit.rlim_cur = 256.min(limit.rlim_max);
                    check(libc::setrlimit(libc::RLIMIT_NOFILE, &limit))
                });
            }
            assert!(cmd.status().unwrap().success());
            return;
        }
        let (was, hard) = soft();
        if std::env::var(CHILD).unwrap() == "self" {
            // A flexvm child (a standby a VM process refills, say): started where its parent was.
            assert_eq!(std::env::var("FLEXVM_TEST_NOFILE_WAS").unwrap(), was.to_string());
            return;
        }
        raise_nofile();
        assert_eq!(soft(), (hard, hard));
        let out = run_until(std::process::Command::new("sh").args(["-c", "ulimit -Sn"]), || Ok(())).unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), was.to_string());
        let dir = crate::test_util::TempDir::new("nofile");
        let log = std::fs::File::create(dir.join("log")).unwrap();
        let was = was.to_string();
        let args = ["--exact", "util::tests::a_raised_open_file_limit_is_not_passed_on"];
        let mut child = spawn_self_child(&args, &log, log.as_raw_fd(), None, None, &[(CHILD, "self"), ("FLEXVM_TEST_NOFILE_WAS", &was)]).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "{status}: {}", std::fs::read_to_string(dir.join("log")).unwrap_or_default());
    }

    #[test]
    fn signal_flush_preserves_ignored_sighup() {
        const CHILD: &str = "FLEXVM_TEST_IGNORED_SIGHUP";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "util::tests::signal_flush_preserves_ignored_sighup"])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "ignored SIGHUP child: {status}");
            return;
        }
        unsafe {
            assert_ne!(libc::signal(libc::SIGHUP, libc::SIG_IGN), libc::SIG_ERR);
            let mut hup: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut hup);
            libc::sigaddset(&mut hup, libc::SIGHUP);
            assert_eq!(libc::pthread_sigmask(libc::SIG_UNBLOCK, &hup, std::ptr::null_mut()), 0);
            on_signal(&[libc::SIGHUP, libc::SIGTERM], |sig| raise_signal(sig));
            let mut mask: libc::sigset_t = std::mem::zeroed();
            assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask), 0);
            assert_eq!(libc::sigismember(&mask, libc::SIGHUP), 0, "ignored signals must not be blocked");
            assert_eq!(libc::kill(libc::getpid(), libc::SIGHUP), 0);
            let mut action: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGHUP, std::ptr::null(), &mut action), 0);
            assert_eq!(action.sa_sigaction, libc::SIG_IGN);
        }
    }

    #[test]
    fn a_final_log_waits_for_queue_space_but_only_until_its_deadline() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        tx.send(LogMsg::Line("first".into())).unwrap();
        let (full, waited) = std::sync::mpsc::channel();
        let sender = std::thread::spawn(move || {
            let start = Instant::now();
            let delay = Duration::from_millis(20);
            assert!(!send_log_by(&tx, LogMsg::Line("full".into()), start + delay));
            assert!(start.elapsed() >= delay && start.elapsed() < Duration::from_secs(5));
            let long = LogMsg::Line("x".repeat(LOG_LINE_MAX + 1));
            full.send(unsafe { libc::gettid() }).unwrap();
            assert!(send_log_by(&tx, long, Instant::now() + WAIT));
        });
        let tid = waited.recv_timeout(WAIT).unwrap();
        // Asleep with "first" still queued: only send_log_by's wait for space sleeps there.
        crate::test_util::wait_until("the second send to wait for queue space", || {
            assert!(!sender.is_finished(), "the second send returned with the queue full");
            crate::test_util::asleep(tid)
        });
        assert!(matches!(rx.recv_timeout(WAIT).unwrap(), LogMsg::Line(line) if line == "first"));
        assert!(matches!(rx.recv_timeout(WAIT).unwrap(), LogMsg::Line(line) if line.len() > LOG_LINE_MAX));
        sender.join_within().unwrap();
    }

    /// A long text (a dead Firecracker's log) goes out whole, in order, in pieces each under the line cap, cut at
    /// newlines, or on a character boundary inside a line longer than a piece.
    #[test]
    fn long_text_is_logged_whole_in_pieces_under_the_cap() {
        let mut text: String = (0..3000).map(|i| format!("[{i:>8}] line {i}\n")).collect();
        text.push_str(&"é".repeat(5000));
        text.push_str("\nthe end");
        let chunks: Vec<&str> = super::log_chunks(&text, super::LOG_CHUNK).collect();
        assert_eq!(chunks.concat(), text);
        assert!(chunks.iter().all(|c| !c.is_empty() && c.len() <= super::LOG_CHUNK));
        // Every piece but those of the overlong line and the last ends a line.
        assert!(chunks.iter().filter(|c| !c.ends_with('\n')).count() <= 2, "{:?}", chunks.iter().map(|c| c.len()).collect::<Vec<_>>());
        assert!(chunks[0].ends_with('\n') && chunks.last().unwrap().ends_with("the end"));
        assert_eq!(super::log_chunks("", 8).count(), 0);
        assert_eq!(super::log_chunks("ab\ncd", 8).collect::<Vec<_>>(), ["ab\ncd"]);
        assert_eq!(super::log_chunks("ab\ncd", 4).collect::<Vec<_>>(), ["ab\n", "cd"]);
        assert_eq!(super::log_chunks("éé", 3).collect::<Vec<_>>(), ["é", "é"]);
    }

    #[test]
    fn a_long_log_line_is_cut_on_a_character_boundary_within_its_cap() {
        let mut l = "é".repeat(20);
        super::cap_line(&mut l, 30);
        assert_eq!(l, "ééééé... (30 bytes cut)\n");
        // Caps that fit a note: the real one is 16 KiB.
        for max in 30..200 {
            for len in [max - 1, max, max + 1, 2 * max, 1000] {
                let mut l = "é".repeat(len / 2) + &"x".repeat(len % 2);
                super::cap_line(&mut l, max);
                assert!(l.len() <= max, "{len} bytes capped at {max}: {}", l.len());
            }
        }
        let mut short = "short\n".to_string();
        super::cap_line(&mut short, 16);
        assert_eq!(short, "short\n");
    }

    /// A flush returns once every line handed over before it is written,
    /// whatever other threads log meanwhile.
    #[test]
    fn a_flush_follows_every_line_logged_before_it() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1024);
        let lines = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
        let written = lines.clone();
        let writer = std::thread::spawn(move || {
            write_logs(rx, |line, _| {
                written.lock().unwrap().insert(line.to_string());
            })
        });
        std::thread::scope(|scope| {
            for t in 0..8 {
                let (tx, lines) = (&tx, &lines);
                scope.spawn(move || {
                    for i in 0..25 {
                        let marker = format!("{t}.{i}");
                        tx.send(LogMsg::Line(marker.clone())).unwrap();
                        flush_log_to(tx, Instant::now() + Duration::from_secs(30));
                        assert!(lines.lock().unwrap().contains(&marker), "flush missed {marker}");
                    }
                });
            }
        });
        drop(tx);
        writer.join().unwrap();
    }

    /// Past the cap a log moves to `.1` whole and its writers go on in a new
    /// one: nothing written is cut or lost, and a second writer follows.
    #[test]
    fn a_full_log_is_rotated_by_its_writers() {
        let d = crate::test_util::TempDir::new("rotate");
        let log = d.join("vm.log");
        // Its lock, as another writer takes it.
        let open = || crate::host::private_file(&output::log_lock(&log).unwrap()).unwrap();
        let read = |n: &str| String::from_utf8(std::fs::read(d.join(n)).unwrap()).unwrap();
        assert!(output::append_capped(&log, b"one\n", 10), "under the cap");
        // Past it: rotated; the next write starts a new log.
        assert!(output::append_capped(&log, b"two two two\n", 10));
        assert_eq!(read("vm.log.1"), "one\ntwo two two\n");
        assert!(output::append_capped(&log, b"three\n", 10) && read("vm.log") == "three\n");
        // A whole write is never cut, even past the cap.
        output::append_capped(&log, &[b'x'; 100], 10);
        assert_eq!(read("vm.log.1").len(), "three\n".len() + 100);
        // A log that is gone (garbage collection's) is made again.
        assert!(output::append_capped(&log, b"four\n", 10) && read("vm.log") == "four\n");
        std::fs::remove_file(&log).unwrap();
        assert!(output::append_capped(&log, b"five\n", 10) && read("vm.log") == "five\n");
        // Another holder of its lock (stopped, or an arrival's shared one) holds
        // writes up for at most `STALL` from each call, together, not in turn:
        // made unlocked, and nothing rotated meanwhile.
        let held = open();
        crate::host::flock(&held, libc::LOCK_SH).unwrap();
        let timed = |l: std::path::PathBuf| {
            let t = Instant::now();
            (output::append_capped(&l, b"six six\n", 10), t.elapsed())
        };
        let (l1, l2) = (log.clone(), log.clone());
        let w = std::thread::spawn(move || timed(l1));
        // Each call waits out its own `STALL` (1 s); in turn, the second would take 2 s.
        for (written, took) in [timed(l2), w.join_within().unwrap()] {
            assert!(written && took < Duration::from_millis(1900), "{took:?}");
        }
        assert_eq!(read("vm.log"), "five\nsix six\nsix six\n");
        crate::host::flock(&held, libc::LOCK_UN).unwrap();
        assert!(output::append_capped(&log, b"seven\n", 10) && read("vm.log.1") == "five\nsix six\nsix six\nseven\n");
        // A holder that rotates and stalls before letting go: a writer waiting
        // meanwhile goes on in the new log, never into `.1`. Only a rename within
        // the writer's `STALL` shows that; a round slowed past it is tried again.
        let held = open();
        crate::host::flock(&held, libc::LOCK_EX).unwrap();
        for round in 1.. {
            std::fs::write(&log, "eight\n").unwrap();
            let (l, (started, start)) = (log.clone(), std::sync::mpsc::channel());
            let w = std::thread::spawn(move || {
                started.send(Instant::now()).unwrap();
                output::append_capped(&l, b"nine\n", 10)
            });
            let start = start.recv_timeout(WAIT).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            std::fs::rename(&log, d.join("vm.log.1")).unwrap();
            let waiting = start.elapsed() < Duration::from_secs(1);
            assert!(w.join_within().unwrap());
            if waiting {
                break;
            }
            assert!(round < 10, "never renamed within the writer's stall");
        }
        assert_eq!((read("vm.log.1"), read("vm.log")), ("eight\n".into(), "nine\n".into()));
    }

    #[test]
    fn a_send_to_a_full_backlog_ends_by_its_deadline() {
        let dir = crate::test_util::TempDir::new("backlog");
        let path = dir.join("s");
        let _ = std::fs::remove_file(&path);
        let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert_eq!(unsafe { libc::listen(l.as_raw_fd(), 0) }, 0);
        let held: Vec<_> = (0..64).map_while(|_| connect_unix(&path, Duration::from_millis(1)).ok()).collect();
        assert!(held.len() < 64);
        let start = Instant::now();
        let e = send_unix(&path, b"{}\n", &[], start + Duration::from_millis(200)).unwrap_err();
        assert!(e.raw_os_error() == Some(libc::EAGAIN) && start.elapsed() < Duration::from_secs(5), "{e}");
    }

    /// What a standby claim's handshake rests on: once the claimer shuts its reads,
    /// the standby's `claiming` fails, and one sent before is still read.
    #[test]
    fn a_read_shutdown_fails_later_writes_and_keeps_earlier_ones() {
        let (a, b) = UnixStream::pair().unwrap();
        (&b).write_all(b"sent\n").unwrap();
        a.shutdown(std::net::Shutdown::Read).unwrap();
        assert_eq!((&b).write(b"late\n").unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(io::read_to_string(&a).unwrap(), "sent\n");
    }

    #[test]
    fn truncated_fds_fail_the_receive() {
        let (a, b) = UnixStream::pair().unwrap();
        let null = std::fs::File::open("/dev/null").unwrap();
        send_with_fds(&a, b"{}\n", &[null.as_raw_fd(); 2], Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(recv_with_fds(&b, 64, || Ok(())).unwrap().1.len(), 2);
        // The aligned receive buffer still holds 256 bytes, including the header.
        assert!(std::mem::align_of::<u64>() >= std::mem::align_of::<libc::cmsghdr>());
        send_with_fds(&a, b"{}\n", &[null.as_raw_fd(); 60], Instant::now() + Duration::from_secs(5)).unwrap();
        let (_, fds) = recv_with_fds(&b, 64, || Ok(())).unwrap();
        assert_eq!(fds.len(), 60);
        for fd in fds {
            assert_ne!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
        }
        // More than the receive buffer holds: an error, not a request missing some.
        send_with_fds(&a, b"{}\n", &[null.as_raw_fd(); 100], Instant::now() + Duration::from_secs(5)).unwrap();
        let e = recv_with_fds(&b, 64, || Ok(())).unwrap_err();
        assert!(e.kind() == io::ErrorKind::InvalidData && e.to_string().contains("truncated"), "{e}");
    }

    #[test]
    fn json_line_limit_bounds_consumption() {
        let mut input = io::Cursor::new(vec![b' '; MAX_LINE as usize + 100]);
        assert!(recv_json(&mut input).unwrap_err().to_string().contains("exceeds"));
        assert_eq!(input.position(), MAX_LINE);
        let mut line = vec![b' '; MAX_LINE as usize - 2];
        line.extend_from_slice(b"0\n1\n");
        let mut input = io::Cursor::new(line);
        assert_eq!(recv_json(&mut input).unwrap(), Some(0.into()));
        assert_eq!(recv_json(&mut input).unwrap(), Some(1.into()));
        assert!(recv_json(&mut input).unwrap().is_none());
        let mut line = vec![b' '; MAX_LINE as usize + 100];
        line.extend_from_slice(b"2\n");
        assert_eq!(recv_json_max::<serde_json::Value>(&mut io::Cursor::new(line), 2 * MAX_LINE).unwrap(), Some(2.into()));
        let mut input = io::Cursor::new(b"[1,2]\n3\n");
        assert_eq!(recv_json_max::<Vec<u64>>(&mut input, MAX_LINE).unwrap(), Some(vec![1, 2]));
        assert_eq!(recv_json(&mut input).unwrap(), Some(3.into()));
    }

    #[test]
    fn state_and_suspended_directories_are_private() {
        let tmp = crate::test_util::TempDir::new("private");
        // Made here, not by the guard, so its mode is create_dir_durably's.
        let root = tmp.join("root");
        let dir = root.join("state/suspended");
        create_dir_durably(&dir, 0o700).unwrap();
        for path in [&root, &root.join("state"), &dir] {
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o700);
        }
        create_dir_durably(&dir, 0o700).unwrap();
    }

    #[test]
    fn pinned_ancestors_are_synced_once_even_on_error() {
        let root = crate::test_util::TempDir::new("ancestor-count");
        std::fs::create_dir_all(root.join("a/b/c")).unwrap();
        let path = root.join("a/b/c").canonicalize().unwrap();
        let dir = open_dir(&path).unwrap();
        let want: std::collections::HashSet<_> = path.ancestors().skip(1).map(|p| dir_id(open_dir(p).unwrap().as_raw_fd()).unwrap()).collect();
        for fail in [false, true] {
            let calls = std::sync::Mutex::new(Vec::new());
            let result = sync_ancestors_fd_with(dir.as_raw_fd(), &|d| {
                calls.lock().unwrap().push(dir_id(d.as_raw_fd())?);
                if fail {
                    Err(io::Error::other("injected fsync error"))
                } else {
                    Ok(())
                }
            });
            assert_eq!(result.is_err(), fail);
            let calls = calls.into_inner().unwrap();
            assert_eq!(calls.len(), want.len(), "exactly one fsync per ancestor");
            assert_eq!(calls.into_iter().collect::<std::collections::HashSet<_>>(), want);
        }
    }

    #[test]
    fn directory_syncs_overlap_and_join_on_error() {
        let root = crate::test_util::TempDir::new("ancestor-overlap");
        let dirs = [open_dir(&root).unwrap(), open_dir(&root).unwrap()];
        let entered = std::sync::Mutex::new(0);
        let ready = std::sync::Condvar::new();
        let completed = AtomicUsize::new(0);
        let result = sync_dirs_with(&dirs, &|_| {
            let mut n = entered.lock().unwrap();
            *n += 1;
            ready.notify_all();
            let (guard, timeout) = ready.wait_timeout_while(n, Duration::from_secs(5), |n| *n < 2).unwrap();
            drop(guard);
            assert!(!timeout.timed_out(), "fsyncs must overlap");
            completed.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("injected fsync error"))
        });
        assert!(result.is_err());
        assert_eq!(completed.load(Ordering::SeqCst), 2, "all syncs joined before returning an error");
    }

    #[test]
    fn ancestors_are_synced_physically_and_through_symlinks() {
        use std::os::unix::fs::MetadataExt;
        let root = crate::test_util::TempDir::new("ancestors");
        std::fs::create_dir_all(root.join("real/a/b")).unwrap();
        std::fs::create_dir_all(root.join("l")).unwrap();
        std::os::unix::fs::symlink("../real/a", root.join("l/link")).unwrap();
        let root = root.canonicalize().unwrap();
        let id = |p: &Path| std::fs::metadata(p).map(|m| (m.dev(), m.ino())).unwrap();
        let walk = |p: &Path, seen: &mut Seen| {
            let mut synced = vec![];
            sync_ancestors_with(p, seen, &mut |d| dir_id(d.as_raw_fd()).map(|id| synced.push(id))).map(|()| synced)
        };
        // The link's directory (not on the physical chain) and everything above both.
        let synced = walk(&root.join("l/link/b"), &mut Default::default()).unwrap();
        let mut want: Vec<_> = [root.join("l"), root.join("real/a"), root.join("real")].iter().map(|p| id(p)).collect();
        want.extend(root.ancestors().map(id));
        let set: std::collections::HashSet<_> = synced.iter().copied().collect();
        assert_eq!(synced.len(), set.len(), "each once: {synced:?}");
        assert_eq!(set, want.iter().copied().collect(), "{synced:?}");
        assert!(synced.contains(&id(Path::new("/"))));

        // A link in a link's target: p/l1 -> q/l2 -> real/a; q holds l2. Then nothing twice.
        std::fs::create_dir_all(root.join("p")).unwrap();
        std::fs::create_dir_all(root.join("q")).unwrap();
        std::os::unix::fs::symlink(root.join("q/l2"), root.join("p/l1")).unwrap();
        std::os::unix::fs::symlink("../real/a", root.join("q/l2")).unwrap();
        let mut seen = Seen::new();
        let synced = walk(&root.join("p/l1/b"), &mut seen).unwrap();
        for d in ["p", "q", "real/a", "real"] {
            assert!(synced.contains(&id(&root.join(d))), "{d}: {synced:?}");
        }
        assert_eq!(walk(&root.join("p/l1/b"), &mut seen).unwrap(), []);

        // A link target walks through directories that ".." then leaves behind.
        std::fs::create_dir_all(root.join("q/inner")).unwrap();
        std::os::unix::fs::symlink("../q/inner/../../real/a", root.join("p/link")).unwrap();
        let synced = walk(&root.join("p/link/b"), &mut Default::default()).unwrap();
        for d in ["p", "q", "q/inner", "real/a", "real"] {
            assert!(synced.contains(&id(&root.join(d))), "{d}: {synced:?}");
        }
        assert_eq!(synced.len(), synced.iter().collect::<std::collections::HashSet<_>>().len());

        // From a pinned directory, a swapped-in path is never followed.
        let pinned = std::fs::File::open(root.join("real/a/b")).unwrap();
        std::fs::rename(root.join("real"), root.join("moved")).unwrap();
        std::fs::create_dir_all(root.join("other/a")).unwrap();
        std::os::unix::fs::symlink("other", root.join("real")).unwrap();
        let mut synced = vec![];
        walk_up(pinned.as_raw_fd(), &mut Default::default(), &mut |d| {
            synced.push(dir_id(d.as_raw_fd())?);
            Ok(())
        })
        .unwrap();
        assert_eq!(synced[..2], [id(&root.join("moved/a")), id(&root.join("moved"))]);
        assert!(!synced.contains(&id(&root.join("other/a"))));

        assert!(sync_ancestors(&root.join("missing")).is_err());
        assert!(sync_ancestors_with(&root.join("moved/a/b"), &mut Default::default(), &mut |_| Err(io::Error::other("eio"))).is_err());
        assert!(sync_ancestors(&root.join("real/a")).is_ok());
        assert!(sync_dir(&root.join("moved/a/b")).is_ok());
        std::fs::write(root.join("f"), "").unwrap();
        assert!(sync_dir(&root.join("f")).is_err());
    }
}

/// A VM process's stdout and stderr: pipes that relay threads copy to the
/// terminal (or the claimer's, `retarget`). A target that fails or does not
/// take output within `STALL` (a closed terminal, a broken or stalled pipe)
/// is given up for the VM's log file, so printing never fails, never aborts
/// the VM and never holds it up for long; nothing is locked across a write.
/// A target that is a log in the run directory is kept under `LOG_CAP` by
/// its writers: past it, `log` becomes `log.1` and a new one is started; a
/// writer whose log was rotated by another follows. A VM's logs are a
/// lifetime's directory (`Host::open_logs`), which its writers hold: they
/// write and rotate only in it, so once it is retired (`rm`, `rename`, a new
/// VM of the name) nothing of theirs reaches the name's later logs.
pub mod output {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    const STALL: Duration = Duration::from_secs(1);
    /// A log is rotated once past this.
    pub const LOG_CAP: u64 = 8 << 20;
    static TARGETS: Mutex<[Option<Arc<File>>; 2]> = Mutex::new([None, None]);
    /// The capped log each target writes to, if it is one.
    static LOGS: Mutex<[Option<Log>; 2]> = Mutex::new([None, None]);
    /// The VM's logs, once its terminal is gone.
    static LOG: Mutex<Option<Log>> = Mutex::new(None);
    static RELAYS: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());

    /// A capped log: a VM's, in its lifetime's directory (held), or one at a path
    /// (a standby pool's).
    #[derive(Clone)]
    enum Log {
        In(Arc<File>),
        At(PathBuf),
        /// An arrival's, until published (`arriving`): appended to, never capped.
        Plain(Arc<File>),
    }

    impl Log {
        fn append(&self, data: &[u8]) -> bool {
            match self {
                Log::In(dir) => append_in(dir, data, LOG_CAP),
                Log::At(path) => append_capped(path, data, LOG_CAP),
                Log::Plain(f) => (&**f).write_all(data).is_ok(),
            }
        }
    }

    pub fn guard() -> std::io::Result<()> {
        for (i, fd) in [1, 2].into_iter().enumerate() {
            let mut p = [0; 2];
            let orig = super::eintr(|| unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) })?;
            super::eintr(|| unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) })?;
            super::eintr(|| unsafe { libc::dup2(p[1], fd) })?;
            unsafe { libc::close(p[1]) };
            let orig = unsafe { File::from_raw_fd(orig) };
            LOGS.lock().unwrap()[i] = capped(&orig);
            TARGETS.lock().unwrap()[i] = Some(Arc::new(own(orig)));
            let mut from = unsafe { File::from_raw_fd(p[0]) };
            RELAYS.lock().unwrap().push(std::thread::spawn(move || {
                let mut buf = [0u8; 64 << 10];
                while let Ok(n @ 1..) = from.read(&mut buf) {
                    relay(i, &buf[..n]);
                }
            }));
        }
        Ok(())
    }

    /// Diagnostics bypass the app's streams, and are recorded exactly once even in detached mode.
    pub fn diagnostic(data: &[u8], info: bool) {
        let target_log = LOGS.lock().unwrap()[1].clone();
        // Where stderr goes, if that is a log (a standby's own until claimed); else a terminal's VM log.
        let log = target_log.clone().or_else(|| LOG.lock().unwrap().clone());
        if let Some(log) = &log {
            log.append(data);
        }
        if target_log.is_some() || (info && !super::verbose()) {
            return;
        }
        let target = TARGETS.lock().unwrap()[1].clone();
        if let Some(target) = target {
            write_within(&target, data, Instant::now() + STALL);
        } else {
            let _ = std::io::stderr().write_all(data);
        }
    }

    fn relay(i: usize, data: &[u8]) {
        // A capped log's output is appended there or dropped, never written twice.
        let log = LOGS.lock().unwrap()[i].clone();
        if let Some(log) = log {
            log.append(data);
            return;
        }
        let target = TARGETS.lock().unwrap()[i].clone();
        let sent = target.as_ref().map_or(0, |t| write_within(t, data, Instant::now() + STALL));
        if sent == data.len() {
            return;
        }
        // Given up, unless a retarget replaced it meanwhile.
        let fallback = {
            let mut targets = TARGETS.lock().unwrap();
            if targets[i].as_ref().map(Arc::as_ptr) == target.as_ref().map(Arc::as_ptr) {
                LOGS.lock().unwrap()[i] = LOG.lock().unwrap().clone();
                targets[i] = None;
            }
            (targets[i].clone(), LOGS.lock().unwrap()[i].clone())
        };
        if let Some(log) = fallback.1 {
            log.append(&data[sent..]);
        } else if let Some(f) = fallback.0.as_deref() {
            write_within(f, &data[sent..], Instant::now() + STALL);
        }
    }

    /// What was written by `deadline`: regular files take the whole buffer;
    /// other targets take pipe-sized pieces, each once the target is ready.
    fn write_within(f: &File, data: &[u8], deadline: Instant) -> usize {
        use std::os::unix::fs::FileTypeExt;
        let kind = f.metadata().ok().map(|m| m.file_type());
        let regular = kind.is_some_and(|k| k.is_file());
        let socket = kind.is_some_and(|k| k.is_socket());
        let mut sent = 0;
        while sent < data.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            let mut p = libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
            if left.is_zero() || (!regular && (unsafe { libc::poll(&mut p, 1, left.as_millis().max(1) as i32) } <= 0 || p.revents & libc::POLLOUT == 0)) {
                break;
            }
            let piece = &data[sent..if regular { data.len() } else { (sent + 4096).min(data.len()) }];
            let (fd, buf, len) = (f.as_raw_fd(), piece.as_ptr().cast(), piece.len());
            // Another relay may have filled a shared target since the poll: retried.
            let n = if socket { unsafe { libc::send(fd, buf, len, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) } } else { unsafe { libc::write(fd, buf, len) } };
            match n {
                n if n > 0 => sent += n as usize,
                _ if matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINTR | libc::EAGAIN)) => {}
                _ => break,
            }
        }
        sent
    }

    /// A target's own open file, non-blocking (flags set on `f` would change every process's
    /// sharing it); a regular file, a socket or one that cannot be reopened (a /dev/tty away
    /// from its terminal: a claimer passes its own) is kept as is.
    pub fn own(f: File) -> File {
        use std::os::unix::fs::FileTypeExt;
        if f.metadata().is_ok_and(|m| m.is_file() || m.file_type().is_socket()) {
            return f;
        }
        let path = format!("/proc/self/fd/{}", f.as_raw_fd());
        File::options().write(true).custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY).open(path).unwrap_or(f)
    }

    /// Where the VM's output goes once its terminal is gone: its logs (`Host::open_logs`).
    /// Only a VM's own process writes them; any other's output is its terminal's alone.
    pub fn fall_back_to(logs: File) {
        *LOG.lock().unwrap() = Some(Log::In(Arc::new(logs)));
    }

    /// A claimed standby's output goes to its claimer's terminal.
    pub fn retarget(fds: [RawFd; 2]) {
        let mut targets = TARGETS.lock().unwrap();
        for (i, fd) in fds.into_iter().enumerate() {
            if let Ok(dup) = super::eintr(|| unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) }) {
                let f = unsafe { File::from_raw_fd(dup) };
                LOGS.lock().unwrap()[i] = capped(&f);
                targets[i] = Some(Arc::new(own(f)));
            }
        }
    }

    /// An arrival's (`listen::incoming`): its output's file is its log until published (`published`),
    /// so every diagnostic goes there, as to a VM's log, info lines too; none to the name's logs,
    /// whose `log` the published one replaces.
    pub fn arriving() {
        let targets = TARGETS.lock().unwrap();
        let mut caps = LOGS.lock().unwrap();
        for (i, t) in targets.iter().enumerate() {
            if let Some(t) = t.as_ref().filter(|t| caps[i].is_none() && t.metadata().is_ok_and(|m| m.is_file())) {
                caps[i] = Some(Log::Plain(t.clone()));
            }
        }
    }

    /// An arrival's log was published as `log` in `logs` (`listen::finish_incoming_log`), a new
    /// lifetime: capped there from now on, and the VM's logs from here.
    pub fn published(logs: File) {
        let targets = TARGETS.lock().unwrap();
        let mut caps = LOGS.lock().unwrap();
        let logs = Arc::new(logs);
        *LOG.lock().unwrap() = Some(Log::In(logs.clone()));
        for (i, t) in targets.iter().enumerate() {
            if t.as_ref().is_some_and(|t| is_log_in(t, &logs)) {
                caps[i] = Some(Log::In(logs.clone()));
            }
        }
    }

    fn same_file(f: &File, path: &Path) -> bool {
        match (f.metadata(), std::fs::metadata(path)) {
            (Ok(a), Ok(b)) => a.ino() == b.ino() && a.dev() == b.dev(),
            _ => false,
        }
    }

    /// Whether `f` is the `log` in `dir`.
    fn is_log_in(f: &File, dir: &File) -> bool {
        match (f.metadata(), super::stat_at(dir.as_raw_fd(), c"log")) {
            (Ok(a), Some(b)) => a.ino() == b.st_ino && a.dev() == b.st_dev,
            _ => false,
        }
    }

    /// The log `f` is, if this process caps it: a regular file in the run directory, not an
    /// arrival's (hidden: published once accepted). A VM's (`log` in `NAME.logs`) by its
    /// directory, held; any other by its path.
    fn capped(f: &File) -> Option<Log> {
        if !f.metadata().ok()?.is_file() {
            return None;
        }
        let path = std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())).ok()?;
        let hidden = |p: &Path| p.file_name().and_then(|n| n.to_str()).is_none_or(|n| n.starts_with('.'));
        if !path.starts_with(crate::host::run_dir()?) || hidden(&path) {
            return None;
        }
        match path.parent().filter(|d| !hidden(d) && d.extension().is_some_and(|e| e == "logs") && path.file_name().is_some_and(|n| n == "log")) {
            Some(dir) => open_dir(dir).ok().filter(|d| is_log_in(f, d)).map(|d| Log::In(Arc::new(d))),
            None => same_file(f, &path).then_some(Log::At(path)),
        }
    }

    /// `dir`, a directory (never through a link), opened to work in.
    pub fn open_dir(dir: &Path) -> std::io::Result<File> {
        File::options().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(dir)
    }

    /// `name` in `dir`, opened with `flags` (and 0600 if made); never through a link.
    pub fn open_in(dir: &File, name: &std::ffi::CStr, flags: i32) -> std::io::Result<File> {
        let fd = super::eintr(|| unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0o600) })?;
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Appends `data` to `log` in `dir` (a VM's logs), holding the directory's lock (a flock of
    /// an open of this call's own), so no write goes to a log another writer is rotating. Past
    /// `cap`, `log` is renamed `log.1` (replacing the one before); the next write starts a new
    /// `log` (0600), so one interrupted between leaves `log.1` for `logs` to read. A lock not had
    /// within `STALL` (a stopped holder) is done without: the append is made unlocked and
    /// nothing rotated. All of it in `dir`: retired, it is never the name's again. Whether
    /// `data` was written; it is never written twice.
    pub fn append_in(dir: &File, data: &[u8], cap: u64) -> bool {
        let lock = lock_dir(dir);
        let written = open_in(dir, c"log", libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT).is_ok_and(|mut f| {
            let written = f.write_all(data).is_ok();
            if lock.is_some() && f.metadata().is_ok_and(|m| m.len() > cap) {
                let d = dir.as_raw_fd();
                unsafe { libc::renameat(d, c"log".as_ptr(), d, c"log.1".as_ptr()) };
            }
            written
        });
        if let Some(l) = lock {
            // Unlocked, not only closed: see `host::Flock`.
            let _ = crate::host::flock(&l, libc::LOCK_UN);
        }
        written
    }

    /// `dir`'s (a VM's logs') writers' lock: a flock of an open of this call's own, had within
    /// `STALL` (else None: a stopped holder, done without). Let go of with `LOCK_UN`.
    pub fn lock_dir(dir: &File) -> Option<File> {
        let deadline = Instant::now() + STALL;
        loop {
            let take = || {
                let f = open_in(dir, c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
                crate::host::flock(&f, libc::LOCK_EX | libc::LOCK_NB).map(|()| f)
            };
            match take() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
                result => break result.ok(),
            }
        }
    }

    /// Appends `data` to the file at `log`, holding `log`'s lock (`log_lock`; never
    /// the log itself, which other users may read), so no write goes to a generation
    /// another writer is rotating or removing. Past `cap`, `log` is renamed `log.1`
    /// (replacing the one before); the next write starts a new `log` (0600). A lock
    /// not had within `STALL` of the call (a stopped holder) is done without: the
    /// append is made unlocked and nothing rotated (a rotation racing it may take it
    /// to `log.1`). Whether `data` was written; it is never written twice.
    pub fn append_capped(log: &Path, data: &[u8], cap: u64) -> bool {
        let deadline = Instant::now() + STALL;
        // Taken on an open of this call's own: one shared would not exclude the others sharing it.
        let lock = log_lock(log).ok().and_then(|path| loop {
            match crate::host::lock_path(&path, libc::LOCK_EX | libc::LOCK_NB) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
                result => break result.ok(),
            }
        });
        let locked = lock.is_some();
        let written = File::options().create(true).append(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(log).is_ok_and(|mut f| {
            let written = f.write_all(data).is_ok();
            if locked && f.metadata().is_ok_and(|m| m.len() > cap) {
                let mut old = log.as_os_str().to_owned();
                old.push(".1");
                let _ = std::fs::rename(log, old);
            }
            written
        });
        if let Some(l) = lock {
            // Unlocked, not only closed: see `host::Flock`.
            let _ = crate::host::flock(&l, libc::LOCK_UN);
        }
        written
    }

    /// `log`'s lock: `.locks/NAME` in its directory.
    pub fn log_lock(log: &Path) -> std::io::Result<PathBuf> {
        let (dir, name) = (log.parent().ok_or(std::io::ErrorKind::InvalidInput)?, log.file_name().ok_or(std::io::ErrorKind::InvalidInput)?);
        Ok(crate::host::locks(dir).join(name))
    }

    /// Drains the relays before exit, after queued diagnostics have been flushed.
    /// Bounded by a little over `STALL` from the start, so a relay's write that
    /// began just before and waits out its own `STALL` (a log's stopped lock
    /// holder) still lands: what was printed reaches its target if it can. No
    /// output lock is taken (a thread may hold stdout's for good); what std
    /// still buffers, exit flushes if free.
    pub fn drain() {
        let deadline = Instant::now() + STALL + STALL / 4;
        let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        if null >= 0 {
            unsafe {
                libc::dup2(null, 1);
                libc::dup2(null, 2);
                libc::close(null);
            }
        }
        let Ok(relays) = RELAYS.try_lock().map(|mut r| std::mem::take(&mut *r)) else { return };
        for r in relays {
            while !r.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    #[test]
    fn regular_output_writes_the_whole_buffer() {
        let dir = crate::test_util::TempDir::new("regular-output");
        let path = dir.join("output");
        let f = File::create(&path).unwrap();
        let data = vec![42; 64 << 10];
        assert_eq!(write_within(&f, &data, Instant::now() + STALL), data.len());
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert_eq!(write_within(&f, b"late", Instant::now()), 0);
    }

    /// A VM's fallback writes its logs' lifetime: rotated (by another writer, or by it past the
    /// cap) it goes on in a new `log`; retired (`rm`, `rename`, a new VM of the name), all it
    /// writes, rotations too, stays in the retired directory, never the name's later logs.
    #[test]
    fn fallback_log_follows_rotation_and_never_writes_a_later_lifetime() {
        const CHILD: &str = "FLEXVM_FALLBACK_ROTATION_TEST";
        if let Some(path) = std::env::var_os(CHILD) {
            let dir = PathBuf::from(path);
            std::fs::create_dir(&dir).unwrap();
            let (log, old) = (dir.join("log"), dir.join("log.1"));
            fall_back_to(open_dir(&dir).unwrap());
            TARGETS.lock().unwrap()[0] = Some(Arc::new(File::open("/dev/null").unwrap()));
            relay(0, b"first");
            assert!(matches!(LOGS.lock().unwrap()[0], Some(Log::In(_))));
            assert!(TARGETS.lock().unwrap()[0].is_none());
            std::fs::rename(&log, &old).unwrap();
            relay(0, b"second");
            assert_eq!(std::fs::read(&old).unwrap(), b"first");
            assert_eq!(std::fs::read(&log).unwrap(), b"second");
            std::fs::remove_file(&old).unwrap();
            relay(0, &vec![42; LOG_CAP as usize]);
            assert!(!log.exists());
            relay(0, b"third");
            assert_eq!(std::fs::read(&log).unwrap(), b"third");
            // Interrupted mid-rotation: `log.1` alone; the next write starts `log`.
            std::fs::rename(&log, &old).unwrap();
            relay(0, b"fourth");
            assert_eq!(std::fs::read(&log).unwrap(), b"fourth");
            // Retired, and a later VM's logs made at the path: this writer, stale, goes on in its
            // own, past the cap too.
            let gone = dir.with_extension("logs.gone");
            std::fs::rename(&dir, &gone).unwrap();
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(&log, b"replacement").unwrap();
            relay(0, b"after rm");
            relay(0, &vec![42; LOG_CAP as usize]);
            relay(0, b"rotated");
            assert_eq!(std::fs::read(&log).unwrap(), b"replacement");
            assert!(!old.exists());
            assert_eq!(std::fs::read(gone.join("log")).unwrap(), b"rotated");
            // Removed (its directory gone): nothing is made again.
            std::fs::remove_dir_all(&gone).unwrap();
            relay(0, b"after removal");
            assert!(!gone.exists());
            assert_eq!(std::fs::read(&log).unwrap(), b"replacement");
            return;
        }
        let dir = crate::test_util::TempDir::new("fallback-rotation");
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "util::output::fallback_log_follows_rotation_and_never_writes_a_later_lifetime", "--nocapture"])
            .env(CHILD, dir.join("vm.logs"))
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    }

    /// A log that cannot be made (no inodes left, say) loses that write only: the next makes it.
    #[test]
    fn a_log_that_cannot_be_made_is_made_by_the_next_write() {
        let d = crate::test_util::TempDir::new("log-make");
        let dir = open_dir(&d).unwrap();
        std::fs::create_dir(d.join("log")).unwrap();
        assert!(!append_in(&dir, b"lost\n", 10));
        std::fs::remove_dir(d.join("log")).unwrap();
        assert!(append_in(&dir, b"one\n", 10));
        assert!(append_in(&dir, b"two two two\n", 10));
        assert_eq!(std::fs::read(d.join("log.1")).unwrap(), b"one\ntwo two two\n");
        assert!(!d.join("log").exists());
        assert!(append_in(&dir, b"three\n", 10));
        assert_eq!(std::fs::read(d.join("log")).unwrap(), b"three\n");
    }

    #[test]
    fn diagnostics_and_app_streams_are_routed_and_logged_once() {
        const CHILD: &str = "FLEXVM_OUTPUT_TEST_LOG";
        if let Some(log) = std::env::var_os(CHILD) {
            // Run alone: these targets and the diagnostic writer are process globals.
            super::set_verbose(std::env::var_os("FLEXVM_OUTPUT_TEST_VERBOSE").is_some());
            guard().unwrap();
            let logs = PathBuf::from(log);
            std::fs::create_dir(&logs).unwrap();
            let open = || open_dir(&logs).unwrap();
            if std::env::var_os("FLEXVM_OUTPUT_TEST_DETACHED").is_some() {
                *LOGS.lock().unwrap() = [Some(Log::In(Arc::new(open()))), Some(Log::In(Arc::new(open())))];
            }
            fall_back_to(open());
            std::io::stdout().write_all(b"app-out-marker\n").unwrap();
            std::io::stderr().write_all(b"app-err-marker\n").unwrap();
            super::info_line("info-marker\n".into());
            super::log_line("error-marker\n".into());
            super::log_final("hint-marker\n".into(), true);
            super::flush_log(super::LOG_FLUSH);
            drain();
            return;
        }
        for mode in ["quiet", "flag", "debug", "detached"] {
            let dir = crate::test_util::TempDir::new("output-routing");
            let log = dir.join("vm.logs");
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args(["--exact", "util::output::diagnostics_and_app_streams_are_routed_and_logged_once", "--nocapture"])
                .env(CHILD, &log)
                .env_remove("FLEXVM_LOG")
                .env_remove("FLEXVM_OUTPUT_TEST_VERBOSE")
                .env_remove("FLEXVM_OUTPUT_TEST_DETACHED");
            match mode {
                "flag" => {
                    cmd.env("FLEXVM_OUTPUT_TEST_VERBOSE", "1");
                }
                "debug" => {
                    cmd.env("FLEXVM_LOG", "debug");
                }
                "detached" => {
                    cmd.env("FLEXVM_OUTPUT_TEST_DETACHED", "1");
                }
                _ => {}
            }
            let output = cmd.output().unwrap();
            assert!(output.status.success(), "{mode}: {output:?}");
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            let log = std::fs::read_to_string(log.join("log")).unwrap();
            if mode == "detached" {
                assert!(!stdout.contains("marker") && !stderr.contains("marker"), "{stdout} {stderr}");
            } else {
                assert!(stdout.contains("app-out-marker") && !stdout.contains("app-err-marker"), "{stdout}");
                assert!(stderr.contains("app-err-marker") && !stderr.contains("app-out-marker"), "{stderr}");
                assert!(!stdout.contains("info-marker") && !stdout.contains("error-marker") && !stdout.contains("hint-marker"), "{stdout}");
                assert_eq!(stderr.contains("info-marker"), mode != "quiet", "{stderr}");
                assert!(stderr.contains("error-marker") && stderr.contains("hint-marker"), "{stderr}");
            }
            for marker in ["app-out-marker", "app-err-marker", "info-marker", "error-marker", "hint-marker"] {
                // A foreground VM's own output is its terminal's alone.
                let want = usize::from(mode == "detached" || !marker.starts_with("app-"));
                assert_eq!(log.matches(marker).count(), want, "{mode} {marker}: {log}");
            }
        }
    }

    /// An arrival's diagnostics, info lines too, all go to its log (its output's file), once,
    /// none to the name's logs, whose `log` its log replaces once published.
    #[test]
    fn an_arrivals_diagnostics_all_go_to_its_log() {
        const CHILD: &str = "FLEXVM_OUTPUT_TEST_ARRIVAL";
        if let Some(log) = std::env::var_os(CHILD) {
            guard().unwrap();
            let logs = PathBuf::from(log);
            std::fs::create_dir(&logs).unwrap();
            arriving();
            fall_back_to(open_dir(&logs).unwrap());
            std::io::stderr().write_all(b"app-err-marker\n").unwrap();
            super::info_line("info-marker\n".into());
            super::log_line("error-marker\n".into());
            super::flush_log(super::LOG_FLUSH);
            drain();
            return;
        }
        let dir = crate::test_util::TempDir::new("output-arrival");
        let (logs, arrival) = (dir.join("vm.logs"), dir.join(".incoming.log"));
        let out = File::create(&arrival).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "util::output::an_arrivals_diagnostics_all_go_to_its_log", "--nocapture"])
            .env(CHILD, &logs)
            .env_remove("FLEXVM_LOG")
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .status()
            .unwrap();
        assert!(status.success());
        let got = std::fs::read_to_string(&arrival).unwrap();
        for marker in ["app-err-marker", "info-marker", "error-marker"] {
            assert_eq!(got.matches(marker).count(), 1, "{marker}: {got}");
        }
        assert!(!logs.join("log").exists(), "{:?}", std::fs::read_to_string(logs.join("log")));
    }

    #[test]
    fn a_full_target_is_given_up_by_the_deadline_leaving_its_sharers_blocking() {
        let mut p = [0; 2];
        assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let (_r, w) = unsafe { (File::from_raw_fd(p[0]), File::from_raw_fd(p[1])) };
        let t = own(w.try_clone().unwrap());
        while (&t).write(&[0; 4096]).is_ok() {}
        let start = Instant::now();
        assert_eq!(write_within(&t, &[0; 100], start + Duration::from_millis(200)), 0);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(unsafe { libc::fcntl(w.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK, 0);
    }

    #[test]
    fn a_retargeted_full_pipe_keeps_the_fallback_output() {
        use crate::test_util::{wait_until, JoinWithin};
        struct Restore(Option<Arc<File>>, Option<Log>);
        impl Drop for Restore {
            fn drop(&mut self) {
                // Also after a panic, which may have poisoned either lock.
                TARGETS.lock().unwrap_or_else(|e| e.into_inner())[0] = self.0.take();
                LOGS.lock().unwrap_or_else(|e| e.into_inner())[0] = self.1.take();
            }
        }
        let _restore = Restore(TARGETS.lock().unwrap()[0].clone(), LOGS.lock().unwrap()[0].clone());
        let full = || {
            let mut p = [0; 2];
            assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            let (r, w) = unsafe { (File::from_raw_fd(p[0]), File::from_raw_fd(p[1])) };
            let w = own(w);
            let mut filled = 0;
            while let Ok(n) = (&w).write(&[0; 4096]) {
                filled += n;
            }
            (r, Arc::new(w), filled)
        };
        let (_old, target, _) = full();
        let (mut next, fallback, filled) = full();
        TARGETS.lock().unwrap()[0] = Some(target.clone());
        let relay = std::thread::spawn(|| relay(0, b"kept"));
        wait_until("relay to take the old target", || Arc::strong_count(&target) == 3);
        TARGETS.lock().unwrap()[0] = Some(fallback.clone());
        wait_until("relay to take the fallback", || Arc::strong_count(&fallback) == 3);
        next.read_exact(&mut vec![0; filled]).unwrap();
        relay.join_within().unwrap();
        assert!(super::readable(&next, Duration::ZERO).unwrap(), "the finished relay left no fallback output");
        let mut data = [0; 4];
        next.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"kept");
    }
}
