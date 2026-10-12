use std::io::{self, BufRead, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => { return Err(format!($($arg)*).into()) };
}

pub const PAGE_SIZE: usize = 4096;

/// Writes one JSON value as a line.
pub fn send_json(w: &mut impl Write, v: &serde_json::Value) -> io::Result<()> {
    let mut buf = serde_json::to_vec(v)?;
    buf.push(b'\n');
    w.write_all(&buf)?;
    w.flush()
}

/// Reads one JSON line. Returns None on EOF.
pub fn recv_json(r: &mut impl BufRead) -> Result<Option<serde_json::Value>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&line)?))
}

/// Retries `f` until it succeeds or `timeout` elapses.
pub fn retry<T>(timeout: Duration, mut f: impl FnMut() -> Result<T>) -> Result<T> {
    let start = Instant::now();
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) if start.elapsed() >= timeout => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_micros(200)),
        }
    }
}

/// Connects to `addr`, trying each address it resolves to within one deadline.
pub fn connect(addr: &str, timeout: Duration) -> io::Result<std::net::TcpStream> {
    use std::net::ToSocketAddrs;
    let deadline = Instant::now() + timeout;
    let mut last = io::Error::other(format!("{addr} resolves to no address"));
    for a in addr.to_socket_addrs()? {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match std::net::TcpStream::connect_timeout(&a, left) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Connects to the unix socket at `path` within `timeout`, with reads and
/// writes on it timing out after `timeout` too. (A blocking connect waits
/// for as long as the listener's backlog stays full.)
pub fn connect_unix(path: &std::path::Path, timeout: Duration) -> io::Result<UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    let deadline = Instant::now() + timeout;
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= sa.sun_path.len() {
        return Err(io::Error::other("socket path too long"));
    }
    for (d, s) in sa.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
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
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    Ok(s)
}

/// A pidfd for `pid`: it keeps naming that process even once the pid is reused.
pub fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// SIGKILLs the process behind `pidfd`; one that already exited is fine.
pub fn pidfd_kill(pidfd: &OwnedFd) -> io::Result<()> {
    let null = std::ptr::null::<libc::siginfo_t>();
    if unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), libc::SIGKILL, null, 0) } < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(e);
        }
    }
    Ok(())
}

/// Waits up to `timeout` for the process behind `pidfd` to exit.
pub fn pidfd_wait(pidfd: &OwnedFd, timeout: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd { fd: pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    match unsafe { libc::poll(&mut pfd, 1, timeout.as_millis().min(i32::MAX as u128) as i32) } {
        n if n < 0 => Err(io::Error::last_os_error()),
        n => Ok(n > 0),
    }
}

pub fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1e5).round() / 100.0
}

/// Back-to-back phase timings: each mark covers the time since the previous
/// one, so the phases sum to the total.
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

    /// Ends phase `name` now and returns its length.
    pub fn mark(&mut self, name: &str) -> Duration {
        let now = Instant::now();
        let d = now - self.last;
        self.last = now;
        self.marks.insert(name.into(), ms(d).into());
        d
    }

    /// Time from the start to the last mark.
    pub fn total(&self) -> Duration {
        self.last - self.start
    }

    pub fn json(&self) -> serde_json::Value {
        let mut marks = self.marks.clone();
        marks.insert("total".into(), ms(self.total()).into());
        marks.into()
    }
}

/// Reads a `Key: value kB` field from a /proc style file, in bytes.
pub fn proc_kb(path: &str, key: &str) -> Option<u64> {
    let s = std::fs::read_to_string(path).ok()?;
    s.lines()
        .find(|l| l.starts_with(key) && l[key.len()..].starts_with(':'))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|kb| kb * 1024)
}

pub fn host_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}
