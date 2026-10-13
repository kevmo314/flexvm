use std::io::{self, BufRead, Read, Write};
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

/// Longest JSON line `recv_json` accepts: room for an exec command of the
/// guest's 1 MiB limit even when escaping inflates it.
const MAX_LINE: u64 = 8 << 20;

/// Reads one JSON line. Returns None on EOF.
pub fn recv_json(r: &mut impl BufRead) -> Result<Option<serde_json::Value>> {
    recv_json_max(r, MAX_LINE)
}

/// Reads one JSON line of at most `max` bytes. Returns None on EOF.
pub fn recv_json_max(r: &mut impl BufRead, max: u64) -> Result<Option<serde_json::Value>> {
    let mut line = String::new();
    if r.take(max).read_line(&mut line)? == 0 {
        return Ok(None);
    }
    if line.len() as u64 == max && !line.ends_with('\n') {
        bail!("JSON line exceeds limit of {max} bytes");
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

/// Connects to `addr` within `timeout`, splitting what is left of it evenly
/// across the addresses not tried yet, so a blackholed one cannot use it all.
pub fn connect(addr: &str, timeout: Duration) -> io::Result<std::net::TcpStream> {
    use std::net::ToSocketAddrs;
    let deadline = Instant::now() + timeout;
    let addrs: Vec<_> = addr.to_socket_addrs()?.collect();
    let mut last = io::Error::other(format!("{addr} resolves to no address"));
    for (i, a) in addrs.iter().enumerate() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match std::net::TcpStream::connect_timeout(a, left / (addrs.len() - i) as u32) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// A socket whose timeouts can be set per operation.
pub trait Timed: Read + Write {
    fn read_timeout(&self, t: Duration) -> io::Result<()>;
    fn write_timeout(&self, t: Duration) -> io::Result<()>;
}

impl Timed for std::net::TcpStream {
    fn read_timeout(&self, t: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(t))
    }
    fn write_timeout(&self, t: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(t))
    }
}

impl Timed for UnixStream {
    fn read_timeout(&self, t: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(t))
    }
    fn write_timeout(&self, t: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(t))
    }
}

/// `s`, with every read and write (each partial one) ending by `at`,
/// however slowly the other end trickles.
pub struct By<S> {
    pub s: S,
    pub at: Instant,
}

impl<S> By<S> {
    fn left(&self) -> io::Result<Duration> {
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

impl<S: Timed> Read for By<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.s.read_timeout(self.left()?)?;
        self.s.read(buf).map_err(timed_out)
    }
}

impl<S: Timed> Write for By<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.s.write_timeout(self.left()?)?;
        self.s.write(buf).map_err(timed_out)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.s.flush()
    }
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
    crate::socket::check(path)?;
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

/// Creates `dir` and any missing parents, and fsyncs every parent along the
/// way (each time, as a crash may have lost an entry made before, or another
/// process made it without syncing), so the hierarchy survives a power loss.
/// Errors name the directory.
pub fn create_dir_durably(dir: &std::path::Path) -> io::Result<()> {
    create_dir_durably_mode(dir, 0o777)
}

/// Creates private state directories, including missing parents.
pub fn create_private_dir_durably(dir: &std::path::Path) -> io::Result<()> {
    create_dir_durably_mode(dir, 0o700)
}

fn create_dir_durably_mode(dir: &std::path::Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let named = |p: &std::path::Path, what: &str, e: io::Error| io::Error::new(e.kind(), format!("{what} {}: {e}", p.display()));
    let dir = std::path::absolute(dir).map_err(|e| named(dir, "resolving", e))?;
    let mut path = std::path::PathBuf::from("/");
    for part in dir.components().skip(1) {
        let parent = path.clone();
        path.push(part);
        match std::fs::DirBuilder::new().mode(mode).create(&path) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(named(&path, "creating", e)),
            _ => {}
        }
        std::fs::File::open(&parent).and_then(|f| f.sync_all()).map_err(|e| named(&parent, "fsync of directory", e))?;
    }
    Ok(())
}

/// Sends `line` (one JSON request line) on `s` with `fds` attached.
pub fn send_with_fds(s: &UnixStream, line: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let mut iov = libc::iovec { iov_base: line.as_ptr() as *mut libc::c_void, iov_len: line.len() };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    let mut cbuf = vec![0u8; space];
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
    let n = loop {
        let n = unsafe { libc::sendmsg(s.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if n >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break n;
        }
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if (n as usize) < line.len() {
        (&*s).write_all(&line[n as usize..])?;
    }
    Ok(())
}

/// Reads one request line from `s`, and the fds that came with it. The
/// peer sends nothing after the line until it has an answer.
pub fn recv_with_fds(s: &UnixStream, max: usize) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut line = Vec::new();
    let mut fds = Vec::new();
    let mut buf = [0u8; 4096];
    while !line.ends_with(b"\n") {
        if line.len() > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request line too long"));
        }
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let mut cbuf = [0u8; 256];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = cbuf.len() as _;
        let n = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
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
        if n == 0 {
            break;
        }
        line.extend_from_slice(&buf[..n as usize]);
    }
    Ok((line, fds))
}

/// Blocks `sigs` in this thread and every thread it starts afterwards, so
/// only `wait_signal` sees them.
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

pub fn wait_signal(set: &libc::sigset_t) -> i32 {
    let mut sig = 0;
    while unsafe { libc::sigwait(set, &mut sig) } != 0 {}
    sig
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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
        // Callers that expect more (migration headers) raise the limit.
        let mut line = vec![b' '; MAX_LINE as usize + 100];
        line.extend_from_slice(b"2\n");
        assert_eq!(recv_json_max(&mut io::Cursor::new(line), 2 * MAX_LINE).unwrap(), Some(2.into()));
    }

    #[test]
    fn state_and_suspended_directories_are_private() {
        let root = std::env::temp_dir().join(format!("flexvm-private-{}", std::process::id()));
        let dir = root.join("state/suspended");
        create_private_dir_durably(&dir).unwrap();
        for path in [&root, &root.join("state"), &dir] {
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o700);
        }
        create_private_dir_durably(&dir).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
