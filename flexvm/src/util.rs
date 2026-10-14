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

pub fn send_json(w: &mut impl Write, v: &serde_json::Value) -> io::Result<()> {
    let mut buf = serde_json::to_vec(v)?;
    buf.push(b'\n');
    w.write_all(&buf)?;
    w.flush()
}

/// Room for an exec command of the guest's 1 MiB limit even when escaping inflates it.
const MAX_LINE: u64 = 8 << 20;

/// None on EOF.
pub fn recv_json(r: &mut impl BufRead) -> Result<Option<serde_json::Value>> {
    recv_json_max(r, MAX_LINE)
}

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

/// Splits the timeout across the addresses so a blackholed one cannot use it all.
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

pub trait Timed: Read + Write {
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
timed!(std::net::TcpStream, &std::net::TcpStream, UnixStream);

/// Every read and write (each partial one) ends by `at`, however slowly the peer trickles.
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

/// Reads and writes time out after `timeout` too. (A blocking connect waits for as long
/// as the listener's backlog stays full.)
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
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    Ok(s)
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

pub fn pidfd_wait(pidfd: &OwnedFd, timeout: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd { fd: pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let end = Instant::now() + timeout;
    let left = || end.saturating_duration_since(Instant::now()).as_millis().min(i32::MAX as u128) as i32;
    Ok(eintr(|| unsafe { libc::poll(&mut pfd, 1, left()) })? > 0)
}

/// After a failed `accept`: one worth retrying at once (interrupted, the
/// peer gone) returns; anything else (out of fds) waits rather than spins.
pub fn accept_failed(what: &str, e: &io::Error) {
    if !matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted) {
        eprintln!("{what}: accept: {e}");
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

/// Fsyncs every parent each time: a crash may have lost an entry made before, or another
/// process made it without syncing.
pub fn create_dir_durably(dir: &std::path::Path) -> io::Result<()> {
    create_dir_durably_mode(dir, 0o777)
}

pub fn create_dir_durably_mode(dir: &std::path::Path, mode: u32) -> io::Result<()> {
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
    let n = eintr(|| unsafe { libc::sendmsg(s.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) })? as usize;
    if n < line.len() {
        (&*s).write_all(&line[n..])?;
    }
    Ok(())
}

/// The peer must send nothing after the line until it has an answer.
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
        let n = eintr(|| unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) })?;
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

pub fn wait_signal(set: &libc::sigset_t) -> i32 {
    let mut sig = 0;
    while unsafe { libc::sigwait(set, &mut sig) } != 0 {}
    sig
}

/// In a session of its own (it outlives the caller), with `fd3` as its fd 3.
pub fn spawn_self<S: AsRef<std::ffi::OsStr>>(args: &[S], log: &std::fs::File, fd3: RawFd, env: &[(&str, &str)]) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("/proc/self/exe");
    cmd.args(args).envs(env.iter().copied()).stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log.try_clone()?);
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            // dup2 onto itself would leave it close-on-exec.
            let moved = if fd3 == 3 { libc::fcntl(3, libc::F_SETFD, 0) } else { libc::dup2(fd3, 3) };
            if moved < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    std::thread::spawn(move || child.wait());
    Ok(())
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
        let mut line = vec![b' '; MAX_LINE as usize + 100];
        line.extend_from_slice(b"2\n");
        assert_eq!(recv_json_max(&mut io::Cursor::new(line), 2 * MAX_LINE).unwrap(), Some(2.into()));
    }

    #[test]
    fn state_and_suspended_directories_are_private() {
        let root = std::env::temp_dir().join(format!("flexvm-private-{}", std::process::id()));
        let dir = root.join("state/suspended");
        create_dir_durably_mode(&dir, 0o700).unwrap();
        for path in [&root, &root.join("state"), &dir] {
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o700);
        }
        create_dir_durably_mode(&dir, 0o700).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}

/// A VM process's stdout and stderr: pipes that relay threads copy to the
/// terminal (or the claimer's, `retarget`). A target that fails or does not
/// take output within `STALL` (a closed terminal, a broken or stalled pipe)
/// is given up for the VM's log file, so printing never fails, never aborts
/// the VM and never holds it up for long; nothing is locked across a write.
pub mod output {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    const STALL: Duration = Duration::from_secs(1);
    static TARGETS: Mutex<[Option<Arc<File>>; 2]> = Mutex::new([None, None]);
    static LOG: Mutex<Option<PathBuf>> = Mutex::new(None);
    static RELAYS: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());

    pub fn guard() -> std::io::Result<()> {
        for (i, fd) in [1, 2].into_iter().enumerate() {
            let mut p = [0; 2];
            let orig = super::eintr(|| unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) })?;
            super::eintr(|| unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) })?;
            super::eintr(|| unsafe { libc::dup2(p[1], fd) })?;
            unsafe { libc::close(p[1]) };
            TARGETS.lock().unwrap()[i] = Some(Arc::new(unsafe { File::from_raw_fd(orig) }));
            let mut from = unsafe { File::from_raw_fd(p[0]) };
            RELAYS.lock().unwrap().push(std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                while let Ok(n @ 1..) = from.read(&mut buf) {
                    relay(i, &buf[..n]);
                }
            }));
        }
        Ok(())
    }

    fn relay(i: usize, data: &[u8]) {
        let target = TARGETS.lock().unwrap()[i].clone();
        let sent = target.as_ref().map_or(0, |t| write_within(t, data, Instant::now() + STALL));
        if sent == data.len() {
            return;
        }
        // Given up, unless a retarget replaced it meanwhile.
        let log = || LOG.lock().unwrap().as_ref().and_then(|p| File::options().create(true).append(true).open(p).ok()).map(Arc::new);
        let fallback = {
            let mut targets = TARGETS.lock().unwrap();
            if targets[i].as_ref().map(Arc::as_ptr) == target.as_ref().map(Arc::as_ptr) {
                targets[i] = log();
            }
            targets[i].clone()
        };
        if let Some(mut f) = fallback.as_deref() {
            let _ = f.write_all(&data[sent..]);
        }
    }

    /// What was written by `deadline`: in pieces no bigger than a pipe takes
    /// at once, each only once the target is ready for it.
    fn write_within(f: &File, data: &[u8], deadline: Instant) -> usize {
        let mut sent = 0;
        while sent < data.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            let mut p = libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
            if left.is_zero() || unsafe { libc::poll(&mut p, 1, left.as_millis().max(1) as i32) } <= 0 || p.revents & libc::POLLOUT == 0 {
                break;
            }
            let piece = &data[sent..(sent + 4096).min(data.len())];
            match unsafe { libc::write(f.as_raw_fd(), piece.as_ptr().cast(), piece.len()) } {
                n if n > 0 => sent += n as usize,
                _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
                _ => break,
            }
        }
        sent
    }

    /// Where output goes once the terminal is gone.
    pub fn fall_back_to(log: PathBuf) {
        *LOG.lock().unwrap() = Some(log);
    }

    /// A claimed standby's output goes to its claimer's terminal.
    pub fn retarget(fds: [RawFd; 2]) {
        let mut targets = TARGETS.lock().unwrap();
        for (i, fd) in fds.into_iter().enumerate() {
            if let Ok(dup) = super::eintr(|| unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) }) {
                targets[i] = Some(Arc::new(unsafe { File::from_raw_fd(dup) }));
            }
        }
    }

    /// Before exit, bounded by a second from the start: what was printed
    /// reaches its target if it can. No output lock is taken (a thread may
    /// hold stdout's for good); what std still buffers, exit flushes if free.
    pub fn drain() {
        let deadline = Instant::now() + STALL;
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
}
