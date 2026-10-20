//! flexvm-init, PID 1 in the guest: sets up a writable overlay on the read-only (DAX) root, then
//! serves one-line requests on vsock: `PING`, `START <ip> <secs.nanos> [dns]` (network and
//! host clock), `CLOCK <secs.nanos>`, `FORKS`, and those in session.rs and app.rs.
//! Replies are frames (proto.rs).

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

mod app;
mod input;
mod mem;
mod net;
#[allow(dead_code)]
mod proto;
mod session;
mod tar;
mod user;

use proto::{write_frame, FRAME_MSG, FRAME_STDERR, FRAME_STDOUT, MAX_BODY, TRY_AGAIN};

const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// CHECK hex-encodes a command of up to MAX_BODY bytes on its request line.
const MAX_LINE: u64 = 2 * MAX_BODY as u64 + 128;
const MAX_BODY_READERS: usize = 16;
static BODY_READERS: AtomicUsize = AtomicUsize::new(0);

/// Children someone waits for.
type Statuses = Arc<(Mutex<Children>, Condvar)>;

/// Spawned children by pid until reaped, then their exit codes by token. A pid can be reused once
/// its child is reaped; a token never is, so a newer child (or an orphan reaped under the same pid)
/// cannot touch an older one's status.
#[derive(Default)]
struct Children {
    running: HashMap<i32, u64>,
    finished: HashMap<u64, i32>,
}

impl Children {
    /// Records a reaped child's exit, if it is one of ours (orphans are not).
    fn reaped(&mut self, pid: i32, code: i32) -> bool {
        self.running.remove(&pid).map(|token| self.finished.insert(token, code)).is_some()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.running.is_empty() && self.finished.is_empty()
    }
}

static TOKENS: AtomicU64 = AtomicU64::new(1);

fn main() {
    // `cp`'s tar ends, run in a session as /proc/self/exe.
    if let Some(code) = tar::tool_main(&std::env::args().skip(1).collect::<Vec<_>>()) {
        std::process::exit(code);
    }
    if unsafe { libc::getpid() } == 1 {
        if let Err(e) = setup_root() {
            log(&format!("root setup failed: {e}"));
        }
        if let Err(e) = net::setup() {
            log(&format!("network setup failed: {e}"));
        }
        mem::start();
    }
    app::init();
    let statuses = Statuses::default();
    let reaped = statuses.clone();
    thread::spawn(move || reap(reaped));
    log("ready");
    if let Err(e) = serve(statuses) {
        log(&format!("vsock server failed: {e}"));
    }
    loop {
        unsafe { libc::pause() };
    }
}

fn log(msg: &str) {
    let _ = writeln!(io::stderr(), "flexvm-init: {msg}");
}

fn os<T: Default + PartialOrd>(rc: T) -> io::Result<T> {
    if rc < T::default() {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

fn mount(src: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> io::Result<()> {
    let c = |s: &str| CString::new(s).unwrap();
    let (src_c, target_c, fstype_c, data_c) = (c(src), c(target), c(fstype), c(data));
    let fstype = if fstype.is_empty() { std::ptr::null() } else { fstype_c.as_ptr() };
    match os(unsafe { libc::mount(src_c.as_ptr(), target_c.as_ptr(), fstype, flags, data_c.as_ptr().cast()) }) {
        Err(e) if e.raw_os_error() != Some(libc::EBUSY) => Err(io::Error::new(e.kind(), format!("mount {target}: {e}"))),
        _ => Ok(()),
    }
}

/// Overlayfs takes the merged root's attributes from the upper directory. Xattrs are best-effort:
/// tmpfs may lack a namespace (user.* before 6.6, ACLs without TMPFS_POSIX_ACL, which our kernel
/// has), and overlayfs's own trusted.overlay.* would change how the upper root is read.
fn copy_root_metadata(lower: &str, upper: &str) -> io::Result<()> {
    let lower = File::open(lower)?;
    let upper = File::open(upper)?;
    let meta = lower.metadata()?;
    let (src, dst) = (lower.as_raw_fd(), upper.as_raw_fd());
    let mode = |m: u32| upper.set_permissions(std::fs::Permissions::from_mode(m));
    // With an access ACL, the group bits are its mask: alone they could grant the owning group
    // what the ACL denied, so a root whose ACL is not copied gets no group access at all.
    let no_acl = || {
        log("root ACL not copied: dropping group access to /");
        mode(meta.mode() & 0o7707)
    };
    os(unsafe { libc::fchown(dst, meta.uid(), meta.gid()) })?;
    mode(meta.mode() & 0o7777)?;
    let names = (|| {
        let n = os(unsafe { libc::flistxattr(src, std::ptr::null_mut(), 0) })?;
        let mut names = vec![0u8; n as usize];
        let n = os(unsafe { libc::flistxattr(src, names.as_mut_ptr().cast(), names.len()) })?;
        names.truncate(n as usize);
        Ok::<_, io::Error>(names)
    })();
    let names = match names {
        Ok(names) => names,
        Err(e) => {
            log(&format!("root xattrs: {e}"));
            return no_acl();
        }
    };
    for name in names.split_inclusive(|&b| b == 0) {
        let name = CStr::from_bytes_with_nul(name).map_err(io::Error::other)?;
        if name.to_bytes().starts_with(b"trusted.overlay.") {
            continue;
        }
        let copied = (|| {
            let n = os(unsafe { libc::fgetxattr(src, name.as_ptr(), std::ptr::null_mut(), 0) })?;
            let mut value = vec![0u8; n as usize];
            let n = os(unsafe { libc::fgetxattr(src, name.as_ptr(), value.as_mut_ptr().cast(), value.len()) })?;
            os(unsafe { libc::fsetxattr(dst, name.as_ptr(), value.as_ptr().cast(), n as usize, 0) })
        })();
        if let Err(e) = copied {
            log(&format!("root xattr {}: {e}", name.to_string_lossy()));
            if name == c"system.posix_acl_access" {
                no_acl()?;
            }
        }
    }
    Ok(())
}

/// Pivots into an overlay whose tmpfs upper layer keeps guest writes in RAM, so they migrate.
fn setup_root() -> io::Result<()> {
    mount("proc", "/proc", "proc", 0, "")?;
    mount("sysfs", "/sys", "sysfs", 0, "")?;
    mount("devtmpfs", "/dev", "devtmpfs", 0, "")?;
    // tmpfs sizes to half of RAM at mount time and memory is hotplugged later: leave it unbounded.
    mount("tmpfs", "/run", "tmpfs", 0, "mode=755,size=0")?;
    for d in ["/run/ovl/upper", "/run/ovl/work", "/run/root"] {
        std::fs::create_dir_all(d)?;
    }
    if let Err(e) = copy_root_metadata("/", "/run/ovl/upper") {
        log(&format!("root metadata: {e}"));
    }
    mount("overlay", "/run/root", "overlay", 0, "lowerdir=/,upperdir=/run/ovl/upper,workdir=/run/ovl/work")?;
    for d in ["/proc", "/sys", "/dev"] {
        mount(d, &format!("/run/root{d}"), "", libc::MS_MOVE, "")?;
    }
    std::env::set_current_dir("/run/root")?;
    std::fs::create_dir_all("/run/root/mnt/oldroot")?;
    os(unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c"mnt/oldroot".as_ptr()) })?;
    std::env::set_current_dir("/")?;
    unsafe { libc::umount2(c"/mnt/oldroot".as_ptr(), libc::MNT_DETACH) };
    mount("tmpfs", "/run", "tmpfs", 0, "mode=755,size=0")?;
    mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777,size=0")?;
    std::fs::create_dir_all("/dev/pts")?;
    mount("devpts", "/dev/pts", "devpts", 0, "")?;
    std::fs::create_dir_all("/dev/shm")?;
    mount("tmpfs", "/dev/shm", "tmpfs", 0, "size=0")?;
    // devtmpfs lacks these; images log to /dev/stdout (nginx) and the like.
    for (link, target) in [("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"), ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2")] {
        let _ = std::os::unix::fs::symlink(target, format!("/dev/{link}"));
    }
    unsafe { libc::sethostname(c"flexvm".as_ptr(), 6) };
    std::env::set_var("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    std::env::set_var("HOME", "/root");
    Ok(())
}

/// Reaps every child (orphans too, as PID 1), recording the exit codes `spawn` registered.
fn reap(statuses: Statuses) {
    let (lock, cv) = &*statuses;
    loop {
        let mut map = lock.lock().unwrap();
        let mut status = 0;
        // Checked under the lock `spawn` holds, so a new child cannot be missed.
        let mut pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid == 0 {
            drop(map);
            // Waits without consuming the exit: std may still be waiting for a
            // child whose exec failed inside `spawn`, holding our lock.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let waited = os(unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOWAIT) });
            map = lock.lock().unwrap();
            match waited.map_err(|e| e.raw_os_error()) {
                Ok(_) => pid = unsafe { libc::waitpid(info.si_pid(), &mut status, libc::WNOHANG) },
                Err(Some(libc::ECHILD)) => {
                    drop(cv.wait(map).unwrap());
                    continue;
                }
                Err(Some(libc::EINTR)) => continue,
                Err(_) => return,
            }
            // `spawn` may already have consumed this failed-exec child.
            if pid <= 0 {
                continue;
            }
        }
        match os(pid).map_err(|e| e.raw_os_error()) {
            Err(Some(libc::ECHILD)) => drop(cv.wait(map).unwrap()),
            Err(Some(libc::EINTR)) => {}
            Err(_) => return,
            Ok(pid) => {
                let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 128 + libc::WTERMSIG(status) };
                if map.reaped(pid, code) {
                    cv.notify_all();
                }
            }
        }
    }
}

/// Also returns the child's token in `Statuses` and, with `pidfd`, a pidfd for it (None if the
/// kernel has none), opened before the reaper can reap it, so it never names a reused pid.
fn spawn_watched(command: &mut Command, statuses: &Statuses, pidfd: bool) -> io::Result<(Child, Option<OwnedFd>, u64)> {
    let (lock, cv) = &**statuses;
    // Held through spawn and registration, even if the child exits at once.
    let mut map = lock.lock().unwrap();
    let child = command.spawn()?;
    let fd = pidfd.then(|| unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) as RawFd });
    let fd = fd.filter(|&fd| fd >= 0).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    let token = TOKENS.fetch_add(1, Ordering::Relaxed);
    map.running.insert(child.id() as i32, token);
    cv.notify_all();
    Ok((child, fd, token))
}

/// Waits for the exit of the child `spawn_watched` gave `token`.
fn wait_exit(statuses: &Statuses, token: u64, deadline: Option<Instant>) -> Option<i32> {
    let (lock, cv) = &**statuses;
    let mut map = lock.lock().unwrap();
    loop {
        if let Some(code) = map.finished.remove(&token) {
            return Some(code);
        }
        map = match deadline.map(|d| d.saturating_duration_since(Instant::now())) {
            None => cv.wait(map).unwrap(),
            Some(left) if left.is_zero() => return None,
            Some(left) => cv.wait_timeout(map, left).unwrap().0,
        };
    }
}

/// Sends `sig` to `pid` (its process group with `group`) only while it is still `token`'s unreaped
/// child, checked under the reaper's lock: once reaped, its pid (and an emptied group's id) may be
/// another process's. Returns whether it was sent.
fn kill_running(statuses: &Statuses, pid: i32, token: u64, group: bool, sig: libc::c_int) -> bool {
    let map = statuses.0.lock().unwrap();
    if pid <= 0 || map.running.get(&pid) != Some(&token) {
        return false;
    }
    unsafe { libc::kill(if group { -pid } else { pid }, sig) == 0 }
}

/// A child's output pipes, by frame kind.
fn outputs(child: &mut Child) -> Vec<(File, u8)> {
    let out = child.stdout.take().map(|s| (File::from(OwnedFd::from(s)), FRAME_STDOUT));
    out.into_iter().chain(child.stderr.take().map(|s| (File::from(OwnedFd::from(s)), FRAME_STDERR))).collect()
}

/// Pumps output (`outputs`, or a pty's master) until EOF or, once `exited` (a pidfd) is readable, `drain`
/// more: background processes may hold the pipes open for good. `deliver` returns how long it waited
/// for its reader, which is not counted. Returns the pipes still open.
fn pump_until(mut streams: Vec<(File, u8)>, mut exited: Option<OwnedFd>, drain: Duration, mut deliver: impl FnMut(u8, &[u8]) -> Duration) -> Vec<File> {
    let mut buf = [0; 16 * 1024];
    let mut left: Option<Duration> = None;
    while !streams.is_empty() {
        let mut fds: Vec<_> = streams.iter().map(|(f, _)| libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLIN, revents: 0 }).collect();
        if let Some(fd) = &exited {
            fds.push(libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        let timeout = left.map_or(-1, |l| l.as_millis().clamp(1, i32::MAX as u128) as i32);
        let start = Instant::now();
        let (mut waited, mut fired) = (Duration::ZERO, false);
        let polled = os(unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) });
        match polled {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
            Ok(_) => {
                if exited.is_some() && fds.pop().is_some_and(|p| p.revents != 0) {
                    (exited, left, fired) = (None, Some(drain), true);
                }
                for i in (0..fds.len()).rev().filter(|&i| fds[i].revents != 0) {
                    match streams[i].0.read(&mut buf) {
                        Ok(0) => drop(streams.remove(i)),
                        Ok(n) => waited += deliver(streams[i].1, &buf[..n]),
                        // A pty's master is non-blocking, for its writer.
                        Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) => {}
                        Err(_) => drop(streams.remove(i)),
                    }
                }
            }
        }
        if let Some(l) = left.as_mut().filter(|_| !fired) {
            *l = l.saturating_sub(start.elapsed().saturating_sub(waited));
            if l.is_zero() {
                break;
            }
        }
    }
    streams.into_iter().map(|(f, _)| f).collect()
}

/// Pipes the discarder keeps at most: 2 fds each, so a flood of finished execs whose background
/// processes hold their output cannot use up flexvm-init's fds. Past it a newly finished exec's pipes
/// are closed instead (their writers then get SIGPIPE): the jobs started earlier keep working.
const MAX_DISCARDED: usize = 256;

/// Reads and drops whatever comes down its pipes until each one's EOF, on one thread for all.
struct Discarder {
    cap: usize,
    /// Pipes kept: being read, or queued for the thread.
    held: AtomicUsize,
    queue: Mutex<Vec<File>>,
    wake: File,
}

impl Discarder {
    fn start(cap: usize) -> io::Result<Arc<Discarder>> {
        let mut fds = [0; 2];
        os(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) })?;
        let (woken, wake) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
        let d = Arc::new(Discarder { cap, held: AtomicUsize::new(0), queue: Mutex::new(Vec::new()), wake });
        let run = d.clone();
        thread::Builder::new().spawn(move || run.run(woken))?;
        Ok(d)
    }

    /// Takes as many of `pipes` as fit under the cap; returns how many it closed instead.
    fn add(&self, mut pipes: Vec<File>) -> usize {
        let want = pipes.len();
        let room = self.held.fetch_update(Ordering::AcqRel, Ordering::Acquire, |h| Some(h + want.min(self.cap.saturating_sub(h)))).unwrap();
        let took = want.min(self.cap.saturating_sub(room));
        let refused = pipes.split_off(took).len();
        if took > 0 {
            self.queue.lock().unwrap().extend(pipes);
            let _ = (&self.wake).write(&[1]);
        }
        refused
    }

    fn run(&self, mut woken: File) {
        let mut pipes: Vec<File> = Vec::new();
        let mut buf = [0; 16 * 1024];
        loop {
            let mut fds: Vec<_> = std::iter::once(&woken).chain(&pipes).map(|f| libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLIN, revents: 0 }).collect();
            if os(unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) }).is_err() {
                continue;
            }
            for i in (1..fds.len()).rev().filter(|&i| fds[i].revents != 0) {
                match pipes[i - 1].read(&mut buf) {
                    Ok(n) if n > 0 => continue,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted || e.kind() == io::ErrorKind::WouldBlock => continue,
                    _ => {}
                }
                drop(pipes.swap_remove(i - 1));
                self.held.fetch_sub(1, Ordering::AcqRel);
            }
            if fds[0].revents != 0 {
                while woken.read(&mut buf).is_ok_and(|n| n > 0) {}
                pipes.append(&mut self.queue.lock().unwrap());
            }
        }
    }
}

static DISCARDER: std::sync::OnceLock<Option<Arc<Discarder>>> = std::sync::OnceLock::new();

/// Hands a finished exec's still-open pipes to the discarder (closed if it is full or cannot start).
fn discard(pipes: Vec<File>) {
    if pipes.is_empty() {
        return;
    }
    let n = pipes.len();
    let refused = DISCARDER.get_or_init(|| Discarder::start(MAX_DISCARDED).ok()).as_ref().map_or(n, |d| d.add(pipes));
    if refused > 0 {
        eprintln!("flexvm-init: closed {refused} output pipe(s) still held by a finished exec's background processes: {MAX_DISCARDED} are kept at most");
    }
}

fn accept_delay(backoff: &mut Duration) -> Duration {
    *backoff = if backoff.is_zero() { Duration::from_millis(10) } else { (*backoff * 2).min(Duration::from_secs(1)) };
    *backoff
}

fn vsock_addr(cid: u32, port: u32) -> libc::sockaddr_vm {
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    (addr.svm_family, addr.svm_port, addr.svm_cid) = (libc::AF_VSOCK as _, port, cid);
    addr
}

fn vsock_socket() -> io::Result<OwnedFd> {
    Ok(unsafe { OwnedFd::from_raw_fd(os(libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0))?) })
}

fn serve(statuses: Statuses) -> io::Result<()> {
    let fd = vsock_socket()?;
    let addr = vsock_addr(libc::VMADDR_CID_ANY, proto::PORT);
    os(unsafe { libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_vm).cast(), std::mem::size_of_val(&addr) as _) })?;
    os(unsafe { libc::listen(fd.as_raw_fd(), 64) })?;
    let sessions = session::Sessions::default();
    let (swept, statuses_) = (sessions.clone(), statuses.clone());
    session::start_clock();
    thread::spawn(move || loop {
        thread::sleep(session::sweep_every());
        session::cleanup(&swept, &statuses_);
    });
    let mut backoff = Duration::ZERO;
    loop {
        let mut peer: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut peer_len = std::mem::size_of_val(&peer) as libc::socklen_t;
        let conn = match os(unsafe { libc::accept4(fd.as_raw_fd(), (&mut peer as *mut libc::sockaddr_vm).cast(), &mut peer_len, libc::SOCK_CLOEXEC) }) {
            Ok(conn) => conn,
            // A client gone before accept, or a signal, says nothing about resources.
            Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted) => continue,
            Err(e) => {
                if backoff.is_zero() {
                    log(&format!("vsock accept failed: {e}; backing off"));
                }
                thread::sleep(accept_delay(&mut backoff));
                continue;
            }
        };
        backoff = Duration::ZERO;
        let stream = unsafe { File::from_raw_fd(conn) };
        if !host_peer(&peer, peer_len) {
            continue;
        }
        // The host sends its request with the connection; don't let a silent one stall accepting.
        sock_timeout(conn, libc::SO_RCVTIMEO, Some(Duration::from_secs(1)));
        let Ok(mut r) = stream.try_clone().map(BufReader::new) else { continue };
        let line = match request_line(&mut r) {
            Ok(line) => line,
            Err(e) => {
                let _ = fail(&stream, e);
                continue;
            }
        };
        // START is on every start's critical path, where a new thread costs ms: quick requests are answered inline.
        if ["PING", "START ", "CLOCK ", "FORKS", "HOSTNAME "].iter().any(|v| line.starts_with(v)) {
            let _ = handle(&stream, &line, &statuses);
            continue;
        }
        let (statuses, sessions) = (statuses.clone(), sessions.clone());
        let at = Instant::now() + BODY_TIMEOUT;
        // Out of threads: drop this connection (closing it) rather than abort PID 1.
        let _ = thread::Builder::new().spawn(move || {
            match line.split_whitespace().next() {
                Some("SESSIONS") => return drop(msg(&stream, session::counts(&sessions))),
                Some("SESSION" | "ARGV" | "ATTACH" | "REJOIN" | "CLOSE" | "RELEASE") => {}
                // Its input may have come with the request, read ahead into `r`.
                Some("APPIN") => return drop(app::appin(line.trim_end().split_once(' ').map_or("", |(_, a)| a), &stream, r.buffer())),
                _ => return drop(handle(&stream, &line, &statuses)),
            }
            // A session's command arrives a round trip later, which a guest faulting in memory can stretch past a second.
            let body = match session::parse(&line) {
                Ok(session::Request::Start { len, .. }) => match BodyReader::admit() {
                    Some(_reader) => read_body(&mut r, conn, len, at),
                    None => Err(io::Error::other(busy())),
                },
                _ => Ok(Vec::new()),
            };
            // After the command, input an interactive session's client sent at once (read ahead into `r`) is its feeder's.
            let body = body.map(|mut body| {
                body.extend_from_slice(r.buffer());
                body
            });
            // Kept by the session, so that a later ATTACH can shut this one down.
            let _ = match body.and_then(|body| Ok((body, stream.try_clone()?))) {
                Ok((body, conn)) => session::handle(&stream, &body, Some(conn), &line, &sessions, &statuses),
                Err(e) => fail(&stream, e),
            };
        });
    }
}

/// Sets a socket's SO_RCVTIMEO or SO_SNDTIMEO; None: none, its reads (writes) wait however long it takes.
fn sock_timeout(fd: RawFd, opt: libc::c_int, t: Option<Duration>) {
    // 0 is none: a timeout is at least 1 us.
    let t = t.map_or(Duration::ZERO, |t| t.max(Duration::from_micros(1)));
    let tv = libc::timeval { tv_sec: t.as_secs() as _, tv_usec: t.subsec_micros() as _ };
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, opt, (&tv as *const libc::timeval).cast(), std::mem::size_of_val(&tv) as _) };
}

/// Refused while `MAX_BODY_READERS` commands are still arriving: the host waits for a slot.
fn busy() -> String {
    format!("too many commands arriving at once{TRY_AGAIN}")
}

struct BodyReader;

impl BodyReader {
    fn admit() -> Option<BodyReader> {
        // Counted from here: dropped when refused, it gives the slot back.
        let slot = BodyReader;
        (BODY_READERS.fetch_add(1, Ordering::SeqCst) < MAX_BODY_READERS).then_some(slot)
    }
}

impl Drop for BodyReader {
    fn drop(&mut self) {
        BODY_READERS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The whole body must arrive by `at`, however slowly; memory grows only as bytes arrive.
fn read_body(r: &mut impl Read, fd: RawFd, len: usize, at: Instant) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    while body.len() < len {
        let left = at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "the command did not arrive in time"));
        }
        sock_timeout(fd, libc::SO_RCVTIMEO, Some(left));
        let want = (len - body.len()).min(buf.len());
        match r.read(&mut buf[..want]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(body)
}

fn msg(w: impl Write, m: impl AsRef<[u8]>) -> io::Result<()> {
    write_frame(w, FRAME_MSG, m.as_ref())
}

fn fail(w: impl Write, e: impl std::fmt::Display) -> io::Result<()> {
    msg(w, format!("error: {e}"))
}

fn handle(out: &File, line: &str, statuses: &Statuses) -> io::Result<()> {
    let line = line.trim_end();
    let (verb, arg) = line.split_once(' ').unwrap_or((line, ""));
    let mut parts = arg.split_whitespace();
    let reply = match verb {
        "PING" => Ok("pong".to_string()),
        // Acked only once the clock is set, so "ok" means it is.
        "START" => match (parts.next().map(|ip| ip.parse()), parts.next().and_then(parse_time)) {
            (Some(Ok(ip)), Some(now)) => net::configure(ip, parts.next()).map_err(|e| e.to_string()).and_then(|()| set_clock(now)).map(|_| "ok".into()),
            _ => Err(format!("bad start request {arg:?}")),
        },
        "CLOCK" => parse_time(arg.trim()).ok_or_else(|| format!("bad time {arg:?}")).and_then(set_clock).map(|off| format!("ok {off}")),
        "FORKS" => forks().map(|n| format!("ok {n}")).map_err(|e| e.to_string()),
        "HOSTNAME" => set_hostname(arg.trim()).map(|()| "ok".into()).map_err(|e| e.to_string()),
        v if app::VERBS.contains(&v) => return app::handle(v, arg, out, statuses),
        _ => return msg(out, format!("unknown request {verb:?}")),
    };
    reply.map_or_else(|e| fail(out, e), |m| msg(out, m))
}

/// The VM's name as the hostname, and as /etc/hosts' 127.0.1.1 so that it resolves (left as it is if
/// unwritable or absent). Set at each start, restore and rename: a template's snapshot has "flexvm".
fn set_hostname(name: &str) -> io::Result<()> {
    if name.is_empty() || name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        return Err(io::Error::other(format!("bad hostname {name:?}")));
    }
    os(unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) })?;
    let _ = name_in_hosts(std::path::Path::new("/etc/hosts"), name);
    Ok(())
}

/// Most of an /etc file (hosts, passwd, group) that is read.
const MAX_ETC: u64 = 1 << 20;

/// `path`'s text and metadata, if it is a regular file of at most `MAX_ETC`, opened with `flags` too (O_NOFOLLOW:
/// no link followed): anything else (a FIFO, a device) is never waited on but refused.
fn read_etc(path: &std::path::Path, flags: libc::c_int) -> io::Result<(String, std::fs::Metadata)> {
    let f = File::options().read(true).custom_flags(flags | libc::O_NONBLOCK | libc::O_NOCTTY).open(path)?;
    let meta = f.metadata()?;
    let mut text = String::new();
    if !meta.is_file() || f.take(MAX_ETC + 1).read_to_string(&mut text)? as u64 > MAX_ETC {
        return Err(io::Error::other("not a regular file of at most 1 MiB"));
    }
    Ok((text, meta))
}

/// `hosts` (`read_etc`'s, no link followed) rewritten `with_hostname`, replaced whole by a renamed copy, so a lookup
/// sees the old file or the new one.
fn name_in_hosts(hosts: &std::path::Path, name: &str) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let (old, meta) = read_etc(hosts, libc::O_NOFOLLOW)?;
    let new = with_hostname(&old, name);
    if new == old {
        return Ok(());
    }
    let tmp = hosts.with_file_name(".hosts.flexvm");
    let _ = std::fs::remove_file(&tmp);
    let res = (|| {
        // Readable by none but root until it has the original's owner and mode.
        let mut t = File::options().write(true).create_new(true).mode(0o600).open(&tmp)?;
        t.write_all(new.as_bytes())?;
        std::os::unix::fs::fchown(&t, Some(meta.uid()), Some(meta.gid()))?;
        t.set_permissions(meta.permissions())?;
        std::fs::rename(&tmp, hosts)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// `hosts` with its 127.0.1.1 lines (or a new one) naming `name` alone.
fn with_hostname(hosts: &str, name: &str) -> String {
    let line = format!("127.0.1.1\t{name}\n");
    let mut found = false;
    let mut out = String::new();
    for l in hosts.lines() {
        if l.split_whitespace().next() == Some("127.0.1.1") {
            if !found {
                out += &line;
            }
            found = true;
        } else {
            out += l;
            out.push('\n');
        }
    }
    if !found {
        out += &line;
    }
    out
}

fn parse_time(s: &str) -> Option<libc::timespec> {
    let (secs, nanos) = s.split_once('.')?;
    let nanos: i64 = nanos.parse().ok().filter(|n| (0..1_000_000_000).contains(n) && nanos.len() == 9)?;
    Some(libc::timespec { tv_sec: secs.parse().ok()?, tv_nsec: nanos as _ })
}

/// Steps CLOCK_REALTIME unless within a few ms (transit time); returns the offset (ns, guest minus `now`).
fn set_clock(now: libc::timespec) -> Result<i128, String> {
    let ns = |t: &libc::timespec| t.tv_sec as i128 * 1_000_000_000 + t.tv_nsec as i128;
    let mut cur = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut cur) };
    let off = ns(&cur) - ns(&now);
    if off.abs() >= 5_000_000 && unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &now) } != 0 {
        return Err(format!("set clock: {}", io::Error::last_os_error()));
    }
    Ok(off)
}

/// Counts the kernel's "crng reseeded due to virtual machine fork" records in the whole kmsg ring (one a read). The host checks
/// for a nonzero count, relying on cold-boot templates having none before their snapshot.
/// vmgenid sends no uevent; /dev/sysgenid isn't ordered against the reseed.
fn forks() -> io::Result<usize> {
    let mut kmsg = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open("/dev/kmsg")?;
    let (mut buf, mut n) = (vec![0u8; 8192], 0);
    loop {
        match kmsg.read(&mut buf) {
            Ok(0) => return Ok(n),
            Ok(r) => n += kernel_fork(&buf[..r]) as usize,
            // Records overwritten while reading; carry on with the next.
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(n),
            Err(e) => return Err(e),
        }
    }
}

/// A record ("PRI,SEQ,TS,FLAGS;message\n" then " KEY=value" lines) is the kernel's reseed: facility 0
/// (userspace's writes get LOG_USER at least), its whole message the one random.c logs.
fn kernel_fork(record: &[u8]) -> bool {
    const FORK_MSG: &[u8] = b"random: crng reseeded due to virtual machine fork";
    let Some(semi) = record.iter().position(|&b| b == b';') else { return false };
    let (header, msg) = (&record[..semi], &record[semi + 1..]);
    let msg = msg.split(|&b| b == b'\n').next().unwrap_or_default();
    let pri = header.split(|&b| b == b',').next().and_then(|p| std::str::from_utf8(p).ok()).and_then(|s| s.parse::<u32>().ok());
    pri.is_some_and(|p| p >> 3 == 0) && msg == FORK_MSG
}

fn host_peer(peer: &libc::sockaddr_vm, len: libc::socklen_t) -> bool {
    len as usize == std::mem::size_of_val(peer) && peer.svm_family == libc::AF_VSOCK as libc::sa_family_t && peer.svm_cid == libc::VMADDR_CID_HOST
}

fn request_line(r: &mut impl BufRead) -> io::Result<String> {
    let mut line = String::new();
    r.take(MAX_LINE).read_line(&mut line)?;
    if !line.ends_with('\n') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request line too long or incomplete"));
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    #[test]
    fn overlay_upper_keeps_lower_root_metadata() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = crate::test_util::TempDir::new("overlay-root");
        let lower = dir.join("lower");
        let upper = dir.join("upper");
        std::fs::create_dir(&lower).unwrap();
        std::fs::create_dir(&upper).unwrap();
        std::fs::set_permissions(&lower, std::fs::Permissions::from_mode(0o2750)).unwrap();
        let src = std::fs::File::open(&lower).unwrap();
        assert_eq!(unsafe { libc::fsetxattr(src.as_raw_fd(), c"user.note".as_ptr(), b"root".as_ptr().cast(), 4, 0) }, 0);
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, perm) in [(1u16, 7u16), (4, 5), (32, 0)] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&perm.to_le_bytes());
            acl.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        assert_eq!(unsafe { libc::fsetxattr(src.as_raw_fd(), c"system.posix_acl_default".as_ptr(), acl.as_ptr().cast(), acl.len(), 0) }, 0);
        super::copy_root_metadata(lower.to_str().unwrap(), upper.to_str().unwrap()).unwrap();
        let (src, dst) = (src.metadata().unwrap(), std::fs::metadata(&upper).unwrap());
        assert_eq!((dst.uid(), dst.gid(), dst.mode()), (src.uid(), src.gid(), src.mode()));
        let dst = std::fs::File::open(&upper).unwrap();
        let mut note = [0u8; 4];
        assert_eq!(unsafe { libc::fgetxattr(dst.as_raw_fd(), c"user.note".as_ptr(), note.as_mut_ptr().cast(), note.len()) }, 4);
        assert_eq!(&note, b"root");
        let mut copied = vec![0u8; acl.len()];
        assert_eq!(
            unsafe { libc::fgetxattr(dst.as_raw_fd(), c"system.posix_acl_default".as_ptr(), copied.as_mut_ptr().cast(), copied.len()) },
            acl.len() as isize
        );
        assert_eq!(copied, acl);
    }

    #[test]
    fn fork_messages_must_come_from_the_kernel() {
        for pri in 0..24 {
            let record = format!("{pri},42,123,-;random: crng reseeded due to virtual machine fork\n");
            assert_eq!(super::kernel_fork(record.as_bytes()), pri < 8);
        }
        for record in [
            "6,42,123,-;unrelated message\n",
            "crng reseeded due to virtual machine fork",
            ",42,123,-;crng reseeded due to virtual machine fork\n",
            "bad,42,123,-;crng reseeded due to virtual machine fork\n",
            "4294967296,42,123,-;random: crng reseeded due to virtual machine fork\n",
            "6,42,123,-;x: random: crng reseeded due to virtual machine fork\n",
            "6,42,123,-;random: crng reseeded due to virtual machine fork, says me\n",
            "6,42,123,-;unrelated\n SUBSYSTEM=random: crng reseeded due to virtual machine fork\n",
        ] {
            assert!(!super::kernel_fork(record.as_bytes()));
        }
    }

    #[test]
    fn hosts_name_the_vm_once() {
        let image = "127.0.0.1\tlocalhost\n::1\tlocalhost\n127.0.1.1\tflexvm\n";
        assert_eq!(super::with_hostname(image, "web"), "127.0.0.1\tlocalhost\n::1\tlocalhost\n127.0.1.1\tweb\n");
        assert_eq!(super::with_hostname("127.0.0.1 localhost", "web"), "127.0.0.1 localhost\n127.0.1.1\tweb\n");
        assert_eq!(super::with_hostname("127.0.1.1 a\n127.0.1.1 b\n", "web"), "127.0.1.1\tweb\n");
        assert!(super::set_hostname(&"x".repeat(65)).is_err() && super::set_hostname("a b").is_err());
    }

    /// Replaced whole, mode kept; a FIFO (never waited on), a link (never followed) or an endless file is refused.
    #[test]
    fn hosts_is_rewritten_only_as_a_regular_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("flexvm-hosts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let hosts = dir.join("hosts");
        std::fs::write(&hosts, "127.0.0.1\tlocalhost\n").unwrap();
        std::fs::set_permissions(&hosts, std::fs::Permissions::from_mode(0o604)).unwrap();
        super::name_in_hosts(&hosts, "web").unwrap();
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "127.0.0.1\tlocalhost\n127.0.1.1\tweb\n");
        assert_eq!(std::fs::metadata(&hosts).unwrap().permissions().mode() & 0o7777, 0o604);
        assert!(!dir.join(".hosts.flexvm").exists());

        let target = dir.join("target");
        std::fs::write(&target, "127.0.0.1\tlocalhost\n").unwrap();
        std::fs::remove_file(&hosts).unwrap();
        std::os::unix::fs::symlink(&target, &hosts).unwrap();
        assert!(super::name_in_hosts(&hosts, "web").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "127.0.0.1\tlocalhost\n");
        assert!(std::fs::symlink_metadata(&hosts).unwrap().file_type().is_symlink());

        std::fs::remove_file(&hosts).unwrap();
        let c = std::ffi::CString::new(hosts.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let start = std::time::Instant::now();
        assert!(super::name_in_hosts(&hosts, "web").is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert!(std::os::unix::fs::FileTypeExt::is_fifo(&std::fs::symlink_metadata(&hosts).unwrap().file_type()));

        std::fs::remove_file(&hosts).unwrap();
        std::fs::write(&hosts, vec![b'#'; (super::MAX_ETC + 1) as usize]).unwrap();
        assert!(super::name_in_hosts(&hosts, "web").is_err());
        assert_eq!(std::fs::metadata(&hosts).unwrap().len(), super::MAX_ETC + 1);
        // Through a link only when asked (passwd and group, as pull reads them), and then still a regular file.
        std::fs::remove_file(&hosts).unwrap();
        std::os::unix::fs::symlink(&target, &hosts).unwrap();
        assert_eq!(super::read_etc(&hosts, 0).unwrap().0, "127.0.0.1\tlocalhost\n");
        assert!(super::read_etc(&hosts, libc::O_NOFOLLOW).is_err());
        let fifo = std::ffi::CString::new(dir.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        std::fs::remove_file(&hosts).unwrap();
        std::os::unix::fs::symlink(dir.join("fifo"), &hosts).unwrap();
        assert!(super::read_etc(&hosts, 0).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn discarder_keeps_at_most_its_cap() {
        let d = Discarder::start(4).unwrap();
        let pipe = || {
            let mut fds = [0; 2];
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
        };
        let (mut writers, mut refused) = (Vec::new(), 0);
        // Three finished execs' stdout and stderr: one more than fits.
        for _ in 0..3 {
            let ((out, out_w), (err, err_w)) = (pipe(), pipe());
            refused += d.add(vec![out, err]);
            writers.extend([out_w, err_w]);
        }
        assert_eq!((refused, d.held.load(Ordering::Acquire)), (2, 4));
        // Kept pipes are drained: far more than a pipe holds goes through.
        let chunk = vec![0u8; 64 * 1024];
        for w in &mut writers[..4] {
            for _ in 0..16 {
                w.write_all(&chunk).unwrap();
            }
        }
        // Refused ones were closed (the test harness ignores SIGPIPE).
        for w in &mut writers[4..] {
            assert_eq!(w.write(b"x").unwrap_err().raw_os_error(), Some(libc::EPIPE));
        }
        // A writer's exit (EOF) makes room again.
        writers.drain(..2);
        let deadline = Instant::now() + Duration::from_secs(5);
        while d.held.load(Ordering::Acquire) > 2 {
            assert!(Instant::now() < deadline, "EOF did not free the pipes");
            thread::sleep(Duration::from_millis(10));
        }
        let ((out, _out_w), (err, _err_w)) = (pipe(), pipe());
        assert_eq!(d.add(vec![out, err]), 0);
        assert_eq!(d.held.load(Ordering::Acquire), 4);
    }

    use super::*;

    #[test]
    #[allow(clippy::zombie_processes)] // reap() consumes children; wait_exit receives their statuses.
    fn failed_exec_does_not_race_the_reaper() {
        // Isolate waitpid(P_ALL) from children of the other tests.
        const CHILD: &str = "FLEXVM_REAPER_TEST";
        if std::env::var_os(CHILD).is_none() {
            assert!(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::failed_exec_does_not_race_the_reaper"])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success());
            return;
        }
        let statuses = Statuses::default();
        let reaper = statuses.clone();
        thread::spawn(move || reap(reaper));
        let (_child, _, token) = spawn_watched(Command::new("/bin/sleep").arg("0.2"), &statuses, false).unwrap();
        // Let the reaper reach its blocking wait before failed execs exit.
        thread::sleep(Duration::from_millis(10));
        for _ in 0..200 {
            // A pre_exec makes std fork and reap a failed exec itself, as with the throttle cgroup.
            let mut missing = Command::new("/flexvm/nonexistent-executable");
            unsafe { std::os::unix::process::CommandExt::pre_exec(&mut missing, || Ok(())) };
            assert!(spawn_watched(&mut missing, &statuses, false).is_err());
        }
        assert_eq!(wait_exit(&statuses, token, None), Some(0));
        let (_child, _, token) = spawn_watched(Command::new("/bin/sh").args(["-c", "exit 7"]), &statuses, false).unwrap();
        assert_eq!(wait_exit(&statuses, token, None), Some(7));
        assert!(statuses.0.lock().unwrap().is_empty());
    }

    #[test]
    fn backoff_grows_caps_and_resets() {
        let mut backoff = Duration::ZERO;
        for ms in [10, 20, 40, 80, 160, 320, 640, 1000, 1000] {
            assert_eq!(accept_delay(&mut backoff), Duration::from_millis(ms));
        }
        backoff = Duration::ZERO;
        assert_eq!(accept_delay(&mut backoff), Duration::from_millis(10));
    }

    #[test]
    fn a_busy_refusal_carries_the_hosts_try_again_marker() {
        assert!(busy().ends_with(TRY_AGAIN));
    }

    #[test]
    fn bodies_end_by_their_deadline_and_readers_are_capped() {
        let at = Instant::now() + Duration::from_secs(5);
        assert_eq!(read_body(&mut &b"echo hi"[..], -1, 7, at).unwrap(), b"echo hi");
        assert_eq!(read_body(&mut &b"echo"[..], -1, 7, at).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let past = Instant::now() - Duration::from_millis(1);
        assert_eq!(read_body(&mut &b"echo hi"[..], -1, 7, past).unwrap_err().kind(), io::ErrorKind::TimedOut);
        let readers: Vec<_> = std::iter::from_fn(BodyReader::admit).take(MAX_BODY_READERS + 1).collect();
        assert_eq!(readers.len(), MAX_BODY_READERS);
        drop(readers);
        assert!(BodyReader::admit().is_some());
    }

    #[test]
    fn lines_are_bounded_and_large_checks_fit() {
        let mut input = io::Cursor::new(vec![b'x'; MAX_LINE as usize + 1]);
        assert!(request_line(&mut input).is_err());
        assert_eq!(input.position(), MAX_LINE);
        let line = format!("CHECK 1000 {}\n", "ab".repeat(MAX_BODY));
        assert_eq!(request_line(&mut io::Cursor::new(line.as_bytes())).unwrap(), line);
        assert!(request_line(&mut io::Cursor::new(b"PING")).is_err());
        let mut input = io::Cursor::new(b"PING\nNEXT\n");
        assert_eq!(request_line(&mut input).unwrap(), "PING\n");
        assert_eq!(input.position(), 5);
    }

    #[test]
    fn only_host_cid_is_allowed() {
        let mut peer = vsock_addr(libc::VMADDR_CID_HOST, 0);
        let len = std::mem::size_of_val(&peer) as _;
        assert!(host_peer(&peer, len));
        assert!(!host_peer(&peer, 0));
        peer.svm_cid = 3;
        assert!(!host_peer(&peer, len));
    }

    #[test]
    fn times_parse_strictly() {
        let t = parse_time("12.000000005").unwrap();
        assert_eq!((t.tv_sec, t.tv_nsec), (12, 5));
        for bad in ["12", "12.5", "12.1000000000", "x.000000000", "12.-00000001"] {
            assert!(parse_time(bad).is_none(), "{bad}");
        }
    }
}

#[cfg(test)]
#[path = "../../flexvm/src/test_util.rs"]
mod test_util;
