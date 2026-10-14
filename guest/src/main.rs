//! flexvm-init: PID 1 inside the guest.
//!
//! Sets up a writable overlay on top of the read-only (DAX) root, then serves
//! a tiny command protocol on vsock so the host can run things in the VM.
//! Requests are one text line: `PING`, `NET <ip> [dns]`, `START <ip> <secs.nanos> [dns]`
//! (NET plus the host's wall clock), `CLOCK <secs.nanos>`, `FORKS`, the session
//! requests in session.rs and the app requests in app.rs. Replies are frames
//! (see proto.rs).

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Child, ChildStderr, ChildStdout, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

mod app;
mod mem;
mod net;
#[allow(dead_code)]
mod proto;
mod session;

use proto::{FRAME_MSG, FRAME_STDERR, FRAME_STDOUT, MAX_BODY};

/// How long a command body may take to arrive, all of it.
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// CHECK hex-encodes a command of up to MAX_BODY bytes on its request line.
const MAX_LINE: u64 = 2 * MAX_BODY as u64 + 128;
/// How many command bodies may be arriving at once; more are refused.
const MAX_BODY_READERS: usize = 16;
static BODY_READERS: AtomicUsize = AtomicUsize::new(0);

/// Exit codes of children someone waits for, by pid (None while running).
type Statuses = Arc<(Mutex<HashMap<i32, Option<i32>>>, Condvar)>;

fn main() {
    if unsafe { libc::getpid() } == 1 {
        if let Err(e) = setup_root() {
            log(&format!("root setup failed: {e}"));
        }
        if let Err(e) = net::setup() {
            log(&format!("network setup failed: {e}"));
        }
        mem::start();
    }
    let statuses: Statuses = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
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

/// A syscall's result, or its error if it returned a negative value.
fn os<T: Default + PartialOrd>(rc: T) -> io::Result<T> {
    if rc < T::default() { Err(io::Error::last_os_error()) } else { Ok(rc) }
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

/// Mounts the pseudo filesystems and pivots into an overlay whose upper layer
/// is a tmpfs, so guest writes live in guest RAM and migrate with it.
fn setup_root() -> io::Result<()> {
    mount("proc", "/proc", "proc", 0, "")?;
    mount("sysfs", "/sys", "sysfs", 0, "")?;
    mount("devtmpfs", "/dev", "devtmpfs", 0, "")?;
    // tmpfs defaults to half of RAM *at mount time*; memory grows by hotplug
    // later, so leave the size unbounded and let the host decide.
    mount("tmpfs", "/run", "tmpfs", 0, "mode=755,size=0")?;
    for d in ["/run/ovl/upper", "/run/ovl/work", "/run/root"] {
        std::fs::create_dir_all(d)?;
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

/// Waits for an exit without consuming it: std may still be waiting for a
/// child whose exec failed inside spawn, while it holds our lock.
fn exited_child() -> io::Result<i32> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOWAIT) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.si_pid() })
}

/// Reaps every child (we are PID 1, so orphans land here too) and records
/// the exit codes that `spawn` registered.
fn reap(statuses: Statuses) {
    let (lock, cv) = &*statuses;
    loop {
        let mut map = lock.lock().unwrap();
        let mut status = 0;
        // Checked under the lock `spawn` holds, so a new child cannot be missed.
        let mut pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid == 0 {
            drop(map);
            pid = unsafe { libc::waitpid(-1, &mut status, 0) };
            map = lock.lock().unwrap();
            pid = unsafe { libc::waitpid(exited, &mut status, libc::WNOHANG) };
            // spawn may already have consumed this failed-exec child.
            if pid == 0 || (pid < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)) {
                continue;
            }
        }
        match os(pid).map_err(|e| e.raw_os_error()) {
            Err(Some(libc::ECHILD)) => drop(cv.wait(map).unwrap()),
            Err(Some(libc::EINTR)) => {}
            Err(_) => return,
            Ok(pid) => {
                let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 128 + libc::WTERMSIG(status) };
                if let Some(exit) = map.get_mut(&pid) {
                    *exit = Some(code);
                    cv.notify_all();
                }
            }
        }
    }
}

/// Spawns a child whose exit code `wait_pid` can collect.
fn spawn(command: &mut Command, statuses: &Statuses) -> io::Result<Child> {
    let (lock, cv) = &**statuses;
    // Held through spawn and registration, even if the child exits at once.
    let mut map = lock.lock().unwrap();
    let child = command.spawn()?;
    map.insert(child.id() as i32, None);
    cv.notify_all();
    Ok(child)
}

/// Waits for `pid`'s exit code, until `deadline` if one is given.
fn wait_pid(statuses: &Statuses, pid: i32, deadline: Option<Instant>) -> Option<i32> {
    let (lock, cv) = &**statuses;
    let mut map = lock.lock().unwrap();
    loop {
        if let Some(Some(code)) = map.get(&pid).copied() {
            map.remove(&pid);
            return Some(code);
        }
        map = match deadline.map(|d| d.saturating_duration_since(Instant::now())) {
            None => cv.wait(map).unwrap(),
            Some(left) if left.is_zero() => return None,
            Some(left) => cv.wait_timeout(map, left).unwrap().0,
        };
    }
}

/// Hands a child's stdout and stderr to `deliver` (frame kind, bytes) as they
/// come, from one thread, until both are closed.
fn pump(stdout: Option<ChildStdout>, stderr: Option<ChildStderr>, mut deliver: impl FnMut(u8, &[u8])) {
    let out = stdout.map(|s| (File::from(OwnedFd::from(s)), FRAME_STDOUT));
    let mut streams: Vec<(File, u8)> = out.into_iter().chain(stderr.map(|s| (File::from(OwnedFd::from(s)), FRAME_STDERR))).collect();
    let mut buf = [0; 16 * 1024];
    while !streams.is_empty() {
        let mut fds: Vec<_> = streams.iter().map(|(f, _)| libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLIN, revents: 0 }).collect();
        match os(unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) }) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
            Ok(_) => {}
        }
        for i in (0..fds.len()).rev().filter(|&i| fds[i].revents != 0) {
            match streams[i].0.read(&mut buf) {
                Ok(0) => drop(streams.remove(i)),
                Ok(n) => deliver(streams[i].1, &buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => drop(streams.remove(i)),
            }
        }
    }
}

/// Delay consecutive accept failures without spinning under resource pressure.
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
    let swept = sessions.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(60));
        session::cleanup(&swept);
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
        sock_timeout(conn, libc::SO_RCVTIMEO, Duration::from_secs(1));
        let Ok(mut r) = stream.try_clone().map(BufReader::new) else { continue };
        let line = match request_line(&mut r) {
            Ok(line) => line,
            Err(e) => {
                let _ = fail(&stream, e);
                continue;
            }
        };
        // START is on the critical path of every start, right after restore, when a
        // new thread costs milliseconds; the quick requests are answered right here.
        if ["PING", "NET ", "START ", "CLOCK ", "FORKS"].iter().any(|v| line.starts_with(v)) {
            let _ = handle(&stream, &line, &statuses);
            continue;
        }
        let (statuses, sessions) = (statuses.clone(), sessions.clone());
        let at = Instant::now() + BODY_TIMEOUT;
        // Out of threads: drop this connection (closing it) rather than abort PID 1.
        let _ = thread::Builder::new().spawn(move || {
            if !matches!(line.split_whitespace().next(), Some("SESSION" | "ATTACH" | "CLOSE")) {
                return drop(handle(&stream, &line, &statuses));
            }
            // A session's command follows a round trip later (the host's reply to the
            // connect), which a guest faulting in its memory can stretch past a second.
            let body = match session::parse(&line) {
                Ok(session::Request::Start { len, .. }) => match BodyReader::admit() {
                    Some(_reader) => read_body(&mut r, conn, len, at),
                    None => Err(io::Error::other("too many commands arriving at once; try again")),
                },
                _ => Ok(Vec::new()),
            };
            // Kept by the session, so that a later ATTACH can shut this one down.
            let _ = match body.and_then(|body| Ok((body, stream.try_clone()?))) {
                Ok((body, conn)) => session::handle(&stream, &body, Some(conn), &line, &sessions, &statuses),
                Err(e) => fail(&stream, e),
            };
        });
    }
}

/// Sets a socket's SO_RCVTIMEO or SO_SNDTIMEO (at least 1 us: 0 means forever).
fn sock_timeout(fd: RawFd, opt: libc::c_int, t: Duration) {
    let tv = libc::timeval { tv_sec: t.as_secs() as _, tv_usec: t.subsec_micros().max(u32::from(t.is_zero())) as _ };
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, opt, (&tv as *const libc::timeval).cast(), std::mem::size_of_val(&tv) as _) };
}

/// One of the `MAX_BODY_READERS` slots for a command body being read.
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

/// Reads a `len`-byte command body from `r` (socket `fd`), all of it by
/// `at`, however slowly it trickles in. Memory grows only as bytes arrive.
fn read_body(r: &mut impl Read, fd: RawFd, len: usize, at: Instant) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    while body.len() < len {
        let left = at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "the command did not arrive in time"));
        }
        sock_timeout(fd, libc::SO_RCVTIMEO, left);
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

fn write_frame(mut w: impl Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    w.write_all(&[&[kind][..], &(payload.len() as u32).to_le_bytes()].concat())?;
    w.write_all(payload)
}

fn msg(w: impl Write, m: impl AsRef<[u8]>) -> io::Result<()> {
    write_frame(w, FRAME_MSG, m.as_ref())
}

fn fail(w: impl Write, e: impl std::fmt::Display) -> io::Result<()> {
    msg(w, format!("error: {e}"))
}

/// Serves one request other than the session ones; `line` is all of it.
fn handle(out: &File, line: &str, statuses: &Statuses) -> io::Result<()> {
    let line = line.trim_end();
    let (verb, arg) = line.split_once(' ').unwrap_or((line, ""));
    let mut parts = arg.split_whitespace();
    let reply = match verb {
        "PING" => Ok("pong".to_string()),
        "NET" => match parts.next().map(|ip| ip.parse()) {
            Some(Ok(ip)) => net::configure(ip, parts.next()).map(|()| "ok".into()).map_err(|e| e.to_string()),
            _ => Err(format!("bad address {arg:?}")),
        },
        // Acked only once the clock is set, so "ok" means it is.
        "START" => match (parts.next().map(|ip| ip.parse()), parts.next().and_then(parse_time)) {
            (Some(Ok(ip)), Some(now)) => {
                net::configure(ip, parts.next()).map_err(|e| e.to_string()).and_then(|()| set_clock(now)).map(|_| "ok".into())
            }
            _ => Err(format!("bad start request {arg:?}")),
        },
        // Answers how far off the clock was (ns, guest minus host).
        "CLOCK" => parse_time(arg.trim()).ok_or_else(|| format!("bad time {arg:?}")).and_then(set_clock).map(|off| format!("ok {off}")),
        "FORKS" => forks().map(|n| format!("ok {n}")).map_err(|e| e.to_string()),
        v if app::VERBS.contains(&v) => return app::handle(v, arg, out, statuses),
        _ => return msg(out, format!("unknown request {verb:?}")),
    };
    match reply {
        Ok(m) => msg(out, m),
        Err(e) => fail(out, e),
    }
}

/// Parses `secs.nanos` (nanos zero-padded to 9 digits).
fn parse_time(s: &str) -> Option<libc::timespec> {
    let (secs, nanos) = s.split_once('.')?;
    let nanos: i64 = nanos.parse().ok().filter(|n| (0..1_000_000_000).contains(n) && nanos.len() == 9)?;
    Some(libc::timespec { tv_sec: secs.parse().ok()?, tv_nsec: nanos as _ })
}

/// Steps CLOCK_REALTIME to `now` unless it is already within a few ms (the
/// request's own transit time). Returns how far off it was (ns, guest minus `now`).
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

/// Counts the kernel's "crng reseeded due to virtual machine fork" messages,
/// printed right after it reseeds for a new VMGenID: once the count has gone up
/// since a snapshot, the RNG has fresh state. (vmgenid sends no uevent, and
/// /dev/sysgenid is not ordered against the reseed.) Reads the whole ring
/// buffer, so it needs no state from before the snapshot.
fn forks() -> io::Result<usize> {
    const FORK_MSG: &[u8] = b"crng reseeded due to virtual machine fork";
    let mut kmsg = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open("/dev/kmsg")?;
    let (mut buf, mut n) = (vec![0u8; 8192], 0);
    loop {
        match kmsg.read(&mut buf) {
            Ok(0) => return Ok(n),
            Ok(r) => n += buf[..r].windows(FORK_MSG.len()).any(|w| w == FORK_MSG) as usize,
            // Records overwritten while reading; carry on with the next.
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(n),
            Err(e) => return Err(e),
        }
    }
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
    use super::*;

    #[test]
    #[allow(clippy::zombie_processes)] // reap() consumes children; wait_pid receives their statuses.
    fn failed_exec_does_not_race_the_reaper() {
        // Isolate waitpid(P_ALL) from children of the other tests.
        const CHILD: &str = "FLEXVM_REAPER_TEST";
        if std::env::var_os(CHILD).is_none() {
            assert!(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::failed_exec_does_not_race_the_reaper"])
                .env(CHILD, "1").status().unwrap().success());
            return;
        }
        let statuses: Statuses = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
        let reaper = statuses.clone();
        thread::spawn(move || reap(reaper));
        let child = spawn(Command::new("/bin/sleep").arg("0.2"), &statuses, true).unwrap();
        // Let the reaper reach its blocking wait before failed execs exit.
        thread::sleep(Duration::from_millis(10));
        for _ in 0..200 {
            // A pre_exec makes std fork and reap a failed exec itself, as with the throttle cgroup.
            let mut missing = Command::new("/flexvm/nonexistent-executable");
            unsafe { missing.pre_exec(|| Ok(())) };
            assert!(spawn(&mut missing, &statuses, true).is_err());
        }
        assert_eq!(wait_pid(&statuses, child.id() as i32), 0);
        let child = spawn(Command::new("/bin/sh").args(["-c", "exit 7"]), &statuses, true).unwrap();
        assert_eq!(wait_pid(&statuses, child.id() as i32), 7);
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
