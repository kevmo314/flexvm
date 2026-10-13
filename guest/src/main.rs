//! flexvm-init: PID 1 inside the guest.
//!
//! Sets up a writable overlay on top of the read-only (DAX) root, then serves
//! a tiny command protocol on vsock so the host can run things in the VM.
//!
//! Request: one text line, `PING`, `NET <ip> [dns]`, `START <ip> <secs.nanos> [dns]`,
//! `EXEC <len>` or `SPAWN <len>`; EXEC/SPAWN are followed by `len` bytes of shell
//! command. `START` is `NET` plus the host's wall clock, sent on every start;
//! `CLOCK <secs.nanos>` sets just the clock, after a migration or a resume;
//! `FORKS` counts the RNG reseeds for new VMGenIDs the kernel has done.
//! Resumable commands use `SESSION <id> <len>`, `ATTACH <id> <offset>` and
//! `CLOSE <id>` (see session.rs). Image templates add the app requests in `app.rs`.
//! Response: frames of `[kind u8][len u32 LE][payload]`, where kind is
//! 1 = stdout, 2 = stderr, 3 = exit code (i32 LE), 4 = message.

use std::collections::HashMap;
use std::ffi::CString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

mod app;
mod net;
mod session;

const VSOCK_PORT: u32 = 52;
/// How long a command's body (after its request line) may take to arrive,
/// all of it.
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest request line and command body.
const MAX_LINE: u64 = 4096;
const MAX_BODY: usize = 1024 * 1024;
/// How many command bodies may be arriving at once; more are refused.
const MAX_BODY_READERS: usize = 16;
static BODY_READERS: AtomicUsize = AtomicUsize::new(0);

const FRAME_STDOUT: u8 = 1;
const FRAME_STDERR: u8 = 2;
const FRAME_EXIT: u8 = 3;
const FRAME_MSG: u8 = 4;

type Statuses = Arc<(Mutex<HashMap<i32, Option<i32>>>, Condvar)>;

fn main() {
    if unsafe { libc::getpid() } == 1 {
        if let Err(e) = setup_root() {
            log(&format!("root setup failed: {e}"));
        }
        if let Err(e) = net::setup() {
            log(&format!("network setup failed: {e}"));
        }
    }
    let statuses: Statuses = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
    {
        let statuses = statuses.clone();
        thread::spawn(move || reap(statuses));
    }
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

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn mount(src: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> io::Result<()> {
    let (src_c, target_c, fstype_c, data_c) = (cstr(src), cstr(target), cstr(fstype), cstr(data));
    let rc = unsafe {
        libc::mount(
            src_c.as_ptr(),
            target_c.as_ptr(),
            if fstype.is_empty() { std::ptr::null() } else { fstype_c.as_ptr() },
            flags,
            data_c.as_ptr().cast(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EBUSY) {
            return Ok(());
        }
        Err(io::Error::new(err.kind(), format!("mount {target}: {err}")))
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
    for d in ["/run/ovl", "/run/ovl/upper", "/run/ovl/work", "/run/root"] {
        std::fs::create_dir_all(d)?;
    }
    mount(
        "overlay",
        "/run/root",
        "overlay",
        0,
        "lowerdir=/,upperdir=/run/ovl/upper,workdir=/run/ovl/work",
    )?;
    for d in ["/proc", "/sys", "/dev"] {
        mount(d, &format!("/run/root{d}"), "", libc::MS_MOVE, "")?;
    }
    std::env::set_current_dir("/run/root")?;
    std::fs::create_dir_all("/run/root/mnt/oldroot")?;
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c"mnt/oldroot".as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
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

/// Reaps every child (we are PID 1, so orphans land here too) and records
/// exit codes for the EXEC handlers waiting on them.
fn reap(statuses: Statuses) {
    let (lock, cv) = &*statuses;
    loop {
        let mut map = lock.lock().unwrap();
        let mut status = 0;
        // Check for children under the spawn lock so a notification cannot be missed.
        let mut pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid == 0 {
            drop(map);
            pid = unsafe { libc::waitpid(-1, &mut status, 0) };
            if pid < 0 {
                match io::Error::last_os_error().raw_os_error() {
                    Some(libc::ECHILD) | Some(libc::EINTR) => continue,
                    _ => return,
                }
            }
            map = lock.lock().unwrap();
        }
        if pid < 0 {
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::ECHILD) => drop(cv.wait(map).unwrap()),
                Some(libc::EINTR) => {}
                _ => return,
            }
            continue;
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        };
        if let Some(exit) = map.get_mut(&pid) {
            *exit = Some(code);
            cv.notify_all();
        }
    }
}

fn spawn(command: &mut Command, statuses: &Statuses, deliver_exit: bool) -> io::Result<Child> {
    let (lock, cv) = &**statuses;
    // Hold the lock through spawn and registration, even if the child exits immediately.
    let mut map = lock.lock().unwrap();
    let child = command.spawn()?;
    if deliver_exit {
        map.insert(child.id() as i32, None);
    }
    cv.notify_all();
    Ok(child)
}

fn wait_pid(statuses: &Statuses, pid: i32) -> i32 {
    let (lock, cv) = &**statuses;
    let mut map = lock.lock().unwrap();
    loop {
        if let Some(Some(code)) = map.get(&pid).copied() {
            map.remove(&pid);
            return code;
        }
        map = cv.wait(map).unwrap();
    }
}

/// Delay consecutive accept failures without spinning under resource pressure.
fn accept_delay(backoff: &mut Duration) -> Duration {
    *backoff = if backoff.is_zero() {
        Duration::from_millis(10)
    } else {
        (*backoff * 2).min(Duration::from_secs(1))
    };
    *backoff
}

fn serve(statuses: Statuses) -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as _;
    addr.svm_port = VSOCK_PORT;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    let rc = unsafe {
        libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_vm).cast(), std::mem::size_of_val(&addr) as _)
    };
    if rc != 0 || unsafe { libc::listen(fd.as_raw_fd(), 64) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let sessions = session::Sessions::default();
    {
        let sessions = sessions.clone();
        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(60));
            session::cleanup(&sessions);
        });
    }
    let mut backoff = Duration::ZERO;
    loop {
        let conn = unsafe { libc::accept4(fd.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
        if conn < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                if backoff.is_zero() {
                    eprintln!("vsock accept failed: {e}; backing off");
                }
                thread::sleep(accept_delay(&mut backoff));
            }
            continue;
        }
        backoff = Duration::ZERO;
        let stream = unsafe { std::fs::File::from_raw_fd(conn as RawFd) };
        // The host sends its request with the connection; don't let a silent one stall accepting.
        receive_timeout(conn, Duration::from_secs(1));
        let Ok(mut r) = stream.try_clone().map(BufReader::new) else { continue };
        let mut line = String::new();
        if !(r.by_ref().take(MAX_LINE).read_line(&mut line).is_ok() && line.ends_with('\n')) {
            continue;
        }
        // NET is on the critical path of every start, right after restore, when a new
        // thread (stack, task, a wakeup on another vCPU) costs milliseconds. PING and
        // NET are quick, so answer them here; only commands get a thread.
        if ["PING", "NET ", "START ", "CLOCK ", "FORKS"].iter().any(|v| line.starts_with(v)) {
            let _ = handle(stream, None, &line, &statuses);
        } else {
            // A command's body follows the host's reply to the connect, a round
            // trip later, which a guest still faulting in its memory after a
            // restore or migration can stretch past a second. It is read off
            // the accept loop, by a bounded number of readers, within
            // BODY_TIMEOUT of now.
            let body = match body_len(&line) {
                None => None,
                Some(Err(e)) => {
                    let _ = write_frame(&mut &stream, FRAME_MSG, format!("error: {e}").as_bytes());
                    continue;
                }
                Some(Ok(len)) => match BodyReader::admit() {
                    Some(reader) => Some((len, reader, Instant::now() + BODY_TIMEOUT)),
                    None => {
                        let _ = write_frame(&mut &stream, FRAME_MSG, b"error: too many commands arriving at once; try again");
                        continue;
                    }
                },
            };
            let statuses = statuses.clone();
            let sessions = sessions.clone();
            // Out of threads: drop this connection (closing it) rather than abort PID 1.
            let _ = thread::Builder::new().spawn(move || {
                let body = match body {
                    None => None,
                    Some((len, reader, at)) => {
                        let body = read_body(&mut r, conn, len, at);
                        drop(reader);
                        match body {
                            Ok(b) => Some(b),
                            Err(e) => {
                                let _ = write_frame(&mut &stream, FRAME_MSG, format!("error: {e}").as_bytes());
                                return;
                            }
                        }
                    }
                };
                // A blocked write is backpressure from a slow client; migration resets the socket.
                if matches!(line.split_whitespace().next(), Some("SESSION" | "ATTACH" | "CLOSE")) {
                    let body = body.unwrap_or_default();
                    // Kept by the session, so that a later ATTACH can shut this one down.
                    match stream.try_clone() {
                        Ok(conn) => {
                            let _ = session::handle(stream, body.as_slice(), Some(conn), &line, &sessions, &statuses);
                        }
                        Err(e) => {
                            let _ = write_frame(&mut &stream, FRAME_MSG, format!("error: {e}").as_bytes());
                        }
                    }
                } else {
                    let _ = handle(stream, body, &line, &statuses);
                }
            });
        }
    }
}

/// Sets how long each receive on `fd` may wait (at least 1 us: 0 means forever).
fn receive_timeout(fd: RawFd, t: Duration) {
    let timeout = libc::timeval { tv_sec: t.as_secs() as _, tv_usec: t.subsec_micros().max(u32::from(t.is_zero())) as _ };
    let opt = (&timeout as *const libc::timeval).cast();
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, opt, std::mem::size_of_val(&timeout) as _) };
}

/// The length of the command body that follows request `line`, if its verb
/// takes one.
fn body_len(line: &str) -> Option<io::Result<usize>> {
    let mut parts = line.split_whitespace();
    let len = match parts.next()? {
        "EXEC" | "SPAWN" => parts.next(),
        "SESSION" => parts.nth(1),
        _ => return None,
    };
    Some(len.and_then(|n| n.parse().ok()).filter(|&n| n <= MAX_BODY).ok_or_else(|| io::Error::other("bad command length")))
}

/// One of the `MAX_BODY_READERS` slots for a command body being read.
struct BodyReader;

impl BodyReader {
    fn admit() -> Option<BodyReader> {
        let n = BODY_READERS.fetch_add(1, Ordering::SeqCst);
        if n >= MAX_BODY_READERS {
            BODY_READERS.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(BodyReader)
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
        receive_timeout(fd, left);
        let want = (len - body.len()).min(buf.len());
        match r.read(&mut buf[..want]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
    Ok(body)
}

fn frame(w: &Mutex<std::fs::File>, kind: u8, payload: &[u8]) -> io::Result<()> {
    write_frame(&mut *w.lock().unwrap(), kind, payload)
}

fn write_frame(w: &mut impl Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = kind;
    hdr[1..].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    w.write_all(&hdr)?;
    w.write_all(payload)
}

/// Serves one request; `line` is its first line, and `body` the command
/// that follows it for EXEC and SPAWN.
fn handle(stream: std::fs::File, body: Option<Vec<u8>>, line: &str, statuses: &Statuses) -> io::Result<()> {
    let line = line.trim_end();
    let out = Arc::new(Mutex::new(stream));
    let (verb, arg) = line.split_once(' ').unwrap_or((line, ""));
    // Commands may span lines, so they come as `<verb> <len>` plus raw bytes.
    let text;
    let (verb, arg) = match verb {
        "EXEC" | "SPAWN" => {
            text = String::from_utf8_lossy(body.as_deref().unwrap_or_default()).into_owned();
            (verb, text.as_str())
        }
        _ => (verb, arg),
    };
    match verb {
        "PING" => frame(&out, FRAME_MSG, b"pong"),
        // NET <ipv4> [nameserver]
        "NET" => {
            let mut parts = arg.split_whitespace();
            let res = match parts.next().map(|ip| ip.parse()) {
                Some(Ok(ip)) => net::configure(ip, parts.next()).map_err(|e| e.to_string()),
                _ => Err(format!("bad address {arg:?}")),
            };
            match res {
                Ok(()) => frame(&out, FRAME_MSG, b"ok"),
                Err(e) => frame(&out, FRAME_MSG, format!("error: {e}").as_bytes()),
            }
        }
        // START <ipv4> <unix time secs.nanos> [nameserver]: NET for a VM that was just
        // restored or resumed, plus the host's wall clock. The guest clock otherwise
        // carries on from the moment the template was snapshotted.
        "START" => {
            let mut parts = arg.split_whitespace();
            let (ip, now, dns) = (parts.next(), parts.next(), parts.next());
            let res = match (ip.map(|ip| ip.parse()), now.and_then(parse_time)) {
                (Some(Ok(ip)), Some(now)) => net::configure(ip, dns).map_err(|e| e.to_string()).map(|()| now),
                _ => Err(format!("bad start request {arg:?}")),
            };
            // Acked only once the clock is set, so "ok" means it is.
            match res.and_then(set_clock) {
                Ok(_) => frame(&out, FRAME_MSG, b"ok"),
                Err(e) => frame(&out, FRAME_MSG, format!("error: {e}").as_bytes()),
            }
        }
        // CLOCK <unix time secs.nanos>: the host's wall clock, after a VM resumed
        // from a pause or arrived by migration (which costs it the downtime).
        // Answers `ok <ns>`: how far off the clock was (guest minus host).
        "CLOCK" => match parse_time(arg.trim()).ok_or_else(|| format!("bad time {arg:?}")).and_then(set_clock) {
            Ok(off) => frame(&out, FRAME_MSG, format!("ok {off}").as_bytes()),
            Err(e) => frame(&out, FRAME_MSG, format!("error: {e}").as_bytes()),
        },
        // FORKS: how many times the kernel has reseeded its RNG for a new
        // VMGenID, i.e. how many snapshot restores this guest has finished
        // processing. See `forks`.
        "FORKS" => match forks() {
            Ok(n) => frame(&out, FRAME_MSG, format!("ok {n}").as_bytes()),
            Err(e) => frame(&out, FRAME_MSG, format!("error: {e}").as_bytes()),
        },
        "SPAWN" => {
            let child = spawn(
                Command::new("/bin/sh")
                    .args(["-c", arg])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .process_group(0),
                statuses, false,
            )?;
            frame(&out, FRAME_MSG, child.id().to_string().as_bytes())
        }
        "EXEC" => {
            let spawned = spawn(
                Command::new("/bin/sh")
                    .args(["-c", arg])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped()),
                statuses, true,
            );
            // Minimal images (distroless, scratch) have no shell.
            let mut child = match spawned {
                Ok(c) => c,
                Err(e) => {
                    let msg = format!("flexvm-init: cannot run /bin/sh: {e} (does the image have a shell?)\n");
                    frame(&out, FRAME_STDERR, msg.as_bytes())?;
                    return frame(&out, FRAME_EXIT, &127i32.to_le_bytes());
                }
            };
            let pid = child.id() as i32;
            let pumps = [
                pump(child.stdout.take().unwrap(), out.clone(), FRAME_STDOUT),
                pump(child.stderr.take().unwrap(), out.clone(), FRAME_STDERR),
            ];
            for p in pumps {
                let _ = p.join();
            }
            let code = wait_pid(statuses, pid);
            frame(&out, FRAME_EXIT, &code.to_le_bytes())
        }
        v if app::VERBS.contains(&v) => app::handle(v, arg, &out, statuses),
        _ => frame(&out, FRAME_MSG, format!("unknown request {verb:?}").as_bytes()),
    }
}

/// Parses `secs.nanos` (nanos zero-padded to 9 digits).
fn parse_time(s: &str) -> Option<libc::timespec> {
    let (secs, nanos) = s.split_once('.')?;
    let nanos: i64 = nanos.parse().ok().filter(|n| (0..1_000_000_000).contains(n) && nanos.len() == 9)?;
    Some(libc::timespec { tv_sec: secs.parse().ok()?, tv_nsec: nanos as _ })
}

/// Steps CLOCK_REALTIME to `now` unless it is already within a few ms (the
/// request's own transit time), which leaves a clock that is right alone.
/// (The host makes sure no clock request is still in flight when it
/// snapshots the VM; see `Vm::start_source`.)
/// Returns how far off the clock was (ns, guest minus `now`).
fn set_clock(now: libc::timespec) -> Result<i128, String> {
    let ns = |t: &libc::timespec| t.tv_sec as i128 * 1_000_000_000 + t.tv_nsec as i128;
    let mut cur = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut cur) };
    let off = ns(&cur) - ns(&now);
    if off.abs() < 5_000_000 {
        return Ok(off);
    }
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &now) } != 0 {
        return Err(format!("set clock: {}", io::Error::last_os_error()));
    }
    Ok(off)
}

/// Counts "crng reseeded due to virtual machine fork" in the kernel log.
/// The kernel prints it in add_vmfork_randomness() right after crng_reseed()
/// for a new VMGenID, so once the count has gone up since a snapshot was
/// taken, everything that reads the RNG from then on gets fresh state. (This
/// kernel's vmgenid sends no uevent, and /dev/sysgenid's counter is not
/// ordered against the reseed.) Reads the whole ring buffer, so it needs no
/// state from before the snapshot.
fn forks() -> io::Result<usize> {
    let fd = unsafe { libc::open(c"/dev/kmsg".as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut buf = vec![0u8; 8192];
    let mut n = 0;
    loop {
        let r = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if r < 0 {
            match io::Error::last_os_error().raw_os_error() {
                // Records overwritten while reading; carry on with the next.
                Some(libc::EPIPE) => continue,
                Some(libc::EAGAIN) => return Ok(n),
                _ => return Err(io::Error::last_os_error()),
            }
        }
        if r == 0 {
            return Ok(n);
        }
        let record = &buf[..r as usize];
        if record.windows(FORK_MSG.len()).any(|w| w == FORK_MSG) {
            n += 1;
        }
    }
}

const FORK_MSG: &[u8] = b"crng reseeded due to virtual machine fork";

fn pump(mut r: impl Read + Send + 'static, out: Arc<Mutex<std::fs::File>>, kind: u8) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 || frame(&out, kind, &buf[..n]).is_err() {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn body_lengths() {
        assert_eq!(body_len("EXEC 12\n").unwrap().unwrap(), 12);
        assert_eq!(body_len("SESSION abc 3\n").unwrap().unwrap(), 3);
        assert!(body_len("SESSION abc 1048577\n").unwrap().is_err());
        assert!(body_len("SPAWN x\n").unwrap().is_err());
        assert!(body_len("ATTACH abc 0\n").is_none());
        assert!(body_len("PING\n").is_none());
    }

    #[test]
    fn bodies_end_by_their_deadline() {
        let at = Instant::now() + Duration::from_secs(5);
        assert_eq!(read_body(&mut &b"echo hi"[..], -1, 7, at).unwrap(), b"echo hi");
        assert_eq!(read_body(&mut &b"echo"[..], -1, 7, at).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let past = Instant::now() - Duration::from_millis(1);
        assert_eq!(read_body(&mut &b"echo hi"[..], -1, 7, past).unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn body_readers_are_capped() {
        let readers: Vec<_> = std::iter::from_fn(BodyReader::admit).take(MAX_BODY_READERS + 1).collect();
        assert_eq!(readers.len(), MAX_BODY_READERS);
        drop(readers);
        assert!(BodyReader::admit().is_some());
    }
}
