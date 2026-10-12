//! flexvm-init: PID 1 inside the guest.
//!
//! Sets up a writable overlay on top of the read-only (DAX) root, then serves
//! a tiny command protocol on vsock so the host can run things in the VM.
//!
//! Request: one text line, `PING`, `NET <ip> [dns]`, `EXEC <len>` or `SPAWN <len>`;
//! EXEC/SPAWN are followed by `len` bytes of shell command. Resumable commands use
//! `SESSION <id> <len>`, `ATTACH <id> <offset>` and `CLOSE <id>` (see session.rs).
//! Response: frames of `[kind u8][len u32 LE][payload]`, where kind is
//! 1 = stdout, 2 = stderr, 3 = exit code (i32 LE), 4 = message.

use std::collections::HashMap;
use std::ffi::CString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

mod net;
mod session;

const VSOCK_PORT: u32 = 52;

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
    let sessions: session::Sessions = Arc::new(Mutex::new(HashMap::new()));
    {
        let sessions = sessions.clone();
        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(60));
            session::cleanup(&sessions);
        });
    }
    loop {
        let conn = unsafe { libc::accept4(fd.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
        if conn < 0 {
            continue;
        }
        let stream = unsafe { std::fs::File::from_raw_fd(conn as RawFd) };
        // The host sends its request with the connection; don't let a silent one stall accepting.
        let timeout = libc::timeval { tv_sec: 1, tv_usec: 0 };
        let opt = (&timeout as *const libc::timeval).cast();
        unsafe { libc::setsockopt(conn, libc::SOL_SOCKET, libc::SO_RCVTIMEO, opt, std::mem::size_of_val(&timeout) as _) };
        let Ok(mut r) = stream.try_clone().map(BufReader::new) else { continue };
        let mut line = String::new();
        if r.read_line(&mut line).is_err() {
            continue;
        }
        // NET is on the critical path of every start, right after restore, when a new
        // thread (stack, task, a wakeup on another vCPU) costs milliseconds. PING and
        // NET are quick, so answer them here; only commands get a thread.
        if line.starts_with("PING") || line.starts_with("NET ") {
            let _ = handle(stream, r, &line, &statuses);
        } else {
            let statuses = statuses.clone();
            let sessions = sessions.clone();
            thread::spawn(move || {
                if matches!(line.split_whitespace().next(), Some("SESSION" | "ATTACH" | "CLOSE")) {
                    let timeout = libc::timeval { tv_sec: 2, tv_usec: 0 };
                    unsafe {
                        libc::setsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDTIMEO,
                            (&timeout as *const libc::timeval).cast(), std::mem::size_of_val(&timeout) as _);
                    }
                    let mut errors = match stream.try_clone() { Ok(w) => w, Err(_) => return };
                    if let Err(e) = session::handle(stream, r, &line, &sessions, &statuses) {
                        let _ = write_frame(&mut errors, FRAME_MSG, format!("error: {e}").as_bytes());
                    }
                } else {
                    let _ = handle(stream, r, &line, &statuses);
                }
            });
        }
    }
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

/// Serves one request; `line` is its first line, already read from `r`.
fn handle(stream: std::fs::File, mut r: BufReader<std::fs::File>, line: &str, statuses: &Statuses) -> io::Result<()> {
    let line = line.trim_end();
    let out = Arc::new(Mutex::new(stream));
    let (verb, arg) = line.split_once(' ').unwrap_or((line, ""));
    // Commands may span lines, so they come as `<verb> <len>` plus raw bytes.
    let body;
    let (verb, arg) = match verb {
        "EXEC" | "SPAWN" => {
            let len: usize = arg.trim().parse().map_err(|_| io::Error::other("bad command length"))?;
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf)?;
            body = String::from_utf8_lossy(&buf).into_owned();
            (verb, body.as_str())
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
            let mut child = spawn(
                Command::new("/bin/sh")
                    .args(["-c", arg])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped()),
                statuses, true,
            )?;
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
        _ => frame(&out, FRAME_MSG, format!("unknown request {verb:?}").as_bytes()),
    }
}

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
