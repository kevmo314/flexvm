//! The container image's entrypoint, supervised by flexvm-init.
//!
//! Image templates carry `/etc/flexvm/app.conf`, written at build time from
//! the image config. The host starts the app with `APP` (at `run`, or at
//! template time for warm templates). flexvm-init reaps it like any child,
//! records its exit status and keeps its stdout and stderr in a bounded ring.
//!
//! Requests: `APP`, `APPSTATUS`, `LOGS <offset> <follow 0|1>`, `PROBE <port>`,
//! `CHECK <timeout ms> <hex shell command>` and `QUIESCE`. Replies are
//! frames, as for the other requests.
//!
//! An app with a non-root user runs with no_new_privs and an empty
//! capability bounding set, so setuid binaries and file capabilities in the
//! image cannot take it back to root (and do not work for it).
//!
//! app.conf is one `key value` per line; values escape `\` and newline as
//! `\\` and `\n`. Keys: `arg` (repeated, argv in order), `env` (repeated,
//! `K=V`), `cwd`, `uid`, `gid`, `groups` (space separated).

use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::{frame, spawn, wait_pid, Statuses, FRAME_MSG, FRAME_STDOUT};

const CONF: &str = "/etc/flexvm/app.conf";
/// Bytes of app output kept for `LOGS`; older output is dropped.
const RING_BYTES: usize = 1 << 20;

pub const VERBS: [&str; 6] = ["APP", "APPSTATUS", "LOGS", "PROBE", "CHECK", "QUIESCE"];

#[derive(Clone, Copy)]
enum State {
    Idle,
    Running(i32),
    Exited(i32),
}

struct App {
    state: State,
    ring: VecDeque<u8>,
    /// Stream offset of `ring[0]`: output dropped so far.
    dropped: u64,
}

static APP: Mutex<App> = Mutex::new(App { state: State::Idle, ring: VecDeque::new(), dropped: 0 });
static CHANGED: Condvar = Condvar::new();

impl App {
    fn push(&mut self, data: &[u8]) {
        self.ring.extend(data);
        if self.ring.len() > RING_BYTES {
            let n = self.ring.len() - RING_BYTES;
            self.ring.drain(..n);
            self.dropped += n as u64;
        }
        CHANGED.notify_all();
    }

    fn status(&self) -> String {
        match self.state {
            State::Idle => "idle".into(),
            State::Running(pid) => format!("running {pid}"),
            State::Exited(code) => format!("exited {code}"),
        }
    }
}

/// Bounds writes, so a host that stops reading cannot park this thread.
fn send_timeout(out: &Mutex<File>, secs: i64) {
    use std::os::fd::AsRawFd;
    let tv = libc::timeval { tv_sec: secs, tv_usec: 0 };
    let fd = out.lock().unwrap().as_raw_fd();
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO, (&tv as *const libc::timeval).cast(), std::mem::size_of_val(&tv) as _)
    };
}

pub fn handle(verb: &str, arg: &str, out: &Mutex<File>, statuses: &Statuses) -> io::Result<()> {
    // `LOGS` may legitimately wait on a slow reader; it holds no lock while writing.
    if verb != "LOGS" {
        send_timeout(out, 5);
    }
    match verb {
        "APP" => {
            let reply = match start(statuses) {
                Ok(pid) => format!("ok {pid}"),
                Err(e) => format!("error: {e}"),
            };
            frame(out, FRAME_MSG, reply.as_bytes())
        }
        "APPSTATUS" => {
            let status = APP.lock().unwrap().status();
            frame(out, FRAME_MSG, status.as_bytes())
        }
        "CHECK" => {
            let reply = check(arg, statuses).unwrap_or_else(|e| format!("error: {e}"));
            frame(out, FRAME_MSG, reply.as_bytes())
        }
        "LOGS" => {
            let mut a = arg.split_whitespace();
            let offset = a.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            logs(out, offset, a.next() == Some("1"))
        }
        "PROBE" => {
            let reply = match arg.trim().parse::<u16>() {
                Ok(port) => {
                    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
                    match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                        Ok(_) => "ok".to_string(),
                        Err(e) => format!("error: {e}"),
                    }
                }
                Err(_) => format!("error: bad port {arg:?}"),
            };
            frame(out, FRAME_MSG, reply.as_bytes())
        }
        // Done before a template snapshot; needs no shell in the image.
        "QUIESCE" => {
            unsafe { libc::sync() };
            let _ = std::fs::write("/proc/sys/vm/drop_caches", "3");
            let _ = std::fs::write("/proc/sys/vm/compact_memory", "1");
            frame(out, FRAME_MSG, b"ok")
        }
        _ => frame(out, FRAME_MSG, format!("unknown request {verb:?}").as_bytes()),
    }
}

struct Conf {
    argv: Vec<String>,
    env: Vec<(String, String)>,
    cwd: String,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        match (c, c == '\\') {
            (_, true) => match it.next() {
                Some('n') => out.push('\n'),
                Some(c) => out.push(c),
                None => {}
            },
            (c, false) => out.push(c),
        }
    }
    out
}

fn read_conf() -> io::Result<Conf> {
    let text = std::fs::read_to_string(CONF).map_err(|e| io::Error::new(e.kind(), format!("{CONF}: {e}")))?;
    let mut c = Conf { argv: vec![], env: vec![], cwd: "/".into(), uid: 0, gid: 0, groups: vec![] };
    let num = |v: &str| v.trim().parse::<u32>().map_err(|_| io::Error::other(format!("{CONF}: bad id {v:?}")));
    for line in text.lines() {
        let (k, v) = line.split_once(' ').unwrap_or((line, ""));
        match k {
            "arg" => c.argv.push(unescape(v)),
            "env" => {
                let kv = unescape(v);
                let (k, v) = kv.split_once('=').unwrap_or((&kv, ""));
                c.env.push((k.into(), v.into()));
            }
            "cwd" => c.cwd = unescape(v),
            "uid" => c.uid = num(v)?,
            "gid" => c.gid = num(v)?,
            "groups" => c.groups = v.split_whitespace().map(num).collect::<io::Result<_>>()?,
            _ => {}
        }
    }
    if c.argv.is_empty() {
        return Err(io::Error::other("the image has no entrypoint or command"));
    }
    Ok(c)
}

/// Runs a readiness command as the app would run (its user, env, workdir and
/// restrictions) with output discarded: `ok`, `exit <code>` or `timeout`.
///
/// The command and everything it starts live in a cgroup of their own, which
/// is killed, checked empty and removed whenever the check ends; a check
/// whose cleanup fails is an error, never `ok`. A non-root check requires
/// that cgroup and fails closed without it. A root check is trusted (it
/// could leave any cgroup): without cgroup2 its session is killed instead.
fn check(arg: &str, statuses: &Statuses) -> io::Result<String> {
    let (ms, hex) = arg.trim().split_once(' ').ok_or_else(|| io::Error::other("usage: CHECK <ms> <hex>"))?;
    let ms: u64 = ms.parse().map_err(|_| io::Error::other("bad timeout"))?;
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| hex.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| io::Error::other("bad command encoding"))?;
    let c = read_conf()?;
    let mut cg = match CheckGroup::new() {
        Ok(g) => Some(g),
        Err(_) if c.uid == 0 => None,
        Err(e) => return Err(io::Error::other(format!("cannot contain a non-root readiness check: {e}"))),
    };
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", &String::from_utf8_lossy(&bytes)])
        .env_clear()
        .envs(c.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&c.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    restrict(&mut cmd, &c, cg.as_ref().map(|g| g.procs.clone()));
    // On error the guard removes the (empty) group.
    let child = spawn(&mut cmd, statuses, true).map_err(|e| io::Error::new(e.kind(), format!("cannot run /bin/sh: {e}")))?;
    let pid = child.id() as i32;
    let code = wait_until(statuses, pid, Instant::now() + Duration::from_millis(ms));
    // Kill whatever is left, the leader included if it timed out.
    let cleaned = match &mut cg {
        Some(g) => g.cleanup(),
        None => {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            Ok(())
        }
    };
    let code = match code {
        Some(code) => Some(code),
        None => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            if wait_until(statuses, pid, Instant::now() + Duration::from_secs(2)).is_none() {
                return Err(io::Error::other(format!("readiness command {pid} would not die")));
            }
            None
        }
    };
    cleaned.map_err(|e| io::Error::other(format!("readiness check cleanup failed: {e}")))?;
    Ok(match code {
        Some(0) => "ok".into(),
        Some(code) => format!("exit {code}"),
        None => "timeout".into(),
    })
}

/// Waits for `pid`'s exit status until `deadline`.
fn wait_until(statuses: &Statuses, pid: i32, deadline: Instant) -> Option<i32> {
    let (lock, cv) = &**statuses;
    let mut map = lock.lock().unwrap();
    loop {
        if let Some(Some(code)) = map.get(&pid).copied() {
            map.remove(&pid);
            return Some(code);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        map = cv.wait_timeout(map, left).unwrap().0;
    }
}

/// A cgroup2 group for one readiness check. Dropping it without `cleanup`
/// (an early return) still kills and removes it, within the same bound.
struct CheckGroup {
    dir: String,
    /// `<dir>/cgroup.procs`, for the child to move itself into before exec.
    procs: CString,
    done: bool,
}

impl CheckGroup {
    fn new() -> io::Result<CheckGroup> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        const ROOT: &str = "/sys/fs/cgroup";
        if !std::path::Path::new(&format!("{ROOT}/cgroup.procs")).exists() {
            let (src, dst, ty) = (c"cgroup2", c"/sys/fs/cgroup", c"cgroup2");
            if unsafe { libc::mount(src.as_ptr(), dst.as_ptr(), ty.as_ptr(), 0, std::ptr::null()) } != 0 {
                return Err(io::Error::other(format!("mount cgroup2: {}", io::Error::last_os_error())));
            }
        }
        let dir = format!("{ROOT}/flexvm-check-{}", NEXT.fetch_add(1, Ordering::Relaxed));
        std::fs::create_dir(&dir).map_err(|e| io::Error::other(format!("create {dir}: {e}")))?;
        let g = CheckGroup { procs: CString::new(format!("{dir}/cgroup.procs")).unwrap(), dir, done: false };
        // Needs cgroup.kill (Linux 5.14) to kill every task at once.
        if !std::path::Path::new(&format!("{}/cgroup.kill", g.dir)).exists() {
            return Err(io::Error::other("the kernel has no cgroup.kill"));
        }
        Ok(g)
    }

    /// Kills every task in the group, checks it emptied within 2 s, and
    /// removes it. Any failure is returned.
    fn cleanup(&mut self) -> io::Result<()> {
        self.done = true;
        std::fs::write(format!("{}/cgroup.kill", self.dir), "1")?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let events = std::fs::read_to_string(format!("{}/cgroup.events", self.dir))?;
            if events.lines().any(|l| l == "populated 0") {
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!("{} still has tasks after 2 s", self.dir)));
            }
            thread::sleep(Duration::from_millis(5));
        }
        std::fs::remove_dir(&self.dir)
    }
}

impl Drop for CheckGroup {
    fn drop(&mut self) {
        if !self.done {
            if let Err(e) = self.cleanup() {
                let _ = writeln!(io::stderr(), "flexvm-init: readiness check group: {e}");
            }
        }
    }
}

/// Sets up a child as the app runs: its own session, in `cgroup` if given,
/// the app's credentials and, for a non-root user, no capabilities and
/// no_new_privs. Credentials are dropped here rather than with
/// CommandExt::uid, which would clear the supplementary groups.
fn restrict(cmd: &mut Command, c: &Conf, cgroup: Option<CString>) {
    let (uid, gid, groups) = (c.uid, c.gid, c.groups.clone());
    unsafe {
        cmd.pre_exec(move || {
            let fail = || Err(io::Error::last_os_error());
            if let Some(procs) = &cgroup {
                // "0" moves the writing process; only raw syscalls after fork.
                let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if fd < 0 || libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                    return fail();
                }
                libc::close(fd);
            }
            if libc::setsid() < 0 {
                return fail();
            }
            if uid != 0 {
                // No way back to root: drop every capability from the bounding set
                // while we still may (EINVAL: past the kernel's last capability).
                for cap in 0..64 {
                    if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0
                        && *libc::__errno_location() != libc::EINVAL
                    {
                        return fail();
                    }
                }
            }
            let ok = libc::setgroups(groups.len(), groups.as_ptr()) == 0
                && libc::setgid(gid) == 0
                && libc::setuid(uid) == 0
                && (uid == 0 || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            if ok { Ok(()) } else { fail() }
        });
    }
}

/// Starts the app unless it is already running. Returns its pid.
fn start(statuses: &Statuses) -> io::Result<i32> {
    let mut app = APP.lock().unwrap();
    if let State::Running(pid) = app.state {
        return Ok(pid);
    }
    let c = read_conf()?;
    let mut cmd = Command::new(&c.argv[0]);
    cmd.args(&c.argv[1..])
        .env_clear()
        .envs(c.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&c.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Keep the app (even as root) from reading flexvm-init's memory or ptracing it.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    restrict(&mut cmd, &c, None);
    let mut child = spawn(&mut cmd, statuses, true).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", c.argv[0])))?;
    let pid = child.id() as i32;
    app.state = State::Running(pid);
    app.push(format!("flexvm-init: started {:?} as pid {pid}\n", c.argv).as_bytes());
    drop(app);
    pump(child.stdout.take().unwrap());
    pump(child.stderr.take().unwrap());
    let statuses = statuses.clone();
    thread::spawn(move || {
        let code = wait_pid(&statuses, pid);
        let mut app = APP.lock().unwrap();
        app.state = State::Exited(code);
        app.push(format!("flexvm-init: pid {pid} exited with status {code}\n").as_bytes());
    });
    Ok(pid)
}

fn pump(mut r: impl Read + Send + 'static) {
    thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            APP.lock().unwrap().push(&buf[..n]);
        }
    });
}

/// Sends the app's output from stream offset `offset` (clamped to what the
/// ring still holds), then its status. With `follow`, keeps sending new
/// output until the app has exited.
fn logs(out: &Mutex<File>, mut offset: u64, follow: bool) -> io::Result<()> {
    // Without `follow`, only what was there when asked.
    let stop = {
        let app = APP.lock().unwrap();
        if follow { u64::MAX } else { app.dropped + app.ring.len() as u64 }
    };
    loop {
        let (chunk, status, done) = {
            let mut app = APP.lock().unwrap();
            loop {
                let end = app.dropped + app.ring.len() as u64;
                offset = offset.clamp(app.dropped, end);
                let exited = !matches!(app.state, State::Running(_));
                if offset < end || !follow || exited {
                    break;
                }
                let (a, timeout) = CHANGED.wait_timeout(app, Duration::from_secs(5)).unwrap();
                app = a;
                if timeout.timed_out() {
                    break;
                }
            }
            let start = (offset - app.dropped) as usize;
            let avail = (app.ring.len() - start) as u64;
            let n = avail.min(stop.saturating_sub(offset)).min(64 * 1024) as usize;
            let chunk: Vec<u8> = app.ring.range(start..start + n).copied().collect();
            let done = !follow || !matches!(app.state, State::Running(_));
            (chunk, app.status(), done)
        };
        offset += chunk.len() as u64;
        // An empty frame doubles as a keepalive that notices a closed connection.
        frame(out, FRAME_STDOUT, &chunk)?;
        if done && chunk.is_empty() {
            return frame(out, FRAME_MSG, format!("{status} {offset}").as_bytes());
        }
    }
}
