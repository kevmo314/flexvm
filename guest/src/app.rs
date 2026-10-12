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
use std::fs::File;
use std::io::{self, Read};
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

/// Runs a readiness command with output discarded, killing its process
/// group if it outlives the deadline: `ok`, `exit <code>` or `timeout`.
fn check(arg: &str, statuses: &Statuses) -> io::Result<String> {
    let (ms, hex) = arg.trim().split_once(' ').ok_or_else(|| io::Error::other("usage: CHECK <ms> <hex>"))?;
    let ms: u64 = ms.parse().map_err(|_| io::Error::other("bad timeout"))?;
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| hex.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| io::Error::other("bad command encoding"))?;
    let cmd = String::from_utf8_lossy(&bytes).into_owned();
    let child = spawn(
        Command::new("/bin/sh")
            .args(["-c", &cmd])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0),
        statuses,
        true,
    )
    .map_err(|e| io::Error::new(e.kind(), format!("cannot run /bin/sh: {e}")))?;
    let pid = child.id() as i32;
    let deadline = Instant::now() + Duration::from_millis(ms);
    let (lock, cv) = &**statuses;
    let mut map = lock.lock().unwrap();
    loop {
        if let Some(Some(code)) = map.get(&pid).copied() {
            map.remove(&pid);
            return Ok(if code == 0 { "ok".into() } else { format!("exit {code}") });
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            drop(map);
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            wait_pid(statuses, pid);
            return Ok("timeout".into());
        }
        map = cv.wait_timeout(map, left).unwrap().0;
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
    let (uid, gid, groups) = (c.uid, c.gid, c.groups.clone());
    // Keep the app (even as root) from reading flexvm-init's memory or ptracing it.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    // Its own session, so signals for flexvm-init's console never reach it.
    // Credentials are dropped here rather than with CommandExt::uid, which
    // would clear the supplementary groups.
    unsafe {
        cmd.pre_exec(move || {
            if uid != 0 {
                // No way back to root: drop every capability from the bounding set
                // while we still may, then forbid gaining privileges on exec.
                for cap in 0..64 {
                    libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
                }
            }
            let ok = libc::setsid() >= 0
                && libc::setgroups(groups.len(), groups.as_ptr()) == 0
                && libc::setgid(gid) == 0
                && libc::setuid(uid) == 0
                && (uid == 0 || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            if ok { Ok(()) } else { Err(io::Error::last_os_error()) }
        });
    }
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
