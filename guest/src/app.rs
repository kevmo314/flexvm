//! The image's entrypoint, supervised by flexvm-init. `/etc/flexvm/app.conf` (written at build) has one
//! `key value` per line, `\` and newline escaped as `\\` and `\n`: `arg`/`env` (repeated), `cwd`, `uid`,
//! `gid`, `groups`. Requests: `APP`, `APPSTATUS`, `LOGS <offset> <follow 0|1>`, `PROBE <port>`,
//! `CHECK <timeout ms> <hex shell command>`, `QUIESCE`. A non-root app runs with no_new_privs and an
//! empty bounding set, so setuid binaries and file capabilities cannot take it back to root.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Seek, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Condvar, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::{fail, mem, msg, session::Output, spawn, wait_pid, write_frame, Statuses, FRAME_STDOUT};
use crate::proto::FRAME_LOST;

const CONF: &str = "/etc/flexvm/app.conf";
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
    output: Output,
    /// The pid whose output pump last finished.
    pumped: i32,
}

static APP: LazyLock<Mutex<App>> = LazyLock::new(|| Mutex::new(App { state: State::Idle, output: Output::default(), pumped: 0 }));
static CHANGED: Condvar = Condvar::new();

impl App {
    fn push(&mut self, data: &[u8]) {
        self.output.push(FRAME_STDOUT, data, RING_BYTES);
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

pub fn handle(verb: &str, arg: &str, out: &File, statuses: &Statuses) -> io::Result<()> {
    // Bounds writes, so a host that stops reading cannot park this thread;
    // `LOGS` may legitimately wait on a slow reader, holding no lock while writing.
    if verb != "LOGS" {
        crate::sock_timeout(out.as_raw_fd(), libc::SO_SNDTIMEO, Duration::from_secs(5));
    }
    let reply = match verb {
        "APP" => start(statuses).map(|pid| format!("ok {pid}")),
        "APPSTATUS" => Ok(APP.lock().unwrap().status()),
        "CHECK" => check(arg, statuses),
        "LOGS" => {
            let mut a = arg.split_whitespace();
            let offset = a.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            return logs(out, offset, a.next() == Some("1"));
        }
        "PROBE" => match arg.trim().parse::<u16>() {
            Ok(port) => TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_millis(500))
                .map(|_| "ok".into()),
            Err(_) => Err(io::Error::other(format!("bad port {arg:?}"))),
        },
        // Before a template snapshot; needs no shell in the image.
        "QUIESCE" => {
            unsafe { libc::sync() };
            let _ = std::fs::write("/proc/sys/vm/drop_caches", "3");
            let _ = std::fs::write("/proc/sys/vm/compact_memory", "1");
            Ok("ok".into())
        }
        _ => return msg(out, format!("unknown request {verb:?}")),
    };
    match reply {
        Ok(m) => msg(out, m),
        Err(e) => fail(out, e),
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
    let (mut out, mut it) = (String::with_capacity(s.len()), s.chars());
    while let Some(c) = it.next() {
        out.push(match (c, if c == '\\' { it.next() } else { None }) {
            ('\\', Some('n')) => '\n',
            ('\\', Some(c)) => c,
            ('\\', None) => break,
            (c, _) => c,
        });
    }
    out
}

fn parse_conf(text: &str) -> io::Result<Conf> {
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

fn command<S: AsRef<std::ffi::OsStr>>(c: &Conf, argv: &[S]) -> Command {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).env_clear().envs(c.env.iter().map(|(k, v)| (k, v))).current_dir(&c.cwd).stdin(Stdio::null());
    cmd
}

/// Runs a readiness command as the app would (`ok`, `exit <code>` or `timeout`) in its own cgroup, killed,
/// checked empty and removed at the end; failed cleanup is an error, never `ok`. A non-root check fails
/// closed without that cgroup; a root check is trusted, and without cgroup2 its session is killed instead.
fn check(arg: &str, statuses: &Statuses) -> io::Result<String> {
    let (ms, hex) = arg.trim().split_once(' ').ok_or_else(|| io::Error::other("usage: CHECK <ms> <hex>"))?;
    let ms: u64 = ms.parse().map_err(|_| io::Error::other("bad timeout"))?;
    let bytes: Option<Vec<u8>> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect();
    let bytes = bytes.ok_or_else(|| io::Error::other("bad command encoding"))?;
    let c = parse_conf(&read_conf()?)?;
    let mut cg = match CheckGroup::new() {
        Ok(g) => Some(g),
        Err(_) if c.uid == 0 => None,
        Err(e) => return Err(io::Error::other(format!("cannot contain a non-root readiness check: {e}"))),
    };
    let mut cmd = command(&c, &["/bin/sh", "-c", &String::from_utf8_lossy(&bytes)]);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    match &cg {
        Some(g) => mem::enter(&mut cmd, g.procs.clone(), true),
        None => mem::work_procs().into_iter().for_each(|work| mem::enter(&mut cmd, work, false)),
    }
    restrict(&mut cmd, &c);
    let pid = spawn(&mut cmd, statuses).map_err(|e| io::Error::new(e.kind(), format!("cannot run /bin/sh: {e}")))?.id() as i32;
    let code = wait_pid(statuses, pid, Some(Instant::now() + Duration::from_millis(ms)));
    // Kill whatever is left, the leader included if it timed out.
    let cleaned = match &mut cg {
        Some(g) => g.cleanup(),
        None => {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            Ok(())
        }
    };
    if code.is_none() {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        if wait_pid(statuses, pid, Some(Instant::now() + Duration::from_secs(2))).is_none() {
            return Err(io::Error::other(format!("readiness command {pid} would not die")));
        }
    }
    cleaned.map_err(|e| io::Error::other(format!("readiness check cleanup failed: {e}")))?;
    Ok(match code {
        Some(0) => "ok".into(),
        Some(code) => format!("exit {code}"),
        None => "timeout".into(),
    })
}

fn read_conf() -> io::Result<String> {
    std::fs::read_to_string(CONF).map_err(|e| io::Error::new(e.kind(), format!("{CONF}: {e}")))
}

/// Dropped without `cleanup` (an early return), it is still killed and removed.
struct CheckGroup {
    dir: String,
    procs: CString,
    done: bool,
}

impl CheckGroup {
    fn new() -> io::Result<CheckGroup> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        if !std::path::Path::new(&format!("{}/cgroup.procs", mem::CGROUP_ROOT)).exists() {
            crate::mount("cgroup2", mem::CGROUP_ROOT, "cgroup2", 0, "")?;
        }
        // Under the guest's memory mark, like the app (see mem.rs).
        let parent = if mem::work_procs().is_some() { mem::CGROUP } else { mem::CGROUP_ROOT };
        let dir = format!("{parent}/flexvm-check-{}", NEXT.fetch_add(1, Ordering::Relaxed));
        std::fs::create_dir(&dir).map_err(|e| io::Error::other(format!("create {dir}: {e}")))?;
        Self::from_dir(dir)
    }

    fn from_dir(dir: String) -> io::Result<CheckGroup> {
        let mut g = CheckGroup { procs: CString::new(format!("{dir}/cgroup.procs")).unwrap(), dir, done: false };
        // Needs cgroup.kill (Linux 5.14) to kill every task at once.
        if !std::path::Path::new(&format!("{}/cgroup.kill", g.dir)).exists() {
            g.done = true;
            std::fs::remove_dir(&g.dir)?;
            return Err(io::Error::other("the kernel has no cgroup.kill"));
        }
        Ok(g)
    }

    fn cleanup(&mut self) -> io::Result<()> {
        self.done = true;
        std::fs::write(format!("{}/cgroup.kill", self.dir), "1")?;
        // Reading through the polled fd rearms its POLLPRI, so a change after the read still wakes the poll.
        let mut events = File::open(format!("{}/cgroup.events", self.dir))?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while !(events.rewind().and_then(|_| io::read_to_string(&events))?).lines().any(|l| l == "populated 0") {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::other(format!("{} still has tasks after 2 s", self.dir)));
            }
            let mut fd = libc::pollfd { fd: events.as_raw_fd(), events: libc::POLLPRI, revents: 0 };
            unsafe { libc::poll(&mut fd, 1, left.as_millis().max(1) as i32) };
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

/// Own session, the app's credentials and, if non-root, no capabilities and no_new_privs; done by
/// hand because CommandExt::uid would clear the supplementary groups.
fn restrict(cmd: &mut Command, c: &Conf) {
    let (uid, gid, groups) = (c.uid, c.gid, c.groups.clone());
    unsafe {
        cmd.pre_exec(move || {
            let fail = || Err(io::Error::last_os_error());
            if libc::setsid() < 0 {
                return fail();
            }
            if uid != 0 {
                // No way back to root: drop the bounding set (EINVAL: past the kernel's last capability).
                for cap in 0..64 {
                    if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && *libc::__errno_location() != libc::EINVAL {
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

fn start(statuses: &Statuses) -> io::Result<i32> {
    let mut app = APP.lock().unwrap();
    if let State::Running(pid) = app.state {
        return Ok(pid);
    }
    let c = parse_conf(&read_conf()?)?;
    let mut cmd = command(&c, &c.argv);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    // Keep the app from reading or ptracing flexvm-init (a root app with CAP_SYS_PTRACE still can).
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if let Some(work) = mem::work_procs() {
        mem::enter(&mut cmd, work, true);
    }
    restrict(&mut cmd, &c);
    let mut child = spawn(&mut cmd, statuses).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", c.argv[0])))?;
    let pid = child.id() as i32;
    app.state = State::Running(pid);
    app.push(format!("flexvm-init: started {:?} as pid {pid}\n", c.argv).as_bytes());
    drop(app);
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    thread::spawn(move || {
        crate::pump(stdout, stderr, |_, data| APP.lock().unwrap().push(data));
        APP.lock().unwrap().pumped = pid;
        CHANGED.notify_all();
    });
    let statuses = statuses.clone();
    thread::spawn(move || {
        let code = wait_pid(&statuses, pid, None).unwrap_or(-1);
        // Descendants may hold the app's pipes after it exits; never wait indefinitely.
        let (mut app, _) = CHANGED.wait_timeout_while(APP.lock().unwrap(), Duration::from_secs(2), |a| a.pumped != pid).unwrap();
        app.state = State::Exited(code);
        app.push(format!("flexvm-init: pid {pid} exited with status {code}\n").as_bytes());
    });
    Ok(pid)
}

/// Output from `offset` (clamped to the ring), then `<status> <next offset>`; with `follow`, until exit.
/// Following, a clamp is told first (FRAME_LOST, the offset output goes on from, u64 LE), so a
/// reader that fell behind the ring keeps its offset right.
fn logs(mut out: impl Write, mut offset: u64, follow: bool) -> io::Result<()> {
    let stop = {
        let app = APP.lock().unwrap();
        if follow { u64::MAX } else { app.output.end }
    };
    loop {
        let (chunk, status, done, moved) = {
            let (app, _) = CHANGED.wait_timeout_while(APP.lock().unwrap(), Duration::from_secs(5), |a| {
                follow && offset >= a.output.end && matches!(a.state, State::Running(_))
            }).unwrap();
            let clamped = offset.clamp(app.output.start, app.output.end);
            let moved = clamped != offset;
            offset = clamped;
            let chunk = app.output.read_chunk(offset).map_or_else(Vec::new, |(_, data)| {
                data[..data.len().min(64 * 1024).min(stop.saturating_sub(offset) as usize)].to_vec()
            });
            (chunk, app.status(), !follow || !matches!(app.state, State::Running(_)), moved)
        };
        if follow && moved {
            write_frame(&mut out, FRAME_LOST, &offset.to_le_bytes())?;
        }
        offset += chunk.len() as u64;
        // An empty frame doubles as a keepalive that notices a closed connection.
        write_frame(&mut out, FRAME_STDOUT, &chunk)?;
        if done && chunk.is_empty() {
            return msg(out, format!("{status} {offset}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_check_group_is_removed() {
        let dir = std::env::temp_dir().join(format!("flexvm-check-group-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        assert!(CheckGroup::from_dir(dir.to_str().unwrap().into()).err().unwrap().to_string().contains("cgroup.kill"));
        assert!(!dir.exists());
    }

    #[test]
    fn pump_keeps_the_crash_tail() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "head -c 131072 /dev/zero; echo crash-tail >&2; kill -KILL $$"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = [Vec::new(), Vec::new()];
        crate::pump(child.stdout.take(), child.stderr.take(), |kind, data| out[usize::from(kind != FRAME_STDOUT)].extend_from_slice(data));
        assert!(!child.wait().unwrap().success());
        assert_eq!(out, [vec![0; 131072], b"crash-tail\n".to_vec()]);
    }

    #[test]
    fn followed_logs_catch_up_through_exit() {
        let mut app = APP.lock().unwrap();
        (app.output, app.state) = (Output::default(), State::Running(1));
        app.push(&vec![b'x'; RING_BYTES + 10]);
        drop(app);
        let reader = thread::spawn(|| {
            let mut frames = Vec::new();
            logs(&mut frames, 0, true).map(|_| frames)
        });
        let mut app = APP.lock().unwrap();
        app.state = State::Exited(7);
        app.push(b"crash-tail\n");
        let end = app.output.end;
        drop(app);
        let frames = reader.join().unwrap().unwrap();
        // Asked from 0, behind the ring: told where it goes on from (FRAME_LOST, u64 LE) first.
        // The reader may get ahead of the second push or fall behind it again, so walk the
        // frames: a FRAME_LOST jumps to where it goes on from, data moves on by its length.
        let (mut data, mut rest, mut lost, mut at) = (Vec::new(), &frames[..], Vec::new(), 0);
        while rest[0] == FRAME_STDOUT || rest[0] == FRAME_LOST {
            let n = u32::from_le_bytes(rest[1..5].try_into().unwrap()) as usize;
            match rest[0] {
                FRAME_LOST => {
                    at = u64::from_le_bytes(rest[5..5 + n].try_into().unwrap());
                    lost.push(at);
                }
                _ => {
                    data.extend_from_slice(&rest[5..5 + n]);
                    at += n as u64;
                }
            }
            rest = &rest[5 + n..];
        }
        assert!(frames[0] == FRAME_LOST && lost.iter().all(|&at| at == 10 || at == 21), "{lost:?}");
        assert_eq!(&rest[5..], format!("exited 7 {end}").as_bytes());
        assert_eq!(at, end, "the reader ends exactly where the output does");
        let tail = data.len() - b"crash-tail\n".len();
        assert!(data[..tail].iter().all(|&b| b == b'x') && &data[tail..] == b"crash-tail\n");
    }

    #[test]
    fn conf_lines_and_escapes() {
        let c = parse_conf("arg /bin/app\narg a\\nb\\\\c\nenv K=v=w\nenv BARE\ncwd /srv\nuid 7\ngid 8\ngroups 9 10\nx y").unwrap();
        assert_eq!(c.argv, ["/bin/app", "a\nb\\c"]);
        assert_eq!(c.env, [("K".into(), "v=w".into()), ("BARE".into(), String::new())]);
        assert_eq!((c.cwd.as_str(), c.uid, c.gid, c.groups), ("/srv", 7, 8, vec![9, 10]));
        assert!(parse_conf("cwd /").is_err());
        assert!(parse_conf("arg x\nuid root").is_err());
    }
}
