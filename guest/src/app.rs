//! The image's entrypoint, supervised by flexvm-init. `/etc/flexvm/app.conf` (written at build) has one
//! `key value` per line, `\` and newline escaped as `\\` and `\n`: `arg`/`env` (repeated), `cwd`, `uid`,
//! `gid`, `groups`. Requests: `APP [<hex settings>]`, `APPSTATUS`, `LOGS <offset> <follow 0|1>`,
//! `APPIN <stream>`, `PROBE <port>`, `CHECK <timeout ms> <hex shell command>`, `QUIESCE`, `SIGNAL <signo>`.
//! `APP`'s settings are a run's (`run -e`, `--entrypoint`, `-i`, `-t`), in app.conf's form: `env` lines
//! replace the image's of their key, `arg` lines (if any) its whole argv, `stdin` keeps its stdin open
//! (for `APPIN`), `tty` gives it a pty. `LOGS` frames are the app's stdout and stderr (a pty's output is
//! stdout) and FRAME_NOTE, flexvm-init's lines. `APPIN` (input.rs) feeds client `stream`'s input frames to
//! the app's stdin, answering `ok <taken> <tty 0|1>` (or `closed <tty>`), then FRAME_ACK as it takes
//! them; a newer `APPIN` takes over. `SIGNAL` goes to the app's process alone, as docker kill's does. A non-root app runs with no_new_privs and an empty bounding set, so setuid binaries and file
//! capabilities cannot take it back to root.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::input::{feed, Stdin};
use crate::proto::{FRAME_ACK, FRAME_LOST, FRAME_NOTE};
use crate::session::{cannot_run, Output, DRAIN};
use crate::user::resolve_user;
use crate::{fail, kill_running, mem, msg, spawn_watched, wait_exit, write_frame, Statuses, FRAME_STDOUT};

const CONF: &str = "/etc/flexvm/app.conf";
static CONFIG: LazyLock<io::Result<Conf>> = LazyLock::new(|| read_conf(CONF));
const RING_BYTES: usize = 1 << 20;

/// Capture the image's configuration before serving requests or starting any app process.
pub fn init() {
    LazyLock::force(&CONFIG);
}

fn config() -> io::Result<&'static Conf> {
    CONFIG.as_ref().map_err(|e| io::Error::new(e.kind(), e.to_string()))
}

pub const VERBS: [&str; 8] = ["APP", "APPSTATUS", "LOGS", "APPIN", "PROBE", "CHECK", "QUIESCE", "SIGNAL"];

#[derive(Clone, Copy, Default)]
enum State {
    #[default]
    Idle,
    Running(i32),
    Exited(i32),
}

#[derive(Default)]
struct App {
    state: State,
    /// The running app's reaper token: a signal reaches it only while it is unreaped (`kill_running`).
    token: u64,
    output: Output,
    /// `run -i`'s: the running app's stdin.
    stdin: Option<Arc<Stdin>>,
    /// `run -t`'s.
    tty: bool,
    /// The `APPIN` feeding it (a duplicate of its connection, to shut it down when replaced), by number. No
    /// connection yet while it reads what its stream took: its hello is not sent, so nothing may shut it down.
    appin: Option<(u64, Option<File>)>,
    appins: u64,
}

static APP: LazyLock<Mutex<App>> = LazyLock::new(|| Mutex::new(App::default()));
static CHANGED: Condvar = Condvar::new();

impl App {
    fn push(&mut self, kind: u8, data: &[u8]) {
        self.output.push(kind, data, RING_BYTES);
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
        crate::sock_timeout(out.as_raw_fd(), libc::SO_SNDTIMEO, Some(Duration::from_secs(5)));
    }
    let reply = match verb {
        // `applied`: the run's settings were (an older agent ignored them).
        "APP" => start(arg, statuses).map(|pid| format!("ok {pid}{}", if arg.trim().is_empty() { "" } else { " applied" })),
        "APPSTATUS" => Ok(APP.lock().unwrap().status()),
        "CHECK" => check(arg, statuses),
        "SIGNAL" => signal(arg, statuses),
        "LOGS" => {
            let mut a = arg.split_whitespace();
            let offset = a.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            return logs(out, offset, a.next() == Some("1"));
        }
        "APPIN" => return appin(arg, out, &[]),
        "PROBE" => match arg.trim().parse::<u16>() {
            Ok(port) => TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_millis(500)).map(|_| "ok".into()),
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
    reply.map_or_else(|e| fail(out, e), |m| msg(out, m))
}

#[derive(Clone)]
pub(crate) struct Conf {
    argv: Vec<String>,
    env: Vec<(String, String)>,
    cwd: String,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    /// A run's `-i` and `-t`.
    stdin: bool,
    tty: bool,
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
    let mut c = Conf { argv: vec![], env: vec![], cwd: "/".into(), uid: 0, gid: 0, groups: vec![], stdin: false, tty: false };
    let num = |v: &str| v.trim().parse::<u32>().map_err(|_| io::Error::other(format!("{CONF}: bad id {v:?}")));
    // Only LF delimits records; str::lines() also removes a value's trailing CR.
    for line in text.split('\n') {
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
    Ok(c)
}

/// The image's configuration with a run's settings (`APP`'s): `env K=V` replaces the image's `K`,
/// `arg` lines (any) the whole argv, as `docker run --entrypoint` drops the image's command too.
fn with_settings(c: &Conf, text: &str) -> io::Result<Conf> {
    let (mut c, mut argv) = (c.clone(), None);
    for line in text.split('\n').filter(|l| !l.is_empty()) {
        let (k, v) = line.split_once(' ').unwrap_or((line, ""));
        match k {
            "arg" => argv.get_or_insert_with(Vec::new).push(unescape(v)),
            "env" => set_env(&mut c, &unescape(v)),
            "stdin" => c.stdin = true,
            "tty" => c.tty = true,
            _ => return Err(io::Error::other(format!("unknown app setting {k:?}"))),
        }
    }
    if let Some(argv) = argv {
        c.argv = argv;
    }
    Ok(c)
}

/// `K=V` (or a bare `K`, empty) in place of `c`'s `K`: a run's `-e`, and an exec's on top of it.
/// With a pty, as docker's -t: TERM, unless set.
fn terminal_env(c: &mut Conf) {
    if !c.env.iter().any(|(k, _)| k == "TERM") {
        set_env(c, "TERM=xterm");
    }
}

fn set_env(c: &mut Conf, kv: &str) {
    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
    c.env.retain(|(e, _)| e != k);
    c.env.push((k.into(), v.into()));
}

fn unhex(hex: &str) -> Option<Vec<u8>> {
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect()
}

fn command<S: AsRef<std::ffi::OsStr>>(c: &Conf, argv: &[S]) -> Command {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).env_clear().envs(c.env.iter().map(|(k, v)| (k, v))).current_dir(&c.cwd).stdin(Stdio::null());
    // Docker's: the hostname (the VM's name, `HOSTNAME` in main.rs), unless the image or run sets one.
    if !c.env.iter().any(|(k, _)| k == "HOSTNAME") {
        cmd.env("HOSTNAME", std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim_end());
    }
    cmd
}

/// The configuration the app was last started with (the image's and the run's settings): what an exec
/// inherits, as docker exec does a container's. The image's until an app is started.
static RUN: Mutex<Option<Conf>> = Mutex::new(None);

/// An exec's command: argv with no shell, run as the app is (its environment, directory and
/// credentials, without its own session), with `-u`, `-w` and `-e` overriding those for it alone. Its
/// credentials are `credentials`' (without a session of its own), applied once the caller has done what needs root (its cgroup).
pub(crate) fn exec_command(e: &crate::proto::Exec) -> io::Result<(Command, Conf)> {
    let base = RUN.lock().unwrap().clone();
    let base = match base {
        Some(c) => c,
        None => config()?.clone(),
    };
    // Only `-u` needs them (the image's user was resolved at pull), through links as pull reads them. One
    // there but unreadable (a dangling link too) fails the exec: read as empty, a numeric user's group would become 0.
    let read = |p: &str| match e.user.as_ref().map(|_| crate::read_etc(p.as_ref(), 0)) {
        Some(Err(err)) if err.kind() != io::ErrorKind::NotFound || std::fs::symlink_metadata(p).is_ok() => {
            Err(cannot_run(126, format!("cannot read {p}: {err}")))
        }
        got => Ok(got.and_then(Result::ok).map(|(text, _)| text).unwrap_or_default()),
    };
    let c = exec_conf(base, e, &read("/etc/passwd")?, &read("/etc/group")?)?;
    Ok((command(&c, &e.argv), c))
}

/// `APPIN`: feeds the app's stdin until the connection closes, a newer one takes over or the app exits.
/// `pending`: input that came with the request.
pub(crate) fn appin(arg: &str, out: &File, pending: &[u8]) -> io::Result<()> {
    appin_on(&APP, arg, out, pending, || ())
}

/// `appin` on `apps`; `claimed` runs once its slot is claimed, before its hello (a test's app exits there).
fn appin_on(apps: &Mutex<App>, arg: &str, out: &File, pending: &[u8], claimed: impl FnOnce()) -> io::Result<()> {
    crate::sock_timeout(out.as_raw_fd(), libc::SO_SNDTIMEO, Some(Duration::from_secs(5)));
    let stream = arg.trim().parse::<u64>().map_err(|_| io::Error::other(format!("bad stream {arg:?}")))?;
    // Claimed with no connection, which the app's end (`app_ended`) would shut down with no hello sent: the client
    // must always be told "ok" or "closed", or a fast `run -i` app's status is lost (#832).
    let (stdin, me) = {
        let mut app = apps.lock().unwrap();
        let Some(stdin) = app.stdin.clone().filter(|_| matches!(app.state, State::Running(_))) else {
            return msg(out, format!("closed {}", u8::from(app.tty)));
        };
        app.appins += 1;
        let me = app.appins;
        if let Some((_, Some(old))) = app.appin.replace((me, None)) {
            unsafe { libc::shutdown(old.as_raw_fd(), libc::SHUT_RDWR) };
        }
        (stdin, me)
    };
    // Not under APP's lock: the feeder replaced may hold the stdin's while it asks `current` (APP's) once more.
    let taken = stdin.taken(stream);
    claimed();
    {
        let mut app = apps.lock().unwrap();
        let mine = app.appin.as_ref().is_some_and(|(id, _)| *id == me);
        if !matches!(app.state, State::Running(_)) {
            return msg(out, format!("closed {}", u8::from(app.tty)));
        }
        // A newer one took over already: this one ends as though it was shut down.
        if !mine {
            return Ok(());
        }
        let hello = msg(out, format!("ok {taken} {}", u8::from(stdin.tty()))).and_then(|()| out.try_clone());
        match hello {
            Ok(conn) => app.appin = Some((me, Some(conn))),
            Err(e) => {
                app.appin = None;
                return Err(e);
            }
        }
    }
    crate::sock_timeout(out.as_raw_fd(), libc::SO_RCVTIMEO, None);
    let current = || {
        let app = apps.lock().unwrap();
        app.appin.as_ref().is_some_and(|(id, _)| *id == me) && matches!(app.state, State::Running(_))
    };
    let mut ack_error = None;
    let fed = feed(&mut pending.chain(out.try_clone()?), &stdin, stream, &current, &mut |taken| {
        if let Err(e) = write_frame(out, FRAME_ACK, &taken.to_le_bytes()) {
            ack_error.get_or_insert(e);
        }
    });
    let mut app = apps.lock().unwrap();
    if app.appin.as_ref().is_some_and(|(id, _)| *id == me) {
        app.appin = None;
    }
    drop(app);
    ack_error.map_or(fed.map(drop), Err)
}

/// The app's end, once its output is drained: its `APPIN` is shut down (its client then sees it closed).
fn app_ended(app: &mut App, pid: i32, code: i32) {
    (app.state, app.stdin) = (State::Exited(code), None);
    if let Some((_, Some(conn))) = app.appin.take() {
        unsafe { libc::shutdown(conn.as_raw_fd(), libc::SHUT_RDWR) };
    }
    app.push(FRAME_NOTE, format!("flexvm-init: pid {pid} exited with status {code}\n").as_bytes());
}

/// A user missing from the guest's /etc/passwd (resolved as pull resolves the image's), or a directory
/// that is not one, is the command's failure (126), as with docker exec.
fn exec_conf(mut c: Conf, e: &crate::proto::Exec, passwd: &str, group: &str) -> io::Result<Conf> {
    if e.argv.first().is_none_or(|p| p.is_empty()) {
        return Err(io::Error::other("exec needs CMD"));
    }
    if let Some(user) = &e.user {
        let (uid, gid, home, groups) = resolve_user(user, passwd, group).map_err(|e| cannot_run(126, e))?;
        (c.uid, c.gid, c.groups) = (uid, gid, groups);
        // Pull set HOME for the image's user; this one's is the passwd entry's, unless -e names one.
        set_env(&mut c, &format!("HOME={home}"));
    }
    for kv in &e.env {
        if kv.split_once('=').is_none_or(|(k, _)| k.is_empty()) {
            return Err(io::Error::other(format!("exec env needs K=V: {kv:?}")));
        }
        set_env(&mut c, kv);
    }
    if let Some(dir) = &e.workdir {
        c.cwd = dir.clone();
    }
    if e.tty {
        terminal_env(&mut c);
    }
    if !std::fs::metadata(&c.cwd).is_ok_and(|m| m.is_dir()) {
        let why = std::fs::metadata(&c.cwd).map_or_else(|e| e.to_string(), |_| "not a directory".into());
        return Err(cannot_run(126, format!("cannot change to directory {}: {why}", c.cwd)));
    }
    Ok(c)
}

/// Runs a readiness command as the app would (`ok`, `exit <code>` or `timeout`) in its own cgroup, killed,
/// checked empty and removed at the end; failed cleanup is an error, never `ok`. A non-root check fails
/// closed without that cgroup; a root check is trusted, and without cgroup2 its session is killed instead.
fn check(arg: &str, statuses: &Statuses) -> io::Result<String> {
    let (ms, hex) = arg.trim().split_once(' ').ok_or_else(|| io::Error::other("usage: CHECK <ms> <hex>"))?;
    let ms: u64 = ms.parse().map_err(|_| io::Error::other("bad timeout"))?;
    let bytes = unhex(hex).ok_or_else(|| io::Error::other("bad command encoding"))?;
    let c = config()?;
    let mut cg = match CheckGroup::new() {
        Ok(g) => Some(g),
        Err(_) if c.uid == 0 => None,
        Err(e) => return Err(io::Error::other(format!("cannot contain a non-root readiness check: {e}"))),
    };
    let mut cmd = command(c, &["/bin/sh", "-c", &String::from_utf8_lossy(&bytes)]);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    match &cg {
        Some(g) => mem::enter(&mut cmd, g.procs.clone(), true),
        None => mem::work_procs().into_iter().for_each(|work| mem::enter(&mut cmd, work, false)),
    }
    credentials(&mut cmd, c, true);
    let (child, _, token) = spawn_watched(&mut cmd, statuses, false).map_err(|e| io::Error::new(e.kind(), format!("cannot run /bin/sh: {e}")))?;
    let pid = child.id() as i32;
    let code = wait_exit(statuses, token, Some(Instant::now() + Duration::from_millis(ms)));
    // Kill whatever is left, the leader included if it timed out. Without a cgroup only its session
    // (group) can be, and only while the leader is unreaped: a reaped leader's pid may be anyone's.
    let cleaned = match &mut cg {
        Some(g) => g.cleanup(),
        None => {
            kill_running(statuses, pid, token, true, libc::SIGKILL);
            Ok(())
        }
    };
    if code.is_none() {
        kill_running(statuses, pid, token, false, libc::SIGKILL);
        if wait_exit(statuses, token, Some(Instant::now() + Duration::from_secs(2))).is_none() {
            forget(statuses, token);
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

fn read_conf(path: impl AsRef<std::path::Path>) -> io::Result<Conf> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    parse_conf(&text)
}

/// The check groups not yet removed of checks under way: a sweep leaves them be (one just created is empty).
static CHECK_GROUPS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Removes the `flexvm-check-*` groups under `parent` that no check under way holds: left behind
/// when a killed task outlived both `cleanup` and the drop's retry (D state, say). One still
/// populated stays (rmdir refuses it) for a later sweep. Under `live`, so none is created meanwhile.
fn sweep_check_groups(parent: &str, live: &[String]) {
    for e in std::fs::read_dir(parent).into_iter().flatten().flatten() {
        let path = format!("{parent}/{}", e.file_name().to_string_lossy());
        if e.file_name().to_string_lossy().starts_with("flexvm-check-") && e.file_type().is_ok_and(|t| t.is_dir()) && !live.contains(&path) {
            let _ = std::fs::remove_dir(&path);
        }
    }
}

/// Dropped without `cleanup` (an early return, or a cleanup that failed), it is killed and removed.
struct CheckGroup {
    dir: String,
    procs: CString,
    done: bool,
    /// `cleanup` ran (and failed): the drop does not wait out its tasks again, past the host's deadline.
    tried: bool,
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
        {
            let mut live = CHECK_GROUPS.lock().unwrap();
            sweep_check_groups(parent, &live);
            std::fs::create_dir(&dir).map_err(|e| io::Error::other(format!("create {dir}: {e}")))?;
            live.push(dir.clone());
        }
        Self::from_dir(dir)
    }

    /// Done: removed, or left for a sweep.
    fn finished(&mut self) {
        self.done = true;
        CHECK_GROUPS.lock().unwrap().retain(|d| *d != self.dir);
    }

    fn from_dir(dir: String) -> io::Result<CheckGroup> {
        let mut g = CheckGroup { procs: CString::new(format!("{dir}/cgroup.procs")).unwrap(), dir, done: false, tried: false };
        // Needs cgroup.kill (Linux 5.14) to kill every task at once.
        if !std::path::Path::new(&format!("{}/cgroup.kill", g.dir)).exists() {
            g.finished();
            std::fs::remove_dir(&g.dir)?;
            return Err(io::Error::other("the kernel has no cgroup.kill"));
        }
        Ok(g)
    }

    /// Done only once the group is removed: until then the drop tries again.
    fn cleanup(&mut self) -> io::Result<()> {
        self.tried = true;
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
        std::fs::remove_dir(&self.dir)?;
        self.finished();
        Ok(())
    }
}

impl Drop for CheckGroup {
    fn drop(&mut self) {
        if !self.done {
            let res = if self.tried { std::fs::remove_dir(&self.dir) } else { self.cleanup() };
            if let Err(e) = res {
                let _ = writeln!(io::stderr(), "flexvm-init: readiness check group: {e} (the next check removes it)");
            }
            self.finished();
        }
    }
}

/// A session of its own if `own_session`, the app's credentials and, if non-root, no capabilities and
/// no_new_privs; done by hand because CommandExt::uid would clear the supplementary groups.
pub(crate) fn credentials(cmd: &mut Command, c: &Conf, own_session: bool) {
    let (uid, gid, groups) = (c.uid, c.gid, c.groups.clone());
    unsafe {
        cmd.pre_exec(move || {
            if own_session {
                crate::os(libc::setsid())?;
            }
            if uid != 0 {
                // No way back to root: drop the bounding set (EINVAL: past the kernel's last capability).
                for cap in 0..64 {
                    if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && *libc::__errno_location() != libc::EINVAL {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
            let ok = libc::setgroups(groups.len(), groups.as_ptr()) == 0
                && libc::setgid(gid) == 0
                && libc::setuid(uid) == 0
                && (uid == 0 || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            ok.then_some(()).ok_or_else(io::Error::last_os_error)
        });
    }
}

fn start(settings: &str, statuses: &Statuses) -> io::Result<i32> {
    let mut app = APP.lock().unwrap();
    if let State::Running(pid) = app.state {
        return Ok(pid);
    }
    let settings = unhex(settings.trim()).ok_or_else(|| io::Error::other("bad app settings encoding"))?;
    let c = &mut with_settings(config()?, &String::from_utf8_lossy(&settings))?;
    if c.argv.is_empty() {
        return Err(io::Error::other("the image has no entrypoint or command: there is no app"));
    }
    if c.tty {
        terminal_env(c);
    }
    let pty = c.tty.then(|| crate::input::openpty(None)).transpose()?;
    let mut cmd = command(c, &c.argv);
    crate::input::stdio(&mut cmd, pty.as_ref().map(|(_, slave)| slave), c.stdin)?;
    if let Some(work) = mem::work_procs() {
        mem::enter(&mut cmd, work, true);
    }
    // A pty's session is its own already.
    credentials(&mut cmd, c, pty.is_none());
    let (pid, _) = launch(&mut app, &mut cmd, statuses, pty.map(|(master, _)| master)).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", c.argv[0])))?;
    // Without `-i`, a pty's input is not the client's either.
    if !c.stdin {
        app.stdin = None;
    }
    *RUN.lock().unwrap() = Some(c.clone());
    app.push(FRAME_NOTE, format!("flexvm-init: started {:?} as pid {pid}\n", c.argv).as_bytes());
    Ok(pid)
}

/// Its supervisor (returned) logs output as an exec session's: until its exit and `DRAIN` more, then
/// discarded, so descendants that hold the pipes never write into the log once it is marked exited.
/// Its stdio is `input::stdio`'s; `pty`, its master.
fn launch(app: &mut App, cmd: &mut Command, statuses: &Statuses, pty: Option<File>) -> io::Result<(i32, thread::JoinHandle<()>)> {
    let tty = pty.is_some();
    let (mut child, exited, token) = spawn_watched(cmd, statuses, true)?;
    let pid = child.id() as i32;
    let Some(exited) = exited else { return Err(unwatched(statuses, pid, token, io::Error::other("cannot open a pidfd to watch it"))) };
    let (streams, stdin) = crate::input::streams(&mut child, pty).map_err(|e| unwatched(statuses, pid, token, e))?;
    let watched = statuses.clone();
    let supervisor = thread::Builder::new()
        .spawn(move || {
            crate::discard(crate::pump_until(streams, Some(exited), DRAIN, |kind, data| {
                APP.lock().unwrap().push(kind, data);
                Duration::ZERO
            }));
            let code = wait_exit(&watched, token, None).expect("no deadline");
            app_ended(&mut APP.lock().unwrap(), pid, code);
        })
        .map_err(|e| unwatched(statuses, pid, token, e))?;
    (app.state, app.token, app.tty, app.stdin) = (State::Running(pid), token, tty, stdin.map(Arc::new));
    Ok((pid, supervisor))
}

/// `kill -s SIGNAL NAME`: to the app's process (not its group), while it runs.
fn signal(arg: &str, statuses: &Statuses) -> io::Result<String> {
    signal_app(&APP.lock().unwrap(), arg, statuses)
}

fn signal_app(app: &App, arg: &str, statuses: &Statuses) -> io::Result<String> {
    let sig = arg.trim().parse::<i32>().ok().filter(|s| (1..=64).contains(s)).ok_or_else(|| io::Error::other(format!("bad signal {arg:?}")))?;
    match app.state {
        State::Running(pid) if kill_running(statuses, pid, app.token, false, sig) => Ok("ok".into()),
        State::Idle => Err(io::Error::other("no app was started")),
        _ => Err(io::Error::other("the app is not running (it exited)")),
    }
}

/// Without a pidfd or supervisor thread the app cannot be watched: its session is killed and reaped.
pub(crate) fn unwatched(statuses: &Statuses, pid: i32, token: u64, error: io::Error) -> io::Error {
    // By group even if the leader exited at once and was reaped: no new process gets the group's id while
    // a member lives, and once none does the pid comes back only after the pid space wraps, not since the spawn.
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    if wait_exit(statuses, token, Some(Instant::now() + Duration::from_secs(2))).is_none() {
        // Forgotten: reaped later, it is an orphan whose status is not kept.
        forget(statuses, token);
    }
    error
}

/// A late reap must not retain a status after its watcher has given up.
fn forget(statuses: &Statuses, token: u64) {
    let mut map = statuses.0.lock().unwrap();
    map.running.retain(|_, t| *t != token);
    map.finished.remove(&token);
}

/// Output from `offset` (clamped to the ring), then `<status> <next offset>`; with `follow`, until exit.
/// Following, a clamp is told first (FRAME_LOST, the offset output goes on from, u64 LE), so a
/// reader that fell behind the ring keeps its offset right.
fn logs(mut out: impl Write, mut offset: u64, follow: bool) -> io::Result<()> {
    let stop = {
        let app = APP.lock().unwrap();
        if follow {
            u64::MAX
        } else {
            app.output.end
        }
    };
    loop {
        let (chunk, status, done, moved) = {
            let (app, _) = CHANGED
                // Past the end (`attach` asks for what comes from now on), it is clamped, and told, at once.
                .wait_timeout_while(APP.lock().unwrap(), Duration::from_secs(5), |a| follow && offset == a.output.end && matches!(a.state, State::Running(_)))
                .unwrap();
            let clamped = offset.clamp(app.output.start, app.output.end);
            let moved = clamped != offset;
            offset = clamped;
            let (kind, chunk) = app.output.read_chunk(offset).map_or_else(
                || (FRAME_STDOUT, Vec::new()),
                |(kind, data)| (kind, data[..data.len().min(64 * 1024).min(stop.saturating_sub(offset) as usize)].to_vec()),
            );
            ((kind, chunk), app.status(), !follow || !matches!(app.state, State::Running(_)), moved)
        };
        let (kind, chunk) = chunk;
        if follow && moved {
            write_frame(&mut out, FRAME_LOST, &offset.to_le_bytes())?;
        }
        offset += chunk.len() as u64;
        // An empty frame doubles as a keepalive that notices a closed connection.
        write_frame(&mut out, kind, &chunk)?;
        if done && chunk.is_empty() {
            return msg(out, format!("{status} {offset}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn exec(argv: &[&str], env: &[&str], workdir: Option<&str>, user: Option<&str>) -> crate::proto::Exec {
        let strings = |v: &[&str]| v.iter().map(|s| s.to_string()).collect();
        crate::proto::Exec { argv: strings(argv), env: strings(env), workdir: workdir.map(String::from), user: user.map(String::from), ..Default::default() }
    }

    #[test]
    fn exec_inherits_the_runs_settings_and_overrides_env_and_directory() {
        let image = parse_conf("arg /app\nenv K=image\nenv KEEP=yes\ncwd /\nuid 1000\ngid 2000\ngroups 2000 42\n").unwrap();
        // As docker exec sees a container's `run -e`.
        let run = with_settings(&image, "env KEEP=run\n").unwrap();
        let c = exec_conf(run.clone(), &exec(&["true"], &["K=first", "K=last=two", "EMPTY="], Some("/tmp"), None), "", "").unwrap();
        assert_eq!(c.cwd, "/tmp");
        assert_eq!(c.env, [("KEEP".into(), "run".into()), ("K".into(), "last=two".into()), ("EMPTY".into(), "".into())]);
        assert_eq!((c.uid, c.gid, c.groups.clone()), (1000, 2000, vec![2000, 42]));
        let cmd = command(&c, &["true"]);
        let mut env: std::collections::BTreeMap<_, _> = cmd.get_envs().map(|(k, v)| (k.to_str().unwrap(), v.unwrap().to_str().unwrap())).collect();
        // The host's own hostname here; the VM's in a guest.
        assert!(env.remove("HOSTNAME").is_some());
        assert_eq!(env, [("EMPTY", ""), ("K", "last=two"), ("KEEP", "run")].into());
        let named = with_settings(&image, "env HOSTNAME=set\n").unwrap();
        assert_eq!(command(&named, &["true"]).get_envs().filter(|(k, _)| *k == "HOSTNAME").count(), 1);
        assert_eq!(exec_conf(run.clone(), &exec(&["true"], &[], None, None), "", "").unwrap().cwd, "/");
        for bad in [exec(&["true"], &["BAD"], None, None), exec(&["true"], &["=x"], None, None), exec(&[], &[], None, None), exec(&[""], &[], None, None)] {
            assert!(exec_conf(run.clone(), &bad, "", "").is_err());
        }
    }

    #[test]
    fn exec_runs_argv_without_a_shell() {
        let words = ["/usr/bin/printf", "%s\n", "a b", "", "$HOME", "x; echo wrong", "'quoted'"];
        let c = parse_conf("cwd /\n").unwrap();
        let output = command(&c, &words).output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"a b\n\n$HOME\nx; echo wrong\n'quoted'\n");
    }

    #[test]
    fn exec_as_another_user_gets_its_home_and_bad_users_or_directories_cannot_run() {
        let c = parse_conf("arg /app\nenv HOME=/root\nenv K=v\ncwd /\n").unwrap();
        let passwd = "nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n";
        let n = exec_conf(c.clone(), &exec(&["id"], &[], Some("/tmp"), Some("nobody")), passwd, "").unwrap();
        assert_eq!((n.uid, n.gid, n.groups.clone()), (65534, 65534, vec![65534]));
        assert_eq!(n.env, [("K".into(), "v".into()), ("HOME".into(), "/nonexistent".into())]);
        let h = exec_conf(c.clone(), &exec(&["id"], &["HOME=/h"], None, Some("nobody")), passwd, "").unwrap();
        assert_eq!(h.env.last().unwrap(), &("HOME".into(), "/h".into()), "-e HOME wins");
        assert_eq!(exec_conf(c.clone(), &exec(&["id"], &[], None, None), passwd, "").unwrap().env, c.env);
        let status = format!("{}126", crate::proto::EXIT_STATUS);
        for (cwd, user) in [(Some("/nonexistent-flexvm-dir"), None), (Some("/etc/passwd"), None), (None, Some("missing"))] {
            let e = exec_conf(c.clone(), &exec(&["id"], &[], cwd, user), passwd, "").err().unwrap();
            assert!(e.to_string().ends_with(&status), "{e}");
        }
    }

    #[test]
    fn exec_users_resolve_numeric_names_and_explicit_groups() {
        let passwd = "app:x:1000:1000::/home/app:/bin/sh\n";
        let groups = "app:x:1000:\nstaff:x:2000:app\nextra:x:42:app\n";
        for user in ["app", "1000", "app:"] {
            assert_eq!(resolve_user(user, passwd, groups).unwrap(), (1000, 1000, "/home/app".into(), vec![1000, 2000, 42]));
        }
        for user in ["app:staff", "1000:2000"] {
            assert_eq!(resolve_user(user, passwd, groups).unwrap(), (1000, 2000, "/home/app".into(), vec![2000]));
        }
        assert_eq!(resolve_user("9999:42", "", "").unwrap(), (9999, 42, "/".into(), vec![42]));
        assert!(resolve_user("missing", passwd, groups).is_err());
        assert!(resolve_user("app:missing", passwd, groups).is_err());
    }

    #[test]
    fn readiness_token_is_forgotten_even_if_reaped_during_timeout() {
        for reaped in [false, true] {
            let statuses = Statuses::default();
            let (pid, token) = (123, 7);
            statuses.0.lock().unwrap().running.insert(pid, token);
            if reaped {
                assert!(statuses.0.lock().unwrap().reaped(pid, 0));
            }
            forget(&statuses, token);
            assert!(statuses.0.lock().unwrap().is_empty());
            assert!(!statuses.0.lock().unwrap().reaped(pid, 0), "a late reap is an orphan");
            assert!(statuses.0.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn unsupported_check_group_is_removed() {
        let dir = crate::test_util::TempDir::new("check-group");
        assert!(CheckGroup::from_dir(dir.to_str().unwrap().into()).err().unwrap().to_string().contains("cgroup.kill"));
        assert!(!dir.exists());
    }

    /// A cleanup that could not remove the group leaves it to the drop, which tries again.
    #[test]
    fn check_group_is_done_only_once_removed() {
        let dir = crate::test_util::TempDir::new("check-group-left");
        std::fs::write(dir.join("cgroup.kill"), "").unwrap();
        std::fs::write(dir.join("cgroup.events"), "populated 0\n").unwrap();
        let mut g = CheckGroup::from_dir(dir.to_str().unwrap().into()).unwrap();
        // A plain directory with files in it: rmdir fails, as on a group a task still holds.
        assert!(g.cleanup().is_err());
        assert!(!g.done);
        g.done = true;
    }

    #[test]
    fn leftover_check_groups_are_swept() {
        let dir = crate::test_util::TempDir::new("check-sweep");
        let parent = dir.to_str().unwrap();
        for d in ["flexvm-check-1", "flexvm-check-2", "flexvm-check-3", "other"] {
            std::fs::create_dir(dir.join(d)).unwrap();
        }
        // Populated: rmdir refuses it.
        std::fs::write(dir.join("flexvm-check-3/task"), "").unwrap();
        sweep_check_groups(parent, &[format!("{parent}/flexvm-check-2")]);
        assert!(!dir.join("flexvm-check-1").exists());
        assert!(dir.join("flexvm-check-2").exists(), "a check under way keeps its group");
        assert!(dir.join("flexvm-check-3").exists());
        assert!(dir.join("other").exists());
    }

    #[test]
    fn supervisor_spawn_error_kills_and_reaps_the_child() {
        let statuses = Statuses::default();
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("100").process_group(0);
        let (child, _, token) = spawn_watched(&mut cmd, &statuses, false).unwrap();
        let pid = child.id() as i32;
        let watched = statuses.clone();
        let reaper = thread::spawn(move || {
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
            assert!(watched.0.lock().unwrap().reaped(pid, 128 + libc::SIGKILL));
            watched.1.notify_all();
        });
        let error = unwatched(&statuses, pid, token, io::Error::from_raw_os_error(libc::EAGAIN));
        assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
        reaper.join().unwrap();
        assert!(statuses.0.lock().unwrap().is_empty());
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
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
        crate::pump_until(crate::outputs(&mut child), None, Duration::ZERO, |kind, data| {
            out[usize::from(kind != FRAME_STDOUT)].extend_from_slice(data);
            Duration::ZERO
        });
        assert!(!child.wait().unwrap().success());
        assert_eq!(out, [vec![0; 131072], b"crash-tail\n".to_vec()]);
    }

    #[test]
    fn descendants_holding_the_pipes_leave_nothing_behind() {
        // Alone in a process: the reaper waits on every child, and this test owns APP.
        const CHILD: &str = "FLEXVM_APP_TEST";
        if std::env::var_os(CHILD).is_none() {
            let name = "app::tests::descendants_holding_the_pipes_leave_nothing_behind";
            assert!(Command::new(std::env::current_exe().unwrap()).args(["--exact", name]).env(CHILD, "1").status().unwrap().success());
            return;
        }
        let statuses = Statuses::default();
        let reaper = statuses.clone();
        thread::spawn(move || crate::reap(reaper));
        let count = |dir: &str| std::fs::read_dir(format!("/proc/self/{dir}")).unwrap().count();
        let (tasks, fds) = (count("task"), count("fd"));
        for _ in 0..3 {
            let mut cmd = Command::new("/bin/sh");
            cmd.args(["-c", "echo early; (sleep 3; echo late) & exit 0"]);
            crate::input::stdio(&mut cmd, None, false).unwrap();
            let begun = Instant::now();
            let (_, supervisor) = launch(&mut APP.lock().unwrap(), &mut cmd, &statuses, None).unwrap();
            supervisor.join().unwrap();
            // Not waited for the descendants' `late` (checked in the log below): only reported.
            eprintln!("supervisor done in {:?} (drain {DRAIN:?})", begun.elapsed());
            assert!(matches!(APP.lock().unwrap().state, State::Exited(0)));
            // Only the discarder's thread is added, however many starts. A joined thread
            // can still be in /proc/self/task until the kernel finishes its exit.
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let remaining = count("task");
                if remaining == tasks + 1 {
                    break;
                }
                assert!(Instant::now() < deadline, "{remaining} tasks, expected {}", tasks + 1);
                thread::sleep(Duration::from_millis(20));
            }
        }
        // Once the descendants exit, their pipes are closed: only the discarder's wake pipe is left.
        let deadline = Instant::now() + Duration::from_secs(10);
        while count("fd") > fds + 2 {
            assert!(Instant::now() < deadline, "{} fds, {fds} before", count("fd"));
            thread::sleep(Duration::from_millis(50));
        }
        // Without a pidfd the app's whole group is killed, even once the leader was reaped, and its token cleared.
        let refuse = |script: &str, reaped: bool| {
            let mut cmd = Command::new("/bin/sh");
            cmd.args(["-c", script]).process_group(0);
            let (child, _, token) = spawn_watched(&mut cmd, &statuses, false).unwrap();
            let pid = child.id() as i32;
            // A leader that exits is reaped soon; one that runs (`sleep 100`) is not.
            let deadline = Instant::now() + Duration::from_secs(5);
            while reaped && !statuses.0.lock().unwrap().finished.contains_key(&token) {
                assert!(Instant::now() < deadline, "the leader was never reaped");
                thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(statuses.0.lock().unwrap().finished.contains_key(&token), reaped);
            assert!(unwatched(&statuses, pid, token, io::Error::other("pidfd")).to_string().contains("pidfd"));
            let deadline = Instant::now() + Duration::from_secs(5);
            while unsafe { libc::kill(-pid, 0) } == 0 {
                assert!(Instant::now() < deadline, "the app's group outlived it");
                thread::sleep(Duration::from_millis(20));
            }
        };
        refuse("sleep 100 & sleep 100", false);
        refuse("sleep 100 & exit 7", true);
        assert!(statuses.0.lock().unwrap().is_empty());
        // Reaping that outlasts the wait (a pid past pid_max, never reaped): the token is forgotten.
        let (pid, token) = (i32::MAX, crate::TOKENS.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        statuses.0.lock().unwrap().running.insert(pid, token);
        assert!(unwatched(&statuses, pid, token, io::Error::other("pidfd")).to_string().contains("pidfd"));
        assert!(!statuses.0.lock().unwrap().reaped(pid, 137));
        assert!(statuses.0.lock().unwrap().is_empty());
        let app = APP.lock().unwrap();
        let mut log = Vec::new();
        while let Some((_, data)) = app.output.read_chunk(log.len() as u64) {
            log.extend_from_slice(data);
        }
        let log = String::from_utf8(log).unwrap();
        assert_eq!((log.matches("early").count(), log.matches("exited with status 0").count()), (3, 3), "{log}");
        assert!(!log.contains("late"), "{log}");
    }

    #[test]
    fn followed_logs_catch_up_through_exit() {
        let mut app = APP.lock().unwrap();
        (app.output, app.state) = (Output::default(), State::Running(1));
        app.push(FRAME_STDOUT, &vec![b'x'; RING_BYTES + 10]);
        drop(app);
        let reader = thread::spawn(|| {
            let mut frames = Vec::new();
            logs(&mut frames, 0, true).map(|_| frames)
        });
        let mut app = APP.lock().unwrap();
        app.state = State::Exited(7);
        app.push(FRAME_STDOUT, b"crash-tail\n");
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
    fn cached_config_survives_replacement_and_removal() {
        let dir = crate::test_util::TempDir::new("cached-app-conf");
        let path = dir.join("app.conf");
        std::fs::write(&path, "arg /bin/app\nenv PATH=/usr/bin\ncwd /srv\nuid 1000\ngid 2000\ngroups 2000 42\n").unwrap();
        let cached = LazyLock::new(|| read_conf(&path));
        LazyLock::force(&cached).as_ref().unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "arg /bin/attacker\nenv PATH=/attacker\ncwd /\nuid 0\ngid 0\ngroups 0\n").unwrap();
        assert_eq!(read_conf(&path).unwrap().uid, 0);
        for remove in [false, true] {
            if remove {
                std::fs::remove_file(&path).unwrap();
            }
            let c = cached.as_ref().unwrap();
            assert_eq!((c.uid, c.gid, c.groups.as_slice()), (1000, 2000, [2000, 42].as_slice()));
            let cmd = command(c, &["/bin/sh", "-c", "ready"]);
            assert_eq!(cmd.get_current_dir().unwrap(), std::path::Path::new("/srv"));
            assert_eq!(
                cmd.get_envs().filter(|(k, _)| *k != "HOSTNAME").collect::<Vec<_>>(),
                [(std::ffi::OsStr::new("PATH"), Some(std::ffi::OsStr::new("/usr/bin")))]
            );
            assert_eq!(c.argv, ["/bin/app"]);
        }
    }

    #[test]
    fn cached_config_keeps_startup_errors() {
        let dir = crate::test_util::TempDir::new("cached-app-error");
        let path = dir.join("app.conf");
        let cached = LazyLock::new(|| read_conf(&path));
        assert!(cached.as_ref().err().unwrap().to_string().starts_with(&format!("{}: ", path.display())));
        assert_eq!(cached.as_ref().err().unwrap().kind(), io::ErrorKind::NotFound);
        std::fs::write(&path, "arg /bin/app\nuid 0\n").unwrap();
        assert!(read_conf(&path).is_ok());
        assert_eq!(cached.as_ref().err().unwrap().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn conf_preserves_whitespace_and_carriage_returns() {
        let c = parse_conf("arg /bin/app\r\narg \r\narg  a\r\\nb\\\\r \t\r\nenv FOO=bar\r\nenv EMPTY=\nenv CR=\r\ncwd /srv\r\n").unwrap();
        assert_eq!(c.argv, ["/bin/app\r", "\r", " a\r\nb\\r \t\r"]);
        assert_eq!(c.env, [("FOO".into(), "bar\r".into()), ("EMPTY".into(), "".into()), ("CR".into(), "\r".into())]);
        assert_eq!(c.cwd, "/srv\r");
        let cmd = command(&c, &c.argv);
        assert_eq!(cmd.get_program(), "/bin/app\r");
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["\r", " a\r\nb\\r \t\r"]);
        assert!(cmd.get_envs().any(|(k, v)| k == "FOO" && v == Some(std::ffi::OsStr::new("bar\r"))));
    }

    #[test]
    fn run_settings_override_env_by_key_and_replace_argv() {
        let image = parse_conf("arg nginx\narg -g\nenv PATH=/bin\nenv A=image\ncwd /srv\nuid 7").unwrap();
        let c = with_settings(&image, "env A=run\nenv NEW=a\\nb\n").unwrap();
        assert_eq!(c.argv, ["nginx", "-g"], "no arg lines: the image's argv");
        assert_eq!(c.env, [("PATH".into(), "/bin".into()), ("A".into(), "run".into()), ("NEW".into(), "a\nb".into())]);
        assert_eq!((c.cwd.as_str(), c.uid), ("/srv", 7));
        let c = with_settings(&image, "arg /bin/sh\narg -c\narg echo  hi\n").unwrap();
        assert_eq!(c.argv, ["/bin/sh", "-c", "echo  hi"], "an entrypoint drops the image's command too");
        assert_eq!(with_settings(&image, "").unwrap().argv, image.argv);
        assert!(with_settings(&image, "cwd /").is_err(), "only env and arg are a run's");
        assert_eq!(unhex("656e76"), Some(b"env".to_vec()));
        assert_eq!(unhex(""), Some(vec![]));
        assert_eq!(unhex("6"), None);
        assert_eq!(unhex("zz"), None);
    }

    /// The client's `ok` or `closed` frame (its first), the connection's end.
    fn hello(peer: &mut std::os::unix::net::UnixStream) -> String {
        let mut head = [0; 5];
        peer.read_exact(&mut head).unwrap();
        assert_eq!(head[0], crate::FRAME_MSG);
        let mut m = vec![0; u32::from_le_bytes(head[1..].try_into().unwrap()) as usize];
        peer.read_exact(&mut m).unwrap();
        String::from_utf8(m).unwrap()
    }

    /// #832: an app that ends between `APPIN` claiming its slot and its hello: its client is told "closed", and
    /// so goes on to the app's status; never left a connection shut down with nothing said.
    #[test]
    fn an_appin_whose_app_ends_before_its_hello_says_closed() {
        use std::os::unix::net::UnixStream;
        for ends in [true, false] {
            let (r, w) = std::io::pipe().unwrap();
            let apps = Mutex::new(App {
                state: State::Running(1),
                stdin: Some(Arc::new(Stdin::new(File::from(std::os::fd::OwnedFd::from(w)), None).unwrap())),
                ..App::default()
            });
            let (ours, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let out = File::from(std::os::fd::OwnedFd::from(ours));
            let fed = thread::scope(|s| {
                let fed = s.spawn(|| {
                    appin_on(&apps, "7", &out, &[], || {
                        if ends {
                            app_ended(&mut apps.lock().unwrap(), 1, 3)
                        }
                    })
                });
                let said = hello(&mut peer);
                assert_eq!(said, if ends { "closed 0" } else { "ok 0 0" }, "app ending first: {ends}");
                if !ends {
                    assert!(apps.lock().unwrap().appin.as_ref().is_some_and(|(_, c)| c.is_some()), "registered once told");
                    app_ended(&mut apps.lock().unwrap(), 1, 3);
                }
                fed.join().unwrap()
            });
            assert!(fed.is_ok(), "{fed:?}");
            drop(out);
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty(), "nothing after: {rest:?}");
            assert!(apps.lock().unwrap().appin.is_none());
            drop(r);
        }
    }

    #[test]
    fn a_signal_reaches_only_a_running_app() {
        let statuses = Statuses::default();
        let mut app = App::default();
        assert!(signal_app(&app, "15", &statuses).unwrap_err().to_string().contains("no app"));
        let mut child = Command::new("/bin/sleep").arg("100").spawn().unwrap();
        let pid = child.id() as i32;
        (app.state, app.token) = (State::Running(pid), 99);
        assert!(signal_app(&app, "x", &statuses).is_err());
        assert!(signal_app(&app, "65", &statuses).is_err());
        // Not this token's unreaped child (as once reaped): never signalled.
        assert!(signal_app(&app, "15", &statuses).is_err());
        statuses.0.lock().unwrap().running.insert(pid, 99);
        assert_eq!(signal_app(&app, "15", &statuses).unwrap(), "ok");
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGTERM));
        app.state = State::Exited(143);
        assert!(signal_app(&app, "15", &statuses).unwrap_err().to_string().contains("not running"));
    }

    #[test]
    fn conf_lines_and_escapes() {
        let c = parse_conf("arg /bin/app\narg a\\nb\\\\c\nenv K=v=w\nenv BARE\ncwd /srv\nuid 7\ngid 8\ngroups 9 10\nx y").unwrap();
        assert_eq!(c.argv, ["/bin/app", "a\nb\\c"]);
        assert_eq!(c.env, [("K".into(), "v=w".into()), ("BARE".into(), String::new())]);
        assert_eq!((c.cwd.as_str(), c.uid, c.gid, c.groups), ("/srv", 7, 8, vec![9, 10]));
        assert!(parse_conf("cwd /").unwrap().argv.is_empty(), "no app");
        assert!(parse_conf("arg x\nuid root").is_err());
    }
}
