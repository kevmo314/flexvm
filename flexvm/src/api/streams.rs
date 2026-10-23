//! Attach and exec: docker's hijacked streams. The connection is upgraded (`101 UPGRADED`, `Upgrade: tcp`) and
//! carries what the command (`flexvm attach`, `flexvm exec`) reads and writes: the client's bytes as its stdin,
//! its stdout and stderr back, framed (docker's multiplexed stream) or, on a pty, raw. A pty is this server's:
//! the command runs on it as on a terminal (raw, its size followed: a resize sets it, and the command, told by
//! SIGWINCH, passes it on), so the detach keys, Ctrl-P Ctrl-Q, are flexvm's own. A client gone ends the
//! command as a closed terminal would (SIGHUP: an exec's command is closed in the guest, an attach detaches).

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Stdio;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONNECTION, CONTENT_TYPE, UPGRADE};
use hyper::{Request, Response, StatusCode};
use serde_json::{json, Value};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::containers::{find, frame, state, stream_type};
use super::{body_json, empty, full, ok, Api, Error, Query, Reply};

/// The longest a client's attach waits for its container to start running (docker's `run`: attach, then start).
const START_WAIT: Duration = Duration::from_secs(600);

/// What the server holds of attaches and execs while it runs (docker's exec instances are its daemon's too).
#[derive(Default)]
pub struct Streams {
    execs: Mutex<HashMap<String, Exec>>,
    /// The size a container's next attach's pty gets (a resize can come before its attach starts).
    sizes: Mutex<HashMap<String, (u16, u16)>>,
    /// Each attach's or exec's pty, by `container NAME` or `exec ID`, for its resizes.
    ptys: Mutex<Vec<(String, Weak<AsyncFd<OwnedFd>>)>>,
}

#[derive(Debug, Clone)]
struct Exec {
    container: String,
    config: Value,
    started: bool,
    running: bool,
    exit: Option<i64>,
    pid: u32,
    size: Option<(u16, u16)>,
    /// When it ended, for forgetting it.
    ended: Option<Instant>,
}

/// An exec's record is kept this long once it ended (for `docker exec`'s inspect of its status).
const EXEC_KEPT: Duration = Duration::from_secs(600);

fn set_size(fd: &impl AsRawFd, (rows, cols): (u16, u16)) {
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
}

/// A pty, its terminal raw from the start (bytes before the command makes it raw are never echoed or edited).
fn pty(size: Option<(u16, u16)>) -> std::io::Result<(OwnedFd, OwnedFd)> {
    let check = |rc: libc::c_int| if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(rc) };
    let master = unsafe { OwnedFd::from_raw_fd(check(libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC))?) };
    check(unsafe { libc::grantpt(master.as_raw_fd()) })?;
    check(unsafe { libc::unlockpt(master.as_raw_fd()) })?;
    let mut name = [0 as libc::c_char; 128];
    if unsafe { libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let slave = unsafe { OwnedFd::from_raw_fd(check(libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC))?) };
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    check(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut t) })?;
    unsafe { libc::cfmakeraw(&mut t) };
    check(unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &t) })?;
    set_size(&master, size.unwrap_or((24, 80)));
    let flags = check(unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) })?;
    check(unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
    Ok((master, slave))
}

/// A command's ends: pipes, or a pty's master.
enum Ends {
    Pipes(tokio::process::ChildStdin, tokio::process::ChildStdout, tokio::process::ChildStderr),
    Pty(Arc<AsyncFd<OwnedFd>>),
}

struct Running {
    child: tokio::process::Child,
    ends: Ends,
}

impl Running {
    /// `cmd` with its stdin, stdout and stderr this server's to carry: on a pty of `size` (its controlling
    /// terminal, in a session of its own) or on pipes.
    fn spawn(mut cmd: tokio::process::Command, tty: Option<(u16, u16)>) -> std::io::Result<Running> {
        cmd.kill_on_drop(true);
        let Some(size) = tty else {
            let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
            let (i, o, e) = (child.stdin.take(), child.stdout.take(), child.stderr.take());
            return Ok(Running { child, ends: Ends::Pipes(i.unwrap(), o.unwrap(), e.unwrap()) });
        };
        let (master, slave) = pty(Some(size))?;
        cmd.stdin(Stdio::from(slave.try_clone()?)).stdout(Stdio::from(slave.try_clone()?)).stderr(Stdio::from(slave));
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        // Its copies of the terminal's end closed here: the command's alone keep it open.
        drop(cmd);
        // SAFETY: an OwnedFd, owned by the AsyncFd from here on.
        let master = Arc::new(unsafe { AsyncFd::register(master) }?);
        Ok(Running { child, ends: Ends::Pty(master) })
    }
}

impl Api {
    /// The command `words` (`Running::spawn`), its pty kept by `key` for resizes.
    fn spawn_streamed(&self, words: &[String], env: &[(&str, &str)], tty: Option<(u16, u16)>, key: &str) -> std::io::Result<Running> {
        let mut cmd = self.command(words);
        cmd.envs(env.iter().copied());
        let run = Running::spawn(cmd, tty)?;
        if let Ends::Pty(master) = &run.ends {
            let mut ptys = self.streams.ptys.lock().unwrap();
            ptys.retain(|(_, p)| p.strong_count() > 0);
            ptys.push((key.to_string(), Arc::downgrade(master)));
        }
        Ok(run)
    }

    /// Sets the size of `key`'s ptys.
    fn resize(&self, key: &str, size: (u16, u16)) {
        for (_, p) in self.streams.ptys.lock().unwrap().iter().filter(|(k, _)| k == key) {
            if let Some(p) = p.upgrade() {
                set_size(p.get_ref(), size);
            }
        }
    }
}

async fn read_pty(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|f| {
            let n = unsafe { libc::read(f.get_ref().as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            // The terminal hung up: every holder of its other end is gone.
            Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return Ok(0),
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

async fn write_pty(fd: &AsyncFd<OwnedFd>, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let mut guard = fd.writable().await?;
        match guard.try_io(|f| {
            let n = unsafe { libc::write(f.get_ref().as_raw_fd(), data.as_ptr().cast(), data.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(n)) => data = &data[n..],
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

/// What the client asked for of a stream.
#[derive(Clone, Copy)]
struct Wanted {
    stdin: bool,
    stdout: bool,
    stderr: bool,
}

/// The client's end of the connection, written to until a write fails (its client gone: the command is hung up).
struct Out<W> {
    w: W,
    failed: bool,
    hang_up: Box<dyn Fn() + Send>,
}

impl<W: tokio::io::AsyncWrite + Unpin> Out<W> {
    async fn send(&mut self, data: &[u8]) {
        if !self.failed && (self.w.write_all(data).await.is_err() || self.w.flush().await.is_err()) {
            self.failed = true;
            (self.hang_up)();
        }
    }
}

/// Carries `run`'s streams over the upgraded connection until the command ends: its exit status (128 + the
/// signal that ended it: SIGHUP, its client gone).
async fn pump(run: Running, upgraded: hyper::upgrade::Upgraded, want: Wanted) -> Option<i32> {
    let io = hyper_util::rt::TokioIo::new(upgraded);
    let (mut rd, wr) = tokio::io::split(io);
    let Running { mut child, ends } = run;
    let pid = child.id();
    // SIGHUP, as a terminal's hangup: an exec's command is closed in the guest, an attach leaves (never the app's
    // signal, which a SIGTERM to an attach would be).
    let hang_up = move || {
        if let Some(pid) = pid {
            unsafe { libc::kill(pid as i32, libc::SIGHUP) };
        }
    };
    let (mut stdin_pipe, mut outputs, master) = match ends {
        Ends::Pipes(i, o, e) => (Some(i), Some((o, e)), None),
        Ends::Pty(m) => (None, None, Some(m)),
    };
    // The client's bytes: its stdin, if it asked for it (else only watched for the client going). Its end
    // of input (a half-close) closes a pipe's stdin; a pty's input has no end. A stdin not asked for is
    // held open until the command ends: an attach without stdin must never close the app's.
    let reader = {
        let master = master.clone();
        tokio::spawn(async move {
            let mut buf = vec![0; 32 << 10];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) => {
                        if want.stdin {
                            drop(stdin_pipe.take());
                        }
                        break;
                    }
                    Ok(n) if want.stdin => {
                        let sent = match (&mut stdin_pipe, &master) {
                            (Some(p), _) => p.write_all(&buf[..n]).await,
                            (None, Some(m)) => write_pty(m, &buf[..n]).await,
                            (None, None) => Ok(()),
                        };
                        // The command took no more: what follows is its output, and its end.
                        if sent.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        hang_up();
                        break;
                    }
                }
            }
            std::future::pending::<()>().await;
            drop(stdin_pipe);
        })
    };
    let mut out = Out { w: wr, failed: false, hang_up: Box::new(hang_up) };
    let mut b1 = vec![0; 32 << 10];
    if let Some((o, e)) = &mut outputs {
        let mut b2 = vec![0; 32 << 10];
        let (mut out_open, mut err_open) = (true, true);
        while out_open || err_open {
            tokio::select! {
                r = o.read(&mut b1), if out_open => match r {
                    Ok(n) if n > 0 => if want.stdout { out.send(&frame(1, &b1[..n])).await },
                    _ => out_open = false,
                },
                r = e.read(&mut b2), if err_open => match r {
                    Ok(n) if n > 0 => if want.stderr { out.send(&frame(2, &b2[..n])).await },
                    _ => err_open = false,
                },
            }
        }
    }
    if let Some(m) = &master {
        loop {
            match read_pty(m, &mut b1).await {
                Ok(n) if n > 0 => {
                    if want.stdout || want.stderr {
                        out.send(&b1[..n]).await
                    }
                }
                _ => break,
            }
        }
    }
    let status = child.wait().await.ok();
    reader.abort();
    let _ = out.w.shutdown().await;
    status.and_then(|s| {
        use std::os::unix::process::ExitStatusExt;
        s.code().or_else(|| s.signal().map(|sig| 128 + sig))
    })
}

/// Whether the client asked to upgrade the connection, as docker's does for its streams.
fn upgrading<B>(req: &Request<B>) -> bool {
    let has = |h, v: &str| req.headers().get_all(h).iter().any(|x| x.to_str().is_ok_and(|x| x.to_ascii_lowercase().split(',').any(|w| w.trim() == v)));
    has(CONNECTION, "upgrade") && has(UPGRADE, "tcp")
}

/// Docker's answer to an upgrade: `101 UPGRADED`, its stream's type.
fn upgraded(tty: bool) -> Reply {
    let mut res = Response::new(full(Vec::new()));
    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let h = res.headers_mut();
    h.insert(CONTENT_TYPE, stream_type(tty));
    h.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    h.insert(UPGRADE, HeaderValue::from_static("tcp"));
    Ok(res)
}

fn needs_upgrade() -> Error {
    Error::bad("a stream needs the connection upgraded (Connection: Upgrade, Upgrade: tcp), as docker's client asks")
}

/// `POST /containers/{id}/attach?stream&stdin&stdout&stderr&logs`: `flexvm attach` of its app, from its first
/// byte if it is yet to start (docker's `run`: attach, then start) or with `logs`, else from now. A container
/// not running is refused, as docker's is, unless it was created and is yet to start: its attach waits for it.
pub async fn attach(api: &Arc<Api>, key: &str, mut req: Request<Incoming>) -> Reply {
    let q = Query::of(&req);
    if !q.flag("stream", false)? {
        return Err(Error::unsupported("attach without stream (logs alone): use the logs endpoint"));
    }
    let want = Wanted { stdin: q.flag("stdin", false)?, stdout: q.flag("stdout", false)?, stderr: q.flag("stderr", false)? };
    let vms = super::containers::all(api).await?;
    let v = find(&vms, key)?;
    let name = v["name"].as_str().unwrap_or_default().to_string();
    let created = v["state"] == "created";
    if !created && !state(v).running {
        return Err(Error::conflict("You cannot attach to a stopped container, start it first"));
    }
    let tty = v["spec"]["tty"] == true || v["docker"]["config"]["Tty"] == true;
    let from_start = created || q.flag("logs", false)?;
    if !upgrading(&req) {
        return Err(needs_upgrade());
    }
    let on = hyper::upgrade::on(&mut req);
    let api = api.clone();
    tokio::spawn(async move {
        let Ok(conn) = on.await else { return };
        // Started, its VM registered (an attach of a VM that is not is refused); given up once nothing holds the
        // name after it ran, or at START_WAIT.
        let until = Instant::now() + START_WAIT;
        while api.host.entry(&name).is_err() && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let size = tty.then(|| api.streams.sizes.lock().unwrap().get(&name).copied().unwrap_or((24, 80)));
        let env: &[(&str, &str)] = if from_start { &[("FLEXVM_ATTACH_FROM", "0")] } else { &[] };
        let words = vec!["attach".to_string(), "--".into(), name.clone()];
        match api.spawn_streamed(&words, env, size, &format!("container {name}")) {
            Ok(run) => drop(pump(run, conn, want).await),
            Err(e) => crate::log!("flexvm api: attach {name}: {e}"),
        }
    });
    upgraded(tty)
}

/// `POST /containers/{id}/resize?h&w`: its attaches' ptys, and the next one's.
pub async fn resize_container(api: &Arc<Api>, key: &str, q: Query) -> Reply {
    let size = size_of(&q)?;
    let name = super::containers::resolve(api, key).await?;
    api.streams.sizes.lock().unwrap().insert(name.clone(), size);
    api.resize(&format!("container {name}"), size);
    empty(StatusCode::OK)
}

fn size_of(q: &Query) -> Result<(u16, u16), Error> {
    let (h, w) = (q.number::<u16>("h")?.unwrap_or(0), q.number::<u16>("w")?.unwrap_or(0));
    if h == 0 || w == 0 {
        return Err(Error::bad("a resize needs h and w"));
    }
    Ok((h, w))
}

/// `POST /containers/{id}/exec`: an exec instance, to start (`exec/{id}/start`), with docker's settings.
pub async fn exec_create(api: &Arc<Api>, key: &str, body: Value) -> Reply {
    let vms = super::containers::all(api).await?;
    let v = find(&vms, key)?;
    let name = v["name"].as_str().unwrap_or_default().to_string();
    let st = state(v);
    if st.paused {
        return Err(Error::conflict(format!("Container {name} is paused, unpause the container before exec")));
    }
    if !st.running {
        return Err(Error::conflict(format!("container {name} is not running")));
    }
    let cmd = body["Cmd"].as_array().filter(|c| !c.is_empty() && c.iter().all(Value::is_string)).ok_or_else(|| Error::bad("No exec command specified"))?;
    if cmd[0].as_str() == Some("") {
        return Err(Error::bad("No exec command specified"));
    }
    // `Privileged` asks nothing more: a VM's command runs as root of its own kernel.
    let size = body["ConsoleSize"].as_array().and_then(|s| Some((s.first()?.as_u64()? as u16, s.get(1)?.as_u64()? as u16))).filter(|&(h, w)| h > 0 && w > 0);
    let id = crate::util::random_hex(32)?;
    let mut execs = api.streams.execs.lock().unwrap();
    execs.retain(|_, e| e.ended.is_none_or(|t| t.elapsed() < EXEC_KEPT));
    execs.insert(id.clone(), Exec { container: name, config: body, started: false, running: false, exit: None, pid: 0, size, ended: None });
    Ok(super::json(StatusCode::CREATED, &json!({"Id": id})))
}

fn no_exec(id: &str) -> Error {
    Error::missing(format!("No such exec instance: {id}"))
}

/// `flexvm exec`'s words for an exec instance.
fn exec_words(e: &Exec, detach: bool, tty: bool) -> Vec<String> {
    let c = &e.config;
    let mut words = vec!["exec".to_string()];
    if detach {
        words.push("--detach".into());
    }
    if c["AttachStdin"] == true && !detach {
        words.push("--interactive".into());
    }
    if tty {
        words.push("--tty".into());
    }
    for kv in c["Env"].as_array().into_iter().flatten().filter_map(Value::as_str).filter(|kv| kv.contains('=')) {
        words.extend(["--env".to_string(), kv.to_string()]);
    }
    if let Some(w) = c["WorkingDir"].as_str().filter(|w| !w.is_empty()) {
        words.extend(["--workdir".to_string(), w.to_string()]);
    }
    if let Some(u) = c["User"].as_str().filter(|u| !u.is_empty()) {
        words.extend(["--user".to_string(), u.to_string()]);
    }
    words.extend(["--".to_string(), e.container.clone()]);
    words.extend(c["Cmd"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from));
    words
}

/// `POST /exec/{id}/start`: `flexvm exec` of it, on the upgraded connection (or `-d`, detached).
pub async fn exec_start(api: &Arc<Api>, id: &str, mut req: Request<Incoming>) -> Reply {
    let upgrade = upgrading(&req).then(|| hyper::upgrade::on(&mut req));
    let body = body_json(req).await?;
    let (e, detach, tty) = {
        let mut execs = api.streams.execs.lock().unwrap();
        let e = execs.get_mut(id).ok_or_else(|| no_exec(id))?;
        if e.started {
            return Err(Error::conflict(format!("exec instance {id} has been started already")));
        }
        e.started = true;
        if let Some(s) =
            body["ConsoleSize"].as_array().and_then(|s| Some((s.first()?.as_u64()? as u16, s.get(1)?.as_u64()? as u16))).filter(|&(h, w)| h > 0 && w > 0)
        {
            e.size = Some(s);
        }
        let tty = e.config["Tty"] == true || body["Tty"] == true;
        (e.clone(), body["Detach"] == true, tty)
    };
    let words = exec_words(&e, detach, tty);
    if detach {
        let r = api.run(&words).await;
        if let Some(e) = api.streams.execs.lock().unwrap().get_mut(id) {
            e.ended = Some(Instant::now());
        }
        r?;
        return empty(StatusCode::OK);
    }
    let Some(on) = upgrade else { return Err(needs_upgrade()) };
    let want = Wanted { stdin: e.config["AttachStdin"] == true, stdout: e.config["AttachStdout"] != false, stderr: e.config["AttachStderr"] != false };
    let (api2, id2) = (api.clone(), id.to_string());
    tokio::spawn(async move {
        let Ok(conn) = on.await else { return };
        let size = tty.then(|| e.size.unwrap_or((24, 80)));
        let run = match api2.spawn_streamed(&words, &[], size, &format!("exec {id2}")) {
            Ok(r) => r,
            Err(err) => return crate::log!("flexvm api: exec {id2}: {err}"),
        };
        if let Some(e) = api2.streams.execs.lock().unwrap().get_mut(&id2) {
            (e.running, e.pid) = (true, run.child.id().unwrap_or(0));
        }
        let code = pump(run, conn, want).await;
        if let Some(e) = api2.streams.execs.lock().unwrap().get_mut(&id2) {
            (e.running, e.exit, e.ended) = (false, code.map(i64::from), Some(Instant::now()));
        }
    });
    upgraded(tty)
}

/// `POST /exec/{id}/resize?h&w`.
pub async fn exec_resize(api: &Arc<Api>, id: &str, q: Query) -> Reply {
    let size = size_of(&q)?;
    api.streams.execs.lock().unwrap().get_mut(id).ok_or_else(|| no_exec(id))?.size = Some(size);
    api.resize(&format!("exec {id}"), size);
    empty(StatusCode::OK)
}

/// `GET /exec/{id}/json`.
pub async fn exec_inspect(api: &Arc<Api>, id: &str) -> Reply {
    let e = api.streams.execs.lock().unwrap().get(id).cloned().ok_or_else(|| no_exec(id))?;
    let c = &e.config;
    let cmd: Vec<String> = c["Cmd"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
    ok(&json!({
        "ID": id,
        "Running": e.running,
        "ExitCode": e.exit,
        "ProcessConfig": {"tty": c["Tty"] == true, "entrypoint": cmd.first(), "arguments": cmd.get(1..).unwrap_or_default(),
            "privileged": c["Privileged"] == true, "user": c["User"].as_str().unwrap_or_default()},
        "OpenStdin": c["AttachStdin"] == true,
        "OpenStderr": c["AttachStderr"] == true,
        "OpenStdout": c["AttachStdout"] == true,
        "CanRemove": false,
        "ContainerID": super::containers::id_of(&e.container),
        "DetachKeys": "",
        "Pid": e.pid,
    }))
}

/// The requests under `/exec`.
pub async fn route(api: &Arc<Api>, req: Request<Incoming>, words: &[&str]) -> Option<Reply> {
    let method = req.method().clone();
    Some(match (method, words) {
        (hyper::Method::POST, [id, "start"]) => exec_start(api, id, req).await,
        (hyper::Method::POST, [id, "resize"]) => exec_resize(api, id, Query::of(&req)).await,
        (hyper::Method::GET, [id, "json"]) => exec_inspect(api, id).await,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_settings_become_flags() {
        let e = Exec {
            container: "web".into(),
            config: json!({"AttachStdin": true, "Tty": true, "Env": ["A=1", "BARE"], "WorkingDir": "/srv", "User": "app", "Cmd": ["sh", "-c", "echo hi"]}),
            started: false,
            running: false,
            exit: None,
            pid: 0,
            size: None,
            ended: None,
        };
        assert_eq!(
            exec_words(&e, false, true),
            ["exec", "--interactive", "--tty", "--env", "A=1", "--workdir", "/srv", "--user", "app", "--", "web", "sh", "-c", "echo hi"]
        );
        assert_eq!(exec_words(&e, true, false), ["exec", "--detach", "--env", "A=1", "--workdir", "/srv", "--user", "app", "--", "web", "sh", "-c", "echo hi"]);
    }

    #[test]
    fn upgrades_are_asked_for_as_dockers_client_asks() {
        let req = |c: &str, u: &str| Request::builder().header(CONNECTION, c).header(UPGRADE, u).body(()).unwrap();
        assert!(upgrading(&req("Upgrade", "tcp")));
        assert!(upgrading(&req("keep-alive, Upgrade", "tcp")));
        assert!(!upgrading(&req("close", "tcp")));
        assert!(!upgrading(&Request::builder().body(()).unwrap()));
    }

    /// A hijacked stream to `sh -c SCRIPT`, as docker's client drives one: the upgrade, then `input` and a
    /// half-close; all that came back after the head.
    async fn hijacked(script: &str, tty: Option<(u16, u16)>, want: Wanted, input: &[u8]) -> (String, Vec<u8>, Option<i32>) {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let tx = Arc::new(Mutex::new(Some(tx)));
        let script = script.to_string();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |mut req: Request<Incoming>| {
                let (tx, script) = (tx.clone(), script.clone());
                async move {
                    assert!(upgrading(&req));
                    let on = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        let mut cmd = tokio::process::Command::new("sh");
                        cmd.args(["-c", &script]);
                        let run = Running::spawn(cmd, tty).unwrap();
                        let code = pump(run, on.await.unwrap(), want).await;
                        let _ = tx.lock().unwrap().take().unwrap().send(code);
                    });
                    Ok::<_, std::convert::Infallible>(upgraded(tty.is_some()).unwrap())
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(server), service).with_upgrades().await;
        });
        let mut client = client;
        client.write_all(b"POST /exec/x/start HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = client.read(&mut buf).await.unwrap();
            assert!(n > 0, "no head: {:?}", String::from_utf8_lossy(&got));
            got.extend_from_slice(&buf[..n]);
        }
        let end = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let (head, mut body) = (String::from_utf8_lossy(&got[..end]).into_owned(), got[end..].to_vec());
        client.write_all(input).await.unwrap();
        if tty.is_none() {
            client.shutdown().await.unwrap();
        }
        loop {
            match tokio::time::timeout(Duration::from_secs(20), client.read(&mut buf)).await.expect("the stream ends") {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&buf[..n]),
            }
        }
        (head, body, rx.await.unwrap())
    }

    /// Docker's frames, read back: (stream, bytes) per stream, joined.
    fn unframe(mut b: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        while b.len() >= 8 {
            let n = u32::from_be_bytes(b[4..8].try_into().unwrap()) as usize;
            match b[0] {
                1 => out.extend_from_slice(&b[8..8 + n]),
                2 => err.extend_from_slice(&b[8..8 + n]),
                s => panic!("stream {s}"),
            }
            b = &b[8 + n..];
        }
        assert!(b.is_empty(), "a frame cut short");
        (out, err)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hijacked_stream_carries_stdin_and_framed_output() {
        let all = Wanted { stdin: true, stdout: true, stderr: true };
        let (head, body, code) = hijacked("cat; echo to-err >&2; exit 3", None, all, b"hello\n").await;
        assert!(head.starts_with("HTTP/1.1 101") && head.contains("application/vnd.docker.multiplexed-stream"), "{head}");
        assert_eq!(unframe(&body), (b"hello\n".to_vec(), b"to-err\n".to_vec()));
        assert_eq!(code, Some(3));
        // Stdin not asked for: held open (cat would end at its EOF), never fed.
        let out_only = Wanted { stdin: false, stdout: true, stderr: false };
        let (_, body, code) = hijacked("read -t 1 x; echo read=$?; echo e >&2", None, out_only, b"ignored\n").await;
        let (out, err) = unframe(&body);
        assert!(String::from_utf8_lossy(&out).starts_with("read=") && out != b"read=0\n" && err.is_empty(), "{out:?} {err:?}");
        assert_eq!(code, Some(0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hijacked_pty_is_raw_and_sized() {
        let all = Wanted { stdin: true, stdout: true, stderr: true };
        let (head, body, code) = hijacked("stty size; read x; echo got-$x; exit 5", Some((33, 101)), all, b"typed\n").await;
        assert!(head.contains("application/vnd.docker.raw-stream"), "{head}");
        let text = String::from_utf8_lossy(&body);
        // Raw: what was typed is not echoed back by this side's terminal, and a newline stays one.
        assert_eq!(text, "33 101\ngot-typed\n", "{text:?}");
        assert_eq!(code, Some(5));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_pty_is_raw_and_sized() {
        let (master, slave) = pty(Some((40, 120))).unwrap();
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) }, 0);
        assert_eq!((ws.ws_row, ws.ws_col), (40, 120));
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut t) };
        assert_eq!(t.c_lflag & (libc::ECHO | libc::ICANON), 0, "raw: no echo, no line editing");
        // What the client types reaches the command as typed, and nothing is echoed back.
        let master = unsafe { AsyncFd::register(master) }.unwrap();
        write_pty(&master, b"hi\n").await.unwrap();
        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(slave.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(&buf[..n as usize], b"hi\n");
        unsafe { libc::write(slave.as_raw_fd(), b"out".as_ptr().cast(), 3) };
        let n = read_pty(&master, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"out");
        drop(slave);
        assert_eq!(read_pty(&master, &mut buf).await.unwrap(), 0, "hung up: the end");
    }
}
