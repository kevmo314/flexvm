//! Client for flexvm-init's vsock protocol, through Firecracker's vsock UDS.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::bail;
use crate::host::{fault, tripped_once};
use crate::util::{By, Error, Result};

#[path = "../../guest/src/proto.rs"]
mod proto;
pub use proto::*;

pub const TIMEOUT: Duration = Duration::from_secs(5);

/// The connection broke before the guest answered (e.g. a restore reset vsock): unlike an
/// answer, worth another try.
fn lost(why: impl Into<String>) -> Error {
    std::io::Error::new(ErrorKind::ConnectionAborted, why.into()).into()
}

/// As opposed to the guest answering, or not answering in time.
pub fn dropped(e: &Error) -> bool {
    use ErrorKind::*;
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|e| matches!(e.kind(), ConnectionRefused | ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof | NotConnected))
}

/// Retries `attempt` while its connection drops. Only for requests safe to repeat: the agent
/// serves them in connection order, so an earlier try never lands last.
pub fn answered<T>(what: &'static str, deadline: Instant, mut attempt: impl FnMut(Instant) -> Result<T>) -> Result<T> {
    let mut pause = Duration::from_millis(5);
    loop {
        match attempt(deadline) {
            Ok(v) => return Ok(v),
            Err(e) if !dropped(&e) || Instant::now() + pause >= deadline => return Err(e),
            Err(_) => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(100));
                *RETRIES.lock().unwrap().entry(what).or_default() += 1;
            }
        }
    }
}

static RETRIES: Mutex<BTreeMap<&'static str, u64>> = Mutex::new(BTreeMap::new());

pub fn retries() -> BTreeMap<&'static str, u64> {
    RETRIES.lock().unwrap().clone()
}

/// Sends `line` in the same write as CONNECT: Firecracker forwards what follows its newline
/// once the guest accepts, saving a round trip.
pub fn handshake<S: Read + Write>(s: S, line: &str) -> Result<BufReader<S>> {
    let mut r = BufReader::new(s);
    r.get_mut().write_all(format!("CONNECT {PORT}\n{line}\n").as_bytes())?;
    let mut ok = String::new();
    r.by_ref().take(64).read_line(&mut ok)?;
    if !ok.starts_with("OK") {
        return Err(lost(format!("vsock connect refused: {ok:?}")));
    }
    Ok(r)
}

/// Vsock sockets of Firecrackers that died: calls on them fail at once, never retried.
static ABANDONED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

pub fn abandon(uds: &Path) {
    ABANDONED.lock().unwrap().push(uds.to_path_buf());
}

/// All I/O by `deadline`; nothing is sent once it has passed. Test faults: `guest_drop`,
/// `guest_lose_reply` (one reply each arming: `tripped_once`).
fn ask(uds: &Path, line: &str, deadline: Instant) -> Result<(u8, Vec<u8>)> {
    ask_watched(uds, line, deadline, |_| Ok(()))
}

/// `ask`, with `watch` shown the connection before anything is sent.
fn ask_watched(uds: &Path, line: &str, deadline: Instant, watch: impl FnOnce(&UnixStream) -> Result<()>) -> Result<(u8, Vec<u8>)> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(std::io::Error::new(ErrorKind::TimedOut, format!("no time left for {line:?}")).into());
    }
    if ABANDONED.lock().unwrap().iter().any(|p| p == uds) {
        bail!("its firecracker exited");
    }
    let s = crate::util::connect_unix(uds, left)?;
    if fault("guest_drop") {
        return Err(lost("injected fault: guest connection refused"));
    }
    watch(&s)?;
    let reply = read_frame(&mut handshake(By { s, at: deadline }, line)?)?;
    let reply = reply.ok_or_else(|| lost(format!("guest closed the connection before answering {line:?}")))?;
    if tripped_once("guest_lose_reply") {
        return Err(lost("injected fault: guest reply lost"));
    }
    Ok(reply)
}

/// On a fresh connection, so a caller can register it before anything reaches the guest.
pub fn request_on(s: UnixStream, line: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    handshake(s, line)
}

pub fn untimed(r: &BufReader<UnixStream>) -> Result<()> {
    r.get_ref().set_read_timeout(None)?;
    Ok(r.get_ref().set_write_timeout(None)?)
}

/// A session's body: a string is a shell command (a VM's main command), an object `exec`'s argv
/// and options (`Exec`'s fields).
pub fn command_body(cmd: &serde_json::Value) -> Result<String> {
    if let Some(s) = cmd.as_str() {
        return Ok(s.to_owned());
    }
    let strings = |k: &str| -> Result<Vec<String>> {
        cmd[k].as_array().map_or(Ok(vec![]), |a| a.iter().map(|v| v.as_str().map(String::from).ok_or_else(|| format!("bad exec {k}").into())).collect())
    };
    let size = cmd["size"].as_array().and_then(|s| Some((u16::try_from(s.first()?.as_u64()?).ok()?, u16::try_from(s.get(1)?.as_u64()?).ok()?)));
    let e = Exec {
        argv: strings("argv")?,
        env: strings("env")?,
        workdir: cmd["workdir"].as_str().map(String::from),
        user: cmd["user"].as_str().map(String::from),
        detach: cmd["detach"] == true,
        stdin: cmd["stdin"] == true,
        tty: cmd["tty"] == true,
        size,
    };
    Ok(e.encode()?)
}

pub fn session(s: UnixStream, action: &str, id: &str, offset: u64, cmd: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    session_on(action, id, offset, cmd, |line| request_on(s, line, timeout))
}

/// `request_on`, all of it (the reply's OK line read a byte at a time) by `at`, however slowly the guest trickles.
pub fn request_by(s: UnixStream, line: &str, at: Instant) -> Result<BufReader<UnixStream>> {
    By { s: &s, at }.write_all(format!("CONNECT {PORT}\n{line}\n").as_bytes())?;
    let mut r = BufReader::new(s);
    let (mut ok, mut byte) = (Vec::new(), [0]);
    while ok.len() < 64 {
        By { s: &mut r, at }.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        ok.push(byte[0]);
    }
    if !ok.starts_with(b"OK") {
        return Err(lost(format!("vsock connect refused: {:?}", String::from_utf8_lossy(&ok))));
    }
    Ok(r)
}

/// The agent's supported attachment form, cached per VM process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AttachForm {
    Numbered = 1,
    Plain = 2,
    Epoch = 3,
}

impl AttachForm {
    pub fn older(self) -> Self {
        match self {
            Self::Epoch => Self::Numbered,
            Self::Numbered | Self::Plain => Self::Plain,
        }
    }
}

/// ATTACH or REJOIN with the host process's epoch and claim where supported; plain ATTACH for old agents.
pub fn attach_line(id: &str, offset: u64, claim: u64, epoch: u64, form: AttachForm, rejoin: bool) -> Result<String> {
    if !valid_session_id(id) {
        bail!("bad session id");
    }
    let verb = if rejoin && form != AttachForm::Plain { "REJOIN" } else { "ATTACH" };
    Ok(match form {
        AttachForm::Plain => format!("{verb} {id} {offset}"),
        AttachForm::Numbered => format!("{verb} {id} {offset} {claim}"),
        AttachForm::Epoch => format!("{verb} {id} {offset} {claim} {epoch}"),
    })
}

/// `RELEASE`: closes session `id` only if it exited with `code` after `end` bytes (a late acknowledgement's, #1047).
pub fn release(s: UnixStream, id: &str, end: u64, code: i32, timeout: Duration) -> Result<BufReader<UnixStream>> {
    if !valid_session_id(id) {
        bail!("bad session id");
    }
    request_on(s, &format!("RELEASE {id} {end} {code}"), timeout)
}

/// The agent drops a command longer than `MAX_BODY` unread: refused here, before connecting.
pub fn fits(cmd: &str) -> Result<()> {
    if cmd.len() > MAX_BODY {
        bail!("the command is {} bytes; the guest takes at most {MAX_BODY}", cmd.len());
    }
    Ok(())
}

/// The guest refused a session for want of slots (`MAX_LIVE`, `MAX_DETACHED`).
pub fn at_session_cap(m: &str) -> bool {
    m.contains(TOO_MANY_SESSIONS) || m.contains(TOO_MANY_DETACHED)
}

/// A refusal worth another try (`TRY_AGAIN`), not an answer.
pub fn transient(m: &str) -> bool {
    m.contains(TRY_AGAIN)
}

fn session_on<S: Read + Write>(action: &str, id: &str, offset: u64, cmd: &str, open: impl FnOnce(&str) -> Result<BufReader<S>>) -> Result<BufReader<S>> {
    if !valid_session_id(id) {
        bail!("bad session id");
    }
    let line = match action {
        "start" | "argv" => {
            fits(cmd)?;
            let verb = if action == "argv" { "ARGV" } else { "SESSION" };
            format!("{verb} {id} {}", cmd.len())
        }
        "attach" => format!("ATTACH {id} {offset}"),
        "close" => format!("CLOSE {id}"),
        _ => bail!("bad session action"),
    };
    let mut r = open(&line)?;
    if matches!(action, "start" | "argv") {
        r.get_mut().write_all(cmd.as_bytes())?;
    }
    Ok(r)
}

pub fn exec_output(r: &mut impl Read, id: &str, mut out: impl FnMut(u8, &[u8]) -> Result<()>) -> Result<i32> {
    let mut offset = 0;
    loop {
        match read_frame(r)? {
            Some((kind @ (FRAME_STDOUT | FRAME_STDERR), d)) => {
                let bytes = session_output(&d, offset)?;
                offset += bytes.len() as u64;
                out(kind, bytes)?;
            }
            Some((FRAME_EXIT, d)) => return session_exit(&d, offset),
            Some((FRAME_MSG, m)) if m == id.as_bytes() || m == b"waiting" => {}
            Some((FRAME_LOST, _)) => bail!("guest command output lost"),
            Some((_, m)) => bail!("guest command: {}", refusal(&m)),
            None => bail!("guest closed the connection before the command exited"),
        }
    }
}

pub fn close(uds: &Path, id: &str, deadline: Instant) -> Result<()> {
    match ask(uds, &format!("CLOSE {id}"), deadline)? {
        (FRAME_MSG, m) if m == b"closed" => Ok(()),
        (_, m) => bail!("closing session {id}: {}", String::from_utf8_lossy(&m)),
    }
}

pub fn session_output(data: &[u8], offset: u64) -> Result<&[u8]> {
    let start = u64::from_le_bytes(data.get(..8).ok_or("short session output frame")?.try_into()?);
    if start != offset {
        bail!("session output offset {start}, expected {offset}");
    }
    Ok(&data[8..])
}

pub fn session_exit(data: &[u8], offset: u64) -> Result<i32> {
    if data.len() != 12 {
        bail!("bad session exit frame");
    }
    Ok(i32::from_le_bytes(session_output(data, offset)?.try_into()?))
}

/// An owned wire frame: the relay forwards it without copying its payload.
pub struct WireFrame(Vec<u8>);

impl WireFrame {
    pub fn kind(&self) -> u8 {
        self.0[0]
    }

    pub fn data(&self) -> &[u8] {
        &self.0[5..]
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

fn frame_header(r: &mut impl Read) -> Result<Option<([u8; 5], usize)>> {
    let mut hdr = [0u8; 5];
    match r.read_exact(&mut hdr[..1]) {
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        res => res?,
    }
    r.read_exact(&mut hdr[1..])?;
    let len = u32::from_le_bytes(hdr[1..].try_into().unwrap()) as usize;
    if len > MAX_BODY {
        bail!("guest frame too large: {len}");
    }
    Ok(Some((hdr, len)))
}

pub fn read_wire_frame(r: &mut impl Read) -> Result<Option<WireFrame>> {
    let Some((hdr, len)) = frame_header(r)? else { return Ok(None) };
    let mut buf = vec![0u8; 5 + len];
    buf[..5].copy_from_slice(&hdr);
    r.read_exact(&mut buf[5..])?;
    Ok(Some(WireFrame(buf)))
}

pub fn read_frame(r: &mut impl Read) -> Result<Option<(u8, Vec<u8>)>> {
    let Some((hdr, len)) = frame_header(r)? else { return Ok(None) };
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some((hdr[0], buf)))
}

pub fn ping(uds: &Path) -> Result<()> {
    answered("PING", Instant::now() + Duration::from_secs(2), |by| match ask(uds, "PING", by)? {
        (FRAME_MSG, m) if m == b"pong" => Ok(()),
        other => bail!("unexpected ping reply {other:?}"),
    })
}

/// Runs a command, draining its output without retaining it.
pub fn exec(uds: &Path, cmd: &str, timeout: Duration) -> Result<i32> {
    let at = Instant::now().checked_add(timeout).ok_or("guest timeout is too large")?;
    let s = crate::util::connect_unix(uds, timeout)?;
    let (code, _, closed) = run(s, uds, cmd, at, 0)?;
    closed?;
    Ok(code)
}

/// How long past its deadline `run` may take to close a command it gave up on.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// Drains all output, keeping at most `max_out` bytes; returns the close result separately. The
/// session is closed however it ended (past the deadline, the command is stopped).
pub fn run(s: UnixStream, uds: &Path, cmd: &str, deadline: Instant, max_out: usize) -> Result<(i32, String, Result<()>)> {
    let id = crate::util::random_hex(16)?;
    let mut out = Vec::new();
    let code = session_on("start", &id, 0, cmd, |line| handshake(By { s, at: deadline }, line)).and_then(|mut r| {
        exec_output(&mut r, &id, |_, d| {
            out.extend_from_slice(&d[..d.len().min(max_out.saturating_sub(out.len()))]);
            Ok(())
        })
    });
    // A command cut off by the deadline still gets a moment to be closed.
    let closed = close(uds, &id, deadline.max(Instant::now() + CLOSE_GRACE));
    Ok((code?, String::from_utf8_lossy(&out).into_owned(), closed))
}

fn now() -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(format!("{}.{:09}", now.as_secs(), now.subsec_nanos()))
}

/// The agent's answer to a request it refused; one too old to know the request is told apart.
pub fn refusal(m: &[u8]) -> String {
    let hint = if m.starts_with(b"unknown request") { "; rebuild the rootfs and its templates" } else { "" };
    format!("{}{hint}", String::from_utf8_lossy(m))
}

fn refused(verb: &'static str, m: &[u8]) -> Error {
    format!("guest {}: {}", verb.to_lowercase(), refusal(m)).into()
}

/// Address, nameserver and wall clock; doubles as the readiness check.
pub fn start(uds: &Path, ip: std::net::Ipv4Addr, dns: Option<&str>) -> Result<()> {
    let dns = dns.unwrap_or("");
    answered("START", Instant::now() + TIMEOUT, |by| match ask(uds, &format!("START {ip} {} {dns}", now()?), by)? {
        (FRAME_MSG, m) if m == b"ok" => Ok(()),
        (_, m) => Err(refused("START", &m)),
    })
}

/// Returns the offset (ms, guest minus host).
pub fn clock(uds: &Path, timeout: Duration) -> Result<f64> {
    answered("CLOCK", Instant::now().checked_add(timeout).ok_or("guest timeout is too large")?, |by| match ask(uds, &format!("CLOCK {}", now()?), by)? {
        (FRAME_MSG, m) if m.starts_with(b"ok ") => Ok(String::from_utf8_lossy(&m[3..]).trim().parse::<f64>()? / 1e6),
        (_, m) => Err(refused("CLOCK", &m)),
    })
}

fn message(uds: &Path, line: &str, timeout: Duration) -> Result<String> {
    match ask(uds, line, Instant::now().checked_add(timeout).ok_or("guest timeout is too large")?)? {
        (FRAME_MSG, m) => Ok(String::from_utf8_lossy(&m).into_owned()),
        (_, m) => bail!("unexpected reply to {line}: {}", String::from_utf8_lossy(&m)),
    }
}

/// The guest's hostname and /etc/hosts entry: `name`. An agent that predates it keeps "flexvm".
pub fn set_hostname(uds: &Path, name: &str) -> Result<()> {
    // Named, as a timeout alone does not say which step of a resume or restore went unanswered (#1211).
    match message(uds, &format!("HOSTNAME {name}"), TIMEOUT).map_err(|e| format!("setting its hostname: {e}"))?.as_str() {
        "ok" => Ok(()),
        m if m.starts_with("unknown request") => Ok(()),
        m => bail!("setting its hostname: {}", m.trim_start_matches("error: ")),
    }
}

/// Times the guest reseeded its RNG for a new VMGenID.
pub fn forks(uds: &Path) -> Result<usize> {
    let m = message(uds, "FORKS", TIMEOUT)?;
    Ok(m.strip_prefix("ok ").ok_or_else(|| refused("FORKS", m.as_bytes()))?.trim().parse()?)
}

/// `settings`: a run's (`vmproc::RunSpec::app_settings`), in app.conf's form; empty for the image's own.
pub fn start_app(uds: &Path, settings: &str) -> Result<u32> {
    let line = match settings {
        "" => "APP".to_string(),
        s => format!("APP {}", s.bytes().map(|b| format!("{b:02x}")).collect::<String>()),
    };
    let reply = message(uds, &line, TIMEOUT)?;
    app_started(&reply, !settings.is_empty())
}

/// `ok <pid>`, and ` applied` or ` ignored` if settings were sent: an older agent starts the image's app as is.
fn app_started(reply: &str, settings: bool) -> Result<u32> {
    let Some(rest) = reply.strip_prefix("ok ") else { bail!("starting the app: {}", reply.trim_start_matches("error: ")) };
    let mut words = rest.split_whitespace();
    let pid = words.next().ok_or("starting the app: no pid")?.parse()?;
    if settings {
        match words.next() {
            Some("applied") => {}
            Some("ignored") => bail!("the app is already running, so its run settings were ignored"),
            _ => bail!("its template's flexvm-init predates -e, --env-file and --entrypoint at run, so its app started without them: pull its image again"),
        }
    }
    Ok(pid)
}

/// `kill -s`: `sig` to the app's process.
pub fn signal_app(uds: &Path, sig: i32) -> Result<()> {
    match message(uds, &format!("SIGNAL {sig}"), TIMEOUT)?.as_str() {
        "ok" => Ok(()),
        m if m.starts_with("unknown request") => bail!("its template's flexvm-init predates kill -s: pull its image again"),
        m => bail!("{}", m.trim_start_matches("error: ")),
    }
}

/// How many sessions the agent has live, and how many of those are exited and unacknowledged.
pub fn sessions(uds: &Path) -> Result<(u64, u64)> {
    let m = message(uds, "SESSIONS", TIMEOUT)?;
    let counts: Vec<u64> =
        m.strip_prefix("ok ").ok_or_else(|| refused("SESSIONS", m.as_bytes()))?.split_whitespace().map(str::parse).collect::<std::result::Result<_, _>>()?;
    match counts[..] {
        [live, unacknowledged] => Ok((live, unacknowledged)),
        _ => bail!("bad sessions reply {m:?}"),
    }
}

/// `idle`, `running <pid>` or `exited <code>`.
pub fn app_status(uds: &Path) -> Result<String> {
    message(uds, "APPSTATUS", TIMEOUT)
}

/// A readiness request whose connection is shut down once `stop` fails, so an interrupted
/// pull is not held for the request's whole timeout.
fn readiness(uds: &Path, line: &str, timeout: Duration, stop: &(dyn Fn() -> Result<()> + Sync)) -> Result<String> {
    let deadline = Instant::now().checked_add(timeout).ok_or("guest timeout is too large")?;
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let reply = std::thread::scope(|scope| {
        let reply = ask_watched(uds, line, deadline, |s| {
            let s = s.try_clone()?;
            scope.spawn(move || loop {
                if stop().is_err() {
                    let _ = s.shutdown(std::net::Shutdown::Both);
                    return;
                }
                if finished.recv_timeout(Duration::from_millis(50)) != Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
                    return;
                }
            });
            Ok(())
        });
        drop(done);
        reply
    });
    stop()?;
    match reply? {
        (FRAME_MSG, m) => Ok(String::from_utf8_lossy(&m).into_owned()),
        (_, m) => bail!("unexpected reply to {line}: {}", String::from_utf8_lossy(&m)),
    }
}

pub fn probe(uds: &Path, port: u16, stop: &(dyn Fn() -> Result<()> + Sync)) -> Result<bool> {
    Ok(readiness(uds, &format!("PROBE {port}"), TIMEOUT, stop)? == "ok")
}

pub fn check(uds: &Path, cmd: &str, timeout: Duration, stop: &(dyn Fn() -> Result<()> + Sync)) -> Result<bool> {
    let hex: String = cmd.bytes().map(|b| format!("{b:02x}")).collect();
    match readiness(uds, &format!("CHECK {} {hex}", timeout.as_millis()), timeout.checked_add(TIMEOUT).ok_or("guest timeout is too large")?, stop)? {
        m if m == "ok" => Ok(true),
        m if m.starts_with("exit ") || m == "timeout" => Ok(false),
        m => bail!("readiness command: {m}"),
    }
}

pub fn quiesce(uds: &Path) -> Result<()> {
    match message(uds, "QUIESCE", TIMEOUT)?.as_str() {
        "ok" => Ok(()),
        m => bail!("quiesce: {m}"),
    }
}

/// Frames end with a message `<status> <next offset>`.
/// `APPIN`: client `stream`'s input for the app's stdin.
pub fn start_appin(s: UnixStream, stream: u64, timeout: Duration) -> Result<BufReader<UnixStream>> {
    request_on(s, &format!("APPIN {stream}"), timeout)
}

pub fn start_logs(s: UnixStream, offset: u64, follow: bool, timeout: Duration) -> Result<BufReader<UnixStream>> {
    request_on(s, &format!("LOGS {offset} {}", follow as u8), timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn attachment_forms_keep_old_agents_compatible() {
        for (form, attach, rejoin) in [
            (AttachForm::Plain, "ATTACH sid 5", "ATTACH sid 5"),
            (AttachForm::Numbered, "ATTACH sid 5 3", "REJOIN sid 5 3"),
            (AttachForm::Epoch, "ATTACH sid 5 3 18446744073709551615", "REJOIN sid 5 3 18446744073709551615"),
        ] {
            assert_eq!(attach_line("sid", 5, 3, u64::MAX, form, false).unwrap(), attach);
            assert_eq!(attach_line("sid", 5, 3, u64::MAX, form, true).unwrap(), rejoin);
            assert!(attach_line("bad/id", 0, 1, 2, form, false).is_err());
        }
    }

    /// A socket standing in for the guest agent's (through Firecracker's vsock), in a fixture directory.
    fn agent(tag: &str) -> (crate::test_util::TempDir, PathBuf, UnixListener) {
        let dir = crate::test_util::TempDir::new(tag);
        let path = dir.join("fixture");
        let listener = UnixListener::bind(&path).unwrap();
        (dir, path, listener)
    }

    /// Accepts the next connection to the agent, checks its CONNECT, and returns it with its request line.
    fn accept(listener: &UnixListener) -> (BufReader<UnixStream>, String) {
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        stream.read_line(&mut line).unwrap();
        assert_eq!(line, format!("CONNECT {PORT}\n"));
        line.clear();
        stream.read_line(&mut line).unwrap();
        (stream, line)
    }

    /// #730: a guest call that finds its Firecracker gone (its vsock socket refusing) is retried until the VM is
    /// marked dead (`abandon`), then fails at once saying so, rather than waiting out its deadline.
    #[test]
    fn a_retried_call_ends_once_its_firecracker_is_marked_dead() {
        let (_dir, path, listener) = agent("dead-fc");
        // Bound and closed: a dead Firecracker's socket, refusing every connect.
        drop(listener);
        let mut attempts = 0;
        // A deadline far off: only the death can end the retries in time.
        let e = answered("TEST", Instant::now() + Duration::from_secs(600), |by| {
            attempts += 1;
            // Its first try refused (and retried); the death comes before the second.
            if attempts == 2 {
                abandon(&path);
            }
            ask(&path, "START", by)
        })
        .unwrap_err();
        assert_eq!((e.to_string().as_str(), attempts), ("its firecracker exited", 2), "ended by the death, not its deadline");
    }

    #[test]
    fn run_settings_must_be_applied_by_the_agent() {
        assert_eq!(app_started("ok 42", false).unwrap(), 42);
        assert_eq!(app_started("ok 42 applied", true).unwrap(), 42);
        assert_eq!(app_started("ok 42 ignored", false).unwrap(), 42);
        assert!(app_started("ok 42 ignored", true).unwrap_err().to_string().contains("already running"));
        assert!(app_started("ok 42", true).unwrap_err().to_string().contains("pull its image again"), "an older agent ignores them");
        assert!(app_started("error: no app", false).unwrap_err().to_string().contains("no app"));
        assert!(app_started("ok x", false).is_err());
    }

    #[test]
    fn argv_wire_preserves_words_and_checks_serialized_size() {
        let cmd = serde_json::json!({"argv": ["printf", "%s", "a b", "", "$HOME"], "env": ["K=v"], "detach": true});
        let body = command_body(&cmd).unwrap();
        let stream = std::io::Cursor::new(Vec::new());
        let sent = session_on("argv", "id", 0, &body, |line| {
            assert_eq!(line, format!("ARGV id {}", body.len()));
            Ok(BufReader::new(stream))
        })
        .unwrap()
        .into_inner()
        .into_inner();
        let e = Exec::decode(std::str::from_utf8(&sent).unwrap()).unwrap();
        assert_eq!(
            e,
            Exec { argv: ["printf", "%s", "a b", "", "$HOME"].map(String::from).into(), env: vec!["K=v".into()], detach: true, ..Default::default() }
        );
        let e = Exec { argv: vec!["x".into()], workdir: Some("/w".into()), user: Some("1:2".into()), ..Default::default() };
        assert_eq!(Exec::decode(&e.encode().unwrap()).unwrap(), e);
        assert!(Exec { argv: vec!["a\0b".into()], ..Default::default() }.encode().is_err());
        for bad in ["", "a", "\0", "x\0", "dx\0"] {
            assert!(Exec::decode(bad).is_err(), "{bad:?}");
        }
        assert_eq!(refusal_status(&format!("error: cannot run x{EXIT_STATUS}127")), Some((127, "error: cannot run x")));
        assert_eq!(refusal_status("error: busy"), None);
        let too_large = command_body(&serde_json::json!({"argv": ["x".repeat(MAX_BODY)]})).unwrap();
        assert!(session_on("argv", "id", 0, &too_large, |_| -> Result<BufReader<std::io::Cursor<Vec<u8>>>> { panic!("must not connect") }).is_err());
    }

    #[test]
    fn an_oversized_command_is_refused_before_connecting() {
        let opened = std::cell::Cell::new(false);
        let open = |_: &str| -> Result<BufReader<UnixStream>> {
            opened.set(true);
            Err("opened".into())
        };
        let e = session_on("start", "id", 0, &"x".repeat(MAX_BODY + 1), open).unwrap_err();
        assert!(e.to_string().contains(&format!("at most {MAX_BODY}")), "{e}");
        assert!(!opened.get());
        assert_eq!(session_on("start", "id", 0, &"x".repeat(MAX_BODY), open).unwrap_err().to_string(), "opened");
        assert!(opened.get());
    }

    #[test]
    fn transient_refusals_share_one_marker() {
        assert!(transient(&format!("vm a{}", crate::vm::CHECKPOINTING)));
        assert!(transient(&format!("error: too many commands arriving at once{TRY_AGAIN}")));
        assert!(!transient("error: too many sessions: 64 commands are running or awaiting their client"));
        assert!(at_session_cap("error: too many sessions: 64 commands are running or awaiting their client"));
        assert!(at_session_cap("error: too many detached or interactive tty sessions: 64 commands are running or awaiting their client"));
        assert!(!at_session_cap("error: too many sessions finished in the last 30 s"));
    }

    #[test]
    fn overflowing_timeouts_fail_before_contacting_the_guest() {
        let path = Path::new("/nonexistent-flexvm-timeout-test");
        for error in [clock(path, Duration::MAX).unwrap_err(), check(path, "true", Duration::MAX, &|| Ok(())).unwrap_err()] {
            assert_eq!(error.to_string(), "guest timeout is too large");
        }
    }

    #[test]
    fn fast_readiness_replies_wake_the_watcher() {
        let (_dir, path, listener) = agent("readiness-fast");
        let (watching, watched) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            for _ in 0..20 {
                let (mut stream, _) = accept(&listener);
                watched.recv_timeout(TIMEOUT).unwrap();
                stream.get_mut().write_all(b"OK 1\n").unwrap();
                write_frame(stream.get_mut(), FRAME_MSG, b"ok").unwrap();
            }
        });
        let start = Instant::now();
        for i in 0..20 {
            let started = std::sync::atomic::AtomicBool::new(false);
            let stop = || {
                if !started.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    watching.send(()).unwrap();
                }
                Ok(())
            };
            assert!(match i % 2 {
                0 => probe(&path, 80, &stop).unwrap(),
                _ => check(&path, "true", Duration::from_secs(1), &stop).unwrap(),
            });
        }
        assert!(start.elapsed() < Duration::from_millis(750), "watchers waited out their polling intervals");
        server.join().unwrap();
    }

    #[test]
    fn readiness_cancellation_shuts_down_an_unanswered_request() {
        let (_dir, path, listener) = agent("readiness-cancel");
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            let client = scope.spawn(|| {
                readiness(&path, "PROBE 80", Duration::from_secs(60), &|| {
                    if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                        bail!("cancelled");
                    }
                    Ok(())
                })
            });
            let (mut stream, line) = accept(&listener);
            assert_eq!(line, "PROBE 80\n");
            cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
            assert_eq!(client.join().unwrap().unwrap_err().to_string(), "cancelled");
        });
    }

    #[test]
    fn readiness_errors_also_stop_the_watcher() {
        let (_dir, path, listener) = agent("readiness-error");
        let server = std::thread::spawn(move || {
            for reply in [None, Some(FRAME_STDOUT)] {
                let (mut stream, _) = accept(&listener);
                stream.get_mut().write_all(b"OK 1\n").unwrap();
                if let Some(kind) = reply {
                    write_frame(stream.get_mut(), kind, b"bad reply").unwrap();
                }
            }
        });
        assert!(readiness(&path, "PROBE 80", TIMEOUT, &|| Ok(())).is_err());
        assert!(readiness(&path, "CHECK 1 78", TIMEOUT, &|| Ok(())).unwrap_err().to_string().contains("unexpected reply"));
        server.join().unwrap();
    }

    #[test]
    fn message_deadline_bounds_a_trickled_frame() {
        let (_dir, path, listener) = agent("message");
        let uds = path.clone();
        let client = std::thread::spawn(move || {
            let start = Instant::now();
            let e = message(&uds, "FORKS", Duration::from_millis(100)).unwrap_err();
            assert_eq!(e.downcast_ref::<std::io::Error>().unwrap().kind(), ErrorKind::TimedOut);
            assert!(start.elapsed() < Duration::from_secs(1));
        });
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"OK 1\n").unwrap();
        let mut frame = Vec::new();
        write_frame(&mut frame, FRAME_MSG, b"ok 123456789").unwrap();
        for byte in frame {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        client.join().unwrap();
    }

    #[test]
    fn exec_deadline_bounds_a_guest_that_keeps_answering() {
        let (_dir, path, listener) = agent("exec");
        let uds = path.clone();
        let client = std::thread::spawn(move || {
            let start = Instant::now();
            let e = exec(&uds, "true", Duration::from_millis(100)).unwrap_err();
            assert_eq!(e.downcast_ref::<std::io::Error>().unwrap().kind(), ErrorKind::TimedOut);
            assert!(start.elapsed() < Duration::from_secs(5) + CLOSE_GRACE);
        });
        // The request after CONNECT.
        let request = |stream: &std::os::unix::net::UnixStream| {
            let mut r = BufReader::new(stream);
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            line.clear();
            r.read_line(&mut line).unwrap();
            line
        };
        let (mut stream, _) = listener.accept().unwrap();
        let id = request(&stream).split_whitespace().nth(1).unwrap().to_string();
        stream.write_all(b"OK 1\n").unwrap();
        let data = vec![b'x'; 64 << 10];
        for i in 0..100 {
            if write_frame(&mut stream, FRAME_STDOUT, &at(i * data.len() as u64, &data)).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Given up on, the command is still closed.
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(request(&stream), format!("CLOSE {id}\n"));
        // CLOSE has its own grace period; the client may already have hung up.
        let _ = stream.write_all(b"OK 1\n");
        let _ = write_frame(&mut stream, FRAME_MSG, b"closed");
        client.join().unwrap();
    }

    #[test]
    fn ping_waits_for_pong_without_a_session() {
        let (_dir, path, listener) = agent("ping");
        for reply in [b"pong".as_slice(), b"error: no shell"] {
            let (tx, rx) = std::sync::mpsc::channel();
            let uds = path.clone();
            let client = std::thread::spawn(move || tx.send(ping(&uds).is_ok()).unwrap());
            let (mut stream, line) = accept(&listener);
            assert_eq!(line, "PING\n");
            stream.get_mut().write_all(b"OK 1\n").unwrap();
            assert!(matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
            write_frame(stream.get_mut(), FRAME_MSG, reply).unwrap();
            assert_eq!(rx.recv_timeout(TIMEOUT).unwrap(), reply == b"pong");
            client.join().unwrap();
        }
    }

    #[test]
    fn current_agent_protocol_is_required() {
        let (_dir, path, listener) = agent("current-agent");
        let replies: &[(&str, &[u8])] = &[
            ("START", b"ok"),
            ("START", b"unknown request START"),
            ("CLOCK", b"ok -2500000"),
            ("CLOCK", b"unknown request CLOCK"),
            ("CLOCK", b"ok"),
            ("CLOCK", b"ok invalid"),
            ("FORKS", b"ok 1"),
            ("FORKS", b"unknown request FORKS"),
        ];
        let server = std::thread::spawn(move || {
            for (verb, reply) in replies {
                let (mut stream, line) = accept(&listener);
                let parts: Vec<_> = line.split_whitespace().collect();
                assert_eq!(parts[0], *verb);
                match *verb {
                    "START" => {
                        assert_eq!(parts[1], "10.0.0.2");
                        assert!(parts[2].parse::<f64>().is_ok());
                        assert_eq!(parts[3], "1.1.1.1");
                    }
                    "CLOCK" => assert!(parts[1].parse::<f64>().is_ok()),
                    _ => assert_eq!(parts.len(), 1),
                }
                stream.get_mut().write_all(b"OK 1\n").unwrap();
                write_frame(stream.get_mut(), FRAME_MSG, reply).unwrap();
            }
        });
        let ip = "10.0.0.2".parse().unwrap();
        start(&path, ip, Some("1.1.1.1")).unwrap();
        let e = start(&path, ip, Some("1.1.1.1")).unwrap_err();
        assert!(e.to_string().contains("guest start: unknown request START; rebuild the rootfs and its templates"), "{e}");
        assert_eq!(clock(&path, TIMEOUT).unwrap(), -2.5);
        assert!(clock(&path, TIMEOUT).unwrap_err().to_string().contains("guest clock: unknown request CLOCK; rebuild the rootfs and its templates"));
        for _ in 0..2 {
            let e = clock(&path, TIMEOUT).unwrap_err();
            assert!(!e.to_string().contains("rebuild"), "{e}");
        }
        assert_eq!(forks(&path).unwrap(), 1);
        assert!(forks(&path).unwrap_err().to_string().contains("guest forks: unknown request FORKS; rebuild the rootfs and its templates"));
        server.join().unwrap();
    }

    fn wire(frames: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut wire = Vec::new();
        frames.iter().for_each(|(kind, data)| write_frame(&mut wire, *kind, data).unwrap());
        wire
    }

    fn at(offset: u64, data: &[u8]) -> Vec<u8> {
        [&offset.to_le_bytes()[..], data].concat()
    }

    #[test]
    fn exec_output_follows_a_session_to_its_exit() {
        let ok = wire(&[
            (FRAME_MSG, b"id".to_vec()),
            (FRAME_STDOUT, at(0, b"ab")),
            (FRAME_MSG, b"waiting".to_vec()),
            (FRAME_STDERR, at(2, b"c")),
            (FRAME_EXIT, at(3, &(-7i32).to_le_bytes())),
        ]);
        let mut got = Vec::new();
        let code = exec_output(&mut ok.as_slice(), "id", |k, d| {
            got.extend([k].iter().chain(d));
            Ok(())
        });
        let code = code.unwrap();
        assert_eq!((code, got), (-7, [&[FRAME_STDOUT][..], b"ab", &[FRAME_STDERR], b"c"].concat()));
        for bad in [(FRAME_STDOUT, at(1, b"x")), (FRAME_LOST, at(5, b"")), (FRAME_MSG, b"error: session closed".to_vec()), (FRAME_EXIT, at(0, b""))] {
            assert!(exec_output(&mut wire(&[bad]).as_slice(), "id", |_, _| Ok(())).is_err());
        }
        assert!(exec_output(&mut &b""[..], "id", |_, _| Ok(())).is_err());
        let old = exec_output(&mut wire(&[(FRAME_MSG, b"unknown request \"SESSION\"".to_vec())]).as_slice(), "id", |_, _| Ok(()));
        assert!(old.unwrap_err().to_string().ends_with("unknown request \"SESSION\"; rebuild the rootfs and its templates"));
    }

    #[test]
    fn session_offsets() {
        let data = at(9, b"abc");
        assert_eq!(session_output(&data, 9).unwrap(), b"abc");
        assert!(session_output(&data, 8).is_err() && session_output(&data, 10).is_err() && session_output(b"short", 0).is_err());
        let exit = at(12, &7i32.to_le_bytes());
        assert_eq!(session_exit(&exit, 12).unwrap(), 7);
        assert!(session_exit(&exit, 11).is_err() && session_exit(&exit[..11], 12).is_err());
    }

    #[test]
    fn retries_only_dropped_connections() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut tries = 0;
        let got = answered("TEST", deadline, |_| {
            tries += 1;
            match tries {
                1 => Err(lost("guest closed the connection")),
                2 => Err(std::io::Error::from(ErrorKind::ConnectionReset).into()),
                _ => Ok(7),
            }
        });
        assert_eq!((got.unwrap(), tries), (7, 3));
        for e in [|| -> Result<()> { bail!("guest clock: bad time") }, || Err(std::io::Error::from(ErrorKind::WouldBlock).into())] {
            let mut tries = 0;
            assert!(answered("TEST", deadline, |_| {
                tries += 1;
                e()
            })
            .is_err());
            assert_eq!(tries, 1);
        }
        let start = Instant::now();
        assert!(answered("TEST", start + Duration::from_millis(50), |_| -> Result<()> { Err(lost("gone")) }).is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn no_attempt_after_the_deadline() {
        // Refused before connecting: the socket's absence is never noticed.
        let e = ask(Path::new("/nonexistent/v.sock"), "PING", Instant::now()).unwrap_err();
        assert_eq!(e.downcast_ref::<std::io::Error>().map(|e| e.kind()), Some(ErrorKind::TimedOut));
        assert!(!dropped(&e));
    }

    #[test]
    fn a_dead_firecrackers_guest_is_not_retried() {
        // A listener that refuses everything, as a dead Firecracker's leftover socket does.
        let dir = crate::test_util::TempDir::new("abandon");
        let uds = dir.join("v.sock");
        drop(std::os::unix::net::UnixListener::bind(&uds).unwrap());
        let start = Instant::now();
        assert!(ping(&uds).is_err());
        assert!(start.elapsed() > Duration::from_millis(500), "refused connections are retried");
        abandon(&uds);
        let start = Instant::now();
        let e = ping(&uds).unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(5) && !dropped(&e), "{e}");
    }

    #[test]
    fn wire_frames_keep_the_header_and_bound_the_payload() {
        for (kind, data) in [(FRAME_STDOUT, b"abc".to_vec()), (255, vec![]), (FRAME_STDERR, vec![42; MAX_BODY])] {
            let wire = frame(kind, &[&data]);
            let mut input = wire.as_slice();
            let got = read_wire_frame(&mut input).unwrap().unwrap();
            assert_eq!((got.kind(), got.data(), got.bytes()), (kind, data.as_slice(), wire.as_slice()));
            assert!(read_wire_frame(&mut input).unwrap().is_none());
            for end in [1, 3, wire.len() - 1] {
                assert!(read_wire_frame(&mut &wire[..end]).is_err());
            }
        }
        let mut oversized = &[1, 255, 255, 255, 255, 42][..];
        assert!(read_wire_frame(&mut oversized).is_err());
        assert_eq!(oversized, [42], "refused before reading the payload");
    }

    #[test]
    fn frames() {
        let wire = [vec![FRAME_STDOUT, 3, 0, 0, 0], b"abc".to_vec()].concat();
        assert_eq!(read_frame(&mut wire.as_slice()).unwrap(), Some((FRAME_STDOUT, b"abc".to_vec())));
        assert!(read_frame(&mut &wire[..7]).is_err());
        assert!(read_frame(&mut &wire[..3]).is_err());
        assert!(read_frame(&mut &b""[..]).unwrap().is_none());
        assert!(read_frame(&mut &[1, 255, 255, 255, 255][..]).is_err());
    }
}
