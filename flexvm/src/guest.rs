//! Client for flexvm-init's vsock protocol, through Firecracker's vsock UDS.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::bail;
use crate::host::fault;
use crate::util::{By, Error, Result};

#[path = "../../guest/src/proto.rs"]
mod proto;
pub use proto::*;

/// How long a request may wait on Firecracker or the guest agent.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// A request whose connection broke before the guest answered it: Firecracker
/// refused or dropped it, or the guest closed it early (e.g. a restore or a
/// migration reset its vsock connections). Unlike an answer, worth another try.
fn lost(why: impl Into<String>) -> Error {
    std::io::Error::new(ErrorKind::ConnectionAborted, why.into()).into()
}

/// Whether `e` means the request's connection broke (see `lost`), as opposed
/// to the guest answering, or not answering in time.
pub fn dropped(e: &Error) -> bool {
    use ErrorKind::*;
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|e| matches!(e.kind(), ConnectionRefused | ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof | NotConnected))
}

/// Sends a request (`attempt`, given the deadline for all of its I/O) until the
/// guest answers it or `deadline` passes, again after a short pause whenever its
/// connection dropped (counted under `what`). Only for requests safe to repeat:
/// the agent serves them in connection order, so an earlier try never lands last.
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

/// How many times each kind of retried guest request went again.
pub fn retries() -> BTreeMap<&'static str, u64> {
    RETRIES.lock().unwrap().clone()
}

/// Asks Firecracker to connect to the agent, with request `line` in the same
/// write: Firecracker reads only up to the CONNECT line's newline (dropping
/// the connection if it is incomplete) and forwards the rest once the guest
/// accepts, saving a round trip.
fn handshake<S: Read + Write>(s: S, line: &str) -> Result<BufReader<S>> {
    let mut r = BufReader::new(s);
    r.get_mut().write_all(format!("CONNECT {PORT}\n{line}\n").as_bytes())?;
    let mut ok = String::new();
    r.by_ref().take(64).read_line(&mut ok)?;
    if !ok.starts_with("OK") {
        return Err(lost(format!("vsock connect refused: {ok:?}")));
    }
    Ok(r)
}

/// Sends one request line and reads the one frame that answers it, all of
/// it (connecting, the handshake, every partial write and read) by
/// `deadline`; none is sent once that has passed. Test faults (`flexvm debug
/// fault`): `guest_drop` cuts the connection before the request reaches the
/// guest, `guest_lose_reply` loses the reply to a request carried out.
fn ask(uds: &Path, line: &str, deadline: Instant) -> Result<(u8, Vec<u8>)> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(std::io::Error::new(ErrorKind::TimedOut, format!("no time left for {line:?}")).into());
    }
    let s = crate::util::connect_unix(uds, left)?;
    if fault("guest_drop") {
        return Err(lost("injected fault: guest connection refused"));
    }
    let reply = read_frame(&mut handshake(By { s, at: deadline }, line)?)?;
    let reply = reply.ok_or_else(|| lost(format!("guest closed the connection before answering {line:?}")))?;
    if fault("guest_lose_reply") {
        return Err(lost("injected fault: guest reply lost"));
    }
    Ok(reply)
}

/// Opens a connection to the guest agent and sends one request line. Reads
/// and writes on the returned stream time out after `timeout`.
pub fn request(uds: &Path, line: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    request_on(crate::util::connect_unix(uds, timeout)?, line, timeout)
}

/// `request` on `s`, a fresh connection to Firecracker's vsock socket (so a
/// caller can register it before anything reaches the guest).
pub fn request_on(s: UnixStream, line: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    handshake(s, line)
}

/// Lets a stream from `request` wait on the guest for as long as it takes.
pub fn untimed(r: &BufReader<UnixStream>) -> Result<()> {
    r.get_ref().set_read_timeout(None)?;
    Ok(r.get_ref().set_write_timeout(None)?)
}

/// A fresh random session id.
pub fn session_id() -> Result<String> {
    let mut random = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(random.iter().map(|b| format!("{b:02x}")).collect())
}

/// Starts, resumes or acknowledges a resumable command.
pub fn session(s: UnixStream, action: &str, id: &str, offset: u64, cmd: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    if !valid_session_id(id) {
        bail!("bad session id");
    }
    let line = match action {
        "start" => format!("SESSION {id} {}", cmd.len()),
        "attach" => format!("ATTACH {id} {offset}"),
        "close" => format!("CLOSE {id}"),
        _ => bail!("bad session action"),
    };
    let mut r = request_on(s, &line, timeout)?;
    if action == "start" {
        r.get_mut().write_all(cmd.as_bytes())?;
    }
    Ok(r)
}

/// Starts a shell command in the guest as a session under a fresh id. Its
/// frames follow on the returned stream (see `exec_output`), which still has
/// `request`'s timeouts; `close` the session once it has exited.
pub fn start_exec(s: UnixStream, cmd: &str, timeout: Duration) -> Result<(BufReader<UnixStream>, String)> {
    let id = session_id()?;
    Ok((session(s, "start", &id, 0, cmd, timeout)?, id))
}

/// Follows session `id` from its start to its exit, handing each piece of
/// output (frame kind, bytes) to `out`. Returns the exit code.
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
            Some((_, m)) => bail!("guest command: {}", String::from_utf8_lossy(&m)),
            None => bail!("guest closed the connection before the command exited"),
        }
    }
}

/// Closes session `id` once it has exited, freeing its output, by `deadline`.
pub fn close(uds: &Path, id: &str, deadline: Instant) -> Result<()> {
    match ask(uds, &format!("CLOSE {id}"), deadline)? {
        (FRAME_MSG, m) if m == b"closed" => Ok(()),
        (_, m) => bail!("closing session {id}: {}", String::from_utf8_lossy(&m)),
    }
}

/// Validates a session output frame before any bytes reach the terminal.
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

pub fn write_frame(w: &mut impl Write, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&[&[kind][..], &(payload.len() as u32).to_le_bytes()].concat())?;
    w.write_all(payload)
}

/// Reads one frame. Returns None at end of stream.
pub fn read_frame(r: &mut impl Read) -> Result<Option<(u8, Vec<u8>)>> {
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
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some((hdr[0], buf)))
}

/// Checks that the guest agent answers, within 2 s.
pub fn ping(uds: &Path) -> Result<()> {
    answered("PING", Instant::now() + Duration::from_secs(2), |by| match ask(uds, "PING", by)? {
        (FRAME_MSG, m) if m == b"pong" => Ok(()),
        other => bail!("unexpected ping reply {other:?}"),
    })
}

/// Runs a shell command in the guest and collects its output.
pub fn exec(uds: &Path, cmd: &str) -> Result<(i32, Vec<u8>)> {
    let (mut r, id) = start_exec(crate::util::connect_unix(uds, TIMEOUT)?, cmd, TIMEOUT)?;
    untimed(&r)?;
    let mut out = Vec::new();
    let code = exec_output(&mut r, &id, |_, data| {
        out.extend_from_slice(data);
        Ok(())
    })?;
    close(uds, &id, Instant::now() + TIMEOUT)?;
    Ok((code, out))
}

fn now() -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(format!("{}.{:09}", now.as_secs(), now.subsec_nanos()))
}

/// Tells a just started (or resumed) guest its address, nameserver and the wall
/// clock (otherwise it carries on from the snapshot); doubles as the readiness
/// check. Agents that predate `START` get `NET`, remembered in `legacy`.
pub fn start(uds: &Path, ip: std::net::Ipv4Addr, dns: Option<&str>, legacy: &AtomicBool) -> Result<()> {
    let dns = dns.unwrap_or("");
    answered("START", Instant::now() + TIMEOUT, |by| {
        let reply = match legacy.load(Ordering::Relaxed) {
            true => None,
            false => Some(ask(uds, &format!("START {ip} {} {dns}", now()?), by)?),
        };
        match reply {
            Some((FRAME_MSG, m)) if m == b"ok" => Ok(()),
            Some((FRAME_MSG, m)) if !m.starts_with(b"unknown request") => bail!("guest start: {}", String::from_utf8_lossy(&m)),
            Some((FRAME_MSG, _)) | None => {
                legacy.store(true, Ordering::Relaxed);
                match ask(uds, &format!("NET {ip} {dns}"), by)? {
                    (FRAME_MSG, m) if m == b"ok" => Ok(()),
                    (_, m) => bail!("guest network setup: {}", String::from_utf8_lossy(&m)),
                }
            }
            Some((_, m)) => bail!("guest start: {}", String::from_utf8_lossy(&m)),
        }
    })
}

/// Steps the guest's wall clock to the host's, e.g. after a migration (the
/// guest's clock misses the downtime) or a resume. Returns how far off the
/// guest clock was (ms, guest minus host), or None for agents that predate it
/// (`legacy`). Bounded by `timeout`; a dropped connection is retried, with
/// the time then (see `answered`).
pub fn clock(uds: &Path, legacy: &AtomicBool, timeout: Duration) -> Result<Option<f64>> {
    if legacy.load(Ordering::Relaxed) {
        return Ok(None);
    }
    answered("CLOCK", Instant::now() + timeout, |by| match ask(uds, &format!("CLOCK {}", now()?), by)? {
        (FRAME_MSG, m) if m.starts_with(b"ok") => Ok(Some(String::from_utf8_lossy(&m[2..]).trim().parse().unwrap_or(0.0) / 1e6)),
        (FRAME_MSG, m) if m.starts_with(b"unknown request") => {
            legacy.store(true, Ordering::Relaxed);
            Ok(None)
        }
        (_, m) => bail!("guest clock: {}", String::from_utf8_lossy(&m)),
    })
}

/// Sends a request whose reply is one message frame.
fn message(uds: &Path, line: &str, timeout: Duration) -> Result<String> {
    match read_frame(&mut request(uds, line, timeout)?)? {
        Some((FRAME_MSG, m)) => Ok(String::from_utf8_lossy(&m).into_owned()),
        Some((_, m)) => bail!("unexpected reply to {line}: {}", String::from_utf8_lossy(&m)),
        None => bail!("guest closed the connection during {line}"),
    }
}

/// How many times the guest kernel has reseeded its RNG for a new VMGenID
/// (`FORKS`), or None if the agent predates the request.
pub fn forks(uds: &Path) -> Result<Option<usize>> {
    match message(uds, "FORKS", TIMEOUT)? {
        m if m.starts_with("unknown request") => Ok(None),
        m => Ok(Some(m.strip_prefix("ok ").ok_or_else(|| format!("guest forks: {m}"))?.trim().parse()?)),
    }
}

/// Starts an image template's app (a no-op if it is running). Returns its pid.
pub fn start_app(uds: &Path) -> Result<u32> {
    let reply = message(uds, "APP", TIMEOUT)?;
    match reply.strip_prefix("ok ") {
        Some(pid) => Ok(pid.trim().parse()?),
        None => bail!("starting the app: {}", reply.trim_start_matches("error: ")),
    }
}

/// `idle`, `running <pid>` or `exited <code>`.
pub fn app_status(uds: &Path) -> Result<String> {
    message(uds, "APPSTATUS", TIMEOUT)
}

/// Whether something in the guest accepts connections on 127.0.0.1:port.
pub fn probe(uds: &Path, port: u16) -> Result<bool> {
    Ok(message(uds, &format!("PROBE {port}"), TIMEOUT)? == "ok")
}

/// Runs a readiness command (`sh -c`) in the guest with its output
/// discarded; the guest kills it if it runs past `timeout`. True on exit 0.
pub fn check(uds: &Path, cmd: &str, timeout: Duration) -> Result<bool> {
    let hex: String = cmd.bytes().map(|b| format!("{b:02x}")).collect();
    match message(uds, &format!("CHECK {} {hex}", timeout.as_millis()), timeout + TIMEOUT)? {
        m if m == "ok" => Ok(true),
        m if m.starts_with("exit ") || m == "timeout" => Ok(false),
        m => bail!("readiness command: {m}"),
    }
}

/// Syncs and drops guest caches before a snapshot, without needing a shell.
pub fn quiesce(uds: &Path) -> Result<()> {
    match message(uds, "QUIESCE", TIMEOUT)?.as_str() {
        "ok" => Ok(()),
        m => bail!("quiesce: {m}"),
    }
}

/// Streams the app's output from `offset`; frames follow on the returned
/// stream, which still has `request`'s timeouts, and end with a message
/// `<status> <next offset>`.
pub fn start_logs(s: UnixStream, offset: u64, follow: bool, timeout: Duration) -> Result<BufReader<UnixStream>> {
    request_on(s, &format!("LOGS {offset} {}", follow as u8), timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // A gap, a loss, an error, a short exit frame or a cut stream fail.
        for bad in [(FRAME_STDOUT, at(1, b"x")), (FRAME_LOST, at(5, b"")), (FRAME_MSG, b"error: session closed".to_vec()), (FRAME_EXIT, at(0, b""))] {
            assert!(exec_output(&mut wire(&[bad]).as_slice(), "id", |_, _| Ok(())).is_err());
        }
        assert!(exec_output(&mut &b""[..], "id", |_, _| Ok(())).is_err());
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
        // An answer, or no answer in time, is final.
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
        assert!(start.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn no_attempt_after_the_deadline() {
        // Refused before connecting: the socket's absence is never noticed.
        let e = ask(Path::new("/nonexistent/v.sock"), "PING", Instant::now()).unwrap_err();
        assert_eq!(e.downcast_ref::<std::io::Error>().map(|e| e.kind()), Some(ErrorKind::TimedOut));
        assert!(!dropped(&e));
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
