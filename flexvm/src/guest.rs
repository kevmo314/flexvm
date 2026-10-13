//! Client for flexvm-init's vsock protocol, through Firecracker's vsock UDS.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::bail;
use crate::util::Result;

pub const PORT: u32 = 52;
pub const FRAME_STDOUT: u8 = 1;
pub const FRAME_STDERR: u8 = 2;
pub const FRAME_EXIT: u8 = 3;
pub const FRAME_MSG: u8 = 4;
pub const FRAME_LOST: u8 = 5;

/// How long a request may wait on Firecracker or the guest agent.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// A request whose connection broke before the guest answered it:
/// Firecracker refused or dropped it, or the guest closed it early (e.g. its
/// vsock connections were reset by a restore or a migration). Unlike an
/// answer, worth another try.
#[derive(Debug)]
pub struct Dropped(pub String);

impl std::fmt::Display for Dropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Dropped {}

/// Whether `e` means the request's connection broke (see `Dropped`), as
/// opposed to the guest answering, or not answering in time.
pub fn dropped(e: &crate::util::Error) -> bool {
    use std::io::ErrorKind::*;
    e.is::<Dropped>()
        || e.downcast_ref::<std::io::Error>().is_some_and(|e| {
            matches!(e.kind(), ConnectionRefused | ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof | NotConnected)
        })
}

/// Sends a request (`attempt`, given the time left) until the guest
/// answers it or `deadline` passes: one whose connection dropped goes again
/// after a short pause. Only for requests that are safe to repeat. The agent
/// serves them one at a time in the order they connect, so an earlier try
/// that still reached it never lands after a later one.
pub fn answered<T>(deadline: Instant, mut attempt: impl FnMut(Duration) -> Result<T>) -> Result<T> {
    let mut pause = Duration::from_millis(5);
    loop {
        let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        match attempt(left) {
            Ok(v) => return Ok(v),
            Err(e) if !dropped(&e) || Instant::now() + pause >= deadline => return Err(e),
            Err(_) => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(100));
            }
        }
    }
}

/// Opens a connection to the guest agent and sends one request line. Reads
/// and writes on the returned stream time out after `timeout`.
pub fn request(uds: &Path, line: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    request_on(crate::util::connect_unix(uds, timeout)?, line, timeout)
}

/// `request` on `s`, a fresh connection to Firecracker's vsock socket (so a
/// caller can register it before anything reaches the guest).
pub fn request_on(mut s: UnixStream, line: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    if dropping() {
        let _ = s.shutdown(std::net::Shutdown::Both);
        return Err(Dropped("injected fault: guest connection dropped".into()).into());
    }
    // One write: Firecracker reads the CONNECT line without blocking as soon as
    // any of it arrives, and drops the connection if the line is incomplete.
    // It reads only up to the newline, so the request rides along and is
    // forwarded once the guest accepts, saving a round trip.
    s.write_all(format!("CONNECT {PORT}\n{line}\n").as_bytes())?;
    let mut r = BufReader::new(s);
    let mut ok = String::new();
    r.read_line(&mut ok)?;
    if !ok.starts_with("OK") {
        return Err(Dropped(format!("vsock connect refused: {ok:?}")).into());
    }
    Ok(r)
}

/// Test fault `guest_drop` (see `Daemon::inject`): for this long from the
/// first guest request after it is armed (the start, once known), every
/// guest request's connection is cut before the request reaches the guest,
/// as a refused or reset vsock connection would be.
pub static DROP_FOR: std::sync::Mutex<Option<(Duration, Option<Instant>)>> = std::sync::Mutex::new(None);

fn dropping() -> bool {
    let mut armed = DROP_FOR.lock().unwrap();
    let Some((span, start)) = armed.as_mut() else { return false };
    start.get_or_insert_with(Instant::now).elapsed() < *span
}

/// Starts a shell command in the guest; frames follow on the returned
/// stream, which still has `request`'s timeouts.
pub fn start_exec(s: UnixStream, cmd: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    let mut r = request_on(s, &format!("EXEC {}", cmd.len()), timeout)?;
    r.get_mut().write_all(cmd.as_bytes())?;
    Ok(r)
}

/// Lets a stream from `request` wait on the guest for as long as it takes.
pub fn untimed(r: &BufReader<UnixStream>) -> Result<()> {
    r.get_ref().set_read_timeout(None)?;
    r.get_ref().set_write_timeout(None)?;
    Ok(())
}

/// Starts, resumes or acknowledges a resumable command. Legacy EXEC remains separate.
pub fn session(s: UnixStream, action: &str, id: &str, offset: u64, cmd: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
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

/// Validates a session output frame before any bytes reach the terminal.
pub fn session_output(data: &[u8], offset: u64) -> Result<&[u8]> {
    let header = data.get(..8).ok_or("short session output frame")?;
    let start = u64::from_le_bytes(header.try_into()?);
    if start != offset {
        bail!("session output offset {start}, expected {offset}");
    }
    Ok(&data[8..])
}

pub fn session_exit(data: &[u8], offset: u64) -> Result<i32> {
    if data.len() != 12 {
        bail!("bad session exit frame");
    }
    session_output(data, offset)?;
    Ok(i32::from_le_bytes(data[8..].try_into()?))
}

/// Reads one frame. Returns None at end of stream.
pub fn read_frame(r: &mut impl Read) -> Result<Option<(u8, Vec<u8>)>> {
    let mut hdr = [0u8; 5];
    if let Err(e) = r.read_exact(&mut hdr[..1]) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e.into());
    }
    r.read_exact(&mut hdr[1..])?;
    let len = u32::from_le_bytes(hdr[1..].try_into().unwrap()) as usize;
    if len > 1024 * 1024 {
        bail!("guest frame too large: {len}");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some((hdr[0], buf)))
}

/// Checks that the guest agent answers, within 2 s.
pub fn ping(uds: &Path) -> Result<()> {
    answered(Instant::now() + Duration::from_secs(2), |left| {
        let mut r = request(uds, "PING", left)?;
        match read_frame(&mut r)? {
            Some((FRAME_MSG, m)) if m == b"pong" => Ok(()),
            None => Err(Dropped("guest closed the connection before answering a ping".into()).into()),
            other => bail!("unexpected ping reply {other:?}"),
        }
    })
}

/// Runs a shell command in the guest and collects its output.
pub fn exec(uds: &Path, cmd: &str) -> Result<(i32, Vec<u8>)> {
    let mut r = start_exec(crate::util::connect_unix(uds, TIMEOUT)?, cmd, TIMEOUT)?;
    untimed(&r)?;
    let mut out = Vec::new();
    while let Some((kind, data)) = read_frame(&mut r)? {
        match kind {
            FRAME_EXIT => return Ok((i32::from_le_bytes(data[..4].try_into()?), out)),
            _ => out.extend_from_slice(&data),
        }
    }
    bail!("guest closed the connection before the command exited")
}

/// Tells a just started (or resumed) guest its address, nameserver and the
/// wall-clock time: its clock otherwise carries on from the template snapshot.
/// Doubles as the readiness check. Agents that predate `START` get `NET`
/// instead, and `legacy` remembers that for the template. Bounded by
/// `TIMEOUT`; a dropped connection is retried (see `answered`).
pub fn start(uds: &Path, ip: std::net::Ipv4Addr, dns: Option<&str>, legacy: &AtomicBool) -> Result<()> {
    answered(Instant::now() + TIMEOUT, |left| {
        if legacy.load(Ordering::Relaxed) {
            return net(uds, ip, dns, left);
        }
        let started = Instant::now();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let line = format!("START {ip} {}.{:09} {}", now.as_secs(), now.subsec_nanos(), dns.unwrap_or(""));
        let mut r = request(uds, &line, left)?;
        match read_frame(&mut r)? {
            Some((FRAME_MSG, m)) if m == b"ok" => Ok(()),
            Some((FRAME_MSG, m)) if m.starts_with(b"unknown request") => {
                legacy.store(true, Ordering::Relaxed);
                net(uds, ip, dns, left.saturating_sub(started.elapsed()).max(Duration::from_millis(1)))
            }
            Some((_, m)) => bail!("guest start: {}", String::from_utf8_lossy(&m)),
            None => Err(Dropped("guest closed the connection during start".into()).into()),
        }
    })
}

/// Steps the guest's wall clock to the host's, e.g. after a migration (the
/// guest's clock misses the downtime) or a resume. A no-op for agents that
/// predate it (`legacy`).
///
/// Returns how far off the guest clock was (ms, guest minus host), or None
/// if the agent cannot do it. Bounded by `timeout`; a dropped connection is
/// retried, with the time then (see `answered`).
pub fn clock(uds: &Path, legacy: &AtomicBool, timeout: Duration) -> Result<Option<f64>> {
    if legacy.load(Ordering::Relaxed) {
        return Ok(None);
    }
    answered(Instant::now() + timeout, |left| {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let mut r = request(uds, &format!("CLOCK {}.{:09}", now.as_secs(), now.subsec_nanos()), left)?;
        match read_frame(&mut r)? {
            Some((FRAME_MSG, m)) if m.starts_with(b"ok") => {
                let off: f64 = String::from_utf8_lossy(&m[2..]).trim().parse().unwrap_or(0.0);
                Ok(Some(off / 1e6))
            }
            Some((FRAME_MSG, m)) if m.starts_with(b"unknown request") => {
                legacy.store(true, Ordering::Relaxed);
                Ok(None)
            }
            Some((_, m)) => bail!("guest clock: {}", String::from_utf8_lossy(&m)),
            None => Err(Dropped("guest closed the connection while setting the clock".into()).into()),
        }
    })
}

/// How many times the guest kernel has reseeded its RNG for a new VMGenID
/// (`FORKS`), or None if the agent predates the request.
pub fn forks(uds: &Path) -> Result<Option<usize>> {
    let mut r = request(uds, "FORKS", TIMEOUT)?;
    match read_frame(&mut r)? {
        Some((FRAME_MSG, m)) if m.starts_with(b"ok ") => Ok(Some(String::from_utf8_lossy(&m[3..]).trim().parse()?)),
        Some((FRAME_MSG, m)) if m.starts_with(b"unknown request") => Ok(None),
        Some((_, m)) => bail!("guest forks: {}", String::from_utf8_lossy(&m)),
        None => bail!("guest closed the connection"),
    }
}

/// Sets the guest's address (and nameserver), within `timeout`: `start`
/// for agents that predate `START`.
fn net(uds: &Path, ip: std::net::Ipv4Addr, dns: Option<&str>, timeout: Duration) -> Result<()> {
    let mut r = request(uds, &format!("NET {ip} {}", dns.unwrap_or("")), timeout)?;
    match read_frame(&mut r)? {
        Some((FRAME_MSG, m)) if m == b"ok" => Ok(()),
        Some((_, m)) => bail!("guest network setup: {}", String::from_utf8_lossy(&m)),
        None => Err(Dropped("guest closed the connection during network setup".into()).into()),
    }
}

/// Sends a request whose reply is one message frame.
fn message(uds: &Path, line: &str) -> Result<String> {
    let mut r = request(uds, line, TIMEOUT)?;
    match read_frame(&mut r)? {
        Some((FRAME_MSG, m)) => Ok(String::from_utf8_lossy(&m).into_owned()),
        Some((_, m)) => bail!("unexpected reply to {line}: {}", String::from_utf8_lossy(&m)),
        None => bail!("guest closed the connection during {line}"),
    }
}

/// Starts an image template's app (a no-op if it is running). Returns its pid.
pub fn start_app(uds: &Path) -> Result<u32> {
    let reply = message(uds, "APP")?;
    match reply.strip_prefix("ok ") {
        Some(pid) => Ok(pid.trim().parse()?),
        None => bail!("starting the app: {}", reply.trim_start_matches("error: ")),
    }
}

/// `idle`, `running <pid>` or `exited <code>`.
pub fn app_status(uds: &Path) -> Result<String> {
    message(uds, "APPSTATUS")
}

/// Whether something in the guest accepts connections on 127.0.0.1:port.
pub fn probe(uds: &Path, port: u16) -> Result<bool> {
    Ok(message(uds, &format!("PROBE {port}"))? == "ok")
}

/// Runs a readiness command (`sh -c`) in the guest with its output
/// discarded; the guest kills it if it runs past `timeout`. True on exit 0.
pub fn check(uds: &Path, cmd: &str, timeout: Duration) -> Result<bool> {
    let hex: String = cmd.bytes().map(|b| format!("{b:02x}")).collect();
    let mut r = request(uds, &format!("CHECK {} {hex}", timeout.as_millis()), timeout + TIMEOUT)?;
    match read_frame(&mut r)? {
        Some((FRAME_MSG, m)) if m == b"ok" => Ok(true),
        Some((FRAME_MSG, m)) if m.starts_with(b"exit ") || m == b"timeout" => Ok(false),
        Some((_, m)) => bail!("readiness command: {}", String::from_utf8_lossy(&m)),
        None => bail!("guest closed the connection during the readiness command"),
    }
}

/// Syncs and drops guest caches before a snapshot, without needing a shell.
pub fn quiesce(uds: &Path) -> Result<()> {
    match message(uds, "QUIESCE")?.as_str() {
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

    #[test]
    fn session_offsets() {
        let data = [9u64.to_le_bytes().as_slice(), b"abc"].concat();
        assert_eq!(session_output(&data, 9).unwrap(), b"abc");
        assert!(session_output(&data, 8).is_err());
        assert!(session_output(&data, 10).is_err());
        assert!(session_output(b"short", 0).is_err());
        let exit = [12u64.to_le_bytes().as_slice(), &7i32.to_le_bytes()].concat();
        assert_eq!(session_exit(&exit, 12).unwrap(), 7);
        assert!(session_exit(&exit, 11).is_err());
        assert!(session_exit(&exit[..11], 12).is_err());
    }

    #[test]
    fn retries_only_dropped_connections() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut tries = 0;
        let got = answered(deadline, |_| {
            tries += 1;
            match tries {
                1 => Err(Dropped("guest closed the connection".into()).into()),
                2 => Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into()),
                _ => Ok(7),
            }
        });
        assert_eq!((got.unwrap(), tries), (7, 3));
        // An answer, or no answer in time, is final.
        for e in [|| -> Result<()> { bail!("guest clock: bad time") }, || Err(std::io::Error::from(std::io::ErrorKind::WouldBlock).into())] {
            let mut tries = 0;
            assert!(answered(deadline, |_| {
                tries += 1;
                e()
            })
            .is_err());
            assert_eq!(tries, 1);
        }
        let start = Instant::now();
        assert!(answered(start + Duration::from_millis(50), |_| -> Result<()> { Err(Dropped("gone".into()).into()) }).is_err());
        assert!(start.elapsed() < Duration::from_millis(500));
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
