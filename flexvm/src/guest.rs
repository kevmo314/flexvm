//! Client for flexvm-init's vsock protocol, through Firecracker's vsock UDS.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

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

/// Opens a connection to the guest agent and sends one request line. Reads
/// and writes on the returned stream time out after `timeout`.
pub fn request(uds: &Path, line: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    let mut s = crate::util::connect_unix(uds, timeout)?;
    // One write: Firecracker reads the CONNECT line without blocking as soon as
    // any of it arrives, and drops the connection if the line is incomplete.
    // It reads only up to the newline, so the request rides along and is
    // forwarded once the guest accepts, saving a round trip.
    s.write_all(format!("CONNECT {PORT}\n{line}\n").as_bytes())?;
    let mut r = BufReader::new(s);
    let mut ok = String::new();
    r.read_line(&mut ok)?;
    if !ok.starts_with("OK") {
        bail!("vsock connect refused: {ok:?}");
    }
    Ok(r)
}

/// Starts a shell command in the guest; frames follow on the returned
/// stream, which still has `request`'s timeouts.
pub fn start_exec(uds: &Path, cmd: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    let mut r = request(uds, &format!("EXEC {}", cmd.len()), timeout)?;
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
pub fn session(uds: &Path, action: &str, id: &str, offset: u64, cmd: &str, timeout: Duration) -> Result<BufReader<UnixStream>> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        bail!("bad session id");
    }
    let line = match action {
        "start" => format!("SESSION {id} {}", cmd.len()),
        "attach" => format!("ATTACH {id} {offset}"),
        "close" => format!("CLOSE {id}"),
        _ => bail!("bad session action"),
    };
    let mut r = request(uds, &line, timeout)?;
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

pub fn ping(uds: &Path) -> Result<()> {
    let mut r = request(uds, "PING", Duration::from_secs(2))?;
    match read_frame(&mut r)? {
        Some((FRAME_MSG, m)) if m == b"pong" => Ok(()),
        other => bail!("unexpected ping reply {other:?}"),
    }
}

/// Runs a shell command in the guest and collects its output.
pub fn exec(uds: &Path, cmd: &str) -> Result<(i32, Vec<u8>)> {
    let mut r = start_exec(uds, cmd, TIMEOUT)?;
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

/// Sets the guest's address (and nameserver). Doubles as the readiness check.
pub fn net(uds: &Path, ip: std::net::Ipv4Addr, dns: Option<&str>) -> Result<()> {
    let mut r = request(uds, &format!("NET {ip} {}", dns.unwrap_or("")), TIMEOUT)?;
    match read_frame(&mut r)? {
        Some((FRAME_MSG, m)) if m == b"ok" => Ok(()),
        Some((_, m)) => bail!("guest network setup: {}", String::from_utf8_lossy(&m)),
        None => bail!("guest closed the connection during network setup"),
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
pub fn start_logs(uds: &Path, offset: u64, follow: bool, timeout: Duration) -> Result<BufReader<UnixStream>> {
    request(uds, &format!("LOGS {offset} {}", follow as u8), timeout)
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
    fn frames() {
        let wire = [vec![FRAME_STDOUT, 3, 0, 0, 0], b"abc".to_vec()].concat();
        assert_eq!(read_frame(&mut wire.as_slice()).unwrap(), Some((FRAME_STDOUT, b"abc".to_vec())));
        assert!(read_frame(&mut &wire[..7]).is_err());
        assert!(read_frame(&mut &wire[..3]).is_err());
        assert!(read_frame(&mut &b""[..]).unwrap().is_none());
        assert!(read_frame(&mut &[1, 255, 255, 255, 255][..]).is_err());
    }
}
