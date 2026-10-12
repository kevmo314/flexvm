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

/// Opens a connection to the guest agent and sends one request line.
pub fn request(uds: &Path, line: &str) -> Result<BufReader<UnixStream>> {
    let mut s = UnixStream::connect(uds)?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(s, "CONNECT {PORT}\n")?;
    let mut r = BufReader::new(s);
    let mut ok = String::new();
    r.read_line(&mut ok)?;
    if !ok.starts_with("OK") {
        bail!("vsock connect refused: {ok:?}");
    }
    r.get_ref().set_read_timeout(None)?;
    r.get_mut().write_all(format!("{line}\n").as_bytes())?;
    Ok(r)
}

/// Starts a shell command in the guest; frames follow on the returned stream.
pub fn start_exec(uds: &Path, cmd: &str) -> Result<BufReader<UnixStream>> {
    let mut r = request(uds, &format!("EXEC {}", cmd.len()))?;
    r.get_mut().write_all(cmd.as_bytes())?;
    Ok(r)
}

/// Reads one frame. Returns None at end of stream.
pub fn read_frame(r: &mut impl Read) -> Result<Option<(u8, Vec<u8>)>> {
    let mut hdr = [0u8; 5];
    if let Err(e) = r.read_exact(&mut hdr) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e.into());
    }
    let len = u32::from_le_bytes(hdr[1..].try_into().unwrap()) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some((hdr[0], buf)))
}

pub fn ping(uds: &Path) -> Result<()> {
    let mut r = request(uds, "PING")?;
    match read_frame(&mut r)? {
        Some((FRAME_MSG, m)) if m == b"pong" => Ok(()),
        other => bail!("unexpected ping reply {other:?}"),
    }
}

/// Runs a shell command in the guest and collects its output.
pub fn exec(uds: &Path, cmd: &str) -> Result<(i32, Vec<u8>)> {
    let mut r = start_exec(uds, cmd)?;
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
    let mut r = request(uds, &format!("NET {ip} {}", dns.unwrap_or("")))?;
    match read_frame(&mut r)? {
        Some((FRAME_MSG, m)) if m == b"ok" => Ok(()),
        Some((_, m)) => bail!("guest network setup: {}", String::from_utf8_lossy(&m)),
        None => bail!("guest closed the connection during network setup"),
    }
}
