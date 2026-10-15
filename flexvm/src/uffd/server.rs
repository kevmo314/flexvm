use super::{page_runs, Mapping, Pager, MAX_FETCH};
use crate::bail;
use crate::util::{Result, PAGE_SIZE};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const SERVE_WRITE: Duration = Duration::from_secs(30);

/// How long a page-server connection may idle while its VM is still a migration source; a client that comes back later
/// just reconnects.
const SERVE_IDLE: Duration = Duration::from_secs(600);

/// Serves page reads for `pager` on an accepted page-server connection (already answered `ok`), until the client hangs
/// up, sits idle for `SERVE_IDLE`, asks for more than `MAX_FETCH`, or `stop()` says to drop it. `stop` is asked before
/// every request and every second meanwhile, so a connection ends soon after its VM stops being a migration source.
/// `pace()` is called before each reply (a test fault slows the server with it). `conn` is the socket under `stream`, for
/// its timeouts.
pub fn serve_pages(pager: &Pager, conn: &TcpStream, mut stream: impl Read + Write, stop: impl Fn() -> bool, pace: impl Fn()) -> io::Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(1)))?;
    conn.set_write_timeout(Some(SERVE_WRITE))?;
    let mut req = [0u8; 12];
    let mut buf = Vec::new();
    while read_request(&mut stream, &mut req, &stop) && !stop() {
        let offset = u64::from_le_bytes(req[..8].try_into().unwrap());
        let len = u32::from_le_bytes(req[8..].try_into().unwrap()) as usize;
        if len > MAX_FETCH {
            crate::log!("page server: refusing a {len}-byte read (at most {MAX_FETCH}); dropping the connection");
            return stream.write_all(&[1]);
        }
        // The status byte, then the pages: sent with one write. The buffer only grows (zeroed once): `read_guest`
        // overwrites what is sent.
        pace();
        if buf.len() < 1 + len {
            buf.resize(1 + len, 0);
        }
        let reply = &mut buf[..1 + len];
        reply[0] = 0;
        match pager.read_guest(offset, &mut reply[1..]) {
            Ok(()) => stream.write_all(reply)?,
            Err(e) => {
                crate::log!("page server: {e}");
                stream.write_all(&[1])?;
            }
        }
    }
    Ok(())
}

/// Reads one 12-byte request through the socket's 1 s read timeout. False when the client hung up or the connection
/// should end (`stop`, or idle for `SERVE_IDLE`).
fn read_request(stream: &mut impl Read, req: &mut [u8; 12], stop: &impl Fn() -> bool) -> bool {
    let since = Instant::now();
    let mut n = 0;
    while n < req.len() {
        match stream.read(&mut req[n..]) {
            Ok(0) => return false,
            Ok(k) => n += k,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if stop() || since.elapsed() >= SERVE_IDLE {
                    return false;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

impl Pager {
    pub fn read_guest(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        Ok(self.read_at(offset, &[libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() }])?)
    }

    /// Reads guest memory from `offset` out of Firecracker into the buffers `local`, as many bytes as they hold, all
    /// within one region.
    pub(super) fn read_at(&self, offset: u64, local: &[libc::iovec]) -> io::Result<()> {
        let len: usize = local.iter().map(|v| v.iov_len).sum();
        let Some(m) = self.locate(offset) else { return Err(io::Error::other(format!("offset {offset:#x} outside guest memory"))) };
        if offset + len as u64 > m.offset + m.size as u64 {
            return Err(io::Error::other("read crosses a region boundary"));
        }
        let remote = libc::iovec { iov_base: (m.base_host_virt_addr + (offset - m.offset)) as *mut _, iov_len: len };
        let pid = self.pid.load(Ordering::SeqCst) as libc::pid_t;
        if unsafe { libc::process_vm_readv(pid, local.as_ptr(), local.len() as _, &remote, 1, 0) } != len as isize {
            return Err(io::Error::other(format!("process_vm_readv: {}", io::Error::last_os_error())));
        }
        // The pid was Firecracker's all along.
        if self.exited() {
            return Err(io::Error::other("firecracker exited"));
        }
        Ok(())
    }

    /// Reads the pages of `list` (one page of `data` each) out of the paused Firecracker, a run of consecutive pages at
    /// a time.
    pub fn read_preload(&self, list: &[u64], data: &mut [u8]) -> Result<()> {
        let pid = self.pid.load(Ordering::SeqCst) as libc::pid_t;
        capture_preload(self.mappings(), list, data, |local, remote| {
            match unsafe { libc::process_vm_readv(pid, local.as_ptr(), local.len() as _, remote.as_ptr(), remote.len() as _, 0) } {
                n if n < 0 => Err(io::Error::last_os_error()),
                n => Ok(n as usize),
            }
        })?;
        if self.exited() {
            bail!("firecracker exited");
        }
        Ok(())
    }

    /// Whether Firecracker has exited (or was never named): what was just read by its pid may then be another
    /// process's.
    pub(super) fn exited(&self) -> bool {
        self.pidfd.get().is_none_or(|fd| crate::util::readable(fd, Duration::ZERO).unwrap_or(true))
    }
}

/// Reads the pages of `list` into `data` (a page each), a run per iovec and up to IOV_MAX of them per `read(local,
/// remote)`, which returns the bytes read.
pub(super) fn capture_preload(
    mappings: &[Mapping],
    list: &[u64],
    data: &mut [u8],
    mut read: impl FnMut(&[libc::iovec], &[libc::iovec]) -> io::Result<usize>,
) -> Result<()> {
    if data.len() != list.len() * PAGE_SIZE {
        bail!("preload of {} pages has {} bytes", list.len(), data.len());
    }
    let mut runs = page_runs(list, mappings).peekable();
    while runs.peek().is_some() {
        let (mut local, mut remote, mut bytes) = (Vec::new(), Vec::new(), 0);
        for (index, n) in runs.by_ref().take(1024) {
            let offset = list[index] * PAGE_SIZE as u64;
            let Some(m) = mappings.iter().find(|m| offset >= m.offset && offset < m.offset + m.size as u64) else {
                bail!("offset {offset:#x} outside guest memory");
            };
            let len = n * PAGE_SIZE;
            local.push(libc::iovec { iov_base: data[index * PAGE_SIZE..].as_mut_ptr().cast(), iov_len: len });
            remote.push(libc::iovec { iov_base: (m.base_host_virt_addr + offset - m.offset) as *mut _, iov_len: len });
            bytes += len;
        }
        let read = read(&local, &remote)?;
        if read != bytes {
            bail!("read {read} of {bytes} bytes of preloaded pages");
        }
    }
    Ok(())
}
