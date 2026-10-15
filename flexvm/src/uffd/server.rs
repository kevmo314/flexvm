use super::{page_runs, Mapping, Pager, MAX_FETCH};
use crate::bail;
use crate::util::{Result, PAGE_SIZE};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SERVE_WRITE: Duration = Duration::from_secs(30);

/// How long a page-server connection may idle while its VM is still a migration source; a client that comes back later
/// just reconnects.
const SERVE_IDLE: Duration = Duration::from_secs(600);

/// Page-server connections this process serves at once, apart from its control connections (#335). A target uses 12
/// (`FAULT_FETCHERS` + `PULL_THREADS`), and more for a while after it reconnects; one past this takes the place of the
/// one idle longest, so connections a peer leaves open never shut out a target's reconnect. Each one's buffer is at
/// most `1 + MAX_FETCH`, so this bounds their buffers too.
const MAX_CONNS: usize = 32;
const _: () = assert!(MAX_CONNS * (1 + MAX_FETCH) <= 40 << 20);
static CONNS: Mutex<Vec<Arc<Conn>>> = Mutex::new(Vec::new());

struct Conn {
    sock: TcpStream,
    /// Since when it has waited for a request; None while it answers one.
    idle: Mutex<Option<Instant>>,
}

/// A page-server connection's place among `MAX_CONNS`, given up when dropped.
pub struct Admitted(Arc<Conn>);

impl Drop for Admitted {
    fn drop(&mut self) {
        CONNS.lock().unwrap().retain(|c| !Arc::ptr_eq(c, &self.0));
    }
}

/// A place for `conn` among the page-server connections; when they are all taken, the one idle longest is shut down
/// for it (its client reconnects when it needs it), or None if every one is answering a request.
pub fn admit(conn: &TcpStream) -> io::Result<Option<Admitted>> {
    let c = Arc::new(Conn { sock: conn.try_clone()?, idle: Mutex::new(Some(Instant::now())) });
    let mut all = CONNS.lock().unwrap();
    if all.len() >= MAX_CONNS {
        let longest = all.iter().enumerate().filter_map(|(i, c)| c.idle.lock().unwrap().map(|t| (t, i))).min();
        let Some((since, i)) = longest else { return Ok(None) };
        let old = all.swap_remove(i);
        crate::log!("page server: {MAX_CONNS} connections; dropping one idle for {} s", since.elapsed().as_secs());
        let _ = old.sock.shutdown(Shutdown::Both);
    }
    all.push(c.clone());
    Ok(Some(Admitted(c)))
}

/// Serves page reads for `pager` on an accepted page-server connection (already answered `ok`), until the client hangs
/// up, sits idle for `SERVE_IDLE` (or longest, as another one is admitted), asks for more than `MAX_FETCH`, or `stop()`
/// says to drop it. `stop` is asked before
/// every request and every second meanwhile, so a connection ends soon after its VM stops being a migration source.
/// `pace()` is called before each reply (a test fault slows the server with it). `conn` is the socket under `stream`, for
/// its timeouts; `admitted` its place (`admit`).
pub fn serve_pages(
    pager: &Pager,
    conn: &TcpStream,
    admitted: &Admitted,
    mut stream: impl Read + Write,
    stop: impl Fn() -> bool,
    pace: impl Fn(),
) -> io::Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(1)))?;
    conn.set_write_timeout(Some(SERVE_WRITE))?;
    let mut req = [0u8; 12];
    let mut buf = Vec::new();
    let idle = |yes: bool| *admitted.0.idle.lock().unwrap() = yes.then(Instant::now);
    while read_request(&mut stream, &mut req, &stop) && !stop() {
        idle(false);
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
        idle(true);
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
        let Some((addr, m)) = self.host_addr(offset) else { return Err(io::Error::other(format!("offset {offset:#x} outside guest memory"))) };
        if offset + len as u64 > m.offset + m.size as u64 {
            return Err(io::Error::other("read crosses a region boundary"));
        }
        let remote = libc::iovec { iov_base: addr as *mut _, iov_len: len };
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
