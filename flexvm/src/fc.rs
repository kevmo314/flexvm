//! A Firecracker process and a minimal client for its HTTP-over-UDS API.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::Value;

use crate::bail;
use crate::socket::{SocketRoot, Sockets};
use crate::util::{retry, Result};

/// How long a new Firecracker has to open its API socket.
pub const SPAWN_READY: Duration = Duration::from_secs(5);

/// Deadline for a Firecracker API call that does not pick its own.
pub const API_TIMEOUT: Duration = Duration::from_secs(30);

/// A request that never reached Firecracker: its API socket would not take
/// a connection (it is dead, say). Any other failure, an error answer
/// included, may come after Firecracker acted on some of it.
#[derive(Debug)]
pub struct NotSent(String);

impl std::fmt::Display for NotSent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NotSent {}

/// Whether `e` says the request never reached Firecracker.
pub fn not_sent(e: &crate::util::Error) -> bool {
    e.downcast_ref::<NotSent>().is_some()
}

pub struct Firecracker {
    child: Child,
    pub sockets: Sockets,
}

impl Firecracker {
    /// Starts Firecracker with private sockets and a log inside `dir`, and
    /// waits up to `ready` for its API socket.
    pub fn spawn(bin: &Path, dir: &Path, sockets: Sockets, ready: Duration) -> Result<Self> {
        crate::socket::check(&sockets.api)?;
        let log = File::create(dir.join("firecracker.log"))?;
        let child = Command::new(bin)
            .arg("--api-sock")
            .arg(&sockets.api)
            .arg("--level")
            .arg("Warn")
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?;
        let fc = Firecracker { child, sockets };
        retry(ready, || Ok(UnixStream::connect(&fc.sockets.api)?))?;
        Ok(fc)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn put(&self, path: &str, body: Value) -> Result<Value> {
        self.request("PUT", path, Some(body))
    }

    pub fn patch(&self, path: &str, body: Value) -> Result<Value> {
        self.request("PATCH", path, Some(body))
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        self.request("GET", path, None)
    }

    pub fn pause(&self) -> Result<()> {
        self.patch("/vm", serde_json::json!({"state": "Paused"})).map(|_| ())
    }

    pub fn resume(&self) -> Result<()> {
        self.patch("/vm", serde_json::json!({"state": "Resumed"})).map(|_| ())
    }

    /// Every call has a deadline, so none can hold a VM's API lock forever.
    fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        self.request_within(method, path, body, API_TIMEOUT)
    }

    /// `request`, all of it (connecting, writing, every read) within `timeout`.
    pub fn request_within(&self, method: &str, path: &str, body: Option<Value>, timeout: Duration) -> Result<Value> {
        if timeout.is_zero() {
            bail!("firecracker {method} {path}: out of time");
        }
        let at = std::time::Instant::now() + timeout;
        let s = crate::util::connect_unix(&self.sockets.api, timeout)
            .map_err(|e| Box::new(NotSent(format!("firecracker {method} {path}: cannot connect: {e}"))))?;
        self.send(crate::util::By { s, at }, method, path, body)
    }

    fn send(&self, mut stream: crate::util::By<UnixStream>, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        // One write, so Firecracker's API thread wakes once per request.
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(req.as_bytes())?;
        let mut r = BufReader::new(stream);
        let mut status = String::new();
        r.read_line(&mut status)?;
        let code: u16 = status.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        let mut len = 0usize;
        loop {
            let mut h = String::new();
            r.read_line(&mut h)?;
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        let text = String::from_utf8_lossy(&buf);
        if code == 0 {
            bail!("firecracker {method} {path}: no status in the answer");
        }
        if !(200..300).contains(&code) {
            bail!("firecracker {method} {path}: {code} {text}");
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text.into_owned())))
    }

    /// Whether the process is still running (it has not exited or been killed).
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// How Firecracker exited, if it has, and the end of its log: why a
    /// request to it failed.
    pub fn post_mortem(&mut self, dir: &Path) -> String {
        let status = match self.child.try_wait() {
            Ok(Some(st)) => format!("exited ({st})"),
            Ok(None) => "still running".into(),
            Err(e) => format!("unknown ({e})"),
        };
        let log = File::open(dir.join("firecracker.log")).and_then(|mut f| log_tail(&mut f)).unwrap_or_default();
        let tail: Vec<&str> = log.lines().rev().take(5).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        format!("firecracker {} {status}; log: {}", self.pid(), tail.join(" | "))
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.sockets.cleanup();
    }
}

/// Reads at most the last 64 KiB, dropping the first partial line when
/// seeking into a log. Invalid UTF-8 is replaced, not fatal.
fn log_tail(r: &mut (impl Read + Seek)) -> std::io::Result<String> {
    const MAX: u64 = 64 << 10;
    let len = r.seek(SeekFrom::End(0))?;
    // One byte before the tail tells whether it starts on a line boundary.
    let start = len.saturating_sub(MAX + 1);
    r.seek(SeekFrom::Start(start))?;
    let mut log = Vec::new();
    r.take(MAX + 1).read_to_end(&mut log)?;
    if log.len() as u64 > MAX {
        let end = log.iter().position(|&b| b == b'\n').map_or(log.len(), |i| i + 1);
        log.drain(..end);
    }
    Ok(String::from_utf8_lossy(&log).into_owned())
}

impl Drop for Firecracker {
    fn drop(&mut self) {
        self.kill();
    }
}

/// An idle Firecracker with its directory, (already joined) cgroup and tap.
/// Dropping it kills the Firecracker and removes all three.
pub struct Idle {
    pub fc: Firecracker,
    pub dir: PathBuf,
    pub cgroup: Option<PathBuf>,
    pub tap: String,
}

impl Idle {
    /// Takes the parts out; the caller becomes responsible for cleaning them up.
    pub fn into_parts(self) -> (Firecracker, PathBuf, Option<PathBuf>, String) {
        let me = std::mem::ManuallyDrop::new(self);
        // SAFETY: `me` is never used or dropped again, so each field is moved out exactly once.
        unsafe { (std::ptr::read(&me.fc), std::ptr::read(&me.dir), std::ptr::read(&me.cgroup), std::ptr::read(&me.tap)) }
    }
}

impl Drop for Idle {
    fn drop(&mut self) {
        self.fc.kill();
        release(&self.tap, self.cgroup.as_deref(), &self.dir);
    }
}

/// Removes a VM's tap, cgroup and directory. Its Firecracker must be gone.
pub fn release(tap: &str, cgroup: Option<&Path>, dir: &Path) {
    crate::net::delete_tap(tap);
    if let Some(cg) = cgroup.filter(|cg| cg.exists()) {
        // The cgroup stays busy until the kernel has finished tearing the process down.
        let _ = retry(Duration::from_secs(2), || Ok(std::fs::remove_dir(cg)?));
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Idle Firecracker processes, spawned ahead of time so starting a VM only
/// pays for the snapshot load. Each one owns a fresh directory under `root`
/// and has already been moved into its own cgroup (that move alone costs tens
/// of milliseconds, as it waits for an RCU grace period).
///
/// A single background worker keeps `size` of them ready, so concurrent
/// takes cannot make the pool overshoot.
pub struct Pool {
    bin: PathBuf,
    root: PathBuf,
    sockets: Arc<SocketRoot>,
    cgroups: Option<PathBuf>,
    tap_prefix: String,
    size: usize,
    state: Mutex<PoolState>,
    wake: Condvar,
    worker: Mutex<Option<JoinHandle<()>>>,
    next: AtomicU64,
}

#[derive(Default)]
struct PoolState {
    idle: Vec<Idle>,
    closed: bool,
}

impl Pool {
    pub fn new(bin: &Path, root: &Path, sockets: Arc<SocketRoot>, cgroups: Option<PathBuf>, tap_prefix: &str, size: usize) -> Arc<Pool> {
        let pool = Arc::new(Pool {
            bin: bin.into(),
            root: root.into(),
            sockets,
            cgroups,
            tap_prefix: tap_prefix.into(),
            size,
            state: Mutex::new(PoolState::default()),
            wake: Condvar::new(),
            worker: Mutex::new(None),
            next: AtomicU64::new(0),
        });
        let p = pool.clone();
        *pool.worker.lock().unwrap() = Some(std::thread::spawn(move || p.refill()));
        pool
    }

    fn spawn(&self, ready: Duration) -> Result<Idle> {
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        let id = format!("idle-{}-{n}", std::process::id());
        let tap = format!("{}{n:x}", self.tap_prefix);
        let dir = self.root.join(&id);
        let cgroup = self.cgroups.as_ref().map(|root| root.join(&id));
        let fc = (|| {
            crate::net::create_tap(&tap)?;
            std::fs::create_dir_all(&dir)?;
            let fc = Firecracker::spawn(&self.bin, &dir, self.sockets.allocate()?, ready)?;
            if let Some(cg) = &cgroup {
                std::fs::create_dir_all(cg)?;
                std::fs::write(cg.join("cgroup.procs"), fc.pid().to_string())?;
            }
            Ok(fc)
        })();
        match fc {
            Ok(fc) => Ok(Idle { fc, dir, cgroup, tap }),
            Err(e) => {
                // A Firecracker that was started has already been killed by its drop.
                release(&tap, cgroup.as_deref(), &dir);
                Err(e)
            }
        }
    }

    /// Hands out an idle Firecracker, or spawns one right away if none is
    /// ready. One that has died meanwhile is torn down, never handed out.
    pub fn take(&self) -> Result<Idle> {
        self.take_by(None)
    }

    /// `take`, done by `deadline` if given (a spawned Firecracker must be up by then).
    pub fn take_by(&self, deadline: Option<std::time::Instant>) -> Result<Idle> {
        let ready = match deadline {
            Some(d) => d.saturating_duration_since(std::time::Instant::now()).min(SPAWN_READY),
            None => SPAWN_READY,
        };
        if ready.is_zero() {
            bail!("out of time for an idle firecracker");
        }
        let mut dead = Vec::new();
        let got = {
            let mut s = self.state.lock().unwrap();
            if s.closed {
                bail!("daemon is shutting down");
            }
            loop {
                match s.idle.pop() {
                    Some(mut f) => match f.fc.alive() {
                        true => break Some(f),
                        false => dead.push(f),
                    },
                    None => break None,
                }
            }
        };
        self.wake.notify_one();
        for mut f in dead {
            eprintln!("pool: dropping a dead idle firecracker: {}", f.fc.post_mortem(&f.dir));
        }
        match got {
            Some(f) => Ok(f),
            None => self.spawn(ready),
        }
    }

    /// The worker: tops the pool up to `size`, one Firecracker at a time.
    fn refill(&self) {
        let mut backoff = Duration::from_millis(100);
        loop {
            {
                let s = self.state.lock().unwrap();
                let s = self.wake.wait_while(s, |s| !s.closed && s.idle.len() >= self.size).unwrap();
                if s.closed {
                    return;
                }
            }
            match self.spawn(SPAWN_READY) {
                Ok(f) => {
                    backoff = Duration::from_millis(100);
                    let mut s = self.state.lock().unwrap();
                    if s.closed {
                        drop(s);
                        drop(f);
                        return;
                    }
                    s.idle.push(f);
                }
                Err(e) => {
                    eprintln!("pool: cannot spawn firecracker: {e}");
                    let s = self.state.lock().unwrap();
                    let _ = self.wake.wait_timeout_while(s, backoff, |s| !s.closed);
                    backoff = (backoff * 2).min(Duration::from_secs(10));
                }
            }
        }
    }

    /// Stops the worker and tears down every idle Firecracker. Later takes fail.
    pub fn close(&self) {
        let idle = {
            let mut s = self.state.lock().unwrap();
            s.closed = true;
            std::mem::take(&mut s.idle)
        };
        self.wake.notify_all();
        if let Some(w) = self.worker.lock().unwrap().take() {
            let _ = w.join();
        }
        drop(idle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counted<R> {
        inner: R,
        read: usize,
    }

    impl<R: Read> Read for Counted<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read += n;
            Ok(n)
        }
    }

    impl<R: Seek> Seek for Counted<R> {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    #[test]
    fn post_mortem_log_reads_only_a_bounded_tail() {
        let path = std::env::temp_dir().join(format!("flexvm-fc-tail-{}", std::process::id()));
        let mut f = File::create(&path).unwrap();
        // Invalid UTF-8 outside the tail must never be read. The tail starts
        // halfway through a long line, which must be discarded.
        f.write_all(&vec![0xff; 2 << 20]).unwrap();
        f.write_all(&vec![b'x'; 64 << 10]).unwrap();
        f.write_all(b"\nfirst\nsecond\nthird\nfourth\nfifth\n").unwrap();
        drop(f);
        let mut r = Counted { inner: File::open(&path).unwrap(), read: 0 };
        assert_eq!(log_tail(&mut r).unwrap(), "first\nsecond\nthird\nfourth\nfifth\n");
        assert_eq!(r.read, (64 << 10) + 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn log_tail_keeps_small_logs_and_discards_partial_lines() {
        use std::io::Cursor;
        for log in ["", "one", "one\ntwo\n"] {
            assert_eq!(log_tail(&mut Cursor::new(log.as_bytes())).unwrap(), log);
        }
        assert_eq!(log_tail(&mut Cursor::new(vec![b'x'; 128 << 10])).unwrap(), "");
        // Seeking can land inside a UTF-8 character in the discarded line.
        let mut log = "é".repeat(64 << 10).into_bytes();
        log.extend_from_slice(b"\nlast");
        assert_eq!(log_tail(&mut Cursor::new(log)).unwrap(), "last");
        // A tail that starts exactly on a line keeps that line.
        let mut log = vec![b'x'; 100];
        log.push(b'\n');
        log.extend(std::iter::repeat_n(b'y', (64 << 10) - 4));
        log.extend_from_slice(b"\nend");
        assert_eq!(log_tail(&mut Cursor::new(&log)).unwrap().len(), 64 << 10);
        assert!(log_tail(&mut Cursor::new(&log)).unwrap().starts_with('y'));
        // Short logs without a trailing newline and with binary junk.
        let log = b"ok\n\xff\xfe junk\nlast line";
        assert_eq!(log_tail(&mut Cursor::new(&log[..])).unwrap(), "ok\n\u{fffd}\u{fffd} junk\nlast line");
    }
}
