//! A Firecracker process and a minimal client for its HTTP-over-UDS API.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::Value;

use crate::bail;
use crate::util::{retry, Result};

/// Deadline for a Firecracker API call that does not pick its own.
pub const API_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Firecracker {
    child: Child,
    sock: PathBuf,
}

impl Firecracker {
    /// Starts Firecracker with its API socket and log inside `dir`.
    pub fn spawn(bin: &Path, dir: &Path) -> Result<Self> {
        let sock = dir.join("api.sock");
        let _ = std::fs::remove_file(&sock);
        let log = File::create(dir.join("firecracker.log"))?;
        let child = Command::new(bin)
            .arg("--api-sock")
            .arg(&sock)
            .arg("--level")
            .arg("Warn")
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?;
        let fc = Firecracker { child, sock };
        retry(Duration::from_secs(5), || Ok(UnixStream::connect(&fc.sock)?))?;
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

    /// `request`, but connecting, writing and reading each time out after `timeout`.
    pub fn request_within(&self, method: &str, path: &str, body: Option<Value>, timeout: Duration) -> Result<Value> {
        if timeout.is_zero() {
            bail!("firecracker {method} {path}: out of time");
        }
        self.send(crate::util::connect_unix(&self.sock, timeout)?, method, path, body)
    }

    fn send(&self, mut stream: UnixStream, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
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
        if !(200..300).contains(&code) {
            bail!("firecracker {method} {path}: {code} {text}");
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text.into_owned())))
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.sock);
    }
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
    pub fn new(bin: &Path, root: &Path, cgroups: Option<PathBuf>, tap_prefix: &str, size: usize) -> Arc<Pool> {
        let pool = Arc::new(Pool {
            bin: bin.into(),
            root: root.into(),
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

    fn spawn(&self) -> Result<Idle> {
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        let id = format!("idle-{}-{n}", std::process::id());
        let tap = format!("{}{n:x}", self.tap_prefix);
        let dir = self.root.join(&id);
        let cgroup = self.cgroups.as_ref().map(|root| root.join(&id));
        let fc = (|| {
            crate::net::create_tap(&tap)?;
            std::fs::create_dir_all(&dir)?;
            let fc = Firecracker::spawn(&self.bin, &dir)?;
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

    /// Hands out an idle Firecracker, or spawns one right away if none is ready.
    pub fn take(&self) -> Result<Idle> {
        let got = {
            let mut s = self.state.lock().unwrap();
            if s.closed {
                bail!("daemon is shutting down");
            }
            s.idle.pop()
        };
        self.wake.notify_one();
        match got {
            Some(f) => Ok(f),
            None => self.spawn(),
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
            match self.spawn() {
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
