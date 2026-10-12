//! A Firecracker process and a minimal client for its HTTP-over-UDS API.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use crate::bail;
use crate::util::{retry, Result};

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

    fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        self.send(UnixStream::connect(&self.sock)?, method, path, body)
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
pub struct Idle {
    pub fc: Firecracker,
    pub dir: PathBuf,
    pub cgroup: Option<PathBuf>,
    pub tap: String,
}

/// Idle Firecracker processes, spawned ahead of time so starting a VM only
/// pays for the snapshot load. Each one owns a fresh directory under `root`
/// and has already been moved into its own cgroup (that move alone costs tens
/// of milliseconds, as it waits for an RCU grace period).
pub struct Pool {
    bin: PathBuf,
    root: PathBuf,
    cgroups: Option<PathBuf>,
    tap_prefix: String,
    size: usize,
    idle: Mutex<Vec<Idle>>,
    next: AtomicU64,
}

impl Pool {
    pub fn new(bin: &Path, root: &Path, cgroups: Option<PathBuf>, tap_prefix: &str, size: usize) -> Arc<Pool> {
        let pool = Arc::new(Pool {
            bin: bin.into(),
            root: root.into(),
            cgroups,
            tap_prefix: tap_prefix.into(),
            size,
            idle: Mutex::new(Vec::new()),
            next: AtomicU64::new(0),
        });
        pool.refill();
        pool
    }

    fn spawn(&self) -> Result<Idle> {
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        let id = format!("idle-{}-{n}", std::process::id());
        let tap = format!("{}{n:x}", self.tap_prefix);
        crate::net::create_tap(&tap)?;
        let dir = self.root.join(&id);
        std::fs::create_dir_all(&dir)?;
        let fc = Firecracker::spawn(&self.bin, &dir)?;
        let cgroup = match &self.cgroups {
            Some(root) => {
                let cg = root.join(&id);
                std::fs::create_dir_all(&cg)?;
                std::fs::write(cg.join("cgroup.procs"), fc.pid().to_string())?;
                Some(cg)
            }
            None => None,
        };
        Ok(Idle { fc, dir, cgroup, tap })
    }

    /// Hands out an idle Firecracker, then tops the pool back up.
    pub fn take(self: &Arc<Self>) -> Result<Idle> {
        let got = self.idle.lock().unwrap().pop();
        let got = match got {
            Some(f) => f,
            None => self.spawn()?,
        };
        self.refill();
        Ok(got)
    }

    fn refill(self: &Arc<Self>) {
        let pool = self.clone();
        std::thread::spawn(move || {
            while pool.idle.lock().unwrap().len() < pool.size {
                match pool.spawn() {
                    Ok(f) => pool.idle.lock().unwrap().push(f),
                    Err(e) => {
                        eprintln!("pool: cannot spawn firecracker: {e}");
                        return;
                    }
                }
            }
        });
    }
}
