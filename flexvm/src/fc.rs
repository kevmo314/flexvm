//! A Firecracker process and a minimal client for its HTTP-over-UDS API.

use std::cell::RefCell;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::bail;
use crate::socket::{SocketRoot, Sockets};
use crate::util::{retry, Result};

pub const SPAWN_READY: Duration = Duration::from_secs(5);
pub const API_TIMEOUT: Duration = Duration::from_secs(30);

/// Never reached Firecracker; any other failure (error answers too) may come after it acted.
#[derive(Debug)]
pub struct NotSent(String);

impl std::fmt::Display for NotSent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NotSent {}

pub fn not_sent(e: &crate::util::Error) -> bool {
    e.downcast_ref::<NotSent>().is_some()
}

pub struct Firecracker {
    child: Child,
    pub sockets: Sockets,
    api: Api,
    /// The cgroup move: joined before the kill, so its pid is never reused meanwhile.
    joining: Option<std::thread::JoinHandle<()>>,
}

impl Firecracker {
    pub fn spawn(bin: &Path, dir: &Path, sockets: Sockets, ready: Duration) -> Result<Self> {
        crate::socket::check(&sockets.api)?;
        use std::os::unix::process::CommandExt;
        let log = File::create(dir.join("firecracker.log"))?;
        let mut cmd = Command::new(bin);
        cmd.arg("--api-sock").arg(&sockets.api).arg("--level").arg("Warn").stdin(Stdio::null()).stdout(log.try_clone()?).stderr(log);
        // Firecracker never outlives its VM process (whose pager serves its memory). The
        // signal comes when the spawning *thread* exits, so spawn from the main thread.
        let parent = std::process::id() as i32;
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::other("its parent died"));
                }
                // Out of the terminal's process group: Ctrl-Z, Ctrl-C and a hang-up
                // are for the VM process, which decides what becomes of Firecracker.
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let fc = Firecracker { child, sockets, api: Api::default(), joining: None };
        let id = crate::host::Ident::of(fc.pid()).ok_or("firecracker exited at once")?;
        crate::host::store(&dir.join("fc"), &id, false)?;
        retry(ready, || Ok(UnixStream::connect(&fc.sockets.api)?))?;
        Ok(fc)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn put(&self, path: &str, body: Value) -> Result<Value> {
        self.request_within("PUT", path, Some(body), API_TIMEOUT)
    }

    pub fn patch(&self, path: &str, body: Value) -> Result<Value> {
        self.request_within("PATCH", path, Some(body), API_TIMEOUT)
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        self.request_within("GET", path, None, API_TIMEOUT)
    }

    /// With no `clock_realtime`, only prepares the load (`firecracker/0002-*.patch`).
    pub fn load_snapshot(&self, vmstate: &Path, tap: &str, clock_realtime: Option<bool>, timeout: Duration) -> Result<Value> {
        let mut body = serde_json::json!({
            "snapshot_path": vmstate,
            "mem_backend": {"backend_type": "Uffd", "backend_path": self.sockets.uffd},
            "vsock_override": {"uds_path": self.sockets.vsock},
            "network_overrides": [{"iface_id": "eth0", "host_dev_name": tap}],
        });
        let Some(realtime) = clock_realtime else { return self.request_within("PUT", "/snapshot/prepare", Some(body), timeout) };
        body["clock_realtime"] = realtime.into();
        body["resume_vm"] = false.into();
        self.request_within("PUT", "/snapshot/load", Some(body), timeout)
    }

    pub fn pause(&self) -> Result<()> {
        self.patch("/vm", serde_json::json!({"state": "Paused"})).map(|_| ())
    }

    pub fn resume(&self) -> Result<()> {
        self.patch("/vm", serde_json::json!({"state": "Resumed"})).map(|_| ())
    }

    /// Every call has a deadline, so none can hold a VM's API lock forever.
    pub fn request_within(&self, method: &str, path: &str, body: Option<Value>, timeout: Duration) -> Result<Value> {
        self.api.request(&self.sockets.api, method, path, body, timeout)
    }

    pub fn alive(&mut self) -> bool {
        matches!(exited(&self.child), Ok(None))
    }

    pub fn post_mortem(&mut self, dir: &Path) -> String {
        let status = match exited(&self.child) {
            Ok(Some(st)) => format!("exited ({st})"),
            Ok(None) => "still running".into(),
            Err(e) => format!("unknown ({e})"),
        };
        let log = File::open(dir.join("firecracker.log")).and_then(|mut f| log_tail(&mut f)).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        format!("firecracker {} {status}; log: {}", self.pid(), lines[lines.len().saturating_sub(5)..].join(" | "))
    }

    /// Reaps it: callers stop its pager first, which reads its memory by pid.
    pub fn kill(&mut self) {
        if let Some(j) = self.joining.take() {
            let _ = j.join();
        }
        self.api.connection.get_mut().take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.sockets.cleanup();
    }
}

/// `child`'s exit status once it exited, leaving it unreaped: only `kill` reaps Firecracker,
/// after the cgroup move, so nothing acting on its pid meanwhile can meet a reused one.
fn exited(child: &Child) -> std::io::Result<Option<ExitStatus>> {
    use std::os::unix::process::ExitStatusExt;
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::waitid(libc::P_PID, child.id(), &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (pid, st) = unsafe { (info.si_pid(), info.si_status()) };
    Ok((pid != 0).then(|| match info.si_code {
        libc::CLD_EXITED => ExitStatus::from_raw((st & 0xff) << 8),
        libc::CLD_DUMPED => ExitStatus::from_raw(st | 0x80),
        _ => ExitStatus::from_raw(st),
    }))
}

/// Calls on a VM hold its `fc` mutex; idle Firecrackers have one owner.
#[derive(Default)]
struct Api {
    connection: RefCell<Option<BufReader<crate::util::By<UnixStream>>>>,
}

impl Api {
    fn request(&self, socket: &Path, method: &str, path: &str, body: Option<Value>, timeout: Duration) -> Result<Value> {
        let at = std::time::Instant::now() + timeout;
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        // A cached connection Firecracker closed fails before a byte goes out: one fresh retry.
        loop {
            // Anything readable on an idle connection (stray bytes, or the close
            // of a Firecracker that died) means it is never used again (#109).
            let cached = self.connection.borrow_mut().take().filter(|r| !readable(&r.get_ref().s));
            let reused = cached.is_some();
            let mut r = match cached {
                Some(mut r) => {
                    r.get_mut().at = at;
                    r
                }
                None => {
                    let left = at.saturating_duration_since(std::time::Instant::now());
                    let s = if left.is_zero() {
                        Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "deadline passed"))
                    } else {
                        crate::util::connect_unix(socket, left)
                    };
                    match s {
                        Ok(s) => BufReader::new(crate::util::By { s, at }),
                        Err(e) => return Err(Box::new(NotSent(format!("firecracker {method} {path}: cannot connect: {e}")))),
                    }
                }
            };
            let mut sent = false;
            let (code, buf, close) = match exchange(&mut r, req.as_bytes(), &mut sent) {
                Ok(response) => response,
                Err(_) if !sent && reused => continue,
                Err(e) if !sent => return Err(Box::new(NotSent(format!("firecracker {method} {path}: {e}")))),
                Err(e) => return Err(e),
            };
            // Bytes past the answer mean the stream is out of step.
            if !close && r.buffer().is_empty() {
                *self.connection.borrow_mut() = Some(r);
            }
            let text = String::from_utf8_lossy(&buf);
            if !(200..300).contains(&code) {
                bail!("firecracker {method} {path}: {code} {text}");
            }
            return if text.trim().is_empty() {
                Ok(Value::Null)
            } else {
                Ok(serde_json::from_str(&text).unwrap_or(Value::String(text.into_owned())))
            };
        }
    }
}

fn exchange(r: &mut BufReader<crate::util::By<UnixStream>>, mut req: &[u8], sent: &mut bool) -> Result<(u16, Vec<u8>, bool)> {
    // After a partial write the request may have reached Firecracker: never replay it.
    while !req.is_empty() {
        match r.get_mut().write(req) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "firecracker request write returned zero").into()),
            Ok(n) => {
                *sent = true;
                req = &req[n..];
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let mut status = String::new();
    if r.read_line(&mut status)? == 0 {
        bail!("firecracker closed the connection without answering");
    }
    let code: u16 = status.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    if code == 0 || !status.ends_with("\r\n") {
        bail!("firecracker: invalid response status");
    }
    let mut len = None;
    let mut close = false;
    loop {
        let mut h = String::new();
        r.read_line(&mut h)?;
        if !h.ends_with("\r\n") {
            bail!("firecracker: incomplete response headers");
        }
        if h == "\r\n" {
            break;
        }
        let Some((k, v)) = h.trim_end().split_once(':') else {
            bail!("firecracker: invalid response header");
        };
        if k.eq_ignore_ascii_case("content-length") {
            let n: usize = v.trim().parse()?;
            if len.is_some_and(|previous| previous != n) {
                bail!("firecracker: conflicting content lengths");
            }
            len = Some(n);
        } else if k.eq_ignore_ascii_case("connection") {
            close |= v.split(',').any(|v| v.trim().eq_ignore_ascii_case("close"));
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            bail!("firecracker: unsupported transfer encoding");
        }
    }
    // micro_http omits Content-Length for 204; reading to EOF would lose keep-alive.
    let len = if code == 204 || code == 304 {
        if code == 204 && len.is_some_and(|n| n != 0) {
            bail!("firecracker: nonzero content length for 204");
        }
        0
    } else {
        len.ok_or("firecracker: missing content length")?
    };
    let mut buf = vec![0; len];
    r.read_exact(&mut buf)?;
    Ok((code, buf, close))
}

fn readable(s: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut p = libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut p, 1, 0) != 0 }
}

/// At most the last 64 KiB, without the first partial line.
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

/// Dropping it kills the Firecracker and removes its directory, cgroup and tap.
pub struct Idle {
    pub fc: Firecracker,
    pub dir: PathBuf,
    pub cgroup: Option<PathBuf>,
    pub tap: String,
}

impl Idle {
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

/// Its Firecracker must be gone.
pub fn release(tap: &str, cgroup: Option<&Path>, dir: &Path) {
    crate::net::delete_tap(tap);
    if let Some(cg) = cgroup.filter(|cg| cg.exists()) {
        // Busy until the kernel has torn the process down.
        let _ = retry(Duration::from_secs(2), || Ok(std::fs::remove_dir(cg)?));
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Starts Firecrackers, each with its own directory, tap and cgroup; the cgroup is joined in
/// the background (an RCU grace period). Spawn from a thread that lives as long as the VM.
pub struct Spawner {
    bin: PathBuf,
    root: PathBuf,
    sockets: Arc<SocketRoot>,
    cgroups: Option<PathBuf>,
    tap_prefix: String,
    next: AtomicU64,
}

impl Spawner {
    pub fn new(bin: &Path, root: &Path, sockets: Arc<SocketRoot>, cgroups: Option<PathBuf>, tap_prefix: &str) -> Spawner {
        Spawner { bin: bin.into(), root: root.into(), sockets, cgroups, tap_prefix: tap_prefix.into(), next: AtomicU64::new(0) }
    }

    pub fn take(&self, deadline: Option<std::time::Instant>) -> Result<Idle> {
        let ready = deadline.map_or(SPAWN_READY, |d| d.saturating_duration_since(std::time::Instant::now()).min(SPAWN_READY));
        if ready.is_zero() {
            bail!("out of time to start firecracker");
        }
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        let id = format!("idle-{}-{n}", std::process::id());
        let tap = format!("{}{n:x}", self.tap_prefix);
        let dir = self.root.join(&id);
        let cgroup = self.cgroups.as_ref().map(|root| root.join(&id));
        let made = {
            let t = tap.clone();
            std::thread::spawn(move || crate::net::create_tap(&t))
        };
        let fc = std::fs::create_dir_all(&dir).map_err(Into::into).and_then(|()| Firecracker::spawn(&self.bin, &dir, self.sockets.allocate()?, ready));
        let made = made.join().unwrap_or_else(|_| Err("tap thread panicked".into()));
        // A Firecracker without its tap is dropped (killed) here, before `release`.
        let mut fc = match fc.and_then(|fc| made.map(|()| fc)) {
            Ok(fc) => fc,
            Err(e) => {
                release(&tap, cgroup.as_deref(), &dir);
                return Err(e);
            }
        };
        // Under test, each VM's Firecracker keeps its device metrics (`metrics.json` in its
        // directory, appended every 60 s and on `FlushMetrics`), so a test can see what a
        // device did (#149). Metrics can only be configured before a load.
        if std::env::var("FLEXVM_FAULTS").is_ok_and(|v| v == "1") {
            let path = dir.join("metrics.json");
            if let Err(e) = File::create(&path).map_err(Into::into).and_then(|_| fc.put("/metrics", serde_json::json!({"metrics_path": path}))) {
                eprintln!("firecracker {}: no metrics: {e}", fc.pid());
            }
        }
        if let Some(cg) = cgroup.clone() {
            let pid = fc.pid();
            fc.joining = Some(std::thread::spawn(move || {
                // Never swapped: at its mark the VM is throttled (sleeps a migration's or
                // checkpoint's lift waits out), not paged out to swap, whose reads would hold
                // up its pauses. Without swap accounting the file is missing: nothing to do.
                let joined = std::fs::create_dir(&cg).and_then(|()| {
                    if let Err(e) = std::fs::write(cg.join("memory.swap.max"), "0").or_else(|e| match e.kind() {
                        std::io::ErrorKind::NotFound => Ok(()),
                        _ => Err(e),
                    }) {
                        eprintln!("firecracker {pid}: its memory may be swapped ({}): {e}", cg.display());
                    }
                    std::fs::write(cg.join("cgroup.procs"), pid.to_string())
                });
                if let Err(e) = joined {
                    eprintln!("firecracker {pid}: no cgroup of its own ({}): {e}", cg.display());
                }
            }));
        }
        Ok(Idle { fc, dir, cgroup, tap })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::net::UnixListener;
    use std::thread::JoinHandle;

    struct Server {
        path: PathBuf,
        thread: Option<JoinHandle<()>>,
    }

    impl Server {
        fn new(f: impl FnOnce(UnixListener) + Send + 'static) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!("flexvm-api-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            Self { path, thread: Some(std::thread::spawn(move || f(listener))) }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.thread.take().unwrap().join().unwrap();
            std::fs::remove_file(&self.path).unwrap();
        }
    }

    fn accept(listener: &UnixListener) -> BufReader<UnixStream> {
        let s = retry(Duration::from_secs(2), || Ok(listener.accept()?.0)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        BufReader::new(s)
    }

    fn read_request(r: &mut BufReader<UnixStream>) {
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert!(line.ends_with("HTTP/1.1\r\n"));
        let mut len = 0;
        loop {
            line.clear();
            r.read_line(&mut line).unwrap();
            assert!(line.ends_with("\r\n"));
            if line == "\r\n" {
                break;
            }
            if let Some(v) = line.strip_prefix("Content-Length:") {
                len = v.trim().parse().unwrap();
            }
        }
        r.read_exact(&mut vec![0; len]).unwrap();
    }

    fn answer(r: &mut BufReader<UnixStream>, response: &[u8]) {
        read_request(r);
        r.get_mut().write_all(response).unwrap();
    }

    fn no_more(listener: &UnixListener) {
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }

    const NO_CONTENT: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";

    fn call(api: &Api, socket: &Path) -> Result<Value> {
        api.request(socket, "PATCH", "/vm", Some(serde_json::json!({"state": "Resumed"})), Duration::from_secs(1))
    }

    #[test]
    fn api_reuses_connection_and_reads_exact_bodies() {
        let server = Server::new(|listener| {
            let mut r = accept(&listener);
            // A non-success answer also has to be fully consumed and cached.
            answer(&mut r, b"HTTP/1.1 400 Bad Request\r\ncontent-length: 7\r\n\r\n{\"n\":1}");
            answer(&mut r, b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"n\":2}");
            no_more(&listener);
        });
        let api = Api::default();
        assert!(call(&api, &server.path).unwrap_err().to_string().contains("400"));
        assert_eq!(call(&api, &server.path).unwrap(), serde_json::json!({"n": 2}));
    }

    #[test]
    fn api_reconnects_after_unsent_write_on_closed_connection() {
        let (closed, wait) = std::sync::mpsc::channel();
        let server = Server::new(move |listener| {
            answer(&mut accept(&listener), NO_CONTENT);
            closed.send(()).unwrap();
            answer(&mut accept(&listener), NO_CONTENT);
        });
        let api = Api::default();
        assert_eq!(call(&api, &server.path).unwrap(), Value::Null);
        wait.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(call(&api, &server.path).unwrap(), Value::Null);
    }

    #[test]
    fn api_drops_a_connection_it_cannot_reuse() {
        for (first, second, want) in [
            // The header alone must force a new connection (the old one stays open).
            (&b"HTTP/1.1 200 OK\r\ncOnNeCtIoN: keep-alive, Close\r\nContent-Length: 4\r\n\r\nnull"[..], NO_CONTENT, Value::Null),
            (&b"HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"[..], &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n2"[..], serde_json::json!(2)),
        ] {
            let server = Server::new(move |listener| {
                let mut r = accept(&listener);
                answer(&mut r, first);
                answer(&mut accept(&listener), second);
            });
            let api = Api::default();
            call(&api, &server.path).unwrap();
            assert!(api.connection.borrow().is_none());
            assert_eq!(call(&api, &server.path).unwrap(), want);
        }
    }

    #[test]
    fn api_never_reads_bytes_that_arrive_on_an_idle_connection() {
        let (stray, wait) = std::sync::mpsc::channel();
        let server = Server::new(move |listener| {
            let mut r = accept(&listener);
            answer(&mut r, NO_CONTENT);
            r.get_mut().write_all(b"HTTP/1.1 500 Late\r\n\r\n").unwrap();
            stray.send(()).unwrap();
            answer(&mut accept(&listener), b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n3");
        });
        let api = Api::default();
        call(&api, &server.path).unwrap();
        wait.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(call(&api, &server.path).unwrap(), serde_json::json!(3));
    }

    #[test]
    fn api_does_not_replay_a_request_with_a_lost_response() {
        let server = Server::new(|listener| {
            read_request(&mut accept(&listener));
            // This is the caller's next request, not a replay of the failed one.
            answer(&mut accept(&listener), NO_CONTENT);
        });
        let api = Api::default();
        assert!(!not_sent(&call(&api, &server.path).unwrap_err()));
        assert!(api.connection.borrow().is_none());
        call(&api, &server.path).unwrap();
    }

    #[test]
    fn api_stalled_response_keeps_one_deadline_and_drops_connection() {
        for response in [
            &b""[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length:"[..],
        ] {
            let server = Server::new(move |listener| {
                let mut r = accept(&listener);
                read_request(&mut r);
                std::thread::sleep(Duration::from_millis(30));
                r.get_mut().write_all(response).unwrap();
                std::thread::sleep(Duration::from_millis(150));
                no_more(&listener);
            });
            let api = Api::default();
            let start = std::time::Instant::now();
            let e = api.request(&server.path, "GET", "/vm", None, Duration::from_millis(60)).unwrap_err();
            assert!(!not_sent(&e));
            assert!(start.elapsed() < Duration::from_millis(150));
            assert!(api.connection.borrow().is_none());
        }
    }

    #[test]
    fn api_rejects_bad_framing_and_truncated_bodies() {
        for response in [
            &b"HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\nxx"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: wrong\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        ] {
            let server = Server::new(move |listener| answer(&mut accept(&listener), response));
            let api = Api::default();
            assert!(!not_sent(&call(&api, &server.path).unwrap_err()));
            assert!(api.connection.borrow().is_none());
        }
    }

    #[test]
    fn api_does_not_retry_a_fresh_connection() {
        let server = Server::new(|listener| {
            // Closed before reading: a fresh connection is never tried twice.
            drop(accept(&listener));
            std::thread::sleep(Duration::from_millis(100));
            no_more(&listener);
        });
        assert!(call(&Api::default(), &server.path).is_err());
    }

    #[test]
    fn api_connect_failure_and_expired_deadline_are_not_sent() {
        let api = Api::default();
        let missing = Path::new("/no-flexvm-api/socket");
        assert!(not_sent(&call(&api, missing).unwrap_err()));
        assert!(not_sent(&api.request(missing, "GET", "/vm", None, Duration::ZERO).unwrap_err()));
    }

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

    /// Liveness checks never reap, so the pid stays Firecracker's until `kill` waits for it.
    #[test]
    fn exit_status_leaves_the_child_unreaped() {
        for (script, want) in [("exit 3", "exit status: 3"), ("kill -9 $$", "signal: 9")] {
            let mut child = Command::new("sh").args(["-c", script]).spawn().unwrap();
            let st = retry(Duration::from_secs(5), || Ok(exited(&child)?.ok_or("running")?)).unwrap();
            assert!(st.to_string().contains(want), "{st}");
            assert!(exited(&child).unwrap().is_some(), "still there to ask again");
            assert!(Path::new(&format!("/proc/{}", child.id())).exists(), "a zombie, its pid not free");
            assert_eq!(child.wait().unwrap(), st);
        }
    }

    #[test]
    fn post_mortem_log_reads_only_a_bounded_tail() {
        let path = std::env::temp_dir().join(format!("flexvm-fc-tail-{}", std::process::id()));
        let mut f = File::create(&path).unwrap();
        // Invalid UTF-8 outside the tail must never be read; the partial line is discarded.
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
        let mut log = "é".repeat(64 << 10).into_bytes();
        log.extend_from_slice(b"\nlast");
        assert_eq!(log_tail(&mut Cursor::new(log)).unwrap(), "last");
        let mut log = vec![b'x'; 100];
        log.push(b'\n');
        log.extend(std::iter::repeat_n(b'y', (64 << 10) - 4));
        log.extend_from_slice(b"\nend");
        assert_eq!(log_tail(&mut Cursor::new(&log)).unwrap().len(), 64 << 10);
        assert!(log_tail(&mut Cursor::new(&log)).unwrap().starts_with('y'));
        let log = b"ok\n\xff\xfe junk\nlast line";
        assert_eq!(log_tail(&mut Cursor::new(&log[..])).unwrap(), "ok\n\u{fffd}\u{fffd} junk\nlast line");
    }
}
