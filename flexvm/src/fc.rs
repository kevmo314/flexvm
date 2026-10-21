//! A Firecracker process and a minimal client for its HTTP-over-UDS API.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use crate::bail;
use crate::socket::{SocketRoot, Sockets};
use crate::util::{retry, Result};

pub const SPAWN_READY: Duration = Duration::from_secs(5);
pub const API_TIMEOUT: Duration = Duration::from_secs(30);

/// A full snapshot writes all of guest memory: more time for large guests on a busy disk.
pub fn memory_timeout(mem_mib: u64) -> Duration {
    API_TIMEOUT + Duration::from_secs(mem_mib.div_ceil(1024))
}

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
    pub dir: PathBuf,
    cgroup: RefCell<Option<PathBuf>>,
    /// Empty for image builders, which own their directory and network.
    pub tap: String,
    api: Api,
    /// The cgroup move: joined before a load or reap.
    joining: RefCell<Option<std::thread::JoinHandle<std::io::Result<()>>>>,
    /// Under a `--cpus` cap (`Spawner::cap_cpus`): one it cannot be held to is an error.
    capped: bool,
    /// Its cgroup move failed (`join_cgroup`): not one the host lacks, so no `--cpus` cap can be set on it.
    lost_cgroup: Cell<bool>,
    /// Drained after exit, before reading diagnostics or removing the directory.
    logging: RefCell<Option<std::thread::JoinHandle<()>>>,
}

/// Why no VM starts where `/proc` is not this PID namespace's (`host::proc_is_mine`).
pub const FOREIGN_PROC: &str = "no vm can start here: /proc is not this PID namespace's (`unshare --pid` without `--mount-proc`, say); mount one of its own";

impl Firecracker {
    pub fn spawn(bin: &Path, dir: &Path, sockets: Sockets, ready: Duration) -> Result<Self> {
        // Its pid (`Child::id`) is this namespace's, which another's /proc names another process by:
        // its identity, executable, fds, maps, tasks and network namespace read there would be
        // another's, so no VM starts at all (#1146).
        if !crate::host::proc_is_mine() {
            return Err(FOREIGN_PROC.into());
        }
        crate::socket::check(&sockets.api)?;
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new(bin);
        cmd.arg("--api-sock").arg(&sockets.api).arg("--level").arg("Warn").stdin(Stdio::null());
        // Its output is a pipe now: its working directory is how tools find its directory.
        cmd.current_dir(dir);
        // Firecracker never outlives its VM process (whose pager serves its memory). The
        // signal comes when the spawning *thread* exits, so spawn from the main thread.
        let parent = std::process::id() as i32;
        unsafe {
            cmd.pre_exec(move || {
                crate::util::check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL))?;
                if libc::getppid() != parent {
                    return Err(std::io::Error::other("its parent died"));
                }
                // Out of the terminal's process group: Ctrl-Z, Ctrl-C and a hang-up
                // are for the VM process, which decides what becomes of Firecracker.
                crate::util::check(libc::setpgid(0, 0))?;
                Ok(())
            });
        }
        let (child, logging) = spawn_logged(cmd, dir).map_err(|e| format!("{}: {e} (see README: Setup)", bin.display()))?;
        let fc = Firecracker {
            child,
            sockets,
            dir: dir.into(),
            cgroup: RefCell::new(None),
            tap: String::new(),
            api: Api { bin: bin.into(), ..Api::default() },
            joining: RefCell::new(None),
            capped: false,
            lost_cgroup: Cell::new(false),
            logging: RefCell::new(Some(logging)),
        };
        let id = crate::host::Ident::of(fc.pid()).ok_or_else(|| fc.post_mortem())?;
        crate::host::store(&dir.join("fc"), &id, false)?;
        let connection = retry(ready, Duration::from_micros(200), || -> Result<Result<UnixStream>> {
            if !fc.alive() {
                return Ok(Err(fc.post_mortem().into()));
            }
            Ok(Ok(UnixStream::connect(&fc.sockets.api)?))
        })??;
        *fc.api.connection.borrow_mut() = Some(BufReader::new(crate::util::By { s: connection, at: std::time::Instant::now() }));
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
    /// `template` is the vmstate of the template the VM was made from: Firecracker refuses a
    /// `vmstate` with devices other than it has, and takes no host resource (tap, socket, file)
    /// from `vmstate` (#548).
    /// What a template's snapshot names its root filesystem (`template::ROOTFS`), in this Firecracker's directory.
    pub fn link_rootfs(&self, rootfs: &Path) -> Result<()> {
        let link = self.dir.join(crate::template::ROOTFS);
        // Linked already by the prepare: a migration's load, while paused, only checks.
        if std::fs::read_link(&link).is_ok_and(|l| l == rootfs) {
            return Ok(());
        }
        match std::fs::remove_file(&link) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            r => r?,
        }
        Ok(std::os::unix::fs::symlink(rootfs, link)?)
    }

    pub fn load_snapshot(
        &self,
        vmstate: &Path,
        template: &crate::template::Template,
        tap: &str,
        clock_realtime: Option<bool>,
        timeout: Duration,
    ) -> Result<Value> {
        self.join_cgroup()?;
        self.link_rootfs(&template.meta.rootfs)?;
        let mut body = snapshot_load_body(vmstate, template, tap, &self.sockets.vsock, &self.sockets.uffd)?;
        let Some(realtime) = clock_realtime else { return self.request_within("PUT", "/snapshot/prepare", Some(body), timeout) };
        body["clock_realtime"] = realtime.into();
        body["resume_vm"] = false.into();
        self.request_within("PUT", "/snapshot/load", Some(body), timeout)
    }

    pub fn pause(&self, timeout: Duration) -> Result<()> {
        self.request_within("PATCH", "/vm", Some(serde_json::json!({"state": "Paused"})), timeout).map(|_| ())
    }

    pub fn resume(&self, timeout: Duration) -> Result<()> {
        self.request_within("PATCH", "/vm", Some(serde_json::json!({"state": "Resumed"})), timeout).map(|_| ())
    }

    /// Every call has a deadline, so none can hold a VM's API lock forever.
    pub fn request_within(&self, method: &str, path: &str, body: Option<Value>, timeout: Duration) -> Result<Value> {
        self.api.request(&self.sockets.api, method, path, body, timeout)
    }

    pub fn alive(&self) -> bool {
        matches!(exited(&self.child), Ok(None))
    }

    pub fn post_mortem(&self) -> String {
        let status = match exited(&self.child) {
            Ok(Some(st)) => {
                self.join_log();
                format!("exited ({st})")
            }
            Ok(None) => "still running".into(),
            Err(e) => format!("unknown ({e})"),
        };
        format!("firecracker {} {status}; log: {}", self.pid(), post_mortem_lines(&firecracker_log_tail(&self.dir)))
    }

    /// The end of its log (up to 64 KiB, the guest's console with it), once it exited: a guest crash's cause comes
    /// well before the few lines `post_mortem` keeps.
    pub fn log_tail(&self) -> String {
        if matches!(exited(&self.child), Ok(Some(_))) {
            self.join_log();
        }
        firecracker_log_tail(&self.dir)
    }

    /// An error only under a `--cpus` cap: outside its cgroup, the VM would run uncapped.
    pub fn join_cgroup(&self) -> Result<()> {
        let joined = match self.joining.borrow_mut().take() {
            Some(j) => j.join().unwrap_or_else(|_| Err(std::io::Error::other("cgroup thread panicked"))),
            None => Ok(()),
        };
        if joined.is_err() {
            if let Some(cg) = self.cgroup.borrow_mut().take() {
                self.lost_cgroup.set(true);
                let _ = std::fs::remove_dir(cg);
            }
        }
        match joined {
            Err(e) if self.capped => bail!("--cpus not applied: firecracker {} has no cgroup of its own: {e}", self.pid()),
            _ => Ok(()),
        }
    }

    /// A builder owns its tap and directory, but needs the same per-VM memory cgroup.
    pub fn isolate(&mut self) -> Result<()> {
        if let Some(root) = crate::vmproc::cgroup_root() {
            let cg = root.join(crate::host::idle_cgroup(self.pid()));
            self.attach_cgroup(cg, false);
            self.join_cgroup()?;
        }
        Ok(())
    }

    fn attach_cgroup(&mut self, cg: PathBuf, made: bool) {
        let pid = self.pid();
        *self.cgroup.get_mut() = Some(cg.clone());
        *self.joining.get_mut() = Some(std::thread::spawn(move || {
            // Test fault `cgroup_join_fail`: its cgroup move fails.
            let made = match (crate::host::fault("cgroup_join_fail"), made) {
                (true, _) => Err(std::io::Error::other("injected fault: joining its cgroup failed")),
                (false, true) => Ok(()),
                (false, false) => std::fs::create_dir(&cg),
            };
            // Like ordinary starts: throttle at memory.high, without swapping.
            let joined = made.and_then(|()| {
                if let Err(e) = std::fs::write(cg.join("memory.swap.max"), "0") {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        crate::log!("firecracker {pid}: its memory may be swapped ({}): {e}", cg.display());
                    }
                }
                std::fs::write(cg.join("cgroup.procs"), pid.to_string())
            });
            if let Err(e) = &joined {
                crate::log!("firecracker {pid}: no cgroup of its own ({}): {e}", cg.display());
            }
            joined
        }));
    }

    /// Whether it was to have a cgroup of its own but failed to join it (and so never will).
    pub fn lost_cgroup(&self) -> bool {
        let _ = self.join_cgroup();
        self.lost_cgroup.get()
    }

    pub fn cgroup(&self) -> Option<PathBuf> {
        let _ = self.join_cgroup();
        self.cgroup.borrow().clone()
    }

    /// `cpu.max` on its cgroup (`vm::Resources::cpu_max`), for a claimed standby's.
    pub fn set_cpu_max(&self, max: &str) -> Result<()> {
        self.join_cgroup()?;
        let cgroup = self.cgroup.borrow();
        let cg = cgroup.as_ref().ok_or_else(|| match self.lost_cgroup.get() {
            true => format!("--cpus not applied: firecracker {} failed to join its cgroup", self.pid()),
            false => "--cpus needs per-VM cgroups, which this host does not have".into(),
        })?;
        std::fs::write(cg.join("cpu.max"), max).map_err(|e| format!("--cpus not applied: {}: {e}", cg.join("cpu.max").display()))?;
        Ok(())
    }

    fn join_log(&self) {
        if let Some(j) = self.logging.borrow_mut().take() {
            let _ = j.join();
        }
    }
}

/// Common to every load (restore, standby, migration prepare and load): Firecracker opens no pmem
/// file but the one `template` names (`Template::pmem_path`), read only, whoever sent the vmstate
/// or the template (`firecracker/0002-*.patch`, #788).
pub(crate) fn snapshot_load_body(vmstate: &Path, template: &crate::template::Template, tap: &str, vsock: &Path, uffd: &Path) -> Result<Value> {
    Ok(serde_json::json!({
        "snapshot_path": vmstate,
        "device_reference_path": template.vmstate(),
        "confined_pmem": template.pmem_path()?,
        "mem_backend": {"backend_type": "Uffd", "backend_path": uffd},
        "vsock_override": {"uds_path": vsock},
        "network_overrides": [{"iface_id": "eth0", "host_dev_name": tap}],
    }))
}

/// One reader for both streams, with bounded memory even for a console without newlines.
/// Firecracker gets pipe writers only, so guest output cannot bypass log rotation.
fn spawn_logged(mut cmd: Command, dir: &Path) -> std::io::Result<(Child, std::thread::JoinHandle<()>)> {
    let log = dir.join("firecracker.log");
    crate::host::write_record(&log, b"")?;
    let (mut reader, writer) = std::io::pipe()?;
    cmd.stdout(writer.try_clone()?).stderr(writer);
    let child = crate::util::unblock_signals_in(&mut cmd).spawn()?;
    // Command retains the write ends too: close them so exit delivers EOF to the reader.
    drop(cmd);
    let logging = std::thread::spawn(move || {
        let mut buf = [0; 64 << 10];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    crate::util::output::append_capped(&log, &buf[..n], crate::util::output::LOG_CAP);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });
    Ok((child, logging))
}

/// Lines a guest kernel starts its oops or panic report with: what it hit, before the registers.
const GUEST_CRASH: [&str; 5] = ["Kernel panic", "BUG:", "Oops", "general protection fault", "Unable to handle"];

/// The log's last 5 lines, after the start of the guest kernel's crash report if it has one
/// (its first lines say why; the last ones are only its stack and the reboot).
fn post_mortem_lines(log: &str) -> String {
    let lines: Vec<&str> = log.lines().collect();
    let last = lines.len().saturating_sub(5);
    let report = match lines[..last].iter().position(|l| GUEST_CRASH.iter().any(|c| l.contains(c))) {
        Some(i) => lines[i..(i + 8).min(last)].iter().copied().chain(if i + 8 < last { Some("...") } else { None }).collect(),
        None => Vec::new(),
    };
    report.into_iter().chain(lines[last..].iter().copied()).collect::<Vec<_>>().join(" | ")
}

fn firecracker_log_tail(dir: &Path) -> String {
    // Rotation may have just removed the current file, or left fewer than five lines in it.
    ["firecracker.log.1", "firecracker.log"].into_iter().filter_map(|name| File::open(dir.join(name)).and_then(|mut f| log_tail(&mut f)).ok()).collect()
}

/// `child`'s exit status once it exited, leaving it unreaped: only `Drop` reaps Firecracker,
/// after the cgroup move, so nothing acting on its pid meanwhile can meet a reused one.
fn exited(child: &Child) -> std::io::Result<Option<ExitStatus>> {
    use std::os::unix::process::ExitStatusExt;
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    crate::util::check(unsafe { libc::waitid(libc::P_PID, child.id(), &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) })?;
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
    bin: PathBuf,
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
            let cached = self.connection.borrow_mut().take().filter(|r| !crate::util::readable(&r.get_ref().s, Duration::ZERO).unwrap_or(true));
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
                        Err(e) => return Err(Box::new(NotSent(format!("firecracker {method} {path} (timeout {timeout:?}): cannot connect: {e}")))),
                    }
                }
            };
            let mut sent = false;
            let (code, buf, close) = match exchange(&mut r, req.as_bytes(), &mut sent) {
                Ok(response) => response,
                Err(_) if !sent && reused => continue,
                Err(e) if !sent => return Err(Box::new(NotSent(format!("firecracker {method} {path} (timeout {timeout:?}): {e}")))),
                Err(e) => {
                    let kind = e.downcast_ref::<std::io::Error>().map_or(std::io::ErrorKind::Other, |e| e.kind());
                    return Err(std::io::Error::new(kind, format!("firecracker {method} {path} (timeout {timeout:?}): {e}")).into());
                }
            };
            // Bytes past the answer mean the stream is out of step.
            if !close && r.buffer().is_empty() {
                *self.connection.borrow_mut() = Some(r);
            }
            let text = String::from_utf8_lossy(&buf);
            if !(200..300).contains(&code) {
                return Err(api_error(method, path, code, &text, &self.bin));
            }
            return if text.trim().is_empty() { Ok(Value::Null) } else { Ok(serde_json::from_str(&text).unwrap_or(Value::String(text.into_owned()))) };
        }
    }
}

fn api_error(method: &str, path: &str, code: u16, text: &str, bin: &Path) -> crate::util::Error {
    if code == 400 && matches!(path, "/snapshot/load" | "/snapshot/prepare") && text.contains("unknown field `confined_pmem`") {
        return format!(
            "firecracker {method} {path}: this Firecracker predates flexvm's pmem confinement (artifacts-4); \
             remove {} so the pinned one is downloaded, or build one with scripts/build-firecracker.sh, then pull its templates again",
            bin.display()
        )
        .into();
    }
    format!("firecracker {method} {path}: {code} {text}").into()
}

const API_LINE: u64 = 8192;
const API_HEADERS: usize = 64;
const API_BODY: usize = 1 << 20;

fn response_line(r: &mut impl BufRead) -> Result<String> {
    let mut line = String::new();
    r.take(API_LINE + 1).read_line(&mut line)?;
    if line.len() as u64 > API_LINE {
        bail!("response line too long");
    }
    Ok(line)
}

fn exchange(r: &mut BufReader<crate::util::By<UnixStream>>, mut req: &[u8], sent: &mut bool) -> Result<(u16, Vec<u8>, bool)> {
    // After a partial write the request may have reached Firecracker: never replay it.
    while !req.is_empty() {
        match r.get_mut().write(req) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "request write returned zero").into()),
            Ok(n) => {
                *sent = true;
                req = &req[n..];
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let status = response_line(r)?;
    if status.is_empty() {
        bail!("closed the connection without answering");
    }
    let code: u16 = status.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    if code == 0 || !status.ends_with("\r\n") {
        bail!("invalid response status");
    }
    let mut len = None;
    let mut close = false;
    let mut headers = 0;
    loop {
        let h = response_line(r)?;
        if !h.ends_with("\r\n") {
            bail!("incomplete response headers");
        }
        if h == "\r\n" {
            break;
        }
        headers += 1;
        if headers > API_HEADERS {
            bail!("too many response headers");
        }
        let Some((k, v)) = h.trim_end().split_once(':') else {
            bail!("invalid response header");
        };
        if k.eq_ignore_ascii_case("content-length") {
            let n: usize = v.trim().parse()?;
            if n > API_BODY {
                bail!("response body too large");
            }
            if len.is_some_and(|previous| previous != n) {
                bail!("conflicting content lengths");
            }
            len = Some(n);
        } else if k.eq_ignore_ascii_case("connection") {
            close |= v.split(',').any(|v| v.trim().eq_ignore_ascii_case("close"));
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            bail!("unsupported transfer encoding");
        }
    }
    // micro_http omits Content-Length for 204; reading to EOF would lose keep-alive.
    let len = if code == 204 || code == 304 {
        if code == 204 && len.is_some_and(|n| n != 0) {
            bail!("nonzero content length for 204");
        }
        0
    } else {
        len.ok_or("missing content length")?
    };
    let mut buf = vec![0; len];
    r.read_exact(&mut buf)?;
    Ok((code, buf, close))
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
        // Reaped only once its pager has stopped.
        let _ = self.join_cgroup();
        self.api.connection.get_mut().take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.join_log();
        if !self.tap.is_empty() {
            release(Some(&self.tap), self.cgroup.get_mut().as_deref(), &self.dir);
        } else if let Some(cg) = self.cgroup.get_mut().take() {
            let _ = remove_cgroup(&cg);
        }
    }
}

/// Its Firecracker must be gone.
fn release(tap: Option<&str>, cgroup: Option<&Path>, dir: &Path) {
    if let Some(tap) = tap {
        crate::net::delete_tap(tap);
    }
    if let Some(cg) = cgroup {
        let _ = remove_cgroup(cg);
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Kills what is in it and removes it, busy until the kernel has torn those down.
pub fn remove_cgroup(cg: &Path) -> std::io::Result<()> {
    let _ = std::fs::write(cg.join("cgroup.kill"), "1");
    let until = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match std::fs::remove_dir(cg) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) && std::time::Instant::now() < until => std::thread::sleep(Duration::from_millis(1)),
            r => return r,
        }
    }
}

/// Starts Firecrackers, each with its own directory, tap and cgroup; the cgroup is joined in
/// the background (an RCU grace period). Spawn from a thread that lives as long as the VM.
pub struct Spawner {
    bin: PathBuf,
    root: PathBuf,
    sockets: Arc<SocketRoot>,
    cgroups: Option<PathBuf>,
    tap_prefix: String,
    /// Each tap's alias (`host::tap_alias`).
    tap_owner: String,
    next: AtomicU64,
    /// Taps handed out but not made yet: a concurrent `take` sees none of them in sysfs.
    making: Arc<Mutex<HashSet<String>>>,
    /// `cpu.max` for each Firecracker taken from now on (`--cpus`), written before it is handed out.
    cpu_max: Mutex<Option<String>>,
}

/// Reuse vanished taps; the lifetime counter is only for directories and cgroups.
/// The name is added to `making`, for its taker to remove once its tap is made or not.
fn free_tap(prefix: &str, interfaces: &Path, making: &Mutex<HashSet<String>>) -> Result<String> {
    let mut making = making.lock().unwrap();
    let mut n = 0u64;
    loop {
        let tap = format!("{prefix}{n:x}");
        if tap.len() >= libc::IFNAMSIZ {
            bail!("tap {tap:?} is over {} bytes (no free tap names)", libc::IFNAMSIZ - 1);
        }
        if !making.contains(&tap) && !interfaces.join(&tap).try_exists()? {
            making.insert(tap.clone());
            return Ok(tap);
        }
        n += 1;
    }
}

/// How many names a take claims before giving up: each but the last failed only as another
/// process made a tap of that name after `free_tap` looked (one of another PID namespace with
/// this process's pid, which has the same prefix: `vmproc`).
const TAP_CLAIMS: usize = 16;

/// Claims `tap` (`net::claim_tap`), and while another process has made a tap of that name since
/// `free_tap` passed it, the next free name. (the name it holds in `making`, the claimed name)
fn claim_free_tap(
    mut tap: String,
    prefix: &str,
    interfaces: &Path,
    making: &Mutex<HashSet<String>>,
    mut claim: impl FnMut(&str) -> std::io::Result<()>,
) -> (Option<String>, Result<String>) {
    let mut claims = 0;
    loop {
        claims += 1;
        match claim(&tap) {
            Err(e) if crate::net::name_taken(&e) && claims < TAP_CLAIMS => {}
            Ok(()) => return (Some(tap.clone()), Ok(tap)),
            Err(e) => return (Some(tap.clone()), Err(format!("create tap {tap}: {e}").into())),
        }
        // Taken: sysfs has it now, so `free_tap` passes it by.
        making.lock().unwrap().remove(&tap);
        tap = match free_tap(prefix, interfaces, making) {
            Ok(t) => t,
            Err(e) => return (None, Err(e)),
        };
    }
}

/// `take`'s tap thread: `make` sets a tap up around `claim_free_tap` (`net::create_tap_with`),
/// or fails before it claims anything. (the name it holds in `making`, the made tap): `first`,
/// reserved by `free_tap`, until a claim moves on from it.
fn make_free_tap<T: ?Sized>(
    first: String,
    prefix: &str,
    interfaces: &Path,
    making: &Mutex<HashSet<String>>,
    make: impl FnOnce(&mut dyn FnMut(&T) -> Result<String>) -> Result<String>,
    claim: impl Fn(&T, &str) -> std::io::Result<()>,
) -> (Option<String>, Result<String>) {
    let mut held = Some(first.clone());
    let mut first = Some(first);
    let made = make(&mut |t| {
        let Some(tap) = first.take() else { return Err("tap claimed twice".into()) };
        let (h, made) = claim_free_tap(tap, prefix, interfaces, making, |name| claim(t, name));
        held = h;
        made
    });
    (held, made)
}

impl Spawner {
    pub fn new(bin: &Path, root: &Path, sockets: Arc<SocketRoot>, cgroups: Option<PathBuf>, tap_prefix: &str, tap_owner: &str) -> Spawner {
        Spawner {
            bin: bin.into(),
            root: root.into(),
            sockets,
            cgroups,
            tap_prefix: tap_prefix.into(),
            tap_owner: tap_owner.into(),
            next: AtomicU64::new(0),
            making: Arc::default(),
            cpu_max: Mutex::default(),
        }
    }

    /// Every Firecracker `take` hands out from now on is held to `max` (`cpu.max`), or not taken.
    pub fn cap_cpus(&self, max: Option<String>) {
        *self.cpu_max.lock().unwrap() = max;
    }

    pub fn take(&self, deadline: Option<std::time::Instant>) -> Result<Firecracker> {
        let ready = deadline.map_or(SPAWN_READY, |d| d.saturating_duration_since(std::time::Instant::now()).min(SPAWN_READY));
        if ready.is_zero() {
            bail!("out of time to start firecracker");
        }
        let tap = free_tap(&self.tap_prefix, Path::new("/sys/class/net"), &self.making)?;
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        // Named by this process's identity, not its pid alone: never a dead one's with the same pid.
        let id = crate::host::idle_cgroup(n);
        let dir = self.root.join(&id);
        let cgroup = self.cgroups.as_ref().map(|root| root.join(&id));
        let made = {
            let (first, owner, prefix, making) = (tap.clone(), self.tap_owner.clone(), self.tap_prefix.clone(), self.making.clone());
            std::thread::spawn(move || {
                let make = |claim: &mut dyn FnMut(&std::os::fd::OwnedFd) -> Result<String>| crate::net::create_tap_with(&owner, claim);
                make_free_tap(first, &prefix, Path::new("/sys/class/net"), &making, make, crate::net::claim_tap)
            })
        };
        let fc = crate::host::host_dir(&dir, 0o700).map_err(Into::into).and_then(|()| Firecracker::spawn(&self.bin, &dir, self.sockets.allocate()?, ready));
        let (held, made) = made.join().unwrap_or_else(|_| (Some(tap), Err("tap thread panicked".into())));
        let tap = made.as_ref().ok().cloned();
        // A Firecracker without its tap is dropped (killed) here, before `release`.
        let fc = fc.and_then(|fc| made.map(|_| fc)).inspect_err(|_| release(tap.as_deref(), cgroup.as_deref(), &dir));
        // Made (sysfs has it now) or released: no longer kept from other takes.
        if let Some(held) = held {
            self.making.lock().unwrap().remove(&held);
        }
        let (mut fc, tap) = (fc?, tap.unwrap_or_default());
        // Under test, each VM's Firecracker keeps its device metrics (`metrics.json` in its
        // directory, appended every 60 s and on `FlushMetrics`), so a test can see what a
        // device did (#149). Metrics can only be configured before a load.
        if crate::host::faults_on() {
            let path = dir.join("metrics.json");
            if let Err(e) =
                crate::host::write_record(&path, b"").map_err(Into::into).and_then(|_| fc.put("/metrics", serde_json::json!({"metrics_path": path})))
            {
                crate::log!("firecracker {}: no metrics: {e}", fc.pid());
            }
        }
        // A capped one's cgroup is made, and capped, before Firecracker joins it (or none is taken):
        // the cap holds from the VM's first instruction.
        let cap = self.cpu_max.lock().unwrap().clone();
        if let Some(max) = &cap {
            fc.capped = true;
            *fc.cgroup.get_mut() = cgroup.clone();
            fc.tap = tap.clone();
            let cg = cgroup.as_ref().ok_or("--cpus needs per-VM cgroups (cgroup2 at /sys/fs/cgroup), which this host does not have")?;
            std::fs::create_dir(cg).map_err(|e| format!("--cpus not applied: {}: {e}", cg.join("cpu.max").display()))?;
            fc.set_cpu_max(max)?;
        }
        if let Some(cg) = cgroup {
            fc.attach_cgroup(cg, cap.is_some());
        }
        fc.tap = tap;
        Ok(fc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::net::UnixListener;
    use std::thread::JoinHandle;

    #[test]
    fn failed_cgroup_join_disables_limits_and_removes_the_directory() {
        for capped in [false, true] {
            let dir = crate::test_util::TempDir::new("fc-no-cgroup");
            let cg = dir.join("cg");
            std::fs::create_dir(&cg).unwrap();
            let sockets = SocketRoot::from_bases(&[dir.join("s")], &dir, None).unwrap().allocate().unwrap();
            let fc = Firecracker {
                child: Command::new("sleep").arg("30").spawn().unwrap(),
                sockets,
                dir: dir.to_path_buf(),
                cgroup: RefCell::new(Some(cg.clone())),
                tap: String::new(),
                api: Api::default(),
                joining: RefCell::new(Some(std::thread::spawn(|| Err(std::io::Error::from_raw_os_error(libc::EACCES))))),
                capped,
                lost_cgroup: Cell::new(false),
                logging: RefCell::new(None),
            };
            assert_eq!(fc.join_cgroup().is_err(), capped);
            assert_eq!(fc.cgroup(), None);
            assert!(fc.lost_cgroup());
            assert!(!cg.exists());
            assert!(fc.set_cpu_max("100000 100000").is_err());
            let limit = crate::limit::Limit::new(fc.cgroup());
            limit.start(512, 1024);
            assert_eq!(limit.used(), None);
            assert_eq!(limit.admitted(), 0);
        }
        // None to join (the host has no per-VM cgroups): none lost, so a standby is not given up for it.
        let dir = crate::test_util::TempDir::new("fc-no-cgroups");
        let fc = Firecracker {
            child: Command::new("sleep").arg("30").spawn().unwrap(),
            sockets: SocketRoot::from_bases(&[dir.join("s")], &dir, None).unwrap().allocate().unwrap(),
            dir: dir.to_path_buf(),
            cgroup: RefCell::new(None),
            tap: String::new(),
            api: Api::default(),
            joining: RefCell::new(None),
            capped: false,
            lost_cgroup: Cell::new(false),
            logging: RefCell::new(None),
        };
        assert!(fc.set_cpu_max("100000 100000").is_err());
        assert!(!fc.lost_cgroup());
    }

    #[test]
    fn firecracker_output_flood_is_capped_and_keeps_final_diagnostics() {
        let dir = crate::test_util::TempDir::new("fc-log-flood");
        let mut cmd = Command::new("sh");
        // Flood both streams without line boundaries, then emit distinct final diagnostics.
        cmd.arg("-c")
            .arg(
                "i=0; while [ \"$i\" -lt 4096 ]; do printf '%s' \"$1\"; printf '%s' \"$1\" >&2; i=$((i+1)); done; \
             printf '\\nstdout final\\n'; printf 'stderr final\\n' >&2",
            )
            .arg("sh")
            .arg("x".repeat(4096));
        let (child, logging) = spawn_logged(cmd, &dir).unwrap();
        let mut child = crate::test_util::ChildGuard(child);
        assert!(child.wait().unwrap().success());
        logging.join().unwrap();
        let mut total = 0;
        for name in ["firecracker.log", "firecracker.log.1"] {
            let len = std::fs::metadata(dir.join(name)).unwrap().len();
            assert!(len <= crate::util::output::LOG_CAP + (64 << 10), "{name}: {len}");
            total += len;
        }
        assert!(total < 32 << 20, "the flood must have rotated");
        assert!(firecracker_log_tail(&dir).ends_with("stdout final\nstderr final\n"));
    }

    #[test]
    fn a_guest_crash_report_keeps_its_first_lines() {
        assert_eq!(post_mortem_lines("a\nb\nc\n"), "a | b | c");
        let mut log = vec!["boot".to_string(), "[ 19.1] BUG: unable to handle page fault for address: ffff8880".into()];
        log.extend((0..20).map(|i| format!("stack {i}")));
        log.push("[ 19.8] Rebooting in 1 seconds..".into());
        let got = post_mortem_lines(&log.join("\n"));
        assert!(got.starts_with("[ 19.1] BUG: unable to handle page fault for address: ffff8880 | stack 0 |"), "{got}");
        assert!(got.contains("stack 6 | ... | stack 16 |") && got.ends_with("[ 19.8] Rebooting in 1 seconds.."), "{got}");
        // A report already within the last lines is not repeated.
        assert_eq!(post_mortem_lines("x\nOops: 0000\ny\nz\nw\n"), "x | Oops: 0000 | y | z | w");
    }

    #[test]
    fn firecracker_diagnostics_span_rotation_even_without_a_current_log() {
        let dir = crate::test_util::TempDir::new("fc-log-rotation");
        std::fs::write(dir.join("firecracker.log.1"), "first\nsecond\n").unwrap();
        assert_eq!(firecracker_log_tail(&dir), "first\nsecond\n");
        std::fs::write(dir.join("firecracker.log"), "third\n").unwrap();
        assert_eq!(firecracker_log_tail(&dir), "first\nsecond\nthird\n");
    }

    #[test]
    fn spawner_reuses_tap_names_past_256_and_4096_takes() {
        // Six prefix bytes and six pid digits leave two suffix digits; five leave three.
        for prefix in ["abcdef3ffffft", "abcde3ffffft"] {
            let interfaces = crate::test_util::TempDir::new("tap-names");
            let making = Mutex::default();
            let mut live = std::collections::VecDeque::new();
            for take in 0..5000 {
                // The allocation step of take(), with sysfs replaced by fake live interfaces.
                let tap = free_tap(prefix, &interfaces, &making).unwrap();
                assert!(tap.len() <= 15, "take {take}: {tap}");
                assert!(!live.contains(&tap), "take {take}: duplicate live tap {tap}");
                assert_eq!(tap, format!("{prefix}{:x}", take % 8), "lowest free suffix");
                std::fs::create_dir(interfaces.join(&tap)).unwrap();
                making.lock().unwrap().remove(&tap);
                live.push_back(tap);
                if live.len() == 8 {
                    std::fs::remove_dir(interfaces.join(live.pop_front().unwrap())).unwrap();
                }
            }
        }
    }

    #[test]
    fn spawner_refuses_overlong_tap_before_probing_or_spawning() {
        let interfaces = crate::test_util::TempDir::new("tap-full");
        let prefix = "abcdef3ffffft";
        for n in 0..256 {
            std::fs::create_dir(interfaces.join(format!("{prefix}{n:x}"))).unwrap();
        }
        let error = free_tap(prefix, &interfaces, &Mutex::default()).unwrap_err().to_string();
        assert!(error.contains("abcdef3ffffft100") && error.contains("15 bytes"), "{error}");
        // Even an invalid prefix is checked before looking at the interface directory.
        let error = free_tap("abcdefgh3ffffft", &interfaces.join("absent"), &Mutex::default()).unwrap_err().to_string();
        assert!(error.contains("abcdefgh3ffffft0") && error.contains("15 bytes"), "{error}");
        std::fs::remove_dir(interfaces.join(format!("{prefix}80"))).unwrap();
        assert_eq!(free_tap(prefix, &interfaces, &Mutex::default()).unwrap(), format!("{prefix}80"));
    }

    #[test]
    fn a_tap_another_process_made_first_is_passed_by() {
        // Another PID namespace's process with this pid made fvt0 after `free_tap` looked.
        let interfaces = crate::test_util::TempDir::new("tap-taken");
        let making = Mutex::default();
        let first = free_tap("fvt", &interfaces, &making).unwrap();
        let mut claimed = Vec::new();
        let (held, made) = claim_free_tap(first, "fvt", &interfaces, &making, |name| {
            claimed.push(name.to_string());
            if name == "fvt0" {
                std::fs::create_dir(interfaces.join(name)).unwrap();
                return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
            }
            Ok(())
        });
        assert_eq!((held.as_deref(), made.unwrap().as_str(), claimed), (Some("fvt1"), "fvt1", vec!["fvt0".to_string(), "fvt1".to_string()]));
        // Only fvt1 is still kept from other takes, for the taker to let go.
        assert_eq!(*making.lock().unwrap(), HashSet::from(["fvt1".to_string()]));
        // Every name taken: a bounded number of claims, then the error; other errors are not retried.
        let making = Mutex::default();
        let mut claims = 0;
        let (held, made) = claim_free_tap(free_tap("fvu", &interfaces, &making).unwrap(), "fvu", &interfaces, &making, |name| {
            claims += 1;
            std::fs::create_dir(interfaces.join(name)).unwrap();
            Err(std::io::Error::from_raw_os_error(libc::EBUSY))
        });
        assert_eq!((claims, held.as_deref()), (TAP_CLAIMS, Some(&*format!("fvu{:x}", TAP_CLAIMS - 1))));
        assert!(made.unwrap_err().to_string().contains("busy"));
        let (_, made) = claim_free_tap("fvv0".into(), "fvv", &interfaces, &Mutex::default(), |_| Err(std::io::Error::from_raw_os_error(libc::EPERM)));
        assert!(made.unwrap_err().to_string().contains("create tap fvv0"));
    }

    #[test]
    fn a_tap_that_fails_before_its_claim_lets_its_reserved_name_go() {
        let interfaces = crate::test_util::TempDir::new("tap-unclaimed");
        let making = Mutex::default();
        // An owner too long, or no /dev/net/tun: nothing claimed, and fvt0 is still the taker's to let go.
        let first = free_tap("fvt", &interfaces, &making).unwrap();
        let (held, made) =
            make_free_tap::<()>(first, "fvt", &interfaces, &making, |_| Err("/dev/net/tun: too many open files".into()), |_, _| panic!("claimed"));
        assert_eq!((held.as_deref(), made.is_err()), (Some("fvt0"), true));
        making.lock().unwrap().remove(&held.unwrap());
        assert!(making.lock().unwrap().is_empty());
        // A claim moves the hold to the name it made.
        let first = free_tap("fvt", &interfaces, &making).unwrap();
        let (held, made) = make_free_tap(
            first,
            "fvt",
            &interfaces,
            &making,
            |claim| claim(&()),
            |_, name| {
                if name == "fvt0" {
                    std::fs::create_dir(interfaces.join(name)).unwrap();
                    return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
                }
                Ok(())
            },
        );
        assert_eq!((held.as_deref(), made.unwrap().as_str()), (Some("fvt1"), "fvt1"));
    }

    #[test]
    fn spawner_never_hands_out_a_tap_still_being_made() {
        // Two takes with neither tap made yet (`create_tap` runs on its own thread).
        let interfaces = crate::test_util::TempDir::new("tap-making");
        let making = Mutex::default();
        let (a, b) = (free_tap("fvt", &interfaces, &making).unwrap(), free_tap("fvt", &interfaces, &making).unwrap());
        assert_eq!((a.as_str(), b.as_str()), ("fvt0", "fvt1"));
        // A failed make lets its name go: the next take reuses it.
        making.lock().unwrap().remove(&a);
        assert_eq!(free_tap("fvt", &interfaces, &making).unwrap(), "fvt0");
        // A made one is kept out by sysfs once its reservation is gone.
        std::fs::create_dir(interfaces.join(&b)).unwrap();
        making.lock().unwrap().remove(&b);
        assert_eq!(free_tap("fvt", &interfaces, &making).unwrap(), "fvt2");
    }

    struct Server {
        path: PathBuf,
        thread: Option<JoinHandle<()>>,
        _dir: crate::test_util::TempDir,
    }

    impl Server {
        fn new(f: impl FnOnce(UnixListener) + Send + 'static) -> Self {
            let dir = crate::test_util::TempDir::new("http");
            let path = dir.join("api");
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            Self { path, thread: Some(std::thread::spawn(move || f(listener))), _dir: dir }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.thread.take().unwrap().join().unwrap();
            std::fs::remove_file(&self.path).unwrap();
        }
    }

    fn accept(listener: &UnixListener) -> BufReader<UnixStream> {
        let s = retry(PATIENCE, Duration::from_millis(1), || Ok(listener.accept()?.0)).unwrap();
        s.set_read_timeout(Some(PATIENCE)).unwrap();
        s.set_write_timeout(Some(PATIENCE)).unwrap();
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

    #[test]
    fn memory_deadline_scales_with_gib_rounded_up() {
        for (mib, seconds) in [(0, 30), (1, 31), (1024, 31), (1025, 32), (47_872, 77), (u64::MAX, 30 + u64::MAX.div_ceil(1024))] {
            assert_eq!(memory_timeout(mib), Duration::from_secs(seconds));
        }
    }

    const NO_CONTENT: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";

    #[test]
    fn snapshot_unknown_confined_pmem_names_the_fix() {
        let body = r#"{"fault_message":"unknown field `confined_pmem`, expected `snapshot_path` at line 1 column 16"}"#;
        let bin = Path::new("/custom/state/artifacts/firecracker");
        for path in ["/snapshot/load", "/snapshot/prepare"] {
            let error = api_error("PUT", path, 400, body, bin).to_string();
            assert_eq!(error, format!(
                "firecracker PUT {path}: this Firecracker predates flexvm's pmem confinement (artifacts-4); \
                 remove /custom/state/artifacts/firecracker so the pinned one is downloaded, or build one with scripts/build-firecracker.sh, then pull its templates again"
            ));
        }
        for (path, code, body) in [
            ("/snapshot/load", 500, body),
            ("/vm", 400, body),
            ("/snapshot/load", 400, "unknown field `other`, expected `confined_pmem`"),
            ("/snapshot/prepare", 400, "cannot open confined_pmem"),
        ] {
            assert_eq!(api_error("PUT", path, code, body, bin).to_string(), format!("firecracker PUT {path}: {code} {body}"));
        }
    }

    /// How long a test side waits on the other: a bound for a hung test, never what one checks. A loaded host
    /// stalls a test process for seconds (#136), which a tighter call deadline took for a failed call.
    const PATIENCE: Duration = Duration::from_secs(30);

    fn call(api: &Api, socket: &Path) -> Result<Value> {
        api.request(socket, "PATCH", "/vm", Some(serde_json::json!({"state": "Resumed"})), PATIENCE)
    }

    /// #730: a Firecracker killed during an API call fails that call at once (not at its deadline), and the
    /// next call too: its socket refuses, never retried. Its "Firecracker" is a child process (this test).
    #[test]
    fn an_api_call_to_a_firecracker_killed_meanwhile_fails_at_once() {
        const CHILD: &str = "FLEXVM_TEST_FAKE_FIRECRACKER";
        if let Some(dir) = std::env::var_os(CHILD) {
            let dir = PathBuf::from(dir);
            let listener = UnixListener::bind(dir.join("api")).unwrap();
            std::fs::write(dir.join("listening"), b"").unwrap();
            let mut r = accept(&listener);
            read_request(&mut r);
            std::fs::write(dir.join("read"), b"").unwrap();
            loop {
                std::thread::park();
            }
        }
        let dir = crate::test_util::TempDir::new("fake-fc");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child.args(["--exact", "fc::tests::an_api_call_to_a_firecracker_killed_meanwhile_fails_at_once", "--nocapture"]).env(CHILD, dir.as_os_str());
        let mut child = crate::test_util::ChildGuard(child.spawn().unwrap());
        let socket = dir.join("api");
        retry(PATIENCE, Duration::from_millis(1), || Ok(std::fs::metadata(dir.join("listening")).map(drop)?))
            .unwrap_or_else(|e: crate::util::Error| panic!("{e}"));
        let killer = {
            let (read, pid) = (dir.join("read"), child.0.id() as i32);
            std::thread::spawn(move || {
                retry(PATIENCE, Duration::from_millis(1), || Ok(std::fs::metadata(&read).map(drop)?)).unwrap_or_else(|e: crate::util::Error| panic!("{e}"));
                unsafe { libc::kill(pid, libc::SIGKILL) };
            })
        };
        // Its deadline is PATIENCE (30 s): an error naming the close, not the deadline, is the death's.
        let api = Api::default();
        let e = api.request(&socket, "PATCH", "/vm", Some(serde_json::json!({"state": "Paused"})), PATIENCE).unwrap_err();
        killer.join().unwrap();
        assert!(e.to_string().contains("closed the connection without answering"), "{e}");
        // Wholly gone (its listener may close a moment after the connection did).
        child.0.wait().unwrap();
        let start = std::time::Instant::now();
        let e = call(&api, &socket).unwrap_err();
        assert!(e.downcast_ref::<NotSent>().is_some() && e.to_string().contains("cannot connect"), "{e}");
        assert!(start.elapsed() < PATIENCE / 2, "refused at once, not retried: {:?}", start.elapsed());
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
    fn api_uses_the_readiness_connection_for_its_first_request() {
        let server = Server::new(|listener| {
            let mut r = accept(&listener);
            answer(&mut r, NO_CONTENT);
            no_more(&listener);
        });
        let s = UnixStream::connect(&server.path).unwrap();
        let api = Api::default();
        *api.connection.borrow_mut() = Some(BufReader::new(crate::util::By { s, at: std::time::Instant::now() }));
        call(&api, &server.path).unwrap();
    }

    #[test]
    fn api_reconnects_after_unsent_write_on_closed_connection() {
        let (closed, wait) = std::sync::mpsc::channel();
        let server = Server::new(move |listener| {
            let mut r = accept(&listener);
            answer(&mut r, NO_CONTENT);
            // Shut down, not only dropped: a child another test forks meanwhile shares the socket until it execs,
            // and the connection would stay open for that long.
            r.get_ref().shutdown(std::net::Shutdown::Both).unwrap();
            drop(r);
            closed.send(()).unwrap();
            answer(&mut accept(&listener), NO_CONTENT);
        });
        let api = Api::default();
        assert_eq!(call(&api, &server.path).unwrap(), Value::Null);
        wait.recv_timeout(PATIENCE).unwrap();
        assert_eq!(call(&api, &server.path).unwrap(), Value::Null);
    }

    #[test]
    fn api_drops_a_connection_it_cannot_reuse() {
        for (first, second, want) in [
            // The header alone must force a new connection (the old one stays open).
            (&b"HTTP/1.1 200 OK\r\ncOnNeCtIoN: keep-alive, Close\r\nContent-Length: 4\r\n\r\nnull"[..], NO_CONTENT, Value::Null),
            (
                &b"HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"[..],
                &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n2"[..],
                serde_json::json!(2),
            ),
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
        wait.recv_timeout(PATIENCE).unwrap();
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
        // Response bytes arrive halfway to the deadline: one restarted by them, not kept for the whole call, would
        // return no sooner than TIMEOUT after they were sent, so the call has TIMEOUT / 2 of scheduling slack.
        const TIMEOUT: Duration = Duration::from_secs(2);
        for response in [&b""[..], &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"[..], &b"HTTP/1.1 200 OK\r\nContent-Length:"[..]] {
            let (sent_tx, sent_rx) = std::sync::mpsc::channel();
            let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
            let server = Server::new(move |listener| {
                let mut r = accept(&listener);
                read_request(&mut r);
                std::thread::sleep(TIMEOUT / 2);
                sent_tx.send(std::time::Instant::now()).unwrap();
                // A client already past its deadline (a loaded host) has closed: EPIPE.
                let _ = r.get_mut().write_all(response);
                // Open until the client is done with it (or has failed): then it never came back to replay.
                let _ = done_rx.recv();
                no_more(&listener);
            });
            // Dropped before `server` on a failure, so its thread ends.
            let done_tx = done_tx;
            let api = Api::default();
            let e = api.request(&server.path, "GET", "/vm", None, TIMEOUT).unwrap_err();
            let returned = std::time::Instant::now();
            assert!(!not_sent(&e));
            assert_eq!(e.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::TimedOut);
            assert_eq!(e.to_string(), format!("firecracker GET /vm (timeout {TIMEOUT:?}): deadline passed"));
            let sent = sent_rx.recv().unwrap();
            assert!(returned < sent + TIMEOUT, "deadline restarted by the response bytes: returned {:?} after them", returned - sent);
            assert!(api.connection.borrow().is_none());
            done_tx.send(()).unwrap();
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
    fn api_bounds_response_lines_headers_and_body() {
        let responses = [
            format!("HTTP/1.1 200 {}", "x".repeat(API_LINE as usize)),
            format!("HTTP/1.1 200 OK\r\nX: {}", "x".repeat(API_LINE as usize)),
            format!("HTTP/1.1 200 OK\r\n{}Content-Length: 0\r\n\r\n", "X: y\r\n".repeat(API_HEADERS + 1)),
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", API_BODY + 1),
        ];
        for response in responses {
            let server = Server::new(move |listener| answer(&mut accept(&listener), response.as_bytes()));
            let api = Api::default();
            assert!(!not_sent(&call(&api, &server.path).unwrap_err()));
            assert!(api.connection.borrow().is_none());
        }
        assert_eq!(response_line(&mut &b"ok\r\n"[..]).unwrap(), "ok\r\n");
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
        let e = api.request(missing, "GET", "/vm", None, Duration::ZERO).unwrap_err();
        assert!(not_sent(&e));
        assert_eq!(e.to_string(), "firecracker GET /vm (timeout 0ns): cannot connect: deadline passed");
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
            let mut child = crate::test_util::ChildGuard(Command::new("sh").args(["-c", script]).spawn().unwrap());
            let st = retry(Duration::from_secs(5), Duration::from_millis(10), || Ok(exited(&child)?.ok_or("running")?)).unwrap();
            assert!(st.to_string().contains(want), "{st}");
            assert!(exited(&child).unwrap().is_some(), "still there to ask again");
            assert!(Path::new(&format!("/proc/{}", child.id())).exists(), "a zombie, its pid not free");
            assert_eq!(child.wait().unwrap(), st);
        }
    }

    #[test]
    fn post_mortem_log_reads_only_a_bounded_tail() {
        let _dir = crate::test_util::TempDir::new("fc-tail");
        let path = _dir.join("fixture");
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
