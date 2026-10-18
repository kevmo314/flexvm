//! Temporary fixtures shared by the host and guest unit tests.
use std::fs;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

pub const WAIT: Duration = Duration::from_secs(60);

/// Wait for observable progress, allowing for a heavily contended test host.
#[track_caller]
pub fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let end = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Keep a broken helper from hanging its test in `join`.
#[allow(dead_code)] // the guest shares this file
pub trait JoinWithin<T> {
    fn join_within(self) -> std::thread::Result<T>;
}

impl<T> JoinWithin<T> for std::thread::JoinHandle<T> {
    #[track_caller]
    fn join_within(self) -> std::thread::Result<T> {
        wait_until("helper thread to finish", || self.is_finished());
        self.join()
    }
}

/// Accepts on a blocking listener, failing after `WAIT` rather than hanging.
#[track_caller]
fn accept<T>(listener: &impl std::os::fd::AsRawFd, accept: impl FnOnce() -> std::io::Result<T>) -> T {
    let mut fd = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let n = loop {
        let n = unsafe { libc::poll(&mut fd, 1, WAIT.as_millis() as _) };
        if n >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break n;
        }
    };
    assert!(n > 0, "no helper connection: {}", if n < 0 { std::io::Error::last_os_error().to_string() } else { "timed out".into() });
    accept().unwrap()
}

#[allow(dead_code)] // the guest shares this file
#[track_caller]
pub fn accept_tcp(listener: &std::net::TcpListener) -> (std::net::TcpStream, std::net::SocketAddr) {
    let (stream, addr) = accept(listener, || listener.accept());
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    (stream, addr)
}

#[allow(dead_code)] // the guest shares this file
#[track_caller]
pub fn accept_unix(listener: &std::os::unix::net::UnixListener) -> (std::os::unix::net::UnixStream, std::os::unix::net::SocketAddr) {
    let (stream, addr) = accept(listener, || listener.accept());
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    (stream, addr)
}

/// An `#[ignore]`d test that needs root fails, not passes, without it: CI runs them under sudo
/// (`cargo test -- --ignored`), and one that returned early there would check nothing.
#[allow(dead_code)] // not every crate that shares this file has one
pub fn assert_root() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "a root-only test: run it as root (cargo test -- --ignored, under sudo)");
}

/// Kills and reaps a helper process even when its test unwinds.
pub struct ChildGuard(pub std::process::Child);

impl Deref for ChildGuard {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A helper process's exit status, failing after `WAIT` rather than hanging.
#[allow(dead_code)] // the guest shares this file
pub fn status(command: &mut std::process::Command) -> std::io::Result<std::process::ExitStatus> {
    let (mut child, end) = (ChildGuard(command.spawn()?), Instant::now() + WAIT);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= end {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "helper process did not exit"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn sleeper(secs: u64) -> ChildGuard {
    ChildGuard(std::process::Command::new("sleep").arg(secs.to_string()).spawn().unwrap())
}

#[test]
fn helper_process_is_killed_and_reaped_on_unwind() {
    let child = sleeper(60);
    let pid = child.id();
    let result = std::panic::catch_unwind(move || {
        let _child = child;
        panic!("exercise child cleanup");
    });
    assert!(result.is_err());
    assert_eq!(unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
}

#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        static SWEEP: Once = Once::new();
        // Unix socket fixtures must fit sun_path regardless of TMPDIR.
        let root = Path::new("/tmp");
        // /tmp can be shared by PID namespaces: a live test elsewhere may look dead
        // here. Never sweep another freshly started suite's fixtures.
        SWEEP.call_once(|| sweep(root, std::time::Duration::from_secs(24 * 60 * 60)));
        Self::new_in(root, name)
    }

    pub fn new_in(root: &Path, name: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let dir = root.join(format!("flexvm-test-{name}-{}-{}", NEXT.fetch_add(1, Ordering::Relaxed), std::process::id()));
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Self(dir),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create {}: {e}", dir.display()),
            }
        }
    }
}

impl Deref for TempDir {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.0
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sweep(root: &Path, minimum_age: std::time::Duration) {
    let Ok(entries) = fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let age = entry.metadata().and_then(|m| m.modified()).ok().and_then(|modified| modified.elapsed().ok());
        if age.is_none_or(|age| age < minimum_age) {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // Only test fixtures: in particular, flexvm-s-<uid> is a production socket root.
        const PREFIXES: &[&str] = &[
            "flexvm-test-",
            "flexvm-host-",
            "flexvm-standby-",
            "flexvm-compat-",
            "fv-long-",
            "fv-proc-",
            "fvs-test-",
            "flexvm-abandon-",
            "flexvm-trusted-",
            "flexvm-write-file-",
            "flexvm-scope-",
            "flexvm-rotate-",
            "flexvm-backlog-",
            "flexvm-private-",
            "flexvm-ancestors-",
            "flexvm-arrival-log-",
            "flexvm-listen-",
            "flexvm-limit-",
            "flexvm-relieve-",
            "flexvm-api-",
            "flexvm-refill-",
            "flexvm-gc-",
            "flexvm-kill-source-",
            "flexvm-exec-dead-",
            "flexvm-img-",
            "flexvm-wset-mib-",
            "flexvm-identity-",
            "flexvm-check-group-",
            "flexvm-map-integrity-",
            "flexvm-lengths-",
            "flexvm-ckpt-",
            "flexvm-delta-",
            "flexvm-parallel-sync-",
            "flexvm-stage-",
            "flexvm-baseruns-",
        ];
        if !PREFIXES.iter().any(|prefix| name.starts_with(prefix)) {
            continue;
        }
        // These older fixtures used <pid>-<counter>; all others end in <pid>.
        let mut parts = name.rsplit('-');
        let last = parts.next().unwrap();
        let pid =
            if ["flexvm-identity-", "flexvm-api-", "fvs-test-"].iter().any(|prefix| name.starts_with(prefix)) { parts.next().unwrap_or("") } else { last };
        let Ok(pid) = pid.parse::<i32>() else { continue };
        if pid > 0 && unsafe { libc::kill(pid, 0) } == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

#[test]
fn temporary_directories_are_unique_and_removed_on_unwind() {
    let first = TempDir::new("guard");
    assert_eq!(first.parent(), Some(Path::new("/tmp")), "socket fixtures need a short root regardless of TMPDIR");
    let path = first.to_path_buf();
    let other = TempDir::new("guard");
    assert_ne!(*first, *other);
    let result = std::panic::catch_unwind(move || {
        let _dir = first;
        fs::write(_dir.join("file"), b"fixture").unwrap();
        panic!("exercise cleanup");
    });
    assert!(result.is_err());
    assert!(!path.exists());
    assert!(other.exists());
}

#[test]
fn sweep_removes_dead_fixtures_and_preserves_live_and_unrelated_directories() {
    let root = TempDir::new("sweep");
    let mut child = ChildGuard(std::process::Command::new("/bin/true").spawn().unwrap());
    let dead = child.id();
    child.wait().unwrap();
    let gone = [
        format!("flexvm-host-marks-{dead}"),
        format!("flexvm-standby-budget-{dead}"),
        format!("flexvm-compat-{dead}"),
        format!("fv-long-{dead}"),
        format!("fv-proc-pause-{dead}"),
        format!("flexvm-identity-{dead}-2"),
        format!("flexvm-api-{dead}-3"),
        format!("fvs-test-{dead}-4"),
        format!("flexvm-test-guard-5-{dead}"),
    ];
    let kept = [format!("flexvm-host-live-{}", std::process::id()), format!("unrelated-{dead}"), "flexvm-host-no-pid".into(), format!("flexvm-s-{dead}")];
    for name in gone.iter().chain(&kept) {
        fs::create_dir(root.join(name)).unwrap();
        fs::write(root.join(name).join("file"), b"fixture").unwrap();
    }
    let link = root.join(format!("flexvm-link-{dead}"));
    std::os::unix::fs::symlink(root.join(&kept[1]), &link).unwrap();
    sweep(&root, std::time::Duration::from_secs(24 * 60 * 60));
    assert!(gone.iter().all(|name| root.join(name).exists()), "fresh fixtures may belong to a live test in another PID namespace");
    sweep(&root, std::time::Duration::ZERO);
    assert!(gone.iter().all(|name| !root.join(name).exists()));
    assert!(kept.iter().all(|name| root.join(name).exists()));
    assert!(link.is_symlink());
}

/// Held by each root networking test (`--ignored`) while it runs. Run in parallel, one test's
/// fork (`tc`, say) inherits another's /dev/net/tun descriptor until it execs, keeping the tap
/// attached, so a reattach in between fails with EBUSY (#552).
#[allow(dead_code)] // the guest's tests share this file
pub fn root_net_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
