//! Temporary fixtures shared by the host and guest unit tests.
use std::fs;
use std::ops::Deref;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;

#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        static SWEEP: Once = Once::new();
        let root = std::env::temp_dir();
        SWEEP.call_once(|| sweep(&root));
        Self::new_in(&root, name)
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

fn sweep(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
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
    let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
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
    sweep(&root);
    assert!(gone.iter().all(|name| !root.join(name).exists()));
    assert!(kept.iter().all(|name| root.join(name).exists()));
    assert!(link.is_symlink());
}
