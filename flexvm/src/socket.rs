//! Short, private socket directories, independent of artifact and run paths.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::util::Result;

/// Linux sun_path includes the terminating NUL.
pub fn check(path: &Path) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 || bytes.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!(
            "Unix socket path {} ({} bytes) must be shorter than 108 bytes and contain no NUL", path.display(), bytes.len()
        )));
    }
    Ok(())
}

/// Never reuse a symlink, someone else's directory, or a shared directory.
pub fn private(path: &Path) -> io::Result<()> {
    private_for(path, unsafe { libc::geteuid() })
}

fn private_for(path: &Path, uid: u32) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o7777 != 0o700 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!(
            "socket directory {} must be a real directory owned by uid {uid} with mode 0700", path.display()
        )));
    }
    Ok(())
}

fn bases() -> [PathBuf; 3] {
    let uid = unsafe { libc::geteuid() };
    [
        PathBuf::from("/run/flexvm/s"),
        PathBuf::from(format!("/run/user/{uid}/flexvm-s")),
        PathBuf::from(format!("/tmp/flexvm-s-{uid}")),
    ]
}

/// The run directory's mapping survives a crash. Validate it before using
/// it to identify orphan processes or remove their sockets.
pub fn previous(run: &Path) -> Result<Option<PathBuf>> {
    mapped_root(run, &bases())
}

fn mapped_root(run: &Path, allowed: &[PathBuf]) -> Result<Option<PathBuf>> {
    let dir = match fs::read_link(run.join("sockets")) {
        Ok(dir) => dir,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let valid_name = dir.file_name().is_some_and(|n| n.as_bytes().len() == 16 && n.as_bytes().iter().all(u8::is_ascii_hexdigit));
    let base = dir.parent().filter(|p| allowed.iter().any(|b| b == p));
    let Some(base) = base.filter(|_| valid_name) else {
        return Err(format!("invalid socket directory mapping {}", dir.display()).into());
    };
    private(base)?;
    if base.starts_with("/run") {
        private(base.parent().unwrap())?;
    }
    match private(&dir) {
        Ok(()) => Ok(Some(dir)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn directory(path: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    private(path)
}

/// One daemon or template builder. Slots keep it alive until their cleanup.
pub struct SocketRoot {
    pub dir: PathBuf,
    next: AtomicU64,
}

impl SocketRoot {
    pub fn new() -> Result<Arc<Self>> {
        Self::from_bases(&bases())
    }

    fn from_bases(candidates: &[PathBuf]) -> Result<Arc<Self>> {
        let mut errors = Vec::new();
        for base in candidates {
            let attempt = (|| {
                if base.starts_with("/run") {
                    // /run is system-owned; every directory below it used
                    // here must be private to our uid.
                    directory(base.parent().unwrap())?;
                }
                directory(base)?;
                Self::under(base)
            })();
            match attempt {
                Ok(root) => return Ok(root),
                Err(e) => errors.push(format!("{}: {e}", base.display())),
            }
        }
        Err(format!("cannot create a private socket directory: {}", errors.join("; ")).into())
    }

    fn under(base: &Path) -> Result<Arc<Self>> {
        use std::hash::{BuildHasher, Hasher};
        private(base)?;
        loop {
            let id = std::collections::hash_map::RandomState::new().build_hasher().finish();
            let dir = base.join(format!("{id:016x}"));
            // Check the longest possible slot and Firecracker's port suffix
            // before creating anything, even if a future base is longer.
            check(&dir.join("ffffffffffffffff/v.sock_4294967295"))?;
            match DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(Arc::new(Self { dir, next: AtomicU64::new(0) })),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub fn allocate(self: &Arc<Self>) -> Result<Sockets> {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let dir = self.dir.join(format!("{n:x}"));
        let api = dir.join("api.sock");
        let vsock = dir.join("v.sock");
        let uffd = dir.join("uffd.sock");
        for path in [&api, &vsock, &uffd, &dir.join("v.sock_4294967295")] {
            check(path)?;
        }
        DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(Sockets { api, vsock, uffd, dir, _root: self.clone() })
    }
}

impl Drop for SocketRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.dir);
    }
}

/// Owned by Firecracker; removing the directory also removes vsock port UDSes.
pub struct Sockets {
    pub api: PathBuf,
    pub vsock: PathBuf,
    pub uffd: PathBuf,
    dir: PathBuf,
    _root: Arc<SocketRoot>,
}

impl Sockets {
    pub fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Drop for Sockets {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = PathBuf::from(format!("/tmp/fvs-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        DirBuilder::new().mode(0o700).create(&base).unwrap();
        base
    }

    #[test]
    fn short_unique_paths_and_cleanup() {
        let base = fixture();
        let root = SocketRoot::under(&base).unwrap();
        let root_dir = root.dir.clone();
        private(&root_dir).unwrap();
        let a = root.allocate().unwrap();
        root.next.store(u64::MAX, Ordering::Relaxed);
        let b = root.allocate().unwrap();
        assert_ne!(a.dir, b.dir);
        private(&a.dir).unwrap();
        for sockets in [&a, &b] {
            for path in [&sockets.api, &sockets.vsock, &sockets.uffd, &sockets.dir.join("v.sock_4294967295")] {
                check(path).unwrap();
                fs::write(path, b"socket placeholder").unwrap();
            }
        }
        drop(root);
        let dir = a.dir.clone();
        drop(a);
        assert!(!dir.exists());
        assert!(root_dir.exists());
        assert!(b.dir.exists());
        b.cleanup();
        assert!(!b.dir.exists());
        drop(b);
        assert!(!root_dir.exists());
        fs::remove_dir(base).unwrap();
    }

    #[test]
    fn rejects_shared_symlink_and_wrong_owner() {
        let base = fixture();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SocketRoot::under(&base).is_err());
        assert!(directory(&base).is_err());
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.join("link");
        symlink(&base, &link).unwrap();
        assert!(private(&link).is_err());
        assert!(directory(&link).is_err());
        // Exercise ownership without needing chown privileges.
        assert!(private_for(&base, unsafe { libc::geteuid() } ^ 1).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn length_is_in_bytes_and_errors_name_the_path() {
        check(Path::new(&"x".repeat(107))).unwrap();
        for name in ["x".repeat(108), "é".repeat(54), "bad\0path".into()] {
            let error = check(Path::new(&name)).unwrap_err().to_string();
            assert!(error.contains(&name));
            assert!(error.contains("108"));
        }
        let base = fixture();
        let deep = base.join("x".repeat(80));
        directory(&deep).unwrap();
        assert!(SocketRoot::under(&deep).is_err());
        assert_eq!(fs::read_dir(&deep).unwrap().count(), 0);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn fallback_and_restart_mapping() {
        let base = fixture();
        let shared = base.join("shared");
        directory(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let fallback = base.join("private");
        let allowed = [shared.clone(), fallback.clone()];
        let root = SocketRoot::from_bases(&allowed).unwrap();
        assert_eq!(root.dir.parent().unwrap(), fallback);
        assert_eq!(fs::metadata(shared).unwrap().mode() & 0o777, 0o777);
        symlink(&root.dir, base.join("sockets")).unwrap();
        assert_eq!(mapped_root(&base, &allowed).unwrap(), Some(root.dir.clone()));
        assert!(previous(&base).is_err()); // Arbitrary mappings are refused.
        fs::set_permissions(&root.dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(mapped_root(&base, &allowed).is_err());
        fs::set_permissions(&root.dir, fs::Permissions::from_mode(0o700)).unwrap();
        drop(root);
        assert_eq!(mapped_root(&base, &allowed).unwrap(), None);
        fs::remove_dir_all(base).unwrap();
    }
}
