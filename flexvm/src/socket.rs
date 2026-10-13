//! Short, private socket directories, independent of artifact and run paths.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};

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

fn denied(path: &Path, what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("socket directory {}: {what}", path.display()))
}

/// A real directory (not a symlink) owned by us with mode 0700.
fn private(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
        return Err(denied(path, "must be a real directory owned by this user with mode 0700"));
    }
    Ok(())
}

/// Creates `base` as a private directory, or checks the one that is there.
/// Its parent must be one only root or we can rename it out of (sticky
/// directories like /tmp included), so nobody can swap it later.
fn base_dir(base: &Path) -> io::Result<()> {
    let parent = base.parent().unwrap();
    let _ = DirBuilder::new().mode(0o700).create(parent);
    let m = fs::symlink_metadata(parent)?;
    let euid = unsafe { libc::geteuid() };
    if !m.is_dir() || (m.uid() != 0 && m.uid() != euid) || (m.mode() & 0o022 != 0 && m.mode() & libc::S_ISVTX == 0) {
        return Err(denied(parent, "must be a real directory that only root or this user can change"));
    }
    match DirBuilder::new().mode(0o700).create(base) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    private(base)
}

fn bases() -> [PathBuf; 2] {
    [PathBuf::from("/run/flexvm/s"), PathBuf::from(format!("/tmp/flexvm-s-{}", unsafe { libc::geteuid() }))]
}

/// The socket root a `SocketRoot::new(key)` would use under each base. Named
/// after the key, so a restarted daemon finds what its predecessor left.
pub fn roots(key: &Path) -> Vec<PathBuf> {
    roots_in(&bases(), key)
}

fn roots_in(bases: &[PathBuf], key: &Path) -> Vec<PathBuf> {
    let h = Sha256::digest(key.as_os_str().as_bytes());
    let name: String = h[..8].iter().map(|b| format!("{b:02x}")).collect();
    // Only under bases that are ours: anything else is not ours to trust or remove.
    bases.iter().filter(|b| private(b).is_ok()).map(|b| b.join(&name)).collect()
}

/// Removes every socket root of `key`; their Firecrackers must be gone.
pub fn remove(key: &Path) {
    for dir in roots(key) {
        let _ = fs::remove_dir_all(dir);
    }
}

/// One daemon or template build. Slots keep it alive until their cleanup.
pub struct SocketRoot {
    pub dir: PathBuf,
    next: AtomicU64,
}

impl SocketRoot {
    /// A fresh root for `key` (the daemon's canonical run directory, or a
    /// template build's directory), replacing a stale one of the same key.
    pub fn new(key: &Path) -> Result<Arc<Self>> {
        Self::from_bases(&bases(), key)
    }

    fn from_bases(bases: &[PathBuf], key: &Path) -> Result<Arc<Self>> {
        let mut errors = Vec::new();
        for base in bases {
            let attempt = (|| -> Result<Arc<Self>> {
                base_dir(base)?;
                let dir = roots_in(std::slice::from_ref(base), key).remove(0);
                // The longest slot and Firecracker's vsock port suffix.
                check(&dir.join("ffffffffffffffff/v.sock_4294967295"))?;
                let _ = fs::remove_dir_all(&dir);
                DirBuilder::new().mode(0o700).create(&dir)?;
                Ok(Arc::new(Self { dir, next: AtomicU64::new(0) }))
            })();
            match attempt {
                Ok(root) => return Ok(root),
                Err(e) => errors.push(format!("{}: {e}", base.display())),
            }
        }
        Err(format!("cannot create a private socket directory: {}", errors.join("; ")).into())
    }

    pub fn allocate(self: &Arc<Self>) -> Result<Sockets> {
        let dir = self.dir.join(format!("{:x}", self.next.fetch_add(1, Ordering::Relaxed)));
        DirBuilder::new().mode(0o700).create(&dir)?;
        let at = |name| dir.join(name);
        Ok(Sockets { api: at("api.sock"), vsock: at("v.sock"), uffd: at("uffd.sock"), dir, _root: self.clone() })
    }
}

impl Drop for SocketRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.dir);
    }
}

/// One Firecracker's sockets; removing the directory also removes its vsock port UDSes.
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
        let base = std::env::temp_dir().join(format!("fvs-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        DirBuilder::new().mode(0o700).create(&base).unwrap();
        base
    }

    #[test]
    fn short_paths_cleanup_and_restart() {
        let t = fixture();
        let bases = [t.join("s")];
        let key = Path::new(&"/very/deep/run".repeat(20)).to_path_buf();
        let root = SocketRoot::from_bases(&bases, &key).unwrap();
        assert_eq!(roots_in(&bases, &key), [root.dir.clone()]);
        private(&root.dir).unwrap();
        let a = root.allocate().unwrap();
        root.next.store(u64::MAX, Ordering::Relaxed);
        let b = root.allocate().unwrap();
        for s in [&a, &b] {
            private(&s.dir).unwrap();
            for path in [&s.api, &s.vsock, &s.uffd, &s.dir.join("v.sock_4294967295")] {
                check(path).unwrap();
                fs::write(path, b"").unwrap();
            }
        }
        drop(root);
        let dir = a.dir.clone();
        drop(a);
        assert!(!dir.exists() && b.dir.exists());
        // A restart with the same key replaces what is left.
        let again = SocketRoot::from_bases(&bases, &key).unwrap();
        assert!(!b.dir.exists());
        drop(again);
        drop(b);
        assert_eq!(fs::read_dir(&bases[0]).unwrap().count(), 0);
        fs::remove_dir_all(t).unwrap();
    }

    #[test]
    fn refuses_shared_symlinked_or_foreign_bases() {
        let t = fixture();
        let shared = t.join("shared");
        DirBuilder::new().mode(0o777).create(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        symlink(&t, t.join("link")).unwrap();
        // A base inside a directory others can write, a shared base, a symlinked base.
        for base in [shared.join("s"), shared.clone(), t.join("link")] {
            assert!(SocketRoot::from_bases(&[base.clone()], &t).is_err(), "{}", base.display());
            assert!(roots_in(&[base], &t).is_empty());
        }
        assert_eq!(fs::read_dir(&shared).unwrap().count(), 0);
        // Falls back to the next base.
        let root = SocketRoot::from_bases(&[shared.clone(), t.join("ok")], &t).unwrap();
        assert_eq!(root.dir.parent().unwrap(), t.join("ok"));
        drop(root);
        fs::remove_dir_all(t).unwrap();
    }

    #[test]
    fn length_is_in_bytes_and_errors_name_the_path() {
        check(Path::new(&"x".repeat(107))).unwrap();
        for name in ["x".repeat(108), "é".repeat(54), "bad\0path".into()] {
            let error = check(Path::new(&name)).unwrap_err().to_string();
            assert!(error.contains(&name) && error.contains("108"));
        }
        let t = fixture();
        let deep = t.join("x".repeat(80));
        let e = SocketRoot::from_bases(&[deep.clone()], &t).err().unwrap().to_string();
        assert!(e.contains("108"), "{e}");
        assert_eq!(fs::read_dir(&deep).unwrap().count(), 0);
        fs::remove_dir_all(t).unwrap();
    }
}
