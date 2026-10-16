//! Short, private socket directories, independent of artifact and run paths.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::util::Result;

/// Linux sun_path includes the terminating NUL.
pub fn check(path: &Path) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unix socket path {} ({} bytes) must be shorter than 108 bytes and contain no NUL", path.display(), bytes.len()),
        ));
    }
    Ok(())
}

fn denied(path: &Path, what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("socket directory {}: {what}", path.display()))
}

fn private(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
        return Err(denied(path, "must be a real directory owned by this user with mode 0700"));
    }
    Ok(())
}

/// Its parent must be one only root or we can rename it out of (sticky /tmp included), so
/// nobody can swap it later. It is made 0755 whatever the umask, when this user can (root, for
/// /run/flexvm): it is also the default run directory, which non-root users read, and root then
/// never needs the /tmp base, whose name anyone can take first.
fn base_dir(base: &Path) -> io::Result<()> {
    let parent = base.parent().unwrap();
    if DirBuilder::new().mode(0o755).create(parent).is_ok() {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
    }
    let m = fs::symlink_metadata(parent)?;
    let euid = unsafe { libc::geteuid() };
    if !m.is_dir() || (m.uid() != 0 && m.uid() != euid) || (m.mode() & 0o022 != 0 && m.mode() & libc::S_ISVTX == 0) {
        return Err(denied(parent, "must be a real directory that only root or this user can change"));
    }
    match DirBuilder::new().mode(0o700).create(base) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
        _ => private(base),
    }
}

fn bases() -> [PathBuf; 2] {
    [PathBuf::from("/run/flexvm/s"), PathBuf::from(format!("/tmp/flexvm-s-{}", unsafe { libc::geteuid() }))]
}

/// Named after the key, so a process with the same key finds what its predecessor left.
fn roots_in(bases: &[PathBuf], key: &Path) -> Vec<PathBuf> {
    let h = Sha256::digest(key.as_os_str().as_bytes());
    let name: String = h[..8].iter().map(|b| format!("{b:02x}")).collect();
    // Only under bases that are ours: anything else is not ours to trust or remove.
    bases.iter().filter(|b| private(b).is_ok()).map(|b| b.join(&name)).collect()
}

/// Their Firecrackers must be gone.
pub fn remove(key: &Path) {
    for dir in roots_in(&bases(), key) {
        let _ = fs::remove_dir_all(dir);
    }
}

/// One VM process or template build. Slots keep it alive until their cleanup.
pub struct SocketRoot {
    pub dir: PathBuf,
    next: AtomicU64,
}

impl SocketRoot {
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

impl Drop for Sockets {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture() -> crate::test_util::TempDir {
        // Leave room for the longest socket suffix regardless of TMPDIR's length.
        crate::test_util::TempDir::new_in(Path::new("/tmp"), "socket")
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
    }

    #[test]
    fn a_missing_parent_is_made_0755_or_the_fallback_is_used() {
        let t = fixture();
        let parent = t.join("run");
        let root = SocketRoot::from_bases(&[parent.join("s"), t.join("fallback")], &t).unwrap();
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, 0o755);
        assert_eq!(root.dir.parent().unwrap(), parent.join("s"));
        drop(root);
        // A parent this user cannot make (root can make anything).
        let closed = t.join("closed");
        DirBuilder::new().mode(0o555).create(&closed).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            let root = SocketRoot::from_bases(&[closed.join("run/s"), t.join("fallback")], &t).unwrap();
            assert!(!closed.join("run").exists());
            assert_eq!(root.dir.parent().unwrap(), t.join("fallback"));
        }
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();
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
        let root = SocketRoot::from_bases(&[shared.clone(), t.join("ok")], &t).unwrap();
        assert_eq!(root.dir.parent().unwrap(), t.join("ok"));
        drop(root);
    }

    #[test]
    fn length_is_in_bytes_and_errors_name_the_path() {
        check(Path::new(&"x".repeat(107))).unwrap();
        for name in ["x".repeat(108), "é".repeat(54), "bad\0path".into()] {
            let error = check(Path::new(&name)).unwrap_err().to_string();
            assert!(error.contains(&name) && error.contains(&format!("{} bytes", name.len())) && error.contains("108"));
        }
        let t = fixture();
        let deep = t.join("x".repeat(80));
        let e = SocketRoot::from_bases(&[deep.clone()], &t).err().unwrap().to_string();
        assert!(e.contains("108"), "{e}");
        assert_eq!(fs::read_dir(&deep).unwrap().count(), 0);
    }
}
