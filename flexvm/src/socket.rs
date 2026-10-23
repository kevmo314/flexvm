//! Short, private socket directories, independent of artifact and run paths.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::util::Result;

/// Take systemd's fd 3 once at startup; no child inherits it.
pub fn activated() -> Option<OwnedFd> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let n: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    (pid == std::process::id() && n >= 1 && unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } == 0).then(|| unsafe { OwnedFd::from_raw_fd(3) })
}

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

/// Bound at `private` (in a 0700 directory, so nobody else can connect while its mode is the
/// umask's), made 0600 there, then moved to `sock`: never reachable by others at any mode. Bound
/// through its directory's fd, so the private path is no longer than `sock` needs.
pub fn bind_private(private: &Path, sock: &Path) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::fd::AsRawFd;
    check(sock)?;
    let (dir, name) = (private.parent().unwrap_or(Path::new(".")), private.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?);
    let dir = fs::File::options().read(true).custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC).open(dir)?;
    let m = dir.metadata()?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(denied(private, "must be owned by this user and closed to group and others"));
    }
    // Held from the sweep until the socket is moved out: a `.PID.NS.sock` (`private_name`) seen under
    // it is no bind's in progress, only one a bind left behind, whatever its pid. An earlier build's
    // `.PID.sock` may be a bind of one from before this lock: it goes only once its pid is gone here
    // and it is older than any bind takes, as a pid alone cannot tell, its binder being perhaps of
    // another PID namespace sharing the directory, with that pid there (#1146).
    let _bind = crate::host::Flock::new(dir.try_clone()?, libc::LOCK_EX)?;
    let opened = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    for entry in fs::read_dir(&opened)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(owner) = name.to_str().and_then(|s| s.strip_prefix('.')?.strip_suffix(".sock")).and_then(crate::standby::sock_of) else {
            continue;
        };
        if !entry.file_type()?.is_socket() {
            continue;
        }
        let stale = match owner {
            (_, Some(_)) => true,
            (pid, None) => {
                let gone = libc::pid_t::try_from(pid)
                    .is_ok_and(|pid| pid > 0 && unsafe { libc::kill(pid, 0) } < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH));
                gone && crate::host::unwritten_for(&entry.path()).is_some_and(|a| a > STALE_BIND)
            }
        };
        if stale {
            let _ = fs::remove_file(entry.path());
        }
    }
    let short = opened.join(name);
    check(&short)?;
    let _ = fs::remove_file(&short);
    let listener = std::os::unix::net::UnixListener::bind(&short)?;
    let placed = fs::set_permissions(&short, fs::Permissions::from_mode(0o600)).and_then(|()| fs::rename(&short, sock));
    if placed.is_err() {
        let _ = fs::remove_file(&short);
    }
    placed.map(|()| listener)
}

/// Longer than an earlier build's bind ever lies at its private name, bound and not yet moved.
const STALE_BIND: std::time::Duration = std::time::Duration::from_secs(60);

/// This process's private name for `bind_private` in a directory its binds share: `.PID.NS.sock`, NS
/// its PID namespace in hex (`host::pid_ns`), as a standby's socket is named (`standby::sock_name`),
/// so binders of other namespaces with its pid never take it; `.PID.sock` where none can be read.
pub fn private_name() -> String {
    format!(".{}.sock", crate::standby::own_name())
}

/// Whether `c`'s peer is root or this process's user: one a 0600 socket would admit.
pub fn trusted_peer(c: &std::os::unix::net::UnixStream) -> bool {
    crate::util::peer_cred(c).is_ok_and(|cred| cred.uid == 0 || cred.uid == unsafe { libc::geteuid() })
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
    if !m.is_dir() || !crate::host::guarded(m.uid(), m.mode(), true) {
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

/// Named after the key and this process's PID namespace (`host::pid_ns`), so a process with the
/// same key finds what its predecessor left, and one in another PID namespace whose key reads the
/// same (a work directory `RUN/w/PID-START` under the same path, in a container with the same pid
/// and start time) never takes or removes this one's: the bases are shared by every host (#1084).
/// A key unique however pids read (a template build's staging directory, named by a nonce) is
/// named without (`SocketRoot::unique`), as every key was by earlier builds.
fn roots_in(bases: &[PathBuf], key: &Path, ns: Option<u64>) -> Vec<PathBuf> {
    let mut h = Sha256::new();
    h.update(key.as_os_str().as_bytes());
    if let Some(ns) = ns {
        // A path has no NUL: no key with one hashes as another without.
        h.update(format!("\0pidns:{ns}"));
    }
    let name: String = h.finalize()[..8].iter().map(|b| format!("{b:02x}")).collect();
    // Only under bases that are ours: anything else is not ours to trust or remove.
    bases.iter().filter(|b| private(b).is_ok()).map(|b| b.join(&name)).collect()
}

/// Their Firecrackers must be gone.
pub fn remove(key: &Path) {
    for dir in roots_in(&bases(), key, crate::host::pid_ns()) {
        let _ = fs::remove_dir_all(dir);
    }
}

/// Where `SocketRoot::new` records, in its key's directory, the root it made: the PID namespace
/// hashed into its name is its creator's, which a sweeper's need not be (a container restarted
/// with its run directory kept is in another).
pub const RECORD: &str = "sockets";

/// A dead owner's: the root its key's directory records (`RECORD`), as `remove` names it, as an
/// earlier build named it and as a unique key's is named (`SocketRoot::unique`): without a PID
/// namespace.
pub fn remove_left(key: &Path) {
    remove_left_in(&bases(), key);
}

fn remove_left_in(bases: &[PathBuf], key: &Path) {
    if let Some(dir) = recorded_root(bases, key) {
        let _ = fs::remove_dir_all(dir);
    }
    for dir in roots_in(bases, key, crate::host::pid_ns()).into_iter().chain(roots_in(bases, key, None)) {
        let _ = fs::remove_dir_all(dir);
    }
}

/// The root `key`'s record names, if it is one `roots_in` could have named: a hash-named
/// directory right under one of `bases` that is ours, never anything else a record may say. The
/// path returned is built from the base and the name, never the record's spelling (a trailing `/`
/// or `/.` would follow a link there), and is no symlink.
fn recorded_root(bases: &[PathBuf], key: &Path) -> Option<PathBuf> {
    let record = fs::read(key.join(RECORD)).ok()?;
    let slash = record.iter().rposition(|&b| b == b'/')?;
    let (parent, name) = (&record[..slash], &record[slash + 1..]);
    let hashed = name.len() == 16 && name.iter().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    let base = bases.iter().find(|b| b.as_os_str().as_bytes() == parent && private(b).is_ok())?;
    let dir = base.join(std::ffi::OsStr::from_bytes(name));
    (hashed && fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir())).then_some(dir)
}

/// One VM process or template build. Slots keep it alive until their cleanup.
pub struct SocketRoot {
    pub dir: PathBuf,
    next: AtomicU64,
}

impl SocketRoot {
    /// A process's, by a key that names it (`roots_in`): a directory of its own, which records
    /// the root (`RECORD`) for whoever sweeps it once the process is gone (`remove_left`).
    pub fn new(key: &Path) -> Result<Arc<Self>> {
        Self::recorded(&bases(), key, crate::host::pid_ns())
    }

    fn recorded(bases: &[PathBuf], key: &Path, ns: Option<u64>) -> Result<Arc<Self>> {
        let root = Self::from_bases(bases, key, ns)?;
        crate::util::write_file(key, RECORD, root.dir.as_os_str().as_bytes(), false)
            .map_err(|e| format!("recording socket directory {} in {}: {e}", root.dir.display(), key.display()))?;
        Ok(root)
    }

    /// By a key no other process has, in any PID namespace.
    pub fn unique(key: &Path) -> Result<Arc<Self>> {
        Self::from_bases(&bases(), key, None)
    }

    pub(crate) fn from_bases(bases: &[PathBuf], key: &Path, ns: Option<u64>) -> Result<Arc<Self>> {
        let mut errors = Vec::new();
        for base in bases {
            let attempt = (|| -> Result<Arc<Self>> {
                base_dir(base)?;
                let dir = roots_in(std::slice::from_ref(base), key, ns).remove(0);
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

    #[test]
    fn activation_checks_environment_and_sets_cloexec() {
        if let Ok(case) = std::env::var("FLEXVM_TEST_ACTIVATION") {
            let fd = super::activated();
            assert_eq!(fd.is_some(), case == "valid");
            if let Some(fd) = fd {
                use std::os::fd::AsRawFd;
                assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
            }
            return;
        }
        for (case, setup) in [
            ("valid", "LISTEN_PID=$$ LISTEN_FDS=1"),
            ("wrong-pid", "LISTEN_PID=0 LISTEN_FDS=1"),
            ("no-fds", "LISTEN_PID=$$ LISTEN_FDS=0"),
            ("invalid", "LISTEN_PID=$$ LISTEN_FDS=invalid"),
            ("missing", ""),
        ] {
            let script = format!("exec 3</dev/null; {setup} exec \"$0\" --exact socket::tests::activation_checks_environment_and_sets_cloexec --quiet");
            let status = std::process::Command::new("sh")
                .args(["-c", &script])
                .arg(std::env::current_exe().unwrap())
                .env_remove("LISTEN_PID")
                .env_remove("LISTEN_FDS")
                .env("FLEXVM_TEST_ACTIVATION", case)
                .status()
                .unwrap();
            assert!(status.success(), "{case}");
        }
    }

    fn fixture() -> crate::test_util::TempDir {
        // Leave room for the longest socket suffix regardless of TMPDIR's length.
        crate::test_util::TempDir::new_in(Path::new("/tmp"), "socket")
    }

    #[test]
    fn private_binds_need_only_a_short_destination() {
        let t = fixture();
        let deep = t.join("d".repeat(60)).join("e".repeat(60));
        DirBuilder::new().recursive(true).mode(0o700).create(&deep).unwrap();
        let private = deep.join(".1.sock");
        assert!(check(&private).is_err(), "longer than a socket path");
        let sock = t.join("c.sock");
        let _l = bind_private(&private, &sock).unwrap();
        assert_eq!(fs::metadata(&sock).unwrap().mode() & 0o777, 0o600);
        assert!(!private.exists());
        std::os::unix::net::UnixStream::connect(&sock).unwrap();
        // One that could not be connected to is never published.
        let long = deep.join("c.sock");
        assert_eq!(bind_private(&private, &long).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(!long.exists() && !private.exists());
    }

    #[test]
    fn private_bind_checks_directory_and_sweeps_dead_sockets() {
        let t = fixture();
        let dir = t.join("private");
        fs::create_dir(&dir).unwrap();
        let staging = dir.join(format!(".{}.sock", std::process::id()));
        let sock = t.join("c.sock");
        for mode in [0o720, 0o702, 0o750, 0o705] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(bind_private(&staging, &sock).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        // An earlier build's `.PID.sock`: judged by its pid here, and only once older than a bind.
        let dead = dir.join(".2147483647.sock");
        let fresh = dir.join(".2147483645.sock");
        let live = dir.join(format!(".{}.sock", std::process::id()));
        let plain = dir.join(".2147483646.sock");
        // `.PID.NS.sock`: a bind holding the lock made it, so one seen under it is left over, its pid alive or not.
        let left = [dir.join(format!(".{}.{:x}.sock", std::process::id(), 0xabcdefu64)), dir.join(".2147483647.1f.sock")];
        let other = dir.join(".1.2.3.sock");
        let _socks: Vec<_> = [&dead, &fresh, &live, &left[0], &left[1], &other].iter().map(|p| std::os::unix::net::UnixListener::bind(p).unwrap()).collect();
        for p in [&dead, &live] {
            let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
            let old = [libc::timespec { tv_sec: 1, tv_nsec: 0 }; 2];
            assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), old.as_ptr(), 0) }, 0);
        }
        fs::write(&plain, b"keep").unwrap();
        let _l = bind_private(&dir.join("staging"), &sock).unwrap();
        assert!(!dead.exists() && !left[0].exists() && !left[1].exists());
        assert!(live.exists() && plain.exists() && fresh.exists() && other.exists());
    }

    #[test]
    fn private_names_name_the_pid_namespace() {
        let name = private_name();
        let stem = name.strip_prefix('.').and_then(|n| n.strip_suffix(".sock")).unwrap();
        assert_eq!(crate::standby::sock_of(stem), Some((std::process::id(), crate::host::pid_ns())));
    }

    #[test]
    fn private_binds_wait_for_one_in_progress() {
        use crate::test_util::JoinWithin;
        let t = fixture();
        let dir = t.join("private");
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        // As a bind in progress holds it: a sweep then must not see its socket, nor a bind start.
        let held = crate::host::Flock::new(fs::File::open(&dir).unwrap(), libc::LOCK_EX).unwrap();
        let (staging, sock) = (dir.join(".1.sock"), t.join("c.sock"));
        let bind = std::thread::spawn(move || bind_private(&staging, &sock).map(drop));
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!bind.is_finished() && !t.join("c.sock").exists(), "bound with the directory locked");
        drop(held);
        bind.join_within().unwrap().unwrap();
        assert!(t.join("c.sock").exists());
    }

    #[test]
    fn short_paths_cleanup_and_restart() {
        let t = fixture();
        let bases = [t.join("s")];
        let key = Path::new(&"/very/deep/run".repeat(20)).to_path_buf();
        let root = SocketRoot::from_bases(&bases, &key, None).unwrap();
        assert_eq!(roots_in(&bases, &key, None), [root.dir.clone()]);
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
        let again = SocketRoot::from_bases(&bases, &key, None).unwrap();
        assert!(!b.dir.exists());
        drop(again);
        drop(b);
        assert_eq!(fs::read_dir(&bases[0]).unwrap().count(), 0);
    }

    /// #1084: a process of another PID namespace whose key reads the same (its work directory under
    /// the same run path, the same pid and start time there) has a root of its own, which a restart
    /// here never replaces; a unique key's is named as earlier builds named every one.
    #[test]
    fn roots_of_other_pid_namespaces_are_apart() {
        let t = fixture();
        let bases = [t.join("s")];
        let key = t.join("run/w/42-7");
        let theirs = SocketRoot::from_bases(&bases, &key, Some(1)).unwrap();
        let ours = SocketRoot::from_bases(&bases, &key, Some(2)).unwrap();
        let old = SocketRoot::from_bases(&bases, &key, None).unwrap();
        assert!(theirs.dir != ours.dir && ours.dir != old.dir && theirs.dir != old.dir);
        let again = SocketRoot::from_bases(&bases, &key, Some(2)).unwrap();
        assert_eq!(again.dir, ours.dir);
        assert!(theirs.dir.is_dir() && old.dir.is_dir(), "a restart replaces only its own");
        assert_eq!(roots_in(&bases, &key, Some(1)), [theirs.dir.clone()]);
        // With this process's namespace, as `new` and `remove` name them.
        let ns = crate::host::pid_ns();
        assert!(ns.is_some());
        assert_eq!(roots_in(&bases, &key, ns), roots_in(&bases, &key, ns));
        assert_ne!(roots_in(&bases, &key, ns), roots_in(&bases, &key, None));
    }

    /// A root is removed by its key's record whatever PID namespace made it: a container restarted
    /// with its run directory kept sweeps its predecessor's from another namespace. A record naming
    /// anything but a root under the bases is never followed.
    #[test]
    fn a_dead_owners_root_goes_by_its_record_from_any_namespace() {
        let t = fixture();
        let bases = [t.join("s")];
        let key = t.join("run/w/42-7");
        DirBuilder::new().recursive(true).mode(0o700).create(&key).unwrap();
        let other = crate::host::pid_ns().unwrap() + 1;
        let root = SocketRoot::recorded(&bases, &key, Some(other)).unwrap();
        let dir = root.dir.clone();
        assert_eq!(fs::read(key.join(RECORD)).unwrap(), dir.as_os_str().as_bytes());
        assert!(!roots_in(&bases, &key, crate::host::pid_ns()).contains(&dir) && !roots_in(&bases, &key, None).contains(&dir));
        std::mem::forget(root);
        remove_left_in(&bases, &key);
        assert!(!dir.exists(), "removed by its record, not by this namespace's name");
        // Earlier builds' and this namespace's names go without a record.
        fs::remove_file(key.join(RECORD)).unwrap();
        let (old, ours) = (SocketRoot::from_bases(&bases, &key, None).unwrap(), SocketRoot::from_bases(&bases, &key, crate::host::pid_ns()).unwrap());
        let (old_dir, our_dir) = (old.dir.clone(), ours.dir.clone());
        std::mem::forget((old, ours));
        remove_left_in(&bases, &key);
        assert!(!old_dir.exists() && !our_dir.exists());
        // A record naming anything else is not followed.
        let decoys = [t.join("decoy"), bases[0].join("not-a-hash"), t.join("elsewhere/0123456789abcdef")];
        for decoy in &decoys {
            DirBuilder::new().recursive(true).create(decoy).unwrap();
            fs::write(key.join(RECORD), decoy.as_os_str().as_bytes()).unwrap();
            remove_left_in(&bases, &key);
            assert!(decoy.exists(), "{}", decoy.display());
        }
        // Nor a hash-named link out of the bases, however the record spells it: a trailing `/` or
        // `/.` would have the removal follow it.
        let outside = t.join("outside");
        DirBuilder::new().create(&outside).unwrap();
        fs::write(outside.join("precious"), b"keep").unwrap();
        let link = bases[0].join("0123456789abcdef");
        symlink(&outside, &link).unwrap();
        let spelled = link.as_os_str().as_bytes();
        for record in [spelled.to_vec(), [spelled, b"/"].concat(), [spelled, b"/."].concat(), [spelled, b"//"].concat()] {
            fs::write(key.join(RECORD), &record).unwrap();
            assert_eq!(recorded_root(&bases, &key), None, "{:?}", String::from_utf8_lossy(&record));
            remove_left_in(&bases, &key);
            assert!(outside.join("precious").exists() && link.is_symlink(), "{:?}", String::from_utf8_lossy(&record));
        }
        // A real root recorded with a trailing separator is not taken either (no spelling but its own).
        fs::remove_file(&link).unwrap();
        DirBuilder::new().mode(0o700).create(&link).unwrap();
        fs::write(key.join(RECORD), [spelled, b"/"].concat()).unwrap();
        assert_eq!(recorded_root(&bases, &key), None);
        fs::write(key.join(RECORD), spelled).unwrap();
        assert_eq!(recorded_root(&bases, &key), Some(link.clone()));
        remove_left_in(&bases, &key);
        assert!(!link.exists());
    }

    #[test]
    fn a_missing_parent_is_made_0755_or_the_fallback_is_used() {
        let t = fixture();
        let parent = t.join("run");
        let root = SocketRoot::from_bases(&[parent.join("s"), t.join("fallback")], &t, None).unwrap();
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, 0o755);
        assert_eq!(root.dir.parent().unwrap(), parent.join("s"));
        drop(root);
        // A parent this user cannot make (root can make anything).
        let closed = t.join("closed");
        DirBuilder::new().mode(0o555).create(&closed).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            let root = SocketRoot::from_bases(&[closed.join("run/s"), t.join("fallback")], &t, None).unwrap();
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
            assert!(SocketRoot::from_bases(&[base.clone()], &t, None).is_err(), "{}", base.display());
            assert!(roots_in(&[base], &t, None).is_empty());
        }
        assert_eq!(fs::read_dir(&shared).unwrap().count(), 0);
        let root = SocketRoot::from_bases(&[shared.clone(), t.join("ok")], &t, None).unwrap();
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
        let e = SocketRoot::from_bases(&[deep.clone()], &t, None).err().unwrap().to_string();
        assert!(e.contains("108"), "{e}");
        assert_eq!(fs::read_dir(&deep).unwrap().count(), 0);
    }
}
