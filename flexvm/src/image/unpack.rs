//! Applies image layers to a directory, as root, the way a container runtime
//! does: whiteouts and opaque directories, ownership, modes, xattrs, device
//! nodes, symlinks and hard links.
//!
//! Every path is resolved with `openat2(RESOLVE_IN_ROOT)`, so symlinks in the
//! image (absolute ones included) resolve inside the image and a layer can
//! never write outside it. Operations then act on a final component inside a
//! resolved parent directory, never following it.

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::bail;
use crate::util::Result;

pub struct Root {
    fd: OwnedFd,
    /// Entries written so far, to size the filesystem's inode table.
    pub entries: u64,
}

fn cpath(p: &Path) -> Result<CString> {
    Ok(CString::new(p.as_os_str().as_bytes()).map_err(|_| format!("NUL in path {p:?}"))?)
}

fn check(rc: libc::c_int, what: &str, path: &Path) -> Result<()> {
    if rc < 0 {
        bail!("{what} {path:?}: {}", io::Error::last_os_error());
    }
    Ok(())
}

/// Splits a path from a layer into normal components; `None` for the root itself.
fn normalize(p: &Path) -> Result<Option<(PathBuf, CString)>> {
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => parts.push(n),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir => bail!("layer path {p:?} contains '..'"),
            Component::Prefix(_) => bail!("bad layer path {p:?}"),
        }
    }
    let Some(name) = parts.pop() else { return Ok(None) };
    Ok(Some((parts.iter().collect(), CString::new(name.as_bytes()).map_err(|_| "NUL in path")?)))
}

/// Joins `..` lexically, clamped at the root, as resolution inside a root does.
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out
}

/// A resolved parent directory and the final component inside it.
struct At {
    dir: OwnedFd,
    name: CString,
}

impl At {
    /// `/proc/self/fd/N/name`: lets path-based calls act on the entry without
    /// re-resolving its parent.
    fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.dir.as_raw_fd())).join(std::ffi::OsStr::from_bytes(self.name.as_bytes()))
    }

    fn lstat(&self) -> Option<libc::stat> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstatat(self.dir.as_raw_fd(), self.name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        (rc == 0).then_some(st)
    }

    fn is_dir(&self) -> bool {
        self.lstat().is_some_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR)
    }

    /// Removes whatever is there, recursively.
    fn remove(&self) -> Result<()> {
        if self.is_dir() {
            std::fs::remove_dir_all(self.proc_path()).map_err(|e| format!("remove {:?}: {e}", self.name))?;
        } else if self.lstat().is_some() {
            check(unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0) }, "unlink", Path::new(""))?;
        }
        Ok(())
    }
}

impl Root {
    pub fn open(dir: &Path) -> Result<Root> {
        let fd = unsafe { libc::open(cpath(dir)?.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        check(fd, "open", dir)?;
        Ok(Root { fd: unsafe { OwnedFd::from_raw_fd(fd) }, entries: 0 })
    }

    /// Opens `rel` (a directory path inside the root) with symlinks resolved in the root.
    fn resolve(&self, rel: &Path) -> io::Result<OwnedFd> {
        let path = CString::new(if rel.as_os_str().is_empty() { b".".as_slice() } else { rel.as_os_str().as_bytes() })
            .map_err(|_| io::Error::other("NUL in path"))?;
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
        how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
        let fd = unsafe {
            libc::syscall(libc::SYS_openat2, self.fd.as_raw_fd(), path.as_ptr(), &how, std::mem::size_of::<libc::open_how>())
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    /// Resolves directory `rel`, creating missing directories (root, 0755).
    fn mkdir_p(&mut self, rel: &Path) -> Result<OwnedFd> {
        self.mkdir_p_depth(rel, 0)
    }

    fn mkdir_p_depth(&mut self, rel: &Path, depth: u32) -> Result<OwnedFd> {
        if depth > 40 {
            bail!("too many levels of symbolic links creating {rel:?}");
        }
        match self.resolve(rel) {
            Ok(fd) => return Ok(fd),
            Err(e) if e.raw_os_error() != Some(libc::ENOENT) => bail!("resolve {rel:?}: {e}"),
            Err(_) => {}
        }
        let mut cur = PathBuf::new();
        let mut fd = self.resolve(&cur)?;
        for c in rel.components() {
            let name = CString::new(c.as_os_str().as_bytes()).map_err(|_| "NUL in path")?;
            cur.push(c);
            fd = match self.resolve(&cur) {
                Ok(next) => next,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    if unsafe { libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o755) } == 0 {
                        self.entries += 1;
                        self.resolve(&cur)?
                    } else {
                        // A dangling symlink (say var/run -> /run before run exists):
                        // create its target, as container runtimes do.
                        let mut buf = vec![0u8; 4096];
                        let n = unsafe { libc::readlinkat(fd.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
                        if n < 0 {
                            bail!("mkdir {cur:?}: {}", io::Error::last_os_error());
                        }
                        let target = Path::new(std::ffi::OsStr::from_bytes(&buf[..n as usize]));
                        let base = if target.is_absolute() { PathBuf::new() } else { cur.parent().unwrap().to_path_buf() };
                        self.mkdir_p_depth(&lexical(&base.join(target)), depth + 1)?;
                        self.resolve(&cur)?
                    }
                }
                Err(e) => bail!("resolve {cur:?}: {e}"),
            };
        }
        Ok(fd)
    }

    fn at(&mut self, path: &Path) -> Result<Option<At>> {
        let Some((parent, name)) = normalize(path)? else { return Ok(None) };
        Ok(Some(At { dir: self.mkdir_p(&parent)?, name }))
    }

    /// Applies one (decompressed) layer tarball.
    pub fn apply_layer(&mut self, layer: impl Read) -> Result<()> {
        let mut ar = tar::Archive::new(layer);
        // Paths this layer wrote; an opaque directory keeps only these.
        let mut mine: HashSet<PathBuf> = HashSet::new();
        for entry in ar.entries()? {
            let mut e = entry?;
            let path = e.path()?.into_owned();
            let Some((parent, name)) = normalize(&path)? else {
                // The root directory itself: keep ours.
                continue;
            };
            let name_bytes = name.as_bytes();
            if name_bytes == b".wh..wh..opq" {
                self.make_opaque(&parent, &mine)?;
                continue;
            }
            if let Some(hidden) = name_bytes.strip_prefix(b".wh.") {
                if let Ok(dir) = self.resolve(&parent) {
                    let at = At { dir, name: CString::new(hidden).unwrap() };
                    at.remove()?;
                }
                continue;
            }
            let rel = parent.join(std::ffi::OsStr::from_bytes(name_bytes));
            self.entry(&mut e, &rel)?;
            mine.insert(rel);
        }
        Ok(())
    }

    /// Removes everything under `dir` that lower layers put there.
    fn make_opaque(&mut self, dir: &Path, mine: &HashSet<PathBuf>) -> Result<()> {
        let Ok(fd) = self.resolve(dir) else { return Ok(()) };
        let listing = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
        for child in std::fs::read_dir(&listing)? {
            let child = child?;
            let rel = dir.join(child.file_name());
            if mine.contains(&rel) && child.file_type()?.is_dir() {
                self.make_opaque(&rel, mine)?;
            } else if !mine.contains(&rel) {
                let at = At { dir: self.resolve(dir)?, name: CString::new(child.file_name().as_bytes()).unwrap() };
                at.remove()?;
            }
        }
        Ok(())
    }

    fn entry<R: Read>(&mut self, e: &mut tar::Entry<R>, rel: &Path) -> Result<()> {
        use tar::EntryType as T;
        let h = e.header().clone();
        let kind = h.entry_type();
        let mut uid = h.uid()? as u32;
        let mut gid = h.gid()? as u32;
        let mode = h.mode()? & 0o7777;
        let mtime = h.mtime().unwrap_or(0) as i64;
        let mut xattrs = Vec::new();
        if let Some(pax) = e.pax_extensions()? {
            for ext in pax {
                let ext = ext?;
                let key = ext.key().map_err(|_| "bad pax key")?;
                if let Some(x) = key.strip_prefix("SCHILY.xattr.") {
                    xattrs.push((x.to_string(), ext.value_bytes().to_vec()));
                } else if key == "uid" {
                    uid = ext.value().ok().and_then(|v| v.parse().ok()).unwrap_or(uid);
                } else if key == "gid" {
                    gid = ext.value().ok().and_then(|v| v.parse().ok()).unwrap_or(gid);
                }
            }
        }
        let at = self.at(rel)?.ok_or("empty path")?;
        let (dfd, name) = (at.dir.as_raw_fd(), at.name.as_ptr());
        match kind {
            T::Directory => {
                if !at.is_dir() {
                    at.remove()?;
                    check(unsafe { libc::mkdirat(dfd, name, 0o700) }, "mkdir", rel)?;
                }
            }
            T::Regular | T::Continuous => {
                at.remove()?;
                let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
                let fd = unsafe { libc::openat(dfd, name, flags, 0o600) };
                check(fd, "create", rel)?;
                let mut f = unsafe { File::from_raw_fd(fd) };
                io::copy(e, &mut f).map_err(|err| format!("write {rel:?}: {err}"))?;
            }
            T::Symlink => {
                let target = e.link_name()?.ok_or("symlink without target")?;
                at.remove()?;
                check(unsafe { libc::symlinkat(cpath(&target)?.as_ptr(), dfd, name) }, "symlink", rel)?;
            }
            T::Link => {
                let target = e.link_name()?.ok_or("hard link without target")?;
                let src = self.at(&target)?.ok_or("hard link to the root")?;
                if let (Some(a), Some(b)) = (src.lstat(), at.lstat()) {
                    if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) {
                        return Ok(());
                    }
                }
                at.remove()?;
                let rc = unsafe { libc::linkat(src.dir.as_raw_fd(), src.name.as_ptr(), dfd, name, 0) };
                check(rc, "link", rel)?;
                // A hard link shares its target's inode and metadata.
                self.entries += 1;
                return Ok(());
            }
            T::Char | T::Block | T::Fifo => {
                at.remove()?;
                let fmt = match kind {
                    T::Char => libc::S_IFCHR,
                    T::Block => libc::S_IFBLK,
                    _ => libc::S_IFIFO,
                };
                let dev = libc::makedev(h.device_major()?.unwrap_or(0), h.device_minor()?.unwrap_or(0));
                check(unsafe { libc::mknodat(dfd, name, fmt | 0o600, dev) }, "mknod", rel)?;
            }
            // Global PAX headers and the like carry nothing to apply.
            T::XGlobalHeader | T::XHeader | T::GNULongName | T::GNULongLink => return Ok(()),
            other => bail!("unsupported tar entry type {other:?} at {rel:?}"),
        }
        self.entries += 1;
        let nofollow = libc::AT_SYMLINK_NOFOLLOW;
        check(unsafe { libc::fchownat(dfd, name, uid, gid, nofollow) }, "chown", rel)?;
        if kind != T::Symlink {
            // After chown, which clears setuid/setgid bits.
            check(unsafe { libc::fchmodat(dfd, name, mode, 0) }, "chmod", rel)?;
        }
        for (key, value) in &xattrs {
            let (p, k) = (cpath(&at.proc_path())?, CString::new(key.as_str()).map_err(|_| "NUL in xattr")?);
            let rc = unsafe { libc::lsetxattr(p.as_ptr(), k.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
            if rc < 0 {
                eprintln!("image: xattr {key} on {rel:?}: {}", io::Error::last_os_error());
            }
        }
        let ts = [libc::timespec { tv_sec: mtime, tv_nsec: 0 }; 2];
        unsafe { libc::utimensat(dfd, name, ts.as_ptr(), nofollow) };
        Ok(())
    }

    /// Creates directory `rel` (and parents) if missing, with `mode` if new.
    pub fn ensure_dir(&mut self, rel: &str, mode: u32) -> Result<()> {
        let at = self.at(Path::new(rel))?.ok_or("empty path")?;
        if at.lstat().is_none() {
            let (dfd, name) = (at.dir.as_raw_fd(), at.name.as_ptr());
            check(unsafe { libc::mkdirat(dfd, name, 0o700) }, "mkdir", Path::new(rel))?;
            check(unsafe { libc::fchmodat(dfd, name, mode, 0) }, "chmod", Path::new(rel))?;
            self.entries += 1;
        }
        Ok(())
    }

    /// Replaces `rel` with a root-owned regular file.
    pub fn write_file(&mut self, rel: &str, data: &[u8], mode: u32) -> Result<()> {
        let at = self.at(Path::new(rel))?.ok_or("empty path")?;
        at.remove()?;
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(at.dir.as_raw_fd(), at.name.as_ptr(), flags, 0o600) };
        check(fd, "create", Path::new(rel))?;
        let mut f = unsafe { File::from_raw_fd(fd) };
        f.write_all(data)?;
        check(unsafe { libc::fchmod(f.as_raw_fd(), mode) }, "chmod", Path::new(rel))?;
        self.entries += 1;
        Ok(())
    }

    /// Whether `rel` is a regular file (not following a final symlink).
    pub fn is_file(&mut self, rel: &str) -> bool {
        let Ok(Some(at)) = normalize(Path::new(rel)) else { return false };
        let Ok(dir) = self.resolve(&at.0) else { return false };
        let at = At { dir, name: at.1 };
        at.lstat().is_some_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG)
    }

    /// Reads a file inside the root, following symlinks within it.
    pub fn read(&self, rel: &str) -> Option<Vec<u8>> {
        let path = CString::new(rel.trim_start_matches('/')).ok()?;
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (libc::O_RDONLY | libc::O_CLOEXEC) as u64;
        how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
        let fd = unsafe {
            libc::syscall(libc::SYS_openat2, self.fd.as_raw_fd(), path.as_ptr(), &how, std::mem::size_of::<libc::open_how>())
        };
        if fd < 0 {
            return None;
        }
        let mut data = Vec::new();
        BufReader::new(unsafe { File::from_raw_fd(fd as i32) }).take(16 << 20).read_to_end(&mut data).ok()?;
        Some(data)
    }
}

/// Wraps a layer blob in the decompressor its magic bytes call for.
pub fn decompress(r: impl Read + 'static) -> Result<Box<dyn Read>> {
    let mut r = BufReader::with_capacity(256 << 10, r);
    let magic = r.fill_buf()?.get(..4).map(|m| m.to_vec()).unwrap_or_default();
    Ok(match magic.as_slice() {
        [0x1f, 0x8b, ..] => Box::new(flate2::read::MultiGzDecoder::new(r)),
        [0x28, 0xb5, 0x2f, 0xfd] => Box::new(
            ruzstd::decoding::StreamingDecoder::new(r).map_err(|e| format!("zstd layer: {e}"))?,
        ),
        _ => Box::new(r),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layer of (path, kind, data or link target).
    fn layer(entries: &[(&str, char, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let (uid, gid) = unsafe { (libc::getuid() as u64, libc::getgid() as u64) };
        for &(path, kind, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_uid(uid);
            h.set_gid(gid);
            h.set_mtime(1);
            match kind {
                'd' => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_mode(0o755);
                    h.set_size(0);
                    b.append_data(&mut h, path, io::empty()).unwrap();
                }
                'f' => {
                    h.set_mode(0o4755);
                    h.set_size(data.len() as u64);
                    b.append_data(&mut h, path, data.as_bytes()).unwrap();
                }
                'l' | 'h' => {
                    h.set_entry_type(if kind == 'l' { tar::EntryType::Symlink } else { tar::EntryType::Link });
                    h.set_mode(0o777);
                    h.set_size(0);
                    b.append_link(&mut h, path, data).unwrap();
                }
                _ => unreachable!(),
            }
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn layers_whiteouts_and_symlinks() {
        let dir = std::env::temp_dir().join(format!("flexvm-unpack-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut root = Root::open(&dir).unwrap();
        let lower = layer(&[
            ("a/", 'd', ""),
            ("a/x", 'f', "x"),
            ("a/sub/y", 'f', "y"),
            ("b/z", 'f', "z"),
            ("c", 'f', "c"),
            ("abs", 'l', "/a"),
            ("var/run", 'l', "/run"),
        ]);
        root.apply_layer(&lower[..]).unwrap();
        let upper = layer(&[
            ("a/kept", 'f', "kept"),
            ("a/.wh..wh..opq", 'f', ""),
            ("a/new", 'f', "new"),
            ("b/.wh.z", 'f', ""),
            (".wh.c", 'f', ""),
            // Through an absolute symlink: must land inside the root.
            ("abs/through", 'f', "t"),
            // Through a dangling one: creates its target.
            ("var/run/pid", 'f', "1"),
            ("hard", 'h', "a/new"),
        ]);
        root.apply_layer(&upper[..]).unwrap();
        let read = |p: &str| std::fs::read_to_string(dir.join(p)).ok();
        assert_eq!(read("a/x"), None, "an opaque dir hides lower files");
        assert!(!dir.join("a/sub").exists(), "and lower dirs");
        assert_eq!(read("a/kept").as_deref(), Some("kept"), "but keeps its own layer's files");
        assert_eq!(read("a/new").as_deref(), Some("new"));
        assert_eq!(read("a/through").as_deref(), Some("t"));
        assert_eq!(read("run/pid").as_deref(), Some("1"));
        assert!(dir.join("b").is_dir() && !dir.join("b/z").exists());
        assert!(!dir.join("c").exists());
        use std::os::unix::fs::MetadataExt;
        let (h, n) = (std::fs::metadata(dir.join("hard")).unwrap(), std::fs::metadata(dir.join("a/new")).unwrap());
        assert_eq!(h.ino(), n.ino());
        assert_eq!(n.mode() & 0o7777, 0o4755);
        assert_eq!(root.read("abs/through"), Some(b"t".to_vec()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
