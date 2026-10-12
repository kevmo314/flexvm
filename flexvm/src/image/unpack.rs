//! Applies image layers to a directory, as root, the way a container runtime
//! does: whiteouts and opaque directories, ownership, modes, xattrs, device
//! nodes, symlinks and hard links.
//!
//! Layers are untrusted input. Every path is resolved with
//! `openat2(RESOLVE_IN_ROOT)`, so symlinks in the image (absolute ones
//! included) resolve inside the image and a layer can never write outside it.
//! Operations then act on one normal final component inside a resolved parent
//! directory, with `*at` calls that never follow it; removal walks directory
//! fds the same way. Sizes, entry counts and tar metadata are bounded by
//! `Limits` before anything is allocated or written.

use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::bail;
use crate::util::Result;

/// Budgets for one image build. Everything is checked before allocating or
/// writing; exceeding one fails the build.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Compressed bytes of all layers together (downloads and local blobs).
    pub download: u64,
    /// Uncompressed bytes of all layers together, tar headers included.
    pub unpacked: u64,
    /// Bytes of any one file.
    pub file: u64,
    /// Tar entries across all layers.
    pub entries: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { download: 8 << 30, unpacked: 16 << 30, file: 4 << 30, entries: 1_000_000 }
    }
}

/// Largest manifest, index or config document accepted.
pub const MAX_DOCUMENT: u64 = 4 << 20;
/// Largest tar metadata entry (PAX header, GNU long name or link).
const MAX_META: u64 = 1 << 20;
/// Deepest directory tree removal descends into.
const MAX_DEPTH: u32 = 4096;

pub struct Root {
    fd: OwnedFd,
    limits: Limits,
    /// Entries written so far, to size the filesystem's inode table.
    pub entries: u64,
    /// Tar entries read so far, against `limits.entries`.
    seen: u64,
    /// Uncompressed layer bytes read so far, against `limits.unpacked`.
    unpacked: u64,
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

/// A whiteout's target must be exactly one normal path component.
fn whiteout_target(name: &[u8]) -> Result<CString> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0) {
        bail!("bad whiteout target {:?}", String::from_utf8_lossy(name));
    }
    Ok(CString::new(name).unwrap())
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

fn lstat_at(dir: RawFd, name: &CStr) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    (rc == 0).then_some(st)
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// Opens directory `name` in `dir` without following a symlink.
fn open_dir_at(dir: RawFd, name: &CStr) -> Result<OwnedFd> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags) };
    if fd < 0 {
        bail!("open directory {name:?}: {}", io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The names in directory `dir`, without `.` and `..`.
fn list_dir(dir: RawFd) -> Result<Vec<CString>> {
    let fd = open_dir_at(dir, c".")?;
    let d = unsafe { libc::fdopendir(fd.as_raw_fd()) };
    if d.is_null() {
        bail!("read directory: {}", io::Error::last_os_error());
    }
    std::mem::forget(fd); // closedir closes it
    let mut names = Vec::new();
    loop {
        let e = unsafe { libc::readdir(d) };
        if e.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) };
        if name != c"." && name != c".." {
            names.push(name.to_owned());
        }
    }
    unsafe { libc::closedir(d) };
    Ok(names)
}

/// Removes `name` in `dir`, recursively, never leaving `dir`: every step is
/// an `*at` call on a directory fd opened without following symlinks.
fn remove_at(dir: RawFd, name: &CStr, depth: u32) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("directory tree too deep to remove");
    }
    let Some(st) = lstat_at(dir, name) else { return Ok(()) };
    if is_dir(&st) {
        let sub = open_dir_at(dir, name)?;
        for child in list_dir(sub.as_raw_fd())? {
            remove_at(sub.as_raw_fd(), &child, depth + 1)?;
        }
        check(unsafe { libc::unlinkat(dir, name.as_ptr(), libc::AT_REMOVEDIR) }, "rmdir", Path::new(""))
    } else {
        check(unsafe { libc::unlinkat(dir, name.as_ptr(), 0) }, "unlink", Path::new(""))
    }
}

/// Removes everything under directory `fd` (at `dir`) that lower layers
/// put there: entries this layer wrote stay, and so do directories with
/// entries from this layer below them, which are cleaned the same way.
fn make_opaque(fd: RawFd, dir: &Path, mine: &HashSet<PathBuf>, ancestors: &HashSet<PathBuf>, depth: u32) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("directory tree too deep");
    }
    for name in list_dir(fd)? {
        let rel = dir.join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        let keep = mine.contains(&rel) || ancestors.contains(&rel);
        match lstat_at(fd, &name) {
            Some(st) if keep && is_dir(&st) => {
                let sub = open_dir_at(fd, &name)?;
                make_opaque(sub.as_raw_fd(), &rel, mine, ancestors, depth + 1)?;
            }
            _ if keep => {}
            _ => remove_at(fd, &name, 0)?,
        }
    }
    Ok(())
}

/// A resolved parent directory and the final component inside it.
struct At {
    dir: OwnedFd,
    name: CString,
}

impl At {
    fn lstat(&self) -> Option<libc::stat> {
        lstat_at(self.dir.as_raw_fd(), &self.name)
    }

    fn is_dir(&self) -> bool {
        self.lstat().is_some_and(|st| is_dir(&st))
    }

    /// Removes whatever is there, recursively.
    fn remove(&self) -> Result<()> {
        remove_at(self.dir.as_raw_fd(), &self.name, 0)
    }

    /// Sets an extended attribute on the entry itself (not a symlink target),
    /// through an O_PATH fd so device nodes and FIFOs are never opened.
    fn set_xattr(&self, key: &str, value: &[u8]) -> Result<()> {
        let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), self.name.as_ptr(), flags) };
        if fd < 0 {
            bail!("{}", io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let path = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        let key = CString::new(key).map_err(|_| "NUL in xattr name")?;
        if unsafe { libc::setxattr(path.as_ptr(), key.as_ptr(), value.as_ptr().cast(), value.len(), 0) } < 0 {
            bail!("{}", io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Hashes and counts what passes through, failing past `limit` bytes.
struct Meter<R> {
    inner: R,
    hash: Sha256,
    n: u64,
    limit: u64,
}

impl<R: Read> Read for Meter<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.n += n as u64;
        if self.n > self.limit {
            return Err(io::Error::other("image exceeds the unpacked size limit (--max-unpacked-mib)"));
        }
        self.hash.update(&buf[..n]);
        Ok(n)
    }
}

/// The parts of a tar entry that metadata entries before it can override.
#[derive(Default)]
struct Pending {
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
    pax: Vec<(String, Vec<u8>)>,
}

fn read_meta<R: Read>(e: &mut tar::Entry<R>) -> Result<Vec<u8>> {
    if e.size() > MAX_META {
        bail!("tar metadata entry of {} bytes is over the {MAX_META} byte limit", e.size());
    }
    let mut v = Vec::with_capacity(e.size() as usize);
    e.take(MAX_META).read_to_end(&mut v)?;
    Ok(v)
}

fn trim_nul(mut v: Vec<u8>) -> Vec<u8> {
    while v.last() == Some(&0) {
        v.pop();
    }
    v
}

/// What one tar entry asks for, after long names and PAX records.
struct Entry {
    path: PathBuf,
    link: Option<PathBuf>,
    uid: u32,
    gid: u32,
    xattrs: Vec<(String, Vec<u8>)>,
}

impl Root {
    pub fn open(dir: &Path, limits: Limits) -> Result<Root> {
        let fd = unsafe { libc::open(cpath(dir)?.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        check(fd, "open", dir)?;
        Ok(Root { fd: unsafe { OwnedFd::from_raw_fd(fd) }, limits, entries: 0, seen: 0, unpacked: 0 })
    }

    fn openat2(&self, rel: &[u8], flags: i32) -> io::Result<OwnedFd> {
        let path = CString::new(if rel.is_empty() { b".".as_slice() } else { rel })
            .map_err(|_| io::Error::other("NUL in path"))?;
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (flags | libc::O_CLOEXEC) as u64;
        how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
        let fd = unsafe {
            libc::syscall(libc::SYS_openat2, self.fd.as_raw_fd(), path.as_ptr(), &how, std::mem::size_of::<libc::open_how>())
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    /// Opens `rel` (a directory path inside the root) with symlinks resolved in the root.
    fn resolve(&self, rel: &Path) -> io::Result<OwnedFd> {
        self.openat2(rel.as_os_str().as_bytes(), libc::O_PATH | libc::O_DIRECTORY)
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

    /// Applies one decompressed layer tarball and returns its digest (the
    /// image config's `diff_id` for it). Reads the stream to its end, so the
    /// digest covers all of it.
    pub fn apply_layer(&mut self, layer: impl Read) -> Result<String> {
        let mut m = Meter { inner: layer, hash: Sha256::new(), n: 0, limit: self.limits.unpacked - self.unpacked };
        let res = self.apply_entries(&mut m).and_then(|_| Ok(io::copy(&mut m, &mut io::sink()).map(|_| ())?));
        self.unpacked += m.n;
        res?;
        Ok(format!("sha256:{:x}", m.hash.finalize()))
    }

    fn apply_entries(&mut self, r: &mut impl Read) -> Result<()> {
        let mut ar = tar::Archive::new(r);
        // Paths this layer wrote, and their ancestors: an opaque directory
        // keeps these and drops only what lower layers put there.
        let mut mine: HashSet<PathBuf> = HashSet::new();
        let mut ancestors: HashSet<PathBuf> = HashSet::new();
        let mut pending = Pending::default();
        // Raw entries: metadata entries are read here, within MAX_META,
        // instead of whole into memory by the tar crate.
        for entry in ar.entries()?.raw(true) {
            let mut e = entry?;
            self.seen += 1;
            if self.seen > self.limits.entries {
                bail!("image has more than {} tar entries (--max-entries)", self.limits.entries);
            }
            use tar::EntryType as T;
            match e.header().entry_type() {
                T::GNULongName => {
                    pending.long_name = Some(trim_nul(read_meta(&mut e)?));
                    continue;
                }
                T::GNULongLink => {
                    pending.long_link = Some(trim_nul(read_meta(&mut e)?));
                    continue;
                }
                T::XHeader => {
                    let data = read_meta(&mut e)?;
                    for ext in tar::PaxExtensions::new(&data) {
                        let ext = ext.map_err(|_| "bad PAX record")?;
                        let key = ext.key().map_err(|_| "bad PAX key")?.to_string();
                        pending.pax.push((key, ext.value_bytes().to_vec()));
                    }
                    continue;
                }
                T::XGlobalHeader => {
                    read_meta(&mut e)?;
                    continue;
                }
                _ => {}
            }
            let p = std::mem::take(&mut pending);
            let ent = self.describe(&e, p)?;
            let Some((parent, name)) = normalize(&ent.path)? else {
                // The root directory itself: keep ours.
                continue;
            };
            let name_bytes = name.as_bytes();
            if name_bytes == b".wh..wh..opq" {
                if let Ok(dir) = self.resolve(&parent) {
                    make_opaque(dir.as_raw_fd(), &parent, &mine, &ancestors, 0)?;
                }
                continue;
            }
            if name_bytes.starts_with(b".wh..wh.") {
                continue; // other aufs metadata
            }
            if let Some(hidden) = name_bytes.strip_prefix(b".wh.") {
                let hidden = whiteout_target(hidden)?;
                if let Ok(dir) = self.resolve(&parent) {
                    remove_at(dir.as_raw_fd(), &hidden, 0)?;
                }
                continue;
            }
            let rel = parent.join(std::ffi::OsStr::from_bytes(name_bytes));
            self.entry(&mut e, &rel, ent)?;
            let mut a = rel.parent();
            while let Some(p) = a.filter(|p| !p.as_os_str().is_empty()) {
                if !ancestors.insert(p.to_path_buf()) {
                    break;
                }
                a = p.parent();
            }
            mine.insert(rel);
        }
        Ok(())
    }

    fn describe<R: Read>(&self, e: &tar::Entry<R>, p: Pending) -> Result<Entry> {
        let h = e.header();
        let mut path = p.long_name.unwrap_or_else(|| h.path_bytes().into_owned());
        let mut link = p.long_link.or_else(|| h.link_name_bytes().map(|l| l.into_owned()));
        let (mut uid, mut gid) = (h.uid()? as u32, h.gid()? as u32);
        let mut xattrs = Vec::new();
        for (key, value) in p.pax {
            let num = || std::str::from_utf8(&value).ok().and_then(|v| v.parse::<u64>().ok());
            match key.as_str() {
                "path" => path = value,
                "linkpath" => link = Some(value),
                "uid" => uid = num().ok_or("bad PAX uid")? as u32,
                "gid" => gid = num().ok_or("bad PAX gid")? as u32,
                "size" if num() != Some(e.size()) => bail!("PAX size overrides are not supported"),
                k => {
                    if let Some(x) = k.strip_prefix("SCHILY.xattr.") {
                        xattrs.push((x.to_string(), value));
                    }
                }
            }
        }
        let to_path = |b: Vec<u8>| PathBuf::from(<std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(b));
        Ok(Entry { path: to_path(path), link: link.map(to_path), uid, gid, xattrs })
    }

    fn entry<R: Read>(&mut self, e: &mut tar::Entry<R>, rel: &Path, ent: Entry) -> Result<()> {
        use tar::EntryType as T;
        let h = e.header().clone();
        let kind = h.entry_type();
        let mode = h.mode()? & 0o7777;
        let mtime = h.mtime().unwrap_or(0) as i64;
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
                if e.size() > self.limits.file {
                    bail!("{rel:?} is {} bytes, over the per-file limit (--max-file-mib)", e.size());
                }
                if e.size() > self.limits.unpacked - self.unpacked {
                    bail!("image exceeds the unpacked size limit (--max-unpacked-mib)");
                }
                at.remove()?;
                let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
                let fd = unsafe { libc::openat(dfd, name, flags, 0o600) };
                check(fd, "create", rel)?;
                let mut f = unsafe { File::from_raw_fd(fd) };
                io::copy(e, &mut f).map_err(|err| format!("write {rel:?}: {err}"))?;
            }
            T::Symlink => {
                let target = ent.link.as_ref().ok_or("symlink without target")?;
                at.remove()?;
                check(unsafe { libc::symlinkat(cpath(target)?.as_ptr(), dfd, name) }, "symlink", rel)?;
            }
            T::Link => {
                let target = ent.link.as_ref().ok_or("hard link without target")?;
                let src = self.at(target)?.ok_or("hard link to the root")?;
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
            other => bail!("unsupported tar entry type {other:?} at {rel:?}"),
        }
        self.entries += 1;
        let nofollow = libc::AT_SYMLINK_NOFOLLOW;
        check(unsafe { libc::fchownat(dfd, name, ent.uid, ent.gid, nofollow) }, "chown", rel)?;
        if kind != T::Symlink {
            // After chown, which clears setuid/setgid bits.
            check(unsafe { libc::fchmodat(dfd, name, mode, 0) }, "chmod", rel)?;
            for (key, value) in &ent.xattrs {
                if let Err(e) = at.set_xattr(key, value) {
                    eprintln!("image: xattr {key} on {rel:?}: {e}");
                }
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
        let Ok(Some((parent, name))) = normalize(Path::new(rel)) else { return false };
        let Ok(dir) = self.resolve(&parent) else { return false };
        lstat_at(dir.as_raw_fd(), &name).is_some_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG)
    }

    /// Reads a regular file of at most 1 MiB inside the root, following
    /// symlinks within it. Anything else (a FIFO, a device node, a
    /// directory) is never opened for reading and counts as missing.
    pub fn read(&self, rel: &str) -> Option<Vec<u8>> {
        let fd = self.openat2(rel.trim_start_matches('/').as_bytes(), libc::O_PATH).ok()?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return None;
        }
        // Reopen the very inode checked above for reading.
        let path = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        let rfd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if rfd < 0 {
            return None;
        }
        let f = unsafe { File::from_raw_fd(rfd) };
        let mut data = Vec::new();
        f.take(1 << 20).read_to_end(&mut data).ok()?;
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

    /// A layer of (path, kind, data or link target). Kinds: d(ir), f(ile),
    /// l (symlink), h(ard link), p (FIFO).
    fn layer(entries: &[(&str, char, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let (uid, gid) = unsafe { (libc::getuid() as u64, libc::getgid() as u64) };
        for &(path, kind, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_uid(uid);
            h.set_gid(gid);
            h.set_mtime(1);
            match kind {
                'd' | 'p' => {
                    h.set_entry_type(if kind == 'd' { tar::EntryType::Directory } else { tar::EntryType::Fifo });
                    h.set_device_major(0).unwrap();
                    h.set_device_minor(0).unwrap();
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

    /// A raw tar header with a name written verbatim (the builder refuses odd names).
    fn raw_entry(name: &[u8], kind: tar::EntryType, size: u64) -> Vec<u8> {
        let mut h = tar::Header::new_ustar();
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        h.set_entry_type(kind);
        h.set_mode(0o644);
        h.set_size(size);
        let (uid, gid) = unsafe { (libc::getuid() as u64, libc::getgid() as u64) };
        h.set_uid(uid);
        h.set_gid(gid);
        h.set_cksum();
        let mut v = h.as_bytes().to_vec();
        v.resize(512 + size.div_ceil(512) as usize * 512, 0);
        v
    }

    fn end(mut v: Vec<u8>) -> Vec<u8> {
        v.extend_from_slice(&[0u8; 1024]);
        v
    }

    /// `parent/root` to unpack into, with `parent/outside` next to it.
    struct Sandbox {
        parent: PathBuf,
        root: PathBuf,
    }

    impl Sandbox {
        fn new(tag: &str) -> Sandbox {
            let parent = std::env::temp_dir().join(format!("flexvm-unpack-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&parent);
            let root = parent.join("root");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(parent.join("outside"), "keep").unwrap();
            Sandbox { parent, root }
        }

        fn open(&self) -> Root {
            Root::open(&self.root, Limits::default()).unwrap()
        }

        fn read(&self, p: &str) -> Option<String> {
            std::fs::read_to_string(self.root.join(p)).ok()
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            assert_eq!(std::fs::read_to_string(self.parent.join("outside")).ok().as_deref(), Some("keep"), "escaped the root");
            let _ = std::fs::remove_dir_all(&self.parent);
        }
    }

    #[test]
    fn layers_whiteouts_and_symlinks() {
        let s = Sandbox::new("basic");
        let mut root = s.open();
        let lower = layer(&[
            ("a/", 'd', ""),
            ("a/x", 'f', "x"),
            ("a/sub/y", 'f', "y"),
            ("b/z", 'f', "z"),
            ("c", 'f', "c"),
            ("abs", 'l', "/a"),
            ("var/run", 'l', "/run"),
        ]);
        let diff = root.apply_layer(&lower[..]).unwrap();
        assert_eq!(diff, format!("sha256:{:x}", Sha256::digest(&lower)));
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
        assert_eq!(s.read("a/x"), None, "an opaque dir hides lower files");
        assert!(!s.root.join("a/sub").exists(), "and lower dirs");
        assert_eq!(s.read("a/kept").as_deref(), Some("kept"), "but keeps its own layer's files");
        assert_eq!(s.read("a/new").as_deref(), Some("new"));
        assert_eq!(s.read("a/through").as_deref(), Some("t"));
        assert_eq!(s.read("run/pid").as_deref(), Some("1"));
        assert!(s.root.join("b").is_dir() && !s.root.join("b/z").exists());
        assert!(!s.root.join("c").exists());
        use std::os::unix::fs::MetadataExt;
        let (h, n) = (std::fs::metadata(s.root.join("hard")).unwrap(), std::fs::metadata(s.root.join("a/new")).unwrap());
        assert_eq!(h.ino(), n.ino());
        assert_eq!(n.mode() & 0o7777, 0o4755);
        assert_eq!(root.read("abs/through"), Some(b"t".to_vec()));
    }

    #[test]
    fn whiteouts_cannot_leave_their_directory() {
        for name in [&b".wh.."[..], b".wh..", b"a/.wh..", b".wh.", b"a/.wh."] {
            let s = Sandbox::new("wh");
            std::fs::create_dir_all(s.root.join("a")).unwrap();
            std::fs::write(s.root.join("a/f"), "f").unwrap();
            let mut root = s.open();
            let tar = end(raw_entry(name, tar::EntryType::Regular, 0));
            let e = root.apply_layer(&tar[..]).unwrap_err().to_string();
            assert!(e.contains("bad whiteout target"), "{name:?}: {e}");
            assert_eq!(s.read("a/f").as_deref(), Some("f"));
        }
        // Through a symlink pointing out of the root: still confined.
        let s = Sandbox::new("wh-link");
        let mut root = s.open();
        let tar = layer(&[("esc", 'l', "../.."), ("esc/.wh.outside", 'f', "")]);
        root.apply_layer(&tar[..]).unwrap();
    }

    #[test]
    fn opaque_keeps_same_layer_descendants_in_any_order() {
        let s = Sandbox::new("opq");
        let mut root = s.open();
        root.apply_layer(&layer(&[("a/x", 'f', "x"), ("a/sub/y", 'f', "y"), ("old", 'f', "o")])[..]).unwrap();
        root.apply_layer(
            &layer(&[
                // Before the markers, with their parent directories implied.
                ("a/b/new", 'f', "n"),
                ("a/sub/z", 'f', "z"),
                ("keep/me", 'f', "m"),
                ("a/.wh..wh..opq", 'f', ""),
                (".wh..wh..opq", 'f', ""),
            ])[..],
        )
        .unwrap();
        assert_eq!(s.read("a/b/new").as_deref(), Some("n"));
        assert_eq!(s.read("a/sub/z").as_deref(), Some("z"));
        assert_eq!(s.read("keep/me").as_deref(), Some("m"));
        assert_eq!(s.read("a/sub/y"), None);
        assert_eq!(s.read("a/x"), None);
        assert_eq!(s.read("old"), None);
    }

    #[test]
    fn limits_are_enforced() {
        let s = Sandbox::new("limits");
        let tar = layer(&[("a", 'f', "1234"), ("b", 'f', "1"), ("c", 'f', "1")]);
        let mut root = Root::open(&s.root, Limits { entries: 2, ..Limits::default() }).unwrap();
        assert!(root.apply_layer(&tar[..]).unwrap_err().to_string().contains("--max-entries"));
        let mut root = Root::open(&s.root, Limits { file: 3, ..Limits::default() }).unwrap();
        assert!(root.apply_layer(&tar[..]).unwrap_err().to_string().contains("--max-file-mib"));
        let mut root = Root::open(&s.root, Limits { unpacked: 1000, ..Limits::default() }).unwrap();
        assert!(root.apply_layer(&tar[..]).unwrap_err().to_string().contains("unpacked size limit"));
        // A huge PAX header is refused before it is read into memory.
        let huge = end(raw_entry(b"PaxHeader", tar::EntryType::XHeader, 2 << 20));
        let e = s.open().apply_layer(&huge[..]).unwrap_err().to_string();
        assert!(e.contains("metadata entry"), "{e}");
    }

    #[test]
    fn reading_image_files_never_opens_special_files() {
        let s = Sandbox::new("read");
        let mut root = s.open();
        root.apply_layer(&layer(&[("etc/passwd", 'p', ""), ("etc/group", 'l', "/etc/real"), ("etc/real", 'f', "g")])[..]).unwrap();
        // A FIFO would block a plain open forever.
        assert_eq!(root.read("etc/passwd"), None);
        assert_eq!(root.read("etc/group"), Some(b"g".to_vec()));
        assert_eq!(root.read("etc"), None);
    }
}
