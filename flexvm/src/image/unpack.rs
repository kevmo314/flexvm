//! Applies untrusted image layers as a container runtime does: paths resolve with `openat2(RESOLVE_IN_ROOT)`,
//! final components via `*at` calls that never follow them; `Limits` apply before anything is written.

use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::bail;
use crate::util::Result;
use crate::util::{cpath, stat_at};

/// Budgets for one image build: bytes compressed, uncompressed and per file, and tar entries.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub download: u64,
    pub unpacked: u64,
    pub file: u64,
    pub entries: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { download: 8 << 30, unpacked: 16 << 30, file: 4 << 30, entries: 1_000_000 }
    }
}

pub const MAX_DOCUMENT: u64 = 4 << 20;
/// Most tar metadata (PAX header, GNU long name and link) for one entry, together.
const MAX_META: u64 = 1 << 20;
const MAX_PAX_RECORDS: usize = 256;
const MAX_DEPTH: u32 = 4096;
/// Largest zstd window a layer may declare (libzstd's default), since decoding holds that much.
const MAX_ZSTD_WINDOW: u64 = 128 << 20;

pub fn check(rc: libc::c_int, what: &str, path: &Path) -> Result<()> {
    crate::util::check(rc).map_err(|e| format!("{what} {path:?}: {e}").into())
}

/// `p` with `..` applied lexically, clamped at the root as inside a root.
pub fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::ParentDir => _ = out.pop(),
            _ => {}
        }
    }
    out
}

fn split(p: &Path) -> Result<Option<(PathBuf, CString)>> {
    if p.components().any(|c| c == Component::ParentDir) {
        bail!("layer path {p:?} contains '..'");
    }
    let p = lexical(p);
    let Some(name) = p.file_name() else { return Ok(None) };
    Ok(Some((p.parent().unwrap().to_path_buf(), cpath(Path::new(name))?)))
}

pub fn open_at(dir: RawFd, name: &CStr, flags: i32) -> Result<OwnedFd> {
    crate::util::openat(dir, name, flags).map_err(|e| format!("open {name:?}: {e}").into())
}

pub fn open_dir_at(dir: RawFd, name: &CStr) -> Result<OwnedFd> {
    crate::util::open_dir_at(dir, name).map_err(|e| format!("open {name:?}: {e}").into())
}

fn proc_path(fd: &OwnedFd) -> CString {
    CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap()
}

pub fn is_type(dir: RawFd, name: &CStr, fmt: libc::mode_t) -> bool {
    stat_at(dir, name).is_some_and(|st| st.st_mode & libc::S_IFMT == fmt)
}

fn list_dir(dir: RawFd) -> Result<Vec<CString>> {
    let names = std::fs::read_dir(format!("/proc/self/fd/{dir}"))?;
    names.map(|e| Ok(CString::new(e?.file_name().into_vec()).unwrap())).collect()
}

/// Removes `name` in `dir` recursively, never leaving `dir`.
pub fn remove_at(dir: RawFd, name: &CStr, depth: u32) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("directory tree too deep to remove");
    }
    if is_type(dir, name, libc::S_IFDIR) {
        let sub = open_dir_at(dir, name)?;
        for child in list_dir(sub.as_raw_fd())? {
            remove_at(sub.as_raw_fd(), &child, depth + 1)?;
        }
        check(unsafe { libc::unlinkat(dir, name.as_ptr(), libc::AT_REMOVEDIR) }, "rmdir", Path::new(OsStr::from_bytes(name.to_bytes())))
    } else {
        match (unsafe { libc::unlinkat(dir, name.as_ptr(), 0) } < 0).then(io::Error::last_os_error) {
            Some(e) if e.raw_os_error() != Some(libc::ENOENT) => bail!("unlink {name:?}: {e}"),
            _ => Ok(()),
        }
    }
}

/// An entry as resolved, not as spelled: a directory by its (dev, ino), anything else by its directory's and its name.
type Key = (libc::dev_t, libc::ino_t, CString);

fn key(dir: RawFd, name: &CStr) -> Option<Key> {
    let st = stat_at(dir, name)?;
    if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
        return Some((st.st_dev, st.st_ino, CString::default()));
    }
    let d = stat_at(dir, c"")?;
    Some((d.st_dev, d.st_ino, name.to_owned()))
}

/// Hides lower layers' entries under `fd`, keeping `layer` (this layer's entries and their directories).
fn opaque(fd: RawFd, layer: &HashSet<Key>, depth: u32) -> Result<()> {
    for name in list_dir(fd)? {
        hide(fd, &name, layer, depth)?;
    }
    Ok(())
}

/// Whiteout of `name` in `fd`: removed if from a lower layer, else made opaque.
fn hide(fd: RawFd, name: &CStr, layer: &HashSet<Key>, depth: u32) -> Result<()> {
    if !key(fd, name).is_some_and(|k| layer.contains(&k)) {
        return remove_at(fd, name, 0);
    }
    if depth > MAX_DEPTH {
        bail!("directory tree too deep");
    }
    match is_type(fd, name, libc::S_IFDIR) {
        true => opaque(open_dir_at(fd, name)?.as_raw_fd(), layer, depth + 1),
        false => Ok(()),
    }
}

struct At {
    dir: OwnedFd,
    name: CString,
}

impl At {
    fn remove(&self) -> Result<()> {
        remove_at(self.dir.as_raw_fd(), &self.name, 0)
    }

    fn create(&self) -> Result<File> {
        self.remove()?;
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
        Ok(open_at(self.dir.as_raw_fd(), &self.name, flags)?.into())
    }

    /// Sets an xattr on the entry itself through an O_PATH fd, so device
    /// nodes and FIFOs are never opened and symlinks never followed.
    fn set_xattr(&self, key: &str, value: &[u8]) -> Result<()> {
        let fd = open_at(self.dir.as_raw_fd(), &self.name, libc::O_PATH | libc::O_NOFOLLOW)?;
        let key = CString::new(key).map_err(|_| "NUL in xattr name")?;
        check(unsafe { libc::setxattr(proc_path(&fd).as_ptr(), key.as_ptr(), value.as_ptr().cast(), value.len(), 0) }, "setxattr", Path::new(""))
    }
}

pub struct Hashed<R> {
    inner: R,
    hash: Sha256,
    pub n: u64,
}

impl<R> Hashed<R> {
    pub fn new(inner: R) -> Self {
        Hashed { inner, hash: Sha256::new(), n: 0 }
    }

    pub fn digest(&self) -> String {
        format!("sha256:{:x}", self.hash.clone().finalize())
    }
}

impl<R: Read> Read for Hashed<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.n += n as u64;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
}

pub struct Meta {
    pub path: PathBuf,
    pub link: Option<PathBuf>,
    uid: u32,
    gid: u32,
    xattrs: Vec<(String, Vec<u8>)>,
}

/// Calls `f` for each tar entry, counted in `seen` up to `max`. Metadata
/// entries are read here within `MAX_META`, not whole by the tar crate.
pub fn each_entry<R: Read>(r: R, seen: &mut u64, max: u64, mut f: impl FnMut(&mut tar::Entry<'_, R>, Meta) -> Result<()>) -> Result<()> {
    use tar::EntryType as T;
    let mut ar = tar::Archive::new(r);
    let (mut name, mut link, mut pax, mut bytes) = (None, None, None, 0);
    for e in ar.entries()?.raw(true) {
        let mut e = e?;
        *seen += 1;
        if *seen > max {
            bail!("more than {max} tar entries (--max-entries)");
        }
        let kind = e.header().entry_type();
        let slot = match kind {
            T::GNULongName => Some(&mut name),
            T::GNULongLink => Some(&mut link),
            T::XHeader => Some(&mut pax),
            T::XGlobalHeader => None,
            _ => {
                let meta = describe(&e, name.take(), link.take(), pax.take())?;
                bytes = 0;
                f(&mut e, meta)?;
                continue;
            }
        };
        // A global header is skipped within a budget of its own.
        let left = if slot.is_some() { MAX_META - bytes } else { MAX_META };
        if e.size() > left {
            bail!("tar metadata for one entry exceeds {MAX_META} bytes");
        }
        let mut data = Vec::with_capacity(e.size() as usize);
        (&mut e).take(left).read_to_end(&mut data)?;
        match slot {
            Some(Some(_)) => bail!("repeated {kind:?} metadata before one tar entry"),
            Some(s) => (*s, bytes) = (Some(data), bytes + e.size()),
            None => {}
        }
    }
    Ok(())
}

fn describe<R: Read>(e: &tar::Entry<R>, name: Option<Vec<u8>>, link: Option<Vec<u8>>, pax: Option<Vec<u8>>) -> Result<Meta> {
    let h = e.header();
    let trim = |mut v: Vec<u8>| {
        v.truncate(v.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1));
        v
    };
    let mut path = name.map(trim).unwrap_or_else(|| h.path_bytes().into_owned());
    let mut link = link.map(trim).or_else(|| h.link_name_bytes().map(|l| l.into_owned()));
    let (mut uid, mut gid) = (h.uid()? as u32, h.gid()? as u32);
    let mut xattrs = Vec::new();
    for (i, ext) in tar::PaxExtensions::new(pax.as_deref().unwrap_or_default()).enumerate() {
        if i == MAX_PAX_RECORDS {
            bail!("more than {MAX_PAX_RECORDS} PAX records for one tar entry");
        }
        let ext = ext.map_err(|_| "bad PAX record")?;
        let value = ext.value_bytes();
        let num = || std::str::from_utf8(value).ok()?.parse::<u64>().ok();
        match ext.key().map_err(|_| "bad PAX key")? {
            "path" => path = value.to_vec(),
            "linkpath" => link = Some(value.to_vec()),
            "uid" => uid = num().ok_or("bad PAX uid")? as u32,
            "gid" => gid = num().ok_or("bad PAX gid")? as u32,
            "size" if num() != Some(e.size()) => bail!("PAX size overrides are not supported"),
            k => xattrs.extend(k.strip_prefix("SCHILY.xattr.").map(|x| (x.to_string(), value.to_vec()))),
        }
    }
    let to_path = |b| PathBuf::from(OsString::from_vec(b));
    Ok(Meta { path: to_path(path), link: link.map(to_path), uid, gid, xattrs })
}

pub struct Root {
    fd: OwnedFd,
    limits: Limits,
    pub entries: u64,
    seen: u64,
    unpacked: u64,
}

impl Root {
    #[cfg(test)]
    pub fn open(dir: &Path, limits: Limits) -> Result<Root> {
        Ok(Root::from_fd(open_at(libc::AT_FDCWD, &cpath(dir)?, libc::O_PATH | libc::O_DIRECTORY)?, limits))
    }

    pub fn from_fd(fd: OwnedFd, limits: Limits) -> Root {
        Root { fd, limits, entries: 0, seen: 0, unpacked: 0 }
    }

    fn openat2(&self, rel: &[u8], flags: i32) -> io::Result<OwnedFd> {
        let path = CString::new(if rel.is_empty() { b".".as_slice() } else { rel }).map_err(|_| io::Error::other("NUL in path"))?;
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (flags | libc::O_CLOEXEC) as u64;
        how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
        let fd = unsafe { libc::syscall(libc::SYS_openat2, self.fd.as_raw_fd(), path.as_ptr(), &how, std::mem::size_of::<libc::open_how>()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    fn resolve(&self, rel: &Path) -> io::Result<OwnedFd> {
        self.openat2(rel.as_os_str().as_bytes(), libc::O_PATH | libc::O_DIRECTORY)
    }

    fn mkdir_p(&mut self, rel: &Path, depth: u32) -> Result<OwnedFd> {
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
            let name = cpath(c.as_ref())?;
            cur.push(c);
            fd = match self.resolve(&cur) {
                Ok(next) => next,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    if unsafe { libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o755) } == 0 {
                        self.entries += 1;
                    } else {
                        // A dangling symlink (say var/run -> /run): create its target, as container runtimes do.
                        let mut buf = vec![0u8; 4096];
                        let n = unsafe { libc::readlinkat(fd.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
                        check(n as i32, "mkdir", &cur)?;
                        let target = cur.parent().unwrap().join(OsStr::from_bytes(&buf[..n as usize]));
                        self.mkdir_p(&lexical(&target), depth + 1)?;
                    }
                    self.resolve(&cur)?
                }
                Err(e) => bail!("resolve {cur:?}: {e}"),
            };
        }
        Ok(fd)
    }

    fn at(&mut self, path: &Path) -> Result<At> {
        let (parent, name) = split(path)?.ok_or("empty path")?;
        Ok(At { dir: self.mkdir_p(&parent, 0)?, name })
    }

    /// Applies one decompressed layer, read to its end; returns its digest (the config's diff_id).
    pub fn apply_layer(&mut self, layer: impl Read) -> Result<String> {
        let limit = self.limits.unpacked.saturating_sub(self.unpacked);
        let mut r = Hashed::new(layer.take(limit.saturating_add(1)));
        let mut seen = self.seen;
        // This layer's entries and the directories holding them, which its whiteouts keep.
        let mut mine = HashSet::new();
        let res = each_entry(&mut r, &mut seen, self.limits.entries, |e, m| self.apply(e, m, &mut mine))
            .and_then(|_| Ok(io::copy(&mut r, &mut io::sink()).map(|_| ())?));
        self.seen = seen;
        self.unpacked += r.n;
        if r.n > limit {
            bail!("image exceeds the unpacked size limit (--max-unpacked-mib)");
        }
        res?;
        Ok(r.digest())
    }

    fn apply<R: Read>(&mut self, e: &mut tar::Entry<R>, m: Meta, mine: &mut HashSet<Key>) -> Result<()> {
        let Some((parent, name)) = split(&m.path)? else { return Ok(()) };
        let name = name.as_bytes();
        if let Some(rest) = name.strip_prefix(b".wh.") {
            // Other `.wh..wh.` names are aufs metadata.
            let opq = rest == b".wh..opq";
            if !opq && rest.starts_with(b".wh.") {
                return Ok(());
            }
            if rest.is_empty() || rest == b"." || rest == b".." {
                bail!("bad whiteout target {:?}", String::from_utf8_lossy(rest));
            }
            if let Ok(dir) = self.resolve(&parent) {
                match opq {
                    true => opaque(dir.as_raw_fd(), mine, 0)?,
                    false => hide(dir.as_raw_fd(), &CString::new(rest).unwrap(), mine, 0)?,
                }
            }
            return Ok(());
        }
        let at = self.entry(e, &parent.join(OsStr::from_bytes(name)), m)?;
        mine.extend(key(at.dir.as_raw_fd(), &at.name));
        // Up from where the entry landed, which a symlinked parent may have moved.
        let (root, mut dir) = (key(self.fd.as_raw_fd(), c""), at.dir);
        while let Some(k) = key(dir.as_raw_fd(), c"").filter(|k| Some(k) != root.as_ref()) {
            if !mine.insert(k) {
                break;
            }
            dir = open_dir_at(dir.as_raw_fd(), c"..")?;
        }
        Ok(())
    }

    fn entry<R: Read>(&mut self, e: &mut tar::Entry<R>, rel: &Path, m: Meta) -> Result<At> {
        use tar::EntryType as T;
        let h = e.header().clone();
        let kind = h.entry_type();
        let at = self.at(rel)?;
        let (dfd, name) = (at.dir.as_raw_fd(), at.name.as_ptr());
        match kind {
            T::Directory => {
                if !is_type(dfd, &at.name, libc::S_IFDIR) {
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
                // No bigger than the file: most are small, and a 256 KiB buffer each would be an mmap.
                let mut file = BufWriter::with_capacity((e.size() as usize).min(256 << 10), at.create()?);
                io::copy(e, &mut file).and_then(|_| file.flush()).map_err(|err| format!("write {rel:?}: {err}"))?;
            }
            T::Symlink => {
                let target = m.link.as_ref().ok_or("symlink without target")?;
                at.remove()?;
                check(unsafe { libc::symlinkat(cpath(target)?.as_ptr(), dfd, name) }, "symlink", rel)?;
            }
            T::Link => {
                let src = self.at(m.link.as_ref().ok_or("hard link without target")?)?;
                let ino = |a: &At| stat_at(a.dir.as_raw_fd(), &a.name).map(|st| (st.st_dev, st.st_ino));
                if ino(&src).is_some_and(|i| Some(i) == ino(&at)) {
                    return Ok(at);
                }
                at.remove()?;
                check(unsafe { libc::linkat(src.dir.as_raw_fd(), src.name.as_ptr(), dfd, name, 0) }, "link", rel)?;
                // A hard link shares its target's inode and metadata.
                self.entries += 1;
                return Ok(at);
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
        check(unsafe { libc::fchownat(dfd, name, m.uid, m.gid, nofollow) }, "chown", rel)?;
        if kind != T::Symlink {
            // After chown, which clears setuid/setgid bits.
            check(unsafe { libc::fchmodat(dfd, name, h.mode()? & 0o7777, 0) }, "chmod", rel)?;
            for (key, value) in &m.xattrs {
                if let Err(e) = at.set_xattr(key, value) {
                    crate::log!("image: xattr {key} on {rel:?}: {e}");
                }
            }
        }
        let ts = [libc::timespec { tv_sec: h.mtime().unwrap_or(0) as i64, tv_nsec: 0 }; 2];
        unsafe { libc::utimensat(dfd, name, ts.as_ptr(), nofollow) };
        Ok(at)
    }

    pub fn ensure_dir(&mut self, rel: &str, mode: u32) -> Result<()> {
        let at = self.at(Path::new(rel))?;
        if stat_at(at.dir.as_raw_fd(), &at.name).is_none() {
            let (dfd, name) = (at.dir.as_raw_fd(), at.name.as_ptr());
            check(unsafe { libc::mkdirat(dfd, name, 0o700) }, "mkdir", Path::new(rel))?;
            check(unsafe { libc::fchmodat(dfd, name, mode, 0) }, "chmod", Path::new(rel))?;
            self.entries += 1;
        }
        Ok(())
    }

    pub fn write_file(&mut self, rel: &str, data: &[u8], mode: u32) -> Result<()> {
        let mut f = self.at(Path::new(rel))?.create()?;
        f.write_all(data)?;
        check(unsafe { libc::fchmod(f.as_raw_fd(), mode) }, "chmod", Path::new(rel))?;
        self.entries += 1;
        Ok(())
    }

    pub fn is_file(&mut self, rel: &str) -> bool {
        let Ok(Some((parent, name))) = split(Path::new(rel)) else { return false };
        self.resolve(&parent).is_ok_and(|dir| is_type(dir.as_raw_fd(), &name, libc::S_IFREG))
    }

    /// At most 1 MiB of a regular file; anything else (a FIFO, a device) is never opened.
    pub fn read(&self, rel: &str) -> Option<Vec<u8>> {
        let fd = self.openat2(rel.trim_start_matches('/').as_bytes(), libc::O_PATH).ok()?;
        if !is_type(fd.as_raw_fd(), c"", libc::S_IFREG) {
            return None;
        }
        // Reopen the very inode checked above.
        let f = File::from(open_at(libc::AT_FDCWD, &proc_path(&fd), libc::O_RDONLY | libc::O_NONBLOCK).ok()?);
        let mut data = Vec::new();
        f.take(1 << 20).read_to_end(&mut data).ok()?;
        Some(data)
    }
}

pub fn decompress<'a>(r: impl Read + 'a) -> Result<Box<dyn Read + 'a>> {
    let mut r = BufReader::with_capacity(256 << 10, r);
    let magic = r.fill_buf()?.get(..4).map(|m| m.to_vec()).unwrap_or_default();
    Ok(match magic.as_slice() {
        [0x1f, 0x8b, ..] => Box::new(flate2::read::MultiGzDecoder::new(r)),
        [0x28, 0xb5, 0x2f, 0xfd] => {
            // Checked on every frame since ruzstd 0.9 (0.8 skipped the first); 0.9.1 also bounds each block (RUSTSEC-2026-0344).
            let mut dec = ruzstd::decoding::FrameDecoder::new();
            dec.set_max_window_size(MAX_ZSTD_WINDOW);
            Box::new(ZstdFrames { src: r, dec, active: false })
        }
        _ => Box::new(r),
    })
}

/// Decodes every zstd frame (a `StreamingDecoder` stops after the first), so all of a layer counts.
struct ZstdFrames<R> {
    src: R,
    dec: ruzstd::decoding::FrameDecoder,
    active: bool,
}

impl<R: BufRead> Read for ZstdFrames<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
        use ruzstd::decoding::BlockDecodingStrategy;
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.active {
                while self.dec.can_collect() < buf.len() && !self.dec.is_finished() {
                    let want = buf.len() - self.dec.can_collect();
                    self.dec.decode_blocks(&mut self.src, BlockDecodingStrategy::UptoBytes(want)).map_err(io::Error::other)?;
                }
                let n = self.dec.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                self.active = !(self.dec.is_finished() && self.dec.can_collect() == 0);
                continue;
            }
            if self.src.fill_buf()?.is_empty() {
                return Ok(0);
            }
            match self.dec.init(&mut self.src) {
                Ok(()) => self.active = true,
                Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame { length, .. })) => {
                    let skipped = io::copy(&mut (&mut self.src).take(length as u64), &mut io::sink())?;
                    if skipped != length as u64 {
                        return Err(io::Error::other("truncated zstd skippable frame"));
                    }
                }
                Err(e) => return Err(io::Error::other(format!("zstd layer: {e}"))),
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use tar::EntryType as T;

    /// A layer of (path, kind, data or link target); kinds d, f, l(symlink), h(ard link), p(FIFO).
    pub fn layer(entries: &[(&str, char, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for &(path, kind, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_uid(unsafe { libc::getuid() } as u64);
            h.set_gid(unsafe { libc::getgid() } as u64);
            h.set_mtime(1);
            h.set_mode(if kind == 'f' { 0o4755 } else { 0o755 });
            h.set_size(if kind == 'f' { data.len() as u64 } else { 0 });
            h.set_device_major(0).unwrap();
            h.set_device_minor(0).unwrap();
            h.set_entry_type(match kind {
                'd' => T::Directory,
                'p' => T::Fifo,
                'l' => T::Symlink,
                'h' => T::Link,
                _ => T::Regular,
            });
            match kind {
                'l' | 'h' => b.append_link(&mut h, path, data),
                _ => b.append_data(&mut h, path, data.as_bytes()),
            }
            .unwrap();
        }
        b.into_inner().unwrap()
    }

    /// A raw tar header with a name written verbatim (the builder refuses odd names).
    fn raw_entry(name: &[u8], kind: T, size: u64) -> Vec<u8> {
        let mut h = tar::Header::new_ustar();
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        h.set_entry_type(kind);
        h.set_mode(0o644);
        h.set_size(size);
        h.set_uid(unsafe { libc::getuid() } as u64);
        h.set_gid(unsafe { libc::getgid() } as u64);
        h.set_cksum();
        let mut v = h.as_bytes().to_vec();
        v.resize(512 + size.div_ceil(512) as usize * 512, 0);
        v
    }

    fn end(mut v: Vec<u8>) -> Vec<u8> {
        v.extend_from_slice(&[0u8; 1024]);
        v
    }

    pub struct Tmp(PathBuf);

    impl std::ops::Deref for Tmp {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub fn tmpdir(tag: &str) -> Tmp {
        let d = std::env::temp_dir().join(format!("flexvm-img-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }

    struct Sandbox {
        dir: Tmp,
        root: PathBuf,
    }

    impl Sandbox {
        fn new(tag: &str) -> Sandbox {
            let dir = tmpdir(&format!("unpack-{tag}"));
            let root = dir.join("root");
            std::fs::create_dir(&root).unwrap();
            std::fs::write(dir.join("outside"), "keep").unwrap();
            Sandbox { dir, root }
        }

        fn open(&self) -> Root {
            Root::open(&self.root, Limits::default()).unwrap()
        }

        fn read(&self, p: &str) -> Option<String> {
            std::fs::read_to_string(self.root.join(p)).ok()
        }

        fn apply(&self, limits: Limits, tar: &[u8]) -> String {
            Root::open(&self.root, limits).unwrap().apply_layer(tar).unwrap_err().to_string()
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            assert_eq!(std::fs::read_to_string(self.dir.join("outside")).ok().as_deref(), Some("keep"), "escaped the root");
        }
    }

    #[test]
    fn large_files_flush_the_final_partial_buffer() {
        let s = Sandbox::new("large-file");
        let data = "x".repeat((512 << 10) + 123);
        s.open().apply_layer(&layer(&[("large", 'f', &data)])[..]).unwrap();
        assert_eq!(s.read("large").unwrap(), data);
    }

    #[test]
    fn layers_whiteouts_and_symlinks() {
        let s = Sandbox::new("basic");
        let mut root = s.open();
        let lower = layer(&[("a/", 'd', ""), ("a/x", 'f', "x"), ("b/z", 'f', "z"), ("c", 'f', "c"), ("abs", 'l', "/a"), ("var/run", 'l', "/run")]);
        assert_eq!(root.apply_layer(&lower[..]).unwrap(), format!("sha256:{:x}", Sha256::digest(&lower)));
        let upper = layer(&[
            ("b/.wh.z", 'f', ""),
            (".wh.c", 'f', ""),
            // Through an absolute symlink: must land inside the root.
            ("abs/through", 'f', "t"),
            ("var/run/pid", 'f', "1"),
            ("hard", 'h', "a/x"),
        ]);
        root.apply_layer(&upper[..]).unwrap();
        assert_eq!(s.read("a/through").as_deref(), Some("t"));
        assert_eq!(s.read("run/pid").as_deref(), Some("1"));
        assert!(s.root.join("b").is_dir() && !s.root.join("b/z").exists());
        assert!(!s.root.join("c").exists());
        use std::os::unix::fs::MetadataExt;
        let (h, n) = (std::fs::metadata(s.root.join("hard")).unwrap(), std::fs::metadata(s.root.join("a/x")).unwrap());
        assert_eq!(h.ino(), n.ino());
        assert_eq!(n.mode() & 0o7777, 0o4755);
        assert_eq!(root.read("abs/through"), Some(b"t".to_vec()));
    }

    #[test]
    fn whiteouts_hide_only_lower_entries_in_any_order() {
        type Layer<'a> = &'a [(&'a str, char, &'a str)];
        type Want<'a> = &'a [(&'a str, Option<&'a str>)];
        let cases: &[(Layer, Layer, Want)] = &[
            (
                &[("foo", 'f', "lower"), ("dir/old", 'f', "old"), ("gone", 'f', "gone")],
                &[("foo", 'f', "upper"), (".wh.foo", 'f', ""), ("dir/new", 'f', "new"), (".wh.dir", 'f', ""), (".wh.gone", 'f', "")],
                &[("foo", Some("upper")), ("dir/new", Some("new")), ("dir/old", None), ("gone", None), (".wh.foo", None)],
            ),
            (
                &[("a/b/c/old", 'f', "old"), ("a/b/x", 'f', "x"), ("pre", 'f', "lower"), ("o/old", 'f', "o")],
                &[
                    (".wh.pre", 'f', ""),
                    ("pre", 'f', "upper"), // before the same layer's pre
                    ("a/b/c/new", 'f', "new"),
                    ("a/b/.wh.c", 'f', ""), // nested: keeps c/new, drops c/old
                    ("a/b/link", 'h', "a/b/x"),
                    ("a/b/.wh.link", 'f', ""), // hard link to a lower file, kept
                    ("a/b/.wh.x", 'f', ""),    // lower: removed, the link keeps its data
                    ("o/new", 'f', "n"),
                    ("o/.wh..wh..opq", 'f', ""),
                    ("o/.wh.new", 'f', ""),
                ],
                &[
                    ("pre", Some("upper")),
                    ("a/b/c/new", Some("new")),
                    ("a/b/c/old", None),
                    ("a/b/link", Some("x")),
                    ("a/b/x", None),
                    ("o/new", Some("n")),
                    ("o/old", None),
                ],
            ),
            // Opaque directories keep this layer's descendants, written before the markers.
            (
                &[("a/x", 'f', "x"), ("a/sub/y", 'f', "y"), ("old", 'f', "o"), ("low/f", 'f', "f")],
                &[("a/b/new", 'f', "n"), ("a/sub/z", 'f', "z"), ("keep/me", 'f', "m"), ("a/.wh..wh..opq", 'f', ""), (".wh..wh..opq", 'f', "")],
                &[("a/b/new", Some("n")), ("a/sub/z", Some("z")), ("keep/me", Some("m")), ("a/sub/y", None), ("a/x", None), ("old", None), ("low", None)],
            ),
            // Written through a symlinked parent, in either order.
            (
                &[("real/old", 'f', "o"), ("alias", 'l', "real")],
                &[("alias/new", 'f', "n"), ("real/.wh..wh..opq", 'f', "")],
                &[("real/new", Some("n")), ("real/old", None)],
            ),
            (
                &[("real/old", 'f', "o"), ("alias", 'l', "real")],
                &[("real/.wh..wh..opq", 'f', ""), ("alias/new", 'f', "n")],
                &[("real/new", Some("n")), ("real/old", None)],
            ),
        ];
        for (i, (lower, upper, want)) in cases.iter().enumerate() {
            let s = Sandbox::new(&format!("wh{i}"));
            let mut root = s.open();
            root.apply_layer(&layer(lower)[..]).unwrap();
            root.apply_layer(&layer(upper)[..]).unwrap();
            for (p, content) in *want {
                assert_eq!(s.read(p).as_deref(), *content, "case {i}: {p}");
                assert_eq!(s.root.join(p).exists(), content.is_some(), "case {i}: {p}");
            }
        }
    }

    #[test]
    fn whiteouts_cannot_leave_their_directory() {
        for name in [&b".wh.."[..], b"a/.wh..", b".wh.", b"a/.wh."] {
            let s = Sandbox::new("wh");
            std::fs::create_dir_all(s.root.join("a")).unwrap();
            std::fs::write(s.root.join("a/f"), "f").unwrap();
            let e = s.apply(Limits::default(), &end(raw_entry(name, T::Regular, 0)));
            assert!(e.contains("bad whiteout target"), "{name:?}: {e}");
            assert_eq!(s.read("a/f").as_deref(), Some("f"));
        }
        // Through a symlink pointing out of the root: still confined.
        let s = Sandbox::new("wh-link");
        s.open().apply_layer(&layer(&[("esc", 'l', "../.."), ("esc/.wh.outside", 'f', "")])[..]).unwrap();
    }

    fn pax(records: &[(&str, &str)]) -> Vec<u8> {
        let mut data = Vec::new();
        for (k, v) in records {
            let rec = |len: usize| format!("{len} {k}={v}\n");
            let mut len = rec(0).len();
            while rec(len).len() != len {
                len = rec(len).len();
            }
            data.extend_from_slice(rec(len).as_bytes());
        }
        let mut v = raw_entry(b"PaxHeader", T::XHeader, data.len() as u64);
        v[512..512 + data.len()].copy_from_slice(&data);
        v
    }

    #[test]
    fn limits_are_enforced() {
        let s = Sandbox::new("limits");
        let tar = layer(&[("a", 'f', "1234"), ("b", 'f', "1"), ("c", 'f', "1")]);
        let d = Limits::default();
        for (limits, want) in [
            (Limits { entries: 2, ..d }, "--max-entries"),
            (Limits { file: 3, ..d }, "--max-file-mib"),
            (Limits { unpacked: 1000, ..d }, "unpacked size limit"),
        ] {
            let e = s.apply(limits, &tar);
            assert!(e.contains(want), "{e}");
        }
        // Tar metadata is bounded before it is read into memory, and cannot pile up.
        let file = &tar[..1024]; // one entry, without the end-of-archive blocks
        let many: Vec<String> = (0..300).map(|i| format!("k{i}")).collect();
        let many: Vec<(&str, &str)> = many.iter().map(|k| (k.as_str(), "v")).collect();
        let big = "x".repeat(700_000);
        for (meta, want) in [
            (raw_entry(b"PaxHeader", T::XHeader, 2 << 20), "tar metadata"),
            ([pax(&[("comment", "a")]), pax(&[("comment", "b")])].concat(), "repeated"),
            (pax(&many), "PAX records"),
            // A long name and a PAX header that each fit, but not together.
            ([raw_entry(b"././@LongLink", T::GNULongName, 600_000), pax(&[("comment", &big)])].concat(), "exceeds"),
        ] {
            let e = s.apply(d, &end([meta, file.to_vec()].concat()));
            assert!(e.contains(want), "{e}");
        }
    }

    #[test]
    fn zstd_layers_decode_every_frame() {
        use ruzstd::encoding::{compress_to_vec, CompressionLevel};
        let tar = layer(&[("a", 'f', "first"), ("b", 'f', "second")]);
        let (one, two) = tar.split_at(1024);
        let mut z = compress_to_vec(one, CompressionLevel::Fastest);
        z.extend_from_slice(&0x184D2A50u32.to_le_bytes());
        z.extend_from_slice(&3u32.to_le_bytes());
        z.extend_from_slice(b"abc");
        z.extend(compress_to_vec(two, CompressionLevel::Fastest));
        let mut out = Vec::new();
        decompress(io::Cursor::new(z.clone())).unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(out, tar);
        let s = Sandbox::new("zstd");
        let diff = s.open().apply_layer(decompress(io::Cursor::new(z)).unwrap()).unwrap();
        assert_eq!(diff, format!("sha256:{:x}", Sha256::digest(&tar)));
        assert_eq!(s.read("b").as_deref(), Some("second"));
        let mut bad = compress_to_vec(&tar[..], CompressionLevel::Fastest);
        bad.extend_from_slice(b"trailing junk");
        assert!(decompress(io::Cursor::new(bad)).unwrap().read_to_end(&mut Vec::new()).is_err());
    }

    #[test]
    fn zstd_windows_are_capped_on_every_frame() {
        use ruzstd::encoding::{compress_to_vec, CompressionLevel};
        // 8 MiB of 128 KiB RLE blocks, which a 4 GiB window would hold back instead of returning.
        let blocks: Vec<u8> = (0..64u32).flat_map(|i| [&((128 << 13) | 1 << 1 | (i == 63) as u32).to_le_bytes()[..3], b"x"].concat()).collect();
        let magic = [0x28, 0xb5, 0x2f, 0xfd];
        // Window descriptor 2^32, and a single-segment frame whose content size (the window) is 2^32.
        let headers = [[&magic[..], &[0x00, 22 << 3]].concat(), [&magic[..], &[0xe0], &(1u64 << 32).to_le_bytes()].concat()];
        let mut first = compress_to_vec(&b"ok"[..], CompressionLevel::Fastest);
        first.extend_from_slice(&0x184D2A50u32.to_le_bytes());
        first.extend_from_slice(&0u32.to_le_bytes());
        for prefix in [vec![], first] {
            for h in &headers {
                let mut out = Vec::new();
                let z = [&prefix[..], h, &blocks].concat();
                let e = decompress(io::Cursor::new(z)).unwrap().read_to_end(&mut out).unwrap_err();
                assert!(e.to_string().contains("window_size is too big"), "{e}");
                assert!(out.len() <= 2);
            }
        }
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
