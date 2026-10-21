//! Tar archives for `flexvm cp`, made and unpacked with std and libc alone: in the guest by flexvm-init
//! (`tool_main`) and on the host, which includes this file. Writes ustar, with PAX records for what does not
//! fit; reads ustar, PAX and GNU long names. Unpacking trusts no name in the archive: everything below the
//! target directory is reached one component at a time from directory fds, never through a symlink.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

const BLOCK: usize = 512;

/// To stderr, which the host's lints keep to `writeln!`.
macro_rules! warn {
    ($($t:tt)*) => {{
        let _ = writeln!(io::stderr(), $($t)*);
    }};
}

/// The most a PAX or GNU long-name record may hold.
const MAX_RECORD: u64 = 64 << 10;
/// What `extract` keeps of the directories it puts metadata on at the end: their names' bytes, and `DIR_COST` each.
#[cfg(not(test))]
const MAX_DIRS: usize = 128 << 20;
#[cfg(test)]
const MAX_DIRS: usize = 64 << 10;
const DIR_COST: usize = 128;

#[derive(Clone, Default)]
struct Header {
    path: Vec<u8>,
    link: Vec<u8>,
    kind: u8,
    mode: u32,
    uid: u64,
    gid: u64,
    size: u64,
    mtime: i64,
    dev: (u32, u32),
}

fn invalid(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

fn with(name: impl std::fmt::Display, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{name}: {e}"))
}

fn os(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

fn cstr(b: &[u8]) -> io::Result<CString> {
    CString::new(b).map_err(|_| invalid("a name contains a nul byte"))
}

/// `n` rounded up to whole blocks; refused (a size an archive gave) when that does not fit a u64.
fn padded(n: u64) -> io::Result<u64> {
    n.checked_next_multiple_of(BLOCK as u64).ok_or_else(|| invalid(format!("an entry of {n} bytes")))
}

fn zeros(out: &mut dyn Write, mut n: u64) -> io::Result<()> {
    let z = [0u8; BLOCK];
    while n > 0 {
        let k = n.min(BLOCK as u64) as usize;
        out.write_all(&z[..k])?;
        n -= k as u64;
    }
    Ok(())
}

/// False if `v` does not fit the field (its last byte is the NUL).
fn octal(field: &mut [u8], v: u64) -> bool {
    let s = format!("{v:o}");
    let end = field.len() - 1;
    let Some(pad) = end.checked_sub(s.len()) else { return false };
    field[..pad].fill(b'0');
    field[pad..end].copy_from_slice(s.as_bytes());
    true
}

fn pax_record(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    let body = key.len() + value.len() + 3;
    let mut len = body;
    while body + len.to_string().len() != len {
        len = body + len.to_string().len();
    }
    out.extend_from_slice(format!("{len} {key}=").as_bytes());
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn write_header(out: &mut dyn Write, h: &Header) -> io::Result<()> {
    let mut b = [0u8; BLOCK];
    let mut pax = Vec::new();
    for (value, at, key) in [(&h.path, 0, "path"), (&h.link, 157, "linkpath")] {
        if value.len() > 100 {
            pax_record(&mut pax, key, value);
        }
        b[at..at + value.len().min(100)].copy_from_slice(&value[..value.len().min(100)]);
    }
    octal(&mut b[100..108], u64::from(h.mode & 0o7777));
    for (at, key, v) in [(108, "uid", h.uid), (116, "gid", h.gid), (124, "size", h.size)] {
        let len = if key == "size" { 12 } else { 8 };
        if !octal(&mut b[at..at + len], v) {
            pax_record(&mut pax, key, v.to_string().as_bytes());
            octal(&mut b[at..at + len], 0);
        }
    }
    octal(&mut b[136..148], h.mtime.max(0) as u64);
    b[156] = h.kind;
    b[257..263].copy_from_slice(b"ustar\0");
    b[263..265].copy_from_slice(b"00");
    octal(&mut b[329..337], h.dev.0.into());
    octal(&mut b[337..345], h.dev.1.into());
    if !pax.is_empty() {
        write_header(out, &Header { path: b"././@PaxHeader".to_vec(), kind: b'x', mode: 0o644, size: pax.len() as u64, ..Default::default() })?;
        out.write_all(&pax)?;
        zeros(out, padded(pax.len() as u64)? - pax.len() as u64)?;
    }
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    out.write_all(&b)
}

/// Writes a tar of `src` (resolved in this process's filesystem) to `out`, docker cp's way: the top entry is named
/// `basename(src)`, or `.` (its contents) when `src` ends in `/.`. A symlink is archived as a link, unless `src` ends in `/`.
/// Below `src` nothing is followed or opened by name twice: each entry is opened once from its directory's fd,
/// without following a link (`O_PATH | O_NOFOLLOW`), typed by `fstat` of that fd, and read from that very inode.
/// One swapped for a link meanwhile is archived as what it was when opened, or as the link, never as its target.
pub fn create(src: &str, out: &mut dyn Write) -> io::Result<()> {
    let (path, name, follow) = match src.strip_suffix("/.").or((src == ".").then_some("")) {
        Some(dir) => (
            if dir.is_empty() && src != "." {
                "/"
            } else if dir.is_empty() {
                "."
            } else {
                dir
            },
            ".".to_string(),
            true,
        ),
        None => {
            let trimmed = src.trim_end_matches('/');
            let path = if trimmed.is_empty() { "/" } else { trimmed };
            let base = match trimmed.rsplit('/').next().unwrap_or("") {
                "" => ".".to_string(),
                ".." => std::fs::canonicalize(path).map_err(|e| with(src, e))?.file_name().map_or(".".into(), |n| n.to_string_lossy().into_owned()),
                b => b.to_string(),
            };
            (path, base, src.ends_with('/'))
        }
    };
    // The path the user gave is resolved as given; only its last component is not followed, unless asked.
    let nofollow = if follow || name == "." { 0 } else { libc::O_NOFOLLOW };
    let node = Node::open(libc::AT_FDCWD, &cstr(path.as_bytes())?, nofollow).map_err(|e| with(src, e))?;
    if name == "." && node.kind() != libc::S_IFDIR {
        return Err(with(src, io::Error::from_raw_os_error(libc::ENOTDIR)));
    }
    let dev = node.st.st_dev;
    walk(out, node, Path::new(path), name.into_bytes(), dev, &mut HashMap::new())?;
    out.write_all(&[0; BLOCK * 2])?;
    out.flush()
}

/// Where `walk` is, for a test to change the tree under it (`tests::race`).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// An entry's name was read from its directory; it is not opened yet.
    Listed,
    /// It is opened (`O_PATH`) and typed; its contents are not read yet.
    Typed,
    /// A cp's DST is a link, opened (`O_PATH`) and its owner approved; its target is not read yet.
    Approved,
}

#[cfg(test)]
type Hook = Box<dyn FnMut(Step, &Path)>;

#[cfg(test)]
thread_local! {
    static HOOK: std::cell::RefCell<Option<Hook>> = std::cell::RefCell::new(None);
}

fn hook(_step: Step, _path: &Path) {
    #[cfg(test)]
    HOOK.with(|h| {
        if let Some(f) = h.borrow_mut().as_mut() {
            f(_step, _path)
        }
    });
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    os(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

/// An entry opened `O_PATH` (no link followed but where asked), and what it was when opened.
struct Node {
    fd: OwnedFd,
    st: libc::stat,
}

impl Node {
    fn open(dir: RawFd, name: &CString, nofollow: libc::c_int) -> io::Result<Node> {
        let fd = os(unsafe { libc::openat(dir, name.as_ptr(), libc::O_PATH | libc::O_CLOEXEC | nofollow) })?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(fd.as_raw_fd())?;
        Ok(Node { fd, st })
    }

    fn kind(&self) -> libc::mode_t {
        self.st.st_mode & libc::S_IFMT
    }

    /// The node itself opened for reading (`O_PATH` cannot read). A directory through itself; a file through its
    /// /proc magic link, which is the inode this fd holds, whatever its name is now (no other node of that name is
    /// opened: a device put there is never opened). Either way its metadata is the opened fd's.
    fn read(&self) -> io::Result<(OwnedFd, libc::stat)> {
        let fd = match self.kind() {
            libc::S_IFDIR => os(unsafe { libc::openat(self.fd.as_raw_fd(), c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?,
            _ => {
                let proc = cstr(format!("/proc/self/fd/{}", self.fd.as_raw_fd()).as_bytes())?;
                os(unsafe { libc::open(proc.as_ptr(), libc::O_RDONLY | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC) })?
            }
        };
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(fd.as_raw_fd())?;
        if st.st_mode & libc::S_IFMT != self.kind() || (st.st_dev, st.st_ino) != (self.st.st_dev, self.st.st_ino) {
            return Err(io::Error::other("changed while it was archived"));
        }
        Ok((fd, st))
    }
}

/// The names in the directory open at `d`, sorted, without `.` and `..`.
fn names(d: &OwnedFd) -> io::Result<Vec<Vec<u8>>> {
    // Through its /proc magic link: that very directory, read from the start on a descriptor of its own.
    let mut v = std::fs::read_dir(format!("/proc/self/fd/{}", d.as_raw_fd()))?.map(|e| Ok(e?.file_name().into_vec())).collect::<io::Result<Vec<_>>>()?;
    v.sort();
    Ok(v)
}

/// `dev`: the device the copy started on. A directory on another (/proc, /sys, /dev under `cp vm:/`) is
/// archived as an empty one, as `tar --one-file-system` does.
fn walk(
    out: &mut dyn Write,
    node: Node,
    path: &Path,
    name: Vec<u8>,
    dev: libc::dev_t,
    links: &mut HashMap<(libc::dev_t, libc::ino_t), Vec<u8>>,
) -> io::Result<()> {
    let header = |st: &libc::stat, path: Vec<u8>| Header {
        path,
        mode: st.st_mode,
        uid: st.st_uid.into(),
        gid: st.st_gid.into(),
        mtime: st.st_mtime,
        ..Default::default()
    };
    hook(Step::Typed, path);
    // A device is archived by each name: it has no data to save, and an unpacker that skips devices (the host) would
    // find a link entry's target missing.
    if node.st.st_nlink > 1 && !matches!(node.kind(), libc::S_IFDIR | libc::S_IFSOCK | libc::S_IFCHR | libc::S_IFBLK) {
        match links.entry((node.st.st_dev, node.st.st_ino)) {
            Entry::Occupied(first) => {
                let mut h = header(&node.st, name);
                (h.kind, h.link) = (b'1', first.get().clone());
                return write_header(out, &h);
            }
            Entry::Vacant(first) => {
                first.insert(name.clone());
            }
        }
    }
    match node.kind() {
        libc::S_IFDIR => {
            let (d, st) = node.read().map_err(|e| with(path.display(), e))?;
            // One descriptor per level of the walk: the directory's, which its entries are opened from.
            drop(node);
            let entries = if st.st_dev == dev { names(&d).map_err(|e| with(path.display(), e))? } else { Vec::new() };
            let h = header(&st, name);
            let mut dir = h.clone();
            (dir.kind, dir.path) = (b'5', [&h.path[..], b"/"].concat());
            write_header(out, &dir)?;
            for e in entries {
                let p = path.join(std::ffi::OsStr::from_bytes(&e));
                hook(Step::Listed, &p);
                let child = match Node::open(d.as_raw_fd(), &cstr(&e)?, libc::O_NOFOLLOW) {
                    // Gone since it was listed: as if it had never been there.
                    Err(err) if err.raw_os_error() == Some(libc::ENOENT) => continue,
                    r => r.map_err(|err| with(p.display(), err))?,
                };
                walk(out, child, &p, [&h.path[..], b"/", &e].concat(), dev, links)?;
            }
            Ok(())
        }
        libc::S_IFREG => {
            let (fd, st) = node.read().map_err(|e| with(path.display(), e))?;
            let mut f = File::from(fd);
            let mut h = header(&st, name);
            (h.kind, h.size) = (b'0', st.st_size as u64);
            write_header(out, &h)?;
            let n = io::copy(&mut (&mut f).take(h.size), out).map_err(|e| with(path.display(), e))?;
            // A file that shrank meanwhile is padded to the size its header says.
            zeros(out, padded(h.size)? - n)
        }
        kind => {
            let mut h = header(&node.st, name);
            h.kind = match kind {
                libc::S_IFLNK => {
                    // The link this fd holds (an empty name: the fd's own node).
                    let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
                    let n = unsafe { libc::readlinkat(node.fd.as_raw_fd(), c"".as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
                    if n < 0 {
                        return Err(with(path.display(), io::Error::last_os_error()));
                    }
                    buf.truncate(n as usize);
                    h.link = buf;
                    b'2'
                }
                libc::S_IFIFO => b'6',
                libc::S_IFCHR | libc::S_IFBLK => {
                    h.dev = (libc::major(node.st.st_rdev), libc::minor(node.st.st_rdev));
                    if kind == libc::S_IFCHR {
                        b'3'
                    } else {
                        b'4'
                    }
                }
                _ => {
                    warn!("flexvm: cp: skipping {} (a socket)", path.display());
                    return Ok(());
                }
            };
            write_header(out, &h)
        }
    }
}

struct Reader<'a> {
    r: &'a mut dyn Read,
    /// The current entry's data and padding still unread.
    left: u64,
}

fn num(field: &[u8]) -> io::Result<u64> {
    if field[0] & 0x80 != 0 {
        return field[1..]
            .iter()
            .try_fold(u64::from(field[0] & 0x7f), |v, &b| v.checked_mul(256).map(|v| v + u64::from(b)))
            .ok_or_else(|| invalid("number too big"));
    }
    let digits: Vec<u8> = field.iter().copied().skip_while(|&b| b == b' ').take_while(|&b| b != 0 && b != b' ').collect();
    match digits.is_empty() {
        true => Ok(0),
        false => u64::from_str_radix(std::str::from_utf8(&digits).unwrap_or("x"), 8).map_err(|_| invalid("bad number in a tar header")),
    }
}

fn field(b: &[u8]) -> Vec<u8> {
    b.iter().copied().take_while(|&c| c != 0).collect()
}

impl Reader<'_> {
    fn skip(&mut self) -> io::Result<()> {
        let n = io::copy(&mut (&mut *self.r).take(self.left), &mut io::sink())?;
        if n < std::mem::take(&mut self.left) {
            return Err(invalid("the archive ends inside an entry"));
        }
        Ok(())
    }

    fn data(&mut self, size: u64, out: &mut dyn Write) -> io::Result<()> {
        if io::copy(&mut (&mut *self.r).take(size), out)? < size {
            return Err(invalid("the archive ends inside an entry"));
        }
        self.left = self.left.checked_sub(size).ok_or_else(|| invalid("an entry's data past its end"))?;
        Ok(())
    }

    fn record(&mut self, size: u64) -> io::Result<Vec<u8>> {
        if size > MAX_RECORD {
            return Err(invalid(format!("an extended header of {size} bytes")));
        }
        let mut v = Vec::new();
        self.left = padded(size)?;
        self.data(size, &mut v)?;
        self.skip()?;
        Ok(v)
    }

    fn next(&mut self) -> io::Result<Option<Header>> {
        self.skip()?;
        let (mut path, mut link, mut pax) = (None, None, Vec::new());
        // What an entry's extended headers hold, in all: each one is `MAX_RECORD` at most, and so are they all.
        let mut extended = 0u64;
        loop {
            let mut b = Vec::with_capacity(BLOCK);
            (&mut *self.r).take(BLOCK as u64).read_to_end(&mut b)?;
            match b.len() {
                // Without its end-of-archive block: cut short (its maker failed), never taken as complete.
                0 => return Err(invalid("the archive was cut short")),
                BLOCK => {}
                _ => return Err(invalid("the archive ends inside a header")),
            }
            if b.iter().all(|&x| x == 0) {
                return Ok(None);
            }
            let stored = num(&b[148..156])?;
            let sum: u64 = b.iter().enumerate().map(|(i, &x)| if (148..156).contains(&i) { 32 } else { u64::from(x) }).sum();
            if sum != stored {
                return Err(invalid("bad tar header checksum"));
            }
            let size = num(&b[124..136])?;
            if matches!(b[156], b'x' | b'g' | b'L' | b'K') {
                extended = extended.saturating_add(size);
                if extended > MAX_RECORD {
                    return Err(invalid(format!("extended headers of more than {MAX_RECORD} bytes for one entry")));
                }
            }
            match b[156] {
                // Its sparse map can extend past the header in blocks not counted in size.
                b'S' => return Err(invalid("old-GNU sparse entries are not supported")),
                b'x' => {
                    let rec = self.record(size)?;
                    let mut rest = &rec[..];
                    while !rest.is_empty() {
                        let len = rest.iter().position(|&c| c == b' ').and_then(|sp| std::str::from_utf8(&rest[..sp]).ok()?.parse::<usize>().ok());
                        let Some(len) = len.filter(|&l| l <= rest.len() && l > 0 && rest[l - 1] == b'\n') else { return Err(invalid("bad PAX record")) };
                        let kv = &rest[rest.iter().position(|&c| c == b' ').unwrap_or(0) + 1..len - 1];
                        let eq = kv.iter().position(|&c| c == b'=').ok_or_else(|| invalid("bad PAX record"))?;
                        // Every GNU PAX sparse format (0.0, 0.1, 1.0) marks its entry with these keys; its payload is
                        // packed (1.0 also prefixes a map), so writing it out as a regular file would corrupt it.
                        if kv[..eq].starts_with(b"GNU.sparse.") {
                            return Err(invalid("PAX sparse entries are not supported"));
                        }
                        pax.push((String::from_utf8_lossy(&kv[..eq]).into_owned(), kv[eq + 1..].to_vec()));
                        rest = &rest[len..];
                    }
                    continue;
                }
                b'g' => {
                    self.left = padded(size)?;
                    self.skip()?;
                    continue;
                }
                b'L' => path = Some(field(&self.record(size)?)),
                b'K' => link = Some(field(&self.record(size)?)),
                _ => {}
            }
            if matches!(b[156], b'L' | b'K') {
                continue;
            }
            let mut h = Header {
                path: field(&b[..100]),
                link: field(&b[157..257]),
                kind: b[156],
                mode: num(&b[100..108])? as u32,
                uid: num(&b[108..116])?,
                gid: num(&b[116..124])?,
                size,
                mtime: num(&b[136..148])? as i64,
                dev: (num(&b[329..337])? as u32, num(&b[337..345])? as u32),
            };
            if &b[257..263] == b"ustar\0" && b[345] != 0 {
                h.path = [field(&b[345..500]), b"/".to_vec(), h.path].concat();
            }
            h.path = path.unwrap_or(h.path);
            h.link = link.unwrap_or(h.link);
            for (k, v) in pax {
                let bad = || invalid(format!("bad PAX {k}"));
                let n = || String::from_utf8_lossy(&v).split('.').next().unwrap_or("").parse::<i64>().map_err(|_| bad());
                // Never negative: -1 is not taken as u64::MAX.
                let u = || n().and_then(|n| u64::try_from(n).map_err(|_| bad()));
                match k.as_str() {
                    "path" => h.path = v.clone(),
                    "linkpath" => h.link = v.clone(),
                    "size" => h.size = u()?,
                    "uid" => h.uid = u()?,
                    "gid" => h.gid = u()?,
                    "mtime" => h.mtime = n()?,
                    _ => {}
                }
            }
            self.left = padded(h.size)?;
            return Ok(Some(h));
        }
    }
}

/// What `cp NAME:PATH DST` asked for, known on the host without asking the guest: the top entry `create` names
/// `basename(PATH)`, or the directory's contents (PATH ending in `/.`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Top {
    Named(Vec<u8>),
    Contents,
}

/// The top `create(src)` makes, from `src` alone. A last component of `..` (which `create` resolves in its filesystem) is
/// taken lexically from `/`, where a guest path starts, to a name: a guest that resolves it otherwise has its archive
/// refused. One that comes to `/` lexically is refused here: through a link (`/bin/..`, with `/bin -> usr/bin`) it is
/// `usr` in the guest, and taken as contents, it would let the guest name anything below DST.
#[allow(dead_code)] // Only the host checks a guest's archive.
pub fn top_of(src: &str) -> io::Result<Top> {
    if src == "." || src.ends_with("/.") {
        return Ok(Top::Contents);
    }
    let trimmed = src.trim_end_matches('/');
    let named = |c: &str| if c.is_empty() || c == "." { Top::Contents } else { Top::Named(c.as_bytes().to_vec()) };
    match trimmed.rsplit('/').next().unwrap_or("") {
        ".." => {
            let mut comps = Vec::new();
            for c in trimmed.split('/') {
                match c {
                    "" | "." => {}
                    ".." => drop(comps.pop()),
                    c => comps.push(c),
                }
            }
            match comps.last() {
                Some(c) => Ok(named(c)),
                None => Err(io::Error::other(format!("{src}: a path whose .. comes to /; give /. for its contents"))),
            }
        }
        c => Ok(named(c)),
    }
}

pub enum Dest<'a> {
    /// docker cp's DST rules, applied to the archive's top entry (see below), whatever that is named: an archive the user made.
    Cp(&'a str),
    /// docker cp's DST rules for a guest's archive (`cp NAME:PATH DST`): its entries must be all below the top asked for
    /// (`top_of(PATH)`), or for `Top::Contents`, anything below DST. The guest never chooses what is written outside that.
    #[allow(dead_code)] // Only the host unpacks a guest's archive.
    Guest(&'a str, &'a Top),
    /// `cp - NAME:DIR`: an existing directory the archive is unpacked into as it is.
    #[allow(dead_code)] // Only the guest unpacks a user's archive.
    Into(&'a str),
}

/// An entry's name as components: no `..`, nothing absolute (but in an archive the user gave, `into`).
fn components(path: &[u8], into: bool) -> io::Result<Vec<Vec<u8>>> {
    let name = || String::from_utf8_lossy(path).into_owned();
    if path.contains(&0) {
        return Err(invalid(format!("{}: a name with a nul byte", name())));
    }
    if path.first() == Some(&b'/') && !into {
        return Err(invalid(format!("{}: an absolute name", name())));
    }
    let mut v = Vec::new();
    for c in path.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => return Err(invalid(format!("{}: a name with ..", name()))),
            c => v.push(c.to_vec()),
        }
    }
    Ok(v)
}

/// The directory at `comps` below `base`, each component opened without following a symlink; missing ones made if `make`.
fn walk_dir(base: &OwnedFd, comps: &[Vec<u8>], make: Option<Option<(u32, u32)>>) -> io::Result<OwnedFd> {
    let mut fd = base.try_clone()?;
    for c in comps {
        let name = cstr(c)?;
        let open = |at: RawFd| os(unsafe { libc::openat(at, name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) });
        let next = match (open(fd.as_raw_fd()), make) {
            (Err(e), Some(owner)) if e.raw_os_error() == Some(libc::ENOENT) => {
                os(unsafe { libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o755) })?;
                let new = open(fd.as_raw_fd())?;
                if let Some((u, g)) = owner {
                    os(unsafe { libc::fchown(new, u, g) })?;
                }
                new
            }
            (r, _) => r.map_err(|e| with(String::from_utf8_lossy(c), e))?,
        };
        fd = unsafe { OwnedFd::from_raw_fd(next) };
    }
    Ok(fd)
}

/// Where a docker cp's DST puts the archive's top entry: the directory, and the top's name and what it becomes there
/// (None: the contents go into the directory).
type Target = (OwnedFd, Option<(Vec<u8>, Vec<u8>)>);

#[cfg(test)]
thread_local! {
    /// Who `extract` follows DST links of, in place of its euid.
    static AS_UID: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// DST pinned: the directory it is in (its path followed), its name there, and what it is (None: missing), all
/// opened once (`O_PATH`), so what is checked is what is unpacked into. A link at DST itself (with a trailing slash
/// too) is followed only if root or whoever unpacks made it (merged /usr's /bin, /var/run): one that someone else
/// planted in a directory they may write does not redirect the copy. The approved link's target is read from the
/// link opened, and resolved from the pinned directory: a link swapped in after it was checked is never read.
struct Pinned {
    parent: OwnedFd,
    leaf: CString,
    node: Option<Node>,
}

fn pin(dst: &str) -> io::Result<Pinned> {
    let trimmed = dst.trim_end_matches('/');
    let (parent, leaf) = match trimmed.rsplit_once('/') {
        Some((p, l)) => (if p.is_empty() { "/" } else { p }, l),
        None if trimmed.is_empty() && dst.starts_with('/') => ("/", "."),
        None => (".", trimmed),
    };
    let fd = os(unsafe { libc::open(cstr(parent.as_bytes())?.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
    let (parent, leaf) = (unsafe { OwnedFd::from_raw_fd(fd) }, cstr(leaf.as_bytes())?);
    let missing = |e: &io::Error| e.raw_os_error() == Some(libc::ENOENT);
    let node = match Node::open(parent.as_raw_fd(), &leaf, libc::O_NOFOLLOW) {
        Err(e) if missing(&e) => None,
        Err(e) => return Err(e),
        Ok(link) if link.kind() == libc::S_IFLNK => {
            let me = unsafe { libc::geteuid() };
            #[cfg(test)]
            let me = AS_UID.with(|u| u.get()).unwrap_or(me);
            if link.st.st_uid != 0 && link.st.st_uid != me {
                return Err(io::Error::other(format!("a link that uid {} made, not followed: give its target", link.st.st_uid)));
            }
            hook(Step::Approved, Path::new(dst));
            let mut to = vec![0u8; libc::PATH_MAX as usize];
            let n = unsafe { libc::readlinkat(link.fd.as_raw_fd(), c"".as_ptr(), to.as_mut_ptr().cast(), to.len()) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            to.truncate(n as usize);
            // The rest of the way is followed, as the link would be; a dangling one is as missing as before.
            match Node::open(parent.as_raw_fd(), &cstr(&to)?, 0) {
                Err(e) if missing(&e) => None,
                r => Some(r?),
            }
        }
        Ok(node) => Some(node),
    };
    // A trailing slash asks for a directory, as the kernel's lookup of `x/` does: a file (or a link to one) is not
    // replaced through it.
    if dst.ends_with('/') && node.as_ref().is_some_and(|n| n.kind() != libc::S_IFDIR) {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok(Pinned { parent, leaf, node })
}

/// A directory opened for writing into, from its `O_PATH` fd: the same inode, no name looked up again.
fn reopen_dir(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let fd = os(unsafe { libc::openat(fd.as_raw_fd(), c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// DST for unpacking into: an existing directory.
fn into_dir(dst: &str) -> io::Result<OwnedFd> {
    match pin(dst)?.node {
        Some(n) if n.kind() == libc::S_IFDIR => reopen_dir(&n.fd),
        Some(_) => Err(io::Error::from_raw_os_error(libc::ENOTDIR)),
        None => Err(io::Error::from_raw_os_error(libc::ENOENT)),
    }
}

/// DST for a directory's contents: made if missing.
fn contents(dst: &str) -> io::Result<Target> {
    let p = pin(dst).map_err(|e| with(dst, e))?;
    let dir = match &p.node {
        Some(n) if n.kind() == libc::S_IFDIR => reopen_dir(&n.fd),
        Some(_) => Err(io::Error::from_raw_os_error(libc::ENOTDIR)),
        None => {
            let (at, name) = (p.parent.as_raw_fd(), p.leaf.as_ptr());
            os(unsafe { libc::mkdirat(at, name, 0o777) })
                .and_then(|_| os(unsafe { libc::openat(at, name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) }))
                .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        }
    };
    Ok((dir.map_err(|e| with(dst, e))?, None))
}

fn target(dst: &str, comps: &[Vec<u8>], first: &Header) -> io::Result<Target> {
    let Some(root) = comps.first() else { return contents(dst) };
    let is_dir = comps.len() > 1 || first.kind == b'5';
    let p = pin(dst).map_err(|e| with(dst, e))?;
    match &p.node {
        Some(n) if n.kind() == libc::S_IFDIR => return Ok((reopen_dir(&n.fd)?, Some((root.clone(), root.clone())))),
        Some(_) if is_dir => return Err(io::Error::other(format!("cannot copy a directory onto a file: {dst}"))),
        None if dst.ends_with('/') && !is_dir => return Err(io::Error::other(format!("no such directory: {dst}"))),
        _ => {}
    }
    if matches!(p.leaf.as_bytes(), b"" | b"." | b"..") {
        return Err(io::Error::other(format!("bad destination {dst}")));
    }
    Ok((reopen_dir(&p.parent)?, Some((root.clone(), p.leaf.into_bytes()))))
}

/// Unpacks `input` at `dest`. `owner`: everything is chowned to it (lchown for links); None leaves the files
/// owned by whoever runs this (the host, root under sudo, from a guest's archive), and then no setuid or setgid
/// bit and no device node comes from the archive. Modes and mtimes are kept; a directory's after its contents.
pub fn extract(input: &mut dyn Read, dest: Dest, owner: Option<(u32, u32)>) -> io::Result<()> {
    let mut rd = Reader { r: input, left: 0 };
    let Some(first) = rd.next()? else { return Ok(()) };
    let into = matches!(dest, Dest::Into(_));
    let (base, top) = match dest {
        Dest::Into(dir) => (into_dir(dir).map_err(|e| with(dir, e))?, None),
        Dest::Cp(dst) => target(dst, &components(&first.path, false)?, &first)?,
        Dest::Guest(dst, Top::Contents) => {
            components(&first.path, false)?;
            contents(dst)?
        }
        Dest::Guest(dst, Top::Named(want)) => {
            let comps = components(&first.path, false)?;
            if comps.first() != Some(want) {
                let (got, want) = (String::from_utf8_lossy(&first.path), String::from_utf8_lossy(want));
                return Err(invalid(format!("the vm's archive starts with {got:?}, not {want:?}, the name asked for")));
            }
            target(dst, &comps, &first)?
        }
    };
    let rename = |path: &[u8]| -> io::Result<Vec<Vec<u8>>> {
        let mut comps = components(path, into)?;
        if let Some((root, to)) = &top {
            if comps.first() != Some(root) {
                return Err(invalid(format!("{}: outside the archive's top entry", String::from_utf8_lossy(path))));
            }
            comps[0] = to.clone();
        }
        Ok(comps)
    };
    // Each directory by its path as unpacked (its components joined by `/`, kept once), with the order it first
    // came in and its last entry's metadata: that goes on at the end, deepest (last come) first. Bounded: a guest's
    // archive must not make the host keep more than `MAX_DIRS`.
    let (mut dirs, mut kept) = (std::collections::HashMap::<Vec<u8>, (usize, Header)>::new(), 0);
    let mut next = Some(first);
    while let Some(e) = next.take() {
        let comps = rename(&e.path)?;
        if let Some((leaf, parent)) = comps.split_last() {
            let link = if e.kind == b'1' { rename(&e.link)? } else { Vec::new() };
            unpack(&base, parent, leaf, &link, &e, &mut rd, owner).map_err(|err| with(String::from_utf8_lossy(&e.path), err))?;
            if e.kind == b'5' {
                let (n, meta) = (dirs.len(), Header { path: Vec::new(), link: Vec::new(), ..e });
                match dirs.entry(comps.join(&b'/')) {
                    Entry::Occupied(mut o) => o.get_mut().1 = meta,
                    Entry::Vacant(v) => {
                        kept += v.key().len() + DIR_COST;
                        if kept > MAX_DIRS {
                            return Err(invalid(format!("more directories than cp keeps ({} MiB of names)", MAX_DIRS >> 20)));
                        }
                        v.insert((n, meta));
                    }
                }
            }
        }
        next = rd.next()?;
    }
    let mut dirs: Vec<_> = dirs.into_iter().collect();
    dirs.sort_unstable_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
    for (path, (_, e)) in dirs {
        let comps: Vec<Vec<u8>> = path.split(|&b| b == b'/').map(<[u8]>::to_vec).collect();
        let fd = walk_dir(&base, &comps, None).map_err(|err| with(String::from_utf8_lossy(&path), err))?;
        finish(fd.as_raw_fd(), &e, owner)?;
    }
    Ok(())
}

/// An archive's mode as given to what it makes: without setuid and setgid unless chowned (`extract`).
fn mode(e: &Header, owner: Option<(u32, u32)>) -> libc::mode_t {
    e.mode & if owner.is_some() { 0o7777 } else { 0o1777 }
}

fn times(e: &Header) -> [libc::timespec; 2] {
    [libc::timespec { tv_sec: e.mtime as libc::time_t, tv_nsec: 0 }; 2]
}

/// Owner, then mode (a chown clears setuid), then mtime.
fn finish(fd: RawFd, e: &Header, owner: Option<(u32, u32)>) -> io::Result<()> {
    if let Some((u, g)) = owner {
        os(unsafe { libc::fchown(fd, u, g) })?;
    }
    os(unsafe { libc::fchmod(fd, mode(e, owner)) })?;
    os(unsafe { libc::futimens(fd, times(e).as_ptr()) }).map(drop)
}

/// Metadata of a node `finish` cannot open (a link, a fifo, a device), by name, not following it.
fn finish_at(d: RawFd, name: &CString, e: &Header, owner: Option<(u32, u32)>, chmod: bool) -> io::Result<()> {
    if let Some((u, g)) = owner {
        os(unsafe { libc::fchownat(d, name.as_ptr(), u, g, libc::AT_SYMLINK_NOFOLLOW) })?;
    }
    if chmod {
        // fchmodat follows a link: one put in its place since it was made would be what changes. Through an O_PATH
        // descriptor of the node itself (checked to be none), by its /proc magic link, it is the node.
        let fd = os(unsafe { libc::openat(d, name.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) })?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        os(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
        if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(io::Error::other("replaced by a symlink while unpacking"));
        }
        os(unsafe { libc::chmod(cstr(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_bytes())?.as_ptr(), mode(e, owner)) })?;
    }
    os(unsafe { libc::utimensat(d, name.as_ptr(), times(e).as_ptr(), libc::AT_SYMLINK_NOFOLLOW) }).map(drop)
}

fn unpack(base: &OwnedFd, parent: &[Vec<u8>], leaf: &[u8], link: &[Vec<u8>], e: &Header, rd: &mut Reader, owner: Option<(u32, u32)>) -> io::Result<()> {
    // Before anything is made or removed: what it would replace is left as it is.
    let path = || String::from_utf8_lossy(&e.path);
    let skip = match e.kind {
        b'3' | b'4' if owner.is_none() => Some(format!("device {}: devices are copied into a vm only", path())),
        0 | b'0'..=b'7' => None,
        k => Some(format!("{} (tar entry type {:?})", path(), k as char)),
    };
    if let Some(why) = skip {
        warn!("flexvm: cp: skipping {why}");
        return Ok(());
    }
    let dir = walk_dir(base, parent, Some(owner))?;
    let (d, name) = (dir.as_raw_fd(), cstr(leaf)?);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let exists = unsafe { libc::fstatat(d, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0;
    let is_dir = exists && st.st_mode & libc::S_IFMT == libc::S_IFDIR;
    if e.kind == b'5' {
        if exists && !is_dir {
            os(unsafe { libc::unlinkat(d, name.as_ptr(), 0) })?;
        }
        if !is_dir {
            os(unsafe { libc::mkdirat(d, name.as_ptr(), 0o700) })?;
        }
        return Ok(());
    }
    if is_dir {
        return Err(io::Error::other("a directory is in the way"));
    }
    if exists {
        os(unsafe { libc::unlinkat(d, name.as_ptr(), 0) })?;
    }
    match e.kind {
        0 | b'0' | b'7' => {
            let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let mut f = unsafe { File::from_raw_fd(os(libc::openat(d, name.as_ptr(), flags, 0o600))?) };
            rd.data(e.size, &mut f)?;
            finish(f.as_raw_fd(), e, owner)
        }
        b'2' => {
            os(unsafe { libc::symlinkat(cstr(&e.link)?.as_ptr(), d, name.as_ptr()) })?;
            finish_at(d, &name, e, owner, false)
        }
        b'1' => {
            let (target, tparent) = link.split_last().ok_or_else(|| invalid("a hard link to nothing"))?;
            let tdir = walk_dir(base, tparent, None)?;
            os(unsafe { libc::linkat(tdir.as_raw_fd(), cstr(target)?.as_ptr(), d, name.as_ptr(), 0) }).map(drop)
        }
        b'6' => {
            os(unsafe { libc::mkfifoat(d, name.as_ptr(), 0o600) })?;
            finish_at(d, &name, e, owner, true)
        }
        _ => {
            let kind = if e.kind == b'3' { libc::S_IFCHR } else { libc::S_IFBLK };
            match os(unsafe { libc::mknodat(d, name.as_ptr(), kind | 0o600, libc::makedev(e.dev.0, e.dev.1)) }) {
                Ok(_) => finish_at(d, &name, e, owner, true),
                Err(err) => {
                    warn!("flexvm: cp: skipping device {}: {err}", path());
                    Ok(())
                }
            }
        }
    }
}

/// flexvm-init's multicall entry: `[--flexvm-cp-out, SRC]` writes create(SRC)'s tar to stdout; `[--flexvm-cp-in, cp|into, DST]`
/// extracts stdin there with owner Some((0, 0)). Returns None if `args` (argv without argv[0]) is not one of these; else the exit
/// status (errors printed to stderr as "flexvm: cp: ...", status 1).
#[allow(dead_code)] // The host only makes and unpacks archives.
pub fn tool_main(args: &[String]) -> Option<i32> {
    let res = match args {
        [m, src] if m == "--flexvm-cp-out" => {
            let mut out = io::BufWriter::with_capacity(64 << 10, io::stdout().lock());
            create(src, &mut out)
        }
        [m, how, dst] if m == "--flexvm-cp-in" => {
            let dest = match how.as_str() {
                "cp" => Dest::Cp(dst),
                "into" => Dest::Into(dst),
                _ => return None,
            };
            let mut input = io::stdin().lock();
            // What follows the archive (a tar's padding to its record size) is read too, so its writer never sees EPIPE.
            extract(&mut input, dest, Some((0, 0))).and_then(|()| io::copy(&mut input, &mut io::sink()).map(drop))
        }
        _ => return None,
    };
    Some(match res {
        Ok(()) => 0,
        Err(e) => {
            warn!("flexvm: cp: {e}");
            1
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Tmp {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("flexvm-tar-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }

        fn s(&self, rel: &str) -> String {
            self.0.join(rel).to_str().unwrap().to_string()
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            fn writable(p: &Path) {
                if std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) {
                    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
                    std::fs::read_dir(p).into_iter().flatten().flatten().for_each(|e| writable(&e.path()));
                }
            }
            writable(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tar_of(src: &str) -> Vec<u8> {
        let mut v = Vec::new();
        create(src, &mut v).unwrap();
        v
    }

    fn unpack_to(archive: &[u8], dest: Dest) -> io::Result<()> {
        extract(&mut &archive[..], dest, None)
    }

    /// An archive by hand: (name, kind, link target or file data).
    fn archive(entries: &[(&str, u8, &str)]) -> Vec<u8> {
        let mut v = Vec::new();
        for &(name, kind, x) in entries {
            let data = if kind == b'0' { x.as_bytes() } else { b"" };
            let link = if kind == b'0' { Vec::new() } else { x.as_bytes().to_vec() };
            let h = Header { path: name.into(), link, kind, mode: if kind == b'5' { 0o755 } else { 0o644 }, size: data.len() as u64, ..Default::default() };
            write_header(&mut v, &h).unwrap();
            v.extend_from_slice(data);
            v.resize(padded(v.len() as u64).unwrap() as usize, 0);
        }
        v.extend_from_slice(&[0; BLOCK * 2]);
        v
    }

    fn set_mtime(p: &str, secs: i64) {
        let t = [libc::timespec { tv_sec: secs, tv_nsec: 0 }; 2];
        assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, cstr(p.as_bytes()).unwrap().as_ptr(), t.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) }, 0);
    }

    /// Type, mode, mtime and contents (or link) of every node below `root`, by relative path.
    fn listing(root: &Path) -> Vec<(String, u32, i64, Vec<u8>)> {
        let mut out = Vec::new();
        fn go(root: &Path, p: &Path, out: &mut Vec<(String, u32, i64, Vec<u8>)>) {
            let m = std::fs::symlink_metadata(p).unwrap();
            let rel = p.strip_prefix(root).unwrap().display().to_string();
            let body = match () {
                _ if m.is_file() => std::fs::read(p).unwrap(),
                _ if m.file_type().is_symlink() => std::fs::read_link(p).unwrap().into_os_string().into_vec(),
                _ => Vec::new(),
            };
            let mtime = if m.file_type().is_symlink() { 0 } else { m.mtime() };
            out.push((rel, m.mode(), mtime, body));
            if m.is_dir() {
                let mut es: Vec<_> = std::fs::read_dir(p).unwrap().map(|e| e.unwrap().path()).collect();
                es.sort();
                es.iter().for_each(|e| go(root, e, out));
            }
        }
        go(root, root, &mut out);
        out
    }

    fn tree(t: &Tmp) -> String {
        let src = t.s("src");
        let long = format!("{src}/{}", ["d".repeat(60), "e".repeat(60), "f".repeat(60), "g".repeat(60), "h".repeat(60)].join("/"));
        for d in ["a/b", "ro", &long[src.len() + 1..]] {
            std::fs::create_dir_all(format!("{src}/{d}")).unwrap();
        }
        std::fs::write(format!("{src}/a/b/c.txt"), "hello\n").unwrap();
        std::fs::write(format!("{src}/ro/inner"), "inside").unwrap();
        std::fs::write(format!("{src}/empty"), "").unwrap();
        std::fs::write(format!("{long}/{}", "x".repeat(90)), "deep").unwrap();
        let big: Vec<u8> = (0..3 << 20).map(|i: u32| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        std::fs::write(format!("{src}/big"), big).unwrap();
        std::fs::write(format!("{src}/suid"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(format!("{src}/suid"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        symlink("a/b/c.txt", format!("{src}/link")).unwrap();
        symlink("/nowhere/at/all", format!("{src}/dangling")).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cstr(format!("{src}/fifo").as_bytes()).unwrap().as_ptr(), 0o640) }, 0);
        set_mtime(&format!("{src}/a/b/c.txt"), 1_000_000_000);
        set_mtime(&format!("{src}/a"), 1_100_000_000);
        std::fs::set_permissions(format!("{src}/ro"), std::fs::Permissions::from_mode(0o555)).unwrap();
        src
    }

    /// #868: what is kept of the directories is bounded (each one's components once), the archive then refused.
    #[test]
    fn too_many_directories_are_refused() {
        let t = Tmp::new("many-dirs");
        let src = t.s("src");
        for i in 0..MAX_DIRS / DIR_COST + 1 {
            std::fs::create_dir_all(format!("{src}/{i}")).unwrap();
        }
        std::fs::create_dir(t.s("dst")).unwrap();
        let e = extract(&mut &tar_of(&src)[..], Dest::Cp(&t.s("dst")), None).unwrap_err();
        assert!(e.to_string().contains("more directories than cp keeps"), "{e}");
        // Fewer, they are all unpacked.
        std::fs::remove_dir(format!("{src}/0")).unwrap();
        for i in MAX_DIRS / DIR_COST / 2..MAX_DIRS / DIR_COST + 1 {
            std::fs::remove_dir(format!("{src}/{i}")).unwrap();
        }
        std::fs::create_dir(t.s("dst2")).unwrap();
        extract(&mut &tar_of(&src)[..], Dest::Cp(&t.s("dst2")), None).unwrap();
        assert_eq!(std::fs::read_dir(t.s("dst2/src")).unwrap().count(), MAX_DIRS / DIR_COST / 2 - 1);
    }

    #[test]
    fn a_tree_round_trips() {
        let t = Tmp::new("round");
        let src = tree(&t);
        std::fs::create_dir(t.s("dst")).unwrap();
        // Chowned (to whoever runs this: no root needed), as the guest unpacks: setuid kept.
        let me = unsafe { (libc::getuid(), libc::getgid()) };
        extract(&mut &tar_of(&src)[..], Dest::Cp(&t.s("dst")), Some(me)).unwrap();
        let (want, got) = (listing(Path::new(&src)), listing(&t.0.join("dst/src")));
        assert_eq!(want.len(), got.len());
        for (w, g) in want.iter().zip(&got).skip(1) {
            assert_eq!(w, g);
        }
        assert!(got.iter().any(|(p, m, ..)| p == "suid" && m & 0o7777 == 0o4755));
        // Not chowned, as the host unpacks a guest's archive: no setuid.
        std::fs::create_dir(t.s("host")).unwrap();
        unpack_to(&tar_of(&src), Dest::Cp(&t.s("host"))).unwrap();
        assert!(listing(&t.0.join("host/src")).iter().any(|(p, m, ..)| p == "suid" && m & 0o7777 == 0o755));
        assert!(got.iter().any(|(p, ..)| p.len() > 300), "the long path");
        // Contents (`src/.`) into a new directory; `src/` of a link to a directory follows it.
        unpack_to(&tar_of(&format!("{src}/.")), Dest::Cp(&t.s("contents"))).unwrap();
        assert_eq!(std::fs::read(t.0.join("contents/a/b/c.txt")).unwrap(), b"hello\n");
        symlink(&src, t.0.join("tolink")).unwrap();
        unpack_to(&tar_of(&t.s("tolink")), Dest::Cp(&t.s("dst"))).unwrap();
        assert!(std::fs::symlink_metadata(t.0.join("dst/tolink")).unwrap().file_type().is_symlink());
        unpack_to(&tar_of(&format!("{}/", t.s("tolink"))), Dest::Cp(&t.s("followed"))).unwrap();
        assert_eq!(std::fs::read(t.0.join("followed/a/b/c.txt")).unwrap(), b"hello\n");
    }

    #[test]
    fn hard_links_are_archived_once_and_round_trip() {
        for kind in [b'0', b'2', b'6'] {
            let t = Tmp::new("hard-links");
            std::fs::create_dir_all(t.s("src/z")).unwrap();
            let first = format!("a{}", "x".repeat(100));
            let path = t.0.join("src").join(&first);
            match kind {
                b'0' => std::fs::write(&path, b"hello\n").unwrap(),
                b'2' => symlink("missing", &path).unwrap(),
                _ => assert_eq!(unsafe { libc::mkfifo(cstr(path.as_os_str().as_bytes()).unwrap().as_ptr(), 0o640) }, 0),
            }
            for name in ["b", "c"] {
                std::fs::hard_link(&path, t.0.join("src/z").join(name)).unwrap();
            }
            for suffix in ["", "/."] {
                let src = format!("{}{suffix}", t.s("src"));
                let tar = tar_of(&src);
                let mut r = &tar[..];
                let mut rd = Reader { r: &mut r, left: 0 };
                let mut entries = Vec::new();
                while let Some(h) = rd.next().unwrap() {
                    if h.kind != b'5' {
                        entries.push(h);
                    }
                }
                assert_eq!(entries.len(), 3);
                let top = if suffix.is_empty() { "src" } else { "." };
                assert_eq!(entries[0].path, format!("{top}/{first}").as_bytes());
                assert_eq!(entries[0].kind, kind);
                assert_eq!(entries[0].size, if kind == b'0' { 6 } else { 0 });
                for h in &entries[1..] {
                    assert_eq!(h.kind, b'1');
                    assert_eq!(h.size, 0);
                    assert_eq!(h.link, entries[0].path);
                }
                let dst = t.s(if suffix.is_empty() { "named" } else { "contents" });
                unpack_to(&tar, Dest::Guest(&dst, &top_of(&src).unwrap())).unwrap();
                let original = std::fs::symlink_metadata(Path::new(&dst).join(&first)).unwrap();
                for name in ["z/b", "z/c"] {
                    let linked = std::fs::symlink_metadata(Path::new(&dst).join(name)).unwrap();
                    assert_eq!((linked.dev(), linked.ino()), (original.dev(), original.ino()));
                }
                if kind == b'0' {
                    assert_eq!(std::fs::read(Path::new(&dst).join("z/b")).unwrap(), b"hello\n");
                }
            }
        }
    }

    #[test]
    #[ignore] // root: mknod of a device needs CAP_MKNOD (CI's root step runs it)
    fn hard_linked_devices_skipped_by_the_host_do_not_fail_the_copy() {
        let t = Tmp::new("hard-linked-devices");
        std::fs::create_dir_all(t.s("src")).unwrap();
        let null = cstr(t.s("src/a").as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mknod(null.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) }, 0);
        std::fs::hard_link(t.s("src/a"), t.s("src/b")).unwrap();
        std::fs::write(t.s("src/c"), b"x").unwrap();
        let tar = tar_of(&t.s("src"));
        unpack_to(&tar, Dest::Guest(&t.s("out"), &top_of(&t.s("src")).unwrap())).unwrap();
        assert_eq!(std::fs::read(t.s("out/c")).unwrap(), b"x");
        assert!(std::fs::symlink_metadata(t.s("out/b")).is_err());
    }

    /// Archives `src` with `swap` run once, at `step` of the entry at `at`; returns the archive's entries' names and data.
    fn race(src: &str, at: &Path, step: Step, swap: impl FnOnce() + 'static) -> Vec<(Vec<u8>, u8, Vec<u8>)> {
        let (at, mut swap) = (at.to_path_buf(), Some(swap));
        HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |s, p| {
                if s == step && p == at {
                    if let Some(f) = swap.take() {
                        f();
                    }
                }
            }))
        });
        let tar = tar_of(src);
        HOOK.with(|h| h.borrow_mut().take());
        let (mut r, mut got) = (&tar[..], Vec::new());
        let mut rd = Reader { r: &mut r, left: 0 };
        while let Some(h) = rd.next().unwrap() {
            let mut data = Vec::new();
            rd.data(h.size, &mut data).unwrap();
            got.push((h.path, h.kind, if h.kind == b'2' { h.link } else { data }));
        }
        got
    }

    #[test]
    fn a_link_swapped_in_while_archiving_is_never_followed() {
        let t = Tmp::new("race");
        let (src, secret) = (t.s("src"), t.s("secret"));
        std::fs::create_dir_all(format!("{src}/d")).unwrap();
        std::fs::write(&secret, "the secret").unwrap();
        std::fs::create_dir(t.s("elsewhere")).unwrap();
        std::fs::write(t.0.join("elsewhere/hidden"), "the secret too").unwrap();
        let leaked = |got: &[(Vec<u8>, u8, Vec<u8>)]| got.iter().any(|(_, _, d)| d.windows(10).any(|w| w == b"the secret"));
        let (f, d) = (t.0.join("src/f"), t.0.join("src/d"));
        let swap = |victim: &Path, to: &str| {
            let (victim, to) = (victim.to_path_buf(), to.to_string());
            move || {
                if victim.is_dir() {
                    std::fs::remove_dir_all(&victim).unwrap();
                } else {
                    std::fs::remove_file(&victim).unwrap();
                }
                symlink(&to, &victim).unwrap();
            }
        };

        // Opened and typed as a file, then swapped for a link to the secret: its own contents still.
        std::fs::write(&f, "mine").unwrap();
        let got = race(&src, &f, Step::Typed, swap(&f, &secret));
        assert!(!leaked(&got), "{got:?}");
        assert!(got.iter().any(|(p, k, d)| p == b"src/f" && *k == b'0' && d == b"mine"), "{got:?}");

        // Swapped after it was listed, before it was opened: the link is archived, as a link.
        std::fs::remove_file(&f).unwrap();
        std::fs::write(&f, "mine").unwrap();
        let got = race(&src, &f, Step::Listed, swap(&f, &secret));
        assert!(!leaked(&got), "{got:?}");
        assert!(got.iter().any(|(p, k, l)| p == b"src/f" && *k == b'2' && l == secret.as_bytes()), "{got:?}");

        // A directory typed, then swapped for a link to another: the one it was is listed, nothing of the other.
        std::fs::write(d.join("inner"), "inner").unwrap();
        let got = race(&src, &d, Step::Typed, swap(&d, &t.s("elsewhere")));
        assert!(!leaked(&got), "{got:?}");
        assert!(!got.iter().any(|(p, ..)| p.ends_with(b"hidden")), "{got:?}");
    }

    #[test]
    fn copy_follows_only_its_own_or_roots_destination_links() {
        let t = Tmp::new("destination-symlinks");
        std::fs::create_dir(t.s("outside")).unwrap();
        std::fs::write(t.s("outside/file"), b"original").unwrap();
        // As root, the links are someone's: root's would be followed.
        let owner = match unsafe { libc::geteuid() } {
            0 => 65534,
            me => me,
        };
        // Someone else's links: refused.
        AS_UID.with(|u| u.set(Some(owner ^ 1)));
        for (leaf, to) in [("dir-link", "outside"), ("file-link", "outside/file"), ("dangling", "missing")] {
            symlink(to, t.s(leaf)).unwrap();
            std::os::unix::fs::lchown(t.s(leaf), Some(owner), None).unwrap();
            for suffix in ["", "/", "///"] {
                let dst = format!("{}{suffix}", t.s(leaf));
                for entries in [vec![("file", b'0', "replacement")], vec![("dir", b'5', ""), ("dir/new", b'0', "new")]] {
                    let data = archive(&entries);
                    let e = unpack_to(&data, Dest::Cp(&dst)).unwrap_err();
                    assert!(e.to_string().contains("not followed"), "{dst}: {e}");
                    let top = Top::Named(entries[0].0.as_bytes().to_vec());
                    assert!(unpack_to(&data, Dest::Guest(&dst, &top)).is_err(), "{dst}");
                    assert!(unpack_to(&data, Dest::Guest(&dst, &Top::Contents)).is_err(), "{dst}");
                    assert!(unpack_to(&data, Dest::Into(&dst)).is_err(), "{dst}");
                }
            }
        }
        assert_eq!(std::fs::read(t.s("outside/file")).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(t.s("outside")).unwrap().count(), 1);
        assert!(!t.0.join("missing").exists());
        // Its own (or root's, as /bin of a merged /usr): followed, as docker cp does.
        AS_UID.with(|u| u.set(Some(owner)));
        let data = archive(&[("file", b'0', "new")]);
        unpack_to(&data, Dest::Cp(&t.s("dir-link"))).unwrap();
        unpack_to(&data, Dest::Guest(&format!("{}/", t.s("dir-link")), &Top::Contents)).unwrap();
        unpack_to(&archive(&[("into", b'0', "new")]), Dest::Into(&t.s("dir-link"))).unwrap();
        assert_eq!(std::fs::read(t.s("outside/file")).unwrap(), b"new");
        assert_eq!(std::fs::read(t.s("outside/into")).unwrap(), b"new");
        // With a trailing slash, its link to a file (or the file itself) is no directory: not replaced.
        for leaf in ["file-link", "outside/file"] {
            for suffix in ["/", "//"] {
                let dst = format!("{}{suffix}", t.s(leaf));
                let e = unpack_to(&data, Dest::Cp(&dst)).unwrap_err();
                assert!(e.to_string().contains("Not a directory"), "{dst}: {e}");
                assert!(unpack_to(&data, Dest::Guest(&dst, &Top::Named(b"file".to_vec()))).is_err(), "{dst}");
                assert!(unpack_to(&data, Dest::Guest(&dst, &Top::Contents)).is_err(), "{dst}");
            }
        }
        assert!(std::fs::symlink_metadata(t.s("file-link")).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(t.s("outside/file")).unwrap(), b"new");
    }

    #[test]
    fn a_destination_link_swapped_after_its_check_is_never_read() {
        let t = Tmp::new("destination-swap");
        for d in ["pinned", "elsewhere"] {
            std::fs::create_dir(t.s(d)).unwrap();
        }
        let (link, data) = (t.s("link"), archive(&[("file", b'0', "new")]));
        let dsts = [link.clone(), format!("{link}/")];
        let tops = [None, Some(Top::Contents), Some(Top::Named(b"file".to_vec()))];
        for (n, (dst, top)) in dsts.iter().flat_map(|d| tops.iter().map(move |t| (d, t))).enumerate() {
            let _ = std::fs::remove_file(&link);
            symlink("pinned", &link).unwrap();
            let (at, swapped) = (dst.clone(), std::rc::Rc::new(std::cell::Cell::new(false)));
            let (now, link) = (swapped.clone(), link.clone());
            let elsewhere = t.s("elsewhere");
            HOOK.with(|h| {
                *h.borrow_mut() = Some(Box::new(move |s, p| {
                    if s == Step::Approved && p == Path::new(&at) && !now.replace(true) {
                        // Atomically, as an attacker would: the checked link's name now names another link.
                        let new = format!("{link}.new");
                        symlink(&elsewhere, &new).unwrap();
                        std::fs::rename(&new, &link).unwrap();
                    }
                }))
            });
            let r = match top {
                None => unpack_to(&data, Dest::Cp(dst)),
                Some(top) => unpack_to(&data, Dest::Guest(dst, top)),
            };
            HOOK.with(|h| h.borrow_mut().take());
            r.unwrap();
            assert!(swapped.get(), "case {n}: {dst}");
            assert_eq!(std::fs::read_link(t.s("link")).unwrap(), Path::new(&t.s("elsewhere")), "case {n}");
            assert_eq!(std::fs::read(t.s("pinned/file")).unwrap(), b"new", "case {n}: {dst}");
            std::fs::remove_file(t.s("pinned/file")).unwrap();
            assert_eq!(std::fs::read_dir(t.s("elsewhere")).unwrap().count(), 0, "case {n}: {dst}");
        }
        // Into: the same.
        std::fs::remove_file(t.s("link")).unwrap();
        symlink("pinned", t.s("link")).unwrap();
        let (link, elsewhere) = (t.s("link"), t.s("elsewhere"));
        let at = link.clone();
        HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |s, p| {
                if s == Step::Approved && p == Path::new(&at) {
                    std::fs::remove_file(&at).unwrap();
                    symlink(&elsewhere, &at).unwrap();
                }
            }))
        });
        let r = unpack_to(&data, Dest::Into(&link));
        HOOK.with(|h| h.borrow_mut().take());
        r.unwrap();
        assert_eq!(std::fs::read(t.s("pinned/file")).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(t.s("elsewhere")).unwrap().count(), 0);
    }

    #[test]
    fn docker_cp_destination_rules() {
        let t = Tmp::new("rules");
        std::fs::create_dir_all(t.0.join("dir/sub")).unwrap();
        std::fs::write(t.0.join("dir/sub/f"), "f").unwrap();
        std::fs::write(t.0.join("file"), "new").unwrap();
        std::fs::create_dir(t.0.join("existing")).unwrap();
        std::fs::write(t.0.join("old"), "old contents").unwrap();
        let (file, dir) = (tar_of(&t.s("file")), tar_of(&t.s("dir")));
        unpack_to(&file, Dest::Cp(&t.s("existing"))).unwrap();
        assert_eq!(std::fs::read(t.0.join("existing/file")).unwrap(), b"new");
        unpack_to(&file, Dest::Cp(&t.s("renamed"))).unwrap();
        assert_eq!(std::fs::read(t.0.join("renamed")).unwrap(), b"new");
        unpack_to(&file, Dest::Cp(&t.s("old"))).unwrap();
        assert_eq!(std::fs::read(t.0.join("old")).unwrap(), b"new");
        assert!(unpack_to(&dir, Dest::Cp(&t.s("old"))).unwrap_err().to_string().contains("onto a file"));
        unpack_to(&dir, Dest::Cp(&t.s("newdir"))).unwrap();
        assert_eq!(std::fs::read(t.0.join("newdir/sub/f")).unwrap(), b"f");
        unpack_to(&dir, Dest::Cp(&t.s("existing"))).unwrap();
        assert_eq!(std::fs::read(t.0.join("existing/dir/sub/f")).unwrap(), b"f");
        unpack_to(&tar_of(&format!("{}/.", t.s("dir"))), Dest::Cp(&t.s("existing"))).unwrap();
        assert_eq!(std::fs::read(t.0.join("existing/sub/f")).unwrap(), b"f");
        assert!(unpack_to(&file, Dest::Cp(&format!("{}/", t.s("missing")))).unwrap_err().to_string().contains("no such directory"));
        assert!(unpack_to(&file, Dest::Cp(&t.s("missing/deeper"))).is_err(), "the parent must exist");
        assert!(unpack_to(&tar_of(&format!("{}/.", t.s("dir"))), Dest::Cp(&t.s("old"))).is_err());
        // Into: as it is, a leading `/` dropped.
        unpack_to(&archive(&[("/abs/z", b'0', "z"), ("./rel", b'0', "r")]), Dest::Into(&t.s("existing"))).unwrap();
        assert_eq!(std::fs::read(t.0.join("existing/abs/z")).unwrap(), b"z");
        assert_eq!(std::fs::read(t.0.join("existing/rel")).unwrap(), b"r");
        assert!(unpack_to(&file, Dest::Into(&t.s("nonexistent"))).is_err());
    }

    /// A device unpacked outside a vm, or an entry of a kind not known, leaves what is there and makes no parent.
    #[test]
    fn skipped_entries_change_nothing() {
        let t = Tmp::new("skipped");
        std::fs::write(t.0.join("existing"), "kept").unwrap();
        for kind in [b'3', b'4', b'Z'] {
            unpack_to(&archive(&[("null", kind, "")]), Dest::Cp(&t.s("existing"))).unwrap();
            assert_eq!(std::fs::read(t.0.join("existing")).unwrap(), b"kept");
            unpack_to(&archive(&[("d/", b'5', ""), ("d/new/null", kind, "")]), Dest::Cp(&t.s("d"))).unwrap();
            assert!(!t.0.join("d/new").exists());
        }
    }

    #[test]
    fn extended_headers_are_bounded_in_all() {
        // Many PAX headers, each small, before any entry: refused once they come to MAX_RECORD.
        let rec = b"20 comment=xxxxxxxx\n";
        let h = Header { path: b"PaxHeader".to_vec(), kind: b'x', mode: 0o644, size: rec.len() as u64, ..Default::default() };
        let mut one = Vec::new();
        write_header(&mut one, &h).unwrap();
        one.extend_from_slice(rec);
        one.resize(one.len().div_ceil(BLOCK) * BLOCK, 0);
        let bomb = one.repeat((MAX_RECORD as usize / rec.len()) + 2);
        let t = Tmp::new("paxbomb");
        assert!(unpack_to(&bomb, Dest::Cp(&t.s("dst"))).unwrap_err().to_string().contains("extended headers"));
    }

    #[test]
    fn an_archive_cut_short_is_refused() {
        let t = Tmp::new("cut");
        let src = tree(&t);
        let whole = tar_of(&src);
        // Its end-of-archive blocks gone, as when its maker failed between entries.
        let cut = &whole[..whole.len() - 2 * BLOCK];
        std::fs::create_dir(t.s("dst")).unwrap();
        assert!(unpack_to(cut, Dest::Cp(&t.s("dst"))).unwrap_err().to_string().contains("cut short"));
        assert!(unpack_to(&[], Dest::Cp(&t.s("dst"))).is_err(), "nothing at all");
    }

    #[test]
    fn hostile_archives_stay_inside() {
        let t = Tmp::new("hostile");
        let (dst, outside) = (t.s("dst"), t.s("outside"));
        std::fs::create_dir(&dst).unwrap();
        std::fs::create_dir(&outside).unwrap();
        for (bad, why) in [
            (archive(&[("../x", b'0', "x")]), ".."),
            (archive(&[("/abs", b'0', "x")]), "absolute"),
            (archive(&[("a/", b'5', ""), ("a/../../x", b'0', "x")]), ".."),
            (archive(&[("r/", b'5', ""), ("other", b'0', "x")]), "outside"),
            (archive(&[("r/", b'5', ""), ("r/l", b'1', "../../etc/passwd")]), ".."),
        ] {
            let e = unpack_to(&bad, Dest::Cp(&dst)).unwrap_err().to_string();
            assert!(e.contains(why), "{e}");
        }
        // Through a symlink the archive made: refused, nothing written outside.
        let through = archive(&[("r/", b'5', ""), ("r/l", b'2', &outside), ("r/l/pwned", b'0', "x")]);
        assert!(unpack_to(&through, Dest::Cp(&dst)).is_err());
        assert!(unpack_to(&through, Dest::Into(&dst)).is_err());
        // A file where a link is: the link is replaced, never written through.
        let over = archive(&[("q/", b'5', ""), ("q/f", b'2', &format!("{outside}/target")), ("q/f", b'0', "mine")]);
        unpack_to(&over, Dest::Cp(&dst)).unwrap();
        assert_eq!(std::fs::read(t.0.join("dst/q/f")).unwrap(), b"mine");
        assert!(!std::fs::symlink_metadata(t.0.join("dst/q/f")).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "nothing outside");
        // A hard link to an earlier entry works; one through a link the archive made does not.
        unpack_to(&archive(&[("h/", b'5', ""), ("h/a", b'0', "a"), ("h/b", b'1', "h/a")]), Dest::Cp(&dst)).unwrap();
        assert_eq!(std::fs::metadata(t.0.join("dst/h/b")).unwrap().ino(), std::fs::metadata(t.0.join("dst/h/a")).unwrap().ino());
        std::fs::write(t.0.join("outside/secret"), "s").unwrap();
        let hl = archive(&[("k/", b'5', ""), ("k/l", b'2', &outside), ("k/b", b'1', "k/l/secret")]);
        assert!(unpack_to(&hl, Dest::Cp(&dst)).is_err());
        assert!(!t.0.join("dst/k/b").exists());
    }

    /// Every node below `root` with its contents, to show that nothing there changed.
    /// `listing`, but the root's own mtime left out: a test removing what it allowed in the root
    /// changes that (by a second, across a second's boundary) without the root's contents changing.
    fn snapshot(root: &Path) -> Vec<(String, u32, i64, Vec<u8>)> {
        let mut l = listing(root);
        if let Some(top) = l.iter_mut().find(|e| e.0.is_empty()) {
            top.2 = 0;
        }
        l
    }

    #[test]
    fn the_top_asked_for_is_the_top_create_makes() {
        let t = Tmp::new("topof");
        std::fs::create_dir_all(t.0.join("d/sub")).unwrap();
        std::fs::write(t.0.join("d/f"), "f").unwrap();
        let first = |src: &str| {
            let tar = tar_of(src);
            let mut r = &tar[..];
            let h = Reader { r: &mut r, left: 0 }.next().unwrap().unwrap();
            match components(&h.path, false).unwrap().first() {
                Some(c) => Top::Named(c.clone()),
                None => Top::Contents,
            }
        };
        let d = t.s("d");
        for src in
            [d.clone(), format!("{d}/"), format!("{d}//"), format!("{d}/."), format!("{d}/./"), format!("{d}/f"), format!("{d}/sub/.."), format!("{d}/sub/../")]
        {
            assert_eq!(top_of(&src).unwrap(), first(&src), "{src}");
        }
        assert_eq!(top_of(&format!("{d}/sub/..")).unwrap(), Top::Named(b"d".to_vec()));
        for src in ["/", "//", "/.", ".", "./", "a/./"] {
            assert_eq!(top_of(src).unwrap(), Top::Contents, "{src}");
        }
        // A `..` that comes to / lexically may be a name in the guest (`/bin/..` through `/bin -> usr/bin`): never contents.
        for src in ["..", "../", "/..", "/bin/..", "/bin/../", "a/../..", "/a/./.."] {
            assert!(top_of(src).is_err(), "{src}");
        }
        assert_eq!(top_of("/etc/hostname").unwrap(), Top::Named(b"hostname".to_vec()));
        assert_eq!(top_of("etc/ssh/").unwrap(), Top::Named(b"ssh".to_vec()));
        assert_eq!(top_of("/a/b/../c/..").unwrap(), Top::Named(b"a".to_vec()));
        assert_eq!(top_of("/usr/bin/..").unwrap(), Top::Named(b"usr".to_vec()));
    }

    #[test]
    fn a_guest_archive_lands_where_it_was_asked_for() {
        let t = Tmp::new("guestok");
        std::fs::create_dir_all(t.0.join("etc/sub")).unwrap();
        std::fs::write(t.0.join("etc/hostname"), "vm\n").unwrap();
        std::fs::write(t.0.join("etc/sub/x"), "x").unwrap();
        std::fs::create_dir(t.0.join("dst")).unwrap();
        let get = |src: String, dst: String| unpack_to(&tar_of(&src), Dest::Guest(&dst, &top_of(&src).unwrap()));
        get(t.s("etc/hostname"), t.s("dst")).unwrap();
        assert_eq!(std::fs::read(t.0.join("dst/hostname")).unwrap(), b"vm\n");
        get(t.s("etc/hostname"), t.s("renamed")).unwrap();
        assert_eq!(std::fs::read(t.0.join("renamed")).unwrap(), b"vm\n");
        get(t.s("etc"), t.s("dst")).unwrap();
        assert_eq!(std::fs::read(t.0.join("dst/etc/sub/x")).unwrap(), b"x");
        get(format!("{}/.", t.s("etc")), t.s("contents")).unwrap();
        assert_eq!(std::fs::read(t.0.join("contents/sub/x")).unwrap(), b"x");
        assert_eq!(std::fs::read(t.0.join("contents/hostname")).unwrap(), b"vm\n");
    }

    /// `cp vm:/var/log/app.log home` (and `vm:/srv/. home`) from a guest that answers with something else: refused,
    /// and nothing in home, or beside it, changes.
    #[test]
    fn a_guest_never_chooses_what_is_written() {
        let t = Tmp::new("guestbad");
        let (home, outside) = (t.0.join("home"), t.0.join("outside"));
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".bashrc"), "mine").unwrap();
        std::fs::write(home.join(".ssh/authorized_keys"), "my key").unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret"), "s").unwrap();
        let (h, o) = (home.to_str().unwrap().to_string(), outside.to_str().unwrap().to_string());
        let named = Top::Named(b"app.log".to_vec());
        let before = (snapshot(&home), snapshot(&outside));
        let refused = |bad: &[u8], top: &Top, why: &str| {
            let e = unpack_to(bad, Dest::Guest(&h, top)).unwrap_err().to_string();
            assert!(e.contains(why), "{why}: {e}");
            // What was asked for may have been written before the entry refused; nothing else.
            let _ = std::fs::remove_file(home.join("app.log")).or_else(|_| std::fs::remove_dir_all(home.join("app.log")));
            assert_eq!((snapshot(&home), snapshot(&outside)), before, "{why}: {e}");
        };
        let cases: Vec<(Vec<u8>, &Top, &str)> = vec![
            // The name the guest picks, rather than the one asked for.
            (archive(&[("./.bashrc", b'0', "pwned")]), &named, "not \"app.log\""),
            (archive(&[("./", b'5', ""), ("./.bashrc", b'0', "pwned")]), &named, "not \"app.log\""),
            (archive(&[(".bashrc", b'0', "pwned")]), &named, "not \"app.log\""),
            (archive(&[(".ssh/", b'5', ""), (".ssh/authorized_keys", b'0', "evil key")]), &named, "not \"app.log\""),
            (archive(&[("app.log", b'0', "log"), (".bashrc", b'0', "pwned")]), &named, "outside the archive's top"),
            (archive(&[("app.log/", b'5', ""), ("./.bashrc", b'0', "pwned")]), &named, "outside the archive's top"),
            // Up and out, or absolute, either way.
            (archive(&[("app.log/../.bashrc", b'0', "pwned")]), &named, ".."),
            (archive(&[("app.log/", b'5', ""), ("app.log/../.bashrc", b'0', "pwned")]), &named, ".."),
            (archive(&[("../outside/secret", b'0', "pwned")]), &Top::Contents, ".."),
            (archive(&[("./", b'5', ""), ("x/../../outside/y", b'0', "pwned")]), &Top::Contents, ".."),
            (archive(&[("/app.log", b'0', "pwned")]), &named, "absolute"),
            (archive(&[("./", b'5', ""), (&format!("{h}/.bashrc"), b'0', "pwned")]), &Top::Contents, "absolute"),
            // Hard links to what is outside: by .., absolute, or outside the top.
            (archive(&[("app.log", b'1', "app.log/../outside/secret")]), &named, ".."),
            (archive(&[("app.log", b'1', &format!("{o}/secret"))]), &named, "absolute"),
            (archive(&[("app.log", b'1', ".bashrc")]), &named, "outside the archive's top"),
            (archive(&[("./", b'5', ""), ("l", b'1', "../outside/secret")]), &Top::Contents, ".."),
            (archive(&[("./", b'5', ""), ("l", b'1', &format!("{o}/secret"))]), &Top::Contents, "absolute"),
        ];
        for (bad, top, why) in &cases {
            refused(bad, top, why);
        }
        // A symlink the archive made, then an entry below it, or a hard link through it: refused, nothing written through it.
        for (bad, top) in [
            (archive(&[("app.log/", b'5', ""), ("app.log/l", b'2', &o), ("app.log/l/pwned", b'0', "x")]), &named),
            (archive(&[("app.log/", b'5', ""), ("app.log/l", b'2', &o), ("app.log/b", b'1', "app.log/l/secret")]), &named),
            (archive(&[("./", b'5', ""), ("l", b'2', &o), ("l/pwned", b'0', "x")]), &Top::Contents),
            (archive(&[("./", b'5', ""), ("l", b'2', &o), ("b", b'1', "l/secret")]), &Top::Contents),
            (archive(&[("./", b'5', ""), ("ssh", b'2', &format!("{h}/.ssh")), ("ssh/authorized_keys", b'0', "evil key")]), &Top::Contents),
        ] {
            assert!(unpack_to(&bad, Dest::Guest(&h, top)).is_err());
            assert_eq!(snapshot(&outside), before.1);
            assert_eq!(std::fs::read(home.join(".ssh/authorized_keys")).unwrap(), b"my key");
            assert_eq!(std::fs::read(home.join(".bashrc")).unwrap(), b"mine");
            assert!(!home.join("app.log/b").exists() && !home.join("b").exists());
            let _ = std::fs::remove_dir_all(home.join("app.log"));
        }
        // A directory entry where the archive made a link: the link is replaced by the directory, inside DST.
        let replaced = archive(&[("app.log/", b'5', ""), ("app.log/l", b'2', &o), ("app.log/l/", b'5', ""), ("app.log/l/f", b'0', "x")]);
        unpack_to(&replaced, Dest::Guest(&h, &named)).unwrap();
        assert!(std::fs::symlink_metadata(home.join("app.log/l")).unwrap().is_dir());
        assert_eq!(std::fs::read(home.join("app.log/l/f")).unwrap(), b"x");
        assert_eq!(snapshot(&outside), before.1);
        // A link the host already had below DST is never followed either.
        std::os::unix::fs::symlink(&outside, home.join("tolink")).unwrap();
        assert!(unpack_to(&archive(&[("./", b'5', ""), ("tolink/pwned", b'0', "x")]), Dest::Guest(&h, &Top::Contents)).is_err());
        assert_eq!(snapshot(&outside), before.1);
    }

    /// One header block of `kind` named `name`, its size field given as is, checksummed.
    fn raw_header(name: &str, kind: u8, size: &[u8; 12]) -> Vec<u8> {
        let mut v = Vec::new();
        write_header(&mut v, &Header { path: name.into(), kind, mode: 0o644, ..Default::default() }).unwrap();
        v[124..136].copy_from_slice(size);
        checksum(&mut v);
        v
    }

    fn checksum(b: &mut [u8]) {
        b[148..156].fill(b' ');
        let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
        b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    #[test]
    fn gnu_timestamps_are_not_a_name_prefix() {
        let mut b = raw_header("plain", b'0', b"00000000000\0");
        b[257..265].copy_from_slice(b"ustar  \0");
        octal(&mut b[345..357], 1_700_000_000);
        octal(&mut b[357..369], 1_700_000_001);
        checksum(&mut b);
        let mut r = &b[..];
        let h = Reader { r: &mut r, left: 0 }.next().unwrap().unwrap();
        assert_eq!(h.path, b"plain");
    }

    #[test]
    fn posix_ustar_prefix_is_joined() {
        let mut b = raw_header("plain", b'0', b"00000000000\0");
        b[257..263].copy_from_slice(b"ustar\0");
        b[345..351].copy_from_slice(b"parent");
        checksum(&mut b);
        let mut r = &b[..];
        let h = Reader { r: &mut r, left: 0 }.next().unwrap().unwrap();
        assert_eq!(h.path, b"parent/plain");
    }

    #[test]
    fn old_gnu_sparse_with_extensions_is_refused_clearly() {
        let t = Tmp::new("sparse");
        let mut b = raw_header("sparse", b'S', b"00000000005\0");
        b[257..265].copy_from_slice(b"ustar  \0");
        // Four sparse extents in the header, and a fifth in an extension block.
        for i in 0..4 {
            octal(&mut b[386 + i * 24..398 + i * 24], (i * 2) as u64);
            octal(&mut b[398 + i * 24..410 + i * 24], 1);
        }
        b[482] = 1;
        octal(&mut b[483..495], 9);
        checksum(&mut b);
        let mut ext = [0; BLOCK];
        octal(&mut ext[..12], 8);
        octal(&mut ext[12..24], 1);
        b.extend_from_slice(&ext);
        b.extend_from_slice(b"abcde");
        b.resize(BLOCK * 3, 0);
        b.extend(archive(&[("after", b'0', "kept")]));
        let e = unpack_to(&b, Dest::Into(t.0.to_str().unwrap())).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("old-GNU sparse entries are not supported"), "{e}");
        assert!(!e.to_string().contains("checksum"), "{e}");
    }

    /// Build PAX records and a regular-file payload, including the map block for sparse 1.0.
    fn pax_sparse_archive(kind: u8, keys: &[(&str, &str)], name: &str, payload: &[u8]) -> Vec<u8> {
        let mut pax = Vec::new();
        for (key, value) in keys {
            pax_record(&mut pax, key, value.as_bytes());
        }
        let mut v = Vec::new();
        for (name, kind, data) in [("PaxHeader", kind, pax.as_slice()), (name, b'0', payload)] {
            let mut size = [0; 12];
            assert!(octal(&mut size, data.len() as u64));
            v.extend(raw_header(name, kind, &size));
            v.extend_from_slice(data);
            v.resize(v.len().div_ceil(BLOCK) * BLOCK, 0);
        }
        v.extend_from_slice(&[0; BLOCK * 2]);
        v
    }

    fn assert_pax_sparse_refused(archive: &[u8]) {
        use std::os::unix::fs::MetadataExt;
        let t = Tmp::new("pax-sparse");
        let dst = t.s("sparse");
        std::fs::write(&dst, b"original destination").unwrap();
        let before = std::fs::metadata(&dst).unwrap();
        let top = Top::Named(b"sparse".to_vec());
        for dest in [Dest::Into(t.0.to_str().unwrap()), Dest::Cp(&dst), Dest::Guest(&dst, &top)] {
            let e = unpack_to(archive, dest).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            assert!(e.to_string().contains("PAX sparse entries are not supported"), "{e}");
            assert_eq!(std::fs::read(&dst).unwrap(), b"original destination");
            let after = std::fs::metadata(&dst).unwrap();
            assert_eq!((after.ino(), after.mode(), after.mtime(), after.mtime_nsec()), (before.ino(), before.mode(), before.mtime(), before.mtime_nsec()));
            assert_eq!(std::fs::read_dir(&t.0).unwrap().count(), 1);
        }
        let absent = t.s("absent");
        assert!(unpack_to(archive, Dest::Cp(&absent)).unwrap_err().to_string().contains("PAX sparse entries are not supported"));
        assert!(!Path::new(&absent).exists());
    }

    #[test]
    fn pax_sparse_formats_are_refused_before_replacing_destination() {
        // Each archive represents 8192 logical bytes with DATA at offset 4096.
        let v00 = pax_sparse_archive(
            b'x',
            &[
                ("GNU.sparse.size", "8192"),
                ("GNU.sparse.numblocks", "2"),
                ("GNU.sparse.offset", "4096"),
                ("GNU.sparse.numbytes", "4"),
                ("GNU.sparse.offset", "8192"),
                ("GNU.sparse.numbytes", "0"),
            ],
            "sparse",
            b"DATA",
        );
        let v01 = pax_sparse_archive(
            b'x',
            &[("GNU.sparse.size", "8192"), ("GNU.sparse.numblocks", "2"), ("GNU.sparse.name", "sparse"), ("GNU.sparse.map", "4096,4,8192,0")],
            "./GNUSparseFile.123/sparse",
            b"DATA",
        );
        let mut payload = b"2\n4096\n4\n8192\n0\n".to_vec();
        payload.resize(BLOCK, 0);
        payload.extend_from_slice(b"DATA");
        let v10 = pax_sparse_archive(
            b'x',
            &[("GNU.sparse.major", "1"), ("GNU.sparse.minor", "0"), ("GNU.sparse.name", "sparse"), ("GNU.sparse.realsize", "8192")],
            "./GNUSparseFile.123/sparse",
            &payload,
        );
        for archive in [v00, v01, v10] {
            assert_pax_sparse_refused(&archive);
        }
    }

    #[test]
    fn pax_sparse_keys_are_refused_but_sparse_looking_names_are_not() {
        for key in ["GNU.sparse.size", "GNU.sparse.map", "GNU.sparse.major", "GNU.sparse.future"] {
            assert_pax_sparse_refused(&pax_sparse_archive(b'x', &[(key, "")], "sparse", b"DATA"));
        }
        // Only the keys mark a sparse entry: a regular file may be named like GNU tar's synthetic path.
        for (keys, name) in [(&[][..], "GNUSparseFile.123/sparse"), (&[("path", "GNUSparseFile.1/x")][..], "sparse")] {
            let t = Tmp::new("pax-sparse-name");
            unpack_to(&pax_sparse_archive(b'x', keys, name, b"DATA"), Dest::Into(t.0.to_str().unwrap())).unwrap();
            let want = keys.first().map_or(name, |(_, v)| *v);
            assert_eq!(std::fs::read(t.0.join(want)).unwrap(), b"DATA");
        }
    }

    #[test]
    fn sizes_that_overflow_are_refused() {
        let t = Tmp::new("oversize");
        let dst = t.s("dst");
        std::fs::create_dir(&dst).unwrap();
        let top = Top::Named(b"f".to_vec());
        let mut cases = Vec::new();
        for size in ["-1", "18446744073709551615", "18446744073709551200", "99999999999999999999999", "-9223372036854775808"] {
            let mut pax = Vec::new();
            pax_record(&mut pax, "size", size.as_bytes());
            let mut v = Vec::new();
            write_header(&mut v, &Header { path: b"PaxHeader".to_vec(), kind: b'x', mode: 0o644, size: pax.len() as u64, ..Default::default() }).unwrap();
            v.extend_from_slice(&pax);
            v.resize(v.len().div_ceil(BLOCK) * BLOCK, 0);
            v.extend(raw_header("f", b'0', b"00000000000\0"));
            v.extend_from_slice(&[0; BLOCK * 2]);
            cases.push(v);
        }
        // Base-256: u64::MAX, and just below it.
        for last in [0xff, 0x01] {
            let mut size = [0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, last];
            let mut v = raw_header("f", b'0', &size);
            v.extend_from_slice(&[0; BLOCK * 2]);
            cases.push(v);
            // And as a PAX header's own size, and a global one's.
            for kind in [b'x', b'g', b'L'] {
                size[11] = last;
                let mut v = raw_header("PaxHeader", kind, &size);
                v.extend_from_slice(&[0; BLOCK * 2]);
                cases.push(v);
            }
        }
        for bad in &cases {
            assert!(unpack_to(bad, Dest::Guest(&dst, &top)).is_err());
            assert!(unpack_to(bad, Dest::Cp(&dst)).is_err());
        }
        assert_eq!(std::fs::read_dir(&dst).unwrap().filter_map(|e| std::fs::read(e.unwrap().path()).ok()).filter(|d| !d.is_empty()).count(), 0);
        assert!(padded(u64::MAX).is_err() && padded(u64::MAX - 510).is_err());
        assert_eq!(padded(u64::MAX - 511).unwrap(), u64::MAX - 511);
    }

    #[test]
    fn system_tar_interoperates() {
        if std::process::Command::new("tar").arg("--version").output().is_err() {
            return;
        }
        let t = Tmp::new("systar");
        let src = tree(&t);
        std::fs::write(t.0.join("ours.tar"), tar_of(&src)).unwrap();
        let list = std::process::Command::new("tar").arg("-tvf").arg(t.0.join("ours.tar")).output().unwrap();
        assert!(list.status.success(), "{}", String::from_utf8_lossy(&list.stderr));
        let names = String::from_utf8_lossy(&list.stdout);
        assert!(names.contains("src/link -> a/b/c.txt") && names.contains(&"x".repeat(90)), "{names}");
        let made = std::process::Command::new("tar").arg("-cf").arg(t.0.join("theirs.tar")).arg("-C").arg(&src).arg(".").status().unwrap();
        assert!(made.success());
        let theirs = std::fs::read(t.0.join("theirs.tar")).unwrap();
        extract(&mut &theirs[..], Dest::Cp(&t.s("fromtar")), Some(unsafe { (libc::getuid(), libc::getgid()) })).unwrap();
        let (want, got) = (listing(Path::new(&src)), listing(&t.0.join("fromtar")));
        assert_eq!(want[1..], got[1..]);
    }
}
