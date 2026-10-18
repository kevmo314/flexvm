//! Tar archives for `flexvm cp`, made and unpacked with std and libc alone: in the guest by flexvm-init
//! (`tool_main`) and on the host, which includes this file. Writes ustar, with PAX records for what does not
//! fit; reads ustar, PAX and GNU long names. Unpacking trusts no name in the archive: everything below the
//! target directory is reached one component at a time from directory fds, never through a symlink.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
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

fn padded(n: u64) -> u64 {
    n.div_ceil(BLOCK as u64) * BLOCK as u64
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
        zeros(out, padded(pax.len() as u64) - pax.len() as u64)?;
    }
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    out.write_all(&b)
}

/// Writes a tar of `src` (resolved in this process's filesystem) to `out`, docker cp's way: the top entry is named
/// `basename(src)`, or `.` (its contents) when `src` ends in `/.`. A symlink is archived as a link, unless `src` ends in `/`.
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
    let meta = if follow || name == "." { std::fs::metadata(path) } else { std::fs::symlink_metadata(path) }.map_err(|e| with(src, e))?;
    if name == "." && !meta.is_dir() {
        return Err(with(src, io::Error::from_raw_os_error(libc::ENOTDIR)));
    }
    walk(out, Path::new(path), name.into_bytes(), &meta)?;
    out.write_all(&[0; BLOCK * 2])?;
    out.flush()
}

fn walk(out: &mut dyn Write, path: &Path, name: Vec<u8>, meta: &std::fs::Metadata) -> io::Result<()> {
    let ft = meta.file_type();
    let mut h = Header { path: name, mode: meta.mode(), uid: meta.uid().into(), gid: meta.gid().into(), mtime: meta.mtime(), ..Default::default() };
    if ft.is_dir() {
        let mut entries = std::fs::read_dir(path).and_then(|d| d.collect::<io::Result<Vec<_>>>()).map_err(|e| with(path.display(), e))?;
        entries.sort_by_key(|e| e.file_name());
        let mut dir = h.clone();
        (dir.kind, dir.path) = (b'5', [&h.path[..], b"/"].concat());
        write_header(out, &dir)?;
        for e in entries {
            let p = e.path();
            let m = std::fs::symlink_metadata(&p).map_err(|e| with(p.display(), e))?;
            walk(out, &p, [&h.path[..], b"/", e.file_name().as_bytes()].concat(), &m)?;
        }
        return Ok(());
    }
    if ft.is_file() {
        let mut f = File::open(path).map_err(|e| with(path.display(), e))?;
        (h.kind, h.size) = (b'0', meta.len());
        write_header(out, &h)?;
        let n = io::copy(&mut (&mut f).take(h.size), out).map_err(|e| with(path.display(), e))?;
        // A file that shrank meanwhile is padded to the size its header says.
        return zeros(out, padded(h.size) - n);
    }
    h.kind = match () {
        _ if ft.is_symlink() => {
            h.link = std::fs::read_link(path)?.into_os_string().into_vec();
            b'2'
        }
        _ if ft.is_fifo() => b'6',
        _ if ft.is_char_device() || ft.is_block_device() => {
            h.dev = (libc::major(meta.rdev()), libc::minor(meta.rdev()));
            if ft.is_char_device() {
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
        self.left -= size;
        Ok(())
    }

    fn record(&mut self, size: u64) -> io::Result<Vec<u8>> {
        if size > MAX_RECORD {
            return Err(invalid(format!("an extended header of {size} bytes")));
        }
        let mut v = Vec::new();
        self.left = padded(size);
        self.data(size, &mut v)?;
        self.skip()?;
        Ok(v)
    }

    fn next(&mut self) -> io::Result<Option<Header>> {
        self.skip()?;
        let (mut path, mut link, mut pax) = (None, None, Vec::new());
        // What an entry's extended headers hold, in all: each one is `MAX_RECORD` at most, and so are they all.
        let mut extended = 0;
        loop {
            let mut b = [0u8; BLOCK];
            let mut got = 0;
            while got < BLOCK {
                match self.r.read(&mut b[got..]) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            match got {
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
                extended += size;
                if extended > MAX_RECORD {
                    return Err(invalid(format!("extended headers of more than {MAX_RECORD} bytes for one entry")));
                }
            }
            match b[156] {
                b'x' => {
                    let rec = self.record(size)?;
                    let mut rest = &rec[..];
                    while !rest.is_empty() {
                        let len = rest.iter().position(|&c| c == b' ').and_then(|sp| std::str::from_utf8(&rest[..sp]).ok()?.parse::<usize>().ok());
                        let Some(len) = len.filter(|&l| l <= rest.len() && l > 0 && rest[l - 1] == b'\n') else { return Err(invalid("bad PAX record")) };
                        let kv = &rest[rest.iter().position(|&c| c == b' ').unwrap_or(0) + 1..len - 1];
                        let eq = kv.iter().position(|&c| c == b'=').ok_or_else(|| invalid("bad PAX record"))?;
                        pax.push((String::from_utf8_lossy(&kv[..eq]).into_owned(), kv[eq + 1..].to_vec()));
                        rest = &rest[len..];
                    }
                    continue;
                }
                b'g' => {
                    self.left = padded(size);
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
            if &b[257..262] == b"ustar" && b[345] != 0 {
                h.path = [field(&b[345..500]), b"/".to_vec(), h.path].concat();
            }
            h.path = path.unwrap_or(h.path);
            h.link = link.unwrap_or(h.link);
            for (k, v) in pax {
                let n = || String::from_utf8_lossy(&v).split('.').next().unwrap_or("").parse::<i64>().map_err(|_| invalid(format!("bad PAX {k}")));
                match k.as_str() {
                    "path" => h.path = v.clone(),
                    "linkpath" => h.link = v.clone(),
                    "size" => h.size = n()? as u64,
                    "uid" => h.uid = n()? as u64,
                    "gid" => h.gid = n()? as u64,
                    "mtime" => h.mtime = n()?,
                    _ => {}
                }
            }
            self.left = padded(h.size);
            return Ok(Some(h));
        }
    }
}

pub enum Dest<'a> {
    /// docker cp's DST rules, applied to the archive's top entry (see below).
    Cp(&'a str),
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

fn open_dir(path: &str) -> io::Result<OwnedFd> {
    let fd = os(unsafe { libc::open(cstr(path.as_bytes())?.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) }).map_err(|e| with(path, e))?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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

fn target(dst: &str, comps: &[Vec<u8>], first: &Header) -> io::Result<Target> {
    let Some(root) = comps.first() else {
        match std::fs::metadata(dst) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(with(dst, io::Error::from_raw_os_error(libc::ENOTDIR))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => std::fs::create_dir(dst).map_err(|e| with(dst, e))?,
            Err(e) => return Err(with(dst, e)),
        }
        return Ok((open_dir(dst)?, None));
    };
    let is_dir = comps.len() > 1 || first.kind == b'5';
    match std::fs::metadata(dst) {
        Ok(m) if m.is_dir() => return Ok((open_dir(dst)?, Some((root.clone(), root.clone())))),
        Ok(_) if is_dir => return Err(io::Error::other(format!("cannot copy a directory onto a file: {dst}"))),
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(with(dst, e)),
        Err(_) if dst.ends_with('/') && !is_dir => return Err(io::Error::other(format!("no such directory: {dst}"))),
        _ => {}
    }
    let trimmed = dst.trim_end_matches('/');
    let (parent, leaf) = match trimmed.rsplit_once('/') {
        Some((p, l)) => (if p.is_empty() { "/" } else { p }, l),
        None => (".", trimmed),
    };
    if matches!(leaf, "" | "." | "..") {
        return Err(io::Error::other(format!("bad destination {dst}")));
    }
    Ok((open_dir(parent)?, Some((root.clone(), leaf.as_bytes().to_vec()))))
}

/// Unpacks `input` at `dest`. `owner`: everything is chowned to it (lchown for links); None leaves the files
/// owned by whoever runs this (the host, root under sudo, from a guest's archive), and then no setuid or setgid
/// bit and no device node comes from the archive. Modes and mtimes are kept; a directory's after its contents.
pub fn extract(input: &mut dyn Read, dest: Dest, owner: Option<(u32, u32)>) -> io::Result<()> {
    let mut rd = Reader { r: input, left: 0 };
    let Some(first) = rd.next()? else { return Ok(()) };
    let into = matches!(dest, Dest::Into(_));
    let (base, top) = match dest {
        Dest::Into(dir) => (open_dir(dir)?, None),
        Dest::Cp(dst) => target(dst, &components(&first.path, false)?, &first)?,
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
    // Each directory's last entry, in the order they first came: their metadata goes on at the end, deepest last first.
    let (mut dirs, mut order) = (std::collections::HashMap::new(), Vec::new());
    let mut next = Some(first);
    while let Some(e) = next.take() {
        let comps = rename(&e.path)?;
        if let Some((leaf, parent)) = comps.split_last() {
            let link = if e.kind == b'1' { rename(&e.link)? } else { Vec::new() };
            unpack(&base, parent, leaf, &link, &e, &mut rd, owner).map_err(|err| with(String::from_utf8_lossy(&e.path), err))?;
            if e.kind == b'5' {
                if !dirs.contains_key(&comps) {
                    order.push(comps.clone());
                }
                dirs.insert(comps, e);
            }
        }
        next = rd.next()?;
    }
    for comps in order.iter().rev() {
        let e = &dirs[comps];
        let fd = walk_dir(&base, comps, None).map_err(|err| with(String::from_utf8_lossy(&e.path), err))?;
        finish(fd.as_raw_fd(), e, owner)?;
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
        b'3' | b'4' if owner.is_none() => {
            warn!("flexvm: cp: skipping device {}: devices are copied into a vm only", String::from_utf8_lossy(&e.path));
            Ok(())
        }
        b'3' | b'4' => {
            let kind = if e.kind == b'3' { libc::S_IFCHR } else { libc::S_IFBLK };
            match os(unsafe { libc::mknodat(d, name.as_ptr(), kind | 0o600, libc::makedev(e.dev.0, e.dev.1)) }) {
                Ok(_) => finish_at(d, &name, e, owner, true),
                Err(err) => {
                    warn!("flexvm: cp: skipping device {}: {err}", String::from_utf8_lossy(&e.path));
                    Ok(())
                }
            }
        }
        k => {
            warn!("flexvm: cp: skipping {} (tar entry type {:?})", String::from_utf8_lossy(&e.path), k as char);
            Ok(())
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
    use std::os::unix::fs::{symlink, PermissionsExt};
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
            v.resize(padded(v.len() as u64) as usize, 0);
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
