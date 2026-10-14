//! Durable checkpoints: a VM's state as a delta against its template, restored lazily.
//! A directory (format 2): manifest.json (checksum line, then the `Manifest`), vmstate,
//! pagemap ("FVPGMAP2", run count, data page count, runs of (first page, count, kind, index
//! in `pages`) as u64 LE, then each stored page's CRC32C as u32 LE) and pages (DATA pages).
//! A page is BASE (template's, or zero over a hole; not stored), ZERO or DATA; a delta
//! (format 3) names a `parent` and adds TEMPLATE runs. Directories are staged root-only,
//! fsynced and renamed into place, never over anything: complete or absent, never changed.

use std::collections::BTreeMap;
use std::fs::File;
use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::bail;

macro_rules! ensure {
    ($ok:expr, $($why:tt)*) => { if !$ok { bail!($($why)*) } };
}
use crate::crc32c;
use crate::template::{Hash, Template};
use crate::uffd::{Pager, Runs, REMOTE};
use crate::util::{Error, Phases, Result, PAGE_SIZE};
use crate::vm::Vm;

pub const FORMAT: u64 = 2;
pub const FORMAT_INCREMENTAL: u64 = 3;
const MAGIC: &[u8; 8] = b"FVPGMAP2";
const DATA: u64 = 1;
const ZERO: u64 = 2;
const TEMPLATE: u64 = 3;
pub const MAX_CHAIN: usize = 64;
const UNIT: usize = 256;
/// Most writer threads; a few saturate the disk.
const MAX_WRITERS: usize = 12;
const MAX_VMSTATE: u64 = 64 << 20;
const MAX_CHAIN_META: u64 = 256 << 20;

/// Most metadata (manifests, VM states, page maps) opening a chain may read:
/// it scales with the host, never with what a (possibly forged) manifest
/// claims. A page map costs at most 36 bytes per guest page, under 1% of it.
pub fn chain_meta_budget() -> u64 {
    MAX_CHAIN_META.max(crate::util::proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0) / 16)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSum {
    pub len: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u64,
    pub created_unix_ms: u64,
    pub name: String,
    pub ip: Ipv4Addr,
    pub template: String,
    pub template_id: String,
    pub vcpus: u32,
    pub mem_mib: u64,
    pub max_mib: u64,
    pub hotplug_mib: u64,
    pub guest_pages: u64,
    pub data_pages: u64,
    pub zero_pages: u64,
    pub files: BTreeMap<String, FileSum>,
    /// The checkpoint this one is a delta against (format 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Parent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parent {
    /// Relative to this checkpoint's directory, or absolute.
    pub path: String,
    pub id: String,
}

fn sum(bytes: &[u8]) -> String {
    let mut h = Hash::new();
    h.update(bytes);
    h.finish()
}

fn sums_sum(sums: &[u32]) -> String {
    let mut h = Hash::new();
    sums.iter().for_each(|&c| h.word(c as u64));
    h.finish()
}

fn cname(name: &str) -> CString {
    CString::new(name).expect("no NUL in file names")
}

fn publish_permissions(files: &[RawFd], dir: RawFd, owner: &libc::stat) -> io::Result<()> {
    for (fd, mode) in files.iter().copied().map(|fd| (fd, 0o600)).chain(std::iter::once((dir, 0o700))) {
        check(unsafe { libc::fchown(fd, owner.st_uid, owner.st_gid) })?;
        check(unsafe { libc::fchmod(fd, mode) })?;
    }
    Ok(())
}

fn check(rc: libc::c_int) -> io::Result<()> {
    (rc >= 0).then_some(()).ok_or_else(io::Error::last_os_error)
}

/// Opens `name` in `dir`, never through a symlink (O_NOFOLLOW is added).
fn openat(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
    check(fd)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_dir_at(dir: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    openat(dir, name, libc::O_RDONLY | libc::O_DIRECTORY)
}

fn create_at(dir: RawFd, name: &str) -> io::Result<File> {
    openat(dir, &cname(name), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL).map(File::from)
}

/// Opens file `name` in `dir` for reading. O_NONBLOCK: a FIFO planted in its
/// place must not block (callers check for a regular file).
fn open_at(dir: RawFd, name: &str) -> io::Result<File> {
    openat(dir, &cname(name), libc::O_RDONLY | libc::O_NONBLOCK).map(File::from)
}

const STAGING_PREFIX: &str = ".flexvm-staging-";

pub enum CommitError {
    /// Nothing was published (or what was is durably unusable): the VM may resume.
    Failed(Error),
    /// Published, maybe not durably, and not revocable: the VM must not
    /// resume, or a stale checkpoint could later restore.
    Uncertain(Error),
}

impl<E: Into<Error>> From<E> for CommitError {
    fn from(e: E) -> Self {
        CommitError::Failed(e.into())
    }
}

/// A checkpoint being written: published as `dest` once complete and durable, else removed.
/// We run as root under a directory a user may own, so nothing follows a path they can change:
/// dirs are pinned by fd, files created O_EXCL|O_NOFOLLOW in root-only staging, renamed fd to fd.
pub struct Staging {
    dest: PathBuf,
    parent: OwnedFd,
    base: CString,
    /// The root-only staging directory in `parent`, and "ck" in it, published as `dest`.
    outer: OwnedFd,
    outer_name: CString,
    ck: OwnedFd,
    vmstate: PathBuf,
    pages: Option<PagesFile>,
    published: bool,
    pub meta_left: u64,
}

impl Staging {
    /// Firecracker writes the VM state to `vmstate`, a path only root controls.
    pub fn new(dest: &Path, vmstate: PathBuf) -> Result<Staging> {
        let parent = dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let base = dest.file_name().ok_or_else(|| format!("bad checkpoint path {}", dest.display()))?;
        let parent_path = parent.canonicalize().map_err(|e| format!("checkpoint directory {}: {e}", parent.display()))?;
        let dest = parent_path.join(base);
        let pfd = open_dir_at(libc::AT_FDCWD, &CString::new(parent_path.as_os_str().as_bytes())?)
            .map_err(|e| format!("checkpoint directory {}: {e}", parent_path.display()))?;
        let base = CString::new(base.as_bytes())?;
        ensure!(!exists_at(pfd.as_raw_fd(), &base), "{} already exists; checkpoints are never overwritten", dest.display());
        clear_stale(&pfd);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
        let outer_name = cname(&format!("{STAGING_PREFIX}{}-{nanos:x}", std::process::id()));
        check(unsafe { libc::mkdirat(pfd.as_raw_fd(), outer_name.as_ptr(), 0o700) })?;
        let outer = open_dir_at(pfd.as_raw_fd(), &outer_name)?;
        ensure!(private_dir(outer.as_raw_fd()), "staging directory in {} was replaced", parent_path.display());
        check(unsafe { libc::mkdirat(outer.as_raw_fd(), c"ck".as_ptr(), 0o700) })?;
        let ck = open_dir_at(outer.as_raw_fd(), c"ck")?;
        let _ = std::fs::remove_file(&vmstate);
        Ok(Staging { dest, parent: pfd, base, outer, outer_name, ck, vmstate, pages: None, published: false, meta_left: chain_meta_budget() })
    }

    pub fn dest(&self) -> &Path {
        &self.dest
    }

    /// A path to the destination's directory as pinned; valid while this lives.
    pub fn pinned_dir(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.parent.as_raw_fd()))
    }

    pub fn vmstate(&self) -> PathBuf {
        self.vmstate.clone()
    }

    fn create(&self, name: &str) -> io::Result<File> {
        create_at(self.ck.as_raw_fd(), name)
    }

    pub fn add_file(&self, name: &str, bytes: &[u8]) -> io::Result<File> {
        let f = self.create(name)?;
        (&f).write_all(bytes)?;
        f.sync_all()?;
        Ok(f)
    }

    /// Allocates disk space ahead of the pause.
    pub fn preallocate(&mut self, pages: usize) -> Result<()> {
        let file = PagesFile::new(self.create("pages")?);
        file.reserve(pages);
        self.pages = Some(file);
        Ok(())
    }

    /// Writes `runs` (read from `src`) and metadata, then publishes. With a `parent`, `runs`
    /// lists only what changed since it (BASE runs explicit): a delta.
    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        mut self,
        vm: &Vm,
        src: &dyn GuestPages,
        runs: &Runs,
        parent: Option<Parent>,
        hotplug_mib: u64,
        t: &mut Phases,
        still_valid: impl FnOnce() -> Result<()>,
    ) -> std::result::Result<(Manifest, String), CommitError> {
        let pages = if let Some(p) = self.pages.take() { p } else { PagesFile::new(self.create("pages")?) };
        let out = write_pages(&vm.template, src, runs, &pages, writer_threads(), parent.is_some())?;
        t.mark("write_pages");
        pages.file.sync_all()?;
        let map = &out.map;
        let pagemap = self.add_file("pagemap", map)?;
        let vmstate = std::fs::read(&self.vmstate)?;
        if vmstate.len() as u64 > MAX_VMSTATE {
            return Err(format!("its vmstate is over {MAX_VMSTATE} bytes").into());
        }
        let vmstate_file = self.add_file("vmstate", &vmstate)?;
        let files = BTreeMap::from([
            ("vmstate".into(), FileSum { len: vmstate.len() as u64, hash: sum(&vmstate) }),
            ("pagemap".into(), FileSum { len: map.len() as u64, hash: sum(map) }),
            ("pages".into(), FileSum { len: out.data * PAGE_SIZE as u64, hash: sums_sum(&out.sums) }),
        ]);
        let meta = &vm.template.meta;
        let manifest = Manifest {
            format: if parent.is_some() { FORMAT_INCREMENTAL } else { FORMAT },
            created_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
            name: vm.name.clone(),
            ip: vm.ip,
            template: vm.template.name.clone(),
            template_id: meta.id.clone(),
            vcpus: meta.vcpus,
            mem_mib: meta.mem_mib,
            max_mib: meta.max_mib,
            hotplug_mib,
            guest_pages: vm.pager.total_pages() as u64,
            data_pages: out.data,
            zero_pages: out.zero,
            files,
            parent,
        };
        let body = serde_json::to_vec_pretty(&manifest)?;
        let id = sum(&body);
        let text = [format!("{id}\n").as_bytes(), &body].concat();
        if (text.len() + vmstate.len() + map.len()) as u64 > self.meta_left {
            let budget = chain_meta_budget();
            return Err(match manifest.parent {
                Some(_) => format!("its chain would have more than {budget} bytes of metadata; take a full one"),
                None => format!("it would have more than {budget} bytes of metadata"),
            }
            .into());
        }
        let mf = self.add_file("manifest.json", &text)?;
        // Owned by the directory's owner (we run as root), who may move and delete it.
        let owner = fstat(self.parent.as_raw_fd())?;
        publish_permissions(&[pages.file.as_raw_fd(), pagemap.as_raw_fd(), vmstate_file.as_raw_fd(), mf.as_raw_fd()], self.ck.as_raw_fd(), &owner)?;
        check(unsafe { libc::fsync(self.ck.as_raw_fd()) })?;
        still_valid()?;
        // The pinned directory must still be the one `dest` names.
        use std::os::unix::fs::MetadataExt;
        let moved = format!("the directory of {} was moved or replaced during the checkpoint", self.dest.display());
        let named = std::fs::metadata(self.dest.parent().unwrap_or(Path::new("/"))).map_err(|e| format!("{moved}: {e}"))?;
        let pinned = fstat(self.parent.as_raw_fd())?;
        if named.dev() != pinned.st_dev as u64 || named.ino() != pinned.st_ino as u64 {
            return Err(moved.into());
        }
        t.mark("fsync");
        let (outer, parent) = (self.outer.as_raw_fd(), self.parent.as_raw_fd());
        check(unsafe { libc::renameat2(outer, c"ck".as_ptr(), parent, self.base.as_ptr(), libc::RENAME_NOREPLACE) })
            .map_err(|e| format!("publish checkpoint at {}: {e}", self.dest.display()))?;
        self.published = true;
        if let Err(e) = check(unsafe { libc::fsync(parent) }) {
            // A crash could bring it back after the VM ran on: revoke it, durably.
            let revoked = check(unsafe { libc::unlinkat(self.ck.as_raw_fd(), c"manifest.json".as_ptr(), 0) })
                .and_then(|()| check(unsafe { libc::fsync(self.ck.as_raw_fd()) }));
            let e = format!("making checkpoint {} durable: {e}", self.dest.display());
            return Err(match revoked {
                Ok(()) => CommitError::Failed(format!("{e} (revoked it)").into()),
                Err(r) => CommitError::Uncertain(format!("{e}; revoking it failed too: {r}").into()),
            });
        }
        t.mark("publish");
        Ok((manifest, id))
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let ck = (!self.published).then(|| self.ck.as_raw_fd());
        remove_staging(self.parent.as_raw_fd(), &self.outer_name, self.outer.as_raw_fd(), ck);
        let _ = std::fs::remove_file(&self.vmstate);
    }
}

fn remove_staging(parent: RawFd, name: &CStr, outer: RawFd, ck: Option<RawFd>) {
    // Every file in it (only we write there; `add_file` adds more than the four).
    if let Some(ck) = ck {
        for f in std::fs::read_dir(format!("/proc/self/fd/{ck}")).into_iter().flatten().flatten() {
            unsafe { libc::unlinkat(ck, cname(&f.file_name().to_string_lossy()).as_ptr(), 0) };
        }
    }
    unsafe { libc::unlinkat(outer, c"ck".as_ptr(), libc::AT_REMOVEDIR) };
    unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) };
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

/// Whether `fd` is ours and nobody else may enter it, as staging is made.
fn private_dir(fd: RawFd) -> bool {
    fstat(fd).is_ok_and(|st| st.st_uid == unsafe { libc::geteuid() } && st.st_mode & 0o077 == 0)
}

fn exists_at(dir: RawFd, name: &CStr) -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) == 0 }
}

fn clear_stale(parent: &OwnedFd) {
    let Ok(dir) = std::fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd())) else { return };
    for e in dir.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix(STAGING_PREFIX) else { continue };
        let pid = rest.split('-').next().unwrap_or("");
        if pid.is_empty() || Path::new(&format!("/proc/{pid}")).exists() {
            continue;
        }
        let Ok(outer) = open_dir_at(parent.as_raw_fd(), &cname(&name)) else { continue };
        if !private_dir(outer.as_raw_fd()) {
            continue;
        }
        let ck = open_dir_at(outer.as_raw_fd(), c"ck").ok();
        remove_staging(parent.as_raw_fd(), &cname(&name), outer.as_raw_fd(), ck.as_ref().map(|c| c.as_raw_fd()));
    }
}

pub(crate) trait GuestPages: Sync {
    fn region_end(&self, page: usize) -> Option<usize>;
    fn read(&self, page: usize, buf: &mut [u8]) -> Result<()>;
    /// A page someone waits on, whose unit to write next.
    fn wanted(&self) -> Option<usize> {
        None
    }
}

impl GuestPages for Pager {
    fn region_end(&self, page: usize) -> Option<usize> {
        Pager::region_end(self, page)
    }

    fn read(&self, page: usize, buf: &mut [u8]) -> Result<()> {
        self.read_guest((page * PAGE_SIZE) as u64, buf)
    }
}

fn writer_threads() -> usize {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    let n = std::env::var("FLEXVM_CKPT_THREADS").ok().and_then(|v| v.parse().ok());
    n.unwrap_or(cpus).clamp(1, MAX_WRITERS)
}

struct Written {
    map: Vec<u8>,
    data: u64,
    zero: u64,
    sums: Vec<u32>,
}

const BASE: u8 = 0;

fn classify(template: &Template, page: usize, bytes: &[u8]) -> (u8, u32) {
    let tpl = template.has_data(page);
    if tpl && bytes == template.pages(page, 1) {
        return (BASE, 0);
    }
    match crc32c::page(bytes) {
        (_, true) if tpl => (ZERO as u8, 0),
        (_, true) => (BASE, 0),
        (sum, false) => (DATA as u8, sum),
    }
}

struct Unit {
    first: usize,
    kinds: Vec<u8>,
    sums: Vec<u32>,
    at: u64,
}

struct PagesFile {
    file: File,
    allocated: AtomicUsize,
}

impl PagesFile {
    fn new(file: File) -> PagesFile {
        let _ = direct(&file, true);
        PagesFile { file, allocated: AtomicUsize::new(0) }
    }

    /// Allocates room for `pages` pages so writes run in parallel (ext4 with O_DIRECT).
    fn reserve(&self, pages: usize) {
        let have = self.allocated.load(Ordering::Relaxed);
        let (off, len) = ((have * PAGE_SIZE) as libc::off_t, (pages.saturating_sub(have) * PAGE_SIZE) as libc::off_t);
        if pages > have && unsafe { libc::fallocate(self.file.as_raw_fd(), 0, off, len) } == 0 {
            self.allocated.store(pages, Ordering::Relaxed);
        }
    }

    /// Safety: `iov` is page-aligned whole pages the caller keeps alive and unchanged until return.
    fn write(&self, iov: &mut [libc::iovec], off: u64) -> io::Result<()> {
        match pwritev_all(&self.file, &mut iov.to_vec(), off) {
            // O_DIRECT does not work here after all.
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => direct(&self.file, false).and_then(|()| pwritev_all(&self.file, iov, off)),
            r => r,
        }
    }
}

fn direct(file: &File, on: bool) -> io::Result<()> {
    let (fd, flag) = (file.as_raw_fd(), libc::O_DIRECT);
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    check(unsafe { libc::fcntl(fd, libc::F_SETFL, if on { flags | flag } else { flags & !flag }) })
}

// Each iovec points into initialized storage the caller keeps alive and
// unchanged throughout; advancing one stays within its allocation.
fn pwritev_all(file: &File, mut iov: &mut [libc::iovec], mut off: u64) -> io::Result<()> {
    while !iov.is_empty() {
        let cnt = iov.len().min(libc::UIO_MAXIOV as usize) as libc::c_int;
        let n = unsafe { libc::pwritev(file.as_raw_fd(), iov.as_ptr(), cnt, off as libc::off_t) };
        let e = (n <= 0).then(|| if n < 0 { io::Error::last_os_error() } else { io::ErrorKind::WriteZero.into() });
        match e {
            Some(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Some(e) => return Err(e),
            None => {}
        }
        off += n as u64;
        let mut n = n as usize;
        while let Some(first) = iov.first_mut() {
            if n < first.iov_len {
                first.iov_base = unsafe { first.iov_base.add(n) };
                first.iov_len -= n;
                break;
            }
            n -= first.iov_len;
            iov = &mut iov[1..];
        }
    }
    Ok(())
}

/// One page, aligned for O_DIRECT.
#[derive(Clone)]
#[repr(C, align(4096))]
struct Page([u8; PAGE_SIZE]);

fn aligned(n: usize) -> io::Result<Vec<Page>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "cannot allocate checkpoint buffer"))?;
    v.resize(n, Page([0; PAGE_SIZE]));
    Ok(v)
}

fn as_bytes(pages: &mut [Page]) -> &mut [u8] {
    // `Page` is PAGE_SIZE initialized bytes with no padding.
    unsafe { std::slice::from_raw_parts_mut(pages.as_mut_ptr().cast(), std::mem::size_of_val(pages)) }
}

/// Writes the REMOTE pages of `runs` into `out` and builds the page map; with `explicit`
/// (a delta), listed template pages get TEMPLATE runs.
fn write_pages(template: &Template, src: &dyn GuestPages, runs: &Runs, out: &PagesFile, threads: usize, explicit: bool) -> Result<Written> {
    let mut units: Vec<(usize, usize)> = Vec::new();
    for &(first, count, _) in runs.iter().filter(|r| r.2 == REMOTE) {
        let (mut p, end) = (first as usize, (first + count) as usize);
        while p < end {
            let region_end = src.region_end(p).ok_or_else(|| format!("page {p} outside guest memory"))?;
            let n = UNIT.min(end - p).min(region_end - p);
            units.push((p, n));
            p += n;
        }
    }
    out.reserve(units.iter().map(|u| u.1).sum());
    let done: Vec<Mutex<Option<Unit>>> = units.iter().map(|_| Mutex::new(None)).collect();
    let taken: Vec<AtomicBool> = units.iter().map(|_| AtomicBool::new(false)).collect();
    let (next, placed, failed) = (AtomicUsize::new(0), AtomicU64::new(0), AtomicBool::new(false));
    let pick = || -> Option<usize> {
        while let Some(p) = src.wanted() {
            let k = units.partition_point(|u| u.0 <= p).checked_sub(1);
            if let Some(k) = k.filter(|&k| p < units[k].0 + units[k].1 && !taken[k].swap(true, Ordering::SeqCst)) {
                return Some(k);
            }
        }
        (0..).map(|_| next.fetch_add(1, Ordering::Relaxed)).take_while(|&k| k < units.len()).find(|&k| !taken[k].swap(true, Ordering::SeqCst))
    };
    let work = || -> Result<()> {
        let mut buf = aligned(UNIT)?;
        let mut iov: Vec<libc::iovec> = Vec::with_capacity(UNIT);
        loop {
            if failed.load(Ordering::Relaxed) {
                return Ok(());
            }
            let Some(k) = pick() else { return Ok(()) };
            let (first, n) = units[k];
            let bytes = &mut as_bytes(&mut buf)[..n * PAGE_SIZE];
            src.read(first, bytes)?;
            let mut unit = Unit { first, kinds: Vec::with_capacity(n), sums: Vec::new(), at: 0 };
            iov.clear();
            // Whole pages of this one allocation, not reused until `write` returns.
            for (i, page) in bytes.chunks(PAGE_SIZE).enumerate() {
                let (kind, sum) = classify(template, first + i, page);
                unit.kinds.push(kind);
                if kind != DATA as u8 {
                    continue;
                }
                unit.sums.push(sum);
                match iov.last_mut() {
                    Some(v) if unsafe { (v.iov_base as *const u8).add(v.iov_len) } == page.as_ptr() => v.iov_len += PAGE_SIZE,
                    _ => iov.push(libc::iovec { iov_base: page.as_ptr() as *mut _, iov_len: PAGE_SIZE }),
                }
            }
            unit.at = placed.fetch_add(unit.sums.len() as u64, Ordering::Relaxed);
            if !iov.is_empty() {
                out.write(&mut iov, unit.at * PAGE_SIZE as u64)?;
            }
            *done[k].lock().unwrap() = Some(unit);
        }
    };
    let threads = threads.min(units.len()).max(1);
    std::thread::scope(|s| {
        // A failed spawn must not panic (that aborts with the VM paused): stop the rest and report it.
        let mut spawned: Result<()> = Ok(());
        let handles: Vec<_> = (0..threads)
            .map_while(|_| {
                let h = std::thread::Builder::new().spawn_scoped(s, || work().inspect_err(|_| failed.store(true, Ordering::Relaxed)));
                h.map_err(|e| (failed.store(true, Ordering::Relaxed), spawned = Err(e.into()))).ok()
            })
            .collect();
        let joined = handles.into_iter().try_for_each(|h| h.join().unwrap());
        spawned.and(joined)
    })?;
    let data = placed.into_inner();
    let mut w = Written { map: MAGIC.to_vec(), data, zero: 0, sums: vec![0; data as usize] };
    let mut map: Vec<[u64; 4]> = Vec::new();
    let mut push = |page: usize, kind: u64, at: u64| {
        let kind = match kind {
            ZERO | DATA => kind,
            _ if explicit => TEMPLATE,
            _ => return,
        };
        w.zero += (kind == ZERO) as u64;
        match map.last_mut() {
            Some([f, n, k, a]) if *k == kind && *f + *n == page as u64 && (kind != DATA || *a + *n == at) => *n += 1,
            _ => map.push([page as u64, 1, kind, at]),
        }
    };
    let mut done = done.into_iter().map(|u| u.into_inner().unwrap().unwrap()).peekable();
    for &(first, count, state) in runs {
        if state == REMOTE {
            while let Some(u) = done.next_if(|u| u.first < (first + count) as usize) {
                let mut at = u.at;
                for (i, &kind) in u.kinds.iter().enumerate() {
                    push(u.first + i, kind as u64, at);
                    at += (kind as u64 == DATA) as u64;
                }
                w.sums[u.at as usize..u.at as usize + u.sums.len()].copy_from_slice(&u.sums);
            }
            continue;
        }
        // Discarded pages read as zero, which a template hole already is.
        for p in (first..first + count).map(|p| p as usize) {
            push(p, if state == crate::uffd::ZERO && template.has_data(p) { ZERO } else { BASE as u64 }, 0);
        }
    }
    out.file.set_len(data * PAGE_SIZE as u64)?;
    let words = [map.len() as u64, data].into_iter().chain(map.into_iter().flatten());
    w.map.extend(words.flat_map(u64::to_le_bytes));
    w.map.extend(w.sums.iter().flat_map(|s| s.to_le_bytes()));
    Ok(w)
}

pub struct Checkpoint {
    pub dir: PathBuf,
    pub manifest: Manifest,
    /// The manifest's checksum, by which a child names its parent.
    pub id: String,
    /// The verified VM state: load these bytes, not the file, which may have changed.
    pub vmstate: Vec<u8>,
    /// Initial page states for the pager: DATA pages are REMOTE, read from `file`.
    pub runs: Runs,
    pub file: Arc<PageFile>,
    /// Its ancestors, nearest first.
    pub chain: Vec<PathBuf>,
    pub chain_ids: Vec<String>,
    pub meta_left: u64,
}

fn read_at(dir: RawFd, name: &str, max: u64) -> io::Result<(File, Vec<u8>)> {
    let f = open_at(dir, name)?;
    let st = fstat(f.as_raw_fd())?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    io::Read::take(&f, max).read_to_end(&mut bytes)?;
    Ok((f, bytes))
}

struct Link {
    dir: PathBuf,
    manifest: Manifest,
    id: String,
    vmstate: Vec<u8>,
    map: Vec<Run>,
    file: Option<File>,
    sums: Vec<u32>,
}

impl Link {
    /// With `meta_left`, also reads and checks the rest within that budget (debited) and opens `pages`.
    fn open(dir: &Path, ck: usize, meta_left: Option<&mut u64>) -> Result<Link> {
        let dir = dir.canonicalize().map_err(|e| format!("checkpoint {}: {e}", dir.display()))?;
        let bad = |why: String| format!("checkpoint {} is invalid: {why}", dir.display());
        let dfd = open_dir_at(libc::AT_FDCWD, &CString::new(dir.as_os_str().as_bytes())?).map_err(|e| bad(e.to_string()))?;
        let (_, text) = read_at(dfd.as_raw_fd(), "manifest.json", 1 << 20).map_err(|e| bad(format!("manifest.json: {e}")))?;
        let split = text.iter().position(|&b| b == b'\n').ok_or_else(|| bad("manifest has no checksum".into()))?;
        ensure!(text[..split] == *sum(&text[split + 1..]).as_bytes(), "{}", bad("manifest checksum mismatch".into()));
        let manifest: Manifest = serde_json::from_slice(&text[split + 1..]).map_err(|e| bad(format!("manifest: {e}")))?;
        let id = String::from_utf8_lossy(&text[..split]).into_owned();
        match (manifest.format, &manifest.parent) {
            (FORMAT, None) | (FORMAT_INCREMENTAL, Some(_)) => {}
            (f, _) => bail!("{}", bad(format!("format {f}; this flexvm reads formats {FORMAT} and {FORMAT_INCREMENTAL}"))),
        }
        let Some(meta_left) = meta_left else {
            return Ok(Link { dir, manifest, id, vmstate: Vec::new(), map: Vec::new(), file: None, sums: Vec::new() });
        };
        // Bound what we read: a page map has at most a run (32 bytes) and a checksum (4) per page.
        let len = |name: &str| manifest.files.get(name).map_or(0, |f| f.len);
        let map_max = manifest.guest_pages.checked_mul(36).and_then(|n| n.checked_add(24));
        ensure!(len("vmstate") <= MAX_VMSTATE && map_max.is_some_and(|m| len("pagemap") <= m), "{}", bad("vmstate or pagemap is too long".into()));
        let cost = (text.len() as u64 + len("vmstate")).saturating_add(len("pagemap"));
        *meta_left = meta_left.checked_sub(cost).ok_or_else(|| bad(format!("its chain has more than {} bytes of metadata", chain_meta_budget())))?;
        let read_checked = |name: &str| -> Result<Vec<u8>> {
            let want = manifest.files.get(name).ok_or_else(|| bad(format!("manifest lists no {name}")))?;
            let (_, bytes) = read_at(dfd.as_raw_fd(), name, want.len + 1).map_err(|e| bad(format!("{name}: {e}")))?;
            ensure!(bytes.len() as u64 == want.len && sum(&bytes) == want.hash, "{}", bad(format!("{name} does not match its checksum")));
            Ok(bytes)
        };
        let vmstate = read_checked("vmstate")?;
        let (map, sums) = parse_pagemap(&read_checked("pagemap")?, manifest.guest_pages, manifest.parent.is_some(), ck).map_err(|e| bad(e.to_string()))?;
        let data: u64 = map.iter().filter(|r| r.2 == DATA).map(|r| r.1).sum();
        ensure!(data == manifest.data_pages && manifest.files.get("pages").map(|f| f.len) == Some(data * PAGE_SIZE as u64), "{}", bad("page counts do not add up".into()));
        ensure!(manifest.files["pages"].hash == sums_sum(&sums), "{}", bad("page checksums do not match the manifest".into()));
        let (file, _) = read_at(dfd.as_raw_fd(), "pages", 0).map_err(|e| bad(format!("pages: {e}")))?;
        ensure!(file.metadata()?.len() == data * PAGE_SIZE as u64, "{}", bad("pages has the wrong length".into()));
        Ok(Link { dir, manifest, id, vmstate, map, file: Some(file), sums })
    }
}

/// The chain ending at `dir`, nearest first; `full` verifies all metadata within
/// `chain_meta_budget` (returning what is left), else only manifests.
fn open_chain(dir: &Path, full: bool) -> Result<(Vec<Link>, u64)> {
    let mut meta_left = chain_meta_budget();
    let mut links = vec![Link::open(dir, 0, full.then_some(&mut meta_left))?];
    while let Some(parent) = links.last().unwrap().manifest.parent.clone() {
        let child = links.last().unwrap();
        ensure!(links.len() < MAX_CHAIN, "checkpoint {} is more than {MAX_CHAIN} deltas deep", dir.display());
        let link = Link::open(&child.dir.join(&parent.path), links.len(), full.then_some(&mut meta_left))
            .map_err(|e| format!("parent of {}: {e}", child.dir.display()))?;
        ensure!(link.id == parent.id, "checkpoint {}: its parent {} has changed (id {} is not {})", child.dir.display(), link.dir.display(), link.id, parent.id);
        ensure!(child.manifest.template_id == link.manifest.template_id && child.manifest.guest_pages == link.manifest.guest_pages, "checkpoint {}: its parent {} is of another template or size", child.dir.display(), link.dir.display());
        links.push(link);
    }
    Ok((links, meta_left))
}

pub fn chain_ids(dir: &Path) -> Result<Vec<String>> {
    Ok(open_chain(dir, false)?.0.into_iter().map(|l| l.id).collect())
}

pub fn parent_path(child: &Path, parent: &Path) -> String {
    match (child.parent(), parent.parent(), parent.file_name()) {
        (Some(a), Some(b), Some(name)) if a == b => format!("../{}", name.to_string_lossy()),
        _ => parent.to_string_lossy().into_owned(),
    }
}

impl Checkpoint {
    /// Opens the chain ending at `dir`, verifying all but page data, which is checked as read.
    pub fn open(dir: &Path) -> Result<Checkpoint> {
        let (mut links, meta_left) = open_chain(dir, true)?;
        let layers: Vec<Vec<Run>> = links.iter_mut().rev().map(|l| std::mem::take(&mut l.map)).collect();
        let (mut files, mut sums, mut rest) = (Vec::new(), Vec::new(), Vec::new());
        for l in links {
            files.push(l.file.unwrap());
            sums.push(l.sums);
            rest.push((l.dir, l.manifest, l.id, l.vmstate));
        }
        let mut rest = rest.into_iter();
        let (dir, manifest, id, vmstate) = rest.next().unwrap();
        let (chain, chain_ids) = rest.map(|(dir, _, id, _)| (dir, id)).unzip();
        let (runs, file) = flatten(&layers, files, sums);
        Ok(Checkpoint { dir, manifest, id, vmstate, runs, file: Arc::new(file), chain, chain_ids, meta_left })
    }

    fn each_page(&self, drop_cache: bool, mut f: impl FnMut(usize, &[u8])) -> Result<()> {
        let mut buf = vec![0u8; 256 * PAGE_SIZE];
        for &(first, count, state) in &self.runs {
            for p in (first as usize..(first + count) as usize).step_by(256) {
                let n = ((first + count) as usize - p).min(256);
                if state != REMOTE {
                    (p..p + n).for_each(|p| f(p, &[]));
                    continue;
                }
                let b = &mut buf[..n * PAGE_SIZE];
                self.file.read(p, b, drop_cache)?;
                b.chunks(PAGE_SIZE).enumerate().for_each(|(i, page)| f(p + i, page));
            }
        }
        Ok(())
    }

    pub fn verify_data(&self) -> Result<()> {
        self.each_page(true, |_, _| {})
    }

    pub fn data_pages(&self) -> u64 {
        self.file.runs.iter().map(|r| r.1).sum()
    }

    pub fn content_hash(&self, template: &Template) -> Result<String> {
        let mut canon = Canon::new(template);
        self.each_page(false, |p, b| canon.page(p, b))?;
        Ok(canon.finish())
    }
}

/// A hash of guest memory independent of how it is stored: every page that
/// is neither the template's nor zero over a template hole, with its number,
/// in page order. A paused VM and a checkpoint of it hash the same.
pub struct Canon<'a> {
    template: &'a Template,
    hash: Hash,
    pages: u64,
}

impl<'a> Canon<'a> {
    pub fn new(template: &'a Template) -> Canon<'a> {
        Canon { template, hash: Hash::new(), pages: 0 }
    }

    /// Adds page `p` with contents `bytes` (empty: a zero page). Call in page order.
    pub fn page(&mut self, p: usize, bytes: &[u8]) {
        static ZEROES: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
        let bytes = if bytes.is_empty() { &ZEROES[..] } else { bytes };
        let base: &[u8] = if self.template.has_data(p) { self.template.pages(p, 1) } else { &ZEROES };
        if bytes != base {
            self.hash.word(p as u64);
            self.hash.update(bytes);
            self.pages += 1;
        }
    }

    pub fn finish(self) -> String {
        format!("{}/{}", self.hash.finish(), self.pages)
    }
}

/// A page map run: (first page, count, kind, checkpoint's index in its
/// chain, index of the first in that checkpoint's `pages`).
type Run = (u64, u64, u64, usize, u64);

fn overlay(base: &[Run], top: &[Run]) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::with_capacity(base.len() + top.len());
    for &(first, count, kind, ck, at) in base {
        let end = first + count;
        let mut pos = first;
        let mut t = top.partition_point(|r| r.0 + r.1 <= first);
        while pos < end {
            let next = top.get(t).filter(|r| r.0 < end);
            let gap_end = next.map_or(end, |r| r.0.max(pos));
            if gap_end > pos {
                let skip = pos - first;
                out.push((pos, gap_end - pos, kind, ck, if kind == DATA { at + skip } else { 0 }));
            }
            pos = next.map_or(end, |r| (r.0 + r.1).max(pos));
            t += 1;
        }
    }
    out.extend_from_slice(top);
    out.sort_unstable_by_key(|r| r.0);
    out
}

fn flatten(layers: &[Vec<Run>], files: Vec<File>, sums: Vec<Vec<u32>>) -> (Runs, PageFile) {
    let mut runs: Vec<Run> = Vec::new();
    for layer in layers {
        runs = overlay(&runs, layer);
    }
    let mut states: Runs = Vec::new();
    let mut data = Vec::new();
    for (first, count, kind, ck, at) in runs.into_iter().filter(|r| r.2 != TEMPLATE) {
        if kind == DATA {
            data.push((first, count, ck, at));
        }
        states.push((first, count, if kind == DATA { REMOTE } else { crate::uffd::ZERO }));
    }
    (states, PageFile { files, runs: data, sums })
}

/// TEMPLATE runs are allowed only in a delta.
fn parse_pagemap(map: &[u8], guest_pages: u64, delta: bool, ck: usize) -> Result<(Vec<Run>, Vec<u32>)> {
    let word = |i: usize| -> Result<u64> {
        Ok(u64::from_le_bytes(map.get(i * 8..i * 8 + 8).ok_or("pagemap truncated")?.try_into()?))
    };
    ensure!(map.len() >= 24 && &map[..8] == MAGIC, "bad pagemap header");
    let (nruns, ndata) = (word(1)?, word(2)?);
    ensure!(Some(map.len() as u64) == nruns.checked_mul(32).zip(ndata.checked_mul(4)).and_then(|(r, d)| (24 + r).checked_add(d)), "bad pagemap length");
    let nruns = nruns as usize;
    let (mut runs, mut next) = (Vec::with_capacity(nruns), 0u64);
    for r in 0..nruns {
        let [first, count, kind, at] = [0, 1, 2, 3].map(|i| word(3 + 4 * r + i));
        let (first, count, kind, at) = (first?, count?, kind?, at?);
        let end = first.checked_add(count).filter(|&e| count > 0 && first >= next && e <= guest_pages);
        let Some(end) = end else { bail!("page run {r} out of order or bounds") };
        next = end;
        match kind {
            DATA | ZERO => runs.push((first, count, kind, ck, at)),
            TEMPLATE if delta => runs.push((first, count, kind, ck, 0)),
            k => bail!("page run {r} has kind {k}"),
        }
    }
    let mut tiles: Vec<(u64, u64)> = runs.iter().filter(|r| r.2 == DATA).map(|r| (r.4, r.1)).collect();
    tiles.sort_unstable();
    let end = tiles.iter().try_fold(0u64, |pos, &(at, n)| (at == pos).then_some(pos + n));
    ensure!(end == Some(ndata), "data runs do not cover the {ndata} stored pages exactly once");
    let sums = map[24 + 32 * nruns..].chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    Ok((runs, sums))
}

pub struct PageFile {
    files: Vec<File>,
    /// DATA runs: (first guest page, pages, file, index of the first in it).
    runs: Vec<(u64, u64, usize, u64)>,
    sums: Vec<Vec<u32>>,
}

fn corrupt(why: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("checkpoint page file: {why}"))
}

impl PageFile {
    /// Errors are InvalidData, which the pager treats as fatal.
    pub fn read(&self, page: usize, buf: &mut [u8], drop_cache: bool) -> io::Result<()> {
        let n = buf.len() / PAGE_SIZE;
        let mut done = 0;
        while done < n {
            let p = (page + done) as u64;
            let r = self.runs.partition_point(|r| r.0 <= p);
            let (first, count, f, d) = match r.checked_sub(1).map(|r| self.runs[r]) {
                Some(run) if p < run.0 + run.1 => run,
                _ => return Err(corrupt(format!("page {p} is not stored"))),
            };
            let (k, d) = (((first + count - p) as usize).min(n - done), d + p - first);
            let (out, off, file) = (&mut buf[done * PAGE_SIZE..(done + k) * PAGE_SIZE], d * PAGE_SIZE as u64, &self.files[f]);
            file.read_exact_at(out, off).map_err(|e| corrupt(format!("read at {off}: {e}")))?;
            if drop_cache {
                unsafe { libc::posix_fadvise(file.as_raw_fd(), off as i64, out.len() as i64, libc::POSIX_FADV_DONTNEED) };
            }
            for (i, page) in out.chunks(PAGE_SIZE).enumerate() {
                let d = d as usize + i;
                if crc32c::page(page).0 != self.sums[f][d] {
                    return Err(corrupt(format!("data page {d} does not match its checksum")));
                }
            }
            done += k;
        }
        Ok(())
    }

    pub fn drop_cache(&self) {
        for f in &self.files {
            unsafe { libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::Paths;
    use crate::uffd::{BASE as P_BASE, ZERO as P_ZERO};
    use serde_json::json;
    use std::fs;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("flexvm-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn manifest(guest_pages: usize, parent: Option<Parent>, files: serde_json::Value) -> Manifest {
        serde_json::from_value(json!({
            "format": if parent.is_some() { FORMAT_INCREMENTAL } else { FORMAT }, "created_unix_ms": 0, "name": "x",
            "ip": "10.0.0.1", "template": "tpl", "template_id": "id", "vcpus": 1, "mem_mib": 1, "max_mib": 1,
            "hotplug_mib": 0, "guest_pages": guest_pages, "data_pages": 0, "zero_pages": 0, "parent": parent, "files": files,
        }))
        .unwrap()
    }

    /// A 256-page checkpoint with nothing stored, its manifest changed by `edit`; returns its id.
    fn link(dir: &Path, parent: Option<Parent>, edit: impl FnOnce(&mut Manifest)) -> String {
        fs::create_dir_all(dir).unwrap();
        let map = [MAGIC.as_slice(), &[0; 16]].concat();
        for (name, bytes) in [("vmstate", &b"s"[..]), ("pagemap", &map), ("pages", &[])] {
            fs::write(dir.join(name), bytes).unwrap();
        }
        let files = json!({"vmstate": {"len": 1, "hash": sum(b"s")}, "pagemap": {"len": map.len(), "hash": sum(&map)}, "pages": {"len": 0, "hash": sums_sum(&[])}});
        let mut m = manifest(256, parent, files);
        edit(&mut m);
        let body = serde_json::to_vec(&m).unwrap();
        fs::write(dir.join("manifest.json"), [format!("{}\n", sum(&body)).as_bytes(), &body].concat()).unwrap();
        sum(&body)
    }

    #[test]
    fn metadata_is_bounded_before_reading() {
        let dir = tmp("lengths");
        type Edit = fn(&mut Manifest);
        let cases: [(Edit, &str); 5] = [
            (|m| m.files.get_mut("vmstate").unwrap().len = MAX_VMSTATE + 1, "too long"),
            (|m| m.files.get_mut("vmstate").unwrap().len = u64::MAX, "too long"),
            (|m| m.files.get_mut("pagemap").unwrap().len = 24 + 36 * 256 + 1, "too long"),
            (|m| (m.guest_pages, m.files.get_mut("pagemap").unwrap().len) = (u64::MAX, u64::MAX), "too long"),
            (|m| (m.guest_pages, m.files.get_mut("pagemap").unwrap().len) = (1 << 40, 1 << 40), "bytes of metadata"),
        ];
        for (edit, want) in cases {
            link(&dir.join("bad"), None, edit);
            let e = Checkpoint::open(&dir.join("bad")).err().unwrap().to_string();
            assert!(e.contains(want), "{e}");
        }
        // A chain reads at most its budget: the base is refused once it runs out.
        let (mut parent, mut ids) = (None, Vec::new());
        for i in 0..3 {
            let id = link(&dir.join(format!("ck{i}")), parent, |_| {});
            ids.insert(0, id.clone());
            parent = Some(Parent { path: format!("../ck{i}"), id });
        }
        let top = dir.join("ck2");
        let ck = Checkpoint::open(&top).unwrap();
        assert_eq!((ck.chain.len(), &ck.chain_ids[..], chain_ids(&top).unwrap()), (2, &ids[1..], ids.clone()));
        let cost = chain_meta_budget() - ck.meta_left;
        Link::open(&top, 0, Some(&mut { cost })).unwrap();
        let mut left = cost - 1;
        let e = (0..3).rev().try_for_each(|i| Link::open(&dir.join(format!("ck{i}")), 0, Some(&mut left)).map(drop));
        assert!(e.err().unwrap().to_string().contains("bytes of metadata"));
        fs::remove_dir_all(&dir).unwrap();
    }

    fn template(dir: &Path, pages: &[Option<u8>]) -> Arc<Template> {
        let tdir = dir.join("tpl");
        fs::create_dir_all(&tdir).unwrap();
        fs::write(tdir.join("meta.json"), r#"{"vcpus": 1, "mem_mib": 1, "max_mib": 1, "kernel": "/k", "rootfs": "/r"}"#).unwrap();
        let mem = File::create(tdir.join("mem")).unwrap();
        mem.set_len((pages.len() * PAGE_SIZE) as u64).unwrap();
        for (i, b) in pages.iter().enumerate().filter_map(|(i, p)| Some((i, (*p)?))) {
            mem.write_all_at(&[b; PAGE_SIZE], (i * PAGE_SIZE) as u64).unwrap();
        }
        let paths = Paths { firecracker: "/f".into(), kernel: "/k".into(), rootfs: "/r".into(), templates: dir.into() };
        Template::open(&paths, "tpl").unwrap()
    }

    fn page(seed: usize) -> Vec<u8> {
        (0..PAGE_SIZE).map(|i| (i * 31 + seed * 7 + 1) as u8).collect()
    }

    fn pages_file(path: &Path) -> PagesFile {
        let dir = File::open(path.parent().unwrap()).unwrap();
        PagesFile::new(create_at(dir.as_raw_fd(), path.file_name().unwrap().to_str().unwrap()).unwrap())
    }

    /// Guest memory: pages, in regions of `.1` pages; reading page `.2` fails.
    struct Guest(Vec<Vec<u8>>, usize, Option<usize>);

    impl GuestPages for Guest {
        fn region_end(&self, page: usize) -> Option<usize> {
            (page < self.0.len()).then(|| ((page / self.1 + 1) * self.1).min(self.0.len()))
        }

        fn read(&self, page: usize, buf: &mut [u8]) -> Result<()> {
            for (i, b) in buf.chunks_mut(PAGE_SIZE).enumerate() {
                if Some(page + i) == self.2 {
                    bail!("cannot read page {}", page + i);
                }
                b.copy_from_slice(&self.0[page + i]);
            }
            Ok(())
        }
    }

    fn runs_of(ps: impl IntoIterator<Item = (usize, u8)>) -> Runs {
        let mut out: Runs = Vec::new();
        for (p, s) in ps {
            match out.last_mut() {
                Some((f, n, st)) if *st == s && *f + *n == p as u64 => *n += 1,
                _ => out.push((p as u64, 1, s)),
            }
        }
        out
    }

    fn restore(tpl: &Template, n: usize, runs: &Runs, file: &PageFile) -> Vec<(u8, Vec<u8>)> {
        let mut state = vec![P_BASE; n];
        runs.iter().for_each(|&(f, c, s)| state[f as usize..(f + c) as usize].fill(s));
        let mut b = vec![0; PAGE_SIZE];
        let mut read = |i: usize, st: u8| match st {
            P_BASE if tpl.has_data(i) => tpl.pages(i, 1).to_vec(),
            P_BASE | P_ZERO => vec![0; PAGE_SIZE],
            _ => file.read(i, &mut b, false).map(|()| b.clone()).unwrap(),
        };
        state.into_iter().enumerate().map(|(i, st)| (st, read(i, st))).collect()
    }

    #[test]
    fn pages_roundtrip_against_the_template() {
        let dir = tmp("ckpt");
        let n = 1000;
        let tpl_pages: Vec<Option<u8>> = (0..n).map(|i| (i % 2 == 0).then_some(i as u8 | 1)).collect();
        let tpl = template(&dir, &tpl_pages);
        let zero = || vec![0; PAGE_SIZE];
        let pages: Vec<Vec<u8>> = (0..n).map(|i| [tpl_pages[i].map_or(zero(), |b| vec![b; PAGE_SIZE]), zero()].get(i % 5).cloned().unwrap_or_else(|| page(i))).collect();
        // Pages 7 and 300..320 were discarded by the guest; 900.. were never touched.
        let discarded = |i: usize| i == 7 || (300..320).contains(&i);
        let input = runs_of((0..900).map(|i| (i, if discarded(i) { P_ZERO } else { REMOTE })));
        let want = |i: usize| if discarded(i) { zero() } else if i < 900 { pages[i].clone() } else { tpl.pages(i, 1).to_vec() };
        let guest = Guest(pages.clone(), 333, None);
        let want_data = (0..900).filter(|&i| i % 5 >= 2 && !discarded(i)).count() as u64;
        let want_zero = (0..900).filter(|&i| i % 2 == 0 && (i % 5 == 1 || discarded(i))).count() as u64;
        let mut last = None;
        for threads in [8, 3, 1] {
            let path = dir.join(format!("pages-{threads}"));
            let w = write_pages(&tpl, &guest, &input, &pages_file(&path), threads, false).unwrap();
            assert_eq!((w.data, w.zero, fs::metadata(&path).unwrap().len()), (want_data, want_zero, w.data * PAGE_SIZE as u64));
            let (map, sums) = parse_pagemap(&w.map, n as u64, false, 0).unwrap();
            // Runs past the guest's end, a truncated map, and a DATA run pointing anywhere but its place.
            let mut bad = w.map.clone();
            let r = (0..map.len()).find(|&r| bad[24 + 32 * r + 16] == DATA as u8).unwrap();
            bad[24 + 32 * r + 24] ^= 1;
            for (map, pages) in [(&w.map[..], 899), (&w.map[..w.map.len() - 4], n as u64), (&bad[..], n as u64)] {
                assert!(parse_pagemap(map, pages, false, 0).is_err());
            }
            let (runs, file) = flatten(&[map], vec![File::open(&path).unwrap()], vec![sums]);
            let got = restore(&tpl, n, &runs, &file);
            for (i, (st, page)) in got.iter().enumerate() {
                assert!(*page == want(i), "page {i} (state {st}, {threads} threads)");
            }
            last = Some((runs, got, file, path));
        }
        let (runs, got, file, path) = last.unwrap();
        let (f, c, _) = runs.iter().copied().filter(|r| r.2 == REMOTE).max_by_key(|r| r.1).unwrap();
        let mut b = vec![0; c as usize * PAGE_SIZE];
        file.read(f as usize, &mut b, true).unwrap();
        assert_eq!(&b[(c as usize - 1) * PAGE_SIZE..], &want((f + c) as usize - 1)[..]);
        // Pages that are not stored, and exactly the corrupt page, are InvalidData.
        let mut one = zero();
        assert_eq!(file.read(0, &mut one, false).unwrap_err().kind(), io::ErrorKind::InvalidData);
        fs::OpenOptions::new().write(true).open(&path).unwrap().write_all_at(&[0xff], (5 * PAGE_SIZE + 5) as u64).unwrap();
        let bad: Vec<_> = (0..n).filter_map(|i| (got[i].0 == REMOTE).then(|| file.read(i, &mut one, false).err()).flatten()).collect();
        assert_eq!(bad.iter().map(|e| e.kind()).collect::<Vec<_>>(), [io::ErrorKind::InvalidData]);
        // A failed read fails the whole write instead of hanging the other writers.
        assert!(write_pages(&tpl, &Guest(pages, 333, Some(500)), &input, &pages_file(&dir.join("pages-fail")), 4, false).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn deltas_flatten_over_their_parents() {
        let dir = tmp("delta");
        let n = 300;
        let tpl_pages: Vec<Option<u8>> = (0..n).map(|i| (i % 3 == 0).then_some(i as u8 | 1)).collect();
        let tpl = template(&dir, &tpl_pages);
        let tpl_page = |i: usize| tpl_pages[i].map_or(vec![0; PAGE_SIZE], |b| vec![b; PAGE_SIZE]);
        let v1: Vec<Vec<u8>> = (0..n).map(|i| if i < 200 { page(i) } else { tpl_page(i) }).collect();
        let w1 = write_pages(&tpl, &Guest(v1.clone(), 128, None), &runs_of((0..200).map(|i| (i, REMOTE))), &pages_file(&dir.join("p1")), 3, false).unwrap();
        // Generation 2: new data, back to the template's, zero, discarded, and populated since (BASE before).
        let (mut v2, mut dirty) = (v1, Vec::new());
        type Change<'a> = (&'a [usize], u8, &'a dyn Fn(usize) -> Vec<u8>);
        let changes: [Change; 5] = [
            (&[5, 6, 7, 50, 199, 251], REMOTE, &|i| page(i + 1000)),
            (&[9, 10], REMOTE, &tpl_page),
            (&[20], REMOTE, &|_| vec![0; PAGE_SIZE]),
            (&[30, 31, 32, 33], P_ZERO, &|_| vec![0; PAGE_SIZE]),
            (&[250], P_BASE, &tpl_page),
        ];
        for (pages, state, bytes) in changes {
            for &i in pages {
                v2[i] = bytes(i);
                dirty.push((i, state));
            }
        }
        dirty.sort();
        let w2 = write_pages(&tpl, &Guest(v2.clone(), 128, None), &runs_of(dirty), &pages_file(&dir.join("p2")), 2, true).unwrap();
        assert_eq!(w2.data, 6, "only the changed data pages are stored");
        let (m1, s1) = parse_pagemap(&w1.map, n as u64, false, 1).unwrap();
        let (m2, s2) = parse_pagemap(&w2.map, n as u64, true, 0).unwrap();
        assert!(parse_pagemap(&w2.map, n as u64, false, 0).is_err(), "TEMPLATE runs only in a delta");
        assert!(m2.iter().any(|r| r.2 == TEMPLATE));
        let files = vec![File::open(dir.join("p2")).unwrap(), File::open(dir.join("p1")).unwrap()];
        let (runs, file) = flatten(&[m1, m2], files, vec![s2, s1]);
        for (i, (st, page)) in restore(&tpl, n, &runs, &file).into_iter().enumerate() {
            assert!(page == v2[i], "page {i} (state {st})");
        }
        let mut want = Canon::new(&tpl);
        v2.iter().enumerate().for_each(|(i, p)| want.page(i, p));
        let (manifest, file) = (manifest(n, None, json!({})), Arc::new(file));
        let ck = Checkpoint { dir: dir.clone(), manifest, id: String::new(), vmstate: Vec::new(), runs, file, chain: Vec::new(), chain_ids: Vec::new(), meta_left: 0 };
        assert_eq!(ck.content_hash(&tpl).unwrap(), want.finish());
        ck.verify_data().unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn overlays_buffers_and_parent_paths() {
        let base: Vec<Run> = vec![(0, 10, DATA, 1, 100), (20, 5, ZERO, 1, 0)];
        let top: Vec<Run> = vec![(2, 2, ZERO, 0, 0), (5, 1, TEMPLATE, 0, 0), (9, 13, DATA, 0, 7)];
        let want = [(0, 2, DATA, 1, 100), (2, 2, ZERO, 0, 0), (4, 1, DATA, 1, 104), (5, 1, TEMPLATE, 0, 0), (6, 3, DATA, 1, 106), (9, 13, DATA, 0, 7), (22, 3, ZERO, 1, 0)];
        assert_eq!(overlay(&base, &top), want);
        assert_eq!(parent_path(Path::new("/d/ck2"), Path::new("/d/ck1")), "../ck1");
        assert_eq!(parent_path(Path::new("/e/ck2"), Path::new("/d/ck1")), "/d/ck1");
        // Writer buffers are aligned and zeroed; one larger than Linux can map fails, even with overcommit.
        let mut buf = aligned(2).unwrap();
        assert_eq!(buf.as_ptr() as usize % PAGE_SIZE, 0);
        assert!(as_bytes(&mut buf).len() == 2 * PAGE_SIZE && as_bytes(&mut buf).iter().all(|&b| b == 0));
        assert_eq!(aligned(isize::MAX as usize / PAGE_SIZE).err().unwrap().kind(), io::ErrorKind::OutOfMemory);
    }

    #[test]
    fn staging_is_private_never_overwrites_and_cleans_up() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let dir = tmp("stage");
        let dest = dir.join("ck");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        // Staging left by a process that is gone is cleared if it is private like ours; anything else is left alone.
        let (stale, foreign) = (dir.join(format!("{STAGING_PREFIX}999999999-1")), dir.join(format!("{STAGING_PREFIX}999999998-1")));
        fs::create_dir_all(stale.join("ck")).unwrap();
        fs::write(stale.join("ck/pages"), b"x").unwrap();
        fs::write(stale.join("ck/GEN"), b"generation").unwrap();
        fs::create_dir_all(&foreign).unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755)).unwrap();
        let s = Staging::new(&dest, dir.join("vmstate.private")).unwrap();
        assert!(!stale.exists() && foreign.exists());
        let ours = format!("{STAGING_PREFIX}{}", std::process::id());
        let mine = || fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(&ours)).collect::<Vec<_>>();
        assert_eq!(mine().iter().map(|p| mode(p)).collect::<Vec<_>>(), [0o700]);
        drop(s.create("pages").unwrap());
        assert!(s.create("pages").is_err());
        symlink("/etc/hostname", dir.join("link")).unwrap();
        assert!(create_at(s.parent.as_raw_fd(), "link").is_err() && open_at(s.parent.as_raw_fd(), "link").is_err());
        let files: Vec<_> = ["vmstate", "pagemap", "manifest.json"].map(|f| s.create(f).unwrap()).into();
        s.add_file("GEN", b"generation").unwrap();
        let owner = fstat(s.parent.as_raw_fd()).unwrap();
        publish_permissions(&files.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>(), s.ck.as_raw_fd(), &owner).unwrap();
        for m in files.iter().map(|f| f.metadata().unwrap()) {
            assert_eq!((m.permissions().mode() & 0o777, m.uid(), m.gid()), (0o600, owner.st_uid, owner.st_gid));
        }
        assert_eq!(mode(&mine()[0].join("ck")), 0o700);
        drop(s);
        assert!(!dest.exists() && mine().is_empty());
        fs::create_dir_all(&dest).unwrap();
        assert!(Staging::new(&dest, dir.join("vmstate.private")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
