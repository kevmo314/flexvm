//! Durable checkpoints: a VM's complete state on disk, stored as a delta
//! against its template, and the page source that restores one lazily.
//!
//! A checkpoint is a directory (format 2):
//!
//!   manifest.json  line 1: checksum of the rest of the file; then the
//!                  `Manifest` JSON (template id, address, machine, file sums)
//!   vmstate        Firecracker's vCPU and device state (a state-only snapshot)
//!   pagemap        "FVPGMAP2", run count, data page count (u64 LE each), then
//!                  runs as (first page, page count, kind, index of the first
//!                  in `pages`) (u64 LE each) and the CRC32C of every page in
//!                  `pages` (u32 LE each)
//!   pages          the DATA pages, back to back (in about guest page order)
//!
//! Every guest page is one of
//!
//!   BASE  the template's page (a template hole is a zero page); not stored
//!   ZERO  a zero page where the template has data; stored as a run only
//!   DATA  anything else; stored in `pages`
//!
//! The pager's PRESENT pages are a superset of the pages that differ from the
//! template (prefetched template pages are PRESENT too), so the writer
//! compares each one with the template and with zero before storing it.
//!
//! The writer splits the PRESENT pages into units of `UNIT` pages that
//! `writer_threads` threads take in turn. A thread copies its unit out of
//! Firecracker (the one copy), classifies and checksums each page in a
//! single pass, reserves room in `pages` for the unit's DATA pages and
//! writes them there straight from its buffer with O_DIRECT. Units take
//! their place in `pages` as they finish, so no thread waits for another;
//! the page map records where each run went. `pages` is preallocated before
//! the VM pauses so the writes run in parallel.
//!
//! Crash consistency: everything is written into a fresh `.NAME.partial-*`
//! directory next to the destination, fsynced, and then renamed into place
//! (never over an existing one) and the parent fsynced. A checkpoint directory
//! therefore either holds a complete checkpoint or does not exist, and is
//! never modified afterwards. Restores verify the manifest, `vmstate` and
//! `pagemap` up front, and every page of `pages` as it is read.

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
use crate::crc32c;
use crate::template::{Hash, Template};
use crate::uffd::{Pager, Runs, REMOTE};
use crate::util::{Error, Phases, Result, PAGE_SIZE};
use crate::vm::Vm;

pub const FORMAT: u64 = 2;
const MAGIC: &[u8; 8] = b"FVPGMAP2";
const DATA: u64 = 1;
const ZERO: u64 = 2;
/// Pages per writer work unit: read, classified and written together.
const UNIT: usize = 256;
/// Most writer threads; a few saturate the disk.
const MAX_WRITERS: usize = 12;

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
    /// virtio-mem memory plugged at checkpoint time.
    pub hotplug_mib: u64,
    pub guest_pages: u64,
    pub data_pages: u64,
    pub zero_pages: u64,
    pub files: BTreeMap<String, FileSum>,
}

fn sum(bytes: &[u8]) -> String {
    let mut h = Hash::new();
    h.update(bytes);
    h.finish()
}

/// The checksum of the per-page checksums, for the manifest.
fn sums_sum(sums: &[u32]) -> String {
    let mut h = Hash::new();
    sums.iter().for_each(|&c| h.word(c as u64));
    h.finish()
}

fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn cname(name: &str) -> CString {
    CString::new(name).expect("no NUL in file names")
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Opens directory `name` in `dir` without following a symlink.
fn open_dir_at(dir: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::openat(dir, name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    check(fd)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Creates file `name` in `dir`; never an existing file, never through a symlink.
fn create_at(dir: RawFd, name: &str) -> io::Result<File> {
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(dir, cname(name).as_ptr(), flags, 0o600) };
    check(fd)?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Opens file `name` in `dir` for reading, never through a symlink.
fn open_at(dir: RawFd, name: &str) -> io::Result<File> {
    // O_NONBLOCK: opening a FIFO planted in its place must not block; callers
    // check it is a regular file, where the flag changes nothing.
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let fd = unsafe { libc::openat(dir, cname(name).as_ptr(), flags) };
    check(fd)?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn fsync_fd(fd: RawFd) -> io::Result<()> {
    check(unsafe { libc::fsync(fd) })
}

/// The files of a checkpoint, as `Staging` writes them.
const FILES: [&str; 4] = ["vmstate", "pages", "pagemap", "manifest.json"];
const STAGING_PREFIX: &str = ".flexvm-staging-";

/// Why a commit failed.
pub enum CommitError {
    /// Nothing was published (or what was is durably unusable): the VM may resume.
    Failed(Error),
    /// The checkpoint was published but may not be durable, and could not be
    /// revoked: resuming the VM could leave a stale checkpoint behind that
    /// later restores, so it must not resume.
    Uncertain(Error),
}

impl<E: Into<Error>> From<E> for CommitError {
    fn from(e: E) -> Self {
        CommitError::Failed(e.into())
    }
}

/// A checkpoint being written, which becomes `dest` only once complete and
/// durable. Dropped unpublished, it is removed.
///
/// The destination's directory may belong to an unprivileged user while the
/// daemon runs as root, so nothing here follows a path the user can change:
/// the destination's directory is pinned by fd, files are written inside a
/// root-only (0700) staging directory in it, also pinned, and are created
/// with `O_EXCL | O_NOFOLLOW`. Firecracker writes the VM state into the VM's
/// own run directory, from where it is copied in. Publishing renames the
/// checkpoint out of the staging directory into the destination's directory,
/// fd to fd, never over anything.
pub struct Staging {
    dest: PathBuf,
    parent: OwnedFd,
    base: CString,
    /// The root-only staging directory in `parent`, and its name there.
    outer: OwnedFd,
    outer_name: CString,
    /// The checkpoint directory inside `outer` (named "ck"), published as `dest`.
    ck: OwnedFd,
    vmstate: PathBuf,
    /// `pages`, once preallocated.
    pages: Option<PagesFile>,
    published: bool,
}

impl Staging {
    /// Claims a staging directory for a checkpoint at `dest`, which must not
    /// exist yet (checkpoints are immutable); Firecracker is to write the VM
    /// state to `vmstate`, a path only root controls. Clears out staging
    /// directories that daemons no longer running left in the same directory.
    pub fn new(dest: &Path, vmstate: PathBuf) -> Result<Staging> {
        let parent = match dest.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let base = dest.file_name().ok_or_else(|| format!("bad checkpoint path {}", dest.display()))?;
        let parent_path = parent.canonicalize().map_err(|e| format!("checkpoint directory {}: {e}", parent.display()))?;
        let dest = parent_path.join(base);
        let pfd = open_dir_at(libc::AT_FDCWD, &CString::new(parent_path.as_os_str().as_bytes())?)
            .map_err(|e| format!("checkpoint directory {}: {e}", parent_path.display()))?;
        let base = CString::new(base.as_bytes())?;
        if exists_at(pfd.as_raw_fd(), &base) {
            bail!("{} already exists; checkpoints are never overwritten", dest.display());
        }
        clear_stale(&pfd);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
        let outer_name = cname(&format!("{STAGING_PREFIX}{}-{nanos:x}", std::process::id()));
        check(unsafe { libc::mkdirat(pfd.as_raw_fd(), outer_name.as_ptr(), 0o700) })?;
        let outer = open_dir_at(pfd.as_raw_fd(), &outer_name)?;
        // Someone could have swapped in a directory of their own meanwhile.
        let st = fstat(outer.as_raw_fd())?;
        if st.st_uid != unsafe { libc::geteuid() } || st.st_mode & 0o077 != 0 {
            bail!("staging directory in {} was replaced", parent_path.display());
        }
        check(unsafe { libc::mkdirat(outer.as_raw_fd(), c"ck".as_ptr(), 0o700) })?;
        let ck = open_dir_at(outer.as_raw_fd(), c"ck")?;
        let _ = std::fs::remove_file(&vmstate);
        Ok(Staging { dest, parent: pfd, base, outer, outer_name, ck, vmstate, pages: None, published: false })
    }

    pub fn dest(&self) -> &Path {
        &self.dest
    }

    /// Where Firecracker is to write the VM's state.
    pub fn vmstate(&self) -> PathBuf {
        self.vmstate.clone()
    }

    fn create(&self, name: &str) -> io::Result<File> {
        create_at(self.ck.as_raw_fd(), name)
    }

    /// Allocates disk space for about `pages` pages, ahead of the pause.
    pub fn preallocate(&mut self, pages: usize) -> Result<()> {
        let file = PagesFile::new(self.create("pages")?);
        file.reserve(pages);
        self.pages = Some(file);
        Ok(())
    }

    /// Writes the pages and metadata of `vm`, whose state is already in
    /// `vmstate` and whose pages are in the states `runs` (as exported by the
    /// pager's checkpoint barrier), then publishes the checkpoint.
    pub fn commit(
        mut self,
        vm: &Vm,
        runs: &Runs,
        t: &mut Phases,
        still_valid: impl FnOnce() -> Result<()>,
    ) -> std::result::Result<Manifest, CommitError> {
        let hotplug = vm.fc(|fc| fc.get("/hotplug/memory")).ok();
        let hotplug_mib = hotplug.and_then(|h| h["plugged_size_mib"].as_u64()).unwrap_or(0);
        let pages = match self.pages.take() {
            Some(p) => p,
            None => PagesFile::new(self.create("pages")?),
        };
        let out = write_pages(&vm.template, vm.pager.as_ref(), runs, &pages, writer_threads())?;
        t.mark("write_pages");
        pages.file.sync_all()?;
        let (map, data_pages, zero_pages) = (&out.map, out.data, out.zero);
        let pagemap = self.create("pagemap")?;
        (&pagemap).write_all(map)?;
        pagemap.sync_all()?;
        let vmstate = std::fs::read(&self.vmstate)?;
        let vmstate_file = self.create("vmstate")?;
        (&vmstate_file).write_all(&vmstate)?;
        vmstate_file.sync_all()?;
        let mut files = BTreeMap::new();
        files.insert("vmstate".into(), FileSum { len: vmstate.len() as u64, hash: sum(&vmstate) });
        files.insert("pagemap".into(), FileSum { len: map.len() as u64, hash: sum(map) });
        files.insert("pages".into(), FileSum { len: data_pages * PAGE_SIZE as u64, hash: sums_sum(&out.sums) });
        let meta = &vm.template.meta;
        let manifest = Manifest {
            format: FORMAT,
            created_unix_ms: unix_ms(),
            name: vm.name.clone(),
            ip: vm.ip,
            template: vm.template.name.clone(),
            template_id: meta.id.clone(),
            vcpus: meta.vcpus,
            mem_mib: meta.mem_mib,
            max_mib: meta.max_mib,
            hotplug_mib,
            guest_pages: vm.pager.total_pages() as u64,
            data_pages,
            zero_pages,
            files,
        };
        let body = serde_json::to_vec_pretty(&manifest)?;
        let mut text = format!("{}\n", sum(&body)).into_bytes();
        text.extend_from_slice(&body);
        let mf = self.create("manifest.json")?;
        (&mf).write_all(&text)?;
        mf.sync_all()?;
        // The checkpoint belongs to whoever owns the directory it was put in
        // (the daemon runs as root), so they can move and delete it.
        let owner = fstat(self.parent.as_raw_fd())?;
        for (fd, mode) in [(pages.file.as_raw_fd(), 0o644), (pagemap.as_raw_fd(), 0o644), (vmstate_file.as_raw_fd(), 0o644), (mf.as_raw_fd(), 0o644), (self.ck.as_raw_fd(), 0o755)] {
            check(unsafe { libc::fchown(fd, owner.st_uid, owner.st_gid) })?;
            check(unsafe { libc::fchmod(fd, mode) })?;
        }
        fsync_fd(self.ck.as_raw_fd())?;
        // Last check before it becomes visible.
        still_valid()?;
        t.mark("fsync");
        let (outer, parent) = (self.outer.as_raw_fd(), self.parent.as_raw_fd());
        let rc = unsafe { libc::renameat2(outer, c"ck".as_ptr(), parent, self.base.as_ptr(), libc::RENAME_NOREPLACE) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            return Err(CommitError::Failed(format!("publish checkpoint at {}: {e}", self.dest.display()).into()));
        }
        self.published = true;
        if let Err(e) = fsync_fd(parent) {
            // Published, but maybe not durably: a crash could still bring it
            // back after the VM has run on. Revoke it, durably, or the VM
            // must not resume.
            let revoked = check(unsafe { libc::unlinkat(self.ck.as_raw_fd(), c"manifest.json".as_ptr(), 0) })
                .and_then(|()| fsync_fd(self.ck.as_raw_fd()));
            let e = format!("making checkpoint {} durable: {e}", self.dest.display());
            return Err(match revoked {
                Ok(()) => CommitError::Failed(format!("{e} (revoked it)").into()),
                Err(r) => CommitError::Uncertain(format!("{e}; revoking it failed too: {r}").into()),
            });
        }
        t.mark("publish");
        Ok(manifest)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.published {
            for f in FILES {
                unsafe { libc::unlinkat(self.ck.as_raw_fd(), cname(f).as_ptr(), 0) };
            }
            unsafe { libc::unlinkat(self.outer.as_raw_fd(), c"ck".as_ptr(), libc::AT_REMOVEDIR) };
        }
        // Empty now; if someone swapped another directory in under its name,
        // removing that only works if it is empty too.
        unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.outer_name.as_ptr(), libc::AT_REMOVEDIR) };
        let _ = std::fs::remove_file(&self.vmstate);
    }
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

fn exists_at(dir: RawFd, name: &CStr) -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) == 0 }
}

/// Removes staging directories of daemons that are gone: only directories
/// this user owns and nobody else may enter, as `Staging::new` makes them.
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
        match fstat(outer.as_raw_fd()) {
            Ok(st) if st.st_uid == unsafe { libc::geteuid() } && st.st_mode & 0o077 == 0 => {}
            _ => continue,
        }
        if let Ok(ck) = open_dir_at(outer.as_raw_fd(), c"ck") {
            for f in FILES {
                unsafe { libc::unlinkat(ck.as_raw_fd(), cname(f).as_ptr(), 0) };
            }
        }
        unsafe { libc::unlinkat(outer.as_raw_fd(), c"ck".as_ptr(), libc::AT_REMOVEDIR) };
        unsafe { libc::unlinkat(parent.as_raw_fd(), cname(&name).as_ptr(), libc::AT_REMOVEDIR) };
    }
}

/// Where the writer gets guest pages from.
pub(crate) trait GuestPages: Sync {
    /// The first page past the memory region holding `page`.
    fn region_end(&self, page: usize) -> Option<usize>;
    /// Copies the pages from `page` on (all in one region) into `buf`.
    fn read(&self, page: usize, buf: &mut [u8]) -> Result<()>;
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
    n.unwrap_or(cpus.min(MAX_WRITERS)).max(1)
}

/// What `write_pages` wrote: the page map, DATA and ZERO page counts and
/// the checksums of the pages in the file.
struct Written {
    map: Vec<u8>,
    data: u64,
    zero: u64,
    sums: Vec<u32>,
}

/// Pages not stored (the template's, or zero over a template hole).
const BASE: u8 = 0;

/// How one page is stored, and its checksum if DATA.
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

/// A unit's pages, classified, and where its DATA pages went in the file.
struct Unit {
    first: usize,
    kinds: Vec<u8>,
    sums: Vec<u32>,
    at: u64,
}

/// The page file, written with O_DIRECT where the filesystem allows it.
struct PagesFile {
    file: File,
    /// Pages allocated on disk.
    allocated: AtomicUsize,
}

impl PagesFile {
    /// Takes over `file` (created in the staging directory) and switches it
    /// to O_DIRECT if its filesystem supports that.
    fn new(file: File) -> PagesFile {
        let fd = file.as_raw_fd();
        unsafe { libc::fcntl(fd, libc::F_SETFL, libc::fcntl(fd, libc::F_GETFL) | libc::O_DIRECT) };
        PagesFile { file, allocated: AtomicUsize::new(0) }
    }

    /// Allocates room for `pages` pages, so writes up to there need no
    /// block allocation and (on ext4, with O_DIRECT) run in parallel. Best
    /// effort; the file is trimmed to what was written in the end.
    fn reserve(&self, pages: usize) {
        let have = self.allocated.load(Ordering::Relaxed);
        if pages > have {
            let (off, len) = ((have * PAGE_SIZE) as libc::off_t, ((pages - have) * PAGE_SIZE) as libc::off_t);
            if unsafe { libc::fallocate(self.file.as_raw_fd(), 0, off, len) } == 0 {
                self.allocated.store(pages, Ordering::Relaxed);
            }
        }
    }

    /// Writes the buffers in `iov` (page-aligned, whole pages) at `off`.
    fn write(&self, iov: &mut [libc::iovec], off: u64) -> io::Result<()> {
        match pwritev_all(&self.file, &mut iov.to_vec(), off) {
            // O_DIRECT turned out not to work here after all: write through the cache.
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                let fd = self.file.as_raw_fd();
                check(unsafe { libc::fcntl(fd, libc::F_SETFL, libc::fcntl(fd, libc::F_GETFL) & !libc::O_DIRECT) })?;
                pwritev_all(&self.file, iov, off)
            }
            r => r,
        }
    }
}

fn pwritev_all(file: &File, mut iov: &mut [libc::iovec], mut off: u64) -> io::Result<()> {
    while !iov.is_empty() {
        let cnt = iov.len().min(libc::UIO_MAXIOV as usize) as libc::c_int;
        let n = unsafe { libc::pwritev(file.as_raw_fd(), iov.as_ptr(), cnt, off as libc::off_t) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
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

/// A page-aligned buffer, for O_DIRECT.
struct Buf(*mut u8, usize);

impl Buf {
    fn new(len: usize) -> Buf {
        let layout = std::alloc::Layout::from_size_align(len, PAGE_SIZE).unwrap();
        let p = unsafe { std::alloc::alloc(layout) };
        assert!(!p.is_null(), "out of memory");
        Buf(p, len)
    }

    fn get(&mut self, len: usize) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.0, len.min(self.1)) }
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.0, std::alloc::Layout::from_size_align(self.1, PAGE_SIZE).unwrap()) };
    }
}

/// Writes the pages in states `runs` (REMOTE: in the guest, read from
/// `src`; anything else: discarded by the guest) into `out` with `threads`
/// threads, and builds the page map.
fn write_pages(template: &Template, src: &dyn GuestPages, runs: &Runs, out: &PagesFile, threads: usize) -> Result<Written> {
    // Units of REMOTE pages, never across a memory region.
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
    let (next, placed, failed) = (AtomicUsize::new(0), AtomicU64::new(0), AtomicBool::new(false));
    let work = || -> Result<()> {
        let mut buf = Buf::new(UNIT * PAGE_SIZE);
        let mut iov: Vec<libc::iovec> = Vec::with_capacity(UNIT);
        loop {
            let k = next.fetch_add(1, Ordering::Relaxed);
            let Some(&(first, n)) = units.get(k).filter(|_| !failed.load(Ordering::Relaxed)) else { return Ok(()) };
            let bytes = buf.get(n * PAGE_SIZE);
            src.read(first, bytes)?;
            let mut unit = Unit { first, kinds: Vec::with_capacity(n), sums: Vec::new(), at: 0 };
            iov.clear();
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
        let handles: Vec<_> = (0..threads).map(|_| s.spawn(|| work().inspect_err(|_| failed.store(true, Ordering::Relaxed)))).collect();
        handles.into_iter().try_for_each(|h| h.join().unwrap())
    })?;
    // The page map, in page order: discarded runs and units interleave.
    let data = placed.into_inner();
    let mut w = Written { map: Vec::new(), data, zero: 0, sums: vec![0; data as usize] };
    let mut map: Vec<[u64; 4]> = Vec::new();
    let mut push = |page: usize, kind: u64, at: u64| {
        let page = page as u64;
        match map.last_mut() {
            Some([f, n, k, a]) if *k == kind && *f + *n == page && (kind != DATA || *a + *n == at) => *n += 1,
            _ => map.push([page, 1, kind, at]),
        }
    };
    let mut done = done.into_iter().map(|u| u.into_inner().unwrap().unwrap()).peekable();
    for &(first, count, state) in runs {
        if state == REMOTE {
            while let Some(u) = done.next_if(|u| u.first < (first + count) as usize) {
                let mut at = u.at;
                for (i, &kind) in u.kinds.iter().enumerate().filter(|k| *k.1 != BASE) {
                    push(u.first + i, kind as u64, at);
                    if kind == DATA as u8 {
                        at += 1;
                    } else {
                        w.zero += 1;
                    }
                }
                let at = u.at as usize;
                w.sums[at..at + u.sums.len()].copy_from_slice(&u.sums);
            }
            continue;
        }
        // Discarded pages read as zero, which a template hole already is.
        for p in (first..first + count).map(|p| p as usize).filter(|&p| template.has_data(p)) {
            push(p, ZERO, 0);
            w.zero += 1;
        }
    }
    out.file.set_len(data * PAGE_SIZE as u64)?;
    w.map.reserve(24 + map.len() * 32 + w.sums.len() * 4);
    w.map.extend_from_slice(MAGIC);
    w.map.extend_from_slice(&(map.len() as u64).to_le_bytes());
    w.map.extend_from_slice(&data.to_le_bytes());
    for v in map.iter().flatten() {
        w.map.extend_from_slice(&v.to_le_bytes());
    }
    for s in &w.sums {
        w.map.extend_from_slice(&s.to_le_bytes());
    }
    Ok(w)
}

/// A checkpoint opened for restore, with its manifest and metadata verified.
pub struct Checkpoint {
    pub dir: PathBuf,
    pub manifest: Manifest,
    /// The verified VM state. Load these bytes (from a file only root
    /// controls), not the checkpoint's file, which may have changed since.
    pub vmstate: Vec<u8>,
    /// Initial page states for the pager: DATA pages are REMOTE, read from `file`.
    pub runs: Runs,
    pub file: Arc<PageFile>,
}

/// Opens regular file `name` in `dir` (never through a symlink) and reads up
/// to `max` bytes of it.
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

impl Checkpoint {
    /// Opens the checkpoint at `dir` and verifies everything but the page
    /// data itself, which is checked page by page as it is read.
    pub fn open(dir: &Path) -> Result<Checkpoint> {
        let dir = dir.canonicalize().map_err(|e| format!("checkpoint {}: {e}", dir.display()))?;
        let bad = |why: String| format!("checkpoint {} is invalid: {why}", dir.display());
        let dfd = open_dir_at(libc::AT_FDCWD, &CString::new(dir.as_os_str().as_bytes())?).map_err(|e| bad(e.to_string()))?;
        let (_, text) = read_at(dfd.as_raw_fd(), "manifest.json", 1 << 20).map_err(|e| bad(format!("manifest.json: {e}")))?;
        let split = text.iter().position(|&b| b == b'\n').ok_or_else(|| bad("manifest has no checksum".into()))?;
        let (want, body) = (&text[..split], &text[split + 1..]);
        if want != sum(body).as_bytes() {
            bail!("{}", bad("manifest checksum mismatch".into()));
        }
        let manifest: Manifest = serde_json::from_slice(body).map_err(|e| bad(format!("manifest: {e}")))?;
        if manifest.format != FORMAT {
            bail!("{}", bad(format!("format {}; this flexvm reads format {FORMAT}", manifest.format)));
        }
        let read_checked = |name: &str| -> Result<Vec<u8>> {
            let want = manifest.files.get(name).ok_or_else(|| bad(format!("manifest lists no {name}")))?;
            let (_, bytes) = read_at(dfd.as_raw_fd(), name, want.len + 1).map_err(|e| bad(format!("{name}: {e}")))?;
            if bytes.len() as u64 != want.len || sum(&bytes) != want.hash {
                bail!("{}", bad(format!("{name} does not match its checksum")));
            }
            Ok(bytes)
        };
        let vmstate = read_checked("vmstate")?;
        let map = read_checked("pagemap")?;
        let (runs, data_runs, sums) = parse_pagemap(&map, manifest.guest_pages).map_err(|e| bad(e.to_string()))?;
        let data: u64 = data_runs.iter().map(|r| r.1).sum();
        let pages_len = manifest.files.get("pages").map(|f| f.len);
        if data != manifest.data_pages || pages_len != Some(data * PAGE_SIZE as u64) {
            bail!("{}", bad("page counts do not add up".into()));
        }
        if manifest.files["pages"].hash != sums_sum(&sums) {
            bail!("{}", bad("page checksums do not match the manifest".into()));
        }
        let (file, _) = read_at(dfd.as_raw_fd(), "pages", 0).map_err(|e| bad(format!("pages: {e}")))?;
        if file.metadata()?.len() != data * PAGE_SIZE as u64 {
            bail!("{}", bad("pages has the wrong length".into()));
        }
        let file = Arc::new(PageFile { file, runs: data_runs, sums });
        Ok(Checkpoint { dir, manifest, vmstate, runs, file })
    }
}

/// DATA runs as (first guest page, pages, index of the first in the page file).
type DataRuns = Vec<(u64, u64, u64)>;

/// Parses and checks a page map for a guest of `guest_pages` pages. Returns
/// the pager's initial page states, the DATA runs and the page checksums.
fn parse_pagemap(map: &[u8], guest_pages: u64) -> Result<(Runs, DataRuns, Vec<u32>)> {
    let word = |i: usize| -> Result<u64> {
        Ok(u64::from_le_bytes(map.get(i * 8..i * 8 + 8).ok_or("pagemap truncated")?.try_into()?))
    };
    if map.len() < 24 || &map[..8] != MAGIC {
        bail!("bad pagemap header");
    }
    let (nruns, ndata) = (word(1)?, word(2)?);
    if Some(map.len() as u64) != nruns.checked_mul(32).zip(ndata.checked_mul(4)).and_then(|(r, d)| (24 + r).checked_add(d)) {
        bail!("bad pagemap length");
    }
    let nruns = nruns as usize;
    let (mut runs, mut data_runs, mut next) = (Vec::with_capacity(nruns), Vec::new(), 0u64);
    for r in 0..nruns {
        let [first, count, kind, at] = [0, 1, 2, 3].map(|i| word(3 + 4 * r + i));
        let (first, count, kind, at) = (first?, count?, kind?, at?);
        let end = first.checked_add(count).filter(|&e| count > 0 && first >= next && e <= guest_pages);
        let Some(end) = end else { bail!("page run {r} out of order or bounds") };
        next = end;
        match kind {
            DATA => {
                data_runs.push((first, count, at));
                runs.push((first, count, REMOTE));
            }
            ZERO => runs.push((first, count, crate::uffd::ZERO)),
            k => bail!("page run {r} has kind {k}"),
        }
    }
    // The DATA runs must tile the page file exactly.
    let mut tiles: Vec<(u64, u64)> = data_runs.iter().map(|r| (r.2, r.1)).collect();
    tiles.sort_unstable();
    let end = tiles.iter().try_fold(0u64, |pos, &(at, n)| (at == pos).then_some(pos + n));
    if end != Some(ndata) {
        bail!("data runs do not cover the {ndata} stored pages exactly once");
    }
    let sums = map[24 + 32 * nruns..].chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    Ok((runs, data_runs, sums))
}

/// Reads guest pages out of a checkpoint's page file, verifying each one.
pub struct PageFile {
    file: File,
    /// DATA runs: (first guest page, pages, index of the first in the file).
    runs: Vec<(u64, u64, u64)>,
    /// The CRC32C of each data page.
    sums: Vec<u32>,
}

fn corrupt(why: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("checkpoint page file: {why}"))
}

impl PageFile {
    /// Fills `buf` with the guest pages from `page` on, which must all be
    /// DATA. Errors are InvalidData, which the pager treats as fatal.
    /// `drop_cache` evicts what it read from the page cache.
    pub fn read(&self, page: usize, buf: &mut [u8], drop_cache: bool) -> io::Result<()> {
        let n = buf.len() / PAGE_SIZE;
        let mut done = 0;
        while done < n {
            let p = (page + done) as u64;
            let r = self.runs.partition_point(|r| r.0 <= p);
            let (first, count, d) = match r.checked_sub(1).map(|r| self.runs[r]) {
                Some(run) if p < run.0 + run.1 => run,
                _ => return Err(corrupt(format!("page {p} is not stored"))),
            };
            let k = ((first + count - p) as usize).min(n - done);
            self.read_data(d + p - first, &mut buf[done * PAGE_SIZE..(done + k) * PAGE_SIZE], drop_cache)?;
            done += k;
        }
        Ok(())
    }

    /// Reads data pages from index `d` on into `out` and checks them.
    fn read_data(&self, d: u64, out: &mut [u8], drop_cache: bool) -> io::Result<()> {
        let off = d * PAGE_SIZE as u64;
        self.file.read_exact_at(out, off).map_err(|e| corrupt(format!("read at {off}: {e}")))?;
        if drop_cache {
            unsafe { libc::posix_fadvise(self.file.as_raw_fd(), off as i64, out.len() as i64, libc::POSIX_FADV_DONTNEED) };
        }
        for (i, page) in out.chunks(PAGE_SIZE).enumerate() {
            let d = d as usize + i;
            if crc32c::page(page).0 != self.sums[d] {
                return Err(corrupt(format!("data page {d} does not match its checksum")));
            }
        }
        Ok(())
    }

    /// Evicts the whole file from the page cache, once every page is in.
    pub fn drop_cache(&self) {
        unsafe { libc::posix_fadvise(self.file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::Paths;

    /// A template whose memory file has `pages` pages; `Some(b)` is a page
    /// filled with `b`, `None` a hole.
    fn template(dir: &Path, pages: &[Option<u8>]) -> Arc<Template> {
        let tdir = dir.join("tpl");
        std::fs::create_dir_all(&tdir).unwrap();
        let meta = r#"{"vcpus": 1, "mem_mib": 1, "max_mib": 1, "kernel": "/k", "rootfs": "/r"}"#;
        std::fs::write(tdir.join("meta.json"), meta).unwrap();
        let mem = File::create(tdir.join("mem")).unwrap();
        mem.set_len((pages.len() * PAGE_SIZE) as u64).unwrap();
        for (i, p) in pages.iter().enumerate() {
            if let Some(b) = p {
                mem.write_all_at(&[*b; PAGE_SIZE], (i * PAGE_SIZE) as u64).unwrap();
            }
        }
        mem.sync_all().unwrap();
        let paths = Paths { firecracker: "/f".into(), kernel: "/k".into(), rootfs: "/r".into(), templates: dir.into() };
        Template::open(&paths, "tpl").unwrap()
    }

    fn page(seed: usize) -> Vec<u8> {
        (0..PAGE_SIZE).map(|i| (i * 31 + seed * 7 + 1) as u8).collect()
    }

    /// A new page file at `path`, created the way `Staging` creates it.
    fn pages_file(path: &Path) -> PagesFile {
        let dir = open_dir_at(libc::AT_FDCWD, &CString::new(path.parent().unwrap().as_os_str().as_bytes()).unwrap()).unwrap();
        PagesFile::new(create_at(dir.as_raw_fd(), path.file_name().unwrap().to_str().unwrap()).unwrap())
    }

    /// Guest memory for tests: pages in regions of `region` pages; reading
    /// page `fail` fails.
    struct Guest {
        pages: Vec<Vec<u8>>,
        region: usize,
        fail: Option<usize>,
    }

    impl GuestPages for Guest {
        fn region_end(&self, page: usize) -> Option<usize> {
            (page < self.pages.len()).then(|| ((page / self.region + 1) * self.region).min(self.pages.len()))
        }

        fn read(&self, page: usize, buf: &mut [u8]) -> Result<()> {
            for (i, b) in buf.chunks_mut(PAGE_SIZE).enumerate() {
                if Some(page + i) == self.fail {
                    bail!("cannot read page {}", page + i);
                }
                b.copy_from_slice(&self.pages[page + i]);
            }
            Ok(())
        }
    }

    #[test]
    fn pages_roundtrip_against_the_template() {
        let dir = std::env::temp_dir().join(format!("flexvm-ckpt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let n = 1000;
        let tpl_pages: Vec<Option<u8>> = (0..n).map(|i| (i % 2 == 0).then_some(i as u8 | 1)).collect();
        let tpl = template(&dir, &tpl_pages);
        // What the guest holds: the template's page, zeroes, or new data.
        let pages: Vec<Vec<u8>> = (0..n)
            .map(|i| match i % 5 {
                0 => tpl_pages[i].map_or(vec![0; PAGE_SIZE], |b| vec![b; PAGE_SIZE]),
                1 => vec![0; PAGE_SIZE],
                _ => page(i),
            })
            .collect();
        // Pages 7 and 300..320 were discarded by the guest; 900.. were never touched.
        let discarded = |i: usize| i == 7 || (300..320).contains(&i);
        let mut input: Runs = Vec::new();
        for i in 0..900 {
            let s = if discarded(i) { crate::uffd::ZERO } else { REMOTE };
            match input.last_mut() {
                Some((f, c, st)) if *st == s && *f + *c == i as u64 => *c += 1,
                _ => input.push((i as u64, 1, s)),
            }
        }
        let want = |i: usize| if discarded(i) { vec![0; PAGE_SIZE] } else if i < 900 { pages[i].clone() } else { tpl.pages(i, 1).to_vec() };
        let guest = Guest { pages: pages.clone(), region: 333, fail: None };
        let want_data = (0..900).filter(|&i| i % 5 >= 2 && !discarded(i)).count() as u64;
        let want_zero = (0..900).filter(|&i| i % 2 == 0 && (i % 5 == 1 || discarded(i))).count() as u64;
        let mut last = None;
        for threads in [8, 3, 1] {
            let path = dir.join(format!("pages-{threads}"));
            let w = write_pages(&tpl, &guest, &input, &pages_file(&path), threads).unwrap();
            // Zero pages over template holes, and discarded holes, cost nothing.
            assert_eq!((w.data, w.zero), (want_data, want_zero));
            assert_eq!(std::fs::metadata(&path).unwrap().len(), w.data * PAGE_SIZE as u64);
            let (runs, data_runs, sums) = parse_pagemap(&w.map, n as u64).unwrap();
            assert!(parse_pagemap(&w.map, 899).is_err(), "runs past the guest's end");
            assert!(parse_pagemap(&w.map[..w.map.len() - 4], n as u64).is_err());
            // A DATA run pointing anywhere but its own place in the file.
            let mut bad = w.map.clone();
            let r = (0..runs.len()).find(|&r| bad[24 + 32 * r + 16] == DATA as u8).unwrap();
            bad[24 + 32 * r + 24] ^= 1;
            assert!(parse_pagemap(&bad, n as u64).is_err(), "overlapping data runs");
            let file = PageFile { file: File::open(&path).unwrap(), runs: data_runs, sums };
            // Rebuild every page the way the pager would and compare.
            let mut state = vec![crate::uffd::BASE; n];
            for &(f, c, s) in &runs {
                state[f as usize..(f + c) as usize].fill(s);
            }
            for i in 0..n {
                let got = match state[i] {
                    crate::uffd::BASE if tpl.has_data(i) => tpl.pages(i, 1).to_vec(),
                    crate::uffd::BASE | crate::uffd::ZERO => vec![0; PAGE_SIZE],
                    _ => {
                        let mut b = vec![0; PAGE_SIZE];
                        file.read(i, &mut b, false).unwrap();
                        b
                    }
                };
                assert!(got == want(i), "page {i} (state {}, {threads} threads)", state[i]);
            }
            last = Some((runs, state, file, path));
        }
        let (runs, state, file, path) = last.unwrap();
        // Runs of DATA pages read in one go.
        let (f, c, _) = runs.iter().copied().filter(|r| r.2 == REMOTE).max_by_key(|r| r.1).unwrap();
        let mut b = vec![0; c as usize * PAGE_SIZE];
        file.read(f as usize, &mut b, true).unwrap();
        assert_eq!(&b[(c as usize - 1) * PAGE_SIZE..], &want((f + c) as usize - 1)[..]);
        // Pages that are not stored, and corrupt pages, are InvalidData.
        let mut one = vec![0; PAGE_SIZE];
        assert_eq!(file.read(0, &mut one, false).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let f2 = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f2.write_all_at(&[0xff], (5 * PAGE_SIZE + 5) as u64).unwrap();
        let bad: Vec<usize> = (0..n).filter(|&i| state[i] == REMOTE && file.read(i, &mut one, false).is_err()).collect();
        assert_eq!(bad.len(), 1, "exactly the corrupt page fails");
        assert_eq!(file.read(bad[0], &mut one, false).unwrap_err().kind(), io::ErrorKind::InvalidData);
        // A failed read fails the whole write instead of hanging the other writers.
        let guest = Guest { fail: Some(500), ..guest };
        assert!(write_pages(&tpl, &guest, &input, &pages_file(&dir.join("pages-fail")), 4).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_is_private_never_overwrites_and_cleans_up() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("flexvm-stage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("ck");
        // Staging left by a daemon that is gone is cleared, if it is private
        // like ours; anything else with that name is left alone.
        let stale = dir.join(format!("{STAGING_PREFIX}999999999-1"));
        std::fs::create_dir_all(stale.join("ck")).unwrap();
        std::fs::write(stale.join("ck/pages"), b"x").unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o700)).unwrap();
        let foreign = dir.join(format!("{STAGING_PREFIX}999999998-1"));
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = Staging::new(&dest, dir.join("vmstate.private")).unwrap();
        assert!(!stale.exists());
        assert!(foreign.exists());
        let ours: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(&format!("{STAGING_PREFIX}{}", std::process::id())))
            .collect();
        assert_eq!(ours.len(), 1);
        assert_eq!(ours[0].metadata().unwrap().permissions().mode() & 0o777, 0o700);
        // Files are never created over, or through, anything already there.
        let f = s.create("pages").unwrap();
        drop(f);
        assert!(s.create("pages").is_err());
        let ck = s.ck.as_raw_fd();
        symlink("/etc/hostname", dir.join("link")).unwrap();
        let pfd = s.parent.as_raw_fd();
        assert!(create_at(pfd, "link").is_err());
        assert!(open_at(pfd, "link").is_err());
        assert!(create_at(ck, "pagemap").is_ok());
        drop(s);
        assert!(!dest.exists());
        assert!(std::fs::read_dir(&dir).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().contains(&std::process::id().to_string())));
        std::fs::create_dir_all(&dest).unwrap();
        assert!(Staging::new(&dest, dir.join("vmstate.private")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore]
    fn bench_write_pages() {
        let dir = PathBuf::from(std::env::var("FLEXVM_BENCH_DIR").unwrap());
        let mib: usize = std::env::var("FLEXVM_BENCH_MIB").map_or(1024, |v| v.parse().unwrap());
        let n = mib << 8;
        let tdir = dir.join(format!("bench-tpl-{}", std::process::id()));
        let tpl = template(&tdir, &vec![None; n]);
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let pages: Vec<Vec<u8>> = (0..n)
            .map(|_| {
                (0..PAGE_SIZE / 8)
                    .flat_map(|_| {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        x.to_le_bytes()
                    })
                    .collect()
            })
            .collect();
        let guest = Guest { pages, region: n, fail: None };
        let runs: Runs = vec![(0, n as u64, REMOTE)];
        for _ in 0..3 {
            let path = dir.join(format!("bench-pages-{}", std::process::id()));
            let out = pages_file(&path);
            if std::env::var_os("FLEXVM_BENCH_PREALLOC").is_some() {
                out.reserve(n);
            }
            let start = std::time::Instant::now();
            let w = write_pages(&tpl, &guest, &runs, &out, writer_threads()).unwrap();
            let took = start.elapsed();
            let f = File::open(&path).unwrap();
            f.sync_all().unwrap();
            let synced = start.elapsed();
            eprintln!("{mib} MiB, {} threads: write_pages {:.0} ms ({:.2} GB/s), +fsync {:.0} ms", writer_threads(), took.as_secs_f64() * 1e3, (w.data as f64 * PAGE_SIZE as f64) / took.as_secs_f64() / 1e9, (synced - took).as_secs_f64() * 1e3);
            std::fs::remove_file(&path).unwrap();
        }
        let _ = std::fs::remove_dir_all(&tdir);
    }
}
