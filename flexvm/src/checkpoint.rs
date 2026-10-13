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
//! Firecracker (the one copy), checksums each page in the same pass that
//! checks it for zeroes (pages where the template has data are compared
//! with it first), reserves room in `pages` for the unit's DATA pages and
//! writes them there straight from its buffer with O_DIRECT. Units take
//! their place in `pages` as they finish, so no thread waits for another;
//! the page map records where each run went. `pages` is preallocated before
//! the VM pauses so the writes run in parallel.
//!
//! Incremental checkpoints (format 3) add `parent` to the manifest: the
//! parent checkpoint's path (relative to this one's directory if they share
//! a parent directory) and its id (the checksum line of its manifest). Their
//! page map lists only the pages that changed since the parent's pause, with
//! a third kind, TEMPLATE (the template's page, stored as a run only); every
//! page it does not list is as in the parent. A restore follows the chain
//! (at most `MAX_CHAIN` deep), checks every link and flattens the maps, so
//! pages are read from whichever checkpoint holds their latest version.
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
/// Incremental checkpoints: format 2 plus `parent` and TEMPLATE runs.
pub const FORMAT_INCREMENTAL: u64 = 3;
const MAGIC: &[u8; 8] = b"FVPGMAP2";
const DATA: u64 = 1;
const ZERO: u64 = 2;
const TEMPLATE: u64 = 3;
/// Most checkpoints in a chain of incremental checkpoints.
pub const MAX_CHAIN: usize = 64;
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
    /// The checkpoint this one is a delta against (format 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Parent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parent {
    /// Relative to this checkpoint's directory, or absolute.
    pub path: String,
    /// The parent's manifest checksum.
    pub id: String,
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
    ///
    /// Pages come from `src`; with a `parent`, `runs` lists only what changed
    /// since it (BASE runs being explicit), and the checkpoint is a delta.
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
        let pages = match self.pages.take() {
            Some(p) => p,
            None => PagesFile::new(self.create("pages")?),
        };
        let out = write_pages(&vm.template, src, runs, &pages, writer_threads(), parent.is_some())?;
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
            format: if parent.is_some() { FORMAT_INCREMENTAL } else { FORMAT },
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
            parent,
        };
        let body = serde_json::to_vec_pretty(&manifest)?;
        let id = sum(&body);
        let mut text = format!("{id}\n").into_bytes();
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
        Ok((manifest, id))
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
    // The override is for benchmarking; keep it bounded either way.
    n.unwrap_or(cpus).clamp(1, MAX_WRITERS)
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
/// `src`; ZERO: discarded by the guest; BASE: the template's) into `out` with
/// `threads` threads, and builds the page map. With `explicit` (a delta),
/// pages listed that are the template's get TEMPLATE runs instead of no run.
fn write_pages(template: &Template, src: &dyn GuestPages, runs: &Runs, out: &PagesFile, threads: usize, explicit: bool) -> Result<Written> {
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
    let taken: Vec<AtomicBool> = units.iter().map(|_| AtomicBool::new(false)).collect();
    let (next, placed, failed) = (AtomicUsize::new(0), AtomicU64::new(0), AtomicBool::new(false));
    // The next unit to write: one something waits on, else the next in order.
    let pick = || -> Option<usize> {
        while let Some(p) = src.wanted() {
            let k = units.partition_point(|u| u.0 <= p).checked_sub(1);
            if let Some(k) = k.filter(|&k| p < units[k].0 + units[k].1 && !taken[k].swap(true, Ordering::SeqCst)) {
                return Some(k);
            }
        }
        loop {
            let k = next.fetch_add(1, Ordering::Relaxed);
            if k >= units.len() {
                return None;
            }
            if !taken[k].swap(true, Ordering::SeqCst) {
                return Some(k);
            }
        }
    };
    let work = || -> Result<()> {
        let mut buf = Buf::new(UNIT * PAGE_SIZE);
        let mut iov: Vec<libc::iovec> = Vec::with_capacity(UNIT);
        loop {
            if failed.load(Ordering::Relaxed) {
                return Ok(());
            }
            let Some(k) = pick() else { return Ok(()) };
            let (first, n) = units[k];
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
        // A failed spawn must not panic (panic = abort with the VM paused):
        // stop the workers already running and report it.
        let mut handles = Vec::with_capacity(threads);
        let mut spawned: crate::util::Result<()> = Ok(());
        for _ in 0..threads {
            match std::thread::Builder::new().spawn_scoped(s, || work().inspect_err(|_| failed.store(true, Ordering::Relaxed))) {
                Ok(h) => handles.push(h),
                Err(e) => {
                    failed.store(true, Ordering::Relaxed);
                    spawned = Err(e.into());
                    break;
                }
            }
        }
        let joined = handles.into_iter().try_for_each(|h| h.join().unwrap());
        spawned.and(joined)
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
                for (i, &kind) in u.kinds.iter().enumerate() {
                    match kind as u64 {
                        DATA => {
                            push(u.first + i, DATA, at);
                            at += 1;
                        }
                        ZERO => {
                            push(u.first + i, ZERO, 0);
                            w.zero += 1;
                        }
                        _ if explicit => push(u.first + i, TEMPLATE, 0),
                        _ => {}
                    }
                }
                let at = u.at as usize;
                w.sums[at..at + u.sums.len()].copy_from_slice(&u.sums);
            }
            continue;
        }
        // Discarded pages read as zero, which a template hole already is.
        for p in (first..first + count).map(|p| p as usize) {
            if state == crate::uffd::ZERO && template.has_data(p) {
                push(p, ZERO, 0);
                w.zero += 1;
            } else if explicit {
                push(p, TEMPLATE, 0);
            }
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

/// A checkpoint opened for restore, with its manifest and metadata verified
/// (those of every checkpoint in its chain, for an incremental one).
pub struct Checkpoint {
    pub dir: PathBuf,
    pub manifest: Manifest,
    /// The manifest's checksum, which a child names its parent by.
    pub id: String,
    /// The verified VM state. Load these bytes (from a file only root
    /// controls), not the checkpoint's file, which may have changed since.
    pub vmstate: Vec<u8>,
    /// Initial page states for the pager: DATA pages are REMOTE, read from `file`.
    pub runs: Runs,
    pub file: Arc<PageFile>,
    /// The checkpoints it is built on, nearest first.
    pub chain: Vec<PathBuf>,
    /// The ids of `chain`, in the same order.
    pub chain_ids: Vec<String>,
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

/// One checkpoint directory, verified on its own.
struct Link {
    dir: PathBuf,
    manifest: Manifest,
    id: String,
    vmstate: Vec<u8>,
    map: MapRuns,
    file: File,
    sums: Vec<u32>,
}

impl Link {
    fn open(dir: &Path) -> Result<Link> {
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
        match (manifest.format, &manifest.parent) {
            (FORMAT, None) | (FORMAT_INCREMENTAL, Some(_)) => {}
            (f, _) => bail!("{}", bad(format!("format {f}; this flexvm reads formats {FORMAT} and {FORMAT_INCREMENTAL}"))),
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
        let raw = read_checked("pagemap")?;
        let (map, sums) = parse_pagemap(&raw, manifest.guest_pages, manifest.parent.is_some()).map_err(|e| bad(e.to_string()))?;
        let data: u64 = map.iter().filter(|r| r.2 == DATA).map(|r| r.1).sum();
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
        Ok(Link { dir, manifest, id: String::from_utf8_lossy(want).into_owned(), vmstate, map, file, sums })
    }
}

/// The id (manifest checksum) of the checkpoint at `dir`, if it has a
/// manifest whose checksum holds. Cheap: reads only the manifest.
pub fn checkpoint_id(dir: &Path) -> Result<String> {
    let dfd = open_dir_at(libc::AT_FDCWD, &CString::new(dir.as_os_str().as_bytes())?)?;
    let (_, text) = read_at(dfd.as_raw_fd(), "manifest.json", 1 << 20)?;
    let split = text.iter().position(|&b| b == b'\n').ok_or("manifest has no checksum")?;
    if text[..split] != *sum(&text[split + 1..]).as_bytes() {
        bail!("manifest checksum mismatch");
    }
    Ok(String::from_utf8_lossy(&text[..split]).into_owned())
}

/// How `child` (a checkpoint directory) names `parent`: relative to the
/// child when they share a directory, else absolute.
pub fn parent_path(child: &Path, parent: &Path) -> String {
    match (child.parent(), parent.parent(), parent.file_name()) {
        (Some(a), Some(b), Some(name)) if a == b => format!("../{}", name.to_string_lossy()),
        _ => parent.to_string_lossy().into_owned(),
    }
}

impl Checkpoint {
    /// Opens the checkpoint at `dir`, and the chain of checkpoints it is a
    /// delta against, and verifies everything but the page data itself,
    /// which is checked page by page as it is read.
    pub fn open(dir: &Path) -> Result<Checkpoint> {
        let top = Link::open(dir)?;
        let mut links = vec![top];
        while let Some(parent) = links.last().unwrap().manifest.parent.clone() {
            let child = links.last().unwrap();
            if links.len() >= MAX_CHAIN {
                bail!("checkpoint {} is more than {MAX_CHAIN} deltas deep", dir.display());
            }
            let path = child.dir.join(&parent.path);
            let link = Link::open(&path).map_err(|e| format!("parent of {}: {e}", child.dir.display()))?;
            let (c, p) = (&child.manifest, &link.manifest);
            if link.id != parent.id {
                bail!("checkpoint {}: its parent {} has changed (id {} is not {})", child.dir.display(), link.dir.display(), link.id, parent.id);
            }
            if c.template_id != p.template_id || c.guest_pages != p.guest_pages {
                bail!("checkpoint {}: its parent {} is of another template or size", child.dir.display(), link.dir.display());
            }
            links.push(link);
        }
        let layers: Vec<Vec<Run>> = links.iter().enumerate().rev().map(|(i, l)| l.map.iter().map(|&(f, c, k, a)| (f, c, k, i, a)).collect()).collect();
        let mut files = Vec::new();
        let mut sums = Vec::new();
        let mut chain = Vec::new();
        let mut chain_ids = Vec::new();
        let mut top = None;
        for (i, l) in links.into_iter().enumerate() {
            files.push(l.file);
            sums.push(l.sums);
            if i == 0 {
                top = Some((l.dir, l.manifest, l.id, l.vmstate));
            } else {
                chain.push(l.dir);
                chain_ids.push(l.id);
            }
        }
        let (dir, manifest, id, vmstate) = top.unwrap();
        let (runs, file) = flatten(&layers, files, sums);
        Ok(Checkpoint { dir, manifest, id, vmstate, runs, file: Arc::new(file), chain, chain_ids })
    }

    /// Pages the restored VM pulls from the checkpoint files.
    pub fn data_pages(&self) -> u64 {
        self.file.runs.iter().map(|r| r.1).sum()
    }

    /// The canonical hash of the memory this checkpoint restores (a test
    /// hook; see `Canon`).
    pub fn content_hash(&self, template: &Template) -> Result<String> {
        let mut canon = Canon::new(template);
        let mut buf = vec![0u8; 256 * PAGE_SIZE];
        for &(first, count, state) in &self.runs {
            let (mut p, end) = (first as usize, (first + count) as usize);
            while p < end {
                if state != REMOTE {
                    canon.page(p, &[]);
                    p += 1;
                    continue;
                }
                let n = (end - p).min(256);
                let b = &mut buf[..n * PAGE_SIZE];
                self.file.read(p, b, false)?;
                for (i, page) in b.chunks(PAGE_SIZE).enumerate() {
                    canon.page(p + i, page);
                }
                p += n;
            }
        }
        Ok(canon.finish())
    }
}

/// A hash of guest memory that does not depend on how it is stored: every
/// page that is neither the template's nor zero over a template hole, with
/// its number, in page order. Memory read out of a paused VM and the memory
/// a checkpoint of it restores hash the same.
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
        if bytes == base {
            return;
        }
        self.hash.word(p as u64);
        self.hash.update(bytes);
        self.pages += 1;
    }

    pub fn finish(self) -> String {
        format!("{}/{}", self.hash.finish(), self.pages)
    }
}

/// One checkpoint's page map runs: (first page, count, kind, index in `pages`).
type MapRuns = Vec<(u64, u64, u64, u64)>;

/// A page map run of one checkpoint in a chain: (first page, count, kind,
/// checkpoint index, index of the first in that checkpoint's `pages`).
type Run = (u64, u64, u64, usize, u64);

/// Lays `top` over `base` (both ascending and disjoint): pages `top` lists
/// come from it, the rest from `base`.
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
            match next {
                Some(r) => {
                    pos = (r.0 + r.1).max(pos);
                    t += 1;
                }
                None => pos = end,
            }
        }
    }
    out.extend_from_slice(top);
    out.sort_unstable_by_key(|r| r.0);
    out
}

/// Flattens the page maps of a chain (`layers`, oldest first; layer `i`
/// names checkpoint `files[i]`... by its own index) into the pager's initial
/// page states and a reader for the DATA pages.
fn flatten(layers: &[Vec<Run>], files: Vec<File>, sums: Vec<Vec<u32>>) -> (Runs, PageFile) {
    let mut runs: Vec<Run> = Vec::new();
    for layer in layers {
        runs = overlay(&runs, layer);
    }
    let mut states: Runs = Vec::new();
    let mut data = Vec::new();
    for (first, count, kind, ck, at) in runs {
        match kind {
            DATA => {
                data.push((first, count, ck, at));
                states.push((first, count, REMOTE));
            }
            ZERO => states.push((first, count, crate::uffd::ZERO)),
            _ => {}
        }
    }
    (states, PageFile { files, runs: data, sums })
}

/// Parses and checks a page map for a guest of `guest_pages` pages (TEMPLATE
/// runs only in a delta). Returns its runs (first, count, kind, index in
/// `pages`) and the page checksums.
fn parse_pagemap(map: &[u8], guest_pages: u64, delta: bool) -> Result<(MapRuns, Vec<u32>)> {
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
    let (mut runs, mut next) = (Vec::with_capacity(nruns), 0u64);
    for r in 0..nruns {
        let [first, count, kind, at] = [0, 1, 2, 3].map(|i| word(3 + 4 * r + i));
        let (first, count, kind, at) = (first?, count?, kind?, at?);
        let end = first.checked_add(count).filter(|&e| count > 0 && first >= next && e <= guest_pages);
        let Some(end) = end else { bail!("page run {r} out of order or bounds") };
        next = end;
        match kind {
            DATA | ZERO => runs.push((first, count, kind, at)),
            TEMPLATE if delta => runs.push((first, count, kind, 0)),
            k => bail!("page run {r} has kind {k}"),
        }
    }
    // The DATA runs must tile the page file exactly.
    let mut tiles: Vec<(u64, u64)> = runs.iter().filter(|r| r.2 == DATA).map(|r| (r.3, r.1)).collect();
    tiles.sort_unstable();
    let end = tiles.iter().try_fold(0u64, |pos, &(at, n)| (at == pos).then_some(pos + n));
    if end != Some(ndata) {
        bail!("data runs do not cover the {ndata} stored pages exactly once");
    }
    let sums = map[24 + 32 * nruns..].chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    Ok((runs, sums))
}

/// Reads guest pages out of the page files of a checkpoint (chain),
/// verifying each one.
pub struct PageFile {
    files: Vec<File>,
    /// DATA runs: (first guest page, pages, file, index of the first in it).
    runs: Vec<(u64, u64, usize, u64)>,
    /// The CRC32C of each data page, per file.
    sums: Vec<Vec<u32>>,
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
            let (first, count, f, d) = match r.checked_sub(1).map(|r| self.runs[r]) {
                Some(run) if p < run.0 + run.1 => run,
                _ => return Err(corrupt(format!("page {p} is not stored"))),
            };
            let k = ((first + count - p) as usize).min(n - done);
            self.read_data(f, d + p - first, &mut buf[done * PAGE_SIZE..(done + k) * PAGE_SIZE], drop_cache)?;
            done += k;
        }
        Ok(())
    }

    /// Reads data pages from index `d` of file `f` on into `out` and checks them.
    fn read_data(&self, f: usize, d: u64, out: &mut [u8], drop_cache: bool) -> io::Result<()> {
        let off = d * PAGE_SIZE as u64;
        let file = &self.files[f];
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
        Ok(())
    }

    /// Evicts the files from the page cache, once every page is in.
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
            let w = write_pages(&tpl, &guest, &input, &pages_file(&path), threads, false).unwrap();
            // Zero pages over template holes, and discarded holes, cost nothing.
            assert_eq!((w.data, w.zero), (want_data, want_zero));
            assert_eq!(std::fs::metadata(&path).unwrap().len(), w.data * PAGE_SIZE as u64);
            let (map, sums) = parse_pagemap(&w.map, n as u64, false).unwrap();
            assert!(parse_pagemap(&w.map, 899, false).is_err(), "runs past the guest's end");
            assert!(parse_pagemap(&w.map[..w.map.len() - 4], n as u64, false).is_err());
            // A DATA run pointing anywhere but its own place in the file.
            let mut bad = w.map.clone();
            let r = (0..map.len()).find(|&r| bad[24 + 32 * r + 16] == DATA as u8).unwrap();
            bad[24 + 32 * r + 24] ^= 1;
            assert!(parse_pagemap(&bad, n as u64, false).is_err(), "overlapping data runs");
            let layer: Vec<Run> = map.iter().map(|&(f, c, k, a)| (f, c, k, 0, a)).collect();
            let (runs, file) = flatten(&[layer], vec![File::open(&path).unwrap()], vec![sums]);
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
        assert!(write_pages(&tpl, &guest, &input, &pages_file(&dir.join("pages-fail")), 4, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// Builds runs of `state` for the pages `ps` (ascending).
    fn runs_of(ps: &[(usize, u8)]) -> Runs {
        let mut out: Runs = Vec::new();
        for &(p, s) in ps {
            match out.last_mut() {
                Some((f, n, st)) if *st == s && *f + *n == p as u64 => *n += 1,
                _ => out.push((p as u64, 1, s)),
            }
        }
        out
    }

    #[test]
    fn deltas_flatten_over_their_parents() {
        let dir = std::env::temp_dir().join(format!("flexvm-delta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let n = 300;
        let tpl_pages: Vec<Option<u8>> = (0..n).map(|i| (i % 3 == 0).then_some(i as u8 | 1)).collect();
        let tpl = template(&dir, &tpl_pages);
        let tpl_page = |i: usize| tpl_pages[i].map_or(vec![0; PAGE_SIZE], |b| vec![b; PAGE_SIZE]);
        // Generation 1: pages 0..200 populated with data, the rest untouched.
        let v1: Vec<Vec<u8>> = (0..n).map(|i| if i < 200 { page(i) } else { tpl_page(i) }).collect();
        let full_runs = runs_of(&(0..200).map(|i| (i, REMOTE)).collect::<Vec<_>>());
        let w1 = write_pages(&tpl, &Guest { pages: v1.clone(), region: 128, fail: None }, &full_runs, &pages_file(&dir.join("p1")), 3, false).unwrap();
        // Generation 2 changes some pages: new data, back to the template's,
        // zero, discarded (ZERO), and a page populated since (BASE before).
        let mut v2 = v1.clone();
        let mut dirty: Vec<(usize, u8)> = Vec::new();
        for i in [5usize, 6, 7, 50, 199] {
            v2[i] = page(i + 1000);
            dirty.push((i, REMOTE));
        }
        for i in [9usize, 10] {
            v2[i] = tpl_page(i);
            dirty.push((i, REMOTE));
        }
        v2[20] = vec![0; PAGE_SIZE];
        dirty.push((20, REMOTE));
        for i in [30usize, 31, 32, 33] {
            v2[i] = vec![0; PAGE_SIZE];
            dirty.push((i, crate::uffd::ZERO));
        }
        v2[250] = tpl_page(250);
        dirty.push((250, crate::uffd::BASE));
        v2[251] = page(251);
        dirty.push((251, REMOTE));
        dirty.sort();
        let delta = runs_of(&dirty);
        let g2 = Guest { pages: v2.clone(), region: 128, fail: None };
        let w2 = write_pages(&tpl, &g2, &delta, &pages_file(&dir.join("p2")), 2, true).unwrap();
        assert_eq!(w2.data, 6, "only the changed data pages are stored");
        let (m1, s1) = parse_pagemap(&w1.map, n as u64, false).unwrap();
        let (m2, s2) = parse_pagemap(&w2.map, n as u64, true).unwrap();
        assert!(parse_pagemap(&w2.map, n as u64, false).is_err(), "TEMPLATE runs only in a delta");
        assert!(m2.iter().any(|r| r.2 == TEMPLATE));
        let layers = vec![
            m1.iter().map(|&(f, c, k, a)| (f, c, k, 1, a)).collect::<Vec<Run>>(),
            m2.iter().map(|&(f, c, k, a)| (f, c, k, 0, a)).collect::<Vec<Run>>(),
        ];
        let files = vec![File::open(dir.join("p2")).unwrap(), File::open(dir.join("p1")).unwrap()];
        let (runs, file) = flatten(&layers, files, vec![s2, s1]);
        let mut state = vec![crate::uffd::BASE; n];
        for &(f, c, s) in &runs {
            state[f as usize..(f + c) as usize].fill(s);
        }
        for i in 0..n {
            let got = match state[i] {
                crate::uffd::BASE => tpl_page(i),
                crate::uffd::ZERO => vec![0; PAGE_SIZE],
                _ => {
                    let mut b = vec![0; PAGE_SIZE];
                    file.read(i, &mut b, false).unwrap();
                    b
                }
            };
            assert!(got == v2[i], "page {i} (state {})", state[i]);
        }
        // The canonical hash of what the chain restores is that of generation 2.
        let mut want = Canon::new(&tpl);
        for (i, p) in v2.iter().enumerate() {
            want.page(i, p);
        }
        let ck = Checkpoint { dir: dir.clone(), manifest: serde_json::from_value(serde_json::json!({
            "format": 2, "created_unix_ms": 0, "name": "x", "ip": "10.0.0.1", "template": "tpl", "template_id": "", "vcpus": 1,
            "mem_mib": 1, "max_mib": 1, "hotplug_mib": 0, "guest_pages": n, "data_pages": 0, "zero_pages": 0, "files": {}})).unwrap(),
            id: String::new(), vmstate: Vec::new(), runs, file: Arc::new(file), chain: Vec::new(), chain_ids: Vec::new() };
        assert_eq!(ck.content_hash(&tpl).unwrap(), want.finish());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overlay_splits_runs() {
        let base: Vec<Run> = vec![(0, 10, DATA, 1, 100), (20, 5, ZERO, 1, 0)];
        let top: Vec<Run> = vec![(2, 2, ZERO, 0, 0), (5, 1, TEMPLATE, 0, 0), (9, 13, DATA, 0, 7)];
        assert_eq!(
            overlay(&base, &top),
            vec![(0, 2, DATA, 1, 100), (2, 2, ZERO, 0, 0), (4, 1, DATA, 1, 104), (5, 1, TEMPLATE, 0, 0), (6, 3, DATA, 1, 106), (9, 13, DATA, 0, 7), (22, 3, ZERO, 1, 0)]
        );
        assert_eq!(parent_path(Path::new("/d/ck2"), Path::new("/d/ck1")), "../ck1");
        assert_eq!(parent_path(Path::new("/e/ck2"), Path::new("/d/ck1")), "/d/ck1");
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
            let w = write_pages(&tpl, &guest, &runs, &out, writer_threads(), false).unwrap();
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
