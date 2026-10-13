//! Durable checkpoints: a VM's complete state on disk, stored as a delta
//! against its template, and the page source that restores one lazily.
//!
//! A checkpoint is a directory (format 1):
//!
//!   manifest.json  line 1: checksum of the rest of the file; then the
//!                  `Manifest` JSON (template id, address, machine, file sums)
//!   vmstate        Firecracker's vCPU and device state (a state-only snapshot)
//!   pagemap        "FVPGMAP1", run count, block count (u64 LE each), then
//!                  runs as (first page, page count, kind) and one checksum
//!                  per block of `BLOCK_PAGES` data pages (u64 LE each)
//!   pages          the DATA pages, back to back in guest page order
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
//! Crash consistency: everything is written into a fresh `.NAME.partial-*`
//! directory next to the destination, fsynced, and then renamed into place
//! (never over an existing one) and the parent fsynced. A checkpoint directory
//! therefore either holds a complete checkpoint or does not exist, and is
//! never modified afterwards. Restores verify the manifest, `vmstate` and
//! `pagemap` up front, and every block of `pages` as it is read.

use std::collections::BTreeMap;
use std::fs::File;
use std::ffi::{CStr, CString};
use std::io::{self, BufWriter, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::bail;
use crate::template::{Hash, Template};
use crate::uffd::{Runs, REMOTE};
use crate::util::{Error, Phases, Result, PAGE_SIZE};
use crate::vm::Vm;

pub const FORMAT: u64 = 1;
/// Data pages per checksummed block (256 KiB).
pub const BLOCK_PAGES: usize = 64;
const MAGIC: &[u8; 8] = b"FVPGMAP1";
const DATA: u64 = 1;
const ZERO: u64 = 2;
/// Pages read out of the guest per copy.
const CHUNK: usize = 256;

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
    pub block_pages: u64,
    pub data_pages: u64,
    pub zero_pages: u64,
    pub files: BTreeMap<String, FileSum>,
}

fn sum(bytes: &[u8]) -> String {
    let mut h = Hash::new();
    h.update(bytes);
    h.finish()
}

/// A block's checksum: its pages hashed one at a time, as `PageWriter` does.
fn block_sum(bytes: &[u8]) -> u64 {
    let mut h = Hash::new();
    bytes.chunks(PAGE_SIZE).for_each(|p| h.update(p));
    h.value()
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
        Ok(Staging { dest, parent: pfd, base, outer, outer_name, ck, vmstate, published: false })
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
        let pages = self.create("pages")?;
        let mut w = PageWriter::new(&vm.template, BufWriter::with_capacity(1 << 20, &pages));
        let mut buf = vec![0u8; CHUNK * PAGE_SIZE];
        for &(first, count, state) in runs {
            let (mut p, end) = (first as usize, (first + count) as usize);
            while p < end {
                if state != REMOTE {
                    w.zero(p);
                    p += 1;
                    continue;
                }
                let region_end = vm.pager.region_end(p).ok_or_else(|| format!("page {p} outside guest memory"))?;
                let n = CHUNK.min(end - p).min(region_end - p);
                let b = &mut buf[..n * PAGE_SIZE];
                vm.pager.read_guest((p * PAGE_SIZE) as u64, b)?;
                for (i, page) in b.chunks(PAGE_SIZE).enumerate() {
                    w.page(p + i, page)?;
                }
                p += n;
            }
        }
        let (map, data_pages, zero_pages, blocks) = w.finish()?;
        t.mark("write_pages");
        pages.sync_all()?;
        let pagemap = self.create("pagemap")?;
        (&pagemap).write_all(&map)?;
        pagemap.sync_all()?;
        let vmstate = std::fs::read(&self.vmstate)?;
        let vmstate_file = self.create("vmstate")?;
        (&vmstate_file).write_all(&vmstate)?;
        vmstate_file.sync_all()?;
        let mut files = BTreeMap::new();
        files.insert("vmstate".into(), FileSum { len: vmstate.len() as u64, hash: sum(&vmstate) });
        files.insert("pagemap".into(), FileSum { len: map.len() as u64, hash: sum(&map) });
        let mut blocks_sum = Hash::new();
        blocks.iter().for_each(|b| blocks_sum.word(*b));
        files.insert("pages".into(), FileSum { len: data_pages * PAGE_SIZE as u64, hash: blocks_sum.finish() });
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
            block_pages: BLOCK_PAGES as u64,
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
        for (fd, mode) in [(pages.as_raw_fd(), 0o644), (pagemap.as_raw_fd(), 0o644), (vmstate_file.as_raw_fd(), 0o644), (mf.as_raw_fd(), 0o644), (self.ck.as_raw_fd(), 0o755)] {
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

/// Classifies pages against the template, appends DATA pages to the page
/// file with a checksum per block, and builds the page map.
struct PageWriter<'a, W: Write> {
    template: &'a Template,
    out: W,
    runs: Vec<(u64, u64, u64)>,
    blocks: Vec<u64>,
    block: Hash,
    in_block: usize,
    data: u64,
    zero: u64,
}

impl<'a, W: Write> PageWriter<'a, W> {
    fn new(template: &'a Template, out: W) -> Self {
        PageWriter { template, out, runs: Vec::new(), blocks: Vec::new(), block: Hash::new(), in_block: 0, data: 0, zero: 0 }
    }

    fn push(&mut self, page: usize, kind: u64) {
        let page = page as u64;
        match self.runs.last_mut() {
            Some((f, n, k)) if *k == kind && *f + *n == page => *n += 1,
            _ => self.runs.push((page, 1, kind)),
        }
    }

    /// A page the guest discarded. It reads as zero, which the template
    /// already provides where it has a hole.
    fn zero(&mut self, page: usize) {
        if self.template.has_data(page) {
            self.zero += 1;
            self.push(page, ZERO);
        }
    }

    fn page(&mut self, page: usize, bytes: &[u8]) -> io::Result<()> {
        let template = self.template.has_data(page);
        if template && bytes == self.template.pages(page, 1) {
            return Ok(());
        }
        if bytes.iter().all(|&b| b == 0) {
            self.zero(page);
            return Ok(());
        }
        self.out.write_all(bytes)?;
        self.block.update(bytes);
        self.in_block += 1;
        if self.in_block == BLOCK_PAGES {
            self.end_block();
        }
        self.data += 1;
        self.push(page, DATA);
        Ok(())
    }

    fn end_block(&mut self) {
        self.blocks.push(std::mem::replace(&mut self.block, Hash::new()).value());
        self.in_block = 0;
    }

    /// Returns the page map, DATA and ZERO page counts and block checksums.
    fn finish(mut self) -> io::Result<(Vec<u8>, u64, u64, Vec<u64>)> {
        if self.in_block > 0 {
            self.end_block();
        }
        self.out.flush()?;
        let mut map = Vec::with_capacity(24 + self.runs.len() * 24 + self.blocks.len() * 8);
        map.extend_from_slice(MAGIC);
        map.extend_from_slice(&(self.runs.len() as u64).to_le_bytes());
        map.extend_from_slice(&(self.blocks.len() as u64).to_le_bytes());
        for &(f, n, k) in &self.runs {
            for v in [f, n, k] {
                map.extend_from_slice(&v.to_le_bytes());
            }
        }
        for b in &self.blocks {
            map.extend_from_slice(&b.to_le_bytes());
        }
        Ok((map, self.data, self.zero, self.blocks))
    }
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
    /// data itself, which is checked block by block as it is read.
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
        if manifest.format != FORMAT || manifest.block_pages != BLOCK_PAGES as u64 {
            bail!("{}", bad(format!("format {} with {}-page blocks; this flexvm reads format {FORMAT}", manifest.format, manifest.block_pages)));
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
        let (runs, data_runs, blocks) = parse_pagemap(&map, manifest.guest_pages).map_err(|e| bad(e.to_string()))?;
        let data: u64 = data_runs.iter().map(|r| r.1).sum();
        let pages_len = manifest.files.get("pages").map(|f| f.len);
        if data != manifest.data_pages || pages_len != Some(data * PAGE_SIZE as u64) {
            bail!("{}", bad("page counts do not add up".into()));
        }
        let mut blocks_sum = Hash::new();
        blocks.iter().for_each(|b| blocks_sum.word(*b));
        if manifest.files["pages"].hash != blocks_sum.finish() {
            bail!("{}", bad("block checksums do not match the manifest".into()));
        }
        let (file, _) = read_at(dfd.as_raw_fd(), "pages", 0).map_err(|e| bad(format!("pages: {e}")))?;
        if file.metadata()?.len() != data * PAGE_SIZE as u64 {
            bail!("{}", bad("pages has the wrong length".into()));
        }
        let file = Arc::new(PageFile { file, runs: data_runs, blocks, data_pages: data });
        Ok(Checkpoint { dir, manifest, vmstate, runs, file })
    }
}

/// DATA runs as (first guest page, pages, index of the first in the page file).
type DataRuns = Vec<(u64, u64, u64)>;

/// Parses and checks a page map for a guest of `guest_pages` pages. Returns
/// the pager's initial page states, the DATA runs and the block checksums.
fn parse_pagemap(map: &[u8], guest_pages: u64) -> Result<(Runs, DataRuns, Vec<u64>)> {
    let word = |i: usize| -> Result<u64> {
        Ok(u64::from_le_bytes(map.get(i * 8..i * 8 + 8).ok_or("pagemap truncated")?.try_into()?))
    };
    if map.len() < 24 || &map[..8] != MAGIC {
        bail!("bad pagemap header");
    }
    let (nruns, nblocks) = (word(1)?, word(2)?);
    if Some(map.len() as u64) != nruns.checked_mul(24).zip(nblocks.checked_mul(8)).and_then(|(r, b)| (24 + r).checked_add(b)) {
        bail!("bad pagemap length");
    }
    let (nruns, nblocks) = (nruns as usize, nblocks as usize);
    let (mut runs, mut data_runs, mut data, mut next) = (Vec::with_capacity(nruns), Vec::new(), 0u64, 0u64);
    for r in 0..nruns {
        let (first, count, kind) = (word(3 + 3 * r)?, word(4 + 3 * r)?, word(5 + 3 * r)?);
        let end = first.checked_add(count).filter(|&e| count > 0 && first >= next && e <= guest_pages);
        let Some(end) = end else { bail!("page run {r} out of order or bounds") };
        next = end;
        match kind {
            DATA => {
                data_runs.push((first, count, data));
                data += count;
                runs.push((first, count, REMOTE));
            }
            ZERO => runs.push((first, count, crate::uffd::ZERO)),
            k => bail!("page run {r} has kind {k}"),
        }
    }
    if nblocks as u64 != data.div_ceil(BLOCK_PAGES as u64) {
        bail!("{nblocks} block checksums for {data} data pages");
    }
    let blocks = (0..nblocks).map(|b| word(3 + 3 * nruns + b)).collect::<Result<_>>()?;
    Ok((runs, data_runs, blocks))
}

/// Reads guest pages out of a checkpoint's page file, verifying each block.
pub struct PageFile {
    file: File,
    /// DATA runs: (first guest page, pages, index of the first in the file).
    runs: Vec<(u64, u64, u64)>,
    blocks: Vec<u64>,
    data_pages: u64,
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

    /// Reads data pages from index `d` on into `out`, through whole blocks.
    fn read_data(&self, d: u64, out: &mut [u8], drop_cache: bool) -> io::Result<()> {
        let bp = BLOCK_PAGES as u64;
        let n = (out.len() / PAGE_SIZE) as u64;
        let (b0, b1) = (d / bp, (d + n - 1) / bp);
        let (start, end) = (b0 * bp, ((b1 + 1) * bp).min(self.data_pages));
        let mut tmp = vec![0u8; ((end - start) as usize) * PAGE_SIZE];
        let off = start * PAGE_SIZE as u64;
        self.file.read_exact_at(&mut tmp, off).map_err(|e| corrupt(format!("read at {off}: {e}")))?;
        if drop_cache {
            unsafe { libc::posix_fadvise(self.file.as_raw_fd(), off as i64, tmp.len() as i64, libc::POSIX_FADV_DONTNEED) };
        }
        for b in b0..=b1 {
            let (s, e) = ((b * bp - start) as usize * PAGE_SIZE, (((b + 1) * bp).min(self.data_pages) - start) as usize * PAGE_SIZE);
            if block_sum(&tmp[s..e]) != self.blocks[b as usize] {
                return Err(corrupt(format!("block {b} does not match its checksum")));
            }
        }
        let s = (d - start) as usize * PAGE_SIZE;
        out.copy_from_slice(&tmp[s..s + out.len()]);
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

    #[test]
    fn pages_roundtrip_against_the_template() {
        let dir = std::env::temp_dir().join(format!("flexvm-ckpt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let n = 400;
        let tpl_pages: Vec<Option<u8>> = (0..n).map(|i| (i % 2 == 0).then_some(i as u8 | 1)).collect();
        let tpl = template(&dir, &tpl_pages);
        // What the guest holds: the template's page, zeroes, or new data.
        let guest: Vec<Vec<u8>> = (0..n)
            .map(|i| match i % 5 {
                0 => tpl_pages[i].map_or(vec![0; PAGE_SIZE], |b| vec![b; PAGE_SIZE]),
                1 => vec![0; PAGE_SIZE],
                _ => page(i),
            })
            .collect();
        let mut out = Vec::new();
        let mut w = PageWriter::new(&tpl, &mut out);
        for (i, g) in guest.iter().enumerate() {
            if i == 7 {
                w.zero(i); // discarded by the guest
            } else {
                w.page(i, g).unwrap();
            }
        }
        let (map, data, zero, blocks) = w.finish().unwrap();
        // Zero pages over template holes, and a discarded hole (7), cost nothing.
        let want_data = (0..n).filter(|&i| i % 5 >= 2 && i != 7).count() as u64;
        let want_zero = (0..n).filter(|&i| i % 5 == 1 && i % 2 == 0).count() as u64;
        assert_eq!((data, zero), (want_data, want_zero));
        assert_eq!(out.len() as u64, data * PAGE_SIZE as u64);
        assert!(blocks.len() > 1);

        let (runs, data_runs, blocks) = parse_pagemap(&map, n as u64).unwrap();
        assert!(parse_pagemap(&map, n as u64 - 1).is_err(), "runs past the guest's end");
        assert!(parse_pagemap(&map[..map.len() - 8], n as u64).is_err());
        std::fs::write(dir.join("pages"), &out).unwrap();
        let file = PageFile { file: File::open(dir.join("pages")).unwrap(), runs: data_runs, blocks, data_pages: data };
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
            let want = if i == 7 { vec![0; PAGE_SIZE] } else { guest[i].clone() };
            assert!(got == want, "page {i} (state {})", state[i]);
        }
        // Runs of DATA pages read in one go, across blocks.
        let (f, c, _) = runs.iter().copied().filter(|r| r.2 == REMOTE).max_by_key(|r| r.1).unwrap();
        let mut b = vec![0; c as usize * PAGE_SIZE];
        file.read(f as usize, &mut b, true).unwrap();
        assert_eq!(&b[..PAGE_SIZE], &guest[f as usize][..]);
        // Pages that are not stored, and corrupt blocks, are InvalidData.
        let mut one = vec![0; PAGE_SIZE];
        assert_eq!(file.read(0, &mut one, false).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let f2 = std::fs::OpenOptions::new().write(true).open(dir.join("pages")).unwrap();
        f2.write_all_at(&[0xff], (BLOCK_PAGES * PAGE_SIZE + 5) as u64).unwrap();
        let bad: Vec<usize> = (0..n).filter(|&i| state[i] == REMOTE && file.read(i, &mut one, false).is_err()).collect();
        assert_eq!(bad.len(), BLOCK_PAGES, "exactly the pages of the corrupt block fail");
        assert_eq!(file.read(bad[0], &mut one, false).unwrap_err().kind(), io::ErrorKind::InvalidData);
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
}
