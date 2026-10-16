//! Templates: a VM cold-booted once and snapshotted once its agent is up. Every VM is a
//! UFFD restore of one, so "boot" costs a snapshot load plus the pages the guest touches.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bail;
use crate::fc::{memory_timeout, Firecracker};
use crate::guest;
use crate::image::{ImageMeta, Reference};
use crate::socket::SocketRoot;
use crate::util::{ms, retry, Result, PAGE_SIZE};

pub const BALLOON_STATS_S: u16 = 1;

pub const BOOT_ARGS: &str = "console=ttyS0 quiet reboot=k panic=1 pci=off \
    i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd \
    rootflags=dax init=/sbin/flexvm-init psi=1 \
    memhp_default_state=online memory_hotplug.online_policy=auto-movable memory_hotplug.auto_movable_ratio=2000";

/// Restores pay per KVM memslot and untouched memory is free, so slots are big.
pub const SLOT_MIB: u64 = 1024;
pub const STEP_MIB: u64 = 128;
/// Kernel memory (page structs of hot-plugged memory, 1/64 of it, and the rest) grows with
/// the plug: blocks online auto-movable (BOOT_ARGS), movable only while there is 1/20 as
/// much kernel memory (#97). This base keeps a guest's first ~20x of it movable.
pub fn base_mib(max_mib: u64) -> u64 {
    (256 + max_mib / 32).div_ceil(STEP_MIB) * STEP_MIB
}

/// Plugged in the snapshot (untouched, it costs nothing), so early allocations never wait
/// on the host; the controller never shrinks a VM below it.
pub const PLUG_MIB: u64 = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub compatibility: crate::compat::Compat,
    pub vcpus: u32,
    pub mem_mib: u64,
    pub max_mib: u64,
    pub plugged_mib: u64,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub id: String,
    components: BTreeMap<String, Component>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageMeta>,
    /// `recipe()` of the build: a pull of the same image skips the build only if it matches.
    #[serde(default)]
    pub recipe: String,
}

pub const FORMAT_VERSION: u64 = 2;

/// What a build does that its inputs do not record: the boot command line, the memory and
/// device layout, flexvm's version. Not part of the content id (generations stay compatible).
pub fn recipe() -> String {
    let mut h = Hash::new();
    h.word(FORMAT_VERSION);
    for w in [SLOT_MIB, STEP_MIB, BALLOON_STATS_S as u64] {
        h.word(w);
    }
    h.update(BOOT_ARGS.as_bytes());
    h.update(env!("CARGO_PKG_VERSION").as_bytes());
    h.finish()
}

/// ctime changes with every write (and with rewrites that restore mtime); a rename or copy
/// changes the inode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Stamp {
    size: u64,
    ctime: i64,
    ctime_nsec: i64,
    inode: u64,
    device: u64,
}

impl Stamp {
    pub(crate) fn of(m: &std::fs::Metadata) -> Self {
        Self { size: m.len(), ctime: m.ctime(), ctime_nsec: m.ctime_nsec(), inode: m.ino(), device: m.dev() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Component {
    pub(crate) hash: String,
    pub(crate) metadata: Stamp,
}

/// An identity check for trusted files, not protection against tampering.
pub(crate) struct Hash(u64);

impl Hash {
    pub(crate) fn new() -> Self {
        Self(0xcbf29ce484222325)
    }

    pub(crate) fn word(&mut self, w: u64) {
        let h = (self.0 ^ w).wrapping_mul(0x9e3779b97f4a7c15);
        self.0 = h ^ (h >> 29);
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.word(bytes.len() as u64);
        let mut words = bytes.chunks_exact(8);
        for w in &mut words {
            self.word(u64::from_le_bytes(w.try_into().unwrap()));
        }
        let mut tail = [0u8; 8];
        tail[..words.remainder().len()].copy_from_slice(words.remainder());
        self.word(u64::from_le_bytes(tail));
    }

    pub(crate) fn finish(self) -> String {
        format!("{:016x}", self.0)
    }
}

fn zero(page: &[u8]) -> bool {
    page.iter().fold(0, |a, &b| a | b) == 0
}

/// Length plus non-zero pages, so sparse and dense copies of the same bytes match.
fn content_hash(file: &File) -> Result<String> {
    let len = file.metadata()?.len();
    let page = PAGE_SIZE as u64;
    let mut hash = Hash::new();
    hash.word(len);
    let mut buf = vec![0u8; 1 << 20];
    let mut next = 0;
    for (start, end) in data_extents(file, len)? {
        let mut off = (start / page * page).max(next);
        next = end.div_ceil(page) * page;
        while off < next {
            let n = (next - off).min(buf.len() as u64) as usize;
            let have = (len - off).min(n as u64) as usize;
            file.read_exact_at(&mut buf[..have], off)?;
            buf[have..n].fill(0);
            for (i, p) in buf[..n].chunks(PAGE_SIZE).enumerate() {
                if !zero(p) {
                    hash.word(off / page + i as u64);
                    hash.update(p);
                }
            }
            off += n as u64;
        }
    }
    Ok(hash.finish())
}

pub(crate) fn hash_file(path: &Path) -> Result<Component> {
    let file = File::open(path).map_err(|e| format!("template component {}: {e}", path.display()))?;
    let metadata = Stamp::of(&file.metadata()?);
    let hash = content_hash(&file)?;
    if Stamp::of(&file.metadata()?) != metadata {
        bail!("template component {} changed while hashing", path.display());
    }
    Ok(Component { hash, metadata })
}

fn content_id(components: &BTreeMap<String, Component>, image: Option<&ImageMeta>) -> String {
    let mut hash = Hash::new();
    hash.word(FORMAT_VERSION);
    for (name, component) in components {
        hash.update(name.as_bytes());
        hash.update(component.hash.as_bytes());
    }
    if let Some(i) = image {
        for part in ["image", &i.digest, &i.config_digest, &i.app_conf] {
            hash.update(part.as_bytes());
        }
        hash.word(i.warm as u64);
    }
    hash.finish()
}

impl Meta {
    fn read(dir: &Path) -> Result<Meta> {
        Self::read_from(dir, dir, false)
    }

    fn read_from(dir: &Path, display: &Path, pinned: bool) -> Result<Meta> {
        serde_json::from_slice(&std::fs::read(dir.join("meta.json"))?).map_err(|e| {
            let error = e.to_string();
            let older = ["tsc_khz", "tsc_control", "msrs"].iter().any(|field| error.starts_with(&format!("missing field `{field}`")));
            let hint = if pinned && older {
                "this checkpoint or suspended VM was made with an older flexvm whose template record lacks required host compatibility fields and cannot be restored"
            } else if pinned {
                "this checkpoint or suspended VM pins this template generation; rebuilding the named template cannot repair it"
            } else {
                "pull it again with `flexvm pull`"
            };
            format!("template {}: {error}; {hint}", display.display()).into()
        })
    }

    fn files(&self, paths: &Paths, dir: &Path) -> [(&'static str, PathBuf); 5] {
        [
            ("vmstate", dir.join("vmstate")),
            ("mem", dir.join("mem")),
            ("rootfs", self.rootfs.clone()),
            ("kernel", self.kernel.clone()),
            ("firecracker", paths.firecracker.clone()),
        ]
    }

    fn identify(&mut self, paths: &Paths, dir: &Path) -> Result<()> {
        for (name, path) in self.files(paths, dir) {
            self.components.insert(name.into(), hash_file(&path)?);
        }
        self.id = content_id(&self.components, self.image.as_ref());
        Ok(())
    }

    /// Except for the build-only kernel, files whose stat matches `cache`, the creation
    /// stamp or one another process wrote back to `dir`'s meta.json since are trusted;
    /// others are rehashed. Returns whether anything was rehashed.
    fn verify(&self, paths: &Paths, dir: &Path, cache: &mut BTreeMap<String, Stamp>) -> Result<bool> {
        let files = self.files(paths, dir);
        let named = self.components.len() == files.len() && files.iter().all(|(name, _)| self.components.contains_key(*name));
        if !named || !valid_id(&self.id) || content_id(&self.components, self.image.as_ref()) != self.id {
            bail!("template at {} has no valid content id; pull it again with `flexvm pull`", dir.display());
        }
        let mut rehashed = false;
        let mut written: Option<Option<Meta>> = None;
        for (name, path) in files {
            // The kernel contributes to the build's identity, but restores use the kernel
            // already in guest memory and never read this file again.
            if name == "kernel" {
                continue;
            }
            let component = &self.components[name];
            let stamp = Stamp::of(&std::fs::metadata(&path).map_err(|e| format!("template component {}: {e}", path.display()))?);
            if cache.get(name).unwrap_or(&component.metadata) == &stamp {
                continue;
            }
            // Another VM process may have rehashed it already: N VMs need not each do it.
            let written = written.get_or_insert_with(|| Meta::read(dir).ok());
            if written.as_ref().and_then(|m| m.components.get(name)).is_some_and(|c| c.hash == component.hash && c.metadata == stamp) {
                cache.insert(name.into(), stamp);
                continue;
            }
            let now = hash_file(&path)?;
            if now.hash != component.hash {
                bail!("template component {} does not match template {}", path.display(), self.id);
            }
            cache.insert(name.into(), now.metadata);
            rehashed = true;
        }
        Ok(rehashed)
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub templates: PathBuf,
}

impl Paths {
    /// `STATE/artifacts` (as scripts/fetch.sh and build-*.sh install it; resolved, so templates
    /// record the files themselves) and `STATE/templates`.
    pub fn new(state: &Path) -> Self {
        let a = state.join("artifacts");
        let a = a.canonicalize().unwrap_or(a);
        Paths { firecracker: a.join("firecracker"), kernel: a.join("vmlinux"), templates: state.join("templates") }
    }
}

fn runs_mib(runs: &[(u64, u64)]) -> u64 {
    (runs.iter().map(|r| r.1).sum::<u64>() * crate::util::PAGE_SIZE as u64) >> 20
}

pub struct Template {
    pub name: String,
    pub dir: PathBuf,
    pub meta: Meta,
    /// `(first_page, count)` runs a fresh VM touches on its way to ready.
    pub working_set: Vec<(u64, u64)>,
    /// Pages Firecracker touches loading the snapshot, the same in every VM: a migration
    /// source sends them with the vmstate so the target need not fault them one by one.
    load_set: Mutex<BTreeSet<u64>>,
    map: *const u8,
    len: usize,
    data: Vec<u64>,
    verified: Mutex<BTreeMap<String, Stamp>>,
    /// The directory as opened, through `_handle`, whatever its path refers to now.
    fixed: PathBuf,
    _handle: File,
    /// Its use lock, held shared while it is open: `rmi` never removes a generation a VM
    /// process (starting, standing by or running) has open.
    _use: crate::host::Flock,
}

unsafe impl Send for Template {}
unsafe impl Sync for Template {}

/// `templates/.gen/<content id>/` never changes (bar cached stamps); `templates/NAME` is a
/// symlink to the current one, swapped atomically by `create`.
pub const GENERATIONS: &str = ".gen";

const MAX_LOAD_SET: usize = 512;
/// Template builds' guest commands, on a possibly loaded host.
const EXEC_TIMEOUT: Duration = Duration::from_secs(120);

/// What `run` (without `--template`) uses, pulled when missing.
pub const DEFAULT_IMAGE: &str = "ubuntu:24.04";

/// Room for the build's lock and staging names around it in one file name (255 bytes).
pub const MAX_NAME: usize = 200;

/// A template name is a file name in the templates directory, never a path: the
/// `Reference::template_name` of an image reference (`name_of`).
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME || name.starts_with('.') || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.+:@".contains(&b)) {
        bail!("bad template name {name:?}: up to {MAX_NAME} letters, digits, '-', '_', '.', '+', ':' or '@', not starting with '.'");
    }
    Ok(())
}

/// The template an image reference names (`ubuntu:24.04`, `docker.io/library/nginx:latest`
/// is `nginx`, `ghcr.io/org/app:v1` is `ghcr.io+org+app:v1`); a template's own name names itself.
pub fn name_of(image: &str) -> Result<String> {
    let name = Reference::from_template_name(image).map_err(|e| format!("{e}: not an image reference or template name"))?.template_name();
    check_name(&name)?;
    Ok(name)
}

/// The image reference a template name stands for (`nginx` is `nginx:latest`), as users write it.
pub fn image_of(name: &str) -> String {
    Reference::from_template_name(name).map_or_else(|_| name.to_string(), |r| r.familiar())
}

/// Content ids are hex (`Hash::finish`), so one is a file name too.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Template {
    pub fn resolve(paths: &Paths, name: &str) -> Result<PathBuf> {
        check_name(name)?;
        let link = paths.templates.join(name);
        match std::fs::read_link(&link) {
            Ok(target) => Ok(paths.templates.join(target)),
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                bail!("template {name:?} is not a symlink; remove {} and pull it again: flexvm pull {}", link.display(), image_of(name))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!("no image {} in {} (pull it: flexvm pull {0})", image_of(name), paths.templates.display())
            }
            Err(e) => bail!("template {name:?}: {e}"),
        }
    }

    pub fn generation(paths: &Paths, id: &str) -> Option<PathBuf> {
        let dir = paths.templates.join(GENERATIONS).join(id);
        (valid_id(id) && dir.is_dir()).then_some(dir)
    }

    pub fn open(paths: &Paths, name: &str) -> Result<Arc<Template>> {
        Template::open_dir(name, Template::resolve(paths, name)?)
    }

    /// Generation `id`, even if the name has moved on since, verified. Both may come from a
    /// peer: neither is used as a path until checked.
    pub fn open_id(paths: &Paths, name: &str, id: &str) -> Result<Arc<Template>> {
        check_name(name)?;
        if !valid_id(id) {
            bail!("bad template id {id:?}");
        }
        let dir = match Template::generation(paths, id) {
            Some(dir) => dir,
            None => Template::resolve(paths, name)?,
        };
        let tpl = Template::open_dir_with_context(name, dir, true)?;
        tpl.check_id(id)?;
        tpl.verify(paths)?;
        Ok(tpl)
    }

    pub fn open_dir(name: &str, dir: PathBuf) -> Result<Arc<Template>> {
        Self::open_dir_with_context(name, dir, false)
    }

    fn open_dir_with_context(name: &str, dir: PathBuf, pinned: bool) -> Result<Arc<Template>> {
        // All reads, the vmstate Firecracker loads included, go through one directory handle.
        let handle = File::open(&dir).map_err(|e| format!("template {name:?}: {e}"))?;
        let st = crate::util::fstat(handle.as_raw_fd())?;
        let _use = crate::host::shared_at(&crate::host::host_locks()?, &crate::host::use_lock(&st))?;
        // Removed (`rmi`) before the lock was ours: what the handle reads is gone.
        if std::fs::metadata(&dir).ok().map(|m| (m.dev(), m.ino())) != Some((st.st_dev, st.st_ino)) {
            bail!("template {name:?} was removed (flexvm rmi) as it was opened");
        }
        let fixed = PathBuf::from(format!("/proc/{}/fd/{}", std::process::id(), handle.as_raw_fd()));
        let meta = Meta::read_from(&fixed, &dir, pinned).map_err(|e| format!("template {name:?}: {e}"))?;
        let file = File::open(fixed.join("mem"))?;
        let len = file.metadata()?.len() as usize;
        let data = memory_bitmap(&file, len, &fixed)?;
        let map = unsafe { libc::mmap(std::ptr::null_mut(), len.max(1), libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0) };
        if map == libc::MAP_FAILED {
            bail!("mmap template memory: {}", std::io::Error::last_os_error());
        }
        let working_set = std::fs::read(fixed.join("wset")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Ok(Arc::new(Template {
            name: name.into(),
            dir,
            meta,
            working_set,
            load_set: Mutex::default(),
            map: map as *const u8,
            len,
            data,
            verified: Mutex::default(),
            fixed,
            _handle: handle,
            _use,
        }))
    }

    pub fn note_load_fault(&self, page: u64) {
        let mut set = self.load_set.lock().unwrap();
        if set.len() < MAX_LOAD_SET {
            set.insert(page);
        }
    }

    /// What a cold start pages in up front (`Pager::prefetch`), MiB.
    pub fn working_set_mib(&self) -> u64 {
        runs_mib(&self.working_set)
    }

    /// `working_set_mib` of what `name` resolves to now, without opening it (its memory).
    pub fn working_set_mib_of(paths: &Paths, name: &str) -> Result<u64> {
        let runs: Vec<(u64, u64)> = serde_json::from_slice(&std::fs::read(Template::resolve(paths, name)?.join("wset"))?)?;
        Ok(runs_mib(&runs))
    }

    pub fn load_set(&self) -> Vec<u64> {
        self.load_set.lock().unwrap().iter().copied().collect()
    }

    /// Rehash files whose stat changed. Never call on the run path.
    pub fn verify(&self, paths: &Paths) -> Result<()> {
        let cache = &mut self.verified.lock().unwrap();
        // Through the handle: `dir` may name another template by now.
        if self.meta.verify(paths, &self.fixed, cache)? {
            // Into what is there now, so stamps other processes wrote back are kept; locked, so
            // none is lost to a concurrent write-back.
            let st = crate::util::fstat(self._handle.as_raw_fd())?;
            let _dir = crate::host::lock_at(crate::host::host_locks()?, &crate::host::keyed("verify", &st, &format!("-{}", self.meta.id)), libc::LOCK_EX)?;
            let mut meta = Meta::read(&self.fixed).ok().filter(|m| m.id == self.meta.id).unwrap_or_else(|| self.meta.clone());
            for (name, stamp) in cache.iter() {
                if let Some(c) = meta.components.get_mut(name).filter(|c| c.hash == self.meta.components[name].hash) {
                    c.metadata = stamp.clone();
                }
            }
            crate::util::write_file(&self.fixed, "meta.json", &serde_json::to_vec_pretty(&meta)?, true).inspect_err(|_| cache.clear())?;
        }
        Ok(())
    }

    pub fn check_id(&self, id: &str) -> Result<()> {
        if self.meta.id != id {
            bail!("template {:?} id mismatch: local {}, source {id}", self.name, self.meta.id);
        }
        Ok(())
    }

    pub fn vmstate(&self) -> PathBuf {
        self.fixed.join("vmstate")
    }

    pub fn has_data(&self, page: usize) -> bool {
        self.data.get(page / 64).is_some_and(|w| w & (1 << (page % 64)) != 0)
    }

    /// The pages must all have data.
    pub fn pages(&self, page: usize, n: usize) -> &[u8] {
        let start = page * PAGE_SIZE;
        assert!(start + n * PAGE_SIZE <= self.len);
        unsafe { std::slice::from_raw_parts(self.map.add(start), n * PAGE_SIZE) }
    }
}

impl Drop for Template {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.map as *mut _, self.len.max(1)) };
    }
}

/// Derived from the immutable memory file. A changed inode/stamp or a damaged cache is a miss,
/// including after copying a generation to another host. Old generations populate it on first open.
#[derive(Serialize, Deserialize)]
struct MemoryExtents {
    stamp: Stamp,
    extents: Vec<(u64, u64)>,
}

fn memory_bitmap(file: &File, len: usize, dir: &Path) -> Result<Vec<u64>> {
    let stamp = Stamp::of(&file.metadata()?);
    let cached = std::fs::read(dir.join("extents.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<MemoryExtents>(&b).ok())
        .filter(|c| c.stamp == stamp && valid_extents(&c.extents, len as u64));
    let extents = match cached {
        Some(c) => c.extents,
        None => {
            let extents = data_extents(file, len as u64)?;
            if Stamp::of(&file.metadata()?) == stamp {
                let cache = MemoryExtents { stamp, extents: extents.clone() };
                let _ = crate::util::write_file(dir, "extents.json", &serde_json::to_vec(&cache)?, false);
            }
            extents
        }
    };
    let pages = len.div_ceil(PAGE_SIZE);
    let mut bits = vec![0u64; pages.div_ceil(64)];
    for (data, end) in extents {
        for p in (data as usize / PAGE_SIZE)..(end as usize).div_ceil(PAGE_SIZE).min(pages) {
            bits[p / 64] |= 1 << (p % 64);
        }
    }
    Ok(bits)
}

fn valid_extents(extents: &[(u64, u64)], len: u64) -> bool {
    let mut previous = 0;
    extents.iter().all(|&(start, end)| {
        let valid = previous <= start && start < end && end <= len;
        previous = end;
        valid
    })
}

fn data_extents(file: &File, len: u64) -> Result<Vec<(u64, u64)>> {
    let fd = file.as_raw_fd();
    let mut extents = Vec::new();
    let mut off = 0;
    while off < len {
        let data = unsafe { libc::lseek(fd, off as i64, libc::SEEK_DATA) };
        if data < 0 {
            // ENXIO: no data past `off`. Anything else would silently zero real pages.
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(e.into());
        }
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let end = (hole as u64).min(len);
        if end <= data as u64 {
            bail!("invalid sparse extent");
        }
        extents.push((data as u64, end));
        off = end;
    }
    Ok(extents)
}

/// Punches out zero pages, reading 1 MiB at a time and punching each run of them at once.
fn sparsify(path: &Path) -> Result<u64> {
    let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut punched = 0u64;
    let mut punch = |start: u64, end: u64| {
        let mode = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE;
        if unsafe { libc::fallocate(f.as_raw_fd(), mode, start as i64, (end - start) as i64) } == 0 {
            punched += end - start;
        }
    };
    for (data, end) in data_extents(&f, f.metadata()?.len())? {
        let (mut off, mut zeroes) = (data, None);
        while off < end {
            let n = (end - off).min(buf.len() as u64) as usize;
            f.read_exact_at(&mut buf[..n], off)?;
            for (i, p) in buf[..n].chunks(PAGE_SIZE).enumerate() {
                let at = off + (i * PAGE_SIZE) as u64;
                match (zero(p), zeroes) {
                    (true, None) => zeroes = Some(at),
                    (false, Some(start)) => {
                        punch(start, at);
                        zeroes = None;
                    }
                    _ => {}
                }
            }
            off += n as u64;
        }
        if let Some(start) = zeroes {
            punch(start, end);
        }
    }
    Ok(punched)
}

/// Records the pages a restore touches until its agent answers; restores prefetch them.
fn record_working_set(paths: &Paths, dir: &Path, tap: &str, sockets: &Arc<SocketRoot>) -> Result<usize> {
    let tpl = Template::open_dir("(building)", dir.to_path_buf())?;
    let run = tpl.dir.join("record");
    let _ = std::fs::remove_dir_all(&run);
    std::fs::create_dir_all(&run)?;
    let fc = Firecracker::spawn(&paths.firecracker, &run, sockets.allocate()?, crate::fc::SPAWN_READY)?;
    let p = crate::vm::Prepared::new(fc, tpl.clone())?;
    let fc = p.firecracker();
    // Like VM restores: stepping the clock touches pages of its own.
    fc.load_snapshot(&tpl.vmstate(), &tpl.vmstate(), tap, Some(true), crate::fc::API_TIMEOUT)?;
    fc.resume(crate::fc::API_TIMEOUT)?;
    retry(Duration::from_secs(10), Duration::from_millis(10), || guest::ping(&fc.sockets.vsock))?;
    guest::start(&fc.sockets.vsock, "10.255.255.254".parse()?, None)?;
    if tpl.meta.image.as_ref().is_some_and(|i| i.starts_at_run()) {
        guest::start_app(&fc.sockets.vsock)?;
    }
    // An exec records the session path's pages, so the first exec after a restore is fast;
    // an image with no shell can't run one, and an agent round trip stands in.
    if guest::exec(&fc.sockets.vsock, "true", EXEC_TIMEOUT).is_err() {
        guest::ping(&fc.sockets.vsock)?;
    }
    fc.pause(crate::fc::API_TIMEOUT)?;
    let runs = pad_runs(p.pager.present_runs(), crate::uffd::FAULT_AROUND as u64);
    drop(p);
    let _ = std::fs::remove_dir_all(&run);
    std::fs::write(tpl.dir.join("wset"), serde_json::to_vec(&runs)?)?;
    Ok(runs.iter().map(|r| r.1 as usize).sum::<usize>() * PAGE_SIZE)
}

/// A fresh VM touches pages near the recorded ones too; bulk prefetch beats faulting.
fn pad_runs(runs: Vec<(u64, u64)>, align: u64) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (first, count) in runs {
        let (start, end) = (first / align * align, (first + count).div_ceil(align) * align);
        match out.last_mut() {
            Some((f, n)) if start <= *f + *n => *n = end.max(*f + *n) - *f,
            _ => out.push((start, end - start)),
        }
    }
    out
}

fn plug(fc: &Firecracker, mib: u64) -> Result<u64> {
    if mib == 0 {
        return Ok(0);
    }
    fc.patch("/hotplug/memory", json!({"requested_size_mib": mib}))?;
    retry(Duration::from_secs(60), Duration::from_millis(10), || match fc.get("/hotplug/memory")?["plugged_size_mib"].as_u64() {
        Some(p) if p == mib => Ok(()),
        p => bail!("plugged {p:?} of {mib} MiB"),
    })?;
    Ok(mib)
}

/// So freed plug memory is reported in the template, not in every VM after restore (~64 MiB
/// RSS each). Done: 4 s quiet after `expect_mib` reported. Returns (MiB, done).
fn wait_reporting_done(fc: &Firecracker, metrics: &Path, expect_mib: u64) -> Result<(u64, bool)> {
    let (start, mut quiet, mut total, mut seen) = (Instant::now(), 0, 0u64, 0usize);
    // Reporting starts 2 s after memory is freed and works through it in rounds.
    while !(quiet >= 4 && total >> 20 >= expect_mib) && start.elapsed() < Duration::from_secs(120) {
        interrupted()?;
        std::thread::sleep(Duration::from_secs(1));
        fc.put("/actions", json!({"action_type": "FlushMetrics"}))?;
        let text = std::fs::read_to_string(metrics)?;
        let mut freed = 0;
        for line in text[seen..].lines() {
            let m: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
            freed += m["balloon"]["free_page_report_freed"].as_u64().unwrap_or(0);
        }
        seen = text.len();
        total += freed;
        quiet = if freed == 0 { quiet + 1 } else { 0 };
    }
    Ok((total >> 20, quiet >= 4 && total >> 20 >= expect_mib))
}

/// A template build's tap: the host's tap prefix, `x` and the build's pid
/// in hex (a VM process's taps have a `t` after theirs), which garbage
/// collection sweeps once the build is proven gone (by its alias, `host::tap_alias`).
pub fn tap(prefix: &str) -> String {
    format!("{prefix}x{:x}", std::process::id())
}

/// The signal a build was interrupted by, if any (`interrupt`).
static INTERRUPT: AtomicI32 = AtomicI32::new(0);

/// Asks the running build to stop at its next step, cleaning up after itself.
pub fn interrupt(sig: i32) {
    INTERRUPT.store(sig, Ordering::Relaxed);
}

/// Read after the build has unwound and removed its staging and tap.
pub fn interrupted_signal() -> Option<i32> {
    match INTERRUPT.load(Ordering::Relaxed) {
        0 => None,
        sig => Some(sig),
    }
}

/// Also checked by image builds (`image::prepare`), which run under the same signal thread.
pub fn interrupted() -> Result<()> {
    match interrupted_signal() {
        None => Ok(()),
        Some(sig) => bail!("template build interrupted (signal {sig})"),
    }
}

/// Held shared while a build makes its staging directory and while it publishes, exclusive
/// while one sweeps: a staging directory without a lock, or a link, seen under it is dead.
fn templates_lock(paths: &Paths, how: i32) -> Result<crate::host::Flock> {
    Ok(crate::host::Flock::new(template_lock(paths, "templates", "")?, how)?)
}

/// A lock on the templates directory's contents: in the host's lock directory
/// (`host::host_locks`), named by `kind`, the directory's (dev, inode) and `rest`.
/// Callers that change it pass `paths.templates` as a `host::Directory`'s path.
fn template_lock(paths: &Paths, kind: &str, rest: &str) -> std::io::Result<File> {
    crate::host::open_lock(&crate::host::host_locks()?, template_lock_name(paths, kind, rest)?.as_ref())
}

fn template_lock_name(paths: &Paths, kind: &str, rest: &str) -> std::io::Result<String> {
    Ok(crate::host::keyed(kind, &crate::host::Directory::open(&paths.templates)?.stat()?, rest))
}

/// Whether `file` is `.{name}.{kind}-{nonce}`, as `Staging::new` and `publish` name theirs.
fn leftover(file: &str, kind: &str) -> bool {
    file.strip_prefix('.').and_then(|f| f.rsplit_once(&format!(".{kind}-"))).is_some_and(|(name, n)| check_name(name).is_ok() && crate::util::is_nonce(n))
}

/// A build's `.{name}.new-{nonce}`, flocked through its lock (`template-new-DEV-INO-.{name}.new-{nonce}`
/// in the host's lock directory) while the build runs (made first), and removed when dropped. A killed
/// build's is removed by the next build (`sweep`).
struct Staging {
    dir: PathBuf,
    lock: (String, File),
    parent: crate::host::Directory,
}

impl Staging {
    fn new(paths: &Paths, name: &str) -> Result<Staging> {
        crate::util::create_dir_durably(&paths.templates, 0o777)?;
        let parent = crate::host::Directory::open(&paths.templates)?;
        let paths = &Paths { templates: parent.path.clone(), ..paths.clone() };
        sweep(paths)?;
        let _l = templates_lock(paths, libc::LOCK_SH)?;
        let file = format!(".{name}.new-{}", crate::util::random_hex(8)?);
        let lock_name = template_lock_name(paths, "template-new", &format!("-{file}"))?;
        let lock = crate::host::open_lock(&crate::host::host_locks()?, lock_name.as_ref())?;
        crate::host::flock(&lock, libc::LOCK_EX)?;
        let staging = Staging { dir: paths.templates.join(&file), lock: (lock_name, lock), parent };
        std::fs::create_dir(&staging.dir)?;
        Ok(staging)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        // Unlinked while held, then let go of explicitly: see `host::Flock`.
        if let (Ok(locks), Ok(name)) = (crate::host::host_locks(), std::ffi::CString::new(self.lock.0.as_str())) {
            unsafe { libc::unlinkat(locks.as_raw_fd(), name.as_ptr(), 0) };
        }
        let _ = crate::host::flock(&self.lock.1, libc::LOCK_UN);
    }
}

/// Removes staging directories whose builds are gone (their lock free, or no lock) and
/// leftover publish links: builds killed before they could clean up.
fn sweep(paths: &Paths) -> Result<()> {
    let _l = templates_lock(paths, libc::LOCK_EX)?;
    let locks = crate::host::host_locks()?;
    let prefix = template_lock_name(paths, "template-new", "-")?;
    let live = |name: &str| {
        crate::host::existing_lock(&locks, format!("{prefix}{name}").as_ref()).is_ok_and(|f| crate::host::flock(&f, libc::LOCK_EX | libc::LOCK_NB).is_err())
    };
    for entry in std::fs::read_dir(&paths.templates)? {
        let entry = entry?;
        let (name, kind) = (entry.file_name().to_string_lossy().into_owned(), entry.file_type()?);
        if kind.is_symlink() && leftover(&name, "link") {
            let _ = std::fs::remove_file(entry.path());
        } else if kind.is_dir() && leftover(&name, "new") && !live(&name) {
            crate::log!("template: removing {}, left by a build that did not finish", entry.path().display());
            if let Ok(key) = std::fs::canonicalize(entry.path()) {
                crate::socket::remove(&key);
            }
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
    let gens = paths.templates.join(GENERATIONS);
    let entries = match std::fs::read_dir(&gens) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        r => Some(r?),
    };
    for entry in entries.into_iter().flatten() {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let tombstone = name.strip_prefix('.').and_then(|n| n.split_once(".rm-")).is_some_and(|(id, nonce)| valid_id(id) && crate::util::is_nonce(nonce));
        if entry.file_type()?.is_dir() && tombstone {
            finish_remove(paths, &entry.path(), None)?;
        }
    }
    // A lock made under this lock (shared) and its build's directory gone: its build's too.
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", locks.as_raw_fd())).into_iter().flatten().flatten() {
        let lock = entry.file_name().to_string_lossy().into_owned();
        let Some(name) = lock.strip_prefix(&prefix) else { continue };
        if leftover(name, "new") && !live(name) && !paths.templates.join(name).exists() {
            if let Ok(c) = std::ffi::CString::new(lock.as_str()) {
                unsafe { libc::unlinkat(locks.as_raw_fd(), c.as_ptr(), 0) };
            }
        }
    }
    Ok(())
}

/// A template's sizes, fixed in its snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub vcpus: u32,
    /// Boot memory.
    pub mem_mib: u64,
    /// Boot memory plus the hotplug region, which is rounded down to whole slots.
    pub max_mib: u64,
    /// Plugged in the snapshot, rounded down to whole steps and to the hotplug region.
    pub plug_mib: u64,
}

impl Size {
    fn hotplug_mib(&self) -> u64 {
        self.max_mib.saturating_sub(self.mem_mib) / SLOT_MIB * SLOT_MIB
    }

    fn plugged_mib(&self) -> u64 {
        self.plug_mib.min(self.hotplug_mib()) / STEP_MIB * STEP_MIB
    }
}

/// The content id of `name`'s generation if building it again from `rootfs` and `image` would
/// make the same template: the same image, app and root filesystem, sizes, recipe, and kernel
/// and Firecracker (by content), and its files intact. A moved tag, new options or replaced
/// artifacts make a new generation; this only spares an identical rebuild.
pub fn up_to_date(paths: &Paths, name: &str, size: Size, rootfs: &Path, image: &ImageMeta) -> Option<String> {
    let dir = Template::resolve(paths, name).ok()?;
    let meta = Meta::read(&dir).ok()?;
    let same_image = meta.image.as_ref().is_some_and(|i| {
        (&i.digest, &i.config_digest, &i.app_conf, &i.argv, i.warm) == (&image.digest, &image.config_digest, &image.app_conf, &image.argv, image.warm)
            && serde_json::to_value(&i.ready).ok() == serde_json::to_value(&image.ready).ok()
    });
    let sizes = (meta.vcpus, meta.mem_mib, meta.max_mib, meta.plugged_mib) == (size.vcpus, size.mem_mib, size.mem_mib + size.hotplug_mib(), size.plugged_mib());
    if !same_image || !sizes || meta.recipe != recipe() || std::fs::canonicalize(rootfs).ok()? != meta.rootfs {
        return None;
    }
    let kernel = std::fs::canonicalize(&paths.kernel).ok()?;
    if meta.components.get("kernel")?.hash != hash_file(&kernel).ok()?.hash {
        return None;
    }
    // Firecracker, the root filesystem and the snapshot files (rehashed if their stat changed).
    meta.verify(paths, &dir, &mut BTreeMap::new()).ok()?;
    Some(meta.id)
}

/// Builds `name` from an image's root filesystem and publishes it as a new generation.
pub fn create(paths: &Paths, name: &str, size: Size, rootfs: &Path, image: ImageMeta, tap: &str) -> Result<()> {
    // The caller owns `tap` through image preparation and the build.
    // Running VMs map the old files, which must not be rewritten under them.
    let staging = Staging::new(paths, name)?;
    build(paths, &staging.dir, name, size, rootfs, tap, image).map_err(|e| format!("template {name:?}: {e}"))?;
    interrupted()?;
    let paths = &Paths { templates: staging.parent.path.clone(), ..paths.clone() };
    publish(paths, name, &staging.dir, interrupted)
}

/// Nothing is deleted: VMs and checkpoints refer to generations by content id, so old ones
/// stay until an operator removes them.
fn publish(paths: &Paths, name: &str, staged: &Path, check_interrupt: impl FnOnce() -> Result<()>) -> Result<()> {
    // Every name below is in the directories as opened here, whatever their paths name meanwhile.
    let parent = crate::host::Directory::open(&paths.templates)?;
    let paths = &Paths { templates: parent.path.clone(), ..paths.clone() };
    let staged = &paths.templates.join(staged.file_name().ok_or("staging has no name")?);
    let meta = Meta::read(staged)?;
    match std::fs::create_dir(paths.templates.join(GENERATIONS)) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        r => r?,
    }
    crate::util::sync_dir(&paths.templates)?;
    let gens = crate::host::Directory::open(&paths.templates.join(GENERATIONS))?;
    let gen = gens.path.join(&meta.id);
    // Its files and their names are durable before the generation is published.
    for entry in std::fs::read_dir(staged)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            File::open(entry.path())?.sync_all()?;
        }
    }
    let _l = templates_lock(paths, libc::LOCK_SH)?;
    crate::util::sync_dir(staged)?;
    check_interrupt()?;
    match std::fs::rename(staged, &gen) {
        // An identical build published it already.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {}
        r => r?,
    }
    let live = paths.templates.join(name);
    let tmp = paths.templates.join(format!(".{name}.link-{}", crate::util::random_hex(8)?));
    std::os::unix::fs::symlink(Path::new(GENERATIONS).join(&meta.id), &tmp)?;
    crate::util::sync_dir(&gens.path)?;
    std::fs::rename(&tmp, &live)?;
    Ok(crate::util::sync_dir(&paths.templates)?)
}

fn build(paths: &Paths, dir: &Path, name: &str, size: Size, rootfs: &Path, tap: &str, image: ImageMeta) -> Result<()> {
    let Size { vcpus, mem_mib, max_mib, plug_mib } = size;
    let run = dir.join("boot");
    std::fs::create_dir_all(&run)?;

    // The image cache's file itself: the snapshot's page cache needs these bytes.
    let rootfs = std::fs::canonicalize(rootfs).map_err(|e| format!("{}: {e}", rootfs.display()))?;
    // Downloaded on first use if missing (`artifacts`): every later VM restores with the Firecracker built with.
    crate::artifacts::ensure(&[(&paths.kernel, &crate::artifacts::KERNEL), (&paths.firecracker, &crate::artifacts::FIRECRACKER)])?;
    let kernel = std::fs::canonicalize(&paths.kernel).map_err(|e| format!("{}: {e} (fetch it: scripts/fetch.sh)", paths.kernel.display()))?;
    let sockets = SocketRoot::new(&std::fs::canonicalize(dir)?)?;
    let start = Instant::now();
    let fc = Firecracker::spawn(&paths.firecracker, &run, sockets.allocate()?, crate::fc::SPAWN_READY)?;
    let vsock = fc.sockets.vsock.clone();
    let metrics = run.join("metrics.json");
    File::create(&metrics)?;
    fc.put("/metrics", json!({"metrics_path": metrics}))?;
    fc.put("/boot-source", json!({"kernel_image_path": kernel, "boot_args": BOOT_ARGS}))?;
    fc.put("/machine-config", json!({"vcpu_count": vcpus, "mem_size_mib": mem_mib}))?;
    fc.put("/pmem/root", json!({"id": "root", "path_on_host": rootfs, "root_device": true, "read_only": true}))?;
    fc.put("/balloon", json!({"amount_mib": 0, "deflate_on_oom": false, "stats_polling_interval_s": BALLOON_STATS_S, "free_page_reporting": true}))?;
    let hotplug = max_mib.saturating_sub(mem_mib) / SLOT_MIB * SLOT_MIB;
    if hotplug > 0 {
        fc.put("/hotplug/memory", json!({"total_size_mib": hotplug, "slot_size_mib": SLOT_MIB}))?;
    }
    fc.put("/vsock", json!({"guest_cid": 3, "uds_path": vsock}))?;
    fc.put("/network-interfaces/eth0", json!({"iface_id": "eth0", "host_dev_name": tap, "guest_mac": crate::net::mac_string(&crate::net::GUEST_MAC)}))?;
    fc.put("/entropy", json!({}))?;
    fc.put("/actions", json!({"action_type": "InstanceStart"}))?;
    retry(Duration::from_secs(30), Duration::from_millis(10), || guest::ping(&vsock))
        .map_err(|e| format!("the guest did not boot: {e}; {}", fc.post_mortem()))?;
    let booted = start.elapsed();
    interrupted()?;
    let plugged = plug(&fc, plug_mib.min(hotplug) / STEP_MIB * STEP_MIB)?;

    if image.warm {
        crate::image::warm_up(&vsock, &image)?;
    }
    // Images may have no shell.
    guest::quiesce(&vsock)?;
    interrupted()?;
    let (reported, done) = wait_reporting_done(&fc, &metrics, plugged * 3 / 4)?;
    if !done {
        crate::log!(
            "template {name}: free page reporting did not finish ({reported} MiB reported of {plugged} MiB \
             plugged); VMs will report the rest after restore, at some RSS each"
        );
    }
    fc.pause(crate::fc::API_TIMEOUT)?;
    fc.request_within(
        "PUT",
        "/snapshot/create",
        Some(json!({"snapshot_type": "Full", "snapshot_path": dir.join("vmstate"), "mem_file_path": dir.join("mem")})),
        memory_timeout(mem_mib + hotplug),
    )?;
    let compatibility = crate::compat::local(fc.pid())?;
    drop(fc);
    interrupted()?;
    let sparsifying = Instant::now();
    let punched = sparsify(&dir.join("mem"))?;
    let sparsified = sparsifying.elapsed();
    let memory = File::open(dir.join("mem"))?;
    memory_bitmap(&memory, memory.metadata()?.len() as usize, dir)?;
    let _ = std::fs::remove_dir_all(&run);

    let mut meta = Meta {
        compatibility,
        vcpus,
        mem_mib,
        max_mib: mem_mib + hotplug,
        plugged_mib: plugged,
        kernel,
        rootfs,
        id: String::new(),
        components: BTreeMap::new(),
        image: Some(image),
        recipe: recipe(),
    };
    meta.identify(paths, dir)?;
    std::fs::write(dir.join("meta.json"), serde_json::to_vec_pretty(&meta)?)?;
    let _ = std::fs::remove_file(dir.join("wset"));
    interrupted()?;
    let wset = record_working_set(paths, dir, tap, &sockets)?;
    let size = std::fs::metadata(dir.join("mem"))?.len();
    crate::output(format_args!(
        "template {name} (id {}): {vcpus} vCPUs, {mem_mib} MiB base + {hotplug} MiB hotplug ({plugged} MiB plugged, \
         {reported} MiB reported free), booted in {} ms, memory file {} MiB ({} MiB of zeroes punched out in {} ms), working set {} MiB\n",
        meta.id,
        ms(booted),
        size >> 20,
        punched >> 20,
        ms(sparsified),
        wset >> 20
    ))?;
    Ok(())
}

/// The names in the templates directory (links to generations) and the generations they link to.
fn names(templates: &Path) -> Result<Vec<(String, String)>> {
    let entries = match std::fs::read_dir(templates) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        r => r?,
    };
    let mut out = vec![];
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if check_name(&name).is_err() || !entry.file_type()?.is_symlink() {
            continue;
        }
        let target = std::fs::read_link(entry.path())?;
        let id = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        out.push((name, id));
    }
    out.sort();
    Ok(out)
}

fn generations(templates: &Path) -> Result<Vec<String>> {
    let entries = match std::fs::read_dir(templates.join(GENERATIONS)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        r => r?,
    };
    let mut ids = vec![];
    for entry in entries {
        let entry = entry?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if valid_id(&id) && entry.file_type()?.is_dir() {
            ids.push(id);
        }
    }
    ids.sort();
    Ok(ids)
}

fn describe(name: Option<&str>, id: &str, dir: &Path) -> Value {
    let (repository, tag) = match name.map(Reference::from_template_name) {
        Some(Ok(r)) => (r.familiar_repository(), r.reference.clone()),
        Some(Err(_)) => (name.unwrap_or_default().to_string(), String::new()),
        None => ("<none>".into(), "<none>".into()),
    };
    // The snapshot's time: its vmstate is never rewritten (meta.json is, with stamps).
    let created = std::fs::metadata(dir.join("vmstate"))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    let mut v = json!({"name": name, "repository": repository, "tag": tag, "id": id, "created": created});
    match Meta::read(dir) {
        Ok(m) => {
            // What it holds on disk: its memory file's blocks and its image's root filesystem.
            let blocks = std::fs::metadata(dir.join("mem")).map_or(0, |m| m.blocks() * 512);
            let rootfs = std::fs::metadata(&m.rootfs).map_or(0, |m| m.len());
            v["vcpus"] = json!(m.vcpus);
            v["mem_mib"] = json!(m.mem_mib);
            v["max_mib"] = json!(m.max_mib);
            v["plugged_mib"] = json!(m.plugged_mib);
            v["size_mib"] = json!((blocks + rootfs) >> 20);
            if let Some(i) = &m.image {
                v["source"] = json!(i.source);
                v["digest"] = json!(i.digest);
                v["app"] = json!(i.argv);
                v["warm"] = json!(i.warm);
            }
        }
        Err(e) => v["error"] = json!(e.to_string()),
    }
    v
}

/// `flexvm images`: every name, and the generations no name links to (`<none>`, kept for VMs
/// and checkpoints of earlier pulls until `rmi ID`).
pub fn images(paths: &Paths) -> Result<Vec<Value>> {
    let names = names(&paths.templates)?;
    let gens = paths.templates.join(GENERATIONS);
    let mut out: Vec<Value> = names.iter().map(|(name, id)| describe(Some(name), id, &gens.join(id))).collect();
    for id in generations(&paths.templates)? {
        if !names.iter().any(|(_, i)| *i == id) {
            out.push(describe(None, &id, &gens.join(&id)));
        }
    }
    Ok(out)
}

/// The generation `rmi` means by `id`: a whole content id or a prefix of only one.
pub fn generation_by_prefix(paths: &Paths, id: &str) -> Result<String> {
    if id.len() < 4 || !valid_id(id) {
        bail!("no image {id:?}");
    }
    let found: Vec<String> = generations(&paths.templates)?.into_iter().filter(|g| g.starts_with(id)).collect();
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!("no image {id:?}"),
        _ => bail!("{id:?} is the start of {} image ids; give more of it", found.len()),
    }
}

/// `rmi`: removes the name `name` (if given), then the generation `id` (the one the name linked to)
/// unless a name still links to it or a VM here uses it (`in_use`, content ids), and the image
/// root filesystems that no generation left uses. The caller checked that no VM uses the name.
pub fn remove(paths: &Paths, images: &Path, name: Option<&str>, id: &str, in_use: &BTreeSet<String>) -> Result<Value> {
    let parent = crate::host::Directory::open(&paths.templates)?;
    let paths = &Paths { templates: parent.path.clone(), ..paths.clone() };
    // No build publishes meanwhile (they take it shared).
    let _l = templates_lock(paths, libc::LOCK_EX)?;
    if let Some(name) = name {
        check_name(name)?;
        let link = paths.templates.join(name);
        if std::fs::read_link(&link)?.file_name() != Some(id.as_ref()) {
            bail!("image {} was pulled again meanwhile; try again", image_of(name));
        }
        std::fs::remove_file(&link)?;
        crate::util::sync_dir(&paths.templates)?;
    }
    let names = names(&paths.templates)?;
    if let Some((other, _)) = names.iter().find(|(_, i)| i == id) {
        if name.is_none() {
            bail!("image {id} is {}; remove that: flexvm rmi {0}", image_of(other));
        }
        return Ok(json!({"untagged": name, "kept": id, "reason": format!("{} is the same image", image_of(other))}));
    }
    if in_use.contains(id) {
        if name.is_none() {
            bail!("image {id} is used by a VM here");
        }
        return Ok(json!({"untagged": name, "kept": id, "reason": "used by a VM here"}));
    }
    let gens = paths.templates.join(GENERATIONS);
    // Kept while a VM process has it open (one starting has no registry entry yet).
    let st = crate::util::fstat(File::open(gens.join(id))?.as_raw_fd())?;
    let _use = match crate::host::lock_at(crate::host::host_locks()?, &crate::host::use_lock(&st), libc::LOCK_EX | libc::LOCK_NB) {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            if name.is_none() {
                bail!("image {id} is open in a VM process here");
            }
            return Ok(json!({"untagged": name, "kept": id, "reason": "open in a VM process here"}));
        }
        r => r?,
    };
    let tombstone = gens.join(format!(".{id}.rm-{}", crate::util::random_hex(8)?));
    std::fs::rename(gens.join(id), &tombstone)?;
    crate::util::sync_dir(&gens)?;
    let removed_rootfs = finish_remove(paths, &tombstone, Some(images))?;
    Ok(json!({"untagged": name, "deleted": id, "rootfs": removed_rootfs}))
}

/// Under the templates lock. Tombstones are no longer rootfs users. Their metadata stays
/// intact until rootfs cleanup finishes, so a sweep can retry after an interrupted removal.
fn finish_remove(paths: &Paths, tombstone: &Path, images: Option<&Path>) -> Result<Option<PathBuf>> {
    let mut removed = None;
    if let Ok(meta) = Meta::read(tombstone) {
        let rootfs = meta.rootfs;
        let gens = paths.templates.join(GENERATIONS);
        let mut used = false;
        for g in generations(&paths.templates)? {
            used |= Meta::read(&gens.join(g)).map_or(true, |m| m.rootfs == rootfs);
        }
        // Sweep has no caller's cache path; image root filesystems live in CACHE/rootfs.
        if let Some(cache) = images.or_else(|| rootfs.parent().and_then(Path::parent)) {
            if !used && crate::image::remove_rootfs(cache, &rootfs)? {
                removed = Some(rootfs);
            }
        }
    }
    std::fs::remove_dir_all(tombstone)?;
    crate::util::sync_dir(&paths.templates.join(GENERATIONS))?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn working_set_mib_is_read_without_opening_the_template() {
        let root = crate::test_util::TempDir::new("wset-mib");
        std::fs::create_dir_all(root.join("templates/.gen/a")).unwrap();
        std::os::unix::fs::symlink(".gen/a", root.join("templates/t")).unwrap();
        let paths = Paths::new(&root);
        // 1 GiB and 2 MiB of 4 KiB pages; no memory file, which opening it would need.
        std::fs::write(root.join("templates/t/wset"), b"[[0, 262144], [300000, 512]]").unwrap();
        assert_eq!(Template::working_set_mib_of(&paths, "t").unwrap(), 1026);
        assert!(Template::working_set_mib_of(&paths, "none").is_err());
    }

    #[test]
    fn working_set_runs_are_padded_and_merged() {
        assert_eq!(pad_runs(vec![(3, 2), (17, 1), (20, 40), (100, 1)], 16), vec![(0, 64), (96, 16)]);
        assert_eq!(pad_runs(vec![], 16), vec![]);
    }

    #[test]
    fn missing_kernel_names_the_fetch_script_before_spawning() {
        let dir = crate::test_util::TempDir::new("kernel");
        let paths = Paths::new(&dir);
        std::fs::write(dir.join("rootfs"), b"rootfs").unwrap();
        let size = Size { vcpus: 1, mem_mib: 256, max_mib: 256, plug_mib: 256 };
        let error = build(&paths, &dir.join("build"), "test", size, &dir.join("rootfs"), "unused", image("sha256:a", "")).unwrap_err().to_string();
        assert!(error.starts_with(&format!("{}:", paths.kernel.display())), "{error}");
        assert!(error.contains("scripts/fetch.sh"), "{error}");
    }

    #[test]
    fn boot_memory_holds_page_structs_for_the_ceiling() {
        assert_eq!(base_mib(0), 256);
        assert_eq!(base_mib(32000), 1280);
        for max in [4096, 32000, 262144] {
            // Page structs of a fully plugged region take 1/64 of it; leave as much again.
            assert!(base_mib(max) >= 256 + max / 64 * 2, "{max}");
        }
    }

    fn image(digest: &str, conf: &str) -> ImageMeta {
        ImageMeta {
            source: "x".into(),
            digest: digest.into(),
            config_digest: "sha256:c".into(),
            app_conf: conf.into(),
            argv: vec!["/x".into()],
            warm: false,
            ready: None,
            ready_timeout: Duration::ZERO,
        }
    }

    struct Fixture {
        paths: Paths,
        dir: crate::test_util::TempDir,
        meta: Meta,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = crate::test_util::TempDir::new("template");
            let paths = Paths { firecracker: dir.join("firecracker"), kernel: dir.join("kernel"), templates: dir.clone() };
            let mut meta = Meta {
                compatibility: crate::compat::Compat {
                    cpu: String::new(),
                    tsc_khz: 2_000_000,
                    tsc_control: false,
                    msrs: Default::default(),
                    firecracker: String::new(),
                    features: BTreeMap::new(),
                    xsave: BTreeMap::new(),
                },
                vcpus: 2,
                mem_mib: 256,
                max_mib: 1024,
                plugged_mib: 0,
                kernel: paths.kernel.clone(),
                rootfs: dir.join("rootfs"),
                id: String::new(),
                components: BTreeMap::new(),
                image: None,
                recipe: String::new(),
            };
            for (name, path) in meta.files(&paths, &dir) {
                std::fs::write(path, name.as_bytes()).unwrap();
            }
            meta.identify(&paths, &dir).unwrap();
            Self { paths, dir, meta }
        }

        fn replace(&self, name: &str, bytes: &[u8]) {
            let path = self.meta.files(&self.paths, &self.dir).into_iter().find(|(n, _)| *n == name).unwrap().1;
            let tmp = self.dir.join("replacement");
            std::fs::write(&tmp, bytes).unwrap();
            std::fs::rename(tmp, path).unwrap();
        }

        fn verify(&self, meta: &Meta, cache: &mut BTreeMap<String, Stamp>) -> Result<bool> {
            meta.verify(&self.paths, &self.dir, cache)
        }

        fn fresh(&self) -> Result<bool> {
            self.verify(&self.meta, &mut BTreeMap::new())
        }

        /// The template in `dir` itself, as a VM process opens its generation.
        fn open(&self) -> Result<Arc<Template>> {
            Template::open_dir("t", self.dir.clone())
        }

        fn write_meta(&self, meta: &Meta, dir: &Path) {
            std::fs::write(dir.join("meta.json"), serde_json::to_vec(meta).unwrap()).unwrap();
        }
    }

    #[test]
    fn incomplete_metadata_requires_a_rebuild() {
        let f = Fixture::new();
        for field in ["compatibility", "plugged_mib", "id", "components"] {
            let mut meta = serde_json::to_value(&f.meta).unwrap();
            meta.as_object_mut().unwrap().remove(field);
            std::fs::write(f.dir.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
            let error = Meta::read(&f.dir).unwrap_err().to_string();
            assert!(error.contains(field) && error.contains("pull it again with `flexvm pull`"), "{error}");
        }
    }

    #[test]
    fn older_pinned_template_errors_name_real_generation_without_rebuild_hint() {
        let f = Fixture::new();
        let generation = f.paths.templates.join(GENERATIONS).join(&f.meta.id);
        std::fs::create_dir_all(generation.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&f.dir, &generation).unwrap();
        // The named template has been rebuilt, but saved VMs still pin the old id.
        let rebuilt = f.paths.templates.join("rebuilt");
        std::fs::create_dir(&rebuilt).unwrap();
        let mut rebuilt_meta = f.meta.clone();
        rebuilt_meta.id = "0000000000000000".into();
        f.write_meta(&rebuilt_meta, &rebuilt);
        std::os::unix::fs::symlink(&rebuilt, f.paths.templates.join("t")).unwrap();
        for field in ["tsc_khz", "tsc_control", "msrs"] {
            let mut meta = serde_json::to_value(&f.meta).unwrap();
            meta["compatibility"].as_object_mut().unwrap().remove(field);
            std::fs::write(f.dir.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
            let error = Template::open_id(&f.paths, "t", &f.meta.id).err().unwrap().to_string();
            assert!(error.contains(&generation.display().to_string()) && error.contains(field), "{error}");
            assert!(error.contains("checkpoint or suspended VM") && error.contains("older flexvm") && error.contains("cannot be restored"), "{error}");
            assert!(!error.contains("/proc/") && !error.contains("rebuild"), "{error}");
            // Fresh template loads retain the useful rebuild hint and a real path too.
            let error = f.open().err().unwrap().to_string();
            assert!(error.contains(&f.dir.display().to_string()) && error.contains("pull it again"), "{error}");
            assert!(!error.contains("/proc/"), "{error}");
        }
    }

    #[test]
    fn resolve_requires_a_symlink() {
        let f = Fixture::new();
        let entry = f.paths.templates.join("t");
        std::fs::create_dir(&entry).unwrap();
        let error = Template::resolve(&f.paths, "t").unwrap_err().to_string();
        assert!(error.contains("not a symlink") && error.contains("pull it again"), "{error}");
        std::fs::remove_dir(&entry).unwrap();
        std::fs::write(&entry, b"").unwrap();
        assert!(Template::resolve(&f.paths, "t").is_err());
        std::fs::remove_file(&entry).unwrap();
        std::os::unix::fs::symlink(".gen/a", &entry).unwrap();
        assert_eq!(Template::resolve(&f.paths, "t").unwrap(), f.paths.templates.join(".gen/a"));
    }

    fn set_mtime(file: &File, sec: i64, nsec: i64) {
        let times = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }, libc::timespec { tv_sec: sec, tv_nsec: nsec }];
        assert_eq!(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) }, 0);
    }

    #[test]
    fn publication_stays_in_the_locked_directory_when_its_path_is_replaced() {
        let f = Fixture::new();
        let staged = f.paths.templates.join(".t.new-swap");
        std::fs::create_dir(&staged).unwrap();
        f.write_meta(&f.meta, &staged);
        let old = f.paths.templates.with_extension("old");
        publish(&f.paths, "t", &staged, || {
            std::fs::rename(&f.paths.templates, &old)?;
            std::fs::create_dir(&f.paths.templates)?;
            Ok(())
        })
        .unwrap();
        assert!(!f.paths.templates.join("t").exists());
        assert!(old.join("t").is_symlink());
        assert!(old.join(GENERATIONS).join(&f.meta.id).join("meta.json").exists());
        std::fs::remove_dir_all(old).unwrap();
    }

    #[test]
    fn verification_removes_its_lock_after_writing_stamps() {
        let f = Fixture::new();
        f.write_meta(&f.meta, &f.dir);
        let tpl = f.open().unwrap();
        tpl.verify(&f.paths).unwrap();
        let st = crate::util::stat_at(tpl._handle.as_raw_fd(), c"").unwrap();
        let name = crate::host::keyed("verify", &st, &format!("-{}", tpl.meta.id));
        assert!(crate::host::existing_lock(&crate::host::host_locks().unwrap(), name.as_ref()).is_err());
    }

    #[test]
    fn publish_checks_interrupt_after_sync_before_rename() {
        let f = Fixture::new();
        let staged = f.dir.join(".t.new-interrupted");
        std::fs::create_dir(&staged).unwrap();
        let meta = Meta { id: "interrupted".into(), ..f.meta.clone() };
        f.write_meta(&meta, &staged);
        std::fs::write(staged.join("vmstate"), b"state").unwrap();
        let error = publish(&f.paths, "t", &staged, || {
            // This checkpoint follows the file fsyncs and directory fsync.
            assert!(staged.join("vmstate").exists());
            assert!(!f.dir.join(GENERATIONS).join(&meta.id).exists());
            Err("template build interrupted (signal 2)".into())
        })
        .unwrap_err();
        assert!(error.to_string().contains("interrupted"), "{error}");
        assert!(staged.exists());
        assert!(!f.dir.join(GENERATIONS).join(&meta.id).exists());
        assert!(!f.paths.templates.join("t").exists());
    }

    #[test]
    fn image_references_name_templates() {
        let digest = format!("ghcr.io+o+a@sha256:{}", "c".repeat(64));
        for ok in ["ubuntu:24.04", "nginx", "ci", "ghcr.io+o+a:V1", "localhost:5000+x", &digest] {
            check_name(ok).unwrap();
        }
        for bad in ["", "a/b", ".x", "../x", "a b", "[::1]:5000+x", &"a".repeat(MAX_NAME + 1)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
        for (arg, name) in [
            ("ubuntu:24.04", "ubuntu:24.04"),
            ("docker.io/library/nginx:latest", "nginx"),
            ("nginx:latest", "nginx"),
            ("ci", "ci"),
            ("ghcr.io/o/a:v1", "ghcr.io+o+a:v1"),
            ("ghcr.io+o+a:v1", "ghcr.io+o+a:v1"),
        ] {
            assert_eq!(name_of(arg).unwrap(), name, "{arg}");
        }
        assert!(name_of("Upper").is_err());
        assert!(name_of(".typo").unwrap_err().to_string().contains("bad template name"));
        assert!(name_of("[::1]:5000/x").is_err());
        assert_eq!(image_of("nginx"), "nginx:latest");
        assert_eq!(image_of("ghcr.io+o+a:v1"), "ghcr.io/o/a:v1");
        assert_eq!(name_of(DEFAULT_IMAGE).unwrap(), DEFAULT_IMAGE);
    }

    /// Publishes a generation `id` of `name` with the fixture's files and `meta`.
    fn publish_as(f: &Fixture, name: &str, meta: &Meta) {
        let dir = f.dir.join(format!(".{name}.new-{}", meta.id));
        std::fs::create_dir_all(&dir).unwrap();
        for file in ["vmstate", "mem"] {
            std::fs::copy(f.dir.join(file), dir.join(file)).unwrap();
        }
        f.write_meta(meta, &dir);
        publish(&f.paths, name, &dir, || Ok(())).unwrap();
    }

    #[test]
    fn pulling_again_rebuilds_only_what_changed() {
        let f = Fixture::new();
        let rootfs = std::fs::canonicalize(&f.meta.rootfs).unwrap();
        let size = Size { vcpus: 2, mem_mib: 256, max_mib: 256 + 1024 + 100, plug_mib: 4096 };
        let mut meta =
            Meta { rootfs: rootfs.clone(), max_mib: 1280, plugged_mib: 1024, image: Some(image("sha256:a", "arg /x\n")), recipe: recipe(), ..f.meta.clone() };
        meta.identify(&f.paths, &f.dir).unwrap();
        publish_as(&f, "t", &meta);
        let img = image("sha256:a", "arg /x\n");
        assert_eq!(up_to_date(&f.paths, "t", size, &rootfs, &img), Some(meta.id.clone()));
        assert_eq!(up_to_date(&f.paths, "other", size, &rootfs, &img), None);
        // A moved tag (another manifest), another app, other sizes or root filesystem.
        assert_eq!(up_to_date(&f.paths, "t", size, &rootfs, &image("sha256:b", "arg /x\n")), None);
        assert_eq!(up_to_date(&f.paths, "t", size, &rootfs, &image("sha256:a", "arg /y\n")), None);
        assert_eq!(up_to_date(&f.paths, "t", Size { vcpus: 4, ..size }, &rootfs, &img), None);
        assert_eq!(up_to_date(&f.paths, "t", Size { plug_mib: 512, ..size }, &rootfs, &img), None);
        assert_eq!(up_to_date(&f.paths, "t", size, &f.paths.kernel, &img), None);
        // A build by another recipe, or with another kernel or Firecracker.
        let gen = Template::resolve(&f.paths, "t").unwrap();
        f.write_meta(&Meta { recipe: String::new(), ..meta.clone() }, &gen);
        assert_eq!(up_to_date(&f.paths, "t", size, &rootfs, &img), None);
        f.write_meta(&meta, &gen);
        assert!(up_to_date(&f.paths, "t", size, &rootfs, &img).is_some());
        f.replace("kernel", b"another kernel");
        assert_eq!(up_to_date(&f.paths, "t", size, &rootfs, &img), None);
        f.replace("kernel", b"kernel");
        assert!(up_to_date(&f.paths, "t", size, &rootfs, &img).is_some());
        f.replace("firecracker", b"another firecracker");
        assert_eq!(up_to_date(&f.paths, "t", size, &rootfs, &img), None);
    }

    #[test]
    fn rmi_removes_names_and_unused_generations_only() {
        let f = Fixture::new();
        let images_dir = f.dir.join("images");
        let gen = |id: &str| Meta { id: id.into(), image: Some(image("sha256:a", "")), ..f.meta.clone() };
        // t was pulled twice (aaaa1111 is an earlier pull's), u once.
        publish_as(&f, "t", &gen("aaaa1111"));
        publish_as(&f, "t", &gen("bbbb2222"));
        publish_as(&f, "u", &gen("cccc3333"));
        let listed = images(&f.paths).unwrap();
        let rows: Vec<(String, String)> = listed.iter().map(|v| (v["repository"].as_str().unwrap().into(), v["id"].as_str().unwrap().into())).collect();
        assert_eq!(rows, [("t".into(), "bbbb2222".into()), ("u".into(), "cccc3333".into()), ("<none>".into(), "aaaa1111".into())]);
        assert_eq!(listed[0]["tag"], "latest");
        let none = BTreeSet::new();
        // Generations by id: only one no name links to and no VM uses.
        assert_eq!(generation_by_prefix(&f.paths, "aaaa").unwrap(), "aaaa1111");
        assert!(generation_by_prefix(&f.paths, "aaa").is_err());
        assert!(generation_by_prefix(&f.paths, "dddd").is_err());
        assert!(remove(&f.paths, &images_dir, None, "cccc3333", &none).unwrap_err().to_string().contains("flexvm rmi u:latest"));
        let vm = BTreeSet::from(["aaaa1111".to_string()]);
        assert!(remove(&f.paths, &images_dir, None, "aaaa1111", &vm).is_err());
        // A name goes; its generation too, unless a VM here uses it.
        let r = remove(&f.paths, &images_dir, Some("t"), "bbbb2222", &none).unwrap();
        assert_eq!(r["deleted"], "bbbb2222");
        assert!(Template::resolve(&f.paths, "t").is_err() && Template::generation(&f.paths, "bbbb2222").is_none());
        assert!(Template::generation(&f.paths, "aaaa1111").is_some(), "an earlier pull's stays for its VMs");
        let used = BTreeSet::from(["cccc3333".to_string()]);
        assert_eq!(remove(&f.paths, &images_dir, Some("u"), "cccc3333", &used).unwrap()["kept"], "cccc3333");
        assert!(Template::resolve(&f.paths, "u").is_err() && Template::generation(&f.paths, "cccc3333").is_some());
        assert_eq!(remove(&f.paths, &images_dir, None, "aaaa1111", &none).unwrap()["deleted"], "aaaa1111");
        // A name pulled again since it was looked up is left alone.
        publish_as(&f, "v", &gen("dddd4444"));
        assert!(remove(&f.paths, &images_dir, Some("v"), "cccc3333", &none).unwrap_err().to_string().contains("pulled again"));
        assert!(Template::resolve(&f.paths, "v").is_ok());
    }

    #[test]
    fn rmi_and_sweep_finish_interrupted_removals() {
        let f = Fixture::new();
        let cache = f.dir.join("images");
        std::fs::create_dir_all(cache.join("rootfs")).unwrap();
        let rootfs = cache.join("rootfs/a.ext4");
        for ext in ["ext4", "ok", "conf"] {
            std::fs::write(rootfs.with_extension(ext), b"image").unwrap();
        }
        let meta = Meta { id: "aaaa1111".into(), rootfs: rootfs.clone(), ..f.meta.clone() };
        publish_as(&f, "t", &meta);
        let gens = f.paths.templates.join(GENERATIONS);
        let tombstone = gens.join(".aaaa1111.rm-0000000000000001");
        std::fs::remove_file(f.paths.templates.join("t")).unwrap();
        std::fs::rename(gens.join(&meta.id), &tombstone).unwrap();
        // Interrupted immediately after rename: sweep still has metadata for the rootfs.
        sweep(&f.paths).unwrap();
        assert!(!tombstone.exists());
        for ext in ["ext4", "ok", "conf"] {
            assert!(!rootfs.with_extension(ext).exists());
        }
        // Interrupted during tombstone deletion: missing metadata cannot pin another rootfs.
        std::fs::create_dir(&tombstone).unwrap();
        std::fs::write(tombstone.join("mem"), b"remaining").unwrap();
        std::fs::write(&rootfs, b"image").unwrap();
        publish_as(&f, "u", &Meta { id: "bbbb2222".into(), ..meta.clone() });
        assert_eq!(remove(&f.paths, &cache, Some("u"), "bbbb2222", &BTreeSet::new()).unwrap()["rootfs"], json!(rootfs));
        assert!(!rootfs.exists());
        sweep(&f.paths).unwrap();
        assert!(!tombstone.exists());
    }

    #[test]
    fn sweep_keeps_rootfs_used_by_a_live_generation() {
        let f = Fixture::new();
        let cache = f.dir.join("images");
        std::fs::create_dir_all(cache.join("rootfs")).unwrap();
        let rootfs = cache.join("rootfs/a.ext4");
        std::fs::write(&rootfs, b"image").unwrap();
        let meta = Meta { id: "aaaa1111".into(), rootfs: rootfs.clone(), ..f.meta.clone() };
        publish_as(&f, "t", &meta);
        let tombstone = f.paths.templates.join(GENERATIONS).join(".bbbb2222.rm-0000000000000001");
        std::fs::create_dir(&tombstone).unwrap();
        f.write_meta(&meta, &tombstone);
        sweep(&f.paths).unwrap();
        assert!(!tombstone.exists());
        assert!(rootfs.exists());
        assert!(Template::resolve(&f.paths, "t").is_ok());
        assert_eq!(remove(&f.paths, &cache, Some("t"), "aaaa1111", &BTreeSet::new()).unwrap()["rootfs"], json!(rootfs));
        assert!(!rootfs.exists());
    }

    #[test]
    fn rmi_keeps_a_generation_a_vm_process_has_open() {
        let f = Fixture::new();
        let images_dir = f.dir.join("images");
        publish_as(&f, "t", &Meta { id: "aaaa1111".into(), image: Some(image("sha256:a", "")), ..f.meta.clone() });
        // A cold run between opening its template and registering its VM: no VM entry names it.
        let starting = Template::open(&f.paths, "t").unwrap();
        let none = BTreeSet::new();
        let r = remove(&f.paths, &images_dir, Some("t"), "aaaa1111", &none).unwrap();
        assert_eq!((r["kept"].as_str(), r["reason"].as_str()), (Some("aaaa1111"), Some("open in a VM process here")));
        assert!(remove(&f.paths, &images_dir, None, "aaaa1111", &none).unwrap_err().to_string().contains("open in a VM process"));
        assert!(Template::generation(&f.paths, "aaaa1111").is_some());
        assert_eq!(starting.pages(0, 0).len(), 0);
        drop(starting);
        assert_eq!(remove(&f.paths, &images_dir, None, "aaaa1111", &none).unwrap()["deleted"], "aaaa1111");
        assert!(Template::open_dir("t", f.dir.join(GENERATIONS).join("aaaa1111")).is_err());
    }

    #[test]
    fn publish_swaps_generations_and_keeps_them_all() {
        let f = Fixture::new();
        let stage = |id: &str| {
            let dir = f.dir.join(format!(".t.new-{id}"));
            std::fs::create_dir_all(&dir).unwrap();
            f.write_meta(&Meta { id: id.into(), ..f.meta.clone() }, &dir);
            std::fs::write(dir.join("vmstate"), id).unwrap();
            dir
        };
        let current = || std::fs::read_to_string(Template::resolve(&f.paths, "t").unwrap().join("vmstate")).unwrap();
        let gens = || {
            let mut g: Vec<String> = std::fs::read_dir(f.dir.join(GENERATIONS)).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
            g.sort();
            g
        };
        publish(&f.paths, "t", &stage("a"), || Ok(())).unwrap();
        assert_eq!(current(), "a");
        let a = Template::resolve(&f.paths, "t").unwrap();
        publish(&f.paths, "t", &stage("b"), || Ok(())).unwrap();
        assert_eq!(current(), "b");
        // Whoever resolved `a` before the swap still reads a's files.
        assert_eq!(std::fs::read_to_string(a.join("vmstate")).unwrap(), "a");
        assert_eq!(gens(), ["a", "b"]);
        publish(&f.paths, "t", &stage("c"), || Ok(())).unwrap();
        assert_eq!(current(), "c");
        assert_eq!(gens(), ["a", "b", "c"]);
        assert_eq!(Template::generation(&f.paths, "a"), Some(f.dir.join(GENERATIONS).join("a")));
        assert_eq!(Template::generation(&f.paths, "x"), None);
    }

    #[test]
    fn identity_roundtrip_metadata_independence_and_old_templates() {
        let f = Fixture::new();
        let mut meta: Meta = serde_json::from_slice(&serde_json::to_vec(&f.meta).unwrap()).unwrap();
        for component in meta.components.values_mut() {
            component.metadata.inode += 1;
            component.metadata.ctime += 1;
        }
        assert_eq!(content_id(&meta.components, None), f.meta.id);
        f.verify(&meta, &mut BTreeMap::new()).unwrap();
        meta.id = "wrong".into();
        assert!(f.verify(&meta, &mut BTreeMap::new()).is_err());
        // Templates from before content ids must be recreated.
        meta.id.clear();
        meta.components.clear();
        assert!(f.verify(&meta, &mut BTreeMap::new()).is_err());
    }

    #[test]
    fn image_identity_is_part_of_the_id() {
        let f = Fixture::new();
        let ids: Vec<String> = [image("sha256:a", "arg /x\n"), image("sha256:b", "arg /x\n"), image("sha256:a", "arg /y\n")]
            .iter()
            .map(|i| content_id(&f.meta.components, Some(i)))
            .collect();
        assert!(ids[0] != f.meta.id && ids[0] != ids[1] && ids[0] != ids[2]);
        let mut meta = f.meta.clone();
        meta.image = Some(image("sha256:a", "arg /x\n"));
        meta.identify(&f.paths, &f.dir).unwrap();
        f.verify(&meta, &mut BTreeMap::new()).unwrap();
        meta.image.as_mut().unwrap().digest = "sha256:b".into();
        assert!(f.verify(&meta, &mut BTreeMap::new()).is_err());
    }

    #[test]
    fn changed_components_are_rejected() {
        for name in ["vmstate", "mem", "rootfs", "firecracker"] {
            let f = Fixture::new();
            let mut cache = BTreeMap::new();
            f.verify(&f.meta, &mut cache).unwrap();
            // Replacement changes inode even for equal-size content.
            f.replace(name, &vec![b'x'; name.len()]);
            let error = f.verify(&f.meta, &mut cache).unwrap_err().to_string();
            assert!(error.contains("does not match"), "{error}");
        }
    }

    #[test]
    fn replaced_or_missing_kernel_allows_migration_and_checkpoint_admission() {
        let f = Fixture::new();
        f.write_meta(&f.meta, &f.dir);
        let tpl = f.open().unwrap();
        let gens = f.dir.join(GENERATIONS);
        std::fs::create_dir(&gens).unwrap();
        std::os::unix::fs::symlink(&f.dir, gens.join(&f.meta.id)).unwrap();

        f.replace("kernel", b"new kernel");
        let mut rebuilt = f.meta.clone();
        rebuilt.identify(&f.paths, &f.dir).unwrap();
        assert_ne!(rebuilt.id, f.meta.id);
        assert_ne!(rebuilt.components["kernel"].hash, f.meta.components["kernel"].hash);

        for missing in [false, true] {
            if missing {
                std::fs::remove_file(&f.paths.kernel).unwrap();
            }
            // Migration source verification and destination / resume / restore admission.
            tpl.verify(&f.paths).unwrap();
            let admitted = Template::open_id(&f.paths, "t", &f.meta.id).unwrap();
            assert_eq!(admitted.meta.id, f.meta.id);
            assert_eq!(admitted.meta.components["kernel"].hash, f.meta.components["kernel"].hash);
        }
    }

    #[test]
    fn cache_refresh_rehashes_changed_files() {
        let f = Fixture::new();
        let mut cache = BTreeMap::new();
        f.verify(&f.meta, &mut cache).unwrap();
        f.replace("rootfs", b"rootfs");
        assert!(f.verify(&f.meta, &mut cache).unwrap());
        assert!(!f.verify(&f.meta, &mut cache).unwrap());
        f.replace("rootfs", b"broken");
        assert!(f.verify(&f.meta, &mut cache).is_err());
    }

    #[test]
    fn hash_is_logical_content() {
        let f = Fixture::new();
        let file = |name: &str, offset: u64, value: u8, sparse: bool| {
            let file = File::options().read(true).write(true).create_new(true).open(f.dir.join(name)).unwrap();
            if sparse {
                file.set_len(64 << 20).unwrap();
            } else {
                file.write_all_at(&vec![0; 64 << 20], 0).unwrap();
            }
            file.write_all_at(&[value; 100], offset).unwrap();
            file.sync_all().unwrap();
            file
        };
        let a = file("a", 1 << 20, 1, true);
        let hash = content_hash(&a).unwrap();
        assert_eq!(data_extents(&a, 64 << 20).unwrap(), vec![(1 << 20, (1 << 20) + PAGE_SIZE as u64)]);
        assert_eq!(hash, content_hash(&file("dense", 1 << 20, 1, false)).unwrap());
        assert_ne!(hash, content_hash(&file("b", 2 << 20, 1, true)).unwrap());
        assert_ne!(hash, content_hash(&file("c", 1 << 20, 2, true)).unwrap());
        assert_ne!(hash, content_hash(&file("d", (1 << 20) + 1, 1, true)).unwrap());
        a.set_len(128 << 20).unwrap();
        assert_ne!(hash, content_hash(&a).unwrap());
    }

    #[test]
    fn open_does_not_verify() {
        let f = Fixture::new();
        f.write_meta(&f.meta, &f.dir);
        let tpl = f.open().unwrap();
        tpl.check_id(&f.meta.id).unwrap();
        let error = tpl.check_id("wrong").unwrap_err().to_string();
        assert!(error.contains("id mismatch"));
        assert!(error.contains(&f.meta.id));
        f.replace("rootfs", b"changed");
        f.open().unwrap();
        assert!(tpl.verify(&f.paths).is_err());
    }

    #[test]
    fn size_and_mtime_invalidate_cache() {
        let f = Fixture::new();
        let file = File::options().read(true).write(true).open(&f.meta.rootfs).unwrap();
        let original = file.metadata().unwrap();
        file.set_len(original.len() + 1).unwrap();
        assert_ne!(Stamp::of(&file.metadata().unwrap()).size, original.len());
        assert!(f.fresh().is_err());
        file.set_len(original.len()).unwrap();
        set_mtime(&file, original.mtime() + 1, original.mtime_nsec());
        assert!(f.fresh().unwrap());
    }

    #[test]
    fn failed_metadata_rewrites_fail_until_one_succeeds() {
        let f = Fixture::new();
        f.write_meta(&f.meta, &f.dir);
        let tpl = f.open().unwrap();
        f.replace("rootfs", b"rootfs");
        std::fs::remove_file(f.dir.join("meta.json")).unwrap();
        std::fs::create_dir(f.dir.join("meta.json")).unwrap();
        assert!(tpl.verify(&f.paths).is_err() && tpl.verify(&f.paths).is_err());
        std::fs::remove_dir(f.dir.join("meta.json")).unwrap();
        tpl.verify(&f.paths).unwrap();
        f.open().unwrap().verify(&f.paths).unwrap();
    }

    #[test]
    fn same_size_rewrite_with_restored_mtime_is_caught() {
        let f = Fixture::new();
        let mut cache = BTreeMap::new();
        f.verify(&f.meta, &mut cache).unwrap();
        let file = File::options().write(true).open(&f.meta.rootfs).unwrap();
        let before = file.metadata().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        file.write_all_at(b"ROOTFS", 0).unwrap();
        set_mtime(&file, before.mtime(), before.mtime_nsec());
        let error = f.verify(&f.meta, &mut cache).unwrap_err().to_string();
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn hostile_names_and_ids_are_refused_on_migration_in() {
        let f = Fixture::new();
        f.write_meta(&f.meta, &f.dir);
        let id = f.meta.id.clone();
        let err = |name: &str, id: &str| Template::open_id(&f.paths, name, id).err().map(|e| e.to_string()).unwrap_or_default();
        // A self-consistent template outside the templates directory, named by absolute path.
        let outside = f.dir.to_str().unwrap();
        let shallow = f.dir.join("sub");
        std::fs::create_dir(&shallow).unwrap();
        let paths = Paths { templates: shallow.clone(), ..f.paths.clone() };
        for name in [outside, "..", "../", "./..", "a/b", "/tmp/x", ".gen", ""] {
            let e = Template::open_id(&paths, name, &id).err().map(|e| e.to_string()).unwrap_or_default();
            assert!(e.contains("bad template name"), "{name:?}: {e}");
        }
        for bad in ["..", "../x", "a/b", "/tmp", "", "0123456789abcdeg"] {
            assert!(err("t", bad).contains("bad template id"), "{bad:?}: {}", err("t", bad));
        }
        // A generation is found by a hex id, and the name by a plain one.
        std::fs::create_dir(shallow.join(GENERATIONS)).unwrap();
        std::os::unix::fs::symlink(&f.dir, shallow.join(GENERATIONS).join(&id)).unwrap();
        assert_eq!(Template::open_id(&paths, "t", &id).unwrap().meta.id, id);
        std::os::unix::fs::symlink(Path::new(GENERATIONS).join(&id), shallow.join("t")).unwrap();
        assert_eq!(Template::open(&paths, "t").unwrap().meta.id, id);
        assert!(Template::open(&paths, "../t").is_err() && Template::open(&paths, outside).is_err());
    }

    #[test]
    fn wrong_component_keys_are_an_error() {
        let f = Fixture::new();
        for (from, to) in [("kernel", "kernal"), ("mem", "../mem")] {
            let mut meta = f.meta.clone();
            let c = meta.components.remove(from).unwrap();
            meta.components.insert(to.into(), c);
            meta.id = content_id(&meta.components, None);
            let e = f.verify(&meta, &mut BTreeMap::new()).unwrap_err().to_string();
            assert!(e.contains("no valid content id"), "{e}");
        }
        let mut meta = f.meta.clone();
        meta.components.insert("extra".into(), meta.components["mem"].clone());
        meta.id = content_id(&meta.components, None);
        assert!(f.verify(&meta, &mut BTreeMap::new()).is_err());
    }

    #[test]
    fn leftover_staging_is_removed_by_the_next_build() {
        let f = Fixture::new();
        let staging = |name: &str, lock: bool| {
            let dir = f.dir.join(name);
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("mem"), b"gigabytes").unwrap();
            lock.then(|| template_lock(&f.paths, "template-new", &format!("-{name}")).unwrap())
        };
        let exists = |name: &str| f.dir.join(name).exists() || f.dir.join(name).is_symlink();
        // A killed build's: its lock free; one killed before it made its lock; one of a
        // template whose name has `.link-` in it.
        drop(staging(".t.new-0000000000000001", true));
        staging(".u.new-0000000000000003", false);
        drop(staging(".foo.link-bar.new-0000000000000004", true));
        // A running build's, perhaps on another host sharing the directory.
        let running = staging(".t.new-0000000000000002", true).unwrap();
        crate::host::flock(&running, libc::LOCK_EX).unwrap();
        // A killed publish's link.
        std::os::unix::fs::symlink(".gen/x", f.dir.join(".t.link-0000000000000005")).unwrap();
        // Not named as flexvm names its own: left alone.
        let foreign = [".t.new-6", ".t.new-000000000000000g", "..new-0000000000000007", ".t.link-0000000000000008"];
        for name in &foreign[..3] {
            staging(name, true);
        }
        std::fs::create_dir(f.dir.join(foreign[3])).unwrap();
        // Recreate a killed build's socket directory, without a live SocketRoot to clean it up.
        use sha2::{Digest, Sha256};
        use std::os::unix::{ffi::OsStrExt, fs::DirBuilderExt};
        let base = PathBuf::from(format!("/tmp/flexvm-s-{}", unsafe { libc::geteuid() }));
        match std::fs::DirBuilder::new().mode(0o700).create(&base) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => panic!("{e}"),
            _ => {}
        }
        let key = f.dir.join(".t.new-0000000000000001");
        let hash = Sha256::digest(key.as_os_str().as_bytes());
        let sockets = base.join(hash[..8].iter().map(|b| format!("{b:02x}")).collect::<String>());
        std::fs::create_dir(&sockets).unwrap();
        std::fs::write(sockets.join("api.sock"), b"leftover socket").unwrap();
        let mine = Staging::new(&f.paths, "t").unwrap();
        assert!(!sockets.exists());
        for gone in [".t.new-0000000000000001", ".u.new-0000000000000003", ".foo.link-bar.new-0000000000000004", ".t.link-0000000000000005"] {
            assert!(!exists(gone), "{gone}");
        }
        let lock_exists = |name: &str| {
            let lock = template_lock_name(&f.paths, "template-new", &format!("-{name}")).unwrap();
            crate::host::existing_lock(&crate::host::host_locks().unwrap(), lock.as_ref()).is_ok()
        };
        assert!(exists(".t.new-0000000000000002") && lock_exists(&mine.dir.file_name().unwrap().to_string_lossy()));
        assert!(!lock_exists(".t.new-0000000000000001"), "a dead build's lock goes with it");
        assert!(foreign.iter().all(|name| exists(name)));
        // A concurrent build of the same name gets a directory of its own, and each leaves
        // the other's alone.
        let second = Staging::new(&f.paths, "t").unwrap();
        assert!(second.dir != mine.dir && second.dir.exists() && mine.dir.exists());
        let dir = mine.dir.clone();
        drop(mine);
        assert!(!dir.exists() && second.dir.exists());
        // A concurrent fork can inherit the open file description until exec.
        crate::host::flock(&running, libc::LOCK_UN).unwrap();
        drop(running);
        sweep(&f.paths).unwrap();
        assert!(!exists(".t.new-0000000000000002") && second.dir.exists());
        // Templates and generations are never touched.
        assert!(exists("kernel") && exists("mem"));
    }

    #[test]
    fn stamps_written_back_elsewhere_spare_a_rehash() {
        let f = Fixture::new();
        f.write_meta(&f.meta, &f.dir);
        let (a, b) = (f.open().unwrap(), f.open().unwrap());
        f.replace("rootfs", b"rootfs");
        a.verify(&f.paths).unwrap();
        // b loaded the meta.json from before a's rehash, and takes a's stamp from the file.
        let mut cache = BTreeMap::new();
        assert!(!f.verify(&b.meta, &mut cache).unwrap());
        assert_eq!(cache.keys().collect::<Vec<_>>(), ["rootfs"]);
        // A rehash of its own is merged into the file, keeping a's stamp.
        f.replace("firecracker", b"firecracker");
        b.verify(&f.paths).unwrap();
        let written = Meta::read(&f.dir).unwrap();
        assert!(!f.verify(&written, &mut BTreeMap::new()).unwrap());
        // A stamp written back for other content is no reason to trust a file.
        f.replace("firecracker", b"FIRECRACKER");
        let mut forged = Meta::read(&f.dir).unwrap();
        forged.components.get_mut("firecracker").unwrap().metadata = Stamp::of(&std::fs::metadata(&f.paths.firecracker).unwrap());
        forged.components.get_mut("firecracker").unwrap().hash = "0".into();
        f.write_meta(&forged, &f.dir);
        assert!(f.verify(&written, &mut BTreeMap::new()).is_err());
    }

    #[test]
    fn memory_extent_cache_skips_seeks_and_invalidates_safely() {
        let f = Fixture::new();
        let path = f.dir.join("sparse");
        let file = File::options().read(true).write(true).create_new(true).open(&path).unwrap();
        let len = 8 * PAGE_SIZE;
        file.set_len(len as u64).unwrap();
        file.write_all_at(&[1; PAGE_SIZE], PAGE_SIZE as u64).unwrap();
        file.sync_all().unwrap();
        let original = memory_bitmap(&file, len, &f.dir).unwrap();
        assert_eq!(original, vec![2]);
        // SEEK_DATA/HOLE change the file offset. A hit must leave it alone.
        assert_eq!(unsafe { libc::lseek(file.as_raw_fd(), 17, libc::SEEK_SET) }, 17);
        assert_eq!(memory_bitmap(&file, len, &f.dir).unwrap(), original);
        assert_eq!(unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_CUR) }, 17);
        file.write_all_at(&[2; PAGE_SIZE], (5 * PAGE_SIZE) as u64).unwrap();
        file.sync_all().unwrap();
        let changed = memory_bitmap(&file, len, &f.dir).unwrap();
        assert_eq!(changed, vec![2 | 32]);
        std::fs::write(f.dir.join("extents.json"), b"broken").unwrap();
        assert_eq!(memory_bitmap(&file, len, &f.dir).unwrap(), changed);
        let invalid = MemoryExtents { stamp: Stamp::of(&file.metadata().unwrap()), extents: vec![(0, len as u64 + 1)] };
        std::fs::write(f.dir.join("extents.json"), serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert_eq!(memory_bitmap(&file, len, &f.dir).unwrap(), changed);
        // An unwritable cache is optional; existing templates still open.
        std::fs::remove_file(f.dir.join("extents.json")).unwrap();
        std::fs::create_dir(f.dir.join("extents.json")).unwrap();
        assert_eq!(memory_bitmap(&file, len, &f.dir).unwrap(), changed);
        assert!(valid_extents(&[], 0));
        assert!(!valid_extents(&[(2, 4), (3, 5)], 8));
        assert!(!valid_extents(&[(2, 2)], 8));
    }

    #[test]
    fn sparsify_punches_zero_runs_and_keeps_content() {
        let f = Fixture::new();
        let path = f.dir.join("dense");
        let page = PAGE_SIZE as u64;
        // Data at pages 0, 3 and 600 (past the first 1 MiB read); zeroes elsewhere, written out.
        let file = File::options().read(true).write(true).create_new(true).open(&path).unwrap();
        file.write_all_at(&vec![0; 700 * PAGE_SIZE], 0).unwrap();
        for p in [0u64, 3, 600] {
            file.write_all_at(&[p as u8 + 1; 10], p * page + 100).unwrap();
        }
        file.sync_all().unwrap();
        let before = content_hash(&file).unwrap();
        assert_eq!(sparsify(&path).unwrap(), 697 * page);
        assert_eq!(data_extents(&file, 700 * page).unwrap(), vec![(0, page), (3 * page, 4 * page), (600 * page, 601 * page)]);
        assert_eq!(content_hash(&file).unwrap(), before);
        assert_eq!(sparsify(&path).unwrap(), 0);
    }
}
