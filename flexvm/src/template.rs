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
use serde_json::json;

use crate::bail;
use crate::fc::Firecracker;
use crate::guest;
use crate::image::ImageMeta;
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
    #[serde(default)]
    pub compatibility: Option<crate::compat::Compat>,
    pub vcpus: u32,
    pub mem_mib: u64,
    pub max_mib: u64,
    #[serde(default)]
    pub plugged_mib: u64,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    components: BTreeMap<String, Component>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageMeta>,
}

pub const FORMAT_VERSION: u64 = 2;

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
        Ok(serde_json::from_slice(&std::fs::read(dir.join("meta.json"))?)?)
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

    /// Files whose stat matches `cache`, the creation stamp or one another process wrote
    /// back to `dir`'s meta.json since are trusted; others are rehashed. Returns whether
    /// anything was rehashed.
    fn verify(&self, paths: &Paths, dir: &Path, cache: &mut BTreeMap<String, Stamp>) -> Result<bool> {
        let files = self.files(paths, dir);
        let named = self.components.len() == files.len() && files.iter().all(|(name, _)| self.components.contains_key(*name));
        if !named || !valid_id(&self.id) || content_id(&self.components, self.image.as_ref()) != self.id {
            bail!("template at {} has no valid content id; recreate it with `flexvm template`", dir.display());
        }
        let mut rehashed = false;
        let mut written: Option<Option<Meta>> = None;
        for (name, path) in files {
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
    pub rootfs: PathBuf,
    pub templates: PathBuf,
}

impl Paths {
    pub fn new(artifacts: &Path, templates: Option<PathBuf>) -> Result<Self> {
        let a = artifacts.canonicalize().map_err(|e| {
            format!("artifacts dir {}: {e} (give the one with firecracker, vmlinux and rootfs.ext4: --artifacts DIR or FLEXVM_ARTIFACTS)", artifacts.display())
        })?;
        Ok(Paths {
            firecracker: a.join("firecracker"),
            kernel: a.join("vmlinux"),
            rootfs: a.join("rootfs.ext4"),
            templates: templates.unwrap_or_else(|| a.join("templates")),
        })
    }

    /// As a VM process this one spawns without `--artifacts` finds them: `FLEXVM_ARTIFACTS`
    /// (else `./artifacts`) and `FLEXVM_TEMPLATES`, which `main` sets from its flags.
    pub fn from_env() -> Result<Self> {
        let artifacts = std::env::var_os("FLEXVM_ARTIFACTS").map_or_else(|| PathBuf::from("artifacts"), PathBuf::from);
        Paths::new(&artifacts, std::env::var_os("FLEXVM_TEMPLATES").map(PathBuf::from))
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
}

unsafe impl Send for Template {}
unsafe impl Sync for Template {}

/// `templates/.gen/<content id>/` never changes (bar cached stamps); `templates/NAME` is a
/// symlink to the current one, swapped atomically by `create`.
pub const GENERATIONS: &str = ".gen";

const MAX_LOAD_SET: usize = 512;
/// Template builds' guest commands, on a possibly loaded host.
const EXEC_TIMEOUT: Duration = Duration::from_secs(120);

/// A template name is a file name in the templates directory, never a path.
pub fn check_name(name: &str) -> Result<()> {
    crate::host::check_name(name).map_err(|_| format!("bad template name {name:?}: up to 64 letters, digits, '-', '_' or '.', not starting with '.'").into())
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
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Ok(link),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!("no template {name:?} in {} (build it: flexvm template {name}; or give --templates DIR)", paths.templates.display())
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
        let tpl = match Template::generation(paths, id) {
            Some(dir) => Template::open_dir(name, dir)?,
            None => Template::open(paths, name)?,
        };
        tpl.check_id(id)?;
        tpl.verify(paths)?;
        Ok(tpl)
    }

    pub fn open_dir(name: &str, dir: PathBuf) -> Result<Arc<Template>> {
        // All reads, the vmstate Firecracker loads included, go through one directory handle.
        let handle = File::open(&dir).map_err(|e| format!("template {name:?}: {e}"))?;
        let fixed = PathBuf::from(format!("/proc/{}/fd/{}", std::process::id(), handle.as_raw_fd()));
        let meta: Meta = serde_json::from_slice(&std::fs::read(fixed.join("meta.json")).map_err(|e| format!("template {name:?}: {e}"))?)?;
        let file = File::open(fixed.join("mem"))?;
        let len = file.metadata()?.len() as usize;
        let data = data_bitmap(&file, len)?;
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
            let _dir = crate::host::Flock::new(File::open(&self.fixed)?, libc::LOCK_EX)?;
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
        if self.meta.id.is_empty() || self.meta.id != id {
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

fn data_bitmap(file: &File, len: usize) -> Result<Vec<u64>> {
    let pages = len.div_ceil(PAGE_SIZE);
    let mut bits = vec![0u64; pages.div_ceil(64)];
    for (data, end) in data_extents(file, len as u64)? {
        for p in (data as usize / PAGE_SIZE)..(end as usize).div_ceil(PAGE_SIZE).min(pages) {
            bits[p / 64] |= 1 << (p % 64);
        }
    }
    Ok(bits)
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
    fc.load_snapshot(&tpl.vmstate(), tap, Some(true), crate::fc::API_TIMEOUT)?;
    fc.resume()?;
    retry(Duration::from_secs(10), Duration::from_millis(10), || guest::ping(&fc.sockets.vsock))?;
    guest::start(&fc.sockets.vsock, "10.255.255.254".parse()?, None)?;
    if tpl.meta.image.as_ref().is_some_and(|i| !i.warm) {
        guest::start_app(&fc.sockets.vsock)?;
    }
    // An exec records the session path's pages, so the first exec after a restore is fast;
    // an image with no shell can't run one, and an agent round trip stands in.
    if guest::exec(&fc.sockets.vsock, "true", EXEC_TIMEOUT).is_err() {
        guest::ping(&fc.sockets.vsock)?;
    }
    fc.pause()?;
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

fn interrupted() -> Result<()> {
    match INTERRUPT.load(Ordering::Relaxed) {
        0 => Ok(()),
        sig => bail!("template build interrupted (signal {sig})"),
    }
}

/// Held shared while a build makes its staging directory and while it publishes, exclusive
/// while one sweeps: a staging directory without a lock, or a link, seen under it is dead.
fn templates_lock(paths: &Paths, how: i32) -> Result<crate::host::Flock> {
    let f = File::options().create(true).truncate(false).read(true).write(true).open(paths.templates.join(".lock"))?;
    Ok(crate::host::Flock::new(f, how)?)
}

/// 16 hex digits, so concurrent builds on hosts sharing a templates directory never pick the
/// same staging directory or link.
fn nonce() -> Result<String> {
    let mut random = [0u8; 8];
    std::io::Read::read_exact(&mut File::open("/dev/urandom")?, &mut random)?;
    Ok(random.iter().map(|b| format!("{b:02x}")).collect())
}

/// Whether `file` is `.{name}.{kind}-{nonce}`, as `Staging::new` and `publish` name theirs.
fn leftover(file: &str, kind: &str) -> bool {
    file.strip_prefix('.')
        .and_then(|f| f.rsplit_once(&format!(".{kind}-")))
        .is_some_and(|(name, n)| check_name(name).is_ok() && n.len() == 16 && n.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A build's `.{name}.new-{nonce}`, flocked through `lock` inside it while the build runs, and
/// removed when dropped. A killed build's is removed by the next build (`sweep`).
struct Staging {
    dir: PathBuf,
    _lock: File,
}

impl Staging {
    fn new(paths: &Paths, name: &str) -> Result<Staging> {
        std::fs::create_dir_all(&paths.templates)?;
        sweep(paths)?;
        let _l = templates_lock(paths, libc::LOCK_SH)?;
        let dir = paths.templates.join(format!(".{name}.new-{}", nonce()?));
        std::fs::create_dir(&dir)?;
        let lock = File::create(dir.join("lock"))?;
        crate::host::flock(&lock, libc::LOCK_EX)?;
        Ok(Staging { dir, _lock: lock })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Removes staging directories whose builds are gone (their lock free, or no lock) and
/// leftover publish links: builds killed before they could clean up.
fn sweep(paths: &Paths) -> Result<()> {
    let _l = templates_lock(paths, libc::LOCK_EX)?;
    for entry in std::fs::read_dir(&paths.templates)? {
        let entry = entry?;
        let (name, kind) = (entry.file_name().to_string_lossy().into_owned(), entry.file_type()?);
        if kind.is_symlink() && leftover(&name, "link") {
            let _ = std::fs::remove_file(entry.path());
        } else if kind.is_dir() && leftover(&name, "new") {
            let live = File::open(entry.path().join("lock")).is_ok_and(|f| crate::host::flock(&f, libc::LOCK_EX | libc::LOCK_NB).is_err());
            if !live {
                crate::log!("template: removing {}, left by a build that did not finish", entry.path().display());
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn create(paths: &Paths, name: &str, vcpus: u32, mem_mib: u64, max_mib: u64, plug_mib: u64, image: Option<ImageMeta>, tap: &str) -> Result<()> {
    // `tap` is made (under the host lock, `Host::tap_prefix`) and removed here.
    let res = (|| {
        // Running VMs map the old files, which must not be rewritten under them.
        let staging = Staging::new(paths, name)?;
        build(paths, &staging.dir, name, vcpus, mem_mib, max_mib, plug_mib, tap, image)?;
        interrupted()?;
        publish(paths, name, &staging.dir)
    })();
    crate::net::delete_tap(tap);
    res
}

/// Nothing is deleted: VMs and checkpoints refer to generations by content id, so old ones
/// stay until an operator removes them.
fn publish(paths: &Paths, name: &str, staged: &Path) -> Result<()> {
    let meta = Meta::read(staged)?;
    let gens = paths.templates.join(GENERATIONS);
    crate::util::create_dir_durably(&gens, 0o777)?;
    let gen = gens.join(&meta.id);
    // Its files and their names are durable before the generation is published.
    for entry in std::fs::read_dir(staged)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            File::open(entry.path())?.sync_all()?;
        }
    }
    let _l = templates_lock(paths, libc::LOCK_SH)?;
    // Not part of the generation; the build's flock holds on, through its open file.
    match std::fs::remove_file(staged.join("lock")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        r => r?,
    }
    crate::util::sync_dir(staged)?;
    match std::fs::rename(staged, &gen) {
        // An identical build published it already.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {}
        r => r?,
    }
    let live = paths.templates.join(name);
    let tmp = paths.templates.join(format!(".{name}.link-{}", nonce()?));
    std::os::unix::fs::symlink(Path::new(GENERATIONS).join(&meta.id), &tmp)?;
    crate::util::sync_dir(&gens)?;
    std::fs::rename(&tmp, &live)?;
    Ok(crate::util::sync_dir(&paths.templates)?)
}

#[allow(clippy::too_many_arguments)]
fn build(paths: &Paths, dir: &Path, name: &str, vcpus: u32, mem_mib: u64, max_mib: u64, plug_mib: u64, tap: &str, image: Option<ImageMeta>) -> Result<()> {
    let run = dir.join("boot");
    std::fs::create_dir_all(&run)?;
    let sockets = SocketRoot::new(dir)?;

    // rootfs.ext4 is a symlink a rebuild repoints; the snapshot's page cache needs these bytes.
    let rootfs = std::fs::canonicalize(&paths.rootfs)
        .map_err(|e| format!("{}: {e} (build it: scripts/build-rootfs.sh, or give --image REF)", paths.rootfs.display()))?;
    let start = Instant::now();
    let fc = Firecracker::spawn(&paths.firecracker, &run, sockets.allocate()?, crate::fc::SPAWN_READY)?;
    let vsock = fc.sockets.vsock.clone();
    let metrics = run.join("metrics.json");
    File::create(&metrics)?;
    fc.put("/metrics", json!({"metrics_path": metrics}))?;
    fc.put("/boot-source", json!({"kernel_image_path": paths.kernel, "boot_args": BOOT_ARGS}))?;
    fc.put("/machine-config", json!({"vcpu_count": vcpus, "mem_size_mib": mem_mib}))?;
    fc.put("/pmem/root", json!({"id": "root", "path_on_host": rootfs, "root_device": true, "read_only": true}))?;
    fc.put("/balloon", json!({"amount_mib": 0, "deflate_on_oom": false, "stats_polling_interval_s": BALLOON_STATS_S, "free_page_reporting": true}))?;
    let hotplug = max_mib.saturating_sub(mem_mib) / SLOT_MIB * SLOT_MIB;
    if hotplug > 0 {
        fc.put("/hotplug/memory", json!({"total_size_mib": hotplug, "slot_size_mib": SLOT_MIB}))?;
    }
    fc.put("/vsock", json!({"guest_cid": 3, "uds_path": vsock}))?;
    fc.put("/network-interfaces/eth0", json!({"iface_id": "eth0", "host_dev_name": tap, "guest_mac": crate::net::GUEST_MAC}))?;
    fc.put("/entropy", json!({}))?;
    fc.put("/actions", json!({"action_type": "InstanceStart"}))?;
    retry(Duration::from_secs(30), Duration::from_millis(10), || guest::ping(&vsock))
        .map_err(|e| format!("the guest did not boot: {e}; {}", fc.post_mortem()))?;
    let booted = start.elapsed();
    interrupted()?;
    let plugged = plug(&fc, plug_mib.min(hotplug) / STEP_MIB * STEP_MIB)?;

    match &image {
        Some(img) => {
            if img.warm {
                crate::image::warm_up(&vsock, img)?;
            }
            // Images may have no shell.
            guest::quiesce(&vsock)?;
        }
        None => {
            guest::exec(&vsock, "sync; echo 3 > /proc/sys/vm/drop_caches; echo 1 > /proc/sys/vm/compact_memory", EXEC_TIMEOUT)?;
        }
    }
    interrupted()?;
    let (reported, done) = wait_reporting_done(&fc, &metrics, plugged * 3 / 4)?;
    if !done {
        crate::log!(
            "template {name}: free page reporting did not finish ({reported} MiB reported of {plugged} MiB \
             plugged); VMs will report the rest after restore, at some RSS each"
        );
    }
    fc.pause()?;
    fc.put("/snapshot/create", json!({"snapshot_type": "Full", "snapshot_path": dir.join("vmstate"), "mem_file_path": dir.join("mem")}))?;
    let compatibility = crate::compat::local(fc.pid())?;
    drop(fc);
    interrupted()?;
    let sparsifying = Instant::now();
    let punched = sparsify(&dir.join("mem"))?;
    let sparsified = sparsifying.elapsed();
    let _ = std::fs::remove_dir_all(&run);

    let mut meta = Meta {
        compatibility: Some(compatibility),
        vcpus,
        mem_mib,
        max_mib: mem_mib + hotplug,
        plugged_mib: plugged,
        kernel: paths.kernel.clone(),
        rootfs,
        id: String::new(),
        components: BTreeMap::new(),
        image,
    };
    meta.identify(paths, dir)?;
    std::fs::write(dir.join("meta.json"), serde_json::to_vec_pretty(&meta)?)?;
    let _ = std::fs::remove_file(dir.join("wset"));
    interrupted()?;
    let wset = record_working_set(paths, dir, tap, &sockets)?;
    let size = std::fs::metadata(dir.join("mem"))?.len();
    println!(
        "template {name} (id {}): {vcpus} vCPUs, {mem_mib} MiB base + {hotplug} MiB hotplug ({plugged} MiB plugged, \
         {reported} MiB reported free), booted in {} ms, memory file {} MiB ({} MiB of zeroes punched out in {} ms), working set {} MiB",
        meta.id,
        ms(booted),
        size >> 20,
        punched >> 20,
        ms(sparsified),
        wset >> 20
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn working_set_mib_is_read_without_opening_the_template() {
        let root = std::env::temp_dir().join(format!("flexvm-wset-mib-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("templates/t")).unwrap();
        let paths = Paths::new(&root, None).unwrap();
        // 1 GiB and 2 MiB of 4 KiB pages; no memory file, which opening it would need.
        std::fs::write(root.join("templates/t/wset"), b"[[0, 262144], [300000, 512]]").unwrap();
        assert_eq!(Template::working_set_mib_of(&paths, "t").unwrap(), 1026);
        assert!(Template::working_set_mib_of(&paths, "none").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn working_set_runs_are_padded_and_merged() {
        assert_eq!(pad_runs(vec![(3, 2), (17, 1), (20, 40), (100, 1)], 16), vec![(0, 64), (96, 16)]);
        assert_eq!(pad_runs(vec![], 16), vec![]);
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

    struct Fixture {
        paths: Paths,
        dir: PathBuf,
        meta: Meta,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!("flexvm-identity-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir_all(&dir).unwrap();
            let paths = Paths { firecracker: dir.join("firecracker"), kernel: dir.join("kernel"), rootfs: dir.join("rootfs"), templates: dir.clone() };
            let mut meta = Meta {
                compatibility: None,
                vcpus: 2,
                mem_mib: 256,
                max_mib: 1024,
                plugged_mib: 0,
                kernel: paths.kernel.clone(),
                rootfs: paths.rootfs.clone(),
                id: String::new(),
                components: BTreeMap::new(),
                image: None,
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

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn set_mtime(file: &File, sec: i64, nsec: i64) {
        let times = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }, libc::timespec { tv_sec: sec, tv_nsec: nsec }];
        assert_eq!(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) }, 0);
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
        publish(&f.paths, "t", &stage("a")).unwrap();
        assert_eq!(current(), "a");
        let a = Template::resolve(&f.paths, "t").unwrap();
        publish(&f.paths, "t", &stage("b")).unwrap();
        assert_eq!(current(), "b");
        // Whoever resolved `a` before the swap still reads a's files.
        assert_eq!(std::fs::read_to_string(a.join("vmstate")).unwrap(), "a");
        assert_eq!(gens(), ["a", "b"]);
        publish(&f.paths, "t", &stage("c")).unwrap();
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
        let image = |digest: &str, conf: &str| ImageMeta {
            source: "x".into(),
            digest: digest.into(),
            config_digest: "sha256:c".into(),
            app_conf: conf.into(),
            argv: vec!["/x".into()],
            warm: false,
            ready: None,
            ready_timeout: Duration::ZERO,
        };
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
        for name in ["vmstate", "mem", "rootfs", "kernel", "firecracker"] {
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
        f.replace("kernel", b"changed");
        f.open().unwrap();
        assert!(tpl.verify(&f.paths).is_err());
    }

    #[test]
    fn size_and_mtime_invalidate_cache() {
        let f = Fixture::new();
        let file = File::options().read(true).write(true).open(f.dir.join("kernel")).unwrap();
        let original = file.metadata().unwrap();
        file.set_len(original.len() + 1).unwrap();
        assert_ne!(Stamp::of(&file.metadata().unwrap()).size, original.len());
        assert!(f.fresh().is_err());
        file.set_len(original.len()).unwrap();
        set_mtime(&file, original.mtime() + 1, original.mtime_nsec());
        assert!(f.fresh().unwrap());
    }

    #[test]
    fn rehash_is_remembered_across_opens() {
        let f = Fixture::new();
        f.write_meta(&f.meta, &f.dir);
        f.replace("rootfs", b"rootfs");
        f.open().unwrap().verify(&f.paths).unwrap();
        let meta: Meta = serde_json::from_slice(&std::fs::read(f.dir.join("meta.json")).unwrap()).unwrap();
        assert!(!f.verify(&meta, &mut BTreeMap::new()).unwrap());
        f.open().unwrap().verify(&f.paths).unwrap();
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
        let file = File::options().write(true).open(f.dir.join("kernel")).unwrap();
        let before = file.metadata().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        file.write_all_at(b"KERNEL", 0).unwrap();
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
            lock.then(|| File::create(dir.join("lock")).unwrap())
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
        let mine = Staging::new(&f.paths, "t").unwrap();
        for gone in [".t.new-0000000000000001", ".u.new-0000000000000003", ".foo.link-bar.new-0000000000000004", ".t.link-0000000000000005"] {
            assert!(!exists(gone), "{gone}");
        }
        assert!(exists(".t.new-0000000000000002") && mine.dir.join("lock").exists());
        assert!(foreign.iter().all(|name| exists(name)));
        // A concurrent build of the same name gets a directory of its own, and each leaves
        // the other's alone.
        let second = Staging::new(&f.paths, "t").unwrap();
        assert!(second.dir != mine.dir && second.dir.exists() && mine.dir.exists());
        let dir = mine.dir.clone();
        drop(mine);
        assert!(!dir.exists() && second.dir.exists());
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
        f.replace("kernel", b"kernel");
        b.verify(&f.paths).unwrap();
        let written = Meta::read(&f.dir).unwrap();
        assert!(!f.verify(&written, &mut BTreeMap::new()).unwrap());
        // A stamp written back for other content is no reason to trust a file.
        f.replace("kernel", b"KERNEL");
        let mut forged = Meta::read(&f.dir).unwrap();
        forged.components.get_mut("kernel").unwrap().metadata = Stamp::of(&std::fs::metadata(&f.paths.kernel).unwrap());
        forged.components.get_mut("kernel").unwrap().hash = "0".into();
        f.write_meta(&forged, &f.dir);
        assert!(f.verify(&written, &mut BTreeMap::new()).is_err());
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
