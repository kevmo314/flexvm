//! Templates: a VM cold-booted once and snapshotted right after the guest
//! agent came up. Every VM is a UFFD restore of a template, so "boot" costs a
//! snapshot load and pages are copied in only as the guest touches them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::bail;
use crate::fc::Firecracker;
use crate::guest;
use crate::image::ImageMeta;
use crate::socket::SocketRoot;
use crate::uffd::Pager;
use crate::util::{ms, retry, Result, PAGE_SIZE};

/// How often Firecracker refreshes the guest's balloon statistics.
pub const BALLOON_STATS_S: u16 = 1;

pub const BOOT_ARGS: &str = "console=ttyS0 quiet reboot=k panic=1 pci=off \
    i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd \
    rootflags=dax init=/sbin/flexvm-init memhp_default_state=online_movable psi=1";

/// KVM memslot size for the virtio-mem region (MiB). Restores pay per slot,
/// and plugged but untouched memory costs the host nothing, so slots are big.
pub const SLOT_MIB: u64 = 1024;
/// Step the controller grows and shrinks guests by (MiB).
pub const STEP_MIB: u64 = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub vcpus: u32,
    pub mem_mib: u64,
    pub max_mib: u64,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    components: BTreeMap<String, Component>,
    /// Set for templates built from a container image; part of the content id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageMeta>,
}

pub const FORMAT_VERSION: u64 = 2;

/// What a component file looked like when it was last hashed. ctime catches
/// rewrites that restore mtime; a rename or copy changes the inode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stamp {
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    inode: u64,
    device: u64,
}

impl Stamp {
    fn of(m: &std::fs::Metadata) -> Self {
        Self {
            size: m.len(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
            inode: m.ino(),
            device: m.dev(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Component {
    hash: String,
    metadata: Stamp,
}

/// FNV-1a over 64-bit words, folded so high bits feed back down. An identity
/// check for trusted files, not protection against tampering.
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

/// Hashes a file's logical content: its length and every page that is not all
/// zeroes, so sparse and fully allocated copies of the same bytes match.
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
                if p.iter().fold(0, |a, &b| a | b) != 0 {
                    hash.word(off / page + i as u64);
                    hash.update(p);
                }
            }
            off += n as u64;
        }
    }
    Ok(hash.finish())
}

/// Hashes the file at `path`, failing if it changes underneath.
fn hash_file(path: &Path) -> Result<Component> {
    let file = File::open(path).map_err(|e| format!("template component {}: {e}", path.display()))?;
    let metadata = Stamp::of(&file.metadata()?);
    let hash = content_hash(&file)?;
    if Stamp::of(&file.metadata()?) != metadata {
        bail!("template component {} changed while hashing", path.display());
    }
    Ok(Component { hash, metadata })
}

/// Image templates also cover the image's identity and the app config; the
/// root filesystem built from the image is the `rootfs` component.
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

    /// Checks the files still match the recorded hashes. Files whose stat
    /// matches `cache` (or the stamp from creation) are trusted; others are
    /// rehashed if `rehash`, else rejected. Returns whether anything was rehashed.
    fn verify(&self, paths: &Paths, dir: &Path, cache: &mut BTreeMap<String, Stamp>, rehash: bool) -> Result<bool> {
        if self.id.is_empty() || self.components.len() != 5 || content_id(&self.components, self.image.as_ref()) != self.id {
            bail!("template at {} has no valid content id; recreate it with `flexvm template`", dir.display());
        }
        let mut rehashed = false;
        for (name, path) in self.files(paths, dir) {
            let component = &self.components[name];
            let stamp = Stamp::of(
                &std::fs::metadata(&path).map_err(|e| format!("template component {}: {e}", path.display()))?,
            );
            if cache.get(name).unwrap_or(&component.metadata) == &stamp {
                continue;
            }
            if !rehash {
                bail!("template component {} changed since preflight", path.display());
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

/// Paths shared by everything that creates or runs VMs.
#[derive(Debug, Clone)]
pub struct Paths {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub templates: PathBuf,
}

impl Paths {
    pub fn new(artifacts: &Path, templates: Option<PathBuf>) -> Result<Self> {
        let a = artifacts.canonicalize().map_err(|e| format!("artifacts dir {artifacts:?}: {e}"))?;
        Ok(Paths {
            firecracker: a.join("firecracker"),
            kernel: a.join("vmlinux"),
            rootfs: a.join("rootfs.ext4"),
            templates: templates.unwrap_or_else(|| a.join("templates")),
        })
    }
}

pub struct Template {
    pub name: String,
    pub dir: PathBuf,
    pub meta: Meta,
    /// Pages a fresh VM touches on its way to ready, as `(first_page, count)`.
    pub working_set: Vec<(u64, u64)>,
    /// Its guest agent predates `START`, so starts use `NET` and leave the clock alone.
    pub legacy_agent: AtomicBool,
    /// Pages Firecracker touches while loading this template's snapshot,
    /// learned from the hot pool's loads here (`Pager::learn_load_set`): vCPU
    /// clock pages, virtqueues and the like, at the same addresses in every
    /// VM of the template. A migration source sends the ones it has along
    /// with the vmstate, so the target's load need not fetch them one round
    /// trip at a time.
    load_set: Mutex<BTreeSet<u64>>,
    map: *const u8,
    len: usize,
    /// Bitmap of pages that hold data in the memory file (the rest are holes).
    data: Vec<u64>,
    verified: Mutex<BTreeMap<String, Stamp>>,
    /// The directory as opened, through `_handle`, whatever its path refers to now.
    fixed: PathBuf,
    /// The directory's inode: a different one at `dir` is another template.
    pub ino: u64,
    _handle: File,
}

unsafe impl Send for Template {}
unsafe impl Sync for Template {}

/// Published templates live in `templates/.gen/<content id>/` and never change
/// afterwards (apart from cached file stamps in meta.json); `templates/NAME` is
/// a symlink to the current generation, swapped atomically by `create`. A
/// running VM keeps the generation it was restored from.
pub const GENERATIONS: &str = ".gen";

/// Most pages a template's load set holds (2 MiB).
const MAX_LOAD_SET: usize = 512;

impl Template {
    /// The directory `templates/name` currently stands for: its generation, or
    /// the directory itself for a template made before generations existed.
    pub fn resolve(paths: &Paths, name: &str) -> Result<PathBuf> {
        let link = paths.templates.join(name);
        match std::fs::read_link(&link) {
            Ok(target) => Ok(paths.templates.join(target)),
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Ok(link),
            Err(e) => bail!("template {name:?}: {e}"),
        }
    }

    /// Generation `id` of template `name`, if this host has it.
    pub fn generation(paths: &Paths, id: &str) -> Option<PathBuf> {
        let dir = paths.templates.join(GENERATIONS).join(id);
        (!id.is_empty() && !id.contains('/') && dir.is_dir()).then_some(dir)
    }

    pub fn open(paths: &Paths, name: &str) -> Result<Arc<Template>> {
        Template::open_dir(name, Template::resolve(paths, name)?)
    }

    /// Opens the template files in `dir`, which `open` resolved from `name`.
    pub fn open_dir(name: &str, dir: PathBuf) -> Result<Arc<Template>> {
        // Everything is read through one handle on the directory, and so is
        // the vmstate Firecracker loads later (`vmstate`): a template from
        // before generations is replaced by renaming another directory over
        // its path, and this one must keep reading the files it started with.
        let handle = File::open(&dir).map_err(|e| format!("template {name:?}: {e}"))?;
        let ino = handle.metadata()?.ino();
        let fixed = PathBuf::from(format!("/proc/{}/fd/{}", std::process::id(), handle.as_raw_fd()));
        let meta: Meta = serde_json::from_slice(
            &std::fs::read(fixed.join("meta.json")).map_err(|e| format!("template {name:?}: {e}"))?,
        )?;
        let file = File::open(fixed.join("mem"))?;
        let len = file.metadata()?.len() as usize;
        let data = data_bitmap(&file, len)?;
        let map = unsafe {
            libc::mmap(std::ptr::null_mut(), len.max(1), libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0)
        };
        if map == libc::MAP_FAILED {
            bail!("mmap template memory: {}", std::io::Error::last_os_error());
        }
        let working_set = std::fs::read(fixed.join("wset"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Ok(Arc::new(Template {
            name: name.into(),
            dir,
            meta,
            working_set,
            legacy_agent: AtomicBool::new(false),
            load_set: Mutex::default(),
            map: map as *const u8,
            len,
            data,
            verified: Mutex::default(),
            fixed,
            ino,
            _handle: handle,
        }))
    }

    /// Records that a snapshot load faulted on `page` (see `load_set`).
    pub fn note_load_fault(&self, page: u64) {
        let mut set = self.load_set.lock().unwrap();
        if set.len() < MAX_LOAD_SET {
            set.insert(page);
        }
    }

    /// The pages snapshot loads of this template touched here, sorted.
    pub fn load_set(&self) -> Vec<u64> {
        self.load_set.lock().unwrap().iter().copied().collect()
    }

    /// Checks the files against the content id: stat only, unless `rehash` and
    /// a file changed since it was last hashed. Never call on the run path.
    pub fn verify(&self, paths: &Paths, rehash: bool) -> Result<()> {
        let cache = &mut self.verified.lock().unwrap();
        // Through the handle: `dir` may name another template by now.
        if self.meta.verify(paths, &self.fixed, cache, rehash)? {
            // Record the new stamps so the next daemon on this host need not rehash.
            let mut meta = self.meta.clone();
            for (name, stamp) in cache.iter() {
                meta.components.get_mut(name).unwrap().metadata = stamp.clone();
            }
            let tmp = self.fixed.join(format!("meta.json.{}", std::process::id()));
            let _ = std::fs::write(&tmp, serde_json::to_vec_pretty(&meta)?)
                .and_then(|_| std::fs::rename(&tmp, self.fixed.join("meta.json")));
        }
        Ok(())
    }

    pub fn check_id(&self, id: &str) -> Result<()> {
        if self.meta.id.is_empty() {
            bail!("template {:?} has no content id; recreate it with `flexvm template`", self.name);
        }
        if self.meta.id != id {
            bail!("template {:?} id mismatch: local {}, source {id}", self.name, self.meta.id);
        }
        Ok(())
    }

    /// Identifies this generation: its content id (or directory, for old templates).
    pub fn key(&self) -> String {
        if self.meta.id.is_empty() {
            self.dir.display().to_string()
        } else {
            self.meta.id.clone()
        }
    }

    pub fn vmstate(&self) -> PathBuf {
        self.fixed.join("vmstate")
    }

    pub fn has_data(&self, page: usize) -> bool {
        self.data.get(page / 64).is_some_and(|w| w & (1 << (page % 64)) != 0)
    }

    /// The template's bytes for `n` pages starting at `page`. They must all have data.
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

/// Finds the data extents of a sparse file with SEEK_DATA / SEEK_HOLE.
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

/// Punches holes over all-zero pages so they cost nothing to store or serve.
fn sparsify(path: &Path) -> Result<u64> {
    use std::os::unix::fs::FileExt;
    let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    let len = f.metadata()?.len() as i64;
    let fd = f.as_raw_fd();
    let mut buf = vec![0u8; PAGE_SIZE];
    let mut punched = 0u64;
    let mut off: i64 = 0;
    while off < len {
        let data = unsafe { libc::lseek(fd, off, libc::SEEK_DATA) };
        if data < 0 {
            break;
        }
        let end = match unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) } {
            h if h < 0 => len,
            h => h,
        };
        let mut p = data;
        while p < end {
            let n = f.read_at(&mut buf, p as u64)?;
            if n > 0 && buf[..n].iter().all(|&b| b == 0) {
                let rc = unsafe {
                    libc::fallocate(fd, libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, p, n as i64)
                };
                if rc == 0 {
                    punched += n as u64;
                }
            }
            p += PAGE_SIZE as i64;
        }
        off = end;
    }
    Ok(punched)
}

/// Restores the template once and records which pages the guest touches
/// until its agent answers; restores prefetch exactly those.
fn record_working_set(paths: &Paths, name: &str, tap: &str, sockets: &Arc<SocketRoot>) -> Result<usize> {
    let tpl = Template::open(paths, name)?;
    let run = tpl.dir.join("record");
    // A failed earlier build may have left its logs behind.
    let _ = std::fs::remove_dir_all(&run);
    std::fs::create_dir_all(&run)?;
    let fc = Firecracker::spawn(&paths.firecracker, &run, sockets.allocate()?)?;
    let pager = Pager::start(&fc.sockets.uffd, tpl.clone(), None)?;
    pager.set_pid(fc.pid())?;
    fc.put(
        "/snapshot/load",
        json!({
            "snapshot_path": tpl.vmstate(),
            "mem_backend": {"backend_type": "Uffd", "backend_path": fc.sockets.uffd},
            "vsock_override": {"uds_path": fc.sockets.vsock},
            "network_overrides": [{"iface_id": "eth0", "host_dev_name": tap}],
            // Like the daemon's restores: stepping the clock touches pages of its own.
            "clock_realtime": true,
            "resume_vm": true,
        }),
    )?;
    retry(Duration::from_secs(10), || guest::ping(&fc.sockets.vsock))?;
    guest::start(&fc.sockets.vsock, "10.255.255.254".parse()?, None, &tpl.legacy_agent)?;
    // Like `run`: start a cold image template's app.
    if tpl.meta.image.as_ref().is_some_and(|i| !i.warm) {
        guest::start_app(&fc.sockets.vsock)?;
    }
    guest::exec(&fc.sockets.vsock, "true")?;
    fc.pause()?;
    let runs = pager.present_runs();
    pager.stop();
    drop(fc);
    let _ = std::fs::remove_dir_all(&run);
    std::fs::write(tpl.dir.join("wset"), serde_json::to_vec(&runs)?)?;
    Ok(runs.iter().map(|r| r.1 as usize).sum::<usize>() * PAGE_SIZE)
}

/// Cold-boots a VM and snapshots it into `paths.templates/name`.
pub fn create(paths: &Paths, name: &str, vcpus: u32, mem_mib: u64, max_mib: u64, image: Option<ImageMeta>) -> Result<()> {
    // Restores swap in each VM's own tap; this one only exists while building.
    let tap = format!("fvtpl{}", std::process::id());
    crate::net::create_tap(&tap)?;
    // Build next to the live template and swap it in at the end: running VMs
    // map the old files, which must not be truncated or rewritten under them.
    let staging = format!(".{name}.new-{}", std::process::id());
    let _ = std::fs::remove_dir_all(paths.templates.join(&staging));
    let res = build(paths, &staging, name, vcpus, mem_mib, max_mib, &tap, image);
    crate::net::delete_tap(&tap);
    let staged = paths.templates.join(&staging);
    let res = res.and_then(|()| publish(paths, name, &staged));
    let _ = std::fs::remove_dir_all(&staged);
    res
}

/// Moves a finished build into its generation directory and points
/// `templates/name` at it with one atomic rename of a symlink. Nothing is ever
/// deleted here: running and suspended VMs, migrations, pooled VMs and
/// checkpoints refer to generations by content id, so old generations stay
/// until an operator removes them (see the README).
fn publish(paths: &Paths, name: &str, staged: &Path) -> Result<()> {
    let meta: Meta = serde_json::from_slice(&std::fs::read(staged.join("meta.json"))?)?;
    let gens = paths.templates.join(GENERATIONS);
    std::fs::create_dir_all(&gens)?;
    let gen = gens.join(&meta.id);
    if !gen.exists() {
        std::fs::rename(staged, &gen)?;
    }
    let live = paths.templates.join(name);
    let tmp = paths.templates.join(format!(".{name}.link-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(Path::new(GENERATIONS).join(&meta.id), &tmp)?;
    // A template from before generations is a plain directory: it becomes a
    // generation itself (suspended VMs and checkpoints may name its content
    // id), or, without a usable id, is kept aside; never deleted.
    if std::fs::symlink_metadata(&live).is_ok_and(|m| m.is_dir()) {
        let id = std::fs::read(live.join("meta.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Meta>(&b).ok())
            .map(|m| m.id)
            .filter(|id| !id.is_empty() && !id.contains('/') && !gens.join(id).exists());
        let aside = match id {
            Some(id) => gens.join(id),
            None => gens.join(format!("legacy-{name}-{}", std::process::id())),
        };
        std::fs::rename(&live, &aside)?;
    }
    std::fs::rename(&tmp, &live)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build(
    paths: &Paths,
    staging: &str,
    name: &str,
    vcpus: u32,
    mem_mib: u64,
    max_mib: u64,
    tap: &str,
    image: Option<ImageMeta>,
) -> Result<()> {
    let dir = paths.templates.join(staging);
    std::fs::create_dir_all(&dir)?;
    let run = dir.join("boot");
    std::fs::create_dir_all(&run)?;
    let sockets = SocketRoot::new(&dir)?;

    // Pin the exact image file: artifacts/rootfs.ext4 is a symlink a rebuild
    // repoints, and this snapshot's page cache is only valid for these bytes.
    let rootfs = std::fs::canonicalize(&paths.rootfs)?;
    let start = Instant::now();
    let fc = Firecracker::spawn(&paths.firecracker, &run, sockets.allocate()?)?;
    let vsock = fc.sockets.vsock.clone();
    fc.put("/boot-source", json!({"kernel_image_path": paths.kernel, "boot_args": BOOT_ARGS}))?;
    fc.put("/machine-config", json!({"vcpu_count": vcpus, "mem_size_mib": mem_mib}))?;
    fc.put("/pmem/root", json!({"id": "root", "path_on_host": rootfs, "root_device": true, "read_only": true}))?;
    fc.put(
        "/balloon",
        json!({"amount_mib": 0, "deflate_on_oom": false, "stats_polling_interval_s": BALLOON_STATS_S, "free_page_reporting": true}),
    )?;
    let hotplug = max_mib.saturating_sub(mem_mib) / SLOT_MIB * SLOT_MIB;
    if hotplug > 0 {
        fc.put("/hotplug/memory", json!({"total_size_mib": hotplug, "slot_size_mib": SLOT_MIB}))?;
    }
    fc.put("/vsock", json!({"guest_cid": 3, "uds_path": vsock}))?;
    fc.put(
        "/network-interfaces/eth0",
        json!({"iface_id": "eth0", "host_dev_name": tap, "guest_mac": crate::net::GUEST_MAC}),
    )?;
    fc.put("/entropy", json!({}))?;
    fc.put("/actions", json!({"action_type": "InstanceStart"}))?;
    retry(Duration::from_secs(30), || guest::ping(&vsock))?;
    let booted = start.elapsed();

    // Leave as little as possible in the snapshot.
    match &image {
        Some(img) => {
            if img.warm {
                crate::image::warm_up(&vsock, img)?;
            }
            // Images may have no shell.
            guest::quiesce(&vsock)?;
        }
        None => {
            guest::exec(&vsock, "sync; echo 3 > /proc/sys/vm/drop_caches; echo 1 > /proc/sys/vm/compact_memory")?;
        }
    }
    fc.pause()?;
    fc.put(
        "/snapshot/create",
        json!({"snapshot_type": "Full", "snapshot_path": dir.join("vmstate"), "mem_file_path": dir.join("mem")}),
    )?;
    drop(fc);
    let punched = sparsify(&dir.join("mem"))?;
    let _ = std::fs::remove_dir_all(&run);

    let mut meta = Meta {
        vcpus,
        mem_mib,
        max_mib: mem_mib + hotplug,
        kernel: paths.kernel.clone(),
        rootfs,
        id: String::new(),
        components: BTreeMap::new(),
        image,
    };
    meta.identify(paths, &dir)?;
    std::fs::write(dir.join("meta.json"), serde_json::to_vec_pretty(&meta)?)?;
    let _ = std::fs::remove_file(dir.join("wset"));
    let wset = record_working_set(paths, staging, tap, &sockets)?;
    let size = std::fs::metadata(dir.join("mem"))?.len();
    println!(
        "template {name} (id {}): {vcpus} vCPUs, {mem_mib} MiB base + {hotplug} MiB hotplug, booted in {} ms, \
         memory file {} MiB ({} MiB of zeroes punched out), working set {} MiB",
        meta.id,
        ms(booted),
        size >> 20,
        punched >> 20,
        wset >> 20
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture {
        paths: Paths,
        dir: PathBuf,
        meta: Meta,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "flexvm-identity-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let paths = Paths {
                firecracker: dir.join("firecracker"),
                kernel: dir.join("kernel"),
                rootfs: dir.join("rootfs"),
                templates: dir.clone(),
            };
            let mut meta = Meta {
                vcpus: 2, mem_mib: 256, max_mib: 1024,
                kernel: paths.kernel.clone(), rootfs: paths.rootfs.clone(),
                id: String::new(), components: BTreeMap::new(), image: None,
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
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn publish_swaps_generations_and_keeps_them_all() {
        let f = Fixture::new();
        let stage = |id: &str| {
            let dir = f.dir.join(format!(".t.new-{id}"));
            std::fs::create_dir_all(&dir).unwrap();
            let meta = Meta { id: id.into(), ..f.meta.clone() };
            std::fs::write(dir.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
            std::fs::write(dir.join("vmstate"), id).unwrap();
            dir
        };
        let current = || std::fs::read_to_string(Template::resolve(&f.paths, "t").unwrap().join("vmstate")).unwrap();
        let gens = || {
            let mut g: Vec<String> = std::fs::read_dir(f.dir.join(GENERATIONS))
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            g.sort();
            g
        };
        // A template from before generations: a plain directory, with an id.
        std::fs::create_dir_all(f.dir.join("t")).unwrap();
        std::fs::write(f.dir.join("t/vmstate"), "legacy").unwrap();
        let old = Meta { id: "l".into(), ..f.meta.clone() };
        std::fs::write(f.dir.join("t/meta.json"), serde_json::to_vec(&old).unwrap()).unwrap();
        assert_eq!(current(), "legacy");
        publish(&f.paths, "t", &stage("a")).unwrap();
        assert_eq!(current(), "a");
        // Kept, as the generation of its own content id.
        assert_eq!(std::fs::read_to_string(f.dir.join(GENERATIONS).join("l/vmstate")).unwrap(), "legacy");
        let a = Template::resolve(&f.paths, "t").unwrap();
        publish(&f.paths, "t", &stage("b")).unwrap();
        assert_eq!(current(), "b");
        // Whoever resolved `a` before the swap still reads a's files.
        assert_eq!(std::fs::read_to_string(a.join("vmstate")).unwrap(), "a");
        assert_eq!(gens(), ["a", "b", "l"]);
        publish(&f.paths, "t", &stage("c")).unwrap();
        assert_eq!(current(), "c");
        assert_eq!(gens(), ["a", "b", "c", "l"]);
        assert_eq!(Template::generation(&f.paths, "a"), Some(f.dir.join(GENERATIONS).join("a")));
        assert_eq!(Template::generation(&f.paths, "x"), None);
    }

    #[test]
    fn identity_roundtrip_and_metadata_independence() {
        let f = Fixture::new();
        let mut meta: Meta = serde_json::from_slice(&serde_json::to_vec(&f.meta).unwrap()).unwrap();
        for component in meta.components.values_mut() {
            component.metadata.inode += 1;
            component.metadata.mtime += 1;
        }
        assert_eq!(content_id(&meta.components, None), f.meta.id);
        meta.verify(&f.paths, &f.dir, &mut BTreeMap::new(), true).unwrap();
        meta.id = "wrong".into();
        assert!(meta.verify(&f.paths, &f.dir, &mut BTreeMap::new(), true).is_err());
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
        meta.verify(&f.paths, &f.dir, &mut BTreeMap::new(), false).unwrap();
        meta.image.as_mut().unwrap().digest = "sha256:b".into();
        assert!(meta.verify(&f.paths, &f.dir, &mut BTreeMap::new(), false).is_err());
    }

    #[test]
    fn changed_components_are_rejected() {
        for name in ["vmstate", "mem", "rootfs", "kernel", "firecracker"] {
            let f = Fixture::new();
            let mut cache = BTreeMap::new();
            f.meta.verify(&f.paths, &f.dir, &mut cache, true).unwrap();
            // Replacement changes inode even for equal-size content.
            f.replace(name, &vec![b'x'; name.len()]);
            let error = f.meta.verify(&f.paths, &f.dir, &mut cache, true).unwrap_err().to_string();
            assert!(error.contains("does not match"), "{error}");
        }
    }

    #[test]
    fn cache_refresh_requires_preflight() {
        let f = Fixture::new();
        let mut cache = BTreeMap::new();
        f.meta.verify(&f.paths, &f.dir, &mut cache, false).unwrap();
        f.replace("rootfs", b"rootfs");
        assert!(f.meta.verify(&f.paths, &f.dir, &mut cache, false).is_err());
        f.meta.verify(&f.paths, &f.dir, &mut cache, true).unwrap();
        f.meta.verify(&f.paths, &f.dir, &mut cache, false).unwrap();
        f.replace("rootfs", b"broken");
        assert!(f.meta.verify(&f.paths, &f.dir, &mut cache, true).is_err());
        assert!(f.meta.verify(&f.paths, &f.dir, &mut cache, false).is_err());
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
        std::fs::write(f.dir.join("meta.json"), serde_json::to_vec(&f.meta).unwrap()).unwrap();
        let tpl = Template::open(&f.paths, "").unwrap();
        tpl.check_id(&f.meta.id).unwrap();
        let error = tpl.check_id("wrong").unwrap_err().to_string();
        assert!(error.contains("id mismatch"));
        assert!(error.contains(&f.meta.id));
        f.replace("kernel", b"changed");
        Template::open(&f.paths, "").unwrap();
        assert!(tpl.verify(&f.paths, false).is_err());
        assert!(tpl.verify(&f.paths, true).is_err());
    }

    #[test]
    fn size_and_mtime_invalidate_cache() {
        let f = Fixture::new();
        let path = f.dir.join("kernel");
        let file = File::options().read(true).write(true).open(path).unwrap();
        let original = Stamp::of(&file.metadata().unwrap());
        file.set_len(original.size + 1).unwrap();
        assert_ne!(Stamp::of(&file.metadata().unwrap()).size, original.size);
        assert!(f.meta.verify(&f.paths, &f.dir, &mut BTreeMap::new(), false).is_err());
        file.set_len(original.size).unwrap();
        let times = [
            libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
            libc::timespec { tv_sec: original.mtime + 1, tv_nsec: original.mtime_nsec },
        ];
        assert_eq!(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) }, 0);
        assert_ne!(Stamp::of(&file.metadata().unwrap()).mtime, original.mtime);
        assert!(f.meta.verify(&f.paths, &f.dir, &mut BTreeMap::new(), false).is_err());
        f.meta.verify(&f.paths, &f.dir, &mut BTreeMap::new(), true).unwrap();
    }

    #[test]
    fn rehash_is_remembered_across_opens() {
        let f = Fixture::new();
        std::fs::write(f.dir.join("meta.json"), serde_json::to_vec(&f.meta).unwrap()).unwrap();
        f.replace("rootfs", b"rootfs");
        assert!(Template::open(&f.paths, "").unwrap().verify(&f.paths, false).is_err());
        Template::open(&f.paths, "").unwrap().verify(&f.paths, true).unwrap();
        Template::open(&f.paths, "").unwrap().verify(&f.paths, false).unwrap();
    }

    #[test]
    fn same_size_rewrite_with_restored_mtime_is_caught() {
        let f = Fixture::new();
        let mut cache = BTreeMap::new();
        f.meta.verify(&f.paths, &f.dir, &mut cache, true).unwrap();
        let file = File::options().write(true).open(f.dir.join("kernel")).unwrap();
        let before = Stamp::of(&file.metadata().unwrap());
        std::thread::sleep(Duration::from_millis(10));
        file.write_all_at(b"KERNEL", 0).unwrap();
        let times = [
            libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
            libc::timespec { tv_sec: before.mtime, tv_nsec: before.mtime_nsec },
        ];
        assert_eq!(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) }, 0);
        assert!(f.meta.verify(&f.paths, &f.dir, &mut cache, false).is_err());
        let error = f.meta.verify(&f.paths, &f.dir, &mut cache, true).unwrap_err().to_string();
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn old_templates_require_recreation() {
        let f = Fixture::new();
        let mut meta = f.meta.clone();
        meta.id.clear();
        meta.components.clear();
        assert!(meta.verify(&f.paths, &f.dir, &mut BTreeMap::new(), true).is_err());
    }
}
