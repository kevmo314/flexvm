//! Templates: a VM cold-booted once and snapshotted once its agent is up. Every VM is a
//! UFFD restore of one, so "boot" costs a snapshot load plus the pages the guest touches.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
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
    /// SHA-256 `digests` of its files and metadata, from its build or its receipt (None if built by v0.1.0):
    /// the content id is no check against a peer that made files to match it. Checkpoints record them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digests: Option<BTreeMap<String, String>>,
    /// Received from a peer (`receive`): used only for a source or checkpoint whose `digests` match.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub received: bool,
}

pub const FORMAT_VERSION: u64 = 2;

/// The root filesystem as a template's snapshot names it: a file in its Firecracker's directory,
/// linked to the generation's own at every load (`Firecracker::link_rootfs`), so it can be anywhere
/// (a pushed generation's is in its directory). Those built by v0.1.0 name theirs by its path.
pub const ROOTFS: &str = "rootfs";

/// What a build does that its inputs do not record: the boot command line, the memory and
/// device layout, flexvm's version. Not part of the content id (generations stay compatible).
pub fn recipe() -> String {
    let mut h = Hash::new();
    h.word(FORMAT_VERSION);
    for w in [SLOT_MIB, STEP_MIB, BALLOON_STATS_S as u64] {
        h.word(w);
    }
    h.update(BOOT_ARGS.as_bytes());
    h.update(ROOTFS.as_bytes());
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
    let mut hash = Hash::new();
    hash.word(file.metadata()?.len());
    nonzero_pages(file, |n, p| {
        hash.word(n);
        hash.update(p);
    })?;
    Ok(hash.finish())
}

/// `content_hash`'s page walk, but cryptographic: what a received generation is compared by.
fn digest(path: &Path) -> Result<String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Hashing::new(file.metadata()?.len());
    nonzero_pages(&file, |n, p| h.page(n, p))?;
    Ok(h.finish().1)
}

/// `content_hash` and `digest` together, of a file's pages as they come, in order (`receive_file`, as it writes
/// them, so a received file is not read again; #46): bytes at any offsets past the last, holes left zero.
struct Hashing {
    fnv: Hash,
    sha: sha2::Sha256,
    /// The page bytes are being written into, by index: hashed once one past it is written to, or at the end.
    page: Option<u64>,
    buf: Box<[u8; PAGE_SIZE]>,
}

impl Hashing {
    fn new(len: u64) -> Self {
        use sha2::Digest;
        let (mut fnv, mut sha) = (Hash::new(), sha2::Sha256::new());
        fnv.word(len);
        sha.update(len.to_le_bytes());
        Hashing { fnv, sha, page: None, buf: Box::new([0; PAGE_SIZE]) }
    }

    /// Whole page `n`, as `nonzero_pages` gives it.
    fn page(&mut self, n: u64, p: &[u8]) {
        Self::hash_page(&mut self.fnv, &mut self.sha, n, p);
    }

    fn hash_page(fnv: &mut Hash, sha: &mut sha2::Sha256, n: u64, p: &[u8]) {
        use sha2::Digest;
        if !zero(p) {
            fnv.word(n);
            fnv.update(p);
            sha.update(n.to_le_bytes());
            sha.update(p);
        }
    }

    /// `bytes` at `off`, at or past every offset written before.
    fn write(&mut self, mut off: u64, mut bytes: &[u8]) {
        let size = PAGE_SIZE as u64;
        while !bytes.is_empty() {
            let (n, at) = (off / size, (off % size) as usize);
            if self.page != Some(n) {
                self.flush();
                self.page = Some(n);
            }
            let take = (PAGE_SIZE - at).min(bytes.len());
            self.buf[at..at + take].copy_from_slice(&bytes[..take]);
            (off, bytes) = (off + take as u64, &bytes[take..]);
        }
    }

    fn flush(&mut self) {
        if let Some(n) = self.page.take() {
            Self::hash_page(&mut self.fnv, &mut self.sha, n, &self.buf[..]);
            self.buf.fill(0);
        }
    }

    /// `content_hash` and `digest`.
    fn finish(mut self) -> (String, String) {
        use sha2::Digest;
        self.flush();
        (self.fnv.finish(), format!("{:x}", self.sha.finalize()))
    }
}

/// Calls `f` with each page of `file` that is not all zero, by index, in order.
fn nonzero_pages(file: &File, mut f: impl FnMut(u64, &[u8])) -> Result<()> {
    let len = file.metadata()?.len();
    let page = PAGE_SIZE as u64;
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
                    f(off / page + i as u64, p);
                }
            }
            off += n as u64;
        }
    }
    Ok(())
}

/// The SHA-256 digests of a generation's files and of what its metadata says beyond its content id
/// (its host's CPU and Firecracker, sizes, image, recipe), which `Meta::digests` records.
fn digests(meta: &Meta, vmstate: &Path, mem: &Path, rootfs: &Path) -> Result<BTreeMap<String, String>> {
    digests_of(meta, [digest(vmstate)?, digest(mem)?, digest(rootfs)?])
}

/// `digests`, given its files' (vmstate, mem, rootfs).
fn digests_of(meta: &Meta, [vmstate, mem, rootfs]: [String; 3]) -> Result<BTreeMap<String, String>> {
    use sha2::Digest;
    let said =
        serde_json::to_vec(&(&meta.id, &meta.compatibility, [meta.vcpus as u64, meta.mem_mib, meta.max_mib, meta.plugged_mib], &meta.image, &meta.recipe))?;
    let mut out = BTreeMap::from([("meta".to_string(), format!("{:x}", sha2::Sha256::digest(said)))]);
    out.extend([("vmstate", vmstate), ("mem", mem), ("rootfs", rootfs)].map(|(n, d)| (n.to_string(), d)));
    Ok(out)
}

/// Whether `vmstate` names `rootfs` by its path, as generations built by v0.1.0 do (not `ROOTFS`).
fn names_by_path(vmstate: &[u8], rootfs: &Path) -> bool {
    let path = rootfs.as_os_str().as_encoded_bytes();
    !path.is_empty() && vmstate.windows(path.len()).any(|w| w == path)
}

pub(crate) fn hash_file(path: &Path) -> Result<Component> {
    let file = File::open(path).map_err(|e| format!("template component {}: {e}", path.display()))?;
    hash_open_file(&file, path)
}

fn hash_open_file(file: &File, path: &Path) -> Result<Component> {
    let metadata = Stamp::of(&file.metadata()?);
    let hash = content_hash(file)?;
    if Stamp::of(&file.metadata()?) != metadata {
        bail!("template component {} changed while hashing", path.display());
    }
    Ok(Component { hash, metadata })
}

/// `hash_file` and `digest` of `file` (at `path`), in one read.
fn hash_and_digest(file: &File, path: &Path) -> Result<(Component, String)> {
    let metadata = Stamp::of(&file.metadata()?);
    let mut h = Hashing::new(file.metadata()?.len());
    nonzero_pages(file, |n, p| h.page(n, p))?;
    if Stamp::of(&file.metadata()?) != metadata {
        bail!("template component {} changed while hashing", path.display());
    }
    let (hash, digest) = h.finish();
    Ok((Component { hash, metadata }, digest))
}

/// Reuse only a local generation's hashes for the exact same rootfs inode and stamp.
fn cached_rootfs(paths: &Paths, file: &File) -> Option<(Component, String)> {
    let stamp = Stamp::of(&file.metadata().ok()?);
    for id in generations(&paths.templates).ok()? {
        let Ok(meta) = Meta::read(&paths.templates.join(GENERATIONS).join(id)) else { continue };
        if meta.received || !meta.identified() {
            continue;
        }
        if let Some(component) = meta.components.get("rootfs").filter(|c| c.metadata == stamp) {
            if let Some(digest) = meta.digests.as_ref().and_then(|d| d.get("rootfs")) {
                return Some((component.clone(), digest.clone()));
            }
        }
    }
    None
}

/// The image cache's root filesystem `path` names, opened only if it is one: a regular file `KEY.ext4` right in
/// `paths.images`' `rootfs` directory, reached through no symlink. A peer names it (an older generation's vmstate,
/// `receive`), so nothing else is opened for reading, not a device, FIFO or watchdog an open alone acts on, nor any
/// file elsewhere whose content a hash comparison would reveal (#823): it is opened `O_PATH` and checked first.
fn open_cached_rootfs(paths: &Paths, path: &Path) -> Result<File> {
    let dir = std::fs::canonicalize(paths.images.join("rootfs")).map_err(|e| format!("this host's image cache: {e}"))?;
    let name = path
        .file_name()
        .filter(|n| path.parent() == Some(dir.as_path()) && Path::new(n).extension() == Some("ext4".as_ref()) && n.len() > 5)
        .ok_or("not a root filesystem of this host's image cache")?;
    open_regular_at(&dir, name)
}

/// The regular file `name` in `dir`, not through a symlink, opened for reading only once that is checked.
fn open_regular_at(dir: &Path, name: &std::ffi::OsStr) -> Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let dir = crate::util::openat(libc::AT_FDCWD, &crate::util::cpath(dir)?, libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| "NUL in its name")?;
    let fd = crate::util::openat(dir.as_raw_fd(), &name, libc::O_PATH | libc::O_NOFOLLOW)?;
    let st = crate::util::fstat(fd.as_raw_fd())?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        bail!("not a regular file");
    }
    // The inode just checked, opened for reading through its O_PATH descriptor.
    let file = File::open(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    let got = crate::util::fstat(file.as_raw_fd())?;
    if (got.st_dev, got.st_ino) != (st.st_dev, st.st_ino) {
        bail!("replaced as it was opened");
    }
    Ok(file)
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
            let hint = if pinned {
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

    /// Names every component, and its id is theirs and the image's.
    fn identified(&self) -> bool {
        let names = ["vmstate", "mem", "rootfs", "kernel", "firecracker"];
        self.components.len() == names.len()
            && names.iter().all(|n| self.components.contains_key(*n))
            && valid_id(&self.id)
            && content_id(&self.components, self.image.as_ref()) == self.id
    }

    #[cfg(test)]
    fn identify(&mut self, paths: &Paths, dir: &Path) -> Result<()> {
        self.identify_inputs(paths, dir, BTreeMap::new())
    }

    fn identify_inputs(&mut self, paths: &Paths, dir: &Path, inputs: BTreeMap<String, Component>) -> Result<()> {
        let mut digests = [String::new(), String::new(), String::new()];
        for (i, (name, path)) in self.files(paths, dir).into_iter().enumerate() {
            let component = if let Some(input) = inputs.get(name) {
                input.clone()
            } else if i < digests.len() {
                let file = File::open(&path).map_err(|e| format!("template component {}: {e}", path.display()))?;
                let (component, digest) = if name == "rootfs" {
                    cached_rootfs(paths, &file).map(Ok).unwrap_or_else(|| hash_and_digest(&file, &path))?
                } else {
                    hash_and_digest(&file, &path)?
                };
                digests[i] = digest;
                component
            } else {
                hash_file(&path)?
            };
            self.components.insert(name.into(), component);
        }
        self.id = content_id(&self.components, self.image.as_ref());
        self.digests = Some(digests_of(self, digests)?);
        Ok(())
    }

    /// Except for the build-only kernel, files whose stat matches `cache`, the creation
    /// stamp or one another process wrote back to `dir`'s meta.json since are trusted;
    /// others are rehashed. Returns whether anything was rehashed.
    fn verify(&self, paths: &Paths, dir: &Path, cache: &mut BTreeMap<String, Stamp>) -> Result<bool> {
        let files = self.files(paths, dir);
        if !self.identified() {
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
    pub images: PathBuf,
}

impl Paths {
    /// `STATE/artifacts` (as scripts/fetch.sh and build-*.sh install it; resolved, so templates
    /// record the files themselves) and `STATE/templates`.
    pub fn new(state: &Path) -> Self {
        let a = state.join("artifacts");
        let a = a.canonicalize().unwrap_or(a);
        Paths { firecracker: a.join("firecracker"), kernel: a.join("vmlinux"), templates: state.join("templates"), images: state.join("images") }
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
/// In an `in_use` set, this and then why: every generation stays (`Host::template_users`, while a
/// checkpoint record here cannot be read). Content ids are hex, so none starts so.
pub(crate) const KEEP_ALL: &str = "*";
/// `delete_unused`'s reason for a generation `KEEP_ALL` kept.
const KEPT_ALL: &str = "kept while ";

const MAX_LOAD_SET: usize = 512;
/// Template builds' guest commands, on a possibly loaded host.
const EXEC_TIMEOUT: Duration = Duration::from_secs(120);

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
pub(crate) fn valid_id(id: &str) -> bool {
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

    /// Opened again if a pull moved the name on and deleted what it linked to as it was opened.
    pub fn open(paths: &Paths, name: &str) -> Result<Arc<Template>> {
        let dir = Template::resolve(paths, name)?;
        Template::open_dir(name, dir.clone()).or_else(|e| match Template::resolve(paths, name)? {
            again if again != dir => Template::open_dir(name, again),
            _ => Err(e),
        })
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
        let fixed = crate::host::fd_path(handle.as_raw_fd());
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

    /// `digests` of this generation, as a source compares them with a target's received copy: recorded,
    /// or for one built by v0.1.0, computed.
    pub fn digests(&self) -> Result<BTreeMap<String, String>> {
        match &self.meta.digests {
            Some(d) => Ok(d.clone()),
            None => digests(&self.meta, &self.vmstate(), &self.fixed.join("mem"), &self.meta.rootfs),
        }
    }

    /// Refuses a received generation unless `vouched` (a source's or a checkpoint's digests) matches it.
    pub fn check_vouched(&self, vouched: Option<&BTreeMap<String, String>>, by: &str) -> Result<()> {
        if self.meta.received && vouched != self.meta.digests.as_ref() {
            bail!("template {} here was received from a peer, and {by} does not vouch for its files (SHA-256 digests)", self.meta.id);
        }
        Ok(())
    }

    /// Whether its snapshot names its root filesystem by its path (built by v0.1.0), which v0.1.0 needs.
    pub fn names_rootfs_by_path(&self) -> Result<bool> {
        Ok(names_by_path(&std::fs::read(self.vmstate())?, &self.meta.rootfs))
    }

    /// The only file a load of it may open as pmem: `ROOTFS`, or for one built by v0.1.0 its root
    /// filesystem's path, which for a received one `receive` found holding it here. Never one its
    /// vmstate (perhaps a peer's) chooses.
    pub fn pmem_path(&self) -> Result<PathBuf> {
        Ok(if self.names_rootfs_by_path()? { self.meta.rootfs.clone() } else { ROOTFS.into() })
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

    /// Starts page-cache reads of up to `n` pages from `page`, clamped to the whole pages mapped; best effort.
    pub fn willneed(&self, page: usize, n: usize) {
        let n = n.min((self.len / PAGE_SIZE).saturating_sub(page));
        if n > 0 {
            // Page aligned and within the mapping; an advisory failure changes nothing.
            unsafe { libc::madvise(self.map.add(page * PAGE_SIZE) as *mut libc::c_void, n * PAGE_SIZE, libc::MADV_WILLNEED) };
        }
    }

    /// Faults up to `n` pages from `page` in, clamped to the whole pages mapped, so a copy from them does not wait on
    /// disk; without MADV_POPULATE_READ (Linux < 5.14) a read-ahead hint instead. Best effort.
    pub fn prefault(&self, page: usize, n: usize) {
        let n = n.min((self.len / PAGE_SIZE).saturating_sub(page));
        if n > 0 {
            // Page aligned and within the mapping; failure leaves the copy to fault it in.
            let rc = unsafe { libc::madvise(self.map.add(page * PAGE_SIZE) as *mut libc::c_void, n * PAGE_SIZE, libc::MADV_POPULATE_READ) };
            if rc != 0 {
                self.willneed(page, n);
            }
        }
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
/// Firecracker leaves holes for the pages that hold no data (firecracker/0006), so this reads only
/// what the guest touched: tens of MiB of zeroes for an ubuntu:24.04 template, in tens of ms.
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
fn record_working_set(host: &crate::host::Host, paths: &Paths, dir: &Path, tap: &str, sockets: &Arc<SocketRoot>) -> Result<usize> {
    let tpl = Template::open_dir("(building)", dir.to_path_buf())?;
    let run = tpl.dir.join("record");
    // No working set exists yet: start with the minimum allowance and grow as needed.
    let mut admission = crate::limit::Building::admit(host, 0)?;
    let mut load = || -> Result<crate::vm::Prepared> {
        let _ = std::fs::remove_dir_all(&run);
        std::fs::create_dir_all(&run)?;
        let mut fc = Firecracker::spawn(&paths.firecracker, &run, sockets.allocate()?, crate::fc::SPAWN_READY)?;
        admission.start(&mut fc, tpl.meta.mem_mib + tpl.meta.plugged_mib)?;
        let p = crate::vm::Prepared::new(fc, tpl.clone())?;
        // Like VM restores: stepping the clock touches pages of its own. Loaded paused.
        p.firecracker().load_snapshot(&tpl.vmstate(), &tpl, tap, Some(true), crate::fc::API_TIMEOUT)?;
        p.pager.wait_ready(Duration::from_secs(5))?;
        // As for a restore: memory mapped behind the pager's back would be recorded from zeroes (#949).
        p.pager.check_foreign(Duration::from_secs(10))?;
        Ok(p)
    };
    let p = match load() {
        // Its memory was read while being mapped: a fresh Firecracker maps it again.
        Err(e) if e.to_string().starts_with(crate::uffd::FOREIGN) => {
            crate::log!("template: recording the working set: {e}; once more on a fresh firecracker");
            load()?
        }
        r => r?,
    };
    let fc = p.firecracker();
    fc.resume(crate::fc::API_TIMEOUT)?;
    retry(Duration::from_secs(10), Duration::from_millis(10), || guest::ping(&fc.sockets.vsock))?;
    guest::start(&fc.sockets.vsock, "10.255.255.254".parse()?, None)?;
    if tpl.meta.image.as_ref().is_some_and(|i| i.starts_at_run()) {
        guest::start_app(&fc.sockets.vsock, "")?;
    }
    // An exec records the session path's pages, so the first exec after a restore is fast;
    // an image with no shell can't run one, and an agent round trip stands in.
    if guest::exec(&fc.sockets.vsock, "true", EXEC_TIMEOUT).is_err() {
        guest::ping(&fc.sockets.vsock)?;
    }
    let lifted = admission.lift(fc.pid());
    fc.pause(crate::fc::API_TIMEOUT)?;
    let runs = pad_runs(p.pager.present_runs(), crate::uffd::FAULT_AROUND as u64);
    drop(lifted);
    drop(p);
    drop(admission);
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

/// So memory warm-up freed, which still holds its data, is discarded before the snapshot. Done: 4 s
/// quiet after `expect_mib` reported. Returns (MiB, done).
fn wait_reporting_done(fc: &Firecracker, metrics: &Path, expect_mib: u64) -> Result<(u64, bool)> {
    let (start, mut quiet, mut total) = (Instant::now(), 0, 0u64);
    let mut reader = BufReader::new(File::open(metrics)?);
    let mut line = String::new();
    // Reporting starts 2 s after memory is freed and works through it in rounds.
    while !(quiet >= 4 && total >> 20 >= expect_mib) && start.elapsed() < Duration::from_secs(120) {
        interrupted()?;
        std::thread::sleep(Duration::from_secs(1));
        fc.put("/actions", json!({"action_type": "FlushMetrics"}))?;
        let mut freed = 0;
        while reader.read_line(&mut line)? != 0 {
            // A flush may still be appending a record: retain its partial line.
            if !line.ends_with('\n') {
                break;
            }
            let m: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
            freed += m["balloon"]["free_page_report_freed"].as_u64().unwrap_or(0);
            line.clear();
        }
        total += freed;
        quiet = if freed == 0 { quiet + 1 } else { 0 };
    }
    Ok((total >> 20, quiet >= 4 && total >> 20 >= expect_mib))
}

/// A template build's tap: the host's tap prefix, `x` and the build's pid
/// in hex (a VM process's taps have a `t` after theirs), which garbage
/// collection sweeps once the build is proven gone (by its alias, `host::tap_alias`).
/// `net::create_free_tap` adds a hex suffix if this name is already taken.
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

/// Held shared while a build makes its staging directory, exclusive while one publishes or sweeps:
/// a staging directory without a lock, or a link, seen under it is dead.
pub(crate) fn templates_lock(paths: &Paths, how: i32) -> Result<crate::host::Flock> {
    Ok(crate::host::Flock::new(template_lock(paths, "templates", "")?, how)?)
}

/// Serialize the freshness check and publication for one normalized template name. Taken before
/// any other pull lock (image cache, blobs, `templates_lock`); a signal stops the wait.
pub fn pull_lock(paths: &Paths, name: &str) -> Result<crate::host::Flock> {
    check_name(name)?;
    std::fs::create_dir_all(&paths.templates)?;
    let file = template_lock(paths, "template-pull", &format!("-{name}"))?;
    crate::image::wait_lock(&file, libc::LOCK_EX, interrupted)?;
    // Held already through this open file: this only hands it to the guard.
    Ok(crate::host::Flock::new(file, libc::LOCK_EX)?)
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
    sweep_locked(paths)
}

/// `sweep`, if there is a templates directory: what a killed build or receive left, at once (a listener's start).
pub fn sweep_leftovers(paths: &Paths) -> Result<()> {
    if !paths.templates.is_dir() {
        return Ok(());
    }
    let parent = crate::host::Directory::open(&paths.templates)?;
    sweep(&Paths { templates: parent.path.clone(), ..paths.clone() })
}

fn sweep_locked(paths: &Paths) -> Result<()> {
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
                crate::socket::remove_left(&key);
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
        // Like a build's leftovers: one it cannot finish must not stop every build after it.
        if entry.file_type()?.is_dir() && tombstone {
            if let Err(e) = finish_remove(paths, &entry.path()) {
                crate::log!("template: removing {}, left by an rmi that did not finish: {e}", entry.path().display());
            }
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
    up_to_date_with(paths, name, size, rootfs, image, || crate::compat::local_binary(&paths.firecracker))
}

fn up_to_date_with(
    paths: &Paths,
    name: &str,
    size: Size,
    rootfs: &Path,
    image: &ImageMeta,
    host: impl FnOnce() -> Result<crate::compat::Compat>,
) -> Option<String> {
    let tpl = Template::open(paths, name).ok()?;
    let meta = &tpl.meta;
    if meta.received || meta.compatibility.check(&host().ok()?).is_err() {
        return None;
    }
    let same_image = meta.image.as_ref().is_some_and(|i| {
        (&i.digest, &i.config_digest, &i.app_conf, &i.argv, i.warm) == (&image.digest, &image.config_digest, &image.app_conf, &image.argv, image.warm)
            && serde_json::to_value(&i.ready).ok() == serde_json::to_value(&image.ready).ok()
    });
    let sizes = (meta.vcpus, meta.mem_mib, meta.max_mib, meta.plugged_mib) == (size.vcpus, size.mem_mib, size.mem_mib + size.hotplug_mib(), size.plugged_mib());
    if !same_image || !sizes || meta.recipe != recipe() || std::fs::canonicalize(rootfs).ok()? != meta.rootfs {
        return None;
    }
    let kernel = std::fs::canonicalize(&paths.kernel).ok()?;
    let saved_kernel = meta.components.get("kernel")?;
    if saved_kernel.metadata != Stamp::of(&std::fs::metadata(&kernel).ok()?) && saved_kernel.hash != hash_file(&kernel).ok()?.hash {
        return None;
    }
    // Firecracker, the root filesystem and the snapshot files (rehashed if their stat changed).
    tpl.verify(paths).ok()?;
    crate::image::note_rootfs(&paths.images, &meta.rootfs, &std::fs::canonicalize(&paths.templates).ok()?).ok()?;
    Some(meta.id.clone())
}

/// In a templates directory another state links to: VMs this host does not know of (a suspended
/// one there holds no lock) may use its generations, so pulls leave those they supersede to `image prune`,
/// which reads the records of the states `STATES` lists (`shared_users`).
const SHARED: &str = ".shared";
/// `SHARED`'s contents once every state that uses the directory is recorded in `STATES` before it
/// is marked. flexvm before #869 left it empty: states may link to it unrecorded.
const RECORDED: &[u8] = b"states\n";
/// In a shared templates directory, one file per state that uses it (`note_shared`): named by a
/// hash of the state's canonical path, which it holds.
const STATES: &str = ".states";

pub(crate) fn state_key(state: &Path) -> String {
    use sha2::Digest;
    use std::os::unix::ffi::OsStrExt;
    format!("{:x}", sha2::Sha256::digest(state.as_os_str().as_bytes()))[..32].to_string()
}

/// The state a templates directory is `STATE/templates` of (its canonical path), if it looks like one
/// (`Host::open` made `.synced` there): one that links to it records itself, and this one too.
fn owner_state(templates: &Path) -> Option<PathBuf> {
    let parent = templates.parent().filter(|_| templates.file_name() == Some("templates".as_ref()))?;
    parent.join(".synced").is_file().then(|| parent.to_path_buf())
}

/// Marks the templates directory `STATE/templates` links to as shared (`Host::open`), under the
/// templates lock: a pull's `prune` decides under it exclusively. Each state that uses a shared one
/// (linked to it, or the state it belongs to) is recorded in it first (`STATES`), so `image prune`
/// can read their VMs' records and checkpoints.
pub fn note_shared(paths: &Paths, state: &Path) -> std::io::Result<()> {
    let linked = paths.templates.is_symlink();
    if !paths.templates.is_dir() || !(linked || paths.templates.join(SHARED).exists()) {
        return Ok(());
    }
    let dir = std::fs::canonicalize(&paths.templates)?;
    let users: BTreeSet<PathBuf> = [Some(std::fs::canonicalize(state)?), owner_state(&dir)].into_iter().flatten().collect();
    let states = dir.join(STATES);
    let missing: Vec<&PathBuf> =
        users.iter().filter(|s| std::fs::read(states.join(state_key(s))).ok().as_deref() != Some(s.as_os_str().as_encoded_bytes())).collect();
    if missing.is_empty() && dir.join(SHARED).exists() {
        return Ok(());
    }
    let _l = crate::host::Flock::new(template_lock(paths, "templates", "")?, libc::LOCK_SH)?;
    crate::util::create_dir_durably(&states, 0o755)?;
    for s in missing {
        crate::util::write_file(&states, &state_key(s), s.as_os_str().as_encoded_bytes(), true)?;
    }
    if !dir.join(SHARED).exists() {
        crate::util::write_file(&dir, SHARED, RECORDED, true)?;
    }
    Ok(())
}

/// What the other states that use a shared templates directory use of it (pinned, under its lock held
/// exclusively): the content ids their suspended VMs and stored checkpoints name (`host::recorded_template_users`;
/// their running VMs hold a generation's use lock, on this host whichever state they are of). A `KEEP_ALL` entry
/// while one is recorded but cannot be read or is gone (moved, or on a filesystem not mounted now), or the
/// directory was marked shared before states were recorded (`RECORDED`), unless `force` (`--force-shared`):
/// then the record is taken as right, gone states are forgotten and the marker is brought up to date. A
/// recorded state whose `templates` is another directory now uses none (its record stays). Without
/// `checkpoints`, only the record is read: none of the states' VMs or checkpoints.
fn shared_users(paths: &Paths, force: bool, checkpoints: bool) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let keep = |ids: &mut BTreeSet<String>, why: String| {
        ids.insert(format!("{KEEP_ALL}{why}"));
    };
    match std::fs::read(paths.templates.join(SHARED)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ids,
        Err(e) => keep(&mut ids, format!("{} cannot be read ({e})", paths.templates.join(SHARED).display())),
        Ok(m) if m == RECORDED => {}
        Ok(_) if force => {
            if let Err(e) = crate::util::write_file(&paths.templates, SHARED, RECORDED, true) {
                keep(&mut ids, format!("{} cannot be updated ({e})", paths.templates.join(SHARED).display()));
            }
        }
        Ok(_) => keep(
            &mut ids,
            "other states have linked to these templates since before flexvm recorded which (once each has run a flexvm command, image prune --force-shared trusts the record)"
                .into(),
        ),
    }
    let here = match std::fs::metadata(&paths.templates) {
        Ok(m) => (m.dev(), m.ino()),
        Err(e) => {
            keep(&mut ids, format!("{} cannot be read ({e})", paths.templates.display()));
            return ids;
        }
    };
    let states = paths.templates.join(STATES);
    let entries = match std::fs::read_dir(&states) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ids,
        Err(e) => {
            keep(&mut ids, format!("the states linked to these templates cannot be listed ({}: {e})", states.display()));
            return ids;
        }
        Ok(entries) => entries,
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                keep(&mut ids, format!("the states linked to these templates cannot be listed ({}: {e})", states.display()));
                continue;
            }
        };
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            continue;
        }
        let state = match std::fs::read(entry.path()) {
            Ok(b) => PathBuf::from(<std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(b)),
            Err(e) => {
                keep(&mut ids, format!("a state linked to these templates cannot be read ({}: {e})", entry.path().display()));
                continue;
            }
        };
        match std::fs::metadata(&state).and_then(|_| std::fs::metadata(state.join("templates"))) {
            // Gone: removed, or moved (its records with it) or not mounted now. Only `force` forgets it.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound && std::fs::symlink_metadata(&state).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                if force {
                    crate::log!("flexvm: {} is gone: its record as a user of these templates goes", state.display());
                    if let Err(e) = std::fs::remove_file(entry.path()).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) }) {
                        keep(&mut ids, format!("{} cannot be removed ({e})", entry.path().display()));
                    }
                } else {
                    keep(
                        &mut ids,
                        format!("{}, recorded as using these templates, is gone (if it was removed, image prune --force-shared forgets it)", state.display()),
                    );
                }
            }
            // Its templates are elsewhere now (or none): it uses none of these, while that lasts.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(m) if (m.dev(), m.ino()) != here => {}
            Err(e) => keep(&mut ids, format!("{}, linked to these templates, cannot be read ({e})", state.display())),
            Ok(_) if checkpoints => ids.extend(crate::host::recorded_template_users(&state, &format!("in {}", state.display()))),
            Ok(_) => {}
        }
    }
    ids
}

/// Builds `name` from an image's root filesystem and publishes it as a new generation; returns
/// the generation the name linked to before, for the caller to delete if nothing uses it.
pub fn create(host: &crate::host::Host, paths: &Paths, name: &str, size: Size, rootfs: &Path, image: ImageMeta, tap: &str) -> Result<Option<String>> {
    // The caller owns `tap` through image preparation and the build.
    // Running VMs map the old files, which must not be rewritten under them.
    let staging = Staging::new(paths, name)?;
    build(host, paths, &staging.dir, name, size, rootfs, tap, image).map_err(|e| format!("template {name:?}: {e}"))?;
    interrupted()?;
    let paths = &Paths { templates: staging.parent.path.clone(), ..paths.clone() };
    publish(paths, name, &staging.dir, interrupted)
}

/// Returns the generation the name linked to before, if another. Nothing is deleted here: VMs
/// refer to generations by content id, so the pull deletes it (`prune` of only that one) once no
/// name links to it and nothing here uses it (`Host::template_users`). Checkpoints in other
/// directories than flexvm's own (`checkpoint::managed`) are not known: theirs may go.
fn publish(paths: &Paths, name: &str, staged: &Path, check_interrupt: impl FnOnce() -> Result<()>) -> Result<Option<String>> {
    // Every name below is in the directories as opened here, whatever their paths name meanwhile.
    let parent = crate::host::Directory::open(&paths.templates)?;
    let paths = &Paths { templates: parent.path.clone(), ..paths.clone() };
    // Exclusive: two pulls of a name each see the link the other replaced (the one each supersedes).
    let (id, _l) = publish_generation(paths, staged, libc::LOCK_EX, check_interrupt)?;
    let live = paths.templates.join(name);
    let tmp = paths.templates.join(format!(".{name}.link-{}", crate::util::random_hex(8)?));
    std::os::unix::fs::symlink(Path::new(GENERATIONS).join(&id), &tmp)?;
    let old = std::fs::read_link(&live).ok().and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned())).filter(|old| *old != id);
    std::fs::rename(&tmp, &live)?;
    crate::util::sync_dir(&paths.templates)?;
    Ok(old)
}

/// Publishes the staged build in `paths.templates` (as the caller opened it) as `.gen/ID`, an identical
/// one published already kept, and returns ID with the templates lock (taken `how`) still held:
/// nothing removes the unnamed generation before the caller names it or opens it.
fn publish_generation(paths: &Paths, staged: &Path, how: i32, check_interrupt: impl FnOnce() -> Result<()>) -> Result<(String, crate::host::Flock)> {
    let staged = &paths.templates.join(staged.file_name().ok_or("staging has no name")?);
    let meta = Meta::read(staged)?;
    match std::fs::create_dir(paths.templates.join(GENERATIONS)) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        r => r?,
    }
    crate::util::sync_dir(&paths.templates)?;
    let gens = crate::host::Directory::open(&paths.templates.join(GENERATIONS))?;
    // Its files and their names are durable before the generation is published.
    for entry in std::fs::read_dir(staged)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            File::open(entry.path())?.sync_all()?;
        }
    }
    let l = templates_lock(paths, how)?;
    crate::util::sync_dir(staged)?;
    check_interrupt()?;
    crate::image::note_rootfs(&paths.images, &meta.rootfs, &std::fs::canonicalize(&paths.templates)?)?;
    match std::fs::rename(staged, gens.path.join(&meta.id)) {
        // An identical build published it already.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {}
        r => r?,
    }
    crate::util::sync_dir(&gens.path)?;
    Ok((meta.id, l))
}

/// What `send` and `receive` refuse: far past any template.
const MAX_META: u64 = 1 << 20;
const MAX_VMSTATE: u64 = 64 << 20;
const MAX_FILE: u64 = 1 << 44;
const MAX_EXTENTS: u64 = 1 << 20;
/// A received template's guest memory at most (its bitmap, 64 MiB, is allocated at open).
pub const MAX_MEM_MIB: u64 = 2 << 20;
/// The data bytes of one generation's files together.
pub const MAX_DATA: u64 = 64 << 30;
/// Room a received generation leaves on its filesystem.
const KEEP_FREE: u64 = 1 << 30;
/// Pushes leave another GiB for local checkpoints and suspends (checkpoint imports keep `KEEP_FREE`).
const PUSH_FREE: u64 = KEEP_FREE + (1 << 30);
/// Where a pushed generation (and its staging) records the peer that pushed it, as this host saw it.
const PUSH_PEER: &str = "push-peer";
/// A received generation younger than this is not reclaimed under pressure: its arrival may not hold it yet
/// (or no longer, past `MAX_HELD`) before it opens it.
const RECLAIM_AFTER: Duration = Duration::from_secs(300);
/// Made once as a generation is received: its mtime is when (the directory's is when it was last used, `collect`).
const RECEIVED_AT: &str = "received-at";

/// Whether the generation in `dir` was received within `RECLAIM_AFTER` (one from before `RECEIVED_AT` is not).
fn fresh(dir: &Path) -> bool {
    std::fs::metadata(dir.join(RECEIVED_AT)).ok().and_then(|m| m.modified().ok()).is_some_and(|t| t.elapsed().unwrap_or_default() < RECLAIM_AFTER)
}

/// The budget of spare received generations on a filesystem of `size` bytes, in all and per peer: an eighth
/// of it, 4 to 128 GiB, and a quarter of that.
fn received_budget(size: u64) -> (u64, u64) {
    let total = (size / 8).clamp(4 << 30, 128 << 30);
    (total, total / 4)
}

/// A peer's push (`listen`): admitted only within the room `PUSH_FREE` leaves and the budget of spare received
/// generations (`received_budget`), reclaiming the oldest spares first, within their idle grace too.
pub struct Push<'a> {
    pub peer: std::net::IpAddr,
    /// What its source says it sends (`Sending::len`), checked before its data.
    pub bytes: Option<u64>,
    pub in_use: &'a dyn Fn() -> BTreeSet<String>,
    /// The generations the listener holds for arrivals (open, yet charged).
    pub held: &'a dyn Fn() -> BTreeSet<String>,
}

impl Push<'_> {
    pub fn receive<R: Read>(&self, paths: &Paths, r: &mut R, id: &str, ready: impl FnOnce(&Meta) -> Result<()>) -> Result<Arc<Template>> {
        receive_inner(paths, r, id, None, Some(self), ready, |_| Ok(()))
    }

    /// Admits `bytes` more of the push staged in `own` (None before it is), under the room lock (the caller's)
    /// and the templates lock, returned: held through allocation, so concurrent pushes are charged each other's.
    fn check(&self, paths: &Paths, bytes: u64, own: Option<&Path>) -> Result<crate::host::Flock> {
        if bytes > MAX_DATA + MAX_VMSTATE + MAX_META {
            bail!("{} MiB is past the {} MiB a template may be", bytes >> 20, MAX_DATA >> 20);
        }
        let lock = templates_lock(paths, libc::LOCK_EX)?;
        if self.room(paths, bytes, own).is_ok() {
            return Ok(lock);
        }
        // What killed receives left, then the spares, oldest first: pressure overrides their idle grace,
        // never a name, a use, a record or an arrival's `RECLAIM_AFTER`.
        sweep_locked(paths)?;
        let mut spares = vec![];
        for id in generations(&paths.templates)? {
            let dir = paths.templates.join(GENERATIONS).join(&id);
            let Ok(m) = std::fs::metadata(&dir) else { continue };
            if Meta::read(&dir).is_ok_and(|m| m.received) && !fresh(&dir) {
                spares.push((m.mtime(), id));
            }
        }
        spares.sort();
        for (_, id) in spares {
            if delete_unused(paths, &id, self.in_use)?.is_ok() {
                crate::log!("template: removed received generation {id} for a push from {}", self.peer);
                if self.room(paths, bytes, own).is_ok() {
                    return Ok(lock);
                }
            }
        }
        self.room(paths, bytes, own)?;
        Ok(lock)
    }

    fn room(&self, paths: &Paths, bytes: u64, own: Option<&Path>) -> Result<()> {
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        crate::util::check(unsafe { libc::statvfs(crate::util::cpath(&paths.templates)?.as_ptr(), &mut st) })?;
        let (total, peer) = received_budget(st.f_blocks.saturating_mul(st.f_frsize));
        let (others, ours, mine) = self.usage(paths, own)?;
        check_budget(others, ours, mine.saturating_add(bytes), total, peer)?;
        check_free(st.f_bavail.saturating_mul(st.f_frsize), bytes, PUSH_FREE)
    }

    /// The blocks spares take (unnamed received generations nothing here or in the states sharing the templates
    /// uses, held for arrivals, received within `RECLAIM_AFTER` or open in no VM process) and other pushes' staging: in all, of this peer's (those
    /// a peer pushed, as `PUSH_PEER` records), and of `own`.
    fn usage(&self, paths: &Paths, own: Option<&Path>) -> Result<(u64, u64, u64)> {
        let named: BTreeSet<String> = names(&paths.templates)?.into_iter().map(|(_, id)| id).collect();
        let (users, held, locks) = (users(paths, self.in_use, false), (self.held)(), crate::host::host_locks()?);
        let mut dirs = vec![];
        for id in generations(&paths.templates)? {
            let dir = paths.templates.join(GENERATIONS).join(&id);
            if named.contains(&id) || users.contains(&id) || !Meta::read(&dir).is_ok_and(|m| m.received) {
                continue;
            }
            let Ok(handle) = File::open(&dir) else { continue };
            let st = crate::util::fstat(handle.as_raw_fd())?;
            // Open but fresh: published, its arrival hold not yet taken (or past `MAX_HELD`).
            if held.contains(&id) || fresh(&dir) || crate::host::try_lock_at(locks.try_clone()?, &crate::host::use_lock(&st))?.is_some() {
                dirs.push(dir);
            }
        }
        for entry in std::fs::read_dir(&paths.templates)? {
            let entry = entry?;
            if entry.file_name().to_str().is_some_and(|n| leftover(n, "new")) && entry.path().join(PUSH_PEER).is_file() {
                dirs.push(entry.path());
            }
        }
        let (mut others, mut ours, mut mine) = (0u64, 0u64, 0u64);
        for dir in dirs {
            let size = allocated(&dir)?;
            if own.is_some_and(|o| o.file_name() == dir.file_name()) {
                mine = mine.saturating_add(size);
                continue;
            }
            others = others.saturating_add(size);
            // Only a total for those no peer pushed (a checkpoint's import, or from before `PUSH_PEER`).
            let owner = std::fs::read_to_string(dir.join(PUSH_PEER)).ok().and_then(|p| p.trim().parse::<std::net::IpAddr>().ok());
            if owner.is_some_and(|p| p.to_canonical() == self.peer.to_canonical()) {
                ours = ours.saturating_add(size);
            }
        }
        Ok((others, ours, mine))
    }
}

/// The blocks allocated to the files in `dir` (holes take none), 0 once it is gone.
fn allocated(dir: &Path) -> Result<u64> {
    let entries = match std::fs::read_dir(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        r => r?,
    };
    let mut size = 0u64;
    for entry in entries {
        match entry?.metadata() {
            Ok(m) => size = size.saturating_add(m.blocks().saturating_mul(512)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(size)
}

/// A push of `need` bytes, given the spares `others` of which `ours` its peer's, within `total` and `peer`
/// budgets. One alone (nothing else charged) may be larger: the room it leaves bounds it.
fn check_budget(others: u64, ours: u64, need: u64, total: u64, peer: u64) -> Result<()> {
    if others > 0 && others.saturating_add(need) > total {
        bail!("no room for its {} MiB: received templates not in use take {} MiB of the {} MiB they may", need >> 20, others >> 20, total >> 20);
    }
    if ours > 0 && ours.saturating_add(need) > peer {
        bail!("no room for its {} MiB: templates this peer sent take {} MiB of the {} MiB one peer's may", need >> 20, ours >> 20, peer >> 20);
    }
    Ok(())
}

/// Generation `tpl` as `receive` reads it, its files open and their extents read: `len` is known
/// before anything is written (a tar member's size, `checkpoint save`).
pub struct Sending {
    meta: Vec<u8>,
    /// Each file, its length and its data extents.
    files: Vec<(File, u64, Extents)>,
}

type Extents = Vec<(u64, u64)>;

impl Sending {
    pub fn new(tpl: &Template) -> Result<Sending> {
        let meta = serde_json::to_vec(&tpl.meta)?;
        let mut files = vec![];
        for path in [tpl.vmstate(), tpl.meta.rootfs.clone(), tpl.fixed.join("mem")] {
            let file = File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let len = file.metadata()?.len();
            let extents = data_extents(&file, len)?;
            files.push((file, len, extents));
        }
        Ok(Sending { meta, files })
    }

    /// The bytes `write` writes.
    pub fn len(&self) -> u64 {
        let files: u64 = self.files.iter().map(|(_, _, x)| 16 + x.iter().map(|(s, e)| 16 + e - s).sum::<u64>()).sum();
        8 + self.meta.len() as u64 + files
    }

    /// Its metadata, then its vmstate, root filesystem and memory, each as its length, its data
    /// extents and their bytes, so holes stay holes. Returns the data bytes.
    pub fn write(self, w: &mut impl Write) -> Result<u64> {
        self.write_meta(w)?;
        self.write_files(w)
    }

    /// What `write` writes first: the metadata, which `receive` checks before it reads on (its `ready`).
    pub fn write_meta(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(&(self.meta.len() as u64).to_le_bytes())?;
        w.write_all(&self.meta)?;
        Ok(w.flush()?)
    }

    /// The rest of `write`, after `write_meta`. Returns the data bytes.
    pub fn write_files(self, w: &mut impl Write) -> Result<u64> {
        let (mut sent, mut buf) = (0, vec![0u8; 1 << 20]);
        for (file, len, extents) in self.files {
            let head = [len, extents.len() as u64].into_iter().chain(extents.iter().flat_map(|&(s, e)| [s, e]));
            w.write_all(&head.flat_map(u64::to_le_bytes).collect::<Vec<u8>>())?;
            for (mut off, end) in extents {
                sent += end - off;
                while off < end {
                    let n = (end - off).min(buf.len() as u64) as usize;
                    file.read_exact_at(&mut buf[..n], off)?;
                    w.write_all(&buf[..n])?;
                    off += n as u64;
                }
            }
        }
        w.flush()?;
        Ok(sent)
    }
}

/// Writes generation `tpl` for `receive` (`Sending::write`). Returns the data bytes.
#[cfg(test)]
pub fn send(tpl: &Template, w: &mut impl Write) -> Result<u64> {
    Sending::new(tpl)?.write(w)
}

/// Whose turn it is to obtain generation `id` here (`receive`), waited for until `by`: a second
/// push of one template finds the first's generation instead of sending it again.
pub fn turn(paths: &Paths, id: &str, by: Instant) -> Result<crate::host::HeldLock> {
    if !valid_id(id) {
        bail!("bad template id {id:?}");
    }
    // A host that never pulled anything has none yet.
    crate::util::create_dir_durably(&paths.templates, 0o777)?;
    let name = template_lock_name(paths, "template-in", &format!("-{id}"))?;
    let take = |f: &File| loop {
        match crate::host::flock(f, libc::LOCK_EX | libc::LOCK_NB) {
            Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) && Instant::now() < by => std::thread::sleep(Duration::from_millis(50)),
            r => return r,
        }
    };
    Ok(crate::host::lock_at_with(crate::host::host_locks()?, &name, take).map_err(|e| format!("waiting for another arrival of template {id}: {e}"))?)
}

/// Reads a generation `send` wrote and publishes it unnamed (no name here is taken or moved), once its
/// content id is `id` and each file it got hashes to its component: it is never named or found by
/// tag. Returns it open, so held: no `rmi`, prune or sweep removes it while it is. A failure leaves no
/// generation: its staging goes, or, killed, the next build's or receive's sweep (or the listener's, `collect`).
/// `ready` (given its metadata, checked) is called before any file is read: what it fails is refused before
/// the source sends its data (`listen::push`). With `vouched` (a checkpoint's `template_digests`), one whose
/// digests differ is refused before it is published, as is one that `finish` (given the reader, once all of
/// it is read: what follows it) fails.
pub fn receive<R: Read>(
    paths: &Paths,
    r: &mut R,
    id: &str,
    vouched: Option<&BTreeMap<String, String>>,
    ready: impl FnOnce(&Meta) -> Result<()>,
    finish: impl FnOnce(&mut R) -> Result<()>,
) -> Result<Arc<Template>> {
    receive_inner(paths, r, id, vouched, None, ready, finish)
}

fn receive_inner<R: Read>(
    paths: &Paths,
    r: &mut R,
    id: &str,
    vouched: Option<&BTreeMap<String, String>>,
    push: Option<&Push<'_>>,
    ready: impl FnOnce(&Meta) -> Result<()>,
    finish: impl FnOnce(&mut R) -> Result<()>,
) -> Result<Arc<Template>> {
    let [len] = read_words(r)?;
    if len > MAX_META {
        bail!("template {id}: {len} bytes of metadata");
    }
    let mut bytes = vec![0u8; len as usize];
    r.read_exact(&mut bytes)?;
    let mut meta: Meta = serde_json::from_slice(&bytes).map_err(|e| format!("template {id}: its metadata: {e}"))?;
    if meta.id != id || !meta.identified() || !meta.rootfs.is_absolute() || meta.max_mib > MAX_MEM_MIB {
        bail!("template {id}: the metadata sent is not that template's, or past the limits");
    }
    // The kernel is in guest memory; restores never read it (`Meta::verify`).
    crate::artifacts::ensure(&[(&paths.firecracker, &crate::artifacts::FIRECRACKER)])?;
    let firecracker = hash_file(&paths.firecracker)?;
    if firecracker.hash != meta.components["firecracker"].hash {
        bail!("template {id} was built with another Firecracker than {}: copy one Firecracker binary to every host", paths.firecracker.display());
    }
    if let Some(push) = push {
        crate::util::create_dir_durably(&paths.templates, 0o777)?;
        let parent = crate::host::Directory::open(&paths.templates)?;
        let _room = crate::host::lock_at(crate::host::host_locks()?, ROOM_LOCK, libc::LOCK_EX)?;
        let _templates = push.check(&Paths { templates: parent.path.clone(), ..paths.clone() }, push.bytes.unwrap_or(0), None)?;
    }
    ready(&meta)?;
    let staging = Staging::new(paths, id)?;
    let paths = &Paths { templates: staging.parent.path.clone(), ..paths.clone() };
    if let Some(push) = push {
        std::fs::write(staging.dir.join(PUSH_PEER), push.peer.to_canonical().to_string())?;
    }
    let gen = std::fs::canonicalize(&staging.parent.path)?.join(GENERATIONS).join(id);
    let mut budget = MAX_DATA;
    let mut file = |r: &mut _, name: &str, len| {
        receive_file(r, &staging.dir.join(name), len, &mut budget, push.map(|p| (paths, p))).map_err(|e| format!("template {id}: its {name}: {e}"))
    };
    let vmstate = file(r, "vmstate", 0..=MAX_VMSTATE)?;
    // Older generations name the root filesystem by its path (not `ROOTFS`), which must hold it here too: only
    // a file of this host's image cache (`open_cached_rootfs`). Its use lock held through publication, as a pull
    // holds it (`image::Cached::reserved`): no `rmi` removes it meanwhile.
    let local = match names_by_path(&std::fs::read(staging.dir.join("vmstate"))?, &meta.rootfs) {
        false => None,
        true => Some(
            (|| -> Result<_> {
                let have = open_cached_rootfs(paths, &meta.rootfs)?;
                let st = crate::util::fstat(have.as_raw_fd())?;
                let held = crate::host::shared_at(&crate::host::host_locks()?, &crate::host::use_lock(&st))?;
                // Still what its path names, now that no `rmi` removes it: one unlinked before the lock was taken is not.
                let now = crate::util::fstat(open_cached_rootfs(paths, &meta.rootfs)?.as_raw_fd())?;
                if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino) {
                    bail!("replaced as it was opened");
                }
                Ok((have, held))
            })()
            .map_err(|e| format!("template {id} names its root filesystem by its path {}, which does not hold it here ({e})", meta.rootfs.display()))?,
        ),
    };
    let sent_rootfs = file(r, "rootfs", 0..=MAX_FILE)?;
    // Test gate: half received, for a test to kill the receiver.
    crate::host::hold("receive_hold");
    // As long as its guest memory, which opening it maps a bitmap of.
    let mem = file(r, "mem", meta.max_mib << 20..=meta.max_mib << 20)?;
    let staged = |n: &str| staging.dir.join(n);
    let (rootfs, rootfs_use) = match local {
        Some((have, held)) => {
            // Read the stream before hashing the cached copy: a slow disk must not stall the paced sender.
            let (c, sha) = hash_and_digest(&have, &meta.rootfs).map_err(|e| format!("template {id}: its root filesystem {}: {e}", meta.rootfs.display()))?;
            if c.hash != meta.components["rootfs"].hash {
                bail!("template {id} names its root filesystem by its path {}, which does not hold it here", meta.rootfs.display());
            }
            std::fs::remove_file(staged("rootfs"))?;
            ((c, sha), Some(held))
        }
        None => (sent_rootfs, None),
    };
    (meta.digests, meta.received) = (Some(digests_of(&meta, [vmstate.1.clone(), mem.1.clone(), rootfs.1.clone()])?), true);
    if vouched.is_some_and(|v| Some(v) != meta.digests.as_ref()) {
        bail!("template {id}: its files do not match the SHA-256 digests the checkpoint records");
    }
    if rootfs_use.is_none() {
        meta.rootfs = gen.join("rootfs");
    }
    let got = [("vmstate", vmstate.0), ("mem", mem.0), ("rootfs", rootfs.0), ("firecracker", firecracker)];
    for (name, c) in got {
        if c.hash != meta.components[name].hash {
            bail!("template {id}: its {name} does not hash to the template's");
        }
        meta.components.insert(name.into(), c);
    }
    meta.kernel = paths.kernel.clone();
    std::fs::write(staging.dir.join("meta.json"), serde_json::to_vec_pretty(&meta)?)?;
    finish(r)?;
    // Stamped once all of it is in, however long it took: fresh from its publication on.
    File::create(staging.dir.join(RECEIVED_AT))?;
    let (_, _l) = publish_generation(paths, &staging.dir, libc::LOCK_SH, || Ok(()))?;
    let tpl = Template::open_dir(id, paths.templates.join(GENERATIONS).join(id))?;
    tpl.verify(paths)?;
    Ok(tpl)
}

fn check_free(free: u64, bytes: u64, keep_free: u64) -> Result<()> {
    if free < bytes.saturating_add(keep_free) {
        bail!("no room for its {} MiB: it would leave less than {} MiB free", bytes >> 20, keep_free >> 20);
    }
    Ok(())
}

fn read_words<const N: usize>(r: &mut impl Read) -> Result<[u64; N]> {
    let (mut out, mut b) = ([0; N], [0u8; 8]);
    for w in &mut out {
        r.read_exact(&mut b)?;
        *w = u64::from_le_bytes(b);
    }
    Ok(out)
}

/// The host-wide lock taken while a receive (or `checkpoint load`) checks its filesystem's room and
/// allocates a file's blocks, so the next one's check, in whichever process, sees them gone.
pub(crate) const ROOM_LOCK: &str = "receive-room";

/// One of `send`'s files, written to a new `path` with the same length (one of `lens`) and holes, within
/// what is left of the generation's `budget` (`MAX_DATA`) and of its filesystem's room, by blocks. Returns
/// its component (hash and stamp) and digest, hashed as it is written (`Hashing`).
fn receive_file(
    r: &mut impl Read,
    path: &Path,
    lens: std::ops::RangeInclusive<u64>,
    budget: &mut u64,
    push: Option<(&Paths, &Push<'_>)>,
) -> Result<(Component, String)> {
    let [len, n] = read_words(r)?;
    if !lens.contains(&len) || n > MAX_EXTENTS {
        bail!("{len} bytes in {n} extents is past the limits");
    }
    let extents: Vec<(u64, u64)> = (0..n).map(|_| read_words(r).map(|[s, e]| (s, e))).collect::<Result<_>>()?;
    if !valid_extents(&extents, len) {
        bail!("bad extents");
    }
    let file = File::options().write(true).create_new(true).open(path)?;
    file.set_len(len)?;
    let admit = crate::host::lock_at(crate::host::host_locks()?, ROOM_LOCK, libc::LOCK_EX)?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    crate::util::check(unsafe { libc::fstatvfs(file.as_raw_fd(), &mut st) })?;
    let block = st.f_frsize.max(PAGE_SIZE as u64);
    let blocks: u64 = extents.iter().map(|(s, e)| (e.div_ceil(block) - s / block) * block).sum();
    if blocks > *budget {
        bail!("{blocks} bytes of blocks are past the limit");
    }
    let templates = push.map(|(paths, push)| push.check(paths, blocks, path.parent())).transpose()?;
    if push.is_none() && st.f_bavail.saturating_mul(st.f_frsize) < blocks + KEEP_FREE {
        bail!("{blocks} bytes of blocks would leave less than {} MiB free", KEEP_FREE >> 20);
    }
    *budget -= blocks;
    // Allocated now, under the lock: a filesystem that cannot (EOPNOTSUPP) takes no pushes.
    for &(start, end) in &extents {
        crate::util::check(unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, start as i64, (end - start) as i64) })
            .map_err(|e| format!("allocating its blocks: {e}"))?;
    }
    drop(templates);
    drop(admit);
    let (mut buf, mut hash) = (vec![0u8; 1 << 20], Hashing::new(len));
    for (mut off, end) in extents {
        while off < end {
            let n = (end - off).min(buf.len() as u64) as usize;
            r.read_exact(&mut buf[..n])?;
            file.write_all_at(&buf[..n], off)?;
            hash.write(off, &buf[..n]);
            off += n as u64;
        }
    }
    let (hash, digest) = hash.finish();
    Ok((Component { hash, metadata: Stamp::of(&file.metadata()?) }, digest))
}

#[allow(clippy::too_many_arguments)]
fn build(host: &crate::host::Host, paths: &Paths, dir: &Path, name: &str, size: Size, rootfs: &Path, tap: &str, image: ImageMeta) -> Result<()> {
    let Size { vcpus, mem_mib, max_mib, plug_mib } = size;
    let run = dir.join("boot");
    std::fs::create_dir_all(&run)?;

    // The image cache's file itself: the snapshot's page cache needs these bytes.
    let rootfs = std::fs::canonicalize(rootfs).map_err(|e| format!("{}: {e}", rootfs.display()))?;
    // Downloaded on first use if missing (`artifacts`): every later VM restores with the Firecracker built with.
    crate::artifacts::ensure(&[(&paths.kernel, &crate::artifacts::KERNEL), (&paths.firecracker, &crate::artifacts::FIRECRACKER)])?;
    let kernel = std::fs::canonicalize(&paths.kernel).map_err(|e| format!("{}: {e} (fetch it: scripts/fetch.sh)", paths.kernel.display()))?;
    let kernel_file = File::open(&kernel)?;
    let kernel_component = hash_open_file(&kernel_file, &kernel)?;
    let kernel_source = crate::host::fd_path(kernel_file.as_raw_fd());
    let sockets = SocketRoot::unique(&std::fs::canonicalize(dir)?)?;
    let start = Instant::now();
    let hotplug = max_mib.saturating_sub(mem_mib) / SLOT_MIB * SLOT_MIB;
    let mut admission = crate::limit::Building::admit(host, mem_mib)?;
    let mut fc = Firecracker::spawn(&paths.firecracker, &run, sockets.allocate()?, crate::fc::SPAWN_READY)?;
    admission.start(&mut fc, mem_mib + plug_mib.min(hotplug) / STEP_MIB * STEP_MIB)?;
    let vsock = fc.sockets.vsock.clone();
    let metrics = run.join("metrics.json");
    File::create(&metrics)?;
    fc.put("/metrics", json!({"metrics_path": metrics}))?;
    fc.put("/boot-source", json!({"kernel_image_path": kernel_source, "boot_args": BOOT_ARGS}))?;
    fc.put("/machine-config", json!({"vcpu_count": vcpus, "mem_size_mib": mem_mib}))?;
    fc.link_rootfs(&rootfs)?;
    fc.put("/pmem/root", json!({"id": "root", "path_on_host": ROOTFS, "root_device": true, "read_only": true}))?;
    fc.put("/balloon", json!({"amount_mib": 0, "deflate_on_oom": false, "stats_polling_interval_s": BALLOON_STATS_S, "free_page_reporting": true}))?;
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
    // Only warm-up leaves freed memory with data in it; for the rest, waiting takes ~26 s, and VMs
    // report it after restore instead (~7 MiB RSS each).
    let (reported, done) = match image.warm {
        true => wait_reporting_done(&fc, &metrics, plugged * 3 / 4)?,
        false => (0, true),
    };
    if !done {
        crate::log!(
            "template {name}: free page reporting did not finish ({reported} MiB reported of {plugged} MiB \
             plugged); VMs will report the rest after restore, at some RSS each"
        );
    }
    let lifted = admission.lift(fc.pid());
    fc.pause(crate::fc::API_TIMEOUT)?;
    let snapshotting = Instant::now();
    fc.request_within(
        "PUT",
        "/snapshot/create",
        Some(json!({"snapshot_type": "Full", "snapshot_path": dir.join("vmstate"), "mem_file_path": dir.join("mem")})),
        memory_timeout(mem_mib + hotplug),
    )?;
    let snapshotted = snapshotting.elapsed();
    let compatibility = crate::compat::local(fc.pid())?;
    let executable = PathBuf::from(format!("/proc/{}/exe", fc.pid()));
    if Stamp::of(&kernel_file.metadata()?) != kernel_component.metadata {
        bail!("kernel changed during template boot");
    }
    let inputs = BTreeMap::from([("kernel".into(), kernel_component), ("firecracker".into(), hash_file(&executable)?)]);
    drop(lifted);
    drop(fc);
    drop(admission);
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
        digests: None,
        received: false,
    };
    meta.identify_inputs(paths, dir, inputs)?;
    std::fs::write(dir.join("meta.json"), serde_json::to_vec_pretty(&meta)?)?;
    interrupted()?;
    let wset = record_working_set(host, paths, dir, tap, &sockets)?;
    let size = std::fs::metadata(dir.join("mem"))?.len();
    crate::output(format_args!(
        "template {name} (id {}): {vcpus} vCPUs, {mem_mib} MiB base + {hotplug} MiB hotplug ({plugged} MiB plugged, \
         {reported} MiB reported free), booted in {} ms, memory file {} MiB (snapshot in {} ms, {} MiB of zeroes punched out in {} ms), working set {} MiB\n",
        meta.id,
        ms(booted),
        size >> 20,
        ms(snapshotted),
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

/// `describe` of generation `id`, if there is one here (`inspect`).
pub fn describe_id(paths: &Paths, id: &str) -> Option<Value> {
    Template::generation(paths, id).map(|dir| describe(None, id, &dir))
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
/// of earlier pulls until `rmi ID` or `image prune`).
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

/// Give a pulled generation another name, under the same publication lock as removal.
pub fn tag(paths: &Paths, src: &str, dst: &str) -> Result<Value> {
    let dst = name_of(dst)?;
    let parent = crate::host::Directory::open(&paths.templates)?;
    let paths = &Paths { templates: parent.path.clone(), ..paths.clone() };
    let _lock = templates_lock(paths, libc::LOCK_EX)?;
    let source = name_of(src).ok().filter(|n| paths.templates.join(n).is_symlink());
    let id = match source {
        Some(name) => {
            let target = std::fs::read_link(paths.templates.join(name))?;
            let id = target.file_name().ok_or("image has no generation")?.to_string_lossy().into_owned();
            if target != Path::new(GENERATIONS).join(&id) {
                bail!("image has an invalid generation link");
            }
            generation_by_prefix(paths, &id)?
        }
        None => generation_by_prefix(paths, src)?,
    };
    let meta = Meta::read(&paths.templates.join(GENERATIONS).join(&id))?;
    if meta.received {
        bail!("tag cannot name a generation received from a peer; pull the image locally");
    }
    if meta.image.is_none() {
        bail!("tag needs a pulled image generation");
    }
    let live = paths.templates.join(&dst);
    if live.symlink_metadata().is_ok_and(|m| !m.file_type().is_symlink()) {
        bail!("image {} is not a symlink", image_of(&dst));
    }
    let tmp = paths.templates.join(format!(".{dst}.link-{}", crate::util::random_hex(8)?));
    std::os::unix::fs::symlink(Path::new(GENERATIONS).join(&id), &tmp)?;
    if let Err(e) = std::fs::rename(&tmp, &live) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    crate::util::sync_dir(&paths.templates)?;
    Ok(json!({"tagged": image_of(&dst), "id": id}))
}

/// `image prune`: each unnamed generation (or only `only`, which a pull moved its name off, unless
/// other states share the templates directory: `SHARED`), as `rmi ID` would remove it; those still
/// used stay, here or in the states that share the directory (`shared_users`; `force_shared`: take
/// its record of them as right). One pass: the names, then, a batch at a time (`PRUNE_BATCH`), each
/// candidate's use lock and then what uses them (read after the batch's locks are ours: a VM that
/// suspended since has published its checkpoint), then the root filesystems the rest use.
pub fn prune(paths: &Paths, only: Option<&str>, in_use: &dyn Fn() -> BTreeSet<String>, force_shared: bool) -> Result<Vec<Value>> {
    if !paths.templates.exists() {
        return Ok(vec![]);
    }
    let linked = paths.templates.is_symlink();
    let parent = crate::host::Directory::open(&paths.templates)?;
    let paths = &Paths { templates: parent.path.clone(), ..paths.clone() };
    let _lock = templates_lock(paths, libc::LOCK_EX)?;
    if let Some(id) = only.filter(|_| linked || paths.templates.join(SHARED).exists()) {
        crate::log!("flexvm: kept {id}: other states share these templates, and their VMs may use it; image prune removes it");
        return Ok(vec![]);
    }
    note_rootfs_locked(paths)?;
    sweep_locked(paths)?;
    // `--force-shared` brings the record up to date (the marker, gone states) whether or not anything is pruned.
    // Only the record's failures end it: a state's unreadable checkpoint keeps every generation, as without it.
    if force_shared {
        let shared = shared_users(paths, true, false);
        if let Some(why) = shared.iter().find_map(|u| u.strip_prefix(KEEP_ALL)) {
            bail!("image prune --force-shared: {why}");
        }
    }
    let named: BTreeSet<String> = names(&paths.templates)?.into_iter().map(|(_, id)| id).collect();
    let (gens, locks) = (paths.templates.join(GENERATIONS), crate::host::host_locks()?);
    let candidates: Vec<String> = generations(&paths.templates)?.into_iter().filter(|id| only.is_none_or(|o| o == id) && !named.contains(id)).collect();
    let mut tombstones = vec![];
    // In batches, each holding a bounded number of use locks (two descriptors each).
    for batch in candidates.chunks(PRUNE_BATCH) {
        let mut unused = vec![];
        for id in batch {
            // Kept while a VM process has it open (one starting has no registry entry yet).
            let st = crate::util::fstat(File::open(gens.join(id))?.as_raw_fd())?;
            match crate::host::try_lock_at(locks.try_clone()?, &crate::host::use_lock(&st))? {
                Some(held) => unused.push((id, held)),
                // Asked for this one (a pull's superseded generation): say why it stays.
                None if only.is_some() => crate::log!("flexvm: kept generation {id}: a process here still has it open; image prune removes it once unused"),
                None => {}
            }
        }
        if unused.is_empty() {
            continue;
        }
        let users = users(paths, in_use, force_shared);
        if let Some(why) = users.iter().find_map(|u| u.strip_prefix(KEEP_ALL)) {
            crate::log!("flexvm: {}{KEPT_ALL}{why}", only.map_or("image prune: unused generations are ".into(), |id| format!("generation {id} is ")));
            break;
        }
        for (id, _held) in unused.iter().filter(|(id, _)| !users.contains(*id)) {
            let tombstone = gens.join(format!(".{id}.rm-{}", crate::util::random_hex(8)?));
            std::fs::rename(gens.join(id), &tombstone)?;
            tombstones.push((id.to_string(), tombstone));
        }
        crate::util::sync_dir(&gens)?;
    }
    let rootfs_used = rootfs_users(paths)?;
    let mut removed = vec![];
    for (id, tombstone) in tombstones {
        removed.push(json!({"deleted": id, "rootfs": finish_remove_with(paths, &tombstone, &rootfs_used, force_shared)?}));
    }
    // Recorded entries no generation here uses: a record left by a crash before its publication, or
    // (`--force-shared`) entries kept only for gone states or as legacy, recorded or not.
    if let (None, Some(used)) = (only, rootfs_users(paths)?) {
        let templates = std::fs::canonicalize(&paths.templates)?;
        for rootfs in crate::image::recorded_rootfs(&paths.images, force_shared)?.into_iter().filter(|r| !used.contains(r)) {
            match crate::image::remove_rootfs(&paths.images, &rootfs, &templates, force_shared) {
                Ok(crate::image::Removal::Removed) => removed.push(json!({"rootfs": rootfs})),
                Ok(_) => {}
                Err(e) => crate::log!("image: removing {}: {e}", rootfs.display()),
            }
        }
    }
    Ok(removed)
}

/// How many generations `prune` holds the use locks of at once, reading what uses them once per batch.
const PRUNE_BATCH: usize = 64;

/// What uses generations: `in_use` (this state's records) and the other states' that share the
/// templates directory (`shared_users`).
fn users(paths: &Paths, in_use: &dyn Fn() -> BTreeSet<String>, force_shared: bool) -> BTreeSet<String> {
    let mut users = in_use();
    users.extend(shared_users(paths, force_shared, true));
    users
}

/// How long a received generation (`receive`) that no name links to stays once nothing uses it: no VM process
/// has it open, no VM record or checkpoint here names it and no listener holds it for an arrival. A push serves
/// the arrival right behind it, and that VM process holds it as long as it runs; an hour unused more spares a
/// VM moving back, or another of its template coming, a second copy of GiBs. Push admission
/// overrides this grace under pressure, with byte budgets and `PUSH_FREE` reserved for local work.
pub const RECEIVED_IDLE: Duration = Duration::from_secs(3600);

/// The periodic collection (`gc`): a sweep of what killed builds and receives left (`sweep`), then each received
/// generation that no name links to and nothing has used for `idle` (`RECEIVED_IDLE`), removed as `rmi ID` would.
/// One in use is stamped (its directory's mtime) as used now: how long it has been unused is how long since the
/// last such stamp. Pulled generations and templates directories other states share (`SHARED`: their VMs and
/// checkpoints are not in `in_use`) are left to `image prune`. Skipped while another holds the templates lock.
/// Returns the ids removed.
pub fn collect(paths: &Paths, idle: Duration, in_use: &dyn Fn() -> BTreeSet<String>) -> Result<Vec<String>> {
    if !paths.templates.is_dir() {
        return Ok(vec![]);
    }
    let linked = paths.templates.is_symlink();
    let parent = crate::host::Directory::open(&paths.templates)?;
    let paths = &Paths { templates: parent.path.clone(), ..paths.clone() };
    let Ok(_lock) = templates_lock(paths, libc::LOCK_EX | libc::LOCK_NB) else { return Ok(vec![]) };
    sweep_locked(paths)?;
    if linked || paths.templates.join(SHARED).exists() {
        return Ok(vec![]);
    }
    let (named, gens) = (names(&paths.templates)?, paths.templates.join(GENERATIONS));
    let mut users = None;
    let mut removed = vec![];
    for id in generations(&paths.templates)? {
        let dir = gens.join(&id);
        if named.iter().any(|(_, i)| *i == id) || !Meta::read(&dir).is_ok_and(|m| m.received) {
            continue;
        }
        let Ok(handle) = File::open(&dir) else { continue };
        let st = crate::util::fstat(handle.as_raw_fd())?;
        let open = crate::host::try_lock_at(crate::host::host_locks()?, &crate::host::use_lock(&st))?.is_none();
        // A checkpoint here that cannot be read (`KEEP_ALL`) may use any: each counts as used now.
        let users = users.get_or_insert_with(in_use);
        if open || users.contains(&id) || users.iter().any(|u| u.starts_with(KEEP_ALL)) {
            crate::util::check(unsafe { libc::futimens(handle.as_raw_fd(), std::ptr::null()) })?;
            continue;
        }
        let unused = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs().saturating_sub(st.st_mtime as u64);
        if unused < idle.as_secs() {
            continue;
        }
        if delete_unused(paths, &id, in_use)?.is_ok() {
            crate::log!("template: removed received generation {id}, unused for {} s", unused);
            removed.push(id);
        }
    }
    Ok(removed)
}

/// `rmi`: removes the name `name` (if given), then the generation `id` (the one the name linked to)
/// unless a name still links to it or a VM here uses it, and the image root filesystems that no
/// generation left uses. The caller checked that no VM uses the name. `in_use` reads the content ids
/// VMs here use from their records (`Host::template_users`); it is read under the generation's
/// exclusive use lock, after every process that had the generation open let it go: a VM that
/// suspended (or started resuming) since an earlier read is seen then.
pub fn remove(paths: &Paths, name: Option<&str>, id: &str, in_use: &dyn Fn() -> BTreeSet<String>) -> Result<Value> {
    let parent = crate::host::Directory::open(&paths.templates)?;
    let paths = &Paths { templates: parent.path.clone(), ..paths.clone() };
    // No build publishes meanwhile (they take it too).
    let _l = templates_lock(paths, libc::LOCK_EX)?;
    remove_locked(paths, name, id, in_use)
}

/// `remove`, with the templates directory pinned and its lock held exclusively by the caller.
pub(crate) fn remove_locked(paths: &Paths, name: Option<&str>, id: &str, in_use: &dyn Fn() -> BTreeSet<String>) -> Result<Value> {
    sweep_locked(paths)?;
    // Test gate: what the caller saw of the VMs here may be out of date by the time this goes on.
    crate::host::hold("rmi_hold");
    if let Some(name) = name {
        check_name(name)?;
        let link = paths.templates.join(name);
        if std::fs::read_link(&link)?.file_name() != Some(id.as_ref()) {
            bail!("image {} was pulled again meanwhile; try again", image_of(name));
        }
        std::fs::remove_file(&link)?;
        crate::util::sync_dir(&paths.templates)?;
    }
    match delete_unused(paths, id, in_use)? {
        Ok(rootfs) => Ok(json!({"untagged": name, "deleted": id, "rootfs": rootfs})),
        Err((reason, _)) if name.is_some() => Ok(json!({"untagged": name, "kept": id, "reason": reason})),
        Err((_, refusal)) => bail!("{refusal}"),
    }
}

/// Deletes generation `id` and the root filesystem only it used, unless a name links to it or a
/// VM here has it open or uses it: then it is kept, with the reason and the refusal to give.
fn delete_unused(paths: &Paths, id: &str, in_use: &dyn Fn() -> BTreeSet<String>) -> Result<std::result::Result<Option<PathBuf>, (String, String)>> {
    if let Some((other, _)) = names(&paths.templates)?.iter().find(|(_, i)| i == id) {
        return Ok(Err((format!("{} is the same image", image_of(other)), format!("image {id} is {0}; remove that: flexvm rmi {0}", image_of(other)))));
    }
    let gens = paths.templates.join(GENERATIONS);
    // Kept while a VM process has it open (one starting has no registry entry yet).
    let st = crate::util::fstat(File::open(gens.join(id))?.as_raw_fd())?;
    let Some(_use) = crate::host::try_lock_at(crate::host::host_locks()?, &crate::host::use_lock(&st))? else {
        return Ok(Err(("open in a VM process here".into(), format!("image {id} is open in a VM process here"))));
    };
    let (here, shared) = (in_use(), shared_users(paths, false, true));
    if let Some(why) = here.iter().chain(&shared).find_map(|u| u.strip_prefix(KEEP_ALL)) {
        return Ok(Err((format!("{KEPT_ALL}{why}"), format!("image {id} is {KEPT_ALL}{why}"))));
    }
    if here.contains(id) {
        return Ok(Err(("used by a VM here".into(), format!("image {id} is used by a VM here"))));
    }
    if shared.contains(id) {
        let why = "used by a VM or checkpoint of a state that shares these templates";
        return Ok(Err((why.into(), format!("image {id} is {why}"))));
    }
    let tombstone = gens.join(format!(".{id}.rm-{}", crate::util::random_hex(8)?));
    std::fs::rename(gens.join(id), &tombstone)?;
    crate::util::sync_dir(&gens)?;
    Ok(Ok(finish_remove(paths, &tombstone)?))
}

/// Under the templates lock. A tombstone's generation is gone, but it stays a rootfs user until
/// its rootfs is decided: its `meta.json` is kept (the rest removed) while a pull uses the rootfs
/// (`Removal::InUse`), and the next sweep asks again, so a pull that fails leaves no rootfs nothing
/// will remove. Interrupted, a sweep retries it the same way.
fn finish_remove(paths: &Paths, tombstone: &Path) -> Result<Option<PathBuf>> {
    finish_remove_with(paths, tombstone, &rootfs_users(paths)?, false)
}

/// Backfill records for old cache keys and refresh the path of moved states on open. Shared, as
/// every command and VM opens the state: excludes prune and publication, not other opens. Neither
/// lock is waited for: a holder of the templates lock may be waiting on this very open (a receive
/// starting its VM), and a key a build holds would stall every command behind its `mkfs`. Skipped
/// ones are recorded at the next open, and by prune (under its own lock) before it removes anything.
pub(crate) fn note_rootfs(paths: &Paths) -> Result<()> {
    if !paths.templates.exists() {
        return Ok(());
    }
    let _lock = match templates_lock(paths, libc::LOCK_SH | libc::LOCK_NB) {
        Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) => return Ok(()),
        r => r?,
    };
    note_rootfs_locked(paths)
}

/// Under the templates lock, before prune can remove any generation. A key another holds (a build,
/// which records its own as it publishes) is not waited for under it.
fn note_rootfs_locked(paths: &Paths) -> Result<()> {
    let templates = std::fs::canonicalize(&paths.templates)?;
    for g in generations(&paths.templates)? {
        let meta = match Meta::read(&paths.templates.join(GENERATIONS).join(&g)) {
            Ok(meta) => meta,
            Err(e) => {
                crate::log!("image: reading generation {g} to record its root filesystem: {e}");
                continue;
            }
        };
        if let Err(e) = crate::image::note_published_rootfs(&paths.images, &meta.rootfs, &templates) {
            crate::log!("image: recording {}: {e}", meta.rootfs.display());
        }
    }
    Ok(())
}

/// The root filesystems the generations here use; None while one's `meta.json` cannot be read
/// (it may use any).
fn rootfs_users(paths: &Paths) -> Result<Option<BTreeSet<PathBuf>>> {
    let gens = paths.templates.join(GENERATIONS);
    let mut used = BTreeSet::new();
    for g in generations(&paths.templates)? {
        match Meta::read(&gens.join(g)) {
            Ok(m) => drop(used.insert(m.rootfs)),
            Err(_) => return Ok(None),
        }
    }
    Ok(Some(used))
}

/// `finish_remove`, given what `rootfs_users` read (under the same hold of the templates lock).
fn finish_remove_with(paths: &Paths, tombstone: &Path, rootfs_used: &Option<BTreeSet<PathBuf>>, force: bool) -> Result<Option<PathBuf>> {
    let gens = paths.templates.join(GENERATIONS);
    let mut removed = None;
    if let Ok(meta) = Meta::read(tombstone) {
        let rootfs = meta.rootfs;
        let used = rootfs_used.as_ref().is_none_or(|u| u.contains(&rootfs));
        match if used {
            crate::image::Removal::Absent
        } else {
            match crate::image::remove_rootfs(&paths.images, &rootfs, &std::fs::canonicalize(&paths.templates)?, force) {
                Ok(removal) => removal,
                Err(e) => {
                    crate::log!("image: removing {}: {e}", rootfs.display());
                    crate::image::Removal::InUse
                }
            }
        } {
            crate::image::Removal::Removed => removed = Some(rootfs),
            crate::image::Removal::Absent => {}
            crate::image::Removal::InUse => {
                for entry in std::fs::read_dir(tombstone)? {
                    let entry = entry?;
                    match entry.file_name() {
                        n if n == "meta.json" => {}
                        _ if entry.file_type()?.is_dir() => std::fs::remove_dir_all(entry.path())?,
                        _ => std::fs::remove_file(entry.path())?,
                    }
                }
                crate::util::sync_dir(tombstone)?;
                return Ok(None);
            }
        }
    }
    std::fs::remove_dir_all(tombstone)?;
    crate::util::sync_dir(&gens)?;
    Ok(removed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn generation_ids(templates: &Path) -> Vec<String> {
        generations(templates).unwrap()
    }

    #[test]
    fn identify_hashes_and_digests_match_separate_passes() {
        let mut f = Fixture::new();
        let mem = File::create(f.dir.join("mem")).unwrap();
        mem.set_len((4 * PAGE_SIZE + 17) as u64).unwrap();
        mem.write_all_at(b"memory", PAGE_SIZE as u64).unwrap();
        mem.write_all_at(b"tail", (4 * PAGE_SIZE + 13) as u64).unwrap();
        f.meta.image = Some(image("sha256:a", "arg /x\n"));
        f.meta.identify(&f.paths, &f.dir).unwrap();
        let mut components = BTreeMap::new();
        for (name, path) in f.meta.files(&f.paths, &f.dir) {
            let expected = hash_file(&path).unwrap();
            assert_eq!(f.meta.components[name].hash, expected.hash);
            assert_eq!(f.meta.components[name].metadata, expected.metadata);
            components.insert(name.into(), expected);
        }
        assert_eq!(f.meta.id, content_id(&components, f.meta.image.as_ref()));
        assert_eq!(f.meta.digests.as_ref().unwrap(), &digests(&f.meta, &f.dir.join("vmstate"), &f.dir.join("mem"), &f.meta.rootfs).unwrap());
    }

    #[test]
    fn streaming_hash_reuses_its_page_and_clears_holes() {
        let len = 5 * PAGE_SIZE + 37;
        let mut bytes = vec![0; len];
        let mut hash = Hashing::new(len as u64);
        let buf = hash.buf.as_ptr();
        for (off, data) in [(3, vec![7; PAGE_SIZE + 19]), (2 * PAGE_SIZE + 9, vec![0; PAGE_SIZE]), (5 * PAGE_SIZE + 31, vec![9; 6])] {
            bytes[off..off + data.len()].copy_from_slice(&data);
            hash.write(off as u64, &data);
            assert_eq!(hash.buf.as_ptr(), buf);
        }
        let mut want = Hashing::new(len as u64);
        for (n, bytes) in bytes.chunks(PAGE_SIZE).enumerate() {
            let mut page = [0; PAGE_SIZE];
            page[..bytes.len()].copy_from_slice(bytes);
            want.page(n as u64, &page);
        }
        assert_eq!(hash.finish(), want.finish());
    }

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
        let host = crate::host::Host::open(&dir.join("state"), &dir.join("run")).unwrap();
        let error = build(&host, &paths, &dir.join("build"), "test", size, &dir.join("rootfs"), "unused", image("sha256:a", "")).unwrap_err().to_string();
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
            let paths = Paths { firecracker: dir.join("firecracker"), kernel: dir.join("kernel"), templates: dir.clone(), images: dir.join("images") };
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
                digests: None,
                received: false,
            };
            for (name, path) in meta.files(&paths, &dir) {
                std::fs::write(path, name.as_bytes()).unwrap();
            }
            meta.identify(&paths, &dir).unwrap();
            meta.digests = None; // Legacy generations have none.
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
    fn every_load_confines_pmem_to_the_generations_root_filesystem() {
        for by_path in [false, true] {
            let mut f = Fixture::new();
            if by_path {
                // Where a pull puts it, the only place a received older generation's may be (`open_cached_rootfs`).
                let cache = f.paths.images.join("rootfs");
                std::fs::create_dir_all(&cache).unwrap();
                f.meta.rootfs = std::fs::canonicalize(&cache).unwrap().join("k.ext4");
                std::fs::rename(f.dir.join("rootfs"), &f.meta.rootfs).unwrap();
            }
            let rootfs = f.meta.rootfs.clone();
            let named = if by_path { rootfs.display().to_string() } else { ROOTFS.to_string() };
            let (tpl, buf) = sent(&mut f, &named);
            let want = if by_path { rootfs.display().to_string() } else { ROOTFS.to_string() };
            let (_dir, paths) = elsewhere(&f);
            // Local or received, built by v0.1.0 or since: the vmstate chooses no other file.
            for tpl in [tpl.clone(), receive(&paths, &mut &buf[..], &tpl.meta.id, None, |_| Ok(()), |_| Ok(())).unwrap()] {
                let body = crate::fc::snapshot_load_body(Path::new("vmstate"), &tpl, "tap0", Path::new("vsock"), Path::new("uffd")).unwrap();
                assert_eq!(body["confined_pmem"], want, "by_path={by_path}, received={}", tpl.meta.received);
            }
        }
    }

    /// A generation in `f.dir` with a sparse memory file and a vmstate naming `rootfs` as given, sent.
    fn sent(f: &mut Fixture, rootfs_named: &str) -> (Arc<Template>, Vec<u8>) {
        std::fs::write(f.dir.join("vmstate"), format!("state, pmem at {rootfs_named}")).unwrap();
        let mem = File::create(f.dir.join("mem")).unwrap();
        mem.set_len(f.meta.max_mib << 20).unwrap();
        mem.write_all_at(&[7u8; PAGE_SIZE], 3 * PAGE_SIZE as u64).unwrap();
        mem.write_all_at(&[9u8; PAGE_SIZE], 40 * PAGE_SIZE as u64).unwrap();
        f.meta.identify(&f.paths, &f.dir).unwrap();
        f.write_meta(&f.meta, &f.dir);
        // Recorded, as scripts/build-firecracker.sh records its build: `artifacts::ensure` runs no other unpinned one.
        use sha2::Digest;
        let sum = format!("{:x}  firecracker\n", sha2::Sha256::digest(std::fs::read(&f.paths.firecracker).unwrap()));
        std::fs::write(f.dir.join("firecracker.sha256"), sum).unwrap();
        let tpl = f.open().unwrap();
        let mut buf = vec![];
        assert_eq!(send(&tpl, &mut buf).unwrap(), 2 * PAGE_SIZE as u64 + std::fs::metadata(&f.meta.rootfs).unwrap().len() + rootfs_named.len() as u64 + 15);
        assert_eq!(Sending::new(&tpl).unwrap().len(), buf.len() as u64, "known before it is written");
        (tpl, buf)
    }

    /// A generation `.gen/ID` that `send` can send, its digests recorded as a build records them, in a
    /// templates directory of its own (`checkpoint save`'s tests).
    pub(crate) fn sendable() -> (crate::test_util::TempDir, Paths, Arc<Template>) {
        let mut f = Fixture::new();
        let (tpl, _) = sent(&mut f, ROOTFS);
        f.meta.digests = Some(tpl.digests().unwrap());
        f.write_meta(&f.meta, &f.dir);
        std::fs::create_dir_all(f.dir.join(GENERATIONS)).unwrap();
        std::os::unix::fs::symlink(&*f.dir, f.dir.join(GENERATIONS).join(&f.meta.id)).unwrap();
        let tpl = f.open().unwrap();
        (f.dir, f.paths, tpl)
    }

    /// Another host's templates directory with `paths`' Firecracker (`elsewhere`).
    pub(crate) fn elsewhere_of(paths: &Paths) -> (crate::test_util::TempDir, Paths) {
        let dir = crate::test_util::TempDir::new("template-in");
        let paths = Paths { templates: dir.clone(), kernel: dir.join("vmlinux"), ..paths.clone() };
        (dir, paths)
    }

    /// Another host's templates directory, with `f`'s Firecracker.
    fn elsewhere(f: &Fixture) -> (crate::test_util::TempDir, Paths) {
        let dir = crate::test_util::TempDir::new("template-in");
        let paths = Paths { templates: dir.clone(), kernel: dir.join("vmlinux"), ..f.paths.clone() };
        (dir, paths)
    }

    /// Nothing of a generation in `paths`: no generation and no staging.
    fn nothing_in(paths: &Paths) -> bool {
        generations(&paths.templates).unwrap().is_empty()
            && std::fs::read_dir(&paths.templates).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().contains(".new-"))
    }

    #[test]
    fn a_received_generation_is_verified_unnamed_and_keeps_its_holes() {
        let mut f = Fixture::new();
        let (tpl, buf) = sent(&mut f, ROOTFS);
        let (dir, paths) = elsewhere(&f);
        let got = receive(&paths, &mut &buf[..], &tpl.meta.id, None, |_| Ok(()), |_| Ok(())).unwrap();
        assert_eq!(got.meta.id, tpl.meta.id);
        let gen = std::fs::canonicalize(&*dir).unwrap().join(GENERATIONS).join(&tpl.meta.id);
        assert_eq!(got.meta.rootfs, gen.join("rootfs"));
        assert_eq!(std::fs::read(gen.join("rootfs")).unwrap(), std::fs::read(&f.meta.rootfs).unwrap());
        assert_eq!(got.meta.kernel, paths.kernel);
        let mem = File::open(gen.join("mem")).unwrap();
        assert_eq!(mem.metadata().unwrap().len(), f.meta.max_mib << 20);
        assert_eq!(data_extents(&mem, f.meta.max_mib << 20).unwrap().iter().map(|(s, e)| e - s).sum::<u64>(), 2 * PAGE_SIZE as u64, "holes stay holes");
        assert!(got.has_data(40) && !got.has_data(4) && got.pages(3, 1) == [7u8; PAGE_SIZE]);
        // No name: listed as <none>, and the name the source has is not taken here.
        assert!(names(&paths.templates).unwrap().is_empty());
        assert_eq!(images(&paths).unwrap()[0]["name"], Value::Null);
        assert!(Template::open_id(&paths, "t", &tpl.meta.id).is_ok());
        // What a source compares: a copy made to match the content id, or with other metadata, differs.
        assert!(got.meta.received && got.meta.digests.as_ref() == Some(&tpl.digests().unwrap()));
        assert!(got.check_vouched(None, "a v0.1.0 source").is_err() && got.check_vouched(Some(&tpl.digests().unwrap()), "it").is_ok());
        let (_other, elsewhere_paths) = elsewhere(&f);
        let mut meta = tpl.meta.clone();
        meta.compatibility.cpu = "another".into();
        let forged = [
            &(serde_json::to_vec(&meta).unwrap().len() as u64).to_le_bytes()[..],
            &serde_json::to_vec(&meta).unwrap(),
            &buf[8 + u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize..],
        ]
        .concat();
        let poisoned = receive(&elsewhere_paths, &mut &forged[..], &tpl.meta.id, None, |_| Ok(()), |_| Ok(())).unwrap();
        assert!(poisoned.check_vouched(Some(&tpl.digests().unwrap()), "a checkpoint of it").is_err());
        // Vouched for by other digests (a checkpoint's): refused before it is published.
        let (_other, vouching) = elsewhere(&f);
        let mut other = tpl.digests().unwrap();
        other.insert("mem".into(), "0".repeat(64));
        let e = receive(&vouching, &mut &buf[..], &tpl.meta.id, Some(&other), |_| Ok(()), |_| Ok(())).err().unwrap().to_string();
        assert!(e.contains("do not match the SHA-256 digests") && nothing_in(&vouching), "{e}");
        assert!(receive(&vouching, &mut &buf[..], &tpl.meta.id, Some(&tpl.digests().unwrap()), |_| Ok(()), |_| Ok(())).is_ok());
        // An identical one arriving again keeps the first.
        drop(got);
        receive(&paths, &mut &buf[..], &tpl.meta.id, None, |_| Ok(()), |_| Ok(())).unwrap();
        assert_eq!(generations(&paths.templates).unwrap(), [tpl.meta.id.clone()]);
    }

    #[test]
    fn a_corrupt_truncated_or_foreign_generation_leaves_nothing() {
        let mut f = Fixture::new();
        let (tpl, buf) = sent(&mut f, ROOTFS);
        let id = &tpl.meta.id;
        let (_dir, paths) = elsewhere(&f);
        let mut corrupt = buf.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let e = receive(&paths, &mut &corrupt[..], id, None, |_| Ok(()), |_| Ok(())).err().unwrap().to_string();
        assert!(e.contains("its mem does not hash"), "{e}");
        assert!(receive(&paths, &mut &buf[..buf.len() - 10], id, None, |_| Ok(()), |_| Ok(())).is_err());
        // A root filesystem path that is empty or relative, or memory past the cap, is refused before anything is read.
        assert!(!names_by_path(b"anything", Path::new("")));
        for (rootfs, max_mib) in [("", tpl.meta.max_mib), ("rootfs", tpl.meta.max_mib), ("/r", MAX_MEM_MIB + 1)] {
            let meta = serde_json::to_vec(&Meta { rootfs: rootfs.into(), max_mib, ..tpl.meta.clone() }).unwrap();
            let forged = [&(meta.len() as u64).to_le_bytes()[..], &meta, &buf[8 + u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize..]].concat();
            assert!(receive(&paths, &mut &forged[..], id, None, |_| Ok(()), |_| Ok(())).err().unwrap().to_string().contains("past the limits"));
        }
        let e = receive(&paths, &mut &buf[..], "abcd", None, |_| Ok(()), |_| Ok(())).err().unwrap().to_string();
        assert!(e.contains("not that template's"), "{e}");
        assert!(nothing_in(&paths));
        // Extents past the file, and more data than the cap.
        let mut path = paths.templates.join("x");
        for words in [[8u64, 1, 0, 16], [MAX_DATA + 1, 1, 0, MAX_DATA + 1]] {
            let head: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            path.set_extension("y");
            assert!(receive_file(&mut &head[..], &path, 0..=u64::MAX, &mut MAX_DATA.clone(), None).is_err());
        }
        let (_other, mut paths) = elsewhere(&f);
        paths.firecracker = paths.templates.join("firecracker");
        std::fs::write(&paths.firecracker, "another build").unwrap();
        use sha2::Digest;
        std::fs::write(paths.templates.join("firecracker.sha256"), format!("{:x}  firecracker\n", sha2::Sha256::digest("another build"))).unwrap();
        let e = receive(&paths, &mut &buf[..], id, None, |_| Ok(()), |_| Ok(())).err().unwrap().to_string();
        assert!(e.contains("another Firecracker"), "{e}");
    }

    #[test]
    fn an_older_generation_needs_its_root_filesystem_at_its_path() {
        let mut f = Fixture::new();
        // Where a pull puts it: the image cache's (`image::Cached`).
        let cache = f.paths.images.join("rootfs");
        std::fs::create_dir_all(&cache).unwrap();
        f.meta.rootfs = std::fs::canonicalize(&cache).unwrap().join("k.ext4");
        std::fs::rename(f.dir.join("rootfs"), &f.meta.rootfs).unwrap();
        let rootfs = f.meta.rootfs.to_string_lossy().into_owned();
        let (tpl, buf) = sent(&mut f, &rootfs);
        let (_dir, paths) = elsewhere(&f);
        let got = receive(&paths, &mut &buf[..], &tpl.meta.id, None, |_| Ok(()), |_| Ok(())).unwrap();
        assert_eq!(got.meta.rootfs, f.meta.rootfs, "the file its snapshot names, already here");
        assert!(!got.fixed.join("rootfs").exists());
        drop(got);
        let (_dir, paths) = elsewhere(&f);
        std::fs::write(&f.meta.rootfs, "another build").unwrap();
        let e = receive(&paths, &mut &buf[..], &tpl.meta.id, None, |_| Ok(()), |_| Ok(())).err().unwrap().to_string();
        assert!(e.contains("names its root filesystem by its path"), "{e}");
        assert!(nothing_in(&paths));
        // A peer naming any other file, a device, a FIFO or a file outside the image cache, is refused without
        // opening it to read (#823), and at once: a FIFO's open would block.
        let fifo = std::fs::canonicalize(&cache).unwrap().join("fifo.ext4");
        let path = crate::util::cpath(&fifo).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let elsewhere_file = f.dir.join("elsewhere.ext4");
        std::fs::write(&elsewhere_file, "another build").unwrap();
        for named in [Path::new("/dev/zero"), Path::new("/dev/watchdog"), &fifo, &elsewhere_file] {
            let mut meta = tpl.meta.clone();
            meta.rootfs = named.into();
            let state = format!("state, pmem at {}", named.display());
            let (_dir, paths) = elsewhere(&f);
            let forged = forged_stream(&buf, &meta, state.as_bytes());
            let started = Instant::now();
            let e = receive(&paths, &mut &forged[..], &tpl.meta.id, None, |_| Ok(()), |_| Ok(())).err().unwrap().to_string();
            assert!(e.contains("which does not hold it here") && started.elapsed() < Duration::from_secs(5), "{named:?}: {e}");
            assert!(nothing_in(&paths));
        }
    }

    #[test]
    fn cached_rootfs_is_hashed_after_the_stream_is_read() {
        struct Stream<'a> {
            bytes: &'a [u8],
            rootfs: &'a Path,
        }
        impl Read for Stream<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.bytes.read(buf)?;
                if self.bytes.is_empty() {
                    std::fs::write(self.rootfs, b"rootfs")?;
                }
                Ok(n)
            }
        }
        let mut f = Fixture::new();
        let cache = f.paths.images.join("rootfs");
        std::fs::create_dir_all(&cache).unwrap();
        f.meta.rootfs = std::fs::canonicalize(&cache).unwrap().join("k.ext4");
        std::fs::rename(f.dir.join("rootfs"), &f.meta.rootfs).unwrap();
        let named = f.meta.rootfs.to_string_lossy().into_owned();
        let (tpl, buf) = sent(&mut f, &named);
        std::fs::write(&f.meta.rootfs, b"not yet the cached image").unwrap();
        let (_dir, paths) = elsewhere(&f);
        let mut stream = Stream { bytes: &buf, rootfs: &f.meta.rootfs };
        let got = receive(&paths, &mut stream, &tpl.meta.id, None, |_| Ok(()), |_| Ok(())).unwrap();
        assert!(stream.bytes.is_empty());
        assert_eq!(got.meta.rootfs, f.meta.rootfs);
    }

    /// `buf` (a `send` of a generation whose vmstate names `ROOTFS` or a path) with `meta` for its metadata and
    /// `vmstate` for its vmstate, the rest as sent.
    fn forged_stream(buf: &[u8], meta: &Meta, vmstate: &[u8]) -> Vec<u8> {
        let skip = 8 + u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize;
        let [len, n] = [0, 8].map(|o| u64::from_le_bytes(buf[skip + o..skip + o + 8].try_into().unwrap()));
        let rest = &buf[skip + 16 + 16 * n as usize + len as usize..];
        let meta = serde_json::to_vec(meta).unwrap();
        let state = [vmstate.len() as u64, 1, 0, vmstate.len() as u64].map(u64::to_le_bytes).concat();
        [&(meta.len() as u64).to_le_bytes()[..], &meta, &state, vmstate, rest].concat()
    }

    #[test]
    fn only_a_regular_file_of_the_image_cache_is_opened() {
        let f = Fixture::new();
        let cache = f.paths.images.join("rootfs");
        std::fs::create_dir_all(&cache).unwrap();
        let cache = std::fs::canonicalize(&cache).unwrap();
        std::fs::write(cache.join("k.ext4"), "fs").unwrap();
        let mut got = String::new();
        open_cached_rootfs(&f.paths, &cache.join("k.ext4")).unwrap().read_to_string(&mut got).unwrap();
        assert_eq!(got, "fs");
        std::os::unix::fs::symlink(cache.join("k.ext4"), cache.join("link.ext4")).unwrap();
        std::fs::create_dir(cache.join("dir.ext4")).unwrap();
        let fifo = crate::util::cpath(&cache.join("fifo.ext4")).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        std::fs::write(f.dir.join("out.ext4"), "fs").unwrap();
        std::fs::write(cache.join("k"), "fs").unwrap();
        let started = Instant::now();
        for path in [
            cache.join("link.ext4"),
            cache.join("dir.ext4"),
            cache.join("fifo.ext4"),
            cache.join("missing.ext4"),
            cache.join("../rootfs/k.ext4"),
            cache.join("k"),
            cache.join(".ext4"),
            f.dir.join("out.ext4"),
            "/dev/null".into(),
        ] {
            assert!(open_cached_rootfs(&f.paths, &path).is_err(), "{path:?}");
        }
        // Devices are neither opened (O_PATH: no driver's open runs) nor accepted.
        for dev in ["null", "zero", "urandom"] {
            let e = open_regular_at(Path::new("/dev"), dev.as_ref()).err().unwrap().to_string();
            assert!(e.contains("not a regular file"), "{dev}: {e}");
        }
        assert!(open_regular_at(&cache, "fifo.ext4".as_ref()).err().unwrap().to_string().contains("not a regular file"));
        assert!(started.elapsed() < Duration::from_secs(5), "nothing waited on");
    }

    #[test]
    fn a_file_is_hashed_as_it_is_received() {
        let dir = crate::test_util::TempDir::new("hash-received");
        let page = PAGE_SIZE as u64;
        let len = 40 * page + 123;
        // Extents not page aligned, two in one page, a page all zero, and the last page partial.
        let extents = [(100, 200), (300, page + 7), (3 * page, 4 * page), (9 * page + 1, 9 * page + 2), (39 * page + 5, len)];
        let byte = |o: u64| if (3 * page..4 * page).contains(&o) { 0 } else { (o % 251 + 1) as u8 };
        let mut stream: Vec<u8> = [len, extents.len() as u64].into_iter().chain(extents.iter().flat_map(|&(s, e)| [s, e])).flat_map(u64::to_le_bytes).collect();
        for &(s, e) in &extents {
            stream.extend((s..e).map(byte));
        }
        let path = dir.join("f");
        let (c, sha) = receive_file(&mut &stream[..], &path, 0..=len, &mut MAX_DATA.clone(), None).unwrap();
        assert_eq!(c.hash, hash_file(&path).unwrap().hash);
        assert_eq!(c.metadata, Stamp::of(&std::fs::metadata(&path).unwrap()));
        assert_eq!(sha, digest(&path).unwrap());
        assert_eq!(hash_and_digest(&File::open(&path).unwrap(), &path).unwrap().1, sha);
        // As a dense copy of the same bytes hashes.
        let dense = dir.join("dense");
        std::fs::write(&dense, std::fs::read(&path).unwrap()).unwrap();
        assert_eq!((hash_file(&dense).unwrap().hash, digest(&dense).unwrap()), (c.hash, sha));
    }

    /// Sets `path`'s times `secs` back.
    fn aged(path: &Path, secs: i64) {
        let t = libc::timespec { tv_sec: unsafe { libc::time(std::ptr::null_mut()) } - secs, tv_nsec: 0 };
        let p = crate::util::cpath(path).unwrap();
        assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, p.as_ptr(), [t, t].as_ptr(), 0) }, 0);
    }

    fn fs_size(dir: &Path) -> u64 {
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::statvfs(crate::util::cpath(dir).unwrap().as_ptr(), &mut st) }, 0);
        st.f_blocks * st.f_frsize
    }

    #[test]
    fn push_budgets_and_the_local_reserve() {
        assert_eq!(received_budget(16 << 30), (4 << 30, 1 << 30));
        assert_eq!(received_budget(512 << 30), (64 << 30, 16 << 30));
        assert_eq!(received_budget(64 << 40), (128 << 30, 32 << 30));
        let (t, p) = (8 << 30, 2 << 30);
        assert!(check_budget(t - p, p - 1, 1, t, p).is_ok());
        assert!(check_budget(t, 0, 1, t, p).unwrap_err().to_string().contains("not in use"));
        assert!(check_budget(p, p, 1, t, p).unwrap_err().to_string().contains("one peer's"));
        assert!(check_budget(u64::MAX, u64::MAX, u64::MAX, t, p).is_err());
        // One alone may be larger than either: the room it leaves bounds it.
        assert!(check_budget(0, 0, 4 * t, t, p).is_ok());
        assert!(check_budget(1, 0, t, t, p).is_err());
        assert!(check_free(PUSH_FREE + 4096, 4096, PUSH_FREE).is_ok());
        assert!(check_free(PUSH_FREE + 4095, 4096, PUSH_FREE).is_err());
        // Local imports can use the extra GiB reserved from pushes.
        assert!(check_free(PUSH_FREE, 4096, KEEP_FREE).is_ok());
        assert!(check_free(PUSH_FREE, 4096, PUSH_FREE).unwrap_err().to_string().contains("2048 MiB free"));
        // Past any template: refused before anything is reclaimed.
        let f = Fixture::new();
        let none = BTreeSet::new;
        let push = Push { peer: "192.0.2.1".parse().unwrap(), bytes: None, in_use: &none, held: &none };
        assert!(push.check(&f.paths, 1 << 50, None).err().unwrap().to_string().contains("past"));
    }

    #[test]
    fn push_usage_counts_allocated_blocks_of_spares_holds_and_uploads() {
        let mut f = Fixture::new();
        let (tpl, buf) = sent(&mut f, ROOTFS);
        let id = tpl.meta.id.clone();
        let (_dir, paths) = elsewhere(&f);
        let peer = "192.0.2.1".parse().unwrap();
        let none = BTreeSet::new;
        let held = || BTreeSet::from([id.clone()]);
        let push = Push { peer, bytes: Some(buf.len() as u64), in_use: &none, held: &held };
        let got = push.receive(&paths, &mut &buf[..], &id, |_| Ok(())).unwrap();
        assert_eq!(std::fs::read_to_string(got.fixed.join(PUSH_PEER)).unwrap(), peer.to_string());
        let (total, ours, _) = push.usage(&paths, None).unwrap();
        assert!(total > 0 && total == ours, "arrival holds are charged");
        // Its memory file is 64 MiB long, two pages of it written: blocks, not lengths.
        assert!(total < 1 << 20, "{total}");
        let other = Push { peer: "192.0.2.2".parse().unwrap(), ..push };
        assert_eq!(other.usage(&paths, None).unwrap(), (total, 0, 0));
        let mapped = Push { peer: "::ffff:192.0.2.1".parse().unwrap(), ..push };
        assert_eq!(mapped.usage(&paths, None).unwrap(), (total, total, 0));
        // Open and just received, its hold not yet taken: charged.
        assert_eq!(Push { held: &none, ..push }.usage(&paths, None).unwrap(), (total, total, 0));
        // Open, neither held nor fresh: a VM process (or a standby, or another state's) runs it.
        aged(&got.fixed.join(RECEIVED_AT), RECLAIM_AFTER.as_secs() as i64);
        assert_eq!(Push { held: &none, ..push }.usage(&paths, None).unwrap(), (0, 0, 0));
        let used = || BTreeSet::from([id.clone()]);
        assert_eq!(Push { in_use: &used, ..push }.usage(&paths, None).unwrap(), (0, 0, 0));
        std::os::unix::fs::symlink(Path::new(GENERATIONS).join(&id), paths.templates.join("named")).unwrap();
        assert_eq!(push.usage(&paths, None).unwrap(), (0, 0, 0));
        std::fs::remove_file(paths.templates.join("named")).unwrap();
        drop(got);
        let unheld = Push { held: &none, ..push };
        assert_eq!(unheld.usage(&paths, None).unwrap(), (total, total, 0), "a spare");
        let staging = Staging::new(&paths, "abcd").unwrap();
        std::fs::write(staging.dir.join(PUSH_PEER), peer.to_string()).unwrap();
        let sparse = File::create(staging.dir.join("mem")).unwrap();
        sparse.set_len(1 << 40).unwrap();
        sparse.write_all_at(&[1; PAGE_SIZE], 0).unwrap();
        let (active, _, _) = push.usage(&paths, None).unwrap();
        assert!(active > total && active < 1 << 20, "allocated blocks of an upload, not its length");
        assert_eq!(push.usage(&paths, Some(&staging.dir)).unwrap().0, total, "its own apart");
        drop(staging);
        assert_eq!(push.usage(&paths, None).unwrap(), (total, total, 0));
        // No peer pushed it (a checkpoint's, or from before provenance): charged in all only.
        std::fs::remove_file(paths.templates.join(GENERATIONS).join(&id).join(PUSH_PEER)).unwrap();
        let (legacy, ours, _) = push.usage(&paths, None).unwrap();
        assert!(legacy > 0 && ours == 0);
    }

    /// A slow transfer's generation is fresh from its publication, not from when its transfer began.
    #[test]
    fn a_slow_receipt_is_fresh_once_published() {
        let mut f = Fixture::new();
        let (tpl, buf) = sent(&mut f, ROOTFS);
        let (_dir, paths) = elsewhere(&f);
        let staging = || std::fs::read_dir(&paths.templates).unwrap().flatten().find(|e| leftover(&e.file_name().to_string_lossy(), "new")).unwrap().path();
        let ended = std::cell::Cell::new(None);
        // Its staging aged past `RECLAIM_AFTER` as the last of it arrives, as a transfer that took that long.
        let finish = |_: &mut &[u8]| {
            let dir = staging();
            assert!(!dir.join(RECEIVED_AT).exists(), "not stamped before all of it is in");
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                aged(&e.path(), 2 * RECLAIM_AFTER.as_secs() as i64);
            }
            aged(&dir, 2 * RECLAIM_AFTER.as_secs() as i64);
            ended.set(Some(std::time::SystemTime::now()));
            Ok(())
        };
        let got = receive(&paths, &mut &buf[..], &tpl.meta.id, None, |_| Ok(()), finish).unwrap();
        let at = std::fs::metadata(got.fixed.join(RECEIVED_AT)).unwrap().modified().unwrap();
        assert!(at >= ended.get().unwrap() - Duration::from_secs(1) && fresh(&got.fixed));
    }

    #[test]
    fn understated_or_missing_push_bytes_cannot_bypass_the_peer_budget() {
        let f = Fixture::new();
        let none = BTreeSet::new;
        let (_, per_peer) = received_budget(fs_size(&f.paths.templates));
        for bytes in [Some(0), None] {
            let push = Push { peer: "192.0.2.1".parse().unwrap(), bytes, in_use: &none, held: &none };
            // Another upload of this peer's, under way.
            let other = Staging::new(&f.paths, "abcd").unwrap();
            std::fs::write(other.dir.join(PUSH_PEER), push.peer.to_string()).unwrap();
            let staging = Staging::new(&f.paths, "abcd").unwrap();
            std::fs::write(staging.dir.join(PUSH_PEER), push.peer.to_string()).unwrap();
            let len = per_peer;
            // Only extent headers: refused before reading or allocating any of the data.
            let stream: Vec<u8> = [len, 1, 0, len].into_iter().flat_map(u64::to_le_bytes).collect();
            let path = staging.dir.join("rootfs");
            let error = receive_file(&mut &stream[..], &path, 0..=MAX_FILE, &mut MAX_DATA.clone(), Some((&f.paths, &push))).unwrap_err();
            assert!(error.to_string().contains("one peer's"), "{error}");
            assert_eq!(std::fs::metadata(path).unwrap().blocks(), 0);
        }
    }

    #[test]
    fn push_pressure_reclaims_spares_but_keeps_names_records_open_and_fresh_ones() {
        let f = Fixture::new();
        let ids = [
            ("idle", "aaaa", true),
            ("named", "bbbb", true),
            ("used", "cccc", true),
            ("open", "dddd", true),
            ("built", "eeee", false),
            ("fresh", "ffff", true),
        ];
        for (name, id, received) in ids {
            publish_as(&f, name, &Meta { id: id.into(), received, ..f.meta.clone() });
            if name != "named" {
                std::fs::remove_file(f.paths.templates.join(name)).unwrap();
            }
            // Received long ago, though just used (`collect` stamps the directory): not fresh.
            let at = f.paths.templates.join(GENERATIONS).join(id).join(RECEIVED_AT);
            File::create(&at).unwrap();
            if name != "fresh" {
                aged(&at, RECLAIM_AFTER.as_secs() as i64);
            }
        }
        let open = Template::open_dir("dddd", f.paths.templates.join(GENERATIONS).join("dddd")).unwrap();
        let used = || BTreeSet::from(["cccc".into()]);
        let none = BTreeSet::new;
        let push = Push { peer: "192.0.2.1".parse().unwrap(), bytes: None, in_use: &used, held: &none };
        assert!(collect(&f.paths, RECEIVED_IDLE, &used).unwrap().is_empty());
        let abandoned = f.paths.templates.join(format!(".ffff.new-{}", crate::util::random_hex(8).unwrap()));
        std::fs::create_dir(&abandoned).unwrap();
        std::fs::write(abandoned.join(PUSH_PEER), push.peer.to_string()).unwrap();
        // Past what the spares that may go leave: reclaimed, then refused.
        let (total, _) = received_budget(fs_size(&f.paths.templates));
        assert!(push.check(&f.paths, total, None).err().unwrap().to_string().contains("not in use"));
        assert_eq!(generations(&f.paths.templates).unwrap(), ["bbbb", "cccc", "dddd", "eeee", "ffff"]);
        assert!(!abandoned.exists(), "a killed upload's staging is reclaimed too");
        // What fits is admitted.
        drop(push.check(&f.paths, 1 << 20, None).unwrap());
        drop(open);
        let unknown = || BTreeSet::from([format!("{KEEP_ALL}unreadable checkpoint")]);
        assert!(Push { in_use: &unknown, ..push }.check(&f.paths, total, None).is_err());
        assert!(Template::generation(&f.paths, "dddd").is_some());
    }

    #[test]
    fn received_generations_are_collected_once_unused_for_a_while() {
        let mut f = Fixture::new();
        let (tpl, buf) = sent(&mut f, ROOTFS);
        let id = tpl.meta.id.clone();
        let (_dir, paths) = elsewhere(&f);
        let none = || BTreeSet::new();
        let got = receive(&paths, &mut &buf[..], &id, None, |_| Ok(()), |_| Ok(())).unwrap();
        let gen = paths.templates.join(GENERATIONS).join(&id);
        let age = |secs: i64| {
            let t = libc::timespec { tv_sec: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 - secs, tv_nsec: 0 };
            let p = crate::util::cpath(&gen).unwrap();
            assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, p.as_ptr(), [t, t].as_ptr(), 0) }, 0);
        };
        // Open (a listener holds it, or a VM process runs it): kept, and stamped as used now.
        age(7200);
        assert!(collect(&paths, RECEIVED_IDLE, &none).unwrap().is_empty());
        assert!(std::fs::metadata(&gen).unwrap().modified().unwrap().elapsed().unwrap() < Duration::from_secs(60), "stamped");
        drop(got);
        // Used by a VM record or checkpoint here: kept.
        age(7200);
        assert!(collect(&paths, RECEIVED_IDLE, &|| BTreeSet::from([id.clone()])).unwrap().is_empty());
        // While a checkpoint record here cannot be read: kept, and stamped.
        age(7200);
        assert!(collect(&paths, Duration::ZERO, &|| BTreeSet::from([format!("{KEEP_ALL}a checkpoint here cannot be read")])).unwrap().is_empty());
        // Unused, but not for long: kept.
        assert!(collect(&paths, RECEIVED_IDLE, &none).unwrap().is_empty() && Template::generation(&paths, &id).is_some());
        // Named here: kept (`image prune` and `rmi` decide).
        age(7200);
        std::os::unix::fs::symlink(Path::new(GENERATIONS).join(&id), paths.templates.join("t")).unwrap();
        assert!(collect(&paths, RECEIVED_IDLE, &none).unwrap().is_empty());
        std::fs::remove_file(paths.templates.join("t")).unwrap();
        // Templates other states share: their checkpoints are not known here.
        std::fs::write(paths.templates.join(SHARED), "").unwrap();
        assert!(collect(&paths, RECEIVED_IDLE, &none).unwrap().is_empty());
        std::fs::remove_file(paths.templates.join(SHARED)).unwrap();
        // A killed receive's staging is swept by it too.
        std::fs::create_dir(paths.templates.join(format!(".{id}.new-{}", crate::util::random_hex(8).unwrap()))).unwrap();
        assert_eq!(collect(&paths, RECEIVED_IDLE, &none).unwrap(), [id.clone()]);
        assert!(nothing_in(&paths));
        // A built (pulled) one is never collected.
        drop(receive(&paths, &mut &buf[..], &id, None, |_| Ok(()), |_| Ok(())).unwrap());
        let mut meta = Meta::read(&gen).unwrap();
        meta.received = false;
        f.write_meta(&meta, &gen);
        age(7200);
        assert!(collect(&paths, Duration::ZERO, &none).unwrap().is_empty() && Template::generation(&paths, &id).is_some());
    }

    #[test]
    fn a_killed_receives_staging_is_swept_at_once() {
        let f = Fixture::new();
        let (_dir, paths) = elsewhere(&f);
        sweep_leftovers(&Paths { templates: paths.templates.join("none"), ..paths.clone() }).unwrap();
        let staging = paths.templates.join(format!(".abcd.new-{}", crate::util::random_hex(8).unwrap()));
        std::fs::create_dir(&staging).unwrap();
        let live = Staging::new(&paths, "abce").unwrap();
        sweep_leftovers(&paths).unwrap();
        assert!(!staging.exists() && live.dir.exists(), "only the dead one's");
    }

    #[test]
    fn arrivals_of_one_template_take_turns() {
        let f = Fixture::new();
        let (_dir, mut paths) = elsewhere(&f);
        paths.templates = paths.templates.join("templates");
        drop(turn(&paths, "abcd", Instant::now()).unwrap());
        let first = turn(&f.paths, "abcd", Instant::now()).unwrap();
        assert!(turn(&f.paths, "abcd", Instant::now() + Duration::from_millis(100)).is_err());
        assert!(turn(&f.paths, "abce", Instant::now()).is_ok());
        assert!(turn(&f.paths, "../x", Instant::now()).is_err());
        drop(first);
        turn(&f.paths, "abcd", Instant::now()).unwrap();
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
    fn pinned_template_errors_name_real_generation() {
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
        let mut meta = serde_json::to_value(&f.meta).unwrap();
        meta.as_object_mut().unwrap().remove("vcpus");
        std::fs::write(f.dir.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
        let error = Template::open_id(&f.paths, "t", &f.meta.id).err().unwrap().to_string();
        assert!(error.contains(&generation.display().to_string()) && error.contains("vcpus"), "{error}");
        assert!(error.contains("pins this template generation") && !error.contains("/proc/"), "{error}");
        let error = f.open().err().unwrap().to_string();
        assert!(error.contains(&f.dir.display().to_string()) && error.contains("pull it again"), "{error}");
        assert!(!error.contains("/proc/"), "{error}");
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
        assert_eq!(name_of("ubuntu:24.04").unwrap(), "ubuntu:24.04");
    }

    /// Publishes a generation `id` of `name` with the fixture's files and `meta`.
    fn publish_as(f: &Fixture, name: &str, meta: &Meta) -> Option<String> {
        let dir = f.dir.join(format!(".{name}.new-{}", meta.id));
        std::fs::create_dir_all(&dir).unwrap();
        for file in ["vmstate", "mem"] {
            std::fs::copy(f.dir.join(file), dir.join(file)).unwrap();
        }
        f.write_meta(meta, &dir);
        publish(&f.paths, name, &dir, || Ok(())).unwrap()
    }

    /// A pull deletes only the generation it moved its name off, and only when nothing uses it.
    #[test]
    fn a_pull_deletes_the_generation_it_superseded_once_unused() {
        let f = Fixture::new();
        let gen = |id: &str| Meta { id: id.into(), image: Some(image("sha256:a", "")), ..f.meta.clone() };
        let none = BTreeSet::new;
        assert_eq!(publish_as(&f, "t", &gen("aaaa1111")), None);
        assert_eq!(publish_as(&f, "t", &gen("aaaa1111")), None, "an identical build moves nothing");
        publish_as(&f, "u", &gen("eeee5555"));
        assert_eq!(publish_as(&f, "u", &gen("ffff6666")).as_deref(), Some("eeee5555"));
        let old = publish_as(&f, "t", &gen("bbbb2222")).unwrap();
        assert_eq!(old, "aaaa1111");
        let removed = prune(&f.paths, Some(&old), &none, false).unwrap();
        assert_eq!(removed, [json!({"deleted": "aaaa1111", "rootfs": null})]);
        assert_eq!(generations(&f.paths.templates).unwrap(), ["bbbb2222", "eeee5555", "ffff6666"], "another unnamed one is prune's");
        // Kept while a VM record names it, a VM process has it open, or another name links to it.
        let old = publish_as(&f, "t", &gen("cccc3333")).unwrap();
        let users = || BTreeSet::from([old.clone()]);
        assert!(prune(&f.paths, Some(&old), &users, false).unwrap().is_empty());
        let open = Template::open_dir("t", f.dir.join(GENERATIONS).join(&old)).unwrap();
        assert!(prune(&f.paths, Some(&old), &none, false).unwrap().is_empty());
        drop(open);
        tag(&f.paths, &old, "alias").unwrap();
        assert!(prune(&f.paths, Some(&old), &none, false).unwrap().is_empty());
        assert!(Template::generation(&f.paths, &old).is_some());
        // Collected once free.
        remove(&f.paths, Some("alias"), &old, &none).unwrap();
        assert!(Template::generation(&f.paths, &old).is_none());
        // Another state linking to this templates directory marks it shared (its VMs are not seen here).
        let other = crate::test_util::TempDir::new("template-sharer");
        std::os::unix::fs::symlink(&f.paths.templates, other.join("templates")).unwrap();
        let theirs = Paths { templates: other.join("templates"), ..f.paths.clone() };
        let old = publish_as(&f, "t", &gen("eeee5555")).unwrap();
        assert!(prune(&theirs, Some(&old), &none, false).unwrap().is_empty(), "pulled through a link");
        note_shared(&f.paths, &f.dir).unwrap();
        assert!(!f.paths.templates.join(SHARED).exists(), "only a link marks it");
        note_shared(&theirs, &other).unwrap();
        assert!(prune(&f.paths, Some(&old), &none, false).unwrap().is_empty() && Template::generation(&f.paths, &old).is_some());
        assert_eq!(prune(&f.paths, None, &none, false).unwrap().len(), 1, "image prune still removes it");
    }

    #[test]
    fn force_shared_reports_registry_failures_without_prune_candidates() {
        for (broken, why) in [(SHARED, "cannot be read"), (STATES, "cannot be listed"), (".states/entry", "cannot be read")] {
            let f = Fixture::new();
            if broken == SHARED {
                std::fs::create_dir(f.paths.templates.join(SHARED)).unwrap();
            } else {
                std::fs::write(f.paths.templates.join(SHARED), RECORDED).unwrap();
                if broken == STATES {
                    std::fs::write(f.paths.templates.join(STATES), b"not a directory").unwrap();
                } else {
                    std::fs::create_dir_all(f.paths.templates.join(broken)).unwrap();
                }
            }
            let error = prune(&f.paths, None, &BTreeSet::new, true).unwrap_err().to_string();
            assert!(error.contains("image prune --force-shared") && error.contains(broken) && error.contains(why), "{error}");
        }
    }

    #[test]
    fn force_shared_keeps_all_for_a_sharing_states_unreadable_checkpoint() {
        let f = Fixture::new();
        let gen = |id: &str| Meta { id: id.into(), image: Some(image("sha256:a", "")), ..f.meta.clone() };
        publish_as(&f, "t", &gen("aaaa1111"));
        let old = publish_as(&f, "t", &gen("bbbb2222")).unwrap();
        let other = crate::test_util::TempDir::new("template-sharer-unreadable");
        std::os::unix::fs::symlink(&f.paths.templates, other.join("templates")).unwrap();
        note_shared(&Paths { templates: other.join("templates"), ..f.paths.clone() }, &other).unwrap();
        std::fs::create_dir_all(other.join("suspended/web")).unwrap();
        std::fs::write(other.join("suspended/web/manifest.json"), b"not json").unwrap();
        // Not a registry failure: the prune runs, and keeps every unused generation.
        assert!(prune(&f.paths, None, &BTreeSet::new, true).unwrap().is_empty());
        assert!(Template::generation(&f.paths, &old).is_some());
        std::fs::remove_dir_all(other.join("suspended/web")).unwrap();
        assert!(!prune(&f.paths, None, &BTreeSet::new, true).unwrap().is_empty());
        assert!(Template::generation(&f.paths, &old).is_none());
    }

    #[test]
    fn force_shared_reports_failed_marker_updates_and_record_deletions() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        for marker in [true, false] {
            let f = Fixture::new();
            std::fs::write(f.paths.templates.join(SHARED), if marker { b"" } else { RECORDED }).unwrap();
            let states = f.paths.templates.join(STATES);
            std::fs::create_dir(&states).unwrap();
            std::fs::write(states.join("gone"), f.dir.join("gone-state").as_os_str().as_encoded_bytes()).unwrap();
            let readonly = if marker { &f.paths.templates } else { &states };
            let permissions = std::fs::metadata(readonly).unwrap().permissions();
            std::fs::set_permissions(readonly, std::fs::Permissions::from_mode(0o555)).unwrap();
            let result = prune(&f.paths, None, &BTreeSet::new, true);
            std::fs::set_permissions(readonly, permissions).unwrap();
            let error = result.unwrap_err().to_string();
            let (path, why) = if marker { (SHARED, "cannot be updated") } else { ("gone", "cannot be removed") };
            assert!(error.contains("image prune --force-shared") && error.contains(path) && error.contains(why), "{error}");
        }
    }

    #[test]
    fn pulling_again_rebuilds_only_what_changed() {
        let f = Fixture::new();
        let host = f.meta.compatibility.clone();
        let up_to_date =
            |paths: &Paths, name: &str, size, rootfs: &Path, image: &ImageMeta| up_to_date_with(paths, name, size, rootfs, image, || Ok(host.clone()));
        let cache = crate::test_util::TempDir::new("shared-images");
        std::fs::create_dir(cache.join("rootfs")).unwrap();
        let rootfs = cache.join("rootfs/a.ext4");
        std::fs::copy(&f.meta.rootfs, &rootfs).unwrap();
        std::os::unix::fs::symlink(&*cache, &f.paths.images).unwrap();
        let size = Size { vcpus: 2, mem_mib: 256, max_mib: 256 + 1024 + 100, plug_mib: 4096 };
        let mut meta =
            Meta { rootfs: rootfs.clone(), max_mib: 1280, plugged_mib: 1024, image: Some(image("sha256:a", "arg /x\n")), recipe: recipe(), ..f.meta.clone() };
        meta.identify(&f.paths, &f.dir).unwrap();
        publish_as(&f, "t", &meta);
        let img = image("sha256:a", "arg /x\n");
        std::fs::remove_dir_all(rootfs.with_extension("users")).unwrap();
        assert_eq!(up_to_date(&f.paths, "t", size, &rootfs, &img), Some(meta.id.clone()));
        let gen = Template::resolve(&f.paths, "t").unwrap();
        let mut incompatible = meta.clone();
        incompatible.compatibility.cpu = "changed microcode".into();
        f.write_meta(&incompatible, &gen);
        assert!(up_to_date(&f.paths, "t", size, &rootfs, &img).is_none());
        incompatible = meta.clone();
        incompatible.compatibility.tsc_khz /= 2;
        f.write_meta(&incompatible, &gen);
        assert!(up_to_date(&f.paths, "t", size, &rootfs, &img).is_none());
        f.write_meta(&meta, &gen);
        let memory = gen.join("mem");
        let bytes = std::fs::read(&memory).unwrap();
        std::fs::write(&memory, bytes).unwrap();
        assert!(up_to_date(&f.paths, "t", size, &rootfs, &img).is_some());
        assert_eq!(Meta::read(&gen).unwrap().components["mem"].metadata, Stamp::of(&std::fs::metadata(&memory).unwrap()));
        let record = rootfs.with_extension("users").join(crate::image::rootfs_user_key(&f.paths.templates).unwrap());
        assert!(record.is_file(), "reusing a legacy entry records this state without rebuilding");
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
    fn tag_refuses_received_image_by_id_and_name() {
        let f = Fixture::new();
        let meta = Meta { id: "aaaa1111".into(), received: true, image: Some(image("sha256:a", "")), ..f.meta.clone() };
        publish_as(&f, "peer", &meta);
        for source in ["aaaa", "peer"] {
            assert!(tag(&f.paths, source, "local").unwrap_err().to_string().contains("received from a peer"));
            assert!(!f.paths.templates.join("local").exists());
        }
    }

    #[test]
    fn rootfs_hash_cache_requires_local_matching_stamp() {
        let mut f = Fixture::new();
        f.meta.identify(&f.paths, &f.dir).unwrap();
        publish_as(&f, "t", &f.meta);
        let file = File::open(&f.meta.rootfs).unwrap();
        assert_eq!(cached_rootfs(&f.paths, &file).unwrap().1, digest(&f.meta.rootfs).unwrap());
        let gen = Template::resolve(&f.paths, "t").unwrap();
        f.write_meta(&Meta { received: true, ..f.meta.clone() }, &gen);
        assert!(cached_rootfs(&f.paths, &file).is_none());
        f.write_meta(&f.meta, &gen);
        std::fs::write(&f.meta.rootfs, b"changed rootfs").unwrap();
        assert!(cached_rootfs(&f.paths, &file).is_none());
    }

    #[test]
    fn booted_descriptor_keeps_identity_after_path_replacement() {
        let f = Fixture::new();
        let file = File::open(&f.paths.kernel).unwrap();
        let original = hash_open_file(&file, &f.paths.kernel).unwrap();
        f.replace("kernel", b"replacement kernel");
        assert_eq!(hash_open_file(&file, &f.paths.kernel).unwrap().hash, original.hash);
        let source = crate::host::fd_path(file.as_raw_fd());
        assert_eq!(hash_file(&source).unwrap().hash, original.hash, "the boot source reaches the pinned descriptor");
        assert_ne!(hash_file(&f.paths.kernel).unwrap().hash, original.hash);
    }

    #[test]
    fn pulls_lock_only_the_same_name() {
        let f = Fixture::new();
        let _held = pull_lock(&f.paths, "t").unwrap();
        let same = template_lock(&f.paths, "template-pull", "-t").unwrap();
        assert_eq!(crate::host::flock(&same, libc::LOCK_EX | libc::LOCK_NB).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        let _other = pull_lock(&f.paths, "other").unwrap();
    }

    #[test]
    fn tag_names_generations_and_prune_removes_only_unused_unnamed_ones() {
        let f = Fixture::new();
        let gen = |id: &str| Meta { id: id.into(), image: Some(image("sha256:a", "")), ..f.meta.clone() };
        publish_as(&f, "t", &gen("aaaa1111"));
        tag(&f.paths, "t", "ghcr.io/org/app:v1").unwrap();
        let alias = name_of("ghcr.io/org/app:v1").unwrap();
        assert_eq!(Template::resolve(&f.paths, "t").unwrap(), Template::resolve(&f.paths, &alias).unwrap());
        assert!(tag(&f.paths, "t", "../bad").is_err());
        assert!(tag(&f.paths, "missing", "new").is_err());
        // The name moves on; the alias keeps the old generation, so nothing is unnamed.
        publish_as(&f, "t", &gen("bbbb2222"));
        assert!(prune(&f.paths, None, &BTreeSet::new, false).unwrap().is_empty());
        // By ID prefix, an existing name moves too: now aaaa1111 is unnamed.
        tag(&f.paths, "bbbb", &alias).unwrap();
        publish_as(&f, "t", &gen("cccc3333"));
        let users = || BTreeSet::from(["aaaa1111".to_string()]);
        assert!(prune(&f.paths, None, &users, false).unwrap().is_empty(), "a VM record uses it");
        let handle = File::open(f.paths.templates.join(GENERATIONS).join("aaaa1111")).unwrap();
        let st = crate::util::fstat(handle.as_raw_fd()).unwrap();
        let held = crate::host::lock_at(crate::host::host_locks().unwrap(), &crate::host::use_lock(&st), libc::LOCK_SH).unwrap();
        assert!(prune(&f.paths, None, &BTreeSet::new, false).unwrap().is_empty(), "a VM process has it open");
        drop((held, handle));
        let removed = prune(&f.paths, None, &BTreeSet::new, false).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0]["deleted"], "aaaa1111");
        assert_eq!(generations(&f.paths.templates).unwrap(), ["bbbb2222", "cccc3333"]);
    }

    #[test]
    fn an_unreadable_checkpoint_keeps_every_generation_and_says_why() {
        let f = Fixture::new();
        for id in ["aaaa1111", "bbbb2222"] {
            publish_as(&f, "t", &Meta { id: id.into(), ..f.meta.clone() });
        }
        let users = || BTreeSet::from(["aaaa1111".into(), format!("{KEEP_ALL}checkpoint x is unreadable")]);
        assert!(prune(&f.paths, None, &users, false).unwrap().is_empty());
        let refusal = remove(&f.paths, None, "aaaa1111", &users).unwrap_err().to_string();
        assert_eq!(refusal, "image aaaa1111 is kept while checkpoint x is unreadable");
        let r = remove(&f.paths, Some("t"), "bbbb2222", &users).unwrap();
        assert_eq!((&r["kept"], &r["reason"]), (&json!("bbbb2222"), &json!("kept while checkpoint x is unreadable")));
        assert_eq!(generations(&f.paths.templates).unwrap(), ["aaaa1111", "bbbb2222"]);
    }

    #[test]
    fn rmi_removes_names_and_unused_generations_only() {
        let f = Fixture::new();
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
        assert!(remove(&f.paths, None, "cccc3333", &|| none.clone()).unwrap_err().to_string().contains("flexvm rmi u:latest"));
        let vm = BTreeSet::from(["aaaa1111".to_string()]);
        assert!(remove(&f.paths, None, "aaaa1111", &|| vm.clone()).is_err());
        // A name goes; its generation too, unless a VM here uses it.
        let r = remove(&f.paths, Some("t"), "bbbb2222", &|| none.clone()).unwrap();
        assert_eq!(r["deleted"], "bbbb2222");
        assert!(Template::resolve(&f.paths, "t").is_err() && Template::generation(&f.paths, "bbbb2222").is_none());
        assert!(Template::generation(&f.paths, "aaaa1111").is_some(), "an earlier pull's stays for its VMs");
        let used = BTreeSet::from(["cccc3333".to_string()]);
        assert_eq!(remove(&f.paths, Some("u"), "cccc3333", &|| used.clone()).unwrap()["kept"], "cccc3333");
        assert!(Template::resolve(&f.paths, "u").is_err() && Template::generation(&f.paths, "cccc3333").is_some());
        assert_eq!(remove(&f.paths, None, "aaaa1111", &|| none.clone()).unwrap()["deleted"], "aaaa1111");
        // A name pulled again since it was looked up is left alone.
        publish_as(&f, "v", &gen("dddd4444"));
        assert!(remove(&f.paths, Some("v"), "cccc3333", &|| none.clone()).unwrap_err().to_string().contains("pulled again"));
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
        assert_eq!(remove(&f.paths, Some("u"), "bbbb2222", &BTreeSet::new).unwrap()["rootfs"], json!(rootfs));
        assert!(!rootfs.exists());
        assert!(!tombstone.exists(), "rmi finishes earlier tombstones too");
    }

    #[test]
    fn rmi_sweeps_an_unrelated_tombstone_even_when_keeping_its_target() {
        let f = Fixture::new();
        let rootfs = f.paths.images.join("rootfs/old.ext4");
        std::fs::create_dir_all(rootfs.parent().unwrap()).unwrap();
        std::fs::write(&rootfs, b"old image").unwrap();
        publish_as(&f, "t", &Meta { id: "aaaa1111".into(), ..f.meta.clone() });
        let tombstone = f.paths.templates.join(GENERATIONS).join(".bbbb2222.rm-0000000000000001");
        std::fs::create_dir(&tombstone).unwrap();
        f.write_meta(&Meta { rootfs: rootfs.clone(), ..f.meta.clone() }, &tombstone);
        let used = BTreeSet::from(["aaaa1111".into()]);
        assert_eq!(remove(&f.paths, Some("t"), "aaaa1111", &|| used.clone()).unwrap()["kept"], "aaaa1111");
        assert!(!tombstone.exists());
        assert!(!rootfs.exists());
    }

    #[test]
    fn sweep_keeps_rootfs_outside_the_states_image_cache() {
        let f = Fixture::new();
        let rootfs = f.dir.join("other-cache/rootfs/a.ext4");
        std::fs::create_dir_all(rootfs.parent().unwrap()).unwrap();
        std::fs::write(&rootfs, b"external rootfs").unwrap();
        let tombstone = f.paths.templates.join(GENERATIONS).join(".aaaa1111.rm-0000000000000001");
        std::fs::create_dir_all(&tombstone).unwrap();
        f.write_meta(&Meta { rootfs: rootfs.clone(), ..f.meta.clone() }, &tombstone);
        sweep(&f.paths).unwrap();
        assert!(!tombstone.exists());
        assert!(rootfs.exists());
    }

    #[test]
    fn rmi_tracks_rootfs_in_a_symlinked_cache_shared_by_two_states() {
        let a = Fixture::new();
        let b = Fixture::new();
        let cache = crate::test_util::TempDir::new("shared-images");
        std::fs::create_dir(cache.join("rootfs")).unwrap();
        let rootfs = cache.join("rootfs/a.ext4");
        for ext in ["ext4", "ok", "conf"] {
            std::fs::write(rootfs.with_extension(ext), b"image").unwrap();
        }
        // As a build makes it: an entry without one is legacy.
        std::fs::create_dir(rootfs.with_extension("users")).unwrap();
        for f in [&a, &b] {
            std::os::unix::fs::symlink(&*cache, &f.paths.images).unwrap();
            publish_as(f, "t", &Meta { id: "aaaa1111".into(), rootfs: rootfs.clone(), ..f.meta.clone() });
        }
        assert_eq!(remove(&a.paths, Some("t"), "aaaa1111", &BTreeSet::new).unwrap()["rootfs"], Value::Null);
        assert!(generation_ids(&a.paths.templates).is_empty());
        let generation = Template::resolve(&b.paths, "t").unwrap();
        assert_eq!(Meta::read(&generation).unwrap().rootfs, rootfs);
        assert_eq!(std::fs::read(&rootfs).unwrap(), b"image");
        assert_eq!(remove(&b.paths, Some("t"), "aaaa1111", &BTreeSet::new).unwrap()["rootfs"], json!(rootfs));
        assert!(generation_ids(&b.paths.templates).is_empty());
        // The last state removes the entry and its records.
        for ext in ["ext4", "ok", "conf", "users"] {
            assert!(!rootfs.with_extension(ext).exists());
        }
    }

    #[test]
    fn a_symlinked_cache_frees_rootfs_after_the_last_local_generation() {
        for removal in ["rmi", "prune", "sweep"] {
            let f = Fixture::new();
            let cache = crate::test_util::TempDir::new("shared-images");
            std::fs::create_dir(cache.join("rootfs")).unwrap();
            let rootfs = cache.join("rootfs/a.ext4");
            for ext in ["ext4", "ok", "conf"] {
                std::fs::write(rootfs.with_extension(ext), b"image").unwrap();
            }
            // As a build makes it: an entry without one is legacy.
            std::fs::create_dir(rootfs.with_extension("users")).unwrap();
            std::os::unix::fs::symlink(&*cache, &f.paths.images).unwrap();
            for (name, id) in [("t", "aaaa1111"), ("u", "bbbb2222")] {
                publish_as(&f, name, &Meta { id: id.into(), rootfs: rootfs.clone(), ..f.meta.clone() });
            }
            let record = rootfs.with_extension("users").join(crate::image::rootfs_user_key(&f.paths.templates).unwrap());
            assert!(record.is_file());
            remove(&f.paths, Some("t"), "aaaa1111", &BTreeSet::new).unwrap();
            assert!(rootfs.exists() && record.exists(), "another local generation still uses it");
            match removal {
                "rmi" => {
                    remove(&f.paths, Some("u"), "bbbb2222", &BTreeSet::new).unwrap();
                }
                "prune" => {
                    std::fs::remove_file(f.paths.templates.join("u")).unwrap();
                    assert_eq!(prune(&f.paths, None, &BTreeSet::new, false).unwrap().len(), 1);
                }
                _ => {
                    std::fs::remove_file(f.paths.templates.join("u")).unwrap();
                    let gens = f.paths.templates.join(GENERATIONS);
                    std::fs::rename(gens.join("bbbb2222"), gens.join(".bbbb2222.rm-0000000000000001")).unwrap();
                    sweep(&f.paths).unwrap();
                    assert!(std::fs::read_dir(gens).unwrap().next().is_none());
                }
            }
            for ext in ["ext4", "ok", "conf", "users"] {
                assert!(!rootfs.with_extension(ext).exists(), "{removal}: {ext}");
            }
        }
    }

    #[test]
    fn a_shared_entry_kept_for_legacy_or_gone_states_goes_with_force_shared() {
        let f = Fixture::new();
        let other = crate::test_util::TempDir::new("other-templates");
        let cache = crate::test_util::TempDir::new("shared-images");
        std::fs::create_dir(cache.join("rootfs")).unwrap();
        let rootfs = cache.join("rootfs/a.ext4");
        // Built by an older flexvm: no records, and states that have not pulled since may use it.
        for ext in ["ext4", "ok", "conf"] {
            std::fs::write(rootfs.with_extension(ext), b"image").unwrap();
        }
        std::os::unix::fs::symlink(&*cache, &f.paths.images).unwrap();
        // A crash left a half-made records directory: never renamed into place, it is made again.
        std::fs::create_dir(rootfs.with_extension("newusers")).unwrap();
        std::fs::write(rootfs.with_extension("newusers").join("junk"), b"").unwrap();
        publish_as(&f, "t", &Meta { id: "aaaa1111".into(), rootfs: rootfs.clone(), ..f.meta.clone() });
        let users = rootfs.with_extension("users");
        assert!(users.join("legacy").is_file() && !users.join("junk").exists() && !rootfs.with_extension("newusers").exists());
        for dir in [&*other, Path::new("/nonexistent/templates")] {
            std::fs::write(users.join(state_key(dir)), dir.as_os_str().as_encoded_bytes()).unwrap();
        }
        assert_eq!(remove(&f.paths, Some("t"), "aaaa1111", &BTreeSet::new).unwrap()["rootfs"], Value::Null);
        assert!(prune(&f.paths, None, &BTreeSet::new, false).unwrap().is_empty());
        assert!(rootfs.exists() && users.join("legacy").exists());
        // --force-shared forgets the legacy users and the gone state, not one whose templates are there.
        assert!(prune(&f.paths, None, &BTreeSet::new, true).unwrap().is_empty());
        let left: Vec<_> = std::fs::read_dir(&users).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, [std::ffi::OsString::from(state_key(&other))]);
        drop(other);
        assert_eq!(prune(&f.paths, None, &BTreeSet::new, true).unwrap(), [json!({"rootfs": rootfs})]);
        for ext in ["ext4", "ok", "conf", "users"] {
            assert!(!rootfs.with_extension(ext).exists());
        }
        // A record a crash left before its generation was published goes with the next prune.
        for ext in ["ext4", "ok", "conf"] {
            std::fs::write(rootfs.with_extension(ext), b"image").unwrap();
        }
        std::fs::create_dir(&users).unwrap();
        crate::image::note_rootfs(&f.paths.images, &rootfs, &std::fs::canonicalize(&f.paths.templates).unwrap()).unwrap();
        assert_eq!(prune(&f.paths, None, &BTreeSet::new, false).unwrap(), [json!({"rootfs": rootfs})]);
        assert!(!rootfs.exists() && !users.exists());
    }

    #[test]
    fn force_shared_protects_an_unrecorded_v3_entry_used_by_another_state() {
        let a = Fixture::new();
        let b = Fixture::new();
        let cache = crate::test_util::TempDir::new("v3-images");
        std::fs::create_dir(cache.join("rootfs")).unwrap();
        let rootfs = cache.join("rootfs/v3.ext4");
        for ext in ["ext4", "ok", "conf"] {
            std::fs::write(rootfs.with_extension(ext), b"old image").unwrap();
        }
        for f in [&a, &b] {
            std::os::unix::fs::symlink(&*cache, &f.paths.images).unwrap();
        }
        publish_as(&b, "old", &Meta { id: "aaaa1111".into(), rootfs: rootfs.clone(), ..b.meta.clone() });
        // Before #983: its v3 key cannot be reused by today's pull, and no record exists.
        std::fs::remove_dir_all(rootfs.with_extension("users")).unwrap();
        assert!(prune(&a.paths, None, &BTreeSet::new, true).unwrap().is_empty());
        assert_eq!(std::fs::read(&rootfs).unwrap(), b"old image");
        assert_eq!(Meta::read(&b.paths.templates.join(GENERATIONS).join("aaaa1111")).unwrap().rootfs, rootfs);
    }

    #[test]
    fn prune_records_existing_generations_and_open_refreshes_a_moved_state() {
        let mut f = Fixture::new();
        let cache = crate::test_util::TempDir::new("old-images");
        std::fs::create_dir(cache.join("rootfs")).unwrap();
        let rootfs = cache.join("rootfs/v3.ext4");
        for ext in ["ext4", "ok", "conf"] {
            std::fs::write(rootfs.with_extension(ext), b"old image").unwrap();
        }
        std::os::unix::fs::symlink(&*cache, &f.paths.images).unwrap();
        publish_as(&f, "old", &Meta { id: "aaaa1111".into(), rootfs: rootfs.clone(), ..f.meta.clone() });
        let users = rootfs.with_extension("users");
        std::fs::remove_dir_all(&users).unwrap();
        assert!(prune(&f.paths, None, &BTreeSet::new, true).unwrap().is_empty());
        let key = crate::image::rootfs_user_key(&f.paths.templates).unwrap();
        assert_eq!(std::fs::read(users.join(&key)).unwrap(), f.paths.templates.as_os_str().as_encoded_bytes());
        assert!(users.join("legacy").exists());
        // Move the directory itself so its inode (and therefore its record key) stays the same.
        let state = crate::test_util::TempDir::new("moved-state");
        let templates = state.join("templates");
        std::fs::rename(&f.paths.templates, &templates).unwrap();
        f.paths.images = templates.join("images");
        f.paths.templates = templates;
        // The same helper Host::open calls, without creating a host or starting VMs.
        note_rootfs(&f.paths).unwrap();
        assert_eq!(crate::image::rootfs_user_key(&f.paths.templates).unwrap(), key);
        assert_eq!(std::fs::read(users.join(&key)).unwrap(), f.paths.templates.as_os_str().as_encoded_bytes());
        assert_eq!(std::fs::read_dir(&users).unwrap().count(), 2, "one state record plus legacy");
        // TempDir still owns the old path, so restore it for cleanup.
        std::fs::rename(&f.paths.templates, &*f.dir).unwrap();
    }

    #[test]
    fn prune_skips_a_bad_cache_entry_and_removes_the_next() {
        let f = Fixture::new();
        let dir = f.paths.images.join("rootfs");
        std::fs::create_dir_all(&dir).unwrap();
        for key in ["a", "b"] {
            for ext in ["ext4", "ok", "conf"] {
                std::fs::write(dir.join(format!("{key}.{ext}")), b"image").unwrap();
            }
        }
        std::fs::write(dir.join("a.users"), b"not a directory").unwrap();
        std::fs::create_dir(dir.join("b.users")).unwrap();
        assert_eq!(prune(&f.paths, None, &BTreeSet::new, false).unwrap(), [json!({"rootfs": dir.join("b.ext4")})]);
        assert!(dir.join("a.ext4").exists());
        assert!(!dir.join("b.users").exists());
    }

    #[test]
    fn sweep_handles_legacy_rootfs_without_records() {
        for linked in [false, true] {
            let f = Fixture::new();
            let cache = crate::test_util::TempDir::new("shared-images");
            if linked {
                std::os::unix::fs::symlink(&*cache, &f.paths.images).unwrap();
            }
            let dir = if linked { cache.join("rootfs") } else { f.paths.images.join("rootfs") };
            std::fs::create_dir_all(&dir).unwrap();
            let rootfs = dir.join("a.ext4");
            std::fs::write(&rootfs, b"image").unwrap();
            let tombstone = f.paths.templates.join(GENERATIONS).join(".aaaa1111.rm-0000000000000001");
            std::fs::create_dir_all(&tombstone).unwrap();
            f.write_meta(&Meta { rootfs: rootfs.clone(), ..f.meta.clone() }, &tombstone);
            sweep(&f.paths).unwrap();
            assert!(!tombstone.exists());
            assert_eq!(rootfs.exists(), linked);
            assert!(!rootfs.with_extension("users").exists());
            if linked {
                // Never recorded: even --force-shared cannot know which other states use it.
                for ext in ["ok", "conf"] {
                    std::fs::write(rootfs.with_extension(ext), b"").unwrap();
                }
                assert!(prune(&f.paths, None, &BTreeSet::new, false).unwrap().is_empty());
                assert!(rootfs.exists());
                assert!(prune(&f.paths, None, &BTreeSet::new, true).unwrap().is_empty());
                assert!(rootfs.exists() && rootfs.with_extension("ok").exists());
            }
        }
    }

    #[test]
    fn a_symlinked_rootfs_directory_is_neither_recorded_nor_pruned() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let outside = crate::test_util::TempDir::new("outside-rootfs");
        let rootfs = outside.join("a.ext4");
        for ext in ["ext4", "ok", "conf"] {
            std::fs::write(rootfs.with_extension(ext), b"image").unwrap();
        }
        std::fs::create_dir(rootfs.with_extension("users")).unwrap();
        std::fs::set_permissions(rootfs.with_extension("users"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(&f.paths.images).unwrap();
        std::os::unix::fs::symlink(&*outside, f.paths.images.join("rootfs")).unwrap();
        publish_as(&f, "t", &Meta { id: "aaaa1111".into(), rootfs: rootfs.clone(), ..f.meta.clone() });
        for force in [false, true] {
            assert!(prune(&f.paths, None, &BTreeSet::new, force).unwrap().is_empty());
        }
        assert_eq!(remove(&f.paths, Some("t"), "aaaa1111", &BTreeSet::new).unwrap()["rootfs"], Value::Null);
        assert!(rootfs.exists() && rootfs.with_extension("ok").exists());
        let users = rootfs.with_extension("users");
        assert_eq!(std::fs::read_dir(&users).unwrap().count(), 0);
        assert_eq!(std::fs::metadata(&users).unwrap().permissions().mode() & 0o777, 0o755);
    }

    #[test]
    fn a_tombstone_sweep_cannot_remove_does_not_stop_builds() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let gens = f.paths.templates.join(GENERATIONS);
        std::fs::create_dir_all(&gens).unwrap();
        let stuck = gens.join(".aaaa1111.rm-0000000000000001/stuck");
        std::fs::create_dir_all(&stuck).unwrap();
        std::fs::write(stuck.join("file"), b"x").unwrap();
        std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o555)).unwrap();
        let removable = std::fs::remove_file(stuck.join("file")).is_ok(); // as root
        let res = sweep(&f.paths);
        // As root the sweep could remove it all.
        if stuck.exists() {
            std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        res.unwrap();
        assert!(removable || stuck.exists());
        assert!(Staging::new(&f.paths, "t").is_ok());
    }

    #[test]
    fn sweep_keepsrootfs_used_by_a_live_generation() {
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
        assert_eq!(remove(&f.paths, Some("t"), "aaaa1111", &BTreeSet::new).unwrap()["rootfs"], json!(rootfs));
        assert!(!rootfs.exists());
    }

    #[test]
    fn rmi_keeps_a_generation_a_vm_process_has_open() {
        let f = Fixture::new();
        publish_as(&f, "t", &Meta { id: "aaaa1111".into(), image: Some(image("sha256:a", "")), ..f.meta.clone() });
        // A cold run between opening its template and registering its VM: no VM entry names it.
        let starting = Template::open(&f.paths, "t").unwrap();
        let none = BTreeSet::new();
        let r = remove(&f.paths, Some("t"), "aaaa1111", &|| none.clone()).unwrap();
        assert_eq!((r["kept"].as_str(), r["reason"].as_str()), (Some("aaaa1111"), Some("open in a VM process here")));
        assert!(remove(&f.paths, None, "aaaa1111", &|| none.clone()).unwrap_err().to_string().contains("open in a VM process"));
        assert!(Template::generation(&f.paths, "aaaa1111").is_some());
        assert_eq!(starting.pages(0, 0).len(), 0);
        drop(starting);
        assert_eq!(remove(&f.paths, None, "aaaa1111", &|| none.clone()).unwrap()["deleted"], "aaaa1111");
        assert!(Template::open_dir("t", f.dir.join(GENERATIONS).join("aaaa1111")).is_err());
    }

    /// #631: a VM that suspends while `rmi` runs lets its use lock go only after its checkpoint (the
    /// record that names the generation) is published, so `rmi` must read the records after it holds
    /// the use lock exclusively, not before: every round, the VM is a user at each moment, and the
    /// generation stays.
    #[test]
    fn rmi_keeps_the_generation_of_a_vm_that_suspends_meanwhile() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{mpsc, Arc};
        let f = Fixture::new();
        let (mut open_seen, mut record_seen) = (0, 0);
        for round in 0..200u32 {
            let id = format!("{:08x}", 0xa000_0000u32 + round);
            publish_as(&f, "t", &Meta { id: id.clone(), image: Some(image("sha256:a", "")), ..f.meta.clone() });
            let suspended = Arc::new(AtomicBool::new(false));
            let tpl = Template::open(&f.paths, "t").unwrap();
            let (go, started) = mpsc::channel();
            let vm = {
                let suspended = suspended.clone();
                std::thread::spawn(move || {
                    started.recv().unwrap();
                    for _ in 0..round % 50 {
                        std::thread::yield_now();
                    }
                    // The suspend: its checkpoint published, then the process ends.
                    suspended.store(true, Ordering::SeqCst);
                    drop(tpl);
                })
            };
            let gen = Template::generation(&f.paths, &id).unwrap();
            let in_use = || {
                // Read under the exclusive use lock: no process may take it shared now.
                let st = crate::util::fstat(File::open(&gen).unwrap().as_raw_fd()).unwrap();
                let lock = crate::host::open_lock(&crate::host::host_locks().unwrap(), crate::host::use_lock(&st).as_ref()).unwrap();
                assert!(crate::host::flock(&lock, libc::LOCK_SH | libc::LOCK_NB).is_err(), "read before the use lock was held");
                if suspended.load(Ordering::SeqCst) {
                    BTreeSet::from([id.clone()])
                } else {
                    BTreeSet::new()
                }
            };
            go.send(()).unwrap();
            let r = remove(&f.paths, Some("t"), &id, &in_use).unwrap();
            vm.join().unwrap();
            match r["reason"].as_str() {
                Some("open in a VM process here") => open_seen += 1,
                Some("used by a VM here") => record_seen += 1,
                _ => panic!("round {round}: the generation of a VM suspending meanwhile went: {r}"),
            }
            assert!(Template::generation(&f.paths, &id).is_some());
        }
        assert!(record_seen > 0, "no round saw the VM suspended first ({open_seen} saw it open)");
    }

    /// A tombstone stays a rootfs user while a pull holds the rootfs: kept (its `meta.json` only) and
    /// asked again by each sweep, so a pull that fails leaves no rootfs behind that nothing removes.
    #[test]
    fn a_tombstone_waits_for_a_pull_holding_its_rootfs() {
        let f = Fixture::new();
        let cache = crate::test_util::TempDir::new("shared-images");
        std::os::unix::fs::symlink(&*cache, &f.paths.images).unwrap();
        let rootfs = cache.join("rootfs/a.ext4");
        std::fs::create_dir_all(rootfs.parent().unwrap()).unwrap();
        for ext in ["ext4", "ok", "conf"] {
            std::fs::write(rootfs.with_extension(ext), b"image").unwrap();
        }
        // As a build makes it: an entry without one is legacy.
        std::fs::create_dir(rootfs.with_extension("users")).unwrap();
        publish_as(&f, "t", &Meta { id: "aaaa1111".into(), rootfs: rootfs.clone(), ..f.meta.clone() });
        let st = crate::util::fstat(File::open(&rootfs).unwrap().as_raw_fd()).unwrap();
        let pulling = crate::host::shared_at(&crate::host::host_locks().unwrap(), &crate::host::use_lock(&st)).unwrap();
        let r = remove(&f.paths, Some("t"), "aaaa1111", &BTreeSet::new).unwrap();
        assert_eq!((r["deleted"].as_str(), &r["rootfs"]), (Some("aaaa1111"), &Value::Null));
        let gens = f.paths.templates.join(GENERATIONS);
        let left: Vec<PathBuf> = std::fs::read_dir(&gens).unwrap().map(|e| e.unwrap().path()).collect();
        assert_eq!(left.len(), 1, "the tombstone stays");
        let files: Vec<_> = std::fs::read_dir(&left[0]).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(files, ["meta.json"]);
        sweep(&f.paths).unwrap();
        assert!(left[0].exists() && rootfs.exists(), "still held");
        // The pull failed: the next sweep removes the rootfs, then the tombstone.
        drop(pulling);
        sweep(&f.paths).unwrap();
        assert!(!left[0].exists() && !rootfs.exists() && !rootfs.with_extension("ok").exists());
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
        // Older kernels may keep ctime unchanged for writes within the same tick.
        crate::test_util::wait_until("rootfs rewrite to change its stamp", || {
            file.write_all_at(b"ROOTFS", 0).unwrap();
            set_mtime(&file, before.mtime(), before.mtime_nsec());
            Stamp::of(&file.metadata().unwrap()) != Stamp::of(&before)
        });
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
        let before = Stamp::of(&file.metadata().unwrap());
        // Keep the cached stamp in place: this must exercise invalidation, even on
        // kernels whose ctime only advances once per tick.
        crate::test_util::wait_until("memory rewrite to change its stamp", || {
            file.write_all_at(&[2; PAGE_SIZE], (5 * PAGE_SIZE) as u64).unwrap();
            file.sync_all().unwrap();
            Stamp::of(&file.metadata().unwrap()) != before
        });
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
