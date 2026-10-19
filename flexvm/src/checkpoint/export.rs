//! `checkpoint save` and `checkpoint load` (#775): one self-contained tar of a stored checkpoint,
//! its chain and its template generation, and its import, all verified before it is published.
//!
//! Members, in this order: `flexvm-checkpoint.json` (the `Header`); for each checkpoint of the
//! chain, oldest first, `checkpoints/ID/manifest.json`, `vmstate`, `pagemap` and `pages`; then,
//! unless the head's manifest records no template digests (v0.1.0's), `template/TEMPLATE_ID`: the
//! generation as `template::send` writes it (its files' data extents, so holes stay holes).
//!
//! The loader reads only these names, in this order, each within its limit, and takes no path from
//! the archive: names are compared, never opened. A checkpoint is verified by its id (its manifest's
//! checksum, which covers its files' checksums and its pages' CRC32C) and its place in the chain;
//! the template by its content id and the SHA-256 digests the head's manifest records, before it is
//! published (`template::receive`), and only if this host has no generation of that id. No name of
//! a template is read, taken or moved: the source's tags may name other builds than this host's.
use super::{
    bail,
    chain::{chain_meta_budget, read_at},
    format::{parse_pagemap, sum, DATA, MAX_VMSTATE},
    open_at, open_dir_at, read_manifest, store, Checkpoint, Manifest, Parent, Staging, FORMAT, FORMAT_INCREMENTAL, MAX_CHAIN,
};
use crate::{
    template::{self, Paths, Template},
    util::{Result, PAGE_SIZE},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsRawFd, OwnedFd},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

pub const HEADER: &str = "flexvm-checkpoint.json";
const EXPORT_FORMAT: u64 = 1;
const MAX_HEADER: u64 = 64 << 10;
const MAX_MANIFEST: u64 = 1 << 20;
/// Zero bytes past the end of the archive that are taken as padding (a tar record's, as `tar` pads).
const MAX_TAIL: u64 = 1 << 20;
/// Guest memory of `template::receive`'s limit (2 TiB), in pages.
const MAX_GUEST_PAGES: u64 = 1 << 29;
/// Room a loaded checkpoint's pages leave on the store's filesystem.
const KEEP_FREE: u64 = 1 << 30;
/// How long a load waits for another arrival of its template (a migration's push) to finish.
const TURN_WAIT: Duration = Duration::from_secs(600);
const BLOCK: usize = 512;

/// The first member: what follows, by id.
#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    pub format: u64,
    pub id: String,
    /// Its name in the saving host's store.
    pub name: Option<String>,
    /// Its ids, the head's first, as each child names its parent.
    pub chain: Vec<String>,
    pub template_id: String,
    /// Whether `template/TEMPLATE_ID` follows the checkpoints.
    pub template: bool,
}

fn warn(what: std::fmt::Arguments) {
    let _ = writeln!(io::stderr(), "flexvm: warning: {what}");
}

pub fn checkpoint_member(id: &str, file: &str) -> String {
    format!("checkpoints/{id}/{file}")
}

pub fn template_member(id: &str) -> String {
    format!("template/{id}")
}

/// A save's SHA-256, which `save` and `load` print and `load --sha256` requires: of each checkpoint of
/// the chain, oldest first, its id and its files as saved (name, length, SHA-256). The checkpoints'
/// own ids and checksums are no cryptographic check; the head's manifest, so this, covers the
/// template's digests.
#[derive(Default)]
struct SaveDigest(Sha256);

impl SaveDigest {
    fn checkpoint(&mut self, id: &str) {
        self.0.update(id.as_bytes());
    }

    fn file(&mut self, name: &str, len: u64, sha: &[u8]) {
        self.0.update(name.as_bytes());
        self.0.update(len.to_le_bytes());
        self.0.update(sha);
    }

    fn finish(self) -> String {
        format!("{:x}", self.0.finalize())
    }
}

/// Hashes what is read through it.
struct Hashing<R> {
    r: R,
    h: Sha256,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.r.read(buf)?;
        self.h.update(&buf[..n]);
        Ok(n)
    }
}

// --- tar framing: GNU headers, regular files only -------------------------------------------

/// Counts what it writes, so each member is checked against the size its header declared.
struct TarOut<W: Write> {
    w: W,
    n: u64,
}

impl<W: Write> Write for TarOut<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let k = self.w.write(b)?;
        self.n += k as u64;
        Ok(k)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

fn padding(size: u64) -> usize {
    (BLOCK - (size % BLOCK as u64) as usize) % BLOCK
}

impl<W: Write> TarOut<W> {
    fn member(&mut self, name: &str, size: u64, body: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_path(name)?;
        h.set_size(size);
        h.set_mode(0o600);
        h.set_mtime(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()));
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        self.write_all(h.as_bytes())?;
        let start = self.n;
        body(self)?;
        ensure!(self.n - start == size, "{name}: wrote {} bytes, not the {size} declared", self.n - start);
        self.write_all(&[0u8; BLOCK][..padding(size)])?;
        Ok(())
    }

    fn bytes(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        self.member(name, bytes.len() as u64, |w| Ok(w.write_all(bytes)?))
    }

    fn finish(&mut self) -> Result<u64> {
        self.write_all(&[0u8; 2 * BLOCK])?;
        self.flush()?;
        Ok(self.n)
    }
}

/// Reads members by the names expected next; a member's bytes are read through it (`Read`), up to its size.
struct TarIn<'a> {
    r: &'a mut dyn Read,
    left: u64,
    pad: usize,
}

fn truncated(e: io::Error) -> crate::util::Error {
    match e.kind() {
        io::ErrorKind::UnexpectedEof => "the archive is truncated".into(),
        _ => e.into(),
    }
}

impl Read for TarIn<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        if n == 0 {
            return Ok(0);
        }
        let got = self.r.read(&mut buf[..n])?;
        if got == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.left -= got as u64;
        Ok(got)
    }
}

impl TarIn<'_> {
    fn skip(&mut self) -> Result<()> {
        io::copy(self, &mut io::sink()).map_err(truncated)?;
        let mut pad = [0u8; BLOCK];
        self.r.read_exact(&mut pad[..self.pad]).map_err(truncated)?;
        self.pad = 0;
        Ok(())
    }

    /// The next member, which must be `want`: its size.
    fn member(&mut self, want: &str) -> Result<u64> {
        self.skip()?;
        let mut block = [0u8; BLOCK];
        self.r.read_exact(&mut block).map_err(truncated)?;
        ensure!(block.iter().any(|&b| b != 0), "the archive ends before {want}");
        let h = tar::Header::from_byte_slice(&block);
        let sum: u64 = block.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { b as u64 }).sum();
        ensure!(h.cksum().ok().map(u64::from) == Some(sum), "bad tar header before {want}: not a flexvm checkpoint save");
        ensure!(h.path_bytes().as_ref() == want.as_bytes(), "{want} expected, found {:?}", String::from_utf8_lossy(&h.path_bytes()));
        ensure!(h.entry_type() == tar::EntryType::Regular, "{want} is not a regular file");
        let size = h.size().map_err(|e| format!("{want}: bad size: {e}"))?;
        (self.left, self.pad) = (size, padding(size));
        Ok(size)
    }

    /// Nothing after the last member: the two zero blocks that end an archive, then at most `MAX_TAIL`
    /// zero bytes of padding up to the end of the input.
    fn end(&mut self) -> Result<()> {
        self.skip()?;
        let mut block = [0u8; 2 * BLOCK];
        self.r.read_exact(&mut block[..BLOCK]).map_err(truncated)?;
        ensure!(block.iter().all(|&b| b == 0), "the archive has more than one checkpoint save");
        self.r.read_exact(&mut block[BLOCK..]).map_err(truncated)?;
        let mut tail = vec![];
        (&mut *self.r).take(MAX_TAIL + 1).read_to_end(&mut tail)?;
        ensure!(block.iter().chain(&tail).all(|&b| b == 0) && tail.len() as u64 <= MAX_TAIL, "the archive has more than one checkpoint save");
        Ok(())
    }
}

// --- save -------------------------------------------------------------------------------------

/// A chain member's files, read and checked under the store's lock: its pages stay readable once open.
struct Saved {
    id: String,
    manifest: Vec<u8>,
    vmstate: Vec<u8>,
    pagemap: Vec<u8>,
    pages: File,
    pages_len: u64,
}

fn read_member(dir: &Path, id: &str) -> Result<Saved> {
    let bad = |why: String| format!("checkpoint {}: {why}", dir.display());
    let dfd = open_dir_at(libc::AT_FDCWD, &CString::new(dir.as_os_str().as_bytes())?).map_err(|e| bad(e.to_string()))?;
    let (_, text) = read_at(dfd.as_raw_fd(), "manifest.json", MAX_MANIFEST).map_err(|e| bad(format!("manifest.json: {e}")))?;
    let (sum_line, body) = text.split_at(text.iter().position(|&b| b == b'\n').ok_or_else(|| bad("manifest has no checksum".into()))?);
    ensure!(sum_line == id.as_bytes() && sum(&body[1..]) == id, "{}", bad("it changed as it was saved".into()));
    let manifest: Manifest = serde_json::from_slice(&body[1..])?;
    let read = |name: &str| -> Result<Vec<u8>> {
        let want = manifest.files.get(name).ok_or_else(|| bad(format!("manifest lists no {name}")))?;
        let (_, bytes) = read_at(dfd.as_raw_fd(), name, want.len + 1).map_err(|e| bad(format!("{name}: {e}")))?;
        ensure!(bytes.len() as u64 == want.len && sum(&bytes) == want.hash, "{}", bad(format!("{name} does not match its checksum")));
        Ok(bytes)
    };
    let (vmstate, pagemap) = (read("vmstate")?, read("pagemap")?);
    let (pages, _) = read_at(dfd.as_raw_fd(), "pages", 0).map_err(|e| bad(format!("pages: {e}")))?;
    let pages_len = pages.metadata()?.len();
    ensure!(Some(pages_len) == manifest.files.get("pages").map(|f| f.len), "{}", bad("pages has the wrong length".into()));
    Ok(Saved { id: id.into(), manifest: text, vmstate, pagemap, pages, pages_len })
}

/// `checkpoint save`: stored checkpoint `what`, its chain and its template generation, as one tar
/// written to `w`. Returns what it wrote.
pub fn save(state: &Path, paths: &Paths, what: &str, w: &mut dyn Write) -> Result<Value> {
    // Everything is opened under the store's lock, so no removal takes part of it; held no longer,
    // so a slow reader holds up no `checkpoint rm`. The open generation is kept by its use lock.
    let lock = store::lock(state, libc::LOCK_SH)?;
    let all = store::list(state);
    let entry = store::find(&all, what)?;
    let ck = Checkpoint::open(&entry.dir)?;
    let dirs: Vec<(PathBuf, String)> =
        std::iter::once((ck.dir.clone(), ck.id.clone())).chain(ck.chain.iter().cloned().zip(ck.chain_ids.iter().cloned())).collect();
    let mut members = dirs.iter().map(|(dir, id)| read_member(dir, id)).collect::<Result<Vec<_>>>()?;
    members.reverse();
    let (tid, digests) = (&ck.manifest.template_id, ck.manifest.template_digests.as_ref());
    let tpl = Template::generation(paths, tid)
        .map(|dir| Template::open_dir(tid, dir))
        .transpose()?
        .ok_or_else(|| format!("checkpoint {what}: its template generation {tid} is not here"))?;
    drop(lock);
    // What a loader would refuse: refused here, before anything is written.
    if let (Some(want), Some(have)) = (digests, tpl.meta.digests.as_ref()) {
        ensure!(want == have, "checkpoint {what}: template {tid} here does not match the SHA-256 digests the checkpoint records");
    }
    tpl.check_vouched(digests, "the checkpoint")?;
    let sending = digests.map(|_| template::Sending::new(&tpl)).transpose()?;
    if sending.is_none() {
        warn(format_args!(
            "checkpoint {what} records no SHA-256 digests of its template (taken by v0.1.0, or on a template it built): saved without template {tid}, which the loading host must have"
        ));
    }
    let header = Header {
        format: EXPORT_FORMAT,
        id: ck.id.clone(),
        name: entry.name.clone(),
        chain: dirs.iter().map(|(_, id)| id.clone()).collect(),
        template_id: tid.clone(),
        template: sending.is_some(),
    };
    let mut out = TarOut { w, n: 0 };
    out.bytes(HEADER, &serde_json::to_vec_pretty(&header)?)?;
    let mut digest = SaveDigest::default();
    for m in members {
        digest.checkpoint(&m.id);
        for (name, bytes) in [("manifest.json", &m.manifest), ("vmstate", &m.vmstate), ("pagemap", &m.pagemap)] {
            out.bytes(&checkpoint_member(&m.id, name), bytes)?;
            digest.file(name, bytes.len() as u64, &Sha256::digest(bytes));
        }
        let mut pages = Hashing { r: (&m.pages).take(m.pages_len), h: Sha256::new() };
        out.member(&checkpoint_member(&m.id, "pages"), m.pages_len, |w| {
            let copied = io::copy(&mut pages, w)?;
            ensure!(copied == m.pages_len, "checkpoint {}: its pages file is shorter than its manifest says", m.id);
            Ok(())
        })?;
        digest.file("pages", m.pages_len, &pages.h.finalize());
    }
    if let Some(s) = sending {
        out.member(&template_member(tid), s.len(), |w| s.write(w).map(drop))?;
    }
    let bytes = out.finish()?;
    Ok(json!({"saved": ck.id, "name": entry.name, "chain": header.chain.len(), "template_id": tid, "template": header.template, "bytes": bytes,
              "sha256": digest.finish()}))
}

// --- load -------------------------------------------------------------------------------------

/// Where `import` reads members from: a tar (`load`) or checkpoint directories (`load_dir`).
enum Source<'a> {
    Tar(TarIn<'a>),
    Dir { dirs: BTreeMap<String, OwnedFd>, file: Option<io::Take<File>> },
}

impl Source<'_> {
    fn member(&mut self, name: &str) -> Result<u64> {
        match self {
            Source::Tar(t) => t.member(name),
            Source::Dir { dirs, file } => {
                let (id, f) =
                    name.strip_prefix("checkpoints/").and_then(|n| n.split_once('/')).ok_or_else(|| format!("no {name} in a checkpoint directory"))?;
                let dir = dirs.get(id).ok_or_else(|| format!("no checkpoint {id} in the chain"))?;
                let opened = open_at(dir.as_raw_fd(), f)?;
                let st = crate::util::fstat(opened.as_raw_fd())?;
                ensure!(st.st_mode & libc::S_IFMT == libc::S_IFREG, "checkpoint {id}: {f} is not a regular file");
                *file = Some(opened.take(st.st_size as u64));
                Ok(st.st_size as u64)
            }
        }
    }

    fn reader(&mut self) -> &mut dyn Read {
        match self {
            Source::Tar(t) => t,
            Source::Dir { file, .. } => file.as_mut().expect("a member is open"),
        }
    }

    fn skip(&mut self) -> Result<()> {
        io::copy(self.reader(), &mut io::sink()).map_err(truncated)?;
        Ok(())
    }

    fn end(&mut self) -> Result<()> {
        match self {
            Source::Tar(t) => t.end(),
            Source::Dir { .. } => Ok(()),
        }
    }
}

/// Exactly `len` bytes of the current member.
fn read_all(src: &mut Source, len: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(len.min(1 << 26) as usize);
    src.reader().take(len).read_to_end(&mut bytes).map_err(truncated)?;
    ensure!(bytes.len() as u64 == len, "the archive is truncated");
    Ok(bytes)
}

/// Allocates `need` bytes for new `file`, refused if that would leave less than `KEEP_FREE` on its
/// filesystem. Under a host-wide lock: a concurrent load's check sees these blocks gone.
fn reserve(file: &File, need: u64) -> Result<()> {
    let _admit = crate::host::lock_at(crate::host::host_locks()?, template::ROOM_LOCK, libc::LOCK_EX)?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    crate::util::check(unsafe { libc::fstatvfs(file.as_raw_fd(), &mut st) })?;
    let free = st.f_bavail.saturating_mul(st.f_frsize);
    ensure!(free >= need.saturating_add(KEEP_FREE), "{} MiB of pages would leave less than {} MiB free in the checkpoint store", need >> 20, KEEP_FREE >> 20);
    // Allocated now, under the lock: a filesystem that cannot (EOPNOTSUPP) takes no loads, as it takes no pushes.
    if need > 0 {
        crate::util::check(unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, need as i64) })
            .map_err(|e| format!("allocating {} MiB for the checkpoint's pages: {e}", need >> 20))?;
    }
    Ok(())
}

/// The current member, `len` bytes, is the same as `local`'s bytes (hashed into `sha`).
fn same(src: &mut Source, len: u64, local: &Path, sha: &mut Sha256) -> Result<bool> {
    let Ok(mut have) = File::open(local) else { return Ok(false) };
    if have.metadata()?.len() != len {
        return Ok(false);
    }
    let (mut a, mut b, mut left) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20], len);
    let mut equal = true;
    while left > 0 {
        let n = left.min(a.len() as u64) as usize;
        src.reader().read_exact(&mut a[..n]).map_err(truncated)?;
        sha.update(&a[..n]);
        have.read_exact(&mut b[..n])?;
        equal &= a[..n] == b[..n];
        left -= n as u64;
    }
    Ok(equal)
}

/// One checkpoint of the chain, read and verified: staged, or already in the store.
struct Loaded {
    /// Its id here: the source's, unless its parent's path was rewritten (`Parent`).
    id: String,
    manifest: Manifest,
    staging: Option<Staging>,
    /// The SHA-256 of each of its files as it is here: what one found under its id must have.
    files: Vec<(&'static str, Vec<u8>)>,
}

fn file_sha(path: &Path) -> Result<Vec<u8>> {
    let mut h = Sha256::new();
    io::copy(&mut File::open(path)?, &mut h)?;
    Ok(h.finalize().to_vec())
}

/// Whether checkpoint directory `dir` has exactly `files` (by SHA-256).
fn has(dir: &Path, files: &[(&str, Vec<u8>)]) -> bool {
    files.iter().all(|(name, sha)| file_sha(&dir.join(name)).is_ok_and(|have| have == *sha))
}

/// Reads checkpoint `id` (`chain[i]`), whose parent the chain says is `parent` (the source's id and
/// the one it has here), verifying it as `Link::open` and `PageFile::read` do: within `meta_left`,
/// its pages against their checksums. Its parent is named `../ID` here, the store's way.
#[allow(clippy::too_many_arguments)]
fn receive(
    src: &mut Source,
    store_dir: &Path,
    id: &str,
    parent: Option<(&str, &str)>,
    template_id: &str,
    meta_left: &mut u64,
    digest: &mut SaveDigest,
) -> Result<Loaded> {
    let bad = |why: &str| format!("checkpoint {id}: {why}");
    digest.checkpoint(id);
    let take = |len: u64, max: u64, what: &str, meta_left: &mut u64| -> Result<()> {
        ensure!(len <= max, "{}", bad(&format!("its {what} is too long")));
        *meta_left = meta_left.checked_sub(len).ok_or_else(|| bad(&format!("its chain has more than {} bytes of metadata", chain_meta_budget())))?;
        Ok(())
    };
    let len = src.member(&checkpoint_member(id, "manifest.json"))?;
    take(len, MAX_MANIFEST, "manifest", meta_left)?;
    let mut text = read_all(src, len)?;
    digest.file("manifest.json", len, &Sha256::digest(&text));
    let split = text.iter().position(|&b| b == b'\n').ok_or_else(|| bad("its manifest has no checksum"))?;
    ensure!(text[..split] == *id.as_bytes() && sum(&text[split + 1..]) == id, "{}", bad("its manifest does not match its id"));
    let mut manifest: Manifest = serde_json::from_slice(&text[split + 1..]).map_err(|e| bad(&format!("its manifest: {e}")))?;
    match (manifest.format, &manifest.parent, parent) {
        (FORMAT, None, None) => {}
        (FORMAT_INCREMENTAL, Some(p), Some((want, _))) if p.id == want => {}
        _ => bail!("{}", bad("its format or parent is not the chain's")),
    }
    ensure!(manifest.template_id == template_id, "{}", bad("it is of another template than the chain"));
    ensure!(manifest.guest_pages <= MAX_GUEST_PAGES, "{}", bad("its guest memory is past the limits"));
    let mut here = id.to_string();
    if let Some((was, now)) = parent {
        let path = Path::new("..").join(now);
        if manifest.parent.as_ref().is_some_and(|p| p.path != path) || was != now {
            manifest.parent = Some(Parent { path, id: now.into() });
            let body = serde_json::to_vec_pretty(&manifest)?;
            here = sum(&body);
            text = [format!("{here}\n").as_bytes(), &body].concat();
        }
    }
    let local = store_dir.join(&here);
    if read_manifest(&local).is_ok() {
        // This host has one by its id, which is no cryptographic check: used only if it is the same, byte for byte.
        let differs = || bad(&format!("this host has a checkpoint {here} with other files: remove it (flexvm checkpoint rm {here}) to load this one"));
        ensure!(std::fs::read(local.join("manifest.json")).is_ok_and(|have| have == text), "{}", differs());
        let mut files = vec![("manifest.json", Sha256::digest(&text).to_vec())];
        for name in ["vmstate", "pagemap", "pages"] {
            let len = src.member(&checkpoint_member(id, name))?;
            let mut sha = Sha256::new();
            ensure!(same(src, len, &local.join(name), &mut sha)?, "{}", differs());
            let sha = sha.finalize();
            digest.file(name, len, &sha);
            files.push((name, sha.to_vec()));
        }
        return Ok(Loaded { id: here, manifest, staging: None, files });
    }
    let staging = Staging::import(store_dir)?;
    let want = |name: &str| manifest.files.get(name).cloned().ok_or_else(|| bad(&format!("its manifest lists no {name}")));
    let mut checked = |name: &str, max: u64, meta_left: &mut u64| -> Result<Vec<u8>> {
        let want = want(name)?;
        let len = src.member(&checkpoint_member(id, name))?;
        ensure!(len == want.len, "{}", bad(&format!("its {name} is not as long as its manifest says")));
        take(len, max, name, meta_left)?;
        let bytes = read_all(src, len)?;
        ensure!(sum(&bytes) == want.hash, "{}", bad(&format!("its {name} does not match its checksum")));
        digest.file(name, len, &Sha256::digest(&bytes));
        staging.add_file(name, &bytes)?;
        Ok(bytes)
    };
    let vmstate = checked("vmstate", MAX_VMSTATE, meta_left)?;
    let map_max = manifest.guest_pages * 36 + 24;
    let map = checked("pagemap", map_max, meta_left)?;
    let mut files = vec![("vmstate", Sha256::digest(&vmstate).to_vec()), ("pagemap", Sha256::digest(&map).to_vec())];
    let (runs, sums) = parse_pagemap(&map, manifest.guest_pages, manifest.parent.is_some(), 0).map_err(|e| bad(&e.to_string()))?;
    let data: u64 = runs.iter().filter(|r| r.2 == DATA).map(|r| r.1).sum();
    let pages_len = data * PAGE_SIZE as u64;
    ensure!(data == manifest.data_pages && want("pages")?.len == pages_len, "{}", bad("its page counts do not add up"));
    let len = src.member(&checkpoint_member(id, "pages"))?;
    ensure!(len == pages_len, "{}", bad("its pages are not as long as its manifest says"));
    let file = staging.create("pages")?;
    reserve(&file, len)?;
    let (mut buf, mut sha) = (vec![0u8; 256 * PAGE_SIZE], Sha256::new());
    let mut d = 0;
    while d < data {
        let n = ((data - d) as usize).min(256);
        let chunk = &mut buf[..n * PAGE_SIZE];
        src.reader().read_exact(chunk).map_err(truncated)?;
        sha.update(&*chunk);
        for (i, page) in chunk.chunks(PAGE_SIZE).enumerate() {
            ensure!(crate::crc32c::page(page).0 == sums[d as usize + i], "{}", bad(&format!("its data page {} does not match its checksum", d as usize + i)));
        }
        (&file).write_all(chunk)?;
        d += n as u64;
    }
    file.sync_all()?;
    let sha = sha.finalize();
    digest.file("pages", len, &sha);
    files.extend([("pages", sha.to_vec()), ("manifest.json", Sha256::digest(&text).to_vec())]);
    staging.add_file("manifest.json", &text)?;
    Ok(Loaded { id: here, manifest, staging: Some(staging), files })
}

/// `checkpoint load`: a `save`'s tar from `r`, into the store, named `name` (else as it was saved);
/// with `sha256`, only if that is the save's (`SaveDigest`).
pub fn load(state: &Path, paths: &Paths, r: &mut dyn Read, name: Option<&str>, sha256: Option<&str>) -> Result<Value> {
    let mut tar = TarIn { r, left: 0, pad: 0 };
    let len = tar.member(HEADER).map_err(|e| format!("not a flexvm checkpoint save: {e}"))?;
    ensure!(len <= MAX_HEADER, "its {HEADER} is too long");
    let mut src = Source::Tar(tar);
    let header: Header = serde_json::from_slice(&read_all(&mut src, len)?).map_err(|e| format!("its {HEADER}: {e}"))?;
    import(state, paths, header, &mut src, name, sha256)
}

/// `checkpoint load -i DIR`: checkpoint directory `dir` (v0.1.0's, or a copy of a stored one) and its
/// chain, into the store; its template is not in it, so this host needs its generation to restore it.
pub fn load_dir(state: &Path, paths: &Paths, dir: &Path, name: Option<&str>, sha256: Option<&str>) -> Result<Value> {
    let ck = Checkpoint::open(dir)?;
    let chain: Vec<String> = std::iter::once(ck.id.clone()).chain(ck.chain_ids.iter().cloned()).collect();
    let mut dirs = BTreeMap::new();
    for (d, id) in std::iter::once(&ck.dir).chain(&ck.chain).zip(&chain) {
        dirs.insert(id.clone(), open_dir_at(libc::AT_FDCWD, &CString::new(d.as_os_str().as_bytes())?)?);
    }
    let header = Header { format: EXPORT_FORMAT, id: ck.id.clone(), name: None, chain, template_id: ck.manifest.template_id.clone(), template: false };
    import(state, paths, header, &mut Source::Dir { dirs, file: None }, name, sha256)
}

/// The checkpoint name `names/NAME` links to, if any.
fn named(state: &Path, name: &str) -> Option<String> {
    let target = std::fs::read_link(store::dir(state).join("names").join(name)).ok()?;
    Some(target.file_name()?.to_string_lossy().into_owned())
}

fn import(state: &Path, paths: &Paths, header: Header, src: &mut Source, name: Option<&str>, sha256: Option<&str>) -> Result<Value> {
    let chain = &header.chain;
    ensure!(header.format == EXPORT_FORMAT, "a checkpoint save of format {}; this flexvm reads format {EXPORT_FORMAT}", header.format);
    ensure!(
        !chain.is_empty()
            && chain.len() <= MAX_CHAIN
            && chain[0] == header.id
            && chain.iter().all(|id| store::is_id(id))
            && chain.iter().collect::<BTreeSet<_>>().len() == chain.len(),
        "its {HEADER} names no chain of checkpoint ids (of at most {MAX_CHAIN})"
    );
    ensure!(template::valid_id(&header.template_id) && header.template_id.len() <= 64, "its {HEADER} names no template id");
    let name = name.map(str::to_string).or(header.name.clone());
    if let Some(n) = &name {
        ensure!(crate::host::check_name(n).is_ok(), "bad checkpoint name {n:?}: up to 64 letters, digits, '-', '_' or '.', not starting with '.'");
        // Refused before anything is read: a name is one checkpoint's.
        if named(state, n).is_none_or(|have| have != header.id) {
            store::check_free(state, n).map_err(|e| format!("{e}; give another with --name"))?;
        }
    }
    drop(store::lock(state, libc::LOCK_SH)?);
    let store_dir = store::dir(state);
    let mut meta_left = chain_meta_budget();
    let (mut loaded, mut digest): (Vec<Loaded>, _) = (vec![], SaveDigest::default());
    for (i, id) in chain.iter().enumerate().rev() {
        let parent = loaded.last().map(|p: &Loaded| (chain[i + 1].as_str(), p.id.as_str()));
        let l = receive(src, &store_dir, id, parent, &header.template_id, &mut meta_left, &mut digest)?;
        if let Some(p) = loaded.last() {
            ensure!(p.manifest.guest_pages == l.manifest.guest_pages, "checkpoint {id}: its parent is of another size");
        }
        loaded.push(l);
    }
    let sha = digest.finish();
    if let Some(want) = sha256 {
        ensure!(want.eq_ignore_ascii_case(&sha), "the save's SHA-256 is {sha}, not {want}: refused");
    }
    let head = &loaded.last().unwrap().manifest;
    let digests = head.template_digests.clone();
    ensure!(
        loaded.iter().all(|l| l.manifest.template_digests.is_none() || l.manifest.template_digests == digests),
        "the chain's checkpoints record other digests of their template"
    );
    let tid = &header.template_id;
    let by = "the checkpoint";
    let open = |dir: PathBuf| -> Result<Arc<Template>> {
        let tpl = Template::open_dir(tid, dir)?;
        tpl.check_vouched(digests.as_ref(), by)?;
        Ok(tpl)
    };
    // Held until the checkpoint that uses it is published: no prune or `rmi` removes it meanwhile.
    let (tpl, how) = match Template::generation(paths, tid) {
        Some(dir) => {
            if header.template {
                src.member(&template_member(tid))?;
                src.skip()?;
            }
            (Some(open(dir)?), "present")
        }
        None if header.template => {
            let vouched = digests.as_ref().ok_or("the checkpoint records no SHA-256 digests of its template, which cannot be verified")?;
            src.member(&template_member(tid))?;
            let _turn = template::turn(paths, tid, Instant::now() + TURN_WAIT)?;
            match Template::generation(paths, tid) {
                // Another arrival brought it meanwhile.
                Some(dir) => {
                    src.skip()?;
                    (Some(open(dir)?), "present")
                }
                None => {
                    let Source::Tar(tar) = src else { bail!("a checkpoint directory has no template") };
                    // Nothing follows it, checked before it is published.
                    let finish = |t: &mut TarIn| {
                        ensure!(t.left == 0, "template {tid}: the archive has more of it than it is");
                        t.end()
                    };
                    let tpl = template::receive(paths, tar, tid, Some(vouched), finish)?;
                    tpl.check_vouched(Some(vouched), by)?;
                    (Some(tpl), "received")
                }
            }
        }
        None => (None, "missing"),
    };
    if how != "received" {
        src.end()?;
    }
    // Exclusive: nothing is published (another load's, which may revoke it) or removed (`rm`, `prune`)
    // meanwhile. Whatever is under an id now, found before or published since, is used only if it has
    // the very files verified here (by SHA-256), its id being no cryptographic check.
    let _lock = store::lock(state, libc::LOCK_EX)?;
    let mut stored = 0;
    for l in loaded.iter_mut() {
        let dest = store_dir.join(&l.id);
        match std::fs::symlink_metadata(dest.join("manifest.json")) {
            Ok(_) => {
                ensure!(
                    has(&dest, &l.files),
                    "checkpoint {} here has other files than the save's: remove it (flexvm checkpoint rm {0}) to load this one",
                    l.id
                );
                drop(l.staging.take());
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // A revoked publication's leftover (as `rm` clears it), else nothing.
                if std::fs::symlink_metadata(&dest).is_ok() {
                    std::fs::remove_dir_all(&dest)?;
                    crate::util::sync_dir(&store_dir)?;
                }
                let s = l.staging.take().ok_or_else(|| format!("checkpoint {} here was removed as this one loaded; load it again", l.id))?;
                ensure!(s.publish_as(&l.id)?, "checkpoint {} was published as this one loaded; load it again", l.id);
                stored += 1;
            }
            Err(e) => return Err(io::Error::new(e.kind(), format!("checking checkpoint {}: {e}", dest.display())).into()),
        }
    }
    let id = loaded.last().unwrap().id.clone();
    // As a restore opens it.
    Checkpoint::open(&store_dir.join(&id)).map_err(|e| format!("the loaded checkpoint {id} does not open: {e}"))?;
    if let Some(n) = &name {
        if named(state, n).as_deref() != Some(id.as_str()) {
            store::link(state, n, &id).map_err(|e| format!("loaded checkpoint {id}, but {e}"))?;
        }
    }
    drop(tpl);
    if how == "missing" {
        warn(format_args!("loaded checkpoint {id}, but template generation {tid} is not here: restoring it needs it (pull its image, or load a save of it)"));
    }
    Ok(json!({"loaded": id, "name": name, "chain": loaded.len(), "stored": stored, "template_id": tid, "template": how, "sha256": sha}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::format::MAGIC;
    use std::fs;

    /// A checkpoint of `tpl` with `seeds.len()` data pages (one run from page `at`) in store `state`,
    /// a delta on `parent` if given, its manifest changed by `edit`; returns its id.
    fn stored(state: &Path, tpl: &Template, parent: Option<&str>, at: u64, seeds: &[u8], edit: impl FnOnce(&mut Manifest)) -> String {
        drop(store::lock(state, libc::LOCK_SH).unwrap());
        let new = store::dir(state).join(".new");
        fs::create_dir_all(&new).unwrap();
        let pages: Vec<u8> = seeds.iter().flat_map(|&s| (0..PAGE_SIZE).map(move |i| (i as u8).wrapping_mul(31).wrapping_add(s))).collect();
        let n = seeds.len() as u64;
        let mut map = [MAGIC.as_slice(), &1u64.to_le_bytes(), &n.to_le_bytes()].concat();
        for w in [at, n, DATA, 0] {
            map.extend(w.to_le_bytes());
        }
        for p in pages.chunks(PAGE_SIZE) {
            map.extend(crate::crc32c::page(p).0.to_le_bytes());
        }
        for (name, bytes) in [("vmstate", &b"state"[..]), ("pagemap", &map), ("pages", &pages)] {
            fs::write(new.join(name), bytes).unwrap();
        }
        let mut m: Manifest = serde_json::from_value(json!({
            "format": if parent.is_some() { FORMAT_INCREMENTAL } else { FORMAT }, "created_unix_ms": at, "name": "web",
            "ip": "10.0.0.1", "template": "t", "template_id": tpl.meta.id, "saved_msrs": [], "saved_tsc_khz": 2000000, "vcpus": 1,
            "mem_mib": 1, "max_mib": 1, "hotplug_mib": 0, "guest_pages": 256, "data_pages": n, "zero_pages": 0,
            "parent": parent.map(|p| json!({"path": format!("../{p}"), "id": p})),
            "files": {"vmstate": {"len": 5, "hash": sum(b"state")}, "pagemap": {"len": map.len(), "hash": sum(&map)}, "pages": {"len": pages.len()}},
            "template_digests": tpl.digests().unwrap(),
        }))
        .unwrap();
        edit(&mut m);
        let body = serde_json::to_vec_pretty(&m).unwrap();
        let id = sum(&body);
        fs::write(new.join("manifest.json"), [format!("{id}\n").as_bytes(), &body].concat()).unwrap();
        fs::rename(&new, store::dir(state).join(&id)).unwrap();
        id
    }

    struct Host {
        state: crate::test_util::TempDir,
        paths: Paths,
        _templates: crate::test_util::TempDir,
    }

    /// A host that never pulled anything, with `paths`' Firecracker.
    fn fresh(paths: &Paths) -> Host {
        let (templates, paths) = template::tests::elsewhere_of(paths);
        Host { state: crate::test_util::TempDir::new("ckpt-load"), paths, _templates: templates }
    }

    fn ids(state: &Path) -> Vec<String> {
        store::list(state).into_iter().map(|e| e.id).collect()
    }

    fn gens(paths: &Paths) -> Vec<String> {
        fs::read_dir(paths.templates.join(template::GENERATIONS))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// Nothing published: no checkpoint (staging gone too) and no generation.
    fn nothing(h: &Host) -> bool {
        let staged =
            fs::read_dir(store::dir(&h.state)).into_iter().flatten().flatten().any(|e| e.file_name().to_string_lossy().starts_with(".flexvm-staging-"));
        ids(&h.state).is_empty() && gens(&h.paths).is_empty() && !staged
    }

    fn load_bytes(h: &Host, tar: &[u8], name: Option<&str>) -> Result<Value> {
        load(&h.state, &h.paths, &mut &tar[..], name, None)
    }

    /// A store with a named chain of two (a full checkpoint and a delta) and its save.
    fn saved() -> (crate::test_util::TempDir, Paths, Arc<Template>, crate::test_util::TempDir, Vec<String>, Vec<u8>) {
        let (dir, paths, tpl) = template::tests::sendable();
        let state = crate::test_util::TempDir::new("ckpt-save");
        let base = stored(&state, &tpl, None, 0, &[1, 2, 3], |_| {});
        let head = stored(&state, &tpl, Some(&base), 10, &[4], |_| {});
        store::link(&state, "web", &head).unwrap();
        let mut tar = vec![];
        let r = save(&state, &paths, "web", &mut tar).unwrap();
        assert_eq!(
            (r["saved"].as_str(), r["chain"].as_u64(), r["template"].as_bool(), r["bytes"].as_u64()),
            (Some(&head[..]), Some(2), Some(true), Some(tar.len() as u64))
        );
        (dir, paths, tpl, state, vec![head, base], tar)
    }

    #[test]
    fn a_save_loads_on_a_host_without_its_template_by_content_id() {
        let (_dir, paths, tpl, state, chain, tar) = saved();
        // A tar any tar reads: the header, the chain oldest first, then the template.
        let names: Vec<String> = tar::Archive::new(&tar[..]).entries().unwrap().map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned()).collect();
        let mut want = vec![HEADER.to_string()];
        for id in chain.iter().rev() {
            want.extend(["manifest.json", "vmstate", "pagemap", "pages"].map(|f| checkpoint_member(id, f)));
        }
        want.push(template_member(&tpl.meta.id));
        assert_eq!(names, want);
        let b = fresh(&paths);
        // B's tag names another build: it stays as it is.
        fs::create_dir_all(&b.paths.templates).unwrap();
        std::os::unix::fs::symlink(".gen/0123456789abcdef", b.paths.templates.join("t")).unwrap();
        // `--sha256`: only the save whose SHA-256 `save` printed.
        let sha = save(&state, &paths, "web", &mut vec![]).unwrap()["sha256"].as_str().unwrap().to_string();
        let e = load(&b.state, &b.paths, &mut &tar[..], None, Some(&"0".repeat(64))).err().unwrap().to_string();
        assert!(e.contains(&format!("SHA-256 is {sha}")) && nothing(&b), "{e}");
        let r = load(&b.state, &b.paths, &mut &tar[..], None, Some(&sha.to_uppercase())).unwrap();
        assert_eq!(
            (r["loaded"].as_str(), r["name"].as_str(), r["stored"].as_u64(), r["template"].as_str()),
            (Some(&chain[0][..]), Some("web"), Some(2), Some("received"))
        );
        assert_eq!(r["sha256"], sha.as_str(), "as save printed it");
        assert_eq!(ids(&b.state), ids(&state), "the same ids, oldest first");
        assert_eq!(fs::read_link(b.paths.templates.join("t")).unwrap(), Path::new(".gen/0123456789abcdef"));
        assert_eq!(gens(&b.paths), [tpl.meta.id.clone()]);
        let got = Template::open_id(&b.paths, "t", &tpl.meta.id).unwrap();
        assert!(got.meta.received && got.check_vouched(tpl.meta.digests.as_ref(), "it").is_ok());
        let ck = Checkpoint::open(&store::dir(&b.state).join(&chain[0])).unwrap();
        ck.verify_data().unwrap();
        assert_eq!(ck.data_pages(), 4);
        for f in ["manifest.json", "vmstate", "pagemap", "pages"] {
            for id in &chain {
                assert_eq!(fs::read(store::dir(&b.state).join(id).join(f)).unwrap(), fs::read(store::dir(&state).join(id).join(f)).unwrap());
            }
        }
        // Again: nothing new, and its own name is no conflict.
        let r = load_bytes(&b, &tar, None).unwrap();
        assert_eq!((r["stored"].as_u64(), r["template"].as_str(), r["sha256"].as_str()), (Some(0), Some("present"), Some(&sha[..])));
        // A checkpoint here under one of its ids but with other bytes is never taken for it.
        let pages = store::dir(&b.state).join(&chain[1]).join("pages");
        let mut changed = fs::read(&pages).unwrap();
        changed[7] ^= 1;
        fs::write(&pages, &changed).unwrap();
        let e = load_bytes(&b, &tar, None).err().unwrap().to_string();
        assert!(e.contains("with other files") && e.contains(&chain[1]), "{e}");
        changed[7] ^= 1;
        fs::write(&pages, &changed).unwrap();
        // Another checkpoint has the name: refused before anything is read, unless --name.
        let c = fresh(&paths);
        let other = stored(&c.state, &tpl, None, 5, &[9], |_| {});
        store::link(&c.state, "web", &other).unwrap();
        assert!(load_bytes(&c, &tar, None).err().unwrap().to_string().contains("--name"));
        assert_eq!(ids(&c.state), [other.clone()]);
        let r = load_bytes(&c, &tar, Some("web2")).unwrap();
        assert_eq!(r["name"], "web2");
        assert_eq!(store::find(&store::list(&c.state), "web2").unwrap().id, chain[0]);
        // A revoked publication's leftover under one of its ids (no manifest) is cleared, as `rm` clears it.
        let e = fresh(&paths);
        fs::create_dir_all(store::dir(&e.state).join(&chain[1])).unwrap();
        fs::write(store::dir(&e.state).join(&chain[1]).join("pages"), b"debris").unwrap();
        assert_eq!(load_bytes(&e, &tar, None).unwrap()["stored"], 2);
        Checkpoint::open(&store::dir(&e.state).join(&chain[0])).unwrap().verify_data().unwrap();
        // A stored ancestor is not stored again, and a chain whose base is there loads its head.
        let d = fresh(&paths);
        load_bytes(&d, &tar, None).unwrap();
        store::remove(&d.state, &[chain[0].clone()], false).unwrap();
        assert_eq!(load_bytes(&d, &tar, None).unwrap()["stored"], 1);
    }

    #[test]
    fn a_tampered_or_truncated_save_publishes_nothing() {
        let (_dir, paths, _tpl, _state, _chain, tar) = saved();
        // Every 4 KiB step of truncation, and into the end of the archive.
        for len in (0..tar.len()).step_by(4096).chain([tar.len() - 2 * BLOCK - 1, tar.len() - 2 * BLOCK + 1, tar.len() - BLOCK, tar.len() - 1]) {
            let b = fresh(&paths);
            assert!(load_bytes(&b, &tar[..len], None).is_err(), "truncated at {len} of {}", tar.len());
            assert!(nothing(&b), "truncated at {len}: published something");
        }
        // A flipped byte in a page, in a manifest, in the template's memory.
        let page = tar.windows(PAGE_SIZE.min(64)).position(|w| w[..8] == [1, 32, 63, 94, 125, 156, 187, 218]).unwrap();
        let manifest = tar.windows(12).position(|w| w == b"\"data_pages\"").unwrap() + 15;
        let mem = tar.len() - 2 * BLOCK - 100;
        for (at, want) in [(page, "data page 0 does not match"), (manifest, "does not match its id"), (mem, "")] {
            let mut bad = tar.clone();
            bad[at] ^= 0x40;
            let b = fresh(&paths);
            let e = load_bytes(&b, &bad, None).err().unwrap().to_string();
            assert!(e.contains(want), "{e}");
            assert!(nothing(&b), "a flip at {at}: published something");
        }
        // Trailing bytes after the save.
        let b = fresh(&paths);
        let mut more = tar[..tar.len() - 2 * BLOCK].to_vec();
        more.extend_from_slice(&tar[..BLOCK]);
        assert!(load_bytes(&b, &more, None).err().unwrap().to_string().contains("more than one"));
        assert!(nothing(&b), "not even its template");
        // Anything but zeros after the end, or zeros past `MAX_TAIL`; zeros (a tar record's padding) are taken.
        for (tail, ok) in [(vec![0u8; 9 * BLOCK], true), ([vec![0u8; BLOCK], vec![1]].concat(), false), (vec![0u8; MAX_TAIL as usize + 1], false)] {
            let b = fresh(&paths);
            let r = load_bytes(&b, &[&tar[..], &tail].concat(), None);
            assert_eq!(r.is_ok(), ok, "{r:?}");
            assert!(ok || nothing(&b));
        }
    }

    /// `tar` with member `i`'s header (and, if given, its bytes) replaced; sizes as given.
    fn forged(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = TarOut { w: vec![], n: 0 };
        for (name, bytes) in members {
            let mut h = tar::Header::new_gnu();
            h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_size(bytes.len() as u64);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            out.write_all(h.as_bytes()).unwrap();
            out.write_all(bytes).unwrap();
            out.write_all(&[0u8; BLOCK][..padding(bytes.len() as u64)]).unwrap();
        }
        out.finish().unwrap();
        out.w
    }

    #[test]
    fn a_save_names_no_path_and_stays_within_its_limits() {
        let (_dir, paths, tpl, _state, chain, _) = saved();
        let header = |chain: &[&str], tid: &str| {
            serde_json::to_vec(&json!({"format": 1, "id": chain[0], "name": null, "chain": chain, "template_id": tid, "template": true})).unwrap()
        };
        let tid = tpl.meta.id.as_str();
        type Case<'a> = (Vec<(&'a str, Vec<u8>)>, &'a str);
        let cases: Vec<Case> = vec![
            (vec![("../flexvm-checkpoint.json", header(&[&chain[0]], tid))], "expected"),
            (vec![(HEADER, header(&["../../etc/passwd"], tid))], "no chain of checkpoint ids"),
            (vec![(HEADER, header(&[&chain[0]], "../x"))], "no template id"),
            (
                vec![(
                    HEADER,
                    serde_json::to_vec(&json!({"format": 1, "id": chain[0], "name": "../../x", "chain": [chain[0]], "template_id": tid, "template": true}))
                        .unwrap(),
                )],
                "bad checkpoint name",
            ),
            (vec![(HEADER, header(&[&chain[0], &chain[0]], tid))], "no chain of checkpoint ids"),
            (vec![(HEADER, vec![b' '; MAX_HEADER as usize + 1])], "too long"),
            (vec![(HEADER, header(&[&chain[0]], tid)), ("checkpoints/../../x/manifest.json", vec![])], "expected"),
            // A manifest declared past its limit is refused before it is read.
            (
                vec![
                    (HEADER, header(&[&chain[0]], tid)),
                    (&*Box::leak(checkpoint_member(&chain[0], "manifest.json").into_boxed_str()), vec![0; MAX_MANIFEST as usize + 1]),
                ],
                "too long",
            ),
        ];
        for (members, want) in cases {
            let b = fresh(&paths);
            let e = load_bytes(&b, &forged(&members), None).err().unwrap().to_string();
            assert!(e.contains(want), "{want}: {e}");
            assert!(nothing(&b));
        }
        // Not a tar, or another kind of member.
        let b = fresh(&paths);
        assert!(load_bytes(&b, &[7u8; 2048], None).err().unwrap().to_string().contains("not a flexvm checkpoint save"));
        let mut link = forged(&[(HEADER, header(&[&chain[0]], tid))]);
        link[156] = b'2';
        let h = tar::Header::from_byte_slice(&link[..BLOCK]).clone();
        let mut h = h;
        h.set_cksum();
        link[..BLOCK].copy_from_slice(h.as_bytes());
        assert!(load_bytes(&b, &link, None).err().unwrap().to_string().contains("not a regular file"));
        assert!(nothing(&b));
    }

    #[test]
    fn a_received_template_is_used_only_with_the_checkpoints_digests() {
        let (_dir, paths, tpl, state, _, _) = saved();
        // The head vouches for other files: its template is refused before it is published.
        let mut other = tpl.digests().unwrap();
        other.insert("rootfs".into(), "0".repeat(64));
        let base = store::list(&state)[0].id.clone();
        let head = stored(&state, &tpl, Some(&base), 20, &[5], |m| m.template_digests = Some(other.clone()));
        // The save refuses what the template here does not match.
        assert!(save(&state, &paths, &head, &mut vec![]).err().unwrap().to_string().contains("SHA-256"));
        let mut tar = vec![];
        let good = store::list(&state)[1].id.clone();
        save(&state, &paths, &good, &mut tar).unwrap();
        // The same save with the head's digests forged (its id changes with them, so it is another chain).
        let b = fresh(&paths);
        load_bytes(&b, &tar, None).unwrap();
        let received = Template::open_id(&b.paths, "t", &tpl.meta.id).unwrap();
        assert!(received.check_vouched(Some(&other), "it").is_err());
        // A host whose copy was received with other digests refuses a checkpoint vouching for these.
        let c = fresh(&paths);
        let mut forged_meta = received.meta.clone();
        forged_meta.digests = Some(other.clone());
        let gen = c.paths.templates.join(template::GENERATIONS).join(&tpl.meta.id);
        fs::create_dir_all(gen.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&received.dir, &gen).unwrap();
        let copy = crate::test_util::TempDir::new("received-copy");
        for f in ["vmstate", "mem", "rootfs"] {
            fs::copy(received.dir.join(f), copy.join(f)).unwrap();
        }
        forged_meta.rootfs = copy.join("rootfs");
        fs::write(copy.join("meta.json"), serde_json::to_vec(&forged_meta).unwrap()).unwrap();
        fs::remove_file(&gen).unwrap();
        std::os::unix::fs::symlink(&*copy, &gen).unwrap();
        let e = load_bytes(&c, &tar, None).err().unwrap().to_string();
        assert!(e.contains("does not vouch"), "{e}");
        assert!(ids(&c.state).is_empty());
    }

    #[test]
    fn a_checkpoint_directory_loads_with_its_chain_named_the_stores_way() {
        let (_dir, paths, tpl, _state, _, _) = saved();
        // v0.1.0's way: directories side by side, the delta naming its parent by a path of its own.
        let elsewhere = crate::test_util::TempDir::new("ckpt-dirs");
        let scratch = fresh(&paths);
        let base = stored(&scratch.state, &tpl, None, 0, &[1, 2], |_| {});
        let head = stored(&scratch.state, &tpl, Some(&base), 1, &[3], |m| m.parent.as_mut().unwrap().path = "../older".into());
        fs::rename(store::dir(&scratch.state).join(&base), elsewhere.join("older")).unwrap();
        fs::rename(store::dir(&scratch.state).join(&head), elsewhere.join("newer")).unwrap();
        let b = fresh(&paths);
        let r = load_dir(&b.state, &b.paths, &elsewhere.join("newer"), Some("old"), None).unwrap();
        let id = r["loaded"].as_str().unwrap().to_string();
        assert_ne!(id, head, "its parent's path is the store's now, so its id changed");
        assert_eq!((r["stored"].as_u64(), r["template"].as_str()), (Some(2), Some("missing")));
        let ck = Checkpoint::open(&store::dir(&b.state).join(&id)).unwrap();
        assert_eq!((ck.chain_ids.as_slice(), ck.manifest.parent.clone().unwrap().path), (&[base.clone()][..], Path::new("..").join(&base)));
        ck.verify_data().unwrap();
        assert_eq!(store::find(&store::list(&b.state), "old").unwrap().id, id);
        // A damaged page is refused, nothing published.
        let mut pages = fs::read(elsewhere.join("older/pages")).unwrap();
        pages[100] ^= 1;
        fs::write(elsewhere.join("older/pages"), pages).unwrap();
        let c = fresh(&paths);
        assert!(load_dir(&c.state, &c.paths, &elsewhere.join("newer"), None, None).is_err());
        assert!(nothing(&c));
    }
}
