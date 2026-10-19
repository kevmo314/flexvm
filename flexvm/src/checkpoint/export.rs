//! `checkpoint save` and `checkpoint load` (#775): one self-contained tar of a stored checkpoint,
//! its chain and its template generation, and its import, all verified before it is published.
//!
//! Members, in this order: `flexvm-checkpoint.json` (the `Header`); for each checkpoint of the
//! chain, oldest first, `checkpoints/ID/manifest.json`, its run settings `SPEC` if it has them (and
//! the header lists it in `specs`), `vmstate`, `pagemap` and `pages`; then,
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
    chain::{chain_ids, chain_meta_budget, read_at},
    format::{parse_pagemap, sum, DATA, MAX_VMSTATE},
    open_at, open_dir_at, read_manifest, store, Checkpoint, CommitError, Manifest, Parent, Staging, FORMAT, FORMAT_INCREMENTAL, MAX_CHAIN,
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
/// A checkpoint's run settings (`SPEC`, `app::RunSpec`), at most.
const MAX_SPEC: u64 = 1 << 20;
/// What a load or save copies of a pages file at a time.
const CHUNK: usize = 1 << 20;
/// A stored checkpoint's run settings: not in its manifest, so not in its id.
const SPEC: &str = "SPEC";

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
    /// The checkpoints of the chain whose `SPEC` follows their manifest (none in a save from before them).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub specs: Vec<String>,
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
/// the chain, oldest first, its id and its files as saved (name, length, SHA-256), `SPEC` among them
/// if it has one (so a save without any has the SHA-256 it had before they were saved). The checkpoints'
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

/// Whether `block` is a tar header, by its checksum.
fn header_ok(block: &[u8]) -> bool {
    let sum: u64 = block.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { b as u64 }).sum();
    tar::Header::from_byte_slice(block).cksum().ok().map(u64::from) == Some(sum)
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
        ensure!(header_ok(&block), "bad tar header before {want}: not a flexvm checkpoint save");
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
        if block.iter().any(|&b| b != 0) {
            match header_ok(&block[..BLOCK]) {
                true => bail!(
                    "the archive has a member after the save's last: {:?} (one save is loaded at a time)",
                    String::from_utf8_lossy(&tar::Header::from_byte_slice(&block[..BLOCK]).path_bytes())
                ),
                false => bail!("the archive has bytes after the save's last member, where its end should be"),
            }
        }
        self.r.read_exact(&mut block[BLOCK..]).map_err(truncated)?;
        let mut tail = vec![];
        (&mut *self.r).take(MAX_TAIL + 1).read_to_end(&mut tail)?;
        ensure!(
            block.iter().chain(&tail).all(|&b| b == 0) && tail.len() as u64 <= MAX_TAIL,
            "the archive goes on past its end (more than {} KiB of zeros, or other bytes)",
            MAX_TAIL >> 10
        );
        Ok(())
    }
}

// --- save -------------------------------------------------------------------------------------

/// A chain member's files, read and checked under the store's lock: its pages stay readable once open.
struct Saved {
    id: String,
    manifest: Manifest,
    text: Vec<u8>,
    spec: Option<Vec<u8>>,
    vmstate: Vec<u8>,
    pagemap: Vec<u8>,
    pages: File,
    pages_len: u64,
}

/// Its run settings, as a restore reads them: refused here if a load would refuse them.
fn check_spec(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() as u64 <= MAX_SPEC, "its run settings ({SPEC}) are over {} KiB", MAX_SPEC >> 10);
    serde_json::from_slice::<crate::app::RunSpec>(bytes).map_err(|e| format!("its run settings ({SPEC}): {e}"))?;
    Ok(())
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
    let spec = match read_at(dfd.as_raw_fd(), SPEC, MAX_SPEC + 1) {
        Ok((_, bytes)) => Some(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => bail!("{}", bad(format!("{SPEC}: {e}"))),
    };
    if let Some(spec) = &spec {
        check_spec(spec).map_err(|e| bad(e.to_string()))?;
    }
    let (vmstate, pagemap) = (read("vmstate")?, read("pagemap")?);
    let (pages, _) = read_at(dfd.as_raw_fd(), "pages", 0).map_err(|e| bad(format!("pages: {e}")))?;
    let pages_len = pages.metadata()?.len();
    ensure!(Some(pages_len) == manifest.files.get("pages").map(|f| f.len), "{}", bad("pages has the wrong length".into()));
    Ok(Saved { id: id.into(), manifest, text, spec, vmstate, pagemap, pages, pages_len })
}

/// `checkpoint save`: stored checkpoint `what`, its chain and its template generation, as one tar
/// written to `w`. Returns what it wrote.
pub fn save(state: &Path, paths: &Paths, what: &str, w: &mut dyn Write) -> Result<Value> {
    // Everything is opened under the store's lock, so no removal takes part of it; held no longer,
    // so a slow reader holds up no `checkpoint rm`. The open generation is kept by its use lock.
    let lock = store::lock(state, libc::LOCK_SH)?;
    let all = store::list(state);
    let entry = store::find(&all, what)?;
    // The chain by its manifests; `read_member` verifies each against its id. In the store, each is named by its id.
    let chain = chain_ids(&entry.dir)?;
    let store_dir = store::dir(state);
    let mut members = chain.iter().map(|id| read_member(&store_dir.join(id), id)).collect::<Result<Vec<_>>>()?;
    members.reverse();
    let head = &members.last().unwrap().manifest;
    let (tid, digests) = (head.template_id.clone(), head.template_digests.clone());
    let tpl = Template::generation(paths, &tid)
        .map(|dir| Template::open_dir(&tid, dir))
        .transpose()?
        .ok_or_else(|| format!("checkpoint {what}: its template generation {tid} is not here"))?;
    drop(lock);
    // What a loader would refuse: refused here, before anything is written.
    if let (Some(want), Some(have)) = (&digests, tpl.meta.digests.as_ref()) {
        ensure!(want == have, "checkpoint {what}: template {tid} here does not match the SHA-256 digests the checkpoint records");
    }
    tpl.check_vouched(digests.as_ref(), "the checkpoint")?;
    let sending = digests.as_ref().map(|_| template::Sending::new(&tpl)).transpose()?;
    if sending.is_none() {
        warn(format_args!(
            "checkpoint {what} records no SHA-256 digests of its template (taken by v0.1.0, or on a template it built): saved without template {tid}, which the loading host must have"
        ));
    }
    let header = Header {
        format: EXPORT_FORMAT,
        id: entry.id.clone(),
        name: entry.name.clone(),
        chain,
        template_id: tid.clone(),
        template: sending.is_some(),
        specs: members.iter().filter(|m| m.spec.is_some()).map(|m| m.id.clone()).collect(),
    };
    let mut out = TarOut { w, n: 0 };
    out.bytes(HEADER, &serde_json::to_vec_pretty(&header)?)?;
    let mut digest = SaveDigest::default();
    let mut buf = vec![0u8; CHUNK];
    for m in members {
        digest.checkpoint(&m.id);
        let files = [("manifest.json", Some(&m.text)), (SPEC, m.spec.as_ref()), ("vmstate", Some(&m.vmstate)), ("pagemap", Some(&m.pagemap))];
        for (name, bytes) in files.into_iter().filter_map(|(n, b)| Some((n, b?))) {
            out.bytes(&checkpoint_member(&m.id, name), bytes)?;
            digest.file(name, bytes.len() as u64, &Sha256::digest(bytes));
        }
        let mut sha = Sha256::new();
        out.member(&checkpoint_member(&m.id, "pages"), m.pages_len, |w| {
            let mut left = m.pages_len;
            while left > 0 {
                let chunk = &mut buf[..left.min(CHUNK as u64) as usize];
                (&m.pages).read_exact(chunk).map_err(|_| format!("checkpoint {}: its pages file is shorter than its manifest says", m.id))?;
                sha.update(&*chunk);
                w.write_all(chunk)?;
                left -= chunk.len() as u64;
            }
            Ok(())
        })?;
        digest.file("pages", m.pages_len, &sha.finalize());
    }
    if let Some(s) = sending {
        out.member(&template_member(&tid), s.len(), |w| s.write(w).map(drop))?;
    }
    let bytes = out.finish()?;
    Ok(json!({"saved": entry.id, "name": entry.name, "chain": header.chain.len(), "template_id": tid, "template": header.template, "bytes": bytes,
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

/// A checkpoint this host has under the id of one being loaded, compared with it before the store's
/// lock is taken: each file compared is held open (`None`: absent, as it must be), so its inode is
/// never another's meanwhile. Under the lock, then, its names leading to these inodes still is
/// enough; only if they do not are its files hashed again (`has`).
struct Pinned {
    dir: OwnedFd,
    files: Vec<(&'static str, Option<File>)>,
    equal: bool,
}

fn regular(f: &File) -> bool {
    crate::util::fstat(f.as_raw_fd()).is_ok_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG)
}

impl Pinned {
    fn open(dir: &Path) -> Option<Pinned> {
        let dir = open_dir_at(libc::AT_FDCWD, &CString::new(dir.as_os_str().as_bytes()).ok()?).ok()?;
        Some(Pinned { dir, files: vec![], equal: true })
    }

    /// Compares its `name` with `want` (`None`: it has none).
    fn compare(&mut self, name: &'static str, want: Option<&[u8]>) {
        match (open_at(self.dir.as_raw_fd(), name), want) {
            (Ok(f), Some(want)) => {
                let mut have = vec![];
                self.equal &= regular(&f) && (&f).take(want.len() as u64 + 1).read_to_end(&mut have).is_ok() && have == want;
                self.files.push((name, Some(f)));
            }
            (Err(e), None) if e.kind() == io::ErrorKind::NotFound => self.files.push((name, None)),
            _ => self.equal = false,
        }
    }

    /// Its pages, if as long as `len`, to compare as they are read.
    fn pages(&mut self, len: u64) -> Option<File> {
        let f = open_at(self.dir.as_raw_fd(), "pages").ok().filter(|f| regular(f) && f.metadata().is_ok_and(|m| m.len() == len));
        match f.as_ref().and_then(|f| f.try_clone().ok()) {
            Some(pin) => self.files.push(("pages", Some(pin))),
            None => self.equal = false,
        }
        f
    }

    /// Whether `dest`'s files are still the ones compared.
    fn still(&self, dest: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        self.files.iter().all(|(name, f)| match (std::fs::symlink_metadata(dest.join(name)), f) {
            (Ok(m), Some(f)) => crate::util::fstat(f.as_raw_fd()).is_ok_and(|st| (st.st_dev, st.st_ino) == (m.dev(), m.ino())),
            (Err(e), None) => e.kind() == io::ErrorKind::NotFound,
            _ => false,
        })
    }
}

/// Where a verified checkpoint's files go: staged, or compared with the one this host has under its id.
enum Sink {
    Stage(Staging),
    Same(Pinned),
}

/// A checkpoint's pages, as `Sink::pages` takes them.
enum Pages {
    Stage(File),
    Same { have: Option<File>, buf: Vec<u8> },
}

impl Sink {
    /// File `name`'s `bytes` (`None`: it has none).
    fn small(&mut self, name: &'static str, bytes: Option<&[u8]>) -> Result<()> {
        match (self, bytes) {
            (Sink::Stage(s), Some(bytes)) => drop(s.add_file(name, bytes)?),
            (Sink::Stage(_), None) => {}
            (Sink::Same(p), bytes) => p.compare(name, bytes),
        }
        Ok(())
    }

    fn pages(&mut self, len: u64) -> Result<Pages> {
        Ok(match self {
            Sink::Stage(s) => {
                let file = s.create("pages")?;
                reserve(&file, len)?;
                Pages::Stage(file)
            }
            Sink::Same(p) => Pages::Same { have: p.pages(len), buf: vec![] },
        })
    }
}

impl Pages {
    fn put(&mut self, chunk: &[u8]) -> Result<()> {
        match self {
            Pages::Stage(f) => f.write_all(chunk)?,
            Pages::Same { have: Some(f), buf } => {
                buf.resize(chunk.len(), 0);
                if f.read_exact(buf).is_err() || buf != chunk {
                    *self = Pages::Same { have: None, buf: vec![] };
                }
            }
            Pages::Same { have: None, .. } => {}
        }
        Ok(())
    }

    /// Whether they were the same (staged: synced).
    fn finish(self) -> Result<bool> {
        match self {
            Pages::Stage(f) => {
                f.sync_all()?;
                Ok(true)
            }
            Pages::Same { have, .. } => Ok(have.is_some()),
        }
    }
}

/// One checkpoint of the chain, read and verified: staged, or already in the store.
struct Loaded {
    /// Its id here: the source's, unless its parent's path was rewritten (`Parent`).
    id: String,
    manifest: Manifest,
    staging: Option<Staging>,
    /// The one here under its id, compared with it.
    pinned: Option<Pinned>,
    /// The SHA-256 of each of its files as it is here (`None`: it has none): what one found under its id must have.
    files: Vec<(&'static str, Option<Vec<u8>>)>,
    /// Its metadata, as a restore counts it (`chain_meta_budget`).
    meta: u64,
}

fn file_sha(path: &Path) -> io::Result<Vec<u8>> {
    let mut h = Sha256::new();
    io::copy(&mut File::open(path)?, &mut h)?;
    Ok(h.finalize().to_vec())
}

/// Whether checkpoint directory `dir` has exactly `files` (by SHA-256; `None`: none of that name).
fn has(dir: &Path, files: &[(&str, Option<Vec<u8>>)]) -> bool {
    files.iter().all(|(name, sha)| match (file_sha(&dir.join(name)), sha) {
        (Ok(have), Some(sha)) => have == *sha,
        (Err(e), None) => e.kind() == io::ErrorKind::NotFound,
        _ => false,
    })
}

/// Reads checkpoint `id` (`chain[i]`), whose parent the chain says is `parent` (the source's id and
/// the one it has here), and its run settings if `spec`, verifying it as `Link::open` and
/// `PageFile::read` do: each file within its limit, its pages against their checksums. Its parent
/// is named `../ID` here, the store's way. One checkpoint's metadata is held at a time, so the
/// chain's is not limited here (a restore applies its host's budget), only each file's.
fn receive(
    src: &mut Source,
    store_dir: &Path,
    id: &str,
    parent: Option<(&str, &str)>,
    template_id: &str,
    spec: bool,
    digest: &mut SaveDigest,
) -> Result<Loaded> {
    let bad = |why: &str| format!("checkpoint {id}: {why}");
    digest.checkpoint(id);
    // Each member is held whole in memory as it is checked: none past what a restore here reads of a
    // whole chain, so a forged length exhausts no memory (and none a restore here could not open is lost).
    let room = chain_meta_budget();
    let take = |len: u64, max: u64, what: &str| -> Result<()> {
        ensure!(len <= max, "{}", bad(&format!("its {what} is too long")));
        ensure!(len <= room, "{}", bad(&format!("its {what} has more than the {} MiB of metadata a restore here reads", room >> 20)));
        Ok(())
    };
    let len = src.member(&checkpoint_member(id, "manifest.json"))?;
    take(len, MAX_MANIFEST, "manifest")?;
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
    // This host may have one by its id, which is no cryptographic check: what was sent is verified all
    // the same, then either staged or, for one here, compared byte for byte with it (and used only if equal).
    let local = store_dir.join(&here);
    let mut sink = match read_manifest(&local).ok().and_then(|_| Pinned::open(&local)) {
        Some(mut p) => {
            p.compare("manifest.json", Some(&text));
            Sink::Same(p)
        }
        None => Sink::Stage(Staging::import(store_dir)?),
    };
    let spec = match spec {
        true => {
            let len = src.member(&checkpoint_member(id, SPEC))?;
            take(len, MAX_SPEC, "run settings")?;
            let bytes = read_all(src, len)?;
            check_spec(&bytes).map_err(|e| bad(&e.to_string()))?;
            digest.file(SPEC, len, &Sha256::digest(&bytes));
            Some(bytes)
        }
        false => None,
    };
    sink.small(SPEC, spec.as_deref())?;
    let want = |name: &str| manifest.files.get(name).cloned().ok_or_else(|| bad(&format!("its manifest lists no {name}")));
    let mut checked = |name: &'static str, max: u64, sink: &mut Sink| -> Result<Vec<u8>> {
        let want = want(name)?;
        let len = src.member(&checkpoint_member(id, name))?;
        ensure!(len == want.len, "{}", bad(&format!("its {name} is not as long as its manifest says")));
        take(len, max, name)?;
        let bytes = read_all(src, len)?;
        ensure!(sum(&bytes) == want.hash, "{}", bad(&format!("its {name} does not match its checksum")));
        digest.file(name, len, &Sha256::digest(&bytes));
        sink.small(name, Some(&bytes))?;
        Ok(bytes)
    };
    let vmstate = checked("vmstate", MAX_VMSTATE, &mut sink)?;
    let map_max = manifest.guest_pages * 36 + 24;
    let map = checked("pagemap", map_max, &mut sink)?;
    let meta = (text.len() + vmstate.len() + map.len()) as u64;
    let mut files = vec![
        (SPEC, spec.as_ref().map(|b| Sha256::digest(b).to_vec())),
        ("vmstate", Some(Sha256::digest(&vmstate).to_vec())),
        ("pagemap", Some(Sha256::digest(&map).to_vec())),
    ];
    drop(vmstate);
    let (runs, sums) = parse_pagemap(&map, manifest.guest_pages, manifest.parent.is_some(), 0).map_err(|e| bad(&e.to_string()))?;
    drop(map);
    let data: u64 = runs.iter().filter(|r| r.2 == DATA).map(|r| r.1).sum();
    let pages_len = data * PAGE_SIZE as u64;
    ensure!(data == manifest.data_pages && want("pages")?.len == pages_len, "{}", bad("its page counts do not add up"));
    let len = src.member(&checkpoint_member(id, "pages"))?;
    ensure!(len == pages_len, "{}", bad("its pages are not as long as its manifest says"));
    let mut out = sink.pages(len)?;
    let per = CHUNK / PAGE_SIZE;
    let (mut buf, mut sha) = (vec![0u8; CHUNK], Sha256::new());
    let mut d = 0;
    while d < data {
        let n = ((data - d) as usize).min(per);
        let chunk = &mut buf[..n * PAGE_SIZE];
        src.reader().read_exact(chunk).map_err(truncated)?;
        sha.update(&*chunk);
        for (i, page) in chunk.chunks(PAGE_SIZE).enumerate() {
            ensure!(crate::crc32c::page(page).0 == sums[d as usize + i], "{}", bad(&format!("its data page {} does not match its checksum", d as usize + i)));
        }
        out.put(chunk)?;
        d += n as u64;
    }
    let equal = out.finish()?;
    let sha = sha.finalize();
    digest.file("pages", len, &sha);
    files.extend([("pages", Some(sha.to_vec())), ("manifest.json", Some(Sha256::digest(&text).to_vec()))]);
    let (staging, pinned) = match sink {
        Sink::Stage(staging) => {
            staging.add_file("manifest.json", &text)?;
            (Some(staging), None)
        }
        Sink::Same(p) => {
            ensure!(
                p.equal && equal,
                "{}",
                bad(&format!("this host has a checkpoint {here} with other files: remove it (flexvm checkpoint rm {here}) to load this one"))
            );
            (None, Some(p))
        }
    };
    Ok(Loaded { id: here, manifest, staging, pinned, files, meta })
}

/// `checkpoint load`: a `save`'s tar from `r`, into the store, named `name` (else as it was saved);
/// with `sha256`, only if that is the save's (`SaveDigest`). `in_use`: the template ids VMs here use
/// (`Host::template_users`), so a template it received stays if the load fails after all but one uses it.
pub fn load(state: &Path, paths: &Paths, r: &mut dyn Read, name: Option<&str>, sha256: Option<&str>, in_use: &dyn Fn() -> BTreeSet<String>) -> Result<Value> {
    let mut tar = TarIn { r, left: 0, pad: 0 };
    let len = tar.member(HEADER).map_err(|e| format!("not a flexvm checkpoint save: {e}"))?;
    ensure!(len <= MAX_HEADER, "its {HEADER} is too long");
    let mut src = Source::Tar(tar);
    let header: Header = serde_json::from_slice(&read_all(&mut src, len)?).map_err(|e| format!("its {HEADER}: {e}"))?;
    import(state, paths, header, &mut src, name, sha256, in_use)
}

/// `checkpoint load -i DIR`: checkpoint directory `dir` (v0.1.0's, or a copy of a stored one) and its
/// chain, with their run settings, into the store; its template is not in it, so this host needs its
/// generation to restore it.
pub fn load_dir(state: &Path, paths: &Paths, dir: &Path, name: Option<&str>, sha256: Option<&str>) -> Result<Value> {
    let ck = Checkpoint::open(dir)?;
    let chain: Vec<String> = std::iter::once(ck.id.clone()).chain(ck.chain_ids.iter().cloned()).collect();
    let mut dirs = BTreeMap::new();
    for (d, id) in std::iter::once(&ck.dir).chain(&ck.chain).zip(&chain) {
        dirs.insert(id.clone(), open_dir_at(libc::AT_FDCWD, &CString::new(d.as_os_str().as_bytes())?)?);
    }
    let specs = chain.iter().filter(|id| crate::util::stat_at(dirs[*id].as_raw_fd(), &CString::new(SPEC).unwrap()).is_some()).cloned().collect();
    let header = Header { format: EXPORT_FORMAT, id: ck.id.clone(), name: None, chain, template_id: ck.manifest.template_id.clone(), template: false, specs };
    import(state, paths, header, &mut Source::Dir { dirs, file: None }, name, sha256, &BTreeSet::new)
}

/// The checkpoint name `names/NAME` links to, if any.
fn named(state: &Path, name: &str) -> Option<String> {
    let target = std::fs::read_link(store::dir(state).join("names").join(name)).ok()?;
    Some(target.file_name()?.to_string_lossy().into_owned())
}

/// How a load has the chain's template generation.
#[derive(Clone, Copy, PartialEq)]
enum How {
    Present,
    Received,
    Missing,
}

impl How {
    fn as_str(self) -> &'static str {
        match self {
            How::Present => "present",
            How::Received => "received",
            How::Missing => "missing",
        }
    }
}

fn import(
    state: &Path,
    paths: &Paths,
    header: Header,
    src: &mut Source,
    name: Option<&str>,
    sha256: Option<&str>,
    in_use: &dyn Fn() -> BTreeSet<String>,
) -> Result<Value> {
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
    let specs: BTreeSet<&String> = header.specs.iter().collect();
    ensure!(specs.len() == header.specs.len() && specs.iter().all(|id| chain.contains(id)), "its {HEADER} names run settings of no checkpoint of its chain");
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
    let (mut loaded, mut digest): (Vec<Loaded>, _) = (vec![], SaveDigest::default());
    for (i, id) in chain.iter().enumerate().rev() {
        let parent = loaded.last().map(|p: &Loaded| (chain[i + 1].as_str(), p.id.as_str()));
        let l = receive(src, &store_dir, id, parent, &header.template_id, specs.contains(id), &mut digest)?;
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
    let open = |dir: PathBuf| -> Result<Arc<Template>> {
        let tpl = Template::open_dir(tid, dir)?;
        tpl.check_vouched(digests.as_ref(), "the checkpoint")?;
        Ok(tpl)
    };
    // Held until the checkpoint that uses it is published: no prune or `rmi` removes it meanwhile.
    let (tpl, how) = match Template::generation(paths, tid) {
        Some(dir) => {
            if header.template {
                src.member(&template_member(tid))?;
                src.skip()?;
            }
            (Some(open(dir)?), How::Present)
        }
        None if header.template => {
            let vouched = digests.as_ref().ok_or("the checkpoint records no SHA-256 digests of its template, which cannot be verified")?;
            src.member(&template_member(tid))?;
            let _turn = template::turn(paths, tid, Instant::now() + TURN_WAIT)?;
            match Template::generation(paths, tid) {
                // Another arrival brought it meanwhile.
                Some(dir) => {
                    src.skip()?;
                    (Some(open(dir)?), How::Present)
                }
                None => {
                    let Source::Tar(tar) = src else { bail!("a checkpoint directory has no template") };
                    // Nothing follows it, checked before it is published.
                    let finish = |t: &mut TarIn| {
                        ensure!(t.left == 0, "template {tid}: the archive has more of it than it is");
                        t.end()
                    };
                    // Refused unless its digests are `vouched`, as `check_vouched` would.
                    (Some(template::receive(paths, tar, tid, Some(vouched), finish)?), How::Received)
                }
            }
        }
        None => (None, How::Missing),
    };
    if how != How::Received {
        src.end()?;
    }
    let (id, stored) = match publish(state, &mut loaded, name.as_deref()) {
        Ok(done) => done,
        Err(e) => {
            // Nothing of it stays: not the template it brought either, unless something here uses it by now.
            drop(tpl);
            if how == How::Received {
                let _ = template::prune(paths, Some(tid), in_use);
            }
            return Err(e);
        }
    };
    drop(tpl);
    let meta: u64 = loaded.iter().map(|l| l.meta).sum();
    if meta > chain_meta_budget() {
        warn(format_args!(
            "loaded checkpoint {id}, but its chain has {} MiB of metadata, more than a restore here reads ({} MiB): restore it on a host with more memory",
            meta >> 20,
            chain_meta_budget() >> 20
        ));
    }
    if how == How::Missing {
        warn(format_args!("loaded checkpoint {id}, but template generation {tid} is not here: restoring it needs it (pull its image, or load a save of it)"));
    }
    Ok(json!({"loaded": id, "name": name, "chain": loaded.len(), "stored": stored, "template_id": tid, "template": how.as_str(), "sha256": sha}))
}

/// Why `publish` failed: undoing what it published, or keeping it (`Keep`), as it may be in use.
enum Abort {
    Undo(crate::util::Error),
    /// A checkpoint or name may stay (not durably removed): what it needs stays too.
    Keep(crate::util::Error),
}

impl<E: Into<crate::util::Error>> From<E> for Abort {
    fn from(e: E) -> Self {
        Abort::Undo(e.into())
    }
}

/// Publishes the chain `loaded` (oldest first) and names its head `name`: its id, and how many of it
/// were stored. Under the store's lock, exclusive: nothing is published (another load's, which may
/// revoke it) or removed (`rm`, `prune`) meanwhile. Whatever is under an id now, found before or
/// published since, is used only if it has the very files verified here, its id being no
/// cryptographic check. On failure, what it published goes again.
fn publish(state: &Path, loaded: &mut [Loaded], name: Option<&str>) -> Result<(String, usize)> {
    let _lock = store::lock(state, libc::LOCK_EX)?;
    let store_dir = store::dir(state);
    let mut published = vec![];
    let done = (|| -> std::result::Result<String, Abort> {
        for l in loaded.iter_mut() {
            let dest = store_dir.join(&l.id);
            match std::fs::symlink_metadata(dest.join("manifest.json")) {
                Ok(_) => ensure!(
                    l.pinned.as_ref().is_some_and(|p| p.still(&dest)) || has(&dest, &l.files),
                    "checkpoint {} here has other files than the save's: remove it (flexvm checkpoint rm {0}) to load this one",
                    l.id
                ),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    // A revoked publication's leftover (as `rm` clears it), else nothing.
                    if std::fs::symlink_metadata(&dest).is_ok() {
                        std::fs::remove_dir_all(&dest)?;
                        crate::util::sync_dir(&store_dir)?;
                    }
                    let s = l.staging.take().ok_or_else(|| format!("checkpoint {} here was removed as this one loaded; load it again", l.id))?;
                    match s.publish_as(&l.id) {
                        Ok(true) => published.push(l.id.clone()),
                        Ok(false) => bail!("checkpoint {} was published as this one loaded; load it again", l.id),
                        Err(CommitError::Failed(e)) => return Err(e.into()),
                        // Its manifest may stay: what it builds on stays too, whole.
                        Err(CommitError::Uncertain(e)) => return Err(Abort::Keep(e)),
                    }
                }
                Err(e) => return Err(io::Error::new(e.kind(), format!("checking checkpoint {}: {e}", dest.display())).into()),
            }
        }
        let id = loaded.last().unwrap().id.clone();
        // Its chain, by its manifests, as a restore finds it (its other files were verified as they came).
        chain_ids(&store_dir.join(&id)).map_err(|e| format!("the loaded checkpoint {id} does not open: {e}"))?;
        #[cfg(test)]
        ensure!(!tests::FAIL_NAMING.get(), "injected: naming it failed");
        if let Some(n) = name {
            if named(state, n).as_deref() != Some(id.as_str()) {
                if let Err(e) = store::link(state, n, &id) {
                    // Perhaps linked, not durably: it goes before what it names, or that stays.
                    if named(state, n).as_deref() == Some(id.as_str()) {
                        if let Err(u) = crate::util::unlink_durably(&store::dir(state).join("names").join(n)) {
                            return Err(Abort::Keep(format!("{e}; removing the name failed too: {u}").into()));
                        }
                    }
                    return Err(e.into());
                }
            }
        }
        Ok(id)
    })();
    match done {
        Ok(id) => Ok((id, published.len())),
        Err(Abort::Keep(e)) if published.is_empty() => Err(e),
        Err(Abort::Keep(e)) => Err(format!("{e} (the checkpoints it published are kept, whole: flexvm checkpoint rm removes them)").into()),
        Err(Abort::Undo(e)) => {
            published.reverse();
            match store::unpublish(state, &published) {
                Ok(()) => Err(e),
                Err(u) => Err(format!("{e} (removing the checkpoints it published: {u}; flexvm checkpoint rm removes them)").into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::format::MAGIC;
    use std::{cell::Cell, fs};

    thread_local! {
        /// Fails `publish` once the chain is published, before it is named.
        pub(super) static FAIL_NAMING: Cell<bool> = const { Cell::new(false) };
    }

    /// The run settings of the head of `saved`'s chain.
    fn spec() -> Vec<u8> {
        serde_json::to_vec(&crate::app::RunSpec { keep: true, env: vec!["A=1".into()], entrypoint: Some(vec!["/bin/app".into()]), ..Default::default() })
            .unwrap()
    }

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
        load(&h.state, &h.paths, &mut &tar[..], name, None, &BTreeSet::new)
    }

    /// A store with a named chain of two (a full checkpoint and a delta) and its save.
    fn saved() -> (crate::test_util::TempDir, Paths, Arc<Template>, crate::test_util::TempDir, Vec<String>, Vec<u8>) {
        let (dir, paths, tpl) = template::tests::sendable();
        let state = crate::test_util::TempDir::new("ckpt-save");
        let base = stored(&state, &tpl, None, 0, &[1, 2, 3], |_| {});
        let head = stored(&state, &tpl, Some(&base), 10, &[4], |_| {});
        store::link(&state, "web", &head).unwrap();
        fs::write(store::dir(&state).join(&head).join(SPEC), spec()).unwrap();
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
            let files: &[&str] =
                if id == &chain[0] { &["manifest.json", SPEC, "vmstate", "pagemap", "pages"] } else { &["manifest.json", "vmstate", "pagemap", "pages"] };
            want.extend(files.iter().map(|f| checkpoint_member(id, f)));
        }
        want.push(template_member(&tpl.meta.id));
        assert_eq!(names, want);
        let b = fresh(&paths);
        // B's tag names another build: it stays as it is.
        fs::create_dir_all(&b.paths.templates).unwrap();
        std::os::unix::fs::symlink(".gen/0123456789abcdef", b.paths.templates.join("t")).unwrap();
        // `--sha256`: only the save whose SHA-256 `save` printed.
        let sha = save(&state, &paths, "web", &mut vec![]).unwrap()["sha256"].as_str().unwrap().to_string();
        let e = load(&b.state, &b.paths, &mut &tar[..], None, Some(&"0".repeat(64)), &BTreeSet::new).err().unwrap().to_string();
        assert!(e.contains(&format!("SHA-256 is {sha}")) && nothing(&b), "{e}");
        let r = load(&b.state, &b.paths, &mut &tar[..], None, Some(&sha.to_uppercase()), &BTreeSet::new).unwrap();
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
        // Its run settings came with it; its base has none.
        assert_eq!(fs::read(store::dir(&b.state).join(&chain[0]).join(SPEC)).unwrap(), spec());
        assert!(!store::dir(&b.state).join(&chain[1]).join(SPEC).exists());
        assert_eq!(crate::lifecycle::read_spec(&store::dir(&b.state).join(&chain[0])).unwrap().env, ["A=1"]);
        // Again: nothing new, and its own name is no conflict.
        let r = load_bytes(&b, &tar, None).unwrap();
        assert_eq!((r["stored"].as_u64(), r["template"].as_str(), r["sha256"].as_str()), (Some(0), Some("present"), Some(&sha[..])));
        // One here with other run settings, or none, or some where the save has none, is not the save's.
        let here = store::dir(&b.state).join(&chain[0]).join(SPEC);
        for (at, bytes) in [(&here, Some(&b"{}"[..])), (&here, None), (&store::dir(&b.state).join(&chain[1]).join(SPEC), Some(&b"{}"[..]))] {
            match bytes {
                Some(bytes) => fs::write(at, bytes).unwrap(),
                None => fs::remove_file(at).unwrap(),
            }
            let e = load_bytes(&b, &tar, None).err().unwrap().to_string();
            assert!(e.contains("with other files"), "{e}");
            match at == &here {
                true => fs::write(at, spec()).unwrap(),
                false => fs::remove_file(at).unwrap(),
            }
        }
        assert_eq!(load_bytes(&b, &tar, None).unwrap()["stored"], 0);
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
        let e = load_bytes(&b, &more, None).err().unwrap().to_string();
        assert!(e.contains(&format!("a member after the save's last: {HEADER:?}")), "{e}");
        assert!(nothing(&b), "not even its template");
        let mut more = tar[..tar.len() - 2 * BLOCK].to_vec();
        more.extend_from_slice(&[7u8; 2 * BLOCK]);
        let e = load_bytes(&b, &more, None).err().unwrap().to_string();
        assert!(e.contains("bytes after the save's last member"), "{e}");
        assert!(nothing(&b));
        // Anything but zeros after the end, or zeros past `MAX_TAIL`; zeros (a tar record's padding) are taken.
        for (tail, ok) in [(vec![0u8; 9 * BLOCK], true), ([vec![0u8; BLOCK], vec![1]].concat(), false), (vec![0u8; MAX_TAIL as usize + 1], false)] {
            let b = fresh(&paths);
            let r = load_bytes(&b, &[&tar[..], &tail].concat(), None);
            assert_eq!(r.is_ok(), ok, "{r:?}");
            assert!(ok || nothing(&b));
        }
    }

    #[test]
    fn a_damaged_checkpoint_here_is_refused_even_as_its_own_save() {
        let (_dir, paths, _tpl, state, chain, _) = saved();
        // Damaged where it is stored: its save carries the damage (save reads pages unchecked), and
        // loading it back where it came from verifies the pages as for any other host.
        let pages = store::dir(&state).join(&chain[1]).join("pages");
        let mut damaged = fs::read(&pages).unwrap();
        damaged[PAGE_SIZE + 9] ^= 1;
        fs::write(&pages, &damaged).unwrap();
        let mut tar = vec![];
        save(&state, &paths, "web", &mut tar).unwrap();
        let e = load(&state, &paths, &mut &tar[..], None, None, &BTreeSet::new).err().unwrap().to_string();
        assert!(e.contains("data page 1 does not match its checksum"), "{e}");
        assert_eq!(ids(&state).len(), 2);
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

    #[test]
    fn run_settings_are_in_the_saves_sha256_and_a_save_without_them_is_as_before() {
        let (_dir, paths, _tpl, state, chain, tar) = saved();
        // The base has none: its save's header names none (as a save before them), and its SHA-256 has none.
        let base = |tar: &[u8]| -> Value {
            let mut a = tar::Archive::new(tar);
            let mut first = a.entries().unwrap().next().unwrap().unwrap();
            serde_json::from_reader(&mut first).unwrap()
        };
        let mut plain = vec![];
        let without = save(&state, &paths, &chain[1], &mut plain).unwrap()["sha256"].as_str().unwrap().to_string();
        assert!(base(&plain).get("specs").is_none(), "{}", base(&plain));
        assert_eq!(base(&tar)["specs"], json!([chain[0]]));
        fs::write(store::dir(&state).join(&chain[1]).join(SPEC), spec()).unwrap();
        let with = save(&state, &paths, &chain[1], &mut vec![]).unwrap()["sha256"].as_str().unwrap().to_string();
        assert_ne!(with, without, "the SHA-256 covers them");
        // A save from before them (none named) loads, with none.
        let b = fresh(&paths);
        let r = load(&b.state, &b.paths, &mut &plain[..], None, Some(&without), &BTreeSet::new).unwrap();
        assert_eq!(r["loaded"], chain[1].as_str());
        assert!(!store::dir(&b.state).join(&chain[1]).join(SPEC).exists());
        // Settings no restore could read are refused, saving and loading.
        fs::write(store::dir(&state).join(&chain[1]).join(SPEC), b"{\"keep\": 3}").unwrap();
        assert!(save(&state, &paths, &chain[1], &mut vec![]).err().unwrap().to_string().contains("run settings"));
        let header = |specs: &[&str]| {
            serde_json::to_vec(&json!({"format": 1, "id": chain[1], "name": null, "chain": [chain[1]], "template_id": "0", "template": false, "specs": specs}))
                .unwrap()
        };
        for specs in [&[&chain[0][..]][..], &[&chain[1], &chain[1]]] {
            let c = fresh(&paths);
            let e = load_bytes(&c, &forged(&[(HEADER, header(specs))]), None).err().unwrap().to_string();
            assert!(e.contains("run settings of no checkpoint"), "{e}");
        }
    }

    #[test]
    fn a_load_that_fails_as_it_publishes_leaves_nothing() {
        let (_dir, paths, _tpl, _state, chain, tar) = saved();
        let b = fresh(&paths);
        FAIL_NAMING.set(true);
        let e = load_bytes(&b, &tar, None).err().unwrap().to_string();
        FAIL_NAMING.set(false);
        assert!(e.contains("injected"), "{e}");
        // Neither the chain, published by then, nor the template it brought.
        assert!(nothing(&b), "{:?} {:?}", ids(&b.state), gens(&b.paths));
        let left: Vec<String> = fs::read_dir(store::dir(&b.state)).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert!(left.iter().all(|n| n == "names" || n.starts_with('.') && !n.starts_with(".removed-")), "{left:?}");
        // A template that was here stays, and so does a checkpoint of the chain that was.
        load_bytes(&b, &tar, None).unwrap();
        store::remove(&b.state, &[chain[0].clone()], false).unwrap();
        FAIL_NAMING.set(true);
        assert!(load_bytes(&b, &tar, Some("other")).is_err());
        FAIL_NAMING.set(false);
        assert_eq!(ids(&b.state), [chain[1].clone()]);
        assert_eq!(gens(&b.paths).len(), 1);
    }

    #[test]
    fn a_checkpoint_compared_is_checked_again_by_its_inodes_and_hashed_only_if_they_changed() {
        let (_dir, _paths, _tpl, state, chain, _) = saved();
        let dir = store::dir(&state).join(&chain[0]);
        let mut p = Pinned::open(&dir).unwrap();
        let files: Vec<(&str, Option<Vec<u8>>)> = ["manifest.json", "vmstate", "pagemap"]
            .into_iter()
            .map(|n| {
                let bytes = fs::read(dir.join(n)).unwrap();
                p.compare(n, Some(&bytes));
                (n, Some(Sha256::digest(&bytes).to_vec()))
            })
            .chain([("gone", None)])
            .collect();
        p.compare("gone", None);
        assert!(p.equal && p.still(&dir) && has(&dir, &files));
        // The same bytes in another inode: no longer pinned, but hashed, still the same.
        let vmstate = fs::read(dir.join("vmstate")).unwrap();
        fs::remove_file(dir.join("vmstate")).unwrap();
        fs::write(dir.join("vmstate"), &vmstate).unwrap();
        assert!(!p.still(&dir) && has(&dir, &files));
        fs::write(dir.join("vmstate"), b"other").unwrap();
        assert!(!has(&dir, &files));
        // One that should be absent, there.
        fs::write(dir.join("gone"), b"").unwrap();
        let mut q = Pinned::open(&dir).unwrap();
        q.compare("gone", None);
        assert!(!q.equal);
    }

    #[test]
    fn a_member_past_what_a_restore_here_reads_is_refused_before_it_is_read() {
        let (_dir, paths, tpl, _state, _, _) = saved();
        let scratch = fresh(&paths);
        let room = chain_meta_budget();
        // A manifest whose page map is as long as its (forged) guest memory allows, and longer than that.
        let id = stored(&scratch.state, &tpl, None, 0, &[1], |m| {
            m.guest_pages = MAX_GUEST_PAGES;
            m.files.get_mut("pagemap").unwrap().len = room + 1;
        });
        let dir = store::dir(&scratch.state).join(&id);
        let header = serde_json::to_vec(&json!({"format": 1, "id": id, "name": null, "chain": [id], "template_id": tpl.meta.id, "template": false})).unwrap();
        let mut tar = forged(&[
            (HEADER, header),
            (&checkpoint_member(&id, "manifest.json"), fs::read(dir.join("manifest.json")).unwrap()),
            (&checkpoint_member(&id, "vmstate"), b"state".to_vec()),
        ]);
        // Its header alone: its bytes are never sent, nor needed.
        tar.truncate(tar.len() - 2 * BLOCK);
        let mut h = tar::Header::new_gnu();
        h.set_path(checkpoint_member(&id, "pagemap")).unwrap();
        h.set_size(room + 1);
        h.set_cksum();
        tar.extend_from_slice(h.as_bytes());
        let b = fresh(&paths);
        let e = load_bytes(&b, &tar, None).err().unwrap().to_string();
        assert!(e.contains("a restore here reads"), "{e}");
        assert!(nothing(&b));
    }
}
