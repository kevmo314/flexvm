//! Where images come from: a registry, a `docker save` or OCI archive
//! (`.tar`), or an OCI image layout directory. Each yields the verified image
//! config and its layers in order, as streams; nothing is held in memory or
//! extracted to disk first.
//!
//! All of it is untrusted. Documents are size-capped and digest-checked
//! before use; layer blobs are checked against their descriptors' digest and
//! size (`Layer::verify`) right before they are unpacked, and their
//! uncompressed contents against the config's `diff_ids` while unpacking.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::reference::Reference;
use super::registry::{blob_path, sha256_hex, Registry};
use super::unpack::{Limits, MAX_DOCUMENT};
use crate::bail;
use crate::util::Result;

pub struct Image {
    /// Manifest digest (the config digest for a legacy `docker save`).
    pub digest: String,
    pub config_digest: String,
    /// The config, already checked against `config_digest`.
    pub config: Vec<u8>,
    pub layers: Vec<Layer>,
    /// Digests of the uncompressed layers, from the config.
    pub diff_ids: Vec<String>,
}

pub struct Layer {
    pub src: Blob,
    /// The descriptor's digest and size; a legacy `docker save` has neither
    /// and relies on the config's `diff_ids` alone.
    pub digest: Option<String>,
    pub size: Option<u64>,
}

/// A blob: a whole file, or a member of an uncompressed tar archive.
pub enum Blob {
    File(PathBuf),
    Slice { file: PathBuf, offset: u64, len: u64 },
}

impl Blob {
    fn open(&self) -> Result<(Box<dyn Read>, u64)> {
        Ok(match self {
            Blob::File(p) => {
                let f = File::open(p)?;
                let m = f.metadata()?;
                if !m.is_file() {
                    bail!("{p:?} is not a regular file");
                }
                (Box::new(f), m.len())
            }
            Blob::Slice { file, offset, len } => {
                let mut f = File::open(file)?;
                f.seek(SeekFrom::Start(*offset))?;
                (Box::new(f.take(*len)), *len)
            }
        })
    }

    fn read_document(&self) -> Result<Vec<u8>> {
        let (r, len) = self.open()?;
        if len > MAX_DOCUMENT {
            bail!("document of {len} bytes is over the {MAX_DOCUMENT} byte limit");
        }
        let mut data = Vec::with_capacity(len as usize);
        r.take(MAX_DOCUMENT).read_to_end(&mut data)?;
        Ok(data)
    }
}

impl Layer {
    pub fn name(&self) -> String {
        match (&self.digest, &self.src) {
            (Some(d), _) => d.chars().take(19).collect(),
            (None, Blob::File(p)) => p.to_string_lossy().chars().rev().take(24).collect::<Vec<_>>().into_iter().rev().collect(),
            (None, Blob::Slice { offset, .. }) => format!("@{offset}"),
        }
    }

    pub fn open(&self) -> Result<Box<dyn Read>> {
        Ok(self.src.open()?.0)
    }

    /// Reads the whole blob and checks it against its descriptor.
    pub fn verify(&self) -> Result<()> {
        let (mut r, len) = self.src.open()?;
        if let Some(size) = self.size {
            if len != size {
                bail!("layer {} is {len} bytes, its descriptor says {size}", self.name());
            }
        }
        let Some(digest) = &self.digest else { return Ok(()) };
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        let got = format!("sha256:{:x}", h.finalize());
        if &got != digest {
            bail!("layer blob {digest} has digest {got}");
        }
        Ok(())
    }
}

/// `REF` is a local OCI layout directory, a local archive, or a registry reference.
pub fn fetch(cache: &Path, src: &str, limits: &Limits) -> Result<Image> {
    let path = Path::new(src);
    let img = if path.is_dir() {
        from_files(Files::Dir(path.to_path_buf()), limits)?
    } else if path.is_file() {
        from_files(Files::Tar(TarIndex::new(path, limits)?), limits)?
    } else {
        let r = Reference::parse(src).map_err(|e| format!("{e} (and no such file or directory)"))?;
        pull(cache, Registry::new(r), limits)?
    };
    if sha256_hex(&img.config) != img.config_digest {
        bail!("image config does not match its digest {}", img.config_digest);
    }
    Ok(img)
}

/// The config's `rootfs.diff_ids`, one per layer.
fn diff_ids(config: &[u8], layers: usize) -> Result<Vec<String>> {
    let v: Value = serde_json::from_slice(config)?;
    let ids: Vec<String> = v["rootfs"]["diff_ids"]
        .as_array()
        .ok_or("image config has no rootfs.diff_ids")?
        .iter()
        .map(|d| d.as_str().map(String::from).ok_or("bad diff_id"))
        .collect::<std::result::Result<_, _>>()?;
    if ids.len() != layers {
        bail!("image config lists {} layers, the manifest {layers}", ids.len());
    }
    for d in &ids {
        blob_path(Path::new(""), d)?; // a well-formed sha256 digest
    }
    Ok(ids)
}

/// Layer descriptors from a manifest: digests, and sizes within the download budget.
fn descriptors(manifest: &Value, limits: &Limits) -> Result<Vec<(String, u64)>> {
    let descs = manifest["layers"].as_array().ok_or("manifest has no layers")?;
    let mut total = 0u64;
    let mut out = Vec::new();
    for l in descs {
        let d = l["digest"].as_str().ok_or("layer without digest")?.to_string();
        blob_path(Path::new(""), &d)?;
        let size = l["size"].as_u64().ok_or("layer without size")?;
        total = total.saturating_add(size);
        out.push((d, size));
    }
    if total > limits.download {
        bail!("image layers total {} MiB, over the download limit (--max-download-mib)", total >> 20);
    }
    Ok(out)
}

/// Picks the linux/amd64 entry of an image index.
fn pick_platform(index: &Value) -> Result<String> {
    let manifests = index["manifests"].as_array().ok_or("image index has no manifests")?;
    fn plat(m: &Value) -> (Option<&str>, Option<&str>) {
        (m["platform"]["os"].as_str(), m["platform"]["architecture"].as_str())
    }
    let found = manifests
        .iter()
        .find(|m| plat(m) == (Some("linux"), Some("amd64")))
        // An OCI layout's index.json often lists one manifest with no platform.
        .or_else(|| manifests.iter().find(|m| m["platform"].is_null()));
    match found {
        Some(m) => Ok(m["digest"].as_str().ok_or("index entry without digest")?.to_string()),
        None => {
            let have: Vec<String> = manifests.iter().map(|m| format!("{:?}", plat(m))).collect();
            bail!("no linux/amd64 image in the index (has {})", have.join(", "))
        }
    }
}

fn pull(cache: &Path, mut reg: Registry, limits: &Limits) -> Result<Image> {
    let blobs = cache.join("blobs");
    let what = reg.r.to_string();
    let (mut manifest, mut digest) = reg.manifest(&reg.r.reference.clone())?;
    let mut depth = 0;
    while manifest["manifests"].is_array() {
        depth += 1;
        if depth > 4 {
            bail!("{what}: nested image indexes");
        }
        let d = pick_platform(&manifest)?;
        (manifest, digest) = reg.manifest(&d)?;
    }
    eprintln!("image: {what} -> {digest}");
    let config_digest = manifest["config"]["digest"].as_str().ok_or("manifest has no config")?.to_string();
    let config_size = manifest["config"]["size"].as_u64().ok_or("config without size")?;
    if config_size > MAX_DOCUMENT {
        bail!("image config of {config_size} bytes is over the {MAX_DOCUMENT} byte limit");
    }
    let config = std::fs::read(reg.blob(&config_digest, config_size, &blobs)?)?;
    let descs = descriptors(&manifest, limits)?;
    let mut layers = Vec::new();
    for (i, (d, size)) in descs.iter().enumerate() {
        let cached = blob_path(&blobs, d)?.exists();
        eprintln!(
            "image: layer {}/{} {d} {:.1} MiB{}",
            i + 1,
            descs.len(),
            *size as f64 / 1048576.0,
            if cached { " (cached)" } else { "" }
        );
        let path = reg.blob(d, *size, &blobs)?;
        layers.push(Layer { src: Blob::File(path), digest: Some(d.clone()), size: Some(*size) });
    }
    let diff_ids = diff_ids(&config, layers.len())?;
    Ok(Image { digest, config_digest, config, layers, diff_ids })
}

/// The members of an uncompressed tar archive, by path, located without
/// extracting it.
pub struct TarIndex {
    file: PathBuf,
    members: HashMap<String, Member>,
}

enum Member {
    Data { offset: u64, len: u64 },
    Link(String),
}

fn clean(p: &str) -> String {
    Path::new(p)
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

impl TarIndex {
    fn new(file: &Path, limits: &Limits) -> Result<TarIndex> {
        let mut f = File::open(file)?;
        let mut magic = [0u8; 2];
        f.read_exact(&mut magic)?;
        if magic == [0x1f, 0x8b] {
            bail!("{file:?} is compressed; decompress it first (gunzip)");
        }
        f.rewind()?;
        let mut ar = tar::Archive::new(f);
        let mut members = HashMap::new();
        let mut long_name = None;
        // Raw entries, so long names are read within a bound here rather
        // than whole by the tar crate.
        for (i, e) in ar.entries()?.raw(true).enumerate() {
            let mut e = e?;
            if i as u64 >= limits.entries {
                bail!("{file:?} has more than {} entries", limits.entries);
            }
            let kind = e.header().entry_type();
            if kind.is_gnu_longname() || kind.is_pax_local_extensions() {
                if e.size() > 4096 {
                    bail!("{file:?}: oversized tar metadata");
                }
                let mut data = Vec::new();
                e.read_to_end(&mut data)?;
                long_name = if kind.is_gnu_longname() {
                    Some(String::from_utf8_lossy(&data).trim_end_matches('\0').to_string())
                } else {
                    tar::PaxExtensions::new(&data)
                        .flatten()
                        .find(|x| x.key() == Ok("path"))
                        .and_then(|x| x.value().ok().map(String::from))
                };
                continue;
            }
            let path = clean(&long_name.take().unwrap_or_else(|| String::from_utf8_lossy(&e.header().path_bytes()).into_owned()));
            let member = if kind.is_symlink() || kind.is_hard_link() {
                let target = e.link_name()?.ok_or("link without target")?.to_string_lossy().into_owned();
                // Symlinks are relative to their directory; hard links to the archive root.
                let target = match (kind.is_symlink(), Path::new(&path).parent()) {
                    (true, Some(dir)) => clean(&normalize_join(dir, &target)),
                    _ => clean(&target),
                };
                Member::Link(target)
            } else if kind.is_file() {
                Member::Data { offset: e.raw_file_position(), len: e.size() }
            } else {
                continue;
            };
            members.insert(path, member);
        }
        Ok(TarIndex { file: file.to_path_buf(), members })
    }

    fn get(&self, path: &str) -> Result<(u64, u64)> {
        let mut p = clean(path);
        for _ in 0..16 {
            match self.members.get(&p) {
                Some(Member::Data { offset, len }) => return Ok((*offset, *len)),
                Some(Member::Link(t)) => p = t.clone(),
                None => bail!("{:?} has no {path:?}", self.file),
            }
        }
        bail!("{:?}: too many links at {path:?}", self.file)
    }
}

/// `dir/target` with `..` applied lexically.
fn normalize_join(dir: &Path, target: &str) -> String {
    let mut out: Vec<String> = clean(&dir.to_string_lossy()).split('/').filter(|s| !s.is_empty()).map(String::from).collect();
    for c in target.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c.to_string()),
        }
    }
    out.join("/")
}

/// An OCI layout or `docker save` output, as a directory or as a tarball.
enum Files {
    Dir(PathBuf),
    Tar(TarIndex),
}

impl Files {
    fn blob(&self, path: &str) -> Result<Blob> {
        match self {
            Files::Dir(d) => {
                let p = d.join(clean(path));
                if !p.is_file() {
                    bail!("{d:?} has no {path:?}");
                }
                Ok(Blob::File(p))
            }
            Files::Tar(t) => {
                let (offset, len) = t.get(path)?;
                Ok(Blob::Slice { file: t.file.clone(), offset, len })
            }
        }
    }

    fn exists(&self, path: &str) -> bool {
        match self {
            Files::Dir(d) => d.join(clean(path)).is_file(),
            Files::Tar(t) => t.get(path).is_ok(),
        }
    }

    fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.blob(path)?.read_document()
    }

    /// Reads a document blob by digest and checks it.
    fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let data = self.read(&Files::blob_name(digest)?)?;
        if sha256_hex(&data) != digest {
            bail!("blob {digest} does not match its digest");
        }
        Ok(data)
    }

    fn blob_name(digest: &str) -> Result<String> {
        Ok(blob_path(Path::new("blobs"), digest)?.to_string_lossy().into_owned())
    }
}

fn from_files(files: Files, limits: &Limits) -> Result<Image> {
    if files.exists("index.json") {
        // OCI image layout (also what `docker save` writes since Docker 25).
        let mut v: Value = serde_json::from_slice(&files.read("index.json")?)?;
        let mut digest = String::new();
        let mut depth = 0;
        while v["manifests"].is_array() {
            depth += 1;
            if depth > 4 {
                bail!("nested image indexes");
            }
            digest = pick_platform(&v)?;
            v = serde_json::from_slice(&files.read_blob(&digest)?)?;
        }
        let config_digest = v["config"]["digest"].as_str().ok_or("manifest has no config")?.to_string();
        let config = files.read_blob(&config_digest)?;
        let layers: Vec<Layer> = descriptors(&v, limits)?
            .into_iter()
            .map(|(d, size)| Ok(Layer { src: files.blob(&Files::blob_name(&d)?)?, digest: Some(d), size: Some(size) }))
            .collect::<Result<_>>()?;
        let diff_ids = diff_ids(&config, layers.len())?;
        return Ok(Image { digest, config_digest, config, layers, diff_ids });
    }
    if files.exists("manifest.json") {
        // Legacy `docker save`: [{"Config": path, "Layers": [paths]}]. No
        // digests: the config is identified by its own hash, and layers are
        // checked against its diff_ids while unpacking.
        let m: Value = serde_json::from_slice(&files.read("manifest.json")?)?;
        let m = m.get(0).ok_or("empty manifest.json")?;
        let config = files.read(m["Config"].as_str().ok_or("manifest.json has no Config")?)?;
        let config_digest = sha256_hex(&config);
        let mut total = 0u64;
        let layers: Vec<Layer> = m["Layers"]
            .as_array()
            .ok_or("manifest.json has no Layers")?
            .iter()
            .map(|l| {
                let src = files.blob(l.as_str().ok_or("bad layer path")?)?;
                total = total.saturating_add(src.open()?.1);
                Ok(Layer { src, digest: None, size: None })
            })
            .collect::<Result<_>>()?;
        if total > limits.download {
            bail!("image layers total {} MiB, over the download limit (--max-download-mib)", total >> 20);
        }
        let diff_ids = diff_ids(&config, layers.len())?;
        return Ok(Image { digest: config_digest.clone(), config_digest, config, layers, diff_ids });
    }
    bail!("not an OCI layout or docker save archive: no index.json or manifest.json")
}
