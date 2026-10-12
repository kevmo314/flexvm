//! Where images come from: a registry, a `docker save` or OCI archive
//! (`.tar`), or an OCI image layout directory. Each yields the image config
//! and its layers in order, as streams; nothing is held in memory or
//! extracted to disk first.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use super::reference::Reference;
use super::registry::{blob_path, sha256_hex, Registry};
use crate::bail;
use crate::util::Result;

pub struct Image {
    pub digest: String,
    pub config_digest: String,
    pub config: Vec<u8>,
    pub layers: Vec<Layer>,
}

/// A layer blob: a whole file, or a member of an uncompressed tar archive.
pub enum Layer {
    File(PathBuf),
    Slice { file: PathBuf, offset: u64, len: u64, name: String },
}

impl Layer {
    pub fn name(&self) -> String {
        match self {
            Layer::File(p) => p.file_name().map(|n| n.to_string_lossy().chars().take(19).collect()).unwrap_or_default(),
            Layer::Slice { name, .. } => name.clone(),
        }
    }

    pub fn open(&self) -> Result<Box<dyn Read>> {
        Ok(match self {
            Layer::File(p) => Box::new(File::open(p)?),
            Layer::Slice { file, offset, len, .. } => {
                let mut f = File::open(file)?;
                f.seek(SeekFrom::Start(*offset))?;
                Box::new(f.take(*len))
            }
        })
    }
}

/// `REF` is a local OCI layout directory, a local archive, or a registry reference.
pub fn fetch(cache: &Path, src: &str) -> Result<Image> {
    let path = Path::new(src);
    if path.is_dir() {
        return from_files(Files::Dir(path.to_path_buf()));
    }
    if path.is_file() {
        return from_files(Files::Tar(TarIndex::new(path)?));
    }
    let r = Reference::parse(src).map_err(|e| format!("{e} (and no such file or directory)"))?;
    pull(cache, Registry::new(r))
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

fn pull(cache: &Path, mut reg: Registry) -> Result<Image> {
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
    let config = std::fs::read(reg.blob(&config_digest, &blobs)?)?;
    let mut layers = Vec::new();
    let descs = manifest["layers"].as_array().ok_or("manifest has no layers")?;
    for (i, l) in descs.iter().enumerate() {
        let d = l["digest"].as_str().ok_or("layer without digest")?;
        let cached = blob_path(&blobs, d)?.exists();
        eprintln!(
            "image: layer {}/{} {d} {:.1} MiB{}",
            i + 1,
            descs.len(),
            l["size"].as_f64().unwrap_or(0.0) / 1048576.0,
            if cached { " (cached)" } else { "" }
        );
        layers.push(Layer::File(reg.blob(d, &blobs)?));
    }
    Ok(Image { digest, config_digest, config, layers })
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
    fn new(file: &Path) -> Result<TarIndex> {
        let mut f = File::open(file)?;
        let mut magic = [0u8; 2];
        f.read_exact(&mut magic)?;
        if magic == [0x1f, 0x8b] {
            bail!("{file:?} is compressed; decompress it first (gunzip)");
        }
        f.rewind()?;
        let mut ar = tar::Archive::new(f);
        let mut members = HashMap::new();
        for e in ar.entries()? {
            let e = e?;
            let path = clean(&e.path()?.to_string_lossy());
            let kind = e.header().entry_type();
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
    fn layer(&self, path: &str, name: String) -> Result<Layer> {
        match self {
            Files::Dir(d) => {
                let p = d.join(clean(path));
                if !p.is_file() {
                    bail!("{d:?} has no {path:?}");
                }
                Ok(Layer::File(p))
            }
            Files::Tar(t) => {
                let (offset, len) = t.get(path)?;
                Ok(Layer::Slice { file: t.file.clone(), offset, len, name })
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
        let mut data = Vec::new();
        self.layer(path, String::new())?.open()?.take(16 << 20).read_to_end(&mut data)?;
        Ok(data)
    }

    fn blob_name(digest: &str) -> Result<String> {
        Ok(blob_path(Path::new("blobs"), digest)?.to_string_lossy().into_owned())
    }
}

fn from_files(files: Files) -> Result<Image> {
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
            let data = files.read(&Files::blob_name(&digest)?)?;
            if sha256_hex(&data) != digest {
                bail!("blob {digest} does not match its digest");
            }
            v = serde_json::from_slice(&data)?;
        }
        let config_digest = v["config"]["digest"].as_str().ok_or("manifest has no config")?.to_string();
        let config = files.read(&Files::blob_name(&config_digest)?)?;
        let layers = v["layers"]
            .as_array()
            .ok_or("manifest has no layers")?
            .iter()
            .map(|l| {
                let d = l["digest"].as_str().ok_or("layer without digest")?;
                files.layer(&Files::blob_name(d)?, d.chars().take(19).collect())
            })
            .collect::<Result<_>>()?;
        return Ok(Image { digest, config_digest, config, layers });
    }
    if files.exists("manifest.json") {
        // Legacy `docker save`: [{"Config": path, "Layers": [paths]}].
        let m: Value = serde_json::from_slice(&files.read("manifest.json")?)?;
        let m = m.get(0).ok_or("empty manifest.json")?;
        let config = files.read(m["Config"].as_str().ok_or("manifest.json has no Config")?)?;
        let config_digest = sha256_hex(&config);
        let layers = m["Layers"]
            .as_array()
            .ok_or("manifest.json has no Layers")?
            .iter()
            .map(|l| {
                let p = l.as_str().ok_or("bad layer path")?;
                files.layer(p, p.chars().take(24).collect())
            })
            .collect::<Result<_>>()?;
        return Ok(Image { digest: config_digest.clone(), config_digest, config, layers });
    }
    bail!("not an OCI layout or docker save archive: no index.json or manifest.json")
}
