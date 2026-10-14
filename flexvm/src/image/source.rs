//! Where images come from: a registry, a `docker save` or OCI archive, or an
//! OCI layout directory. All untrusted: documents are size-capped and
//! digest-checked before use, layer blobs while they are unpacked.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use super::reference::Reference;
use super::registry::{blob_path, sha256_hex, Registry};
use super::unpack::{each_entry, lexical, Hashed, Limits, MAX_DOCUMENT};
use crate::bail;
use crate::util::Result;

pub struct Image {
    pub digest: String,
    pub config_digest: String,
    pub config: Vec<u8>,
    pub layers: Vec<Layer>,
    pub diff_ids: Vec<String>,
}

/// Digest and size are the descriptor's; a legacy `docker save` has neither and relies on `diff_ids`.
pub struct Layer {
    pub src: Blob,
    pub digest: Option<String>,
    pub size: Option<u64>,
}

pub enum Blob {
    File(PathBuf),
    Slice { file: PathBuf, offset: u64, len: u64 },
    Cached { blobs: PathBuf, registry: Box<Registry>, digest: String, size: u64 },
}

impl Blob {
    pub(super) fn open(&self) -> Result<(Box<dyn Read>, u64)> {
        Ok(match self {
            Blob::Cached { blobs, registry, digest, size } => {
                let path = registry.as_ref().clone().blob(digest, *size, blobs)?;
                return Blob::File(path).open();
            }
            Blob::File(p) => {
                use std::os::unix::fs::OpenOptionsExt;
                // Never block on a FIFO or open a device a symlink points at.
                let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW).open(p)?;
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
            (None, Blob::Cached { digest, .. }) => digest.chars().take(19).collect(),
        }
    }

    pub fn open(&self) -> Result<Hashed<Box<dyn Read>>> {
        let (inner, len) = self.src.open()?;
        self.check_size(len)?;
        Ok(Hashed::new(inner))
    }

    fn check_size(&self, len: u64) -> Result<()> {
        match self.size {
            Some(size) if size != len => bail!("layer {} is {len} bytes, its descriptor says {size}", self.name()),
            _ => Ok(()),
        }
    }

    pub fn verify(&self, mut r: Hashed<Box<dyn Read>>) -> Result<()> {
        std::io::copy(&mut r, &mut std::io::sink())?;
        self.check_size(r.n)?;
        match &self.digest {
            Some(d) if *d != r.digest() => bail!("layer blob {d} has digest {}", r.digest()),
            _ => Ok(()),
        }
    }
}

pub fn fetch(cache: &Path, src: &str, limits: &Limits) -> Result<Image> {
    let path = Path::new(src);
    let img = if path.is_dir() {
        let path = std::fs::canonicalize(path)?;
        let in_dir = |p: &str| {
            let f = std::fs::canonicalize(path.join(lexical(Path::new(p)))).map_err(|e| format!("{path:?} has no {p:?}: {e}"))?;
            if !f.starts_with(&path) {
                bail!("{p:?} escapes image directory {path:?}");
            }
            match f.is_file() {
                true => Ok(Blob::File(f)),
                false => bail!("{path:?} has no {p:?}"),
            }
        };
        from_files(&in_dir, limits)?
    } else if path.is_file() {
        from_files(&tar_index(path, limits)?, limits)?
    } else {
        let r = Reference::parse(src).map_err(|e| format!("{e} (and no such file or directory)"))?;
        pull(cache, Registry::new(r), limits)?
    };
    if sha256_hex(&img.config) != img.config_digest {
        bail!("image config does not match its digest {}", img.config_digest);
    }
    Ok(img)
}

fn image(digest: String, config_digest: String, config: Vec<u8>, layers: Vec<Layer>) -> Result<Image> {
    let v: Value = serde_json::from_slice(&config)?;
    let diff_ids = Vec::<String>::deserialize(&v["rootfs"]["diff_ids"]).map_err(|e| format!("image config rootfs.diff_ids: {e}"))?;
    if diff_ids.len() != layers.len() {
        bail!("image config lists {} layers, the manifest {}", diff_ids.len(), layers.len());
    }
    for d in &diff_ids {
        blob_path(Path::new(""), d)?; // a well-formed sha256 digest
    }
    Ok(Image { digest, config_digest, config, layers, diff_ids })
}

/// A cached document: a regular file of exactly `size` bytes (at most `MAX_DOCUMENT`) matching `digest`.
pub(super) fn read_verified(path: &Path, size: u64, digest: &str) -> Result<Vec<u8>> {
    let data = Blob::File(path.to_path_buf()).read_document()?;
    if data.len() as u64 != size || sha256_hex(&data) != digest {
        bail!("cached blob {} does not match {digest} ({size} bytes)", path.display());
    }
    Ok(data)
}

fn check_download(total: u64, limits: &Limits) -> Result<()> {
    if total > limits.download {
        bail!("image layers total {} MiB, over the download limit (--max-download-mib)", total >> 20);
    }
    Ok(())
}

fn descriptors(manifest: &Value, limits: &Limits) -> Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    for l in manifest["layers"].as_array().ok_or("manifest has no layers")? {
        let d = l["digest"].as_str().ok_or("layer without digest")?.to_string();
        blob_path(Path::new(""), &d)?;
        out.push((d, l["size"].as_u64().ok_or("layer without size")?));
    }
    check_download(out.iter().fold(0u64, |t, (_, s)| t.saturating_add(*s)), limits)?;
    Ok(out)
}

fn resolve_index(mut v: Value, mut digest: String, mut get: impl FnMut(&str) -> Result<Value>) -> Result<(Value, String)> {
    let mut depth = 0;
    while let Some(manifests) = v["manifests"].as_array() {
        depth += 1;
        if depth > 4 {
            bail!("nested image indexes");
        }
        fn plat(m: &Value) -> (Option<&str>, Option<&str>) {
            (m["platform"]["os"].as_str(), m["platform"]["architecture"].as_str())
        }
        let found = manifests
            .iter()
            .find(|m| plat(m) == (Some("linux"), Some("amd64")))
            // An OCI layout's index.json often lists one manifest with no platform.
            .or_else(|| manifests.iter().find(|m| m["platform"].is_null()));
        let Some(m) = found else {
            let have: Vec<String> = manifests.iter().map(|m| format!("{:?}", plat(m))).collect();
            bail!("no linux/amd64 image in the index (has {})", have.join(", "))
        };
        digest = m["digest"].as_str().ok_or("index entry without digest")?.to_string();
        v = get(&digest)?;
    }
    Ok((v, digest))
}

fn pull(cache: &Path, mut reg: Registry, limits: &Limits) -> Result<Image> {
    let blobs = cache.join("blobs");
    super::registry::sweep_parts(&blobs.join("sha256"));
    let (manifest, digest) = reg.manifest(&reg.r.reference.clone())?;
    let (manifest, digest) = resolve_index(manifest, digest, |d| Ok(reg.manifest(d)?.0))?;
    eprintln!("image: {} -> {digest}", reg.r);
    let config_digest = manifest["config"]["digest"].as_str().ok_or("manifest has no config")?.to_string();
    let config_size = manifest["config"]["size"].as_u64().ok_or("config without size")?;
    if config_size > MAX_DOCUMENT {
        bail!("image config of {config_size} bytes is over the {MAX_DOCUMENT} byte limit");
    }
    let config = read_verified(&reg.blob(&config_digest, config_size, &blobs)?, config_size, &config_digest)?;
    let descs = descriptors(&manifest, limits)?;
    for (i, (d, size)) in descs.iter().enumerate() {
        let cached = if blob_path(&blobs, d)?.exists() { " (cached)" } else { "" };
        eprintln!("image: layer {}/{} {d} {:.1} MiB{cached}", i + 1, descs.len(), *size as f64 / 1048576.0);
    }
    download_layers(&descs, |d, size| {
        reg.clone().layer_blob(d, size, &blobs)?;
        Ok(())
    })?;
    let layers = descs.into_iter().map(|(d, size)| Layer {
        src: Blob::Cached { blobs: blobs.clone(), registry: Box::new(reg.clone()), digest: d.clone(), size },
        digest: Some(d),
        size: Some(size),
    }).collect();
    image(digest, config_digest, config, layers)
}

fn download_layers(descs: &[(String, u64)], download: impl Fn(&str, u64) -> Result<()> + Sync) -> Result<()> {
    // One download per digest: concurrent writes share a PID-based .part name.
    let mut unique = HashMap::new();
    for (d, size) in descs {
        if unique.insert(d, *size).is_some_and(|previous| previous != *size) {
            bail!("layer {d} has conflicting sizes");
        }
    }
    let workers = unique.len().min(4);
    let pending = std::sync::Mutex::new(unique.into_iter());
    std::thread::scope(|scope| -> Result<()> {
        let jobs: Vec<_> = (0..workers).map(|_| {
            scope.spawn(|| -> Result<()> {
                loop {
                    let next = pending.lock().unwrap().next();
                    let Some((d, size)) = next else { return Ok(()) };
                    download(d, size)?;
                }
            })
        }).collect();
        for job in jobs {
            job.join().map_err(|_| "layer download panicked")??;
        }
        Ok(())
    })
}

enum Member {
    Data { offset: u64, len: u64 },
    Link(PathBuf),
}

fn tar_index(file: &Path, limits: &Limits) -> Result<impl Fn(&str) -> Result<Blob>> {
    let mut f = File::open(file)?;
    let mut magic = [0u8; 2];
    f.read_exact(&mut magic)?;
    if magic == [0x1f, 0x8b] {
        bail!("{file:?} is compressed; decompress it first (gunzip)");
    }
    f.rewind()?;
    let mut members = HashMap::new();
    each_entry(f, &mut 0, limits.entries, |e, m| {
        let kind = e.header().entry_type();
        let path = lexical(&m.path);
        let member = if kind.is_symlink() || kind.is_hard_link() {
            let target = m.link.ok_or("link without target")?;
            // Symlinks are relative to their directory; hard links to the archive root.
            Member::Link(lexical(&if kind.is_symlink() { path.parent().unwrap_or(&path).join(target) } else { target }))
        } else if kind.is_file() {
            Member::Data { offset: e.raw_file_position(), len: e.size() }
        } else {
            return Ok(());
        };
        members.insert(path, member);
        Ok(())
    })
    .map_err(|e| format!("{file:?}: {e}"))?;
    let file = file.to_path_buf();
    Ok(move |path: &str| {
        let mut p = lexical(Path::new(path));
        for _ in 0..16 {
            match members.get(&p) {
                Some(Member::Data { offset, len }) => return Ok(Blob::Slice { file: file.clone(), offset: *offset, len: *len }),
                Some(Member::Link(t)) => p = t.clone(),
                None => bail!("{file:?} has no {path:?}"),
            }
        }
        bail!("{file:?}: too many links at {path:?}")
    })
}

fn from_files(blob: &dyn Fn(&str) -> Result<Blob>, limits: &Limits) -> Result<Image> {
    let read = |path: &str| blob(path)?.read_document();
    let by_digest = |d: &str| -> Result<String> { Ok(blob_path(Path::new("blobs"), d)?.to_string_lossy().into_owned()) };
    let read_blob = |d: &str| -> Result<Vec<u8>> {
        let data = read(&by_digest(d)?)?;
        if sha256_hex(&data) != d {
            bail!("blob {d} does not match its digest");
        }
        Ok(data)
    };
    if blob("index.json").is_ok() {
        // OCI image layout (also what `docker save` writes since Docker 25).
        let index = serde_json::from_slice(&read("index.json")?)?;
        let (v, digest) = resolve_index(index, String::new(), |d| Ok(serde_json::from_slice(&read_blob(d)?)?))?;
        let config_digest = v["config"]["digest"].as_str().ok_or("manifest has no config")?.to_string();
        let config = read_blob(&config_digest)?;
        let layers = descriptors(&v, limits)?
            .into_iter()
            .map(|(d, size)| Ok(Layer { src: blob(&by_digest(&d)?)?, digest: Some(d), size: Some(size) }))
            .collect::<Result<_>>()?;
        return image(digest, config_digest, config, layers);
    }
    if blob("manifest.json").is_err() {
        bail!("not an OCI layout or docker save archive: no index.json or manifest.json");
    }
    // Legacy `docker save`: the config is identified by its own hash, layers by its diff_ids.
    let m: Value = serde_json::from_slice(&read("manifest.json")?)?;
    let m = m.get(0).ok_or("empty manifest.json")?;
    let config = read(m["Config"].as_str().ok_or("manifest.json has no Config")?)?;
    let (mut layers, mut total) = (Vec::new(), 0u64);
    for l in m["Layers"].as_array().ok_or("manifest.json has no Layers")? {
        let src = blob(l.as_str().ok_or("bad layer path")?)?;
        total = total.saturating_add(src.open()?.1);
        layers.push(Layer { src, digest: None, size: None });
    }
    check_download(total, limits)?;
    let digest = sha256_hex(&config);
    image(digest.clone(), digest, config, layers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, Mutex};

    #[test]
    fn layer_downloads_are_parallel_bounded_and_deduplicated() {
        let mut descs: Vec<_> = (0..8).map(|i| (format!("layer{i}"), i)).collect();
        descs.push(descs[0].clone());
        let barrier = Barrier::new(4);
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let downloaded = Mutex::new(HashMap::new());
        download_layers(&descs, |d, size| {
            let n = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(n, Ordering::SeqCst);
            barrier.wait();
            assert!(downloaded.lock().unwrap().insert(d.to_string(), size).is_none());
            active.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }).unwrap();
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert_eq!(*downloaded.lock().unwrap(), descs.into_iter().collect());
    }

    #[test]
    fn layer_download_failures_and_conflicting_sizes_are_reported() {
        let descs = vec![("a".to_string(), 1), ("b".to_string(), 2)];
        let completed = AtomicUsize::new(0);
        let err = download_layers(&descs, |d, _| {
            completed.fetch_add(1, Ordering::SeqCst);
            if d == "a" { bail!("failed download"); }
            Ok(())
        }).unwrap_err();
        assert!(err.to_string().contains("failed download"));
        assert_eq!(completed.load(Ordering::SeqCst), 2);
        let err = download_layers(&[("a".to_string(), 1), ("a".to_string(), 2)], |_, _| panic!("invalid descriptors must not download")).unwrap_err();
        assert!(err.to_string().contains("conflicting sizes"));
    }
}
