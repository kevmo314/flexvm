//! A minimal OCI distribution (registry v2) client.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::reference::Reference;
use super::unpack::{Hashed, MAX_DOCUMENT};
use crate::bail;
use crate::util::Result;

pub const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

#[derive(Clone)]
pub struct Registry {
    agent: ureq::Agent,
    pub r: Reference,
    /// base64 `user:password` from the Docker config.
    basic: Option<String>,
    auth: Option<String>,
}

impl Registry {
    pub fn new(r: Reference) -> Registry {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(30))
            .timeout_read(Duration::from_secs(120))
            .user_agent(concat!("flexvm/", env!("CARGO_PKG_VERSION")))
            // Redirects are followed by hand, never carrying credentials.
            .redirects(0)
            .build();
        // Credentials only ever travel over TLS.
        let basic = if r.base_url().starts_with("https://") { docker_credentials(&r.registry) } else { None };
        Registry { agent, r, basic, auth: None }
    }

    /// Credentials go only over HTTPS to the registry itself or its well-known token service.
    fn trusted(&self, url: &str) -> bool {
        let Some(rest) = url.strip_prefix("https://") else { return false };
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        host == self.r.registry || (self.r.registry == "registry-1.docker.io" && host == "auth.docker.io")
    }

    /// Authenticates on a 401 and retries once; redirects (blob storage) are followed without credentials.
    fn get(&mut self, path: &str, accept: &str) -> Result<ureq::Response> {
        let base = format!("{}/{path}", self.r.base_url());
        let (mut url, mut redirects, mut authenticated) = (base.clone(), 0, false);
        loop {
            let mut req = self.agent.get(&url);
            if redirects == 0 {
                req = req.set("Accept", accept);
                if let Some(a) = &self.auth {
                    req = req.set("Authorization", a);
                }
            }
            match req.call() {
                Ok(resp) if (300..400).contains(&resp.status()) => {
                    let loc = resp.header("location").ok_or("redirect without a location")?;
                    url = if loc.starts_with("https://") || loc.starts_with("http://") {
                        loc.to_string()
                    } else if loc.starts_with('/') {
                        format!("{}{loc}", url.splitn(4, '/').take(3).collect::<Vec<_>>().join("/"))
                    } else {
                        bail!("unsupported redirect to {loc:?}");
                    };
                    if base.starts_with("https://") && !url.starts_with("https://") {
                        bail!("refusing a redirect from HTTPS to {url}");
                    }
                    redirects += 1;
                    if redirects > 5 {
                        bail!("too many redirects from {base}");
                    }
                }
                Ok(resp) => return Ok(resp),
                Err(ureq::Error::Status(401, resp)) if !authenticated && redirects == 0 => {
                    let challenge = resp.header("www-authenticate").unwrap_or("").to_string();
                    self.authenticate(&challenge)?;
                    authenticated = true;
                }
                Err(ureq::Error::Status(401, _)) if redirects == 0 => {
                    bail!("GET {url}: unauthorized{}", if self.basic.is_none() { " (no credentials in docker config)" } else { "" })
                }
                Err(ureq::Error::Status(code, resp)) => {
                    let mut body = Vec::new();
                    let _ = resp.into_reader().take(300).read_to_end(&mut body);
                    bail!("GET {url}: HTTP {code}: {}", String::from_utf8_lossy(&body).trim())
                }
                Err(e) => bail!("GET {url}: {e}"),
            }
        }
    }

    fn authenticate(&mut self, challenge: &str) -> Result<()> {
        let (scheme, params) = challenge.split_once(' ').unwrap_or((challenge, ""));
        if scheme.eq_ignore_ascii_case("basic") {
            let Some(b) = &self.basic else { bail!("{} wants basic credentials; none found", self.r.registry) };
            self.auth = Some(format!("Basic {b}"));
            return Ok(());
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            bail!("{}: unsupported auth challenge {challenge:?}", self.r.registry);
        }
        let param = |name: &str| {
            params.split(',').find_map(|kv| {
                let (k, v) = kv.trim().split_once('=')?;
                (k.trim() == name).then(|| v.trim().trim_matches('"').to_string())
            })
        };
        let realm = param("realm").ok_or("auth challenge has no realm")?;
        let mut req = self.agent.get(&realm);
        if let Some(service) = param("service") {
            req = req.query("service", &service);
        }
        req = req.query("scope", &param("scope").unwrap_or(format!("repository:{}:pull", self.r.repository)));
        // Anywhere else gets an anonymous token request.
        match &self.basic {
            Some(b) if self.trusted(&realm) => req = req.set("Authorization", &format!("Basic {b}")),
            Some(_) => eprintln!("image: not sending credentials to untrusted token realm {realm}"),
            None => {}
        }
        let body: Value = match req.call() {
            Ok(r) if r.status() == 200 => serde_json::from_reader(r.into_reader().take(1 << 20))?,
            Ok(r) => bail!("token from {realm}: HTTP {}", r.status()),
            Err(e) => bail!("token from {realm}: {e}"),
        };
        let token = body["token"].as_str().or(body["access_token"].as_str()).ok_or("token response has no token")?;
        self.auth = Some(format!("Bearer {token}"));
        Ok(())
    }

    pub fn manifest(&mut self, reference: &str) -> Result<(Value, String)> {
        let resp = self.get(&format!("manifests/{reference}"), MANIFEST_TYPES)?;
        let mut body = Vec::new();
        resp.into_reader().take(MAX_DOCUMENT + 1).read_to_end(&mut body)?;
        if body.len() as u64 > MAX_DOCUMENT {
            bail!("manifest {reference} is over the {MAX_DOCUMENT} byte limit");
        }
        let digest = sha256_hex(&body);
        if reference.starts_with("sha256:") && reference != digest {
            bail!("manifest {reference} has digest {digest}");
        }
        Ok((serde_json::from_slice(&body)?, digest))
    }

    /// Defers checking cached layers until unpacking actually opens them.
    pub fn layer_blob(&mut self, digest: &str, size: u64, blobs: &Path) -> Result<PathBuf> {
        let path = blob_path(blobs, digest)?;
        if path.exists() {
            sync_dir(path.parent().unwrap())?;
            return Ok(path);
        }
        self.blob(digest, size, blobs)
    }

    /// Checks cached blobs before reuse; a corrupt one gets one fresh download, renamed over it so that
    /// concurrent pulls never see the path missing.
    pub fn blob(&mut self, digest: &str, size: u64, blobs: &Path) -> Result<PathBuf> {
        cached_blob(digest, size, blobs, || Ok(self.get(&format!("blobs/{digest}"), "*/*")?.into_reader()))
    }
}

fn cached_blob<R: Read>(digest: &str, size: u64, blobs: &Path, download: impl FnOnce() -> Result<R>) -> Result<PathBuf> {
    let path = blob_path(blobs, digest)?;
    let dir = path.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir)?;
    if path.exists() {
        let (reader, len) = super::source::Blob::File(path.clone()).open()?;
        let mut cached = Hashed::new(reader.take(size.saturating_add(1)));
        std::io::copy(&mut cached, &mut std::io::sink())?;
        if len == size && cached.n == size && cached.digest() == digest {
            sync_dir(&dir)?;
            return Ok(path);
        }
        eprintln!("image: cached blob {digest} is corrupt; downloading it again");
    }
    let mut r = Hashed::new(download()?.take(size.saturating_add(1)));
    super::replace(&path, |f| {
        std::io::copy(&mut r, f)?;
        if r.n != size {
            bail!("blob {digest} does not have its descriptor's {size} bytes");
        }
        if r.digest() != digest {
            bail!("blob {digest} downloaded with digest {}", r.digest());
        }
        Ok(())
    })?;
    sync_dir(&dir)?;
    Ok(path)
}

pub(super) fn sweep_parts(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some((hex, pid)) = name.to_str().and_then(|n| n.rsplit_once(".part")) else { continue };
        let pid = pid.parse::<libc::pid_t>().unwrap_or(0);
        let dead = pid > 0 && unsafe { libc::kill(pid, 0) } != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        if dead && hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

pub fn sync_dir(dir: &Path) -> Result<()> {
    Ok(std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|e| format!("fsync of directory {}: {e}", dir.display()))?)
}

pub fn sha256_hex(data: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(data))
}

/// `blobs/sha256/<hex>`, refusing anything that is not a sha256 digest.
pub fn blob_path(blobs: &Path, digest: &str) -> Result<PathBuf> {
    match digest.strip_prefix("sha256:") {
        Some(hex) if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(blobs.join("sha256").join(hex)),
        _ => bail!("unsupported digest {digest:?}"),
    }
}

/// From `$DOCKER_CONFIG`, `~/.docker` or the sudo user's; credential helpers are not supported.
fn docker_credentials(registry: &str) -> Option<String> {
    let sudo_home = std::env::var("SUDO_USER").ok().and_then(|user| {
        std::fs::read_to_string("/etc/passwd").ok()?.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 5 && f[0] == user).then(|| PathBuf::from(f[5]))
        })
    });
    let homes = [std::env::var_os("DOCKER_CONFIG").map(PathBuf::from), std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".docker")), sudo_home.map(|h| h.join(".docker"))];
    let hub = ["index.docker.io", "docker.io", "registry-1.docker.io"];
    let wanted: &[&str] = if registry == hub[2] { &hub } else { &[registry] };
    for dir in homes.into_iter().flatten() {
        let Some(cfg) = std::fs::read(dir.join("config.json")).ok().and_then(|t| serde_json::from_slice::<Value>(&t).ok()) else { continue };
        for (key, entry) in cfg["auths"].as_object().into_iter().flatten() {
            let host = key.trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or("");
            if !wanted.contains(&host) {
                continue;
            }
            if let Some(auth) = entry["auth"].as_str().filter(|a| !a.is_empty()) {
                return Some(auth.to_string());
            }
            if let (Some(u), Some(p)) = (entry["username"].as_str(), entry["password"].as_str()) {
                return Some(base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_layers_are_not_verified_until_needed() {
        let dir = super::super::unpack::tests::tmpdir("blob-lazy");
        let digest = sha256_hex(b"good");
        let path = blob_path(&dir, &digest).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"evil").unwrap();
        let mut reg = Registry::new(Reference::parse("localhost:1/test").unwrap());
        // No server: returning a corrupt cached layer must not attempt a download.
        assert_eq!(reg.layer_blob(&digest, 4, &dir).unwrap(), path);
        assert_eq!(std::fs::read(&path).unwrap(), b"evil");
        assert_eq!(cached_blob(&digest, 4, &dir, || Ok(&b"good"[..])).unwrap(), path);
        assert_eq!(std::fs::read(&path).unwrap(), b"good");
    }

    #[test]
    fn corrupt_cached_blobs_are_downloaded_once() {
        let digest = sha256_hex(b"good");
        let cases: &[(&[u8], &[u8])] = &[(b"evil", b"good"), (b"x", b"good"), (b"good-extra", b"good"), (b"evil", b"evil"), (b"evil", b"x")];
        for (i, &(cached, downloaded)) in cases.iter().enumerate() {
            let dir = super::super::unpack::tests::tmpdir(&format!("blob-retry{i}"));
            let path = blob_path(&dir, &digest).unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, cached).unwrap();
            let mut downloads = 0;
            let result = cached_blob(&digest, 4, &dir, || {
                downloads += 1;
                Ok(downloaded)
            });
            assert_eq!(downloads, 1);
            if downloaded == b"good" {
                assert_eq!(result.unwrap(), path);
                assert_eq!(std::fs::read(&path).unwrap(), b"good");
                assert_eq!(cached_blob::<&[u8]>(&digest, 4, &dir, || panic!("must reuse the repaired blob")).unwrap(), path);
            } else {
                let err = result.unwrap_err().to_string();
                assert!(err.contains(if downloaded.len() == 4 { "downloaded with digest" } else { "descriptor's 4 bytes" }), "{err}");
                assert_eq!(std::fs::read(&path).unwrap(), cached, "a failed download keeps what was there");
            }
            assert!(!path.with_extension(format!("part{}", std::process::id())).exists());
        }
    }

    #[test]
    fn sweep_removes_only_dead_downloads() {
        let dir = super::super::unpack::tests::tmpdir("parts");
        let hex = "a".repeat(64);
        let stale = dir.join(format!("{hex}.part2147483647"));
        let live = dir.join(format!("{hex}.part{}", std::process::id()));
        let other = dir.join("unrelated.part2147483647");
        let blob = dir.join(&hex);
        for path in [&stale, &live, &other, &blob] {
            std::fs::write(path, "data").unwrap();
        }
        sweep_parts(&dir);
        assert!(!stale.exists());
        assert!(live.exists() && other.exists() && blob.exists());
    }

    #[test]
    fn credentials_only_go_to_trusted_realms() {
        let hub = Registry::new(Reference::parse("nginx").unwrap());
        assert!(hub.trusted("https://auth.docker.io/token"));
        assert!(hub.trusted("https://registry-1.docker.io/token?x"));
        assert!(!hub.trusted("http://auth.docker.io/token"));
        assert!(!hub.trusted("https://auth.docker.io.evil.com/token"));
        assert!(!hub.trusted("https://evil.com/?https://auth.docker.io"));
        let ghcr = Registry::new(Reference::parse("ghcr.io/o/a").unwrap());
        assert!(ghcr.trusted("https://ghcr.io/token"));
        assert!(!ghcr.trusted("https://auth.docker.io/token"));
        assert!(Registry::new(Reference::parse("localhost:5000/a").unwrap()).basic.is_none());
    }
}
