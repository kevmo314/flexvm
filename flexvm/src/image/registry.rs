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
                    let body = String::from_utf8_lossy(&body);
                    bail!("GET {url}: HTTP {code}: {}", body.chars().take(300).collect::<String>().trim())
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

    /// Size and digest are checked before the fsynced rename; cached blobs are checked where used.
    pub fn blob(&mut self, digest: &str, size: u64, blobs: &Path) -> Result<PathBuf> {
        let path = blob_path(blobs, digest)?;
        let dir = path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        sweep_parts(&dir);
        if path.exists() {
            return Ok(path);
        }
        let mut r = Hashed::new(self.get(&format!("blobs/{digest}"), "*/*")?.into_reader().take(size + 1));
        super::publish(&path, |f| {
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
}

fn sweep_parts(dir: &Path) {
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
    fn sweep_removes_only_dead_downloads() {
        let dir = std::env::temp_dir().join(format!("flexvm-parts-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
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
        std::fs::remove_dir_all(dir).unwrap();
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
