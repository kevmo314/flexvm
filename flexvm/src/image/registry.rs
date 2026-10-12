//! A minimal OCI distribution (registry v2) client: anonymous or basic
//! credentials exchanged for a bearer token, manifests, and blobs streamed to
//! disk with their digests checked.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::reference::Reference;
use crate::bail;
use crate::util::Result;

pub const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

pub struct Registry {
    agent: ureq::Agent,
    pub r: Reference,
    /// base64 `user:password` from the Docker config, if any.
    basic: Option<String>,
    /// `Authorization` header value once authenticated.
    auth: Option<String>,
}

impl Registry {
    pub fn new(r: Reference) -> Registry {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(30))
            .timeout_read(Duration::from_secs(120))
            .user_agent(concat!("flexvm/", env!("CARGO_PKG_VERSION")))
            .build();
        let basic = docker_credentials(&r.registry);
        Registry { agent, r, basic, auth: None }
    }

    /// GETs `path` under the repository, authenticating on a 401 and retrying once.
    fn get(&mut self, path: &str, accept: &str) -> Result<ureq::Response> {
        let url = format!("{}/{path}", self.r.base_url());
        for attempt in 0..2 {
            let mut req = self.agent.get(&url).set("Accept", accept);
            if let Some(a) = &self.auth {
                req = req.set("Authorization", a);
            }
            match req.call() {
                Ok(resp) => return Ok(resp),
                Err(ureq::Error::Status(401, resp)) if attempt == 0 => {
                    let challenge = resp.header("www-authenticate").unwrap_or("").to_string();
                    self.authenticate(&challenge)?;
                }
                Err(ureq::Error::Status(code, resp)) => {
                    let body = resp.into_string().unwrap_or_default();
                    bail!("GET {url}: HTTP {code}: {}", body.chars().take(300).collect::<String>().trim())
                }
                Err(e) => bail!("GET {url}: {e}"),
            }
        }
        bail!("GET {url}: unauthorized{}", if self.basic.is_none() { " (no credentials in docker config)" } else { "" })
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
        if let Some(b) = &self.basic {
            req = req.set("Authorization", &format!("Basic {b}"));
        }
        let body: Value = match req.call() {
            Ok(r) => serde_json::from_reader(r.into_reader().take(1 << 20))?,
            Err(ureq::Error::Status(code, _)) => bail!("token from {realm}: HTTP {code}"),
            Err(e) => bail!("token from {realm}: {e}"),
        };
        let token = body["token"].as_str().or(body["access_token"].as_str()).ok_or("token response has no token")?;
        self.auth = Some(format!("Bearer {token}"));
        Ok(())
    }

    /// Fetches a manifest or index by tag or digest; returns it with its digest.
    pub fn manifest(&mut self, reference: &str) -> Result<(Value, String)> {
        let resp = self.get(&format!("manifests/{reference}"), MANIFEST_TYPES)?;
        let mut body = Vec::new();
        resp.into_reader().take(8 << 20).read_to_end(&mut body)?;
        let digest = sha256_hex(&body);
        if reference.starts_with("sha256:") && reference != digest {
            bail!("manifest {reference} has digest {digest}");
        }
        Ok((serde_json::from_slice(&body)?, digest))
    }

    /// Downloads blob `digest` into `blobs/sha256/<hex>` unless it is already
    /// there, streaming through a temporary file and checking the digest.
    pub fn blob(&mut self, digest: &str, blobs: &Path) -> Result<PathBuf> {
        let path = blob_path(blobs, digest)?;
        if path.exists() {
            return Ok(path);
        }
        std::fs::create_dir_all(path.parent().unwrap())?;
        let tmp = path.with_extension(format!("part{}", std::process::id()));
        let resp = self.get(&format!("blobs/{digest}"), "*/*")?;
        let res = (|| {
            let mut f = std::fs::File::create(&tmp)?;
            let mut r = resp.into_reader();
            let mut h = Sha256::new();
            let mut buf = vec![0u8; 256 << 10];
            loop {
                let n = r.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
                f.write_all(&buf[..n])?;
            }
            let got = format!("sha256:{:x}", h.finalize());
            if got != digest {
                bail!("blob {digest} downloaded with digest {got}");
            }
            std::fs::rename(&tmp, &path)?;
            Ok(path.clone())
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        res
    }
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

/// Basic credentials for `registry` from the Docker config (`$DOCKER_CONFIG`,
/// `~/.docker/config.json`, or the invoking user's under sudo). Credential
/// helpers are not supported.
fn docker_credentials(registry: &str) -> Option<String> {
    let mut homes: Vec<PathBuf> = std::env::var_os("DOCKER_CONFIG").map(PathBuf::from).into_iter().collect();
    if let Some(h) = std::env::var_os("HOME") {
        homes.push(PathBuf::from(h).join(".docker"));
    }
    if let Ok(user) = std::env::var("SUDO_USER") {
        if let Some(home) = user_home(&user) {
            homes.push(home.join(".docker"));
        }
    }
    let wanted: &[&str] = if registry == "registry-1.docker.io" {
        &["index.docker.io", "docker.io", "registry-1.docker.io"]
    } else {
        &[registry]
    };
    for dir in homes {
        let Ok(text) = std::fs::read(dir.join("config.json")) else { continue };
        let Ok(cfg) = serde_json::from_slice::<Value>(&text) else { continue };
        for (key, entry) in cfg["auths"].as_object().into_iter().flatten() {
            let host = key.trim_start_matches("https://").trim_start_matches("http://");
            let host = host.split('/').next().unwrap_or("");
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

fn user_home(user: &str) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 5 && f[0] == user).then(|| PathBuf::from(f[5]))
    })
}
