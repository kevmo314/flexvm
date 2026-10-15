//! A minimal OCI distribution (registry v2) client.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::reference::Reference;
use super::unpack::{Hashed, MAX_DOCUMENT};
use crate::bail;
use crate::util::{sync_dir, Result};

pub const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

/// Every transfer, from its first request through auth and redirects to its last body byte, ends by a
/// deadline: this long, plus the transfer's size at `MIN_RATE`. A slow registry otherwise holds a pull,
/// and the rootfs cache's per-key lock, indefinitely.
const TRANSFER_BASE: Duration = Duration::from_secs(300);
const MIN_RATE: u64 = 128 << 10;

fn deadline(size: u64) -> Instant {
    Instant::now() + TRANSFER_BASE + Duration::from_secs(size / MIN_RATE)
}

/// An agent for one transfer: DNS and TLS obey the transfer's deadline. TLS runs over a socket that enforces it,
/// handshake included (ureq's own deadline starts only once the handshake is done), and its
/// connections are never pooled into another transfer.
fn agent(deadline: Instant) -> ureq::Agent {
    static TLS: std::sync::OnceLock<Arc<ureq::rustls::ClientConfig>> = std::sync::OnceLock::new();
    // As ureq's default.
    let tls = TLS.get_or_init(|| {
        let roots = ureq::rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let config = ureq::rustls::ClientConfig::builder_with_provider(ureq::rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&ureq::rustls::version::TLS12, &ureq::rustls::version::TLS13])
            .expect("ring supports TLS 1.2 and 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(config)
    });
    ureq::AgentBuilder::new()
        .resolver(move |addr: &str| crate::util::resolve(addr, deadline))
        .timeout_connect(Duration::from_secs(30))
        .timeout_read(IDLE)
        .timeout_write(IDLE)
        .tls_connector(Arc::new(DeadlineTls { tls: tls.clone(), deadline }))
        .user_agent(concat!("flexvm/", env!("CARGO_PKG_VERSION")))
        // Redirects are followed by hand, never carrying credentials.
        .redirects(0)
        .build()
}

/// Longest wait for any one read or write.
const IDLE: Duration = Duration::from_secs(120);

struct DeadlineTls {
    tls: Arc<ureq::rustls::ClientConfig>,
    deadline: Instant,
}

impl ureq::TlsConnector for DeadlineTls {
    fn connect(&self, dns_name: &str, io: Box<dyn ureq::ReadWrite>) -> std::result::Result<Box<dyn ureq::ReadWrite>, ureq::Error> {
        self.tls.connect(dns_name, Box::new(Deadlined { io, deadline: self.deadline }))
    }
}

/// Every read and write waits at most until the deadline, and none starts after it.
#[derive(Debug)]
struct Deadlined {
    io: Box<dyn ureq::ReadWrite>,
    deadline: Instant,
}

impl Deadlined {
    fn io<T>(&mut self, op: impl FnOnce(&mut Box<dyn ureq::ReadWrite>) -> std::io::Result<T>) -> std::io::Result<T> {
        let timed_out = || std::io::Error::new(std::io::ErrorKind::TimedOut, "transfer deadline passed");
        let left = self.deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or_else(timed_out)?;
        let socket = self.io.socket().ok_or_else(|| std::io::Error::other("TLS without a TCP socket"))?;
        socket.set_read_timeout(Some(left.min(IDLE)))?;
        socket.set_write_timeout(Some(left.min(IDLE)))?;
        op(&mut self.io).map_err(|e| if e.kind() == std::io::ErrorKind::WouldBlock { timed_out() } else { e })
    }
}

impl Read for Deadlined {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.io(|io| io.read(buf))
    }
}

impl std::io::Write for Deadlined {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.io(|io| io.write(buf))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io(|io| io.flush())
    }
}

impl ureq::ReadWrite for Deadlined {
    fn socket(&self) -> Option<&std::net::TcpStream> {
        self.io.socket()
    }
}

/// Shared by all of an image's layers (`Arc`), its token with them.
pub struct Registry {
    pub r: Reference,
    /// base64 `user:password` from the Docker config.
    basic: Option<String>,
    auth: Mutex<Option<Arc<str>>>,
}

impl Registry {
    pub fn new(r: Reference) -> Registry {
        // Credentials only ever travel over TLS.
        let basic = if r.base_url().starts_with("https://") { docker_credentials(&r.registry) } else { None };
        Registry { r, basic, auth: Mutex::new(None) }
    }

    /// Credentials go only over HTTPS to the registry itself or its well-known token service.
    fn trusted(&self, url: &str) -> bool {
        let Some(rest) = url.strip_prefix("https://") else { return false };
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        host == self.r.registry || (self.r.registry == "registry-1.docker.io" && host == "auth.docker.io")
    }

    /// The time left before `deadline`, for the next request; ureq holds connect, writes and the body to it.
    fn left(deadline: Instant, what: &str) -> Result<Duration> {
        match deadline.checked_duration_since(Instant::now()) {
            Some(left) if !left.is_zero() => Ok(left),
            _ => bail!("{what}: transfer deadline passed"),
        }
    }

    /// Authenticates on a 401 and retries once; redirects (blob storage) are followed without credentials.
    fn get(&self, path: &str, accept: &str, deadline: Instant) -> Result<ureq::Response> {
        let base = format!("{}/{path}", self.r.base_url());
        let (mut url, mut redirects, mut authenticated) = (base.clone(), 0, false);
        let agent = agent(deadline);
        loop {
            let mut req = agent.get(&url).timeout(Self::left(deadline, &format!("GET {url}"))?);
            if redirects == 0 {
                req = req.set("Accept", accept);
                if let Some(a) = self.auth.lock().unwrap().clone() {
                    req = req.set("Authorization", &a);
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
                    self.authenticate(&agent, &challenge, deadline)?;
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

    fn authenticate(&self, agent: &ureq::Agent, challenge: &str, deadline: Instant) -> Result<()> {
        let (scheme, params) = challenge.split_once(' ').unwrap_or((challenge, ""));
        if scheme.eq_ignore_ascii_case("basic") {
            let Some(b) = &self.basic else { bail!("{} wants basic credentials; none found", self.r.registry) };
            *self.auth.lock().unwrap() = Some(format!("Basic {b}").into());
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
        let mut req = agent.get(&realm).timeout(Self::left(deadline, &format!("token from {realm}"))?);
        if let Some(service) = param("service") {
            req = req.query("service", &service);
        }
        req = req.query("scope", &param("scope").unwrap_or(format!("repository:{}:pull", self.r.repository)));
        // Anywhere else gets an anonymous token request.
        match &self.basic {
            Some(b) if self.trusted(&realm) => req = req.set("Authorization", &format!("Basic {b}")),
            Some(_) => crate::log!("image: not sending credentials to untrusted token realm {realm}"),
            None => {}
        }
        let body: Value = match req.call() {
            Ok(r) if r.status() == 200 => serde_json::from_reader(r.into_reader().take(1 << 20))?,
            Ok(r) => bail!("token from {realm}: HTTP {}", r.status()),
            Err(e) => bail!("token from {realm}: {e}"),
        };
        let token = body["token"].as_str().or(body["access_token"].as_str()).ok_or("token response has no token")?;
        *self.auth.lock().unwrap() = Some(format!("Bearer {token}").into());
        Ok(())
    }

    pub fn manifest(&self, reference: &str) -> Result<(Value, String)> {
        let resp = self.get(&format!("manifests/{reference}"), MANIFEST_TYPES, deadline(MAX_DOCUMENT))?;
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

    /// Checks cached blobs before reuse; a corrupt one gets one fresh download, renamed over it so that
    /// concurrent pulls never see the path missing.
    pub fn blob(&self, digest: &str, size: u64, blobs: &Path) -> Result<PathBuf> {
        cached_blob(digest, size, blobs, || Ok(self.get(&format!("blobs/{digest}"), "*/*", deadline(size))?.into_reader()))
    }
}

fn cached_blob<R: Read>(digest: &str, size: u64, blobs: &Path, download: impl FnOnce() -> Result<R>) -> Result<PathBuf> {
    let path = blob_path(blobs, digest)?;
    let dir = path.parent().unwrap().to_path_buf();
    // `pull` synced the directory chain; each blob syncs only its own entry.
    if path.exists() {
        let (reader, len) = super::source::Blob::File(path.clone()).open()?;
        let mut cached = Hashed::new(reader.take(size.saturating_add(1)));
        std::io::copy(&mut cached, &mut std::io::sink())?;
        if len == size && cached.n == size && cached.digest() == digest {
            sync_dir(&dir)?;
            return Ok(path);
        }
        crate::log!("image: cached blob {digest} is corrupt; downloading it again");
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
    let Ok(dir_lock) = std::fs::File::open(dir) else { return };
    let Ok(_lock) = crate::host::Flock::new(dir_lock, libc::LOCK_EX | libc::LOCK_NB) else { return };
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some((hex, id)) = name.to_str().and_then(|n| n.rsplit_once(".part")) else { continue };
        if crate::util::is_nonce(id) && hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            let Ok(f) = std::fs::File::open(entry.path()) else { continue };
            // Let go explicitly, not by close: a child another thread forks shares the descriptor.
            if let Ok(_held) = crate::host::Flock::new(f, libc::LOCK_EX | libc::LOCK_NB) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
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

/// From `$DOCKER_CONFIG`, `~/.docker` or the sudo user's; credential helpers are not supported.
fn docker_credentials(registry: &str) -> Option<String> {
    let sudo_home = std::env::var("SUDO_USER").ok().and_then(|user| {
        std::fs::read_to_string("/etc/passwd").ok()?.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 5 && f[0] == user).then(|| PathBuf::from(f[5]))
        })
    });
    let homes = [
        std::env::var_os("DOCKER_CONFIG").map(PathBuf::from),
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".docker")),
        sudo_home.map(|h| h.join(".docker")),
    ];
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
pub(super) mod tests {
    use super::*;

    #[test]
    fn agent_dns_obeys_the_transfer_deadline() {
        let err = agent(Instant::now()).get("http://unused.example:80/").call().unwrap_err();
        let ureq::Error::Transport(err) = err else { panic!("expected DNS failure") };
        assert_eq!(err.kind(), ureq::ErrorKind::Dns);
        let cause = std::error::Error::source(&err).unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(cause.kind(), std::io::ErrorKind::TimedOut);
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
            let parts = std::fs::read_dir(path.parent().unwrap()).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().contains(".part"));
            assert_eq!(parts.count(), 0);
        }
    }

    #[test]
    fn sweep_removes_only_unlocked_downloads() {
        let dir = super::super::unpack::tests::tmpdir("parts");
        let hex = "a".repeat(64);
        let stale = dir.join(format!("{hex}.part2147483647"));
        let live = dir.join(format!("{hex}.part{}", crate::util::nonce().unwrap()));
        let dead = dir.join(format!("{hex}.part{}", crate::util::nonce().unwrap()));
        let other = dir.join("unrelated.part2147483647");
        let blob = dir.join(&hex);
        for path in [&stale, &live, &dead, &other, &blob] {
            std::fs::write(path, "data").unwrap();
        }
        let lock = std::fs::File::open(&live).unwrap();
        crate::host::flock(&lock, libc::LOCK_EX).unwrap();
        sweep_parts(&dir);
        assert!(!dead.exists());
        // Named by pid by older builds: no lock says whose, so never removed.
        assert!(stale.exists() && live.exists() && other.exists() && blob.exists());
        // Unlocked, not only closed: a child another test forks meanwhile shares the lock until it execs.
        crate::host::flock(&lock, libc::LOCK_UN).unwrap();
        drop(lock);
        sweep_parts(&dir);
        assert!(!live.exists());
    }

    /// Serves each connection by its request path: `/v2/<image>/<path>` answers `respond(path)`, one byte at a
    /// time every `drip` once past its first `fast` bytes, until the client hangs up.
    pub(in super::super) fn drip_server(fast: usize, drip: Duration, respond: impl Fn(&str, &str) -> String + Send + Sync + 'static) -> String {
        use std::io::{BufRead, BufReader, Write};
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap().to_string();
        let respond = Arc::new(respond);
        let base = addr.clone();
        std::thread::spawn(move || {
            for mut socket in server.incoming().flatten() {
                let (respond, base) = (respond.clone(), base.clone());
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(socket.try_clone().unwrap());
                    let mut request = String::new();
                    reader.read_line(&mut request).unwrap();
                    while reader.read_line(&mut String::new()).is_ok_and(|n| n > 2) {}
                    let path = request.split(' ').nth(1).unwrap_or("").to_string();
                    let resp = respond(&base, &path).into_bytes();
                    let _ = socket.write_all(&resp[..fast.min(resp.len())]);
                    for b in resp.iter().skip(fast) {
                        std::thread::sleep(drip);
                        if socket.write_all(&[*b]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    #[test]
    fn slow_transfers_hit_the_overall_deadline() {
        let body = |b: &str| format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len());
        // Each byte arrives well within the 120 s read timeout; only the deadline ends them.
        type Respond = fn(&str, &str) -> String;
        let cases: [(&str, usize, Respond); 3] = [
            ("headers", 0, |_, _| format!("HTTP/1.1 200 OK\r\n{}Content-Length: 0\r\n\r\n", "X-Pad: y\r\n".repeat(100))),
            ("body", 64, |_, _| format!("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{}", "x".repeat(1000))),
            ("token", 64, |base, path| {
                if path.starts_with("/token") {
                    let t = format!("{{\"token\": \"{}\"}}", "t".repeat(1000));
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{t}", t.len())
                } else {
                    format!(
                        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"http://{base}/token\"\r\n\
                         Content-Length: 0\r\nConnection: close\r\n{}\r\n",
                        " ".repeat(64)
                    )
                }
            }),
        ];
        for (name, fast, respond) in cases {
            let addr = drip_server(fast, Duration::from_millis(20), respond);
            let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
            let start = Instant::now();
            let res = reg.get("blobs/x", "*/*", start + Duration::from_millis(700)).and_then(|r| {
                let mut data = Vec::new();
                r.into_reader().read_to_end(&mut data)?;
                Ok(data)
            });
            let err = res.expect_err(name).to_string();
            assert!(err.contains("timed out") || err.contains("deadline"), "{name}: {err}");
            assert!(start.elapsed() < Duration::from_secs(5), "{name}: took {:?}", start.elapsed());
        }
        // A fast transfer is unaffected.
        let addr = drip_server(usize::MAX, Duration::ZERO, move |_, _| body("blob"));
        let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
        let mut data = String::new();
        reg.get("blobs/x", "*/*", Instant::now() + Duration::from_secs(5)).unwrap().into_reader().read_to_string(&mut data).unwrap();
        assert_eq!(data, "blob");
    }

    #[test]
    fn a_dripped_tls_handshake_hits_the_deadline() {
        use std::io::Write;
        // Announces a 16 KiB handshake record, then sends it a byte at a time: each read succeeds
        // well within the idle timeout, and no certificate is ever needed.
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            for mut socket in server.incoming().flatten() {
                std::thread::spawn(move || {
                    let _ = socket.read(&mut [0; 4096]);
                    let _ = socket.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]);
                    while socket.write_all(&[0]).is_ok() {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                });
            }
        });
        let start = Instant::now();
        let deadline = start + Duration::from_millis(700);
        let err = agent(deadline).get(&format!("https://{addr}/v2/")).timeout(deadline - start).call().unwrap_err().to_string();
        assert!(err.contains("deadline") || err.contains("timed out"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(5), "took {:?}", start.elapsed());
    }

    #[test]
    fn the_deadline_grows_with_the_transfer() {
        let now = Instant::now();
        assert!(deadline(0) >= now + TRANSFER_BASE && deadline(0) < now + TRANSFER_BASE + Duration::from_secs(5));
        assert!(deadline(1 << 30) >= now + TRANSFER_BASE + Duration::from_secs(8192));
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
