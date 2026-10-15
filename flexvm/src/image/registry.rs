//! A minimal OCI distribution (registry v2) client.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{Buffers, ConnectionDetails, Connector, NextTimeout, RustlsConnector, TcpConnector, Transport};
use ureq::Timeout;

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

/// An agent for one transfer: DNS, connect, the TLS handshake and every read and write obey the transfer's deadline
/// (ureq holds each handshake read, not the handshake, to its connect timeout), and its connections are never pooled
/// into another transfer. With `public_only`, it connects only to public addresses (as resolved, so DNS cannot
/// rebind it elsewhere).
fn agent(deadline: Instant, public_only: bool) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(30)))
        .user_agent(concat!("flexvm/", env!("CARGO_PKG_VERSION")))
        // Redirects are followed by hand, never carrying credentials; statuses are handled by hand.
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .proxy(None)
        .build();
    let connector = TcpConnector::default().chain(DeadlineConnector(deadline)).chain(RustlsConnector::default());
    ureq::Agent::with_parts(config, connector, DeadlineResolver { deadline, public_only })
}

/// Longest wait for any one read or write.
const IDLE: Duration = Duration::from_secs(120);

#[derive(Debug)]
struct DeadlineResolver {
    deadline: Instant,
    public_only: bool,
}

impl Resolver for DeadlineResolver {
    fn resolve(&self, uri: &ureq::http::Uri, _: &ureq::config::Config, _: NextTimeout) -> std::result::Result<ResolvedSocketAddrs, ureq::Error> {
        let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) else { return Err(ureq::Error::HostNotFound) };
        let addr = DefaultResolver::host_and_port(scheme, authority).ok_or(ureq::Error::HostNotFound)?;
        let mut addrs = self.empty();
        let found = crate::util::resolve(&addr, self.deadline)?;
        for a in reachable(&found, self.public_only).take(16) {
            addrs.push(a);
        }
        if addrs.is_empty() && !found.is_empty() {
            return Err(ureq::Error::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("{addr} is not on a public address"))));
        }
        if addrs.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(addrs)
    }
}

/// The addresses of `found` to connect to: with `public_only`, its public ones.
fn reachable(found: &[std::net::SocketAddr], public_only: bool) -> impl Iterator<Item = std::net::SocketAddr> + '_ {
    found.iter().copied().filter(move |a| !public_only || is_public(a.ip()))
}

/// Not loopback, link-local, private (RFC 1918, unique local, shared CGNAT space), unspecified, broadcast or multicast.
fn is_public(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast())
                && a != 0
                && !(a == 100 && b & 0xc0 == 64)
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                let s0 = v6.segments()[0];
                !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || s0 & 0xfe00 == 0xfc00 || s0 & 0xffc0 == 0xfe80)
            }
        },
    }
}

/// Puts `Deadlined` under TLS, so the handshake obeys the deadline too.
#[derive(Debug)]
struct DeadlineConnector(Instant);

impl<In: Transport> Connector<In> for DeadlineConnector {
    type Out = Deadlined<In>;

    fn connect(&self, _: &ConnectionDetails, chained: Option<In>) -> std::result::Result<Option<Self::Out>, ureq::Error> {
        Ok(chained.map(|io| Deadlined { io, deadline: self.0 }))
    }
}

/// Every read and write waits at most `IDLE`, and until the deadline; none starts after it.
#[derive(Debug)]
struct Deadlined<T> {
    io: T,
    deadline: Instant,
}

impl<T> Deadlined<T> {
    fn timeout(&self, next: NextTimeout) -> std::result::Result<NextTimeout, ureq::Error> {
        let left = self.deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(ureq::Error::Timeout(Timeout::Global))?;
        let idle = NextTimeout { after: next.after.min(IDLE.into()), reason: next.reason };
        Ok(if idle.after > left.into() { NextTimeout { after: left.into(), reason: Timeout::Global } } else { idle })
    }
}

impl<T: Transport> Transport for Deadlined<T> {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.io.buffers()
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> std::result::Result<(), ureq::Error> {
        let timeout = self.timeout(timeout)?;
        self.io.transmit_output(amount, timeout)
    }

    fn await_input(&mut self, timeout: NextTimeout) -> std::result::Result<bool, ureq::Error> {
        let timeout = self.timeout(timeout)?;
        self.io.await_input(timeout)
    }

    fn is_open(&mut self) -> bool {
        self.io.is_open()
    }

    fn is_tls(&self) -> bool {
        self.io.is_tls()
    }
}

/// `loc` resolved against `base` (an absolute http(s) URL) as RFC 3986 section 5.2 does, without its fragment or any
/// userinfo; only http(s) URLs with a host are accepted.
fn resolve_location(base: &str, loc: &str) -> Result<String> {
    // Scheme, authority, path and query (RFC 3986 appendix B).
    fn split(r: &str) -> (Option<&str>, Option<&str>, &str, Option<&str>) {
        let r = r.split('#').next().unwrap_or("");
        let (r, query) = r.split_once('?').map_or((r, None), |(r, q)| (r, Some(q)));
        let (scheme, r) = match r.split_once(':') {
            Some((s, rest)) if !s.is_empty() && !s.contains('/') => (Some(s), rest),
            _ => (None, r),
        };
        let (auth, path) = match r.strip_prefix("//") {
            Some(r) => r.find('/').map_or((Some(r), ""), |i| (Some(&r[..i]), &r[i..])),
            None => (None, r),
        };
        (scheme, auth, path, query)
    }
    // Section 5.2.4, for a path from the root.
    fn remove_dots(path: &str) -> String {
        let segs: Vec<&str> = path.strip_prefix('/').unwrap_or(path).split('/').collect();
        let mut out = Vec::new();
        for (i, seg) in segs.iter().enumerate() {
            match *seg {
                "." | ".." => {
                    if *seg == ".." {
                        out.pop();
                    }
                    if i + 1 == segs.len() {
                        out.push("");
                    }
                }
                s => out.push(s),
            }
        }
        format!("/{}", out.join("/"))
    }
    let (Some(scheme), Some(auth), path, query) = split(base) else { bail!("redirect from a relative URL {base:?}") };
    let (s, a, p, q) = split(loc);
    let (scheme, auth, path, query) = match (s, a) {
        (Some(s), _) => (s, a.unwrap_or(""), remove_dots(p), q),
        (None, Some(a)) => (scheme, a, remove_dots(p), q),
        (None, None) if p.is_empty() => (scheme, auth, if path.is_empty() { "/".into() } else { path.to_string() }, q.or(query)),
        (None, None) if p.starts_with('/') => (scheme, auth, remove_dots(p), q),
        (None, None) => (scheme, auth, remove_dots(&format!("{}{p}", &path[..path.rfind('/').map_or(0, |i| i + 1)])), q),
    };
    let scheme = scheme.to_ascii_lowercase();
    let host = auth.rsplit_once('@').map_or(auth, |(_, host)| host);
    if !matches!(scheme.as_str(), "http" | "https") || host.is_empty() {
        bail!("unsupported redirect to {loc:?}");
    }
    Ok(format!("{scheme}://{host}{path}{}", query.map(|q| format!("?{q}")).unwrap_or_default()))
}

/// Retries of a 429 or 503 (a registry's rate limit, or one briefly unavailable) per request, within its transfer's
/// deadline.
const MAX_RETRIES: u32 = 5;

/// The wait before retry `n` (from 0) without a `Retry-After`: 1 s, doubling, at most 30 s.
fn backoff(n: u32) -> Duration {
    Duration::from_secs(1u64 << n.min(5)).min(Duration::from_secs(30))
}

/// `req` sent, and sent again after a 429 or 503 (a rate limit, or a registry briefly unavailable) up to `MAX_RETRIES`
/// times: after its `Retry-After` in seconds, or else `backoff`, and only while that wait ends before `deadline`. The
/// last answer is returned whatever its status.
fn call(
    what: &str,
    deadline: Instant,
    req: impl Fn(Duration) -> ureq::RequestBuilder<ureq::typestate::WithoutBody>,
) -> Result<ureq::http::Response<ureq::Body>> {
    for retries in 0.. {
        let left = Registry::left(deadline, what)?;
        let resp = match req(left).call() {
            Ok(resp) => resp,
            Err(e) => bail!("{what}: {e}"),
        };
        let code = resp.status().as_u16();
        if !matches!(code, 429 | 503) || retries == MAX_RETRIES {
            return Ok(resp);
        }
        // An HTTP date (rare) gets the backoff.
        let after = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()?.trim().parse().ok());
        let wait = after.map_or(backoff(retries), Duration::from_secs);
        if wait >= deadline.saturating_duration_since(Instant::now()) {
            bail!("{what}: HTTP {code}, and a retry in {} s would pass the transfer deadline", wait.as_secs());
        }
        crate::log!("image: {what}: HTTP {code}; retrying in {} s", wait.as_secs_f32().ceil());
        std::thread::sleep(wait);
    }
    unreachable!()
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

    /// The time left before `deadline`, for the next request: ureq's own limit for it, under `Deadlined`'s.
    fn left(deadline: Instant, what: &str) -> Result<Duration> {
        match deadline.checked_duration_since(Instant::now()) {
            Some(left) if !left.is_zero() => Ok(left),
            _ => bail!("{what}: transfer deadline passed"),
        }
    }

    /// Authenticates on a 401 and retries once; redirects (blob storage) are followed without credentials.
    fn get(&self, path: &str, accept: &str, deadline: Instant) -> Result<ureq::Body> {
        let base = format!("{}/{path}", self.r.base_url());
        let (mut url, mut redirects, mut authenticated) = (base.clone(), 0, false);
        let agent = agent(deadline, false);
        loop {
            let auth = if redirects == 0 { self.auth.lock().unwrap().clone() } else { None };
            let resp = call(&format!("GET {url}"), deadline, |left| {
                let mut req = agent.get(&url).config().timeout_global(Some(left)).build();
                if redirects == 0 {
                    req = req.header("Accept", accept);
                }
                if let Some(a) = &auth {
                    req = req.header("Authorization", &**a);
                }
                req
            })?;
            let header = |name: &str| resp.headers().get(name).and_then(|v| v.to_str().ok());
            match resp.status().as_u16() {
                300..=399 => {
                    let loc = header("location").ok_or("redirect without a location")?;
                    url = resolve_location(&url, loc)?;
                    if base.starts_with("https://") && !url.starts_with("https://") {
                        bail!("refusing a redirect from HTTPS to {url}");
                    }
                    redirects += 1;
                    if redirects > 5 {
                        bail!("too many redirects from {base}");
                    }
                }
                ..=299 => return Ok(resp.into_body()),
                401 if !authenticated && redirects == 0 => {
                    let challenge = header("www-authenticate").unwrap_or("").to_string();
                    self.authenticate(&challenge, deadline)?;
                    authenticated = true;
                }
                401 if redirects == 0 => {
                    bail!("GET {url}: unauthorized{}", if self.basic.is_none() { " (no credentials in docker config)" } else { "" })
                }
                code => {
                    let mut body = Vec::new();
                    let _ = resp.into_body().into_reader().take(300).read_to_end(&mut body);
                    bail!("GET {url}: HTTP {code}: {}", String::from_utf8_lossy(&body).trim())
                }
            }
        }
    }

    /// Whether the image reference names a local registry: `localhost`, or a loopback, link-local or private address
    /// as written (never as resolved: DNS could answer otherwise for the registry than for its token realm). Its token
    /// service may be local too.
    fn local(&self) -> bool {
        let host = self.r.registry.strip_prefix('[').and_then(|h| h.split(']').next());
        let host = host.unwrap_or_else(|| self.r.registry.split(':').next().unwrap_or(""));
        host.eq_ignore_ascii_case("localhost") || host.parse().is_ok_and(|ip| !is_public(ip))
    }

    fn authenticate(&self, challenge: &str, deadline: Instant) -> Result<()> {
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
        // The registry names where to fetch: never down from HTTPS, nor into this host's own networks (its loopback
        // or metadata services) unless the registry is there itself.
        if self.r.base_url().starts_with("https://") && !realm.starts_with("https://") {
            bail!("{}: refusing token realm {realm}: not HTTPS", self.r.registry);
        }
        let agent = agent(deadline, !self.local());
        let creds = match &self.basic {
            Some(b) if self.trusted(&realm) => Some(format!("Basic {b}")),
            // Anywhere else gets an anonymous token request.
            Some(_) => {
                crate::log!("image: not sending credentials to untrusted token realm {realm}");
                None
            }
            None => None,
        };
        let resp = call(&format!("token from {realm}"), deadline, |left| {
            let mut req = agent.get(&realm).config().timeout_global(Some(left)).build();
            if let Some(service) = param("service") {
                req = req.query("service", &service);
            }
            req = req.query("scope", param("scope").unwrap_or(format!("repository:{}:pull", self.r.repository)));
            if let Some(c) = &creds {
                req = req.header("Authorization", c);
            }
            req
        })?;
        let body: Value = match resp.status().as_u16() {
            200 => serde_json::from_reader(resp.into_body().into_reader().take(1 << 20))?,
            code => bail!("token from {realm}: HTTP {code}"),
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

    /// flexvm's test binary's allocator: the system's, counting the bytes each thread allocates (`allocated`).
    struct Counting;

    thread_local! {
        static ALLOCATED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    unsafe impl std::alloc::GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
            let _ = ALLOCATED.try_with(|n| n.set(n.get() + layout.size() as u64));
            unsafe { std::alloc::System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
            unsafe { std::alloc::System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
            let _ = ALLOCATED.try_with(|n| n.set(n.get() + new_size as u64));
            unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static COUNTING: Counting = Counting;

    /// Bytes this thread has allocated so far (each reallocation counted at its new size).
    pub fn allocated() -> u64 {
        ALLOCATED.with(|n| n.get())
    }

    #[test]
    fn agent_dns_obeys_the_transfer_deadline() {
        let err = agent(Instant::now(), false).get("http://unused.example:80/").call().unwrap_err();
        let ureq::Error::Io(err) = err else { panic!("expected a timed-out lookup: {err}") };
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
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
        http_server(respond, move |socket, resp| {
            use std::io::Write;
            let _ = socket.write_all(&resp[..fast.min(resp.len())]);
            for b in resp.iter().skip(fast) {
                std::thread::sleep(drip);
                if socket.write_all(&[*b]).is_err() {
                    return;
                }
            }
        })
    }

    /// Serves each connection by its request path: `/v2/<image>/<path>` gets `send(socket, respond(base, path))`.
    fn http_server(
        respond: impl Fn(&str, &str) -> String + Send + Sync + 'static,
        send: impl Fn(&mut std::net::TcpStream, Vec<u8>) + Send + Sync + 'static,
    ) -> String {
        use std::io::{BufRead, BufReader};
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap().to_string();
        let (respond, send) = (Arc::new(respond), Arc::new(send));
        let base = addr.clone();
        std::thread::spawn(move || {
            for mut socket in server.incoming().flatten() {
                let (respond, send, base) = (respond.clone(), send.clone(), base.clone());
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(socket.try_clone().unwrap());
                    let mut request = String::new();
                    reader.read_line(&mut request).unwrap();
                    while reader.read_line(&mut String::new()).is_ok_and(|n| n > 2) {}
                    let path = request.split(' ').nth(1).unwrap_or("").to_string();
                    send(&mut socket, respond(&base, &path).into_bytes());
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
            assert!(err.contains("timed out") || err.contains("timeout") || err.contains("deadline"), "{name}: {err}");
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
        // No timeout of ureq's own: it would hold each handshake read to it, not the handshake.
        let err = agent(deadline, false).get(&format!("https://{addr}/v2/")).call().unwrap_err().to_string();
        assert!(err.contains("timeout") || err.contains("timed out"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(5), "took {:?}", start.elapsed());
    }

    /// Answers every request with `head(base, path)`, then `fill` without end, until the client hangs up.
    fn endless_server(head: impl Fn(&str, &str) -> String + Send + Sync + 'static, fill: u8) -> String {
        http_server(head, move |socket, head| {
            use std::io::Write;
            let chunk = [fill; 64 << 10];
            if socket.write_all(&head).is_ok() {
                while socket.write_all(&chunk).is_ok() {}
            }
        })
    }

    /// A chunk-size line, a header or a trailer without end is refused once ureq's fixed input buffer is full; ureq 2
    /// grew it until the deadline.
    #[test]
    fn endless_lines_allocate_a_bounded_amount() {
        const CHUNKED: &str = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        type Head = fn(&str, &str) -> String;
        let cases: [(&str, Head, u8); 4] = [
            ("chunk size", |_, _| CHUNKED.into(), b'1'),
            ("trailer", |_, _| format!("{CHUNKED}0\r\nX-Trailer: "), b'x'),
            ("header", |_, _| "HTTP/1.1 200 OK\r\nX-Pad: ".into(), b'x'),
            (
                "token",
                |base, path| {
                    if path.starts_with("/token") {
                        CHUNKED.into()
                    } else {
                        format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"http://{base}/token\"\r\nContent-Length: 0\r\n\r\n")
                    }
                },
                b'f',
            ),
        ];
        for (name, head, fill) in cases {
            let addr = endless_server(head, fill);
            let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
            let (start, before) = (Instant::now(), allocated());
            let res = reg.get("manifests/x", "*/*", start + Duration::from_secs(30)).and_then(|r| {
                let mut data = Vec::new();
                r.into_reader().read_to_end(&mut data)?;
                Ok(data)
            });
            let allocated = allocated() - before;
            let err = res.expect_err(name).to_string();
            assert!(allocated < 2 << 20, "{name}: allocated {allocated} bytes ({err})");
            assert!(start.elapsed() < Duration::from_secs(10), "{name}: took {:?} ({err})", start.elapsed());
        }
    }

    #[test]
    fn redirects_resolve_as_urls_do() {
        let base = "https://reg.example/v2/a/b/blobs/sha256:x?q=1";
        let cases = [
            ("https://cdn.example/blob?sig=2", "https://cdn.example/blob?sig=2"),
            ("HTTPS://cdn.example/a/./b/../c", "https://cdn.example/a/c"),
            ("//cdn.example/blob", "https://cdn.example/blob"),
            ("//cdn.example", "https://cdn.example/"),
            ("/other/path?x=y#frag", "https://reg.example/other/path?x=y"),
            ("../blob", "https://reg.example/v2/a/b/blob"),
            ("../../../../../../blob", "https://reg.example/blob"),
            ("blob2", "https://reg.example/v2/a/b/blobs/blob2"),
            ("./", "https://reg.example/v2/a/b/blobs/"),
            ("..", "https://reg.example/v2/a/b/"),
            ("?z", "https://reg.example/v2/a/b/blobs/sha256:x?z"),
            ("", "https://reg.example/v2/a/b/blobs/sha256:x?q=1"),
            ("#f", "https://reg.example/v2/a/b/blobs/sha256:x?q=1"),
            ("https://user:pw@cdn.example/blob", "https://cdn.example/blob"),
            ("//user@cdn.example/blob", "https://cdn.example/blob"),
            ("http://cdn.example/blob", "http://cdn.example/blob"),
        ];
        for (loc, want) in cases {
            assert_eq!(resolve_location(base, loc).unwrap(), want, "{loc:?}");
        }
        assert_eq!(resolve_location("http://127.0.0.1:5000/v2/x", "//cdn/y").unwrap(), "http://cdn/y");
        for loc in ["ftp://cdn.example/blob", "https:///blob", "https:blob", "file:/etc/passwd", "javascript:x"] {
            assert!(resolve_location(base, loc).is_err(), "{loc:?}");
        }
    }

    /// `get` follows a protocol-relative redirect to its host, not the registry's, without credentials; one to
    /// plain HTTP from HTTPS is refused after resolution (here, the registry is HTTP, so it is followed).
    #[test]
    fn redirects_go_where_they_point() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let blob = drip_server(usize::MAX, Duration::ZERO, |_, path| {
            let body = if path == "/v2/test/blob" { "moved" } else { "wrong" };
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        });
        let hops = Arc::new(AtomicUsize::new(0));
        let (blob2, hops2) = (blob.clone(), hops.clone());
        let addr = drip_server(usize::MAX, Duration::ZERO, move |_, path| {
            hops2.fetch_add(1, Ordering::SeqCst);
            let loc = if path.ends_with("/blobs/x") { "../elsewhere".to_string() } else { format!("//{blob2}/v2/test/blob") };
            format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        });
        let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
        *reg.auth.lock().unwrap() = Some("Bearer secret".into());
        let mut data = String::new();
        reg.get("blobs/x", "*/*", Instant::now() + Duration::from_secs(5)).unwrap().into_reader().read_to_string(&mut data).unwrap();
        assert_eq!(data, "moved");
        assert_eq!(hops.load(Ordering::SeqCst), 2, "/v2/test/blobs/x, then /v2/test/elsewhere");
    }

    /// A 429 (or 503) is retried after its `Retry-After`, or a backoff, unless that would pass the deadline.
    #[test]
    fn rate_limits_are_retried_within_the_deadline() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let addr = drip_server(usize::MAX, Duration::ZERO, move |_, _| {
            if calls2.fetch_add(1, Ordering::SeqCst) == 0 {
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nblob".into()
            }
        });
        let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
        let (start, mut data) = (Instant::now(), String::new());
        reg.get("blobs/x", "*/*", start + Duration::from_secs(10)).unwrap().into_reader().read_to_string(&mut data).unwrap();
        assert_eq!((data.as_str(), calls.load(Ordering::SeqCst)), ("blob", 2));
        assert!(start.elapsed() >= Duration::from_secs(1), "waited {:?}", start.elapsed());

        // A wait past the deadline fails at once; one always busy stops after MAX_RETRIES.
        let addr = drip_server(usize::MAX, Duration::ZERO, |_, _| {
            "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 3600\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        });
        let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
        let start = Instant::now();
        let err = reg.get("blobs/x", "*/*", start + Duration::from_secs(60)).err().unwrap().to_string();
        assert!(err.contains("HTTP 503") && err.contains("deadline"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(5));
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let addr = drip_server(usize::MAX, Duration::ZERO, move |_, _| {
            calls2.fetch_add(1, Ordering::SeqCst);
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        });
        let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
        let err = reg.get("blobs/x", "*/*", Instant::now() + Duration::from_secs(10)).err().unwrap().to_string();
        assert!(err.contains("HTTP 429"), "{err}");
        assert_eq!(calls.load(Ordering::SeqCst), 1 + MAX_RETRIES as usize);
    }

    /// Token requests are retried too; a `Retry-After` too large for any deadline, or an HTTP date, is no panic.
    #[test]
    fn token_rate_limits_and_huge_retry_afters() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let addr = drip_server(usize::MAX, Duration::ZERO, move |base, path| {
            if !path.starts_with("/token") {
                let auth = "WWW-Authenticate: Bearer realm=\"http://".to_string() + base + "/token\"";
                return format!("HTTP/1.1 401 Unauthorized\r\n{auth}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
            match calls2.fetch_add(1, Ordering::SeqCst) {
                0 => "HTTP/1.1 429 Too Many Requests\r\nRetry-After: Wed, 21 Oct 2015 07:28:00 GMT\r\nContent-Length: 0\r\n\r\n".into(),
                1 => "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 18446744073709551615\r\nContent-Length: 0\r\n\r\n".into(),
                _ => "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"token\":\"t\"}".into(),
            }
        });
        let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
        let start = Instant::now();
        let err = reg.authenticate(&format!("Bearer realm=\"http://{addr}/token\""), start + Duration::from_secs(10)).unwrap_err().to_string();
        assert!(err.contains("HTTP 503") && err.contains("deadline"), "{err}");
        // The HTTP date got the 1 s backoff.
        assert!(start.elapsed() >= Duration::from_secs(1) && calls.load(Ordering::SeqCst) == 2);
        reg.authenticate(&format!("Bearer realm=\"http://{addr}/token\""), Instant::now() + Duration::from_secs(10)).unwrap();
        assert_eq!(reg.auth.lock().unwrap().as_deref(), Some("Bearer t"));
        assert_eq!(
            (backoff(0), backoff(1), backoff(4), backoff(5), backoff(50)),
            (Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(16), Duration::from_secs(30), Duration::from_secs(30))
        );
    }

    /// A registry cannot point the token request at this host's own networks, by address or by name, nor down to HTTP.
    #[test]
    fn token_realms_stay_out_of_local_networks() {
        let served = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let served2 = served.clone();
        let local = drip_server(usize::MAX, Duration::ZERO, move |_, _| {
            served2.store(true, std::sync::atomic::Ordering::SeqCst);
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"token\":\"t\"}".into()
        });
        let port = local.rsplit(':').next().unwrap();
        // A public registry (TEST-NET-3, never contacted here).
        let public = Registry::new(Reference::parse("203.0.113.7/test").unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        for realm in [format!("https://127.0.0.1:{port}/t"), format!("https://localhost:{port}/t"), format!("https://[::1]:{port}/t")] {
            let err = public.authenticate(&format!("Bearer realm=\"{realm}\""), deadline).unwrap_err().to_string();
            assert!(err.contains("not on a public address"), "{realm}: {err}");
        }
        let err = public.authenticate("Bearer realm=\"http://auth.example/t\"", deadline).unwrap_err().to_string();
        assert!(err.contains("not HTTPS"), "{err}");
        assert!(!served.load(std::sync::atomic::Ordering::SeqCst));
        // A local registry may use a local token service.
        let reg = Registry::new(Reference::parse(&format!("{local}/test")).unwrap());
        reg.authenticate(&format!("Bearer realm=\"http://{local}/t\""), deadline).unwrap();
        assert!(served.load(std::sync::atomic::Ordering::SeqCst));

        // Only a registry local as written is exempt; a name is filtered whatever it resolves to.
        let local = |r: &str| Registry::new(Reference::parse(&format!("{r}/test")).unwrap()).local();
        assert!(local("127.0.0.1:5000") && local("localhost:5000") && local("10.0.0.5") && local("[::1]:5000"));
        assert!(!local("registry.example") && !local("localhost.evil.example") && !local("8.8.8.8:5000"));
        let mixed: Vec<std::net::SocketAddr> = vec!["8.8.8.8:443".parse().unwrap(), "10.0.0.1:443".parse().unwrap(), "[fe80::1]:443".parse().unwrap()];
        assert_eq!(reachable(&mixed, true).collect::<Vec<_>>(), &mixed[..1]);
        assert_eq!(reachable(&mixed, false).count(), 3);

        use std::net::IpAddr;
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_public(ip.parse::<IpAddr>().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "203.0.113.7", "100.128.0.1", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public(ip.parse::<IpAddr>().unwrap()), "{ip}");
        }
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
