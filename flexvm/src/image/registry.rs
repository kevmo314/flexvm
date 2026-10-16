//! A minimal OCI distribution (registry v2) client.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, RustlsConnector, Transport};
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

/// Where the last connection an agent opened went: its socket's peer, as connected.
type Peer = Arc<Mutex<Option<SocketAddr>>>;

/// An agent for one transfer: DNS, connect, the TLS handshake and every read and write obey the transfer's deadline
/// (ureq holds each handshake read, not the handshake, to its connect timeout), and its connections are never pooled,
/// into another transfer or another request of this one: each request opens its own, and records its peer in `peer`.
/// With `public_only`, it connects only to public addresses (as resolved, so DNS cannot rebind it elsewhere).
fn agent(deadline: Instant, public_only: bool, peer: Peer) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(30)))
        .user_agent(concat!("flexvm/", env!("CARGO_PKG_VERSION")))
        // Redirects are followed by hand, never carrying credentials; statuses are handled by hand.
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .proxy(None)
        .max_idle_connections(0)
        .max_idle_connections_per_host(0)
        .build();
    let connector = PeerConnector(peer).chain(DeadlineConnector(deadline)).chain(RustlsConnector::default());
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
        #[cfg(test)]
        let found = match tests::fake_dns(&addr) {
            Some(found) => found,
            None => crate::util::resolve(&addr, self.deadline)?,
        };
        #[cfg(not(test))]
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
    #[cfg(test)]
    if tests::PRETEND_PUBLIC.lock().unwrap().contains(&ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast())
                && a != 0
                && !(a == 100 && b & 0xc0 == 64)
        }
        // IPv4-mapped, or NAT64's well-known prefix (RFC 6052): as the IPv4 address it stands for.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped().or_else(|| nat64_well_known(v6)) {
            Some(v4) => is_public(IpAddr::V4(v4)),
            // NAT64's local-use prefix (RFC 8215) may translate to anything, private addresses included.
            None if is_nat64(v6) => false,
            None => {
                let s0 = v6.segments()[0];
                !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || s0 & 0xfe00 == 0xfc00 || s0 & 0xffc0 == 0xfe80)
            }
        },
    }
}

/// The IPv4 address embedded in an address under NAT64's well-known prefix, 64:ff9b::/96.
fn nat64_well_known(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let s = v6.segments();
    (s[..6] == [0x64, 0xff9b, 0, 0, 0, 0]).then(|| std::net::Ipv4Addr::from(u128::from(v6) as u32))
}

/// Under a NAT64 prefix: the well-known 64:ff9b::/96 or the local-use 64:ff9b:1::/48.
fn is_nat64(v6: std::net::Ipv6Addr) -> bool {
    let s = v6.segments();
    nat64_well_known(v6).is_some() || s[..3] == [0x64, 0xff9b, 1]
}

/// Whether a registry at `ip` is local: a loopback, link-local or private address, but never one reached through
/// NAT64, which translates to an address this host cannot see and need not be its own network's. (A network-specific
/// NAT64 prefix, such as a ULA /96, cannot be told from a native address without the host's translation config.)
fn local_address(ip: std::net::IpAddr) -> bool {
    !is_public(ip) && !matches!(ip, std::net::IpAddr::V6(v6) if is_nat64(v6))
}

/// Connects as ureq's `TcpConnector` does, trying each resolved address in turn, and records the connected socket's
/// peer: the address the answer to this request comes from (whatever else DNS answered).
#[derive(Debug)]
struct PeerConnector(Peer);

impl Connector<()> for PeerConnector {
    type Out = PeerTcp;

    fn connect(&self, details: &ConnectionDetails, _: Option<()>) -> std::result::Result<Option<PeerTcp>, ureq::Error> {
        use std::io::ErrorKind::*;
        let (start, budget, n) = (Instant::now(), details.timeout.not_zero().map(|t| *t), details.addrs.len());
        let mut last = None;
        for (i, addr) in details.addrs.iter().enumerate() {
            // Every address but the last gets half the time left, so one that never answers leaves time for the rest.
            let per = budget.map(|b| {
                let left = b.saturating_sub(start.elapsed());
                if i + 1 < n { left / 2 } else { left }.max(Duration::from_millis(10))
            });
            match per.map_or_else(|| TcpStream::connect(addr), |t| TcpStream::connect_timeout(addr, t)) {
                Ok(stream) => {
                    stream.set_nodelay(details.config.no_delay())?;
                    *self.0.lock().unwrap() = Some(stream.peer_addr()?);
                    let buffers = LazyBuffers::new(details.config.input_buffer_size(), details.config.output_buffer_size());
                    return Ok(Some(PeerTcp { stream, buffers }));
                }
                Err(e) if matches!(e.kind(), ConnectionRefused | HostUnreachable | NetworkUnreachable | AddrNotAvailable | TimedOut | WouldBlock) => {
                    last = Some(e)
                }
                Err(e) => return Err(e.into()),
            }
            if budget.is_some_and(|b| start.elapsed() >= b) {
                break;
            }
        }
        Err(match last {
            Some(e) if matches!(e.kind(), TimedOut | WouldBlock) => ureq::Error::Timeout(details.timeout.reason),
            Some(e) => e.into(),
            None => ureq::Error::HostNotFound,
        })
    }
}

/// A plain TCP connection (ureq's own is not nameable outside it).
#[derive(Debug)]
struct PeerTcp {
    stream: TcpStream,
    buffers: LazyBuffers,
}

fn io_error(e: std::io::Error, timeout: NextTimeout) -> ureq::Error {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ureq::Error::Timeout(timeout.reason),
        _ => e.into(),
    }
}

impl Transport for PeerTcp {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> std::result::Result<(), ureq::Error> {
        self.stream.set_write_timeout(timeout.not_zero().map(|t| *t))?;
        self.stream.write_all(&self.buffers.output()[..amount]).map_err(|e| io_error(e, timeout))
    }

    fn await_input(&mut self, timeout: NextTimeout) -> std::result::Result<bool, ureq::Error> {
        self.stream.set_read_timeout(timeout.not_zero().map(|t| *t))?;
        let n = self.stream.read(self.buffers.input_append_buf()).map_err(|e| io_error(e, timeout))?;
        self.buffers.input_appended(n);
        Ok(n > 0)
    }

    /// Open while nothing is waiting to be read and the peer has not hung up.
    fn is_open(&mut self) -> bool {
        if self.stream.set_nonblocking(true).is_err() {
            return false;
        }
        let idle = matches!(self.stream.read(&mut [0]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock);
        self.stream.set_nonblocking(false).is_ok() && idle
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

/// Where redirect `redirects` (0 for the first) from `url` to `loc` goes: refused from an HTTPS `base` to anything
/// else, and past the fifth.
fn next_hop(base: &str, url: &str, loc: &str, redirects: usize) -> Result<String> {
    let next = resolve_location(url, loc)?;
    if base.starts_with("https://") && !next.starts_with("https://") {
        bail!("refusing a redirect from HTTPS to {next}");
    }
    if redirects >= 5 {
        bail!("too many redirects from {base}");
    }
    Ok(next)
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

/// The longest wait a `Retry-After` gets: a registry asking for more is asked again after this.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(120);

/// The wait before retry `n`: `retry_after` in seconds, at most `MAX_RETRY_AFTER`, or else (also for an HTTP date,
/// which is rare) `backoff`.
fn retry_wait(retry_after: Option<&str>, n: u32) -> Duration {
    retry_after.and_then(|v| v.trim().parse().ok()).map_or(backoff(n), |s| Duration::from_secs(s).min(MAX_RETRY_AFTER))
}

/// `req` sent, and sent again after a 429 or 503 (a rate limit, or a registry briefly unavailable) up to `MAX_RETRIES`
/// times: after `retry_wait`, and only while that wait ends before `deadline`. The last answer is returned whatever its
/// status.
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
        let wait = retry_wait(resp.headers().get("retry-after").and_then(|v| v.to_str().ok()), retries);
        if wait >= deadline.saturating_duration_since(Instant::now()) {
            bail!("{what}: HTTP {code}, and a retry in {} s would pass the transfer deadline", wait.as_secs());
        }
        crate::log!("image: {what}: HTTP {code}; retrying in {} s", wait.as_secs_f32().ceil());
        std::thread::sleep(wait);
    }
    unreachable!()
}

/// A `WWW-Authenticate` challenge's scheme and auth-params (RFC 9110 section 11.2), their names lowercased; a quoted
/// value may hold commas, and backslash-escaped quotes. Anything not `name=value` (a token68) is skipped.
fn parse_challenge(challenge: &str) -> (&str, Vec<(String, String)>) {
    let challenge = challenge.trim();
    let (scheme, mut rest) = challenge.split_once(|c: char| c.is_ascii_whitespace()).unwrap_or((challenge, ""));
    let mut params = Vec::new();
    loop {
        rest = rest.trim_start_matches(|c: char| c == ',' || c.is_ascii_whitespace());
        let Some(i) = rest.find(['=', ',']) else { break };
        if rest.as_bytes()[i] == b',' {
            rest = &rest[i..];
            continue;
        }
        let name = rest[..i].trim().to_ascii_lowercase();
        rest = rest[i + 1..].trim_start();
        let mut value = String::new();
        if let Some(quoted) = rest.strip_prefix('"') {
            let (mut chars, mut end) = (quoted.char_indices(), quoted.len());
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => value.extend(chars.next().map(|(_, c)| c)),
                    '"' => {
                        end = i + 1;
                        break;
                    }
                    c => value.push(c),
                }
            }
            rest = &quoted[end..];
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            value = rest[..end].trim().to_string();
            rest = &rest[end..];
        }
        params.push((name, value));
    }
    (scheme, params)
}

/// Shared by all of an image's layers (`Arc`), its token with them.
pub struct Registry {
    pub r: Reference,
    /// `r.base_url()` (tests point it elsewhere).
    base: String,
    /// base64 `user:password` from the Docker config.
    basic: Option<String>,
    auth: Mutex<Option<Arc<str>>>,
}

impl Registry {
    pub fn new(r: Reference) -> Registry {
        // Credentials only ever travel over TLS.
        let base = r.base_url();
        let basic = if base.starts_with("https://") { docker_credentials(&r.registry) } else { None };
        Registry { r, base, basic, auth: Mutex::new(None) }
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

    /// Authenticates on a 401 and retries once; redirects (blob storage) are followed without credentials, and, as
    /// the token service is, only to public addresses unless the registry is local.
    fn get(&self, path: &str, accept: &str, deadline: Instant) -> Result<ureq::Body> {
        let base = format!("{}/{path}", self.base);
        let (mut url, mut redirects, mut authenticated) = (base.clone(), 0, false);
        let peer = Peer::default();
        // The registry itself may be anywhere: it is what the image reference names.
        let registry = agent(deadline, false, peer.clone());
        let (mut local, mut hops) = (self.local(), None);
        loop {
            let auth = if redirects == 0 { self.auth.lock().unwrap().clone() } else { None };
            let client = if redirects == 0 { &registry } else { hops.get_or_insert_with(|| agent(deadline, !local, Peer::default())) };
            let resp = call(&format!("GET {url}"), deadline, |left| {
                let mut req = client.get(&url).config().timeout_global(Some(left)).build();
                if redirects == 0 {
                    req = req.header("Accept", accept);
                }
                if let Some(auth) = auth {
                    req = req.header("Authorization", auth);
                }
                req
            })?;
            if redirects == 0 {
                // The registry is local, and may send this host to its own networks, if it is written as a local
                // address or this answer came over a connection to one. Its DNS cannot make that so from outside: a
                // name answering with a private address sends flexvm to that host, whose answer (the realm or the
                // redirect included) the name's owner does not write; and what counts is the peer of the socket the
                // answer came over (never pooled, so this request's own), not any address DNS also answered.
                local = self.local() || peer.lock().unwrap().take().is_some_and(|p| local_address(p.ip()));
            }
            let header = |name: &str| resp.headers().get(name).and_then(|v| v.to_str().ok());
            match resp.status().as_u16() {
                300..=399 => {
                    let loc = match resp.headers().get("location") {
                        None => bail!("GET {url}: redirect without a location"),
                        Some(v) => match v.to_str() {
                            Ok(loc) => loc,
                            Err(_) => bail!("GET {url}: redirect to a location that is not ASCII: {:?}", String::from_utf8_lossy(v.as_bytes())),
                        },
                    };
                    url = next_hop(&base, &url, loc, redirects)?;
                    redirects += 1;
                }
                ..=299 => return Ok(resp.into_body()),
                401 if !authenticated && redirects == 0 => {
                    let challenge = header("www-authenticate").unwrap_or("").to_string();
                    self.authenticate(&challenge, deadline, local)?;
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

    /// Whether the image reference names a local registry as written: `localhost`, or a loopback, link-local or
    /// private address. (`get` also finds one local by the address it answers from.)
    fn local(&self) -> bool {
        let host = self.r.host();
        host.eq_ignore_ascii_case("localhost") || host.parse().is_ok_and(local_address)
    }

    /// Answers `challenge` for a registry that is `local` or not: a local registry's token service may be anywhere,
    /// any other's must be HTTPS on a public address.
    fn authenticate(&self, challenge: &str, deadline: Instant, local: bool) -> Result<()> {
        let (scheme, params) = parse_challenge(challenge);
        if scheme.eq_ignore_ascii_case("basic") {
            let Some(b) = &self.basic else { bail!("{} wants basic credentials; none found", self.r.registry) };
            *self.auth.lock().unwrap() = Some(format!("Basic {b}").into());
            return Ok(());
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            bail!("{}: unsupported auth challenge {challenge:?}", self.r.registry);
        }
        let param = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
        let realm = param("realm").ok_or("auth challenge has no realm")?;
        // The registry names where to fetch: never down from HTTPS, nor into this host's own networks (its loopback
        // or metadata services) unless the registry is there itself.
        if (self.base.starts_with("https://") || !local) && !realm.starts_with("https://") {
            bail!("{}: refusing token realm {realm}: not HTTPS", self.r.registry);
        }
        let agent = agent(deadline, !local, Peer::default());
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

    /// Addresses `is_public` takes for public: loopback ones the tests stand public servers on.
    pub(super) static PRETEND_PUBLIC: Mutex<Vec<std::net::IpAddr>> = Mutex::new(Vec::new());

    /// Names the agents' resolver answers itself: `(HOST:PORT, addresses)`.
    static FAKE_DNS: Mutex<Vec<(String, Vec<SocketAddr>)>> = Mutex::new(Vec::new());

    pub(super) fn fake_dns(addr: &str) -> Option<Vec<SocketAddr>> {
        FAKE_DNS.lock().unwrap().iter().find(|(name, _)| name == addr).map(|(_, a)| a.clone())
    }

    /// A public address, as far as the tests' `is_public` knows, on this host's loopback.
    const PUBLIC: &str = "127.0.0.2";

    /// A server on `ip` answering every request with `respond(base, path)`, counting its requests.
    fn counting_server(ip: &str, respond: impl Fn(&str, &str) -> String + Send + Sync + 'static) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let hits2 = hits.clone();
        let addr = http_server_on(
            ip,
            move |base, path| {
                hits2.fetch_add(1, Ordering::SeqCst);
                respond(base, path)
            },
            |socket, resp| {
                let _ = socket.write_all(&resp);
            },
        );
        (addr.parse().unwrap(), hits)
    }

    /// A registry for `test` at `name` (resolved to `addrs`), over plain HTTP whatever the name.
    fn named_registry(name: &str, addrs: &[SocketAddr]) -> Registry {
        PRETEND_PUBLIC.lock().unwrap().push(PUBLIC.parse().unwrap());
        let port = addrs[0].port();
        FAKE_DNS.lock().unwrap().push((format!("{name}:{port}"), addrs.to_vec()));
        let mut reg = Registry::new(Reference::parse(&format!("{name}:{port}/test")).unwrap());
        reg.base = format!("http://{name}:{port}/v2/test");
        reg
    }

    const CLOSE: &str = "Content-Length: 0\r\nConnection: close\r\n\r\n";

    /// A registry is local by the address its answer came from: one reached on a private address by name may use a
    /// private token service and redirect into private networks; one reached on a public address may not, nor can a
    /// mixed DNS answer make it local while the answer came from the public address.
    #[test]
    fn registries_are_local_by_their_peer() {
        use std::sync::atomic::Ordering;
        let deadline = || Instant::now() + Duration::from_secs(10);
        let ok = |b: &str| format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len());
        let (token, tokens) = counting_server("127.0.0.1", move |_, _| ok("{\"token\":\"t\"}"));
        let (blob, blobs) = counting_server("127.0.0.1", move |_, _| ok("private"));
        let challenge = move |realm: &str| format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"{realm}://{token}/token\"\r\n{CLOSE}");
        let fetch = |reg: &Registry| {
            reg.get("blobs/x", "*/*", deadline()).and_then(|r| {
                let mut data = String::new();
                r.into_reader().read_to_string(&mut data)?;
                Ok(data)
            })
        };
        // Answers 401 until it gets a token, then redirects to the private blob server.
        let registry = move |ip: &str, realm: &'static str| {
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            counting_server(ip, move |_, _| match calls.fetch_add(1, Ordering::SeqCst) {
                0 => challenge(realm),
                _ => format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{blob}/v2/test/blob\r\n{CLOSE}"),
            })
            .0
        };

        // Private by name: its private realm and redirect are followed.
        let private = registry("127.0.0.1", "http");
        assert_eq!(fetch(&named_registry("private.test", &[private])).unwrap(), "private");
        assert_eq!((tokens.load(Ordering::SeqCst), blobs.load(Ordering::SeqCst)), (1, 1));

        // Public by name: neither its private realm, over HTTPS or not, nor its redirect.
        for realm in ["https", "http"] {
            let err = fetch(&named_registry("public.test", &[registry(PUBLIC, realm)])).unwrap_err().to_string();
            assert!(err.contains(if realm == "https" { "not on a public address" } else { "not HTTPS" }), "{err}");
        }
        let (redirect, _) = counting_server(PUBLIC, move |_, _| format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{blob}/v2/test/blob\r\n{CLOSE}"));
        let err = fetch(&named_registry("public-redirect.test", &[redirect])).unwrap_err().to_string();
        assert!(err.contains("not on a public address") && err.contains(&blob.to_string()), "{err}");

        // A mixed answer, public first: the answer comes from the public address, and the registry is not local.
        let public = registry(PUBLIC, "https");
        let err = fetch(&named_registry("mixed.test", &[public, registry("127.0.0.1", "https")])).unwrap_err().to_string();
        assert!(err.contains("not on a public address"), "{err}");
        // Public, unreachable first (a refused port): the private one connected, so local.
        let refused = std::net::TcpListener::bind((PUBLIC, 0)).unwrap().local_addr().unwrap();
        assert_eq!(fetch(&named_registry("mixed-down.test", &[refused, registry("127.0.0.1", "http")])).unwrap(), "private");
        assert_eq!((tokens.load(Ordering::SeqCst), blobs.load(Ordering::SeqCst)), (2, 2));
    }

    /// A redirect to a location that is not ASCII says so.
    #[test]
    fn non_ascii_locations_are_reported() {
        let (addr, _) = counting_server("127.0.0.1", |_, _| format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: /caf\u{e9}\r\n{CLOSE}"));
        let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
        let err = reg.get("blobs/x", "*/*", Instant::now() + Duration::from_secs(10)).err().unwrap().to_string();
        assert!(err.contains("not ASCII") && err.contains("caf"), "{err}");
    }

    #[test]
    fn retry_after_is_capped() {
        assert_eq!(retry_wait(Some("3600"), 0), MAX_RETRY_AFTER);
        assert_eq!(retry_wait(Some("18446744073709551615"), 0), MAX_RETRY_AFTER);
        assert_eq!(retry_wait(Some(" 7 "), 0), Duration::from_secs(7));
        assert_eq!(retry_wait(Some("Wed, 21 Oct 2015 07:28:00 GMT"), 2), backoff(2));
        assert_eq!(retry_wait(None, 1), backoff(1));
    }

    #[test]
    fn challenges_parse_as_rfc_9110_has_them() {
        let p = |c: &str| {
            let (scheme, params) = parse_challenge(c);
            (scheme.to_string(), params.into_iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>())
        };
        let want = |s: &str, ps: &[&str]| (s.to_string(), ps.iter().map(|p| p.to_string()).collect::<Vec<_>>());
        assert_eq!(
            p(r#"Bearer realm="https://auth.example/token",service="registry.example",scope="repository:a/b:pull,push""#),
            want("Bearer", &["realm=https://auth.example/token", "service=registry.example", "scope=repository:a/b:pull,push"])
        );
        assert_eq!(p(r#"bearer  Realm = "https://a/t" , SCOPE=x , Service="s""#), want("bearer", &["realm=https://a/t", "scope=x", "service=s"]));
        assert_eq!(p(r#"Bearer realm="a\"b\\c,d""#), want("Bearer", &[r#"realm=a"b\c,d"#]));
        assert_eq!(p("Bearer	realm=https://a/t,,service=s,"), want("Bearer", &["realm=https://a/t", "service=s"]));
        assert_eq!(p(r#"Bearer junk, realm="r""#), want("Bearer", &["realm=r"]));
        assert_eq!(p(r#"Bearer realm="unterminated, scope=x"#), want("Bearer", &["realm=unterminated, scope=x"]));
        assert_eq!(p("Basic"), want("Basic", &[]));
        assert_eq!(p(""), want("", &[]));
        // Names match whatever their case.
        let reg = Registry::new(Reference::parse("203.0.113.7/test").unwrap());
        let err = reg.authenticate(r#"Bearer REALM="http://auth.example/t""#, Instant::now() + Duration::from_secs(5), false).unwrap_err().to_string();
        assert!(err.contains("not HTTPS"), "{err}");
    }

    /// NAT64 addresses are public as the IPv4 address they embed (well-known prefix) or never (local-use prefix), and
    /// never make a registry local.
    #[test]
    fn nat64_addresses() {
        use std::net::IpAddr;
        for (ip, public, local) in [
            ("64:ff9b::808:808", true, false),
            ("64:ff9b::a00:5", false, false),
            ("64:ff9b::7f00:1", false, false),
            ("64:ff9b::a9fe:a9fe", false, false),
            ("64:ff9b:1::808:808", false, false),
            ("64:ff9b:1:ffff::1", false, false),
            ("64:ff9b:2::1", true, false),
            ("fd00::1", false, true),
            ("10.0.0.5", false, true),
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!((is_public(ip), local_address(ip)), (public, local), "{ip}");
        }
        for host in ["[64:ff9b::a00:5]:5000", "[64:ff9b:1::1]", "[64:ff9b::7f00:1]:5000"] {
            assert!(!Registry::new(Reference::parse(&format!("{host}/x")).unwrap()).local(), "{host}");
        }
    }

    #[test]
    fn ipv6_registries_are_local_as_written() {
        let reg = Registry::new(Reference::parse("[::1]:5000/x").unwrap());
        assert!(reg.local() && reg.base.starts_with("http://[::1]:5000/"));
        assert!(!Registry::new(Reference::parse("[2606:4700::1111]:5000/x").unwrap()).local());
    }

    #[test]
    fn agent_dns_obeys_the_transfer_deadline() {
        let err = agent(Instant::now(), false, Peer::default()).get("http://unused.example:80/").call().unwrap_err();
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
        http_server_on("127.0.0.1", respond, send)
    }

    /// `http_server`, listening on `ip`.
    fn http_server_on(
        ip: &str,
        respond: impl Fn(&str, &str) -> String + Send + Sync + 'static,
        send: impl Fn(&mut std::net::TcpStream, Vec<u8>) + Send + Sync + 'static,
    ) -> String {
        http_server_headers(ip, move |base, path, _| respond(base, path), send)
    }

    /// `http_server_on`, `respond` seeing the request's headers too.
    fn http_server_headers(
        ip: &str,
        respond: impl Fn(&str, &str, &ureq::http::HeaderMap) -> String + Send + Sync + 'static,
        send: impl Fn(&mut std::net::TcpStream, Vec<u8>) + Send + Sync + 'static,
    ) -> String {
        use std::io::{BufRead, BufReader};
        let server = std::net::TcpListener::bind((ip, 0)).unwrap();
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
                    let mut headers = ureq::http::HeaderMap::new();
                    let mut line = String::new();
                    while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                        if let Some((name, value)) = line.trim_end().split_once(':') {
                            if let (Ok(name), Ok(value)) = (name.parse::<ureq::http::HeaderName>(), value.trim().parse()) {
                                headers.append(name, value);
                            }
                        }
                        line.clear();
                    }
                    let path = request.split(' ').nth(1).unwrap_or("").to_string();
                    send(&mut socket, respond(&base, &path, &headers).into_bytes());
                });
            }
        });
        addr
    }

    type Requests = Arc<Mutex<Vec<(String, ureq::http::HeaderMap)>>>;

    fn capturing_server(respond: impl Fn(&str, &str) -> String + Send + Sync + 'static) -> (String, Requests) {
        let requests: Requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let addr = http_server_headers(
            "127.0.0.1",
            move |base, path, headers| {
                seen.lock().unwrap().push((path.into(), headers.clone()));
                respond(base, path)
            },
            |socket, response| {
                use std::io::Write;
                socket.write_all(&response).unwrap();
            },
        );
        (addr, requests)
    }

    fn response(status: &str, headers: &str, body: &str) -> String {
        format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
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
        let err = agent(deadline, false, Peer::default()).get(&format!("https://{addr}/v2/")).call().unwrap_err().to_string();
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
        let (blob, blob_requests) = capturing_server(|_, path| {
            let body = if path == "/v2/test/blob" { "moved" } else { "wrong" };
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        });
        let hops = Arc::new(AtomicUsize::new(0));
        let (blob2, hops2) = (blob.clone(), hops.clone());
        let (addr, requests) = capturing_server(move |_, path| {
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
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].1.get("authorization").unwrap(), "Bearer secret");
        assert!(!requests[1].1.contains_key("authorization"));
        let blob_requests = blob_requests.lock().unwrap();
        assert_eq!(blob_requests.len(), 1);
        assert!(!blob_requests[0].1.contains_key("authorization"));
    }

    #[test]
    fn authentication_failures_are_clear_and_bounded() {
        // Each case runs through get, including the registry's challenge and token exchange.
        for (challenge, token, expected, registry_calls, token_calls) in [
            ("Basic realm=\"test\"", "", "wants basic credentials; none found", 1, 0),
            ("Digest realm=\"test\"", "", "unsupported auth challenge", 1, 0),
            ("Bearer service=\"test\"", "", "auth challenge has no realm", 1, 0),
            ("Bearer realm=\"file:///token\"", "", "token from file:///token", 1, 0),
            ("Bearer realm=\"{base}/token\"", "{", "EOF while parsing", 1, 1),
            ("Bearer realm=\"{base}/token\"", "{}", "token response has no token", 1, 1),
            ("Bearer realm=\"{base}/token\"", "{\"token\":\"secret\"}", "unauthorized (no credentials in docker config)", 2, 1),
        ] {
            let (addr, requests) = capturing_server(move |base, path| {
                if path.starts_with("/token") {
                    response("200 OK", "", token)
                } else {
                    let challenge = challenge.replace("{base}", &format!("http://{base}"));
                    response("401 Unauthorized", &format!("WWW-Authenticate: {challenge}\r\n"), "")
                }
            });
            let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
            let err = reg.get("blobs/x", "*/*", Instant::now() + Duration::from_secs(2)).err().unwrap().to_string();
            assert!(err.contains(expected), "{challenge}: {err}");
            let seen = requests.lock().unwrap();
            assert_eq!(seen.iter().filter(|(p, _)| p.starts_with("/v2/")).count(), registry_calls, "{challenge}");
            assert_eq!(seen.iter().filter(|(p, _)| p.starts_with("/token")).count(), token_calls, "{challenge}");
            if registry_calls == 2 {
                assert_eq!(seen.last().unwrap().1.get("authorization").unwrap(), "Bearer secret");
            }
        }
    }

    #[test]
    fn redirect_failures_stop_before_the_forbidden_destination() {
        let forbidden = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        forbidden.set_nonblocking(true).unwrap();
        let destination = format!("http://{}/forbidden", forbidden.local_addr().unwrap());
        for missing in [true, false] {
            let dest = destination.clone();
            let (addr, seen) = capturing_server(move |_, path| {
                let headers = if missing {
                    String::new()
                } else if path.ends_with("/5") {
                    format!("Location: {dest}\r\n")
                } else {
                    let n = path.rsplit('/').next().unwrap().parse::<usize>().unwrap();
                    format!("Location: /v2/test/{}\r\n", n + 1)
                };
                response("307 Temporary Redirect", &headers, "")
            });
            let reg = Registry::new(Reference::parse(&format!("{addr}/test")).unwrap());
            let err = reg.get("0", "*/*", Instant::now() + Duration::from_secs(2)).err().unwrap().to_string();
            assert!(err.contains(if missing { "redirect without a location" } else { "too many redirects" }), "{err}");
            assert_eq!(seen.lock().unwrap().len(), if missing { 1 } else { 6 });
            assert_eq!(forbidden.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        }
        // From HTTPS, a hop to anything else is refused (`get` bails before requesting it), directly or after
        // an HTTPS hop; a plain-HTTP registry's redirects may stay plain.
        let base = "https://reg.example/v2/test/blobs/x";
        let refused = |url: &str, loc: &str| next_hop(base, url, loc, 1).unwrap_err().to_string();
        assert!(refused(base, &destination).contains("refusing a redirect from HTTPS"));
        let hop = next_hop(base, base, "//cdn.example/next", 0).unwrap();
        assert_eq!(hop, "https://cdn.example/next");
        assert!(refused(&hop, &destination).contains("refusing a redirect from HTTPS"));
        assert_eq!(next_hop("http://127.0.0.1:5000/v2/x", "http://127.0.0.1:5000/v2/x", &destination, 0).unwrap(), destination);
        // The fifth redirect is followed, the sixth is not.
        assert_eq!(next_hop(base, base, "/v2/test/5", 4).unwrap(), "https://reg.example/v2/test/5");
        assert!(next_hop(base, base, "/v2/test/6", 5).unwrap_err().to_string().contains("too many redirects"));
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
        let err = reg.authenticate(&format!("Bearer realm=\"http://{addr}/token\""), start + Duration::from_secs(10), true).unwrap_err().to_string();
        assert!(err.contains("HTTP 503") && err.contains("deadline"), "{err}");
        // The HTTP date got the 1 s backoff.
        assert!(start.elapsed() >= Duration::from_secs(1) && calls.load(Ordering::SeqCst) == 2);
        reg.authenticate(&format!("Bearer realm=\"http://{addr}/token\""), Instant::now() + Duration::from_secs(10), true).unwrap();
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
            let err = public.authenticate(&format!("Bearer realm=\"{realm}\""), deadline, public.local()).unwrap_err().to_string();
            assert!(err.contains("not on a public address"), "{realm}: {err}");
        }
        let err = public.authenticate("Bearer realm=\"http://auth.example/t\"", deadline, false).unwrap_err().to_string();
        assert!(err.contains("not HTTPS"), "{err}");
        assert!(!served.load(std::sync::atomic::Ordering::SeqCst));
        // A local registry may use a local token service.
        let reg = Registry::new(Reference::parse(&format!("{local}/test")).unwrap());
        reg.authenticate(&format!("Bearer realm=\"http://{local}/t\""), deadline, reg.local()).unwrap();
        assert!(served.load(std::sync::atomic::Ordering::SeqCst));

        // Local as written; a name is local only by the address it answers from (`registries_are_local_by_their_peer`).
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
