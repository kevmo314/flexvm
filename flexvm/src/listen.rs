//! The peer listener (`flexvm listen`): a stateless, restartable helper
//! (socket-activatable) that serves only configured peers. Each connection
//! starts with one JSON line, consumed exactly through its newline so nothing after it is:
//! `template` (a migration's template, pushed before it), `migrate_in`, `pages` (handed to the source
//! VM process), `migration` (status/done), `route`, `lend`, `source` (source liveness).

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::host::{fault, Host};
use crate::util::{send_json, Result, Slot};

/// Requests handled at once; more connections are closed unanswered.
const MAX_ACTIVE: usize = 512;
const MAX_ACTIVE_FROM: usize = MAX_ACTIVE / 2;
static ACTIVE: std::sync::LazyLock<Waiting> = std::sync::LazyLock::new(|| Waiting::new(MAX_ACTIVE, MAX_ACTIVE_FROM));
/// Of those, requests that take the host lock (`route`, `lend`, `migration`); more are
/// refused as busy. The rest stay for requests that need none, page handoffs above all,
/// however long the lock's holder keeps it (a stalled disk, a stopped VM process).
const MAX_LOCKING: usize = MAX_ACTIVE * 3 / 4;
static LOCKING: AtomicUsize = AtomicUsize::new(0);
/// How long such a request waits for the host lock: its peer gives up on the call by then
/// (`vmproc::peer_call`), and asks again.
const LOCK_WAIT: Duration = Duration::from_secs(2);
/// What a request that took the host lock too long, or found no room, is answered.
pub(crate) const BUSY: &str = "host busy, try again";
/// Arrival processes from their start until they commit or are refused (or end), in all
/// and from any one peer address; more arrivals are refused at once, before their source
/// pauses anything.
const MAX_ARRIVALS: usize = 8;
const MAX_ARRIVALS_FROM: usize = MAX_ARRIVALS / 2;
static ARRIVALS: std::sync::LazyLock<Waiting> = std::sync::LazyLock::new(|| Waiting::new(MAX_ARRIVALS, MAX_ARRIVALS_FROM));
/// Templates being received (`template`) at once, in all and from any one peer; more are refused as
/// busy. Two arrivals of one template take turns (`template::turn`), the second without a slot while it
/// waits, and sends nothing: it finds the first's generation.
const MAX_PUSHES: usize = 4;
const MAX_PUSHES_FROM: usize = 2;
static PUSHES: std::sync::LazyLock<Waiting> = std::sync::LazyLock::new(|| Waiting::new(MAX_PUSHES, MAX_PUSHES_FROM));
/// Pushes waiting for their turn or receiving, in all and from any one peer; more are refused as busy, so
/// arrivals of one template waiting on a long receive keep no more of the listener's `MAX_ACTIVE` than this.
static PUSHERS: std::sync::LazyLock<Waiting> = std::sync::LazyLock::new(|| Waiting::new(2 * MAX_PUSHES, 2 * MAX_PUSHES_FROM));
/// How long a push waits for another arrival of its template to have received it (`template::turn`).
pub const TURN_WAIT: Duration = Duration::from_secs(600);
/// The pace a push's bytes keep (`util::Paced`), either way: `PUSH_GRACE`, then a second for every `PUSH_RATE`
/// bytes, so a 64 GiB template over 1 GbE fits as one that stalls does not hold its slot for long.
pub const PUSH_GRACE: Duration = Duration::from_secs(60);
pub const PUSH_RATE: u64 = 8 << 20;
/// Each of a push's answers is written within this.
pub const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// How long the generation stays open after the answer: until the arrival, whose request follows at once,
/// has opened it itself (`open_id`) or been refused.
const PUSH_HOLD: Duration = Duration::from_secs(REQUEST_DEADLINE.as_secs() + PREPARE_WAIT.as_secs());
/// An arrival is prepared, or refused, within this of its request's accept: well within
/// its source's preflight (`migrate::PREFLIGHT_TIMEOUT`, 10 s from before it connects).
pub const PREPARE_WAIT: Duration = Duration::from_secs(7);

fn monotonic_ms() -> u64 {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1_000_000
}

/// When an arrival's preparation must be done: `PREPARE_WAIT` after the listener accepted
/// its request (`FLEXVM_INCOMING_BY`, monotonic milliseconds), else after now.
pub fn prepare_by() -> Instant {
    match std::env::var("FLEXVM_INCOMING_BY").ok().and_then(|v| v.parse::<u64>().ok()) {
        Some(by) => Instant::now() + Duration::from_millis(by.saturating_sub(monotonic_ms())),
        None => Instant::now() + PREPARE_WAIT,
    }
}
/// Unknown addresses held while a peer's name with no addresses yet is
/// looked up, in all and from any one address (a peer's restart backlog can
/// hold a few of its requests); more are refused at once. One source cannot
/// take them all; many at once still can, each for `ADMIT_WAIT`.
const MAX_WAITING: usize = 64;
const MAX_WAITING_FROM: usize = 4;
/// Unknown addresses held while a name that has addresses is looked up again
/// (a peer by name may be back on a new one, #311): a budget of its own, so
/// non-peers, which always find such a lookup to wait for, never take the
/// one above. A peer they keep out is still looked up at once, and gets in
/// on its sender's retry (`vmproc::tell`).
const MAX_MOVED: usize = 4;
const MAX_MOVED_FROM: usize = 1;

#[derive(Clone)]
struct Waiting {
    held: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max: usize,
    max_from: usize,
}

struct Wait(Waiting, IpAddr);

impl Waiting {
    fn new(max: usize, max_from: usize) -> Waiting {
        Waiting { held: Arc::default(), max, max_from }
    }

    fn take(&self, from: IpAddr) -> Option<Wait> {
        self.take_besides(from, &HashMap::new())
    }

    /// Counting `others` too: held elsewhere, by address.
    fn take_besides(&self, from: IpAddr, others: &HashMap<IpAddr, usize>) -> Option<Wait> {
        let from = from.to_canonical();
        let mut w = self.held.lock().unwrap();
        let of = |m: &HashMap<IpAddr, usize>| m.get(&from).copied().unwrap_or(0);
        let total = w.values().sum::<usize>() + others.values().sum::<usize>();
        if total >= self.max || of(&w) + of(others) >= self.max_from {
            return None;
        }
        *w.entry(from).or_default() += 1;
        Some(Wait(self.clone(), from))
    }
}

impl Drop for Wait {
    fn drop(&mut self) {
        let mut w = self.0.held.lock().unwrap();
        if let Some(n) = w.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                w.remove(&self.1);
            }
        }
    }
}

/// Each of `listeners` (a name's addresses each have one) must be reachable as advertised.
pub fn validate(listeners: &[TcpListener], cfg: &crate::host::Config) -> Result<Cached> {
    // Bounded: this runs under the host lock. Seeds `PEER_CACHE` before the advertised
    // address is derived from it (a wildcard listener's underlay): at a first start or
    // after a boot, nothing else has looked the peers up yet.
    let by = Instant::now() + Duration::from_secs(2);
    let found: Vec<Option<Vec<IpAddr>>> = cfg.peers.iter().map(|p| crate::util::resolve(p, by).ok().map(|a| a.iter().map(SocketAddr::ip).collect())).collect();
    if let Some(run) = &cfg.run {
        let mut c = Cached::read(run, &cfg.peers);
        c.names.retain(|n, _| cfg.peers.contains(n));
        for (n, a) in cfg.peers.iter().zip(&found).filter(|(n, _)| n.parse::<SocketAddr>().is_err()) {
            match a {
                Some(a) => drop(c.names.insert(n.clone(), a.clone())),
                // One that failed keeps what it had, else has none.
                None => {
                    c.names.entry(n.clone()).or_default();
                }
            }
        }
        c.write(&run.join(PEER_CACHE));
    }
    // Under the host lock: from what was just seeded, never a lookup.
    let advertised = cfg.advertise_by(false)?;
    let toward =
        || crate::host::toward(&found.iter().map(|a| a.clone().unwrap_or_default()).collect::<Vec<_>>(), |a| crate::net::is_local_addr(a).unwrap_or(false));
    for listener in listeners {
        let local = listener.local_addr()?;
        if let Some(e) = unreachable_at(local, v6only(listener), advertised.as_deref()) {
            bail!("{e}");
        }
        if let Some(e) = loopback_with_remote(local, toward) {
            bail!("{e}");
        }
    }
    Ok(Cached { names: cfg.peers.iter().cloned().zip(found).filter_map(|(n, a)| a.map(|a| (n, a))).collect() })
}

/// A loopback listener is reachable, and a loopback underlay usable, only by peers on this machine.
fn loopback_with_remote(local: SocketAddr, toward: impl FnOnce() -> crate::host::Toward) -> Option<String> {
    if !local.ip().to_canonical().is_loopback() {
        return None;
    }
    let crate::host::Toward::Remote(peer) = toward() else { return None };
    Some(format!("{local} is loopback, but peer {peer} is elsewhere and cannot reach it; listen on 0.0.0.0 or this host's address toward it"))
}

pub fn main(host: Host, listeners: Vec<TcpListener>, validated: Cached) -> Result<()> {
    crate::net::ip_forward()?;
    let dev = host.cfg.announce_dev();
    if let Some(dev) = &dev {
        let _ = crate::net::proxy_arp(dev);
    }
    let underlay = host.cfg.underlay().map_or("none".into(), |u| u.to_string());
    let at = listeners.iter().map(|l| l.local_addr().map(|a| a.to_string())).collect::<std::io::Result<Vec<_>>>()?.join(", ");
    crate::info!("flexvm listening on {at} (underlay {underlay}, announce device {})", dev.as_deref().unwrap_or("none"));
    // A sweep and a refill now, not after the first period: a listener started at boot is
    // what recovers a quiet host (#555).
    let first = host.clone();
    std::thread::spawn(move || {
        // What receives killed with an earlier listener left (#823): its fallocated blocks count against the next push's room.
        if let Err(e) = crate::template::sweep_leftovers(&crate::template::Paths::new(&first.state)) {
            crate::log!("flexvm: sweeping the templates directory: {e}");
        }
        match crate::gc::after_boot(&first, true) {
            Ok(false) => crate::gc::recover(&first),
            Err(e) => crate::log!("flexvm: recovering after boot: {e}"),
            Ok(true) => {}
        }
    });
    crate::standby::maintain(host.clone());
    crate::gc::periodic(host.clone());
    let peers = Peers::watch(host.clone(), validated);
    let (waits, moved) = (Waiting::new(MAX_WAITING, MAX_WAITING_FROM), Waiting::new(MAX_MOVED, MAX_MOVED_FROM));
    let host = std::sync::Arc::new(host);
    let mut listeners = listeners.into_iter();
    let first = listeners.next().ok_or("no listening socket")?;
    // A name's other addresses: the same admission, slots and waits as the first.
    for l in listeners {
        let (host, peers, waits, moved) = (host.clone(), peers.clone(), waits.clone(), moved.clone());
        std::thread::Builder::new().name("accept".into()).spawn(move || accept(&l, &host, &peers, &waits, &moved))?;
    }
    accept(&first, &host, &peers, &waits, &moved);
    Ok(())
}

fn accept(listener: &TcpListener, host: &Arc<Host>, peers: &Peers, waits: &Waiting, moved: &Waiting) {
    for conn in listener.incoming() {
        // Everything a request does before it is read, checking its peer
        // included, counts against its deadline.
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let conn = match conn {
            Ok(c) => c,
            Err(e) => {
                crate::util::accept_failed("peer listener", &e);
                continue;
            }
        };
        let Ok(from) = conn.peer_addr().map(|a| a.ip()) else { continue };
        // Refused here, at once, unless a configured name is still being
        // looked up, or not looked up lately (it is then): it may be this
        // one's, and a bounded few wait for it (a peer's restart backlog, a
        // peer just added, a peer by name back on a new address).
        let waiting = match peers.check(&host.config_now().peers, from) {
            Admission::Peer => {
                let Some(slot) = ACTIVE.take(from) else { continue };
                let (host, peers) = (Arc::clone(host), peers.clone());
                spawn_request(std::thread::Builder::new(), move || serve(&host, &peers, conn, slot, deadline));
                continue;
            }
            Admission::Refused => None,
            Admission::Unresolved => waits.take(from),
            Admission::Moved => moved.take(from),
        };
        let Some(waiting) = waiting else {
            not_a_peer(conn, from);
            continue;
        };
        let (host, peers) = (Arc::clone(host), peers.clone());
        spawn_request(std::thread::Builder::new(), move || {
            let admitted = peers.admit_by(&host, from, Instant::now() + ADMIT_WAIT);
            drop(waiting);
            match admitted.then(|| ACTIVE.take(from)).flatten() {
                Some(slot) => serve(&host, &peers, conn, slot, deadline),
                None if !admitted => not_a_peer(conn, from),
                None => {}
            }
        });
    }
}

fn spawn_request(builder: std::thread::Builder, work: impl FnOnce() + Send + 'static) {
    // A failed spawn drops the closure, closing its connection and releasing its slot.
    if let Err(e) = builder.spawn(work) {
        log_refusal(format_args!("cannot start request worker: {e}"));
    }
}

fn serve(host: &Host, peers: &Peers, conn: TcpStream, _slot: Wait, deadline: Instant) {
    let _ = conn.set_nodelay(true);
    if let Err(e) = handle(host, peers, conn, deadline, &LOCKING) {
        log_refusal(e);
    }
}

pub fn v6only(l: &TcpListener) -> bool {
    let (mut v, mut len) = (0i32, std::mem::size_of::<i32>() as libc::socklen_t);
    let r = unsafe { libc::getsockopt(l.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &mut v as *mut i32 as *mut libc::c_void, &mut len) };
    r == 0 && v != 0
}

/// Why peers cannot reach a listener bound at `local` through the endpoint
/// it advertises: an IPv6 socket takes IPv4 connections only bound to the
/// wildcard without IPV6_V6ONLY (net.ipv6.bindv6only), or to a mapped address.
fn unreachable_at(local: SocketAddr, v6only: bool, advertised: Option<&str>) -> Option<String> {
    let v4 = advertised.and_then(|a| a.parse::<SocketAddr>().ok()).is_some_and(|a| a.is_ipv4());
    let takes_v4 = local.ip().to_canonical().is_ipv4() || (local.ip().is_unspecified() && !v6only);
    (v4 && !takes_v4).then(|| {
        format!(
            "{local} takes no IPv4 connections, but peers are told to reach this host at {}; listen on 0.0.0.0, a dual-stack [::] or the underlay address",
            advertised.unwrap_or_default()
        )
    })
}

/// Peers are compared by address, an IPv4 one also as it arrives on a
/// dual-stack socket (::ffff:a.b.c.d).
fn is_peer(peers: &[IpAddr], from: IpAddr) -> bool {
    peers.iter().any(|a| a.to_canonical() == from.to_canonical())
}

/// What `Peers::check` makes of an address.
#[derive(Debug, PartialEq)]
enum Admission {
    Peer,
    Refused,
    /// May be a peer whose name has no addresses yet: its lookup is under way.
    Unresolved,
    /// May be a peer by name now elsewhere: a name with addresses is being looked up again.
    Moved,
}

/// The configured peers' addresses. Names are resolved off the accept loop,
/// each by a thread of its own (at most one per name, so one hung lookup holds
/// up no other), published as each finishes: at start, every `PEER_REFRESH`,
/// and when a request finds a name it has no addresses for, but at most every
/// `LOOKUP_EVERY` per name; a name that fails to resolve keeps the addresses it
/// last had. Requests go by host.json as it is now: an address given as such needs no lookup, and
/// a name no longer configured counts for nothing, whatever a refresh still
/// holds for it.
#[derive(Clone, Default)]
struct Peers(Arc<PeersInner>);

#[derive(Default)]
struct PeersInner {
    resolved: RwLock<HashMap<String, Vec<IpAddr>>>,
    /// Each name's lookup: None while under way, else when the last one ended.
    lookups: Mutex<HashMap<String, Option<Instant>>>,
    /// The listener's: where each name's last-known addresses are kept for other processes
    /// (`PEER_CACHE` in RUN), with what was last written there.
    cache: Option<(std::path::PathBuf, Mutex<Cached>)>,
}

/// `RUN/peers.json`: {name: [address, ...]}, each peer name the listener looked up with its
/// last-known addresses (none for one that never resolved), for restores, resumes and
/// underlay/announce-device derivation in other processes.
///
/// Who asks decides how fresh peer addresses must be. A peer is the attacker #549 guards
/// against: what a peer asks for (arrival, route, lend) is checked by the listener against
/// its own lookups, waiting briefly for any under way on a peer name (cached addresses or not)
/// and refused after. Restore and resume are root's own: they go by this file whatever its age,
/// never waiting on DNS, and are refused at once only for a name it has no entry for (no
/// listener looked it up yet). A peer whose name moved since is not caught there.
const PEER_CACHE: &str = "peers.json";

#[derive(Clone, Default, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Cached {
    names: HashMap<String, Vec<IpAddr>>,
}

const PEER_REFRESH: Duration = Duration::from_secs(30);
const LOOKUP_EVERY: Duration = Duration::from_secs(2);
/// How long an unknown address waits for a lookup under way, well within a
/// peer's deadline for its call (`vmproc::peer_call`).
const ADMIT_WAIT: Duration = Duration::from_millis(1500);

impl Peers {
    /// Admission starts with this validation's lookups; the disk cache also keeps earlier ones.
    fn listener(host: &Host, validated: Cached) -> Peers {
        let cache = Some((host.run.join(PEER_CACHE), Mutex::new(Cached::read(&host.run, &host.config_now().peers))));
        Peers(Arc::new(PeersInner { resolved: RwLock::new(validated.names), cache, ..Default::default() }))
    }

    fn watch(host: Host, validated: Cached) -> Peers {
        let peers = Peers::listener(&host, validated);
        let p = peers.clone();
        std::thread::spawn(move || loop {
            let names = host.config_now().peers;
            p.0.resolved.write().unwrap().retain(|n, _| names.contains(n));
            p.0.lookups.lock().unwrap().retain(|n, l| l.is_none() || names.contains(n));
            p.cache(|c| c.names.retain(|n, _| names.contains(n)));
            p.refresh(&names);
            std::thread::sleep(PEER_REFRESH);
        });
        peers
    }

    /// Starts a lookup of each name that has none under way nor one ended
    /// within `LOOKUP_EVERY`; never waits on one.
    fn refresh<'a>(&self, names: impl IntoIterator<Item = &'a String>) {
        let names: Vec<&String> = names.into_iter().filter(|n| n.parse::<SocketAddr>().is_err()).collect();
        // A new name gets an empty entry before its lookup starts: other processes then never
        // look up one this listener knows of (`Config::derived`), however long its lookup takes.
        self.cache_missing(&names);
        let mut lookups = self.0.lookups.lock().unwrap();
        for n in names {
            if lookups.get(n).is_some_and(|l| l.is_none_or(|t| t.elapsed() < LOOKUP_EVERY)) {
                continue;
            }
            let (p, name) = (self.clone(), n.clone());
            let lookup = std::thread::Builder::new().spawn(move || {
                let found = crate::util::lookup(&name).ok().map(|a| a.iter().map(|a| a.ip()).collect::<Vec<_>>());
                if let Some(a) = &found {
                    p.0.resolved.write().unwrap().insert(name.clone(), a.clone());
                }
                // For restores and resumes (`known_peers`): one that failed keeps what it had, else has none.
                p.cache(|c| match found {
                    Some(a) => drop(c.names.insert(name.clone(), a)),
                    None => {
                        c.names.entry(name.clone()).or_default();
                    }
                });
                p.0.lookups.lock().unwrap().insert(name, Some(Instant::now()));
            });
            lookups.insert(n.clone(), if lookup.is_ok() { None } else { Some(Instant::now()) });
        }
    }

    /// An empty entry for each of `names` the listener's cache has none for, written only if any.
    fn cache_missing(&self, names: &[&String]) {
        let Some((_, cached)) = &self.0.cache else { return };
        if names.iter().all(|n| cached.lock().unwrap().names.contains_key(*n)) {
            return;
        }
        self.cache(|c| {
            for n in names {
                c.names.entry((*n).clone()).or_default();
            }
        });
    }

    /// Changes the listener's cache and writes it to RUN. One that cannot be written is
    /// removed, never left to answer for addresses since changed: restores are refused until
    /// it is written again.
    fn cache(&self, change: impl FnOnce(&mut Cached)) {
        let Some((path, cached)) = &self.0.cache else { return };
        let mut c = cached.lock().unwrap();
        change(&mut c);
        c.write(path);
    }

    /// The asking peer's confirmed addresses: `from`, and those of each configured peer it is one of
    /// (as `all_addrs` just waited for), with that peer's configured underlays.
    fn sender(&self, cfg: &crate::host::Config, from: IpAddr) -> Vec<IpAddr> {
        let r = self.0.resolved.read().unwrap();
        let mut out = vec![from];
        for n in &cfg.peers {
            let addrs = n.parse::<SocketAddr>().map_or_else(|_| r.get(n).cloned().unwrap_or_default(), |a| vec![a.ip()]);
            if is_peer(&addrs, from) || cfg.underlays_of(n).iter().any(|&u| IpAddr::V4(u) == from.to_canonical()) {
                out.extend(addrs);
                out.extend(cfg.underlays_of(n).iter().map(|&u| IpAddr::V4(u)));
            }
        }
        out
    }

    /// The configured peer `from` is one of (`sender`), else `from` itself: who a loan is to.
    fn borrower(&self, cfg: &crate::host::Config, from: IpAddr) -> String {
        let r = self.0.resolved.read().unwrap();
        cfg.peers
            .iter()
            .find(|n| {
                let addrs = n.parse::<SocketAddr>().map_or_else(|_| r.get(*n).cloned().unwrap_or_default(), |a| vec![a.ip()]);
                is_peer(&addrs, from) || cfg.underlays_of(n).iter().any(|&u| IpAddr::V4(u) == from.to_canonical())
            })
            .cloned()
            .unwrap_or_else(|| from.to_canonical().to_string())
    }

    /// The addresses of `names`; a name not resolved yet is looked up.
    fn addrs(&self, names: &[String]) -> Vec<IpAddr> {
        let r = self.0.resolved.read().unwrap();
        let mut addrs = Vec::new();
        let mut missing = Vec::new();
        for n in names {
            match (n.parse::<SocketAddr>(), r.get(n)) {
                (Ok(a), _) => addrs.push(a.ip()),
                (_, Some(a)) => addrs.extend(a),
                _ => missing.push(n),
            }
        }
        drop(r);
        self.refresh(missing);
        addrs
    }

    /// `addrs` once no name has its lookup under way (it could give any address, a name with
    /// addresses a new one too), waiting for one until `by`, then an error: asked again, it may
    /// have ended. A lookup that ended with none (a name that does not resolve) gives none (#411).
    fn all_addrs(&self, names: &[String], by: Instant) -> Result<Vec<IpAddr>> {
        loop {
            // Starts a lookup of a name with none; then addresses and lookups under way read
            // together, so one that publishes meanwhile is either in the addresses or waited for.
            self.addrs(names);
            let (addrs, pending) = {
                let (r, l) = (self.0.resolved.read().unwrap(), self.0.lookups.lock().unwrap());
                let mut addrs = Vec::new();
                let mut pending = false;
                for n in names {
                    match n.parse::<SocketAddr>() {
                        Ok(a) => addrs.push(a.ip()),
                        Err(_) => {
                            addrs.extend(r.get(n).into_iter().flatten());
                            pending |= l.get(n) == Some(&None);
                        }
                    }
                }
                (addrs, pending)
            };
            if !pending {
                return Ok(addrs);
            }
            if Instant::now() >= by {
                bail!("a peer's name is still being looked up; try again");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn admit(&self, names: &[String], from: IpAddr) -> bool {
        is_peer(&self.addrs(names), from)
    }

    /// Whether a name in `names` with no addresses yet has its lookup under
    /// way, and whether one with addresses has.
    fn resolving(&self, names: &[String]) -> (bool, bool) {
        let (r, l) = (self.0.resolved.read().unwrap(), self.0.lookups.lock().unwrap());
        let under_way = |cached: bool| names.iter().any(|n| r.contains_key(n) == cached && l.get(n) == Some(&None));
        (under_way(false), under_way(true))
    }

    /// Whether `from` is a peer, or may yet be. One it would refuse looks
    /// again for any name not looked up within `LOOKUP_EVERY`: a peer by name
    /// may be back on a new address (DHCP), which would otherwise wait for
    /// `PEER_REFRESH` (#311).
    fn check(&self, names: &[String], from: IpAddr) -> Admission {
        if self.admit(names, from) {
            return Admission::Peer;
        }
        self.refresh(names);
        match self.resolving(names) {
            (true, _) => Admission::Unresolved,
            (_, true) => Admission::Moved,
            // A lookup that ended since may have given its address.
            _ if self.admit(names, from) => Admission::Peer,
            _ => Admission::Refused,
        }
    }

    /// Admits `from` once a lookup under way gives its address, or refuses it
    /// when none is left under way, or at `by`.
    fn admit_by(&self, host: &Host, from: IpAddr, by: Instant) -> bool {
        loop {
            match self.check(&host.config_now().peers, from) {
                Admission::Peer => return true,
                Admission::Refused => return false,
                _ if Instant::now() >= by => return false,
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}

fn not_a_peer(conn: TcpStream, from: IpAddr) {
    let local = conn.local_addr().map(|a| a.to_string()).unwrap_or_default();
    let e = format!("{from} is not a peer of {local} (add it to peers in that host's host.json)");
    log_refusal(&e);
    refuse(conn, &e, None);
}

/// All request refusals share a budget, including those from configured peers.
fn log_refusal(e: impl std::fmt::Display) {
    static WINDOW: Mutex<RefusalLog> = Mutex::new(RefusalLog { second: 0, logged: 0, unlogged: 0 });
    let second = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let line = WINDOW.lock().unwrap_or_else(|p| p.into_inner()).line(second, e);
    if let Some(line) = line {
        crate::log!("{line}");
    }
}

/// Refusals logged at most in any one second.
const REFUSALS_LOGGED: u32 = 10;

/// This second's refusal lines, and the refusals not logged since the last line.
struct RefusalLog {
    second: u64,
    logged: u32,
    unlogged: u64,
}

impl RefusalLog {
    fn line(&mut self, second: u64, e: impl std::fmt::Display) -> Option<String> {
        self.take(second).map(|n| match n {
            0 => format!("peer request: {e}"),
            n => format!("peer request: {e} ({n} refusals before it not logged)"),
        })
    }

    /// Whether a refusal in `second` is logged, with how many were not since the last that was.
    fn take(&mut self, second: u64) -> Option<u64> {
        if self.second != second {
            (self.second, self.logged) = (second, 0);
        }
        if self.logged >= REFUSALS_LOGGED {
            self.unlogged += 1;
            return None;
        }
        self.logged += 1;
        Some(std::mem::take(&mut self.unlogged))
    }
}

/// Tells the client why, then reads off what it already sent so the close
/// does not reset the reply away: until `wait` from now in all, however the
/// client trickles (#352), or with none only what has arrived, never waiting
/// on the client.
pub fn refuse(conn: TcpStream, why: &str, wait: Option<Duration>) {
    let mut c = crate::util::By { s: &conn, at: Instant::now() + wait.unwrap_or_default() };
    if wait.is_none() && conn.set_nonblocking(true).is_err() {
        return;
    }
    let reply = json!({"ok": false, "error": why});
    let _ = match wait {
        Some(_) => send_json(&mut c, &reply),
        None => send_json(&mut &conn, &reply),
    };
    let _ = conn.shutdown(std::net::Shutdown::Write);
    let _ = match wait {
        Some(_) => std::io::copy(&mut c.take(1 << 20), &mut std::io::sink()),
        None => std::io::copy(&mut (&conn).take(1 << 20), &mut std::io::sink()),
    };
}

pub fn activated() -> Option<TcpListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let n: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    // Close-on-exec: no child it starts inherits it (#386).
    (pid == std::process::id() && n >= 1 && unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } == 0).then(|| unsafe { TcpListener::from_raw_fd(3) })
}

/// From a peer: they are authenticated by address only (`main`), the network between them is trusted.
fn handle(host: &Host, peers: &Peers, mut conn: TcpStream, deadline: Instant, locking: &'static AtomicUsize) -> Result<()> {
    let line = read_line_by(&conn, deadline)?;
    let req: Value = serde_json::from_slice(&line)?;
    let op = req["op"].as_str().unwrap_or("");
    let locking = matches!(op, "migration" | "route" | "lend").then(|| Slot::take(locking, MAX_LOCKING));
    let reply = match op {
        // Checked by the arrival (`check_vm_ip`) against these, as route and lend are: a name
        // with no addresses yet, its lookup under way (a peer just added), is waited for.
        "migrate_in" => {
            let by = deadline - REQUEST_DEADLINE + PREPARE_WAIT;
            return match peers.all_addrs(&host.config_now().peers, Instant::now() + ADMIT_WAIT) {
                Ok(peers) => incoming(host, &req, &line, conn, by, &peers),
                Err(e) => send_json(&mut conn, &json!({"ok": false, "error": e.to_string()})).map_err(Into::into),
            };
        }
        "pages" => return pages(host, &req, conn),
        "template" => return push(host, &req, conn),
        _ if matches!(locking, Some(None)) => Err(BUSY.into()),
        "migration" => (|| {
            if req["done"] != true {
                return migration(host, &req, |_, _| false);
            }
            let cfg = host.config_now();
            let from = conn.peer_addr()?.ip();
            // Names resolved first; one still being looked up only leaves its addresses out.
            let _ = peers.all_addrs(&cfg.peers, Instant::now() + ADMIT_WAIT);
            let (sender, name) = (peers.sender(&cfg, from), peers.borrower(&cfg, from));
            // The peer it came from by any of its addresses (a record from before they were kept has
            // none), or the one its source named itself as: it may have resolved elsewhere since.
            migration(host, &req, |source, peer| {
                peer.is_some_and(|p| is_peer(&sender, p)) || source == name || source.parse::<SocketAddr>().is_ok_and(|a| is_peer(&sender, a.ip()))
            })
        })(),
        // Its peers by address, those configured by name too, and the one asking.
        // And their configured underlays; a withdrawal goes by the asking peer's own (`Peers::sender`).
        "route" => {
            let (cfg, from) = (host.config_now(), conn.peer_addr().ok().map(|a| a.ip()));
            peers.all_addrs(&cfg.peers, Instant::now() + ADMIT_WAIT).and_then(|mut all| {
                all.extend(from);
                all.extend(cfg.peer_underlay_addrs());
                route(host, &req, &all, &from.map(|f| peers.sender(&cfg, f)).unwrap_or_default())
            })
        }
        "lend" => (|| {
            let cfg = host.config_now();
            let from = conn.peer_addr()?.ip();
            let mut all = peers.all_addrs(&cfg.peers, Instant::now() + ADMIT_WAIT)?;
            all.push(from);
            lend(host, &req, &all, &peers.borrower(&cfg, from))
        })(),
        // Whether a migration's source process is proven gone (never from published state).
        "source" => serde_json::from_value(req["ident"].clone())
            .map_err(|e| format!("bad ident: {e}").into())
            // One whose migration's outcome this host still owes counts as there: its target keeps the record it will ask about.
            .map(|id: crate::host::Ident| json!({"gone": id.liveness() == crate::host::Liveness::Gone && !host.owes(&id)})),
        op => Err(format!("unknown op {op:?}").into()),
    };
    let reply = crate::util::reply(&reply);
    send_json(&mut conn, &reply)?;
    Ok(())
}

/// The whole request line must arrive within this, however it trickles in.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
const MAX_LINE: usize = 64 << 10;

/// Peeks in chunks and consumes exactly through the newline: whatever
/// follows stays in the socket for whoever gets the connection next. Each
/// wait gets only what is left until `deadline`.
fn read_line_by(conn: &TcpStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut buf = [0u8; 4096];
    while line.len() < MAX_LINE {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            bail!("request line not received in time");
        }
        conn.set_read_timeout(Some(left))?;
        let want = buf.len().min(MAX_LINE + 1 - line.len());
        let n = match conn.peek(&mut buf[..want]) {
            Ok(0) => bail!("peer hung up"),
            Ok(n) => n,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                bail!("request line not received in time")
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        let (take, done) = match buf[..n].iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (n, false),
        };
        // Already queued, so this does not wait.
        (&*conn).read_exact(&mut buf[..take])?;
        line.extend_from_slice(&buf[..take - done as usize]);
        if done {
            conn.set_read_timeout(None)?;
            return Ok(line);
        }
    }
    bail!("request line too long")
}

/// Spawns the incoming VM process with the connection as fd 3; it answers the source. Its
/// arrival slot is held, by the shared reaper, until it says it committed or was refused
/// (on its fd 4, `FLEXVM_NOTIFY_FD`) or it ends.
fn incoming(host: &Host, req: &Value, line: &[u8], conn: TcpStream, by: Instant, peers: &[IpAddr]) -> Result<()> {
    let name = req["name"].as_str().unwrap_or("");
    let refuse = |mut c: &TcpStream, e: String| send_json(&mut c, &json!({"ok": false, "error": e}));
    if let Err(e) = crate::host::check_name(name) {
        refuse(&conn, e.to_string())?;
        return Ok(());
    }
    // Refused before anything is made: the source has paused nothing yet, and its VM runs on.
    // Arrivals an earlier listener started (they outlive it) count too.
    let from = conn.peer_addr()?.ip().to_canonical();
    let Some(slot) = ARRIVALS.take_besides(from, &earlier_arrivals(host)) else {
        let why = format!("too many migrations are arriving here already (at most {MAX_ARRIVALS}, {MAX_ARRIVALS_FROM} from one peer); try again later");
        refuse(&conn, why)?;
        return Ok(());
    };
    if let Err(e) = crate::util::start_reaper() {
        refuse(&conn, format!("cannot start the vm process: {e}"))?;
        return Ok(());
    }
    // Each arrival owns its log until accepted; refusing a duplicate name
    // must not remove the running VM's log.
    static ARRIVAL: AtomicUsize = AtomicUsize::new(0);
    // Its lock (`RUN/vms/.locks/` and the log's name), made before the log, is held
    // until the arrival publishes or removes its log (its fd 5 shares it), so a dead
    // arrival's log is told from a live one's and swept (`gc`), and a later listener
    // counts it, by its peer (`earlier_arrivals`).
    let n = ARRIVAL.fetch_add(1, Ordering::Relaxed);
    let file = format!("{}{}-{n}-{from}.log", crate::gc::ARRIVAL_LOG, std::process::id());
    let vms = host.run.join("vms");
    let (log_path, lock_path) = (vms.join(&file), crate::host::locks(&vms).join(&file));
    // Retried until the file locked is the path's: a sweep may remove a lock with no log yet
    // (`gc::orphan_log_locks`) between its creation and the flock.
    let lock = crate::host::lock_path(&lock_path, libc::LOCK_SH)?;
    let log = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().create_new(true).append(true).mode(0o600).open(&log_path).inspect_err(|_| drop(std::fs::remove_file(&lock_path)))?
    };
    let args = ["--state".as_ref(), host.state.as_os_str(), "--run".as_ref(), host.run.as_os_str(), "run".as_ref(), "--incoming".as_ref()];
    let (done, told) = std::os::unix::net::UnixStream::pair()?;
    let by = (monotonic_ms() + by.saturating_duration_since(Instant::now()).as_millis() as u64).to_string();
    let peers = serde_json::to_string(peers)?;
    let spawned = crate::util::spawn_self_child(
        &args,
        &log,
        conn.as_raw_fd(),
        Some(told.as_raw_fd()),
        Some(lock.as_raw_fd()),
        &[
            ("FLEXVM_INCOMING", std::str::from_utf8(line)?),
            ("FLEXVM_INCOMING_LOG", log_path.to_str().ok_or("non-UTF8 log path")?),
            ("FLEXVM_NOTIFY_FD", "4"),
            ("FLEXVM_INCOMING_BY", &by),
            ("FLEXVM_INCOMING_PEERS", &peers),
        ],
    );
    drop(told);
    match spawned {
        Ok(child) => crate::util::reap_later(child, Some((done.into(), Box::new(slot)))),
        Err(e) => {
            let _ = std::fs::remove_file(log_path);
            let _ = std::fs::remove_file(lock_path);
            refuse(&conn, format!("cannot start the vm process: {e}"))?;
        }
    }
    Ok(())
}

/// Live arrivals that other listener processes started (an earlier one, before a
/// restart), by peer: their `.incoming-LPID-N-PEER.log` files, each locked for its
/// arrival's life. One with no peer in its name counts toward the total only.
fn earlier_arrivals(host: &Host) -> HashMap<IpAddr, usize> {
    let me = std::process::id().to_string();
    let mut n = HashMap::new();
    for e in std::fs::read_dir(crate::host::locks(&host.run.join("vms"))).into_iter().flatten().flatten() {
        let name = e.file_name();
        let Some(rest) = name.to_str().and_then(|f| f.strip_prefix(crate::gc::ARRIVAL_LOG)?.strip_suffix(".log")) else { continue };
        let mut parts = rest.splitn(3, '-');
        if parts.next() == Some(me.as_str()) || crate::util::locked(&e.path(), libc::LOCK_EX) != Some(true) {
            continue;
        }
        let peer = parts.nth(1).and_then(|p| p.parse::<IpAddr>().ok()).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        *n.entry(peer.to_canonical()).or_default() += 1;
    }
    n
}

/// Publish only an accepted arrival's log. A refused arrival owns only its
/// temporary file, even when the requested name already belongs to a VM.
/// Its lock goes with it: held, it is the caller's to let go of then.
pub fn finish_incoming_log(host: &Host, name: &str, log: &std::path::Path, accepted: bool) -> Result<()> {
    if accepted {
        let _logs = host.logs_lock(libc::LOCK_SH)?;
        let _ = std::fs::remove_file(host.vms(name, "log.1")?);
        std::fs::rename(log, host.vms(name, "log")?)?;
    } else {
        std::fs::remove_file(log)?;
    }
    if let Some(file) = log.file_name() {
        let _ = std::fs::remove_file(crate::host::locks(&host.run.join("vms")).join(file));
    }
    Ok(())
}

fn pages(host: &Host, req: &Value, conn: TcpStream) -> Result<()> {
    let name = req["name"].as_str().unwrap_or("");
    let fwd = json!({"op": "pages", "mig": req["mig"]});
    // Connected only to a valid name's socket in RUN/vms (`connect` checks it).
    if let Err(e) = crate::vmproc::connect(host, name, &fwd, &[conn.as_raw_fd()], Instant::now() + Duration::from_secs(5), None) {
        // The reason stays here: it tells what exists on this host.
        log_refusal(format_args!("migration {}: page request for {name:?} refused: {e}", req["mig"]));
        crate::vmproc::refuse_not_source(conn, name, &req["mig"]);
    }
    Ok(())
}

/// `template`: whether this host has generation `id` (by content id only: no name here counts), answered
/// `have`; if not, receiving it (`template::receive`), answered again once published. Both before the
/// source pauses anything. Either way it stays open for `PUSH_HOLD`, so nothing removes it before the arrival opens it.
/// One held already is answered at once, without a turn or a slot. With `have` set, only asked, and answered
/// `have` false if it is not here (a source's last check before its prepare, which refreshes the hold, #824). With
/// `ack` set, its metadata is answered too (`go`, or a refusal: room for its `bytes`, the limits, Firecracker)
/// before its source sends its data.
fn push(host: &Host, req: &Value, conn: TcpStream) -> Result<()> {
    let answer = |r: &Result<Value>| send_json(&mut crate::util::By { s: &conn, at: Instant::now() + ANSWER_WAIT }, &crate::util::reply(r));
    let (paths, id) = (crate::template::Paths::new(&host.state), req["id"].as_str().unwrap_or(""));
    let (only_ask, ack) = (req["have"] == true, req["ack"] == true);
    let held = || HELD.lock().unwrap().get(id).map(|h| h.0.clone());
    // A received one's digests, for the source to compare: its content id is no proof of its files.
    let have = |t: &crate::template::Template| json!({"have": true, "digests": t.meta.received.then_some(&t.meta.digests)});
    if let Some(tpl) = held() {
        hold(tpl.clone());
        answer(&Ok(have(&tpl)))?;
        return Ok(());
    }
    // Held to the end, through the drain after a refusal too: what a source sends is read off only within it.
    let (mut asked, mut waiting) = (false, None);
    let got = (|| -> Result<Option<Arc<crate::template::Template>>> {
        let _turn = match only_ask {
            true => None,
            false => {
                waiting = Some(PUSHERS.take(conn.peer_addr()?.ip()).ok_or(BUSY)?);
                Some(crate::template::turn(&paths, id, Instant::now() + TURN_WAIT)?)
            }
        };
        if let Some(tpl) = held() {
            return Ok(Some(tpl));
        }
        let _slot = PUSHES.take(conn.peer_addr()?.ip()).ok_or(BUSY)?;
        if let Some(dir) = crate::template::Template::generation(&paths, id) {
            return crate::template::Template::open_dir(id, dir).map(Some);
        }
        if only_ask {
            return Ok(None);
        }
        answer(&Ok(json!({"have": false, "ack": ack})))?;
        asked = true;
        let (in_use, held) = (|| host.template_users(), || HELD.lock().unwrap().keys().cloned().collect());
        let push = crate::template::Push { peer: conn.peer_addr()?.ip(), bytes: req["bytes"].as_u64(), in_use: &in_use, held: &held };
        let ready = |_: &crate::template::Meta| {
            if ack {
                answer(&Ok(json!({"go": true})))?;
            }
            Ok(())
        };
        let mut r = std::io::BufReader::with_capacity(1 << 20, crate::util::Paced::new(&conn, PUSH_GRACE, PUSH_RATE));
        push.receive(&paths, &mut r, id, ready).map(Some)
    })();
    match got {
        Ok(Some(tpl)) => {
            // Held (and so charged to its peer's budget, `template::Push`) before the source hears it is here.
            hold(tpl.clone());
            answer(&Ok(match asked {
                true => json!({"received": true, "digests": tpl.meta.digests}),
                false => have(&tpl),
            }))?;
        }
        Ok(None) => answer(&Ok(json!({"have": false})))?,
        Err(e) => {
            answer(&Err(e))?;
            // What the source still sends, so it reads the answer instead of a reset: only once it was asked for
            // data, and within its place among `PUSHERS`. One refused before sent nothing more.
            if asked && waiting.is_some() {
                let _ = conn.shutdown(std::net::Shutdown::Write);
                let _ = std::io::copy(&mut crate::util::By { s: &conn, at: Instant::now() + Duration::from_secs(30) }, &mut std::io::sink());
            }
        }
    }
    drop(waiting);
    Ok(())
}

/// Generations held for arrivals, by content id, until when: one hold (and thread) each, however often asked.
static HELD: Mutex<std::collections::BTreeMap<String, (Arc<crate::template::Template>, Instant)>> = Mutex::new(std::collections::BTreeMap::new());

/// Generations held at once at most: past it, an arrival's own `open_id` must come before any `rmi` does.
const MAX_HELD: usize = 16;

fn hold(tpl: Arc<crate::template::Template>) {
    let (id, mut held) = (tpl.meta.id.clone(), HELD.lock().unwrap());
    if held.len() >= MAX_HELD && !held.contains_key(&id) || held.insert(id.clone(), (tpl, Instant::now() + PUSH_HOLD)).is_some() {
        return;
    }
    drop(held);
    std::thread::spawn(move || loop {
        let mut held = HELD.lock().unwrap();
        let left = held[&id].1.saturating_duration_since(Instant::now());
        if left.is_zero() {
            held.remove(&id);
            return;
        }
        drop(held);
        std::thread::sleep(left);
    });
}

/// The host lock, waited for `LOCK_WAIT` at most: then refused as busy.
fn host_lock(host: &Host) -> Result<crate::host::Locked> {
    host.lock_by(Some(Instant::now() + LOCK_WAIT)).map_err(|e| match e.downcast_ref::<std::io::Error>().map(|e| e.kind()) {
        Some(std::io::ErrorKind::WouldBlock) => BUSY.into(),
        _ => e,
    })
}

fn migration(host: &Host, req: &Value, source: impl Fn(&str, Option<IpAddr>) -> bool) -> Result<Value> {
    if fault("status") {
        bail!("injected fault: migration status unavailable");
    }
    let mig = req["mig"].as_u64().ok_or("missing mig")?;
    // Held through `mig_done` or `mig_status`, which take it again (reentrant) without waiting.
    let _l = host_lock(host)?;
    if req["done"] == json!(true) {
        if host.mig_done_from(mig, source)? {
            crate::info!("migration {mig}: its source says done; forgetting it");
        }
        return Ok(json!({"done": true}));
    }
    let outcome = host.mig_status(mig)?;
    // Under the host lock: never a lookup.
    Ok(json!({"outcome": outcome, "underlay": host.config_now().underlay_known().map(|u| u.to_string())}))
}

fn lend(host: &Host, req: &Value, peers: &[IpAddr], borrower: &str) -> Result<Value> {
    let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
    routable(ip, &host.config_now(), peers, &crate::net::gateways(&std::fs::read_to_string("/proc/net/route")?))?;
    let l = host_lock(host)?;
    if req["start"] == true {
        let gen = req["gen"].as_u64().ok_or("missing gen")?;
        host.start_loan(&l, ip, gen, borrower)?;
        return Ok(json!({"ip": ip.to_string(), "gen": gen}));
    }
    let gen = host.lend_new(&l, ip, borrower, req["lease"] == true)?;
    Ok(json!({"ip": ip.to_string(), "gen": gen, "lease": req["lease"] == true}))
}

/// Stale generations and revisions (see `host::Addr`) are ignored; an
/// address a VM here holds keeps its local route.
/// Test fault `route_refuse`: refused, as by a listener that is down.
/// `sender`: the asking peer's own addresses; only the peer a generation is routed via withdraws it.
fn route(host: &Host, req: &Value, peers: &[IpAddr], sender: &[IpAddr]) -> Result<Value> {
    if fault("route_refuse") {
        bail!("injected fault: route messages refused");
    }
    let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
    let gen = req["gen"].as_u64().filter(|&g| g > 0).ok_or("route messages carry the address's generation")?;
    let via: Option<Ipv4Addr> = req["via"].as_str().map(|v| v.parse()).transpose()?;
    if let Some(via) = via {
        check_vm_ip(host, ip, peers)?;
        check_via(via, peers)?;
    }
    let rev = match via {
        Some(_) => req["rev"].as_u64().ok_or("route announcements carry the location's revision")?,
        None => 0,
    };
    // A withdrawal's: the latest revision of the generation its sender knows (none: 0).
    let withdrawn_rev = req["rev"].as_u64().unwrap_or(0);
    // Test hook: an announcement held up (as by a slow network) while armed; its answer is logged
    // once given, which is how a test knows the listener got to it.
    let held = via.filter(|_| fault("route_stall"));
    if let Some(via) = held {
        crate::log!("route {ip} via {via}: held up (injected fault)");
        while fault("route_stall") {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let answer = (|| {
        let l = host_lock(host)?;
        if via.is_none() {
            let a = host.addr(&l, ip)?;
            // A recorded generation remains withdrawable after the allowlist narrows, including retries.
            if a.seen == 0 {
                check_vm_ip(host, ip, peers)?;
            }
            // Not by another peer, unless it had the VM later: a newer generation, or a newer revision
            // (the VM migrated on to it and ended there before its announcement got here).
            if let Some(owner) = a.via.filter(|&o| gen == a.seen && !a.withdrawn && withdrawn_rev <= a.rev && !is_peer(sender, IpAddr::V4(o))) {
                bail!("{ip} generation {gen} is routed via {owner} at revision {}, not via the asking peer: only that peer, or one with a newer revision, withdraws it", a.rev);
            }
        }
        if !host.observe(&l, ip, gen, rev, via)? {
            return Ok(json!({"ip": ip.to_string(), "stale": true}));
        }
        let local = host.keeps_route(&l, ip, gen)?;
        if !local {
            match via {
                Some(via) => crate::net::route_via(ip, via)?,
                None => crate::net::unroute(ip),
            }
        }
        Ok(json!({"ip": ip.to_string(), "local": local}))
    })();
    if let Some(via) = held {
        let how = match &answer {
            Ok(r) if r["stale"] == json!(true) => "stale".to_string(),
            Ok(_) => "taken".to_string(),
            Err(e) => format!("refused: {e}"),
        };
        crate::info!("route {ip} via {via} generation {gen} revision {rev}: held announcement answered: {how}");
    }
    answer
}

/// Validates an address from a migration or a checkpoint before it is prepared or claimed,
/// never waiting on DNS itself: `peers` are the peers' addresses, as the listener goes by
/// (`FLEXVM_INCOMING_PEERS` for an arrival, plus its source; `known_peers` for a restore).
/// Peers configured by address count as they are now.
pub fn check_vm_ip(host: &Host, ip: Ipv4Addr, peers: &[IpAddr]) -> Result<()> {
    let cfg = host.config_now();
    let mut known = peers.to_vec();
    known.extend(cfg.peers.iter().filter_map(|p| p.parse::<SocketAddr>().ok().map(|a| a.ip())));
    routable(ip, &cfg, &known, &crate::net::gateways(&std::fs::read_to_string("/proc/net/route")?))
}

/// A next hop is the connection's peer or a configured peer (its addresses or `peer_underlays`),
/// never a non-unicast address: a cluster VM's route to a peer's own address sends its traffic to
/// that peer only, which any peer may claim by announcing the VM moved to it.
/// Callers include the connection address in `peers`; named peers come from strict listener lookup.
/// A peer's local address (hosts sharing a network namespace, loopback included) is taken:
/// `net::route_via` installs nothing for it, and a migration's handoff relies on it.
pub fn check_via(via: Ipv4Addr, peers: &[IpAddr]) -> Result<()> {
    via_by(via, peers)
}

pub(crate) fn via_by(via: Ipv4Addr, peers: &[IpAddr]) -> Result<()> {
    if !is_peer(peers, IpAddr::V4(via)) || via.is_unspecified() || via.is_broadcast() || via.is_multicast() {
        bail!("{via} is not a peer next hop: not a peer's address, or not unicast");
    }
    Ok(())
}

/// The configured peers' addresses for a restore or resume (root's own, see `PEER_CACHE`):
/// as the listener last knew them, whatever their age, never looked up here. A name it has
/// no entry for is refused at once.
pub fn known_peers(host: &Host) -> Result<Vec<IpAddr>> {
    let cfg = host.config_now();
    let cache = Cached::read(&host.run, &cfg.peers);
    let mut addrs = cfg.peer_underlay_addrs();
    for n in &cfg.peers {
        addrs.extend(cache.addrs(n)?);
    }
    Ok(addrs)
}

/// The configured peers by name the listener knows no address of (yet: a lookup failed or not
/// made since a boot), as `known_peers` reads them.
pub fn unknown_peers(host: &Host) -> Vec<String> {
    let names = host.config_now().peers;
    let cache = Cached::read(&host.run, &names);
    names.into_iter().filter(|n| cache.addrs(n).map_or(true, |a| a.is_empty())).collect()
}

impl Cached {
    pub fn read(run: &std::path::Path, names: &[String]) -> Self {
        match names.iter().any(|n| n.parse::<SocketAddr>().is_err()) {
            true => crate::util::trusted_file(&run.join(PEER_CACHE))
                .and_then(|f| serde_json::from_reader(std::io::BufReader::new(f).take(1 << 20)).ok())
                .unwrap_or_default(),
            false => Self::default(),
        }
    }

    /// One that cannot be written is removed, never left to answer for addresses since changed.
    fn write(&self, path: &std::path::Path) {
        let (dir, name) = (path.parent().unwrap(), path.file_name().unwrap().to_str().unwrap());
        if let Err(e) = serde_json::to_vec(self).map_err(std::io::Error::from).and_then(|b| crate::util::write_file(dir, name, &b, false)) {
            let gone = match std::fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => format!("; cannot remove it either: {e}"),
                _ => String::new(),
            };
            crate::log!("{}: {e}{gone}", path.display());
        }
    }

    pub fn addrs(&self, name: &str) -> std::io::Result<Vec<IpAddr>> {
        match (name.parse::<SocketAddr>(), self.names.get(name)) {
            (Ok(a), _) => Ok(vec![a.ip()]),
            (_, Some(a)) => Ok(a.clone()),
            _ => Err(std::io::Error::other(format!(
                "peer {name} has not been looked up by this host's listener yet, so its addresses are unknown; try again once flexvm listen runs"
            ))),
        }
    }
}

/// A peer routes only a VM's address, never one this host reaches its peers or network by (#365).
fn routable(ip: Ipv4Addr, cfg: &crate::host::Config, peers: &[IpAddr], gateways: &[Ipv4Addr]) -> Result<()> {
    routable_by(ip, cfg, peers, gateways, crate::net::is_local_addr)
}

fn routable_by(ip: Ipv4Addr, cfg: &crate::host::Config, peers: &[IpAddr], gateways: &[Ipv4Addr], local: impl FnOnce(Ipv4Addr) -> Result<bool>) -> Result<()> {
    // Only local configuration authorizes a VM address; a peer's range is untrusted.
    if !cfg.cluster()?.contains(ip) {
        bail!("{ip} is not a vm's address: outside this host's configured VM ranges");
    }
    let peer = is_peer(peers, IpAddr::V4(ip)) || is_peer(&cfg.peer_underlay_addrs(), IpAddr::V4(ip));
    // A derived underlay is an interface's source address, covered by is_local_addr below.
    let listen = cfg.listen.as_deref().and_then(|s| s.parse::<SocketAddr>().ok()).map(|a| a.ip().to_canonical());
    let underlay = cfg.underlay == Some(ip) || listen == Some(IpAddr::V4(ip));
    let special = ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || underlay || gateways.contains(&ip);
    if peer || special || local(ip)? {
        bail!("{ip} is not a vm's address: a local, peer, underlay or gateway address, or not unicast");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A push refused once its metadata is read, before its data; answered from the hold without a slot or turn;
    /// asked again (`have`) as a source does right before its prepare (#824).
    #[test]
    fn pushes_are_refused_before_their_data_and_answered_from_the_hold() {
        let (_src, src_paths, tpl) = crate::template::tests::sendable();
        let id = tpl.meta.id.clone();
        let root = crate::test_util::TempDir::new("push");
        let state = root.join("state");
        std::fs::create_dir_all(&state).unwrap();
        // The source's Firecracker (`template::Paths::new`), as every host must have.
        std::os::unix::fs::symlink(src_paths.firecracker.parent().unwrap(), state.join("artifacts")).unwrap();
        let host = Host::open(&state, &root.join("run")).unwrap();
        let paths = crate::template::Paths::new(&state);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let conn = conn.unwrap();
                let req: Value = serde_json::from_slice(&read_line_by(&conn, Instant::now() + REQUEST_DEADLINE).unwrap()).unwrap();
                let host = host.clone();
                std::thread::spawn(move || push(&host, &req, conn).unwrap());
            }
        });
        let ask = |req: Value| {
            let (conn, reply) = crate::util::rpc(&addr, Duration::from_secs(2), Instant::now() + Duration::from_secs(10), &req).unwrap();
            (conn, reply)
        };
        let read = |conn: &TcpStream| crate::util::recv_json(&mut std::io::BufReader::new(conn)).unwrap().unwrap();
        // No room for what it says it sends: refused right after its metadata, and the source reads why.
        let (mut conn, reply) = ask(json!({"op": "template", "id": id, "ack": true, "bytes": 1u64 << 50}));
        assert_eq!(reply, json!({"have": false, "ack": true}));
        crate::template::Sending::new(&tpl).unwrap().write_meta(&mut conn).unwrap();
        let refused = read(&conn);
        assert!(refused["ok"] == false && refused["error"].as_str().unwrap().contains("past"), "{refused}");
        assert!(crate::template::Template::generation(&paths, &id).is_none());
        // Asked only: not here, and nothing is received.
        let e = crate::migrate::push_template(&addr, &tpl, true).err().unwrap().to_string();
        assert!(e.contains("no longer has"), "{e}");
        assert!(crate::template::Template::generation(&paths, &id).is_none());
        // Sent: its metadata acknowledged, then its data; held before the source is answered (charged to its peer).
        let (got, digests) = crate::migrate::push_template(&addr, &tpl, false).unwrap().unwrap();
        assert!(got["ms"].is_number() && digests == json!(tpl.digests().unwrap()), "{got}");
        assert!(crate::template::Template::generation(&paths, &id).is_some() && HELD.lock().unwrap().contains_key(&id));
        // Held: answered though every slot of this peer is taken and another arrival of it has its turn.
        let _slots = [PUSHES.take("127.0.0.1".parse().unwrap()), PUSHES.take("127.0.0.1".parse().unwrap())];
        let _turn = crate::template::turn(&paths, &id, Instant::now()).unwrap();
        assert!(crate::migrate::push_template(&addr, &tpl, false).unwrap().is_some());
        assert!(crate::migrate::push_template(&addr, &tpl, true).unwrap().is_some());
        // As an old source (no `ack`) asks.
        assert_eq!(ask(json!({"op": "template", "id": id})).1["have"], true);
        // Waiting for a turn takes a place of its own, so waiters are bounded too: one for another template is busy.
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let _waiters: Vec<_> = (0..2 * MAX_PUSHES_FROM).map(|_| PUSHERS.take(ip)).collect();
        let other = "0".repeat(16);
        let busy = crate::util::rpc(&addr, Duration::from_secs(2), Instant::now() + Duration::from_secs(10), &json!({"op": "template", "id": other}));
        assert!(busy.err().unwrap().to_string().contains(BUSY));
        drop(_waiters);
        // No such generation, asked only: not here, by any id.
        drop((_slots, _turn));
        assert_eq!(ask(json!({"op": "template", "id": "../x", "have": true})).1, json!({"have": false}));
    }

    #[test]
    fn next_hops_are_known_peers_and_unicast() {
        let via: Ipv4Addr = "192.0.2.7".parse().unwrap();
        let peers = [IpAddr::V4(via), "::ffff:192.0.2.8".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        via_by(via, &peers).unwrap();
        via_by("192.0.2.8".parse().unwrap(), &peers).unwrap();
        // Peers sharing this network namespace route via a local address (net::route_via skips it).
        via_by("127.0.0.1".parse().unwrap(), &peers).unwrap();
        assert!(via_by("192.0.2.9".parse().unwrap(), &peers).is_err());
        assert!(via_by("127.0.0.2".parse().unwrap(), &peers).is_err());
        for ip in ["0.0.0.0", "255.255.255.255", "224.0.0.1"] {
            let ip = ip.parse().unwrap();
            assert!(via_by(ip, &[IpAddr::V4(ip)]).is_err());
        }
    }

    #[test]
    fn route_rejects_untrusted_next_hops_before_recording_and_withdraws_old_ranges() {
        let root = crate::test_util::TempDir::new("route-via");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let ip: Ipv4Addr = "10.201.0.7".parse().unwrap();
        for via in ["192.0.2.99", "127.0.0.2"] {
            assert!(route(&host, &json!({"ip": "10.200.0.7", "gen": 3, "rev": 0, "via": via}), &["127.0.0.1".parse().unwrap()], &[]).is_err());
            assert!(!host.state.join("addrs/10.200.0.7").exists());
        }
        // Held here, without a deadline, so `route` takes it again at once: another test holding
        // the process-wide host lock past LOCK_WAIT would otherwise make it BUSY.
        let l = host.lock().unwrap();
        let (b, c): (IpAddr, IpAddr) = ("192.0.2.7".parse().unwrap(), "192.0.2.8".parse().unwrap());
        host.observe(&l, ip, 3, 0, Some("192.0.2.7".parse().unwrap())).unwrap();
        let req = json!({"ip": ip.to_string(), "gen": 3});
        // Routed via B: another peer (C) does not withdraw that generation.
        let e = route(&host, &req, &[b, c], &[c]).unwrap_err().to_string();
        assert!(e.contains("only that peer, or one with a newer revision, withdraws it"), "{e}");
        assert!(!host.addr(&l, ip).unwrap().withdrawn);
        // C, at B's revision or an older one, neither; at a newer one (the VM migrated on to C and
        // ended there before C's announcement got here), it does.
        let moved: Ipv4Addr = "10.201.0.9".parse().unwrap();
        host.observe(&l, moved, 3, 2, Some("192.0.2.7".parse().unwrap())).unwrap();
        for rev in [0, 2] {
            assert!(route(&host, &json!({"ip": moved.to_string(), "gen": 3, "rev": rev}), &[b, c], &[c]).is_err(), "rev {rev}");
        }
        assert!(!host.addr(&l, moved).unwrap().withdrawn);
        route(&host, &json!({"ip": moved.to_string(), "gen": 3, "rev": 3}), &[b, c], &[c]).unwrap();
        assert!(host.addr(&l, moved).unwrap().withdrawn);
        // B does, retries included.
        route(&host, &req, &[b, c], &[b]).unwrap();
        route(&host, &req, &[b, c], &[b]).unwrap();
        assert!(host.addr(&l, ip).unwrap().withdrawn);
        // A newer generation is a move: any peer's.
        host.observe(&l, ip, 4, 0, Some("192.0.2.7".parse().unwrap())).unwrap();
        route(&host, &json!({"ip": ip.to_string(), "gen": 5}), &[b, c], &[c]).unwrap();
        assert_eq!(host.addr(&l, ip).unwrap().seen, 5);
        assert!(route(&host, &json!({"ip": "10.201.0.8", "gen": 3}), &[], &[]).is_err());
    }

    /// A peer's configured underlays (`peer_underlays`) are its next hops, and no VM's address;
    /// a peer no longer configured has none.
    #[test]
    fn configured_peer_underlays_are_next_hops() {
        let mut cfg = crate::host::Config { peers: vec!["192.0.2.7:7070".into()], ..Default::default() };
        let data: Ipv4Addr = "198.51.100.7".parse().unwrap();
        cfg.peer_underlays.insert("192.0.2.7:7070".into(), vec![data]);
        cfg.peer_underlays.insert("192.0.2.9:7070".into(), vec!["198.51.100.9".parse().unwrap()]);
        assert_eq!(cfg.peer_underlay_addrs(), [IpAddr::V4(data)]);
        let known = [vec!["192.0.2.7".parse().unwrap()], cfg.peer_underlay_addrs()].concat();
        via_by(data, &known).unwrap();
        assert!(via_by("198.51.100.9".parse().unwrap(), &known).is_err(), "not a configured peer's");
        // The asking peer's own addresses take in its underlays, never another peer's.
        cfg.peers.push("192.0.2.10:7070".into());
        cfg.peer_underlays.insert("192.0.2.10:7070".into(), vec!["198.51.100.10".parse().unwrap()]);
        let sender = Peers::default().sender(&cfg, "192.0.2.7".parse().unwrap());
        assert!(is_peer(&sender, IpAddr::V4(data)) && !is_peer(&sender, "198.51.100.10".parse().unwrap()), "{sender:?}");
        cfg.cluster_ips = Some("198.51.100.0/24".into());
        cfg.vm_ips = "198.51.100.0/25".into();
        assert!(routable_by(data, &cfg, &[], &[], |_| Ok(false)).is_err());
        routable_by("198.51.100.8".parse().unwrap(), &cfg, &[], &[], |_| Ok(false)).unwrap();
    }

    #[test]
    fn admitted_connections_leave_half_the_slots_for_other_peers() {
        let active = Waiting::new(MAX_ACTIVE, MAX_ACTIVE_FROM);
        let one = "10.9.0.1".parse().unwrap();
        let two = "10.9.0.2".parse().unwrap();
        let mut held: Vec<_> = (0..MAX_ACTIVE_FROM).map(|_| active.take(one).unwrap()).collect();
        assert!(active.take(one).is_none());
        assert!(active.take("::ffff:10.9.0.1".parse().unwrap()).is_none());
        let others: Vec<_> = (0..MAX_ACTIVE_FROM).map(|_| active.take(two).unwrap()).collect();
        assert!(active.take("10.9.0.3".parse().unwrap()).is_none());
        held.pop();
        assert!(active.take(one).is_some());
        drop((held, others));
        assert!(active.held.lock().unwrap().is_empty());
    }

    #[test]
    fn migration_done_belongs_to_the_source_peer_across_ports_and_underlays() {
        let (_root, mut host) = crate::host::tests::host("done-peer");
        host.cfg.peers = vec!["192.0.2.1:7070".into(), "192.0.2.2:7070".into()];
        host.cfg.peer_underlays.insert("192.0.2.1:7070".into(), vec!["198.51.100.1".parse().unwrap()]);
        let peers = Peers::default();
        for (id, from) in [(1, "192.0.2.1:49152"), (2, "198.51.100.1:50001"), (3, "[::ffff:192.0.2.1]:50002")] {
            let mut r = host.mig_begin(id, "192.0.2.1:7070", None, None).unwrap().with_peer("192.0.2.1".parse().unwrap());
            r.commit(&host.lock().unwrap()).unwrap();
            r.release(None, None).unwrap();
            // The host lock is shared by this process's threads: a parallel test's may make it busy.
            let ask = |from: &[IpAddr]| loop {
                match migration(&host, &json!({"mig": id, "done": true}), |_, p| p.is_some_and(|p| is_peer(from, p))) {
                    Err(e) if e.to_string() == BUSY => continue,
                    r => break r,
                }
            };
            let e = ask(&peers.sender(&host.cfg, "192.0.2.2".parse().unwrap())).unwrap_err();
            assert!(e.to_string().contains("only accepted from its source"), "{e}");
            ask(&peers.sender(&host.cfg, from.parse::<SocketAddr>().unwrap().ip())).unwrap();
            assert_eq!(host.mig_status(id).unwrap(), "released");
            assert_eq!(peers.borrower(&host.cfg, from.parse::<SocketAddr>().unwrap().ip()), "192.0.2.1:7070");
        }
    }

    #[test]
    fn loan_connections_use_the_same_peer_across_addresses_and_underlays() {
        let mut cfg = crate::host::Config { peers: vec!["other:7070".into(), "borrower:7070".into(), "unresolved:7070".into()], ..Default::default() };
        cfg.peer_underlays.insert("borrower:7070".into(), vec!["198.51.100.1".parse().unwrap()]);
        cfg.peer_underlays.insert("unresolved:7070".into(), vec!["198.51.100.2".parse().unwrap(), "198.51.100.3".parse().unwrap()]);
        let peers = Peers::default();
        peers.0.resolved.write().unwrap().extend([
            // The old sender expansion would pick 'other' for one borrower address only.
            ("other:7070".into(), vec!["192.0.2.9".parse().unwrap()]),
            ("borrower:7070".into(), vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap(), "192.0.2.9".parse().unwrap()]),
            ("unresolved:7070".into(), vec![]),
        ]);
        for (name, sources) in [
            ("borrower:7070", vec!["192.0.2.1", "192.0.2.2", "198.51.100.1", "::ffff:192.0.2.1", "::ffff:198.51.100.1"]),
            ("unresolved:7070", vec!["198.51.100.2", "198.51.100.3"]),
        ] {
            for from in sources {
                let borrower = peers.borrower(&cfg, from.parse().unwrap());
                assert_eq!(borrower, name, "{from}");
            }
        }
        assert_eq!(peers.borrower(&cfg, "::ffff:203.0.113.1".parse().unwrap()), "203.0.113.1");
    }

    #[test]
    fn lend_refuses_peer_addresses_without_creating_a_record() {
        let root = crate::test_util::TempDir::new("lend-peer");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let ip = "10.9.0.1";
        let e = lend(&host, &json!({"ip": ip}), &[ip.parse().unwrap()], "borrower").unwrap_err();
        assert!(e.to_string().contains("not a vm's address"));
        assert!(!host.state.join("addrs").join(ip).exists());
    }

    /// In a child started with a descriptor on fd 3, as systemd would: none of this one's is touched.
    #[test]
    fn the_activated_socket_is_close_on_exec() {
        if std::env::var_os("LISTEN_FDS").is_none() {
            let script = r#"exec 3</dev/null; LISTEN_PID=$$ LISTEN_FDS=1 exec "$0" --exact listen::tests::the_activated_socket_is_close_on_exec --quiet"#;
            let st = std::process::Command::new("sh").args(["-c", script]).arg(std::env::current_exe().unwrap()).status().unwrap();
            return assert!(st.success());
        }
        std::mem::forget(activated().expect("fd 3 taken"));
        assert_eq!(unsafe { libc::fcntl(3, libc::F_GETFD) } & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    }

    #[test]
    fn pages_stays_in_run_vms_and_tells_nothing() {
        let root = crate::test_util::TempDir::new("pages-name");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        // A socket the traversal name would reach, and a suspended VM.
        let outside = std::os::unix::net::UnixListener::bind(root.join("outside.sock")).unwrap();
        outside.set_nonblocking(true).unwrap();
        std::fs::create_dir_all(host.suspended("asleep").unwrap()).unwrap();
        std::fs::write(host.suspended("asleep").unwrap().join("manifest.json"), "").unwrap();
        // A running VM that is not the source: it refuses as `Proc::pages` does.
        let running = std::os::unix::net::UnixListener::bind(host.sock("web").unwrap()).unwrap();
        let vm = std::thread::spawn(move || {
            let (c, _) = running.accept().unwrap();
            let (line, fds) = crate::util::recv_with_fds(&c, 4096, || Ok(())).unwrap();
            let req: Value = serde_json::from_slice(&line).unwrap();
            let fd = fds.into_iter().next().unwrap();
            crate::vmproc::refuse_not_source(TcpStream::from(fd), "web", &req["mig"]);
        });
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let ask = |name: &str| {
            let mut c = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
            pages(&host, &json!({"op": "pages", "name": name, "mig": 7}), tcp.accept().unwrap().0).unwrap();
            let mut reply = Vec::new();
            c.read_to_end(&mut reply).unwrap();
            String::from_utf8(reply).unwrap()
        };
        let refusal = |name: &str| format!("{}\n", json!({"ok": false, "error": format!("vm {name:?} is not the source of migration 7")}));
        for name in ["../../outside", "asleep", "nothing", "web"] {
            assert_eq!(ask(name), refusal(name), "{name}");
        }
        vm.join().unwrap();
        assert_eq!(outside.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn fresh_process_vm_address_checks_need_no_dns() {
        let root = crate::test_util::TempDir::new("vm-ip-no-dns");
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        host.configure(|cfg| {
            cfg.peers = vec!["peer.example:7000".into(), "10.98.0.1:7000".into(), "[::ffff:10.98.0.2]:7000".into()];
            Ok(())
        })
        .unwrap();
        // No resolver is started or waited for, even with an empty process cache.
        check_vm_ip(&host, "10.98.0.1".parse().unwrap(), &[]).unwrap_err();
        // A restore or resume goes by what the listener looked up, never looking up itself:
        // a name it has not looked up yet is refused at once.
        let start = Instant::now();
        let e = known_peers(&host).unwrap_err().to_string();
        assert!(e.contains("not been looked up") && start.elapsed() < Duration::from_millis(500), "{e}");
        let listener = Peers(Arc::new(PeersInner { cache: Some((host.run.join(PEER_CACHE), Mutex::default())), ..Default::default() }));
        listener.cache(|c| drop(c.names.insert("peer.example:7000".into(), vec!["10.93.0.1".parse().unwrap()])));
        let known = known_peers(&host).unwrap();
        assert!(known.contains(&"10.93.0.1".parse().unwrap()), "{known:?}");
        assert!(check_vm_ip(&host, "10.93.0.1".parse().unwrap(), &known).unwrap_err().to_string().contains("not a vm's address"));
        // Whatever its age; a lookup that fails later keeps what it had; one that never resolved has none.
        let old = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options().write(true).open(host.run.join(PEER_CACHE)).unwrap().set_modified(old).unwrap();
        assert!(known_peers(&host).unwrap().contains(&"10.93.0.1".parse().unwrap()));
        listener.cache(|c| {
            c.names.entry("peer.example:7000".into()).or_default();
        });
        assert!(known_peers(&host).unwrap().contains(&"10.93.0.1".parse().unwrap()));
        listener.cache(|c| drop(c.names.insert("peer.example:7000".into(), Vec::new())));
        assert!(!known_peers(&host).unwrap().contains(&"10.93.0.1".parse().unwrap()));
        routable_by("10.200.0.7".parse().unwrap(), &host.config_now(), &[], &[], |_| Ok(false)).unwrap();
        host.configure(|cfg| {
            cfg.underlay = Some("10.97.0.1".parse().unwrap());
            cfg.listen = Some("[::ffff:10.96.0.1]:7000".into());
            Ok(())
        })
        .unwrap();
        for ip in ["10.98.0.1", "10.98.0.2", "10.97.0.1", "10.96.0.1"] {
            let e = check_vm_ip(&host, ip.parse().unwrap(), &[]).unwrap_err();
            assert!(e.to_string().contains("not a vm's address"), "{e}");
        }
        // An arrival inherits resolved names from the listener, even during an
        // unsuccessful refresh, and adds its actual source (including mapped IPv4).
        let peers = Peers::default();
        peers.0.resolved.write().unwrap().insert("peer.example:7000".into(), vec!["10.94.0.1".parse().unwrap()]);
        peers.0.lookups.lock().unwrap().insert("peer.example:7000".into(), None);
        let mut known = peers.addrs(&host.config_now().peers);
        known.push("::ffff:10.95.0.1".parse().unwrap());
        for ip in ["10.94.0.1", "10.95.0.1"] {
            assert!(check_vm_ip(&host, ip.parse().unwrap(), &known).unwrap_err().to_string().contains("not a vm's address"));
        }
        let cfg = host.config_now();
        routable_by("10.200.0.7".parse().unwrap(), &cfg, &known, &[], |_| Ok(false)).unwrap();
        assert!(routable_by("10.200.0.7".parse().unwrap(), &cfg, &known, &[], |_| Ok(true)).is_err());
    }

    /// At a first start or after a boot nothing has looked the peers up: the listener does
    /// before deriving the underlay it advertises for a wildcard address (#579), and its own
    /// lookups then keep the others' entries.
    #[test]
    fn a_wildcard_listener_derives_its_underlay_from_its_own_lookups() {
        let root = crate::test_util::TempDir::new("listen-seed");
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        host.configure(|cfg| {
            cfg.listen = Some("0.0.0.0:7106".into());
            cfg.peers = vec!["localhost:7107".into()];
            validate(std::slice::from_ref(&listener), cfg)?;
            assert_eq!(cfg.advertise()?.as_deref(), Some("127.0.0.1:7106"));
            Ok(())
        })
        .unwrap();
        // Seeded even when refused: a name that does not resolve gets an empty entry, the others keep theirs.
        let e = host.configure(|cfg| {
            cfg.peers = vec!["localhost:7107".into(), "never.invalid:7107".into(), "10.98.0.1:7107".into()];
            validate(std::slice::from_ref(&listener), cfg).map(|_| ())
        });
        assert!(e.is_err(), "a loopback listener with a peer elsewhere");
        let peers = ["localhost:7107".to_string(), "never.invalid:7107".into()];
        let seeded = Cached::read(&host.run, &peers);
        assert!(seeded.addrs("localhost:7107").unwrap().iter().any(|a| a.is_loopback()), "{seeded:?}");
        assert_eq!(seeded.addrs("never.invalid:7107").unwrap(), Vec::<IpAddr>::new());
        assert_eq!(seeded.names.len(), 2, "names only: {seeded:?}");
        // The listener's own first lookup to end keeps the others' entries.
        host.configure(|cfg| {
            cfg.peers = peers.to_vec();
            Ok(())
        })
        .unwrap();
        Peers::listener(&host, Cached::default()).cache(|c| drop(c.names.insert("never.invalid:7107".into(), vec!["10.93.0.1".parse().unwrap()])));
        let after = Cached::read(&host.run, &peers);
        assert!(after.addrs("localhost:7107").unwrap().iter().any(|a| a.is_loopback()), "{after:?}");
    }

    #[test]
    fn validated_peers_are_admitted_without_another_lookup() {
        let root = crate::test_util::TempDir::new("listen-admission-seed");
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut validated = Cached::default();
        host.configure(|cfg| {
            cfg.listen = Some(listener.local_addr()?.to_string());
            cfg.peers = vec!["localhost:7107".into()];
            validated = validate(std::slice::from_ref(&listener), cfg)?;
            cfg.peers.push("old.invalid:1".into());
            Ok(())
        })
        .unwrap();
        let from = validated.names["localhost:7107"][0];
        // An earlier listener's cached lookup is not this validation's.
        let mut cached = Cached::read(&host.run, &host.cfg.peers);
        cached.names.insert("old.invalid:1".into(), vec!["10.93.0.1".parse().unwrap()]);
        cached.write(&host.run.join(PEER_CACHE));
        let p = Peers::listener(&host, validated);
        // Simulate a failed refresh: it keeps the validated addresses.
        for name in &host.cfg.peers {
            p.0.lookups.lock().unwrap().insert(name.clone(), Some(Instant::now()));
        }
        assert!(matches!(p.check(&host.cfg.peers, from), Admission::Peer));
        assert!(!p.0.resolved.read().unwrap().contains_key("old.invalid:1"));
        assert!(p.0.lookups.lock().unwrap()["localhost:7107"].is_some());
        assert!(matches!(p.check(&[], from), Admission::Refused));
    }

    /// A name the listener is to look up has an entry, empty until its lookup ends, so other
    /// processes never look it up themselves; an entry it has is kept.
    #[test]
    fn a_new_peer_name_gets_an_empty_entry_before_its_lookup() {
        let root = crate::test_util::TempDir::new("listen-new-name");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let p = Peers::listener(&host, Cached::default());
        p.cache(|c| drop(c.names.insert("old.invalid:1".into(), vec!["10.93.0.1".parse().unwrap()])));
        let names = ["old.invalid:1".to_string(), "new.invalid:1".into(), "10.98.0.1:1".into()];
        // As if its lookup were under way already: none is started, the entry is still written.
        p.0.lookups.lock().unwrap().insert("new.invalid:1".into(), None);
        p.0.lookups.lock().unwrap().insert("old.invalid:1".into(), Some(Instant::now()));
        p.refresh(&names);
        let c = Cached::read(&host.run, &names);
        assert_eq!(c.addrs("new.invalid:1").unwrap(), Vec::<IpAddr>::new());
        assert_eq!(c.addrs("old.invalid:1").unwrap(), ["10.93.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(c.names.len(), 2, "names only: {c:?}");
        assert!(p.0.resolved.read().unwrap().is_empty(), "an empty entry admits no one");
    }

    #[test]
    fn peers_route_only_vm_addresses() {
        let mut cfg = crate::host::Config {
            peers: vec!["10.98.0.1:7000".into(), "peer.example:7000".into()],
            underlay: Some("10.97.0.1".parse().unwrap()),
            ..Default::default()
        };
        let gw: Ipv4Addr = "10.96.0.1".parse().unwrap();
        // The peer configured by name, as resolved; and the one asking.
        let p = Peers::default();
        let soon = || Instant::now() + Duration::from_millis(50);
        // Its lookup under way: refused, after a wait.
        p.0.lookups.lock().unwrap().insert("peer.example:7000".into(), None);
        let e = p.all_addrs(&cfg.peers, soon()).unwrap_err().to_string();
        assert!(e.contains("still being looked up"), "{e}");
        // Ended with no address (it does not resolve): no addresses, not a refusal forever.
        p.0.lookups.lock().unwrap().insert("peer.example:7000".into(), Some(Instant::now()));
        assert_eq!(p.all_addrs(&cfg.peers, soon()).unwrap(), ["10.98.0.1".parse::<IpAddr>().unwrap()]);
        // Cached, but looked up again (it may come back on a new address): refused after a wait
        // too, never answered with the old address alone; then with the new one.
        p.0.resolved.write().unwrap().insert("peer.example:7000".into(), vec!["10.94.0.2".parse().unwrap()]);
        p.0.lookups.lock().unwrap().insert("peer.example:7000".into(), None);
        let e = p.all_addrs(&cfg.peers, soon()).unwrap_err().to_string();
        assert!(e.contains("still being looked up"), "{e}");
        p.0.resolved.write().unwrap().insert("peer.example:7000".into(), vec!["10.94.0.1".parse().unwrap()]);
        p.0.lookups.lock().unwrap().insert("peer.example:7000".into(), Some(Instant::now()));
        let peers = [p.all_addrs(&cfg.peers, soon()).unwrap(), vec!["10.95.0.1".parse().unwrap()]].concat();
        assert!(peers.contains(&"10.94.0.1".parse().unwrap()) && !peers.contains(&"10.94.0.2".parse().unwrap()));
        let check = |ip: &str, cfg: &crate::host::Config| routable_by(ip.parse().unwrap(), cfg, &peers, &[gw], |ip| Ok(ip.is_loopback()));
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "10.98.0.1",
            "10.94.0.1",
            "10.97.0.1",
            "10.96.0.1",
            "10.95.0.1",
            "169.254.169.254",
            "10.96.0.53",
            "10.96.0.42",
        ] {
            assert!(check(ip, &cfg).is_err(), "{ip} is refused");
        }
        check("10.200.0.7", &cfg).unwrap();
        // A peer's own VM range grants nothing; only local configuration can allow it.
        assert!(check("10.201.0.7", &cfg).is_err());
        cfg.cluster_ips = Some("10.200.0.0/15".into());
        check("10.201.0.7", &cfg).unwrap();
        // Even an overlapping cluster range cannot authorize our network's addresses.
        cfg.cluster_ips = Some("0.0.0.0-255.255.255.255".into());
        for ip in ["127.0.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1", "10.98.0.1", "10.94.0.1", "10.97.0.1", "10.96.0.1", "10.95.0.1"] {
            assert!(check(ip, &cfg).is_err(), "{ip} is refused even inside cluster_ips");
        }
        assert!(routable_by("10.201.0.7".parse().unwrap(), &cfg, &peers, &[gw], |_| Ok(true)).is_err());
    }

    #[test]
    fn refused_arrival_removes_only_its_own_log() {
        let root = crate::test_util::TempDir::new("arrival-log");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let arrival = host.run.join("vms/.incoming.log");
        let existing = host.vms("web", "log").unwrap();
        let previous = host.vms("web", "log.1").unwrap();
        std::fs::write(&existing, b"existing vm").unwrap();
        std::fs::write(&previous, b"earlier stay").unwrap();
        std::fs::write(&arrival, b"refused").unwrap();
        finish_incoming_log(&host, "web", &arrival, false).unwrap();
        assert!(!arrival.exists());
        assert_eq!(std::fs::read(&existing).unwrap(), b"existing vm");
        assert_eq!(std::fs::read(&previous).unwrap(), b"earlier stay");
        std::fs::write(&arrival, b"accepted").unwrap();
        finish_incoming_log(&host, "web", &arrival, true).unwrap();
        assert!(!arrival.exists());
        assert_eq!(std::fs::read(&existing).unwrap(), b"accepted");
        assert!(!previous.exists());
    }

    #[test]
    fn arrivals_past_either_bound_or_without_a_reaper_are_refused_at_once_starting_nothing() {
        let root = crate::test_util::TempDir::new("arrivals-full");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let line = br#"{"op":"migrate_in","name":"web"}"#;
        let refused = |why: &str| {
            let (client, server) = pair();
            let start = Instant::now();
            incoming(&host, &serde_json::from_slice(line).unwrap(), line, server, Instant::now() + PREPARE_WAIT, &[]).unwrap();
            assert!(start.elapsed() < Duration::from_secs(1));
            let reply = crate::util::recv_json(&mut std::io::BufReader::new(&client)).unwrap().unwrap();
            assert_eq!(reply["ok"], false);
            assert!(reply["error"].as_str().unwrap().contains(why), "{reply}");
            let vms = host.run.join("vms");
            let made = |d: &std::path::Path| std::fs::read_dir(d).unwrap().filter(|e| e.as_ref().unwrap().file_name() != crate::host::LOCKS).count();
            assert_eq!(made(&vms) + made(&crate::host::locks(&vms)), 0, "no arrival log or lock made");
        };
        let held = || ARRIVALS.held.lock().unwrap().values().sum::<usize>();
        let take = |from: &str, n: usize| (0..n).map(|_| ARRIVALS.take(from.parse().unwrap()).unwrap()).collect::<Vec<_>>();
        // One peer takes at most half.
        let mine = take("127.0.0.1", MAX_ARRIVALS_FROM);
        assert!(ARRIVALS.take("127.0.0.1".parse().unwrap()).is_none());
        refused("arriving here already");
        drop(mine);
        // Others hold them all.
        let others: Vec<_> = (1..=MAX_ARRIVALS).map(|i| take(&format!("10.9.0.{i}"), 1)).collect();
        refused("arriving here already");
        drop(others);
        assert_eq!(held(), 0);
        // Even with the shared reaper cached, failure is refused and its slot given back.
        crate::util::start_reaper().unwrap();
        crate::util::NO_REAPER.with(|n| n.set(true));
        refused("cannot start the vm process");
        crate::util::NO_REAPER.with(|n| n.set(false));
        assert_eq!(held(), 0);
    }

    /// Arrivals an earlier listener started outlive it: a restarted one counts their
    /// locks (`.locks/` and the log's name), by peer, and admits none past either bound (#521).
    #[test]
    fn arrivals_an_earlier_listener_started_count_against_both_bounds() {
        let root = crate::test_util::TempDir::new("arrivals-earlier");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let vms = crate::host::locks(&host.run.join("vms"));
        let line = br#"{"op":"migrate_in","name":"web"}"#;
        // Each held as its arrival holds it; `None`: dead, unlocked. An arrival that
        // ends is taken away by its name (a lock let go may linger a moment in a child
        // another test forks meanwhile).
        let log = |name: String, live: bool| {
            let f = crate::host::private_file(&vms.join(&name)).unwrap();
            live.then(|| (crate::host::flock(&f, libc::LOCK_SH).map(|()| f).unwrap(), vms.join(name)))
        };
        let end = |logs: Vec<Option<(std::fs::File, std::path::PathBuf)>>| logs.into_iter().flatten().for_each(|(_, p)| std::fs::remove_file(p).unwrap());
        let refused = |why: &str| {
            let (client, server) = pair();
            incoming(&host, &serde_json::from_slice(line).unwrap(), line, server, Instant::now() + PREPARE_WAIT, &[]).unwrap();
            let reply = crate::util::recv_json(&mut std::io::BufReader::new(&client)).unwrap().unwrap();
            assert_eq!(reply["ok"], false);
            assert!(reply["error"].as_str().unwrap().contains(why), "{reply}");
        };
        let other = std::process::id() + 1;
        // This one's own and dead ones do not count: the memory has the former.
        let mut held: Vec<_> = (0..MAX_ARRIVALS_FROM).map(|i| log(format!(".incoming-{}-{i}-127.0.0.1.log", std::process::id()), true)).collect();
        held.extend((0..MAX_ARRIVALS).map(|i| log(format!(".incoming-{other}-{}-127.0.0.1.log", 100 + i), false)));
        assert!(earlier_arrivals(&host).is_empty());
        let mine: Vec<_> = (0..MAX_ARRIVALS_FROM).map(|i| log(format!(".incoming-{other}-{i}-127.0.0.1.log"), true)).collect();
        assert_eq!(earlier_arrivals(&host), HashMap::from([("127.0.0.1".parse().unwrap(), MAX_ARRIVALS_FROM)]));
        refused("arriving here already");
        // The peer's quota is free again; others' arrivals (one of an older name, with
        // no peer) fill the total.
        end(mine);
        let mut others: Vec<_> = (1..MAX_ARRIVALS).map(|i| log(format!(".incoming-{other}-{i}-10.9.0.{i}.log"), true)).collect();
        others.push(log(format!(".incoming-{other}-0.log"), true));
        assert_eq!(earlier_arrivals(&host).values().sum::<usize>(), MAX_ARRIVALS);
        refused("arriving here already");
        end(others);
        assert!(earlier_arrivals(&host).is_empty());
    }

    /// Requests that take the host lock wait for it a bounded time and then are told the
    /// host is busy; past their own budget they are told so at once, while page
    /// handoffs, which need no host lock, are still answered (#521).
    #[test]
    fn host_lock_waits_are_bounded_and_leave_page_handoffs_room() {
        use crate::test_util::WAIT;
        use std::io::Write;
        let root = crate::test_util::TempDir::new("listen-busy");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        // Saturating this test's budget must not make other hosts' requests busy.
        static LOCKING: AtomicUsize = AtomicUsize::new(0);
        let ask = |req: Value| {
            let (client, server) = pair();
            let (start, mut line) = (Instant::now(), req.to_string().into_bytes());
            line.push(b'\n');
            (&client).write_all(&line).unwrap();
            handle(&host, &Peers::default(), server, Instant::now() + REQUEST_DEADLINE, &LOCKING).unwrap();
            let reply = crate::util::recv_json(&mut std::io::BufReader::new(&client)).unwrap().unwrap();
            (reply, start.elapsed())
        };
        let requests = [json!({"op": "lend", "ip": "10.200.0.7"}), json!({"op": "migration", "mig": 7}), json!({"op": "route", "ip": "10.200.0.8", "gen": 3})];
        // Held by another process, as one stopped while holding it would.
        // Explicitly unlock on drop: a parallel test can fork and inherit the file.
        let held = crate::host::Flock::new(crate::host::private_file(&host.lock_file()).unwrap(), libc::LOCK_EX).unwrap();
        std::thread::scope(|s| {
            let waits: Vec<_> = requests.iter().map(|r| s.spawn(|| ask(r.clone()))).collect();
            for w in waits {
                let (reply, took) = w.join().unwrap();
                assert_eq!(reply["error"], BUSY, "{reply}");
                // The lock stays held until every request has timed out. Allow for
                // scheduling delays without losing the lower bound on its wait.
                assert!(took >= LOCK_WAIT && took < WAIT, "{took:?}");
            }
        });
        // Its budget taken: page handoffs still bypass both admission and the held lock.
        let full: Vec<_> = std::iter::from_fn(|| Slot::take(&LOCKING, MAX_LOCKING)).collect();
        assert_eq!(full.len(), MAX_LOCKING);
        assert!(Slot::take(&LOCKING, MAX_LOCKING).is_none());
        // Refused before any lock wait: well under LOCK_WAIT while another still holds the lock.
        for r in &requests {
            let (reply, took) = ask(r.clone());
            assert!(reply["error"] == BUSY && took < LOCK_WAIT, "{reply} {took:?}");
        }
        // Answered (its refusal then drains what the client sent, `vmproc::refuse_pages`).
        let (reply, _) = ask(json!({"op": "pages", "name": "web", "mig": 7}));
        assert!(reply["error"].as_str().unwrap().contains("not the source"), "{reply}");
        drop(held);
        // Acquire without a deadline, so other tests' process-wide lock waits cannot
        // make these requests BUSY. On this thread the lock is now reentrant: only
        // admission can refuse them, without a fragile stopwatch assertion.
        let _l = host.lock().unwrap();
        for r in &requests {
            let (reply, _) = ask(r.clone());
            assert_eq!(reply["error"], BUSY, "{reply}");
        }
        drop(full);
        // Once admission is free, the same request succeeds under the same lock.
        let (reply, _) = ask(requests[0].clone());
        assert_eq!(reply["result"]["ip"], "10.200.0.7", "{reply}");
    }

    #[test]
    fn a_refusal_flood_is_logged_a_few_lines_a_second_and_counted() {
        let mut w = RefusalLog { second: 0, logged: 0, unlogged: 0 };
        let first: Vec<_> = (0..1000).map(|_| w.take(5)).collect();
        assert_eq!(first.iter().filter(|l| l.is_some()).count(), REFUSALS_LOGGED as usize);
        assert!(first.iter().flatten().all(|&n| n == 0));
        assert_eq!(w.take(6), Some(1000 - REFUSALS_LOGGED as u64));
        assert_eq!(w.take(6), Some(0));
    }

    #[test]
    fn configured_peer_errors_share_the_refusal_budget_and_report_suppressed_counts() {
        let mut w = RefusalLog { second: 0, logged: 0, unlogged: 0 };
        let errors = ["invalid JSON", "migration 7: page request refused", "not a peer", "cannot start request worker"];
        for i in 0..100 {
            let e = errors[i % errors.len()];
            let line = w.line(5, e);
            if i < REFUSALS_LOGGED as usize {
                assert_eq!(line, Some(format!("peer request: {e}")));
            } else {
                assert_eq!(line, None);
            }
        }
        assert_eq!(w.line(6, errors[1]), Some(format!("peer request: {} (90 refusals before it not logged)", errors[1])));
        assert_eq!(w.line(6, errors[0]), Some(format!("peer request: {}", errors[0])));
    }

    #[test]
    fn a_failed_request_spawn_closes_the_connection_and_releases_its_slot() {
        for waiting in [Waiting::new(MAX_ACTIVE, MAX_ACTIVE_FROM), Waiting::new(MAX_WAITING, MAX_WAITING_FROM), Waiting::new(MAX_MOVED, MAX_MOVED_FROM)] {
            let from = "127.0.0.1".parse().unwrap();
            let slot = waiting.take(from).unwrap();
            let (mut client, conn) = std::os::unix::net::UnixStream::pair().unwrap();
            client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let (done, ran) = std::sync::mpsc::channel();
            // An impossible stack allocation fails without exhausting tasks for other tests.
            spawn_request(std::thread::Builder::new().stack_size(usize::MAX / 2), move || {
                drop((conn, slot));
                let _ = done.send(());
            });
            assert_eq!(ran.recv_timeout(Duration::from_secs(5)), Err(std::sync::mpsc::RecvTimeoutError::Disconnected), "the request must not run");
            assert!(waiting.held.lock().unwrap().is_empty(), "the failed spawn must release admission capacity");
            assert_eq!(client.read(&mut [0]).unwrap(), 0, "the unanswered connection is closed");
            let slot = waiting.take(from).unwrap();
            let (done, ran) = std::sync::mpsc::channel();
            spawn_request(std::thread::Builder::new(), move || {
                drop(slot);
                done.send(()).unwrap();
            });
            ran.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(waiting.held.lock().unwrap().is_empty());
        }
    }

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        (c, l.accept().unwrap().0)
    }

    #[test]
    fn a_request_line_is_read_exactly_through_its_newline() {
        use std::io::Write;
        let (mut c, mut s) = pair();
        c.write_all(b"{\"op\":\"x\"}\nafter").unwrap();
        // In pieces too: a line split across chunks.
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(read_line_by(&s, deadline).unwrap(), b"{\"op\":\"x\"}");
        let mut rest = [0u8; 5];
        s.read_exact(&mut rest).unwrap();
        assert_eq!(&rest, b"after", "nothing after the line is consumed");
        let long = vec![b'a'; 10_000];
        c.write_all(&long).unwrap();
        c.write_all(b"\nnext").unwrap();
        assert_eq!(read_line_by(&s, deadline).unwrap(), long);
        s.read_exact(&mut rest[..4]).unwrap();
        assert_eq!(&rest[..4], b"next");
        c.write_all(&vec![b'a'; MAX_LINE + 1]).unwrap();
        assert!(read_line_by(&s, deadline).unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn a_slow_sender_gets_one_deadline_for_the_whole_line() {
        use std::io::Write;
        let (mut c, s) = pair();
        let sender = std::thread::spawn(move || {
            // Each byte well within a per-read timeout of the whole deadline.
            for _ in 0..20 {
                if c.write_all(b"x").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = c.write_all(b"\n");
        });
        let start = Instant::now();
        let e = read_line_by(&s, start + Duration::from_millis(400)).unwrap_err();
        assert!(e.to_string().contains("in time"), "{e}");
        assert!(start.elapsed() < Duration::from_millis(1000), "{:?}", start.elapsed());
        drop(s);
        sender.join().unwrap();
    }

    #[test]
    fn an_ipv4_peer_on_a_dual_stack_socket_is_a_peer() {
        let peers = vec!["10.1.0.2:7070".to_string(), "[2001:db8::2]:7070".to_string()];
        let peers = Peers::default().addrs(&peers);
        for from in ["10.1.0.2", "::ffff:10.1.0.2", "2001:db8::2"] {
            assert!(is_peer(&peers, from.parse().unwrap()), "{from}");
        }
        for from in ["10.1.0.3", "::ffff:10.1.0.3", "::1", "2001:db8::3"] {
            assert!(!is_peer(&peers, from.parse().unwrap()), "{from}");
        }
        assert!(is_peer(&Peers::default().addrs(&["[::ffff:10.1.0.2]:7070".to_string()]), "10.1.0.2".parse().unwrap()));
        // Unresolvable now: kept as last resolved.
        let (p, name) = (Peers::default(), vec!["no-such-host.invalid:7070".to_string()]);
        p.0.resolved.write().unwrap().insert(name[0].clone(), vec!["10.1.0.2".parse().unwrap()]);
        p.refresh(&name);
        assert!(settled(&p, &name) && is_peer(&p.addrs(&name), "10.1.0.2".parse().unwrap()));
        // A name no longer configured counts for nothing, whatever is cached for it.
        assert!(p.addrs(&[]).is_empty());
        // One not resolved yet is looked up, and gets nothing meanwhile.
        let other = ["other.invalid:7070".to_string()];
        assert!(p.addrs(&other).is_empty() && p.0.lookups.lock().unwrap().contains_key(&other[0]));
    }

    /// Whether `names`' lookups have all ended, within 60 s (a bound on a hung lookup only: on a loaded machine
    /// one can take seconds).
    fn settled(p: &Peers, names: &[String]) -> bool {
        let ended = || names.iter().all(|n| p.0.lookups.lock().unwrap().get(n).is_some_and(|l| l.is_some()));
        (0..6000).any(|_| ended() || (std::thread::sleep(Duration::from_millis(10)), false).1)
    }

    fn host_with_peers(label: &str, peers: &[&str]) -> (crate::test_util::TempDir, Host) {
        let root = crate::test_util::TempDir::new(&format!("listen-{label}"));
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        host.configure(|c| {
            c.peers = peers.iter().map(|p| p.to_string()).collect();
            Ok(())
        })
        .unwrap();
        (root, host)
    }

    #[test]
    fn a_peer_by_name_is_admitted_once_its_lookup_completes() {
        let (_root, host) = host_with_peers("by-name", &["localhost:7070"]);
        let names = host.config_now().peers;
        // As at start, or for a peer just added: nothing resolved, so the accept loop hands it to a waiting slot.
        // The lookup under way is marked here, not run: a real one of localhost can end before `resolving` is asked (#294).
        let p = Peers::default();
        let local: [IpAddr; 2] = ["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
        p.0.lookups.lock().unwrap().insert(names[0].clone(), None);
        assert!(!p.admit(&names, local[0]) && p.resolving(&names) == (true, false) && p.check(&names, local[0]) == Admission::Unresolved);
        // A request that finds the name unresolved starts its lookup, and is admitted once it ends.
        p.0.lookups.lock().unwrap().clear();
        assert!(!p.admit(&names, local[0]) && p.0.lookups.lock().unwrap().contains_key(&names[0]));
        // Only a bound on a hung lookup: on a loaded machine one of localhost can take seconds.
        let by = Instant::now() + Duration::from_secs(60);
        assert!(local.iter().any(|&a| p.admit_by(&host, a, by)), "admitted once localhost resolved");
    }

    #[test]
    fn a_non_peer_is_refused_at_once_with_every_name_looked_up() {
        let (_root, host) = host_with_peers("non-peer", &["localhost:7070", "no-such-host.invalid:7070", "10.1.0.2:7070"]);
        let (p, names) = (Peers::default(), host.config_now().peers);
        p.addrs(&names);
        assert!(settled(&p, &names[..2]));
        // localhost resolved, the other failed: nothing under way to wait for. Each ended "now" for as long as this
        // takes, so the failed one is not looked up again (`LOOKUP_EVERY`) however slowly it runs (#294).
        p.0.lookups.lock().unwrap().values_mut().for_each(|l| *l = Some(Instant::now() + Duration::from_secs(3600)));
        assert_eq!(p.resolving(&names), (false, false));
        // Refused at once: `check` has its answer, so `admit_by` never waits (not timed, as a loaded machine can take
        // any time over it, #294).
        let from = "10.9.9.9".parse().unwrap();
        assert_eq!(p.check(&names, from), Admission::Refused);
        assert!(!p.admit_by(&host, from, Instant::now() + Duration::from_secs(60)));
    }

    #[test]
    fn one_source_cannot_take_every_wait() {
        let w = Waiting::new(MAX_WAITING, MAX_WAITING_FROM);
        let (one, other): (IpAddr, IpAddr) = ("10.9.9.9".parse().unwrap(), "10.1.0.2".parse().unwrap());
        let held: Vec<_> = (0..MAX_WAITING_FROM).map(|_| w.take(one).unwrap()).collect();
        assert!(w.take(one).is_none() && w.take("::ffff:10.9.9.9".parse().unwrap()).is_none());
        let peer = w.take(other).expect("another source still waits");
        drop(held);
        assert!(w.take(one).is_some(), "freed as each wait ends");
        drop(peer);
        // Many sources still share MAX_WAITING in all.
        let many: Vec<_> = (0..).map_while(|i: u32| w.take(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)))).collect();
        assert_eq!(many.len(), MAX_WAITING);
    }

    #[test]
    fn non_peers_waiting_on_a_refresh_take_only_its_small_budget() {
        let names = vec!["peer.test:7070".to_string(), "new.test:7070".to_string()];
        let p = Peers::default();
        // A refresh of a name with addresses under way (slow, or hung): unknown sources may wait, on `MAX_MOVED` only.
        p.0.resolved.write().unwrap().insert(names[0].clone(), vec!["10.1.0.2".parse().unwrap()]);
        p.0.lookups.lock().unwrap().insert(names[0].clone(), None);
        p.0.lookups.lock().unwrap().insert(names[1].clone(), Some(Instant::now() + Duration::from_secs(3600)));
        assert_eq!(p.check(&names, "10.9.9.9".parse().unwrap()), Admission::Moved);
        let moved = Waiting::new(MAX_MOVED, MAX_MOVED_FROM);
        let attackers: Vec<IpAddr> = (0..16).map(|i: u32| IpAddr::V4(Ipv4Addr::from(0x0a09_0000 + i))).collect();
        let held: Vec<_> = attackers.iter().flat_map(|&a| std::iter::repeat_n(a, 4)).filter_map(|a| moved.take(a)).collect();
        assert_eq!(held.len(), MAX_MOVED, "one each, four in all");
        // A name with no addresses yet still has #291's waits, all of them, for its peer.
        p.0.lookups.lock().unwrap().insert(names[1].clone(), None);
        assert_eq!(p.check(&names, "10.1.0.3".parse().unwrap()), Admission::Unresolved);
        let waits = Waiting::new(MAX_WAITING, MAX_WAITING_FROM);
        assert!(waits.take("10.1.0.3".parse().unwrap()).is_some());
    }

    #[test]
    fn a_lookup_ending_while_admitting_is_not_a_refusal() {
        let names = vec!["peer.test:7070".to_string()];
        let from: IpAddr = "10.1.0.2".parse().unwrap();
        for _ in 0..2000 {
            let p = Peers::default();
            p.0.lookups.lock().unwrap().insert(names[0].clone(), None);
            // As the lookup thread ends: published, then no longer under way.
            let q = p.clone();
            let lookup = std::thread::spawn(move || {
                q.0.resolved.write().unwrap().insert("peer.test:7070".into(), vec!["10.1.0.2".parse().unwrap()]);
                q.0.lookups.lock().unwrap().insert("peer.test:7070".into(), Some(Instant::now()));
            });
            assert_ne!(p.check(&names, from), Admission::Refused);
            lookup.join().unwrap();
            assert_eq!(p.check(&names, from), Admission::Peer);
        }
    }

    #[test]
    fn a_peer_by_name_on_a_new_address_is_admitted_before_the_refresh() {
        let (_root, host) = host_with_peers("moved", &["localhost:7070"]);
        let names = host.config_now().peers;
        let p = Peers::default();
        // Resolved before it moved (DHCP), and not looked up since `LOOKUP_EVERY`.
        p.0.resolved.write().unwrap().insert(names[0].clone(), vec!["10.1.0.2".parse().unwrap()]);
        let Some(long_ago) = Instant::now().checked_sub(LOOKUP_EVERY) else { return };
        p.0.lookups.lock().unwrap().insert(names[0].clone(), Some(long_ago));
        let local: [IpAddr; 2] = ["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
        // Not refused: looked up again, and waited for (on the moved budget, not #291's).
        assert!(matches!(p.check(&names, local[0]), Admission::Moved | Admission::Peer));
        assert_ne!(p.0.lookups.lock().unwrap()[&names[0]], Some(long_ago), "a lookup started");
        // Only a bound on a hung lookup: on a loaded machine one of localhost can take seconds.
        let by = Instant::now() + Duration::from_secs(60);
        assert!(local.iter().any(|&a| p.admit_by(&host, a, by)), "admitted once localhost resolved");
    }

    #[test]
    fn a_trickling_client_is_refused_by_one_deadline() {
        use std::io::Write;
        let (mut c, s) = pair();
        let sender = std::thread::spawn(move || {
            // Each byte well within a per-read timeout of the whole wait.
            for _ in 0..50 {
                if c.write_all(b"x").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let start = Instant::now();
        refuse(s, "no", Some(Duration::from_millis(400)));
        assert!(start.elapsed() < Duration::from_millis(2000), "{:?}", start.elapsed());
        sender.join().unwrap();
    }

    #[test]
    fn a_failing_name_is_looked_up_at_most_every_lookup_every() {
        let (p, name) = (Peers::default(), vec!["no-such-host.invalid:7070".to_string()]);
        p.addrs(&name);
        assert!(settled(&p, &name));
        // Ended "now" for as long as the requests below take, however slowly they run (#294).
        let ended = Some(Instant::now() + Duration::from_secs(3600));
        p.0.lookups.lock().unwrap().insert(name[0].clone(), ended);
        // Every request asks for it, none starts a lookup.
        for _ in 0..1000 {
            assert!(p.addrs(&name).is_empty());
        }
        assert_eq!(p.0.lookups.lock().unwrap()[&name[0]], ended);
        // Once LOOKUP_EVERY has passed, the next request looks it up again.
        let Some(long_ago) = Instant::now().checked_sub(LOOKUP_EVERY) else { return };
        p.0.lookups.lock().unwrap().insert(name[0].clone(), Some(long_ago));
        p.addrs(&name);
        assert_ne!(p.0.lookups.lock().unwrap()[&name[0]], Some(long_ago));
    }

    #[test]
    fn a_hung_lookup_holds_up_no_other_name() {
        let p = Peers::default();
        // Its lookup under way (and hung): never started again, never waited for.
        p.0.lookups.lock().unwrap().insert("hung.invalid:7070".into(), None);
        let names = ["hung.invalid:7070".to_string(), "localhost:7070".to_string(), "10.1.0.2:7070".to_string()];
        let start = Instant::now();
        p.refresh(&names);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(is_peer(&p.addrs(&names), "10.1.0.2".parse().unwrap()), "an address needs no lookup");
        let local = || is_peer(&p.addrs(&names), "127.0.0.1".parse().unwrap()) || is_peer(&p.addrs(&names), "::1".parse().unwrap());
        assert!((0..6000).any(|_| local() || (std::thread::sleep(Duration::from_millis(10)), false).1), "localhost resolved meanwhile");
        assert_eq!(p.0.lookups.lock().unwrap()["hung.invalid:7070"], None);
    }

    #[test]
    fn a_running_listener_takes_peers_configured_since() {
        let root = crate::test_util::TempDir::new("listen-peers");
        let running = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let p = Peers::default();
        let admit = |h: &Host, from| p.admit(&h.config_now().peers, from);
        let from = "10.1.0.9".parse().unwrap();
        assert!(!admit(&running, from));
        let mut other = running.clone();
        let set = |c: &mut crate::host::Config, p: &[&str]| {
            c.peers = p.iter().map(|p| p.to_string()).collect();
            Ok(())
        };
        other.configure(|c| set(c, &["10.1.0.9:7070"])).unwrap();
        assert!(admit(&running, from));
        // Unreadable (mid-write, or gone): the newest read stands, never the startup one.
        std::fs::write(running.state.join("host.json"), b"{\"peers\": [").unwrap();
        assert!(admit(&running, from));
        std::fs::remove_file(running.state.join("host.json")).unwrap();
        assert!(admit(&running, from));
        other.configure(|c| set(c, &[])).unwrap();
        assert!(!admit(&running, from));
    }

    #[test]
    fn an_ipv6_only_listener_cannot_advertise_an_ipv4_endpoint() {
        let at = |s: &str| s.parse::<SocketAddr>().unwrap();
        let v4 = Some("10.1.0.2:7070");
        assert!(unreachable_at(at("[::]:7070"), false, v4).is_none());
        assert!(unreachable_at(at("[::]:7070"), true, v4).is_some());
        assert!(unreachable_at(at("[fe80::1%3]:7070"), false, v4).is_some());
        assert!(unreachable_at(at("[2001:db8::1]:7070"), false, v4).is_some());
        assert!(unreachable_at(at("[::ffff:0.0.0.0]:7070"), true, v4).is_none());
        assert!(unreachable_at(at("0.0.0.0:7070"), false, v4).is_none());
        assert!(unreachable_at(at("[::]:7070"), true, Some("[2001:db8::1]:7070")).is_none());
        assert!(unreachable_at(at("[2001:db8::1]:7070"), true, Some("[2001:db8::1]:7070")).is_none());
        assert!(unreachable_at(at("[::]:7070"), true, None).is_none());
    }

    #[test]
    fn a_loopback_listener_is_refused_with_a_peer_elsewhere() {
        use crate::host::Toward;
        let at = |s: &str| s.parse::<SocketAddr>().unwrap();
        let remote = || Toward::Remote(Ipv4Addr::new(192, 168, 1, 11));
        let e = loopback_with_remote(at("127.0.0.1:7070"), remote).unwrap();
        assert!(e.contains("192.168.1.11 is elsewhere"), "{e}");
        assert!(loopback_with_remote(at("[::ffff:127.0.0.1]:7070"), remote).is_some());
        // Peers are not even looked up for an address that is not loopback.
        assert!(loopback_with_remote(at("0.0.0.0:7070"), || unreachable!()).is_none());
        // Peers on this machine, or none, or one whose address is unknown (a name that may yet be local): allowed.
        for t in [Toward::Local, Toward::Unknown] {
            assert!(loopback_with_remote(at("127.0.0.1:7070"), || t).is_none());
        }
    }

    /// What this host's kernel does with a dual-stack wildcard bind.
    #[test]
    fn a_wildcard_bind_reports_its_v6only() {
        let Ok(l) = TcpListener::bind("[::]:0") else { return };
        let sysctl = std::fs::read_to_string("/proc/sys/net/ipv6/bindv6only").unwrap_or_default();
        assert_eq!(v6only(&l), sysctl.trim() == "1");
    }
}
