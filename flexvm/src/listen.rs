//! The peer listener (`flexvm listen`): a stateless, restartable helper
//! (socket-activatable) that serves only configured peers. Each connection
//! starts with one JSON line, consumed exactly through its newline so nothing after it is:
//! `migrate_in`, `pages` (handed to the source VM process), `migration`
//! (status/done), `route`, `lend`, `source` (source liveness).

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
const BUSY: &str = "host busy, try again";
/// Arrival processes from their start until they commit or are refused (or end), in all
/// and from any one peer address; more arrivals are refused at once, before their source
/// pauses anything.
const MAX_ARRIVALS: usize = 8;
const MAX_ARRIVALS_FROM: usize = MAX_ARRIVALS / 2;
static ARRIVALS: std::sync::LazyLock<Waiting> = std::sync::LazyLock::new(|| Waiting::new(MAX_ARRIVALS, MAX_ARRIVALS_FROM));
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

pub fn validate(listener: &TcpListener, cfg: &crate::host::Config) -> Result<()> {
    let local = listener.local_addr()?;
    if let Some(e) = unreachable_at(local, v6only(listener), cfg.advertise()?.as_deref()) {
        bail!("{e}");
    }
    // Bounded: this runs under the host lock.
    let by = Instant::now() + Duration::from_secs(2);
    let resolve = |p: &String| crate::util::resolve(p, by).map(|a| a.iter().map(SocketAddr::ip).collect()).unwrap_or_default();
    let toward = || crate::host::toward(&cfg.peers.iter().map(resolve).collect::<Vec<_>>(), |a| crate::net::is_local_addr(a).unwrap_or(false));
    if let Some(e) = loopback_with_remote(local, toward) {
        bail!("{e}");
    }
    Ok(())
}

/// A loopback listener is reachable, and a loopback underlay usable, only by peers on this machine.
fn loopback_with_remote(local: SocketAddr, toward: impl FnOnce() -> crate::host::Toward) -> Option<String> {
    if !local.ip().to_canonical().is_loopback() {
        return None;
    }
    let crate::host::Toward::Remote(peer) = toward() else { return None };
    Some(format!("{local} is loopback, but peer {peer} is elsewhere and cannot reach it; listen on 0.0.0.0 or this host's address toward it"))
}

pub fn main(host: Host, listener: TcpListener) -> Result<()> {
    crate::net::ip_forward()?;
    let dev = host.cfg.announce_dev();
    if let Some(dev) = &dev {
        crate::net::proxy_arp(dev);
    }
    let underlay = host.cfg.underlay().map_or("none".into(), |u| u.to_string());
    crate::log!("flexvm listening on {} (underlay {underlay}, announce device {})", listener.local_addr()?, dev.as_deref().unwrap_or("none"));
    crate::standby::maintain(host.clone());
    crate::gc::periodic(host.clone());
    let peers = Peers::watch(host.clone());
    let (waits, moved) = (Waiting::new(MAX_WAITING, MAX_WAITING_FROM), Waiting::new(MAX_MOVED, MAX_MOVED_FROM));
    let host = std::sync::Arc::new(host);
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
                let (host, peers) = (host.clone(), peers.clone());
                std::thread::spawn(move || serve(&host, &peers, conn, slot, deadline));
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
        let (host, peers) = (host.clone(), peers.clone());
        std::thread::spawn(move || {
            let admitted = peers.admit_by(&host, from, Instant::now() + ADMIT_WAIT);
            drop(waiting);
            match admitted.then(|| ACTIVE.take(from)).flatten() {
                Some(slot) => serve(&host, &peers, conn, slot, deadline),
                None if !admitted => not_a_peer(conn, from),
                None => {}
            }
        });
    }
    Ok(())
}

fn serve(host: &Host, peers: &Peers, conn: TcpStream, _slot: Wait, deadline: Instant) {
    let _ = conn.set_nodelay(true);
    if let Err(e) = handle(host, peers, conn, deadline) {
        crate::log!("peer request: {e}");
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
}

const PEER_REFRESH: Duration = Duration::from_secs(30);
const LOOKUP_EVERY: Duration = Duration::from_secs(2);
/// How long an unknown address waits for a lookup under way, well within a
/// peer's deadline for its call (`vmproc::peer_call`).
const ADMIT_WAIT: Duration = Duration::from_millis(1500);

impl Peers {
    fn watch(host: Host) -> Peers {
        let peers = Peers::default();
        let p = peers.clone();
        std::thread::spawn(move || loop {
            let names = host.config_now().peers;
            p.0.resolved.write().unwrap().retain(|n, _| names.contains(n));
            p.0.lookups.lock().unwrap().retain(|n, l| l.is_none() || names.contains(n));
            p.refresh(&names);
            std::thread::sleep(PEER_REFRESH);
        });
        peers
    }

    /// Starts a lookup of each name that has none under way nor one ended
    /// within `LOOKUP_EVERY`; never waits on one.
    fn refresh<'a>(&self, names: impl IntoIterator<Item = &'a String>) {
        let mut lookups = self.0.lookups.lock().unwrap();
        for n in names.into_iter().filter(|n| n.parse::<SocketAddr>().is_err()) {
            if lookups.get(n).is_some_and(|l| l.is_none_or(|t| t.elapsed() < LOOKUP_EVERY)) {
                continue;
            }
            let (p, name) = (self.clone(), n.clone());
            let lookup = std::thread::Builder::new().spawn(move || {
                if let Ok(a) = crate::util::lookup(&name) {
                    p.0.resolved.write().unwrap().insert(name.clone(), a.iter().map(|a| a.ip()).collect());
                }
                p.0.lookups.lock().unwrap().insert(name, Some(Instant::now()));
            });
            lookups.insert(n.clone(), if lookup.is_ok() { None } else { Some(Instant::now()) });
        }
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

    /// `addrs` once no name without addresses has its lookup under way (it could give any
    /// address), waiting for one until `by`, then an error: asked again, it may have ended. A
    /// lookup that ended with none (a name that does not resolve) gives none (#411).
    fn all_addrs(&self, names: &[String], by: Instant) -> Result<Vec<IpAddr>> {
        loop {
            let addrs = self.addrs(names);
            if !self.resolving(names).0 {
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
    let e = format!("{from} is not a peer of {local} (add it there: flexvm config --peer)");
    // A flood of non-peers is counted, not logged line by line.
    static WINDOW: Mutex<RefusalLog> = Mutex::new(RefusalLog { second: 0, logged: 0, unlogged: 0 });
    let second = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let logged = WINDOW.lock().unwrap_or_else(|p| p.into_inner()).take(second);
    match logged {
        Some(0) => crate::log!("peer request: {e}"),
        Some(n) => crate::log!("peer request: {e} ({n} refusals before it not logged)"),
        None => {}
    }
    refuse(conn, &e, None);
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
fn handle(host: &Host, peers: &Peers, mut conn: TcpStream, deadline: Instant) -> Result<()> {
    let line = read_line_by(&conn, deadline)?;
    let req: Value = serde_json::from_slice(&line)?;
    let op = req["op"].as_str().unwrap_or("");
    let locking = matches!(op, "migration" | "route" | "lend").then(|| Slot::take(&LOCKING, MAX_LOCKING));
    let reply = match op {
        "migrate_in" => return incoming(host, &req, &line, conn, deadline - REQUEST_DEADLINE + PREPARE_WAIT),
        "pages" => return pages(host, &req, conn),
        _ if matches!(locking, Some(None)) => Err(BUSY.into()),
        "migration" => migration(host, &req),
        // Its peers by address, those configured by name too, and the one asking.
        "route" => peers
            .all_addrs(&host.config_now().peers, Instant::now() + ADMIT_WAIT)
            .and_then(|p| route(host, &req, &[p, conn.peer_addr().into_iter().map(|a| a.ip()).collect()].concat())),
        "lend" => peers
            .all_addrs(&host.config_now().peers, Instant::now() + ADMIT_WAIT)
            .and_then(|p| lend(host, &req, &[p, conn.peer_addr().into_iter().map(|a| a.ip()).collect()].concat())),
        // Whether a migration's source process is proven gone (never from published state).
        "source" => serde_json::from_value(req["ident"].clone())
            .map_err(|e| format!("bad ident: {e}").into())
            // One whose migration's outcome this host still owes counts as there: its target keeps the record it will ask about.
            .map(|id: crate::host::Ident| json!({"gone": id.liveness() == crate::host::Liveness::Gone && !host.owes(&id)})),
        op => Err(format!("unknown op {op:?}").into()),
    };
    let reply = match reply {
        Ok(v) => json!({"ok": true, "result": v}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    };
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
fn incoming(host: &Host, req: &Value, line: &[u8], conn: TcpStream, by: Instant) -> Result<()> {
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
    let lock = crate::host::private_file(&lock_path)?;
    crate::host::flock(&lock, libc::LOCK_SH)?;
    let log = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().create_new(true).append(true).mode(0o600).open(&log_path).inspect_err(|_| drop(std::fs::remove_file(&lock_path)))?
    };
    let args = ["--state".as_ref(), host.state.as_os_str(), "--run".as_ref(), host.run.as_os_str(), "run".as_ref(), "--incoming".as_ref()];
    let (done, told) = std::os::unix::net::UnixStream::pair()?;
    let by = (monotonic_ms() + by.saturating_duration_since(Instant::now()).as_millis() as u64).to_string();
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
        crate::log!("migration {}: page request for {name:?} refused: {e}", req["mig"]);
        crate::vmproc::refuse_not_source(conn, name, &req["mig"]);
    }
    Ok(())
}

/// The host lock, waited for `LOCK_WAIT` at most: then refused as busy.
fn host_lock(host: &Host) -> Result<crate::host::Locked> {
    host.lock_by(Some(Instant::now() + LOCK_WAIT)).map_err(|e| match e.downcast_ref::<std::io::Error>().map(|e| e.kind()) {
        Some(std::io::ErrorKind::WouldBlock) => BUSY.into(),
        _ => e,
    })
}

fn migration(host: &Host, req: &Value) -> Result<Value> {
    if fault("status") {
        bail!("injected fault: migration status unavailable");
    }
    let mig = req["mig"].as_u64().ok_or("missing mig")?;
    // Held through `mig_done` or `mig_status`, which take it again (reentrant) without waiting.
    let _l = host_lock(host)?;
    if req["done"] == json!(true) {
        if host.mig_done(mig)? {
            crate::log!("migration {mig}: its source says done; forgetting it");
        }
        return Ok(json!({"done": true}));
    }
    let outcome = host.mig_status(mig)?;
    Ok(json!({"outcome": outcome, "underlay": host.config_now().underlay().map(|u| u.to_string())}))
}

fn lend(host: &Host, req: &Value, peers: &[IpAddr]) -> Result<Value> {
    let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
    routable(ip, &host.config_now(), peers, &crate::net::gateways(&std::fs::read_to_string("/proc/net/route")?))?;
    let gen = host.lend_new(&host_lock(host)?, ip)?;
    Ok(json!({"ip": ip.to_string(), "gen": gen}))
}

/// Stale generations and revisions (see `host::Addr`) are ignored; an
/// address a VM here holds keeps its local route.
/// Test fault `route_refuse`: refused, as by a listener that is down.
fn route(host: &Host, req: &Value, peers: &[IpAddr]) -> Result<Value> {
    if fault("route_refuse") {
        bail!("injected fault: route messages refused");
    }
    let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
    routable(ip, &host.config_now(), peers, &crate::net::gateways(&std::fs::read_to_string("/proc/net/route")?))?;
    let gen = req["gen"].as_u64().filter(|&g| g > 0).ok_or("route messages carry the address's generation")?;
    let via: Option<Ipv4Addr> = req["via"].as_str().map(|v| v.parse()).transpose()?;
    let rev = match via {
        Some(_) => req["rev"].as_u64().ok_or("route announcements carry the location's revision")?,
        None => 0,
    };
    if let Some(via) = via.filter(|_| fault("route_stall")) {
        // Test hook: an announcement held up (as by a slow network) while armed.
        crate::log!("route {ip} via {via}: held up (injected fault)");
        while fault("route_stall") {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let l = host_lock(host)?;
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
}

/// Validate addresses from migrations and checkpoints before preparing or claiming them.
pub fn check_vm_ip(host: &Host, ip: Ipv4Addr, from: Option<IpAddr>, by: Instant) -> Result<()> {
    static PEERS: std::sync::LazyLock<Peers> = std::sync::LazyLock::new(Peers::default);
    let cfg = host.config_now();
    PEERS.refresh(&cfg.peers);
    let mut peers = PEERS.all_addrs(&cfg.peers, by)?;
    peers.extend(from);
    routable(ip, &cfg, &peers, &crate::net::gateways(&std::fs::read_to_string("/proc/net/route")?))
}

/// A peer routes only a VM's address, never one this host reaches its peers or network by (#365).
fn routable(ip: Ipv4Addr, cfg: &crate::host::Config, peers: &[IpAddr], gateways: &[Ipv4Addr]) -> Result<()> {
    let peer = is_peer(peers, IpAddr::V4(ip));
    let special = ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || cfg.underlay() == Some(ip) || gateways.contains(&ip);
    if peer || special || crate::net::is_local_addr(ip)? {
        bail!("{ip} is not a vm's address: a local, peer, underlay or gateway address, or not unicast");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn lend_refuses_peer_addresses_without_creating_a_record() {
        let root = crate::test_util::TempDir::new("lend-peer");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let ip = "10.9.0.1";
        let e = lend(&host, &json!({"ip": ip}), &[ip.parse().unwrap()]).unwrap_err();
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
    fn peers_route_only_vm_addresses() {
        let cfg = crate::host::Config {
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
        p.0.resolved.write().unwrap().insert("peer.example:7000".into(), vec!["10.94.0.1".parse().unwrap()]);
        let peers = [p.all_addrs(&cfg.peers, soon()).unwrap(), vec!["10.95.0.1".parse().unwrap()]].concat();
        let check = |ip: &str| routable(ip.parse().unwrap(), &cfg, &peers, &[gw]);
        for ip in ["127.0.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1", "10.98.0.1", "10.94.0.1", "10.97.0.1", "10.96.0.1", "10.95.0.1"] {
            assert!(check(ip).is_err(), "{ip} is refused");
        }
        check("10.200.0.7").unwrap();
    }

    #[test]
    fn refused_arrival_removes_only_its_own_log() {
        let root = crate::test_util::TempDir::new("arrival-log");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let arrival = host.run.join("vms/.incoming.log");
        let existing = host.vms("web", "log").unwrap();
        std::fs::write(&existing, b"existing vm").unwrap();
        std::fs::write(&arrival, b"refused").unwrap();
        finish_incoming_log(&host, "web", &arrival, false).unwrap();
        assert!(!arrival.exists());
        assert_eq!(std::fs::read(&existing).unwrap(), b"existing vm");
        std::fs::write(&arrival, b"accepted").unwrap();
        finish_incoming_log(&host, "web", &arrival, true).unwrap();
        assert!(!arrival.exists());
        assert_eq!(std::fs::read(&existing).unwrap(), b"accepted");
    }

    #[test]
    fn arrivals_past_either_bound_or_without_a_reaper_are_refused_at_once_starting_nothing() {
        let root = crate::test_util::TempDir::new("arrivals-full");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let line = br#"{"op":"migrate_in","name":"web"}"#;
        let refused = |why: &str| {
            let (client, server) = pair();
            let start = Instant::now();
            incoming(&host, &serde_json::from_slice(line).unwrap(), line, server, Instant::now() + PREPARE_WAIT).unwrap();
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
            incoming(&host, &serde_json::from_slice(line).unwrap(), line, server, Instant::now() + PREPARE_WAIT).unwrap();
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
        use std::io::Write;
        let root = crate::test_util::TempDir::new("listen-busy");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let ask = |req: Value| {
            let (client, server) = pair();
            let (start, mut line) = (Instant::now(), req.to_string().into_bytes());
            line.push(b'\n');
            (&client).write_all(&line).unwrap();
            handle(&host, &Peers::default(), server, Instant::now() + REQUEST_DEADLINE).unwrap();
            let reply = crate::util::recv_json(&mut std::io::BufReader::new(&client)).unwrap().unwrap();
            (reply, start.elapsed())
        };
        let requests = [json!({"op": "lend", "ip": "10.200.0.7"}), json!({"op": "migration", "mig": 7}), json!({"op": "route", "ip": "10.200.0.8", "gen": 3})];
        // Held by another process, as one stopped while holding it would.
        let held = crate::host::private_file(&host.lock_file()).unwrap();
        crate::host::flock(&held, libc::LOCK_EX).unwrap();
        std::thread::scope(|s| {
            let waits: Vec<_> = requests.iter().map(|r| s.spawn(|| ask(r.clone()))).collect();
            for w in waits {
                let (reply, took) = w.join().unwrap();
                assert_eq!(reply["error"], BUSY, "{reply}");
                assert!(took >= LOCK_WAIT && took < LOCK_WAIT + Duration::from_secs(2), "{took:?}");
            }
        });
        // Its budget taken: refused at once, the lock never waited for.
        let full: Vec<_> = std::iter::from_fn(|| Slot::take(&LOCKING, MAX_LOCKING)).collect();
        assert!(full.len() <= MAX_LOCKING && Slot::take(&LOCKING, MAX_LOCKING).is_none());
        for r in &requests {
            let (reply, took) = ask(r.clone());
            assert!(reply["error"] == BUSY && took < Duration::from_secs(1), "{reply} {took:?}");
        }
        // Answered (its refusal then drains what the client sent, `vmproc::refuse_pages`).
        let (reply, _) = ask(json!({"op": "pages", "name": "web", "mig": 7}));
        assert!(reply["error"].as_str().unwrap().contains("not the source"), "{reply}");
        drop(full);
        drop(held);
        // Lent once free (other tests' hosts share this process's lock threads: a few tries).
        let reply = (0..5).map(|_| ask(requests[0].clone()).0).find(|r| r["error"] != BUSY).expect("lent");
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
