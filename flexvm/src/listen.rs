//! The peer listener (`flexvm listen`): a stateless, restartable helper
//! (socket-activatable) that serves only configured peers. Each connection
//! starts with one JSON line, consumed exactly through its newline so nothing after it is:
//! `migrate_in`, `pages` (handed to the source VM process), `migration`
//! (status/done), `route`, `lend`, `source` (source liveness).

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::host::{fault, Host};
use crate::util::{send_json, Result, Slot};

/// Requests handled at once; more connections are closed unanswered.
const MAX_ACTIVE: usize = 512;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

pub fn validate(listener: &TcpListener, cfg: &crate::host::Config) -> Result<()> {
    if let Some(e) = unreachable_at(listener.local_addr()?, v6only(listener), cfg.advertise()?.as_deref()) {
        bail!("{e}");
    }
    Ok(())
}

pub fn main(host: Host, listener: TcpListener) -> Result<()> {
    crate::net::sysctl("net.ipv4.ip_forward", "1")?;
    if let Some(dev) = &host.cfg.announce_dev {
        crate::net::sysctl(&format!("net.ipv4.conf.{dev}.proxy_arp"), "1")?;
    }
    crate::log!("flexvm listening on {}", listener.local_addr()?);
    crate::standby::maintain(host.clone());
    crate::gc::periodic(host.clone());
    let peers = Peers::watch(host.clone());
    // Refusals are logged off the accept loop, never waiting on stderr: past 64 queued, dropped.
    let (refusals, queued) = std::sync::mpsc::sync_channel::<String>(64);
    std::thread::spawn(move || queued.into_iter().for_each(|e| crate::log!("peer request: {e}")));
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
        // Refused here, at once: a non-peer never takes a slot or a thread.
        match conn.peer_addr() {
            Ok(from) if peers.admit(&host, from.ip()) => {}
            Ok(from) => {
                refuse(conn, from.ip(), &refusals);
                continue;
            }
            Err(_) => continue,
        }
        let Some(slot) = Slot::take(&ACTIVE, MAX_ACTIVE) else { continue };
        let host = host.clone();
        std::thread::spawn(move || {
            let _slot = slot;
            let _ = conn.set_nodelay(true);
            if let Err(e) = handle(&host, conn, deadline) {
                crate::log!("peer request: {e}");
            }
        });
    }
    Ok(())
}

fn v6only(l: &TcpListener) -> bool {
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

/// The configured peers' addresses. Names are resolved off the request path,
/// each by a thread of its own (at most one per name, so one hung lookup holds
/// up no other), published as each finishes: at start, every `PEER_REFRESH`,
/// and soon after a request finds a name it has no addresses for; a name that
/// fails to resolve keeps the addresses it last had. Requests go by host.json as it is now
/// (`flexvm config --peer` reaches a running listener) and never wait on DNS:
/// an address given as such needs none, and a name no longer configured
/// counts for nothing, whatever a refresh still holds for it.
#[derive(Clone, Default)]
struct Peers(Arc<PeersInner>);

#[derive(Default)]
struct PeersInner {
    resolved: RwLock<HashMap<String, Vec<IpAddr>>>,
    wanted: (Mutex<bool>, Condvar),
    resolving: Mutex<HashSet<String>>,
}

const PEER_REFRESH: Duration = Duration::from_secs(30);

impl Peers {
    fn watch(host: Host) -> Peers {
        let peers = Peers::default();
        peers.refresh(&host.config_now().peers);
        let p = peers.clone();
        std::thread::spawn(move || loop {
            let (wanted, cv) = &p.0.wanted;
            let w = wanted.lock().unwrap();
            let mut w = cv.wait_timeout_while(w, PEER_REFRESH, |w| !*w).unwrap().0;
            *w = false;
            drop(w);
            p.refresh(&host.config_now().peers);
        });
        peers
    }

    /// Starts a lookup of each name that has none under way; never waits on one.
    fn refresh(&self, names: &[String]) {
        self.0.resolved.write().unwrap().retain(|n, _| names.contains(n));
        for n in names.iter().filter(|n| n.parse::<SocketAddr>().is_err()) {
            if !self.0.resolving.lock().unwrap().insert(n.clone()) {
                continue;
            }
            let (p, name) = (self.clone(), n.clone());
            let lookup = std::thread::Builder::new().spawn(move || {
                if let Ok(a) = name.to_socket_addrs() {
                    p.0.resolved.write().unwrap().insert(name.clone(), a.map(|a| a.ip()).collect());
                }
                p.0.resolving.lock().unwrap().remove(&name);
            });
            if lookup.is_err() {
                self.0.resolving.lock().unwrap().remove(n);
            }
        }
    }

    /// The addresses of `names`; a name not resolved yet asks the refresher.
    fn addrs(&self, names: &[String]) -> Vec<IpAddr> {
        let r = self.0.resolved.read().unwrap();
        let mut addrs = Vec::new();
        for n in names {
            match (n.parse::<SocketAddr>(), r.get(n)) {
                (Ok(a), _) => addrs.push(a.ip()),
                (_, Some(a)) => addrs.extend(a),
                _ => {
                    *self.0.wanted.0.lock().unwrap() = true;
                    self.0.wanted.1.notify_one();
                }
            }
        }
        addrs
    }

    fn admit(&self, host: &Host, from: IpAddr) -> bool {
        is_peer(&self.addrs(&host.config_now().peers), from)
    }
}

/// Tells a non-peer why, without waiting on it: what it already sent is
/// read off first, so the close does not reset the reply away.
fn refuse(mut conn: TcpStream, from: IpAddr, log: &std::sync::mpsc::SyncSender<String>) {
    let local = conn.local_addr().map(|a| a.to_string()).unwrap_or_default();
    let e = format!("{from} is not a peer of {local} (add it there: flexvm config --peer)");
    let _ = log.try_send(e.clone());
    if conn.set_nonblocking(true).is_ok() {
        let _ = send_json(&mut conn, &json!({"ok": false, "error": e}));
        let _ = conn.shutdown(std::net::Shutdown::Write);
        let mut buf = [0u8; 4096];
        for _ in 0..16 {
            if !matches!(conn.read(&mut buf), Ok(n) if n > 0) {
                break;
            }
        }
    }
}

pub fn activated() -> Option<TcpListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let n: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    (pid == std::process::id() && n >= 1).then(|| unsafe { TcpListener::from_raw_fd(3) })
}

/// From a peer: they are authenticated by address only (`main`), the network between them is trusted.
fn handle(host: &Host, mut conn: TcpStream, deadline: Instant) -> Result<()> {
    let line = read_line_by(&conn, deadline)?;
    let req: Value = serde_json::from_slice(&line)?;
    let reply = match req["op"].as_str().unwrap_or("") {
        "migrate_in" => return incoming(host, &req, &line, conn),
        "pages" => return pages(host, &req, conn),
        "migration" => migration(host, &req),
        "route" => route(host, &req),
        "lend" => lend(host, &req),
        // Whether a migration's source process is proven gone (never from published state).
        "source" => serde_json::from_value(req["ident"].clone())
            .map_err(|e| format!("bad ident: {e}").into())
            .map(|id: crate::host::Ident| json!({"gone": id.liveness() == crate::host::Liveness::Gone})),
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

/// Spawns the incoming VM process with the connection as fd 3; it answers the source.
fn incoming(host: &Host, req: &Value, line: &[u8], conn: TcpStream) -> Result<()> {
    let name = req["name"].as_str().unwrap_or("");
    let refuse = |mut c: &TcpStream, e: String| send_json(&mut c, &json!({"ok": false, "error": e}));
    if let Err(e) = crate::host::check_name(name) {
        refuse(&conn, e.to_string())?;
        return Ok(());
    }
    // Each arrival owns its log until accepted; refusing a duplicate name
    // must not remove the running VM's log.
    static ARRIVAL: AtomicUsize = AtomicUsize::new(0);
    // Locked for the arrival's life (its stdout shares the lock), so a dead
    // arrival's log is told from a live one's and swept (`gc`).
    let log_path = host.run.join("vms").join(format!("{}{}-{}.log", crate::gc::ARRIVAL_LOG, std::process::id(), ARRIVAL.fetch_add(1, Ordering::Relaxed)));
    let log = std::fs::OpenOptions::new().create_new(true).append(true).open(&log_path)?;
    crate::host::flock(&log, libc::LOCK_SH)?;
    let args = ["--state".as_ref(), host.state.as_os_str(), "--run".as_ref(), host.run.as_os_str(), "run".as_ref(), "--incoming".as_ref()];
    if let Err(e) = crate::util::spawn_self(
        &args,
        &log,
        conn.as_raw_fd(),
        &[("FLEXVM_INCOMING", std::str::from_utf8(line)?), ("FLEXVM_INCOMING_LOG", log_path.to_str().ok_or("non-UTF8 log path")?)],
    ) {
        let _ = std::fs::remove_file(log_path);
        refuse(&conn, format!("cannot start the vm process: {e}"))?;
    }
    Ok(())
}

/// Publish only an accepted arrival's log. A refused arrival owns only its
/// temporary file, even when the requested name already belongs to a VM.
pub fn finish_incoming_log(host: &Host, name: &str, log: &std::path::Path, accepted: bool) -> Result<()> {
    if accepted {
        std::fs::rename(log, host.vms(name, "log"))?;
    } else {
        std::fs::remove_file(log)?;
    }
    Ok(())
}

fn pages(host: &Host, req: &Value, conn: TcpStream) -> Result<()> {
    let name = req["name"].as_str().unwrap_or("");
    let fwd = json!({"op": "pages", "mig": req["mig"]});
    if let Err(e) = crate::vmproc::connect(host, name, &fwd, &[conn.as_raw_fd()], std::time::Instant::now() + std::time::Duration::from_secs(5)) {
        refuse_pages(conn, &format!("vm {name} is not the source of migration {}: {e}", req["mig"]));
    }
    Ok(())
}

pub fn refuse_pages(mut conn: TcpStream, why: &str) {
    let _ = send_json(&mut conn, &json!({"ok": false, "error": why}));
    // Drain the client's request so closing does not RST before it reads why.
    let _ = conn.shutdown(std::net::Shutdown::Write);
    let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(1)));
    let _ = std::io::copy(&mut (&mut conn).take(1 << 20), &mut std::io::sink());
}

fn migration(host: &Host, req: &Value) -> Result<Value> {
    if fault("status") {
        bail!("injected fault: migration status unavailable");
    }
    let mig = req["mig"].as_u64().ok_or("missing mig")?;
    if req["done"] == json!(true) {
        host.mig_done(mig)?;
        return Ok(json!({"done": true}));
    }
    let outcome = host.mig_status(mig)?;
    Ok(json!({"outcome": outcome, "underlay": host.cfg.underlay().map(|u| u.to_string())}))
}

fn lend(host: &Host, req: &Value) -> Result<Value> {
    let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
    let gen = host.lend_new(&host.lock()?, ip)?;
    Ok(json!({"ip": ip.to_string(), "gen": gen}))
}

/// Stale generations and revisions (see `host::Addr`) are ignored; an
/// address a VM here holds keeps its local route.
fn route(host: &Host, req: &Value) -> Result<Value> {
    let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
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
    let l = host.lock()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_arrival_removes_only_its_own_log() {
        let root = std::env::temp_dir().join(format!("flexvm-arrival-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let arrival = host.run.join("vms/.incoming.log");
        let existing = host.vms("web", "log");
        std::fs::write(&existing, b"existing vm").unwrap();
        std::fs::write(&arrival, b"refused").unwrap();
        finish_incoming_log(&host, "web", &arrival, false).unwrap();
        assert!(!arrival.exists());
        assert_eq!(std::fs::read(&existing).unwrap(), b"existing vm");
        std::fs::write(&arrival, b"accepted").unwrap();
        finish_incoming_log(&host, "web", &arrival, true).unwrap();
        assert!(!arrival.exists());
        assert_eq!(std::fs::read(&existing).unwrap(), b"accepted");
        std::fs::remove_dir_all(root).unwrap();
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
        let p = Peers::default();
        p.refresh(&peers);
        let peers = p.addrs(&peers);
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
        let settled = |p: &Peers| (0..500).any(|_| p.0.resolving.lock().unwrap().is_empty() || (std::thread::sleep(Duration::from_millis(10)), false).1);
        assert!(settled(&p) && is_peer(&p.addrs(&name), "10.1.0.2".parse().unwrap()));
        // A name no longer configured counts for nothing, whatever is cached for it.
        assert!(p.addrs(&[]).is_empty());
        // One not resolved yet asks the refresher, and gets nothing meanwhile.
        assert!(p.addrs(&["other.invalid:7070".to_string()]).is_empty() && *p.0.wanted.0.lock().unwrap());
    }

    #[test]
    fn a_hung_lookup_holds_up_no_other_name() {
        let p = Peers::default();
        // Its lookup under way (and hung): never started again, never waited for.
        p.0.resolving.lock().unwrap().insert("hung.invalid:7070".into());
        let names = ["hung.invalid:7070".to_string(), "localhost:7070".to_string(), "10.1.0.2:7070".to_string()];
        let start = Instant::now();
        p.refresh(&names);
        assert!(start.elapsed() < Duration::from_millis(100));
        assert!(is_peer(&p.addrs(&names), "10.1.0.2".parse().unwrap()), "an address needs no lookup");
        let local = || is_peer(&p.addrs(&names), "127.0.0.1".parse().unwrap()) || is_peer(&p.addrs(&names), "::1".parse().unwrap());
        assert!((0..500).any(|_| local() || (std::thread::sleep(Duration::from_millis(10)), false).1), "localhost resolved meanwhile");
        assert!(p.0.resolving.lock().unwrap().contains("hung.invalid:7070"));
    }

    #[test]
    fn a_running_listener_takes_peers_configured_since() {
        let root = std::env::temp_dir().join(format!("flexvm-listen-peers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let running = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let peers = Peers::default();
        let from = "10.1.0.9".parse().unwrap();
        assert!(!peers.admit(&running, from));
        let mut other = running.clone();
        let set = |c: &mut crate::host::Config, p: &[&str]| {
            c.peers = p.iter().map(|p| p.to_string()).collect();
            Ok(())
        };
        other.configure(|c| set(c, &["10.1.0.9:7070"])).unwrap();
        assert!(peers.admit(&running, from));
        // Unreadable (mid-write, or gone): the newest read stands, never the startup one.
        std::fs::write(running.state.join("host.json"), b"{\"peers\": [").unwrap();
        assert!(peers.admit(&running, from));
        std::fs::remove_file(running.state.join("host.json")).unwrap();
        assert!(peers.admit(&running, from));
        other.configure(|c| set(c, &[])).unwrap();
        assert!(!peers.admit(&running, from));
        std::fs::remove_dir_all(root).unwrap();
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

    /// What this host's kernel does with a dual-stack wildcard bind.
    #[test]
    fn a_wildcard_bind_reports_its_v6only() {
        let Ok(l) = TcpListener::bind("[::]:0") else { return };
        let sysctl = std::fs::read_to_string("/proc/sys/net/ipv6/bindv6only").unwrap_or_default();
        assert_eq!(v6only(&l), sysctl.trim() == "1");
    }
}
