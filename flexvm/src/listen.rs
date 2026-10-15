//! The peer listener (`flexvm listen`): a stateless, restartable helper
//! (socket-activatable) that serves only configured peers. Each connection
//! starts with one JSON line, consumed exactly through its newline so nothing after it is:
//! `migrate_in`, `pages` (handed to the source VM process), `migration`
//! (status/done), `route`, `lend`, `source` (source liveness).

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
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
    eprintln!("flexvm listening on {}", listener.local_addr()?);
    crate::standby::maintain(host.clone());
    crate::gc::periodic(host.clone());
    let peers = Peers::watch(host.clone());
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
        let Some(slot) = Slot::take(&ACTIVE, MAX_ACTIVE) else { continue };
        let (host, peers) = (host.clone(), peers.clone());
        std::thread::spawn(move || {
            let _slot = slot;
            let _ = conn.set_nodelay(true);
            if let Err(e) = handle(&host, &peers, conn, deadline) {
                eprintln!("peer request: {e}");
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

/// The configured peers' addresses, resolved off the request path: at start,
/// then every `PEER_REFRESH` in the background, from host.json as it is then
/// (`flexvm config --peer` reaches a running listener). A name that fails to
/// resolve keeps the addresses it last had.
#[derive(Clone)]
struct Peers(Arc<RwLock<Vec<Peer>>>);

/// A configured peer and the addresses it last resolved to.
type Peer = (String, Vec<IpAddr>);

const PEER_REFRESH: Duration = Duration::from_secs(30);

impl Peers {
    fn new(names: &[String]) -> Peers {
        let peers = Peers(Arc::new(RwLock::new(Vec::new())));
        peers.refresh(names);
        peers
    }

    fn watch(host: Host) -> Peers {
        let peers = Peers::new(&host.config_now().peers);
        let p = peers.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(PEER_REFRESH);
            p.refresh(&host.config_now().peers);
        });
        peers
    }

    fn refresh(&self, names: &[String]) {
        let resolved: Vec<_> = names.iter().map(|n| n.to_socket_addrs().ok().map(|a| a.map(|a| a.ip()).collect::<Vec<_>>())).collect();
        let mut w = self.0.write().unwrap();
        let last = |n: &String| w.iter().find(|(o, _)| o == n).map(|(_, a)| a.clone()).unwrap_or_default();
        *w = names.iter().zip(resolved).map(|(n, new)| (n.clone(), new.unwrap_or_else(|| last(n)))).collect();
    }

    /// Whether `from` is a peer by the configuration as it is now: changed peers are resolved at once.
    fn admit(&self, host: &Host, from: IpAddr) -> bool {
        let names = host.config_now().peers;
        if !self.0.read().unwrap().iter().map(|(n, _)| n).eq(names.iter()) {
            self.refresh(&names);
        }
        is_peer(&self.addrs(), from)
    }

    fn addrs(&self) -> Vec<IpAddr> {
        self.0.read().unwrap().iter().flat_map(|(_, a)| a.iter().copied()).collect()
    }
}

pub fn activated() -> Option<TcpListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let n: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    (pid == std::process::id() && n >= 1).then(|| unsafe { TcpListener::from_raw_fd(3) })
}

fn handle(host: &Host, peers: &Peers, mut conn: TcpStream, deadline: Instant) -> Result<()> {
    // Peers are authenticated by address only: the network between them is trusted.
    let from = conn.peer_addr()?.ip();
    if !peers.admit(host, from) {
        // Told why, not just hung up on; its request is read first (briefly), so closing does not reset the reply.
        let e = format!("{from} is not a peer of {} (add it there: flexvm config --peer)", conn.local_addr()?);
        let _ = read_line_by(&conn, deadline.min(Instant::now() + Duration::from_secs(1)));
        let _ = send_json(&mut conn, &json!({"ok": false, "error": e}));
        bail!("{e}");
    }
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
        eprintln!("route {ip} via {via}: held up (injected fault)");
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
        let peers = Peers::new(&peers).addrs();
        for from in ["10.1.0.2", "::ffff:10.1.0.2", "2001:db8::2"] {
            assert!(is_peer(&peers, from.parse().unwrap()), "{from}");
        }
        for from in ["10.1.0.3", "::ffff:10.1.0.3", "::1", "2001:db8::3"] {
            assert!(!is_peer(&peers, from.parse().unwrap()), "{from}");
        }
        assert!(is_peer(&Peers::new(&["[::ffff:10.1.0.2]:7070".to_string()]).addrs(), "10.1.0.2".parse().unwrap()));
        // Unresolvable now: kept as last resolved.
        let p = Peers::new(&["10.1.0.2:7070".to_string()]);
        p.0.write().unwrap()[0].0 = "no-such-host.invalid:7070".into();
        p.refresh(&["no-such-host.invalid:7070".to_string()]);
        assert!(is_peer(&p.addrs(), "10.1.0.2".parse().unwrap()));
        // A peer no longer configured is not one.
        p.refresh(&[]);
        assert!(!is_peer(&p.addrs(), "10.1.0.2".parse().unwrap()));
    }

    #[test]
    fn a_running_listener_takes_peers_configured_since() {
        let root = std::env::temp_dir().join(format!("flexvm-listen-peers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let running = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let peers = Peers::new(&running.config_now().peers);
        let from = "10.1.0.9".parse().unwrap();
        assert!(!peers.admit(&running, from));
        let mut other = running.clone();
        let set = |c: &mut crate::host::Config, p: &[&str]| {
            c.peers = p.iter().map(|p| p.to_string()).collect();
            Ok(())
        };
        other.configure(|c| set(c, &["10.1.0.9:7070"])).unwrap();
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
