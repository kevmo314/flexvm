//! The peer listener (`flexvm listen`): a stateless, restartable helper
//! (socket-activatable) that serves only configured peers. Each connection
//! starts with one JSON line, read unbuffered so nothing after it is consumed:
//! `migrate_in`, `pages` (handed to the source VM process), `migration`
//! (status/done), `route`, `lend`.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

use crate::bail;
use crate::host::{fault, Host};
use crate::util::{send_json, Result};

/// Requests handled at once; more connections are closed unanswered.
const MAX_ACTIVE: usize = 512;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

pub fn main(host: Host) -> Result<()> {
    let listener = match activated() {
        Some(l) => l,
        None => {
            let addr = host.cfg.listen.clone().ok_or("listen needs an address (flexvm listen ADDR)")?;
            TcpListener::bind(&addr).map_err(|e| format!("listen on {addr}: {e}"))?
        }
    };
    if let Some(e) = unreachable_at(listener.local_addr()?, v6only(&listener), host.cfg.advertise()?.as_deref()) {
        bail!("{e}");
    }
    crate::net::sysctl("net.ipv4.ip_forward", "1")?;
    if let Some(dev) = &host.cfg.announce_dev {
        crate::net::sysctl(&format!("net.ipv4.conf.{dev}.proxy_arp"), "1")?;
    }
    eprintln!("flexvm listening on {}", listener.local_addr()?);
    let host = std::sync::Arc::new(host);
    for conn in listener.incoming() {
        let conn = match conn {
            Ok(c) => c,
            Err(e) => {
                crate::util::accept_failed("peer listener", &e);
                continue;
            }
        };
        if ACTIVE.fetch_add(1, Ordering::SeqCst) >= MAX_ACTIVE {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let host = host.clone();
        std::thread::spawn(move || {
            let _ = conn.set_nodelay(true);
            if let Err(e) = handle(&host, conn) {
                eprintln!("peer request: {e}");
            }
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
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
        format!("{local} takes no IPv4 connections, but peers are told to reach this host at {}; listen on 0.0.0.0, a dual-stack [::] or the underlay address", advertised.unwrap_or_default())
    })
}

/// Peers are compared by address, an IPv4 one also as it arrives on a
/// dual-stack socket (::ffff:a.b.c.d).
fn is_peer(peers: &[String], from: IpAddr) -> bool {
    peers.iter().filter_map(|p| p.to_socket_addrs().ok()).flatten().any(|a| a.ip().to_canonical() == from.to_canonical())
}

fn activated() -> Option<TcpListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let n: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    (pid == std::process::id() && n >= 1).then(|| unsafe { TcpListener::from_raw_fd(3) })
}

fn handle(host: &Host, mut conn: TcpStream) -> Result<()> {
    // Peers are authenticated by address only: the network between them is trusted.
    let from = conn.peer_addr()?.ip();
    if !is_peer(&host.cfg.peers, from) {
        bail!("{from} is not a peer of this host (flexvm listen --peer)");
    }
    let line = read_line(&mut conn)?;
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
            .map(|id| json!({"gone": crate::host::gone(&id)})),
        op => Err(format!("unknown op {op:?}").into()),
    };
    let reply = match reply {
        Ok(v) => json!({"ok": true, "result": v}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    };
    send_json(&mut conn, &reply)?;
    Ok(())
}

/// Byte by byte: whatever follows belongs to whoever gets the connection next.
fn read_line(conn: &mut TcpStream) -> Result<Vec<u8>> {
    conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while line.len() < 64 << 10 {
        if conn.read(&mut b)? == 0 {
            bail!("peer hung up");
        }
        if b[0] == b'\n' {
            conn.set_read_timeout(None)?;
            return Ok(line);
        }
        line.push(b[0]);
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
    let log = std::fs::OpenOptions::new().create(true).append(true).open(host.run.join("vms").join(format!("{name}.log")))?;
    let args = ["--state".as_ref(), host.state.as_os_str(), "--run".as_ref(), host.run.as_os_str(), "run".as_ref(), "--incoming".as_ref()];
    if let Err(e) = crate::util::spawn_self(&args, &log, conn.as_raw_fd(), &[("FLEXVM_INCOMING", std::str::from_utf8(line)?)]) {
        refuse(&conn, format!("cannot start the vm process: {e}"))?;
    }
    Ok(())
}

fn pages(host: &Host, req: &Value, conn: TcpStream) -> Result<()> {
    let name = req["name"].as_str().unwrap_or("");
    let fwd = json!({"op": "pages", "mig": req["mig"]});
    if let Err(e) = crate::vmproc::connect(host, name, &fwd, &[conn.as_raw_fd()]) {
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

/// Stale generations (see `host::Addr`) are ignored; an address a VM here
/// holds keeps its local route.
fn route(host: &Host, req: &Value) -> Result<Value> {
    let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
    let gen = req["gen"].as_u64().filter(|&g| g > 0).ok_or("route messages carry the address's generation")?;
    let via: Option<Ipv4Addr> = req["via"].as_str().map(|v| v.parse()).transpose()?;
    let l = host.lock()?;
    if !host.observe(&l, ip, gen, via)? {
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
    fn an_ipv4_peer_on_a_dual_stack_socket_is_a_peer() {
        let peers = vec!["10.1.0.2:7070".to_string(), "[2001:db8::2]:7070".to_string()];
        for from in ["10.1.0.2", "::ffff:10.1.0.2", "2001:db8::2"] {
            assert!(is_peer(&peers, from.parse().unwrap()), "{from}");
        }
        for from in ["10.1.0.3", "::ffff:10.1.0.3", "::1", "2001:db8::3"] {
            assert!(!is_peer(&peers, from.parse().unwrap()), "{from}");
        }
        assert!(is_peer(&["[::ffff:10.1.0.2]:7070".to_string()], "10.1.0.2".parse().unwrap()));
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
