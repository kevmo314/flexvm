//! The peer listener (`flexvm listen`): an optional, stateless helper that
//! receives migrations. It can be socket-activated (`LISTEN_FDS`) and
//! restarted at any time; everything it knows is in the host's files.
//!
//! Each connection starts with one JSON line, read unbuffered so nothing
//! after it is consumed:
//! - `migrate_in`: spawns `flexvm run --incoming`, handing it the connection;
//! - `pages`: passes the connection to the VM process named (the source of
//!   a migration), whose page server takes it from there;
//! - `migration`: how an incoming migration went (see `Host::mig_status`),
//!   or (`done`) that its source will not ask again;
//! - `route`: a peer announces or withdraws a VM address.

use std::io::Read;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

use crate::bail;
use crate::host::{fault, Host};
use crate::util::{send_json, Result};

/// Requests handled at once; more connections are closed unanswered. Each
/// has 10 s to send its request line.
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
    crate::net::sysctl("net.ipv4.ip_forward", "1")?;
    if let Some(dev) = &host.cfg.announce_dev {
        crate::net::sysctl(&format!("net.ipv4.conf.{dev}.proxy_arp"), "1")?;
    }
    eprintln!("flexvm listening on {}", listener.local_addr()?);
    let host = std::sync::Arc::new(host);
    for conn in listener.incoming() {
        let conn = match conn {
            Ok(c) => c,
            // A client gone before accept, or a signal, says nothing about resources.
            Err(e) if matches!(e.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::ConnectionAborted) => continue,
            Err(e) => {
                // Out of fds, say: wait rather than spin.
                eprintln!("accept: {e}");
                std::thread::sleep(std::time::Duration::from_millis(100));
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

/// The listening socket systemd passed, if any.
fn activated() -> Option<TcpListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let n: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    (pid == std::process::id() && n >= 1).then(|| unsafe { TcpListener::from_raw_fd(3) })
}

fn handle(host: &Host, mut conn: TcpStream) -> Result<()> {
    let line = read_line(&mut conn)?;
    let req: Value = serde_json::from_slice(&line)?;
    let reply = match req["op"].as_str().unwrap_or("") {
        "migrate_in" => return incoming(host, &req, &line, conn),
        "pages" => return pages(host, &req, conn),
        "migration" => migration(host, &req),
        "route" => route(host, &req),
        op => Err(format!("unknown op {op:?}").into()),
    };
    let reply = match reply {
        Ok(v) => json!({"ok": true, "result": v}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    };
    send_json(&mut conn, &reply)?;
    Ok(())
}

/// One line, byte by byte: whatever follows belongs to whoever gets the
/// connection next.
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

/// Starts the VM process that takes in a migration, with the connection as
/// its fd 3. It answers the source itself.
fn incoming(host: &Host, req: &Value, line: &[u8], conn: TcpStream) -> Result<()> {
    let name = req["name"].as_str().unwrap_or("");
    let refuse = |mut c: &TcpStream, e: String| send_json(&mut c, &json!({"ok": false, "error": e}));
    if let Err(e) = crate::host::check_name(name) {
        refuse(&conn, e.to_string())?;
        return Ok(());
    }
    let log = std::fs::OpenOptions::new().create(true).append(true).open(host.run.join("vms").join(format!("{name}.log")))?;
    let fd = conn.as_raw_fd();
    let mut cmd = Command::new("/proc/self/exe");
    cmd.args(["--state".as_ref(), host.state.as_os_str(), "--run".as_ref(), host.run.as_os_str(), "run".as_ref(), "--incoming".as_ref()])
        .env("FLEXVM_INCOMING", std::str::from_utf8(line)?)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            if libc::dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    match cmd.spawn() {
        Ok(mut child) => {
            drop(conn);
            std::thread::spawn(move || child.wait());
        }
        Err(e) => refuse(&conn, format!("cannot start the vm process: {e}"))?,
    }
    Ok(())
}

/// Hands a page connection to the VM process it is for.
fn pages(host: &Host, req: &Value, conn: TcpStream) -> Result<()> {
    let name = req["name"].as_str().unwrap_or("");
    let fwd = json!({"op": "pages", "mig": req["mig"]});
    if let Err(e) = crate::vmproc::connect(host, name, &fwd, &[conn.as_raw_fd()]) {
        refuse_pages(conn, &format!("vm {name} is not the source of migration {}: {e}", req["mig"]));
    }
    Ok(())
}

/// Refuses a page connection with one JSON line, which its pager reports.
pub fn refuse_pages(mut conn: TcpStream, why: &str) {
    let _ = send_json(&mut conn, &json!({"ok": false, "error": why}));
    // Take what the client sent meanwhile (its first request), so closing
    // does not reset the connection before it reads why.
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

/// A peer tells us where a VM's address lives now (`via`), or that the VM is
/// gone. Stale messages (older generations, see `host::Addr`) are ignored;
/// an address a VM here holds keeps its route.
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
