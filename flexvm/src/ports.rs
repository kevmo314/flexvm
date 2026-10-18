//! Host-local proxies. Bound sockets are the reservation and the only external resource:
//! even SIGKILL releases them, so gc has no kernel rules or port files to sweep.
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::util::Result;

const CONNECTIONS: usize = 256;
const BUFFER: usize = 65536;
const UDP_IDLE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    pub ip: Ipv4Addr,
    pub host_port: u16,
    pub vm_port: u16,
    pub protocol: Protocol,
}

impl std::str::FromStr for Port {
    type Err = crate::util::Error;
    fn from_str(s: &str) -> Result<Self> {
        let (addr, protocol) = match s.split_once('/') {
            None => (s, Protocol::Tcp),
            Some((s, "tcp")) => (s, Protocol::Tcp),
            Some((s, "udp")) => (s, Protocol::Udp),
            _ => crate::bail!("bad port {s:?}: expected [IP:]HOST_PORT:VM_PORT[/tcp|/udp]"),
        };
        let parts: Vec<_> = addr.split(':').collect();
        let (ip, host, vm) = match parts.as_slice() {
            [host, vm] => (Ipv4Addr::UNSPECIFIED, *host, *vm),
            [ip, host, vm] => (ip.parse::<Ipv4Addr>().map_err(|_| format!("bad port address {ip:?}"))?, *host, *vm),
            _ => crate::bail!("bad port {s:?}: expected [IP:]HOST_PORT:VM_PORT[/tcp|/udp]"),
        };
        let port = |v: &str| -> Result<u16> {
            v.parse::<u16>().ok().filter(|&p| p > 0 && v.bytes().all(|b| b.is_ascii_digit())).ok_or_else(|| format!("bad port number {v:?}").into())
        };
        Ok(Self { ip, host_port: port(host)?, vm_port: port(vm)?, protocol })
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}/{}", self.ip, self.host_port, self.vm_port, if self.protocol == Protocol::Tcp { "tcp" } else { "udp" })
    }
}

enum Bound {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

/// Bind the actual listeners, without SO_REUSEPORT, and retain them for the VM's
/// lifetime. This atomically rejects overlapping forwards across processes/run directories
/// and ordinary bound ports; a failed batch releases everything it acquired.
pub struct Forwarder {
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl Forwarder {
    pub fn start(ports: &[Port], vm: Ipv4Addr) -> Result<Self> {
        let bound = ports
            .iter()
            .map(|p| -> Result<_> {
                if p.host_port == 0 || p.vm_port == 0 {
                    crate::bail!("forwarded ports must be nonzero");
                }
                let addr = SocketAddrV4::new(p.ip, p.host_port);
                let socket = match p.protocol {
                    Protocol::Tcp => {
                        let s = TcpListener::bind(addr).map_err(|e| format!("forward {p}: bind: {e}"))?;
                        s.set_nonblocking(true)?;
                        Bound::Tcp(s)
                    }
                    Protocol::Udp => {
                        let s = UdpSocket::bind(addr).map_err(|e| format!("forward {p}: bind: {e}"))?;
                        s.set_nonblocking(true)?;
                        Bound::Udp(s)
                    }
                };
                Ok((socket, SocketAddrV4::new(vm, p.vm_port)))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut forwarder = Self { stop: Arc::new(AtomicBool::new(false)), workers: Vec::new() };
        for (socket, target) in bound {
            let stop = forwarder.stop.clone();
            forwarder.workers.push(thread::Builder::new().name("port-forward".into()).spawn(move || match socket {
                Bound::Tcp(s) => tcp(s, target, &stop),
                Bound::Udp(s) => udp(s, target, &stop),
            })?);
        }
        Ok(forwarder)
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn wait(fds: &mut [libc::pollfd]) {
    // Bounded so Drop joins promptly, even with idle or stalled connections.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 100) };
}

fn poll(fd: &impl AsRawFd, events: i16) -> libc::pollfd {
    libc::pollfd { fd: if events == 0 { -1 } else { fd.as_raw_fd() }, events, revents: 0 }
}

/// Nonblocking connect: an unreachable guest cannot stall accepts or cleanup.
fn connect(target: SocketAddrV4) -> io::Result<TcpStream> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as _,
        sin_port: target.port().to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(target.ip().octets()) },
        sin_zero: [0; 8],
    };
    if unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_in).cast(), std::mem::size_of_val(&addr) as _) } < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(e);
        }
    }
    Ok(stream)
}

#[derive(Default)]
struct Direction {
    bytes: VecDeque<u8>,
    eof: bool,
    shut: bool,
}

impl Direction {
    fn events(&self, reverse: &Self) -> i16 {
        (if !self.eof && self.bytes.len() < BUFFER { libc::POLLIN } else { 0 }) | (if !reverse.bytes.is_empty() { libc::POLLOUT } else { 0 })
    }

    fn pump(&mut self, mut from: &TcpStream, mut to: &TcpStream) -> io::Result<()> {
        let mut buf = [0; 16384];
        let room = (BUFFER - self.bytes.len()).min(buf.len());
        if !self.eof && room > 0 {
            match from.read(&mut buf[..room]) {
                Ok(0) => self.eof = true,
                Ok(n) => self.bytes.extend(&buf[..n]),
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if !self.bytes.is_empty() {
            match to.write(self.bytes.make_contiguous()) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.bytes.drain(..n);
                }
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if self.eof && self.bytes.is_empty() && !self.shut {
            to.shutdown(Shutdown::Write)?;
            self.shut = true;
        }
        Ok(())
    }
}

fn transient(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted)
}

struct Connection {
    client: TcpStream,
    guest: TcpStream,
    connected: bool,
    since: Instant,
    out: Direction,
    incoming: Direction,
}

fn tcp(listener: TcpListener, target: SocketAddrV4, stop: &AtomicBool) {
    let mut connections: Vec<Connection> = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        let mut fds = vec![poll(&listener, if connections.len() < CONNECTIONS { libc::POLLIN } else { 0 })];
        for c in &connections {
            fds.push(poll(&c.client, if c.connected { c.out.events(&c.incoming) } else { 0 }));
            fds.push(poll(&c.guest, if c.connected { c.incoming.events(&c.out) } else { libc::POLLOUT }));
        }
        wait(&mut fds);
        connections.retain_mut(|c| {
            if !c.connected {
                if c.guest.take_error().ok().flatten().is_some() || c.since.elapsed() > Duration::from_secs(10) {
                    return false;
                }
                c.connected = c.guest.peer_addr().is_ok();
                if !c.connected {
                    return true;
                }
            }
            c.out.pump(&c.client, &c.guest).is_ok() && c.incoming.pump(&c.guest, &c.client).is_ok() && !(c.out.shut && c.incoming.shut)
        });
        if connections.len() < CONNECTIONS {
            if let Ok((client, _)) = listener.accept() {
                if let Ok(guest) = connect(target) {
                    if client.set_nonblocking(true).is_ok() {
                        connections.push(Connection {
                            client,
                            guest,
                            connected: false,
                            since: Instant::now(),
                            out: Direction::default(),
                            incoming: Direction::default(),
                        });
                    }
                }
            }
        }
    }
}

fn udp(listener: UdpSocket, target: SocketAddrV4, stop: &AtomicBool) {
    // A connected guest socket per client preserves reply isolation. Idle sessions expire,
    // and both protocols bound the number of sockets and per-stream queued bytes.
    let mut clients: HashMap<SocketAddr, (UdpSocket, Instant)> = HashMap::new();
    let mut buf = vec![0; BUFFER];
    while !stop.load(Ordering::SeqCst) {
        let mut fds = vec![poll(&listener, libc::POLLIN)];
        fds.extend(clients.values().map(|(s, _)| poll(s, libc::POLLIN)));
        wait(&mut fds);
        if let Ok((n, peer)) = listener.recv_from(&mut buf) {
            if !clients.contains_key(&peer) && clients.len() < CONNECTIONS {
                if let Ok(s) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
                    if s.connect(target).and_then(|()| s.set_nonblocking(true)).is_ok() {
                        clients.insert(peer, (s, Instant::now()));
                    }
                }
            }
            if let Some((s, at)) = clients.get_mut(&peer) {
                let _ = s.send(&buf[..n]);
                *at = Instant::now();
            }
        }
        clients.retain(|peer, (s, at)| {
            if let Ok(n) = s.recv(&mut buf) {
                let _ = listener.send_to(&buf[..n], peer);
                *at = Instant::now();
            }
            at.elapsed() < UDP_IDLE
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_record_ports() {
        let tcp: Port = "8080:80".parse().unwrap();
        assert_eq!(tcp, Port { ip: Ipv4Addr::UNSPECIFIED, host_port: 8080, vm_port: 80, protocol: Protocol::Tcp });
        let udp: Port = "127.0.0.1:5353:53/udp".parse().unwrap();
        assert_eq!(udp.protocol, Protocol::Udp);
        assert_eq!(udp.ip, Ipv4Addr::LOCALHOST);
        for p in [tcp, udp, "65535:1/tcp".parse().unwrap()] {
            assert_eq!(p.to_string().parse::<Port>().unwrap(), p);
            assert_eq!(serde_json::from_slice::<Port>(&serde_json::to_vec(&p).unwrap()).unwrap(), p);
        }
        for bad in
            ["", "80", "1:2:3:4", ":80:80", "localhost:80:80", "::1:80:80", "0:80", "80:0", "65536:80", "1:-1", "+1:2", "1:2/sctp", "1:2/tcp/udp", "1:2/"]
        {
            assert!(bad.parse::<Port>().is_err(), "{bad}");
        }
        let old: crate::host::Entry = serde_json::from_str(r#"{"pid":1,"start":1,"boot":"old"}"#).unwrap();
        assert!(old.ports.is_empty(), "old VM records remain readable");
    }

    fn mapping(host: u16, guest: u16, protocol: Protocol) -> Port {
        Port { ip: Ipv4Addr::LOCALHOST, host_port: host, vm_port: guest, protocol }
    }

    fn free_tcp() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
    }

    #[test]
    fn bound_ports_conflict_and_failed_batch_releases_its_reservations() {
        let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let busy_port = busy.local_addr().unwrap().port();
        let free = free_tcp();
        assert!(Forwarder::start(&[mapping(free, 80, Protocol::Tcp), mapping(busy_port, 80, Protocol::Tcp)], Ipv4Addr::LOCALHOST).is_err());
        let tcp_udp = Forwarder::start(&[mapping(busy_port, 53, Protocol::Udp)], Ipv4Addr::LOCALHOST).unwrap();
        drop(tcp_udp);
        let p = mapping(free, 80, Protocol::Tcp);
        assert!(Forwarder::start(&[p.clone(), p.clone()], Ipv4Addr::LOCALHOST).is_err());
        let f = Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST).unwrap();
        assert!(Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST).is_err());
        let wildcard = Port { ip: Ipv4Addr::UNSPECIFIED, ..p.clone() };
        assert!(Forwarder::start(&[wildcard], Ipv4Addr::LOCALHOST).is_err());
        drop(f);
        let _again = Forwarder::start(&[p], Ipv4Addr::LOCALHOST).unwrap();
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let p = mapping(udp.local_addr().unwrap().port(), 80, Protocol::Udp);
        assert!(Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST).is_err());
        drop(udp);
        let f = Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST).unwrap();
        assert!(Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST).is_err());
        drop(f);
        let _again = Forwarder::start(&[p], Ipv4Addr::LOCALHOST).unwrap();
    }

    #[test]
    fn tcp_relays_large_streams_and_half_closes_then_releases_active_clients() {
        let guest = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let p = mapping(free_tcp(), guest.local_addr().unwrap().port(), Protocol::Tcp);
        let f = Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST).unwrap();
        let mut client = TcpStream::connect((p.ip, p.host_port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = guest.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut data = Vec::new();
            s.read_to_end(&mut data).unwrap();
            assert_eq!(data, vec![42; BUFFER * 4]);
            s.write_all(b"after EOF").unwrap();
            guest
        });
        client.write_all(&vec![42; BUFFER * 4]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"after EOF");
        let guest = server.join().unwrap();
        let mut active = TcpStream::connect((p.ip, p.host_port)).unwrap();
        active.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (_guest_connection, _) = guest.accept().unwrap();
        let at = Instant::now();
        drop(f);
        assert!(at.elapsed() < Duration::from_secs(1));
        match active.read(&mut [0]) {
            Ok(n) => assert_eq!(n, 0),
            Err(e) => assert!(!transient(&e) && e.kind() != io::ErrorKind::TimedOut, "client stayed open: {e}"),
        }
        let _again = Forwarder::start(&[p], Ipv4Addr::LOCALHOST).unwrap();
    }

    #[test]
    fn process_death_releases_ports() {
        const ENV: &str = "FLEXVM_TEST_PORTS_DEATH";
        if let Ok(spec) = std::env::var(ENV) {
            let ports: Vec<Port> = serde_json::from_str(&spec).unwrap();
            let _forwarder = Forwarder::start(&ports, Ipv4Addr::LOCALHOST).unwrap();
            println!("forwarder ready");
            io::stdout().flush().unwrap();
            let _ = io::stdin().read(&mut [0]);
            // Deliberately bypass Drop, even if the parent exits first.
            std::process::exit(0);
        }
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let ports = vec![mapping(free_tcp(), 80, Protocol::Tcp), mapping(udp.local_addr().unwrap().port(), 53, Protocol::Udp)];
        drop(udp);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ports::tests::process_death_releases_ports", "--nocapture"])
            .env(ENV, serde_json::to_string(&ports).unwrap())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::BufRead;
        let mut output = io::BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert!(output.read_line(&mut line).unwrap() > 0, "child did not bind its ports");
            if line.contains("forwarder ready") {
                break;
            }
        }
        assert!(Forwarder::start(&ports, Ipv4Addr::LOCALHOST).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        let _again = Forwarder::start(&ports, Ipv4Addr::LOCALHOST).unwrap();
    }

    #[test]
    fn udp_replies_are_isolated_by_client_and_zero_length_datagrams_work() {
        let guest = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        guest.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let host_port = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port();
        let p = mapping(host_port, guest.local_addr().unwrap().port(), Protocol::Udp);
        let _f = Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST).unwrap();
        let a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        for client in [&a, &b] {
            client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        }
        a.send_to(b"a", (p.ip, p.host_port)).unwrap();
        b.send_to(b"b", (p.ip, p.host_port)).unwrap();
        let mut buf = [0; 64];
        let (n1, peer1) = guest.recv_from(&mut buf).unwrap();
        let msg1 = buf[..n1].to_vec();
        let (n2, peer2) = guest.recv_from(&mut buf).unwrap();
        assert_ne!(peer1, peer2);
        guest.send_to(&buf[..n2], peer2).unwrap();
        guest.send_to(&msg1, peer1).unwrap();
        assert_eq!(a.recv(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], b'a');
        assert_eq!(b.recv(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], b'b');
        a.send_to(b"", (p.ip, p.host_port)).unwrap();
        let (n, peer) = guest.recv_from(&mut buf).unwrap();
        assert_eq!(n, 0);
        guest.send_to(b"", peer).unwrap();
        assert_eq!(a.recv(&mut buf).unwrap(), 0);
    }
}
