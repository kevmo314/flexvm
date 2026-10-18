//! Host-local proxies. Bound sockets are the reservation and the only external resource:
//! even SIGKILL releases them, so gc has no kernel rules or port files to sweep.
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::util::Result;

const CONNECTIONS: usize = 256;
const BUFFER: usize = 65536;
/// UDP sessions expire after this; a TCP forward this idle is closed only to admit a client at the cap.
const IDLE: Duration = Duration::from_secs(60);
const CONNECT_WAIT: Duration = Duration::from_secs(10);
/// The most datagrams taken from one socket per wakeup: a flood on one cannot starve the others.
const BURST: usize = 1024;
/// Workers wake for their sockets or `Forwarder::drop`'s eventfd; this only bounds when idle
/// sessions and stalled connects are noticed.
const TICK: libc::c_int = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    /// None binds both 0.0.0.0 and [::], as Docker does.
    pub ip: Option<IpAddr>,
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
        let port = |v: &str| -> Result<u16> {
            v.parse::<u16>().ok().filter(|&p| p > 0 && v.bytes().all(|b| b.is_ascii_digit())).ok_or_else(|| format!("bad port number {v:?}").into())
        };
        let Some((bind, vm)) = addr.rsplit_once(':') else { crate::bail!("bad port {s:?}: expected [IP:]HOST_PORT:VM_PORT[/tcp|/udp]") };
        let (ip, host_port) = match bind.rsplit_once(':') {
            None => (None, port(bind)?),
            // IP:PORT or [IPv6]:PORT, without a scope the record could not keep.
            Some((_, host)) => match bind.parse::<SocketAddr>() {
                Ok(a) if !matches!(a, SocketAddr::V6(v) if v.scope_id() != 0) => (Some(a.ip()), port(host)?),
                _ => crate::bail!("bad port address in {s:?}: expected IPv4 or [IPv6]"),
            },
        };
        Ok(Self { ip, host_port, vm_port: port(vm)?, protocol })
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let protocol = if self.protocol == Protocol::Tcp { "tcp" } else { "udp" };
        match self.ip {
            Some(ip) => write!(f, "{}:{}/{protocol}", SocketAddr::new(ip, self.host_port), self.vm_port),
            None => write!(f, "{}:{}/{protocol}", self.host_port, self.vm_port),
        }
    }
}

/// The actual listeners, without SO_REUSEPORT, held for the VM's lifetime. Binding
/// atomically refuses overlapping forwards across processes and run directories and
/// ordinary bound ports; a failed batch releases everything it acquired.
pub struct Forwarder {
    /// Readable once the forwarder is dropped: in every worker's poll set, so they stop at once.
    stop: Arc<OwnedFd>,
    /// A worker's: one -p's sockets, of each address it binds.
    bound: Vec<(Vec<OwnedFd>, Protocol, u16)>,
    workers: Vec<JoinHandle<()>>,
    /// What is bound, an entry per address: for `ps` and `run`'s reply.
    pub ports: Vec<Port>,
}

impl Forwarder {
    /// Before the VM's address is claimed: a clash refuses the start with nothing to give back.
    pub fn bind(ports: &[Port]) -> Result<Self> {
        let (mut bound, mut bound_ports) = (Vec::new(), Vec::new());
        for p in ports {
            let mut fds = Vec::new();
            for ip in p.ip.map_or_else(|| vec![Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()], |ip| vec![ip]) {
                let at = Port { ip: Some(ip), ..p.clone() };
                match listen(SocketAddr::new(ip, p.host_port), p.protocol) {
                    Ok(fd) => {
                        fds.push(fd);
                        bound_ports.push(at);
                    }
                    Err(e) if p.ip.is_none() && no_ipv6(ip, &e) => {}
                    Err(e) => crate::bail!("forward {at}: bind: {e}"),
                }
            }
            bound.push((fds, p.protocol, p.vm_port));
        }
        let stop = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if stop < 0 {
            crate::bail!("forward: eventfd: {}", io::Error::last_os_error());
        }
        let stop = Arc::new(unsafe { OwnedFd::from_raw_fd(stop) });
        Ok(Self { stop, bound, workers: Vec::new(), ports: bound_ports })
    }

    /// Proxies to the VM at `vm`, once its address is known.
    pub fn serve(&mut self, vm: Ipv4Addr) -> Result<()> {
        for (fds, protocol, port) in self.bound.drain(..) {
            let (stop, target) = (self.stop.clone(), SocketAddrV4::new(vm, port));
            self.workers.push(thread::Builder::new().name("port-forward".into()).spawn(move || match protocol {
                Protocol::Tcp => tcp(fds.into_iter().map(TcpListener::from).collect(), target, stop.as_fd(), CONNECTIONS, IDLE),
                Protocol::Udp => udp(fds.into_iter().map(UdpSocket::from).collect(), target, stop.as_fd()),
            })?);
        }
        Ok(())
    }

    #[cfg(test)]
    fn start(ports: &[Port], vm: Ipv4Addr) -> Result<Self> {
        let mut f = Self::bind(ports)?;
        f.serve(vm)?;
        Ok(f)
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        let one = 1u64;
        unsafe { libc::write(self.stop.as_raw_fd(), (&one as *const u64).cast(), 8) };
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// Waits on `fds` and the stop eventfd (last); false once stopped.
fn wait(fds: &mut Vec<libc::pollfd>, stop: BorrowedFd) -> bool {
    fds.push(libc::pollfd { fd: stop.as_raw_fd(), events: libc::POLLIN, revents: 0 });
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, TICK) };
    fds.pop().is_some_and(|s| s.revents == 0)
}

/// Whether the socket has something for us (data, room, or an error or hangup to find out by trying).
fn ready(fd: &libc::pollfd) -> bool {
    fd.revents != 0
}

fn poll(fd: &impl AsRawFd, events: i16) -> libc::pollfd {
    libc::pollfd { fd: if events == 0 { -1 } else { fd.as_raw_fd() }, events, revents: 0 }
}

/// Only where a default bind may go without: a host with no IPv6 support or address.
fn no_ipv6(ip: IpAddr, e: &io::Error) -> bool {
    ip.is_ipv6() && matches!(e.raw_os_error(), Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL))
}

/// std cannot set IPV6_V6ONLY before binding: [::] would also take IPv4 where
/// net.ipv6.bindv6only is 0. TCP reuses addresses, as std's binds do.
fn listen(addr: SocketAddr, protocol: Protocol) -> io::Result<OwnedFd> {
    let tcp = protocol == Protocol::Tcp;
    // A wildcard UDP listener learns each datagram's destination, which its replies leave from.
    let pktinfo = !tcp && addr.ip().is_unspecified();
    let SocketAddr::V6(a) = addr else {
        let fd: OwnedFd = match protocol {
            Protocol::Tcp => TcpListener::bind(addr).and_then(|s| s.set_nonblocking(true).map(|()| s.into()))?,
            Protocol::Udp => UdpSocket::bind(addr).and_then(|s| s.set_nonblocking(true).map(|()| s.into()))?,
        };
        return if !pktinfo || on(&fd, libc::IPPROTO_IP, libc::IP_PKTINFO) { Ok(fd) } else { Err(io::Error::last_os_error()) };
    };
    let fd = unsafe { libc::socket(libc::AF_INET6, if tcp { libc::SOCK_STREAM } else { libc::SOCK_DGRAM } | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let on = |level, name| on(&fd, level, name);
    let sa = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as _,
        sin6_port: a.port().to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: a.ip().octets() },
        sin6_scope_id: 0,
    };
    let ok = (!tcp || on(libc::SOL_SOCKET, libc::SO_REUSEADDR))
        && on(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)
        && (!pktinfo || on(libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO))
        && unsafe { libc::bind(fd.as_raw_fd(), (&sa as *const libc::sockaddr_in6).cast(), std::mem::size_of_val(&sa) as _) } == 0
        && (!tcp || unsafe { libc::listen(fd.as_raw_fd(), 128) } == 0);
    if !ok {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn on(fd: &OwnedFd, level: libc::c_int, name: libc::c_int) -> bool {
    let one: libc::c_int = 1;
    unsafe { libc::setsockopt(fd.as_raw_fd(), level, name, (&one as *const libc::c_int).cast(), std::mem::size_of_val(&one) as _) == 0 }
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

    /// True if it moved anything.
    fn pump(&mut self, mut from: &TcpStream, mut to: &TcpStream) -> io::Result<bool> {
        let (mut buf, mut moved) = ([0; 16384], false);
        let room = (BUFFER - self.bytes.len()).min(buf.len());
        if !self.eof && room > 0 {
            match from.read(&mut buf[..room]) {
                Ok(0) => (self.eof, moved) = (true, true),
                Ok(n) => {
                    self.bytes.extend(&buf[..n]);
                    moved = true;
                }
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if !self.bytes.is_empty() {
            match to.write(self.bytes.make_contiguous()) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.bytes.drain(..n);
                    moved = true;
                }
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if self.eof && self.bytes.is_empty() && !self.shut {
            to.shutdown(Shutdown::Write)?;
            self.shut = true;
        }
        Ok(moved)
    }
}

fn transient(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted)
}

struct Connection {
    client: TcpStream,
    guest: TcpStream,
    connected: bool,
    /// Connected on this pass, not yet admitted: it has moved nothing.
    fresh: bool,
    since: Instant,
    /// When it last moved data (or connected).
    active: Instant,
    out: Direction,
    incoming: Direction,
}

/// The connected forward idle longest, if for at least `idle`: the one to close for a new client at the cap.
fn idlest(connections: &[Connection], idle: Duration) -> Option<usize> {
    let (i, c) = connections.iter().enumerate().filter(|(_, c)| c.connected).min_by_key(|(_, c)| c.active)?;
    (c.active.elapsed() >= idle).then_some(i)
}

/// How many connected forwards have been idle for `idle`: each may make way for one more client.
fn spare(connections: &[Connection], idle: Duration) -> usize {
    connections.iter().filter(|c| c.connected && c.active.elapsed() >= idle).count()
}

/// Keeps at most `cap` connected: each fresh one over it replaces the idlest, or else is closed itself.
/// Only fresh ones take it over, so there is always one to close.
fn admit(connections: &mut Vec<Connection>, cap: usize, idle: Duration) {
    while connections.iter().filter(|c| c.connected).count() > cap {
        let Some(i) = idlest(connections, idle).or_else(|| connections.iter().position(|c| c.fresh)) else { break };
        connections.swap_remove(i);
    }
    for c in connections.iter_mut() {
        c.fresh = false;
    }
}

/// At most `cap` connected, and as many more connecting as forwards are idle: each replaces one once
/// connected, or is closed if none is idle by then.
fn tcp(listeners: Vec<TcpListener>, target: SocketAddrV4, stop: BorrowedFd, cap: usize, idle: Duration) {
    let mut connections: Vec<Connection> = Vec::new();
    loop {
        // Idle forwards cannot hold the cap: at it, a waiting client replaces the idlest once it connects.
        let room = if connections.len() < cap + spare(&connections, idle) { libc::POLLIN } else { 0 };
        let mut fds: Vec<_> = listeners.iter().map(|l| poll(l, room)).collect();
        for c in &connections {
            fds.push(poll(&c.client, if c.connected { c.out.events(&c.incoming) } else { 0 }));
            fds.push(poll(&c.guest, if c.connected { c.incoming.events(&c.out) } else { libc::POLLOUT }));
        }
        if !wait(&mut fds, stop) {
            return;
        }
        let (accepting, mut each) = (fds[..listeners.len()].to_vec(), fds[listeners.len()..].chunks(2));
        connections.retain_mut(|c| {
            let [client, guest] = each.next().unwrap() else { unreachable!() };
            if !c.connected {
                if !ready(guest) {
                    return c.since.elapsed() <= CONNECT_WAIT;
                }
                if c.guest.take_error().ok().flatten().is_some() {
                    return false;
                }
                c.connected = c.guest.peer_addr().is_ok();
                if !c.connected {
                    return c.since.elapsed() <= CONNECT_WAIT;
                }
                // It moves nothing until it is admitted below.
                (c.fresh, c.active) = (true, Instant::now());
                return true;
            } else if !ready(client) && !ready(guest) {
                return true;
            }
            let Ok(out) = c.out.pump(&c.client, &c.guest) else { return false };
            let Ok(incoming) = c.incoming.pump(&c.guest, &c.client) else { return false };
            if out || incoming {
                c.active = Instant::now();
            }
            !(c.out.shut && c.incoming.shut)
        });
        // Only now: a replacement whose connect fails closes nothing.
        admit(&mut connections, cap, idle);
        let spare = spare(&connections, idle);
        for (listener, fd) in listeners.iter().zip(&accepting) {
            // Attempts are bounded too: a client whose guest connect fails (EMFILE, say) is dropped,
            // and a flood of them must still let the loop see its stop.
            if !ready(fd) {
                continue;
            }
            for _ in 0..CONNECTIONS {
                if connections.len() >= cap + spare {
                    break;
                }
                let client = match listener.accept() {
                    Ok((client, _)) => client,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                if let Ok(guest) = connect(target) {
                    if client.set_nonblocking(true).is_ok() {
                        connections.push(Connection {
                            client,
                            guest,
                            connected: false,
                            fresh: false,
                            since: Instant::now(),
                            active: Instant::now(),
                            out: Direction::default(),
                            incoming: Direction::default(),
                        });
                    }
                }
            }
        }
    }
}

/// Where a wildcard listener's datagram was sent, which its replies leave from. The interface is
/// kept only for a link-local address (which needs it): other replies are routed as before.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Local(IpAddr, u32);

/// A datagram, its sender and, on a wildcard listener, its `Local`.
fn recv_datagram(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<Local>)> {
    unsafe {
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut control = [0u64; 8];
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let mut msg: libc::msghdr = std::mem::zeroed();
        (msg.msg_name, msg.msg_namelen) = ((&raw mut addr).cast(), size_of_val(&addr) as _);
        (msg.msg_iov, msg.msg_iovlen) = (&mut iov, 1);
        (msg.msg_control, msg.msg_controllen) = (control.as_mut_ptr().cast(), size_of_val(&control));
        let n = libc::recvmsg(socket.as_raw_fd(), &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let peer = if addr.ss_family as i32 == libc::AF_INET {
            let a = &*(&raw const addr).cast::<libc::sockaddr_in>();
            SocketAddr::from((u32::from_be(a.sin_addr.s_addr).to_be_bytes(), u16::from_be(a.sin_port)))
        } else {
            let a = &*(&raw const addr).cast::<libc::sockaddr_in6>();
            std::net::SocketAddrV6::new(a.sin6_addr.s6_addr.into(), u16::from_be(a.sin6_port), a.sin6_flowinfo, a.sin6_scope_id).into()
        };
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            match ((*c).cmsg_level, (*c).cmsg_type) {
                // The local address, not the header's: for a broadcast, the interface's.
                (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                    let p = &*libc::CMSG_DATA(c).cast::<libc::in_pktinfo>();
                    return Ok((n as usize, peer, Some(Local(IpAddr::from(u32::from_be(p.ipi_spec_dst.s_addr).to_be_bytes()), 0))));
                }
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                    let p = &*libc::CMSG_DATA(c).cast::<libc::in6_pktinfo>();
                    let ip = Ipv6Addr::from(p.ipi6_addr.s6_addr);
                    // No multicast source: the kernel picks one, as before.
                    let ip = if ip.is_multicast() { Ipv6Addr::UNSPECIFIED } else { ip };
                    return Ok((n as usize, peer, Some(Local(ip.into(), if ip.is_unicast_link_local() { p.ipi6_ifindex } else { 0 }))));
                }
                _ => c = libc::CMSG_NXTHDR(&msg, c),
            }
        }
        Ok((n as usize, peer, None))
    }
}

/// `send_to`, from `local` if known.
fn send_datagram(socket: &UdpSocket, data: &[u8], peer: SocketAddr, local: Option<Local>) -> io::Result<usize> {
    let Some(Local(ip, interface)) = local else { return socket.send_to(data, peer) };
    unsafe {
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut control = [0u64; 8];
        let mut iov = libc::iovec { iov_base: data.as_ptr().cast_mut().cast(), iov_len: data.len() };
        let mut msg: libc::msghdr = std::mem::zeroed();
        (msg.msg_name, msg.msg_iov, msg.msg_iovlen) = ((&raw mut addr).cast(), &mut iov, 1);
        (msg.msg_control, msg.msg_controllen) = (control.as_mut_ptr().cast(), size_of_val(&control));
        let c = &mut *libc::CMSG_FIRSTHDR(&msg);
        let len = match (peer, ip) {
            (SocketAddr::V4(peer), IpAddr::V4(ip)) => {
                let a = &mut *(&raw mut addr).cast::<libc::sockaddr_in>();
                (a.sin_family, a.sin_port, a.sin_addr.s_addr) = (libc::AF_INET as _, peer.port().to_be(), u32::from_ne_bytes(peer.ip().octets()));
                (msg.msg_namelen, c.cmsg_level, c.cmsg_type) = (size_of_val(a) as _, libc::IPPROTO_IP, libc::IP_PKTINFO);
                (*libc::CMSG_DATA(c).cast::<libc::in_pktinfo>()).ipi_spec_dst.s_addr = u32::from_ne_bytes(ip.octets());
                size_of::<libc::in_pktinfo>()
            }
            (SocketAddr::V6(peer), IpAddr::V6(ip)) => {
                let a = &mut *(&raw mut addr).cast::<libc::sockaddr_in6>();
                (a.sin6_family, a.sin6_port, a.sin6_addr.s6_addr, a.sin6_scope_id) =
                    (libc::AF_INET6 as _, peer.port().to_be(), peer.ip().octets(), peer.scope_id());
                (msg.msg_namelen, c.cmsg_level, c.cmsg_type) = (size_of_val(a) as _, libc::IPPROTO_IPV6, libc::IPV6_PKTINFO);
                let p = &mut *libc::CMSG_DATA(c).cast::<libc::in6_pktinfo>();
                (p.ipi6_addr.s6_addr, p.ipi6_ifindex) = (ip.octets(), interface);
                size_of::<libc::in6_pktinfo>()
            }
            _ => return socket.send_to(data, peer),
        };
        (c.cmsg_len, msg.msg_controllen) = (libc::CMSG_LEN(len as _) as _, libc::CMSG_SPACE(len as _) as _);
        match libc::sendmsg(socket.as_raw_fd(), &msg, 0) {
            n if n < 0 => Err(io::Error::last_os_error()),
            n => Ok(n as usize),
        }
    }
}

fn udp(listeners: Vec<UdpSocket>, target: SocketAddrV4, stop: BorrowedFd) {
    // A connected guest socket per client preserves reply isolation. Idle sessions expire,
    // and both protocols bound the number of sockets and per-stream queued bytes.
    // Replies leave by the listener the client sent to.
    // Keyed by where the client sent to, on a wildcard listener.
    let mut clients: HashMap<(SocketAddr, Option<Local>), (UdpSocket, Instant, usize)> = HashMap::new();
    let mut buf = vec![0; BUFFER];
    loop {
        let mut fds: Vec<_> = listeners.iter().map(|l| poll(l, libc::POLLIN)).collect();
        let peers: Vec<_> = clients.keys().copied().collect();
        fds.extend(peers.iter().map(|p| poll(&clients[p].0, libc::POLLIN)));
        if !wait(&mut fds, stop) {
            return;
        }
        // Replies first: the sessions polled are those in `peers`, before any is added below.
        for (peer, fd) in peers.iter().zip(&fds[listeners.len()..]) {
            let Some((s, at, i)) = clients.get_mut(peer).filter(|_| ready(fd)) else { continue };
            for _ in 0..BURST {
                match s.recv(&mut buf) {
                    Ok(n) => {
                        let _ = send_datagram(&listeners[*i], &buf[..n], peer.0, peer.1);
                        *at = Instant::now();
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    // WouldBlock, or the guest refused one (ICMP): the session goes on.
                    Err(_) => break,
                }
            }
        }
        for ((i, listener), fd) in listeners.iter().enumerate().zip(&fds) {
            if !ready(fd) {
                continue;
            }
            for _ in 0..BURST {
                let (n, peer) = match recv_datagram(listener, &mut buf) {
                    Ok((n, peer, local)) => (n, (peer, local)),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                if !clients.contains_key(&peer) && clients.len() < CONNECTIONS {
                    if let Ok(s) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
                        if s.connect(target).and_then(|()| s.set_nonblocking(true)).is_ok() {
                            clients.insert(peer, (s, Instant::now(), i));
                        }
                    }
                }
                if let Some((s, at, _)) = clients.get_mut(&peer) {
                    let _ = s.send(&buf[..n]);
                    *at = Instant::now();
                }
            }
        }
        clients.retain(|_, (_, at, _)| at.elapsed() < IDLE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{wait_until, JoinWithin, WAIT};

    #[test]
    fn wildcard_udp_replies_from_each_destination() {
        retry_ports(|| {
            let guest = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            guest.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mapping = Port { ip: None, host_port: 0, vm_port: guest.local_addr().unwrap().port(), protocol: Protocol::Udp };
            let mut forwarder = Forwarder::bind(&[mapping])?;
            let port = UdpSocket::from(forwarder.bound[0].0[0].try_clone().unwrap()).local_addr().unwrap().port();
            let v6_port = forwarder.bound[0].0.get(1).map(|fd| UdpSocket::from(fd.try_clone().unwrap()).local_addr().unwrap().port());
            forwarder.serve(Ipv4Addr::LOCALHOST)?;
            // Reuse one client endpoint across destinations: these must be separate sessions.
            let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0; 32];
            let mut sessions = Vec::new();
            for ip in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)] {
                client.connect((ip, port)).unwrap();
                client.send(&ip.octets()).unwrap();
                let (n, session) = guest.recv_from(&mut buf).unwrap();
                assert_eq!(&buf[..n], &ip.octets());
                sessions.push((session, ip));
            }
            assert_ne!(sessions[0].0, sessions[1].0);
            for (session, ip) in sessions {
                client.connect((ip, port)).unwrap();
                guest.send_to(&ip.octets(), session).unwrap();
                let (n, source) = client.recv_from(&mut buf).unwrap();
                assert_eq!(source, SocketAddr::new(ip.into(), port));
                assert_eq!(&buf[..n], &ip.octets());
            }
            if let Some(port) = v6_port {
                let client = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
                client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                client.connect((Ipv6Addr::LOCALHOST, port)).unwrap();
                client.send(b"v6").unwrap();
                let (n, session) = guest.recv_from(&mut buf).unwrap();
                guest.send_to(&buf[..n], session).unwrap();
                let (n, source) = client.recv_from(&mut buf).unwrap();
                assert_eq!(source, SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port));
                assert_eq!(&buf[..n], b"v6");
            }
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn only_a_connected_forward_idle_for_long_is_closed_for_a_new_client() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let ago = |d: Duration| Instant::now().checked_sub(d).unwrap();
        let connection = |connected, active| {
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let guest = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            Connection { client, guest, connected, fresh: false, since: active, active, out: Direction::default(), incoming: Direction::default() }
        };
        let mut connections = vec![connection(true, ago(IDLE / 2)), connection(false, ago(IDLE * 3))];
        assert_eq!(idlest(&connections, IDLE), None, "a busy forward and a pending connect stay");
        connections.push(connection(true, ago(IDLE)));
        connections.push(connection(true, ago(IDLE * 2)));
        assert_eq!(idlest(&connections, IDLE), Some(3));
    }

    #[test]
    fn with_none_idle_the_replacement_just_connected_is_closed_not_one_already_forwarding() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let ago = |d: Duration| Instant::now().checked_sub(d).unwrap();
        let connection = |since, fresh| {
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let guest = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            Connection { client, guest, connected: true, fresh, since, active: Instant::now(), out: Direction::default(), incoming: Direction::default() }
        };
        // Replacements a and then b were accepted for two idle forwards; b connected first and replaced
        // one, the other is busy again, and now a connects.
        let (old, a, b) = (ago(IDLE * 2), ago(Duration::from_secs(2)), ago(Duration::from_secs(1)));
        let mut connections = vec![connection(old, false), connection(b, false), connection(a, true)];
        admit(&mut connections, 2, IDLE);
        let mut left: Vec<_> = connections.iter().map(|c| c.since).collect();
        left.sort();
        assert_eq!(left, [old, b], "b, already forwarding, stays");
        assert!(connections.iter().all(|c| !c.fresh));
    }

    /// A TCP worker of `cap` connections to a new guest listener: its address, the guest, and its stop.
    fn worker(cap: usize, idle: Duration) -> (SocketAddr, TcpListener, Arc<OwnedFd>, JoinHandle<()>) {
        let guest = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (addr, target) = (listener.local_addr().unwrap(), SocketAddrV4::new(Ipv4Addr::LOCALHOST, guest.local_addr().unwrap().port()));
        let stop = Arc::new(unsafe { OwnedFd::from_raw_fd(libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK)) });
        let worker = {
            let stop = stop.clone();
            thread::spawn(move || tcp(vec![listener], target, stop.as_fd(), cap, idle))
        };
        (addr, guest, stop, worker)
    }

    fn halt(stop: &OwnedFd, worker: JoinHandle<()>) {
        unsafe { libc::write(stop.as_raw_fd(), (&1u64 as *const u64).cast(), 8) };
        worker.join_within().unwrap();
    }

    fn echo(c: &mut TcpStream, s: &mut TcpStream) {
        c.write_all(b"x").unwrap();
        s.read_exact(&mut [0]).unwrap();
        s.write_all(b"y").unwrap();
        c.read_exact(&mut [0]).unwrap();
    }

    /// Fills `guest`'s accept queue: further SYNs are dropped, so connects to it stay in progress.
    fn fill(guest: &TcpListener) -> Vec<TcpStream> {
        assert_eq!(unsafe { libc::listen(guest.as_raw_fd(), 0) }, 0);
        let filler: Vec<_> = (0..4).map_while(|_| TcpStream::connect_timeout(&guest.local_addr().unwrap(), Duration::from_millis(200)).ok()).collect();
        assert!(filler.len() < 4, "the accept queue never filled");
        filler
    }

    #[test]
    fn a_replacement_that_finds_none_idle_once_connected_is_closed() {
        const IDLE: Duration = Duration::from_secs(1);
        let (addr, guest, stop, worker) = worker(1, IDLE);
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        let (mut server, _) = crate::test_util::accept_tcp(&guest);
        echo(&mut client, &mut server);
        let _filler = fill(&guest);
        thread::sleep(IDLE + Duration::from_millis(200));
        // Admitted while the forward is idle, it is still connecting when the forward is busy again.
        let replacement = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(TICK as u64) * 2);
        replacement.set_nonblocking(true).unwrap();
        guest.set_nonblocking(true).unwrap();
        let (mut accepted, deadline) = (Vec::new(), Instant::now() + Duration::from_secs(20));
        // Both stay busy: one of them must go.
        loop {
            echo(&mut client, &mut server);
            let _ = (&replacement).write(b"r");
            accepted.extend(std::iter::from_fn(|| guest.accept().ok()));
            match (&replacement).read(&mut [0]) {
                Ok(n) => break assert_eq!(n, 0),
                Err(e) if transient(&e) => assert!(Instant::now() < deadline, "the replacement went over the cap"),
                Err(_) => break,
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert!(!accepted.is_empty(), "the replacement never connected");
        echo(&mut client, &mut server);
        halt(&stop, worker);
    }

    #[test]
    fn a_replacement_still_connecting_closes_nothing() {
        const IDLE: Duration = Duration::from_millis(500);
        let (addr, guest, stop, worker) = worker(1, IDLE);
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        let (mut server, _) = crate::test_util::accept_tcp(&guest);
        echo(&mut client, &mut server);
        let _filler = fill(&guest);
        thread::sleep(IDLE * 2);
        let _waiting = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(TICK as u64) * 2);
        echo(&mut client, &mut server);
        halt(&stop, worker);
    }

    #[test]
    fn at_the_cap_a_waiting_client_replaces_the_idlest_forward_once_it_is_idle() {
        const IDLE: Duration = Duration::from_secs(2);
        let (addr, guest, stop, worker) = worker(2, IDLE);
        let mut forwards = Vec::new();
        for _ in 0..2 {
            let mut client = TcpStream::connect(addr).unwrap();
            client.set_read_timeout(Some(WAIT)).unwrap();
            let (mut server, _) = crate::test_util::accept_tcp(&guest);
            echo(&mut client, &mut server);
            forwards.push((client, server));
            thread::sleep(Duration::from_millis(50));
        }
        let mut waiting = TcpStream::connect(addr).unwrap();
        waiting.write_all(b"w").unwrap();
        thread::sleep(Duration::from_millis(200));
        guest.set_nonblocking(true).unwrap();
        assert!(guest.accept().is_err(), "a forward was closed before it was idle");
        guest.set_nonblocking(false).unwrap();
        let (mut server, _) = crate::test_util::accept_tcp(&guest);
        let mut b = [0];
        server.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"w");
        match forwards[0].0.read(&mut b) {
            Ok(n) => assert_eq!(n, 0, "the idlest forward is closed"),
            Err(e) => assert!(!transient(&e) && e.kind() != io::ErrorKind::TimedOut, "the idlest forward stayed open: {e}"),
        }
        let (client, server) = &mut forwards[1];
        echo(client, server);
        halt(&stop, worker);
    }

    #[test]
    fn parse_and_record_ports() {
        let tcp: Port = "8080:80".parse().unwrap();
        assert_eq!(tcp, Port { ip: None, host_port: 8080, vm_port: 80, protocol: Protocol::Tcp });
        let udp: Port = "127.0.0.1:5353:53/udp".parse().unwrap();
        assert_eq!(udp.protocol, Protocol::Udp);
        assert_eq!(udp.ip, Some(Ipv4Addr::LOCALHOST.into()));
        let v6: Port = "[::1]:8080:80".parse().unwrap();
        assert_eq!((v6.ip, v6.to_string()), (Some(Ipv6Addr::LOCALHOST.into()), "[::1]:8080:80/tcp".into()));
        assert_eq!(serde_json::to_value(&v6).unwrap()["ip"], "::1");
        for p in [tcp, udp, v6, "[::]:1:2/udp".parse().unwrap(), "65535:1/tcp".parse().unwrap()] {
            assert_eq!(p.to_string().parse::<Port>().unwrap(), p);
            assert_eq!(serde_json::from_slice::<Port>(&serde_json::to_vec(&p).unwrap()).unwrap(), p);
        }
        for bad in [
            "",
            "80",
            "1:2:3:4",
            ":80:80",
            "localhost:80:80",
            "::1:80:80",
            "0:80",
            "80:0",
            "65536:80",
            "1:-1",
            "+1:2",
            "1:2/sctp",
            "1:2/tcp/udp",
            "1:2/",
            "[::1:80:80",
            "[127.0.0.1]:80:80",
            "[::1]:0:80",
            "[::1]:+1:80",
            "[fe80::1%2]:80:80",
        ] {
            assert!(bad.parse::<Port>().is_err(), "{bad}");
        }
        let old: crate::host::Entry = serde_json::from_str(r#"{"pid":1,"start":1,"boot":"old"}"#).unwrap();
        assert!(old.ports.is_empty(), "old VM records remain readable");
    }

    #[test]
    fn a_default_bind_takes_both_families_on_one_thread_and_a_clash_on_either_refuses_it() {
        retry_ports(|| {
            // An explicit IPv6 address must bind, even where a default [::] may go without.
            let absent = Port { ip: Some("2001:db8::1".parse().unwrap()), ..mapping(0, 80, Protocol::Tcp) };
            assert!(Forwarder::bind(&[absent]).is_err());
            let Ok(v6) = listen((Ipv6Addr::UNSPECIFIED, 0).into(), Protocol::Tcp) else {
                crate::log!("no IPv6: skipped");
                return Ok(());
            };
            assert!(crate::listen::v6only(&TcpListener::from(v6)));
            let (guest, udp_guest) = (TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(), UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap());
            udp_guest.set_read_timeout(Some(WAIT)).unwrap();
            let port = free_tcp();
            let tcp = Port { ip: None, ..mapping(port, guest.local_addr().unwrap().port(), Protocol::Tcp) };
            let udp = Port { protocol: Protocol::Udp, vm_port: udp_guest.local_addr().unwrap().port(), ..tcp.clone() };
            let f = Forwarder::start(&[tcp.clone(), udp.clone()], Ipv4Addr::LOCALHOST)?;
            assert_eq!(f.workers.len(), 2);
            assert_eq!(f.ports.len(), 4);
            assert_eq!(f.ports[1].to_string(), format!("[::]:{port}:{}/tcp", tcp.vm_port));
            let mut buf = [0; 8];
            for ip in [IpAddr::from(Ipv4Addr::LOCALHOST), Ipv6Addr::LOCALHOST.into()] {
                let mut client = TcpStream::connect((ip, port)).unwrap();
                client.set_read_timeout(Some(WAIT)).unwrap();
                client.write_all(b"t").unwrap();
                let (mut server, _) = crate::test_util::accept_tcp(&guest);
                server.read_exact(&mut buf[..1]).unwrap();
                server.write_all(b"T").unwrap();
                client.read_exact(&mut buf[..1]).unwrap();
                assert_eq!(&buf[..1], b"T");
                let client = UdpSocket::bind((ip, 0)).unwrap();
                client.set_read_timeout(Some(WAIT)).unwrap();
                client.send_to(b"u", (ip, port)).unwrap();
                let (n, peer) = udp_guest.recv_from(&mut buf).unwrap();
                udp_guest.send_to(&buf[..n], peer).unwrap();
                assert_eq!(client.recv_from(&mut buf).unwrap(), (1, (ip, port).into()));
            }
            drop(f);
            // V6ONLY keeps the families apart, and the refused bind releases the family it got.
            let (any4, any6) = (IpAddr::from(Ipv4Addr::UNSPECIFIED), IpAddr::from(Ipv6Addr::UNSPECIFIED));
            for (taken, other) in [(any4, any6), (any6, any4)] {
                for p in [&tcp, &udp] {
                    let _held = Forwarder::bind(&[Port { ip: Some(taken), ..p.clone() }])?;
                    assert!(Forwarder::bind(std::slice::from_ref(p)).is_err());
                    let _other = Forwarder::bind(&[Port { ip: Some(other), ..p.clone() }])?;
                }
            }
            Ok(())
        })
        .unwrap();
    }

    fn mapping(host: u16, guest: u16, protocol: Protocol) -> Port {
        Port { ip: Some(Ipv4Addr::LOCALHOST.into()), host_port: host, vm_port: guest, protocol }
    }

    // A probe cannot reserve the port through the later bind, and an IPv4 TCP probe
    // says nothing about IPv6 or UDP. Retry the entire scenario with fresh probes,
    // including any release/rebind checks. Other errors and failed assertions stay fatal.
    fn retry_ports<T>(mut test: impl FnMut() -> Result<T>) -> Result<T> {
        for _ in 0..9 {
            match test() {
                Err(e) if e.to_string().contains(&format!("(os error {})", libc::EADDRINUSE)) => continue,
                result => return result,
            }
        }
        test()
    }

    fn free_tcp() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
    }

    #[test]
    fn bound_ports_conflict_and_failed_batch_releases_its_reservations() {
        retry_ports(|| {
            let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let busy_port = busy.local_addr().unwrap().port();
            let free = free_tcp();
            assert!(Forwarder::start(&[mapping(free, 80, Protocol::Tcp), mapping(busy_port, 80, Protocol::Tcp)], Ipv4Addr::LOCALHOST).is_err());
            let tcp_udp = Forwarder::start(&[mapping(busy_port, 53, Protocol::Udp)], Ipv4Addr::LOCALHOST)?;
            drop(tcp_udp);
            let p = mapping(free, 80, Protocol::Tcp);
            assert!(Forwarder::start(&[p.clone(), p.clone()], Ipv4Addr::LOCALHOST).is_err());
            let f = Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST)?;
            assert!(Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST).is_err());
            let wildcard = Port { ip: Some(Ipv4Addr::UNSPECIFIED.into()), ..p.clone() };
            assert!(Forwarder::start(&[wildcard], Ipv4Addr::LOCALHOST).is_err());
            drop(f);
            let _again = Forwarder::start(&[p], Ipv4Addr::LOCALHOST)?;
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let p = mapping(udp.local_addr().unwrap().port(), 80, Protocol::Udp);
            assert!(Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST).is_err());
            drop(udp);
            let f = Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST)?;
            assert!(Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST).is_err());
            drop(f);
            let _again = Forwarder::start(&[p], Ipv4Addr::LOCALHOST)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tcp_relays_large_streams_and_half_closes_then_releases_active_clients() {
        retry_ports(|| {
            let guest = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let p = mapping(free_tcp(), guest.local_addr().unwrap().port(), Protocol::Tcp);
            let mut f = Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST)?;
            let mut client = TcpStream::connect((p.ip.unwrap(), p.host_port)).unwrap();
            client.set_read_timeout(Some(WAIT)).unwrap();
            let server = thread::spawn(move || {
                let (mut s, _) = crate::test_util::accept_tcp(&guest);
                s.set_read_timeout(Some(WAIT)).unwrap();
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
            let guest = server.join_within().unwrap();
            let mut active = TcpStream::connect((p.ip.unwrap(), p.host_port)).unwrap();
            active.set_read_timeout(Some(WAIT)).unwrap();
            let (_guest_connection, _) = crate::test_util::accept_tcp(&guest);
            let workers = std::mem::take(&mut f.workers);
            let at = Instant::now();
            drop(f);
            while !workers.iter().all(|w| w.is_finished()) {
                assert!(at.elapsed() < Duration::from_secs(1), "active forwarding workers stayed open");
                thread::sleep(Duration::from_millis(5));
            }
            assert!(at.elapsed() < Duration::from_secs(1));
            for worker in workers {
                worker.join_within().unwrap();
            }
            match active.read(&mut [0]) {
                Ok(n) => assert_eq!(n, 0),
                Err(e) => assert!(!transient(&e) && e.kind() != io::ErrorKind::TimedOut, "client stayed open: {e}"),
            }
            let _again = Forwarder::start(&[p], Ipv4Addr::LOCALHOST)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn drops_wake_the_workers_at_once() {
        retry_ports(|| {
            let guest = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut took = Duration::ZERO;
            for _ in 0..10 {
                let tcp = mapping(free_tcp(), guest.local_addr().unwrap().port(), Protocol::Tcp);
                let udp = Port { protocol: Protocol::Udp, ..tcp.clone() };
                let mut f = Forwarder::start(&[tcp, udp], Ipv4Addr::LOCALHOST)?;
                // Asleep in poll, with nothing to do.
                thread::sleep(Duration::from_millis(20));
                // Keep the handles so a missed wake fails by a deadline instead of hanging Drop.
                let workers = std::mem::take(&mut f.workers);
                let at = Instant::now();
                drop(f);
                wait_until("forwarding workers to stop", || workers.iter().all(|w| w.is_finished()));
                took += at.elapsed();
                for worker in workers {
                    worker.join_within().unwrap();
                }
            }
            // A worker that only noticed on its poll tick took most of a tick each time.
            let tick = Duration::from_millis(TICK as u64);
            assert!(took < tick * 5, "10 drops took {took:?}");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn a_burst_of_tcp_clients_is_taken_at_once() {
        retry_ports(|| {
            const N: usize = 64;
            let guest = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let p = mapping(free_tcp(), guest.local_addr().unwrap().port(), Protocol::Tcp);
            let _f = Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST)?;
            let server = thread::spawn(move || {
                let mut held = Vec::new();
                for _ in 0..N {
                    let (mut s, _) = crate::test_util::accept_tcp(&guest);
                    s.set_read_timeout(Some(WAIT)).unwrap();
                    let mut b = [0; 1];
                    s.read_exact(&mut b).unwrap();
                    s.write_all(&b).unwrap();
                    held.push(s);
                }
                held
            });
            // All queued on the listener before the forwarder wakes.
            let mut clients: Vec<_> = (0..N).map(|_| TcpStream::connect((p.ip.unwrap(), p.host_port)).unwrap()).collect();
            for (i, c) in clients.iter_mut().enumerate() {
                c.set_read_timeout(Some(WAIT)).unwrap();
                c.write_all(&[i as u8]).unwrap();
            }
            for (i, c) in clients.iter_mut().enumerate() {
                let mut b = [0; 1];
                c.read_exact(&mut b).unwrap();
                assert_eq!(b[0], i as u8);
            }
            assert_eq!(server.join_within().unwrap().len(), N);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn a_burst_of_datagrams_reaches_the_guest_and_back() {
        retry_ports(|| {
            const N: usize = 200;
            let guest = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            guest.set_read_timeout(Some(WAIT)).unwrap();
            let host_port = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port();
            let p = mapping(host_port, guest.local_addr().unwrap().port(), Protocol::Udp);
            let _f = Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST)?;
            let clients: Vec<_> = (0..4).map(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap()).collect();
            for c in &clients {
                c.set_read_timeout(Some(WAIT)).unwrap();
            }
            // Each client's first datagram opens its session; then a burst from all of them.
            let mut buf = [0; 64];
            for c in &clients {
                c.send_to(b"open", (p.ip.unwrap(), p.host_port)).unwrap();
                let (_, peer) = guest.recv_from(&mut buf).unwrap();
                guest.send_to(b"open", peer).unwrap();
                assert_eq!(c.recv(&mut buf).unwrap(), 4);
            }
            for i in 0..N {
                clients[i % clients.len()].send_to(&(i as u32).to_be_bytes(), (p.ip.unwrap(), p.host_port)).unwrap();
            }
            let mut peers = Vec::new();
            for _ in 0..N {
                let (n, peer) = guest.recv_from(&mut buf).unwrap();
                assert_eq!(n, 4);
                peers.push((peer, buf[..4].to_vec()));
            }
            for (peer, msg) in &peers {
                guest.send_to(msg, peer).unwrap();
            }
            let mut got = std::collections::HashSet::new();
            for i in 0..N {
                let n = clients[i % clients.len()].recv(&mut buf).unwrap();
                let v = u32::from_be_bytes(buf[..n].try_into().unwrap()) as usize;
                assert_eq!(v % clients.len(), i % clients.len(), "a reply went to another client");
                got.insert(v);
            }
            assert_eq!(got.len(), N);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn process_death_releases_ports() {
        const ENV: &str = "FLEXVM_TEST_PORTS_DEATH";
        if std::env::var_os(ENV).is_some() {
            let (_forwarder, ports) = retry_ports(|| {
                let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                let ports = vec![mapping(free_tcp(), 80, Protocol::Tcp), mapping(udp.local_addr().unwrap().port(), 53, Protocol::Udp)];
                drop(udp);
                Ok((Forwarder::start(&ports, Ipv4Addr::LOCALHOST)?, ports))
            })
            .unwrap();
            println!("forwarder ready: {}", serde_json::to_string(&ports).unwrap());
            io::stdout().flush().unwrap();
            let _ = io::stdin().read(&mut [0]);
            // Deliberately bypass Drop, even if the parent exits first.
            std::process::exit(0);
        }
        retry_ports(|| {
            let mut child = crate::test_util::ChildGuard(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "ports::tests::process_death_releases_ports", "--nocapture"])
                    .env(ENV, "1")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            use std::io::BufRead;
            let mut output = io::BufReader::new(child.stdout.take().unwrap());
            let ready = thread::spawn(move || loop {
                let mut line = String::new();
                assert!(output.read_line(&mut line).unwrap() > 0, "child did not bind its ports");
                if let Some(spec) = line.strip_prefix("forwarder ready: ") {
                    break serde_json::from_str(spec.trim()).unwrap();
                }
            });
            let ports: Vec<Port> = ready.join_within().unwrap();
            assert!(Forwarder::start(&ports, Ipv4Addr::LOCALHOST).is_err());
            child.kill().unwrap();
            child.wait().unwrap();
            let _again = Forwarder::start(&ports, Ipv4Addr::LOCALHOST)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn udp_replies_are_isolated_by_client_and_zero_length_datagrams_work() {
        retry_ports(|| {
            let guest = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            guest.set_read_timeout(Some(WAIT)).unwrap();
            let host_port = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port();
            let p = mapping(host_port, guest.local_addr().unwrap().port(), Protocol::Udp);
            let _f = Forwarder::start(std::slice::from_ref(&p), Ipv4Addr::LOCALHOST)?;
            let a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            for client in [&a, &b] {
                client.set_read_timeout(Some(WAIT)).unwrap();
            }
            a.send_to(b"a", (p.ip.unwrap(), p.host_port)).unwrap();
            b.send_to(b"b", (p.ip.unwrap(), p.host_port)).unwrap();
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
            a.send_to(b"", (p.ip.unwrap(), p.host_port)).unwrap();
            let (n, peer) = guest.recv_from(&mut buf).unwrap();
            assert_eq!(n, 0);
            guest.send_to(b"", peer).unwrap();
            assert_eq!(a.recv(&mut buf).unwrap(), 0);
            Ok(())
        })
        .unwrap();
    }
}
