//! Host-local proxies. Bound sockets are the reservation and the only external resource:
//! even SIGKILL releases them, so gc has no kernel rules or port files to sweep.
use std::collections::HashMap;
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
/// Once either side fails, how long buffered data and the other side's FIN have to finish:
/// closing on it at once would reset what the kernel has yet to deliver.
const LINGER: Duration = Duration::from_secs(10);
/// The most datagrams taken from one socket per wakeup: a flood on one cannot starve the others.
const BURST: usize = 1024;
/// Workers wake for their sockets or `Forwarder::drop`'s eventfd; this only bounds when idle
/// sessions, stalled connects, and failure deadlines are noticed.
const TICK: libc::c_int = 1000;
/// How long accepting rests once out of descriptors (or memory).
const ACCEPT_REST: Duration = Duration::from_millis(100);

/// Idle and failure time can be pinned in a test worker; connect deadlines keep using real time.
fn idle_now() -> Instant {
    #[cfg(test)]
    if let Some(now) = tests::CLOCK.with(|c| c.borrow().as_ref().map(|(_, now)| *now)) {
        return now;
    }
    Instant::now()
}

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

impl Port {
    /// Whether both would bind one address and port (no IP: both wildcards; a wildcard takes its family's).
    pub fn overlaps(&self, other: &Self) -> bool {
        let ips = |p: &Self| p.ip.map_or_else(|| vec![Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()], |ip| vec![ip]);
        let covers = |a: IpAddr, b: IpAddr| a == b || (a.is_unspecified() && a.is_ipv4() == b.is_ipv4());
        self.protocol == other.protocol
            && self.host_port == other.host_port
            && ips(self).into_iter().any(|a| ips(other).into_iter().any(|b| covers(a, b) || covers(b, a)))
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
                Protocol::Udp => udp(fds.into_iter().map(UdpSocket::from).collect(), target, stop.as_fd(), CONNECTIONS, IDLE),
            })?);
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn bound_socket(&self) -> BorrowedFd<'_> {
        self.bound[0].0[0].as_fd()
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
fn wait(fds: &mut Vec<libc::pollfd>, stop: BorrowedFd, until: Option<Instant>) -> bool {
    fds.push(libc::pollfd { fd: stop.as_raw_fd(), events: libc::POLLIN, revents: 0 });
    let ms = until.map_or(TICK, |u| (u.saturating_duration_since(Instant::now()).as_millis() as libc::c_int + 1).min(TICK));
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, ms) };
    fds.pop().is_some_and(|s| s.revents == 0)
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
    stream.set_nodelay(true)?;
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
    bytes: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    /// Its source failed (a reset, say): it ends once what was read before is written.
    failed: bool,
    /// Its sink failed: what it held is dropped, and what its source still sends is read and dropped.
    broken: bool,
    /// It has ended: its source finished (a FIN, or a failure once what came before is written) and
    /// that end was passed on as a FIN, or its sink failed and its source has finished since.
    done: bool,
}

impl Direction {
    fn events(&self, reverse: &Self) -> i16 {
        (if !self.eof && self.end < BUFFER { libc::POLLIN } else { 0 }) | (if reverse.start < reverse.end { libc::POLLOUT } else { 0 })
    }

    /// True if it relayed data. Each pass takes at most BUFFER bytes per direction. A read error
    /// still writes what came before it (a reply the guest sent before resetting); a write error
    /// ends only this direction.
    fn pump(&mut self, mut from: &TcpStream, mut to: &TcpStream) -> bool {
        let (mut moved, mut taken) = (false, 0);
        while !self.eof && self.end < BUFFER && taken < BUFFER {
            self.bytes.resize(BUFFER, 0);
            match from.read(&mut self.bytes[self.end..]) {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    taken += n;
                    // Broken, it reads only to discard: closing a socket with data unread would reset
                    // it, and the peer would lose what the other direction has yet to deliver.
                    if !self.broken {
                        self.end += n;
                        moved = true;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => (self.eof, self.failed) = (true, true),
            }
        }
        while self.start < self.end {
            match to.write(&self.bytes[self.start..self.end]) {
                Ok(n) if n > 0 => {
                    self.start += n;
                    moved = true;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                _ => {
                    (self.broken, self.start, self.end) = (true, 0, 0);
                    break;
                }
            }
        }
        if self.start == self.end {
            (self.start, self.end) = (0, 0);
            // A failed source ends as a FIN too: the sink gets all that came before, cleanly.
            if self.eof && !self.done {
                if !self.broken {
                    let _ = to.shutdown(Shutdown::Write);
                }
                self.done = true;
            }
        }
        moved
    }
}

fn rest(e: &io::Error, resting: &mut Option<Instant>) -> bool {
    let exhausted = matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM));
    if exhausted {
        *resting = Some(Instant::now() + ACCEPT_REST);
    }
    exhausted
}

struct Connection {
    client: TcpStream,
    guest: TcpStream,
    connected: bool,
    /// Connected on this pass, not yet admitted: it has moved nothing.
    fresh: bool,
    since: Instant,
    /// When it last moved data (or connected). Data it holds for a stalled reader keeps it from idling.
    active: Instant,
    out: Direction,
    incoming: Direction,
    /// The error and hangup bits each socket has reported (they stay set): such a socket is polled
    /// only for what its directions still want of it, or poll would return at once every pass.
    client_down: i16,
    guest_down: i16,
    /// Since either side failed, or it last relayed data after: drainage and the other side's FIN
    /// have LINGER to make progress.
    lingering: Option<Instant>,
}

impl Connection {
    /// Relays one connected forward, bounding failures even if buffered data cannot drain.
    fn forward(&mut self, client: i16, guest: i16) -> bool {
        if self.lingering.is_some_and(|t| idle_now().duration_since(t) > LINGER) {
            return false;
        }
        if client == 0 && guest == 0 {
            return true;
        }
        (self.client_down, self.guest_down) = (self.client_down | client & DOWN, self.guest_down | guest & DOWN);
        // Both directions: what one socket sent before failing still goes out the other way.
        let (out, incoming) = (self.out.pump(&self.client, &self.guest), self.incoming.pump(&self.guest, &self.client));
        if out || incoming {
            self.active = idle_now();
            // What is still delivered keeps it: a slow reader gets the rest, and LINGER for its FIN after.
            self.lingering = self.lingering.and(Some(self.active));
        }
        // A failed socket (an error polled, or found reading or writing it): nothing reaches it any
        // more. Allow buffered data to drain, but bound each stall even if the sink never reads.
        let failed = |down: i16, from: &Direction, to: &Direction| down & (libc::POLLERR | libc::POLLNVAL) != 0 || from.failed || to.broken;
        let client_failed = failed(self.client_down, &self.out, &self.incoming);
        if client_failed || failed(self.guest_down, &self.incoming, &self.out) {
            self.lingering.get_or_insert_with(idle_now);
        }
        !self.out.done || !self.incoming.done && !client_failed
    }

    /// Connected, with nothing it holds yet to deliver, and nothing relayed for `idle`.
    fn idle(&self, idle: Duration) -> bool {
        let queued = |d: &Direction| d.start < d.end;
        self.connected && !queued(&self.out) && !queued(&self.incoming) && idle_now().duration_since(self.active) >= idle
    }

    /// Its client failed: reset, or a socket error pending (POLLERR), or both directions closed (POLLHUP).
    /// A FIN alone is not that: a half-closed client may still wait for its reply. At the cap, a gone
    /// one takes over no live forward.
    fn client_gone(&self) -> bool {
        let mut p = libc::pollfd { fd: self.client.as_raw_fd(), events: 0, revents: 0 };
        (unsafe { libc::poll(&mut p, 1, 0) }) > 0 && p.revents & (libc::POLLERR | libc::POLLHUP) != 0
    }
}

const DOWN: i16 = libc::POLLERR | libc::POLLHUP | libc::POLLNVAL;

/// The connected forward idle longest, if for at least `idle`: the one to close for a new client at the cap.
fn idlest(connections: &[Connection], idle: Duration) -> Option<usize> {
    connections.iter().enumerate().filter(|(_, c)| c.idle(idle)).min_by_key(|(_, c)| c.active).map(|(i, _)| i)
}

/// How many connected forwards have been idle for `idle`: each may make way for one more client.
fn spare(connections: &[Connection], idle: Duration) -> usize {
    connections.iter().filter(|c| c.idle(idle)).count()
}

/// Keeps at most `cap` connected: each fresh one over it replaces the idlest, or else is closed itself.
/// Only fresh ones take it over, so there is always one to close. One whose client is gone already
/// (it hung up while its guest connected) goes first: it takes over no live forward.
fn admit(connections: &mut Vec<Connection>, cap: usize, idle: Duration) {
    while connections.iter().filter(|c| c.connected).count() > cap {
        let gone = connections.iter().position(|c| c.fresh && c.client_gone());
        let Some(i) = gone.or_else(|| idlest(connections, idle)).or_else(|| connections.iter().position(|c| c.fresh)) else { break };
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
    let mut fds = Vec::new();
    // Out of descriptors, accepting rests a while (the forwards go on): a pending client would wake it at once.
    let mut resting: Option<Instant> = None;
    loop {
        resting = resting.filter(|&r| r > Instant::now());
        // Idle forwards cannot hold the cap: at it, a waiting client replaces the idlest once it connects.
        let room = if resting.is_none() && connections.len() < cap + spare(&connections, idle) { libc::POLLIN } else { 0 };
        fds.clear();
        fds.extend(listeners.iter().map(|l| poll(l, room)));
        for c in &connections {
            // Connected sockets stay polled for errors and hangups after read EOF (a half-closed
            // client that resets), until they report one.
            let (client, guest) = if c.connected { (c.out.events(&c.incoming), c.incoming.events(&c.out)) } else { (0, libc::POLLOUT) };
            let fd = |s: &TcpStream, events: i16, down: i16| if down != 0 && events == 0 { -1 } else { s.as_raw_fd() };
            fds.push(libc::pollfd { fd: if c.connected { fd(&c.client, client, c.client_down) } else { -1 }, events: client, revents: 0 });
            fds.push(libc::pollfd { fd: fd(&c.guest, guest, c.guest_down), events: guest, revents: 0 });
        }
        if !wait(&mut fds, stop, resting) {
            return;
        }
        #[cfg(test)]
        tests::tick_clock();
        let (accepting, forwarding) = fds.split_at(listeners.len());
        let mut each = forwarding.chunks(2);
        connections.retain_mut(|c| {
            let [client, guest] = each.next().unwrap() else { unreachable!() };
            if !c.connected {
                if guest.revents == 0 {
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
                (c.fresh, c.active) = (true, idle_now());
                return true;
            }
            c.forward(client.revents, guest.revents)
        });
        // Only now: a replacement whose connect fails closes nothing.
        admit(&mut connections, cap, idle);
        let spare = spare(&connections, idle);
        for (listener, fd) in listeners.iter().zip(accepting) {
            // Attempts are bounded too: a client whose guest connect fails (EMFILE, say) is dropped,
            // and a flood of them must still let the loop see its stop.
            if resting.is_some() || fd.revents == 0 {
                continue;
            }
            for _ in 0..CONNECTIONS {
                if connections.len() >= cap + spare {
                    break;
                }
                let client = match listener.accept() {
                    Ok((client, _)) => client,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if rest(&e, &mut resting) => break,
                    Err(_) => break,
                };
                match connect(target) {
                    Err(e) if rest(&e, &mut resting) => break,
                    Ok(guest) if client.set_nonblocking(true).is_ok() && client.set_nodelay(true).is_ok() => {
                        connections.push(Connection {
                            client,
                            guest,
                            connected: false,
                            fresh: false,
                            since: Instant::now(),
                            active: idle_now(),
                            out: Direction::default(),
                            incoming: Direction::default(),
                            client_down: 0,
                            guest_down: 0,
                            lingering: None,
                        });
                    }
                    _ => {}
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

/// The session quiet longest, if for at least `quiet`: the one a new client replaces at the cap.
fn udp_idle<T: Copy>(clients: &HashMap<T, (UdpSocket, Instant, usize)>, now: Instant, quiet: Duration) -> Option<T> {
    clients.iter().min_by_key(|(_, (_, at, _))| *at).filter(|(_, (_, at, _))| now.duration_since(*at) >= quiet).map(|(peer, _)| *peer)
}

/// At most `cap` sessions, each expiring `idle` after its last datagram; at the cap a new client
/// replaces the session quiet longest, if for half that, once its own socket is ready.
fn udp(listeners: Vec<UdpSocket>, target: SocketAddrV4, stop: BorrowedFd, cap: usize, idle: Duration) {
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
        if !wait(&mut fds, stop, None) {
            return;
        }
        #[cfg(test)]
        tests::tick_clock();
        // Replies first: the sessions polled are those in `peers`, before any is added below.
        for (peer, fd) in peers.iter().zip(&fds[listeners.len()..]) {
            let Some((s, at, i)) = clients.get_mut(peer).filter(|_| fd.revents != 0) else { continue };
            for _ in 0..BURST {
                match s.recv(&mut buf) {
                    Ok(n) => {
                        #[cfg(test)]
                        tests::tick_clock();
                        let _ = send_datagram(&listeners[*i], &buf[..n], peer.0, peer.1);
                        *at = idle_now();
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    // WouldBlock, or the guest refused one (ICMP): the session goes on.
                    Err(_) => break,
                }
            }
        }
        for ((i, listener), fd) in listeners.iter().enumerate().zip(&fds) {
            if fd.revents == 0 {
                continue;
            }
            for _ in 0..BURST {
                let (n, peer) = match recv_datagram(listener, &mut buf) {
                    Ok((n, peer, local)) => (n, (peer, local)),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                #[cfg(test)]
                tests::tick_clock();
                if !clients.contains_key(&peer) {
                    // Half the expiry protects recent traffic while letting new clients through.
                    // Admitted (in place of the victim, if any) only once its socket is ready.
                    let admit = if clients.len() < cap { Some(None) } else { udp_idle(&clients, idle_now(), idle / 2).map(Some) };
                    if let Some(victim) = admit {
                        if let Ok(s) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
                            if s.connect(target).and_then(|()| s.set_nonblocking(true)).is_ok() {
                                if let Some(v) = victim {
                                    clients.remove(&v);
                                }
                                clients.insert(peer, (s, idle_now(), i));
                            }
                        }
                    }
                }
                if let Some((s, at, _)) = clients.get_mut(&peer) {
                    let _ = s.send(&buf[..n]);
                    *at = idle_now();
                }
                #[cfg(test)]
                tests::udp_processed(peer.0);
            }
        }
        clients.retain(|_, (_, at, _)| idle_now().duration_since(*at) < idle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{wait_until, JoinWithin, WAIT};

    // Snapshot per TCP pass or UDP datagram: advancing time cannot age a timestamp between
    // relaying bytes and recording their activity. Other workers and tests keep real clocks.
    thread_local! {
        pub(super) static CLOCK: std::cell::RefCell<Option<(Arc<std::sync::Mutex<Instant>>, Instant)>> = const { std::cell::RefCell::new(None) };
        static UDP_PROCESSED: std::cell::RefCell<Option<std::sync::mpsc::Sender<SocketAddr>>> = const { std::cell::RefCell::new(None) };
    }

    pub(super) fn udp_processed(peer: SocketAddr) {
        UDP_PROCESSED.with(|sender| {
            if let Some(sender) = sender.borrow().as_ref() {
                let _ = sender.send(peer);
            }
        });
    }

    pub(super) fn tick_clock() {
        CLOCK.with(|c| {
            if let Some((clock, now)) = c.borrow_mut().as_mut() {
                *now = *clock.lock().unwrap();
            }
        });
    }

    fn pin_clock(clock: Arc<std::sync::Mutex<Instant>>) {
        let now = *clock.lock().unwrap();
        CLOCK.with(|c| *c.borrow_mut() = Some((clock, now)));
    }

    fn transient(e: &io::Error) -> bool {
        matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted)
    }

    #[test]
    fn socket_exhaustion_rests_accepting() {
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            let mut resting = None;
            let before = Instant::now();
            assert!(rest(&io::Error::from_raw_os_error(errno), &mut resting));
            assert!(resting.unwrap() >= before + ACCEPT_REST);
            assert!(resting.unwrap() <= Instant::now() + ACCEPT_REST);
        }
        for errno in [libc::ECONNREFUSED, libc::EINTR, libc::EAGAIN] {
            let mut resting = None;
            assert!(!rest(&io::Error::from_raw_os_error(errno), &mut resting));
            assert!(resting.is_none());
        }
    }

    #[test]
    fn udp_admission_preserves_recent_sessions() {
        let now = Instant::now();
        let mut clients = HashMap::new();
        for (peer, idle) in [(1, IDLE / 4), (2, IDLE / 2), (3, IDLE * 3 / 4)] {
            clients.insert(peer, (UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(), now - idle, 0));
        }
        assert_eq!(udp_idle(&clients, now, IDLE / 2), Some(3));
        clients.remove(&3);
        assert_eq!(udp_idle(&clients, now, IDLE / 2), Some(2));
        clients.remove(&2);
        assert_eq!(udp_idle(&clients, now, IDLE / 2), None);
    }

    #[test]
    fn at_the_udp_cap_a_new_client_replaces_only_the_session_quiet_longest() {
        let ip = Ipv4Addr::new(127, 0, 0, 2);
        let guest = UdpSocket::bind((ip, 0)).unwrap();
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (addr, target) = (listener.local_addr().unwrap(), SocketAddrV4::new(ip, guest.local_addr().unwrap().port()));
        let stop = Arc::new(unsafe { OwnedFd::from_raw_fd(libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK)) });
        let start = Instant::now();
        let clock = Arc::new(std::sync::Mutex::new(start));
        let (processed, received) = std::sync::mpsc::channel();
        let worker = {
            let stop = stop.clone();
            let clock = clock.clone();
            thread::spawn(move || {
                pin_clock(clock);
                UDP_PROCESSED.with(|sender| *sender.borrow_mut() = Some(processed));
                udp(vec![listener], target, stop.as_fd(), 2, IDLE);
            })
        };
        let worker = Worker { stop, thread: Some(worker) };
        let client = || UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (a, b, c) = (client(), client(), client());
        // Different sending sockets can arrive out of order, even on the same listener.
        // Acknowledge processing (including refusal) before another probe or clock advance.
        let send = |client: &UdpSocket, data: &[u8]| {
            client.send_to(data, addr).unwrap();
            assert_eq!(received.recv_timeout(WAIT).unwrap(), client.local_addr().unwrap());
        };
        // What the guest gets next, and from which session.
        let got = || {
            guest.set_read_timeout(Some(WAIT)).unwrap();
            let mut buf = [0; 16];
            let (n, from) = guest.recv_from(&mut buf).unwrap();
            (String::from_utf8_lossy(&buf[..n]).into_owned(), from)
        };
        send(&a, b"a");
        let (_, from_a) = got();
        send(&b, b"b");
        let (_, from_b) = got();
        send(&c, b"c");
        send(&b, b"recent");
        assert_eq!(got(), ("recent".into(), from_b), "admitted over the cap with both sessions recent");
        *clock.lock().unwrap() = start + IDLE * 3 / 8;
        send(&b, b"busy");
        assert_eq!(got(), ("busy".into(), from_b));
        // a quiet for half the expiry, b not: a goes for c.
        *clock.lock().unwrap() = start + IDLE * 5 / 8;
        send(&c, b"c");
        let (data, from_c) = got();
        assert!(data == "c" && from_c != from_a && from_c != from_b);
        assert!(clock.lock().unwrap().duration_since(start) < IDLE, "replacement must precede expiry");
        send(&a, b"a");
        send(&b, b"survived");
        assert_eq!(got(), ("survived".into(), from_b), "a was not replaced or b's busy session was replaced");
        send(&c, b"survived");
        assert_eq!(got(), ("survived".into(), from_c), "c's admitted session was replaced");
        worker.halt();
    }

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
            Connection {
                client,
                guest,
                connected,
                fresh: false,
                since: active,
                active,
                out: Direction::default(),
                incoming: Direction::default(),
                client_down: 0,
                guest_down: 0,
                lingering: None,
            }
        };
        let mut connections = vec![connection(true, ago(IDLE / 2)), connection(false, ago(IDLE * 3))];
        assert_eq!(idlest(&connections, IDLE), None, "a busy forward and a pending connect stay");
        connections.push(connection(true, ago(IDLE)));
        connections.push(connection(true, ago(IDLE * 2)));
        assert_eq!(idlest(&connections, IDLE), Some(3));
        // What it still holds for a stalled reader would be lost: it is not idle.
        connections[3].incoming.end = 1;
        assert_eq!((idlest(&connections, IDLE), spare(&connections, IDLE)), (Some(2), 1));
    }

    #[test]
    fn a_replacement_whose_client_hung_up_while_connecting_closes_no_idle_forward() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let ago = |d: Duration| Instant::now().checked_sub(d).unwrap();
        let connection = |since, fresh| {
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let guest = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            Connection {
                client,
                guest,
                connected: true,
                fresh,
                since,
                active: since,
                out: Direction::default(),
                incoming: Direction::default(),
                client_down: 0,
                guest_down: 0,
                lingering: None,
            }
        };
        let (old, new) = (ago(IDLE * 2), ago(Duration::ZERO));
        let mut connections = vec![connection(old, false), connection(new, true)];
        // The fresh one's client's peer, found by address: accept order need not be connect order. A FIN
        // alone is no hangup (a half-closed client may wait for its reply); a reset is.
        let mut peers: Vec<_> = (0..4).map(|_| listener.accept().unwrap().0).collect();
        let client = connections[1].client.local_addr().unwrap();
        let peer = peers.remove(peers.iter().position(|p| p.peer_addr().unwrap() == client).unwrap());
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        wait_until("the FIN to arrive", || {
            let mut b = 0u8;
            (unsafe { libc::recv(connections[1].client.as_raw_fd(), (&mut b as *mut u8).cast(), 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) }) == 0
        });
        assert!(!connections[1].client_gone(), "half-closed, it still waits for its reply");
        let linger = libc::linger { l_onoff: 1, l_linger: 0 };
        let size = std::mem::size_of::<libc::linger>() as libc::socklen_t;
        assert_eq!(unsafe { libc::setsockopt(peer.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER, (&linger as *const libc::linger).cast(), size) }, 0);
        drop(peer);
        let fresh = &connections[1];
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fresh.client_gone() {
            assert!(Instant::now() < deadline, "the hangup never arrived");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!connections[0].client_gone());
        admit(&mut connections, 1, IDLE);
        assert_eq!(connections.iter().map(|c| c.since).collect::<Vec<_>>(), [old], "the idle forward stays");
    }

    #[test]
    fn with_none_idle_the_replacement_just_connected_is_closed_not_one_already_forwarding() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let ago = |d: Duration| Instant::now().checked_sub(d).unwrap();
        let connection = |since, fresh| {
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let guest = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            Connection {
                client,
                guest,
                connected: true,
                fresh,
                since,
                active: Instant::now(),
                out: Direction::default(),
                incoming: Direction::default(),
                client_down: 0,
                guest_down: 0,
                lingering: None,
            }
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

    /// A running port worker: `halt` stops it and checks it ended; dropped (a failed test), it is stopped all the same.
    struct Worker {
        stop: Arc<OwnedFd>,
        thread: Option<JoinHandle<()>>,
    }

    impl Worker {
        fn signal(&self) {
            unsafe { libc::write(self.stop.as_raw_fd(), (&1u64 as *const u64).cast(), 8) };
        }

        fn halt(mut self) {
            self.signal();
            self.thread.take().unwrap().join_within().unwrap();
        }
    }

    impl Drop for Worker {
        fn drop(&mut self) {
            if let Some(t) = self.thread.take() {
                self.signal();
                let _ = t.join();
            }
        }
    }

    /// A TCP worker of `cap` connections to a new guest listener: its address, the guest, and the worker.
    fn worker(cap: usize, idle: Duration) -> (SocketAddr, TcpListener, Worker) {
        worker_with_clock(cap, idle, None)
    }

    fn worker_with_clock(cap: usize, idle: Duration, clock: Option<Arc<std::sync::Mutex<Instant>>>) -> (SocketAddr, TcpListener, Worker) {
        // Unrelated localhost RPC retries must not enter the guest's accept queue.
        let ip = Ipv4Addr::new(127, 0, 0, 2);
        let guest = TcpListener::bind((ip, 0)).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (addr, target) = (listener.local_addr().unwrap(), SocketAddrV4::new(ip, guest.local_addr().unwrap().port()));
        let stop = Arc::new(unsafe { OwnedFd::from_raw_fd(libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK)) });
        let worker = {
            let stop = stop.clone();
            thread::spawn(move || {
                if let Some(clock) = clock {
                    pin_clock(clock);
                }
                tcp(vec![listener], target, stop.as_fd(), cap, idle)
            })
        };
        (addr, guest, Worker { stop, thread: Some(worker) })
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
        let start = Instant::now();
        let clock = Arc::new(std::sync::Mutex::new(start));
        let (addr, guest, worker) = worker_with_clock(1, IDLE, Some(clock.clone()));
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        let (mut server, _) = crate::test_util::accept_tcp(&guest);
        echo(&mut client, &mut server);
        let _filler = fill(&guest);
        *clock.lock().unwrap() = start + IDLE;
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
        worker.halt();
    }

    #[test]
    fn out_of_descriptors_accepting_or_connecting_rests_and_forwards_go_on() {
        const CHILD: &str = "FLEXVM_TEST_ACCEPT_EMFILE";
        let Ok(stage) = std::env::var(CHILD) else {
            // Alone in a process: it runs out of descriptors.
            for stage in ["accept", "connect"] {
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "ports::tests::out_of_descriptors_accepting_or_connecting_rests_and_forwards_go_on"])
                    .env(CHILD, stage)
                    .status()
                    .unwrap();
                assert!(status.success(), "{stage}: {status}");
            }
            return;
        };
        unsafe {
            let mut limit: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            limit.rlim_cur = limit.rlim_cur.min(1024);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
        }
        let (addr, guest, worker) = worker(CONNECTIONS, IDLE);
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        let (mut server, _) = crate::test_util::accept_tcp(&guest);
        echo(&mut client, &mut server);
        let mut fillers: Vec<std::fs::File> = std::iter::from_fn(|| std::fs::File::open("/dev/null").ok()).collect();
        // One for the pending client; optionally one to accept it, but none for its guest socket.
        fillers.pop();
        if stage == "connect" {
            fillers.pop();
        }
        let _pending = TcpStream::connect(addr).unwrap();
        let cpu = || unsafe {
            let mut u: libc::rusage = std::mem::zeroed();
            libc::getrusage(libc::RUSAGE_SELF, &mut u);
            Duration::new(u.ru_utime.tv_sec as u64, u.ru_utime.tv_usec as u32 * 1000)
                + Duration::new(u.ru_stime.tv_sec as u64, u.ru_stime.tv_usec as u32 * 1000)
        };
        let (from, used) = (Instant::now(), cpu());
        for _ in 0..50 {
            echo(&mut client, &mut server);
        }
        assert!(from.elapsed() < Duration::from_secs(2), "the forward slowed to {:?} for 50 echoes", from.elapsed());
        thread::sleep(Duration::from_secs(1));
        assert!(cpu() - used < Duration::from_millis(500), "spinning: {:?} of CPU", cpu() - used);
        drop(fillers);
        let _retry = (stage == "connect").then(|| TcpStream::connect(addr).unwrap());
        let _accepted = crate::test_util::accept_tcp(&guest);
        worker.halt();
    }

    #[test]
    fn a_replacement_still_connecting_closes_nothing() {
        const IDLE: Duration = Duration::from_millis(500);
        let (addr, guest, worker) = worker(1, IDLE);
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        let (mut server, _) = crate::test_util::accept_tcp(&guest);
        echo(&mut client, &mut server);
        let _filler = fill(&guest);
        thread::sleep(IDLE * 2);
        let _waiting = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(TICK as u64) * 2);
        echo(&mut client, &mut server);
        worker.halt();
    }

    #[test]
    fn at_the_cap_a_waiting_client_replaces_the_idlest_forward_once_it_is_idle() {
        const IDLE: Duration = Duration::from_secs(2);
        let (addr, guest, worker) = worker(2, IDLE);
        let at = Instant::now();
        let mut forwards = Vec::new();
        for _ in 0..2 {
            let mut client = TcpStream::connect(addr).unwrap();
            client.set_read_timeout(Some(WAIT)).unwrap();
            let (mut server, _) = crate::test_util::accept_tcp(&guest);
            echo(&mut client, &mut server);
            forwards.push((client, server));
        }
        let mut waiting = TcpStream::connect(addr).unwrap();
        waiting.write_all(b"w").unwrap();
        guest.set_nonblocking(true).unwrap();
        let mut accepted = None;
        wait_until("the waiting client to replace the idle forward", || {
            let (client, server) = &mut forwards[1];
            echo(client, server);
            match guest.accept() {
                Ok((server, _)) => accepted = Some(server),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return false,
                Err(e) => panic!("accept: {e}"),
            }
            true
        });
        assert!(at.elapsed() >= IDLE, "a forward was closed before it was idle");
        let mut server = accepted.unwrap();
        server.set_read_timeout(Some(WAIT)).unwrap();
        let mut b = [0];
        server.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"w");
        match forwards[0].0.read(&mut b) {
            Ok(n) => assert_eq!(n, 0, "the idlest forward is closed"),
            Err(e) => assert!(!transient(&e) && e.kind() != io::ErrorKind::TimedOut, "the idlest forward stayed open: {e}"),
        }
        let (client, server) = &mut forwards[1];
        echo(client, server);
        worker.halt();
    }

    #[test]
    fn a_half_closed_client_admitted_at_the_cap_still_gets_its_reply() {
        let start = Instant::now();
        let clock = Arc::new(std::sync::Mutex::new(start));
        let (addr, guest, worker) = worker_with_clock(1, IDLE, Some(clock.clone()));
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        let (mut server, _) = crate::test_util::accept_tcp(&guest);
        echo(&mut client, &mut server);
        *clock.lock().unwrap() = start + IDLE;
        // An empty request, ended by its FIN before its guest connect completes: the guest's full accept
        // queue holds the connect until the FIN is acknowledged.
        let filler = fill(&guest);
        let mut asking = TcpStream::connect(addr).unwrap();
        asking.shutdown(std::net::Shutdown::Write).unwrap();
        asking.set_read_timeout(Some(WAIT)).unwrap();
        wait_until("the FIN to be acknowledged", || {
            let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
            let mut size = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
            let got = unsafe { libc::getsockopt(asking.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_INFO, (&mut info as *mut libc::tcp_info).cast(), &mut size) };
            // TCP_FIN_WAIT2: its FIN is acknowledged, the other end still open.
            got == 0 && info.tcpi_state == 5
        });
        // Now the guest takes the fillers, then the forward's connect (its SYN, sent again).
        let fillers: Vec<SocketAddr> = filler.iter().map(|f| f.local_addr().unwrap()).collect();
        let mut replying = loop {
            let (s, from) = crate::test_util::accept_tcp(&guest);
            if !fillers.contains(&from) {
                break s;
            }
        };
        replying.set_read_timeout(Some(WAIT)).unwrap();
        assert_eq!(replying.read(&mut [0]).unwrap(), 0, "the FIN is passed on");
        replying.write_all(b"reply").unwrap();
        drop(replying);
        let mut got = Vec::new();
        asking.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"reply");
        match client.read(&mut [0]) {
            Ok(n) => assert_eq!(n, 0, "the idle forward made way"),
            Err(e) => assert!(!transient(&e) && e.kind() != io::ErrorKind::TimedOut, "the idle forward stayed open: {e}"),
        }
        worker.halt();
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
    fn duplicate_port_specs_are_rejected_before_binding() {
        let specs = |a: &str, b: &str| {
            let args = crate::Args::parse(["run", "-p", a, "-p", b, "image"].map(String::from)).unwrap();
            crate::port_specs(&args)
        };
        for (a, b) in [
            ("8080:80", "8080:80/tcp"),
            ("127.0.0.1:8080:80", "127.0.0.1:8080:81"),
            ("[::1]:8080:80", "[0:0:0:0:0:0:0:1]:8080:80"),
            // A wildcard overlaps its family's addresses: the second bind would fail.
            ("8080:80", "127.0.0.1:8080:80"),
            ("[::]:8080:80", "8080:80"),
            ("0.0.0.0:8080:80/udp", "127.0.0.1:8080:9/udp"),
        ] {
            assert!(specs(a, b).unwrap_err().to_string().contains("duplicate port mapping"));
        }
        for (a, b) in [
            ("8080:80", "8080:80/udp"),
            ("127.0.0.1:8080:80", "127.0.0.2:8080:80"),
            ("8080:80", "8081:80"),
            ("0.0.0.0:8080:80", "[::1]:8080:80"),
            ("[::]:8080:80", "127.0.0.1:8080:80"),
        ] {
            assert_eq!(specs(a, b).unwrap().len(), 2);
        }
    }

    #[test]
    fn pump_drains_more_than_one_read_and_reuses_its_buffer() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut source = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (from, _) = listener.accept().unwrap();
        let to = connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port())).unwrap();
        assert!(to.nodelay().unwrap());
        let (mut sink, _) = crate::test_util::accept_tcp(&listener);
        from.set_nonblocking(true).unwrap();
        sink.set_read_timeout(Some(WAIT)).unwrap();
        let mut direction = Direction::default();
        for byte in [42, 17] {
            let data = vec![byte; BUFFER];
            source.write_all(&data).unwrap();
            wait_until("the source bytes to arrive", || {
                let mut available: libc::c_int = 0;
                assert_eq!(unsafe { libc::ioctl(from.as_raw_fd(), libc::FIONREAD, &mut available) }, 0);
                available as usize == BUFFER
            });
            assert!(direction.pump(&from, &to));
            assert_eq!((direction.start, direction.end), (0, 0));
            let mut received = vec![0; BUFFER];
            sink.read_exact(&mut received).unwrap();
            assert_eq!(received, data);
        }
    }

    #[test]
    fn a_reset_after_client_half_close_releases_the_slot_without_guest_writes() {
        let (addr, guest, worker) = worker(1, IDLE);
        let client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = crate::test_util::accept_tcp(&guest);
        server.set_read_timeout(Some(WAIT)).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(server.read(&mut [0]).unwrap(), 0);
        let linger = libc::linger { l_onoff: 1, l_linger: 0 };
        assert_eq!(
            unsafe {
                libc::setsockopt(client.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER, (&linger as *const libc::linger).cast(), size_of_val(&linger) as _)
            },
            0
        );
        drop(client);
        let mut replacement = TcpStream::connect(addr).unwrap();
        replacement.set_read_timeout(Some(WAIT)).unwrap();
        let (mut accepted, _) = crate::test_util::accept_tcp(&guest);
        echo(&mut replacement, &mut accepted);
        worker.halt();
    }

    fn reset(s: TcpStream) {
        let linger = libc::linger { l_onoff: 1, l_linger: 0 };
        let set =
            unsafe { libc::setsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER, (&linger as *const libc::linger).cast(), size_of_val(&linger) as _) };
        assert_eq!(set, 0);
    }

    #[test]
    fn discarded_requests_cannot_keep_a_failed_guest_with_a_blocked_reply_alive() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (host, _) = crate::test_util::accept_tcp(&listener);
        let guest = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = crate::test_util::accept_tcp(&listener);
        client.set_write_timeout(Some(WAIT)).unwrap();
        host.set_nonblocking(true).unwrap();
        guest.set_nonblocking(true).unwrap();
        let size: libc::c_int = 4096;
        for (socket, name) in [(&host, libc::SO_SNDBUF), (&client, libc::SO_RCVBUF)] {
            assert_eq!(
                unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, name, (&size as *const libc::c_int).cast(), size_of_val(&size) as _) },
                0
            );
        }
        let start = Instant::now();
        let clock = Arc::new(std::sync::Mutex::new(start));
        pin_clock(clock.clone());
        let mut connection = Connection {
            client: host,
            guest,
            connected: true,
            fresh: false,
            since: start,
            active: start,
            out: Direction::default(),
            incoming: Direction { bytes: vec![42; BUFFER], end: BUFFER, ..Direction::default() },
            client_down: 0,
            guest_down: 0,
            lingering: None,
        };
        // The client never reads: fill its receive queue and the proxy's send queue and buffer. ACKs
        // still due may free a little more later: the deadline is checked against relays as seen.
        wait_until("the reply to block", || {
            connection.incoming.start = 0;
            connection.incoming.end = BUFFER;
            !connection.incoming.pump(&connection.guest, &connection.client)
        });
        reset(server);
        let mut fd = poll(&connection.guest, libc::POLLIN);
        assert_eq!(unsafe { libc::poll(&mut fd, 1, WAIT.as_millis() as _) }, 1);
        assert_ne!(fd.revents & libc::POLLERR, 0);
        assert!(connection.forward(0, fd.revents));
        assert_eq!(connection.lingering, Some(start), "failure starts the deadline before the reply drains");
        // Discover the broken outgoing direction before checking subsequent discarded requests.
        client.write_all(b"request after reset").unwrap();
        let mut fd = poll(&connection.client, libc::POLLIN);
        assert_eq!(unsafe { libc::poll(&mut fd, 1, WAIT.as_millis() as _) }, 1);
        assert!(connection.forward(fd.revents, 0));
        assert!(connection.out.broken);
        // Only the reply can relay now (to the client): note when it does, and hold the deadline to that.
        let step = Duration::from_secs(1);
        let reply = |c: &Connection| (c.incoming.start, c.incoming.end, c.incoming.done);
        let (mut seen, mut relayed, mut now) = (reply(&connection), start, start);
        let mut taken = [0; 4096];
        let closed = loop {
            now += step;
            assert!(now < start + 100 * LINGER, "the forward never closed");
            *clock.lock().unwrap() = now;
            tick_clock();
            if now == start + LINGER {
                // A client that reads a little is still being delivered to: its deadline restarts.
                client.set_nonblocking(true).unwrap();
                wait_until("the reply to move again", || {
                    let _ = client.read(&mut taken);
                    assert!(connection.forward(libc::POLLOUT, 0));
                    reply(&connection) != seen
                });
                client.set_nonblocking(false).unwrap();
            }
            client.write_all(b"discarded request").unwrap();
            let mut fd = poll(&connection.client, libc::POLLIN);
            assert_eq!(unsafe { libc::poll(&mut fd, 1, WAIT.as_millis() as _) }, 1);
            if !connection.forward(fd.revents, 0) {
                break now;
            }
            if reply(&connection) != seen {
                (seen, relayed) = (reply(&connection), now);
            }
            assert_eq!(connection.active, relayed, "discarded bytes are not activity");
            assert_eq!(connection.lingering, Some(relayed), "only relays move the deadline");
        };
        assert!(relayed >= start + LINGER, "reading restarted the deadline");
        assert!(closed > relayed + LINGER, "closed before LINGER past the last relay");
        assert!(closed <= relayed + LINGER + step, "a blocked reply must not prevent expiry");
        CLOCK.with(|c| *c.borrow_mut() = None);
    }

    /// Until all `s` sent is acknowledged: a reset discards what its kernel still holds (a small write
    /// Nagle keeps back behind an unacknowledged byte, say), which no proxy could relay.
    fn acknowledged(s: &TcpStream) {
        wait_until("what was sent to be acknowledged", || {
            let mut queued: libc::c_int = 0;
            assert_eq!(unsafe { libc::ioctl(s.as_raw_fd(), libc::TIOCOUTQ, &mut queued) }, 0);
            queued == 0
        });
    }

    #[test]
    fn what_arrives_before_a_reset_is_still_relayed_both_ways() {
        let (addr, guest, worker) = worker(4, IDLE);
        let reply: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        for _ in 0..20 {
            // The guest replies and resets at once: the proxy finds the data and the error together.
            let mut client = TcpStream::connect(addr).unwrap();
            client.set_read_timeout(Some(WAIT)).unwrap();
            let (mut server, _) = crate::test_util::accept_tcp(&guest);
            server.set_read_timeout(Some(WAIT)).unwrap();
            echo(&mut client, &mut server);
            server.write_all(&reply).unwrap();
            acknowledged(&server);
            reset(server);
            let mut got = Vec::new();
            let _ = client.read_to_end(&mut got);
            assert_eq!(got.len(), reply.len());
            // And a client's last request before its reset reaches the guest.
            let mut client = TcpStream::connect(addr).unwrap();
            let (mut server, _) = crate::test_util::accept_tcp(&guest);
            server.set_read_timeout(Some(WAIT)).unwrap();
            client.write_all(&reply).unwrap();
            acknowledged(&client);
            reset(client);
            let mut got = Vec::new();
            let _ = server.read_to_end(&mut got);
            assert_eq!(got.len(), reply.len());
        }
        worker.halt();
    }

    #[test]
    fn a_reply_held_for_a_slow_client_survives_the_guest_resetting() {
        let (addr, guest, worker) = worker(4, IDLE);
        // Small enough for the proxy to hand all of it to the kernel at once (and be done with the
        // guest before the client's next request comes), and too big for that.
        for len in [10_000u32, 100_000] {
            // A small receive window: most of the reply waits in the proxy.
            let client = unsafe { OwnedFd::from_raw_fd(libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)) };
            let size: libc::c_int = 4096;
            let set = unsafe {
                libc::setsockopt(client.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, (&size as *const libc::c_int).cast(), size_of_val(&size) as _)
            };
            assert_eq!(set, 0);
            let SocketAddr::V4(at) = addr else { unreachable!() };
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: at.port().to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from(*at.ip()).to_be() },
                sin_zero: [0; 8],
            };
            assert_eq!(unsafe { libc::connect(client.as_raw_fd(), (&sa as *const libc::sockaddr_in).cast(), size_of_val(&sa) as _) }, 0);
            let mut client = TcpStream::from(client);
            client.set_read_timeout(Some(WAIT)).unwrap();
            let (mut server, _) = crate::test_util::accept_tcp(&guest);
            echo(&mut client, &mut server);
            let reply: Vec<u8> = (0..len).map(|i| i as u8).collect();
            server.write_all(&reply).unwrap();
            acknowledged(&server);
            reset(server);
            thread::sleep(Duration::from_millis(50));
            // A request the reset guest cannot take: that direction ends, the reply still goes out.
            client.write_all(b"next request").unwrap();
            thread::sleep(Duration::from_millis(50));
            // Slowly: the proxy writes the last of the reply long before it is read.
            let (mut got, mut chunk) = (Vec::new(), [0; 2048]);
            loop {
                match client.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&chunk[..n]),
                    // A reset: the proxy closed with the request unread, or before it came.
                    Err(e) => panic!("after {} of the {len}-byte reply: {e}", got.len()),
                }
                thread::sleep(Duration::from_millis(2));
            }
            assert_eq!(got.len(), reply.len());
            assert!(got == reply);
        }
        worker.halt();
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
