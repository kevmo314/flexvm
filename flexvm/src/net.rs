//! Host networking: every VM gets a /32 routed to its own tap.
//!
//! All taps share one MAC, as do all guests, so moving a VM between hosts is just moving
//! its route (plus, with `--announce-dev`, a gratuitous ARP for proxy-ARP LAN peers).

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{
    c_int, IFA_ADDRESS, IFA_LOCAL, IFLA_ADDRESS, NDA_DST, NDA_LLADDR, NLMSG_ERROR, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_REPLACE, NLM_F_REQUEST, NUD_PERMANENT, RTA_DST, RTA_GATEWAY, RTA_OIF, RTM_DELLINK, RTM_DELROUTE,
    RTM_NEWADDR, RTM_NEWNEIGH, RTM_NEWROUTE, RTM_SETLINK, RTN_UNICAST, RTPROT_STATIC, RT_SCOPE_HOST, RT_SCOPE_LINK,
    RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN,
};

use crate::bail;
use crate::util::Result;

pub const GATEWAY_MAC: &str = "06:00:a9:fe:01:01";
pub const GUEST_MAC: &str = "06:00:ac:10:00:02";

fn socket(domain: c_int, kind: c_int, protocol: c_int, what: &str) -> Result<OwnedFd> {
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        bail!("{what}: {}", std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn send_to<A>(fd: &OwnedFd, buf: &[u8], addr: &A) -> isize {
    let len = std::mem::size_of::<A>() as libc::socklen_t;
    unsafe { libc::sendto(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0, (addr as *const A).cast(), len) }
}

/// Down, a tap takes no packets, so Firecracker writes none into guest memory.
pub fn set_link_up(name: &str, up: bool) -> Result<()> {
    let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0, "socket")?;
    let mut req = ifreq(name);
    let done = unsafe {
        libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req) >= 0 && {
            let flags = &mut req.ifr_ifru.ifru_flags;
            *flags = if up { *flags | libc::IFF_UP as libc::c_short } else { *flags & !(libc::IFF_UP as libc::c_short) };
            libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS, &req) >= 0
        }
    };
    if !done {
        bail!("set {name} {}: {}", if up { "up" } else { "down" }, std::io::Error::last_os_error());
    }
    Ok(())
}

/// Without an address on the tap, rp_filter (even loose) drops what the guest sends while
/// its address is routed elsewhere (`hold`); a per-tap `rp_filter=0` loses to `all`=2.
pub const TAP_ADDR: &str = "169.254.1.2/32";

/// Room for the packets a migration held, injected all at once (default 1000).
pub const TAP_QUEUE: u32 = 4096;

/// Ioctls and rtnetlink, as spawning `ip` costs tens of milliseconds.
pub fn create_tap(name: &str) -> Result<()> {
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        bail!("/dev/net/tun: {}", std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = ifreq(name);
    req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &req) } < 0 || unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETPERSIST, 1) } < 0 {
        bail!("create tap {name}: {}", std::io::Error::last_os_error());
    }
    drop(fd);
    let made = (|| -> Result<()> {
        let index = ifindex(name)?;
        let mut addr = vec![libc::AF_INET as u8, 32, 0, RT_SCOPE_HOST];
        addr.extend_from_slice(&index.to_ne_bytes());
        let local: Ipv4Addr = TAP_ADDR.split('/').next().unwrap_or_default().parse()?;
        attr(&mut addr, IFA_LOCAL, &local.octets());
        attr(&mut addr, IFA_ADDRESS, &local.octets());
        netlink(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &addr)?;
        set_mac(index, &parse_mac(GATEWAY_MAC)?)?;
        let mut q = ifreq(name);
        q.ifr_ifru.ifru_metric = TAP_QUEUE as i32;
        let sock = socket(libc::AF_INET, libc::SOCK_DGRAM, 0, "socket")?;
        if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFTXQLEN as _, &q) } < 0 {
            bail!("txqueuelen of {name}: {}", std::io::Error::last_os_error());
        }
        sysctl(&format!("net.ipv4.conf.{name}.arp_ignore"), "3")?;
        set_link_up(name, true)
    })();
    if made.is_err() {
        delete_tap(name);
    }
    made
}

pub fn delete_tap(name: &str) {
    let Ok(index) = ifindex(name) else { return };
    let _ = netlink(RTM_DELLINK, 0, &ifinfomsg(index));
}

fn ifreq(name: &str) -> libc::ifreq {
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, s) in req.ifr_name.iter_mut().zip(name.bytes().take(libc::IFNAMSIZ - 1)) {
        *d = s as libc::c_char;
    }
    req
}

/// Puts the gateway MAC back first: udev (`MACAddressPolicy=persistent`) may have replaced
/// it, leaving the guest's pinned gateway ARP entry pointing nowhere.
pub fn attach(ip: Ipv4Addr, tap: &str) -> Result<()> {
    route_dev(true, ip, neighbour(ip, tap)?)
}

/// `attach` but the route, which a migration target installs at its commit; returns the
/// tap's index.
pub fn neighbour(ip: Ipv4Addr, tap: &str) -> Result<u32> {
    let ifindex = ifindex(tap)?;
    set_mac(ifindex, &parse_mac(GATEWAY_MAC)?)?;
    let mut neigh = Vec::with_capacity(32);
    neigh.extend_from_slice(&[libc::AF_INET as u8, 0, 0, 0]);
    neigh.extend_from_slice(&ifindex.to_ne_bytes());
    neigh.extend_from_slice(&NUD_PERMANENT.to_ne_bytes());
    neigh.extend_from_slice(&[0, 0]); // flags, type
    attr(&mut neigh, NDA_DST, &ip.octets());
    attr(&mut neigh, NDA_LLADDR, &parse_mac(GUEST_MAC)?);
    netlink(RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE, &neigh)?;
    Ok(ifindex)
}

/// struct ifinfomsg: family, pad, type, index, flags, change.
fn ifinfomsg(ifindex: u32) -> Vec<u8> {
    let mut msg = vec![libc::AF_UNSPEC as u8, 0, 0, 0];
    msg.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    msg.extend_from_slice(&[0; 8]);
    msg
}

fn set_mac(ifindex: u32, mac: &[u8; 6]) -> Result<()> {
    let mut msg = ifinfomsg(ifindex);
    attr(&mut msg, IFLA_ADDRESS, mac);
    netlink(RTM_SETLINK, 0, &msg)
}

pub fn is_local_addr(ip: Ipv4Addr) -> Result<bool> {
    if ip.is_loopback() {
        return Ok(true);
    }
    let mut addrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        bail!("getifaddrs: {}", std::io::Error::last_os_error());
    }
    let mut current = addrs;
    let mut local = false;
    while !current.is_null() && !local {
        let addr = unsafe { &*current };
        if !addr.ifa_addr.is_null() && unsafe { (*addr.ifa_addr).sa_family } == libc::AF_INET as u16 {
            let v4 = unsafe { &*addr.ifa_addr.cast::<libc::sockaddr_in>() };
            local = v4.sin_addr.s_addr.to_ne_bytes() == ip.octets();
        }
        current = addr.ifa_next;
    }
    unsafe { libc::freeifaddrs(addrs) };
    Ok(local)
}

/// Hosts sharing a netns share routes: never replace the target's tap route with one via us.
pub fn route_via(ip: Ipv4Addr, via: Ipv4Addr) -> Result<()> {
    // Not knowing is no reason to leave a peer's VM unrouted.
    if is_local_addr(via).unwrap_or(false) {
        static LOGGED: std::sync::Once = std::sync::Once::new();
        LOGGED.call_once(|| eprintln!("not routing {ip} via {via}: a local address (hosts sharing a network namespace); this is logged once"));
        return Ok(());
    }
    let mut route = rtmsg(RT_SCOPE_UNIVERSE);
    attr(&mut route, RTA_DST, &ip.octets());
    attr(&mut route, RTA_GATEWAY, &via.octets());
    netlink(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, &route)
}

/// A delete names the device, so it removes only that route.
pub fn route_dev(add: bool, ip: Ipv4Addr, ifindex: u32) -> Result<()> {
    let mut route = rtmsg(RT_SCOPE_LINK);
    attr(&mut route, RTA_DST, &ip.octets());
    attr(&mut route, RTA_OIF, &ifindex.to_ne_bytes());
    match add {
        true => netlink(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, &route),
        false => netlink(RTM_DELROUTE, 0, &route),
    }
}

pub fn unroute(ip: Ipv4Addr) {
    let mut route = rtmsg(RT_SCOPE_NOWHERE);
    attr(&mut route, RTA_DST, &ip.octets());
    let _ = netlink(RTM_DELROUTE, 0, &route);
}

fn rtmsg(scope: u8) -> Vec<u8> {
    let mut m = Vec::with_capacity(48);
    m.extend_from_slice(&[libc::AF_INET as u8, 32, 0, 0, RT_TABLE_MAIN, RTPROT_STATIC, scope, RTN_UNICAST]);
    m.extend_from_slice(&0u32.to_ne_bytes());
    m
}

fn attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
    buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

fn netlink(kind: u16, flags: c_int, body: &[u8]) -> Result<()> {
    let fd = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket")?;
    let mut msg = Vec::with_capacity(16 + body.len());
    msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&((flags | NLM_F_REQUEST | NLM_F_ACK) as u16).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(body);
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let mut ack = [0u8; 1024];
    let res = match send_to(&fd, &msg, &addr) {
        sent if sent < 0 => -1,
        _ => unsafe { libc::recv(fd.as_raw_fd(), ack.as_mut_ptr().cast(), ack.len(), 0) },
    };
    if res < 20 {
        bail!("netlink: {}", std::io::Error::last_os_error());
    }
    let kind = u16::from_ne_bytes([ack[4], ack[5]]);
    let code = i32::from_ne_bytes(ack[16..20].try_into().unwrap());
    if kind == NLMSG_ERROR as u16 && code != 0 {
        bail!("netlink: {}", std::io::Error::from_raw_os_error(-code));
    }
    Ok(())
}

pub fn ifindex(dev: &str) -> Result<u32> {
    let name = std::ffi::CString::new(dev)?;
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => bail!("no interface {dev}"),
        i => Ok(i),
    }
}

pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    for (m, part) in mac.iter_mut().zip(s.trim().split(':')) {
        *m = u8::from_str_radix(part, 16)?;
    }
    Ok(mac)
}

pub fn sysctl(key: &str, value: &str) -> Result<()> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::write(&path, value).map_err(|e| format!("sysctl {key}: {e}"))?;
    Ok(())
}

pub fn gratuitous_arp(dev: &str, ip: Ipv4Addr) -> Result<()> {
    let ifindex = ifindex(dev)?;
    let mac = parse_mac(&std::fs::read_to_string(format!("/sys/class/net/{dev}/address"))?)?;
    let fd = socket(libc::AF_PACKET, libc::SOCK_RAW, 0x0806u16.to_be() as i32, "packet socket")?;
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&[0x08, 0x06]); // ARP
    frame.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]); // ethernet/ipv4, request
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&ip.octets());
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&ip.octets());
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_ifindex = ifindex as i32;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    if send_to(&fd, &frame, &addr) < 0 {
        bail!("send gratuitous arp: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// `a.b.c.d/len` or `first-last`.
#[derive(Debug, Clone)]
pub struct IpRange {
    first: u32,
    last: u32,
}

impl std::fmt::Display for IpRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}-{}", Ipv4Addr::from(self.first), Ipv4Addr::from(self.last))
    }
}

impl IpRange {
    pub fn parse(s: &str) -> Result<IpRange> {
        if let Some((a, b)) = s.split_once('-') {
            let (first, last) = (u32::from(a.parse::<Ipv4Addr>()?), u32::from(b.parse::<Ipv4Addr>()?));
            if first > last {
                bail!("empty address range {s}");
            }
            return Ok(IpRange { first, last });
        }
        let (net, len) = s.split_once('/').ok_or_else(|| format!("bad address range {s:?}"))?;
        let len: u32 = len.parse()?;
        if !(1..=30).contains(&len) {
            bail!("prefix length must be 1..30 in {s}");
        }
        let mask = u32::MAX << (32 - len);
        let base = u32::from(net.parse::<Ipv4Addr>()?) & mask;
        Ok(IpRange { first: base + 1, last: (base | !mask) - 1 })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (self.first..=self.last).contains(&u32::from(ip))
    }

    /// The first address not `taken`, looking from `hint` (if in range) to the
    /// end, then from the start: each address at most once.
    pub fn allocate(&self, hint: Option<Ipv4Addr>, taken: impl Fn(Ipv4Addr) -> bool) -> Option<Ipv4Addr> {
        let start = hint.map(u32::from).filter(|h| (self.first..=self.last).contains(h)).unwrap_or(self.first);
        (start..=self.last).chain(self.first..start).map(Ipv4Addr::from).find(|ip| !taken(*ip))
    }

    /// The address after `ip`, wrapping around.
    pub fn after(&self, ip: Ipv4Addr) -> Ipv4Addr {
        let n = u32::from(ip);
        Ipv4Addr::from(if n >= self.last || n < self.first { self.first } else { n + 1 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_starts_at_the_hint_and_wraps() {
        let r = IpRange::parse("10.9.0.1-10.9.0.4").unwrap();
        let ip = |n: u8| Ipv4Addr::new(10, 9, 0, n);
        let probe = |hint: Option<u8>, used: &[u8]| {
            let probed = std::cell::RefCell::new(Vec::new());
            let got = r.allocate(hint.map(ip), |a| {
                probed.borrow_mut().push(a.octets()[3]);
                used.contains(&a.octets()[3])
            });
            (got.map(|a| a.octets()[3]), probed.into_inner())
        };
        assert_eq!(probe(None, &[]), (Some(1), vec![1]));
        assert_eq!(probe(Some(3), &[]), (Some(3), vec![3]), "no rescan from the start");
        assert_eq!(probe(Some(3), &[3, 4]), (Some(1), vec![3, 4, 1]), "wraps around");
        assert_eq!(probe(Some(2), &[1, 2, 3, 4]), (None, vec![2, 3, 4, 1]), "each address once");
        assert_eq!(probe(Some(9), &[]), (Some(1), vec![1]), "a hint out of range starts at the start");
        assert_eq!((r.after(ip(2)), r.after(ip(4)), r.after(ip(9))), (ip(3), ip(1), ip(1)));
    }

    #[test]
    fn loopback_routes_are_noops() {
        for via in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 42, 3, 4), Ipv4Addr::new(127, 255, 255, 255)] {
            // Works without CAP_NET_ADMIN: no route request is sent.
            route_via(Ipv4Addr::new(192, 0, 2, 123), via).unwrap();
        }
    }
}
