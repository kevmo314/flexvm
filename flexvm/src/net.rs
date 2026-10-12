//! Host networking: every VM gets a /32 routed to its own tap.
//!
//! All taps share one MAC (the guest's gateway, pinned in the template) and
//! every guest has the same MAC, so the only per-VM state is the address and
//! the route to it. Moving a VM between hosts is then just moving the route:
//! the target routes the address to its new tap, tells its peers to route the
//! address via it, and (with `--announce-dev`) sends a gratuitous ARP so the
//! rest of the LAN, reaching VMs through proxy ARP, follows immediately.

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use crate::bail;
use crate::util::Result;

/// The MAC of every tap, which the guests see as their gateway's.
pub const GATEWAY_MAC: &str = "06:00:a9:fe:01:01";
/// The MAC of every guest's eth0.
pub const GUEST_MAC: &str = "06:00:ac:10:00:02";

/// Brings tap `name` up or down. Down, it takes no packets, so Firecracker
/// does not write any into guest memory.
pub fn set_link_up(name: &str, up: bool) -> Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        bail!("socket: {}", std::io::Error::last_os_error());
    }
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, s) in req.ifr_name.iter_mut().zip(name.bytes().take(libc::IFNAMSIZ - 1)) {
        *d = s as libc::c_char;
    }
    let res = unsafe {
        if libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut req) < 0 {
            -1
        } else {
            let flags = &mut req.ifr_ifru.ifru_flags;
            *flags = if up { *flags | libc::IFF_UP as libc::c_short } else { *flags & !(libc::IFF_UP as libc::c_short) };
            libc::ioctl(fd, libc::SIOCSIFFLAGS, &req)
        }
    };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if res < 0 {
        bail!("set {name} {}: {err}", if up { "up" } else { "down" });
    }
    Ok(())
}

/// Runs `ip` commands in one process, continuing past errors.
pub fn ip_batch(cmds: &[String]) -> Result<()> {
    let mut child = Command::new("ip")
        .args(["-force", "-batch", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(cmds.join("\n").as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("ip: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

pub fn create_tap(name: &str) -> Result<()> {
    ip_batch(&[
        format!("tuntap add dev {name} mode tap"),
        format!("link set dev {name} address {GATEWAY_MAC} up"),
    ])
}

pub fn delete_tap(name: &str) {
    let _ = ip_batch(&[format!("link del dev {name}")]);
}

/// Deletes taps left behind by an earlier run with the same prefix.
pub fn delete_taps_with_prefix(prefix: &str) {
    let cmds: Vec<String> = std::fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(prefix))
        .map(|n| format!("link del dev {n}"))
        .collect();
    if !cmds.is_empty() {
        let _ = ip_batch(&cmds);
    }
}

/// Routes `ip` to the VM behind `tap`, with a permanent neighbor entry so the
/// first packet does not wait on ARP.
pub fn attach(ip: Ipv4Addr, tap: &str) -> Result<()> {
    let ifindex = ifindex(tap)?;
    let mut route = rtmsg(RT_SCOPE_LINK);
    attr(&mut route, RTA_DST, &ip.octets());
    attr(&mut route, RTA_OIF, &ifindex.to_ne_bytes());
    netlink(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, &route)?;
    let mut neigh = Vec::with_capacity(32);
    neigh.extend_from_slice(&[libc::AF_INET as u8, 0, 0, 0]);
    neigh.extend_from_slice(&ifindex.to_ne_bytes());
    neigh.extend_from_slice(&NUD_PERMANENT.to_ne_bytes());
    neigh.extend_from_slice(&[0, 0]); // flags, type
    attr(&mut neigh, NDA_DST, &ip.octets());
    attr(&mut neigh, NDA_LLADDR, &parse_mac(GUEST_MAC)?);
    netlink(RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE, &neigh)
}

/// Routes `ip` to the host at `via`, where the VM now lives.
pub fn route_via(ip: Ipv4Addr, via: Ipv4Addr) -> Result<()> {
    let mut route = rtmsg(RT_SCOPE_UNIVERSE);
    attr(&mut route, RTA_DST, &ip.octets());
    attr(&mut route, RTA_GATEWAY, &via.octets());
    netlink(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, &route)
}

pub fn unroute(ip: Ipv4Addr) {
    let mut route = rtmsg(RT_SCOPE_NOWHERE);
    attr(&mut route, RTA_DST, &ip.octets());
    let _ = netlink(RTM_DELROUTE, 0, &route);
}

// Just enough rtnetlink to change routes and neighbours without spawning
// `ip`, which costs tens of milliseconds on a busy host.
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWNEIGH: u16 = 28;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_NOWHERE: u8 = 255;
const RTN_UNICAST: u8 = 1;
const NUD_PERMANENT: u16 = 0x80;

/// A /32 IPv4 `struct rtmsg` in the main table.
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

/// Sends one request and waits for its acknowledgement.
fn netlink(kind: u16, flags: u16, body: &[u8]) -> Result<()> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
    if fd < 0 {
        bail!("netlink socket: {}", std::io::Error::last_os_error());
    }
    let mut msg = Vec::with_capacity(16 + body.len());
    msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(body);
    let mut ack = [0u8; 1024];
    let res = unsafe {
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as u16;
        let sent = libc::sendto(
            fd,
            msg.as_ptr().cast(),
            msg.len(),
            0,
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        );
        if sent < 0 {
            -1
        } else {
            libc::recv(fd, ack.as_mut_ptr().cast(), ack.len(), 0)
        }
    };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if res < 20 {
        bail!("netlink: {err}");
    }
    let kind = u16::from_ne_bytes([ack[4], ack[5]]);
    let code = i32::from_ne_bytes(ack[16..20].try_into().unwrap());
    if kind == NLMSG_ERROR && code != 0 {
        bail!("netlink: {}", std::io::Error::from_raw_os_error(-code));
    }
    Ok(())
}

fn ifindex(dev: &str) -> Result<u32> {
    let name = std::ffi::CString::new(dev)?;
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => bail!("no interface {dev}"),
        i => Ok(i),
    }
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
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

/// Broadcasts a gratuitous ARP on `dev` claiming `ip` for this host's MAC.
pub fn gratuitous_arp(dev: &str, ip: Ipv4Addr) -> Result<()> {
    let ifindex = ifindex(dev)?;
    let mac = parse_mac(&std::fs::read_to_string(format!("/sys/class/net/{dev}/address"))?)?;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0x0806u16.to_be() as i32) };
    if fd < 0 {
        bail!("packet socket: {}", std::io::Error::last_os_error());
    }
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
    let rc = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr().cast(),
            frame.len(),
            0,
            (&addr as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if rc < 0 {
        bail!("send gratuitous arp: {err}");
    }
    Ok(())
}

/// The block of addresses a daemon hands out, as `a.b.c.d/len` or `first-last`.
#[derive(Debug, Clone)]
pub struct IpRange {
    first: u32,
    last: u32,
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
        // Skip the network and broadcast addresses.
        Ok(IpRange { first: base + 1, last: (base | !mask) - 1 })
    }

    /// The first address in the range that `taken` rejects.
    pub fn allocate(&self, taken: impl Fn(Ipv4Addr) -> bool) -> Option<Ipv4Addr> {
        (self.first..=self.last).map(Ipv4Addr::from).find(|ip| !taken(*ip))
    }
}
