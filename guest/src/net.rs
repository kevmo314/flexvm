//! Guest networking, done with ioctls and rtnetlink so the image needs no iproute2.
//!
//! Every VM is a clone of one template, so everything except the VM's own
//! address is identical and set up once at template boot: eth0 talks to a
//! fixed link-local gateway whose MAC is pinned with a static ARP entry. The
//! host gives every tap that same MAC, so this keeps working after a VM
//! migrates to another host. The address itself is set per VM with `NET`.

use std::io;
use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicU32, Ordering};

pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);
pub const GATEWAY_MAC: [u8; 6] = [0x06, 0x00, 0xa9, 0xfe, 0x01, 0x01];
const IFACE: &str = "eth0";

struct Sock(libc::c_int);

impl Sock {
    fn new() -> io::Result<Sock> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Sock(fd))
    }

    fn ioctl<T>(&self, req: libc::c_ulong, arg: &mut T) -> io::Result<()> {
        if unsafe { libc::ioctl(self.0, req as _, arg as *mut T) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Sock {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn sockaddr(ip: Ipv4Addr) -> libc::sockaddr {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as _,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: u32::from(ip).to_be() },
        sin_zero: [0; 8],
    };
    unsafe { std::mem::transmute(sin) }
}

fn ifreq(name: &str) -> libc::ifreq {
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, s) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *d = s as libc::c_char;
    }
    req
}

fn link_up(s: &Sock, name: &str) -> io::Result<()> {
    let mut req = ifreq(name);
    s.ioctl(libc::SIOCGIFFLAGS, &mut req)?;
    unsafe { req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
    s.ioctl(libc::SIOCSIFFLAGS, &mut req)
}

fn add_route(s: &Sock, dst: Ipv4Addr, mask: Ipv4Addr, gw: Option<Ipv4Addr>) -> io::Result<()> {
    let mut dev = *b"eth0\0";
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    rt.rt_dst = sockaddr(dst);
    rt.rt_genmask = sockaddr(mask);
    rt.rt_flags = libc::RTF_UP;
    if mask == Ipv4Addr::BROADCAST {
        rt.rt_flags |= libc::RTF_HOST;
    }
    if let Some(gw) = gw {
        rt.rt_gateway = sockaddr(gw);
        rt.rt_flags |= libc::RTF_GATEWAY;
    }
    rt.rt_dev = dev.as_mut_ptr().cast();
    match s.ioctl(libc::SIOCADDRT, &mut rt) {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        r => r,
    }
}

/// rtnetlink socket and eth0's index, kept from template boot for `configure`.
static NETLINK: OnceLock<(libc::c_int, u32)> = OnceLock::new();

/// Template-time setup: lo and eth0 up, gateway route and its static ARP entry.
pub fn setup() -> io::Result<()> {
    let s = Sock::new()?;
    link_up(&s, "lo")?;
    link_up(&s, IFACE)?;
    add_route(&s, GATEWAY, Ipv4Addr::BROADCAST, None)?;
    add_route(&s, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, Some(GATEWAY))?;
    pin_gateway(&s)?;
    let mut req = ifreq(IFACE);
    s.ioctl(libc::SIOCGIFINDEX, &mut req)?;
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = NETLINK.set((fd, unsafe { req.ifr_ifru.ifru_ifindex } as u32));
    Ok(())
}

/// The host never answers ARP for the gateway; its MAC is pinned instead.
fn pin_gateway(s: &Sock) -> io::Result<()> {
    let mut arp: libc::arpreq = unsafe { std::mem::zeroed() };
    arp.arp_pa = sockaddr(GATEWAY);
    arp.arp_ha.sa_family = libc::ARPHRD_ETHER;
    for (d, s) in arp.arp_ha.sa_data.iter_mut().zip(GATEWAY_MAC) {
        *d = s as libc::c_char;
    }
    arp.arp_flags = libc::ATF_PERM | libc::ATF_COM;
    for (d, s) in arp.arp_dev.iter_mut().zip(IFACE.bytes()) {
        *d = s as libc::c_char;
    }
    s.ioctl(libc::SIOCSARP, &mut arp)
}

/// Gives eth0 its per-VM /32 address, and optionally a nameserver.
///
/// This runs on every start, right after restore, when each guest page the
/// kernel touches for the first time costs a nested page fault. So it is one
/// RTM_NEWADDR on a netlink socket opened at template boot: adding an address
/// leaves the gateway route and ARP entry alone, where SIOCSIFADDR plus
/// SIOCSIFNETMASK flush them and need them put back.
pub fn configure(ip: Ipv4Addr, dns: Option<&str>) -> io::Result<()> {
    // One receiver owns the shared socket until its matching ACK arrives.
    static REQUEST: Mutex<()> = Mutex::new(());
    static SEQUENCE: AtomicU32 = AtomicU32::new(1);
    let _request = REQUEST.lock().unwrap();
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let (fd, ifindex) = *NETLINK.get().ok_or_else(|| io::Error::other("no netlink socket"))?;
    let mut msg = [0u8; 40];
    msg[..4].copy_from_slice(&40u32.to_ne_bytes());
    msg[4..6].copy_from_slice(&libc::RTM_NEWADDR.to_ne_bytes());
    let flags = libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_REPLACE;
    msg[6..8].copy_from_slice(&(flags as u16).to_ne_bytes());
    msg[8..12].copy_from_slice(&seq.to_ne_bytes());
    // struct ifaddrmsg: family, prefixlen, flags, scope, index.
    msg[16..20].copy_from_slice(&[libc::AF_INET as u8, 32, 0, libc::RT_SCOPE_UNIVERSE]);
    msg[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    for (i, kind) in [libc::IFA_LOCAL, libc::IFA_ADDRESS].into_iter().enumerate() {
        let a = &mut msg[24 + 8 * i..32 + 8 * i];
        a[..2].copy_from_slice(&8u16.to_ne_bytes());
        a[2..4].copy_from_slice(&kind.to_ne_bytes());
        a[4..].copy_from_slice(&ip.octets());
    }
    let mut ack = [0u8; 64];
    if unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    loop {
        let n = unsafe { libc::recv(fd, ack.as_mut_ptr().cast(), ack.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if let Some(result) = matching_ack(&ack[..n as usize], seq) {
            result?;
            break;
        }
    }
    if let Some(dns) = dns {
        std::fs::write("/etc/resolv.conf", format!("nameserver {dns}\n"))?;
    }
    Ok(())
}

// A datagram may contain several aligned netlink messages.
fn matching_ack(mut data: &[u8], seq: u32) -> Option<io::Result<()>> {
    while data.len() >= 16 {
        let len = u32::from_ne_bytes(data[..4].try_into().unwrap()) as usize;
        if len < 16 || len > data.len() {
            return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "malformed netlink ACK")));
        }
        if u32::from_ne_bytes(data[8..12].try_into().unwrap()) == seq
            && u16::from_ne_bytes(data[4..6].try_into().unwrap()) == libc::NLMSG_ERROR as u16
        {
            if len < 20 {
                return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "short netlink ACK")));
            }
            let code = i32::from_ne_bytes(data[16..20].try_into().unwrap());
            return Some(if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code.saturating_neg())) });
        }
        let aligned = (len + 3) & !3;
        data = data.get(aligned..).unwrap_or_default();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(seq: u32, code: i32) -> Vec<u8> {
        let mut data = vec![0; 20];
        data[..4].copy_from_slice(&20u32.to_ne_bytes());
        data[4..6].copy_from_slice(&(libc::NLMSG_ERROR as u16).to_ne_bytes());
        data[8..12].copy_from_slice(&seq.to_ne_bytes());
        data[16..20].copy_from_slice(&code.to_ne_bytes());
        data
    }

    #[test]
    fn ack_matches_sequence_and_reports_errors() {
        assert!(matching_ack(&ack(1, -libc::EPERM), 2).is_none());
        let data = [ack(1, -libc::EPERM), ack(2, 0)].concat();
        matching_ack(&data, 2).unwrap().unwrap();
        assert_eq!(matching_ack(&ack(2, -libc::EPERM), 2).unwrap().unwrap_err().raw_os_error(), Some(libc::EPERM));
        let mut short = ack(2, 0);
        short[..4].copy_from_slice(&16u32.to_ne_bytes());
        assert!(matching_ack(&short[..16], 2).unwrap().is_err());
    }
}
