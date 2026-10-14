//! Guest networking via ioctls and rtnetlink, so images need no iproute2. All but the VM's own
//! address is set up at template boot: eth0 talks to a fixed link-local gateway whose MAC is pinned
//! by a static ARP entry (every host tap has that MAC, so it survives migration).

use std::io;
use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};

use crate::os;

#[path = "../../shared/netlink.rs"]
mod netlink;
use netlink::Netlink;

pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);
pub const GATEWAY_MAC: [u8; 6] = [0x06, 0x00, 0xa9, 0xfe, 0x01, 0x01];
const IFACE: &str = "eth0";

struct Sock(std::os::fd::OwnedFd);

impl Sock {
    fn ioctl<T>(&self, req: libc::c_ulong, arg: &mut T) -> io::Result<()> {
        os(unsafe { libc::ioctl(std::os::fd::AsRawFd::as_raw_fd(&self.0), req as _, arg as *mut T) }).map(drop)
    }
}

fn sockaddr(ip: Ipv4Addr) -> libc::sockaddr {
    let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
    addr.sa_family = libc::AF_INET as _;
    for (d, s) in addr.sa_data[2..6].iter_mut().zip(ip.octets()) {
        *d = s as libc::c_char;
    }
    addr
}

fn name<const N: usize>(dst: &mut [libc::c_char; N], name: &str) {
    for (d, s) in dst.iter_mut().zip(name.bytes()) {
        *d = s as libc::c_char;
    }
}

fn ifreq(iface: &str) -> libc::ifreq {
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    name(&mut req.ifr_name, iface);
    req
}

fn link_up(s: &Sock, iface: &str) -> io::Result<()> {
    let mut req = ifreq(iface);
    s.ioctl(libc::SIOCGIFFLAGS, &mut req)?;
    unsafe { req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
    s.ioctl(libc::SIOCSIFFLAGS, &mut req)
}

fn add_route(s: &Sock, dst: Ipv4Addr, mask: Ipv4Addr, gw: Option<Ipv4Addr>) -> io::Result<()> {
    let mut dev = *b"eth0\0";
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    (rt.rt_dst, rt.rt_genmask, rt.rt_flags) = (sockaddr(dst), sockaddr(mask), libc::RTF_UP);
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

static NETLINK: OnceLock<(Netlink, u32)> = OnceLock::new();

pub fn setup() -> io::Result<()> {
    let s = Sock(unsafe { std::os::fd::FromRawFd::from_raw_fd(os(libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0))?) });
    link_up(&s, "lo")?;
    link_up(&s, IFACE)?;
    add_route(&s, GATEWAY, Ipv4Addr::BROADCAST, None)?;
    add_route(&s, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, Some(GATEWAY))?;
    let mut arp: libc::arpreq = unsafe { std::mem::zeroed() };
    (arp.arp_pa, arp.arp_ha.sa_family, arp.arp_flags) = (sockaddr(GATEWAY), libc::ARPHRD_ETHER, libc::ATF_PERM | libc::ATF_COM);
    for (d, s) in arp.arp_ha.sa_data.iter_mut().zip(GATEWAY_MAC) {
        *d = s as libc::c_char;
    }
    name(&mut arp.arp_dev, IFACE);
    s.ioctl(libc::SIOCSARP, &mut arp)?;
    let mut req = ifreq(IFACE);
    s.ioctl(libc::SIOCGIFINDEX, &mut req)?;
    let _ = NETLINK.set((Netlink::open()?, unsafe { req.ifr_ifru.ifru_ifindex } as u32));
    Ok(())
}

/// Gives eth0 its per-VM /32 (and optionally a nameserver). Runs right after every restore, so it is
/// one RTM_NEWADDR on a socket opened at template boot (then RTM_DELADDR of a fork's old address):
/// SIOCSIFADDR, or deleting eth0's last address first, would flush the gateway route and ARP entry.
pub fn configure(ip: Ipv4Addr, dns: Option<&str>) -> io::Result<()> {
    // The managed address, kept in snapshot state under the socket's ACK lock.
    static ADDRESS: Mutex<Option<Ipv4Addr>> = Mutex::new(None);
    let mut address = ADDRESS.lock().unwrap();
    let (fd, ifindex) = NETLINK.get().ok_or_else(|| io::Error::other("no netlink socket"))?;
    update_address(&mut address, ip, |kind, ip| address_request(fd, *ifindex, kind, ip))?;
    if let Some(dns) = dns {
        std::fs::write("/etc/resolv.conf", format!("nameserver {dns}\n"))?;
    }
    Ok(())
}

fn update_address(address: &mut Option<Ipv4Addr>, ip: Ipv4Addr, mut request: impl FnMut(u16, Ipv4Addr) -> io::Result<()>) -> io::Result<()> {
    request(libc::RTM_NEWADDR, ip)?;
    // Keep the old address until it is gone, so a failed delete is retried.
    match address.filter(|old| *old != ip).map(|old| request(libc::RTM_DELADDR, old)) {
        Some(Err(e)) if e.raw_os_error() != Some(libc::EADDRNOTAVAIL) => Err(e),
        _ => {
            *address = Some(ip);
            Ok(())
        }
    }
}

fn address_request(fd: &Netlink, ifindex: u32, kind: u16, ip: Ipv4Addr) -> io::Result<()> {
    let flags = if kind == libc::RTM_NEWADDR { libc::NLM_F_CREATE | libc::NLM_F_REPLACE } else { 0 };
    fd.request(kind, flags, &netlink::address(ifindex, libc::RT_SCOPE_UNIVERSE, ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_has_the_ipv4_ioctl_layout() {
        let addr = sockaddr(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(addr.sa_family, libc::AF_INET as u16);
        assert_eq!(addr.sa_data.map(|b| b as u8), [0, 0, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_new_address_is_added_before_the_previous_one_is_deleted() {
        let old = Ipv4Addr::new(10, 0, 0, 1);
        let new = Ipv4Addr::new(10, 0, 0, 2);
        let mut address = None;
        for (ip, expected) in [
            (old, vec![(libc::RTM_NEWADDR, old)]),
            (old, vec![(libc::RTM_NEWADDR, old)]),
            (new, vec![(libc::RTM_NEWADDR, new), (libc::RTM_DELADDR, old)]),
        ] {
            let mut sent = Vec::new();
            update_address(&mut address, ip, |kind, ip| { sent.push((kind, ip)); Ok(()) }).unwrap();
            assert_eq!(sent, expected);
            assert_eq!(address, Some(ip));
        }
        // A failed add keeps the old address; one already gone is not an error.
        assert!(update_address(&mut address, old, |_, _| Err(io::Error::other("add failed"))).is_err());
        assert_eq!(address, Some(new));
        // A failed delete must remain retryable on the next configure.
        assert!(update_address(&mut address, old, |kind, _| {
            if kind == libc::RTM_DELADDR { Err(io::Error::from_raw_os_error(libc::EPERM)) } else { Ok(()) }
        }).is_err());
        assert_eq!(address, Some(new));
        let mut retry = Vec::new();
        update_address(&mut address, old, |kind, ip| { retry.push((kind, ip)); Ok(()) }).unwrap();
        assert_eq!(retry, vec![(libc::RTM_NEWADDR, old), (libc::RTM_DELADDR, new)]);
        address = Some(new);
        let gone = |kind, _| if kind == libc::RTM_DELADDR { Err(io::Error::from_raw_os_error(libc::EADDRNOTAVAIL)) } else { Ok(()) };
        update_address(&mut address, old, gone).unwrap();
        assert_eq!(address, Some(old));
    }
}
