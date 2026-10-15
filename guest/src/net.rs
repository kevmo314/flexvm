//! Guest networking via ioctls and rtnetlink, so images need no iproute2. All but the VM's own
//! address is set up at template boot: eth0 talks to a fixed link-local gateway whose MAC is pinned
//! by a static ARP entry (every host tap has that MAC, so it survives migration).

use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::os;

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
    // struct sockaddr_in: family, port, address.
    let mut sa_data = [0; 14];
    sa_data[2..6].copy_from_slice(&ip.octets().map(|b| b as libc::c_char));
    libc::sockaddr { sa_family: libc::AF_INET as _, sa_data }
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

static NETLINK: OnceLock<(libc::c_int, u32)> = OnceLock::new();

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
    let fd = os(unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) })?;
    let _ = NETLINK.set((fd, unsafe { req.ifr_ifru.ifru_ifindex } as u32));
    Ok(())
}

/// Gives eth0 its per-VM /32 (and optionally a nameserver). Runs right after every restore, so it is
/// one RTM_NEWADDR on a socket opened at template boot (then RTM_DELADDR of a fork's old address):
/// SIOCSIFADDR, or deleting eth0's last address first, would flush the gateway route and ARP entry.
pub fn configure(ip: Ipv4Addr, dns: Option<&str>) -> io::Result<()> {
    // The managed address, kept in snapshot state under the socket's ACK lock.
    static ADDRESS: Mutex<Option<Ipv4Addr>> = Mutex::new(None);
    let mut address = ADDRESS.lock().unwrap();
    let (fd, ifindex) = *NETLINK.get().ok_or_else(|| io::Error::other("no netlink socket"))?;
    update_address(&mut address, ip, |kind, ip| address_request(fd, ifindex, kind, ip))?;
    if let Some(dns) = dns {
        resolv_conf(std::path::Path::new("/etc/resolv.conf"), dns)?;
    }
    Ok(())
}

fn resolv_conf(path: &std::path::Path, dns: &str) -> io::Result<()> {
    let content = format!("nameserver {dns}\n");
    if std::fs::read(path).is_ok_and(|old| old == content.as_bytes()) {
        return Ok(());
    }
    let tmp = path.with_extension("conf.tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(tmp, path)
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

fn address_request(fd: libc::c_int, ifindex: u32, kind: u16, ip: Ipv4Addr) -> io::Result<()> {
    static SEQUENCE: AtomicU32 = AtomicU32::new(1);
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut msg = [0u8; 40];
    msg[..4].copy_from_slice(&40u32.to_ne_bytes());
    msg[4..6].copy_from_slice(&kind.to_ne_bytes());
    let mut flags = libc::NLM_F_REQUEST | libc::NLM_F_ACK;
    if kind == libc::RTM_NEWADDR {
        flags |= libc::NLM_F_CREATE | libc::NLM_F_REPLACE;
    }
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
    os(unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) })?;
    // An error ACK carries the request back (and may carry extended attributes).
    let mut ack = [0u8; 1024];
    loop {
        match os(unsafe { libc::recv(fd, ack.as_mut_ptr().cast(), ack.len(), 0) }) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
            Ok(n) => {
                if let Some(result) = matching_ack(&ack[..n as usize], seq) {
                    return result;
                }
            }
        }
    }
}

fn matching_ack(mut data: &[u8], seq: u32) -> Option<io::Result<()>> {
    while data.len() >= 16 {
        let len = u32::from_ne_bytes(data[..4].try_into().unwrap()) as usize;
        if len < 16 || len > data.len() {
            return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "malformed netlink ACK")));
        }
        if u32::from_ne_bytes(data[8..12].try_into().unwrap()) == seq && u16::from_ne_bytes(data[4..6].try_into().unwrap()) == libc::NLMSG_ERROR as u16 {
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

    #[test]
    fn resolv_conf_is_replaced_atomically_and_unchanged_content_is_skipped() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::test_util::TempDir::new("resolv");
        let path = dir.join("resolv.conf");
        resolv_conf(&path, "1.1.1.1").unwrap();
        let old = std::fs::File::open(&path).unwrap();
        let ino = old.metadata().unwrap().ino();
        resolv_conf(&path, "1.1.1.1").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino);
        resolv_conf(&path, "8.8.8.8").unwrap();
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), ino);
        assert_eq!(std::io::read_to_string(old).unwrap(), "nameserver 1.1.1.1\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "nameserver 8.8.8.8\n");
        assert!(!path.with_extension("conf.tmp").exists());
        // A failed replacement leaves the published file intact.
        std::fs::create_dir(path.with_extension("conf.tmp")).unwrap();
        resolv_conf(&path, "8.8.8.8").unwrap();
        assert!(resolv_conf(&path, "9.9.9.9").is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "nameserver 8.8.8.8\n");
    }

    #[test]
    fn a_new_address_is_added_before_the_previous_one_is_deleted() {
        let old = Ipv4Addr::new(10, 0, 0, 1);
        let new = Ipv4Addr::new(10, 0, 0, 2);
        let mut address = None;
        for (ip, expected) in
            [(old, vec![(libc::RTM_NEWADDR, old)]), (old, vec![(libc::RTM_NEWADDR, old)]), (new, vec![(libc::RTM_NEWADDR, new), (libc::RTM_DELADDR, old)])]
        {
            let mut sent = Vec::new();
            update_address(&mut address, ip, |kind, ip| {
                sent.push((kind, ip));
                Ok(())
            })
            .unwrap();
            assert_eq!(sent, expected);
            assert_eq!(address, Some(ip));
        }
        // A failed add keeps the old address; one already gone is not an error.
        assert!(update_address(&mut address, old, |_, _| Err(io::Error::other("add failed"))).is_err());
        assert_eq!(address, Some(new));
        // A failed delete must remain retryable on the next configure.
        assert!(update_address(&mut address, old, |kind, _| {
            if kind == libc::RTM_DELADDR {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            } else {
                Ok(())
            }
        })
        .is_err());
        assert_eq!(address, Some(new));
        let mut retry = Vec::new();
        update_address(&mut address, old, |kind, ip| {
            retry.push((kind, ip));
            Ok(())
        })
        .unwrap();
        assert_eq!(retry, vec![(libc::RTM_NEWADDR, old), (libc::RTM_DELADDR, new)]);
        address = Some(new);
        let gone = |kind, _| if kind == libc::RTM_DELADDR { Err(io::Error::from_raw_os_error(libc::EADDRNOTAVAIL)) } else { Ok(()) };
        update_address(&mut address, old, gone).unwrap();
        assert_eq!(address, Some(old));
    }

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
