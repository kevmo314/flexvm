//! Host networking: every VM gets a /32 routed to its own tap.
//!
//! All taps share one MAC, as do all guests, so moving a VM between hosts is just moving
//! its route (plus, with `announce_dev`, a gratuitous ARP for proxy-ARP LAN peers).

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{
    c_int, IFA_ADDRESS, IFA_LOCAL, IFLA_ADDRESS, IFLA_IFALIAS, NDA_DST, NDA_LLADDR, NLMSG_ERROR, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST,
    NUD_PERMANENT, RTA_DST, RTA_GATEWAY, RTA_OIF, RTM_DELLINK, RTM_DELROUTE, RTM_NEWADDR, RTM_NEWNEIGH, RTM_NEWROUTE, RTM_SETLINK, RTN_UNICAST, RTPROT_STATIC,
    RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN,
};

use crate::bail;
use crate::util::Result;

pub const GATEWAY_MAC: [u8; 6] = [0x06, 0x00, 0xa9, 0xfe, 0x01, 0x01];
pub const GUEST_MAC: [u8; 6] = [0x06, 0x00, 0xac, 0x10, 0x00, 0x02];

/// `aa:bb:...`, as Firecracker takes it.
pub fn mac_string(mac: &[u8; 6]) -> String {
    mac.map(|b| format!("{b:02x}")).join(":")
}

fn socket(domain: c_int, kind: c_int, protocol: c_int, what: &str) -> Result<OwnedFd> {
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    crate::syscall_check!(fd < 0, "{what}");
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn send_to<A>(fd: &OwnedFd, buf: &[u8], addr: &A) -> isize {
    let len = std::mem::size_of::<A>() as libc::socklen_t;
    unsafe { libc::sendto(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0, (addr as *const A).cast(), len) }
}

/// Down, a tap takes no packets, so Firecracker writes none into guest memory.
pub fn set_link_up(name: &str, up: bool) -> Result<()> {
    let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0, "socket")?;
    let mut req = ifreq(name)?;
    let done = unsafe {
        libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req) >= 0 && {
            let flags = &mut req.ifr_ifru.ifru_flags;
            *flags = if up { *flags | libc::IFF_UP as libc::c_short } else { *flags & !(libc::IFF_UP as libc::c_short) };
            libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS, &req) >= 0
        }
    };
    crate::syscall_check!(!done, "set {name} {}", if up { "up" } else { "down" });
    Ok(())
}

/// Whether frames wait on a tap for its guest, through a copy of Firecracker's descriptor of
/// it (`tap_fd_of`): tun's ring is not empty. Paused vCPUs post no rx buffers, so a VM paused
/// with frames there loses them when the tap goes (a migration, `checkpoint --stop`, a
/// suspend), and no counter shows it: a guest slow to refill under load leaves hundreds (#136).
pub fn tap_queued(fd: &OwnedFd) -> Result<bool> {
    let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let n = crate::util::eintr(|| unsafe { libc::poll(&mut pfd, 1, 0) }).map_err(|e| format!("poll: {e}"))?;
    Ok(n > 0 && pfd.revents & libc::POLLIN != 0)
}

/// Reads off the frames queued on a tap (`tap_fd_of`, non-blocking as Firecracker opened it),
/// each with its virtio-net header, handing each to `each` as it is read: for a VM leaving
/// them, so they are passed on or counted. Returns how many.
pub fn read_tap_queue(fd: &OwnedFd, each: &mut dyn FnMut(&[u8])) -> u64 {
    // A frame with its virtio-net header, up to the 64 KiB a GSO frame can be.
    let mut buf = vec![0u8; 65562 + 64];
    let mut n = 0;
    // Do not change shared descriptor flags; keep polling per frame if it is blocking after all.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    let nonblocking = flags >= 0 && flags & libc::O_NONBLOCK != 0;
    if !tap_queued(fd).unwrap_or(false) {
        return 0;
    }
    // Bounded by the ring (TAP_QUEUE), even if more traffic arrives meanwhile.
    while n < u64::from(TAP_QUEUE) {
        let Ok(len) = crate::util::eintr(|| unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) }) else { break };
        if len == 0 {
            break;
        }
        let len = len as usize;
        each(&buf[..len]);
        n += 1;
        if !nonblocking && !tap_queued(fd).unwrap_or(false) {
            break;
        }
    }
    n
}

/// Process `pid`'s descriptor attached to `tap` (its fdinfo says `iff: TAP`), duplicated here
/// (`pidfd_getfd`), to watch its queue. Reading a tun fdinfo takes RTNL, so this can wait on
/// other network changes: done before the VM's address is held.
pub fn tap_fd_of(pid: u32, tap: &str) -> Result<OwnedFd> {
    let pidfd = crate::util::pidfd_open(pid).map_err(|e| format!("pidfd_open {pid}: {e}"))?;
    let want = format!("iff:\t{tap}\n");
    for entry in std::fs::read_dir(format!("/proc/{pid}/fdinfo"))? {
        let entry = entry?;
        let Some(target) = entry.file_name().to_str().and_then(|s| s.parse::<c_int>().ok()) else { continue };
        if !std::fs::read_to_string(entry.path()).is_ok_and(|s| s.contains(&want)) {
            continue;
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), target, 0) };
        crate::syscall_check!(fd < 0, "pidfd_getfd {pid} {target}");
        return Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) });
    }
    bail!("process {pid} has no descriptor attached to {tap}")
}

/// Without an address on the tap, rp_filter (even loose) drops what the guest sends while
/// its address is routed elsewhere (`hold`); a per-tap `rp_filter=0` loses to `all`=2.
pub const TAP_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 2);

/// Room for the packets a migration held, injected all at once (default 1000).
pub const TAP_QUEUE: u32 = 4096;

/// Ioctls and rtnetlink, as spawning `ip` costs tens of milliseconds. `owner` becomes the
/// tap's alias (`host::tap_alias`), set before the tap is made persistent: a tap left
/// behind always names its owner, and garbage collection goes by that, never by the name.
pub fn create_tap(name: &str, owner: &str) -> Result<()> {
    // Subscribed before the tap exists: udev's event for it cannot come before.
    make_tap(name, owner, udev_monitor())
}

/// `create_tap`, with `udev` (if any) handed to the tap's watcher (`keep_mac_from_udev`).
fn make_tap(name: &str, owner: &str, udev: Option<OwnedFd>) -> Result<()> {
    if owner.len() >= 256 {
        bail!("tap {name}: owner {owner:?} is over 255 bytes (a shorter run directory)");
    }
    let mut req = ifreq(name)?;
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    crate::syscall_check!(fd < 0, "/dev/net/tun");
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // Never a leaked tap of a dead process with this name, nor its routes.
    req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
    crate::syscall_check!(unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &req) } < 0, "create tap {name}");
    // Until TUNSETPERSIST the tap goes with `fd`, so with this process.
    let mut alias = ifinfomsg(ifindex(name)?);
    attr(&mut alias, IFLA_IFALIAS, owner.as_bytes());
    netlink(RTM_SETLINK, 0, &alias).map_err(|e| format!("tap {name}: its owner: {e}"))?;
    crate::syscall_check!(unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETPERSIST, 1) } < 0, "create tap {name}");
    drop(fd);
    let made = (|| -> Result<()> {
        let index = ifindex(name)?;
        let mut addr = [&[libc::AF_INET as u8, 32, 0, RT_SCOPE_HOST][..], &index.to_ne_bytes()].concat();
        attr(&mut addr, IFA_LOCAL, &TAP_ADDR.octets());
        attr(&mut addr, IFA_ADDRESS, &TAP_ADDR.octets());
        netlink(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &addr)?;
        set_mac(index, &GATEWAY_MAC)?;
        let mut q = ifreq(name)?;
        q.ifr_ifru.ifru_metric = TAP_QUEUE as i32;
        let sock = socket(libc::AF_INET, libc::SOCK_DGRAM, 0, "socket")?;
        crate::syscall_check!(unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFTXQLEN as _, &q) } < 0, "txqueuelen of {name}");
        conf("ipv4", name, "arp_ignore", "3")?;
        // The guest is IPv4 only. With IPv6, the host sends an MLD report out of the tap as
        // it comes up: dropped (tx_dropped) when no Firecracker reads it yet (an arrival's),
        // which reads as a frame lost on its way to the guest. As for the hold device.
        let _ = conf("ipv6", name, "disable_ipv6", "1");
        // Shut until `neighbour` names the VM's address: nothing the guest sends gets out.
        guard(index, None).map_err(|e| format!("tap {name}: {e}"))?;
        set_link_up(name, true)
    })();
    match (&made, udev) {
        (Err(_), _) => delete_tap(name),
        (Ok(()), Some(udev)) => {
            if let Ok(index) = ifindex(name) {
                let tap = name.to_string();
                // Not fatal: neighbour still checks the MAC when the tap is handed to a VM.
                if let Err(e) = std::thread::Builder::new().name("udev-mac".into()).spawn(move || keep_mac_from_udev(&udev, index, &tap, UDEV_RECHECK)) {
                    crate::log!("tap {name}: not watching for udev replacing its MAC: {e}");
                }
            }
        }
        (Ok(()), None) => {}
    }
    made
}

/// How often a tap's watcher checks its MAC, and that it is still there, between udev's events.
const UDEV_RECHECK: std::time::Duration = std::time::Duration::from_secs(5);
const NETLINK_KOBJECT_UEVENT: c_int = 15;
/// The uevent socket's group udev (re)broadcasts each event on once it has handled it (1 is the kernel's).
const UDEV_GROUP: u32 = 2;

/// A socket on udev's monitor group, when udevd runs and sees this network namespace's devices:
/// none without it (nothing to wait for), nor in another namespace than init's (`ip netns exec`
/// keeps /run/udev, but uevents of its devices never reach udev), whose taps udev never touches.
fn udev_monitor() -> Option<OwnedFd> {
    use std::os::unix::fs::MetadataExt;
    let ns = |pid: &str| std::fs::metadata(format!("/proc/{pid}/ns/net")).map(|m| (m.dev(), m.ino())).ok();
    let watched = std::path::Path::new("/run/udev/control").exists() && ns("self").is_some_and(|me| ns("1") == Some(me));
    watched.then(|| uevent_socket(UDEV_GROUP)).flatten()
}

fn uevent_socket(groups: u32) -> Option<OwnedFd> {
    let fd = socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT, "uevent socket").ok()?;
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    (addr.nl_family, addr.nl_groups) = (libc::AF_NETLINK as u16, groups);
    let bound = unsafe { libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_nl).cast(), std::mem::size_of_val(&addr) as libc::socklen_t) };
    (bound == 0).then_some(fd)
}

/// udev's `ACTION` and `IFINDEX` of a message on its monitor group: a `struct monitor_netlink_header`
/// ("libudev", magic 0xfeedcafe big-endian, then native header size, properties offset and length)
/// and `KEY=value` properties, each NUL-terminated. None for anything else.
fn udev_event(msg: &[u8]) -> Option<(&[u8], u32)> {
    let word = |at: usize| Some(u32::from_ne_bytes(msg.get(at..at + 4)?.try_into().ok()?) as usize);
    if msg.get(..8)? != b"libudev\0" || msg.get(8..12)? != 0xfeedcafe_u32.to_be_bytes() {
        return None;
    }
    let (off, len) = (word(16)?, word(20)?);
    let props = msg.get(off..off.checked_add(len)?)?;
    let (mut action, mut index) = (None, None);
    for p in props.split(|&b| b == 0) {
        if let Some(a) = p.strip_prefix(b"ACTION=") {
            action = Some(a);
        } else if let Some(i) = p.strip_prefix(b"IFINDEX=") {
            index = std::str::from_utf8(i).ok()?.parse().ok();
        }
    }
    Some((action?, index?))
}

/// udev (systemd's default `MACAddressPolicy=persistent`) gives a new tap a MAC of its own if it
/// reads the tap's address as the kernel's random one, which it can in the millisecond or so
/// before `create_tap` sets the gateway's; its write then lands whenever its worker gets to it,
/// on a loaded host after `neighbour` checked the MAC and the VM runs: the host drops all the
/// guest sends (to the gateway MAC), so no SYN it is sent is answered (#841). udev broadcasts its
/// event for the tap only once it applied its link settings, so the gateway MAC goes back then.
/// udev may take minutes (its event timeout is 3, and events queue before), or the event may be
/// lost to an overrun: until it comes the MAC is checked every `recheck`, as long as the tap is
/// there (a watcher lives no longer than its tap).
fn keep_mac_from_udev(udev: &OwnedFd, index: u32, name: &str, recheck: std::time::Duration) {
    // A network device's event is a few hundred bytes; a longer one, truncated, is another's.
    let mut buf = [0u8; 8192];
    // By the clock, not each poll's timeout: other devices' events, however many, hold no recheck up.
    let mut next = std::time::Instant::now() + recheck;
    loop {
        let now = std::time::Instant::now();
        if now >= next {
            if !restore_mac(index, name) {
                return;
            }
            next = now + recheck;
        }
        let mut pfd = libc::pollfd { fd: udev.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ms = next.saturating_duration_since(now).as_millis().clamp(1, i32::MAX as u128) as c_int;
        match crate::util::eintr(|| unsafe { libc::poll(&mut pfd, 1, ms) }) {
            Err(_) => {
                restore_mac(index, name);
                return;
            }
            Ok(0) => continue,
            Ok(_) => {}
        }
        let n = unsafe { libc::recv(udev.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        match (n > 0).then(|| udev_event(&buf[..n as usize])).flatten() {
            Some((b"add", i)) if i == index => {
                restore_mac(index, name);
                return;
            }
            Some((b"remove", i)) if i == index => return,
            _ => {}
        }
    }
}

/// Puts the gateway MAC back on tap `name` at `index` if something replaced it, while the
/// index still has that name (as `delete_link`): never another device's. Whether it still has.
fn restore_mac(index: u32, name: &str) -> bool {
    if !has_name(index, name) {
        return false;
    }
    let mac = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok().and_then(|s| parse_mac(&s).ok());
    if mac.is_some_and(|m| m != GATEWAY_MAC) {
        if let Err(e) = set_mac(index, &GATEWAY_MAC) {
            crate::log!("tap {name}: udev replaced its MAC, and putting the gateway's back failed: {e}");
        }
    }
    true
}

pub fn delete_tap(name: &str) {
    if let Ok(index) = ifindex(name) {
        delete_link(index, name);
    }
}

/// By index, while it still has `name`: a tap made since under the name has another
/// index, and one renamed or moved away (its index reused) another name. A rename in
/// between the check and the delete is not caught.
pub fn delete_link(ifindex: u32, name: &str) {
    if has_name(ifindex, name) {
        let _ = netlink(RTM_DELLINK, 0, &ifinfomsg(ifindex));
    }
}

fn has_name(index: u32, name: &str) -> bool {
    let mut now = [0 as libc::c_char; libc::IFNAMSIZ];
    let named = unsafe { libc::if_indextoname(index, now.as_mut_ptr()) };
    !named.is_null() && unsafe { std::ffi::CStr::from_ptr(named) }.to_bytes() == name.as_bytes()
}

/// A longer name is refused: the kernel would take it truncated.
pub fn ifreq(name: &str) -> Result<libc::ifreq> {
    if name.len() >= libc::IFNAMSIZ {
        bail!("interface name {name:?} is over {} bytes", libc::IFNAMSIZ - 1);
    }
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, s) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *d = s as libc::c_char;
    }
    Ok(req)
}

/// Puts the gateway MAC back first: udev (`MACAddressPolicy=persistent`) may have replaced
/// it, leaving the guest's pinned gateway ARP entry pointing nowhere.
pub fn attach(ip: Ipv4Addr, tap: &str) -> Result<()> {
    route(ip, neighbour(ip, tap)?)
}

/// Installs the route using the index retained when the caller readied the tap.
pub fn route(ip: Ipv4Addr, index: u32) -> Result<()> {
    route_dev(true, ip, index)
}

/// `attach` but the route, which a migration target installs at its commit; returns the
/// tap's index.
pub fn neighbour(ip: Ipv4Addr, tap: &str) -> Result<u32> {
    let ifindex = ifindex(tap)?;
    if std::fs::read_to_string(format!("/sys/class/net/{tap}/address")).ok().and_then(|s| parse_mac(&s).ok()) != Some(GATEWAY_MAC) {
        set_mac(ifindex, &GATEWAY_MAC)?;
    }
    // Before the neighbour entry and the route: the tap passes only `ip`'s packets once it is `ip`'s.
    guard(ifindex, Some(ip)).map_err(|e| format!("tap {tap}: {e}"))?;
    // struct ndmsg: family, pad, index, state, flags, type.
    let mut neigh = [&[libc::AF_INET as u8, 0, 0, 0][..], &ifindex.to_ne_bytes(), &NUD_PERMANENT.to_ne_bytes(), &[0, 0]].concat();
    attr(&mut neigh, NDA_DST, &ip.octets());
    attr(&mut neigh, NDA_LLADDR, &GUEST_MAC);
    netlink(RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE, &neigh)?;
    Ok(ifindex)
}

const TC_H_ROOT: u32 = 0xffff_ffff;
const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCQ_PLUG_BUFFER: i32 = 0;
const TCQ_PLUG_RELEASE_INDEFINITE: i32 = 2;
/// Bytes a plugged tap buffers: `sch_plug` drops beyond (counted by `unplug_tap`).
const PLUG_LIMIT: u32 = 16 << 20;
const TCA_STATS: u16 = 3;

/// struct tcmsg (family, pads, ifindex, handle, parent, info) for the root qdisc at `ifindex`, with `handle`.
fn tcmsg(ifindex: u32, handle: u32) -> Vec<u8> {
    [&[libc::AF_UNSPEC as u8, 0, 0, 0][..], &ifindex.to_ne_bytes(), &handle.to_ne_bytes(), &TC_H_ROOT.to_ne_bytes(), &0u32.to_ne_bytes()].concat()
}

/// The root plug qdisc, with TCA_KIND "plug" and its struct tc_plug_qopt (action, limit).
fn plug_msg(ifindex: u32, action: i32) -> Vec<u8> {
    let mut m = tcmsg(ifindex, 0x1_0000);
    attr(&mut m, TCA_KIND, b"plug\0");
    attr(&mut m, TCA_OPTIONS, &[&action.to_ne_bytes()[..], &PLUG_LIMIT.to_ne_bytes()].concat());
    m
}

/// clsact's handle and parent, and its ingress hook's (`TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)`).
const CLSACT_HANDLE: u32 = 0xffff_0000;
const TC_H_CLSACT: u32 = 0xffff_fff1;
const CLSACT_INGRESS: u32 = 0xffff_fff2;
const TCA_BPF_OPS_LEN: u16 = 4;
const TCA_BPF_OPS: u16 = 5;
const TCA_BPF_FLAGS: u16 = 8;
const TCA_BPF_FLAG_ACT_DIRECT: u32 = 1;
const TC_ACT_OK: u32 = 0;
const TC_ACT_SHOT: u32 = 2;

/// The guest is untrusted, and the host forwards what it sends (with a loose rp_filter, which
/// the hold needs: `TAP_ADDR`), so the tap's ingress lets through only IPv4 from `ip` and ARP
/// naming `ip` as its sender, nothing else (no other source, IPv6, VLAN or other ethertype);
/// with no `ip`, nothing. ARP is held to the address too: the guest never needs another (its
/// gateway's entry is pinned, and the host's for it is permanent), and a spoofed sender could
/// only leave stale neighbour entries. A clsact qdisc (made once, kept by a create of one
/// already there) holds a classic BPF filter in direct-action mode, which a replace swaps at
/// once, with no gap; both go with the tap.
fn guard(ifindex: u32, ip: Option<Ipv4Addr>) -> Result<()> {
    let tc = |handle: u32, parent: u32, info: u32| {
        [&[libc::AF_UNSPEC as u8, 0, 0, 0][..], &ifindex.to_ne_bytes(), &handle.to_ne_bytes(), &parent.to_ne_bytes(), &info.to_ne_bytes()].concat()
    };
    if ip.is_none() {
        let mut qdisc = tc(CLSACT_HANDLE, TC_H_CLSACT, 0);
        attr(&mut qdisc, TCA_KIND, b"clsact\0");
        netlink(libc::RTM_NEWQDISC, NLM_F_CREATE, &qdisc).map_err(|e| format!("its clsact qdisc (sch_ingress): {e}"))?;
    }
    // Handle 1, priority 1, every protocol (in network order).
    let mut filter = tc(1, CLSACT_INGRESS, 1 << 16 | u32::from((libc::ETH_P_ALL as u16).to_be()));
    attr(&mut filter, TCA_KIND, b"bpf\0");
    let ops = source_filter(ip);
    let mut opts = Vec::new();
    attr(&mut opts, TCA_BPF_OPS_LEN, &(ops.len() as u16).to_ne_bytes());
    attr(&mut opts, TCA_BPF_OPS, &ops.iter().flat_map(|op| [&op.code.to_ne_bytes()[..], &[op.jt, op.jf], &op.k.to_ne_bytes()].concat()).collect::<Vec<u8>>());
    attr(&mut opts, TCA_BPF_FLAGS, &TCA_BPF_FLAG_ACT_DIRECT.to_ne_bytes());
    attr(&mut filter, TCA_OPTIONS, &opts);
    netlink(libc::RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE, &filter).map_err(|e| format!("its source filter (cls_bpf): {e}"))?;
    Ok(())
}

/// The classic BPF program of `guard`, run on frames from their Ethernet header on; a load
/// past a frame's end would end it with 0 (pass), so lengths are checked first.
fn source_filter(ip: Option<Ipv4Addr>) -> Vec<libc::sock_filter> {
    let op = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    let (ld_w, ld_h, ld_len, jeq, jge, ret) = (0x20, 0x28, 0x80, 0x15, 0x35, 0x06);
    let Some(ip) = ip else { return vec![op(ret, 0, 0, TC_ACT_SHOT)] };
    let ip = u32::from(ip);
    // SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT: the kernel strips a VLAN tag before ingress.
    let vlan = 0xffff_f000 + 48;
    // Jumps are relative to the next instruction; 13 drops, 14 passes.
    vec![
        op(ld_w, 0, 0, vlan),       // 0
        op(jeq, 0, 11, 0),          // 1: tagged: drop
        op(ld_h, 0, 0, 12),         // 2: ethertype
        op(jeq, 0, 4, 0x0800),      // 3: not IPv4: 8
        op(ld_len, 0, 0, 0),        // 4
        op(jge, 0, 7, 14 + 20),     // 5: Ethernet and an IPv4 header
        op(ld_w, 0, 0, 14 + 12),    // 6: source
        op(jeq, 6, 5, ip),          // 7
        op(jeq, 0, 4, 0x0806),      // 8: not ARP: drop
        op(ld_len, 0, 0, 0),        // 9
        op(jge, 0, 2, 14 + 28),     // 10: Ethernet and an Ethernet/IPv4 ARP body
        op(ld_w, 0, 0, 14 + 14),    // 11: sender protocol address
        op(jeq, 1, 0, ip),          // 12
        op(ret, 0, 0, TC_ACT_SHOT), // 13
        op(ret, 0, 0, TC_ACT_OK),   // 14
    ]
}

/// Packets the host routes out of `tap` wait in its qdisc, in their order, until
/// `unplug_tap`; frames a packet socket sends past the qdisc (`hold::Injector`) do not.
/// Returns whether the plug may be installed, which `unplug_tap` is then due for: when it
/// is, and when the kernel's answer was lost (the change may have been made). Not when the
/// kernel refused it (no `sch_plug`, a root qdisc of another kind at 1:): then there is
/// nothing of ours to let go of, and an unplug would only cost its retries.
pub fn plug_tap(tap: &str) -> (bool, Result<()>) {
    let Ok(ifindex) = ifindex(tap) else { return (false, Err(format!("no tap {tap}").into())) };
    match request(libc::RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, &plug_msg(ifindex, TCQ_PLUG_BUFFER)) {
        Ok(()) => (true, Ok(())),
        Err(Failed::Unchanged(e)) => (false, Err(e)),
        Err(Failed::Unanswered(e)) => (true, Err(e)),
    }
}

/// Our plug at the tap's root (handle 1:, kind "plug"), and nothing else: the kernel
/// refuses the delete if the root qdisc is not that one.
fn remove_plug(ifindex: u32) -> Result<()> {
    let mut m = tcmsg(ifindex, 0x1_0000);
    attr(&mut m, TCA_KIND, b"plug\0");
    netlink(libc::RTM_DELQDISC, 0, &m)
}

/// What waited goes out, in order, and the qdisc lets everything through from then on, a
/// FIFO: a packet arriving meanwhile queues behind the waiting ones. Failing that (tried
/// three times), the plug goes, the tap's default qdisc coming back, and what waited with
/// it; failing that too, that is retried in the background for a minute, so the tap never
/// stays plugged. Only our plug is released or removed (`remove_plug`), never another root
/// qdisc. Returns the packets the plug dropped (past `PLUG_LIMIT`, or discarded with it),
/// and whether it let them through.
///
/// Released, the plug stays the tap's root qdisc, in place of its default (fq_codel), and
/// never holds anything: tun never stops its queue, taking each packet into its ring (of
/// `TAP_QUEUE`, the tap's txqueuelen) or dropping it there (the tap's tx_dropped), so a
/// root qdisc only ever passes packets straight through, the default as well. Putting the
/// default back would cost more than it gives: any root qdisc change on a running tap
/// first points its queues at noop_qdisc for an RCU grace period (`dev_deactivate`), which
/// drops what the new route sends the VM meanwhile. The plug is put in place before the
/// route, so nothing is routed to the tap yet then.
pub fn unplug_tap(tap: &str) -> (u64, Result<()>) {
    let Ok(ifindex) = ifindex(tap) else { return (0, Err(format!("no tap {tap}").into())) };
    let stats = || qdisc_stats(ifindex, PLUG, STATS_WAIT).unwrap_or_default();
    let Err(e) = retry3(|| netlink(libc::RTM_NEWQDISC, 0, &plug_msg(ifindex, TCQ_PLUG_RELEASE_INDEFINITE))) else { return (stats().0, Ok(())) };
    let (drops, queued) = stats();
    let remove = move || remove_plug(ifindex);
    if retry3(remove).is_ok() {
        return (drops + queued, Err(format!("{e}; removed the plug instead").into()));
    }
    let tap = tap.to_string();
    std::thread::spawn(move || {
        let mut latest = (drops, queued);
        for _ in 0..60 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            // Only while the index is still this tap's.
            if crate::net::ifindex(&tap).ok() != Some(ifindex) {
                return;
            }
            latest = qdisc_stats(ifindex, PLUG, STATS_WAIT).unwrap_or(latest);
            if remove().is_ok() {
                return crate::log!("tap {tap}: plug removed, {} extra drops, {} queued packets discarded", latest.0.saturating_sub(drops), latest.1);
            }
        }
        crate::log!("tap {tap}: could not remove its plug, {} extra drops; backlog stays queued", latest.0.saturating_sub(drops));
    });
    (drops, Err(format!("{e}; removing the plug failed too, retrying").into()))
}

/// Waits up to `wait` for what `tap`'s root qdisc still holds to reach the tap's own queue,
/// and returns how many packets it holds then (0 if it cannot say). Taking a link down resets
/// its qdisc, which frees what is there without counting it anywhere (#817).
pub fn drain_qdisc(tap: &str, wait: std::time::Duration) -> u64 {
    let Ok(ifindex) = ifindex(tap) else { return 0 };
    let end = std::time::Instant::now() + wait;
    loop {
        // Whatever the root qdisc is (a default one, or our plug); the answer waited for only
        // within `wait` (at least a millisecond), so an unanswered query never holds it longer.
        let left = end.saturating_duration_since(std::time::Instant::now()).max(std::time::Duration::from_millis(1));
        let queued = qdisc_stats(ifindex, 0, left).map_or(0, |(_, queued)| queued);
        if queued == 0 || std::time::Instant::now() >= end {
            return queued;
        }
        std::thread::sleep(std::time::Duration::from_micros(200));
    }
}

fn retry3(mut f: impl FnMut() -> Result<()>) -> Result<()> {
    let mut res = Ok(());
    for _ in 0..3 {
        res = f();
        if res.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    res
}

/// Our plug's handle (1:).
const PLUG: u32 = 0x1_0000;

/// Whether our plug is `tap`'s root qdisc (released or not).
pub fn plug_is_root(tap: &str) -> bool {
    ifindex(tap).is_ok_and(|i| qdisc_stats(i, PLUG, STATS_WAIT).is_some())
}

/// How long `qdisc_stats` waits for its answer, unless told otherwise.
const STATS_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// The root qdisc's (drops, queued packets), if its handle is `handle` (0: whatever it is), from
/// RTM_GETQDISC on a socket of its own: the qdisc echoed back (NLM_F_ECHO; a get without it
/// answers nothing), no ACK, waited for up to `wait`.
fn qdisc_stats(ifindex: u32, handle: u32, wait: std::time::Duration) -> Option<(u64, u64)> {
    const NLM_F_ECHO: c_int = 8;
    let sock = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket").ok()?;
    // A zero timeval would mean no timeout at all.
    let wait = wait.max(std::time::Duration::from_micros(1));
    let timeout = libc::timeval { tv_sec: wait.as_secs() as libc::time_t, tv_usec: wait.subsec_micros() as libc::suseconds_t };
    let size = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    if unsafe { libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&timeout as *const libc::timeval).cast(), size) } != 0 {
        return None;
    }
    let body = tcmsg(ifindex, handle);
    let mut buf = [0u8; 8192];
    let reply = exchange(&sock, libc::RTM_GETQDISC, NLM_F_ECHO, &body, &mut buf).ok()?;
    if reply.len() < 36 || u16::from_ne_bytes([reply[4], reply[5]]) != libc::RTM_NEWQDISC {
        return None;
    }
    // After nlmsghdr (16) and tcmsg (20): attributes (length, type, data, padded to 4).
    let mut at = 36;
    while at + 4 <= reply.len() {
        let len = u16::from_ne_bytes([reply[at], reply[at + 1]]) as usize;
        let kind = u16::from_ne_bytes([reply[at + 2], reply[at + 3]]);
        if len < 4 || at + len > reply.len() {
            return None;
        }
        // struct tc_stats: bytes u64, packets, drops, overlimits, bps, pps, qlen, backlog (u32).
        if kind == TCA_STATS && len >= 4 + 36 {
            let u32_at = |o: usize| u64::from(u32::from_ne_bytes(reply[at + 4 + o..at + 8 + o].try_into().unwrap()));
            return Some((u32_at(12), u32_at(28)));
        }
        at += len.next_multiple_of(4);
    }
    None
}

/// struct ifinfomsg: family, pad, type, index, flags, change.
fn ifinfomsg(ifindex: u32) -> Vec<u8> {
    [&[libc::AF_UNSPEC as u8, 0, 0, 0][..], &ifindex.to_ne_bytes(), &[0; 8]].concat()
}

fn set_mac(ifindex: u32, mac: &[u8; 6]) -> Result<()> {
    let mut msg = ifinfomsg(ifindex);
    attr(&mut msg, IFLA_ADDRESS, mac);
    netlink(RTM_SETLINK, 0, &msg)
}

pub fn is_local_addr(ip: Ipv4Addr) -> Result<bool> {
    is_local_ip(ip.into())
}

/// Whether `ip` is one of this network namespace's addresses, IPv4 or IPv6 (an IPv4-mapped one as its IPv4).
pub fn is_local_ip(ip: std::net::IpAddr) -> Result<bool> {
    let ip = ip.to_canonical();
    if ip.is_loopback() {
        return Ok(true);
    }
    // At most a second old: listen checks one per route it installs.
    static LOCAL: std::sync::Mutex<(Option<std::time::Instant>, Vec<std::net::IpAddr>)> = std::sync::Mutex::new((None, Vec::new()));
    let mut local = LOCAL.lock().unwrap();
    if local.0.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(1)) {
        let mut addrs = std::ptr::null_mut();
        crate::syscall_check!(unsafe { libc::getifaddrs(&mut addrs) } != 0, "getifaddrs");
        local.1.clear();
        let mut current = addrs;
        while !current.is_null() {
            let addr = unsafe { &*current };
            if !addr.ifa_addr.is_null() {
                match unsafe { (*addr.ifa_addr).sa_family } as i32 {
                    libc::AF_INET => {
                        let v4 = unsafe { &*addr.ifa_addr.cast::<libc::sockaddr_in>() };
                        local.1.push(Ipv4Addr::from(v4.sin_addr.s_addr.to_ne_bytes()).into());
                    }
                    libc::AF_INET6 => {
                        let v6 = unsafe { &*addr.ifa_addr.cast::<libc::sockaddr_in6>() };
                        local.1.push(std::net::Ipv6Addr::from(v6.sin6_addr.s6_addr).into());
                    }
                    _ => {}
                }
            }
            current = addr.ifa_next;
        }
        unsafe { libc::freeifaddrs(addrs) };
        local.0 = Some(std::time::Instant::now());
    }
    Ok(local.1.contains(&ip))
}

/// The kernel's route toward `to`, as `ip route get` reads it (policy routing
/// included): its output device and the source address it would use.
pub fn route_get(to: Ipv4Addr) -> Result<(String, Ipv4Addr)> {
    let sock = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket")?;
    // struct rtmsg: family, dst_len 32, the rest 0.
    let mut msg = vec![libc::AF_INET as u8, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    attr(&mut msg, RTA_DST, &to.octets());
    let mut buf = [0u8; 4096];
    let reply = exchange(&sock, libc::RTM_GETROUTE, 0, &msg, &mut buf).map_err(|_| format!("no route toward {to}: netlink failed"))?;
    route_from_reply(to, reply)
}

fn route_from_reply(to: Ipv4Addr, reply: &[u8]) -> Result<(String, Ipv4Addr)> {
    let (oif, src) = parse_route(reply).map_err(|e| format!("no route toward {to}{e}"))?;
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    crate::syscall_check!(unsafe { libc::if_indextoname(oif, name.as_mut_ptr()) }.is_null(), "the route toward {to}: interface {oif}");
    Ok((unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_string_lossy().into_owned(), src))
}

/// A route reply's (RTM_NEWROUTE) output interface and preferred source; else why not
/// (": " and the kernel's error, or nothing).
fn parse_route(reply: &[u8]) -> std::result::Result<(u32, Ipv4Addr), String> {
    if reply.len() >= 20 && u16::from_ne_bytes([reply[4], reply[5]]) == NLMSG_ERROR as u16 {
        let code = i32::from_ne_bytes(reply[16..20].try_into().unwrap());
        return Err(format!(": {}", std::io::Error::from_raw_os_error(-code)));
    }
    parse_new_route(reply).ok_or_else(String::new)
}

fn parse_new_route(reply: &[u8]) -> Option<(u32, Ipv4Addr)> {
    if reply.len() < 28 || u16::from_ne_bytes([reply[4], reply[5]]) != RTM_NEWROUTE {
        return None;
    }
    let end = (u32::from_ne_bytes(reply[..4].try_into().ok()?) as usize).min(reply.len());
    // After nlmsghdr (16) and rtmsg (12): attributes (length, type, data, padded to 4).
    let (mut at, mut oif, mut src) = (28, None, None);
    while at + 4 <= end {
        let len = u16::from_ne_bytes([reply[at], reply[at + 1]]) as usize;
        if len < 4 || at + len > end {
            return None;
        }
        let data: Option<[u8; 4]> = reply[at + 4..at + len].try_into().ok();
        match u16::from_ne_bytes([reply[at + 2], reply[at + 3]]) {
            RTA_OIF => oif = data.map(u32::from_ne_bytes),
            libc::RTA_PREFSRC => src = data.map(Ipv4Addr::from),
            _ => {}
        }
        at += len.next_multiple_of(4);
    }
    Some((oif?, src?))
}

/// Hosts sharing a netns share routes: never replace the target's tap route with one via us.
pub fn route_via(ip: Ipv4Addr, via: Ipv4Addr) -> Result<()> {
    if is_local_addr(via)? {
        static LOGGED: std::sync::Once = std::sync::Once::new();
        LOGGED.call_once(|| crate::info!("not routing {ip} via {via}: a local address (hosts sharing a network namespace); this is logged once"));
        return Ok(());
    }
    let mut route = rtmsg(RT_SCOPE_UNIVERSE);
    attr(&mut route, RTA_DST, &ip.octets());
    attr(&mut route, RTA_GATEWAY, &via.octets());
    netlink(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, &route)
}

/// The next hops in `table` (`/proc/net/route`: hex, in network byte order).
pub fn gateways(table: &str) -> Vec<Ipv4Addr> {
    let hop = |l: &str| u32::from_str_radix(l.split_whitespace().nth(2)?, 16).ok().filter(|&g| g != 0);
    table.lines().skip(1).filter_map(hop).map(|g| Ipv4Addr::from(g.to_ne_bytes())).collect()
}

/// A delete names the device, so it removes only that route.
pub fn route_dev(add: bool, ip: Ipv4Addr, ifindex: u32) -> Result<()> {
    let mut route = rtmsg(RT_SCOPE_LINK);
    attr(&mut route, RTA_DST, &ip.octets());
    attr(&mut route, RTA_OIF, &ifindex.to_ne_bytes());
    let (kind, flags) = if add { (RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE) } else { (RTM_DELROUTE, 0) };
    netlink(kind, flags, &route)
}

/// Removes `ip`'s route through a gateway (`route_via`'s, whichever peer it names: a migration's
/// switch to its target is never recorded, and a record can name a newer peer than the route):
/// universe scope only, so never a tap's or the hold device's (`route_dev`, link scope), which
/// hosts sharing a network namespace each keep for their own VMs.
pub fn unroute(ip: Ipv4Addr) {
    let mut route = rtmsg(RT_SCOPE_UNIVERSE);
    attr(&mut route, RTA_DST, &ip.octets());
    let _ = netlink(RTM_DELROUTE, 0, &route);
}

fn rtmsg(scope: u8) -> Vec<u8> {
    vec![libc::AF_INET as u8, 32, 0, 0, RT_TABLE_MAIN, RTPROT_STATIC, scope, RTN_UNICAST, 0, 0, 0, 0]
}

fn attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
    buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

/// Whether a failed request left things unchanged or its answer was lost (the change may have been made).
enum Failed {
    Unchanged(crate::util::Error),
    Unanswered(crate::util::Error),
}

fn netlink(kind: u16, flags: c_int, body: &[u8]) -> Result<()> {
    request(kind, flags, body).map_err(|(Failed::Unchanged(e) | Failed::Unanswered(e))| e)
}

thread_local!(static FD: std::cell::Cell<Option<OwnedFd>> = const { std::cell::Cell::new(None) });

/// Opens this thread's netlink socket now, if it has none: before a lock its first request is made under.
pub fn ready() {
    if let Some(sock) = FD.take().or_else(|| socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket").ok()) {
        FD.set(Some(sock));
    }
}

/// One socket per thread, so each recv is the ACK of the request just sent and a slow one
/// (a tap's teardown) holds up no other thread; any failure drops it, so no stale ACK is
/// left for the next.
fn request(kind: u16, flags: c_int, body: &[u8]) -> std::result::Result<(), Failed> {
    let sock = FD.take().map_or_else(|| socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket"), Ok).map_err(Failed::Unchanged)?;
    let mut ack = [0u8; 1024];
    let reply = exchange(&sock, kind, flags | NLM_F_ACK, body, &mut ack)?;
    if reply.len() < 20 {
        return Err(Failed::Unanswered(format!("netlink: short reply ({} bytes)", reply.len()).into()));
    }
    FD.set(Some(sock));
    let kind = u16::from_ne_bytes([ack[4], ack[5]]);
    let code = i32::from_ne_bytes(ack[16..20].try_into().unwrap());
    if kind == NLMSG_ERROR as u16 && code != 0 {
        return Err(Failed::Unchanged(format!("netlink: {}", std::io::Error::from_raw_os_error(-code)).into()));
    }
    Ok(())
}

fn exchange<'a>(sock: &OwnedFd, kind: u16, flags: c_int, body: &[u8], buf: &'a mut [u8]) -> std::result::Result<&'a [u8], Failed> {
    let flags = ((flags | NLM_F_REQUEST) as u16).to_ne_bytes();
    // struct nlmsghdr: length, type, flags, seq, pid.
    let msg = [&((16 + body.len()) as u32).to_ne_bytes()[..], &kind.to_ne_bytes(), &flags, &[1, 0, 0, 0, 0, 0, 0, 0], body].concat();
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    if send_to(sock, &msg, &addr) < 0 {
        return Err(Failed::Unchanged(format!("netlink: {}", std::io::Error::last_os_error()).into()));
    }
    let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        return Err(Failed::Unanswered(format!("netlink: {}", std::io::Error::last_os_error()).into()));
    }
    Ok(&buf[..n as usize])
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

/// Whether `dev` is an Ethernet link (ARPHRD_ETHER), one that takes ARP announcements.
pub fn is_ethernet(dev: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{dev}/type")).is_ok_and(|t| t.trim() == "1")
}

/// `/proc/sys/net/{family}/conf/{dev}/{key}`, by its path: a sysctl key's dots would split a
/// device name with one (`eth0.100`, a `--prefix` with a dot).
pub fn conf(family: &str, dev: &str, key: &str, value: &str) -> Result<()> {
    std::fs::write(format!("/proc/sys/net/{family}/conf/{dev}/{key}"), value).map_err(|e| format!("{family} {key} of {dev}: {e}"))?;
    Ok(())
}

/// How long a failed proxy ARP setup waits before it is tried again.
const PROXY_ARP_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

type ProxyArp = std::collections::BTreeMap<String, std::result::Result<u32, std::time::Instant>>;

/// Proxy ARP on an announce device, once per interface (a derived one follows the routes; one
/// recreated under its name gets it again). A failure is warned of once and an error until it
/// is tried again, after `PROXY_ARP_RETRY`.
pub fn proxy_arp(dev: &str) -> Result<()> {
    static ON: std::sync::Mutex<ProxyArp> = std::sync::Mutex::new(ProxyArp::new());
    enable_proxy_arp(&mut ON.lock().unwrap(), dev, ifindex(dev), || conf("ipv4", dev, "proxy_arp", "1"))
}

fn enable_proxy_arp(on: &mut ProxyArp, dev: &str, index: Result<u32>, write: impl FnOnce() -> Result<()>) -> Result<()> {
    match (on.get(dev), &index) {
        (Some(Ok(was)), Ok(now)) if was == now => return Ok(()),
        (Some(Err(at)), _) if at.elapsed() < PROXY_ARP_RETRY => bail!("proxy ARP on {dev} failed; tried again shortly"),
        _ => {}
    }
    match index.and_then(|i| write().map(|()| i)) {
        Ok(i) => {
            on.insert(dev.into(), Ok(i));
            Ok(())
        }
        Err(e) => {
            if !matches!(on.insert(dev.into(), Err(std::time::Instant::now())), Some(Err(_))) {
                crate::log!("WARNING: proxy ARP on {dev}: {e}");
            }
            Err(e)
        }
    }
}

pub fn ip_forward() -> Result<()> {
    enable("/proc/sys/net/ipv4/ip_forward".as_ref()).map_err(|e| format!("ip_forward: {e}").into())
}

/// Sets a boolean sysctl to 1, written only if it is not already: one already on is enough even
/// where it is read-only (a container's /proc/sys).
fn enable(path: &std::path::Path) -> std::io::Result<()> {
    if std::fs::read_to_string(path).is_ok_and(|v| v.trim() == "1") {
        return Ok(());
    }
    std::fs::write(path, "1")
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
    addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
    addr.sll_ifindex = ifindex as i32;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    crate::syscall_check!(send_to(&fd, &frame, &addr) < 0, "send gratuitous arp");
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

    pub fn contains_range(&self, other: &IpRange) -> bool {
        self.first <= other.first && other.last <= self.last
    }

    /// In it, and never with a 16-bit half all zeros or all ones: checksum completion could
    /// rewrite one into the other and leave the IP header checksum valid (#365), forging a source.
    pub fn allocatable(&self, ip: Ipv4Addr) -> bool {
        let n = u32::from(ip);
        self.contains(ip) && [n >> 16, n & 0xffff].iter().all(|h| ![0, 0xffff].contains(h))
    }

    /// The first address not `taken`, looking from `hint` (if in range) to the
    /// end, then from the start: each address at most once.
    pub fn allocate(&self, hint: Option<Ipv4Addr>, taken: impl Fn(Ipv4Addr) -> bool) -> Option<Ipv4Addr> {
        let start = hint.map(u32::from).filter(|h| (self.first..=self.last).contains(h)).unwrap_or(self.first);
        (start..=self.last).chain(self.first..start).map(Ipv4Addr::from).find(|ip| self.allocatable(*ip) && !taken(*ip))
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
    fn tap_queue_drains_nonblocking_frames_and_stops_at_empty() {
        use std::os::unix::net::UnixDatagram;

        let (read, write) = UnixDatagram::pair().unwrap();
        let fd: OwnedFd = read.into();
        for nonblocking in [false, true] {
            if nonblocking {
                assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) }, 0);
            }
            write.send(b"first").unwrap();
            write.send(b"second").unwrap();
            let mut frames = Vec::new();
            assert_eq!(read_tap_queue(&fd, &mut |f| frames.push(f.to_vec())), 2);
            assert_eq!(frames, [b"first".to_vec(), b"second".to_vec()]);
            assert_eq!(read_tap_queue(&fd, &mut |_| panic!("empty")), 0);
        }
        write.send(b"ongoing").unwrap();
        assert_eq!(
            read_tap_queue(&fd, &mut |_| {
                write.send(b"ongoing").unwrap();
            }),
            u64::from(TAP_QUEUE)
        );
    }

    #[test]
    fn proxy_arp_retries_failures_after_a_pause_and_recreated_interfaces() {
        let mut on = ProxyArp::new();
        let writes = std::cell::Cell::new(0);
        let write = || {
            writes.set(writes.get() + 1);
            Ok(())
        };
        let expire = |on: &mut ProxyArp| on.insert("eth0".into(), Err(std::time::Instant::now() - PROXY_ARP_RETRY));
        assert!(enable_proxy_arp(&mut on, "eth0", Err("missing".into()), write).is_err());
        assert!(enable_proxy_arp(&mut on, "eth0", Ok(1), write).is_err(), "a failure waits before it is tried again");
        assert_eq!(writes.get(), 0);
        expire(&mut on);
        assert!(enable_proxy_arp(&mut on, "eth0", Ok(1), || Err("write failed".into())).is_err());
        expire(&mut on);
        enable_proxy_arp(&mut on, "eth0", Ok(1), write).unwrap();
        enable_proxy_arp(&mut on, "eth0", Ok(1), write).unwrap();
        assert_eq!(writes.get(), 1, "success alone skips a write");
        enable_proxy_arp(&mut on, "eth0", Ok(2), write).unwrap();
        assert_eq!(writes.get(), 2, "the same name with a new index needs setup");
    }

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
    fn no_address_has_a_half_of_all_zeros_or_ones() {
        let r = IpRange::parse("10.9.255.254-10.10.0.2").unwrap();
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert!(r.allocatable(ip("10.9.255.254")) && r.allocatable(ip("10.10.0.1")));
        assert!(!r.allocatable(ip("10.9.255.255")) && !r.allocatable(ip("10.10.0.0")));
        assert!(r.contains(ip("10.9.255.255")) && r.contains(ip("10.10.0.0")), "still in it: a home address");
        let mut got = Vec::new();
        while let Some(a) = r.allocate(None, |a| got.contains(&a)) {
            got.push(a);
        }
        assert_eq!(got, [ip("10.9.255.254"), ip("10.10.0.1"), ip("10.10.0.2")]);
    }

    #[test]
    fn gateways_are_read_off_the_route_table() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
                     eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(gateways(table), [Ipv4Addr::new(192, 168, 1, 1)]);
    }

    #[test]
    fn a_route_reply_gives_its_device_and_source() {
        let reply = |kind: u16, attrs: &[(u16, &[u8])]| {
            let mut m = vec![0u8; 16];
            m[4..6].copy_from_slice(&kind.to_ne_bytes());
            m.extend_from_slice(&[libc::AF_INET as u8, 32, 0, 0, 254, 2, 0, 1, 0, 0, 0, 0]);
            for (k, d) in attrs {
                attr(&mut m, *k, d);
            }
            let len = m.len() as u32;
            m[..4].copy_from_slice(&len.to_ne_bytes());
            m
        };
        let (dst, src, gw) = ([100u8, 64, 0, 7], [100u8, 101, 9, 2], [192u8, 168, 1, 1]);
        let full = reply(
            RTM_NEWROUTE,
            &[(RTA_DST, &dst), (libc::RTA_TABLE, &52u32.to_ne_bytes()), (libc::RTA_PREFSRC, &src), (RTA_GATEWAY, &gw), (RTA_OIF, &9u32.to_ne_bytes())],
        );
        assert_eq!(parse_route(&full), Ok((9, Ipv4Addr::from(src))));
        // Trailing bytes past the message are not read as attributes.
        assert_eq!(parse_route(&[&full[..], &[8, 0, 4, 0, 1, 0, 0, 0]].concat()), Ok((9, Ipv4Addr::from(src))));
        assert_eq!(parse_route(&reply(RTM_NEWROUTE, &[(RTA_OIF, &9u32.to_ne_bytes())])), Err("".into()), "no source");
        assert_eq!(parse_route(&reply(RTM_NEWROUTE, &[(libc::RTA_PREFSRC, &src)])), Err("".into()), "no device");
        // An error gives the kernel's errno (struct nlmsgerr: a negative errno after the header).
        let mut err = reply(NLMSG_ERROR as u16, &[]);
        err[16..20].copy_from_slice(&(-libc::ENETUNREACH).to_ne_bytes());
        let why = std::io::Error::from_raw_os_error(libc::ENETUNREACH).to_string();
        assert_eq!(parse_route(&err), Err(format!(": {why}")));
        assert_eq!(parse_route(&err[..19]), Err("".into()), "a short error");
        let mut bad = full.clone();
        bad[28] = 200;
        assert_eq!(parse_route(&bad), Err("".into()), "an attribute past the end");
    }

    #[test]
    fn route_lookup_errors_and_vanished_interfaces_are_reported() {
        let to = Ipv4Addr::new(192, 0, 2, 1);
        let err = route_from_reply(to, &[]).unwrap_err().to_string();
        assert!(err.contains("no route toward 192.0.2.1"), "{err}");
        let mut reply = vec![0u8; 28];
        reply[4..6].copy_from_slice(&RTM_NEWROUTE.to_ne_bytes());
        attr(&mut reply, RTA_OIF, &u32::MAX.to_ne_bytes());
        attr(&mut reply, libc::RTA_PREFSRC, &[192, 0, 2, 2]);
        let len = reply.len() as u32;
        reply[..4].copy_from_slice(&len.to_ne_bytes());
        let err = route_from_reply(to, &reply).unwrap_err().to_string();
        assert!(err.contains("route toward 192.0.2.1: interface 4294967295:"), "{err}");
    }

    #[test]
    fn the_kernel_names_the_route_toward_loopback() {
        let (dev, src) = route_get(Ipv4Addr::LOCALHOST).unwrap();
        assert!(!dev.is_empty() && src == Ipv4Addr::LOCALHOST, "{dev} {src}");
        // Loopback (ARPHRD_LOOPBACK) takes no ARP announcements, nor does a device that is not there.
        assert!(!is_ethernet("lo") && !is_ethernet("flexvm-none0"));
    }

    #[test]
    fn long_interface_names_are_refused() {
        assert!(ifreq("fvci0A3fffffhff").is_ok(), "15 bytes");
        // Refused before /dev/net/tun is opened (no CAP_NET_ADMIN needed).
        let e = create_tap("fvci0A3fffffta00", "").unwrap_err().to_string();
        assert!(e.contains("over 15 bytes"), "{e}");
    }

    /// Needs root: `sudo cargo test -- --ignored`. A tap names its owner; a plug the kernel
    /// refuses is told apart (nothing to unplug), and only our plug is ever removed.
    #[test]
    #[ignore]
    fn taps_name_their_owner_and_only_our_plug_goes() {
        let _root = crate::test_util::root_net_lock();
        let tap = format!("tw4p{:x}", std::process::id());
        let tc = |args: &str| std::process::Command::new("tc").args(args.split(' ')).output().unwrap();
        let root = || String::from_utf8_lossy(&tc(&format!("qdisc show dev {tap} root")).stdout).into_owned();
        struct TapGuard<'a>(&'a str);
        impl Drop for TapGuard<'_> {
            fn drop(&mut self) {
                delete_tap(self.0);
            }
        }
        create_tap(&tap, "flexvm 1 2 /run/x").unwrap();
        let _tap = TapGuard(&tap);
        let alias = std::fs::read_to_string(format!("/sys/class/net/{tap}/ifalias")).unwrap();
        assert_eq!(alias.trim_end(), "flexvm 1 2 /run/x");
        assert!(tc(&format!("qdisc add dev {tap} root handle 1: fq_codel")).status.success());
        let (plugged, res) = plug_tap(&tap);
        assert!(!plugged && res.is_err(), "another kind at 1: refuses the plug");
        assert!(remove_plug(ifindex(&tap).unwrap()).is_err());
        assert!(root().contains("fq_codel 1:"), "{}", root());
        assert!(tc(&format!("qdisc del dev {tap} root")).status.success());
        let (plugged, res) = plug_tap(&tap);
        assert!(plugged && res.is_ok(), "{res:?}");
        assert!(root().contains("plug 1:"), "{}", root());
        let (drops, res) = unplug_tap(&tap);
        assert!(drops == 0 && res.is_ok(), "{res:?}");
        remove_plug(ifindex(&tap).unwrap()).unwrap();
        assert!(!root().contains("plug"), "{}", root());
        // Shut from the start; an address, then another, replaces its one filter.
        let filters = || String::from_utf8_lossy(&tc(&format!("filter show dev {tap} ingress")).stdout).into_owned();
        assert!(filters().matches("direct-action").count() == 1 && filters().contains("bytecode '1,6 0 0 2'"), "{}", filters());
        for ip in [Ipv4Addr::new(192, 0, 2, 7), Ipv4Addr::new(192, 0, 2, 8)] {
            neighbour(ip, &tap).unwrap();
            let f = filters();
            assert!(f.matches("direct-action").count() == 1 && f.contains(&format!(" {},", u32::from(ip))), "{f}");
        }
    }

    /// A message as udev broadcasts it on its monitor group (`udev_event`).
    fn udev_message(props: &[&str]) -> Vec<u8> {
        let props: Vec<u8> = props.iter().flat_map(|p| [p.as_bytes(), b"\0"].concat()).collect();
        let words = [40u32, 40, props.len() as u32, 0, 0, 0, 0].map(u32::to_ne_bytes).concat();
        [&b"libudev\0"[..], &0xfeedcafe_u32.to_be_bytes(), &words, &props].concat()
    }

    #[test]
    fn udev_events_name_their_action_and_interface() {
        let msg = udev_message(&["ACTION=add", "DEVPATH=/devices/virtual/net/fx0t0", "SUBSYSTEM=net", "INTERFACE=fx0t0", "IFINDEX=4242", "SEQNUM=9"]);
        assert_eq!(udev_event(&msg), Some((&b"add"[..], 4242)));
        assert_eq!(udev_event(&udev_message(&["ACTION=remove", "IFINDEX=7"])), Some((&b"remove"[..], 7)));
        // Not a network device's, the kernel's own format, a bad magic, properties past the end.
        assert_eq!(udev_event(&udev_message(&["ACTION=add", "DEVNAME=/dev/kvm"])), None);
        assert_eq!(udev_event(b"add@/devices/virtual/net/fx0t0\0ACTION=add\0IFINDEX=4242\0"), None);
        let mut bad = msg.clone();
        bad[8] ^= 1;
        assert_eq!(udev_event(&bad), None);
        assert_eq!(udev_event(&msg[..msg.len() - 3]), None);
        assert_eq!(udev_event(&msg[..20]), None);
    }

    /// Needs root: `sudo cargo test -- --ignored`. udev's late write of a MAC of its own (#841) is
    /// undone once udev says it is done with the tap, not before, and not for another device's
    /// event; the MAC is checked meanwhile, and the watcher ends with its tap.
    #[test]
    #[ignore]
    fn udevs_late_mac_is_undone_once_udev_is_done() {
        use std::time::{Duration, Instant};
        let _root = crate::test_util::root_net_lock();
        let tap = format!("tw4u{:x}", std::process::id());
        struct TapGuard<'a>(&'a str);
        impl Drop for TapGuard<'_> {
            fn drop(&mut self) {
                delete_tap(self.0);
            }
        }
        // Made with no watcher of its own; a udevd here is done with it before the test goes on.
        make_tap(&tap, "test", None).unwrap();
        let _tap = TapGuard(&tap);
        let _ = std::process::Command::new("udevadm").args(["settle", "--timeout=10"]).status();
        let index = ifindex(&tap).unwrap();
        set_mac(index, &GATEWAY_MAC).unwrap();
        let mac = || parse_mac(&std::fs::read_to_string(format!("/sys/class/net/{tap}/address")).unwrap()).unwrap();
        let udev = uevent_socket(UDEV_GROUP).expect("a socket on udev's group");
        let ours = [0x72, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sender = socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_KOBJECT_UEVENT, "uevent socket").unwrap();
        let send = |props: &[&str]| {
            let mut to: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            (to.nl_family, to.nl_groups) = (libc::AF_NETLINK as u16, UDEV_GROUP);
            assert!(send_to(&sender, &udev_message(props), &to) > 0, "{}", std::io::Error::last_os_error());
        };
        let (on, other) = (format!("IFINDEX={index}"), format!("IFINDEX={}", index + 1000));
        // Detached, so a failed assertion leaves it behind rather than joining a watcher that never ends.
        let udev = std::sync::Arc::new(udev);
        let watch = |recheck| {
            let (udev, tap) = (udev.clone(), tap.clone());
            std::thread::spawn(move || keep_mac_from_udev(&udev, index, &tap, recheck))
        };
        let ends = |w: &std::thread::JoinHandle<()>| {
            let by = Instant::now() + Duration::from_secs(10);
            while !w.is_finished() && Instant::now() < by {
                std::thread::sleep(Duration::from_millis(10));
            }
            w.is_finished()
        };
        set_mac(index, &ours).unwrap();
        let start = Instant::now();
        let w = watch(Duration::from_secs(60));
        send(&["ACTION=add", "SUBSYSTEM=net", &other]);
        send(&["ACTION=change", "SUBSYSTEM=net", &on]);
        std::thread::sleep(Duration::from_millis(300));
        assert!(!w.is_finished() && mac() == ours, "another device's event, or a change, is not udev done with this tap");
        send(&["ACTION=add", "SUBSYSTEM=net", &format!("INTERFACE={tap}"), &on]);
        assert!(ends(&w) && mac() == GATEWAY_MAC && start.elapsed() < Duration::from_secs(10), "by the event, not a recheck: {:?}", start.elapsed());
        // With no event, a recheck puts it back, however busy udev is with other devices, and the
        // watcher goes on until udev's remove.
        set_mac(index, &ours).unwrap();
        let w = watch(Duration::from_millis(200));
        let back = Instant::now() + Duration::from_secs(5);
        while mac() != GATEWAY_MAC && Instant::now() < back {
            send(&["ACTION=change", "SUBSYSTEM=net", &other]);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(mac(), GATEWAY_MAC);
        assert!(!w.is_finished());
        send(&["ACTION=remove", "SUBSYSTEM=net", &on]);
        assert!(ends(&w));
        // A tap gone ends its watcher at the next recheck, touching no other device.
        assert!(!restore_mac(index, "flexvm-none0"));
        let w = watch(Duration::from_millis(50));
        delete_tap(&tap);
        assert!(ends(&w));
    }

    /// `source_filter`'s verdict on `frame` (with a VLAN tag stripped or not), by a classic BPF
    /// interpreter of the instructions it uses, a load past the end returning 0 as the kernel's.
    fn verdict(ip: Option<Ipv4Addr>, frame: &[u8], tagged: bool) -> u32 {
        let prog = source_filter(ip);
        let (mut a, mut pc) = (0u32, 0usize);
        loop {
            let op = &prog[pc];
            pc += 1;
            let jump = |taken: bool| if taken { op.jt as usize } else { op.jf as usize };
            match op.code {
                0x20 if op.k == 0xffff_f030 => a = tagged as u32,
                0x20 | 0x28 => {
                    let n = if op.code == 0x20 { 4 } else { 2 };
                    let Some(b) = frame.get(op.k as usize..op.k as usize + n) else { return 0 };
                    a = b.iter().fold(0, |a, &b| a << 8 | u32::from(b));
                }
                0x80 => a = frame.len() as u32,
                0x15 => pc += jump(a == op.k),
                0x35 => pc += jump(a >= op.k),
                0x06 => return op.k,
                c => panic!("unexpected op {c:#x}"),
            }
        }
    }

    #[test]
    fn taps_pass_only_their_own_address() {
        let (me, other) = (Ipv4Addr::new(10, 9, 0, 2), Ipv4Addr::new(10, 9, 0, 3));
        let eth = |ty: u16| [&GATEWAY_MAC[..], &GUEST_MAC, &ty.to_be_bytes()].concat();
        let ipv4 = |src: Ipv4Addr| [&eth(0x0800)[..], &[0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0], &src.octets(), &[10, 9, 0, 9], &[0; 8]].concat();
        let arp = |sender: Ipv4Addr| [&eth(0x0806)[..], &[0, 1, 8, 0, 6, 4, 0, 1], &GUEST_MAC, &sender.octets(), &[0; 6], &[169, 254, 1, 1]].concat();
        let pass = |ip, frame: &[u8]| verdict(ip, frame, false) == TC_ACT_OK;
        assert!(pass(Some(me), &ipv4(me)));
        assert!(!pass(Some(me), &ipv4(other)), "another's source");
        assert!(!pass(Some(other), &ipv4(me)), "an old address, once readdressed");
        assert!(!pass(Some(me), &ipv4(Ipv4Addr::UNSPECIFIED)), "a DHCP client's");
        assert!(pass(Some(me), &arp(me)));
        assert!(!pass(Some(me), &arp(other)), "ARP with another's sender");
        assert!(!pass(Some(me), &ipv4(me)[..33]), "short of an IPv4 header");
        assert!(!pass(Some(me), &arp(me)[..41]), "short of an ARP body");
        assert!(!pass(Some(me), &eth(0x0800)), "an Ethernet header alone");
        assert!(!pass(Some(me), &[&eth(0x86dd)[..], &[0; 40]].concat()), "IPv6");
        assert!(!pass(Some(me), &[&eth(0x88cc)[..], &[0; 40]].concat()), "another ethertype");
        assert!(verdict(Some(me), &ipv4(me), true) == TC_ACT_SHOT, "VLAN tagged");
        assert!(!pass(None, &ipv4(me)) && !pass(None, &arp(me)), "a tap with no address yet");
    }

    #[test]
    fn macs_print_as_firecracker_takes_them() {
        assert_eq!(mac_string(&GUEST_MAC), "06:00:ac:10:00:02");
        assert_eq!(parse_mac(&mac_string(&GATEWAY_MAC)).unwrap(), GATEWAY_MAC);
    }

    #[test]
    fn loopback_routes_are_noops() {
        for via in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 42, 3, 4), Ipv4Addr::new(127, 255, 255, 255)] {
            // Works without CAP_NET_ADMIN: no route request is sent.
            route_via(Ipv4Addr::new(192, 0, 2, 123), via).unwrap();
        }
    }

    #[test]
    fn a_failed_local_address_check_stops_routing() {
        const CHILD: &str = "FLEXVM_TEST_GETIFADDRS_FAILURE";
        if std::env::var_os(CHILD).is_some() {
            // A fresh process has no cached addresses; no spare fd makes getifaddrs fail.
            let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
            let e = route_via(Ipv4Addr::new(198, 51, 100, 7), Ipv4Addr::new(192, 0, 2, 1)).unwrap_err().to_string();
            assert!(e.contains("getifaddrs"), "{e}");
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "net::tests::a_failed_local_address_check_stops_routing", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn interface_indices_must_still_have_the_expected_name() {
        let index = ifindex("lo").unwrap();
        assert!(has_name(index, "lo"));
        assert!(!has_name(index, "flexvm-none0"));
        assert!(!has_name(0, "lo"));
    }

    /// Needs CAP_SYS_ADMIN and CAP_NET_ADMIN, and iproute2; no VM. Routes stay in a private netns.
    #[test]
    #[ignore]
    fn withdrawals_remove_only_gateway_routes() {
        std::thread::spawn(|| {
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0, "{}", std::io::Error::last_os_error());
            let ip = |args: &[&str]| {
                let out = std::process::Command::new("ip").args(args).output().unwrap();
                assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
                String::from_utf8(out.stdout).unwrap()
            };
            ip(&["link", "add", "peer0", "type", "dummy"]);
            ip(&["addr", "add", "192.0.2.3/24", "dev", "peer0"]);
            ip(&["link", "set", "peer0", "up"]);
            let index = ifindex("peer0").unwrap();
            let target = Ipv4Addr::new(198, 51, 100, 7);
            let route = || ip(&["-4", "route", "show", "198.51.100.7/32"]);
            route_dev(true, target, index).unwrap();
            unroute(target);
            assert!(route().contains("dev peer0"), "a tap route survives a withdrawal");
            route_via(target, Ipv4Addr::new(192, 0, 2, 2)).unwrap();
            unroute(target);
            assert!(route().is_empty(), "a route via any peer goes");
        })
        .join()
        .unwrap();
    }

    /// An already enabled sysctl needs no write, so a read-only one that is on is no failure.
    #[test]
    fn a_sysctl_already_on_is_not_written() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::test_util::TempDir::new("sysctl");
        let (on, off) = (d.join("on"), d.join("off"));
        for (p, v) in [(&on, "1\n"), (&off, "0\n")] {
            std::fs::write(p, v).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        assert!(enable(&on).is_ok());
        if unsafe { libc::geteuid() } != 0 {
            assert!(enable(&off).is_err(), "off and read-only: a failure");
        }
        let w = d.join("w");
        std::fs::write(&w, "0").unwrap();
        enable(&w).unwrap();
        assert_eq!(std::fs::read_to_string(&w).unwrap(), "1");
    }
}
