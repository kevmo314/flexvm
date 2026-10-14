//! Host networking: every VM gets a /32 routed to its own tap.
//!
//! All taps share one MAC, as do all guests, so moving a VM between hosts is just moving
//! its route (plus, with `--announce-dev`, a gratuitous ARP for proxy-ARP LAN peers).

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{
    c_int, IFA_ADDRESS, IFA_LOCAL, IFLA_ADDRESS, IFLA_IFALIAS, NDA_DST, NDA_LLADDR, NLMSG_ERROR, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST,
    NUD_PERMANENT, RTA_DST, RTA_GATEWAY, RTA_OIF, RTM_DELLINK, RTM_DELROUTE, RTM_NEWADDR, RTM_NEWNEIGH, RTM_NEWROUTE, RTM_SETLINK, RTN_UNICAST, RTPROT_STATIC,
    RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN,
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
    let mut req = ifreq(name)?;
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

/// Whether frames wait on a tap for its guest, through a copy of Firecracker's descriptor of
/// it (`tap_fd_of`): tun's ring is not empty. Paused vCPUs post no rx buffers, so a VM paused
/// with frames there loses them when the tap goes (a migration, `checkpoint --stop`, a
/// suspend), and no counter shows it: a guest slow to refill under load leaves hundreds (#136).
pub fn tap_queued(fd: &OwnedFd) -> Result<bool> {
    loop {
        let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        match unsafe { libc::poll(&mut pfd, 1, 0) } {
            n if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => continue,
            n if n < 0 => bail!("poll: {}", std::io::Error::last_os_error()),
            n => return Ok(n > 0 && pfd.revents & libc::POLLIN != 0),
        }
    }
}

/// Reads off and counts the frames queued on a tap (`tap_fd_of`, non-blocking as Firecracker
/// opened it): for a VM leaving with frames its guest would not take, so their loss is counted.
pub fn discard_tap_queue(fd: &OwnedFd) -> u64 {
    // A frame with its virtio-net header, up to the 64 KiB a GSO frame can be.
    let mut buf = vec![0u8; 65562 + 64];
    let mut n = 0;
    // Bounded by the ring (TAP_QUEUE) and in case the descriptor were blocking after all.
    while n < u64::from(TAP_QUEUE) && tap_queued(fd).unwrap_or(false) {
        if unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } < 0 {
            break;
        }
        n += 1;
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
        if fd < 0 {
            bail!("pidfd_getfd {pid} {target}: {}", std::io::Error::last_os_error());
        }
        return Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) });
    }
    bail!("process {pid} has no descriptor attached to {tap}")
}

/// Without an address on the tap, rp_filter (even loose) drops what the guest sends while
/// its address is routed elsewhere (`hold`); a per-tap `rp_filter=0` loses to `all`=2.
pub const TAP_ADDR: &str = "169.254.1.2/32";

/// Room for the packets a migration held, injected all at once (default 1000).
pub const TAP_QUEUE: u32 = 4096;

/// Ioctls and rtnetlink, as spawning `ip` costs tens of milliseconds. `owner` becomes the
/// tap's alias (`host::tap_alias`), set before the tap is made persistent: a tap left
/// behind always names its owner, and garbage collection goes by that, never by the name.
pub fn create_tap(name: &str, owner: &str) -> Result<()> {
    if owner.len() >= 256 {
        bail!("tap {name}: owner {owner:?} is over 255 bytes (a shorter run directory)");
    }
    let mut req = ifreq(name)?;
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        bail!("/dev/net/tun: {}", std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // Never a leaked tap of a dead process with this name, nor its routes.
    req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &req) } < 0 {
        bail!("create tap {name}: {}", std::io::Error::last_os_error());
    }
    // Until TUNSETPERSIST the tap goes with `fd`, so with this process.
    let mut alias = ifinfomsg(ifindex(name)?);
    attr(&mut alias, IFLA_IFALIAS, owner.as_bytes());
    netlink(RTM_SETLINK, 0, &alias).map_err(|e| format!("tap {name}: its owner: {e}"))?;
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETPERSIST, 1) } < 0 {
        bail!("create tap {name}: {}", std::io::Error::last_os_error());
    }
    drop(fd);
    let made = (|| -> Result<()> {
        let index = ifindex(name)?;
        let mut addr = [&[libc::AF_INET as u8, 32, 0, RT_SCOPE_HOST][..], &index.to_ne_bytes()].concat();
        let local: Ipv4Addr = TAP_ADDR.split('/').next().unwrap_or_default().parse()?;
        attr(&mut addr, IFA_LOCAL, &local.octets());
        attr(&mut addr, IFA_ADDRESS, &local.octets());
        netlink(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &addr)?;
        set_mac(index, &parse_mac(GATEWAY_MAC)?)?;
        let mut q = ifreq(name)?;
        q.ifr_ifru.ifru_metric = TAP_QUEUE as i32;
        let sock = socket(libc::AF_INET, libc::SOCK_DGRAM, 0, "socket")?;
        if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFTXQLEN as _, &q) } < 0 {
            bail!("txqueuelen of {name}: {}", std::io::Error::last_os_error());
        }
        sysctl(&format!("net.ipv4.conf.{name}.arp_ignore"), "3")?;
        // The guest is IPv4 only. With IPv6, the host sends an MLD report out of the tap as
        // it comes up: dropped (tx_dropped) when no Firecracker reads it yet (an arrival's),
        // which reads as a frame lost on its way to the guest. As for the hold device.
        let _ = sysctl(&format!("net.ipv6.conf.{name}.disable_ipv6"), "1");
        set_link_up(name, true)
    })();
    if made.is_err() {
        delete_tap(name);
    }
    made
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
    let mut now = [0 as libc::c_char; libc::IFNAMSIZ];
    let named = unsafe { libc::if_indextoname(ifindex, now.as_mut_ptr()) };
    if !named.is_null() && unsafe { std::ffi::CStr::from_ptr(named) }.to_bytes() == name.as_bytes() {
        let _ = netlink(RTM_DELLINK, 0, &ifinfomsg(ifindex));
    }
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
    route_dev(true, ip, neighbour(ip, tap)?)
}

/// `attach` but the route, which a migration target installs at its commit; returns the
/// tap's index.
pub fn neighbour(ip: Ipv4Addr, tap: &str) -> Result<u32> {
    let ifindex = ifindex(tap)?;
    let mac = parse_mac(GATEWAY_MAC)?;
    if std::fs::read_to_string(format!("/sys/class/net/{tap}/address")).ok().and_then(|s| parse_mac(&s).ok()) != Some(mac) {
        set_mac(ifindex, &mac)?;
    }
    // struct ndmsg: family, pad, index, state, flags, type.
    let mut neigh = [&[libc::AF_INET as u8, 0, 0, 0][..], &ifindex.to_ne_bytes(), &NUD_PERMANENT.to_ne_bytes(), &[0, 0]].concat();
    attr(&mut neigh, NDA_DST, &ip.octets());
    attr(&mut neigh, NDA_LLADDR, &parse_mac(GUEST_MAC)?);
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
        Err(Failed::Refused(e)) | Err(Failed::Unsent(e)) => (false, Err(e)),
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
    let stats = || qdisc_stats(ifindex).unwrap_or_default();
    let Err(e) = retry3(|| netlink(libc::RTM_NEWQDISC, 0, &plug_msg(ifindex, TCQ_PLUG_RELEASE_INDEFINITE))) else { return (stats().0, Ok(())) };
    let (drops, queued) = stats();
    let remove = move || remove_plug(ifindex);
    if retry3(remove).is_ok() {
        return (drops + queued, Err(format!("{e}; removed the plug instead").into()));
    }
    let tap = tap.to_string();
    std::thread::spawn(move || {
        for _ in 0..60 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            // Only while the index is still this tap's.
            if crate::net::ifindex(&tap).ok() != Some(ifindex) {
                return;
            }
            if remove().is_ok() {
                return eprintln!("tap {tap}: plug removed");
            }
        }
        eprintln!("tap {tap}: could not remove its plug");
    });
    (drops + queued, Err(format!("{e}; removing the plug failed too, retrying").into()))
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

/// The root qdisc's (drops, queued packets), from RTM_GETQDISC on a socket of its own: the
/// qdisc echoed back (NLM_F_ECHO; a get without it answers nothing), no ACK, waited for up to
/// a second.
fn qdisc_stats(ifindex: u32) -> Option<(u64, u64)> {
    const NLM_F_ECHO: c_int = 8;
    let sock = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket").ok()?;
    let timeout = libc::timeval { tv_sec: 1, tv_usec: 0 };
    let size = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    if unsafe { libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&timeout as *const libc::timeval).cast(), size) } != 0 {
        return None;
    }
    let body = tcmsg(ifindex, 0x1_0000);
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
    if ip.is_loopback() {
        return Ok(true);
    }
    // At most a second old: listen checks one per route it installs.
    static LOCAL: std::sync::Mutex<(Option<std::time::Instant>, Vec<Ipv4Addr>)> = std::sync::Mutex::new((None, Vec::new()));
    let mut local = LOCAL.lock().unwrap();
    if local.0.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(1)) {
        let mut addrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
            bail!("getifaddrs: {}", std::io::Error::last_os_error());
        }
        local.1.clear();
        let mut current = addrs;
        while !current.is_null() {
            let addr = unsafe { &*current };
            if !addr.ifa_addr.is_null() && unsafe { (*addr.ifa_addr).sa_family } == libc::AF_INET as u16 {
                let v4 = unsafe { &*addr.ifa_addr.cast::<libc::sockaddr_in>() };
                local.1.push(Ipv4Addr::from(v4.sin_addr.s_addr.to_ne_bytes()));
            }
            current = addr.ifa_next;
        }
        unsafe { libc::freeifaddrs(addrs) };
        local.0 = Some(std::time::Instant::now());
    }
    Ok(local.1.contains(&ip))
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
    let (kind, flags) = if add { (RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE) } else { (RTM_DELROUTE, 0) };
    netlink(kind, flags, &route)
}

pub fn unroute(ip: Ipv4Addr) {
    let mut route = rtmsg(RT_SCOPE_NOWHERE);
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

/// Why a request failed: the kernel answered no (nothing changed), it was never sent, or its
/// answer was lost after it was sent (the change may have been made).
enum Failed {
    Refused(crate::util::Error),
    Unsent(crate::util::Error),
    Unanswered(crate::util::Error),
}

fn netlink(kind: u16, flags: c_int, body: &[u8]) -> Result<()> {
    request(kind, flags, body).map_err(|(Failed::Refused(e) | Failed::Unsent(e) | Failed::Unanswered(e))| e)
}

/// One socket per thread, so each recv is the ACK of the request just sent and a slow one
/// (a tap's teardown) holds up no other thread; any failure drops it, so no stale ACK is
/// left for the next.
fn request(kind: u16, flags: c_int, body: &[u8]) -> std::result::Result<(), Failed> {
    thread_local!(static FD: std::cell::Cell<Option<OwnedFd>> = const { std::cell::Cell::new(None) });
    let sock = FD.take().map_or_else(|| socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE, "netlink socket"), Ok).map_err(Failed::Unsent)?;
    let mut ack = [0u8; 1024];
    let reply = exchange(&sock, kind, flags | NLM_F_ACK, body, &mut ack)?;
    if reply.len() < 20 {
        return Err(Failed::Unanswered(format!("netlink: short reply ({} bytes)", reply.len()).into()));
    }
    FD.set(Some(sock));
    let kind = u16::from_ne_bytes([ack[4], ack[5]]);
    let code = i32::from_ne_bytes(ack[16..20].try_into().unwrap());
    if kind == NLMSG_ERROR as u16 && code != 0 {
        return Err(Failed::Refused(format!("netlink: {}", std::io::Error::from_raw_os_error(-code)).into()));
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
        return Err(Failed::Unsent(format!("netlink: {}", std::io::Error::last_os_error()).into()));
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
        let tap = format!("tw4p{:x}", std::process::id());
        let tc = |args: &str| std::process::Command::new("tc").args(args.split(' ')).output().unwrap();
        let root = || String::from_utf8_lossy(&tc(&format!("qdisc show dev {tap} root")).stdout).into_owned();
        create_tap(&tap, "flexvm 1 2 /run/x").unwrap();
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
        delete_tap(&tap);
    }

    #[test]
    fn loopback_routes_are_noops() {
        for via in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 42, 3, 4), Ipv4Addr::new(127, 255, 255, 255)] {
            // Works without CAP_NET_ADMIN: no route request is sent.
            route_via(Ipv4Addr::new(192, 0, 2, 123), via).unwrap();
        }
    }
}
