//! Holds packets for a migrating VM while it is paused, and delivers them
//! once it runs again, instead of letting them hit a downed tap (where TCP
//! peers would wait out a retransmit timeout: 200 ms, or 400+ ms when the
//! retransmit is lost too).
//!
//! Source: each daemon owns one TUN device, `fv<port>h`. Just before pausing
//! a VM, `hold` points the VM's /32 at it (one rtnetlink message; that route
//! is all this module adds to the host's routing). A thread reads the device
//! and queues each packet on its address's entry, up to `CAP` bytes, and
//! does nothing else. Once the target has the VM running, `release` hands
//! the queue, then whatever still reaches the device, to a sink, switches
//! the route to the target, and hands over what arrived meanwhile. The
//! daemon's sink streams them to the target daemon over TCP (`send`).
//!
//! Target: `receive` reads that stream and injects each packet into the
//! guest by sending it as an Ethernet frame out of the VM's tap from an
//! AF_PACKET socket (`Injector`): Firecracker reads it like any frame for
//! the guest, byte for byte as it arrived (no host routing, no header
//! rewrite). The target announces the VM only after the stream ends, so
//! held packets come before traffic sent straight to it.
//!
//! After an aborted migration the source injects the queue into the VM's
//! own tap the same way, before resuming it.

use std::collections::{HashMap, VecDeque};
use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::util::Result;

/// Bytes held per address; packets beyond it are dropped and counted.
pub const CAP: usize = 4 << 20;
/// How long `release` hands over packets still on their way through the
/// TUN device, on each side of the route switch. Past that (a flood faster
/// than the sink), the rest is dropped and counted.
const CATCH_UP: Duration = Duration::from_millis(100);
/// Largest frame in the stream (an IP packet is at most 64 KiB).
const MAX_FRAME: usize = 65535;
/// How long a source waits for a target to accept its held packets.
const ACCEPT_WAIT: Duration = Duration::from_secs(1);
/// How long a source waits for a target to confirm a sync.
const SYNC_WAIT: Duration = Duration::from_millis(250);
/// How long a source may take to send one buffer of the stream.
const FLUSH_WAIT: Duration = Duration::from_millis(400);
/// How long a source waits for the target's account of the stream.
const REPLY_WAIT: Duration = Duration::from_secs(1);

pub struct Holder {
    dev: String,
    ifindex: u32,
    tun: OwnedFd,
    /// Lookups and inserts only: no I/O happens under this lock.
    held: Mutex<HashMap<Ipv4Addr, Arc<Entry>>>,
    /// The reader has packets in hand that it has not queued yet.
    reading: AtomicBool,
    /// Times the reader has found the device empty: once it moves on, every
    /// packet that was in the device before has been queued.
    passes: AtomicU64,
    /// Held while the TUN route of an address is added or deleted.
    routes: Mutex<()>,
}

struct Entry {
    /// The migration holding the address.
    mig: u64,
    q: Mutex<Queue>,
}

#[derive(Default)]
struct Queue {
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
    /// Being released: `holding` no longer reports it.
    releasing: bool,
    /// Dropped here: queue full, or not handed over in time.
    dropped: u64,
}

/// What became of a migration's held packets.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    /// Handed to the sink (sent to the target, or injected here).
    pub packets: u64,
    pub bytes: u64,
    /// Dropped here: over `CAP`, not handed over within `CATCH_UP`, or the
    /// sink failed.
    pub dropped: u64,
    /// Injected into the guest's tap by the target.
    pub injected: u64,
    /// Lost on the target: injection failed, the tap queue overflowed, or
    /// the stream broke off.
    pub dropped_target: u64,
}

impl Stats {
    pub fn json(&self) -> Value {
        json!({
            "packets": self.packets,
            "kib": self.bytes >> 10,
            "dropped": self.dropped,
            "injected": self.injected,
            "dropped_target": self.dropped_target,
        })
    }
}

impl Holder {
    /// Creates TUN device `fv<port>h`, owned by this daemon alone: if another
    /// process has it, this fails (the caller stops). None, with a warning,
    /// if the host has no TUN support: then nothing is held.
    pub fn new(port: u16) -> Result<Option<Arc<Holder>>> {
        let dev = format!("fv{port}h");
        let tun = match open_tun(&dev) {
            Ok(tun) => tun,
            Err(Tun::Busy(e)) => return Err(e),
            Err(Tun::Unsupported(e)) => {
                eprintln!("packets in flight during migrations will be dropped: {e}");
                return Ok(None);
            }
        };
        let _ = crate::net::sysctl(&format!("net.ipv6.conf.{dev}.disable_ipv6"), "1");
        crate::net::set_link_up(&dev, true)?;
        let ifindex = crate::net::ifindex(&dev)?;
        let h = Arc::new(Holder { dev, ifindex, tun, held: Mutex::new(HashMap::new()), reading: AtomicBool::new(false), passes: AtomicU64::new(0), routes: Mutex::new(()) });
        let reader = h.clone();
        std::thread::Builder::new().name("hold".into()).spawn(move || reader.read_loop())?;
        Ok(Some(h))
    }

    /// Starts holding packets for `ip` for migration `mig`: call just before
    /// the VM stops taking them.
    pub fn hold(&self, ip: Ipv4Addr, mig: u64) -> Result<()> {
        let _routes = self.routes.lock().unwrap();
        let entry = Arc::new(Entry { mig, q: Mutex::default() });
        self.held.lock().unwrap().insert(ip, entry);
        if let Err(e) = tun_route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, ip, self.ifindex) {
            self.held.lock().unwrap().remove(&ip);
            return Err(e);
        }
        Ok(())
    }

    /// Whether packets for `ip` are held here, including while they are
    /// released, until `release` has switched the route: no one else may
    /// move it meanwhile.
    pub fn holding(&self, ip: Ipv4Addr) -> bool {
        self.entry(ip).is_some()
    }

    /// Whether migration `mig` holds `ip` and has not released it.
    pub fn holding_for(&self, ip: Ipv4Addr, mig: u64) -> bool {
        self.entry(ip).is_some_and(|e| e.mig == mig && !e.q.lock().unwrap().releasing)
    }

    fn entry(&self, ip: Ipv4Addr) -> Option<Arc<Entry>> {
        self.held.lock().unwrap().get(&ip).cloned()
    }

    /// Hands what migration `mig` held for `ip` to `sink`, in order, then
    /// what reached the TUN device meanwhile until it is empty, then calls
    /// `barrier` (which may wait for the sink's far end to catch up; what
    /// arrives meanwhile goes in another round, up to four); calls `switch`
    /// to move the address's route; then hands over the packets that
    /// entered the device during the switch, and stops holding. `sink`
    /// returns false for a packet it lost; `barrier` false if the far end is
    /// lost, and then nothing more is handed over (what is left counts as
    /// dropped) but the route still switches. None if `mig` does not hold `ip`.
    pub fn release(
        &self,
        ip: Ipv4Addr,
        mig: u64,
        sink: &mut dyn FnMut(&[u8]) -> bool,
        barrier: &mut dyn FnMut() -> bool,
        switch: impl FnOnce() -> Result<()>,
    ) -> Option<(Stats, Result<()>)> {
        let e = self.entry(ip).filter(|e| e.mig == mig)?;
        {
            let mut q = e.q.lock().unwrap();
            if q.releasing {
                return None;
            }
            q.releasing = true;
        }
        let mut stats = Stats::default();
        let mut lost = false;
        // What arrives while `barrier` waits is handed over in another round.
        for _ in 0..4 {
            self.hand_over(&e, sink, &mut stats);
            if !barrier() {
                lost = true;
                break;
            }
            if e.q.lock().unwrap().packets.len() < 16 && !readable(&self.tun) {
                break;
            }
        }
        let switched = switch();
        if !lost {
            self.hand_over(&e, sink, &mut stats);
        }
        {
            let mut held = self.held.lock().unwrap();
            if held.get(&ip).is_some_and(|x| Arc::ptr_eq(x, &e)) {
                held.remove(&ip);
            }
        }
        let mut q = e.q.lock().unwrap();
        stats.dropped += q.dropped + q.packets.len() as u64;
        q.packets.clear();
        Some((stats, switched))
    }

    /// `release` into a VM on this host (`sink` injects into its tap, which
    /// never waits), for a VM paused only briefly. Waits only for `ip`'s own
    /// packets: on each side of `switch`, for the reader to get past what was
    /// in the device then, never for the device to go quiet (another VM's
    /// held traffic may keep it busy); and for at most `within` in all. If
    /// `switch` fails the address stays held, its route through the device
    /// too, until the caller `forget`s it.
    pub fn release_local(
        &self,
        ip: Ipv4Addr,
        mig: u64,
        sink: &mut dyn FnMut(&[u8]) -> bool,
        switch: impl FnOnce() -> Result<()>,
        within: Duration,
    ) -> Option<(Stats, Result<()>)> {
        let e = self.entry(ip).filter(|e| e.mig == mig)?;
        {
            let mut q = e.q.lock().unwrap();
            if q.releasing {
                return None;
            }
            q.releasing = true;
        }
        let end = Instant::now() + within;
        let mut stats = Stats::default();
        self.drain(&e, sink, &mut stats, end);
        let switched = switch();
        self.drain(&e, sink, &mut stats, end);
        if switched.is_ok() {
            let mut held = self.held.lock().unwrap();
            if held.get(&ip).is_some_and(|x| Arc::ptr_eq(x, &e)) {
                held.remove(&ip);
            }
        }
        let mut q = e.q.lock().unwrap();
        stats.dropped += q.dropped;
        q.dropped = 0;
        if switched.is_ok() {
            stats.dropped += q.packets.len() as u64;
            q.packets.clear();
        }
        Some((stats, switched))
    }

    /// Hands `e`'s queue to `sink`; then, once the reader has got past what
    /// is in the device now (or by `end`), what that added.
    fn drain(&self, e: &Entry, sink: &mut dyn FnMut(&[u8]) -> bool, stats: &mut Stats, end: Instant) {
        let mut give = |stats: &mut Stats| loop {
            let batch = e.q.lock().unwrap().take_batch();
            if batch.is_empty() {
                return;
            }
            for p in batch {
                match sink(&p) {
                    true => {
                        stats.packets += 1;
                        stats.bytes += p.len() as u64;
                    }
                    false => stats.dropped += 1,
                }
            }
        };
        give(stats);
        let pass = self.passes.load(Ordering::SeqCst);
        while Instant::now() < end
            && self.passes.load(Ordering::SeqCst) == pass
            && (self.reading.load(Ordering::SeqCst) || readable(&self.tun))
        {
            std::thread::yield_now();
        }
        give(stats);
    }

    /// Hands queued packets to `sink` until the queue and the device are
    /// empty, or for at most `CATCH_UP` (checked between packets).
    fn hand_over(&self, e: &Entry, sink: &mut dyn FnMut(&[u8]) -> bool, stats: &mut Stats) {
        let end = Instant::now() + CATCH_UP;
        loop {
            let batch = e.q.lock().unwrap().take_batch();
            if batch.is_empty() {
                if !self.reading.load(Ordering::SeqCst) && !readable(&self.tun) || Instant::now() >= end {
                    return;
                }
                std::thread::yield_now();
                continue;
            }
            let mut rest = batch.into_iter();
            for p in rest.by_ref() {
                if sink(&p) {
                    stats.packets += 1;
                    stats.bytes += p.len() as u64;
                } else {
                    stats.dropped += 1;
                }
                if Instant::now() >= end {
                    break;
                }
            }
            stats.dropped += rest.len() as u64;
            if Instant::now() >= end {
                return;
            }
        }
    }

    /// Drops what migration `mig` held for `ip` (its VM is gone, or the
    /// packets cannot be delivered), and the address's route through the TUN
    /// device if it is still there. Returns what it dropped.
    pub fn forget(&self, ip: Ipv4Addr, mig: u64) -> Stats {
        // With the hold check and the route deletion under `routes`, a newer
        // migration's hold of `ip` can never lose its route to this one.
        let _routes = self.routes.lock().unwrap();
        let gone = {
            let mut held = self.held.lock().unwrap();
            match held.get(&ip) {
                Some(e) if e.mig == mig => held.remove(&ip),
                _ => None,
            }
        };
        let Some(e) = gone else { return Stats::default() };
        // Matches the TUN device as the route's interface: never another route.
        let _ = tun_route(RTM_DELROUTE, 0, ip, self.ifindex);
        let mut q = e.q.lock().unwrap();
        let dropped = q.dropped + q.packets.len() as u64;
        q.packets.clear();
        Stats { dropped, ..Stats::default() }
    }

    /// Reads the TUN device and queues each packet on its address's entry.
    /// It never sends: no I/O but the read.
    fn read_loop(&self) {
        let mut pfd = libc::pollfd { fd: self.tun.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let mut buf = vec![0u8; 65536];
        loop {
            if unsafe { libc::poll(&mut pfd, 1, -1) } < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return eprintln!("hold device {}: {e}", self.dev);
            }
            self.reading.store(true, Ordering::SeqCst);
            loop {
                let n = unsafe { libc::read(self.tun.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                let p = &buf[..n as usize];
                if p.len() < 20 || p[0] >> 4 != 4 {
                    continue;
                }
                let Some(e) = self.entry(Ipv4Addr::new(p[16], p[17], p[18], p[19])) else { continue };
                let mut q = e.q.lock().unwrap();
                if q.bytes + p.len() > CAP {
                    q.dropped += 1;
                } else {
                    q.bytes += p.len();
                    q.packets.push_back(p.to_vec());
                }
            }
            self.passes.fetch_add(1, Ordering::SeqCst);
            self.reading.store(false, Ordering::SeqCst);
        }
    }
}

impl Queue {
    fn take_batch(&mut self) -> Vec<Vec<u8>> {
        let n = self.packets.len().min(256);
        let batch: Vec<_> = self.packets.drain(..n).collect();
        self.bytes -= batch.iter().map(Vec::len).sum::<usize>();
        batch
    }
}

/// Sends IP packets to a guest as Ethernet frames out of its tap, from the
/// gateway's MAC to the guest's, as Firecracker would deliver them.
pub struct Injector {
    fd: OwnedFd,
    tap: String,
    ifindex: u32,
    header: [u8; 14],
    tx_dropped: u64,
}

impl Injector {
    pub fn new(tap: &str) -> Result<Injector> {
        // Protocol 0: this socket sends and never receives.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            bail!("packet socket: {}", std::io::Error::last_os_error());
        }
        let mut header = [0u8; 14];
        header[..6].copy_from_slice(&crate::net::parse_mac(crate::net::GUEST_MAC)?);
        header[6..12].copy_from_slice(&crate::net::parse_mac(crate::net::GATEWAY_MAC)?);
        header[12..].copy_from_slice(&[0x08, 0x00]);
        Ok(Injector {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            tap: tap.into(),
            ifindex: crate::net::ifindex(tap)?,
            header,
            tx_dropped: tap_tx_dropped(tap),
        })
    }

    /// Queues one packet for the guest; false if the kernel refused it.
    pub fn send(&self, packet: &[u8]) -> bool {
        let mut frame = Vec::with_capacity(14 + packet.len());
        frame.extend_from_slice(&self.header);
        frame.extend_from_slice(packet);
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = self.ifindex as i32;
        addr.sll_protocol = 0x0800u16.to_be();
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&self.header[..6]);
        let rc = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                libc::MSG_DONTWAIT,
                (&addr as *const libc::sockaddr_ll).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        rc >= 0
    }

    /// Frames the tap dropped since this injector was made (its queue was
    /// full). Includes any the guest's own traffic lost meanwhile.
    pub fn dropped(&self) -> u64 {
        tap_tx_dropped(&self.tap).saturating_sub(self.tx_dropped)
    }
}

fn tap_tx_dropped(tap: &str) -> u64 {
    std::fs::read_to_string(format!("/sys/class/net/{tap}/statistics/tx_dropped"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

// The stream, on the migration connection right after the target's answer.
// The source opens it with `START`; the receiver answers `b'a'` and the
// sequence number it expects first (a u64, 0), and only then does the
// source take packets off its queue. Then frames: a big-endian u32 length,
// a u64 sequence number and that many bytes of IP packet. `SYNC` (no more)
// asks the receiver to answer `b's'` once it has injected everything
// before it; a missing or wrong answer breaks the stream. Length 0 ends
// it, and the receiver answers with one JSON line (`Received`). Sequence
// numbers let the receiver count what went missing and drop duplicates.
// Nothing is resent: what a broken stream loses is counted as dropped.
const SYNC: u32 = u32::MAX;
const START: u32 = u32::MAX - 1;
/// Receivers running at once, all migrations together.
const MAX_RECEIVERS: usize = 8;
static RECEIVERS: AtomicUsize = AtomicUsize::new(0);

/// What a target did with a stream of held packets.
#[derive(Debug, Default)]
pub struct Received {
    pub injected: u64,
    /// Not injected: malformed or not for the VM, duplicated, missing from
    /// the sequence, refused by the kernel, or lost to a full tap queue.
    pub dropped: u64,
    /// The stream ended properly (rather than timing out or breaking off).
    pub ended: bool,
    /// The next sequence number expected.
    pub next: u64,
}

/// Waits until `deadline` for a source to open a stream on `r` (`START`).
pub fn wait_start(r: &mut BufReader<TcpStream>, deadline: Instant) -> bool {
    let mut head = [0u8; 4];
    read_by(r, &mut head, deadline).is_ok() && u32::from_be_bytes(head) == START
}

/// Accepts a stream opened with `START` and injects its packets, all for
/// `ip`, into `tap` until it ends or `deadline` (enforced on every read and
/// write, partial frames included). Each injection happens under `revoked`
/// and only while it is false (the VM is still the one the stream is for).
/// Answers the source when the stream ends. None if too many streams are
/// being received already.
pub fn receive(r: &mut BufReader<TcpStream>, ip: Ipv4Addr, tap: &str, revoked: &Mutex<bool>, deadline: Instant) -> Option<Received> {
    let _slot = Receiver::enter()?;
    let mut got = Received::default();
    let Ok(inj) = Injector::new(tap) else { return Some(got) };
    let mut ack = vec![b'a'];
    ack.extend_from_slice(&0u64.to_be_bytes());
    if write_by(r.get_ref(), &ack, deadline).is_err() {
        return Some(got);
    }
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        let mut head = [0u8; 4];
        if read_by(r, &mut head, deadline).is_err() {
            break;
        }
        let len = u32::from_be_bytes(head);
        if len == SYNC {
            if write_by(r.get_ref(), b"s", deadline).is_err() {
                break;
            }
            continue;
        }
        let len = len as usize;
        if len == 0 {
            got.ended = true;
            break;
        }
        let mut seq = [0u8; 8];
        if len > MAX_FRAME || read_by(r, &mut seq, deadline).is_err() || read_by(r, &mut buf[..len], deadline).is_err() {
            break;
        }
        let seq = u64::from_be_bytes(seq);
        if seq < got.next {
            got.dropped += 1;
            continue;
        }
        got.dropped += seq - got.next;
        got.next = seq + 1;
        let sent = {
            let revoked = revoked.lock().unwrap();
            !*revoked && valid(&buf[..len], ip) && inj.send(&buf[..len])
        };
        if sent {
            got.injected += 1;
        } else {
            got.dropped += 1;
        }
    }
    got.dropped += inj.dropped();
    if got.ended {
        let reply = json!({"injected": got.injected, "dropped": got.dropped});
        let _ = write_by(r.get_ref(), format!("{reply}\n").as_bytes(), deadline);
    }
    Some(got)
}

/// An IPv4 packet, whole, for `ip`: all a guest is ever handed.
pub fn valid(p: &[u8], ip: Ipv4Addr) -> bool {
    let ihl = (p.first().copied().unwrap_or(0) & 15) as usize * 4;
    p.len() >= 20
        && p[0] >> 4 == 4
        && ihl >= 20
        && ihl <= p.len()
        && u16::from_be_bytes([p[2], p[3]]) as usize == p.len()
        && p[16..20] == ip.octets()
}

/// Counts running receivers, up to `MAX_RECEIVERS`.
struct Receiver;

impl Receiver {
    fn enter() -> Option<Receiver> {
        RECEIVERS
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < MAX_RECEIVERS).then_some(n + 1))
            .ok()
            .map(|_| Receiver)
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        RECEIVERS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Fills `buf` from `r`, giving up at `deadline` however the bytes trickle in.
fn read_by(r: &mut BufReader<TcpStream>, mut buf: &mut [u8], deadline: Instant) -> std::io::Result<()> {
    while !buf.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        r.get_ref().set_read_timeout(Some(left))?;
        match r.read(buf) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Writes all of `buf`, giving up at `deadline` however slowly it drains.
fn write_by(mut w: &TcpStream, mut buf: &[u8], deadline: Instant) -> std::io::Result<()> {
    while !buf.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        w.set_write_timeout(Some(left))?;
        match w.write(buf) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Opens a stream on `conn` (`START`) and waits for the receiver to accept
/// it. Returns the sequence number to start at (0).
pub fn start(conn: &TcpStream) -> Result<u64> {
    let deadline = Instant::now() + ACCEPT_WAIT;
    write_by(conn, &START.to_be_bytes(), deadline)?;
    let mut ack = [0u8; 9];
    let mut r = BufReader::with_capacity(9, conn.try_clone()?);
    read_by(&mut r, &mut ack, deadline)?;
    if ack[0] != b'a' {
        bail!("the target refused the held packets");
    }
    Ok(u64::from_be_bytes(ack[1..].try_into().unwrap()))
}

/// Streams what migration `mig` held for `ip` to a target over `conn`,
/// after `start` (numbering from `seq`), and reads back what the target did
/// with it. Before `switch` moves the route (and with it newer packets) to
/// the target, it waits, up to `CATCH_UP` per round, until the target has
/// injected everything sent so far (`SYNC`), so those come first.
pub fn send(holder: &Holder, ip: Ipv4Addr, mig: u64, conn: &TcpStream, seq: u64, switch: impl FnOnce() -> Result<()>) -> Option<(Stats, Result<()>)> {
    let out = std::cell::RefCell::new(Out { buf: Vec::with_capacity(64 << 10), seq, broken: false, conn });
    let mut sink = |p: &[u8]| out.borrow_mut().frame(p);
    // Exactly one `s` per sync, in time, or the stream counts as broken.
    let mut barrier = || {
        let mut o = out.borrow_mut();
        o.buf.extend_from_slice(&SYNC.to_be_bytes());
        let mut ack = [0u8; 1];
        // One deadline for sending the sync and reading its answer.
        let deadline = Instant::now() + SYNC_WAIT;
        let ok = o.flush(deadline) && conn.try_clone().is_ok_and(|c| read_by(&mut BufReader::with_capacity(1, c), &mut ack, deadline).is_ok()) && ack[0] == b's';
        if !ok {
            o.broken = true;
            eprintln!("hold {ip}: the target did not confirm the held packets; dropping the rest");
        }
        ok
    };
    let (mut stats, switched) = holder.release(ip, mig, &mut sink, &mut barrier, switch)?;
    let mut o = out.into_inner();
    o.buf.extend_from_slice(&0u32.to_be_bytes());
    let reply = o.flush(Instant::now() + FLUSH_WAIT).then(|| read_reply(conn, Instant::now() + REPLY_WAIT)).flatten();
    match reply {
        Some(r) => {
            stats.injected = r["injected"].as_u64().unwrap_or(0);
            stats.dropped_target = r["dropped"].as_u64().unwrap_or(0);
        }
        // Whatever was sent is unaccounted for: count it lost.
        None => stats.dropped_target = stats.packets,
    }
    Some((stats, switched))
}

/// The receiver's closing JSON line: at most 256 bytes, by `deadline`.
fn read_reply(conn: &TcpStream, deadline: Instant) -> Option<Value> {
    let mut r = BufReader::with_capacity(1, conn.try_clone().ok()?);
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while line.len() < 256 {
        read_by(&mut r, &mut b, deadline).ok()?;
        if b[0] == b'\n' {
            return serde_json::from_slice(&line).ok();
        }
        line.push(b[0]);
    }
    None
}

/// The sending end of a held-packet stream, buffered.
struct Out<'a> {
    buf: Vec<u8>,
    seq: u64,
    broken: bool,
    conn: &'a TcpStream,
}

impl Out<'_> {
    fn frame(&mut self, p: &[u8]) -> bool {
        if self.broken {
            return false;
        }
        self.buf.extend_from_slice(&(p.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(&self.seq.to_be_bytes());
        self.buf.extend_from_slice(p);
        self.seq += 1;
        self.buf.len() < 48 << 10 || self.flush(Instant::now() + FLUSH_WAIT)
    }

    /// Sends what is buffered by `deadline`, or marks the stream broken.
    fn flush(&mut self, deadline: Instant) -> bool {
        if !self.broken {
            self.broken = write_by(self.conn, &self.buf, deadline).is_err();
        }
        self.buf.clear();
        !self.broken
    }
}

fn readable(fd: &OwnedFd) -> bool {
    let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut pfd, 1, 0) > 0 }
}

enum Tun {
    /// Another process has the device.
    Busy(crate::util::Error),
    Unsupported(crate::util::Error),
}

/// Opens TUN device `dev`. TUNSETIFF fails (busy) if another process has it.
fn open_tun(dev: &str) -> std::result::Result<OwnedFd, Tun> {
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if fd < 0 {
        return Err(Tun::Unsupported(format!("/dev/net/tun: {}", std::io::Error::last_os_error()).into()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, s) in req.ifr_name.iter_mut().zip(dev.bytes().take(libc::IFNAMSIZ - 1)) {
        *d = s as libc::c_char;
    }
    req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &req) } < 0 {
        let e = std::io::Error::last_os_error();
        let msg = format!("{dev}: {e}");
        return Err(match e.raw_os_error() {
            Some(libc::EBUSY | libc::EEXIST | libc::EPERM) => Tun::Busy(format!("{msg} (another daemon on this port?)").into()),
            _ => Tun::Unsupported(msg.into()),
        });
    }
    // Room for what arrives while a release is catching up (the default is 500).
    req.ifr_ifru.ifru_metric = 10000;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock >= 0 {
        unsafe {
            libc::ioctl(sock, libc::SIOCSIFTXQLEN as _, &req);
            libc::close(sock);
        }
    }
    Ok(fd)
}

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;

/// Adds or deletes the main-table route of `ip` through the TUN device
/// (`ifindex`). A delete names the device, so it removes only that route.
fn tun_route(kind: u16, flags: u16, ip: Ipv4Addr, ifindex: u32) -> Result<()> {
    // struct rtmsg: family, dst_len, src_len, tos, table (main), protocol
    // (static), scope (link), type (unicast); flags
    let mut m = vec![libc::AF_INET as u8, 32, 0, 0, 254, 4, 253, 1, 0, 0, 0, 0];
    for (kind, data) in [(1u16, &ip.octets()[..]), (4, &ifindex.to_ne_bytes()[..])] {
        m.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        m.extend_from_slice(&kind.to_ne_bytes());
        m.extend_from_slice(data);
    }
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
    if fd < 0 {
        bail!("netlink socket: {}", std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut msg = Vec::with_capacity(16 + m.len());
    msg.extend_from_slice(&((16 + m.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    msg.extend_from_slice(&m);
    let mut ack = [0u8; 256];
    let n = unsafe {
        if libc::send(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) < 0 {
            -1
        } else {
            libc::recv(fd.as_raw_fd(), ack.as_mut_ptr().cast(), ack.len(), 0)
        }
    };
    if n < 20 {
        bail!("netlink: {}", std::io::Error::last_os_error());
    }
    let code = i32::from_ne_bytes(ack[16..20].try_into().unwrap());
    if u16::from_ne_bytes([ack[4], ack[5]]) == 2 && code != 0 {
        bail!("route {ip} through the hold device: {}", std::io::Error::from_raw_os_error(-code));
    }
    Ok(())
}
