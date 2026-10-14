//! Holds packets for a paused VM and delivers them once it runs again, instead of letting
//! them hit a downed tap (TCP peers would wait out a retransmit timeout).
//!
//! `hold` routes the VM's /32 to this process's TUN device; `release` hands the queue to a
//! sink and switches the route. A migration streams them to the target (`send`), which
//! injects them out of the VM's tap and announces the VM only after, so they come first.

use std::collections::{HashMap, VecDeque};
use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::util::{eintr, By, Result};

/// Bytes held per address; packets beyond it are dropped.
pub const CAP: usize = 4 << 20;
/// Per round of `release`; past it (a flood faster than the sink) packets are dropped.
const CATCH_UP: Duration = Duration::from_millis(100);
const MAX_FRAME: usize = 65535;
/// Packets read off the device at a time before what was read is handed over.
const PASS: usize = 256;
/// The hold device's queue length (`open_tun`).
const TXQ: usize = 10000;
const ACCEPT_WAIT: Duration = Duration::from_secs(1);
const SYNC_WAIT: Duration = Duration::from_millis(250);
/// For the target to take the address over: a route change, which waits for RTNL. The
/// address stays held here meanwhile, so waiting loses nothing.
const SWITCH_WAIT: Duration = Duration::from_secs(2);
const FLUSH_WAIT: Duration = Duration::from_millis(400);
const REPLY_WAIT: Duration = Duration::from_secs(1);

/// Where `release_local` hands packets, from more than one thread.
pub type LocalSink<'a> = &'a mut (dyn FnMut(&[u8]) -> bool + Send);

pub struct Holder {
    dev: String,
    ifindex: u32,
    tun: OwnedFd,
    /// Lookups and inserts only: no I/O under it.
    held: Mutex<HashMap<Ipv4Addr, Arc<Entry>>>,
    /// The reader has packets in hand not queued yet.
    reading: AtomicBool,
    /// Times the reader emptied the device: once it moves on, what was there is queued.
    passes: AtomicU64,
    /// Held while an address's TUN route is added or deleted.
    routes: Mutex<()>,
    /// Held while a packet is read off the device and queued.
    rx: Mutex<()>,
}

struct Entry {
    mig: u64,
    q: Mutex<Queue>,
}

#[derive(Default)]
struct Queue {
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
    releasing: bool,
    dropped: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    /// Handed to the sink.
    pub packets: u64,
    pub bytes: u64,
    pub dropped: u64,
    pub injected: u64,
    pub dropped_target: u64,
}

impl Stats {
    pub fn json(&self) -> Value {
        json!({"packets": self.packets, "kib": self.bytes >> 10, "dropped": self.dropped, "injected": self.injected, "dropped_target": self.dropped_target})
    }

    fn give(&mut self, sink: &mut dyn FnMut(&[u8]) -> bool, p: &[u8]) {
        match sink(p) {
            true => (self.packets, self.bytes) = (self.packets + 1, self.bytes + p.len() as u64),
            false => self.dropped += 1,
        }
    }
}

impl Holder {
    /// None, with a warning, without TUN support: then nothing is held.
    pub fn new(dev: &str) -> Result<Option<Arc<Holder>>> {
        let dev = dev.to_string();
        let tun = match open_tun(&dev) {
            Ok(tun) => tun,
            Err((true, e)) => return Err(e),
            Err((false, e)) => {
                eprintln!("packets in flight during migrations will be dropped: {e}");
                return Ok(None);
            }
        };
        let _ = crate::net::sysctl(&format!("net.ipv6.conf.{dev}.disable_ipv6"), "1");
        crate::net::set_link_up(&dev, true)?;
        let ifindex = crate::net::ifindex(&dev)?;
        let h = Arc::new(Holder { dev, ifindex, tun, held: Mutex::default(), reading: AtomicBool::new(false), passes: AtomicU64::new(0), routes: Mutex::new(()), rx: Mutex::new(()) });
        let reader = h.clone();
        std::thread::Builder::new().name("hold".into()).spawn(move || reader.read_loop())?;
        Ok(Some(h))
    }

    pub fn hold(&self, ip: Ipv4Addr, mig: u64) -> Result<()> {
        let _routes = self.routes.lock().unwrap();
        self.held.lock().unwrap().insert(ip, Arc::new(Entry { mig, q: Mutex::default() }));
        crate::net::route_dev(true, ip, self.ifindex).inspect_err(|_| drop(self.held.lock().unwrap().remove(&ip)))
    }

    pub fn holding_for(&self, ip: Ipv4Addr, mig: u64) -> bool {
        self.entry(ip).is_some_and(|e| e.mig == mig && !e.q.lock().unwrap().releasing)
    }

    fn entry(&self, ip: Ipv4Addr) -> Option<Arc<Entry>> {
        self.held.lock().unwrap().get(&ip).cloned()
    }

    /// None if not held or already being released.
    fn releasing(&self, ip: Ipv4Addr, mig: u64) -> Option<Arc<Entry>> {
        let e = self.entry(ip).filter(|e| e.mig == mig)?;
        let first = !std::mem::replace(&mut e.q.lock().unwrap().releasing, true);
        first.then_some(e)
    }

    /// Unless a newer hold replaced it.
    fn unhold(&self, ip: Ipv4Addr, e: &Arc<Entry>) {
        let mut held = self.held.lock().unwrap();
        if held.get(&ip).is_some_and(|x| Arc::ptr_eq(x, e)) {
            held.remove(&ip);
        }
    }

    /// Hands the queue to `sink` then `barrier`s (far end catching up), up to four rounds, then
    /// `switch`es and hands over the rest. `barrier` false: far end lost, but the route switches.
    pub fn release(
        &self,
        ip: Ipv4Addr,
        mig: u64,
        sink: &mut dyn FnMut(&[u8]) -> bool,
        barrier: &mut dyn FnMut() -> bool,
        switch: impl FnOnce() -> Result<()>,
    ) -> Option<(Stats, Result<()>)> {
        let e = self.releasing(ip, mig)?;
        let mut stats = Stats::default();
        let mut lost = false;
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
        match switched {
            Ok(()) => self.unhold(ip, &e),
            // Left to the TUN, the address would be dropped here until the caller's retry.
            Err(_) => self.unroute(ip, &e),
        }
        stats.dropped += e.q.lock().unwrap().discard();
        Some((stats, switched))
    }

    /// `release` into a VM here. `switch` (a route change) may wait long, for RTNL: a helper
    /// thread hands over what arrives meanwhile. Once it is done, what the device took before
    /// it is read off it right away (not waiting for the reader thread, which a busy host may
    /// not run for a while), so the packets routed to the VM from then on have as little as
    /// possible to overtake, and handed over a pass at a time, so a backlog is delivered
    /// rather than dropped at `CAP`. Nothing held is dropped for taking long, and traffic that
    /// keeps arriving never holds the switch up: each hand-over takes only what was queued when
    /// it began, and reading after the switch stops at the device's queue length. With
    /// `linger`, the device is then watched that long more for a packet from a sender that
    /// looked the old route up just before the switch. If `switch` fails the address stays
    /// held until `forget`.
    pub fn release_local(
        &self,
        ip: Ipv4Addr,
        mig: u64,
        sink: LocalSink,
        switch: impl FnOnce() -> Result<()>,
        linger: Duration,
    ) -> Option<(Stats, Result<()>)> {
        let e = self.releasing(ip, mig)?;
        let out = Mutex::new((sink, Stats::default()));
        let give = |o: &mut (LocalSink, Stats)| self.give_queued(&e, &mut *o.0, &mut o.1);
        give(&mut out.lock().unwrap());
        let switching = AtomicBool::new(true);
        let mut buf = vec![0u8; MAX_FRAME];
        let switched = std::thread::scope(|sc| {
            sc.spawn(|| {
                while switching.load(Ordering::SeqCst) {
                    if !give(&mut out.lock().unwrap()) {
                        std::thread::sleep(Duration::from_micros(200));
                    }
                }
            });
            let switched = switch();
            // Right away, here: the helper may be asleep, or not running at all.
            let mut o = out.lock().unwrap();
            if switched.is_ok() {
                // Nothing reaches the device for this address any more.
                let mut read = 0;
                loop {
                    let n = (0..PASS).take_while(|_| self.read_one(&mut buf)).count();
                    give(&mut o);
                    read += n;
                    if n < PASS || read >= TXQ {
                        break;
                    }
                }
            }
            switching.store(false, Ordering::SeqCst);
            switched
        });
        let mut o = out.into_inner().unwrap();
        if switched.is_ok() {
            let end = Instant::now() + linger;
            while Instant::now() < end {
                let mut pfd = libc::pollfd { fd: self.tun.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                let wait = end.saturating_duration_since(Instant::now()).as_millis().max(1) as i32;
                if unsafe { libc::poll(&mut pfd, 1, wait) } > 0 {
                    (0..PASS).take_while(|_| self.read_one(&mut buf)).count();
                }
                give(&mut o);
            }
        }
        give(&mut o);
        let mut stats = o.1;
        if switched.is_ok() {
            self.unhold(ip, &e);
        }
        let mut q = e.q.lock().unwrap();
        stats.dropped += match switched {
            Ok(()) => q.discard(),
            Err(_) => std::mem::take(&mut q.dropped),
        };
        Some((stats, switched))
    }

    /// Hands over what is queued now, not what arrives meanwhile; false if there was none.
    fn give_queued(&self, e: &Entry, sink: &mut dyn FnMut(&[u8]) -> bool, stats: &mut Stats) -> bool {
        let mut left = e.q.lock().unwrap().packets.len();
        let any = left > 0;
        while left > 0 {
            let batch = e.q.lock().unwrap().take_batch();
            if batch.is_empty() {
                break;
            }
            left = left.saturating_sub(batch.len());
            batch.iter().for_each(|p| stats.give(sink, p));
        }
        any
    }

    fn hand_over(&self, e: &Entry, sink: &mut dyn FnMut(&[u8]) -> bool, stats: &mut Stats) {
        let end = Instant::now() + CATCH_UP;
        while Instant::now() < end {
            let batch = e.q.lock().unwrap().take_batch();
            if batch.is_empty() {
                if !self.reading.load(Ordering::SeqCst) && !readable(&self.tun) {
                    return;
                }
                std::thread::yield_now();
                continue;
            }
            let mut rest = batch.iter();
            for p in rest.by_ref() {
                stats.give(sink, p);
                if Instant::now() >= end {
                    break;
                }
            }
            stats.dropped += rest.len() as u64;
        }
    }

    pub fn forget(&self, ip: Ipv4Addr, mig: u64) -> Stats {
        let Some(e) = self.entry(ip).filter(|e| e.mig == mig) else { return Stats::default() };
        self.unroute(ip, &e);
        let dropped = e.q.lock().unwrap().discard();
        Stats { dropped, ..Stats::default() }
    }

    /// Drops `e` and its TUN route, unless a newer hold replaced it.
    fn unroute(&self, ip: Ipv4Addr, e: &Arc<Entry>) {
        // Under `routes`: a newer hold of `ip` never loses its route to this one.
        let _routes = self.routes.lock().unwrap();
        if self.entry(ip).is_some_and(|x| Arc::ptr_eq(&x, e)) {
            self.unhold(ip, e);
            let _ = crate::net::route_dev(false, ip, self.ifindex);
        }
    }

    fn read_loop(&self) {
        let mut pfd = libc::pollfd { fd: self.tun.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let mut buf = vec![0u8; 65536];
        loop {
            if let Err(e) = eintr(|| unsafe { libc::poll(&mut pfd, 1, -1) }) {
                return eprintln!("hold device {}: {e}", self.dev);
            }
            self.reading.store(true, Ordering::SeqCst);
            while self.read_one(&mut buf) {}
            self.passes.fetch_add(1, Ordering::SeqCst);
            self.reading.store(false, Ordering::SeqCst);
        }
    }

    /// Reads a packet off the device and queues it for its address; false once it is empty.
    /// Read and queued under `rx`, so packets are queued in the order they were read, by
    /// whichever thread.
    fn read_one(&self, buf: &mut [u8]) -> bool {
        let _rx = self.rx.lock().unwrap();
        let Ok(n) = eintr(|| unsafe { libc::read(self.tun.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) }) else { return false };
        let p = &buf[..n as usize];
        if p.len() < 20 || p[0] >> 4 != 4 {
            return true;
        }
        if let Some(e) = self.entry(Ipv4Addr::new(p[16], p[17], p[18], p[19])) {
            let mut q = e.q.lock().unwrap();
            if q.bytes + p.len() > CAP {
                q.dropped += 1;
            } else {
                q.bytes += p.len();
                q.packets.push_back(p.to_vec());
            }
        }
        true
    }
}

impl Queue {
    fn take_batch(&mut self) -> Vec<Vec<u8>> {
        let batch: Vec<_> = self.packets.drain(..self.packets.len().min(256)).collect();
        self.bytes -= batch.iter().map(Vec::len).sum::<usize>();
        batch
    }

    /// Empties it, counting what is thrown away as dropped.
    fn discard(&mut self) -> u64 {
        let n = std::mem::take(&mut self.dropped) + self.packets.len() as u64;
        (self.packets, self.bytes) = Default::default();
        n
    }
}

/// Sends IP packets to a guest as Ethernet frames out of its tap, as Firecracker would.
pub struct Injector {
    fd: OwnedFd,
    tap: String,
    ifindex: u32,
    header: [u8; 14],
    tx_dropped: u64,
}

impl Injector {
    pub fn new(tap: &str) -> Result<Injector> {
        // Protocol 0: it sends and never receives.
        let fd = eintr(|| unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) }).map_err(|e| format!("packet socket: {e}"))?;
        let mut header = [0u8; 14];
        header[..6].copy_from_slice(&crate::net::parse_mac(crate::net::GUEST_MAC)?);
        header[6..12].copy_from_slice(&crate::net::parse_mac(crate::net::GATEWAY_MAC)?);
        header[12..].copy_from_slice(&[0x08, 0x00]);
        Ok(Injector { fd: unsafe { OwnedFd::from_raw_fd(fd) }, tap: tap.into(), ifindex: crate::net::ifindex(tap)?, header, tx_dropped: tap_tx_dropped(tap) })
    }

    pub fn send(&self, packet: &[u8]) -> bool {
        let frame = [&self.header[..], packet].concat();
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = self.ifindex as i32;
        addr.sll_protocol = 0x0800u16.to_be();
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&self.header[..6]);
        let size = std::mem::size_of::<libc::sockaddr_ll>() as u32;
        unsafe { libc::sendto(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len(), libc::MSG_DONTWAIT, (&addr as *const libc::sockaddr_ll).cast(), size) >= 0 }
    }

    /// Includes the guest's own traffic.
    pub fn dropped(&self) -> u64 {
        tap_tx_dropped(&self.tap).saturating_sub(self.tx_dropped)
    }
}

fn tap_tx_dropped(tap: &str) -> u64 {
    std::fs::read_to_string(format!("/sys/class/net/{tap}/statistics/tx_dropped")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

// Stream: `START`, answered `b'a'` + first expected seq (u64). Frames: u32 BE length, u64
// seq, packet. `SYNC` gets `b's'` once all before it is injected. `SWITCH` (hosts sharing
// routes) gets `b'w'` once all before it is injected and the target took the address over.
// Length 0 ends it and gets one JSON line. Nothing is resent.
const SYNC: u32 = u32::MAX;
const START: u32 = u32::MAX - 1;
const SWITCH: u32 = u32::MAX - 2;
const MAX_RECEIVERS: usize = 8;
static RECEIVERS: AtomicUsize = AtomicUsize::new(0);

fn read_by(r: &mut BufReader<By<TcpStream>>, buf: &mut [u8], deadline: Instant) -> std::io::Result<()> {
    r.get_mut().at = deadline;
    r.read_exact(buf)
}

fn write_by(w: &TcpStream, buf: &[u8], deadline: Instant) -> std::io::Result<()> {
    By { s: w, at: deadline }.write_all(buf)
}

pub fn wait_start(r: &mut BufReader<By<TcpStream>>, deadline: Instant) -> bool {
    let mut head = [0u8; 4];
    read_by(r, &mut head, deadline).is_ok() && u32::from_be_bytes(head) == START
}

/// Injects only while `revoked` is false; on `SWITCH`, `take_over` takes the address. Refused if
/// too many streams are being received.
pub fn receive(r: &mut BufReader<By<TcpStream>>, ip: Ipv4Addr, tap: &str, revoked: &Mutex<bool>, deadline: Instant, take_over: &mut dyn FnMut()) {
    if RECEIVERS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < MAX_RECEIVERS).then_some(n + 1)).is_ok() {
        receive_counted(r, ip, tap, revoked, deadline, take_over);
        RECEIVERS.fetch_sub(1, Ordering::SeqCst);
    }
}

fn receive_counted(r: &mut BufReader<By<TcpStream>>, ip: Ipv4Addr, tap: &str, revoked: &Mutex<bool>, deadline: Instant, take_over: &mut dyn FnMut()) {
    let (Ok(conn), Ok(inj)) = (r.get_ref().s.try_clone(), Injector::new(tap)) else { return };
    if write_by(&conn, &[&b"a"[..], &0u64.to_be_bytes()].concat(), deadline).is_err() {
        return;
    }
    let (mut buf, mut next, mut injected, mut dropped) = (vec![0u8; MAX_FRAME], 0, 0, 0);
    let ended = loop {
        let mut head = [0u8; 4];
        if read_by(r, &mut head, deadline).is_err() {
            break false;
        }
        let len = match u32::from_be_bytes(head) {
            SYNC if write_by(&conn, b"s", deadline).is_ok() => continue,
            SYNC => break false,
            SWITCH => {
                // What was injected before is queued on the tap ahead of anything routed.
                take_over();
                match write_by(&conn, b"w", deadline) {
                    Ok(()) => continue,
                    Err(_) => break false,
                }
            }
            0 => break true,
            len => len as usize,
        };
        let mut seq = [0u8; 8];
        if len > MAX_FRAME || read_by(r, &mut seq, deadline).is_err() || read_by(r, &mut buf[..len], deadline).is_err() {
            break false;
        }
        let seq = u64::from_be_bytes(seq);
        if seq < next {
            dropped += 1;
            continue;
        }
        dropped += seq - next;
        next = seq + 1;
        match !*revoked.lock().unwrap() && valid(&buf[..len], ip) && inj.send(&buf[..len]) {
            true => injected += 1,
            false => dropped += 1,
        }
    };
    if ended {
        let reply = json!({"injected": injected, "dropped": dropped + inj.dropped()});
        let _ = write_by(&conn, format!("{reply}\n").as_bytes(), deadline);
    }
}

/// A whole IPv4 packet for `ip`: all a guest is ever handed.
pub fn valid(p: &[u8], ip: Ipv4Addr) -> bool {
    let ihl = (p.first().copied().unwrap_or(0) & 15) as usize * 4;
    p.len() >= 20 && p[0] >> 4 == 4 && ihl >= 20 && ihl <= p.len() && u16::from_be_bytes([p[2], p[3]]) as usize == p.len() && p[16..20] == ip.octets()
}

pub fn start(conn: &TcpStream) -> Result<u64> {
    let deadline = Instant::now() + ACCEPT_WAIT;
    write_by(conn, &START.to_be_bytes(), deadline)?;
    let mut ack = [0u8; 9];
    By { s: conn, at: deadline }.read_exact(&mut ack)?;
    if ack[0] != b'a' {
        bail!("the target refused the held packets");
    }
    Ok(u64::from_be_bytes(ack[1..].try_into().unwrap()))
}

/// Before `switch` moves the route, `SYNC`s until the target injected all sent so far. With
/// `handoff` (hosts sharing routes) the target routes the address itself, after those.
pub fn send(
    holder: &Holder,
    ip: Ipv4Addr,
    mig: u64,
    conn: &TcpStream,
    seq: u64,
    handoff: bool,
    switch: impl FnOnce() -> Result<()>,
) -> Option<(Stats, Result<()>)> {
    let out = std::cell::RefCell::new(Out { buf: Vec::with_capacity(64 << 10), seq, broken: false, conn });
    let mut sink = |p: &[u8]| out.borrow_mut().frame(p);
    let mut barrier = || {
        let mut o = out.borrow_mut();
        o.buf.extend_from_slice(&SYNC.to_be_bytes());
        let (mut ack, deadline) = ([0u8; 1], Instant::now() + SYNC_WAIT);
        let ok = o.flush(deadline) && By { s: conn, at: deadline }.read_exact(&mut ack).is_ok() && ack[0] == b's';
        if !ok {
            o.broken = true;
            eprintln!("hold {ip}: the target did not confirm the held packets; dropping the rest");
        }
        ok
    };
    // A handoff moves the route on the target; `switch` runs after the stragglers went, as
    // until they are injected, packets routed to the target overtake them.
    let mut switch = Some(switch);
    let handover = || match handoff {
        true => {
            let mut o = out.borrow_mut();
            o.buf.extend_from_slice(&SWITCH.to_be_bytes());
            let (mut ack, deadline) = ([0u8; 1], Instant::now() + SWITCH_WAIT);
            if !(o.flush(deadline) && By { s: conn, at: deadline }.read_exact(&mut ack).is_ok() && ack[0] == b'w') {
                o.broken = true;
                eprintln!("hold {ip}: the target did not take the address over; dropping the rest");
                bail!("the target did not take {ip} over (its held packets after this are lost)");
            }
            Ok(())
        }
        false => switch.take().map_or(Ok(()), |f| f()),
    };
    let (mut stats, switched) = holder.release(ip, mig, &mut sink, &mut barrier, handover)?;
    let mut o = out.into_inner();
    o.buf.extend_from_slice(&0u32.to_be_bytes());
    match o.flush(Instant::now() + FLUSH_WAIT).then(|| read_reply(conn, Instant::now() + REPLY_WAIT)).flatten() {
        Some(r) => (stats.injected, stats.dropped_target) = (r["injected"].as_u64().unwrap_or(0), r["dropped"].as_u64().unwrap_or(0)),
        None => stats.dropped_target = stats.packets,
    }
    let switched = switched.and_then(|()| switch.take().map_or(Ok(()), |f| f()));
    Some((stats, switched))
}

/// A byte at a time: nothing after the line is consumed.
fn read_reply(conn: &TcpStream, deadline: Instant) -> Option<Value> {
    crate::util::recv_json_max(&mut BufReader::with_capacity(1, By { s: conn, at: deadline }), 257).ok().flatten()
}

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

/// The error flag: another process has it (rather than no TUN support).
fn open_tun(dev: &str) -> std::result::Result<OwnedFd, (bool, crate::util::Error)> {
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    let fd = eintr(|| unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK) })
        .map_err(|e| (false, format!("/dev/net/tun: {e}").into()))?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, s) in req.ifr_name.iter_mut().zip(dev.bytes().take(libc::IFNAMSIZ - 1)) {
        *d = s as libc::c_char;
    }
    req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    if let Err(e) = eintr(|| unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &req) }) {
        let busy = matches!(e.raw_os_error(), Some(libc::EBUSY | libc::EEXIST | libc::EPERM));
        return Err((busy, format!("{dev}: {e}{}", if busy { " (another process has it)" } else { "" }).into()));
    }
    // Room for what arrives while a release catches up (default 500).
    req.ifr_ifru.ifru_metric = TXQ as i32;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock >= 0 {
        unsafe {
            libc::ioctl(sock, libc::SIOCSIFTXQLEN as _, &req);
            libc::close(sock);
        }
    }
    Ok(fd)
}
