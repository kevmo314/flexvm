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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::util::{eintr, By, Result, Slot};

/// Bytes held per address; packets beyond it are dropped.
pub const CAP: usize = 4 << 20;
/// Per round of `release`; past it (a flood faster than the sink) packets are dropped.
const CATCH_UP: Duration = Duration::from_millis(100);
const MAX_FRAME: usize = 65535;
/// The least `gso_size` a TSO frame is cut by (TCP_MIN_MSS): a smaller one would make many
/// times its size in segments.
const MIN_MSS: usize = 88;
/// The hold device's virtio-net header (`open_tun`): struct virtio_net_hdr.
const VNET_HDR: usize = 10;
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
/// How long a let-go address's stragglers (`Holder::gone`) are re-sent or counted.
const GONE_FOR: Duration = Duration::from_secs(30);
/// Stragglers are logged at most this often per address after the first report.
const STRAGGLER_LOG: Duration = Duration::from_secs(1);

/// Where frames read off a tap go, one at a time (`Holder::hold_first`).
pub type Each<'a> = &'a mut dyn FnMut(&[u8]);

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
    /// Held while an address's TUN route is added or deleted.
    routes: Mutex<()>,
    /// Held while a packet is read off the device and queued.
    rx: Mutex<()>,
    /// Addresses let go of. A sender that looked the route up before the switch can still
    /// hand a packet to this device after the release took the last one off it (a stalled
    /// vCPU, preemption between the lookup and the transmit): with no entry it would be lost,
    /// uncounted (#254). It is re-sent (`resend`), routed to where the address is now, or
    /// counted as dropped (`Holder::straggler`).
    gone: Mutex<HashMap<Ipv4Addr, Gone>>,
    /// A raw socket (IPPROTO_RAW: the packet's own header) the kernel routes re-sent packets by.
    resend: Option<OwnedFd>,
}

#[derive(Clone, Copy)]
struct Gone {
    at: Instant,
    /// The route moved on (a switched release), not dropped: stragglers are re-sent.
    moved: bool,
    /// Not reported yet (`report_stragglers`): re-sent, dropped.
    resent: u64,
    dropped: u64,
    reported: Option<Instant>,
}

impl Gone {
    fn new(moved: bool) -> Gone {
        Gone { at: Instant::now(), moved, resent: 0, dropped: 0, reported: None }
    }
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
    /// Routed away from the device: what is still on it is bounded by the device's queue, and
    /// queued whatever `CAP` says, to be handed over.
    switched: bool,
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
                crate::log!("packets in flight during migrations will be dropped: {e}");
                return Ok(None);
            }
        };
        let _ = crate::net::conf("ipv6", &dev, "disable_ipv6", "1");
        crate::net::set_link_up(&dev, true)?;
        let ifindex = crate::net::ifindex(&dev)?;
        let resend = match unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_RAW) } {
            fd if fd >= 0 => Some(unsafe { OwnedFd::from_raw_fd(fd) }),
            _ => {
                crate::log!("hold device {dev}: no raw socket ({}); packets reaching it after a release are dropped", std::io::Error::last_os_error());
                None
            }
        };
        let h = Arc::new(Holder {
            dev,
            ifindex,
            tun,
            held: Mutex::default(),
            reading: AtomicBool::new(false),
            routes: Mutex::new(()),
            rx: Mutex::new(()),
            gone: Mutex::default(),
            resend,
        });
        let reader = h.clone();
        std::thread::Builder::new().name("hold".into()).spawn(move || reader.read_loop())?;
        Ok(Some(h))
    }

    pub fn hold(&self, ip: Ipv4Addr, mig: u64) -> Result<()> {
        let (pending, routed) = {
            let _routes = self.routes.lock().unwrap();
            self.held.lock().unwrap().insert(ip, Arc::new(Entry { mig, q: Mutex::default() }));
            let routed = crate::net::route_dev(true, ip, self.ifindex);
            let pending = match &routed {
                Ok(()) => self.gone.lock().unwrap().remove(&ip),
                // Not held after all: its stragglers are still counted.
                Err(_) => {
                    self.discard_hold(ip);
                    None
                }
            };
            (pending, routed)
        };
        // Off the locks: a blocked stderr holds up no route change or reader.
        if let Some(g) = pending {
            report(ip, &self.dev, &g);
        }
        routed
    }

    /// Under `routes`; `rx` keeps the reader from queuing after removal.
    fn discard_hold(&self, ip: Ipv4Addr) {
        let _rx = self.rx.lock().unwrap();
        if let Some(e) = self.held.lock().unwrap().remove(&ip) {
            let dropped = e.q.lock().unwrap().discard();
            if dropped > 0 {
                let mut gone = self.gone.lock().unwrap();
                gone.entry(ip).or_insert(Gone::new(false)).dropped += dropped;
            }
        }
    }

    /// The IPv4 packets in the frames `take` hands over, oldest first (`from_tap`, within `CAP`
    /// with what is held; the rest counted as dropped), go ahead of what is held for `ip`: routed
    /// to the VM's tap before the hold, they reached it too late for its guest to take before
    /// the pause (#379). Each frame is cut as it comes, so a backlog is never all in memory.
    pub fn hold_first(&self, ip: Ipv4Addr, mig: u64, take: impl FnOnce(Each)) {
        let Some(e) = self.entry(ip).filter(|e| e.mig == mig) else { return };
        let mut q = e.q.lock().unwrap();
        let mut first = Vec::new();
        take(&mut |f| match from_tap(f, CAP.saturating_sub(q.bytes)) {
            Some(Ok(packets)) => {
                q.bytes += packets.iter().map(Vec::len).sum::<usize>();
                first.extend(packets);
            }
            Some(Err(n)) => q.dropped += n,
            None => q.dropped += 1,
        });
        first.into_iter().rev().for_each(|p| q.packets.push_front(p));
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

    /// Unless a newer hold replaced it. `moved`: the address is routed elsewhere now, where
    /// stragglers that still reach the device are re-sent.
    fn unhold(&self, ip: Ipv4Addr, e: &Arc<Entry>, moved: bool) {
        // Under `rx`: no read is between finding `e` and queuing on it, so nothing reaches its
        // queue once it is gone from `held` (what is there is then counted or handed over).
        let _rx = self.rx.lock().unwrap();
        let mut held = self.held.lock().unwrap();
        if held.get(&ip).is_some_and(|x| Arc::ptr_eq(x, e)) {
            held.remove(&ip);
            let mut gone = self.gone.lock().unwrap();
            gone.retain(|_, g| g.at.elapsed() < GONE_FOR || g.resent + g.dropped > 0);
            gone.insert(ip, Gone::new(moved));
        }
    }

    /// Hands the queue to `sink` then `barrier`s (far end catching up), up to four rounds, then
    /// `switch`es and hands over the rest. `barrier` false: far end lost, but the route switches.
    /// `refused` (set by a failed `switch`): the far end routes the address itself once it has
    /// all, so the route here stays until then, what reaches it counted as dropped, never
    /// removed (the address would go nowhere meanwhile) nor re-sent (it would come back).
    pub fn release(
        &self,
        ip: Ipv4Addr,
        mig: u64,
        sink: &mut dyn FnMut(&[u8]) -> bool,
        barrier: &mut dyn FnMut() -> bool,
        switch: impl FnOnce() -> Result<()>,
        refused: &std::cell::Cell<bool>,
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
            if e.q.lock().unwrap().packets.len() < 16 && !crate::util::readable(&self.tun, Duration::ZERO).unwrap_or(false) {
                break;
            }
        }
        let switched = switch();
        match (lost, &switched) {
            (true, _) => {}
            (false, Ok(())) => self.drain_switched(&e, &mut || {
                self.give_queued(&e, sink, &mut stats);
            }),
            (false, Err(_)) => {
                self.hand_over(&e, sink, &mut stats);
                // What the device took meanwhile, read here rather than left to the reader
                // (which a busy host may not run for a while): read after `unhold`, it would be a
                // straggler, counted as dropped (#539).
                if refused.get() {
                    let mut buf = vec![0u8; VNET_HDR + MAX_FRAME];
                    (0..PASS).take_while(|_| self.read_one(&mut buf)).count();
                }
            }
        }
        match switched {
            Ok(()) => self.unhold(ip, &e, true),
            Err(_) if refused.get() => self.unhold(ip, &e, false),
            // Left to the TUN, the address would be dropped here until the caller's retry.
            Err(_) => self.unroute(ip, &e),
        }
        // After `unhold`: a packet read since is a straggler, re-sent (or, refused, counted),
        // not discarded here. Refused, the stream goes on, so what the reader queued after the
        // last hand-over goes too (#539).
        if !lost && (switched.is_ok() || refused.get()) {
            self.give_queued(&e, sink, &mut stats);
        }
        stats.dropped += e.q.lock().unwrap().discard();
        self.report_stragglers();
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
    pub fn release_local(&self, ip: Ipv4Addr, mig: u64, sink: LocalSink, switch: impl FnOnce() -> Result<()>, linger: Duration) -> Option<(Stats, Result<()>)> {
        let e = self.releasing(ip, mig)?;
        let out = Mutex::new((sink, Stats::default()));
        let give = |o: &mut (LocalSink, Stats)| self.give_queued(&e, &mut *o.0, &mut o.1);
        give(&mut out.lock().unwrap());
        // `release_late`: the hand-over is held up from 20 ms before the switch to 30 ms after
        // it, as a busy host may (packets the device took before the switch are still here
        // when routed ones reach the VM).
        let late = crate::host::fault("release_late");
        if late {
            std::thread::sleep(Duration::from_millis(20));
        }
        let switching = AtomicBool::new(!late);
        let mut buf = vec![0u8; VNET_HDR + MAX_FRAME];
        let switched = std::thread::scope(|sc| {
            sc.spawn(|| {
                while switching.load(Ordering::SeqCst) {
                    if !give(&mut out.lock().unwrap()) {
                        std::thread::sleep(Duration::from_micros(200));
                    }
                }
            });
            let switched = switch();
            if late {
                std::thread::sleep(Duration::from_millis(30));
            }
            // Right away, here: the helper may be asleep, or not running at all.
            let mut o = out.lock().unwrap();
            if switched.is_ok() {
                self.drain_switched(&e, &mut || {
                    give(&mut o);
                });
            }
            switching.store(false, Ordering::SeqCst);
            switched
        });
        let mut o = out.into_inner().unwrap();
        if switched.is_ok() {
            let end = Instant::now() + linger;
            while Instant::now() < end {
                if crate::util::readable(&self.tun, end.saturating_duration_since(Instant::now()).max(Duration::from_millis(1))).unwrap_or(false) {
                    (0..PASS).take_while(|_| self.read_one(&mut buf)).count();
                }
                give(&mut o);
            }
        }
        if switched.is_ok() {
            self.unhold(ip, &e, true);
        }
        // After `unhold`: a packet read since is a straggler, re-sent, not discarded below.
        give(&mut o);
        let mut stats = o.1;
        let mut q = e.q.lock().unwrap();
        stats.dropped += match switched {
            Ok(()) => q.discard(),
            Err(_) => std::mem::take(&mut q.dropped),
        };
        drop(q);
        self.report_stragglers();
        Some((stats, switched))
    }

    /// Routed away, nothing new reaches the device for the address: what it took is read off it
    /// here (the reader thread may not run for a while on a busy host), a pass at a time, each
    /// `give`n before the next, up to its queue length, so no flood can make it more.
    fn drain_switched(&self, e: &Entry, give: &mut dyn FnMut()) {
        e.q.lock().unwrap().switched = true;
        let mut buf = vec![0u8; VNET_HDR + MAX_FRAME];
        for read in (0..TXQ).step_by(PASS) {
            let pass = PASS.min(TXQ - read);
            let n = (0..pass).take_while(|_| self.read_one(&mut buf)).count();
            give();
            if n < pass {
                break;
            }
        }
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
                if !self.reading.load(Ordering::SeqCst) && !crate::util::readable(&self.tun, Duration::ZERO).unwrap_or(false) {
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
            self.unhold(ip, e, false);
            let _ = crate::net::route_dev(false, ip, self.ifindex);
        }
    }

    fn read_loop(&self) {
        let mut pfd = libc::pollfd { fd: self.tun.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let mut buf = vec![0u8; VNET_HDR + MAX_FRAME];
        let mut wait = -1;
        loop {
            if let Err(e) = eintr(|| unsafe { libc::poll(&mut pfd, 1, wait) }) {
                return crate::log!("hold device {}: {e}", self.dev);
            }
            self.reading.store(true, Ordering::SeqCst);
            // Due reports also go out under sustained traffic, not only once the device is empty.
            let mut n = 0usize;
            while self.read_one(&mut buf) {
                n += 1;
                if n % PASS == 0 {
                    self.report_stragglers();
                }
            }
            self.reading.store(false, Ordering::SeqCst);
            wait = self.report_stragglers();
        }
    }

    /// Logs every straggler counted and not reported yet, whenever the last report was: for a
    /// process about to end, whose rate-limited reports would otherwise never come.
    pub fn report_now(&self) {
        self.gone.lock().unwrap().values_mut().for_each(|g| g.reported = None);
        self.report_stragglers();
    }

    /// Logs the stragglers counted since an address's last report: the first report at once,
    /// later ones at most every `STRAGGLER_LOG`. Here, off `rx`: a blocked stderr never holds
    /// up reading the device or a release. Returns the reader's poll timeout (ms): until the
    /// next report is due, or at most `STRAGGLER_LOG` while any let-go address is remembered
    /// (a release's own reads may count stragglers meanwhile), else -1.
    fn report_stragglers(&self) -> i32 {
        let mut due: Option<Duration> = None;
        let mut gone = self.gone.lock().unwrap();
        let ready: Vec<_> = gone
            .iter_mut()
            .filter(|(_, g)| g.resent + g.dropped > 0)
            .filter_map(|(ip, g)| match g.reported.map(|r| STRAGGLER_LOG.saturating_sub(r.elapsed())).filter(|d| !d.is_zero()) {
                Some(d) => {
                    due = Some(due.map_or(d, |x| x.min(d)));
                    None
                }
                None => {
                    let out = (*ip, *g);
                    (g.resent, g.dropped, g.reported) = (0, 0, Some(Instant::now()));
                    Some(out)
                }
            })
            .collect();
        gone.retain(|_, g| g.at.elapsed() < GONE_FOR || g.resent + g.dropped > 0);
        let watching = !gone.is_empty();
        drop(gone);
        ready.iter().for_each(|(ip, g)| report(*ip, &self.dev, g));
        match (due, watching) {
            (Some(d), _) => d.min(STRAGGLER_LOG).as_millis().max(1) as i32,
            (None, true) => STRAGGLER_LOG.as_millis() as i32,
            (None, false) => -1,
        }
    }

    /// Reads a packet off the device and queues it for its address; false once it is empty.
    /// Read and queued under `rx`, so packets are queued in the order they were read, by
    /// whichever thread.
    fn read_one(&self, buf: &mut [u8]) -> bool {
        let _rx = self.rx.lock().unwrap();
        let Ok(n) = eintr(|| unsafe { libc::read(self.tun.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) }) else { return false };
        // #362: a guest frame with VIRTIO_NET_HDR_F_NEEDS_CSUM can aim checksum completion at
        // its own IP source, after the tap's ingress filter passed the original. The device
        // leaves completion to us (`open_tun`): `accept` does it only at a TCP or UDP checksum
        // field, so no forged source is queued, nor re-sent by `straggler` (whose IPPROTO_RAW
        // resend recomputes the header checksum).
        // Refused, it is counted as dropped for the address it was sent to, if it has one.
        let Some((h, p)) = buf[..n as usize].split_at_mut_checked(VNET_HDR) else { return true };
        let ip = (p.len() >= 20).then(|| Ipv4Addr::new(p[16], p[17], p[18], p[19]));
        let Some(ip) = ip.filter(|_| accept(h, 0, p)) else {
            if let Some(ip) = ip {
                self.refused(ip);
            }
            return true;
        };
        match self.entry(ip) {
            Some(e) => {
                let mut q = e.q.lock().unwrap();
                if q.bytes + p.len() > CAP && !q.switched {
                    q.dropped += 1;
                } else {
                    q.bytes += p.len();
                    q.packets.push_back(p.to_vec());
                }
            }
            None => self.straggler(ip, p),
        }
        true
    }

    /// A packet for `ip` that `accept` refused: dropped where `ip`'s packets are counted, held or
    /// let go of (then reported as a straggler). Under `rx`.
    fn refused(&self, ip: Ipv4Addr) {
        match self.entry(ip) {
            Some(e) => e.q.lock().unwrap().dropped += 1,
            None => {
                if let Some(g) = self.gone.lock().unwrap().get_mut(&ip).filter(|g| g.at.elapsed() < GONE_FOR) {
                    g.dropped += 1;
                }
            }
        }
    }

    /// A packet for `ip` read after it was let go of: re-sent if the address moved on, else
    /// counted (and logged by `report_stragglers`, not here: this runs under `rx`). Its TTL
    /// goes down by one, so a route that still leads here cannot loop it. Limits, each counted
    /// as dropped: a fragment with IP ID 0 (the kernel would give it a new ID, so it would no
    /// longer reassemble with its siblings), and a packet larger than the new route's MTU
    /// (EMSGSIZE). A re-sent packet can arrive after newer ones that took the new route (and
    /// behind what a plugged tap holds): late rather than lost.
    fn straggler(&self, ip: Ipv4Addr, p: &mut [u8]) {
        let mut gone = self.gone.lock().unwrap();
        let Some(g) = gone.get_mut(&ip).filter(|g| g.at.elapsed() < GONE_FOR) else { return };
        let fragment = u16::from_be_bytes([p[6], p[7]]) & 0x3fff != 0;
        let zero_id = p[4] == 0 && p[5] == 0;
        let sent = g.moved
            && !(fragment && zero_id)
            && p[8] > 1
            && self.resend.as_ref().is_some_and(|fd| {
                p[8] -= 1;
                // The kernel fills the header checksum in.
                let mut to: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                to.sin_family = libc::AF_INET as u16;
                to.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
                let size = std::mem::size_of::<libc::sockaddr_in>() as u32;
                unsafe { libc::sendto(fd.as_raw_fd(), p.as_ptr().cast(), p.len(), libc::MSG_DONTWAIT, (&to as *const libc::sockaddr_in).cast(), size) >= 0 }
            });
        match sent {
            true => g.resent += 1,
            false => g.dropped += 1,
        }
    }
}

/// Whether `p`'s IPv4 header checksum is valid (the one's-complement sum over the header,
/// including its own checksum field, is 0xffff). The header length is `p[0] & 0xf` 32-bit
/// words; a truncated or under-length header is treated as invalid.
fn ipv4_header_csum_ok(p: &[u8]) -> bool {
    let ihl = (p[0] & 0xf) as usize * 4;
    ihl >= 20 && p.len() >= ihl && sum16(&p[..ihl]) == 0xffff
}

/// The one's-complement sum of `b` as big-endian 16-bit words (an odd last byte padded), folded.
fn sum16(b: &[u8]) -> u16 {
    let mut sum: u32 = b.chunks(2).map(|w| u32::from(u16::from_be_bytes([w[0], w.get(1).copied().unwrap_or(0)]))).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// The IPv4 packets in a frame read off a tap (a 12-byte virtio-net header, then Ethernet),
/// each `accept`ed: one, or a TCP GSO frame's segments (Firecracker turns TSO on for a guest
/// that takes it, as Linux does: a bulk download's frames are mostly these, #411), cut as
/// `tcp_gso_segment` would. None for anything else (UDP GSO, IPv6, a `gso_size` under
/// `MIN_MSS`); Err(how many) if they would take more than `room` bytes.
fn from_tap(f: &[u8], room: usize) -> Option<std::result::Result<Vec<Vec<u8>>, u64>> {
    let (h, eth) = (f.get(..12)?, f.get(12..)?);
    let mut p = eth.get(14..14 + usize::from(u16::from_be_bytes([*eth.get(16)?, *eth.get(17)?])))?.to_vec();
    // `h` as for one packet: what each segment must pass, and the whole frame first.
    let one = [&[h[0], 0][..], &h[2..]].concat();
    match (eth[12..14] == [8, 0], h[1] & 0x7f) {
        (true, 0) => return (h[1] == 0 && accept(h, 14, &mut p)).then(|| if p.len() <= room { Ok(vec![p]) } else { Err(1) }),
        // TCPv4 (0x80: ECN), its checksum left to the device: only in TCP's own field.
        (true, 1) if p.get(9) == Some(&6) && h[0] & 1 != 0 && accept(&one, 14, &mut p.clone()) => {}
        _ => return None,
    }
    let (ihl, mss) = (usize::from(p[0] & 0xf) * 4, usize::from(u16::from_le_bytes([h[4], h[5]])));
    let thl = usize::from(*p.get(ihl + 12)? >> 4) * 4;
    let (head, body) = p.split_at_checked(ihl + thl)?;
    if mss < MIN_MSS || thl < 20 || body.is_empty() {
        return None;
    }
    let (id, seq, n) = (u16::from_be_bytes([p[4], p[5]]), u32::from_be_bytes(p[ihl + 4..ihl + 8].try_into().ok()?), body.len().div_ceil(mss));
    // Sized before any is made: each segment repeats the headers.
    if body.len() + n * head.len() > room {
        return Some(Err(n as u64));
    }
    let segment = |(i, data): (usize, &[u8])| {
        let mut s = [head, data].concat();
        let len = s.len() as u16;
        s[2..4].copy_from_slice(&len.to_be_bytes());
        s[4..6].copy_from_slice(&id.wrapping_add(i as u16).to_be_bytes());
        s[10..12].fill(0);
        let sum = !sum16(&s[..ihl]);
        s[10..12].copy_from_slice(&sum.to_be_bytes());
        s[ihl + 4..ihl + 8].copy_from_slice(&seq.wrapping_add((i * mss) as u32).to_be_bytes());
        // FIN and PSH on the last segment only, CWR on the first.
        s[ihl + 13] &= !(if i + 1 < n { 0x09 } else { 0 } | if i > 0 { 0x80 } else { 0 });
        // The pseudo-header's sum where the checksum goes, for `accept` to complete.
        let pseudo = sum16(&[&s[12..20], &[0, 6], &(len - ihl as u16).to_be_bytes()].concat());
        s[ihl + 16..ihl + 18].copy_from_slice(&pseudo.to_be_bytes());
        accept(&one, 14, &mut s).then_some(s)
    };
    body.chunks(mss).enumerate().map(segment).collect::<Option<_>>().map(Ok)
}

/// Whether IPv4 packet `p`, behind virtio-net header `h`, may go to a guest or be re-sent,
/// its L4 checksum completed if `h` leaves that to the device (as `skb_checksum_help` would).
/// Completed only in a TCP or UDP packet's own checksum field, its `csum_start` right after
/// the IP header (`eth`: the bytes before that header it counts): anywhere else a guest could
/// aim the write at the header and forge a source the header checksum still passes (#406:
/// 0x0000 to 0xffff across the middle bytes of 10.0.0.2). Then the header checksum must
/// verify (`ipv4_header_csum_ok`). Not GSO (many packets in one).
fn accept(h: &[u8], eth: usize, p: &mut [u8]) -> bool {
    if p.len() < 20 || p[0] >> 4 != 4 || h[1] != 0 {
        return false;
    }
    if h[0] & 1 != 0 {
        let ihl = usize::from(p[0] & 0xf) * 4;
        let Some(field) = (match p[9] {
            6 => Some(16),
            17 => Some(6),
            _ => None,
        }) else {
            return false;
        };
        let (start, off) = (usize::from(u16::from_le_bytes([h[6], h[7]])), usize::from(u16::from_le_bytes([h[8], h[9]])));
        if start != eth + ihl || off != field || ihl < 20 || p.len() < ihl + field + 2 {
            return false;
        }
        let sum = !sum16(&p[ihl..]);
        p[ihl + field..ihl + field + 2].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
    }
    ipv4_header_csum_ok(p)
}

/// Logs `g`'s straggler counts, if any ("dropped N" is what loss accounting reads).
fn report(ip: Ipv4Addr, dev: &str, g: &Gone) {
    let after = format!("{dev} after it let go of the address ({} ms ago)", g.at.elapsed().as_millis());
    match (g.resent, g.dropped) {
        (0, 0) => {}
        (r, 0) => crate::log!("hold {ip}: re-sent {r} packets that reached {after}"),
        (r, d) => crate::log!("hold {ip}: dropped {d} packets that reached {after}, re-sent {r}"),
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
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // Past the tap's qdisc, straight to the tap: ahead of what a plugged qdisc holds back
        // (`net::plug_tap`). Without it (older kernels) the frames queue there too.
        const SOL_PACKET: libc::c_int = 263;
        const PACKET_QDISC_BYPASS: libc::c_int = 20;
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(fd.as_raw_fd(), SOL_PACKET, PACKET_QDISC_BYPASS, (&one as *const libc::c_int).cast(), std::mem::size_of::<libc::c_int>() as u32)
        };
        let mut header = [0u8; 14];
        header[..6].copy_from_slice(&crate::net::GUEST_MAC);
        header[6..12].copy_from_slice(&crate::net::GATEWAY_MAC);
        header[12..].copy_from_slice(&[0x08, 0x00]);
        Ok(Injector { fd, tap: tap.into(), ifindex: crate::net::ifindex(tap)?, header, tx_dropped: tap_tx_dropped(tap) })
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
        unsafe {
            libc::sendto(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len(), libc::MSG_DONTWAIT, (&addr as *const libc::sockaddr_ll).cast(), size) >= 0
        }
    }

    /// Dropped by the tap since this was made (with the guest's own traffic): reported with the injected packets.
    pub fn dropped(&self) -> u64 {
        tap_tx_dropped(&self.tap).saturating_sub(self.tx_dropped)
    }
}

fn tap_tx_dropped(tap: &str) -> u64 {
    std::fs::read_to_string(format!("/sys/class/net/{tap}/statistics/tx_dropped")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

// Stream (over TCP: nothing lost or reordered): `START`, answered `b'a'`. Frames: u32 BE
// length, packet. `SYNC` gets `b's'` once all before it is injected. `SWITCH` (hosts sharing
// routes) gets `b'w'` once all before it is injected and the target took the address over,
// `b'n'` if it could not (the stream goes on: the target routes the address once it ends).
// Length 0 ends it and gets one JSON line. Nothing is resent.
const SYNC: u32 = u32::MAX;
/// Not `u32::MAX - 1`, which started the stream with sequence numbers: a target here refuses
/// such a source's stream (which counts its packets dropped), never misreads it.
const START: u32 = u32::MAX - 3;
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

/// Injects only while `revoked` is false; on `SWITCH`, `take_over` takes the address (false if it
/// could not, which the source is told). Refused if too many streams are being received.
/// Returns how many tap drops were reported with them (`Injector::dropped`), if they were.
pub fn receive(
    r: &mut BufReader<By<TcpStream>>,
    ip: Ipv4Addr,
    tap: &str,
    revoked: &Mutex<bool>,
    deadline: Instant,
    take_over: &mut dyn FnMut() -> bool,
) -> Option<u64> {
    let _slot = Slot::take(&RECEIVERS, MAX_RECEIVERS)?;
    let (Ok(conn), Ok(inj)) = (r.get_ref().s.try_clone(), Injector::new(tap)) else { return None };
    if write_by(&conn, b"a", deadline).is_err() {
        return None;
    }
    let (mut buf, mut injected, mut dropped) = (vec![0u8; MAX_FRAME], 0, 0);
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
                let took = take_over();
                match write_by(&conn, if took { b"w" } else { b"n" }, deadline) {
                    Ok(()) => continue,
                    Err(_) => break false,
                }
            }
            0 => break true,
            len => len as usize,
        };
        if len > MAX_FRAME || read_by(r, &mut buf[..len], deadline).is_err() {
            break false;
        }
        match !*revoked.lock().unwrap() && valid(&buf[..len], ip) && inj.send(&buf[..len]) {
            true => injected += 1,
            false => dropped += 1,
        }
    };
    if !ended {
        return None;
    }
    let tap_dropped = inj.dropped();
    // Closing a packet socket waits for an RCU grace period (tens of ms): not before the
    // caller routes the address.
    std::thread::spawn(move || drop(inj));
    let reply = json!({"injected": injected, "dropped": dropped + tap_dropped});
    write_by(&conn, format!("{reply}\n").as_bytes(), deadline).ok().map(|()| tap_dropped)
}

/// A whole IPv4 packet for `ip`: all a guest is ever handed.
pub fn valid(p: &[u8], ip: Ipv4Addr) -> bool {
    let ihl = (p.first().copied().unwrap_or(0) & 15) as usize * 4;
    p.len() >= 20 && p[0] >> 4 == 4 && ihl >= 20 && ihl <= p.len() && u16::from_be_bytes([p[2], p[3]]) as usize == p.len() && p[16..20] == ip.octets()
}

pub fn start(conn: &TcpStream) -> Result<()> {
    let deadline = Instant::now() + ACCEPT_WAIT;
    write_by(conn, &START.to_be_bytes(), deadline)?;
    let mut ack = [0u8; 1];
    By { s: conn, at: deadline }.read_exact(&mut ack)?;
    if ack[0] != b'a' {
        bail!("the target refused the held packets");
    }
    Ok(())
}

/// Before `switch` moves the route, `SYNC`s until the target injected all sent so far. With
/// `handoff` (hosts sharing routes) the target routes the address itself, after those.
pub fn send(holder: &Holder, ip: Ipv4Addr, mig: u64, conn: &TcpStream, handoff: bool, switch: impl FnOnce() -> Result<()>) -> Option<(Stats, Result<()>)> {
    let out = std::cell::RefCell::new(Out { buf: Vec::with_capacity(64 << 10), broken: false, conn });
    let mut sink = |p: &[u8]| out.borrow_mut().frame(p);
    let mut barrier = || {
        let mut o = out.borrow_mut();
        o.buf.extend_from_slice(&SYNC.to_be_bytes());
        let (mut ack, deadline) = ([0u8; 1], Instant::now() + SYNC_WAIT);
        let ok = o.flush(deadline) && By { s: conn, at: deadline }.read_exact(&mut ack).is_ok() && ack[0] == b's';
        if !ok {
            o.broken = true;
            crate::log!("hold {ip}: the target did not confirm the held packets; dropping the rest");
        }
        ok
    };
    // A handoff moves the route on the target; `switch` runs after the stragglers went, as
    // until they are injected, packets routed to the target overtake them.
    let mut switch = Some(switch);
    let refused = std::cell::Cell::new(false);
    let handover = || match handoff {
        true => {
            let mut o = out.borrow_mut();
            o.buf.extend_from_slice(&SWITCH.to_be_bytes());
            let (mut ack, deadline) = ([0u8; 1], Instant::now() + SWITCH_WAIT);
            let answered = o.flush(deadline) && By { s: conn, at: deadline }.read_exact(&mut ack).is_ok();
            match ack[0] {
                b'w' if answered => Ok(()),
                // It could not route the address yet: the rest still goes to it, which routes
                // the address once the stream ends.
                b'n' if answered => {
                    refused.set(true);
                    crate::log!("hold {ip}: the target could not take the address over; it routes it after the held packets");
                    bail!("the target could not take {ip} over")
                }
                _ => {
                    o.broken = true;
                    crate::log!("hold {ip}: the target did not take the address over; dropping the rest");
                    bail!("the target did not take {ip} over (its held packets after this are lost)")
                }
            }
        }
        false => switch.take().map_or(Ok(()), |f| f()),
    };
    let (mut stats, switched) = holder.release(ip, mig, &mut sink, &mut barrier, handover, &refused)?;
    let mut o = out.into_inner();
    o.buf.extend_from_slice(&0u32.to_be_bytes());
    match o.flush(Instant::now() + FLUSH_WAIT).then(|| read_reply(conn, Instant::now() + REPLY_WAIT)).flatten() {
        Some(r) => (stats.injected, stats.dropped_target) = (r["injected"].as_u64().unwrap_or(0), r["dropped"].as_u64().unwrap_or(0)),
        None => stats.dropped_target = stats.packets,
    }
    // Refused, the target routes the address itself once the stream ends (or breaks): no route
    // is owed here, nor retried (#539).
    let switched = match switched {
        Err(_) if refused.get() => Ok(()),
        s => s.and_then(|()| switch.take().map_or(Ok(()), |f| f())),
    };
    Some((stats, switched))
}

/// The final reply on the held-packet stream; its caller reads nothing further.
fn read_reply(conn: &TcpStream, deadline: Instant) -> Option<Value> {
    crate::util::recv_json_max(&mut BufReader::new(By { s: conn, at: deadline }), 257).ok().flatten()
}

struct Out<'a> {
    buf: Vec<u8>,
    broken: bool,
    conn: &'a TcpStream,
}

impl Out<'_> {
    fn frame(&mut self, p: &[u8]) -> bool {
        if self.broken {
            return false;
        }
        self.buf.extend_from_slice(&(p.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(p);
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

/// The error flag: another process has it, or the name is too long (rather than no TUN support).
fn open_tun(dev: &str) -> std::result::Result<OwnedFd, (bool, crate::util::Error)> {
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    let fd = eintr(|| unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK) })
        .map_err(|e| (false, format!("/dev/net/tun: {e}").into()))?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = crate::net::ifreq(dev).map_err(|e| (true, e))?;
    req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short;
    if let Err(e) = eintr(|| unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &req) }) {
        let busy = matches!(e.raw_os_error(), Some(libc::EBUSY | libc::EEXIST | libc::EPERM));
        return Err((busy, format!("{dev}: {e}{}", if busy { " (another process has it)" } else { "" }).into()));
    }
    // TUN_F_CSUM: checksums reach us left to the device (`accept`), never completed by the
    // kernel at whatever offset a guest gave.
    const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54d0;
    if let Err(e) = eintr(|| unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETOFFLOAD as _, 1 as libc::c_ulong) }) {
        return Err((true, format!("{dev}: checksum offload: {e}").into()));
    }
    // Room for what arrives while a release catches up (default 500).
    req.ifr_ifru.ifru_metric = TXQ as i32;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock >= 0 {
        let sock = unsafe { OwnedFd::from_raw_fd(sock) };
        unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFTXQLEN as _, &req) };
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reading `tun`, with no routes or raw socket: nothing here needs root.
    fn holder(tun: OwnedFd) -> Holder {
        let (held, gone) = (Mutex::default(), Mutex::default());
        Holder { dev: "test".into(), ifindex: 0, tun, held, reading: AtomicBool::new(false), routes: Mutex::new(()), rx: Mutex::new(()), gone, resend: None }
    }

    /// A UDP datagram 10.9.0.2 -> `dst` (ports 12345 -> 54321), its header checksum filled in.
    fn udp_to(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 29, 0, 1, 0, 0, 64, 17, 0, 0, 10, 9, 0, 2, 0, 0, 0, 0, 0x30, 0x39, 0xd4, 0x31, 0, 9, 0, 0, 0];
        p[16..20].copy_from_slice(&dst.octets());
        let sum = !sum16(&p[..20]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p
    }

    /// `p` as a tap frame: virtio-net header (`flags`, `gso_type`, csum start and offset from
    /// the Ethernet header), Ethernet header, and `pad` bytes after it.
    fn tap_frame(p: &[u8], flags: u8, gso: u8, csum: (u16, u16), pad: usize) -> Vec<u8> {
        [&vnet_hdr(flags, gso, csum)[..], &[0, 0], &[2; 12], &[8, 0], p, &vec![0; pad]].concat()
    }

    /// A struct virtio_net_hdr: `flags`, `gso_type`, csum start and offset.
    fn vnet_hdr(flags: u8, gso: u8, csum: (u16, u16)) -> Vec<u8> {
        [&[flags, gso, 0, 0, 0, 0][..], &csum.0.to_le_bytes(), &csum.1.to_le_bytes()].concat()
    }

    /// Codex's #406 frame: a UDP datagram from 10.0.0.2 whose payload makes a completion over
    /// bytes 13 on write 0xffff at bytes 13-14, its source then 10.255.255.2.
    fn forgery() -> Vec<u8> {
        let mut p = [&udp_to(Ipv4Addr::new(10, 9, 0, 8))[..], &[0, 0]].concat();
        (p[3], p[25]) = (31, 11);
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[10..12].fill(0);
        let sum = !sum16(&p[..20]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        let x = (0..=u16::MAX).find(|&x| {
            p[29..31].copy_from_slice(&x.to_be_bytes());
            sum16(&p[13..]) == 0xffff
        });
        assert!(x.is_some());
        p
    }

    #[test]
    fn completion_never_writes_into_the_ip_header() {
        let p = forgery();
        // Completed as asked, the source is forged and the header checksum still passes.
        let mut naive = p.clone();
        let sum = !sum16(&p[13..]);
        naive[13..15].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
        assert_eq!((&naive[12..16], ipv4_header_csum_ok(&naive)), (&[10, 255, 255, 2][..], true));
        assert_eq!(cut(&tap_frame(&p, 1, 0, (14 + 13, 0), 0)), None, "Codex's frame");
        assert_eq!(cut(&tap_frame(&p, 1, 0, (14 + 21, 6), 0)), None, "a misaligned start");
        assert_eq!(cut(&tap_frame(&p, 1, 0, (14 + 20, 16), 0)), None, "TCP's field in a UDP packet");
        assert!(cut(&tap_frame(&p, 1, 0, (14 + 20, 6), 0)).is_some(), "UDP's own field");
        // The hold device's reads too: the kernel leaves completion to it.
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
        let (h, w) = unsafe { (holder(OwnedFd::from_raw_fd(fds[0])), OwnedFd::from_raw_fd(fds[1])) };
        let dst = Ipv4Addr::new(10, 9, 0, 8);
        h.held.lock().unwrap().insert(dst, Arc::new(Entry { mig: 1, q: Mutex::default() }));
        let mut buf = vec![0u8; VNET_HDR + MAX_FRAME];
        for (csum, queued) in [((13, 0), 0), ((21, 6), 0), ((20, 16), 0), ((20, 6), 1)] {
            let f = [&vnet_hdr(1, 0, csum)[..], &p].concat();
            assert_eq!(unsafe { libc::write(w.as_raw_fd(), f.as_ptr().cast(), f.len()) }, f.len() as isize);
            h.read_one(&mut buf);
            assert_eq!(h.entry(dst).unwrap().q.lock().unwrap().packets.len(), queued, "{csum:?}");
        }
        let q = h.entry(dst).unwrap().q.lock().unwrap().packets[0].clone();
        assert_eq!((&q[12..16], ipv4_header_csum_ok(&q)), (&[10, 0, 0, 2][..], true));
    }

    #[test]
    fn tap_frames_become_packets_with_their_checksums_completed() {
        // As the host sends to a tap with checksum offload: the UDP checksum holds the pseudo-header's sum.
        let mut p = udp_to(Ipv4Addr::new(10, 9, 0, 8));
        let pseudo = [&p[12..20], &[0, 17, 0, 9]].concat();
        p[26..28].copy_from_slice(&sum16(&pseudo).to_be_bytes());
        let got = cut(&tap_frame(&p, 1, 0, (14 + 20, 6), 3)).unwrap().remove(0);
        assert_eq!(got.len(), 29, "Ethernet padding is not the packet's");
        assert_eq!((&got[..26], &got[28..]), (&p[..26], &p[28..]));
        assert_eq!(sum16(&[&pseudo[..], &got[20..]].concat()), 0xffff, "the UDP checksum verifies");
        assert_eq!(cut(&tap_frame(&p, 0, 0, (0, 0), 0)).unwrap(), [p.clone()], "a complete one is as it was");
        assert_eq!(cut(&tap_frame(&p, 1, 3, (14 + 20, 6), 0)), None, "UDP GSO");
        let mut arp = tap_frame(&p, 0, 0, (0, 0), 0);
        arp[24..26].copy_from_slice(&[8, 6]);
        assert_eq!(cut(&arp), None, "not IPv4");
        assert_eq!(cut(&tap_frame(&p[..20], 0, 0, (0, 0), 0)), None, "truncated");
    }

    /// `from_tap` with all of `CAP` to fill.
    fn cut(f: &[u8]) -> Option<Vec<Vec<u8>>> {
        from_tap(f, CAP).map(|r| r.unwrap())
    }

    /// `frames` handed to `hold_first`, as `Vm::take_tap_queue` would.
    fn feed(frames: &[Vec<u8>]) -> impl FnOnce(Each) + '_ {
        move |each| frames.iter().for_each(|f| each(f))
    }

    /// As the host's TCP sends `data` to a tap with TSO, cut by `mss`: one frame, its checksum
    /// field holding the pseudo-header's sum without the length, FIN and PSH set.
    fn tso_frame(data: &[u8], mss: u16, csum: (u16, u16)) -> Vec<u8> {
        let tcp = [&[0x30, 0x39, 0x1f, 0x40][..], &1000u32.to_be_bytes(), &[0, 0, 0, 1], &[0x50, 0x19, 0xff, 0xff, 0, 0, 0, 0]].concat();
        let mut p = [&[0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0, 10, 9, 0, 2, 10, 9, 0, 8][..], &tcp, data].concat();
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        let sum = !sum16(&p[..20]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        let pseudo = sum16(&[&p[12..20], &[0, 6, 0, 0]].concat());
        p[36..38].copy_from_slice(&pseudo.to_be_bytes());
        let mut f = tap_frame(&p, 1, 1, csum, 0);
        f[2..4].copy_from_slice(&54u16.to_le_bytes());
        f[4..6].copy_from_slice(&mss.to_le_bytes());
        f
    }

    /// A full tap backlog (`TAP_QUEUE` frames, 64 MB) of TSO frames: one with a tiny
    /// `gso_size` is dropped whole, and others are cut only within `CAP`, the rest counted as
    /// dropped (#415: 64 KiB by 1 byte would be 65,000 packets, gigabytes for a backlog).
    #[test]
    fn a_tap_backlog_takes_at_most_cap() {
        let ip = Ipv4Addr::new(10, 9, 0, 8);
        let data = vec![7u8; 16000];
        let backlog = |h: &Holder, mss: u16| {
            h.held.lock().unwrap().insert(ip, Arc::new(Entry { mig: 1, q: Mutex::default() }));
            let f = tso_frame(&data, mss, (14 + 20, 16));
            h.hold_first(ip, 1, |each| (0..crate::net::TAP_QUEUE).for_each(|_| each(&f)));
            let e = h.entry(ip).unwrap();
            let q = e.q.lock().unwrap();
            (q.packets.len() as u64, q.bytes, q.dropped)
        };
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        assert_eq!(backlog(&h, 1), (0, 0, u64::from(crate::net::TAP_QUEUE)), "under MIN_MSS: dropped, nothing made");
        let (kept, bytes, dropped) = backlog(&h, MIN_MSS as u16);
        let per = data.len().div_ceil(MIN_MSS) as u64;
        assert!(bytes <= CAP && kept > 0, "{bytes} bytes in {kept} packets");
        assert_eq!(kept + dropped, per * u64::from(crate::net::TAP_QUEUE), "every segment kept or counted");
    }

    #[test]
    fn a_tso_frame_is_cut_into_its_segments() {
        // As the host's TCP sends to a tap with TSO: one frame for three segments, its checksum
        // field holding the pseudo-header's sum without the length, FIN and PSH set.
        let data: Vec<u8> = (0..3500u32).map(|i| i as u8).collect();
        let tso = |csum: (u16, u16)| tso_frame(&data, 1448, csum);
        let segs = cut(&tso((14 + 20, 16))).unwrap();
        assert_eq!(segs.iter().map(Vec::len).collect::<Vec<_>>(), [40 + 1448, 40 + 1448, 40 + 604]);
        let mut joined = Vec::new();
        for (i, s) in segs.iter().enumerate() {
            assert!(ipv4_header_csum_ok(s) && valid(s, Ipv4Addr::new(10, 9, 0, 8)), "segment {i}");
            assert_eq!((&s[12..16], u16::from_be_bytes([s[4], s[5]])), (&[10, 9, 0, 2][..], 0x1234 + i as u16));
            assert_eq!(u32::from_be_bytes(s[24..28].try_into().unwrap()), 1000 + 1448 * i as u32);
            assert_eq!(s[33], if i == 2 { 0x19 } else { 0x10 }, "FIN and PSH on the last only");
            let pseudo = [&s[12..20], &[0, 6], &(s.len() as u16 - 20).to_be_bytes()].concat();
            assert_eq!(sum16(&[&pseudo[..], &s[20..]].concat()), 0xffff, "segment {i}'s TCP checksum verifies");
            joined.extend_from_slice(&s[40..]);
        }
        assert_eq!(joined, data);
        // Held first, in their order, ahead of what was held.
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        let q = Queue { packets: VecDeque::from([b"held".to_vec()]), bytes: 4, ..Queue::default() };
        h.held.lock().unwrap().insert(Ipv4Addr::new(10, 9, 0, 8), Arc::new(Entry { mig: 1, q: Mutex::new(q) }));
        h.hold_first(Ipv4Addr::new(10, 9, 0, 8), 1, feed(&[tso((14 + 20, 16))]));
        assert_eq!(h.entry(Ipv4Addr::new(10, 9, 0, 8)).unwrap().q.lock().unwrap().packets, [&segs[..], &[b"held".to_vec()]].concat());
        // Its checksum asked for anywhere but TCP's own field, as for one packet: dropped.
        assert_eq!(cut(&tso((14 + 13, 0))), None, "Codex's offsets");
        assert_eq!(cut(&tso((14 + 20, 6))), None, "UDP's field");
    }

    #[test]
    fn frames_left_on_the_tap_go_ahead_of_the_held_packets() {
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        let ip = Ipv4Addr::new(10, 9, 0, 8);
        let (first, second, held) = (udp_to(ip), [&udp_to(ip)[..28], b"!"].concat(), b"held".to_vec());
        let q = Queue { packets: VecDeque::from([held.clone()]), bytes: 4, ..Queue::default() };
        h.held.lock().unwrap().insert(ip, Arc::new(Entry { mig: 1, q: Mutex::new(q) }));
        let frames = [tap_frame(&first, 0, 0, (0, 0), 0), tap_frame(&second, 0, 1, (0, 0), 0), tap_frame(&second, 0, 0, (0, 0), 0)];
        h.hold_first(ip, 2, feed(&frames));
        assert_eq!(h.entry(ip).unwrap().q.lock().unwrap().packets.len(), 1, "another migration's hold");
        h.hold_first(ip, 1, feed(&frames));
        let e = h.entry(ip).unwrap();
        let q = e.q.lock().unwrap();
        assert_eq!(q.packets, [first, second, held]);
        assert_eq!((q.bytes, q.dropped), (29 + 29 + 4, 1), "the GSO frame is counted as dropped");
    }

    #[test]
    fn failed_hold_counts_queued_and_overflow_packets() {
        let h = holder(std::fs::File::open("/dev/null").unwrap().into());
        let ip = Ipv4Addr::new(10, 100, 254, 9);
        for existing in [false, true] {
            if existing {
                h.gone.lock().unwrap().insert(ip, Gone { resent: 2, dropped: 3, ..Gone::new(true) });
            }
            let e = Arc::new(Entry {
                mig: 1,
                q: Mutex::new(Queue { packets: VecDeque::from([vec![0; 20], vec![0; 20]]), bytes: 40, dropped: 4, ..Queue::default() }),
            });
            h.held.lock().unwrap().insert(ip, e.clone());
            let _routes = h.routes.lock().unwrap();
            h.discard_hold(ip);
            assert!(h.entry(ip).is_none());
            let g = h.gone.lock().unwrap()[&ip];
            assert_eq!((g.resent, g.dropped), if existing { (2, 9) } else { (0, 6) });
            assert_eq!(g.moved, existing);
            let mut q = e.q.lock().unwrap();
            assert!(q.packets.is_empty());
            assert_eq!(q.bytes, 0);
            assert_eq!(q.discard(), 0);
            h.discard_hold(ip);
            assert_eq!(h.gone.lock().unwrap()[&ip].dropped, g.dropped);
        }
    }

    #[test]
    fn a_rewritten_header_fails_its_checksum() {
        let p = udp_to(Ipv4Addr::new(10, 9, 0, 8));
        assert!(ipv4_header_csum_ok(&p), "a well-formed header passes");
        // Checksum completion overwrote the low two bytes of the source (#362): the header
        // checksum is now stale, so it no longer verifies.
        let mut forged = p.clone();
        forged[14] = 0x00;
        forged[15] = 0x63;
        assert!(!ipv4_header_csum_ok(&forged), "a rewritten source no longer matches the checksum");
        assert!(!ipv4_header_csum_ok(&p[..19]), "a truncated header is rejected");
    }

    #[test]
    fn read_one_drops_a_rewritten_header() {
        // A held entry for the destination, and the reader fed from a pipe standing in for the tun.
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        let h = holder(unsafe { OwnedFd::from_raw_fd(r) });
        let dst = Ipv4Addr::new(10, 9, 0, 8);
        h.held.lock().unwrap().insert(dst, Arc::new(Entry { mig: 1, q: Mutex::default() }));
        let p = udp_to(dst);
        let queued = || h.entry(dst).unwrap().q.lock().unwrap().packets.len();
        let write = |p: &[u8]| {
            let f = [&vnet_hdr(0, 0, (0, 0))[..], p].concat();
            assert_eq!(unsafe { libc::write(w, f.as_ptr().cast(), f.len()) }, f.len() as isize)
        };
        let mut buf = vec![0u8; 2048];
        write(&p);
        h.read_one(&mut buf);
        assert_eq!(queued(), 1, "a valid packet is queued");
        // Checksum completion overwrote the source low byte (#362): now dropped, not queued or straggled.
        let mut forged = p.clone();
        forged[15] ^= 0xff;
        write(&forged);
        h.read_one(&mut buf);
        assert_eq!(queued(), 1, "a rewritten-header packet is dropped");
        assert_eq!(h.entry(dst).unwrap().q.lock().unwrap().dropped, 1, "and counted for its address (#512)");
        // Let go of, the address counts it with its stragglers.
        h.held.lock().unwrap().clear();
        h.gone.lock().unwrap().insert(dst, Gone::new(false));
        write(&forged);
        h.read_one(&mut buf);
        assert_eq!(h.gone.lock().unwrap()[&dst].dropped, 1, "a let-go address counts it too");
        unsafe { libc::close(w) };
    }

    /// A fake handoff target on `l`: confirms each `SYNC`, answers `SWITCH` with `switch_ack`,
    /// and counts the packets it got in its final reply. Returns those packets.
    fn fake_target(l: std::net::TcpListener, switch_ack: u8) -> std::thread::JoinHandle<Vec<Vec<u8>>> {
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut got = Vec::new();
            loop {
                let mut head = [0u8; 4];
                c.read_exact(&mut head).unwrap();
                match u32::from_be_bytes(head) {
                    SYNC => c.write_all(b"s").unwrap(),
                    SWITCH => c.write_all(&[switch_ack]).unwrap(),
                    0 => break,
                    len => {
                        let mut p = vec![0u8; len as usize];
                        c.read_exact(&mut p).unwrap();
                        got.push(p);
                    }
                }
            }
            c.write_all(format!("{}\n", json!({"injected": got.len(), "dropped": 0})).as_bytes()).unwrap();
            got
        })
    }

    /// #512: a target that could not take the address over says so (`b'n'`): the handover fails,
    /// but the stream goes on, so nothing held is dropped, and the address is not let go of as
    /// moved (its stragglers would be re-sent into the route that still leads here). It routes
    /// the address itself: no route is owed here (#539). A packet on the device that no reader
    /// took (a busy host's) goes on the stream too, not dropped with the queue (#539).
    #[test]
    fn a_refused_switch_keeps_the_stream() {
        for (ack, took) in [(b'w', true), (b'n', false)] {
            let mut fds = [0; 2];
            assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
            let (h, w) = unsafe { (holder(OwnedFd::from_raw_fd(fds[0])), OwnedFd::from_raw_fd(fds[1])) };
            let ip = Ipv4Addr::new(10, 9, 0, 8);
            let q = Queue { packets: VecDeque::from(vec![udp_to(ip); 3]), bytes: 3 * 29, ..Queue::default() };
            h.held.lock().unwrap().insert(ip, Arc::new(Entry { mig: 1, q: Mutex::new(q) }));
            let late = [&vnet_hdr(0, 0, (0, 0))[..], &udp_to(ip)].concat();
            assert_eq!(unsafe { libc::write(w.as_raw_fd(), late.as_ptr().cast(), late.len()) }, late.len() as isize);
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let target = fake_target(l, ack);
            let conn = TcpStream::connect(addr).unwrap();
            let switch = std::cell::Cell::new(false);
            let (stats, switched) = send(&h, ip, 1, &conn, true, || {
                switch.set(true);
                Ok(())
            })
            .unwrap();
            let got = target.join().unwrap();
            assert!(switched.is_ok() && switch.get() == took, "{}: refused, nothing owed or routed here", ack as char);
            assert_eq!((got.len(), stats.packets, stats.injected, stats.dropped, stats.dropped_target), (4, 4, 4, 0, 0), "{}", ack as char);
            assert!(h.entry(ip).is_none(), "{}: no longer held", ack as char);
            let moved = h.gone.lock().unwrap().get(&ip).map(|g| g.moved);
            assert_eq!(moved, Some(took), "{}: stragglers re-sent only once it moved", ack as char);
        }
    }

    /// The reader thread queues packets all through a release: those it queues after the last
    /// hand-over must not be discarded with the queue (#365). Read after `unhold`, they are
    /// stragglers (counted there, with no raw socket to re-send them by).
    #[test]
    fn a_release_discards_nothing_the_reader_queues() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);
        let (h, w) = unsafe { (holder(OwnedFd::from_raw_fd(fds[0])), OwnedFd::from_raw_fd(fds[1])) };
        let ip = Ipv4Addr::new(10, 9, 0, 8);
        let (p, stop) = ([&vnet_hdr(0, 0, (0, 0))[..], &udp_to(ip)].concat(), AtomicBool::new(false));
        std::thread::scope(|s| {
            s.spawn(|| {
                while !stop.load(Ordering::SeqCst) {
                    unsafe { libc::write(w.as_raw_fd(), p.as_ptr().cast(), p.len()) };
                }
            });
            s.spawn(|| {
                let mut buf = vec![0u8; MAX_FRAME];
                while !stop.load(Ordering::SeqCst) {
                    h.read_one(&mut buf);
                }
            });
            let dropped: Vec<u64> = (0..10)
                .map(|mig| {
                    h.held.lock().unwrap().insert(ip, Arc::new(Entry { mig, q: Mutex::default() }));
                    let (stats, switched) = h.release_local(ip, mig, &mut |_| true, || Ok(()), Duration::ZERO).unwrap();
                    switched.unwrap();
                    stats.dropped
                })
                .collect();
            stop.store(true, Ordering::SeqCst);
            assert!(dropped.iter().all(|&d| d == 0), "{dropped:?}");
        });
    }

    #[test]
    fn held_frames_are_a_length_and_the_packet() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut s, _) = l.accept().unwrap();
        let mut out = Out { buf: Vec::new(), broken: false, conn: &c };
        assert!(out.frame(b"one") && out.frame(b"three") && out.flush(Instant::now() + FLUSH_WAIT));
        let mut got = [0u8; 16];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"\0\0\0\x03one\0\0\0\x05three");
    }

    /// Reserve a distinct test address for as long as its UDP port remains bound.
    /// All concurrent root test processes share this port allocator.
    fn root_address() -> (std::net::UdpSocket, std::net::Ipv4Addr) {
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let [hi, lo] = reservation.local_addr().unwrap().port().to_be_bytes();
        (reservation, std::net::Ipv4Addr::new(198, 18, hi, lo))
    }

    /// Needs root: `sudo cargo test -- --ignored`. A TSO frame the kernel's TCP puts on a tap
    /// opened as Firecracker opens one (a 12-byte virtio-net header, checksum and TSO4 offload)
    /// is cut into segments that carry the stream as sent, each valid (#411). The test answers
    /// the host's SYN itself, as a guest would.
    #[test]
    #[ignore]
    fn a_kernel_tso_frame_is_cut_into_valid_segments() {
        let tap = format!("tso{:x}t0", std::process::id());
        let (_address, ip) = root_address();
        crate::net::create_tap(&tap, "test").unwrap();
        let raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        assert!(raw >= 0, "open /dev/net/tun: {}", std::io::Error::last_os_error());
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut req = crate::net::ifreq(&tap).unwrap();
        req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short;
        let hdr: libc::c_int = 12;
        let ok = |what: &str, r: libc::c_int| assert_eq!(r, 0, "{what}: {}", std::io::Error::last_os_error());
        unsafe {
            ok("TUNSETIFF", libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &req));
            ok("TUNSETVNETHDRSZ", libc::ioctl(fd.as_raw_fd(), 0x4004_54d8, &hdr));
            ok("TUNSETOFFLOAD", libc::ioctl(fd.as_raw_fd(), 0x4004_54d0, 0x3 as libc::c_ulong /* CSUM, TSO4 */));
        }
        crate::net::set_link_up(&tap, true).unwrap();
        crate::net::attach(ip, &tap).unwrap();
        let mut buf = vec![0u8; 70000];
        let mut next = |what: &dyn Fn(&[u8]) -> bool| loop {
            assert!(crate::util::readable(&fd, Duration::from_secs(5)).unwrap(), "no frame came");
            let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 && what(&buf[..n as usize]) {
                break buf[..n as usize].to_vec();
            }
        };
        let tcp = |f: &[u8]| f.len() > 12 + 14 + 40 && f[12 + 12..12 + 14] == [8, 0] && f[12 + 14 + 9] == 6;
        let data: Vec<u8> = (0..60000u32).map(|i| (i % 251) as u8).collect();
        let sent = data.clone();
        let sender = std::thread::spawn(move || {
            let mut c = TcpStream::connect((ip, 7000)).unwrap();
            c.write_all(&sent).unwrap();
            c
        });
        // Its SYN, answered: a SYN-ACK with an MSS of 1460 and a 64 KiB window.
        let syn = next(&|f| tcp(f) && f[12 + 14 + 33] == 0x02);
        let p = &syn[26..];
        let mut synack = [&p[16..20], &p[12..16]].concat();
        synack.splice(0..0, [0x45, 0, 0, 44, 0, 0, 0x40, 0, 64, 6, 0, 0]);
        let isn = u32::from_be_bytes(p[24..28].try_into().unwrap());
        synack.extend_from_slice(&[0x1b, 0x58]);
        synack.extend_from_slice(&p[20..22]);
        synack.extend_from_slice(&5000u32.to_be_bytes());
        synack.extend_from_slice(&(isn + 1).to_be_bytes());
        synack.extend_from_slice(&[0x60, 0x12, 0xff, 0xff, 0, 0, 0, 0, 2, 4, 0x05, 0xb4]);
        let sum = !sum16(&synack[..20]);
        synack[10..12].copy_from_slice(&sum.to_be_bytes());
        let sum = !sum16(&[&synack[12..20], &[0, 6, 0, 24], &synack[20..]].concat());
        synack[36..38].copy_from_slice(&sum.to_be_bytes());
        let frame = [&[0u8; 12][..], &crate::net::GATEWAY_MAC, &crate::net::GUEST_MAC, &[8, 0], &synack].concat();
        assert_eq!(unsafe { libc::write(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) }, frame.len() as isize);
        let tso = next(&|f| tcp(f) && f[1] & 0x7f == 1);
        let segs = cut(&tso).unwrap();
        let (first, mut joined) = (u32::from_be_bytes(segs[0][24..28].try_into().unwrap()), Vec::new());
        assert!(segs.len() >= 2, "{} segments", segs.len());
        for s in &segs {
            let pseudo = [&s[12..20], &[0, 6], &(s.len() as u16 - 20).to_be_bytes()].concat();
            assert!(ipv4_header_csum_ok(s) && sum16(&[&pseudo[..], &s[20..]].concat()) == 0xffff && s.len() - 40 <= 1460);
            assert_eq!(u32::from_be_bytes(s[24..28].try_into().unwrap()), first + joined.len() as u32, "in sequence");
            joined.extend_from_slice(&s[40..]);
        }
        let at = (first - isn - 1) as usize;
        assert_eq!(joined, data[at..at + joined.len()], "the stream as sent");
        drop(fd);
        crate::net::delete_tap(&tap);
        drop(sender);
    }

    /// Needs root: `sudo cargo test -- --ignored`. A sender that looked the route up before a
    /// release hands its packet to the device after it (#254), here by binding to the device:
    /// it is re-sent to where the address went, never lost uncounted.
    #[test]
    #[ignore]
    fn stragglers_follow_the_address() {
        let (a, b) =
            (Holder::new(&format!("tsa{:x}h", std::process::id())).unwrap().unwrap(), Holder::new(&format!("tsb{:x}h", std::process::id())).unwrap().unwrap());
        let (_address, ip) = root_address();
        a.hold(ip, 1).unwrap();
        let mut none = |_: &[u8]| true;
        let (_, switched) = a.release_local(ip, 1, &mut none, || b.hold(ip, 2), Duration::ZERO).unwrap();
        switched.unwrap();
        let s = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let dev = a.dev.as_bytes();
        assert_eq!(unsafe { libc::setsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_BINDTODEVICE, dev.as_ptr().cast(), dev.len() as u32) }, 0);
        s.send_to(b"late", (ip, 9)).unwrap();
        let mut got = Vec::new();
        let mut sink = |p: &[u8]| {
            got.push(p.to_vec());
            true
        };
        std::thread::sleep(Duration::from_millis(200));
        let (stats, _) = b.release_local(ip, 2, &mut sink, || Ok(()), Duration::ZERO).unwrap();
        b.forget(ip, 2);
        let _ = crate::net::route_dev(false, ip, b.ifindex);
        assert_eq!((stats.packets, stats.dropped), (1, 0));
        assert!(got[0].ends_with(b"late") && got[0][8] == 63, "{got:?}");
        // A fragment with IP ID 0 would get a new ID if re-sent (no longer reassembling with its
        // siblings): counted as dropped instead. One with an ID is re-sent.
        let counts = |a: &Holder| a.gone.lock().unwrap().get(&ip).map(|g| (g.resent, g.dropped)).unwrap();
        let mut frag = [0x45u8, 0, 0, 28, 0, 0, 0x20, 0, 64, 17, 0, 0, 10, 100, 254, 1, 10, 100, 254, 9, 0, 1, 0, 9, 0, 8, 0, 0];
        frag[16..20].copy_from_slice(&ip.octets());
        let before = counts(&a);
        a.straggler(ip, &mut frag);
        assert_eq!(counts(&a), (before.0, before.1 + 1));
        frag[4..6].copy_from_slice(&[0x12, 0x34]);
        a.straggler(ip, &mut frag);
        assert_eq!(counts(&a), (before.0 + 1, before.1 + 1));
    }
}
