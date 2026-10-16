use std::collections::HashMap;
use std::io::BufReader;
use std::net::{Ipv4Addr, Shutdown};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::{Firecracker, Spawner, API_TIMEOUT};
use crate::template::{Template, BALLOON_STATS_S};
use crate::uffd::{Origin, Pager, Runs};
use crate::util::{Phases, Result, PAGE_SIZE};

/// How long a VM about to be paused gets to take what is queued on its tap (`Vm::drain_tap`).
/// It runs meanwhile; only what reaches its held address waits.
const TAP_DRAIN_WAIT: Duration = Duration::from_millis(500);

const PULL_WAIT: Duration = Duration::from_secs(30);
/// A clock request slower than this may have left the guest that far behind.
pub const CLOCK_RTT: Duration = Duration::from_millis(5);
/// What a guest call is refused with while a checkpoint (a suspend's too) has
/// the VM paused: a running command's reattach waits it out.
pub const CHECKPOINTING: &str = " is being checkpointed; try again once it is done";
const NO_REALTIME: &str = "clock_realtime requested but not present in the snapshot state";

/// The vmstate a VM is restored from.
#[derive(Clone, Copy)]
pub enum Snapshot<'a> {
    Path(&'a Path),
    /// Written next to the Firecracker that loads them.
    Bytes(&'a [u8]),
}

/// Where a VM is; transitions happen under its process's operation lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Running,
    Paused,
    Checkpointing,
    /// Paused for migration `.0`: never resumed unless the target says it aborted.
    Source(u64),
    Failed,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Running => "running",
            State::Paused => "paused",
            State::Checkpointing => "checkpointing",
            State::Source(_) => "source",
            State::Failed => "failed",
        }
    }

    /// Whether the VM's address is served from this host.
    pub fn local(self) -> bool {
        matches!(self, State::Running | State::Paused | State::Checkpointing)
    }
}

/// How long setting a VM's first memory mark waits for the host lock to admit more.
const ADMIT_WAIT: Duration = Duration::from_millis(500);

pub struct Vm {
    pub name: String,
    pub template: Arc<Template>,
    pub dir: PathBuf,
    pub ip: Ipv4Addr,
    pub tap: String,
    pub pager: Arc<Pager>,
    pub state: Mutex<State>,
    pub last_resize: Mutex<Instant>,
    pub starved: AtomicBool,
    /// Growth the reserve refused is not asked for again until this expires.
    pub grant_backoff: Mutex<crate::vmproc::GrantBackoff>,
    pub limit: crate::limit::Limit,
    reports_held: AtomicBool,
    /// During a copy-on-write checkpoint the VM may grow, not shrink: resizes hold this.
    pub cow_copy: Mutex<bool>,
    /// Host ends of exec sessions, so a checkpoint can close them.
    execs: Mutex<HashMap<u64, UnixStream>>,
    /// Serializes `restore_devices` with leaving for a migration or checkpoint.
    devices: Mutex<()>,
    /// A failed clock request may still reach the guest: `leave` waits it out.
    clock_unsure: AtomicBool,
    next_exec: AtomicU64,
    fc: Mutex<Option<Firecracker>>,
    /// Its Firecracker's (pid) tap descriptor, copied (`tap_watch`).
    tap_watch: Mutex<Option<(u32, Arc<OwnedFd>)>>,
    /// Paused with frames still queued on its tap that its guest did not take (`drain_tap`), until it runs again.
    tap_stuck: AtomicBool,
    /// How many of the tap's drops were reported with injected packets (`tap_drops_reported`).
    tap_drops_reported: AtomicU64,
    pub vsock: PathBuf,
    was_paused: AtomicBool,
    pub clock_pending: AtomicBool,
    /// Restored at a new address the guest has not taken yet.
    pub pending_net: AtomicBool,
    /// Discards after this count mean the saved state and memory may disagree.
    pub snapshot_discards: AtomicU64,
    /// (dir, id) of the last write-tracked checkpoint: a delta's base.
    pub last_checkpoint: Mutex<Option<(PathBuf, String)>>,
    /// A kill is waiting: a checkpoint in progress gives up (and clears it).
    pub cancel_checkpoint: AtomicUsize,
    /// Its Firecracker died (`mark_dead`): waits on it end at once.
    dead: AtomicBool,
    /// Whether `state` is known after the last pause or resume (see `Unsure`).
    unsure: Mutex<Unsure>,
    /// Its tap could not be raised or routed when it resumed: the next `unpause` does that first.
    link_down: AtomicBool,
}

/// After a pause or resume: `Pause`, its outcome Firecracker could not tell (`state` may be wrong, so the next `switch`
/// asks); `Resume`, a resume failed and the VM could not be paused again, so Firecracker saying Paused proves nothing
/// (see `after_failed_resume`).
#[derive(Clone, Copy, PartialEq)]
enum Unsure {
    Settled,
    Pause,
    Resume,
}

impl Vm {
    /// `kill` (test fault `resume_kill`) kills Firecracker right after the request is sent.
    pub fn start(&self, kill: bool) -> Result<()> {
        self.fc(|fc| {
            let res = fc.resume(API_TIMEOUT);
            if kill {
                self.pager.kill_firecracker();
                bail!("injected fault: firecracker killed after the resume was sent");
            }
            res
        })?;
        self.record(State::Running);
        Ok(())
    }

    /// The part of a restore that needs no vmstate, done by a migration target before its source pauses.
    pub fn prepare(fc: Firecracker, template: Arc<Template>, phases: &mut Phases) -> Result<Prepared> {
        crate::compat::check(&template, fc.pid())?;
        let prepared = Prepared::new(fc, template)?;
        phases.mark("pager_start");
        Ok(prepared)
    }

    /// Cannot grow here: refused a plug, or throttled at its memory mark.
    /// Only while it runs here (a migration's source sits at its mark through the pull).
    pub fn starving(&self) -> bool {
        self.state() == State::Running && (self.starved.load(Ordering::SeqCst) || self.limit.throttled.load(Ordering::SeqCst))
    }

    /// (MiB it holds or still pages in, the guest's size).
    pub fn mem_sizes(&self) -> (u64, u64) {
        mem_sizes(&self.pager, &self.template, self.hotplug_plugged())
    }

    /// Sets its memory mark once it runs here: at once what its start was
    /// admitted (`granted`), then what it holds and still pages in beyond
    /// that (`sizes`), if admitted within `ADMIT_WAIT` (refused, or not
    /// answered by then, it stays at its mark until the watcher admits a step).
    /// An arrival's was admitted before its commit (`Proc::admit_arrival`).
    pub fn start_limit(&self, granted: u64, (need, cap): (u64, u64), host: &crate::host::Host) {
        self.limit.start(granted, cap);
        let more = need.saturating_sub(granted);
        if more == 0 {
            return;
        }
        match host.grant(more, Some(Instant::now() + ADMIT_WAIT)) {
            Ok(Some(_)) => self.limit.plug(cap, more),
            Ok(None) => {}
            Err(e) => crate::log!("vm {}: admitting {more} MiB: {e}", self.name),
        }
    }

    pub fn mem_sock(&self) -> PathBuf {
        PathBuf::from(format!("{}_{}", self.vsock.display(), crate::guest::MEM_PORT))
    }

    pub fn state(&self) -> State {
        match self.pager.failed() {
            Some(_) => State::Failed,
            None => *self.state.lock().unwrap(),
        }
    }

    pub fn fc<R>(&self, f: impl FnOnce(&Firecracker) -> Result<R>) -> Result<R> {
        match self.fc.lock().unwrap().as_ref() {
            Some(fc) => f(fc),
            None => bail!("vm {} is not running", self.name),
        }
    }

    pub fn post_mortem(&self) -> String {
        match self.fc.lock().unwrap().as_ref() {
            Some(fc) => fc.post_mortem(),
            None => "no firecracker".into(),
        }
    }

    /// Its Firecracker died: whatever operation is in progress is cut short
    /// rather than waited out. Guest calls fail without retrying, waits on
    /// Firecracker give up, and the pager stops (`kill` still reaps
    /// Firecracker only once the pager has stopped).
    pub fn mark_dead(&self) {
        self.dead.store(true, Ordering::SeqCst);
        crate::guest::abandon(&self.vsock);
        self.pager.stop();
    }

    pub fn dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// One busy with a request counts as alive.
    pub fn firecracker_alive(&self) -> bool {
        self.fc.try_lock().map_or(true, |fc| fc.as_ref().is_some_and(|f| f.alive()))
    }

    pub fn pid(&self) -> Option<u32> {
        self.fc.lock().unwrap().as_ref().map(|f| f.pid())
    }

    pub fn rss(&self) -> u64 {
        self.pid().and_then(|p| crate::util::proc_kb(&format!("/proc/{p}/status"), "VmRSS")).unwrap_or(0)
    }

    /// Saves device and vCPU state and returns page states matching it. Paused vCPUs do not
    /// stop devices writing memory, so execs close, `unroute` holds packets and the tap goes
    /// down. `resume` undoes this; a target calls `restore_devices`. Once `unroute` says the
    /// address is held, the guest takes what is still queued on its tap before the pause.
    pub fn save_state(&self, vmstate: &Path, sync: bool, park: bool, unroute: impl FnOnce() -> bool, t: &mut Phases) -> Result<Runs> {
        // No huge-page collapse in flight or starting during the pause (`resume` lets it go on).
        self.pager.hold_collapse(true);
        if park {
            self.park_balloon()?;
            t.mark("park_balloon");
        }
        for (_, s) in self.execs.lock().unwrap().drain() {
            let _ = s.shutdown(Shutdown::Both);
        }
        // Before the hold: finding it can wait on RTNL (`net::tap_fd_of`).
        let watch = self.tap_watch();
        // `tap_backlog_stuck` keeps it stopped until the wait for the queue gave up too.
        let stuck = crate::host::fault("tap_backlog_stuck");
        let stopped = (stuck || crate::host::fault("tap_backlog")).then(|| self.pid()).flatten();
        if let Some(pid) = stopped {
            // Frames pile up on the tap while Firecracker is stopped, more than the guest has
            // buffers for, and the address is held before it goes on: a queue to take. Stopped
            // until one is there, however late a loaded sender's first frames come (#294).
            crate::log!("vm {}: injected fault: stopping firecracker for 200 ms or until frames queue on its tap, holding its address meanwhile", self.name);
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
            std::thread::sleep(Duration::from_millis(200));
            let until = Instant::now() + Duration::from_secs(5);
            while watch.as_ref().is_some_and(|fd| !crate::net::tap_queued(fd).unwrap_or(true)) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let go_on = || {
            if let Some(pid) = stopped {
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) };
            }
        };
        let held = unroute();
        // Read while its Firecracker is still stopped, so a guest that empties the queue before
        // `drain_tap` first looks is still seen to have had one (#294).
        let backlog = stopped.is_some() && watch.as_ref().is_some_and(|fd| crate::net::tap_queued(fd).unwrap_or(false));
        if !stuck {
            go_on();
        }
        t.mark("hold");
        if let (true, Some(fd)) = (held, watch) {
            // Not read off here: resumed (a checkpoint, an aborted migration), its Firecracker
            // delivers them once the guest posts buffers. `kill` counts what is left.
            let emptied = self.drain_tap(&fd, backlog);
            self.tap_stuck.store(!emptied, Ordering::SeqCst);
            t.mark("drain_tap");
        }
        if stuck {
            go_on();
        }
        // Even if paused: only an API pause freezes device emulation.
        self.fc(|fc| fc.pause(API_TIMEOUT))?;
        t.mark("pause");
        // Link-down waits for an RCU grace period; joined on every path so `resume` never races it.
        let tap = self.tap.clone();
        let down = std::thread::spawn(move || crate::net::set_link_up(&tap, false));
        let saved = self.fc(|fc| {
            self.snapshot_discards.store(self.pager.discards(), Ordering::SeqCst);
            fc.put("/snapshot/create", json!({"snapshot_type": "Full", "snapshot_path": vmstate, "mem_file_path": "", "sync_snapshot_files": sync}))
        });
        t.mark("snapshot_create");
        let down = down.join().unwrap_or_else(|_| Err("link-down thread panicked".into()));
        t.mark("link_down");
        saved?;
        down?;
        let runs = self.pager.quiesce_export()?;
        t.mark("export_runs");
        Ok(runs)
    }

    /// A copy of its Firecracker's descriptor of its tap (`net::tap_fd_of`), found once per
    /// Firecracker; None (said why) if it cannot be had.
    fn tap_watch(&self) -> Option<Arc<OwnedFd>> {
        let pid = self.pid()?;
        let mut w = self.tap_watch.lock().unwrap();
        if let Some((_, fd)) = w.as_ref().filter(|(p, _)| *p == pid) {
            return Some(fd.clone());
        }
        match crate::net::tap_fd_of(pid, &self.tap) {
            Ok(fd) => {
                let fd = Arc::new(fd);
                *w = Some((pid, fd.clone()));
                Some(fd)
            }
            Err(e) => {
                crate::log!("vm {}: not waiting for its tap's queue before the pause: {e}", self.name);
                None
            }
        }
    }

    /// With its address held nothing new reaches the tap, so the running guest empties its
    /// queue unless it stops taking frames; false if it has not by `TAP_DRAIN_WAIT`. `queued`:
    /// a queue was already seen there since the hold.
    fn drain_tap(&self, fd: &OwnedFd, queued: bool) -> bool {
        // Paused, its guest takes nothing: no use waiting.
        if self.was_paused() {
            return match crate::net::tap_queued(fd) {
                Ok(queued) => {
                    if queued {
                        crate::log!("vm {}: frames still queued on its tap, which its paused guest does not take", self.name);
                    }
                    !queued
                }
                Err(e) => {
                    crate::log!("vm {}: not waiting for its tap's queue before the pause: {e}", self.name);
                    true
                }
            };
        }
        let start = Instant::now();
        let mut queued = queued;
        loop {
            match crate::net::tap_queued(fd) {
                Ok(false) => break,
                Ok(true) => queued = true,
                Err(e) => {
                    crate::log!("vm {}: not waiting for its tap's queue before the pause: {e}", self.name);
                    return true;
                }
            }
            if start.elapsed() >= TAP_DRAIN_WAIT {
                crate::log!(
                    "vm {}: frames still queued on its tap {} ms after its address was held; pausing it anyway",
                    self.name,
                    start.elapsed().as_millis()
                );
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if queued {
            crate::log!("vm {}: its guest took what was queued on its tap in {:.1} ms before the pause", self.name, start.elapsed().as_secs_f64() * 1e3);
        }
        true
    }

    /// What is queued on its tap, read off it. Its Firecracker paused, that reached the tap after
    /// `drain_tap` last looked, from a sender that looked the route up before the hold (#379).
    pub fn take_tap_queue(&self, each: &mut dyn FnMut(&[u8])) {
        self.tap_stuck.store(false, Ordering::SeqCst);
        if let Some((_, fd)) = self.tap_watch.lock().unwrap().as_ref() {
            crate::net::read_tap_queue(fd, each);
        }
    }

    /// `n` of the tap's drops were reported (with packets a hold injected); `tap_dropped` leaves them out.
    pub fn tap_drops_reported(&self, n: u64) {
        self.tap_drops_reported.fetch_add(n, Ordering::SeqCst);
    }

    /// Frames the tap dropped, its queue full, that were not reported with injected packets.
    pub fn tap_dropped(&self) -> Option<u64> {
        let n = std::fs::read_to_string(format!("/sys/class/net/{}/statistics/tx_dropped", self.tap)).ok()?.trim().parse::<u64>().ok()?;
        Some(n.saturating_sub(self.tap_drops_reported.load(Ordering::SeqCst)))
    }

    /// Its write must precede the snapshot.
    pub fn park_balloon(&self) -> Result<()> {
        self.fc(|fc| fc.patch("/balloon/statistics", json!({"stats_polling_interval_s": u16::MAX})).map(drop))
    }

    /// For a migration (`Source`) or a checkpoint.
    pub fn leave(&self, to: State) -> Result<()> {
        let _devices = self.devices.lock().unwrap();
        self.can_leave()?;
        let mut st = self.state.lock().unwrap();
        self.leavable(*st)?;
        self.was_paused.store(*st == State::Paused, Ordering::SeqCst);
        *st = to;
        Ok(())
    }

    /// `leave`'s checks, also run before a keep-running checkpoint arms write tracking.
    pub fn can_leave(&self) -> Result<()> {
        self.leavable(self.state())?;
        // Whether it was paused is recorded by `leave` and kept (a checkpoint returns it to that, a migration's
        // target starts so): after a pause or resume that ended unknown, Firecracker must say which.
        if self.reconcile().is_none() {
            bail!(
                "vm {}: an earlier pause or resume ended unknown and firecracker cannot say whether it is paused; pause or resume it, then try again",
                self.name
            );
        }
        // The agent serves in order, so an answered ping means a lost clock request landed.
        if self.clock_unsure.load(Ordering::SeqCst) {
            crate::guest::ping(&self.vsock).map_err(|e| format!("vm {}: guest agent not answering: {e}", self.name))?;
            self.clock_unsure.store(false, Ordering::SeqCst);
        }
        Ok(())
    }

    fn leavable(&self, st: State) -> Result<()> {
        if !matches!(st, State::Running | State::Paused) || self.pager.failed().is_some() {
            bail!("vm {} is not running here", self.name);
        }
        if self.pager.remote_left() > 0 {
            bail!("vm {} is still pulling its memory from its previous host or checkpoint", self.name);
        }
        if self.pending_net.load(Ordering::SeqCst) {
            bail!("vm {} has not taken its new address yet; resume it first", self.name);
        }
        Ok(())
    }

    /// Back in service (Running or Paused), undoes `quiesce_export`: the prefetch and collapse it cut short go on.
    pub fn back_here(&self) {
        if matches!(self.state(), State::Running | State::Paused) {
            self.pager.unquiesce();
        }
    }

    pub fn was_paused(&self) -> bool {
        self.was_paused.load(Ordering::SeqCst)
    }

    /// On failure its state is settled (`settle_failed_resume`) and returned with the error.
    pub fn resume(&self, attached: bool) -> std::result::Result<State, (State, crate::util::Error)> {
        let resumed = self.resume_vcpus(attached);
        self.after_resume(resumed.is_ok());
        resumed.map_err(|e| (self.settle_failed_resume(), e))
    }

    /// The part of `resume` the guest waits for: its devices back and its vCPUs running (unless it was paused before).
    fn resume_vcpus(&self, attached: bool) -> Result<State> {
        // A successful held-packet release already raised the link and attached it.
        if crate::host::fault("resume_link_fail") {
            self.link_down.store(true, Ordering::SeqCst);
            bail!("injected fault: raising its tap failed");
        }
        if !attached {
            self.link_up()?;
        }
        // Kept paused, its frames stay queued on the tap (`tap_stuck`) until it runs again.
        let resumed = match self.was_paused.swap(false, Ordering::SeqCst) {
            true => Ok(State::Paused),
            false => self.fc(|fc| fc.resume(API_TIMEOUT)).map(|()| State::Running),
        };
        if matches!(resumed, Ok(State::Running)) {
            self.running_again();
        }
        resumed
    }

    /// The rest of `resume`, with the guest already running: balloon statistics back on (slow, behind Firecracker's
    /// post-resume queue processing, #190) and the memory mark restored.
    pub fn after_resume(&self, resumed: bool) {
        // Out of the pause, but with the mark still lifted: Firecracker throttled at it could time this out.
        if resumed {
            self.unpark_balloon();
        }
        self.limit.restore();
    }

    /// Routes the address to the tap (its neighbour entry is there: `net::neighbour`)
    /// unless the VM left meanwhile (a checkpoint's or migration's hold routes it then).
    /// Under `state` (not `devices`, which a slow balloon request may hold): `leave` changes
    /// it before the hold routes the address elsewhere.
    pub fn route_here(&self) -> Result<()> {
        self.if_here(|| crate::net::route_dev(true, self.ip, crate::net::ifindex(&self.tap)?)).map(drop)
    }

    /// Runs `f` (which routes the address) unless the VM left; false if it had.
    pub fn if_here(&self, f: impl FnOnce() -> Result<()>) -> Result<bool> {
        let st = self.state.lock().unwrap();
        if !matches!(*st, State::Running | State::Paused) || self.pager.failed().is_some() {
            return Ok(false);
        }
        f()?;
        Ok(true)
    }

    /// `resume_vcpus` after a checkpoint; the caller does `after_resume`.
    pub fn end_checkpoint(&self, attached: bool) -> Result<State> {
        if *self.state.lock().unwrap() != State::Checkpointing {
            bail!("vm {} is not being checkpointed", self.name);
        }
        let res = self.resume_vcpus(attached);
        let now = match &res {
            Ok(s) => {
                self.record(*s);
                *s
            }
            Err(_) => self.settle_failed_resume(),
        };
        res.map_err(|e| format!("resuming vm {} after its checkpoint failed: {e}; it is {}", self.name, now.name()).into())
    }

    /// Raises its tap and routes its address there; failing, it is left for the next `unpause`.
    fn link_up(&self) -> Result<()> {
        let res = crate::net::set_link_up(&self.tap, true).and_then(|()| crate::net::attach(self.ip, &self.tap));
        self.link_down.store(res.is_err(), Ordering::SeqCst);
        res
    }

    /// After a resume that failed: Running if Firecracker says so (only once every vCPU acknowledged), else paused
    /// again explicitly (twice at most: a vCPU's late answer to the resume may be read first); None if neither.
    /// Firecracker saying Paused proves nothing: it resumes vCPUs one by one and says Paused until all acknowledge
    /// (and answers a failed resume 400), so some may have run.
    fn after_failed_resume(&self) -> Option<State> {
        if self.fc_state() == Some(State::Running) {
            return Some(State::Running);
        }
        self.pager.hold_collapse(true);
        // Test fault `repause_fail`: the pause after it fails too.
        let pause = || {
            if crate::host::fault("repause_fail") {
                Err("injected fault: pausing it again failed".into())
            } else {
                self.fc(|fc| fc.pause(API_TIMEOUT))
            }
        };
        (0..2).any(|_| pause().is_ok()).then_some(State::Paused)
    }

    /// `after_failed_resume`, recorded; Paused but unsure if it cannot be had (the next pause or resume tries again).
    /// Never Failed: it can still be resumed.
    fn settle_failed_resume(&self) -> State {
        let now = self.after_failed_resume();
        *self.unsure.lock().unwrap() = if now.is_none() { Unsure::Resume } else { Unsure::Settled };
        let now = now.unwrap_or(State::Paused);
        self.record(now);
        now
    }

    pub fn pause(&self) -> Result<()> {
        self.switch(State::Running, State::Paused)
    }

    /// A migration target first pulls all its memory, so it never runs split across two hosts. Waits up to
    /// `PULL_WAIT`: callers do it before taking the host lock (#334), which `unpause` then finds done.
    pub fn await_peer_pages(&self) -> Result<()> {
        if self.pager.pulling_from_peer() && !self.pager.wait_pulled(Some(PULL_WAIT)) {
            bail!("vm {} is still pulling its memory from its previous host; resume it once that is done", self.name);
        }
        Ok(())
    }

    pub fn unpause(&self) -> Result<()> {
        self.await_peer_pages()?;
        if self.link_down.load(Ordering::SeqCst) {
            self.link_up().map_err(|e| format!("vm {}: raising its network: {e}", self.name))?;
        }
        self.switch(State::Paused, State::Running)
    }

    fn switch(&self, from: State, to: State) -> Result<()> {
        let mut state = self.state();
        // After an unknown outcome, Firecracker says where it is (recorded, so a failure below leaves the record
        // right); if it still cannot, the request is sent all the same.
        if matches!(state, State::Running | State::Paused) {
            state = self.reconcile().unwrap_or(from);
        }
        match state {
            s if s == to => return Ok(()),
            s if s != from => bail!("vm {} is {}, not {}", self.name, s.name(), from.name()),
            _ => {}
        }
        let pausing = to == State::Paused;
        if pausing {
            self.pager.hold_collapse(true);
        }
        // Test faults `pause_fail` and `resume_partial` (a resume some vCPUs missed: Firecracker still says Paused).
        let mut res = match crate::host::fault(if pausing { "pause_fail" } else { "resume_partial" }) {
            true => Err(format!("injected fault: firecracker PATCH /vm: 400 the {} failed part way", if pausing { "pause" } else { "resume" }).into()),
            false => self.fc(|fc| if pausing { fc.pause(API_TIMEOUT) } else { fc.resume(API_TIMEOUT) }).map(drop),
        };
        // Test fault `pause_lost`: the pause landed, but its answer is lost.
        if pausing && res.is_ok() && crate::host::fault("pause_lost") {
            res = Err("injected fault: the pause's answer was lost".into());
        }
        // A timeout or a lost answer may still have switched it: Firecracker says which state it is in. If that cannot
        // be had either, it is recorded as it was but unsure (collapsing held, after a pause), so the next pause or
        // resume asks again or sends its request whatever the record says.
        let resume_failed = *self.unsure.lock().unwrap() == Unsure::Resume;
        let now = match &res {
            Ok(()) => Some(to),
            // Not `rejected`: a resume that failed part way is answered 400 too.
            Err(_) if !pausing => self.after_failed_resume(),
            // Still unsettled after a failed resume: only Firecracker saying Running (every vCPU acknowledged) settles
            // it here, never its saying Paused (some vCPUs may run) nor a refusal.
            Err(_) if resume_failed => self.fc_state().filter(|&s| s == State::Running),
            Err(e) if rejected(e, "/vm") => Some(from),
            Err(_) => self.fc_state(),
        };
        // Recorded whichever it is (a failed resume may find it still paused).
        if let Some(s) = now {
            self.record(s);
        }
        // A failed resume's is kept until an explicit pause succeeds or Running is confirmed.
        *self.unsure.lock().unwrap() = match now {
            Some(_) => Unsure::Settled,
            None if resume_failed || !pausing => Unsure::Resume,
            None => Unsure::Pause,
        };
        if now == Some(to) {
            if let Err(e) = &res {
                crate::log!("vm {}: {e}, but firecracker is {}", self.name, to.name());
            }
            return Ok(());
        }
        res
    }

    /// Whether a pause or resume ended unknown (see `switch`).
    pub fn switch_unsure(&self) -> bool {
        *self.unsure.lock().unwrap() != Unsure::Settled
    }

    /// Its state, after a pause or resume that ended unknown first recorded as Firecracker has it, or after a failed
    /// resume as `after_failed_resume` makes it (settling `unsure`); None if that cannot be had.
    fn reconcile(&self) -> Option<State> {
        let unsure = *self.unsure.lock().unwrap();
        if unsure != Unsure::Settled {
            // After a resume that failed, Firecracker saying Paused proves nothing: it is paused again instead.
            self.record(if unsure == Unsure::Resume { self.after_failed_resume() } else { self.fc_state() }?);
            *self.unsure.lock().unwrap() = Unsure::Settled;
        }
        Some(self.state())
    }

    fn record(&self, s: State) {
        *self.state.lock().unwrap() = s;
        if s == State::Running {
            self.running_again();
        }
    }

    /// Its vCPUs run again: collapsing goes on, and its Firecracker delivers what is still queued on its tap.
    fn running_again(&self) {
        self.pager.hold_collapse(false);
        self.tap_stuck.store(false, Ordering::SeqCst);
    }

    /// Paused or Running, as Firecracker has it (test fault `pause_unknown`: it cannot say).
    fn fc_state(&self) -> Option<State> {
        if crate::host::fault("pause_unknown") {
            return None;
        }
        self.fc(|fc| fc.get("/")).ok().and_then(|info| match info["state"].as_str() {
            Some("Paused") => Some(State::Paused),
            Some("Running") => Some(State::Running),
            _ => None,
        })
    }

    fn running_here(&self) -> Result<()> {
        match self.state() {
            State::Running => {}
            State::Paused => bail!("vm {} is paused; resume it with flexvm resume {}", self.name, self.name),
            State::Checkpointing => bail!("vm {}{CHECKPOINTING}", self.name),
            _ => bail!("vm {} is not running here", self.name),
        }
        Ok(())
    }

    pub fn set_failed(&self) {
        *self.state.lock().unwrap() = State::Failed;
    }

    pub fn hotplug_plugged(&self) -> Option<u64> {
        self.hotplug(crate::guest::TIMEOUT).ok()?["plugged_size_mib"].as_u64()
    }

    fn hotplug(&self, within: Duration) -> Result<Value> {
        self.fc(|fc| fc.request_within("GET", "/hotplug/memory", None, within))
    }

    /// Waits out the last virtio-mem resize, whose requests discard memory even with vCPUs
    /// paused; past half of `deadline` it requests the plugged size. Callers hold the op lock.
    pub fn settle_hotplug(&self, deadline: Instant) -> Result<()> {
        if self.template.meta.max_mib <= self.template.meta.mem_mib {
            return Ok(());
        }
        let half = Instant::now() + deadline.saturating_duration_since(Instant::now()) / 2;
        let mut gave_up = false;
        // Test fault `settle_unpause`: the test paused the vCPUs to hold a resize until now.
        let mut unpause = crate::host::fault("settle_unpause");
        loop {
            let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            let hp = self.hotplug(left)?;
            let (requested, plugged) = (hp["requested_size_mib"].as_u64(), hp["plugged_size_mib"].as_u64());
            if std::mem::take(&mut unpause) {
                crate::log!("vm {}: injected fault: resuming its vCPUs at {plugged:?} of {requested:?} MiB plugged", self.name);
                self.fc(|fc| fc.resume(API_TIMEOUT))?;
            }
            if requested.is_some() && requested == plugged {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("vm {}: virtio-mem did not settle (requested {requested:?} MiB, plugged {plugged:?} MiB)", self.name);
            }
            if let Some(p) = plugged.filter(|_| !gave_up && Instant::now() >= half) {
                self.fc(|fc| fc.request_within("PATCH", "/hotplug/memory", Some(json!({"requested_size_mib": p})), left))?;
                gave_up = true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn restore_devices(&self) {
        let _devices = self.devices.lock().unwrap();
        if matches!(self.state(), State::Running | State::Paused) {
            self.unpark_balloon();
        }
    }

    fn track(&self, s: &UnixStream) -> Result<u64> {
        let id = self.next_exec.fetch_add(1, Ordering::SeqCst);
        self.execs.lock().unwrap().insert(id, s.try_clone()?);
        if let Err(e) = self.running_here() {
            self.untrack_exec(id);
            let _ = s.shutdown(Shutdown::Both);
            return Err(e);
        }
        Ok(id)
    }

    /// Returns the offset (ms); the guest ends up behind by a request's transit, so slow
    /// round trips are repeated.
    pub fn sync_clock(&self, deadline: Instant) -> Result<f64> {
        let mut first = None;
        for tries in 1.. {
            let start = Instant::now();
            match crate::guest::clock(&self.vsock, deadline.saturating_duration_since(start)) {
                Ok(off) => {
                    let off = *first.get_or_insert(off);
                    if start.elapsed() < CLOCK_RTT || Instant::now() + Duration::from_millis(200) >= deadline {
                        return Ok(off);
                    }
                    // A guest still faulting its memory in answers slowly.
                    if tries >= 3 {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                Err(e) => {
                    self.clock_unsure.store(true, Ordering::SeqCst);
                    return Err(e);
                }
            }
        }
        unreachable!()
    }

    /// So no discard reaches the pager while a CoW checkpoint copies (`firecracker/0003-*.patch`).
    /// Counts as held until a release lands, unless Firecracker rejects it.
    pub fn hold_reports(&self) -> Result<()> {
        const PATH: &str = "/balloon/reporting/hold";
        self.reports_held.store(true, Ordering::SeqCst);
        let res = self.fc(|fc| fc.request_within("PATCH", PATH, None, Duration::from_secs(1)));
        if res.as_ref().is_err_and(|e| rejected(e, PATH)) {
            self.reports_held.store(false, Ordering::SeqCst);
        }
        res.map(drop)
    }

    /// A release that fails stays due (`release_pending`) for the controller.
    pub fn release_reports(&self, within: Duration) -> Result<()> {
        const PATH: &str = "/balloon/reporting/release";
        let deadline = Instant::now() + within;
        while self.reports_held.load(Ordering::SeqCst) {
            match self.fc(|fc| fc.request_within("PATCH", PATH, None, deadline.saturating_duration_since(Instant::now()))) {
                Ok(_) => self.reports_held.store(false, Ordering::SeqCst),
                Err(e) if rejected(&e, PATH) || self.pid().is_none() || self.dead() => {
                    self.reports_held.store(false, Ordering::SeqCst);
                    return Err(e);
                }
                Err(e) if Instant::now() >= deadline => return Err(e),
                Err(e) => {
                    crate::log!("vm {}: releasing free page reports: {e}; retrying", self.name);
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        Ok(())
    }

    pub fn release_pending(&self) -> bool {
        self.reports_held.load(Ordering::SeqCst)
    }

    fn unpark_balloon(&self) {
        let deadline = Instant::now() + Duration::from_millis(500);
        let body = json!({"stats_polling_interval_s": BALLOON_STATS_S});
        let res = loop {
            match self.fc(|fc| fc.request_within("PATCH", "/balloon/statistics", Some(body.clone()), deadline.saturating_duration_since(Instant::now()))) {
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                r => break r,
            }
        };
        if let Err(e) = res {
            crate::log!("vm {}: balloon statistics stay off: {e}", self.name);
        }
    }

    /// Registers the session (so a checkpoint can close it) before `start` talks to the guest.
    pub fn exec(&self, start: impl FnOnce(UnixStream) -> Result<BufReader<UnixStream>>) -> Result<(BufReader<UnixStream>, u64)> {
        self.running_here()?;
        let s = crate::util::connect_unix(&self.vsock, crate::guest::TIMEOUT)?;
        let id = self.track(&s)?;
        match start(s).and_then(|g| crate::guest::untimed(&g).map(|()| g)) {
            Ok(g) => Ok((g, id)),
            Err(e) => {
                self.untrack_exec(id);
                Err(e)
            }
        }
    }

    /// A failure leaves the clock unsure (see `leave`).
    pub fn guest_net(&self, ip: Ipv4Addr, dns: Option<&str>) -> Result<()> {
        self.running_here()?;
        let res = crate::guest::start(&self.vsock, ip, dns);
        if res.is_err() {
            self.clock_unsure.store(true, Ordering::SeqCst);
        }
        res
    }

    pub fn start_app(&self) -> Result<u32> {
        self.running_here()?;
        crate::guest::start_app(&self.vsock)
    }

    pub fn untrack_exec(&self, id: u64) {
        self.execs.lock().unwrap().remove(&id);
    }

    pub fn kill(&self) {
        teardown(&self.pager, || {
            let fc = self.fc.lock().unwrap().take()?;
            // Before the tap goes (`fc::release`) with its counters: a full queue drops frames
            // (a guest not keeping up), counted only there.
            if let Some(n) = self.tap_dropped().filter(|&n| n > 0) {
                crate::log!("vm {}: its tap dropped {n} frames (its queue full, or no Firecracker reading it)", self.name);
            }
            // Before the tap goes too, which purges its queue; not keeping it after.
            if let Some((_, fd)) = self.tap_watch.lock().unwrap().take() {
                if self.tap_stuck.swap(false, Ordering::SeqCst) {
                    // Gone (not reaped, so its pid is not reused), so no read of its races these.
                    let gone = crate::util::pidfd_open(fc.pid()).and_then(|p| crate::util::readable(&p, Duration::from_secs(2)));
                    if !matches!(gone, Ok(true)) {
                        crate::log!("vm {}: firecracker not seen gone ({gone:?}); counting what is left on its tap anyway", self.name);
                    }
                    let n = crate::net::read_tap_queue(&fd, &mut |_| {});
                    crate::log!("vm {}: dropped {n} frames still queued on its tap when it left (its guest was not taking them)", self.name);
                }
            }
            let _ = UnixStream::connect(self.mem_sock());
            Some(fc)
        });
    }

    pub fn describe(&self) -> Value {
        let [base, present, zero, remote, inflight, discarded] = self.pager.census();
        let mib = |pages: usize| (pages * PAGE_SIZE) as u64 >> 20;
        let hotplug = self.hotplug(Duration::from_millis(500)).unwrap_or(Value::Null);
        json!({
            "name": self.name,
            "ip": self.ip.to_string(),
            "tap": self.tap,
            "pid": self.pid(),
            "template": self.template.name,
            "template_id": self.template.meta.id,
            "regions": self.pager.regions(),
            "state": self.state().name(),
            "state_unsure": self.switch_unsure(),
            "vcpus": self.template.meta.vcpus,
            "rss_mib": self.rss() >> 20,
            "guest_mib": self.template.meta.mem_mib + hotplug["plugged_size_mib"].as_u64().unwrap_or(0),
            "max_mib": self.template.meta.max_mib,
            "plugged_mib": hotplug["plugged_size_mib"],
            "admitted_mib": self.limit.admitted(),
            "cgroup_mib": self.limit.used(),
            "throttled": self.limit.throttled.load(Ordering::SeqCst),
            "tap_dropped": self.tap_dropped(),
            "requested_mib": hotplug["requested_size_mib"],
            "pages_mib": {"base": mib(base), "present": mib(present), "zero": mib(zero), "remote": mib(remote + inflight + discarded)},
            "checkpoint_copy": self.pager.copying(),
            "write_tracking": self.pager.tracking(),
        })
    }
}

fn mem_sizes(pager: &Pager, tpl: &Template, plugged: Option<u64>) -> (u64, u64) {
    let [_, present, _, remote, inflight, discarded] = pager.census();
    let need = ((present + remote + inflight + discarded) * PAGE_SIZE) as u64 >> 20;
    (need, tpl.meta.mem_mib + plugged.unwrap_or(tpl.meta.max_mib - tpl.meta.mem_mib))
}

/// A Firecracker with its pager started and no VM of its own yet; torn down when dropped.
pub struct Prepared {
    fc: Option<Firecracker>,
    pub pager: Arc<Pager>,
    template: Arc<Template>,
    /// Routes the VM's /32 to its tap while loading; a migration target does it at commit.
    route: bool,
}

impl Prepared {
    pub fn new(fc: Firecracker, template: Arc<Template>) -> Result<Self> {
        let pager = Pager::start(&fc.sockets.uffd, template.clone(), None)?;
        let p = Prepared { fc: Some(fc), pager, template, route: true };
        p.pager.set_pid(p.firecracker().pid())?;
        Ok(p)
    }

    pub fn template(&self) -> Arc<Template> {
        self.template.clone()
    }

    pub fn firecracker(&self) -> &Firecracker {
        self.fc.as_ref().unwrap()
    }

    /// The load leaves the address's route alone (a migration target routes it at commit).
    pub fn unrouted(mut self) -> Prepared {
        self.route = false;
        self
    }

    /// As `Vm::mem_sizes`, for a loaded one.
    pub fn mem_sizes(&self) -> (u64, u64) {
        let plugged = self.firecracker().get("/hotplug/memory").ok().and_then(|h| h["plugged_size_mib"].as_u64());
        mem_sizes(&self.pager, &self.template, plugged)
    }

    pub fn into_vm(mut self, name: &str, ip: Ipv4Addr, state: State) -> Arc<Vm> {
        let idle = self.fc.take().unwrap();
        Arc::new(Vm {
            name: name.into(),
            template: self.template.clone(),
            dir: idle.dir.clone(),
            ip,
            tap: idle.tap.clone(),
            pager: self.pager.clone(),
            state: Mutex::new(state),
            last_resize: Mutex::new(Instant::now()),
            starved: AtomicBool::new(false),
            grant_backoff: Mutex::default(),
            limit: crate::limit::Limit::new(idle.cgroup.clone()),
            reports_held: AtomicBool::new(false),
            cow_copy: Mutex::new(false),
            execs: Mutex::new(HashMap::new()),
            devices: Mutex::new(()),
            clock_unsure: AtomicBool::new(false),
            next_exec: AtomicU64::new(0),
            vsock: idle.sockets.vsock.clone(),
            fc: Mutex::new(Some(idle)),
            tap_watch: Mutex::new(None),
            tap_stuck: AtomicBool::new(false),
            tap_drops_reported: AtomicU64::new(0),
            was_paused: AtomicBool::new(false),
            clock_pending: AtomicBool::new(false),
            pending_net: AtomicBool::new(false),
            snapshot_discards: AtomicU64::new(0),
            last_checkpoint: Mutex::new(None),
            cancel_checkpoint: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
            unsure: Mutex::new(Unsure::Settled),
            link_down: AtomicBool::new(false),
        })
    }

    /// Does the template-only part of the coming load (`firecracker/0002-*.patch`); false,
    /// changing nothing, if unsupported.
    /// Given up at `by` (Firecracker's answer included).
    pub fn prepare_load(&self, by: Instant) -> Result<bool> {
        static UNSUPPORTED: AtomicBool = AtomicBool::new(false);
        if UNSUPPORTED.load(Ordering::Relaxed) {
            return Ok(false);
        }
        let wait = API_TIMEOUT.min(by.saturating_duration_since(Instant::now()));
        if wait.is_zero() {
            bail!("out of time to prepare the snapshot load");
        }
        // Before the request: Firecracker connects to the pager during it.
        self.pager.expect_seed(true);
        match self.firecracker().load_snapshot(&self.template.vmstate(), &self.firecracker().tap, None, wait) {
            Ok(_) => Ok(true),
            Err(e) if e.to_string().contains("Invalid request method and/or path") => {
                self.pager.expect_seed(false);
                if !UNSUPPORTED.swap(true, Ordering::Relaxed) {
                    crate::log!("firecracker cannot prepare snapshot loads ({e}); migrations load the whole snapshot while paused");
                }
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Loads with vCPUs (and with `hold`, devices) stopped. A failed load never ran the guest,
    /// so if a fresh Firecracker could do it, it is retried once after `before_retry`.
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        self,
        spawner: &Spawner,
        name: &str,
        vmstate: Snapshot,
        seed: Option<(Runs, Origin)>,
        ip: Ipv4Addr,
        hold: bool,
        deadline: Option<Instant>,
        before_retry: impl FnOnce() -> Result<()>,
        t: &mut Phases,
    ) -> Result<(Arc<Vm>, Duration)> {
        let (tpl, route) = (self.template.clone(), self.route);
        let (e, realtime) = match self.load_once(name, vmstate, seed.clone(), ip, hold, true, deadline, t) {
            Ok(r) => return Ok(r),
            Err((e, None)) => return Err(e),
            Err((e, Some(realtime))) => (e, realtime),
        };
        crate::log!("vm {name}: load failed ({e}); once more on a fresh firecracker{}", if realtime { "" } else { ", without clock_realtime" });
        before_retry()?;
        let mut fresh = Vm::prepare(spawner.take(deadline)?, tpl, t)?;
        fresh.route = route;
        if !route {
            // The route waits, but everything else about it goes on the fresh tap.
            crate::net::neighbour(ip, &fresh.firecracker().tap)?;
        }
        fresh.load_once(name, vmstate, seed, ip, hold, realtime, deadline, t).map_err(|(e, _)| e)
    }

    /// On failure, whether another (and with `clock_realtime`) may work.
    #[allow(clippy::too_many_arguments)]
    fn load_once(
        self,
        name: &str,
        vmstate: Snapshot,
        seed: Option<(Runs, Origin)>,
        ip: Ipv4Addr,
        hold: bool,
        clock_realtime: bool,
        deadline: Option<Instant>,
        t: &mut Phases,
    ) -> std::result::Result<(Arc<Vm>, Duration), (crate::util::Error, Option<bool>)> {
        let left = |most: Duration| deadline.map_or(most, |d| d.saturating_duration_since(Instant::now()).min(most));
        let mut load_failed = None;
        let loaded = (|| -> Result<Duration> {
            if let Some((runs, origin)) = seed {
                self.pager.seed(runs, origin)?;
            }
            let path = match vmstate {
                Snapshot::Path(p) => p.to_path_buf(),
                Snapshot::Bytes(b) => {
                    let p = self.firecracker().dir.join("vmstate.in");
                    std::fs::write(&p, b)?;
                    t.mark("write_state");
                    p
                }
            };
            let fc = self.firecracker();
            let tap = fc.tap.clone();
            let route = self.route.then(|| std::thread::spawn(move || crate::net::attach(ip, &tap)));
            // Before `left` is read: the deadline covers it too.
            fc.join_cgroup();
            let loaded = fc.load_snapshot(&path, &fc.tap, Some(clock_realtime), left(API_TIMEOUT));
            if matches!(vmstate, Snapshot::Bytes(_)) {
                let _ = std::fs::remove_file(&path);
            }
            self.pager.loaded();
            let took = t.mark("snapshot_load");
            if let Err(e) = &loaded {
                load_failed = Some(e.to_string());
            }
            let held = loaded.and_then(|_| {
                if hold {
                    self.pager.hold_collapse(true);
                    // Only an API pause holds device emulation.
                    fc.pause(left(API_TIMEOUT))?;
                    t.mark("hold_paused");
                }
                self.pager.wait_ready(left(Duration::from_secs(5)))
            });
            let routed = route.map_or(Ok(Ok(())), |r| r.join()).map_err(|_| "route thread panicked")?;
            held?;
            routed?;
            t.mark("route_wait");
            Ok(took)
        })();
        match loaded {
            Ok(took) => Ok((self.into_vm(name, ip, State::Paused), took)),
            Err(e) => {
                let idle = self.fc.as_ref().unwrap();
                let retry = match &load_failed {
                    Some(why) if why.contains(NO_REALTIME) && clock_realtime => Some(false),
                    // Died on its own, with no page given up.
                    Some(_) if !self.pager.lost_pages() && !idle.alive() => Some(clock_realtime),
                    _ => None,
                };
                crate::log!("vm {name}: restore failed: {e} ({})", idle.post_mortem());
                Err((e, retry))
            }
        }
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if self.fc.is_some() {
            teardown(&self.pager, || self.fc.take());
        }
    }
}

/// Kills before taking the API lock; reaps only once the pager has stopped.
fn teardown(pager: &Pager, take: impl FnOnce() -> Option<Firecracker>) {
    pager.stop();
    pager.kill_firecracker();
    let Some(fc) = take() else { return };
    pager.join();
    drop(fc);
}

/// A 4xx to a PATCH of `path` means it had no effect; anything else may have been applied.
fn rejected(e: &crate::util::Error, path: &str) -> bool {
    e.to_string().strip_prefix(&format!("firecracker PATCH {path}: ")).is_some_and(|r| r.starts_with('4'))
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_client_error_means_nothing_was_held() {
        let p = "/balloon/reporting/hold";
        let rejected = |m: &str| super::rejected(&m.into(), p);
        assert!(rejected("firecracker PATCH /balloon/reporting/hold: 400 {\"fault_message\":\"x\"}"));
        for m in [
            "firecracker PATCH /balloon/reporting/hold: out of time",
            "firecracker PATCH /balloon/reporting/hold: 500 oops",
            "Resource temporarily unavailable (os error 11)",
            "firecracker PATCH /balloon/reporting/release: 400 x",
        ] {
            assert!(!rejected(m));
        }
    }
}
