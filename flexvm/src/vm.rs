use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::net::{Ipv4Addr, Shutdown};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::{Firecracker, Idle, Spawner, API_TIMEOUT};
use crate::template::{Template, BALLOON_STATS_S};
use crate::uffd::{Origin, Pager, Runs};
use crate::util::{Phases, Result, PAGE_SIZE};

const PULL_WAIT: Duration = Duration::from_secs(30);
/// A clock request slower than this may have left the guest that far behind.
pub const CLOCK_RTT: Duration = Duration::from_millis(5);
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
    pub vsock: PathBuf,
    cgroup: Option<PathBuf>,
    was_paused: AtomicBool,
    pub clock_pending: AtomicBool,
    /// Restored held paused at a new address: the guest still has this old one.
    pub pending_net: Mutex<Option<Ipv4Addr>>,
    /// Discards after this count mean the saved state and memory may disagree.
    pub snapshot_discards: AtomicU64,
    /// (dir, id) of the last write-tracked checkpoint: a delta's base.
    pub last_checkpoint: Mutex<Option<(PathBuf, String)>>,
    /// A kill is waiting: a checkpoint in progress gives up (and clears it).
    pub cancel_checkpoint: AtomicUsize,
}

impl Vm {
    /// `kill` (test fault `resume_kill`) kills Firecracker right after the request is sent.
    pub fn start(&self, kill: bool) -> Result<()> {
        self.fc(|fc| {
            let res = fc.resume();
            if kill {
                self.pager.kill_firecracker();
                bail!("injected fault: firecracker killed after the resume was sent");
            }
            res
        })?;
        *self.state.lock().unwrap() = State::Running;
        Ok(())
    }

    /// The part of a restore that needs no vmstate, done by a migration target before its source pauses.
    pub fn prepare(idle: Idle, template: Arc<Template>, phases: &mut Phases) -> Result<Prepared> {
        crate::compat::check(&template, idle.fc.pid())?;
        let pager = Pager::start(&idle.fc.sockets.uffd, template.clone(), None)?;
        let prepared = Prepared { idle: Some(idle), pager, template, route: true };
        prepared.pager.set_pid(prepared.firecracker().pid())?;
        phases.mark("pager_start");
        Ok(prepared)
    }

    /// Cannot grow here: refused a plug, or throttled at its memory mark.
    pub fn starving(&self) -> bool {
        self.starved.load(Ordering::SeqCst) || self.limit.throttled.load(Ordering::SeqCst)
    }

    /// (MiB it holds or still pages in, the guest's size).
    pub fn mem_sizes(&self) -> (u64, u64) {
        mem_sizes(&self.pager, &self.template, self.hotplug_plugged())
    }

    /// Sets its memory mark once it runs here: what its start was admitted
    /// (`granted`); what it holds and still pages in beyond that (`sizes`)
    /// is admitted first (refused, it is throttled until a step is).
    pub fn start_limit(&self, granted: u64, (need, cap): (u64, u64), host: &crate::host::Host) {
        let more = need.saturating_sub(granted);
        let admitted = if more > 0 && host.admit(more) { need } else { granted };
        self.limit.start(admitted, cap);
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
        match self.fc.lock().unwrap().as_mut() {
            Some(fc) => fc.post_mortem(&self.dir),
            None => "no firecracker".into(),
        }
    }

    /// One busy with a request counts as alive.
    pub fn firecracker_alive(&self) -> bool {
        self.fc.try_lock().map_or(true, |mut fc| fc.as_mut().is_some_and(|f| f.alive()))
    }

    pub fn pid(&self) -> Option<u32> {
        self.fc.lock().unwrap().as_ref().map(|f| f.pid())
    }

    pub fn rss(&self) -> u64 {
        self.pid().and_then(|p| crate::util::proc_kb(&format!("/proc/{p}/status"), "VmRSS")).unwrap_or(0)
    }

    /// Saves device and vCPU state and returns page states matching it. Paused vCPUs do not
    /// stop devices writing memory, so execs close, `unroute` holds packets and the tap goes
    /// down. `resume` undoes this; a target calls `restore_devices`.
    pub fn save_state(&self, vmstate: &Path, sync: bool, park: bool, unroute: impl FnOnce(), t: &mut Phases) -> Result<Runs> {
        if park {
            self.park_balloon()?;
            t.mark("park_balloon");
        }
        for (_, s) in self.execs.lock().unwrap().drain() {
            let _ = s.shutdown(Shutdown::Both);
        }
        unroute();
        t.mark("hold");
        // Even if paused: only an API pause freezes device emulation.
        self.fc(|fc| fc.pause())?;
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

    /// Its write must precede the snapshot.
    pub fn park_balloon(&self) -> Result<()> {
        self.fc(|fc| fc.patch("/balloon/statistics", json!({"stats_polling_interval_s": u16::MAX})).map(drop))
    }

    /// For a migration (`Source`) or a checkpoint.
    pub fn leave(&self, to: State) -> Result<()> {
        let _devices = self.devices.lock().unwrap();
        let leavable = |st: State| -> Result<()> {
            if !matches!(st, State::Running | State::Paused) || self.pager.failed().is_some() {
                bail!("vm {} is not running here", self.name);
            }
            if self.pager.remote_left() > 0 {
                bail!("vm {} is still pulling its memory from its previous host or checkpoint", self.name);
            }
            if self.pending_net.lock().unwrap().is_some() {
                bail!("vm {} has not taken its new address yet; resume it first", self.name);
            }
            Ok(())
        };
        leavable(*self.state.lock().unwrap())?;
        // The agent serves in order, so an answered ping means a lost clock request landed.
        if self.clock_unsure.load(Ordering::SeqCst) {
            crate::guest::ping(&self.vsock).map_err(|e| format!("vm {}: guest agent not answering: {e}", self.name))?;
            self.clock_unsure.store(false, Ordering::SeqCst);
        }
        let mut st = self.state.lock().unwrap();
        leavable(*st)?;
        self.was_paused.store(*st == State::Paused, Ordering::SeqCst);
        *st = to;
        Ok(())
    }

    pub fn was_paused(&self) -> bool {
        self.was_paused.load(Ordering::SeqCst)
    }

    pub fn resume(&self) -> Result<State> {
        crate::net::set_link_up(&self.tap, true)?;
        // The link-down took the VM's /32 route with it.
        crate::net::attach(self.ip, &self.tap)?;
        self.unpark_balloon();
        self.limit.restore();
        if self.was_paused.swap(false, Ordering::SeqCst) {
            return Ok(State::Paused);
        }
        self.fc(|fc| fc.resume())?;
        Ok(State::Running)
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

    pub fn end_checkpoint(&self) -> Result<State> {
        if *self.state.lock().unwrap() != State::Checkpointing {
            bail!("vm {} is not being checkpointed", self.name);
        }
        let res: Result<State> = self.resume().map_err(|e| format!("resuming vm {} after its checkpoint failed: {e}", self.name).into());
        *self.state.lock().unwrap() = *res.as_ref().unwrap_or(&State::Failed);
        res
    }

    pub fn pause(&self) -> Result<()> {
        self.switch(State::Running, State::Paused)
    }

    /// A migration target first pulls all its memory, so it never runs split across two hosts.
    pub fn unpause(&self) -> Result<()> {
        if self.pager.pulling_from_peer() && !self.pager.wait_pulled(Some(PULL_WAIT)) {
            bail!("vm {} is still pulling its memory from its previous host; resume it once that is done", self.name);
        }
        self.switch(State::Paused, State::Running)
    }

    fn switch(&self, from: State, to: State) -> Result<()> {
        match self.state() {
            s if s == to => return Ok(()),
            s if s != from => bail!("vm {} is {}, not {}", self.name, s.name(), from.name()),
            _ => {}
        }
        self.fc(|fc| if to == State::Paused { fc.pause() } else { fc.resume() })?;
        *self.state.lock().unwrap() = to;
        Ok(())
    }

    fn running_here(&self) -> Result<()> {
        if self.state() != State::Running {
            bail!("vm {} is not running here", self.name);
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
        loop {
            let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            let hp = self.hotplug(left)?;
            let (requested, plugged) = (hp["requested_size_mib"].as_u64(), hp["plugged_size_mib"].as_u64());
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

    pub fn sh(&self, cmd: &str, deadline: Instant) -> Result<(i32, String)> {
        const MAX_OUTPUT: usize = 64 << 10;
        if self.state() != State::Running || Instant::now() >= deadline {
            bail!("vm {} is not running here, or no time is left", self.name);
        }
        let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        let raw = crate::util::connect_unix(&self.vsock, left)?;
        let id = self.track(&raw)?;
        let sid = crate::guest::session_id()?;
        let res = (|| -> Result<(i32, String)> {
            let s = crate::util::By { s: raw.try_clone()?, at: deadline };
            let mut g = crate::guest::handshake(s, &format!("SESSION {sid} {}", cmd.len()))?;
            g.get_mut().write_all(cmd.as_bytes())?;
            let mut out = Vec::new();
            let code = crate::guest::exec_output(&mut g, &sid, |_, d| {
                out.extend_from_slice(&d[..d.len().min(MAX_OUTPUT.saturating_sub(out.len()))]);
                Ok(())
            })
            .map_err(|e| format!("guest command {cmd:?}: {e}"))?;
            let _ = crate::guest::close(&self.vsock, &sid, deadline);
            Ok((code, String::from_utf8_lossy(&out).into_owned()))
        })();
        let _ = raw.shutdown(Shutdown::Both);
        self.untrack_exec(id);
        res
    }

    /// Returns the offset (ms); the guest ends up behind by a request's transit, so slow
    /// round trips are repeated.
    pub fn sync_clock(&self, deadline: Instant) -> Result<f64> {
        static WARNED: AtomicBool = AtomicBool::new(false);
        let mut first = None;
        for tries in 1.. {
            let start = Instant::now();
            match crate::guest::clock(&self.vsock, &self.template.legacy_agent, deadline.saturating_duration_since(start)) {
                Ok(Some(off)) => {
                    let off = *first.get_or_insert(off);
                    if start.elapsed() < CLOCK_RTT || Instant::now() + Duration::from_millis(200) >= deadline {
                        return Ok(off);
                    }
                    // A guest still faulting its memory in answers slowly.
                    if tries >= 3 {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                Ok(None) => {
                    if first.is_none() && !WARNED.swap(true, Ordering::Relaxed) {
                        eprintln!("vm {}: its guest agent cannot set the clock (no CLOCK); clocks of such VMs are left alone", self.name);
                    }
                    return Ok(first.unwrap_or(0.0));
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
                Err(e) if rejected(&e, PATH) || self.pid().is_none() => {
                    self.reports_held.store(false, Ordering::SeqCst);
                    return Err(e);
                }
                Err(e) if Instant::now() >= deadline => return Err(e),
                Err(e) => {
                    eprintln!("vm {}: releasing free page reports: {e}; retrying", self.name);
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
            eprintln!("vm {}: balloon statistics stay off: {e}", self.name);
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
        let res = crate::guest::start(&self.vsock, ip, dns, &self.template.legacy_agent);
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
        self.pager.stop();
        // First, so a call in progress (holding `fc`) fails at once.
        self.pager.kill_firecracker();
        let Some(mut fc) = self.fc.lock().unwrap().take() else { return };
        let _ = UnixStream::connect(self.mem_sock());
        // Reaped only once the pager has stopped, so its pid is not reused under the pager.
        self.pager.join();
        fc.kill();
        crate::fc::release(&self.tap, self.cgroup.as_deref(), &self.dir);
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
            "vcpus": self.template.meta.vcpus,
            "rss_mib": self.rss() >> 20,
            "guest_mib": self.template.meta.mem_mib + hotplug["plugged_size_mib"].as_u64().unwrap_or(0),
            "max_mib": self.template.meta.max_mib,
            "plugged_mib": hotplug["plugged_size_mib"],
            "admitted_mib": self.limit.admitted(),
            "cgroup_mib": self.limit.used(),
            "throttled": self.limit.throttled.load(Ordering::SeqCst),
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
    idle: Option<Idle>,
    pub pager: Arc<Pager>,
    template: Arc<Template>,
    /// Routes the VM's /32 to its tap while loading; a migration target does it at commit.
    route: bool,
}

impl Prepared {
    pub fn template(&self) -> Arc<Template> {
        self.template.clone()
    }

    pub fn firecracker(&self) -> &Firecracker {
        &self.idle.as_ref().unwrap().fc
    }

    /// The load leaves the address's route alone (a migration target routes it at commit).
    pub fn unrouted(mut self) -> Prepared {
        self.route = false;
        self
    }

    pub fn tap(&self) -> &str {
        &self.idle.as_ref().unwrap().tap
    }

    /// As `Vm::mem_sizes`, for a loaded one.
    pub fn mem_sizes(&self) -> (u64, u64) {
        let plugged = self.firecracker().get("/hotplug/memory").ok().and_then(|h| h["plugged_size_mib"].as_u64());
        mem_sizes(&self.pager, &self.template, plugged)
    }

    pub fn dir(&self) -> &Path {
        &self.idle.as_ref().unwrap().dir
    }

    pub fn firecracker_alive(&mut self) -> bool {
        self.idle.as_mut().is_some_and(|i| i.fc.alive())
    }

    pub fn into_vm(mut self, name: &str, ip: Ipv4Addr, state: State) -> Arc<Vm> {
        let (fc, dir, cgroup, tap) = self.idle.take().unwrap().into_parts();
        Arc::new(Vm {
            name: name.into(),
            template: self.template.clone(),
            dir,
            ip,
            tap,
            pager: self.pager.clone(),
            state: Mutex::new(state),
            last_resize: Mutex::new(Instant::now()),
            starved: AtomicBool::new(false),
            limit: crate::limit::Limit::new(cgroup.clone()),
            reports_held: AtomicBool::new(false),
            cow_copy: Mutex::new(false),
            execs: Mutex::new(HashMap::new()),
            devices: Mutex::new(()),
            clock_unsure: AtomicBool::new(false),
            next_exec: AtomicU64::new(0),
            vsock: fc.sockets.vsock.clone(),
            fc: Mutex::new(Some(fc)),
            cgroup,
            was_paused: AtomicBool::new(false),
            clock_pending: AtomicBool::new(false),
            pending_net: Mutex::new(None),
            snapshot_discards: AtomicU64::new(0),
            last_checkpoint: Mutex::new(None),
            cancel_checkpoint: AtomicUsize::new(0),
        })
    }

    /// Does the template-only part of the coming load (`firecracker/0002-*.patch`); false,
    /// changing nothing, if unsupported.
    pub fn prepare_load(&self) -> Result<bool> {
        static UNSUPPORTED: AtomicBool = AtomicBool::new(false);
        if UNSUPPORTED.load(Ordering::Relaxed) {
            return Ok(false);
        }
        // Before the request: Firecracker connects to the pager during it.
        self.pager.expect_seed(true);
        match self.firecracker().load_snapshot(&self.template.vmstate(), self.tap(), None, API_TIMEOUT) {
            Ok(_) => Ok(true),
            Err(e) if e.to_string().contains("Invalid request method and/or path") => {
                self.pager.expect_seed(false);
                if !UNSUPPORTED.swap(true, Ordering::Relaxed) {
                    eprintln!("firecracker cannot prepare snapshot loads ({e}); migrations load the whole snapshot while paused");
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
        eprintln!("vm {name}: load failed ({e}); once more on a fresh firecracker{}", if realtime { "" } else { ", without clock_realtime" });
        before_retry()?;
        let mut fresh = Vm::prepare(spawner.take(deadline)?, tpl, t)?;
        fresh.route = route;
        if !route {
            // The route waits, but everything else about it goes on the fresh tap.
            crate::net::neighbour(ip, fresh.tap())?;
        }
        fresh.load_once(name, vmstate, seed, ip, hold, realtime, deadline, t).map_err(|(e, _)| e)
    }

    /// On failure, whether another (and with `clock_realtime`) may work.
    #[allow(clippy::too_many_arguments)]
    fn load_once(
        mut self,
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
                    let p = self.dir().join("vmstate.in");
                    std::fs::write(&p, b)?;
                    t.mark("write_state");
                    p
                }
            };
            let fc = self.firecracker();
            let tap = self.tap().to_string();
            let route = self.route.then(|| std::thread::spawn(move || crate::net::attach(ip, &tap)));
            let loaded = fc.load_snapshot(&path, self.tap(), Some(clock_realtime), left(API_TIMEOUT));
            self.pager.loaded();
            let took = t.mark("snapshot_load");
            if let Err(e) = &loaded {
                load_failed = Some(e.to_string());
            }
            let held = loaded.and_then(|_| {
                if hold {
                    // Only an API pause holds device emulation.
                    fc.request_within("PATCH", "/vm", Some(json!({"state": "Paused"})), left(API_TIMEOUT))?;
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
                let idle = self.idle.as_mut().unwrap();
                let retry = match &load_failed {
                    Some(why) if why.contains(NO_REALTIME) && clock_realtime => Some(false),
                    // Died on its own, with no page given up.
                    Some(_) if !self.pager.lost_pages() && !idle.fc.alive() => Some(clock_realtime),
                    _ => None,
                };
                eprintln!("vm {name}: restore failed: {e} ({})", idle.fc.post_mortem(&idle.dir));
                Err((e, retry))
            }
        }
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(idle) = self.idle.take() {
            self.pager.stop();
            self.pager.kill_firecracker();
            // Reaped only once the pager has stopped (see `Vm::kill`).
            self.pager.join();
            drop(idle);
        }
    }
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
        for m in ["firecracker PATCH /balloon/reporting/hold: out of time", "firecracker PATCH /balloon/reporting/hold: 500 oops",
                  "Resource temporarily unavailable (os error 11)", "firecracker PATCH /balloon/reporting/release: 400 x"] {
            assert!(!rejected(m));
        }
    }
}
