use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
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

/// How long resuming a paused migration target waits for its memory to arrive.
const PULL_WAIT: Duration = Duration::from_secs(30);
/// A clock request slower than this may have left the guest that far behind.
pub const CLOCK_RTT: Duration = Duration::from_millis(5);
/// Firecracker's error for a snapshot without KVM's realtime clock loaded with `clock_realtime`.
const NO_REALTIME: &str = "clock_realtime requested but not present in the snapshot state";

/// The vmstate a VM is restored from.
#[derive(Clone, Copy)]
pub enum Snapshot<'a> {
    /// A file that stays put, such as a template's.
    Path(&'a Path),
    /// Bytes to write next to the Firecracker that loads them.
    Bytes(&'a [u8]),
}

/// Where a VM is; transitions happen under its process's operation lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Running,
    Paused,
    /// Paused for a checkpoint to disk; goes back to Running or Paused.
    Checkpointing,
    /// Paused here for migration `.0`: never resumed unless the target says it aborted.
    Source(u64),
    /// Its memory is lost, or it could not be resumed.
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
    /// Needs more memory than this host can give it.
    pub starved: AtomicBool,
    /// A hold of free page reports may be in place (see `hold_reports`).
    reports_held: AtomicBool,
    /// While a copy-on-write checkpoint copies the running VM it may grow
    /// (not shrink): resizes hold this, and the checkpoint takes it to end.
    pub cow_copy: Mutex<bool>,
    /// Host ends of exec sessions, so a checkpoint can close them.
    execs: Mutex<HashMap<u64, UnixStream>>,
    /// Serializes `restore_devices` with leaving for a migration or checkpoint.
    devices: Mutex<()>,
    /// A clock request failed and may still reach the guest: `leave` waits it out.
    clock_unsure: AtomicBool,
    next_exec: AtomicU64,
    fc: Mutex<Option<Firecracker>>,
    vsock: PathBuf,
    cgroup: Option<PathBuf>,
    /// Paused when its current migration or checkpoint began.
    was_paused: AtomicBool,
    /// A background clock check is queued.
    pub clock_pending: AtomicBool,
    /// Restored held paused at a new address: the guest still has this old one.
    pub pending_net: Mutex<Option<Ipv4Addr>>,
    /// The pager's discard count at the last snapshot: one after it means
    /// the saved state and memory may disagree.
    pub snapshot_discards: AtomicU64,
    /// The last checkpoint taken with write tracking (dir, id): a delta's base.
    pub last_checkpoint: Mutex<Option<(PathBuf, String)>>,
    /// A kill is waiting: a checkpoint in progress gives up (and clears it).
    pub cancel_checkpoint: AtomicUsize,
}

impl Vm {
    /// Resumes vCPUs stopped since the load. With `kill` (test fault
    /// `resume_kill`), Firecracker is killed right after the request is sent.
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

    /// The part of a restore that needs no vmstate: checks the host, starts
    /// the pager (seeded later). A migration target does it before its source pauses.
    pub fn prepare(idle: Idle, template: Arc<Template>, phases: &mut Phases) -> Result<Prepared> {
        crate::compat::check(&template, idle.fc.pid())?;
        let pager = Pager::start(&idle.fc.sockets.uffd, template.clone(), None)?;
        let prepared = Prepared { idle: Some(idle), pager, template };
        prepared.pager.set_pid(prepared.firecracker().pid())?;
        phases.mark("pager_start");
        Ok(prepared)
    }

    pub fn vsock(&self) -> PathBuf {
        self.vsock.clone()
    }

    /// Where Firecracker forwards the guest's connections to host port `MEM_PORT`.
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

    /// How its Firecracker exited, and the end of its log.
    pub fn post_mortem(&self) -> String {
        match self.fc.lock().unwrap().as_mut() {
            Some(fc) => fc.post_mortem(&self.dir),
            None => "no firecracker".into(),
        }
    }

    /// Whether its Firecracker still runs (one busy with a request does).
    pub fn firecracker_alive(&self) -> bool {
        self.fc.try_lock().map_or(true, |mut fc| fc.as_mut().is_some_and(|f| f.alive()))
    }

    pub fn pid(&self) -> Option<u32> {
        self.fc.lock().unwrap().as_ref().map(|f| f.pid())
    }

    /// Host memory this VM is actually using.
    pub fn rss(&self) -> u64 {
        self.pid().and_then(|p| crate::util::proc_kb(&format!("/proc/{p}/status"), "VmRSS")).unwrap_or(0)
    }

    /// Pauses the VM and saves its device and vCPU state (memory stays with
    /// the pager); returns the page states, taken so they match it.
    ///
    /// Paused vCPUs do not stop devices writing guest memory, so first exec
    /// sessions close, `unroute` moves the address off the tap (packets are
    /// held from then on), and after the pause the tap goes down; the balloon
    /// statistics timer is parked unless `park` was done already. `resume`
    /// undoes this; a target calls `restore_devices`. Firecracker fsyncs the
    /// state if `sync`.
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
        // Link-down waits for an RCU grace period: alongside the snapshot,
        // joined on every path so `resume` never races it.
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

    /// Parks the balloon statistics timer (its write must precede the snapshot).
    pub fn park_balloon(&self) -> Result<()> {
        self.fc(|fc| fc.patch("/balloon/statistics", json!({"stats_polling_interval_s": u16::MAX})).map(drop))
    }

    /// Marks the VM the source of migration `mig`; no exec session opens after.
    pub fn start_source(&self, mig: u64) -> Result<()> {
        self.leave(State::Source(mig))
    }

    pub fn start_checkpoint(&self) -> Result<()> {
        self.leave(State::Checkpointing)
    }

    /// Leaves Running or Paused for a migration or checkpoint.
    fn leave(&self, to: State) -> Result<()> {
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
        // A failed clock request may still be on its way: the agent serves in
        // order, so an answered ping means it landed before the snapshot.
        if self.clock_unsure.load(Ordering::SeqCst) {
            crate::guest::ping(&self.vsock()).map_err(|e| format!("vm {}: guest agent not answering: {e}", self.name))?;
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

    /// Undoes `save_state`: devices back, vCPUs resumed unless it was paused.
    pub fn resume(&self) -> Result<State> {
        crate::net::set_link_up(&self.tap, true)?;
        // The link-down took the VM's /32 route with it.
        crate::net::attach(self.ip, &self.tap)?;
        self.unpark_balloon();
        if self.was_paused.swap(false, Ordering::SeqCst) {
            return Ok(State::Paused);
        }
        self.fc(|fc| fc.resume())?;
        Ok(State::Running)
    }

    /// Ends a checkpoint that keeps the VM here: running, paused, or failed.
    pub fn end_checkpoint(&self) -> Result<State> {
        if *self.state.lock().unwrap() != State::Checkpointing {
            bail!("vm {} is not being checkpointed", self.name);
        }
        let (s, res) = match self.resume() {
            Ok(s) => (s, Ok(s)),
            Err(e) => (State::Failed, Err(format!("resuming vm {} after its checkpoint failed: {e}", self.name).into())),
        };
        *self.state.lock().unwrap() = s;
        res
    }

    pub fn pause(&self) -> Result<()> {
        match self.state() {
            State::Paused => return Ok(()),
            State::Running => {}
            s => bail!("vm {} is {}, not running", self.name, s.name()),
        }
        self.fc(|fc| fc.pause())?;
        *self.state.lock().unwrap() = State::Paused;
        Ok(())
    }

    /// Resumes a paused VM; a paused migration target first pulls all its
    /// memory, so it never runs split across two hosts.
    pub fn unpause(&self) -> Result<()> {
        if self.pager.pulling_from_peer() && !self.pager.wait_pulled_for(PULL_WAIT) {
            bail!("vm {} is still pulling its memory from its previous host; resume it once that is done", self.name);
        }
        match self.state() {
            State::Running => return Ok(()),
            State::Paused => {}
            s => bail!("vm {} is {}, not paused", self.name, s.name()),
        }
        self.fc(|fc| fc.resume())?;
        *self.state.lock().unwrap() = State::Running;
        Ok(())
    }

    pub fn set_failed(&self) {
        *self.state.lock().unwrap() = State::Failed;
    }

    pub fn hotplug_plugged(&self) -> Option<u64> {
        let hp = self.fc(|fc| fc.request_within("GET", "/hotplug/memory", None, crate::guest::TIMEOUT)).ok()?;
        hp["plugged_size_mib"].as_u64()
    }

    /// Waits until the guest has carried out the last virtio-mem resize, so
    /// none of its requests (which discard memory, paused vCPUs or not) can
    /// still come; past half of `deadline`, stops asking for a size the guest
    /// cannot reach (requested = plugged). Callers hold the operation lock.
    pub fn settle_hotplug(&self, deadline: Instant) -> Result<()> {
        if self.template.meta.max_mib <= self.template.meta.mem_mib {
            return Ok(());
        }
        let half = Instant::now() + deadline.saturating_duration_since(Instant::now()) / 2;
        let mut gave_up = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            let hp = self.fc(|fc| fc.request_within("GET", "/hotplug/memory", None, left))?;
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

    /// On a migration target: puts back the balloon timer the source parked,
    /// unless it is migrating on already.
    pub fn restore_devices(&self) {
        let _devices = self.devices.lock().unwrap();
        if matches!(self.state(), State::Running | State::Paused) {
            self.unpark_balloon();
        }
    }

    /// Registers an exec session, then checks the VM still runs here.
    fn track(&self, s: &UnixStream) -> Result<u64> {
        let id = self.next_exec.fetch_add(1, Ordering::SeqCst);
        self.execs.lock().unwrap().insert(id, s.try_clone()?);
        if self.state() != State::Running {
            self.untrack_exec(id);
            let _ = s.shutdown(Shutdown::Both);
            bail!("vm {} is not running here", self.name);
        }
        Ok(id)
    }

    /// Runs `cmd` in the guest; its exit code and (at most 64 KiB of) output,
    /// all by `deadline`.
    pub fn sh(&self, cmd: &str, deadline: Instant) -> Result<(i32, String)> {
        const MAX_OUTPUT: usize = 64 << 10;
        if self.state() != State::Running || Instant::now() >= deadline {
            bail!("vm {} is not running here, or no time is left", self.name);
        }
        let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        let s = crate::util::connect_unix(&self.vsock(), left)?;
        let raw = s.try_clone()?;
        let mut g = BufReader::new(crate::util::By { s, at: deadline });
        let id = self.track(&raw)?;
        let res = (|| -> Result<(i32, String)> {
            g.get_mut().write_all(format!("CONNECT {}\nEXEC {}\n{cmd}", crate::guest::PORT, cmd.len()).as_bytes())?;
            let mut ok = String::new();
            g.by_ref().take(64).read_line(&mut ok)?;
            if !ok.starts_with("OK") {
                bail!("vsock connect refused: {ok:?}");
            }
            let mut out = Vec::new();
            loop {
                match crate::guest::read_frame(&mut g).map_err(|e| format!("guest command {cmd:?}: {e}"))? {
                    Some((crate::guest::FRAME_EXIT, d)) if d.len() >= 4 => {
                        return Ok((i32::from_le_bytes(d[..4].try_into().unwrap()), String::from_utf8_lossy(&out).into_owned()))
                    }
                    Some((_, d)) => out.extend_from_slice(&d[..d.len().min(MAX_OUTPUT.saturating_sub(out.len()))]),
                    None => bail!("guest closed the connection before the command exited"),
                }
            }
        })();
        let _ = raw.shutdown(Shutdown::Both);
        self.untrack_exec(id);
        res
    }

    /// Steps the guest's wall clock to the host's by `deadline` (a restore
    /// leaves it where it was saved); returns how far off it was (ms). The
    /// guest ends up behind by a request's transit, so slow round trips are
    /// repeated. An agent without `CLOCK` gets no step.
    pub fn sync_clock(&self, deadline: Instant) -> Result<f64> {
        static WARNED: AtomicBool = AtomicBool::new(false);
        let mut first = None;
        for tries in 1.. {
            let start = Instant::now();
            match crate::guest::clock(&self.vsock(), &self.template.legacy_agent, deadline.saturating_duration_since(start)) {
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

    /// Holds the guest's free page reports (`firecracker/0003-*.patch`), so no
    /// discard reaches the pager while a copy-on-write checkpoint copies.
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

    /// Releases held free page reports, retrying for `within`; one that fails
    /// stays due (`release_pending`) for the controller.
    pub fn release_reports(&self, within: Duration) -> Result<()> {
        const PATH: &str = "/balloon/reporting/release";
        let deadline = Instant::now() + within;
        while self.reports_held.load(Ordering::SeqCst) {
            match self.fc(|fc| fc.request_within("PATCH", PATH, None, deadline.saturating_duration_since(Instant::now()))) {
                Ok(_) => self.reports_held.store(false, Ordering::SeqCst),
                // Nothing to release: no such endpoint, or no Firecracker.
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

    /// Best effort: only the balloon statistics go stale.
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

    /// Opens an exec session: connects, registers it (so a checkpoint can
    /// close it), and only then lets `start` talk to the guest.
    pub fn exec(&self, start: impl FnOnce(UnixStream) -> Result<BufReader<UnixStream>>) -> Result<(BufReader<UnixStream>, u64)> {
        if self.state() != State::Running {
            bail!("vm {} is not running here", self.name);
        }
        let s = crate::util::connect_unix(&self.vsock(), crate::guest::TIMEOUT)?;
        let id = self.track(&s)?;
        match start(s).and_then(|g| crate::guest::untimed(&g).map(|()| g)) {
            Ok(g) => Ok((g, id)),
            Err(e) => {
                self.untrack_exec(id);
                Err(e)
            }
        }
    }

    /// Sets the guest's address and wall clock (`START`). A failure leaves
    /// the clock unsure (see `leave`).
    pub fn guest_net(&self, ip: Ipv4Addr, dns: Option<&str>) -> Result<()> {
        if self.state() != State::Running {
            bail!("vm {} is not running here", self.name);
        }
        let res = crate::guest::start(&self.vsock(), ip, dns, &self.template.legacy_agent);
        if res.is_err() {
            self.clock_unsure.store(true, Ordering::SeqCst);
        }
        res
    }

    /// Starts an image template's app.
    pub fn start_app(&self) -> Result<u32> {
        if self.state() != State::Running {
            bail!("vm {} is not running here", self.name);
        }
        crate::guest::start_app(&self.vsock())
    }

    pub fn untrack_exec(&self, id: u64) {
        self.execs.lock().unwrap().remove(&id);
    }

    pub fn kill(&self) {
        self.pager.stop();
        // First, so a Firecracker call in progress (holding `fc`) fails at once.
        self.pager.kill_firecracker();
        let Some(mut fc) = self.fc.lock().unwrap().take() else { return };
        fc.kill();
        // Wakes the listener for guest memory requests.
        let _ = UnixStream::connect(self.mem_sock());
        self.pager.join();
        crate::fc::release(&self.tap, self.cgroup.as_deref(), &self.dir);
    }

    pub fn describe(&self) -> Value {
        let [base, present, zero, remote, inflight, discarded] = self.pager.census();
        let mib = |pages: usize| (pages * PAGE_SIZE) as u64 >> 20;
        let hotplug = self.fc(|fc| fc.request_within("GET", "/hotplug/memory", None, Duration::from_millis(500))).unwrap_or(Value::Null);
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
            "requested_mib": hotplug["requested_size_mib"],
            "pages_mib": {"base": mib(base), "present": mib(present), "zero": mib(zero), "remote": mib(remote + inflight + discarded)},
            "checkpoint_copy": self.pager.copying(),
            "write_tracking": self.pager.tracking(),
        })
    }
}

/// A Firecracker with its pager started and no VM of its own yet: about to
/// load one, or (a standby VM) holding one loaded and paused. Dropped, it is
/// torn down.
pub struct Prepared {
    idle: Option<Idle>,
    pub pager: Arc<Pager>,
    template: Arc<Template>,
}

impl Prepared {
    pub fn template(&self) -> Arc<Template> {
        self.template.clone()
    }

    pub fn firecracker(&self) -> &Firecracker {
        &self.idle.as_ref().unwrap().fc
    }

    pub fn tap(&self) -> &str {
        &self.idle.as_ref().unwrap().tap
    }

    pub fn dir(&self) -> &Path {
        &self.idle.as_ref().unwrap().dir
    }

    pub fn firecracker_alive(&mut self) -> bool {
        self.idle.as_mut().is_some_and(|i| i.fc.alive())
    }

    /// Test fault `kill_prepared`: kills the Firecracker (and waits for it).
    pub fn kill_firecracker(&mut self) {
        self.idle.as_mut().unwrap().fc.kill();
    }

    /// The VM `name` at `ip`, loaded into this Firecracker.
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

    /// Has Firecracker do the template-only part of the coming load
    /// (`firecracker/0002-*.patch`), so the load proper restores only vCPU,
    /// VM and device state. False, changing nothing, if it cannot.
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

    /// Loads `vmstate` as VM `name` at `ip` (routed to its tap), its pager
    /// seeded with `seed`, its vCPUs stopped and, with `hold`, its devices
    /// too; everything by `deadline`. The caller resumes it (`Vm::start`).
    /// A failed load never ran the guest: if a fresh Firecracker could do it
    /// (this one died on its own, or the snapshot has no realtime clock), it
    /// is tried once more on one from `spawner`, after `before_retry`.
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
        let tpl = self.template.clone();
        let (e, realtime) = match self.load_once(name, vmstate, seed.clone(), ip, hold, true, deadline, t) {
            Ok(r) => return Ok(r),
            Err((e, None)) => return Err(e),
            Err((e, Some(realtime))) => (e, realtime),
        };
        eprintln!("vm {name}: load failed ({e}); once more on a fresh firecracker{}", if realtime { "" } else { ", without clock_realtime" });
        before_retry()?;
        let fresh = Vm::prepare(spawner.take_by(deadline)?, tpl, t)?;
        fresh.load_once(name, vmstate, seed, ip, hold, realtime, deadline, t).map_err(|(e, _)| e)
    }

    /// One load; on failure, whether another (and with `clock_realtime`) may work.
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
            // Routed while Firecracker restores.
            let tap = self.tap().to_string();
            let route = std::thread::spawn(move || crate::net::attach(ip, &tap));
            let loaded = fc.load_snapshot(&path, self.tap(), Some(clock_realtime), left(API_TIMEOUT));
            self.pager.loaded();
            let took = t.mark("snapshot_load");
            if let Err(e) = &loaded {
                load_failed = Some(e.to_string());
            }
            let held = loaded.and_then(|_| {
                if hold {
                    // Only an API pause holds device emulation too.
                    fc.request_within("PATCH", "/vm", Some(json!({"state": "Paused"})), left(API_TIMEOUT))?;
                    t.mark("hold_paused");
                }
                self.pager.wait_ready(left(Duration::from_secs(5)))
            });
            let routed = route.join().map_err(|_| "route thread panicked")?;
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
            drop(idle);
            self.pager.join();
        }
    }
}

/// Whether Firecracker answered a PATCH of `path` with a 4xx: no such
/// endpoint, so it had no effect. Anything else may have been applied.
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
