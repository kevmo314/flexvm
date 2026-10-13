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
use crate::fc::{Firecracker, Idle, Spawner};
use crate::template::{Template, BALLOON_STATS_S};

/// How long resuming a paused migration target waits for its memory to arrive.
const PULL_WAIT: Duration = Duration::from_secs(30);

/// How a restored VM starts out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Load {
    Running,
    /// Paused, devices included (held in Firecracker's pause loop).
    Paused,
    /// vCPUs stopped but devices running, as Firecracker leaves a VM loaded
    /// with `resume_vm: false`: a migration target about to resume it once
    /// it owns the VM, and test fault `restore_no_hold`.
    PausedUnheld,
    /// Test fault `resume_kill` only: `Running`, but Firecracker is killed
    /// right after the resume request is sent, as if it crashed with the
    /// guest already running.
    RunningKilled,
}

impl Load {
    fn running(self) -> bool {
        matches!(self, Load::Running | Load::RunningKilled)
    }
}

/// The vmstate a VM is restored from.
#[derive(Clone, Copy)]
pub enum Snapshot<'a> {
    /// A file that stays put, such as a template's.
    Path(&'a Path),
    /// Bytes to write next to the Firecracker that loads them.
    Bytes(&'a [u8]),
}

/// Firecracker's error for a snapshot saved without KVM's realtime clock,
/// loaded with `clock_realtime`.
const NO_REALTIME: &str = "clock_realtime requested but not present in the snapshot state";

/// Why another load, on a fresh Firecracker, could succeed where one failed.
/// Every load stops the vCPUs (`resume_vm: false`), so a failed one never ran
/// the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// The Firecracker died on its own before the load, nothing given up.
    Fresh,
    /// The snapshot has no realtime clock: load it without `clock_realtime`.
    WithoutRealtime,
}

/// A snapshot load that failed, and whether another Firecracker could do it.
#[derive(Debug)]
pub struct LoadFailed {
    error: String,
    pub retry: Option<Retry>,
}

impl std::fmt::Display for LoadFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.error)
    }
}

impl std::error::Error for LoadFailed {}

/// The retry `e` (from `Prepared::load`) allows, if any.
pub fn retry_of(e: &crate::util::Error) -> Option<Retry> {
    e.downcast_ref::<LoadFailed>().and_then(|l| l.retry)
}

/// Snapshot loads started (`Prepared::load`, retries included), for tests to count.
static LOADS: AtomicU64 = AtomicU64::new(0);

pub fn loads() -> u64 {
    LOADS.load(Ordering::SeqCst)
}

use crate::uffd::{Origin, Pager, Runs};
use crate::util::{Phases, Result, PAGE_SIZE};

/// Where a VM is in its lifecycle on this host. Transitions happen under the
/// daemon's per-name operation lock (see `Daemon::reserve`); the states of a
/// VM without a Firecracker here (starting, suspended) live in the daemon.
/// A clock request that took longer than this may have left the guest that
/// far behind (see `sync_clock`).
pub const CLOCK_RTT: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Running,
    /// vCPUs stopped by `pause`, memory and devices kept.
    Paused,
    /// Paused for a checkpoint to disk; goes back to Running or Paused.
    Checkpointing,
    /// Paused here for migration `.0`: the target may own the VM from the
    /// moment it gets the state, so this copy is never resumed unless the
    /// target confirms the migration aborted.
    Source(u64),
    /// Its memory is lost (the pager gave up) or it could not be resumed.
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
    /// Free page reports may be held in Firecracker: a hold was sent and no
    /// release has landed since (see `hold_reports`).
    reports_held: AtomicBool,
    /// Host ends of exec sessions, by id, so a checkpoint can close them.
    /// Held only for map operations, never across I/O.
    execs: Mutex<HashMap<u64, UnixStream>>,
    /// Serializes putting back device settings on a migration target
    /// (`restore_devices`) with leaving for a migration or checkpoint.
    devices: Mutex<()>,
    /// A clock request (START or CLOCK) failed and may not have reached the
    /// guest yet: a migration or checkpoint must first see the agent answer
    /// (`leave`).
    clock_unsure: AtomicBool,
    next_exec: AtomicU64,
    fc: Mutex<Option<Firecracker>>,
    vsock: PathBuf,
    cgroup: Option<PathBuf>,
    /// Set by `start_source` and `start_checkpoint` for a VM that was
    /// paused: `resume` then puts it back paused (and a migration target
    /// keeps it paused).
    was_paused: AtomicBool,
    /// A background clock check is queued (see `Daemon::sync_clock_later`).
    pub clock_pending: AtomicBool,
    /// Restored held paused at a new address: the guest still has this old
    /// one, and gets the new one on its first resume.
    pub pending_net: Mutex<Option<Ipv4Addr>>,
    /// The pager's discard count just before the last snapshot: a discard
    /// after it means the saved state and memory may disagree.
    pub snapshot_discards: AtomicU64,
    /// The last checkpoint taken of this VM here while write tracking ran
    /// (its directory and id), which the next one can be a delta against.
    pub last_checkpoint: Mutex<Option<(PathBuf, String)>>,
    /// Kills waiting: a checkpoint in progress gives up (and clears it).
    pub cancel_checkpoint: AtomicUsize,
}

impl Vm {
    /// Restores `vmstate` into a fresh Firecracker, its memory served by a
    /// pager over the template plus `remote` pages (from a migration source
    /// or a checkpoint), with `ip` routed to its tap, starting it as `load`
    /// says. Marks each step in `phases`.
    ///
    /// The snapshot is loaded with the vCPUs stopped, so a load that fails
    /// never ran the guest and is tried once more, on a fresh Firecracker,
    /// when `Prepared::load` says it may (see `Retry`). A running VM is
    /// resumed only once loaded, and never retried after that: once the
    /// resume is sent the guest may have run, and running the snapshot again
    /// could repeat what it did.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        pool: &Spawner,
        name: &str,
        template: Arc<Template>,
        vmstate: Snapshot,
        remote: Option<(Runs, Origin)>,
        ip: Ipv4Addr,
        load: Load,
        phases: &mut Phases,
    ) -> Result<(Arc<Vm>, Duration)> {
        let mut clock_realtime = true;
        let mut retried = false;
        let (vm, took) = loop {
            let idle = pool.take()?;
            phases.mark("pool_take");
            let prepared = Vm::prepare(idle, template.clone(), phases)?;
            let path = match vmstate {
                Snapshot::Path(p) => p.to_path_buf(),
                Snapshot::Bytes(b) => {
                    let p = prepared.dir().join("vmstate.in");
                    std::fs::write(&p, b)?;
                    phases.mark("write_state");
                    p
                }
            };
            if let Some((runs, origin)) = &remote {
                prepared.pager.seed(runs.clone(), origin.clone())?;
            }
            let held = if load.running() { Load::PausedUnheld } else { load };
            match prepared.load(name, &path, ip, held, clock_realtime, None, phases) {
                Ok(r) => break r,
                Err(e) => match retry_of(&e) {
                    Some(Retry::WithoutRealtime) if !retried => {
                        eprintln!("vm {name}: snapshot saved without KVM's realtime clock; loading it without clock_realtime");
                        clock_realtime = false;
                    }
                    Some(Retry::Fresh) if !retried => eprintln!("vm {name}: restore failed ({e}); once more on a fresh firecracker"),
                    _ => return Err(e),
                },
            }
            retried = true;
        };
        if load.running() {
            if let Err(e) = vm.start(load == Load::RunningKilled) {
                vm.kill();
                bail!("resuming the restored vm failed (it may have run, so it is not loaded again): {e}");
            }
            *vm.state.lock().unwrap() = State::Running;
            phases.mark("resume");
        }
        Ok((vm, took))
    }

    /// Resumes the vCPUs of a VM just loaded with them stopped. With `kill`
    /// (test fault `resume_kill`), Firecracker is killed right after the
    /// request is sent.
    pub fn start(&self, kill: bool) -> Result<()> {
        self.fc(|fc| {
            let res = fc.resume();
            if kill {
                self.pager.kill_firecracker();
                bail!("injected fault: firecracker killed after the resume was sent");
            }
            res
        })
    }

    /// The part of a restore that needs no vmstate: names the cgroup and
    /// starts the pager, which gets its page states later (`Pager::seed`).
    /// A migration target does this before its source pauses.
    pub fn prepare(idle: Idle, template: Arc<Template>, phases: &mut Phases) -> Result<Prepared> {
        crate::compat::check(&template, idle.fc.pid())?;
        let pager = match Pager::start(&idle.fc.sockets.uffd, template.clone(), None) {
            Ok(p) => p,
            Err(e) => {
                drop(idle);
                return Err(e);
            }
        };
        let prepared = Prepared { idle: Some(idle), pager, template };
        prepared.pager.set_pid(prepared.idle.as_ref().unwrap().fc.pid())?;
        phases.mark("pager_start");
        Ok(prepared)
    }

    /// A VM made of a restored Firecracker and its resources.
    pub fn assemble(name: &str, template: Arc<Template>, idle: Idle, ip: Ipv4Addr, pager: Arc<Pager>, state: State) -> Arc<Vm> {
        let (fc, dir, cgroup, tap) = idle.into_parts();
        Arc::new(Vm {
            name: name.into(),
            template,
            dir,
            ip,
            tap,
            pager,
            state: Mutex::new(state),
            last_resize: Mutex::new(Instant::now()),
            starved: AtomicBool::new(false),
            reports_held: AtomicBool::new(false),
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

    pub fn vsock(&self) -> PathBuf {
        self.vsock.clone()
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

    /// Whether its Firecracker still runs. A Firecracker busy with a request
    /// counts as running.
    pub fn firecracker_alive(&self) -> bool {
        match self.fc.try_lock() {
            Ok(mut fc) => fc.as_mut().is_some_and(|f| f.alive()),
            Err(_) => true,
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.fc.lock().unwrap().as_ref().map(|f| f.pid())
    }

    /// Host memory this VM is actually using.
    pub fn rss(&self) -> u64 {
        self.pid()
            .and_then(|p| crate::util::proc_kb(&format!("/proc/{p}/status"), "VmRSS"))
            .unwrap_or(0)
    }

    /// Pauses the VM and saves only its device/vCPU state (memory stays put
    /// and is served by the pager). Returns the page states a target needs,
    /// taken behind the pager's barrier so they match the saved state.
    ///
    /// Pausing stops only the vCPUs; Firecracker's devices would go on
    /// writing guest memory (and their rings) behind the saved state, which
    /// the target then pulls. So first the tap goes down (no RX), host exec
    /// sessions are closed (vsock RX is gated after the snapshot, but host
    /// socket events still walk the TX queue), and the balloon's statistics
    /// timer is pushed out of the way (its next round happens now, before the
    /// snapshot). `resume` undoes this; a target calls `restore_devices`.
    ///
    /// `unroute` runs just before the pause and moves the VM's address off
    /// the tap (`hold`), so packets for it from then on are held rather than
    /// queued on a tap that a paused Firecracker no longer reads and that
    /// then goes down; what the guest sends until the pause still leaves
    /// through the tap. Call after `start_source`.
    ///
    /// `park`s the balloon timer first, unless a migration did that already
    /// (`park_balloon`, while the VM still ran, so that is not part of the
    /// pause). Firecracker fsyncs the state file if `sync`.
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
        // Always, even if already paused: Firecracker freezes device
        // emulation only while it sits in the loop an API pause enters (a VM
        // loaded paused is not in it). Nothing may write guest memory from
        // here until the pages are captured or served: we send no
        // guest-facing request (balloon, hotplug) to a paused source.
        self.fc(|fc| fc.pause())?;
        t.mark("pause");
        // The tap goes down after the pause, so the guest's last packets
        // still leave. That waits for an RCU grace period (milliseconds on a
        // busy host), so it runs alongside the snapshot: Firecracker serves
        // the snapshot request from its pause loop, which reads no tap, and
        // the address already routes elsewhere (`unroute`). It is down
        // before the page states are captured, and joined on every path:
        // `resume` must not race a late link-down.
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

    /// Pushes the balloon's statistics timer out of the way (see
    /// `save_state`): changing it makes Firecracker write the stats queue,
    /// which must happen before the snapshot. Call after `start_source`;
    /// `resume` puts it back.
    pub fn park_balloon(&self) -> Result<()> {
        self.fc(|fc| fc.patch("/balloon/statistics", json!({"stats_polling_interval_s": u16::MAX})).map(drop))
    }

    /// Marks the VM as the source of migration `mig`. From then on no host
    /// vsock session opens (see `exec`), so `checkpoint` can close them all.
    pub fn start_source(&self, mig: u64) -> Result<()> {
        self.leave(State::Source(mig))
    }

    /// Marks the VM as being checkpointed to disk, like `start_source`.
    pub fn start_checkpoint(&self) -> Result<()> {
        self.leave(State::Checkpointing)
    }

    /// Leaves Running or Paused for a migration or checkpoint. Exec sessions
    /// need no lock against this: one registered before is closed by
    /// `save_state`, one registered after sees the state and closes itself.
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
        // A clock request that failed may still be on its way into the guest,
        // and must not arrive after the snapshot (on a target, or in a
        // checkpoint) with a stale time. The agent serves requests in order,
        // so a ping answered now means it has been dealt with. Not under the
        // state lock: a ping can take seconds, and the daemon reads `state`
        // under its VM map's lock.
        if self.clock_unsure.load(Ordering::SeqCst) {
            crate::guest::ping(&self.vsock()).map_err(|e| format!("vm {}: guest agent not answering: {e}", self.name))?;
            self.clock_unsure.store(false, Ordering::SeqCst);
        }
        // Transitions are serialized by the daemon's reservation; check again
        // all the same (the pager may have failed meanwhile).
        let mut st = self.state.lock().unwrap();
        leavable(*st)?;
        self.was_paused.store(*st == State::Paused, Ordering::SeqCst);
        *st = to;
        Ok(())
    }

    /// Whether the VM was paused when its current migration or checkpoint began.
    pub fn was_paused(&self) -> bool {
        self.was_paused.load(Ordering::SeqCst)
    }

    /// Undoes `checkpoint`: puts the devices back and resumes the vCPUs,
    /// unless the VM was paused before. Returns the state to go back to.
    pub fn resume(&self) -> Result<State> {
        crate::net::set_link_up(&self.tap, true)?;
        // Taking the tap down deleted the VM's /32 route; put it back.
        crate::net::attach(self.ip, &self.tap)?;
        self.unpark_balloon();
        if self.was_paused.swap(false, Ordering::SeqCst) {
            return Ok(State::Paused);
        }
        self.fc(|fc| fc.resume())?;
        Ok(State::Running)
    }

    /// Ends a checkpoint to disk that keeps the VM here: back to running or
    /// paused, or failed if it cannot be resumed. (Transitions are serialized
    /// by the daemon's reservation; the state lock is never held across a
    /// Firecracker request, so readers never wait on one.)
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

    /// Stops the vCPUs; memory and devices stay as they are.
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

    /// Resumes a VM stopped by `pause`. A paused migration target first
    /// pulls all its memory from the source (waiting up to `PULL_WAIT`), so
    /// it never runs split across two hosts.
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



    /// Marks the VM failed: it stays as it is until killed.
    pub fn set_failed(&self) {
        *self.state.lock().unwrap() = State::Failed;
    }

    /// virtio-mem memory currently plugged, if Firecracker answers.
    pub fn hotplug_plugged(&self) -> Option<u64> {
        let hp = self.fc(|fc| fc.request_within("GET", "/hotplug/memory", None, crate::guest::TIMEOUT)).ok()?;
        hp["plugged_size_mib"].as_u64()
    }

    /// Waits until the guest has carried out the last virtio-mem resize
    /// (plugged == requested), so that no request of its can still reach
    /// the device; past half of `deadline`, stops asking for a size the
    /// guest cannot reach (requested = plugged). Firecracker processes
    /// virtio-mem requests on its VMM thread, paused vCPUs or not, and each
    /// can discard memory and write the used ring; the guest driver only
    /// sends them to follow a size change from the host. Callers keep the
    /// controller from resizing meanwhile (the VM's reservation).
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
            if !gave_up && Instant::now() >= half {
                if let Some(p) = plugged {
                    let body = json!({"requested_size_mib": p});
                    self.fc(|fc| fc.request_within("PATCH", "/hotplug/memory", Some(body), left))?;
                    gave_up = true;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// On a migration target: puts back the balloon statistics timer that the
    /// source's `checkpoint` parked, unless the VM is already migrating on
    /// (its next host does it then). Runs off the critical path; holding the
    /// devices lock keeps a new migration from parking the timer meanwhile.
    pub fn restore_devices(&self) {
        let _devices = self.devices.lock().unwrap();
        if matches!(self.state(), State::Running | State::Paused) {
            self.unpark_balloon();
        }
    }

    /// Registers a new exec session, then checks the VM still runs here: if
    /// it no longer does (a migration or checkpoint started meanwhile), the
    /// session is closed again.
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

    /// Runs `cmd` in the guest and returns its exit code and (at most 64 KiB
    /// of) output. Everything (admission, connecting, the handshake, writing
    /// the command, every read and the bookkeeping) ends by `deadline`; the
    /// session is closed if it does not.
    pub fn sh(&self, cmd: &str, deadline: Instant) -> Result<(i32, String)> {
        const MAX_OUTPUT: usize = 64 << 10;
        if Instant::now() >= deadline {
            bail!("guest command {cmd:?}: deadline already passed");
        }
        if self.state() != State::Running {
            bail!("vm {} is not running here", self.name);
        }
        let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        let s = crate::util::connect_unix(&self.vsock(), left)?;
        let raw = s.try_clone()?;
        let mut g = BufReader::new(crate::util::By { s, at: deadline });
        // Registered (and the state rechecked) before the guest sees a byte.
        let id = match self.track(&raw) {
            Ok(id) => id,
            Err(e) => {
                let _ = raw.shutdown(Shutdown::Both);
                return Err(e);
            }
        };
        let started = (|| -> Result<()> {
            let req = format!("CONNECT {}\nEXEC {}\n{cmd}", crate::guest::PORT, cmd.len());
            g.get_mut().write_all(req.as_bytes())?;
            let mut ok = String::new();
            g.by_ref().take(64).read_line(&mut ok)?;
            if !ok.starts_with("OK") {
                bail!("vsock connect refused: {ok:?}");
            }
            Ok(())
        })();
        if let Err(e) = started {
            let _ = raw.shutdown(Shutdown::Both);
            self.untrack_exec(id);
            return Err(e);
        }
        let mut out = Vec::new();
        let res: Result<i32> = loop {
            // read_frame bounds the frame size; By bounds every read.
            match crate::guest::read_frame(&mut g) {
                Ok(Some((crate::guest::FRAME_EXIT, d))) if d.len() >= 4 => {
                    break Ok(i32::from_le_bytes(d[..4].try_into().unwrap()))
                }
                Ok(Some((_, d))) => out.extend_from_slice(&d[..d.len().min(MAX_OUTPUT.saturating_sub(out.len()))]),
                Ok(None) => break Err("guest closed the connection before the command exited".into()),
                Err(e) => break Err(format!("guest command {cmd:?}: {e}").into()),
            }
        };
        let _ = raw.shutdown(Shutdown::Both);
        self.untrack_exec(id);
        Ok((res?, String::from_utf8_lossy(&out).into_owned()))
    }

    /// Steps the guest's wall clock to the host's, all of it by `deadline`.
    /// A restore leaves the guest's clock where it was saved (the guest's TSC
    /// clocksource resumes from its saved value, and Firecracker's
    /// `clock_realtime` only moves kvmclock), so it lags by however long the
    /// VM was stopped. One agent request (`CLOCK`) sets the host's time and
    /// reports how far off the clock was (ms, returned); as the guest ends up
    /// behind by the request's transit time, it goes again (a few times at
    /// most) until a round trip is short. The guest skips steps under 5 ms.
    /// Callers hold the VM's reservation. An agent without `CLOCK` gets no
    /// step (logged once): a command run through exec could be delayed past
    /// the deadline and land after a snapshot, which nothing can fence.
    pub fn sync_clock(&self, deadline: Instant) -> Result<f64> {
        static WARNED: AtomicBool = AtomicBool::new(false);
        let mut first = None;
        for tries in 1.. {
            let start = Instant::now();
            let left = deadline.saturating_duration_since(start);
            match crate::guest::clock(&self.vsock(), &self.template.legacy_agent, left) {
                Ok(Some(off)) => {
                    let off = *first.get_or_insert(off);
                    if start.elapsed() < CLOCK_RTT {
                        return Ok(off);
                    }
                    // A guest still faulting its memory in answers slowly: past
                    // three tries, keep going (a little apart) while time is
                    // left, as each slow step leaves it behind by its transit.
                    if Instant::now() + Duration::from_millis(200) >= deadline {
                        break;
                    }
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
        Ok(first.unwrap_or(0.0))
    }

    /// Holds the guest's free page reports in the balloon's queue: held,
    /// Firecracker does not discard reported pages, so no REMOVE reaches the
    /// pager while a copy-on-write checkpoint still has pages to save. Needs
    /// `firecracker/0003-hold-free-page-reporting.patch`. Until a release
    /// lands (`release_reports`) the hold counts as in place, even if this
    /// fails: Firecracker may have applied it and its answer been lost. Only
    /// a Firecracker that rejects the request (unpatched) holds nothing.
    pub fn hold_reports(&self) -> Result<()> {
        const PATH: &str = "/balloon/reporting/hold";
        self.reports_held.store(true, Ordering::SeqCst);
        let res = self.fc(|fc| fc.request_within("PATCH", PATH, None, Duration::from_secs(1)));
        if res.as_ref().is_err_and(|e| rejected(e, PATH)) {
            self.reports_held.store(false, Ordering::SeqCst);
        }
        res.map(drop)
    }

    /// Carries out the free page reports a hold kept back, if one may be in
    /// place, retrying for `within`. Until a release lands the guest's
    /// reported pages stay off its free lists, so one that fails stays due
    /// (`release_pending`) and the controller retries it.
    pub fn release_reports(&self, within: Duration) -> Result<()> {
        const PATH: &str = "/balloon/reporting/release";
        let deadline = Instant::now() + within;
        while self.reports_held.load(Ordering::SeqCst) {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.fc(|fc| fc.request_within("PATCH", PATH, None, left)) {
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

    /// Whether a release of held free page reports is still due.
    pub fn release_pending(&self) -> bool {
        self.reports_held.load(Ordering::SeqCst)
    }

    /// Retries a few times; the VM keeps running regardless, only its
    /// statistics go stale.
    fn unpark_balloon(&self) {
        let deadline = Instant::now() + Duration::from_millis(500);
        let res = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let body = json!({"stats_polling_interval_s": BALLOON_STATS_S});
            match self.fc(|fc| fc.request_within("PATCH", "/balloon/statistics", Some(body), left)) {
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                r => break r,
            }
        };
        if let Err(e) = res {
            eprintln!("vm {}: balloon statistics stay off: {e}", self.name);
        }
    }

    /// Opens an exec session: connects to the VM's vsock socket, registers
    /// the connection (so a checkpoint can close it) and checks the VM still
    /// runs here, and only then lets `start` send anything to the guest. No
    /// lock is held while `start` talks to the guest (it has its own
    /// deadline, `guest::TIMEOUT`); the session is untimed afterwards.
    pub fn exec(&self, start: impl FnOnce(UnixStream) -> Result<BufReader<UnixStream>>) -> Result<(BufReader<UnixStream>, u64)> {
        if self.state() != State::Running {
            bail!("vm {} is not running here", self.name);
        }
        let s = crate::util::connect_unix(&self.vsock(), crate::guest::TIMEOUT)?;
        let id = self.track(&s)?;
        let started = start(s).and_then(|g| {
            crate::guest::untimed(&g)?;
            Ok(g)
        });
        match started {
            Ok(g) => Ok((g, id)),
            Err(e) => {
                self.untrack_exec(id);
                Err(e)
            }
        }
    }

    /// Sets the guest's address and wall clock (`START`; `NET` for older
    /// agents), unless the VM is no longer running here. Bounded by
    /// `guest::TIMEOUT`. Callers hold the VM's reservation, so no migration
    /// or checkpoint starts meanwhile. If it fails, the clock may be anyone's
    /// guess (see `leave`).
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

    /// Starts an image template's app, unless the VM is no longer running
    /// here. Bounded by `guest::TIMEOUT`; callers hold the VM's reservation.
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
            "state": self.state().name(),
            "vcpus": self.template.meta.vcpus,
            "rss_mib": self.rss() >> 20,
            "guest_mib": self.template.meta.mem_mib + hotplug["plugged_size_mib"].as_u64().unwrap_or(0),
            "max_mib": self.template.meta.max_mib,
            "pages_mib": {"base": mib(base), "present": mib(present), "zero": mib(zero), "remote": mib(remote + inflight + discarded)},
            "checkpoint_copy": self.pager.copying(),
            "write_tracking": self.pager.tracking(),
        })
    }
}

/// A Firecracker set up for a restore, with its pager started but no
/// snapshot loaded yet (`Vm::prepare`). Dropping it tears everything down.
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

    pub fn firecracker_alive(&mut self) -> bool {
        self.idle.as_mut().is_some_and(|i| i.fc.alive())
    }

    /// The VM `name` at `ip`, now loaded into this Firecracker.
    pub fn into_vm(mut self, name: &str, ip: Ipv4Addr, state: State) -> Arc<Vm> {
        let idle = self.idle.take().unwrap();
        Vm::assemble(name, self.template.clone(), idle, ip, self.pager.clone(), state)
    }

    /// Test fault `kill_prepared`: kills the Firecracker (and waits for it).
    pub fn kill_firecracker(&mut self) {
        self.idle.as_mut().unwrap().fc.kill();
    }

    /// The Firecracker's directory, where the vmstate to load goes.
    pub fn dir(&self) -> &Path {
        &self.idle.as_ref().unwrap().dir
    }

    /// Has Firecracker do the part of the coming load that only depends on
    /// the template (KVM VM, vCPUs, memory slots, guest memory handed to the
    /// pager, vsock socket, pmem mapping; `firecracker/0002-*.patch`), so the
    /// load proper only restores vCPU, VM and device state. The pager then
    /// waits for its seed. Returns false, changing nothing, if this
    /// Firecracker cannot prepare a load.
    pub fn prepare_load(&self) -> Result<bool> {
        static UNSUPPORTED: AtomicBool = AtomicBool::new(false);
        if UNSUPPORTED.load(Ordering::Relaxed) {
            return Ok(false);
        }
        let idle = self.idle.as_ref().unwrap();
        // Before the request: Firecracker connects to the pager during it.
        self.pager.expect_seed(true);
        let res = idle.fc.put(
            "/snapshot/prepare",
            json!({
                "snapshot_path": self.template.vmstate(),
                "mem_backend": {"backend_type": "Uffd", "backend_path": idle.fc.sockets.uffd},
                "vsock_override": {"uds_path": idle.fc.sockets.vsock},
                "network_overrides": [{"iface_id": "eth0", "host_dev_name": idle.tap}],
            }),
        );
        match res {
            Ok(_) => Ok(true),
            // A Firecracker without the patch rejects the path before doing anything.
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

    /// Loads `vmstate`, the vCPUs stopped, held paused as `load` says (a
    /// running VM is resumed by the caller: see `Vm::restore`), with
    /// `ip` routed to its tap. Seed the pager first if pages are to come from
    /// elsewhere. Every Firecracker request and wait ends by `deadline`, if
    /// given. A failure (`LoadFailed` for a failed load request) says whether
    /// a fresh Firecracker could do it: the guest never ran here either way.
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        mut self,
        name: &str,
        vmstate: &Path,
        ip: Ipv4Addr,
        load: Load,
        clock_realtime: bool,
        deadline: Option<Instant>,
        phases: &mut Phases,
    ) -> Result<(Arc<Vm>, Duration)> {
        LOADS.fetch_add(1, Ordering::SeqCst);
        let idle = self.idle.as_ref().unwrap();
        let (fc, tap) = (&idle.fc, idle.tap.clone());
        let left = |most: Duration| deadline.map_or(most, |d| d.saturating_duration_since(Instant::now()).min(most));
        let mut load_failed = None;
        let restored = (|| -> Result<Duration> {
            // Route the VM's address while Firecracker restores; it is not on the critical path.
            let route = std::thread::spawn(move || crate::net::attach(ip, &tap));
            let body = load_body(vmstate, fc, &idle.tap, clock_realtime);
            let loaded = fc.request_within("PUT", "/snapshot/load", Some(body), left(crate::fc::API_TIMEOUT));
            self.pager.loaded();
            let took = phases.mark("snapshot_load");
            if let Err(e) = &loaded {
                load_failed = Some(e.to_string());
            }
            let held = loaded.and_then(|_| {
                if load == Load::Paused {
                    // Loaded paused, Firecracker stops only the vCPUs and goes on
                    // emulating devices; an API pause enters the loop that holds
                    // device emulation too, until the resume.
                    fc.request_within("PATCH", "/vm", Some(json!({"state": "Paused"})), left(crate::fc::API_TIMEOUT))?;
                    phases.mark("hold_paused");
                }
                self.pager.wait_ready(left(Duration::from_secs(5)))
            });
            let routed = route.join().map_err(|_| "route thread panicked")?;
            held?;
            routed?;
            phases.mark("route_wait");
            Ok(took)
        })();
        let took = match restored {
            Ok(took) => took,
            Err(e) => {
                let idle = self.idle.as_mut().unwrap();
                let retry = match &load_failed {
                    Some(why) if why.contains(NO_REALTIME) => Some(Retry::WithoutRealtime),
                    // Died on its own, with no page given up.
                    Some(_) if !self.pager.lost_pages() && !idle.fc.alive() => Some(Retry::Fresh),
                    _ => None,
                };
                eprintln!("vm {name}: restore failed: {e} ({})", idle.fc.post_mortem(&idle.dir));
                if load_failed.is_some() {
                    return Err(Box::new(LoadFailed { error: e.to_string(), retry }));
                }
                return Err(e);
            }
        };
        // Its vCPUs are stopped: running once the caller resumes it.
        let state = if load.running() { State::Running } else { State::Paused };
        Ok((self.into_vm(name, ip, state), took))
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

/// The body of a `PUT /snapshot/load` of `vmstate` into `fc`, with the
/// vCPUs stopped (they are resumed only once nothing can fail any more).
pub fn load_body(vmstate: &Path, fc: &Firecracker, tap: &str, clock_realtime: bool) -> Value {
    json!({
        "snapshot_path": vmstate,
        "mem_backend": {"backend_type": "Uffd", "backend_path": fc.sockets.uffd},
        "vsock_override": {"uds_path": fc.sockets.vsock},
        "network_overrides": [{"iface_id": "eth0", "host_dev_name": tap}],
        "clock_realtime": clock_realtime,
        "resume_vm": false,
    })
}

/// Whether Firecracker answered a PATCH of `path` with a client error (4xx):
/// it has no such endpoint, so the request had no effect. Anything else (a
/// timeout, a lost answer) may have been applied.
fn rejected(e: &crate::util::Error, path: &str) -> bool {
    e.to_string().strip_prefix(&format!("firecracker PATCH {path}: ")).is_some_and(|r| r.starts_with('4'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_client_error_means_nothing_was_held() {
        let p = "/balloon/reporting/hold";
        let err = |m: &str| -> crate::util::Error { m.into() };
        assert!(rejected(&err("firecracker PATCH /balloon/reporting/hold: 400 {\"fault_message\":\"x\"}"), p));
        assert!(!rejected(&err("firecracker PATCH /balloon/reporting/hold: out of time"), p));
        assert!(!rejected(&err("firecracker PATCH /balloon/reporting/hold: 500 oops"), p));
        assert!(!rejected(&err("Resource temporarily unavailable (os error 11)"), p));
        assert!(!rejected(&err("firecracker PATCH /balloon/reporting/release: 400 x"), p));
    }
}
