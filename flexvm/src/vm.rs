use std::collections::HashMap;
use std::io::BufReader;
use std::net::{Ipv4Addr, Shutdown};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::{Firecracker, Idle};
use crate::template::{Template, BALLOON_STATS_S};

/// How long resuming a paused migration target waits for its memory to arrive.
const PULL_WAIT: Duration = Duration::from_secs(30);
use crate::uffd::{Origin, Pager, Runs, Source};
use crate::util::{Phases, Result, PAGE_SIZE};

/// Where a VM is in its lifecycle on this host. Transitions happen under the
/// daemon's per-name operation lock (see `Daemon::reserve`); the states of a
/// VM without a Firecracker here (starting, suspended) live in the daemon.
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
    /// Migration target only: the source's answer to `release`, true or an error.
    pub released: OnceLock<Value>,
    /// Host ends of exec sessions, by id. Also the admission lock for host
    /// vsock sessions: held from checking the VM runs here until a session is
    /// registered, and by `start_source` while it marks the VM migrating.
    execs: Mutex<HashMap<u64, UnixStream>>,
    next_exec: AtomicU64,
    fc: Mutex<Option<Firecracker>>,
    cgroup: Option<PathBuf>,
    /// Set by `start_source` and `start_checkpoint` for a VM that was
    /// paused: `resume` then puts it back paused (and a migration target
    /// keeps it paused).
    was_paused: AtomicBool,
    /// A background clock check is queued (see `Daemon::sync_clock_later`).
    pub clock_pending: AtomicBool,
    /// The pager's discard count just before the last snapshot: a discard
    /// after it means the saved state and memory may disagree.
    pub snapshot_discards: AtomicU64,
}

impl Vm {
    /// Restores `vmstate` into an idle Firecracker, with guest memory served
    /// by a pager over `template` plus `remote` pages when migrating in, and
    /// `ip` routed to the VM's tap. Marks each step in `phases`.
    pub fn restore(
        idle: Idle,
        name: &str,
        template: Arc<Template>,
        vmstate: &Path,
        remote: Option<(Runs, Source)>,
        ip: Ipv4Addr,
        phases: &mut Phases,
    ) -> Result<(Arc<Vm>, Duration)> {
        let origin = remote.map(|(runs, source)| (runs, Origin::Peer(source)));
        Vm::restore_from(idle, name, template, vmstate, origin, ip, true, phases)
    }

    /// `restore`, from any page origin, and leaving the VM paused unless `resume`.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_from(
        idle: Idle,
        name: &str,
        template: Arc<Template>,
        vmstate: &Path,
        remote: Option<(Runs, Origin)>,
        ip: Ipv4Addr,
        resume: bool,
        phases: &mut Phases,
    ) -> Result<(Arc<Vm>, Duration)> {
        let Idle { fc, dir, cgroup, tap } = idle;
        // Name the cgroup after the VM; renaming is free, joining is not.
        let cgroup = cgroup.map(|cg| {
            let named = cg.with_file_name(name);
            let _ = std::fs::remove_dir(&named);
            match std::fs::rename(&cg, &named) {
                Ok(()) => named,
                Err(_) => cg,
            }
        });
        phases.mark("cgroup_rename");
        let pager = Pager::start(&dir.join("uffd.sock"), template.clone(), remote);
        let restored = (|| {
            let pager = pager.as_ref().map_err(|e| e.to_string())?.clone();
            pager.set_pid(fc.pid())?;
            // Route the VM's address while Firecracker restores; it is not on the critical path.
            let route = {
                let tap = tap.clone();
                std::thread::spawn(move || crate::net::attach(ip, &tap))
            };
            phases.mark("pager_start");
            fc.put(
                "/snapshot/load",
                json!({
                    "snapshot_path": vmstate,
                    "mem_backend": {"backend_type": "Uffd", "backend_path": dir.join("uffd.sock")},
                    "vsock_override": {"uds_path": dir.join("v.sock")},
                    "network_overrides": [{"iface_id": "eth0", "host_dev_name": tap}],
                    "clock_realtime": true,
                    "resume_vm": resume,
                }),
            )?;
            // Includes Firecracker's resume: the load request sets resume_vm.
            let took = phases.mark("snapshot_load");
            pager.wait_ready(Duration::from_secs(5))?;
            route.join().map_err(|_| "route thread panicked")??;
            phases.mark("route_wait");
            Ok((pager, took))
        })();
        let (pager, took) = match restored {
            Ok(r) => r,
            Err(e) => {
                if let Ok(pager) = pager {
                    pager.stop();
                }
                drop(fc);
                crate::net::delete_tap(&tap);
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        let vm = Arc::new(Vm {
            name: name.into(),
            template,
            dir,
            ip,
            tap,
            pager,
            state: Mutex::new(if resume { State::Running } else { State::Paused }),
            last_resize: Mutex::new(Instant::now()),
            starved: AtomicBool::new(false),
            released: OnceLock::new(),
            execs: Mutex::new(HashMap::new()),
            next_exec: AtomicU64::new(0),
            fc: Mutex::new(Some(fc)),
            cgroup,
            was_paused: AtomicBool::new(false),
            clock_pending: AtomicBool::new(false),
            snapshot_discards: AtomicU64::new(0),
        });
        Ok((vm, took))
    }

    pub fn vsock(&self) -> PathBuf {
        self.dir.join("v.sock")
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
    /// Call after `start_source`.
    pub fn checkpoint(&self, vmstate: &Path) -> Result<Runs> {
        self.save_state(vmstate, false)
    }

    /// `checkpoint`, with Firecracker fsyncing the state file if `sync`.
    /// Call after `start_source` or `start_checkpoint`.
    pub fn save_state(&self, vmstate: &Path, sync: bool) -> Result<Runs> {
        crate::net::set_link_up(&self.tap, false)?;
        for (_, s) in self.execs.lock().unwrap().drain() {
            let _ = s.shutdown(Shutdown::Both);
        }
        let paused = self.was_paused.load(Ordering::SeqCst);
        self.fc(|fc| {
            if !paused {
                fc.pause()?;
            }
            fc.patch("/balloon/statistics", json!({"stats_polling_interval_s": u16::MAX}))?;
            self.snapshot_discards.store(self.pager.discards(), Ordering::SeqCst);
            fc.put("/snapshot/create", json!({"snapshot_type": "Full", "snapshot_path": vmstate, "mem_file_path": "", "sync_snapshot_files": sync}))
        })?;
        self.pager.quiesce_export()
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

    fn leave(&self, to: State) -> Result<()> {
        let _admission = self.execs.lock().unwrap();
        let mut st = self.state.lock().unwrap();
        if !matches!(*st, State::Running | State::Paused) || self.pager.failed().is_some() {
            bail!("vm {} is not running here", self.name);
        }
        if self.pager.remote_left() > 0 {
            bail!("vm {} is still pulling its memory from its previous host or checkpoint", self.name);
        }
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
        self.unpark_balloon();
        if self.was_paused.swap(false, Ordering::SeqCst) {
            return Ok(State::Paused);
        }
        self.fc(|fc| fc.resume())?;
        Ok(State::Running)
    }

    /// Ends a checkpoint to disk that keeps the VM here: back to running or
    /// paused, or failed if it cannot be resumed.
    pub fn end_checkpoint(&self) -> Result<State> {
        let mut st = self.state.lock().unwrap();
        if *st != State::Checkpointing {
            bail!("vm {} is not being checkpointed", self.name);
        }
        match self.resume() {
            Ok(s) => {
                *st = s;
                Ok(s)
            }
            Err(e) => {
                *st = State::Failed;
                bail!("resuming vm {} after its checkpoint failed: {e}", self.name)
            }
        }
    }

    /// Stops the vCPUs; memory and devices stay as they are.
    pub fn pause(&self) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        match self.state_locked(&st) {
            State::Paused => return Ok(()),
            State::Running => {}
            s => bail!("vm {} is {}, not running", self.name, s.name()),
        }
        self.fc(|fc| fc.pause())?;
        *st = State::Paused;
        Ok(())
    }

    /// Resumes a VM stopped by `pause`. A paused migration target first
    /// pulls all its memory from the source (waiting up to `PULL_WAIT`), so
    /// it never runs split across two hosts.
    pub fn unpause(&self) -> Result<()> {
        if self.pager.pulling_from_peer() && !self.pager.wait_pulled_for(PULL_WAIT) {
            bail!("vm {} is still pulling its memory from its previous host; resume it once that is done", self.name);
        }
        let mut st = self.state.lock().unwrap();
        match self.state_locked(&st) {
            State::Running => return Ok(()),
            State::Paused => {}
            s => bail!("vm {} is {}, not paused", self.name, s.name()),
        }
        self.fc(|fc| fc.resume())?;
        *st = State::Running;
        Ok(())
    }

    fn state_locked(&self, st: &State) -> State {
        if self.pager.failed().is_some() {
            return State::Failed;
        }
        *st
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
    /// admission lock keeps a new migration from parking the timer meanwhile.
    pub fn restore_devices(&self) {
        let _admission = self.execs.lock().unwrap();
        if matches!(self.state(), State::Running | State::Paused) {
            self.unpark_balloon();
        }
    }

    /// Runs `cmd` in the guest and returns its exit code and (at most 64 KiB
    /// of) output. Gives up at `deadline`, closing the session.
    pub fn sh(&self, cmd: &str, deadline: Instant) -> Result<(i32, String)> {
        const MAX_OUTPUT: usize = 64 << 10;
        let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        let (mut g, id) = self.exec(|uds| crate::guest::start_exec(uds, cmd, left))?;
        let mut out = Vec::new();
        let res = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Err(format!("guest command timed out: {cmd:?}").into());
            }
            if let Err(e) = g.get_ref().set_read_timeout(Some(left)) {
                break Err(e.into());
            }
            match crate::guest::read_frame(&mut g) {
                Ok(Some((crate::guest::FRAME_EXIT, d))) if d.len() >= 4 => {
                    break Ok(i32::from_le_bytes(d[..4].try_into().unwrap()))
                }
                Ok(Some((_, d))) => out.extend_from_slice(&d[..d.len().min(MAX_OUTPUT.saturating_sub(out.len()))]),
                Ok(None) => break Err("guest closed the connection before the command exited".into()),
                Err(e) => break Err(e),
            }
        };
        if res.is_err() {
            let _ = g.get_ref().shutdown(Shutdown::Both);
        }
        self.untrack_exec(id);
        Ok((res?, String::from_utf8_lossy(&out).into_owned()))
    }

    /// Steps the guest's wall clock to the host's if it is off by more than
    /// `tolerance`; all of it done by `deadline`. A restore leaves the
    /// guest's clock where it was saved (the guest's TSC clocksource resumes
    /// from its saved value, and Firecracker's `clock_realtime` only moves
    /// kvmclock), so it lags by however long the VM was stopped. The offset is
    /// measured with one exec bracketed by host timestamps; the step sets an
    /// absolute time (the host's, plus half the measured round trip for the
    /// exec's delay), so running it twice never steps twice. Returns the
    /// offset found (ms). Callers hold the VM's reservation. The one place
    /// that sets the guest clock (a guest agent request would replace the
    /// execs here).
    pub fn sync_clock(&self, tolerance: Duration, deadline: Instant) -> Result<f64> {
        let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as i128;
        let before = now();
        let (code, out) = self.sh("date +%s%N", deadline)?;
        let after = now();
        let guest: i128 = match (code, out.trim().parse()) {
            (0, Ok(ns)) => ns,
            _ => bail!("reading the guest clock: {out:?} (exit {code})"),
        };
        let offset = guest - (before + after) / 2;
        if offset.unsigned_abs() > tolerance.as_nanos() {
            let at = now() + (after - before) / 2;
            let cmd = format!("date -s @{}.{:09} >/dev/null", at / 1_000_000_000, at % 1_000_000_000);
            match self.sh(&cmd, deadline)? {
                (0, _) => {}
                (code, out) => bail!("setting the guest clock: {out:?} (exit {code})"),
            }
        }
        Ok(offset as f64 / 1e6)
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

    /// Opens an exec session with `start` and registers the session so a checkpoint
    /// can close it. Fails unless the VM is running here. Everything done
    /// under the admission lock has a deadline (`guest::TIMEOUT`), so a stuck
    /// guest cannot hold off migrations; the session is untimed afterwards.
    pub fn exec(&self, start: impl FnOnce(&Path) -> Result<BufReader<UnixStream>>) -> Result<(BufReader<UnixStream>, u64)> {
        let (g, id) = {
            let mut execs = self.execs.lock().unwrap();
            if self.state() != State::Running {
                bail!("vm {} is not running here", self.name);
            }
            let g = start(&self.vsock())?;
            let id = self.next_exec.fetch_add(1, Ordering::SeqCst);
            execs.insert(id, g.get_ref().try_clone()?);
            (g, id)
        };
        crate::guest::untimed(&g)?;
        Ok((g, id))
    }

    /// Sets the guest's address, unless the VM is no longer running here.
    /// Bounded by `guest::TIMEOUT`, as it holds the admission lock.
    pub fn guest_net(&self, ip: Ipv4Addr, dns: Option<&str>) -> Result<()> {
        let _admission = self.execs.lock().unwrap();
        if self.state() != State::Running {
            bail!("vm {} is not running here", self.name);
        }
        crate::guest::net(&self.vsock(), ip, dns)
    }

    /// Starts an image template's app, unless the VM is no longer running
    /// here. Bounded by `guest::TIMEOUT`, as it holds the admission lock.
    pub fn start_app(&self) -> Result<u32> {
        let _admission = self.execs.lock().unwrap();
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
        let Some(mut fc) = self.fc.lock().unwrap().take() else { return };
        fc.kill();
        crate::net::delete_tap(&self.tap);
        if let Some(cg) = &self.cgroup {
            // The cgroup stays busy until the kernel has finished tearing the process down.
            let _ = crate::util::retry(Duration::from_secs(2), || Ok(std::fs::remove_dir(cg)?));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }

    pub fn describe(&self) -> Value {
        let [base, present, zero, remote, inflight, discarded] = self.pager.census();
        let mib = |pages: usize| (pages * PAGE_SIZE) as u64 >> 20;
        let hotplug = self.fc(|fc| fc.get("/hotplug/memory")).unwrap_or(Value::Null);
        json!({
            "name": self.name,
            "ip": self.ip.to_string(),
            "tap": self.tap,
            "template": self.template.name,
            "template_id": self.template.meta.id,
            "state": self.state().name(),
            "vcpus": self.template.meta.vcpus,
            "rss_mib": self.rss() >> 20,
            "guest_mib": self.template.meta.mem_mib + hotplug["plugged_size_mib"].as_u64().unwrap_or(0),
            "max_mib": self.template.meta.max_mib,
            "pages_mib": {"base": mib(base), "present": mib(present), "zero": mib(zero), "remote": mib(remote + inflight + discarded)},
        })
    }
}
