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
use crate::uffd::{Pager, Runs, Source};
use crate::util::{Phases, Result, PAGE_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Running,
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
            State::Source(_) => "source",
            State::Failed => "failed",
        }
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
                    "resume_vm": true,
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
            state: Mutex::new(State::Running),
            last_resize: Mutex::new(Instant::now()),
            starved: AtomicBool::new(false),
            released: OnceLock::new(),
            execs: Mutex::new(HashMap::new()),
            next_exec: AtomicU64::new(0),
            fc: Mutex::new(Some(fc)),
            cgroup,
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
        crate::net::set_link_up(&self.tap, false)?;
        for (_, s) in self.execs.lock().unwrap().drain() {
            let _ = s.shutdown(Shutdown::Both);
        }
        self.fc(|fc| {
            fc.pause()?;
            fc.patch("/balloon/statistics", json!({"stats_polling_interval_s": u16::MAX}))?;
            fc.put("/snapshot/create", json!({"snapshot_type": "Full", "snapshot_path": vmstate, "mem_file_path": "", "sync_snapshot_files": false}))
        })?;
        self.pager.quiesce_export()
    }

    /// Marks the VM as the source of migration `mig`. From then on no host
    /// vsock session opens (see `exec`), so `checkpoint` can close them all.
    pub fn start_source(&self, mig: u64) -> Result<()> {
        let _admission = self.execs.lock().unwrap();
        let mut st = self.state.lock().unwrap();
        if *st != State::Running || self.pager.failed().is_some() {
            bail!("vm {} is not running here", self.name);
        }
        if self.pager.remote_left() > 0 {
            bail!("vm {} is still pulling its memory from its previous host", self.name);
        }
        *st = State::Source(mig);
        Ok(())
    }

    /// Resumes a VM paused by `checkpoint`, putting its devices back first.
    pub fn resume(&self) -> Result<()> {
        crate::net::set_link_up(&self.tap, true)?;
        self.unpark_balloon();
        self.fc(|fc| fc.resume())
    }

    /// On a migration target: puts back the balloon statistics timer that the
    /// source's `checkpoint` parked, unless the VM is already migrating on
    /// (its next host does it then). Runs off the critical path; holding the
    /// admission lock keeps a new migration from parking the timer meanwhile.
    pub fn restore_devices(&self) {
        let _admission = self.execs.lock().unwrap();
        if self.state() == State::Running {
            self.unpark_balloon();
        }
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
