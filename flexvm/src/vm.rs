use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::{Firecracker, Idle};
use crate::template::Template;
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
            pager.set_pid(fc.pid());
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
                drop(fc);
                if let Ok(pager) = pager {
                    pager.stop();
                }
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
    pub fn checkpoint(&self, vmstate: &Path) -> Result<Runs> {
        self.fc(|fc| {
            fc.pause()?;
            fc.put("/snapshot/create", json!({"snapshot_type": "Full", "snapshot_path": vmstate, "mem_file_path": "", "sync_snapshot_files": false}))
        })?;
        self.pager.quiesce_export()
    }

    pub fn resume(&self) -> Result<()> {
        self.fc(|fc| fc.resume())
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
            "template": self.template.name,
            "state": self.state().name(),
            "vcpus": self.template.meta.vcpus,
            "rss_mib": self.rss() >> 20,
            "guest_mib": self.template.meta.mem_mib + hotplug["plugged_size_mib"].as_u64().unwrap_or(0),
            "max_mib": self.template.meta.max_mib,
            "pages_mib": {"base": mib(base), "present": mib(present), "zero": mib(zero), "remote": mib(remote + inflight + discarded)},
        })
    }
}
