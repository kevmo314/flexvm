use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::{Firecracker, Idle};
use crate::template::Template;
use crate::uffd::{Pager, Runs};
use crate::util::{Result, PAGE_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Running,
    /// Paused here while a migration target pulls its memory.
    Source,
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
    fc: Mutex<Option<Firecracker>>,
    cgroup: Option<PathBuf>,
}

impl Vm {
    /// Restores `vmstate` into an idle Firecracker, with guest memory served
    /// by a pager over `template` plus `remote` pages when migrating in, and
    /// `ip` routed to the VM's tap.
    pub fn restore(
        idle: Idle,
        name: &str,
        template: Arc<Template>,
        vmstate: &Path,
        remote: Option<(Runs, String, String)>,
        ip: Ipv4Addr,
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
        let restored = (|| {
            let pager = Pager::start(&dir.join("uffd.sock"), template.clone(), remote)?;
            pager.set_pid(fc.pid());
            // Route the VM's address while Firecracker restores; it is not on the critical path.
            let route = {
                let tap = tap.clone();
                std::thread::spawn(move || crate::net::attach(ip, &tap))
            };
            let start = Instant::now();
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
            let took = start.elapsed();
            pager.wait_ready(Duration::from_secs(5))?;
            route.join().map_err(|_| "route thread panicked")??;
            Ok((pager, took))
        })();
        let (pager, took) = match restored {
            Ok(r) => r,
            Err(e) => {
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
            fc: Mutex::new(Some(fc)),
            cgroup,
        });
        Ok((vm, took))
    }

    pub fn vsock(&self) -> PathBuf {
        self.dir.join("v.sock")
    }

    pub fn state(&self) -> State {
        *self.state.lock().unwrap()
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
    /// and is served by the pager). Returns the page states a target needs.
    pub fn checkpoint(&self, vmstate: &Path) -> Result<Runs> {
        self.fc(|fc| {
            fc.pause()?;
            fc.put("/snapshot/create", json!({"snapshot_type": "Full", "snapshot_path": vmstate, "mem_file_path": ""}))
        })?;
        self.pager.export_runs()
    }

    pub fn resume(&self) -> Result<()> {
        self.fc(|fc| fc.resume())
    }

    pub fn kill(&self) {
        self.pager.stop();
        if let Some(mut fc) = self.fc.lock().unwrap().take() {
            fc.kill();
        }
        crate::net::delete_tap(&self.tap);
        if let Some(cg) = &self.cgroup {
            // The cgroup stays busy until the kernel has finished tearing the process down.
            let _ = crate::util::retry(Duration::from_secs(2), || Ok(std::fs::remove_dir(cg)?));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }

    pub fn describe(&self) -> Value {
        let [base, present, zero, remote, inflight] = self.pager.census();
        let mib = |pages: usize| (pages * PAGE_SIZE) as u64 >> 20;
        let hotplug = self.fc(|fc| fc.get("/hotplug/memory")).unwrap_or(Value::Null);
        json!({
            "name": self.name,
            "ip": self.ip.to_string(),
            "template": self.template.name,
            "state": format!("{:?}", self.state()).to_lowercase(),
            "vcpus": self.template.meta.vcpus,
            "rss_mib": self.rss() >> 20,
            "guest_mib": self.template.meta.mem_mib + hotplug["plugged_size_mib"].as_u64().unwrap_or(0),
            "max_mib": self.template.meta.max_mib,
            "pages_mib": {"base": mib(base), "present": mib(present), "zero": mib(zero), "remote": mib(remote + inflight)},
        })
    }
}
