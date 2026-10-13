//! The VM lifecycle beyond run, migrate and kill: pause and resume, durable
//! checkpoints to disk, restores from them, and suspend (a checkpoint to
//! local disk after which the VM's memory is freed).
//!
//! Every lifecycle operation, and each controller resize, first reserves the
//! VM's name (`reserve`), so operations on one VM are serialized:
//!
//!   starting -> running <-> paused
//!   running | paused -> checkpointing -> running | paused   (checkpoint)
//!                                     -> gone                (checkpoint --stop)
//!                                     -> suspended -> resuming -> running
//!   running | paused -> source (migrating) -> gone | running | paused
//!   any -> failed (memory lost) -> gone (kill)
//!
//! Paused and suspended VMs are never resized or picked for a pressure
//! migration. A paused VM migrates without post-copy: it stays paused on the
//! target, which pulls all its pages before it can run.

use super::*;
use crate::util::PAGE_SIZE;

impl Daemon {
    /// Reserves `name` for lifecycle operation `op`, waiting up to `wait`
    /// for an operation already in progress on it.
    pub(super) fn reserve(&self, name: &str, op: &'static str, wait: Duration) -> Result<Busy<'_>> {
        let deadline = Instant::now() + wait;
        let mut busy = self.busy.0.lock().unwrap();
        while let Some(&other) = busy.get(name) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("vm {name:?} is busy ({other})");
            }
            busy = self.busy.1.wait_timeout(busy, left).unwrap().0;
        }
        busy.insert(name.into(), op);
        Ok(Busy { d: self, name: name.into() })
    }

    /// Whether a VM here, running or suspended, has this name.
    pub(super) fn taken(&self, name: &str) -> bool {
        self.vms.lock().unwrap().contains_key(name) || self.suspended.lock().unwrap().contains_key(name)
    }

    pub(super) fn list(&self) -> Value {
        let vms = self.vms.lock().unwrap();
        let suspended = self.suspended.lock().unwrap();
        let mut out: Vec<Value> = vms.values().map(|v| v.describe()).collect();
        for (name, s) in suspended.iter() {
            let m = &s.manifest;
            out.push(json!({
                "name": name,
                "ip": m.ip.to_string(),
                "template": m.template,
                "template_id": m.template_id,
                "state": "suspended",
                "vcpus": m.vcpus,
                "rss_mib": 0,
                "guest_mib": m.mem_mib + m.hotplug_mib,
                "max_mib": m.max_mib,
                "checkpoint": s.dir,
                "checkpoint_mib": (m.data_pages * PAGE_SIZE as u64) >> 20,
            }));
        }
        // Names reserved by an operation that has no VM to show yet.
        for (name, op) in self.busy.0.lock().unwrap().iter() {
            if !vms.contains_key(name) && !suspended.contains_key(name) {
                out.push(json!({"name": name, "state": op}));
            }
        }
        json!(out)
    }

    pub(super) fn pause(&self, name: &str) -> Result<Value> {
        let _busy = self.reserve(name, "pausing", LIFECYCLE_WAIT)?;
        let vm = self.vm(name)?;
        let start = Instant::now();
        vm.pause()?;
        Ok(json!({"name": name, "state": "paused", "pause_ms": ms(start.elapsed())}))
    }

    /// Resumes a paused VM, or restores a suspended one from its checkpoint.
    pub(super) fn resume(&self, name: &str) -> Result<Value> {
        let _busy = self.reserve(name, "resuming", LIFECYCLE_WAIT)?;
        if let Ok(vm) = self.vm(name) {
            let start = Instant::now();
            vm.unpause()?;
            let took = start.elapsed();
            // Off the critical path: the guest's clock keeps counting while
            // paused (its TSC runs on), so this rarely needs to change it.
            sync_clock_later(vm);
            return Ok(json!({"name": name, "state": "running", "from": "paused", "resume_ms": ms(took)}));
        }
        let mut t = Phases::new();
        let s = self.suspended.lock().unwrap().remove(name);
        let Some(s) = s else { bail!("no vm named {name:?}") };
        // Out of suspended/ first, so a daemon restart never brings back a
        // copy of a VM that has run since.
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let resumed = self.cfg.state_dir.join("resumed").join(format!("{name}-{nanos:x}"));
        let moved = std::fs::create_dir_all(resumed.parent().unwrap()).and_then(|()| std::fs::rename(&s.dir, &resumed));
        if let Err(e) = moved {
            let dir = s.dir.display().to_string();
            self.suspended.lock().unwrap().insert(name.into(), s);
            bail!("moving checkpoint {dir} aside: {e}");
        }
        let res = Checkpoint::open(&resumed).and_then(|ck| {
            t.mark("verify_checkpoint");
            self.restore_checkpoint(name, ck, s.manifest.ip, true, &mut t)
        });
        if res.is_err() {
            let _ = std::fs::rename(&resumed, &s.dir);
            self.suspended.lock().unwrap().insert(name.into(), s);
        }
        res.map(|mut v| {
            v["from"] = json!("suspended");
            v
        })
    }

    /// Checkpoints `name` to `dir`, then resumes it or (`stop`) kills it.
    pub(super) fn checkpoint(&self, name: &str, dir: &str, stop: bool) -> Result<Value> {
        let mut t = Phases::new();
        let _busy = self.reserve(name, "checkpointing", LIFECYCLE_WAIT)?;
        let vm = self.vm(name)?;
        let staging = Staging::new(Path::new(dir))?;
        let dest = staging.dest().to_path_buf();
        t.mark("prepare");
        let (m, paused) = self.save(&vm, staging, &mut t)?;
        let state = if stop {
            self.kill_reserved(name)?;
            t.mark("stop");
            "stopped"
        } else {
            let s = vm.end_checkpoint()?;
            t.mark("resume");
            if s == State::Running {
                sync_clock_later(vm.clone());
            }
            s.name()
        };
        Ok(json!({
            "name": name,
            "dir": dest,
            "state": state,
            "paused_ms": ms(paused.elapsed()),
            "checkpoint_ms": ms(t.total()),
            "data_mib": (m.data_pages * PAGE_SIZE as u64) >> 20,
            "zero_mib": (m.zero_pages * PAGE_SIZE as u64) >> 20,
            "vmstate_kib": m.files["vmstate"].len >> 10,
            "timings_ms": t.json(),
        }))
    }

    /// Suspends `name` to local disk and frees its memory.
    pub(super) fn suspend(&self, name: &str) -> Result<Value> {
        let mut t = Phases::new();
        let _busy = self.reserve(name, "suspending", LIFECYCLE_WAIT)?;
        if name.is_empty() || name.starts_with('.') || name.contains('/') {
            bail!("cannot suspend a vm named {name:?}");
        }
        let vm = self.vm(name)?;
        let rss = vm.rss();
        let dest = self.cfg.state_dir.join("suspended").join(name);
        std::fs::create_dir_all(dest.parent().unwrap())?;
        let staging = Staging::new(&dest)?;
        let (manifest, _) = self.save(&vm, staging, &mut t)?;
        // The checkpoint is durable; only now let go of the memory. The pager
        // stops before Firecracker dies, and its page states are never read
        // again: a resume pages in from the checkpoint.
        self.vms.lock().unwrap().remove(name);
        vm.kill();
        t.mark("release");
        let data_mib = (manifest.data_pages * PAGE_SIZE as u64) >> 20;
        self.suspended.lock().unwrap().insert(name.into(), Suspended { dir: dest.clone(), manifest });
        Ok(json!({
            "name": name,
            "state": "suspended",
            "dir": dest,
            "freed_rss_mib": rss >> 20,
            "data_mib": data_mib,
            "suspend_ms": ms(t.total()),
            "timings_ms": t.json(),
        }))
    }

    /// Restores the checkpoint at `dir` as a new VM, by default with the name
    /// and address it was checkpointed with.
    pub(super) fn restore(&self, dir: &str, name: Option<&str>, ip: Option<&str>) -> Result<Value> {
        let mut t = Phases::new();
        let ck = Checkpoint::open(Path::new(dir))?;
        t.mark("verify_checkpoint");
        let name = name.unwrap_or(&ck.manifest.name).to_string();
        let _busy = self.reserve(&name, "restoring", Duration::ZERO)?;
        if name.is_empty() || self.taken(&name) {
            bail!("vm name {name:?} is empty or taken");
        }
        let ip = match ip {
            Some("auto") => self.claim_ip(None)?,
            Some(ip) => self.claim_ip(Some(ip))?,
            None => {
                let ip = ck.manifest.ip;
                for peer in &self.cfg.peers {
                    let used = peer_info(peer).is_ok_and(|i| i["ips"].as_array().is_some_and(|a| a.contains(&json!(ip.to_string()))));
                    if used {
                        bail!("{ip} is in use on {peer}; restore with --ip");
                    }
                }
                self.claim_ip(Some(&ip.to_string()))?
            }
        };
        t.mark("claim_ip");
        self.restore_checkpoint(&name, ck, ip, false, &mut t).inspect_err(|_| {
            self.ips.lock().unwrap().remove(&ip);
        })
    }

    /// Restores `ck` as VM `name` at `ip` (already claimed), its memory paged
    /// in lazily from the checkpoint and pulled in the background, the
    /// template's working set first. `owned` checkpoints (a suspended VM's)
    /// are deleted once the VM no longer needs them.
    fn restore_checkpoint(&self, name: &str, ck: Checkpoint, ip: Ipv4Addr, owned: bool, t: &mut Phases) -> Result<Value> {
        let m = ck.manifest.clone();
        let tpl = self.template(&m.template)?;
        tpl.check_id(&m.template_id)?;
        tpl.verify(&self.cfg.paths, true)?;
        t.mark("verify_template");
        let idle = self.pool.take()?;
        t.mark("pool_take");
        let (vmstate, dir) = (ck.vmstate(), ck.dir.clone());
        let origin = Some((ck.runs, Origin::File(ck.file)));
        let (vm, restore) = Vm::restore_from(idle, name, tpl, &vmstate, origin, ip, true, t)?;
        self.vms.lock().unwrap().insert(name.into(), vm.clone());
        t.mark("register");
        let ready = (|| -> Result<Duration> {
            vm.restore_devices();
            if ip != m.ip {
                vm.guest_net(ip, self.cfg.dns.as_deref())?;
                // The guest keeps its old address too; drop it if it has iproute2.
                let _ = vm.sh(&format!("ip -4 addr del {}/32 dev eth0 2>/dev/null", m.ip));
            }
            crate::guest::ping(&vm.vsock())?;
            let ready = t.total();
            t.mark("guest_ready");
            Ok(ready)
        })();
        let ready = match ready {
            Ok(r) => r,
            Err(e) => {
                self.vms.lock().unwrap().remove(name);
                vm.kill();
                return Err(e);
            }
        };
        // The guest's clock stopped when it was checkpointed.
        let clock = vm.sync_clock(CLOCK_TOLERANCE);
        t.mark("clock");
        self.announce(ip);
        let to_load = (m.data_pages * PAGE_SIZE as u64) >> 20;
        let state = vm.state().name();
        thread::spawn(move || {
            let pulled = vm.pager.wait_pulled();
            let took = vm.pager.pull_time().map(ms);
            eprintln!("vm {}: {to_load} MiB paged in from {} (complete: {pulled}, {took:?} ms)", vm.name, dir.display());
            if owned {
                if let Err(e) = std::fs::remove_dir_all(&dir) {
                    eprintln!("vm {}: removing {}: {e}", vm.name, dir.display());
                }
            }
        });
        Ok(json!({
            "name": name,
            "ip": ip.to_string(),
            "state": state,
            "restore_ms": ms(restore),
            "ready_ms": ms(ready),
            "clock_offset_ms": clock.as_ref().ok(),
            "clock_error": clock.as_ref().err().map(|e| e.to_string()),
            "to_load_mib": to_load,
            "timings_ms": t.json(),
        }))
    }

    /// Checkpoints `vm` through `staging`, leaving it in `Checkpointing`
    /// (or as it was, on failure). Returns the manifest and when it paused.
    fn save(&self, vm: &Vm, mut staging: Staging, t: &mut Phases) -> Result<(Manifest, Instant)> {
        // A VM still pulling memory from a migration source or its own
        // checkpoint finishes that first.
        if vm.pager.remote_left() > 0 && !vm.pager.wait_pulled_for(DRAIN_WAIT) {
            bail!("vm {} is still pulling its memory; try again once it has", vm.name);
        }
        t.mark("drain");
        // Disk space for the pages it has now, while it still runs.
        staging.preallocate(vm.pager.census()[crate::uffd::PRESENT as usize])?;
        t.mark("preallocate");
        vm.start_checkpoint()?;
        let paused = Instant::now();
        let saved = vm.save_state(&staging.vmstate(), true).and_then(|runs| {
            t.mark("snapshot");
            staging.commit(vm, &runs, t)
        });
        match saved {
            Ok(m) => Ok((m, paused)),
            Err(e) => match vm.end_checkpoint() {
                Ok(_) => Err(e),
                Err(r) => Err(format!("{e}; {r}").into()),
            },
        }
    }

    /// Picks up the VMs a previous daemon left suspended in `state_dir`.
    pub(super) fn load_suspended(&self) -> Result<()> {
        let root = self.cfg.state_dir.join("suspended");
        std::fs::create_dir_all(&root).map_err(|e| format!("state dir {}: {e}", root.display()))?;
        // Checkpoints of VMs that were resumed: those VMs have run since, and
        // died with the previous daemon.
        let _ = std::fs::remove_dir_all(self.cfg.state_dir.join("resumed"));
        for e in std::fs::read_dir(&root)?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                // A suspend that never completed; its VM died with the daemon.
                let _ = std::fs::remove_dir_all(e.path());
                continue;
            }
            match Checkpoint::open(&e.path()) {
                Ok(ck) => {
                    if !self.ips.lock().unwrap().insert(ck.manifest.ip) {
                        eprintln!("suspended vm {name}: {} is already taken; leaving it suspended", ck.manifest.ip);
                    }
                    eprintln!("suspended vm {name} ({}) found in {}", ck.manifest.ip, e.path().display());
                    self.suspended.lock().unwrap().insert(name, Suspended { dir: ck.dir, manifest: ck.manifest });
                }
                Err(err) => eprintln!("ignoring {}: {err}", e.path().display()),
            }
        }
        Ok(())
    }
}

/// Steps the guest's clock in the background, if it is off.
fn sync_clock_later(vm: Arc<Vm>) {
    thread::spawn(move || match vm.sync_clock(CLOCK_TOLERANCE) {
        Ok(off) if off.abs() > CLOCK_TOLERANCE.as_secs_f64() * 1e3 => {
            eprintln!("vm {}: guest clock was {off:.1} ms off after resuming; stepped it", vm.name)
        }
        Ok(_) => {}
        Err(e) => eprintln!("vm {}: checking the guest clock: {e}", vm.name),
    });
}
