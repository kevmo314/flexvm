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

    /// Test hook (FLEXVM_FAULTS=1): a hash of every page of `name`'s memory
    /// that is in place, read out of Firecracker, with their count.
    pub(super) fn memhash(&self, name: &str) -> Result<Value> {
        if self.faults.is_none() {
            bail!("memhash is a test hook (start the daemon with FLEXVM_FAULTS=1)");
        }
        let vm = self.vm(name)?;
        let mut hash = crate::template::Hash::new();
        let (mut pages, mut buf) = (0u64, vec![0u8; 256 * PAGE_SIZE]);
        for (first, count) in vm.pager.present_runs() {
            let (mut p, end) = (first, first + count);
            while p < end {
                let region_end = vm.pager.region_end(p as usize).ok_or("page outside guest memory")? as u64;
                let n = (end - p).min(256).min(region_end - p);
                let b = &mut buf[..n as usize * PAGE_SIZE];
                vm.pager.read_guest(p * PAGE_SIZE as u64, b)?;
                hash.word(p);
                hash.update(b);
                pages += n;
                p += n;
            }
        }
        Ok(json!({"name": name, "hash": hash.finish(), "pages": pages, "remote": vm.pager.remote_left()}))
    }

    pub(super) fn pause(&self, name: &str) -> Result<Value> {
        let _busy = self.reserve(name, "pausing", LIFECYCLE_WAIT)?;
        let vm = self.vm(name)?;
        let start = Instant::now();
        vm.pause()?;
        Ok(json!({"name": name, "state": "paused", "pause_ms": ms(start.elapsed())}))
    }

    /// Resumes a paused VM, or restores a suspended one from its checkpoint.
    pub(super) fn resume(self: &Arc<Self>, name: &str) -> Result<Value> {
        let busy = self.reserve(name, "resuming", LIFECYCLE_WAIT)?;
        if let Ok(vm) = self.vm(name) {
            let start = Instant::now();
            vm.unpause()?;
            let took = start.elapsed();
            // A held restore at a new address: the guest gets it now, still
            // under the reservation.
            let old = vm.pending_net.lock().unwrap().take();
            if let Some(old) = old {
                if let Err(e) = vm.guest_net(vm.ip, self.cfg.dns.as_deref()) {
                    *vm.pending_net.lock().unwrap() = Some(old);
                    bail!("vm {name} resumed, but setting its address {} failed: {e}", vm.ip);
                }
                let deadline = Instant::now() + crate::guest::TIMEOUT;
                let _ = vm.sh(&format!("ip -4 addr del {old}/32 dev eth0 2>/dev/null"), deadline);
            }
            drop(busy);
            // Off the critical path: the guest's clock keeps counting while
            // paused (its TSC runs on), so this rarely needs to change it.
            self.sync_clock_later(vm);
            return Ok(json!({"name": name, "state": "running", "from": "paused", "resume_ms": ms(took)}));
        }
        let mut t = Phases::new();
        let s = self.suspended.lock().unwrap().remove(name);
        let Some(s) = s else { bail!("no vm named {name:?}") };
        // The checkpoint stays where it is; `restore_checkpoint` marks it
        // STARTED, durably, before any vCPU runs, and a daemon restart
        // discards started checkpoints instead of bringing them back.
        let res = Checkpoint::open(&s.dir).map_err(Restore::NotRun).and_then(|ck| {
            t.mark("verify_checkpoint");
            self.restore_checkpoint(name, ck, s.manifest.ip, true, false, &mut t)
        });
        match res {
            Ok(mut v) => {
                v["from"] = json!("suspended");
                Ok(v)
            }
            // The VM never ran: it is still suspended, as it was.
            Err(Restore::NotRun(e)) => {
                self.suspended.lock().unwrap().insert(name.into(), s);
                Err(e)
            }
            // Its vCPUs may have run, so its checkpoint is consumed:
            // re-arming it would replay whatever the VM did since.
            Err(Restore::Ran(e)) => {
                self.ips.lock().unwrap().remove(&s.manifest.ip);
                if let Err(r) = delete_checkpoint(&s.dir) {
                    eprintln!("vm {name}: removing {}: {r}", s.dir.display());
                }
                bail!("vm {name} failed after it resumed: {e}; it is gone, its checkpoint is consumed")
            }
        }
    }

    /// Checkpoints `name` to `dir`, then resumes it or (`stop`) kills it.
    pub(super) fn checkpoint(self: &Arc<Self>, name: &str, dir: &str, stop: bool) -> Result<Value> {
        let mut t = Phases::new();
        let busy = self.reserve(name, "checkpointing", LIFECYCLE_WAIT)?;
        let vm = self.vm(name)?;
        let staging = Staging::new(Path::new(dir), vm.dir.join("checkpoint.vmstate"))?;
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
            drop(busy);
            if s == State::Running {
                self.sync_clock_later(vm.clone());
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
        let staging = Staging::new(&dest, vm.dir.join("checkpoint.vmstate"))?;
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

    /// Deletes a suspended VM's checkpoint for `kill`: first marks it
    /// DISCARDED, durably, so the kill holds across a crash (a restart
    /// deletes marked checkpoints) even if the deletion does not.
    pub(super) fn discard_suspended(&self, name: &str, s: &Suspended) -> Result<()> {
        mark_durably(&s.dir, DISCARDED).map_err(|e| format!("discarding the checkpoint of {name}: {e}"))?;
        if let Err(e) = delete_checkpoint(&s.dir) {
            eprintln!("vm {name}: removing {}: {e}", s.dir.display());
        }
        Ok(())
    }

    /// Restores the checkpoint at `dir` as a new VM, by default with the name
    /// and address it was checkpointed with.
    pub(super) fn restore(&self, dir: &str, name: Option<&str>, ip: Option<&str>, paused: bool) -> Result<Value> {
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
        // A user's checkpoint is immutable and may be restored again whether
        // or not this VM got to run.
        self.restore_checkpoint(&name, ck, ip, false, paused, &mut t).map_err(|e| {
            self.ips.lock().unwrap().remove(&ip);
            e.error()
        })
    }

    /// Restores `ck` as VM `name` at `ip` (already claimed), its memory paged
    /// in lazily from the checkpoint and pulled in the background, the
    /// template's working set first. `owned` checkpoints (a suspended VM's)
    /// are deleted once the VM no longer needs them. On failure, says
    /// whether the VM's vCPUs ran.
    fn restore_checkpoint(&self, name: &str, ck: Checkpoint, ip: Ipv4Addr, owned: bool, hold: bool, t: &mut Phases) -> std::result::Result<Value, Restore> {
        let m = ck.manifest.clone();
        let (vm, restore) = (|| -> Result<_> {
            let tpl = self.template(&m.template)?;
            tpl.check_id(&m.template_id)?;
            tpl.verify(&self.cfg.paths, true)?;
            t.mark("verify_template");
            let idle = self.pool.take()?;
            t.mark("pool_take");
            // Load the bytes that were verified, from a file only root controls.
            let vmstate = idle.dir.join("vmstate.in");
            std::fs::write(&vmstate, &ck.vmstate)?;
            let origin = Some((ck.runs, Origin::File(ck.file)));
            let load = match hold && self.fault("restore_no_hold") {
                true => crate::vm::Load::PausedUnheld,
                false => crate::vm::Load::Paused,
            };
            // Loaded paused: everything up to the resume below can fail
            // without the VM having run.
            Vm::restore_from(idle, name, tpl, &vmstate, origin, ip, load, t)
        })()
        .map_err(Restore::NotRun)?;
        let dir = ck.dir;
        let kill = |e: Error| {
            vm.kill();
            e
        };
        vm.restore_devices();
        if self.fault("restore_before_run") {
            return Err(Restore::NotRun(kill("injected fault: restore failed before the vm ran".into())));
        }
        // Everything that can fail without the VM having run, first.
        if let Some(why) = vm.pager.failed() {
            return Err(Restore::NotRun(kill(format!("its memory cannot be paged in: {why}").into())));
        }
        if vm.state() != State::Paused {
            return Err(Restore::NotRun(kill(format!("vm is {} before resuming", vm.state().name()).into())));
        }
        if hold {
            // Held paused, devices frozen too (see `Vm::restore_from`), until
            // `resume`; its memory is still paged in meanwhile. A new address
            // reaches the guest on that resume.
            if ip != m.ip {
                *vm.pending_net.lock().unwrap() = Some(m.ip);
            }
            self.vms.lock().unwrap().insert(name.into(), vm.clone());
            self.announce(ip);
            return Ok(json!({"name": name, "ip": ip.to_string(), "state": "paused", "restore_ms": ms(restore), "timings_ms": t.json()}));
        }
        if owned {
            // Durably consumed before it can run: a crash from here on must
            // not bring this checkpoint back (see `load_suspended`).
            if let Err(e) = mark_durably(&dir, STARTED) {
                let _ = std::fs::remove_file(dir.join(STARTED));
                return Err(Restore::NotRun(kill(format!("marking the checkpoint started: {e}").into())));
            }
        }
        // From the resume request on, the vCPUs may have run.
        vm.unpause().map_err(|e| Restore::Ran(kill(e)))?;
        t.mark("resume");
        self.vms.lock().unwrap().insert(name.into(), vm.clone());
        t.mark("register");
        let ready = (|| -> Result<Duration> {
            if self.fault("restore_after_run") {
                bail!("injected fault: restore failed after the vm ran");
            }
            if ip != m.ip {
                vm.guest_net(ip, self.cfg.dns.as_deref())?;
                // The guest keeps its old address too; drop it if it has iproute2.
                let deadline = Instant::now() + crate::guest::TIMEOUT;
                let _ = vm.sh(&format!("ip -4 addr del {}/32 dev eth0 2>/dev/null", m.ip), deadline);
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
                return Err(Restore::Ran(kill(e)));
            }
        };
        // The guest's clock stopped when it was checkpointed. The caller
        // holds the VM's reservation, as every clock step must.
        let clock = vm.sync_clock(CLOCK_TOLERANCE, Instant::now() + CLOCK_DEADLINE);
        t.mark("clock");
        self.announce(ip);
        let to_load = (m.data_pages * PAGE_SIZE as u64) >> 20;
        let state = vm.state().name();
        thread::spawn(move || {
            let pulled = vm.pager.wait_pulled();
            let took = vm.pager.pull_time().map(ms);
            eprintln!("vm {}: {to_load} MiB paged in from {} (complete: {pulled}, {took:?} ms)", vm.name, dir.display());
            if owned {
                if let Err(e) = delete_checkpoint(&dir) {
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
    /// (or as it was, on failure; or failed, if a checkpoint may have been
    /// published that could not be revoked). Returns the manifest and when
    /// it paused.
    fn save(&self, vm: &Vm, mut staging: Staging, t: &mut Phases) -> Result<(Manifest, Instant)> {
        // A VM still pulling memory from a migration source or its own
        // checkpoint finishes that first.
        if vm.pager.remote_left() > 0 && !vm.pager.wait_pulled_for(DRAIN_WAIT) {
            bail!("vm {} is still pulling its memory; try again once it has", vm.name);
        }
        t.mark("drain");
        // Pausing stops the vCPUs, not Firecracker's device handling: a
        // virtio-mem request still in flight could discard memory after the
        // state is saved. The guest only sends one to follow a size change
        // from the host, so wait until it has followed the last one (the
        // controller cannot make another while we hold the reservation).
        vm.settle_hotplug(Instant::now() + SETTLE_WAIT)?;
        t.mark("settle_hotplug");
        // Disk space for the pages it has now, while it still runs.
        staging.preallocate(vm.pager.census()[crate::uffd::PRESENT as usize])?;
        t.mark("preallocate");
        let plugged = vm.hotplug_plugged();
        vm.start_checkpoint()?;
        let paused = Instant::now();
        let saved = vm.save_state(&staging.vmstate(), true).map_err(CommitError::Failed).and_then(|runs| {
            t.mark("snapshot");
            // A discard (balloon or virtio-mem) or resize from just before the
            // snapshot on would make the pages disagree with the saved state:
            // never publish such a checkpoint (the next attempt can succeed).
            let discards = vm.snapshot_discards.load(Ordering::SeqCst);
            staging.commit(vm, &runs, t, || {
                if vm.pager.discards() != discards || vm.hotplug_plugged() != plugged {
                    bail!("guest memory changed after the vm was paused (a device discarded pages); try again");
                }
                Ok(())
            })
        });
        match saved {
            Ok(m) => Ok((m, paused)),
            Err(CommitError::Failed(e)) => match vm.end_checkpoint() {
                Ok(_) => Err(e),
                Err(r) => Err(format!("{e}; {r}").into()),
            },
            Err(CommitError::Uncertain(e)) => {
                vm.set_failed();
                Err(format!("{e}; vm {} stays paused and is marked failed, as the checkpoint may come back", vm.name).into())
            }
        }
    }

    /// Picks up the VMs a previous daemon left suspended in `state_dir`,
    /// which this daemon has locked.
    pub(super) fn load_suspended(&self) -> Result<()> {
        let root = self.cfg.state_dir.join("suspended");
        for e in std::fs::read_dir(&root)?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let (started, discarded) = (e.path().join(STARTED).exists(), e.path().join(DISCARDED).exists());
            if name.starts_with('.') || started || discarded {
                // Staging of a suspend that never completed (its VM died with
                // the daemon), a VM that was resumed (it has run since, and
                // died with the daemon), or a killed one. Only root writes here.
                if let Err(err) = delete_checkpoint(&e.path()) {
                    eprintln!("removing {}: {err}", e.path().display());
                }
                continue;
            }
            match Checkpoint::open(&e.path()) {
                Ok(ck) => {
                    if !self.ips.lock().unwrap().insert(ck.manifest.ip) {
                        eprintln!("suspended vm {name}: {} is already taken", ck.manifest.ip);
                    }
                    eprintln!("suspended vm {name} ({}) found in {}", ck.manifest.ip, e.path().display());
                    self.suspended.lock().unwrap().insert(name, Suspended { dir: ck.dir, manifest: ck.manifest });
                }
                Err(err) => eprintln!("ignoring {}: {err}", e.path().display()),
            }
        }
        Ok(())
    }


    /// Steps the guest's clock in the background, if it is off: under the
    /// VM's reservation (so never inside a snapshot or on a VM that has
    /// migrated on), and at most one at a time per VM.
    fn sync_clock_later(self: &Arc<Self>, vm: Arc<Vm>) {
        if vm.clock_pending.swap(true, Ordering::SeqCst) {
            return;
        }
        let d = self.clone();
        thread::spawn(move || {
            let res = d.reserve(&vm.name, "clock", LIFECYCLE_WAIT).and_then(|_busy| {
                let current = d.vm(&vm.name).is_ok_and(|v| Arc::ptr_eq(&v, &vm));
                vm.clock_pending.store(false, Ordering::SeqCst);
                if !current || vm.state() != State::Running {
                    return Ok(None);
                }
                vm.sync_clock(CLOCK_TOLERANCE, Instant::now() + CLOCK_DEADLINE).map(Some)
            });
            vm.clock_pending.store(false, Ordering::SeqCst);
            match res {
                Ok(Some(off)) if off.abs() > CLOCK_TOLERANCE.as_secs_f64() * 1e3 => {
                    eprintln!("vm {}: guest clock was {off:.1} ms off after resuming; stepped it", vm.name)
                }
                Ok(_) => {}
                Err(e) => eprintln!("vm {}: checking the guest clock: {e}", vm.name),
            }
        });
    }
}

/// How a restore failed: before the VM's vCPUs ever ran, or after.
pub(super) enum Restore {
    NotRun(Error),
    Ran(Error),
}

impl Restore {
    fn error(self) -> Error {
        match self {
            Restore::NotRun(e) | Restore::Ran(e) => e,
        }
    }
}


/// In a suspended VM's checkpoint: it has been resumed (its VM may have run
/// since), so it must never be resumed again.
const STARTED: &str = "STARTED";
/// In a suspended VM's checkpoint: the VM was killed.
const DISCARDED: &str = "DISCARDED";

/// Creates marker file `name` in `dir` and makes it durable.
fn mark_durably(dir: &Path, name: &str) -> std::io::Result<()> {
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(dir.join(name))?.sync_all()?;
    std::fs::File::open(dir)?.sync_all()
}

/// Creates `dir` and any missing parents, and fsyncs every parent along the
/// way (each time, as a crash may have lost an entry made before), so the
/// hierarchy survives a power loss.
pub(super) fn create_dir_durably(dir: &Path) -> std::io::Result<()> {
    let dir = std::path::absolute(dir)?;
    let mut path = PathBuf::from("/");
    for part in dir.components().skip(1) {
        let parent = path.clone();
        path.push(part);
        match std::fs::create_dir(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e),
            _ => {}
        }
        std::fs::File::open(&parent)?.sync_all()?;
    }
    Ok(())
}

/// Deletes a checkpoint directory so that a crash part way through cannot
/// leave a complete checkpoint without its marker (`remove_dir_all` may
/// unlink STARTED or DISCARDED first): the manifest goes first, durably,
/// which makes what is left unloadable, then the rest. If the manifest
/// cannot be removed durably, nothing else is touched.
fn delete_checkpoint(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join("manifest.json")) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    std::fs::File::open(dir)?.sync_all()?;
    std::fs::remove_dir_all(dir)
}
