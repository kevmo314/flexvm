//! Pause and resume, checkpoints, restores, and suspend (a checkpoint to the
//! host's disk, after which the process exits):
//!
//!   running <-> paused                                  (SIGTSTP / SIGCONT)
//!   running | paused -> checkpointing -> running | paused (checkpoint)
//!                                     -> gone            (checkpoint --stop)
//!                                     -> suspended       (SIGTERM; `flexvm resume`)
//!   running | paused -> source (migrating) -> gone | running | paused

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::checkpoint::{Checkpoint, CommitError, Manifest, Staging};
use crate::host::{fault, Host};
use crate::template::Template;
use crate::uffd::{Frozen, Origin};
use crate::util::{ms, Error, Phases, Result, PAGE_SIZE};
use crate::vm::{Snapshot, State, Vm};
use crate::vmproc::{End, Op, Proc, CLOCK_DEADLINE};

/// How long a checkpoint waits for a VM to finish pulling its memory.
const DRAIN_WAIT: Duration = Duration::from_secs(60);
/// How long a checkpoint waits for virtio-mem to carry out the last resize.
pub const SETTLE_WAIT: Duration = Duration::from_secs(10);
/// Longest a checkpoint's release waits for held packets still on their way.
const CKPT_RELEASE: Duration = Duration::from_millis(20);
/// Markers in a suspended VM's checkpoint: resumed (its VM may have run
/// since: never again); killed; its address's generation; and, after a resume
/// whose STARTED may or may not be durable, `<boot id> <why>` (not resumed
/// until a reboot shows what the disk holds).
const STARTED: &str = "STARTED";
const DISCARDED: &str = "DISCARDED";
const GEN: &str = "GEN";
const QUARANTINE: &str = "QUARANTINE";

/// How a restore failed: before the vCPUs ever ran, after, or before but
/// with its (owned) checkpoint maybe marked STARTED.
pub enum Restore {
    NotRun(Error),
    Ran(Error),
    Uncertain(Error),
}

impl Proc {
    /// Test hook: a hash of every page of the VM's memory in place, read out
    /// of Firecracker, with their count.
    pub fn memhash(&self) -> Result<Value> {
        let vm = self.vm();
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
        Ok(json!({"name": vm.name, "hash": hash.finish(), "pages": pages, "remote": vm.pager.remote_left()}))
    }

    /// SIGCONT: resumes a paused VM (a held restore at a new address gets it now).
    pub fn resume(&self) -> Result<Value> {
        let vm = self.vm();
        let op = self.op_within()?;
        let start = Instant::now();
        let still = self.still_current(vm.ip)?;
        vm.unpause()?;
        drop(still);
        self.paused_by_request.store(false, Ordering::SeqCst);
        let took = start.elapsed();
        if let Some(old) = vm.pending_net.lock().unwrap().take() {
            if let Err(e) = self.readdress(vm, old) {
                *vm.pending_net.lock().unwrap() = Some(old);
                bail!("vm {} resumed, but setting its address {} failed: {e}", vm.name, vm.ip);
            }
        }
        self.publish();
        drop(op);
        // Off the critical path; the guest's clock runs on while paused anyway.
        self.sync_clock_later();
        Ok(json!({"name": vm.name, "state": "running", "resume_ms": ms(took)}))
    }

    /// Gives the guest its new address, and drops the `old` one if it has iproute2.
    fn readdress(&self, vm: &Vm, old: Ipv4Addr) -> Result<()> {
        vm.guest_net(vm.ip, self.host.cfg.dns.as_deref())?;
        let _ = vm.sh(&format!("ip -4 addr del {old}/32 dev eth0 2>/dev/null"), Instant::now() + crate::guest::TIMEOUT);
        Ok(())
    }

    /// Checkpoints the VM to `dir`; it runs on (paused only to save its state
    /// and arm copy-on-write) or, `stop`, stays paused for the caller to
    /// destroy. `incremental`: only what changed since its last checkpoint.
    pub fn checkpoint(&self, _op: &Op, dir: &str, stop: bool, incremental: bool) -> Result<Value> {
        let vm = self.vm();
        let mut t = Phases::new();
        let staging = Staging::new(Path::new(dir), vm.dir.join("checkpoint.vmstate"))?;
        let dest = staging.dest().to_path_buf();
        t.mark("prepare");
        let saved = self.save(vm, staging, !stop, incremental, &mut t);
        self.publish();
        let (m, mut v) = saved?;
        let state = match vm.state() {
            _ if stop => "stopped",
            State::Running => {
                self.sync_clock_later();
                "running"
            }
            s => s.name(),
        };
        let extra = json!({
            "name": vm.name,
            "dir": dest,
            "state": state,
            "checkpoint_ms": ms(t.total()),
            "data_mib": (m.data_pages * PAGE_SIZE as u64) >> 20,
            "zero_mib": (m.zero_pages * PAGE_SIZE as u64) >> 20,
            "vmstate_kib": m.files["vmstate"].len >> 10,
            "incremental": m.parent.is_some(),
            "parent": m.parent.as_ref().map(|p| &p.path),
            "timings_ms": t.json(),
        });
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        Ok(v)
    }

    /// SIGTERM: checkpoints the VM into the host's state directory, frees it
    /// and ends the process (`flexvm resume` brings it back). Returns only if
    /// that failed; the VM runs on.
    pub fn suspend(&self) -> Error {
        let vm = self.vm();
        let mut t = Phases::new();
        let op = self.op();
        let saved = (|| -> Result<(Manifest, Value)> {
            if !matches!(vm.state(), State::Running | State::Paused) {
                bail!("vm {} is {}; not suspending it", vm.name, vm.state().name());
            }
            // The checkpoint it was resumed from goes first: this one goes there.
            if let Some(dir) = self.consumed.lock().unwrap().take() {
                delete_consumed(&vm.name, &dir);
            }
            let staging = Staging::new(&self.host.suspended(&vm.name), vm.dir.join("checkpoint.vmstate"))?;
            // Its address's generation, published with the checkpoint.
            staging.add_file(GEN, self.gen().to_string().as_bytes())?;
            let saved = self.save(vm, staging, false, false, &mut t);
            self.publish();
            saved
        })();
        match saved {
            // Durable: only now let go of the memory.
            Ok((m, _)) => {
                let data = (m.data_pages * PAGE_SIZE as u64) >> 20;
                eprintln!("{}", json!({"name": vm.name, "state": "suspended", "dir": self.host.suspended(&vm.name), "freed_rss_mib": vm.rss() >> 20, "data_mib": data, "suspend_ms": ms(t.total()), "timings_ms": t.json()}));
                self.finish(&op, End::Suspended, 0, None)
            }
            Err(e) => e,
        }
    }

    /// `flexvm resume NAME`: restores a suspended VM from its checkpoint.
    pub fn resume_suspended(&self, name: &str) -> Result<Value> {
        let mut t = Phases::new();
        self.set_name(self.host.take_name(name, true)?);
        let dir = self.host.suspended(name);
        if !dir.exists() {
            bail!("no vm named {name:?}");
        }
        if dir.join(DISCARDED).exists() || dir.join(STARTED).exists() {
            discard(&self.host, name)?;
            bail!("no vm named {name:?} (its checkpoint was consumed)");
        }
        if let Ok(q) = std::fs::read_to_string(dir.join(QUARANTINE)) {
            let (boot, why) = q.split_once(' ').unwrap_or((&q, ""));
            if boot == crate::host::boot_id() {
                bail!("vm {name} is quarantined: {why}; kill it to discard its checkpoint");
            }
            // Rebooted since: the disk holds no STARTED marker, so it never ran.
            unmark_durably(&dir, QUARANTINE)?;
        }
        let gen = read_gen(&dir).ok_or_else(|| {
            format!("vm {name} is quarantined: its address generation was never recorded, so it cannot be resumed with its address; restore its checkpoint with --ip auto")
        })?;
        let ck = Checkpoint::open(&dir)?;
        t.mark("verify_checkpoint");
        let ip = ck.manifest.ip;
        let claim = {
            let l = self.host.lock()?;
            if !self.host.current(&l, ip, gen)? {
                bail!("vm {name}: {ip} generation {gen} was withdrawn or given out again meanwhile; restore its checkpoint with --ip auto");
            }
            self.host.claim_incoming(&l, name, ip, gen)?
        };
        self.set_addr(claim);
        match self.restore_checkpoint(name, ck, ip, true, false, &mut t) {
            Ok(mut v) => {
                v["from"] = json!("suspended");
                Ok(v)
            }
            // Never ran: still suspended, as it was.
            Err(Restore::NotRun(e)) => {
                self.keep_addr();
                Err(e)
            }
            Err(Restore::Uncertain(e)) => {
                self.keep_addr();
                let _ = std::fs::write(dir.join(QUARANTINE), format!("{} {e}", crate::host::boot_id()));
                bail!("vm {name} is quarantined: {e}; kill it to discard its checkpoint")
            }
            // May have run: re-arming the checkpoint would replay what it did since.
            Err(Restore::Ran(e)) => {
                let _ = discard(&self.host, name);
                bail!("vm {name} failed after it resumed: {e}; it is gone, its checkpoint is consumed")
            }
        }
    }

    /// `flexvm restore DIR`: a new VM from a checkpoint, by default with the
    /// name and address it was checkpointed with (another host's is borrowed).
    pub fn restore(&self, dir: &Path, name: Option<&str>, ip: Option<&str>, paused: bool) -> Result<Value> {
        let mut t = Phases::new();
        let ck = Checkpoint::open(dir)?;
        t.mark("verify_checkpoint");
        let name = name.unwrap_or(&ck.manifest.name).to_string();
        self.set_name(self.host.take_name(&name, false)?);
        let want = match ip {
            Some("auto") => None,
            Some(ip) => Some(ip.parse().map_err(|_| format!("bad address {ip:?}"))?),
            None => Some(ck.manifest.ip),
        };
        let claim = match want.filter(|&ip| !self.host.cfg.range().is_ok_and(|r| r.contains(ip))) {
            Some(ip) => self.borrow(&name, ip)?,
            None => self.host.claim_new(&self.host.lock()?, &name, want).map_err(|e| format!("{e}; restore with --ip auto (or another address)"))?,
        };
        let ip = self.set_addr(claim);
        t.mark("claim_ip");
        // A user's checkpoint is immutable: restorable again, run or not.
        self.restore_checkpoint(&name, ck, ip, false, paused, &mut t).map_err(|(Restore::NotRun(e) | Restore::Ran(e) | Restore::Uncertain(e))| e)
    }

    /// Restores `ck` as VM `name` at `ip` (claimed), its memory paged in from
    /// the checkpoint and pulled in the background. An `owned` checkpoint (a
    /// suspended VM's) is marked STARTED before the VM runs and deleted once
    /// it is not needed. `hold`: left paused until SIGCONT.
    fn restore_checkpoint(&self, name: &str, ck: Checkpoint, ip: Ipv4Addr, owned: bool, hold: bool, t: &mut Phases) -> std::result::Result<Value, Restore> {
        let m = ck.manifest.clone();
        let to_load = (ck.data_pages() * PAGE_SIZE as u64) >> 20;
        let (vm, restore) = (|| -> Result<_> {
            let tpl = Template::open_id(&self.paths, &m.template, &m.template_id)?;
            t.mark("verify_template");
            let seed = Some((ck.runs, Origin::File(ck.file)));
            let prepared = Vm::prepare(self.spawner.take()?, tpl, t)?;
            prepared.load(&self.spawner, name, Snapshot::Bytes(&ck.vmstate), seed, ip, !(hold && fault("restore_no_hold")), None, || Ok(()), t)
        })()
        .map_err(Restore::NotRun)?;
        let dir = ck.dir;
        let kill = |e: Error| {
            vm.kill();
            e
        };
        vm.restore_devices();
        let ready = match (fault("restore_before_run"), vm.pager.failed(), vm.state()) {
            (true, ..) => Err("injected fault: restore failed before the vm ran".into()),
            (_, Some(why), _) => Err(format!("its memory cannot be paged in: {why}").into()),
            (_, _, State::Paused) => Ok(()),
            (_, _, s) => Err(format!("vm is {} before resuming", s.name()).into()),
        };
        ready.map_err(|e| Restore::NotRun(kill(e)))?;
        if hold {
            // Held paused, devices too, until SIGCONT; memory still paged in.
            if ip != m.ip {
                *vm.pending_net.lock().unwrap() = Some(m.ip);
            }
            self.set_vm(vm.clone());
            self.paused_by_request.store(true, Ordering::SeqCst);
            self.publish();
            self.announce();
            return Ok(json!({"name": name, "ip": ip.to_string(), "pid": std::process::id(), "state": "paused", "restore_ms": ms(restore), "timings_ms": t.json()}));
        }
        let still = self.still_current(ip).map_err(|e| Restore::NotRun(kill(e)))?;
        if owned {
            // Durably consumed before it can run: a crash must not bring it back.
            let failing = |e: &str| std::fs::remove_file(dir.join(STARTED)).and(Err(std::io::Error::other(format!("injected fault: {e}"))));
            let marked = match fault("started_fsync") {
                true => std::fs::File::create(dir.join(STARTED)).and(Err(std::io::Error::other("injected fault: fsync failed"))),
                false => mark_durably(&dir, STARTED),
            };
            if let Err(e) = marked {
                // It may be on disk, or get there: take it back durably.
                vm.kill();
                let unmarked = if fault("started_unmark") { failing("fsync failed") } else { unmark_durably(&dir, STARTED) };
                return Err(match unmarked {
                    Ok(()) => Restore::NotRun(format!("marking the checkpoint started: {e}").into()),
                    Err(r) => Restore::Uncertain(format!("marking the checkpoint started: {e}; removing the mark: {r}").into()),
                });
            }
            *self.consumed.lock().unwrap() = Some(dir.clone());
        }
        // From the resume request on, the vCPUs may have run.
        vm.unpause().map_err(|e| Restore::Ran(kill(e)))?;
        drop(still);
        t.mark("resume");
        self.set_vm(vm.clone());
        self.publish();
        t.mark("register");
        let ready = (|| -> Result<Duration> {
            if fault("restore_after_run") {
                bail!("injected fault: restore failed after the vm ran");
            }
            if ip != m.ip {
                self.readdress(&vm, m.ip)?;
            }
            crate::guest::ping(&vm.vsock())?;
            let ready = t.total();
            t.mark("guest_ready");
            Ok(ready)
        })()
        .map_err(|e| Restore::Ran(kill(e)))?;
        // The guest's clock stopped when it was checkpointed.
        let clock = vm.sync_clock(Instant::now() + CLOCK_DEADLINE);
        t.mark("clock");
        self.announce();
        let state = vm.state().name();
        let p = self.arc();
        thread::spawn(move || {
            let pulled = vm.pager.wait_pulled();
            eprintln!("vm {}: {to_load} MiB paged in from {} (complete: {pulled}, {:?} ms)", vm.name, dir.display(), vm.pager.pull_time().map(ms));
            // Under the operation lock: a suspend may be about to write here.
            if let Some(p) = p {
                let _op = p.op();
                if let Some(dir) = p.consumed.lock().unwrap().take() {
                    delete_consumed(&vm.name, &dir);
                }
            }
        });
        Ok(json!({
            "name": name,
            "ip": ip.to_string(),
            "pid": std::process::id(),
            "state": state,
            "restore_ms": ms(restore),
            "ready_ms": ms(ready),
            "clock_offset_ms": clock.as_ref().ok(),
            "clock_error": clock.as_ref().err().map(|e| e.to_string()),
            "to_load_mib": to_load,
            "timings_ms": t.json(),
        }))
    }

    /// Checkpoints `vm` through `staging`: its manifest, and what to report.
    /// Without `cow` the VM stays paused for the write, left `Checkpointing`
    /// (as it was on failure; failed if a checkpoint may have been published
    /// that could not be revoked). With `cow` it is paused only until memory
    /// is write-protected, and runs on while the pages are written.
    /// `incremental`: a delta on its last checkpoint here.
    fn save(&self, vm: &Arc<Vm>, mut staging: Staging, cow: bool, incremental: bool, t: &mut Phases) -> Result<(Manifest, Value)> {
        let last = |e: &dyn std::fmt::Display| format!("the last checkpoint of vm {}: {e}; take a full one", vm.name);
        let parent = match incremental {
            false => None,
            true => {
                let Some((dir, id)) = vm.last_checkpoint.lock().unwrap().clone().filter(|_| vm.pager.tracking()) else {
                    bail!("vm {} has no checkpoint to build on: take a full one with --keep-running first (an incremental checkpoint builds on the last one taken of the vm on this host, since it was last restored or migrated, that the vm ran on after)", vm.name)
                };
                // The whole chain must restore, with room for one more.
                let ck = Checkpoint::open(&dir).map_err(|e| last(&e))?;
                if ck.id != id {
                    bail!("{}", last(&format!("{} has changed", dir.display())));
                }
                if ck.chain.len() + 2 > crate::checkpoint::MAX_CHAIN {
                    bail!("vm {}: a delta on {} would make a chain of more than {} checkpoints; take a full one", vm.name, dir.display(), crate::checkpoint::MAX_CHAIN);
                }
                // A VM that stops after this is never stopped onto a chain
                // that cannot restore: read the pages it inherits now.
                if !cow {
                    ck.verify_data().map_err(|e| last(&e))?;
                    t.mark("verify_chain");
                }
                // A delta has about its parent's VM state: refuse it before the pause.
                if ck.meta_left < ck.vmstate.len() as u64 {
                    bail!("vm {}: the chain of {} has no metadata budget left; take a full one", vm.name, dir.display());
                }
                staging.meta_left = ck.meta_left;
                let ids: Vec<String> = std::iter::once(ck.id.clone()).chain(ck.chain_ids.iter().cloned()).collect();
                Some((crate::checkpoint::Parent { path: crate::checkpoint::parent_path(staging.dest(), &dir), id }, ids))
            }
        };
        let cancelled = || -> Result<()> {
            if vm.cancel_checkpoint.swap(0, Ordering::SeqCst) > 0 {
                bail!("vm {} is being killed", vm.name);
            }
            Ok(())
        };
        // A VM still pulling its memory finishes first, unless being killed.
        let drained = Instant::now() + DRAIN_WAIT;
        while vm.pager.remote_left() > 0 && !vm.pager.wait_pulled_for(Duration::from_millis(100)) {
            cancelled()?;
            if Instant::now() >= drained {
                bail!("vm {} is still pulling its memory; try again once it has", vm.name);
            }
        }
        t.mark("drain");
        // A virtio-mem request in flight could discard memory after the state
        // is saved (paused vCPUs do not stop the device): let it settle.
        vm.settle_hotplug(Instant::now() + SETTLE_WAIT)?;
        t.mark("settle_hotplug");
        let present = vm.pager.census()[crate::uffd::PRESENT as usize];
        staging.preallocate(if incremental { present.min(vm.pager.dirty_count()) } else { present })?;
        t.mark("preallocate");
        if cow {
            // Write-protected while it still runs, so the pause only re-protects
            // what it writes from now. Arming starts the dirty history afresh.
            if !vm.pager.tracking() {
                *vm.last_checkpoint.lock().unwrap() = None;
            }
            vm.pager.arm_tracking()?;
            t.mark("arm_tracking");
        }
        let plugged = vm.hotplug_plugged();
        cancelled()?;
        vm.start_checkpoint()?;
        let paused = Instant::now();
        let mut hold = PacketHold { d: self, vm, id: crate::migrate::migration_id(), stats: None };
        // A failed checkpoint gives back the dirty pages it took
        // (`Pager::unfreeze`), so the last one stays the base of the next delta.
        let mut memhash = None;
        let frozen = (|| -> Result<Frozen> {
            let runs = vm.save_state(&staging.vmstate(), false, true, || hold.hold(), &mut Phases::new())?;
            t.mark("snapshot");
            if fault("ckpt_memhash") {
                memhash = Some(vm.pager.content_hash()?);
                t.mark("memhash");
            }
            if fault("ckpt_fail_protect") {
                vm.pager.fail_protect.store(true, Ordering::SeqCst);
            }
            let frozen = vm.pager.freeze(&runs, incremental, cow)?;
            t.mark("freeze");
            // A device discard from just before the snapshot on would make
            // the pages disagree with the saved state.
            let checked = match vm.pager.discards() != vm.snapshot_discards.load(Ordering::SeqCst) {
                true => Err("guest memory changed after the vm was paused (a device discarded pages); try again".into()),
                false => cancelled(),
            };
            checked.inspect_err(|_| vm.pager.unfreeze(&frozen)).map(|()| frozen)
        })();
        let frozen = frozen.map_err(|e| match hold.end() {
            Ok(_) => e,
            Err(r) => format!("{e}; {r}").into(),
        })?;
        let (mut pause, mut growth) = (None, None);
        // Free page reports wait in the balloon's queue until the copy is over
        // (released when this drops): a discard of an unsaved page would stall
        // the guest. The guard first: a hold whose answer is lost may still apply.
        let _held = (cow && !fault("ckpt_no_hold")).then(|| {
            let held = HeldReports(vm);
            if let Err(e) = vm.hold_reports() {
                eprintln!("vm {}: free page reports may not be held during the copy: {e}", vm.name);
            }
            held
        });
        if cow {
            hold.end().inspect_err(|_| vm.pager.unfreeze(&frozen))?;
            pause = Some(paused.elapsed());
            t.mark("resume");
            // Running on during the copy: it may grow meanwhile.
            growth = Some(CopyGrowth::start(vm));
            if fault("ckpt_abort") {
                // Test: give the copy up half way through.
                let (pager, c) = (vm.pager.clone(), frozen.cow.clone().unwrap());
                let half = c.left() / 2;
                thread::spawn(move || {
                    let start = Instant::now();
                    while c.left() > half && c.active() && start.elapsed() < Duration::from_secs(10) {
                        thread::sleep(Duration::from_millis(1));
                    }
                    pager.abort_copy();
                });
            }
        }
        // Test gate: COW armed, disk writers held off until the test is done.
        while cow && fault("ckpt_copy_wait") {
            cancelled().inspect_err(|_| vm.pager.unfreeze(&frozen))?;
            thread::sleep(Duration::from_millis(10));
        }
        let slow = Duration::from_millis(if fault("ckpt_crawl") { 500 } else if fault("ckpt_slow") { 50 } else { 0 });
        let cow_pages = frozen.cow.as_deref().map(|c| crate::cow::CowPages { guest: vm.pager.as_ref(), cow: c, slow });
        let src: &dyn crate::checkpoint::GuestPages = match &cow_pages {
            Some(c) => c,
            None => vm.pager.as_ref(),
        };
        let snapshot_discards = vm.snapshot_discards.load(Ordering::SeqCst);
        let dest = staging.dest().to_path_buf();
        let (parent, links) = parent.unzip();
        let pinned = staging.pinned_dir();
        let parent_ref = parent.clone();
        let committed = staging.commit(vm, src, &frozen.runs, parent, plugged.unwrap_or(0), t, || {
            cancelled()?;
            if fault("ckpt_fail_write") {
                bail!("injected fault: writing the checkpoint failed");
            }
            // The chain this delta needs must still be there, unchanged, walked
            // as a restore will (this one's `../NAME` is NAME in the pinned dir).
            if let (Some(p), Some(ids)) = (&parent_ref, &links) {
                let first = p.path.strip_prefix("../").map_or_else(|| PathBuf::from(&p.path), |name| pinned.join(name));
                let now = crate::checkpoint::chain_ids(&first);
                if now.as_ref().ok() != Some(ids) {
                    bail!("the checkpoints this delta builds on changed or went ({}); take a full one", now.err().map_or("other ids".into(), |e| e.to_string()));
                }
            }
            match &frozen.cow {
                // Discards while it runs are fine once their pages were saved.
                Some(c) => {
                    if let Some(why) = c.error() {
                        bail!("{why}; try again");
                    }
                }
                None if vm.pager.discards() != snapshot_discards => {
                    bail!("guest memory changed after the vm was paused (a device discarded pages); try again")
                }
                None => {}
            }
            // A copy-on-write copy lets the VM grow; it saved the size at the pause.
            match vm.hotplug_plugged() {
                Some(now) if cow && now >= plugged.unwrap_or(0) => Ok(()),
                now if now == plugged => Ok(()),
                now => bail!("guest memory was resized during the checkpoint ({plugged:?} -> {now:?} MiB plugged); try again"),
            }
        });
        // No resize is in progress once this drops, and none starts.
        drop(growth);
        let copy = frozen.cow.as_ref().map(|c| c.report());
        match &committed {
            Ok(_) => vm.pager.end_copy(),
            Err(_) => vm.pager.unfreeze(&frozen),
        }
        let paused = pause.unwrap_or_else(|| paused.elapsed());
        match committed {
            Ok((manifest, id)) => {
                // The new base of deltas, if the VM runs on with tracking.
                *vm.last_checkpoint.lock().unwrap() = cow.then(|| (dest, id.clone()));
                Ok((manifest, json!({
                    "id": id,
                    "paused_ms": ms(paused),
                    "dirty_mib": (frozen.dirty * PAGE_SIZE) >> 20,
                    "protect": {"ranges": frozen.protected, "ms": ms(frozen.protect)},
                    "copy": copy,
                    "pause_memhash": memhash,
                    "held_packets": hold.stats.map(|s| s.json()),
                })))
            }
            Err(CommitError::Failed(e)) if cow => Err(e),
            Err(CommitError::Failed(e)) => match hold.end() {
                Ok(_) => Err(e),
                Err(r) => Err(format!("{e}; {r}").into()),
            },
            // Running on already: like any checkpoint of a VM that ran on.
            Err(CommitError::Uncertain(e)) if cow => Err(format!("{e}; the checkpoint may reappear after a crash").into()),
            Err(CommitError::Uncertain(e)) => {
                vm.set_failed();
                Err(format!("{e}; vm {} stays paused and is marked failed, as the checkpoint may come back", vm.name).into())
            }
        }
    }
}

/// Packets for the VM while a checkpoint has it paused, held as a migration
/// does (see `hold`); `end` injects them into its tap and routes the address
/// back before it resumes, ahead of newer traffic. Dropped, they are forgotten.
struct PacketHold<'a> {
    d: &'a Proc,
    vm: &'a Vm,
    id: u64,
    stats: Option<crate::hold::Stats>,
}

impl PacketHold<'_> {
    /// `save_state`'s `unroute`: just before the pause.
    fn hold(&self) {
        if let Some(Err(e)) = self.d.holder().map(|h| h.hold(self.vm.ip, self.id)) {
            eprintln!("vm {}: not holding packets during the checkpoint: {e}", self.vm.name);
        }
    }

    /// Hands the held packets to the VM, then `Vm::end_checkpoint`.
    fn end(&mut self) -> Result<State> {
        let Some(h) = self.d.holder() else { return self.vm.end_checkpoint() };
        let (ip, tap) = (self.vm.ip, &self.vm.tap);
        self.stats = crate::migrate::release_into(h, ip, self.id, self.vm, CKPT_RELEASE, |()| crate::net::attach(ip, tap));
        let res = self.vm.end_checkpoint();
        // Never left on the device, even if the route could not be switched back.
        h.forget(ip, self.id);
        res
    }
}

impl Drop for PacketHold<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.d.holder() {
            h.forget(self.vm.ip, self.id);
        }
    }
}

/// Releases the free page reports a copy-on-write checkpoint held (else the
/// controller retries).
struct HeldReports<'a>(&'a Vm);

impl Drop for HeldReports<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.release_reports(Duration::from_secs(5)) {
            eprintln!("vm {}: releasing free page reports failed: {e}", self.0.name);
        }
    }
}

/// While alive, the VM may grow although its checkpoint holds the operation
/// lock (see `Proc::resize`); dropping it waits for a resize in progress.
struct CopyGrowth<'a>(&'a Vm);

impl<'a> CopyGrowth<'a> {
    fn start(vm: &'a Vm) -> Self {
        *vm.cow_copy.lock().unwrap() = true;
        CopyGrowth(vm)
    }
}

impl Drop for CopyGrowth<'_> {
    fn drop(&mut self) {
        *self.0.cow_copy.lock().unwrap() = false;
    }
}

fn read_gen(dir: &Path) -> Option<u64> {
    std::fs::read_to_string(dir.join(GEN)).ok()?.trim().parse().ok()
}

fn mark_durably(dir: &Path, name: &str) -> std::io::Result<()> {
    std::fs::File::create(dir.join(name))?.sync_all()?;
    std::fs::File::open(dir)?.sync_all()
}

/// Removes `dir/name` (or `dir/manifest.json`: `delete_checkpoint`), if there, durably.
fn unmark_durably(dir: &Path, name: &str) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(name)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => std::fs::File::open(dir)?.sync_all(),
    }
}

/// Deletes a checkpoint marked STARTED or DISCARDED: the manifest first,
/// durably (what is left cannot load), then the rest, so a crash midway
/// never leaves a complete checkpoint without its marker.
pub fn delete_consumed(name: &str, dir: &Path) {
    if let Err(e) = unmark_durably(dir, "manifest.json").and_then(|()| std::fs::remove_dir_all(dir)) {
        eprintln!("vm {name}: removing {}: {e}", dir.display());
    }
}

/// Deletes suspended VM `name` (killed, or its checkpoint consumed): marked
/// DISCARDED durably first, then its address freed and withdrawn.
pub fn discard(host: &Host, name: &str) -> Result<()> {
    let dir = host.suspended(name);
    let (ip, gen) = (manifest(&dir).map(|m| m.ip), read_gen(&dir));
    mark_durably(&dir, DISCARDED).map_err(|e| format!("discarding the checkpoint of {name}: {e}"))?;
    delete_consumed(name, &dir);
    if let Some(ip) = ip {
        let l = host.lock()?;
        host.release(&l, ip, name)?;
        if let Some(gen) = gen {
            host.observe(&l, ip, gen, None)?;
            drop(l);
            crate::vmproc::tell_peers(host, json!({"op": "route", "ip": ip.to_string(), "gen": gen}));
        }
    }
    Ok(())
}

/// A checkpoint's manifest, unverified.
fn manifest(dir: &Path) -> Option<Manifest> {
    let text = std::fs::read(dir.join("manifest.json")).ok()?;
    serde_json::from_slice(text.splitn(2, |&b| b == b'\n').nth(1)?).ok()
}

/// What `ls` shows of a suspended VM; not one consumed or discarded.
pub fn describe_suspended(host: &Host, name: &str) -> Option<Value> {
    let dir = host.suspended(name);
    if dir.join(STARTED).exists() || dir.join(DISCARDED).exists() {
        return None;
    }
    let m = manifest(&dir)?;
    let state = if read_gen(&dir).is_none() || dir.join(QUARANTINE).exists() { "quarantined" } else { "suspended" };
    Some(json!({
        "name": name, "ip": m.ip.to_string(), "template": m.template, "template_id": m.template_id,
        "state": state, "vcpus": m.vcpus, "guest_mib": m.mem_mib + m.hotplug_mib, "max_mib": m.max_mib,
        "checkpoint_mib": (m.data_pages * PAGE_SIZE as u64) >> 20,
    }))
}

/// Test hook: the canonical hash of the memory a checkpoint (chain) restores.
pub fn ckhash(paths: &crate::template::Paths, dir: &Path) -> Result<Value> {
    let ck = Checkpoint::open(dir)?;
    let tpl = Template::open(paths, &ck.manifest.template)?;
    tpl.check_id(&ck.manifest.template_id)?;
    Ok(json!({"hash": ck.content_hash(&tpl)?, "id": ck.id, "chain": ck.chain, "data_pages": ck.data_pages()}))
}
