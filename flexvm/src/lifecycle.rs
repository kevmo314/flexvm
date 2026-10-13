//! Pause and resume, durable checkpoints, restores from them, and suspend
//! (a checkpoint to local disk, after which the process exits).
//!
//!   running <-> paused                                  (SIGTSTP / SIGCONT)
//!   running | paused -> checkpointing -> running | paused (checkpoint)
//!                                     -> gone            (checkpoint --stop)
//!                                     -> suspended       (SIGTERM; `flexvm resume`)
//!   running | paused -> source (migrating) -> gone | running | paused
//!
//! A paused VM migrates without post-copy: it stays paused on the target,
//! which pulls all its pages before it can run.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::checkpoint::{Checkpoint, CommitError, Manifest, Staging};
use crate::template::Template;
use crate::host::{fault, Host};
use crate::uffd::{Frozen, Origin};
use crate::util::{ms, Error, Phases, Result, PAGE_SIZE};
use crate::vm::{State, Vm};
use crate::vmproc::{End, Op, Proc, CLOCK_DEADLINE};

/// How long a checkpoint waits for a VM to finish pulling its memory.
const DRAIN_WAIT: Duration = Duration::from_secs(60);
/// How long a checkpoint waits for virtio-mem to carry out the last resize.
pub const SETTLE_WAIT: Duration = Duration::from_secs(10);

impl Proc {
    /// Test hook: a hash of every page of the VM's memory that is in place,
    /// read out of Firecracker, with their count.
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

    /// SIGCONT: resumes a paused VM.
    pub fn resume(&self) -> Result<Value> {
        let vm = self.vm();
        let op = self.op_within()?;
        let start = Instant::now();
        let still = self.still_current(vm.ip)?;
        vm.unpause()?;
        drop(still);
        self.paused_by_request.store(false, Ordering::SeqCst);
        let took = start.elapsed();
        // A held restore at a new address: the guest gets it now.
        let old = vm.pending_net.lock().unwrap().take();
        if let Some(old) = old {
            if let Err(e) = vm.guest_net(vm.ip, self.host.cfg.dns.as_deref()) {
                *vm.pending_net.lock().unwrap() = Some(old);
                bail!("vm {} resumed, but setting its address {} failed: {e}", vm.name, vm.ip);
            }
            let deadline = Instant::now() + crate::guest::TIMEOUT;
            let _ = vm.sh(&format!("ip -4 addr del {old}/32 dev eth0 2>/dev/null"), deadline);
        }
        // Running in the registry once it has its address.
        self.publish();
        drop(op);
        // Off the critical path: the guest's clock keeps counting while
        // paused (its TSC runs on), so this rarely needs to change it.
        self.sync_clock_later();
        Ok(json!({"name": vm.name, "state": "running", "resume_ms": ms(took)}))
    }

    /// Checkpoints the VM to `dir`, then it runs on or (`stop`) stays paused
    /// for the caller to destroy. A VM that runs on is paused only to save
    /// its state and arm copy-on-write; its pages are written while it runs.
    /// `incremental` writes only what changed since its last such checkpoint.
    pub fn checkpoint(&self, _op: &Op, dir: &str, stop: bool, incremental: bool) -> Result<Value> {
        let vm = self.vm();
        let mut t = Phases::new();
        let staging = Staging::new(Path::new(dir), vm.dir.join("checkpoint.vmstate"))?;
        let dest = staging.dest().to_path_buf();
        t.mark("prepare");
        let saved = self.save(vm, staging, !stop, incremental, &mut t);
        self.publish();
        let saved = saved?;
        let m = &saved.manifest;
        let state = match vm.state() {
            _ if stop => "stopped",
            State::Running => {
                self.sync_clock_later();
                "running"
            }
            s => s.name(),
        };
        Ok(json!({
            "name": vm.name,
            "dir": dest,
            "state": state,
            "paused_ms": ms(saved.paused),
            "checkpoint_ms": ms(t.total()),
            "data_mib": (m.data_pages * PAGE_SIZE as u64) >> 20,
            "zero_mib": (m.zero_pages * PAGE_SIZE as u64) >> 20,
            "vmstate_kib": m.files["vmstate"].len >> 10,
            "incremental": m.parent.is_some(),
            "parent": m.parent.as_ref().map(|p| &p.path),
            "id": saved.id,
            "dirty_mib": (saved.dirty * PAGE_SIZE) >> 20,
            "protect": {"ranges": saved.protected, "ms": ms(saved.protect)},
            "copy": saved.copy,
            "pause_memhash": saved.memhash,
            "held_packets": saved.held,
            "timings_ms": t.json(),
        }))
    }

    /// SIGTERM: checkpoints the VM into the host's state directory, frees
    /// it and ends the process; `flexvm resume` brings it back. Returns only
    /// if that failed (the VM runs on).
    pub fn suspend(&self) -> Error {
        let vm = self.vm();
        let mut t = Phases::new();
        let op = self.op();
        let saved = (|| -> Result<Saved> {
            if !matches!(vm.state(), State::Running | State::Paused) {
                bail!("vm {} is {}; not suspending it", vm.name, vm.state().name());
            }
            // The checkpoint it was resumed from, if any, goes first: it is
            // where this one goes.
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
            // Durable: only now let go of the memory. The pager stops before
            // Firecracker dies, and its page states are never read again: a
            // resume pages in from the checkpoint.
            Ok(s) => {
                let data = (s.manifest.data_pages * PAGE_SIZE as u64) >> 20;
                eprintln!("{}", json!({"name": vm.name, "state": "suspended", "freed_rss_mib": vm.rss() >> 20, "data_mib": data, "suspend_ms": ms(t.total()), "timings_ms": t.json()}));
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
        let marked = |m: &str| dir.join(m).exists();
        if !dir.exists() {
            bail!("no vm named {name:?}");
        }
        if marked(DISCARDED) || marked(STARTED) {
            // Killed, or resumed before (its VM may have run since): gone.
            discard(&self.host, name)?;
            bail!("no vm named {name:?} (its checkpoint was consumed)");
        }
        if let Ok(q) = std::fs::read_to_string(dir.join(QUARANTINE)) {
            let (boot, why) = q.split_once(' ').unwrap_or((&q, ""));
            if boot == boot_id() {
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
            // Claimed as its own again, in case a stale holder record is there.
            self.host.claim_incoming(&l, name, ip, gen)?
        };
        self.set_addr(claim);
        match self.restore_checkpoint(name, ck, ip, true, false, &mut t) {
            Ok(mut v) => {
                v["from"] = json!("suspended");
                Ok(v)
            }
            // The VM never ran: it is still suspended, as it was.
            Err(Restore::NotRun(e)) => {
                self.keep_addr();
                Err(e)
            }
            // It never ran, but its checkpoint may or may not be marked
            // STARTED on disk: neither resumable nor to be deleted, until a
            // reboot shows what the disk holds.
            Err(Restore::Uncertain(e)) => {
                self.keep_addr();
                let why = e.to_string();
                let _ = std::fs::write(dir.join(QUARANTINE), format!("{} {why}", boot_id()));
                bail!("vm {name} is quarantined: {why}; kill it to discard its checkpoint")
            }
            // Its vCPUs may have run, so its checkpoint is consumed:
            // re-arming it would replay whatever the VM did since.
            Err(Restore::Ran(e)) => {
                let _ = discard(&self.host, name);
                bail!("vm {name} failed after it resumed: {e}; it is gone, its checkpoint is consumed")
            }
        }
    }

    /// `flexvm restore DIR`: a new VM from a checkpoint, by default with the
    /// name and address it was checkpointed with.
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
            // Another host's address: borrowed from that host.
            Some(ip) => self.borrow(&name, ip)?,
            None => {
                let l = self.host.lock()?;
                self.host.claim_new(&l, &name, want).map_err(|e| format!("{e}; restore with --ip auto (or another address)"))?
            }
        };
        let ip = self.set_addr(claim);
        t.mark("claim_ip");
        // A user's checkpoint is immutable and may be restored again whether
        // or not this VM got to run.
        self.restore_checkpoint(&name, ck, ip, false, paused, &mut t).map_err(Restore::error)
    }

    /// Restores `ck` as VM `name` at `ip` (already claimed), its memory paged
    /// in lazily from the checkpoint and pulled in the background, the
    /// template's working set first. `owned` checkpoints (a suspended VM's)
    /// are deleted once the VM no longer needs them. On failure, says
    /// whether the VM's vCPUs ran.
    fn restore_checkpoint(&self, name: &str, ck: Checkpoint, ip: Ipv4Addr, owned: bool, hold: bool, t: &mut Phases) -> std::result::Result<Value, Restore> {
        let m = ck.manifest.clone();
        let to_load = (ck.data_pages() * PAGE_SIZE as u64) >> 20;
        let (vm, restore) = (|| -> Result<_> {
            let tpl = Template::open_id(&self.paths, &m.template, &m.template_id)?;
            t.mark("verify_template");
            let origin = Some((ck.runs, Origin::File(ck.file)));
            let load = match hold && fault("restore_no_hold") {
                true => crate::vm::Load::PausedUnheld,
                false => crate::vm::Load::Paused,
            };
            // Loaded paused: everything up to the resume below can fail
            // without the VM having run. The bytes that were verified are
            // loaded, from a file only root controls.
            Vm::restore(&self.spawner, name, tpl, crate::vm::Snapshot::Bytes(&ck.vmstate), origin, ip, load, false, t)
        })()
        .map_err(Restore::NotRun)?;
        let dir = ck.dir;
        let kill = |e: Error| {
            vm.kill();
            e
        };
        vm.restore_devices();
        if fault("restore_before_run") {
            return Err(Restore::NotRun(kill("injected fault: restore failed before the vm ran".into())));
        }
        if let Some(why) = vm.pager.failed() {
            return Err(Restore::NotRun(kill(format!("its memory cannot be paged in: {why}").into())));
        }
        if vm.state() != State::Paused {
            return Err(Restore::NotRun(kill(format!("vm is {} before resuming", vm.state().name()).into())));
        }
        if hold {
            // Held paused, devices frozen too, until SIGCONT; its memory is
            // still paged in meanwhile. A new address reaches the guest then.
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
            // Durably consumed before it can run: a crash from here on must
            // not bring this checkpoint back.
            let marked = match fault("started_fsync") {
                true => std::fs::File::create(dir.join(STARTED)).and(Err(std::io::Error::other("injected fault: fsync failed"))),
                false => mark_durably(&dir, STARTED),
            };
            if let Err(e) = marked {
                // The marker may be on disk, or get there later: take it
                // back durably, or the VM may be neither resumable nor gone.
                vm.kill();
                let unmarked = match fault("started_unmark") {
                    true => std::fs::remove_file(dir.join(STARTED)).and(Err(std::io::Error::other("injected fault: fsync failed"))),
                    false => unmark_durably(&dir, STARTED),
                };
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
                vm.guest_net(ip, self.host.cfg.dns.as_deref())?;
                // The guest keeps its old address too; drop it if it has iproute2.
                let deadline = Instant::now() + crate::guest::TIMEOUT;
                let _ = vm.sh(&format!("ip -4 addr del {}/32 dev eth0 2>/dev/null", m.ip), deadline);
            }
            crate::guest::ping(&vm.vsock())?;
            let ready = t.total();
            t.mark("guest_ready");
            Ok(ready)
        })();
        let ready = ready.map_err(|e| Restore::Ran(kill(e)))?;
        // The guest's clock stopped when it was checkpointed.
        let clock = vm.sync_clock(Instant::now() + CLOCK_DEADLINE);
        t.mark("clock");
        self.announce();
        let state = vm.state().name();
        let p = self.arc();
        thread::spawn(move || {
            let pulled = vm.pager.wait_pulled();
            let took = vm.pager.pull_time().map(ms);
            eprintln!("vm {}: {to_load} MiB paged in from {} (complete: {pulled}, {took:?} ms)", vm.name, dir.display());
            // Under the operation lock: a suspend may be about to write
            // the next checkpoint where this one is.
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

    /// Checkpoints `vm` through `staging`. Without `cow` it stays paused for
    /// the write and is left in `Checkpointing` (or as it was, on failure; or
    /// failed, if a checkpoint may have been published that could not be
    /// revoked). With `cow` it is paused only until memory is frozen
    /// (write-protected), then goes back to running (or paused) while the
    /// pages are written. `incremental` writes a delta against the VM's last
    /// checkpoint here.
    fn save(&self, vm: &Arc<Vm>, mut staging: Staging, cow: bool, incremental: bool, t: &mut Phases) -> Result<Saved> {
        let parent = match incremental {
            false => None,
            true => {
                let last = vm.last_checkpoint.lock().unwrap().clone();
                let Some((dir, id)) = last.filter(|_| vm.pager.tracking()) else {
                    bail!("vm {} has no checkpoint to build on: take a full one with --keep-running first (an incremental checkpoint builds on the last one taken of the vm on this host, since it was last restored or migrated, that the vm ran on after)", vm.name)
                };
                // The whole chain must restore: every link verified, and room
                // for one more.
                let ck = Checkpoint::open(&dir).map_err(|e| format!("the last checkpoint of vm {}: {e}; take a full one", vm.name))?;
                if ck.id != id {
                    bail!("the last checkpoint of vm {}, {}, has changed; take a full one", vm.name, dir.display());
                }
                if ck.chain.len() + 2 > crate::checkpoint::MAX_CHAIN {
                    bail!("vm {}: a delta on {} would make a chain of more than {} checkpoints; take a full one", vm.name, dir.display(), crate::checkpoint::MAX_CHAIN);
                }
                // Page data is checked as it is read: for a VM that stops
                // after this checkpoint, read the pages it inherits now, so
                // it is never stopped onto a chain that cannot restore. (A
                // VM that runs on keeps its memory either way.)
                if !cow {
                    ck.verify_data().map_err(|e| format!("the last checkpoint of vm {}: {e}; take a full one", vm.name))?;
                    t.mark("verify_chain");
                }
                // A delta has about its parent's VM state: refuse it before the pause.
                if ck.meta_left < ck.vmstate.len() as u64 {
                    bail!("vm {}: the chain of {} has no metadata budget left; take a full one", vm.name, dir.display());
                }
                staging.meta_left = ck.meta_left;
                let mut ids = vec![ck.id.clone()];
                ids.extend(ck.chain_ids.iter().cloned());
                let parent = crate::checkpoint::Parent { path: crate::checkpoint::parent_path(staging.dest(), &dir), id };
                Some((parent, ids))
            }
        };
        let cancelled = || -> Result<()> {
            if vm.cancel_checkpoint.swap(0, Ordering::SeqCst) > 0 {
                bail!("vm {} is being killed", vm.name);
            }
            Ok(())
        };
        // A VM still pulling memory from a migration source or its own
        // checkpoint finishes that first, unless it is being killed.
        let drained = Instant::now() + DRAIN_WAIT;
        while vm.pager.remote_left() > 0 && !vm.pager.wait_pulled_for(Duration::from_millis(100)) {
            cancelled()?;
            if Instant::now() >= drained {
                bail!("vm {} is still pulling its memory; try again once it has", vm.name);
            }
        }
        t.mark("drain");
        // Pausing stops the vCPUs, not Firecracker's device handling: a
        // virtio-mem request still in flight could discard memory after the
        // state is saved. The guest only sends one to follow a size change
        // from the host, so wait until it has followed the last one (the
        // controller cannot make another while we hold the operation lock).
        vm.settle_hotplug(Instant::now() + SETTLE_WAIT)?;
        t.mark("settle_hotplug");
        // Disk space for the pages it has now, while it still runs.
        let present = vm.pager.census()[crate::uffd::PRESENT as usize];
        staging.preallocate(if incremental { present.min(vm.pager.dirty_count()) } else { present })?;
        t.mark("preallocate");
        if cow {
            // Write-protect everything while the VM still runs, so the pause
            // only re-protects what it writes from here on. Arming starts the
            // dirty history afresh: until a full checkpoint succeeds after it,
            // there is no base for a delta.
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
        // Packets for the VM from just before the pause until it runs again
        // are held, not lost on its downed tap (see `PacketHold`).
        let mut hold = PacketHold { d: self, vm, id: crate::migrate::migration_id(), stats: None };
        // A checkpoint that fails gives back the dirty pages it took (see
        // `Pager::unfreeze`), so the last checkpoint stays the base of the
        // next delta; one that succeeds becomes it.
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
            // A discard (balloon or virtio-mem) from just before the snapshot
            // on would make the pages disagree with the saved state.
            let checked = match vm.pager.discards() != vm.snapshot_discards.load(Ordering::SeqCst) {
                true => Err("guest memory changed after the vm was paused (a device discarded pages); try again".into()),
                false => cancelled(),
            };
            if let Err(e) = checked {
                vm.pager.unfreeze(&frozen);
                return Err(e);
            }
            Ok(frozen)
        })();
        let frozen = match frozen {
            Ok(f) => f,
            Err(e) => {
                return Err(match hold.end() {
                    Ok(_) => e,
                    Err(r) => format!("{e}; {r}").into(),
                });
            }
        };
        let mut pause = None;
        let mut growth = None;
        // Free page reports wait in the balloon's queue until the copy is
        // over (released when this goes out of scope, after `end_copy` or
        // `unfreeze`): a discard of an unsaved page would make the pager
        // save everything left first, stalling the guest. Without the
        // Firecracker patch the copy still saves first, only slower (test
        // fault `ckpt_no_hold` skips the hold, to compare). The guard comes
        // first: a hold whose answer is lost may still have been applied.
        let _held = (cow && !fault("ckpt_no_hold")).then(|| {
            let held = HeldReports(vm);
            if let Err(e) = vm.hold_reports() {
                eprintln!("vm {}: free page reports may not be held during the copy: {e}", vm.name);
            }
            held
        });
        if cow {
            if let Err(e) = hold.end() {
                vm.pager.unfreeze(&frozen);
                return Err(e);
            }
            pause = Some(paused.elapsed());
            t.mark("resume");
            // Running on while the pages are copied: it may grow meanwhile.
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
        // Test gate: resume and arm COW, but keep disk writers out until the
        // test has freed memory and observed the hold. The fault expires too.
        while cow && fault("ckpt_copy_wait") {
            if let Err(e) = cancelled() {
                vm.pager.unfreeze(&frozen);
                return Err(e);
            }
            thread::sleep(Duration::from_millis(10));
        }
        let slow = match (fault("ckpt_crawl"), fault("ckpt_slow")) {
            (true, _) => Duration::from_millis(500),
            (false, true) => Duration::from_millis(50),
            _ => Duration::ZERO,
        };
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
            // The chain this delta needs must still be there, unchanged.
            // Walked as a restore will: from this checkpoint's own reference
            // to its parent, through each manifest's.
            if let (Some(p), Some(ids)) = (&parent_ref, &links) {
                // (This checkpoint's directory exists only once published,
                // as a plain directory in the pinned one, so `../NAME` is
                // NAME in that.)
                let first = match p.path.strip_prefix("../") {
                    Some(name) => pinned.join(name),
                    None => PathBuf::from(&p.path),
                };
                let now = crate::checkpoint::chain_ids(&first);
                if now.as_ref().ok() != Some(ids) {
                    bail!("the checkpoints this delta builds on changed or went ({}); take a full one", now.err().map_or("other ids".into(), |e| e.to_string()));
                }
            }
            match &frozen.cow {
                // Discards while it runs are fine once the pages they hit were saved.
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
            // A copy-on-write copy lets the VM grow (see `Proc::resize`); what
            // it saved is the size at the pause.
            match vm.hotplug_plugged() {
                Some(now) if cow && now >= plugged.unwrap_or(0) => {}
                now if now == plugged => {}
                now => bail!("guest memory was resized during the checkpoint ({plugged:?} -> {now:?} MiB plugged); try again"),
            }
            Ok(())
        });
        // No resize is in progress once this returns, and none starts.
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
                let held = hold.stats.map(|s| s.json());
                Ok(Saved { manifest, id, paused, dirty: frozen.dirty, protected: frozen.protected, protect: frozen.protect, copy, memhash, held })
            }
            Err(CommitError::Failed(e)) if cow => Err(e),
            Err(CommitError::Failed(e)) => match hold.end() {
                Ok(_) => Err(e),
                Err(r) => Err(format!("{e}; {r}").into()),
            },
            // Running on already: a checkpoint that may reappear after a
            // crash is one of a VM that went on running, as any other is.
            Err(CommitError::Uncertain(e)) if cow => Err(format!("{e}; the checkpoint may reappear after a crash").into()),
            Err(CommitError::Uncertain(e)) => {
                vm.set_failed();
                Err(format!("{e}; vm {} stays paused and is marked failed, as the checkpoint may come back", vm.name).into())
            }
        }
    }

}

/// What `Proc::save` wrote.
pub struct Saved {
    pub manifest: Manifest,
    pub id: String,
    /// Write-protect ranges re-armed in the pause, and how long that took.
    pub protected: usize,
    pub protect: Duration,
    /// How long the VM was paused.
    pub paused: Duration,
    /// Pages dirtied since the previous checkpoint's pause.
    pub dirty: usize,
    /// Copy-on-write statistics, when the VM ran on during the write.
    pub copy: Option<Value>,
    /// Test hook: the canonical hash of memory at the pause.
    pub memhash: Option<String>,
    /// The packets held while it was paused, when it went back to running.
    pub held: Option<Value>,
}

/// Packets for a VM's address while a checkpoint has it paused: held on the
/// hold device (see `hold`) from just before the pause, as a migration
/// does, instead of following the host's default route once the downed tap
/// takes the VM's /32 with it (a TCP peer would wait out a retransmit
/// timeout). `end` injects them into the VM's own tap and gives the address
/// back to it before resuming, so they arrive ahead of newer traffic.
/// Dropped without `end` (the VM stops here), they are forgotten.
/// Longest a checkpoint's release waits for held packets still on their way.
const CKPT_RELEASE: Duration = Duration::from_millis(20);

struct PacketHold<'a> {
    d: &'a Proc,
    vm: &'a Vm,
    id: u64,
    stats: Option<crate::hold::Stats>,
}

impl PacketHold<'_> {
    /// For the `unroute` of `save_state`: just before the pause.
    fn hold(&self) {
        if let Some(Err(e)) = self.d.holder().map(|h| h.hold(self.vm.ip, self.id)) {
            eprintln!("vm {}: not holding packets during the checkpoint: {e}", self.vm.name);
        }
    }

    /// Hands the held packets to the VM, then `Vm::end_checkpoint`. Waits at
    /// most `CKPT_RELEASE` for packets still on their way, as the VM stays
    /// paused meanwhile.
    fn end(&mut self) -> Result<State> {
        let Some(h) = self.d.holder() else { return self.vm.end_checkpoint() };
        let (ip, tap) = (self.vm.ip, &self.vm.tap);
        self.stats = crate::migrate::release_into(h, ip, self.id, self.vm, CKPT_RELEASE, |()| crate::net::attach(ip, tap));
        let res = self.vm.end_checkpoint();
        // Still held only if the route could not be switched back (the
        // resume routes it again, or failed): never leave it on the device.
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

/// How a restore failed: before the VM's vCPUs ever ran, or after.
pub enum Restore {
    NotRun(Error),
    Ran(Error),
    /// Not run, but its (owned) checkpoint may be marked STARTED or not.
    Uncertain(Error),
}

impl Restore {
    fn error(self) -> Error {
        match self {
            Restore::NotRun(e) | Restore::Ran(e) | Restore::Uncertain(e) => e,
        }
    }
}


/// In a suspended VM's checkpoint: it has been resumed (its VM may have run
/// since), so it must never be resumed again.
const STARTED: &str = "STARTED";
/// In a suspended VM's checkpoint: the VM was killed.
const DISCARDED: &str = "DISCARDED";

/// Releases the free page reports a copy-on-write checkpoint held; if that
/// fails, the controller retries it.
struct HeldReports<'a>(&'a Vm);

impl Drop for HeldReports<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.release_reports(Duration::from_secs(5)) {
            eprintln!("vm {}: releasing free page reports failed: {e}", self.0.name);
        }
    }
}

/// In a suspended VM's checkpoint: its address's generation (see `host::Addr`).
const GEN: &str = "GEN";

fn read_gen(dir: &Path) -> Option<u64> {
    std::fs::read_to_string(dir.join(GEN)).ok()?.trim().parse().ok()
}

/// Creates marker file `name` in `dir` and makes it durable.
fn mark_durably(dir: &Path, name: &str) -> std::io::Result<()> {
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(dir.join(name))?.sync_all()?;
    std::fs::File::open(dir)?.sync_all()
}

/// Removes marker file `name` from `dir`, if there, and makes that durable.
fn unmark_durably(dir: &Path, name: &str) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(name)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    std::fs::File::open(dir)?.sync_all()
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

/// While alive, `vm` may grow although its checkpoint holds its operation
/// lock (see `Proc::resize`). Ending it waits for a resize in progress.
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

/// After a failed resume whose STARTED marker may or may not be durable:
/// `<boot id> <why>`. Such a VM is not resumed again until the host
/// reboots, when the disk shows whether the marker made it.
const QUARANTINE: &str = "QUARANTINE";

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default().trim().to_string()
}

/// Deletes suspended VM `name` (`flexvm kill` of a suspended VM, or a
/// consumed checkpoint): marks its checkpoint DISCARDED durably first, so
/// it never comes back, then frees and withdraws its address.
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
            for peer in &host.cfg.peers {
                let _ = crate::vmproc::peer_call(peer, json!({"op": "route", "ip": ip.to_string(), "gen": gen}));
            }
        }
    }
    Ok(())
}

/// Deletes a checkpoint marked STARTED or DISCARDED.
pub fn delete_consumed(name: &str, dir: &Path) {
    if let Err(e) = delete_checkpoint(dir) {
        eprintln!("vm {name}: removing {}: {e}", dir.display());
    }
}

/// A checkpoint's manifest, unverified.
fn manifest(dir: &Path) -> Option<Manifest> {
    let text = std::fs::read(dir.join("manifest.json")).ok()?;
    serde_json::from_slice(text.splitn(2, |&b| b == b'\n').nth(1)?).ok()
}

/// What `ls` shows of a suspended VM, from its manifest. A consumed one
/// (resumed, its process gone) is not shown.
pub fn describe_suspended(host: &Host, name: &str) -> Option<Value> {
    let dir = host.suspended(name);
    if dir.join(STARTED).exists() || dir.join(DISCARDED).exists() {
        return None;
    }
    let m = manifest(&dir)?;
    // Without its address's generation it is never resumed (see `resume_suspended`).
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
