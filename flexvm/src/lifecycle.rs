//! Pause/resume, checkpoints, restores and suspend:
//!   running <-> paused                                  (SIGTSTP / SIGCONT)
//!   running | paused -> checkpointing -> running | paused (checkpoint)
//!                                     -> gone            (checkpoint --stop)
//!                                     -> suspended       (SIGTERM; `flexvm resume`)
//!   running | paused -> source (migrating) -> gone | running | paused

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
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

pub const DRAIN_WAIT: Duration = Duration::from_secs(60);
pub const SETTLE_WAIT: Duration = Duration::from_secs(10);
const CKPT_RELEASE: Duration = Duration::from_millis(20);
/// Suspended-checkpoint markers: STARTED (may have run: never resume again),
/// DISCARDED, GEN (address generation), and QUARANTINE `<boot id> <why>` when
/// STARTED's durability is unknown (held until a reboot shows the disk).
const STARTED: &str = "STARTED";
const DISCARDED: &str = "DISCARDED";
const GEN: &str = "GEN";
const QUARANTINE: &str = "QUARANTINE";

/// Set while a suspend or `checkpoint --stop` saves the VM, and for good once
/// it did: the app log follower writes nothing past the offset the checkpoint
/// records (what the reader still drains, the restored VM prints). One VM per process.
pub static APP_LOG_HELD: AtomicBool = AtomicBool::new(false);

/// Clears `APP_LOG_HELD` when dropped: the VM runs on, printing what was held.
struct AppLogHeld;

impl Drop for AppLogHeld {
    fn drop(&mut self) {
        APP_LOG_HELD.store(false, Ordering::SeqCst);
    }
}

/// Uncertain: never ran, but an owned checkpoint may be marked STARTED.
pub enum Restore {
    NotRun(Error),
    Ran(Error),
    Uncertain(Error),
}

impl Proc {
    /// Test hook.
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

    /// SIGCONT; a held restore at a new address gets it now.
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
        self.sync_clock_later();
        Ok(json!({"name": vm.name, "state": "running", "resume_ms": ms(took)}))
    }

    /// The app log offset, counting only output written out: the follower
    /// writes a chunk and counts it under the stdout lock. `hold`: nothing
    /// more is written until the guard is dropped.
    fn app_log_written(&self, hold: bool) -> (u64, Option<AppLogHeld>) {
        let _out = std::io::stdout().lock();
        APP_LOG_HELD.fetch_or(hold, Ordering::SeqCst);
        (self.app_log.load(Ordering::SeqCst), hold.then_some(AppLogHeld))
    }

    /// For a migration: the offset sent to the target, with the follower
    /// held from then on, so the source prints nothing the target will
    /// (`release_app_log` when the source runs on after all).
    pub(crate) fn hold_app_log(&self) -> u64 {
        let (at, held) = self.app_log_written(true);
        std::mem::forget(held);
        at
    }

    pub(crate) fn release_app_log(&self) {
        APP_LOG_HELD.store(false, Ordering::SeqCst);
    }

    fn readdress(&self, vm: &Vm, old: Ipv4Addr) -> Result<()> {
        vm.guest_net(vm.ip, self.host.cfg.dns.as_deref())?;
        let _ = vm.sh(&format!("ip -4 addr del {old}/32 dev eth0 2>/dev/null"), Instant::now() + crate::guest::TIMEOUT);
        Ok(())
    }

    /// With `stop` the VM stays paused for the caller to destroy.
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

    /// SIGTERM. Returns only on failure, with the VM running on.
    pub fn suspend(&self) -> Error {
        let vm = self.vm();
        let mut t = Phases::new();
        let op = self.op();
        let saved = (|| -> Result<(Manifest, Value)> {
            if !matches!(vm.state(), State::Running | State::Paused) {
                bail!("vm {} is {}; not suspending it", vm.name, vm.state().name());
            }
            self.settle_arrival(&op, DRAIN_WAIT)?;
            // This one goes where the checkpoint it was resumed from is.
            if let Some(dir) = self.consumed.lock().unwrap().take() {
                delete_consumed(&vm.name, &dir);
            }
            // What an earlier removal of it left (its address is this VM's).
            let dir = self.host.suspended(&vm.name);
            if dir.exists() && !self.host.is_suspended(&vm.name) {
                remove_durably(&dir).map_err(|e| format!("removing what is left of {}: {e}", dir.display()))?;
            }
            let staging = Staging::new(&dir, vm.dir.join("checkpoint.vmstate"))?;
            staging.add_file(GEN, self.gen().to_string().as_bytes())?;
            let saved = self.save(vm, staging, false, false, &mut t);
            self.publish();
            saved
        })();
        // A kill asked for meanwhile (SIGINT means destroy) revokes what was published.
        if saved.is_ok() {
            crate::host::stall("suspend_stall");
        }
        // As `flexvm kill` does to a suspended VM; one that cannot be revoked stays suspended.
        if saved.is_ok() && vm.cancel_checkpoint.load(Ordering::SeqCst) > 0 {
            match revoke(&self.host, &vm.name) {
                Ok(freed) => {
                    if let Err(e) = freed {
                        eprintln!("vm {}: killed while suspending, its checkpoint revoked; freeing its address: {e}", vm.name);
                    }
                    self.finish(&op, End::Gone, 128 + libc::SIGINT, None)
                }
                Err(e) => {
                    eprintln!("vm {}: killed while suspending, but its checkpoint stays: {e}", vm.name);
                    self.finish(&op, End::Suspended, crate::vmproc::FAILED, None)
                }
            }
        }
        match saved {
            Ok((m, _)) => {
                let data = (m.data_pages * PAGE_SIZE as u64) >> 20;
                eprintln!("{}", json!({"name": vm.name, "state": "suspended", "dir": self.host.suspended(&vm.name), "freed_rss_mib": vm.rss() >> 20, "data_mib": data, "suspend_ms": ms(t.total()), "timings_ms": t.json()}));
                self.finish(&op, End::Suspended, 128 + libc::SIGTERM, None)
            }
            Err(e) => e,
        }
    }

    pub fn resume_suspended(&self, name: &str) -> Result<Value> {
        let mut t = Phases::new();
        self.set_name(self.host.take_name(name, true)?);
        // Taking the name removed what an interrupted suspend, resume or discard left.
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
            Err(Restore::NotRun(e)) => {
                self.keep_addr();
                Err(e)
            }
            Err(Restore::Uncertain(e)) => {
                self.keep_addr();
                let _ = std::fs::write(dir.join(QUARANTINE), format!("{} {e}", crate::host::boot_id()));
                bail!("vm {name} is quarantined: {e}; kill it to discard its checkpoint")
            }
            // Re-arming the checkpoint would replay what it did since.
            Err(Restore::Ran(e)) => {
                let _ = discard(&self.host, name);
                bail!("vm {name} failed after it resumed: {e}; it is gone, its checkpoint is consumed")
            }
        }
    }

    /// Another host's address is borrowed.
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
        self.restore_checkpoint(&name, ck, ip, false, paused, &mut t).map_err(|(Restore::NotRun(e) | Restore::Ran(e) | Restore::Uncertain(e))| e)
    }

    /// An `owned` (suspended) checkpoint is durably marked STARTED before the
    /// VM runs and deleted once not needed. `hold`: left paused until SIGCONT.
    fn restore_checkpoint(&self, name: &str, ck: Checkpoint, ip: Ipv4Addr, owned: bool, hold: bool, t: &mut Phases) -> std::result::Result<Value, Restore> {
        let m = ck.manifest.clone();
        let to_load = (ck.data_pages() * PAGE_SIZE as u64) >> 20;
        self.app_log.store(m.app_log, Ordering::SeqCst);
        let (vm, restore) = (|| -> Result<_> {
            let tpl = Template::open_id(&self.paths, &m.template, &m.template_id)?;
            t.mark("verify_template");
            self.admit_start(to_load)?;
            let seed = Some((ck.runs, Origin::File(ck.file)));
            let prepared = Vm::prepare(self.spawner.take(None)?, tpl, t)?;
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
            // A crash must not bring it back once it may have run.
            let failing = |e: &str| std::fs::remove_file(dir.join(STARTED)).and(Err(std::io::Error::other(format!("injected fault: {e}"))));
            let marked = match fault("started_fsync") {
                true => std::fs::File::create(dir.join(STARTED)).and(Err(std::io::Error::other("injected fault: fsync failed"))),
                false => mark_durably(&dir, STARTED),
            };
            if let Err(e) = marked {
                vm.kill();
                let unmarked = if fault("started_unmark") { failing("fsync failed") } else { unmark_durably(&dir, STARTED) };
                return Err(match unmarked {
                    Ok(()) => Restore::NotRun(format!("marking the checkpoint started: {e}").into()),
                    Err(r) => Restore::Uncertain(format!("marking the checkpoint started: {e}; removing the mark: {r}").into()),
                });
            }
            *self.consumed.lock().unwrap() = Some(dir.clone());
        }
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
            crate::guest::ping(&vm.vsock)?;
            let ready = t.total();
            t.mark("guest_ready");
            Ok(ready)
        })()
        .map_err(|e| Restore::Ran(kill(e)))?;
        let clock = vm.sync_clock(Instant::now() + CLOCK_DEADLINE);
        t.mark("clock");
        self.announce();
        let state = vm.state().name();
        let p = self.arc();
        thread::spawn(move || {
            let pulled = vm.pager.wait_pulled(None);
            eprintln!("vm {}: {to_load} MiB paged in from {} (complete: {pulled}, {:?} ms)", vm.name, dir.display(), vm.pager.pull_time().map(ms));
            // Under the op lock: a suspend may be about to write here.
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

    /// Without `cow` the VM stays paused (`Checkpointing`) for the write, and
    /// is marked failed if a checkpoint that could not be revoked may have been
    /// published. With `cow` it runs on once memory is write-protected.
    fn save(&self, vm: &Arc<Vm>, mut staging: Staging, cow: bool, incremental: bool, t: &mut Phases) -> Result<(Manifest, Value)> {
        let last = |e: &dyn std::fmt::Display| format!("the last checkpoint of vm {}: {e}; take a full one", vm.name);
        let parent = match incremental {
            false => None,
            true => {
                let Some((dir, id)) = vm.last_checkpoint.lock().unwrap().clone().filter(|_| vm.pager.tracking()) else {
                    bail!("vm {} has no checkpoint to build on: take a full one with --keep-running first (an incremental checkpoint builds on the last one taken of the vm on this host, since it was last restored or migrated, that the vm ran on after)", vm.name)
                };
                let ck = Checkpoint::open(&dir).map_err(|e| last(&e))?;
                if ck.id != id {
                    bail!("{}", last(&format!("{} has changed", dir.display())));
                }
                if ck.chain.len() + 2 > crate::checkpoint::MAX_CHAIN {
                    bail!("vm {}: a delta on {} would make a chain of more than {} checkpoints; take a full one", vm.name, dir.display(), crate::checkpoint::MAX_CHAIN);
                }
                // Never stop a VM onto a chain that cannot restore.
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
        let drained = Instant::now() + DRAIN_WAIT;
        while vm.pager.remote_left() > 0 && !vm.pager.wait_pulled(Some(Duration::from_millis(100))) {
            cancelled()?;
            if Instant::now() >= drained {
                bail!("vm {} is still pulling its memory; try again once it has", vm.name);
            }
        }
        t.mark("drain");
        let _lifted = vm.limit.lift(vm.pid());
        // Paused vCPUs do not stop virtio-mem discarding memory after the save.
        vm.settle_hotplug(Instant::now() + SETTLE_WAIT)?;
        t.mark("settle_hotplug");
        let present = vm.pager.census()[crate::uffd::PRESENT as usize];
        staging.preallocate(if incremental { present.min(vm.pager.dirty_count()) } else { present })?;
        t.mark("preallocate");
        if cow {
            // Arm while running so the pause only re-protects what it writes from now.
            if !vm.pager.tracking() {
                *vm.last_checkpoint.lock().unwrap() = None;
            }
            vm.pager.arm_tracking()?;
            t.mark("arm_tracking");
        }
        let plugged = vm.hotplug_plugged();
        cancelled()?;
        vm.leave(State::Checkpointing)?;
        let paused = Instant::now();
        let mut hold = PacketHold { d: self, vm, id: crate::migrate::migration_id(), stats: None };
        // Failure must `unfreeze` so the last checkpoint stays the delta base.
        let mut memhash = None;
        let frozen = (|| -> Result<Frozen> {
            let runs = vm.save_state(&staging.vmstate(), false, true, || hold.hold(), &mut Phases::new())?;
            t.mark("snapshot");
            if fault("ckpt_memhash") {
                memhash = Some(vm.pager.content_hash()?);
                t.mark("memhash");
            }
            vm.pager.wp_race.store(fault("ckpt_wp_race"), Ordering::SeqCst);
            if fault("ckpt_fail_protect") {
                vm.pager.fail_protect.store(true, Ordering::SeqCst);
            }
            let frozen = vm.pager.freeze(&runs, incremental, cow)?;
            t.mark("freeze");
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
        // What of the app log was passed on while paused: a restore follows on from there.
        // A VM running on writes more, which its ring at the snapshot does not have.
        staging.app_log = self.app_log_written(false).0;
        let (mut pause, mut growth) = (None, None);
        // Hold free page reports during the copy (discarding an unsaved page
        // would stall the guest). Guard first: a lost answer may still apply.
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
            growth = Some(CopyGrowth::start(vm));
            if fault("ckpt_abort") {
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
        while cow && fault("ckpt_copy_wait") {
            cancelled().inspect_err(|_| vm.pager.unfreeze(&frozen))?;
            thread::sleep(Duration::from_millis(10));
        }
        let slow = || Duration::from_millis(if fault("ckpt_crawl") { 500 } else if fault("ckpt_slow") { 50 } else { 0 });
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
        // Still paused: what the reader drained since counts too, and from
        // now on what it drains is left to the restored VM.
        let held = (!cow).then(|| self.app_log_written(true)).map(|(at, held)| {
            staging.app_log = at;
            held
        });
        let committed = staging.commit(vm, src, &frozen.runs, parent, plugged.unwrap_or(0), t, || {
            cancelled()?;
            if fault("ckpt_fail_write") {
                bail!("injected fault: writing the checkpoint failed");
            }
            // The parent chain must be unchanged, walked as a restore will.
            if let (Some(p), Some(ids)) = (&parent_ref, &links) {
                let first = p.path.strip_prefix("../").map_or_else(|| PathBuf::from(&p.path), |name| pinned.join(name));
                let now = crate::checkpoint::chain_ids(&first);
                if now.as_ref().ok() != Some(ids) {
                    bail!("the checkpoints this delta builds on changed or went ({}); take a full one", now.err().map_or("other ids".into(), |e| e.to_string()));
                }
            }
            match &frozen.cow {
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
            match vm.hotplug_plugged() {
                Some(now) if cow && now >= plugged.unwrap_or(0) => Ok(()),
                now if now == plugged => Ok(()),
                now => bail!("guest memory was resized during the checkpoint ({plugged:?} -> {now:?} MiB plugged); try again"),
            }
        });
        drop(growth);
        if committed.is_ok() {
            // The VM ends here; the checkpoint prints the rest.
            std::mem::forget(held);
        }
        let copy = frozen.cow.as_ref().map(|c| c.report());
        match &committed {
            Ok(_) => vm.pager.end_copy(),
            Err(_) => vm.pager.unfreeze(&frozen),
        }
        let paused = pause.unwrap_or_else(|| paused.elapsed());
        match committed {
            Ok((manifest, id)) => {
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
            Err(CommitError::Uncertain(e)) if cow => Err(format!("{e}; the checkpoint may reappear after a crash").into()),
            Err(CommitError::Uncertain(e)) => {
                vm.set_failed();
                Err(format!("{e}; vm {} stays paused and is marked failed, as the checkpoint may come back", vm.name).into())
            }
        }
    }
}

/// Packets held while a checkpoint pauses the VM; `end` injects them before
/// it resumes, ahead of newer traffic. Dropped, they are forgotten.
struct PacketHold<'a> {
    d: &'a Proc,
    vm: &'a Vm,
    id: u64,
    stats: Option<crate::hold::Stats>,
}

impl PacketHold<'_> {
    fn hold(&self) {
        if let Some(Err(e)) = self.d.holder().map(|h| h.hold(self.vm.ip, self.id)) {
            eprintln!("vm {}: not holding packets during the checkpoint: {e}", self.vm.name);
        }
    }

    fn end(&mut self) -> Result<State> {
        let Some(h) = self.d.holder() else { return self.vm.end_checkpoint() };
        let (ip, tap) = (self.vm.ip, &self.vm.tap);
        self.stats = crate::migrate::release_into(h, ip, self.id, self.vm, CKPT_RELEASE, |()| crate::net::attach(ip, tap));
        let res = self.vm.end_checkpoint();
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

struct HeldReports<'a>(&'a Vm);

impl Drop for HeldReports<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.release_reports(Duration::from_secs(5)) {
            eprintln!("vm {}: releasing free page reports failed: {e}", self.0.name);
        }
    }
}

/// While alive the VM may grow despite the checkpoint's op lock (`Proc::resize`).
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

fn unmark_durably(dir: &Path, name: &str) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(name)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => std::fs::File::open(dir)?.sync_all(),
    }
}

/// Manifest first, durably, so a crash midway never leaves a loadable
/// checkpoint without its marker (what it may leave is debris, removed by the
/// name's next holder).
pub fn delete_consumed(name: &str, dir: &Path) {
    if let Err(e) = remove_durably(dir) {
        eprintln!("vm {name}: removing {}: {e}", dir.display());
    }
}

fn remove_durably(dir: &Path) -> std::io::Result<()> {
    unmark_durably(dir, "manifest.json")?;
    std::fs::remove_dir_all(dir)?;
    match dir.parent() {
        Some(parent) => std::fs::File::open(parent)?.sync_all(),
        None => Ok(()),
    }
}

/// A suspended directory that is not a suspended VM (`Host::is_suspended`):
/// one with no manifest, or consumed, or discarded. Its name's holder
/// removes it and lets go of its address here, without withdrawing its
/// generation: a consumed checkpoint's VM may run on elsewhere.
pub fn remove_debris(host: &Host, name: &str) -> Result<()> {
    let dir = host.suspended(name);
    let ip = manifest(&dir).map(|m| m.ip);
    remove_durably(&dir).map_err(|e| format!("vm {name}: removing what is left of its suspended checkpoint {}: {e}", dir.display()))?;
    if let Some(ip) = ip {
        let l = host.lock()?;
        host.release(&l, ip, name)?;
    }
    Ok(())
}

/// Marked DISCARDED durably before the address is freed and withdrawn.
pub fn discard(host: &Host, name: &str) -> Result<()> {
    revoke(host, name)?
}

/// The outer error: not revoked (still resumable). The inner one: revoked,
/// but freeing its address failed (a later `kill` or the address's next
/// claim finishes that).
fn revoke(host: &Host, name: &str) -> Result<Result<()>> {
    let dir = host.suspended(name);
    let (ip, gen) = (manifest(&dir).map(|m| m.ip), read_gen(&dir));
    mark_durably(&dir, DISCARDED).map_err(|e| format!("discarding the checkpoint of {name}: {e}"))?;
    delete_consumed(name, &dir);
    Ok(free_address(host, name, ip, gen))
}

fn free_address(host: &Host, name: &str, ip: Option<Ipv4Addr>, gen: Option<u64>) -> Result<()> {
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

fn manifest(dir: &Path) -> Option<Manifest> {
    let text = std::fs::read(dir.join("manifest.json")).ok()?;
    serde_json::from_slice(text.splitn(2, |&b| b == b'\n').nth(1)?).ok()
}

pub fn describe_suspended(host: &Host, name: &str) -> Option<Value> {
    if !host.is_suspended(name) {
        return None;
    }
    let dir = host.suspended(name);
    let m = manifest(&dir)?;
    let state = if read_gen(&dir).is_none() || dir.join(QUARANTINE).exists() { "quarantined" } else { "suspended" };
    Some(json!({
        "name": name, "ip": m.ip.to_string(), "template": m.template, "template_id": m.template_id,
        "state": state, "vcpus": m.vcpus, "guest_mib": m.mem_mib + m.hotplug_mib, "max_mib": m.max_mib,
        "checkpoint_mib": (m.data_pages * PAGE_SIZE as u64) >> 20,
    }))
}

/// Test hook.
pub fn ckhash(paths: &crate::template::Paths, dir: &Path) -> Result<Value> {
    let ck = Checkpoint::open(dir)?;
    let tpl = Template::open(paths, &ck.manifest.template)?;
    tpl.check_id(&ck.manifest.template_id)?;
    Ok(json!({"hash": ck.content_hash(&tpl)?, "id": ck.id, "chain": ck.chain, "data_pages": ck.data_pages()}))
}
