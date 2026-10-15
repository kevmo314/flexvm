//! Pause/resume, checkpoints, restores and suspend:
//!   running <-> paused                                  (SIGTSTP / SIGCONT)
//!   running | paused -> checkpointing -> running | paused (checkpoint)
//!                                     -> gone            (checkpoint --stop)
//!                                     -> suspended       (SIGTERM; `flexvm resume`)
//!   running | paused -> source (migrating) -> gone | running | paused

use std::io::Write;
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
/// How long `finish_later` retries what a resume left undone; one runs at a time (one VM per process).
const GUEST_WAIT: Duration = Duration::from_secs(300);
static FINISHING: AtomicBool = AtomicBool::new(false);
/// Suspended-checkpoint markers: STARTED (may have run: never resume again),
/// DISCARDED, GEN (address generation), and QUARANTINE `<boot id> <why>` when
/// STARTED's durability is unknown (held until a reboot shows the disk).
const STARTED: &str = "STARTED";
const DISCARDED: &str = "DISCARDED";
const GEN: &str = "GEN";
const QUARANTINE: &str = "QUARANTINE";
/// A suspended `run -- CMD` VM's command and its session (`{"cmd", "session"}`), reattached on resume.
const CMD: &str = "CMD";

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
        // An arriving VM's pages first, so the host lock is held only through the resume itself (#334).
        vm.await_peer_pages()?;
        let still = self.still_current(vm.ip)?;
        vm.unpause()?;
        drop(still);
        self.paused_by_request.store(false, Ordering::SeqCst);
        let took = start.elapsed();
        self.publish();
        if let Err(e) = self.take_address(vm) {
            drop(op);
            // An existing finish worker may only be retrying the address.
            self.sync_clock_later();
            self.finish_later(vm.clone(), true, false);
            return Err(e);
        }
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

    /// Sets a pending new address (`pending_net`) in the guest; failing, it stays
    /// pending, and the next `flexvm resume` (SIGCONT) tries again. Under `op`.
    fn take_address(&self, vm: &Vm) -> Result<()> {
        if !vm.pending_net.load(Ordering::SeqCst) {
            return Ok(());
        }
        let res = match fault("readdress_fail") {
            true => Err("injected fault: setting the address failed".into()),
            false => vm.guest_net(vm.ip, self.host.cfg.dns.as_deref()),
        };
        match res {
            Ok(()) => {
                vm.pending_net.store(false, Ordering::SeqCst);
                Ok(())
            }
            Err(e) => bail!("vm {} runs, but setting its address {} failed: {e}; flexvm resume {} tries again", vm.name, vm.ip, vm.name),
        }
    }

    /// With `stop` the VM stays paused for the caller to destroy.
    pub fn checkpoint(&self, _op: &Op, dir: &str, stop: bool, incremental: bool) -> Result<Value> {
        let vm = self.vm();
        let mut t = Phases::new();
        let staging = Staging::new(Path::new(dir), vm.dir.join("checkpoint.vmstate"))?;
        let dest = staging.dest().to_path_buf();
        t.mark("prepare");
        let saved = self.save(vm, staging, !stop, incremental, &mut t, || Ok(()));
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

    /// SIGTERM, `reserved` first. Returns only on failure, with the VM running
    /// on, the reservation let go (after the command's session).
    pub fn suspend(&self, reserved: crate::vmproc::SuspendReserved) -> Error {
        let vm = self.vm();
        let mut t = Phases::new();
        let op = self.op();
        let mut cmd_held = None;
        let saved = (|| -> Result<(Manifest, Value)> {
            if !matches!(vm.state(), State::Running | State::Paused) {
                bail!("vm {} is {}; not suspending it", vm.name, vm.state().name());
            }
            // Test fault `suspend_slow`: each suspend holds `op` a while first.
            if fault("suspend_slow") {
                thread::sleep(Duration::from_millis(300));
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
            let cmd = match self.cmd.lock().unwrap().clone() {
                Some(cmd) => Some((cmd, self.cmd_session()?, staging.create(CMD)?)),
                None => None,
            };
            // With the VM paused (its guest can no longer end or forget the session), held from
            // here on: nothing more of its output is written here, the resumed VM goes on from what was.
            let record = || -> Result<()> {
                if let Some((cmd, session, f)) = cmd {
                    let session = session.lock().unwrap();
                    (&f).write_all(&serde_json::to_vec(&json!({"cmd": cmd, "session": *session}))?)?;
                    f.sync_all()?;
                    cmd_held = Some(session);
                }
                Ok(())
            };
            let saved = self.save(vm, staging, false, false, &mut t, record);
            self.publish();
            saved
        })();
        // A kill asked for meanwhile (SIGINT means destroy) revokes what was published.
        if saved.is_ok() {
            crate::host::stall("suspend_stall");
        }
        // As `flexvm kill` does to a suspended VM; one that cannot be revoked stays suspended.
        // Its Firecracker dying meanwhile cancels it too: then it ends as a death does.
        if saved.is_ok() && vm.cancel_checkpoint.load(Ordering::SeqCst) > 0 {
            let how = if vm.dead() { "died" } else { "killed" };
            match revoke(&self.host, &vm.name) {
                Ok(freed) if vm.dead() => {
                    if let Err(e) = freed {
                        crate::log!("vm {}: died while suspending, its checkpoint revoked; freeing its address: {e}", vm.name);
                    }
                    self.end_died(&op)
                }
                Ok(freed) => {
                    if let Err(e) = freed {
                        crate::log!("vm {}: killed while suspending, its checkpoint revoked; freeing its address: {e}", vm.name);
                    }
                    self.finish(&op, End::Gone, 128 + libc::SIGINT, None)
                }
                Err(e) => {
                    crate::log!("vm {}: {how} while suspending, but its checkpoint stays: {e}", vm.name);
                    self.finish(&op, End::Suspended, crate::vmproc::FAILED, None)
                }
            }
        }
        match saved {
            Ok((m, _)) => {
                let data = (m.data_pages * PAGE_SIZE as u64) >> 20;
                crate::log!(
                    "{}",
                    json!({"name": vm.name, "state": "suspended", "dir": self.host.suspended(&vm.name), "freed_rss_mib": vm.rss() >> 20, "data_mib": data, "suspend_ms": ms(t.total()), "timings_ms": t.json()})
                );
                self.finish(&op, End::Suspended, 128 + libc::SIGTERM, None)
            }
            Err(e) => {
                drop(cmd_held);
                drop(reserved);
                e
            }
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
        if let Ok(q) = std::fs::read_to_string(dir.join(QUARANTINE)) {
            let (boot, why) = q.split_once(' ').unwrap_or((&q, ""));
            if boot == crate::host::boot_id() {
                bail!("vm {name} is quarantined: {why}; kill it to discard its checkpoint");
            }
            crate::util::unlink_durably(&dir.join(QUARANTINE))?;
        }
        let gen = read_gen(&dir).ok_or_else(|| {
            format!("vm {name} is quarantined: its address generation was never recorded, so it cannot be resumed with its address; restore {dir:?} with --name NEW --ip auto (choose an unused name), or flexvm kill {name} to discard it")
        })?;
        let ck = Checkpoint::open(&dir)?;
        let cmd = read_cmd(&dir).map_err(|e| format!("vm {name}: its command's record {}: {e}", dir.join(CMD).display()))?;
        t.mark("verify_checkpoint");
        let tpl = self.admit_checkpoint(&ck, &mut t)?;
        let ip = ck.manifest.ip;
        let claim = {
            let l = self.host.lock()?;
            if !self.host.current(&l, ip, gen)? {
                bail!("vm {name}: {ip} generation {gen} was withdrawn or given out again meanwhile; restore {dir:?} with --name NEW --ip auto (choose an unused name), or flexvm kill {name} to discard it");
            }
            self.host.claim_incoming(&l, name, ip, gen, None)?
        };
        self.set_addr(claim);
        // Before it is published: eviction leaves a CMD VM alone.
        *self.cmd.lock().unwrap() = cmd.as_ref().map(|(c, _)| c.clone());
        match self.restore_checkpoint(name, ck, tpl, ip, true, false, &mut t) {
            Ok(mut v) => {
                v["from"] = json!("suspended");
                // Its command runs on in the guest: the process reattaches it and ends with it.
                if let Some((_, session)) = cmd {
                    let _ = self.cmd_session.set(std::sync::Mutex::new(session));
                }
                Ok(v)
            }
            Err(Restore::NotRun(e)) => {
                *self.cmd.lock().unwrap() = None;
                self.keep_addr();
                Err(e)
            }
            Err(Restore::Uncertain(e)) => {
                *self.cmd.lock().unwrap() = None;
                self.keep_addr();
                let _ = std::fs::write(dir.join(QUARANTINE), format!("{} {e}", crate::host::boot_id()));
                bail!("vm {name} is quarantined: {e}; kill it to discard its checkpoint")
            }
            // Re-arming the checkpoint would replay what it did since.
            Err(Restore::Ran(e)) => {
                let _ = revoke(&self.host, name);
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
        let tpl = self.admit_checkpoint(&ck, &mut t)?;
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
        self.restore_checkpoint(&name, ck, tpl, ip, false, paused, &mut t).map_err(|(Restore::NotRun(e) | Restore::Ran(e) | Restore::Uncertain(e))| e)
    }

    /// Its template, once the restore is admitted: before any address is
    /// claimed or borrowed, so a refusal leaves nothing to give back.
    fn admit_checkpoint(&self, ck: &Checkpoint, t: &mut Phases) -> Result<Arc<Template>> {
        let tpl = Template::open_id(&self.paths, &ck.manifest.template, &ck.manifest.template_id)?;
        t.mark("verify_template");
        // The template's working set is prefetched too.
        self.admit_start(tpl.working_set_mib() + ((ck.data_pages() * PAGE_SIZE as u64) >> 20), None, crate::host::Floor::Reserve)?;
        Ok(tpl)
    }

    /// An `owned` (suspended) checkpoint is durably marked STARTED before the
    /// VM runs and deleted once not needed. `hold`: left paused until SIGCONT.
    #[allow(clippy::too_many_arguments)]
    fn restore_checkpoint(
        &self,
        name: &str,
        ck: Checkpoint,
        tpl: Arc<Template>,
        ip: Ipv4Addr,
        owned: bool,
        hold: bool,
        t: &mut Phases,
    ) -> std::result::Result<Value, Restore> {
        let m = ck.manifest.clone();
        let to_load = (ck.data_pages() * PAGE_SIZE as u64) >> 20;
        self.app_log.store(m.app_log, Ordering::SeqCst);
        let (vm, restore) = (|| -> Result<_> {
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
        // Published paused, until SIGCONT (`flexvm resume`); `why`: a resume that failed.
        let keep_paused = |t: &mut Phases, why: Option<String>| {
            if ip != m.ip {
                vm.pending_net.store(true, Ordering::SeqCst);
            }
            self.set_vm(vm.clone());
            self.paused_by_request.store(true, Ordering::SeqCst);
            self.publish();
            self.announce();
            self.watch_checkpoint_pull(vm.clone(), dir.clone(), to_load);
            json!({"name": name, "ip": ip.to_string(), "pid": std::process::id(), "state": "paused", "resume_error": why, "restore_ms": ms(restore), "timings_ms": t.json()})
        };
        if hold {
            return Ok(keep_paused(t, None));
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
                let unmarked = if fault("started_unmark") { failing("fsync failed") } else { crate::util::unlink_durably(&dir.join(STARTED)) };
                return Err(match unmarked {
                    Ok(()) => Restore::NotRun(format!("marking the checkpoint started: {e}").into()),
                    Err(r) => Restore::Uncertain(format!("marking the checkpoint started: {e}; removing the mark: {r}").into()),
                });
            }
            *self.consumed.lock().unwrap() = Some(dir.clone());
        }
        let unpaused = match fault("restore_unpause_fail") {
            true => Err("injected fault: resuming its vCPUs failed".into()),
            false => vm.unpause(),
        };
        // Some of its vCPUs may have run all the same (STARTED stays): paused again, it is kept, for a
        // `flexvm resume`; destroyed only if not even that is known.
        if let Err(e) = unpaused {
            drop(still);
            return match vm.state() == State::Paused && !vm.switch_unsure() {
                true => {
                    crate::log!("vm {name}: resuming it failed: {e}; it stays paused (flexvm resume {name} runs it)");
                    Ok(keep_paused(t, Some(e.to_string())))
                }
                false => Err(Restore::Ran(kill(e))),
            };
        }
        drop(still);
        t.mark("resume");
        if fault("restore_after_run") {
            return Err(Restore::Ran(kill("injected fault: restore failed after the vm ran".into())));
        }
        // It runs: from here a slow or failed guest step is reported, never fatal (its checkpoint,
        // still where its memory comes from, is deleted once all of it is in). Pending until the guest has it.
        if ip != m.ip {
            vm.pending_net.store(true, Ordering::SeqCst);
        }
        self.set_vm(vm.clone());
        self.publish();
        t.mark("register");
        let address_error = self.take_address(&vm).err().map(|e| e.to_string());
        let pinged = match fault("restore_ping_slow") {
            true => {
                thread::sleep(Duration::from_millis(2500));
                Err("injected fault: the guest agent did not answer within 2 s".into())
            }
            false => crate::guest::ping(&vm.vsock),
        };
        let guest_error = pinged.err().map(|e| e.to_string());
        let ready = guest_error.is_none().then(|| t.total());
        t.mark("guest_ready");
        let clock = match &guest_error {
            None => vm.sync_clock(Instant::now() + CLOCK_DEADLINE),
            Some(e) => Err(format!("guest agent not answering: {e}").into()),
        };
        t.mark("clock");
        if let Some(e) = &address_error {
            crate::log!("vm {name}: {e}");
        }
        if let Some(e) = &guest_error {
            crate::log!("vm {name}: runs, but its guest agent did not answer: {e}; waiting for it");
        }
        if guest_error.is_some() || address_error.is_some() || clock.is_err() {
            self.finish_later(vm.clone(), guest_error.is_none(), clock.is_err());
        }
        self.announce();
        let state = vm.state().name();
        self.watch_checkpoint_pull(vm.clone(), dir, to_load);
        Ok(json!({
            "name": name,
            "ip": ip.to_string(),
            "pid": std::process::id(),
            "state": state,
            "restore_ms": ms(restore),
            "ready_ms": ready.map(ms),
            "guest_error": guest_error,
            "address_error": address_error,
            "clock_offset_ms": clock.as_ref().ok(),
            "clock_error": clock.as_ref().err().map(|e| e.to_string()),
            "to_load_mib": to_load,
            "timings_ms": t.json(),
        }))
    }

    /// For a VM whose resume left guest steps undone: until `GUEST_WAIT`, waits for its guest agent (unless
    /// `answered`), then retries setting a pending address and (`clock`) syncing its clock, each until it succeeds.
    fn finish_later(&self, vm: Arc<Vm>, mut answered: bool, mut clock: bool) {
        let Some(p) = self.arc() else { return };
        if FINISHING.swap(true, Ordering::SeqCst) {
            return;
        }
        thread::spawn(move || {
            struct Done;
            impl Drop for Done {
                fn drop(&mut self) {
                    FINISHING.store(false, Ordering::SeqCst);
                }
            }
            let _done = Done;
            let start = Instant::now();
            let mut failed: Option<String> = None;
            while !vm.dead() && start.elapsed() < GUEST_WAIT {
                let step = (|| -> Result<bool> {
                    if vm.state() != State::Running {
                        return Ok(false);
                    }
                    if !answered {
                        crate::guest::ping(&vm.vsock)?;
                        answered = true;
                        crate::log!("vm {}: its guest agent answered {} ms after it resumed", vm.name, ms(start.elapsed()));
                    }
                    if vm.pending_net.load(Ordering::SeqCst) {
                        let _op = p.op_within()?;
                        p.take_address(&vm)?;
                        crate::log!("vm {}: took its address {}", vm.name, vm.ip);
                    }
                    if clock {
                        let _op = p.op_within()?;
                        if vm.state() == State::Running {
                            let off = vm.sync_clock(Instant::now() + CLOCK_DEADLINE)?;
                            crate::log!("vm {}: guest clock synced ({off:.1} ms off)", vm.name);
                            clock = false;
                        }
                    }
                    Ok(!clock)
                })();
                match step {
                    Ok(true) => return,
                    Ok(false) => {}
                    // Logged as it changes, once the agent answers (until then each ping fails much alike).
                    Err(e) if answered && failed.as_deref() != Some(&e.to_string()) => {
                        crate::log!("vm {}: {e}; trying again", vm.name);
                        failed = Some(e.to_string());
                    }
                    Err(e) => failed = Some(e.to_string()),
                }
                thread::sleep(Duration::from_secs(1));
            }
            if !vm.dead() {
                crate::log!("vm {}: gave up finishing its resume after {} s: {}", vm.name, GUEST_WAIT.as_secs(), failed.as_deref().unwrap_or("not running"));
            }
        });
    }

    /// Release disk admission and a consumed checkpoint once the pull finishes.
    fn watch_checkpoint_pull(&self, vm: Arc<Vm>, dir: PathBuf, to_load: u64) {
        let p = self.arc();
        thread::spawn(move || {
            let pulled = p.as_ref().map_or_else(|| vm.pager.wait_pulled(None), |p| p.wait_pulled(&vm));
            crate::log!("vm {}: {to_load} MiB paged in from {} (complete: {pulled}, {:?} ms)", vm.name, dir.display(), vm.pager.pull_time().map(ms));
            if let Some(p) = p {
                // Not under `op`: the memory is in, whatever operation runs.
                if pulled && p.pulled_all() {
                    p.release_hold();
                }
                // Under the op lock: a suspend may be about to write here.
                let _op = p.op();
                if let Some(dir) = p.consumed.lock().unwrap().take() {
                    delete_consumed(&vm.name, &dir);
                }
            }
        });
    }

    /// Without `cow` the VM stays paused (`Checkpointing`) for the write, and
    /// is marked failed if a checkpoint that could not be revoked may have been
    /// published. With `cow` it runs on once memory is write-protected.
    /// `before_publish` runs once the checkpoint's pages are written, before it is
    /// published (with the VM still paused, without `cow`); failing, it fails the checkpoint.
    fn save(
        &self,
        vm: &Arc<Vm>,
        mut staging: Staging,
        cow: bool,
        incremental: bool,
        t: &mut Phases,
        before_publish: impl FnOnce() -> Result<()>,
    ) -> Result<(Manifest, Value)> {
        let last = |e: &dyn std::fmt::Display| format!("the last checkpoint of vm {}: {e}; take a full one", vm.name);
        let parent = match incremental {
            false => None,
            true => {
                let Some((dir, id)) = vm.last_checkpoint.lock().unwrap().clone().filter(|_| vm.pager.tracking()) else {
                    bail!("vm {} has no checkpoint to build on: take a full one with flexvm checkpoint NAME DIR first (without --stop) (an incremental checkpoint builds on the last one taken of the vm on this host, since it was last restored or migrated, that the vm ran on after)", vm.name)
                };
                let ck = Checkpoint::open(&dir).map_err(|e| last(&e))?;
                if ck.id != id {
                    bail!("{}", last(&format!("{} has changed", dir.display())));
                }
                if ck.chain.len() + 2 > crate::checkpoint::MAX_CHAIN {
                    bail!(
                        "vm {}: a delta on {} would make a chain of more than {} checkpoints; take a full one",
                        vm.name,
                        dir.display(),
                        crate::checkpoint::MAX_CHAIN
                    );
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
        // Let the arrival inject its queue before a new hold replaces it or the tap pauses.
        while self.held_in.lock().unwrap().is_some() {
            cancelled()?;
            if Instant::now() >= drained {
                bail!("vm {} is still receiving its held packets; try again once it has", vm.name);
            }
            thread::sleep(Duration::from_millis(10));
        }
        t.mark("drain");
        // Paused vCPUs do not stop virtio-mem discarding memory after the save.
        vm.settle_hotplug(Instant::now() + SETTLE_WAIT)?;
        t.mark("settle_hotplug");
        let present = vm.pager.census()[crate::uffd::PRESENT as usize];
        staging.preallocate(if incremental { present.min(vm.pager.dirty_count()) } else { present })?;
        t.mark("preallocate");
        if cow {
            // Refused before arming, so a refusal leaves no write tracking (and collapse not halted for it).
            vm.can_leave()?;
            // Arm while running so the pause only re-protects what it writes from now.
            if !vm.pager.tracking() {
                *vm.last_checkpoint.lock().unwrap() = None;
            }
            vm.pager.arm_tracking()?;
            t.mark("arm_tracking");
            vm.pager.prepare_hot();
            t.mark("prepare_hot");
        }
        let plugged = vm.hotplug_plugged();
        cancelled()?;
        let _lifted = vm.limit.lift(vm.pid());
        vm.leave(State::Checkpointing)?;
        self.publish();
        let paused = Instant::now();
        let mut hold = PacketHold { d: self, vm, id: crate::migrate::migration_id(), stats: None, resumed: None, rearm: None };
        // Failure must `unfreeze` so the last checkpoint stays the delta base.
        let mut memhash = None;
        let frozen = (|| -> Result<Frozen> {
            let runs = vm.save_state(&staging.vmstate(), false, true, || self.hold_addr(vm, hold.id, "the checkpoint"), &mut Phases::new())?;
            t.mark("snapshot");
            if fault("ckpt_memhash") {
                memhash = Some(vm.pager.content_hash()?);
                t.mark("memhash");
            }
            vm.pager.wp_race.store(fault("ckpt_wp_race"), Ordering::SeqCst);
            vm.pager.rescue_fail.store(fault("ckpt_rescue_fail"), Ordering::SeqCst);
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
        // A VM running on writes more, which its ring at the snapshot does not have
        // (one staying paused counts it below, holding the reader).
        if cow {
            staging.app_log = self.app_log_written(false).0;
        }
        let (mut pause, mut growth) = (None, None);
        // Hold free page reports during the copy (discarding an unsaved page
        // would stall the guest). Guard first: a lost answer may still apply.
        let _held = (cow && !fault("ckpt_no_hold")).then(|| {
            let held = HeldReports(vm);
            if let Err(e) = vm.hold_reports() {
                crate::log!("vm {}: free page reports may not be held during the copy: {e}", vm.name);
            }
            held
        });
        if cow {
            hold.end().inspect_err(|_| vm.pager.unfreeze(&frozen))?;
            // Up to the vCPUs running: the balloon re-arm after it is the guest's time (#190).
            pause = Some(hold.resumed.unwrap_or_else(Instant::now).duration_since(paused));
            // Out of the pause: `ls` shows it running while the copy goes on (#152).
            self.publish();
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
        let slow = || {
            Duration::from_millis(if fault("ckpt_crawl") {
                500
            } else if fault("ckpt_slow") {
                50
            } else {
                0
            })
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
        // Still paused: what the reader drained since counts too, and from
        // now on what it drains is left to the restored VM.
        let held = (!cow).then(|| self.app_log_written(true)).map(|(at, held)| {
            staging.app_log = at;
            held
        });
        let committed = staging.commit(vm, src, &frozen.runs, parent, plugged.unwrap_or(0), t, || {
            cancelled()?;
            before_publish()?;
            if fault("ckpt_fail_write") {
                bail!("injected fault: writing the checkpoint failed");
            }
            // The parent chain must be unchanged, walked as a restore will.
            if let (Some(p), Some(ids)) = (&parent_ref, &links) {
                let first = p.path.strip_prefix("../").map_or_else(|| PathBuf::from(&p.path), |name| pinned.join(name));
                let now = crate::checkpoint::chain_ids(&first);
                if now.as_ref().ok() != Some(ids) {
                    bail!(
                        "the checkpoints this delta builds on changed or went ({}); take a full one",
                        now.err().map_or("other ids".into(), |e| e.to_string())
                    );
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
            Ok(_) => vm.pager.commit_copy(&frozen),
            Err(_) => vm.pager.unfreeze(&frozen),
        }
        self.publish();
        let paused = pause.unwrap_or_else(|| paused.elapsed());
        match committed {
            Ok((manifest, id)) => {
                *vm.last_checkpoint.lock().unwrap() = cow.then(|| (dest, id.clone()));
                Ok((
                    manifest,
                    json!({
                        "id": id,
                        "paused_ms": ms(paused),
                        "balloon_rearm_ms": hold.rearm.map(ms),
                        "dirty_mib": (frozen.dirty * PAGE_SIZE) >> 20,
                        "protect": {"ranges": frozen.protected, "ms": ms(frozen.protect)},
                        "hot": {"mib": (frozen.hot * PAGE_SIZE) as f64 / (1 << 20) as f64,
                                "copied_mib": (frozen.held.as_ref().map_or(0, |h| h.pages().len()) * PAGE_SIZE) as f64 / (1 << 20) as f64,
                                "unchanged_mib": (frozen.hot_unchanged * PAGE_SIZE) as f64 / (1 << 20) as f64,
                                "ms": ms(frozen.hot_time)},
                        "copy": copy,
                        "pause_memhash": memhash,
                        "held_packets": hold.stats.map(|s| s.json()),
                    }),
                ))
            }
            Err(CommitError::Failed(e)) if cow => Err(e),
            Err(CommitError::Failed(e)) => match hold.end() {
                Ok(_) => Err(e),
                Err(r) => Err(format!("{e}; {r}").into()),
            },
            Err(CommitError::Uncertain(e)) if cow => Err(format!("{e}; the checkpoint may reappear after a crash").into()),
            Err(CommitError::Uncertain(e)) => {
                vm.set_failed();
                self.publish();
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
    /// When `end` had the vCPUs running again, and how long re-arming the balloon took after that.
    resumed: Option<Instant>,
    rearm: Option<Duration>,
}

impl PacketHold<'_> {
    fn end(&mut self) -> Result<State> {
        let (stats, attached) = self.d.release_to_tap(self.vm, self.id);
        self.stats = stats;
        let res = self.vm.end_checkpoint(attached);
        // Left paused by the failure: `flexvm resume` (SIGCONT) runs it again.
        if res.is_err() && self.vm.state() == State::Paused {
            self.d.paused_by_request.store(true, Ordering::SeqCst);
        }
        let resumed = Instant::now();
        self.resumed = Some(resumed);
        self.vm.after_resume(res.is_ok());
        self.rearm = Some(resumed.elapsed());
        res
    }
}

impl Drop for PacketHold<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.d.holder() {
            h.forget(self.vm.ip, self.id);
        }
        // Back in service (a keep-running checkpoint, or any that failed), as after an aborted migration.
        self.vm.back_here();
    }
}

struct HeldReports<'a>(&'a Vm);

impl Drop for HeldReports<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.release_reports(Duration::from_secs(5)) {
            crate::log!("vm {}: releasing free page reports failed: {e}", self.0.name);
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

fn read_cmd(dir: &Path) -> Result<Option<(String, crate::Session)>> {
    let bytes = match std::fs::read(dir.join(CMD)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let v: Value = serde_json::from_slice(&bytes)?;
    let cmd = v["cmd"].as_str().ok_or("no command")?.to_string();
    Ok(Some((cmd, serde_json::from_value(v["session"].clone())?)))
}

fn read_gen(dir: &Path) -> Option<u64> {
    std::fs::read_to_string(dir.join(GEN)).ok()?.trim().parse().ok()
}

fn mark_durably(dir: &Path, name: &str) -> std::io::Result<()> {
    std::fs::File::create(dir.join(name))?.sync_all()?;
    crate::util::sync_dir(dir)
}

/// Manifest first, durably, so a crash midway never leaves a loadable
/// checkpoint without its marker (what it may leave is debris, removed by the
/// name's next holder).
pub fn delete_consumed(name: &str, dir: &Path) {
    if let Err(e) = remove_durably(dir) {
        crate::log!("vm {name}: removing {}: {e}", dir.display());
    }
}

fn remove_durably(dir: &Path) -> std::io::Result<()> {
    crate::util::unlink_durably(&dir.join("manifest.json"))?;
    std::fs::remove_dir_all(dir)?;
    crate::util::sync_dir(dir.parent().unwrap_or(Path::new("/")))
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
        host.release(&l, ip, name, None)?;
    }
    Ok(())
}

/// Marked DISCARDED durably before the address is freed and withdrawn.
/// The outer error: not revoked (still resumable). The inner one: revoked,
/// but freeing its address failed (a later `kill` or the address's next
/// claim finishes that).
pub fn revoke(host: &Host, name: &str) -> Result<Result<()>> {
    let dir = host.suspended(name);
    let (ip, gen) = (manifest(&dir).map(|m| m.ip), read_gen(&dir));
    mark_durably(&dir, DISCARDED).map_err(|e| format!("discarding the checkpoint of {name}: {e}"))?;
    delete_consumed(name, &dir);
    Ok(free_address(host, name, ip, gen))
}

fn free_address(host: &Host, name: &str, ip: Option<Ipv4Addr>, gen: Option<u64>) -> Result<()> {
    if let Some(ip) = ip {
        let l = host.lock()?;
        // Recorded before the claim goes; failing, the claim stays (a later kill finishes it).
        if let Some(gen) = gen {
            host.withdraw_noted(&l, ip, gen)?;
        }
        host.release(&l, ip, name, None)?;
        drop(l);
        if gen.is_some() {
            host.deliver_withdrawals();
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
