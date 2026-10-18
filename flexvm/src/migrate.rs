//! Post-copy live migration over one TCP connection to the target's listener:
//! `template` (the template, unless the target has it) and `migrate_in` + answer (before the
//! pause); header, vmstate, preload; commit
//! answer; held packets. The target pulls the rest via `pages`.
//! Ownership: the target commits (`STATE/migs/ID`) before the VM runs there.
//! The source resumes only on a refusal or `aborted` (never committed, or the
//! target died without every page), and exits only on `released`.

use std::borrow::Cow;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bail;
use crate::hold::{self, Holder};
use crate::host::{fault, tripped};
use crate::template::Template;
use crate::uffd::{Origin, Runs, Source, MAX_PRELOAD};
use crate::util::{ms, recv_json, send_json, By, Error, Phases, Result};
use crate::vm::{Snapshot, State, Vm};
use crate::vmproc::{peer_call, Busy, End, Op, Proc, BUSY};

/// From the target's prepare answer to its commit answer: the target receives, loads and commits
/// within it, or refuses. The source's one deadline for its post-pause sends and the commit reply is as
/// long, but starts at the pause, after that answer reached it: it ends after the target's, so an
/// honest target's answer is never cut short, and waiting past it (for more bytes, a slower link) would
/// only hold the VM paused for a target that has already given up. A bigger budget is the target's to give.
const INCOMING_WAIT: Duration = Duration::from_secs(30);
const MAX_VMSTATE: u64 = 64 << 20;
const MAX_HEADER: u64 = 256 << 20;
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);
const HOLD_FENCE: Duration = Duration::from_millis(250);
const HELD_STREAM: Duration = Duration::from_secs(2);
/// How long a same-host target's hold, let go, watches for a packet sent along the old route
/// (the VM runs meanwhile: no downtime).
const STRAGGLERS: Duration = Duration::from_millis(5);
/// How long migrating on waits for an arrival still pulling.
const ARRIVAL_WAIT: Duration = Duration::from_secs(10);

/// What the source sends once paused, as one JSON line: the page states, then the vmstate's and the preloaded pages'
/// lengths (their bytes follow the line). Deserialized directly from the bounded line: no `Value` tree, which for a long
/// `runs` would be many times the line's size.
#[derive(Serialize, Deserialize)]
struct Header<'a> {
    runs: Cow<'a, [(u64, u64, u8)]>,
    vmstate_len: u64,
    preload: Cow<'a, [u64]>,
    paused: bool,
    app_log: u64,
}

enum Outcome {
    Committed(Value),
    Aborted,
}

/// A reroute remains owed even before its target underlay can be validated.
#[derive(Clone)]
pub(crate) struct Route {
    to: String,
    target: Value,
    peer: Option<IpAddr>,
    via: Option<Ipv4Addr>,
}

impl Route {
    fn new(to: &str, target: &Value, conn: Option<&TcpStream>) -> Self {
        Self { to: to.into(), target: target.clone(), peer: conn.and_then(|c| c.peer_addr().ok()).map(|a| a.ip()), via: None }
    }

    fn resolve(&mut self, host: &crate::host::Host) -> Result<Ipv4Addr> {
        if let Some(via) = self.via {
            return Ok(via);
        }
        let via = target_via(host, &self.target, &self.to, self.peer)?;
        self.via = Some(via);
        Ok(via)
    }
}

impl Proc {
    /// Releases held packets back to the VM's tap, returning stats and whether the route was attached.
    pub(crate) fn release_to_tap(&self, vm: &Vm, id: u64) -> (Option<hold::Stats>, bool) {
        let Some(h) = self.holder() else { return (None, false) };
        let (stats, res) = release_into(h, vm.ip, id, vm, Duration::ZERO, |()| crate::net::attach(vm.ip, &vm.tap));
        (stats, stats.is_some() && res.is_ok())
    }

    /// Everything not needing vmstate is prepared on the target before the
    /// pause. Once the target may have the state, this copy resumes only if
    /// the target says it aborted.
    /// `if_idle` (eviction): refused at once if the VM is busy or still arriving.
    /// `evict`: the host moves it for memory; the target admits it only above its own eviction mark.
    pub fn migrate(self: &Arc<Self>, to: &str, if_idle: bool, evict: bool) -> Result<Value> {
        let vm = self.vm().clone();
        let Some(source) = self.host.config_now().advertise()? else {
            bail!("this host runs no peer listener (flexvm listen): the target fetches the vm's memory through it");
        };
        let op = match if_idle {
            true => self.op_now().ok_or_else(|| Busy(format!("vm {}: {BUSY}", vm.name)))?,
            false => self.op_within()?,
        };
        if self.cmd.lock().unwrap().is_some() {
            match evict {
                true => return Err(Busy(format!("vm {} runs a command here that its process ends with; {BUSY}", vm.name)).into()),
                false => bail!("vm {} runs `run -- CMD`, which ends with its command here: it cannot migrate", vm.name),
            }
        }
        if if_idle && self.arrived.lock().unwrap().is_some() {
            return Err(Busy(format!("vm {} is still arriving; {BUSY}", vm.name)).into());
        }
        self.settle_arrival(&op, ARRIVAL_WAIT)?;
        vm.can_leave()?;
        vm.template.verify(&self.paths)?;
        let pushed = push_template(to, &vm.template)?;
        if pushed.is_none() && !vm.template.names_rootfs_by_path()? {
            bail!("{to} runs flexvm v0.1.0, which cannot load template {} (built since): upgrade it first", vm.template.meta.id);
        }
        let settle = Instant::now();
        vm.settle_hotplug(settle + crate::lifecycle::SETTLE_WAIT)?;
        let settle = settle.elapsed();
        let (mig, gen, prep) = (migration_id(), self.gen(), Instant::now());
        let vouched = pushed.as_ref().map_or(Value::Null, |p| p.1.clone());
        let (conn, prepared) = self.prepare_target(&vm, to, mig, gen, &source, evict, vouched).map_err(|e| match &pushed {
            None => format!("{e} ({to} is too old to be sent template {}: it migrates in only VMs of templates it has)", vm.template.meta.id).into(),
            Some(_) => e,
        })?;
        // Before the pause: dropped, the connection ends the target's arrival.
        check_app_support(to, &vm.name.get(), &prepared, &self.spec.lock().unwrap().moving(), vm.template.meta.image.as_ref())?;
        let prepare = prep.elapsed();
        // The pages worth sending with the state, ours and the target's: read and sorted before the pause.
        let mut wanted = crate::standby::load_set(&self.host, &vm.template);
        wanted.extend(serde_json::from_value::<Vec<u64>>(prepared["load_set"].clone()).unwrap_or_default());
        wanted.sort_unstable();
        wanted.dedup();
        wanted.truncate(MAX_PRELOAD);
        // Only now, right before the pause: the guest runs on at its mark meanwhile.
        let unthrottle = Instant::now();
        let _lifted = vm.limit.lift(vm.pid());
        let unthrottle = unthrottle.elapsed();
        // Made now, not in the hold right before the pause.
        self.holder();
        // A kill that came while this prepared wins (#567): its connection dropped, the target's arrival goes.
        self.not_destroyed()?;
        // Lent durably first: a crash with the outcome unknown must not hand the address out.
        self.lent_here.fetch_or(self.host.lend(&self.host.lock()?, vm.ip, gen, mig, to)?, Ordering::SeqCst);
        // Test gate: lent, not yet leaving.
        crate::host::gate("leave_gate");
        self.drop_held_in();
        self.set_leaving(true);
        // Test fault `leave_fail`: leaving fails once the address is lent.
        // A kill that comes before the VM is a source wins; one after it is refused (`try_destroy`).
        let left = crate::fault_result!(tripped("leave_fail") => Err("injected fault: leaving failed".into());
            vm.leave_unless(State::Source(mig), || self.not_destroyed()));
        if let Err(e) = left {
            self.set_leaving(false);
            // Leaving and its own loan undone in one write.
            let unlend = self.lent_here.load(Ordering::SeqCst).then_some(gen);
            match self.host.lock().and_then(|l| self.host.stay(&l, vm.ip, unlend)) {
                Ok(()) => self.lent_here.store(false, Ordering::SeqCst),
                Err(r) => crate::log!("vm {}: marking it here again and undoing its loan after a refused migration: {r}", vm.name),
            }
            return Err(e);
        }
        self.publish();
        // Test fault `park_fail`: parking the balloon fails, the VM still running as the source.
        let parked = crate::fault_result!(tripped("park_fail") => Err("injected fault: parking the balloon failed".into());
            vm.park_balloon());
        parked.map_err(|e| self.abort(&op, &vm, mig, e))?;
        let mut t = Phases::new();
        let vmstate = vm.dir.join("vmstate.out");
        let hold = || self.hold_addr(&vm, mig, "migration");
        let captured = (|| -> Result<_> {
            let saved = vm.save_state(&vmstate, false, false, hold, &mut t).and_then(|r| {
                // Test fault `capture_fail`: paused, its state captured, reading it fails.
                let read = crate::fault_result!(tripped("capture_fail") => Err(std::io::Error::other("injected fault: reading the vmstate failed"));
                    std::fs::read(&vmstate));
                Ok((r, t.total(), read?))
            });
            let _ = std::fs::remove_file(&vmstate);
            let (runs, paused, state) = saved?;
            t.mark("read_state");
            let pages = crate::uffd::remote_among(&runs, wanted);
            let mut data = vec![0u8; pages.len() * crate::util::PAGE_SIZE];
            // Test fault `preload_read_fail`: reading the pages it sends with the state fails.
            if tripped("preload_read_fail") {
                bail!("injected fault: reading the preloaded pages failed");
            }
            vm.pager.read_preload(&pages, &mut data)?;
            t.mark("read_preload");
            Ok((runs, paused, state, pages, data))
        })();
        let (runs, paused, state, mut pages, mut data) = captured.map_err(|e| self.abort(&op, &vm, mig, e))?;
        // Test fault `bad_preload`: a preload page past any guest memory, which the target refuses.
        if fault("bad_preload") {
            pages.push(u64::MAX);
            data.resize(data.len() + crate::util::PAGE_SIZE, 0);
        }
        let remote_pages: u64 = runs.iter().filter(|r| r.2 == crate::uffd::REMOTE).map(|r| r.1).sum();
        let sent = send_paused(
            &conn,
            &Header {
                runs: Cow::Borrowed(&runs),
                vmstate_len: state.len() as u64,
                preload: Cow::Borrowed(&pages),
                paused: vm.was_paused(),
                app_log: match self.hold_app_log() {
                    // Test fault `bad_app_log`: an offset past all of the guest's output.
                    _ if fault("bad_app_log") => u64::MAX,
                    at => at,
                },
            },
            &state,
            &data,
            // Ends after the target's own (`INCOMING_WAIT`), which started at its prepare answer.
            Instant::now() + INCOMING_WAIT,
            &mut t,
        );
        let (target, conn) = match sent {
            Ok(reply) if reply["ok"] == json!(true) => (reply["result"].clone(), Some(conn)),
            // A target refuses only before resuming the VM, or after killing it.
            Ok(reply) => return Err(self.abort(&op, &vm, mig, format!("target refused: {}", reply["error"]).into())),
            Err(e) => {
                // Close before asking its outcome, so the target's arrival can abort.
                drop(conn);
                match outcome(to, mig, Duration::from_secs(2)) {
                    Some(Outcome::Committed(target)) => (target, None),
                    Some(Outcome::Aborted) => return Err(self.abort(&op, &vm, mig, e)),
                    None => {
                        self.reconcile_later(mig, to.to_string());
                        bail!("migrating {} to {to}: {e}; {to} has not said whether it resumed the vm, so it stays paused here until it does", vm.name);
                    }
                }
            }
        };
        t.mark("target");
        let downtime = t.total();
        let (held, rerouted) = self.reroute(mig, to, &target, conn.as_ref());
        if let Err(e) = &rerouted {
            crate::log!("vm {}: migration {mig} to {to}: rerouting failed: {e}", self.name());
        }
        t.mark("reroute");
        self.wait_release(mig, to.to_string());
        Ok(json!({
            "name": vm.name,
            "to": to,
            "mig": mig,
            "template_push": pushed.map(|p| p.0),
            "settle_hotplug_ms": ms(settle),
            "prepare_ms": ms(prepare),
            "unthrottle_ms": ms(unthrottle),
            "checkpoint_ms": ms(paused),
            "downtime_ms": ms(downtime),
            "rerouted_ms": ms(t.total()),
            "reroute_error": rerouted.err().map(|e| e.to_string()),
            "held": held.map(|s| s.json()),
            "target_restore_ms": target["restore_ms"],
            "timings_ms": t.json(),
            "target_timings_ms": target["timings_ms"],
            "target_prepare_timings_ms": prepared["timings_ms"],
            "vmstate_kib": state.len() >> 10,
            "preload_pages": pages.len(),
            "to_transfer_mib": (remote_pages * crate::util::PAGE_SIZE as u64) >> 20,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_target(&self, vm: &Vm, to: &str, mig: u64, gen: u64, source: &str, evict: bool, vouched: Value) -> Result<(TcpStream, Value)> {
        let pid = vm.pid().ok_or("firecracker is gone")?;
        let msrs = crate::compat::local(pid)?.msrs;
        let tsc_khz = vm.tsc_khz;
        let (conn, prepared) = crate::util::rpc(
            to,
            Duration::from_secs(2),
            Instant::now() + PREFLIGHT_TIMEOUT,
            &json!({
                "op": "migrate_in",
                "name": vm.name,
                "mig": mig,
                "template": vm.template.name,
                "id": vm.template.meta.id,
                // For a copy the target received from a peer: what this host's files digest to (`push_template`).
                "template_digests": vouched,
                "ip": vm.ip.to_string(),
                "gen": gen,
                "rev": self.rev(),
                "source": source,
                "source_ident": crate::host::Ident::me(),
                "rss_mib": vm.rss() >> 20,
                // Settled: the arrival's memory mark is sized by it without asking its Firecracker.
                "plugged_mib": vm.hotplug_plugged(),
                "resources": vm.resources(),
                // What becomes of it once its app exits goes with it; its forwards stay here.
                "spec": self.spec.lock().unwrap().moving(),
                "regions": vm.pager.regions(),
                // The MSRs its vmstate will hold: this host's, which may be more than the template's.
                "msrs": msrs,
                "tsc_khz": tsc_khz,
                "evict": evict,
            }),
        )
        .map_err(|e| format!("cannot move vm {} to {e}", vm.name))?;
        conn.set_nodelay(true)?;
        conn.set_read_timeout(Some(Duration::from_secs(30)))?;
        conn.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok((conn, prepared))
    }

    /// Resumes this copy. Holds the host lock from the generation check to the
    /// resume: if a newer generation was recorded, the address went to another
    /// VM and this copy is destroyed instead.
    fn abort(&self, op: &Op, vm: &Arc<Vm>, mig: u64, e: Error) -> Error {
        if *vm.state.lock().unwrap() != State::Source(mig) {
            return e;
        }
        // A late abort (`abort_later`) comes after `migrate` restored the mark:
        // the resume's balloon unpark must not wait on Firecracker throttled at it.
        let _lifted = vm.limit.lift(vm.pid());
        let gen = self.gen();
        // Test fault `abort_gen_fail`: the address's record cannot be read.
        let checked = self.host.lock().and_then(|l| {
            crate::fault_result!(tripped("abort_gen_fail") => Err("injected fault: reading the address's generation failed".into());
                Ok((self.host.current(&l, vm.ip, gen)?, l)))
        });
        let l = match checked {
            Ok((true, l)) => l,
            Ok((false, l)) => {
                drop(l);
                if let Some(h) = self.holder() {
                    h.forget(vm.ip, mig);
                }
                crate::log!("vm {}: {e}; generation {gen} of {} was superseded meanwhile, so it is destroyed instead of resumed", vm.name, vm.ip);
                self.finish(op, End::Gone, crate::vmproc::FAILED, None)
            }
            Err(r) => {
                vm.set_failed();
                self.publish();
                return self
                    .abort_error(op, format!("{e}; and whether its address went to another vm cannot be told ({r}), so it stays paused, failed").into());
            }
        };
        // Past the revision its target took (and may have announced, if it committed): published or
        // recorded before it runs here again, so a late announcement of the target's is stale here (#533).
        if let Err(r) = self.advance(&l, 2) {
            drop(l);
            vm.set_failed();
            self.publish();
            return self.abort_error(
                op,
                format!("{e}; and its revision past its target's could be neither published nor recorded here ({r}), so it stays paused, failed").into(),
            );
        }
        let (_, attached) = self.release_to_tap(vm, mig);
        let (s, e) = match vm.resume(attached) {
            Ok(s) => (s, e),
            // Never Failed: as Firecracker has it (paused again, if it could not say), so a SIGCONT runs it again.
            Err((s, r)) => {
                if s != State::Running {
                    self.paused_by_request.store(true, Ordering::SeqCst);
                }
                (s, format!("{e}; resuming it here failed too: {r}; it is {} here (flexvm unpause {} runs it)", s.name(), vm.name).into())
            }
        };
        // Under the host lock: a route retry still running sees it is no longer this migration's source.
        *vm.state.lock().unwrap() = s;
        self.take_pending_route(mig);
        // Running here again, so do the collapse pass and prefetch the save cut short.
        vm.back_here();
        self.release_app_log();
        // Leaving and its own loan undone in one write: a crash leaves both (settled
        // through its target, `withdraw_dead`) or neither.
        let unlend = self.lent_here.load(Ordering::SeqCst).then_some(gen);
        // Test fault `abort_stay_fail`: resumed here, recording so fails.
        let stayed = crate::fault_result!(tripped("abort_stay_fail") => Err("injected fault: marking it here again failed".into());
                self.host.stay(&l, vm.ip, unlend));
        match stayed {
            Ok(()) => self.lent_here.store(false, Ordering::SeqCst),
            Err(r) => crate::log!("vm {}: marking it here again and undoing its loan after an aborted migration: {r}", vm.name),
        }
        drop(l);
        self.set_leaving(false);
        self.publish();
        if s != State::Failed {
            self.announce();
        }
        if s == State::Running {
            self.sync_clock_later();
        }
        self.abort_error(op, e)
    }

    /// An aborted migration, even one left failed and paused, no longer needs to keep
    /// memory for its target. A killed foreground claimer must not leave it behind.
    pub(crate) fn abort_error(&self, op: &Op, e: Error) -> Error {
        if self.claimer_gone.load(Ordering::SeqCst) {
            crate::log!("vm {}: {e}; its claimer (a foreground run) is gone, so it is destroyed", self.name());
            self.finish(op, End::Gone, crate::vmproc::FAILED, None)
        }
        e
    }

    /// Until the outcome is known, a kill ends this copy (`Proc::destroy`); once it
    /// is, this takes it back first, or (a kill took it) leaves the process to end.
    fn reconcile_later(self: &Arc<Self>, mig: u64, to: String) {
        self.reconciling(mig, &to);
        let p = self.clone();
        thread::spawn(move || {
            let mut patience = Duration::from_secs(1);
            loop {
                let o = outcome(&to, mig, patience);
                if o.is_some() && !p.known(mig) {
                    return;
                }
                match o {
                    Some(Outcome::Committed(target)) => {
                        crate::info!("vm {}: migration {mig} to {to} committed", p.name());
                        if let (_, Err(e)) = p.reroute(mig, &to, &target, None) {
                            crate::log!("vm {}: migration {mig} to {to}: rerouting failed: {e}", p.name());
                        }
                        return p.wait_release(mig, to);
                    }
                    Some(Outcome::Aborted) => return p.abort_later(mig, &format!("migration {mig} to {to} aborted")),
                    None => patience = (patience * 2).min(Duration::from_secs(30)),
                }
            }
        });
    }

    fn abort_later(&self, mig: u64, why: &str) {
        let (vm, op) = (self.vm().clone(), self.op());
        let e = self.abort(&op, &vm, mig, why.into());
        crate::log!("vm {}: {e}; now {}", vm.name, vm.state().name());
    }

    /// Ends the process once the target is `released`; on `aborted` this copy,
    /// as of the pause, is the only one left and runs again here.
    fn wait_release(self: &Arc<Self>, mig: u64, to: String) {
        let p = self.clone();
        thread::spawn(move || {
            let mut delay = Duration::from_millis(20);
            loop {
                match peer_call(&to, json!({"op": "migration", "mig": mig})).map(|r| r["outcome"].clone()) {
                    Ok(o) if o == "released" => break,
                    Ok(o) if o == "aborted" => {
                        return p.abort_later(mig, &format!("{to} lost the vm before it had all its memory; it runs here again, from the pause"));
                    }
                    _ => thread::sleep(delay),
                }
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            // One last try, never a retry loop: until `finish` the source stays unkillable, keeps its
            // name, claim and paused Firecracker, and a migration back here waits. `retry_route` already
            // retried in the background while the target pulled.
            if let Some(mut route) = p.take_pending_route(mig) {
                if let Err(e) = route.resolve(&p.host).and_then(|via| p.switch_route(mig, via)) {
                    crate::log!("route {} to {}: {e}; giving up", p.vm().ip, route.to);
                }
            }
            let op = p.op();
            // Decided here durably first: once the target forgets its record, the
            // migration would read as aborted there.
            match p.host.lock().and_then(|l| p.host.release(&l, p.vm().ip, &p.vm().name.get(), Some(&crate::host::Ident::me()))) {
                Ok(()) => drop(peer_call(&to, json!({"op": "migration", "mig": mig, "done": true}))),
                Err(e) => crate::log!(
                    "vm {}: recording that {to} has it: {e}; {to} is not told it is done, so it keeps its record for this host to ask about",
                    p.vm().name
                ),
            }
            p.finish(&op, End::Moved(to), 0, None)
        });
    }

    /// A failed route is retried in the background: the target owns the VM either way.
    /// The forwards stay until `finish` (`End::Moved`): meanwhile they reach the VM by the route to
    /// the target, and an abort after this runs the VM here again with them.
    fn reroute(&self, mig: u64, to: &str, target: &Value, conn: Option<&TcpStream>) -> (Option<hold::Stats>, Result<()>) {
        let ip = self.vm().ip;
        let mut route = Route::new(to, target, conn);
        *self.pending_route.lock().unwrap() = Some((mig, route.clone()));
        let via = match route.resolve(&self.host) {
            Ok(via) => via,
            Err(e) => {
                if let Some(h) = self.holder() {
                    h.forget(ip, mig);
                }
                self.retry_route(mig, route, &e);
                return (None, Err(e));
            }
        };
        *self.pending_route.lock().unwrap() = Some((mig, route.clone()));
        let (mut held, mut res) = (None, None);
        if let Some(h) = self.holder().filter(|h| h.holding_for(ip, mig)) {
            // Its paused Firecracker takes nothing off the tap: what is there came before the hold.
            h.hold_first(ip, mig, |each| self.vm().take_tap_queue(each));
            match conn.map(|c| (c, hold::start(c))) {
                Some((c, Ok(()))) => {
                    // Sharing our routes, the target takes the address over itself, after the held packets.
                    let handoff = crate::net::is_local_addr(via).unwrap_or(false);
                    (held, res) = hold::send(h, ip, mig, c, handoff, || self.switch_route(mig, via)).map(|(s, r)| (Some(s), Some(r))).unwrap_or_default()
                }
                started => {
                    if let Some((_, Err(e))) = started {
                        crate::log!("vm {}: {to} did not take the held packets: {e}", self.name());
                    }
                    held = Some(h.forget(ip, mig));
                }
            }
        }
        let res = res.unwrap_or_else(|| self.switch_route(mig, via));
        if let Err(e) = &res {
            self.retry_route(mig, route, e);
        } else {
            self.take_pending_route(mig);
        }
        (held, res)
    }

    fn retry_route(&self, mig: u64, mut route: Route, error: &dyn std::fmt::Display) {
        let Some(p) = self.arc() else { return };
        let what = format!("route {} to {}", self.vm().ip, route.to);
        crate::log!("{what}: {error}; retrying");
        thread::spawn(move || {
            if !retry(&what, || {
                let via = route.resolve(&p.host)?;
                let mut pending = p.pending_route.lock().unwrap();
                if pending.as_ref().is_some_and(|(m, _)| *m == mig) {
                    *pending = Some((mig, route.clone()));
                }
                drop(pending);
                p.switch_route(mig, via)
            }) {
                return;
            }
            match p.take_pending_route(mig) {
                Some(_) => crate::info!("{what}: done"),
                None => crate::info!("{what}: dropped, migration {mig} no longer owes it"),
            }
        });
    }

    /// Migration `mig`'s pending route, taken: never a later migration's, which an old retry or
    /// an abort must leave for that migration's own `wait_release`.
    fn take_pending_route(&self, mig: u64) -> Option<Route> {
        let mut pending = self.pending_route.lock().unwrap();
        pending.take_if(|(m, _)| *m == mig).map(|(_, route)| route)
    }

    /// Runs `f`, a route change for this VM's address, under the host lock and only while
    /// this process holds the address with a current generation; None, doing nothing, if not.
    fn if_current<R>(&self, f: impl FnOnce() -> Result<R>) -> Result<Option<R>> {
        let (ip, gen, l) = (self.vm().ip, self.gen(), self.host.lock()?);
        if self.host.holder(&l, ip)?.is_none_or(|h| h != self.name()) || !self.host.current(&l, ip, gen)? {
            return Ok(None);
        }
        let out = f()?;
        drop(l);
        Ok(Some(out))
    }

    /// Under the host lock, so a later claim of the address routes after; only while this VM is
    /// still the source of migration `mig`, since an abort resumes it here and keeps its route.
    fn switch_route(&self, mig: u64, via: Ipv4Addr) -> Result<()> {
        let (ip, gen, l) = (self.vm().ip, self.gen(), self.host.lock()?);
        if *self.vm().state.lock().unwrap() != State::Source(mig)
            || self.host.holder(&l, ip)?.is_some_and(|h| h != self.name())
            || !self.host.current(&l, ip, gen)?
        {
            return Ok(());
        }
        if fault("route") {
            bail!("injected fault: route_via failed");
        }
        crate::net::route_via(ip, via)
    }

    /// Target side. Without a commit, `finish` gives back what it took.
    pub fn migrate_in(self: &Arc<Self>, req: &Value, conn: TcpStream) -> Result<()> {
        let _ = conn.set_nodelay(true);
        let mut w = conn;
        let mig = req["mig"].as_u64().ok_or("missing mig")?;
        let mut prep = Phases::new();
        // Refused once its source cannot wait longer, or has hung up.
        let by = crate::listen::prepare_by();
        let going = || -> Result<()> {
            if Instant::now() >= by {
                bail!("not prepared within {} s", crate::listen::PREPARE_WAIT.as_secs());
            }
            if crate::util::hung_up(&w) {
                bail!("the source hung up");
            }
            Ok(())
        };
        let prepared = match self.prepare_in(req, mig, w.peer_addr()?.ip(), &mut prep, by, &going) {
            Ok(p) => p,
            Err(e) => {
                send_json(&mut w, &json!({"ok": false, "error": e.to_string()}))?;
                return Err(e);
            }
        };
        // `follows_app`: this side takes the VM's run settings (`spec`) and follows its app; `attaches`: -i and -t too.
        let result = json!({"timings_ms": prep.json(), "load_set": prepared.4, "hold_switch2": true, "follows_app": true, "attaches": true});
        send_json(&mut w, &json!({"ok": true, "result": result}))?;
        let deadline = Instant::now() + if fault("short_incoming") { Duration::from_secs(2) } else { INCOMING_WAIT };
        let mut r = BufReader::new(By { s: w.try_clone()?, at: deadline });
        let pager = prepared.0.pager.clone();
        // Bytes the source has declared and this side not yet read, at most what it may send: a refusal drains them.
        let owed = &std::sync::atomic::AtomicU64::new(arrival_owed(u64::MAX, usize::MAX));
        let res = thread::scope(|scope| -> Result<(Arc<Vm>, Value)> {
            let hdr: Header<'static> = crate::util::recv_json_max(&mut r, MAX_HEADER)?.ok_or("source hung up before sending the vmstate")?;
            owed.store(arrival_owed(hdr.vmstate_len, hdr.preload.len()), Ordering::SeqCst);
            let preload_len = (hdr.preload.len() * crate::util::PAGE_SIZE) as u64;
            let mut t = Phases::new();
            let runs: Runs = hdr.runs.into_owned();
            let pages: Vec<u64> = hdr.preload.into_owned();
            // Before anything counts or walks them: a bad page index would otherwise overflow, or hang the preload.
            crate::uffd::check_incoming(&runs, &pages, &prepared.2.regions).map_err(|e| format!("bad migration header: {e}"))?;
            let sizes = arrival_sizes(&runs, &prepared.0.template(), req["plugged_mib"].as_u64());
            // The guest ran on while this side prepared: what it pulls now is admitted
            // before anything is seeded or loaded, else refused while the source can resume.
            self.admit_arrival(sizes, arrival_floor(req), deadline)?;
            crate::host::stall("admitted_stall");
            *self.sizes.lock().unwrap() = Some(sizes);
            let state = read_vec(&mut r, hdr.vmstate_len, MAX_VMSTATE)?;
            owed.store(arrival_owed(0, pages.len()), Ordering::SeqCst);
            t.mark("recv_state");
            self.app_log.store(hdr.app_log, Ordering::SeqCst);
            // Preload installed while Firecracker parses the state; all in, or no commit.
            let r = &mut r;
            let preload = scope.spawn(move || -> Result<Result<()>> {
                let data = read_vec(r, preload_len, u64::MAX);
                owed.store(0, Ordering::SeqCst);
                let data = data.map_err(|e| format!("receiving the preloaded pages: {e}"))?;
                Ok(pager.preload(&pages, &data, deadline).map(drop).map_err(|e| format!("preloading pages: {e}").into()))
            });
            let preloaded = move || preload.join().unwrap_or_else(|_| Err("preloading panicked".into()));
            let paused = hdr.paused;
            self.paused_by_request.store(paused, Ordering::SeqCst);
            let vm = self.take_in(prepared, runs, &state, paused, deadline, preloaded, &mut t)?;
            Ok((vm, t.json()))
        });
        let answer = |reply: Value| send_json(&mut By { s: &w, at: deadline }, &reply);
        let (vm, t) = match res {
            Ok(r) => r,
            Err(e) => {
                refuse_arrival(&w, &mut r, &json!({"ok": false, "error": e.to_string()}), owed.load(Ordering::SeqCst), deadline);
                return Err(e);
            }
        };
        let revoked = Arc::new(Mutex::new(false));
        *self.held_in.lock().unwrap() = Some(revoked.clone());
        if fault("lost_ack") {
            let _ = w.shutdown(std::net::Shutdown::Both);
        } else {
            let _ = answer(json!({"ok": true, "result": {
                // On the downtime: never a lookup (the process's start made any it needed).
                "underlay": self.host.config_now().underlay_known().map(|u| u.to_string()),
                "timings_ms": t,
                "resume_error": (vm.state() == State::Failed).then_some("resuming failed"),
            }}));
        }
        // Off the downtime: the source waits for the answer above to reroute.
        self.start_limit();
        if vm.state() == State::Running {
            self.sync_clock_later();
        }
        let p = self.clone();
        let shared = shares_routes(req["source"].as_str().unwrap_or(""));
        let holder = self.holder().cloned().filter(|_| shared);
        thread::spawn(move || {
            // Sharing the source's routes, the address is routed here only once the
            // packets its hold took first are in (#78). When the source hands it over,
            // this process's hold takes it (what the source still has comes first),
            // and lets go of it once the stream ends; without a handover, the end
            // of the stream routes it. Each step only while the address is still
            // this VM's: a newer one's route, announced meanwhile, stays.
            let (mut routed, mut holding, mut plugged) = (!shared, false, false);
            // False, which the source is told, if it could not: the source still routes the
            // address to its own hold, where packets it re-sent would come back to (#512).
            let mut take_over = || {
                if std::mem::replace(&mut routed, true) {
                    return true;
                }
                let mut took = p.if_current(|| match holder.as_deref() {
                    // Test fault `hold_route_fail`: this hold's route fails.
                    Some(h) => vm.if_here(|| {
                        crate::fault_result!(tripped("hold_route_fail") => Err("injected fault: routing the address to the hold failed".into());
                            h.hold(vm.ip, mig))
                    }),
                    None => vm.route_here().map(|()| false),
                });
                if let Err(e) = &took {
                    // Routed to the tap at once instead, a few tries well within the source's
                    // wait, but only once plugged: what the route sends then waits there behind
                    // the source's last held packets, injected past the plug, until the stream
                    // ends. Unplugged, it would overtake them: left to the stream's end then.
                    crate::log!("vm {}: taking over {}: {e}; routing it to its tap", vm.name, vm.ip);
                    // Test fault `hold_plug_fail`: the tap's plug is refused.
                    // Keep the uncertain installed state on an unanswered request: it must be unplugged.
                    let (plug, res) = crate::fault_result!(tripped("hold_plug_fail") =>
                        (false, Err("injected fault: plugging the tap failed".into())); crate::net::plug_tap(&vm.tap));
                    plugged = plug;
                    match res {
                        Err(e) => crate::log!("vm {}: plugging its tap: {e}; routing {} once the held packets are in", vm.name, vm.ip),
                        Ok(()) => {
                            for delay in [0, 20, 80] {
                                thread::sleep(Duration::from_millis(delay));
                                took = p.if_current(|| vm.route_here()).map(|r| r.map(|()| false));
                                if took.is_ok() {
                                    break;
                                }
                            }
                        }
                    }
                }
                match took {
                    Ok(Some(held)) => holding = held,
                    Ok(None) => crate::log!("vm {}: {} went to a newer vm; not taking it over", vm.name, vm.ip),
                    Err(e) => {
                        crate::log!("vm {}: taking over {}: {e}", vm.name, vm.ip);
                        routed = false;
                    }
                }
                routed
            };
            let fence = Instant::now();
            crate::host::stall("handoff_stall");
            crate::host::gate("handoff_gate");
            if hold::wait_start(&mut r, (fence + HOLD_FENCE).min(deadline)) {
                if let Some(reported) = hold::receive(&mut r, vm.ip, &vm.tap, &revoked, (Instant::now() + HELD_STREAM).min(deadline), &mut take_over) {
                    vm.tap_drops_reported(reported);
                }
            } else {
                crate::log!("vm {}: no held packets from the source after {} ms", vm.name, ms(fence.elapsed()));
            }
            if plugged {
                let drops = unplug(&vm);
                if drops > 0 {
                    crate::log!("vm {}: its tap's plug dropped {drops} packets while taking {} over", vm.name, vm.ip);
                }
            }
            // Only the route switch is under the host lock: the tap's plug, not the lock,
            // keeps what the new route sends behind the held packets (#164).
            let ended = match (holder.as_deref(), holding) {
                (Some(h), true) => {
                    let start = Instant::now();
                    let mut current = true;
                    // What is routed to the tap from the switch on waits in its qdisc, in order,
                    // until the hold has handed over all it took before the switch (which a busy
                    // host can delay past the next packet): then it follows, in order.
                    // Whether our plug may be on the tap (also when the kernel's answer was
                    // lost): only then is it unplugged, never after a refusal.
                    let (plugged, res) = crate::net::plug_tap(&vm.tap);
                    if let Err(e) = res {
                        crate::log!("vm {}: plugging its tap: {e}", vm.name);
                    }
                    let (released, switched) = release_into(h, vm.ip, mig, &vm, STRAGGLERS, |()| {
                        let routed = p.if_current(|| {
                            // `release_stall`: the route change waits long (for RTNL, say).
                            if fault("release_stall") {
                                thread::sleep(Duration::from_millis(300));
                            }
                            vm.route_here()
                        })?;
                        current = routed.is_some();
                        routed.ok_or_else(|| format!("{} went to a newer vm", vm.ip).into())
                    });
                    let plug_drops = if plugged { unplug(&vm) } else { 0 };
                    if let Some(mut s) = released.filter(|_| current) {
                        s.dropped_target += plug_drops;
                        crate::log!("vm {}: let go of {} after {} ms, {} packets injected", vm.name, vm.ip, ms(start.elapsed()), s.injected);
                        if s.dropped + s.dropped_target > 0 {
                            crate::log!("vm {}: dropped {} of the packets held while taking {} over", vm.name, s.dropped + s.dropped_target, vm.ip);
                        }
                    }
                    if current {
                        switched.map(Some)
                    } else {
                        Ok(None)
                    }
                }
                _ if !routed => p.if_current(|| vm.route_here()),
                _ => p.if_current(|| Ok(())),
            };
            match ended {
                Ok(Some(())) => {}
                Ok(None) => {
                    if let Some(h) = holder.as_deref().filter(|_| holding) {
                        h.forget(vm.ip, mig);
                    }
                    crate::log!("vm {}: {} went to a newer vm; not routing it here", vm.name, vm.ip);
                }
                Err(e) => {
                    crate::log!("vm {}: routing {} to its tap: {e}; retrying", vm.name, vm.ip);
                    if let Some(h) = holder.as_deref() {
                        h.forget(vm.ip, mig);
                    }
                    retry(&format!("vm {}: routing {} to its tap", vm.name, vm.ip), || p.if_current(|| vm.route_here()).map(drop));
                }
            }
            p.held_in.lock().unwrap().take();
            p.announce();
            // Defer both revision fsyncs (file, then addrs directory) until after the reply and
            // packet handoff, so the disk never delays the route switch. The old durable claim still
            // has the generation, owner and `arriving` migration; only the routing revision lags,
            // published at the commit meanwhile (`commit_arrival`), so a late announcement of the
            // source's is still stale here (#533). The durable commit prevents a live target from
            // answering aborted; after its death, mig_status reaps it before allowing the source to
            // resume. Neither decision depends on the revision. Keep write_file's file-before-rename
            // ordering here so a crash cannot corrupt the old claim.
            if let Err(e) = p.host.lock().and_then(|l| p.advance(&l, 0)) {
                crate::log!("vm {}: recording its revision: {e}", p.name());
            }
        });
        let p = self.clone();
        let source = req["source"].as_str().unwrap_or("").to_string();
        thread::spawn(move || {
            let vm = p.vm().clone();
            vm.restore_devices();
            let start = Instant::now();
            p.wait_pulled(&vm);
            crate::info!("vm {}: pull from {source} ended after {} ms", vm.name, ms(start.elapsed()));
            // Unless an operation settled it first, or the VM ended (its source's
            // copy runs again). `op` is let go between tries, for a kill.
            loop {
                let op = p.op();
                match p.settle_arrival(&op, Duration::ZERO) {
                    Err(e) if p.pulled_all() => crate::log!("{e}"),
                    _ => return,
                }
                drop(op);
                thread::sleep(Duration::from_secs(1));
            }
        });
        Ok(())
    }

    fn prepare_in(
        &self,
        req: &Value,
        mig: u64,
        from: std::net::IpAddr,
        t: &mut Phases,
        until: Instant,
        going: &dyn Fn() -> Result<()>,
    ) -> Result<(crate::vm::Prepared, Ipv4Addr, Source, String, Vec<u64>)> {
        let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
        // The peers' addresses as the listener goes by (it waited for a name just added), else as a
        // restore's are known; and the source's.
        let mut peers: Vec<std::net::IpAddr> = match std::env::var("FLEXVM_INCOMING_PEERS") {
            Ok(p) => serde_json::from_str(&p)?,
            Err(_) => crate::listen::known_peers(&self.host)?,
        };
        peers.push(from);
        crate::listen::check_vm_ip(&self.host, ip, &peers)?;
        crate::util::check_kvm()?;
        let name = req["name"].as_str().ok_or("missing name")?.to_string();
        let regions = serde_json::from_value::<Vec<_>>(req["regions"].clone()).map_err(|e| format!("bad regions: {e}"))?;
        if regions.is_empty() {
            bail!("the source sent no memory regions");
        }
        let source = Source { addr: req["source"].as_str().ok_or("missing source")?.into(), vm: name.clone(), mig, regions };
        self.set_name(self.host.take_name(&name, false)?);
        // Bound before the prepare is answered (#593, as a resume's): failing, the source never
        // pauses. Until the VM is adopted, the socket says it is starting; an abort's `finish`
        // unlinks it with the name.
        self.serve_control()?;
        let by = serde_json::from_value(req["source_ident"].clone()).ok();
        let tpl = Template::open_id(&self.paths, req["template"].as_str().ok_or("missing template")?, req["id"].as_str().ok_or("missing template id")?)?;
        // One received from a peer only for a source with the same files: its content id proves none.
        if tpl.meta.received.is_some() && req["template_digests"] != json!(tpl.meta.received) {
            bail!(
                "template {} here was received from a peer, and this source does not vouch for its files (one older than this host's flexvm cannot)",
                tpl.meta.id
            );
        }
        // Its caps move with it (the same template: they fit).
        // Refused before the source pauses: a capped VM never runs uncapped here.
        self.keep_resources(serde_json::from_value(req["resources"].clone()).unwrap_or_default())?;
        // Its forwards stayed on the source, as host-local proxies.
        *self.spec.lock().unwrap() = serde_json::from_value::<crate::app::RunSpec>(req["spec"].clone()).unwrap_or_default().moving();
        t.mark("template");
        going()?;
        // Admission, the record and the claim under one wait for the lock, which gives up in time.
        let l = self.host.lock_by(Some(until)).map_err(|e| format!("not admitted within {} s: {e}", crate::listen::PREPARE_WAIT.as_secs()))?;
        // Before the record (fsynced) and the claim: a refusal leaves nothing to undo. Never past the guest's size.
        self.admit_start(req["rss_mib"].as_u64().unwrap_or(0).min(tpl.meta.max_mib), None, arrival_floor(req))?;
        *self.arrived.lock().unwrap() = Some(self.host.mig_begin(mig, &source.addr, by, Some(ip))?);
        // The source's next revision: past it, its resume after an abort outranks this location.
        let rev = req["rev"].as_u64().ok_or("missing rev")?.saturating_add(1);
        let claim = self.host.claim_arrival(&l, &name, ip, req["gen"].as_u64().unwrap_or(0), rev, mig)?;
        drop(l);
        self.set_addr(claim);
        t.mark("claim_ip");
        going()?;
        let idle = self.spawner.take(Some(until))?;
        going()?;
        crate::host::stall("incoming_stall");
        crate::host::gate("incoming_gate");
        t.mark("spawn");
        let load_set = crate::standby::load_set(&self.host, &tpl);
        let saved = serde_json::from_value(req["msrs"].clone()).map_err(|e| format!("bad msrs: {e}"))?;
        let tsc_khz = serde_json::from_value(req["tsc_khz"].clone()).map_err(|e| format!("bad tsc_khz: {e}"))?;
        let vm = crate::vm::Prepared::with_saved_tsc(idle, tpl, || Ok((tsc_khz, &saved)))?;
        t.mark("pager_start");
        // All of routing the address here but the route itself, which waits for the commit.
        let ifindex = crate::net::neighbour(ip, &vm.firecracker().tap)?;
        t.mark("neighbour");
        if shares_routes(&source.addr) {
            // Ready before the source pauses: it takes the address over from the source's hold.
            self.holder();
            t.mark("holder");
        }
        if vm.prepare_load(until)? {
            t.mark("prepare_load");
        }
        if fault("prepare_fail") {
            bail!("injected fault: preparing failed");
        }
        going()?;
        Ok((vm.unrouted(ifindex), ip, source, name, load_set))
    }

    /// Every check that can still abort runs before the commit; the host lock
    /// is held from the commit through the resume.
    #[allow(clippy::too_many_arguments)]
    fn take_in(
        &self,
        (prepared, ip, source, name, _): (crate::vm::Prepared, Ipv4Addr, Source, String, Vec<u64>),
        runs: Runs,
        state: &[u8],
        paused: bool,
        deadline: Instant,
        before_commit: impl FnOnce() -> Result<Result<()>>,
        t: &mut Phases,
    ) -> Result<Arc<Vm>> {
        let mut before_commit = Some(before_commit);
        let probe = runs.iter().find(|r| r.2 == crate::uffd::REMOTE).map(|r| {
            let (source, page) = (source.clone(), r.0);
            thread::spawn(move || crate::uffd::probe(&source, page, deadline))
        });
        if fault("kill_prepared") {
            prepared.pager.firecracker_gone();
        }
        if fault("fetch_tail_enomem") {
            prepared.pager.tail_fail.store(2, Ordering::SeqCst);
        }
        if fault("pull_enomem") {
            prepared.pager.pull_fail.store(40, Ordering::SeqCst);
        }
        if fault("fetch_enomem_stuck") {
            // Pullers held off from here; copies fail from the resume on (below), once the load had its pages.
            *prepared.pager.stuck_from.lock().unwrap() = Some(Instant::now() + Duration::from_secs(86400));
        }
        // A retry first drains the preload off the connection (the source still serves those pages).
        let seed = Some((runs, Origin::Peer(source.clone())));
        let retry = || before_commit.take().unwrap()().map(drop);
        // Routed here at the commit (sharing the source's routes, after the held packets):
        // until then the route back to the source stays, whatever happens to this arrival.
        let shared = shares_routes(&source.addr);
        let restored = prepared.load(&self.spawner, &name, Snapshot::Bytes(state), seed, ip, paused, Some(deadline), retry, t);
        let probed = probe.map_or(Ok(()), |p| p.join().unwrap_or_else(|_| Err(std::io::Error::other("probe panicked"))));
        // A load that fails for want of pages says less than the probe of the source does.
        let (vm, _) = match (restored, &probed) {
            (Ok(r), _) => r,
            (Err(_), Err(e)) => bail!("migration source {} does not serve pages: {e} (it never ran here)", source.addr),
            (Err(e), Ok(())) => bail!("{e} (it never ran here)"),
        };
        let checked = match (probed, vm.pager.failed()) {
            (Err(e), _) => Err(format!("migration source {} does not serve pages: {e}", source.addr).into()),
            (_, Some(why)) => Err(format!("its memory cannot be paged in: {why}").into()),
            _ => before_commit.take().map_or(Ok(Ok(())), |f| f()).and_then(|r| r).and_then(|()| {
                // Test gate `commit_gate`: a test looks at the loaded, never-run VM here; only with time to spare
                // (the test lets go within 5 s), so waiting there never ends in a deadline error.
                if deadline.saturating_duration_since(Instant::now()) >= Duration::from_secs(10) {
                    crate::host::gate("commit_gate");
                }
                // The ownership boundary (refused if fenced).
                let l = self.host.lock_by(Some(deadline))?;
                if Instant::now() >= deadline {
                    bail!("the migration ran past its deadline");
                }
                if !self.host.current(&l, ip, self.gen())? {
                    bail!("generation {} of {ip} was withdrawn or superseded meanwhile", self.gen());
                }
                // A failed commit takes the tap, and this route, with it; `finish` puts the peer's back.
                if !shared {
                    vm.route()?;
                    t.mark("route");
                }
                // Test fault `commit_fail`: the durable commit fails, its route (if any) installed.
                if tripped("commit_fail") {
                    bail!("injected fault: committing failed");
                }
                self.commit_arrival(&l)?;
                Ok(l)
            }),
        };
        let committed = match checked {
            Ok(l) => l,
            Err(e) => {
                vm.kill();
                return Err(format!("{e} (it never ran here)").into());
            }
        };
        t.mark("register");
        // Its memory mark is set once the source has its answer (`migrate_in`).
        self.adopt(vm.clone());
        if !paused {
            if let Err(e) = vm.start(fault("resume_kill")) {
                crate::log!("vm {name}: resuming after migration {} failed: {e}", source.mig);
                vm.set_failed();
            }
            t.mark("resume");
            // Test fault `fetch_enomem_stuck`: its copies fail from now on.
            if let Some(from) = vm.pager.stuck_from.lock().unwrap().as_mut() {
                *from = Instant::now();
            }
        }
        drop(committed);
        self.publish();
        Ok(vm)
    }
}

/// Has `to` take generation `tpl`, by content id, before anything else of a migration (so before the
/// pause): sent unless it has it. Returns its timings and, for a copy `to` received from a peer, the
/// digests this host vouches for it with (`template::digests`), which the arrival checks. None if `to`
/// is too old to be sent one (then it must have it).
fn push_template(to: &str, tpl: &Template) -> Result<Option<(Value, Value)>> {
    let (start, at) = (Instant::now(), Instant::now() + crate::listen::PUSH_WAIT);
    let fail = |e: Error| -> Error { format!("cannot send template {} to {to}: {e}", tpl.meta.id).into() };
    let (conn, mut reply) = match crate::util::rpc(to, Duration::from_secs(2), at, &json!({"op": "template", "id": tpl.meta.id})) {
        Err(e) if e.to_string().contains("unknown op \"template\"") => return Ok(None),
        r => r.map_err(fail)?,
    };
    let mut sent = 0;
    if reply["have"] != json!(true) {
        let n = crate::template::send(tpl, &mut std::io::BufWriter::with_capacity(1 << 20, By { s: &conn, at }));
        // Its answer says more than a failed write: it may have refused the template part way.
        reply = crate::util::recv_json(&mut BufReader::new(By { s: &conn, at })).and_then(|r| crate::util::answer(r, to, "refused")).map_err(fail)?;
        sent = n.map_err(fail)?;
    }
    let digests = match reply["digests"].is_null() {
        true => Value::Null,
        false => json!(tpl.digests()?),
    };
    if digests != reply["digests"] {
        bail!("{to} has a copy of template {} received from a peer whose files differ from this host's: remove it there (flexvm rmi {0})", tpl.meta.id);
    }
    Ok(Some((json!({"sent_mib": sent >> 20, "ms": ms(start.elapsed())}), digests)))
}

/// Header, state, preload and commit reply share one cap: partial writes cannot extend the pause.
fn send_paused(conn: &TcpStream, header: &Header<'_>, state: &[u8], data: &[u8], at: Instant, t: &mut Phases) -> Result<Value> {
    let mut conn = By { s: conn, at };
    send_json(&mut conn, header)?;
    conn.write_all(state)?;
    if fault("slow_preload") {
        thread::sleep(Duration::from_millis(300));
    }
    conn.write_all(data)?;
    t.mark("send_state");
    Ok(recv_json(&mut BufReader::new(conn))?.ok_or("target hung up")?)
}

/// Check the target before forwarding held packets or changing any route.
fn target_via(host: &crate::host::Host, target: &Value, to: &str, peer: Option<IpAddr>) -> Result<Ipv4Addr> {
    let via = target["underlay"].as_str().ok_or("target sent no underlay")?.parse()?;
    let cfg = host.config_now();
    let cache = crate::listen::Cached::read(&host.run, &cfg.peers);
    let mut peers = cfg.peer_underlay_addrs();
    for name in &cfg.peers {
        if let Ok(addrs) = cache.addrs(name) {
            peers.extend(addrs);
        }
    }
    match peer {
        Some(peer) => peers.push(peer),
        None => {
            if let Ok(addrs) = crate::util::resolve(to, Instant::now() + Duration::from_secs(2)) {
                peers.extend(addrs.iter().map(|a| a.ip()));
            }
        }
    }
    crate::listen::check_via(via, &peers)?;
    Ok(via)
}

/// An arrival's (MiB to page in, guest size) from what its source sent: the
/// pages it pulls, and its boot memory plus what is plugged (all of the
/// hotplug region from a source that does not say).
fn arrival_sizes(runs: &Runs, tpl: &Template, plugged: Option<u64>) -> (u64, u64) {
    let remote: u64 = runs.iter().filter(|r| r.2 == crate::uffd::REMOTE).map(|r| r.1).sum();
    let meta = &tpl.meta;
    ((remote * crate::util::PAGE_SIZE as u64) >> 20, meta.mem_mib + plugged.unwrap_or(meta.max_mib - meta.mem_mib).min(meta.max_mib - meta.mem_mib))
}

/// What an arrival's admission leaves available: the eviction mark for one moved by eviction.
fn arrival_floor(req: &Value) -> crate::host::Floor {
    match req["evict"] == true {
        true => crate::host::Floor::EvictMark,
        false => crate::host::Floor::Reserve,
    }
}

/// Whether the host at `addr` (a listener's) is this one, routes and all.
fn shares_routes(addr: &str) -> bool {
    let ip = match addr.parse::<std::net::SocketAddr>().map(|a| a.ip()) {
        Ok(std::net::IpAddr::V4(ip)) => ip,
        Ok(std::net::IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
            Some(ip) => ip,
            None => return ip.is_loopback(),
        },
        Err(_) => return false,
    };
    crate::net::is_local_addr(ip).unwrap_or(false)
}

/// Tries `f` up to 10 times, 100 ms after the last and doubling to 5 s apart, logging failures as `what`; whether it
/// succeeded.
fn retry(what: &str, mut f: impl FnMut() -> Result<()>) -> bool {
    let mut delay = Duration::from_millis(100);
    for _ in 0..10 {
        thread::sleep(delay);
        match f() {
            Ok(()) => return true,
            Err(e) => crate::log!("{what}: {e}"),
        }
        delay = (delay * 2).min(Duration::from_secs(5));
    }
    false
}

fn outcome(to: &str, mig: u64, patience: Duration) -> Option<Outcome> {
    let start = Instant::now();
    loop {
        if let Ok(r) = peer_call(to, json!({"op": "migration", "mig": mig})) {
            match r["outcome"].as_str() {
                Some("committed" | "released") => return Some(Outcome::Committed(r)),
                Some("aborted") => return Some(Outcome::Aborted),
                _ => {}
            }
        }
        if start.elapsed() >= patience {
            return None;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Injects held packets, `switch`es the route, then injects stragglers. A
/// failed switch forgets the hold; the caller retries the route.
pub fn release_into(h: &Holder, ip: Ipv4Addr, mig: u64, vm: &Vm, linger: Duration, switch: impl FnOnce(()) -> Result<()>) -> (Option<hold::Stats>, Result<()>) {
    if !h.holding_for(ip, mig) {
        return (None, Ok(()));
    }
    let inj = match crate::net::set_link_up(&vm.tap, true).and_then(|()| hold::Injector::new(&vm.tap)) {
        Ok(inj) => inj,
        Err(e) => {
            crate::log!("vm {}: dropping held packets: {e}", vm.name);
            h.forget(ip, mig);
            return (None, Err(e));
        }
    };
    let Some((mut stats, switched)) = h.release_local(ip, mig, &mut |p| hold::valid(p, ip) && inj.send(p), || switch(()), linger) else {
        return (None, Ok(()));
    };
    if let Err(e) = &switched {
        h.forget(ip, mig);
        crate::log!("vm {}: routing {ip} back to its tap after injecting the held packets: {e}", vm.name);
    }
    let tap_dropped = inj.dropped();
    (stats.injected, stats.dropped_target) = (stats.packets, tap_dropped);
    vm.tap_drops_reported(tap_dropped);
    // Closing a packet socket waits for an RCU grace period; the VM need not.
    thread::spawn(move || drop(inj));
    (Some(stats), switched)
}

/// 53 bits, so any JSON parser keeps it.
pub fn migration_id() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    h.write_u32(std::process::id());
    h.finish() >> 11
}

/// What an arrival still to read `vmstate_len` bytes of state and `preload` pages is drained of if refused: never
/// more than a source may send.
fn arrival_owed(vmstate_len: u64, preload: usize) -> u64 {
    vmstate_len.min(MAX_VMSTATE) + (preload.min(MAX_PRELOAD) * crate::util::PAGE_SIZE) as u64
}

/// Answers a refusal, then reads what the source still sends (`owed` bytes, by `at`): closed with that unread, the
/// connection would be reset, and the source, still writing, would never read the reason.
fn refuse_arrival(w: &TcpStream, r: &mut impl Read, reply: &Value, owed: u64, at: Instant) {
    let _ = send_json(&mut By { s: w, at }, reply);
    let _ = w.shutdown(std::net::Shutdown::Write);
    let _ = std::io::copy(&mut r.take(owed), &mut std::io::sink());
}

fn read_vec(r: &mut impl Read, len: u64, max: u64) -> Result<Vec<u8>> {
    if len > max {
        bail!("{len} bytes, more than {max}");
    }
    let mut v = vec![0u8; len as usize];
    r.read_exact(&mut v)?;
    Ok(v)
}

fn unplug(vm: &Vm) -> u64 {
    let (drops, res) = crate::net::unplug_tap(&vm.tap);
    if let Err(e) = res {
        crate::log!("vm {}: letting {}'s packets through its tap: {e}", vm.name, vm.ip);
    }
    drops
}

/// Older targets neither preserve run settings nor end the VM when its app exits.
fn check_app_support(to: &str, name: &str, prepared: &Value, spec: &crate::app::RunSpec, image: Option<&crate::image::ImageMeta>) -> Result<()> {
    if prepared["follows_app"] != true && (*spec != crate::app::RunSpec::default() || spec.has_app(image)) {
        bail!("{to} runs an older flexvm, which would drop vm {name}'s run settings (-e, --entrypoint, --keep, --rm, --ip) or fail to exit with its app: upgrade it first");
    }
    if prepared["attaches"] != true && (spec.stdin || spec.tty) {
        bail!("{to} runs an older flexvm, which cannot attach to vm {name}'s app (run -i, -t): upgrade it first");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_targets_must_support_the_app_and_run_settings() {
        use crate::app::RunSpec;
        let plain = RunSpec::default();
        let image = |argv: &[&str], warm| {
            serde_json::from_value::<crate::image::ImageMeta>(json!({
                "source": "x", "digest": "d", "config_digest": "c", "app_conf": "", "argv": argv, "warm": warm,
            }))
            .unwrap()
        };
        let idle = image(&[], false);
        let app = image(&["/bin/sleep", "10"], false);
        let warm = image(&["/bin/server"], true);
        let settings = [
            RunSpec { env: vec!["A=1".into()], ..Default::default() },
            RunSpec { entrypoint: Some(vec!["/bin/server".into()]), ..Default::default() },
            RunSpec { keep: true, ..Default::default() },
            RunSpec { rm: true, ..Default::default() },
            RunSpec { ip: Some("10.0.0.9".parse().unwrap()), ..Default::default() },
        ];
        let it = RunSpec { stdin: true, tty: true, ..Default::default() };
        let e = check_app_support("peer", "vm", &json!({"follows_app": true}), &it, Some(&app)).unwrap_err().to_string();
        assert!(e.contains("cannot attach"), "{e}");
        check_app_support("peer", "vm", &json!({"follows_app": true, "attaches": true}), &it, Some(&app)).unwrap();
        for target in [json!({}), json!({"follows_app": false}), json!({"follows_app": true})] {
            // `-p` ports stay on the source: they never need a newer target.
            let ported = RunSpec { ports: vec!["8080:80".parse().unwrap()], ..Default::default() }.moving();
            for image in [None, Some(&idle)] {
                assert!(check_app_support("peer", "vm", &target, &plain, image).is_ok());
                assert!(check_app_support("peer", "vm", &target, &ported, image).is_ok());
            }
            for (spec, image) in [(&plain, Some(&app)), (&plain, Some(&warm))].into_iter().chain(settings.iter().map(|s| (s, Some(&idle)))) {
                let result = check_app_support("peer", "vm", &target, spec, image);
                if target["follows_app"] == true {
                    assert!(result.is_ok());
                } else {
                    let e = result.unwrap_err().to_string();
                    assert!(e.contains("older flexvm") && e.contains("exit with its app") && e.contains("upgrade it first"), "{e}");
                }
            }
        }
    }

    #[test]
    fn target_underlay_must_be_a_known_peer() {
        let root = crate::test_util::TempDir::new("target-via");
        let mut host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        host.configure(|c| {
            c.peers = vec!["192.0.2.7:7070".into(), "127.0.0.1:7070".into()];
            Ok(())
        })
        .unwrap();
        assert_eq!(target_via(&host, &json!({"underlay": "192.0.2.7"}), "192.0.2.99:7070", None).unwrap(), "192.0.2.7".parse::<Ipv4Addr>().unwrap());
        // A peer sharing this network namespace: the handoff goes by its local underlay.
        assert_eq!(target_via(&host, &json!({"underlay": "127.0.0.1"}), "192.0.2.99:7070", None).unwrap(), Ipv4Addr::LOCALHOST);
        for target in [json!({}), json!({"underlay": "192.0.2.8"}), json!({"underlay": "127.0.0.2"})] {
            assert!(target_via(&host, &target, "192.0.2.99:7070", None).is_err());
        }
        host.configure(|c| {
            c.peers.push("unseen.invalid:7070".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(target_via(&host, &json!({"underlay": "192.0.2.7"}), "192.0.2.99:7070", None).unwrap(), "192.0.2.7".parse::<Ipv4Addr>().unwrap());
        // An available name's cached addresses survive another name's missing entry.
        host.configure(|c| {
            c.peers.push("cached.invalid:7070".into());
            Ok(())
        })
        .unwrap();
        crate::util::write_file(&host.run, "peers.json", br#"{"names":{"cached.invalid:7070":["192.0.2.8"]}}"#, false).unwrap();
        assert_eq!(target_via(&host, &json!({"underlay": "192.0.2.8"}), "192.0.2.99:7070", None).unwrap(), "192.0.2.8".parse::<Ipv4Addr>().unwrap());
        // Failed destination resolution must not discard cached or explicit underlays.
        assert_eq!(target_via(&host, &json!({"underlay": "192.0.2.8"}), "bad address", None).unwrap(), "192.0.2.8".parse::<Ipv4Addr>().unwrap());
        host.configure(|c| {
            c.peer_underlays.insert("cached.invalid:7070".into(), vec!["192.0.2.9".parse().unwrap()]);
            Ok(())
        })
        .unwrap();
        assert_eq!(target_via(&host, &json!({"underlay": "192.0.2.9"}), "bad address", None).unwrap(), "192.0.2.9".parse::<Ipv4Addr>().unwrap());
        assert!(target_via(&host, &json!({"underlay": "192.0.2.10"}), "bad address", None).is_err());
        // The connection authorizes the target even before its name is cached.
        host.configure(|c| {
            c.peers = vec!["unseen.invalid:7070".into()];
            Ok(())
        })
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let conn = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        assert_eq!(
            target_via(&host, &json!({"underlay": "127.0.0.1"}), "unseen.invalid:7070", Some(conn.peer_addr().unwrap().ip())).unwrap(),
            Ipv4Addr::LOCALHOST
        );
        // Reconciliation has no connection: resolve the destination instead (an address: no resolver to wait on).
        assert_eq!(target_via(&host, &json!({"underlay": "127.0.0.1"}), "127.0.0.1:7070", None).unwrap(), Ipv4Addr::LOCALHOST);
        assert!(target_via(&host, &json!({"underlay": "192.0.2.8"}), "127.0.0.1:7070", Some(conn.peer_addr().unwrap().ip())).is_err());
        assert!(target_via(&host, &json!({"underlay": "224.0.0.1"}), "224.0.0.1:7070", None).is_err());
    }

    #[test]
    fn retry_rechecks_target_underlay_after_validation_failure() {
        let root = crate::test_util::TempDir::new("target-via-retry");
        let mut host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let mut attempts = 0;
        assert!(retry("target underlay", || {
            attempts += 1;
            let via = target_via(&host, &json!({"underlay": "192.0.2.7"}), "bad address", None);
            if attempts == 1 {
                assert!(via.is_err());
                host.configure(|c| {
                    c.peers.push("192.0.2.7:7070".into());
                    Ok(())
                })?;
            }
            via.map(|_| ())
        }));
        assert_eq!(attempts, 2);
    }

    #[test]
    fn unresolved_pending_route_can_be_resolved_at_release() {
        let root = crate::test_util::TempDir::new("pending-route");
        let mut host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let mut pending = Some((7, Route::new("bad address", &json!({"underlay": "192.0.2.7"}), None)));
        // Neither the initial attempt nor its background retry can validate the target yet.
        for _ in 0..2 {
            assert!(pending.as_mut().unwrap().1.resolve(&host).is_err());
        }
        host.configure(|c| {
            c.peers.push("192.0.2.7:7070".into());
            Ok(())
        })
        .unwrap();
        // Release still has the unresolved reroute, even if all earlier attempts failed.
        assert!(pending.take_if(|(mig, _)| *mig == 8).is_none());
        let (_, mut route) = pending.take_if(|(mig, _)| *mig == 7).unwrap();
        assert_eq!(route.resolve(&host).unwrap(), "192.0.2.7".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn route_retry_retains_the_connection_peer() {
        let root = crate::test_util::TempDir::new("route-peer-retry");
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let conn = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let route = Route::new("bad address", &json!({"underlay": "127.0.0.1"}), Some(&conn));
        drop(conn);
        // The connection address survives copying the unresolved route to the retry thread.
        let mut retry = route.clone();
        assert_eq!(retry.resolve(&host).unwrap(), Ipv4Addr::LOCALHOST);
        assert!(route.via.is_none());
        assert!(target_via(&host, &route.target, &route.to, None).is_err());
    }

    #[test]
    fn paused_send_deadline_bounds_a_slow_target() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let conn = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let reader = thread::spawn(move || {
            let mut buf = [0; 4096];
            let mut drained = 0;
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            while !stopped.load(Ordering::SeqCst) {
                let n = peer.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                drained += n;
                thread::sleep(Duration::from_millis(10));
            }
            drained
        });
        let header = Header { runs: Cow::Borrowed(&[]), vmstate_len: 1, preload: Cow::Borrowed(&[]), paused: false, app_log: 0 };
        let data = vec![7; 16 << 20];
        let start = Instant::now();
        let budget = Duration::from_millis(200);
        let result = send_paused(&conn, &header, &[0], &data, start + budget, &mut Phases::new());
        let elapsed = start.elapsed();
        stop.store(true, Ordering::SeqCst);
        drop(conn);
        let drained = reader.join().unwrap();
        assert_eq!(result.unwrap_err().downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::TimedOut);
        assert!(elapsed >= budget && elapsed < budget + Duration::from_secs(1), "{elapsed:?}");
        assert!(drained > 4096 && drained < data.len(), "peer must make partial progress: {drained}");
    }

    #[test]
    fn paused_send_deadline_bounds_the_commit_reply() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let conn = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        // Takes everything at once, then never answers.
        let reader = thread::spawn(move || std::io::copy(&mut peer, &mut std::io::sink()).unwrap());
        let header = Header { runs: Cow::Borrowed(&[]), vmstate_len: 1, preload: Cow::Borrowed(&[]), paused: false, app_log: 0 };
        let data = vec![7; 1 << 20];
        let start = Instant::now();
        let budget = Duration::from_millis(300);
        let result = send_paused(&conn, &header, &[0], &data, start + budget, &mut Phases::new());
        let elapsed = start.elapsed();
        drop(conn);
        let drained = reader.join().unwrap();
        assert_eq!(result.unwrap_err().downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::TimedOut);
        assert!(elapsed >= budget && elapsed < budget + Duration::from_secs(1), "{elapsed:?}");
        assert!(drained > data.len() as u64, "all was sent before the wait for the reply: {drained}");
    }

    /// A refused arrival reads what its source still sends, so the source, still writing, gets the reason, not a reset.
    #[test]
    fn a_refusal_drains_what_the_source_still_sends() {
        const LEN: usize = 64 << 20;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let source = thread::spawn(move || -> Result<Value> {
            let mut c = TcpStream::connect(addr)?;
            c.write_all(&vec![7u8; LEN])?;
            Ok(recv_json(&mut BufReader::new(&c))?.ok_or("hung up")?)
        });
        let (w, _) = l.accept().unwrap();
        let at = Instant::now() + Duration::from_secs(20);
        let mut r = BufReader::new(By { s: w.try_clone().unwrap(), at });
        // Its header read, it is refused.
        r.read_exact(&mut [0u8; 100]).unwrap();
        refuse_arrival(&w, &mut r, &json!({"ok": false, "error": "no room"}), (LEN - 100) as u64, at);
        drop((w, r));
        assert_eq!(source.join().unwrap().unwrap()["error"], "no room");
    }

    /// A header declaring more than a source may send (a million preload pages) drains no more than that.
    #[test]
    fn a_refusal_drains_at_most_what_a_source_may_send() {
        let most = MAX_VMSTATE + (MAX_PRELOAD * crate::util::PAGE_SIZE) as u64;
        assert_eq!(arrival_owed(u64::MAX, 1_000_000), most);
        assert_eq!(arrival_owed(100, 2), 100 + 2 * crate::util::PAGE_SIZE as u64);
        assert_eq!(arrival_owed(0, 0), 0);
    }
}
