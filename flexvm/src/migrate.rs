//! Post-copy live migration over one TCP connection to the target's listener:
//! `migrate_in` + answer (before the pause); header, vmstate, preload; commit
//! answer; held packets. The target pulls the rest via `pages`.
//! Ownership: the target commits (`STATE/migs/ID`) before the VM runs there.
//! The source resumes only on a refusal or `aborted` (never committed, or the
//! target died without every page), and exits only on `released`.

use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::hold::{self, Holder};
use crate::host::fault;
use crate::template::Template;
use crate::uffd::{Origin, Runs, Source};
use crate::util::{ms, recv_json, send_json, By, Error, Phases, Result};
use crate::vm::{Snapshot, State, Vm};
use crate::vmproc::{peer_call, End, Op, Proc};

/// From the target's prepare answer to its commit answer.
const INCOMING_WAIT: Duration = Duration::from_secs(30);
const MAX_VMSTATE: u64 = 64 << 20;
const MAX_PRELOAD: usize = 4096;
const MAX_HEADER: u64 = 256 << 20;
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);
const HOLD_FENCE: Duration = Duration::from_millis(250);
const HELD_STREAM: Duration = Duration::from_secs(2);
/// How long a same-host target's hold, let go, watches for a packet sent along the old route
/// (the VM runs meanwhile: no downtime).
const STRAGGLERS: Duration = Duration::from_millis(5);
/// How long migrating on waits for an arrival still pulling.
const ARRIVAL_WAIT: Duration = Duration::from_secs(10);

enum Outcome {
    Committed(Value),
    Aborted,
}

impl Proc {
    /// Everything not needing vmstate is prepared on the target before the
    /// pause. Once the target may have the state, this copy resumes only if
    /// the target says it aborted.
    /// `if_idle` (eviction): refused at once if the VM is busy or still arriving.
    /// `evict`: the host moves it for memory; the target admits it only above its own eviction mark.
    pub fn migrate(self: &Arc<Self>, to: &str, if_idle: bool, evict: bool) -> Result<Value> {
        let vm = self.vm().clone();
        let Some(source) = self.host.cfg.advertise()? else {
            bail!("this host runs no peer listener (flexvm listen): the target fetches the vm's memory through it");
        };
        let op = match if_idle {
            true => self.op_now().ok_or_else(|| format!("vm {}: {}", vm.name, crate::vmproc::BUSY))?,
            false => self.op_within()?,
        };
        if self.cmd.lock().unwrap().is_some() {
            match evict {
                true => bail!("vm {} runs a command here that its process ends with; {}", vm.name, crate::vmproc::BUSY),
                false => bail!("vm {} runs `run -- CMD`, which ends with its command here: it cannot migrate", vm.name),
            }
        }
        if if_idle && self.arrived.lock().unwrap().is_some() {
            bail!("vm {} is still arriving; {}", vm.name, crate::vmproc::BUSY);
        }
        self.settle_arrival(&op, ARRIVAL_WAIT)?;
        vm.template.verify(&self.paths, true)?;
        let settle = Instant::now();
        vm.settle_hotplug(settle + crate::lifecycle::SETTLE_WAIT)?;
        let settle = settle.elapsed();
        let (mig, gen, prep) = (migration_id(), self.gen(), Instant::now());
        let (mut conn, prepared) = self.prepare_target(&vm, to, mig, gen, &source, evict)?;
        let prepare = prep.elapsed();
        // Only now, right before the pause: the guest runs on at its mark meanwhile.
        let unthrottle = Instant::now();
        let _lifted = vm.limit.lift(vm.pid());
        let unthrottle = unthrottle.elapsed();
        let holder = self.holder().cloned();
        // Lent durably first: a crash with the outcome unknown must not hand the address out.
        self.lent_here.store(self.host.lend(&self.host.lock()?, vm.ip, gen)?, Ordering::SeqCst);
        self.drop_held_in();
        self.set_leaving(true);
        if let Err(e) = vm.leave(State::Source(mig)) {
            if self.lent_here.swap(false, Ordering::SeqCst) {
                let _ = self.host.unlend(&self.host.lock()?, vm.ip, gen);
            }
            self.set_leaving(false);
            return Err(e);
        }
        self.publish();
        if let Err(e) = vm.park_balloon() {
            return Err(self.abort(&op, &vm, mig, e));
        }
        let mut t = Phases::new();
        let vmstate = vm.dir.join("vmstate.out");
        let hold = || match holder.as_ref().map(|h| h.hold(vm.ip, mig)) {
            Some(Ok(())) => true,
            Some(Err(e)) => {
                eprintln!("vm {}: not holding packets during migration: {e}", vm.name);
                false
            }
            None => false,
        };
        let captured = (|| -> Result<_> {
            let saved = vm.save_state(&vmstate, false, false, hold, &mut t);
            if saved.is_err() {
                let _ = std::fs::remove_file(&vmstate);
            }
            let runs = saved?;
            let paused = t.total();
            let state = std::fs::read(&vmstate);
            let _ = std::fs::remove_file(&vmstate);
            let state = state?;
            t.mark("read_state");
            let mut wanted = crate::standby::load_set(&self.host, &vm.template);
            wanted.extend(serde_json::from_value::<Vec<u64>>(prepared["load_set"].clone()).unwrap_or_default());
            wanted.sort_unstable();
            wanted.dedup();
            let pages = crate::uffd::remote_among(&runs, wanted);
            let mut data = vec![0u8; pages.len() * crate::util::PAGE_SIZE];
            vm.pager.read_preload(&pages, &mut data)?;
            t.mark("read_preload");
            Ok((runs, paused, state, pages, data))
        })();
        let (runs, paused, state, pages, data) = match captured {
            Ok(c) => c,
            Err(e) => return Err(self.abort(&op, &vm, mig, e)),
        };
        let remote_pages: u64 = runs.iter().filter(|r| r.2 == crate::uffd::REMOTE).map(|r| r.1).sum();
        let sent = (|| -> Result<Value> {
            send_json(
                &mut conn,
                &json!({
                    "runs": runs,
                    "vmstate_len": state.len(),
                    "preload": pages,
                    "paused": vm.was_paused(),
                    "app_log": self.hold_app_log(),
                }),
            )?;
            conn.write_all(&state)?;
            if fault("slow_preload") {
                thread::sleep(Duration::from_millis(300));
            }
            conn.write_all(&data)?;
            t.mark("send_state");
            Ok(recv_json(&mut BufReader::new(By { s: &conn, at: Instant::now() + Duration::from_secs(30) }))?.ok_or("target hung up")?)
        })();
        let (target, answered) = match sent {
            Ok(reply) if reply["ok"] == json!(true) => (reply["result"].clone(), true),
            // A target refuses only before resuming the VM, or after killing it.
            Ok(reply) => return Err(self.abort(&op, &vm, mig, format!("target refused: {}", reply["error"]).into())),
            Err(e) => match outcome(to, mig, Duration::from_secs(2)) {
                Some(Outcome::Committed(target)) => (target, false),
                Some(Outcome::Aborted) => return Err(self.abort(&op, &vm, mig, e)),
                None => {
                    self.reconcile_later(mig, to.to_string());
                    bail!("migrating {} to {to}: {e}; {to} has not said whether it resumed the vm, so it stays paused here until it does", vm.name);
                }
            },
        };
        t.mark("target");
        let downtime = t.total();
        // A target that takes `SWITCH` says so (`hold_switch`); with any other, the hold switches as before.
        let (held, rerouted) = self.reroute(mig, to, &target, answered.then_some(&conn), prepared["hold_switch"] == true);
        t.mark("reroute");
        self.wait_release(mig, to.to_string());
        Ok(json!({
            "name": vm.name,
            "to": to,
            "mig": mig,
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

    fn prepare_target(&self, vm: &Vm, to: &str, mig: u64, gen: u64, source: &str, evict: bool) -> Result<(TcpStream, Value)> {
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
                "ip": vm.ip.to_string(),
                "gen": gen,
                "source": source,
                "source_ident": crate::host::Ident::me(),
                "rss_mib": vm.rss() >> 20,
                // Settled: the arrival's memory mark is sized by it without asking its Firecracker.
                "plugged_mib": vm.hotplug_plugged(),
                "regions": vm.pager.regions(),
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
        let l = match self.host.lock().and_then(|l| Ok((self.host.current(&l, vm.ip, gen)?, l))) {
            Ok((true, l)) => l,
            Ok((false, l)) => {
                drop(l);
                if let Some(h) = self.holder() {
                    h.forget(vm.ip, mig);
                }
                eprintln!("vm {}: {e}; generation {gen} of {} was superseded meanwhile, so it is destroyed instead of resumed", vm.name, vm.ip);
                self.finish(op, End::Gone, crate::vmproc::FAILED, None)
            }
            Err(r) => {
                vm.set_failed();
                self.publish();
                return format!("{e}; and whether its address went to another vm cannot be told ({r}), so it stays paused, failed").into();
            }
        };
        let attached = self.holder().is_some_and(|h| {
            let (stats, res) = release_into(h, vm.ip, mig, vm, Duration::ZERO, |()| crate::net::attach(vm.ip, &vm.tap));
            stats.is_some() && res.is_ok()
        });
        // It runs here again: so do the collapse pass and prefetch the save cut short.
        vm.pager.unquiesce();
        let (s, e) = match vm.resume(attached) {
            Ok(s) => (s, e),
            Err(r) => (State::Failed, format!("{e}; resuming it here failed too: {r}").into()),
        };
        if let Some(h) = self.holder() {
            h.forget(vm.ip, mig);
        }
        *vm.state.lock().unwrap() = s;
        self.release_app_log();
        if self.lent_here.swap(false, Ordering::SeqCst) {
            let _ = self.host.unlend(&l, vm.ip, gen);
        }
        drop(l);
        self.set_leaving(false);
        self.publish();
        if s == State::Running {
            self.sync_clock_later();
        }
        e
    }

    fn reconcile_later(self: &Arc<Self>, mig: u64, to: String) {
        let p = self.clone();
        thread::spawn(move || {
            let mut patience = Duration::from_secs(1);
            loop {
                match outcome(&to, mig, patience) {
                    Some(Outcome::Committed(target)) => {
                        eprintln!("vm {}: migration {mig} to {to} committed", p.name());
                        let _ = p.reroute(mig, &to, &target, None, false);
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
        eprintln!("vm {}: {e}; now {}", vm.name, vm.state().name());
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
                        p.abort_later(mig, &format!("{to} lost the vm before it had all its memory; it runs here again, from the pause"));
                        return p.announce();
                    }
                    _ => thread::sleep(delay),
                }
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            if let Some(via) = p.pending_route.lock().unwrap().take() {
                if let Err(e) = p.switch_route(via) {
                    eprintln!("route {} via {via}: {e}; giving up", p.vm().ip);
                }
            }
            let op = p.op();
            let _ = peer_call(&to, json!({"op": "migration", "mig": mig, "done": true}));
            p.finish(&op, End::Moved(to), 0, None)
        });
    }

    /// A failed route is retried in the background: the target owns the VM either way.
    fn reroute(&self, mig: u64, to: &str, target: &Value, conn: Option<&TcpStream>, switch: bool) -> (Option<hold::Stats>, Result<()>) {
        let ip = self.vm().ip;
        let Some(via) = target["underlay"].as_str().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
            if let Some(h) = self.holder() {
                h.forget(ip, mig);
            }
            return (None, Err("target sent no underlay".into()));
        };
        let (mut held, mut res) = (None, None);
        if let Some(h) = self.holder().filter(|h| h.holding_for(ip, mig)) {
            match conn.map(|c| (c, hold::start(c))) {
                Some((c, Ok(seq))) => {
                    // Sharing our routes, the target takes the address over itself, after the held packets.
                    let handoff = switch && crate::net::is_local_addr(via).unwrap_or(false);
                    (held, res) = hold::send(h, ip, mig, c, seq, handoff, || self.switch_route(via)).map(|(s, r)| (Some(s), Some(r))).unwrap_or_default()
                }
                started => {
                    if let Some((_, Err(e))) = started {
                        eprintln!("vm {}: {to} did not take the held packets: {e}", self.name());
                    }
                    held = Some(h.forget(ip, mig));
                }
            }
        }
        let res = res.unwrap_or_else(|| self.switch_route(via));
        if let (Err(e), Some(p)) = (&res, self.arc()) {
            eprintln!("route {ip} via {via}: {e}; retrying");
            *self.pending_route.lock().unwrap() = Some(via);
            thread::spawn(move || {
                let mut delay = Duration::from_millis(100);
                for _ in 0..10 {
                    thread::sleep(delay);
                    match p.switch_route(via) {
                        Ok(()) => {
                            p.pending_route.lock().unwrap().take();
                            return eprintln!("route {ip} via {via}: done");
                        }
                        Err(e) => eprintln!("route {ip} via {via}: {e}"),
                    }
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            });
        }
        (held, res)
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

    /// Under the host lock, so a later claim of the address routes after.
    fn switch_route(&self, via: Ipv4Addr) -> Result<()> {
        let (ip, gen, l) = (self.vm().ip, self.gen(), self.host.lock()?);
        if self.host.holder(&l, ip)?.is_some_and(|h| h != self.name()) || !self.host.current(&l, ip, gen)? {
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
        let prepared = match self.prepare_in(req, mig, &mut prep) {
            Ok(p) => p,
            Err(e) => {
                send_json(&mut w, &json!({"ok": false, "error": e.to_string()}))?;
                return Err(e);
            }
        };
        send_json(&mut w, &json!({"ok": true, "result": {"timings_ms": prep.json(), "load_set": prepared.4, "hold_switch": true}}))?;
        let deadline = Instant::now() + if fault("short_incoming") { Duration::from_secs(2) } else { INCOMING_WAIT };
        let mut r = BufReader::new(By { s: w.try_clone()?, at: deadline });
        let pager = prepared.0.pager.clone();
        let res = thread::scope(|scope| -> Result<(Arc<Vm>, Value)> {
            let hdr = crate::util::recv_json_max(&mut r, MAX_HEADER)?.ok_or("source hung up before sending the vmstate")?;
            let mut t = Phases::new();
            let runs: Runs = serde_json::from_value(hdr["runs"].clone())?;
            *self.sizes.lock().unwrap() = Some(arrival_sizes(&runs, &prepared.0.template(), req["plugged_mib"].as_u64()));
            let state = read_vec(&mut r, hdr["vmstate_len"].as_u64().ok_or("missing vmstate_len")?, MAX_VMSTATE)?;
            t.mark("recv_state");
            let pages: Vec<u64> = serde_json::from_value(hdr["preload"].clone()).unwrap_or_default();
            if pages.len() > MAX_PRELOAD {
                bail!("{} pages to preload, more than {MAX_PRELOAD}", pages.len());
            }
            self.app_log.store(hdr["app_log"].as_u64().unwrap_or(0), Ordering::SeqCst);
            // Preload installed while Firecracker parses the state; all in, or no commit.
            let r = &mut r;
            let preload = scope.spawn(move || -> Result<Result<()>> {
                let data = read_vec(r, (pages.len() * crate::util::PAGE_SIZE) as u64, u64::MAX).map_err(|e| format!("receiving the preloaded pages: {e}"))?;
                Ok(pager.preload(&pages, &data, deadline).map(drop).map_err(|e| format!("preloading pages: {e}").into()))
            });
            let preloaded = move || preload.join().unwrap_or_else(|_| Err("preloading panicked".into()));
            let paused = hdr["paused"] == true;
            self.paused_by_request.store(paused, Ordering::SeqCst);
            let vm = self.take_in(prepared, runs, &state, paused, deadline, preloaded, &mut t)?;
            Ok((vm, t.json()))
        });
        let answer = |reply: Value| send_json(&mut By { s: &w, at: deadline }, &reply);
        let (vm, t) = match res {
            Ok(r) => r,
            Err(e) => {
                let _ = answer(json!({"ok": false, "error": e.to_string()}));
                return Err(e);
            }
        };
        self.serve_control();
        if fault("lost_ack") {
            let _ = w.shutdown(std::net::Shutdown::Both);
        } else {
            let _ = answer(json!({"ok": true, "result": {
                "underlay": self.host.cfg.underlay().map(|u| u.to_string()),
                "timings_ms": t,
                "resume_error": (vm.state() == State::Failed).then_some("resuming failed"),
            }}));
        }
        // Off the downtime: the source waits for the answer above to reroute.
        self.start_limit();
        if vm.state() == State::Running {
            self.sync_clock_later();
        }
        let revoked = Arc::new(Mutex::new(false));
        *self.held_in.lock().unwrap() = Some(revoked.clone());
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
            let (mut routed, mut holding) = (!shared, false);
            let mut take_over = || {
                if std::mem::replace(&mut routed, true) {
                    return;
                }
                let took = p.if_current(|| match holder.as_deref() {
                    Some(h) => vm.if_here(|| h.hold(vm.ip, mig)),
                    None => vm.route_here().map(|()| false),
                });
                match took {
                    Ok(Some(held)) => holding = held,
                    Ok(None) => eprintln!("vm {}: {} went to a newer vm; not taking it over", vm.name, vm.ip),
                    Err(e) => {
                        eprintln!("vm {}: taking over {}: {e}", vm.name, vm.ip);
                        routed = false;
                    }
                }
            };
            let fence = Instant::now();
            crate::host::stall("handoff_stall");
            if hold::wait_start(&mut r, (fence + HOLD_FENCE).min(deadline)) {
                if let Some(reported) = hold::receive(&mut r, vm.ip, &vm.tap, &revoked, (Instant::now() + HELD_STREAM).min(deadline), &mut take_over) {
                    vm.tap_drops_reported(reported);
                }
            } else {
                eprintln!("vm {}: no held packets from the source after {} ms", vm.name, ms(fence.elapsed()));
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
                    let plugged = if fault("no_plug") {
                        eprintln!("vm {}: injected fault: not plugging its tap", vm.name);
                        false
                    } else {
                        let (plugged, res) = crate::net::plug_tap(&vm.tap);
                        if let Err(e) = res {
                            eprintln!("vm {}: plugging its tap: {e}", vm.name);
                        }
                        plugged
                    };
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
                    let (plug_drops, unplugged) = match plugged {
                        true => crate::net::unplug_tap(&vm.tap),
                        false => (0, Ok(())),
                    };
                    if let Err(e) = unplugged {
                        eprintln!("vm {}: letting {}'s packets through its tap: {e}", vm.name, vm.ip);
                    }
                    if let Some(mut s) = released.filter(|_| current) {
                        s.dropped_target += plug_drops;
                        eprintln!("vm {}: let go of {} after {} ms, {} packets injected", vm.name, vm.ip, ms(start.elapsed()), s.injected);
                        if s.dropped + s.dropped_target > 0 {
                            eprintln!("vm {}: dropped {} of the packets held while taking {} over", vm.name, s.dropped + s.dropped_target, vm.ip);
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
                    eprintln!("vm {}: {} went to a newer vm; not routing it here", vm.name, vm.ip);
                }
                Err(e) => {
                    eprintln!("vm {}: routing {} to its tap: {e}; retrying", vm.name, vm.ip);
                    if let Some(h) = holder.as_deref() {
                        h.forget(vm.ip, mig);
                    }
                    let mut delay = Duration::from_millis(100);
                    for _ in 0..10 {
                        thread::sleep(delay);
                        match p.if_current(|| vm.route_here()) {
                            Ok(_) => break,
                            Err(e) => eprintln!("vm {}: routing {} to its tap: {e}", vm.name, vm.ip),
                        }
                        delay = (delay * 2).min(Duration::from_secs(5));
                    }
                }
            }
            p.held_in.lock().unwrap().take();
            p.announce();
        });
        let p = self.clone();
        let source = req["source"].as_str().unwrap_or("").to_string();
        thread::spawn(move || {
            let vm = p.vm().clone();
            vm.restore_devices();
            let start = Instant::now();
            p.wait_pulled(&vm);
            eprintln!("vm {}: pull from {source} ended after {} ms", vm.name, ms(start.elapsed()));
            // Unless an operation settled it first, or the VM ended (its source's
            // copy runs again). `op` is let go between tries, for a kill.
            loop {
                let op = p.op();
                match p.settle_arrival(&op, Duration::ZERO) {
                    Err(e) if p.pulled_all() => eprintln!("{e}"),
                    _ => return,
                }
                drop(op);
                thread::sleep(Duration::from_secs(1));
            }
        });
        Ok(())
    }

    fn prepare_in(&self, req: &Value, mig: u64, t: &mut Phases) -> Result<(crate::vm::Prepared, Ipv4Addr, Source, String, Vec<u64>)> {
        let name = req["name"].as_str().ok_or("missing name")?.to_string();
        let regions = serde_json::from_value::<Vec<_>>(req["regions"].clone()).map_err(|e| format!("bad regions: {e}"))?;
        if regions.is_empty() {
            bail!("the source sent no memory regions");
        }
        let source = Source { addr: req["source"].as_str().ok_or("missing source")?.into(), vm: name.clone(), mig, regions };
        self.set_name(self.host.take_name(&name, false)?);
        let by = serde_json::from_value(req["source_ident"].clone()).ok();
        let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
        // Before the record (fsynced) and the claim: a refusal leaves nothing to undo.
        let floor = if req["evict"] == true { crate::host::Floor::EvictMark } else { crate::host::Floor::Reserve };
        self.admit_start(req["rss_mib"].as_u64().unwrap_or(0), None, floor)?;
        *self.arrived.lock().unwrap() = Some(self.host.mig_begin(mig, &source.addr, by, Some(ip))?);
        let tpl = Template::open_id(&self.paths, req["template"].as_str().ok_or("missing template")?, req["id"].as_str().ok_or("missing template id")?)?;
        t.mark("template");
        let claim = self.host.claim_incoming(&self.host.lock()?, &name, ip, req["gen"].as_u64().unwrap_or(0))?;
        self.set_addr(claim);
        t.mark("claim_ip");
        let idle = self.spawner.take(None)?;
        crate::host::stall("incoming_stall");
        t.mark("spawn");
        let load_set = crate::standby::load_set(&self.host, &tpl);
        let vm = Vm::prepare(idle, tpl, t)?;
        // All of routing the address here but the route itself, which waits for the commit.
        crate::net::neighbour(ip, &vm.firecracker().tap)?;
        t.mark("neighbour");
        if shares_routes(&source.addr) {
            // Ready before the source pauses: it takes the address over from the source's hold.
            self.holder();
            t.mark("holder");
        }
        if vm.prepare_load()? {
            t.mark("prepare_load");
        }
        if fault("prepare_fail") {
            bail!("injected fault: preparing failed");
        }
        Ok((vm, ip, source, name, load_set))
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
            prepared.pager.tail_fail.store(1, Ordering::SeqCst);
        }
        if fault("fetch_enomem_stuck") {
            // Late enough for the load (and the resume) to get their pages.
            *prepared.pager.stuck_from.lock().unwrap() = Some(Instant::now() + Duration::from_millis(500));
        }
        // A retry first drains the preload off the connection (the source still serves those pages).
        let seed = Some((runs, Origin::Peer(source.clone())));
        let retry = || before_commit.take().unwrap()().map(drop);
        // Routed here at the commit (sharing the source's routes, after the held packets):
        // until then the route back to the source stays, whatever happens to this arrival.
        let shared = shares_routes(&source.addr);
        let restored = prepared.unrouted().load(&self.spawner, &name, Snapshot::Bytes(state), seed, ip, paused, Some(deadline), retry, t);
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
                // The ownership boundary (refused if fenced).
                let l = self.host.lock()?;
                if Instant::now() >= deadline {
                    bail!("the migration ran past its deadline");
                }
                if !self.host.current(&l, ip, self.gen())? {
                    bail!("generation {} of {ip} was withdrawn or superseded meanwhile", self.gen());
                }
                // A failed commit takes the tap, and this route, with it; `finish` puts the peer's back.
                if !shared {
                    crate::net::route_dev(true, ip, crate::net::ifindex(&vm.tap)?)?;
                    t.mark("route");
                }
                self.arrived.lock().unwrap().as_mut().ok_or("no migration record")?.commit(&l)?;
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
                eprintln!("vm {name}: resuming after migration {} failed: {e}", source.mig);
                vm.set_failed();
            }
            t.mark("resume");
        }
        drop(committed);
        self.publish();
        Ok(vm)
    }
}

/// An arrival's (MiB to page in, guest size) from what its source sent: the
/// pages it pulls, and its boot memory plus what is plugged (all of the
/// hotplug region from a source that does not say).
fn arrival_sizes(runs: &Runs, tpl: &Template, plugged: Option<u64>) -> (u64, u64) {
    let remote: u64 = runs.iter().filter(|r| r.2 == crate::uffd::REMOTE).map(|r| r.1).sum();
    let meta = &tpl.meta;
    ((remote * crate::util::PAGE_SIZE as u64) >> 20, meta.mem_mib + plugged.unwrap_or(meta.max_mib - meta.mem_mib).min(meta.max_mib - meta.mem_mib))
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
            eprintln!("vm {}: dropping held packets: {e}", vm.name);
            h.forget(ip, mig);
            return (None, Err(e));
        }
    };
    let Some((mut stats, switched)) = h.release_local(ip, mig, &mut |p| hold::valid(p, ip) && inj.send(p), || switch(()), linger) else {
        return (None, Ok(()));
    };
    if let Err(e) = &switched {
        h.forget(ip, mig);
        eprintln!("vm {}: routing {ip} back to its tap after injecting the held packets: {e}", vm.name);
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

fn read_vec(r: &mut impl Read, len: u64, max: u64) -> Result<Vec<u8>> {
    if len > max {
        bail!("{len} bytes, more than {max}");
    }
    let mut v = vec![0u8; len as usize];
    r.read_exact(&mut v)?;
    Ok(v)
}
