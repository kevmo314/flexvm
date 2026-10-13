//! Live migration between VM processes on two hosts, post-copy.
//!
//! One TCP connection, from the source VM process to the target's peer
//! listener, which hands it to a new VM process (`flexvm run --incoming`).
//! In order: `migrate_in` (the target gets ready before the source pauses)
//! and its answer; the source's header, vmstate and preloaded pages; the
//! target's answer once it committed and resumed the VM; the held packets.
//! The target then pulls the rest of the memory through the source host's
//! listener (`pages`), and records the migration released once it has it
//! all; the source, polling `migration` on the target's listener, exits then.
//!
//! Ownership: the target commits (`RUN/migs/ID`) before the VM may run
//! there; an id it has answered for as aborted can never commit. The
//! source resumes only on a refusal or an `aborted` answer, never otherwise.

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
use crate::util::{ms, recv_json, send_json, Error, Phases, Result};
use crate::vm::{State, Vm};
use crate::vmproc::{peer_call, Proc};

/// Longest a release of held packets into a VM here waits for those still on
/// their way (after an aborted migration).
const RELEASE_LOCAL: Duration = Duration::from_millis(100);
/// How long an incoming migration may take to send its vmstate.
const INCOMING_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest vmstate a migration target accepts.
const MAX_VMSTATE: u64 = 64 << 20;
/// Most pages a migration source may send along with the vmstate.
const MAX_PRELOAD: usize = 4096;
/// Largest header (page states) a migration source may send.
const MAX_HEADER: u64 = 256 << 20;
/// How long a migration source waits for the target's answer to the prepare request.
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a migration target waits for the first packet its source held
/// before announcing the VM anyway.
const HOLD_FENCE: Duration = Duration::from_millis(250);
/// Longest a target spends taking in held packets.
const HELD_STREAM: Duration = Duration::from_secs(2);

/// How a migration ended on its target, as seen by the source.
enum Outcome {
    Committed(Value),
    Aborted,
}

impl Proc {
    /// Live-migrates the VM to the host whose listener is at `to`.
    ///
    /// Everything that does not need the vmstate happens before the pause:
    /// the target checks the template, takes the name and address, and sets
    /// up a Firecracker with its pager, over the connection that then carries
    /// the state. The downtime is the snapshot, the transfer and the target's
    /// load. Once the target may have the state, this copy is resumed only
    /// if the target says the migration aborted.
    pub fn migrate(self: &Arc<Self>, to: &str) -> Result<Value> {
        let vm = self.vm().clone();
        let Some(source) = self.host.cfg.listen.clone() else {
            bail!("this host runs no peer listener (flexvm listen): the target fetches the vm's memory through it");
        };
        let _op = self.op()?;
        // Before pausing, so a template mismatch costs no downtime.
        vm.template.verify(&self.paths, true)?;
        let settle = Instant::now();
        vm.settle_hotplug(settle + crate::lifecycle::SETTLE_WAIT)?;
        let settle = settle.elapsed();
        let mig = migration_id();
        let gen = self.gen.load(Ordering::SeqCst);
        let prep = Instant::now();
        let (mut conn, mut reader, prepared) = self.prepare_target(&vm, to, mig, gen, &source)?;
        let prepare = prep.elapsed();
        // The hold device exists before the pause.
        let holder = self.holder().cloned();
        // Durably lent before the target can have the VM: a crash with the
        // outcome unknown must not hand the address out. Undone only once
        // this copy is known to stay (`abort`).
        {
            let l = self.host.lock()?;
            self.host.lend(&l, vm.ip, gen)?;
        }
        // Its previous source can no longer send it held packets.
        self.drop_held_in();
        self.set_leaving(true);
        if let Err(e) = vm.start_source(mig) {
            self.unlend(&vm, gen);
            self.set_leaving(false);
            return Err(e);
        }
        self.publish();
        if let Err(e) = vm.park_balloon() {
            return Err(self.abort(&vm, mig, e));
        }
        let mut t = Phases::new();
        let vmstate = vm.dir.join("vmstate.out");
        let hold = || {
            if let Some(Err(e)) = holder.as_ref().map(|h| h.hold(vm.ip, mig)) {
                eprintln!("vm {}: not holding packets during migration: {e}", vm.name);
            }
        };
        let captured = (|| -> Result<_> {
            let runs = vm.save_state(&vmstate, false, false, hold, &mut t)?;
            let paused = t.total();
            let state = std::fs::read(&vmstate)?;
            t.mark("read_state");
            // The pages the target's load will touch, so it need not fetch
            // them one round trip at a time (see `Template::load_set`).
            let mut wanted = crate::standby::load_set(&self.host, &vm.template);
            if let Ok(theirs) = serde_json::from_value::<Vec<u64>>(prepared["load_set"].clone()) {
                wanted.extend(theirs);
                wanted.sort_unstable();
                wanted.dedup();
            }
            let pages = crate::uffd::remote_among(&runs, wanted);
            let mut data = vec![0u8; pages.len() * crate::util::PAGE_SIZE];
            for (page, buf) in pages.iter().zip(data.chunks_exact_mut(crate::util::PAGE_SIZE)) {
                vm.pager.read_guest(page * crate::util::PAGE_SIZE as u64, buf)?;
            }
            t.mark("read_preload");
            Ok((runs, paused, state, (pages, data)))
        })();
        let (runs, paused, state, (pages, data)) = match captured {
            Ok(c) => c,
            // Dropping the connection makes the target give up too.
            Err(e) => return Err(self.abort(&vm, mig, e)),
        };
        let remote_pages: u64 = runs.iter().filter(|r| r.2 == crate::uffd::REMOTE).map(|r| r.1).sum();
        let sent = (|| -> Result<Value> {
            send_json(&mut conn, &json!({
                "runs": runs,
                "vmstate_len": state.len(),
                "preload": pages,
                // A paused VM stays paused on the target, which pulls its pages before it ever runs.
                "paused": vm.was_paused(),
                "app_log": self.app_log.load(Ordering::SeqCst),
            }))?;
            conn.write_all(&state)?;
            if fault("slow_preload") {
                thread::sleep(Duration::from_millis(300));
            }
            conn.write_all(&data)?;
            t.mark("send_state");
            Ok(recv_json(&mut reader)?.ok_or("target hung up")?)
        })();
        let (target, answered) = match sent {
            Ok(reply) if reply["ok"] == json!(true) => (reply["result"].clone(), true),
            // A target only refuses before it resumes the VM, or after killing it.
            Ok(reply) => return Err(self.abort(&vm, mig, format!("target refused: {}", reply["error"]).into())),
            Err(e) => match outcome(to, mig, Duration::from_secs(2)) {
                Some(Outcome::Committed(target)) => (target, false),
                Some(Outcome::Aborted) => return Err(self.abort(&vm, mig, e)),
                None => {
                    self.reconcile_later(mig, to.to_string());
                    bail!("migrating {} to {to}: {e}; {to} has not said whether it resumed the vm, so it stays paused here until it does", vm.name);
                }
            },
        };
        t.mark("target");
        let downtime = t.total();
        // The target owns the VM now; this copy only serves its memory. The
        // packets held meanwhile follow on the migration connection.
        let (held, rerouted) = self.reroute(mig, to, &target, answered.then_some(&conn));
        t.mark("reroute");
        self.wait_release(mig, to.to_string());
        Ok(json!({
            "name": vm.name,
            "to": to,
            "mig": mig,
            "settle_hotplug_ms": ms(settle),
            "prepare_ms": ms(prepare),
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

    /// Asks `to` to get ready to take the VM in as migration `mig`. Returns
    /// the connection to send the state over, a reader for the target's
    /// answer, and what it said. A target that cannot take the VM refuses
    /// here, before anything happened to it.
    fn prepare_target(&self, vm: &Vm, to: &str, mig: u64, gen: u64, source: &str) -> Result<(TcpStream, BufReader<TcpStream>, Value)> {
        let conn = crate::util::connect(to, Duration::from_secs(2))?;
        conn.set_nodelay(true)?;
        conn.set_read_timeout(Some(PREFLIGHT_TIMEOUT))?;
        conn.set_write_timeout(Some(PREFLIGHT_TIMEOUT))?;
        let mut reader = BufReader::new(conn.try_clone()?);
        let mut w = &conn;
        send_json(&mut w, &json!({
            "op": "migrate_in",
            "name": vm.name,
            "mig": mig,
            "template": vm.template.name,
            "id": vm.template.meta.id,
            "ip": vm.ip.to_string(),
            "gen": gen,
            "source": source,
            "rss_mib": vm.rss() >> 20,
            "regions": vm.pager.regions(),
        }))?;
        let reply = recv_json(&mut reader)?.ok_or_else(|| format!("{to} hung up"))?;
        if reply["ok"] != json!(true) {
            let e = reply["error"].as_str().unwrap_or("no reason given");
            bail!("{to} cannot take vm {}: {e}", vm.name);
        }
        // A target that hangs leaves the outcome to `outcome`.
        conn.set_read_timeout(Some(Duration::from_secs(30)))?;
        conn.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok((conn, reader, reply["result"].clone()))
    }

    fn unlend(&self, vm: &Vm, gen: u64) {
        if let Ok(l) = self.host.lock() {
            let _ = self.host.unlend(&l, vm.ip, gen);
        }
    }

    /// Resumes this copy after migration `mig` failed without the target
    /// ever owning the VM. Returns the error to report.
    fn abort(&self, vm: &Arc<Vm>, mig: u64, e: Error) -> Error {
        if *vm.state.lock().unwrap() != State::Source(mig) {
            return e;
        }
        // A newer generation of its address recorded meanwhile means the
        // address went to another VM: this copy must not run again.
        let gen = self.gen.load(Ordering::SeqCst);
        if !self.host.lock().is_ok_and(|l| self.host.current(&l, vm.ip, gen)) {
            if let Some(h) = self.holder() {
                h.forget(vm.ip, mig);
            }
            self.set_leaving(true);
            vm.kill();
            if let Ok(l) = self.host.lock() {
                let _ = self.host.release(&l, vm.ip, &vm.name);
            }
            if let Some(p) = self.arc() {
                // Once the caller has answered.
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(200));
                    p.end(1)
                });
            }
            return format!("{e}; generation {gen} of {} was superseded meanwhile, so the vm was destroyed instead of resumed", vm.ip).into();
        }
        // Packets held meanwhile go into the tap first: Firecracker reads
        // them once resumed, ahead of what the restored route brings.
        if let Some(h) = self.holder() {
            release_into(h, vm.ip, mig, vm, RELEASE_LOCAL, |()| crate::net::attach(vm.ip, &vm.tap));
        }
        let (s, e) = match vm.resume() {
            Ok(s) => (s, e),
            Err(r) => (State::Failed, format!("{e}; resuming it here failed too: {r}").into()),
        };
        if let Some(h) = self.holder() {
            h.forget(vm.ip, mig);
        }
        *vm.state.lock().unwrap() = s;
        self.unlend(vm, self.gen.load(Ordering::SeqCst));
        self.set_leaving(false);
        self.publish();
        if s == State::Running {
            self.sync_clock_later();
        }
        e
    }

    /// Keeps asking `to` how migration `mig` went, the VM paused here, until
    /// it says.
    fn reconcile_later(self: &Arc<Self>, mig: u64, to: String) {
        let p = self.clone();
        thread::spawn(move || {
            let vm = p.vm().clone();
            let mut patience = Duration::from_secs(1);
            loop {
                match outcome(&to, mig, patience) {
                    Some(Outcome::Committed(target)) => {
                        eprintln!("vm {}: migration {mig} to {to} committed", vm.name);
                        let _ = p.reroute(mig, &to, &target, None);
                        return p.wait_release(mig, to);
                    }
                    Some(Outcome::Aborted) => {
                        let _op = p.op();
                        let e = p.abort(&vm, mig, format!("migration {mig} to {to} aborted").into());
                        return eprintln!("vm {}: {e}; now {}", vm.name, vm.state().name());
                    }
                    None => patience = (patience * 2).min(Duration::from_secs(30)),
                }
            }
        });
    }

    /// Serves the VM's memory until the target of migration `mig` has all
    /// of it (or its VM is gone), then ends the process.
    fn wait_release(self: &Arc<Self>, mig: u64, to: String) {
        let p = self.clone();
        thread::spawn(move || {
            let mut delay = Duration::from_millis(20);
            loop {
                if let Ok(r) = peer_call(&to, json!({"op": "migration", "mig": mig})) {
                    if r["outcome"] == "released" {
                        break;
                    }
                }
                thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            // The route retries do not outlive the process: one last try.
            if let Some(via) = p.pending_route.lock().unwrap().take() {
                if let Err(e) = p.switch_route(via) {
                    eprintln!("route {} via {via}: {e}; giving up", p.vm().ip);
                }
            }
            let vm = p.vm();
            p.set_leaving(true);
            vm.kill();
            if let Ok(l) = p.host.lock() {
                let _ = p.host.release(&l, vm.ip, &vm.name);
            }
            let _ = std::fs::write(p.host.run.join("vms").join(format!("{}.moved", vm.name)), &to);
            eprintln!("vm {}: moved to {to}", vm.name);
            p.end(0);
        });
    }

    /// Sends the packets held for the VM to the target `to` of migration
    /// `mig` (on `conn`, the migration connection), pointing the route for
    /// its address at the target meanwhile. On failure retries the route in
    /// the background; the target owns the VM either way.
    fn reroute(&self, mig: u64, to: &str, target: &Value, conn: Option<&TcpStream>) -> (Option<hold::Stats>, Result<()>) {
        let vm = self.vm();
        let ip = vm.ip;
        let via: Ipv4Addr = match target["underlay"].as_str().and_then(|s| s.parse().ok()) {
            Some(via) => via,
            None => {
                if let Some(h) = self.holder() {
                    h.forget(ip, mig);
                }
                return (None, Err("target sent no underlay".into()));
            }
        };
        let mut held = None;
        let mut res = None;
        if let Some(h) = self.holder().filter(|h| h.holding_for(ip, mig)) {
            // Only on the migration connection, and only once the target has
            // accepted the stream is anything taken off the queue.
            match conn.map(hold::start) {
                Some(Ok(seq)) => {
                    if let Some((stats, r)) = hold::send(h, ip, mig, conn.unwrap(), seq, || self.switch_route(via)) {
                        held = Some(stats);
                        res = Some(r);
                    }
                }
                started => {
                    if let Some(Err(e)) = started {
                        eprintln!("vm {}: {to} did not take the held packets: {e}", vm.name);
                    }
                    held = Some(h.forget(ip, mig));
                }
            }
        }
        let res = res.unwrap_or_else(|| self.switch_route(via));
        if let Err(e) = &res {
            eprintln!("route {ip} via {via}: {e}; retrying");
            *self.pending_route.lock().unwrap() = Some(via);
            if let Some(p) = self.arc() {
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
        }
        (held, res)
    }

    /// Points the route for the VM's address at `via`, unless the address
    /// has gone to another VM here or a newer generation meanwhile. Under the
    /// host lock, so a VM claiming the address later routes it after this.
    fn switch_route(&self, via: Ipv4Addr) -> Result<()> {
        let vm = self.vm();
        let gen = self.gen.load(Ordering::SeqCst);
        let l = self.host.lock()?;
        if self.host.holder(&l, vm.ip).is_some_and(|h| h != vm.name) || !self.host.current(&l, vm.ip, gen) {
            return Ok(());
        }
        if fault("route") {
            bail!("injected fault: route_via failed");
        }
        crate::net::route_via(vm.ip, via)
    }

    /// The target of a migration (spawned by the peer listener with `conn`).
    /// First, before the source pauses: check the template, take the name
    /// and address, set up a Firecracker with its pager, answer. Then load
    /// the state the source sends, commit, resume, answer again. Nothing is
    /// left behind if it does not commit.
    pub fn migrate_in(self: &Arc<Self>, req: &Value, conn: TcpStream) -> Result<()> {
        let _ = conn.set_nodelay(true);
        let mut r = BufReader::new(conn.try_clone()?);
        let mut w = conn;
        let mig = req["mig"].as_u64().ok_or("missing mig")?;
        let mut prep = Phases::new();
        let prepared = self.prepare_in(req, mig, &mut prep);
        let prepared = match prepared {
            Ok(p) => p,
            Err(e) => {
                self.unwind_in(req, mig);
                send_json(&mut w, &json!({"ok": false, "error": e.to_string()}))?;
                return Err(e);
            }
        };
        let load_set = prepared.load_set.clone();
        if let Err(e) = send_json(&mut w, &json!({"ok": true, "result": {"timings_ms": prep.json(), "load_set": load_set}})) {
            self.unwind_in(req, mig);
            return Err(e.into());
        }
        // The vmstate follows once the source has paused. From here,
        // everything up to our answer is due by one deadline.
        let wait = if fault("short_incoming") { Duration::from_secs(2) } else { INCOMING_READ_TIMEOUT };
        let deadline = Instant::now() + wait;
        let mut br = ByDeadline { r: &mut r, at: deadline };
        let pager = prepared.vm.pager.clone();
        let res = thread::scope(|scope| -> Result<(Arc<Vm>, Value)> {
            let hdr = crate::util::recv_json_max(&mut br, MAX_HEADER)?.ok_or("source hung up before sending the vmstate")?;
            let mut t = Phases::new();
            let runs: Runs = serde_json::from_value(hdr["runs"].clone())?;
            let state = read_vec(&mut br, hdr["vmstate_len"].as_u64().ok_or("missing vmstate_len")?, MAX_VMSTATE)?;
            t.mark("recv_state");
            let pages: Vec<u64> = serde_json::from_value(hdr["preload"].clone()).unwrap_or_default();
            if pages.len() > MAX_PRELOAD {
                bail!("{} pages to preload, more than {MAX_PRELOAD}", pages.len());
            }
            self.app_log.store(hdr["app_log"].as_u64().unwrap_or(0), Ordering::SeqCst);
            // The pages the load touches follow the vmstate: received and
            // installed while Firecracker parses the state. All of them are
            // in, or the migration aborts, before it commits.
            let br = &mut br;
            let preload = scope.spawn(move || -> Result<Result<()>> {
                let len = (pages.len() * crate::util::PAGE_SIZE) as u64;
                let data = read_vec(br, len, u64::MAX).map_err(|e| format!("receiving the preloaded pages: {e}"))?;
                Ok(pager.preload(&pages, &data, deadline).map(drop).map_err(|e| format!("preloading pages: {e}").into()))
            });
            let preloaded = move || preload.join().unwrap_or_else(|_| Err("preloading panicked".into()));
            let paused = hdr["paused"].as_bool().unwrap_or(false);
            self.paused_by_request.store(paused, Ordering::SeqCst);
            let vm = self.take_in(prepared, runs, &state, paused, deadline, preloaded, &mut t)?;
            Ok((vm, t.json()))
        });
        let (vm, t) = match res {
            Ok(r) => r,
            Err(e) => {
                self.unwind_in(req, mig);
                let _ = w.try_clone().map_err(Error::from).and_then(|s| {
                    Ok(send_json(&mut crate::util::By { s, at: deadline }, &json!({"ok": false, "error": e.to_string()}))?)
                });
                return Err(e);
            }
        };
        self.serve_control();
        let reply = json!({"ok": true, "result": {
            "underlay": self.host.cfg.underlay().map(|u| u.to_string()),
            "timings_ms": t,
            "resume_error": (vm.state() == State::Failed).then_some("resuming failed"),
        }});
        // Committed, but the source never hears about it.
        if fault("lost_ack") {
            let _ = w.shutdown(std::net::Shutdown::Both);
        } else if let Ok(s) = w.try_clone() {
            // A missed deadline leaves a committed migration committed (the source asks).
            let _ = send_json(&mut crate::util::By { s, at: deadline }, &reply);
        }
        // The held packets follow the answer on the same connection; then
        // the VM is announced.
        if vm.state() == State::Running {
            self.sync_clock_later();
        }
        let revoked = Arc::new(Mutex::new(false));
        *self.held_in.lock().unwrap() = Some(revoked.clone());
        let p = self.clone();
        thread::spawn(move || {
            let fence = Instant::now();
            if hold::wait_start(&mut r, (fence + HOLD_FENCE).min(deadline)) {
                hold::receive(&mut r, vm.ip, &vm.tap, &revoked, (Instant::now() + HELD_STREAM).min(deadline));
            } else {
                eprintln!("vm {}: no held packets from the source after {} ms", vm.name, ms(fence.elapsed()));
            }
            p.held_in.lock().unwrap().take();
            p.announce();
        });
        // Once every page has arrived the source may let go of its copy.
        let p = self.clone();
        let source = req["source"].as_str().unwrap_or("").to_string();
        thread::spawn(move || {
            let vm = p.vm().clone();
            vm.restore_devices();
            let start = Instant::now();
            vm.pager.wait_pulled();
            eprintln!("vm {}: pull from {source} ended after {} ms", vm.name, ms(start.elapsed()));
            if vm.pager.failed().is_none() {
                if let Some(mig) = p.arrived.lock().unwrap().take() {
                    let _ = p.host.mig_set(mig, "released");
                }
            }
        });
        Ok(())
    }

    /// Gives back what a migration that did not commit took here.
    fn unwind_in(&self, req: &Value, mig: u64) {
        let _ = self.host.mig_set(mig, "aborted");
        self.arrived.lock().unwrap().take();
        if let (Some(ip), Some(name)) = (req["ip"].as_str().and_then(|s| s.parse().ok()), req["name"].as_str()) {
            if let Ok(l) = self.host.lock() {
                let _ = self.host.release(&l, ip, name);
            }
        }
    }

    /// The part of taking a VM in that needs no vmstate.
    fn prepare_in(&self, req: &Value, mig: u64, t: &mut Phases) -> Result<PreparedIn> {
        let name = req["name"].as_str().ok_or("missing name")?.to_string();
        let source = Source {
            addr: req["source"].as_str().ok_or("missing source")?.into(),
            vm: name.clone(),
            mig,
            regions: serde_json::from_value(req["regions"].clone()).map_err(|e| format!("bad regions: {e}"))?,
        };
        if source.regions.is_empty() {
            bail!("the source sent no memory regions");
        }
        self.set_name(self.host.take_name(&name, false)?);
        self.host.mig_begin(mig)?;
        *self.arrived.lock().unwrap() = Some(mig);
        // Room for it: what it uses at the source, above the reserve.
        let need = req["rss_mib"].as_u64().unwrap_or(0);
        let avail = crate::vmproc::host_available_mib();
        if avail < self.host.cfg.reserve_mib + need {
            bail!("not enough memory here: {avail} MiB available, {need} MiB needed above the {} MiB reserve", self.host.cfg.reserve_mib);
        }
        let tpl = migration_template(&self.paths, req)?;
        t.mark("template");
        let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
        let gen = req["gen"].as_u64().unwrap_or(0);
        {
            let l = self.host.lock()?;
            self.host.claim_incoming(&l, &name, ip, gen)?;
        }
        self.gen.store(gen, Ordering::SeqCst);
        t.mark("claim_ip");
        let idle = self.pool.take()?;
        t.mark("pool_take");
        let load_set = crate::standby::load_set(&self.host, &tpl);
        let vm = Vm::prepare(idle, tpl, t)?;
        if vm.prepare_load()? {
            t.mark("prepare_load");
        }
        if fault("prepare_fail") {
            bail!("injected fault: preparing failed");
        }
        Ok(PreparedIn { vm, ip, source, name, load_set })
    }

    /// Loads the VM held, runs every check that can still abort (the source's
    /// page server, the pager, `before_commit`, `deadline`), commits, then
    /// resumes it.
    #[allow(clippy::too_many_arguments)]
    fn take_in(
        &self,
        p: PreparedIn,
        runs: Runs,
        state: &[u8],
        paused: bool,
        deadline: Instant,
        before_commit: impl FnOnce() -> Result<Result<()>>,
        t: &mut Phases,
    ) -> Result<Arc<Vm>> {
        let PreparedIn { vm: mut prepared, ip, source, name, .. } = p;
        let mut before_commit = Some(before_commit);
        // Is the source's page server there? Asked alongside the load: a VM
        // whose memory cannot come must not be committed here.
        let probe = runs.iter().find(|r| r.2 == crate::uffd::REMOTE).map(|r| {
            let source = source.clone();
            let page = r.0;
            thread::spawn(move || crate::uffd::probe(&source, page, deadline))
        });
        let (tpl, runs_again) = (prepared.template(), runs.clone());
        if fault("kill_prepared") {
            // Dead, and its pager has seen it go: the load fails at once, and
            // the retry below takes over.
            prepared.kill_firecracker();
            prepared.pager.firecracker_gone();
        }
        prepared.pager.seed(runs, Origin::Peer(source.clone()))?;
        if prepared.pager.lost_pages() {
            bail!("its pager failed: {}", prepared.pager.failed().unwrap_or_default());
        }
        let vmstate = prepared.dir().join("vmstate.in");
        std::fs::write(&vmstate, state)?;
        t.mark("write_state");
        // Loaded with its vCPUs stopped: it must not run here before every
        // check that can still abort the migration has passed.
        let load = if paused { crate::vm::Load::Paused } else { crate::vm::Load::PausedUnheld };
        let restored = match prepared.load(&name, &vmstate, ip, load, true, Some(deadline), t) {
            // Once more on a fresh Firecracker (see `Retry`): the failed load
            // never ran the guest, and the source, paused, still serves every page.
            Err(e) if crate::vm::retry_of(&e).is_some() => (|| {
                let realtime = crate::vm::retry_of(&e) != Some(crate::vm::Retry::WithoutRealtime);
                eprintln!("vm {name}: loading it once more on a fresh firecracker{}", if realtime { "" } else { ", without clock_realtime" });
                let _ = before_commit.take().unwrap()()?;
                if Instant::now() >= deadline {
                    bail!("no time left to load it again");
                }
                let fresh = Vm::prepare(self.pool.take_by(Some(deadline))?, tpl, t)?;
                fresh.pager.seed(runs_again, Origin::Peer(source.clone()))?;
                let vmstate = fresh.dir().join("vmstate.in");
                std::fs::write(&vmstate, state)?;
                fresh.load(&name, &vmstate, ip, load, realtime, Some(deadline), t)
            })(),
            r => r,
        };
        let probed = probe.map_or(Ok(()), |p| p.join().unwrap_or_else(|_| Err(std::io::Error::other("probe panicked"))));
        let (vm, _restore) = restored.map_err(|e| format!("{e} (it never ran here)"))?;
        let checked = match (probed, vm.pager.failed()) {
            (Err(e), _) => Err(format!("migration source {} does not serve pages: {e}", source.addr).into()),
            (_, Some(why)) => Err(format!("its memory cannot be paged in: {why}").into()),
            _ => before_commit.take().map_or(Ok(Ok(())), |f| f()).and_then(|r| r).and_then(|()| -> Result<()> {
                // The ownership boundary: the generation is still current,
                // the deadline has not passed, and the migration record goes
                // from pending to committed (refused if the source's query
                // fenced it off). From here on this host owns the VM.
                let l = self.host.lock()?;
                if Instant::now() >= deadline {
                    bail!("the migration ran past its deadline");
                }
                self.host.commit_incoming(&l, ip, self.gen.load(Ordering::SeqCst))?;
                self.host.mig_set_locked(&l, source.mig, "committed")?;
                Ok(())
            }),
        };
        if let Err(e) = checked {
            // Never ran here: the source may resume its copy.
            vm.kill();
            return Err(format!("{e} (it never ran here)").into());
        }
        t.mark("register");
        self.set_vm(vm.clone());
        if !paused {
            match vm.start(fault("resume_kill")) {
                Ok(()) => *vm.state.lock().unwrap() = State::Running,
                Err(e) => {
                    // It may have run: the migration stays committed.
                    eprintln!("vm {name}: resuming after migration {} failed: {e}", source.mig);
                    vm.set_failed();
                }
            }
            t.mark("resume");
        }
        self.publish();
        Ok(vm)
    }
}

/// An incoming migration set up before its source pauses. Dropping it
/// gives the Firecracker back.
struct PreparedIn {
    vm: crate::vm::Prepared,
    ip: Ipv4Addr,
    source: Source,
    name: String,
    load_set: Vec<u64>,
}

/// The local template matching a migration source's: the generation with
/// its content id, even if the name has moved on since.
fn migration_template(paths: &crate::template::Paths, req: &Value) -> Result<Arc<Template>> {
    let name = req["template"].as_str().ok_or("missing template")?;
    let id = req["id"].as_str().ok_or("missing template id")?;
    let tpl = match Template::generation(paths, id) {
        Some(dir) => Template::open_dir(name, dir)?,
        None => Template::open(paths, name)?,
    };
    tpl.check_id(id)?;
    tpl.verify(paths, true)?;
    Ok(tpl)
}

/// Asks `to` how migration `mig` went, for up to `patience`. None if it
/// would not say.
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

/// Injects what migration (or checkpoint) `mig` held for `ip` into `vm`'s
/// tap (brought up for it), calls `switch`, and injects what was still on
/// its way, waiting at most `within` (see `Holder::release_local`). If the
/// switch fails, that is logged and the address stays held until the
/// caller `forget`s it.
pub fn release_into(h: &Holder, ip: Ipv4Addr, mig: u64, vm: &Vm, within: Duration, switch: impl FnOnce(()) -> Result<()>) -> Option<hold::Stats> {
    if !h.holding_for(ip, mig) {
        return None;
    }
    let inj = crate::net::set_link_up(&vm.tap, true).and_then(|()| hold::Injector::new(&vm.tap));
    let inj = match inj {
        Ok(inj) => inj,
        Err(e) => {
            eprintln!("vm {}: dropping held packets: {e}", vm.name);
            h.forget(ip, mig);
            return None;
        }
    };
    let (mut stats, switched) = h.release_local(ip, mig, &mut |p| hold::valid(p, ip) && inj.send(p), || switch(()), within)?;
    if let Err(e) = switched {
        eprintln!("vm {}: routing {ip} back to its tap after injecting the held packets: {e}", vm.name);
    }
    stats.injected = stats.packets;
    stats.dropped_target = inj.dropped();
    // Closing a packet socket waits for an RCU grace period, which the VM,
    // still paused, need not wait for.
    thread::spawn(move || drop(inj));
    Some(stats)
}

/// A random id for a new migration (53 bits, so it survives any JSON parser).
pub fn migration_id() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    h.write_u32(std::process::id());
    h.finish() >> 11
}

/// A reader that fails once `at` has passed, however slowly the other end
/// trickles: each read waits at most for what is left.
struct ByDeadline<'a> {
    r: &'a mut BufReader<TcpStream>,
    at: Instant,
}

fn too_slow() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "migration source too slow")
}

fn timed_out(e: std::io::Error) -> std::io::Error {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => too_slow(),
        _ => e,
    }
}

impl ByDeadline<'_> {
    fn arm(&self) -> std::io::Result<()> {
        match self.at.saturating_duration_since(Instant::now()) {
            d if d.is_zero() => Err(too_slow()),
            d => self.r.get_ref().set_read_timeout(Some(d)),
        }
    }
}

impl Read for ByDeadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.r.read(buf).map_err(timed_out)
    }
}

impl std::io::BufRead for ByDeadline<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.arm()?;
        self.r.fill_buf().map_err(timed_out)
    }
    fn consume(&mut self, n: usize) {
        self.r.consume(n)
    }
}

/// Reads `len` bytes, refusing more than `max`.
fn read_vec(r: &mut impl Read, len: u64, max: u64) -> Result<Vec<u8>> {
    if len > max {
        bail!("{len} bytes, more than {max}");
    }
    let mut v = vec![0u8; len as usize];
    r.read_exact(&mut v)?;
    Ok(v)
}
