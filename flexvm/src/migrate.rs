//! Post-copy live migration over one TCP connection to the target's listener:
//! `template` (the template, unless the target has it) and `migrate_in` + answer (before the
//! pause); header, vmstate, preload; commit
//! answer; held packets. The target pulls the rest via `pages`.
//! Ownership: the target commits (`STATE/migs/ID`) before the VM runs there.
//! The source resumes only on a refusal or `aborted` (never committed, or the
//! target died without every page), and exits only on `released`.

use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
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
/// Test fault `long_preflight`: both sides' preflight deadlines (`PREFLIGHT_TIMEOUT`, `listen::PREPARE_WAIT`), and the
/// target's wait for its source after answering it (`INCOMING_WAIT`), this long instead, so a test parked in the
/// preflight (`incoming_gate`) or right after it (`leave_gate`) lets it go when it is done, not against them.
pub const LONG_PREFLIGHT: Duration = Duration::from_secs(300);
const HOLD_FENCE: Duration = Duration::from_millis(250);
const HELD_STREAM: Duration = Duration::from_secs(2);
/// How long a same-host target's hold, let go, watches for a packet sent along the old route
/// (the VM runs meanwhile: no downtime).
const STRAGGLERS: Duration = Duration::from_millis(5);
/// How long migrating on waits for an arrival still pulling.
const ARRIVAL_WAIT: Duration = Duration::from_secs(10);

/// What the source sends once paused, as one JSON line: the page states, then the vmstate's and the preloaded pages'
/// lengths (their bytes follow the line).
#[derive(Serialize)]
struct Header<'a> {
    runs: &'a [(u64, u64, u8)],
    vmstate_len: u64,
    preload: &'a [u64],
    paused: bool,
    app_log: u64,
}

/// A `Header` as the target reads it: no `Value` tree, which for a long `runs` would be many times the line's size, and
/// `runs` and `preload` left raw for `capped`, so an overlong one is refused at its cap, never decoded whole first.
#[derive(Deserialize)]
struct Incoming<'a> {
    #[serde(borrow)]
    runs: &'a RawValue,
    vmstate_len: u64,
    #[serde(borrow)]
    preload: &'a RawValue,
    paused: bool,
    app_log: u64,
}

impl Incoming<'_> {
    /// Its runs and preload list, refused as soon as either holds more than `regions` can (a run has a page at least,
    /// the preload `MAX_PRELOAD`) or falls out of order. `check_incoming` still checks the rest.
    fn decode(&self, regions: &[(u64, u64)]) -> Result<(Runs, Vec<u64>)> {
        let runs = capped(self.runs, guest_pages(regions), |a: &(u64, u64, u8), b| a.0.saturating_add(a.1) <= b.0);
        let preload = capped(self.preload, MAX_PRELOAD, |a: &u64, b| a < b);
        Ok((runs.map_err(|e| format!("runs: {e}"))?, preload.map_err(|e| format!("preload: {e}"))?))
    }
}

fn guest_pages(regions: &[(u64, u64)]) -> usize {
    regions.iter().map(|r| (r.1 / crate::util::PAGE_SIZE as u64) as usize).sum()
}

/// The longest header an honest source sends for `regions`: a run per page, and a full preload, at their longest numbers.
fn header_max(regions: &[(u64, u64)]) -> u64 {
    MAX_HEADER
        .min((guest_pages(regions) * "[18446744073709551615,18446744073709551615,255],".len() + MAX_PRELOAD * "18446744073709551615,".len() + 4096) as u64)
}

/// A JSON list of at most `max` items, each `after` the one before.
fn capped<T: de::DeserializeOwned>(raw: &RawValue, max: usize, after: fn(&T, &T) -> bool) -> serde_json::Result<Vec<T>> {
    struct List<T>(usize, fn(&T, &T) -> bool);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for List<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a list of at most {} items in order", self.0)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Vec<T>, A::Error> {
            let mut v: Vec<T> = Vec::new();
            while let Some(x) = seq.next_element()? {
                if v.len() == self.0 {
                    return Err(de::Error::custom(format!("more than {} items", self.0)));
                }
                if v.last().is_some_and(|l| !(self.1)(l, &x)) {
                    return Err(de::Error::custom(format!("item {} out of order", v.len())));
                }
                v.push(x);
            }
            Ok(v)
        }
    }
    de::Deserializer::deserialize_seq(&mut serde_json::Deserializer::from_str(raw.get()), List(max, after))
}

struct PreparedIn {
    vm: crate::vm::Prepared,
    ip: Ipv4Addr,
    source: Source,
    name: String,
    load_set: Vec<u64>,
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

/// Where migration `mig`'s target was reached: its connection's address, never `to` looked up again (#1117),
/// and who it answered the prepare as (`host_token`). Every question about the migration's outcome goes there,
/// and an answer from a host that is not that one (holding no record, it would say "aborted") is no answer.
/// Recorded here (`STATE/reached/MIG`) before the address is lent: after this source's death, the outcome it
/// then owes is asked the same way (`owed_outcome`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Reached {
    to: String,
    at: std::net::SocketAddr,
    /// None from an older target, which names no host: its answers from `at` are taken as they come.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    /// The source process: its record goes once it is gone and owes nothing (`Host::owes`).
    by: crate::host::Ident,
}

impl Reached {
    fn new(to: &str, conn: &TcpStream, prepared: &Value) -> Result<Self> {
        let token = prepared["token"].as_str().map(String::from);
        Ok(Self { to: to.into(), at: conn.peer_addr()?, token, by: crate::host::Ident::me() })
    }

    fn path(host: &crate::host::Host, mig: u64) -> std::path::PathBuf {
        host.state.join("reached").join(mig.to_string())
    }

    /// Durably, after letting go of those of sources that are gone and owe nothing.
    fn record(&self, host: &crate::host::Host, mig: u64) -> Result<()> {
        let dir = host.state.join("reached");
        crate::util::create_dir_durably(&dir, 0o700)?;
        let l = host.lock()?;
        // Read once, under the lock, for the first gone source only: what `forget_unless_owed` asks of each.
        let owing = std::cell::OnceCell::new();
        for e in std::fs::read_dir(&dir)?.flatten() {
            let Some(id) = e.file_name().to_str().and_then(|n| n.parse::<u64>().ok()) else { continue };
            if let Ok(Some(r)) = crate::host::load::<Reached>(&e.path()) {
                if r.by.liveness() == crate::host::Liveness::Gone
                    && owing.get_or_init(|| host.owing_sources(&l)).as_ref().is_some_and(|sources: &Vec<_>| !sources.contains(&r.by))
                {
                    Self::forget(host, id);
                }
            }
        }
        drop(l);
        crate::host::store(&Self::path(host, mig), self, true)
    }

    /// Removes `mig`'s record unless its source `by` still owes an outcome here: an owed record, or a claim still
    /// leaving. Under the host lock (`_l`), which `withdraw_dead` holds while it turns the one into the other.
    fn forget_unless_owed(_l: &crate::host::Locked, host: &crate::host::Host, mig: u64, by: &crate::host::Ident) {
        if !host.owes(by) {
            Self::forget(host, mig);
        }
    }

    /// A migration given up before the pause: its record goes once its loan and leaving are undone.
    fn give_up(&self, host: &crate::host::Host, mig: u64) {
        if let Ok(l) = host.lock() {
            Self::forget_unless_owed(&l, host, mig, &self.by);
        }
    }

    /// Unreadable is an error: never a lookup of the name instead.
    fn load(host: &crate::host::Host, mig: u64) -> Result<Option<Self>> {
        crate::host::load(&Self::path(host, mig))
    }

    fn forget(host: &crate::host::Host, mig: u64) {
        let _ = std::fs::remove_file(Self::path(host, mig));
    }

    /// The target's answer about `mig`: an error, never an outcome, from a host that is not it.
    fn ask(&self, mig: u64, wait: bool) -> Result<Value> {
        let ask = |wait| peer_query(&self.at.to_string(), self.token.as_deref(), json!({"op": "migration", "mig": mig, "wait": wait}));
        ask(wait).or_else(|e| if wait { ask(false) } else { Err(e) })
    }

    fn done(&self, mig: u64) {
        let _ = peer_call(&self.at.to_string(), json!({"op": "migration", "mig": mig, "done": true}));
    }
}

/// A migration peer's answer is evidence only when it names the recorded host.
fn peer_query(at: &str, token: Option<&str>, req: Value) -> Result<Value> {
    let r = peer_call(at, req)?;
    if token.is_some_and(|t| r["token"].as_str() != Some(t)) {
        bail!("{at} is not the recorded migration peer: it answers as {}", r["token"]);
    }
    Ok(r)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceReply {
    Gone,
    Keep,
    Mismatch,
}

pub(crate) fn source_gone(source: &str, token: Option<&str>, peer: Option<IpAddr>, by: &crate::host::Ident) -> Result<SourceReply> {
    let (conn, r) = crate::util::rpc(source, Duration::from_millis(500), Instant::now() + Duration::from_secs(2), &json!({"op": "source", "ident": by}))?;
    Ok(source_reply(token, peer, conn.peer_addr().ok().map(|a| a.ip()), &r))
}

fn source_reply(token: Option<&str>, peer: Option<IpAddr>, connected: Option<IpAddr>, r: &Value) -> SourceReply {
    // A missing token (an older peer) is doubt, not evidence of a different host.
    if token.zip(r["token"].as_str()).is_some_and(|(expected, actual)| expected != actual) {
        SourceReply::Mismatch
    } else if source_reply_gone(token, peer, connected, r) {
        SourceReply::Gone
    } else {
        SourceReply::Keep
    }
}

fn source_reply_gone(token: Option<&str>, peer: Option<IpAddr>, connected: Option<IpAddr>, r: &Value) -> bool {
    // Before host tokens were kept, only the recorded connection peer can vouch for the source.
    let same = match token {
        Some(token) => r["token"].as_str() == Some(token),
        None => peer.is_some_and(|p| connected.is_some_and(|a| a.to_canonical() == p.to_canonical())),
    };
    // Identity doubt belongs to this record, not every record at the address.
    same && r["gone"] == true
}

/// The outcome of migration `mig` to `to`, owed since its source here died (`Host::settle_owed`): asked where
/// the source reached its target. Only a record from before they were kept asks `to` by name.
pub(crate) fn owed_outcome(host: &crate::host::Host, to: &str, mig: u64) -> Result<String> {
    let r = match Reached::load(host, mig)? {
        Some(reached) => reached.ask(mig, false)?,
        None => peer_query(to, None, json!({"op": "migration", "mig": mig}))?,
    };
    Ok(r["outcome"].as_str().unwrap_or_default().to_string())
}

/// Tells the target of an owed migration that this host is done with its record.
pub(crate) fn owed_done(host: &crate::host::Host, to: &str, mig: u64, deadline: Instant) {
    match Reached::load(host, mig) {
        Ok(Some(reached)) => {
            if done(&reached.at.to_string(), mig, deadline) {
                Reached::forget(host, mig);
            }
        }
        _ => {
            done(to, mig, deadline);
        }
    }
}

/// Best effort: only an explicit BUSY is retried. Older peers use the same error text;
/// failure leaves the target's record for retirement to prove the source gone.
fn done(at: &str, mig: u64, deadline: Instant) -> bool {
    retry_done(
        deadline,
        |rpc_deadline| crate::util::rpc(at, Duration::from_millis(500), rpc_deadline, &json!({"op": "migration", "mig": mig, "done": true})).map(|(_, r)| r),
        thread::sleep,
        Instant::now,
    )
}

fn retry_done(deadline: Instant, mut call: impl FnMut(Instant) -> Result<Value>, mut nap: impl FnMut(Duration), now: impl Fn() -> Instant) -> bool {
    let mut delay = Duration::from_millis(100);
    for attempt in 0..10 {
        let at = now();
        if attempt > 0 && at >= deadline {
            return false;
        }
        // Every record gets one full attempt, even after slow outcome queries spend the shared budget.
        let rpc_deadline = at + Duration::from_secs(2);
        let Err(e) = call(if attempt == 0 { rpc_deadline } else { rpc_deadline.min(deadline) }) else { return true };
        let why = e.to_string();
        if attempt == 9 || !(why == crate::listen::BUSY || why.ends_with(&format!(": {}", crate::listen::BUSY))) {
            return false;
        }
        let remaining = deadline.saturating_duration_since(now());
        if delay >= remaining {
            return false;
        }
        nap(delay);
        delay = (delay * 2).min(Duration::from_secs(5));
    }
    false
}

/// This host's migration identity: random, kept in `STATE/token` from the first prepare it sends or
/// answers (`create`) on, so a restarted listener answers as the same host. None if there is none yet.
pub(crate) fn host_token(host: &crate::host::Host, create: bool) -> Result<Option<String>> {
    let path = host.state.join("token");
    if let Some(t) = crate::host::load::<String>(&path)? {
        return Ok(Some(t));
    }
    if !create {
        return Ok(None);
    }
    // Linked in, never renamed over: two first prepares at once both answer with the one that won.
    let tmp = host.state.join(format!(".token.{}.tmp", crate::util::random_hex(8)?));
    let linked = crate::host::store(&tmp, &crate::util::random_hex(16)?, true).map(|()| std::fs::hard_link(&tmp, &path));
    let _ = std::fs::remove_file(&tmp);
    match linked? {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e.into()),
        _ => crate::util::sync_dir(&host.state)?,
    }
    crate::host::load::<String>(&path)?.map(Some).ok_or_else(|| "this host's token vanished".into())
}

/// The source's regions, before anything is sized by them: never more memory than a VM of the template has, its
/// boot memory and hotplug region (`max_mib`).
fn check_regions(regions: &[(u64, u64)], max_mib: u64) -> Result<()> {
    let total = regions.iter().try_fold(0u64, |t, r| t.checked_add(r.1)).ok_or("memory regions too large")?;
    if total > max_mib << 20 {
        bail!("the source's memory regions add up to {} MiB, more than the template's {max_mib} MiB", total >> 20);
    }
    Ok(())
}

impl Proc {
    /// Releases held packets back to the VM's tap, returning stats and whether the route was attached.
    pub(crate) fn release_to_tap(&self, vm: &Vm, id: u64) -> (Option<hold::Stats>, bool) {
        let Some(h) = self.holder() else { return (None, false) };
        let (stats, res) = release_into(h, vm.ip, id, vm, Duration::ZERO, |()| crate::net::attach(vm.ip, &vm.tap));
        (stats, stats.is_some() && res.is_ok())
    }

    /// Waits out the arrival's packet hand-off (`held_in`): its injections, link-up and route changes must not
    /// overlap a migration onward, its hold or its device snapshot (#1028). Bounded (the hand-off is, by its
    /// stream's deadline and its route retries); `if_idle` (eviction) refuses at once instead.
    pub(crate) fn settle_handoff(&self, if_idle: bool) -> Result<()> {
        let deadline = Instant::now() + ARRIVAL_WAIT;
        while self.held_in.lock().unwrap().is_some() {
            if if_idle {
                return Err(Busy(format!("vm {} is still receiving its held packets; {BUSY}", self.name())).into());
            }
            self.not_destroyed()?;
            if Instant::now() >= deadline {
                bail!("vm {} is still receiving its held packets; try again once it has", self.name());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
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
        let refused = || -> Result<()> {
            if self.cmd.lock().unwrap().is_some() {
                match evict {
                    true => return Err(Busy(format!("vm {} runs a command here that its process ends with; {BUSY}", vm.name)).into()),
                    false => bail!("vm {} runs `run -- CMD`, which ends with its command here: it cannot migrate", vm.name),
                }
            }
            if if_idle && self.arrived.lock().unwrap().is_some() {
                return Err(Busy(format!("vm {} is still arriving; {BUSY}", vm.name)).into());
            }
            Ok(())
        };
        // What refuses it below, at once: not after a push of minutes.
        if if_idle && self.op_now().is_none() {
            return Err(Busy(format!("vm {}: {BUSY}", vm.name)).into());
        }
        refused()?;
        vm.template.verify(&self.paths)?;
        // Before the op lock: however long the push takes, the VM is resized, checkpointed or evicted meanwhile (#824).
        // Still before the pause.
        let pushed = push_template(to, &vm.template, false)?;
        if pushed.is_none() && !vm.template.names_rootfs_by_path()? {
            bail!("{to} runs flexvm v0.1.0, which cannot load template {} (built since): upgrade it first", vm.template.meta.id);
        }
        let op = match if_idle {
            true => self.op_now().ok_or_else(|| Busy(format!("vm {}: {BUSY}", vm.name)))?,
            false => self.op_within()?,
        };
        refused()?;
        self.settle_arrival(&op, ARRIVAL_WAIT)?;
        self.settle_handoff(if_idle)?;
        vm.can_leave()?;
        let settle = Instant::now();
        vm.settle_hotplug(settle + crate::lifecycle::SETTLE_WAIT)?;
        let settle = settle.elapsed();
        // Asked again right before the prepare, which opens it there: still there, the same files, and held
        // again for `listen::PUSH_HOLD`.
        if pushed.is_some() {
            push_template(to, &vm.template, true)?;
        }
        let (mig, gen, prep) = (migration_id(), self.gen(), Instant::now());
        let vouched = pushed.as_ref().map_or(Value::Null, |p| p.1.clone());
        let (conn, prepared) = self.prepare_target(&vm, to, mig, gen, &source, evict, vouched).map_err(|e| match &pushed {
            None if missing_template(&e) => {
                format!("{e} ({to} is too old to be sent template {}: it migrates in only VMs of templates it has)", vm.template.meta.id).into()
            }
            _ => e,
        })?;
        // Before the pause: dropped, the connection ends the target's arrival.
        check_app_support(to, &vm.name.get(), &prepared, &self.spec.lock().unwrap().moving(), vm.template.meta.image.as_ref())?;
        let reached = Reached::new(to, &conn, &prepared)?;
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
        // Before the loan: its owed outcome, should this process die, is asked there too.
        reached.record(&self.host, mig)?;
        // Lent durably first: a crash with the outcome unknown must not hand the address out.
        // With where the target was reached: only it moves or withdraws the generation here meanwhile (#914).
        let at = target_at(&self.host.config_now(), to, Some(reached.at.ip()));
        let lent = match self.host.lock().and_then(|l| self.host.lend_at(&l, vm.ip, gen, mig, to, &at)) {
            Ok(lent) => lent,
            Err(e) => {
                reached.give_up(&self.host, mig);
                return Err(e);
            }
        };
        self.lent_here.fetch_or(lent, Ordering::SeqCst);
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
            // Kept while its claim still says leaving.
            reached.give_up(&self.host, mig);
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
                runs: &runs,
                vmstate_len: state.len() as u64,
                preload: &pages,
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
                match outcome(&reached, mig, Duration::from_secs(2)) {
                    Some(Outcome::Committed(target)) => (target, None),
                    Some(Outcome::Aborted) => return Err(self.abort(&op, &vm, mig, e)),
                    None => {
                        self.reconcile_later(mig, reached);
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
        self.wait_release(mig, reached);
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
            Instant::now() + if fault("long_preflight") { LONG_PREFLIGHT } else { PREFLIGHT_TIMEOUT },
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
                "source_token": host_token(&self.host, true)?,
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
                // This network namespace's, which the target compares with its own: the same, it shares our routes.
                "netns": crate::net::netns_id(),
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
            Ok(()) => {
                self.lent_here.store(false, Ordering::SeqCst);
                // Nothing is owed for it now.
                Reached::forget(&self.host, mig);
            }
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
    fn reconcile_later(self: &Arc<Self>, mig: u64, reached: Reached) {
        let to = reached.to.clone();
        self.reconciling(mig, &to);
        let p = self.clone();
        thread::spawn(move || {
            let mut patience = Duration::from_secs(1);
            loop {
                let o = outcome(&reached, mig, patience);
                if o.is_some() && !p.known(mig) {
                    return;
                }
                match o {
                    Some(Outcome::Committed(target)) => {
                        crate::info!("vm {}: migration {mig} to {to} committed", p.name());
                        if let (_, Err(e)) = p.reroute(mig, &to, &target, None) {
                            crate::log!("vm {}: migration {mig} to {to}: rerouting failed: {e}", p.name());
                        }
                        return p.wait_release(mig, reached);
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
    /// Asked where the migration reached it (`Reached`).
    fn wait_release(self: &Arc<Self>, mig: u64, reached: Reached) {
        let p = self.clone();
        let to = reached.to.clone();
        thread::spawn(move || {
            let mut delay = Duration::from_millis(20);
            loop {
                match reached.ask(mig, true) {
                    Ok(r) if r["outcome"] == "released" => break,
                    Ok(r) if r["outcome"] == "aborted" => {
                        return p.abort_later(mig, &format!("{to} lost the vm before it had all its memory; it runs here again, from the pause"));
                    }
                    // A target that waited (`listen::migration`) is asked again at once.
                    Ok(r) if r["waited"] == true => delay = Duration::from_millis(20),
                    // An older one answers at once, without waiting: polled with backoff, as before.
                    _ => {
                        thread::sleep(delay);
                        delay = (delay * 2).min(Duration::from_secs(5));
                    }
                }
            }
            // One last try, never a retry loop: until `finish` the source stays unkillable, keeps its
            // name, claim and paused Firecracker, and a migration back here waits. `retry_route` already
            // retried in the background while the target pulled.
            let mut abandoned = false;
            if let Some(mut route) = p.take_pending_route(mig) {
                if let Err(e) = route.resolve(&p.host).and_then(|via| p.switch_route(mig, via)) {
                    abandoned = true;
                    crate::log!("route {} to {}: {e}; giving up", p.vm().ip, route.to);
                }
            }
            let op = p.op();
            // Decided here durably first: once the target forgets its record, the
            // migration would read as aborted there.
            match p.host.lock().and_then(|l| {
                p.host.release(&l, p.vm().ip, &p.vm().name.get(), Some(&crate::host::Ident::me()))?;
                if abandoned {
                    // The target's announcement was saved while our source still held the route.
                    if let Err(e) = p.host.reinstall(&l, p.vm().ip, None) {
                        crate::log!("route {}: reinstall after release: {e}", p.vm().ip);
                    }
                }
                Ok(())
            }) {
                Ok(()) => {
                    reached.done(mig);
                    Reached::forget(&p.host, mig);
                }
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
                    // As the target decided it from our connection (#1028); an older target's, by its underlay.
                    let handoff = target["shares_routes"].as_bool().unwrap_or_else(|| crate::net::is_local_addr(via).unwrap_or(false));
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
        // Whether the source shares this host's routes: by the network namespace it says it is in, else (an older
        // source) by where its connection actually comes from (not the address it advertises, which may be a name).
        // Decided once, for the hold, the commit's route and the hand-off, and told the source with the commit (#1028).
        let from = w.peer_addr()?.ip();
        let shared = shares_routes(req["netns"].as_str(), crate::net::netns_id().as_deref(), from);
        // Which host this is, for the source's questions about the outcome (`Reached`).
        let prepared = match self.prepare_in(req, mig, from, shared, &mut prep, by, &going).and_then(|p| Ok((p, host_token(&self.host, true)?))) {
            Ok((p, token)) => (p, token),
            Err(e) => {
                send_json(&mut w, &json!({"ok": false, "error": e.to_string()}))?;
                return Err(e);
            }
        };
        // `follows_app`: this side takes the VM's run settings (`spec`) and follows its app; `attaches`: -i and -t too.
        let (prepared, token) = prepared;
        let result =
            json!({"timings_ms": prep.json(), "load_set": prepared.load_set, "hold_switch2": true, "follows_app": true, "attaches": true, "token": token});
        send_json(&mut w, &json!({"ok": true, "result": result}))?;
        let deadline = Instant::now()
            + match () {
                _ if fault("short_incoming") => Duration::from_secs(2),
                _ if fault("long_preflight") => LONG_PREFLIGHT,
                _ => INCOMING_WAIT,
            };
        let mut r = BufReader::new(By { s: w.try_clone()?, at: deadline });
        let pager = prepared.vm.pager.clone();
        // Bytes the source has declared and this side not yet read, at most what it may send: a refusal drains them.
        let owed = &std::sync::atomic::AtomicU64::new(arrival_owed(u64::MAX, usize::MAX));
        // Set before the commit adopts the VM, so no operation run from then on (a migration onward, a checkpoint)
        // misses the hand-off below: it waits for it to end (`settle_handoff`, #1028).
        let revoked = Arc::new(Mutex::new(false));
        *self.held_in.lock().unwrap() = Some(revoked.clone());
        let res = thread::scope(|scope| -> Result<(Arc<Vm>, Value)> {
            // A copy: `prepared` goes to `take_in`.
            let regions = &prepared.source.regions.clone();
            let line = crate::util::recv_line_max(&mut r, header_max(regions))?.ok_or("source hung up before sending the vmstate")?;
            let hdr: Incoming = serde_json::from_str(&line)?;
            let (runs, pages) = hdr.decode(regions).map_err(|e| format!("bad migration header: {e}"))?;
            owed.store(arrival_owed(hdr.vmstate_len, pages.len()), Ordering::SeqCst);
            let preload_len = (pages.len() * crate::util::PAGE_SIZE) as u64;
            let mut t = Phases::new();
            // Before anything counts or walks them: a bad page index would otherwise overflow, or hang the preload.
            crate::uffd::check_incoming(&runs, &pages, regions).map_err(|e| format!("bad migration header: {e}"))?;
            let sizes = arrival_sizes(&runs, &prepared.vm.template(), req["plugged_mib"].as_u64());
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
            let vm = self.take_in(prepared, shared, runs, &state, paused, deadline, preloaded, &mut t)?;
            Ok((vm, t.json()))
        });
        let answer = |reply: Value| send_json(&mut By { s: &w, at: deadline }, &reply);
        let (vm, t) = match res {
            Ok(r) => r,
            Err(e) => {
                self.held_in.lock().unwrap().take();
                refuse_arrival(&w, &mut r, &json!({"ok": false, "error": e.to_string()}), owed.load(Ordering::SeqCst), deadline);
                return Err(e);
            }
        };
        if tripped("lost_ack") {
            let _ = w.shutdown(std::net::Shutdown::Both);
        } else {
            let _ = answer(json!({"ok": true, "result": {
                // On the downtime: never a lookup (the process's start made any it needed).
                "underlay": self.host.config_now().underlay_known().map(|u| u.to_string()),
                "timings_ms": t,
                "resume_error": (vm.state() == State::Failed).then_some("resuming failed"),
                // Whether the source hands the address over to this side's route (`reroute`).
                "shares_routes": shared,
            }}));
        }
        // Off the downtime: the source waits for the answer above to reroute.
        self.start_limit();
        if vm.state() == State::Running {
            self.sync_clock_later();
        }
        let p = self.clone();
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

    #[allow(clippy::too_many_arguments)]
    fn prepare_in(
        &self,
        req: &Value,
        mig: u64,
        from: std::net::IpAddr,
        shared: bool,
        t: &mut Phases,
        until: Instant,
        going: &dyn Fn() -> Result<()>,
    ) -> Result<PreparedIn> {
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
        self.set_name(self.host.take_arriving_name(&name)?);
        // Bound before the prepare is answered (#593, as a resume's): failing, the source never
        // pauses. Until the VM is adopted, the socket says it is starting; an abort's `finish`
        // unlinks it with the name.
        self.serve_control()?;
        let by = serde_json::from_value(req["source_ident"].clone()).ok();
        let tpl = Template::open_id(&self.paths, req["template"].as_str().ok_or("missing template")?, req["id"].as_str().ok_or("missing template id")?)?;
        // One received from a peer only for a source with the same files: its content id proves none.
        tpl.check_vouched(serde_json::from_value(req["template_digests"].clone()).ok().as_ref(), "this source (a v0.1.0 one cannot)")?;
        // Before the header and its runs are sized by them.
        check_regions(&source.regions, tpl.meta.max_mib)?;
        // Its caps move with it (the same template: they fit).
        // Refused before the source pauses: a capped VM never runs uncapped here.
        self.keep_resources(serde_json::from_value(req["resources"].clone()).unwrap_or_default())?;
        // Its forwards stayed on the source, as host-local proxies.
        *self.spec.lock().unwrap() = serde_json::from_value::<crate::app::RunSpec>(req["spec"].clone()).unwrap_or_default().moving();
        t.mark("template");
        going()?;
        // Admission, then the record and the claim, each giving up in time. Admitted before the lock is taken: a
        // refusal waits for VM processes without the host lock, which a guard held here would keep.
        let late = |e: Error| -> Error {
            match e.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) {
                true => format!("not admitted within {} s: {e}", crate::listen::PREPARE_WAIT.as_secs()).into(),
                false => e,
            }
        };
        // Before the record (fsynced) and the claim: a refusal leaves nothing to undo. Never past the guest's size.
        self.admit_start(req["rss_mib"].as_u64().unwrap_or(0).min(tpl.meta.max_mib), None, arrival_floor(req), Some(until)).map_err(late)?;
        let l = self.host.lock_by(Some(until)).map_err(late)?;
        *self.arrived.lock().unwrap() = Some(self.host.mig_begin_from(mig, &source.addr, by, Some(ip), Some(from))?.with_token(req["source_token"].as_str()));
        // The source's next revision: past it, its resume after an abort outranks this location.
        let rev = req["rev"].as_u64().ok_or("missing rev")?.saturating_add(1);
        let gen = req["gen"].as_u64().unwrap_or(0);
        // Not a generation newer than the record's where no peer can have one (#914).
        self.host.newer_gen(&self.host.addr(&l, ip)?, ip, gen)?;
        let claim = self.host.claim_arrival(&l, &name, ip, gen, rev, mig)?;
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
        if shared {
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
        Ok(PreparedIn { vm: vm.unrouted(ifindex), ip, source, name, load_set })
    }

    /// Every check that can still abort runs before the commit; the host lock
    /// is held from the commit through the resume.
    #[allow(clippy::too_many_arguments)]
    fn take_in(
        &self,
        PreparedIn { vm: prepared, ip, source, name, .. }: PreparedIn,
        shared: bool,
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
        // Committed: what a VM of the name that moved away left goes (kept for an abort until now).
        if let Err(e) = self.host.arrived(&name) {
            crate::log!("vm {name}: clearing what the vm that moved away from here left: {e}");
        }
        self.publish();
        Ok(vm)
    }
}

/// Has `to` take generation `tpl`, by content id, before anything else of a migration (so before the
/// pause): sent unless it has it. Returns its timings and, for a copy `to` received from a peer, the
/// digests this host vouches for it with (`template::digests`), which the arrival checks. None if `to`
/// is too old to be sent one (then it must have it). With `only_ask`, nothing is sent: an error unless `to`
/// has it still (the check right before the prepare, which refreshes its hold there).
pub(crate) fn push_template(to: &str, tpl: &Template, only_ask: bool) -> Result<Option<(Value, Value)>> {
    use crate::listen::{ANSWER_WAIT, PUSH_GRACE, PUSH_RATE, TURN_WAIT};
    let start = Instant::now();
    let fail = |e: Error| -> Error { format!("cannot send template {} to {to}: {e}", tpl.meta.id).into() };
    // Before the request: once answered, the target holds the generation only so long (`listen::PUSH_HOLD`).
    let ours = json!(tpl.digests()?);
    let sending = match only_ask {
        true => None,
        false => Some(crate::template::Sending::new(tpl).map_err(fail)?),
    };
    let req = match &sending {
        None => json!({"op": "template", "id": tpl.meta.id, "have": true}),
        Some(s) => json!({"op": "template", "id": tpl.meta.id, "ack": true, "bytes": s.len()}),
    };
    // A push's first answer may wait for another arrival's receive of it (`listen::TURN_WAIT`); a question's
    // waits for nothing, and is asked holding the op lock.
    let wait = if only_ask { ASK_WAIT } else { TURN_WAIT + ANSWER_WAIT };
    let (conn, mut reply) = match crate::util::rpc(to, Duration::from_secs(2), Instant::now() + wait, &req) {
        Err(e) if e.to_string().contains("unknown op \"template\"") => return Ok(None),
        r => r.map_err(fail)?,
    };
    let mut sent = 0;
    if reply["have"] != json!(true) {
        let Some(sending) = sending else {
            bail!("{to} no longer has template {}, sent to it for this migration (removed there meanwhile?); try again", tpl.meta.id);
        };
        let read = |at| crate::util::recv_json(&mut BufReader::new(By { s: &conn, at })).and_then(|r| crate::util::answer(r, to, "refused")).map_err(fail);
        let mut w = std::io::BufWriter::with_capacity(1 << 20, crate::util::Paced::new(&conn, PUSH_GRACE, PUSH_RATE));
        let n = match reply["ack"] == true {
            // Its metadata answered first: what the target refuses (room, limits, Firecracker), it refuses before the data.
            true => {
                let meta = sending.write_meta(&mut w);
                read(Instant::now() + ANSWER_WAIT)?;
                meta.map_err(fail)?;
                sending.write_files(&mut w)
            }
            false => sending.write(&mut w),
        };
        // Its answer says more than a failed write: it may have refused the template part way. It publishes it
        // within the pace of its bytes again (it syncs them).
        let moved = w.get_ref().moved;
        reply = read(Instant::now() + PUSH_GRACE + Duration::from_secs(moved / PUSH_RATE))?;
        sent = n.map_err(fail)?;
    }
    let digests = if reply["digests"].is_null() { Value::Null } else { ours };
    if digests != reply["digests"] {
        bail!("{to} has a copy of template {} received from a peer whose files differ from this host's: remove it there (flexvm rmi {0})", tpl.meta.id);
    }
    Ok(Some((json!({"sent_mib": sent >> 20, "ms": ms(start.elapsed())}), digests)))
}

/// How long `push_template`'s question (`only_ask`) waits for its answer.
const ASK_WAIT: Duration = Duration::from_secs(10);

/// Whether a target's refusal of an arrival says it has no such template (one too old to be sent it, `push_template`):
/// by name (`Template::resolve`) or with another build under it (`Template::check_id`), as v0.1.0 words them.
fn missing_template(e: &Error) -> bool {
    let e = e.to_string();
    e.contains("no image ") || e.contains(" id mismatch: local ")
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

/// The target's authority comes from its connection and its own configured underlays.
fn target_at(cfg: &crate::host::Config, to: &str, peer: Option<IpAddr>) -> Vec<IpAddr> {
    peer.into_iter().chain(cfg.underlays_of(to).iter().copied().map(IpAddr::V4)).collect()
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

/// Whether a peer is in this network namespace, routes and all: its namespace's identity (`net::netns_id`) is
/// `ours`; or, either unknown, its connection comes from `from`, one of this namespace's addresses (IPv4, IPv6 or
/// IPv4-mapped).
fn shares_routes(theirs: Option<&str>, ours: Option<&str>, from: IpAddr) -> bool {
    match (theirs, ours) {
        (Some(theirs), Some(ours)) => theirs == ours,
        _ => crate::net::is_local_ip(from).unwrap_or(false),
    }
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

fn outcome(reached: &Reached, mig: u64, patience: Duration) -> Option<Outcome> {
    let start = Instant::now();
    loop {
        if let Ok(r) = reached.ask(mig, false) {
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
            return (Some(h.forget(ip, mig)), Err(e));
        }
    };
    let Some((mut stats, switched)) = h.release_local(ip, mig, &mut |p| hold::valid(p, ip) && inj.send(p), || switch(()), linger) else {
        return (None, Ok(()));
    };
    if let Err(e) = &switched {
        stats.dropped += h.forget(ip, mig).dropped;
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
    fn done_retries_only_busy_with_bounded_backoff() {
        let now = Instant::now();
        for busy in [crate::listen::BUSY.to_string(), format!("127.0.0.1:7070: {}", crate::listen::BUSY)] {
            let (mut calls, mut naps) = (0, vec![]);
            retry_done(
                now + Duration::from_secs(60),
                |_| {
                    calls += 1;
                    if calls < 3 {
                        Err(busy.clone().into())
                    } else {
                        Ok(json!({"done": true}))
                    }
                },
                |d| naps.push(d),
                || now,
            );
            assert_eq!(calls, 3);
            assert_eq!(naps, [Duration::from_millis(100), Duration::from_millis(200)]);
        }
        let (mut calls, mut naps) = (0, vec![]);
        retry_done(
            now + Duration::from_secs(60),
            |_| {
                calls += 1;
                Err(crate::listen::BUSY.into())
            },
            |d| naps.push(d),
            || now,
        );
        assert_eq!(calls, 10);
        assert_eq!(naps.iter().map(Duration::as_millis).collect::<Vec<_>>(), [100, 200, 400, 800, 1600, 3200, 5000, 5000, 5000]);
        for error in ["peer hung up", "unknown op", "not the source", "host busy, try again later"] {
            let mut calls = 0;
            retry_done(
                now + Duration::from_secs(60),
                |_| {
                    calls += 1;
                    Err(error.into())
                },
                |_| panic!("non-BUSY must not be retried"),
                || now,
            );
            assert_eq!(calls, 1);
        }
        // An older target's successful reply need not have any new fields.
        retry_done(now + Duration::from_secs(60), |_| Ok(Value::Null), |_| panic!("success must not be retried"), || now);
    }

    #[test]
    fn done_retries_share_a_deadline_across_records_and_count_rpc_time() {
        let now = std::cell::Cell::new(Instant::now());
        let deadline = now.get() + Duration::from_secs(5);
        let mut calls = 0;
        for _ in 0..5 {
            assert!(!retry_done(
                deadline,
                |rpc_deadline| {
                    calls += 1;
                    now.set(rpc_deadline);
                    Err(crate::listen::BUSY.into())
                },
                |d| now.set(now.get() + d),
                || now.get(),
            ));
        }
        assert_eq!(calls, 7);
        assert_eq!(now.get(), deadline + Duration::from_secs(8));
    }

    #[test]
    fn done_after_slow_outcomes_gets_one_full_attempt_per_record() {
        let start = Instant::now();
        let now = std::cell::Cell::new(start);
        let deadline = start + Duration::from_secs(5);
        let mut calls = 0;
        for record in 0..5 {
            // Later records are released only after slow queries spend the shared budget.
            now.set(now.get() + Duration::from_secs(2));
            let done = retry_done(
                deadline,
                |rpc_deadline| {
                    calls += 1;
                    assert_eq!(rpc_deadline, now.get() + Duration::from_secs(2));
                    if record == 0 {
                        Ok(Value::Null)
                    } else {
                        now.set(rpc_deadline);
                        Err(crate::listen::BUSY.into())
                    }
                },
                |_| panic!("spent shared budget must not retry"),
                || now.get(),
            );
            assert_eq!(done, record == 0);
        }
        assert_eq!(calls, 5);
        assert_eq!(now.get(), start + Duration::from_secs(18));
    }

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

    /// Decided by the namespaces' identities, else by the connection's numeric address (#1028): any of this
    /// namespace's, IPv4, IPv6 or mapped.
    #[test]
    fn shares_routes_by_namespace_else_the_connections_address() {
        use std::net::Ipv6Addr;
        for local in ["127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"] {
            assert!(shares_routes(None, None, local.parse().unwrap()), "{local}");
        }
        for remote in ["192.0.2.7", "::ffff:192.0.2.7", "2001:db8::7", "0.0.0.0", "::"] {
            assert!(!shares_routes(None, None, remote.parse().unwrap()), "{remote}");
        }
        // Every address an interface here has, native IPv6 included (not only loopback).
        let mut addrs = std::ptr::null_mut();
        assert_eq!(unsafe { libc::getifaddrs(&mut addrs) }, 0);
        let (mut current, mut seen) = (addrs, Vec::<IpAddr>::new());
        while !current.is_null() {
            let a = unsafe { &*current };
            if !a.ifa_addr.is_null() {
                match unsafe { (*a.ifa_addr).sa_family } as i32 {
                    libc::AF_INET => seen.push(Ipv4Addr::from(unsafe { &*a.ifa_addr.cast::<libc::sockaddr_in>() }.sin_addr.s_addr.to_ne_bytes()).into()),
                    libc::AF_INET6 => seen.push(Ipv6Addr::from(unsafe { &*a.ifa_addr.cast::<libc::sockaddr_in6>() }.sin6_addr.s6_addr).into()),
                    _ => {}
                }
            }
            current = a.ifa_next;
        }
        unsafe { libc::freeifaddrs(addrs) };
        for ip in seen {
            assert!(shares_routes(None, None, ip), "{ip}");
            if let IpAddr::V4(v4) = ip {
                assert!(shares_routes(None, None, v4.to_ipv6_mapped().into()), "{ip} mapped");
            }
        }
        // Namespace identities decide when both are known: a hairpin-NATed peer here looks remote by its address, and
        // a namespace's address can show up as a peer's in another.
        let ours = crate::net::netns_id().expect("this namespace's identity");
        assert_eq!(crate::net::netns_id().as_deref(), Some(ours.as_str()));
        assert!(shares_routes(Some(&ours), Some(&ours), "192.0.2.7".parse().unwrap()));
        assert!(!shares_routes(Some("other:0:1"), Some(&ours), "127.0.0.1".parse().unwrap()));
        assert!(shares_routes(Some("other:0:1"), None, "127.0.0.1".parse().unwrap()));
        assert!(!shares_routes(None, Some(&ours), "192.0.2.7".parse().unwrap()));
        // Another namespace (where this test may make one) has another identity.
        let other = thread::spawn(|| (unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0).then(crate::net::netns_id)).join().unwrap();
        if let Some(other) = other {
            assert!(other.is_some() && other.as_deref() != Some(ours.as_str()), "{other:?} {ours}");
        }
        // A connection's actual peer address, over loopback in either family.
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(l) = std::net::TcpListener::bind(bind) else { continue };
            let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
            let (s, _) = l.accept().unwrap();
            assert_eq!(s.peer_addr().unwrap(), c.local_addr().unwrap());
            assert!(shares_routes(None, None, s.peer_addr().unwrap().ip()), "{bind}");
        }
    }

    #[test]
    fn leaving_target_authority_uses_only_its_configured_underlays() {
        let mut cfg = crate::host::Config { peers: vec!["target:7070".into(), "other:7070".into()], ..Default::default() };
        cfg.peer_underlays.insert("target:7070".into(), vec!["192.0.2.7".parse().unwrap()]);
        cfg.peer_underlays.insert("other:7070".into(), vec!["192.0.2.8".parse().unwrap()]);
        let peer = "2001:db8::7".parse().unwrap();
        assert_eq!(target_at(&cfg, "target:7070", Some(peer)), vec![peer, "192.0.2.7".parse().unwrap()]);
        assert_eq!(target_at(&cfg, "unconfigured:7070", Some(peer)), vec![peer]);
        assert_eq!(target_at(&cfg, "target:7070", None), vec!["192.0.2.7".parse::<IpAddr>().unwrap()]);
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
        let reader = thread::spawn(move || {
            let mut buf = [0; 4096];
            let mut drained = 0;
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            // Drain to EOF so the reader never closes with unread data and resets the connection.
            loop {
                let n = peer.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                drained += n;
                thread::sleep(Duration::from_millis(10));
            }
            drained
        });
        let header = Header { runs: &[], vmstate_len: 1, preload: &[], paused: false, app_log: 0 };
        let data = vec![7; 16 << 20];
        let start = Instant::now();
        let budget = Duration::from_millis(200);
        let result = send_paused(&conn, &header, &[0], &data, start + budget, &mut Phases::new());
        let elapsed = start.elapsed();
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
        let header = Header { runs: &[], vmstate_len: 1, preload: &[], paused: false, app_log: 0 };
        // Fit in the socket buffers so the deadline tests the reply, even if the reader is delayed.
        let data = vec![7; 32 << 10];
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

    /// A header's runs and preload list are refused at their caps, or at the first item out of order: what follows (here
    /// not even a run) is never decoded.
    #[test]
    fn a_header_is_refused_while_decoding() {
        let regions = [(0, 4 * crate::util::PAGE_SIZE as u64)];
        let decode = |runs: &str, preload: &str| {
            let line = format!(r#"{{"runs":{runs},"vmstate_len":1,"preload":{preload},"paused":false,"app_log":0}}"#);
            let hdr: Incoming = serde_json::from_str(&line).unwrap();
            hdr.decode(&regions).map_err(|e| e.to_string())
        };
        let ok = decode("[[0,1,3],[1,3,0]]", "[0]").unwrap();
        assert_eq!(ok, (vec![(0, 1, 3), (1, 3, 0)], vec![0]));
        let err = decode(r#"[[0,1,3],[1,1,0],[2,1,3],[3,1,0],[0,1,3],"junk"]"#, "[]").unwrap_err();
        assert!(err.contains("runs: more than 4 items"), "{err}");
        let err = decode(r#"[[0,2,3],[1,1,0],"junk"]"#, "[]").unwrap_err();
        assert!(err.contains("runs: item 1 out of order"), "{err}");
        let many = format!("[{}\"junk\"]", (0..=MAX_PRELOAD).map(|p| format!("{p},")).collect::<String>());
        let err = decode("[]", &many).unwrap_err();
        assert!(err.contains(&format!("preload: more than {MAX_PRELOAD} items")), "{err}");
        for preload in [r#"[2,2,"junk"]"#, r#"[3,0,"junk"]"#] {
            let err = decode("[]", preload).unwrap_err();
            assert!(err.contains("preload: item 1 out of order"), "{err}");
        }
    }

    /// The header line is capped by what an honest source could send for the guest's memory, a run per page.
    #[test]
    fn a_header_line_is_capped_by_guest_memory() {
        let regions = [(0, 1u64 << 30)];
        let pages = (1 << 30) / crate::util::PAGE_SIZE;
        let honest = Header {
            runs: &vec![(u64::MAX, u64::MAX, 255); pages],
            vmstate_len: u64::MAX,
            preload: &[u64::MAX; MAX_PRELOAD],
            paused: false,
            app_log: u64::MAX,
        };
        let line = serde_json::to_string(&honest).unwrap() + "\n";
        assert!(line.len() as u64 <= header_max(&regions), "{} > {}", line.len(), header_max(&regions));
        assert!(header_max(&regions) < MAX_HEADER);
        assert_eq!(header_max(&[(0, 1 << 50)]), MAX_HEADER);
        let long = "[".repeat(header_max(&regions) as usize + 1);
        assert!(crate::util::recv_line_max(&mut long.as_bytes(), header_max(&regions)).is_err());
    }

    /// A header declaring more than a source may send (a million preload pages) drains no more than that.
    #[test]
    fn a_refusal_drains_at_most_what_a_source_may_send() {
        let most = MAX_VMSTATE + (MAX_PRELOAD * crate::util::PAGE_SIZE) as u64;
        assert_eq!(arrival_owed(u64::MAX, 1_000_000), most);
        assert_eq!(arrival_owed(100, 2), 100 + 2 * crate::util::PAGE_SIZE as u64);
        assert_eq!(arrival_owed(0, 0), 0);
    }

    /// A listener at 127.0.0.1 answering each status query with `reply` (`token`, `outcome`), counting the queries.
    fn answering(reply: Value) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (at, asked) = (l.local_addr().unwrap(), Arc::new(std::sync::atomic::AtomicUsize::new(0)));
        let n = asked.clone();
        thread::spawn(move || {
            for mut c in l.incoming().flatten() {
                let mut line = String::new();
                let _ = std::io::BufRead::read_line(&mut BufReader::new(&c), &mut line);
                n.fetch_add(1, Ordering::SeqCst);
                let _ = c.write_all(format!("{}\n", json!({"ok": true, "result": reply})).as_bytes());
            }
        });
        (at, asked)
    }

    fn reached(to: &str, at: std::net::SocketAddr, token: Option<&str>) -> Reached {
        Reached { to: to.into(), at, token: token.map(String::from), by: crate::host::Ident::me() }
    }

    /// #1117: a host that never saw the migration says aborted; only the one the migration reached, as it named
    /// itself in the prepare answer, is believed. An older target (no token) is taken at its reached address.
    #[test]
    fn only_the_reached_target_says_what_became_of_a_migration() {
        let (other, _) = answering(json!({"outcome": "aborted", "token": "other"}));
        let (unnamed, _) = answering(json!({"outcome": "aborted"}));
        let (target, _) = answering(json!({"outcome": "committed", "token": "target"}));
        assert!(reached("t:1", other, Some("target")).ask(7, false).is_err());
        assert!(reached("t:1", unnamed, Some("target")).ask(7, false).is_err());
        assert!(outcome(&reached("t:1", other, Some("target")), 7, Duration::ZERO).is_none(), "no answer, never aborted");
        assert!(matches!(outcome(&reached("t:1", target, Some("target")), 7, Duration::ZERO), Some(Outcome::Committed(_))));
        assert!(matches!(outcome(&reached("t:1", other, None), 7, Duration::ZERO), Some(Outcome::Aborted)));
        let old = reached("t:1", unnamed, None).ask(7, true).unwrap();
        assert_eq!(old["outcome"], "aborted");
        assert!(old["waited"].is_null(), "older replies remain usable without claiming a wait");
    }

    /// #1214: a different host at the advertised source address cannot retire its released outcome.
    #[test]
    fn only_the_recorded_source_can_retire_a_released_migration() {
        let root = crate::test_util::TempDir::new("source-token");
        for (i, (reply, token, peer, retired)) in [
            (json!({"gone": true, "token": "other"}), Some("source"), Some("127.0.0.1"), false),
            (json!({"gone": true}), Some("source"), Some("127.0.0.1"), false),
            (json!({"gone": false, "token": "source"}), Some("source"), None, false),
            (json!({"gone": true, "token": "source"}), Some("source"), None, true),
            (json!({"gone": true, "token": "source"}), None, None, false),
            (json!({"gone": true}), None, Some("127.0.0.1"), true),
            (json!({"gone": true}), None, Some("::ffff:127.0.0.1"), true),
            (json!({"gone": true}), None, Some("127.0.0.2"), false),
            (json!({"gone": false}), None, Some("127.0.0.1"), false),
            (json!({}), None, Some("127.0.0.1"), false),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = root.join(i.to_string());
            let host = crate::host::Host::open(&dir.join("state"), &dir.join("run")).unwrap();
            let (at, _) = answering(reply);
            let id = i as u64;
            let mut record =
                host.mig_begin_from(id, &at.to_string(), Some(crate::host::Ident::me()), None, peer.map(|p| p.parse().unwrap())).unwrap().with_token(token);
            record.commit(&host.lock().unwrap()).unwrap();
            record.release(None, None).unwrap();
            host.retire_migrations();
            let stored = crate::host::load::<Value>(&host.state.join("migs").join(id.to_string())).unwrap().unwrap();
            assert_eq!(stored["token"].as_str(), token);
            assert_eq!(stored["done_until_ms"].is_u64(), retired, "{stored}");
        }
    }

    #[test]
    fn lost_long_poll_falls_back_to_identity_checked_status() {
        use crate::test_util::JoinWithin;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for wait in [true, false] {
                let (mut c, _) = crate::test_util::accept_tcp(&listener);
                let mut line = String::new();
                std::io::BufRead::read_line(&mut BufReader::new(&c), &mut line).unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(req["wait"], wait);
                if !wait {
                    writeln!(c, "{}", json!({"ok": true, "result": {"outcome": "released", "token": "target"}})).unwrap();
                }
            }
        });
        assert_eq!(reached("t:1", at, Some("target")).ask(7, true).unwrap()["outcome"], "released");
        server.join_within().unwrap();
        let (other, _) = answering(json!({"outcome": "released", "token": "other"}));
        assert!(reached("t:1", other, Some("target")).ask(7, true).is_err());
    }

    /// A dead source's owed outcome is asked where it reached its target, never by the target's name again, and the
    /// record goes once the target is told done; one from before records were kept asks the name.
    #[test]
    fn an_owed_outcome_is_asked_where_the_source_reached_its_target() {
        let root = crate::test_util::TempDir::new("reached");
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let (at, asked) = answering(json!({"outcome": "released", "token": "target"}));
        reached("unresolvable.invalid:7070", at, Some("target")).record(&host, 3).unwrap();
        assert_eq!(owed_outcome(&host, "unresolvable.invalid:7070", 3).unwrap(), "released");
        owed_done(&host, "unresolvable.invalid:7070", 3, Instant::now());
        assert!(Reached::load(&host, 3).unwrap().is_some(), "no acknowledgement budget: keep the record");
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        owed_done(&host, "unresolvable.invalid:7070", 3, Instant::now() + Duration::from_secs(5));
        assert_eq!(asked.load(Ordering::SeqCst), 2);
        assert!(Reached::load(&host, 3).unwrap().is_none());
        assert!(owed_outcome(&host, "unresolvable.invalid:7070", 3).is_err(), "by name, which does not resolve");
        // Unreadable: no answer, never the name.
        std::fs::write(Reached::path(&host, 4), "{").unwrap();
        assert!(owed_outcome(&host, &at.to_string(), 4).is_err());
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn source_mismatch_requires_an_explicit_different_token() {
        for (reply, expected) in [
            (json!({"token": "other", "gone": true}), SourceReply::Mismatch),
            (json!({"token": "other", "gone": false}), SourceReply::Mismatch),
            (json!({"token": "right", "gone": true}), SourceReply::Gone),
            (json!({"token": "right", "gone": false}), SourceReply::Keep),
            (json!({"gone": true}), SourceReply::Keep),
            (json!({"token": null}), SourceReply::Keep),
            (json!({"token": 7}), SourceReply::Keep),
        ] {
            assert_eq!(source_reply(Some("right"), None, None, &reply), expected);
        }
        assert_eq!(source_reply(None, None, None, &json!({"token": "other", "gone": true})), SourceReply::Keep);
    }

    #[test]
    fn source_reply_requires_the_recorded_identity_and_explicit_gone() {
        let peer = Some("192.0.2.1".parse().unwrap());
        let mapped = Some("::ffff:192.0.2.1".parse().unwrap());
        let other = Some("192.0.2.2".parse().unwrap());
        let gone = json!({"token": "right", "gone": true});
        assert!(source_reply_gone(Some("right"), peer, other, &gone));
        assert!(!source_reply_gone(Some("stale"), peer, peer, &gone));
        assert!(!source_reply_gone(Some("right"), peer, peer, &json!({"gone": true})), "older sources cannot vouch for a token");
        assert!(source_reply_gone(None, peer, mapped, &json!({"gone": true})));
        assert!(!source_reply_gone(None, peer, other, &gone));
        assert!(!source_reply_gone(None, peer, None, &gone));
        assert!(!source_reply_gone(None, None, peer, &gone));
        for reply in [json!({"token": "right"}), json!({"token": "right", "gone": false}), json!({"token": "right", "gone": "true"})] {
            assert!(!source_reply_gone(Some("right"), peer, peer, &reply));
        }
    }

    /// A record goes once its source is gone and owes nothing; a live source's stays.
    #[test]
    fn reached_records_of_gone_sources_that_owe_nothing_go() {
        let root = crate::test_util::TempDir::new("reached-prune");
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let at = "127.0.0.1:1".parse().unwrap();
        let gone = Reached { by: crate::host::Ident { boot: "another boot".into(), ..crate::host::Ident::me() }, ..reached("t:1", at, None) };
        gone.record(&host, 1).unwrap();
        assert_eq!(Reached::load(&host, 1).unwrap(), Some(gone));
        reached("t:1", at, None).record(&host, 2).unwrap();
        reached("t:1", at, None).record(&host, 3).unwrap();
        assert!(Reached::load(&host, 1).unwrap().is_none());
        assert!(Reached::load(&host, 2).unwrap().is_some() && Reached::load(&host, 3).unwrap().is_some());
    }

    #[test]
    fn reached_batch_keeps_dead_sources_when_an_owed_record_is_unreadable() {
        let root = crate::test_util::TempDir::new("reached-corrupt");
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let at = "127.0.0.1:1".parse().unwrap();
        let gone = Reached { by: crate::host::Ident { boot: "another boot".into(), ..crate::host::Ident::me() }, ..reached("t:1", at, None) };
        gone.record(&host, 1).unwrap();
        std::fs::create_dir_all(host.state.join("owed")).unwrap();
        std::fs::write(host.state.join("owed/9"), b"broken").unwrap();
        gone.record(&host, 2).unwrap();
        reached("t:1", at, None).record(&host, 3).unwrap();
        assert!(Reached::load(&host, 1).unwrap().is_some());
        assert!(Reached::load(&host, 2).unwrap().is_some());
        std::fs::remove_file(host.state.join("owed/9")).unwrap();
        reached("t:1", at, None).record(&host, 4).unwrap();
        assert!(Reached::load(&host, 1).unwrap().is_none());
        assert!(Reached::load(&host, 2).unwrap().is_none());
    }

    /// #1117: a gone source's record is let go of only under the host lock, so `withdraw_dead`'s owing it (also
    /// under the lock) is seen: never a moment where neither its owed record nor its leaving claim is there.
    #[test]
    fn a_gone_sources_record_is_decided_under_the_host_lock() {
        let root = crate::test_util::TempDir::new("reached-locked");
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let at = "127.0.0.1:1".parse().unwrap();
        let by = crate::host::Ident { boot: "another boot".into(), ..crate::host::Ident::me() };
        Reached { by: by.clone(), ..reached("t:1", at, None) }.record(&host, 1).unwrap();
        let l = host.lock().unwrap();
        thread::scope(|s| {
            let recording = s.spawn(|| reached("t:1", at, None).record(&host, 2).unwrap());
            thread::sleep(Duration::from_millis(200));
            assert!(!recording.is_finished(), "waits for the host lock");
            // As `withdraw_dead` does under it: owed, then its leaving claim goes.
            host.owe(1, &crate::host::Owed { to: "t:1".into(), ip: Ipv4Addr::new(10, 9, 0, 1), gen: 1, by }).unwrap();
            drop(l);
            recording.join().unwrap();
        });
        assert!(Reached::load(&host, 1).unwrap().is_some(), "owed: kept");
        assert!(Reached::load(&host, 2).unwrap().is_some());
    }

    /// #1117: a migration given up before the pause lets go of its record, unless its source still owes it.
    #[test]
    fn a_migration_given_up_lets_go_of_its_record_unless_owed() {
        let root = crate::test_util::TempDir::new("reached-give-up");
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let r = reached("t:1", "127.0.0.1:1".parse().unwrap(), None);
        r.record(&host, 1).unwrap();
        r.give_up(&host, 1);
        assert!(Reached::load(&host, 1).unwrap().is_none());
        r.record(&host, 2).unwrap();
        host.owe(9, &crate::host::Owed { to: "t:1".into(), ip: Ipv4Addr::new(10, 9, 0, 1), gen: 1, by: crate::host::Ident::me() }).unwrap();
        r.give_up(&host, 2);
        assert!(Reached::load(&host, 2).unwrap().is_some(), "still owed: kept");
    }

    /// A host answers as one identity from its first prepare on, however many ask at once, and none before.
    #[test]
    fn a_host_token_is_made_once() {
        let root = crate::test_util::TempDir::new("host-token");
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        assert_eq!(host_token(&host, false).unwrap(), None);
        let made: Vec<_> = thread::scope(|s| {
            let each: Vec<_> = (0..8).map(|_| s.spawn(|| host_token(&host, true).unwrap().unwrap())).collect();
            each.into_iter().map(|t| t.join().unwrap()).collect()
        });
        assert!(made.iter().all(|t| *t == made[0] && t.len() == 32), "{made:?}");
        assert_eq!(host_token(&host, false).unwrap().as_ref(), Some(&made[0]));
        let again = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        assert_eq!(host_token(&again, true).unwrap().as_ref(), Some(&made[0]));
        assert!(std::fs::read_dir(&host.state).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".tmp")));
    }

    /// #1117: regions past the template's memory (boot and hotplug) are refused before anything is sized by them.
    #[test]
    fn regions_past_the_templates_memory_are_refused() {
        assert!(check_regions(&[(0, 512 << 20), (1 << 32, 512 << 20)], 1024).is_ok());
        assert!(check_regions(&[(0, 512 << 20), (1 << 32, (512 << 20) + 4096)], 1024).is_err());
        assert!(check_regions(&[(0, 256 << 20)], 128).is_err());
        assert!(check_regions(&[(0, u64::MAX), (1, 2)], u64::MAX >> 20).is_err());
    }
}
