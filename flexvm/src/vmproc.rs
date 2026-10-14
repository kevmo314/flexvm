//! The VM process: one process per VM, owning its Firecracker, pager, tap,
//! route and holds, exiting with the VM. SIGTERM suspends, SIGTSTP pauses,
//! SIGCONT resumes, SIGINT (and SIGQUIT) destroys; `RUN/vms/NAME.sock` takes control ops.
//! Every operation, starting included, holds `op`; the process ends only
//! through `finish`, which holds it too.

use std::io::{BufReader, Write};
use std::net::Ipv4Addr;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::Spawner;
use crate::guest;
use crate::hold::Holder;
use crate::host::{fault, AddrClaim, Entry, Host, Ident, MigRecord, NameLock};
use crate::template::{Paths, Template, STEP_MIB};
use crate::util::{ms, proc_kb, send_json, Error, Phases, Result};
use crate::vm::{Snapshot, State, Vm};

/// A VM process's own exit statuses (`run -- CMD` passes CMD's through):
/// 128 + the signal that ended it (130 SIGINT, 143 SIGTERM's suspend), and
/// these two, from the range shells and container runtimes keep for themselves.
pub const FAILED: i32 = 125;
/// Its Firecracker died under it.
pub const DIED: i32 = 124;
const OP_WAIT: Duration = Duration::from_secs(30);
const RELEASE_WAIT: Duration = Duration::from_secs(10);
const CLOCK_TOLERANCE: Duration = Duration::from_millis(20);
pub const CLOCK_DEADLINE: Duration = Duration::from_secs(5);
const SIGNALS: [i32; 6] = [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGCONT, libc::SIGHUP];
const MAX_CONTROL: usize = 256;
static CONTROL: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub enum Start {
    Run { name: String, template: String, ip: Option<Ipv4Addr>, cmd: Option<String> },
    Resume { name: String },
    Restore { dir: PathBuf, name: Option<String>, ip: Option<String>, paused: bool },
    /// The migration connection is fd 3.
    Incoming { req: Value },
    Standby { template: String },
}

pub type Op<'a> = MutexGuard<'a, ()>;

/// How the VM left, which decides what becomes of its address and of an
/// arrival still pulling: Gone lets its source go, Died lets the source run
/// its copy again (`Host::mig_status`). NotStarted withdraws only a fresh gen.
pub enum End {
    Gone,
    Died,
    Suspended,
    Moved(String),
    NotStarted,
}

pub struct Proc {
    pub host: Host,
    pub paths: Paths,
    pub spawner: Spawner,
    ident: Ident,
    name: Mutex<Option<NameLock>>,
    addr: Mutex<Option<AddrClaim>>,
    vm: OnceLock<Arc<Vm>>,
    op: Mutex<()>,
    holder: OnceLock<Option<Arc<Holder>>>,
    /// The migration this VM arrived by, until all its pages are in.
    pub arrived: Mutex<Option<MigRecord>>,
    /// Revocable right of the arrival's source to send the packets it held.
    pub held_in: Mutex<Option<Arc<Mutex<bool>>>>,
    pub app_log: AtomicU64,
    /// Set while a migration away may commit: exit when the VM leaves.
    leaving: AtomicBool,
    /// This VM's migration away lent its address here (and only then may undo it).
    pub lent_here: AtomicBool,
    pub standby: Mutex<Option<crate::vm::Prepared>>,
    pub claimer: Mutex<Option<UnixStream>>,
    pub cmd: Mutex<Option<String>>,
    /// The main command's session: a suspend holds it, so what it records is
    /// what was written out, and the resumed VM reattaches from there.
    pub cmd_session: OnceLock<Mutex<crate::Session>>,
    /// While a suspend runs: the main command neither gives up nor ends the VM.
    /// A lock, not a flag: the command ending the VM and a suspend starting
    /// exclude each other (the command holds it through its `destroy`).
    pub suspending: Mutex<bool>,
    early: Mutex<Vec<i32>>,
    /// Only then does SIGCONT resume (the kernel sends one after any SIGSTOP,
    /// systemd after SIGTERM).
    pub paused_by_request: AtomicBool,
    /// A resumed suspended VM's checkpoint (marked STARTED), deleted once all
    /// its pages are in, or at the end.
    pub consumed: Mutex<Option<PathBuf>>,
    pub pending_route: Mutex<Option<Ipv4Addr>>,
    pub files: Mutex<Vec<PathBuf>>,
    /// What the VM's start was admitted against the reserve (MiB): its first memory mark.
    granted: AtomicU64,
    /// The grant of this start (refunded if the VM never starts).
    charged: AtomicU64,
    /// A disk restore or arrival grant, held until all its memory is here.
    held_grant: Mutex<Option<crate::host::Hold>>,
    /// A standby's (MiB held or to page in, guest size), taken while it waits, so a claim need not.
    pub sizes: Mutex<Option<(u64, u64)>>,
    serving: AtomicBool,
    /// The controller's tick gaps, for `debug status`.
    ticks: Mutex<Ticks>,
    /// How fast the VM's memory grew lately (MiB/s), for eviction's ranking.
    growth: AtomicU64,
    me: std::sync::Weak<Proc>,
}

/// How regularly the controller ticks (every second when nothing holds it up).
#[derive(Default)]
struct Ticks {
    last: Option<Instant>,
    count: u64,
    max_gap: Duration,
    recent: std::collections::VecDeque<Duration>,
}

impl Ticks {
    fn tick(&mut self) {
        let now = Instant::now();
        if let Some(gap) = self.last.map(|l| now - l) {
            self.max_gap = self.max_gap.max(gap);
            if self.recent.len() == 32 {
                self.recent.pop_front();
            }
            self.recent.push_back(gap);
        }
        self.last = Some(now);
        self.count += 1;
    }

    fn json(&self) -> Value {
        json!({
            "ticks": self.count,
            "max_gap_ms": ms(self.max_gap),
            "since_last_ms": self.last.map(|l| ms(l.elapsed())),
            "recent_gaps_ms": self.recent.iter().map(|&g| ms(g)).collect::<Vec<_>>(),
        })
    }
}

impl Proc {
    fn new(host: Host, paths: Paths) -> Result<Arc<Proc>> {
        let ident = Ident::me();
        let work = host.run.join("w").join(ident.pid.to_string());
        if let Some(old) = crate::host::load(&work.join("owner"))? {
            crate::host::reap(&host.run, &old)?;
        }
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work)?;
        crate::host::store(&work.join("owner"), &ident, false)?;
        let tap_prefix = format!("{}{:x}t", host.cfg.prefix, ident.pid);
        let spawner = Spawner::new(&paths.firecracker, &work, crate::socket::SocketRoot::new(&work)?, cgroup_root(), &tap_prefix);
        Ok(Arc::new_cyclic(|me| Proc {
            host,
            paths,
            spawner,
            ident,
            name: Mutex::new(None),
            addr: Mutex::new(None),
            vm: OnceLock::new(),
            op: Mutex::new(()),
            holder: OnceLock::new(),
            arrived: Mutex::new(None),
            held_in: Mutex::new(None),
            app_log: AtomicU64::new(0),
            leaving: AtomicBool::new(false),
            lent_here: AtomicBool::new(false),
            standby: Mutex::new(None),
            claimer: Mutex::new(None),
            cmd: Mutex::new(None),
            cmd_session: OnceLock::new(),
            suspending: Mutex::new(false),
            early: Mutex::new(Vec::new()),
            paused_by_request: AtomicBool::new(false),
            consumed: Mutex::new(None),
            pending_route: Mutex::new(None),
            files: Mutex::new(Vec::new()),
            granted: AtomicU64::new(0),
            charged: AtomicU64::new(0),
            held_grant: Mutex::new(None),
            sizes: Mutex::new(None),
            serving: AtomicBool::new(false),
            ticks: Mutex::new(Ticks::default()),
            growth: AtomicU64::new(0),
            me: me.clone(),
        }))
    }

    pub fn vm(&self) -> &Arc<Vm> {
        self.vm.get().expect("no vm yet")
    }

    pub fn set_vm(&self, vm: Arc<Vm>) {
        self.adopt(vm);
        self.start_limit();
    }

    /// The VM is this process's: its start's grant is spent. Its memory mark
    /// is set apart (`start_limit`), so a migration's arrival sets it after
    /// the VM runs, outside the downtime.
    pub fn adopt(&self, vm: Arc<Vm>) {
        self.charged.store(0, Ordering::SeqCst);
        let _ = self.vm.set(vm);
    }

    /// From the sizes taken ahead (a standby's, an arrival's from the runs
    /// its source sent), else measured now.
    pub fn start_limit(&self) {
        let vm = self.vm();
        let sizes = self.sizes.lock().unwrap().take().unwrap_or_else(|| vm.mem_sizes());
        vm.start_limit(self.granted.load(Ordering::SeqCst), sizes, &self.host);
    }

    pub fn name(&self) -> String {
        self.name.lock().unwrap().as_ref().map(|n| n.name.clone()).unwrap_or_default()
    }

    pub fn set_name(&self, n: NameLock) {
        crate::util::output::fall_back_to(self.host.vms(&n.name, "log"));
        *self.name.lock().unwrap() = Some(n);
    }

    /// Every start, before it loads: what the VM brings (`need` MiB, held or
    /// to page in) and a step, against the host's reserve, less what it
    /// already holds here (`held`: a standby's memory is out of MemAvailable).
    /// An arrival moved here by eviction leaves this host's eviction mark
    /// available instead of only the reserve (`floor`).
    pub fn admit_start(&self, need: u64, held: u64, floor: crate::host::Floor) -> Result<()> {
        let mib = crate::limit::allowance(need);
        let charge = mib.saturating_sub(held);
        let id = self.host.grant_above(charge, floor)?;
        self.granted.store(mib, Ordering::SeqCst);
        self.charged.store(id, Ordering::SeqCst);
        Ok(())
    }

    /// A disk restore or arrival's admission: its grant counts until all its
    /// memory is here or it ends, however long the pull takes.
    pub fn admit_pull(&self, need: u64, floor: crate::host::Floor) -> Result<()> {
        let mib = crate::limit::allowance(need);
        let (id, hold) = self.host.grant_held(mib, floor)?;
        self.granted.store(mib, Ordering::SeqCst);
        self.charged.store(id, Ordering::SeqCst);
        *self.held_grant.lock().unwrap() = Some(hold);
        Ok(())
    }

    pub(crate) fn release_hold(&self) {
        drop(self.held_grant.lock().unwrap().take());
    }

    /// A start that did not happen gives its admission back.
    /// A hold is left to `finish`, which drops it once the VM is killed.
    pub fn refund_start(&self) {
        let id = self.charged.swap(0, Ordering::SeqCst);
        self.granted.store(0, Ordering::SeqCst);
        if id > 0 {
            self.host.refund(id);
        }
    }

    pub fn set_addr(&self, a: AddrClaim) -> Ipv4Addr {
        let ip = a.ip;
        *self.addr.lock().unwrap() = Some(a);
        ip
    }

    /// The peer whose range holds `ip` lends it with a new generation.
    /// All peers are asked at once; only the home host lends (should two, the
    /// loan of every one but the first is given back).
    pub fn borrow(&self, name: &str, ip: Ipv4Addr) -> Result<AddrClaim> {
        let asks: Vec<_> = self
            .host
            .cfg
            .peers
            .iter()
            .cloned()
            .map(|peer| thread::spawn(move || {
                let r = peer_call(&peer, json!({"op": "lend", "ip": ip.to_string()}));
                (peer, r)
            }))
            .collect();
        let (mut lent, mut why) = (Vec::new(), Vec::new());
        for (peer, r) in asks.into_iter().filter_map(|a| a.join().ok()) {
            match r.map(|r| r["gen"].as_u64().filter(|&g| g > 0)) {
                Ok(Some(gen)) => lent.push((peer, gen)),
                Ok(None) => why.push(format!("{peer} lent {ip} without a generation")),
                Err(e) => why.push(format!("{peer}: {e}")),
            }
        }
        let mut lent = lent.into_iter();
        let first = lent.next();
        for (peer, gen) in lent {
            let _ = peer_call(&peer, json!({"op": "route", "ip": ip.to_string(), "gen": gen}));
        }
        if let Some((peer, gen)) = first {
            return match self.host.lock().and_then(|l| self.host.claim_incoming(&l, name, ip, gen)) {
                Ok(mut c) => {
                    c.fresh = true;
                    Ok(c)
                }
                Err(e) => {
                    let _ = peer_call(&peer, json!({"op": "route", "ip": ip.to_string(), "gen": gen}));
                    bail!("cannot take {ip} borrowed from {peer}: {e}; restore with --ip auto")
                }
            };
        }
        bail!("cannot borrow {ip} from its home host ({}); restore with --ip auto", why.join("; "))
    }

    /// The one place an arrival settles, under `op`: once every page is here
    /// its record is released durably, then a home loan taken back. Every
    /// operation that changes who owns the VM (suspend, migrating on,
    /// checkpoint --stop) settles first, waiting up to `wait`, and is refused
    /// while the VM is still arriving.
    /// Recording the release is bounded too (`RELEASE_WAIT`): on a failure
    /// the arrival stays unsettled, for the pull's worker to retry.
    pub fn settle_arrival(&self, _op: &Op, wait: Duration) -> Result<()> {
        if self.arrived.lock().unwrap().is_none() {
            return Ok(());
        }
        let vm = self.vm();
        // In slices: a kill on its way (`destroy`) is not held up by the wait.
        let deadline = Instant::now() + wait;
        while !self.pulled_all() && vm.cancel_checkpoint.load(Ordering::SeqCst) == 0 && vm.pager.failed().is_none() && !vm.dead() && vm.firecracker_alive() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            vm.pager.wait_pulled(Some(left.min(Duration::from_millis(100))));
        }
        if !self.pulled_all() {
            bail!("vm {} is still arriving: not all its memory is here yet", vm.name);
        }
        let mut arrived = self.arrived.lock().unwrap();
        if let Some(rec) = arrived.as_ref() {
            rec.release(Some((vm.ip, self.gen())), Some(RELEASE_WAIT))
                .map_err(|e| format!("vm {}: recording that all its memory arrived: {e}; try again", vm.name))?;
        }
        *arrived = None;
        drop(arrived);
        self.release_hold();
        Ok(())
    }

    /// Every page is here and the VM can still run (a stopped pager, as when
    /// its Firecracker died, ends a wait for the pull without a failure). A VM
    /// whose resume failed cannot, though its Firecracker may not be gone yet.
    pub fn pulled_all(&self) -> bool {
        let vm = self.vm();
        vm.pager.remote_left() == 0 && vm.pager.failed().is_none() && vm.state() != State::Failed && vm.firecracker_alive()
    }

    pub fn keep_addr(&self) {
        if let Some(a) = self.addr.lock().unwrap().take() {
            a.keep();
        }
    }

    /// The host lock, if the generation is still current: hold it until the VM runs.
    pub fn still_current(&self, ip: Ipv4Addr) -> Result<crate::host::Locked> {
        self.host.fence(ip, self.gen()).map_err(|e| format!("{e}; restore with --ip auto").into())
    }

    pub fn gen(&self) -> u64 {
        self.addr.lock().unwrap().as_ref().map_or(0, |a| a.gen)
    }

    pub fn op(&self) -> Op<'_> {
        self.op.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Without waiting: None if another operation holds it.
    pub fn op_now(&self) -> Option<Op<'_>> {
        match self.op.try_lock() {
            Ok(g) => Some(g),
            Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
            Err(_) => None,
        }
    }

    pub fn op_within(&self) -> Result<Op<'_>> {
        let deadline = Instant::now() + OP_WAIT;
        loop {
            match self.op.try_lock() {
                Ok(g) => return Ok(g),
                Err(std::sync::TryLockError::Poisoned(e)) => return Ok(e.into_inner()),
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
                Err(_) => bail!("vm {} is busy", self.name()),
            }
        }
    }

    pub fn holder(&self) -> Option<&Arc<Holder>> {
        self.holder
            .get_or_init(|| {
                Holder::new(&format!("{}{:x}h", self.host.cfg.prefix, self.ident.pid)).unwrap_or_else(|e| {
                    eprintln!("packets in flight while the vm is paused will be dropped: {e}");
                    None
                })
            })
            .as_ref()
    }

    /// Best effort: the registry is for `ls`; nothing decides ownership by it.
    pub fn publish(&self) {
        let (Some(vm), Some(n)) = (self.vm.get(), self.name.lock().unwrap().as_ref().map(|n| n.name.clone())) else { return };
        if fault("publish") {
            return eprintln!("vm {n}: registry: injected fault: not published");
        }
        let e = Entry {
            name: n.clone(),
            ident: self.ident.clone(),
            ip: Some(vm.ip),
            gen: self.gen(),
            template: vm.template.name.clone(),
            template_id: vm.template.meta.id.clone(),
            vcpus: vm.template.meta.vcpus,
            max_mib: vm.template.meta.max_mib,
            state: vm.state().name().into(),
            firecracker: vm.pid(),
            starved: vm.starving(),
            growth_mib_s: self.growth.load(Ordering::SeqCst),
            cmd: self.cmd.lock().unwrap().is_some(),
        };
        if let Err(e) = self.name.lock().unwrap().as_ref().map_or(Ok(()), |l| l.publish(&e)) {
            eprintln!("vm {n}: registry: {e}");
        }
    }

    /// The one way the process ends, holding `op`.
    pub fn finish(&self, _op: &Op, end: End, code: i32, last: Option<(&UnixStream, Value)>) -> ! {
        if matches!(end, End::NotStarted) {
            self.refund_start();
        }
        self.drop_held_in();
        self.set_leaving(true);
        if let Some(vm) = self.vm.get() {
            vm.kill();
        }
        self.release_hold();
        drop(self.standby.lock().unwrap().take());
        // An arrival still pulling that dies leaves its source's copy to run
        // again (see `Host::mig_status`): its address is not withdrawn.
        let source_runs = matches!(end, End::Died) && self.arrived.lock().unwrap().is_some();
        if let Some(rec) = self.arrived.lock().unwrap().take() {
            rec.settle(matches!(end, End::Gone));
        }
        match (end, self.addr.lock().unwrap().take()) {
            (End::Suspended, Some(a)) => a.keep(),
            (End::Gone | End::Died, Some(a)) if !source_runs => self.withdraw(a),
            (End::NotStarted, Some(a)) if a.fresh => self.withdraw(a),
            (End::Moved(to), _) => {
                let _ = std::fs::write(self.host.vms(&self.name(), "moved"), &to);
                eprintln!("vm {}: moved to {to}", self.name());
            }
            // Never ran here: a peer's route for it (say its source's) comes back.
            (_, Some(a)) => {
                let ip = a.ip;
                if let Ok(l) = self.host.lock() {
                    let _ = a.release(&l);
                    let _ = self.host.reinstall(&l, ip);
                }
            }
            (_, None) => {}
        }
        if let Some(dir) = self.consumed.lock().unwrap().take() {
            crate::lifecycle::delete_consumed(&self.name(), &dir);
        }
        drop(self.name.lock().unwrap().take());
        for f in self.files.lock().unwrap().drain(..) {
            let _ = std::fs::remove_file(f);
        }
        if let Some((mut c, v)) = last {
            let _ = send_json(&mut c, &v);
        }
        if let Some(c) = self.claimer.lock().unwrap().take() {
            let _ = send_json(&mut &c, &json!({"exit": code}));
        }
        let work = self.host.run.join("w").join(self.ident.pid.to_string());
        crate::socket::remove(&work);
        let _ = std::fs::remove_dir_all(&work);
        crate::util::output::drain();
        std::process::exit(code)
    }

    /// Returns only if refused: a migration source is never killed, as its
    /// target may still be pulling its memory.
    pub fn destroy(&self, code: i32) -> Error {
        let vm = self.vm();
        let source = || format!("vm {} is the source of a migration in progress; it ends once the target has its memory", vm.name).into();
        if matches!(vm.state(), State::Source(_)) {
            return source();
        }
        vm.cancel_checkpoint.fetch_add(1, Ordering::SeqCst);
        vm.pager.abort_copy();
        let op = self.op();
        if matches!(vm.state(), State::Source(_)) {
            // Refused: the next checkpoint must not take this kill for its own
            // (one it already cancelled consumed it).
            let _ = vm.cancel_checkpoint.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
            return source();
        }
        self.finish(&op, End::Gone, code, None)
    }

    fn withdraw(&self, a: AddrClaim) {
        let (ip, gen) = (a.ip, a.gen);
        if let Ok(l) = self.host.lock() {
            let ours = self.host.holder(&l, ip).is_ok_and(|h| h.is_none_or(|h| h == self.name()));
            let _ = a.release(&l);
            let _ = self.host.observe(&l, ip, gen, None);
            if ours && !self.host.reinstall(&l, ip).unwrap_or(false) {
                crate::net::unroute(ip);
            }
        }
        tell_peers(&self.host, json!({"op": "route", "ip": ip.to_string(), "gen": gen}));
    }

    pub fn announce(&self) {
        let vm = self.vm().clone();
        let (ip, gen, peers, dev) = (vm.ip, self.gen(), self.host.cfg.peers.clone(), self.host.cfg.announce_dev.clone());
        let Some(via) = self.host.cfg.underlay() else {
            if !peers.is_empty() {
                eprintln!("announce {ip}: no underlay address (give flexvm listen an ADDR peers can reach, or --underlay IP); peers not told");
            }
            return;
        };
        thread::spawn(move || {
            let here = || vm.state().local();
            let arp = || {
                if let Some(dev) = dev.as_deref().filter(|_| here()) {
                    crate::net::gratuitous_arp(dev, ip).unwrap_or_else(|e| eprintln!("announce {ip}: {e}"));
                }
            };
            arp();
            // All peers at once: one slow or down peer does not hold up the others.
            let req = json!({"op": "route", "ip": ip.to_string(), "via": via.to_string(), "gen": gen});
            let sends: Vec<_> = peers
                .into_iter()
                .filter(|_| here())
                .map(|peer| {
                    let req = req.clone();
                    thread::spawn(move || {
                        if let Err(e) = peer_call(&peer, req) {
                            eprintln!("announce {ip} to {peer}: {e}");
                        }
                    })
                })
                .collect();
            sends.into_iter().for_each(|s| drop(s.join()));
            thread::sleep(Duration::from_millis(200));
            arp();
        });
    }

    pub fn drop_held_in(&self) {
        if let Some(revoked) = self.held_in.lock().unwrap().take() {
            *revoked.lock().unwrap() = true;
        }
    }

    fn run(&self, name: &str, template: &str, want: Option<Ipv4Addr>) -> Result<Value> {
        let mut t = Phases::new();
        self.set_name(self.host.take_name(name, false)?);
        let tpl = Template::open(&self.paths, template)?;
        t.mark("template");
        // Before the claim: a refused start mints no generation (nor withdraws one).
        self.admit_start(tpl.working_set_mib(), 0, crate::host::Floor::Reserve)?;
        let claim = self.host.claim_new(&self.host.lock()?, name, want)?;
        let ip = self.set_addr(claim);
        t.mark("claim_ip");
        crate::host::stall("start_stall");
        let prepared = Vm::prepare(self.spawner.take(None)?, tpl.clone(), &mut t)?;
        let learn = crate::standby::load_set(&self.host, &tpl).is_empty();
        if learn {
            prepared.pager.learn_load_set();
        }
        let (vm, _) = prepared.load(&self.spawner, name, Snapshot::Path(&tpl.vmstate()), None, ip, false, None, || Ok(()), &mut t)?;
        if learn {
            crate::standby::save_load_set(&self.host, &tpl);
        }
        let still = self.host.fence(ip, self.gen()).inspect_err(|_| vm.kill())?;
        if let Err(e) = vm.start(fault("resume_kill")) {
            vm.kill();
            bail!("resuming the restored vm failed (it may have run, so it is not loaded again): {e}");
        }
        drop(still);
        t.mark("resume");
        self.set_vm(vm);
        let mut v = self.start_guest(&mut t)?;
        v["standby"] = json!(false);
        Ok(v)
    }

    pub fn start_guest(&self, t: &mut Phases) -> Result<Value> {
        let vm = self.vm().clone();
        self.publish();
        t.mark("register");
        let running = t.total();
        vm.guest_net(vm.ip, self.host.cfg.dns.as_deref())?;
        if t.mark("guest_net") >= crate::vm::CLOCK_RTT {
            self.sync_clock_later();
        }
        if vm.template.meta.image.as_ref().is_some_and(|i| !i.warm) {
            vm.start_app().map_err(|e| format!("{e} (see the vm's output)"))?;
            t.mark("app_start");
        }
        self.announce();
        t.mark("announce");
        Ok(json!({
            "name": vm.name,
            "ip": vm.ip.to_string(),
            "pid": self.ident.pid,
            "start": self.ident.start,
            "running_ms": ms(running),
            "ready_ms": ms(t.total()),
            "timings_ms": t.json(),
        }))
    }

    pub fn serve_control(self: &Arc<Self>) {
        if self.serving.swap(true, Ordering::SeqCst) {
            return;
        }
        let sock = self.host.sock(&self.name());
        let _ = std::fs::remove_file(&sock);
        let l = match UnixListener::bind(&sock) {
            Ok(l) => l,
            Err(e) => return eprintln!("vm {}: no control socket at {}: {e}", self.name(), sock.display()),
        };
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600));
        let p = self.clone();
        thread::spawn(move || {
            for c in l.incoming() {
                let c = match c {
                    Ok(c) => c,
                    Err(e) => {
                        crate::util::accept_failed("control socket", &e);
                        continue;
                    }
                };
                if CONTROL.fetch_add(1, Ordering::SeqCst) >= MAX_CONTROL {
                    CONTROL.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let p = p.clone();
                thread::spawn(move || {
                    p.control(c);
                    CONTROL.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
    }

    /// Never returns: the main thread spawned Firecracker, which dies with it.
    fn serve(self: &Arc<Self>) -> ! {
        self.serve_control();
        let spawn = |f: fn(Arc<Proc>)| {
            let p = self.clone();
            thread::spawn(move || f(p));
        };
        spawn(Proc::controller);
        spawn(Proc::serve_memory);
        spawn(Proc::watch_memory);
        if self.vm().template.meta.image.is_some() {
            spawn(Proc::follow_app);
        }
        if let Some(fc) = self.vm().pid().and_then(Ident::of).and_then(|id| crate::host::PidFd::open(&id).ok().flatten()) {
            let p = self.clone();
            thread::spawn(move || {
                while !fc.wait(Duration::from_secs(3600)) {}
                p.died();
            });
        }
        // Before the main command starts: a Ctrl-Z taken during startup pauses the VM first.
        for sig in std::mem::take(&mut *self.early.lock().unwrap()) {
            self.signal(sig);
        }
        if self.cmd.lock().unwrap().is_some() {
            spawn(Proc::main_command);
        }
        loop {
            thread::park();
        }
    }

    fn signal(&self, sig: i32) {
        let Some(vm) = self.vm.get() else {
            if sig != libc::SIGHUP {
                self.early.lock().unwrap().push(sig);
            }
            return;
        };
        let res = match sig {
            libc::SIGTSTP => self.op_within().and_then(|_op| vm.pause()).map(|()| {
                self.paused_by_request.store(true, Ordering::SeqCst);
                self.publish()
            }),
            libc::SIGCONT if self.leaving.load(Ordering::SeqCst) || !self.paused_by_request.load(Ordering::SeqCst) => Ok(()),
            libc::SIGCONT => self.resume().map(drop),
            libc::SIGTERM if matches!(vm.state(), State::Source(_)) => {
                eprintln!("vm {}: migrating away; it ends once the target has its memory", vm.name);
                Ok(())
            }
            libc::SIGTERM => match self.arc() {
                // Off the signal thread, which a later SIGINT needs.
                Some(p) => {
                    thread::spawn(move || eprintln!("vm {}: signal {sig}: {}", p.name(), p.suspend()));
                    Ok(())
                }
                None => Err(self.suspend()),
            },
            libc::SIGINT => Err(self.destroy(128 + libc::SIGINT)),
            _ => Ok(()),
        };
        if let Err(e) = res {
            eprintln!("vm {}: signal {sig}: {e}", vm.name);
        }
    }

    fn control(self: &Arc<Self>, c: UnixStream) {
        let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
        let (line, fds) = match crate::util::recv_with_fds(&c, 1 << 20) {
            Ok(got) => got,
            Err(e) => return drop(send_json(&mut &c, &json!({"ok": false, "error": format!("bad request: {e}")}))),
        };
        let _ = c.set_read_timeout(None);
        let Ok(req) = serde_json::from_slice::<Value>(&line) else { return };
        let reply = match req["op"].as_str().unwrap_or("") {
            "exec" => return self.exec(&req, c),
            "pages" => return self.pages(&req, fds),
            "checkpoint" => self.op_within().and_then(|op| {
                let stop = req["stop"] == true;
                if stop {
                    self.settle_arrival(&op, crate::lifecycle::DRAIN_WAIT)?;
                }
                let v = self.checkpoint(&op, req["dir"].as_str().unwrap_or(""), stop, req["incremental"] == true)?;
                if stop {
                    self.finish(&op, End::Gone, 0, Some((&c, json!({"ok": true, "result": v}))));
                }
                Ok(v)
            }),
            "migrate" => self.migrate(req["to"].as_str().unwrap_or(""), req["if_idle"] == true, req["evict"] == true),
            "debug" => self.debug(&req),
            "claim" => Err("this vm is not a standby vm".into()),
            op => Err(format!("unknown op {op:?}").into()),
        };
        let _ = send_json(&mut &c, &reply.map_or_else(|e| json!({"ok": false, "error": e.to_string()}), |v| json!({"ok": true, "result": v})));
    }

    fn pages(&self, req: &Value, fds: Vec<OwnedFd>) {
        let Some(fd) = fds.into_iter().next() else { return };
        let s = std::net::TcpStream::from(fd);
        let (vm, source) = (self.vm(), req["mig"].as_u64().map(State::Source));
        if source != Some(vm.state()) {
            return crate::listen::refuse_pages(s, &format!("vm {} is not the source of migration {}", vm.name, req["mig"]));
        }
        if fault("pages") {
            return crate::listen::refuse_pages(s, "injected fault: page server down");
        }
        let _ = s.set_nodelay(true);
        let served = send_json(&mut &s, &json!({"ok": true}))
            .and_then(|()| crate::uffd::serve_pages(&vm.pager, &s, &s, || fault("pages") || Some(vm.state()) != source));
        if let Err(e) = served {
            eprintln!("vm {}: page server: {e}", vm.name);
        }
    }

    fn exec(&self, req: &Value, c: UnixStream) {
        let mut w = &c;
        let vm = self.vm();
        let cmd = req["cmd"].as_str().unwrap_or("");
        let mut once = None;
        let started = vm.exec(|s| match req["session"].as_str() {
            Some(id) => guest::session(s, req["action"].as_str().unwrap_or("start"), id, req["offset"].as_u64().unwrap_or(0), cmd, guest::TIMEOUT),
            None => guest::start_exec(s, cmd, guest::TIMEOUT).map(|(g, id)| {
                once = Some(id);
                g
            }),
        });
        let (mut g, id) = match started {
            Ok(g) => g,
            Err(e) => {
                let _ = send_json(&mut w, &json!({"ok": false, "error": e.to_string()}));
                return;
            }
        };
        let _ = (|| -> Result<()> {
            if req["action"] == "close" {
                g.get_ref().set_read_timeout(Some(Duration::from_secs(2)))?;
                let closed = matches!(guest::read_frame(&mut g)?, Some((guest::FRAME_MSG, data)) if data == b"closed");
                return Ok(send_json(&mut w, &json!({"ok": closed, "error": "session close failed"}))?);
            }
            if req["session"].is_string() {
                // The guest heartbeats every second; silence means the VM moved.
                g.get_ref().set_read_timeout(Some(Duration::from_secs(3)))?;
            }
            send_json(&mut w, &json!({"ok": true}))?;
            if let Some(id) = &once {
                let code = guest::exec_output(&mut g, id, |kind, data| Ok(guest::write_frame(&mut w, kind, data)?))?;
                guest::write_frame(&mut w, guest::FRAME_EXIT, &code.to_le_bytes())?;
                return guest::close(&vm.vsock, id, Instant::now() + guest::TIMEOUT);
            }
            std::io::copy(&mut g, &mut w)?;
            Ok(())
        })();
        vm.untrack_exec(id);
    }

    fn debug(&self, req: &Value) -> Result<Value> {
        if req["what"] != "status" && std::env::var("FLEXVM_FAULTS").ok().as_deref() != Some("1") {
            bail!("memhash needs FLEXVM_FAULTS=1");
        }
        let vm = self.vm();
        match req["what"].as_str().unwrap_or("") {
            "memhash" => self.memhash(),
            "hotplug" => {
                let _op = self.op_within()?;
                if vm.state() != State::Running {
                    bail!("vm {} is not running here", vm.name);
                }
                *vm.last_resize.lock().unwrap() = Instant::now();
                let mib = req["mib"].as_u64().ok_or("missing mib")?.min(vm.template.meta.max_mib - vm.template.meta.mem_mib);
                vm.limit.plug(vm.template.meta.mem_mib + mib, 0);
                vm.fc(|fc| fc.patch("/hotplug/memory", json!({"requested_size_mib": mib})))?;
                Ok(json!(mib))
            }
            "status" => Ok(json!({
                "state": vm.state().name(),
                "background_pull_ms": vm.pager.pull_time().map(ms),
                "remote_left": vm.pager.remote_left(),
                "failed": vm.pager.failed(),
                "checkpoint_copy_stats": vm.pager.copy_stats(),
                "faults": vm.pager.fault_stats.report(),
                "discards": vm.pager.discards(),
                "install_eagain": vm.pager.install_eagain(),
                "describe": vm.describe(),
                "guest_retries": guest::retries(),
                "controller": self.ticks.lock().unwrap().json(),
            })),
            w => bail!("unknown debug request {w:?}"),
        }
    }

    /// Not for a migration source, whose end its target decides. An operation
    /// in progress is interrupted, not waited out (#122): its calls on the
    /// guest, Firecracker and pager fail at once and a checkpoint is cancelled,
    /// so `op` comes free promptly.
    fn died(&self) {
        let vm = self.vm();
        if matches!(vm.state(), State::Source(_)) || self.leaving.load(Ordering::SeqCst) {
            return;
        }
        vm.mark_dead();
        vm.cancel_checkpoint.fetch_add(1, Ordering::SeqCst);
        vm.pager.abort_copy();
        let op = self.op();
        if self.leaving.load(Ordering::SeqCst) {
            return;
        }
        self.end_died(&op)
    }

    /// Death's end: why goes in `RUN/vms/NAME.failed`, exit 124.
    pub fn end_died(&self, op: &Op) -> ! {
        let vm = self.vm();
        let why = format!("{}; {}", vm.pager.failed().unwrap_or("its firecracker exited"), vm.post_mortem());
        eprintln!("vm {}: died: {why}", vm.name);
        let _ = std::fs::write(self.host.vms(&vm.name, "failed"), &why);
        self.finish(op, End::Died, DIED, None)
    }

    fn controller(self: Arc<Self>) {
        let (mut published, mut growth) = (false, Growth::default());
        loop {
            thread::sleep(Duration::from_secs(1));
            self.ticks.lock().unwrap().tick();
            let vm = self.vm();
            if !vm.firecracker_alive() || vm.pager.failed().is_some() {
                self.died();
            }
            if let Ok(_op) = self.op.try_lock() {
                if vm.release_pending() && matches!(vm.state(), State::Running | State::Paused) {
                    match vm.release_reports(Duration::from_millis(500)) {
                        Ok(()) => eprintln!("vm {}: released free page reports", vm.name),
                        Err(e) => eprintln!("vm {}: releasing free page reports: {e}", vm.name),
                    }
                }
            }
            if let Err(e) = self.resize(None) {
                eprintln!("vm {}: resize: {e}", vm.name);
            }
            // An arrival's pull is not growth.
            let used = vm.limit.used().unwrap_or_else(|| vm.rss() >> 20);
            let rate = growth.sample(Instant::now(), used, self.arrived.lock().unwrap().is_some());
            let was = self.growth.swap(rate, Ordering::SeqCst);
            // Throttling (`watch_memory`) changes it between ticks too.
            if published != vm.starving() || growth_bucket(rate) != growth_bucket(was) {
                published = vm.starving();
                self.publish();
            }
            relieve(&self.host, host_available_mib(), vm.starving());
        }
    }

    /// During a COW checkpoint's copy the VM may still grow: memory plugged
    /// after the pause was never populated, so the copy never reads it.
    fn resize(&self, hint: Option<u64>) -> Result<Resized> {
        let vm = self.vm();
        if let Ok(_op) = self.op.try_lock() {
            return resize(vm, &self.host, hint, false);
        }
        match *vm.cow_copy.lock().unwrap() {
            true => resize(vm, &self.host, hint, true),
            false => Ok(Resized::Busy),
        }
    }

    fn watch_memory(self: Arc<Self>) {
        let vm = self.vm().clone();
        // Only while it runs here: a paused or migrating VM touches nothing, and a
        // source sitting at its mark through the pull is not starved.
        vm.limit.watch(&self.host, Duration::from_secs(1), || vm.pid().is_some(), || vm.state() == State::Running);
    }

    /// The guest is untrusted: requests are bounded in size and time and
    /// acted on at most once per `MEM_REQUEST_GAP`.
    fn serve_memory(self: Arc<Self>) {
        let vm = self.vm().clone();
        let _ = std::fs::remove_file(vm.mem_sock());
        let listener = match UnixListener::bind(vm.mem_sock()) {
            Ok(l) => l,
            Err(e) => return eprintln!("vm {}: memory requests: {e}", vm.name),
        };
        let mut acted: Option<Instant> = None;
        for conn in listener.incoming() {
            if vm.pid().is_none() {
                break;
            }
            let conn = match conn {
                Ok(c) => c,
                Err(e) => {
                    crate::util::accept_failed("memory requests", &e);
                    continue;
                }
            };
            let _ = conn.set_write_timeout(Some(MEM_REQUEST_DEADLINE));
            let Some(avail) = read_mem_request(&conn) else { continue };
            let reply = if acted.is_some_and(|t| t.elapsed() < MEM_REQUEST_GAP) {
                "busy"
            } else {
                acted = Some(Instant::now());
                match self.resize(Some(avail)) {
                    Ok(Resized::Grew) => "grow",
                    Ok(Resized::Full) => "full",
                    Ok(Resized::Same) => "ok",
                    Ok(Resized::Busy) => "busy",
                    Err(e) => {
                        eprintln!("vm {}: resize on request: {e}", vm.name);
                        "busy"
                    }
                }
            };
            let _ = (&conn).write_all(format!("{reply}\n").as_bytes());
        }
    }

    fn follow_app(self: Arc<Self>) {
        let vm = self.vm().clone();
        while vm.state().local() {
            let got = vm.exec(|s| guest::start_logs(s, self.app_log.load(Ordering::SeqCst), true, guest::TIMEOUT));
            if let Ok((mut g, id)) = got {
                let _ = g.get_ref().set_read_timeout(None);
                while let Ok(Some((kind, data))) = guest::read_frame(&mut g) {
                    // The guest's ring moved past us (or we asked past its end): it goes on from there.
                    if let (guest::FRAME_LOST, Ok(at)) = (kind, <[u8; 8]>::try_from(&data[..data.len().min(8)])) {
                        let (at, was) = (u64::from_le_bytes(at), self.app_log.load(Ordering::SeqCst));
                        if at > was {
                            eprintln!("vm {}: {} bytes of app output lost (the guest keeps its last 1 MiB)", vm.name, at - was);
                        }
                        self.app_log.store(at, Ordering::SeqCst);
                        continue;
                    }
                    if kind == guest::FRAME_MSG {
                        let status = String::from_utf8_lossy(&data);
                        if !status.starts_with("running") {
                            eprintln!("vm {}: app {}", vm.name, status.rsplit_once(' ').map(|(s, _)| s).unwrap_or(&status));
                            vm.untrack_exec(id);
                            return;
                        }
                        break;
                    }
                    let mut out = std::io::stdout().lock();
                    while crate::lifecycle::APP_LOG_HELD.load(Ordering::SeqCst) {
                        drop(out);
                        thread::sleep(Duration::from_millis(10));
                        out = std::io::stdout().lock();
                    }
                    let _ = out.write_all(&data).and_then(|()| out.flush());
                    self.app_log.fetch_add(data.len() as u64, Ordering::SeqCst);
                }
                vm.untrack_exec(id);
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    /// A suspend takes the command along: while one runs the command is never
    /// given up, nor the VM ended; the suspend ends the process, or fails and
    /// the command goes on (reattaching, or ending the VM if it exited meanwhile).
    fn main_command(self: Arc<Self>) {
        let cmd = self.cmd.lock().unwrap().clone().unwrap_or_default();
        loop {
            let res = self.cmd_session().and_then(|s| crate::exec_session(&self.host, &self.name(), &cmd, s, true));
            let suspending = self.suspending.lock().unwrap();
            if *suspending {
                // Afterwards an exit status already received is in the session: the next try returns it.
                drop(suspending);
                while *self.suspending.lock().unwrap() {
                    thread::sleep(Duration::from_millis(20));
                }
                continue;
            }
            let code = res.unwrap_or_else(|e| {
                eprintln!("vm {}: {e}", self.name());
                FAILED
            });
            // Holding `suspending`: no suspend starts until the VM is gone (or the kill refused).
            return eprintln!("vm {}: {}", self.name(), self.destroy(code));
        }
    }

    /// One per VM, whoever asks first (the command, or a suspend before it started).
    pub fn cmd_session(&self) -> Result<&Mutex<crate::Session>> {
        if let Some(s) = self.cmd_session.get() {
            return Ok(s);
        }
        let new = crate::Session::new()?;
        Ok(self.cmd_session.get_or_init(|| Mutex::new(new)))
    }

    pub fn stop_requested(&self) -> bool {
        self.early.lock().unwrap().iter().any(|&s| s == libc::SIGINT || s == libc::SIGTERM)
    }

    pub fn forget_stop(&self) {
        self.early.lock().unwrap().retain(|&s| s != libc::SIGINT && s != libc::SIGTERM);
    }

    pub fn arc(&self) -> Option<Arc<Proc>> {
        self.me.upgrade()
    }

    pub fn set_leaving(&self, v: bool) {
        self.leaving.store(v, Ordering::SeqCst);
    }

    /// Under the op lock, so never inside a snapshot.
    pub fn sync_clock_later(&self) {
        let vm = self.vm().clone();
        let Some(p) = self.me.upgrade().filter(|_| !vm.clock_pending.swap(true, Ordering::SeqCst)) else { return };
        thread::spawn(move || {
            let res = {
                let _op = p.op();
                match vm.state() {
                    State::Running => vm.sync_clock(Instant::now() + CLOCK_DEADLINE).map(Some),
                    _ => Ok(None),
                }
            };
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

pub fn main(host: Host, paths: Paths, start: Start, mut notify: Option<std::fs::File>) -> Result<()> {
    // Blocked first: every thread from here on (the output relays too) inherits it.
    let signals = crate::util::block_signals(&SIGNALS);
    crate::util::output::guard()?;
    let _ = crate::net::sysctl("net.ipv4.ip_forward", "1");
    if let Some(dev) = &host.cfg.announce_dev {
        if let Err(e) = crate::net::sysctl(&format!("net.ipv4.conf.{dev}.proxy_arp"), "1") {
            eprintln!("WARNING: proxy ARP on {dev}: {e}");
        }
    }
    let p = Proc::new(host, paths)?;
    let (host, templates) = (p.host.clone(), p.paths.templates.clone());
    thread::spawn(move || {
        crate::gc::sweep(&host, Some(&templates));
        crate::gc::periodic(host, Some(templates));
    });
    let s = p.clone();
    thread::spawn(move || loop {
        // Ctrl-\ quits like Ctrl-C: the VM is destroyed, not dumped.
        s.signal(match crate::util::wait_signal(&signals) {
            libc::SIGQUIT => libc::SIGINT,
            sig => sig,
        });
    });
    let op = p.op();
    let res = match start {
        Start::Run { name, template, ip, cmd } => {
            *p.cmd.lock().unwrap() = cmd;
            p.run(&name, &template, ip)
        }
        Start::Resume { name } => p.resume_suspended(&name),
        Start::Restore { dir, name, ip, paused } => p.restore(&dir, name.as_deref(), ip.as_deref(), paused),
        Start::Incoming { req } => {
            let log = std::env::var_os("FLEXVM_INCOMING_LOG").map(PathBuf::from);
            std::env::remove_var("FLEXVM_INCOMING_LOG");
            // Its own lock as well as its stdout's, until the log is published or removed.
            let _held = log.as_ref().and_then(|l| std::fs::File::open(l).ok()).filter(|f| crate::host::flock(f, libc::LOCK_SH).is_ok());
            let res = p.migrate_in(&req, unsafe { std::net::TcpStream::from_raw_fd(3) });
            if let Some(log) = log {
                if let Err(e) = crate::listen::finish_incoming_log(&p.host, &p.name(), &log, res.is_ok()) {
                    eprintln!("arrival log {}: {e}", log.display());
                }
            }
            res.map(|()| Value::Null)
        }
        Start::Standby { template } => crate::standby::serve(&p, &template, &mut notify, &op),
    };
    if res.is_ok() {
        p.serve_control();
        // Once running (a standby once claimed), so a start never competes with a refill.
        crate::standby::maintain(p.host.clone());
    }
    let reply = match &res {
        Ok(v) => json!({"ok": true, "result": v}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    };
    match notify.take() {
        Some(mut f) => drop(send_json(&mut f, &reply)),
        None if res.is_ok() && !reply["result"].is_null() => eprintln!("{}", reply["result"]),
        None => {}
    }
    if let Err(e) = res {
        eprintln!("flexvm: {e}");
        p.finish(&op, End::NotStarted, FAILED, None);
    }
    drop(op);
    p.serve()
}

pub fn cgroup_root() -> Option<PathBuf> {
    let root = PathBuf::from("/sys/fs/cgroup/flexvm");
    let setup = || -> Result<()> {
        if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            bail!("no cgroup2 hierarchy mounted at /sys/fs/cgroup");
        }
        std::fs::create_dir_all(&root)?;
        let ctl = std::fs::read_to_string(root.join("cgroup.subtree_control")).unwrap_or_default();
        if !(ctl.contains("cpu") && ctl.contains("memory")) {
            std::fs::write(root.join("cgroup.subtree_control"), "+cpu +memory")?;
        }
        Ok(())
    };
    static WARNED: AtomicBool = AtomicBool::new(false);
    match setup() {
        Ok(()) => Some(root),
        Err(e) if !WARNED.swap(true, Ordering::Relaxed) => {
            eprintln!("WARNING: per-VM cgroups unavailable: {e}");
            None
        }
        Err(_) => None,
    }
}

/// None if it cannot be read: never taken for 0 (pressure). Test fault `no_meminfo`.
pub fn host_available_mib() -> Option<u64> {
    if fault("no_meminfo") {
        return None;
    }
    Some(proc_kb("/proc/meminfo", "MemAvailable")? >> 20)
}

#[derive(Debug, PartialEq)]
pub enum Resized {
    Grew,
    Same,
    Busy,
    /// Short, and at its ceiling or refused by the host's reserve.
    Full,
}

/// Keeps `headroom` free via hotplug, never below the template's size. The
/// guest is untrusted: its free memory (`hint` or balloon stats) only steers
/// bounded, reserve-admitted growth. Callers hold the op lock (or copy-growth).
fn resize(vm: &Vm, host: &Host, hint: Option<u64>, grow_only: bool) -> Result<Resized> {
    let meta = &vm.template.meta;
    let hotplug_total = meta.max_mib - meta.mem_mib;
    if hotplug_total == 0 {
        return Ok(Resized::Full);
    }
    let mut last = vm.last_resize.lock().unwrap();
    if vm.state() != State::Running {
        return Ok(Resized::Busy);
    }
    let (stats, hp) = vm.fc(|fc| Ok((if hint.is_none() { fc.get("/balloon/statistics")? } else { Value::Null }, fc.get("/hotplug/memory")?)))?;
    let (requested, plugged) = (hp["requested_size_mib"].as_u64().ok_or("no hotplug state")?, hp["plugged_size_mib"].as_u64().ok_or("no hotplug state")?);
    let avail = match hint {
        Some(avail) => avail,
        None if stats["total_memory"].as_u64().unwrap_or(0) == 0 => return Ok(Resized::Same), // no stats yet
        None => stats["available_memory"].as_u64().unwrap_or(0) >> 20,
    };
    let sizes = Sizes { mem_mib: meta.mem_mib, floor: meta.plugged_mib.min(hotplug_total), hotplug_total };
    let Some(plan) = sizes.plan(requested, plugged, avail, last.elapsed(), hint.is_some(), grow_only) else {
        return Ok(Resized::Busy);
    };
    let refused = plan.charge > 0 && !host.admit(plan.charge)?;
    let full = plan.short && (plugged == hotplug_total || refused);
    // Starved only when the host refused it: at its own ceiling, moving it cannot help.
    vm.starved.store(plan.short && refused, Ordering::SeqCst);
    let new = if refused { plugged } else { plan.new };
    if new != requested {
        let why = if plan.settle { "stalled" } else if hint.is_some() { "guest asked" } else { "tick" };
        eprintln!("vm {}: available {avail} MiB, hotplug {requested} (plugged {plugged}) -> {new} MiB ({why})", vm.name);
        if new > requested {
            vm.limit.plug(meta.mem_mib + new, if refused { 0 } else { plan.charge });
        }
        vm.fc(|fc| fc.patch("/hotplug/memory", json!({"requested_size_mib": new})))?;
        *last = Instant::now();
    } else if requested == plugged {
        vm.limit.settled(meta.mem_mib + plugged);
    }
    Ok(if new > plugged {
        Resized::Grew
    } else if full {
        Resized::Full
    } else {
        Resized::Same
    })
}

/// How long a resize may go unfinished before it settles at what is plugged.
const RESIZE_STALL: Duration = Duration::from_secs(10);

/// A VM's hotplug geometry (MiB): boot memory, the template's plug (never
/// shrunk below) and the hotplug region.
struct Sizes {
    mem_mib: u64,
    floor: u64,
    hotplug_total: u64,
}

#[derive(Debug, PartialEq)]
struct Plan {
    /// A resize unfinished for RESIZE_STALL is settled first (requested =
    /// plugged), which also restarts the delays below.
    settle: bool,
    new: u64,
    /// Growth past both plugged and requested: an outstanding request is
    /// never charged twice against the host's reserve.
    charge: u64,
    /// The guest has less free than its headroom.
    short: bool,
}

impl Sizes {
    /// None while a resize is still being carried out (`busy`).
    fn plan(&self, requested: u64, plugged: u64, avail: u64, since: Duration, asked: bool, grow_only: bool) -> Option<Plan> {
        // The guest may never finish a resize: kernel-zone blocks (BOOT_ARGS)
        // or memory in use can keep it from unplugging.
        let settle = plugged != requested && since > RESIZE_STALL;
        let (requested, since) = if settle { (plugged, Duration::ZERO) } else { (requested, since) };
        if plugged < requested {
            return None; // growing
        }
        let total = self.mem_mib + plugged;
        let avail = avail.min(total);
        let headroom = guest::headroom(total);
        let round = |mib: u64| mib.div_ceil(STEP_MIB) * STEP_MIB;
        // Balloon statistics lag a plug by up to a second.
        let stale = !asked && since < Duration::from_millis(1500);
        let short = avail < headroom;
        let urgent = short && !stale;
        if plugged > requested && !urgent {
            return None; // shrinking
        }
        // Sizes count from what is plugged: urgent growth cancels a pending shrink.
        let new = if urgent {
            (plugged + round(headroom * 2 - avail).min(round(total / 4).max(STEP_MIB))).min(self.hotplug_total)
        } else if !grow_only && avail > headroom * 3 && plugged > self.floor && since > Duration::from_secs(10) {
            plugged.saturating_sub((avail - headroom * 2) / STEP_MIB * STEP_MIB).max(self.floor)
        } else {
            plugged
        };
        Some(Plan { settle, new, charge: new.saturating_sub(requested.max(plugged)), short })
    }
}

const MEM_REQUEST_MAX: usize = 128;
const MEM_REQUEST_DEADLINE: Duration = Duration::from_millis(500);
const MEM_REQUEST_GAP: Duration = Duration::from_millis(50);

/// `MEM <available KiB> <total KiB>\n` -> available MiB.
fn read_mem_request(conn: &UnixStream) -> Option<u64> {
    use std::io::Read;
    let deadline = Instant::now() + MEM_REQUEST_DEADLINE;
    let (mut buf, mut len) = ([0u8; MEM_REQUEST_MAX], 0);
    while !buf[..len].contains(&b'\n') {
        let left = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
        if len == buf.len() || conn.set_read_timeout(Some(left)).is_err() {
            return None;
        }
        match (&*conn).read(&mut buf[len..]) {
            Ok(0) | Err(_) => return None,
            Ok(n) => len += n,
        }
    }
    let mut f = std::str::from_utf8(&buf[..len]).ok()?.split('\n').next()?.split(' ');
    match (f.next(), f.next().map(str::parse::<u64>), f.next().map(str::parse::<u64>), f.next()) {
        (Some("MEM"), Some(Ok(avail_kib)), Some(Ok(_)), None) => Some(avail_kib >> 10),
        _ => None,
    }
}

/// How long one eviction may take: from asking a VM to migrate until its
/// copy here exits (once the target has all its memory), freeing it.
const EVICT_DEADLINE: Duration = Duration::from_secs(60);
/// Growth is measured over the controller's ticks of the last 5 s.
const GROWTH_WINDOW: Duration = Duration::from_secs(5);
/// Slower growth (MiB/s) is noise, not a trend.
const GROWTH_FLOOR: u64 = 8;

/// A VM's memory (MiB) over the last `GROWTH_WINDOW`.
#[derive(Default)]
struct Growth {
    samples: std::collections::VecDeque<(Instant, u64)>,
}

impl Growth {
    /// MiB/s over the window; 0 until it spans half a second, and while
    /// `reset` (an arrival's pull is not growth).
    fn sample(&mut self, now: Instant, mib: u64, reset: bool) -> u64 {
        if reset {
            self.samples.clear();
            return 0;
        }
        while self.samples.front().is_some_and(|&(t, _)| now.saturating_duration_since(t) > GROWTH_WINDOW) {
            self.samples.pop_front();
        }
        self.samples.push_back((now, mib));
        let (t0, m0) = self.samples[0];
        let secs = now.saturating_duration_since(t0).as_secs_f64();
        if secs < 0.5 {
            return 0;
        }
        (mib.saturating_sub(m0) as f64 / secs) as u64
    }
}

/// Growth in powers of two above the floor: what is published and ranked,
/// so the registry is not rewritten for every small change.
fn growth_bucket(mib_s: u64) -> u32 {
    if mib_s < GROWTH_FLOOR {
        0
    } else {
        mib_s.ilog2()
    }
}

/// Eviction's candidates, in order: the starved (refused here, throttled),
/// then the fastest growing, then the biggest (`rss`, MiB).
/// A VM running `run -- CMD` is not one: CMD's end there would not end it.
fn rank(mut vms: Vec<Entry>, rss: impl Fn(&Entry) -> u64) -> Vec<Entry> {
    vms.retain(|e| e.state == "running" && !e.cmd);
    vms.sort_by_cached_key(|e| (!e.starved, std::cmp::Reverse(growth_bucket(e.growth_mib_s)), std::cmp::Reverse(rss(e))));
    vms
}

/// Per VM and peer (a peer may refuse a big VM but take a small one), in
/// RUN/evict.backoff under evict.lock, so changing deciders share it and a
/// reboot clears it. An entry a minute past its cooldown is forgotten.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct PeerBackoff {
    delay: u64,
    until: u64,
}

impl PeerBackoff {
    fn ready(&self, now: u64) -> bool {
        now >= self.until
    }

    fn refuse(&mut self, now: u64) {
        self.delay = self.delay.saturating_mul(2).clamp(5, 60);
        self.until = now.saturating_add(self.delay);
    }
}

fn eviction_time() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Whether this process is running an eviction (on its own thread).
static EVICTING: AtomicBool = AtomicBool::new(false);

/// Under pressure standby VMs go first, then VMs move to peers. Every VM
/// process calls this each tick; the `STATE/evict.lock` holder decides, at
/// most every 5 s, and runs the eviction on a thread of its own that keeps
/// the lock until it is done, so the controller ticks on meanwhile.
///
/// Pressure starts when MemAvailable falls under the high-water mark
/// (`evict_at`, above the reserve) and lasts until it is back to
/// `evict_until` (`RUN/evict.active` while it lasts). A starved VM is moved
/// whenever it asks, pressure or not. Nothing is done when MemAvailable
/// cannot be read (`avail` None): that is no pressure.
fn relieve(host: &Host, avail: Option<u64>, starved_here: bool) {
    let Some(avail) = avail else { return };
    let cfg = host.config_now();
    let (reserve, at, until) = (cfg.reserve_mib, cfg.evict_at(), cfg.evict_until());
    // Standby VMs go under the reserve whatever eviction is doing (a slow migration holds its lock).
    if avail < reserve && stop_standby(host, avail, reserve) {
        return;
    }
    let active = host.run.join("evict.active");
    let evicting = active.exists();
    if (avail >= at && !evicting && !starved_here) || EVICTING.load(Ordering::SeqCst) {
        return;
    }
    let Ok(lock) = std::fs::File::options().create(true).truncate(false).write(true).open(host.state.join("evict.lock")) else { return };
    if crate::host::flock(&lock, libc::LOCK_EX | libc::LOCK_NB).is_err() {
        return;
    }
    let pressure = avail < until && (evicting || avail < at);
    if pressure && !evicting {
        let _ = std::fs::write(&active, b"");
        eprintln!("host has {avail} MiB available, under its {at} MiB high-water mark ({reserve} MiB reserve): moving vms to peers until it has {until} MiB");
    } else if !pressure && evicting {
        let _ = std::fs::remove_file(&active);
        eprintln!("host has {avail} MiB available, {until} MiB or more: eviction stops");
    }
    if !pressure && !starved_here {
        return;
    }
    let last = host.state.join("evict.last");
    let recent = std::fs::metadata(&last).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
    if cfg.peers.is_empty() || recent.is_some_and(|d| d < Duration::from_secs(5)) {
        return;
    }
    if fault("no_evict") {
        return;
    }
    let rss = |e: &Entry| e.firecracker.and_then(|p| proc_kb(&format!("/proc/{p}/status"), "VmRSS")).unwrap_or(0) >> 10;
    let mut vms = rank(host.entries(), rss);    if !pressure {
        vms.retain(|e| e.starved);
    }
    if vms.is_empty() {
        return;
    }
    let _ = std::fs::write(&last, b"");
    EVICTING.store(true, Ordering::SeqCst);
    let host = host.clone();
    thread::spawn(move || {
        let _lock = lock;
        // Arrivals by eviction are refused while it runs (`Floor::EvictMark`).
        let _worker = match host.evict_worker_lock() {
            Ok(w) => w,
            Err(e) => {
                EVICTING.store(false, Ordering::SeqCst);
                return eprintln!("eviction: {e}");
            }
        };
        evict(&host, &cfg.peers, &vms, avail, Instant::now() + EVICT_DEADLINE);
        EVICTING.store(false, Ordering::SeqCst);
    });
}

/// Under the reserve: SIGINTs the standby VMs, under `STATE/standby.stop.lock`
/// (not eviction's lock, which a migration may hold for a while). True if
/// it stopped any.
fn stop_standby(host: &Host, avail: u64, reserve: u64) -> bool {
    let Ok(lock) = std::fs::File::options().create(true).truncate(false).write(true).open(host.state.join("standby.stop.lock")) else { return false };
    if crate::host::flock(&lock, libc::LOCK_EX | libc::LOCK_NB).is_err() {
        return false;
    }
    let standby: Vec<_> = crate::standby::templates(host).iter().flat_map(|t| crate::standby::live(host, t)).collect();
    standby.iter().for_each(crate::standby::stop);
    if standby.is_empty() {
        return false;
    }
    let _ = std::fs::write(crate::standby::pressure(host), b"");
    eprintln!("host has {avail} MiB available, under its {reserve} MiB reserve: stopped {} standby vms", standby.len());
    true
}

/// Moves the first of `vms` that a peer takes, and waits (until `deadline`)
/// for its copy here to go, so the next decision sees its memory freed.
/// A VM busy with anything (a checkpoint's copy, a migration, an arrival
/// settling) is skipped, never waited for: `if_idle`.
fn evict(host: &Host, peers: &[String], vms: &[Entry], avail: u64, deadline: Instant) {
    let backoff_path = host.run.join("evict.backoff");
    let Ok(saved) = crate::host::load::<std::collections::HashMap<String, PeerBackoff>>(&backoff_path) else { return };
    let mut backoff = saved.unwrap_or_default();
    let now = eviction_time();
    backoff.retain(|_, b| now < b.until.saturating_add(60));
    for vm in vms {
        let why = match (vm.starved, growth_bucket(vm.growth_mib_s)) {
            (true, _) => "cannot grow here".to_string(),
            (false, 0) => "the host is low on memory".to_string(),
            (false, _) => format!("the host is low on memory and it grows {} MiB/s", vm.growth_mib_s),
        };
        for peer in peers {
            let key = format!("{} {peer}", vm.name);
            if backoff.get(&key).is_some_and(|b| !b.ready(eviction_time())) {
                continue;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else { return };
            eprintln!("vm {}: {why} ({avail} MiB available); migrating to {peer}", vm.name);
            match call_within(host, &vm.name, json!({"op": "migrate", "to": peer, "if_idle": true, "evict": true}), left) {
                Ok(_) => {
                    backoff.remove(&key);
                    let _ = crate::host::store(&backoff_path, &backoff, false);
                    eprintln!("vm {}: migrated to {peer}", vm.name);
                    while host.entry(&vm.name).is_ok_and(|e| e.ident == vm.ident) {
                        if Instant::now() >= deadline {
                            return eprintln!("vm {}: its copy here still serves pages to {peer} at the eviction's deadline", vm.name);
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    return;
                }
                Err(e) if e.to_string().contains(BUSY) => break,
                // No answer is no refusal: the VM may still be migrating (busy to the next decider).
                Err(e) if Instant::now() >= deadline => {
                    return eprintln!("vm {}: migrating to {peer}: no answer by the eviction's deadline: {e}", vm.name);
                }
                Err(e) => {
                    eprintln!("vm {}: migrating to {peer}: {e}", vm.name);
                    backoff.entry(key).or_default().refuse(eviction_time());
                    if crate::host::store(&backoff_path, &backoff, false).is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// What `migrate` with `if_idle` answers for a VM busy with something else.
pub const BUSY: &str = "busy with another operation";

fn answer(reply: Option<Value>, who: &str) -> Result<Value> {
    let reply = reply.ok_or_else(|| format!("{who} hung up"))?;
    if reply["ok"] != json!(true) {
        bail!("{}", reply["error"].as_str().unwrap_or("refused"));
    }
    Ok(reply["result"].clone())
}

pub fn peer_call(peer: &str, req: Value) -> Result<Value> {
    let mut c = crate::util::connect(peer, Duration::from_millis(500))?;
    c.set_read_timeout(Some(Duration::from_secs(2)))?;
    c.set_write_timeout(Some(Duration::from_secs(2)))?;
    send_json(&mut c, &req)?;
    answer(crate::util::recv_json(&mut BufReader::new(c))?, peer)
}

pub fn tell_peers(host: &Host, req: Value) {
    let sends: Vec<_> = host.cfg.peers.iter().cloned().map(|p| {
        let req = req.clone();
        thread::spawn(move || peer_call(&p, req))
    }).collect();
    sends.into_iter().for_each(|s| drop(s.join()));
}

pub fn connect(host: &Host, name: &str, req: &Value, fds: &[i32]) -> Result<UnixStream> {
    let c = UnixStream::connect(host.sock(name)).map_err(|e| {
        if host.alive(name) {
            format!("vm {name:?} is starting or its control socket is unavailable; retry once it is ready, or see {}: {e}", host.vms(name, "log").display())
        } else if host.is_suspended(name) {
            format!("vm {name:?} is suspended; use flexvm resume {name} first")
        } else {
            format!("no vm named {name:?}")
        }
    })?;
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    crate::util::send_with_fds(&c, &line, fds)?;
    Ok(c)
}

pub fn call(host: &Host, name: &str, req: Value) -> Result<Value> {
    answer(crate::util::recv_json(&mut BufReader::new(connect(host, name, &req, &[])?))?, &format!("vm {name}"))
}

/// `call`, giving up on the answer after `wait`.
fn call_within(host: &Host, name: &str, req: Value, wait: Duration) -> Result<Value> {
    let c = connect(host, name, &req, &[])?;
    c.set_read_timeout(Some(wait))?;
    answer(crate::util::recv_json(&mut BufReader::new(c))?, &format!("vm {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MemAvailable unreadable (None) is no pressure: no standby is stopped
    /// and no eviction is tried; read as under the reserve, both are.
    #[test]
    fn unreadable_meminfo_relieves_nothing() {
        use std::os::fd::AsRawFd;
        let base = std::env::temp_dir().join(format!("flexvm-relieve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let mut host = Host::open(&base.join("state"), &base.join("run")).unwrap();
        host.cfg.reserve_mib = 1024;
        host.cfg.peers = vec!["127.0.0.1:1".into()];
        // A standby of template t: its lock held, naming a live process.
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let d = host.run.join("standby").join("t");
        std::fs::create_dir_all(&d).unwrap();
        let lock = std::fs::File::create(d.join(format!("{}.lock", child.id()))).unwrap();
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
        std::fs::write(d.join(format!("{}.lock", child.id())), serde_json::to_vec(&Ident::of(child.id()).unwrap()).unwrap()).unwrap();
        assert_eq!(crate::standby::live(&host, "t").len(), 1);
        let (pressure, active) = (crate::standby::pressure(&host), host.run.join("evict.active"));
        for starved in [false, true] {
            relieve(&host, None, starved);
            assert!(!pressure.exists() && !active.exists());
            assert!(child.try_wait().unwrap().is_none(), "a standby was stopped");
        }
        relieve(&host, Some(0), false);
        use std::os::unix::process::ExitStatusExt;
        assert!(pressure.exists() && child.wait().unwrap().signal() == Some(libc::SIGINT));
        drop(lock);
        relieve(&host, Some(0), false);
        assert!(active.exists(), "with no standby left, eviction starts");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn refused_peers_back_off_independently_and_survive_a_new_decider() {
        let mut peers = std::collections::HashMap::<String, PeerBackoff>::new();
        let mut now = 100;
        for delay in [5, 10, 20, 40, 60, 60] {
            let peer = peers.entry("peer-a".into()).or_default();
            assert!(peer.ready(now));
            peer.refuse(now);
            assert_eq!(peer.delay, delay);
            assert!(!peer.ready(now + delay - 1));
            assert!(peer.ready(now + delay));
            assert!(peers.entry("peer-b".into()).or_default().ready(now));
            peers = serde_json::from_slice(&serde_json::to_vec(&peers).unwrap()).unwrap();
            assert!(!peers["peer-a"].ready(now));
            now += delay;
        }
    }

    #[test]
    fn eviction_takes_the_starved_then_the_fastest_growing_then_the_biggest() {
        let vm = |name: &str, starved, growth_mib_s, rss: u64| {
            (Entry { name: name.into(), state: "running".into(), starved, growth_mib_s, firecracker: Some(rss as u32), ..Entry::default() }, rss)
        };
        let vms = [
            vm("big", false, 0, 4000),
            vm("noisy", false, 5, 3000),
            vm("grower", false, 120, 800),
            vm("slow-grower", false, 20, 2000),
            vm("starved", true, 0, 300),
            (Entry { name: "moving".into(), state: "source".into(), growth_mib_s: 500, ..Entry::default() }, 9000),
            (Entry { name: "cmd".into(), state: "running".into(), starved: true, cmd: true, ..Entry::default() }, 9000),
        ];
        let ranked = rank(vms.iter().map(|v| v.0.clone()).collect(), |e| e.firecracker.unwrap_or(0) as u64);
        let names: Vec<_> = ranked.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["starved", "grower", "slow-grower", "big", "noisy"]);
        // Growth within the same power of two ranks by size.
        let ranked = rank(vec![vm("a", false, 70, 100).0, vm("b", false, 100, 200).0], |e| e.firecracker.unwrap_or(0) as u64);
        assert_eq!(ranked[0].name, "b");
    }

    #[test]
    fn growth_is_measured_over_the_window_and_not_while_arriving() {
        let (mut g, t) = (Growth::default(), Instant::now());
        assert_eq!(g.sample(t, 1000, false), 0);
        assert_eq!(g.sample(t + secs(1), 1100, false), 100);
        assert_eq!(g.sample(t + secs(2), 1300, false), 150);
        // Older samples than the window drop out: flat for 5 s is no growth.
        for s in 3..=8 {
            g.sample(t + secs(s), 1300, false);
        }
        assert_eq!(g.sample(t + secs(9), 1300, false), 0);
        // Shrinking is not growth; an arrival's pull starts it over.
        assert_eq!(g.sample(t + secs(10), 900, false), 0);
        assert_eq!(g.sample(t + secs(11), 2000, true), 0);
        assert_eq!(g.sample(t + secs(12), 2100, false), 0);
        assert_eq!(growth_bucket(7), 0);
        assert_eq!(growth_bucket(8), 3);
        assert_eq!(growth_bucket(100), growth_bucket(127));
    }

    #[test]
    fn eviction_starts_at_its_high_water_mark_and_stops_above_it() {
        let mut c = crate::host::Config::default();
        assert_eq!((c.reserve_mib, c.evict_at(), c.evict_until()), (1024, 2048, 2560));
        c.reserve_mib = 256;
        assert_eq!((c.evict_at(), c.evict_until()), (768, 1024));
        c.evict_mib = Some(5000);
        assert_eq!((c.evict_at(), c.evict_until()), (5000, 7372));
        // Never under the reserve; a mark at it still stops a little above.
        c.evict_mib = Some(100);
        assert_eq!((c.evict_at(), c.evict_until()), (256, 384));
    }

    const SIZES: Sizes = Sizes { mem_mib: 256, floor: 4096, hotplug_total: 31744 };

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn stalled_growth_is_settled_not_recharged() {
        // Growth 4096 -> 5248 outstanding and short: busy, nothing charged.
        assert_eq!(SIZES.plan(5248, 4096, 512, secs(5), false, false), None);
        // Stalled: settled at what is plugged; a tick right after (stale stats) does not grow.
        let p = SIZES.plan(5248, 4096, 512, secs(11), false, false).unwrap();
        assert_eq!(p, Plan { settle: true, new: 4096, charge: 0, short: true });
        // The guest asking grows from what is plugged, charging the growth once.
        let p = SIZES.plan(5248, 4096, 512, secs(11), true, false).unwrap();
        assert!(p.settle && p.new > 4096 && p.charge == p.new - 4096, "{p:?}");
        // After the settle, the next tick charges only its own step.
        let p = SIZES.plan(4096, 4096, 512, secs(2), false, false).unwrap();
        assert!(!p.settle && p.new > 4096 && p.charge == p.new - 4096, "{p:?}");
    }

    #[test]
    fn stalled_shrink_is_settled() {
        // Shrink 8192 -> 4736 outstanding, plenty free: busy.
        assert_eq!(SIZES.plan(4736, 8192, 7800, secs(5), false, false), None);
        // Stalled: settled at 8192, and the shrink delay restarts (no new target yet).
        assert_eq!(SIZES.plan(4736, 8192, 7800, secs(11), false, false), Some(Plan { settle: true, new: 8192, charge: 0, short: false }));
        // 10 s later the shrink is chosen again, from what is plugged.
        assert_eq!(SIZES.plan(8192, 8192, 7800, secs(11), false, false), Some(Plan { settle: false, new: 4736, charge: 0, short: false }));
    }

    #[test]
    fn short_guest_cancels_a_pending_shrink() {
        // Shrink 4096 -> 3072 outstanding, guest short: grow from what is plugged.
        let p = SIZES.plan(3072, 4096, 512, secs(2), true, false).unwrap();
        assert!(!p.settle && p.new > 4096 && p.charge == p.new - 4096, "{p:?}");
    }

    #[test]
    fn memory_requests_are_bounded_and_strict() {
        let req = |bytes: &[u8], close: bool| {
            let (a, mut b) = UnixStream::pair().unwrap();
            b.write_all(bytes).unwrap();
            if close {
                drop(b);
            }
            read_mem_request(&a)
        };
        assert_eq!(req(b"MEM 2097152 4194304\n", false), Some(2048));
        for bad in [&b"MEM 1 2 3\n"[..], b"MEM x 2\n", b"GROW 1 2\n", &[b'7'; 4096]] {
            assert_eq!(req(bad, false), None);
        }
        // No newline: gives up when the peer closes, or at the deadline.
        assert_eq!(req(b"MEM 1 2", true), None);
        let t = Instant::now();
        assert_eq!(req(b"MEM 1", false), None);
        assert!(t.elapsed() < MEM_REQUEST_DEADLINE * 2);
    }
}
