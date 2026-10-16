//! The VM process: one process per VM, owning its Firecracker, pager, tap,
//! route and holds, exiting with the VM. SIGTERM suspends, SIGTSTP pauses,
//! SIGCONT resumes, SIGINT (and SIGQUIT) destroys, SIGUSR1 stops a standby (which SIGTERM destroys, unclaimed); `RUN/vms/NAME.sock` takes control ops.
//! Every operation, starting included, holds `op`; the process ends only
//! through `finish`, which holds it too.

use std::io::{BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
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
use crate::util::{answer, ms, proc_kb, send_json, Error, Phases, Result, Slot};
use crate::vm::{Snapshot, State, Vm};

/// A client that takes no output for this long is dropped, freeing its relay and control slot; its
/// session stays in the guest for a reattach.
const CLIENT_STALL: Duration = Duration::from_secs(60);

/// Frame by frame: vsock does not pass a half-close on, so the exit frame is what ends the
/// relay. Then the client's acknowledgement, if it sends one, lets the guest release the session.
fn relay_session(guest: &mut BufReader<impl Read + Write>, client: &mut (impl crate::util::Timed + Write), stall: Duration) -> Result<()> {
    client.write_timeout(stall)?;
    while let Some((kind, data)) = guest::read_frame(guest)? {
        match client.write_all(&guest::frame(kind, &[&data])) {
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                bail!("the client took no output for {} s", stall.as_secs())
            }
            res => res?,
        }
        if kind == guest::FRAME_EXIT {
            let mut ack = [0];
            if (crate::util::By { s: client, at: Instant::now() + Duration::from_secs(2) }).read_exact(&mut ack).is_ok() && ack[0] == guest::SESSION_DONE {
                guest.get_mut().write_all(&ack)?;
            }
            break;
        }
    }
    Ok(())
}

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
/// SIGUSR1 is `standby::stop`'s: it stops a standby VM, and a claimed one ignores it.
const SIGNALS: [i32; 7] = [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGCONT, libc::SIGHUP, libc::SIGUSR1];
const MAX_CONTROL: usize = 256;
static CONTROL: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Page-server requests (peers', forwarded by the listener) refused or served at once: not on `MAX_CONTROL`, so they
/// never shut out local control requests (#335). Those served are bounded further by the page server.
const MAX_PAGES: usize = 64;
/// How long `flexvm resume` waits for the VM to resume (an arrival's pages come first).
const RESUME_WAIT: Duration = Duration::from_secs(60);
static PAGES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Page-server refusals waiting out their `PAGE_REFUSAL` drain, on neither budget above, so a peer's refused requests
/// never keep its page connections out (#352); past this many, a refusal does not wait on the client at all.
static PAGE_REFUSALS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const PAGE_REFUSAL: Duration = Duration::from_secs(1);

pub enum Start {
    Run {
        name: String,
        template: String,
        ip: Option<Ipv4Addr>,
        cmd: Option<String>,
    },
    Resume {
        name: String,
    },
    Restore {
        dir: PathBuf,
        name: Option<String>,
        ip: Option<String>,
        paused: bool,
    },
    /// The migration connection is fd 3.
    Incoming {
        req: Value,
    },
    Standby {
        template: String,
    },
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
    /// A migration source killed before it learned the outcome: its address stays lent.
    Owed,
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
    /// Reserved (`reserve_suspend`) before its worker starts, so SIGTERMs that
    /// overlap make one suspend; `Ending` once the command ends the VM.
    pub suspending: Mutex<Suspend>,
    /// The migration away (and its target) whose outcome this source has yet
    /// to learn (its target never said, nor can be asked): a kill meanwhile ends it.
    reconciling: Mutex<Option<(u64, String)>>,
    /// While an operation waits in `settle_arrival` for the arrival's last pages (`debug status` shows it).
    settling: AtomicBool,
    early: Mutex<Vec<i32>>,
    /// Only then does SIGCONT resume (the kernel sends one after any SIGSTOP,
    /// systemd after SIGTERM).
    pub paused_by_request: AtomicBool,
    /// A resumed suspended VM's checkpoint (marked STARTED), deleted once all
    /// its pages are in, or at the end.
    pub consumed: Mutex<Option<PathBuf>>,
    /// A source's route switch still owed: the migration's id and the target's underlay.
    pub pending_route: Mutex<Option<(u64, Ipv4Addr)>>,
    pub files: Mutex<Vec<PathBuf>>,
    /// What the VM's start was admitted against the reserve (MiB): its first memory mark.
    granted: AtomicU64,
    /// The grant of this start (refunded if the VM never starts).
    charged: AtomicU64,
    /// A disk restore or arrival grant, held until all its memory is here.
    held_grant: Mutex<Option<crate::host::Hold>>,
    /// A standby's (MiB held or to page in, guest size), taken while it waits, so a claim need not.
    pub sizes: Mutex<Option<(u64, u64)>>,
    /// Set once the control socket is bound (a failed bind is tried again).
    serving: Mutex<bool>,
    /// SIGTSTP and SIGCONT, off the signal thread (which a later SIGINT needs).
    pauses: Latest,
    /// What came of the SIGCONTs `flexvm resume` sent, for its answer.
    resumes: Resumes,
    /// The code of a destroy waiting for `op` (0: none): a pause or resume that gets it first does nothing.
    destroying: AtomicI32,
    /// Held by the signal thread from taking a signal to reserving a SIGTERM's suspend,
    /// and by `flexvm resume` asking: one sent earlier is still pending, queued or reserved.
    taking: Mutex<()>,
    /// The controller's tick gaps, for `debug status`.
    ticks: Mutex<Ticks>,
    /// How fast the VM's memory grew lately (MiB/s), for eviction's ranking.
    growth: AtomicU64,
    /// Held by `publish` from reading the VM's state to writing it.
    publishing: Mutex<()>,
    me: std::sync::Weak<Proc>,
    announcer: Arc<Announcer>,
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
        let work = ident.work_dir(&host.run);
        if let Some(old) = crate::host::load(&work.join("owner"))? {
            crate::host::reap(&host.run, &old)?;
        }
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work)?;
        crate::host::store(&work.join("owner"), &ident, false)?;
        crate::host::clear_taps(&host.run, &ident);
        let tap_prefix = format!("{}{:x}t", host.tap_prefix(), ident.pid);
        let tap_owner = crate::host::tap_alias(&host.run, &ident);
        let spawner = Spawner::new(&paths.firecracker, &work, crate::socket::SocketRoot::new(&work)?, cgroup_root(), &tap_prefix, &tap_owner);
        // Before any guest runs: without it no route reaches the peers.
        let h = host.clone();
        let announcer = Announcer::start(
            |f| thread::Builder::new().spawn(f).map(drop),
            |peer, req| peer_call(peer, req.clone()).map(drop),
            Box::new(move || h.config_now().peers),
            ANNOUNCE_RETRY,
        )?;
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
            suspending: Mutex::new(Suspend::Idle),
            reconciling: Mutex::new(None),
            settling: AtomicBool::new(false),
            early: Mutex::new(Vec::new()),
            paused_by_request: AtomicBool::new(false),
            consumed: Mutex::new(None),
            pending_route: Mutex::new(None),
            files: Mutex::new(Vec::new()),
            granted: AtomicU64::new(0),
            charged: AtomicU64::new(0),
            held_grant: Mutex::new(None),
            sizes: Mutex::new(None),
            serving: Mutex::new(false),
            pauses: Latest::default(),
            resumes: Resumes::default(),
            destroying: AtomicI32::new(0),
            taking: Mutex::new(()),
            ticks: Mutex::new(Ticks::default()),
            growth: AtomicU64::new(0),
            publishing: Mutex::new(()),
            me: me.clone(),
            announcer,
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
        let _early = self.early.lock().unwrap();
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
        // Checked when taken.
        if let Ok(log) = self.host.vms(&n.name, "log") {
            crate::util::output::fall_back_to(log);
        }
        *self.name.lock().unwrap() = Some(n);
    }

    /// Admits a start against the host's floor. `held` is memory already here;
    /// None holds the grant until a disk restore or arrival finishes pulling.
    pub fn admit_start(&self, need: u64, held: Option<u64>, floor: crate::host::Floor) -> Result<()> {
        let mib = crate::limit::allowance(need);
        let id = match held {
            Some(held) => self.host.grant_start(mib.saturating_sub(held), floor, false)?.0,
            None => {
                let (id, hold) = self.host.grant_start(mib, floor, true)?;
                *self.held_grant.lock().unwrap() = Some(hold.ok_or("no hold")?);
                id
            }
        };
        self.granted.store(mib, Ordering::SeqCst);
        self.charged.store(id, Ordering::SeqCst);
        Ok(())
    }

    /// An arrival's final footprint, from the runs its source sent once
    /// paused (`sizes`: MiB to page in, the guest's size), admitted on top
    /// of what its start was (from the source's earlier RSS): the held grant
    /// grows by the difference, so the top-up `start_limit` makes once it
    /// runs has nothing left to ask. Refused, nothing changes.
    pub fn admit_arrival(&self, sizes: (u64, u64), floor: crate::host::Floor, deadline: Instant) -> Result<()> {
        let granted = self.granted.load(Ordering::SeqCst);
        let more = arrival_more(granted, sizes);
        if more == 0 {
            return Ok(());
        }
        if let Err(e) = self.host.grow_hold(&self.held_grant, more, floor, Some(deadline))? {
            bail!("its memory grew to {} MiB since it was admitted here for {granted} MiB: {e}", sizes.0);
        }
        self.granted.fetch_add(more, Ordering::SeqCst);
        crate::log!("vm {}: admitted {more} MiB more: it grew to {} MiB since its preflight", self.name(), sizes.0);
        Ok(())
    }

    pub(crate) fn release_hold(&self) {
        drop(self.held_grant.lock().unwrap().take());
    }

    /// Waits for `vm`'s pull, its hold counting only what is still to come:
    /// pages in count in MemAvailable already (#162).
    pub fn wait_pulled(&self, vm: &Vm) -> bool {
        vm.pager.wait_pulled_every(Duration::from_secs(1), |mib| drop(self.host.shrink_hold(&self.held_grant, mib)))
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
            .config_now()
            .peers
            .iter()
            .cloned()
            .filter_map(|peer| {
                thread::Builder::new()
                    .spawn(move || {
                        let r = peer_call(&peer, json!({"op": "lend", "ip": ip.to_string()}));
                        (peer, r)
                    })
                    .inspect_err(|e| crate::log!("borrow {ip}: cannot start peer call: {e}"))
                    .ok()
            })
            .collect();
        let (mut lent, mut why) = (Vec::new(), Vec::new());
        for (peer, r) in asks.into_iter().filter_map(|a| a.join().ok()) {
            match r.map(|r| r["gen"].as_u64().filter(|&g| g > 0)) {
                Ok(Some(gen)) => lent.push((peer, gen)),
                Ok(None) => why.push(format!("{peer} lent {ip} without a generation")),
                Err(e) => why.push(e.to_string()),
            }
        }
        let mut lent = lent.into_iter();
        let first = lent.next();
        for (peer, gen) in lent {
            let _ = peer_call(&peer, json!({"op": "route", "ip": ip.to_string(), "gen": gen}));
        }
        if let Some((peer, gen)) = first {
            return match self.host.lock().and_then(|l| self.host.claim_incoming(&l, name, ip, gen, None)) {
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
        self.settling.store(true, Ordering::SeqCst);
        while !self.pulled_all() && vm.cancel_checkpoint.load(Ordering::SeqCst) == 0 && vm.pager.failed().is_none() && !vm.dead() && vm.firecracker_alive() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            vm.pager.wait_pulled(Some(left.min(Duration::from_millis(100))));
        }
        self.settling.store(false, Ordering::SeqCst);
        if let Some(why) = vm.pager.failed() {
            bail!("vm {}'s arrival failed: {why}", vm.name);
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

    pub fn rev(&self) -> u64 {
        self.addr.lock().unwrap().as_ref().map_or(0, |a| a.rev)
    }

    /// Moves the VM's revision `by` on, recorded here too.
    /// Test fault `advance_fail`: recording it here fails, the revision moved on.
    pub fn advance(&self, l: &crate::host::Locked, by: u64) -> Result<()> {
        let Some((ip, gen, rev)) = self.addr.lock().unwrap().as_mut().map(|a| {
            a.rev = a.rev.saturating_add(by);
            (a.ip, a.gen, a.rev)
        }) else {
            return Ok(());
        };
        if crate::host::tripped("advance_fail") {
            bail!("injected fault: recording the revision failed");
        }
        self.host.advance(l, ip, gen, rev)
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
        let (deadline, mut nap) = (Instant::now() + OP_WAIT, Duration::from_millis(1));
        loop {
            match self.op_now() {
                Some(g) => return Ok(g),
                None if Instant::now() < deadline => {
                    thread::sleep(nap);
                    nap = (nap * 2).min(Duration::from_millis(50));
                }
                None => bail!("vm {} is busy", self.name()),
            }
        }
    }

    /// Whether the address is held.
    pub fn hold_addr(&self, vm: &Vm, id: u64, what: &str) -> bool {
        match self.holder().map(|h| h.hold(vm.ip, id)) {
            Some(Ok(())) => true,
            Some(Err(e)) => {
                crate::log!("vm {}: not holding packets during {what}: {e}", vm.name);
                false
            }
            None => false,
        }
    }

    pub fn holder(&self) -> Option<&Arc<Holder>> {
        self.holder
            .get_or_init(|| {
                Holder::new(&format!("{}{:x}h", self.host.tap_prefix(), self.ident.pid)).unwrap_or_else(|e| {
                    crate::log!("packets in flight while the vm is paused will be dropped: {e}");
                    None
                })
            })
            .as_ref()
    }

    /// Best effort: the registry is for `ls`; nothing decides ownership by it.
    pub fn publish(&self) {
        // Read and written in turn: a publish racing a state change never overwrites the newer entry.
        let _publishing = self.publishing.lock().unwrap();
        let (Some(vm), Some(n)) = (self.vm.get(), self.name.lock().unwrap().as_ref().map(|n| n.name.clone())) else { return };
        if fault("publish") {
            return crate::log!("vm {n}: registry: injected fault: not published");
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
            state: match vm.state() {
                State::Source(mig) if self.reconciling.lock().unwrap().as_ref().is_some_and(|(m, _)| *m == mig) => "reconciling",
                // SIGCONT does nothing then: `flexvm resume` waits for the suspend instead.
                _ if *self.suspending.lock().unwrap() == Suspend::Suspending => "suspending",
                state => state.name(),
            }
            .into(),
            firecracker: vm.pid(),
            starved: vm.starving(),
            growth_mib_s: self.growth.load(Ordering::SeqCst),
            cmd: self.cmd.lock().unwrap().is_some(),
        };
        if let Err(e) = self.name.lock().unwrap().as_ref().map_or(Ok(()), |l| l.publish(&e)) {
            crate::log!("vm {n}: registry: {e}");
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
                if let Ok(moved) = self.host.vms(&self.name(), "moved") {
                    let _ = std::fs::write(moved, &to);
                }
                crate::log!("vm {}: moved to {to}", self.name());
            }
            // Never ran here, or (`Owed`) may run at its target: a peer's route for it comes back, any loan stays.
            (_, Some(a)) => {
                let ip = a.ip;
                if let Ok(l) = self.host.lock() {
                    let _ = a.release(&l);
                    let _ = self.host.reinstall(&l, ip, None);
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
        let work = self.ident.work_dir(&self.host.run);
        crate::socket::remove(&work);
        let _ = std::fs::remove_dir_all(&work);
        // Rate-limited straggler counts not reported yet would end with the process.
        if let Some(h) = self.holder() {
            h.report_now();
        }
        crate::util::flush_log(crate::util::LOG_FLUSH);
        crate::util::output::drain();
        std::process::exit(code)
    }

    /// Returns only if refused: a migration source whose target committed is
    /// never killed, as the target may still be pulling its memory. One whose
    /// outcome is still unknown is (`end_reconciling`).
    pub fn destroy(&self, code: i32) -> Error {
        self.destroying.store(code, Ordering::SeqCst);
        let refused = self.try_destroy(code);
        let _ = self.destroying.compare_exchange(code, 0, Ordering::SeqCst, Ordering::SeqCst);
        refused
    }

    /// The code a destroy asked for, if one is waiting (a kill that cancelled a suspend).
    pub fn destroy_code(&self) -> Option<i32> {
        Some(self.destroying.load(Ordering::SeqCst)).filter(|&c| c != 0)
    }

    /// For a pause or resume: refused once a destroy waits for `op` too.
    pub fn op_unless_destroyed(&self) -> Result<Op<'_>> {
        let op = self.op_within()?;
        if self.destroy_code().is_some() {
            bail!("vm {} is being destroyed", self.name());
        }
        Ok(op)
    }

    fn try_destroy(&self, code: i32) -> Error {
        let vm = self.vm();
        let source = || format!("vm {} is the source of a migration in progress; it ends once the target has its memory", vm.name).into();
        if let State::Source(mig) = vm.state() {
            if self.reconciling.lock().unwrap().as_ref().is_some_and(|(m, _)| *m == mig) {
                let op = self.op();
                return self.end_reconciling(&op, mig, code).unwrap_or_else(source);
            }
            return source();
        }
        vm.cancel_checkpoint.fetch_add(1, Ordering::SeqCst);
        vm.pager.abort_copy();
        let op = self.op();
        if let State::Source(mig) = vm.state() {
            // It became one while this waited (a migration that holds `op` until its outcome is unknown).
            let refused = self.end_reconciling(&op, mig, code).unwrap_or_else(source);
            // Refused: the next checkpoint must not take this kill for its own
            // (one it already cancelled consumed it).
            let _ = vm.cancel_checkpoint.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
            return refused;
        }
        self.finish(&op, End::Gone, code, None)
    }

    /// Marks migration `mig` to `to` as one whose outcome is unknown, until `known` takes it back.
    pub(crate) fn reconciling(&self, mig: u64, to: &str) {
        *self.reconciling.lock().unwrap() = Some((mig, to.into()));
        self.publish();
    }

    /// False if a kill took the reconciliation first (and is ending the process).
    pub(crate) fn known(&self, mig: u64) -> bool {
        let taken = self.reconciling.lock().unwrap().take_if(|(m, _)| *m == mig).is_some();
        if taken {
            self.publish();
        }
        taken
    }

    /// A kill while migration `mig`'s outcome is unknown: None if it is not (or no
    /// longer: the reconciliation learned it), Some (refused) if the outcome could
    /// not be recorded as owed. The target may be running the VM, so nothing is
    /// withdrawn: the process ends as a killed source does, its address left lent
    /// (never handed out here) and the newest route a peer announced for it put
    /// back. The outcome is owed (`Host::owe`), settled by garbage collection once
    /// the target says (`Host::settle_owed`): released, the loan stays the target's;
    /// aborted, the generation is withdrawn then. Never left lent with no record of
    /// whom: unrecorded, the kill is refused and this process goes on reconciling.
    fn end_reconciling(&self, op: &Op, mig: u64, code: i32) -> Option<Error> {
        let vm = self.vm();
        let (ip, gen, by) = (vm.ip, self.gen(), self.ident.clone());
        let to = match owe_or_refuse(&self.reconciling, mig, OWE_TRIES, |to| {
            self.host.owe(mig, &crate::host::Owed { to: to.into(), ip, gen, by: by.clone() })
        }) {
            Ok(Some(to)) => to,
            Ok(None) => return None,
            Err(e) => {
                return Some(
                    format!(
                        "vm {}: the outcome of migration {mig} is unknown, and recording it as owed failed ({e}), so it is not killed: it goes on asking its target, and {ip} stays lent",
                        vm.name
                    )
                    .into(),
                )
            }
        };
        crate::log!(
            "vm {}: killed while the outcome of migration {mig} to {to} is unknown; {to} may still be running it, so {ip} stays lent (not handed out here) until {to} says",
            vm.name
        );
        if let Some(h) = self.holder() {
            h.forget(vm.ip, mig);
        }
        self.finish(op, End::Owed, code, None)
    }

    /// Reserves the one suspend that may run: None if one already is (it
    /// takes this request too) or the VM is ending.
    pub fn reserve_suspend(&self) -> Option<SuspendReserved> {
        let p = self.arc()?;
        let mut s = self.suspending.lock().unwrap();
        (*s == Suspend::Idle).then(|| {
            *s = Suspend::Suspending;
            SuspendReserved(p.clone(), false)
        })
    }

    /// Recorded for the peers first (`Host::withdraw_noted`): told now, and on a
    /// later sweep any peer that could not be.
    fn withdraw(&self, a: AddrClaim) {
        let (ip, gen) = (a.ip, a.gen);
        let Ok(l) = self.host.lock() else {
            // Nothing recorded: told at least once, as before.
            return tell_peers(&self.host, json!({"op": "route", "ip": ip.to_string(), "gen": gen}));
        };
        let ours = self.host.holder(&l, ip).is_ok_and(|h| h.is_none_or(|h| h == self.name()));
        // Recorded before the claim goes: the claim is what a sweep finds it by otherwise.
        match self.host.withdraw_noted(&l, ip, gen) {
            Ok(_) => drop(a.release(&l)),
            Err(e) => {
                crate::log!("vm {}: withdrawing {ip}: {e}; its claim stays, for a sweep to withdraw once this process is gone", self.name());
                a.keep();
            }
        }
        if ours && !self.host.reinstall(&l, ip, None).unwrap_or(false) {
            crate::net::unroute(ip);
        }
        drop(l);
        self.host.deliver_withdrawals();
    }

    pub fn announce(&self) {
        let vm = self.vm().clone();
        // One snapshot of the settings as they are now, derived ones included.
        let cfg = self.host.config_now();
        let (ip, gen, rev, dev) = (vm.ip, self.gen(), self.rev(), cfg.announce_dev());
        if let Some(dev) = &dev {
            crate::net::proxy_arp(dev);
        }
        if !self.announcer.route(&cfg, ip, gen, rev, || vm.state().local()) {
            return;
        }
        let Some(dev) = dev else { return };
        if let Err(e) = thread::Builder::new().spawn(move || {
            let arp = || {
                if vm.state().local() {
                    crate::net::gratuitous_arp(&dev, ip).unwrap_or_else(|e| crate::log!("announce {ip}: {e}"));
                }
            };
            arp();
            // The second ARP 200 ms after the first.
            thread::sleep(Duration::from_millis(200));
            arp();
        }) {
            crate::log!("announce {ip}: no thread for its ARPs: {e}");
        }
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
        self.admit_start(tpl.working_set_mib(), Some(0), crate::host::Floor::Reserve)?;
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
        // Publication makes the VM discoverable to control callers. Bind first;
        // requests can queue behind the start operation until guest setup finishes.
        self.serve_control()?;
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

    pub fn serve_control(&self) -> Result<()> {
        let mut serving = self.serving.lock().unwrap();
        if *serving {
            return Ok(());
        }
        let p = self.arc().ok_or("vm process gone")?;
        let sock = self.host.sock(&self.name())?;
        let _ = std::fs::remove_file(&sock);
        let l = UnixListener::bind(&sock).map_err(|e| format!("vm {}: no control socket at {}: {e}", self.name(), sock.display()))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600));
        thread::Builder::new().spawn(move || {
            for c in l.incoming() {
                let c = match c {
                    Ok(c) => c,
                    Err(e) => {
                        crate::util::accept_failed("control socket", &e);
                        continue;
                    }
                };
                let Some(slot) = Slot::take(&CONTROL, MAX_CONTROL) else {
                    // Not to wait on the client: the reply fits the socket's buffer.
                    let _ = c.set_nonblocking(true);
                    let _ = send_json(&mut &c, &json!({"ok": false, "error": "busy"}));
                    continue;
                };
                let p = p.clone();
                if let Err(e) = thread::Builder::new().spawn(move || p.control(c, slot)) {
                    crate::log!("control: cannot start a connection's thread: {e}");
                }
            }
        })?;
        *serving = true;
        Ok(())
    }

    /// Never returns: the main thread spawned Firecracker, which dies with it.
    fn serve(self: &Arc<Self>) -> ! {
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
        // In order, what comes meanwhile queued behind; and before the main
        // command starts: a Ctrl-Z taken during startup pauses the VM first.
        loop {
            let next = self.early.lock().unwrap().first().copied();
            let Some(sig) = next else { break };
            self.dispatch(sig);
            self.early.lock().unwrap().remove(0);
        }
        while self.pauses.busy.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(10));
        }
        if self.cmd.lock().unwrap().is_some() {
            spawn(Proc::main_command);
        }
        loop {
            thread::park();
        }
    }

    fn signal(self: &Arc<Self>, sig: i32) {
        let mut early = self.early.lock().unwrap();
        // Until those before it are replayed (`serve`), as it would overtake them.
        if self.vm.get().is_none() || !early.is_empty() {
            if sig != libc::SIGHUP {
                early.push(sig);
            }
            return;
        }
        drop(early);
        self.dispatch(sig);
    }

    /// `flexvm resume`: whether a SIGTERM sent before it suspends the VM; if none,
    /// its SIGCONT (which, as a raw one did, discards a Ctrl-Z still pending), and
    /// what came of it: the VM runs, its resume failed, or it is being destroyed.
    fn resume_request(&self) -> Result<Value> {
        let Some(ticket) = self.ask_resume() else { return Ok(json!({"suspending": true})) };
        match self.resumes.wait(ticket, RESUME_WAIT) {
            None => bail!("vm {}: its resume is still under way after {}s; see its log", self.name(), RESUME_WAIT.as_secs()),
            Some(Err(e)) => bail!("{e}"),
            Some(Ok(())) if self.destroy_code().is_some() => bail!("vm {} is being destroyed", self.name()),
            Some(Ok(())) => Ok(json!({"suspending": false})),
        }
    }

    /// None if a suspend is coming; else the SIGCONT is sent, and its ticket returned.
    fn ask_resume(&self) -> Option<u64> {
        let _taking = self.taking.lock().unwrap();
        // Queued first: a replay reserves, then takes it off.
        let coming = self.early.lock().unwrap().contains(&libc::SIGTERM)
            || *self.suspending.lock().unwrap() == Suspend::Suspending
            || crate::util::signal_pending(libc::SIGTERM);
        (!coming).then(|| {
            self.resumes.ask(|| {
                unsafe { libc::kill(libc::getpid(), libc::SIGCONT) };
            })
        })
    }

    fn dispatch(self: &Arc<Self>, sig: i32) {
        if !matches!(sig, libc::SIGTSTP | libc::SIGCONT) {
            let _ = self.handle(sig);
            return;
        }
        if self.resumes.offer(sig, || self.pauses.offer(sig)) {
            let p = self.clone();
            if let Err(e) = thread::Builder::new().spawn(move || {
                while let Some((sig, asked)) = p.resumes.next(|| p.pauses.next()) {
                    let res = p.handle(sig);
                    p.resumes.answer(asked, sig, res);
                }
            }) {
                self.pauses.busy.store(false, Ordering::SeqCst);
                crate::log!("vm {}: signal {sig}: {e}", self.name());
            }
        }
    }

    /// What came of it (logged too).
    fn handle(&self, sig: i32) -> std::result::Result<(), String> {
        let vm = self.vm();
        let res = match sig {
            libc::SIGTSTP => self.op_unless_destroyed().and_then(|_op| {
                let res = vm.pause();
                // A pause that may have landed counts as requested, so SIGCONT resumes it.
                if res.is_ok() || vm.switch_unsure() {
                    self.paused_by_request.store(true, Ordering::SeqCst);
                }
                res?;
                self.publish();
                Ok(())
            }),
            // Also through while a new address is pending (a resume that failed to set it): this one retries it.
            libc::SIGCONT
                if self.leaving.load(Ordering::SeqCst) || !(self.paused_by_request.load(Ordering::SeqCst) || vm.pending_net.load(Ordering::SeqCst)) =>
            {
                Ok(())
            }
            libc::SIGCONT => self.resume().map(drop),
            libc::SIGTERM if matches!(vm.state(), State::Source(_)) => {
                crate::log!("vm {}: migrating away; it ends once the target has its memory", vm.name);
                Ok(())
            }
            libc::SIGTERM => match self.reserve_suspend() {
                None => {
                    crate::log!("vm {}: a suspend is already under way, or the vm is ending", vm.name);
                    Ok(())
                }
                // Off the signal thread, which a later SIGINT needs. Unspawned, the closure and its reservation are dropped.
                Some(mut r) => thread::Builder::new()
                    .spawn(move || {
                        let p = r.proc().clone();
                        r.1 = true;
                        p.publish();
                        crate::log!("vm {}: signal {sig}: {}", p.name(), p.suspend(r))
                    })
                    .map(drop)
                    .map_err(|e| format!("suspending: {e}").into()),
            },
            libc::SIGINT | libc::SIGQUIT => Err(self.destroy(128 + sig)),
            _ => Ok(()),
        };
        res.map_err(|e| {
            crate::log!("vm {}: signal {sig}: {e}", vm.name);
            e.to_string()
        })
    }

    /// `slot`: its place among `MAX_CONTROL`, which a page-server request trades for one among `MAX_PAGES`.
    fn control(self: &Arc<Self>, c: UnixStream, slot: Slot) {
        let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
        let got = crate::util::recv_with_fds(&c, crate::util::MAX_LINE as usize, || Ok(()))
            .and_then(|(line, fds)| Ok((serde_json::from_slice::<Value>(&line)?, fds)));
        let (req, fds) = match got {
            Ok(got) => got,
            Err(e) => return drop(send_json(&mut &c, &json!({"ok": false, "error": format!("bad request: {e}")}))),
        };
        let _ = c.set_read_timeout(None);
        let reply = match req["op"].as_str().unwrap_or("") {
            "exec" => return self.exec(&req, c),
            "pages" => return self.pages(&req, fds, slot),
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
            "resume" => self.resume_request(),
            "claim" => Err("this vm is not a standby vm".into()),
            op => Err(format!("unknown op {op:?}").into()),
        };
        let _ = send_json(&mut &c, &reply.map_or_else(|e| json!({"ok": false, "error": e.to_string()}), |v| json!({"ok": true, "result": v})));
    }

    fn pages(&self, req: &Value, fds: Vec<OwnedFd>, slot: Slot) {
        let Some(fd) = fds.into_iter().next() else { return };
        let s = std::net::TcpStream::from(fd);
        // Checked before taking a page slot: a refusal never holds one.
        let (vm, source) = (self.vm(), req["mig"].as_u64().map(State::Source));
        if source != Some(vm.state()) {
            drop(slot);
            return refuse_not_source(s, &vm.name, &req["mig"]);
        }
        if fault("pages") {
            drop(slot);
            return refuse_pages(s, "injected fault: page server down");
        }
        let Some(pages) = Slot::take(&PAGES, MAX_PAGES) else {
            drop(slot);
            return refuse_pages(s, "page server busy");
        };
        drop(slot);
        let admitted = match crate::uffd::admit(&s) {
            Ok(Some(a)) => a,
            Ok(None) => {
                drop(pages);
                return refuse_pages(s, "page server busy: every connection is answering a request or still ending");
            }
            Err(e) => return crate::log!("vm {}: page server: {e}", vm.name),
        };
        let _ = s.set_nodelay(true);
        let served = send_json(&mut &s, &json!({"ok": true})).and_then(|()| {
            // A slow source, not a lost one: every reply comes, a second late (well within the target's
            // per-request deadline), so an arrival from here stays unfinished for as long as a test needs.
            let pace = || {
                if fault("pages_slow") {
                    std::thread::sleep(Duration::from_secs(1));
                }
            };
            crate::uffd::serve_pages(&vm.pager, &s, &admitted, &s, || fault("pages") || Some(vm.state()) != source, pace)
        });
        if let Err(e) = served {
            crate::log!("vm {}: page server: {e}", vm.name);
        }
    }

    fn exec(&self, req: &Value, c: UnixStream) {
        let mut w = &c;
        let vm = self.vm();
        let cmd = req["cmd"].as_str().unwrap_or("");
        let started = vm.exec(|s| {
            let id = req["session"].as_str().ok_or("missing session id")?;
            guest::session(s, req["action"].as_str().unwrap_or("start"), id, req["offset"].as_u64().unwrap_or(0), cmd, guest::TIMEOUT)
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
                let reply = guest::read_frame(&mut g)?.map(|(_, m)| String::from_utf8_lossy(&m).into_owned());
                return Ok(send_json(
                    &mut w,
                    &match reply.as_deref() {
                        Some("closed") => json!({"ok": true}),
                        r => json!({"ok": false, "error": format!("session close failed: {}", r.unwrap_or_default())}),
                    },
                )?);
            }
            // The guest heartbeats every second; silence means the VM moved, or its agent stalled.
            g.get_ref().set_read_timeout(Some(Duration::from_secs(3)))?;
            send_json(&mut w, &json!({"ok": true}))?;
            relay_session(&mut g, &mut w, CLIENT_STALL)?;
            Ok(())
        })();
        vm.untrack_exec(id);
    }

    fn debug(&self, req: &Value) -> Result<Value> {
        if req["what"] != "status" && !crate::host::faults_on() {
            bail!("debug {} needs FLEXVM_FAULTS=1", req["what"]);
        }
        let vm = self.vm();
        match req["what"].as_str().unwrap_or("") {
            "memhash" => self.memhash(),
            "sessions" => {
                let (live, unacknowledged) = guest::sessions(&vm.vsock)?;
                Ok(json!({"live": live, "unacknowledged": unacknowledged}))
            }
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
                "collapse": vm.pager.collapse_report(),
                "host_regions": vm.pager.host_regions(),
                "remote_left": vm.pager.remote_left(),
                "settling": self.settling.load(Ordering::SeqCst),
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
        crate::log!("vm {}: died: {why}", vm.name);
        if let Ok(failed) = self.host.vms(&vm.name, "failed") {
            let _ = std::fs::write(failed, &why);
        }
        self.finish(op, End::Died, DIED, None)
    }

    fn controller(self: Arc<Self>) {
        let (mut published, mut growth, mut stopping) = (false, Growth::default(), None::<Stopping>);
        loop {
            thread::sleep(Duration::from_secs(1));
            // Standby VMs signalled last tick had that sleep: other processes may stop them now, however long this tick blocks.
            if let Some(s) = &mut stopping {
                s.lock = None;
            }
            self.ticks.lock().unwrap().tick();
            let vm = self.vm();
            if !vm.firecracker_alive() || vm.pager.failed().is_some() {
                self.died();
            }
            if let Ok(_op) = self.op.try_lock() {
                if vm.release_pending() && matches!(vm.state(), State::Running | State::Paused) {
                    match vm.release_reports(Duration::from_millis(500)) {
                        Ok(()) => crate::log!("vm {}: released free page reports", vm.name),
                        Err(e) => crate::log!("vm {}: releasing free page reports: {e}", vm.name),
                    }
                }
            }
            if let Err(e) = self.resize(None) {
                crate::log!("vm {}: resize: {e}", vm.name);
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
            relieve(&self.host, host_available_mib(), vm.starving(), &mut stopping);
            // A derived announce device follows the routes (one that changed gets proxy ARP).
            if let Some(dev) = self.host.config_now().announce_dev() {
                crate::net::proxy_arp(&dev);
            }
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
        vm.limit.watch(&self.host, Duration::from_secs(1), || !vm.dead(), || vm.state() == State::Running);
    }

    /// The guest is untrusted: requests are bounded in size and time and
    /// acted on at most once per `MEM_REQUEST_GAP`.
    fn serve_memory(self: Arc<Self>) {
        let vm = self.vm().clone();
        let _ = std::fs::remove_file(vm.mem_sock());
        let listener = match UnixListener::bind(vm.mem_sock()) {
            Ok(l) => l,
            Err(e) => return crate::log!("vm {}: memory requests: {e}", vm.name),
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
                    // Any guest agent keeps its throttle on `ok`; `full` lifts it (#368).
                    Ok(Resized::Same) | Ok(Resized::Refused) => "ok",
                    Ok(Resized::Busy) => "busy",
                    Err(e) => {
                        crate::log!("vm {}: resize on request: {e}", vm.name);
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
                    if kind == guest::FRAME_LOST {
                        let Ok(at) = <[u8; 8]>::try_from(&data[..data.len().min(8)]) else { continue };
                        let (at, was) = (u64::from_le_bytes(at), self.app_log.load(Ordering::SeqCst));
                        if at > was {
                            crate::log!("vm {}: {} bytes of app output lost (the guest keeps its last 1 MiB)", vm.name, at - was);
                        } else if at < was {
                            // Only an offset past the guest's output (a bad migration header or manifest) moves back.
                            crate::log!(
                                "vm {}: app output offset {was} is past the guest's end {at}; going on from there (output before it may be missing)",
                                vm.name
                            );
                        }
                        self.app_log.store(at, Ordering::SeqCst);
                        continue;
                    }
                    if kind == guest::FRAME_MSG {
                        let status = String::from_utf8_lossy(&data);
                        if !status.starts_with("running") {
                            crate::log!("vm {}: app {}", vm.name, status.rsplit_once(' ').map(|(s, _)| s).unwrap_or(&status));
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
            {
                let mut s = self.suspending.lock().unwrap();
                if *s == Suspend::Suspending {
                    // Afterwards an exit status already received is in the session: the next try returns it.
                    drop(s);
                    while *self.suspending.lock().unwrap() == Suspend::Suspending {
                        thread::sleep(Duration::from_millis(20));
                    }
                    continue;
                }
                // No suspend starts from here (the lock is not held through `destroy`, which waits for `op`).
                *s = Suspend::Ending;
            }
            let code = res.unwrap_or_else(|e| {
                crate::log!("vm {}: {e}", self.name());
                FAILED
            });
            let refused = self.destroy(code);
            *self.suspending.lock().unwrap() = Suspend::Idle;
            return crate::log!("vm {}: {refused}", self.name());
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

    /// A standby VM's exit status if a stop is pending (`stop_status`).
    pub fn stop_requested(&self) -> Option<i32> {
        stop_status(&self.early.lock().unwrap())
    }

    pub fn forget_stop(&self) {
        forget_stop(&mut self.early.lock().unwrap());
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
                    crate::log!("vm {}: guest clock was {off:.1} ms off after resuming; stepped it", vm.name)
                }
                Ok(_) => {}
                Err(e) => crate::log!("vm {}: checking the guest clock: {e}", vm.name),
            }
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suspend {
    Idle,
    /// Reserved, or running.
    Suspending,
    /// The main command is ending the VM.
    Ending,
}

/// The reserved suspend: dropped (it failed, or never started), the next may run.
/// Published (as `suspending`) by its worker, never on the signal thread.
pub struct SuspendReserved(Arc<Proc>, bool);

impl SuspendReserved {
    fn proc(&self) -> &Arc<Proc> {
        &self.0
    }
}

impl Drop for SuspendReserved {
    fn drop(&mut self) {
        let mut s = self.0.suspending.lock().unwrap();
        if *s == Suspend::Suspending {
            *s = Suspend::Idle;
            drop(s);
            if self.1 {
                self.0.publish();
            }
        }
    }
}

/// The newest request offered, taken one at a time by a single worker: a
/// SIGCONT after a SIGTSTP still waiting for the VM leaves it running.
#[derive(Default)]
struct Latest {
    wanted: AtomicI32,
    busy: AtomicBool,
}

impl Latest {
    /// True if the caller is to start the worker.
    fn offer(&self, sig: i32) -> bool {
        self.wanted.store(sig, Ordering::SeqCst);
        !self.busy.swap(true, Ordering::SeqCst)
    }

    /// The worker's next request; None once there is none (and it is to stop).
    fn next(&self) -> Option<i32> {
        loop {
            match self.wanted.swap(0, Ordering::SeqCst) {
                0 => {
                    self.busy.store(false, Ordering::SeqCst);
                    // An offer between the two found it busy: this worker takes it, unless a new one started.
                    if self.wanted.load(Ordering::SeqCst) == 0 || self.busy.swap(true, Ordering::SeqCst) {
                        return None;
                    }
                }
                sig => return Some(sig),
            }
        }
    }
}

/// The SIGCONTs `flexvm resume` sent, and what came of them. Each is asked
/// with a ticket; a SIGCONT offered to the pause worker counts every ticket
/// asked by then, and the worker's turn (`Latest`) takes with it those
/// offered by then. Its handling answers them: a SIGCONT with its outcome, a
/// SIGTSTP (a later Ctrl-Z, which `Latest` lets win) as paused again.
#[derive(Default)]
struct Resumes {
    state: Mutex<ResumeState>,
    answered: std::sync::Condvar,
}

#[derive(Default)]
struct ResumeState {
    asked: u64,
    offered: u64,
    answered: u64,
    outcome: Option<std::result::Result<(), String>>,
}

impl Resumes {
    /// A new ticket, `send` (its SIGCONT) sent holding it.
    fn ask(&self, send: impl FnOnce()) -> u64 {
        let mut s = self.state.lock().unwrap();
        s.asked += 1;
        send();
        s.asked
    }

    /// `offer` (`Latest::offer`) of `sig`, counted with the tickets it answers.
    fn offer(&self, sig: i32, offer: impl FnOnce() -> bool) -> bool {
        let mut s = self.state.lock().unwrap();
        if sig == libc::SIGCONT {
            s.offered = s.asked;
        }
        offer()
    }

    /// The worker's next signal (`Latest::next`), with the tickets offered by then.
    fn next(&self, next: impl FnOnce() -> Option<i32>) -> Option<(i32, u64)> {
        let s = self.state.lock().unwrap();
        next().map(|sig| (sig, s.offered))
    }

    fn answer(&self, upto: u64, sig: i32, res: std::result::Result<(), String>) {
        let mut s = self.state.lock().unwrap();
        if upto <= s.answered {
            return;
        }
        s.answered = upto;
        s.outcome = Some(if sig == libc::SIGCONT { res } else { Err("paused again meanwhile (a later SIGTSTP)".into()) });
        self.answered.notify_all();
    }

    /// What came of `ticket`, if answered within `wait`.
    fn wait(&self, ticket: u64, wait: Duration) -> Option<std::result::Result<(), String>> {
        let s = self.state.lock().unwrap();
        let (s, _) = self.answered.wait_timeout_while(s, wait, |s| s.answered < ticket).unwrap();
        (s.answered >= ticket).then(|| s.outcome.clone().unwrap_or(Ok(())))
    }
}

/// Tries at recording an owed outcome before a kill is refused (`owe_or_refuse`).
const OWE_TRIES: u32 = 5;

/// Records migration `mig`'s outcome as owed (`owe`, given its target), up to `tries`
/// times, holding `reconciling` throughout so the reconciliation can neither learn
/// the outcome meanwhile nor lose its mark: recorded, the mark is taken (Some(target));
/// not reconciling `mig`, None; never recorded, an error with the mark left in place.
fn owe_or_refuse(reconciling: &Mutex<Option<(u64, String)>>, mig: u64, tries: u32, mut owe: impl FnMut(&str) -> Result<()>) -> Result<Option<String>> {
    let mut r = reconciling.lock().unwrap();
    let Some(to) = r.as_ref().filter(|(m, _)| *m == mig).map(|(_, to)| to.clone()) else { return Ok(None) };
    let mut last = None;
    for i in 0..tries.max(1) {
        if i > 0 {
            thread::sleep(Duration::from_millis(100 << i.min(4)));
        }
        match owe(&to) {
            Ok(()) => {
                *r = None;
                return Ok(Some(to));
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| "not recorded".into()))
}

/// What stops a standby VM before its claim: SIGUSR1 (`standby::stop`'s, which
/// the claimed VM ignores), or SIGINT, SIGQUIT or SIGTERM sent to it.
fn is_stop(sig: i32) -> bool {
    matches!(sig, libc::SIGINT | libc::SIGQUIT | libc::SIGTERM | libc::SIGUSR1)
}

/// How a pending stop ends an unclaimed standby VM: 128 + the first SIGINT,
/// SIGQUIT or SIGTERM (it has nothing to suspend, so SIGTERM destroys it too),
/// else 0 for the pool's own stop (SIGUSR1); None while none is pending.
fn stop_status(early: &[i32]) -> Option<i32> {
    let signalled = early.iter().find(|&&s| is_stop(s) && s != libc::SIGUSR1).map(|&s| 128 + s);
    signalled.or_else(|| early.contains(&libc::SIGUSR1).then_some(0))
}

/// A claim discards only the pool's stop; termination requests still replay.
fn forget_stop(early: &mut Vec<i32>) {
    early.retain(|&s| s != libc::SIGUSR1);
}

pub fn main(host: Host, paths: Paths, start: Start, mut notify: Option<std::fs::File>) -> Result<()> {
    // Blocked first: every thread from here on (the output relays too) inherits it.
    let signals = crate::util::block_signals(&SIGNALS);
    crate::util::output::guard()?;
    let _ = crate::net::ip_forward();
    if let Some(dev) = &host.cfg.announce_dev() {
        crate::net::proxy_arp(dev);
    }
    let p = Proc::new(host, paths)?;
    let host = p.host.clone();
    thread::spawn(move || {
        crate::gc::sweep_due(&host);
        crate::gc::periodic(host);
    });
    let s = p.clone();
    let fd = crate::util::signal_fd(&signals)?;
    // Ctrl-\ quits like Ctrl-C: the VM is destroyed, not dumped.
    thread::spawn(move || loop {
        let _ = crate::util::readable(&fd, Duration::from_secs(3600));
        // Taken, and a SIGTERM's suspend reserved, under `taking` (`ask_resume`).
        let taking = s.taking.lock().unwrap();
        let Some(sig) = crate::util::take_signal(&signals) else { continue };
        if sig != libc::SIGTERM {
            drop(taking);
        }
        s.signal(sig);
    });
    let op = p.op();
    // Checked where the failure is answered: to the starter (`notify`), or to the source (`prepare_in`).
    let kvm = if matches!(start, Start::Incoming { .. }) { Ok(()) } else { crate::util::check_kvm() };
    let res = match start {
        _ if kvm.is_err() => kvm.map(|()| Value::Null),
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
                match crate::listen::finish_incoming_log(&p.host, &p.name(), &log, res.is_ok()) {
                    Ok(()) if res.is_ok() => {
                        if let Ok(log) = p.host.vms(&p.name(), "log") {
                            crate::util::output::published(&log)
                        }
                    }
                    Ok(()) => {}
                    Err(e) => crate::log!("arrival log {}: {e}", log.display()),
                }
            }
            res.map(|()| Value::Null)
        }
        Start::Standby { template } => crate::standby::serve(&p, &template, &mut notify, &op),
    };
    let res = res.and_then(|v| {
        p.serve_control()?;
        // Once running (a standby once claimed), so a start never competes with a refill.
        crate::standby::maintain(p.host.clone());
        Ok(v)
    });
    let reply = match &res {
        Ok(v) => json!({"ok": true, "result": v}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    };
    match notify.take() {
        Some(mut f) => drop(send_json(&mut f, &reply)),
        None if res.is_ok() && !reply["result"].is_null() => crate::log!("{}", reply["result"]),
        None => {}
    }
    if let Err(e) = res {
        crate::log!("flexvm: {e}");
        p.finish(&op, End::NotStarted, FAILED, None);
    }
    drop(op);
    p.serve()
}

fn has_controller(controllers: &str, name: &str) -> bool {
    controllers.split_whitespace().any(|controller| controller == name)
}

pub fn cgroup_root() -> Option<PathBuf> {
    let root = PathBuf::from("/sys/fs/cgroup/flexvm");
    let setup = || -> Result<()> {
        if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            bail!("no cgroup2 hierarchy mounted at /sys/fs/cgroup");
        }
        std::fs::create_dir_all(&root)?;
        let ctl = std::fs::read_to_string(root.join("cgroup.subtree_control")).unwrap_or_default();
        if !has_controller(&ctl, "memory") {
            std::fs::write(root.join("cgroup.subtree_control"), "+memory")?;
        }
        static NO_CPU: AtomicBool = AtomicBool::new(false);
        if !has_controller(&ctl, "cpu") {
            if let Err(e) = std::fs::write(root.join("cgroup.subtree_control"), "+cpu") {
                if !NO_CPU.swap(true, Ordering::Relaxed) {
                    crate::log!("cgroup cpu controller unavailable (memory limits still apply): {e}");
                }
            }
        }
        Ok(())
    };
    static WARNED: AtomicBool = AtomicBool::new(false);
    match setup() {
        Ok(()) => Some(root),
        Err(e) if !WARNED.swap(true, Ordering::Relaxed) => {
            crate::log!("WARNING: per-VM cgroups unavailable: {e}");
            None
        }
        Err(_) => None,
    }
}

/// What an arrival admitted `granted` MiB still needs for (`need` MiB to
/// page in, of a guest of `cap`): its allowance, short of what the guest
/// can hold (its memory mark stops there), less what it has.
fn arrival_more(granted: u64, (need, cap): (u64, u64)) -> u64 {
    crate::limit::allowance(need).min(cap.max(need)).saturating_sub(granted)
}

/// None if it cannot be read: never taken for 0 (pressure). Test fault `no_meminfo`;
/// a test's `mem_available_override` stands in for it.
pub fn host_available_mib() -> Option<u64> {
    if fault("no_meminfo") {
        return None;
    }
    if let Some(mib) = crate::host::mem_available_override() {
        return Some(mib);
    }
    Some(proc_kb("/proc/meminfo", "MemAvailable")? >> 20)
}

#[derive(Debug, PartialEq)]
pub enum Resized {
    Grew,
    Same,
    Busy,
    /// Short, and at its ceiling: the guest may use all it has.
    Full,
    /// Short, and refused by the host's reserve: the guest stays throttled
    /// at its mark (killing for memory a plug may still bring is worse) and
    /// the VM starved, so relief moves it; it asks again as it is throttled.
    Refused,
}

/// Keeps `headroom` free via hotplug, never below the template's size. The
/// guest's hint only steers bounded, reserve-admitted growth; only balloon
/// statistics may trigger shrinking. Callers hold the op lock (or copy-growth).
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
    // Refused, it is not asked again (host lock, grants file, MemAvailable) until its backoff
    // expires: a guest throttled at its mark asks about every 250 ms.
    let refused = plan.charge > 0 && {
        let mut backoff = vm.grant_backoff.lock().unwrap();
        let now = Instant::now();
        if !backoff.ready(now) {
            true
        } else if host.grant(plan.charge, None)?.is_some() {
            backoff.granted();
            false
        } else {
            backoff.refused(now);
            true
        }
    };
    // Starved only when the host refused it: at its own ceiling, moving it cannot help.
    let starved = plan.starved(vm.starved.load(Ordering::SeqCst), refused);
    if vm.starved.swap(starved, Ordering::SeqCst) != starved {
        match starved {
            true if host.config_now().peers.is_empty() => {
                crate::log!("vm {}: starved: the host's reserve refused it {} MiB; it stays throttled (no peers to move it to)", vm.name, plan.charge)
            }
            true => crate::log!("vm {}: starved: the host's reserve refused it {} MiB; it stays throttled until it grows or moves", vm.name, plan.charge),
            false => crate::log!("vm {}: no longer starved", vm.name),
        }
    }
    let new = if refused { plugged } else { plan.new };
    if new != requested {
        let why = if plan.settle {
            "stalled"
        } else if hint.is_some() {
            "guest asked"
        } else {
            "tick"
        };
        crate::log!("vm {}: available {avail} MiB, hotplug {requested} (plugged {plugged}) -> {new} MiB ({why})", vm.name);
        if new > requested {
            vm.limit.plug(meta.mem_mib + new, if refused { 0 } else { plan.charge });
        }
        vm.fc(|fc| fc.patch("/hotplug/memory", json!({"requested_size_mib": new})))?;
        *last = Instant::now();
    } else if requested == plugged {
        vm.limit.settled(meta.mem_mib + plugged);
    }
    Ok(Resized::of(new > plugged, plan.short, plugged == hotplug_total, refused))
}

impl Resized {
    fn of(grew: bool, short: bool, at_ceiling: bool, refused: bool) -> Resized {
        match (grew, short) {
            (true, _) => Resized::Grew,
            (false, true) if at_ceiling => Resized::Full,
            (false, true) if refused => Resized::Refused,
            _ => Resized::Same,
        }
    }
}

const GRANT_RETRY_MIN: Duration = Duration::from_millis(250);
const GRANT_RETRY_MAX: Duration = Duration::from_secs(5);

/// After the reserve refuses a VM's growth: 250 ms, doubling to 5 s, before it
/// is asked again; a grant resets it.
#[derive(Default)]
pub struct GrantBackoff {
    delay: Duration,
    until: Option<Instant>,
}

impl GrantBackoff {
    pub(crate) fn ready(&self, now: Instant) -> bool {
        self.until.is_none_or(|until| now >= until)
    }

    pub(crate) fn refused(&mut self, now: Instant) {
        self.delay = (self.delay * 2).clamp(GRANT_RETRY_MIN, GRANT_RETRY_MAX);
        self.until = Some(now + self.delay);
    }

    pub(crate) fn granted(&mut self) {
        *self = GrantBackoff::default();
    }
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
    /// Balloon statistics inside the post-resize delay cannot establish recovery.
    stale: bool,
}

impl Plan {
    fn starved(&self, was: bool, refused: bool) -> bool {
        // A fresh guest request can be refused before the next controller tick.
        // That tick must not clear the refusal just because stale statistics
        // suppress its growth (charge = 0): the guest's next retry would log it again.
        if self.stale {
            was
        } else {
            self.short && refused
        }
    }
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
        } else if !asked && !grow_only && avail > headroom * 3 && plugged > self.floor && since > Duration::from_secs(10) {
            plugged.saturating_sub((avail - headroom * 2) / STEP_MIB * STEP_MIB).max(self.floor)
        } else {
            plugged
        };
        Some(Plan { settle, new, charge: new.saturating_sub(requested.max(plugged)), short, stale })
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
/// reboot clears it. Deadlines use boot-clock seconds and the boot id also
/// expires old wall-clock records. An entry a minute past its cooldown is forgotten.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct PeerBackoff {
    delay: u64,
    until: u64,
    #[serde(default)]
    boot: String,
}

impl PeerBackoff {
    fn ready(&self, now: u64) -> bool {
        !self.recent(now) || now >= self.until
    }

    fn recent(&self, now: u64) -> bool {
        !self.boot.is_empty() && self.boot == crate::host::boot_id() && now < self.until.saturating_add(60)
    }

    fn refuse(&mut self, now: u64) {
        if !self.recent(now) {
            self.delay = 0;
        }
        self.delay = self.delay.saturating_mul(2).clamp(5, 60);
        self.until = now.saturating_add(self.delay);
        self.boot = crate::host::boot_id().into();
    }
}

fn eviction_time() -> u64 {
    crate::host::boottime_ms() / 1000
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
/// `evict_marks` (`RUN/evict.active` while it lasts). A starved VM is moved
/// whenever it asks, pressure or not. Nothing is done when MemAvailable
/// cannot be read (`avail` None): that is no pressure.
fn relieve(host: &Host, avail: Option<u64>, starved_here: bool, stopping: &mut Option<Stopping>) {
    let Some(avail) = avail else {
        *stopping = None;
        return;
    };
    let cfg = host.config_now();
    let (reserve, at, until) = cfg.evict_marks();
    // Standby VMs go under the reserve whatever eviction is doing (a slow migration holds its lock).
    if avail >= reserve {
        *stopping = None;
    } else if stop_standby(host, avail, reserve, stopping) {
        return;
    }
    let active = host.run.join("evict.active");
    let evicting = active.exists();
    if (avail >= at && !evicting && !starved_here) || EVICTING.load(Ordering::SeqCst) {
        return;
    }
    let Ok(lock) = std::fs::File::options().create(true).truncate(false).write(true).open(host.state.join("evict.lock")) else { return };
    let Ok(lock) = crate::host::Flock::new(lock, libc::LOCK_EX | libc::LOCK_NB) else { return };
    let pressure = avail < until && (evicting || avail < at);
    if pressure && !evicting {
        let _ = std::fs::write(&active, b"");
        crate::log!("host has {avail} MiB available, under its {at} MiB high-water mark ({reserve} MiB reserve): moving vms to peers until it has {until} MiB");
    } else if !pressure && evicting {
        let _ = std::fs::remove_file(&active);
        crate::log!("host has {avail} MiB available, {until} MiB or more: eviction stops");
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
    let mut vms = rank(host.entries(), rss);
    if !pressure {
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
                return crate::log!("eviction: {e}");
            }
        };
        evict(&host, &cfg.peers, &vms, avail, Instant::now() + EVICT_DEADLINE);
        EVICTING.store(false, Ordering::SeqCst);
    });
}

/// Standby VMs a controller signalled, settled on its later ticks, never
/// waited for. `STATE/standby.stop.lock` is held only until its next tick starts.
struct Stopping {
    lock: Option<crate::host::Flock>,
    fds: Vec<crate::host::PidFd>,
    by: Instant,
}

/// Under the reserve: SIGUSR1s the standby VMs, under `STATE/standby.stop.lock`
/// (not eviction's lock, which a migration may hold for a while), and marks
/// the pressure so they are not refilled. True until any exits (an idle one
/// takes ~200 ms) or a second passes, while another process is stopping
/// them (it evicts if none exits), and while a refill's standby is not listed
/// yet (`standby::refill`, seconds at most). Loading or claimed VMs must not hold eviction off.
fn stop_standby(host: &Host, avail: u64, reserve: u64, stopping: &mut Option<Stopping>) -> bool {
    if let Some(s) = stopping {
        let stopped = s.fds.iter().filter(|fd| fd.wait(Duration::ZERO)).count();
        if stopped == 0 && Instant::now() < s.by {
            return true;
        }
        *stopping = None;
        if stopped > 0 {
            crate::log!("host has {avail} MiB available, under its {reserve} MiB reserve: stopped {stopped} standby vms");
        }
        return stopped > 0;
    }
    let Ok(lock) = crate::standby::stop_lock(host) else { return false };
    let Ok(lock) = crate::host::Flock::new(lock, libc::LOCK_EX | libc::LOCK_NB) else { return true };
    let fds: Vec<_> =
        crate::standby::templates(host).iter().flat_map(|t| crate::standby::stoppable(host, t)).filter_map(|id| crate::standby::stop(&id)).collect();
    if fds.is_empty() {
        return false;
    }
    let _ = std::fs::write(crate::standby::pressure(host), b"");
    *stopping = Some(Stopping { lock: Some(lock), fds, by: Instant::now() + Duration::from_secs(1) });
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
    backoff.retain(|_, b| b.recent(now));
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
            if Instant::now() >= deadline {
                return;
            }
            crate::log!("vm {}: {why} ({avail} MiB available); migrating to {peer}", vm.name);
            match call(host, &vm.name, json!({"op": "migrate", "to": peer, "if_idle": true, "evict": true}), Some(deadline)) {
                Ok(_) => {
                    backoff.remove(&key);
                    let _ = crate::host::store(&backoff_path, &backoff, false);
                    crate::log!("vm {}: migrated to {peer}", vm.name);
                    while host.entry(&vm.name).is_ok_and(|e| e.ident == vm.ident) {
                        if Instant::now() >= deadline {
                            return crate::log!("vm {}: its copy here still serves pages to {peer} at the eviction's deadline", vm.name);
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    return;
                }
                Err(e) if e.to_string().contains(BUSY) => break,
                // No answer is no refusal: the VM may still be migrating (busy to the next decider).
                Err(e) if Instant::now() >= deadline => {
                    return crate::log!("vm {}: migrating to {peer}: no answer by the eviction's deadline: {e}", vm.name);
                }
                Err(e) => {
                    crate::log!("vm {}: migrating to {peer}: {e}", vm.name);
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

pub fn peer_call(peer: &str, req: Value) -> Result<Value> {
    Ok(crate::util::rpc(peer, Duration::from_millis(500), Instant::now() + Duration::from_secs(2), &req)?.1)
}

/// Two calls and the pause between them (`tell`).
const TELL_WAIT: Duration = Duration::from_secs(5);

/// Tells every peer at once, waiting `TELL_WAIT` at most, a hung lookup of a
/// peer's name included: a peer not told by then is told on alone.
pub fn tell_peers(host: &Host, req: Value) {
    each_peer(host.config_now().peers, Instant::now() + TELL_WAIT, move |p| drop(tell(p, req.clone())));
}

/// Runs `f` for every peer at once, each on a thread of its own, and waits until all are
/// done or `by`: one slow or down peer holds up no other, and a peer not done by then
/// finishes alone.
fn each_peer(peers: Vec<String>, by: Instant, f: impl Fn(&str) + Send + Sync + 'static) {
    let f = Arc::new(f);
    // Nothing is sent: the wait ends once every thread has dropped its sender, or at `by`.
    let (done, finished) = std::sync::mpsc::channel::<()>();
    for p in peers {
        let (f, done) = (f.clone(), done.clone());
        if let Err(e) = thread::Builder::new().spawn(move || {
            f(&p);
            drop(done);
        }) {
            crate::log!("cannot start a peer call: {e}");
        }
    }
    drop(done);
    let _ = finished.recv_timeout(by.saturating_duration_since(Instant::now()));
}

/// The route announcements the peers have yet to take, the newest per peer: one thread of the process's own hands each
/// to a thread of its own, retrying with backoff (a thread not had, a lookup or a call failed) until it is delivered, a
/// newer one replaces it, or its peer is no longer configured. Callers never wait on a peer.
pub struct Announcer {
    pending: Mutex<std::collections::HashMap<String, Pending>>,
    wake: std::sync::Condvar,
    spawn: fn(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
    call: fn(&str, &Value) -> Result<()>,
    /// The peers configured now.
    peers: Box<dyn Fn() -> Vec<String> + Send + Sync>,
    retry: (Duration, Duration),
}

struct Pending {
    req: Value,
    at: Instant,
    backoff: Duration,
    tries: u32,
    /// The call in flight: its dispatch's number, which only its own `done` matches.
    busy: Option<u64>,
}

/// The first and longest pause between tries: a peer down for long is tried quietly, and told once it is back.
const ANNOUNCE_RETRY: (Duration, Duration) = (Duration::from_millis(250), Duration::from_secs(60));

impl Announcer {
    fn start(
        spawn: fn(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
        call: fn(&str, &Value) -> Result<()>,
        peers: Box<dyn Fn() -> Vec<String> + Send + Sync>,
        retry: (Duration, Duration),
    ) -> std::io::Result<Arc<Announcer>> {
        let a = Arc::new(Announcer { pending: Mutex::default(), wake: Default::default(), spawn, call, peers, retry });
        let me = a.clone();
        thread::Builder::new().name("announce".into()).spawn(move || me.run())?;
        Ok(a)
    }

    /// The route part of `Proc::announce`, independent of the VM and its ARP device.
    fn route(&self, cfg: &crate::host::Config, ip: Ipv4Addr, gen: u64, rev: u64, local: impl FnOnce() -> bool) -> bool {
        let peers = cfg.peers.clone();
        let Some(via) = cfg.underlay() else {
            if !peers.is_empty() {
                crate::log!("announce {ip}: no underlay address (give flexvm listen an ADDR peers can reach, or flexvm config --underlay IP); peers not told");
            }
            return false;
        };
        if local() {
            self.tell(peers, json!({"op": "route", "ip": ip.to_string(), "via": via.to_string(), "gen": gen, "rev": rev}));
        }
        true
    }

    /// `req` for each of `peers` (and none for any other), unless one of its address with a newer generation or
    /// revision is pending.
    fn tell(&self, peers: Vec<String>, req: Value) {
        let newer = |old: &Value| old["ip"] == req["ip"] && (old["gen"].as_u64(), old["rev"].as_u64()) > (req["gen"].as_u64(), req["rev"].as_u64());
        let mut p = self.pending.lock().unwrap();
        p.retain(|peer, _| peers.contains(peer));
        for peer in peers {
            let fresh = Pending { req: req.clone(), at: Instant::now(), backoff: self.retry.0, tries: 0, busy: None };
            match p.get_mut(&peer) {
                Some(e) if newer(&e.req) => {}
                Some(e) => *e = Pending { busy: e.busy, ..fresh },
                None => drop(p.insert(peer, fresh)),
            }
        }
        self.wake.notify_all();
    }

    fn run(self: Arc<Self>) {
        let mut seq = 0;
        loop {
            let due: Vec<_> = {
                let mut p = self.pending.lock().unwrap();
                // Read under the lock: a peer configured and told since is not pruned by an older list.
                let peers = (self.peers)();
                p.retain(|peer, _| peers.contains(peer));
                let now = Instant::now();
                p.iter_mut()
                    .filter(|(_, e)| e.busy.is_none() && e.at <= now)
                    .map(|(peer, e)| {
                        seq += 1;
                        e.busy = Some(seq);
                        (peer.clone(), e.req.clone(), seq)
                    })
                    .collect()
            };
            // Unlocked: `tell` never waits on a thread being had.
            for (peer, req, seq) in due {
                let (me, to, sent) = (self.clone(), peer.clone(), req.clone());
                if let Err(err) = (self.spawn)(Box::new(move || me.done(&to, seq, &sent, (me.call)(&to, &sent)))) {
                    self.done(&peer, seq, &req, Err(format!("no thread: {err}").into()));
                }
            }
            let p = self.pending.lock().unwrap();
            let next = p.values().filter(|e| e.busy.is_none()).map(|e| e.at).min();
            drop(match next {
                Some(at) => self.wake.wait_timeout(p, at.saturating_duration_since(Instant::now())).unwrap().0,
                None => self.wake.wait(p).unwrap(),
            });
        }
    }

    /// Call `seq` of `req` to `peer` ended: delivered, it is no longer pending, unless a newer one replaced it meanwhile.
    fn done(&self, peer: &str, seq: u64, req: &Value, r: Result<()>) {
        let mut p = self.pending.lock().unwrap();
        // Not this call's entry: pruned meanwhile, and maybe added afresh.
        let Some(e) = p.get_mut(peer).filter(|e| e.busy == Some(seq)) else { return };
        e.busy = None;
        let what = format!("announce {} gen {} to {peer}", req["ip"].as_str().unwrap_or("?"), req["gen"]);
        match r {
            _ if e.req != *req => {}
            Ok(()) => {
                if e.tries > 0 {
                    crate::log!("{what}: delivered after {} failed tries", e.tries);
                }
                p.remove(peer);
            }
            Err(err) => {
                e.tries += 1;
                // Only the first failure and the delivery are logged.
                if e.tries == 1 {
                    crate::log!("{what}: {err}; trying again until it is delivered or {peer} is no longer a peer");
                }
                e.at = Instant::now() + e.backoff;
                e.backoff = (e.backoff * 2).min(self.retry.1);
            }
        }
        self.wake.notify_all();
    }
}

/// A route message, sent once more a second after it fails: nothing else
/// sends it again, and a peer may be refusing it only for the moment (its
/// listener restarting, or still looking up this host's name).
fn tell(peer: &str, req: Value) -> Result<Value> {
    peer_call(peer, req.clone()).or_else(|_| {
        thread::sleep(Duration::from_secs(1));
        peer_call(peer, req)
    })
}

/// Refuses a page-server request on no page slot: draining for at most `PAGE_REFUSAL` in all while fewer than
/// `MAX_PAGES` refusals do, otherwise without waiting on the client.
/// The one refusal of a page request not for a source here, sent by the
/// listener (no such VM) and by a VM (not the source) alike: a peer cannot
/// tell from it which VMs run here.
pub fn refuse_not_source(s: std::net::TcpStream, name: &str, mig: &Value) {
    refuse_pages(s, &format!("vm {name:?} is not the source of migration {mig}"));
}

fn refuse_pages(s: std::net::TcpStream, why: &str) {
    let draining = Slot::take(&PAGE_REFUSALS, MAX_PAGES);
    crate::listen::refuse(s, why, draining.as_ref().map(|_| PAGE_REFUSAL));
}

/// Connects and sends `req` by `at`; the stream's reads and writes then block.
pub fn connect(host: &Host, name: &str, req: &Value, fds: &[i32], at: Instant) -> Result<UnixStream> {
    let (sock, log) = (host.sock(name)?, host.vms(name, "log")?);
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    let c = crate::util::send_unix(&sock, &line, fds, at).map_err(|e| {
        if host.alive(name) {
            format!("vm {name:?} is starting or its control socket is unavailable; retry once it is ready, or see {}: {e}", log.display())
        } else if host.is_suspended(name) {
            format!("vm {name:?} is suspended; use flexvm resume {name} first")
        } else {
            format!("no vm named {name:?}")
        }
    })?;
    c.set_read_timeout(None)?;
    c.set_write_timeout(None)?;
    Ok(c)
}

/// With `at`, connected, sent and answered by then; otherwise only connecting and sending time out.
pub fn call(host: &Host, name: &str, req: Value, at: Option<Instant>) -> Result<Value> {
    let c = connect(host, name, &req, &[], at.unwrap_or_else(|| Instant::now() + Duration::from_secs(10)))?;
    let reply = match at {
        Some(at) => crate::util::recv_json(&mut BufReader::new(crate::util::By { s: c, at })),
        None => crate::util::recv_json(&mut BufReader::new(c)),
    }?;
    answer(reply, &format!("vm {name}"), "refused")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_controllers_are_whole_words() {
        for (controllers, memory, cpu) in [
            ("", false, false),
            ("cpuset", false, false),
            ("cpuset memory", true, false),
            ("cpu", false, true),
            ("cpu memory", true, true),
            ("\tio\ncpuset cpu  memory\n", true, true),
            ("memory_extra cpuacct", false, false),
        ] {
            assert_eq!(has_controller(controllers, "memory"), memory, "{controllers:?}");
            assert_eq!(has_controller(controllers, "cpu"), cpu, "{controllers:?}");
        }
    }

    /// An arrival admitted for its source's RSS at preflight is admitted the
    /// rest of what it pulls, short of the guest's size: then what it is
    /// admitted covers what it pages in, and nothing is asked twice.
    #[test]
    fn an_arrival_is_admitted_what_it_grew_by() {
        use crate::limit::allowance;
        // Grew from 256 MiB to 2 GiB of a 4 GiB guest: its allowance, less what it had.
        let granted = allowance(256);
        assert_eq!(arrival_more(granted, (2048, 4096)), allowance(2048) - granted);
        // Shrank, or the same: nothing more.
        assert_eq!(arrival_more(granted, (100, 4096)), 0);
        assert_eq!(arrival_more(allowance(2048), (2048, 4096)), 0);
        // Never past the guest's size, yet at least what it pulls.
        assert_eq!(arrival_more(granted, (4000, 4096)), 4096 - granted);
        assert_eq!(arrival_more(0, (4096, 4096)), 4096);
        // What `start_limit` then tops up (need less granted) is nothing.
        for need in [0, 1, 256, 1000, 2048, 4096] {
            let more = arrival_more(granted, (need, 4096));
            assert!(granted + more >= need, "{need}");
        }
    }

    /// The wait ends with the last peer done, or at its deadline while one still runs.
    #[test]
    fn each_peer_waits_until_done_or_by() {
        let done = Arc::new(Mutex::new(Vec::new()));
        let d = done.clone();
        let t = Instant::now();
        each_peer(vec!["a".into(), "b".into()], t + Duration::from_secs(10), move |p| d.lock().unwrap().push(p.to_string()));
        assert!(t.elapsed() < Duration::from_secs(5));
        assert_eq!(done.lock().unwrap().len(), 2);
        let t = Instant::now();
        each_peer(vec!["hung".into(), "fast".into()], t + Duration::from_millis(200), |p| {
            if p == "hung" {
                thread::sleep(Duration::from_secs(3));
            }
        });
        let took = t.elapsed();
        assert!(took >= Duration::from_millis(200) && took < Duration::from_secs(2), "{took:?}");
    }

    /// An announcement waits out refused threads and failed lookups, and is delivered (the newest one) once both can be had.
    #[test]
    fn an_announcement_is_delivered_once_threads_and_its_lookup_can_be_had() {
        use std::sync::atomic::AtomicUsize;
        static SPAWNS: AtomicUsize = AtomicUsize::new(0);
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = format!("localhost:{}", l.local_addr().unwrap().port());
        let configured = peer.clone();
        let a = Announcer::start(
            |f| match SPAWNS.fetch_add(1, Ordering::SeqCst) {
                0 | 1 => Err(std::io::ErrorKind::WouldBlock.into()),
                _ => thread::Builder::new().spawn(f).map(drop),
            },
            |peer, req| match CALLS.fetch_add(1, Ordering::SeqCst) {
                0 | 1 => Err(format!("DNS lookup of {peer}: cannot start a thread").into()),
                _ => peer_call(peer, req.clone()).map(drop),
            },
            Box::new(move || vec![configured.clone()]),
            ANNOUNCE_RETRY,
        )
        .unwrap();
        let route = |gen: u64| json!({"op": "route", "ip": "10.0.0.9", "via": "10.1.0.1", "gen": gen, "rev": 0});
        let t = Instant::now();
        a.tell(vec![peer.clone()], route(3));
        a.tell(vec![peer.clone()], route(4));
        a.tell(vec![peer.clone()], route(2));
        assert!(t.elapsed() < Duration::from_millis(100), "the caller does not wait");
        let (mut c, _) = l.accept().unwrap();
        let req = crate::util::recv_json(&mut BufReader::new(c.try_clone().unwrap())).unwrap().unwrap();
        writeln!(c, "{}", json!({"ok": true, "result": null})).unwrap();
        assert_eq!(req, route(4), "the newest generation");
        assert!(SPAWNS.load(Ordering::SeqCst) >= 4 && CALLS.load(Ordering::SeqCst) >= 3);
        let end = Instant::now() + Duration::from_secs(5);
        while !a.pending.lock().unwrap().is_empty() {
            assert!(Instant::now() < end, "delivered, no longer pending");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Component coverage: a Host, the real memory admission/watch loop, a file-backed cgroup,
    /// and the production route announcer. No hypervisor, VM, network device or cgroup is created.
    #[test]
    fn live_config_reaches_the_running_memory_loop_and_route_announcer() {
        let root = crate::test_util::TempDir::new("live-config-component");
        let mut writer = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        first.set_nonblocking(true).unwrap();
        second.set_nonblocking(true).unwrap();
        let first_peer = first.local_addr().unwrap().to_string();
        let second_peer = second.local_addr().unwrap().to_string();
        writer
            .configure(|cfg| {
                cfg.reserve_mib = Some(u64::MAX / 4);
                cfg.peers = vec![first_peer.clone()];
                cfg.underlay = Some("192.0.2.10".parse().unwrap());
                cfg.announce_dev = Some("none".into());
                Ok(())
            })
            .unwrap();
        let running = writer.clone();
        let cg = root.join("cgroup");
        std::fs::create_dir(&cg).unwrap();
        for (file, value) in [("memory.high", "max"), ("memory.current", "0"), ("memory.events", "high 0")] {
            std::fs::write(cg.join(file), value).unwrap();
        }
        let limit = Arc::new(crate::limit::Limit::new(Some(cg.clone())));
        limit.start(512, 4096);
        let original_high = std::fs::read_to_string(cg.join("memory.high")).unwrap();
        std::fs::write(cg.join("memory.current"), &original_high).unwrap();
        let peers_host = running.clone();
        let announcer = Announcer::start(
            |f| thread::Builder::new().spawn(f).map(drop),
            // Bounds that only catch a hang: a call timed out under load would be retried,
            // and the retry would look like a route to a removed peer.
            |peer, req| crate::util::rpc(peer, Duration::from_secs(30), Instant::now() + Duration::from_secs(60), req).map(drop),
            Box::new(move || peers_host.config_now().peers),
            ANNOUNCE_RETRY,
        )
        .unwrap();
        let (commands, command_rx) = std::sync::mpsc::channel();
        let (results, result_rx) = std::sync::mpsc::channel();
        let watched = limit.clone();
        let controller = thread::spawn(move || {
            let started = std::cell::Cell::new(false);
            let revision = std::cell::Cell::new(0);
            watched.watch(
                &running,
                Duration::from_millis(1),
                || {
                    if started.replace(true) {
                        results.send((watched.admitted(), watched.throttled.load(Ordering::SeqCst))).unwrap();
                    }
                    if command_rx.recv().is_err() {
                        return false;
                    }
                    revision.set(revision.get() + 1);
                    announcer.route(&running.config_now(), "10.0.0.9".parse().unwrap(), 7, revision.get(), || true);
                    true
                },
                || true,
            );
        });
        let tick = || {
            commands.send(()).unwrap();
            result_rx.recv_timeout(Duration::from_secs(60)).unwrap()
        };
        let receive = |listener: &std::net::TcpListener, via: &str| {
            let end = Instant::now() + Duration::from_secs(60);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < end, "route message was not delivered");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
            let req = crate::util::recv_json(&mut BufReader::new(socket.try_clone().unwrap())).unwrap().unwrap();
            writeln!(socket, "{}", json!({"ok": true, "result": null})).unwrap();
            assert_eq!(req["op"], "route");
            assert_eq!(req["ip"], "10.0.0.9");
            assert_eq!(req["gen"], 7);
            assert_eq!(req["via"], via);
        };
        assert_eq!(tick(), (512, true), "the running loop refuses growth at the reserve");
        receive(&first, "192.0.2.10");
        assert_eq!(std::fs::read_to_string(cg.join("memory.high")).unwrap(), original_high);

        // A partially written configuration must retain the last successfully loaded settings.
        std::fs::write(writer.state.join("host.json"), b"{\"reserve_mib\":").unwrap();
        assert_eq!(tick(), (512, true));
        receive(&first, "192.0.2.10");
        assert_eq!(second.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);

        // Repair the malformed file before applying the next normal config update.
        crate::host::store(&writer.state.join("host.json"), &writer.cfg, true).unwrap();
        writer
            .configure(|cfg| {
                cfg.reserve_mib = Some(0);
                cfg.peers = vec![second_peer.clone()];
                cfg.underlay = Some("192.0.2.20".parse().unwrap());
                Ok(())
            })
            .unwrap();
        // Keep the same watcher and its admission backoff: it eventually retries and lifts throttling.
        let end = Instant::now() + Duration::from_secs(60);
        loop {
            let (admitted, throttled) = tick();
            receive(&second, "192.0.2.20");
            if !throttled {
                assert!(admitted > 512);
                break;
            }
            assert!(Instant::now() < end, "repaired config never admitted growth");
            thread::sleep(Duration::from_millis(30));
        }
        assert!(std::fs::read_to_string(cg.join("memory.high")).unwrap().trim().parse::<u64>().unwrap() > original_high.trim().parse::<u64>().unwrap());
        assert_eq!(first.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock, "removed peers receive no new routes");
        drop(commands);
        controller.join().unwrap();
    }

    /// A peer no longer configured is not told on; one down for long (past 36 tries) is told once it is back.
    #[test]
    fn announcements_stop_for_removed_peers_and_reach_one_back_up() {
        static CALLS: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let configured = Arc::new(Mutex::new(vec!["gone".to_string(), "down".to_string()]));
        let c = configured.clone();
        let a = Announcer::start(
            |f| thread::Builder::new().spawn(f).map(drop),
            |peer, _| {
                let mut calls = CALLS.lock().unwrap();
                calls.push(peer.into());
                match calls.iter().filter(|c| *c == "down").count() {
                    41.. if peer == "down" => Ok(()),
                    _ => Err("refused".into()),
                }
            },
            Box::new(move || c.lock().unwrap().clone()),
            (Duration::from_millis(1), Duration::from_millis(5)),
        )
        .unwrap();
        let calls = |p: &str| CALLS.lock().unwrap().iter().filter(|c| *c == p).count();
        let until = |done: &dyn Fn() -> bool| {
            let end = Instant::now() + Duration::from_secs(10);
            while !done() {
                assert!(Instant::now() < end);
                thread::sleep(Duration::from_millis(1));
            }
        };
        // Not told under `configured`'s guard: the announcer reads the peers under `pending`, which tell takes.
        let peers = configured.lock().unwrap().clone();
        a.tell(peers, json!({"op": "route", "ip": "10.0.0.9", "gen": 1, "rev": 0}));
        until(&|| calls("gone") > 0);
        configured.lock().unwrap().retain(|p| p != "gone");
        until(&|| a.pending.lock().unwrap().is_empty());
        let gone = calls("gone");
        assert!(gone < 10, "pruned once no longer configured: {gone}");
        assert_eq!(calls("down"), 41, "tried until delivered, then no more");
        thread::sleep(Duration::from_millis(100));
        assert_eq!((calls("gone"), calls("down")), (gone, 41), "and never called again");
    }

    /// A peer configured and told while the announcer reads the peers is not pruned by the list it read.
    #[test]
    fn a_peer_added_meanwhile_is_not_pruned_by_an_older_list() {
        static CALLS: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let configured = Arc::new(Mutex::new(Vec::<String>::new()));
        let me: Arc<std::sync::OnceLock<std::sync::Weak<Announcer>>> = Default::default();
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (c, m, armed2) = (configured.clone(), me.clone(), armed.clone());
        let a = Announcer::start(
            |f| thread::Builder::new().spawn(f).map(drop),
            |peer, _| {
                CALLS.lock().unwrap().push(peer.into());
                Ok(())
            },
            Box::new(move || {
                let old = c.lock().unwrap().clone();
                if armed2.swap(false, Ordering::SeqCst) {
                    // The peer is configured and told after this list is read, before it is used.
                    let (c, a) = (c.clone(), m.get().unwrap().upgrade().unwrap());
                    thread::spawn(move || {
                        c.lock().unwrap().push("b".into());
                        a.tell(vec!["b".into()], json!({"op": "route", "ip": "10.0.0.9", "gen": 1, "rev": 0}));
                    });
                    thread::sleep(Duration::from_millis(100));
                }
                old
            }),
            ANNOUNCE_RETRY,
        )
        .unwrap();
        me.set(Arc::downgrade(&a)).unwrap();
        armed.store(true, Ordering::SeqCst);
        a.tell(Vec::new(), json!({}));
        let end = Instant::now() + Duration::from_secs(5);
        while !CALLS.lock().unwrap().contains(&"b".to_string()) {
            assert!(Instant::now() < end, "b was told");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn an_unrecorded_owed_outcome_refuses_the_kill_and_keeps_reconciling() {
        let r = Mutex::new(Some((7, "b:1".to_string())));
        let mut calls = 0;
        let e = owe_or_refuse(&r, 7, 3, |to| {
            assert_eq!(to, "b:1");
            calls += 1;
            Err("disk full".into())
        });
        assert!(e.unwrap_err().to_string().contains("disk full"));
        assert_eq!(calls, 3, "retried, bounded");
        assert_eq!(*r.lock().unwrap(), Some((7, "b:1".to_string())), "still reconciling: its thread goes on asking");
        // Another migration's kill is not this one's.
        assert!(owe_or_refuse(&r, 8, 3, |_| panic!("not reconciling 8")).unwrap().is_none());
        // Recorded on a later try: the mark is taken, so the reconciliation stands down.
        let mut calls = 0;
        let got = owe_or_refuse(&r, 7, 3, |_| {
            calls += 1;
            if calls < 2 {
                Err("transient".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(got.unwrap().as_deref(), Some("b:1"));
        assert!(r.lock().unwrap().is_none());
    }

    #[test]
    fn pauses_run_one_at_a_time_the_newest_winning() {
        let l = Latest::default();
        assert!(l.offer(libc::SIGTSTP), "the first starts the worker");
        assert!(!l.offer(libc::SIGCONT), "one worker at a time");
        assert_eq!(l.next(), Some(libc::SIGCONT), "a SIGCONT after a waiting SIGTSTP wins");
        assert!(!l.offer(libc::SIGTSTP));
        assert_eq!(l.next(), Some(libc::SIGTSTP), "taken by the running worker, in order");
        assert_eq!(l.next(), None);
        assert!(l.offer(libc::SIGCONT), "stopped: the next offer starts another");
    }

    #[test]
    fn no_pause_offer_is_lost_to_a_stopping_worker() {
        let l = Arc::new(Latest::default());
        let (handled, workers) = (Arc::new(AtomicI32::new(0)), Arc::new(AtomicI32::new(0)));
        for i in 1..=2000 {
            let sig = if i % 2 == 0 { libc::SIGCONT } else { libc::SIGTSTP };
            if l.offer(sig) {
                let (l, handled, workers) = (l.clone(), handled.clone(), workers.clone());
                workers.fetch_add(1, Ordering::SeqCst);
                thread::spawn(move || {
                    while let Some(sig) = l.next() {
                        handled.store(sig, Ordering::SeqCst);
                    }
                    workers.fetch_sub(1, Ordering::SeqCst);
                });
            }
            while workers.load(Ordering::SeqCst) > 0 && i % 100 == 0 {
                thread::yield_now();
            }
        }
        let end = Instant::now() + Duration::from_secs(5);
        while (workers.load(Ordering::SeqCst) > 0 || l.busy.load(Ordering::SeqCst)) && Instant::now() < end {
            thread::yield_now();
        }
        assert_eq!(handled.load(Ordering::SeqCst), libc::SIGCONT, "the last offer was handled");
        assert_eq!(l.wanted.load(Ordering::SeqCst), 0);
    }

    fn test_proc(tag: &str) -> (Arc<Proc>, crate::test_util::TempDir) {
        let root = crate::test_util::TempDir::new(&format!("fv-proc-{tag}"));
        std::fs::create_dir_all(root.join("templates/.gen/a")).unwrap();
        std::os::unix::fs::symlink(".gen/a", root.join("templates/default")).unwrap();
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        (Proc::new(host, Paths::new(&root)).unwrap(), root)
    }

    #[test]
    fn control_is_bound_synchronously_and_repeated_serving_keeps_the_listener() {
        use std::os::unix::fs::MetadataExt;
        let (p, _root) = test_proc("control-bind");
        p.set_name(p.host.take_name("bound", false).unwrap());
        let sock = p.host.sock("bound").unwrap();
        p.serve_control().unwrap();
        let inode = std::fs::metadata(&sock).unwrap().ino();
        p.serve_control().unwrap();
        assert_eq!(std::fs::metadata(&sock).unwrap().ino(), inode);
        let mut c = UnixStream::connect(sock).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        send_json(&mut c, &json!({"op": "unknown"})).unwrap();
        let reply = crate::util::recv_json(&mut BufReader::new(c)).unwrap().unwrap();
        assert_eq!(reply["error"], "unknown op \"unknown\"");
    }

    #[test]
    fn start_fails_before_publication_when_control_cannot_bind() {
        let (p, _root) = test_proc("control-bind-fails");
        p.set_name(p.host.take_name("blocked", false).unwrap());
        let sock = p.host.sock("blocked").unwrap();
        std::fs::create_dir(&sock).unwrap();
        // No VM is needed: binding must fail before start_guest can publish it.
        let e = p.start_guest(&mut Phases::new()).unwrap_err();
        assert!(e.to_string().contains("no control socket"), "{e}");
        assert!(!*p.serving.lock().unwrap());
        assert!(!p.host.vms("blocked", "json").unwrap().exists());
        std::fs::remove_dir(sock).unwrap();
        p.serve_control().unwrap();
    }

    #[test]
    fn control_replies_to_invalid_json_and_accepts_a_large_escaped_command() {
        static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let (p, _root) = test_proc("control-requests");
        let large = json!({"op": "unknown", "cmd": "\u{1}".repeat(1 << 20)}).to_string();
        assert!(large.len() > 1 << 20 && large.len() < crate::util::MAX_LINE as usize);
        for (request, error) in [("{invalid".to_string(), "bad request:"), (large, "unknown op")] {
            let (mut client, server) = UnixStream::pair().unwrap();
            client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            client.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let q = p.clone();
            let slot = Slot::take(&COUNT, MAX_CONTROL).unwrap();
            let worker = thread::spawn(move || q.control(server, slot));
            use std::io::Write;
            writeln!(client, "{request}").unwrap();
            let reply = crate::util::recv_json(&mut BufReader::new(client)).unwrap().unwrap();
            assert_eq!(reply["ok"], false);
            assert!(reply["error"].as_str().unwrap().starts_with(error), "{reply}");
            worker.join().unwrap();
            assert_eq!(COUNT.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn a_pause_waiting_for_the_vm_yields_to_a_destroy() {
        let (p, root) = test_proc("destroy");
        let held = p.op();
        let q = p.clone();
        let pause = thread::spawn(move || q.op_unless_destroyed().map(drop).map_err(|e| e.to_string()));
        thread::sleep(Duration::from_millis(50));
        // As `destroy` does before it waits for `op`; the pause gets it first.
        p.destroying.store(128 + libc::SIGQUIT, Ordering::SeqCst);
        drop(held);
        assert!(pause.join().unwrap().unwrap_err().contains("being destroyed"));
        assert_eq!(p.destroy_code(), Some(131), "a kill that cancels a suspend reports it");
        // Refused (`destroy` takes its code back): the next pause goes ahead.
        let _ = p.destroying.compare_exchange(131, 0, Ordering::SeqCst, Ordering::SeqCst);
        assert!(p.op_unless_destroyed().is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_resume_asked_while_a_sigterm_is_taken_waits_for_its_reservation() {
        let (p, root) = test_proc("resume-taking");
        assert!(p.ask_resume().is_some());
        // The signal thread has taken a SIGTERM (no longer pending) and not yet reserved.
        let taking = p.taking.lock().unwrap();
        let q = p.clone();
        let asked = thread::spawn(move || q.ask_resume());
        thread::sleep(Duration::from_millis(50));
        assert!(!asked.is_finished(), "waits for the signal thread");
        *p.suspending.lock().unwrap() = Suspend::Suspending;
        drop(taking);
        assert!(asked.join().unwrap().is_none());
        *p.suspending.lock().unwrap() = Suspend::Idle;
        p.early.lock().unwrap().push(libc::SIGTERM);
        assert!(p.ask_resume().is_none(), "queued at startup, still to be replayed");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resume_tickets_are_answered_by_the_handling_that_covers_them() {
        let (r, l) = (Resumes::default(), Latest::default());
        let sent = std::cell::Cell::new(0);
        let (one, two) = (r.ask(|| sent.set(sent.get() + 1)), r.ask(|| sent.set(sent.get() + 1)));
        assert_eq!((one, two, sent.get()), (1, 2, 2));
        assert!(r.offer(libc::SIGCONT, || l.offer(libc::SIGCONT)), "starts the worker");
        // Asked after that SIGCONT was offered: its own comes later.
        let three = r.ask(|| ());
        let (sig, upto) = r.next(|| l.next()).unwrap();
        assert_eq!((sig, upto), (libc::SIGCONT, 2));
        r.answer(upto, sig, Err("resume failed part way".into()));
        assert_eq!(r.wait(one, Duration::ZERO), Some(Err("resume failed part way".into())));
        assert_eq!(r.wait(two, Duration::ZERO), Some(Err("resume failed part way".into())));
        assert_eq!(r.wait(three, Duration::from_millis(20)), None, "not answered yet: bounded");
        // Its SIGCONT, then a later Ctrl-Z that wins: answered as paused again, never left waiting.
        assert!(!r.offer(libc::SIGCONT, || l.offer(libc::SIGCONT)));
        assert!(!r.offer(libc::SIGTSTP, || l.offer(libc::SIGTSTP)));
        let (sig, upto) = r.next(|| l.next()).unwrap();
        assert_eq!((sig, upto), (libc::SIGTSTP, 3));
        r.answer(upto, sig, Ok(()));
        assert!(r.wait(three, Duration::ZERO).unwrap().unwrap_err().contains("paused again"));
        // An older handling finishing late changes nothing.
        r.answer(2, libc::SIGCONT, Ok(()));
        assert!(r.wait(three, Duration::ZERO).unwrap().is_err());
        let four = r.ask(|| ());
        assert!(!r.offer(libc::SIGCONT, || l.offer(libc::SIGCONT)));
        let (sig, upto) = r.next(|| l.next()).unwrap();
        r.answer(upto, sig, Ok(()));
        assert_eq!(r.wait(four, Duration::ZERO), Some(Ok(())));
        assert!(r.next(|| l.next()).is_none(), "the worker stops");
    }

    #[test]
    fn a_resume_answers_without_any_signal_taken() {
        // No signal thread (nor a SIGCONT a Ctrl-Z could erase): answered at once, from what is pending.
        let (p, root) = test_proc("resume-pending");
        thread::spawn(move || {
            let set = crate::util::block_signals(&[libc::SIGTERM, libc::SIGTSTP]);
            unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTSTP) };
            let t = Instant::now();
            assert!(p.ask_resume().is_some(), "a pending Ctrl-Z is no suspend");
            unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
            assert!(p.ask_resume().is_none(), "a SIGTERM not yet taken");
            assert!(t.elapsed() < Duration::from_secs(1));
            while crate::util::take_signal(&set).is_some() {}
        })
        .join()
        .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_blocked_signal_not_yet_taken_is_pending() {
        thread::spawn(|| {
            let set = crate::util::block_signals(&[libc::SIGUSR2]);
            assert!(!crate::util::signal_pending(libc::SIGUSR2));
            unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGUSR2) };
            assert!(crate::util::signal_pending(libc::SIGUSR2));
            assert_eq!(crate::util::wait_signal(&set), libc::SIGUSR2);
            assert!(!crate::util::signal_pending(libc::SIGUSR2));
        })
        .join()
        .unwrap();
    }

    #[test]
    fn claim_keeps_termination_requests() {
        let mut early = vec![libc::SIGUSR1, libc::SIGINT, libc::SIGTSTP, libc::SIGTERM, libc::SIGUSR1, libc::SIGCONT];
        forget_stop(&mut early);
        assert_eq!(early, [libc::SIGINT, libc::SIGTSTP, libc::SIGTERM, libc::SIGCONT]);
    }

    /// Only the pool's own stop leaves an unclaimed standby with 0; a signal sent to it gives 128 + it.
    #[test]
    fn standby_stops_exit_with_their_signal() {
        assert_eq!(stop_status(&[]), None);
        assert_eq!(stop_status(&[libc::SIGTSTP, libc::SIGCONT, libc::SIGHUP]), None);
        assert_eq!(stop_status(&[libc::SIGUSR1]), Some(0));
        for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM] {
            assert_eq!(stop_status(&[sig]), Some(128 + sig));
            assert_eq!(stop_status(&[libc::SIGUSR1, libc::SIGTSTP, sig]), Some(128 + sig));
        }
        assert_eq!(stop_status(&[libc::SIGTERM, libc::SIGINT]), Some(128 + libc::SIGTERM));
    }

    /// MemAvailable unreadable (None) is no pressure: no standby is stopped
    /// and no eviction is tried; read as under the reserve, both are.
    #[test]
    fn unreadable_meminfo_relieves_nothing() {
        let base = crate::test_util::TempDir::new("relieve");
        let mut host = Host::open(&base.join("state"), &base.join("run")).unwrap();
        host.cfg.reserve_mib = Some(1024);
        host.cfg.peers = vec!["127.0.0.1:1".into()];
        // A standby of template t: its lock held, naming a live process.
        // Stopped by SIGUSR1's default action, which an ignored or blocked SIGUSR1 inherited from here would defeat.
        let mut child = std::process::Command::new("sleep");
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut child, || {
                libc::signal(libc::SIGUSR1, libc::SIG_DFL);
                Ok(())
            });
        }
        let mut child = child.arg("30").spawn().unwrap();
        let d = crate::standby::dir(&host, "t");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(".template"), "t").unwrap();
        let id = Ident::of(child.id()).unwrap();
        let path = d.join(format!("{}.lock", id.key()));
        let lock = std::fs::File::create(&path).unwrap();
        let lock = crate::host::Flock::new(lock, libc::LOCK_EX).unwrap();
        std::fs::write(&path, serde_json::to_vec(&id).unwrap()).unwrap();
        assert_eq!(crate::standby::live(&host, "t").len(), 1);
        let (pressure, active) = (crate::standby::pressure(&host), host.run.join("evict.active"));
        let mut stopping = None;
        for starved in [false, true] {
            relieve(&host, None, starved, &mut stopping);
            assert!(!pressure.exists() && !active.exists());
            assert!(child.try_wait().unwrap().is_none(), "a standby was stopped");
        }
        // Mid-claim (`PID-START.claim` locked): not counted as stopped, so eviction starts.
        let id = Ident::of(child.id()).unwrap();
        let claim = std::fs::File::create(d.join(format!("{}.claim", id.key()))).unwrap();
        let claim = crate::host::Flock::new(claim, libc::LOCK_EX).unwrap();
        relieve(&host, Some(0), false, &mut stopping);
        assert!(!pressure.exists() && active.exists());
        assert!(child.try_wait().unwrap().is_none(), "a claiming standby was stopped");
        std::fs::remove_file(&active).unwrap();
        // A claim rolled back makes the standby stoppable again.
        drop(claim);
        relieve(&host, Some(0), false, &mut stopping);
        use std::os::unix::process::ExitStatusExt;
        let stopped = crate::util::retry(Duration::from_secs(10), Duration::from_millis(10), || Ok(child.try_wait()?.ok_or("running")?));
        let _ = child.kill();
        let _ = child.wait();
        assert!(pressure.exists() && stopped.unwrap().signal() == Some(libc::SIGUSR1));
        drop(lock);
        // Its exit is counted at the next tick, which leaves eviction to the one after.
        relieve(&host, Some(0), false, &mut stopping);
        assert!(!active.exists() && stopping.is_none());
        relieve(&host, Some(0), false, &mut stopping);
        assert!(active.exists(), "with no standby left, eviction starts");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_standby_that_has_not_exited_marks_the_pressure_and_holds_eviction_off_a_second_without_waiting() {
        let base = crate::test_util::TempDir::new("relieve-pending");
        let host = Host::open(&base.join("state"), &base.join("run")).unwrap();
        let mut child = std::process::Command::new("sleep");
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut child, || {
                libc::signal(libc::SIGUSR1, libc::SIG_IGN);
                Ok(())
            });
        }
        let mut child = child.arg("30").spawn().unwrap();
        let id = Ident::of(child.id()).unwrap();
        let d = crate::standby::dir(&host, "t");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(".template"), "t").unwrap();
        let path = d.join(format!("{}.lock", id.key()));
        let lock = std::fs::File::create(&path).unwrap();
        let _lock = crate::host::Flock::new(lock, libc::LOCK_EX).unwrap();
        std::fs::write(&path, serde_json::to_vec(&id).unwrap()).unwrap();
        // Loading, or claimed since enumeration: a delivered signal proves neither stopped,
        // but it will stop, so it is not refilled meanwhile.
        let (mut stopping, active) = (None, host.run.join("evict.active"));
        let start = Instant::now();
        relieve(&host, Some(0), false, &mut stopping);
        relieve(&host, Some(0), false, &mut stopping);
        let (took, pressure, held) = (start.elapsed(), crate::standby::pressure(&host).exists(), active.exists());
        thread::sleep(Duration::from_secs(1));
        relieve(&host, Some(0), false, &mut stopping);
        let evicting = active.exists();
        let running = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        std::fs::remove_dir_all(base).unwrap();
        assert!(took < Duration::from_millis(500), "{took:?}");
        assert!(pressure && !held && evicting && running && stopping.is_none());
    }

    #[test]
    fn peer_backoff_uses_boot_clock_across_a_wall_clock_step() {
        // At refusal the wall clock is far ahead of boot time. After a backward
        // wall-clock step, only elapsed boot seconds should govern the cooldown.
        crate::host::pin_clock(100_000);
        assert_eq!(eviction_time(), 100);
        let mut backoff = PeerBackoff::default();
        backoff.refuse(eviction_time());
        let wall_before = 10_000;
        let wall_until = wall_before + backoff.delay;
        let backoff: PeerBackoff = serde_json::from_slice(&serde_json::to_vec(&backoff).unwrap()).unwrap();
        crate::host::pin_clock(104_000);
        assert!(!backoff.ready(eviction_time()));
        crate::host::pin_clock(105_000);
        let wall_after = wall_before - 3600 + 5;
        assert!(wall_after < wall_until, "a wall-clock deadline would still skip this peer");
        assert!(backoff.ready(eviction_time()));
        crate::host::pin_clock(165_000);
        assert!(!backoff.recent(eviction_time()));
    }

    #[test]
    fn peer_backoffs_from_another_boot_or_the_old_wall_clock_format_expire() {
        let mut backoff = PeerBackoff::default();
        backoff.refuse(100);
        backoff.boot = "earlier-boot".into();
        assert!(!backoff.recent(1));
        assert!(backoff.ready(1));
        backoff.refuse(1);
        assert_eq!(backoff.delay, 5);
        assert!(!backoff.ready(1));
        let legacy: PeerBackoff = serde_json::from_str(r#"{"delay":60,"until":1700000000}"#).unwrap();
        assert!(!legacy.recent(100));
        assert!(legacy.ready(100));
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
        let mut c = crate::host::Config { reserve_mib: Some(1024), ..Default::default() };
        assert_eq!(c.evict_marks(), (1024, 2048, 2560));
        c.reserve_mib = Some(256);
        assert_eq!(c.evict_marks(), (256, 768, 1024));
        c.evict_mib = Some(5000);
        assert_eq!(c.evict_marks(), (256, 5000, 7372));
        // Never under the reserve; a mark at it still stops a little above.
        c.evict_mib = Some(100);
        assert_eq!(c.evict_marks(), (256, 256, 384));
        // A hand-edited reserve near u64::MAX saturates instead of wrapping.
        c.reserve_mib = Some(u64::MAX - 1);
        assert_eq!(c.evict_marks(), (u64::MAX - 1, u64::MAX - 1, u64::MAX));
    }

    const SIZES: Sizes = Sizes { mem_mib: 256, floor: 4096, hotplug_total: 31744 };

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn memory_hints_only_grow() {
        for avail in [7800, 99999999 >> 10, u64::MAX] {
            assert_eq!(SIZES.plan(8192, 8192, avail, secs(11), true, false), Some(Plan { settle: false, new: 8192, charge: 0, short: false, stale: false }));
        }
        // Balloon statistics still reclaim surplus memory.
        assert_eq!(SIZES.plan(8192, 8192, 7800, secs(11), false, false), Some(Plan { settle: false, new: 4736, charge: 0, short: false, stale: false }));
        // A fresh hint bypasses the statistics delay and grows promptly.
        let p = SIZES.plan(8192, 8192, 0, Duration::ZERO, true, false).unwrap();
        assert!(p.new > 8192 && p.charge == p.new - 8192 && p.short, "{p:?}");
        assert_eq!(SIZES.plan(8192, 8192, 0, Duration::ZERO, false, false).unwrap().new, 8192);
    }

    #[test]
    fn stalled_growth_is_settled_not_recharged() {
        // Growth 4096 -> 5248 outstanding and short: busy, nothing charged.
        assert_eq!(SIZES.plan(5248, 4096, 512, secs(5), false, false), None);
        // Stalled: settled at what is plugged; a tick right after (stale stats) does not grow.
        let p = SIZES.plan(5248, 4096, 512, secs(11), false, false).unwrap();
        assert_eq!(p, Plan { settle: true, new: 4096, charge: 0, short: true, stale: true });
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
        assert_eq!(SIZES.plan(4736, 8192, 7800, secs(11), false, false), Some(Plan { settle: true, new: 8192, charge: 0, short: false, stale: true }));
        // 10 s later the shrink is chosen again, from what is plugged.
        assert_eq!(SIZES.plan(8192, 8192, 7800, secs(11), false, false), Some(Plan { settle: false, new: 4736, charge: 0, short: false, stale: false }));
    }

    #[test]
    fn short_guest_cancels_a_pending_shrink() {
        // Shrink 4096 -> 3072 outstanding, guest short: grow from what is plugged.
        let p = SIZES.plan(3072, 4096, 512, secs(2), true, false).unwrap();
        assert!(!p.settle && p.new > 4096 && p.charge == p.new - 4096, "{p:?}");
    }

    #[test]
    fn a_refused_plug_is_not_the_ceiling() {
        // Only at its ceiling is the guest told `full` (it lifts its throttle);
        // refused by the reserve it stays throttled (#368).
        assert_eq!(Resized::of(false, true, true, false), Resized::Full);
        assert_eq!(Resized::of(false, true, false, true), Resized::Refused);
        assert_eq!(Resized::of(false, false, false, true), Resized::Same);
        assert_eq!(Resized::of(true, true, false, false), Resized::Grew);
    }

    #[test]
    fn refused_growth_stays_starved_across_stale_ticks_and_retries() {
        let (mut starved, mut logged) = (false, 0);
        let mut observe = |plan: Plan, refused| {
            let next = plan.starved(starved, refused);
            logged += usize::from(next && !starved);
            starved = next;
            next
        };
        // A plug just completed. A fresh guest hint is refused before balloon
        // statistics leave the 1.5 s delay; ticks in that window charge nothing.
        let hint = || SIZES.plan(8192, 8192, 0, Duration::from_millis(250), true, false).unwrap();
        assert!(observe(hint(), true));
        for ms in [500, 1000, 1499] {
            // Both short and apparently recovered stale statistics must preserve it.
            for avail in [0, 7800] {
                let tick = SIZES.plan(8192, 8192, avail, Duration::from_millis(ms), false, false).unwrap();
                assert_eq!(tick.charge, 0);
                assert!(observe(tick, false));
                assert!(observe(hint(), true));
            }
        }
        // Once the delay ends, a tick asks admission too. Refusal (including
        // backoff) is still the same episode, however many times it retries.
        for ms in [1500, 2000, 5000, 15000] {
            let tick = SIZES.plan(8192, 8192, 0, Duration::from_millis(ms), false, false).unwrap();
            assert!(tick.charge > 0);
            assert!(observe(tick, true));
        }
        // A granted step really ends the refusal; another refusal starts a new episode.
        assert!(!observe(hint(), false));
        assert!(observe(hint(), true));
        // Fresh evidence of enough headroom also ends it.
        let recovered = SIZES.plan(8192, 8192, 7800, secs(2), false, false).unwrap();
        assert!(!observe(recovered, false));
        assert_eq!(logged, 2, "one log per episode, including all retries");
    }

    #[test]
    fn refused_growth_backs_off_until_a_grant() {
        let (mut b, t) = (GrantBackoff::default(), Instant::now());
        assert!(b.ready(t));
        let mut waits = vec![];
        for _ in 0..7 {
            b.refused(t);
            waits.push(b.until.unwrap() - t);
        }
        let ms = |n| Duration::from_millis(n);
        assert_eq!(waits, [ms(250), ms(500), ms(1000), ms(2000), ms(4000), ms(5000), ms(5000)]);
        assert!(!b.ready(t + ms(4999)) && b.ready(t + ms(5000)));
        b.granted();
        assert!(b.ready(t));
        b.refused(t);
        assert_eq!(b.until, Some(t + ms(250)));
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

#[cfg(test)]
mod session_relay_tests {
    use super::*;
    use std::io::{self, Cursor};

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.output.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl crate::util::Timed for Duplex {
        fn read_timeout(&self, _: Duration) -> io::Result<()> {
            Ok(())
        }
        fn write_timeout(&self, _: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn exit_acknowledgement_uses_the_existing_attachment_and_is_optional() {
        let out = guest::frame(guest::FRAME_STDOUT, &[&0u64.to_le_bytes()[..], b"hi"]);
        let exit = [out, guest::frame(guest::FRAME_EXIT, &[&2u64.to_le_bytes()[..], &7i32.to_le_bytes()])].concat();
        for ack in [vec![], vec![guest::SESSION_DONE], vec![b'?']] {
            // The exit ends the relay, with the stream still open (vsock passes no half-close on).
            let mut guest = BufReader::new(Duplex { input: Cursor::new([&exit[..], b"never read"].concat()), output: Vec::new() });
            let mut client = Duplex { input: Cursor::new(ack.clone()), output: Vec::new() };
            relay_session(&mut guest, &mut client, CLIENT_STALL).unwrap();
            assert_eq!(client.output, exit);
            assert_eq!(guest.get_ref().output, if ack == [guest::SESSION_DONE] { ack } else { vec![] });
        }
    }

    #[test]
    fn a_silent_client_releases_the_relay_within_its_deadline() {
        let exit = guest::frame(guest::FRAME_EXIT, &[&0u64.to_le_bytes()[..], &0i32.to_le_bytes()]);
        let mut guest = BufReader::new(Duplex { input: Cursor::new(exit.clone()), output: Vec::new() });
        let (relay, mut client) = UnixStream::pair().unwrap();
        // Reads the exit, then neither acknowledges nor hangs up.
        let silent = thread::spawn(move || {
            let mut got = vec![0; exit.len()];
            client.read_exact(&mut got).unwrap();
            thread::sleep(Duration::from_secs(6));
        });
        let t = Instant::now();
        relay_session(&mut guest, &mut &relay, CLIENT_STALL).unwrap();
        assert!(t.elapsed() < Duration::from_secs(4), "the relay waited {:?}", t.elapsed());
        assert!(guest.get_ref().output.is_empty());
        silent.join().unwrap();
    }

    #[test]
    fn a_stalled_client_is_dropped_after_its_deadline() {
        // The guest has output to spare; the client never reads.
        let (relay_end, mut agent) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            for i in 0..1024u64 {
                if agent.write_all(&guest::frame(guest::FRAME_STDOUT, &[&(i * 65536).to_le_bytes()[..], &[b'x'; 65536]])).is_err() {
                    break;
                }
            }
        });
        let mut guest = BufReader::new(relay_end);
        let (relay, _client) = UnixStream::pair().unwrap();
        let t = Instant::now();
        let err = relay_session(&mut guest, &mut &relay, Duration::from_secs(1)).unwrap_err();
        assert!(err.to_string().contains("took no output for 1 s"), "{err}");
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        // Dropped, the guest's connection ends unacknowledged: the session stays for a reattach.
        drop(guest);
        writer.join().unwrap();
    }
}
