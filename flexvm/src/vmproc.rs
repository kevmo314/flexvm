//! The VM process: `flexvm run` (and `resume`, `restore`, an incoming
//! migration, a standby VM) is a process that is one VM. It owns the
//! Firecracker it spawns, the pager, the tap and route, packet holds, guest
//! sessions and checkpoints, and exits when the VM is gone.
//!
//! Signals: SIGTERM suspends, SIGTSTP pauses, SIGCONT resumes, SIGINT
//! destroys. A control socket (`RUN/vms/NAME.sock`) takes `exec`,
//! `checkpoint`, `migrate`, `debug`, page connections passed on by the peer
//! listener (`pages`), and a standby VM's `claim`. Every operation on the VM,
//! starting it included, holds `op`, so they never interleave; and the
//! process ends only through `finish`, which holds it too.

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
use crate::vm::{State, Vm};

/// How long a requested operation waits for another one on the same VM.
pub const OP_WAIT: Duration = Duration::from_secs(30);
/// Guest clock error tolerated after a restore or resume.
pub const CLOCK_TOLERANCE: Duration = Duration::from_millis(20);
/// How long checking and stepping the guest clock may take.
pub const CLOCK_DEADLINE: Duration = Duration::from_secs(5);

/// The signals a VM process takes (all others keep their defaults).
const SIGNALS: [i32; 5] = [libc::SIGTERM, libc::SIGINT, libc::SIGTSTP, libc::SIGCONT, libc::SIGHUP];

/// How a VM process starts.
pub enum Start {
    Run { name: String, template: String, ip: Option<Ipv4Addr>, cmd: Option<String> },
    /// A suspended VM.
    Resume { name: String },
    Restore { dir: PathBuf, name: Option<String>, ip: Option<String>, paused: bool },
    /// Spawned by the peer listener with the migration connection as fd 3.
    Incoming { req: Value },
    Standby { template: String },
}

/// The VM's operation lock, held.
pub type Op<'a> = MutexGuard<'a, ()>;

/// How the VM left this process, which decides what becomes of its address.
pub enum End {
    /// Destroyed, or died: the address is withdrawn.
    Gone,
    /// Suspended to disk: the address stays held by its name.
    Suspended,
    /// Migrated to the peer listening at `.0`, which has all its memory.
    Moved(String),
    /// Never started here (it may still run elsewhere, or be suspended).
    NotStarted,
}

pub struct Proc {
    pub host: Host,
    pub paths: Paths,
    pub spawner: Spawner,
    /// This process, as the registry names it.
    ident: Ident,
    name: Mutex<Option<NameLock>>,
    addr: Mutex<Option<AddrClaim>>,
    vm: OnceLock<Arc<Vm>>,
    op: Mutex<()>,
    holder: OnceLock<Option<Arc<Holder>>>,
    /// The migration this VM arrived by, until all its pages are in.
    pub arrived: Mutex<Option<MigRecord>>,
    /// The right of that migration's source to send the packets it held.
    pub held_in: Mutex<Option<Arc<Mutex<bool>>>>,
    /// Where the app's output has been copied up to (image templates).
    pub app_log: AtomicU64,
    /// Exit when the VM leaves: set while a migration away may commit.
    leaving: AtomicBool,
    /// A standby VM not claimed yet.
    pub standby: Mutex<Option<crate::standby::Paused>>,
    /// The `run` that claimed this standby VM: told the exit status.
    pub claimer: Mutex<Option<UnixStream>>,
    /// The VM's one command (`run NAME -- CMD`).
    pub cmd: Mutex<Option<String>>,
    /// Signals that came before the VM was up, handled once it is.
    early: Mutex<Vec<i32>>,
    /// Paused by SIGTSTP (or held by `restore --paused`): only then does
    /// SIGCONT resume it. The kernel sends SIGCONT after any SIGSTOP, and
    /// systemd right after SIGTERM.
    pub paused_by_request: AtomicBool,
    /// A resumed suspended VM's checkpoint, deleted once all its pages are
    /// in, or when the process ends (it is marked STARTED: consumed).
    pub consumed: Mutex<Option<PathBuf>>,
    /// A route to a migration target that could not be set yet (retried
    /// in the background, and once more before the process ends).
    pub pending_route: Mutex<Option<Ipv4Addr>>,
    /// Files this process owns, removed when it ends (a standby VM's socket and lock).
    pub files: Mutex<Vec<PathBuf>>,
    /// The control socket is open.
    serving: AtomicBool,
    me: std::sync::Weak<Proc>,
}

/// Control connections served at once; more are refused.
const MAX_CONTROL: usize = 256;
static CONTROL: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Proc {
    fn new(host: Host, paths: Paths) -> Result<Arc<Proc>> {
        let ident = Ident::me();
        let work = host.run.join("w").join(ident.pid.to_string());
        // A dead process with this pid left it: what it ran goes first.
        if let Some(old) = std::fs::read_to_string(work.join("owner")).ok().and_then(|s| s.parse().ok()) {
            crate::host::reap(&host.run, old)?;
        }
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work)?;
        std::fs::write(work.join("owner"), ident.to_string())?;
        let sockets = crate::socket::SocketRoot::new(&work)?;
        let tap_prefix = format!("{}{:x}t", host.cfg.prefix, ident.pid);
        let spawner = Spawner::new(&paths.firecracker, &work, sockets, cgroup_root(), &tap_prefix);
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
            standby: Mutex::new(None),
            claimer: Mutex::new(None),
            cmd: Mutex::new(None),
            early: Mutex::new(Vec::new()),
            paused_by_request: AtomicBool::new(false),
            consumed: Mutex::new(None),
            pending_route: Mutex::new(None),
            files: Mutex::new(Vec::new()),
            serving: AtomicBool::new(false),
            me: me.clone(),
        }))
    }

    pub fn vm(&self) -> &Arc<Vm> {
        self.vm.get().expect("no vm yet")
    }

    pub fn set_vm(&self, vm: Arc<Vm>) {
        let _ = self.vm.set(vm);
    }

    pub fn name(&self) -> String {
        self.name.lock().unwrap().as_ref().map(|n| n.name.clone()).unwrap_or_default()
    }

    pub fn set_name(&self, n: NameLock) {
        *self.name.lock().unwrap() = Some(n);
    }

    /// The VM's address and generation are this process's from here on.
    pub fn set_addr(&self, a: AddrClaim) -> Ipv4Addr {
        let ip = a.ip;
        *self.addr.lock().unwrap() = Some(a);
        ip
    }

    /// Borrows `ip`, of another host's range, from that host, for VM `name`
    /// (a restore keeping its checkpoint's address): its home host lends it
    /// out, as to a VM migrating away, with a new generation.
    pub fn borrow(&self, name: &str, ip: Ipv4Addr) -> Result<AddrClaim> {
        let mut why = Vec::new();
        for peer in &self.host.cfg.peers {
            let gen = match peer_call(peer, json!({"op": "lend", "ip": ip.to_string()})) {
                Ok(r) => r["gen"].as_u64().filter(|&g| g > 0).ok_or_else(|| format!("{peer} lent {ip} without a generation"))?,
                Err(e) => {
                    why.push(format!("{peer}: {e}"));
                    continue;
                }
            };
            let claimed = self.host.lock().and_then(|l| self.host.claim_incoming(&l, name, ip, gen));
            return match claimed {
                Ok(mut c) => {
                    c.fresh = true;
                    Ok(c)
                }
                Err(e) => {
                    let _ = peer_call(peer, json!({"op": "route", "ip": ip.to_string(), "gen": gen}));
                    bail!("cannot take {ip} borrowed from {peer}: {e}; restore with --ip auto")
                }
            };
        }
        bail!("cannot borrow {ip} from its home host ({}); restore with --ip auto", why.join("; "))
    }

    /// Lets the VM's name keep its address after this process (suspended).
    pub fn keep_addr(&self) {
        if let Some(a) = self.addr.lock().unwrap().take() {
            a.keep();
        }
    }

    /// The host lock, if the VM's address's generation is still current:
    /// taken right before the VM runs, and held until it does, so no message
    /// about a newer generation is taken in meanwhile.
    pub fn still_current(&self, ip: Ipv4Addr) -> Result<crate::host::Locked> {
        let l = self.host.lock()?;
        let gen = self.gen();
        if !self.host.current(&l, ip, gen)? {
            bail!("{ip}'s generation {gen} was withdrawn or given out again meanwhile; restore with --ip auto");
        }
        Ok(l)
    }

    /// The generation of the VM's address (see `host::Addr`).
    pub fn gen(&self) -> u64 {
        self.addr.lock().unwrap().as_ref().map_or(0, |a| a.gen)
    }

    /// Takes the VM's operation lock, however long that takes: for what must
    /// not be refused (starting, destroying, suspending, ending).
    pub fn op(&self) -> Op<'_> {
        self.op.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `op` for a request, which gives up after `OP_WAIT`.
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

    /// This process's hold device (made on first use, before any pause).
    pub fn holder(&self) -> Option<&Arc<Holder>> {
        self.holder
            .get_or_init(|| {
                let dev = format!("{}{:x}h", self.host.cfg.prefix, self.ident.pid);
                Holder::new(&dev).unwrap_or_else(|e| {
                    eprintln!("packets in flight while the vm is paused will be dropped: {e}");
                    None
                })
            })
            .as_ref()
    }

    /// Writes the VM's registry entry as it is now.
    pub fn publish(&self) {
        let Some(vm) = self.vm.get() else { return };
        let name = self.name.lock().unwrap();
        let Some(n) = name.as_ref() else { return };
        let e = Entry {
            name: n.name.clone(),
            pid: self.ident.pid,
            start: self.ident.start,
            ip: Some(vm.ip),
            gen: self.gen(),
            template: vm.template.name.clone(),
            template_id: vm.template.meta.id.clone(),
            vcpus: vm.template.meta.vcpus,
            max_mib: vm.template.meta.max_mib,
            state: vm.state().name().into(),
            firecracker: vm.pid(),
            starved: vm.starved.load(Ordering::SeqCst),
        };
        if let Err(e) = n.publish(&e) {
            eprintln!("vm {}: registry: {e}", n.name);
        }
    }

    /// Ends the process, the one way it ends: kills the VM, if there is one,
    /// and waits for its Firecracker to exit; settles its address as `end`
    /// says; forgets an arrival that never committed (one that did counts as
    /// released once this process is gone); deletes a consumed checkpoint;
    /// gives up the name; sends `last` on its connection, and the exit status
    /// to a claimer; exits with `code`. Holding `op`, so nothing else runs.
    pub fn finish(&self, _op: &Op, end: End, code: i32, last: Option<(&UnixStream, Value)>) -> ! {
        self.drop_held_in();
        self.set_leaving(true);
        if let Some(vm) = self.vm.get() {
            vm.kill();
        }
        drop(self.standby.lock().unwrap().take());
        let addr = self.addr.lock().unwrap().take();
        match (end, addr) {
            (End::Suspended, Some(a)) => a.keep(),
            (End::Gone, Some(a)) => self.withdraw(a),
            (End::NotStarted, Some(a)) if a.fresh => self.withdraw(a),
            (End::Moved(to), a) => {
                drop(a);
                let name = self.name();
                let _ = std::fs::write(self.host.run.join("vms").join(format!("{name}.moved")), &to);
                eprintln!("vm {name}: moved to {to}");
            }
            (_, Some(a)) => {
                // Never ran here: a peer's route for it comes back (say its
                // migration source's, which runs it again).
                let ip = a.ip;
                if let Ok(l) = self.host.lock() {
                    let _ = a.release(&l);
                    let _ = self.host.reinstall(&l, ip);
                }
            }
            (_, None) => {}
        }
        drop(self.arrived.lock().unwrap().take());
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
        let _ = std::io::stdout().flush();
        std::process::exit(code)
    }

    /// Destroys the VM (SIGINT, or its command ended) and ends the process
    /// with `code`. A checkpoint in progress gives up first. Returns only if
    /// refused: a VM paused here as a migration source is never killed, as
    /// its target may still be pulling its memory.
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
            return source();
        }
        self.finish(&op, End::Gone, code, None)
    }

    /// The VM's address is free again here, and peers are told so (all of
    /// it done before this returns, as the process is about to exit). Its
    /// route goes, or, if a peer announced a newer generation meanwhile,
    /// points there again.
    fn withdraw(&self, a: AddrClaim) {
        let (ip, gen) = (a.ip, a.gen);
        if let Ok(l) = self.host.lock() {
            // Only while it is ours: never another VM's route.
            let ours = self.host.holder(&l, ip).is_ok_and(|h| h.is_none_or(|h| h == self.name()));
            let _ = a.release(&l);
            let _ = self.host.observe(&l, ip, gen, None);
            if ours && !self.host.reinstall(&l, ip).unwrap_or(false) {
                crate::net::unroute(ip);
            }
        }
        let req = json!({"op": "route", "ip": ip.to_string(), "gen": gen});
        let sends: Vec<_> = self.host.cfg.peers.iter().cloned().map(|p| {
            let req = req.clone();
            thread::spawn(move || peer_call(&p, req))
        }).collect();
        for s in sends {
            let _ = s.join();
        }
    }

    /// Points the network at this host for the VM's address: a gratuitous
    /// ARP for the LAN and a route for each peer, in the background, each
    /// only while the VM is still served from here.
    pub fn announce(&self) {
        let vm = self.vm().clone();
        let (ip, gen) = (vm.ip, self.gen());
        let peers = self.host.cfg.peers.clone();
        let dev = self.host.cfg.announce_dev.clone();
        let Some(via) = self.host.cfg.underlay() else {
            if !peers.is_empty() {
                eprintln!("announce {ip}: no underlay address (set --listen or --underlay); peers not told");
            }
            return;
        };
        thread::spawn(move || {
            let here = || vm.state().local();
            if let Some(dev) = dev.as_deref().filter(|_| here()) {
                if let Err(e) = crate::net::gratuitous_arp(dev, ip) {
                    eprintln!("announce {ip}: {e}");
                }
            }
            for peer in &peers {
                if !here() {
                    return;
                }
                let req = json!({"op": "route", "ip": ip.to_string(), "via": via.to_string(), "gen": gen});
                if let Err(e) = peer_call(peer, req) {
                    eprintln!("announce {ip} to {peer}: {e}");
                }
            }
            if let Some(dev) = &dev {
                thread::sleep(Duration::from_millis(200));
                if here() {
                    let _ = crate::net::gratuitous_arp(dev, ip);
                }
            }
        });
    }

    /// Revokes the right of the migration this VM arrived by to send it held
    /// packets (it is killed or leaving), stopping a stream in progress.
    pub fn drop_held_in(&self) {
        if let Some(revoked) = self.held_in.lock().unwrap().take() {
            *revoked.lock().unwrap() = true;
        }
    }

    // Starting.

    /// A VM from a template, loaded here.
    fn run(&self, name: &str, template: &str, want: Option<Ipv4Addr>) -> Result<Value> {
        let mut t = Phases::new();
        self.set_name(self.host.take_name(name, false)?);
        let tpl = Template::open(&self.paths, template)?;
        t.mark("template");
        let claim = {
            let l = self.host.lock()?;
            self.host.claim_new(&l, name, want)?
        };
        let ip = self.set_addr(claim);
        t.mark("claim_ip");
        crate::host::stall("start_stall");
        let load = if fault("resume_kill") { crate::vm::Load::RunningKilled } else { crate::vm::Load::Running };
        // The first load of a template on this host learns what loads touch.
        let learn = crate::standby::load_set(&self.host, &tpl).is_empty();
        let (vm, _) = Vm::restore(&self.spawner, name, tpl.clone(), crate::vm::Snapshot::Path(&tpl.vmstate()), None, ip, load, learn, &mut t)?;
        if learn {
            crate::standby::save_load_set(&self.host, &tpl);
        }
        self.set_vm(vm);
        let mut v = self.start_guest(&mut t)?;
        v["hot"] = json!(false);
        Ok(v)
    }

    /// The guest of a VM that runs now: address, clock, app.
    pub fn start_guest(&self, t: &mut Phases) -> Result<Value> {
        let vm = self.vm().clone();
        self.publish();
        t.mark("register");
        let running = t.total();
        vm.guest_net(vm.ip, self.host.cfg.dns.as_deref())?;
        if t.mark("guest_net") >= crate::vm::CLOCK_RTT {
            // START's clock is behind by its transit time; fixed off this path.
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

    // Steady state.

    /// Opens the control socket (once): before the VM is reported ready, so
    /// whoever started it can use it right away.
    pub fn serve_control(self: &Arc<Self>) {
        if self.serving.swap(true, Ordering::SeqCst) {
            return;
        }
        let sock = self.host.sock(&self.name());
        let _ = std::fs::remove_file(&sock);
        match UnixListener::bind(&sock) {
            Ok(l) => {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600));
                let p = self.clone();
                thread::spawn(move || {
                    for c in l.incoming().flatten() {
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
            Err(e) => eprintln!("vm {}: no control socket at {}: {e}", self.name(), sock.display()),
        }
    }

    /// Runs the controller and the VM's helpers, handles the signals that
    /// came while it started. Never returns: the process ends with the VM.
    fn serve(self: &Arc<Self>) -> ! {
        self.serve_control();
        let p = self.clone();
        thread::spawn(move || p.controller());
        let p = self.clone();
        thread::spawn(move || p.serve_memory());
        if self.vm().template.meta.image.is_some() {
            let p = self.clone();
            thread::spawn(move || p.follow_app());
        }
        if let Some(cmd) = self.cmd.lock().unwrap().clone() {
            let p = self.clone();
            thread::spawn(move || p.main_command(&cmd));
        }
        let early = std::mem::take(&mut *self.early.lock().unwrap());
        for sig in early {
            self.signal(sig);
        }
        // The main thread spawned the Firecracker, which dies with the thread.
        loop {
            thread::park();
        }
    }

    fn signal(&self, sig: i32) {
        let Some(vm) = self.vm.get() else {
            // Not up yet: handled once it is (a standby VM goes at once).
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
            // A migration source goes once its target has the memory; a
            // target still pulling is suspended once it has it all (`save`).
            libc::SIGTERM if matches!(vm.state(), State::Source(_)) => {
                eprintln!("vm {}: migrating away; it ends once the target has its memory", vm.name);
                Ok(())
            }
            libc::SIGTERM => Err(self.suspend()),
            libc::SIGINT => Err(self.destroy(0)),
            _ => Ok(()),
        };
        if let Err(e) = res {
            eprintln!("vm {}: signal {sig}: {e}", vm.name);
        }
    }

    /// One control connection: a request line, possibly with fds.
    fn control(self: &Arc<Self>, c: UnixStream) {
        // A client that never sends its request does not keep the connection.
        let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
        let (line, fds) = match crate::util::recv_with_fds(&c, 1 << 20) {
            Ok(r) => r,
            Err(_) => return,
        };
        let _ = c.set_read_timeout(None);
        let Ok(req) = serde_json::from_slice::<Value>(&line) else { return };
        let reply = match req["op"].as_str().unwrap_or("") {
            "exec" => return self.exec(&req, c),
            "pages" => return self.pages(&req, fds),
            "checkpoint" => self.op_within().and_then(|op| {
                let stop = req["stop"].as_bool().unwrap_or(false);
                let v = self.checkpoint(&op, req["dir"].as_str().unwrap_or(""), stop, req["incremental"].as_bool().unwrap_or(false))?;
                if stop {
                    self.finish(&op, End::Gone, 0, Some((&c, json!({"ok": true, "result": v}))));
                }
                Ok(v)
            }),
            "migrate" => self.migrate(req["to"].as_str().unwrap_or("")),
            "debug" => self.debug(&req),
            "claim" => Err("this vm is not a standby vm".into()),
            op => Err(format!("unknown op {op:?}").into()),
        };
        let reply = match reply {
            Ok(v) => json!({"ok": true, "result": v}),
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        };
        let _ = send_json(&mut &c, &reply);
    }

    /// A page connection the peer listener passed on: answered with one
    /// JSON line, then served (`serve_pages`) while this VM is the source of
    /// that migration.
    fn pages(&self, req: &Value, fds: Vec<OwnedFd>) {
        let Some(fd) = fds.into_iter().next() else { return };
        let s = std::net::TcpStream::from(fd);
        let vm = self.vm();
        let source = req["mig"].as_u64().map(State::Source);
        if source != Some(vm.state()) {
            return crate::listen::refuse_pages(s, &format!("vm {} is not the source of migration {}", vm.name, req["mig"]));
        }
        if fault("pages") {
            return crate::listen::refuse_pages(s, "injected fault: page server down");
        }
        let _ = s.set_nodelay(true);
        let served = (|| -> Result<()> {
            send_json(&mut &s, &json!({"ok": true}))?;
            let r = BufReader::new(s.try_clone()?);
            Ok(crate::uffd::serve_pages(&vm.pager, &s, ReadWrite(r, s.try_clone()?), || fault("pages") || Some(vm.state()) != source)?)
        })();
        if let Err(e) = served {
            eprintln!("vm {}: page server: {e}", vm.name);
        }
    }

    fn exec(&self, req: &Value, c: UnixStream) {
        let mut w = &c;
        let vm = self.vm();
        let cmd = req["cmd"].as_str().unwrap_or("");
        let started = vm.exec(|s| match req["session"].as_str() {
            Some(id) => guest::session(s, req["action"].as_str().unwrap_or("start"), id, req["offset"].as_u64().unwrap_or(0), cmd, guest::TIMEOUT),
            None => guest::start_exec(s, cmd, guest::TIMEOUT),
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
            std::io::copy(&mut g, &mut w)?;
            Ok(())
        })();
        vm.untrack_exec(id);
    }

    /// Test hooks (FLEXVM_FAULTS=1).
    fn debug(&self, req: &Value) -> Result<Value> {
        if req["what"] != "status" && std::env::var("FLEXVM_FAULTS").ok().as_deref() != Some("1") {
            bail!("memhash needs FLEXVM_FAULTS=1");
        }
        let vm = self.vm();
        match req["what"].as_str().unwrap_or("") {
            "memhash" => self.memhash(),
            // Set the VM's hotplug size directly, as the controller would.
            "hotplug" => {
                let _op = self.op_within()?;
                if vm.state() != State::Running {
                    bail!("vm {} is not running here", vm.name);
                }
                *vm.last_resize.lock().unwrap() = Instant::now();
                let mib = req["mib"].as_u64().ok_or("missing mib")?;
                vm.fc(|fc| fc.patch("/hotplug/memory", json!({"requested_size_mib": mib})))
            }
            "status" => Ok(json!({
                "state": vm.state().name(),
                "background_pull_ms": vm.pager.pull_time().map(ms),
                "remote_left": vm.pager.remote_left(),
                "failed": vm.pager.failed(),
                "checkpoint_copy_stats": vm.pager.copy_stats(),
                "describe": vm.describe(),
                "loads": crate::vm::loads(),
                "guest_retries": guest::retries(),
            })),
            w => bail!("unknown debug request {w:?}"),
        }
    }

    /// Once a second: notices a VM that died or lost its memory, resizes
    /// its memory, retries held report releases, and takes a turn at
    /// relieving the host's memory pressure.
    fn controller(self: Arc<Self>) {
        loop {
            thread::sleep(Duration::from_secs(1));
            let vm = self.vm();
            let dead = !vm.firecracker_alive() || vm.pager.failed().is_some();
            if dead && !matches!(vm.state(), State::Source(_)) && !self.leaving.load(Ordering::SeqCst) {
                let op = self.op();
                if self.leaving.load(Ordering::SeqCst) {
                    continue;
                }
                eprintln!("vm {}: gone ({}; {}); stopping", vm.name, vm.pager.failed().unwrap_or("its firecracker exited"), vm.post_mortem());
                self.finish(&op, End::Gone, 1, None);
            }
            if let Ok(_op) = self.op.try_lock() {
                if vm.release_pending() && matches!(vm.state(), State::Running | State::Paused) {
                    match vm.release_reports(Duration::from_millis(500)) {
                        Ok(()) => eprintln!("vm {}: released free page reports", vm.name),
                        Err(e) => eprintln!("vm {}: releasing free page reports: {e}", vm.name),
                    }
                }
            }
            let starved = vm.starved.load(Ordering::SeqCst);
            if let Err(e) = self.resize(None) {
                eprintln!("vm {}: resize: {e}", vm.name);
            }
            if starved != vm.starved.load(Ordering::SeqCst) {
                self.publish();
            }
            crate::evict::tick(&self.host, vm.starved.load(Ordering::SeqCst));
        }
    }

    /// Resizes the VM unless an operation holds it, except that a VM whose
    /// copy-on-write checkpoint is being copied may grow: the copy only reads
    /// the pages it had at the pause, and memory plugged after it was
    /// unplugged then (never populated), so the copy never reads it, and the
    /// checkpoint keeps the plugged size it saved.
    fn resize(&self, hint: Option<u64>) -> Result<Resized> {
        let vm = self.vm();
        if let Ok(_op) = self.op.try_lock() {
            return resize(vm, &self.host, hint, false);
        }
        let copying = vm.cow_copy.lock().unwrap();
        match *copying {
            true => resize(vm, &self.host, hint, true),
            false => Ok(Resized::Busy),
        }
    }

    /// Answers the guest agent's memory requests (sent the moment it runs
    /// low) with an immediate resize, until the VM is gone. The guest is
    /// untrusted: requests are bounded in size and time, malformed ones
    /// dropped, and they are acted on at most once per `MEM_REQUEST_GAP`.
    fn serve_memory(self: Arc<Self>) {
        let vm = self.vm().clone();
        let path = vm.mem_sock();
        let _ = std::fs::remove_file(&path);
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => return eprintln!("vm {}: memory requests: {e}", vm.name),
        };
        let mut acted: Option<Instant> = None;
        for conn in listener.incoming() {
            if vm.pid().is_none() {
                break;
            }
            let Ok(conn) = conn else { continue };
            let _ = conn.set_write_timeout(Some(MEM_REQUEST_DEADLINE));
            let Some(avail) = read_mem_request(&conn) else { continue };
            if acted.is_some_and(|t| t.elapsed() < MEM_REQUEST_GAP) {
                let _ = (&conn).write_all(b"busy\n");
                continue;
            }
            acted = Some(Instant::now());
            let reply = match self.resize(Some(avail)) {
                Ok(Resized::Grew) => "grow",
                Ok(Resized::Busy) => "busy",
                Ok(Resized::Full) => "full",
                Ok(Resized::Same) => "ok",
                Err(e) => {
                    eprintln!("vm {}: resize on request: {e}", vm.name);
                    "busy"
                }
            };
            let _ = (&conn).write_all(format!("{reply}\n").as_bytes());
        }
    }

    /// Copies an image app's output to this process's stdout, from where it
    /// got to, until the app exits; reconnects when vsock resets.
    fn follow_app(self: Arc<Self>) {
        let vm = self.vm().clone();
        while vm.state().local() || vm.state() == State::Checkpointing {
            let offset = self.app_log.load(Ordering::SeqCst);
            let got = vm.exec(|s| guest::start_logs(s, offset, true, guest::TIMEOUT));
            if let Ok((mut g, id)) = got {
                let _ = g.get_ref().set_read_timeout(None);
                while let Ok(Some((kind, data))) = guest::read_frame(&mut g) {
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
                    let _ = out.write_all(&data).and_then(|()| out.flush());
                    self.app_log.fetch_add(data.len() as u64, Ordering::SeqCst);
                }
                vm.untrack_exec(id);
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    /// `run NAME -- CMD`: the VM's one command. Its output goes to this
    /// process's; when it exits the VM is destroyed and the process exits
    /// with its status.
    fn main_command(self: Arc<Self>, cmd: &str) {
        let vm = self.vm().clone();
        let id = format!("main-{}", std::process::id());
        let (mut offset, mut started) = (0u64, false);
        let deadline = Instant::now() + Duration::from_secs(30);
        let code = loop {
            if !vm.state().local() && vm.state() != State::Checkpointing {
                // Migrated or suspended: the command goes on with the VM.
                return;
            }
            let action = if started { "attach" } else { "start" };
            let got = vm.exec(|s| guest::session(s, action, &id, offset, cmd, guest::TIMEOUT));
            if let Ok((mut g, sid)) = got {
                let _ = g.get_ref().set_read_timeout(Some(Duration::from_secs(3)));
                let end = crate::exec_frames(&mut g, &id, &mut started, &mut offset, &mut std::io::stdout(), &mut std::io::stderr(), &mut Instant::now());
                vm.untrack_exec(sid);
                match end {
                    Ok(crate::StreamEnd::Exit(code)) => break code,
                    Ok(crate::StreamEnd::Disconnected(_)) => {}
                    Err(e) => {
                        eprintln!("vm {}: {e}", vm.name);
                        break 255;
                    }
                }
            } else if !started && Instant::now() > deadline {
                break 255;
            }
            thread::sleep(Duration::from_millis(100));
        };
        // Refused while migrating away: the process ends with the migration.
        eprintln!("vm {}: {}", vm.name, self.destroy(code));
    }
}

/// Runs a VM process until its VM is gone. `notify`, if given, gets one JSON
/// line once the VM is ready (or failed to start), and is closed.
pub fn main(host: Host, paths: Paths, start: Start, mut notify: Option<std::fs::File>) -> Result<()> {
    // Before any thread starts, so they all inherit the mask.
    let signals = crate::util::block_signals(&SIGNALS);
    let _ = crate::net::sysctl("net.ipv4.ip_forward", "1");
    let p = Proc::new(host, paths)?;
    let (run, prefix) = (p.host.run.clone(), p.host.cfg.prefix.clone());
    thread::spawn(move || crate::host::collect_garbage(&run, &prefix));
    let s = p.clone();
    thread::spawn(move || loop {
        let sig = crate::util::wait_signal(&signals);
        s.signal(sig);
    });
    // Signals that come while it starts wait for it to be up.
    let op = p.op();
    let res = match start {
        Start::Run { name, template, ip, cmd } => {
            *p.cmd.lock().unwrap() = cmd;
            p.run(&name, &template, ip)
        }
        Start::Resume { name } => p.resume_suspended(&name),
        Start::Restore { dir, name, ip, paused } => p.restore(&dir, name.as_deref(), ip.as_deref(), paused),
        // The migration connection, from the peer listener.
        Start::Incoming { req } => p.migrate_in(&req, unsafe { std::net::TcpStream::from_raw_fd(3) }).map(|()| Value::Null),
        Start::Standby { template } => crate::standby::serve(&p, &template, &mut notify, &op),
    };
    if res.is_ok() {
        p.serve_control();
    }
    let reply = match &res {
        Ok(v) => json!({"ok": true, "result": v}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    };
    match notify.take() {
        Some(mut f) => {
            let _ = send_json(&mut f, &reply);
        }
        None if res.is_ok() && !reply["result"].is_null() => eprintln!("{}", reply["result"]),
        None => {}
    }
    if let Err(e) = res {
        eprintln!("flexvm: {e}");
        p.finish(&op, End::NotStarted, 1, None);
    }
    drop(op);
    p.serve()
}

impl Proc {
    /// Whether SIGINT or SIGTERM came before the VM was up.
    pub fn stop_requested(&self) -> bool {
        self.early.lock().unwrap().iter().any(|&s| s == libc::SIGINT || s == libc::SIGTERM)
    }

    pub fn arc(&self) -> Option<Arc<Proc>> {
        self.me.upgrade()
    }

    pub fn set_leaving(&self, v: bool) {
        self.leaving.store(v, Ordering::SeqCst);
    }

    /// Steps the guest's clock in the background, if it is off: under the
    /// VM's operation lock (so never inside a snapshot), at most one at a time.
    pub fn sync_clock_later(&self) {
        let vm = self.vm().clone();
        if vm.clock_pending.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(p) = self.me.upgrade() else { return };
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

/// The cgroup that VMs' Firecrackers get one cgroup each in, if cgroup v2
/// is writable.
fn cgroup_root() -> Option<PathBuf> {
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
    match setup() {
        Ok(()) => Some(root),
        Err(e) => {
            static WARNED: AtomicBool = AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                eprintln!("WARNING: per-VM cgroups unavailable: {e}");
            }
            None
        }
    }
}

pub fn host_available_mib() -> u64 {
    proc_kb("/proc/meminfo", "MemAvailable").unwrap_or(0) >> 20
}

/// Free memory (MiB) the controller keeps plugged for a guest with `total`
/// MiB. The guest agent asks for more as soon as it has less than this, and
/// throttles allocations that outrun the plug (guest/src/mem.rs uses the same mark).
pub fn headroom(total: u64) -> u64 {
    (total / 4).max(1024.min(total / 2))
}

/// What a resize did, answered to the guest when it asked.
#[derive(Debug, PartialEq)]
pub enum Resized {
    Grew,
    Same,
    /// The guest is still processing the previous request, or the VM is busy.
    Busy,
    /// Short on memory, and at its ceiling or refused by the host's reserve.
    Full,
}

/// Grows or shrinks a VM's hotplugged memory to keep `headroom` of it free,
/// never shrinking below what its template was snapshotted with. Plugged
/// memory the guest has not touched costs the host nothing, and pages it
/// frees go back through free page reporting, so this mostly decides how far
/// the guest may grow before asking again.
///
/// The guest is untrusted: its size comes from Firecracker, and what it says
/// it has free (`hint`, MiB, from its own request; else the balloon
/// statistics) only steers growth, which is bounded per step and admitted
/// against the host's reserve (`Host::admit`). A VM that is short and cannot
/// grow here (at its ceiling, or refused) is flagged as starved, so that it
/// is moved somewhere roomier.
fn resize(vm: &Vm, host: &Host, hint: Option<u64>, grow_only: bool) -> Result<Resized> {
    let meta = &vm.template.meta;
    let hotplug_total = meta.max_mib - meta.mem_mib;
    if hotplug_total == 0 {
        return Ok(Resized::Full);
    }
    // Callers hold the VM's operation lock (or its copy-growth lock), so no
    // lifecycle operation runs meanwhile; only a running VM is resized.
    let mut last = vm.last_resize.lock().unwrap();
    if vm.state() != State::Running {
        return Ok(Resized::Busy);
    }
    let (stats, hp) = vm.fc(|fc| {
        let stats = if hint.is_none() { fc.get("/balloon/statistics")? } else { Value::Null };
        Ok((stats, fc.get("/hotplug/memory")?))
    })?;
    let requested = hp["requested_size_mib"].as_u64().ok_or("no hotplug state")?;
    let plugged = hp["plugged_size_mib"].as_u64().ok_or("no hotplug state")?;
    if plugged != requested {
        return Ok(Resized::Busy);
    }
    let total = meta.mem_mib + plugged;
    let avail = match hint {
        Some(avail) => avail,
        None if stats["total_memory"].as_u64().unwrap_or(0) == 0 => return Ok(Resized::Same), // no stats yet
        None => stats["available_memory"].as_u64().unwrap_or(0) >> 20,
    }
    .min(total);
    let floor = meta.plugged_mib.min(hotplug_total);
    let headroom = headroom(total);
    let round = |mib: u64| mib.div_ceil(STEP_MIB) * STEP_MIB;
    // Balloon statistics lag a plug by up to a second; don't grow twice on stale numbers.
    let stale = hint.is_none() && last.elapsed() < Duration::from_millis(1500);
    let short = headroom.saturating_sub(avail);
    let new = if short > 0 && !stale {
        let step = round(headroom * 2 - avail).min(round(total / 4).max(STEP_MIB));
        (requested + step).min(hotplug_total)
    } else if !grow_only && avail > headroom * 3 && requested > floor && last.elapsed() > Duration::from_secs(10) {
        requested.saturating_sub((avail - headroom * 2) / STEP_MIB * STEP_MIB).max(floor)
    } else {
        requested
    };
    let refused = new > requested && !host.admit(new - requested);
    let full = short > 0 && (requested == hotplug_total || refused);
    vm.starved.store(full, Ordering::SeqCst);
    if new == requested || refused {
        return Ok(if full { Resized::Full } else { Resized::Same });
    }
    let why = if hint.is_some() { "guest asked" } else { "tick" };
    eprintln!("vm {}: available {avail}/{total} MiB, hotplug {requested} -> {new} MiB ({why})", vm.name);
    vm.fc(|fc| fc.patch("/hotplug/memory", json!({"requested_size_mib": new})))?;
    *last = Instant::now();
    Ok(if new > requested { Resized::Grew } else { Resized::Same })
}

/// The longest memory request a guest may send, and how long it has to send it.
const MEM_REQUEST_MAX: usize = 128;
const MEM_REQUEST_DEADLINE: Duration = Duration::from_millis(500);
/// Requests closer together than this are answered `busy` without acting.
const MEM_REQUEST_GAP: Duration = Duration::from_millis(50);

/// Reads one `MEM <available KiB> <total KiB>` line of at most
/// `MEM_REQUEST_MAX` bytes within `MEM_REQUEST_DEADLINE`. Returns the
/// available MiB; the guest's total is ignored (Firecracker knows it).
fn read_mem_request(conn: &UnixStream) -> Option<u64> {
    use std::io::Read;
    let deadline = Instant::now() + MEM_REQUEST_DEADLINE;
    let mut buf = [0u8; MEM_REQUEST_MAX];
    let mut len = 0;
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
    let line = std::str::from_utf8(&buf[..len]).ok()?.split('\n').next()?;
    let mut f = line.split(' ');
    match (f.next(), f.next().map(str::parse::<u64>), f.next().map(str::parse::<u64>), f.next()) {
        (Some("MEM"), Some(Ok(avail_kib)), Some(Ok(_)), None) => Some(avail_kib >> 10),
        _ => None,
    }
}

/// Sends one request to a peer's listener and returns its result.
pub fn peer_call(peer: &str, req: Value) -> Result<Value> {
    let mut c = crate::util::connect(peer, Duration::from_millis(500))?;
    c.set_read_timeout(Some(Duration::from_secs(2)))?;
    c.set_write_timeout(Some(Duration::from_secs(2)))?;
    send_json(&mut c, &req)?;
    let reply = crate::util::recv_json(&mut BufReader::new(c))?.ok_or("peer hung up")?;
    if reply["ok"] != json!(true) {
        bail!("{}", reply["error"].as_str().unwrap_or("refused"));
    }
    Ok(reply["result"].clone())
}

/// Joins a reader and writer into one Read + Write.
pub struct ReadWrite<R, W>(pub R, pub W);

impl<R: std::io::Read, W> std::io::Read for ReadWrite<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl<R, W: Write> Write for ReadWrite<R, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.1.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.1.flush()
    }
}

/// Connects to VM `name`'s control socket and sends `req`, with `fds`.
pub fn connect(host: &Host, name: &str, req: &Value, fds: &[i32]) -> Result<UnixStream> {
    let c = UnixStream::connect(host.sock(name)).map_err(|_| format!("no vm named {name:?}"))?;
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    crate::util::send_with_fds(&c, &line, fds)?;
    Ok(c)
}

/// Sends `req` to VM `name` and returns its result.
pub fn call(host: &Host, name: &str, req: Value) -> Result<Value> {
    let c = connect(host, name, &req, &[])?;
    let reply = crate::util::recv_json(&mut BufReader::new(c))?.ok_or_else(|| format!("vm {name} hung up"))?;
    if reply["ok"] != json!(true) {
        bail!("{}", reply["error"].as_str().unwrap_or("request failed"));
    }
    Ok(reply["result"].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_requests_are_bounded_and_strict() {
        let req = |bytes: &[u8], close: bool| {
            let (a, mut b) = UnixStream::pair().unwrap();
            b.write_all(bytes).unwrap();
            if close {
                drop(b);
                return read_mem_request(&a);
            }
            read_mem_request(&a)
        };
        assert_eq!(req(b"MEM 2097152 4194304\n", false), Some(2048));
        assert_eq!(req(b"MEM 1 2 3\n", false), None);
        assert_eq!(req(b"MEM x 2\n", false), None);
        assert_eq!(req(b"GROW 1 2\n", false), None);
        // No newline: gives up when the peer closes, at the size cap, or at the deadline.
        assert_eq!(req(b"MEM 1 2", true), None);
        assert_eq!(req(&[b'7'; 4096], false), None);
        let t = Instant::now();
        assert_eq!(req(b"MEM 1", false), None);
        assert!(t.elapsed() < MEM_REQUEST_DEADLINE * 2);
    }
}
