//! The VM process: `flexvm run` (and `resume`, `restore`, an incoming
//! migration, a standby VM) is a process that is one VM. It owns the
//! Firecracker it spawns, the pager, the tap and route, packet holds, guest
//! sessions and checkpoints, and exits when the VM is gone.
//!
//! Signals: SIGTERM suspends, SIGTSTP pauses, SIGCONT resumes, SIGINT
//! destroys. A control socket (`RUN/vms/NAME.sock`) takes `exec`,
//! `checkpoint`, `migrate`, `debug`, page connections passed on by the peer
//! listener (`pages`), and a standby VM's `claim`. Every operation on the VM
//! holds `op`, so they never interleave.

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
use crate::fc::Pool;
use crate::guest;
use crate::hold::Holder;
use crate::host::{fault, Entry, Host, NameLock};
use crate::template::{Paths, Template, STEP_MIB};
use crate::util::{ms, proc_kb, send_json, Phases, Result};
use crate::vm::{State, Vm};

/// How long an operation waits for another one on the same VM.
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

pub struct Proc {
    pub host: Host,
    pub paths: Paths,
    pub pool: Arc<Pool>,
    name: Mutex<Option<NameLock>>,
    vm: OnceLock<Arc<Vm>>,
    /// The generation of the VM's address (see `host::Addr`).
    pub gen: AtomicU64,
    op: Mutex<()>,
    holder: OnceLock<Option<Arc<Holder>>>,
    /// The migration this VM arrived by, until all its pages are in.
    pub arrived: Mutex<Option<u64>>,
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
    me: std::sync::Weak<Proc>,
}

/// Control connections served at once; more are refused.
const MAX_CONTROL: usize = 256;
static CONTROL: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Proc {
    fn new(host: Host, paths: Paths) -> Result<Arc<Proc>> {
        let work = host.run.join("w").join(std::process::id().to_string());
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work)?;
        let sockets = crate::socket::SocketRoot::new(&work)?;
        let tap_prefix = format!("{}{:x}t", host.cfg.prefix, std::process::id());
        let pool = Pool::new(&paths.firecracker, &work, sockets, cgroup_root(), &tap_prefix, 0);
        Ok(Arc::new_cyclic(|me| Proc {
            host,
            paths,
            pool,
            name: Mutex::new(None),
            vm: OnceLock::new(),
            gen: AtomicU64::new(0),
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

    /// Takes the VM's operation lock, waiting up to `OP_WAIT`.
    pub fn op(&self) -> Result<MutexGuard<'_, ()>> {
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
                let dev = format!("{}{:x}h", self.host.cfg.prefix, std::process::id());
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
            pid: std::process::id(),
            ip: Some(vm.ip),
            gen: self.gen.load(Ordering::SeqCst),
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

    /// Ends the process: the VM is gone (killed, suspended, migrated away,
    /// failed). Its Firecracker must be dead already.
    pub fn end(&self, code: i32) -> ! {
        if let Some(mig) = self.arrived.lock().unwrap().take() {
            let _ = self.host.mig_set(mig, "released");
        }
        drop(self.name.lock().unwrap().take());
        if let Some(c) = self.claimer.lock().unwrap().take() {
            let mut w = &c;
            let _ = send_json(&mut w, &json!({"exit": code}));
        }
        self.pool.close();
        let work = self.host.run.join("w").join(std::process::id().to_string());
        crate::socket::remove(&work);
        let _ = std::fs::remove_dir_all(&work);
        let _ = std::io::stdout().flush();
        std::process::exit(code)
    }

    /// Kills the VM, gives back its address and tells the peers it is gone.
    /// A VM paused here as a migration source is never killed: its target
    /// may still be pulling its memory.
    pub fn destroy(&self) -> Result<()> {
        let vm = self.vm();
        if matches!(vm.state(), State::Source(_)) {
            bail!("vm {} is the source of a migration in progress; it ends once the target has its memory", vm.name);
        }
        vm.cancel_checkpoint.fetch_add(1, Ordering::SeqCst);
        vm.pager.abort_copy();
        let _op = self.op();
        if matches!(vm.state(), State::Source(_)) {
            bail!("vm {} is the source of a migration in progress", vm.name);
        }
        self.drop_held_in();
        self.set_leaving(true);
        vm.kill();
        self.withdraw();
        Ok(())
    }

    /// The VM's address is free again here, and peers are told so (all of
    /// it done before this returns, as the process is about to exit).
    pub fn withdraw(&self) {
        let vm = self.vm();
        let (ip, gen, name) = (vm.ip, self.gen.load(Ordering::SeqCst), vm.name.clone());
        if let Ok(l) = self.host.lock() {
            let _ = self.host.release(&l, ip, &name);
            let _ = self.host.observe(&l, ip, gen, true);
        }
        crate::net::unroute(ip);
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
        let (ip, gen) = (vm.ip, self.gen.load(Ordering::SeqCst));
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

    /// A VM from a template: from a standby VM if `claim` gets one, else
    /// loaded here.
    fn run(&self, name: &str, template: &str, want: Option<Ipv4Addr>) -> Result<Value> {
        let mut t = Phases::new();
        self.set_name(self.host.take_name(name, false)?);
        let tpl = Template::open(&self.paths, template)?;
        t.mark("template");
        let (ip, gen) = {
            let l = self.host.lock()?;
            self.host.claim_new(&l, name, want)?
        };
        self.gen.store(gen, Ordering::SeqCst);
        t.mark("claim_ip");
        let load = if fault("resume_kill") { crate::vm::Load::RunningKilled } else { crate::vm::Load::Running };
        let vmstate = tpl.vmstate();
        let restored = Vm::restore(&self.pool, name, tpl, crate::vm::Snapshot::Path(&vmstate), None, ip, load, &mut t);
        let vm = match restored {
            Ok((vm, _)) => vm,
            Err(e) => {
                self.release_ip(ip, name);
                return Err(e);
            }
        };
        self.set_vm(vm);
        let mut v = self.start_guest(&mut t)?;
        v["hot"] = json!(false);
        Ok(v)
    }

    fn release_ip(&self, ip: Ipv4Addr, name: &str) {
        if let Ok(l) = self.host.lock() {
            let _ = self.host.release(&l, ip, name);
        }
    }

    /// The guest of a VM that runs now: address, clock, app. On failure the
    /// VM is killed and its address given back.
    pub fn start_guest(&self, t: &mut Phases) -> Result<Value> {
        let vm = self.vm().clone();
        self.publish();
        t.mark("register");
        let running = t.total();
        let started = vm.guest_net(vm.ip, self.host.cfg.dns.as_deref()).and_then(|()| {
            if t.mark("guest_net") >= crate::vm::CLOCK_RTT {
                // START's clock is behind by its transit time; fixed off this path.
                self.sync_clock_later();
            }
            if vm.template.meta.image.as_ref().is_some_and(|i| !i.warm) {
                vm.start_app().map_err(|e| format!("{e} (see the vm's output)"))?;
                t.mark("app_start");
            }
            Ok(())
        });
        if let Err(e) = started {
            vm.kill();
            self.release_ip(vm.ip, &vm.name);
            return Err(e);
        }
        self.announce();
        t.mark("announce");
        Ok(json!({
            "name": vm.name,
            "ip": vm.ip.to_string(),
            "pid": std::process::id(),
            "running_ms": ms(running),
            "ready_ms": ms(t.total()),
            "timings_ms": t.json(),
        }))
    }

    // Steady state.

    /// Serves the control socket, runs the controller and takes signals.
    /// Never returns: the process ends with the VM.
    fn serve(self: &Arc<Self>) -> ! {
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
        let p = self.clone();
        thread::spawn(move || p.controller());
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
            // Not up yet: a standby VM just goes; anything else waits.
            if matches!(sig, libc::SIGINT | libc::SIGTERM) && self.standby.lock().unwrap().take().is_some() {
                self.end(0);
            }
            if sig != libc::SIGHUP {
                self.early.lock().unwrap().push(sig);
            }
            return;
        };
        let res = match sig {
            libc::SIGTSTP => self.op().and_then(|_op| vm.pause()).map(|()| self.publish()),
            libc::SIGCONT => self.resume().map(drop),
            libc::SIGTERM => match self.suspend() {
                Ok(v) => {
                    eprintln!("{v}");
                    self.end(0)
                }
                Err(e) => Err(e),
            },
            libc::SIGINT => match self.destroy() {
                Ok(()) => self.end(0),
                Err(e) => Err(e),
            },
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
        let mut w = &c;
        let reply = match req["op"].as_str().unwrap_or("") {
            "exec" => return self.exec(&req, c),
            "pages" => return self.pages(&req, fds),
            "checkpoint" => {
                let dir = req["dir"].as_str().unwrap_or("");
                let stop = req["stop"].as_bool().unwrap_or(false);
                let res = self.checkpoint(dir, stop, req["incremental"].as_bool().unwrap_or(false));
                if stop && res.is_ok() {
                    let _ = send_json(&mut w, &json!({"ok": true, "result": res.unwrap()}));
                    self.end(0);
                }
                res
            }
            "migrate" => self.migrate(req["to"].as_str().unwrap_or("")),
            "debug" => self.debug(&req),
            "claim" => Err("this vm is not a standby vm".into()),
            op => Err(format!("unknown op {op:?}").into()),
        };
        let reply = match reply {
            Ok(v) => json!({"ok": true, "result": v}),
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        };
        let _ = send_json(&mut w, &reply);
    }

    /// A page connection the peer listener passed on: served if this VM is
    /// the source of that migration.
    fn pages(&self, req: &Value, fds: Vec<OwnedFd>) {
        let Some(fd) = fds.into_iter().next() else { return };
        let mut s = std::net::TcpStream::from(fd);
        let vm = self.vm();
        if req["mig"].as_u64().map(State::Source) != Some(vm.state()) || fault("pages") {
            // The page client reads a status byte: refuse rather than hang up silently.
            let _ = s.write_all(&[1]);
            return;
        }
        let _ = s.set_nodelay(true);
        let r = s.try_clone().map(BufReader::new);
        if let Ok(r) = r {
            let _ = crate::uffd::serve_pages(&vm.pager, ReadWrite(r, s), || fault("pages"));
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
        if std::env::var("FLEXVM_FAULTS").ok().as_deref() != Some("1") {
            bail!("debug requests need FLEXVM_FAULTS=1");
        }
        let vm = self.vm();
        match req["what"].as_str().unwrap_or("") {
            "memhash" => self.memhash(),
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
                let _op = self.op();
                if self.leaving.load(Ordering::SeqCst) {
                    continue;
                }
                eprintln!("vm {}: gone ({}); stopping", vm.name, vm.pager.failed().unwrap_or("its firecracker exited"));
                self.drop_held_in();
                vm.kill();
                self.withdraw();
                self.end(1);
            }
            if let Ok(_op) = self.op.try_lock() {
                if vm.release_pending() && matches!(vm.state(), State::Running | State::Paused) {
                    match vm.release_reports(Duration::from_millis(500)) {
                        Ok(()) => eprintln!("vm {}: released free page reports", vm.name),
                        Err(e) => eprintln!("vm {}: releasing free page reports: {e}", vm.name),
                    }
                }
                if vm.state() == State::Running {
                    let starved = vm.starved.load(Ordering::SeqCst);
                    if let Err(e) = resize(vm, host_available_mib(), self.host.cfg.reserve_mib) {
                        eprintln!("vm {}: resize: {e}", vm.name);
                    }
                    if starved != vm.starved.load(Ordering::SeqCst) {
                        self.publish();
                    }
                }
            }
            crate::evict::tick(&self.host, vm.starved.load(Ordering::SeqCst));
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
        if let Err(e) = self.destroy() {
            eprintln!("vm {}: {e}", vm.name);
        }
        self.end(code);
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
    let res = match start {
        Start::Run { name, template, ip, cmd } => {
            *p.cmd.lock().unwrap() = cmd;
            p.run(&name, &template, ip)
        }
        Start::Resume { name } => p.resume_suspended(&name),
        Start::Restore { dir, name, ip, paused } => p.restore(&dir, name.as_deref(), ip.as_deref(), paused),
        Start::Incoming { req } => {
            // The migration connection, from the peer listener.
            let conn = unsafe { std::net::TcpStream::from_raw_fd(3) };
            match p.migrate_in(&req, conn) {
                Ok(()) => Ok(Value::Null),
                Err(e) => {
                    eprintln!("incoming vm {}: {e}", req["name"].as_str().unwrap_or(""));
                    p.end(1)
                }
            }
        }
        Start::Standby { template } => crate::standby::serve(&p, &template, &mut notify),
    };
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
        p.end(1);
    }
    p.serve()
}

impl Proc {
    /// Becomes the process of `vm`, already running (a claimed standby VM).
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
            let res = p.op().and_then(|_op| {
                vm.clock_pending.store(false, Ordering::SeqCst);
                if vm.state() != State::Running {
                    return Ok(None);
                }
                vm.sync_clock(CLOCK_TOLERANCE, Instant::now() + CLOCK_DEADLINE).map(Some)
            });
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

/// Grows or shrinks a VM's hotplugged memory to keep its free memory within a
/// band. Freed pages inside plugged memory go back to the host through free
/// page reporting, so this mostly decides how far the guest may grow. A VM
/// that needs to grow past what this host can back is flagged as starved so
/// that it is moved somewhere roomier.
fn resize(vm: &Vm, host_avail: u64, reserve: u64) -> Result<()> {
    let meta = &vm.template.meta;
    let hotplug_total = meta.max_mib - meta.mem_mib;
    if hotplug_total == 0 {
        return Ok(());
    }
    let (stats, hp) = vm.fc(|fc| Ok((fc.get("/balloon/statistics")?, fc.get("/hotplug/memory")?)))?;
    let avail = stats["available_memory"].as_u64().unwrap_or(0) >> 20;
    let total = stats["total_memory"].as_u64().unwrap_or(0) >> 20;
    let requested = hp["requested_size_mib"].as_u64().unwrap_or(0);
    let plugged = hp["plugged_size_mib"].as_u64().unwrap_or(0);
    if total == 0 || plugged != requested {
        return Ok(()); // no stats yet, or the guest is still processing the last request
    }
    let headroom = (total / 4).max(256);
    let round = |mib: u64| mib.div_ceil(STEP_MIB) * STEP_MIB;
    let mut last = vm.last_resize.lock().unwrap();
    let new = if avail < headroom {
        (requested + round(headroom * 2 - avail)).min(hotplug_total)
    } else if avail > headroom * 3 && requested > 0 && last.elapsed() > Duration::from_secs(10) {
        requested.saturating_sub((avail - headroom * 2) / STEP_MIB * STEP_MIB)
    } else {
        requested
    };
    let grow = new.saturating_sub(requested);
    // Starved: short on memory and either at its ceiling or growing into the host's reserve.
    let starved = avail < headroom && (new == requested || host_avail.saturating_sub(grow) < reserve);
    vm.starved.store(starved, Ordering::SeqCst);
    if new != requested {
        eprintln!("vm {}: available {avail}/{total} MiB, hotplug {requested} -> {new} MiB", vm.name);
        vm.fc(|fc| fc.patch("/hotplug/memory", json!({"requested_size_mib": new})))?;
        *last = Instant::now();
    }
    Ok(())
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
