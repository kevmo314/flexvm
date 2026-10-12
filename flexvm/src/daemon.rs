//! The per-host daemon: owns VMs, serves their memory to migration targets,
//! and runs the elastic memory controller.
//!
//! Every connection starts with one JSON request line. Most ops answer with
//! one JSON line; `exec` then streams guest frames, `pages` switches to the
//! binary page protocol and `incoming` is followed by the raw vmstate bytes.

use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::Pool;
use crate::guest;
use crate::net::{self, IpRange};
use crate::template::{Paths, Template, STEP_MIB};
use crate::uffd::{serve_pages, Runs, Source};
use crate::util::{ms, proc_kb, recv_json, send_json, Error, Phases, Result};
use crate::vm::{State, Vm};

pub struct Config {
    pub paths: Paths,
    pub listen: String,
    /// Address peers use to reach this daemon (defaults to `listen`).
    pub advertise: String,
    pub run_dir: PathBuf,
    pub peers: Vec<String>,
    /// Migrate a VM away when host MemAvailable drops below this.
    pub reserve_mib: u64,
    /// Idle Firecracker processes to keep ready.
    pub pool: usize,
    /// Addresses this daemon hands to new VMs.
    pub vm_ips: IpRange,
    /// This host's address on the network shared with peers; they route VM addresses to it.
    pub underlay: Ipv4Addr,
    /// Answer ARP for local VMs on this interface and announce them when they arrive.
    pub announce_dev: Option<String>,
    pub dns: Option<String>,
}

pub struct Daemon {
    cfg: Config,
    vms: Mutex<HashMap<String, Arc<Vm>>>,
    templates: Mutex<HashMap<String, Arc<Template>>>,
    pool: Arc<Pool>,
    /// Addresses held by VMs on this host, including ones still starting.
    ips: Mutex<HashSet<Ipv4Addr>>,
    last_migration: Mutex<Option<Instant>>,
    /// Migrations this host was asked to take in. An id it has answered for
    /// as aborted can never start here afterwards.
    migrations: Mutex<HashMap<u64, Incoming>>,
    /// Held for the daemon's lifetime (see `lock_run_dir`).
    _run_lock: Vec<std::fs::File>,
    /// Armed test faults and when they expire; None unless FLEXVM_FAULTS=1.
    faults: Option<Mutex<HashMap<String, Instant>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Incoming {
    /// Restoring; it may resume any moment.
    Pending,
    /// Resumed here: this host owns the VM.
    Committed,
    /// Never resumed here, or killed before the source was answered.
    Aborted,
}

/// How a migration ended on its target, as seen by the source.
enum Outcome {
    Committed(Value),
    Aborted,
}

pub fn run(mut cfg: Config) -> Result<()> {
    std::fs::create_dir_all(&cfg.run_dir)?;
    // Every Firecracker gets paths under the canonical directory, which is
    // what `kill_orphans` compares against.
    cfg.run_dir = cfg.run_dir.canonicalize()?;
    let run_lock = lock_run_dir(&cfg.run_dir)?;
    let listener = TcpListener::bind(&cfg.listen)?;
    kill_orphans(&cfg.run_dir)?;
    let cgroup_root = setup_cgroups(&cfg.listen);
    net::sysctl("net.ipv4.ip_forward", "1")?;
    if let Some(dev) = &cfg.announce_dev {
        net::sysctl(&format!("net.ipv4.conf.{dev}.proxy_arp"), "1")?;
    }
    let port = cfg.listen.rsplit(':').next().unwrap_or("0");
    let tap_prefix = format!("fv{port}x");
    net::delete_taps_with_prefix(&tap_prefix);
    let pool = Pool::new(&cfg.paths.firecracker, &cfg.run_dir, cgroup_root.clone(), &tap_prefix, cfg.pool);
    let d = Arc::new(Daemon {
        cfg,
        vms: Mutex::new(HashMap::new()),
        templates: Mutex::new(HashMap::new()),
        pool,
        ips: Mutex::new(HashSet::new()),
        last_migration: Mutex::new(None),
        migrations: Mutex::new(HashMap::new()),
        _run_lock: run_lock,
        faults: std::env::var("FLEXVM_FAULTS").is_ok_and(|v| v == "1").then(|| Mutex::new(HashMap::new())),
    });
    eprintln!("flexvm daemon listening on {} (advertised as {})", d.cfg.listen, d.cfg.advertise);
    {
        let d = d.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(1000));
            d.control_tick();
        });
    }
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let d = d.clone();
        thread::spawn(move || {
            let _ = conn.set_nodelay(true);
            if let Err(e) = d.handle(conn) {
                eprintln!("request failed: {e}");
            }
        });
    }
    Ok(())
}

/// Claims `run_dir` for this daemon's lifetime: an exclusive lock on it and
/// shared locks on its ancestors, so no other daemon can use the same
/// directory, one inside it or one around it (whose orphan cleanup would
/// otherwise kill this daemon's Firecrackers, or the other way round).
fn lock_run_dir(run_dir: &Path) -> Result<Vec<std::fs::File>> {
    let dir = run_dir.canonicalize()?;
    let mut locks = Vec::new();
    for (i, d) in dir.ancestors().enumerate() {
        let f = std::fs::File::open(d)?;
        let how = if i == 0 { libc::LOCK_EX } else { libc::LOCK_SH };
        if unsafe { libc::flock(f.as_raw_fd(), how | libc::LOCK_NB) } < 0 {
            let e = std::io::Error::last_os_error();
            bail!("run directory {} overlaps another daemon's ({} is locked: {e})", dir.display(), d.display());
        }
        locks.push(f);
    }
    Ok(locks)
}

/// Kills the Firecrackers a previous daemon left running in `run_dir` and
/// confirms they are dead. It must succeed before this daemon answers
/// anything: otherwise a migration target that restarted would answer an
/// unknown migration as aborted, its source would resume, and the orphan
/// would be a second copy.
fn kill_orphans(run_dir: &Path) -> Result<()> {
    let run_dir = run_dir.canonicalize()?;
    let gone = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH);
    // Ok(false) for a process that is not one of ours or no longer exists.
    let ours = |pid: &str| -> Result<bool> {
        let read = |what| match std::fs::read(format!("/proc/{pid}/{what}")) {
            Ok(b) => Ok(Some(b)),
            Err(e) if gone(&e) => Ok(None),
            Err(e) => Err(format!("/proc/{pid}/{what}: {e}")),
        };
        let Some(comm) = read("comm")? else { return Ok(false) };
        let Some(cmdline) = read("cmdline")? else { return Ok(false) };
        if comm.trim_ascii() != b"firecracker" {
            return Ok(false);
        }
        // Its API socket as the process sees it: relative to its cwd and
        // through whatever symlinks an earlier daemon's --run went through.
        let args: Vec<&[u8]> = cmdline.split(|&b| b == 0).collect();
        let Some(sock) = args.iter().position(|a| *a == b"--api-sock").and_then(|i| args.get(i + 1)) else {
            return Ok(false);
        };
        let mut sock = PathBuf::from(std::ffi::OsStr::from_bytes(sock));
        if sock.is_relative() {
            match std::fs::read_link(format!("/proc/{pid}/cwd")) {
                Ok(cwd) => sock = cwd.join(sock),
                Err(e) if gone(&e) => return Ok(false),
                Err(e) => return Err(format!("/proc/{pid}/cwd: {e}").into()),
            }
        }
        let dir = sock.parent().unwrap_or(&sock);
        Ok(dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf()).starts_with(&run_dir))
    };
    let mut orphans = Vec::new();
    for e in std::fs::read_dir("/proc")? {
        let pid = e?.file_name().into_string().unwrap_or_default();
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) || !ours(&pid)? {
            continue;
        }
        let fd = match crate::util::pidfd_open(pid.parse()?) {
            Ok(fd) => fd,
            Err(e) if gone(&e) => continue,
            Err(e) => bail!("pidfd_open({pid}): {e}"),
        };
        // The pid may have been reused between the check and pidfd_open.
        if !ours(&pid)? {
            continue;
        }
        eprintln!("killing firecracker {pid} left over in {}", run_dir.display());
        crate::util::pidfd_kill(&fd).map_err(|e| format!("kill {pid}: {e}"))?;
        orphans.push((pid, fd));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    for (pid, fd) in orphans {
        if !crate::util::pidfd_wait(&fd, deadline.saturating_duration_since(Instant::now()))? {
            bail!("firecracker {pid} left over in {} would not die", run_dir.display());
        }
    }
    Ok(())
}

/// Creates a cgroup subtree for this daemon's VMs, if cgroup v2 is writable.
fn setup_cgroups(listen: &str) -> Option<PathBuf> {
    let root = PathBuf::from("/sys/fs/cgroup/flexvm");
    std::fs::create_dir_all(&root).ok()?;
    std::fs::write(root.join("cgroup.subtree_control"), "+cpu +memory").ok()?;
    let mine = root.join(listen.replace([':', '.', '[', ']'], "_"));
    std::fs::create_dir_all(&mine).ok()?;
    // Drop leftovers from a previous run; rmdir only succeeds on empty cgroups.
    for e in std::fs::read_dir(&mine).ok()?.flatten() {
        if e.path().is_dir() {
            let _ = std::fs::remove_dir(e.path());
        }
    }
    std::fs::write(mine.join("cgroup.subtree_control"), "+cpu +memory").ok()?;
    Some(mine)
}

impl Daemon {
    fn template(&self, name: &str) -> Result<Arc<Template>> {
        let mut t = self.templates.lock().unwrap();
        if let Some(t) = t.get(name) {
            return Ok(t.clone());
        }
        let tpl = Template::open(&self.cfg.paths, name)?;
        t.insert(name.into(), tpl.clone());
        Ok(tpl)
    }

    /// The local template matching a migration source's. Preflight runs before
    /// the source pauses and may rehash changed files; incoming only stats them.
    fn migration_template(&self, req: &Value, preflight: bool) -> Result<Arc<Template>> {
        let name = req["template"].as_str().ok_or("missing template")?;
        let tpl = self.template(name)?;
        tpl.check_id(req["id"].as_str().ok_or("missing template id")?)?;
        tpl.verify(&self.cfg.paths, preflight)?;
        Ok(tpl)
    }

    fn vm(&self, name: &str) -> Result<Arc<Vm>> {
        match self.vms.lock().unwrap().get(name) {
            Some(vm) => Ok(vm.clone()),
            None => bail!("no vm named {name:?}"),
        }
    }

    fn handle(self: &Arc<Self>, conn: TcpStream) -> Result<()> {
        let mut r = BufReader::new(conn.try_clone()?);
        let mut w = conn;
        let Some(req) = recv_json(&mut r)? else { return Ok(()) };
        let op = req["op"].as_str().unwrap_or("").to_string();
        let name = req["name"].as_str().unwrap_or("").to_string();
        let reply = match op.as_str() {
            // Streaming ops write their own replies.
            "pages" => {
                let vm = self.vm(&name)?;
                // Only the copy this migration paused, never a later VM by that name.
                if req["mig"].as_u64().map(State::Source) != Some(vm.state()) {
                    bail!("vm {name} is not the source of migration {}", req["mig"]);
                }
                if self.fault("pages") {
                    bail!("injected fault: page server down");
                }
                let mut stream = ReadWrite(r, w);
                return Ok(serve_pages(&vm.pager, &mut stream, || self.fault("pages"))?);
            }
            "exec" => return self.exec(&name, &req, w),
            "logs" => return self.logs(&name, &req, w),
            "preflight" => self.migration_template(&req, true).map(|tpl| json!({"id": tpl.meta.id})),
            "incoming" => match self.incoming(&req, &mut r) {
                // Committed, but the source never hears about it.
                Ok(_) if self.fault("lost_ack") => return Ok(()),
                res => res,
            },
            "run" => self.run_vm(&name, req["template"].as_str().unwrap_or("default"), req["ip"].as_str()),
            "ls" => Ok(json!(self.vms.lock().unwrap().values().map(|v| v.describe()).collect::<Vec<_>>())),
            "kill" => self.kill(&name),
            "release" => self.release(&name, &req),
            "migration" => self.migration_outcome(&req),
            "fault" => self.inject(&req),
            "route" => self.route(&req),
            "migrate" => self.migrate(&name, req["to"].as_str().unwrap_or("")),
            "info" => Ok(self.info()),
            "bench_info" => self.bench_info(req["template"].as_str().unwrap_or("default")),
            "migration_status" => self.vm(&name).map(|vm| {
                json!({
                    "background_pull_ms": vm.pager.pull_time().map(ms),
                    "released": vm.released.get(),
                    "state": vm.state().name(),
                    "failed": vm.pager.failed(),
                })
            }),
            _ => Err(format!("unknown op {op:?}").into()),
        };
        let reply = match reply {
            Ok(v) => json!({"ok": true, "result": v}),
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        };
        send_json(&mut w, &reply)?;
        Ok(())
    }

    fn run_vm(&self, name: &str, template: &str, ip: Option<&str>) -> Result<Value> {
        let mut t = Phases::new();
        if name.is_empty() || self.vms.lock().unwrap().contains_key(name) {
            bail!("vm name {name:?} is empty or taken");
        }
        let tpl = self.template(template)?;
        let ip = self.claim_ip(ip)?;
        t.mark("claim_ip");
        let restored = self.pool.take().and_then(|idle| {
            t.mark("pool_take");
            Vm::restore(idle, name, tpl.clone(), &tpl.vmstate(), None, ip, &mut t)
        });
        let (vm, restore) = restored.inspect_err(|_| {
            self.ips.lock().unwrap().remove(&ip);
        })?;
        self.vms.lock().unwrap().insert(name.into(), vm.clone());
        t.mark("register");
        let running = t.total();
        // The guest reseeds its RNG itself: Firecracker bumps the VMGenID on restore.
        vm.guest_net(ip, self.cfg.dns.as_deref())?;
        t.mark("guest_net");
        // Image templates start their app now, unless the snapshot holds it running.
        if tpl.meta.image.as_ref().is_some_and(|i| !i.warm) {
            vm.start_app().map_err(|e| format!("{e} (see `flexvm logs {name}`)"))?;
            t.mark("app_start");
        }
        self.announce(ip);
        t.mark("announce");
        Ok(json!({
            "name": name,
            "ip": ip.to_string(),
            "restore_ms": ms(restore),
            "running_ms": ms(running),
            "ready_ms": ms(t.total()),
            "timings_ms": t.json(),
        }))
    }

    /// Reserves `want`, or the first free address in this host's range that no
    /// peer is using either.
    fn claim_ip(&self, want: Option<&str>) -> Result<Ipv4Addr> {
        let ip = match want {
            Some(ip) => ip.parse().map_err(|_| format!("bad address {ip:?}"))?,
            None => {
                let mut used: HashSet<Ipv4Addr> = self.ips.lock().unwrap().clone();
                for peer in &self.cfg.peers {
                    if let Ok(info) = peer_info(peer) {
                        used.extend(info["ips"].as_array().into_iter().flatten().filter_map(|v| v.as_str()?.parse::<Ipv4Addr>().ok()));
                    }
                }
                self.cfg.vm_ips.allocate(|ip| used.contains(&ip)).ok_or("no free addresses left")?
            }
        };
        if !self.ips.lock().unwrap().insert(ip) {
            bail!("{ip} is already in use here");
        }
        Ok(ip)
    }

    /// Points the network at this host for `ip`: a gratuitous ARP for the LAN
    /// and a route for each peer. Runs in the background.
    fn announce(&self, ip: Ipv4Addr) {
        let peers = self.cfg.peers.clone();
        let dev = self.cfg.announce_dev.clone();
        let via = self.cfg.underlay;
        thread::spawn(move || {
            if let Some(dev) = &dev {
                if let Err(e) = net::gratuitous_arp(dev, ip) {
                    eprintln!("announce {ip}: {e}");
                }
            }
            for peer in &peers {
                if let Err(e) = peer_call(peer, json!({"op": "route", "ip": ip.to_string(), "via": via.to_string()})) {
                    eprintln!("announce {ip} to {peer}: {e}");
                }
            }
            // A second ARP for anyone who missed the first.
            if let Some(dev) = &dev {
                thread::sleep(Duration::from_millis(200));
                let _ = net::gratuitous_arp(dev, ip);
            }
        });
    }

    /// A peer tells us where a VM address lives (`via`), or that it is gone.
    fn route(&self, req: &Value) -> Result<Value> {
        let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
        let local = self.vms.lock().unwrap().values().any(|v| v.ip == ip && v.state() == State::Running);
        if !local {
            match req["via"].as_str() {
                Some(via) => net::route_via(ip, via.parse()?)?,
                None => net::unroute(ip),
            }
        }
        Ok(json!({"ip": ip.to_string(), "local": local}))
    }

    /// Stops a VM and withdraws its address from the network.
    fn kill(&self, name: &str) -> Result<Value> {
        let vm = self.vms.lock().unwrap().remove(name);
        let Some(vm) = vm else { bail!("no vm named {name:?}") };
        vm.kill();
        self.ips.lock().unwrap().remove(&vm.ip);
        let peers = self.cfg.peers.clone();
        let ip = vm.ip;
        thread::spawn(move || {
            for peer in &peers {
                let _ = peer_call(peer, json!({"op": "route", "ip": ip.to_string()}));
            }
        });
        Ok(json!({"name": name}))
    }

    /// The target of migration `mig` is done with our paused copy of `name`;
    /// its address stays pointed at the target. Idempotent, and never touches
    /// any other VM by that name, such as the same VM migrated back here.
    fn release(&self, name: &str, req: &Value) -> Result<Value> {
        let mig = req["mig"].as_u64().ok_or("missing mig")?;
        let vm = {
            let mut vms = self.vms.lock().unwrap();
            match vms.get(name).map(|v| v.state()) {
                None => return Ok(json!({"name": name, "already": true})),
                Some(State::Source(m)) if m == mig => vms.remove(name).unwrap(),
                Some(_) => bail!("vm {name} here is not the source of migration {mig}"),
            }
        };
        vm.kill();
        self.ips.lock().unwrap().remove(&vm.ip);
        Ok(json!({"name": name}))
    }

    /// How migration `mig` went here, for a source that lost track of it.
    /// An unknown id is fenced off as aborted, so it can never start later.
    fn migration_outcome(&self, req: &Value) -> Result<Value> {
        if self.fault("status") {
            bail!("injected fault: migration status unavailable");
        }
        let mig = req["mig"].as_u64().ok_or("missing mig")?;
        let outcome = *self.migrations.lock().unwrap().entry(mig).or_insert(Incoming::Aborted);
        let outcome = match outcome {
            Incoming::Pending => "pending",
            Incoming::Committed => "committed",
            Incoming::Aborted => "aborted",
        };
        Ok(json!({"outcome": outcome, "underlay": self.cfg.underlay.to_string()}))
    }

    /// Arms test fault `fault` for `ms` milliseconds: `pages` (the page
    /// server drops connections), `route` (rerouting after a migration
    /// fails), `lost_ack` (incoming migrations get no reply) or `status`
    /// (migration status queries fail).
    fn inject(&self, req: &Value) -> Result<Value> {
        let Some(faults) = &self.faults else { bail!("fault injection is off (start the daemon with FLEXVM_FAULTS=1)") };
        let fault = req["fault"].as_str().ok_or("missing fault")?;
        let until = Instant::now() + Duration::from_millis(req["ms"].as_u64().unwrap_or(1000));
        faults.lock().unwrap().insert(fault.into(), until);
        Ok(json!({"fault": fault}))
    }

    fn fault(&self, name: &str) -> bool {
        self.faults.as_ref().is_some_and(|f| f.lock().unwrap().get(name).is_some_and(|t| Instant::now() < *t))
    }

    fn exec(&self, name: &str, req: &Value, mut w: TcpStream) -> Result<()> {
        let cmd = req["cmd"].as_str().unwrap_or("");
        let guest = self.vm(name).and_then(|vm| {
            let (g, id) = vm.exec(|uds| match req["session"].as_str() {
                Some(id) => guest::session(uds, req["action"].as_str().unwrap_or("start"), id,
                    req["offset"].as_u64().unwrap_or(0), cmd, guest::TIMEOUT),
                None => guest::start_exec(uds, cmd, guest::TIMEOUT),
            })?;
            Ok((vm, g, id))
        });
        match guest {
            Ok((vm, mut g, id)) => {
                let copied = (|| -> Result<()> {
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
                copied?;
            }
            Err(e) => send_json(&mut w, &json!({"ok": false, "error": e.to_string()}))?,
        }
        Ok(())
    }

    /// Streams an image app's output: `offset`, and `follow` to keep going.
    fn logs(&self, name: &str, req: &Value, mut w: TcpStream) -> Result<()> {
        let guest = self.vm(name).and_then(|vm| {
            let (g, id) = vm.logs(req["offset"].as_u64().unwrap_or(0), req["follow"] == json!(true))?;
            Ok((vm, g, id))
        });
        match guest {
            Ok((vm, mut g, id)) => {
                send_json(&mut w, &json!({"ok": true}))?;
                let copied = std::io::copy(&mut g, &mut w);
                vm.untrack_exec(id);
                copied?;
            }
            Err(e) => send_json(&mut w, &json!({"ok": false, "error": e.to_string()}))?,
        }
        Ok(())
    }

    fn info(&self) -> Value {
        json!({
            "addr": self.cfg.advertise,
            "peers": self.cfg.peers,
            "mem_available_mib": proc_kb("/proc/meminfo", "MemAvailable").unwrap_or(0) >> 20,
            "mem_total_mib": proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0) >> 20,
            "reserve_mib": self.cfg.reserve_mib,
            "underlay": self.cfg.underlay.to_string(),
            "ips": self.ips.lock().unwrap().iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
            "vms": self.vms.lock().unwrap().len(),
        })
    }

    fn bench_info(&self, template: &str) -> Result<Value> {
        let read = |path| std::fs::read_to_string(path).ok().map(|s| s.trim().to_string());
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let model = cpuinfo.lines().find_map(|l| Some(l.split_once(':')?).filter(|(k, _)| k.trim() == "model name"));
        let firecracker = std::process::Command::new(&self.cfg.paths.firecracker).arg("--version").output().ok();
        Ok(json!({
            "daemon": self.info(),
            "hostname": read("/proc/sys/kernel/hostname"),
            "kernel": read("/proc/sys/kernel/osrelease"),
            "loadavg": read("/proc/loadavg"),
            "cpu_model": model.map(|(_, v)| v.trim()),
            "host_cpus": crate::util::host_cpus(),
            // This host is itself a guest, so VMs here run nested.
            "nested_virt": cpuinfo.split_whitespace().any(|f| f == "hypervisor"),
            "firecracker": firecracker.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()),
            "pool": self.cfg.pool,
            "template": self.template(template)?.meta,
        }))
    }

    /// Live-migrates `name` to the daemon at `to` with post-copy: pause, ship
    /// the vCPU/device state and a page map, resume on the target, then let
    /// the target pull memory from us on demand and in the background.
    ///
    /// Once the target may have the state it may resume the VM, so from then
    /// on this copy is resumed only if the target says migration `mig`
    /// aborted, and never once it committed.
    fn migrate(self: &Arc<Self>, name: &str, to: &str) -> Result<Value> {
        let vm = self.vm(name)?;
        // Before pausing, so a template mismatch costs no downtime.
        crate::template::preflight(&self.cfg.paths, &vm.template, to)?;
        let mig = migration_id();
        vm.start_source(mig)?;
        let mut t = Phases::new();
        let vmstate = vm.dir.join("vmstate.out");
        let prepared = (|| -> Result<_> {
            let runs = vm.checkpoint(&vmstate)?;
            let paused = t.mark("checkpoint");
            let state = std::fs::read(&vmstate)?;
            t.mark("read_state");
            let conn = crate::util::connect(to, Duration::from_secs(2))?;
            conn.set_nodelay(true)?;
            // A target that hangs leaves the outcome to `outcome` below.
            conn.set_read_timeout(Some(Duration::from_secs(30)))?;
            conn.set_write_timeout(Some(Duration::from_secs(30)))?;
            Ok((runs, paused, state, conn))
        })();
        let (runs, paused, state, mut conn) = match prepared {
            Ok(p) => p,
            Err(e) => return Err(self.abort_migration(&vm, mig, e)),
        };
        let remote_pages: u64 = runs.iter().filter(|r| r.2 == crate::uffd::REMOTE).map(|r| r.1).sum();
        let sent = (|| -> Result<Value> {
            send_json(
                &mut conn,
                &json!({
                    "op": "incoming",
                    "name": name,
                    "mig": mig,
                    "template": vm.template.name,
                    "id": vm.template.meta.id,
                    "ip": vm.ip.to_string(),
                    "source": self.cfg.advertise,
                    "runs": runs,
                    "vmstate_len": state.len(),
                }),
            )?;
            conn.write_all(&state)?;
            t.mark("send_state");
            Ok(recv_json(&mut BufReader::new(conn))?.ok_or("target hung up")?)
        })();
        let target = match sent {
            Ok(reply) if reply["ok"] == json!(true) => reply["result"].clone(),
            // A target only refuses before it resumes the VM, or after killing it.
            Ok(reply) => return Err(self.abort_migration(&vm, mig, format!("target refused: {}", reply["error"]).into())),
            Err(e) => match self.outcome(to, mig, Duration::from_secs(2)) {
                Some(Outcome::Committed(target)) => target,
                Some(Outcome::Aborted) => return Err(self.abort_migration(&vm, mig, e)),
                None => {
                    self.reconcile_later(vm.clone(), mig, to.to_string());
                    bail!("migrating {name} to {to}: {e}; {to} has not said whether it resumed the vm, so it stays paused here until it does");
                }
            },
        };
        t.mark("target");
        let downtime = t.total();
        // The target owns the VM now; this copy only serves its memory.
        let rerouted = self.reroute(vm.ip, &target);
        t.mark("reroute");
        Ok(json!({
            "name": name,
            "to": to,
            "mig": mig,
            "checkpoint_ms": ms(paused),
            "downtime_ms": ms(downtime),
            "rerouted_ms": ms(t.total()),
            "reroute_error": rerouted.err().map(|e| e.to_string()),
            "target_restore_ms": target["restore_ms"],
            "timings_ms": t.json(),
            "target_timings_ms": target["timings_ms"],
            "vmstate_kib": state.len() >> 10,
            "to_transfer_mib": (remote_pages * crate::util::PAGE_SIZE as u64) >> 20,
        }))
    }

    /// Resumes our copy after migration `mig` failed without the target ever
    /// owning the VM. Returns the error to report.
    fn abort_migration(&self, vm: &Vm, mig: u64, e: Error) -> Error {
        let mut st = vm.state.lock().unwrap();
        if *st != State::Source(mig) {
            return e;
        }
        match vm.resume() {
            Ok(()) => {
                *st = State::Running;
                e
            }
            Err(r) => {
                *st = State::Failed;
                format!("{e}; resuming it here failed too: {r}").into()
            }
        }
    }

    /// Asks `to` how migration `mig` went, for up to `patience`. None if it
    /// would not say.
    fn outcome(&self, to: &str, mig: u64, patience: Duration) -> Option<Outcome> {
        let start = Instant::now();
        loop {
            if let Ok(r) = peer_call(to, json!({"op": "migration", "mig": mig})) {
                match r["outcome"].as_str() {
                    Some("committed") => return Some(Outcome::Committed(r)),
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

    /// Keeps asking `to` how migration `mig` went, with the VM paused here,
    /// until it answers or the VM is killed.
    fn reconcile_later(self: &Arc<Self>, vm: Arc<Vm>, mig: u64, to: String) {
        let d = self.clone();
        thread::spawn(move || {
            let mut patience = Duration::from_secs(1);
            while vm.state() == State::Source(mig) && d.vm(&vm.name).is_ok_and(|v| Arc::ptr_eq(&v, &vm)) {
                match d.outcome(&to, mig, patience) {
                    Some(Outcome::Committed(target)) => {
                        eprintln!("vm {}: migration {mig} to {to} committed", vm.name);
                        let _ = d.reroute(vm.ip, &target);
                        return;
                    }
                    Some(Outcome::Aborted) => {
                        let e = d.abort_migration(&vm, mig, format!("migration {mig} to {to} aborted").into());
                        return eprintln!("vm {}: {e}; now {}", vm.name, vm.state().name());
                    }
                    None => patience = (patience * 2).min(Duration::from_secs(30)),
                }
            }
        });
    }

    /// Points our route for `ip` at a migration target. On failure retries in
    /// the background; the target owns the VM either way.
    fn reroute(self: &Arc<Self>, ip: Ipv4Addr, target: &Value) -> Result<()> {
        let via: Ipv4Addr = target["underlay"].as_str().ok_or("target sent no underlay")?.parse()?;
        let res = self.route_via(ip, via);
        if let Err(e) = &res {
            eprintln!("route {ip} via {via}: {e}; retrying");
            let d = self.clone();
            thread::spawn(move || {
                let mut delay = Duration::from_millis(100);
                for _ in 0..10 {
                    thread::sleep(delay);
                    // The VM may have come back here meanwhile.
                    if d.vms.lock().unwrap().values().any(|v| v.ip == ip && v.state() == State::Running) {
                        return;
                    }
                    match d.route_via(ip, via) {
                        Ok(()) => return eprintln!("route {ip} via {via}: done"),
                        Err(e) => eprintln!("route {ip} via {via}: {e}"),
                    }
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            });
        }
        res
    }

    fn route_via(&self, ip: Ipv4Addr, via: Ipv4Addr) -> Result<()> {
        if self.fault("route") {
            bail!("injected fault: route_via failed");
        }
        net::route_via(ip, via)
    }

    fn incoming(self: &Arc<Self>, req: &Value, r: &mut impl Read) -> Result<Value> {
        let mut t = Phases::new();
        let name = req["name"].as_str().ok_or("missing name")?.to_string();
        let mig = req["mig"].as_u64().ok_or("missing mig")?;
        let source = Source { addr: req["source"].as_str().ok_or("missing source")?.into(), vm: name.clone(), mig };
        let runs: Runs = serde_json::from_value(req["runs"].clone())?;
        let mut state = vec![0u8; req["vmstate_len"].as_u64().ok_or("missing vmstate_len")? as usize];
        r.read_exact(&mut state)?;
        t.mark("recv_state");
        {
            let mut migs = self.migrations.lock().unwrap();
            if migs.contains_key(&mig) {
                bail!("migration {mig} was already seen here");
            }
            migs.insert(mig, Incoming::Pending);
        }
        let res = self.take_in(&name, req, runs, source, &state, &mut t);
        // A failed restore has killed the VM, so the source may resume it.
        let outcome = if res.is_ok() { Incoming::Committed } else { Incoming::Aborted };
        self.migrations.lock().unwrap().insert(mig, outcome);
        res
    }

    fn take_in(
        self: &Arc<Self>,
        name: &str,
        req: &Value,
        runs: Runs,
        source: Source,
        state: &[u8],
        t: &mut Phases,
    ) -> Result<Value> {
        if self.vms.lock().unwrap().contains_key(name) {
            bail!("vm name {name:?} is taken here");
        }
        let tpl = self.migration_template(req, false)?;
        let ip = self.claim_ip(Some(req["ip"].as_str().ok_or("missing ip")?))?;
        t.mark("claim_ip");
        let restored = (|| {
            let idle = self.pool.take()?;
            t.mark("pool_take");
            let vmstate = idle.dir.join("vmstate.in");
            std::fs::write(&vmstate, state)?;
            t.mark("write_state");
            Vm::restore(idle, name, tpl, &vmstate, Some((runs, source.clone())), ip, t)
        })();
        let (vm, restore) = restored.inspect_err(|_| {
            self.ips.lock().unwrap().remove(&ip);
        })?;
        self.vms.lock().unwrap().insert(name.into(), vm.clone());
        self.announce(ip);
        t.mark("register");
        // Once every page has arrived, or as soon as the VM is gone here, the
        // source drops its copy: it must never run again either way.
        thread::spawn(move || {
            vm.restore_devices();
            let start = Instant::now();
            vm.pager.wait_pulled();
            let pulled = start.elapsed();
            if let Some(why) = vm.pager.failed() {
                eprintln!("vm {}: lost its memory ({why}); stopping it", vm.name);
                vm.kill();
            }
            let released = release_source(&source);
            eprintln!("vm {}: pull from {} ended after {} ms (release: {released})", vm.name, source.addr, ms(pulled));
            let _ = vm.released.set(released);
        });
        Ok(json!({"restore_ms": ms(restore), "underlay": self.cfg.underlay.to_string(), "timings_ms": t.json()}))
    }

    /// One pass of the elastic memory controller.
    fn control_tick(self: &Arc<Self>) {
        let vms: Vec<Arc<Vm>> = self.vms.lock().unwrap().values().cloned().collect();
        let mut host_avail = host_available_mib();
        for vm in &vms {
            if vm.state() == State::Running {
                match resize(vm, host_avail, self.cfg.reserve_mib) {
                    Ok(grew) => host_avail = host_avail.saturating_sub(grew),
                    Err(e) => eprintln!("vm {}: resize: {e}", vm.name),
                }
            }
        }
        self.relieve_pressure(&vms);
    }

    /// When this host runs low, or a VM cannot grow here, live-migrates a VM
    /// to the peer with the most room: a starved VM first, else the biggest.
    fn relieve_pressure(self: &Arc<Self>, vms: &[Arc<Vm>]) {
        let avail = host_available_mib();
        let running: Vec<&Arc<Vm>> =
            vms.iter().filter(|v| v.state() == State::Running && v.pager.remote_left() == 0).collect();
        let starved = running.iter().find(|v| v.starved.load(Ordering::SeqCst));
        if self.cfg.peers.is_empty() || (avail >= self.cfg.reserve_mib && starved.is_none()) {
            return;
        }
        if let Some(t) = *self.last_migration.lock().unwrap() {
            if t.elapsed() < Duration::from_secs(5) {
                return;
            }
        }
        let Some(vm) = starved.or_else(|| running.iter().max_by_key(|v| v.rss())) else { return };
        // Ask for room for what it uses plus one growth step.
        let need = (vm.rss() >> 20) + 2 * STEP_MIB;
        let target = self
            .cfg
            .peers
            .iter()
            .filter_map(|p| peer_info(p).ok().map(|i| (p, i)))
            .map(|(p, i)| {
                let free = i["mem_available_mib"].as_u64().unwrap_or(0);
                (p, free.saturating_sub(i["reserve_mib"].as_u64().unwrap_or(0)))
            })
            .filter(|(_, spare)| *spare > need)
            .max_by_key(|(_, spare)| *spare);
        let Some((peer, spare)) = target else {
            eprintln!("vm {}: needs {need} MiB but no peer has room (host has {avail} MiB available)", vm.name);
            return;
        };
        *self.last_migration.lock().unwrap() = Some(Instant::now());
        let why = if vm.starved.load(Ordering::SeqCst) { "cannot grow here" } else { "host is low on memory" };
        eprintln!("vm {}: {why} ({avail} MiB available); migrating to {peer} ({spare} MiB spare)", vm.name);
        match self.migrate(&vm.name, peer) {
            Ok(r) => eprintln!("vm {}: migrated: {r}", vm.name),
            Err(e) => eprintln!("vm {}: migration failed: {e}", vm.name),
        }
    }
}

fn host_available_mib() -> u64 {
    proc_kb("/proc/meminfo", "MemAvailable").unwrap_or(0) >> 20
}

/// Grows or shrinks a VM's hotplugged memory to keep its free memory within a
/// band, and returns how much it grew. Freed pages inside plugged memory go
/// back to the host through free page reporting, so this mostly decides how
/// far the guest may grow. A VM that needs to grow past what this host can
/// back is flagged as starved so the controller moves it somewhere roomier.
fn resize(vm: &Vm, host_avail: u64, reserve: u64) -> Result<u64> {
    let meta = &vm.template.meta;
    let hotplug_total = meta.max_mib - meta.mem_mib;
    if hotplug_total == 0 {
        return Ok(0);
    }
    let (stats, hp) = vm.fc(|fc| Ok((fc.get("/balloon/statistics")?, fc.get("/hotplug/memory")?)))?;
    let avail = stats["available_memory"].as_u64().unwrap_or(0) >> 20;
    let total = stats["total_memory"].as_u64().unwrap_or(0) >> 20;
    let requested = hp["requested_size_mib"].as_u64().unwrap_or(0);
    let plugged = hp["plugged_size_mib"].as_u64().unwrap_or(0);
    if total == 0 || plugged != requested {
        return Ok(0); // no stats yet, or the guest is still processing the last request
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
    Ok(grow)
}

/// Tells a migration source to drop its copy, retrying with backoff for a
/// while. Returns true, or the last error.
fn release_source(source: &Source) -> Value {
    let (start, mut delay) = (Instant::now(), Duration::from_millis(50));
    loop {
        match peer_call(&source.addr, json!({"op": "release", "name": source.vm, "mig": source.mig})) {
            Ok(_) => return json!(true),
            Err(e) if start.elapsed() > Duration::from_secs(60) => return json!(e.to_string()),
            Err(_) => thread::sleep(delay),
        }
        delay = (delay * 2).min(Duration::from_secs(5));
    }
}

/// A random id for a new migration (53 bits, so it survives any JSON parser).
fn migration_id() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    h.finish() >> 11
}

fn peer_info(peer: &str) -> Result<Value> {
    peer_call(peer, json!({"op": "info"}))
}

fn peer_call(peer: &str, req: Value) -> Result<Value> {
    let mut c = TcpStream::connect_timeout(&peer.parse()?, Duration::from_millis(500))?;
    c.set_read_timeout(Some(Duration::from_secs(2)))?;
    send_json(&mut c, &req)?;
    let reply = recv_json(&mut BufReader::new(c))?.ok_or("peer hung up")?;
    if reply["ok"] != json!(true) {
        bail!("{}", reply["error"]);
    }
    Ok(reply["result"].clone())
}

/// Joins a reader and writer into one Read + Write.
struct ReadWrite<R, W>(R, W);

impl<R: Read, W> Read for ReadWrite<R, W> {
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
