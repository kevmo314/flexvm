//! The per-host daemon: owns VMs, serves their memory to migration targets,
//! and runs the elastic memory controller.
//!
//! Every connection starts with one JSON request line. Most ops answer with
//! one JSON line; `exec` then streams guest frames, `pages` switches to the
//! binary page protocol and `incoming` is followed by the raw vmstate bytes.

use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
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
use crate::uffd::{serve_pages, Runs};
use crate::util::{ms, proc_kb, recv_json, send_json, Phases, Result};
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
    /// Guest memory backing for VMs started here: "None" (4 KiB) or "2M" (hugetlbfs).
    pub huge_pages: String,
    /// Backing for VMs migrating in. Post-copy fetches a whole huge page per
    /// fault, so 4 KiB keeps migration downtime down.
    pub huge_pages_incoming: String,
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
}

pub fn run(cfg: Config) -> Result<()> {
    std::fs::create_dir_all(&cfg.run_dir)?;
    let listener = TcpListener::bind(&cfg.listen)?;
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
                let mut stream = ReadWrite(r, w);
                return Ok(serve_pages(&vm.pager, &mut stream)?);
            }
            "exec" => return self.exec(&name, req["cmd"].as_str().unwrap_or(""), w),
            "incoming" => self.incoming(&req, &mut r),
            "run" => self.run_vm(&name, req["template"].as_str().unwrap_or("default"), req["ip"].as_str()),
            "ls" => Ok(json!(self.vms.lock().unwrap().values().map(|v| v.describe()).collect::<Vec<_>>())),
            "kill" => self.remove(&name, true),
            "release" => self.remove(&name, false),
            "route" => self.route(&req),
            "migrate" => self.migrate(&name, req["to"].as_str().unwrap_or("")),
            "info" => Ok(self.info()),
            "bench_info" => self.bench_info(req["template"].as_str().unwrap_or("default")),
            "migration_status" => self.vm(&name).map(|vm| {
                json!({"background_pull_ms": vm.pager.pull_time().map(ms), "released": vm.released.get()})
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
            Vm::restore(idle, name, tpl.clone(), &tpl.vmstate(), None, ip, &self.cfg.huge_pages, &mut t)
        });
        let (vm, restore) = restored.inspect_err(|_| {
            self.ips.lock().unwrap().remove(&ip);
        })?;
        self.vms.lock().unwrap().insert(name.into(), vm.clone());
        t.mark("register");
        let running = t.total();
        // The guest reseeds its RNG itself: Firecracker bumps the VMGenID on restore.
        guest::net(&vm.vsock(), ip, self.cfg.dns.as_deref())?;
        t.mark("guest_net");
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

    /// Stops a VM. `kill` also withdraws its address from the network;
    /// `release` (sent by a migration target) leaves it pointing at the target.
    fn remove(&self, name: &str, kill: bool) -> Result<Value> {
        let vm = self.vms.lock().unwrap().remove(name);
        let Some(vm) = vm else { bail!("no vm named {name:?}") };
        vm.kill();
        self.ips.lock().unwrap().remove(&vm.ip);
        if kill {
            let peers = self.cfg.peers.clone();
            let ip = vm.ip;
            thread::spawn(move || {
                for peer in &peers {
                    let _ = peer_call(peer, json!({"op": "route", "ip": ip.to_string()}));
                }
            });
        }
        Ok(json!({"name": name}))
    }

    fn exec(&self, name: &str, cmd: &str, mut w: TcpStream) -> Result<()> {
        let guest = self.vm(name).and_then(|vm| {
            if vm.state() != State::Running {
                bail!("vm {name} is not running here");
            }
            guest::start_exec(&vm.vsock(), cmd)
        });
        match guest {
            Ok(mut g) => {
                send_json(&mut w, &json!({"ok": true}))?;
                std::io::copy(&mut g, &mut w)?;
            }
            Err(e) => send_json(&mut w, &json!({"ok": false, "error": e.to_string()}))?,
        }
        Ok(())
    }

    fn info(&self) -> Value {
        json!({
            "addr": self.cfg.advertise,
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
    fn migrate(&self, name: &str, to: &str) -> Result<Value> {
        let vm = self.vm(name)?;
        {
            let mut st = vm.state.lock().unwrap();
            if *st != State::Running {
                bail!("vm {name} is not running here");
            }
            *st = State::Source;
        }
        let mut t = Phases::new();
        let vmstate = vm.dir.join("vmstate.out");
        let result = (|| -> Result<Value> {
            let runs = vm.checkpoint(&vmstate)?;
            let paused = t.mark("checkpoint");
            let state = std::fs::read(&vmstate)?;
            t.mark("read_state");
            let mut conn = TcpStream::connect(to)?;
            conn.set_nodelay(true)?;
            let remote_pages: u64 = runs.iter().filter(|r| r.2 == crate::uffd::REMOTE).map(|r| r.1).sum();
            send_json(
                &mut conn,
                &json!({
                    "op": "incoming",
                    "name": name,
                    "template": vm.template.name,
                    "ip": vm.ip.to_string(),
                    "source": self.cfg.advertise,
                    "runs": runs,
                    "vmstate_len": state.len(),
                }),
            )?;
            conn.write_all(&state)?;
            t.mark("send_state");
            let reply = recv_json(&mut BufReader::new(conn))?.ok_or("target hung up")?;
            if reply["ok"] != json!(true) {
                bail!("target refused: {}", reply["error"]);
            }
            t.mark("target");
            let downtime = t.total();
            // Send traffic for the VM straight to its new host.
            if let Some(via) = reply["result"]["underlay"].as_str() {
                net::route_via(vm.ip, via.parse()?)?;
            }
            t.mark("reroute");
            Ok(json!({
                "name": name,
                "to": to,
                "checkpoint_ms": ms(paused),
                "downtime_ms": ms(downtime),
                "rerouted_ms": ms(t.total()),
                "target_restore_ms": reply["result"]["restore_ms"],
                "timings_ms": t.json(),
                "target_timings_ms": reply["result"]["timings_ms"],
                "vmstate_kib": state.len() >> 10,
                "to_transfer_mib": (remote_pages * crate::util::PAGE_SIZE as u64) >> 20,
            }))
        })();
        if result.is_err() {
            // Keep running here; nothing on the target owns the VM.
            let _ = vm.resume();
            *vm.state.lock().unwrap() = State::Running;
        }
        result
    }

    fn incoming(self: &Arc<Self>, req: &Value, r: &mut impl Read) -> Result<Value> {
        let mut t = Phases::new();
        let name = req["name"].as_str().ok_or("missing name")?.to_string();
        let source = req["source"].as_str().ok_or("missing source")?.to_string();
        let runs: Runs = serde_json::from_value(req["runs"].clone())?;
        let mut state = vec![0u8; req["vmstate_len"].as_u64().ok_or("missing vmstate_len")? as usize];
        r.read_exact(&mut state)?;
        t.mark("recv_state");
        if self.vms.lock().unwrap().contains_key(&name) {
            bail!("vm name {name:?} is taken here");
        }
        let tpl = self.template(req["template"].as_str().ok_or("missing template")?)?;
        let ip = self.claim_ip(Some(req["ip"].as_str().ok_or("missing ip")?))?;
        t.mark("claim_ip");
        let restored = (|| {
            let idle = self.pool.take()?;
            t.mark("pool_take");
            let vmstate = idle.dir.join("vmstate.in");
            std::fs::write(&vmstate, &state)?;
            t.mark("write_state");
            Vm::restore(idle, &name, tpl, &vmstate, Some((runs, source.clone(), name.clone())), ip, &self.cfg.huge_pages_incoming, &mut t)
        })();
        let (vm, restore) = restored.inspect_err(|_| {
            self.ips.lock().unwrap().remove(&ip);
        })?;
        self.vms.lock().unwrap().insert(name.clone(), vm.clone());
        self.announce(ip);
        t.mark("register");
        // Tell the source to drop its copy once every page has arrived.
        thread::spawn(move || {
            let start = Instant::now();
            while vm.pager.remote_left() > 0 {
                thread::sleep(Duration::from_millis(5));
            }
            let pulled = start.elapsed();
            let release = (|| {
                let mut c = TcpStream::connect(&source)?;
                send_json(&mut c, &json!({"op": "release", "name": name}))?;
                recv_json(&mut BufReader::new(c))
            })();
            let released = match release {
                Ok(Some(r)) if r["ok"] == json!(true) => json!(true),
                Ok(Some(r)) => r["error"].clone(),
                Ok(None) => json!("source hung up"),
                Err(e) => json!(e.to_string()),
            };
            eprintln!("vm {name}: memory pulled from {source} in {} ms (release: {released})", ms(pulled));
            let _ = vm.released.set(released);
        });
        Ok(json!({"restore_ms": ms(restore), "underlay": self.cfg.underlay.to_string(), "timings_ms": t.json()}))
    }

    /// One pass of the elastic memory controller.
    fn control_tick(&self) {
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
    fn relieve_pressure(&self, vms: &[Arc<Vm>]) {
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
