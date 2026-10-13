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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::Pool;
use crate::guest;
use crate::hold::{self, Holder};
use crate::hot::HotPool;
use crate::net::{self, IpRange};
use crate::template::{Paths, Template, STEP_MIB};
use crate::checkpoint::{Checkpoint, CommitError, Manifest, Staging};
use crate::uffd::{serve_pages, Origin, Runs, Source};
use crate::util::{ms, proc_kb, recv_json, send_json, Error, Phases, Result};
use crate::vm::{State, Vm};

#[path = "lifecycle.rs"]
mod lifecycle;

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
    /// Paused, already restored VMs to keep ready per template.
    pub hot: usize,
    /// Host memory all paused VMs together may use (MiB).
    pub hot_mib: u64,
    /// Addresses this daemon hands to new VMs.
    pub vm_ips: IpRange,
    /// This host's address on the network shared with peers; they route VM addresses to it.
    pub underlay: Ipv4Addr,
    /// Answer ARP for local VMs on this interface and announce them when they arrive.
    pub announce_dev: Option<String>,
    pub dns: Option<String>,
    /// Durable local state: checkpoints of suspended VMs. Must be on disk
    /// (not tmpfs) for suspending to free memory.
    pub state_dir: PathBuf,
}

/// How long a lifecycle operation waits for another one on the same VM.
const LIFECYCLE_WAIT: Duration = Duration::from_secs(30);
/// How long a checkpoint waits for a VM to finish pulling its memory.
const DRAIN_WAIT: Duration = Duration::from_secs(60);
/// Guest clock error tolerated after a restore or resume.
const CLOCK_TOLERANCE: Duration = Duration::from_millis(20);
/// How long checking and stepping the guest clock may take.
const CLOCK_DEADLINE: Duration = Duration::from_secs(5);
/// How long an incoming migration may take to send its vmstate.
const INCOMING_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a migration source waits for the target's preflight answer.
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a checkpoint waits for virtio-mem to carry out the last resize.
const SETTLE_WAIT: Duration = Duration::from_secs(10);

/// A VM suspended to a checkpoint under `state_dir/suspended`.
struct Suspended {
    dir: PathBuf,
    manifest: Manifest,
}

pub struct Daemon {
    cfg: Config,
    vms: Mutex<HashMap<String, Arc<Vm>>>,
    /// Opened template generations, by directory.
    templates: Mutex<HashMap<PathBuf, Arc<Template>>>,
    pool: Arc<Pool>,
    hot: Arc<HotPool>,
    cgroup_root: Option<PathBuf>,
    tap_prefix: String,
    /// Set on SIGTERM/SIGINT: no new VMs, migrations or lifecycle operations from then on.
    closing: AtomicBool,
    /// Set by a second SIGTERM/SIGINT: shutdown stops waiting.
    force: AtomicBool,
    /// Starts, migrations (either way) and lifecycle operations in progress;
    /// shutdown lets them finish.
    ops: Counter,
    /// Incoming migrations still to tell their source to drop its copy.
    releases: Counter,
    /// Addresses this host holds or has lent out, under one lock.
    addrs: Mutex<Addrs>,
    last_migration: Mutex<Option<Instant>>,
    /// Migrations this host was asked to take in. An id it has answered for
    /// as aborted can never start here afterwards.
    migrations: Mutex<HashMap<u64, Incoming>>,
    /// Held for the daemon's lifetime (see `lock_run_dir`).
    _run_lock: Vec<std::fs::File>,
    /// Armed test faults and when they expire; None unless FLEXVM_FAULTS=1.
    faults: Option<Mutex<HashMap<String, Instant>>>,
    /// VM names with a lifecycle operation in progress, and which (see `reserve`).
    busy: (Mutex<HashMap<String, &'static str>>, Condvar),
    suspended: Mutex<HashMap<String, Suspended>>,
    /// Holds packets for VMs paused to migrate away; None without TUN support.
    holder: Option<Arc<Holder>>,
    /// Migrations in here whose sources may still send the packets they held.
    held_in: Mutex<HashMap<u64, HeldIn>>,
    _port_lock: std::os::unix::net::UnixListener,
    me: std::sync::Weak<Daemon>,
}

/// The right of a migration's source to send the VM that arrived here the
/// packets it held, on the migration connection: bound to that VM instance,
/// registered while the arrival still holds the VM's name, and gone once
/// the stream ends, when none opens within `HOLD_FENCE`, or when the VM is
/// killed or migrates on (`drop_held_in`, which also stops a stream in
/// progress: every injection checks `revoked` under its lock).
struct HeldIn {
    vm: Arc<Vm>,
    revoked: Arc<Mutex<bool>>,
    conn: Option<TcpStream>,
}

/// A VM name reserved for one lifecycle operation; released on drop.
struct Busy<'a> {
    d: &'a Daemon,
    name: String,
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.d.busy.0.lock().unwrap().remove(&self.name);
        self.d.busy.1.notify_all();
    }
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

/// How long a migration target waits for the first packet its source held
/// before announcing the VM anyway.
const HOLD_FENCE: Duration = Duration::from_millis(250);
/// Longest a target spends taking in held packets.
const HELD_STREAM: Duration = Duration::from_secs(2);

/// Claims `port` for this daemon in this network namespace: an abstract
/// unix socket, gone when the daemon is.
fn lock_port(port: u16) -> Result<std::os::unix::net::UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(format!("flexvm-port-{port}"))?;
    std::os::unix::net::UnixListener::bind_addr(&addr).map_err(|e| format!("port {port} is taken by another flexvm daemon in this network namespace ({e})").into())
}

/// How a migration ended on its target, as seen by the source.
enum Outcome {
    Committed(Value),
    Aborted,
}

pub fn run(mut cfg: Config) -> Result<()> {
    // Before any thread starts, so they all inherit the mask and only `signals` sees them.
    let signals = block_shutdown_signals();
    std::fs::create_dir_all(&cfg.run_dir)?;
    // Every Firecracker gets paths under the canonical directory, which is
    // what `kill_orphans` compares against.
    cfg.run_dir = cfg.run_dir.canonicalize()?;
    let mut run_lock = lock_run_dir(&cfg.run_dir)?;
    // The state dir is this daemon's alone too (another daemon's startup
    // would clear its trees), and must survive a power loss.
    lifecycle::create_dir_durably(&cfg.state_dir.join("suspended"))
        .map_err(|e| format!("state dir {}: {e}", cfg.state_dir.display()))?;
    cfg.state_dir = cfg.state_dir.canonicalize()?;
    run_lock.extend(lock_run_dir(&cfg.state_dir)?);
    let listener = TcpListener::bind(&cfg.listen)?;
    // Before any cleanup: taps, the hold device and cgroups are named after
    // the port, so one daemon per port (in this network namespace) owns them.
    let port: u16 = cfg.listen.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let port_lock = lock_port(port)?;
    let holder = Holder::new(port)?;
    kill_orphans(&cfg.run_dir)?;
    let cgroup_root = setup_cgroups(&cfg.listen);
    net::sysctl("net.ipv4.ip_forward", "1")?;
    if let Some(dev) = &cfg.announce_dev {
        net::sysctl(&format!("net.ipv4.conf.{dev}.proxy_arp"), "1")?;
    }
    let port = cfg.listen.rsplit(':').next().unwrap_or("0");
    let tap_prefix = format!("fv{port}x");
    net::delete_taps_with_prefix(&tap_prefix);
    // Before serving anything: addresses lent out before a restart stay taken.
    let addrs = Addrs::load(cfg.state_dir.join(LENT_FILE))?;
    let pool = Pool::new(&cfg.paths.firecracker, &cfg.run_dir, cgroup_root.clone(), &tap_prefix, cfg.pool);
    let hot = HotPool::new(pool.clone(), cfg.hot, cfg.hot_mib, cfg.reserve_mib);
    let d = Arc::new_cyclic(|me| Daemon {
        me: me.clone(),
        _port_lock: port_lock,
        held_in: Mutex::new(HashMap::new()),
        cfg,
        vms: Mutex::new(HashMap::new()),
        templates: Mutex::new(HashMap::new()),
        pool,
        hot,
        cgroup_root,
        tap_prefix,
        closing: AtomicBool::new(false),
        force: AtomicBool::new(false),
        ops: Counter::default(),
        releases: Counter::default(),
        addrs: Mutex::new(addrs),
        last_migration: Mutex::new(None),
        migrations: Mutex::new(HashMap::new()),
        _run_lock: run_lock,
        faults: std::env::var("FLEXVM_FAULTS").is_ok_and(|v| v == "1").then(|| Mutex::new(HashMap::new())),
        busy: (Mutex::new(HashMap::new()), Condvar::new()),
        suspended: Mutex::new(HashMap::new()),
        holder,
    });
    d.load_suspended()?;
    eprintln!("flexvm daemon listening on {} (advertised as {})", d.cfg.listen, d.cfg.advertise);
    {
        let d = d.clone();
        thread::spawn(move || {
            let sig = wait_for_signal(&signals);
            eprintln!("signal {sig}: shutting down; signal again to stop waiting for migrations");
            let s = d.clone();
            thread::spawn(move || {
                s.shutdown();
                std::process::exit(0);
            });
            let sig = wait_for_signal(&signals);
            eprintln!("signal {sig} again: shutting down without waiting any longer");
            d.force.store(true, Ordering::SeqCst);
        });
    }
    // Most VMs come from the default template; have paused ones ready for the first run.
    let _ = d.template("default");
    {
        let d = d.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(1000));
            d.control_tick();
        });
    }
    if !d.cfg.peers.is_empty() {
        let d = d.clone();
        thread::spawn(move || {
            let mut warned = HashSet::new();
            loop {
                d.check_peer_ranges(&mut warned);
                thread::sleep(Duration::from_secs(10));
            }
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
/// Removes this listen address's cgroups that no daemon can own any more:
/// the name used before roots carried a network namespace, and roots of
/// namespaces that no longer exist. Only empty ones: rmdir refuses a cgroup
/// with processes or children in use, and nothing is ever killed here.
fn prune_cgroups(root: &Path, base: &str, mine: &Path) {
    let live = live_netns();
    for e in std::fs::read_dir(root).into_iter().flatten().flatten() {
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        let stale = match name.strip_prefix(base) {
            Some("") => true,
            Some(rest) => rest.strip_prefix("_ns").and_then(|n| n.parse::<u64>().ok()).is_some_and(|n| !live.contains(&n)),
            None => false,
        };
        if !stale || path == mine || !path.is_dir() {
            continue;
        }
        for child in std::fs::read_dir(&path).into_iter().flatten().flatten() {
            if child.path().is_dir() {
                let _ = std::fs::remove_dir(child.path());
            }
        }
        let _ = std::fs::remove_dir(&path);
    }
}

/// Inodes of the network namespaces that exist: those of processes and
/// those kept by `ip netns`.
fn live_netns() -> HashSet<u64> {
    use std::os::unix::fs::MetadataExt;
    let mut live = HashSet::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        if let Ok(m) = std::fs::metadata(e.path().join("ns/net")) {
            live.insert(m.ino());
        }
    }
    for e in std::fs::read_dir("/run/netns").into_iter().flatten().flatten() {
        if let Ok(m) = std::fs::metadata(e.path()) {
            live.insert(m.ino());
        }
    }
    live
}

fn setup_cgroups(listen: &str) -> Option<PathBuf> {
    let root = PathBuf::from("/sys/fs/cgroup/flexvm");
    std::fs::create_dir_all(&root).ok()?;
    std::fs::write(root.join("cgroup.subtree_control"), "+cpu +memory").ok()?;
    // Daemons in different network namespaces may share a listen address,
    // and must not share a cgroup (shutdown kills everything in it).
    let netns = std::fs::read_link("/proc/self/ns/net").ok()?;
    let netns: String = netns.to_string_lossy().chars().filter(char::is_ascii_digit).collect();
    let base = listen.replace([':', '.', '[', ']'], "_");
    let mine = root.join(format!("{base}_ns{netns}"));
    prune_cgroups(&root, &base, &mine);
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
    /// The current generation of template `name`. One readlink per call, so a
    /// republished template is picked up by the next VM; VMs already running
    /// keep theirs.
    fn template(&self, name: &str) -> Result<Arc<Template>> {
        let dir = Template::resolve(&self.cfg.paths, name)?;
        let tpl = self.template_at(name, dir)?;
        self.hot.warm(&tpl);
        self.forget_old_generations(&tpl);
        Ok(tpl)
    }

    /// Template `name` from generation directory `dir`, opened once. Checked
    /// by inode too: a template from before generations is swapped by renaming
    /// a new directory over the same path.
    fn template_at(&self, name: &str, dir: PathBuf) -> Result<Arc<Template>> {
        use std::os::unix::fs::MetadataExt;
        let ino = std::fs::metadata(&dir).map_err(|e| format!("template {name:?}: {e}"))?.ino();
        if let Some(t) = self.templates.lock().unwrap().get(&dir).filter(|t| t.ino == ino) {
            return Ok(t.clone());
        }
        let tpl = Template::open_dir(name, dir.clone())?;
        let mut t = self.templates.lock().unwrap();
        let stale = match t.get(&dir) {
            Some(cur) if cur.ino == tpl.ino => return Ok(cur.clone()),
            _ => t.insert(dir, tpl.clone()),
        };
        drop(t);
        drop(stale);
        Ok(tpl)
    }

    /// Unmaps older generations of `current` that no VM or paused VM uses any more.
    fn forget_old_generations(&self, current: &Arc<Template>) {
        let unused: Vec<Arc<Template>> = {
            let mut t = self.templates.lock().unwrap();
            let old: Vec<PathBuf> = t
                .iter()
                .filter(|(_, o)| o.name == current.name && !Arc::ptr_eq(o, current) && Arc::strong_count(o) == 1)
                .map(|(d, _)| d.clone())
                .collect();
            old.iter().filter_map(|d| t.remove(d)).collect()
        };
        drop(unused);
    }

    /// The local template matching a migration source's: the generation with
    /// its content id, even if `name` has moved on since. Preflight runs before
    /// the source pauses and may rehash changed files; incoming only stats them.
    fn migration_template(&self, req: &Value, preflight: bool) -> Result<Arc<Template>> {
        let name = req["template"].as_str().ok_or("missing template")?;
        let id = req["id"].as_str().unwrap_or("");
        let tpl = match Template::generation(&self.cfg.paths, id) {
            Some(dir) => self.template_at(name, dir)?,
            None => self.template(name)?,
        };
        tpl.check_id(req["id"].as_str().ok_or("missing template id")?)?;
        tpl.verify(&self.cfg.paths, preflight)?;
        Ok(tpl)
    }

    /// Template `name`, generation `id` if this host has it (a checkpoint or
    /// migration refers to its template by content id), else the current one.
    pub(super) fn template_with_id(&self, name: &str, id: &str) -> Result<Arc<Template>> {
        match Template::generation(&self.cfg.paths, id) {
            Some(dir) => self.template_at(name, dir),
            None => self.template(name),
        }
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
        // A release lets a shutting-down source exit; it must still get its reply out.
        let _releasing = (op == "release").then(|| self.ops.enter());
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
            "incoming" => match {
                // The vmstate follows; a source that stalls must not hold a
                // counted operation (and so shutdown) forever.
                r.get_ref().set_read_timeout(Some(INCOMING_READ_TIMEOUT))?;
                self.incoming(&req, &mut r)
            } {
                // Committed, but the source never hears about it. (Shut down,
                // as the announcing thread holds a clone of the connection.)
                Ok(_) if self.fault("lost_ack") => return Ok(w.shutdown(std::net::Shutdown::Both)?),
                res => res,
            },
            "run" => self.run_vm(&name, req["template"].as_str().unwrap_or("default"), req["ip"].as_str()),
            "ls" => Ok(self.list()),
            "kill" => self.kill(&name),
            "pause" => self.pause(&name),
            "resume" => self.resume(&name),
            "suspend" => self.suspend(&name),
            "checkpoint" => {
                let dir = req["dir"].as_str().ok_or("missing dir")?;
                self.checkpoint(&name, dir, req["stop"].as_bool().unwrap_or(false), req["incremental"].as_bool().unwrap_or(false))
            }
            "restore" => self.restore(
                req["dir"].as_str().ok_or("missing dir")?,
                req["name"].as_str(),
                req["ip"].as_str(),
                req["paused"].as_bool().unwrap_or(false),
            ),
            "memhash" => self.memhash(&name),
            "ckhash" => self.ckhash(req["dir"].as_str().ok_or("missing dir")?),
            "release" => self.release(&name, &req),
            "migration" => self.migration_outcome(&req),
            "fault" => self.inject(&req),
            "route" => self.route(&req),
            "unlend" => {
                let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
                Ok(json!({"freed": self.addrs.lock().unwrap().unlend(ip)}))
            }
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

    fn run_vm(self: &Arc<Self>, name: &str, template: &str, ip: Option<&str>) -> Result<Value> {
        let mut t = Phases::new();
        let _op = self.admit()?;
        let _busy = self.reserve(name, "starting", Duration::ZERO)?;
        if name.is_empty() || self.taken(name) {
            bail!("vm name {name:?} is empty or taken");
        }
        let tpl = self.template(template)?;
        let claim = match ip {
            Some(ip) => self.claim_given_ip(ip, ClaimFor::Run)?,
            None => self.claim_ip()?,
        };
        let ip = claim.ip;
        let claimed = t.mark("claim_ip");
        // A paused VM from the hot pool only needs resuming; otherwise load the snapshot now.
        let hot = self.hot.take(&tpl);
        t.mark("hot_take");
        let hot_age = hot.as_ref().map(|p| p.age());
        let restored = match hot {
            Some(paused) => paused.resume(name, ip, &mut t),
            None => self.pool.take().and_then(|idle| {
                t.mark("pool_take");
                Vm::restore(idle, name, tpl.clone(), &tpl.vmstate(), None, ip, &mut t).map(|(vm, _)| vm)
            }),
        };
        let vm = restored?;
        let restore = t.total() - claimed;
        if let Err(e) = self.publish(name, &vm) {
            vm.kill();
            return Err(e);
        }
        claim.commit();
        t.mark("register");
        let running = t.total();
        // The guest reseeds its RNG itself: Firecracker bumps the VMGenID on restore.
        // Under the reservation, so no migration or checkpoint can take the
        // VM meanwhile; a failure marks it Failed.
        let started = vm.guest_net(ip, self.cfg.dns.as_deref()).and_then(|()| {
            if t.mark("guest_net") >= crate::vm::CLOCK_RTT {
                // START's clock is behind by its transit time; fixed off this path.
                self.sync_clock_later(vm.clone());
            }
            // Image templates start their app now, unless the snapshot holds it running.
            if tpl.meta.image.as_ref().is_some_and(|i| !i.warm) {
                vm.start_app().map_err(|e| format!("{e} (see `flexvm logs {name}`)"))?;
                t.mark("app_start");
            }
            Ok(())
        });
        if let Err(e) = started {
            self.vms.lock().unwrap().remove(name);
            vm.kill();
            self.addrs.lock().unwrap().used.remove(&ip);
            return Err(e);
        }
        self.announce(&vm);
        t.mark("announce");
        Ok(json!({
            "name": name,
            "ip": ip.to_string(),
            "hot": hot_age.is_some(),
            "hot_age_ms": hot_age.map(ms),
            "restore_ms": ms(restore),
            "running_ms": ms(running),
            "ready_ms": ms(t.total()),
            "timings_ms": t.json(),
        }))
    }

    /// Reserves the first free address in this host's `--vm-ips` range. The
    /// ranges of a cluster must be disjoint, so only this host hands these
    /// out: no peer is asked, and two hosts can never pick the same one. An
    /// address that left with a migrated VM stays reserved until it is
    /// reported gone.
    fn claim_ip(&self) -> Result<IpClaim<'_>> {
        let mut a = self.addrs.lock().unwrap();
        let ip = self.cfg.vm_ips.allocate(|ip| a.used.contains(&ip) || a.lent.contains(&ip)).ok_or("no free addresses left")?;
        a.used.insert(ip);
        Ok(IpClaim { addrs: &self.addrs, ip, was_lent: false, done: false })
    }

    /// Reserves a given address: one picked with `run --ip` (checked against
    /// the peers too, best effort), a restore's, or a migrating VM's own.
    /// Only a VM migrating in may take a lent address (it is coming back),
    /// and it leaves the lent set only if the claim commits.
    fn claim_given_ip(&self, ip: &str, why: ClaimFor) -> Result<IpClaim<'_>> {
        let ip: Ipv4Addr = ip.parse().map_err(|_| format!("bad address {ip:?}"))?;
        if why == ClaimFor::Run {
            for peer in &self.cfg.peers {
                if peer_info(peer).is_ok_and(|info| info_ips(&info).any(|i| i == ip)) {
                    bail!("{ip} is in use on {peer}");
                }
            }
        }
        let mut a = self.addrs.lock().unwrap();
        if a.used.contains(&ip) {
            bail!("{ip} is already in use here");
        }
        let was_lent = a.lent.contains(&ip);
        if was_lent && why != ClaimFor::Incoming {
            bail!("{ip} is in use on another host (lent out with a migrated vm)");
        }
        a.used.insert(ip);
        Ok(IpClaim { addrs: &self.addrs, ip, was_lent, done: false })
    }

    /// Reserves an address and keeps it, for callers that roll back themselves
    /// (restores): `want`, or the first free one in this host's range.
    pub(super) fn claim_ip_kept(&self, want: Option<&str>) -> Result<Ipv4Addr> {
        let claim = match want {
            Some(ip) => self.claim_given_ip(ip, ClaimFor::Restore)?,
            None => self.claim_ip()?,
        };
        let ip = claim.ip;
        // Never a lent address (refused above), so this only marks it used.
        claim.commit();
        Ok(ip)
    }

    /// Points the network at this host for `vm`'s address: a gratuitous ARP
    /// for the LAN and a route for each peer. Runs in the background; each
    /// step happens only while `vm` itself is still served from here (not
    /// killed, replaced or migrated on).
    fn announce(&self, vm: &Arc<Vm>) {
        let Some(d) = self.me.upgrade() else { return };
        let vm = vm.clone();
        let ip = vm.ip;
        thread::spawn(move || {
            let current = || d.vm(&vm.name).is_ok_and(|v| Arc::ptr_eq(&v, &vm)) && vm.state().local();
            let dev = d.cfg.announce_dev.clone();
            let via = d.cfg.underlay;
            if let Some(dev) = dev.as_deref().filter(|_| current()) {
                if let Err(e) = net::gratuitous_arp(dev, ip) {
                    eprintln!("announce {ip}: {e}");
                }
            }
            for peer in &d.cfg.peers {
                if !current() {
                    return;
                }
                if let Err(e) = peer_call(peer, json!({"op": "route", "ip": ip.to_string(), "via": via.to_string()})) {
                    eprintln!("announce {ip} to {peer}: {e}");
                }
            }
            // A second ARP for anyone who missed the first.
            if let Some(dev) = &dev {
                thread::sleep(Duration::from_millis(200));
                if current() {
                    let _ = net::gratuitous_arp(dev, ip);
                }
            }
        });
    }

    /// A peer tells us where a VM address lives (`via`), or that it is gone.
    fn route(&self, req: &Value) -> Result<Value> {
        let ip: Ipv4Addr = req["ip"].as_str().ok_or("missing ip")?.parse()?;
        // A withdrawal: the VM holding it was killed, so a lent address is free again.
        if req["via"].is_null() {
            self.addrs.lock().unwrap().unlend(ip);
        }
        let local = self.vms.lock().unwrap().values().any(|v| v.ip == ip && v.state().local());
        // A migration away from here is holding its packets; its release moves the route.
        let held = self.holder.as_ref().is_some_and(|h| h.holding(ip));
        if !local && !held {
            match req["via"].as_str() {
                Some(via) => net::route_via(ip, via.parse()?)?,
                None => net::unroute(ip),
            }
        }
        Ok(json!({"ip": ip.to_string(), "local": local}))
    }

    /// Complains (once per peer and range) when a peer's `--vm-ips` overlaps
    /// ours: both would hand out the same addresses.
    fn check_peer_ranges(&self, warned: &mut HashSet<(String, String)>) {
        for peer in &self.cfg.peers {
            let Ok(info) = peer_info(peer) else { continue };
            let Some(theirs) = info["vm_ips"].as_str().and_then(|r| IpRange::parse(r).ok()) else { continue };
            if theirs.overlaps(&self.cfg.vm_ips) && warned.insert((peer.clone(), theirs.to_string())) {
                eprintln!(
                    "WARNING: --vm-ips {} overlaps {peer}'s {theirs}; both hosts can hand out the same \
                     addresses. Give every host a disjoint range.",
                    self.cfg.vm_ips
                );
            }
        }
    }

    /// Stops a VM and withdraws its address from the network.
    fn kill(&self, name: &str) -> Result<Value> {
        // A checkpoint still writing a running VM's pages gives up rather
        // than hold the kill up.
        let vm = self.vm(name).ok();
        if let Some(vm) = &vm {
            vm.cancel_checkpoint.fetch_add(1, Ordering::SeqCst);
            vm.pager.abort_copy();
        }
        let busy = self.reserve(name, "killing", LIFECYCLE_WAIT);
        // This kill no longer waits; one that gave up leaves its request for
        // the checkpoint in the way to see.
        if let (Some(vm), Ok(_)) = (&vm, &busy) {
            let _ = vm.cancel_checkpoint.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| Some(n.saturating_sub(1)));
        }
        let _busy = busy?;
        self.kill_reserved(name)
    }

    /// `kill`, for a caller holding the name's reservation. A suspended VM's
    /// checkpoint is deleted.
    fn kill_reserved(&self, name: &str) -> Result<Value> {
        // Out of the map and the claims at once (see `switch_route`).
        let vm = {
            let mut addrs = self.addrs.lock().unwrap();
            let vm = self.vms.lock().unwrap().remove(name);
            if let Some(vm) = &vm {
                addrs.used.remove(&vm.ip);
            }
            vm
        };
        let ip = match vm {
            Some(vm) => {
                self.drop_held_in(&vm);
                vm.kill();
                if let (State::Source(mig), Some(h)) = (vm.state(), &self.holder) {
                    h.forget(vm.ip, mig);
                }
                vm.ip
            }
            None => {
                let s = self.suspended.lock().unwrap().remove(name);
                let Some(s) = s else { bail!("no vm named {name:?}") };
                // Durably gone before we say so, or it would come back after a crash.
                if let Err(e) = self.discard_suspended(name, &s) {
                    self.suspended.lock().unwrap().insert(name.into(), s);
                    return Err(e);
                }
                // A live VM's address left the claims with it, above; by now
                // it may be a newer VM's.
                self.addrs.lock().unwrap().used.remove(&s.manifest.ip);
                s.manifest.ip
            }
        };
        let peers = self.cfg.peers.clone();
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
        // The copy leaves the map and its address the claims at once, under
        // the address lock (see `switch_route`).
        let vm = {
            let mut addrs = self.addrs.lock().unwrap();
            let mut vms = self.vms.lock().unwrap();
            let vm = match vms.get(name).map(|v| v.state()) {
                None => return Ok(json!({"name": name, "already": true})),
                Some(State::Source(m)) if m == mig => vms.remove(name).unwrap(),
                Some(_) => bail!("vm {name} here is not the source of migration {mig}"),
            };
            // It lives on at the target: from our range, it stays taken until
            // the VM is withdrawn (killed) wherever it is, or an operator frees it.
            addrs.move_out(vm.ip, self.cfg.vm_ips.contains(vm.ip));
            vm
        };
        vm.kill();
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
            let (g, id) = vm.exec(|s| match req["session"].as_str() {
                Some(id) => guest::session(s, req["action"].as_str().unwrap_or("start"), id,
                    req["offset"].as_u64().unwrap_or(0), cmd, guest::TIMEOUT),
                None => guest::start_exec(s, cmd, guest::TIMEOUT),
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
            // Registered like an exec session, so a checkpoint closes it.
            let (offset, follow) = (req["offset"].as_u64().unwrap_or(0), req["follow"] == json!(true));
            let (g, id) = vm.exec(|s| guest::start_logs(s, offset, follow, guest::TIMEOUT))?;
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
            "vm_ips": self.cfg.vm_ips.to_string(),
            "ips": self.addrs.lock().unwrap().used.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
            "lent_ips": self.addrs.lock().unwrap().lent.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
            "vms": self.vms.lock().unwrap().len(),
            "hot": self.hot.describe(),
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
            "hot": self.cfg.hot,
            "hot_mib": self.cfg.hot_mib,
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
        let _op = self.admit()?;
        let _busy = self.reserve(name, "migrating", LIFECYCLE_WAIT)?;
        let vm = self.vm(name)?;
        // Before pausing, so a template mismatch costs no downtime.
        crate::template::preflight(&self.cfg.paths, &vm.template, to, PREFLIGHT_TIMEOUT)?;
        // Before the pause (not part of the downtime): no virtio-mem resize may
        // still be under way.
        let settle = Instant::now();
        vm.settle_hotplug(settle + SETTLE_WAIT)?;
        let settle = settle.elapsed();
        let mig = migration_id();
        // Durably lent before the target can have the VM: if we crash with
        // the outcome unknown, a restart must not hand the address out. A
        // failure to record it stops the migration here. Undone only once
        // this copy is known to stay (`abort_migration`).
        let ours = self.cfg.vm_ips.contains(vm.ip);
        if ours {
            self.addrs.lock().unwrap().lend(vm.ip)?;
        }
        // Its previous source can no longer send it held packets.
        self.drop_held_in(&vm);
        if let Err(e) = vm.start_source(mig) {
            if ours {
                self.addrs.lock().unwrap().unlend(vm.ip);
            }
            return Err(e);
        }
        let mut t = Phases::new();
        let vmstate = vm.dir.join("vmstate.out");
        // Packets for the VM wait here until it runs again.
        let hold = || {
            if let Some(Err(e)) = self.holder.as_ref().map(|h| h.hold(vm.ip, mig)) {
                eprintln!("vm {name}: not holding packets during migration: {e}");
            }
        };
        let prepared = (|| -> Result<_> {
            let runs = vm.checkpoint(&vmstate, hold)?;
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
                    // A paused VM stays paused on the target, which pulls its pages before it ever runs.
                    "paused": vm.was_paused(),
                }),
            )?;
            conn.write_all(&state)?;
            t.mark("send_state");
            Ok(recv_json(&mut BufReader::new(&conn))?.ok_or("target hung up")?)
        })();
        let (target, answered) = match sent {
            Ok(reply) if reply["ok"] == json!(true) => (reply["result"].clone(), true),
            // A target only refuses before it resumes the VM, or after killing it.
            Ok(reply) => return Err(self.abort_migration(&vm, mig, format!("target refused: {}", reply["error"]).into())),
            Err(e) => match self.outcome(to, mig, Duration::from_secs(2)) {
                Some(Outcome::Committed(target)) => (target, false),
                Some(Outcome::Aborted) => return Err(self.abort_migration(&vm, mig, e)),
                None => {
                    self.reconcile_later(vm.clone(), mig, to.to_string());
                    bail!("migrating {name} to {to}: {e}; {to} has not said whether it resumed the vm, so it stays paused here until it does");
                }
            },
        };
        t.mark("target");
        let downtime = t.total();
        // The target owns the VM now; this copy only serves its memory. The
        // packets held meanwhile follow on the migration connection.
        let (held, rerouted) = self.reroute(&vm, mig, to, &target, answered.then_some(&conn));
        t.mark("reroute");
        Ok(json!({
            "name": name,
            "to": to,
            "mig": mig,
            "settle_hotplug_ms": ms(settle),
            "checkpoint_ms": ms(paused),
            "downtime_ms": ms(downtime),
            "rerouted_ms": ms(t.total()),
            "reroute_error": rerouted.err().map(|e| e.to_string()),
            "held": held.map(|s| s.json()),
            "target_restore_ms": target["restore_ms"],
            "timings_ms": t.json(),
            "target_timings_ms": target["timings_ms"],
            "vmstate_kib": state.len() >> 10,
            "to_transfer_mib": (remote_pages * crate::util::PAGE_SIZE as u64) >> 20,
        }))
    }

    /// Resumes our copy after migration `mig` failed without the target ever
    /// owning the VM. Returns the error to report.
    fn abort_migration(self: &Arc<Self>, vm: &Arc<Vm>, mig: u64, e: Error) -> Error {
        // Only `migrate` itself or, once it has given up, the one
        // `reconcile_later` thread of this migration gets here, so the state
        // lock need not be held across the Firecracker requests.
        if *vm.state.lock().unwrap() != State::Source(mig) {
            return e;
        }
        // Packets held meanwhile go into the tap first: Firecracker reads
        // them once resumed, ahead of what the restored route brings.
        if let Some(h) = &self.holder {
            self.release_into(h, vm.ip, mig, vm, |()| net::attach(vm.ip, &vm.tap));
        }
        let (s, e) = match vm.resume() {
            Ok(s) => (s, e),
            Err(r) => (State::Failed, format!("{e}; resuming it here failed too: {r}").into()),
        };
        *vm.state.lock().unwrap() = s;
        // The VM stays here after all: its address is no longer lent.
        if self.cfg.vm_ips.contains(vm.ip) {
            self.addrs.lock().unwrap().unlend(vm.ip);
        }
        if s == State::Running {
            // The guest clock missed the pause; fixed once the migration lets go of the VM.
            self.sync_clock_later(vm.clone());
        }
        e
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
            // Also once the paused copy is gone (the target released it):
            // the packets held for it still wait for the outcome.
            let here = || vm.state() == State::Source(mig) && d.vm(&vm.name).is_ok_and(|v| Arc::ptr_eq(&v, &vm));
            let held = || d.holder.as_ref().is_some_and(|h| h.holding_for(vm.ip, mig));
            while here() || held() {
                match d.outcome(&to, mig, patience) {
                    Some(Outcome::Committed(target)) => {
                        eprintln!("vm {}: migration {mig} to {to} committed", vm.name);
                        let _ = d.reroute(&vm, mig, &to, &target, None);
                        return;
                    }
                    Some(Outcome::Aborted) if here() => {
                        let e = d.abort_migration(&vm, mig, format!("migration {mig} to {to} aborted").into());
                        return eprintln!("vm {}: {e}; now {}", vm.name, vm.state().name());
                    }
                    Some(Outcome::Aborted) => {
                        if let Some(h) = &d.holder {
                            h.forget(vm.ip, mig);
                        }
                        return;
                    }
                    None => patience = (patience * 2).min(Duration::from_secs(30)),
                }
            }
        });
    }

    /// Sends the packets held for `vm` to the target `to` of migration
    /// `mig` (on `conn`, the migration connection, or a new one), pointing our
    /// route for its address at the target meanwhile. On failure retries the
    /// route in the background; the target owns the VM either way.
    ///
    /// If the address belongs to a newer VM here by now (the VM came back
    /// while this migration's outcome was unknown), the held packets go to
    /// that VM's tap and the route stays.
    fn reroute(self: &Arc<Self>, vm: &Arc<Vm>, mig: u64, to: &str, target: &Value, conn: Option<&TcpStream>) -> (Option<hold::Stats>, Result<()>) {
        let ip = vm.ip;
        let newer = self.vms.lock().unwrap().values().find(|v| v.ip == ip && !Arc::ptr_eq(v, vm) && v.state().local()).cloned();
        if let Some(newer) = newer {
            let held = self.holder.as_ref().and_then(|h| self.release_into(h, ip, mig, &newer, Ok));
            return (held, Ok(()));
        }
        let via: Ipv4Addr = match target["underlay"].as_str().and_then(|s| s.parse().ok()) {
            Some(via) => via,
            None => {
                if let Some(h) = &self.holder {
                    h.forget(ip, mig);
                }
                return (None, Err("target sent no underlay".into()));
            }
        };
        let mut held = None;
        let mut res = None;
        if let Some(h) = self.holder.as_ref().filter(|h| h.holding_for(ip, mig)) {
            // Only on the migration connection, and only once the target has
            // accepted the stream is anything taken off the queue. Otherwise
            // (its answer was lost, it gave up waiting) the packets are dropped.
            match conn.map(hold::start) {
                Some(Ok(seq)) => {
                    if let Some((stats, r)) = hold::send(h, ip, mig, conn.unwrap(), seq, || self.switch_route(vm, via)) {
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
        let res = res.unwrap_or_else(|| self.switch_route(vm, via));
        if let Err(e) = &res {
            eprintln!("route {ip} via {via}: {e}; retrying");
            let d = self.clone();
            let vm = vm.clone();
            thread::spawn(move || {
                let mut delay = Duration::from_millis(100);
                for _ in 0..10 {
                    thread::sleep(delay);
                    // The VM may have come back here meanwhile.
                    if d.vms.lock().unwrap().values().any(|v| v.ip == ip && v.state().local()) {
                        return;
                    }
                    match d.switch_route(&vm, via) {
                        Ok(()) => return eprintln!("route {ip} via {via}: done"),
                        Err(e) => eprintln!("route {ip} via {via}: {e}"),
                    }
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            });
        }
        (held, res)
    }

    /// Injects what migration `mig` held for `ip` into `vm`'s tap (brought
    /// up for it), then calls `switch`.
    fn release_into(&self, h: &Holder, ip: Ipv4Addr, mig: u64, vm: &Vm, switch: impl FnOnce(()) -> Result<()>) -> Option<hold::Stats> {
        if !h.holding_for(ip, mig) {
            return None;
        }
        let inj = net::set_link_up(&vm.tap, true).and_then(|()| hold::Injector::new(&vm.tap));
        let inj = match inj {
            Ok(inj) => inj,
            Err(e) => {
                eprintln!("vm {}: dropping held packets: {e}", vm.name);
                h.forget(ip, mig);
                return None;
            }
        };
        let (mut stats, _) = h.release(ip, mig, &mut |p| hold::valid(p, ip) && inj.send(p), &mut || true, || switch(()))?;
        stats.injected = stats.packets;
        stats.dropped_target = inj.dropped();
        Some(stats)
    }

    /// Revokes the rights to send held packets to `vm` (killed or leaving),
    /// stopping any stream in progress.
    fn drop_held_in(&self, vm: &Arc<Vm>) {
        self.held_in.lock().unwrap().retain(|_, h| {
            if !Arc::ptr_eq(&h.vm, vm) {
                return true;
            }
            *h.revoked.lock().unwrap() = true;
            if let Some(c) = &h.conn {
                let _ = c.shutdown(std::net::Shutdown::Both);
            }
            false
        });
    }

    /// Points the route for `vm`'s address at `via`, unless the address
    /// belongs to a newer VM here by now. Serialized with address claims, so
    /// a VM claiming it later routes it to itself after this; `vm` leaves the
    /// map and the claims together (`release`, `kill_reserved`), so a claim
    /// without it in the map is a newer VM's.
    fn switch_route(&self, vm: &Arc<Vm>, via: Ipv4Addr) -> Result<()> {
        let addrs = self.addrs.lock().unwrap();
        let ours = self.vms.lock().unwrap().values().any(|v| Arc::ptr_eq(v, vm));
        if !ours && addrs.used.contains(&vm.ip) {
            return Ok(());
        }
        self.route_via(vm.ip, via)
    }

    fn route_via(&self, ip: Ipv4Addr, via: Ipv4Addr) -> Result<()> {
        if self.fault("route") {
            bail!("injected fault: route_via failed");
        }
        net::route_via(ip, via)
    }

    fn incoming(self: &Arc<Self>, req: &Value, r: &mut BufReader<TcpStream>) -> Result<Value> {
        let mut t = Phases::new();
        let _op = self.admit()?;
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
        if let Ok((_, vm)) = &res {
            // Nothing more is buffered: the source waits for our answer.
            let conn = r.get_ref().try_clone().ok();
            let revoked = {
                let mut held = self.held_in.lock().unwrap();
                let right = held.get_mut(&mig).filter(|h| Arc::ptr_eq(&h.vm, vm));
                right.map(|h| {
                    h.conn = conn.as_ref().and_then(|c| c.try_clone().ok());
                    h.revoked.clone()
                })
            };
            self.announce_after_held(mig, vm.clone(), conn.zip(revoked));
        }
        // A failed restore has killed the VM, so the source may resume it.
        let outcome = if res.is_ok() { Incoming::Committed } else { Incoming::Aborted };
        self.migrations.lock().unwrap().insert(mig, outcome);
        res.map(|(v, _)| v)
    }

    /// Once a VM that migrated in runs, injects the packets its source held,
    /// which follow our answer on the migration connection, then announces
    /// the VM, so held packets come before traffic sent straight here. If no
    /// stream opens within `HOLD_FENCE` (none held, or the source is slow),
    /// closes the right and announces: a later stream would come after
    /// traffic sent straight here, so its packets are dropped instead.
    fn announce_after_held(self: &Arc<Self>, mig: u64, vm: Arc<Vm>, stream: Option<(TcpStream, Arc<Mutex<bool>>)>) {
        let d = self.clone();
        thread::spawn(move || {
            if let Some((conn, revoked)) = stream {
                let mut r = BufReader::new(conn);
                if hold::wait_start(&mut r, Instant::now() + HOLD_FENCE) {
                    hold::receive(&mut r, vm.ip, &vm.tap, &revoked, Instant::now() + HELD_STREAM);
                }
            }
            d.held_in.lock().unwrap().remove(&mig);
            d.announce(&vm);
        });
    }

    fn take_in(
        self: &Arc<Self>,
        name: &str,
        req: &Value,
        runs: Runs,
        source: Source,
        state: &[u8],
        t: &mut Phases,
    ) -> Result<(Value, Arc<Vm>)> {
        let _busy = self.reserve(name, "incoming", Duration::ZERO)?;
        if self.taken(name) {
            bail!("vm name {name:?} is taken here");
        }
        let tpl = self.migration_template(req, false)?;
        let claim = self.claim_given_ip(req["ip"].as_str().ok_or("missing ip")?, ClaimFor::Incoming)?;
        let ip = claim.ip;
        t.mark("claim_ip");
        let restored = (|| {
            let idle = self.pool.take()?;
            t.mark("pool_take");
            let vmstate = idle.dir.join("vmstate.in");
            std::fs::write(&vmstate, state)?;
            t.mark("write_state");
            let paused = req["paused"].as_bool().unwrap_or(false);
            let origin = Some((runs, Origin::Peer(source.clone())));
            let load = if paused { crate::vm::Load::Paused } else { crate::vm::Load::Running };
            Vm::restore_from(idle, name, tpl, &vmstate, origin, ip, load, t)
        })();
        let (vm, restore) = restored?;
        if let Err(e) = self.publish(name, &vm) {
            // Not ours after all: the source may resume its copy.
            vm.kill();
            return Err(e);
        }
        claim.commit();
        t.mark("register");
        let arrived = vm.clone();
        // While the arrival still holds the name: no kill or migration of
        // this VM can come before it, so none misses it.
        self.held_in.lock().unwrap().insert(source.mig, HeldIn { vm: vm.clone(), revoked: Arc::default(), conn: None });
        // The guest clock missed the downtime; fixed once this migration lets go of the VM.
        if vm.state() == State::Running {
            self.sync_clock_later(vm.clone());
        }
        // Once every page has arrived, or as soon as the VM is gone here, the
        // source drops its copy: it must never run again either way. Shutdown
        // waits for this.
        std::mem::forget(self.releases.enter());
        let d = self.clone();
        thread::spawn(move || {
            let _releasing = CountGuard(&d.releases);
            vm.restore_devices();
            let start = Instant::now();
            vm.pager.wait_pulled();
            let pulled = start.elapsed();
            if let Some(why) = vm.pager.failed() {
                eprintln!("vm {}: lost its memory ({why}); stopping it", vm.name);
                d.drop_held_in(&vm);
                vm.kill();
            }
            let released = release_source(&source);
            eprintln!("vm {}: pull from {} ended after {} ms (release: {released})", vm.name, source.addr, ms(pulled));
            let _ = vm.released.set(released);
        });
        Ok((json!({"restore_ms": ms(restore), "underlay": self.cfg.underlay.to_string(), "timings_ms": t.json()}), arrived))
    }

    /// SIGTERM/SIGINT: stops every VM and paused or idle Firecracker, then
    /// removes their taps, cgroups and the run directory.
    ///
    /// Waits, logging what for, until starts and migrations in progress have
    /// finished, every VM paused here as a migration source has been released
    /// by its target (killing one earlier loses the pages the target has not
    /// pulled yet), and every source of a VM migrated in here has been told
    /// to drop its copy. A second signal stops the waiting.
    fn shutdown(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.wait_while(|| (self.ops.count() > 0).then(|| format!("{} start(s) or migration(s) in progress", self.ops.count())));
        self.hot.close();
        self.pool.close();
        let sources = || -> Vec<String> {
            self.vms
                .lock()
                .unwrap()
                .values()
                .filter_map(|v| match v.state() {
                    State::Source(mig) => Some(format!("{} (migration {mig})", v.name)),
                    _ => None,
                })
                .collect()
        };
        self.wait_while(|| {
            let s = sources();
            (!s.is_empty()).then(|| format!("migration targets to release {}", s.join(", ")))
        });
        self.wait_while(|| (self.ops.count() > 0).then(|| "release replies".to_string()));
        let left = sources();
        if !left.is_empty() {
            eprintln!(
                "shutdown: killing {} anyway: their targets lose every page they have not pulled yet",
                left.join(", ")
            );
        }
        let vms: Vec<Arc<Vm>> = self.vms.lock().unwrap().drain().map(|(_, vm)| vm).collect();
        for vm in vms {
            self.drop_held_in(&vm);
            vm.kill();
            self.addrs.lock().unwrap().used.remove(&vm.ip);
        }
        // Killing a VM still pulling its memory ends its pull; its source must hear of it.
        self.wait_while(|| {
            (self.releases.count() > 0).then(|| format!("{} migration source(s) to drop their copies", self.releases.count()))
        });
        if self.releases.count() > 0 {
            eprintln!("shutdown: {} migration source(s) were not told to drop their copies; they stay paused", self.releases.count());
        }
        // Anything a request was still starting when we got here.
        if let Some(root) = &self.cgroup_root {
            let _ = std::fs::write(root.join("cgroup.kill"), "1");
            for e in std::fs::read_dir(root).into_iter().flatten().flatten() {
                if e.path().is_dir() {
                    let _ = crate::util::retry(Duration::from_secs(2), || Ok(std::fs::remove_dir(e.path())?));
                }
            }
            let _ = std::fs::remove_dir(root);
        }
        net::delete_taps_with_prefix(&self.tap_prefix);
        // The run directory only; the state directory (suspended VMs, lent
        // addresses) outlives us.
        let _ = std::fs::remove_dir_all(&self.cfg.run_dir);
    }

    /// Polls `what` until it returns None (nothing left to wait for) or a
    /// second signal forces shutdown, logging what it waits for every 5 s.
    fn wait_while(&self, what: impl Fn() -> Option<String>) {
        let mut logged: Option<Instant> = None;
        while let Some(why) = what() {
            if self.force.load(Ordering::SeqCst) {
                return;
            }
            if logged.is_none_or(|t| t.elapsed() >= Duration::from_secs(5)) {
                eprintln!("shutdown: waiting for {why} (signal again to stop waiting)");
                logged = Some(Instant::now());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Counts a start or migration in, unless the daemon is shutting down.
    fn admit(&self) -> Result<CountGuard<'_>> {
        let op = self.ops.enter();
        if self.closing.load(Ordering::SeqCst) {
            bail!("daemon is shutting down");
        }
        Ok(op)
    }

    /// Registers a VM under its reserved name, unless shutdown began meanwhile.
    fn publish(&self, name: &str, vm: &Arc<Vm>) -> Result<()> {
        let mut vms = self.vms.lock().unwrap();
        if self.closing.load(Ordering::SeqCst) {
            bail!("daemon is shutting down");
        }
        vms.insert(name.into(), vm.clone());
        Ok(())
    }

    /// One pass of the elastic memory controller.
    fn control_tick(self: &Arc<Self>) {
        let vms: Vec<Arc<Vm>> = self.vms.lock().unwrap().values().cloned().collect();
        let mut host_avail = host_available_mib();
        if host_avail < self.cfg.reserve_mib {
            // Paused VMs are the cheapest memory to give back.
            self.hot.shed();
            host_avail = host_available_mib();
        }
        for vm in &vms {
            // Never alongside a lifecycle operation on the VM; paused and
            // suspended VMs have no fresh statistics and are left alone.
            let Ok(_busy) = self.reserve(&vm.name, "resizing", Duration::ZERO) else { continue };
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
///
/// An obligation: the source stays paused (and a shutting-down source waits)
/// until it hears this, so it is retried with backoff for as long as it
/// takes, through partitions and our own shutdown, until the source answers.
/// Only an answer ends it; an error answer (the source no longer has that
/// migration's copy) is final too.
fn release_source(source: &Source) -> Value {
    let req = json!({"op": "release", "name": source.vm, "mig": source.mig});
    let mut delay = Duration::from_millis(50);
    for attempt in 1u64.. {
        match peer_request(&source.addr, &req) {
            Ok(reply) if reply["ok"] == json!(true) => return json!(true),
            Ok(reply) => return reply["error"].clone(),
            Err(e) => {
                if attempt == 1 || attempt % 20 == 0 {
                    eprintln!("vm {}: cannot tell {} to release it yet (attempt {attempt}): {e}", source.vm, source.addr);
                }
                thread::sleep(delay);
            }
        }
        delay = (delay * 2).min(Duration::from_secs(30));
    }
    unreachable!()
}

/// A random id for a new migration (53 bits, so it survives any JSON parser).
fn migration_id() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    h.finish() >> 11
}

fn info_ips(info: &Value) -> impl Iterator<Item = Ipv4Addr> + '_ {
    info["ips"].as_array().into_iter().flatten().filter_map(|v| v.as_str()?.parse().ok())
}

fn peer_info(peer: &str) -> Result<Value> {
    peer_call(peer, json!({"op": "info"}))
}

fn peer_call(peer: &str, req: Value) -> Result<Value> {
    let reply = peer_request(peer, &req)?;
    if reply["ok"] != json!(true) {
        bail!("{}", reply["error"]);
    }
    Ok(reply["result"].clone())
}

/// Sends `req` to a peer and returns its whole reply, `ok` or not. Errors
/// only when there is no reply.
fn peer_request(peer: &str, req: &Value) -> Result<Value> {
    let mut c = TcpStream::connect_timeout(&peer.parse()?, Duration::from_millis(500))?;
    c.set_read_timeout(Some(Duration::from_secs(2)))?;
    send_json(&mut c, req)?;
    Ok(recv_json(&mut BufReader::new(c))?.ok_or("peer hung up")?)
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

/// Blocks SIGTERM and SIGINT in this thread (and the threads it starts).
fn block_shutdown_signals() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    }
}

fn wait_for_signal(set: &libc::sigset_t) -> i32 {
    let mut sig = 0;
    while unsafe { libc::sigwait(set, &mut sig) } != 0 {}
    sig
}

/// A count of things in progress that shutdown waits for.
#[derive(Default)]
struct Counter(Mutex<usize>);

impl Counter {
    fn enter(&self) -> CountGuard<'_> {
        *self.0.lock().unwrap() += 1;
        CountGuard(self)
    }

    fn count(&self) -> usize {
        *self.0.lock().unwrap()
    }
}

struct CountGuard<'a>(&'a Counter);

impl Drop for CountGuard<'_> {
    fn drop(&mut self) {
        *self.0 .0.lock().unwrap() -= 1;
    }
}

/// Where a daemon keeps the addresses it has lent out, in its state directory.
const LENT_FILE: &str = "lent-ips.json";

/// The addresses this host is responsible for. One lock covers both sets, so
/// handing one out and moving one between them are atomic.
struct Addrs {
    /// Held by VMs here, including ones starting or migrating in.
    used: HashSet<Ipv4Addr>,
    /// From our range, gone with a VM that migrated away. Never handed out
    /// again until that VM is withdrawn (killed) wherever it is, an operator
    /// frees it (`unlend`), or it migrates back. A lost or late message can
    /// only keep one taken for too long, never free one in use. Persisted.
    lent: HashSet<Ipv4Addr>,
    file: PathBuf,
}

impl Addrs {
    fn load(file: PathBuf) -> Result<Addrs> {
        let lent = match std::fs::read(&file) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
            Err(e) => bail!("{}: {e}", file.display()),
        };
        Ok(Addrs { used: HashSet::new(), lent, file })
    }

    /// Records `ip` as lent, durably, or fails (and records nothing).
    fn lend(&mut self, ip: Ipv4Addr) -> Result<()> {
        if !self.lent.insert(ip) {
            return Ok(());
        }
        if let Err(e) = self.save() {
            self.lent.remove(&ip);
            bail!("cannot record {ip} as lent in {}: {e}", self.file.display());
        }
        Ok(())
    }

    /// A VM with `ip` left for another host; `ours` if `ip` is from our range
    /// (then `migrate` has lent it already).
    fn move_out(&mut self, ip: Ipv4Addr, ours: bool) {
        self.used.remove(&ip);
        if ours && self.lent.insert(ip) {
            if let Err(e) = self.save() {
                eprintln!("cannot record lent addresses in {}: {e}", self.file.display());
            }
        }
    }

    /// Frees a lent address. If that cannot be recorded, a restart only
    /// keeps it taken for longer.
    fn unlend(&mut self, ip: Ipv4Addr) -> bool {
        let freed = self.lent.remove(&ip);
        if freed {
            if let Err(e) = self.save() {
                eprintln!("cannot record lent addresses in {}: {e}", self.file.display());
            }
        }
        freed
    }

    /// Writes the lent set atomically and durably.
    fn save(&self) -> std::io::Result<()> {
        let tmp = self.file.with_extension("tmp");
        let res = (|| -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&serde_json::to_vec(&self.lent)?)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.file)?;
            std::fs::File::open(self.file.parent().unwrap_or(Path::new(".")))?.sync_all()
        })();
        res
    }
}

/// Who wants a given address (`Daemon::claim_given_ip`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimFor {
    Run,
    Restore,
    Incoming,
}

/// An address reserved for a VM being started or migrated in. Unless
/// committed, dropping it puts the address back as it was.
struct IpClaim<'a> {
    addrs: &'a Mutex<Addrs>,
    ip: Ipv4Addr,
    was_lent: bool,
    done: bool,
}

impl IpClaim<'_> {
    fn commit(mut self) {
        self.done = true;
        if self.was_lent {
            self.addrs.lock().unwrap().unlend(self.ip);
        }
    }
}

impl Drop for IpClaim<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.addrs.lock().unwrap().used.remove(&self.ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lent_addresses_persist_and_claims_roll_back() {
        let dir = std::env::temp_dir().join(format!("flexvm-addrs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(LENT_FILE);
        let (a, b): (Ipv4Addr, Ipv4Addr) = ("10.0.0.2".parse().unwrap(), "10.0.0.3".parse().unwrap());
        let addrs = Mutex::new(Addrs::load(file.clone()).unwrap());
        addrs.lock().unwrap().used.insert(a);
        addrs.lock().unwrap().move_out(a, true);
        // Survives a restart.
        let addrs = Mutex::new(Addrs::load(file.clone()).unwrap());
        assert!(addrs.lock().unwrap().lent.contains(&a) && addrs.lock().unwrap().used.is_empty());
        // A failed return migration leaves it lent.
        addrs.lock().unwrap().used.insert(a);
        drop(IpClaim { addrs: &addrs, ip: a, was_lent: true, done: false });
        assert!(addrs.lock().unwrap().lent.contains(&a) && !addrs.lock().unwrap().used.contains(&a));
        // A committed one takes it back.
        addrs.lock().unwrap().used.insert(a);
        IpClaim { addrs: &addrs, ip: a, was_lent: true, done: false }.commit();
        assert!(!addrs.lock().unwrap().lent.contains(&a) && addrs.lock().unwrap().used.contains(&a));
        assert!(Addrs::load(file.clone()).unwrap().lent.is_empty());
        // Not from our range: never lent.
        addrs.lock().unwrap().move_out(b, false);
        assert!(!addrs.lock().unwrap().lent.contains(&b));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
