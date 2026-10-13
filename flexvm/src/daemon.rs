//! The per-host daemon: owns VMs, serves their memory to migration targets,
//! and runs the elastic memory controller.
//!
//! Every connection starts with one JSON request line. Most ops answer with
//! one JSON line; `exec` then streams guest frames, `pages` switches to the
//! binary page protocol, and `migrate_in` answers twice (prepared, then
//! loaded) around a header line, the vmstate and preloaded pages, then takes
//! the held packets. Hosts of a cluster run the same version.

use std::collections::{HashMap, HashSet, VecDeque};
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

/// All supported test faults (including lifecycle hooks).
/// Longest a release of held packets into a VM here waits for those still on
/// their way (after an aborted migration); a checkpoint's is shorter.
const RELEASE_LOCAL: Duration = Duration::from_millis(100);

const FAULTS: &[&str] = &[
    "pages", "route", "lost_ack", "status", "prepare_fail", "short_incoming", "slow_preload",
    "restore_no_hold", "restore_before_run", "restore_after_run", "ckpt_memhash", "ckpt_fail_protect",
    "ckpt_no_hold", "ckpt_abort", "ckpt_slow", "ckpt_crawl", "ckpt_fail_write", "ckpt_copy_wait", "resume_kill", "kill_prepared",
    "guest_drop", "guest_lose_reply", "hot_low_estimate", "started_fsync", "started_unmark",
];

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
/// Largest vmstate a migration target accepts.
const MAX_VMSTATE: u64 = 64 << 20;
/// Most pages a migration source may send along with the vmstate.
const MAX_PRELOAD: usize = 4096;
/// Largest header (page states) a migration source may send.
const MAX_HEADER: u64 = 256 << 20;
/// How long a migration source waits for the target's answer to the prepare request.
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a checkpoint waits for virtio-mem to carry out the last resize.
const SETTLE_WAIT: Duration = Duration::from_secs(10);

/// A VM suspended to a checkpoint under `state_dir/suspended`.
struct Suspended {
    dir: PathBuf,
    manifest: Manifest,
    /// Why it cannot be resumed: a resume failed to mark its checkpoint
    /// STARTED and could not durably take the mark back either, so the
    /// checkpoint may or may not come back after a crash. It never ran
    /// from it; `kill` discards it, and a daemon restart goes by what the
    /// disk holds (STARTED: deleted, else suspended again).
    quarantine: Option<String>,
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
    /// Host memory admission for VM growth (see `Admission`).
    admission: Admission,
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
/// unix socket, gone when the daemon is (see `LOCK_WAIT`).
fn lock_port(port: u16) -> Result<std::os::unix::net::UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(format!("flexvm-port-{port}"))?;
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match std::os::unix::net::UnixListener::bind_addr(&addr) {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            r => return r.map_err(|e| format!("port {port} is taken by another flexvm daemon in this network namespace ({e})").into()),
        }
    }
}

/// How long startup waits for a predecessor's locks. A daemon killed with
/// SIGKILL looks dead (its main thread a zombie) while its last thread still
/// closes its files, which takes a while when one of them is its hold device
/// (the kernel unregisters the interface); a restart must not fail on that.
/// A daemon that is alive keeps its locks, and startup fails after this.
const LOCK_WAIT: Duration = Duration::from_secs(3);

/// How a migration ended on its target, as seen by the source.
enum Outcome {
    Committed(Value),
    Aborted,
}

pub fn run(mut cfg: Config) -> Result<()> {
    // Before any thread starts, so they all inherit the mask and only `signals` sees them.
    let signals = block_shutdown_signals();
    std::fs::create_dir_all(&cfg.run_dir)?;
    // Firecrackers' sockets go in a root named after the canonical
    // directory, which is what `kill_orphans` looks for.
    cfg.run_dir = cfg.run_dir.canonicalize()?;
    let mut run_lock = lock_run_dir(&cfg.run_dir)?;
    // The state dir is this daemon's alone too (another daemon's startup
    // would clear its trees), and must survive a power loss.
    crate::util::create_private_dir_durably(&cfg.state_dir.join("suspended"))
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
    let sockets = crate::socket::SocketRoot::new(&cfg.run_dir)?;
    let pool = Pool::new(&cfg.paths.firecracker, &cfg.run_dir, sockets, cgroup_root.clone(), &tap_prefix, cfg.pool);
    let hot = HotPool::new(pool.clone(), cfg.hot, cfg.hot_mib, cfg.reserve_mib);
    let cfg_reserve_mib = cfg.reserve_mib;
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
        admission: Admission::new(cfg_reserve_mib),
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
    let mut backoff = Duration::ZERO;
    for conn in listener.incoming() {
        let conn = match conn {
            Ok(conn) => {
                backoff = Duration::ZERO;
                conn
            }
            Err(e) => {
                // A client gone before accept, or a signal, says nothing about resources.
                if !matches!(e.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::ConnectionAborted) {
                    if backoff.is_zero() {
                        eprintln!("daemon accept failed: {e}; backing off");
                    }
                    thread::sleep(accept_delay(&mut backoff));
                }
                continue;
            }
        };
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

/// Delay consecutive accept failures without spinning under resource pressure.
fn accept_delay(backoff: &mut Duration) -> Duration {
    *backoff = if backoff.is_zero() {
        Duration::from_millis(10)
    } else {
        (*backoff * 2).min(Duration::from_secs(1))
    };
    *backoff
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
        let deadline = Instant::now() + LOCK_WAIT;
        while unsafe { libc::flock(f.as_raw_fd(), how | libc::LOCK_NB) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EWOULDBLOCK) || Instant::now() >= deadline {
                bail!("run directory {} overlaps another daemon's ({} is locked: {e})", dir.display(), d.display());
            }
            thread::sleep(Duration::from_millis(50));
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
    // Sockets live outside the run directory, in roots named after it.
    let roots = crate::socket::roots(&run_dir);
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
        let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        Ok(dir.starts_with(&run_dir) || roots.iter().any(|r| dir.starts_with(r)))
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
    crate::socket::remove(&run_dir);
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
    let setup = || -> Result<PathBuf> {
        // Not a cgroup2 root (cgroup v1's tmpfs would take the writes below
        // as plain files), or none at all (`ip netns exec`'s fresh sysfs).
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            bail!("no cgroup2 hierarchy mounted at /sys/fs/cgroup");
        }
        let root = PathBuf::from("/sys/fs/cgroup/flexvm");
        std::fs::create_dir_all(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
        std::fs::write(root.join("cgroup.subtree_control"), "+cpu +memory")
            .map_err(|e| format!("enable cpu/memory controllers in {}: {e}", root.display()))?;
        // Daemons in different network namespaces may share a listen address,
        // and must not share a cgroup (shutdown kills everything in it).
        let netns = std::fs::read_link("/proc/self/ns/net").map_err(|e| format!("read network namespace: {e}"))?;
        let netns: String = netns.to_string_lossy().chars().filter(char::is_ascii_digit).collect();
        let base = listen.replace([':', '.', '[', ']'], "_");
        let mine = root.join(format!("{base}_ns{netns}"));
        prune_cgroups(&root, &base, &mine);
        std::fs::create_dir_all(&mine).map_err(|e| format!("create {}: {e}", mine.display()))?;
        // Drop leftovers from a previous run; rmdir only succeeds on empty cgroups.
        for e in std::fs::read_dir(&mine).map_err(|e| format!("read {}: {e}", mine.display()))?.flatten() {
            if e.path().is_dir() {
                let _ = std::fs::remove_dir(e.path());
            }
        }
        std::fs::write(mine.join("cgroup.subtree_control"), "+cpu +memory")
            .map_err(|e| format!("enable cpu/memory controllers in {}: {e}", mine.display()))?;
        Ok(mine)
    };
    match setup() {
        Ok(root) => Some(root),
        Err(e) => {
            eprintln!("WARNING: per-VM cgroups unavailable: {e}; CPU/memory isolation and cgroup.kill on shutdown are disabled");
            None
        }
    }
}

impl Daemon {
    /// The current generation of template `name`. One readlink per call, so a
    /// republished template is picked up by the next VM; VMs already running
    /// keep theirs.
    fn template(&self, name: &str) -> Result<Arc<Template>> {
        let dir = Template::resolve(&self.cfg.paths, name)?;
        let tpl = self.template_at(name, dir)?;
        self.hot.warm(&tpl, self.fault("hot_low_estimate"));
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
    /// its content id, even if `name` has moved on since. Runs before the
    /// source pauses, so it may rehash changed files.
    fn migration_template(&self, req: &Value) -> Result<Arc<Template>> {
        let name = req["template"].as_str().ok_or("missing template")?;
        let id = req["id"].as_str().unwrap_or("");
        let tpl = match Template::generation(&self.cfg.paths, id) {
            Some(dir) => self.template_at(name, dir)?,
            None => self.template(name)?,
        };
        tpl.check_id(req["id"].as_str().ok_or("missing template id")?)?;
        tpl.verify(&self.cfg.paths, true)?;
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
        // The hot pool refills only once this run has answered (dropped
        // after the reply is sent), so its load does not slow the START.
        let _starting = (op == "run").then(|| self.hot.starting());
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
            "migrate_in" => return self.migrate_in(&req, r, w),
            "logs" => return self.logs(&name, &req, w),
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
            // Test hook: set a VM's hotplug size directly, as the controller would.
            "hotplug" if self.faults.is_some() => self.reserve(&name, "resizing", Duration::from_secs(2)).and_then(|_busy| {
                let vm = self.vm(&name)?;
                let mib = req["mib"].as_u64().ok_or("missing mib")?;
                *vm.last_resize.lock().unwrap() = Instant::now();
                if vm.state() != State::Running {
                    bail!("vm {name} is not running here");
                }
                vm.fc(|fc| fc.patch("/hotplug/memory", json!({"requested_size_mib": mib})))
            }),
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

    /// Serves the guest's memory requests in the background, once per VM.
    /// Starts and migrations call it as the VM arrives; the controller's
    /// tick catches every other way in (restores, resumes).
    fn watch_memory(self: &Arc<Self>, vm: &Arc<Vm>) {
        if vm.mem_watched.swap(true, Ordering::SeqCst) {
            return;
        }
        let (d, vm) = (self.clone(), vm.clone());
        thread::spawn(move || serve_mem_requests(d, vm));
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
        let kill = self.fault("resume_kill");
        let resumed = hot.map(|paused| paused.resume(name, ip, kill, &mut t));
        let load = if kill { crate::vm::Load::RunningKilled } else { crate::vm::Load::Running };
        let vmstate = tpl.vmstate();
        let cold = |t: &mut Phases| {
            Vm::restore(&self.pool, name, tpl.clone(), crate::vm::Snapshot::Path(&vmstate), None, ip, load, t).map(|(vm, _)| vm)
        };
        let restored = match resumed {
            Some(Ok(vm)) => Ok(vm),
            // The guest may have run (say, the resume timed out): never a second copy.
            Some(Err((e, true))) => Err(format!("resuming a paused vm from the hot pool failed, and it may have run: {e}").into()),
            // Not resumed (or refused): it never ran for `name`, so load a fresh one.
            Some(Err((e, false))) => {
                eprintln!("vm {name}: cannot resume a paused vm from the hot pool ({e}); loading the snapshot");
                cold(&mut t)
            }
            None => cold(&mut t),
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
        self.watch_memory(&vm);
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
    /// fails), `lost_ack` (incoming migrations get no reply), `status`
    /// (migration status queries fail), `prepare_fail` (an incoming migration
    /// fails once everything is prepared), `short_incoming` (a prepared
    /// incoming migration waits 2 s for the source, not 30),
    /// `slow_preload` (a migration source sends the preloaded pages 300 ms
    /// after the vmstate), `kill_prepared` (an incoming migration's
    /// prepared Firecracker dies, and its pager sees it, just before the load), `resume_kill` (Firecracker
    /// is killed right after a restored VM's resume is sent), `started_fsync`
    /// (a suspended VM's resume creates its STARTED marker but fails to make
    /// it durable), `started_unmark` (taking that marker back then fails
    /// at the directory fsync), `guest_drop`
    /// (the daemon's retried guest requests are refused before reaching the
    /// guest) or `guest_lose_reply` (they are carried out but their replies
    /// lost); those two for `ms` from the first request they hit.
    fn inject(&self, req: &Value) -> Result<Value> {
        let Some(faults) = &self.faults else { bail!("fault injection is off (start the daemon with FLEXVM_FAULTS=1)") };
        let fault = req["fault"].as_str().ok_or("missing fault")?;
        if !FAULTS.contains(&fault) {
            bail!("unknown fault {fault:?}; known faults: {}", FAULTS.join(", "));
        }
        let ms = Duration::from_millis(req["ms"].as_u64().unwrap_or(1000));
        match fault {
            "guest_drop" => *guest::FAULT.lock().unwrap() = Some((guest::Fault::Refuse, ms, None)),
            "guest_lose_reply" => *guest::FAULT.lock().unwrap() = Some((guest::Fault::LoseReply, ms, None)),
            _ => {}
        }
        let until = Instant::now() + ms;
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
                let copied = (|| -> Result<()> {
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
            "loads": crate::vm::loads(),
            "guest_retries": guest::retries(),
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
    /// Everything that does not need the vmstate happens before the pause:
    /// the target checks the template, reserves the name and address, and
    /// sets up a pooled Firecracker with its pager (`migrate_in`), over the
    /// connection that then carries the state. The downtime is the
    /// checkpoint, the transfer and the target's snapshot load.
    ///
    /// Once the target may have the state it may resume the VM, so from then
    /// on this copy is resumed only if the target says migration `mig`
    /// aborted, and never once it committed.
    fn migrate(self: &Arc<Self>, name: &str, to: &str) -> Result<Value> {
        let _op = self.admit()?;
        let _busy = self.reserve(name, "migrating", LIFECYCLE_WAIT)?;
        let vm = self.vm(name)?;
        // Before pausing, so a template mismatch costs no downtime.
        vm.template.verify(&self.cfg.paths, true)?;
        // Before the pause (not part of the downtime): no virtio-mem resize may
        // still be under way.
        let settle = Instant::now();
        vm.settle_hotplug(settle + SETTLE_WAIT)?;
        let settle = settle.elapsed();
        let mig = migration_id();
        let prep = Instant::now();
        let (mut conn, mut reader, prepared) = self.prepare_target(&vm, to, mig)?;
        let prepare = prep.elapsed();
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
        // While the VM still runs, so it is not part of the pause.
        if let Err(e) = vm.park_balloon() {
            return Err(self.abort_migration(&vm, mig, e));
        }
        let mut t = Phases::new();
        let vmstate = vm.dir.join("vmstate.out");
        // Packets for the VM wait here until it runs again.
        let hold = || {
            if let Some(Err(e)) = self.holder.as_ref().map(|h| h.hold(vm.ip, mig)) {
                eprintln!("vm {name}: not holding packets during migration: {e}");
            }
        };
        let captured = (|| -> Result<_> {
            let runs = vm.checkpoint(&vmstate, hold, &mut t)?;
            let paused = t.total();
            let state = std::fs::read(&vmstate)?;
            t.mark("read_state");
            // The pages the target's load will touch, so it need not fetch
            // them one round trip at a time (see `Template::load_set`).
            let mut wanted = vm.template.load_set();
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
            Err(e) => return Err(self.abort_migration(&vm, mig, e)),
        };
        let remote_pages: u64 = runs.iter().filter(|r| r.2 == crate::uffd::REMOTE).map(|r| r.1).sum();
        let sent = (|| -> Result<Value> {
            send_json(
                &mut conn,
                &json!({
                    "runs": runs,
                    "vmstate_len": state.len(),
                    "preload": pages,
                    // A paused VM stays paused on the target, which pulls its pages before it ever runs.
                    "paused": vm.was_paused(),
                }),
            )?;
            conn.write_all(&state)?;
            if self.fault("slow_preload") {
                thread::sleep(Duration::from_millis(300));
            }
            conn.write_all(&data)?;
            t.mark("send_state");
            Ok(recv_json(&mut reader)?.ok_or("target hung up")?)
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

    /// Asks `to` to get ready to take `vm` in as migration `mig` (see
    /// `migrate_in`). Returns the connection to send the state over, a reader
    /// for the target's answer, and what it said. A target that cannot take
    /// the VM refuses here, before anything happened to it.
    fn prepare_target(&self, vm: &Vm, to: &str, mig: u64) -> Result<(TcpStream, BufReader<TcpStream>, Value)> {
        let conn = crate::util::connect(to, Duration::from_secs(2))?;
        conn.set_nodelay(true)?;
        conn.set_read_timeout(Some(PREFLIGHT_TIMEOUT))?;
        conn.set_write_timeout(Some(PREFLIGHT_TIMEOUT))?;
        let mut reader = BufReader::new(conn.try_clone()?);
        let mut w = &conn;
        send_json(
            &mut w,
            &json!({
                "op": "migrate_in",
                "name": vm.name,
                "mig": mig,
                "template": vm.template.name,
                "id": vm.template.meta.id,
                "ip": vm.ip.to_string(),
                "source": self.cfg.advertise,
                "regions": vm.pager.regions(),
            }),
        )?;
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
            self.release_into(h, vm.ip, mig, vm, RELEASE_LOCAL, |()| net::attach(vm.ip, &vm.tap));
        }
        let (s, e) = match vm.resume() {
            Ok(s) => (s, e),
            Err(r) => (State::Failed, format!("{e}; resuming it here failed too: {r}").into()),
        };
        // Still held only if the route could not be switched back above
        // (`resume` routes it again): never leave it on the hold device.
        if let Some(h) = &self.holder {
            h.forget(vm.ip, mig);
        }
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
            let held = self.holder.as_ref().and_then(|h| self.release_into(h, ip, mig, &newer, RELEASE_LOCAL, Ok));
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

    /// Injects what migration (or checkpoint) `mig` held for `ip` into `vm`'s
    /// tap (brought up for it), calls `switch`, and injects what was still on
    /// its way, waiting at most `within` (see `Holder::release_local`). If
    /// the switch fails, that is logged and the address stays held until
    /// the caller `forget`s it.
    fn release_into(
        &self,
        h: &Holder,
        ip: Ipv4Addr,
        mig: u64,
        vm: &Vm,
        within: Duration,
        switch: impl FnOnce(()) -> Result<()>,
    ) -> Option<hold::Stats> {
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
        let (mut stats, switched) = h.release_local(ip, mig, &mut |p| hold::valid(p, ip) && inj.send(p), || switch(()), within)?;
        if let Err(e) = switched {
            eprintln!("vm {}: routing {ip} back to its tap after injecting the held packets: {e}", vm.name);
        }
        stats.injected = stats.packets;
        stats.dropped_target = inj.dropped();
        // Closing a packet socket waits for an RCU grace period (tens of ms
        // on a busy host), which the VM, still paused, need not wait for.
        thread::spawn(move || drop(inj));
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

    /// The target of `migrate`, in two steps on one connection. First, before
    /// the source pauses: check the template, reserve the name and address,
    /// and set up a pooled Firecracker with its pager; answer whether the VM
    /// can come. Then the source pauses and sends the page states, the
    /// vmstate and the pages the load will touch; load it and answer again.
    /// A source that goes away in between leaves nothing behind.
    fn migrate_in(self: &Arc<Self>, req: &Value, mut r: BufReader<TcpStream>, mut w: TcpStream) -> Result<()> {
        let mut prep = Phases::new();
        let prepared = self.admit().and_then(|op| Ok((op, self.prepare_in(req, &mut prep)?)));
        let (_op, prepared) = match prepared {
            Ok(p) => p,
            Err(e) => return Ok(send_json(&mut w, &json!({"ok": false, "error": e.to_string()}))?),
        };
        // What this host has learned its loads touch, for the source to send along.
        let load_set = prepared.load_set.clone();
        send_json(&mut w, &json!({"ok": true, "result": {"timings_ms": prep.json(), "load_set": load_set}}))?;
        // The vmstate follows once the source has paused. A source that
        // stalls or trickles must not hold the name, the address, the
        // prepared Firecracker and a counted operation (and so shutdown)
        // forever: from here, everything up to our answer (its reads, the
        // load, the checks, writing the answer) is due by one deadline, and
        // the migration aborts if that passes before it commits.
        let wait = if self.fault("short_incoming") { Duration::from_secs(2) } else { INCOMING_READ_TIMEOUT };
        let deadline = Instant::now() + wait;
        let mut br = ByDeadline { r: &mut r, at: deadline };
        let pager = prepared.vm.pager.clone();
        let res = thread::scope(|scope| -> Result<(Value, Arc<Vm>)> {
            let hdr = crate::util::recv_json_max(&mut br, MAX_HEADER)?.ok_or("source hung up before sending the vmstate")?;
            // The source has paused: the downtime here starts now.
            let mut t = Phases::new();
            let runs: Runs = serde_json::from_value(hdr["runs"].clone())?;
            let state = read_vec(&mut br, hdr["vmstate_len"].as_u64().ok_or("missing vmstate_len")?, MAX_VMSTATE)?;
            t.mark("recv_state");
            let pages: Vec<u64> = serde_json::from_value(hdr["preload"].clone()).unwrap_or_default();
            if pages.len() > MAX_PRELOAD {
                bail!("{} pages to preload, more than {MAX_PRELOAD}", pages.len());
            }
            // The pages the load touches follow the vmstate: received and
            // installed while Firecracker parses the state (one missing when
            // the load wants it is fetched like any other). All of them are
            // in, or the migration aborts, before it commits: nothing else
            // reads this connection until our answer.
            let br = &mut br;
            // Received, then installed (Err inside: a retried load's new
            // pager does without them).
            let preload = scope.spawn(move || -> Result<Result<()>> {
                let len = (pages.len() * crate::util::PAGE_SIZE) as u64;
                let data = read_vec(br, len, u64::MAX).map_err(|e| format!("receiving the preloaded pages: {e}"))?;
                Ok(pager.preload(&pages, &data, deadline).map(drop).map_err(|e| format!("preloading pages: {e}").into()))
            });
            let preloaded = move || preload.join().unwrap_or_else(|_| Err("preloading panicked".into()));
            let paused = hdr["paused"].as_bool().unwrap_or(false);
            self.finish_in(prepared, runs, &state, paused, deadline, preloaded, &mut t)
        });
        let (reply, arrived) = match res {
            Ok((v, vm)) => (json!({"ok": true, "result": v}), Some(vm)),
            Err(e) => (json!({"ok": false, "error": e.to_string()}), None),
        };
        // Committed, but the source never hears about it.
        let lost = arrived.is_some() && self.fault("lost_ack");
        let answered = match lost {
            true => w.shutdown(std::net::Shutdown::Both).map_err(Error::from),
            // Every partial write by the deadline; one that misses it leaves
            // a committed migration committed (the source asks).
            false => w.try_clone().map_err(Error::from).and_then(|s| Ok(send_json(&mut crate::util::By { s, at: deadline }, &reply)?)),
        };
        // Only now, on the same buffered reader: the held packets follow the
        // answer. A committed VM is announced even if answering failed.
        if let Some(vm) = arrived {
            self.after_arrival(req, &vm, r, deadline);
        }
        answered
    }

    /// For a VM that arrived as migration `req["mig"]`, once the source has
    /// our answer: takes the packets its source held, which follow it on `r`
    /// (the migration connection, read through the same buffer), then
    /// announces the VM (`announce_after_held`). Nothing of it past `deadline`.
    fn after_arrival(self: &Arc<Self>, req: &Value, vm: &Arc<Vm>, r: BufReader<TcpStream>, deadline: Instant) {
        let Some(mig) = req["mig"].as_u64() else { return };
        let revoked = {
            let mut held = self.held_in.lock().unwrap();
            let right = held.get_mut(&mig).filter(|h| Arc::ptr_eq(&h.vm, vm));
            right.map(|h| {
                h.conn = r.get_ref().try_clone().ok();
                h.revoked.clone()
            })
        };
        self.announce_after_held(mig, vm.clone(), revoked.map(|rv| (r, rv)), deadline);
    }

    /// The part of taking a VM in that needs no vmstate, before the source
    /// pauses.
    fn prepare_in(&self, req: &Value, t: &mut Phases) -> Result<PreparedIn<'_>> {
        let name = req["name"].as_str().ok_or("missing name")?.to_string();
        let mig = req["mig"].as_u64().ok_or("missing mig")?;
        let source = Source {
            addr: req["source"].as_str().ok_or("missing source")?.into(),
            vm: name.clone(),
            mig,
            regions: serde_json::from_value(req["regions"].clone()).map_err(|e| format!("bad regions: {e}"))?,
        };
        if source.regions.is_empty() {
            bail!("the source sent no memory regions");
        }
        let busy = self.reserve(&name, "incoming", Duration::ZERO)?;
        if self.taken(&name) {
            bail!("vm name {name:?} is taken here");
        }
        // Checked again (and recorded) once the state arrives.
        if self.migrations.lock().unwrap().contains_key(&mig) {
            bail!("migration {mig} was already seen here");
        }
        let tpl = self.migration_template(req)?;
        t.mark("template");
        let claim = self.claim_given_ip(req["ip"].as_str().ok_or("missing ip")?, ClaimFor::Incoming)?;
        t.mark("claim_ip");
        let idle = self.pool.take()?;
        t.mark("pool_take");
        let load_set = tpl.load_set();
        let vm = Vm::prepare(idle, &name, tpl, t)?;
        if vm.prepare_load()? {
            t.mark("prepare_load");
        }
        if self.fault("prepare_fail") {
            bail!("injected fault: preparing failed");
        }
        Ok(PreparedIn { vm, claim, source, name, load_set, _busy: busy })
    }

    /// Restores and resumes a prepared incoming VM from the source's state.
    /// Records the outcome for the source: aborted if the VM was killed
    /// before it ever ran here, committed (by `take_in`) before it may run.
    #[allow(clippy::too_many_arguments)]
    fn finish_in(
        self: &Arc<Self>,
        p: PreparedIn<'_>,
        runs: Runs,
        state: &[u8],
        paused: bool,
        deadline: Instant,
        before_commit: impl FnOnce() -> Result<Result<()>>,
        t: &mut Phases,
    ) -> Result<(Value, Arc<Vm>)> {
        let mig = p.source.mig;
        {
            let mut migs = self.migrations.lock().unwrap();
            if migs.contains_key(&mig) {
                bail!("migration {mig} was already seen here");
            }
            migs.insert(mig, Incoming::Pending);
        }
        let res = self.take_in(p, runs, state, paused, deadline, before_commit, t);
        let mut migs = self.migrations.lock().unwrap();
        // Before committing, a failure has killed a VM that never ran, so the
        // source may resume it. Once committed, it stays committed.
        if res.is_err() && migs.get(&mig) == Some(&Incoming::Pending) {
            migs.insert(mig, Incoming::Aborted);
        }
        res
    }

    /// Once a VM that migrated in runs, injects the packets its source held,
    /// which follow our answer on the migration connection, then announces
    /// the VM, so held packets come before traffic sent straight here. If no
    /// stream opens within `HOLD_FENCE` (none held, or the source is slow),
    /// closes the right and announces: a later stream would come after
    /// traffic sent straight here, so its packets are dropped instead.
    fn announce_after_held(
        self: &Arc<Self>,
        mig: u64,
        vm: Arc<Vm>,
        stream: Option<(BufReader<TcpStream>, Arc<Mutex<bool>>)>,
        deadline: Instant,
    ) {
        let d = self.clone();
        thread::spawn(move || {
            if let Some((mut r, revoked)) = stream {
                if hold::wait_start(&mut r, (Instant::now() + HOLD_FENCE).min(deadline)) {
                    hold::receive(&mut r, vm.ip, &vm.tap, &revoked, (Instant::now() + HELD_STREAM).min(deadline));
                }
            }
            d.held_in.lock().unwrap().remove(&mig);
            d.announce(&vm);
        });
    }

    /// Loads the VM held, runs every check that can still abort (the source's
    /// page server, the pager, `before_commit`, `deadline`, registering the
    /// name), commits, then resumes it.
    #[allow(clippy::too_many_arguments)]
    fn take_in(
        self: &Arc<Self>,
        p: PreparedIn<'_>,
        runs: Runs,
        state: &[u8],
        paused: bool,
        deadline: Instant,
        before_commit: impl FnOnce() -> Result<Result<()>>,
        t: &mut Phases,
    ) -> Result<(Value, Arc<Vm>)> {
        let PreparedIn { vm: mut prepared, claim, source, name, _busy, .. } = p;
        let mut before_commit = Some(before_commit);
        let ip = claim.ip;
        // Is the source's page server there? Asked alongside the load, which
        // may not need it (preloaded pages): a VM whose memory cannot come
        // must not be committed here.
        let probe = runs.iter().find(|r| r.2 == crate::uffd::REMOTE).map(|r| {
            let source = source.clone();
            let page = r.0;
            thread::spawn(move || crate::uffd::probe(&source, page, deadline))
        });
        let (tpl, runs_again) = (prepared.template(), runs.clone());
        if self.fault("kill_prepared") {
            // Dead, and its pager has seen it go: the load fails at once, and
            // the retry below takes over.
            prepared.kill_firecracker();
            prepared.pager.firecracker_gone();
        }
        prepared.pager.seed(runs, Origin::Peer(source.clone()))?;
        // A prepared load connected the pager long ago; it may have given up
        // on pages. (One whose Firecracker went is left to the load, which
        // fails and retries on a fresh one.)
        if prepared.pager.lost_pages() {
            bail!("its pager failed: {}", prepared.pager.failed().unwrap_or_default());
        }
        let vmstate = prepared.dir().join("vmstate.in");
        std::fs::write(&vmstate, state)?;
        t.mark("write_state");
        // Loaded with its vCPUs stopped: it must not run here before every
        // check that can still abort the migration has passed (the source
        // would then resume an older state of a VM that ran on).
        let load = if paused { crate::vm::Load::Paused } else { crate::vm::Load::PausedUnheld };
        let restored = match prepared.load(&name, &vmstate, ip, load, true, Some(deadline), t) {
            // Once more on a fresh Firecracker (see `Retry`): the failed load
            // never ran the guest, nothing is committed, and the source,
            // paused, still serves every page. The preloaded pages went to
            // the old pager; the new one fetches them like any other.
            Err(e) if crate::vm::retry_of(&e).is_some() => (|| {
                let realtime = crate::vm::retry_of(&e) != Some(crate::vm::Retry::WithoutRealtime);
                eprintln!("vm {name}: loading it once more on a fresh firecracker{}", if realtime { "" } else { ", without clock_realtime" });
                // Every byte the source sends before our answer is read first.
                let _ = before_commit.take().unwrap()()?;
                if Instant::now() >= deadline {
                    bail!("no time left to load it again");
                }
                let fresh = Vm::prepare(self.pool.take_by(Some(deadline))?, &name, tpl, t)?;
                fresh.pager.seed(runs_again, Origin::Peer(source.clone()))?;
                let vmstate = fresh.dir().join("vmstate.in");
                std::fs::write(&vmstate, state)?;
                fresh.load(&name, &vmstate, ip, load, realtime, Some(deadline), t)
            })(),
            r => r,
        };
        let probed = probe.map_or(Ok(()), |p| p.join().unwrap_or_else(|_| Err(std::io::Error::other("probe panicked"))));
        let (vm, restore) = restored?;
        let checked = match (probed, vm.pager.failed()) {
            (Err(e), _) => Err(format!("migration source {} does not serve pages: {e}", source.addr).into()),
            (_, Some(why)) => Err(format!("its memory cannot be paged in: {why}").into()),
            _ => before_commit.take().map_or(Ok(Ok(())), |f| f()).and_then(|r| r).and_then(|()| {
                // The ownership boundary, in one step under the locks it
                // takes, with the deadline checked under them too: the VM is
                // registered, its address committed, and the migration
                // recorded committed; from here on this host owns the VM and
                // the source never resumes its copy. Or none of it happens.
                // (An aborted claim rolls back, taking the address lock, only
                // once these are released.)
                let mut addrs = self.addrs.lock().unwrap();
                let mut vms = self.vms.lock().unwrap();
                let late = Instant::now() >= deadline;
                let closing = self.closing.load(Ordering::SeqCst);
                if !late && !closing {
                    vms.insert(name.clone(), vm.clone());
                    claim.commit_with(&mut addrs);
                    self.migrations.lock().unwrap().insert(source.mig, Incoming::Committed);
                    return Ok(());
                }
                drop((vms, addrs));
                drop(claim);
                Err(if late { "the migration ran past its deadline" } else { "daemon is shutting down" }.into())
            }),
        };
        if let Err(e) = checked {
            // Never ran here: the source may resume its copy.
            vm.kill();
            return Err(format!("{e} (it never ran here)").into());
        }
        t.mark("register");
        let arrived = vm.clone();
        // While the arrival still holds the name: no kill or migration of
        // this VM can come before it, so none misses it.
        self.held_in.lock().unwrap().insert(source.mig, HeldIn { vm: vm.clone(), revoked: Arc::default(), conn: None });
        let mut resume_error = None;
        if !paused {
            match vm.start(self.fault("resume_kill")) {
                Ok(()) => *vm.state.lock().unwrap() = State::Running,
                Err(e) => {
                    // It may have run: the migration stays committed.
                    eprintln!("vm {name}: resuming after migration {} failed: {e}", source.mig);
                    vm.set_failed();
                    resume_error = Some(e.to_string());
                }
            }
            t.mark("resume");
        }
        // Announced once the packets its source held are in (`after_arrival`).
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
            d.watch_memory(&vm);
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
        let reply = json!({
            "restore_ms": ms(restore),
            "underlay": self.cfg.underlay.to_string(),
            "timings_ms": t.json(),
            "resume_error": resume_error,
        });
        Ok((reply, arrived))
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
        crate::socket::remove(&self.cfg.run_dir);
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

    /// Resizes `vm` unless a lifecycle operation holds it, except that a VM
    /// whose copy-on-write checkpoint is being copied may grow: the copy only
    /// reads the pages it had at the pause, and memory plugged after it was
    /// unplugged then (never populated), so the copy never reads it, and the
    /// checkpoint keeps the plugged size it saved. Paused and suspended VMs
    /// have no fresh statistics and are left alone.
    fn resize_now(&self, vm: &Vm, hint: Option<u64>) -> Result<Resized> {
        if let Ok(_busy) = self.reserve(&vm.name, "resizing", Duration::ZERO) {
            return resize(vm, &self.admission, hint, false);
        }
        self.resize_during_copy(vm, hint)
    }

    /// Grows `vm` if a copy-on-write checkpoint is copying it (its
    /// reservation is held then; see `resize_now`), else answers `Busy`.
    fn resize_during_copy(&self, vm: &Vm, hint: Option<u64>) -> Result<Resized> {
        let copying = vm.cow_copy.lock().unwrap();
        if *copying {
            return resize(vm, &self.admission, hint, true);
        }
        Ok(Resized::Busy)
    }

    /// One pass of the elastic memory controller.
    fn control_tick(self: &Arc<Self>) {
        let vms: Vec<Arc<Vm>> = self.vms.lock().unwrap().values().cloned().collect();
        if host_available_mib() < self.cfg.reserve_mib {
            // Paused VMs are the cheapest memory to give back.
            self.hot.shed();
        }
        for vm in &vms {
            self.watch_memory(vm);
            // Never alongside a lifecycle operation on the VM (other than
            // growing during a checkpoint copy); paused and suspended VMs
            // have no fresh statistics and are left alone.
            let Ok(_busy) = self.reserve(&vm.name, "resizing", Duration::ZERO) else {
                if let Err(e) = self.resize_during_copy(vm, None) {
                    eprintln!("vm {}: resize: {e}", vm.name);
                }
                continue;
            };
            // Free page reports a checkpoint copy held and could not release
            // (under the reservation, so never a newer copy's hold).
            if vm.release_pending() && matches!(vm.state(), State::Running | State::Paused) {
                match vm.release_reports(Duration::from_millis(500)) {
                    Ok(()) => eprintln!("vm {}: released free page reports", vm.name),
                    Err(e) => eprintln!("vm {}: releasing free page reports: {e}", vm.name),
                }
            }
            if vm.state() == State::Running {
                if let Err(e) = resize(vm, &self.admission, None, false) {
                    eprintln!("vm {}: resize: {e}", vm.name);
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

/// Free memory (MiB) the controller keeps plugged for a guest with `total`
/// MiB. The guest agent asks for more as soon as it has less than this, and
/// throttles allocations that outrun the plug (guest/src/mem.rs uses the same mark).
pub fn headroom(total: u64) -> u64 {
    (total / 4).max(1024.min(total / 2))
}

/// What a resize did, answered to the guest when it asked.
#[derive(Debug, PartialEq)]
enum Resized {
    Grew,
    Same,
    /// The guest is still processing the previous request.
    Busy,
    /// Short on memory, and at its ceiling or refused by the host's reserve.
    Full,
}

/// How long a grant counts as used: the guest touches what it asked for
/// gradually, and MemAvailable only shows it once touched.
const GRANT_WINDOW: Duration = Duration::from_secs(10);

/// Admits VM growth against the host's `--reserve`. Plugging costs the host
/// nothing until the guest touches the memory, so MemAvailable lags every
/// grant; recent grants count as used. One lock serializes admission across
/// all VMs, so concurrent requests cannot each see the same free memory.
struct Admission {
    reserve_mib: u64,
    grants: Mutex<VecDeque<(Instant, u64)>>,
}

impl Admission {
    fn new(reserve_mib: u64) -> Admission {
        Admission { reserve_mib, grants: Mutex::new(VecDeque::new()) }
    }

    /// Records a grant of `mib` unless it would take the host below its reserve.
    fn admit(&self, mib: u64) -> bool {
        let mut grants = self.grants.lock().unwrap();
        while grants.front().is_some_and(|(t, _)| t.elapsed() > GRANT_WINDOW) {
            grants.pop_front();
        }
        let pending: u64 = grants.iter().map(|(_, m)| m).sum();
        if host_available_mib() < self.reserve_mib + pending + mib {
            return false;
        }
        grants.push_back((Instant::now(), mib));
        true
    }
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
/// against the host's reserve. A VM that is short and cannot grow here (at
/// its ceiling, or refused) is flagged as starved so the controller moves it
/// somewhere roomier.
fn resize(vm: &Vm, admission: &Admission, hint: Option<u64>, grow_only: bool) -> Result<Resized> {
    let meta = &vm.template.meta;
    let hotplug_total = meta.max_mib - meta.mem_mib;
    if hotplug_total == 0 {
        return Ok(Resized::Full);
    }
    // Callers hold the VM's reservation, so no lifecycle operation (migration,
    // checkpoint, pause) runs meanwhile; only a running VM is resized.
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
    let refused = new > requested && !admission.admit(new - requested);
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
fn read_mem_request(conn: &std::os::unix::net::UnixStream) -> Option<u64> {
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

/// Answers the guest agent's memory requests for `vm` (sent when it runs
/// low) with an immediate resize, until the VM is gone from this host. The
/// guest is untrusted: requests are bounded in size and time, malformed ones
/// dropped, and they are acted on at most once per `MEM_REQUEST_GAP`.
fn serve_mem_requests(d: Arc<Daemon>, vm: Arc<Vm>) {
    let path = vm.mem_sock();
    let _ = std::fs::remove_file(&path);
    let listener = match std::os::unix::net::UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("vm {}: memory requests: {e}", vm.name);
            return;
        }
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
        if !d.vm(&vm.name).is_ok_and(|v| Arc::ptr_eq(&v, &vm)) {
            break; // this copy is gone from here
        }
        acted = Some(Instant::now());
        // Like a controller tick: not alongside a lifecycle operation, other
        // than growing during a checkpoint copy.
        let reply = match d.resize_now(&vm, Some(avail)) {
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

/// Tells a migration source to drop its copy, retrying with backoff (up to
/// 30 s apart) until it answers, however long that takes. Returns true, or
/// the error it answered with.
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

/// An incoming migration set up before its source pauses
/// (`Daemon::prepare_in`). Dropping it gives everything back.
struct PreparedIn<'a> {
    vm: crate::vm::Prepared,
    claim: IpClaim<'a>,
    source: Source,
    name: String,
    /// The template's load set here (`Template::load_set`).
    load_set: Vec<u64>,
    _busy: Busy<'a>,
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

/// A read timeout firing is the deadline passing.
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

/// An address reserved for a VM being started or migrated in. Unless
/// committed, dropping it puts the address back as it was.
struct IpClaim<'a> {
    addrs: &'a Mutex<Addrs>,
    ip: Ipv4Addr,
    was_lent: bool,
    done: bool,
}

impl IpClaim<'_> {
    fn commit(self) {
        let addrs = self.addrs;
        self.commit_with(&mut addrs.lock().unwrap());
    }

    /// `commit`, for a caller holding the address lock.
    fn commit_with(mut self, addrs: &mut Addrs) {
        self.done = true;
        if self.was_lent {
            addrs.unlend(self.ip);
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
    fn backoff_grows_caps_and_resets() {
        let mut backoff = Duration::ZERO;
        for ms in [10, 20, 40, 80, 160, 320, 640, 1000, 1000] {
            assert_eq!(accept_delay(&mut backoff), Duration::from_millis(ms));
        }
        backoff = Duration::ZERO;
        assert_eq!(accept_delay(&mut backoff), Duration::from_millis(10));
    }

    /// Every fault the code checks can be armed (and nothing else can).
    #[test]
    fn fault_list_matches_the_code() {
        let mut used: Vec<&str> = [include_str!("daemon.rs"), include_str!("lifecycle.rs")]
            .iter()
            .flat_map(|src| src.split("self.fault(\"").skip(1).map(|s| s.split('"').next().unwrap()))
            .collect();
        // Guest faults are armed in `inject` itself.
        let inject = include_str!("daemon.rs").split("fn inject(").nth(1).unwrap().split("\n    }\n").next().unwrap();
        let arms: Vec<&str> = inject.split(" => *guest::FAULT").collect();
        used.extend(arms[..arms.len() - 1].iter().filter_map(|s| s.rsplit('"').nth(1)));
        used.sort();
        used.dedup();
        let mut known = FAULTS.to_vec();
        known.sort();
        assert_eq!(used, known);
    }

    #[test]
    fn memory_requests_are_bounded_and_strict() {
        use std::os::unix::net::UnixStream;
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

    #[test]
    fn admission_counts_recent_grants() {
        let free = host_available_mib();
        // Wide margins: other processes move MemAvailable meanwhile.
        let adm = Admission::new(free.saturating_sub(3000));
        assert!(adm.admit(1000));
        assert!(adm.admit(1000));
        assert!(!adm.admit(2000), "recent grants count as used");
        assert!(!Admission::new(free + 1).admit(1));
    }

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
