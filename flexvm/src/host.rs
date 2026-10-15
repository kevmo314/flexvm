//! Host-wide state in files, shared by VM processes and the listener.
//! Acquisitions (names, addresses, migration records) are guards that give
//! back exactly what they took. The host lock (`STATE/lock`) covers only short
//! sections. A VM process holds `RUN/vms/NAME.lock` for life; a dead one
//! counts as gone only once its Firecrackers have exited (`reap`).

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::bail;
use crate::net::IpRange;
use crate::util::{Error, Result};

/// A held grant (`Host::grant_start`): counted while this lives, and not a
/// moment after its process does (the kernel drops the flock). Dropping it
/// removes the file; if that fails, the free lock tells admission it is gone.
pub struct Hold {
    path: PathBuf,
    id: u64,
    mib: u64,
    _file: File,
}

impl Drop for Hold {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Recent admission: boottime, MiB, id, and optionally the VM's usage baseline.
/// Older records have only the first three elements.
#[derive(Debug, Serialize, Deserialize)]
struct Grant(u64, u64, u64, #[serde(default)] Option<GrantOwner>);

#[derive(Debug, Serialize, Deserialize)]
struct GrantOwner {
    ident: Ident,
    cgroup: PathBuf,
    used_mib: Option<u64>,
}

/// Charge only memory not yet reflected in MemAvailable. Work backwards so
/// growth since a newer grant is credited once, before older grants can use it.
fn pending_grants(grants: &[Grant], held_ids: &HashSet<u64>, mut memory: impl FnMut(&Path) -> Option<u64>) -> u64 {
    let mut usage = HashMap::new();
    grants
        .iter()
        .rev()
        .filter(|g| !held_ids.contains(&g.2))
        .map(|g| {
            let Some(owner) = &g.3 else { return g.1 };
            let Some(baseline) = owner.used_mib else { return g.1 };
            let (current, credited) = usage.entry(&owner.ident).or_insert_with(|| (memory(&owner.cgroup), 0u64));
            let Some(current) = *current else { return g.1 };
            let used = g.1.min(current.saturating_sub(baseline).saturating_sub(*credited));
            *credited += used;
            g.1 - used
        })
        .sum()
}

/// What a grant must leave available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Floor {
    Reserve,
    /// The eviction mark (`Config::evict_at`): an arrival moved here by eviction.
    EvictMark,
}

/// `STATE/host.json`, written by `flexvm listen`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listen: Option<String>,
    pub peers: Vec<String>,
    /// Disjoint across hosts.
    pub vm_ips: String,
    /// Default: the listen address's.
    pub underlay: Option<Ipv4Addr>,
    pub announce_dev: Option<String>,
    pub dns: Option<String>,
    pub reserve_mib: u64,
    /// Eviction's high-water mark (MiB available): below it VMs start moving
    /// to peers (`evict_at`). None: the reserve plus the reserve or 512 MiB, whichever is more.
    pub evict_mib: Option<u64>,
    /// Of taps, hold devices and cgroups.
    pub prefix: String,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            listen: None,
            peers: Vec::new(),
            vm_ips: "10.200.0.0/16".into(),
            underlay: None,
            announce_dev: None,
            dns: None,
            reserve_mib: 1024,
            evict_mib: None,
            prefix: "fv".into(),
        }
    }
}

impl Config {
    /// MemAvailable (MiB) under which eviction starts: never below the reserve.
    pub fn evict_at(&self) -> u64 {
        self.evict_mib.unwrap_or(self.reserve_mib + self.reserve_mib.max(512)).max(self.reserve_mib)
    }

    /// Once started, eviction goes on until MemAvailable is back this high:
    /// the mark plus half its height above the reserve (at least 128 MiB).
    pub fn evict_until(&self) -> u64 {
        let at = self.evict_at();
        at + ((at - self.reserve_mib) / 2).max(128)
    }

    pub fn range(&self) -> Result<IpRange> {
        IpRange::parse(&self.vm_ips)
    }

    /// Never a wildcard address.
    pub fn underlay(&self) -> Option<Ipv4Addr> {
        let from_listen = || match self.listen.as_deref()?.parse::<SocketAddr>().ok()?.ip().to_canonical() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        };
        self.underlay.or_else(from_listen).filter(|u| !u.is_unspecified())
    }

    /// Where peers reach this host's listener (a migration target pulls
    /// pages from it): the listen address, or for a wildcard one (0.0.0.0,
    /// ::, ::ffff:0.0.0.0) or an IPv6 link-local one (its scope id means
    /// nothing elsewhere) the underlay address with the listen port. None
    /// without a listener.
    pub fn advertise(&self) -> Result<Option<String>> {
        let Some(listen) = self.listen.as_deref() else { return Ok(None) };
        let Ok(addr) = listen.parse::<SocketAddr>() else { return Ok(Some(listen.into())) };
        if addr.port() == 0 {
            bail!("listening on {listen}: give a port; peers are told it");
        }
        let ip = addr.ip().to_canonical();
        let local_only = match ip {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified() || v6.is_unicast_link_local(),
        };
        if !local_only {
            return Ok(Some(SocketAddr::new(ip, addr.port()).to_string()));
        }
        match self.underlay() {
            Some(u) => Ok(Some(SocketAddr::from((u, addr.port())).to_string())),
            None => bail!("listening on {listen} needs --underlay: peers cannot reach a wildcard or link-local address"),
        }
    }
}

/// HOST:PORT, an IPv6 address in brackets; a name is resolved only when used.
pub fn is_endpoint(s: &str) -> bool {
    let Some((h, port)) = s.rsplit_once(':') else { return false };
    let host = match h.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<std::net::Ipv6Addr>().is_ok(),
        None => !h.is_empty() && !h.contains([':', '[', ']', '/', ' ']),
    };
    host && port.parse::<u16>().is_ok_and(|p| p > 0)
}

/// Unreadable or corrupt is an error, never None.
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => bail!("{}: {e}", path.display()),
    }
}

/// Who a name lock says holds it: None for an empty lock (created, never
/// written: no VM started under it); unreadable or corrupt is an error.
fn lock_holder(path: &Path) -> Result<Option<Ident>> {
    match std::fs::read(path) {
        Ok(b) if b.is_empty() => Ok(None),
        Ok(b) => Ok(Some(serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => bail!("{}: {e}", path.display()),
    }
}

pub fn store<T: Serialize>(path: &Path, v: &T, durable: bool) -> Result<()> {
    let (dir, name) = (path.parent().ok_or("no directory")?, path.file_name().ok_or("no name")?);
    crate::util::write_file(dir, &name.to_string_lossy(), &serde_json::to_vec(v)?, durable).map_err(|e| format!("{}: {e}", path.display()).into())
}

#[derive(Clone)]
pub struct Host {
    pub state: PathBuf,
    pub run: PathBuf,
    /// As loaded; `config_now` reads host.json again once it changed.
    pub cfg: Config,
    /// host.json's mtime and inode when `cfg` was loaded.
    cfg_stamp: Option<Stamp>,
    /// Last good reload, shared by this Host's clones, never by unrelated Hosts.
    cfg_seen: Arc<Mutex<Option<(Stamp, Config)>>>,
}

/// mtime and inode: `store` renames, so a rewrite in the same mtime tick differs too.
type Stamp = (SystemTime, u64);
fn stamp(path: &Path) -> Option<Stamp> {
    std::fs::metadata(path).ok().and_then(|m| Some((m.modified().ok()?, m.ino())))
}

static RUN_DIR: OnceLock<PathBuf> = OnceLock::new();

/// This process's run directory (canonical), once a host is open.
pub fn run_dir() -> Option<&'static Path> {
    RUN_DIR.get().map(PathBuf::as_path)
}

impl Host {
    /// Synced up to `/` once per state root, not per command: under the root's flock, `.synced` names the
    /// root (dev, inode), so a copy syncs again; it goes before a repair and comes back after the syncs.
    pub fn open(state: &Path, run: &Path) -> Result<Host> {
        let dirs = [("addrs", 0o777), ("standby", 0o777), ("migs", 0o777), ("suspended", 0o700)];
        let (marker, id) = (state.join(".synced"), || std::fs::metadata(state).map(|m| format!("{} {}", m.dev(), m.ino())));
        let named = |d: &Path, e: std::io::Error| {
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied { " (run flexvm as root to create it)" } else { "" };
            format!("{}: {e}{hint}", d.display())
        };
        let root = |e| named(state, e);
        let held = std::fs::create_dir_all(state).and_then(|()| std::fs::File::open(state)).map_err(root)?;
        let _held = Flock::new(held, libc::LOCK_EX).map_err(root)?;
        if id().ok().is_none_or(|id| std::fs::read_to_string(&marker).ok() != Some(id)) || dirs.iter().any(|(d, _)| !state.join(d).is_dir()) {
            let _ = std::fs::remove_file(&marker);
            dirs.iter()
                .try_for_each(|(d, mode)| crate::util::create_dir_durably(&state.join(d), *mode))
                .and_then(|()| std::fs::write(&marker, id()?))
                .map_err(root)?;
        }
        // Only the run directory itself must be made here: a non-root user still reads one root made.
        std::fs::create_dir_all(run).map_err(|e| named(run, e))?;
        for d in ["vms", "standby", "w"] {
            let _ = std::fs::create_dir_all(run.join(d));
        }
        let canon = |d: &Path| d.canonicalize().map_err(|e| named(d, e));
        let (state, run) = (canon(state)?, canon(run)?);
        let _ = RUN_DIR.set(run.clone());
        let cfg_stamp = stamp(&state.join("host.json"));
        let cfg = load(&state.join("host.json"))?.unwrap_or_default();
        Ok(Host { state, run, cfg, cfg_stamp, cfg_seen: Arc::new(Mutex::new(None)) })
    }

    pub fn configure(&mut self, change: impl FnOnce(&mut Config) -> Result<()>) -> Result<()> {
        let _l = self.lock()?;
        let path = self.state.join("host.json");
        let mut cfg: Config = load(&path)?.unwrap_or_default();
        let prefix = cfg.prefix.clone();
        change(&mut cfg)?;
        if cfg.prefix != prefix {
            if let Some(why) = self.prefix_in_use(&cfg.prefix) {
                bail!("cannot change the tap prefix from {prefix:?} to {:?}: {why}", cfg.prefix);
            }
        }
        store(&path, &cfg, true)?;
        self.cfg = cfg;
        self.cfg_stamp = stamp(&path);
        Ok(())
    }

    /// Why the tap prefix cannot become `new` now, under the host lock: so
    /// that this host's taps all have one prefix, no VM process of this host
    /// may be left to make taps under the old one: any whose work directory's
    /// owner is not proven gone, whatever it is doing (it reads the prefix
    /// only once its work directory exists, `tap_prefix`). And no tap may
    /// already read as one of `new`'s, whoever made it, live or leaked: a
    /// VM process's tap would be refused its name. (Sweeps go by a tap's
    /// owner, `tap_alias`, never its name or the prefix.) What cannot be
    /// read is a reason too: never taken for nothing in use.
    fn prefix_in_use(&self, new: &str) -> Option<String> {
        self.prefix_in_use_at(new, Path::new("/sys/class/net"))
    }

    fn prefix_in_use_at(&self, new: &str, net: &Path) -> Option<String> {
        let names = |dir: &Path| -> std::io::Result<Vec<std::ffi::OsString>> { std::fs::read_dir(dir)?.map(|e| e.map(|e| e.file_name())).collect() };
        let w = self.run.join("w");
        let work = match names(&w) {
            Ok(w) => w,
            Err(e) => return Some(format!("{}: {e}", w.display())),
        };
        for pid in work {
            let owner = load::<Ident>(&w.join(&pid).join("owner"));
            if !matches!(owner, Ok(Some(ref o)) if o.liveness() == Liveness::Gone) {
                return Some(format!("vm process {} runs, or may (stop this host's VMs first)", pid.to_string_lossy()));
            }
        }
        let taps: Vec<String> = match names(net) {
            Ok(n) => n.iter().map(|n| n.to_string_lossy().into_owned()).filter(|n| tap_owner(n, new).is_some()).collect(),
            Err(e) => return Some(format!("{}: {e}", net.display())),
        };
        (!taps.is_empty()).then(|| format!("taps {} already read as named under it", taps.join(", ")))
    }

    /// The prefix of the taps of a VM process whose work directory exists:
    /// read from host.json now, not as it was when the process started, so
    /// a prefix change either sees the work directory or is seen here.
    /// Checked here, as host.json may hold one saved under an older limit.
    pub fn tap_prefix(&self) -> Result<String> {
        let prefix = load::<Config>(&self.state.join("host.json"))?.unwrap_or_default().prefix;
        check_prefix(&prefix).map_err(|e| format!("host.json's tap prefix: {e} (set one with `flexvm config --prefix`)"))?;
        Ok(prefix)
    }

    /// The configuration as it is now: `flexvm listen` may have changed the
    /// reserve, the eviction mark or the peers since this process started.
    /// host.json is read again once its mtime or inode changed (then cached by both).
    /// While it cannot be read whole (mid-write, missing), the newest one that was read
    /// stands, never an older one: a peer revoked since is not let back in.
    pub fn config_now(&self) -> Config {
        let path = self.state.join("host.json");
        let now = stamp(&path);
        if now.is_some() && now == self.cfg_stamp {
            return self.cfg.clone();
        }
        let mut seen = self.cfg_seen.lock().unwrap_or_else(|e| e.into_inner());
        let last = seen.clone();
        if let Some((_, cfg)) = last.as_ref().filter(|(t, _)| Some(*t) == now) {
            return cfg.clone();
        }
        if let Some(cfg) = now.and_then(|_| load::<Config>(&path).ok().flatten()) {
            *seen = Some((now.unwrap(), cfg.clone()));
            return cfg;
        }
        match last {
            Some((t, cfg)) if self.cfg_stamp.is_none_or(|own| own.0 <= t.0) => cfg,
            _ => self.cfg.clone(),
        }
    }

    fn worker_flock(&self) -> Option<Flock> {
        let f = File::options().create(true).truncate(false).write(true).open(self.state.join("evict.worker.lock")).ok()?;
        Flock::new(f, libc::LOCK_EX | libc::LOCK_NB).ok()
    }

    /// `STATE/evict.worker.lock`, held by the thread running an eviction for
    /// as long as it runs (and let go with its process). Taken under the
    /// host lock, as `evicting` probes it, so the two never meet.
    pub fn evict_worker_lock(&self) -> Result<Flock> {
        let _l = self.lock()?;
        self.worker_flock().ok_or_else(|| "another eviction runs here".into())
    }

    /// Whether an eviction runs here now (not merely that the host was under
    /// pressure). Under the host lock (see `evict_worker_lock`).
    fn evicting(&self, _l: &Locked) -> bool {
        self.worker_flock().is_none() && self.state.join("evict.worker.lock").exists()
    }

    /// Reentrant within a thread (so a guard dropped under it cannot
    /// deadlock); other threads wait as other processes do.
    pub fn lock(&self) -> Result<Locked> {
        self.lock_by(None)
    }

    /// Gives up at `deadline`, if any, with an I/O `WouldBlock` error.
    pub fn lock_by(&self, deadline: Option<std::time::Instant>) -> Result<Locked> {
        if DEPTH.with(|d| d.get()) > 0 {
            DEPTH.with(|d| d.set(d.get() + 1));
            return Ok(Locked(None));
        }
        let past = || deadline.is_some_and(|d| std::time::Instant::now() >= d);
        let threads = match deadline {
            None => THREADS.lock().unwrap_or_else(|e| e.into_inner()),
            Some(_) => loop {
                match THREADS.try_lock() {
                    Ok(g) => break g,
                    Err(std::sync::TryLockError::Poisoned(e)) => break e.into_inner(),
                    Err(_) if past() => return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "the host lock is busy").into()),
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
            },
        };
        let f = File::options().create(true).truncate(false).write(true).open(self.state.join("lock"))?;
        match deadline {
            None => flock(&f, libc::LOCK_EX)?,
            Some(_) => {
                while let Err(e) = flock(&f, libc::LOCK_EX | libc::LOCK_NB) {
                    if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
                        return Err(e.into());
                    }
                    if past() {
                        return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "the host lock is busy").into());
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
        DEPTH.with(|d| d.set(1));
        Ok(Locked(Some((f, threads))))
    }

    pub fn sock(&self, name: &str) -> PathBuf {
        self.vms(name, "sock")
    }

    pub fn vms(&self, name: &str, ext: &str) -> PathBuf {
        self.run.join("vms").join(format!("{name}.{ext}"))
    }

    pub fn suspended(&self, name: &str) -> PathBuf {
        self.state.join("suspended").join(name)
    }

    /// Whether a suspended VM of this name may still be resumed (or is
    /// quarantined): its checkpoint is published and not consumed. Anything
    /// else in its place is debris of an interrupted suspend, resume or
    /// discard, removed by the next holder of the name.
    pub fn is_suspended(&self, name: &str) -> bool {
        let dir = self.suspended(name);
        dir.join("manifest.json").is_file() && !dir.join("STARTED").exists() && !dir.join("DISCARDED").exists()
    }

    /// What a dead holder left running is reaped first, then debris in its
    /// suspended directory is removed.
    pub fn take_name(&self, name: &str, resuming: bool) -> Result<NameLock> {
        check_name(name)?;
        if !resuming && self.is_suspended(name) {
            bail!("vm {name:?} exists (suspended); resume or kill it");
        }
        // A sweep holds a dead holder's lock for a moment (`collect_owned`):
        // not taken, so tried again briefly.
        let until = std::time::Instant::now() + Duration::from_millis(250);
        let f = loop {
            match lock_path(&self.vms(name, "lock"), libc::LOCK_EX | libc::LOCK_NB) {
                Ok(f) => break f,
                Err(_) if std::time::Instant::now() < until && self.holder_gone(name) => std::thread::sleep(Duration::from_millis(2)),
                Err(_) => bail!("vm name {name:?} is taken"),
            }
        };
        // Locked, so its holder no longer runs it; its Firecrackers are reaped on
        // proof of death only, and an unreadable lock is an error, never no holder.
        if let Some(old) = lock_holder(&self.vms(name, "lock"))?.filter(|o| *o != Ident::me()) {
            reap(&self.run, &old)?;
        }
        if self.suspended(name).exists() && !self.is_suspended(name) {
            crate::lifecycle::remove_debris(self, name)?;
        }
        if !resuming && self.suspended(name).exists() {
            bail!("vm {name:?} exists (suspended); resume or kill it");
        }
        for ext in ["json", "sock", "moved", "failed"] {
            let _ = std::fs::remove_file(self.vms(name, ext));
        }
        f.set_len(0)?;
        f.write_all_at(&serde_json::to_vec(&Ident::me())?, 0)?;
        Ok(NameLock { name: name.into(), host: self.clone(), _file: f })
    }

    /// Whether no process runs `name`, by its lock's record alone (never a
    /// probe of the lock, which a start takes without waiting): none, or one
    /// proven gone.
    pub fn holder_gone(&self, name: &str) -> bool {
        match lock_holder(&self.vms(name, "lock")) {
            Ok(None) => true,
            Ok(Some(id)) => id.liveness() == Liveness::Gone,
            Err(_) => false,
        }
    }

    /// `RUN/.logs.lock`: held shared while a log is opened for a start,
    /// exclusively while garbage collection decides on one and removes it.
    /// Never a name's lock, which a start takes without waiting.
    pub fn logs_lock(&self, how: i32) -> Result<File> {
        let f = File::create(self.run.join(".logs.lock"))?;
        flock(&f, how)?;
        Ok(f)
    }

    pub fn alive(&self, name: &str) -> bool {
        File::open(self.vms(name, "lock")).is_ok_and(|f| flock(&f, libc::LOCK_SH | libc::LOCK_NB).is_err())
    }

    /// Whether `name`'s lock is held: None when that cannot be told (the
    /// file cannot be opened, or the probe fails other than by contention).
    pub fn name_locked(&self, name: &str) -> Option<bool> {
        let f = match File::open(self.vms(name, "lock")) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(false),
            Err(_) => return None,
        };
        match flock(&f, libc::LOCK_SH | libc::LOCK_NB) {
            Ok(()) => Some(false),
            Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => Some(true),
            Err(_) => None,
        }
    }

    /// Whether `id` holds `name` now: None when that cannot be told (the lock
    /// or its record unreadable, or held but not yet written).
    fn held_by(&self, name: &str, id: &Ident) -> Option<bool> {
        if !self.name_locked(name)? {
            return Some(false);
        }
        lock_holder(&self.vms(name, "lock")).ok()?.map(|h| h == *id)
    }

    /// Also requires the last holder's Firecrackers to have exited.
    fn gone(&self, name: &str) -> bool {
        self.name_locked(name) == Some(false) && lock_holder(&self.vms(name, "lock")).is_ok_and(|id| id.is_none_or(|id| reap(&self.run, &id).is_ok()))
    }

    pub fn entries(&self) -> Vec<Entry> {
        let mut out: Vec<Entry> = std::fs::read_dir(self.run.join("vms"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| self.entry(e.file_name().to_str()?.strip_suffix(".json")?).ok())
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Only believed if written by the process holding the name now.
    pub fn entry(&self, name: &str) -> Result<Entry> {
        match load::<Entry>(&self.vms(name, "json")) {
            Ok(Some(e)) if self.alive(name) && lock_holder(&self.vms(name, "lock")).ok().flatten() == Some(e.ident.clone()) => Ok(e),
            _ => bail!("no vm named {name:?}"),
        }
    }

    pub fn signal(&self, name: &str, sig: i32) -> Result<PidFd> {
        let fd = PidFd::open(&self.entry(name)?.ident)?.ok_or_else(|| format!("no vm named {name:?}"))?;
        fd.signal(sig)?;
        Ok(fd)
    }

    // Addresses and generations: all under the host lock.

    fn addr_path(&self, ip: Ipv4Addr) -> PathBuf {
        self.state.join("addrs").join(ip.to_string())
    }

    pub fn addr(&self, _: &Locked, ip: Ipv4Addr) -> Result<Addr> {
        Ok(load(&self.addr_path(ip))?.unwrap_or_default())
    }

    fn put_addr(&self, ip: Ipv4Addr, a: &Addr, durable: bool) -> Result<()> {
        store(&self.addr_path(ip), a, durable)
    }

    /// Stores the record only if `change` changed it.
    fn update<T>(&self, l: &Locked, ip: Ipv4Addr, durable: bool, change: impl FnOnce(&mut Addr) -> T) -> Result<T> {
        let mut a = self.addr(l, ip)?;
        let before = a.clone();
        let out = change(&mut a);
        if a != before {
            self.put_addr(ip, &a, durable)?;
        }
        Ok(out)
    }

    /// Held by the VM instance that claimed it: while that process holds the
    /// name, until its Firecrackers are reaped once it is dead, or while it is
    /// suspended here with this generation. Another instance of the same name
    /// (a restart after a SIGKILL) does not hold it.
    fn held(&self, a: &Addr) -> bool {
        let Some(h) = a.holder.as_deref() else { return false };
        let instance = match &a.holder_id {
            // Written before instances were recorded.
            None => !self.gone(h),
            Some(id) => match id.liveness() {
                // What cannot be read about its name keeps it held.
                Liveness::Alive => self.held_by(h, id).unwrap_or(true),
                // Until its Firecrackers are reaped.
                Liveness::Gone => reap(&self.run, id).is_err(),
                Liveness::Unknown => true,
            },
        };
        instance || self.suspended_with(h, a.held)
    }

    /// A suspended VM `name` with generation `gen` (or one whose generation was
    /// never recorded: quarantined, it keeps what it held).
    fn suspended_with(&self, name: &str, gen: u64) -> bool {
        let recorded = || std::fs::read_to_string(self.suspended(name).join("GEN")).ok().and_then(|g| g.trim().parse::<u64>().ok());
        self.is_suspended(name) && recorded().is_none_or(|g| g == gen)
    }

    pub fn claim_new(&self, l: &Locked, holder: &str, want: Option<Ipv4Addr>) -> Result<AddrClaim> {
        let range = self.cfg.range()?;
        let taken = |ip| self.addr(l, ip).map_or(true, |a| a.lent.is_some() || self.held(&a));
        let ip = match want {
            Some(ip) if !range.contains(ip) => {
                bail!("{ip} is not this host's to hand out (range {range}): start the vm on its home host, or let it pick an address")
            }
            Some(ip) if self.addr(l, ip)?.lent.is_some() => bail!("{ip} is lent out, with a vm that migrated away"),
            Some(ip) if taken(ip) => bail!("{ip} is in use"),
            Some(ip) => ip,
            None => {
                // From where the last allocation stopped, wrapping around: not a
                // rescan of every resident VM's address per start.
                let hint = std::fs::read_to_string(self.alloc_hint()).ok().and_then(|s| s.trim().parse().ok());
                let ip = range.allocate(hint, taken).ok_or("no free addresses left")?;
                let _ = crate::util::write_file(&self.state.join("addrs"), ALLOC_HINT, range.after(ip).to_string().as_bytes(), false);
                ip
            }
        };
        let a = self.addr(l, ip)?;
        let gen = self.next_gen(a.seen)?;
        let me = Ident::me();
        self.put_addr(ip, &Addr { seen: gen, holder: Some(holder.into()), holder_id: Some(me.clone()), held: gen, lent: a.lent, ..Addr::default() }, false)?;
        Ok(AddrClaim { host: self.clone(), ip, gen, rev: 0, holder: holder.into(), id: me, kept: false, fresh: true })
    }

    /// Where the next automatic allocation starts looking: a hint, never a claim.
    fn alloc_hint(&self) -> PathBuf {
        self.state.join("addrs").join(ALLOC_HINT)
    }

    pub fn lend_new(&self, l: &Locked, ip: Ipv4Addr) -> Result<u64> {
        if !self.cfg.range()?.contains(ip) {
            bail!("{ip} is not from this host's range {}", self.cfg.vm_ips);
        }
        let a = self.addr(l, ip)?;
        if let Some(gen) = a.lent {
            bail!("{ip} is lent out (generation {gen})");
        }
        if self.held(&a) {
            bail!("{ip} is in use");
        }
        let gen = self.next_gen(a.seen)?;
        self.put_addr(ip, &Addr { seen: gen, lent: Some(gen), ..Addr::default() }, true)?;
        Ok(gen)
    }

    /// Monotonic across crashes and reboots: a high-water mark reserved
    /// durably `GEN_BLOCK` at a time.
    fn next_gen(&self, seen: u64) -> Result<u64> {
        const GEN_BLOCK: u64 = 1024;
        #[derive(Serialize, Deserialize)]
        struct Gens {
            next: u64,
            reserved: u64,
            boot: String,
        }
        let path = self.state.join("addrs").join(".gens");
        if boot_id().is_empty() {
            bail!("cannot read the boot id: generations would not be ordered across a reboot");
        }
        let g = load::<Gens>(&path)?.unwrap_or(Gens { next: 1, reserved: 0, boot: String::new() });
        let next = if g.boot == boot_id() { g.next } else { g.next.max(g.reserved) };
        let gen = next.max(seen.saturating_add(1));
        let (reserved, durable) = if gen >= g.reserved { (gen.saturating_add(GEN_BLOCK), true) } else { (g.reserved, false) };
        if reserved > GEN_MAX {
            bail!("generations exhausted");
        }
        store(&path, &Gens { next: gen + 1, reserved, boot: boot_id().into() }, durable)?;
        Ok(gen)
    }

    /// At revision `rev` (a migration's target, recorded only once it commits:
    /// one that never does must not outrank its source), else one past the
    /// newest recorded here.
    pub fn claim_incoming(&self, l: &Locked, holder: &str, ip: Ipv4Addr, gen: u64, rev: Option<u64>) -> Result<AddrClaim> {
        let mut a = self.addr(l, ip)?;
        if gen == 0 || gen > RECV_MAX {
            bail!("{ip}: an arrival must carry its address's generation (not {gen})");
        }
        if self.held(&a) && a.holder.as_deref() != Some(holder) {
            bail!("{ip} is in use here");
        }
        if !a.current(gen) {
            bail!("{ip} has a newer generation than this vm's ({gen}): it was given out again");
        }
        if let Some(lent) = a.lent.filter(|&lent| gen < lent) {
            bail!("{ip} is lent out with a newer vm (generation {lent}, not {gen})");
        }
        let (arriving, rev) = (rev.is_some(), rev.unwrap_or(if gen > a.seen { 0 } else { a.rev.saturating_add(1) }));
        if gen > a.seen {
            (a.seen, a.withdrawn, a.via, a.rev) = (gen, false, None, 0);
        }
        if !arriving {
            a.rev = a.rev.max(rev);
        }
        let me = Ident::me();
        (a.holder, a.holder_id, a.held) = (Some(holder.into()), Some(me.clone()), gen);
        self.put_addr(ip, &a, true)?;
        Ok(AddrClaim { host: self.clone(), ip, gen, rev, holder: holder.into(), id: me, kept: false, fresh: false })
    }

    /// The host lock, if `gen` of `ip` is still current: held from this
    /// final check until the VM runs.
    pub fn fence(&self, ip: Ipv4Addr, gen: u64) -> Result<Locked> {
        let l = self.lock()?;
        if !self.current(&l, ip, gen)? {
            bail!("{ip}'s generation {gen} was withdrawn or given out again meanwhile");
        }
        Ok(l)
    }

    /// Lets go of `holder`'s claim; with `id`, only that instance's.
    pub fn release(&self, l: &Locked, ip: Ipv4Addr, holder: &str, id: Option<&Ident>) -> Result<()> {
        self.update(l, ip, false, |a| {
            let by = |h: &Ident| id.is_none_or(|id| id == h);
            if a.holder.as_deref() == Some(holder) && a.holder_id.as_ref().is_none_or(by) {
                (a.holder, a.holder_id) = (None, None);
            }
        })
    }

    /// True if this made the loan (only then may its maker undo it).
    pub fn lend(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        if !self.cfg.range()?.contains(ip) {
            return Ok(false);
        }
        self.update(l, ip, true, |a| a.lent.replace(gen) != Some(gen))
    }

    /// Test fault `unlend_fail`: it fails, leaving the loan.
    pub fn unlend(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<()> {
        if fault("unlend_fail") {
            bail!("injected fault");
        }
        self.update(l, ip, true, |a| a.lent = a.lent.filter(|&lent| lent != gen))
    }

    /// `via` None is a withdrawal (of every revision). False if stale (older,
    /// announcing a withdrawn generation, or an older revision of the newest
    /// one). A withdrawal frees a loan of that gen or older.
    pub fn observe(&self, l: &Locked, ip: Ipv4Addr, gen: u64, rev: u64, via: Option<Ipv4Addr>) -> Result<bool> {
        self.update(l, ip, true, |a| {
            if gen == 0 || gen > RECV_MAX || gen < a.seen || (gen == a.seen && via.is_some() && (a.withdrawn || rev < a.rev)) {
                return false;
            }
            if via.is_some() || gen > a.seen {
                a.rev = rev;
            }
            (a.seen, a.withdrawn, a.via) = (gen, via.is_none(), via);
            if via.is_none() && a.lent.is_some_and(|lent| lent <= gen) {
                a.lent = None;
            }
            true
        })
    }

    /// Records revision `rev` of `gen`, if newer: where this host's VM runs again.
    pub fn advance(&self, l: &Locked, ip: Ipv4Addr, gen: u64, rev: u64) -> Result<()> {
        self.update(l, ip, true, |a| {
            if gen == a.seen {
                a.rev = a.rev.max(rev);
            }
        })
    }

    /// A paused migration source keeps its route too: its release moves it.
    pub fn keeps_route(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        let a = self.addr(l, ip)?;
        let source = || a.holder.as_deref().and_then(|h| self.entry(h).ok()).is_some_and(|e| e.state == "source");
        Ok(self.held(&a) && (a.held >= gen || source()))
    }

    /// Counts `dead` as gone even while its other threads still hold the name lock.
    pub fn reinstall(&self, l: &Locked, ip: Ipv4Addr, dead: Option<&Ident>) -> Result<bool> {
        let a = self.addr(l, ip)?;
        let dying = dead.is_some() && a.holder_id.as_ref() == dead;
        let Some(via) = a.via.filter(|_| !a.withdrawn && (dying || !self.held(&a))) else { return Ok(false) };
        crate::net::route_via(ip, via)?;
        crate::log!("put back route {ip} via {via} (generation {})", a.seen);
        Ok(true)
    }

    pub fn current(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        Ok(self.addr(l, ip)?.current(gen))
    }

    pub fn holder(&self, l: &Locked, ip: Ipv4Addr) -> Result<Option<String>> {
        let a = self.addr(l, ip)?;
        Ok(self.held(&a).then_some(a.holder).flatten())
    }

    /// Live holds (`RUN/holds/ID-MIB`, each flocked by its owner for as
    /// long as it is held), as (id, MiB). One whose lock is free has no
    /// owner left (the kernel let go of it with the process): removed, as is
    /// a free `.ID` (a grant's temp file, never in sight while it is made).
    fn holds(&self, _l: &Locked) -> Vec<(u64, u64)> {
        let dir = self.run.join("holds");
        let mut live = Vec::new();
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let hold = name.split_once('-').and_then(|(i, m)| Some((i.parse().ok()?, m.parse().ok()?)));
            if hold.is_none() && !name.starts_with('.') {
                continue;
            }
            match File::open(e.path()).map(|f| flock(&f, libc::LOCK_EX | libc::LOCK_NB).is_ok()) {
                Ok(true) => drop(std::fs::remove_file(e.path())),
                // Being unlinked by its owner.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                // Held; or unreadable, which counts as held.
                _ => live.extend(hold),
            }
        }
        live
    }

    /// Counts `hold` as `mib` from now on, if less: renamed under the host
    /// lock, its flock going with the file. On failure it counts as before.
    pub fn shrink_hold(&self, hold: &Mutex<Option<Hold>>, mib: u64) -> Result<()> {
        let more = |h: &Hold| h.mib > mib;
        if !hold.lock().unwrap().as_ref().is_some_and(more) {
            return Ok(());
        }
        // The host lock first: whoever has it may be letting the hold go.
        let _l = self.lock()?;
        let mut g = hold.lock().unwrap();
        let Some(h) = g.as_mut().filter(|h| more(h)) else { return Ok(()) };
        let path = h.path.with_file_name(format!("{}-{mib}", h.id));
        std::fs::rename(&h.path, &path)?;
        (h.path, h.mib) = (path, mib);
        Ok(())
    }

    /// Per boot by name: RUN need not be a tmpfs. An unreadable boot id still counts grants.
    pub fn grants(&self) -> PathBuf {
        self.run.join(format!("grants-{}", boot_id()))
    }

    /// Gives back grant `id` (from `grant`) that was not used.
    pub fn refund(&self, id: u64) {
        self.refund_by(id, None)
    }

    /// `refund`, giving up at `deadline` (the grant then expires on its own).
    pub fn refund_by(&self, id: u64, deadline: Option<std::time::Instant>) {
        let Ok(_l) = self.lock_by(deadline) else { return };
        let path = self.grants();
        let mut grants: Vec<Grant> = load(&path).ok().flatten().unwrap_or_default();
        let n = grants.len();
        grants.retain(|g| g.2 != id);
        if grants.len() != n {
            let _ = store(&path, &grants, false);
        }
    }

    /// Against the reserve: None if refused; errors grant nothing (`WouldBlock` if the lock is busy).
    pub fn grant(&self, mib: u64, deadline: Option<std::time::Instant>, cgroup: Option<&Path>) -> Result<Option<u64>> {
        Ok(self.grant_inner(mib, Floor::Reserve, false, deadline, cgroup, crate::vmproc::host_available_mib)?.ok().map(|g| g.0))
    }

    /// A refusal is an error too; `hold` keeps the grant past `GRANT_WINDOW`.
    pub fn grant_start(&self, mib: u64, floor: Floor, hold: bool, cgroup: Option<&Path>) -> Result<(u64, Option<Hold>)> {
        self.grant_inner(mib, floor, hold, None, cgroup, crate::vmproc::host_available_mib)?
    }

    /// MemAvailable lags a grant until the guest touches the memory: recent
    /// grants count only their unused portion, or in full without a readable
    /// owner baseline. Held grants count however old, each once. Returns its id.
    /// Leaves `floor` available, read with the reserve under the host lock.
    /// Ok(Err(why)) if refused. Test fault `no_admit`: refuses everything.
    fn grant_inner(
        &self,
        mib: u64,
        floor: Floor,
        hold: bool,
        deadline: Option<std::time::Instant>,
        cgroup: Option<&Path>,
        available: impl FnOnce() -> Option<u64>,
    ) -> Result<std::result::Result<(u64, Option<Hold>), Error>> {
        if fault("no_admit") {
            return Ok(Err(format!("not enough memory here for {mib} MiB (injected fault)").into()));
        }
        let l = self.lock_by(deadline)?;
        let cfg = self.config_now();
        let (floor, what) = match floor {
            Floor::Reserve => (cfg.reserve_mib, "reserve"),
            // An eviction's arrival: never while this host evicts itself, and it
            // leaves this host's own mark, so it is not moved straight back.
            Floor::EvictMark if self.evicting(&l) => return Ok(Err("this host is moving vms away itself".into())),
            Floor::EvictMark => (cfg.evict_at(), "eviction mark"),
        };
        let path = self.grants();
        let now = boottime_ms();
        let mut grants: Vec<Grant> = load(&path)?.unwrap_or_default();
        // A stamp in the future is an older build's wall clock.
        grants.retain(|g| g.0 <= now && now - g.0 <= GRANT_WINDOW.as_millis() as u64);
        let held = self.holds(&l);
        let held_ids: HashSet<_> = held.iter().map(|h| h.0).collect();
        let pending: u64 = pending_grants(&grants, &held_ids, crate::limit::used_mib) + held.iter().map(|h| h.1).sum::<u64>();
        let avail = available().ok_or("cannot read MemAvailable from /proc/meminfo")?;
        if avail < floor + pending + mib {
            return Ok(Err(format!("not enough memory here for {mib} MiB above the {floor} MiB {what}").into()));
        }
        let id = crate::migrate::migration_id().max(1);
        // Locked before it is visible (renamed in): a probe never takes it for an owner's.
        let hold = match hold {
            false => None,
            true => {
                let dir = self.run.join("holds");
                std::fs::create_dir_all(&dir)?;
                let (tmp, path) = (dir.join(format!(".{id}")), dir.join(format!("{id}-{mib}")));
                let f = File::create(&tmp)?;
                if let Err(e) = flock(&f, libc::LOCK_EX | libc::LOCK_NB).and_then(|()| std::fs::rename(&tmp, &path)) {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e.into());
                }
                Some(Hold { path, id, mib, _file: f })
            }
        };
        let owner = cgroup.map(|cg| GrantOwner { ident: Ident::me(), cgroup: cg.into(), used_mib: crate::limit::used_mib(cg) });
        grants.push(Grant(now, mib, id, owner));
        if let Err(e) = store(&path, &grants, false) {
            drop(hold);
            return Err(e);
        }
        Ok(Ok((id, hold)))
    }

    // Incoming migrations: `STATE/migs/ID`, durable, under the host lock.
    // No record means aborted.

    fn mig_path(&self, id: u64) -> PathBuf {
        self.state.join("migs").join(id.to_string())
    }

    /// `source`: its listener, asked whether the source process `by` is gone
    /// when it never says it is done with a released record.
    /// `ip`: the VM's address, whose peer route comes back if the arrival dies before it commits.
    pub fn mig_begin(&self, id: u64, source: &str, by: Option<Ident>, ip: Option<Ipv4Addr>) -> Result<MigRecord> {
        let _l = self.lock()?;
        if load::<Mig>(&self.mig_path(id))?.is_some() {
            bail!("migration {id} was already seen here");
        }
        store(&self.mig_path(id), &Mig::Pending { owner: Ident::me(), ip }, true)?;
        Ok(MigRecord { host: self.clone(), id, committed: false, source: source.into(), by })
    }

    /// A record whose process died becomes aborted once its Firecrackers are
    /// dead: committed or not, the source's paused copy is the only one left.
    pub fn mig_status(&self, id: u64) -> Result<&'static str> {
        let l = self.lock()?;
        let path = self.mig_path(id);
        let (owner, ip) = match load(&path)? {
            None => return Ok("aborted"),
            Some(Mig::Released { .. }) => return Ok("released"),
            Some(Mig::Pending { owner, .. }) if owner.alive() => return Ok("pending"),
            Some(Mig::Committed { owner }) if owner.alive() => return Ok("committed"),
            Some(Mig::Pending { owner, ip }) => (owner, ip),
            Some(Mig::Committed { owner }) => (owner, None),
        };
        reap(&self.run, &owner)?;
        // Killed before it committed, it never ran here: the newest route a peer
        // announced for its address (say, back to its source) comes back. Until
        // it does, the record stays (still aborted), so the next query retries.
        if let Some(ip) = ip {
            if let Err(e) = self.reinstall(&l, ip, Some(&owner)) {
                crate::log!("migration {id} died before its commit; putting back the route for {ip}: {e}; retried on the next query");
                return Ok("aborted");
            }
        }
        crate::util::unlink_durably(&path)?;
        Ok("aborted")
    }

    pub fn mig_done(&self, id: u64) -> Result<()> {
        let _l = self.lock()?;
        match load(&self.mig_path(id))? {
            Some(Mig::Released { .. }) => Ok(crate::util::unlink_durably(&self.mig_path(id))?),
            _ => Ok(()),
        }
    }

    /// Records no source will ask about again: a dead owner's (aborted, as
    /// `mig_status` would answer), and released ones whose source process is
    /// proven gone (killed before its `done`) by its own host's listener. Any
    /// doubt keeps the record: a source that still waits must find it.
    pub fn retire_migrations(&self) {
        // At most five records (and thus five two-second peer calls) per pass.
        self.retire_migrations_with(5, |source, by| {
            crate::vmproc::peer_call(source, serde_json::json!({"op": "source", "ident": by})).map(|r| r["gone"] == true)
        });
    }

    fn retire_migrations_with(&self, budget: usize, mut query: impl FnMut(&str, &Ident) -> Result<bool>) {
        let Ok(lock) = File::create(self.run.join(".retire.lock")) else { return };
        if flock(&lock, libc::LOCK_EX | libc::LOCK_NB).is_err() {
            return;
        }
        // A sorted ID cursor survives deletions and lets different processes
        // continue the same rotation. Only retirement holds this lock.
        let cursor = self.run.join(".retire.next");
        let last = load::<u64>(&cursor).ok().flatten();
        let mut ids: Vec<u64> =
            std::fs::read_dir(self.state.join("migs")).into_iter().flatten().flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect();
        ids.sort_unstable();
        let start = last.map_or(0, |last| ids.partition_point(|id| *id <= last));
        ids.rotate_left(start);
        let mut unavailable = HashSet::new();
        let mut visited = None;
        for id in ids.into_iter().take(budget) {
            visited = Some(id);
            let Ok(Some(Mig::Released { source, by })) = load(&self.mig_path(id)) else {
                let _ = self.mig_status(id);
                continue;
            };
            let Some(by) = by.filter(|_| !source.is_empty()) else { continue };
            if unavailable.contains(&source) {
                continue;
            }
            match query(&source, &by) {
                Ok(true) => {
                    crate::log!("migration {id}: its source at {source} is gone; forgetting it");
                    let _ = self.mig_done(id);
                }
                Ok(false) => (),
                Err(_) => {
                    unavailable.insert(source);
                }
            }
        }
        if let Some(id) = visited {
            if let Err(e) = store(&cursor, &id, false) {
                crate::log!("migration retirement cursor: {e}");
            }
        }
    }
}

const GRANT_WINDOW: Duration = Duration::from_secs(10);

/// Shared by all processes (RUN is per boot) and unaffected by wall-clock steps.
fn boottime_ms() -> u64 {
    #[cfg(test)]
    if let Some(t) = tests::PINNED_MS.with(|p| p.get()) {
        return t;
    }
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) };
    t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1_000_000
}
const ALLOC_HINT: &str = ".next";
const GEN_MAX: u64 = u64::MAX / 2;
const RECV_MAX: u64 = 1 << 62; // Leave allocation headroom above any peer generation.

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Addr {
    pub seen: u64,
    pub withdrawn: bool,
    /// Gone with a VM of this generation: not handed out until withdrawn or back.
    pub lent: Option<u64>,
    pub holder: Option<String>,
    /// The instance (process) of `holder` that claimed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_id: Option<Ident>,
    pub held: u64,
    pub via: Option<Ipv4Addr>,
    /// Of `seen`, the newest location's revision: a migration's target takes the next.
    pub rev: u64,
}

impl Addr {
    pub fn current(&self, gen: u64) -> bool {
        gen > self.seen || (gen == self.seen && !self.withdrawn)
    }
}

/// Dropped, it gives the address back; a suspended VM `keep`s it.
pub struct AddrClaim {
    host: Host,
    pub ip: Ipv4Addr,
    pub gen: u64,
    /// Where within `gen` the VM is: announced with its route.
    pub rev: u64,
    holder: String,
    id: Ident,
    kept: bool,
    /// A generation made for this VM: withdrawn even if the VM never ran.
    pub fresh: bool,
}

impl AddrClaim {
    pub fn keep(mut self) {
        self.kept = true;
    }

    pub fn release(mut self, l: &Locked) -> Result<()> {
        self.kept = true;
        self.host.release(l, self.ip, &self.holder, Some(&self.id))
    }
}

impl Drop for AddrClaim {
    fn drop(&mut self) {
        if let (false, Ok(l)) = (self.kept, self.host.lock()) {
            let _ = self.host.release(&l, self.ip, &self.holder, Some(&self.id));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Mig {
    Pending {
        owner: Ident,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ip: Option<Ipv4Addr>,
    },
    /// The source must never run it again.
    Committed { owner: Ident },
    /// All memory is here, or the VM is gone: the source may exit.
    Released {
        #[serde(default)]
        source: String,
        /// The source's VM process.
        #[serde(default)]
        by: Option<Ident>,
    },
}

/// Dropped before it commits, the record goes (aborted).
pub struct MigRecord {
    host: Host,
    pub id: u64,
    committed: bool,
    source: String,
    by: Option<Ident>,
}

impl MigRecord {
    /// From here this host owns the VM. Refused if a source query fenced it off.
    pub fn commit(&mut self, _: &Locked) -> Result<()> {
        let path = self.host.mig_path(self.id);
        match load(&path)? {
            Some(Mig::Pending { owner, .. }) if owner == Ident::me() => store(&path, &Mig::Committed { owner }, true)?,
            m => bail!("migration {} was fenced off meanwhile ({m:?})", self.id),
        }
        self.committed = true;
        Ok(())
    }

    /// Destroyed on purpose (`gone`): released so the source goes too;
    /// otherwise it reads aborted once this process is dead.
    pub fn settle(self, gone: bool) {
        if gone && self.committed {
            let _ = self.release(None, None);
        }
    }

    /// Retried until recorded (the source waits for it), or `within` passes.
    /// `home`: the VM's address and generation, whose loan (if this is its
    /// home host) is taken back only after, so a crash in between leaves it
    /// lent, never free.
    pub fn release(&self, home: Option<(Ipv4Addr, u64)>, within: Option<Duration>) -> Result<()> {
        let (mut delay, start) = (Duration::from_millis(100), std::time::Instant::now());
        loop {
            let done = self.host.lock_by(within.map(|w| start + w)).and_then(|l| {
                store(&self.host.mig_path(self.id), &Mig::Released { source: self.source.clone(), by: self.by.clone() }, true)?;
                match home {
                    Some((ip, gen)) => self.host.update(&l, ip, true, |a| a.lent = a.lent.filter(|&lent| lent > gen)),
                    None => Ok(()),
                }
            });
            match done {
                Err(e) if within.is_none_or(|w| start.elapsed() + delay < w) => crate::log!("migration {}: {e}; retrying", self.id),
                done => return done,
            }
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    }
}

impl Drop for MigRecord {
    fn drop(&mut self) {
        if let (false, Ok(_l)) = (self.committed, self.host.lock()) {
            let path = self.host.mig_path(self.id);
            if matches!(load(&path), Ok(Some(Mig::Pending { owner, .. })) if owner == Ident::me()) {
                let _ = crate::util::unlink_durably(&path);
            }
        }
    }
}

pub struct Locked(#[allow(dead_code)] Option<(File, std::sync::MutexGuard<'static, ()>)>);

impl Drop for Locked {
    fn drop(&mut self) {
        if let Some((f, _)) = &self.0 {
            let _ = flock(f, libc::LOCK_UN); // Before the threads' mutex: see `Flock`.
        }
        DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// An exclusive flock, let go of when dropped. Unlocked, not only closed: a
/// child another thread forks meanwhile shares the open file until it execs,
/// and the lock would be held that long.
pub struct Flock(File);

impl Flock {
    pub fn new(f: File, how: i32) -> std::io::Result<Flock> {
        flock(&f, how).map(|()| Flock(f))
    }
}

impl Drop for Flock {
    fn drop(&mut self) {
        let _ = flock(&self.0, libc::LOCK_UN);
    }
}

static THREADS: Mutex<()> = Mutex::new(());
thread_local! {
    static DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub struct NameLock {
    pub name: String,
    host: Host,
    _file: File,
}

impl NameLock {
    pub fn publish(&self, e: &Entry) -> Result<()> {
        store(&self.host.vms(&self.name, "json"), e, false)
    }
}

impl Drop for NameLock {
    fn drop(&mut self) {
        // Unlinked while held: a taker re-checks the path after locking.
        for ext in ["json", "sock", "lock"] {
            let _ = std::fs::remove_file(self.host.vms(&self.name, ext));
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    pub name: String,
    #[serde(flatten)]
    pub ident: Ident,
    pub ip: Option<Ipv4Addr>,
    pub gen: u64,
    pub template: String,
    pub template_id: String,
    pub vcpus: u32,
    pub max_mib: u64,
    pub state: String,
    pub firecracker: Option<u32>,
    pub starved: bool,
    /// How fast its memory grew over the last few seconds (MiB/s), as last published.
    pub growth_mib_s: u64,
    /// Runs `run -- CMD`: its process ends with CMD's, so eviction leaves it here.
    pub cmd: bool,
}

/// Unique however pids are reused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ident {
    pub pid: u32,
    pub start: u64,
    pub boot: String,
}

impl Ident {
    /// Read once. Panics without a boot id or `/proc/self/stat`: a process
    /// that cannot name itself must not take a name, an address or a migration.
    pub fn me() -> Ident {
        static ME: OnceLock<Ident> = OnceLock::new();
        ME.get_or_init(|| Ident::of(std::process::id()).expect("cannot read this process's identity (/proc/self/stat, boot id)")).clone()
    }

    /// None without a boot id: an identity without one would read as another boot's, i.e. gone.
    pub fn of(pid: u32) -> Option<Ident> {
        let boot = boot_id();
        if boot.is_empty() {
            return None;
        }
        Some(Ident { pid, start: starttime(pid)?, boot: boot.into() })
    }

    /// `PID-START`: names what is this instance's own, never another process's that got its pid.
    pub fn key(&self) -> String {
        format!("{}-{}", self.pid, self.start)
    }

    /// Its work directory (`RUN/w/PID-START`): removing it once this one is reaped removes nothing alive.
    pub fn work_dir(&self, run: &Path) -> PathBuf {
        run.join("w").join(self.key())
    }

    /// Alive, gone on proof, or unknown (an unreadable `/proc`, say: never proof).
    pub fn liveness(&self) -> Liveness {
        liveness_by(self, boot_id(), |pid| std::fs::read_to_string(format!("/proc/{pid}/stat")))
    }

    /// Not proven gone: what may still be running is treated as running.
    pub fn alive(&self) -> bool {
        self.liveness() != Liveness::Gone
    }
}

/// The one account of whether a process is gone. Only `Gone` lets its name,
/// address, migration record or work directory be reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Alive,
    /// Proof: another boot, no such pid, a zombie, or another process with its pid.
    Gone,
    /// It cannot be told (a read error, unparsable data): treated as alive.
    Unknown,
}

/// "" when it cannot be read; only a successful read is cached, so a later call retries.
pub fn boot_id() -> &'static str {
    static BOOT: OnceLock<String> = OnceLock::new();
    if let Some(b) = BOOT.get() {
        return b;
    }
    match std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string()) {
        Ok(b) if !b.is_empty() => BOOT.get_or_init(|| b),
        _ => "",
    }
}

pub struct PidFd(OwnedFd);

impl PidFd {
    pub fn open(id: &Ident) -> Result<Option<PidFd>> {
        match crate::util::pidfd_open(id.pid) {
            // Opened, then checked: if it is `id` now, the fd is `id`'s.
            Ok(fd) => match id.liveness() {
                Liveness::Alive => Ok(Some(PidFd(fd))),
                Liveness::Gone => Ok(None),
                Liveness::Unknown => bail!("cannot tell whether process {} is still the one meant", id.pid),
            },
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(None),
            Err(e) => bail!("pidfd_open {}: {e}", id.pid),
        }
    }

    pub fn signal(&self, sig: i32) -> Result<()> {
        Ok(crate::util::pidfd_signal(&self.0, sig).map_err(|e| format!("signal {sig}: {e}"))?)
    }

    pub fn wait(&self, timeout: Duration) -> bool {
        crate::util::readable(&self.0, timeout).unwrap_or(false)
    }
}

/// Kills and waits for a dead process's Firecrackers: they die with it, but not at once.
/// Anything it cannot read is an error, never nothing to reap.
pub fn reap(run: &Path, owner: &Ident) -> Result<()> {
    match owner.liveness() {
        Liveness::Gone => {}
        Liveness::Alive => bail!("process {} is alive", owner.pid),
        Liveness::Unknown => bail!("cannot tell whether process {} is gone", owner.pid),
    }
    let dir = owner.work_dir(run);
    if owner.boot != boot_id() || load::<Ident>(&dir.join("owner"))?.as_ref() != Some(owner) {
        return Ok(());
    }
    // Another process's sweep removes the directory once it reaped them (`collect_garbage`):
    // gone meanwhile, they are dead.
    let gone = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    let entries = match std::fs::read_dir(&dir) {
        Err(e) if gone(&e) => return Ok(()),
        r => r.map_err(|e| format!("{}: {e}", dir.display()))?,
    };
    for e in entries {
        let e = match e {
            Err(e) if gone(&e) => return Ok(()),
            r => r.map_err(|e| format!("{}: {e}", dir.display()))?,
        };
        match e.file_type() {
            Ok(t) if t.is_dir() => {}
            Err(e) if !gone(&e) => return Err(e.into()),
            _ => continue,
        }
        let Some(fc) = load::<Ident>(&e.path().join("fc"))? else { continue };
        if let Some(fd) = PidFd::open(&fc)? {
            // If it exited and was waited for since it was opened (its parent died with SIGKILL
            // pending for it), the kill finds nothing and the wait returns at once.
            crate::util::pidfd_kill(&fd.0).map_err(|e| format!("signal {}: {e}", libc::SIGKILL))?;
            if !fd.wait(Duration::from_secs(5)) {
                bail!("firecracker {} of dead process {} will not exit", fc.pid, owner.pid);
            }
        }
    }
    Ok(())
}

/// The process a tap's name reads as made for: a VM process's (PREFIX, its
/// pid in hex, `t`, a counter) or a template build's (PREFIX `x` pid in hex,
/// `template::tap`; earlier builds' PREFIX `tpl` pid in decimal). Only to
/// keep names apart (`Host::prefix_in_use`): a name proves nothing about
/// whose a tap is (another host's prefix may extend this one's).
fn tap_owner(name: &str, prefix: &str) -> Option<u32> {
    let rest = name.strip_prefix(prefix)?;
    let number = |s: &str, radix| (!s.is_empty() && s.chars().all(|c| c.is_digit(radix))).then(|| u32::from_str_radix(s, radix).ok()).flatten();
    if let Some(pid) = rest.strip_prefix("tpl") {
        return number(pid, 10);
    }
    if let Some(pid) = rest.strip_prefix('x') {
        return number(pid, 16);
    }
    rest.split_once('t').and_then(|(p, _)| u32::from_str_radix(p, 16).ok())
}

/// The VM process a Firecracker's cgroup (`idle-PID-START-N`) was made by.
/// Earlier builds' (`idle-PID-N`) are left alone, as their owner cannot be
/// told by identity: emptied when their Firecrackers exit, gone at a reboot.
fn cgroup_owner(name: &str) -> Option<Ident> {
    let parts: Vec<&str> = name.strip_prefix("idle-")?.split('-').collect();
    let [pid, start, _] = parts[..] else { return None };
    Some(Ident { pid: pid.parse().ok()?, start: start.parse().ok()?, boot: boot_id().into() })
}

/// A tap's alias, naming its owner (`net::create_tap`): `flexvm PID START RUN`,
/// the process that made it and its host's run directory, which no other host
/// shares. Sweeps go by it alone, never by a tap's name.
pub fn tap_alias(run: &Path, owner: &Ident) -> String {
    format!("flexvm {} {} {}", owner.pid, owner.start, run.display())
}

fn parse_tap_alias(alias: &str) -> Option<(Ident, &str)> {
    let mut parts = alias.strip_prefix("flexvm ")?.splitn(3, ' ');
    let (pid, start, run) = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?);
    (!run.is_empty()).then(|| (Ident { pid, start, boot: boot_id().into() }, run))
}

/// This host's taps: tun devices whose alias names its run directory (`tap_alias`), with
/// their index (read before the alias: a tap made since under the name has another) and
/// owner. A tap without such an alias (another host's, an earlier build's, anyone's) is
/// never this host's.
fn taps_of(run: &Path) -> Vec<(String, u32, Ident)> {
    taps_of_at(run, Path::new("/sys/class/net"))
}

fn taps_of_at(run: &Path, net: &Path) -> Vec<(String, u32, Ident)> {
    let run = run.to_string_lossy();
    let mut taps = Vec::new();
    for e in std::fs::read_dir(net).into_iter().flatten().flatten() {
        let dir = e.path();
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).ok();
        let Some(index) = read("ifindex").and_then(|i| i.trim().parse().ok()) else { continue };
        let Some(alias) = read("ifalias") else { continue };
        let Some((owner, of)) = parse_tap_alias(alias.strip_suffix('\n').unwrap_or(&alias)) else { continue };
        if of == run && dir.join("tun_flags").exists() {
            taps.push((e.file_name().to_string_lossy().into_owned(), index, owner));
        }
    }
    taps
}

/// A detached VM process's own cgroup (`vm-PID-START`, `util::spawn_self`)
/// goes once nothing is in it: never killed, so a process that just joined
/// one is never touched. (`rmdir` refuses a populated cgroup anyway.)
fn sweep_scope(dir: &Path) {
    let events = std::fs::read_to_string(dir.join("cgroup.events")).unwrap_or_default();
    if events.lines().any(|l| l == "populated 0") {
        let _ = std::fs::remove_dir(dir);
    }
}

impl Host {
    /// What dead processes left: taps (a template build's too), cgroups, work
    /// directories and names. Only proof of death (`Liveness::Gone`) frees any.
    /// Taps are this host's by their alias (`taps_of`), whatever their name.
    pub fn collect_garbage(&self) -> Result<()> {
        // Deleted by index and name: a tap made since under a dead one's name is another.
        for (name, index, owner) in taps_of(&self.run) {
            if owner.liveness() == Liveness::Gone {
                crate::net::delete_link(index, &name);
            }
        }
        collect_owned(&self.run);
        Ok(())
    }
}

/// Taps that dead processes of this host with `me`'s pid left (a template
/// build's too), whose names `me` would be refused: for `me`, before it
/// makes any, as a sweep may not have run since.
pub fn clear_taps(run: &Path, me: &Ident) {
    for (name, index, owner) in taps_of(run) {
        if owner.pid == me.pid && owner.liveness() == Liveness::Gone {
            crate::log!("removing tap {name}, a dead process's with this pid");
            crate::net::delete_link(index, &name);
        }
    }
}

/// Cgroups, work directories and names of dead processes.
fn collect_owned(run: &Path) {
    // Firecrackers' by identity: once their process is gone no other makes one under their name.
    for e in std::fs::read_dir("/sys/fs/cgroup/flexvm").into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.starts_with("vm-") {
            sweep_scope(&e.path());
        } else if cgroup_owner(&n).is_some_and(|o| o.liveness() == Liveness::Gone) {
            let _ = crate::fc::remove_cgroup(&e.path());
        }
    }
    for e in std::fs::read_dir(run.join("w")).into_iter().flatten().flatten() {
        let owner = load::<Ident>(&e.path().join("owner")).ok().flatten();
        if owner.is_some_and(|o| reap(run, &o).is_ok()) {
            crate::socket::remove(&e.path());
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
    // Names whose holder was killed: taken (so no one else holds them) and let go,
    // as `NameLock` would have. `failed` and `moved` records stay for `ls`.
    for e in std::fs::read_dir(run.join("vms")).into_iter().flatten().flatten() {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "lock") {
            continue;
        }
        // Reaped first, without the lock: a start may take the name meanwhile (`take_name`
        // waits only briefly for a sweep), and then the holder read again under it differs.
        let reaped = match lock_holder(&path) {
            Ok(Some(o)) if o.liveness() == Liveness::Gone && reap(run, &o).is_ok() => Some(Some(o)),
            Ok(None) => Some(None),
            // Alive, unknown, or unreadable: kept, never taken for an empty lock.
            _ => None,
        };
        let Some(reaped) = reaped else { continue };
        let Ok(_held) = lock_path(&path, libc::LOCK_EX | libc::LOCK_NB) else { continue };
        if lock_holder(&path).is_ok_and(|now| now == reaped) {
            for ext in ["json", "sock", "lock"] {
                let _ = std::fs::remove_file(path.with_extension(ext));
            }
        }
    }
}

/// Tap names are 15 bytes at most: PREFIX, a pid in hex (up to 6), `t` and a counter.
pub fn check_prefix(p: &str) -> Result<()> {
    if p.is_empty() || p.len() > 6 || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        bail!("bad prefix {p:?}: 1 to 6 letters, digits, '-', '_' or '.'");
    }
    Ok(())
}

pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 || name.starts_with('.') || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        bail!("bad vm name {name:?}: up to 64 letters, digits, '-', '_' or '.', not starting with '.'");
    }
    Ok(())
}

pub fn flock(f: &File, how: i32) -> std::io::Result<()> {
    crate::util::eintr(|| unsafe { libc::flock(f.as_raw_fd(), how) }).map(drop)
}

/// A holder may unlink the file just before we lock: retry until it is the path's.
fn lock_path(path: &Path, how: i32) -> std::io::Result<File> {
    loop {
        let f = File::options().create(true).truncate(false).read(true).write(true).open(path)?;
        flock(&f, how)?;
        if std::fs::metadata(path).is_ok_and(|m| f.metadata().is_ok_and(|n| n.ino() == m.ino())) {
            return Ok(f);
        }
    }
}

/// Every error, and anything unparsable, is unknown.
fn liveness_by(id: &Ident, boot: &str, stat: impl Fn(u32) -> std::io::Result<String>) -> Liveness {
    // Without either boot id, a mismatch proves nothing.
    if boot.is_empty() || id.boot.is_empty() {
        return Liveness::Unknown;
    }
    if id.boot != boot {
        return Liveness::Gone;
    }
    // Opened while it was exiting, read once it was gone: the task the read was for no longer
    // exists, so neither does `id` (a new process with its pid would be another one).
    let stat = |pid| match stat(pid) {
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        r => r,
    };
    match pid_liveness_by(id.pid, stat) {
        (Liveness::Alive, Some(start)) if start != id.start => Liveness::Gone,
        (l, _) => l,
    }
}

/// Whether any process has `pid` (a zombie counts as gone), and its start time.
fn pid_liveness_by(pid: u32, stat: impl Fn(u32) -> std::io::Result<String>) -> (Liveness, Option<u64>) {
    match stat(pid) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Liveness::Gone, None),
        Err(_) => (Liveness::Unknown, None),
        Ok(text) => match parse_stat(&text) {
            None => (Liveness::Unknown, None),
            Some(("Z", _)) => (Liveness::Gone, None),
            Some((_, start)) => (Liveness::Alive, Some(start)),
        },
    }
}

/// State and start time from `/proc/PID/stat`.
fn parse_stat(stat: &str) -> Option<(&str, u64)> {
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    Some((fields.first()?, fields.get(19)?.parse().ok()?))
}

pub fn starttime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat(&stat).filter(|(state, _)| *state != "Z").map(|(_, start)| start)
}

/// Test faults (`RUN/faults.json`); only with FLEXVM_FAULTS=1.
pub fn fault(name: &str) -> bool {
    static CACHE: Mutex<Option<(SystemTime, HashMap<String, u64>)>> = Mutex::new(None);
    static ON: OnceLock<bool> = OnceLock::new();
    if !*ON.get_or_init(|| std::env::var("FLEXVM_FAULTS").is_ok_and(|v| v == "1")) {
        return false;
    }
    let Some(path) = RUN_DIR.get().map(|r| r.join("faults.json")) else { return false };
    let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    let mut c = CACHE.lock().unwrap();
    if c.as_ref().map(|c| Some(c.0)) != Some(mtime) {
        *c = mtime.map(|m| (m, load(&path).ok().flatten().unwrap_or_default()));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    c.as_ref().is_some_and(|(_, armed)| armed.get(name).is_some_and(|&until| now < until))
}

/// Test hook: a window for a test to kill the process here.
pub fn stall(name: &str) {
    if fault(name) {
        std::thread::sleep(Duration::from_secs(3));
    }
}

pub fn arm(host: &Host, name: &str, ms: u64) -> Result<()> {
    let _l = host.lock()?;
    let path = host.run.join("faults.json");
    let mut armed: HashMap<String, u64> = load(&path).ok().flatten().unwrap_or_default();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    armed.retain(|_, &mut until| until > now);
    match ms {
        0 => armed.remove(name),
        _ => armed.insert(name.into(), now + ms),
    };
    store(&path, &armed, false)?;
    // Ensure the next write changes the mtime the cache keys on.
    std::thread::sleep(Duration::from_millis(10));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(tag: &str) -> Host {
        let base = std::env::temp_dir().join(format!("flexvm-host-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let mut h = Host::open(&base.join("state"), &base.join("run")).unwrap();
        h.cfg.vm_ips = "10.9.0.1-10.9.0.3".into();
        h
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn run_directory_creation_errors_name_the_path() {
        use std::os::unix::fs::PermissionsExt;

        let h = host("run-error");
        let base = h.state.parent().unwrap();
        std::fs::remove_dir_all(&h.run).unwrap();
        std::fs::write(&h.run, "").unwrap();
        let e = Host::open(&h.state, &h.run).err().unwrap().to_string();
        assert!(e.contains(h.run.to_str().unwrap()), "{e}");
        std::fs::remove_file(&h.run).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            let mode = |d: &Path, m| std::fs::set_permissions(d, std::fs::Permissions::from_mode(m)).unwrap();
            mode(base, 0o555);
            let result = Host::open(&h.state, &h.run);
            mode(base, 0o755);
            let e = result.err().unwrap().to_string();
            assert!(e.contains(h.run.to_str().unwrap()) && e.contains("run flexvm as root to create it"), "{e}");
            // A run directory someone else made, without all its subdirectories, still opens.
            std::fs::create_dir(&h.run).unwrap();
            mode(&h.run, 0o555);
            let result = Host::open(&h.state, &h.run);
            mode(&h.run, 0o755);
            result.unwrap();
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn state_directories_are_synced_once_and_remade() {
        let h = host("synced");
        let marker = std::fs::read_to_string(h.state.join(".synced")).unwrap();
        std::fs::remove_dir(h.state.join("standby")).unwrap();
        // Copied from another root: synced again.
        std::fs::write(h.state.join(".synced"), "1 2").unwrap();
        Host::open(&h.state, &h.run).unwrap();
        assert!(h.state.join("standby").is_dir());
        assert_eq!(std::fs::read_to_string(h.state.join(".synced")).unwrap(), marker);
        std::fs::remove_dir_all(h.state.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_wildcard_listener_advertises_its_underlay() {
        let cfg = |listen: Option<&str>, underlay: Option<&str>| Config { listen: listen.map(String::from), underlay: underlay.map(ip), ..Config::default() };
        assert_eq!(cfg(None, None).advertise().unwrap(), None);
        assert_eq!(cfg(Some("10.1.0.1:7070"), None).advertise().unwrap().as_deref(), Some("10.1.0.1:7070"));
        assert_eq!(cfg(Some("10.1.0.1:7070"), Some("10.1.0.2")).advertise().unwrap().as_deref(), Some("10.1.0.1:7070"));
        assert_eq!(cfg(Some("peer.lan:7070"), None).advertise().unwrap().as_deref(), Some("peer.lan:7070"));
        for wild in ["0.0.0.0:7070", "[::]:7070"] {
            assert!(cfg(Some(wild), None).advertise().is_err(), "{wild}");
            assert_eq!(cfg(Some(wild), None).underlay(), None, "{wild}");
            assert_eq!(cfg(Some(wild), Some("10.1.0.2")).advertise().unwrap().as_deref(), Some("10.1.0.2:7070"), "{wild}");
        }
        assert!(cfg(Some("0.0.0.0:7070"), Some("0.0.0.0")).advertise().is_err());
        // An IPv4-mapped wildcard binds as 0.0.0.0; a mapped address is its IPv4 one.
        assert!(cfg(Some("[::ffff:0:0]:7070"), None).advertise().is_err());
        assert_eq!(cfg(Some("[::ffff:0:0]:7070"), Some("10.1.0.2")).advertise().unwrap().as_deref(), Some("10.1.0.2:7070"));
        assert_eq!(cfg(Some("[::ffff:10.1.0.1]:7070"), None).advertise().unwrap().as_deref(), Some("10.1.0.1:7070"));
        assert_eq!(cfg(Some("[::ffff:10.1.0.1]:7070"), None).underlay(), Some(ip("10.1.0.1")));
        // Link-local: its scope id names an interface of this host only.
        for ll in ["[fe80::1%3]:7070", "[fe80::1]:7070"] {
            assert!(cfg(Some(ll), None).advertise().is_err(), "{ll}");
            assert_eq!(cfg(Some(ll), Some("10.1.0.2")).advertise().unwrap().as_deref(), Some("10.1.0.2:7070"), "{ll}");
        }
        assert_eq!(cfg(Some("[2001:db8::1]:7070"), None).advertise().unwrap().as_deref(), Some("[2001:db8::1]:7070"));
        // Port 0 would be advertised as such.
        for p0 in ["10.1.0.1:0", "0.0.0.0:0", "[::]:0"] {
            assert!(cfg(Some(p0), Some("10.1.0.2")).advertise().is_err(), "{p0}");
        }
    }

    fn dead_owner(h: &Host, pid: u32, fcs: &[&Ident]) -> Ident {
        let dead = Ident { pid, start: 1, boot: boot_id().into() };
        let dir = dead.work_dir(&h.run);
        for (i, fc) in fcs.iter().enumerate() {
            std::fs::create_dir_all(dir.join(i.to_string())).unwrap();
            store(&dir.join(i.to_string()).join("fc"), fc, false).unwrap();
        }
        std::fs::create_dir_all(&dir).unwrap();
        store(&dir.join("owner"), &dead, false).unwrap();
        dead
    }

    struct Sleeper(std::process::Child, Ident);

    impl Sleeper {
        fn new() -> Sleeper {
            let c = std::process::Command::new("sleep").arg("60").spawn().unwrap();
            let id = Ident::of(c.id()).unwrap();
            Sleeper(c, id)
        }
        fn done(mut self) -> bool {
            let killed = !self.1.alive();
            let _ = self.0.kill();
            let _ = self.0.wait();
            killed
        }
    }

    #[test]
    fn names_are_locked_for_life() {
        let h = host("names");
        let a = h.take_name("a", false).unwrap();
        assert!(h.take_name("a", false).is_err());
        a.publish(&Entry { name: "a".into(), ident: Ident::me(), ..Entry::default() }).unwrap();
        assert!(h.alive("a") && h.entries().len() == 1);
        a.publish(&Entry { name: "a".into(), ident: Ident { start: 1, ..Ident::me() }, ..Entry::default() }).unwrap();
        assert!(h.entry("a").is_err() && h.signal("a", 0).is_err());
        drop(a);
        assert!(!h.alive("a") && h.entries().is_empty() && h.entry("a").is_err());
        let _again = h.take_name("a", false).unwrap();
        for bad in ["", ".x", "a/b", &"x".repeat(65)] {
            assert!(h.take_name(bad, false).is_err());
        }
        std::fs::create_dir_all(h.suspended("s")).unwrap();
        std::fs::write(h.suspended("s").join("manifest.json"), "").unwrap();
        assert!(h.take_name("s", false).is_err() && h.take_name("s", true).is_ok());
    }

    #[test]
    fn suspend_debris_is_removed_by_the_names_next_holder() {
        let h = host("debris");
        let dir = |n: &str, files: &[&str]| {
            std::fs::create_dir_all(h.suspended(n)).unwrap();
            files.iter().for_each(|f| std::fs::write(h.suspended(n).join(f), "").unwrap());
        };
        // No manifest (an interrupted removal or revoke), consumed, discarded.
        dir("bare", &["GEN", "pages"]);
        dir("started", &["manifest.json", "STARTED"]);
        dir("discarded", &["manifest.json", "DISCARDED"]);
        dir("quarantined", &["manifest.json", "STARTED", "QUARANTINE"]);
        for n in ["bare", "started", "discarded", "quarantined"] {
            assert!(!h.is_suspended(n));
            drop(h.take_name(n, false).unwrap());
            assert!(!h.suspended(n).exists(), "{n}");
        }
        // A suspended VM, quarantined or not, stays.
        dir("kept", &["manifest.json"]);
        dir("held", &["manifest.json", "QUARANTINE"]);
        for n in ["kept", "held"] {
            assert!(h.is_suspended(n) && h.take_name(n, false).is_err());
            drop(h.take_name(n, true).unwrap());
            assert!(h.suspended(n).exists());
        }
        // Held by a live process, it is not touched.
        let _live = h.take_name("live", true).unwrap();
        dir("live", &["GEN"]);
        assert!(h.take_name("live", false).is_err() && h.suspended("live").exists());
    }

    #[test]
    fn a_dead_holders_firecrackers_die_before_its_name_or_address_is_free() {
        let h = host("reap");
        let fc = Sleeper::new();
        store(&h.vms("d", "lock"), &dead_owner(&h, 999_999_901, &[&fc.1]), false).unwrap();
        let l = h.lock().unwrap();
        h.put_addr(ip("10.9.0.1"), &Addr { seen: 1, holder: Some("d".into()), ..Addr::default() }, false).unwrap();
        assert!(fc.1.alive());
        assert!(h.claim_new(&l, "x", Some(ip("10.9.0.1"))).unwrap().gen > 1 && fc.done());
        let fc = Sleeper::new();
        store(&h.vms("e", "lock"), &dead_owner(&h, 999_999_902, &[&fc.1]), false).unwrap();
        let _e = h.take_name("e", false).unwrap();
        assert!(fc.done());
        let fc = Sleeper::new();
        dead_owner(&h, 999_999_903, &[&fc.1]);
        reap(&h.run, &Ident { pid: 999_999_903, start: 2, boot: boot_id().into() }).unwrap();
        assert!(!fc.done());
        // A killed holder's name is let go of by the garbage collector; a live one's is not.
        let fc = Sleeper::new();
        store(&h.vms("k", "lock"), &dead_owner(&h, 999_999_904, &[&fc.1]), false).unwrap();
        std::fs::write(h.vms("k", "failed"), "why").unwrap();
        collect_owned(&h.run);
        assert!(fc.done() && !h.vms("k", "lock").exists() && h.vms("k", "failed").exists());
        assert!(h.vms("e", "lock").exists());
    }

    #[test]
    fn addresses_generations_and_loans() {
        let h = host("addrs");
        let _a = h.take_name("a", false).unwrap();
        let l = h.lock().unwrap();
        let a = h.claim_new(&l, "a", None).unwrap();
        let (a_ip, g1) = (a.ip, a.gen);
        assert_eq!(a_ip, ip("10.9.0.1"));
        let b = h.claim_new(&l, "b-dead", None).unwrap();
        assert!(b.ip == ip("10.9.0.2") && b.gen > g1);
        let c = h.claim_new(&l, "c", Some(b.ip)).unwrap();
        assert!(c.gen > b.gen);
        b.keep();
        c.keep();
        assert!(h.claim_new(&l, "x", Some(a_ip)).is_err() && h.claim_new(&l, "x", Some(ip("10.9.9.9"))).is_err());
        h.lend(&l, a_ip, g1).unwrap();
        a.release(&l).unwrap();
        assert!(h.claim_new(&l, "x", Some(a_ip)).is_err());
        assert!(!h.observe(&l, a_ip, g1 - 1, 0, None).unwrap(), "older withdrawal is stale");
        assert!(h.addr(&l, a_ip).unwrap().lent.is_some());
        assert!(h.observe(&l, a_ip, g1, 0, None).unwrap() && h.addr(&l, a_ip).unwrap().lent.is_none());
        let via = Some(ip("192.0.2.1"));
        assert!(!h.observe(&l, a_ip, g1, 0, via).unwrap() && !h.current(&l, a_ip, g1).unwrap());
        assert!(h.observe(&l, a_ip, g1 + 5, 0, via).unwrap() && h.addr(&l, a_ip).unwrap().via == via);
        assert!(h.claim_incoming(&l, "y", a_ip, g1, None).is_err() && h.claim_incoming(&l, "y", a_ip, 0, None).is_err());
        h.claim_incoming(&l, "y", a_ip, g1 + 5, None).unwrap().keep();
        drop(h.fence(a_ip, g1 + 5).unwrap());
        assert!(h.observe(&l, a_ip, g1 + 5, 0, None).unwrap());
        h.claim_incoming(&l, "y", a_ip, g1 + 6, None).unwrap().keep();
        assert!(h.current(&l, a_ip, g1 + 6).unwrap());
        let _w = h.take_name("w", false).unwrap();
        let wc = h.claim_new(&l, "w", Some(ip("10.9.0.3"))).unwrap();
        assert!(h.claim_incoming(&l, "w2", wc.ip, wc.gen, None).is_err());
        assert_eq!(h.holder(&l, wc.ip).unwrap().as_deref(), Some("w"));
        drop(h.claim_new(&l, "v", None));
        assert_eq!(h.holder(&l, wc.ip).unwrap().as_deref(), Some("w"));
        wc.keep();
        std::fs::write(h.addr_path(ip("10.9.0.3")), "{").unwrap();
        assert!(h.addr(&l, ip("10.9.0.3")).is_err() && h.claim_new(&l, "z", Some(ip("10.9.0.3"))).is_err());
        std::fs::write(h.state.join("addrs/.gens"), r#"{"next": 7, "reserved": 2048, "boot": "other"}"#).unwrap();
        assert!(h.claim_new(&l, "z", None).unwrap().gen >= 2048);
        std::fs::write(h.state.join("addrs/.gens"), "x").unwrap();
        assert!(h.claim_new(&l, "z", None).is_err());
    }

    #[test]
    fn an_address_is_held_by_the_instance_that_claimed_it() {
        let h = host("instances");
        let (x, y) = (ip("10.9.0.1"), ip("10.9.0.2"));
        // `web` SIGKILLed at x (its Firecracker still running), and an earlier crash's claim at y.
        let fc = Sleeper::new();
        let dead = dead_owner(&h, 999_999_911, &[&fc.1]);
        store(&h.vms("web", "lock"), &dead, false).unwrap();
        let l = h.lock().unwrap();
        h.put_addr(x, &Addr { seen: 1, holder: Some("web".into()), holder_id: Some(dead.clone()), held: 1, ..Addr::default() }, false).unwrap();
        let older = Ident { pid: 999_999_912, ..dead.clone() };
        h.put_addr(y, &Addr { seen: 2, holder: Some("web".into()), holder_id: Some(older), held: 2, ..Addr::default() }, false).unwrap();
        // The restart takes the name (reaping it), then the same address.
        let _web = h.take_name("web", false).unwrap();
        assert!(fc.done());
        assert_eq!(h.holder(&l, y).unwrap(), None, "a dead instance's claim is not the new one's");
        assert_eq!(h.holder(&l, x).unwrap(), None);
        let c = h.claim_new(&l, "web", Some(x)).unwrap();
        assert!(c.gen > 1 && h.addr(&l, x).unwrap().holder_id == Some(Ident::me()));
        assert_eq!(h.holder(&l, x).unwrap().as_deref(), Some("web"));
        // Automatic allocation takes the stale claim's address too.
        let d = h.claim_new(&l, "web", None).unwrap();
        assert_eq!(d.ip, y);
        d.keep();
        // A live process that does not hold the name holds nothing.
        let other = Sleeper::new();
        h.put_addr(y, &Addr { seen: 3, holder: Some("web".into()), holder_id: Some(other.1.clone()), held: 3, ..Addr::default() }, false).unwrap();
        assert_eq!(h.holder(&l, y).unwrap(), None);
        assert!(!other.done());
        // An instance lets go of its own claim only, never a later one's of the same name.
        let mut a = h.addr(&l, x).unwrap();
        a.holder_id = Some(Ident { start: 1, ..Ident::me() });
        h.put_addr(x, &a, false).unwrap();
        c.release(&l).unwrap();
        assert_eq!(h.addr(&l, x).unwrap().holder.as_deref(), Some("web"));
        h.release(&l, x, "web", None).unwrap();
        assert_eq!(h.addr(&l, x).unwrap().holder, None, "by name: a suspended VM's, whoever suspended it");
        // Suspended here, it holds the address of its own generation only.
        std::fs::create_dir_all(h.suspended("s")).unwrap();
        std::fs::write(h.suspended("s").join("manifest.json"), "").unwrap();
        let gone = Ident { pid: 999_999_913, ..dead };
        h.put_addr(x, &Addr { seen: 5, holder: Some("s".into()), holder_id: Some(gone), held: 5, ..Addr::default() }, false).unwrap();
        assert_eq!(h.holder(&l, x).unwrap().as_deref(), Some("s"), "quarantined (no GEN): kept");
        std::fs::write(h.suspended("s").join("GEN"), "5").unwrap();
        assert_eq!(h.holder(&l, x).unwrap().as_deref(), Some("s"));
        std::fs::write(h.suspended("s").join("GEN"), "6").unwrap();
        assert_eq!(h.holder(&l, x).unwrap(), None, "suspended with another address");
        // Records from before instances were recorded go by the name.
        h.put_addr(x, &Addr { seen: 7, holder: Some("web".into()), held: 7, ..Addr::default() }, false).unwrap();
        assert_eq!(h.holder(&l, x).unwrap().as_deref(), Some("web"));
    }

    #[test]
    fn what_cannot_be_read_is_never_proof_of_death() {
        let h = host("unreadable");
        // A dead owner whose work directory's owner record cannot be read: not reaped.
        let dead = dead_owner(&h, 999_999_921, &[]);
        let owner = dead.work_dir(&h.run).join("owner");
        std::fs::remove_file(&owner).unwrap();
        std::fs::create_dir(&owner).unwrap();
        assert!(reap(&h.run, &dead).is_err());
        // Nor one with an unreadable Firecracker record.
        let dead = dead_owner(&h, 999_999_922, &[]);
        std::fs::create_dir_all(dead.work_dir(&h.run).join("0/fc")).unwrap();
        assert!(reap(&h.run, &dead).is_err());
        // A name whose lock cannot be read is not free, and its address stays held.
        std::fs::write(h.vms("u", "lock"), "{").unwrap();
        let l = h.lock().unwrap();
        h.put_addr(ip("10.9.0.1"), &Addr { seen: 1, holder: Some("u".into()), held: 1, ..Addr::default() }, false).unwrap();
        assert!(h.take_name("u", false).is_err() && !h.gone("u"));
        assert_eq!(h.holder(&l, ip("10.9.0.1")).unwrap().as_deref(), Some("u"));
        collect_owned(&h.run);
        assert!(h.vms("u", "lock").exists(), "kept by the garbage collector too");
        // An empty lock (created, never written) is no holder.
        std::fs::write(h.vms("e", "lock"), "").unwrap();
        assert!(h.take_name("e", false).is_ok());
        // A live holder whose lock record cannot be read keeps its address.
        let _v = h.take_name("v", false).unwrap();
        let x = h.claim_new(&l, "v", Some(ip("10.9.0.2"))).unwrap();
        for unreadable in ["{", ""] {
            std::fs::write(h.vms("v", "lock"), unreadable).unwrap();
            assert_eq!(h.holder(&l, x.ip).unwrap().as_deref(), Some("v"), "{unreadable:?}");
            assert!(h.claim_new(&l, "w", Some(x.ip)).is_err() && h.lend_new(&l, x.ip).is_err());
        }
        // Read, and naming another instance: not this claim's holder.
        store(&h.vms("v", "lock"), &Ident { start: 1, ..Ident::me() }, false).unwrap();
        assert_eq!(h.holder(&l, x.ip).unwrap(), None);
        x.keep();
    }

    #[test]
    fn taps_and_cgroups_name_their_process() {
        assert_eq!(tap_owner("fv1a2bt0", "fv"), Some(0x1a2b));
        assert_eq!(tap_owner("fv1a2bt1f", "fv"), Some(0x1a2b));
        assert_eq!(tap_owner("fvxf0ac", "fv"), Some(0xf0ac), "a template build's");
        assert_eq!(tap_owner("fvci0.1ax3fffff", "fvci0.1a"), Some(0x3fffff));
        assert_eq!(tap_owner("fvtpl61612", "fv"), Some(61612), "an earlier template build's");
        for (tap, prefix) in [
            ("fvtpl61612", "fc"),
            ("fvtpl", "fv"),
            ("fvtpl12x", "fv"),
            ("fvtpl+1", "fv"),
            ("fvx", "fv"),
            ("fvx+1", "fv"),
            ("fvxg", "fv"),
            ("eth0", "fv"),
            ("fvxyz", "fv"),
        ] {
            assert_eq!(tap_owner(tap, prefix), None, "{tap} under {prefix}");
        }
        assert_eq!(cgroup_owner("idle-4242-77-3"), Some(Ident { pid: 4242, start: 77, boot: boot_id().into() }));
        for cg in ["vm-4242", "vm-4242-77", "other-42", "idle-", "idle-4242-3", "idle-4242-x-3", "idle-1-2-3-4", "cgroup.procs", "memory.max"] {
            assert_eq!(cgroup_owner(cg), None, "{cg}");
        }
    }

    /// The tap prefix never changes while a VM process (any work directory
    /// not proven gone) may have taps under the old one, and a process reads
    /// it only after its work directory is there.
    #[test]
    fn the_tap_prefix_never_changes_under_a_vm_process() {
        fn prefix(p: &str) -> impl FnOnce(&mut Config) -> Result<()> + '_ {
            move |c| {
                c.prefix = p.into();
                Ok(())
            }
        }
        let mut h = host("prefix");
        // Not from the default (`fv`), whose taps this machine may have.
        store(&h.state.join("host.json"), &Config { prefix: "zq1".into(), ..Config::default() }, false).unwrap();
        let w = h.run.join("w").join("4242");
        std::fs::create_dir_all(&w).unwrap();
        // Not yet written: a process just starting.
        let e = h.configure(prefix("zq")).unwrap_err().to_string();
        assert!(e.contains("vm process 4242"), "{e}");
        store(&w.join("owner"), &Ident::me(), false).unwrap();
        assert!(h.configure(prefix("zq")).is_err(), "a live one");
        assert_eq!(h.tap_prefix().unwrap(), "zq1");
        h.configure(|c| {
            c.reserve_mib = 7;
            Ok(())
        })
        .unwrap();
        store(&w.join("owner"), &Ident { pid: 999_999_930, start: 1, boot: boot_id().into() }, false).unwrap();
        assert!(h.prefix_in_use_at("zq", &h.run.join("no-such-net")).is_some(), "the taps unreadable");
        h.configure(prefix("zq")).unwrap();
        assert_eq!(h.tap_prefix().unwrap(), "zq");
        // A tap already read as one under the new prefix.
        let net = h.run.join("net");
        std::fs::create_dir_all(net.join("zq21t0")).unwrap();
        assert!(h.prefix_in_use_at("zq2", &net).unwrap().contains("zq21t0"));
        assert!(h.prefix_in_use_at("zq3", &net).is_none());
        // The work directories unreadable.
        std::fs::remove_dir_all(h.run.join("w")).unwrap();
        assert!(h.prefix_in_use_at("zq3", &net).is_some());
    }

    /// A tap is this host's by its alias alone, whatever its name: hosts
    /// whose prefixes overlap (`fq`, `fq2`) never take each other's.
    #[test]
    fn taps_are_this_hosts_by_their_alias() {
        let h = host("alias");
        let me = Ident::me();
        let alias = tap_alias(&h.run, &me);
        assert_eq!(parse_tap_alias(&alias), Some((me.clone(), &*h.run.to_string_lossy())));
        for bad in ["", "flexvm", "flexvm 1 2", "flexvm 1 2 ", "flexvm x 2 /r", "flexvm 1 y /r", "flexvm1 2 /r", "other 1 2 /r"] {
            assert_eq!(parse_tap_alias(bad), None, "{bad:?}");
        }
        assert_eq!(parse_tap_alias("flexvm 1 2 /run/a b").map(|(o, r)| (o.pid, o.start, r)), Some((1, 2, "/run/a b")));
        let net = h.run.join("net");
        let other = h.run.join("other");
        let dead = Ident { pid: 999_999_931, start: 1, boot: boot_id().into() };
        let dev = |name: &str, index: u32, alias: &str, tun: bool| {
            let d = net.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("ifindex"), format!("{index}\n")).unwrap();
            std::fs::write(d.join("ifalias"), format!("{alias}\n")).unwrap();
            if tun {
                std::fs::write(d.join("tun_flags"), "0x1802\n").unwrap();
            }
        };
        dev("fq3e7t0", 10, &tap_alias(&h.run, &dead), true);
        dev("fqx3e7", 11, &tap_alias(&h.run, &me), true);
        // Host `fq2`'s live and dead taps, which read under `fq` as pids 0x21a2b, 0x21a2c.
        dev("fq21a2bt0", 12, &tap_alias(&other, &me), true);
        dev("fq21a2ct0", 13, &tap_alias(&other, &dead), true);
        dev("fq1t0", 14, "", true);
        dev("fq2t0", 15, &tap_alias(&h.run, &dead), false);
        let mut got = taps_of_at(&h.run, &net);
        got.sort_by_key(|t| t.1);
        assert_eq!(got, vec![("fq3e7t0".into(), 10, dead.clone()), ("fqx3e7".into(), 11, me.clone())]);
        let mut theirs = taps_of_at(&other, &net);
        theirs.sort_by_key(|t| t.1);
        assert_eq!(theirs, vec![("fq21a2bt0".into(), 12, me), ("fq21a2ct0".into(), 13, dead)]);
    }

    /// One saved under the earlier 8-character limit is refused where it is read.
    #[test]
    fn a_stored_prefix_is_checked_where_read() {
        let h = host("oldprefix");
        for (p, ok) in [("fv", true), ("fvci0a", true), ("fvci10a", false), ("fvci0.1a", false), ("", false), ("f/v", false)] {
            store(&h.state.join("host.json"), &Config { prefix: p.into(), ..Config::default() }, false).unwrap();
            let got = h.tap_prefix();
            assert_eq!(got.is_ok(), ok, "{p:?}: {got:?}");
            if let Err(e) = got {
                assert!(e.to_string().contains("flexvm config --prefix"), "{e}");
            }
        }
    }

    /// A VM process's own cgroup goes only once empty, whatever its pid
    /// (a reused one may have joined it): never killed.
    #[test]
    fn a_scope_goes_only_once_empty() {
        let d = std::env::temp_dir().join(format!("flexvm-scope-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (busy, unread) = (d.join("vm-1-1"), d.join("vm-2-2"));
        for cg in [&busy, &unread] {
            std::fs::create_dir_all(cg).unwrap();
        }
        std::fs::write(busy.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        sweep_scope(&busy);
        sweep_scope(&unread);
        assert!(busy.exists() && unread.exists(), "populated or unreadable: kept");
        assert!(!busy.join("cgroup.kill").exists(), "never killed");
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn an_empty_boot_id_is_never_proof_of_death() {
        let me = Ident::me();
        let running = format!("1 (x) S {}", "0 ".repeat(18) + &me.start.to_string());
        let stat = |_| Ok(running.clone());
        // Recorded without one: not "another boot".
        assert_eq!(liveness_by(&Ident { boot: String::new(), ..me.clone() }, boot_id(), stat), Liveness::Unknown);
        // Ours unreadable: nothing can be told.
        assert_eq!(liveness_by(&me, "", stat), Liveness::Unknown);
        assert_eq!(liveness_by(&Ident { boot: "other".into(), ..me.clone() }, boot_id(), stat), Liveness::Gone);
        let h = host("noboot");
        let dead = Ident { pid: 999_999_931, start: 1, boot: String::new() };
        assert!(reap(&h.run, &dead).is_err(), "never reaped as another boot's");
        assert!(!boot_id().is_empty() && Ident::of(std::process::id()).is_some_and(|i| i.boot == boot_id()));
    }

    #[test]
    fn automatic_allocation_goes_on_from_the_last_one() {
        let h = host("hint");
        let l = h.lock().unwrap();
        let a = h.claim_new(&l, "a", None).unwrap();
        assert_eq!(a.ip, ip("10.9.0.1"));
        drop(a);
        // Free again, but the next allocation starts after it.
        let b = h.claim_new(&l, "b", None).unwrap();
        assert_eq!(b.ip, ip("10.9.0.2"));
        b.keep();
        let _c = h.take_name("c", false).unwrap();
        let c = h.claim_new(&l, "c", None).unwrap();
        assert_eq!(c.ip, ip("10.9.0.3"));
        // Wraps around, skipping what is taken (b's name is not held: its claim is stale).
        let _d = h.take_name("d", false).unwrap();
        let d = h.claim_new(&l, "d", None).unwrap();
        assert_eq!(d.ip, ip("10.9.0.1"));
        let _e = h.take_name("e", false).unwrap();
        let e = h.claim_new(&l, "e", None).unwrap();
        assert_eq!(e.ip, ip("10.9.0.2"));
        // A garbled hint is only a hint.
        std::fs::write(h.alloc_hint(), "junk").unwrap();
        assert!(h.claim_new(&l, "e", None).is_err(), "all taken");
        drop((c, d, e));
        assert_eq!(h.claim_new(&l, "e", None).unwrap().ip, ip("10.9.0.1"));
    }

    #[test]
    fn revisions_order_locations_within_a_generation() {
        let h = host("revs");
        let l = h.lock().unwrap();
        let (x, a, b) = (ip("10.9.0.1"), Some(ip("192.0.2.1")), Some(ip("192.0.2.2")));
        assert!(h.observe(&l, x, 7, 3, b).unwrap());
        assert!(!h.observe(&l, x, 7, 2, a).unwrap() && h.addr(&l, x).unwrap().via == b, "a source's delayed announcement is stale");
        assert!(h.observe(&l, x, 7, 3, b).unwrap(), "repeated");
        let _y = h.take_name("y", false).unwrap();
        assert_eq!(h.claim_incoming(&l, "y", x, 7, None).unwrap().rev, 4, "past the newest recorded");
        assert_eq!(h.claim_incoming(&l, "y", x, 7, Some(9)).unwrap().rev, 9);
        assert!(h.observe(&l, x, 7, 4, b).unwrap(), "an arrival's revision counts only once it commits");
        h.advance(&l, x, 7, 6).unwrap();
        assert!(!h.observe(&l, x, 7, 5, b).unwrap());
        assert!(h.observe(&l, x, 8, 0, a).unwrap(), "a newer generation starts over");
        assert!(h.observe(&l, x, 8, 0, None).unwrap() && !h.observe(&l, x, 8, 9, b).unwrap(), "a withdrawal takes every revision");
    }

    #[test]
    fn addresses_are_lent_to_restoring_peers_only_when_free() {
        let h = host("lend");
        let l = h.lock().unwrap();
        let x = ip("10.9.0.2");
        assert!(h.lend_new(&l, ip("10.9.9.9")).is_err(), "not ours");
        let g = h.lend_new(&l, x).unwrap();
        assert!(h.lend_new(&l, x).unwrap_err().to_string().contains("lent"));
        assert!(h.claim_new(&l, "x", Some(x)).err().unwrap().to_string().contains("lent"));
        assert!(h.observe(&l, x, g, 0, None).unwrap());
        let _x = h.take_name("x", false).unwrap();
        let c = h.claim_new(&l, "x", Some(x)).unwrap();
        assert!(c.gen > g && c.fresh);
        assert!(h.lend_new(&l, x).unwrap_err().to_string().contains("in use"));
    }

    fn released_migration(h: &Host, id: u64, source: &str) {
        store(&h.mig_path(id), &Mig::Released { source: source.into(), by: Some(Ident { start: id, ..Ident::me() }) }, false).unwrap();
    }

    #[test]
    fn retirement_respects_record_budget() {
        let h = host("retire-budget");
        for id in 1..=8 {
            released_migration(&h, id, "reachable");
        }
        h.retire_migrations_with(0, |_, _| panic!("zero budget must not query"));
        assert!(!h.run.join(".retire.next").exists());
        let mut queried = Vec::new();
        h.retire_migrations_with(3, |_, by| {
            queried.push(by.start);
            Ok(false)
        });
        assert_eq!(queried, [1, 2, 3]);
        assert_eq!(load::<u64>(&h.run.join(".retire.next")).unwrap(), Some(3));
        assert!((1..=8).all(|id| h.mig_path(id).exists()), "a source still present keeps every record");
    }

    #[test]
    fn retirement_continues_across_passes_and_wraps() {
        let h = host("retire-continue");
        for id in 1..=6 {
            released_migration(&h, id, "reachable");
        }
        let pass = |h: &Host| {
            let mut queried = Vec::new();
            h.retire_migrations_with(2, |_, by| {
                queried.push(by.start);
                Ok(false)
            });
            queried
        };
        assert_eq!(pass(&h), [1, 2]);
        // Removing an earlier record must not shift the continuation past ID 3.
        h.mig_done(1).unwrap();
        let reopened = Host::open(&h.state, &h.run).unwrap();
        assert_eq!(pass(&reopened), [3, 4]);
        assert_eq!(pass(&reopened), [5, 6]);
        assert_eq!(pass(&reopened), [2, 3]);
    }

    #[test]
    fn retirement_skips_unavailable_endpoints_only_for_this_pass() {
        let h = host("retire-endpoints");
        for (id, source) in [(1, "unreachable"), (2, "reachable"), (3, "unreachable"), (4, "reachable"), (5, "unknown"), (6, "unreachable")] {
            released_migration(&h, id, source);
        }
        store(&h.mig_path(7), &Mig::Released { source: "reachable".into(), by: None }, false).unwrap();
        released_migration(&h, 8, "");
        let mut queried = Vec::new();
        h.retire_migrations_with(8, |source, by| {
            queried.push(by.start);
            match source {
                "unreachable" | "unknown" => Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into()),
                "reachable" => Ok(by.start == 4),
                _ => panic!("invalid source must not be queried"),
            }
        });
        assert_eq!(queried, [1, 2, 4, 5]);
        assert!(!h.mig_path(4).exists(), "only an explicit gone response retires a record");
        assert!([1, 2, 3, 5, 6, 7, 8].iter().all(|id| h.mig_path(*id).exists()));
        queried.clear();
        h.retire_migrations_with(3, |_, by| {
            queried.push(by.start);
            Ok(false)
        });
        assert_eq!(queried, [1, 2, 3], "a later pass retries the endpoint");
    }

    #[test]
    fn retirement_uses_its_own_nonblocking_lock() {
        let h = host("retire-lock");
        released_migration(&h, 1, "reachable");
        let gc = File::create(h.run.join(".gc.lock")).unwrap();
        flock(&gc, libc::LOCK_EX | libc::LOCK_NB).unwrap();
        let mut queried = false;
        h.retire_migrations_with(1, |_, _| {
            let retirement = File::open(h.run.join(".retire.lock")).unwrap();
            assert!(flock(&retirement, libc::LOCK_EX | libc::LOCK_NB).is_err());
            queried = true;
            Ok(false)
        });
        assert!(queried, "the local cleanup lock does not block retirement");
        let retirement = File::open(h.run.join(".retire.lock")).unwrap();
        flock(&retirement, libc::LOCK_EX | libc::LOCK_NB).unwrap();
        h.retire_migrations_with(1, |_, _| panic!("busy retirement must be skipped"));
    }

    #[test]
    fn migrations_are_fenced() {
        let h = host("migs");
        let rec = |id: u64| load::<Mig>(&h.mig_path(id)).unwrap();
        assert!(h.mig_status(1).unwrap() == "aborted" && rec(1).is_none());
        let r = h.mig_begin(2, "", None, None).unwrap();
        assert!(h.mig_begin(2, "", None, None).is_err() && h.mig_status(2).unwrap() == "pending");
        drop(r);
        assert_eq!(h.mig_status(2).unwrap(), "aborted");
        let mut r = h.mig_begin(3, "", None, None).unwrap();
        r.commit(&h.lock().unwrap()).unwrap();
        h.mig_done(3).unwrap();
        assert_eq!(h.mig_status(3).unwrap(), "committed", "only a released one is forgotten");
        // A VM back home: its loan stays through the commit, and goes with the release.
        let (home, lent) = (ip("10.9.0.3"), |h: &Host| h.addr(&h.lock().unwrap(), ip("10.9.0.3")).unwrap().lent);
        assert!(h.lend(&h.lock().unwrap(), home, 9).unwrap(), "made the loan");
        assert!(!h.lend(&h.lock().unwrap(), home, 9).unwrap(), "a loan it did not make is not its to undo");
        assert_eq!(lent(&h), Some(9));
        r.release(Some((home, 9)), None).unwrap();
        assert!(h.mig_status(3).unwrap() == "released" && lent(&h).is_none());
        h.mig_done(3).unwrap();
        assert!(rec(3).is_none());
        let mut r = h.mig_begin(4, "", None, None).unwrap();
        store(&h.mig_path(4), &Mig::Pending { owner: dead_owner(&h, 999_999_904, &[]), ip: None }, false).unwrap();
        assert!(h.mig_status(4).unwrap() == "aborted" && rec(4).is_none() && r.commit(&h.lock().unwrap()).is_err());
        // A dead arrival's route that cannot be put back yet keeps its record, for the next query.
        let back = ip("10.9.0.4");
        std::fs::write(h.addr_path(back), "{").unwrap();
        store(&h.mig_path(10), &Mig::Pending { owner: dead_owner(&h, 999_999_910, &[]), ip: Some(back) }, false).unwrap();
        assert!(h.mig_status(10).unwrap() == "aborted" && rec(10).is_some(), "kept while its route cannot be put back");
        std::fs::remove_file(h.addr_path(back)).unwrap();
        assert!(h.mig_status(10).unwrap() == "aborted" && rec(10).is_none());
        let fc = Sleeper::new();
        store(&h.mig_path(5), &Mig::Committed { owner: dead_owner(&h, 999_999_905, &[&fc.1]) }, false).unwrap();
        assert!(h.mig_status(5).unwrap() == "aborted" && fc.done() && rec(5).is_none());
        let mut r = h.mig_begin(7, "", None, None).unwrap();
        r.commit(&h.lock().unwrap()).unwrap();
        r.settle(true);
        assert_eq!(h.mig_status(7).unwrap(), "released");
        // A source that cannot be asked keeps its released record.
        store(&h.mig_path(8), &Mig::Released { source: "127.0.0.1:1".into(), by: Some(Ident::me()) }, false).unwrap();
        // Only proof retires: another boot, no such pid, or another process with the pid.
        let me = Ident::me();
        assert_eq!(me.liveness(), Liveness::Alive);
        for other in [Ident { boot: "other".into(), ..me.clone() }, Ident { pid: 999_999_999, ..me.clone() }, Ident { start: me.start + 1, ..me.clone() }] {
            assert_eq!(other.liveness(), Liveness::Gone, "{other:?}");
        }
        // A bounded lock gives up while another thread holds it.
        let (held, release) = (std::sync::mpsc::channel(), std::sync::mpsc::channel::<()>());
        let other = h.clone();
        let t = std::thread::spawn(move || {
            let _l = other.lock().unwrap();
            held.0.send(()).unwrap();
            release.1.recv().unwrap();
        });
        held.1.recv().unwrap();
        let start = std::time::Instant::now();
        let err = h.lock_by(Some(start + Duration::from_millis(50))).err().unwrap();
        assert_eq!(err.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::WouldBlock);
        assert!(start.elapsed() < Duration::from_secs(1));
        release.0.send(()).unwrap();
        t.join().unwrap();
        // Had once let go of; not within 1 s, as other tests' host locks take the same
        // per-process mutex, and one may hold it for longer than that.
        assert!(h.lock_by(Some(std::time::Instant::now() + Duration::from_secs(30))).is_ok());
        // Errors and garbage are unknown, never gone; a zombie is gone.
        let emfile = |_| Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        assert_eq!(liveness_by(&me, boot_id(), emfile), Liveness::Unknown);
        assert_eq!(liveness_by(&me, boot_id(), |_| Ok("garbage".into())), Liveness::Unknown);
        assert_eq!(liveness_by(&me, "", |_| Ok(String::new())), Liveness::Unknown);
        let zombie = format!("1 (x) Z {}", "0 ".repeat(18) + &me.start.to_string());
        assert_eq!(liveness_by(&me, boot_id(), |_| Ok(zombie.clone())), Liveness::Gone);
        let running = |start: u64| format!("1 (x) S {}", "0 ".repeat(18) + &start.to_string());
        assert_eq!(liveness_by(&me, boot_id(), |_| Ok(running(me.start))), Liveness::Alive);
        assert_eq!(liveness_by(&me, boot_id(), |_| Ok(running(me.start + 1))), Liveness::Gone, "pid reused");
        assert_eq!(pid_liveness_by(1, emfile).0, Liveness::Unknown, "a tap or cgroup of an unreadable pid is kept");
        // /proc/PID/stat of a process that finished exiting between open and read.
        let esrch = |_| Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        assert_eq!(pid_liveness_by(1, esrch).0, Liveness::Unknown, "a bare pid may be another process's by now");
        assert_eq!(liveness_by(&me, boot_id(), esrch), Liveness::Gone);
        // A dead owner's goes, as asking would make it go.
        store(&h.mig_path(9), &Mig::Committed { owner: dead_owner(&h, 999_999_909, &[]) }, false).unwrap();
        h.retire_migrations();
        assert!(h.mig_status(8).unwrap() == "released" && rec(9).is_none());
        std::fs::write(h.mig_path(6), "{").unwrap();
        assert!(h.mig_status(6).is_err());
    }

    /// MemAvailable for admission tests, fixed: the host's own moves with
    /// every other process, so no margin is ever safe.
    const AVAIL: u64 = 10_000;

    thread_local! {
        /// What `boottime_ms` reads on this test's thread, once pinned (`pin_clock`).
        pub(super) static PINNED_MS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    }

    /// Stops the clock grants are stamped and aged by, on this test's thread: other tests share
    /// the host lock's thread mutex, so on a loaded machine a grant can wait on it past
    /// `GRANT_WINDOW` (#294).
    fn pin_clock(ms: u64) {
        PINNED_MS.with(|p| p.set(Some(ms)));
    }

    /// `grant_inner` against `AVAIL`.
    fn grant_at(h: &Host, mib: u64, floor: Floor, hold: bool) -> std::result::Result<(u64, Option<Hold>), Error> {
        h.grant_inner(mib, floor, hold, None, None, || Some(AVAIL)).unwrap()
    }

    #[test]
    fn last_good_config_is_shared_by_clones_and_isolated_from_other_hosts() {
        let mut h = host("config-isolated");
        h.configure(|c| {
            c.peers = vec!["10.1.0.8:7070".into()];
            Ok(())
        })
        .unwrap();
        let clone = h.clone();
        let other = host("config-unrelated");
        let path = h.state.join("host.json");
        let mut cfg = h.cfg.clone();
        for peers in [vec!["10.1.0.9:7070".to_string()], Vec::new()] {
            cfg.peers = peers.clone();
            store(&path, &cfg, false).unwrap();
            assert_eq!(h.config_now().peers, peers);

            // Another Host's reload must not evict this Host's last good config.
            store(&other.state.join("host.json"), &other.cfg, false).unwrap();
            assert!(other.config_now().peers.is_empty());
            std::fs::write(&path, b"{\"peers\": [").unwrap();
            assert_eq!(clone.config_now().peers, peers);
            std::fs::remove_file(&path).unwrap();
            assert_eq!(h.config_now().peers, peers);
        }
        std::fs::remove_dir_all(h.state.parent().unwrap()).unwrap();
        std::fs::remove_dir_all(other.state.parent().unwrap()).unwrap();
    }

    #[test]
    fn config_replacements_with_the_same_mtime_are_seen() {
        let mut h = host("config-stamp");
        h.configure(|_| Ok(())).unwrap();
        let running = h.clone();
        let path = h.state.join("host.json");
        let first = File::open(&path).unwrap();
        let time = first.metadata().unwrap().modified().unwrap();
        let times = std::fs::FileTimes::new().set_modified(time);
        for reserve in [2048, 4096] {
            let previous = File::open(&path).unwrap();
            h.configure(|c| {
                c.reserve_mib = reserve;
                Ok(())
            })
            .unwrap();
            File::open(&path).unwrap().set_times(times).unwrap();
            assert_eq!(stamp(&path).unwrap().0, time);
            assert_ne!(stamp(&path).unwrap().1, previous.metadata().unwrap().ino());
            assert_eq!(running.config_now().reserve_mib, reserve);
        }
    }

    #[test]
    fn peer_generations_are_bounded_before_storing() {
        let h = host("gen-bound");
        let l = h.lock().unwrap();
        let addr = ip("10.9.0.1");
        for gen in [0, RECV_MAX + 1, GEN_MAX - 1025, GEN_MAX - 1024, GEN_MAX - 1, GEN_MAX, GEN_MAX + 1, u64::MAX] {
            assert!(h.claim_incoming(&l, "incoming", addr, gen, None).is_err());
            assert!(!h.observe(&l, addr, gen, 0, Some(ip("10.1.0.2"))).unwrap());
            assert!(!h.observe(&l, addr, gen, 0, None).unwrap());
            assert_eq!(h.addr(&l, addr).unwrap(), Addr::default());
        }
    }

    #[test]
    fn near_bound_peer_generations_do_not_poison_allocation() {
        for (tag, incoming) in [("gen-observe", false), ("gen-incoming", true)] {
            let h = host(tag);
            let l = h.lock().unwrap();
            let addr = ip("10.9.0.1");
            let mut gen = RECV_MAX - 1025;
            if incoming {
                h.claim_incoming(&l, "incoming", addr, gen, None).unwrap().release(&l).unwrap();
            } else {
                assert!(h.observe(&l, addr, gen, 0, Some(ip("10.1.0.2"))).unwrap());
            }
            drop(l);
            for _ in 0..2048 {
                // Taken per round: held across them all, the lock's per-process mutex would
                // keep other tests' host locks waiting for seconds.
                let l = h.lock().unwrap();
                for addr in [addr, ip("10.9.0.2"), ip("10.9.0.3")] {
                    let claim = h.claim_new(&l, "new", Some(addr)).unwrap();
                    assert!(claim.gen > gen && claim.gen <= GEN_MAX);
                    gen = claim.gen;
                    claim.release(&l).unwrap();
                }
            }
        }
    }

    #[test]
    fn admission_uses_this_boots_clock_and_drops_future_grants() {
        let mut h = host("grant-clock");
        h.cfg.reserve_mib = AVAIL - 1000;
        let before = boottime_ms();
        grant_at(&h, 1000, Floor::Reserve, false).unwrap();
        let path = h.grants();
        let grants: Vec<Grant> = load(&path).unwrap().unwrap();
        assert!(grants[0].0 >= before && grants[0].0 <= boottime_ms());
        // From here what counts depends on stamps' ages alone, not on how long the test takes.
        pin_clock(grants[0].0);
        let mut other = Host::open(&h.state, &h.run).unwrap();
        other.cfg.reserve_mib = h.cfg.reserve_mib;
        assert!(grant_at(&other, 1, Floor::Reserve, false).is_err(), "another host handle sees the pending grant");
        // A wall-clock stamp (an older build's, at any wall time) is in the future: dropped, not held forever.
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        for t in [wall, wall - 3_600_000, u64::MAX] {
            store(&path, &vec![(t, 1000u64, 1u64)], false).unwrap();
            grant_at(&h, 1000, Floor::Reserve, false).unwrap();
        }
        // Another boot's grants (a persistent RUN) are another file.
        store(&h.run.join("grants-other-boot"), &vec![(boottime_ms(), 1000u64, 1u64)], false).unwrap();
        std::fs::remove_file(&path).unwrap();
        grant_at(&h, 1000, Floor::Reserve, false).unwrap();
        // A recent boottime stamp counts; one older than the window does not.
        let now = boottime_ms();
        store(&path, &vec![(now - 1000, 1000u64, 1u64)], false).unwrap();
        assert!(grant_at(&h, 1, Floor::Reserve, false).is_err());
        store(&path, &vec![(now - GRANT_WINDOW.as_millis() as u64 - 1000, 1000u64, 1u64)], false).unwrap();
        grant_at(&h, 1000, Floor::Reserve, false).unwrap();
    }

    fn owned_grant(id: u64, baseline: Option<u64>) -> Grant {
        Grant(0, 100, id, Some(GrantOwner { ident: Ident::me(), cgroup: "/fake/vm".into(), used_mib: baseline }))
    }

    #[test]
    fn pending_grants_discount_memory_already_used() {
        let grants = [owned_grant(1, Some(200))];
        for (current, pending) in [(Some(300), 0), (Some(350), 0), (Some(240), 60), (Some(150), 100), (None, 100)] {
            assert_eq!(
                pending_grants(&grants, &HashSet::new(), |cg| {
                    assert_eq!(cg, Path::new("/fake/vm"));
                    current
                }),
                pending,
                "current {current:?}"
            );
        }
    }

    #[test]
    fn pending_grants_keep_unknown_baselines_and_legacy_records_in_full() {
        let legacy: Grant = serde_json::from_str("[0,100,1]").unwrap();
        let grants = [legacy, owned_grant(2, None)];
        assert_eq!(pending_grants(&grants, &HashSet::new(), |_| panic!("no readable baseline")), 200);
        let decoded: Vec<Grant> = serde_json::from_slice(&serde_json::to_vec(&grants).unwrap()).unwrap();
        assert_eq!(pending_grants(&decoded, &HashSet::new(), |_| Some(1000)), 200);
    }

    #[test]
    fn pending_grants_credit_each_owners_growth_once() {
        let mut grants = [owned_grant(1, Some(200)), owned_grant(2, Some(240)), owned_grant(3, Some(200))];
        // Another VM (including reuse of a pid) has its own growth budget.
        grants[2].3.as_mut().unwrap().ident.start += 1;
        let mut reads = 0;
        assert_eq!(
            pending_grants(&grants, &HashSet::new(), |_| {
                reads += 1;
                Some(300)
            }),
            100
        );
        assert_eq!(reads, 2, "one reading per owner");
        assert_eq!(pending_grants(&grants, &HashSet::from([2]), |_| Some(300)), 0);
    }

    #[test]
    fn admission_records_the_vms_cgroup_baseline() {
        let mut h = host("grant-owner");
        h.cfg.reserve_mib = 0;
        let cg = h.run.join("cg");
        std::fs::create_dir(&cg).unwrap();
        std::fs::write(cg.join("memory.current"), (200u64 << 20).to_string()).unwrap();
        let id = h.grant_inner(100, Floor::Reserve, false, None, Some(&cg), || Some(100)).unwrap().unwrap().0;
        let grants: Vec<Grant> = load(&h.grants()).unwrap().unwrap();
        let owner = grants[0].3.as_ref().unwrap();
        assert_eq!(owner.ident, Ident::me());
        assert_eq!(owner.cgroup, cg);
        assert_eq!(owner.used_mib, Some(200));
        std::fs::write(cg.join("memory.current"), (300u64 << 20).to_string()).unwrap();
        assert!(h.grant_inner(100, Floor::Reserve, false, None, None, || Some(100)).unwrap().is_ok());
        h.refund(id);
        let grants: Vec<Grant> = load(&h.grants()).unwrap().unwrap();
        assert_eq!(grants.len(), 1);
        assert!(grants[0].3.is_none());
    }

    #[test]
    fn admission_counts_recent_grants() {
        let mut h = host("admit");
        let admit = |h: &Host, mib| grant_at(h, mib, Floor::Reserve, false).is_ok();
        h.cfg.reserve_mib = AVAIL - 3000;
        pin_clock(boottime_ms());
        assert!(admit(&h, 1000) && admit(&h, 1000));
        assert!(!admit(&h, 1001), "recent grants count as used");
        // A start that did not happen gives its grant back, by id: only its own.
        let id = grant_at(&h, 900, Floor::Reserve, false).unwrap().0;
        assert!(!admit(&h, 101));
        h.refund(id);
        h.refund(u64::MAX);
        assert!(admit(&h, 500) && !admit(&h, 501));
        h.cfg.reserve_mib = AVAIL + 1;
        assert!(!admit(&h, 1));
    }

    /// An unreadable MemAvailable, or a host lock not had in time, is an
    /// error, never a refusal (which marks a VM throttled) nor 0 MiB
    /// available; nothing is granted.
    #[test]
    fn admission_errors_are_not_refusals() {
        let mut h = host("admit-err");
        h.cfg.reserve_mib = 0;
        let grants = || load::<Vec<Grant>>(&h.grants()).unwrap().unwrap_or_default();
        let grant = |avail: Option<u64>| h.grant_inner(1, Floor::Reserve, false, None, None, || avail).map(|r| r.ok().map(|g| g.0));
        assert!(grant(None).unwrap_err().to_string().contains("MemAvailable"));
        assert!(grants().is_empty());
        assert_eq!(grant(Some(0)).unwrap(), None);
        assert!(grant(Some(10)).unwrap().is_some() && grants().len() == 1);
        let (held, release) = (std::sync::mpsc::channel(), std::sync::mpsc::channel::<()>());
        let other = h.clone();
        let t = std::thread::spawn(move || {
            let _l = other.lock().unwrap();
            held.0.send(()).unwrap();
            let _ = release.1.recv();
        });
        held.1.recv().unwrap();
        let err = h.grant(1, Some(std::time::Instant::now() + Duration::from_millis(50)), None).unwrap_err();
        assert_eq!(err.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::WouldBlock);
        release.0.send(()).unwrap();
        t.join().unwrap();
        assert_eq!(grants().len(), 1);
    }

    #[test]
    fn admission_and_eviction_read_the_marks_as_they_change() {
        let mut h = host("marks");
        h.configure(|c| {
            c.reserve_mib = AVAIL - 3000;
            c.evict_mib = Some(AVAIL - 1500);
            Ok(())
        })
        .unwrap();
        let running = h.clone();
        let above = |mib| grant_at(&running, mib, Floor::EvictMark, false).map(|g| g.0);
        // Its grants must all count to the end, however long a loaded machine takes over it.
        pin_clock(boottime_ms());
        assert!(grant_at(&running, 100, Floor::Reserve, false).is_ok());
        // An eviction's arrival leaves the mark available, not only the reserve.
        assert!(above(1401).unwrap_err().to_string().contains("eviction mark"));
        assert!(above(200).is_ok());
        // Not while an eviction runs here; a pressure marker alone does not refuse.
        std::fs::write(running.run.join("evict.active"), b"").unwrap();
        let worker = running.evict_worker_lock().unwrap();
        assert!(running.evict_worker_lock().is_err(), "one eviction at a time");
        assert!(above(1).unwrap_err().to_string().contains("moving vms away"));
        drop(worker);
        assert!(above(1).is_ok());
        // `listen` raises the reserve while this process runs: admission sees it.
        std::thread::sleep(Duration::from_millis(20));
        h.configure(|c| {
            c.reserve_mib = AVAIL - 1000;
            Ok(())
        })
        .unwrap();
        assert_eq!(running.config_now().reserve_mib, AVAIL - 1000);
        assert!(grant_at(&running, 700, Floor::Reserve, false).is_err() && grant_at(&running, 699, Floor::Reserve, false).is_ok());
    }

    #[test]
    fn disk_restore_reservation_survives_expiry_and_can_be_completed_or_refunded() {
        let h = host("disk-restore-hold");
        let charge = crate::limit::allowance(1600);
        let grant = |mib, held| h.grant_inner(mib, Floor::Reserve, held, None, None, || Some(h.cfg.reserve_mib + charge)).unwrap();
        let (id, hold) = grant(charge, true).unwrap();
        let hold = Mutex::new(hold);
        let path = h.grants();
        store(&path, &vec![(0u64, charge, id)], false).unwrap();
        assert!(grant(1, false).is_err(), "disk pull reservation counts after ten seconds");
        // Pages come in: it counts only what is still to come, never more again.
        h.shrink_hold(&hold, 100).unwrap();
        h.shrink_hold(&hold, 200).unwrap();
        assert!(h.run.join(format!("holds/{id}-100")).exists());
        assert!(grant(charge - 99, false).is_err());
        assert!(grant(charge - 100, false).is_ok());
        store(&path, &vec![(0u64, charge, id)], false).unwrap();
        // A grant's temp file left by a dead process goes.
        let tmp = h.run.join("holds/.7");
        std::fs::write(&tmp, b"").unwrap();
        assert!(grant(charge - 100, false).is_ok() && !tmp.exists());
        store(&path, &vec![(0u64, charge, id)], false).unwrap();
        drop(hold); // Pull completed: its pages now count in MemAvailable.
        assert!(grant(1, false).is_ok());
        store(&path, &Vec::<(u64, u64, u64)>::new(), false).unwrap();
        let (id, hold) = grant(charge, true).unwrap();
        drop(hold);
        h.refund(id); // Start failed: refund the recent grant as well as its hold.
        assert!(grant(charge, false).is_ok());
    }

    #[test]
    fn held_grants_count_past_the_window_until_dropped_or_their_owner_is_gone() {
        let mut h = host("held");
        let admit = |h: &Host, mib| grant_at(h, mib, Floor::Reserve, false).is_ok();
        h.cfg.reserve_mib = AVAIL - 3000;
        let hold = grant_at(&h, 2000, Floor::Reserve, true).unwrap().1.unwrap();
        // The window passes (the grant ages out): held, it still counts, once.
        let path = h.grants();
        let aged: Vec<(u64, u64, u64)> = load::<Vec<Grant>>(&path).unwrap().unwrap().into_iter().map(|g| (0, g.1, g.2)).collect();
        store(&path, &aged, false).unwrap();
        assert!(!admit(&h, 1001) && admit(&h, 1000), "a held grant counts after the window, once");
        drop(hold);
        assert!(admit(&h, 1500));
        // A hold whose lock nobody has (its process died; or its removal failed) goes.
        store(&path, &Vec::<(u64, u64, u64)>::new(), false).unwrap();
        std::fs::write(h.run.join("holds").join("99-2000"), b"").unwrap();
        assert!(admit(&h, 2500));
        assert!(!h.run.join("holds").join("99-2000").exists());
    }
}
