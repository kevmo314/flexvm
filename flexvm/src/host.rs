//! Host-wide state in files, shared by VM processes and the listener.
//! Acquisitions (names, addresses, migration records) are guards that give
//! back exactly what they took. The host lock (`STATE/lock`) covers only short
//! sections. A VM process holds `RUN/vms/NAME.lock` for life; a dead one
//! counts as gone only once its Firecrackers have exited (`reap`).

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::bail;
use crate::net::IpRange;
use crate::util::Result;

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
            prefix: "fv".into(),
        }
    }
}

impl Config {
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

/// Unreadable or corrupt is an error, never None.
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => bail!("{}: {e}", path.display()),
    }
}

pub fn store<T: Serialize>(path: &Path, v: &T, durable: bool) -> Result<()> {
    let (dir, name) = (path.parent().ok_or("no directory")?, path.file_name().ok_or("no name")?);
    write_file(dir, &name.to_string_lossy(), &serde_json::to_vec(v)?, durable).map_err(|e| format!("{}: {e}", path.display()).into())
}

fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => bail!("{}: {e}", path.display()),
        _ => Ok(File::open(path.parent().ok_or("no directory")?)?.sync_all()?),
    }
}

#[derive(Clone)]
pub struct Host {
    pub state: PathBuf,
    pub run: PathBuf,
    pub cfg: Config,
}

static RUN_DIR: OnceLock<PathBuf> = OnceLock::new();

impl Host {
    pub fn open(state: &Path, run: &Path) -> Result<Host> {
        for d in ["addrs", "standby", "migs"] {
            let _ = crate::util::create_dir_durably(&state.join(d));
        }
        let _ = crate::util::create_dir_durably_mode(&state.join("suspended"), 0o700);
        for d in ["vms", "standby", "w"] {
            let _ = std::fs::create_dir_all(run.join(d));
        }
        let canon = |d: &Path| d.canonicalize().map_err(|e| format!("{}: {e} (run flexvm as root to create it)", d.display()));
        let (state, run) = (canon(state)?, canon(run)?);
        let _ = RUN_DIR.set(run.clone());
        let cfg = load(&state.join("host.json"))?.unwrap_or_default();
        Ok(Host { state, run, cfg })
    }

    pub fn configure(&mut self, change: impl FnOnce(&mut Config) -> Result<()>) -> Result<()> {
        let _l = self.lock()?;
        let path = self.state.join("host.json");
        let mut cfg = load(&path)?.unwrap_or_default();
        change(&mut cfg)?;
        store(&path, &cfg, true)?;
        self.cfg = cfg;
        Ok(())
    }

    /// Reentrant within a thread (so a guard dropped under it cannot
    /// deadlock); other threads wait as other processes do.
    pub fn lock(&self) -> Result<Locked> {
        self.lock_by(None)
    }

    /// Gives up at `deadline`, if any.
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
                    Err(_) if past() => bail!("the host lock is busy"),
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
            },
        };
        let f = File::options().create(true).truncate(false).write(true).open(self.state.join("lock"))?;
        match deadline {
            None => flock(&f, libc::LOCK_EX)?,
            Some(_) => while let Err(e) = flock(&f, libc::LOCK_EX | libc::LOCK_NB) {
                if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
                    return Err(e.into());
                }
                if past() {
                    bail!("the host lock is busy");
                }
                std::thread::sleep(Duration::from_millis(2));
            },
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
        let f = lock_path(&self.vms(name, "lock"), libc::LOCK_EX | libc::LOCK_NB).map_err(|_| format!("vm name {name:?} is taken"))?;
        if let Some(old) = self.holder_of(name).filter(|o| !o.alive()) {
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

    pub fn alive(&self, name: &str) -> bool {
        File::open(self.vms(name, "lock")).is_ok_and(|f| flock(&f, libc::LOCK_SH | libc::LOCK_NB).is_err())
    }

    fn holder_of(&self, name: &str) -> Option<Ident> {
        load(&self.vms(name, "lock")).ok().flatten()
    }

    /// Also requires the last holder's Firecrackers to have exited.
    fn gone(&self, name: &str) -> bool {
        !self.alive(name) && self.holder_of(name).is_none_or(|id| !id.alive() && reap(&self.run, &id).is_ok())
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
            Ok(Some(e)) if self.alive(name) && self.holder_of(name) == Some(e.ident.clone()) => Ok(e),
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

    fn held(&self, a: &Addr) -> bool {
        a.holder.as_deref().is_some_and(|h| !self.gone(h) || self.is_suspended(h))
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
            None => range.allocate(taken).ok_or("no free addresses left")?,
        };
        let a = self.addr(l, ip)?;
        let gen = self.next_gen(a.seen)?;
        self.put_addr(ip, &Addr { seen: gen, holder: Some(holder.into()), held: gen, lent: a.lent, ..Addr::default() }, false)?;
        Ok(AddrClaim { host: self.clone(), ip, gen, holder: holder.into(), kept: false, fresh: true })
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
        let g = load::<Gens>(&path)?.unwrap_or(Gens { next: 1, reserved: 0, boot: String::new() });
        let next = if g.boot == boot_id() { g.next } else { g.next.max(g.reserved) };
        let gen = next.max(seen + 1);
        let (reserved, durable) = if gen >= g.reserved { (gen + GEN_BLOCK, true) } else { (g.reserved, false) };
        store(&path, &Gens { next: gen + 1, reserved, boot: boot_id().into() }, durable)?;
        Ok(gen)
    }

    pub fn claim_incoming(&self, l: &Locked, holder: &str, ip: Ipv4Addr, gen: u64) -> Result<AddrClaim> {
        let mut a = self.addr(l, ip)?;
        if gen == 0 {
            bail!("{ip}: an arrival must carry its address's generation");
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
        if gen > a.seen {
            (a.seen, a.withdrawn, a.via) = (gen, false, None);
        }
        (a.holder, a.held) = (Some(holder.into()), gen);
        self.put_addr(ip, &a, true)?;
        Ok(AddrClaim { host: self.clone(), ip, gen, holder: holder.into(), kept: false, fresh: false })
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

    pub fn release(&self, l: &Locked, ip: Ipv4Addr, holder: &str) -> Result<()> {
        self.update(l, ip, false, |a| a.holder = a.holder.take().filter(|h| h != holder))
    }

    /// True if this made the loan (only then may its maker undo it).
    pub fn lend(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        if !self.cfg.range()?.contains(ip) {
            return Ok(false);
        }
        self.update(l, ip, true, |a| a.lent.replace(gen) != Some(gen))
    }

    pub fn unlend(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<()> {
        self.update(l, ip, true, |a| a.lent = a.lent.filter(|&lent| lent != gen))
    }

    /// `via` None is a withdrawal. False if stale (older, or announcing a
    /// withdrawn generation). A withdrawal frees a loan of that gen or older.
    pub fn observe(&self, l: &Locked, ip: Ipv4Addr, gen: u64, via: Option<Ipv4Addr>) -> Result<bool> {
        self.update(l, ip, true, |a| {
            if gen < a.seen || (gen == a.seen && a.withdrawn && via.is_some()) {
                return false;
            }
            (a.seen, a.withdrawn, a.via) = (gen, via.is_none(), via);
            if via.is_none() && a.lent.is_some_and(|lent| lent <= gen) {
                a.lent = None;
            }
            true
        })
    }

    /// A paused migration source keeps its route too: its release moves it.
    pub fn keeps_route(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        let a = self.addr(l, ip)?;
        let source = || a.holder.as_deref().and_then(|h| self.entry(h).ok()).is_some_and(|e| e.state == "source");
        Ok(self.held(&a) && (a.held >= gen || source()))
    }

    pub fn reinstall(&self, l: &Locked, ip: Ipv4Addr) -> Result<bool> {
        self.reinstall_after(l, ip, None)
    }

    /// `reinstall`, counting a holder whose name `dead` (a dead process) still locks as
    /// gone: its other threads may hold the lock a moment longer.
    fn reinstall_after(&self, l: &Locked, ip: Ipv4Addr, dead: Option<&Ident>) -> Result<bool> {
        let a = self.addr(l, ip)?;
        let dying = || a.holder.as_deref().is_some_and(|h| dead.is_some() && self.holder_of(h).as_ref() == dead);
        let Some(via) = a.via.filter(|_| !a.withdrawn && (dying() || !self.held(&a))) else { return Ok(false) };
        crate::net::route_via(ip, via)?;
        eprintln!("put back route {ip} via {via} (generation {})", a.seen);
        Ok(true)
    }

    pub fn current(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        Ok(self.addr(l, ip)?.current(gen))
    }

    pub fn holder(&self, l: &Locked, ip: Ipv4Addr) -> Result<Option<String>> {
        let a = self.addr(l, ip)?;
        Ok(self.held(&a).then_some(a.holder).flatten())
    }

    /// MemAvailable lags a grant until the guest touches the memory, so all
    /// processes' grants of the last `GRANT_WINDOW` count as used.
    pub fn admit(&self, mib: u64) -> bool {
        let Ok(_l) = self.lock() else { return false };
        let path = self.run.join("grants");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let mut grants: Vec<(u64, u64)> = load(&path).ok().flatten().unwrap_or_default();
        grants.retain(|&(t, _)| now.saturating_sub(t) <= GRANT_WINDOW.as_millis() as u64);
        let pending: u64 = grants.iter().map(|g| g.1).sum();
        if crate::vmproc::host_available_mib() < self.cfg.reserve_mib + pending + mib {
            return false;
        }
        grants.push((now, mib));
        store(&path, &grants, false).is_ok()
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
        remove(&path)?;
        // Killed before it committed, it never ran here: the newest route a peer
        // announced for its address (say, back to its source) comes back.
        if let Some(ip) = ip {
            if let Err(e) = self.reinstall_after(&l, ip, Some(&owner)) {
                eprintln!("migration {id} died before its commit; putting back the route for {ip}: {e}");
            }
        }
        Ok("aborted")
    }

    pub fn mig_done(&self, id: u64) -> Result<()> {
        let _l = self.lock()?;
        match load(&self.mig_path(id))? {
            Some(Mig::Released { .. }) => remove(&self.mig_path(id)),
            _ => Ok(()),
        }
    }

    /// Records no source will ask about again: a dead owner's (aborted, as
    /// `mig_status` would answer), and released ones whose source process is
    /// proven gone (killed before its `done`) by its own host's listener. Any
    /// doubt keeps the record: a source that still waits must find it.
    pub fn retire_migrations(&self) {
        for e in std::fs::read_dir(self.state.join("migs")).into_iter().flatten().flatten() {
            let Some(id) = e.file_name().to_str().and_then(|n| n.parse().ok()) else { continue };
            let Ok(Some(Mig::Released { source, by })) = load(&self.mig_path(id)) else {
                let _ = self.mig_status(id);
                continue;
            };
            let Some(by) = by.filter(|_| !source.is_empty()) else { continue };
            let gone = crate::vmproc::peer_call(&source, serde_json::json!({"op": "source", "ident": by}));
            if gone.is_ok_and(|r| r["gone"] == true) {
                eprintln!("migration {id}: its source at {source} is gone; forgetting it");
                let _ = self.mig_done(id);
            }
        }
    }
}

const GRANT_WINDOW: Duration = Duration::from_secs(10);

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Addr {
    pub seen: u64,
    pub withdrawn: bool,
    /// Gone with a VM of this generation: not handed out until withdrawn or back.
    pub lent: Option<u64>,
    pub holder: Option<String>,
    pub held: u64,
    pub via: Option<Ipv4Addr>,
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
    holder: String,
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
        self.host.release(l, self.ip, &self.holder)
    }
}

impl Drop for AddrClaim {
    fn drop(&mut self) {
        if let (false, Ok(l)) = (self.kept, self.host.lock()) {
            let _ = self.host.release(&l, self.ip, &self.holder);
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
                Err(e) if within.is_none_or(|w| start.elapsed() + delay < w) => eprintln!("migration {}: {e}; retrying", self.id),
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
                let _ = remove(&path);
            }
        }
    }
}

pub struct Locked(#[allow(dead_code)] Option<(File, std::sync::MutexGuard<'static, ()>)>);

impl Drop for Locked {
    fn drop(&mut self) {
        DEPTH.with(|d| d.set(d.get() - 1));
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
}

/// Unique however pids are reused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ident {
    pub pid: u32,
    pub start: u64,
    pub boot: String,
}

impl Ident {
    pub fn me() -> Ident {
        Ident::of(std::process::id()).expect("no /proc/self/stat")
    }

    pub fn of(pid: u32) -> Option<Ident> {
        Some(Ident { pid, start: starttime(pid)?, boot: boot_id().into() })
    }

    pub fn alive(&self) -> bool {
        self.boot == boot_id() && starttime(self.pid) == Some(self.start)
    }
}

pub fn boot_id() -> &'static str {
    static BOOT: OnceLock<String> = OnceLock::new();
    BOOT.get_or_init(|| std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default().trim().into())
}

pub struct PidFd(OwnedFd);

impl PidFd {
    pub fn open(id: &Ident) -> Result<Option<PidFd>> {
        match crate::util::pidfd_open(id.pid) {
            // Opened, then checked: if it is `id` now, the fd is `id`'s.
            Ok(fd) => Ok(id.alive().then_some(PidFd(fd))),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(None),
            Err(e) => bail!("pidfd_open {}: {e}", id.pid),
        }
    }

    pub fn signal(&self, sig: i32) -> Result<()> {
        Ok(crate::util::pidfd_signal(&self.0, sig).map_err(|e| format!("signal {sig}: {e}"))?)
    }

    pub fn wait(&self, timeout: Duration) -> bool {
        crate::util::pidfd_wait(&self.0, timeout).unwrap_or(false)
    }
}

/// Kills and waits for a dead process's Firecrackers: they die with it, but not at once.
pub fn reap(run: &Path, owner: &Ident) -> Result<()> {
    if owner.alive() {
        bail!("process {} is alive", owner.pid);
    }
    let dir = run.join("w").join(owner.pid.to_string());
    if owner.boot != boot_id() || load::<Ident>(&dir.join("owner")).ok().flatten().as_ref() != Some(owner) {
        return Ok(());
    }
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let Some(fc) = load::<Ident>(&e.path().join("fc")).ok().flatten() else { continue };
        if let Some(fd) = PidFd::open(&fc)? {
            fd.signal(libc::SIGKILL)?;
            if !fd.wait(Duration::from_secs(5)) {
                bail!("firecracker {} of dead process {} will not exit", fc.pid, owner.pid);
            }
        }
    }
    Ok(())
}

pub fn collect_garbage(run: &Path, prefix: &str) {
    let gone = |pid: Option<u32>| pid.is_some_and(|p| starttime(p).is_none());
    for e in std::fs::read_dir("/sys/class/net").into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let pid = n.strip_prefix(prefix).and_then(|r| r.split_once('t')).and_then(|(p, _)| u32::from_str_radix(p, 16).ok());
        if gone(pid) {
            crate::net::delete_tap(&n);
        }
    }
    for e in std::fs::read_dir("/sys/fs/cgroup/flexvm").into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if gone(n.strip_prefix("idle-").and_then(|r| r.split('-').next()).and_then(|p| p.parse().ok())) {
            let _ = std::fs::write(e.path().join("cgroup.kill"), "1");
            let _ = std::fs::remove_dir(e.path());
        }
    }
    for e in std::fs::read_dir(run.join("w")).into_iter().flatten().flatten() {
        let owner = load::<Ident>(&e.path().join("owner")).ok().flatten();
        if owner.is_some_and(|o| !o.alive() && reap(run, &o).is_ok()) {
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
        let Ok(_held) = lock_path(&path, libc::LOCK_EX | libc::LOCK_NB) else { continue };
        if load::<Ident>(&path).ok().flatten().is_none_or(|o| reap(run, &o).is_ok()) {
            for ext in ["json", "sock", "lock"] {
                let _ = std::fs::remove_file(path.with_extension(ext));
            }
        }
    }
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

pub fn write_file(dir: &Path, name: &str, data: &[u8], durable: bool) -> std::io::Result<()> {
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut f = File::create(&tmp)?;
    f.write_all(data)?;
    if durable {
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(name))?;
    if durable {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Some(true) only on proof the process is gone (another boot, no such pid,
/// a zombie, or another process with its pid); None when that cannot be told.
pub fn gone(id: &Ident) -> Option<bool> {
    gone_by(id, boot_id(), |pid| std::fs::read_to_string(format!("/proc/{pid}/stat")))
}

/// Every error, and anything unparsable, is unknown.
fn gone_by(id: &Ident, boot: &str, stat: impl Fn(u32) -> std::io::Result<String>) -> Option<bool> {
    if boot.is_empty() {
        return None;
    }
    if id.boot != boot {
        return Some(true);
    }
    match stat(id.pid) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(true),
        Err(_) => None,
        Ok(text) => match parse_stat(&text)? {
            ("Z", _) => Some(true),
            (_, start) => Some(start != id.start),
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
        let dir = h.run.join("w").join(pid.to_string());
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
        collect_garbage(&h.run, "none");
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
        assert!(!h.observe(&l, a_ip, g1 - 1, None).unwrap(), "older withdrawal is stale");
        assert!(h.addr(&l, a_ip).unwrap().lent.is_some());
        assert!(h.observe(&l, a_ip, g1, None).unwrap() && h.addr(&l, a_ip).unwrap().lent.is_none());
        let via = Some(ip("192.0.2.1"));
        assert!(!h.observe(&l, a_ip, g1, via).unwrap() && !h.current(&l, a_ip, g1).unwrap());
        assert!(h.observe(&l, a_ip, g1 + 5, via).unwrap() && h.addr(&l, a_ip).unwrap().via == via);
        assert!(h.claim_incoming(&l, "y", a_ip, g1).is_err() && h.claim_incoming(&l, "y", a_ip, 0).is_err());
        h.claim_incoming(&l, "y", a_ip, g1 + 5).unwrap().keep();
        drop(h.fence(a_ip, g1 + 5).unwrap());
        assert!(h.observe(&l, a_ip, g1 + 5, None).unwrap());
        h.claim_incoming(&l, "y", a_ip, g1 + 6).unwrap().keep();
        assert!(h.current(&l, a_ip, g1 + 6).unwrap());
        let _w = h.take_name("w", false).unwrap();
        let wc = h.claim_new(&l, "w", Some(ip("10.9.0.3"))).unwrap();
        assert!(h.claim_incoming(&l, "w2", wc.ip, wc.gen).is_err());
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
    fn addresses_are_lent_to_restoring_peers_only_when_free() {
        let h = host("lend");
        let l = h.lock().unwrap();
        let x = ip("10.9.0.2");
        assert!(h.lend_new(&l, ip("10.9.9.9")).is_err(), "not ours");
        let g = h.lend_new(&l, x).unwrap();
        assert!(h.lend_new(&l, x).unwrap_err().to_string().contains("lent"));
        assert!(h.claim_new(&l, "x", Some(x)).err().unwrap().to_string().contains("lent"));
        assert!(h.observe(&l, x, g, None).unwrap());
        let _x = h.take_name("x", false).unwrap();
        let c = h.claim_new(&l, "x", Some(x)).unwrap();
        assert!(c.gen > g && c.fresh);
        assert!(h.lend_new(&l, x).unwrap_err().to_string().contains("in use"));
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
        assert_eq!(gone(&me), Some(false));
        for other in [Ident { boot: "other".into(), ..me.clone() }, Ident { pid: 999_999_999, ..me.clone() }, Ident { start: me.start + 1, ..me.clone() }] {
            assert_eq!(gone(&other), Some(true), "{other:?}");
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
        assert!(h.lock_by(Some(start + Duration::from_millis(50))).is_err() && start.elapsed() < Duration::from_secs(1));
        release.0.send(()).unwrap();
        t.join().unwrap();
        assert!(h.lock_by(Some(std::time::Instant::now() + Duration::from_secs(1))).is_ok());
        // Errors and garbage are unknown, never gone; a zombie is gone.
        let emfile = |_| Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        assert_eq!(gone_by(&me, boot_id(), emfile), None);
        assert_eq!(gone_by(&me, boot_id(), |_| Ok("garbage".into())), None);
        assert_eq!(gone_by(&me, "", |_| Ok(String::new())), None);
        let zombie = format!("1 (x) Z {}", "0 ".repeat(18) + &me.start.to_string());
        assert_eq!(gone_by(&me, boot_id(), |_| Ok(zombie.clone())), Some(true));
        // A dead owner's goes, as asking would make it go.
        store(&h.mig_path(9), &Mig::Committed { owner: dead_owner(&h, 999_999_909, &[]) }, false).unwrap();
        h.retire_migrations();
        assert!(h.mig_status(8).unwrap() == "released" && rec(9).is_none());
        std::fs::write(h.mig_path(6), "{").unwrap();
        assert!(h.mig_status(6).is_err());
    }

    #[test]
    fn admission_counts_recent_grants() {
        let mut h = host("admit");
        let free = crate::vmproc::host_available_mib();
        // Wide margins: other processes move MemAvailable meanwhile.
        h.cfg.reserve_mib = free.saturating_sub(3000);
        assert!(h.admit(1000) && h.admit(1000));
        assert!(!h.admit(2000), "recent grants count as used");
        h.cfg.reserve_mib = free + 1;
        assert!(!h.admit(1));
    }
}
