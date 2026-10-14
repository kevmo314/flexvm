//! Host-wide state in files, shared by VM processes and the peer listener:
//! configuration, the VM registry, address generations and loans, incoming
//! migration records, memory grants and test faults. Acquisitions (names,
//! addresses, migration records) are guards that give back exactly what they
//! took. Short critical sections take the host lock (`STATE/lock`); nothing
//! slow happens under it. A VM process holds `RUN/vms/NAME.lock`, its
//! identity in it, for life. A dead process counts as gone only once the
//! Firecrackers it started have exited (`reap`).

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::bail;
use crate::net::IpRange;
use crate::util::Result;

/// The host's configuration (`STATE/host.json`, written by `flexvm listen`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// The peer listener's address, as peers reach it.
    pub listen: Option<String>,
    pub peers: Vec<String>,
    /// The addresses this host hands to new VMs; disjoint across hosts.
    pub vm_ips: String,
    /// This host's address for peers' routes (default: the listen address's).
    pub underlay: Option<Ipv4Addr>,
    /// Answer ARP for local VMs on this interface, announce arrivals there.
    pub announce_dev: Option<String>,
    pub dns: Option<String>,
    /// Memory to keep free (MiB).
    pub reserve_mib: u64,
    /// Names of taps, hold devices and cgroups start with this.
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

    pub fn underlay(&self) -> Option<Ipv4Addr> {
        self.underlay.or_else(|| self.listen.as_deref()?.rsplit_once(':')?.0.parse().ok())
    }
}

/// A JSON record: None if absent; unreadable or corrupt is an error.
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => bail!("{}: {e}", path.display()),
    }
}

/// Replaces a JSON record atomically; `durable`, it survives a power loss.
pub fn store<T: Serialize>(path: &Path, v: &T, durable: bool) -> Result<()> {
    let (dir, name) = (path.parent().ok_or("no directory")?, path.file_name().ok_or("no name")?);
    write_file(dir, &name.to_string_lossy(), &serde_json::to_vec(v)?, durable).map_err(|e| format!("{}: {e}", path.display()).into())
}

/// Removes a record (absent is fine), durably.
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
        // Made if we can (root); a reader such as `ls` does without.
        for d in ["addrs", "standby", "migs"] {
            let _ = crate::util::create_dir_durably(&state.join(d));
        }
        let _ = crate::util::create_private_dir_durably(&state.join("suspended"));
        for d in ["vms", "standby", "w"] {
            let _ = std::fs::create_dir_all(run.join(d));
        }
        let canon = |d: &Path| d.canonicalize().map_err(|e| format!("{}: {e} (run flexvm as root to create it)", d.display()));
        let (state, run) = (canon(state)?, canon(run)?);
        let _ = RUN_DIR.set(run.clone());
        let cfg = load(&state.join("host.json"))?.unwrap_or_default();
        Ok(Host { state, run, cfg })
    }

    /// Changes the configuration as it is on disk now, under the host lock.
    pub fn configure(&mut self, change: impl FnOnce(&mut Config) -> Result<()>) -> Result<()> {
        let _l = self.lock()?;
        let path = self.state.join("host.json");
        let mut cfg = load(&path)?.unwrap_or_default();
        change(&mut cfg)?;
        store(&path, &cfg, true)?;
        self.cfg = cfg;
        Ok(())
    }

    /// The host lock. Reentrant within a thread (so a guard dropped under it
    /// cannot deadlock); other threads wait as other processes do.
    pub fn lock(&self) -> Result<Locked> {
        if DEPTH.with(|d| d.get()) > 0 {
            DEPTH.with(|d| d.set(d.get() + 1));
            return Ok(Locked(None));
        }
        let threads = THREADS.lock().unwrap_or_else(|e| e.into_inner());
        let f = File::options().create(true).truncate(false).write(true).open(self.state.join("lock"))?;
        flock(&f, libc::LOCK_EX)?;
        DEPTH.with(|d| d.set(1));
        Ok(Locked(Some((f, threads))))
    }

    pub fn sock(&self, name: &str) -> PathBuf {
        self.vms(name, "sock")
    }

    /// `RUN/vms/NAME.EXT`.
    pub fn vms(&self, name: &str, ext: &str) -> PathBuf {
        self.run.join("vms").join(format!("{name}.{ext}"))
    }

    pub fn suspended(&self, name: &str) -> PathBuf {
        self.state.join("suspended").join(name)
    }

    /// Takes `name` for this process while the lock lives. Refused if a live
    /// process has it, or a suspended VM (unless `resuming` it). What a dead
    /// holder left running goes first.
    pub fn take_name(&self, name: &str, resuming: bool) -> Result<NameLock> {
        check_name(name)?;
        if !resuming && self.suspended(name).exists() {
            bail!("vm {name:?} exists (suspended); resume or kill it");
        }
        let f = lock_path(&self.vms(name, "lock"), libc::LOCK_EX | libc::LOCK_NB).map_err(|_| format!("vm name {name:?} is taken"))?;
        if let Some(old) = self.holder_of(name).filter(|o| !o.alive()) {
            reap(&self.run, &old)?;
        }
        for ext in ["json", "sock", "moved", "failed"] {
            let _ = std::fs::remove_file(self.vms(name, ext));
        }
        f.set_len(0)?;
        f.write_all_at(&serde_json::to_vec(&Ident::me())?, 0)?;
        Ok(NameLock { name: name.into(), host: self.clone(), _file: f })
    }

    /// Whether a live process holds `name`.
    pub fn alive(&self, name: &str) -> bool {
        File::open(self.vms(name, "lock")).is_ok_and(|f| flock(&f, libc::LOCK_SH | libc::LOCK_NB).is_err())
    }

    fn holder_of(&self, name: &str) -> Option<Ident> {
        load(&self.vms(name, "lock")).ok().flatten()
    }

    /// Whether nothing of VM `name` runs here: no process holds the name, and
    /// the Firecrackers of the last one that did have exited.
    fn gone(&self, name: &str) -> bool {
        !self.alive(name) && self.holder_of(name).is_none_or(|id| !id.alive() && reap(&self.run, &id).is_ok())
    }

    /// The registry entries of live VMs.
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

    /// The registry entry of live VM `name`, written by the process that
    /// holds the name now.
    pub fn entry(&self, name: &str) -> Result<Entry> {
        match load::<Entry>(&self.vms(name, "json")) {
            Ok(Some(e)) if self.alive(name) && self.holder_of(name) == Some(e.ident.clone()) => Ok(e),
            _ => bail!("no vm named {name:?}"),
        }
    }

    /// Sends `sig` to live VM `name`; the pidfd stays that process's.
    pub fn signal(&self, name: &str, sig: i32) -> Result<PidFd> {
        let fd = PidFd::open(&self.entry(name)?.ident)?.ok_or_else(|| format!("no vm named {name:?}"))?;
        fd.signal(sig)?;
        Ok(fd)
    }

    // Addresses and generations. Every function here wants the host lock.

    fn addr_path(&self, ip: Ipv4Addr) -> PathBuf {
        self.state.join("addrs").join(ip.to_string())
    }

    pub fn addr(&self, _: &Locked, ip: Ipv4Addr) -> Result<Addr> {
        Ok(load(&self.addr_path(ip))?.unwrap_or_default())
    }

    fn put_addr(&self, ip: Ipv4Addr, a: &Addr, durable: bool) -> Result<()> {
        store(&self.addr_path(ip), a, durable)
    }

    /// Whether `a`'s holder is a VM here: running, or suspended.
    fn held(&self, a: &Addr) -> bool {
        a.holder.as_deref().is_some_and(|h| !self.gone(h) || self.suspended(h).exists())
    }

    /// Hands an address of this host's range (`want`, or the first free one)
    /// to new VM `holder`, with a new generation.
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
        // The high-water mark orders generations: this need not be durable.
        self.put_addr(ip, &Addr { seen: gen, holder: Some(holder.into()), held: gen, lent: a.lent, ..Addr::default() }, false)?;
        Ok(AddrClaim { host: self.clone(), ip, gen, holder: holder.into(), kept: false, fresh: true })
    }

    /// Lends `ip`, of this host's range, to a peer restoring a checkpoint
    /// with it, if free here: durably, with a new generation (returned).
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

    /// A generation newer than `seen` and any handed out here before, across
    /// crashes and reboots: a high-water mark reserved `GEN_BLOCK` at a time.
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

    /// Takes in `ip` for a VM arriving (or resumed) with generation `gen`.
    /// Refused if a VM here holds it, if that generation was superseded or
    /// withdrawn, or if it is lent out with a newer one.
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

    /// An arrival commits: its generation must still be current. Takes back
    /// a loan of it (the VM came home).
    pub fn commit_incoming(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<()> {
        let mut a = self.addr(l, ip)?;
        if !a.current(gen) {
            bail!("generation {gen} of {ip} was withdrawn or superseded meanwhile");
        }
        if a.lent.is_some_and(|lent| lent <= gen) {
            a.lent = None;
            self.put_addr(ip, &a, true)?;
        }
        Ok(())
    }

    pub fn release(&self, l: &Locked, ip: Ipv4Addr, holder: &str) -> Result<()> {
        let mut a = self.addr(l, ip)?;
        if a.holder.as_deref() == Some(holder) {
            a.holder = None;
            self.put_addr(ip, &a, false)?;
        }
        Ok(())
    }

    /// Records `ip`, if of this host's range, as lent with generation `gen`
    /// (its VM is about to leave), durably.
    pub fn lend(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<()> {
        if !self.cfg.range()?.contains(ip) {
            return Ok(());
        }
        let mut a = self.addr(l, ip)?;
        a.lent = Some(gen);
        self.put_addr(ip, &a, true)
    }

    /// Takes back a loan of generation `gen` (the migration aborted).
    pub fn unlend(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<()> {
        let mut a = self.addr(l, ip)?;
        if a.lent == Some(gen) {
            a.lent = None;
            self.put_addr(ip, &a, true)?;
        }
        Ok(())
    }

    /// Takes in a message about generation `gen` of `ip`: its VM is at `via`,
    /// or (None) withdrawn. False if stale (an older generation, or an
    /// announcement of a withdrawn one). A withdrawal frees a loan of its
    /// generation or an older one.
    pub fn observe(&self, l: &Locked, ip: Ipv4Addr, gen: u64, via: Option<Ipv4Addr>) -> Result<bool> {
        let mut a = self.addr(l, ip)?;
        if gen < a.seen || (gen == a.seen && a.withdrawn && via.is_some()) {
            return Ok(false);
        }
        let before = a.clone();
        (a.seen, a.withdrawn, a.via) = (gen, via.is_none(), via);
        if via.is_none() && a.lent.is_some_and(|lent| lent <= gen) {
            a.lent = None;
        }
        if a != before {
            self.put_addr(ip, &a, true)?;
        }
        Ok(true)
    }

    /// Whether the VM here holding `ip` keeps its route against a peer's
    /// message about generation `gen`: it has that one or newer, or is a
    /// migration's paused source (whose release moves the route).
    pub fn keeps_route(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        let a = self.addr(l, ip)?;
        let source = || a.holder.as_deref().and_then(|h| self.entry(h).ok()).is_some_and(|e| e.state == "source");
        Ok(self.held(&a) && (a.held >= gen || source()))
    }

    /// Puts back the route a peer announced for `ip`'s current generation
    /// once nothing here holds the address. Whether it did.
    pub fn reinstall(&self, l: &Locked, ip: Ipv4Addr) -> Result<bool> {
        let a = self.addr(l, ip)?;
        let Some(via) = a.via.filter(|_| !a.withdrawn && !self.held(&a)) else { return Ok(false) };
        crate::net::route_via(ip, via)?;
        eprintln!("put back route {ip} via {via} (generation {})", a.seen);
        Ok(true)
    }

    pub fn current(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        Ok(self.addr(l, ip)?.current(gen))
    }

    /// The VM here holding `ip`, if any.
    pub fn holder(&self, l: &Locked, ip: Ipv4Addr) -> Result<Option<String>> {
        let a = self.addr(l, ip)?;
        Ok(self.held(&a).then_some(a.holder).flatten())
    }

    /// Admits `mib` of VM memory unless it would take the host below its
    /// reserve. MemAvailable lags a grant until the guest touches the
    /// memory, so grants of the last `GRANT_WINDOW` (`RUN/grants`, all
    /// processes') count as used.
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

    // Incoming migrations: `STATE/migs/ID`, durable, changed under the host
    // lock. No record means aborted: one is made by `mig_begin` and goes when
    // its process gives up before committing, is found dead before
    // committing, or once the source says it is done with it.

    fn mig_path(&self, id: u64) -> PathBuf {
        self.state.join("migs").join(id.to_string())
    }

    /// Records migration `id` as pending here, for this process; once only.
    pub fn mig_begin(&self, id: u64) -> Result<MigRecord> {
        let _l = self.lock()?;
        if load::<Mig>(&self.mig_path(id))?.is_some() {
            bail!("migration {id} was already seen here");
        }
        store(&self.mig_path(id), &Mig::Pending { owner: Ident::me() }, true)?;
        Ok(MigRecord { host: self.clone(), id, committed: false })
    }

    /// How migration `id` went here: `pending`, `committed`, `released` (the
    /// VM has all its pages, or is gone) or `aborted`. One whose process died
    /// is settled first, once its Firecrackers are dead: aborted (the record
    /// goes) if it never committed, else released.
    pub fn mig_status(&self, id: u64) -> Result<&'static str> {
        let _l = self.lock()?;
        let path = self.mig_path(id);
        Ok(match load(&path)? {
            None => "aborted",
            Some(Mig::Released) => "released",
            Some(Mig::Pending { owner }) if owner.alive() => "pending",
            Some(Mig::Committed { owner }) if owner.alive() => "committed",
            Some(Mig::Pending { owner }) => {
                reap(&self.run, &owner)?;
                remove(&path)?;
                "aborted"
            }
            Some(Mig::Committed { owner }) => {
                reap(&self.run, &owner)?;
                store(&path, &Mig::Released, true)?;
                "released"
            }
        })
    }

    /// The source of migration `id` will never ask about it again.
    pub fn mig_done(&self, id: u64) -> Result<()> {
        let _l = self.lock()?;
        match load(&self.mig_path(id))? {
            Some(Mig::Released) => remove(&self.mig_path(id)),
            _ => Ok(()),
        }
    }
}

/// How long a grant of memory counts as used.
const GRANT_WINDOW: Duration = Duration::from_secs(10);

/// What a host knows about one of the addresses it has seen.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Addr {
    /// The newest generation seen, and whether it was withdrawn.
    pub seen: u64,
    pub withdrawn: bool,
    /// Of this host's range, gone with a VM of this generation (migrated, or
    /// restored elsewhere): not handed out until that VM is withdrawn or back.
    pub lent: Option<u64>,
    /// The VM here using it (alive or suspended), and with what generation.
    pub holder: Option<String>,
    pub held: u64,
    /// Where a peer said the newest generation's VM is (see `reinstall`).
    pub via: Option<Ipv4Addr>,
}

impl Addr {
    /// Whether generation `gen` may still be live: none newer, not withdrawn.
    pub fn current(&self, gen: u64) -> bool {
        gen > self.seen || (gen == self.seen && !self.withdrawn)
    }
}

/// A VM's claim on an address and generation. Dropped, it gives the address
/// back; a suspended VM `keep`s it.
pub struct AddrClaim {
    host: Host,
    pub ip: Ipv4Addr,
    pub gen: u64,
    holder: String,
    kept: bool,
    /// A generation made for this VM (not brought along): withdrawn even if
    /// the VM never ran.
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

/// An incoming migration's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Mig {
    /// Being taken in by `owner`; the VM has not run here.
    Pending { owner: Ident },
    /// The VM is `owner`'s, here: its source must never run it again.
    Committed { owner: Ident },
    /// The VM has all its memory here, or is gone: its source may go.
    Released,
}

/// A migration record this process made; dropped before it commits, the
/// record goes (aborted).
pub struct MigRecord {
    host: Host,
    pub id: u64,
    committed: bool,
}

impl MigRecord {
    /// Pending to committed: from here on this host owns the VM. Refused if
    /// the source's query fenced it off meanwhile.
    pub fn commit(&mut self, _: &Locked) -> Result<()> {
        let path = self.host.mig_path(self.id);
        match load(&path)? {
            Some(Mig::Pending { owner }) if owner == Ident::me() => store(&path, &Mig::Committed { owner }, true)?,
            m => bail!("migration {} was fenced off meanwhile ({m:?})", self.id),
        }
        self.committed = true;
        Ok(())
    }

    /// Committed to released (the VM has all its memory), retried until it
    /// is recorded: the source waits for it.
    pub fn release(self) {
        let mut delay = Duration::from_millis(100);
        while let Err(e) = self.host.lock().and_then(|_l| store(&self.host.mig_path(self.id), &Mig::Released, true)) {
            eprintln!("migration {}: {e}; retrying", self.id);
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    }
}

impl Drop for MigRecord {
    fn drop(&mut self) {
        if let (false, Ok(_l)) = (self.committed, self.host.lock()) {
            let path = self.host.mig_path(self.id);
            if matches!(load(&path), Ok(Some(Mig::Pending { owner })) if owner == Ident::me()) {
                let _ = remove(&path);
            }
        }
    }
}

/// The host lock, held until dropped (by its first taker in this thread).
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

/// A VM process's claim on its name. Dropping it removes the registry entry.
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

/// A VM in the registry (`RUN/vms/NAME.json`).
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
    /// running, paused, checkpointing, source, failed
    pub state: String,
    pub firecracker: Option<u32>,
    /// Needs more memory than this host can give it.
    pub starved: bool,
}

/// A process, by pid, start time and boot: one process, however pids are reused.
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

    /// Process `pid` as it is now, if alive.
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

/// A pidfd: signals through it reach the process it was opened for or none.
pub struct PidFd(OwnedFd);

impl PidFd {
    /// A pidfd for `id`, or None if that process is gone.
    pub fn open(id: &Ident) -> Result<Option<PidFd>> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, id.pid, 0) };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ESRCH) {
                return Ok(None);
            }
            bail!("pidfd_open {}: {e}", id.pid);
        }
        let fd = PidFd(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        // Opened first, then checked: if it is `id` now, the fd is `id`'s.
        Ok(id.alive().then_some(fd))
    }

    pub fn signal(&self, sig: i32) -> Result<()> {
        if unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.0.as_raw_fd(), sig, std::ptr::null::<libc::siginfo_t>(), 0) } < 0 {
            bail!("signal {sig}: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Waits up to `timeout` for the process to exit.
    pub fn wait(&self, timeout: Duration) -> bool {
        let mut pfd = libc::pollfd { fd: self.0.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let end = std::time::Instant::now() + timeout;
        loop {
            match unsafe { libc::poll(&mut pfd, 1, end.saturating_duration_since(std::time::Instant::now()).as_millis() as i32) } {
                n if n > 0 => return true,
                n if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
                _ => return false,
            }
        }
    }
}

/// Kills the Firecrackers dead VM process `owner` left (recorded in its work
/// directory `RUN/w/PID`, if `owner` is still its owner) and waits for them
/// to exit. They die with the process anyway, but not at once.
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

/// Removes what dead VM processes left: taps, cgroups and work directories
/// named after them (only names this host's `prefix` makes).
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
}

pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 || name.starts_with('.') || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        bail!("bad vm name {name:?}: up to 64 letters, digits, '-', '_' or '.', not starting with '.'");
    }
    Ok(())
}

pub fn flock(f: &File, how: i32) -> std::io::Result<()> {
    while unsafe { libc::flock(f.as_raw_fd(), how) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    Ok(())
}

/// Opens and locks `path`, making sure the lock is on the file the path
/// names (a holder may unlink it just before we lock).
fn lock_path(path: &Path, how: i32) -> std::io::Result<File> {
    loop {
        let f = File::options().create(true).truncate(false).read(true).write(true).open(path)?;
        flock(&f, how)?;
        if std::fs::metadata(path).is_ok_and(|m| f.metadata().is_ok_and(|n| n.ino() == m.ino())) {
            return Ok(f);
        }
    }
}

/// Replaces `dir/name` atomically; with `durable`, survives a power loss.
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

/// The start time (field 22 of /proc/PID/stat) of a live process.
pub fn starttime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    (fields.first() != Some(&"Z")).then_some(())?;
    fields.get(19)?.parse().ok()
}

/// Whether test fault `name` (`flexvm debug fault`, in `RUN/faults.json`) is
/// armed; only with FLEXVM_FAULTS=1.
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

/// Test hook: waits 3 s where `name` is armed, for a test to kill the process there.
pub fn stall(name: &str) {
    if fault(name) {
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// Arms `name` for `ms` (0 disarms it).
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
    // A cached copy is reread on the next mtime change; make sure there is one.
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

    /// A dead process whose work directory records `fcs` as its Firecrackers.
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

    /// A process standing in for a Firecracker; reaped by `done`.
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
        // An entry is only believed for the process holding the name.
        a.publish(&Entry { name: "a".into(), ident: Ident { start: 1, ..Ident::me() }, ..Entry::default() }).unwrap();
        assert!(h.entry("a").is_err() && h.signal("a", 0).is_err());
        drop(a);
        assert!(!h.alive("a") && h.entries().is_empty() && h.entry("a").is_err());
        let _again = h.take_name("a", false).unwrap();
        for bad in ["", ".x", "a/b", &"x".repeat(65)] {
            assert!(h.take_name(bad, false).is_err());
        }
        std::fs::create_dir_all(h.suspended("s")).unwrap();
        assert!(h.take_name("s", false).is_err() && h.take_name("s", true).is_ok());
    }

    #[test]
    fn a_dead_holders_firecrackers_die_before_its_name_or_address_is_free() {
        let h = host("reap");
        // Its address is free only once its Firecracker has exited.
        let fc = Sleeper::new();
        store(&h.vms("d", "lock"), &dead_owner(&h, 999_999_901, &[&fc.1]), false).unwrap();
        let l = h.lock().unwrap();
        h.put_addr(ip("10.9.0.1"), &Addr { seen: 1, holder: Some("d".into()), ..Addr::default() }, false).unwrap();
        assert!(fc.1.alive());
        assert!(h.claim_new(&l, "x", Some(ip("10.9.0.1"))).unwrap().gen > 1 && fc.done());
        // The same for its name, taken over.
        let fc = Sleeper::new();
        store(&h.vms("e", "lock"), &dead_owner(&h, 999_999_902, &[&fc.1]), false).unwrap();
        let _e = h.take_name("e", false).unwrap();
        assert!(fc.done());
        // A work directory another process owns now is left alone.
        let fc = Sleeper::new();
        dead_owner(&h, 999_999_903, &[&fc.1]);
        reap(&h.run, &Ident { pid: 999_999_903, start: 2, boot: boot_id().into() }).unwrap();
        assert!(!fc.done());
    }

    #[test]
    fn addresses_generations_and_loans() {
        let h = host("addrs");
        let _a = h.take_name("a", false).unwrap();
        let l = h.lock().unwrap();
        let a = h.claim_new(&l, "a", None).unwrap();
        let (a_ip, g1) = (a.ip, a.gen);
        assert_eq!(a_ip, ip("10.9.0.1"));
        // Held by a live VM: the next claim gets another address.
        let b = h.claim_new(&l, "b-dead", None).unwrap();
        assert!(b.ip == ip("10.9.0.2") && b.gen > g1);
        // b-dead is not alive: its address is free again, with a newer generation.
        let c = h.claim_new(&l, "c", Some(b.ip)).unwrap();
        assert!(c.gen > b.gen);
        b.keep();
        c.keep();
        assert!(h.claim_new(&l, "x", Some(a_ip)).is_err() && h.claim_new(&l, "x", Some(ip("10.9.9.9"))).is_err());
        // a leaves: lent until withdrawn with its generation or a newer one.
        h.lend(&l, a_ip, g1).unwrap();
        a.release(&l).unwrap();
        assert!(h.claim_new(&l, "x", Some(a_ip)).is_err());
        assert!(!h.observe(&l, a_ip, g1 - 1, None).unwrap(), "older withdrawal is stale");
        assert!(h.addr(&l, a_ip).unwrap().lent.is_some());
        assert!(h.observe(&l, a_ip, g1, None).unwrap() && h.addr(&l, a_ip).unwrap().lent.is_none());
        // An announcement of a withdrawn generation is stale; a newer one is not.
        let via = Some(ip("192.0.2.1"));
        assert!(!h.observe(&l, a_ip, g1, via).unwrap() && !h.current(&l, a_ip, g1).unwrap());
        assert!(h.observe(&l, a_ip, g1 + 5, via).unwrap() && h.addr(&l, a_ip).unwrap().via == via);
        // An arrival with an old or no generation is refused, a current one taken in.
        assert!(h.claim_incoming(&l, "y", a_ip, g1).is_err() && h.claim_incoming(&l, "y", a_ip, 0).is_err());
        h.claim_incoming(&l, "y", a_ip, g1 + 5).unwrap().keep();
        h.commit_incoming(&l, a_ip, g1 + 5).unwrap();
        // A newer generation than a withdrawn one is current again.
        assert!(h.observe(&l, a_ip, g1 + 5, None).unwrap());
        h.claim_incoming(&l, "y", a_ip, g1 + 6).unwrap().keep();
        assert!(h.current(&l, a_ip, g1 + 6).unwrap());
        // A refused claim of a held address gives nothing back.
        let _w = h.take_name("w", false).unwrap();
        let wc = h.claim_new(&l, "w", Some(ip("10.9.0.3"))).unwrap();
        assert!(h.claim_incoming(&l, "w2", wc.ip, wc.gen).is_err());
        assert_eq!(h.holder(&l, wc.ip).unwrap().as_deref(), Some("w"));
        // Another VM's claim, dropped, gives back nothing of w's either.
        drop(h.claim_new(&l, "v", None));
        assert_eq!(h.holder(&l, wc.ip).unwrap().as_deref(), Some("w"));
        wc.keep();
        // A record that cannot be read is an error, never a free address.
        std::fs::write(h.addr_path(ip("10.9.0.3")), "{").unwrap();
        assert!(h.addr(&l, ip("10.9.0.3")).is_err() && h.claim_new(&l, "z", Some(ip("10.9.0.3"))).is_err());
        // Generations survive a "reboot": a new boot id jumps to the reserved mark.
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
        // The borrower's withdrawal gives it back, with newer generations after.
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
        // Unknown: aborted, and nothing is recorded.
        assert!(h.mig_status(1).unwrap() == "aborted" && rec(1).is_none());
        // Given up before committing: aborted.
        let r = h.mig_begin(2).unwrap();
        assert!(h.mig_begin(2).is_err() && h.mig_status(2).unwrap() == "pending");
        drop(r);
        assert_eq!(h.mig_status(2).unwrap(), "aborted");
        // Committed, released, forgotten once its source is done with it.
        let mut r = h.mig_begin(3).unwrap();
        r.commit(&h.lock().unwrap()).unwrap();
        h.mig_done(3).unwrap();
        assert_eq!(h.mig_status(3).unwrap(), "committed", "only a released one is forgotten");
        r.release();
        assert_eq!(h.mig_status(3).unwrap(), "released");
        h.mig_done(3).unwrap();
        assert!(rec(3).is_none());
        // Fenced off by a query that found its owner dead: no commit.
        let mut r = h.mig_begin(4).unwrap();
        store(&h.mig_path(4), &Mig::Pending { owner: dead_owner(&h, 999_999_904, &[]) }, false).unwrap();
        assert!(h.mig_status(4).unwrap() == "aborted" && rec(4).is_none() && r.commit(&h.lock().unwrap()).is_err());
        // Committed by a process that is gone: released once its Firecracker is.
        let fc = Sleeper::new();
        store(&h.mig_path(5), &Mig::Committed { owner: dead_owner(&h, 999_999_905, &[&fc.1]) }, false).unwrap();
        assert!(h.mig_status(5).unwrap() == "released" && fc.done());
        // A record that cannot be read answers nothing.
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
