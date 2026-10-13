//! Host-wide state, shared by the VM processes and the peer listener through
//! files: the host's configuration, the VM registry, address generations and
//! loans, incoming migration records and armed test faults. Acquisitions
//! (names, addresses, migration records) are guards that give back exactly
//! what they took when dropped.
//!
//! Short critical sections take the host lock (`STATE/lock`); nothing slow
//! (network, Firecracker) happens under it. A VM process holds an exclusive
//! lock on `RUN/vms/NAME.lock` for as long as it lives, with its identity in
//! it: that lock is its claim on the name and the proof that its registry
//! entry is current. A process that died is only taken for gone once the
//! Firecrackers it started have exited (`reap`).

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::bail;
use crate::net::IpRange;
use crate::util::Result;

/// The host's configuration (`STATE/host.json`, written by `flexvm listen`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Where this host's peer listener takes migrations and page requests;
    /// the address peers reach it at.
    pub listen: Option<String>,
    pub peers: Vec<String>,
    /// The addresses this host hands to new VMs. Disjoint across hosts.
    pub vm_ips: String,
    /// This host's address on the network shared with peers (default: the
    /// listen address's).
    pub underlay: Option<Ipv4Addr>,
    /// Answer ARP for local VMs on this interface, announce arrivals there.
    pub announce_dev: Option<String>,
    pub dns: Option<String>,
    /// Memory to keep free (MiB): migrations in are refused below it, VMs
    /// are moved away, standby VMs are not made.
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

    /// This host's address for peers' routes.
    pub fn underlay(&self) -> Option<Ipv4Addr> {
        self.underlay.or_else(|| self.listen.as_deref()?.rsplit_once(':')?.0.parse().ok())
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
    /// The host whose durable state is in `state` and runtime state in `run`.
    pub fn open(state: &Path, run: &Path) -> Result<Host> {
        // Made if we can (root); a reader such as `ls` does without.
        for d in [state.join("addrs"), state.join("standby"), state.join("migs")] {
            if !d.is_dir() {
                let _ = crate::util::create_dir_durably(&d);
            }
        }
        // Suspended VMs' memory: root's alone.
        let _ = crate::util::create_private_dir_durably(&state.join("suspended"));
        for d in ["vms", "standby", "w"] {
            let _ = std::fs::create_dir_all(run.join(d));
        }
        let canon = |d: &Path| d.canonicalize().map_err(|e| format!("{}: {e} (run flexvm as root to create it)", d.display()));
        let (state, run) = (canon(state)?, canon(run)?);
        let _ = RUN_DIR.set(run.clone());
        let mut h = Host { state, run, cfg: Config::default() };
        h.cfg = h.read_config()?;
        Ok(h)
    }

    fn read_config(&self) -> Result<Config> {
        match std::fs::read(self.state.join("host.json")) {
            Ok(b) => Ok(serde_json::from_slice(&b).map_err(|e| format!("{}/host.json: {e}", self.state.display()))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => bail!("{}/host.json: {e}", self.state.display()),
        }
    }

    /// Changes the configuration as it is on disk now, under the host lock,
    /// so concurrent changes to other settings are kept.
    pub fn configure(&mut self, change: impl FnOnce(&mut Config) -> Result<()>) -> Result<()> {
        let _l = self.lock()?;
        let mut cfg = self.read_config()?;
        change(&mut cfg)?;
        write_file(&self.state, "host.json", &serde_json::to_vec_pretty(&cfg)?, true)?;
        self.cfg = cfg;
        Ok(())
    }

    /// Takes the host lock until the guard is dropped. A thread that holds
    /// it already gets it again (a guard dropped under it, say); other
    /// threads of the process wait as other processes do.
    pub fn lock(&self) -> Result<Locked> {
        if DEPTH.with(|d| d.get()) > 0 {
            DEPTH.with(|d| d.set(d.get() + 1));
            return Ok(Locked(None));
        }
        let inner = THREADS.lock().unwrap_or_else(|e| e.into_inner());
        let f = File::options().create(true).truncate(false).write(true).open(self.state.join("lock"))?;
        flock(&f, libc::LOCK_EX)?;
        DEPTH.with(|d| d.set(1));
        Ok(Locked(Some((f, inner))))
    }

    /// A VM's control socket.
    pub fn sock(&self, name: &str) -> PathBuf {
        self.run.join("vms").join(format!("{name}.sock"))
    }

    fn name_lock(&self, name: &str) -> PathBuf {
        self.run.join("vms").join(format!("{name}.lock"))
    }

    /// Where a suspended VM's checkpoint lives.
    pub fn suspended(&self, name: &str) -> PathBuf {
        self.state.join("suspended").join(name)
    }

    /// Takes `name` for this process, for as long as the returned lock lives.
    /// Refused if a live process has it, or a suspended VM (unless
    /// `resuming` it). What a dead holder left running goes first.
    pub fn take_name(&self, name: &str, resuming: bool) -> Result<NameLock> {
        check_name(name)?;
        if !resuming && self.suspended(name).exists() {
            bail!("vm {name:?} exists (suspended); resume or kill it");
        }
        let mut f = lock_path(&self.name_lock(name), libc::LOCK_EX | libc::LOCK_NB).map_err(|_| format!("vm name {name:?} is taken"))?;
        // Left by a holder that died with the name: what it ran goes first.
        if let Some(old) = read_ident(&mut f).filter(|o| !o.alive()) {
            reap(&self.run, old)?;
        }
        let dir = self.run.join("vms");
        for ext in ["json", "sock", "moved", "failed"] {
            let _ = std::fs::remove_file(dir.join(format!("{name}.{ext}")));
        }
        f.set_len(0)?;
        f.write_all_at(Ident::me().to_string().as_bytes(), 0)?;
        Ok(NameLock { name: name.into(), dir, _file: f })
    }

    /// Whether a live process holds `name`.
    pub fn alive(&self, name: &str) -> bool {
        match File::open(self.name_lock(name)) {
            Ok(f) => flock(&f, libc::LOCK_SH | libc::LOCK_NB).is_err(),
            Err(_) => false,
        }
    }

    /// The process holding `name`, as it wrote itself into the name's lock.
    fn holder_of(&self, name: &str) -> Option<Ident> {
        File::open(self.name_lock(name)).ok().and_then(|mut f| read_ident(&mut f))
    }

    /// Whether nothing of VM `name` runs here any more: no process holds the
    /// name, and the Firecrackers of the last one that did have exited.
    fn gone(&self, name: &str) -> bool {
        if self.alive(name) {
            return false;
        }
        match self.holder_of(name) {
            Some(id) => !id.alive() && reap(&self.run, id).is_ok(),
            None => true,
        }
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

    /// The registry entry of live VM `name`: written by the process that
    /// holds the name now.
    pub fn entry(&self, name: &str) -> Result<Entry> {
        let path = self.run.join("vms").join(format!("{name}.json"));
        let entry: Option<Entry> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok());
        match entry {
            Some(e) if self.alive(name) && self.holder_of(name) == Some(e.ident()) => Ok(e),
            _ => bail!("no vm named {name:?}"),
        }
    }

    /// Sends `sig` to the process of live VM `name`. The pidfd returned
    /// refers to that process and no other, even once it is gone.
    pub fn signal(&self, name: &str, sig: i32) -> Result<PidFd> {
        let e = self.entry(name)?;
        let fd = PidFd::open(e.ident())?.ok_or_else(|| format!("no vm named {name:?}"))?;
        fd.signal(sig)?;
        Ok(fd)
    }

    // Addresses and generations. Every function here wants the host lock.

    fn addr_path(&self, ip: Ipv4Addr) -> PathBuf {
        self.state.join("addrs").join(ip.to_string())
    }

    /// What this host knows about `ip`. A record that cannot be read is an
    /// error, never a free address.
    pub fn addr(&self, _: &Locked, ip: Ipv4Addr) -> Result<Addr> {
        match std::fs::read(self.addr_path(ip)) {
            Ok(b) => Ok(serde_json::from_slice(&b).map_err(|e| format!("address record {ip}: {e}"))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Addr::default()),
            Err(e) => bail!("address record {ip}: {e}"),
        }
    }

    fn put_addr(&self, ip: Ipv4Addr, a: &Addr, durable: bool) -> Result<()> {
        write_file(&self.state.join("addrs"), &ip.to_string(), &serde_json::to_vec(a)?, durable)
            .map_err(|e| format!("cannot record address {ip}: {e}"))?;
        Ok(())
    }

    /// Whether `a`'s holder is a VM here: running, or suspended.
    fn held(&self, a: &Addr) -> bool {
        a.holder.as_deref().is_some_and(|h| !self.gone(h) || self.suspended(h).exists())
    }

    /// Hands an address of this host's range to new VM `holder`, with a new
    /// generation: `want`, or the first free one.
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
        let mut a = self.addr(l, ip)?;
        let gen = self.next_gen(a.seen)?;
        a = Addr { seen: gen, holder: Some(holder.into()), held: gen, lent: a.lent, ..Addr::default() };
        // The high-water mark orders generations; this record need not be durable.
        self.put_addr(ip, &a, false)?;
        Ok(AddrClaim { host: self.clone(), ip, gen, holder: holder.into(), kept: false, fresh: true })
    }

    /// Lends `ip`, from this host's range, to a peer restoring a checkpoint
    /// with it: if no VM here has it and it is not lent out, it is, durably,
    /// with a new generation (returned). The VM's withdrawal wherever it is,
    /// or its migrating here, gives it back.
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

    /// A generation newer than `seen` and than any handed out here before,
    /// across crashes: a high-water mark reserved `GEN_BLOCK` at a time, and
    /// after a reboot (the boot id changed) taken up from the reserved one.
    fn next_gen(&self, seen: u64) -> Result<u64> {
        const GEN_BLOCK: u64 = 1024;
        let boot = boot_id();
        let dir = self.state.join("addrs");
        let text = match std::fs::read_to_string(dir.join(".gens")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            r => r.map_err(|e| format!("address generations: {e}"))?,
        };
        let mut f = text.split_whitespace();
        let mut num = || f.next().map(|s| s.parse::<u64>().map_err(|_| "address generations: corrupt record")).transpose();
        let (next, reserved) = (num()?.unwrap_or(1), num()?.unwrap_or(0));
        let next = if f.next() == Some(&boot) { next } else { next.max(reserved) };
        let gen = next.max(seen + 1);
        let (reserved, durable) = if gen >= reserved { (gen + GEN_BLOCK, true) } else { (reserved, false) };
        write_file(&dir, ".gens", format!("{} {reserved} {boot}", gen + 1).as_bytes(), durable)
            .map_err(|e| format!("cannot record address generations: {e}"))?;
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

    /// `holder` lets go of `ip` (killed, suspended elsewhere, gone).
    pub fn release(&self, l: &Locked, ip: Ipv4Addr, holder: &str) -> Result<()> {
        let mut a = self.addr(l, ip)?;
        if a.holder.as_deref() == Some(holder) {
            a.holder = None;
            self.put_addr(ip, &a, false)?;
        }
        Ok(())
    }

    /// Records `ip`, from this host's range, as lent with generation `gen`
    /// (its VM is about to leave), durably, or fails.
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

    /// Takes in a message about generation `gen` of `ip`: an announcement
    /// that its VM is at `via`, or (None) a withdrawal. Returns false if it
    /// is stale (an older generation, or an announcement of a withdrawn
    /// one). A withdrawal frees a loan of its generation or an older one.
    pub fn observe(&self, l: &Locked, ip: Ipv4Addr, gen: u64, via: Option<Ipv4Addr>) -> Result<bool> {
        let mut a = self.addr(l, ip)?;
        let withdrawn = via.is_none();
        if gen < a.seen || (gen == a.seen && a.withdrawn && !withdrawn) {
            return Ok(false);
        }
        let before = a.clone();
        (a.seen, a.withdrawn, a.via) = (gen, withdrawn, via);
        if withdrawn && a.lent.is_some_and(|lent| lent <= gen) {
            a.lent = None;
        }
        if a != before {
            self.put_addr(ip, &a, true)?;
        }
        Ok(true)
    }

    /// Whether the VM here holding `ip` keeps its route against a peer's
    /// message about generation `gen`: it has that generation or a newer
    /// one, or it is a migration's paused source (whose release moves the
    /// route).
    pub fn keeps_route(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        let a = self.addr(l, ip)?;
        let source = || a.holder.as_deref().and_then(|h| self.entry(h).ok()).is_some_and(|e| e.state == "source");
        Ok(self.held(&a) && (a.held >= gen || source()))
    }

    /// Puts back the route a peer announced for `ip`'s current generation,
    /// once nothing here holds the address: a claim or hold of it here that
    /// kept the route has gone without the VM running here. Whether it did.
    pub fn reinstall(&self, l: &Locked, ip: Ipv4Addr) -> Result<bool> {
        let a = self.addr(l, ip)?;
        let Some(via) = a.via.filter(|_| !a.withdrawn && !self.held(&a)) else { return Ok(false) };
        crate::net::route_via(ip, via)?;
        eprintln!("put back route {ip} via {via} (generation {})", a.seen);
        Ok(true)
    }

    /// Whether generation `gen` of `ip` may still be live here.
    pub fn current(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        Ok(self.addr(l, ip)?.current(gen))
    }

    /// The VM here holding `ip`, if any.
    pub fn holder(&self, l: &Locked, ip: Ipv4Addr) -> Result<Option<String>> {
        let a = self.addr(l, ip)?;
        Ok(self.held(&a).then_some(a.holder).flatten())
    }

    /// Admits `mib` of VM growth unless it would take the host below its
    /// reserve. Plugging costs the host nothing until the guest touches the
    /// memory, so MemAvailable lags every grant: those of the last
    /// `GRANT_WINDOW` (in `RUN/grants`, all VM processes') count as used.
    /// Under the host lock, so concurrent requests cannot each see the same
    /// free memory.
    pub fn admit(&self, mib: u64) -> bool {
        let Ok(_l) = self.lock() else { return false };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let mut grants: Vec<(u64, u64)> = std::fs::read_to_string(self.run.join("grants"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let (t, m) = l.split_once(' ')?;
                Some((t.parse().ok()?, m.parse().ok()?))
            })
            .filter(|&(t, _)| now.saturating_sub(t) <= GRANT_WINDOW.as_millis() as u64)
            .collect();
        let pending: u64 = grants.iter().map(|g| g.1).sum();
        if crate::vmproc::host_available_mib() < self.cfg.reserve_mib + pending + mib {
            return false;
        }
        grants.push((now, mib));
        let text: String = grants.iter().map(|(t, m)| format!("{t} {m}\n")).collect();
        write_file(&self.run, "grants", text.as_bytes(), false).is_ok()
    }

    // Incoming migrations: `STATE/migs/ID`, durable, changed under the host
    // lock. No record means aborted: a record is only made by `mig_begin`,
    // and goes when its process gives up before committing, when it is found
    // dead before committing, or once the source says it is done with it.

    fn mig_read(&self, id: u64) -> Result<Option<Mig>> {
        match std::fs::read(self.state.join("migs").join(id.to_string())) {
            Ok(b) => Ok(Some(serde_json::from_slice(&b).map_err(|e| format!("migration record {id}: {e}"))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => bail!("migration record {id}: {e}"),
        }
    }

    fn mig_write(&self, id: u64, m: &Mig) -> Result<()> {
        write_file(&self.state.join("migs"), &id.to_string(), &serde_json::to_vec(m)?, true)
            .map_err(|e| format!("cannot record migration {id}: {e}"))?;
        Ok(())
    }

    fn mig_remove(&self, id: u64) -> Result<()> {
        let dir = self.state.join("migs");
        match std::fs::remove_file(dir.join(id.to_string())) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => bail!("migration record {id}: {e}"),
            _ => Ok(File::open(&dir)?.sync_all()?),
        }
    }

    /// Records migration `id` as pending here, for this process. An id is
    /// taken in only once.
    pub fn mig_begin(&self, id: u64) -> Result<MigRecord> {
        let _l = self.lock()?;
        if self.mig_read(id)?.is_some() {
            bail!("migration {id} was already seen here");
        }
        self.mig_write(id, &Mig::Pending { owner: Owner::me() })?;
        Ok(MigRecord { host: self.clone(), id, committed: false })
    }

    /// How migration `id` went here, for its source: `pending`, `committed`,
    /// `released` (the VM has all its pages, or is gone) or `aborted`. One
    /// whose process died is settled first, once its Firecrackers are dead
    /// too: aborted (its record goes) if it never committed, else released.
    pub fn mig_status(&self, id: u64) -> Result<&'static str> {
        let _l = self.lock()?;
        Ok(match self.mig_read(id)? {
            None => "aborted",
            Some(Mig::Released) => "released",
            Some(Mig::Pending { owner }) if owner.alive() => "pending",
            Some(Mig::Committed { owner }) if owner.alive() => "committed",
            Some(Mig::Pending { owner }) => {
                owner.reap(&self.run)?;
                self.mig_remove(id)?;
                "aborted"
            }
            Some(Mig::Committed { owner }) => {
                owner.reap(&self.run)?;
                self.mig_write(id, &Mig::Released)?;
                "released"
            }
        })
    }

    /// The source of migration `id` will never ask about it again.
    pub fn mig_done(&self, id: u64) -> Result<()> {
        let _l = self.lock()?;
        match self.mig_read(id)? {
            Some(Mig::Released) => self.mig_remove(id),
            _ => Ok(()),
        }
    }
}

/// How long a grant of memory counts as used: the guest touches what it asked
/// for gradually, and MemAvailable only shows it once touched.
const GRANT_WINDOW: Duration = Duration::from_secs(10);

/// What a host knows about one of the addresses it has seen.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Addr {
    /// The newest generation seen, and whether it was withdrawn.
    pub seen: u64,
    pub withdrawn: bool,
    /// From this host's range, gone with a VM of this generation that
    /// migrated away: not handed out until that VM is withdrawn wherever it
    /// is, or comes back.
    pub lent: Option<u64>,
    /// The VM here using it (alive or suspended), if any, and with what
    /// generation.
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
    /// A generation made for this VM (not one it brought along): withdrawn
    /// even if the VM never ran.
    pub fresh: bool,
}

impl AddrClaim {
    /// The address stays held by the VM's name (suspended).
    pub fn keep(mut self) {
        self.kept = true;
    }

    /// Gives the address back, for a caller holding the host lock.
    pub fn release(mut self, l: &Locked) -> Result<()> {
        self.kept = true;
        self.host.release(l, self.ip, &self.holder)
    }
}

impl Drop for AddrClaim {
    fn drop(&mut self) {
        if !self.kept {
            if let Ok(l) = self.host.lock() {
                let _ = self.host.release(&l, self.ip, &self.holder);
            }
        }
    }
}

/// An incoming migration's record (`STATE/migs/ID`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Mig {
    /// Being taken in by `owner`; the VM has not run here.
    Pending { owner: Owner },
    /// The VM is `owner`'s, here: its source must never run it again.
    Committed { owner: Owner },
    /// The VM has all its memory here, or is gone: its source may go.
    Released,
}

/// A migration record this process made. Dropped before it commits, the
/// record goes: the migration aborted.
pub struct MigRecord {
    host: Host,
    pub id: u64,
    committed: bool,
}

impl MigRecord {
    /// Pending to committed, under the host lock: from here on this host
    /// owns the VM. Refused if the source's query fenced it off meanwhile.
    pub fn commit(&mut self, _: &Locked) -> Result<()> {
        match self.host.mig_read(self.id)? {
            Some(Mig::Pending { owner }) if owner == Owner::me() => self.host.mig_write(self.id, &Mig::Committed { owner })?,
            m => bail!("migration {} was fenced off meanwhile ({m:?})", self.id),
        }
        self.committed = true;
        Ok(())
    }

    /// Committed to released: the VM has all its memory. Retried until it
    /// is recorded (the source waits for it).
    pub fn release(self) {
        let mut delay = Duration::from_millis(100);
        loop {
            match self.host.lock().and_then(|_l| self.host.mig_write(self.id, &Mig::Released)) {
                Ok(()) => return,
                Err(e) => eprintln!("migration {}: {e}; retrying", self.id),
            }
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    }
}

impl Drop for MigRecord {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Ok(_l) = self.host.lock() {
            if matches!(self.host.mig_read(self.id), Ok(Some(Mig::Pending { owner })) if owner == Owner::me()) {
                let _ = self.host.mig_remove(self.id);
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

/// The threads of this process take the host lock one at a time...
static THREADS: Mutex<()> = Mutex::new(());
thread_local! {
    /// ...and a thread holding it may take it again.
    static DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A VM process's claim on its name. Dropping it removes the registry entry.
pub struct NameLock {
    pub name: String,
    dir: PathBuf,
    _file: File,
}

impl NameLock {
    /// Writes (replaces) this VM's registry entry.
    pub fn publish(&self, e: &Entry) -> Result<()> {
        write_file(&self.dir, &format!("{}.json", self.name), &serde_json::to_vec(e)?, false)?;
        Ok(())
    }
}

impl Drop for NameLock {
    fn drop(&mut self) {
        // Unlinked while held: a taker re-checks the path after locking.
        for ext in ["json", "sock", "lock"] {
            let _ = std::fs::remove_file(self.dir.join(format!("{}.{ext}", self.name)));
        }
    }
}

/// A VM in the registry (`RUN/vms/NAME.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    pub name: String,
    pub pid: u32,
    /// The process's start time: with `pid`, names it even once the pid is reused.
    pub start: u64,
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

impl Entry {
    pub fn ident(&self) -> Ident {
        Ident { pid: self.pid, start: self.start }
    }
}

/// A process, by pid and start time: names one process even once the pid
/// is reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ident {
    pub pid: u32,
    pub start: u64,
}

impl Ident {
    pub fn me() -> Ident {
        Ident::of(std::process::id()).expect("no /proc/self/stat")
    }

    /// Process `pid` as it is now, if it is alive.
    pub fn of(pid: u32) -> Option<Ident> {
        Some(Ident { pid, start: starttime(pid)? })
    }

    pub fn alive(&self) -> bool {
        starttime(self.pid) == Some(self.start)
    }
}

impl std::fmt::Display for Ident {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} {}", self.pid, self.start)
    }
}

impl std::str::FromStr for Ident {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Ident, ()> {
        let (pid, start) = s.trim().split_once(' ').ok_or(())?;
        Ok(Ident { pid: pid.parse().map_err(drop)?, start: start.parse().map_err(drop)? })
    }
}

fn read_ident(f: &mut File) -> Option<Ident> {
    let mut s = String::new();
    std::io::Read::read_to_string(f, &mut s).ok()?;
    s.parse().ok()
}

/// A process of this boot, for durable records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    #[serde(flatten)]
    pub id: Ident,
    pub boot: String,
}

impl Owner {
    pub fn me() -> Owner {
        Owner { id: Ident::me(), boot: boot_id() }
    }

    pub fn alive(&self) -> bool {
        self.boot == boot_id() && self.id.alive()
    }

    /// Kills what Firecrackers this dead process left, and waits for them.
    fn reap(&self, run: &Path) -> Result<()> {
        if self.boot == boot_id() {
            reap(run, self.id)?;
        }
        Ok(())
    }
}

pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default().trim().to_string()
}

/// A pidfd: signals sent through it reach the process it was opened for or
/// none, however the pid is reused.
pub struct PidFd(std::os::fd::OwnedFd);

impl PidFd {
    /// A pidfd for `id`, or None if that process is gone.
    pub fn open(id: Ident) -> Result<Option<PidFd>> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, id.pid, 0) };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ESRCH) {
                return Ok(None);
            }
            bail!("pidfd_open {}: {e}", id.pid);
        }
        let fd = PidFd(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) });
        // Opened first, then checked: if it is `id` now, the fd is `id`'s.
        Ok(id.alive().then_some(fd))
    }

    pub fn signal(&self, sig: i32) -> Result<()> {
        let r = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.0.as_raw_fd(), sig, std::ptr::null::<libc::siginfo_t>(), 0) };
        if r < 0 {
            bail!("signal {sig}: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Waits up to `timeout` for the process to exit.
    pub fn wait(&self, timeout: Duration) -> bool {
        let mut pfd = libc::pollfd { fd: self.0.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let end = std::time::Instant::now() + timeout;
        loop {
            let left = end.saturating_duration_since(std::time::Instant::now()).as_millis() as i32;
            match unsafe { libc::poll(&mut pfd, 1, left) } {
                n if n > 0 => return true,
                0 => return false,
                _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => continue,
                _ => return false,
            }
        }
    }
}

/// Kills the Firecrackers dead VM process `owner` left (each recorded in its
/// work directory, `RUN/w/PID`, as the directory's own `owner` file names
/// it), and waits until they have exited. They die with the process (see
/// `Firecracker::spawn`), but not at once.
pub fn reap(run: &Path, owner: Ident) -> Result<()> {
    if owner.alive() {
        bail!("process {} is alive", owner.pid);
    }
    let dir = run.join("w").join(owner.pid.to_string());
    if std::fs::read_to_string(dir.join("owner")).ok().and_then(|s| s.parse().ok()) != Some(owner) {
        return Ok(());
    }
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let Some(fc) = std::fs::read_to_string(e.path().join("fc")).ok().and_then(|s| s.parse().ok()) else { continue };
        if let Some(fd) = PidFd::open(fc)? {
            fd.signal(libc::SIGKILL)?;
            if !fd.wait(Duration::from_secs(5)) {
                bail!("firecracker {} of dead process {} will not exit", fc.pid, owner.pid);
            }
        }
    }
    Ok(())
}

/// Removes what VM processes that died left behind: taps, cgroups and work
/// directories named after their pids. Only names this host's `prefix`
/// makes, and only of processes that are gone.
pub fn collect_garbage(run: &Path, prefix: &str) {
    let gone = |pid: &str| u32::from_str_radix(pid, 16).ok().is_some_and(|p| starttime(p).is_none());
    for e in std::fs::read_dir("/sys/class/net").into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let Some(rest) = n.strip_prefix(prefix) else { continue };
        if let Some(pid) = rest.split_once('t').map(|(p, _)| p).filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_hexdigit())) {
            if gone(pid) {
                crate::net::delete_tap(&n);
            }
        }
    }
    for e in std::fs::read_dir("/sys/fs/cgroup/flexvm").into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let pid = n.strip_prefix("idle-").and_then(|r| r.split('-').next()).and_then(|p| p.parse::<u32>().ok());
        if pid.is_some_and(|p| starttime(p).is_none()) {
            let _ = std::fs::write(e.path().join("cgroup.kill"), "1");
            let _ = std::fs::remove_dir(e.path());
        }
    }
    for e in std::fs::read_dir(run.join("w")).into_iter().flatten().flatten() {
        let owner = std::fs::read_to_string(e.path().join("owner")).ok().and_then(|s| s.parse::<Ident>().ok());
        if owner.is_some_and(|o| !o.alive() && reap(run, o).is_ok()) {
            crate::socket::remove(&e.path());
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

pub fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if !ok {
        bail!("bad vm name {name:?}: up to 64 letters, digits, '-', '_' or '.', not starting with '.'");
    }
    Ok(())
}

fn flock(f: &File, how: i32) -> std::io::Result<()> {
    loop {
        if unsafe { libc::flock(f.as_raw_fd(), how) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Opens and locks `path`, making sure the lock is on the file the path
/// names (a holder may unlink it just before we lock).
fn lock_path(path: &Path, how: i32) -> std::io::Result<File> {
    loop {
        let f = File::options().create(true).truncate(false).read(true).write(true).open(path)?;
        flock(&f, how)?;
        match std::fs::metadata(path) {
            Ok(m) if m.ino() == f.metadata()?.ino() => return Ok(f),
            _ => continue,
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
    let rest = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.first() == Some(&"Z") {
        return None;
    }
    fields.get(19)?.parse().ok()
}

/// Armed test faults (`flexvm debug fault`), host-wide, in `RUN/faults.json`:
/// only with FLEXVM_FAULTS=1.
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
        let armed = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        *c = mtime.map(|m| (m, armed));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    c.as_ref().is_some_and(|(_, armed)| armed.get(name).is_some_and(|&until| now < until))
}

/// Test hook: waits 3 s at a step where `name` is armed, for a test to kill
/// the process there.
pub fn stall(name: &str) {
    if fault(name) {
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// Arms `name` for `ms` (0 disarms it).
pub fn arm(host: &Host, name: &str, ms: u64) -> Result<()> {
    let _l = host.lock()?;
    let path = host.run.join("faults.json");
    let mut armed: HashMap<String, u64> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    armed.retain(|_, &mut until| until > now);
    if ms == 0 {
        armed.remove(name);
    } else {
        armed.insert(name.into(), now + ms);
    }
    write_file(&host.run, "faults.json", &serde_json::to_vec(&armed)?, false)?;
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

    /// A process that is gone, its work directory recording `fcs` as its
    /// Firecrackers.
    fn dead_owner(h: &Host, pid: u32, fcs: &[Ident]) -> Ident {
        let dead = Ident { pid, start: 1 };
        let dir = h.run.join("w").join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("owner"), dead.to_string()).unwrap();
        for (i, fc) in fcs.iter().enumerate() {
            std::fs::create_dir_all(dir.join(i.to_string())).unwrap();
            std::fs::write(dir.join(i.to_string()).join("fc"), fc.to_string()).unwrap();
        }
        dead
    }

    fn sleeper() -> (std::process::Child, Ident) {
        let c = std::process::Command::new("sleep").arg("60").spawn().unwrap();
        let id = Ident::of(c.id()).unwrap();
        (c, id)
    }

    #[test]
    fn names_are_locked_for_life() {
        let h = host("names");
        let a = h.take_name("a", false).unwrap();
        assert!(h.take_name("a", false).is_err());
        let me = Ident::me();
        a.publish(&Entry { name: "a".into(), pid: me.pid, start: me.start, ..Entry::default() }).unwrap();
        assert!(h.alive("a"));
        assert_eq!(h.entries().len(), 1);
        // An entry is only believed for the process holding the name.
        a.publish(&Entry { name: "a".into(), pid: me.pid, start: me.start + 1, ..Entry::default() }).unwrap();
        assert!(h.entry("a").is_err() && h.signal("a", 0).is_err());
        drop(a);
        assert!(!h.alive("a") && h.entries().is_empty() && h.entry("a").is_err());
        let _again = h.take_name("a", false).unwrap();
        for bad in ["", ".x", "a/b", &"x".repeat(65)] {
            assert!(h.take_name(bad, false).is_err());
        }
        std::fs::create_dir_all(h.suspended("s")).unwrap();
        assert!(h.take_name("s", false).is_err());
        assert!(h.take_name("s", true).is_ok());
    }

    #[test]
    fn a_dead_holders_firecrackers_die_before_its_name_or_address_is_free() {
        let h = host("reap");
        let (mut fc, id) = sleeper();
        let dead = dead_owner(&h, 999_999_901, &[id]);
        std::fs::write(h.name_lock("d"), dead.to_string()).unwrap();
        let l = h.lock().unwrap();
        h.put_addr("10.9.0.1".parse().unwrap(), &Addr { seen: 1, holder: Some("d".into()), ..Addr::default() }, false).unwrap();
        assert!(id.alive());
        // Its address is free only once its Firecracker has exited.
        let c = h.claim_new(&l, "x", Some("10.9.0.1".parse().unwrap())).unwrap();
        assert!(!id.alive() && c.gen > 1);
        let _ = fc.wait();
        // The same for its name, taken over.
        let (mut fc, id) = sleeper();
        let dead = dead_owner(&h, 999_999_902, &[id]);
        std::fs::write(h.name_lock("e"), dead.to_string()).unwrap();
        let _e = h.take_name("e", false).unwrap();
        assert!(!id.alive());
        let _ = fc.wait();
        // A work directory another process owns now is left alone.
        let (mut fc, id) = sleeper();
        dead_owner(&h, 999_999_903, &[id]);
        reap(&h.run, Ident { pid: 999_999_903, start: 2 }).unwrap();
        assert!(id.alive());
        let _ = fc.kill();
        let _ = fc.wait();
    }

    #[test]
    fn addresses_generations_and_loans() {
        let h = host("addrs");
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let _a = h.take_name("a", false).unwrap();
        let l = h.lock().unwrap();
        let a = h.claim_new(&l, "a", None).unwrap();
        let (a_ip, g1) = (a.ip, a.gen);
        assert_eq!(a_ip, ip("10.9.0.1"));
        // Held by a live VM: the next claim gets another address.
        let b = h.claim_new(&l, "b-dead", None).unwrap();
        let (b_ip, g2) = (b.ip, b.gen);
        assert!(b_ip == ip("10.9.0.2") && g2 > g1);
        b.keep();
        // b-dead is not alive: its address is free again, with a newer generation.
        let c = h.claim_new(&l, "c", Some(b_ip)).unwrap();
        assert!(c.ip == b_ip && c.gen > g2);
        c.keep();
        assert!(h.claim_new(&l, "x", Some(a_ip)).is_err());
        assert!(h.claim_new(&l, "x", Some(ip("10.9.9.9"))).is_err());
        // a leaves: lent until withdrawn with its generation or a newer one.
        h.lend(&l, a_ip, g1).unwrap();
        a.release(&l).unwrap();
        assert!(h.claim_new(&l, "x", Some(a_ip)).is_err());
        assert!(!h.observe(&l, a_ip, g1 - 1, None).unwrap(), "older withdrawal is stale");
        assert!(h.addr(&l, a_ip).unwrap().lent.is_some());
        assert!(h.observe(&l, a_ip, g1, None).unwrap());
        assert!(h.addr(&l, a_ip).unwrap().lent.is_none());
        // An announcement of a withdrawn generation is stale; a newer one is not.
        let via = Some(ip("192.0.2.1"));
        assert!(!h.observe(&l, a_ip, g1, via).unwrap());
        assert!(!h.current(&l, a_ip, g1).unwrap());
        assert!(h.observe(&l, a_ip, g1 + 5, via).unwrap());
        assert_eq!(h.addr(&l, a_ip).unwrap().via, via);
        // An arrival with an old generation is refused, a current one taken in.
        assert!(h.claim_incoming(&l, "y", a_ip, g1).is_err());
        assert!(h.claim_incoming(&l, "y", a_ip, 0).is_err());
        h.claim_incoming(&l, "y", a_ip, g1 + 5).unwrap().keep();
        h.commit_incoming(&l, a_ip, g1 + 5).unwrap();
        // A newer generation than a withdrawn one is current again.
        assert!(h.observe(&l, a_ip, g1 + 5, None).unwrap());
        h.claim_incoming(&l, "y", a_ip, g1 + 6).unwrap().keep();
        assert!(h.current(&l, a_ip, g1 + 6).unwrap());
        // A refused claim of a held address gives nothing back.
        let w = h.take_name("w", false).unwrap();
        let wc = h.claim_new(&l, "w", Some(ip("10.9.0.3"))).unwrap();
        assert!(h.claim_incoming(&l, "w2", wc.ip, wc.gen).is_err());
        assert_eq!(h.holder(&l, wc.ip).unwrap().as_deref(), Some("w"));
        wc.keep();
        drop(w);
        // A record that cannot be read is an error, never a free address.
        std::fs::write(h.addr_path(ip("10.9.0.3")), "{").unwrap();
        assert!(h.addr(&l, ip("10.9.0.3")).is_err());
        assert!(h.claim_new(&l, "z", Some(ip("10.9.0.3"))).is_err());
        // Generations survive a "reboot": a new boot id jumps to the reserved mark.
        std::fs::write(h.state.join("addrs/.gens"), "7 2048 other-boot").unwrap();
        let g = h.claim_new(&l, "z", None).unwrap().gen;
        assert!(g >= 2048);
        std::fs::write(h.state.join("addrs/.gens"), "x").unwrap();
        assert!(h.claim_new(&l, "z", None).is_err());
    }

    #[test]
    fn addresses_are_lent_to_restoring_peers_only_when_free() {
        let h = host("lend");
        let l = h.lock().unwrap();
        let ip = "10.9.0.2".parse().unwrap();
        assert!(h.lend_new(&l, "10.9.9.9".parse().unwrap()).is_err(), "not ours");
        let g = h.lend_new(&l, ip).unwrap();
        assert!(h.lend_new(&l, ip).unwrap_err().to_string().contains("lent"));
        assert!(h.claim_new(&l, "x", Some(ip)).err().unwrap().to_string().contains("lent"));
        // The borrower's withdrawal gives it back, with newer generations after.
        assert!(h.observe(&l, ip, g, None).unwrap());
        let _x = h.take_name("x", false).unwrap();
        let c = h.claim_new(&l, "x", Some(ip)).unwrap();
        assert!(c.gen > g && c.fresh);
        assert!(h.lend_new(&l, ip).unwrap_err().to_string().contains("in use"));
    }

    #[test]
    fn dropped_address_claims_give_back_only_their_own() {
        let h = host("claims");
        let _w = h.take_name("w", false).unwrap();
        let _v = h.take_name("v", false).unwrap();
        let ip = {
            let l = h.lock().unwrap();
            let c = h.claim_new(&l, "w", None).unwrap();
            let ip = c.ip;
            c.keep();
            ip
        };
        // Another VM's claim, dropped: nothing of w's changes.
        let v = {
            let l = h.lock().unwrap();
            h.claim_new(&l, "v", None).unwrap()
        };
        drop(v);
        let l = h.lock().unwrap();
        assert_eq!(h.holder(&l, ip).unwrap().as_deref(), Some("w"));
    }

    #[test]
    fn migrations_are_fenced() {
        let h = host("migs");
        let rec = |id: u64| h.mig_read(id).unwrap();
        // Unknown: aborted, and nothing is recorded.
        assert_eq!(h.mig_status(1).unwrap(), "aborted");
        assert!(rec(1).is_none());
        // Given up before committing: aborted.
        let r = h.mig_begin(2).unwrap();
        assert!(h.mig_begin(2).is_err());
        assert_eq!(h.mig_status(2).unwrap(), "pending");
        drop(r);
        assert_eq!(h.mig_status(2).unwrap(), "aborted");
        // Committed, released, forgotten once its source is done with it.
        let mut r = h.mig_begin(3).unwrap();
        r.commit(&h.lock().unwrap()).unwrap();
        assert_eq!(h.mig_status(3).unwrap(), "committed");
        h.mig_done(3).unwrap();
        assert_eq!(h.mig_status(3).unwrap(), "committed", "only a released one is forgotten");
        r.release();
        assert_eq!(h.mig_status(3).unwrap(), "released");
        h.mig_done(3).unwrap();
        assert!(rec(3).is_none());
        // Fenced off by a query that found its owner dead: no commit.
        let mut r = h.mig_begin(4).unwrap();
        let dead = Owner { id: dead_owner(&h, 999_999_904, &[]), boot: boot_id() };
        h.mig_write(4, &Mig::Pending { owner: dead.clone() }).unwrap();
        assert_eq!(h.mig_status(4).unwrap(), "aborted");
        assert!(rec(4).is_none() && r.commit(&h.lock().unwrap()).is_err());
        // Committed by a process that is gone: released once its Firecracker is.
        let (mut fc, id) = sleeper();
        let dead = Owner { id: dead_owner(&h, 999_999_905, &[id]), boot: boot_id() };
        h.mig_write(5, &Mig::Committed { owner: dead }).unwrap();
        assert_eq!(h.mig_status(5).unwrap(), "released");
        assert!(!id.alive());
        let _ = fc.wait();
        // A record that cannot be read answers nothing.
        std::fs::write(h.state.join("migs/6"), "{").unwrap();
        assert!(h.mig_status(6).is_err() && h.mig_read(6).is_err());
    }

    #[test]
    fn admission_counts_recent_grants() {
        let mut h = host("admit");
        let free = crate::vmproc::host_available_mib();
        // Wide margins: other processes move MemAvailable meanwhile.
        h.cfg.reserve_mib = free.saturating_sub(3000);
        assert!(h.admit(1000));
        assert!(h.admit(1000));
        assert!(!h.admit(2000), "recent grants count as used");
        h.cfg.reserve_mib = free + 1;
        assert!(!h.admit(1));
    }
}
