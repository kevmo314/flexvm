//! Host-wide state, shared by the VM processes and the peer listener through
//! files: the host's configuration, the VM registry, address generations and
//! loans, incoming migration records and armed test faults.
//!
//! Short critical sections take the host lock (`STATE/lock`); nothing slow
//! (network, Firecracker) happens under it. A VM process holds an exclusive
//! lock on `RUN/vms/NAME.lock` for as long as it lives: that lock is its
//! claim on the name and the proof that its registry entry is current.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
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

pub struct Host {
    pub state: PathBuf,
    pub run: PathBuf,
    pub cfg: Config,
}

static RUN_DIR: OnceLock<PathBuf> = OnceLock::new();

impl Host {
    /// The host whose durable state is in `state` and runtime state in `run`.
    pub fn open(state: &Path, run: &Path) -> Result<Host> {
        for d in [state.join("addrs"), state.join("suspended"), state.join("standby")] {
            crate::util::create_dir_durably(&d)?;
        }
        for d in ["vms", "migs", "standby", "w"] {
            std::fs::create_dir_all(run.join(d)).map_err(|e| format!("{}: {e}", run.join(d).display()))?;
        }
        let (state, run) = (state.canonicalize()?, run.canonicalize()?);
        let cfg = match std::fs::read(state.join("host.json")) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}/host.json: {e}", state.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => bail!("{}/host.json: {e}", state.display()),
        };
        let _ = RUN_DIR.set(run.clone());
        Ok(Host { state, run, cfg })
    }

    pub fn save_config(&self) -> Result<()> {
        write_file(&self.state, "host.json", &serde_json::to_vec_pretty(&self.cfg)?, true)?;
        Ok(())
    }

    /// Takes the host lock until the guard is dropped.
    pub fn lock(&self) -> Result<Locked> {
        let f = File::options().create(true).truncate(false).write(true).open(self.state.join("lock"))?;
        flock(&f, libc::LOCK_EX)?;
        Ok(Locked(f))
    }

    /// A VM's control socket.
    pub fn sock(&self, name: &str) -> PathBuf {
        self.run.join("vms").join(format!("{name}.sock"))
    }

    /// Where a suspended VM's checkpoint lives.
    pub fn suspended(&self, name: &str) -> PathBuf {
        self.state.join("suspended").join(name)
    }

    /// Takes `name` for this process, for as long as the returned lock lives.
    /// Refused if a live process has it, or a suspended VM (unless
    /// `resuming` it).
    pub fn take_name(&self, name: &str, resuming: bool) -> Result<NameLock> {
        check_name(name)?;
        if !resuming && self.suspended(name).exists() {
            bail!("vm {name:?} exists (suspended); resume or kill it");
        }
        let path = self.run.join("vms").join(format!("{name}.lock"));
        let f = lock_path(&path, libc::LOCK_EX | libc::LOCK_NB).map_err(|_| format!("vm name {name:?} is taken"))?;
        let dir = self.run.join("vms");
        // Leftovers of a process that died with the name.
        for ext in ["json", "sock"] {
            let _ = std::fs::remove_file(dir.join(format!("{name}.{ext}")));
        }
        Ok(NameLock { name: name.into(), dir, _file: f })
    }

    /// Whether a live process holds `name`.
    pub fn alive(&self, name: &str) -> bool {
        let path = self.run.join("vms").join(format!("{name}.lock"));
        match File::open(&path) {
            Ok(f) => flock(&f, libc::LOCK_SH | libc::LOCK_NB).is_err(),
            Err(_) => false,
        }
    }

    /// The registry entries of live VMs; stale ones are removed.
    pub fn entries(&self) -> Vec<Entry> {
        let dir = self.run.join("vms");
        let mut out = Vec::new();
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let file = e.file_name().to_string_lossy().into_owned();
            let Some(name) = file.strip_suffix(".json") else { continue };
            if !self.alive(name) {
                // Removed by whoever takes the name next, or here if we can lock it.
                if let Ok(_l) = lock_path(&dir.join(format!("{name}.lock")), libc::LOCK_EX | libc::LOCK_NB) {
                    for ext in ["json", "sock", "lock"] {
                        let _ = std::fs::remove_file(dir.join(format!("{name}.{ext}")));
                    }
                }
                continue;
            }
            if let Some(entry) = std::fs::read(e.path()).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
                out.push(entry);
            }
        }
        out.sort_by(|a: &Entry, b| a.name.cmp(&b.name));
        out
    }

    /// The registry entry of live VM `name`.
    pub fn entry(&self, name: &str) -> Result<Entry> {
        let path = self.run.join("vms").join(format!("{name}.json"));
        let entry = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok());
        match entry {
            Some(e) if self.alive(name) => Ok(e),
            _ => bail!("no vm named {name:?}"),
        }
    }

    // Addresses and generations. Every function here wants the host lock.

    fn addr_path(&self, ip: Ipv4Addr) -> PathBuf {
        self.state.join("addrs").join(ip.to_string())
    }

    pub fn addr(&self, _: &Locked, ip: Ipv4Addr) -> Addr {
        std::fs::read(self.addr_path(ip)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn put_addr(&self, ip: Ipv4Addr, a: &Addr, durable: bool) -> Result<()> {
        write_file(&self.state.join("addrs"), &ip.to_string(), &serde_json::to_vec(a)?, durable)
            .map_err(|e| format!("cannot record address {ip}: {e}"))?;
        Ok(())
    }

    /// Whether `ip`'s holder is a VM here: alive, or suspended.
    fn held(&self, a: &Addr) -> bool {
        a.holder.as_deref().is_some_and(|h| self.alive(h) || self.suspended(h).exists())
    }

    /// Hands an address of this host's range to new VM `holder`, with a new
    /// generation: `want`, or the first free one.
    pub fn claim_new(&self, l: &Locked, holder: &str, want: Option<Ipv4Addr>) -> Result<(Ipv4Addr, u64)> {
        let range = self.cfg.range()?;
        let taken = |ip| {
            let a = self.addr(l, ip);
            a.lent.is_some() || self.held(&a)
        };
        let ip = match want {
            Some(ip) if !range.contains(ip) => {
                bail!("{ip} is not in this host's range {range}: start the vm on its home host, or let it pick an address")
            }
            Some(ip) if taken(ip) => bail!("{ip} is in use"),
            Some(ip) => ip,
            None => range.allocate(taken).ok_or("no free addresses left")?,
        };
        let mut a = self.addr(l, ip);
        let gen = self.next_gen(a.seen)?;
        a.seen = gen;
        a.withdrawn = false;
        a.holder = Some(holder.into());
        // The high-water mark orders generations; this record need not be durable.
        self.put_addr(ip, &a, false)?;
        Ok((ip, gen))
    }

    /// A generation newer than `seen` and than any handed out here before,
    /// across crashes: a high-water mark reserved `GEN_BLOCK` at a time, and
    /// after a reboot (the boot id changed) taken up from the reserved one.
    fn next_gen(&self, seen: u64) -> Result<u64> {
        const GEN_BLOCK: u64 = 1024;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default().trim().to_string();
        let dir = self.state.join("addrs");
        let text = std::fs::read_to_string(dir.join(".gens")).unwrap_or_default();
        let mut f = text.split_whitespace();
        let (next, reserved): (u64, u64) = (f.next().and_then(|s| s.parse().ok()).unwrap_or(1), f.next().and_then(|s| s.parse().ok()).unwrap_or(0));
        let next = if f.next() == Some(&boot) { next } else { next.max(reserved) };
        let gen = next.max(seen + 1);
        let (reserved, durable) = if gen >= reserved { (gen + GEN_BLOCK, true) } else { (reserved, false) };
        write_file(&dir, ".gens", format!("{} {reserved} {boot}", gen + 1).as_bytes(), durable)
            .map_err(|e| format!("cannot record address generations: {e}"))?;
        Ok(gen)
    }

    /// Takes in `ip` for a VM arriving with generation `gen`. Refused if a VM
    /// here holds it, if that generation was superseded or withdrawn, or if
    /// it is lent out with a newer one.
    pub fn claim_incoming(&self, l: &Locked, holder: &str, ip: Ipv4Addr, gen: u64) -> Result<()> {
        let mut a = self.addr(l, ip);
        if self.held(&a) && a.holder.as_deref() != Some(holder) {
            bail!("{ip} is in use here");
        }
        if !a.current(gen) {
            bail!("{ip} has a newer generation than this vm's ({gen}): it was given out again");
        }
        if let Some(lent) = a.lent.filter(|&lent| gen < lent) {
            bail!("{ip} is lent out with a newer vm (generation {lent}, not {gen})");
        }
        a.seen = a.seen.max(gen);
        a.holder = Some(holder.into());
        self.put_addr(ip, &a, true)
    }

    /// An arrival commits: its generation must still be current. Takes back
    /// a loan of it (the VM came home).
    pub fn commit_incoming(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<()> {
        let mut a = self.addr(l, ip);
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
        let mut a = self.addr(l, ip);
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
        let mut a = self.addr(l, ip);
        a.lent = Some(gen);
        self.put_addr(ip, &a, true)
    }

    /// Takes back a loan of generation `gen` (the migration aborted).
    pub fn unlend(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<()> {
        let mut a = self.addr(l, ip);
        if a.lent == Some(gen) {
            a.lent = None;
            self.put_addr(ip, &a, true)?;
        }
        Ok(())
    }

    /// Takes in a message about generation `gen` of `ip`: an announcement, or
    /// a withdrawal. Returns false if it is stale (an older generation, or an
    /// announcement of a withdrawn one). A withdrawal frees a loan of its
    /// generation or an older one.
    pub fn observe(&self, l: &Locked, ip: Ipv4Addr, gen: u64, withdrawn: bool) -> Result<bool> {
        let mut a = self.addr(l, ip);
        let fresh = gen > a.seen || (gen == a.seen && (withdrawn || !a.withdrawn));
        if !fresh {
            return Ok(false);
        }
        let changed = (gen, withdrawn) != (a.seen, a.withdrawn) || (withdrawn && a.lent.is_some_and(|lent| lent <= gen));
        a.seen = gen;
        a.withdrawn = withdrawn;
        if withdrawn && a.lent.is_some_and(|lent| lent <= gen) {
            a.lent = None;
        }
        if changed {
            self.put_addr(ip, &a, true)?;
        }
        Ok(true)
    }

    /// Whether generation `gen` of `ip` may still be live here.
    pub fn current(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> bool {
        self.addr(l, ip).current(gen)
    }

    /// The VM here holding `ip`, if any.
    pub fn holder(&self, l: &Locked, ip: Ipv4Addr) -> Option<String> {
        let a = self.addr(l, ip);
        self.held(&a).then_some(a.holder).flatten()
    }

    // Incoming migrations: `RUN/migs/ID`, each under its own flock.

    fn mig(&self, id: u64) -> Result<(File, PathBuf)> {
        let path = self.run.join("migs").join(id.to_string());
        let f = File::options().create(true).truncate(false).read(true).write(true).open(&path)?;
        flock(&f, libc::LOCK_EX)?;
        Ok((f, path))
    }

    /// Records migration `id` as pending here, for this process. An id is
    /// taken in only once.
    pub fn mig_begin(&self, id: u64) -> Result<()> {
        let (f, path) = self.mig(id)?;
        if f.metadata()?.len() > 0 {
            bail!("migration {id} was already seen here");
        }
        write_at(&f, &path, &format!("pending {}", me()))
    }

    /// Moves migration `id` from pending to `to` (committed, released or
    /// aborted), unless it was fenced off meanwhile.
    pub fn mig_set(&self, id: u64, to: &str) -> Result<()> {
        let (f, path) = self.mig(id)?;
        let now = std::fs::read_to_string(&path)?;
        let state = now.split_whitespace().next().unwrap_or("");
        match (state, to) {
            ("pending", _) | ("committed", "released") => write_at(&f, &path, &format!("{to} {}", me())),
            (s, t) if s == t => Ok(()),
            (s, _) => bail!("migration {id} is {s} here"),
        }
    }

    /// How migration `id` went here, for its source: `pending`, `committed`,
    /// `released` (the VM has all its pages, or is gone) or `aborted`. One
    /// that is unknown, or pending with its process gone, is recorded as
    /// aborted first, so it can never commit.
    pub fn mig_status(&self, id: u64) -> Result<String> {
        let (f, path) = self.mig(id)?;
        let now = std::fs::read_to_string(&path)?;
        let mut w = now.split_whitespace();
        let (state, pid, start) = (w.next().unwrap_or(""), w.next().unwrap_or(""), w.next().unwrap_or(""));
        let live = || pid.parse().ok().and_then(starttime).is_some_and(|s| s.to_string() == start);
        let out = match state {
            "pending" | "" if state.is_empty() || !live() => {
                write_at(&f, &path, "aborted")?;
                "aborted"
            }
            "committed" if !live() => "released",
            s => s,
        };
        Ok(out.into())
    }
}

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
    /// The VM here using it (alive or suspended), if any.
    pub holder: Option<String>,
}

impl Addr {
    /// Whether generation `gen` may still be live: none newer, not withdrawn.
    pub fn current(&self, gen: u64) -> bool {
        gen > self.seen || (gen == self.seen && !self.withdrawn)
    }
}

/// The host lock, held until dropped.
pub struct Locked(File);

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
    pub ip: Option<Ipv4Addr>,
    pub gen: u64,
    pub template: String,
    pub template_id: String,
    pub vcpus: u32,
    pub max_mib: u64,
    /// running, paused, checkpointing, source, starting, arriving, failed
    pub state: String,
    pub firecracker: Option<u32>,
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
        let f = File::options().create(true).truncate(false).write(true).open(path)?;
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

fn write_at(f: &File, path: &Path, text: &str) -> Result<()> {
    f.set_len(0)?;
    std::fs::write(path, text)?;
    Ok(())
}

/// This process, as `<pid> <start time>`: a pid with its start time names
/// one process even once the pid is reused.
fn me() -> String {
    let pid = std::process::id();
    format!("{pid} {}", starttime(pid).unwrap_or(0))
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

    #[test]
    fn names_are_locked_for_life() {
        let h = host("names");
        let a = h.take_name("a", false).unwrap();
        assert!(h.take_name("a", false).is_err());
        a.publish(&Entry { name: "a".into(), pid: 1, ..Entry::default() }).unwrap();
        assert!(h.alive("a"));
        assert_eq!(h.entries().len(), 1);
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
    fn addresses_generations_and_loans() {
        let h = host("addrs");
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let _a = h.take_name("a", false).unwrap();
        let l = h.lock().unwrap();
        let (a_ip, g1) = h.claim_new(&l, "a", None).unwrap();
        assert_eq!(a_ip, ip("10.9.0.1"));
        // Held by a live VM: the next claim gets another address.
        let (b_ip, g2) = h.claim_new(&l, "b-dead", None).unwrap();
        assert!(b_ip == ip("10.9.0.2") && g2 > g1);
        // b-dead is not alive: its address is free again, with a newer generation.
        let (again, g3) = h.claim_new(&l, "c", Some(b_ip)).unwrap();
        assert!(again == b_ip && g3 > g2);
        assert!(h.claim_new(&l, "x", Some(a_ip)).is_err());
        assert!(h.claim_new(&l, "x", Some(ip("10.9.9.9"))).is_err());
        // a leaves: lent until withdrawn with its generation or a newer one.
        h.lend(&l, a_ip, g1).unwrap();
        h.release(&l, a_ip, "a").unwrap();
        assert!(h.claim_new(&l, "x", Some(a_ip)).is_err());
        assert!(!h.observe(&l, a_ip, g1 - 1, true).unwrap(), "older withdrawal is stale");
        assert!(h.addr(&l, a_ip).lent.is_some());
        assert!(h.observe(&l, a_ip, g1, true).unwrap());
        assert!(h.addr(&l, a_ip).lent.is_none());
        // An announcement of a withdrawn generation is stale; a newer one is not.
        assert!(!h.observe(&l, a_ip, g1, false).unwrap());
        assert!(!h.current(&l, a_ip, g1));
        assert!(h.observe(&l, a_ip, g1 + 5, false).unwrap());
        // An arrival with an old generation is refused, a current one taken in.
        assert!(h.claim_incoming(&l, "y", a_ip, g1).is_err());
        h.claim_incoming(&l, "y", a_ip, g1 + 5).unwrap();
        h.commit_incoming(&l, a_ip, g1 + 5).unwrap();
        // Generations survive a "reboot": a new boot id jumps to the reserved mark.
        std::fs::write(h.state.join("addrs/.gens"), "7 2048 other-boot").unwrap();
        let (_, g) = h.claim_new(&l, "z", None).unwrap();
        assert!(g >= 2048);
    }

    #[test]
    fn migrations_are_fenced() {
        let h = host("migs");
        // Unknown: aborted, and stays so.
        assert_eq!(h.mig_status(1).unwrap(), "aborted");
        assert!(h.mig_begin(1).is_err());
        h.mig_begin(2).unwrap();
        assert!(h.mig_begin(2).is_err());
        assert_eq!(h.mig_status(2).unwrap(), "pending");
        h.mig_set(2, "committed").unwrap();
        assert_eq!(h.mig_status(2).unwrap(), "committed");
        h.mig_set(2, "released").unwrap();
        assert_eq!(h.mig_status(2).unwrap(), "released");
        // Pending with its process gone: fenced off.
        std::fs::write(h.run.join("migs/3"), "pending 999999999 1").unwrap();
        assert_eq!(h.mig_status(3).unwrap(), "aborted");
        assert!(h.mig_set(3, "committed").is_err());
        // Committed by a process that is gone: its VM is gone too.
        std::fs::write(h.run.join("migs/4"), "committed 999999999 1").unwrap();
        assert_eq!(h.mig_status(4).unwrap(), "released");
    }
}
