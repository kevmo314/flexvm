//! Host-wide state in files, shared by VM processes and the listener.
//! Acquisitions (names, addresses, migration records) are guards that give
//! back exactly what they took. The host lock (`STATE/.locks/host`) covers only short
//! sections. A VM process holds `RUN/vms/NAME.lock` for life; a dead one
//! counts as gone only once its Firecrackers have exited (`reap`).

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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

impl Hold {
    /// Renamed to count `mib`, under the host lock.
    fn resize(&mut self, mib: u64) -> std::io::Result<()> {
        let path = self.path.with_file_name(format!("{}-{mib}", self.id));
        std::fs::rename(&self.path, &path)?;
        (self.path, self.mib) = (path, mib);
        Ok(())
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// What a grant must leave available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Floor {
    Reserve,
    /// The eviction mark (`Config::evict_at`): an arrival moved here by eviction.
    EvictMark,
}

/// `STATE/host.json`, edited by hand (README: Configuration) and read again live
/// (`config_now`); `flexvm listen` saves its address. What is left unset is derived
/// where it is used, never saved. A field it does not know is refused, not ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The owning host's RUN directory; runtime context, never saved in host.json.
    #[serde(skip)]
    pub run: Option<PathBuf>,
    pub listen: Option<String>,
    pub peers: Vec<String>,
    /// A peer's data-plane addresses besides those it is reached by (`peer_underlays`): next hops
    /// it may report for its VMs, as its own `underlay` on another network. Only a configured peer's count.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub peer_underlays: std::collections::BTreeMap<String, Vec<Ipv4Addr>>,
    /// Disjoint across hosts.
    pub vm_ips: String,
    /// Every host's VM addresses. None: only this host's `vm_ips`.
    pub cluster_ips: Option<String>,
    /// None: derived (`underlay`).
    pub underlay: Option<Ipv4Addr>,
    /// None: derived (`announce_dev`); `none`: no announcements.
    pub announce_dev: Option<String>,
    pub dns: Option<String>,
    /// None: `default_reserve`.
    pub reserve_mib: Option<u64>,
    /// Eviction's high-water mark (MiB available): below it VMs start moving
    /// to peers (`evict_at`). None: the reserve plus the reserve or 512 MiB, whichever is more.
    pub evict_mib: Option<u64>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            run: None,
            listen: None,
            peers: Vec::new(),
            peer_underlays: Default::default(),
            vm_ips: "10.200.0.0/16".into(),
            cluster_ips: None,
            underlay: None,
            announce_dev: None,
            dns: None,
            reserve_mib: None,
            evict_mib: None,
        }
    }
}

/// The reserve of a host that sets none: a sixteenth of its RAM, from 256 MiB to 4 GiB.
pub fn default_reserve() -> u64 {
    reserve_for(crate::util::proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0) >> 20)
}

fn reserve_for(total_mib: u64) -> u64 {
    (total_mib / 16).clamp(256, 4096)
}

/// The underlay address and announce device derived toward the peers.
type Derived = (Option<Ipv4Addr>, Option<String>);

/// Which peer the underlay and announce device are derived toward.
#[derive(Debug, PartialEq)]
pub enum Toward {
    /// Every peer is on this machine (loopback, or one of its addresses), or there is none.
    Local,
    /// The first peer elsewhere with an IPv4 address.
    Remote(Ipv4Addr),
    /// Peers elsewhere, none with an IPv4 address (or a name that did not resolve).
    Unknown,
}

/// `peers`: each peer's addresses, none for a name that did not resolve.
pub fn toward(peers: &[Vec<IpAddr>], local: impl Fn(Ipv4Addr) -> bool) -> Toward {
    let mut out = Toward::Local;
    for addrs in peers {
        let v4: Vec<Ipv4Addr> = addrs.iter().filter_map(|a| if let IpAddr::V4(v) = a.to_canonical() { Some(v) } else { None }).collect();
        if addrs.iter().any(|a| a.to_canonical().is_loopback()) || v4.iter().any(|&a| local(a)) {
            continue;
        }
        match v4.first() {
            Some(&a) => return Toward::Remote(a),
            None => out = Toward::Unknown,
        }
    }
    out
}

/// A peer name's lookup by a process other than the listener, for one the listener has not seen.
const PEER_WAIT: Duration = Duration::from_secs(2);

/// A peer name's lookup, and what this process's lookups found (none for one that failed).
type Lookup<'a> = &'a dyn Fn(&str) -> std::io::Result<Vec<IpAddr>>;
type LookedUp = Mutex<Option<HashMap<String, Vec<IpAddr>>>>;

/// What a derivation found, and the peers whose addresses were unknown.
type Outcome = (std::result::Result<Derived, String>, Vec<String>);

/// The underlay address and announce device toward `peers`, and the peers that did not
/// resolve: `lookup` gives a peer's addresses, `route` the device, source and whether the
/// device is Ethernet (one that is not, a WireGuard or tun link, takes no ARP announcements).
fn derive(
    peers: &[String],
    lookup: impl Fn(&str) -> std::io::Result<Vec<IpAddr>>,
    local: impl Fn(Ipv4Addr) -> bool,
    route: impl Fn(Ipv4Addr) -> Result<(String, Ipv4Addr, bool)>,
) -> Outcome {
    let mut unresolved = Vec::new();
    let addrs: Vec<Vec<IpAddr>> = peers.iter().map(|p| lookup(p).unwrap_or_else(|e| (unresolved.push(format!("peer {p}: {e}")), Vec::new()).1)).collect();
    let out = match toward(&addrs, local) {
        Toward::Local => Ok((Some(Ipv4Addr::LOCALHOST), None)),
        Toward::Remote(to) => route(to).map(|(dev, src, ether)| (Some(src), ether.then_some(dev))).map_err(|e| e.to_string()),
        Toward::Unknown => Err("no peer elsewhere has a known IPv4 address".into()),
    };
    (out, unresolved)
}

impl Config {
    pub fn reserve(&self) -> u64 {
        self.reserve_mib.unwrap_or_else(default_reserve)
    }

    /// MemAvailable (MiB) under which eviction starts: never below the reserve.
    pub fn evict_at(&self) -> u64 {
        self.evict_marks().1
    }

    /// The reserve, the eviction mark and, once started, how high MemAvailable must be back
    /// for eviction to stop: the mark plus half its height above the reserve (at least
    /// 128 MiB). From one read of the reserve, which may follow MemTotal.
    pub fn evict_marks(&self) -> (u64, u64, u64) {
        let reserve = self.reserve();
        let at = self.evict_mib.unwrap_or(reserve.saturating_add(reserve.max(512))).max(reserve);
        (reserve, at, at.saturating_add(((at - reserve) / 2).max(128)))
    }

    pub fn range(&self) -> Result<IpRange> {
        IpRange::parse(&self.vm_ips)
    }

    /// The only addresses a peer's VM may have here (#584): `cluster_ips`, else this host's `vm_ips`.
    pub fn cluster(&self) -> Result<IpRange> {
        IpRange::parse(self.effective_cluster_ips())
    }

    /// What a hand edit must get right: refused on open, and never taken live (`config_now`).
    /// Content only: checks of current interfaces belong in `warnings`.
    pub fn validate(&self) -> Result<()> {
        if !self.cluster()?.contains_range(&self.range()?) {
            bail!("vm_ips {} is not inside cluster_ips {}", self.vm_ips, self.effective_cluster_ips());
        }
        if let Some(p) = self.peers.iter().find(|p| !is_endpoint(p)) {
            bail!("bad peer {p:?}: give HOST:PORT, a peer's flexvm listen address");
        }
        // A peer's underlays count only while it is a peer (`underlays_of`): a dropped peer's are ignored.
        for (peer, ips) in &self.peer_underlays {
            if let Some(ip) = ips.iter().find(|i| i.is_unspecified() || i.is_broadcast() || i.is_multicast() || i.is_loopback()) {
                bail!("peer_underlays {peer}: {ip} is loopback or not unicast");
            }
        }
        if let Some(d) = self.dns.as_deref().filter(|d| d.parse::<Ipv4Addr>().is_err()) {
            bail!("bad dns {d:?}: give an IPv4 address");
        }
        if self.announce_dev.as_deref() == Some("") {
            bail!("announce_dev is empty: name an interface, or \"none\"");
        }
        Ok(())
    }

    /// What `flexvm info` and the listener warn of: valid, but likely a mistake.
    pub fn warnings(&self) -> Vec<String> {
        self.warnings_by(crate::net::is_local_addr)
    }

    fn warnings_by(&self, local: impl Fn(Ipv4Addr) -> Result<bool>) -> Vec<String> {
        let mut w: Vec<String> = self.cluster_warning().into_iter().collect();
        if !self.peers.is_empty() && self.vm_ips == Config::default().vm_ips {
            w.push(format!("flexvm: warning: vm_ips is the default {}; each peer needs a range of its own", self.vm_ips));
        }
        if let Some(e) = self.evict_mib.filter(|&e| e < self.reserve()) {
            w.push(format!("flexvm: the eviction mark {e} MiB is under the {} MiB reserve: eviction starts at the reserve", self.reserve()));
        }
        // Valid (a host.json copied from a larger host), but every start would be refused.
        let total = crate::util::proc_kb("/proc/meminfo", "MemTotal").map_or(u64::MAX, |b| b >> 20);
        if let Some(r) = self.reserve_mib.filter(|&r| r > total) {
            w.push(format!("flexvm: warning: reserve_mib {r} is more than this host's {total} MiB of RAM: every start is refused"));
        }
        if let Some(p) = self.peer_underlays.keys().find(|p| !self.peers.contains(p)) {
            w.push(format!("flexvm: warning: peer_underlays names {p}, which is not a peer: ignored"));
        }
        // Interfaces can change after a config was saved: warn without blocking commands or reloads.
        for (peer, ips) in &self.peer_underlays {
            for &ip in ips {
                match local(ip) {
                    Ok(true) => w.push(format!("flexvm: warning: peer_underlays {peer}: {ip} is local")),
                    Err(e) => w.push(format!("flexvm: warning: peer_underlays {peer}: cannot check whether {ip} is local: {e}")),
                    Ok(false) => {}
                }
            }
        }
        w
    }

    /// `peer`'s configured underlays (`peer_underlays`), none unless it is a configured peer.
    pub fn underlays_of(&self, peer: &str) -> &[Ipv4Addr] {
        match self.peers.iter().any(|p| p == peer) {
            true => self.peer_underlays.get(peer).map_or(&[], Vec::as_slice),
            false => &[],
        }
    }

    /// Every configured peer's configured underlays.
    pub fn peer_underlay_addrs(&self) -> Vec<IpAddr> {
        self.peers.iter().flat_map(|p| self.underlays_of(p)).map(|&u| IpAddr::V4(u)).collect()
    }

    pub fn effective_cluster_ips(&self) -> &str {
        self.cluster_ips.as_deref().unwrap_or(&self.vm_ips)
    }

    pub fn cluster_warning(&self) -> Option<String> {
        (!self.peers.is_empty() && self.cluster_ips.is_none())
            .then(|| format!("flexvm: warning: cluster_ips is unset; peer VM addresses outside vm_ips {} are refused", self.vm_ips))
    }

    /// Never a wildcard address. Unset: the listen address, else the source
    /// address of the kernel's route toward the first peer elsewhere, or
    /// loopback when every peer is on this machine; never loopback with peers elsewhere.
    pub fn underlay(&self) -> Option<Ipv4Addr> {
        self.underlay_by(true)
    }

    /// `underlay` starting no lookup (see `derived`): for callers under the host lock or on a
    /// migration's downtime.
    pub fn underlay_known(&self) -> Option<Ipv4Addr> {
        self.underlay_by(false)
    }

    fn underlay_by(&self, look: bool) -> Option<Ipv4Addr> {
        let from_listen = || match self.listen.as_deref()?.parse::<SocketAddr>().ok()?.ip().to_canonical() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        };
        let listen = self.underlay.or_else(from_listen).filter(|u| !u.is_unspecified());
        listen.or_else(|| self.derived(look).0)
    }

    /// Unset: that route's device, none for peers on this machine; `none`: no announcements.
    pub fn announce_dev(&self) -> Option<String> {
        match self.announce_dev.as_deref() {
            Some("none") => None,
            Some(dev) => Some(dev.into()),
            None => self.derived(true).1,
        }
    }

    /// Derive from the listener's last-known peer addresses, whatever their age; IP literals
    /// need none. A name the listener has seen (an empty entry for one it could not look up
    /// included) is never looked up here; one it has no entry for (no listener has run since
    /// a boot) is, with `look`, within `PEER_WAIT` and once per process, so a VM started first
    /// still announces: its result (none, if it failed) stands until the listener's entry does.
    fn derived(&self, look: bool) -> Derived {
        static LOOKED_UP: LookedUp = Mutex::new(None);
        let by = std::time::Instant::now() + PEER_WAIT;
        let lookup = |p: &str| crate::util::resolve(p, by).map(|a| a.iter().map(SocketAddr::ip).collect());
        let (out, why) = self.derived_by(&LOOKED_UP, look.then_some(&lookup as Lookup));
        static FAILED: Mutex<Option<String>> = Mutex::new(None);
        let mut failed = FAILED.lock().unwrap();
        if let Some(why) = &why {
            if failed.as_ref() != Some(why) {
                crate::log!("flexvm: {why}");
            }
        }
        *failed = why;
        out
    }

    /// What `derived` finds, `lookup` (if any) looking up a name neither the listener nor
    /// `looked_up` has an entry for, and why nothing was derived. The memo is never held
    /// across a lookup: a caller without `lookup` never waits on one.
    fn derived_by(&self, looked_up: &LookedUp, lookup: Option<Lookup>) -> (Derived, Option<String>) {
        let cache = self.run.as_ref().map(|run| crate::listen::Cached::read(run, &self.peers)).unwrap_or_default();
        let unseen: Vec<&str> = self.peers.iter().map(String::as_str).filter(|p| cache.addrs(p).is_err()).collect();
        let find = |p: &str| {
            cache.addrs(p).or_else(|e| {
                if let Some(a) = looked_up.lock().unwrap().get_or_insert_default().get(p) {
                    return Ok(a.clone());
                }
                let Some(lookup) = lookup else { return Err(e) };
                let found = lookup(p);
                looked_up.lock().unwrap().get_or_insert_default().insert(p.into(), found.as_ref().map_or_else(|_| Vec::new(), Clone::clone));
                found
            })
        };
        let route = |to| crate::net::route_get(to).map(|(dev, src)| (dev.clone(), src, crate::net::is_ethernet(&dev)));
        let (out, unresolved) = derive(&self.peers, find, |a| crate::net::is_local_addr(a).unwrap_or(false), route);
        match out {
            Ok(d) => (d, None),
            Err(e) if unseen.is_empty() => {
                (Derived::default(), Some(format!("{e}: no underlay address or announce device derived (set underlay and announce_dev in host.json)")))
            }
            Err(e) => {
                let why = match unresolved.is_empty() {
                    true => String::new(),
                    false => format!(" ({})", unresolved.join("; ")),
                };
                let unseen = unseen.join(", ");
                (
                    Derived::default(),
                    Some(format!(
                        "{e}{why}: no underlay address or announce device derived; this host's listener has not looked up {unseen} yet: start flexvm listen (or set underlay and announce_dev in host.json)"
                    )),
                )
            }
        }
    }

    /// Where peers reach this host's listener (a migration target pulls
    /// pages from it): the listen address, or for a wildcard one (0.0.0.0,
    /// ::, ::ffff:0.0.0.0) or an IPv6 link-local one (its scope id means
    /// nothing elsewhere) the underlay address with the listen port. None
    /// without a listener.
    pub fn advertise(&self) -> Result<Option<String>> {
        self.advertise_by(true)
    }

    /// `advertise`, with `look` false starting no lookup (`underlay_known`).
    pub fn advertise_by(&self, look: bool) -> Result<Option<String>> {
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
        match self.underlay_by(look) {
            Some(u) => Ok(Some(SocketAddr::from((u, addr.port())).to_string())),
            None => bail!(
                "listening on {listen} needs an underlay address (none derived toward the peers: set underlay in host.json): peers cannot reach a wildcard or link-local address"
            ),
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

/// Never through a link, and only a regular file no other user may write: records name processes to signal.
pub fn open_record(path: &Path) -> std::io::Result<File> {
    let f = File::options().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || !guarded(m.uid(), m.mode(), false) {
        crate::log!("{}: refused: not a regular file owned by root or this user, writable by no one else", path.display());
        return Err(untrusted(path, "not a regular file owned by root or this user, writable by no one else"));
    }
    Ok(f)
}

fn read_record(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut f = open_record(path)?;
    let mut b = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut b)?;
    Ok(b)
}

/// Unreadable or corrupt is an error, never None.
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match read_record(path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => bail!("{}: {e}", path.display()),
    }
}

/// Who a name lock says holds it: None for an empty lock (created, never
/// written: no VM started under it); unreadable or corrupt is an error.
fn lock_holder(path: &Path) -> Result<Option<Ident>> {
    match read_record(path) {
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

fn unwritable(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem)
}

/// Whether a directory's recorded binding exists and agrees with `want`.
fn verify_binding(dir: &Path, name: &str, want: &Path) -> Result<bool> {
    let path = dir.join(format!("{name}.json"));
    let Some(saved) = load::<PathBuf>(&path)? else { return Ok(false) };
    if saved != want {
        let (kind, relation) = if name == "run" { ("state", "is bound to") } else { ("run", "belongs to") };
        bail!(
            "{kind} directory {} {relation} {name} directory {}; refusing --{name} {} (with no VM running, remove {} to rebind)",
            dir.display(),
            saved.display(),
            want.display(),
            path.display()
        );
    }
    Ok(true)
}

/// Binds the run directory to one canonical state path in `RUN/state.json` (gone on reboot, as
/// `STATE/run.json` still binds that side). Two state roots hold different flocks, so the first
/// write is a hard link of a whole file, made under a random name, which only one of them can make;
/// every opener then reads the winner. False if the run directory is unclaimed and this user cannot
/// claim it (a non-root opener), so the caller leaves its state unbound too.
fn claim_run(state: &Path, run: &Path) -> Result<bool> {
    use std::io::ErrorKind::AlreadyExists;
    let owner = run.join("state.json");
    let verify = || verify_binding(run, "state", state);
    if verify()? {
        return Ok(true);
    }
    let tmp = run.join(format!(".state.json.{}.tmp", crate::util::random_hex(8)?));
    let made = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&tmp);
    let linked = match made {
        // Another state may have claimed it since it was read.
        Err(e) if unwritable(&e) => return verify(),
        Err(e) => bail!("{}: {e}", tmp.display()),
        Ok(mut f) => {
            if let Err(e) = std::io::Write::write_all(&mut f, &serde_json::to_vec(state)?).and_then(|()| f.sync_all()) {
                let _ = std::fs::remove_file(&tmp);
                bail!("{}: {e}", tmp.display());
            }
            let linked = std::fs::hard_link(&tmp, &owner);
            let _ = std::fs::remove_file(&tmp);
            linked
        }
    };
    match linked {
        Ok(()) => {}
        Err(e) if e.kind() == AlreadyExists || unwritable(&e) => {}
        Err(e) => bail!("{}: {e}", owner.display()),
    }
    // Linked or not, the owner on disk decides.
    verify()
}

impl Host {
    /// Binds each state root to one canonical run path on first open, under the root's flock,
    /// and the run directory to that state root (`claim_run`).
    /// Synced up to `/` once per state root, not per command: under the root's flock, `.synced` names the
    /// root (dev, inode), so a copy syncs again; it goes before a repair and comes back after the syncs.
    /// A `host.json` that does not validate is refused: fix the file.
    pub fn open(state: &Path, run: &Path) -> Result<Host> {
        let host = Self::open_unvalidated(state, run)?;
        host.cfg.validate().map_err(|e| format!("{}: {e} (see README: Configuration)", host.state.join("host.json").display()))?;
        Ok(host)
    }

    /// `open`, taking `host.json` whatever it says (it may still fail to parse).
    fn open_unvalidated(state: &Path, run: &Path) -> Result<Host> {
        let dirs = [("addrs", 0o755), ("standby", 0o755), ("migs", 0o755), ("owed", 0o700), ("withdrawals", 0o700), ("suspended", 0o700)];
        let named = |d: &Path, e: std::io::Error| {
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied { " (run flexvm as root to create it)" } else { "" };
            format!("{}: {e}{hint}", d.display())
        };
        // Each root is made 0755 if missing and followed if a link; everything after uses the canonical path.
        let host_root = |d: &Path| {
            let made = if d.is_dir() { Ok(()) } else { host_dir(d, 0o755) };
            made.and_then(|()| d.canonicalize()).and_then(|c| trusted_root(&c).map(|()| c)).map_err(|e| named(d, e))
        };
        let (state, run) = (host_root(state)?, host_root(run)?);
        let (state, run) = (state.as_path(), run.as_path());
        let root = |e| named(state, e);
        let (marker, id) = (state.join(".synced"), || std::fs::metadata(state).map(|m| format!("{} {}", m.dev(), m.ino())));
        // Only the directories flexvm made here; deeper ones are checked where they are used.
        for d in dirs.iter().map(|(d, _)| state.join(d)).chain([locks(state)]).filter(|d| d.symlink_metadata().is_ok()) {
            trusted_dir(&d).map_err(|e| named(&d, e))?;
        }
        for d in ["vms", "standby", "w", "claims", "live"] {
            let path = run.join(d);
            match host_dir(&path, 0o755) {
                Err(e) if unwritable(&e) && path.symlink_metadata().is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
                r => r.map_err(|e| named(&path, e))?,
            }
        }
        // Readers of an initialized state need no lock: they cannot change its binding
        // or repair it. Never flock the publicly readable directory itself.
        let _held = match private_file(&locks(state).join("open")) {
            Ok(f) => Some(Flock::new(f, libc::LOCK_EX).map_err(root)?),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(e) => return Err(root(e).into()),
        };
        if id().ok().is_none_or(|id| std::fs::read_to_string(&marker).ok() != Some(id)) || dirs.iter().any(|(d, _)| !state.join(d).is_dir()) {
            let _ = std::fs::remove_file(&marker);
            dirs.iter()
                .try_for_each(|(d, mode)| host_dir(&state.join(d), *mode).and_then(|()| crate::util::create_dir_durably(&state.join(d), *mode)))
                .and_then(|()| write_record(&marker, id()?.as_bytes()))
                .map_err(root)?;
        }
        // Name locks (`vms`): made by root, so a non-root reader leaves it be.
        let _ = private_dir(&locks(&run.join("vms")));
        let (state, run) = (state.to_path_buf(), run.to_path_buf());
        let binding = state.join("run.json");
        reserved_run(&state, &run, Path::new(DEFAULT_STATE), Path::new(DEFAULT_RUN))?;
        let bound = verify_binding(&state, "run", &run)?;
        let claimed = claim_run(&state, &run)?;
        // A user who cannot write the state root (a non-root `flexvm ps` of an unbound one) leaves it unbound,
        // as does one who could not claim the run directory: it is not bound to a directory it may not own.
        if !bound && claimed {
            match crate::util::write_file(&state, "run.json", &serde_json::to_vec(&run)?, true) {
                Err(e) if unwritable(&e) => {}
                r => r.map_err(|e| format!("{}: {e}", binding.display()))?,
            }
        }
        let _ = RUN_DIR.set(run.clone());
        let cfg_stamp = stamp(&state.join("host.json"));
        let mut cfg: Config = load(&state.join("host.json"))?.unwrap_or_default();
        cfg.run = Some(run.clone());
        Ok(Host { state, run, cfg, cfg_stamp, cfg_seen: Arc::new(Mutex::new(None)) })
    }

    pub fn configure(&mut self, change: impl FnOnce(&mut Config) -> Result<()>) -> Result<()> {
        let _l = self.lock()?;
        let path = self.state.join("host.json");
        let mut cfg: Config = load(&path)?.unwrap_or_default();
        cfg.run = Some(self.run.clone());
        change(&mut cfg)?;
        cfg.validate()?;
        store(&path, &cfg, true)?;
        self.cfg = cfg;
        self.cfg_stamp = stamp(&path);
        Ok(())
    }

    /// Of this host's taps and hold devices: `f` and five base-36 digits of a
    /// hash of the state directory, so hosts on separate ones read apart. Six
    /// bytes leave a VM process's taps (a pid of up to 6 hex digits, `t`) two
    /// suffix digits (`fc::free_tap`). Two hosts that collide still never share
    /// a name, as each carries its process's pid, and sweeps go by a tap's alias.
    pub fn tap_prefix(&self) -> String {
        tap_prefix(&self.state)
    }

    /// The configuration as it is now: `flexvm listen` may have changed the
    /// reserve, the eviction mark or the peers since this process started.
    /// host.json is read again once its mtime or inode changed (then cached by both).
    /// While it cannot be read whole and validated (mid-write, missing, invalid ranges), the newest one that was read
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
        if let Some(mut cfg) = now.and_then(|_| load::<Config>(&path).ok().flatten().filter(|c| c.validate().is_ok())) {
            cfg.run = Some(self.run.clone());
            *seen = Some((now.unwrap(), cfg.clone()));
            return cfg;
        }
        match last {
            Some((t, cfg)) if self.cfg_stamp.is_none_or(|own| own.0 <= t.0) => cfg,
            _ => self.cfg.clone(),
        }
    }

    /// The host lock's file, `STATE/.locks/host`.
    pub fn lock_file(&self) -> PathBuf {
        locks(&self.state).join("host")
    }

    fn worker_flock(&self) -> Option<Flock> {
        let f = private_file(&locks(&self.state).join("evict.worker")).ok()?;
        Flock::new(f, libc::LOCK_EX | libc::LOCK_NB).ok()
    }

    /// `STATE/.locks/evict.worker`, held by the thread running an eviction for
    /// as long as it runs (and let go with its process). Taken under the
    /// host lock, as `evicting` probes it, so the two never meet.
    pub fn evict_worker_lock(&self) -> Result<Flock> {
        let _l = self.lock()?;
        self.worker_flock().ok_or_else(|| "another eviction runs here".into())
    }

    /// Whether an eviction runs here now (not merely that the host was under
    /// pressure). Under the host lock (see `evict_worker_lock`).
    fn evicting(&self, _l: &Locked) -> bool {
        self.worker_flock().is_none() && locks(&self.state).join("evict.worker").exists()
    }

    /// Reentrant within a thread (so a guard dropped under it cannot
    /// deadlock); other threads wait as other processes do.
    pub fn lock(&self) -> Result<Locked> {
        self.lock_by(None)
    }

    /// Gives up at `deadline`, if any, with an I/O `WouldBlock` error. Either way it waits
    /// blocked, not polling: it has the lock as soon as the holder lets go (#541).
    pub fn lock_by(&self, deadline: Option<std::time::Instant>) -> Result<Locked> {
        if DEPTH.with(|d| d.get()) > 0 {
            DEPTH.with(|d| d.set(d.get() + 1));
            return Ok(Locked(None));
        }
        let busy = || std::io::Error::new(std::io::ErrorKind::WouldBlock, "the host lock is busy");
        let threads = THREADS.take(deadline).ok_or_else(busy)?;
        let f = match deadline {
            None => {
                let f = private_file(&self.lock_file())?;
                flock(&f, libc::LOCK_EX).map(|()| f)?
            }
            Some(d) => flock_by(&self.lock_file(), d).map_err(|e| if e.kind() == std::io::ErrorKind::WouldBlock { busy() } else { e })?,
        };
        DEPTH.with(|d| d.set(1));
        Ok(Locked(Some((f, threads))))
    }

    // The paths made from a VM name refuse a name `check_name` does, so
    // none (a peer's "../x", say) reaches outside its directory.

    pub fn sock(&self, name: &str) -> Result<PathBuf> {
        self.vms(name, "sock")
    }

    /// `RUN/vms/NAME.EXT`; the name's lock is `RUN/vms/.locks/NAME.lock`.
    pub fn vms(&self, name: &str, ext: &str) -> Result<PathBuf> {
        check_name(name)?;
        let vms = self.run.join("vms");
        Ok(if ext == "lock" { locks(&vms) } else { vms }.join(format!("{name}.{ext}")))
    }

    pub fn suspended(&self, name: &str) -> Result<PathBuf> {
        check_name(name)?;
        Ok(self.state.join("suspended").join(name))
    }

    /// Whether a suspended VM of this name may still be resumed (or is
    /// quarantined): its checkpoint is published and not consumed. Anything
    /// else in its place is debris of an interrupted suspend, resume or
    /// discard, removed by the next holder of the name.
    pub fn is_suspended(&self, name: &str) -> bool {
        let Ok(dir) = self.suspended(name) else { return false };
        dir.join("manifest.json").is_file() && !dir.join("STARTED").exists() && !dir.join("DISCARDED").exists()
    }

    /// The template content ids VMs here use as far as their records say: registered VMs, and
    /// every suspended (or quarantined) one, even one a live process holds the name of (a resume
    /// that has not opened its template yet). `rmi` reads it again under a generation's exclusive
    /// use lock: a suspend publishes its checkpoint before its process lets the lock go, and a resume
    /// takes the lock before it marks the checkpoint STARTED, so one of the two shows every such VM.
    pub fn template_users(&self) -> std::collections::BTreeSet<String> {
        let mut ids: std::collections::BTreeSet<String> = self.entries().into_iter().map(|e| e.template_id).filter(|id| !id.is_empty()).collect();
        let suspended = std::fs::read_dir(self.state.join("suspended")).into_iter().flatten().flatten();
        for name in suspended.filter_map(|e| e.file_name().into_string().ok()).filter(|n| !n.starts_with('.')) {
            if let (true, Ok(dir)) = (self.is_suspended(&name), self.suspended(&name)) {
                ids.extend(crate::checkpoint::read_manifest(&dir).ok().map(|m| m.template_id));
            }
        }
        ids
    }

    /// What a dead holder left running is reaped first, then debris in its
    /// suspended directory is removed.
    pub fn take_name(&self, name: &str, resuming: bool) -> Result<NameLock> {
        let (lock, suspended) = (self.vms(name, "lock")?, self.suspended(name)?);
        if !resuming && self.is_suspended(name) {
            bail!("vm {name:?} exists (stopped); flexvm start or rm it");
        }
        // A sweep holds a dead holder's lock for a moment (`collect_owned`):
        // not taken, so tried again briefly.
        let until = std::time::Instant::now() + Duration::from_millis(250);
        let f = loop {
            match lock_path(&lock, libc::LOCK_EX | libc::LOCK_NB) {
                Ok(f) => break f,
                Err(_) if std::time::Instant::now() < until && self.holder_gone(name) => std::thread::sleep(Duration::from_millis(2)),
                Err(_) => bail!("vm name {name:?} is taken"),
            }
        };
        // Locked, so its holder no longer runs it; its Firecrackers are reaped on
        // proof of death only, and an unreadable lock is an error, never no holder.
        if let Some(old) = lock_holder(&lock)?.filter(|o| *o != Ident::me()) {
            reap(&self.run, &old)?;
        }
        if suspended.exists() && !self.is_suspended(name) {
            crate::lifecycle::remove_debris(self, name)?;
        }
        if !resuming && suspended.exists() {
            bail!("vm {name:?} exists (stopped); flexvm start or rm it");
        }
        for ext in ["json", "sock", "moved", "failed", "lost"] {
            let _ = std::fs::remove_file(self.vms(name, ext)?);
        }
        f.set_len(0)?;
        f.write_all_at(&serde_json::to_vec(&Ident::me())?, 0)?;
        Ok(NameLock { name: name.into(), host: self.clone(), _file: f })
    }

    /// Whether no process runs `name`, by its lock's record alone (never a
    /// probe of the lock, which a start takes without waiting): none, or one
    /// proven gone.
    pub fn holder_gone(&self, name: &str) -> bool {
        match self.vms(name, "lock").and_then(|l| lock_holder(&l)) {
            Ok(None) => true,
            Ok(Some(id)) => id.liveness() == Liveness::Gone,
            Err(_) => false,
        }
    }

    /// `RUN/.logs.lock`: held shared while a log is opened for a start,
    /// exclusively while garbage collection decides on one and removes it.
    /// Never a name's lock, which a start takes without waiting.
    pub fn logs_lock(&self, how: i32) -> Result<Flock> {
        Ok(Flock::new(private_file(&locks(&self.run).join("logs"))?, how)?)
    }

    pub fn alive(&self, name: &str) -> bool {
        self.vms(name, "lock").is_ok_and(|l| crate::util::locked(&l, libc::LOCK_SH) == Some(true))
    }

    /// Whether `name`'s lock is held: None when that cannot be told (the
    /// file cannot be opened, or the probe fails other than by contention).
    pub fn name_locked(&self, name: &str) -> Option<bool> {
        let f = match File::open(self.vms(name, "lock").ok()?) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(false),
            Err(_) => return None,
        };
        match probe(&f, libc::LOCK_SH) {
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
        lock_holder(&self.vms(name, "lock").ok()?).ok()?.map(|h| h == *id)
    }

    pub fn entries(&self) -> Vec<Entry> {
        let mut out: Vec<Entry> = std::fs::read_dir(self.run.join("vms"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let file_name = e.file_name();
                let name = file_name.to_str()?.strip_suffix(".json")?;
                if File::open(self.vms(name, "lock").ok()?).is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) {
                    // Display only: operations still require entry()'s lock verification.
                    let entry = load::<Entry>(&e.path()).ok()??;
                    return (entry.ident.liveness() != Liveness::Gone).then_some(entry);
                }
                self.entry(name).ok()
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Only believed if written by the process holding the name now.
    pub fn entry(&self, name: &str) -> Result<Entry> {
        match load::<Entry>(&self.vms(name, "json")?) {
            Ok(Some(e)) if self.alive(name) && lock_holder(&self.vms(name, "lock")?).ok().flatten() == Some(e.ident.clone()) => Ok(e),
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
        self.read_addr(ip)
    }

    /// Records are replaced whole, so reading one needs no lock. Only `claim_new_in`
    /// writes one without fsync, so only that one can come back empty (a power loss after
    /// another write synced the directory, #554). Written before this boot (no
    /// `unsynced_marker` of this boot's), its VM died with the host, and its generation is
    /// below the durable high-water mark: as withdrawn at the mark, the address is free
    /// and its generations still only rise. One written in this boot may be a live VM's,
    /// so it is an error, as is anything else that cannot be read or parsed: never a free
    /// address.
    fn read_addr(&self, ip: Ipv4Addr) -> Result<Addr> {
        let path = self.addr_path(ip);
        if std::fs::metadata(&path).is_ok_and(|m| m.len() == 0) {
            // Free only on proof: no marker, or one read back from another boot. A marker that
            // cannot be read, or no boot id to compare, proves nothing.
            match std::fs::read_to_string(self.unsynced_marker(ip)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Ok(b) if !boot_id().is_empty() && b != boot_id() => {}
                _ => bail!("{}: empty, and maybe written in this boot: its VM may still run", path.display()),
            }
            let g = load::<Gens>(&self.gens_path())?.ok_or_else(|| format!("{}: empty, with no high-water mark to bound it", path.display()))?;
            return Ok(Addr { seen: g.reserved, withdrawn: true, ..Addr::default() });
        }
        Ok(load(&path)?.unwrap_or_default())
    }

    /// `RUN/claims/IP`, with the boot id: the record was last written without fsync in
    /// this boot. A clock can be set, so the boot id, not a time, tells (`read_addr`).
    pub(crate) fn unsynced_marker(&self, ip: Ipv4Addr) -> PathBuf {
        self.run.join("claims").join(ip.to_string())
    }

    /// Marked before a write without fsync; the mark goes once a durable write supersedes it.
    fn put_addr(&self, ip: Ipv4Addr, a: &Addr, durable: bool) -> Result<()> {
        let marker = self.unsynced_marker(ip);
        if !durable {
            crate::util::write_file(marker.parent().ok_or("no directory")?, &ip.to_string(), boot_id().as_bytes(), false)
                .map_err(|e| format!("{}: {e}", marker.display()))?;
        }
        store(&self.addr_path(ip), a, durable)?;
        if durable {
            let _ = std::fs::remove_file(&marker);
        }
        Ok(())
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

    /// Makes `ip`'s record durable if it was last written without fsync (`claim_new_in`): before a
    /// suspended checkpoint that names its generation is published, which a power loss must not
    /// outlive while the record comes back empty (read as withdrawn: #563).
    pub fn sync_addr(&self, l: &Locked, ip: Ipv4Addr) -> Result<()> {
        if !self.unsynced_marker(ip).exists() {
            return Ok(());
        }
        let a = self.addr(l, ip)?;
        self.put_addr(ip, &a, true)
    }

    /// Held by the VM instance that claimed it: while that process holds the
    /// name, until its Firecrackers are reaped once it is dead, or while it is
    /// suspended here with this generation. Another instance of the same name
    /// (a restart after a SIGKILL) does not hold it.
    fn held(&self, a: &Addr) -> bool {
        let (Some(h), Some(id)) = (a.holder.as_deref(), &a.holder_id) else { return false };
        let instance = match id.liveness() {
            // What cannot be read about its name keeps it held.
            Liveness::Alive => self.held_by(h, id).unwrap_or(true),
            // Until its Firecrackers are reaped.
            Liveness::Gone => reap(&self.run, id).is_err(),
            Liveness::Unknown => true,
        };
        instance || self.suspended_with(h, a.held)
    }

    /// A suspended VM `name` with generation `gen` (or one whose generation was
    /// never recorded: quarantined, it keeps what it held).
    fn suspended_with(&self, name: &str, gen: u64) -> bool {
        let recorded = || crate::lifecycle::read_gen(&self.suspended(name).ok()?);
        self.is_suspended(name) && recorded().is_none_or(|g| g == gen)
    }

    /// From the range as host.json has it now (a standby started before a `vm_ips`
    /// change claims from the new one); addresses handed out before it stay.
    pub fn claim_new(&self, l: &Locked, holder: &str, want: Option<Ipv4Addr>) -> Result<AddrClaim> {
        self.claim_new_in(l, &self.config_now(), holder, want)
    }

    /// `claim_new` from `cfg`'s range: a caller that decided by that range claims by it too.
    pub fn claim_new_in(&self, l: &Locked, cfg: &Config, holder: &str, want: Option<Ipv4Addr>) -> Result<AddrClaim> {
        let range = cfg.range()?;
        let taken = |ip| self.addr(l, ip).map_or(true, |a| a.lent.is_some() || self.held(&a));
        let ip = match want {
            Some(ip) if !range.allocatable(ip) => {
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
        // Not fsynced, to keep fsyncs off a start: a crash loses this VM too, and the mark
        // already orders its generation. Lost, the record before it stays; emptied, it reads
        // as withdrawn at the mark (`read_addr`), losing no loan (a lent address is not claimed here).
        self.put_addr(ip, &Addr { seen: gen, holder: Some(holder.into()), holder_id: Some(me.clone()), held: gen, lent: a.lent, ..Addr::default() }, false)?;
        Ok(AddrClaim { host: self.clone(), ip, gen, rev: 0, holder: holder.into(), id: me, kept: false, fresh: true })
    }

    /// Where the next automatic allocation starts looking: a hint, never a claim.
    fn alloc_hint(&self) -> PathBuf {
        self.state.join("addrs").join(ALLOC_HINT)
    }

    pub fn lend_new(&self, l: &Locked, ip: Ipv4Addr) -> Result<u64> {
        // A fresh loan: only an address this host would hand out itself, by its range now.
        let cfg = self.config_now();
        if !cfg.range()?.allocatable(ip) {
            bail!("{ip} is not from this host's range {}", cfg.vm_ips);
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

    fn gens_path(&self) -> PathBuf {
        self.state.join("addrs").join(".gens")
    }

    /// Monotonic across crashes and reboots: every generation handed out is below a
    /// high-water mark (`addrs/.gens`) reserved `GEN_BLOCK` at a time, fsynced with its
    /// directory before one at or above it is used, and never written otherwise (#554:
    /// a rewrite without fsync could come back empty). The cursor below it
    /// (`RUN/.gens.next`) is per boot and never synced, so a start pays no fsync for it.
    /// It names the mark it was written under, once that mark was synced: trusted only
    /// while `.gens` still holds that mark. Otherwise (lost, damaged, another boot's, or a
    /// mark renamed in by a process that died or failed before its directory fsync) the
    /// mark is uncertain, so the next generation is at it, which reserves and syncs a new one.
    fn next_gen(&self, seen: u64) -> Result<u64> {
        const GEN_BLOCK: u64 = 1024;
        let cursor = self.run.join(".gens.next");
        if boot_id().is_empty() {
            bail!("cannot read the boot id: generations would not be ordered across a reboot");
        }
        let mut g = load::<Gens>(&self.gens_path())?.unwrap_or(Gens { next: 1, reserved: 0, boot: String::new() });
        let at = std::fs::read(&cursor).ok().and_then(|b| serde_json::from_slice::<Gens>(&b).ok()).filter(|c| c.boot == boot_id() && c.reserved == g.reserved);
        let gen = at.map_or(g.next.max(g.reserved), |c| c.next.max(g.next)).max(seen.saturating_add(1));
        (g.next, g.boot) = (gen + 1, boot_id().into());
        if gen >= g.reserved {
            g.reserved = gen.saturating_add(GEN_BLOCK);
            if g.reserved > GEN_MAX {
                bail!("generations exhausted");
            }
            store(&self.gens_path(), &g, true)?;
        }
        store(&cursor, &g, false)?;
        Ok(gen)
    }

    /// At revision `rev` (a migration's target, recorded only once it commits:
    /// one that never does must not outrank its source), else one past the
    /// newest recorded here.
    pub fn claim_incoming(&self, l: &Locked, holder: &str, ip: Ipv4Addr, gen: u64, rev: Option<u64>) -> Result<AddrClaim> {
        self.claim_at(l, holder, ip, gen, rev, None)
    }

    /// A migration's target, at revision `rev`: its claim is `arriving` by
    /// migration `mig` until that record is released (`settle_arrived`).
    pub fn claim_arrival(&self, l: &Locked, holder: &str, ip: Ipv4Addr, gen: u64, rev: u64, mig: u64) -> Result<AddrClaim> {
        self.claim_at(l, holder, ip, gen, Some(rev), Some(mig))
    }

    fn claim_at(&self, l: &Locked, holder: &str, ip: Ipv4Addr, gen: u64, rev: Option<u64>, mig: Option<u64>) -> Result<AddrClaim> {
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
        (a.holder, a.holder_id, a.held, a.arriving, a.leaving) = (Some(holder.into()), Some(me.clone()), gen, mig, None);
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
    /// Durable: a claim let go after an outcome was settled must stay gone across a crash.
    /// Its published revision (`publish_live`) goes with it.
    pub fn release(&self, l: &Locked, ip: Ipv4Addr, holder: &str, id: Option<&Ident>) -> Result<()> {
        let mut released = None;
        self.update(l, ip, true, |a| {
            let by = |h: &Ident| id.is_none_or(|id| id == h);
            if a.holder.as_deref() == Some(holder) && a.holder_id.as_ref().is_none_or(by) {
                released = a.holder_id.take();
                (a.holder, a.arriving, a.leaving) = (None, None, None);
            }
        })?;
        if let Some(id) = id.or(released.as_ref()) {
            self.unpublish(l, ip, id);
        }
        Ok(())
    }

    /// True if this made the loan (only then may its maker undo it). The
    /// source's own claim is marked `leaving` until it `stay`s. `mig` to `to`:
    /// what a sweep asks should the source die meanwhile. Lent whatever the
    /// range is now: the range decides only what is newly handed out, never
    /// whether an address in use is tracked, so a range that drops it and later
    /// takes it back never hands it out while the VM runs elsewhere (#521).
    pub fn lend(&self, l: &Locked, ip: Ipv4Addr, gen: u64, mig: u64, to: &str) -> Result<bool> {
        let me = Ident::me();
        self.update(l, ip, true, |a| {
            if a.holder_id.as_ref() == Some(&me) {
                a.leaving = Some(Leaving { mig, to: to.into() });
            }
            a.lent.replace(gen) != Some(gen)
        })
    }

    /// A source whose migration did not happen runs its VM here again: its
    /// death is the VM's once more. With `unlend`, the loan of that generation
    /// (its own) goes in the same write, so no crash leaves one without the other.
    /// Test fault `unlend_fail`: an unlend fails, leaving both.
    pub fn stay(&self, l: &Locked, ip: Ipv4Addr, unlend: Option<u64>) -> Result<()> {
        if unlend.is_some() && fault("unlend_fail") {
            bail!("injected fault");
        }
        let me = Ident::me();
        self.update(l, ip, true, |a| {
            if a.holder_id.as_ref() == Some(&me) {
                a.leaving = None;
            }
            if let Some(gen) = unlend {
                a.lent = a.lent.filter(|&lent| lent != gen);
            }
        })
    }

    /// Migration `mig`'s record is released: the VM it brought to `ip` is this
    /// host's own, and a loan of its generation here (it came home) ends.
    /// Idempotent: a release cut short is finished by `mig_done` or `withdraw_dead`.
    fn settle_arrived(&self, l: &Locked, ip: Ipv4Addr, mig: u64) -> Result<()> {
        self.update(l, ip, true, |a| {
            if a.arriving == Some(mig) {
                a.arriving = None;
                a.lent = a.lent.filter(|&lent| lent > a.held);
            }
        })
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
    /// The record's revision may trail the one its holder here runs at (published, `live`): the
    /// newer of the two decides.
    pub fn observe(&self, l: &Locked, ip: Ipv4Addr, gen: u64, rev: u64, via: Option<Ipv4Addr>) -> Result<bool> {
        let live = via.and_then(|_| self.live_of(ip, &self.addr(l, ip).ok()?)).unwrap_or(0);
        self.update(l, ip, true, |a| {
            if gen == 0 || gen > RECV_MAX || gen < a.seen || (gen == a.seen && via.is_some() && (a.withdrawn || rev < a.rev.max(live))) {
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

    /// Records revision `rev` of `gen`, if newer: where this host's VM runs again. A peer's
    /// route for an older revision goes with it: taken while the record trailed (#533), it
    /// would name a place the VM left as the way to it.
    pub fn advance(&self, l: &Locked, ip: Ipv4Addr, gen: u64, rev: u64) -> Result<()> {
        self.update(l, ip, true, |a| {
            if gen == a.seen && rev > a.rev {
                (a.rev, a.via) = (rev, None);
            }
        })
    }

    fn live_path(&self, ip: Ipv4Addr) -> PathBuf {
        self.run.join("live").join(ip.to_string())
    }

    /// Publishes where this process's VM runs within generation `gen` of `ip` (`RUN/live/IP`, on
    /// tmpfs: replaced, never synced), under the host lock, as its revision changes and before the
    /// record's durable write, which may come later or fail (#533). `observe` goes by it while this
    /// process holds the address; once it is dead the record decides alone.
    pub fn publish_live(&self, _: &Locked, ip: Ipv4Addr, gen: u64, rev: u64) -> Result<()> {
        let path = self.live_path(ip);
        host_dir(path.parent().ok_or("no directory")?, 0o755)?;
        store(&path, &Live { id: Ident::me(), gen, rev }, false)
    }

    /// Removes `ip`'s published revision if `id` published it (and no other instance since).
    pub fn unpublish(&self, _: &Locked, ip: Ipv4Addr, id: &Ident) {
        let path = self.live_path(ip);
        if load::<Live>(&path).ok().flatten().is_some_and(|live| live.id == *id) {
            let _ = std::fs::remove_file(path);
        }
    }

    /// `RUN/live` entries no live process will remove: published by a dead process the record no
    /// longer names (one it names goes with its claim, `withdraw_dead`), unreadable ones, and a
    /// dead writer's temporary files (`.IP.PID.tmp`, from `util::write_file`).
    fn sweep_live(&self) -> Result<()> {
        let dir = self.run.join("live");
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => bail!("cannot read {}: {e}", dir.display()),
        };
        let l = self.lock()?;
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let stale = match name.strip_prefix('.') {
                Some(_) => write_debris_of(&e.path()),
                None => match (name.parse::<Ipv4Addr>(), load::<Live>(&e.path())) {
                    (Ok(ip), Ok(Some(live))) => live.id.liveness() == Liveness::Gone && self.addr(&l, ip)?.holder_id.as_ref() != Some(&live.id),
                    (Ok(_), Ok(None)) => false,
                    _ => true,
                },
            };
            if stale {
                let _ = std::fs::remove_file(e.path());
            }
        }
        Ok(())
    }

    /// The revision of the newest generation of `ip` its holder here runs at, as it published it:
    /// only the record's holder instance's, only while it is alive, and only of the generation it holds.
    pub fn live(&self, l: &Locked, ip: Ipv4Addr) -> Result<Option<u64>> {
        let a = self.addr(l, ip)?;
        Ok(self.live_of(ip, &a))
    }

    fn live_of(&self, ip: Ipv4Addr, a: &Addr) -> Option<u64> {
        let id = a.holder_id.as_ref().filter(|id| a.held == a.seen && id.liveness() == Liveness::Alive)?;
        let live: Live = load(&self.live_path(ip)).ok().flatten()?;
        (live.id == *id && live.gen == a.held).then_some(live.rev)
    }

    /// A paused migration source keeps its route too: its release moves it.
    pub fn keeps_route(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        let a = self.addr(l, ip)?;
        let source = || a.holder.as_deref().and_then(|h| self.entry(h).ok()).is_some_and(|e| matches!(e.state.as_str(), "source" | "reconciling"));
        Ok(self.held(&a) && (a.held >= gen || source()))
    }

    /// Counts `dead` as gone even while its other threads still hold the name lock.
    pub fn reinstall(&self, l: &Locked, ip: Ipv4Addr, dead: Option<&Ident>) -> Result<bool> {
        let a = self.addr(l, ip)?;
        let dying = dead.is_some() && a.holder_id.as_ref() == dead;
        let Some(via) = a.via.filter(|_| !a.withdrawn && (dying || !self.held(&a))) else { return Ok(false) };
        if !self.route_allowed(ip, via) {
            return Ok(false);
        }
        crate::net::route_via(ip, via)?;
        crate::log!("put back route {ip} via {via} (generation {})", a.seen);
        Ok(true)
    }

    /// Recheck saved routes against current configuration, without DNS or a wait under the lock.
    fn route_allowed(&self, ip: Ipv4Addr, via: Ipv4Addr) -> bool {
        self.route_check(ip, via).unwrap_or_else(|e| {
            crate::log!("route {ip} via {via}: not put back: {e}");
            false
        })
    }

    /// Whether the saved route may be put back (a refusal for good is logged): an error while that
    /// cannot be told yet, to try again later. A next hop that is no peer's known address while a
    /// peer by name has none known (a name no listener has looked up since a boot, or whose lookup
    /// failed) may be that peer's.
    fn route_check(&self, ip: Ipv4Addr, via: Ipv4Addr) -> Result<bool> {
        let peers = crate::listen::known_peers(self)?;
        let checked = crate::listen::check_vm_ip(self, ip, &peers).and_then(|()| crate::listen::via_by(via, &peers));
        if let Err(e) = &checked {
            let unknown = crate::listen::unknown_peers(self);
            if !unknown.is_empty() && !peers.iter().any(|p| p.to_canonical() == IpAddr::V4(via)) {
                bail!("{e}, while no address of peer {} is known yet", unknown.join(", "));
            }
            crate::log!("route {ip} via {via}: not put back: {e}");
        }
        Ok(checked.is_ok())
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
    /// An error if the directory (made by the first hold) or an entry of it
    /// cannot be read: holds would be missed.
    fn holds(&self, _l: &Locked) -> Result<Vec<(u64, u64)>> {
        let dir = locks(&self.run).join("holds");
        let mut live = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(live),
            Err(e) => bail!("cannot read {}: {e}", dir.display()),
        };
        for e in entries {
            let e = e.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
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
        Ok(live)
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
        Ok(h.resize(mib)?)
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
        let mut grants: Vec<(u64, u64, u64)> = load(&path).ok().flatten().unwrap_or_default();
        let n = grants.len();
        grants.retain(|g| g.2 != id);
        if grants.len() != n {
            let _ = store(&path, &grants, false);
        }
    }

    /// Against the reserve: None if refused; errors grant nothing (`WouldBlock` if the lock is busy).
    pub fn grant(&self, mib: u64, deadline: Option<std::time::Instant>) -> Result<Option<u64>> {
        self.grant_above(mib, Floor::Reserve, deadline)
    }

    /// As `grant`, leaving `floor` available.
    pub fn grant_above(&self, mib: u64, floor: Floor, deadline: Option<std::time::Instant>) -> Result<Option<u64>> {
        Ok(self.grant_inner(mib, floor, false, deadline, crate::vmproc::host_available_mib)?.ok().map(|g| g.0))
    }

    /// A refusal is an error too; `hold` keeps the grant past `GRANT_WINDOW`.
    pub fn grant_start(&self, mib: u64, floor: Floor, hold: bool) -> Result<(u64, Option<Hold>)> {
        self.grant_inner(mib, floor, hold, None, crate::vmproc::host_available_mib)?
    }

    /// MemAvailable lags a grant until the guest touches the memory, so all
    /// processes' grants of the last `GRANT_WINDOW` count as used, and held
    /// ones (`grant_start`) however old, each once. Returns the grant's id.
    /// Leaves `floor` available, read with the reserve under the host lock.
    /// Ok(Err(why)) if refused.
    fn grant_inner(
        &self,
        mib: u64,
        floor: Floor,
        hold: bool,
        deadline: Option<std::time::Instant>,
        available: impl FnOnce() -> Option<u64>,
    ) -> Result<std::result::Result<(u64, Option<Hold>), Error>> {
        let l = self.lock_by(deadline)?;
        let mut grants = match self.room(&l, mib, floor, available)? {
            Ok(grants) => grants,
            Err(why) => return Ok(Err(why)),
        };
        let path = self.grants();
        let now = boottime_ms();
        let id = crate::migrate::migration_id().max(1);
        // Locked before it is visible (renamed in): a probe never takes it for an owner's.
        let hold = match hold {
            false => None,
            true => {
                let dir = locks(&self.run).join("holds");
                let (tmp, path) = (dir.join(format!(".{id}")), dir.join(format!("{id}-{mib}")));
                let f = private_file(&tmp)?;
                if let Err(e) = flock(&f, libc::LOCK_EX | libc::LOCK_NB).and_then(|()| std::fs::rename(&tmp, &path)) {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e.into());
                }
                Some(Hold { path, id, mib, _file: f })
            }
        };
        grants.push((now, mib, id));
        if let Err(e) = store(&path, &grants, false) {
            drop(hold);
            return Err(e);
        }
        Ok(Ok((id, hold)))
    }

    /// Whether `mib` more fits above `floor` (see `grant_inner`): Ok(Ok(the
    /// grants of the window, to add to)), or Ok(Err(why)) if refused. Test
    /// fault `no_admit`: refuses everything.
    fn room(&self, l: &Locked, mib: u64, floor: Floor, available: impl FnOnce() -> Option<u64>) -> Result<std::result::Result<Grants, Error>> {
        if fault("no_admit") {
            return Ok(Err(format!("not enough memory here for {mib} MiB (injected fault)").into()));
        }
        let cfg = self.config_now();
        let (floor, what) = match floor {
            Floor::Reserve => (cfg.reserve(), "reserve"),
            // An eviction's arrival: never while this host evicts itself, and it
            // leaves this host's own mark, so it is not moved straight back.
            Floor::EvictMark if self.evicting(l) => return Ok(Err("this host is moving vms away itself".into())),
            Floor::EvictMark => (cfg.evict_at(), "eviction mark"),
        };
        let now = boottime_ms();
        let mut grants: Grants = load(&self.grants())?.unwrap_or_default();
        // Ignore future stamps so they cannot extend the cooldown indefinitely.
        grants.retain(|&(t, ..)| t <= now && now - t <= GRANT_WINDOW.as_millis() as u64);
        // Fails closed: unread holds would leave out memory still to arrive.
        let held = self.holds(l).map_err(|e| {
            crate::log!("admission: {e}; granting nothing until it can be read");
            format!("{e}: memory held for migrations and restores still arriving cannot be counted")
        })?;
        let held_ids: HashSet<_> = held.iter().map(|h| h.0).collect();
        // Saturating: a peer's sizes are not trusted to fit.
        let pending = grants.iter().filter(|g| !held_ids.contains(&g.2)).map(|g| g.1).chain(held.iter().map(|h| h.1)).fold(0, u64::saturating_add);
        let avail = available().ok_or("cannot read MemAvailable from /proc/meminfo")?;
        if avail < floor.saturating_add(pending).saturating_add(mib) {
            return Ok(Err(format!("not enough memory here for {mib} MiB above the {floor} MiB {what}").into()));
        }
        Ok(Ok(grants))
    }

    /// Counts `hold` as `mib` more, admitted above `floor` like a grant
    /// (Ok(Err(why)) if refused): renamed under the host lock, as `shrink_hold`
    /// does. Its grant's id stays, so a refund still finds it, and it is
    /// counted once (as a hold). Refused, it counts as before.
    pub fn grow_hold(
        &self,
        hold: &Mutex<Option<Hold>>,
        mib: u64,
        floor: Floor,
        deadline: Option<std::time::Instant>,
    ) -> Result<std::result::Result<(), Error>> {
        self.grow_hold_inner(hold, mib, floor, deadline, crate::vmproc::host_available_mib)
    }

    fn grow_hold_inner(
        &self,
        hold: &Mutex<Option<Hold>>,
        mib: u64,
        floor: Floor,
        deadline: Option<std::time::Instant>,
        available: impl FnOnce() -> Option<u64>,
    ) -> Result<std::result::Result<(), Error>> {
        let l = self.lock_by(deadline)?;
        let mut g = hold.lock().unwrap();
        let h = g.as_mut().ok_or("no held grant to grow")?;
        if let Err(why) = self.room(&l, mib, floor, available)? {
            return Ok(Err(why));
        }
        h.resize(h.mib.saturating_add(mib))?;
        Ok(Ok(()))
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
        Ok(MigRecord { host: self.clone(), id, committed: false, source: source.into(), by, ip })
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
        // Clear only this dead arrival, durably before its evidence goes. Committed
        // records carry no address, so find the claim by migration and owner.
        for e in std::fs::read_dir(self.state.join("addrs"))? {
            let Some(ip) = e?.file_name().to_str().and_then(|n| n.parse::<Ipv4Addr>().ok()) else { continue };
            let a = self.addr(&l, ip)?;
            if a.arriving == Some(id) && a.holder_id.as_ref() == Some(&owner) {
                self.release(&l, ip, a.holder.as_deref().unwrap_or_default(), Some(&owner))?;
            }
        }
        crate::util::unlink_durably(&path)?;
        Ok("aborted")
    }

    /// A released record goes, its address's arrival settled first: it is the
    /// evidence `withdraw_dead` reads should the release have been cut short.
    /// Whether it went (there was one).
    pub fn mig_done(&self, id: u64) -> Result<bool> {
        let l = self.lock()?;
        match load(&self.mig_path(id))? {
            Some(Mig::Released { ip, .. }) => {
                if let Some(ip) = ip {
                    self.settle_arrived(&l, ip, id)?;
                }
                crate::util::unlink_durably(&self.mig_path(id))?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    // Outcomes owed: `STATE/owed/ID`, a migration away whose source process
    // ended before it learned whether its target resumed the VM.

    fn owed_path(&self, id: u64) -> PathBuf {
        self.state.join("owed").join(id.to_string())
    }

    /// Recorded durably before the source process ends: its address stays lent
    /// until `settle_owed` learns the outcome.
    /// Test fault `owe_fail`: it fails, as on a full disk.
    pub fn owe(&self, id: u64, o: &Owed) -> Result<()> {
        if fault("owe_fail") {
            bail!("injected fault: recording the owed outcome failed");
        }
        store(&self.owed_path(id), o, true)
    }

    /// Owed records by id; anything else there (a write's `.ID.PID.tmp`) is not one.
    fn owed_ids(&self) -> std::io::Result<Vec<(u64, PathBuf)>> {
        let ids = std::fs::read_dir(self.state.join("owed"))?
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().into_string().ok()?;
                (!name.is_empty() && name.bytes().all(|b| b.is_ascii_digit())).then(|| Some((name.parse().ok()?, e.path())))?
            })
            .collect();
        Ok(ids)
    }

    /// Whether an outcome is still owed for the source process `by`: its target
    /// must keep its record (the source host asks about it), as if `by` lived.
    /// What cannot be read counts as owed.
    /// So is one whose claim here is still `leaving`: dead, its outcome is yet
    /// to be recorded as owed (`withdraw_dead`); alive, it has not decided.
    pub fn owes(&self, by: &Ident) -> bool {
        let recorded = match self.owed_ids() {
            Ok(ids) => ids.iter().any(|(_, path)| load::<Owed>(path).map_or(true, |o| o.is_some_and(|o| o.by == *by))),
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        };
        recorded || self.leaving_by(by)
    }

    /// Whether `by` holds an address here as a migration source (`leaving`);
    /// what cannot be read counts as such.
    fn leaving_by(&self, by: &Ident) -> bool {
        let entries = match std::fs::read_dir(self.state.join("addrs")) {
            Ok(entries) => entries,
            Err(e) => return e.kind() != std::io::ErrorKind::NotFound,
        };
        entries.into_iter().any(|e| {
            let Ok(e) = e else { return true };
            let Some(ip) = e.file_name().to_str().and_then(|n| n.parse::<Ipv4Addr>().ok()) else { return false };
            self.read_addr(ip).map_or(true, |a| a.leaving.is_some() && a.holder_id.as_ref() == Some(by))
        })
    }

    /// Asks each owed migration's target (five a pass, an unreachable one once): once
    /// it `released`, the VM is the target's, so the loan stays (its own
    /// withdrawal takes it back) and the target is told `done`; once
    /// `aborted`, no copy runs anywhere, so the generation is withdrawn here
    /// and at the peers, which frees the address. Otherwise it is asked again.
    pub fn settle_owed(&self) {
        let host = self.clone();
        self.settle_owed_with(
            5,
            |to, id| {
                let r = crate::vmproc::peer_call(to, serde_json::json!({"op": "migration", "mig": id}))?;
                Ok(r["outcome"].as_str().unwrap_or_default().to_string())
            },
            |to, id| drop(crate::vmproc::peer_call(to, serde_json::json!({"op": "migration", "mig": id, "done": true}))),
            |_, _| host.deliver_withdrawals(),
        );
    }

    fn settle_owed_with(
        &self,
        budget: usize,
        mut query: impl FnMut(&str, u64) -> Result<String>,
        mut done: impl FnMut(&str, u64),
        mut withdrawn: impl FnMut(Ipv4Addr, u64),
    ) {
        let Ok(lock) = private_file(&locks(&self.run).join("owed")) else { return };
        let Ok(_lock) = Flock::new(lock, libc::LOCK_EX | libc::LOCK_NB) else { return };
        self.owed_debris();
        let cursor = self.run.join(".owed.next");
        let last = load::<u64>(&cursor).ok().flatten();
        let mut ids: Vec<u64> = self.owed_ids().unwrap_or_default().into_iter().map(|(id, _)| id).collect();
        ids.sort_unstable();
        let start = last.map_or(0, |last| ids.partition_point(|id| *id <= last));
        ids.rotate_left(start);
        let (mut unavailable, mut visited) = (HashSet::new(), None);
        for id in ids.into_iter().take(budget) {
            visited = Some(id);
            let path = self.owed_path(id);
            let Ok(Some(o)) = load::<Owed>(&path) else { continue };
            if unavailable.contains(&o.to) {
                continue;
            }
            let outcome = query(&o.to, id);
            if outcome.is_err() {
                unavailable.insert(o.to.clone());
            }
            match outcome.as_deref() {
                Ok("released") => {
                    // The decision on the address first (its `leaving` claim retired, durably),
                    // then the record: neither left for a later sweep to owe again once the
                    // target, told `done`, forgets it and would answer aborted.
                    if let Err(e) = self.lock().and_then(|l| self.retire_leaving(&l, &o, id)) {
                        crate::log!("migration {id}: {} has the vm; recording it for {}: {e}; asked again on the next pass", o.to, o.ip);
                        continue;
                    }
                    if crate::util::unlink_durably(&path).is_ok() {
                        crate::log!("migration {id}: {} has the vm; {} stays lent to it", o.to, o.ip);
                        done(&o.to, id);
                    }
                }
                Ok("aborted") => {
                    let freed = self.lock().and_then(|l| {
                        let current = self.withdraw_noted(&l, o.ip, o.gen)?;
                        self.unlend(&l, o.ip, o.gen)?;
                        self.retire_leaving(&l, &o, id)?;
                        // A newer generation here keeps its route.
                        if current && self.holder(&l, o.ip)?.is_none() && !self.reinstall(&l, o.ip, None)? {
                            crate::net::unroute(o.ip);
                        }
                        Ok(())
                    });
                    match freed {
                        Ok(()) => {
                            crate::log!("migration {id}: {} aborted it, and its source is gone; {} generation {} withdrawn", o.to, o.ip, o.gen);
                            withdrawn(o.ip, o.gen);
                            let _ = crate::util::unlink_durably(&path);
                        }
                        Err(e) => crate::log!("migration {id}: withdrawing {}: {e}; retried on the next pass", o.ip),
                    }
                }
                _ => {}
            }
        }
        if let Some(id) = visited {
            let _ = store(&cursor, &id, false);
        }
    }

    /// An interrupted `owe`'s `.ID.PID.tmp`, once its writer is gone.
    fn owed_debris(&self) {
        self.write_debris("owed")
    }

    /// In `STATE/DIR`, an interrupted write's temporary file (`util::write_file`), once its writer is gone.
    fn write_debris(&self, dir: &str) {
        remove_write_debris(&self.state.join(dir), |_| true);
    }

    /// `flexvm reclaim IP --force GEN`: an address lent out with a VM that migrated away, taken
    /// back: its generation withdrawn here (the peers are told by the caller) and any
    /// outcome owed for it forgotten. Only for a target known to be gone for good (the VM
    /// is not running there): a VM still running with the address would share it.
    /// Refuses unless the lent generation still matches the operator's confirmation, under the host lock.
    /// Returns the generation withdrawn and the migrations forgotten.
    pub fn reclaim(&self, ip: Ipv4Addr, expected: u64) -> Result<Lent> {
        let l = self.lock()?;
        let a = self.addr(&l, ip)?;
        let Some(gen) = a.lent else { bail!("{ip} is not lent out") };
        if gen != expected {
            bail!("{ip} is lent out with generation {gen}, not confirmed generation {expected}; run flexvm reclaim {ip} again");
        }
        if let Some(h) = self.holder(&l, ip)? {
            bail!("{ip} is held by vm {h} here");
        }
        let owed: Vec<(u64, PathBuf, Owed)> =
            self.owed_ids()?.into_iter().filter_map(|(id, path)| Some((id, path.clone(), load::<Owed>(&path).ok()??))).filter(|(_, _, o)| o.ip == ip).collect();
        // Withdrawn first: a crash before the records go leaves them to settle as aborted (a withdrawal again).
        let current = self.observe(&l, ip, gen, 0, None)?;
        self.unlend(&l, ip, gen)?;
        // A dead source's `leaving` claim goes too: withdrawn, nothing is owed for it (#570).
        if let (Some(_), Some(name), Some(by)) = (&a.leaving, &a.holder, &a.holder_id) {
            if self.dead_and_reaped(&a) {
                self.release(&l, ip, name, Some(by))?;
            }
        }
        if current && !self.reinstall(&l, ip, None)? {
            crate::net::unroute(ip);
        }
        for (_, path, _) in &owed {
            crate::util::unlink_durably(path)?;
        }
        Ok((gen, owed.into_iter().map(|(id, _, o)| (id, o.to)).collect()))
    }

    /// What `reclaim` would take back: the generation lent and the migrations owed for `ip`.
    pub fn lent_to(&self, ip: Ipv4Addr) -> Result<Option<Lent>> {
        let l = self.lock()?;
        let Some(gen) = self.addr(&l, ip)?.lent else { return Ok(None) };
        let owed = self
            .owed_ids()?
            .into_iter()
            .filter_map(|(id, path)| Some((id, load::<Owed>(&path).ok()??)))
            .filter(|(_, o)| o.ip == ip)
            .map(|(id, o)| (id, o.to))
            .collect();
        Ok(Some((gen, owed)))
    }

    /// Retires aborted arrivals and released records whose source is proven gone.
    /// Any doubt keeps the record: a source that still waits must find it.
    pub fn retire_migrations(&self) {
        // At most five records (and thus five two-second peer calls) per pass.
        self.retire_migrations_with(5, |source, by| {
            crate::vmproc::peer_call(source, serde_json::json!({"op": "source", "ident": by})).map(|r| r["gone"] == true)
        });
    }

    fn retire_migrations_with(&self, budget: usize, mut query: impl FnMut(&str, &Ident) -> Result<bool>) {
        let Ok(lock) = private_file(&locks(&self.run).join("retire")) else { return };
        let Ok(_lock) = Flock::new(lock, libc::LOCK_EX | libc::LOCK_NB) else { return };
        // Migration writers hold the host lock; never sweep an in-progress write.
        if let Ok(_l) = self.lock() {
            self.write_debris("migs");
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
        ids.truncate(budget);
        let mut unavailable = HashSet::new();
        for &id in &ids {
            let Ok(Some(Mig::Released { source, by, .. })) = load(&self.mig_path(id)) else {
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
        if let Some(id) = ids.last() {
            if let Err(e) = store(&cursor, id, false) {
                crate::log!("migration retirement cursor: {e}");
            }
        }
    }
}

/// Recent grants, as (boot-clock ms, MiB, id).
type Grants = Vec<(u64, u64, u64)>;

const GRANT_WINDOW: Duration = Duration::from_secs(10);

#[cfg(test)]
pub(crate) use tests::pin_clock;

/// Shared by all processes (RUN is per boot) and unaffected by wall-clock steps.
pub(crate) fn boottime_ms() -> u64 {
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

/// `addrs/.gens` (the high-water mark `reserved`) and `RUN/.gens.next` (the cursor `next`, in boot `boot`).
#[derive(Serialize, Deserialize)]
struct Gens {
    next: u64,
    reserved: u64,
    boot: String,
}

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
    /// The migration its holder's VM is arriving by, until that record is
    /// released: the holder's death before then is not the VM's (its source
    /// runs it again), after it is (`withdraw_dead` reads the record).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arriving: Option<u64>,
    /// Its holder is the source of this migration, which may have handed the
    /// VM on (from its loan until it `stay`s): should it die meanwhile, the
    /// outcome is owed (`withdraw_dead`), settled once the target says.
    /// (Records written before this field read as not leaving: no
    /// compatibility is kept with them.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaving: Option<Leaving>,
}

impl Addr {
    pub fn current(&self, gen: u64) -> bool {
        gen > self.seen || (gen == self.seen && !self.withdrawn)
    }
}

/// `RUN/live/IP`: the revision of generation `gen` the VM process `id` runs at (`Host::publish_live`).
#[derive(Debug, Serialize, Deserialize)]
struct Live {
    id: Ident,
    gen: u64,
    rev: u64,
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
    /// Kept past this process (suspended): its published revision goes with the process.
    pub fn keep(mut self) {
        self.kept = true;
        if let Ok(l) = self.host.lock() {
            self.host.unpublish(&l, self.ip, &self.id);
        }
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
        /// The VM's address here, whose claim is `arriving` by this migration until settled.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ip: Option<Ipv4Addr>,
    },
}

/// A migration away under way (`Addr::leaving`): its id and target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaving {
    pub mig: u64,
    pub to: String,
}

/// A loan: its generation, and the migrations (id, target) whose outcome is owed for it.
pub type Lent = (u64, Vec<(u64, String)>);

/// An outcome owed (`Host::owe`): migration away to `to` of `ip` at generation `gen`, by source process `by`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owed {
    pub to: String,
    pub ip: Ipv4Addr,
    pub gen: u64,
    pub by: Ident,
}

/// Dropped before it commits, the record goes (aborted).
pub struct MigRecord {
    host: Host,
    pub id: u64,
    committed: bool,
    source: String,
    by: Option<Ident>,
    /// The VM's address: once released, its claim here is no longer `arriving`.
    ip: Option<Ipv4Addr>,
}

impl MigRecord {
    /// From here this host owns the VM. Refused if a source query fenced it off.
    pub fn commit(&mut self, _: &Locked) -> Result<()> {
        let path = self.host.mig_path(self.id);
        match load(&path)? {
            // Keep both fsyncs before running the VM or replying: the file fsync makes
            // Committed's contents durable before rename; the migs directory fsync
            // makes that replacement durable. Overlapping them could recover Pending
            // (or an empty record) after the target has run and the source has left.
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
                store(&self.host.mig_path(self.id), &Mig::Released { source: self.source.clone(), by: self.by.clone(), ip: self.ip }, true)?;
                // Released first, with the address: what a crash leaves undone, the record finishes.
                if let Some(ip) = self.ip {
                    self.host.settle_arrived(&l, ip, self.id)?;
                }
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

pub struct Locked(#[allow(dead_code)] Option<(File, ThreadsHeld)>);

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

/// The host lock between this process's threads (the flock is per open file, and each
/// thread opens its own). A flag and a condvar rather than a `Mutex<()>`: a bounded wait
/// sleeps until the holder lets go, where a mutex could only be polled.
struct Threads {
    held: Mutex<bool>,
    freed: std::sync::Condvar,
}

static THREADS: Threads = Threads { held: Mutex::new(false), freed: std::sync::Condvar::new() };

impl Threads {
    /// None once `deadline` passes with the lock still held.
    fn take(&'static self, deadline: Option<std::time::Instant>) -> Option<ThreadsHeld> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        #[cfg(test)]
        if *held && deadline.is_none() {
            LOCK_WAITING.with(|waiting| {
                if let Some(tx) = waiting.borrow_mut().take() {
                    tx.send(()).unwrap();
                }
            });
        }
        while *held {
            held = match deadline {
                None => self.freed.wait(held).unwrap_or_else(|e| e.into_inner()),
                Some(d) => match d.checked_duration_since(std::time::Instant::now()).filter(|left| !left.is_zero()) {
                    Some(left) => self.freed.wait_timeout(held, left).unwrap_or_else(|e| e.into_inner()).0,
                    None => return None,
                },
            };
        }
        *held = true;
        Some(ThreadsHeld(std::marker::PhantomData))
    }
}

/// Let go of when dropped, a panicking holder's too. Not `Send`, as the `MutexGuard` it
/// replaces was not: `DEPTH` is the taking thread's.
struct ThreadsHeld(std::marker::PhantomData<*const ()>);

impl Drop for ThreadsHeld {
    fn drop(&mut self) {
        *THREADS.held.lock().unwrap_or_else(|e| e.into_inner()) = false;
        THREADS.freed.notify_one();
    }
}
#[cfg(test)]
thread_local! {
    // Fired only after this thread has observed actual host-lock contention.
    pub(crate) static LOCK_WAITING: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
}
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
        store(&self.host.vms(&self.name, "json")?, e, false)
    }
}

impl Drop for NameLock {
    fn drop(&mut self) {
        // Unlinked while held: a taker re-checks the path after locking.
        for ext in ["json", "sock", "lock"] {
            // Checked when taken.
            if let Ok(path) = self.host.vms(&self.name, ext) {
                let _ = std::fs::remove_file(path);
            }
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
    /// Its `run --cpus` cap, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpus: Option<f64>,
    /// Its memory ceiling: the template's, or less (`run --memory`).
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    trusted_root(run)?;
    trusted_dir(&run.join("w"))?;
    let dir = owner.work_dir(run);
    match trusted_dir(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        r => r?,
    }
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
        trusted_dir(&e.path())?;
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
    taps_of_at(run, Path::new("/sys/class/net"), false)
}

fn taps_of_at(run: &Path, net: &Path, orphaned: bool) -> Vec<(String, u32, Ident)> {
    let run = run.to_string_lossy();
    let mut taps = Vec::new();
    for e in std::fs::read_dir(net).into_iter().flatten().flatten() {
        let dir = e.path();
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).ok();
        let Some(index) = read("ifindex").and_then(|i| i.trim().parse().ok()) else { continue };
        let Some(alias) = read("ifalias") else { continue };
        let Some((owner, of)) = parse_tap_alias(alias.strip_suffix('\n').unwrap_or(&alias)) else { continue };
        // Only NotFound proves the other run directory is gone; permission and I/O
        // errors leave its taps alone. The owner must still be proven dead by GC.
        let missing = || Path::new(of).metadata().is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
        if (of == run || (orphaned && missing())) && dir.join("tun_flags").exists() {
            taps.push((e.file_name().to_string_lossy().into_owned(), index, owner));
        }
    }
    taps
}

/// GC also collects taps from deleted private/test run directories, once their owner is gone.
fn dead_taps_at(run: &Path, net: &Path) -> Vec<(String, u32, Ident)> {
    taps_of_at(run, net, true).into_iter().filter(|(_, _, owner)| owner.liveness() == Liveness::Gone).collect()
}

/// A detached VM process's own cgroup (`vm-PID-START`, `util::spawn_self`)
/// goes once nothing is in it: never killed, so a process that just joined
/// one is never touched. (`rmdir` refuses a populated cgroup anyway.)
/// A VM a sweep found dead and withdrew: (name, address, generation).
pub type Withdrawn = (String, Ipv4Addr, u64);

/// Whether `path` is a temporary file of `util::write_file` (`.NAME.TAG.tmp`) whose writer is
/// proven gone. TAG `PID-START-BOOT` (`util::write_tag`) names its process: gone once that
/// process is, or written in another boot. A bare PID (an older flexvm's, or one that could not
/// name itself) is gone once no process has that pid, or once the file is older than this boot.
pub(crate) fn write_debris_of(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return false };
    let Some((_, tag)) = name.strip_prefix('.').and_then(|n| n.strip_suffix(".tmp")).and_then(|n| n.rsplit_once('.')) else { return false };
    let mut parts = tag.split('-');
    let (Some(Ok(pid)), start, boot, None) = (parts.next().map(str::parse::<u32>), parts.next(), parts.next(), parts.next()) else { return false };
    match (start.map(str::parse::<u64>), boot) {
        (Some(Ok(start)), Some(boot)) => {
            let now = boot_id();
            if now.is_empty() || boot.len() != crate::util::BOOT_TAG {
                false
            } else if !now.starts_with(boot) {
                true
            } else {
                Ident { pid, start, boot: now.into() }.liveness() == Liveness::Gone
            }
        }
        (None, None) => !Path::new(&format!("/proc/{pid}")).exists() || older_than_boot(path),
        _ => false,
    }
}

/// Modified before this boot began (`btime` in /proc/stat); false when either cannot be read.
fn older_than_boot(path: &Path) -> bool {
    let btime = std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse::<u64>().ok()))
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
    let mtime = std::fs::symlink_metadata(path).and_then(|m| m.modified()).ok();
    matches!((mtime, btime), (Some(m), Some(b)) if m < b)
}

/// Removes, among `dir`'s entries whose names pass `which`, `write_file` debris (`write_debris_of`):
/// never a published record (no leading dot) nor a live writer's temporary file.
fn remove_write_debris(dir: &Path, which: impl Fn(&str) -> bool) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if e.file_name().to_str().is_some_and(&which) && write_debris_of(&e.path()) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Whether the suspended directory `dir` holds a QUARANTINE written in this boot (one that cannot be
/// read counts as such); an earlier boot's no longer holds (`lifecycle::quarantined`).
fn quarantined_now(dir: &Path) -> bool {
    match std::fs::read_to_string(dir.join("QUARANTINE")) {
        Ok(q) => crate::lifecycle::quarantined(&q, boot_id()).is_some(),
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

pub const DEFAULT_STATE: &str = "/var/lib/flexvm";
pub const DEFAULT_RUN: &str = "/run/flexvm";

/// The run directory of `state` when no `--run` is given, by its path alone: `/run/flexvm` for
/// the default state, `/run/flexvm-PREFIX` (its taps' prefix) for any other. No state defaults to
/// a run directory another may own, so after a reboot none takes another's first (#556). A state
/// bound elsewhere (`run.json`, an older default) is refused without its `--run`, never let to
/// default into it.
pub fn default_run(state: &Path) -> Result<PathBuf> {
    let state = state.canonicalize().unwrap_or_else(|_| state.to_path_buf());
    let run = default_run_of(&state);
    match load::<PathBuf>(&state.join("run.json")) {
        Ok(Some(bound)) if bound != run => bail!(
            "state directory {} is bound to run directory {}, not its default {}: give --run {} (or, with no VM running, remove {} to rebind)",
            state.display(),
            bound.display(),
            run.display(),
            bound.display(),
            state.join("run.json").display()
        ),
        // Unreadable (a non-root reader): `Host::open` decides.
        _ => Ok(run),
    }
}

/// `/run/flexvm` (`default_run`) is only ever the default state's: any other state is refused it,
/// bound or claimed, so no order of opens after a reboot hands it to another (#556).
fn reserved_run(state: &Path, run: &Path, default_state: &Path, default_run: &Path) -> Result<()> {
    let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    if canon(run) == canon(default_run) && canon(state) != canon(default_state) {
        bail!(
            "run directory {} is the default state directory {}'s only; state directory {} takes one of its own (--run, or without it {})",
            run.display(),
            default_state.display(),
            state.display(),
            default_run_of(state).display()
        );
    }
    Ok(())
}

fn default_run_of(state: &Path) -> PathBuf {
    let default = Path::new(DEFAULT_STATE);
    if state == default || default.canonicalize().is_ok_and(|d| d == state) {
        DEFAULT_RUN.into()
    } else {
        format!("{DEFAULT_RUN}-{}", tap_prefix(state)).into()
    }
}

fn sweep_scope(dir: &Path) {
    let events = std::fs::read_to_string(dir.join("cgroup.events")).unwrap_or_default();
    if events.lines().any(|l| l == "populated 0") {
        let _ = std::fs::remove_dir(dir);
    }
}

impl Host {
    /// `RUN/.boot`: the boot id of the last `after_boot` pass here.
    fn boot_marker(&self) -> PathBuf {
        self.run.join(".boot")
    }

    /// Whether the host was recovered in boot `boot` (`mark_recovered`).
    fn recovered(&self, boot: &str) -> bool {
        !boot.is_empty() && std::fs::read_to_string(self.boot_marker()).is_ok_and(|b| b == boot)
    }

    /// Recovery after a boot is complete: written only once every step of it succeeded
    /// (`gc::after_boot`), so until then every opener tries again.
    pub fn mark_recovered(&self) -> Result<()> {
        crate::util::write_file(&self.run, ".boot", boot_id().as_bytes(), false).map_err(|e| format!("{}: {e}", self.boot_marker().display()).into())
    }

    /// Until this boot's recovery is complete (`RUN/.boot`), under the host lock, before anything
    /// else here: what the VMs that ran before the boot left. Each is recorded as lost
    /// (`RUN/vms/NAME.lost`, listed by `ps -a` until `flexvm rm NAME`) before its address is
    /// withdrawn (`withdraw_dead`: a home host's loan ends once the peers are told, an outcome owed
    /// for an interrupted migration is recorded and settled by sweeps), and the routes to peers'
    /// VMs are put back from `STATE/addrs` (kernel routes do not outlive a boot, and peers never
    /// announce again what they delivered, #553). None if recovered already; else whether every
    /// step succeeded. Idempotent: it runs again on the next open until the recovery is marked.
    pub fn after_boot(&self) -> Result<Option<bool>> {
        self.after_boot_with(boot_id(), crate::net::route_via)
    }

    fn after_boot_with(&self, boot: &str, mut route: impl FnMut(Ipv4Addr, Ipv4Addr) -> Result<()>) -> Result<Option<bool>> {
        if boot.is_empty() || self.recovered(boot) {
            return Ok(None);
        }
        let l = self.lock()?;
        if self.recovered(boot) {
            return Ok(None);
        }
        let mut ok = match self.collect_garbage_with(true) {
            Ok(_) => true,
            Err(e) => {
                crate::log!("after boot: {e}");
                false
            }
        };
        let ips = std::fs::read_dir(self.state.join("addrs")).into_iter().flatten().flatten().filter_map(|e| e.file_name().to_str()?.parse::<Ipv4Addr>().ok());
        for ip in ips {
            let a = match self.addr(&l, ip) {
                Ok(a) => a,
                Err(e) => {
                    crate::log!("after boot: route for {ip}: {e}; tried again on the next open");
                    ok = false;
                    continue;
                }
            };
            let Some(via) = a.via.filter(|_| !a.withdrawn && !self.held(&a)) else { continue };
            // Peers never announce again what they delivered (#553): one not checkable yet is tried again.
            match self.route_check(ip, via) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    crate::log!("after boot: route {ip} via {via}: {e}; tried again on the next open");
                    ok = false;
                    continue;
                }
            }
            match route(ip, via) {
                Ok(()) => crate::log!("after boot: put back route {ip} via {via} (generation {})", a.seen),
                Err(e) => {
                    crate::log!("after boot: route {ip} via {via}: {e}; tried again on the next open");
                    ok = false;
                }
            }
        }
        Ok(Some(ok))
    }

    /// `RUN/vms/NAME.lost`, before its address is withdrawn: one that cannot be written keeps the
    /// address for the next try. Nothing for a name held again since (taking it clears the record).
    fn record_lost(&self, name: &str, ip: Ipv4Addr, gen: u64) -> Result<()> {
        if self.alive(name) {
            return Ok(());
        }
        let why = format!("lost: its process ended without withdrawing {ip} (generation {gen}), as in a reboot; the address is withdrawn, its log is gone with the run directory; flexvm rm {name} clears this");
        self.vms(name, "lost")?;
        crate::util::write_file(&self.run.join("vms"), &format!("{name}.lost"), why.as_bytes(), false)
            .map_err(|e| format!("recording vm {name} as lost: {e}").into())
    }

    /// What dead processes left: taps (a template build's too), cgroups, work
    /// directories and names. Only proof of death (`Liveness::Gone`) frees any.
    /// Taps belong here by alias, or name a run directory that no longer exists.
    /// Until this boot's recovery is complete, the dead VMs it withdraws are recorded as lost first.
    pub fn collect_garbage(&self) -> Result<Vec<Withdrawn>> {
        self.collect_garbage_with(!self.recovered(boot_id()))
    }

    fn collect_garbage_with(&self, lost: bool) -> Result<Vec<Withdrawn>> {
        // Deleted by index and name: a tap made since under a dead one's name is another.
        for (name, index, _owner) in dead_taps_at(&self.run, Path::new("/sys/class/net")) {
            crate::net::delete_link(index, &name);
        }
        collect_owned(&self.run);
        // What a write killed midway left of the per-boot records: unsynced-claim markers
        // (`RUN/claims`) and the generation cursor (`RUN/.gens.next`).
        remove_write_debris(&self.run.join("claims"), |_| true);
        remove_write_debris(&self.run, |n| n.starts_with("..gens.next."));
        let withdrawn = self.withdraw_dead(lost);
        // After the sweep of dead holders, whose claims took their published revisions with them.
        if let Err(e) = self.sweep_live() {
            crate::log!("garbage collection: {e}");
        }
        withdrawn
    }

    /// Addresses whose holder died without withdrawing them (SIGKILLed, or a
    /// panic): withdrawn as its `finish` would have, so a home host's loan ends
    /// and no peer keeps a route to this host. The peers are told by
    /// `deliver_withdrawals`, from a notice recorded first.
    /// Returns what it withdrew, as (VM name, address, generation). With `lost` (until this
    /// boot's recovery is complete), each is recorded as lost first (`record_lost`).
    fn withdraw_dead(&self, lost: bool) -> Result<Vec<Withdrawn>> {
        // Candidates first, without the host lock (records are replaced whole): a sweep takes it
        // only when a holder is proven dead, and each is decided again under it.
        let candidates: Vec<Ipv4Addr> = std::fs::read_dir(self.state.join("addrs"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<Ipv4Addr>().ok())
            .filter(|&ip| self.read_addr(ip).ok().and_then(|a| a.holder_id).is_some_and(|id| id.liveness() == Liveness::Gone))
            .collect();
        let (mut withdrawn, mut unrecorded) = (Vec::new(), None);
        if candidates.is_empty() {
            return Ok(withdrawn);
        }
        let l = self.lock()?;
        // What the migrations say, read whole or not at all: a record that cannot be read may be the one that
        // keeps an address (an outcome owed, `owe`; an arrival still pulling; a release cut short).
        let owed: HashSet<Ipv4Addr> = self.records::<Owed>("owed")?.into_iter().map(|(_, o)| o.ip).collect();
        let migs = self.records::<Mig>("migs")?;
        let pulling: Vec<Ident> = migs
            .iter()
            .filter_map(|(_, m)| match m {
                Mig::Pending { owner, .. } | Mig::Committed { owner } => Some(owner.clone()),
                Mig::Released { .. } => None,
            })
            .collect();
        let released: HashSet<(u64, Ipv4Addr)> = migs.iter().filter_map(|(id, m)| Some((*id, released_ip(m)?))).collect();
        for ip in candidates {
            let a = match self.addr(&l, ip) {
                Ok(a) if !owed.contains(&ip) => a,
                _ => continue,
            };
            let (name, gen) = (a.holder.as_deref().unwrap_or_default(), a.held);
            // A source that died mid-migration (its abort's resume included): what became of
            // the VM is its target's to say, as for a source killed while reconciling.
            if let (Some(left), Some(by)) = (a.leaving.as_ref(), a.holder_id.as_ref()) {
                // Its generation withdrawn or superseded: nothing is owed, the claim just goes (#570).
                if !a.current(gen) && self.dead_and_reaped(&a) {
                    match self.release(&l, ip, name, Some(by)) {
                        Ok(()) => crate::log!(
                            "vm {name} died as the source of migration {} to {}: {ip} generation {gen} is withdrawn or superseded, so nothing is owed",
                            left.mig,
                            left.to
                        ),
                        Err(e) => {
                            crate::log!("vm {name} died as the source of migration {}: letting go of its claim: {e}; retried on the next sweep", left.mig)
                        }
                    }
                } else if a.current(gen) && self.dead_and_reaped(&a) {
                    let owe = || {
                        self.owe(left.mig, &Owed { to: left.to.clone(), ip, gen, by: by.clone() })?;
                        self.release(&l, ip, name, Some(by))
                    };
                    match owe() {
                        Ok(()) => crate::log!(
                            "vm {name} died as the source of migration {} to {}: {ip} (generation {gen}) is owed until {} says what became of it",
                            left.mig,
                            left.to,
                            left.to
                        ),
                        Err(e) => crate::log!("vm {name} died as the source of migration {}: recording it as owed: {e}; retried on the next sweep", left.mig),
                    }
                }
                continue;
            }
            if !self.died_holding(&a, ip, &pulling, &released) {
                continue;
            }
            if let Err(e) = if lost { self.record_lost(name, ip, gen) } else { Ok(()) } {
                crate::log!("withdrawing {ip} (generation {gen}) of dead vm {name}: {e}; retried on the next sweep");
                unrecorded.get_or_insert(e);
                continue;
            }
            if let Err(e) = self.withdraw_noted(&l, ip, gen) {
                crate::log!("withdrawing {ip} (generation {gen}) of dead vm {name}: {e}; retried on the next sweep");
                continue;
            }
            crate::log!("withdrew {ip} (generation {gen}): vm {name}'s process died without withdrawing it");
            let _ = self.release(&l, ip, name, a.holder_id.as_ref());
            crate::net::unroute(ip);
            withdrawn.push((name.to_string(), ip, gen));
        }
        // A lost VM not recorded keeps the boot's recovery from completing: it is tried again.
        match unrecorded {
            Some(e) => Err(e),
            None => Ok(withdrawn),
        }
    }

    /// Withdraws `gen` of `ip` here (`observe`), a notice for the peers
    /// recorded first: the one way a withdrawal is made, so each reaches the
    /// peers (`deliver_withdrawals`) whatever dies or is down meanwhile.
    /// A notice of an older generation is replaced; a newer one is kept.
    /// A notice of the same generation and an older revision is replaced too.
    pub fn withdraw_noted(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> Result<bool> {
        let peers = self.config_now().peers;
        let path = self.notice_path(ip);
        let rev = self.withdrawal_rev(l, ip, gen);
        if !peers.is_empty() && load::<Notice>(&path).ok().flatten().is_none_or(|n| (n.gen, n.rev) < (gen, rev)) {
            let peers = peers.into_iter().map(|peer| Unheard { peer, tries: 0, next_ms: 0 }).collect();
            store(&path, &Notice { gen, rev, peers }, true)?;
        }
        self.observe(l, ip, gen, 0, None)
    }

    /// The latest revision of generation `gen` of `ip` here: the record's, or what the VM that
    /// held it published (`RUN/live/IP`, ahead of a record that trails, #533), dead or not.
    pub fn withdrawal_rev(&self, l: &Locked, ip: Ipv4Addr, gen: u64) -> u64 {
        let recorded = self.addr(l, ip).ok().filter(|a| a.seen == gen).map_or(0, |a| a.rev);
        let live = load::<Live>(&self.live_path(ip)).ok().flatten().filter(|v| v.gen == gen).map_or(0, |v| v.rev);
        recorded.max(live)
    }

    /// Migration `mig`'s outcome settled (`o`): a `leaving` claim of it by its
    /// source process goes, durably, before the evidence (the owed record, the
    /// target's) may.
    fn retire_leaving(&self, l: &Locked, o: &Owed, mig: u64) -> Result<()> {
        self.update(l, o.ip, true, |a| {
            if a.leaving.as_ref().is_some_and(|left| left.mig == mig) && a.holder_id.as_ref() == Some(&o.by) {
                (a.holder, a.holder_id, a.arriving, a.leaving) = (None, None, None, None);
            }
        })
    }

    /// Proven dead, with its Firecrackers reaped.
    fn dead_and_reaped(&self, a: &Addr) -> bool {
        a.holder_id.as_ref().is_some_and(|id| id.liveness() == Liveness::Gone) && !self.held(a)
    }

    /// Records in `STATE/DIR` by id (`ID`; anything else there, a write's
    /// temp file, is not one). An error if the directory, an entry or a
    /// record cannot be read: never a partial list.
    fn records<T: DeserializeOwned>(&self, dir: &str) -> Result<Vec<(u64, T)>> {
        let dir = self.state.join(dir);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => bail!("cannot read {}: {e}{REPAIR}", dir.display()),
        };
        let mut out = Vec::new();
        for e in entries {
            let e = e.map_err(|e| format!("cannot read {}: {e}{REPAIR}", dir.display()))?;
            let Some(id) = e.file_name().to_str().filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())).and_then(|n| n.parse().ok()) else {
                continue;
            };
            // Gone meanwhile (settled or retired): nothing to keep.
            if let Some(r) = load::<T>(&e.path()).map_err(|err| format!("cannot read {}: {err}{REPAIR}", e.path().display()))? {
                out.push((id, r));
            }
        }
        Ok(out)
    }

    /// Whether `a`'s holder is proven dead with its Firecrackers reaped and
    /// its VM with it, its generation still current. Not if a checkpoint here
    /// keeps the generation (suspended, or quarantined in this boot: a reboot shows
    /// whether it may resume, and an earlier boot's quarantine no longer holds, #556), nor if the VM may live on elsewhere: a source
    /// that may have handed it on (`leaving`: owed instead), an arrival whose source may run
    /// it again (`arriving`, or the holder owns a pending or committed
    /// record), or a loan of its generation here. An arrival whose record is
    /// released (its release cut short) is the holder's own VM, any loan of it
    /// here (it came home) included. A record without the instance is never proof.
    fn died_holding(&self, a: &Addr, ip: Ipv4Addr, pulling: &[Ident], released: &HashSet<(u64, Ipv4Addr)>) -> bool {
        let (Some(name), Some(id)) = (a.holder.as_deref(), a.holder_id.as_ref()) else { return false };
        let settled = a.arriving.is_some_and(|mig| released.contains(&(mig, ip)));
        a.leaving.is_none()
            && (a.arriving.is_none() || settled)
            && !pulling.contains(id)
            && a.current(a.held)
            && (settled || a.lent.is_none_or(|lent| lent < a.held))
            && self.dead_and_reaped(a)
            && self.suspended(name).is_ok_and(|d| !quarantined_now(&d))
    }

    fn notice_path(&self, ip: Ipv4Addr) -> PathBuf {
        self.state.join("withdrawals").join(ip.to_string())
    }

    /// Tells the peers of the withdrawals recorded (`withdraw_noted`), each
    /// peer until it answers. One that cannot be reached is asked again after
    /// its own backoff (doubling, up to `WITHDRAWAL_MAX_BACKOFF`, then that
    /// often for good): what was never asked goes first, so peers that are
    /// down never crowd out one that is up. A peer no longer configured is not asked.
    pub fn deliver_withdrawals(&self) {
        let _ = self.deliver_withdrawals_with(WITHDRAWAL_CALLS, wall_ms(), |peer, req| crate::vmproc::peer_call(peer, req.clone()).map(drop));
    }

    /// False if another process was delivering (it, or the next sweep, delivers these too).
    fn deliver_withdrawals_with(&self, budget: usize, now: u64, tell: impl Fn(&str, &serde_json::Value) -> Result<()> + Sync) -> bool {
        let Ok(lock) = private_file(&locks(&self.run).join("withdrawals")) else { return false };
        let Ok(_lock) = Flock::new(lock, libc::LOCK_EX | libc::LOCK_NB) else { return false };
        self.write_debris("withdrawals");
        let peers = self.config_now().peers;
        let notices: Vec<(Ipv4Addr, Notice)> = std::fs::read_dir(self.state.join("withdrawals"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<Ipv4Addr>().ok())
            .filter_map(|ip| Some((ip, load::<Notice>(&self.notice_path(ip)).ok()??)))
            .collect();
        // Due calls, the longest waiting (never asked: 0) first.
        let mut due: Vec<(u64, u32, Ipv4Addr, GenRev, String)> = notices
            .iter()
            .flat_map(|(ip, n)| {
                n.peers.iter().filter(|u| u.next_ms <= now && peers.contains(&u.peer)).map(|u| (u.next_ms, u.tries, *ip, (n.gen, n.rev), u.peer.clone()))
            })
            .collect();
        due.sort();
        due.truncate(budget);
        // At once: one slow or down peer holds up no other.
        let answers: Vec<(Ipv4Addr, GenRev, String, Result<()>)> = std::thread::scope(|scope| {
            let calls: Vec<_> = due
                .into_iter()
                .filter_map(|(_, _, ip, (gen, rev), peer)| {
                    let tell = &tell;
                    std::thread::Builder::new()
                        .spawn_scoped(scope, move || {
                            let r = tell(&peer, &serde_json::json!({"op": "route", "ip": ip.to_string(), "gen": gen, "rev": rev}));
                            (ip, (gen, rev), peer, r)
                        })
                        .inspect_err(|e| crate::log!("withdraw {ip}: cannot start peer call: {e}"))
                        .ok()
                })
                .collect();
            calls.into_iter().filter_map(|c| c.join().ok()).collect()
        });
        // Under the host lock, from the notice as it is now: a newer withdrawal recorded meanwhile is kept whole.
        let Ok(_l) = self.lock() else { return true };
        for (ip, _) in notices {
            let path = self.notice_path(ip);
            let Ok(Some(mut n)) = load::<Notice>(&path) else { continue };
            let before = n.clone();
            n.peers.retain(|u| {
                let kept = peers.contains(&u.peer);
                if !kept {
                    crate::log!("{ip} generation {} is withdrawn; {} is no longer a peer, so it is not told", n.gen, u.peer);
                }
                kept
            });
            for (_, _, peer, r) in answers.iter().filter(|a| a.0 == ip && a.1 == (n.gen, n.rev)) {
                let Some(i) = n.peers.iter().position(|u| &u.peer == peer) else { continue };
                match r {
                    Ok(()) => drop(n.peers.remove(i)),
                    Err(e) => {
                        let u = &mut n.peers[i];
                        u.tries += 1;
                        let backoff = withdrawal_backoff(u.tries);
                        u.next_ms = now + backoff;
                        // Once, as it reaches the cap.
                        if backoff == withdrawal_backoff(u32::MAX) && withdrawal_backoff(u.tries - 1) < backoff {
                            crate::log!(
                                "{ip} generation {} is withdrawn, but {peer} has not heard after {} tries ({e}): asked again every {} s; if {peer} lent {ip}, `flexvm reclaim {ip}` there frees it",
                                n.gen,
                                u.tries,
                                backoff / 1000
                            );
                        } else {
                            crate::log!("telling {peer} that {ip} generation {} is withdrawn: {e}; asked again in {} s", n.gen, backoff / 1000);
                        }
                    }
                }
            }
            if n.peers.is_empty() {
                let _ = crate::util::unlink_durably(&path);
            } else if n != before {
                if let Err(e) = store(&path, &n, true) {
                    crate::log!("withdrawal notice for {ip}: {e}");
                }
            }
        }
        true
    }
}

/// The address a released migration record names.
fn released_ip(m: &Mig) -> Option<Ipv4Addr> {
    match m {
        Mig::Released { ip, .. } => *ip,
        _ => None,
    }
}

/// A withdrawal of generation `gen` that `peers` have not heard yet (`STATE/withdrawals/IP`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Notice {
    gen: u64,
    /// The latest revision of `gen` here (the VM's, as it migrated in): a peer that routes `gen`
    /// via the host it had before takes the withdrawal by it (`listen::route`).
    #[serde(default)]
    rev: u64,
    peers: Vec<Unheard>,
}

/// A withdrawal's generation and revision.
type GenRev = (u64, u64);

/// A peer yet to hear a withdrawal: its failed tries, and the wall-clock ms before which it is not asked again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Unheard {
    peer: String,
    tries: u32,
    next_ms: u64,
}

/// Peer calls per delivery pass, and the backoff between a peer's tries (doubling, capped, never given up).
const WITHDRAWAL_CALLS: usize = 8;
const WITHDRAWAL_BACKOFF: Duration = Duration::from_secs(30);
const WITHDRAWAL_MAX_BACKOFF: Duration = Duration::from_secs(3600);

/// Before a peer's next try, after `tries` failed: none before the first.
fn withdrawal_backoff(tries: u32) -> u64 {
    match tries {
        0 => 0,
        t => (WITHDRAWAL_BACKOFF.as_millis() as u64).saturating_mul(1 << (t - 1).min(16)).min(WITHDRAWAL_MAX_BACKOFF.as_millis() as u64),
    }
}

const REPAIR: &str = "; no dead vm's address is withdrawn here until it is repaired or removed by hand (or the address taken back with `flexvm reclaim`)";

/// Notices outlive boots: wall-clock time.
fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
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
    if trusted_root(run).is_err() || trusted_dir(&run.join("w")).is_err() || trusted_dir(&run.join("vms")).is_err() {
        return;
    }
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
    let vms = run.join("vms");
    for e in std::fs::read_dir(locks(&vms)).into_iter().flatten().flatten() {
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
            let name = path.file_stem().unwrap_or_default();
            for ext in ["json", "sock"] {
                let _ = std::fs::remove_file(vms.join(format!("{}.{ext}", name.to_string_lossy())));
            }
            let _ = std::fs::remove_file(&path);
        }
    }
}

fn tap_prefix(state: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    // FNV-1a: stable across builds.
    let h = state.as_os_str().as_bytes().iter().fold(0xcbf29ce484222325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3));
    let digit = |i: u32| char::from_digit((h / 36u64.pow(i) % 36) as u32, 36).unwrap();
    std::iter::once('f').chain((0..5).map(digit)).collect()
}

/// Made up as docker does: an adjective and a scientist, one no VM here has.
pub fn generated_name(host: &Host) -> Result<String> {
    const ADJECTIVES: &[&str] = &[
        "admiring",
        "agitated",
        "amazing",
        "bold",
        "brave",
        "busy",
        "calm",
        "clever",
        "cool",
        "dazzling",
        "eager",
        "ecstatic",
        "elegant",
        "epic",
        "festive",
        "focused",
        "friendly",
        "gallant",
        "happy",
        "hopeful",
        "jolly",
        "keen",
        "kind",
        "laughing",
        "lucid",
        "magical",
        "modest",
        "nifty",
        "nostalgic",
        "optimistic",
        "peaceful",
        "pensive",
        "quirky",
        "relaxed",
        "serene",
        "sharp",
        "stoic",
        "tender",
        "trusting",
        "vibrant",
        "wizardly",
        "youthful",
        "zealous",
    ];
    const NAMES: &[&str] = &[
        "agnesi",
        "albattani",
        "babbage",
        "bardeen",
        "bell",
        "boole",
        "curie",
        "darwin",
        "dijkstra",
        "einstein",
        "euler",
        "faraday",
        "fermat",
        "fermi",
        "feynman",
        "galileo",
        "gauss",
        "goldberg",
        "hamilton",
        "hawking",
        "hopper",
        "hypatia",
        "johnson",
        "kepler",
        "knuth",
        "lamarr",
        "lovelace",
        "maxwell",
        "mccarthy",
        "meitner",
        "newton",
        "noether",
        "pascal",
        "ritchie",
        "shannon",
        "tesla",
        "thompson",
        "torvalds",
        "turing",
        "wiles",
        "wozniak",
        "yalow",
    ];
    for _ in 0..100 {
        let r = u64::from_str_radix(&crate::util::random_hex(8)?, 16).unwrap_or(0);
        let name = format!("{}_{}", ADJECTIVES[(r % ADJECTIVES.len() as u64) as usize], NAMES[((r >> 32) % NAMES.len() as u64) as usize]);
        let taken = host.alive(&name)
            || host.suspended(&name)?.exists()
            || ["failed", "lost", "moved"].iter().any(|ext| host.vms(&name, ext).is_ok_and(|p| p.exists()));
        if !taken {
            return Ok(name);
        }
    }
    bail!("could not make up a free name: give one with --name")
}

/// Whether `take_name` refused a name because a VM (running or stopped) holds it: a made-up
/// name is then made up again (`generated_name`), an explicit one is the caller's error.
pub fn name_taken(e: &crate::util::Error) -> bool {
    let e = e.to_string();
    e.contains("is taken") || e.contains("exists (stopped)")
}

pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 || name.starts_with('.') || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        bail!("bad vm name {name:?}: up to 64 letters, digits, '-', '_' or '.', not starting with '.'");
    }
    Ok(())
}

/// Where locks on what is in `dir` live: `dir/.locks`, a 0700 directory of root's.
/// Linux grants an exclusive flock through a read-only descriptor, so a lock any
/// user can open is one any user can hold. Readable files and directories are
/// never flocked themselves.
pub fn locks(dir: &Path) -> PathBuf {
    dir.join(LOCKS)
}

pub const LOCKS: &str = ".locks";

/// Only root or this user may change it: owned by one of them and not writable by group or others,
/// unless `sticky` allows a sticky directory (nobody else may rename what is ours out of it).
pub fn guarded(uid: u32, mode: u32, sticky: bool) -> bool {
    (uid == 0 || uid == unsafe { libc::geteuid() }) && (mode & 0o022 == 0 || (sticky && mode & libc::S_ISVTX != 0))
}

fn untrusted(path: &Path, why: &str) -> std::io::Error {
    std::io::Error::other(format!("{}: {why}", path.display()))
}

/// Host directories must never let another user plant records or replace subdirectories.
pub fn trusted_dir(path: &Path) -> std::io::Result<()> {
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_dir() || !guarded(m.uid(), m.mode(), false) {
        return Err(untrusted(path, "must be a real directory that only root or this user may write"));
    }
    Ok(())
}

/// A canonical `--state` or `--run`: trusted, and every directory above it up to `/` only root or this user
/// may change (sticky /tmp included), so nobody else may move it and put another tree in its place.
fn trusted_root(path: &Path) -> std::io::Result<()> {
    trusted_dir(path)?;
    for a in path.ancestors().skip(1) {
        let m = std::fs::symlink_metadata(a)?;
        if !guarded(m.uid(), m.mode(), true) {
            return Err(untrusted(a, "only root or this user may change the directories above host trees"));
        }
    }
    Ok(())
}

/// Make host directories with an explicit mode; existing unsafe ones are refused, never repaired.
pub fn host_dir(path: &Path, mode: u32) -> std::io::Result<()> {
    match std::fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            host_dir(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")), mode)?;
            return host_dir(path, mode);
        }
        Err(e) => return Err(e),
    }
    trusted_dir(path)
}

/// Direct host records (including markers), readable as before by non-root `ls`, never truncating a symlink's target.
pub fn write_record(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    File::options().write(true).create(true).truncate(true).mode(0o644).custom_flags(libc::O_NOFOLLOW).open(path)?.write_all(data)
}

/// A lock file, made (0600) if missing, in a directory only this user may enter,
/// made (0700) if missing: one that is not is refused, never repaired. Opened
/// relative to the directory as validated, so no swap of it reaches the open.
pub fn private_file(path: &Path) -> std::io::Result<File> {
    let (dir, name) = split(path)?;
    open_lock(&lock_dir(dir)?, name)
}

/// `path`'s directory and file name, as `lock_dir` and `open_lock` take them.
fn split(path: &Path) -> std::io::Result<(&Path, &std::ffi::OsStr)> {
    let name = path.file_name().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{}: no file name", path.display())))?;
    Ok((path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")), name))
}

pub fn private_dir(path: &Path) -> std::io::Result<()> {
    lock_dir(path).map(drop)
}

/// A directory only this user may enter (0700, its own; made if missing), opened
/// without following a link at its last component and checked through that
/// descriptor: locks are opened relative to it (`open_lock`).
pub fn lock_dir(path: &Path) -> std::io::Result<OwnedFd> {
    match std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let fd = crate::util::openat(libc::AT_FDCWD, &c, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
    let st = crate::util::stat_at(fd.as_raw_fd(), c"").ok_or_else(std::io::Error::last_os_error)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR || st.st_uid != unsafe { libc::geteuid() } || st.st_mode & 0o077 != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("{}: not a directory only this user may enter", path.display())));
    }
    Ok(fd)
}

/// `name` in `dir` (from `lock_dir`), made 0600 if missing, never through a link.
pub fn open_lock(dir: &OwnedFd, name: &std::ffi::OsStr) -> std::io::Result<File> {
    let c = std::ffi::CString::new(name.as_encoded_bytes())?;
    Ok(crate::util::openat(dir.as_raw_fd(), &c, libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW)?.into())
}

/// `name` in `dir` if it is there; never made.
pub fn existing_lock(dir: &OwnedFd, name: &std::ffi::OsStr) -> std::io::Result<File> {
    let c = std::ffi::CString::new(name.as_encoded_bytes())?;
    Ok(crate::util::openat(dir.as_raw_fd(), &c, libc::O_RDONLY | libc::O_NOFOLLOW)?.into())
}

/// The host's own lock directory, shared by every flexvm instance on it whatever its
/// `--state` and `--run`: for locks on what lies where other users may write (image and
/// template directories, a checkpoint's destination), each named for its target's (dev,
/// inode) (`keyed`). In `/run`, where only root makes entries.
pub fn host_locks() -> std::io::Result<OwnedFd> {
    #[cfg(not(test))]
    let root = PathBuf::from(HOST_LOCKS);
    #[cfg(test)]
    let root = std::env::temp_dir().join(format!("flexvm-locks-{}", unsafe { libc::geteuid() }));
    lock_dir(&root)
}

#[cfg_attr(test, allow(dead_code))]
pub const HOST_LOCKS: &str = "/run/flexvm-locks";

/// A host lock's name: `KIND-DEV-INO` of the directory `st` describes, then `rest`.
pub fn keyed(kind: &str, st: &libc::stat, rest: &str) -> String {
    format!("{kind}-{}-{}{rest}", st.st_dev, st.st_ino)
}

/// A directory opened once, for a lock keyed by it (`keyed`) and work in it: `path`
/// reaches it through the descriptor, whatever its own path names since, for this
/// process and its children.
pub struct Directory {
    pub fd: OwnedFd,
    pub path: PathBuf,
}

impl Directory {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let fd: OwnedFd = std::os::unix::fs::OpenOptionsExt::custom_flags(File::options().read(true), libc::O_DIRECTORY).open(path)?.into();
        Ok(Self { path: PathBuf::from(format!("/proc/{}/fd/{}", std::process::id(), fd.as_raw_fd())), fd })
    }

    pub fn stat(&self) -> std::io::Result<libc::stat> {
        crate::util::fstat(self.fd.as_raw_fd())
    }
}

/// A lock held and unlinked when dropped (then let go of explicitly): `lock_at`.
pub struct HeldLock {
    dir: OwnedFd,
    name: std::ffi::CString,
    file: File,
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0) };
        let _ = flock(&self.file, libc::LOCK_UN);
    }
}

/// `name` in `dir`, locked, and the file there still: a holder may unlink it just
/// before we lock (`HeldLock`), so retried until the one locked is the name's.
pub fn lock_at(dir: OwnedFd, name: &str, how: i32) -> std::io::Result<HeldLock> {
    lock_at_with(dir, name, |file| flock(file, how))
}

/// Like `lock_at`, with an interruptible or bounded acquisition.
pub fn lock_at_with(dir: OwnedFd, name: &str, take: impl Fn(&File) -> std::io::Result<()>) -> std::io::Result<HeldLock> {
    let file = acquire(&dir, name.as_ref(), take)?;
    Ok(HeldLock { name: std::ffi::CString::new(name)?, dir, file })
}

/// A shared hold on `name` in `dir` that, unlike `HeldLock`, leaves the file for the other
/// holders when let go. Whoever removes what it guards takes it exclusively with `lock_at` (whose
/// drop unlinks it), so a holder that locked the file it unlinked tries again on the new one.
pub fn shared_at(dir: &OwnedFd, name: &str) -> std::io::Result<Flock> {
    acquire(dir, name.as_ref(), |file| flock(file, libc::LOCK_SH)).map(Flock)
}

/// `name` in `dir` (made if missing), locked by `take`, and still the file the name links to:
/// a holder may unlink it just before we lock (`HeldLock`), so tried again on the new one.
fn acquire(dir: &OwnedFd, name: &std::ffi::OsStr, take: impl Fn(&File) -> std::io::Result<()>) -> std::io::Result<File> {
    let c = std::ffi::CString::new(name.as_encoded_bytes())?;
    loop {
        let file = open_lock(dir, name)?;
        take(&file)?;
        let (now, mine) = (crate::util::stat_at(dir.as_raw_fd(), &c), file.metadata()?);
        if now.is_some_and(|st| st.st_ino == mine.ino() && st.st_dev == mine.dev()) {
            return Ok(file);
        }
        let _ = flock(&file, libc::LOCK_UN);
    }
}

/// The use lock of the file or directory `st` describes (`shared_at` while used, `lock_at`
/// exclusively to remove it): image root filesystems and template generations.
pub fn use_lock(st: &libc::stat) -> String {
    keyed("use", st, "")
}

#[cfg(test)]
mod lock_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::Duration;

    #[test]
    fn shared_holds_keep_the_file_and_keep_out_an_exclusive_one() {
        let root = crate::test_util::TempDir::new("shared-at");
        let dir = lock_dir(&root.join("locks")).unwrap();
        let (a, b) = (shared_at(&dir, "k").unwrap(), shared_at(&dir, "k").unwrap());
        drop(a);
        assert!(root.join("locks/k").exists(), "a holder leaves the file to the others");
        let excl = |how| lock_at(lock_dir(&root.join("locks")).unwrap(), "k", how);
        assert_eq!(excl(libc::LOCK_EX | libc::LOCK_NB).err().map(|e| e.kind()), Some(std::io::ErrorKind::WouldBlock));
        drop(b);
        let held = excl(libc::LOCK_EX | libc::LOCK_NB).unwrap();
        drop(held);
        assert!(!root.join("locks/k").exists(), "the remover's drop unlinks it");
        drop(shared_at(&dir, "k").unwrap());
    }

    #[test]
    fn waiter_on_unlinked_lock_retries_the_current_inode() {
        let root = crate::test_util::TempDir::new("unlinked-waiter");
        let dir = root.join("locks");
        let first = lock_at(lock_dir(&dir).unwrap(), "key", libc::LOCK_EX).unwrap();
        let ((opened, opening), (resume, resumed), (finished, done)) = (mpsc::channel(), mpsc::channel(), mpsc::channel());
        let waiter_dir = dir.clone();
        let waiter = std::thread::spawn(move || {
            let first = AtomicBool::new(true);
            let held = lock_at_with(lock_dir(&waiter_dir).unwrap(), "key", |file| {
                if first.swap(false, Ordering::SeqCst) {
                    opened.send(()).unwrap();
                    resumed.recv().unwrap();
                }
                flock(file, libc::LOCK_EX)
            })
            .unwrap();
            finished.send(()).unwrap();
            held
        });
        opening.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(first);
        assert!(!dir.join("key").exists());
        let next = lock_at(lock_dir(&dir).unwrap(), "key", libc::LOCK_EX).unwrap();
        resume.send(()).unwrap();
        assert!(done.recv_timeout(Duration::from_millis(100)).is_err(), "waiter must contend on the replacement inode");
        drop(next);
        done.recv_timeout(Duration::from_secs(5)).unwrap();
        let held = waiter.join().unwrap();
        let current = std::fs::metadata(dir.join("key")).unwrap();
        assert_eq!(current.ino(), held.file.metadata().unwrap().ino());
        drop(held);
        assert!(!dir.join("key").exists());
    }
}

pub fn flock(f: &File, how: i32) -> std::io::Result<()> {
    crate::util::eintr(|| unsafe { libc::flock(f.as_raw_fd(), how) }).map(drop)
}

/// One blocked flock per lock file in this process, shared by every bounded wait for it
/// (`flock_by`): the helper thread waiting in it, how many callers wait on it now, and what it got.
#[derive(Default)]
struct FlockWait {
    waiters: usize,
    got: Option<std::io::Result<File>>,
}

static FLOCK_WAITS: Mutex<Option<HashMap<PathBuf, FlockWait>>> = Mutex::new(None);
static FLOCK_DONE: std::sync::Condvar = std::sync::Condvar::new();
#[cfg(test)]
static FLOCK_HELPERS: Mutex<Option<HashMap<PathBuf, usize>>> = Mutex::new(None);

/// The exclusive flock of the file at `path` (made if missing), had by `deadline` or refused
/// with `WouldBlock`. Waited for blocked, not polled: had as soon as the holder lets go, while
/// the caller still returns at the deadline. The blocking flock is a helper thread's, one per
/// file however many waits time out: a wait that finds one under way waits for the same, and
/// one that times out only stops waiting. Once the helper has the lock, a caller still waiting
/// takes it over; with none left it is let go of at once.
fn flock_by(path: &Path, deadline: std::time::Instant) -> std::io::Result<File> {
    let open = || private_file(path);
    let mut waits = FLOCK_WAITS.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let map = waits.get_or_insert_with(HashMap::new);
        match map.get_mut(path) {
            Some(w) if w.got.is_some() => {
                let got = map.remove(path).unwrap().got.unwrap();
                // This caller's count went with the entry; any other waiting starts again.
                FLOCK_DONE.notify_all();
                return got;
            }
            Some(_) => {}
            None => {
                let f = open()?;
                match flock(&f, libc::LOCK_EX | libc::LOCK_NB) {
                    Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => {}
                    r => return r.map(|()| f),
                }
                let key = path.to_path_buf();
                map.insert(key.clone(), FlockWait::default());
                #[cfg(test)]
                {
                    *FLOCK_HELPERS.lock().unwrap().get_or_insert_with(HashMap::new).entry(key.clone()).or_default() += 1;
                }
                let spawned = std::thread::Builder::new().name("flock-wait".into()).spawn(move || {
                    let got = flock(&f, libc::LOCK_EX).map(|()| f);
                    let mut waits = FLOCK_WAITS.lock().unwrap_or_else(|e| e.into_inner());
                    let map = waits.get_or_insert_with(HashMap::new);
                    match map.get_mut(&key) {
                        Some(w) if w.waiters > 0 => {
                            w.got = Some(got);
                            FLOCK_DONE.notify_all();
                        }
                        _ => {
                            map.remove(&key);
                            if let Ok(f) = got {
                                let _ = flock(&f, libc::LOCK_UN); // Unlocked, not only closed: see `Flock`.
                            }
                        }
                    }
                });
                if let Err(e) = spawned {
                    map.remove(path);
                    return Err(e);
                }
                continue;
            }
        }
        let left = deadline.checked_duration_since(std::time::Instant::now()).filter(|left| !left.is_zero());
        let Some(left) = left else { return Err(std::io::ErrorKind::WouldBlock.into()) };
        map.get_mut(path).unwrap().waiters += 1;
        waits = FLOCK_DONE.wait_timeout(waits, left).unwrap_or_else(|e| e.into_inner()).0;
        // Counted again on the next turn, if still waiting.
        if let Some(w) = waits.get_or_insert_with(HashMap::new).get_mut(path) {
            w.waiters -= 1;
        }
    }
}

/// Whether `f`'s lock can be had now (`how`, nonblocking), let go of at once
/// when it can: not left to the close, which a child forked meanwhile delays (see `Flock`).
pub fn probe(f: &File, how: i32) -> std::io::Result<()> {
    flock(f, how | libc::LOCK_NB)?;
    flock(f, libc::LOCK_UN)
}

/// A holder may unlink the file just before we lock: retry until it is the path's.
pub fn lock_path(path: &Path, how: i32) -> std::io::Result<File> {
    let (dir, name) = split(path)?;
    acquire(&lock_dir(dir)?, name, |f| flock(f, how))
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

/// Whether test hooks are on: FLEXVM_FAULTS=1.
pub fn faults_on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("FLEXVM_FAULTS").is_ok_and(|v| v == "1"))
}

/// Test faults (`RUN/faults.json`); only with FLEXVM_FAULTS=1.
pub fn fault(name: &str) -> bool {
    static CACHE: Mutex<Option<(SystemTime, HashMap<String, u64>)>> = Mutex::new(None);
    if !faults_on() {
        return false;
    }
    let Some(path) = RUN_DIR.get().map(|r| r.join("faults.json")) else { return false };
    let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    let mut c = CACHE.lock().unwrap();
    if c.as_ref().map(|c| Some(c.0)) != Some(mtime) {
        *c = mtime.map(|m| (m, load(&path).ok().flatten().unwrap_or_default()));
    }
    let now = wall_ms();
    c.as_ref().is_some_and(|(_, armed)| armed.get(name).is_some_and(|&until| now < until))
}

/// Test hook: MemAvailable (MiB) as a test wrote it to `RUN/mem_available_mib`, in place of the host's.
pub fn mem_available_override() -> Option<u64> {
    if !faults_on() {
        return None;
    }
    std::fs::read_to_string(RUN_DIR.get()?.join("mem_available_mib")).ok()?.trim().parse().ok()
}

/// Test hook: a window for a test to kill the process here.
pub fn stall(name: &str) {
    if tripped(name) {
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// Test hook: parks here while `name` is armed (its arming bounds the wait), until a test disarms it.
pub fn gate(name: &str) {
    tripped(name);
    while fault(name) {
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Test fault `name`, armed: also tells a test this process got there (`reached`), so it can tell the fault was hit.
pub fn tripped(name: &str) -> bool {
    let armed = fault(name);
    if armed {
        reached(name);
    }
    armed
}

/// Test hook: parks here, if `name` is armed when reached, until the test removes this process's
/// reached-marker (RUN/gates/NAME.PID; `rm -rf RUN/gates` releases every one), or for at most 10 minutes.
/// Neither the arming's expiry nor the host lock releases it: it parks under the lock too.
pub fn hold(name: &str) {
    if !tripped(name) {
        return;
    }
    let Some(marker) = RUN_DIR.get().map(|r| r.join("gates").join(format!("{name}.{}", std::process::id()))) else { return };
    let end = std::time::Instant::now() + Duration::from_secs(600);
    while marker.exists() && std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Test hook: tells a test this process got to `name` (RUN/gates/NAME.PID), so it acts there, not after a guessed delay.
fn reached(name: &str) {
    if let Some(dir) = RUN_DIR.get().map(|r| r.join("gates")) {
        let _ = host_dir(&dir, 0o700);
        let _ = write_record(&dir.join(format!("{name}.{}", std::process::id())), b"");
    }
}

pub fn arm(host: &Host, name: &str, ms: u64) -> Result<()> {
    let _l = host.lock()?;
    let path = host.run.join("faults.json");
    let mut armed: HashMap<String, u64> = load(&path).ok().flatten().unwrap_or_default();
    let now = wall_ms();
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

    #[test]
    fn cluster_defaults_are_visible_and_warn_with_peers() {
        let mut cfg = Config::default();
        assert_eq!(cfg.effective_cluster_ips(), cfg.vm_ips);
        assert!(cfg.cluster_warning().is_none());
        cfg.peers.push("192.0.2.7:7070".into());
        assert!(cfg.cluster_warning().unwrap().contains(&cfg.vm_ips));
        cfg.cluster_ips = Some("10.200.0.0/15".into());
        assert_eq!(cfg.effective_cluster_ips(), "10.200.0.0/15");
        assert!(cfg.cluster_warning().is_none());
    }

    #[test]
    fn invalid_ranges_are_refused_on_open_and_reload() {
        let (_dir, h) = host("invalid-ranges");
        let path = h.state.join("host.json");
        for (vm, cluster) in [("10.200.0.0/16", Some("10.201.0.0/16")), ("bad", None), ("10.200.0.0/16", Some("bad"))] {
            let cfg = Config { vm_ips: vm.into(), cluster_ips: cluster.map(String::from), ..Config::default() };
            store(&path, &cfg, true).unwrap();
            let e = Host::open(&h.state, &h.run).err().unwrap().to_string();
            assert!(e.contains("host.json") && e.contains("README: Configuration"), "{e}");
            assert_eq!(h.config_now().vm_ips, h.cfg.vm_ips);
            assert_eq!(h.config_now().cluster_ips, h.cfg.cluster_ips);
            // Fixed by hand, it opens again.
            store(&path, &Config::default(), true).unwrap();
            Host::open(&h.state, &h.run).unwrap();
        }
    }

    #[test]
    fn a_hand_edit_is_validated_whole() {
        let (_dir, h) = host("hand-edit");
        let path = h.state.join("host.json");
        let total = crate::util::proc_kb("/proc/meminfo", "MemTotal").unwrap() >> 20;
        for bad in [
            r#"{"peers": ["192.168.1.11"]}"#,
            r#"{"peers": ["a:1"], "peer_underlays": {"a:1": ["127.0.0.1"]}}"#,
            r#"{"peers": ["a:1"], "peer_underlays": {"a:1": ["224.0.0.1"]}}"#,
            r#"{"dns": "::1"}"#,
            r#"{"announce_dev": ""}"#,
            r#"{"vm_ip": "10.9.0.0/24"}"#,
            r#"{"reserve_mib": "x"}"#,
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(Host::open(&h.state, &h.run).is_err(), "{bad}");
        }
        std::fs::write(
            &path,
            r#"{"peers": ["a:1", "[2001:db8::2]:7070"], "peer_underlays": {"a:1": ["198.51.100.7"], "gone:1": ["198.51.100.8"]},
            "vm_ips": "10.9.0.0/24", "cluster_ips": "10.9.0.0/16", "dns": "1.1.1.1", "announce_dev": "none", "reserve_mib": 300, "evict_mib": 200}"#,
        )
        .unwrap();
        let c = Host::open(&h.state, &h.run).unwrap().cfg;
        assert_eq!((c.peers.len(), c.reserve_mib, c.announce_dev()), (2, Some(300), None));
        // A dropped peer's underlays are ignored, with a warning; so is an eviction mark under the reserve.
        assert!(c.underlays_of("gone:1").is_empty());
        let w = c.warnings().join("\n");
        assert!(w.contains("gone:1") && w.contains("under the 300 MiB reserve"), "{w}");
        std::fs::write(&path, format!(r#"{{"reserve_mib": {}}}"#, total + 1)).unwrap();
        assert!(Host::open(&h.state, &h.run).unwrap().cfg.warnings().join("").contains("every start is refused"));
    }

    #[test]
    fn peer_underlay_live_checks_only_warn() {
        let ip = "192.0.2.7".parse().unwrap();
        let mut cfg = Config::default();
        cfg.peer_underlays.insert("peer:7070".into(), vec![ip]);
        cfg.peers.push("peer:7070".into());
        let check = |local: std::result::Result<bool, &str>| {
            cfg.validate().unwrap();
            cfg.warnings_by(|a| {
                assert_eq!(a, ip);
                local.map_err(Into::into)
            })
            .join("\n")
        };
        assert!(!check(Ok(false)).contains("peer_underlays"));
        assert!(check(Ok(true)).contains("peer_underlays peer:7070: 192.0.2.7 is local"));
        assert!(check(Err("getifaddrs failed")).contains("cannot check whether 192.0.2.7 is local: getifaddrs failed"));
    }

    #[test]
    fn peer_underlay_content_is_checked_on_open_reload_and_write() {
        let (_dir, mut h) = host("underlay-validation");
        let path = h.state.join("host.json");
        let mut cfg = Config { peers: vec!["peer:7070".into()], ..Config::default() };
        cfg.peer_underlays.insert("peer:7070".into(), vec!["192.0.2.7".parse().unwrap()]);
        store(&path, &cfg, true).unwrap();
        Host::open(&h.state, &h.run).unwrap();
        assert_eq!(h.config_now().peer_underlays, cfg.peer_underlays);
        h.configure(|c| {
            c.peers = cfg.peers.clone();
            c.peer_underlays = cfg.peer_underlays.clone();
            Ok(())
        })
        .unwrap();
        for ip in ["0.0.0.0", "255.255.255.255", "224.0.0.1", "127.0.0.1"] {
            let mut bad = cfg.clone();
            bad.peer_underlays.insert("peer:7070".into(), vec![ip.parse().unwrap()]);
            store(&path, &bad, true).unwrap();
            assert!(Host::open(&h.state, &h.run).is_err(), "{ip}");
            assert_eq!(h.config_now().peer_underlays, cfg.peer_underlays);
            assert!(h.configure(|_| Ok(())).is_err(), "{ip}");
        }
    }

    #[test]
    fn saved_routes_recheck_peer_gateway_and_local_refusals() {
        let (_dir, mut h) = host("saved-route-check");
        h.cfg.cluster_ips = Some("0.0.0.0-255.255.255.255".into());
        h.cfg.peers = vec!["192.0.2.7:7070".into(), "10.9.5.1:7070".into()];
        let via = ip("192.0.2.7");
        assert!(h.route_allowed(ip("10.9.5.2"), via));
        for dest in [ip("10.9.5.1"), ip("127.0.0.1")] {
            assert!(!h.route_allowed(dest, via));
            h.put_addr(dest, &Addr { seen: 3, via: Some(via), ..Addr::default() }, true).unwrap();
            assert!(!h.reinstall(&h.lock().unwrap(), dest, None).unwrap());
        }
        for gateway in crate::net::gateways(&std::fs::read_to_string("/proc/net/route").unwrap()) {
            assert!(!h.route_allowed(gateway, via));
        }
        assert!(!h.route_allowed(ip("10.9.5.2"), ip("192.0.2.99")));
    }

    #[test]
    fn locks_are_in_directories_only_root_may_enter() {
        use std::os::unix::fs::PermissionsExt;
        let (_root, h) = host("private-locks");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        drop(h.lock().unwrap());
        let name = h.take_name("private", false).unwrap();
        drop(h.logs_lock(libc::LOCK_SH).unwrap());
        drop(h.worker_flock().unwrap());
        for lock in
            [h.lock_file(), locks(&h.state).join("open"), h.vms("private", "lock").unwrap(), locks(&h.run).join("logs"), locks(&h.state).join("evict.worker")]
        {
            assert_eq!(mode(lock.parent().unwrap()), 0o700, "{}", lock.display());
            assert_eq!(mode(&lock), 0o600, "{}", lock.display());
        }
        // An old layout's files are never used: a lock held on one blocks nothing.
        let old = h.state.join("lock");
        std::fs::write(&old, b"").unwrap();
        let _old = Flock::new(File::open(&old).unwrap(), libc::LOCK_EX).unwrap();
        // Probe this host's file directly: lock_by also waits on THREADS, which
        // unrelated tests' host locks may hold past its deadline (#633).
        drop(lock_path(&h.lock_file(), libc::LOCK_EX | libc::LOCK_NB).unwrap());
        drop(name);
    }

    #[test]
    fn a_lock_directory_another_user_could_enter_is_refused_not_repaired() {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::test_util::TempDir::new("open-locks");
        let dir = locks(&root);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(private_file(&dir.join("x")).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o755);
        assert!(!dir.join("x").exists());
    }

    /// A lock directory swapped for a link after it was checked is not followed: locks
    /// are opened relative to the descriptor checked, and a link in its place is refused.
    #[test]
    fn a_lock_directory_swapped_after_its_check_is_not_followed() {
        let root = crate::test_util::TempDir::new("swapped-locks");
        let (dir, moved, theirs) = (locks(&root), root.join("moved"), root.join("theirs"));
        let checked = lock_dir(&dir).unwrap();
        std::fs::rename(&dir, &moved).unwrap();
        std::fs::create_dir(&theirs).unwrap();
        std::os::unix::fs::symlink(&theirs, &dir).unwrap();
        drop(open_lock(&checked, "x".as_ref()).unwrap());
        assert!(moved.join("x").exists() && !theirs.join("x").exists(), "opened where it was checked");
        assert!(private_file(&dir.join("y")).is_err() && !theirs.join("y").exists(), "a link is never a lock directory");
        assert!(lock_path(&dir.join("z"), libc::LOCK_EX).is_err() && !theirs.join("z").exists());
    }

    #[test]
    fn readers_can_open_and_list_without_access_to_lock_inodes() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (_root, h) = host("readonly-locks");
        let name = h.take_name("visible", false).unwrap();
        name.publish(&Entry { name: "visible".into(), ident: Ident::me(), ..Entry::default() }).unwrap();
        // As another user sees them: the lock directories closed.
        let closed = [locks(&h.state), locks(&h.run.join("vms"))];
        for d in &closed {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let reopened = Host::open(&h.state, &h.run);
        let listed = reopened.as_ref().map(|r| r.entries().iter().map(|e| e.name.clone()).collect::<Vec<_>>());
        let refused = reopened.as_ref().map(|r| r.entry("visible").is_err());
        for d in &closed {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_eq!(listed.unwrap(), ["visible"]);
        assert!(refused.unwrap(), "operations still require the private lock");
        drop(name);
    }

    #[test]
    fn locking_the_readable_state_directory_does_not_block_open() {
        let (_root, h) = host("directory-flock");
        let _held = Flock::new(File::open(&h.state).unwrap(), libc::LOCK_EX).unwrap();
        Host::open(&h.state, &h.run).unwrap();
    }

    #[test]
    fn name_paths_refuse_bad_names() {
        let (_base, h) = host("name-paths");
        for name in ["../x", "../../var/run/docker", "a/b", "/etc/passwd", "", ".", "..", ".lock", "x\0y"] {
            assert!(h.sock(name).is_err() && h.vms(name, "lock").is_err() && h.suspended(name).is_err(), "{name:?}");
            assert!(!h.alive(name) && !h.is_suspended(name) && h.entry(name).is_err(), "{name:?}");
        }
        assert_eq!(h.sock("web.1").unwrap(), h.run.join("vms/web.1.sock"));
        assert_eq!(h.suspended("web.1").unwrap(), h.state.join("suspended/web.1"));
    }

    fn host(tag: &str) -> (crate::test_util::TempDir, Host) {
        let base = crate::test_util::TempDir::new(&format!("host-{tag}"));
        let mut h = Host::open(&base.join("state"), &base.join("run")).unwrap();
        h.cfg.vm_ips = "10.9.0.1-10.9.0.3".into();
        (base, h)
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn host_refuses_unsafe_directories() {
        let (_base, h) = host("unsafe-dirs");
        let dirs = [h.state.clone(), h.run.clone()]
            .into_iter()
            .chain(["addrs", "standby", "migs", "owed", "withdrawals", "suspended", LOCKS].map(|d| h.state.join(d)))
            .chain(["w", "vms", "standby", "claims", "live"].map(|d| h.run.join(d)));
        for path in dirs {
            let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
            for unsafe_mode in [0o777, 0o775, 0o757] {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(unsafe_mode)).unwrap();
                assert!(Host::open(&h.state, &h.run).is_err(), "{}", path.display());
                assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, unsafe_mode, "never repair an unsafe directory");
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        // Deeper directories are not walked per command: they are checked where used (`reap`).
        let nested = h.run.join("w/old/0");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(&h.state, h.run.join("w/link")).unwrap();
        Host::open(&h.state, &h.run).unwrap();
        let claims = h.run.join("claims");
        std::fs::remove_dir(&claims).unwrap();
        std::os::unix::fs::symlink(h.run.join("missing"), &claims).unwrap();
        assert!(Host::open(&h.state, &h.run).is_err(), "a dangling trusted directory link is refused");
        std::fs::remove_file(claims).unwrap();
        Host::open(&h.state, &h.run).unwrap();
    }

    #[test]
    fn only_root_or_this_user_may_change_host_trees() {
        let me = unsafe { libc::geteuid() };
        for (uid, mode, sticky, ok) in [
            (me, 0o755, false, true),
            (0, 0o755, false, true),
            (0, 0o1777, true, true),
            (0, 0o1777, false, false),
            (0, 0o777, true, false),
            (me, 0o775, false, false),
            (me, 0o757, false, false),
            (u32::MAX - 1, 0o700, true, false),
        ] {
            assert_eq!(guarded(uid, mode, sticky), ok, "{uid} {mode:o} {sticky}");
        }
        // A linked root is followed, as before: its target is what is checked.
        let base = crate::test_util::TempDir::new("linked-root");
        std::fs::create_dir(base.join("real")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("state")).unwrap();
        assert_eq!(Host::open(&base.join("state"), &base.join("run")).unwrap().state, base.join("real").canonicalize().unwrap());
    }

    #[test]
    fn every_directory_above_a_root_is_checked() {
        let base = crate::test_util::TempDir::new("ancestry");
        let (above, box_) = (base.join("above"), base.join("above/box"));
        std::fs::create_dir_all(&box_).unwrap();
        let open = || Host::open(&box_.join("state"), &box_.join("run"));
        let h = open().unwrap();
        // Another user who may write above could move `box` away and put a fabricated tree there.
        std::fs::set_permissions(&above, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(open().err().unwrap().to_string().contains("above host trees"));
        assert!(reap(&h.run, &Ident { pid: 999999932, start: 1, boot: boot_id().into() }).is_err(), "nor reaped through");
        // Sticky (like /tmp): nobody else may rename what is ours.
        std::fs::set_permissions(&above, std::fs::Permissions::from_mode(0o1777)).unwrap();
        open().unwrap();
    }

    #[test]
    fn the_synced_marker_is_the_canonical_roots() {
        let base = crate::test_util::TempDir::new("synced-link");
        for d in ["one", "two"] {
            std::fs::create_dir(base.join(d)).unwrap();
        }
        let link = base.join("state");
        for d in ["one", "two"] {
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(base.join(d), &link).unwrap();
            let h = Host::open(&link, &base.join(format!("run-{d}"))).unwrap();
            let m = std::fs::metadata(base.join(d)).unwrap();
            assert_eq!(h.state, base.join(d).canonicalize().unwrap());
            assert_eq!(std::fs::read_to_string(base.join(d).join(".synced")).unwrap(), format!("{} {}", m.dev(), m.ino()));
        }
    }

    #[test]
    fn host_directories_have_explicit_modes() {
        const MASK: &str = "FLEXVM_TEST_HOST_UMASK";
        if let Ok(mask) = std::env::var(MASK) {
            unsafe { libc::umask(mask.parse().unwrap()) };
        } else {
            // umask is process-wide: keep other tests out of these changes.
            for mask in [0, 0o077] {
                assert!(std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "host::tests::host_directories_have_explicit_modes"])
                    .env(MASK, mask.to_string())
                    .status()
                    .unwrap()
                    .success());
            }
            return;
        }
        let (_base, h) = host("dir-modes");
        for path in [h.state.clone(), h.run.clone(), h.state.join("addrs"), h.state.join("migs"), h.run.join("w"), h.run.join("vms")] {
            assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o755);
        }
        assert_eq!(std::fs::metadata(h.state.join("suspended")).unwrap().mode() & 0o777, 0o700);
        let record = h.state.join("addrs/record");
        store(&record, &Ident::me(), false).unwrap();
        for path in [record, h.run.join("state.json"), h.state.join("run.json")] {
            assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o022, 0);
        }
    }

    #[test]
    fn records_do_not_follow_symlinks() {
        let (base, h) = host("record-links");
        let victim = base.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        for name in ["vm.failed", "vm.moved", "vm.log", ".marker"] {
            let path = h.run.join("vms").join(name);
            std::os::unix::fs::symlink(&victim, &path).unwrap();
            assert!(write_record(&path, b"replace").is_err());
            assert!(load::<Ident>(&path).is_err());
            assert!(!crate::util::output::append_capped(&path, b"append", 100));
        }
        let tmp = h.run.join(format!(".record.{}.tmp", crate::util::write_tag()));
        std::os::unix::fs::symlink(&victim, tmp).unwrap();
        assert!(crate::util::write_file(&h.run, "record", b"replace", false).is_err());
        assert_eq!(std::fs::read_to_string(victim).unwrap(), "keep");
    }

    #[test]
    fn reap_refuses_untrusted_work_records() {
        let (_base, h) = host("reap-unsafe");
        let child = Sleeper::new();
        let dead = dead_owner(&h, 999999931, &[&child.1]);
        let dir = dead.work_dir(&h.run).join("0");
        for path in [h.run.clone(), h.run.join("w"), dead.work_dir(&h.run), dir.clone()] {
            let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
            assert!(reap(&h.run, &dead).is_err());
            collect_owned(&h.run);
            assert!(child.1.alive());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let fc = dir.join("fc");
        // A record another user may write could be rewritten to name any process.
        for mode in [0o666, 0o664] {
            std::fs::set_permissions(&fc, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(reap(&h.run, &dead).is_err());
            collect_owned(&h.run);
            assert!(child.1.alive());
        }
        std::fs::set_permissions(&fc, std::fs::Permissions::from_mode(0o644)).unwrap();
        let outside = h.run.join("outside");
        std::fs::rename(&fc, &outside).unwrap();
        std::os::unix::fs::symlink(outside, &fc).unwrap();
        assert!(reap(&h.run, &dead).is_err());
        assert!(!child.done(), "a symlinked identity must never authorize SIGKILL");
    }

    #[test]
    fn state_is_bound_to_one_run_directory() {
        let (base, h) = host("run-binding");
        let other = base.join("other-run");
        let e = Host::open(&h.state, &other).err().unwrap().to_string();
        assert!(
            e.contains("is bound to run directory")
                && e.contains(h.state.to_str().unwrap())
                && e.contains(h.run.to_str().unwrap())
                && e.contains(other.to_str().unwrap()),
            "{e}"
        );
        // A different state root can still have its own run directory on this machine.
        Host::open(&base.join("other-state"), &other).unwrap();
        // Canonical paths accept aliases of the same pair.
        let alias = base.join("alias");
        std::os::unix::fs::symlink(&*base, &alias).unwrap();
        Host::open(&alias.join("state"), &alias.join("run")).unwrap();
        // The path binding survives removal of tmpfs contents (for example, a reboot).
        std::fs::remove_dir_all(&h.run).unwrap();
        Host::open(&h.state, &h.run).unwrap();
    }

    #[test]
    fn run_directory_belongs_to_one_state() {
        let (base, h) = host("run-owner");
        let other = base.join("other-state");
        let e = Host::open(&other, &h.run).err().unwrap().to_string();
        assert!(
            e.contains("belongs to state directory")
                && e.contains(h.run.to_str().unwrap())
                && e.contains(h.state.to_str().unwrap())
                && e.contains(other.to_str().unwrap())
                && e.contains("state.json to rebind"),
            "{e}"
        );
        // The refused state is not bound to the run directory it was refused.
        assert!(!other.join("run.json").exists());
        // Once the owner is gone (a reboot empties tmpfs), STATE/run.json still binds the first state.
        std::fs::remove_file(h.run.join("state.json")).unwrap();
        Host::open(&h.state, &h.run).unwrap();
        assert!(Host::open(&other, &h.run).is_err());
    }

    #[test]
    fn racing_states_claim_a_run_directory_once() {
        let base = crate::test_util::TempDir::new("host-run-race");
        let run = base.join("run");
        std::fs::create_dir(&run).unwrap();
        let opened: Vec<bool> = std::thread::scope(|s| {
            let opens: Vec<_> = (0..8)
                .map(|i| {
                    let (state, run) = (base.join(format!("state{i}")), run.clone());
                    s.spawn(move || Host::open(&state, &run).is_ok())
                })
                .collect();
            opens.into_iter().map(|t| t.join().unwrap()).collect()
        });
        assert_eq!(opened.iter().filter(|o| **o).count(), 1, "{opened:?}");
        assert!(std::fs::read_dir(&run).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
    }

    #[test]
    fn invalid_run_binding_is_not_replaced() {
        let (_base, h) = host("run-binding-invalid");
        let binding = h.state.join("run.json");
        std::fs::write(&binding, "").unwrap();
        let e = Host::open(&h.state, &h.run).err().unwrap().to_string();
        assert!(e.contains(binding.to_str().unwrap()), "{e}");
        assert_eq!(std::fs::read(&binding).unwrap(), b"");
    }

    #[test]
    fn an_unwritable_state_opens_unbound() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (_base, h) = host("run-binding-readonly");
        let binding = h.state.join("run.json");
        std::fs::remove_file(&binding).unwrap();
        let mode = |m| std::fs::set_permissions(&h.state, std::fs::Permissions::from_mode(m)).unwrap();
        mode(0o555);
        let result = Host::open(&h.state, &h.run);
        mode(0o755);
        result.unwrap();
        assert!(!binding.exists());
        // Likewise a run directory it cannot write.
        std::fs::remove_file(h.run.join("state.json")).unwrap();
        let mode = |m| std::fs::set_permissions(&h.run, std::fs::Permissions::from_mode(m)).unwrap();
        mode(0o555);
        let result = Host::open(&h.state, &h.run);
        mode(0o755);
        result.unwrap();
        assert!(!h.run.join("state.json").exists());
        // An unbound state is not bound to a run directory it could not claim, and one another state
        // claimed is refused though it cannot be written.
        let other = h.state.with_file_name("other-state");
        mode(0o555);
        let unclaimed = Host::open(&other, &h.run).map(|_| ());
        mode(0o755);
        unclaimed.unwrap();
        assert!(!other.join("run.json").exists());
        std::fs::write(h.run.join("state.json"), serde_json::to_vec(&h.state).unwrap()).unwrap();
        mode(0o555);
        let refused = Host::open(&other, &h.run).map(|_| ());
        mode(0o755);
        assert!(refused.err().unwrap().to_string().contains("belongs to state directory"));
        assert!(!other.join("run.json").exists());
    }

    #[test]
    fn run_directory_creation_errors_name_the_path() {
        use std::os::unix::fs::PermissionsExt;

        let (_h_dir, h) = host("run-error");
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
        let (_h_dir, h) = host("synced");
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
        // A peer elsewhere whose address is unknown: nothing derived.
        let peers = vec!["flexvm-no-such-host.invalid:7070".into()];
        let cfg = |listen: Option<&str>, underlay: Option<&str>| Config {
            listen: listen.map(String::from),
            underlay: underlay.map(ip),
            peers: peers.clone(),
            ..Config::default()
        };
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
        let (_h_dir, h) = host("names");
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
        std::fs::create_dir_all(h.suspended("s").unwrap()).unwrap();
        std::fs::write(h.suspended("s").unwrap().join("manifest.json"), "").unwrap();
        assert!(h.take_name("s", false).is_err() && h.take_name("s", true).is_ok());
    }

    #[test]
    fn suspend_debris_is_removed_by_the_names_next_holder() {
        let (_h_dir, h) = host("debris");
        let dir = |n: &str, files: &[&str]| {
            std::fs::create_dir_all(h.suspended(n).unwrap()).unwrap();
            files.iter().for_each(|f| std::fs::write(h.suspended(n).unwrap().join(f), "").unwrap());
        };
        // No manifest (an interrupted removal or revoke), consumed, discarded.
        dir("bare", &["GEN", "pages"]);
        dir("started", &["manifest.json", "STARTED"]);
        dir("discarded", &["manifest.json", "DISCARDED"]);
        dir("quarantined", &["manifest.json", "STARTED", "QUARANTINE"]);
        for n in ["bare", "started", "discarded", "quarantined"] {
            assert!(!h.is_suspended(n));
            drop(h.take_name(n, false).unwrap());
            assert!(!h.suspended(n).unwrap().exists(), "{n}");
        }
        // A suspended VM, quarantined or not, stays.
        dir("kept", &["manifest.json"]);
        dir("held", &["manifest.json", "QUARANTINE"]);
        for n in ["kept", "held"] {
            assert!(h.is_suspended(n) && h.take_name(n, false).is_err());
            drop(h.take_name(n, true).unwrap());
            assert!(h.suspended(n).unwrap().exists());
        }
        // Held by a live process, it is not touched.
        let _live = h.take_name("live", true).unwrap();
        dir("live", &["GEN"]);
        assert!(h.take_name("live", false).is_err() && h.suspended("live").unwrap().exists());
    }

    #[test]
    fn a_dead_holders_firecrackers_die_before_its_name_or_address_is_free() {
        let (_h_dir, h) = host("reap");
        let fc = Sleeper::new();
        let dead = dead_owner(&h, 999_999_901, &[&fc.1]);
        store(&h.vms("d", "lock").unwrap(), &dead, false).unwrap();
        let l = h.lock().unwrap();
        h.put_addr(ip("10.9.0.1"), &Addr { seen: 1, holder: Some("d".into()), holder_id: Some(dead), held: 1, ..Addr::default() }, false).unwrap();
        assert!(fc.1.alive());
        assert!(h.claim_new(&l, "x", Some(ip("10.9.0.1"))).unwrap().gen > 1 && fc.done());
        let fc = Sleeper::new();
        store(&h.vms("e", "lock").unwrap(), &dead_owner(&h, 999_999_902, &[&fc.1]), false).unwrap();
        let _e = h.take_name("e", false).unwrap();
        assert!(fc.done());
        let fc = Sleeper::new();
        dead_owner(&h, 999_999_903, &[&fc.1]);
        reap(&h.run, &Ident { pid: 999_999_903, start: 2, boot: boot_id().into() }).unwrap();
        assert!(!fc.done());
        // A killed holder's name is let go of by the garbage collector; a live one's is not.
        let fc = Sleeper::new();
        store(&h.vms("k", "lock").unwrap(), &dead_owner(&h, 999_999_904, &[&fc.1]), false).unwrap();
        std::fs::write(h.vms("k", "failed").unwrap(), "why").unwrap();
        collect_owned(&h.run);
        assert!(fc.done() && !h.vms("k", "lock").unwrap().exists() && h.vms("k", "failed").unwrap().exists());
        assert!(h.vms("e", "lock").unwrap().exists());
    }

    #[test]
    fn addresses_generations_and_loans() {
        let (_h_dir, h) = host("addrs");
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
        h.lend(&l, a_ip, g1, 1, "t").unwrap();
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
        // After a reboot (the cursor another boot's), generations go on from the mark.
        std::fs::write(h.state.join("addrs/.gens"), r#"{"next": 7, "reserved": 2048, "boot": "other"}"#).unwrap();
        std::fs::write(h.run.join(".gens.next"), r#"{"next": 9, "reserved": 0, "boot": "other"}"#).unwrap();
        assert!(h.claim_new(&l, "z", None).unwrap().gen >= 2048);
        std::fs::write(h.state.join("addrs/.gens"), "x").unwrap();
        assert!(h.claim_new(&l, "z", None).is_err());
    }

    /// #554: the cursor and a start's record are written without fsync; after a power loss
    /// either may be empty, and neither may stop a start or reuse a generation.
    #[test]
    fn unsynced_records_come_back_empty() {
        let (_dir, h) = host("unsynced");
        let gone = dead_owner(&h, 999_999_991, &[]);
        let l = h.lock().unwrap();
        let x = ip("10.9.0.1");
        let first = h.claim_new(&l, "a", Some(x)).unwrap();
        let gen = first.gen;
        first.keep();
        let gens = || load::<Gens>(&h.gens_path()).unwrap().unwrap();
        // Starts within the block leave the mark alone.
        let mark = gens().reserved;
        assert_eq!(h.next_gen(0).unwrap(), gen + 1);
        assert_eq!(gens().reserved, mark);
        for cursor in ["", "{"] {
            let mark = gens().reserved;
            std::fs::write(h.run.join(".gens.next"), cursor).unwrap();
            assert_eq!(h.next_gen(0).unwrap(), mark);
        }
        // A mark renamed in by a process that died before its directory fsync: the cursor,
        // written under the old one, is not trusted, and a new mark is synced above it.
        let ahead = gens().reserved + 5000;
        store(&h.gens_path(), &Gens { next: 1, reserved: ahead, boot: boot_id().into() }, false).unwrap();
        assert_eq!(h.next_gen(0).unwrap(), ahead);
        assert!(gens().reserved > ahead);
        let mark = gens().reserved;
        // Emptied in this boot, its VM may still run.
        std::fs::write(h.addr_path(x), "").unwrap();
        assert!(h.addr(&l, x).is_err() && h.claim_new(&l, "b", Some(x)).is_err());
        // From an earlier boot: its marker is another boot's, or gone with RUN.
        std::fs::write(h.unsynced_marker(x), "other").unwrap();
        assert!(h.addr(&l, x).unwrap().withdrawn);
        std::fs::remove_file(h.unsynced_marker(x)).unwrap();
        let a = h.addr(&l, x).unwrap();
        assert!(a.seen == mark && a.withdrawn && a.holder.is_none() && a.lent.is_none());
        assert!(!h.observe(&l, x, gen, 0, Some(ip("192.0.2.1"))).unwrap(), "its old generation is stale");
        assert!(!h.owes(&gone));
        drop(l);
        h.withdraw_dead(false).unwrap();
        store(&h.mig_path(3), &Mig::Pending { owner: gone, ip: Some(x) }, false).unwrap();
        assert_eq!(h.mig_status(3).unwrap(), "aborted");
        let l = h.lock().unwrap();
        let c = h.claim_new(&l, "b", Some(x)).unwrap();
        assert!(c.gen > mark && h.unsynced_marker(x).exists());
        // A durable write (here the release) supersedes the unsynced one, and its marker goes.
        c.release(&l).unwrap();
        assert!(!h.unsynced_marker(x).exists());
        // Without a mark nothing bounds it.
        std::fs::write(h.addr_path(ip("10.9.0.2")), "").unwrap();
        std::fs::remove_file(h.gens_path()).unwrap();
        assert!(h.addr(&l, ip("10.9.0.2")).is_err());
    }

    #[test]
    fn an_address_is_held_by_the_instance_that_claimed_it() {
        let (_h_dir, h) = host("instances");
        let (x, y) = (ip("10.9.0.1"), ip("10.9.0.2"));
        // `web` SIGKILLed at x (its Firecracker still running), and an earlier crash's claim at y.
        let fc = Sleeper::new();
        let dead = dead_owner(&h, 999_999_911, &[&fc.1]);
        store(&h.vms("web", "lock").unwrap(), &dead, false).unwrap();
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
        std::fs::create_dir_all(h.suspended("s").unwrap()).unwrap();
        std::fs::write(h.suspended("s").unwrap().join("manifest.json"), "").unwrap();
        let gone = Ident { pid: 999_999_913, ..dead };
        h.put_addr(x, &Addr { seen: 5, holder: Some("s".into()), holder_id: Some(gone), held: 5, ..Addr::default() }, false).unwrap();
        assert_eq!(h.holder(&l, x).unwrap().as_deref(), Some("s"), "quarantined (no GEN): kept");
        std::fs::write(h.suspended("s").unwrap().join("GEN"), "5").unwrap();
        assert_eq!(h.holder(&l, x).unwrap().as_deref(), Some("s"));
        std::fs::write(h.suspended("s").unwrap().join("GEN"), "6").unwrap();
        assert_eq!(h.holder(&l, x).unwrap(), None, "suspended with another address");
    }

    #[test]
    fn a_dead_holders_address_is_withdrawn_unless_its_vm_may_live_on() {
        let (_h_dir, h) = host("withdraw-dead");
        let l = h.lock().unwrap();
        let dead = |pid| dead_owner(&h, pid, &[]);
        let claim = |ip: Ipv4Addr, name: &str, id: Option<Ident>, gen: u64, change: &dyn Fn(&mut Addr)| {
            let mut a = Addr { seen: gen, holder: Some(name.into()), holder_id: id, held: gen, ..Addr::default() };
            change(&mut a);
            h.put_addr(ip, &a, false).unwrap();
        };
        let ips: Vec<Ipv4Addr> = (1..=10).map(|i| ip(&format!("10.9.1.{i}"))).collect();
        // SIGKILLed or panicked after a migration here: withdrawn.
        claim(ips[0], "killed", Some(dead(999_999_931)), 4, &|_| ());
        // An arrival still pulling (its source runs again), its record gone or unknown here.
        claim(ips[1], "arriving", Some(dead(999_999_932)), 4, &|a| a.arriving = Some(77));
        // Lent with its generation (a source at home whose outcome is not settled).
        claim(ips[2], "lent", Some(dead(999_999_933)), 4, &|a| a.lent = Some(4));
        // Given out again, or already withdrawn.
        claim(ips[3], "superseded", Some(dead(999_999_934)), 4, &|a| a.seen = 5);
        claim(ips[4], "withdrawn", Some(dead(999_999_935)), 4, &|a| a.withdrawn = true);
        // Suspended here with its generation; quarantined after a resume that may have run.
        claim(ips[5], "suspended", Some(dead(999_999_936)), 4, &|_| ());
        std::fs::create_dir_all(h.suspended("suspended").unwrap()).unwrap();
        std::fs::write(h.suspended("suspended").unwrap().join("manifest.json"), "").unwrap();
        std::fs::write(h.suspended("suspended").unwrap().join("GEN"), "4").unwrap();
        claim(ips[6], "quarantined", Some(dead(999_999_937)), 4, &|_| ());
        std::fs::create_dir_all(h.suspended("quarantined").unwrap()).unwrap();
        for f in ["manifest.json", "GEN", "STARTED"] {
            std::fs::write(h.suspended("quarantined").unwrap().join(f), "4").unwrap();
        }
        let quarantine = h.suspended("quarantined").unwrap().join("QUARANTINE");
        std::fs::write(&quarantine, format!("{} the mark may be on disk", boot_id())).unwrap();
        // Alive (this process, though it does not hold the name).
        claim(ips[7], "alive", Some(Ident::me()), 4, &|_| ());
        // An older loan of this address, superseded by the dead VM's generation: freed with it.
        claim(ips[9], "older-loan", Some(dead(999_999_938)), 6, &|a| a.lent = Some(5));
        let ips: Vec<Ipv4Addr> = ips.into_iter().chain((11..=17).map(|i| ip(&format!("10.9.1.{i}")))).collect();
        // A source killed while its outcome is owed (#357), even if not marked leaving.
        let owing = dead(999_999_939);
        claim(ips[10], "owing", Some(owing.clone()), 4, &|_| ());
        h.owe(3, &Owed { to: "t".into(), ip: ips[10], gen: 4, by: owing.clone() }).unwrap();
        // A source that may have handed its VM on.
        let leaving = |mig| Some(Leaving { mig, to: "c".into() });
        claim(ips[11], "leaving", Some(dead(999_999_940)), 4, &|a| a.leaving = leaving(40));
        // Its migration record says it was still arriving, whatever the address says.
        let mig = |id: u64, m: Mig| store(&h.mig_path(id), &m, false).unwrap();
        let (pending, committed) = (dead(999_999_941), dead(999_999_942));
        claim(ips[12], "pending", Some(pending.clone()), 4, &|_| ());
        mig(20, Mig::Pending { owner: pending, ip: None });
        claim(ips[13], "committed", Some(committed.clone()), 4, &|_| ());
        mig(21, Mig::Committed { owner: committed });
        // Released, then killed before its address was settled: its own VM, a loan of it too (it came home).
        claim(ips[14], "released", Some(dead(999_999_943)), 4, &|a| a.arriving = Some(22));
        mig(22, Mig::Released { source: String::new(), by: None, ip: Some(ips[14]) });
        claim(ips[15], "homecoming", Some(dead(999_999_944)), 4, &|a| (a.arriving, a.lent) = (Some(23), Some(4)));
        mig(23, Mig::Released { source: String::new(), by: None, ip: Some(ips[15]) });
        // Arrived and settled, then a source again: the old release is no proof.
        claim(ips[16], "left-again", Some(dead(999_999_945)), 4, &|a| a.leaving = leaving(41));
        mig(24, Mig::Released { source: String::new(), by: None, ip: Some(ips[16]) });
        let before: Vec<Addr> = ips.iter().map(|&i| h.addr(&l, i).unwrap()).collect();
        drop(l);
        h.withdraw_dead(false).unwrap();
        let l = h.lock().unwrap();
        for (k, &i) in ips.iter().enumerate() {
            let a = h.addr(&l, i).unwrap();
            match k {
                0 | 9 | 14 | 15 => {
                    assert!(a.withdrawn && a.holder.is_none() && a.holder_id.is_none() && a.lent.is_none(), "{k}: {a:?}");
                    assert!(!a.current(before[k].held), "{k}");
                }
                // A dead source: owed to its target, the claim let go, nothing withdrawn.
                11 | 16 => {
                    let mig = if k == 11 { 40 } else { 41 };
                    let o = load::<Owed>(&h.owed_path(mig)).unwrap().unwrap();
                    assert!(o.to == "c" && o.ip == i && o.gen == 4 && Some(o.by) == before[k].holder_id, "{k}");
                    assert!(a.current(4) && a.holder.is_none() && a.leaving.is_none(), "{k}: {a:?}");
                }
                _ => assert_eq!(a, before[k], "{k}: kept"),
            }
        }
        // Settled, the owed record goes: then it is withdrawn.
        std::fs::remove_file(h.owed_path(3)).unwrap();
        drop(l);
        h.withdraw_dead(false).unwrap();
        let l = h.lock().unwrap();
        assert!(h.addr(&l, ips[10]).unwrap().withdrawn);
        // Once the suspended VM is resumed and dies, its claim goes too.
        std::fs::write(h.suspended("suspended").unwrap().join("STARTED"), "").unwrap();
        drop(l);
        h.withdraw_dead(false).unwrap();
        assert!(h.addr(&h.lock().unwrap(), ips[5]).unwrap().withdrawn);
        // #556: an earlier boot's quarantine no longer holds: that resume never ran its VM.
        assert!(!h.addr(&h.lock().unwrap(), ips[6]).unwrap().withdrawn);
        std::fs::write(&quarantine, "another-boot the mark may be on disk").unwrap();
        let withdrawn = h.withdraw_dead(false).unwrap();
        assert!(h.addr(&h.lock().unwrap(), ips[6]).unwrap().withdrawn);
        assert_eq!(withdrawn, vec![("quarantined".to_string(), ips[6], 4)]);
    }

    #[test]
    fn a_claim_is_moving_while_its_vm_migrates() {
        let (_h_dir, h) = host("moving");
        let (home, away) = (ip("10.9.0.1"), ip("10.9.2.1"));
        let l = h.lock().unwrap();
        let moving = |ip| h.addr(&h.lock().unwrap(), ip).unwrap().leaving.is_some();
        // A source, at home and elsewhere: moving from its loan until it stays.
        let c = h.claim_new(&l, "vm", Some(home)).unwrap();
        assert!(!moving(home) && h.lend(&l, home, c.gen, 1, "t").unwrap() && moving(home));
        h.stay(&l, home, None).unwrap();
        assert!(!moving(home) && h.addr(&l, home).unwrap().lent == Some(c.gen), "the loan is its maker's to undo");
        h.unlend(&l, home, c.gen).unwrap();
        let d = h.claim_incoming(&l, "vm2", away, 7, None).unwrap();
        assert!(!moving(away) && h.lend(&l, away, 7, 2, "t").unwrap() && moving(away), "lent here too, whatever the range");
        h.unlend(&l, away, 7).unwrap();
        // Another instance's claim is not this source's.
        let mut a = h.addr(&l, away).unwrap();
        a.holder_id = Some(Ident { start: 1, ..Ident::me() });
        h.put_addr(away, &a, false).unwrap();
        h.stay(&l, away, None).unwrap();
        assert!(moving(away));
        h.release(&l, away, "vm2", None).unwrap();
        assert!(!moving(away), "released, it holds nothing");
        d.keep();
        c.release(&l).unwrap();
        drop(l);
        // An arrival: arriving by its migration until its record is released.
        let arriving = |ip| h.addr(&h.lock().unwrap(), ip).unwrap().arriving;
        let mut r = h.mig_begin(11, "", None, Some(away)).unwrap();
        let l = h.lock().unwrap();
        let claim = h.claim_arrival(&l, "vm3", away, 8, 1, 11).unwrap();
        assert_eq!(arriving(away), Some(11));
        r.commit(&l).unwrap();
        drop(l);
        assert_eq!(arriving(away), Some(11), "committed, it may still be pulling");
        r.release(None, None).unwrap();
        assert_eq!(arriving(away), None);
        assert!(matches!(load(&h.mig_path(11)).unwrap(), Some(Mig::Released { ip: Some(ip), .. }) if ip == away), "the record names the address");
        claim.keep();
        // Home again: the release also ends its loan.
        let l = h.lock().unwrap();
        h.release(&l, away, "vm3", None).unwrap();
        let x = ip("10.9.0.2");
        let gen = h.lend_new(&l, x).unwrap();
        drop(l);
        let r = h.mig_begin(12, "", None, Some(x)).unwrap();
        h.claim_arrival(&h.lock().unwrap(), "vm4", x, gen, 1, 12).unwrap().keep();
        r.release(None, None).unwrap();
        let a = h.addr(&h.lock().unwrap(), x).unwrap();
        assert!(a.arriving.is_none() && a.lent.is_none(), "{a:?}");
    }

    #[test]
    fn a_source_decides_its_hand_off_before_its_target_may_forget_it() {
        let (_h_dir, h) = host("hand-off");
        let x = ip("10.9.0.1");
        let l = h.lock().unwrap();
        let c = h.claim_new(&l, "vm", Some(x)).unwrap();
        assert!(!h.owes(&Ident::me()));
        assert!(h.lend(&l, x, c.gen, 7, "b").unwrap());
        // Leaving, it has not decided: its target keeps the record it would ask about.
        assert!(h.owes(&Ident::me()), "leaving counts as owed");
        h.release(&l, x, "vm", Some(&Ident::me())).unwrap();
        let a = h.addr(&l, x).unwrap();
        assert!(a.holder.is_none() && a.leaving.is_none() && a.lent == Some(c.gen) && a.current(c.gen), "the loan stays the target's: {a:?}");
        assert!(!h.owes(&Ident::me()), "decided: the target may forget it");
        let gen = c.gen;
        c.keep();
        drop(l);
        // Killed after the target forgot it: nothing is owed, nothing withdrawn.
        h.withdraw_dead(false).unwrap();
        let a = h.addr(&h.lock().unwrap(), x).unwrap();
        assert!(a.current(gen) && a.lent == Some(gen) && !h.owed_path(7).exists());
        // Killed before it decided: its target is asked (it kept its record, as `owes` says).
        let y = ip("10.9.0.2");
        let gone = dead_owner(&h, 999_999_961, &[]);
        let a = Addr {
            seen: 3,
            lent: Some(3),
            holder: Some("vm2".into()),
            holder_id: Some(gone.clone()),
            held: 3,
            leaving: Some(Leaving { mig: 8, to: "b".into() }),
            ..Addr::default()
        };
        h.put_addr(y, &a, false).unwrap();
        assert!(h.owes(&gone));
        h.withdraw_dead(false).unwrap();
        assert!(h.owes(&gone) && h.owed_path(8).exists(), "owed until the target says");
        // What cannot be read counts as leaving.
        let other = dead_owner(&h, 999_999_962, &[]);
        std::fs::write(h.state.join("addrs").join("10.9.0.3"), b"{").unwrap();
        assert!(h.owes(&other));
    }

    #[test]
    fn a_settled_outcome_retires_the_leaving_claim_before_its_record_goes() {
        let (_h_dir, h) = host("owed-retire");
        let x = ip("10.9.0.1");
        let gone = dead_owner(&h, 999_999_963, &[]);
        let a = Addr {
            seen: 3,
            lent: Some(3),
            holder: Some("vm".into()),
            holder_id: Some(gone.clone()),
            held: 3,
            leaving: Some(Leaving { mig: 9, to: "b".into() }),
            ..Addr::default()
        };
        h.put_addr(x, &a, false).unwrap();
        // A sweep owes it, then dies before the claim goes: the owed record and the claim both remain.
        h.owe(9, &Owed { to: "b".into(), ip: x, gen: 3, by: gone.clone() }).unwrap();
        // b has it: the claim is retired before the record goes and before b is told done.
        let order = std::cell::RefCell::new(Vec::new());
        // Again while its lock was busy for a moment (another test's forked child: #374).
        while order.borrow().is_empty() {
            h.settle_owed_with(
                5,
                |_, _| Ok("released".into()),
                |_, id| {
                    let a = h.addr(&h.lock().unwrap(), x).unwrap();
                    order.borrow_mut().push((id, a.leaving.is_none() && a.holder.is_none(), h.owed_path(9).exists()));
                },
                |_, _| (),
            );
        }
        assert_eq!(order.into_inner(), [(9, true, false)], "decided on the address, then the record gone, then done");
        // b has forgotten it (an unknown id reads aborted there): later sweeps owe nothing, withdraw nothing.
        h.withdraw_dead(false).unwrap();
        h.settle_owed_with(5, |_, _| Ok("aborted".into()), |_, _| (), |_, _| ());
        let a = h.addr(&h.lock().unwrap(), x).unwrap();
        assert!(!h.owed_path(9).exists() && a.current(3) && a.lent == Some(3) && !a.withdrawn, "{a:?}");
        // Aborted, the claim goes with the record too.
        let y = ip("10.9.0.2");
        let gone = dead_owner(&h, 999_999_964, &[]);
        let a = Addr {
            seen: 5,
            lent: Some(5),
            holder: Some("vm2".into()),
            holder_id: Some(gone.clone()),
            held: 5,
            leaving: Some(Leaving { mig: 10, to: "b".into() }),
            ..Addr::default()
        };
        h.put_addr(y, &a, false).unwrap();
        h.owe(10, &Owed { to: "b".into(), ip: y, gen: 5, by: gone }).unwrap();
        while h.owed_path(10).exists() {
            h.settle_owed_with(5, |_, _| Ok("aborted".into()), |_, _| (), |_, _| ());
        }
        let a = h.addr(&h.lock().unwrap(), y).unwrap();
        assert!(a.withdrawn && a.lent.is_none() && a.leaving.is_none() && a.holder.is_none() && !h.owed_path(10).exists(), "{a:?}");
    }

    #[test]
    fn an_abort_undoes_leaving_and_its_loan_in_one_write() {
        let (_h_dir, h) = host("stay");
        let x = ip("10.9.0.1");
        let l = h.lock().unwrap();
        let c = h.claim_new(&l, "vm", Some(x)).unwrap();
        assert!(h.lend(&l, x, c.gen, 7, "b").unwrap());
        let before = std::fs::metadata(h.addr_path(x)).unwrap().ino();
        h.stay(&l, x, Some(c.gen)).unwrap();
        let a = h.addr(&l, x).unwrap();
        assert!(a.leaving.is_none() && a.lent.is_none() && a.holder_id == Some(Ident::me()), "{a:?}");
        assert_ne!(std::fs::metadata(h.addr_path(x)).unwrap().ino(), before, "replaced whole (one rename)");
        // A failed write leaves both, never one: settled through the target should it die.
        assert!(h.lend(&l, x, c.gen, 8, "b").unwrap());
        let path = h.addr_path(x);
        let dir = path.parent().unwrap();
        let ro = |mode| std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(mode)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            ro(0o555);
            assert!(h.stay(&l, x, Some(c.gen)).is_err());
            ro(0o777);
            let a = h.addr(&l, x).unwrap();
            assert!(a.leaving.is_some() && a.lent == Some(c.gen), "{a:?}");
        }
        c.keep();
    }

    #[test]
    fn a_withdrawal_is_recorded_before_its_claim_goes() {
        let (_h_dir, mut h) = host("enqueue-first");
        h.cfg.peers = vec!["a".into()];
        let x = ip("10.9.1.1");
        let l = h.lock().unwrap();
        h.put_addr(x, &Addr { seen: 4, holder: Some("vm".into()), holder_id: Some(Ident::me()), held: 4, ..Addr::default() }, false).unwrap();
        // The notice cannot be written: nothing changes, so the claim (kept) still leads a sweep to it.
        let notices = h.state.join("withdrawals");
        std::fs::remove_dir(&notices).unwrap();
        std::fs::write(&notices, b"").unwrap();
        assert!(h.withdraw_noted(&l, x, 4).is_err());
        let a = h.addr(&l, x).unwrap();
        assert!(a.current(4) && a.holder_id == Some(Ident::me()), "{a:?}");
        std::fs::remove_file(&notices).unwrap();
        std::fs::create_dir(&notices).unwrap();
        assert!(h.withdraw_noted(&l, x, 4).unwrap() && notices.join("10.9.1.1").exists());
        // An interrupted notice write's temp file goes once its writer is gone, not before.
        let (dead, live) = (notices.join(".10.9.1.2.999999971.tmp"), notices.join(format!(".10.9.1.3.{}.tmp", std::process::id())));
        std::fs::write(&dead, b"{").unwrap();
        std::fs::write(&live, b"{").unwrap();
        drop(l);
        while !h.deliver_withdrawals_with(8, 0, |_, _| Ok(())) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!dead.exists() && live.exists());
    }

    #[test]
    fn unreadable_migration_records_withdraw_nothing() {
        let (_h_dir, h) = host("withdraw-unreadable");
        let x = ip("10.9.1.1");
        let gone = dead_owner(&h, 999_999_951, &[]);
        h.put_addr(x, &Addr { seen: 4, holder: Some("vm".into()), holder_id: Some(gone), held: 4, ..Addr::default() }, false).unwrap();
        let kept = |h: &Host| !h.addr(&h.lock().unwrap(), x).unwrap().withdrawn;
        // An owed record or a migration record that cannot be read may be the one that keeps it.
        for dir in ["owed", "migs"] {
            let bad = h.state.join(dir).join("5");
            std::fs::write(&bad, b"{not json").unwrap();
            let e = h.withdraw_dead(false).unwrap_err().to_string();
            assert!(e.contains(&bad.display().to_string()) && e.contains("repaired or removed by hand"), "{dir}: {e}");
            assert!(kept(&h), "{dir}");
            std::fs::remove_file(&bad).unwrap();
            // The directory itself.
            let path = h.state.join(dir);
            std::fs::remove_dir(&path).unwrap();
            std::fs::write(&path, b"").unwrap();
            assert!(h.withdraw_dead(false).is_err() && kept(&h), "{dir}");
            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(&path).unwrap();
        }
        // A write's temp file is not a record.
        std::fs::write(h.state.join("migs").join(".5.1.tmp"), b"{").unwrap();
        h.withdraw_dead(false).unwrap();
        assert!(!kept(&h));
    }

    #[test]
    fn a_release_cut_short_is_finished_by_retirement() {
        let (_h_dir, h) = host("release-cut");
        let x = ip("10.9.0.1");
        let gone = dead_owner(&h, 999_999_952, &[]);
        let a = Addr { seen: 4, lent: Some(4), holder: Some("vm".into()), holder_id: Some(gone), held: 4, arriving: Some(30), ..Addr::default() };
        h.put_addr(x, &a, false).unwrap();
        store(&h.mig_path(30), &Mig::Released { source: "s".into(), by: None, ip: Some(x) }, false).unwrap();
        // The source is done (or gone) before any sweep: the record goes, its evidence moved to the address.
        h.mig_done(30).unwrap();
        let a = h.addr(&h.lock().unwrap(), x).unwrap();
        assert!(!h.mig_path(30).exists() && a.arriving.is_none() && a.lent.is_none(), "{a:?}");
        h.withdraw_dead(false).unwrap();
        assert!(h.addr(&h.lock().unwrap(), x).unwrap().withdrawn);
    }

    /// A delivery pass at `now` with `down` failing: who was asked. A pass
    /// that found its lock busy (another test's child, forked but not yet
    /// exec'd, may hold it for a moment: #374) is run again.
    fn deliver(h: &Host, budget: usize, now: u64, down: &[&str]) -> Vec<String> {
        let asked = Mutex::new(Vec::new());
        let tell = |p: &str, req: &serde_json::Value| {
            assert!(req["via"].is_null() && req["gen"].as_u64().is_some());
            asked.lock().unwrap().push(p.to_string());
            if down.contains(&p) {
                bail!("down")
            }
            Ok(())
        };
        while !h.deliver_withdrawals_with(budget, now, tell) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut asked = asked.into_inner().unwrap();
        asked.sort();
        asked
    }

    fn unheard(peers: &[&str]) -> Vec<Unheard> {
        peers.iter().map(|p| Unheard { peer: p.to_string(), tries: 0, next_ms: 0 }).collect()
    }

    #[test]
    fn withdrawals_are_redelivered_until_each_peer_has_them() {
        let (_h_dir, mut h) = host("notices");
        h.cfg.peers = vec!["p1".into(), "p2".into()];
        let x = ip("10.9.1.1");
        let gone = dead_owner(&h, 999_999_953, &[]);
        h.put_addr(x, &Addr { seen: 4, holder: Some("vm".into()), holder_id: Some(gone), held: 4, ..Addr::default() }, false).unwrap();
        h.withdraw_dead(false).unwrap();
        let notice = |h: &Host| load::<Notice>(&h.notice_path(x)).unwrap();
        assert_eq!(notice(&h), Some(Notice { gen: 4, rev: 0, peers: unheard(&["p1", "p2"]) }), "recorded with the withdrawal");
        // p2 is down: p1 is told, p2 asked again only after its backoff.
        assert_eq!(deliver(&h, 8, 1000, &["p2"]), ["p1", "p2"]);
        let n = notice(&h).unwrap();
        let next = 1000 + WITHDRAWAL_BACKOFF.as_millis() as u64;
        assert_eq!(n.peers, [Unheard { peer: "p2".into(), tries: 1, next_ms: next }]);
        assert!(deliver(&h, 8, next - 1, &[]).is_empty(), "not before its backoff");
        assert_eq!(deliver(&h, 8, next, &[]), ["p2"]);
        assert_eq!(notice(&h), None, "every peer has it");
        // A notice left by a process that died before telling anyone is delivered by the next pass.
        store(&h.notice_path(x), &Notice { gen: 4, rev: 0, peers: unheard(&["p1"]) }, false).unwrap();
        assert_eq!(deliver(&h, 8, 0, &[]), ["p1"]);
        assert_eq!(notice(&h), None);
        // A newer withdrawal recorded during a delivery is kept whole; an older one does not replace it.
        store(&h.notice_path(x), &Notice { gen: 4, rev: 0, peers: unheard(&["p1"]) }, false).unwrap();
        let newer = Notice { gen: 9, rev: 0, peers: unheard(&["p1", "p2"]) };
        while !h.deliver_withdrawals_with(8, 0, |_, _| store(&h.notice_path(x), &newer, false)) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(notice(&h), Some(newer.clone()));
        h.withdraw_noted(&h.lock().unwrap(), x, 5).unwrap();
        assert_eq!(notice(&h), Some(newer));
        // A peer no longer configured is not asked.
        h.cfg.peers = vec!["p1".into()];
        assert_eq!(deliver(&h, 8, 0, &[]), ["p1"]);
        assert_eq!(notice(&h), None);
    }

    /// Review of #594: the VM migrated in (a newer revision than its old host announced) and ended
    /// here before a peer heard of it: the withdrawal, retries too, carries that revision, as the
    /// VM published it ahead of its record (#533), so the peer takes it from this host.
    #[test]
    fn a_withdrawal_carries_the_latest_revision_of_its_generation() {
        let (_h_dir, mut h) = host("notice-rev");
        h.cfg.peers = vec!["p1".into()];
        let x = ip("10.9.1.1");
        let gone = dead_owner(&h, 999_999_954, &[]);
        h.put_addr(x, &Addr { seen: 4, rev: 2, holder: Some("vm".into()), holder_id: Some(gone), held: 4, ..Addr::default() }, false).unwrap();
        h.publish_live(&h.lock().unwrap(), x, 4, 3).unwrap();
        h.withdraw_dead(false).unwrap();
        assert_eq!(load::<Notice>(&h.notice_path(x)).unwrap().map(|n| (n.gen, n.rev)), Some((4, 3)));
        let sent = Mutex::new(Vec::new());
        for now in [0, 1 << 40] {
            while !h.deliver_withdrawals_with(8, now, |_, req| {
                sent.lock().unwrap().push(req.clone());
                bail!("down")
            }) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let sent = sent.into_inner().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(sent.iter().all(|r| r["gen"] == 4 && r["rev"] == 3), "{sent:?}");
        // One of the same generation and a newer revision replaces it.
        h.publish_live(&h.lock().unwrap(), x, 4, 5).unwrap();
        h.withdraw_noted(&h.lock().unwrap(), x, 4).unwrap();
        assert_eq!(load::<Notice>(&h.notice_path(x)).unwrap().map(|n| (n.gen, n.rev)), Some((4, 5)));
    }

    #[test]
    fn peers_that_are_down_never_crowd_out_one_that_is_up() {
        let (_h_dir, mut h) = host("notice-fair");
        let peers: Vec<String> = (1..=9).map(|i| format!("p{i}")).collect();
        h.cfg.peers = peers.clone();
        let x = ip("10.9.1.1");
        h.withdraw_noted(&h.lock().unwrap(), x, 4).unwrap();
        // The first eight are down, the ninth (say, the home host) up; eight calls a pass.
        let down: Vec<&str> = peers[..8].iter().map(|p| p.as_str()).collect();
        let first = deliver(&h, 8, 1000, &down);
        assert_eq!(first.len(), 8);
        let second = deliver(&h, 8, 1000, &down);
        assert!(second.contains(&"p9".to_string()), "never asked goes before asked again: {second:?}");
        let n = load::<Notice>(&h.notice_path(x)).unwrap().unwrap();
        assert!(!n.peers.iter().any(|u| u.peer == "p9"), "p9 heard it");
        // Each failure counts against its own peer only.
        assert!(n.peers.iter().all(|u| u.tries >= 1 && u.tries <= 2), "{n:?}");
        // Across notices too: a new withdrawal's peers are asked before old ones' retries.
        let y = ip("10.9.1.2");
        h.withdraw_noted(&h.lock().unwrap(), y, 6).unwrap();
        let asked = deliver(&h, 9, 1_000_000_000, &down);
        assert!(asked.contains(&"p9".to_string()));
        assert_eq!(load::<Notice>(&h.notice_path(y)).unwrap().unwrap().peers.iter().filter(|u| u.peer == "p9").count(), 0);
    }

    #[test]
    fn an_undelivered_withdrawal_is_never_given_up() {
        let (_h_dir, mut h) = host("notice-kept");
        h.cfg.peers = vec!["home".into()];
        let x = ip("10.9.1.1");
        h.withdraw_noted(&h.lock().unwrap(), x, 4).unwrap();
        let cap = WITHDRAWAL_MAX_BACKOFF.as_millis() as u64;
        let mut now = 0;
        // Down for days: asked again at most every cap, never forgotten.
        for _ in 0..100 {
            assert_eq!(deliver(&h, 8, now, &["home"]), ["home"]);
            let n = load::<Notice>(&h.notice_path(x)).unwrap().expect("kept");
            let u = &n.peers[0];
            assert!(u.next_ms > now && u.next_ms <= now + cap);
            now = u.next_ms;
        }
        assert!(now >= 90 * cap);
        // Back: it hears, and only then the notice goes.
        assert_eq!(deliver(&h, 8, now, &[]), ["home"]);
        assert!(load::<Notice>(&h.notice_path(x)).unwrap().is_none());
    }

    #[test]
    fn a_source_killed_after_its_abort_resumed_is_settled_by_its_target() {
        let (_h_dir, mut h) = host("abort-killed");
        h.cfg.peers = vec!["a".into()];
        let x = ip("10.9.1.1");
        let gone = dead_owner(&h, 999_999_954, &[]);
        // Its migration to c aborted and it resumed here, then was killed before it stayed.
        let a = Addr {
            seen: 4,
            holder: Some("vm".into()),
            holder_id: Some(gone.clone()),
            held: 4,
            leaving: Some(Leaving { mig: 50, to: "c".into() }),
            ..Addr::default()
        };
        h.put_addr(x, &a, false).unwrap();
        h.withdraw_dead(false).unwrap();
        assert_eq!(load::<Owed>(&h.owed_path(50)).unwrap(), Some(Owed { to: "c".into(), ip: x, gen: 4, by: gone }));
        let rec = h.addr(&h.lock().unwrap(), x).unwrap();
        assert!(rec.holder.is_none() && rec.leaving.is_none() && !rec.withdrawn, "{rec:?}");
        // Asked again on a later sweep: already owed, nothing more.
        h.withdraw_dead(false).unwrap();
        // c says aborted: no copy runs anywhere, so it is withdrawn and the peers are to hear it.
        h.settle_owed_with(5, |_, _| Ok("aborted".into()), |_, _| (), |_, _| ());
        assert!(h.addr(&h.lock().unwrap(), x).unwrap().withdrawn && !h.owed_path(50).exists());
        assert_eq!(load::<Notice>(&h.notice_path(x)).unwrap().map(|n| n.gen), Some(4));
        // Had c resumed it, the VM would be c's: released, nothing withdrawn.
        let y = ip("10.9.1.2");
        let gone = dead_owner(&h, 999_999_955, &[]);
        let a =
            Addr { seen: 4, holder: Some("vm2".into()), holder_id: Some(gone), held: 4, leaving: Some(Leaving { mig: 51, to: "c".into() }), ..Addr::default() };
        h.put_addr(y, &a, false).unwrap();
        h.withdraw_dead(false).unwrap();
        h.settle_owed_with(5, |_, id| Ok(if id == 51 { "released" } else { "pending" }.into()), |_, _| (), |_, _| ());
        let rec = h.addr(&h.lock().unwrap(), y).unwrap();
        assert!(!rec.withdrawn && rec.current(4) && !h.owed_path(51).exists(), "{rec:?}");
    }

    #[test]
    fn a_dead_sources_leaving_claim_goes_once_its_generation_is_withdrawn_or_superseded() {
        let (_h_dir, h) = host("leaving-stale");
        // Withdrawn (its target released then killed it), superseded (moved on, gen + 1 announced),
        // and reclaimed: each source died after lending, before it stayed or was released.
        let cases = [("10.9.2.1", true, 4, 60, 999_999_941), ("10.9.2.2", false, 5, 61, 999_999_942), ("10.9.2.3", false, 4, 62, 999_999_943)];
        for (x, withdrawn, seen, mig, pid) in cases {
            let gone = dead_owner(&h, pid, &[]);
            let a = Addr {
                seen,
                withdrawn,
                lent: Some(4),
                holder: Some(format!("vm{mig}")),
                holder_id: Some(gone.clone()),
                held: 4,
                leaving: Some(Leaving { mig, to: "b".into() }),
                ..Addr::default()
            };
            h.put_addr(ip(x), &a, false).unwrap();
            assert!(h.owes(&gone));
        }
        let reclaimed = ip("10.9.2.3");
        h.reclaim(reclaimed, 4).unwrap();
        let rec = h.addr(&h.lock().unwrap(), reclaimed).unwrap();
        assert!(rec.withdrawn && rec.holder.is_none() && rec.leaving.is_none(), "{rec:?}");
        h.withdraw_dead(false).unwrap();
        for (x, _, _, mig, pid) in cases {
            let rec = h.addr(&h.lock().unwrap(), ip(x)).unwrap();
            assert!(rec.holder.is_none() && rec.holder_id.is_none() && rec.leaving.is_none(), "{x}: {rec:?}");
            assert!(!h.owed_path(mig).exists(), "{x}: nothing is owed");
            assert!(!h.owes(&Ident { pid, start: 1, boot: boot_id().into() }), "{x}: its target may forget it");
        }
    }

    #[test]
    fn what_cannot_be_read_is_never_proof_of_death() {
        let (_h_dir, h) = host("unreadable");
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
        // A name whose lock cannot be read is not free.
        std::fs::write(h.vms("u", "lock").unwrap(), "{").unwrap();
        let l = h.lock().unwrap();
        assert!(h.take_name("u", false).is_err() && !h.holder_gone("u"));
        collect_owned(&h.run);
        assert!(h.vms("u", "lock").unwrap().exists(), "kept by the garbage collector too");
        // An empty lock (created, never written) is no holder.
        std::fs::write(h.vms("e", "lock").unwrap(), "").unwrap();
        assert!(h.take_name("e", false).is_ok());
        // A live holder whose lock record cannot be read keeps its address.
        let _v = h.take_name("v", false).unwrap();
        let x = h.claim_new(&l, "v", Some(ip("10.9.0.2"))).unwrap();
        for unreadable in ["{", ""] {
            std::fs::write(h.vms("v", "lock").unwrap(), unreadable).unwrap();
            assert_eq!(h.holder(&l, x.ip).unwrap().as_deref(), Some("v"), "{unreadable:?}");
            assert!(h.claim_new(&l, "w", Some(x.ip)).is_err() && h.lend_new(&l, x.ip).is_err());
        }
        // Read, and naming another instance: not this claim's holder.
        store(&h.vms("v", "lock").unwrap(), &Ident { start: 1, ..Ident::me() }, false).unwrap();
        assert_eq!(h.holder(&l, x.ip).unwrap(), None);
        x.keep();
    }

    #[test]
    fn cgroups_name_their_process() {
        assert_eq!(cgroup_owner("idle-4242-77-3"), Some(Ident { pid: 4242, start: 77, boot: boot_id().into() }));
        for cg in ["vm-4242", "vm-4242-77", "other-42", "idle-", "idle-4242-3", "idle-4242-x-3", "idle-1-2-3-4", "cgroup.procs", "memory.max"] {
            assert_eq!(cgroup_owner(cg), None, "{cg}");
        }
    }

    /// #553, #555: until a boot's recovery is marked complete, routes to peers' VMs come back from
    /// the records, and the VMs that died with the host are recorded as lost, then withdrawn.
    #[test]
    fn after_a_boot_routes_come_back_and_lost_vms_are_recorded() {
        let (_h_dir, mut h) = host("after-boot");
        h.cfg.cluster_ips = Some("10.9.0.0/16".into());
        let (peer, gone, mine, withdrawn) = (ip("10.9.5.1"), ip("10.9.5.2"), ip("10.9.5.3"), ip("10.9.5.4"));
        let via = ip("192.0.2.7");
        h.cfg.peers = vec![format!("{via}:7070")];
        let dead = dead_owner(&h, 999_999_946, &[]);
        {
            let l = h.lock().unwrap();
            h.put_addr(peer, &Addr { seen: 3, via: Some(via), ..Addr::default() }, true).unwrap();
            // Recorded before #584 (or under a wider cluster range): never put back.
            h.put_addr(ip("169.254.169.254"), &Addr { seen: 3, via: Some(via), ..Addr::default() }, true).unwrap();
            assert!(!h.reinstall(&l, ip("169.254.169.254"), None).unwrap(), "outside cluster_ips");
            h.put_addr(withdrawn, &Addr { seen: 3, via: Some(via), withdrawn: true, ..Addr::default() }, true).unwrap();
            h.put_addr(gone, &Addr { seen: 5, holder: Some("web".into()), holder_id: Some(dead), held: 5, ..Addr::default() }, true).unwrap();
            let c = h.claim_new_in(&l, &Config { vm_ips: "10.9.5.3-10.9.5.3".into(), ..Config::default() }, "alive", Some(mine)).unwrap();
            c.keep();
        }
        let (routes, down) = (std::cell::RefCell::new(Vec::new()), std::cell::Cell::new(true));
        let route = |ip, via| {
            routes.borrow_mut().push((ip, via));
            if down.get() {
                bail!("Network is unreachable");
            }
            Ok(())
        };
        // A route that cannot be put back yet (its interface not up): not complete, tried again.
        assert_eq!(h.after_boot_with("boot-1", route).unwrap(), Some(false));
        assert_eq!(*routes.borrow(), vec![(peer, via)], "only a peer's live generation, not one withdrawn or held here");
        let l = h.lock().unwrap();
        assert!(h.addr(&l, gone).unwrap().withdrawn && h.addr(&l, gone).unwrap().holder.is_none());
        assert!(!h.addr(&l, mine).unwrap().withdrawn, "a live holder's is kept");
        drop(l);
        let lost = std::fs::read_to_string(h.vms("web", "lost").unwrap()).unwrap();
        assert!(lost.starts_with("lost:") && lost.contains("10.9.5.2") && lost.contains("generation 5"), "{lost}");
        assert!(!h.vms("alive", "lost").unwrap().exists());
        down.set(false);
        assert_eq!(h.after_boot_with("boot-1", route).unwrap(), Some(true), "never marked by the local pass alone");
        assert_eq!(routes.borrow().len(), 2);
        assert!(!h.boot_marker().exists());
        h.mark_recovered().unwrap();
        assert_eq!(h.after_boot_with(boot_id(), route).unwrap(), None, "once marked, not again in the boot");
        assert_eq!(routes.borrow().len(), 2);
        assert_eq!(h.after_boot_with("boot-2", route).unwrap(), Some(true), "and again after the next");
        assert_eq!(h.after_boot_with("", route).unwrap(), None, "never without a boot id");
        // A new VM of the name clears the record.
        drop(h.take_name("web", false).unwrap());
        assert!(!h.vms("web", "lost").unwrap().exists());
    }

    /// Review of #594: a peer by name no listener has looked up since the boot (`RUN/peers.json` is
    /// gone with it) leaves its saved routes uncheckable, so the pass is not complete and tries
    /// again, never dropping them for good.
    #[test]
    fn after_a_boot_routes_wait_for_named_peers_to_be_known() {
        let (_h_dir, mut h) = host("after-boot-named");
        h.cfg.cluster_ips = Some("10.9.0.0/16".into());
        h.cfg.peers = vec!["peer.invalid:7070".into()];
        let (peer, via) = (ip("10.9.5.1"), ip("192.0.2.7"));
        h.put_addr(peer, &Addr { seen: 3, via: Some(via), ..Addr::default() }, true).unwrap();
        let routes = std::cell::RefCell::new(Vec::new());
        let route = |ip, via| {
            routes.borrow_mut().push((ip, via));
            Ok(())
        };
        // Never a peer's next hop: skipped for good once every peer is known.
        h.put_addr(ip("10.9.5.2"), &Addr { seen: 3, via: Some(ip("192.0.2.99")), ..Addr::default() }, true).unwrap();
        assert_eq!(h.after_boot_with("boot-1", route).unwrap(), Some(false));
        assert!(routes.borrow().is_empty());
        // The listener's lookup at its start failed (DNS timed out): an empty entry, still not known.
        crate::util::write_file(&h.run, "peers.json", br#"{"names": {"peer.invalid:7070": []}}"#, false).unwrap();
        assert_eq!(h.after_boot_with("boot-1", route).unwrap(), Some(false));
        assert!(routes.borrow().is_empty());
        crate::util::write_file(&h.run, "peers.json", br#"{"names": {"peer.invalid:7070": ["192.0.2.7"]}}"#, false).unwrap();
        assert_eq!(h.after_boot_with("boot-1", route).unwrap(), Some(true));
        assert_eq!(*routes.borrow(), vec![(peer, via)]);
    }

    /// Review of #565: a lost VM is recorded before its address is withdrawn (a crash between
    /// them never loses the listing): one that cannot be recorded keeps its address until it can
    /// be. Once the boot's recovery is complete, sweeps record nothing.
    #[test]
    fn a_lost_vm_is_recorded_before_its_address_goes() {
        let (_h_dir, h) = host("lost-first");
        let ip = ip("10.9.5.9");
        let claim = |pid| {
            let a = Addr { seen: 2, holder: Some("db".into()), holder_id: Some(dead_owner(&h, pid, &[])), held: 2, ..Addr::default() };
            h.put_addr(ip, &a, true).unwrap();
        };
        claim(999_999_947);
        // `RUN/vms/db.lost` cannot be made: a directory in its place.
        let lost = h.vms("db", "lost").unwrap();
        std::fs::create_dir(&lost).unwrap();
        std::fs::write(lost.join("x"), "").unwrap();
        assert!(h.collect_garbage().is_err(), "a failure, so the pass does not complete");
        assert_eq!(h.after_boot_with("boot-x", |_, _| Ok(())).unwrap(), Some(false));
        assert!(!h.addr(&h.lock().unwrap(), ip).unwrap().withdrawn, "kept until it is recorded");
        std::fs::remove_dir_all(&lost).unwrap();
        assert_eq!(h.collect_garbage().unwrap(), vec![("db".to_string(), ip, 2)]);
        assert!(lost.is_file() && h.addr(&h.lock().unwrap(), ip).unwrap().withdrawn);
        // Recovered: a VM that dies later is a sweep's, not lost with the host.
        std::fs::remove_file(&lost).unwrap();
        h.mark_recovered().unwrap();
        claim(999_999_948);
        h.put_addr(ip, &Addr { seen: 3, held: 3, ..h.addr(&h.lock().unwrap(), ip).unwrap() }, true).unwrap();
        assert_eq!(h.collect_garbage().unwrap().len(), 1);
        assert!(!lost.exists());
    }

    /// #563: a suspended VM's record is made durable before its checkpoint is published.
    #[test]
    fn a_kept_claim_is_synced_once() {
        let (_h_dir, h) = host("sync-addr");
        let l = h.lock().unwrap();
        let c = h.claim_new(&l, "web", None).unwrap();
        let ip = c.ip;
        assert!(h.unsynced_marker(ip).exists());
        h.sync_addr(&l, ip).unwrap();
        assert!(!h.unsynced_marker(ip).exists());
        assert_eq!(h.addr(&l, ip).unwrap().holder.as_deref(), Some("web"));
        h.sync_addr(&l, ip).unwrap();
        c.keep();
    }

    /// #556, #563: a write's temporary file goes once its writer is proven gone (by pid, start time and
    /// boot), never a live one's nor a published record, in STATE and RUN alike.
    #[test]
    fn write_debris_is_told_by_its_writers_identity() {
        let (_h_dir, h) = host("write-debris");
        let me = Ident::me();
        let boot = &boot_id()[..crate::util::BOOT_TAG];
        let mine = crate::util::write_tag();
        assert_eq!(mine, format!("{}-{}-{boot}", me.pid, me.start));
        let claims = h.run.join("claims");
        let files = [
            (format!(".10.9.0.1.{mine}.tmp"), true),
            (format!(".10.9.0.2.{}-{}-{boot}.tmp", me.pid, me.start + 1), false),
            (format!(".10.9.0.3.{}-{}-0000beef.tmp", me.pid, me.start), false),
            (".10.9.0.4.999999971.tmp".to_string(), false),
            (format!(".10.9.0.5.{}.tmp", me.pid), true),
            ("10.9.0.6".to_string(), true),
            (".10.9.0.7.x-1-2.tmp".to_string(), true),
        ];
        for (f, _) in &files {
            std::fs::write(claims.join(f), "").unwrap();
        }
        // Another boot's, by a pid that runs now: an mtime before this boot.
        let old = claims.join(format!(".10.9.0.8.{}.tmp", me.pid));
        File::create(&old).unwrap().set_modified(UNIX_EPOCH + Duration::from_secs(1)).unwrap();
        let gens = [(format!("..gens.next.{}-1-{boot}.tmp", me.pid), false), (format!("..gens.next.{mine}.tmp"), true), (".gens.next".to_string(), true)];
        for (f, _) in &gens {
            std::fs::write(h.run.join(f), "").unwrap();
        }
        let other = h.run.join(".state.json.99999999.tmp");
        std::fs::write(&other, "").unwrap();
        h.collect_garbage().unwrap();
        for (f, kept) in &files {
            assert_eq!(claims.join(f).exists(), *kept, "{f}");
        }
        assert!(!old.exists());
        for (f, kept) in &gens {
            assert_eq!(h.run.join(f).exists(), *kept, "{f}");
        }
        assert!(other.exists(), "only the cursor's temporary files in RUN itself");
        // STATE's records, by the same rule.
        let owed = h.state.join("owed");
        let (dead, live) = (owed.join(format!(".7.{}-1-0000beef.tmp", me.pid)), owed.join(format!(".8.{mine}.tmp")));
        std::fs::write(&dead, "").unwrap();
        std::fs::write(&live, "").unwrap();
        h.write_debris("owed");
        assert!(!dead.exists() && live.exists());
    }

    /// #556: without --run, a state's run directory follows from its path alone, so no state
    /// defaults into another's; one bound elsewhere is refused without its --run.
    #[test]
    fn each_state_has_a_run_directory_of_its_own_by_default() {
        let base = crate::test_util::TempDir::new("default-run");
        let (a, b) = (base.join("a"), base.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        let ra = default_run(&a).unwrap();
        assert_eq!(ra, PathBuf::from(format!("/run/flexvm-{}", tap_prefix(&a.canonicalize().unwrap()))));
        assert_ne!(ra, default_run(&b).unwrap());
        assert_eq!(default_run_of(Path::new(DEFAULT_STATE)), PathBuf::from(DEFAULT_RUN));
        // Bound to the old default (or any other): its --run is needed, never defaulted into.
        let run = base.join("run");
        Host::open(&a, &run).unwrap();
        let e = default_run(&a).unwrap_err().to_string();
        assert!(e.contains(&format!("give --run {}", run.canonicalize().unwrap().display())), "{e}");
        // The default run directory is the default state's alone, whoever opens first.
        let (dstate, drun) = (base.join("default-state"), base.join("default-run"));
        std::fs::create_dir_all(&drun).unwrap();
        let e = reserved_run(&b, &drun, &dstate, &drun).unwrap_err().to_string();
        assert!(e.contains("takes one of its own") && e.contains("/run/flexvm-"), "{e}");
        reserved_run(&dstate, &drun, &dstate, &drun).unwrap();
        reserved_run(&b, &run, &dstate, &drun).unwrap();
    }

    /// Six bytes, `f` and base-36 digits, and apart for separate state directories.
    #[test]
    fn the_tap_prefix_is_the_state_directorys() {
        let prefixes: HashSet<String> = (0..2000).map(|i| tap_prefix(Path::new(&format!("/var/tmp/fvci-{i}/a-state")))).collect();
        assert_eq!(prefixes.len(), 2000);
        for p in &prefixes {
            assert!(p.len() == 6 && p.starts_with('f') && p.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()), "{p}");
        }
        assert_eq!(tap_prefix(Path::new("/var/lib/flexvm")), tap_prefix(Path::new("/var/lib/flexvm")));
        // With a pid of 6 hex digits and `t`, two suffix digits still fit in 15 bytes.
        assert_eq!(format!("{}3ffffft{:x}", tap_prefix(Path::new("/")), 255).len(), 15);
    }

    #[test]
    fn the_default_reserve_is_a_sixteenth_of_ram() {
        for (total_mib, reserve) in [(0, 256), (2048, 256), (4096, 256), (16384, 1024), (65536, 4096), (1 << 20, 4096)] {
            assert_eq!(reserve_for(total_mib), reserve, "{total_mib}");
        }
        // This host's, read in kB from /proc/meminfo here, MiB there.
        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap();
        let kb: u64 = meminfo.lines().find_map(|l| l.strip_prefix("MemTotal:")).unwrap().trim().trim_end_matches(" kB").parse().unwrap();
        assert_eq!(default_reserve(), (kb / 1024 / 16).clamp(256, 4096));
        assert_eq!(Config::default().reserve(), default_reserve());
        assert_eq!(Config { reserve_mib: Some(300), ..Config::default() }.reserve(), 300);
    }

    /// A running process reads one snapshot of the settings as they are now,
    /// what is derived for those unset included.
    #[test]
    fn running_processes_read_the_settings_as_they_change() {
        let (_h_dir, mut h) = host("derived");
        let running = h.clone();
        let set = |h: &mut Host, f: fn(&mut Config)| {
            h.configure(|c| {
                f(c);
                Ok(())
            })
            .unwrap()
        };
        set(&mut h, |c| (c.listen, c.peers) = (Some("0.0.0.0:7070".into()), vec!["127.0.0.1:7071".into()]));
        let now = |r: &Host| (r.config_now().underlay(), r.config_now().announce_dev());
        assert_eq!(now(&running), (Some(Ipv4Addr::LOCALHOST), None));
        set(&mut h, |c| (c.underlay, c.announce_dev) = (Some(Ipv4Addr::new(10, 3, 0, 1)), Some("lo".into())));
        assert_eq!(now(&running), (Some(Ipv4Addr::new(10, 3, 0, 1)), Some("lo".into())));
        assert_eq!(running.config_now().advertise().unwrap().as_deref(), Some("10.3.0.1:7070"));
        set(&mut h, |c| c.announce_dev = Some("none".into()));
        assert_eq!(now(&running).1, None);
        set(&mut h, |c| (c.underlay, c.peers) = (None, vec!["flexvm-no-such-host.invalid:7070".into()]));
        assert_eq!(now(&running).0, None, "never loopback with a peer elsewhere");
    }

    #[test]
    fn fresh_process_derivation_uses_last_known_peers_without_dns() {
        let (_dir, mut h) = host("derive-no-dns");
        h.configure(|c| {
            c.peers = vec!["blackholed.example:7070".into()];
            Ok(())
        })
        .unwrap();
        let reopened = Host::open(&h.state, &h.run).unwrap();
        let now = || (reopened.config_now().underlay(), reopened.config_now().announce_dev());
        let cache = h.run.join("peers.json");
        // Seen by the listener, which could not look it up: never looked up here.
        std::fs::write(&cache, r#"{"names":{"blackholed.example:7070":[]}}"#).unwrap();
        let start = std::time::Instant::now();
        assert_eq!(now(), (None, None), "seen, no addresses: nothing derived, never wait for DNS");
        assert!(start.elapsed() < Duration::from_millis(500));

        std::fs::write(&cache, r#"{"names":{"blackholed.example:7070":["127.0.0.1"]}}"#).unwrap();
        let old = SystemTime::now() - Duration::from_secs(3600);
        File::options().write(true).open(&cache).unwrap().set_modified(old).unwrap();
        assert_eq!(now(), (Some(Ipv4Addr::LOCALHOST), None), "last-known addresses, whatever their age");

        std::fs::write(&cache, r#"{"names":{"blackholed.example:7070":["192.0.2.9"]}}"#).unwrap();
        let literal = Config { peers: vec!["192.0.2.9:7070".into()], ..Config::default() };
        assert_eq!(now(), (literal.underlay(), literal.announce_dev()), "derive the current route from cached addresses");

        h.configure(|c| {
            c.underlay = Some("192.0.2.10".parse().unwrap());
            c.announce_dev = Some("lo".into());
            Ok(())
        })
        .unwrap();
        std::fs::remove_file(cache).unwrap();
        assert_eq!(now(), (Some("192.0.2.10".parse().unwrap()), Some("lo".into())), "explicit settings override derivation");
        h.configure(|c| {
            c.announce_dev = Some("none".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(now().1, None);
    }

    /// Only a name with no entry in `RUN/peers.json` (no listener has run since a boot) is
    /// looked up by a process other than the listener, once per process; one it has seen
    /// never is, even with no addresses (#579).
    #[test]
    fn only_names_the_listener_has_not_seen_are_looked_up_once() {
        type Memo = LookedUp;
        let dir = crate::test_util::TempDir::new("derive-unseen");
        let cfg =
            Config { run: Some(dir.to_path_buf()), peers: vec!["seen.example:1".into(), "unseen.example:1".into(), "127.0.0.2:1".into()], ..Config::default() };
        let asked = std::cell::RefCell::new(Vec::<String>::new());
        let ok = |p: &str| {
            asked.borrow_mut().push(p.into());
            Ok(vec!["127.0.0.1".parse().unwrap()])
        };
        let hung = |p: &str| {
            asked.borrow_mut().push(p.into());
            Err(std::io::Error::other("DNS lookup timed out"))
        };
        let write = |json: &str| std::fs::write(dir.join("peers.json"), json).unwrap();
        let local = (Some(Ipv4Addr::LOCALHOST), None);

        // No listener yet: both names looked up, and found on this machine; once.
        let memo = Memo::default();
        assert_eq!(cfg.derived_by(&memo, Some(&ok)), (local.clone(), None));
        assert_eq!(asked.take(), ["seen.example:1", "unseen.example:1"]);
        assert_eq!(cfg.derived_by(&memo, Some(&ok)), (local.clone(), None));
        assert!(asked.take().is_empty(), "looked up once per process");
        // A caller under the host lock starts none, but has what this process found.
        assert_eq!(cfg.derived_by(&memo, None), (local.clone(), None));
        assert_eq!(cfg.derived_by(&Memo::default(), None).0, (None, None));
        assert!(asked.take().is_empty());

        // A lookup that hangs is waited for once: then the name counts as seen, with no addresses.
        let memo = Memo::default();
        let (d, why) = cfg.derived_by(&memo, Some(&hung));
        assert_eq!((d, asked.take().len()), ((None, None), 2));
        let why = why.unwrap();
        assert!(why.contains("start flexvm listen") && why.contains("seen.example:1, unseen.example:1") && why.contains("timed out"), "{why}");
        let (d, why) = cfg.derived_by(&memo, Some(&hung));
        assert_eq!((d, asked.take()), ((None, None), Vec::<String>::new()));
        assert!(why.unwrap().contains("start flexvm listen"), "the listener has still not looked them up");
        // Until the listener's entry stands instead.
        write(r#"{"names":{"seen.example:1":["127.0.0.1"],"unseen.example:1":["127.0.0.1"]}}"#);
        assert_eq!(cfg.derived_by(&memo, Some(&hung)), (local.clone(), None));
        assert!(asked.take().is_empty());

        // The listener saw one, with no addresses: only the other is looked up.
        write(r#"{"names":{"seen.example:1":[]}}"#);
        let (d, why) = cfg.derived_by(&Memo::default(), Some(&hung));
        assert_eq!((d, asked.take()), ((None, None), vec!["unseen.example:1".to_string()]));
        assert!(why.unwrap().contains("not looked up unseen.example:1 yet: start flexvm listen"));

        // It saw both: nothing is looked up, nor is the listener blamed.
        write(r#"{"names":{"seen.example:1":[],"unseen.example:1":["127.0.0.1"]}}"#);
        let (d, why) = cfg.derived_by(&Memo::default(), Some(&ok));
        assert_eq!((d, asked.take()), ((None, None), Vec::<String>::new()));
        let why = why.unwrap();
        assert!(why.starts_with("no peer elsewhere has a known IPv4 address") && !why.contains("flexvm listen"), "{why}");
    }

    #[test]
    fn the_underlay_is_derived_toward_a_peer_elsewhere() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let mine = |a: Ipv4Addr| a == Ipv4Addr::new(10, 0, 0, 5);
        let peers = |p: &[&[&str]]| p.iter().map(|a| a.iter().map(|s| ip(s)).collect()).collect::<Vec<Vec<_>>>();
        assert_eq!(toward(&[], mine), Toward::Local);
        // Loopback (either family) or one of this host's addresses: on this machine, skipped.
        assert_eq!(toward(&peers(&[&["127.0.0.1"], &["::1", "127.0.0.1"], &["10.0.0.5"]]), mine), Toward::Local);
        assert_eq!(toward(&peers(&[&["127.0.0.1"], &["::1"], &["192.168.1.11"]]), mine), Toward::Remote("192.168.1.11".parse().unwrap()));
        assert_eq!(toward(&peers(&[&["::ffff:192.168.1.11"]]), mine), Toward::Remote("192.168.1.11".parse().unwrap()));
        // A name that did not resolve, or an IPv6-only peer: elsewhere, address unknown.
        assert_eq!(toward(&peers(&[&["127.0.0.1"], &[]]), mine), Toward::Unknown);
        assert_eq!(toward(&peers(&[&["2001:db8::2"], &["192.168.1.12"]]), mine), Toward::Remote("192.168.1.12".parse().unwrap()));
        assert_eq!(toward(&peers(&[&["2001:db8::2"]]), mine), Toward::Unknown);
        // Loopback only without peers elsewhere; the listen address, or one set, comes first.
        let cfg =
            |listen: &str, peers: &[&str]| Config { listen: Some(listen.into()), peers: peers.iter().map(|p| p.to_string()).collect(), ..Config::default() };
        assert_eq!(cfg("0.0.0.0:7070", &["127.0.0.1:7071"]).underlay(), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(cfg("0.0.0.0:7070", &["127.0.0.1:7071", "flexvm-no-such-host.invalid:7070"]).underlay(), None);
        assert_eq!(cfg("10.1.0.1:7070", &["flexvm-no-such-host.invalid:7070"]).underlay(), Some("10.1.0.1".parse().unwrap()));
        let set = Config { underlay: Some("10.2.0.1".parse().unwrap()), ..cfg("0.0.0.0:7070", &["flexvm-no-such-host.invalid:7070"]) };
        assert_eq!(set.underlay(), Some("10.2.0.1".parse().unwrap()));
        // An IPv6 listener is told as it is, with or without an IPv4 underlay.
        assert_eq!(cfg("[2001:db8::1]:7070", &["flexvm-no-such-host.invalid:7070"]).advertise().unwrap().as_deref(), Some("[2001:db8::1]:7070"));
        // The kernel's route toward a peer elsewhere: its device and source, as set ones override.
        let any = cfg("0.0.0.0:7070", &["192.0.2.1:7070"]);
        // Whatever the kernel answers is checked, a failed lookup included: then nothing is derived, never loopback.
        let want = match crate::net::route_get("192.0.2.1".parse().unwrap()) {
            Ok((dev, src)) => (Some(src), crate::net::is_ethernet(&dev).then_some(dev)),
            Err(_) => (None, None),
        };
        assert_eq!((any.underlay(), any.announce_dev()), want);
        let off = Config { announce_dev: Some("none".into()), ..any };
        assert_eq!(off.announce_dev(), None);
    }

    #[test]
    fn derivation_names_unresolvable_peers_and_skips_links_without_arp() {
        let peers = |p: &[&str]| p.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        let lookup = |p: &str| match p {
            "far:1" => Ok(vec!["192.0.2.9".parse().unwrap()]),
            "near:1" => Ok(vec!["127.0.0.1".parse().unwrap()]),
            _ => Err(std::io::Error::other("no such name")),
        };
        let src: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let route = |ether: bool| {
            move |to: Ipv4Addr| -> Result<(String, Ipv4Addr, bool)> {
                assert_eq!(to, Ipv4Addr::new(192, 0, 2, 9));
                Ok(("eth0".into(), src, ether))
            }
        };
        let derive = |p: &[&str], ether| derive(&peers(p), lookup, |_| false, route(ether));
        assert_eq!(derive(&["near:1"], true), (Ok((Some(Ipv4Addr::LOCALHOST), None)), vec![]));
        assert_eq!(derive(&["near:1", "far:1"], true), (Ok((Some(src), Some("eth0".into()))), vec![]));
        // A WireGuard or tun device: the source still, but no ARP announcements on it.
        assert_eq!(derive(&["far:1"], false), (Ok((Some(src), None)), vec![]));
        let gone = || vec!["peer gone:1: no such name".to_string()];
        assert_eq!(derive(&["near:1", "gone:1"], true), (Err("no peer elsewhere has a known IPv4 address".into()), gone()));
        // A peer that did not resolve is named even when the derivation succeeds by another.
        assert_eq!(derive(&["gone:1", "far:1"], true), (Ok((Some(src), Some("eth0".into()))), gone()));
        let failed = super::derive(&peers(&["far:1"]), lookup, |_| false, |_| Err("no route toward 192.0.2.9: Network is unreachable".into()));
        assert_eq!(failed.0, Err("no route toward 192.0.2.9: Network is unreachable".into()));
    }

    /// A tap is this host's by its alias alone, whatever its name: hosts
    /// whose prefixes overlap (`fq`, `fq2`) never take each other's.
    #[test]
    fn taps_are_this_hosts_by_their_alias() {
        let (_h_dir, h) = host("alias");
        let me = Ident::me();
        let alias = tap_alias(&h.run, &me);
        assert_eq!(parse_tap_alias(&alias), Some((me.clone(), &*h.run.to_string_lossy())));
        for bad in ["", "flexvm", "flexvm 1 2", "flexvm 1 2 ", "flexvm x 2 /r", "flexvm 1 y /r", "flexvm1 2 /r", "other 1 2 /r"] {
            assert_eq!(parse_tap_alias(bad), None, "{bad:?}");
        }
        assert_eq!(parse_tap_alias("flexvm 1 2 /run/a b").map(|(o, r)| (o.pid, o.start, r)), Some((1, 2, "/run/a b")));
        let net = h.run.join("net");
        let other = h.run.join("other");
        std::fs::create_dir(&other).unwrap();
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
        let mut got = taps_of_at(&h.run, &net, false);
        got.sort_by_key(|t| t.1);
        assert_eq!(got, vec![("fq3e7t0".into(), 10, dead.clone()), ("fqx3e7".into(), 11, me.clone())]);
        let mut theirs = taps_of_at(&other, &net, false);
        theirs.sort_by_key(|t| t.1);
        assert_eq!(theirs, vec![("fq21a2bt0".into(), 12, me), ("fq21a2ct0".into(), 13, dead)]);
    }

    #[test]
    fn gc_collects_taps_from_deleted_run_dirs_only_after_the_owner_is_gone() {
        let d = crate::test_util::TempDir::new("orphan-taps");
        let run = d.join("run");
        let other = d.join("private run");
        let net = d.join("net");
        std::fs::create_dir(&other).unwrap();
        let dead = Ident { pid: 999_999_931, start: 1, boot: boot_id().into() };
        for (name, index, owner, tun) in [("dead", 10, dead.clone(), true), ("live", 11, Ident::me(), true), ("not-tun", 12, dead.clone(), false)] {
            let dev = net.join(name);
            std::fs::create_dir_all(&dev).unwrap();
            std::fs::write(dev.join("ifindex"), format!("{index}\n")).unwrap();
            std::fs::write(dev.join("ifalias"), format!("{}\n", tap_alias(&other, &owner))).unwrap();
            if tun {
                std::fs::write(dev.join("tun_flags"), "0x1802\n").unwrap();
            }
        }
        assert!(dead_taps_at(&run, &net).is_empty(), "another existing host's taps stay");
        std::fs::remove_dir(&other).unwrap();
        assert_eq!(dead_taps_at(&run, &net), vec![("dead".into(), 10, dead)]);
        assert!(taps_of_at(&run, &net, false).is_empty(), "pid-reuse cleanup still only selects this host's taps");
    }

    /// A VM process's own cgroup goes only once empty, whatever its pid
    /// (a reused one may have joined it): never killed.
    #[test]
    fn a_scope_goes_only_once_empty() {
        let d = crate::test_util::TempDir::new("scope-sweep");
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
        let (_h_dir, h) = host("noboot");
        let dead = Ident { pid: 999_999_931, start: 1, boot: String::new() };
        assert!(reap(&h.run, &dead).is_err(), "never reaped as another boot's");
        assert!(!boot_id().is_empty() && Ident::of(std::process::id()).is_some_and(|i| i.boot == boot_id()));
    }

    #[test]
    fn automatic_allocation_goes_on_from_the_last_one() {
        let (_h_dir, h) = host("hint");
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
        let (_h_dir, h) = host("revs");
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
        assert_eq!(h.addr(&l, x).unwrap().via, None, "a route for an older revision goes with it");
        assert!(!h.observe(&l, x, 7, 5, b).unwrap());
        assert!(h.observe(&l, x, 7, 6, b).unwrap());
        h.advance(&l, x, 7, 6).unwrap();
        assert_eq!(h.addr(&l, x).unwrap().via, b, "one for the same revision stays");
        assert!(h.observe(&l, x, 8, 0, a).unwrap(), "a newer generation starts over");
        assert!(h.observe(&l, x, 8, 0, None).unwrap() && !h.observe(&l, x, 8, 9, b).unwrap(), "a withdrawal takes every revision");
    }

    /// A peer borrows no address this host would not hand out itself (#415).
    #[test]
    fn no_fresh_loan_or_claim_of_a_zero_half_address() {
        let (_dir, mut h) = host("zero-half");
        h.cfg.vm_ips = "10.9.255.254-10.10.0.2".into();
        let l = h.lock().unwrap();
        for x in [ip("10.10.0.0"), ip("10.9.255.255")] {
            assert!(h.lend_new(&l, x).is_err() && h.claim_new(&l, "w", Some(x)).is_err(), "{x}");
        }
        h.lend_new(&l, ip("10.10.0.1")).unwrap();
    }

    /// A `vm_ips` change reaches a Host opened before it (a standby, the listener, a
    /// source): claims, fresh loans and a source's loan go by the range now (#521).
    #[test]
    fn claims_and_loans_go_by_the_range_as_host_json_has_it_now() {
        let (_dir, h) = host("live-range");
        let (old, new) = (ip("10.9.0.1"), ip("10.7.0.5"));
        let mut writer = h.clone();
        writer
            .configure(|c| {
                (c.vm_ips, c.dns) = ("10.7.0.5-10.7.0.5".into(), Some("10.7.0.53".into()));
                Ok(())
            })
            .unwrap();
        assert_eq!(h.cfg.vm_ips, "10.9.0.1-10.9.0.3", "opened before the change");
        assert_eq!(h.config_now().dns.as_deref(), Some("10.7.0.53"));
        let l = h.lock().unwrap();
        let e = h.claim_new(&l, "x", Some(old)).err().unwrap().to_string();
        assert!(e.contains("range 10.7.0.5-10.7.0.5"), "{e}");
        let e = h.lend_new(&l, old).unwrap_err().to_string();
        assert!(e.contains("range 10.7.0.5-10.7.0.5"), "{e}");
        let c = h.claim_new(&l, "x", None).unwrap();
        assert_eq!(c.ip, new);
        assert!(h.lend(&l, new, c.gen, 1, "t").unwrap(), "home by the new range: lent here");
    }

    /// A VM's address the range dropped while it ran: migrated away, its loan is still
    /// recorded, so the range taking it back never hands it out meanwhile (#521).
    #[test]
    fn an_address_a_range_change_dropped_stays_lent_when_its_vm_migrates() {
        let (_dir, mut h) = host("dropped-range");
        let set = |h: &mut Host, r: &str| {
            h.configure(|c| {
                c.vm_ips = r.into();
                Ok(())
            })
            .unwrap()
        };
        set(&mut h, "10.9.0.1-10.9.0.1");
        let x = ip("10.9.0.1");
        let l = h.lock().unwrap();
        let c = h.claim_new(&l, "vm", None).unwrap();
        let gen = c.gen;
        assert_eq!(c.ip, x);
        drop(l);
        set(&mut h, "10.9.0.2-10.9.0.2");
        let l = h.lock().unwrap();
        assert!(h.lend(&l, x, gen, 1, "t").unwrap(), "lent though out of range now");
        // The source lets go once the target has it.
        h.release(&l, x, "vm", None).unwrap();
        c.keep();
        drop(l);
        set(&mut h, "10.9.0.1-10.9.0.1");
        let l = h.lock().unwrap();
        assert_eq!(h.addr(&l, x).unwrap().lent, Some(gen));
        assert!(h.claim_new(&l, "w", Some(x)).err().unwrap().to_string().contains("lent out"));
        assert!(h.claim_new(&l, "w", None).is_err(), "nothing else to hand out");
        assert!(h.lend_new(&l, x).is_err());
        // Withdrawn (the VM gone wherever it ran): free again.
        assert!(h.observe(&l, x, gen, 0, None).unwrap());
        assert_eq!(h.claim_new(&l, "w", None).unwrap().ip, x);
    }

    #[test]
    fn addresses_are_lent_to_restoring_peers_only_when_free() {
        let (_h_dir, h) = host("lend");
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

    #[test]
    fn an_owed_outcome_keeps_the_loan_until_the_target_says() {
        let (_h_dir, h) = host("owed");
        let x = ip("10.9.0.2");
        let gen = {
            let l = h.lock().unwrap();
            let _v = h.take_name("v", false).unwrap();
            let c = h.claim_new(&l, "v", Some(x)).unwrap();
            assert!(h.lend(&l, x, c.gen, 1, "t").unwrap());
            let gen = c.gen;
            c.release(&l).unwrap();
            gen
        };
        let by = |start| Ident { start, ..Ident::me() };
        for id in [7, 8] {
            h.owe(id, &Owed { to: format!("t{id}"), ip: x, gen, by: by(id) }).unwrap();
        }
        assert!(h.owes(&by(7)) && !h.owes(&by(9)), "the target keeps its record for an owed source");
        let lent = |h: &Host| h.addr(&h.lock().unwrap(), x).unwrap().lent;
        let (mut done, mut withdrawn) = (Vec::new(), Vec::new());
        // Unknown, unreachable or still committed: nothing changes.
        for answer in [Err("down".into()), Ok("committed".to_string()), Ok("pending".to_string())] {
            let a = answer.map_err(|e: String| Error::from(e));
            h.settle_owed_with(
                5,
                |_, _| a.as_ref().map(|s| s.clone()).map_err(|e| e.to_string().into()),
                |t, id| done.push((t.to_string(), id)),
                |ip, g| withdrawn.push((ip, g)),
            );
            assert_eq!(lent(&h), Some(gen));
            assert!(h.owed_path(7).exists() && h.owed_path(8).exists());
            assert!(h.claim_new(&h.lock().unwrap(), "w", Some(x)).is_err(), "never handed out meanwhile");
        }
        assert!(done.is_empty() && withdrawn.is_empty());
        // Released: the VM is the target's; the loan stays, the target is told done.
        h.settle_owed_with(
            5,
            |t, _| Ok(if t == "t7" { "released" } else { "committed" }.into()),
            |t, id| done.push((t.to_string(), id)),
            |ip, g| withdrawn.push((ip, g)),
        );
        assert_eq!(done, [("t7".to_string(), 7)]);
        assert!(!h.owed_path(7).exists() && !h.owes(&by(7)) && withdrawn.is_empty());
        assert_eq!(lent(&h), Some(gen), "lent to the target that has it");
        // Aborted: nobody runs it; withdrawn, and the address is free again.
        h.settle_owed_with(5, |_, _| Ok("aborted".into()), |t, id| done.push((t.to_string(), id)), |ip, g| withdrawn.push((ip, g)));
        assert_eq!(withdrawn, [(x, gen)]);
        assert!(!h.owed_path(8).exists() && lent(&h).is_none());
        let a = h.addr(&h.lock().unwrap(), x).unwrap();
        assert!(a.withdrawn && a.seen == gen);
        let _w = h.take_name("w", false).unwrap();
        assert!(h.claim_new(&h.lock().unwrap(), "w", Some(x)).unwrap().gen > gen);
    }

    #[test]
    fn an_interrupted_owed_write_is_not_a_record_and_is_swept_once_its_writer_is_gone() {
        let (_h_dir, h) = host("owed-tmp");
        let dir = h.state.join("owed");
        // An interrupted write: garbage under a temporary name, by a dead process and by this one.
        let dead = dir.join(".7.4294967.tmp");
        let live = dir.join(format!(".8.{}.tmp", std::process::id()));
        std::fs::write(&dead, b"{\"to\": trunc").unwrap();
        std::fs::write(&live, b"").unwrap();
        let by = Ident { start: 1, ..Ident::me() };
        assert!(!h.owes(&by), "a temporary file owes nothing: target retirement goes on");
        h.settle_owed_with(5, |_, _| panic!("no records"), |_, _| {}, |_, _| {});
        assert!(!dead.exists(), "swept: its writer is gone");
        assert!(live.exists(), "kept: its writer may still rename it into place");
        // A record under its own name that cannot be read still counts (fail closed).
        std::fs::write(dir.join("9"), b"{corrupt").unwrap();
        assert!(h.owes(&by));
    }

    #[test]
    fn reclaim_withdraws_a_lent_address_and_forgets_its_owed_outcome() {
        let (_h_dir, h) = host("reclaim");
        let x = ip("10.9.0.2");
        assert!(h.reclaim(x, 1).unwrap_err().to_string().contains("not lent"));
        let gen = {
            let l = h.lock().unwrap();
            let _v = h.take_name("v", false).unwrap();
            let c = h.claim_new(&l, "v", Some(x)).unwrap();
            h.lend(&l, x, c.gen, 1, "t").unwrap();
            let gen = c.gen;
            c.release(&l).unwrap();
            gen
        };
        h.owe(4, &Owed { to: "lost:1".into(), ip: x, gen, by: Ident { start: 4, ..Ident::me() } }).unwrap();
        h.owe(5, &Owed { to: "other:1".into(), ip: ip("10.9.0.3"), gen: 1, by: Ident { start: 5, ..Ident::me() } }).unwrap();
        assert_eq!(h.lent_to(x).unwrap(), Some((gen, vec![(4, "lost:1".to_string())])));
        let warning = crate::reclaim(&h, &x.to_string(), None).unwrap_err().to_string();
        assert!(warning.contains(&format!("Then: flexvm reclaim {x} --force {gen}")), "{warning}");
        assert_eq!(h.reclaim(x, gen).unwrap(), (gen, vec![(4, "lost:1".to_string())]));
        let a = h.addr(&h.lock().unwrap(), x).unwrap();
        assert!(a.withdrawn && a.lent.is_none());
        assert!(!h.owed_path(4).exists() && h.owed_path(5).exists(), "only that address's");
        let _w = h.take_name("w", false).unwrap();
        assert!(h.claim_new(&h.lock().unwrap(), "w", Some(x)).unwrap().gen > gen);
    }

    #[test]
    fn reclaim_refuses_a_generation_lent_again_since_confirmation() {
        let (_h_dir, h) = host("reclaim-generation");
        let x = ip("10.9.0.2");
        h.put_addr(x, &Addr { seen: 4, lent: Some(4), ..Addr::default() }, false).unwrap();
        let (confirmed, _) = h.lent_to(x).unwrap().unwrap();
        // The VM came home and left again while the operator checked its old target.
        h.put_addr(x, &Addr { seen: 5, lent: Some(5), ..Addr::default() }, false).unwrap();
        let owed = Owed { to: "live:1".into(), ip: x, gen: 5, by: Ident::me() };
        h.owe(7, &owed).unwrap();
        let error = h.reclaim(x, confirmed).unwrap_err().to_string();
        assert!(error.contains("generation 5, not confirmed generation 4"), "{error}");
        let a = h.addr(&h.lock().unwrap(), x).unwrap();
        assert_eq!((a.seen, a.lent, a.withdrawn), (5, Some(5), false));
        assert!(h.owed_path(7).exists() && !h.notice_path(x).exists());
        // A loan that ended meanwhile is refused too.
        h.put_addr(x, &Addr { seen: 5, ..Addr::default() }, false).unwrap();
        assert!(h.reclaim(x, confirmed).unwrap_err().to_string().contains("not lent"));
    }

    #[test]
    fn owed_outcomes_respect_the_budget_and_ask_an_unreachable_target_once() {
        let (_h_dir, h) = host("owed-budget");
        let x = ip("10.9.0.3");
        for id in 1..=6 {
            h.owe(id, &Owed { to: if id <= 3 { "down".into() } else { "up".into() }, ip: x, gen: 1, by: Ident { start: id, ..Ident::me() } }).unwrap();
        }
        let mut asked = Vec::new();
        h.settle_owed_with(
            4,
            |t, id| {
                asked.push(id);
                if t == "down" {
                    Err("unreachable".into())
                } else {
                    Ok("pending".into())
                }
            },
            |_, _| panic!("nothing released"),
            |_, _| panic!("nothing aborted"),
        );
        assert_eq!(asked, [1, 4], "four records visited, the unreachable target asked once");
        asked.clear();
        h.settle_owed_with(
            4,
            |_, id| {
                asked.push(id);
                Ok("pending".into())
            },
            |_, _| {},
            |_, _| {},
        );
        assert_eq!(asked, [5, 6, 1, 2], "the next pass goes on from the cursor");
    }

    fn released_migration(h: &Host, id: u64, source: &str) {
        store(&h.mig_path(id), &Mig::Released { source: source.into(), by: Some(Ident { start: id, ..Ident::me() }), ip: None }, false).unwrap();
    }

    #[test]
    fn migration_retirement_sweeps_dead_writers_under_the_host_lock() {
        let (_h_dir, h) = host("migs-tmp");
        let dir = h.state.join("migs");
        let dead = dir.join(".7.999999971.tmp");
        let live = dir.join(format!(".8.{}.tmp", std::process::id()));
        let unrelated = dir.join(".not-a-write");
        for path in [&dead, &live, &unrelated] {
            std::fs::write(path, b"{").unwrap();
        }
        let l = h.lock().unwrap();
        let other = h.clone();
        let (done, finished) = std::sync::mpsc::channel();
        let sweep = std::thread::spawn(move || {
            other.retire_migrations_with(0, |_, _| panic!("no records"));
            done.send(()).unwrap();
        });
        assert!(finished.recv_timeout(Duration::from_millis(50)).is_err(), "sweep must wait for writers' host lock");
        assert!(dead.exists());
        drop(l);
        sweep.join().unwrap();
        assert!(!dead.exists(), "interrupted write swept");
        assert!(live.exists(), "a live writer may still publish its file");
        assert!(unrelated.exists());
    }

    #[test]
    fn aborted_arrivals_release_only_the_matching_dead_claim_and_keep_the_loan() {
        for committed in [false, true] {
            let (_h_dir, h) = host(if committed { "aborted-committed" } else { "aborted-pending" });
            let x = ip("10.9.0.1");
            let owner = dead_owner(&h, 999_999_972, &[]);
            let l = h.lock().unwrap();
            h.lend(&l, x, 8, 1, "source").unwrap();
            h.claim_arrival(&l, "target", x, 8, 2, 7).unwrap().keep();
            h.update(&l, x, false, |a| a.holder_id = Some(owner.clone())).unwrap();
            let mut expected = h.addr(&l, x).unwrap();
            (expected.holder, expected.holder_id, expected.arriving) = (None, None, None);
            // Neither another migration's claim nor another owner's is this arrival's.
            let y = ip("10.9.0.2");
            let z = ip("10.9.0.3");
            h.claim_arrival(&l, "other-migration", y, 8, 2, 9).unwrap().keep();
            h.update(&l, y, false, |a| a.holder_id = Some(owner.clone())).unwrap();
            h.claim_arrival(&l, "other-owner", z, 8, 2, 7).unwrap().keep();
            let unchanged = [h.addr(&l, y).unwrap(), h.addr(&l, z).unwrap()];
            let record = if committed { Mig::Committed { owner } } else { Mig::Pending { owner, ip: Some(x) } };
            store(&h.mig_path(7), &record, false).unwrap();
            drop(l);
            assert_eq!(h.mig_status(7).unwrap(), "aborted");
            assert!(!h.mig_path(7).exists());
            let l = h.lock().unwrap();
            assert_eq!(h.addr(&l, x).unwrap(), expected);
            assert_eq!([h.addr(&l, y).unwrap(), h.addr(&l, z).unwrap()], unchanged);
        }
    }

    #[test]
    fn retirement_respects_record_budget() {
        let (_h_dir, h) = host("retire-budget");
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
        let (_h_dir, h) = host("retire-continue");
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
        let (_h_dir, h) = host("retire-endpoints");
        for (id, source) in [(1, "unreachable"), (2, "reachable"), (3, "unreachable"), (4, "reachable"), (5, "unknown"), (6, "unreachable")] {
            released_migration(&h, id, source);
        }
        store(&h.mig_path(7), &Mig::Released { source: "reachable".into(), by: None, ip: None }, false).unwrap();
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
        let (_h_dir, h) = host("retire-lock");
        released_migration(&h, 1, "reachable");
        let gc = private_file(&locks(&h.run).join("gc")).unwrap();
        flock(&gc, libc::LOCK_EX | libc::LOCK_NB).unwrap();
        let mut queried = false;
        h.retire_migrations_with(1, |_, _| {
            let retirement = File::open(locks(&h.run).join("retire")).unwrap();
            assert!(flock(&retirement, libc::LOCK_EX | libc::LOCK_NB).is_err());
            queried = true;
            Ok(false)
        });
        assert!(queried, "the local cleanup lock does not block retirement");
        let retirement = File::open(locks(&h.run).join("retire")).unwrap();
        flock(&retirement, libc::LOCK_EX | libc::LOCK_NB).unwrap();
        h.retire_migrations_with(1, |_, _| panic!("busy retirement must be skipped"));
    }

    #[test]
    fn a_pass_lets_go_of_its_lock_though_a_forked_child_shares_it() {
        const CHILD: &str = "FLEXVM_TEST_RETIRE_FORK";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "host::tests::a_pass_lets_go_of_its_lock_though_a_forked_child_shares_it"])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "retirement fork child: {status}");
            return;
        }
        let (_h_dir, h) = host("retire-fork");
        released_migration(&h, 1, "reachable");
        let (forked, mut told) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut spawner = None;
        h.retire_migrations_with(1, |_, _| {
            // Another thread forks while the pass holds its lock, and its child is slow to
            // exec, as one making a cgroup scope in `pre_exec` is.
            let fd = forked.as_raw_fd();
            spawner = Some(std::thread::spawn(move || {
                let mut cmd = std::process::Command::new("true");
                unsafe {
                    std::os::unix::process::CommandExt::pre_exec(&mut cmd, move || {
                        libc::write(fd, b"f".as_ptr().cast(), 1);
                        std::thread::sleep(Duration::from_secs(1));
                        Ok(())
                    })
                };
                cmd.status().unwrap();
            }));
            std::io::Read::read_exact(&mut told, &mut [0]).unwrap();
            Ok(false)
        });
        let retirement = File::open(locks(&h.run).join("retire")).unwrap();
        let free = flock(&retirement, libc::LOCK_EX | libc::LOCK_NB).is_ok();
        spawner.unwrap().join().unwrap();
        assert!(free, "the pass let go of its lock, not only closed it");
    }

    /// #533: the record can trail the revision its holder here runs at; what the holder published
    /// decides then, with no process asked. Only the record's holder instance's counts, and only
    /// while it is alive: a crash leaves the record to decide.
    #[test]
    fn announcements_are_judged_by_the_holders_published_revision() {
        let (_dir, h) = host("live-rev");
        let (x, gone, a) = (ip("10.9.4.1"), ip("10.9.4.2"), Some(ip("192.0.2.1")));
        let l = h.lock().unwrap();
        let _y = h.take_name("y", false).unwrap();
        h.claim_incoming(&l, "y", x, 7, None).unwrap().keep();
        let me = Ident::me();
        std::fs::create_dir_all(h.run.join("live")).unwrap();
        // Another instance's (its pid reused) is not believed.
        store(&h.live_path(x), &Live { id: Ident { start: me.start + 1, ..me.clone() }, gen: 7, rev: 5 }, false).unwrap();
        assert_eq!(h.live(&l, x).unwrap(), None);
        // Its own: past the record, which trails it (a failed write, an arrival's deferred one).
        h.publish_live(&l, x, 7, 1).unwrap();
        assert_eq!((h.live(&l, x).unwrap(), h.addr(&l, x).unwrap().rev), (Some(1), 0));
        assert!(!h.observe(&l, x, 7, 0, a).unwrap(), "a late announcement of the record's revision is stale");
        assert_eq!(h.addr(&l, x).unwrap().via, None);
        assert!(h.observe(&l, x, 7, 1, a).unwrap() && h.addr(&l, x).unwrap().via == a, "not older: taken");
        assert!(h.observe(&l, x, 7, 0, None).unwrap(), "a withdrawal is not an announcement");
        // A dead holder's file is stale: the record decides.
        let dead = dead_owner(&h, 999_999_940, &[]);
        let crashed = Addr { seen: 7, held: 7, holder: Some("z".into()), holder_id: Some(dead.clone()), ..Default::default() };
        h.put_addr(gone, &crashed, false).unwrap();
        store(&h.live_path(gone), &Live { id: dead, gen: 7, rev: 5 }, false).unwrap();
        assert_eq!(h.live(&l, gone).unwrap(), None);
        assert!(h.observe(&l, gone, 7, 0, a).unwrap());
    }

    /// #533: a published revision goes with its claim (released, withdrawn or kept past the
    /// process), only if that instance published it; gc sweeps what dead processes left.
    #[test]
    fn published_revisions_go_with_their_claims_and_dead_writers() {
        let (_dir, h) = host("live-gc");
        let (x, y, z) = (ip("10.9.6.1"), ip("10.9.6.2"), ip("10.9.6.3"));
        let me = Ident::me();
        let l = h.lock().unwrap();
        let _n = h.take_name("n", false).unwrap();
        let exists = |ip: Ipv4Addr| h.live_path(ip).exists();
        let claim = h.claim_incoming(&l, "n", x, 7, None).unwrap();
        h.publish_live(&l, x, 7, 1).unwrap();
        claim.release(&l).unwrap();
        assert!(!exists(x), "released, its revision goes");
        let claim = h.claim_incoming(&l, "n", x, 7, None).unwrap();
        h.publish_live(&l, x, 7, 2).unwrap();
        claim.keep();
        assert!(!exists(x), "kept past the process (suspended), it goes");
        h.release(&l, x, "n", None).unwrap();
        // Another instance's (published since) stays when this one lets go.
        let claim = h.claim_incoming(&l, "n", y, 7, None).unwrap();
        store(&h.live_path(y), &Live { id: Ident { start: me.start + 1, ..me.clone() }, gen: 7, rev: 3 }, false).unwrap();
        drop(claim);
        assert!(exists(y), "another instance's stays");
        std::fs::remove_file(h.live_path(y)).unwrap();
        // What dead processes left: a writer the record no longer names, unreadable files and
        // dead writers' temporary files go; a named dead writer's waits for its claim's sweep.
        let (gone, named) = (dead_owner(&h, 999_999_930, &[]), dead_owner(&h, 999_999_931, &[]));
        store(&h.live_path(x), &Live { id: gone, gen: 7, rev: 4 }, false).unwrap();
        let held = Addr { seen: 7, held: 7, holder: Some("m".into()), holder_id: Some(named.clone()), ..Default::default() };
        h.put_addr(y, &held, false).unwrap();
        store(&h.live_path(y), &Live { id: named, gen: 7, rev: 4 }, false).unwrap();
        let _claim = h.claim_incoming(&l, "n", z, 7, None).unwrap();
        h.publish_live(&l, z, 7, 1).unwrap();
        let live = h.run.join("live");
        std::fs::write(live.join("10.9.6.4"), b"{").unwrap();
        std::fs::write(live.join(".10.9.6.5.999999930.tmp"), b"").unwrap();
        let mine = format!(".10.9.6.5.{}.tmp", std::process::id());
        std::fs::write(live.join(&mine), b"").unwrap();
        drop(l);
        h.sweep_live().unwrap();
        let mut left: Vec<_> = std::fs::read_dir(&live).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        assert_eq!(left, [mine, y.to_string(), z.to_string()]);
    }

    #[test]
    fn committed_arrival_does_not_need_its_routing_revision_for_recovery() {
        let (_dir, h) = host("arrival-revision");
        let x = ip("10.9.2.1");
        let mut record = h.mig_begin(1, "", None, Some(x)).unwrap();
        let l = h.lock().unwrap();
        let claim = h.claim_arrival(&l, "target", x, 8, 2, 1).unwrap();
        let before = h.addr(&l, x).unwrap();
        assert_eq!(before.rev, 0, "the incoming revision must not outrank the source before commit");
        record.commit(&l).unwrap();
        drop(l);
        assert_eq!(h.mig_status(1).unwrap(), "committed", "a live target owns it even before the deferred revision write");
        assert_eq!(h.addr(&h.lock().unwrap(), x).unwrap(), before);

        // Model a crash before the deferred write: the durable claim and commit
        // remain, with a dead owner. Recovery must clear that arrival before it
        // tells the source it may resume; no routing revision is needed.
        let dead = dead_owner(&h, 999_999_950, &[]);
        let l = h.lock().unwrap();
        let mut crashed = before.clone();
        crashed.holder_id = Some(dead.clone());
        h.put_addr(x, &crashed, true).unwrap();
        store(&h.mig_path(1), &Mig::Committed { owner: dead }, true).unwrap();
        drop(l);
        assert_eq!(h.mig_status(1).unwrap(), "aborted");
        let recovered = h.addr(&h.lock().unwrap(), x).unwrap();
        assert!(recovered.holder.is_none() && recovered.arriving.is_none());
        assert_eq!((recovered.seen, recovered.rev), (8, 0));
        claim.keep();
    }

    #[test]
    fn migrations_are_fenced() {
        let (_h_dir, h) = host("migs");
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
        assert!(h.lend(&h.lock().unwrap(), home, 9, 3, "t").unwrap(), "made the loan");
        assert!(!h.lend(&h.lock().unwrap(), home, 9, 3, "t").unwrap(), "a loan it did not make is not its to undo");
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
        store(&h.mig_path(8), &Mig::Released { source: "127.0.0.1:1".into(), by: Some(Ident::me()), ip: None }, false).unwrap();
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
    pub(crate) fn pin_clock(ms: u64) {
        PINNED_MS.with(|p| p.set(Some(ms)));
    }

    /// `grant_inner` against `AVAIL`.
    fn grant_at(h: &Host, mib: u64, floor: Floor, hold: bool) -> std::result::Result<(u64, Option<Hold>), Error> {
        h.grant_inner(mib, floor, hold, None, || Some(AVAIL)).unwrap()
    }

    #[test]
    fn last_good_config_is_shared_by_clones_and_isolated_from_other_hosts() {
        let (_h_dir, mut h) = host("config-isolated");
        h.configure(|c| {
            c.peers = vec!["10.1.0.8:7070".into()];
            Ok(())
        })
        .unwrap();
        let clone = h.clone();
        let (_other_dir, other) = host("config-unrelated");
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
        let (_h_dir, mut h) = host("config-stamp");
        h.configure(|_| Ok(())).unwrap();
        let running = h.clone();
        let path = h.state.join("host.json");
        let first = File::open(&path).unwrap();
        let time = first.metadata().unwrap().modified().unwrap();
        let times = std::fs::FileTimes::new().set_modified(time);
        for reserve in [2048, 4096] {
            let previous = File::open(&path).unwrap();
            h.configure(|c| {
                c.reserve_mib = Some(reserve);
                Ok(())
            })
            .unwrap();
            File::open(&path).unwrap().set_times(times).unwrap();
            assert_eq!(stamp(&path).unwrap().0, time);
            assert_ne!(stamp(&path).unwrap().1, previous.metadata().unwrap().ino());
            assert_eq!(running.config_now().reserve(), reserve);
        }
    }

    #[test]
    fn peer_generations_are_bounded_before_storing() {
        let (_h_dir, h) = host("gen-bound");
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
            let (_h_dir, h) = host(tag);
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
        let (_h_dir, mut h) = host("grant-clock");
        h.cfg.reserve_mib = Some(AVAIL - 1000);
        let before = boottime_ms();
        grant_at(&h, 1000, Floor::Reserve, false).unwrap();
        let path = h.grants();
        let grants: Vec<(u64, u64, u64)> = load(&path).unwrap().unwrap();
        assert!(grants[0].0 >= before && grants[0].0 <= boottime_ms());
        // From here what counts depends on stamps' ages alone, not on how long the test takes.
        pin_clock(grants[0].0);
        let mut other = Host::open(&h.state, &h.run).unwrap();
        other.cfg.reserve_mib = h.cfg.reserve_mib;
        assert!(grant_at(&other, 1, Floor::Reserve, false).is_err(), "another host handle sees the pending grant");
        // A future stamp is dropped rather than extending the cooldown indefinitely.
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

    #[test]
    fn admission_counts_recent_grants() {
        let (_h_dir, mut h) = host("admit");
        let admit = |h: &Host, mib| grant_at(h, mib, Floor::Reserve, false).is_ok();
        h.cfg.reserve_mib = Some(AVAIL - 3000);
        pin_clock(boottime_ms());
        assert!(admit(&h, 1000) && admit(&h, 1000));
        assert!(!admit(&h, 1001), "recent grants count as used");
        // A start that did not happen gives its grant back, by id: only its own.
        let id = grant_at(&h, 900, Floor::Reserve, false).unwrap().0;
        assert!(!admit(&h, 101));
        h.refund(id);
        h.refund(u64::MAX);
        assert!(admit(&h, 500) && !admit(&h, 501));
        h.cfg.reserve_mib = Some(AVAIL + 1);
        assert!(!admit(&h, 1));
    }

    /// An unreadable MemAvailable, or a host lock not had in time, is an
    /// error, never a refusal (which marks a VM throttled) nor 0 MiB
    /// available; nothing is granted.
    #[test]
    fn admission_fails_closed_when_holds_cannot_be_read() {
        let (_h_dir, mut h) = host("holds-unreadable");
        h.cfg.reserve_mib = Some(0);
        // Its grants must all count to the end, however long a loaded machine takes over it.
        pin_clock(boottime_ms());
        let grants = || load::<Vec<(u64, u64, u64)>>(&h.grants()).unwrap().unwrap_or_default();
        let grant = || h.grant_inner(1, Floor::Reserve, false, None, || Some(AVAIL)).map(|r| r.ok().map(|g| g.0));
        // No holds directory yet: nothing held, a complete scan.
        assert!(grant().unwrap().is_some());
        // Unreadable (here not a directory): an error that grants nothing, never "no holds".
        let dir = locks(&h.run).join("holds");
        private_dir(&locks(&h.run)).unwrap();
        std::fs::write(&dir, b"").unwrap();
        assert!(grant().unwrap_err().to_string().contains("cannot be counted"));
        assert_eq!(grants().len(), 1);
        assert!(h.grant_inner(1, Floor::Reserve, true, None, || Some(AVAIL)).is_err(), "nor a held grant");
        std::fs::remove_file(&dir).unwrap();
        assert!(grant().unwrap().is_some() && grants().len() == 2);
    }

    #[test]
    fn admission_errors_are_not_refusals() {
        let (_h_dir, mut h) = host("admit-err");
        h.cfg.reserve_mib = Some(0);
        let grants = || load::<Vec<(u64, u64, u64)>>(&h.grants()).unwrap().unwrap_or_default();
        let grant = |avail: Option<u64>| h.grant_inner(1, Floor::Reserve, false, None, || avail).map(|r| r.ok().map(|g| g.0));
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
        let err = h.grant(1, Some(std::time::Instant::now() + Duration::from_millis(50))).unwrap_err();
        assert_eq!(err.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::WouldBlock);
        release.0.send(()).unwrap();
        t.join().unwrap();
        assert_eq!(grants().len(), 1);
    }

    #[test]
    fn admission_and_eviction_read_the_marks_as_they_change() {
        let (_h_dir, mut h) = host("marks");
        h.configure(|c| {
            c.reserve_mib = Some(AVAIL - 3000);
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
            c.reserve_mib = Some(AVAIL - 1000);
            Ok(())
        })
        .unwrap();
        assert_eq!(running.config_now().reserve(), AVAIL - 1000);
        assert!(grant_at(&running, 700, Floor::Reserve, false).is_err() && grant_at(&running, 699, Floor::Reserve, false).is_ok());
    }

    #[test]
    fn disk_restore_reservation_survives_expiry_and_can_be_completed_or_refunded() {
        let (_h_dir, h) = host("disk-restore-hold");
        let charge = crate::limit::allowance(1600);
        let grant = |mib, held| h.grant_inner(mib, Floor::Reserve, held, None, || Some(h.cfg.reserve() + charge)).unwrap();
        let (id, hold) = grant(charge, true).unwrap();
        let hold = Mutex::new(hold);
        let path = h.grants();
        store(&path, &vec![(0u64, charge, id)], false).unwrap();
        assert!(grant(1, false).is_err(), "disk pull reservation counts after ten seconds");
        // Pages come in: it counts only what is still to come, never more again.
        h.shrink_hold(&hold, 100).unwrap();
        h.shrink_hold(&hold, 200).unwrap();
        assert!(locks(&h.run).join(format!("holds/{id}-100")).exists());
        assert!(grant(charge - 99, false).is_err());
        assert!(grant(charge - 100, false).is_ok());
        store(&path, &vec![(0u64, charge, id)], false).unwrap();
        // A grant's temp file left by a dead process goes.
        let tmp = locks(&h.run).join("holds/.7");
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

    /// A held grant grows only if the extra is admitted, then counts once,
    /// grown; refused, it counts as before. Its id stays for a refund.
    #[test]
    fn a_held_grant_grows_only_when_admitted() {
        let (_h_dir, mut h) = host("grow-hold");
        (h.cfg.reserve_mib, h.cfg.evict_mib) = (Some(AVAIL - 3000), Some(AVAIL - 1500));
        pin_clock(boottime_ms());
        let admit = |h: &Host, mib| grant_at(h, mib, Floor::Reserve, false).is_ok();
        let (id, hold) = grant_at(&h, 1000, Floor::Reserve, true).unwrap();
        let hold = Mutex::new(hold);
        let grow = |mib, floor| h.grow_hold_inner(&hold, mib, floor, None, || Some(AVAIL));
        // 2000 MiB left: not 2001 more, and refused it still counts 1000.
        assert!(grow(2001, Floor::Reserve).unwrap().unwrap_err().to_string().contains("not enough memory"));
        assert!(locks(&h.run).join(format!("holds/{id}-1000")).exists());
        // Above the eviction mark there is less room.
        assert!(grow(501, Floor::EvictMark).unwrap().unwrap_err().to_string().contains("eviction mark"));
        grow(500, Floor::EvictMark).unwrap().unwrap();
        grow(1000, Floor::Reserve).unwrap().unwrap();
        assert!(locks(&h.run).join(format!("holds/{id}-2500")).exists());
        // Counted once, grown (its own grant in the window is the hold, not more).
        assert!(!admit(&h, 501) && admit(&h, 500));
        // Pages in: it shrinks as before; dropped, it no longer counts.
        h.shrink_hold(&hold, 100).unwrap();
        assert!(locks(&h.run).join(format!("holds/{id}-100")).exists());
        drop(hold.lock().unwrap().take());
        assert!(grow(1, Floor::Reserve).unwrap_err().to_string().contains("no held grant"));
    }

    /// Sizes past any host's (a peer's, unchecked) saturate: refused, and never wrapped round so later ones fit.
    #[test]
    fn admission_saturates() {
        let (_h_dir, mut h) = host("saturate");
        h.cfg.reserve_mib = Some(AVAIL - 3000);
        pin_clock(boottime_ms());
        assert_eq!(crate::limit::allowance(u64::MAX), u64::MAX);
        assert!(grant_at(&h, u64::MAX, Floor::Reserve, false).is_err());
        let hold = Mutex::new(grant_at(&h, 1000, Floor::Reserve, true).unwrap().1);
        assert!(h.grow_hold_inner(&hold, u64::MAX, Floor::Reserve, None, || Some(AVAIL)).unwrap().is_err());
        // A grant of nearly everything, with the hold, sums past u64::MAX: all else is refused.
        let mut grants: Vec<(u64, u64, u64)> = load(&h.grants()).unwrap().unwrap();
        grants.push((boottime_ms(), u64::MAX - 10, 5));
        store(&h.grants(), &grants, false).unwrap();
        assert!(grant_at(&h, 1, Floor::Reserve, false).is_err());
    }

    #[test]
    fn held_grants_count_past_the_window_until_dropped_or_their_owner_is_gone() {
        let (_h_dir, mut h) = host("held");
        let admit = |h: &Host, mib| grant_at(h, mib, Floor::Reserve, false).is_ok();
        h.cfg.reserve_mib = Some(AVAIL - 3000);
        let hold = grant_at(&h, 2000, Floor::Reserve, true).unwrap().1.unwrap();
        // The window passes (the grant ages out): held, it still counts, once.
        let path = h.grants();
        let aged: Vec<(u64, u64, u64)> = load::<Vec<(u64, u64, u64)>>(&path).unwrap().unwrap().into_iter().map(|g| (0, g.1, g.2)).collect();
        store(&path, &aged, false).unwrap();
        assert!(!admit(&h, 1001) && admit(&h, 1000), "a held grant counts after the window, once");
        drop(hold);
        assert!(admit(&h, 1500));
        // A hold whose lock nobody has (its process died; or its removal failed) goes.
        store(&path, &Vec::<(u64, u64, u64)>::new(), false).unwrap();
        std::fs::write(locks(&h.run).join("holds").join("99-2000"), b"").unwrap();
        assert!(admit(&h, 2500));
        assert!(!locks(&h.run).join("holds").join("99-2000").exists());
    }

    #[test]
    fn a_bounded_flock_wait_wakes_when_the_holder_lets_go() {
        let base = crate::test_util::TempDir::new("flock-by");
        let path = base.join("lock");
        let open = || private_file(&path).unwrap();
        let held = Flock::new(open(), libc::LOCK_EX).unwrap();
        // Let go of while the wait is under way: had then, long before its deadline.
        let (tx, rx) = std::sync::mpsc::channel();
        let start = std::time::Instant::now();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(held);
            tx.send(()).unwrap();
        });
        let got = flock_by(&path, start + Duration::from_secs(30)).unwrap();
        let had = start.elapsed();
        rx.recv().unwrap();
        releaser.join().unwrap();
        assert!(had >= Duration::from_millis(100) && had < Duration::from_secs(5), "had once let go of, not at the deadline: {had:?}");
        assert!(probe(&open(), libc::LOCK_EX).is_err(), "the lock returned is held");
        // Held past the deadline: refused then, and what the helper gets later with no one waiting it lets go of.
        let start = std::time::Instant::now();
        let err = flock_by(&path, start + Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        assert!(start.elapsed() >= Duration::from_millis(50) && start.elapsed() < Duration::from_secs(5));
        flock(&got, libc::LOCK_UN).unwrap();
        let end = std::time::Instant::now() + Duration::from_secs(10);
        let free = loop {
            // Probed (let go of at once), not left to the close: a child another test forks may share the file.
            match probe(&open(), libc::LOCK_EX) {
                Ok(()) => break true,
                Err(_) if std::time::Instant::now() < end => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => break false,
            }
        };
        assert!(free, "the abandoned wait let go of the lock it got");
    }

    #[test]
    fn timed_out_flock_waits_share_one_helper() {
        let base = crate::test_util::TempDir::new("flock-by-shared");
        let path = base.join("lock");
        let open = || private_file(&path).unwrap();
        let held = Flock::new(open(), libc::LOCK_EX).unwrap();
        let helpers = || FLOCK_HELPERS.lock().unwrap().as_ref().and_then(|m| m.get(&path).copied()).unwrap_or(0);
        for _ in 0..20 {
            let err = flock_by(&path, std::time::Instant::now() + Duration::from_millis(5)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        }
        assert_eq!(helpers(), 1, "repeated timeouts leave one helper blocked in flock");
        // A later wait takes over that helper's lock as soon as the holder lets go.
        let start = std::time::Instant::now();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(held);
        });
        let got = flock_by(&path, start + Duration::from_secs(30)).unwrap();
        let had = start.elapsed();
        releaser.join().unwrap();
        assert!(had < Duration::from_secs(5), "had once let go of: {had:?}");
        assert_eq!(helpers(), 1, "the waiting helper's lock was handed over, no new one started");
        assert!(probe(&open(), libc::LOCK_EX).is_err(), "the lock handed over is held");
        flock(&got, libc::LOCK_UN).unwrap();
    }
}
