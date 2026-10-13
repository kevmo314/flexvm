//! The hot pool: VMs already restored from a template and left paused, so
//! `run` only has to resume one instead of loading a snapshot.
//!
//! A paused VM is restored exactly like any other (same pager over the same
//! template), so once resumed it is an ordinary VM that can be migrated and
//! checkpointed.
//!
//! The first run after a restore is slow (Firecracker's first resume, the
//! guest catching up on elapsed time and handling the new VMGenID), so each
//! VM runs once in the background, then is paused until `take`. That run
//! lasts until the guest kernel has reseeded its RNG for the VMGenID
//! Firecracker gave this load (the agent's `FORKS` count goes up; see
//! flexvm-init), plus `SETTLE`. So two VMs from one template never share RNG
//! state once handed out; until then only the idle agent runs. Agents without
//! `FORKS` only show they answer, which does not prove the reseed. The wall
//! clock is set by the agent on `START`: the guest's clock otherwise carries
//! on from the template snapshot, whether or not it was pooled.
//!
//! One background worker fills every template generation's stock, one VM at
//! a time, up to a count per template and a memory budget for all of them
//! together, the VM being loaded included.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::{Idle, Pool};
use crate::guest;
use crate::template::Template;
use crate::uffd::Pager;
use crate::util::{Phases, Result, PAGE_SIZE};
use crate::vm::{name_cgroup, Vm};

/// Host memory a paused VM costs beyond the template pages it prefetched (KiB).
const OVERHEAD_KIB: u64 = 8 << 10;

/// How long a pooled VM keeps running after the guest has reseeded, for the
/// rest of its post-restore work to finish.
const SETTLE: Duration = Duration::from_millis(50);

/// Deadlines for the Firecracker API calls of a load, so a stuck one cannot
/// hold the worker (and shutdown) forever.
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);
const API_TIMEOUT: Duration = Duration::from_secs(5);
/// Fork reseeds in a template's own kernel log (see `wait_for_reseed`).
const FORKS_BASELINE: usize = 0;
/// How long the guest has to reseed after its first resume.
const RESEED_TIMEOUT: Duration = Duration::from_secs(5);

/// A VM restored from a template, run once to settle and paused again.
pub struct Paused {
    idle: Option<Idle>,
    pager: Arc<Pager>,
    template: Arc<Template>,
    loaded: Instant,
}

impl Paused {
    /// Restores `template` into `idle`, lets it settle and pauses it.
    pub fn load(idle: Idle, template: Arc<Template>) -> Result<Paused> {
        let pager = Pager::start(&idle.dir.join("uffd.sock"), template.clone(), None)?;
        let paused = Paused { idle: Some(idle), pager, template, loaded: Instant::now() };
        let idle = paused.idle.as_ref().unwrap();
        paused.pager.set_pid(idle.fc.pid())?;
        let body = json!({
            "snapshot_path": paused.template.vmstate(),
            "mem_backend": {"backend_type": "Uffd", "backend_path": idle.dir.join("uffd.sock")},
            "vsock_override": {"uds_path": idle.dir.join("v.sock")},
            "network_overrides": [{"iface_id": "eth0", "host_dev_name": idle.tap}],
            "clock_realtime": true,
            "resume_vm": false,
        });
        idle.fc.request_within("PUT", "/snapshot/load", Some(body), LOAD_TIMEOUT)?;
        // Loaded with resume_vm false, Firecracker still runs its devices (tap
        // RX, vsock, balloon timer) into guest memory; an API pause stops them.
        idle.fc.request_within("PATCH", "/vm", Some(json!({"state": "Paused"})), API_TIMEOUT)?;
        paused.pager.wait_ready(Duration::from_secs(5))?;
        // Get the slow first run after a restore out of the way, off the request path.
        idle.fc.request_within("PATCH", "/vm", Some(json!({"state": "Resumed"})), API_TIMEOUT)?;
        wait_for_reseed(&idle.dir.join("v.sock"))?;
        // Step the wall clock now: it keeps time while paused, so START at
        // take finds it right and skips clock_settime, which can take tens of
        // ms in a 24-vCPU guest (it IPIs the vCPUs). Best effort: START steps
        // it otherwise.
        let _ = guest::clock(&idle.dir.join("v.sock"), &paused.template.legacy_agent, guest::TIMEOUT);
        std::thread::sleep(SETTLE);
        idle.fc.request_within("PATCH", "/vm", Some(json!({"state": "Paused"})), API_TIMEOUT)?;
        Ok(paused)
    }

    /// How long ago this VM was loaded.
    pub fn age(&self) -> Duration {
        self.loaded.elapsed()
    }

    fn pid(&self) -> Option<u32> {
        self.idle.as_ref().map(|i| i.fc.pid())
    }

    /// Turns this into the running VM `name` at `ip`: names its cgroup, routes
    /// the address to its tap and resumes the vCPUs.
    pub fn resume(mut self, name: &str, ip: Ipv4Addr, phases: &mut Phases) -> Result<Arc<Vm>> {
        let (fc, dir, cgroup, tap) = self.idle.take().unwrap().into_parts();
        let idle = Idle { fc, dir, cgroup: name_cgroup(cgroup, name), tap };
        phases.mark("cgroup_rename");
        let resumed = (|| {
            // Route before the guest can send anything; one netlink round trip.
            crate::net::attach(ip, &idle.tap)?;
            phases.mark("route");
            idle.fc.request_within("PATCH", "/vm", Some(json!({"state": "Resumed"})), API_TIMEOUT)?;
            phases.mark("resume");
            Ok(())
        })();
        if let Err(e) = resumed {
            self.pager.stop();
            drop(idle);
            self.pager.join();
            return Err(e);
        }
        Ok(Vm::assemble(name, self.template.clone(), idle, ip, self.pager.clone(), crate::vm::State::Running))
    }
}

impl Drop for Paused {
    fn drop(&mut self) {
        // Still ours (never resumed): stop the pager, including its prefetch, and tear down.
        if let Some(idle) = self.idle.take() {
            self.pager.stop();
            drop(idle);
            self.pager.join();
        }
    }
}

/// Waits until the guest kernel has reseeded its RNG for a new VMGenID (see
/// the module comment). An agent without `FORKS` only gets to answer.
///
/// Assumes the template's kernel log has no fork reseed in it (a baseline of
/// 0), which holds for templates cold-booted by `flexvm template`. A template
/// made from a restored VM (a checkpoint) would need its own count, taken
/// when it was snapshotted, as the baseline.
fn wait_for_reseed(vsock: &std::path::Path) -> Result<()> {
    static WARNED: AtomicBool = AtomicBool::new(false);
    let deadline = Instant::now() + RESEED_TIMEOUT;
    loop {
        let res = guest::forks(vsock);
        match res {
            Ok(Some(n)) if n > FORKS_BASELINE => return Ok(()),
            Ok(None) => {
                if !WARNED.swap(true, Ordering::Relaxed) {
                    eprintln!("hot pool: guest agent cannot report RNG reseeds (no FORKS); pooled VMs are only checked to answer");
                }
                return Ok(());
            }
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(Some(_)) => bail!("guest did not reseed its RNG for the new VMGenID within {RESEED_TIMEOUT:?}"),
            Err(e) => bail!("guest agent not answering after restore: {e}"),
        }
    }
}

pub struct HotPool {
    cold: Arc<Pool>,
    per_template: usize,
    budget_kib: u64,
    /// Don't load more while the host has less than this available (KiB).
    reserve_kib: u64,
    state: Mutex<State>,
    wake: Condvar,
    worker: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Default)]
struct State {
    /// By template generation (`Template::key`).
    stocks: HashMap<String, Stock>,
    closed: bool,
    /// Bumped by `shed` and `close`: a load started before is thrown away.
    epoch: u64,
    /// The Firecracker of the VM being loaded, killed by `shed` and `close`
    /// through a pidfd (its pid may be reaped and reused by then).
    loading: Option<Arc<OwnedFd>>,
    /// Paused VMs of superseded generations still being torn down (KiB):
    /// they count against the budget until they are gone.
    retiring_kib: u64,
}

struct Stock {
    template: Arc<Template>,
    ready: VecDeque<Paused>,
    /// Largest host memory seen for one of these VMs (KiB), or an estimate.
    cost_kib: u64,
    /// Don't retry before this after a failed load.
    retry_at: Option<Instant>,
}

impl HotPool {
    /// `per_template` paused VMs per template, within `budget_mib` of host
    /// memory in total, and none loaded into the host's last `reserve_mib`.
    pub fn new(cold: Arc<Pool>, per_template: usize, budget_mib: u64, reserve_mib: u64) -> Arc<HotPool> {
        let hot = Arc::new(HotPool {
            cold,
            per_template,
            budget_kib: budget_mib << 10,
            reserve_kib: reserve_mib << 10,
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
            worker: Mutex::new(None),
        });
        if per_template > 0 {
            let h = hot.clone();
            *hot.worker.lock().unwrap() = Some(std::thread::spawn(move || h.refill()));
        }
        hot
    }

    /// Hands out a paused VM of `template`'s generation, or None if there is
    /// none ready.
    pub fn take(&self, template: &Arc<Template>) -> Option<Paused> {
        if self.per_template == 0 {
            return None;
        }
        let got = {
            let mut s = self.state.lock().unwrap();
            if s.closed {
                return None;
            }
            s.stocks.get_mut(&template.key()).and_then(|k| k.ready.pop_front())
        };
        self.wake.notify_one();
        got
    }

    /// Starts keeping paused VMs of `template` ready, and drops the stock of
    /// any older generation of it: those VMs would come from superseded files.
    pub fn warm(self: &Arc<Self>, template: &Arc<Template>) {
        if self.per_template == 0 {
            return;
        }
        let key = template.key();
        let (stale, cost) = {
            let mut s = self.state.lock().unwrap();
            if s.closed || s.stocks.contains_key(&key) {
                return;
            }
            let old: Vec<String> =
                s.stocks.iter().filter(|(_, k)| k.template.name == template.name).map(|(k, _)| k.clone()).collect();
            s.stocks.insert(key, Stock::new(template.clone()));
            let stale: Vec<Stock> = old.iter().filter_map(|k| s.stocks.remove(k)).collect();
            let cost: u64 = stale.iter().map(|k| k.cost_kib * k.ready.len() as u64).sum();
            s.retiring_kib += cost;
            (stale, cost)
        };
        self.wake.notify_one();
        if stale.is_empty() {
            return;
        }
        // Tearing them down takes a while; not on the request that noticed the new generation.
        let hot = self.clone();
        std::thread::spawn(move || {
            for stock in stale {
                eprintln!(
                    "hot pool {}: dropping {} paused vms of generation {}",
                    stock.template.name,
                    stock.ready.len(),
                    stock.template.key()
                );
            }
            hot.state.lock().unwrap().retiring_kib -= cost;
        });
    }

    pub fn describe(&self) -> Value {
        let s = self.state.lock().unwrap();
        let ready: HashMap<String, usize> =
            s.stocks.iter().map(|(k, v)| (format!("{}@{k}", v.template.name), v.ready.len())).collect();
        json!({"per_template": self.per_template, "budget_mib": self.budget_kib >> 10, "ready": ready, "loading": s.loading.is_some()})
    }

    /// The worker: keeps the stocks within the memory budget, and loads one
    /// paused VM at a time for the emptiest stock while it has room.
    fn refill(&self) {
        loop {
            let (pids, epoch) = {
                let s = self.state.lock().unwrap();
                let now = Instant::now();
                let wants = |s: &State| {
                    s.stocks.values().any(|k| k.ready.len() < self.per_template && k.retry_at.is_none_or(|t| t <= now))
                };
                let (s, _) = self.wake.wait_timeout_while(s, Duration::from_secs(1), |s| !s.closed && !wants(s)).unwrap();
                if s.closed {
                    return;
                }
                let pids: Vec<(String, u32)> = s
                    .stocks
                    .iter()
                    .flat_map(|(n, k)| k.ready.iter().filter_map(|p| Some((n.clone(), p.pid()?))))
                    .collect();
                (pids, (s.epoch, s.retiring_kib))
            };
            let (epoch, retiring) = epoch;
            // What the stock costs now, measured outside the lock. Paused VMs
            // grow a little after they are stocked (prefetch, settling).
            let mut used = retiring;
            let mut seen: HashMap<String, u64> = HashMap::new();
            for (key, pid) in &pids {
                let kib = rss_kib(*pid);
                used += kib;
                let max = seen.entry(key.clone()).or_default();
                *max = (*max).max(kib);
            }
            let (pick, excess) = {
                let mut s = self.state.lock().unwrap();
                for (key, kib) in &seen {
                    if let Some(k) = s.stocks.get_mut(key) {
                        k.cost_kib = k.cost_kib.max(*kib);
                    }
                }
                // Over budget: give back the newest paused VMs first.
                let mut excess = Vec::new();
                let mut over = used.saturating_sub(self.budget_kib);
                while over > 0 {
                    let Some(k) = s.stocks.values_mut().filter(|k| !k.ready.is_empty()).max_by_key(|k| k.ready.len()) else {
                        break;
                    };
                    let p = k.ready.pop_back().unwrap();
                    over = over.saturating_sub(p.pid().map(rss_kib).unwrap_or(k.cost_kib));
                    excess.push(p);
                }
                let now = Instant::now();
                let pick = s
                    .stocks
                    .values()
                    .filter(|k| k.ready.len() < self.per_template && k.retry_at.is_none_or(|t| t <= now))
                    .min_by_key(|k| k.ready.len())
                    .map(|k| (k.template.clone(), k.cost_kib));
                (pick, excess)
            };
            if !excess.is_empty() {
                eprintln!("hot pool: dropping {} paused vms over the {} MiB budget", excess.len(), self.budget_kib >> 10);
                drop(excess);
                continue;
            }
            let Some((template, cost)) = pick else { continue };
            // The VM about to be loaded counts against the budget too.
            let avail = crate::util::proc_kb("/proc/meminfo", "MemAvailable").unwrap_or(0) >> 10;
            if used + cost > self.budget_kib || avail < self.reserve_kib + cost {
                let s = self.state.lock().unwrap();
                // Wait for a take (or for prefetches to settle) before trying again.
                let _ = self.wake.wait_timeout(s, Duration::from_secs(1)).unwrap();
                continue;
            }
            let idle = match self.cold.take() {
                Ok(idle) => idle,
                Err(e) => {
                    self.failed(&template, e.to_string());
                    continue;
                }
            };
            {
                let mut s = self.state.lock().unwrap();
                if s.closed || s.epoch != epoch {
                    drop(s);
                    drop(idle);
                    continue;
                }
                match crate::util::pidfd_open(idle.fc.pid()) {
                    Ok(fd) => s.loading = Some(Arc::new(fd)),
                    Err(e) => {
                        drop(s);
                        drop(idle);
                        self.failed(&template, format!("pidfd_open: {e}"));
                        continue;
                    }
                }
            }
            let loaded = Paused::load(idle, template.clone());
            // Recheck before stocking it: its own size, and anything that
            // happened meanwhile (shed, close, a newer generation).
            let size = loaded.as_ref().ok().and_then(|p| p.pid()).map(rss_kib).unwrap_or(0);
            let mut s = self.state.lock().unwrap();
            s.loading = None;
            let current = s.epoch == epoch && !s.closed;
            match (loaded, s.stocks.get_mut(&template.key())) {
                (Ok(p), Some(stock)) if current && used + size <= self.budget_kib => {
                    stock.retry_at = None;
                    stock.cost_kib = stock.cost_kib.max(size);
                    stock.ready.push_back(p);
                }
                (Ok(p), _) => {
                    drop(s);
                    drop(p);
                }
                (Err(e), _) if current => {
                    drop(s);
                    self.failed(&template, e.to_string());
                }
                (Err(_), _) => {}
            }
        }
    }

    fn failed(&self, template: &Template, why: String) {
        eprintln!("hot pool {}: cannot load a paused vm: {why}", template.name);
        if let Some(stock) = self.state.lock().unwrap().stocks.get_mut(&template.key()) {
            stock.retry_at = Some(Instant::now() + Duration::from_secs(5));
        }
    }

    /// Tears down every paused VM, and a load in progress, e.g. to give their
    /// memory back under pressure.
    pub fn shed(&self) {
        let shed: Vec<Paused> = {
            let mut s = self.state.lock().unwrap();
            s.epoch += 1;
            kill(&s.loading);
            s.stocks.values_mut().flat_map(|k| k.ready.drain(..)).collect()
        };
        if !shed.is_empty() {
            eprintln!("hot pool: dropping {} paused vms, the host is low on memory", shed.len());
        }
    }

    /// Stops the worker (killing a load in progress) and tears down every
    /// paused VM. Later takes get None.
    pub fn close(&self) {
        let stocks = {
            let mut s = self.state.lock().unwrap();
            s.closed = true;
            s.epoch += 1;
            kill(&s.loading);
            std::mem::take(&mut s.stocks)
        };
        self.wake.notify_all();
        if let Some(w) = self.worker.lock().unwrap().take() {
            let _ = w.join();
        }
        drop(stocks);
    }
}

/// Kills the Firecracker being loaded, so its API calls fail at once.
fn kill(loading: &Option<Arc<OwnedFd>>) {
    if let Some(fd) = loading {
        let _ = crate::util::pidfd_kill(fd);
    }
}

fn rss_kib(pid: u32) -> u64 {
    crate::util::proc_kb(&format!("/proc/{pid}/status"), "VmRSS").unwrap_or(0) >> 10
}

impl Stock {
    fn new(template: Arc<Template>) -> Stock {
        let wset: u64 = template.working_set.iter().map(|r| r.1).sum();
        let cost_kib = wset * PAGE_SIZE as u64 / 1024 + OVERHEAD_KIB;
        Stock { template, ready: VecDeque::new(), cost_kib, retry_at: None }
    }
}
