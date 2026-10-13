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
use crate::util::{Error, Phases, Result, PAGE_SIZE};
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
/// First wait before loading for a stock again after a failed load, or one
/// that came out over the budget; doubled each time, up to `MAX_BACKOFF`.
const BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Longest a load waits for runs in progress to answer (`starting`): runs
/// that keep coming must not keep the pool from ever refilling.
const MAX_DEFER: Duration = Duration::from_secs(2);

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
        let pager = Pager::start(&idle.fc.sockets.uffd, template.clone(), None)?;
        // Off the request path, so it can afford to learn what a load touches.
        pager.learn_load_set();
        let paused = Paused { idle: Some(idle), pager, template, loaded: Instant::now() };
        let idle = paused.idle.as_ref().unwrap();
        paused.pager.set_pid(idle.fc.pid())?;
        let body = json!({
            "snapshot_path": paused.template.vmstate(),
            "mem_backend": {"backend_type": "Uffd", "backend_path": idle.fc.sockets.uffd},
            "vsock_override": {"uds_path": idle.fc.sockets.vsock},
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
        let resumed = idle.fc.request_within("PATCH", "/vm", Some(json!({"state": "Resumed"})), API_TIMEOUT);
        // The load set includes what resuming touches (Firecracker kicks the
        // virtqueues), as a migration target's load resumes the VM too.
        paused.pager.loaded();
        resumed?;
        wait_for_reseed(&idle.fc.sockets.vsock)?;
        // Step the wall clock now: it keeps time while paused, so START at
        // take finds it right and skips clock_settime, which can take tens of
        // ms in a 24-vCPU guest (it IPIs the vCPUs). Best effort: START steps
        // it otherwise.
        let _ = guest::clock(&idle.fc.sockets.vsock, &paused.template.legacy_agent, guest::TIMEOUT);
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

    /// Whether its Firecracker still runs and its pager has not given up.
    fn alive(&mut self) -> bool {
        self.pager.failed().is_none() && self.idle.as_mut().is_some_and(|i| i.fc.alive())
    }

    /// Turns this into the running VM `name` at `ip`: names its cgroup, routes
    /// the address to its tap and resumes the vCPUs. On failure, the VM is
    /// torn down, and the flag says whether the guest may have run for `name`:
    /// unless the resume never reached Firecracker. With
    /// `kill` (test fault `resume_kill`), Firecracker is killed right after
    /// the resume is sent.
    pub fn resume(mut self, name: &str, ip: Ipv4Addr, kill: bool, phases: &mut Phases) -> std::result::Result<Arc<Vm>, (Error, bool)> {
        let (fc, dir, cgroup, tap) = self.idle.take().unwrap().into_parts();
        let idle = Idle { fc, dir, cgroup: name_cgroup(cgroup, name), tap };
        phases.mark("cgroup_rename");
        let mut sent = false;
        let resumed = (|| {
            // Route before the guest can send anything; one netlink round trip.
            crate::net::attach(ip, &idle.tap)?;
            phases.mark("route");
            sent = true;
            let res = idle.fc.request_within("PATCH", "/vm", Some(json!({"state": "Resumed"})), API_TIMEOUT);
            if kill {
                self.pager.kill_firecracker();
                bail!("injected fault: firecracker killed after the resume was sent");
            }
            res?;
            phases.mark("resume");
            Ok(())
        })();
        if let Err(e) = resumed {
            // Once the request may have reached Firecracker, some vCPUs may
            // have run even if it answers with an error.
            let ran = sent && !crate::fc::not_sent(&e);
            self.pager.stop();
            drop(idle);
            self.pager.join();
            return Err((e, ran));
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
    /// Runs in progress (`starting`), and since when there have been any:
    /// no load starts meanwhile, for up to `MAX_DEFER`.
    starting: usize,
    starting_since: Option<Instant>,
    /// Loads started, for `describe`.
    loads: u64,
}

impl State {
    /// Whether a load should wait for the runs in progress to answer.
    fn deferring(&self) -> bool {
        self.starting > 0 && self.starting_since.is_some_and(|t| t.elapsed() < MAX_DEFER)
    }
}

struct Stock {
    template: Arc<Template>,
    ready: VecDeque<Paused>,
    /// Largest host memory seen for one of these VMs (KiB), or an estimate.
    cost_kib: u64,
    /// Don't retry before this after a failed load, or one over the budget.
    retry_at: Option<Instant>,
    /// The wait before the next retry.
    backoff: Duration,
}

impl Stock {
    fn wants(&self, per_template: usize) -> bool {
        self.ready.len() < per_template && self.retry_at.is_none_or(|t| t <= Instant::now())
    }

    /// Waits longer before each retry, until a load is stocked. Returns the wait.
    fn back_off(&mut self) -> Duration {
        let wait = self.backoff;
        self.retry_at = Some(Instant::now() + wait);
        self.backoff = (wait * 2).min(MAX_BACKOFF);
        wait
    }
}

/// A run in progress (see `HotPool::starting`).
pub struct Starting<'a>(&'a HotPool);

impl Drop for Starting<'_> {
    fn drop(&mut self) {
        {
            let mut s = self.0.state.lock().unwrap();
            s.starting -= 1;
            if s.starting == 0 {
                s.starting_since = None;
            }
        }
        self.0.wake.notify_one();
    }
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

    /// Marks a run as in progress until the guard is dropped, once it has
    /// answered: loading a VM alongside (a snapshot load, the guest's first
    /// run) would slow its resume and `START`, so the worker waits, up to
    /// `MAX_DEFER`, and refills once the last one is done.
    pub fn starting(&self) -> Starting<'_> {
        let mut s = self.state.lock().unwrap();
        if s.starting == 0 {
            s.starting_since = Some(Instant::now());
        }
        s.starting += 1;
        Starting(self)
    }

    /// Hands out a paused VM of `template`'s generation, or None if there is
    /// none ready. One whose Firecracker or pager died meanwhile is torn
    /// down, never handed out.
    pub fn take(&self, template: &Arc<Template>) -> Option<Paused> {
        if self.per_template == 0 {
            return None;
        }
        let mut dead = Vec::new();
        let got = {
            let mut s = self.state.lock().unwrap();
            if s.closed {
                return None;
            }
            let stock = s.stocks.get_mut(&template.key())?;
            loop {
                match stock.ready.pop_front() {
                    Some(mut p) => match p.alive() {
                        true => break Some(p),
                        false => dead.push(p),
                    },
                    None => break None,
                }
            }
        };
        // No wake: the run that took it holds `starting` until it answers,
        // and lets the worker refill then.
        if !dead.is_empty() {
            eprintln!("hot pool {}: dropping {} paused vms that died", template.name, dead.len());
        }
        drop(dead);
        got
    }

    /// Starts keeping paused VMs of `template` ready, and drops the stock of
    /// any older generation of it: those VMs would come from superseded files.
    /// `low_estimate`: test fault `hot_low_estimate` (see `Stock::new`).
    pub fn warm(self: &Arc<Self>, template: &Arc<Template>, low_estimate: bool) {
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
            s.stocks.insert(key, Stock::new(template.clone(), low_estimate));
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
        let cost: HashMap<String, u64> =
            s.stocks.iter().map(|(k, v)| (format!("{}@{k}", v.template.name), v.cost_kib >> 10)).collect();
        json!({
            "per_template": self.per_template,
            "budget_mib": self.budget_kib >> 10,
            "ready": ready,
            "cost_mib": cost,
            "loading": s.loading.is_some(),
            "loads": s.loads,
        })
    }

    /// The worker: keeps the stocks within the memory budget, and loads one
    /// paused VM at a time for the emptiest stock while it has room.
    fn refill(&self) {
        loop {
            let (pids, epoch, dead) = {
                let s = self.state.lock().unwrap();
                let wants = |s: &State| !s.deferring() && s.stocks.values().any(|k| k.wants(self.per_template));
                let (mut s, _) = self.wake.wait_timeout_while(s, Duration::from_secs(1), |s| !s.closed && !wants(s)).unwrap();
                if s.closed {
                    return;
                }
                // A paused VM whose Firecracker or pager died is torn down
                // now: it would neither count against the budget (no RSS)
                // nor ever be handed out, yet hold its stock's place.
                let mut dead = Vec::new();
                for k in s.stocks.values_mut() {
                    for mut p in std::mem::take(&mut k.ready) {
                        match p.alive() {
                            true => k.ready.push_back(p),
                            false => dead.push((k.template.name.clone(), p)),
                        }
                    }
                }
                let pids: Vec<(String, u32, u64)> = s
                    .stocks
                    .iter()
                    .flat_map(|(n, k)| k.ready.iter().filter_map(|p| Some((n.clone(), p.pid()?, k.cost_kib))))
                    .collect();
                (pids, (s.epoch, s.retiring_kib), dead)
            };
            for (name, _) in &dead {
                eprintln!("hot pool {name}: dropping a paused vm that died");
            }
            drop(dead);
            let (epoch, retiring) = epoch;
            // What the stock costs now, measured outside the lock. Paused VMs
            // grow a little after they are stocked (prefetch, settling). One
            // that cannot be measured (it died just now) counts as its
            // stock's cost until it is dropped.
            let mut used = retiring;
            let mut seen: HashMap<String, u64> = HashMap::new();
            for (key, pid, cost) in &pids {
                let kib = rss_kib(*pid);
                used += if kib == 0 { *cost } else { kib };
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
                    over = over.saturating_sub(p.pid().map(rss_kib).filter(|&kib| kib > 0).unwrap_or(k.cost_kib));
                    excess.push(p);
                }
                // While runs are starting, only the budget is kept.
                let pick = match s.deferring() {
                    true => None,
                    false => s
                        .stocks
                        .values()
                        .filter(|k| k.wants(self.per_template))
                        // One that fits first: a template whose VMs never fit
                        // must not keep the others from loading.
                        .min_by_key(|k| (used + k.cost_kib > self.budget_kib, k.ready.len()))
                        .map(|k| (k.template.clone(), k.cost_kib)),
                };
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
                // A run may have started since the pick (taking the idle
                // Firecracker can take a while): wait until it has answered,
                // keeping the Firecracker, so the load never overlaps it.
                while !s.closed && s.epoch == epoch && s.deferring() {
                    let left = s.starting_since.map_or(Duration::ZERO, |t| MAX_DEFER.saturating_sub(t.elapsed()));
                    s = self.wake.wait_timeout(s, left.max(Duration::from_millis(1))).unwrap().0;
                }
                if s.closed || s.epoch != epoch {
                    drop(s);
                    drop(idle);
                    continue;
                }
                match crate::util::pidfd_open(idle.fc.pid()) {
                    Ok(fd) => {
                        s.loading = Some(Arc::new(fd));
                        s.loads += 1;
                    }
                    Err(e) => {
                        drop(s);
                        drop(idle);
                        self.failed(&template, format!("pidfd_open: {e}"));
                        continue;
                    }
                }
            }
            // One that died as it settled is a failed load (and has no size).
            let loaded = Paused::load(idle, template.clone()).and_then(|mut p| match p.alive() {
                true => Ok(p),
                false => Err("its firecracker or pager died as it settled".into()),
            });
            // Recheck before stocking it: its own size, and anything that
            // happened meanwhile (shed, close, a newer generation).
            let size = loaded.as_ref().ok().and_then(|p| p.pid()).map(rss_kib).unwrap_or(0);
            // What the stock uses now: runs may have taken some meanwhile.
            // (Only this worker adds to it.)
            let used = self.in_use();
            let mut s = self.state.lock().unwrap();
            s.loading = None;
            let current = s.epoch == epoch && !s.closed;
            match (loaded, s.stocks.get_mut(&template.key())) {
                (Ok(p), Some(stock)) if current && used + size <= self.budget_kib => {
                    stock.retry_at = None;
                    stock.backoff = BACKOFF;
                    stock.cost_kib = stock.cost_kib.max(size);
                    stock.ready.push_back(p);
                }
                // Over the budget: what it cost is learned (the first
                // estimate is below a paused VM's real size), so the worker
                // waits for room rather than load the same VM again and
                // again; and waits longer each time it still comes out over.
                (Ok(p), Some(stock)) if current => {
                    stock.cost_kib = stock.cost_kib.max(size);
                    let wait = stock.back_off();
                    drop(s);
                    eprintln!(
                        "hot pool {}: dropping a paused vm of {} MiB, over the {} MiB budget ({} MiB in use); next try in {wait:?} at the earliest",
                        template.name,
                        size >> 10,
                        self.budget_kib >> 10,
                        used >> 10
                    );
                    drop(p);
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

    /// Host memory the stocked VMs and those being retired use (KiB),
    /// measured outside the lock; one that cannot be measured counts as its
    /// stock's cost.
    fn in_use(&self) -> u64 {
        let (pids, retiring) = {
            let s = self.state.lock().unwrap();
            let pids: Vec<(u32, u64)> =
                s.stocks.values().flat_map(|k| k.ready.iter().filter_map(|p| Some((p.pid()?, k.cost_kib)))).collect();
            (pids, s.retiring_kib)
        };
        retiring + pids.iter().map(|&(pid, cost)| Some(rss_kib(pid)).filter(|&k| k > 0).unwrap_or(cost)).sum::<u64>()
    }

    fn failed(&self, template: &Template, why: String) {
        let wait = self.state.lock().unwrap().stocks.get_mut(&template.key()).map_or(BACKOFF, Stock::back_off);
        eprintln!("hot pool {}: cannot load a paused vm: {why}; next try in {wait:?}", template.name);
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
    /// `low` (test fault `hot_low_estimate`) leaves the working set out of
    /// the first estimate, so it is below what a paused VM costs.
    fn new(template: Arc<Template>, low: bool) -> Stock {
        let wset: u64 = if low { 0 } else { template.working_set.iter().map(|r| r.1).sum() };
        let cost_kib = wset * PAGE_SIZE as u64 / 1024 + OVERHEAD_KIB;
        Stock { template, ready: VecDeque::new(), cost_kib, retry_at: None, backoff: BACKOFF }
    }
}
