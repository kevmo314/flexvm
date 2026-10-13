//! Memory pressure: when the host goes under its reserve, or a VM cannot
//! grow here, one VM is moved to a peer with room. Every VM process calls
//! `tick` once a second; whichever holds `STATE/evict.lock` decides, at most
//! once per `EVERY`. Standby VMs go first: they are the cheapest memory to
//! give back.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::time::{Duration, SystemTime};

use serde_json::json;

use crate::host::Host;
use crate::vmproc::host_available_mib;

/// Least time between two evictions from this host.
const EVERY: Duration = Duration::from_secs(5);

pub fn tick(host: &Host, starved_here: bool) {
    let avail = host_available_mib();
    let reserve = host.cfg.reserve_mib;
    if avail >= reserve && !starved_here && !host.entries().iter().any(|e| e.starved) {
        return;
    }
    let Ok(lock) = File::options().create(true).truncate(false).write(true).open(host.state.join("evict.lock")) else { return };
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return;
    }
    if avail < reserve {
        let mut shed = 0;
        for t in crate::standby::templates(host) {
            for pid in crate::standby::live(host, &t) {
                unsafe { libc::kill(pid as i32, libc::SIGINT) };
                shed += 1;
            }
        }
        if shed > 0 {
            eprintln!("host has {avail} MiB available, under its {reserve} MiB reserve: stopped {shed} standby vms");
            return;
        }
    }
    if host.cfg.peers.is_empty() {
        return;
    }
    let last = host.state.join("evict.last");
    let recent = std::fs::metadata(&last).and_then(|m| m.modified()).ok().and_then(|t| SystemTime::now().duration_since(t).ok());
    if recent.is_some_and(|d| d < EVERY) {
        return;
    }
    let rss = |pid: Option<u32>| pid.and_then(|p| crate::util::proc_kb(&format!("/proc/{p}/status"), "VmRSS")).unwrap_or(0);
    let running: Vec<_> = host.entries().into_iter().filter(|e| e.state == "running").collect();
    let Some(vm) = running.iter().find(|e| e.starved).or_else(|| running.iter().max_by_key(|e| rss(e.firecracker))) else { return };
    let _ = std::fs::write(&last, b"");
    let why = if vm.starved { "cannot grow here" } else { "the host is low on memory" };
    for peer in &host.cfg.peers {
        eprintln!("vm {}: {why} ({avail} MiB available); migrating to {peer}", vm.name);
        match crate::vmproc::call(host, &vm.name, json!({"op": "migrate", "to": peer})) {
            Ok(_) => return eprintln!("vm {}: migrated to {peer}", vm.name),
            Err(e) => eprintln!("vm {}: migrating to {peer}: {e}", vm.name),
        }
    }
}
