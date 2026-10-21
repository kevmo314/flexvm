//! `flexvm bench`: runs (and optionally migrates) fresh VMs and writes per-phase latency
//! percentiles to `bench/`; `--lifecycle` times pause, checkpoint, restore and suspend.
//! VMs are driven as a user would; migrations go to another host on this machine.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::host::Host;
use crate::util::{ms, Result};
use crate::{bail, Args};

/// VMs start on `a`; migrations and restores go to `b` (`a` again without `--to`).
struct Hosts {
    a: Host,
    b: Host,
    to: Option<String>,
    timeout: Duration,
    cancelled: Arc<AtomicBool>,
}

/// Only successful starts confer ownership; a refused name must never be killed.
struct OwnedVm<'a> {
    h: &'a Hosts,
    name: &'a str,
    hosts: Vec<&'a Host>,
    checkpoint: Option<OwnedCheckpoint<'a>>,
}

impl Drop for OwnedVm<'_> {
    fn drop(&mut self) {
        // The target first: a migration's source refuses removal until the target is gone, then ends or
        // resumes from the pause (a rollback), and is removed on a retry. One that ended moved to the
        // target, removed already, is gone.
        let deadline = Instant::now() + self.h.timeout;
        let mut left: Vec<&Host> = self.hosts.iter().rev().copied().collect();
        let mut target_removed = false;
        while !left.is_empty() {
            let mut retry = Vec::new();
            for host in left {
                let source = self.hosts.len() > 1 && std::ptr::eq(host, self.hosts[0]);
                match self.h.cli(host, &["rm", "-f", self.name]) {
                    Ok(_) => target_removed |= !source,
                    Err(e) if source && e.to_string().contains("migration in progress") && Instant::now() < deadline => retry.push(host),
                    Err(e) if source && target_removed && e.to_string().contains("kill it there") => {}
                    Err(e) => crate::log!("bench: cleanup {}: {e}", self.name),
                }
            }
            if !retry.is_empty() {
                thread::sleep(Duration::from_millis(100));
            }
            left = retry;
        }
    }
}

struct OwnedCheckpoint<'a> {
    state: &'a std::path::Path,
    id: String,
}

impl Drop for OwnedCheckpoint<'_> {
    fn drop(&mut self) {
        if let Err(e) = crate::checkpoint::store::remove(self.state, std::slice::from_ref(&self.id), true) {
            crate::log!("bench: cleanup checkpoint {}: {e}", self.id);
        }
    }
}

fn check(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        bail!("benchmark interrupted");
    }
    Ok(())
}

fn wait(cancelled: &AtomicBool, timeout: Duration, what: &str, cond: impl Fn() -> bool) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        check(cancelled)?;
        if cond() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for {what}");
        }
        thread::sleep(Duration::from_millis(1));
    }
}

// Exec's signal waiters live only in the child. Cancellation reaps it before owned VMs unwind.
fn wait_exec(child: &mut Child, cancelled: &AtomicBool) -> Result<ExitStatus> {
    let result = (|| loop {
        check(cancelled)?;
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(1));
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn report_path(dir: &str, date: &str, sha: &str, id: &str, suffix: &str) -> String {
    format!("{dir}/{date}-{}-{id}{suffix}.json", &sha[..7])
}

impl Hosts {
    fn check(&self) -> Result<()> {
        check(&self.cancelled)
    }

    fn cli(&self, host: &Host, args: &[&str]) -> Result<Value> {
        // Let starts finish and confer ownership even when the terminal sends Ctrl-C; in a background
        // group, never reading the terminal (it would stop).
        let out = Command::new("/proc/self/exe")
            .process_group(0)
            .stdin(std::process::Stdio::null())
            .arg("--state")
            .arg(&host.state)
            .arg("--run")
            .arg(&host.run)
            .args(args)
            .output()?;
        if !out.status.success() {
            bail!("flexvm {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(serde_json::from_slice(&out.stdout).unwrap_or(Value::Null))
    }

    fn exec(&self, host: &Host, name: &str, cmd: &str) -> Result<bool> {
        self.check()?;
        // Its output stays off bench's stdout, which carries only the report path.
        let mut child = Command::new("/proc/self/exe")
            .process_group(0)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .arg("--state")
            .arg(&host.state)
            .arg("--run")
            .arg(&host.run)
            .args(["exec", name, "sh", "-c", cmd])
            .spawn()?;
        Ok(wait_exec(&mut child, &self.cancelled)?.success())
    }

    fn state(host: &Host, name: &str) -> String {
        host.entry(name).map(|e| e.state).unwrap_or_default()
    }

    fn wait(&self, what: &str, cond: impl Fn() -> bool) -> Result<()> {
        wait(&self.cancelled, self.timeout, what, cond)
    }

    fn pulled(&self, host: &Host, name: &str) -> Result<Value> {
        let deadline = Instant::now() + self.timeout;
        loop {
            self.check()?;
            let st = crate::vmproc::call(host, name, json!({"op": "debug", "what": "status"}), None)?;
            if st["background_pull_ms"].is_number() {
                return Ok(st["background_pull_ms"].clone());
            }
            if !st["failed"].is_null() || Instant::now() >= deadline {
                bail!("pull did not finish: {st}");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

pub fn run(args: &Args) -> Result<()> {
    validate(args)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    crate::util::on_signal(&[libc::SIGINT, libc::SIGTERM], move |_| flag.store(true, Ordering::Relaxed));
    let sha = command("git", &["rev-parse", "HEAD"])?;
    let dirty = !command("git", &["status", "--porcelain"])?.is_empty();
    let dir = format!("{}/bench", command("git", &["rev-parse", "--show-toplevel"])?);
    std::fs::create_dir_all(&dir)?;
    let a = crate::open_host(args)?;
    let to = args.get("to").map(String::from);
    let b = match (args.get("to-state"), args.get("to-run")) {
        (Some(s), Some(r)) => Host::open(std::path::Path::new(s), std::path::Path::new(r))?,
        (None, None) if to.is_none() => crate::open_host(args)?,
        _ => bail!("--to needs the target host's --to-state and --to-run (on this machine)"),
    };
    let timeout = Duration::from_secs(args.parse_or::<u64>("timeout", 120)?.max(1));
    let hosts = Hosts { a, b, to, timeout, cancelled };
    let template = &crate::template::name_of(args.get("template").unwrap_or("ubuntu:24.04"))?;
    let date = command("date", &["-u", "+%Y-%m-%dT%H-%M-%SZ"])?;
    let id = format!("{}-{}", std::process::id(), crate::migrate::migration_id());
    // The load before the run, as the one after it is mostly the run's own.
    let loadavg_before = std::fs::read_to_string("/proc/loadavg").ok().map(|s| s.trim().to_string());
    let (report, suffix) = match args.has("lifecycle") {
        true => (lifecycle(&hosts, args, template, &date, &id), "-lifecycle"),
        false => (runs(&hosts, args, template, &date, &id), ""),
    };
    let mut report = report?;
    report["date_utc"] = json!(date);
    report["git_sha"] = json!(sha);
    report["git_dirty"] = json!(dirty);
    report["host_context"] = host_context(template);
    report["host_context"]["loadavg_before"] = json!(loadavg_before);
    let path = report_path(&dir, &date, &sha, &id, suffix);
    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
    serde_json::to_writer_pretty(file, &report)?;
    crate::output(format_args!("{path}\n"))?;
    if let Some(error) = report["error"].as_str() {
        bail!("{error}");
    }
    Ok(())
}

fn validate(args: &Args) -> Result<()> {
    if args.parse_or::<u64>("iterations", 1)? == 0 {
        bail!("--iterations must be positive");
    }
    if args.has("lifecycle") {
        lifecycle_sizes(args)?;
        for flag in ["warmup", "settle-ms", "ready-port", "ready-http"] {
            if args.has(flag) {
                bail!("--{flag} is unused with --lifecycle");
            }
        }
    }
    Ok(())
}

fn record(result: Result<Value>, samples: &mut Vec<Value>, error: &mut Option<String>) -> bool {
    match result {
        Ok(sample) => {
            samples.push(sample);
            true
        }
        Err(e) => {
            *error = Some(e.to_string());
            false
        }
    }
}

fn runs(h: &Hosts, args: &Args, template: &str, date: &str, id: &str) -> Result<Value> {
    let iterations = args.parse_or::<u64>("iterations", 50)?;
    let warmup = args.parse_or::<u64>("warmup", 3)?;
    let dirty_mib = args.parse_or::<u64>("dirty-mib", 0)?;
    let settle = Duration::from_millis(args.parse_or::<u64>("settle-ms", 100)?);
    let ready = match (args.get("ready-port"), args.get("ready-http")) {
        (Some(p), None) => Some((p.parse().map_err(|_| "bad --ready-port")?, false)),
        (None, Some(p)) => Some((p.parse().map_err(|_| "bad --ready-http")?, true)),
        (None, None) => None,
        _ => bail!("pass --ready-port or --ready-http, not both"),
    };
    if dirty_mib > 0 && h.to.is_none() {
        bail!("--dirty-mib needs --to");
    }
    let mut samples = Vec::new();
    let mut error = None;
    for i in 0..warmup + iterations {
        let name = format!("bench-{id}-{i}");
        let result = h.check().and_then(|()| iteration(h, &name, template, dirty_mib, ready)).map_err(|e| format!("iteration {} failed: {e}", i + 1).into());
        if !record(result, &mut samples, &mut error) {
            break;
        }
        if i < warmup {
            samples.pop();
        }
        crate::log!("bench: {}/{}{}", i + 1, warmup + iterations, if i < warmup { " (warmup)" } else { "" });
        // Let standby VMs refill between trials; misses show up as cold runs.
        let until = Instant::now() + settle;
        while Instant::now() < until && h.check().is_ok() {
            thread::sleep(Duration::from_millis(1));
        }
        if let Err(e) = h.check() {
            error = Some(e.to_string());
            break;
        }
    }
    let standby = samples.iter().filter(|s| s["standby"] == json!(true)).count();
    let mut summary = run_summary(&samples)?;
    summary["run_standby_hits"] = json!(standby);
    if h.to.is_some() && !samples.is_empty() {
        summary["migrate"] = summarize(&samples, "migrate")?;
        summary["migrate_target"] = summarize(&samples, "migrate_target")?;
        summary["post_copy"] = summarize(&samples, "post_copy")?;
    }
    Ok(json!({
        "params": {"to": h.to, "template": template, "iterations": iterations, "warmup": warmup, "dirty_mib": dirty_mib,
                   "settle_ms": settle.as_millis(), "ready_port": ready.map(|r| r.0), "ready_http": ready.is_some_and(|r| r.1), "date": date},
        "status": if error.is_some() { "failed" } else { "ok" },
        "error": error,
        "summary_ms": summary,
        "samples_ms": samples,
    }))
}

fn iteration(h: &Hosts, name: &str, template: &str, dirty_mib: u64, ready: Option<(u16, bool)>) -> Result<Value> {
    let start = Instant::now();
    let run = h.cli(&h.a, &["run", "--name", name, "-d", template])?;
    let run_cli = start.elapsed();
    let mut owned = OwnedVm { h, name, hosts: vec![&h.a], checkpoint: None };
    h.check()?;
    let mut sample = json!({"run": run["timings_ms"], "standby": run["standby"], "run_client": {"total": ms(run_cli)}});
    if let Some((port, http)) = ready {
        let ip: std::net::Ipv4Addr = run["ip"].as_str().ok_or("run reply has no ip")?.parse()?;
        wait_ready(h, (ip, port).into(), http, start + h.timeout)?;
        let total = start.elapsed();
        sample["client"] = json!({"run_cli": ms(run_cli), "app_ready": ms(total - run_cli), "total": ms(total)});
    }
    if let Some(to) = &h.to {
        if dirty_mib > 0 {
            // /tmp is a tmpfs, so this lands in guest memory.
            let cmd = format!("dd if=/dev/urandom of=/tmp/dirty bs=1M count={dirty_mib} 2>/dev/null");
            if !h.exec(&h.a, name, &cmd)? {
                bail!("dirtying guest memory failed");
            }
        }
        // The guest reads what it wrote, here and right after the migration
        // (pages still being pulled): the difference is the post-copy stall.
        let read = |host: &Host| -> Result<Option<f64>> {
            let t = Instant::now();
            if dirty_mib > 0 && !h.exec(host, name, "cat /tmp/dirty > /dev/null")? {
                bail!("reading guest memory back failed");
            }
            Ok((dirty_mib > 0).then(|| ms(t.elapsed())))
        };
        let read_local = read(&h.a)?;
        // The name is this run's alone, so a migration that got as far as b is ours to kill there too.
        owned.hosts.push(&h.b);
        let migrated = crate::vmproc::call(&h.a, name, json!({"op": "migrate", "to": to}), None)?;
        let read_after = read(&h.b)?;
        h.wait("the source to let go", || !h.a.alive(name))?;
        let pull = h.pulled(&h.b, name)?;
        let status = crate::vmproc::call(&h.b, name, json!({"op": "debug", "what": "status"}), None)?;
        sample["migrate"] = migrated["timings_ms"].clone();
        sample["migrate"]["downtime"] = migrated["downtime_ms"].clone();
        sample["migrate"]["background_pull"] = pull;
        sample["migrate_target"] = migrated["target_timings_ms"].clone();
        // Fault service on the target, by kind (see `uffd::FaultStats`).
        let mut post = fault_report(&status["faults"])?;
        if let (Some(local), Some(after)) = (read_local, read_after) {
            post["read_local"] = json!(local);
            post["read_after_migrate"] = json!(after);
            post["stall"] = json!(after - local);
        }
        sample["post_copy"] = post;
    }
    h.check()?;
    h.cli(if h.to.is_some() { &h.b } else { &h.a }, &["rm", "-f", name])?;
    owned.hosts.clear();
    Ok(sample)
}

fn lifecycle_sizes(args: &Args) -> Result<Vec<u64>> {
    let sizes: Vec<u64> = args
        .get("dirty-mib")
        .unwrap_or("0,256,1024")
        .split(',')
        .map(|s| s.trim().parse().map_err(|_| format!("bad --dirty-mib {s:?}")))
        .collect::<std::result::Result<_, _>>()?;
    let mut seen = std::collections::HashSet::new();
    for size in &sizes {
        if !seen.insert(*size) {
            bail!("duplicate --dirty-mib size {size}");
        }
    }
    Ok(sizes)
}

fn lifecycle(h: &Hosts, args: &Args, template: &str, date: &str, id: &str) -> Result<Value> {
    let iterations = args.parse_or::<u64>("iterations", 5)?;
    let sizes = lifecycle_sizes(args)?;
    let mut summary = Map::new();
    let mut all = Map::new();
    let mut error = None;
    let mut sizes_mib = Map::new();
    for &mib in &sizes {
        let mut samples = Vec::new();
        for i in 0..iterations {
            let name = format!("lcbench-{id}-{mib}-{i}");
            let res = h.check().and_then(|()| trial(h, &name, template, mib)).map_err(|e| format!("{mib} MiB, trial {}: {e}", i + 1).into());
            if !record(res, &mut samples, &mut error) {
                break;
            }
            crate::log!("bench: {mib} MiB {}/{iterations}", i + 1);
        }
        let mut s = Map::new();
        for group in ["pause_client", "checkpoint", "restore", "suspend", "resume_suspended"] {
            if !samples.is_empty() {
                s.insert(group.into(), summarize(&samples, group)?);
            }
        }
        sizes_mib.insert(format!("{mib}_mib"), extract_sizes(&mut samples));
        summary.insert(format!("{mib}_mib"), s.into());
        all.insert(format!("{mib}_mib"), samples.into());
        if error.is_some() {
            break;
        }
    }
    Ok(json!({
        "params": {"to": h.to, "template": template, "iterations": iterations, "dirty_mib": sizes, "date": date},
        "status": if error.is_some() { "failed" } else { "ok" },
        "error": error,
        "summary_ms": summary,
        "samples_ms": all,
        "checkpoint_data_mib": sizes_mib,
    }))
}

fn extract_sizes(samples: &mut [Value]) -> Value {
    samples.iter_mut().map(|s| s.as_object_mut().unwrap().remove("checkpoint_data_mib").unwrap_or(Value::Null)).collect()
}

/// Ten pause/resume cycles, checkpoint --stop, restore on `b` (by its path in `a`'s store), then suspend and resume.
fn trial(h: &Hosts, name: &str, template: &str, mib: u64) -> Result<Value> {
    h.cli(&h.a, &["run", "--name", name, "-d", template])?;
    let mut owned = OwnedVm { h, name, hosts: vec![&h.a], checkpoint: None };
    h.check()?;
    if mib > 0 && !h.exec(&h.a, name, &format!("dd if=/dev/urandom of=/tmp/f bs=1M count={mib} 2>/dev/null"))? {
        bail!("dirtying guest memory failed");
    }
    let (mut p, mut r) = (Vec::new(), Vec::new());
    for _ in 0..10 {
        h.check()?;
        let t = Instant::now();
        h.a.signal(name, libc::SIGTSTP)?;
        h.wait("pause", || Hosts::state(&h.a, name) == "paused")?;
        p.push(ms(t.elapsed()));
        thread::sleep(Duration::from_millis(20));
        let t = Instant::now();
        h.a.signal(name, libc::SIGCONT)?;
        h.wait("resume", || Hosts::state(&h.a, name) == "running")?;
        r.push(ms(t.elapsed()));
        thread::sleep(Duration::from_millis(20));
    }
    let med = |v: &mut Vec<f64>| {
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    };
    // Signal dispatch, entry/lock reads and the 1 ms state polling interval are included.
    let pause_client = json!({"pause_client": med(&mut p), "resume_client": med(&mut r)});

    let c = crate::vmproc::call(&h.a, name, json!({"op": "checkpoint", "stop": true}), None)?;
    let mut checkpoint = c["timings_ms"].clone();
    checkpoint["paused"] = c["paused_ms"].clone();
    owned.checkpoint = Some(OwnedCheckpoint { state: &h.a.state, id: c["id"].as_str().ok_or("checkpoint reply has no id")?.into() });
    h.wait("the checkpointed vm to go", || !h.a.alive(name))?;
    owned.hosts.clear();

    let restored = |reply: Value| -> Result<Value> {
        let mut t = reply["timings_ms"].clone();
        t["ready"] = reply["ready_ms"].clone();
        t["pull"] = h.pulled(&h.b, name)?;
        Ok(t)
    };
    let ck = c["dir"].as_str().unwrap_or_default().to_string();
    let mut argv = vec!["run", "--checkpoint", &ck, "--name", name, "-d"];
    if h.to.is_some() || h.a.state != h.b.state || h.a.run != h.b.run {
        // Another host gives it an address of its own (its own is the first host's to give).
        argv.extend(["--ip", "auto"]);
    }
    let reply = h.cli(&h.b, &argv);
    // Open once restored: its files stay readable.
    drop(owned.checkpoint.take());
    let reply = reply?;
    owned.hosts.push(&h.b);
    h.check()?;
    let restore = restored(reply)?;

    let t = Instant::now();
    h.b.signal(name, libc::SIGTERM)?;
    h.wait("suspend", || !h.b.alive(name))?;
    let suspend = json!({"total": ms(t.elapsed())});
    let resume_suspended = restored(h.cli(&h.b, &["start", name])?)?;
    h.check()?;
    Ok(
        json!({"checkpoint_data_mib": c["data_mib"], "pause_client": pause_client, "checkpoint": checkpoint, "restore": restore, "suspend": suspend, "resume_suspended": resume_suspended}),
    )
}

fn host_context(template: &str) -> Value {
    let read = |path| std::fs::read_to_string(path).ok().map(|s: String| s.trim().to_string());
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let model = cpuinfo.lines().filter_map(|l| l.split_once(':')).find(|(k, _)| k.trim() == "model name");
    json!({
        "hostname": read("/proc/sys/kernel/hostname"),
        "kernel": read("/proc/sys/kernel/osrelease"),
        "loadavg": read("/proc/loadavg"),
        "cpu_model": model.map(|(_, v)| v.trim()),
        "host_cpus": crate::util::host_cpus(),
        "nested_virt": cpuinfo.split_whitespace().any(|f| f == "hypervisor"),
        "template": template,
    })
}

fn wait_ready(h: &Hosts, addr: SocketAddr, http: bool, deadline: Instant) -> Result<()> {
    loop {
        h.check()?;
        let attempt = (|| -> std::io::Result<()> {
            let mut c = TcpStream::connect_timeout(&addr, Duration::from_millis(200))?;
            if http {
                c.set_read_timeout(Some(Duration::from_secs(2)))?;
                c.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
                let mut b = [0u8; 1];
                if c.read(&mut b)? == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
            }
            Ok(())
        })();
        match attempt {
            Ok(()) => return Ok(()),
            Err(e) if Instant::now() >= deadline => bail!("{addr} not ready: {e}"),
            Err(_) => thread::sleep(Duration::from_millis(1)),
        }
    }
}

fn fault_report(faults: &Value) -> Result<Value> {
    let mut post = json!({});
    for (kind, stats) in faults.as_object().ok_or("status has no fault report")? {
        for stat in ["count", "sum_ms", "p50_us", "p99_us", "max_us"] {
            post[format!("{kind}_{stat}")] = stats[stat].clone();
        }
    }
    // These kinds service faults that block vCPUs (or Firecracker threads).
    let blocked: f64 = ["local", "remote", "wait", "wp"].iter().filter_map(|k| faults[k]["sum_ms"].as_f64()).sum();
    post["fault_blocked"] = json!(blocked);
    Ok(post)
}

fn run_summary(samples: &[Value]) -> Result<Value> {
    let mut summary = json!({});
    for (standby, group) in [(true, "run_standby"), (false, "run_cold")] {
        let population: Vec<_> = samples.iter().filter(|s| s["standby"] == standby).cloned().collect();
        if !population.is_empty() {
            summary[group] = summarize(&population, "run")?;
            summary[format!("{group}_client")] = summarize(&population, "run_client")?;
            // With --ready-port: until the app answers.
            if population.iter().all(|s| s.get("client").is_some()) {
                summary[group.replace("run", "ready")] = summarize(&population, "client")?;
            }
        }
    }
    Ok(summary)
}

/// Nearest-rank percentiles over observed values only, with each phase's sample count.
fn summarize(samples: &[Value], group: &str) -> Result<Value> {
    let mut phases: Vec<&String> = Vec::new();
    for s in samples {
        let Some(p) = s[group].as_object() else {
            bail!("a sample has no {group} timings");
        };
        for k in p.keys() {
            if !phases.contains(&k) {
                phases.push(k);
            }
        }
    }
    if phases.is_empty() {
        bail!("no {group} timings");
    }
    let mut summary = Map::new();
    for phase in phases {
        let mut v: Vec<f64> = samples.iter().filter_map(|s| s[group][phase].as_f64()).collect();
        if v.is_empty() {
            continue;
        }
        v.sort_by(f64::total_cmp);
        let rank = |p: usize| v[(v.len() * p).div_ceil(100) - 1];
        summary.insert(phase.clone(), json!({"count": v.len(), "p50": rank(50), "p90": rank(90), "p99": rank(99), "max": v[v.len() - 1]}));
    }
    Ok(summary.into())
}

fn command(bin: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(bin).args(args).output()?;
    if !out.status.success() {
        bail!("{bin} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_lifecycle_sizes_are_rejected_before_running() {
        for sizes in ["1,1", "0,256,0", "1, 01"] {
            let args = Args::parse(["--lifecycle", "--dirty-mib", sizes].map(String::from)).unwrap();
            assert!(validate(&args).unwrap_err().to_string().contains("duplicate --dirty-mib"));
        }
        let args = Args::parse(["--lifecycle", "--dirty-mib", "256,0,1"].map(String::from)).unwrap();
        assert_eq!(lifecycle_sizes(&args).unwrap(), [256, 0, 1]);
    }

    #[test]
    fn exec_cancellation_reaps_child() {
        let cancelled = AtomicBool::new(false);
        for code in [0, 7] {
            let mut child = Command::new("sh").args(["-c", &format!("exit {code}")]).spawn().unwrap();
            assert_eq!(wait_exec(&mut child, &cancelled).unwrap().code(), Some(code));
        }
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        cancelled.store(true, Ordering::Relaxed);
        assert_eq!(wait_exec(&mut child, &cancelled).unwrap_err().to_string(), "benchmark interrupted");
        assert!(child.try_wait().unwrap().is_some());
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child.id() as i32, &mut status, libc::WNOHANG) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    }

    #[test]
    fn same_second_reports_are_distinct() {
        let dir = crate::test_util::TempDir::new("bench-reports");
        for suffix in ["", "-lifecycle"] {
            for id in ["123-1", "123-2"] {
                let path = report_path(dir.to_str().unwrap(), "2026-10-20T12-00-00Z", "abcdef0123", id, suffix);
                assert!(path.ends_with(&format!("-abcdef0-{id}{suffix}.json")));
                let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
                serde_json::to_writer(file, &json!({"status": "failed", "error": id, "samples_ms": [1]})).unwrap();
            }
            for id in ["123-1", "123-2"] {
                let path = report_path(dir.to_str().unwrap(), "2026-10-20T12-00-00Z", "abcdef0123", id, suffix);
                let report: Value = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();
                assert_eq!(report["error"], id);
                assert_eq!(report["samples_ms"], json!([1]));
            }
        }
    }

    #[test]
    fn cancellation_stops_waits_and_runs_cleanup() {
        const CHILD: &str = "FLEXVM_TEST_BENCH_SIGNAL";
        if let Some(sig) = std::env::var_os(CHILD) {
            let dir = crate::test_util::TempDir::new("bench-signal");
            let cancelled = Arc::new(AtomicBool::new(false));
            let flag = cancelled.clone();
            crate::util::on_signal(&[libc::SIGINT, libc::SIGTERM], move |_| flag.store(true, Ordering::Relaxed));
            // A dangling checkpoint name exercises cleanup without starting a VM.
            let names = dir.join("checkpoints/names");
            std::fs::create_dir_all(&names).unwrap();
            std::os::unix::fs::symlink("../missing", names.join("bench-test")).unwrap();
            let owned = OwnedCheckpoint { state: &dir, id: "bench-test".into() };
            let mut child = Command::new("sleep").arg("30").process_group(0).spawn().unwrap();
            unsafe {
                libc::kill(libc::getpid(), sig.to_str().unwrap().parse().unwrap());
            }
            assert!(wait_exec(&mut child, &cancelled).unwrap_err().to_string().contains("interrupted"));
            assert!(child.try_wait().unwrap().is_some());
            assert!(wait(&cancelled, Duration::from_secs(1), "signal", || false).unwrap_err().to_string().contains("interrupted"));
            assert!(wait(&cancelled, Duration::from_secs(1), "already ready", || true).is_err());
            assert!(check(&cancelled).is_err());
            drop(owned);
            assert!(std::fs::symlink_metadata(names.join("bench-test")).is_err());
            return;
        }
        for sig in [libc::SIGINT, libc::SIGTERM] {
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            // Block before the test harness starts its threads.
            unsafe {
                cmd.pre_exec(|| {
                    crate::util::block_signals(&[libc::SIGINT, libc::SIGTERM]);
                    Ok(())
                });
            }
            let out =
                cmd.args(["--exact", "bench::tests::cancellation_stops_waits_and_runs_cleanup", "--nocapture"]).env(CHILD, sig.to_string()).output().unwrap();
            assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        }
    }

    #[test]
    fn failed_trials_keep_completed_samples() {
        let mut samples = Vec::new();
        let mut error = None;
        assert!(record(Ok(json!({"run": {"total": 4}})), &mut samples, &mut error));
        assert!(!record(Err("trial failed".into()), &mut samples, &mut error));
        assert_eq!(error.as_deref(), Some("trial failed"));
        assert_eq!(summarize(&samples, "run").unwrap()["total"]["count"], 1);
        let mut empty = Vec::new();
        assert!(!record(Err("first trial failed".into()), &mut empty, &mut error));
        assert!(empty.is_empty());
    }

    #[test]
    fn lifecycle_rejects_unused_flags_and_zero_iterations() {
        for lifecycle in [false, true] {
            let mut argv = vec!["--iterations", "0"];
            if lifecycle {
                argv.push("--lifecycle");
            }
            assert!(validate(&Args::parse(argv.into_iter().map(String::from)).unwrap()).is_err());
        }
        for flag in ["--warmup", "--settle-ms", "--ready-port", "--ready-http"] {
            let args = Args::parse(["--lifecycle", flag, "1"].map(String::from)).unwrap();
            assert!(validate(&args).unwrap_err().to_string().contains(flag));
        }
        assert!(validate(&Args::parse(["--lifecycle", "--iterations", "1"].map(String::from)).unwrap()).is_ok());
    }

    #[test]
    fn checkpoint_sizes_are_not_timings() {
        let mut samples = vec![json!({"checkpoint": {"total": 2}, "checkpoint_data_mib": 256})];
        assert_eq!(extract_sizes(&mut samples), json!([256]));
        assert_eq!(summarize(&samples, "checkpoint").unwrap(), json!({"total": {"count": 1, "p50": 2.0, "p90": 2.0, "p99": 2.0, "max": 2.0}}));
        assert!(samples[0].get("checkpoint_data_mib").is_none());
    }

    #[test]
    fn sha_is_resolved_before_opening_hosts_or_running_iterations() {
        const CHILD: &str = "FLEXVM_TEST_BENCH_NO_GIT";
        if std::env::var_os(CHILD).is_some() {
            let args = Args::parse(["--state", "state", "--run", "run"].map(String::from)).unwrap();
            let error = run(&args).unwrap_err().to_string();
            assert!(error.starts_with("git failed:"), "{error}");
            assert!(!std::path::Path::new("state").exists());
            assert!(!std::path::Path::new("run").exists());
            return;
        }
        let dir = crate::test_util::TempDir::new("bench-no-git");
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "bench::tests::sha_is_resolved_before_opening_hosts_or_running_iterations", "--nocapture"])
            .current_dir(&dir)
            .env(CHILD, "1")
            // Even when the temporary directory is inside a checkout.
            .env("GIT_CEILING_DIRECTORIES", dir.parent().unwrap())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .output()
            .unwrap();
        assert!(output.status.success(), "{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    }

    #[test]
    fn run_populations_are_separate() {
        let samples = [
            json!({"standby": true, "run": {"total": 2, "fence": 1}, "run_client": {"total": 4}}),
            json!({"standby": true, "run": {"total": 3, "fence": 2}, "run_client": {"total": 5}}),
            json!({"standby": false, "run": {"total": 50, "snapshot_load": 40}, "run_client": {"total": 55}}),
        ];
        let summary = run_summary(&samples).unwrap();
        assert_eq!(summary["run_standby"]["total"]["p50"], 2.0);
        assert_eq!(summary["run_cold"]["snapshot_load"]["p50"], 40.0);
        assert_eq!(summary["run_cold_client"]["total"]["count"], 1);
        assert!(summary["run_standby"]["snapshot_load"].is_null());
        assert!(run_summary(&samples[..2]).unwrap()["run_cold"].is_null());
        assert!(summary["ready_standby"].is_null());
        let ready: Vec<_> = samples
            .iter()
            .cloned()
            .map(|mut s| {
                s["client"] = json!({"total": s["run_client"]["total"].as_f64().unwrap() + 10.0});
                s
            })
            .collect();
        let summary = run_summary(&ready).unwrap();
        assert_eq!(summary["ready_standby"]["total"]["max"], 15.0);
        assert_eq!(summary["ready_cold"]["total"]["count"], 1);
    }

    #[test]
    fn fault_report_includes_wp_and_future_kinds() {
        let faults = json!({
            "local": {"sum_ms": 1}, "remote": {"sum_ms": 2}, "wait": {"sum_ms": 3},
            "wp": {"count": 7, "sum_ms": 4, "p99_us": 900},
            "pull": {"sum_ms": 100}, "future": {"count": 8},
        });
        let report = fault_report(&faults).unwrap();
        assert_eq!(report["fault_blocked"], 10.0);
        assert_eq!(report["wp_count"], 7);
        assert_eq!(report["wp_p99_us"], 900);
        assert_eq!(report["future_count"], 8);
        assert!(fault_report(&Value::Null).is_err());
    }

    #[test]
    fn nearest_rank_percentiles() {
        let samples: Vec<_> = (1..=100).rev().map(|n| json!({"run": {"total": n}})).collect();
        let want = json!({"total": {"count": 100, "p50": 50.0, "p90": 90.0, "p99": 99.0, "max": 100.0}});
        assert_eq!(summarize(&samples, "run").unwrap(), want);
        let want = json!({"total": {"count": 1, "p50": 100.0, "p90": 100.0, "p99": 100.0, "max": 100.0}});
        assert_eq!(summarize(&samples[..1], "run").unwrap(), want);
        assert!(summarize(&[], "run").is_err());
        let mixed = [json!({"run": {"load": 3, "total": 4}}), json!({"run": {"resume": 1, "total": 2}})];
        let want = json!({
            "load": {"count": 1, "p50": 3.0, "p90": 3.0, "p99": 3.0, "max": 3.0},
            "total": {"count": 2, "p50": 2.0, "p90": 4.0, "p99": 4.0, "max": 4.0},
            "resume": {"count": 1, "p50": 1.0, "p90": 1.0, "p99": 1.0, "max": 1.0},
        });
        assert_eq!(summarize(&mixed, "run").unwrap(), want);
        assert!(summarize(&[json!({"run": {"total": 1}}), json!({})], "run").is_err());
    }
}
