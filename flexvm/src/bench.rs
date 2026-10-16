//! `flexvm bench`: runs (and optionally migrates) fresh VMs and writes per-phase latency
//! percentiles to `bench/`; `--lifecycle DIR` times pause, checkpoint, restore and suspend.
//! VMs are driven as a user would; migrations go to another host on this machine.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
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
}

/// Only successful starts confer ownership; a refused name must never be killed.
struct OwnedVm<'a> {
    h: &'a Hosts,
    name: &'a str,
    hosts: Vec<&'a Host>,
}

impl Drop for OwnedVm<'_> {
    fn drop(&mut self) {
        for host in &self.hosts {
            if let Err(e) = self.h.cli(host, &["kill", self.name]) {
                crate::log!("bench: cleanup {}: {e}", self.name);
            }
        }
    }
}

impl Hosts {
    fn cli(&self, host: &Host, args: &[&str]) -> Result<Value> {
        let out = Command::new("/proc/self/exe").arg("--state").arg(&host.state).arg("--run").arg(&host.run).args(args).output()?;
        if !out.status.success() {
            bail!("flexvm {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(serde_json::from_slice(&out.stdout).unwrap_or(Value::Null))
    }

    fn state(host: &Host, name: &str) -> String {
        host.entry(name).map(|e| e.state).unwrap_or_default()
    }

    fn wait(&self, what: &str, cond: impl Fn() -> bool) -> Result<()> {
        let deadline = Instant::now() + self.timeout;
        while !cond() {
            if Instant::now() >= deadline {
                bail!("timed out waiting for {what}");
            }
            thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    fn pulled(&self, host: &Host, name: &str) -> Result<Value> {
        let deadline = Instant::now() + self.timeout;
        loop {
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
    let hosts = Hosts { a, b, to, timeout };
    let template = args.get("template").unwrap_or("default");
    let date = command("date", &["-u", "+%Y-%m-%dT%H-%M-%SZ"])?;
    let id = format!("{}-{}", std::process::id(), crate::migrate::migration_id());
    let (report, suffix) = match args.get("lifecycle") {
        Some(dir) => {
            let parent = std::path::absolute(dir)?;
            std::fs::create_dir_all(&parent)?;
            let scratch = parent.join(format!("bench-{id}"));
            std::fs::create_dir(&scratch)?;
            let report = lifecycle(&hosts, args, template, &scratch, &date, &id);
            if let Err(e) = std::fs::remove_dir_all(&scratch) {
                crate::log!("bench: cleanup {}: {e}", scratch.display());
            }
            (report, "-lifecycle")
        }
        None => (runs(&hosts, args, template, &date, &id), ""),
    };
    let mut report = report?;
    report["date_utc"] = json!(date);
    report["git_sha"] = json!(sha);
    report["git_dirty"] = json!(dirty);
    report["host_context"] = host_context(template);
    let path = format!("{dir}/{date}-{}{suffix}.json", &sha[..7]);
    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
    serde_json::to_writer_pretty(file, &report)?;
    crate::output(format_args!("{path}\n"))?;
    Ok(())
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
    if iterations == 0 {
        bail!("--iterations must be positive");
    }
    if dirty_mib > 0 && h.to.is_none() {
        bail!("--dirty-mib needs --to");
    }
    let mut samples = Vec::new();
    for i in 0..warmup + iterations {
        let name = format!("bench-{id}-{i}");
        let sample = iteration(h, &name, template, dirty_mib, ready).map_err(|e| format!("iteration {} failed: {e}", i + 1))?;
        if i >= warmup {
            samples.push(sample);
        }
        crate::log!("bench: {}/{}{}", i + 1, warmup + iterations, if i < warmup { " (warmup)" } else { "" });
        // Let standby VMs refill between trials; misses show up as cold runs.
        thread::sleep(settle);
    }
    let standby = samples.iter().filter(|s| s["standby"] == json!(true)).count();
    let mut summary = run_summary(&samples)?;
    summary["run_standby_hits"] = json!(standby);
    if ready.is_some() {
        summary["client"] = summarize(&samples, "client")?;
    }
    if h.to.is_some() {
        summary["migrate"] = summarize(&samples, "migrate")?;
        summary["migrate_target"] = summarize(&samples, "migrate_target")?;
        summary["post_copy"] = summarize(&samples, "post_copy")?;
    }
    Ok(json!({
        "params": {"to": h.to, "template": template, "iterations": iterations, "warmup": warmup, "dirty_mib": dirty_mib,
                   "settle_ms": settle.as_millis(), "ready_port": ready.map(|r| r.0), "ready_http": ready.is_some_and(|r| r.1), "date": date},
        "summary_ms": summary,
        "samples_ms": samples,
    }))
}

fn iteration(h: &Hosts, name: &str, template: &str, dirty_mib: u64, ready: Option<(u16, bool)>) -> Result<Value> {
    let start = Instant::now();
    let run = h.cli(&h.a, &["run", name, "--template", template, "-d"])?;
    let run_cli = start.elapsed();
    let mut owned = OwnedVm { h, name, hosts: vec![&h.a] };
    let mut sample = json!({"run": run["timings_ms"], "standby": run["standby"], "run_client": {"total": ms(run_cli)}});
    if let Some((port, http)) = ready {
        let ip: std::net::Ipv4Addr = run["ip"].as_str().ok_or("run reply has no ip")?.parse()?;
        wait_ready((ip, port).into(), http, start + h.timeout)?;
        let total = start.elapsed();
        sample["client"] = json!({"run_cli": ms(run_cli), "app_ready": ms(total - run_cli), "total": ms(total)});
    }
    if let Some(to) = &h.to {
        if dirty_mib > 0 {
            // /tmp is a tmpfs, so this lands in guest memory.
            let cmd = format!("dd if=/dev/urandom of=/tmp/dirty bs=1M count={dirty_mib} 2>/dev/null");
            if crate::exec(&h.a, name, &cmd)? != 0 {
                bail!("dirtying guest memory failed");
            }
        }
        // The guest reads what it wrote, here and right after the migration
        // (pages still being pulled): the difference is the post-copy stall.
        let read = |host: &Host| -> Result<Option<f64>> {
            let t = Instant::now();
            if dirty_mib > 0 && crate::exec(host, name, "cat /tmp/dirty > /dev/null")? != 0 {
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
    h.cli(if h.to.is_some() { &h.b } else { &h.a }, &["kill", name])?;
    owned.hosts.clear();
    Ok(sample)
}

fn lifecycle(h: &Hosts, args: &Args, template: &str, dir: &std::path::Path, date: &str, id: &str) -> Result<Value> {
    let iterations = args.parse_or::<u64>("iterations", 5)?.max(1);
    let sizes: Vec<u64> = args
        .get("dirty-mib")
        .unwrap_or("0,256,1024")
        .split(',')
        .map(|s| s.trim().parse().map_err(|_| format!("bad --dirty-mib {s:?}")))
        .collect::<std::result::Result<_, _>>()?;
    let mut summary = Map::new();
    let mut all = Map::new();
    for &mib in &sizes {
        let mut samples = Vec::new();
        for i in 0..iterations {
            let name = format!("lcbench-{id}-{mib}-{i}");
            let ck = dir.join(&name);
            let res = trial(h, &name, template, mib, &ck);
            let _ = std::fs::remove_dir_all(&ck);
            samples.push(res.map_err(|e| format!("{mib} MiB, trial {}: {e}", i + 1))?);
            crate::log!("bench: {mib} MiB {}/{iterations}", i + 1);
        }
        let mut s = Map::new();
        for group in ["pause_client", "checkpoint", "restore", "suspend", "resume_suspended"] {
            s.insert(group.into(), summarize(&samples, group)?);
        }
        summary.insert(format!("{mib}_mib"), s.into());
        all.insert(format!("{mib}_mib"), samples.into());
    }
    Ok(json!({
        "params": {"to": h.to, "template": template, "iterations": iterations, "dirty_mib": sizes, "date": date},
        "summary_ms": summary,
        "samples_ms": all,
    }))
}

/// Ten pause/resume cycles, checkpoint --stop, restore on `b`, then suspend and resume.
fn trial(h: &Hosts, name: &str, template: &str, mib: u64, ck: &std::path::Path) -> Result<Value> {
    h.cli(&h.a, &["run", name, "--template", template, "-d"])?;
    let mut owned = OwnedVm { h, name, hosts: vec![&h.a] };
    if mib > 0 && crate::exec(&h.a, name, &format!("dd if=/dev/urandom of=/tmp/f bs=1M count={mib} 2>/dev/null"))? != 0 {
        bail!("dirtying guest memory failed");
    }
    let (mut p, mut r) = (Vec::new(), Vec::new());
    for _ in 0..10 {
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

    let c = crate::vmproc::call(&h.a, name, json!({"op": "checkpoint", "dir": ck, "stop": true}), None)?;
    let mut checkpoint = c["timings_ms"].clone();
    checkpoint["paused"] = c["paused_ms"].clone();
    checkpoint["data_mib"] = c["data_mib"].clone();
    h.wait("the checkpointed vm to go", || !h.a.alive(name))?;
    owned.hosts.clear();

    let restored = |reply: Value| -> Result<Value> {
        let mut t = reply["timings_ms"].clone();
        t["ready"] = reply["ready_ms"].clone();
        t["pull"] = h.pulled(&h.b, name)?;
        Ok(t)
    };
    let ck = ck.to_string_lossy();
    let mut argv = vec!["restore", &ck, "--name", name, "-d"];
    if h.to.is_some() || h.a.state != h.b.state || h.a.run != h.b.run {
        // Another host gives it an address of its own (its own is the first host's to give).
        argv.extend(["--ip", "auto"]);
    }
    let reply = h.cli(&h.b, &argv)?;
    owned.hosts.push(&h.b);
    let restore = restored(reply)?;

    let t = Instant::now();
    h.b.signal(name, libc::SIGTERM)?;
    h.wait("suspend", || !h.b.alive(name))?;
    let suspend = json!({"total": ms(t.elapsed())});
    let resume_suspended = restored(h.cli(&h.b, &["resume", name, "-d"])?)?;
    Ok(json!({"pause_client": pause_client, "checkpoint": checkpoint, "restore": restore, "suspend": suspend, "resume_suspended": resume_suspended}))
}

fn host_context(template: &str) -> Value {
    let read = |path| std::fs::read_to_string(path).ok().map(|s: String| s.trim().to_string());
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let model = cpuinfo.lines().find_map(|l| Some(l.split_once(':')?).filter(|(k, _)| k.trim() == "model name"));
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

fn wait_ready(addr: SocketAddr, http: bool, deadline: Instant) -> Result<()> {
    loop {
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
