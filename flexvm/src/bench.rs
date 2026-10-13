//! `flexvm bench`: runs (and optionally migrates) fresh VMs against live
//! daemons and writes per-phase latency percentiles to `bench/`. Every number
//! is a daemon-side phase timing; the phases of each op sum to its `total`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::util::{ms, Result};
use crate::{bail, call_with_timeout, Args};

pub fn run(host: &str, args: &Args) -> Result<()> {
    let iterations = args.num("iterations", 50)?;
    let warmup = args.num("warmup", 3)?;
    let dirty_mib = args.num("dirty-mib", 0)?;
    let timeout = Duration::from_secs(args.num("timeout", 120)?.max(1));
    let settle = Duration::from_millis(args.num("settle-ms", 100)?);
    let template = args.get("template").unwrap_or("default");
    let (to, ip) = (args.get("to"), args.get("ip"));
    // Image apps: also time, from the client, until the app answers.
    let ready = match (args.get("ready-port"), args.get("ready-http")) {
        (Some(p), None) => Some((p.parse().map_err(|_| "bad --ready-port")?, false)),
        (None, Some(p)) => Some((p.parse().map_err(|_| "bad --ready-http")?, true)),
        (None, None) => None,
        _ => bail!("pass --ready-port or --ready-http, not both"),
    };
    if iterations == 0 {
        bail!("--iterations must be positive");
    }
    if dirty_mib > 0 && to.is_none() {
        bail!("--dirty-mib needs --to");
    }
    let rpc = |host: &str, req| call_with_timeout(host, req, timeout);
    let info = |host: &str| rpc(host, json!({"op": "bench_info", "template": template}));
    let source = info(host)?;
    let target = to.map(info).transpose()?;
    if target.as_ref().is_some_and(|t| t["daemon"]["addr"] == source["daemon"]["addr"]) {
        bail!("--to must be a different daemon");
    }

    let date = command("date", &["-u", "+%Y-%m-%dT%H-%M-%SZ"])?;
    let sha = command("git", &["rev-parse", "HEAD"])?;
    let dir = format!("{}/bench", command("git", &["rev-parse", "--show-toplevel"])?);
    let mut samples = Vec::new();
    for i in 0..warmup + iterations {
        let name = format!("bench-{}-{date}-{i}", std::process::id());
        let sample = iteration(host, to, &name, template, ip, dirty_mib, ready, timeout).map_err(|e| {
            // The VM may be on either host, depending on where the trial failed.
            for h in to.into_iter().chain([host]) {
                let _ = rpc(h, json!({"op": "kill", "name": name}));
            }
            format!("iteration {} failed: {e}", i + 1)
        })?;
        if i >= warmup {
            samples.push(sample);
        }
        eprintln!("bench: {}/{}{}", i + 1, warmup + iterations, if i < warmup { " (warmup)" } else { "" });
        // Let the pool refill between trials; misses still show up in pool_take.
        thread::sleep(settle);
    }

    let hot = samples.iter().filter(|s| s["hot"] == json!(true)).count();
    let mut summary = json!({"run": summarize(&samples, "run")?, "run_hot_pool_hits": hot});
    if ready.is_some() {
        summary["client"] = summarize(&samples, "client")?;
    }
    if to.is_some() {
        summary["migrate"] = summarize(&samples, "migrate")?;
        summary["migrate_target"] = summarize(&samples, "migrate_target")?;
        summary["post_copy"] = summarize(&samples, "post_copy")?;
    }
    let report = json!({
        "date_utc": date,
        "git_sha": sha,
        "git_dirty": !command("git", &["status", "--porcelain"])?.is_empty(),
        "params": {
            "host": host, "to": to, "template": template, "ip": ip, "iterations": iterations,
            "warmup": warmup, "dirty_mib": dirty_mib, "settle_ms": settle.as_millis(),
            "ready_port": ready.map(|r| r.0), "ready_http": ready.is_some_and(|r| r.1),
        },
        "host_context": {"source": source, "target": target},
        "summary_ms": summary,
        "samples_ms": samples,
    });
    std::fs::create_dir_all(&dir)?;
    let path = format!("{dir}/{date}-{}.json", &sha[..7]);
    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
    serde_json::to_writer_pretty(file, &report)?;
    println!("{path}");
    Ok(())
}

/// One trial: run `name`, optionally dirty its memory and migrate it, then
/// kill it. Returns its phase timings grouped by op.
#[allow(clippy::too_many_arguments)]
fn iteration(
    host: &str,
    to: Option<&str>,
    name: &str,
    template: &str,
    ip: Option<&str>,
    dirty_mib: u64,
    ready: Option<(u16, bool)>,
    timeout: Duration,
) -> Result<Value> {
    let rpc = |host: &str, req| call_with_timeout(host, req, timeout);
    let start = Instant::now();
    let run = rpc(host, json!({"op": "run", "name": name, "template": template, "ip": ip}))?;
    let run_rpc = start.elapsed();
    let mut sample = json!({"run": run["timings_ms"], "hot": run["hot"]});
    if let Some((port, http)) = ready {
        let ip: std::net::Ipv4Addr = run["ip"].as_str().ok_or("run reply has no ip")?.parse()?;
        wait_ready((ip, port).into(), http, start + timeout)?;
        sample["client"] = json!({
            "run_rpc": ms(run_rpc),
            "app_ready": ms(start.elapsed() - run_rpc),
            "total": ms(start.elapsed()),
        });
    }
    if let Some(to) = to {
        if dirty_mib > 0 {
            // /tmp is a tmpfs, so this lands in guest memory.
            let cmd = format!("dd if=/dev/urandom of=/tmp/dirty bs=1M count={dirty_mib} 2>/dev/null");
            if crate::exec(host, name, &cmd)? != 0 {
                bail!("dirtying guest memory failed");
            }
        }
        // The guest reads what it wrote, here and right after the migration
        // (while its pages are still being pulled): the difference is how
        // long post-copy faults stalled it.
        let read = |h: &str| -> Result<f64> {
            let t = Instant::now();
            if crate::exec(h, name, "cat /tmp/dirty > /dev/null")? != 0 {
                bail!("reading guest memory back failed");
            }
            Ok(ms(t.elapsed()))
        };
        let read_local = if dirty_mib > 0 { Some(read(host)?) } else { None };
        let migrated = rpc(host, json!({"op": "migrate", "name": name, "to": to}))?;
        let read_after = if dirty_mib > 0 { Some(read(to)?) } else { None };
        // Wait for the full pull and for the source to drop its copy.
        let deadline = Instant::now() + timeout;
        let status = loop {
            let status = rpc(to, json!({"op": "migration_status", "name": name}))?;
            if !status["released"].is_null() && status["background_pull_ms"].is_number() {
                break status;
            }
            if Instant::now() >= deadline {
                bail!("migration pull did not finish within {timeout:?}");
            }
            thread::sleep(Duration::from_millis(10));
        };
        if status["released"] != json!(true) {
            bail!("source release failed: {}", status["released"]);
        }
        sample["migrate"] = migrated["timings_ms"].clone();
        sample["migrate"]["downtime"] = migrated["downtime_ms"].clone();
        sample["migrate"]["background_pull"] = status["background_pull_ms"].clone();
        sample["migrate_target"] = migrated["target_timings_ms"].clone();
        // Fault service on the target, by kind (see `uffd::FaultStats`).
        let f = &status["faults"];
        let mut post = json!({});
        for kind in ["local", "remote", "wait", "fetch", "pull"] {
            for stat in ["count", "sum_ms", "p50_us", "p99_us", "max_us"] {
                post[format!("{kind}_{stat}")] = f[kind][stat].clone();
            }
        }
        // How long vCPUs (and Firecracker's own threads) were blocked on
        // missing pages in all.
        let blocked: f64 = ["local", "remote", "wait"].iter().filter_map(|k| f[k]["sum_ms"].as_f64()).sum();
        post["fault_blocked"] = json!(blocked);
        if let (Some(local), Some(after)) = (read_local, read_after) {
            post["read_local"] = json!(local);
            post["read_after_migrate"] = json!(after);
            post["stall"] = json!(after - local);
        }
        sample["post_copy"] = post;
    }
    rpc(to.unwrap_or(host), json!({"op": "kill", "name": name}))?;
    Ok(sample)
}

/// Waits until `addr` accepts a TCP connection or, with `http`, answers a GET.
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

/// Nearest-rank p50/p90/p99/max of every phase in `group`. A phase only some
/// samples went through (e.g. the snapshot load on a hot pool miss) counts as
/// 0 in the others, so the phases still add up to each sample's total.
pub(crate) fn summarize(samples: &[Value], group: &str) -> Result<Value> {
    let mut phases: Vec<&String> = Vec::new();
    for s in samples {
        let Some(p) = s[group].as_object() else {
            bail!("a sample has no {group} timings; are the daemons up to date?");
        };
        for k in p.keys() {
            if !phases.contains(&k) {
                phases.push(k);
            }
        }
    }
    if phases.is_empty() {
        bail!("no {group} timings; are the daemons up to date?");
    }
    let mut summary = Map::new();
    for phase in phases {
        let mut v: Vec<f64> = samples.iter().map(|s| s[group][phase].as_f64().unwrap_or(0.0)).collect();
        v.sort_by(f64::total_cmp);
        let rank = |p: usize| v[(v.len() * p).div_ceil(100) - 1];
        summary.insert(phase.clone(), json!({"p50": rank(50), "p90": rank(90), "p99": rank(99), "max": v[v.len() - 1]}));
    }
    Ok(summary.into())
}

pub(crate) fn command(bin: &str, args: &[&str]) -> Result<String> {
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
    fn nearest_rank_percentiles() {
        let samples: Vec<_> = (1..=100).rev().map(|n| json!({"run": {"total": n}})).collect();
        let want = json!({"total": {"p50": 50.0, "p90": 90.0, "p99": 99.0, "max": 100.0}});
        assert_eq!(summarize(&samples, "run").unwrap(), want);
        let want = json!({"total": {"p50": 100.0, "p90": 100.0, "p99": 100.0, "max": 100.0}});
        assert_eq!(summarize(&samples[..1], "run").unwrap(), want);
        assert!(summarize(&[], "run").is_err());
        let mixed = [json!({"run": {"load": 3, "total": 4}}), json!({"run": {"resume": 1, "total": 2}})];
        let want = json!({
            "load": {"p50": 0.0, "p90": 3.0, "p99": 3.0, "max": 3.0},
            "total": {"p50": 2.0, "p90": 4.0, "p99": 4.0, "max": 4.0},
            "resume": {"p50": 0.0, "p90": 1.0, "p99": 1.0, "max": 1.0},
        });
        assert_eq!(summarize(&mixed, "run").unwrap(), want);
        assert!(summarize(&[json!({"run": {"total": 1}}), json!({})], "run").is_err());
    }
}
