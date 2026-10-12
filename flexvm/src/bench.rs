//! `flexvm bench`: runs (and optionally migrates) fresh VMs against live
//! daemons and writes per-phase latency percentiles to `bench/`. Every number
//! is a daemon-side phase timing; the phases of each op sum to its `total`.

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::util::Result;
use crate::{bail, call_with_timeout, Args};

pub fn run(host: &str, args: &Args) -> Result<()> {
    let iterations = args.num("iterations", 50)?;
    let warmup = args.num("warmup", 3)?;
    let dirty_mib = args.num("dirty-mib", 0)?;
    let timeout = Duration::from_secs(args.num("timeout", 120)?.max(1));
    let settle = Duration::from_millis(args.num("settle-ms", 100)?);
    let template = args.get("template").unwrap_or("default");
    let (to, ip) = (args.get("to"), args.get("ip"));
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
        let sample = iteration(host, to, &name, template, ip, dirty_mib, timeout).map_err(|e| {
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

    let mut summary = json!({"run": summarize(&samples, "run")?});
    if to.is_some() {
        summary["migrate"] = summarize(&samples, "migrate")?;
        summary["migrate_target"] = summarize(&samples, "migrate_target")?;
    }
    let report = json!({
        "date_utc": date,
        "git_sha": sha,
        "git_dirty": !command("git", &["status", "--porcelain"])?.is_empty(),
        "params": {
            "host": host, "to": to, "template": template, "ip": ip, "iterations": iterations,
            "warmup": warmup, "dirty_mib": dirty_mib, "settle_ms": settle.as_millis(),
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
fn iteration(
    host: &str,
    to: Option<&str>,
    name: &str,
    template: &str,
    ip: Option<&str>,
    dirty_mib: u64,
    timeout: Duration,
) -> Result<Value> {
    let rpc = |host: &str, req| call_with_timeout(host, req, timeout);
    let run = rpc(host, json!({"op": "run", "name": name, "template": template, "ip": ip}))?;
    let mut sample = json!({"run": run["timings_ms"]});
    if let Some(to) = to {
        if dirty_mib > 0 {
            // /tmp is a tmpfs, so this lands in guest memory.
            let cmd = format!("dd if=/dev/urandom of=/tmp/dirty bs=1M count={dirty_mib} 2>/dev/null");
            if crate::exec(host, name, &cmd)? != 0 {
                bail!("dirtying guest memory failed");
            }
        }
        let migrated = rpc(host, json!({"op": "migrate", "name": name, "to": to}))?;
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
    }
    rpc(to.unwrap_or(host), json!({"op": "kill", "name": name}))?;
    Ok(sample)
}

/// Nearest-rank p50/p90/p99/max of every phase in `group`.
fn summarize(samples: &[Value], group: &str) -> Result<Value> {
    let Some(phases) = samples.first().and_then(|s| s[group].as_object()) else {
        bail!("no {group} timings; are the daemons up to date?");
    };
    let mut summary = Map::new();
    for phase in phases.keys() {
        let mut v = samples
            .iter()
            .map(|s| s[group][phase].as_f64().ok_or(format!("a sample is missing {group}.{phase}")))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        v.sort_by(f64::total_cmp);
        let rank = |p: usize| v[(v.len() * p).div_ceil(100) - 1];
        summary.insert(phase.clone(), json!({"p50": rank(50), "p90": rank(90), "p99": rank(99), "max": v[v.len() - 1]}));
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
    fn nearest_rank_percentiles() {
        let samples: Vec<_> = (1..=100).rev().map(|n| json!({"run": {"total": n}})).collect();
        let want = json!({"total": {"p50": 50.0, "p90": 90.0, "p99": 99.0, "max": 100.0}});
        assert_eq!(summarize(&samples, "run").unwrap(), want);
        let want = json!({"total": {"p50": 100.0, "p90": 100.0, "p99": 100.0, "max": 100.0}});
        assert_eq!(summarize(&samples[..1], "run").unwrap(), want);
        assert!(summarize(&[], "run").is_err());
        assert!(summarize(&[json!({"run": {"total": 1}}), json!({"run": {}})], "run").is_err());
    }
}
