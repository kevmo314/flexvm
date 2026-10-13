//! `flexvm bench --lifecycle DIR`: pause/resume latency, checkpoint time
//! against touched memory, restore-to-ready and suspend/resume, against live
//! daemons. Checkpoints go to DIR (on disk) and are removed after each trial.

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::bench::{command, summarize};
use crate::util::{ms, Result};
use crate::{bail, call_with_timeout, Args};

pub fn run(host: &str, args: &Args, dir: &str) -> Result<()> {
    let iterations = args.num("iterations", 5)?.max(1);
    let template = args.get("template").unwrap_or("default");
    let to = args.get("to").unwrap_or(host).to_string();
    let sizes: Vec<u64> = args
        .get("dirty-mib")
        .unwrap_or("0,256,1024")
        .split(',')
        .map(|s| s.trim().parse().map_err(|_| format!("bad --dirty-mib {s:?}")))
        .collect::<std::result::Result<_, _>>()?;
    let timeout = Duration::from_secs(args.num("timeout", 300)?.max(1));
    let dir = std::path::absolute(dir)?;
    std::fs::create_dir_all(&dir)?;
    let rpc = |h: &str, req| call_with_timeout(h, req, timeout);
    let date = command("date", &["-u", "+%Y-%m-%dT%H-%M-%SZ"])?;
    let mut summary = Map::new();
    let mut all = Map::new();
    for &mib in &sizes {
        let mut samples = Vec::new();
        for i in 0..iterations {
            let name = format!("lcbench-{}-{mib}-{i}", std::process::id());
            let ck = dir.join(&name);
            let res = trial(&rpc, host, &to, &name, template, mib, &ck);
            for h in [host, to.as_str()] {
                let _ = rpc(h, json!({"op": "kill", "name": name}));
            }
            let _ = std::fs::remove_dir_all(&ck);
            samples.push(res.map_err(|e| format!("{mib} MiB, trial {}: {e}", i + 1))?);
            eprintln!("bench: {mib} MiB {}/{iterations}", i + 1);
        }
        let mut s = Map::new();
        for group in ["pause", "checkpoint", "restore", "suspend", "resume_suspended"] {
            s.insert(group.into(), summarize(&samples, group)?);
        }
        summary.insert(format!("{mib}_mib"), s.into());
        all.insert(format!("{mib}_mib"), samples.into());
    }
    let sha = command("git", &["rev-parse", "HEAD"])?;
    let report = json!({
        "date_utc": date,
        "git_sha": sha,
        "git_dirty": !command("git", &["status", "--porcelain"])?.is_empty(),
        "params": {"host": host, "to": to, "template": template, "iterations": iterations, "dirty_mib": sizes},
        "host_context": rpc(host, json!({"op": "bench_info", "template": template}))?,
        "summary_ms": summary,
        "samples_ms": all,
    });
    let out = format!("{}/bench", command("git", &["rev-parse", "--show-toplevel"])?);
    std::fs::create_dir_all(&out)?;
    let path = format!("{out}/{date}-{}-lifecycle.json", &sha[..7]);
    serde_json::to_writer_pretty(std::fs::File::create(&path)?, &report)?;
    println!("{path}");
    Ok(())
}

/// One VM with `mib` MiB written to its /tmp: ten pause/resume cycles,
/// checkpoint --stop, restore on `to`, then suspend and resume there.
fn trial(
    rpc: &dyn Fn(&str, Value) -> Result<Value>,
    host: &str,
    to: &str,
    name: &str,
    template: &str,
    mib: u64,
    ck: &Path,
) -> Result<Value> {
    rpc(host, json!({"op": "run", "name": name, "template": template}))?;
    if mib > 0 && crate::exec(host, name, &format!("dd if=/dev/urandom of=/tmp/f bs=1M count={mib} 2>/dev/null"))? != 0 {
        bail!("dirtying guest memory failed");
    }
    let mut pause = Map::new();
    let (mut p, mut r, mut rtt) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..10 {
        p.push(rpc(host, json!({"op": "pause", "name": name}))?["pause_ms"].as_f64().unwrap_or(0.0));
        thread::sleep(Duration::from_millis(20));
        let t2 = Instant::now();
        r.push(rpc(host, json!({"op": "resume", "name": name}))?["resume_ms"].as_f64().unwrap_or(0.0));
        rtt.push(ms(t2.elapsed()));
        thread::sleep(Duration::from_millis(20));
    }
    let med = |v: &mut Vec<f64>| {
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    };
    pause.insert("pause".into(), med(&mut p).into());
    pause.insert("resume".into(), med(&mut r).into());
    pause.insert("resume_rpc".into(), med(&mut rtt).into());

    let c = rpc(host, json!({"op": "checkpoint", "name": name, "dir": ck, "stop": true}))?;
    let mut checkpoint = c["timings_ms"].clone();
    checkpoint["paused"] = c["paused_ms"].clone();
    checkpoint["data_mib"] = c["data_mib"].clone();

    // A new address: only the old one's home host may hand that out.
    let rs = rpc(to, json!({"op": "restore", "dir": ck, "ip": "auto"}))?;
    let mut restore = rs["timings_ms"].clone();
    restore["ready"] = rs["ready_ms"].clone();
    restore["pull"] = wait_pull(rpc, to, name)?;

    let s = rpc(to, json!({"op": "suspend", "name": name}))?;
    let suspend = s["timings_ms"].clone();
    let rr = rpc(to, json!({"op": "resume", "name": name}))?;
    let mut resume_suspended = rr["timings_ms"].clone();
    resume_suspended["ready"] = rr["ready_ms"].clone();
    resume_suspended["pull"] = wait_pull(rpc, to, name)?;
    Ok(json!({"pause": pause, "checkpoint": checkpoint, "restore": restore, "suspend": suspend, "resume_suspended": resume_suspended}))
}

/// Waits for a restored VM to have paged in its whole checkpoint; returns how long that took (ms).
fn wait_pull(rpc: &dyn Fn(&str, Value) -> Result<Value>, host: &str, name: &str) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let st = rpc(host, json!({"op": "migration_status", "name": name}))?;
        if st["background_pull_ms"].is_number() {
            return Ok(st["background_pull_ms"].clone());
        }
        if !st["failed"].is_null() || Instant::now() >= deadline {
            bail!("restore pull did not finish: {st}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
