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
    let scatter = args.num("scatter-pages", 0)?;
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
            let res = trial(&rpc, host, &to, &name, template, mib, scatter, &ck);
            for h in [host, to.as_str()] {
                let _ = rpc(h, json!({"op": "kill", "name": name}));
            }
            for d in ["", "-cow0", "-cow1", "-cow2"] {
                let _ = std::fs::remove_dir_all(format!("{}{d}", ck.display()));
            }
            samples.push(res.map_err(|e| format!("{mib} MiB, trial {}: {e}", i + 1))?);
            eprintln!("bench: {mib} MiB {}/{iterations}", i + 1);
        }
        let mut s = Map::new();
        let cow = (scatter > 0).then_some("cow");
        for group in ["pause", "checkpoint", "restore", "suspend", "resume_suspended"].into_iter().chain(cow) {
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
        "params": {"host": host, "to": to, "template": template, "iterations": iterations, "dirty_mib": sizes, "scatter_pages": scatter},
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
/// checkpoint --stop, restore on `to`, then suspend and resume there. With
/// `scatter` pages, keep-running checkpoints first: one that arms write
/// tracking, one with nothing written since, and one after the guest
/// rewrote `scatter` pages spread evenly over /tmp/f.
#[allow(clippy::too_many_arguments)]
fn trial(
    rpc: &dyn Fn(&str, Value) -> Result<Value>,
    host: &str,
    to: &str,
    name: &str,
    template: &str,
    mib: u64,
    scatter: u64,
    ck: &Path,
) -> Result<Value> {
    rpc(host, json!({"op": "run", "name": name, "template": template}))?;
    if mib > 0 && crate::exec(host, name, &format!("dd if=/dev/urandom of=/tmp/f bs=1M count={mib} 2>/dev/null"))? != 0 {
        bail!("dirtying guest memory failed");
    }
    let mut cow = Map::new();
    if scatter > 0 {
        if mib == 0 {
            bail!("--scatter-pages needs a nonzero --dirty-mib");
        }
        let checkpoint = |sub: &str, incremental: bool| {
            let dir = format!("{}-{sub}", ck.display());
            rpc(host, json!({"op": "checkpoint", "name": name, "dir": dir, "incremental": incremental}))
        };
        cow.insert("arm_paused".into(), checkpoint("cow0", false)?["paused_ms"].clone());
        let idle = checkpoint("cow1", true)?;
        cow.insert("idle_paused".into(), idle["paused_ms"].clone());
        cow.insert("idle_protect".into(), idle["protect"]["ms"].clone());
        let stride = (mib * 256 / scatter).max(1);
        let cmd = format!(
            "i=0; while [ $i -lt {scatter} ]; do dd if=/dev/zero of=/tmp/f bs=4096 count=1 seek=$((i * {stride})) conv=notrunc 2>/dev/null; i=$((i + 1)); done"
        );
        if crate::exec(host, name, &cmd)? != 0 {
            bail!("scattered writes failed");
        }
        let s = checkpoint("cow2", true)?;
        cow.insert("scatter_paused".into(), s["paused_ms"].clone());
        cow.insert("scatter_protect".into(), s["protect"]["ms"].clone());
        cow.insert("scatter_ranges".into(), s["protect"]["ranges"].clone());
        cow.insert("scatter_dirty_mib".into(), s["dirty_mib"].clone());
        cow.insert("scatter_checkpoint".into(), s["checkpoint_ms"].clone());
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

    let rs = rpc(to, json!({"op": "restore", "dir": ck}))?;
    let mut restore = rs["timings_ms"].clone();
    restore["ready"] = rs["ready_ms"].clone();
    restore["pull"] = wait_pull(rpc, to, name)?;

    let s = rpc(to, json!({"op": "suspend", "name": name}))?;
    let suspend = s["timings_ms"].clone();
    let rr = rpc(to, json!({"op": "resume", "name": name}))?;
    let mut resume_suspended = rr["timings_ms"].clone();
    resume_suspended["ready"] = rr["ready_ms"].clone();
    resume_suspended["pull"] = wait_pull(rpc, to, name)?;
    Ok(json!({"pause": pause, "checkpoint": checkpoint, "restore": restore, "suspend": suspend, "resume_suspended": resume_suspended, "cow": cow}))
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
