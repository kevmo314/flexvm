//! Standby VMs: `flexvm run --standby` processes holding a restored, settled,
//! paused VM so `run` is a resume plus `START`. Each listens on
//! `RUN/standby/TEMPLATE/KEY.PID-START.sock` (KEY: template generation) and holds
//! `PID-START.lock` while alive, and `PID-START.claim` locked while a claim is under way. Protocol: `run` sends `claim {name, ip, cmd}` with
//! its stdout/stderr; once the standby replies `claiming`, the claim may have
//! started the VM and is never retried elsewhere. `{"exit": code}` follows.

use std::fs::File;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::Firecracker;
use crate::guest;
use crate::host::{fault, Host, Ident, PidFd};
use crate::template::{Paths, Template};
use crate::util::{send_json, Error, Phases, Result};
use crate::vm::{Prepared, Vm};
use crate::vmproc::{End, Op, Proc};

fn dir(host: &Host, template: &str) -> PathBuf {
    host.run.join("standby").join(template)
}

fn key(paths: &Paths, template: &str) -> Result<String> {
    Ok(dir_key(&Template::resolve(paths, template)?))
}

/// A template generation's key: its directory's name (`.gen/<content id>`).
fn dir_key(dir: &std::path::Path) -> String {
    dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

pub fn target(host: &Host, template: &str) -> usize {
    std::fs::read_to_string(host.state.join("standby").join(template)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

/// The live standby processes of `template`, oldest first.
pub fn live(host: &Host, template: &str) -> Vec<Ident> {
    let mut ids = Vec::new();
    for e in std::fs::read_dir(dir(host, template)).into_iter().flatten().flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || !name.ends_with(".lock") {
            continue;
        }
        let Ok(f) = File::open(e.path()) else { continue };
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
            let _ = std::fs::remove_file(e.path());
        } else if let Ok(id) = serde_json::from_reader::<_, Ident>(&f) {
            ids.push(id);
        }
    }
    ids.sort_by_key(|id| (id.start, id.pid));
    ids
}

/// `live`, less those mid-claim (`PID-START.claim` locked; START keeps a reused pid's apart): a stop would not end them.
pub fn stoppable(host: &Host, template: &str) -> Vec<Ident> {
    let d = dir(host, template);
    let claiming = |id: &Ident| {
        File::open(d.join(format!("{}-{}.claim", id.pid, id.start))).is_ok_and(|f| unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0)
    };
    live(host, template).into_iter().filter(|id| !claiming(id)).collect()
}

/// SIGUSR1, not SIGINT: a stop can reach the process after a claim started
/// (it lists it until the claim is done, and its signal thread may take it
/// late), and the VM it became must not take it for a kill.
pub fn stop(id: &Ident) {
    if let Ok(Some(fd)) = PidFd::open(id) {
        let _ = fd.signal(libc::SIGUSR1);
    }
}

pub fn templates(host: &Host) -> Vec<String> {
    let mut t: Vec<String> = [host.state.join("standby"), host.run.join("standby")]
        .iter()
        .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    t.sort();
    t.dedup();
    t
}

pub fn set(host: &Host, template: &str, n: usize) -> Result<Value> {
    crate::util::write_file(&host.state.join("standby"), template, n.to_string().as_bytes(), true)?;
    for id in live(host, template).iter().skip(n) {
        stop(id);
    }
    let started = refill(host, template)?;
    Ok(json!({"template": template, "standby": n, "started": started}))
}

/// Periodic recovery, run by listeners and running VM processes. A
/// nonblocking refill lock avoids piling up workers behind a slow restore.
/// No refill for a minute after pressure stopped standby VMs (so they do not
/// cycle) or after a template's refill failed (its error is in standby.log).
pub fn maintain(host: Host) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        if recent(&pressure(&host)) {
            continue;
        }
        for template in templates(&host) {
            let failed = dir(&host, &template).join(".failed");
            if recent(&failed) {
                continue;
            }
            if let Err(e) = refill_by(&host, &template, false) {
                let _ = std::fs::write(&failed, b"");
                // As its standby VMs write it: capped, to whichever file is current.
                let path = dir(&host, &template).join("standby.log");
                let line = format!("standby {template}: refill: {e}\n");
                crate::util::output::append_capped(&path, line.as_bytes(), crate::util::output::LOG_CAP);
            }
        }
    });
}

/// Touched when memory pressure stops standby VMs.
pub fn pressure(host: &Host) -> PathBuf {
    host.run.join("standby").join(".pressure")
}

fn recent(path: &std::path::Path) -> bool {
    std::fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|d| d < Duration::from_secs(60))
}

/// Starts standby VMs up to the target and waits for them. Serialised per
/// template so the ones starting are counted.
pub fn refill(host: &Host, template: &str) -> Result<usize> {
    refill_by(host, template, true)
}

fn refill_by(host: &Host, template: &str, wait: bool) -> Result<usize> {
    let d = dir(host, template);
    std::fs::create_dir_all(&d)?;
    let lock = File::create(d.join(".refill"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | if wait { 0 } else { libc::LOCK_NB }) } != 0 {
        let e = std::io::Error::last_os_error();
        if !wait && e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(0);
        }
        return Err(e.into());
    }
    let want = target(host, template).saturating_sub(live(host, template).len());
    if want == 0 {
        return Ok(0);
    }
    let mut ready = Vec::new();
    let log = std::fs::OpenOptions::new().create(true).append(true).open(d.join("standby.log"))?;
    let args = [host.state.as_os_str(), host.run.as_os_str(), template.as_ref()];
    for _ in 0..want {
        if host.grant(256, None)?.is_none() {
            break;
        }
        let (r, w) = std::os::unix::net::UnixStream::pair()?;
        let args = ["--state".as_ref(), args[0], "--run".as_ref(), args[1], "run".as_ref(), "--standby".as_ref(), "--template".as_ref(), args[2]];
        crate::util::spawn_self(&args, &log, w.as_raw_fd(), &[("FLEXVM_NOTIFY_FD", "3")])?;
        ready.push(r);
    }
    let started = ready.len();
    for r in ready {
        let reply = crate::util::recv_json(&mut BufReader::new(r))?.ok_or("a standby vm failed to start (see its log)")?;
        if reply["ok"] != json!(true) {
            bail!("a standby vm failed to start: {}", reply["error"]);
        }
    }
    Ok(started)
}

/// Where what standby loads of a template touch is saved, for migrations to preload: in `host.run`/standby.
fn load_set_name(tpl: &Template) -> String {
    format!(".loadset-{}", tpl.meta.id)
}

pub fn save_load_set(host: &Host, tpl: &Template) {
    let set = tpl.load_set();
    if !set.is_empty() {
        if let Ok(b) = serde_json::to_vec(&set) {
            let _ = crate::util::write_file(&host.run.join("standby"), &load_set_name(tpl), &b, false);
        }
    }
}

pub fn load_set(host: &Host, tpl: &Template) -> Vec<u64> {
    let mut set = tpl.load_set();
    if let Some(saved) = std::fs::read(host.run.join("standby").join(load_set_name(tpl))).ok().and_then(|b| serde_json::from_slice::<Vec<u64>>(&b).ok()) {
        set.extend(saved);
        set.sort_unstable();
        set.dedup();
    }
    set
}

/// `run --standby`: returns once claimed; ends the process if stopped,
/// out of date, extra, or its VM died.
pub fn serve(p: &Arc<Proc>, template: &str, notify: &mut Option<File>, op: &Op) -> Result<Value> {
    let host = &p.host;
    let tpl = Template::open(&p.paths, template)?;
    // The key of the generation opened, not of whatever the name resolves to now: a
    // rebuild in between would publish this snapshot under the new generation's key.
    let mine = dir_key(&tpl.dir);
    let d = dir(host, template);
    std::fs::create_dir_all(&d)?;
    let me = Ident::me();
    let id = format!("{}-{}", me.pid, me.start);
    let (lock_path, sock) = (d.join(format!("{id}.lock")), d.join(format!("{mine}.{id}.sock")));
    let tmp = d.join(format!(".{id}.lock"));
    let lock = File::create(&tmp)?;
    crate::host::flock(&lock, libc::LOCK_EX)?;
    lock.write_all_at(&serde_json::to_vec(&me)?, 0)?;
    std::fs::rename(&tmp, &lock_path)?;
    let claim_path = d.join(format!("{id}.claim"));
    p.files.lock().unwrap().extend([sock.clone(), lock_path, claim_path.clone()]);
    let ready = load(p.spawner.take(None)?, tpl.clone())?;
    // Taken now, so a claim does not scan memory or ask Firecracker.
    *p.sizes.lock().unwrap() = Some(ready.mem_sizes());
    *p.standby.lock().unwrap() = Some(ready);
    save_load_set(host, &tpl);
    let listener = UnixListener::bind(&sock)?;
    if let Some(mut f) = notify.take() {
        let _ = send_json(&mut f, &json!({"ok": true, "result": {"pid": me.pid, "template": template}}));
    }
    loop {
        let mut pfd = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut pfd, 1, 100) } <= 0 {
            let current = key(&p.paths, template).ok();
            let extra = live(host, template).iter().position(|id| *id == me).is_none_or(|i| i >= target(host, template));
            let dead = p.standby.lock().unwrap().as_ref().is_none_or(|s| s.pager.failed().is_some() || !s.firecracker().alive());
            if p.stop_requested() || current.as_deref() != Some(&mine) || extra || dead {
                p.finish(op, End::NotStarted, 0, None);
            }
            continue;
        }
        let Ok((c, _)) = listener.accept() else { continue };
        // In short waits, minding stops: a claimer stopped mid-request must not keep this one.
        let at = Instant::now() + HANDSHAKE_TIMEOUT;
        let ready = || loop {
            if p.stop_requested() || Instant::now() >= at {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            if crate::util::readable(&c, Duration::from_millis(100)).unwrap_or(true) {
                return Ok(());
            }
        };
        let Ok((line, fds)) = crate::util::recv_with_fds(&c, 1 << 20, ready) else { continue };
        let Ok(req) = serde_json::from_slice::<Value>(&line) else { continue };
        // Locked until the claim succeeds or rolls back (dropped): relief does not count it stopped.
        let claiming = File::options().create(true).truncate(false).write(true).open(&claim_path)?;
        crate::host::flock(&claiming, libc::LOCK_EX)?;
        // Not yet `claiming`, so the claimer tries another.
        if p.stop_requested() {
            p.finish(op, End::NotStarted, 0, None);
        }
        // From here the claim may take effect: the claimer must not retry elsewhere.
        if send_json(&mut &c, &json!({"claiming": true})).is_err() {
            continue;
        }
        // Before it is published: eviction leaves a CMD VM alone.
        *p.cmd.lock().unwrap() = req["cmd"].as_str().map(String::from);
        match claim(p, &req) {
            Ok(v) => {
                p.forget_stop();
                crate::host::stall("claim_stall");
                let _ = std::fs::remove_file(&sock);
                p.serve_control();
                let _ = send_json(&mut &c, &json!({"ok": true, "result": v}));
                if let [out, err, ..] = &fds[..] {
                    crate::util::output::retarget([out.as_raw_fd(), err.as_raw_fd()]);
                }
                *p.claimer.lock().unwrap() = Some(c);
                for f in p.files.lock().unwrap().drain(..) {
                    let _ = std::fs::remove_file(f);
                }
                drop(lock);
                let (h, t) = (host.clone(), template.to_string());
                std::thread::spawn(move || {
                    if let Err(e) = refill(&h, &t) {
                        eprintln!("standby {t}: {e}");
                    }
                });
                return Ok(Value::Null);
            }
            Err((e, retry)) => {
                *p.cmd.lock().unwrap() = None;
                let _ = send_json(&mut &c, &json!({"ok": false, "error": e.to_string(), "retry": retry}));
                if p.standby.lock().unwrap().is_none() {
                    p.finish(op, End::NotStarted, crate::vmproc::FAILED, None);
                }
            }
        }
    }
}

/// On failure, the flag says whether another standby (or a cold start) may
/// retry: true only if the VM never ran for that name.
fn claim(p: &Arc<Proc>, req: &Value) -> std::result::Result<Value, (Error, bool)> {
    let host = &p.host;
    let name = req["name"].as_str().unwrap_or("");
    let want: Option<Ipv4Addr> = match req["ip"].as_str().map(|s| s.parse()) {
        Some(Ok(ip)) => Some(ip),
        Some(Err(_)) => return Err((format!("bad address {:?}", req["ip"]).into(), false)),
        None => None,
    };
    let mut t = Phases::new();
    let lock = host.take_name(name, false).map_err(|e| (e, false))?;
    // Its memory is already out of MemAvailable: only the step is charged. Sized
    // as it was loaded (`serve`), and admitted before the address is claimed.
    let held = p.sizes.lock().unwrap().map_or(0, |(held, _)| held);
    p.admit_start(held, Some(held), crate::host::Floor::Reserve).map_err(|e| (e, true))?;
    let not_run = |e: Error, retry: bool| {
        p.refund_start();
        (e, retry)
    };
    let claim = host.lock().and_then(|l| host.claim_new(&l, name, want)).map_err(|e| not_run(e, false))?;
    t.mark("claim_ip");
    let still = host.fence(claim.ip, claim.gen).map_err(|e| not_run(e, false))?;
    let paused = p.standby.lock().unwrap().take().ok_or_else(|| not_run("standby vm gone".into(), true))?;
    let vm = resume(paused, name, claim.ip, fault("resume_kill"), &mut t).map_err(|(e, ran)| {
        let e = format!("resuming a standby vm failed{}: {e}", if ran { ", and it may have run" } else { "" }).into();
        if ran {
            (e, false)
        } else {
            not_run(e, true)
        }
    })?;
    drop(still);
    p.set_name(lock);
    p.set_addr(claim);
    p.set_vm(vm);
    let mut v = p.start_guest(&mut t).map_err(|e| (e, false))?;
    v["standby"] = json!(true);
    Ok(v)
}

/// `run`'s side. Once a standby said `claiming` it may have started the VM:
/// no answer (by `CLAIM_TIMEOUT`) is then an error, never a reason to start it again.
pub fn take(host: &Host, paths: &Paths, template: &str, req: &Value, fds: &[i32]) -> Result<Option<(Value, BufReader<UnixStream>)>> {
    let Ok(key) = key(paths, template) else { return Ok(None) };
    let mut socks: Vec<PathBuf> = std::fs::read_dir(dir(host, template))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(&format!("{key}."))) && p.extension().is_some_and(|e| e == "sock"))
        .collect();
    socks.sort();
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    let name = req["name"].as_str().unwrap_or("");
    // One budget for all (a stopped standby uses it up), and a moment past it for each live one, up to a few.
    let budget = Instant::now() + HANDSHAKE_TIMEOUT;
    for sock in socks {
        if Instant::now() >= budget + 4 * LATE {
            break;
        }
        let at = budget.max(Instant::now() + LATE);
        let c = match crate::util::send_unix(&sock, &line, fds, at) {
            Ok(c) => c,
            // Refused: stale. (A full backlog is a stopped standby's.)
            Err(e) => {
                if e.raw_os_error() == Some(libc::ECONNREFUSED) {
                    let _ = std::fs::remove_file(&sock);
                }
                continue;
            }
        };
        // Not `claiming` by `at`: reads are shut down, so one sent later fails (and
        // claims nothing), and one sent already is read (and is uncertain: no answer
        // can follow on a shut stream, even one sent before).
        let shut = !crate::util::readable(&c, at.saturating_duration_since(Instant::now())).unwrap_or(false);
        if shut {
            let _ = c.shutdown(std::net::Shutdown::Read);
        }
        // Byte by byte: what follows stays unread, for the caller.
        let mut r = BufReader::with_capacity(1, crate::util::By { s: &c, at: Instant::now() + CLAIM_TIMEOUT });
        if crate::util::recv_json(&mut r).ok().flatten().is_none_or(|t| t["claiming"] != json!(true)) {
            continue;
        }
        let answer = match shut {
            true => Err("its claiming came too late".into()),
            false => crate::util::recv_json(&mut r).and_then(|a| a.ok_or_else(|| "it hung up".into())),
        };
        let reply = match answer {
            Ok(r) => r,
            Err(e) => {
                let started = host.entry(name).map(|e| format!("it did: pid {}", e.ident.pid)).unwrap_or_else(|_| "see flexvm ls".into());
                bail!("claiming standby vm {} as {name}: {e}; it may have started the vm ({started}), so it is not started again", sock.display());
            }
        };
        if reply["ok"] == json!(true) {
            c.set_read_timeout(None)?;
            return Ok(Some((reply["result"].clone(), BufReader::new(c))));
        }
        if reply["retry"] != json!(true) {
            bail!("{}", reply["error"].as_str().unwrap_or("claim failed"));
        }
        eprintln!("flexvm: {}; trying another", reply["error"].as_str().unwrap_or(""));
    }
    Ok(None)
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const LATE: Duration = Duration::from_millis(250);
const CLAIM_TIMEOUT: Duration = Duration::from_secs(60);
const SETTLE: Duration = Duration::from_millis(50);
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);
const API_TIMEOUT: Duration = Duration::from_secs(5);
const RESEED_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs the restored VM once (the slow first resume, off the request path)
/// until the guest reseeds, then pauses it.
fn load(idle: Firecracker, template: Arc<Template>) -> Result<Prepared> {
    let p = Vm::prepare(idle, template, &mut Phases::new())?;
    p.pager.learn_load_set();
    let fc = p.firecracker();
    fc.load_snapshot(&p.template().vmstate(), &p.firecracker().tap, Some(true), LOAD_TIMEOUT)?;
    // Only an API pause stops the devices writing guest memory.
    fc.request_within("PATCH", "/vm", Some(json!({"state": "Paused"})), API_TIMEOUT)?;
    p.pager.wait_ready(Duration::from_secs(5))?;
    let resumed = fc.request_within("PATCH", "/vm", Some(json!({"state": "Resumed"})), API_TIMEOUT);
    p.pager.loaded();
    resumed?;
    wait_for_reseed(&fc.sockets.vsock)?;
    // Set the clock now so START at the claim can skip clock_settime (slow in big guests).
    let _ = guest::clock(&fc.sockets.vsock, &p.template().legacy_agent, guest::TIMEOUT);
    std::thread::sleep(SETTLE);
    fc.request_within("PATCH", "/vm", Some(json!({"state": "Paused"})), API_TIMEOUT)?;
    Ok(p)
}

/// On failure the flag says whether the guest may have run for `name` (the
/// resume may have reached Firecracker).
fn resume(p: Prepared, name: &str, ip: Ipv4Addr, kill: bool, t: &mut Phases) -> std::result::Result<Arc<Vm>, (Error, bool)> {
    crate::net::attach(ip, &p.firecracker().tap).map_err(|e| (e, false))?;
    t.mark("route");
    let res = p.firecracker().request_within("PATCH", "/vm", Some(json!({"state": "Resumed"})), API_TIMEOUT);
    if kill {
        p.pager.kill_firecracker();
        return Err(("injected fault: firecracker killed after the resume was sent".into(), true));
    }
    if let Err(e) = res {
        let ran = !crate::fc::not_sent(&e);
        return Err((e, ran));
    }
    t.mark("resume");
    Ok(p.into_vm(name, ip, crate::vm::State::Running))
}

/// Waits for the guest RNG reseed for the new VMGenID; an agent without
/// `FORKS` need only answer.
fn wait_for_reseed(vsock: &std::path::Path) -> Result<()> {
    static WARNED: AtomicBool = AtomicBool::new(false);
    let deadline = Instant::now() + RESEED_TIMEOUT;
    loop {
        let res = guest::forks(vsock);
        match res {
            Ok(Some(n)) if n > 0 => return Ok(()),
            Ok(None) => {
                if !WARNED.swap(true, Ordering::Relaxed) {
                    eprintln!("standby: guest agent cannot report RNG reseeds (no FORKS); standby vms are only checked to answer");
                }
                return Ok(());
            }
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(Some(_)) => bail!("guest did not reseed its RNG for the new VMGenID within {RESEED_TIMEOUT:?}"),
            Err(e) => bail!("guest agent not answering after restore: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopped_standbys_share_one_handshake_budget_and_a_live_one_after_them_wins() {
        let root = std::env::temp_dir().join(format!("flexvm-standby-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        std::fs::create_dir_all(root.join("templates/default")).unwrap();
        let paths = Paths::new(&root, None).unwrap();
        let d = dir(&host, "default");
        std::fs::create_dir_all(&d).unwrap();
        let stopped: Vec<_> = (0..2).map(|n| UnixListener::bind(d.join(format!("default.{n}.sock"))).unwrap()).collect();
        let live = UnixListener::bind(d.join("default.2.sock")).unwrap();
        let live = std::thread::spawn(move || {
            let (c, _) = live.accept().unwrap();
            std::io::BufRead::read_line(&mut BufReader::new(&c), &mut String::new()).unwrap();
            send_json(&mut &c, &json!({"claiming": true})).unwrap();
            send_json(&mut &c, &json!({"ok": true, "result": "live"})).unwrap();
        });
        let start = Instant::now();
        let (v, _) = take(&host, &paths, "default", &json!({"name": "test"}), &[]).unwrap().unwrap();
        assert_eq!(v, json!("live"));
        assert!(start.elapsed() < HANDSHAKE_TIMEOUT + 3 * LATE, "{:?}", start.elapsed());
        live.join().unwrap();
        // The stopped ones' late claims are refused.
        for s in &stopped {
            assert!(send_json(&mut s.accept().unwrap().0, &json!({"claiming": true})).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_reused_pid_keeps_its_own_lock() {
        let root = std::env::temp_dir().join(format!("flexvm-standby-identity-{}", std::process::id()));
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let d = dir(&host, "default");
        std::fs::create_dir_all(&d).unwrap();
        let me = Ident::me();
        let path = d.join(format!("{}-{}.lock", me.pid, me.start));
        let lock = File::create(&path).unwrap();
        crate::host::flock(&lock, libc::LOCK_EX).unwrap();
        lock.write_all_at(&serde_json::to_vec(&me).unwrap(), 0).unwrap();
        let stale = d.join(format!("{}-0.lock", me.pid));
        File::create(&stale).unwrap();
        assert_eq!(live(&host, "default"), [me]);
        assert!(!stale.exists() && path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_finds_persistent_targets_and_respects_refill_lock_and_reserve() {
        let root = std::env::temp_dir().join(format!("flexvm-refill-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        crate::util::write_file(&host.state.join("standby"), "default", b"1", true).unwrap();
        // No runtime pool after a reboot; the persistent target is discovered.
        assert_eq!(templates(&host), vec!["default"]);
        let d = dir(&host, "default");
        std::fs::create_dir_all(&d).unwrap();
        let lock = File::create(d.join(".refill")).unwrap();
        crate::host::flock(&lock, libc::LOCK_EX).unwrap();
        assert_eq!(refill_by(&host, "default", false).unwrap(), 0);
        drop(lock);
        host.cfg.reserve_mib = u64::MAX / 2;
        assert_eq!(refill_by(&host, "default", false).unwrap(), 0);
        assert!(live(&host, "default").is_empty());
        assert!(!recent(&pressure(&host)));
        std::fs::write(pressure(&host), b"").unwrap();
        assert!(recent(&pressure(&host)));
        std::fs::remove_dir_all(root).unwrap();
    }
}
