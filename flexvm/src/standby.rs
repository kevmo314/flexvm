//! Standby VMs: `flexvm run --standby` processes holding a restored, settled,
//! paused VM so `run` is a resume plus `START`. Each listens on
//! `RUN/standby/TEMPLATE/KEY.PID.sock` (KEY: template generation) and holds
//! `PID.lock` while alive. Protocol: `run` sends `claim {name, ip, cmd}` with
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
use crate::fc::Idle;
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
    let dir = Template::resolve(paths, template)?;
    Ok(dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())
}

pub fn target(host: &Host, template: &str) -> usize {
    std::fs::read_to_string(host.state.join("standby").join(template)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

/// The live standby processes of `template`, oldest first.
pub fn live(host: &Host, template: &str) -> Vec<Ident> {
    let mut ids = Vec::new();
    for e in std::fs::read_dir(dir(host, template)).into_iter().flatten().flatten() {
        if !e.file_name().to_string_lossy().ends_with(".lock") {
            continue;
        }
        let Ok(f) = File::open(e.path()) else { continue };
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
            let _ = std::fs::remove_file(e.path());
        } else if let Some(id) = crate::host::load::<Ident>(&e.path()).ok().flatten() {
            ids.push(id);
        }
    }
    ids.sort_by_key(|id| (id.start, id.pid));
    ids
}

pub fn stop(id: &Ident) {
    if let Ok(Some(fd)) = PidFd::open(id) {
        let _ = fd.signal(libc::SIGINT);
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
    crate::host::write_file(&host.state.join("standby"), template, n.to_string().as_bytes(), true)?;
    for id in live(host, template).iter().skip(n) {
        stop(id);
    }
    let started = refill(host, template)?;
    Ok(json!({"template": template, "standby": n, "started": started}))
}

/// Starts standby VMs up to the target and waits for them. Serialised per
/// template so the ones starting are counted.
pub fn refill(host: &Host, template: &str) -> Result<usize> {
    let d = dir(host, template);
    std::fs::create_dir_all(&d)?;
    let lock = File::create(d.join(".refill"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        bail!("standby {template}: {}", std::io::Error::last_os_error());
    }
    let want = target(host, template).saturating_sub(live(host, template).len());
    if want == 0 {
        return Ok(0);
    }
    if crate::vmproc::host_available_mib() < host.cfg.reserve_mib + 256 {
        eprintln!("standby {template}: not starting {want} standby vms, the host is low on memory");
        return Ok(0);
    }
    let mut ready = Vec::new();
    let log = std::fs::OpenOptions::new().create(true).append(true).open(d.join("standby.log"))?;
    let args = [host.state.as_os_str(), host.run.as_os_str(), template.as_ref()];
    for _ in 0..want {
        let (r, w) = std::os::unix::net::UnixStream::pair()?;
        let args = ["--state".as_ref(), args[0], "--run".as_ref(), args[1], "run".as_ref(), "--standby".as_ref(), "--template".as_ref(), args[2]];
        crate::util::spawn_self(&args, &log, w.as_raw_fd(), &[("FLEXVM_NOTIFY_FD", "3")])?;
        ready.push(r);
    }
    for r in ready {
        let reply = crate::util::recv_json(&mut BufReader::new(r))?.ok_or("a standby vm failed to start (see its log)")?;
        if reply["ok"] != json!(true) {
            bail!("a standby vm failed to start: {}", reply["error"]);
        }
    }
    Ok(want)
}

/// What standby loads of a template touch, saved for migrations to preload.
fn load_set_file(host: &Host, tpl: &Template) -> PathBuf {
    host.run.join("standby").join(format!(".loadset-{}", tpl.meta.id))
}

pub fn save_load_set(host: &Host, tpl: &Template) {
    let set = tpl.load_set();
    if !set.is_empty() {
        if let Ok(b) = serde_json::to_vec(&set) {
            let _ = crate::host::write_file(&host.run.join("standby"), &format!(".loadset-{}", tpl.meta.id), &b, false);
        }
    }
}

pub fn load_set(host: &Host, tpl: &Template) -> Vec<u64> {
    let mut set = tpl.load_set();
    if let Some(saved) = std::fs::read(load_set_file(host, tpl)).ok().and_then(|b| serde_json::from_slice::<Vec<u64>>(&b).ok()) {
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
    let key = key(&p.paths, template)?;
    let d = dir(host, template);
    std::fs::create_dir_all(&d)?;
    let me = Ident::me();
    let (lock_path, sock) = (d.join(format!("{}.lock", me.pid)), d.join(format!("{key}.{}.sock", me.pid)));
    let lock = File::create(&lock_path)?;
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    lock.write_all_at(&serde_json::to_vec(&me)?, 0)?;
    p.files.lock().unwrap().extend([sock.clone(), lock_path]);
    *p.standby.lock().unwrap() = Some(load(p.spawner.take(None)?, tpl.clone())?);
    save_load_set(host, &tpl);
    let listener = UnixListener::bind(&sock)?;
    if let Some(mut f) = notify.take() {
        let _ = send_json(&mut f, &json!({"ok": true, "result": {"pid": me.pid, "template": template}}));
    }
    loop {
        let mut pfd = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut pfd, 1, 100) } <= 0 {
            let current = Template::resolve(&p.paths, template).ok().and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()));
            let extra = live(host, template).iter().position(|id| *id == me).is_some_and(|i| i >= target(host, template));
            let dead = p.standby.lock().unwrap().as_mut().is_none_or(|s| s.pager.failed().is_some() || !s.firecracker_alive());
            if p.stop_requested() || current.as_deref() != Some(&key) || extra || dead {
                p.finish(op, End::NotStarted, 0, None);
            }
            continue;
        }
        let Ok((c, _)) = listener.accept() else { continue };
        let Ok((line, fds)) = crate::util::recv_with_fds(&c, 1 << 20) else { continue };
        let Ok(req) = serde_json::from_slice::<Value>(&line) else { continue };
        // Not yet `claiming`, so the claimer tries another.
        if p.stop_requested() {
            p.finish(op, End::NotStarted, 0, None);
        }
        // From here the claim may take effect: the claimer must not retry elsewhere.
        if send_json(&mut &c, &json!({"claiming": true})).is_err() {
            continue;
        }
        match claim(p, &req) {
            Ok(v) => {
                p.forget_stop();
                crate::host::stall("claim_stall");
                let _ = std::fs::remove_file(&sock);
                p.serve_control();
                let _ = send_json(&mut &c, &json!({"ok": true, "result": v}));
                for (fd, to) in fds.iter().zip([1, 2]) {
                    unsafe { libc::dup2(fd.as_raw_fd(), to) };
                }
                *p.claimer.lock().unwrap() = Some(c);
                *p.cmd.lock().unwrap() = req["cmd"].as_str().map(String::from);
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
                let _ = send_json(&mut &c, &json!({"ok": false, "error": e.to_string(), "retry": retry}));
                if p.standby.lock().unwrap().is_none() {
                    p.finish(op, End::NotStarted, 1, None);
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
    let claim = host.lock().and_then(|l| host.claim_new(&l, name, want)).map_err(|e| (e, false))?;
    t.mark("claim_ip");
    let paused = p.standby.lock().unwrap().take().ok_or_else(|| ("standby vm gone".into(), true))?;
    let vm = resume(paused, name, claim.ip, fault("resume_kill"), &mut t).map_err(|(e, ran)| {
        (format!("resuming a standby vm failed{}: {e}", if ran { ", and it may have run" } else { "" }).into(), !ran)
    })?;
    p.set_name(lock);
    p.set_addr(claim);
    p.set_vm(vm);
    let mut v = p.start_guest(&mut t).map_err(|e| (e, false))?;
    v["standby"] = json!(true);
    Ok(v)
}

/// `run`'s side. Once a standby said `claiming` it may have started the VM:
/// no answer is then an error, never a reason to start it again.
pub fn take(host: &Host, paths: &Paths, template: &str, req: &Value, fds: &[i32]) -> Result<Option<(Value, UnixStream)>> {
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
    for sock in socks {
        let Ok(c) = UnixStream::connect(&sock) else {
            let _ = std::fs::remove_file(&sock);
            continue;
        };
        let mut r = BufReader::new(&c);
        let taken = crate::util::send_with_fds(&c, &line, fds).ok().and_then(|()| crate::util::recv_json(&mut r).ok().flatten());
        if taken.is_none_or(|t| t["claiming"] != json!(true)) {
            continue;
        }
        let answer = crate::util::recv_json(&mut r).and_then(|a| a.ok_or_else(|| "it hung up".into()));
        let reply = match answer {
            Ok(r) => r,
            Err(e) => {
                let started = host.entry(name).map(|e| format!("it did: pid {}", e.ident.pid)).unwrap_or_else(|_| "see flexvm ls".into());
                bail!("claiming standby vm {} as {name}: {e}; it may have started the vm ({started}), so it is not started again", sock.display());
            }
        };
        if reply["ok"] == json!(true) {
            return Ok(Some((reply["result"].clone(), c)));
        }
        if reply["retry"] != json!(true) {
            bail!("{}", reply["error"].as_str().unwrap_or("claim failed"));
        }
        eprintln!("flexvm: {}; trying another", reply["error"].as_str().unwrap_or(""));
    }
    Ok(None)
}

const SETTLE: Duration = Duration::from_millis(50);
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);
const API_TIMEOUT: Duration = Duration::from_secs(5);
const RESEED_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs the restored VM once (the slow first resume, off the request path)
/// until the guest reseeds, then pauses it.
fn load(idle: Idle, template: Arc<Template>) -> Result<Prepared> {
    let p = Vm::prepare(idle, template, &mut Phases::new())?;
    p.pager.learn_load_set();
    let fc = p.firecracker();
    fc.load_snapshot(&p.template().vmstate(), p.tap(), Some(true), LOAD_TIMEOUT)?;
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
    crate::net::attach(ip, p.tap()).map_err(|e| (e, false))?;
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

