//! Standby VMs: processes that hold a VM restored from a template, settled
//! and paused, so `run` is a resume and a `START` (a few ms) instead of a
//! snapshot load. `flexvm standby [--template T] N` keeps N of them; each
//! one claimed starts its replacement.
//!
//! A standby VM is `flexvm run --standby` waiting on
//! `RUN/standby/TEMPLATE/KEY.PID.sock` (KEY: the template generation) and
//! holding `RUN/standby/TEMPLATE/PID.lock` while it lives. `run` claims one
//! with `claim {name, ip, cmd}`, passing its stdout and stderr: the standby
//! process takes the name and address and becomes that VM. It answers on
//! the claim connection, and once it ends, sends `{"exit": code}` there.
//!
//! The first run after a restore is slow (Firecracker's first resume, the
//! guest catching up and handling the new VMGenID), so a standby VM runs
//! once until the guest has reseeded its RNG for this load, then pauses
//! (see `hot::Paused::load`).

use std::fs::File;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::host::{fault, Host};

use crate::template::{Paths, Template};
use crate::fc::Idle;
use crate::guest;
use crate::uffd::Pager;
use crate::util::{send_json, Error, Phases, Result};
use crate::vm::{name_cgroup, Vm};
use crate::vmproc::Proc;

fn dir(host: &Host, template: &str) -> PathBuf {
    host.run.join("standby").join(template)
}

/// The key of `template`'s current generation.
fn key(paths: &Paths, template: &str) -> Result<String> {
    let dir = Template::resolve(paths, template)?;
    Ok(dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())
}

/// How many standby VMs `template` should have.
pub fn target(host: &Host, template: &str) -> usize {
    std::fs::read_to_string(host.state.join("standby").join(template)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

/// The pids of the live standby processes of `template`.
pub fn live(host: &Host, template: &str) -> Vec<u32> {
    let d = dir(host, template);
    let mut pids = Vec::new();
    for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let Some(pid) = n.strip_suffix(".lock").and_then(|p| p.parse::<u32>().ok()) else { continue };
        let held = File::open(e.path()).is_ok_and(|f| unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0);
        if held {
            pids.push(pid);
        } else {
            let _ = std::fs::remove_file(e.path());
        }
    }
    pids.sort_unstable();
    pids
}

/// Every template that has or wants standby VMs.
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

/// `flexvm standby N`: records N and makes it so, waiting until new standby
/// VMs are ready.
pub fn set(host: &Host, template: &str, n: usize) -> Result<Value> {
    crate::host::write_file(&host.state.join("standby"), template, n.to_string().as_bytes(), true)?;
    let pids = live(host, template);
    for &pid in pids.iter().skip(n) {
        unsafe { libc::kill(pid as i32, libc::SIGINT) };
    }
    let started = refill(host, template, true)?;
    Ok(json!({"template": template, "standby": n, "started": started}))
}

/// Starts standby VMs of `template` up to its target, unless the host is
/// under its memory reserve. With `wait`, returns once they are ready.
pub fn refill(host: &Host, template: &str, wait: bool) -> Result<usize> {
    let want = target(host, template).saturating_sub(live(host, template).len());
    if want == 0 {
        return Ok(0);
    }
    if crate::vmproc::host_available_mib() < host.cfg.reserve_mib + 256 {
        eprintln!("standby {template}: not starting {want} standby vms, the host is low on memory");
        return Ok(0);
    }
    std::fs::create_dir_all(dir(host, template))?;
    let mut ready = Vec::new();
    for _ in 0..want {
        let log = std::fs::OpenOptions::new().create(true).append(true).open(dir(host, template).join("standby.log"))?;
        let mut cmd = Command::new("/proc/self/exe");
        cmd.args(["--state".as_ref(), host.state.as_os_str(), "--run".as_ref(), host.run.as_os_str()])
            .args(["run", "--standby", "--template", template])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        let (r, w) = std::os::unix::net::UnixStream::pair()?;
        notify_fd(&mut cmd, w.into());
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut child = cmd.spawn()?;
        std::thread::spawn(move || child.wait());
        ready.push(r);
    }
    if wait {
        for r in ready {
            let reply = crate::util::recv_json(&mut BufReader::new(r))?.ok_or("a standby vm failed to start (see its log)")?;
            if reply["ok"] != json!(true) {
                bail!("a standby vm failed to start: {}", reply["error"]);
            }
        }
    }
    Ok(want)
}

/// Makes `w` fd 3 of the child `cmd` starts, for its readiness line.
pub fn notify_fd(cmd: &mut Command, w: OwnedFd) {
    let fd = w.as_raw_fd();
    cmd.env("FLEXVM_NOTIFY_FD", "3");
    unsafe {
        cmd.pre_exec(move || {
            let _keep = &w;
            if libc::dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// `run --standby`: loads a standby VM of `template`, then waits to be
/// claimed. Returns once it has become a claimed VM.
pub fn serve(p: &Arc<Proc>, template: &str, notify: &mut Option<File>) -> Result<Value> {
    let host = &p.host;
    let tpl = Template::open(&p.paths, template)?;
    let key = key(&p.paths, template)?;
    let d = dir(host, template);
    std::fs::create_dir_all(&d)?;
    let me = std::process::id();
    let lock = File::create(d.join(format!("{me}.lock")))?;
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    let paused = Paused::load(p.pool.take()?, tpl.clone())?;
    *p.standby.lock().unwrap() = Some(paused);
    if p.stop_requested() {
        drop(p.standby.lock().unwrap().take());
        p.end(0);
    }
    let sock = d.join(format!("{key}.{me}.sock"));
    p.files.lock().unwrap().extend([sock.clone(), d.join(format!("{me}.lock"))]);
    let listener = UnixListener::bind(&sock)?;
    if let Some(mut f) = notify.take() {
        let _ = send_json(&mut f, &json!({"ok": true, "result": {"pid": me, "template": template}}));
    }
    let gone = |code| -> ! {
        drop(p.standby.lock().unwrap().take());
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(d.join(format!("{me}.lock")));
        p.end(code)
    };
    loop {
        let mut pfd = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut pfd, 1, 1000) } <= 0 {
            // A newer generation of the template, or too many of us: go.
            let current = Template::resolve(&p.paths, template).ok().and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()));
            let pids = live(host, template);
            // The newest go first.
            let extra = pids.iter().position(|&p| p == me).is_some_and(|i| i >= target(host, template));
            let dead = p.standby.lock().unwrap().as_mut().is_none_or(|s| !s.alive());
            if current.as_deref() != Some(&key) || extra || dead {
                gone(0);
            }
            continue;
        }
        let Ok((c, _)) = listener.accept() else { continue };
        let Ok((line, fds)) = crate::util::recv_with_fds(&c, 1 << 20) else { continue };
        let Ok(req) = serde_json::from_slice::<Value>(&line) else { continue };
        match claim(p, &req) {
            Ok(v) => {
                let _ = std::fs::remove_file(&sock);
                let mut w = &c;
                let _ = send_json(&mut w, &json!({"ok": true, "result": v}));
                for (fd, to) in fds.iter().zip([1, 2]) {
                    unsafe { libc::dup2(fd.as_raw_fd(), to) };
                }
                *p.claimer.lock().unwrap() = Some(c);
                *p.cmd.lock().unwrap() = req["cmd"].as_str().map(String::from);
                drop(lock);
                p.files.lock().unwrap().clear();
                let _ = std::fs::remove_file(d.join(format!("{me}.lock")));
                // Off the claim's path: a replacement.
                let (state, run, t) = (host.state.clone(), host.run.clone(), template.to_string());
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    if let Ok(h) = Host::open(&state, &run) {
                        if let Err(e) = refill(&h, &t, false) {
                            eprintln!("standby {t}: {e}");
                        }
                    }
                });
                return Ok(Value::Null);
            }
            Err((e, retry)) => {
                let mut w = &c;
                let _ = send_json(&mut w, &json!({"ok": false, "error": e.to_string(), "retry": retry}));
                if p.standby.lock().unwrap().is_none() {
                    // Its VM was used up by the failed claim.
                    gone(1);
                }
            }
        }
    }
}

/// Becomes VM `req.name`. On failure, says whether another standby VM (or
/// a cold start) may do it instead: the VM never ran for that name.
fn claim(p: &Arc<Proc>, req: &Value) -> std::result::Result<Value, (crate::util::Error, bool)> {
    let host = &p.host;
    let name = req["name"].as_str().unwrap_or("");
    let want: Option<Ipv4Addr> = match req["ip"].as_str().map(|s| s.parse()) {
        Some(Ok(ip)) => Some(ip),
        Some(Err(_)) => return Err((format!("bad address {:?}", req["ip"]).into(), false)),
        None => None,
    };
    let mut t = Phases::new();
    let lock = host.take_name(name, false).map_err(|e| (e, false))?;
    let (ip, gen) = host.lock().and_then(|l| host.claim_new(&l, name, want)).map_err(|e| (e, false))?;
    t.mark("claim_ip");
    let paused = p.standby.lock().unwrap().take().ok_or_else(|| ("standby vm gone".into(), true))?;
    let release = || {
        if let Ok(l) = host.lock() {
            let _ = host.release(&l, ip, name);
        }
    };
    let vm = match paused.resume(name, ip, fault("resume_kill"), &mut t) {
        Ok(vm) => vm,
        Err((e, ran)) => {
            release();
            return Err((format!("resuming a standby vm failed{}: {e}", if ran { ", and it may have run" } else { "" }).into(), !ran));
        }
    };
    p.set_name(lock);
    p.gen.store(gen, Ordering::SeqCst);
    p.set_vm(vm);
    let mut v = p.start_guest(&mut t).map_err(|e| (e, false))?;
    v["hot"] = json!(true);
    Ok(v)
}

/// `run`'s side: claims a standby VM of `template` as `name`, passing it
/// `fds` for its stdout and stderr. None if there is none to claim.
pub fn take(host: &Host, paths: &Paths, template: &str, req: &Value, fds: &[i32]) -> Result<Option<(Value, UnixStream)>> {
    let Ok(key) = key(paths, template) else { return Ok(None) };
    let d = dir(host, template);
    let mut socks: Vec<PathBuf> = std::fs::read_dir(&d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(&format!("{key}."))) && p.extension().is_some_and(|e| e == "sock"))
        .collect();
    socks.sort();
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    for sock in socks {
        let Ok(c) = UnixStream::connect(&sock) else {
            let _ = std::fs::remove_file(&sock);
            continue;
        };
        if crate::util::send_with_fds(&c, &line, fds).is_err() {
            continue;
        }
        let Some(reply) = crate::util::recv_json(&mut BufReader::new(&c)).ok().flatten() else { continue };
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

/// How long a standby VM keeps running after the guest has reseeded, for the
/// rest of its post-restore work to finish.
const SETTLE: Duration = Duration::from_millis(50);
/// Deadlines for the Firecracker API calls of a load.
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);
const API_TIMEOUT: Duration = Duration::from_secs(5);
/// Fork reseeds in a template's own kernel log (see `wait_for_reseed`).
const FORKS_BASELINE: usize = 0;
/// How long the guest has to reseed after its first resume.
const RESEED_TIMEOUT: Duration = Duration::from_secs(5);

/// A VM restored from a template, run once to settle and paused again.
pub struct Paused {
    idle: Option<Idle>,
    pager: Arc<Pager>,
    template: Arc<Template>,
}

impl Paused {
    /// Restores `template` into `idle`, lets it settle and pauses it.
    pub fn load(idle: Idle, template: Arc<Template>) -> Result<Paused> {
        let pager = Pager::start(&idle.fc.sockets.uffd, template.clone(), None)?;
        // Off the request path, so it can afford to learn what a load touches.
        pager.learn_load_set();
        let paused = Paused { idle: Some(idle), pager, template };
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

    /// Whether its Firecracker still runs and its pager has not given up.
    pub fn alive(&mut self) -> bool {
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

