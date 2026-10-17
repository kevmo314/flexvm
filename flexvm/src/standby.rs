//! Standby VMs: `flexvm run --standby` processes holding a restored, settled,
//! paused VM so `run` is a resume plus `START`. Each listens on
//! `RUN/standby/HASH/PID.sock` (HASH: 16 hex characters) and holds
//! `PID-START.lock` while alive, and `PID-START.claim` locked while a claim is under way. Protocol: `run` sends `claim {name, ip, cmd, generation}` with
//! its stdout/stderr; once the standby replies `claiming`, the claim may have
//! started the VM and is never retried elsewhere. `{"exit": code}` follows. An
//! `attached` claim (a foreground `run`'s, with its `cgroup`, which the VM joins) ends the
//! VM if the claimer hangs up first.

use std::fs::File;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bail;
use crate::fc::Firecracker;
use crate::guest;
use crate::host::{fault, flock, Flock, Host, Ident, PidFd};
use crate::template::{Paths, Template};
use crate::util::{locked, send_json, Error, Phases, Result};
use crate::vm::{Prepared, Vm};
use crate::vmproc::{End, Op, Proc};

pub(crate) fn dir(host: &Host, template: &str) -> PathBuf {
    let mut hash = crate::template::Hash::new();
    hash.update(template.as_bytes());
    host.run.join("standby").join(hash.finish())
}

/// Its `.template` (the name, for `templates`) is written once: a rewrite per refill could race another thread's.
fn create_dir(host: &Host, template: &str) -> Result<PathBuf> {
    let d = dir(host, template);
    crate::host::host_dir(&d, 0o755)?;
    if std::fs::read(d.join(".template")).ok().as_deref() != Some(template.as_bytes()) {
        crate::util::write_file(&d, ".template", template.as_bytes(), false)?;
    }
    Ok(d)
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

/// `dir` (or its locks, `locks`), if only root or this user may write it: its sockets and locks name the processes signalled.
fn trusted(host: &Host, template: &str, locks: bool) -> Option<PathBuf> {
    let d = dir(host, template);
    let d = if locks { crate::host::locks(&d) } else { d };
    match crate::host::trusted_dir(d.parent()?).and_then(|()| crate::host::trusted_dir(&d)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => crate::log!("standby {template}: ignored: {e}"),
        r => return r.ok().map(|()| d),
    }
    None
}

/// The live standby processes of `template`, oldest first.
pub fn live(host: &Host, template: &str) -> Vec<Ident> {
    let mut ids = Vec::new();
    let Some(d) = trusted(host, template, true) else { return ids };
    for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || !name.ends_with(".lock") {
            continue;
        }
        let Ok(f) = crate::host::open_record(&e.path()) else { continue };
        if flock(&f, libc::LOCK_SH | libc::LOCK_NB).is_ok() {
            let _ = std::fs::remove_file(e.path());
        } else if let Some(id) = std::io::read_to_string(&f).ok().and_then(|s| serde_json::from_str::<Ident>(&s).ok()) {
            ids.push(id);
        }
    }
    ids.sort_by_key(|id| (id.start, id.pid));
    ids
}

/// `live`, less those mid-claim (`PID-START.claim` locked; START keeps a reused pid's apart): a stop would not end them.
pub fn stoppable(host: &Host, template: &str) -> Vec<Ident> {
    let Some(d) = trusted(host, template, true) else { return Vec::new() };
    let claiming = |id: &Ident| locked(&d.join(format!("{}.claim", id.key())), libc::LOCK_SH) == Some(true);
    live(host, template).into_iter().filter(|id| !claiming(id)).collect()
}

/// SIGUSR1, not SIGINT: a stop can reach the process after a claim started
/// (it lists it until the claim is done, and its signal thread may take it
/// late), and the VM it became must not take it for a kill. The pidfd of the one signalled.
pub fn stop(id: &Ident) -> Option<PidFd> {
    let fd = PidFd::open(id).ok().flatten()?;
    fd.signal(libc::SIGUSR1).ok()?;
    Some(fd)
}

pub fn templates(host: &Host) -> Vec<String> {
    let mut t: Vec<String> = [host.state.join("standby"), host.run.join("standby")]
        .iter()
        .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
        .filter_map(|e| {
            if e.file_type().ok()?.is_dir() {
                std::fs::read_to_string(e.path().join(".template")).ok()
            } else {
                Some(e.file_name().to_string_lossy().into_owned())
            }
        })
        .filter(|n| !n.starts_with('.'))
        .collect();
    t.sort();
    t.dedup();
    t
}

pub fn set(host: &Host, template: &str, n: usize) -> Result<Value> {
    {
        let paths = Paths::new(&host.state);
        let parent = crate::host::Directory::open(&paths.templates)?;
        let paths = Paths { templates: parent.path.clone(), ..paths };
        let _lock = crate::template::templates_lock(&paths, libc::LOCK_SH)?;
        Template::resolve(&paths, template)?;
        crate::util::write_file(&host.state.join("standby"), template, n.to_string().as_bytes(), true)?;
        for id in live(host, template).iter().skip(n) {
            stop(id);
        }
    }
    let started = refill(host, template)?;
    Ok(json!({"template": template, "standby": n, "started": started}))
}

/// Stop a name's pool before removal, under the templates lock. Keep its count if the
/// name survives, including a failed removal; no `set` may write it between these decisions.
pub(crate) fn removing<T>(host: &Host, paths: &Paths, template: &str, remove: impl FnOnce(&Paths) -> Result<T>) -> Result<T> {
    let parent = crate::host::Directory::open(&paths.templates)?;
    let paths = Paths { templates: parent.path.clone(), ..paths.clone() };
    let _lock = crate::template::templates_lock(&paths, libc::LOCK_EX)?;
    // Finish any refill already in progress before taking the pool's pidfds.
    let d = create_dir(host, template)?;
    let _refill = Flock::new(crate::host::private_file(&crate::host::locks(&d).join("refill"))?, libc::LOCK_EX)?;
    let count = host.state.join("standby").join(template);
    let saved = match std::fs::read(&count) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    // Capture before publishing 0: a standby can notice it and unlink its record itself.
    let mut waiting = Vec::new();
    for id in live(host, template) {
        if let Some(fd) = PidFd::open(&id)? {
            waiting.push(fd);
        }
    }
    let result = (|| {
        crate::util::write_file(&host.state.join("standby"), template, b"0", true)?;
        for fd in &waiting {
            if let Err(e) = fd.signal(libc::SIGUSR1) {
                if !fd.wait(Duration::ZERO) {
                    return Err(e);
                }
            }
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        for fd in waiting {
            if !fd.wait(deadline.saturating_duration_since(Instant::now())) {
                bail!("image {}'s standby VMs are still there; try again", crate::template::image_of(template));
            }
        }
        remove(&paths)
    })();
    let gone = std::fs::symlink_metadata(paths.templates.join(template)).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
    match saved.filter(|_| !gone) {
        Some(bytes) => crate::util::write_file(&host.state.join("standby"), template, &bytes, true)?,
        None => match std::fs::remove_file(&count) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            r => r?,
        },
    }
    result
}

/// Periodic recovery, run by listeners and running VM processes. A
/// nonblocking refill lock avoids piling up workers behind a slow restore.
/// No refill for a minute after pressure stopped standby VMs (so they do not
/// cycle) or after a template's refill failed (its error is in standby.log).
pub fn maintain(host: Host) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        refill_round(&host);
    });
}

/// One round of `maintain`: each template short of its count refilled, unless pressure or
/// its refill failed lately.
pub fn refill_round(host: &Host) {
    if recent(&pressure(host)) {
        return;
    }
    for template in templates(host) {
        if target(host, &template) == 0 {
            continue;
        }
        let failed = dir(host, &template).join(".failed");
        if recent(&failed) {
            continue;
        }
        if let Err(e) = refill_by(host, &template, false, true) {
            let _ = crate::host::write_record(&failed, b"");
            // As its standby VMs write it: capped, to whichever file is current.
            let path = dir(host, &template).join("standby.log");
            let line = format!("standby {template}: refill: {e}\n");
            crate::util::output::append_capped(&path, line.as_bytes(), crate::util::output::LOG_CAP);
        }
    }
}

/// `STATE/.locks/standby.stop`: relief holds it exclusively while it lists and
/// signals standby VMs, a refill shared from a grant until its standby is listed.
pub fn stop_lock(host: &Host) -> std::io::Result<File> {
    crate::host::private_file(&crate::host::locks(&host.state).join("standby.stop"))
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
    refill_by(host, template, true, false)
}

/// `cooldown`: none while `.pressure` is recent, checked for each standby under the stop
/// lock, so a refill that waited behind another while relief stopped standbys starts none.
/// Only a count set by hand (`set`) starts them regardless.
fn refill_by(host: &Host, template: &str, wait: bool, cooldown: bool) -> Result<usize> {
    let d = create_dir(host, template)?;
    let lock = crate::host::private_file(&crate::host::locks(&d).join("refill"))?;
    let _lock = match Flock::new(lock, libc::LOCK_EX | if wait { 0 } else { libc::LOCK_NB }) {
        Ok(lock) => lock,
        Err(e) if !wait && e.raw_os_error() == Some(libc::EWOULDBLOCK) => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let want = target(host, template).saturating_sub(live(host, template).len());
    if want == 0 {
        return Ok(0);
    }
    let mut ready = Vec::new();
    let log = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().create(true).append(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(d.join("standby.log"))?
    };
    let mib = grant_mib(host, template);
    // A failed start ends the round, but those started before it are still waited for.
    let mut failed = None;
    for _ in 0..want {
        match start_one(host, template, &log, mib, cooldown) {
            Ok(Some(r)) => ready.push(r),
            Ok(None) => break,
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    let started = ready.len();
    for r in ready {
        if let Err(e) = wait_ready(r, READY_TIMEOUT) {
            failed.get_or_insert(e);
        }
    }
    match failed {
        Some(e) => Err(e),
        None => Ok(started),
    }
}

/// A started standby's readiness reply, within `timeout` of now: counted from when it is
/// read, not from its start, as replies are read only once every start in the round is done.
fn wait_ready(r: BufReader<UnixStream>, timeout: Duration) -> Result<()> {
    let mut r = crate::util::By { s: r, at: Instant::now() + timeout };
    match crate::util::recv_json(&mut r)? {
        None => Err("a standby vm failed to start (see its log)".into()),
        Some(reply) if reply["ok"] != json!(true) => Err(format!("a standby vm failed to start: {}", reply["error"]).into()),
        Some(_) => Ok(()),
    }
}

/// What a refill's grant admits for each standby: what its load pages in, as a cold
/// start admits (`working_set_mib`), and `MIN_GRANT_MIB` at least. The template is
/// found as the standby's process will find it.
fn grant_mib(host: &Host, template: &str) -> u64 {
    let wset = Template::working_set_mib_of(&crate::template::Paths::new(&host.state), template);
    MIN_GRANT_MIB.max(wset.unwrap_or(0))
}

/// One standby started and listed, its readiness reply to come; None if relief
/// holds the stop lock, pressure is recent (`cooldown`), the grant is refused or the host lock is busy.
fn start_one(host: &Host, template: &str, log: &File, mib: u64, cooldown: bool) -> Result<Option<BufReader<UnixStream>>> {
    // Shared from the grant until its lock file exists (`locked`), not through its load:
    // relief either lists it or ran before the grant. None while relief stops them, and
    // held `LOCKED_TIMEOUT` at most (a stuck host lock fails the grant; a child that
    // has not acknowledged its lock by then is killed and reaped).
    let stop = stop_lock(host)?;
    let by = Instant::now() + LOCKED_TIMEOUT;
    let Ok(stop) = Flock::new(stop, libc::LOCK_SH | libc::LOCK_NB) else { return Ok(None) };
    // Relief marks `.pressure` holding the stop lock exclusively: seen now if it came at all.
    if cooldown && recent(&pressure(host)) {
        return Ok(None);
    }
    // Above the eviction mark, and none while an eviction runs here: a refill never takes
    // the room eviction is moving VMs away to make (#600).
    let grant = match host.grant_above(mib, crate::host::Floor::EvictMark, Some(by)) {
        Ok(Some(id)) => id,
        Ok(None) => return Ok(None),
        Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) => return Ok(None),
        Err(e) => return Err(e),
    };
    // What a child left unlisted is gone (`wait_locked`), so relief may go on; then its
    // grant and what it made before its lock (its cgroup and work directory) are freed:
    // locally only, never waiting on peers (`gc::sweep`'s network retirement).
    let release = |stop: Flock| {
        drop(stop);
        host.refund_by(grant, Some(Instant::now() + LOCKED_TIMEOUT));
        crate::gc::local_cleanup(host);
    };
    let started = (|| {
        let (r, w) = UnixStream::pair()?;
        let args =
            ["--state".as_ref(), host.state.as_os_str(), "--run".as_ref(), host.run.as_os_str(), "run".as_ref(), "--standby".as_ref(), template.as_ref()];
        crate::util::start_reaper()?;
        let mut child = crate::util::spawn_self_child(&args, log, w.as_raw_fd(), None, None, &[("FLEXVM_NOTIFY_FD", "3")])?;
        drop(w);
        let mut r = BufReader::new(r);
        wait_locked(&mut r, &mut child, by)?;
        Ok((r, child))
    })();
    let (r, child) = match started {
        Ok(started) => started,
        Err(e) => {
            release(stop);
            return Err(e);
        }
    };
    drop(stop);
    crate::util::reap_later(child, None);
    Ok(Some(r))
}

/// Never let relief pass an unlisted live child, including on a partial or invalid reply.
fn wait_locked(r: &mut BufReader<UnixStream>, child: &mut std::process::Child, by: Instant) -> Result<()> {
    // Keep read-ahead for the readiness reply, which gets its own deadline.
    let mut r = crate::util::By { s: r, at: by };
    let result = match crate::util::recv_json(&mut r) {
        Ok(Some(v)) if v["locked"] == json!(true) => Ok(()),
        // It failed before its lock (its template, say), and said why.
        Ok(Some(v)) if v["ok"] == json!(false) => Err(format!("a standby vm failed to start: {}", v["error"]).into()),
        Ok(_) => Err(Error::from("a standby vm failed to acknowledge its lock (see its log)")),
        Err(e) => Err(format!("a standby vm failed to acknowledge its lock: {e} (see its log)").into()),
    };
    if result.is_err() {
        // The unreaped child's pid cannot be reused. Even EOF can precede its exit.
        let _ = child.kill();
        child.wait()?;
    }
    result
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
    let path = host.run.join("standby").join(load_set_name(tpl));
    // Marked used: gc removes one neither read nor written for a while (`gc::LOADSET_TTL`).
    let _ = File::options().write(true).open(&path).and_then(|f| f.set_modified(std::time::SystemTime::now()));
    if let Some(saved) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<Vec<u64>>(&b).ok()) {
        set.extend(saved);
        set.sort_unstable();
        set.dedup();
    }
    set
}

/// Under the reserve, a standby leaves by itself, marking the pressure so it is not
/// refilled: a host with no running VM has no controller to stop it (#600). A running
/// VM's controller stops them first (`vmproc::relieve`), holding eviction off meanwhile.
fn under_reserve(host: &Host, template: &str) -> bool {
    let Some(avail) = crate::vmproc::host_available_mib() else { return false };
    let reserve = host.config_now().reserve();
    if avail >= reserve {
        return false;
    }
    crate::log!("standby {template}: host has {avail} MiB available, under its {reserve} MiB reserve: leaving");
    let _ = std::fs::write(pressure(host), b"");
    true
}

/// Whether an unclaimed standby leaves, and its exit status: 124 (`DIED`) when its VM
/// died; 0 when it leaves the pool on purpose (its template changed, the pool is over
/// target, its socket is gone, or the host is under its reserve). A signal sent to it ends it first (`Proc::stop_requested`).
fn leave_status(died: bool, left_pool: bool) -> Option<i32> {
    if died {
        Some(crate::vmproc::DIED)
    } else {
        left_pool.then_some(0)
    }
}

/// `run --standby`: returns once claimed; ends the process if stopped,
/// out of date, extra, or its VM died.
pub fn serve(p: &Arc<Proc>, template: &str, notify: &mut Option<File>, op: &Op) -> Result<Value> {
    let host = &p.host;
    let tpl = Template::open(&p.paths, template)?;
    // The key of the generation opened, not of whatever the name resolves to now: a
    // rebuild in between would publish this snapshot under the new generation's key.
    let mine = dir_key(&tpl.dir);
    let d = create_dir(host, template)?;
    let me = Ident::me();
    let id = me.key();
    // Its locks are in `.locks`, which only root may enter; its socket beside it.
    let l = crate::host::locks(&d);
    let (lock_path, sock) = (l.join(format!("{id}.lock")), d.join(format!("{}.sock", me.pid)));
    crate::socket::check(&sock)?;
    crate::host::stall("standby_lock_stall");
    // Test hook: held before its lock for as long as armed (past `LOCKED_TIMEOUT`, say).
    while crate::host::fault("standby_lock_hang") {
        std::thread::sleep(Duration::from_millis(50));
    }
    let tmp = l.join(format!(".{id}.lock"));
    let lock = crate::host::private_file(&tmp)?;
    crate::host::flock(&lock, libc::LOCK_EX)?;
    lock.write_all_at(&serde_json::to_vec(&me)?, 0)?;
    std::fs::rename(&tmp, &lock_path)?;
    // Listed now: the refill lets relief in.
    if let Some(f) = notify {
        let _ = send_json(f, &json!({"locked": true}));
    }
    let claim_path = l.join(format!("{id}.claim"));
    p.files.lock().unwrap().extend([sock.clone(), lock_path, claim_path.clone(), l.join(format!("{id}.take"))]);
    let ready = load(p.spawner.take(None)?, tpl.clone())?;
    // Taken now, so a claim does not scan memory or ask Firecracker.
    *p.sizes.lock().unwrap() = Some(ready.mem_sizes());
    *p.standby.lock().unwrap() = Some(ready);
    save_load_set(host, &tpl);
    // Under `.locks/publish`, a lock (not `*.lock`, which names a standby) a sweep holds: none finds this pid's socket stale and unlinks it after the bind.
    let publish = crate::host::Flock::new(crate::host::private_file(&l.join("publish"))?, libc::LOCK_EX)?;
    let _ = std::fs::remove_file(&sock); // A previous process with this pid may have left it.
    let listener = UnixListener::bind(&sock)?;
    // A claimer refused by a dead standby of this pid may unlink the path after this bind.
    let bound = std::fs::metadata(&sock)?.ino();
    drop(publish);
    if let Some(mut f) = notify.take() {
        let _ = send_json(&mut f, &json!({"ok": true, "result": {"pid": me.pid, "template": template}}));
    }
    let mut checked = Instant::now();
    loop {
        if !crate::util::readable(&listener, Duration::from_millis(100)).unwrap_or(false) {
            if let Some(code) = p.stop_requested() {
                p.finish(op, End::NotStarted, code, None);
            }
            if checked.elapsed() < Duration::from_secs(1) {
                continue;
            }
            checked = Instant::now();
            let current = key(&p.paths, template).ok();
            let extra = live(host, template).iter().position(|id| *id == me).is_none_or(|i| i >= target(host, template));
            let died = p.standby.lock().unwrap().as_ref().map_or(Some("it was given up".to_string()), |s| {
                s.pager.failed().map(String::from).or((!s.firecracker().alive()).then(|| "its firecracker exited".into()))
            });
            let unreachable = std::fs::symlink_metadata(&sock).map(|m| m.ino()).ok() != Some(bound);
            if let Some(why) = &died {
                crate::log!("standby {template}: died: {why}");
            }
            let low = under_reserve(host, template);
            if let Some(code) = leave_status(died.is_some(), current.as_deref() != Some(&mine) || extra || unreachable || low) {
                p.finish(op, End::NotStarted, code, None);
            }
            continue;
        }
        let Ok((c, _)) = listener.accept() else { continue };
        // In short waits, minding stops: a claimer stopped mid-request must not keep this one.
        let at = Instant::now() + HANDSHAKE_TIMEOUT;
        let ready = || loop {
            if p.stop_requested().is_some() || Instant::now() >= at {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            if crate::util::readable(&c, Duration::from_millis(100)).unwrap_or(true) {
                return Ok(());
            }
        };
        let Ok((line, fds)) = crate::util::recv_with_fds(&c, 1 << 20, ready) else { continue };
        let Ok(req) = serde_json::from_slice::<Value>(&line) else { continue };
        if req["generation"] != mine {
            continue;
        }
        // Locked until the claim succeeds or rolls back (dropped): relief does not count it stopped.
        let claiming = crate::host::private_file(&claim_path)?;
        crate::host::flock(&claiming, libc::LOCK_EX)?;
        // Not yet `claiming`, so the claimer tries another.
        if let Some(code) = p.stop_requested() {
            p.finish(op, End::NotStarted, code, None);
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
                crate::host::gate("claim_stall");
                let _ = std::fs::remove_file(&sock);
                // A claimer gone before its answer (a foreground `run` interrupted) would leave
                // the VM running with no one to stop it: it goes, as a cold foreground run's would.
                if let Err(e) = send_json(&mut &c, &json!({"ok": true, "result": v})) {
                    crate::log!("standby {template}: the claimer of {} is gone ({e}): destroying it", req["name"].as_str().unwrap_or(""));
                    // Not `destroy`: this op (the start) is held already. Nothing else runs on the VM yet.
                    p.finish(op, End::Gone, crate::vmproc::FAILED, None);
                }
                if let [out, err, ..] = &fds[..] {
                    crate::util::output::retarget([out.as_raw_fd(), err.as_raw_fd()]);
                }
                // A foreground claimer follows the VM, as a cold foreground run's process is it:
                // one gone later (SIGKILLed) leaves the VM to no one, so it goes too. A detached
                // claimer hangs up once answered.
                let attached = req["attached"] == json!(true);
                // In the claimer's cgroup, as a cold foreground run's VM process is (its Firecracker
                // has its own either way). This process moves itself: its own pid is never a reused one.
                if let (true, Some(cg)) = (attached, req["cgroup"].as_str()) {
                    if let Err(e) = crate::util::join_cgroup(cg) {
                        crate::log!("vm {}: not moved to its claimer's cgroup {cg:?}: {e}", req["name"].as_str().unwrap_or(""));
                    }
                }
                let watch = attached.then(|| c.try_clone());
                *p.claimer.lock().unwrap() = Some(c);
                match watch {
                    Some(Ok(w)) => {
                        let (p, n) = (p.clone(), req["name"].as_str().unwrap_or("").to_string());
                        std::thread::spawn(move || {
                            crate::util::wait_hung_up(&w);
                            // Taken by `finish`: the VM is ending, and the claimer hung up once told.
                            if p.claimer.lock().unwrap().is_none() {
                                return;
                            }
                            // Set first: a migration that refuses the destroy ends the VM if it aborts (`abort`).
                            p.claimer_gone.store(true, std::sync::atomic::Ordering::SeqCst);
                            crate::log!("vm {n}: its claimer (a foreground run) is gone: destroying it");
                            crate::log!("vm {n}: {}", p.destroy(crate::vmproc::FAILED));
                        });
                    }
                    Some(Err(e)) => crate::log!("vm {}: its claimer is not watched: {e}", req["name"].as_str().unwrap_or("")),
                    None => {}
                }
                for f in p.files.lock().unwrap().drain(..) {
                    let _ = std::fs::remove_file(f);
                }
                drop(lock);
                let (h, t) = (host.clone(), template.to_string());
                std::thread::spawn(move || {
                    // As `maintain`: none for a while after pressure stopped standby VMs.
                    if let Err(e) = refill_by(&h, &t, true, true) {
                        crate::log!("standby {t}: {e}");
                    }
                });
                return Ok(Value::Null);
            }
            Err((e, retry)) => {
                *p.cmd.lock().unwrap() = None;
                // Nor its caps (`--memory` included): the next claim sets its own.
                let _ = p.keep_resources(crate::vm::Resources::default());
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
    // Checked against this standby's own generation; a refusal leaves it for another claim.
    let resources: crate::vm::Resources = serde_json::from_value(req["resources"].clone()).map_err(|e| (format!("bad resources: {e}").into(), false))?;
    let tpl = p.standby.lock().unwrap().as_ref().map(|s| s.template()).ok_or_else(|| ("standby vm gone".into(), true))?;
    p.set_resources(resources, &tpl.meta).map_err(|e| (e, false))?;
    // Taken ahead of any claim: every claim sets its cgroup's cap, `max` for none, so one an
    // earlier claim that failed set (after this point) never carries over to this VM.
    {
        let s = p.standby.lock().unwrap();
        let fc = s.as_ref().ok_or_else(|| ("standby vm gone".into(), true))?.firecracker();
        match fc.set_cpu_max(&resources.cpu_max()) {
            Err(e) if resources.cpus.is_some() => return Err((e, false)),
            _ => {}
        }
    }
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
    // Prepare the paused tap outside the host lock; a withdrawal can still win before fence.
    let tap = p.standby.lock().unwrap().as_ref().ok_or_else(|| not_run("standby vm gone".into(), true))?.firecracker().tap.clone();
    let index = crate::net::neighbour(claim.ip, &tap).map_err(|e| {
        // As a failed attach in resume: discard this prepared VM and let the claimer retry.
        p.standby.lock().unwrap().take();
        not_run(format!("resuming a standby vm failed: {e}").into(), true)
    })?;
    // Separate netlink preparation from the generation fence (which can wait
    // for the host lock). Neither belongs to the route replacement below.
    t.mark("neighbour");
    let still = host.fence(claim.ip, claim.gen).map_err(|e| not_run(e, false))?;
    let paused = p.standby.lock().unwrap().take().ok_or_else(|| not_run("standby vm gone".into(), true))?;
    let vm = resume(paused, name, claim.ip, index, fault("resume_kill"), &mut t).map_err(|(e, ran)| {
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
    let Some(d) = trusted(host, template, false) else { return Ok(None) };
    let mut socks: Vec<PathBuf> = std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "sock") && p.file_stem().and_then(|s| s.to_str()).is_some_and(|s| s.parse::<u32>().is_ok()))
        .collect();
    socks.sort();
    let mut req = req.clone();
    req["generation"] = json!(key);
    let mut line = serde_json::to_vec(&req)?;
    line.push(b'\n');
    let name = req["name"].as_str().unwrap_or("");
    // One budget for all (a stopped standby uses it up), and a moment past it for each live one, up to a few.
    let budget = Instant::now() + HANDSHAKE_TIMEOUT;
    // Each tried first by one claimer at a time (`ID.take`, held while it is tried), so
    // concurrent runs take different standbys; those others are trying come last.
    let mut queue: std::collections::VecDeque<(PathBuf, bool)> = socks.into_iter().map(|s| (s, false)).collect();
    while let Some((sock, deferred)) = queue.pop_front() {
        if Instant::now() >= budget + 4 * LATE {
            break;
        }
        let _taking = match deferred {
            false => match try_take(&sock) {
                Some(taking) => taking,
                None => {
                    queue.push_back((sock, true));
                    continue;
                }
            },
            true => None,
        };
        let at = budget.max(Instant::now() + LATE);
        let ino = std::fs::metadata(&sock).map(|m| m.ino()).ok();
        let c = match crate::util::send_unix(&sock, &line, fds, at) {
            Ok(c) => c,
            // Refused: stale. (A full backlog is a stopped standby's.) Unlinked under `.publish`, as gc does,
            // and only the socket refused, not one a standby of a reused pid has bound since.
            Err(e) => {
                if e.raw_os_error() == Some(libc::ECONNREFUSED) {
                    let publish = crate::host::private_file(&publish_lock(&sock)).and_then(|f| Flock::new(f, libc::LOCK_EX | libc::LOCK_NB));
                    if publish.is_ok() && ino.is_some() && std::fs::metadata(&sock).map(|m| m.ino()).ok() == ino {
                        let _ = std::fs::remove_file(&sock);
                    }
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
        // Keep read-ahead (including an early exit) when the deadline is removed.
        let mut r = crate::util::By { s: BufReader::new(c), at: Instant::now() + CLAIM_TIMEOUT };
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
                let started = host.entry(name).map(|e| format!("it did: pid {}", e.ident.pid)).unwrap_or_else(|_| "see flexvm ps".into());
                bail!("claiming standby vm {} as {name}: {e}; it may have started the vm ({started}), so it is not started again", sock.display());
            }
        };
        if reply["ok"] == json!(true) {
            r.s.get_ref().set_read_timeout(None)?;
            return Ok(Some((reply["result"].clone(), r.s)));
        }
        if reply["retry"] != json!(true) {
            bail!("{}", reply["error"].as_str().unwrap_or("claim failed"));
        }
        crate::log!("flexvm: {}; trying another", reply["error"].as_str().unwrap_or(""));
    }
    Ok(None)
}

/// `PID.sock`'s `PID-START.take`, locked: Some(lock), Some(None) if it cannot be had (no
/// such name, a file it cannot create: tried anyway), None if another claimer holds it.
fn try_take(sock: &std::path::Path) -> Option<Option<File>> {
    let Some(stem) = sock.file_stem().and_then(|s| s.to_str()) else { return Some(None) };
    let Some(id) = stem.parse().ok().and_then(Ident::of).map(|id| id.key()) else {
        return Some(None);
    };
    let Ok(f) = crate::host::private_file(&publish_lock(sock).with_file_name(format!("{id}.take"))) else { return Some(None) };
    match flock(&f, libc::LOCK_EX | libc::LOCK_NB) {
        Ok(()) => Some(Some(f)),
        Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => None,
        Err(_) => Some(None),
    }
}

/// The lock a standby's socket is replaced, and found stale, under: `.locks/publish` beside it.
pub fn publish_lock(sock: &std::path::Path) -> PathBuf {
    crate::host::locks(sock.parent().unwrap_or(std::path::Path::new("."))).join("publish")
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// What a refill grants a standby at least (`grant_mib`).
const MIN_GRANT_MIB: u64 = 256;
/// How long a refill holds relief off for each standby it starts: its grant, then its lock file.
const LOCKED_TIMEOUT: Duration = Duration::from_secs(5);
/// Restore, reseed and settle, bounded independently of publishing the lock.
const READY_TIMEOUT: Duration = Duration::from_secs(60);
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
    fc.load_snapshot(&p.template().vmstate(), &p.template().vmstate(), &p.firecracker().tap, Some(true), LOAD_TIMEOUT)?;
    // Only an API pause stops the devices writing guest memory.
    fc.pause(API_TIMEOUT)?;
    p.pager.wait_ready(Duration::from_secs(5))?;
    let resumed = fc.resume(API_TIMEOUT);
    p.pager.loaded();
    resumed?;
    wait_for_reseed(&fc.sockets.vsock)?;
    // Set the clock now so START at the claim can skip clock_settime (slow in big guests).
    let _ = guest::clock(&fc.sockets.vsock, guest::TIMEOUT);
    std::thread::sleep(SETTLE);
    fc.pause(API_TIMEOUT)?;
    Ok(p)
}

/// On failure the flag says whether the guest may have run for `name` (the
/// resume may have reached Firecracker).
fn resume(p: Prepared, name: &str, ip: Ipv4Addr, index: u32, kill: bool, t: &mut Phases) -> std::result::Result<Arc<Vm>, (Error, bool)> {
    t.mark("fence");
    crate::net::route_dev(true, ip, index).map_err(|e| (e, false))?;
    t.mark("route");
    let res = p.firecracker().resume(API_TIMEOUT);
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

/// Waits for the guest RNG reseed for the new VMGenID.
fn wait_for_reseed(vsock: &std::path::Path) -> Result<()> {
    let deadline = Instant::now() + RESEED_TIMEOUT;
    loop {
        let res = guest::forks(vsock);
        match res {
            Ok(n) if n > 0 => return Ok(()),
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(_) => bail!("guest did not reseed its RNG for the new VMGenID within {RESEED_TIMEOUT:?}"),
            Err(e) => bail!("guest agent not answering after restore: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host with template `default` (generation `a`) and its pool's directory.
    fn pool(tag: &str) -> (crate::test_util::TempDir, Host, Paths, PathBuf) {
        let root = crate::test_util::TempDir::new(tag);
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        std::fs::create_dir_all(root.join("templates/.gen/a")).unwrap();
        std::os::unix::fs::symlink(".gen/a", root.join("templates/default")).unwrap();
        let paths = Paths::new(&root);
        let d = dir(&host, "default");
        std::fs::create_dir_all(&d).unwrap();
        (root, host, paths, d)
    }

    #[test]
    fn removal_restores_the_count_only_while_the_name_survives() {
        let (_root, host, paths, _d) = pool("standby-rmi-count");
        let count = host.state.join("standby/default");
        crate::util::write_file(&host.state.join("standby"), "default", b"3\n", true).unwrap();
        for repulled in [false, true] {
            let result: Result<()> = removing(&host, &paths, "default", |paths| {
                assert_eq!(target(&host, "default"), 0);
                if repulled {
                    std::fs::remove_file(paths.templates.join("default"))?;
                    std::os::unix::fs::symlink(".gen/b", paths.templates.join("default"))?;
                }
                Err("removal failed".into())
            });
            assert!(result.is_err());
            assert_eq!(std::fs::read(&count).unwrap(), b"3\n");
        }
        // Even an error after unlinking must leave no count for refills to discover.
        let result: Result<()> = removing(&host, &paths, "default", |paths| {
            std::fs::remove_file(paths.templates.join("default"))?;
            Err("sync failed".into())
        });
        assert!(result.is_err());
        assert!(!count.exists());
        std::os::unix::fs::symlink(".gen/a", paths.templates.join("default")).unwrap();
        removing(&host, &paths, "default", |_| Ok(())).unwrap();
        assert!(!count.exists(), "an unset count stays absent when the name survives");
    }

    #[test]
    fn set_waits_for_removal_and_cannot_leave_a_count_for_a_missing_name() {
        let (_root, host, paths, _d) = pool("standby-rmi-set");
        // `set` uses the host's templates directory.
        std::os::unix::fs::symlink(&paths.templates, host.state.join("templates")).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let setter_host = host.clone();
        let setter = removing(&host, &paths, "default", |paths| {
            let setter = std::thread::spawn(move || tx.send(set(&setter_host, "default", 0)).unwrap());
            assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
            std::fs::remove_file(paths.templates.join("default"))?;
            Ok(setter)
        })
        .unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap().is_err());
        setter.join().unwrap();
        assert!(!host.state.join("standby/default").exists());
    }

    #[test]
    fn removal_waits_for_process_exit_after_its_pool_lock_disappears() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};

        let (_root, host, paths, d) = pool("standby-rmi-exit");
        let mut child = Command::new("sh")
            .args(["-c", "trap 'echo stopped' USR1; echo ready; while :; do read line && exit; done"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        output.read_line(&mut ready).unwrap();
        assert_eq!(ready, "ready\n");
        let id = Ident::of(child.id()).unwrap();
        let record = crate::host::locks(&d).join(format!("{}.lock", id.key()));
        crate::host::write_record(&record, &serde_json::to_vec(&id).unwrap()).unwrap();
        let _held = Flock::new(crate::host::open_record(&record).unwrap(), libc::LOCK_EX).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let removing_host = host.clone();
        let worker = std::thread::spawn(move || {
            removing(&removing_host, &paths, "default", |_| {
                tx.send(()).unwrap();
                Ok(())
            })
        });
        // A signal handler acknowledges the stop after removal captured its pidfd.
        ready.clear();
        output.read_line(&mut ready).unwrap();
        assert_eq!(ready, "stopped\n");
        std::fs::remove_file(&record).unwrap();
        assert!(live(&host, "default").is_empty());
        let early = rx.recv_timeout(Duration::from_millis(100));
        child.kill().unwrap();
        child.wait().unwrap();
        worker.join().unwrap().unwrap();
        assert!(early.is_err(), "removal returned while the process still held its template");
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn a_dead_standby_exits_124_and_only_leaving_the_pool_exits_0() {
        assert_eq!(leave_status(false, false), None);
        assert_eq!(leave_status(false, true), Some(0));
        assert_eq!(leave_status(true, false), Some(crate::vmproc::DIED));
        assert_eq!(leave_status(true, true), Some(crate::vmproc::DIED));
    }

    #[test]
    fn long_template_has_a_short_socket_path() {
        let root = crate::test_util::TempDir::new("fv-long");
        let run = root.join("r".repeat(60usize.saturating_sub(root.as_os_str().len() + 1).max(1)));
        let host = Host::open(&root.join("state"), &run).unwrap();
        let template = "t".repeat(64);
        let d = create_dir(&host, &template).unwrap();
        assert!(host.run.as_os_str().len() >= 60);
        assert_eq!(d.file_name().unwrap().len(), 16);
        for pid in [Ident::me().pid, u32::MAX] {
            let sock = d.join(format!("{pid}.sock"));
            crate::socket::check(&sock).unwrap();
        }
        let sock = d.join(format!("{}.sock", Ident::me().pid));
        let taking = try_take(&sock).unwrap().unwrap();
        assert!(try_take(&sock).is_none());
        assert!(crate::host::locks(&d).join(format!("{}.take", Ident::me().key())).exists());
        drop(taking);
        assert_eq!(templates(&host), [template]);
        assert_ne!(d, dir(&host, &"u".repeat(64)));
    }

    #[test]
    fn unacknowledged_children_are_killed_and_reaped_before_relief() {
        use std::os::unix::process::ExitStatusExt;

        let root = crate::test_util::TempDir::new("standby-locked");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        for reply in ["", "{\"locked\":", "{\"locked\":false}\n", "{\"ok\":false,\"error\":\"no template\"}\n"] {
            let stop = Flock::new(stop_lock(&host).unwrap(), libc::LOCK_SH).unwrap();
            let (r, mut w) = UnixStream::pair().unwrap();
            std::io::Write::write_all(&mut w, reply.as_bytes()).unwrap();
            let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
            let pid = child.id();
            let relief_host = host.clone();
            let relief = std::thread::spawn(move || {
                let _stop = Flock::new(stop_lock(&relief_host).unwrap(), libc::LOCK_EX).unwrap();
                assert!(live(&relief_host, "default").is_empty());
                assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists(), "relief missed a live child");
            });
            let start = Instant::now();
            let error = wait_locked(&mut BufReader::new(r), &mut child, start + Duration::from_millis(100)).unwrap_err();
            assert_eq!(child.try_wait().unwrap().unwrap().signal(), Some(libc::SIGKILL));
            assert!(start.elapsed() < Duration::from_secs(5));
            drop(stop);
            relief.join().unwrap();
            let why = if reply.contains("no template") { "failed to start: \"no template\"" } else { "failed to acknowledge its lock" };
            assert!(error.to_string().contains(why), "{error}");
            if !reply.ends_with('\n') {
                assert!(error.to_string().contains("deadline passed"), "{error}");
            }
        }
    }

    #[test]
    fn a_readiness_reply_queued_long_before_it_is_read_still_counts() {
        // As for the first of many standbys, whose reply waits while the others start.
        let (r, mut w) = UnixStream::pair().unwrap();
        send_json(&mut w, &json!({"ok": true, "result": {}})).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        wait_ready(BufReader::new(r), Duration::from_millis(100)).unwrap();
        // A child that never replies still fails within its timeout, from when it is read.
        let (r, _w) = UnixStream::pair().unwrap();
        let start = Instant::now();
        let timeout = Duration::from_millis(100);
        assert!(wait_ready(BufReader::new(r), timeout).unwrap_err().to_string().contains("deadline passed"));
        let elapsed = start.elapsed();
        assert!(elapsed >= timeout, "readiness timed out early: {elapsed:?}");
        assert!(elapsed < timeout + Duration::from_secs(5), "readiness missed its deadline: {elapsed:?}");
    }

    #[test]
    fn readiness_has_a_deadline_after_a_valid_lock_acknowledgement() {
        let (r, mut w) = UnixStream::pair().unwrap();
        send_json(&mut w, &json!({"locked": true})).unwrap();
        // A partial readiness reply must not extend its deadline either.
        std::io::Write::write_all(&mut w, b"{\"ok\":").unwrap();
        let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
        let mut r = BufReader::new(r);
        wait_locked(&mut r, &mut child, Instant::now() + Duration::from_secs(1)).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        let start = Instant::now();
        let mut r = crate::util::By { s: r, at: start + Duration::from_millis(100) };
        assert!(crate::util::recv_json(&mut r).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn stopped_standbys_share_one_handshake_budget_and_a_live_one_after_them_wins() {
        let (_root, host, paths, d) = pool("standby-budget");
        let stopped = ["0", "00"].map(|n| UnixListener::bind(d.join(format!("{n}.sock"))).unwrap());
        let live = UnixListener::bind(d.join(format!("{}.sock", Ident::me().pid))).unwrap();
        let live = std::thread::spawn(move || {
            let (c, _) = live.accept().unwrap();
            let req = crate::util::recv_json(&mut BufReader::new(&c)).unwrap().unwrap();
            assert_eq!(req["generation"], "a");
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
    }

    #[test]
    fn claim_keeps_an_exit_read_ahead_with_its_reply() {
        let (_root, host, paths, d) = pool("standby-buffer");
        let listener = UnixListener::bind(d.join(format!("{}.sock", Ident::me().pid))).unwrap();
        let peer = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            crate::util::recv_json(&mut BufReader::new(&c)).unwrap().unwrap();
            std::io::Write::write_all(&mut c, b"{\"claiming\":true}\n{\"ok\":true,\"result\":42}\n{\"exit\":7}\n").unwrap();
        });
        let (reply, mut r) = take(&host, &paths, "default", &json!({"name":"test"}), &[]).unwrap().unwrap();
        assert_eq!(reply, json!(42));
        assert!(!r.buffer().is_empty(), "exit was not read ahead");
        assert_eq!(r.get_ref().read_timeout().unwrap(), None);
        assert_eq!(crate::util::recv_json(&mut r).unwrap().unwrap(), json!({"exit":7}));
        peer.join().unwrap();
    }

    #[test]
    fn refill_keeps_readiness_read_ahead_with_the_lock_ack() {
        let (r, mut w) = UnixStream::pair().unwrap();
        std::io::Write::write_all(&mut w, b"{\"locked\":true}\n{\"ok\":true}\n").unwrap();
        let mut r = BufReader::new(r);
        let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
        let locked = wait_locked(&mut r, &mut child, Instant::now() + Duration::from_secs(1));
        child.kill().unwrap();
        child.wait().unwrap();
        locked.unwrap();
        assert!(!r.buffer().is_empty());
        wait_ready(r, Duration::from_millis(100)).unwrap();
    }

    #[test]
    fn concurrent_claimers_take_different_standbys() {
        let (_root, host, paths, d) = pool("standby-take");
        let mut pids = [Ident::me().pid, unsafe { libc::getppid() } as u32];
        pids.sort_by_key(|pid| format!("{pid}.sock"));
        let socks = pids.map(|pid| d.join(format!("{pid}.sock")));
        let first = UnixListener::bind(&socks[0]).unwrap();
        let second = UnixListener::bind(&socks[1]).unwrap();
        let claim = |name: &'static str| {
            let host = host.clone();
            let paths = paths.clone();
            std::thread::spawn(move || take(&host, &paths, "default", &json!({"name": name}), &[]).unwrap().unwrap().0)
        };
        let request = |listener: &UnixListener, name: &str| {
            assert!(crate::util::readable(listener, CLAIM_TIMEOUT).unwrap(), "claimer {name} did not connect");
            let (c, _) = listener.accept().unwrap();
            let mut r = crate::util::By { s: BufReader::new(&c), at: Instant::now() + CLAIM_TIMEOUT };
            assert_eq!(crate::util::recv_json(&mut r).unwrap().unwrap()["name"], name);
            c
        };
        let first_claimer = claim("a");
        // Wait for an actual claim in flight before starting its competitor.
        let mut first_request = request(&first, "a");
        assert!(try_take(&socks[0]).is_none());
        let second_claimer = claim("b");
        let mut second_request = request(&second, "b");
        // The second request reached the other standby while the first handshake
        // was still pending. On timeout the first claimer releases this take lock.
        // Check that state before replying: processing replies can take longer than
        // HANDSHAKE_TIMEOUT (CLAIM_TIMEOUT applies once claiming is received).
        assert!(try_take(&socks[0]).is_none(), "first claimer timed out before the second request arrived");
        for (c, n) in [(&mut first_request, 1), (&mut second_request, 2)] {
            send_json(c, &json!({"claiming": true})).unwrap();
            send_json(c, &json!({"ok": true, "result": n})).unwrap();
        }
        assert_eq!(first_claimer.join().unwrap(), json!(1));
        assert_eq!(second_claimer.join().unwrap(), json!(2));
    }

    #[test]
    fn a_busy_standby_is_tried_if_no_idle_one_remains() {
        let (_root, host, paths, d) = pool("standby-busy");
        let sock = d.join(format!("{}.sock", Ident::me().pid));
        let listener = UnixListener::bind(&sock).unwrap();
        let other = try_take(&sock).unwrap().unwrap();
        let peer = std::thread::spawn(move || {
            let (c, _) = listener.accept().unwrap();
            crate::util::recv_json(&mut BufReader::new(&c)).unwrap().unwrap();
            send_json(&mut &c, &json!({"claiming": true})).unwrap();
            send_json(&mut &c, &json!({"ok": true, "result": 1})).unwrap();
        });
        let (v, _) = take(&host, &paths, "default", &json!({"name": "test"}), &[]).unwrap().unwrap();
        assert_eq!(v, json!(1));
        drop(other);
        peer.join().unwrap();
    }

    #[test]
    fn a_reused_pid_keeps_its_own_lock() {
        let root = crate::test_util::TempDir::new("standby-identity");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let d = crate::host::locks(&dir(&host, "default"));
        crate::host::private_dir(&d).unwrap();
        let me = Ident::me();
        let path = d.join(format!("{}.lock", me.key()));
        let lock = File::create(&path).unwrap();
        crate::host::flock(&lock, libc::LOCK_EX).unwrap();
        lock.write_all_at(&serde_json::to_vec(&me).unwrap(), 0).unwrap();
        let stale = d.join(format!("{}-0.lock", me.pid));
        File::create(&stale).unwrap();
        assert_eq!(live(&host, "default"), [me]);
        assert!(!stale.exists() && path.exists());
    }

    #[test]
    fn planted_standby_records_name_no_one_to_signal() {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::test_util::TempDir::new("standby-planted");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let (d, mut victim) = (dir(&host, "default"), std::process::Command::new("sleep").arg("100").spawn().unwrap());
        let locks = crate::host::locks(&d);
        crate::host::private_dir(&locks).unwrap();
        let id = Ident::of(victim.id()).unwrap();
        let (record, elsewhere) = (locks.join(format!("{}.lock", id.key())), root.join("elsewhere.lock"));
        let lock = File::create(&elsewhere).unwrap();
        crate::host::flock(&lock, libc::LOCK_EX).unwrap();
        lock.write_all_at(&serde_json::to_vec(&id).unwrap(), 0).unwrap();
        std::fs::hard_link(&elsewhere, &record).unwrap();
        let mode = |p: &std::path::Path, m| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        assert_eq!(live(&host, "default"), [id.clone()], "a safe record is believed");
        for (path, unsafe_mode, safe) in [(&d, 0o777, 0o755), (&locks, 0o770, 0o700), (&locks, 0o707, 0o700), (&record, 0o666, 0o644), (&record, 0o664, 0o644)]
        {
            mode(path, unsafe_mode);
            assert!(live(&host, "default").is_empty() && stoppable(&host, "default").is_empty(), "{} {unsafe_mode:o}", path.display());
            mode(path, safe);
        }
        std::fs::remove_file(&record).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &record).unwrap();
        assert!(live(&host, "default").is_empty(), "never through a link");
        assert!(victim.try_wait().unwrap().is_none());
        victim.kill().unwrap();
        victim.wait().unwrap();
    }

    #[test]
    fn recovery_finds_persistent_targets_and_respects_refill_lock_and_reserve() {
        let root = crate::test_util::TempDir::new("refill");
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        crate::util::write_file(&host.state.join("standby"), "default", b"1", true).unwrap();
        // No runtime pool after a reboot; the persistent target is discovered.
        assert_eq!(templates(&host), vec!["default"]);
        let d = dir(&host, "default");
        std::fs::create_dir_all(&d).unwrap();
        let lock = crate::host::private_file(&crate::host::locks(&d).join("refill")).unwrap();
        let lock = Flock::new(lock, libc::LOCK_EX).unwrap();
        assert_eq!(refill_by(&host, "default", false, true).unwrap(), 0);
        drop(lock);
        // Nor while relief stops standby VMs.
        let stop = stop_lock(&host).unwrap();
        let stop = Flock::new(stop, libc::LOCK_EX).unwrap();
        assert_eq!(refill_by(&host, "default", false, true).unwrap(), 0);
        drop(stop);
        // A busy host lock ends this round without a refill failure or backoff, and lets relief in.
        let held = crate::host::private_file(&host.lock_file()).unwrap();
        let held = Flock::new(held, libc::LOCK_EX).unwrap();
        let start = Instant::now();
        assert_eq!(refill_by(&host, "default", false, true).unwrap(), 0);
        assert!(!d.join(".failed").exists());
        assert!(start.elapsed() < LOCKED_TIMEOUT + Duration::from_secs(1), "{:?}", start.elapsed());
        Flock::new(stop_lock(&host).unwrap(), libc::LOCK_EX | libc::LOCK_NB).unwrap();
        // Saving a count also succeeds if its first refill hits the same timeout.
        std::fs::create_dir_all(host.state.join("templates/.gen/a")).unwrap();
        std::os::unix::fs::symlink(".gen/a", host.state.join("templates/default")).unwrap();
        assert_eq!(set(&host, "default", 1).unwrap()["started"], json!(0));
        assert_eq!(target(&host, "default"), 1);
        drop(held);
        host.cfg.reserve_mib = Some(u64::MAX / 2);
        // Hold the reentrant host lock so another test cannot time out this grant before it checks the reserve.
        let l = host.lock().unwrap();
        let started = refill_by(&host, "default", false, true).unwrap();
        drop(l);
        assert_eq!(started, 0);
        assert!(live(&host, "default").is_empty());
        assert!(!recent(&pressure(&host)));
        std::fs::write(pressure(&host), b"").unwrap();
        assert!(recent(&pressure(&host)));
        // Under the stop lock, before the grant: recent pressure ends the round at once, with
        // no grant (one would wait out the busy host lock), even for a refill that got its locks late.
        host.cfg.reserve_mib = Some(0);
        let held = Flock::new(crate::host::private_file(&host.lock_file()).unwrap(), libc::LOCK_EX).unwrap();
        let start = Instant::now();
        assert_eq!(refill_by(&host, "default", true, true).unwrap(), 0);
        assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
        drop(held);
    }

    /// #600: a refill leaves the eviction mark available, not just the reserve, so it
    /// never takes room eviction moves VMs away to make; a refused grant is no failure.
    #[test]
    fn refills_are_admitted_above_the_eviction_mark() {
        let root = crate::test_util::TempDir::new("refill-mark");
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        crate::util::write_file(&host.state.join("standby"), "default", b"1", true).unwrap();
        std::fs::create_dir_all(dir(&host, "default")).unwrap();
        host.cfg.reserve_mib = Some(0);
        host.cfg.evict_mib = Some(u64::MAX / 2);
        let l = host.lock().unwrap();
        let started = refill_by(&host, "default", false, true).unwrap();
        drop(l);
        assert_eq!(started, 0);
        assert!(live(&host, "default").is_empty());
        assert!(!dir(&host, "default").join(".failed").exists());
    }
}
