//! Docker's container commands besides the lifecycle ones: `logs`, `inspect`, `wait`, `rename`,
//! and `ps`'s `--filter` and `--format`. All without a daemon: what they say comes from the
//! records in the run and state directories, and from the VM's own process (a running VM's rename).

use std::io::{Read, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::host::{self, Host, Ident};
use crate::util::Result;
use crate::vm::State;
use crate::vmproc::{Proc, Suspend};
use crate::{bail, template};

/// `RUN/vms/NAME.exit`: how the last process that ran `name` ended, written as it lets the name
/// go (`Proc::finish`). Its identity tells which instance it was, so `wait` never takes an
/// earlier instance's status for the one it waited on.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Exit {
    #[serde(flatten)]
    pub ident: Ident,
    pub code: i32,
}

pub fn record_exit(host: &Host, name: &str, ident: &Ident, code: i32) {
    if let Ok(path) = host.vms(name, "exit") {
        if let Err(e) = host::store(&path, &Exit { ident: ident.clone(), code }, false) {
            crate::log!("vm {name}: recording its exit status: {e}");
        }
    }
}

pub fn exit_record(host: &Host, name: &str) -> Option<Exit> {
    host::load::<Exit>(&host.vms(name, "exit").ok()?).ok().flatten()
}

/// `rm`: a removed VM has no status left to wait for.
pub fn forget_exit(host: &Host, name: &str) {
    if !host.alive(name) {
        if let Ok(path) = host.vms(name, "exit") {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The status a suspend ends its process with (`stop`, SIGTERM).
const STOPPED: i32 = 128 + libc::SIGTERM;

/// `wait NAME`: blocks until the process running `name` ends (a pidfd on the holder of its name),
/// then its status from its record. A VM no process runs: its last status, else what its records
/// say (stopped: 143; failed or lost: 124).
pub fn wait(host: &Host, name: &str) -> Result<i32> {
    host::check_name(name)?;
    let before = exit_record(host, name).map(|e| e.ident);
    loop {
        if host.name_locked(name) != Some(true) {
            return ended(host, name);
        }
        // Empty while a start writes it: read again.
        let Some(id) = host.name_holder(name)? else {
            std::thread::sleep(Duration::from_millis(20));
            continue;
        };
        return wait_for(host, name, &id, before);
    }
}

fn wait_for(host: &Host, name: &str, id: &Ident, before: Option<Ident>) -> Result<i32> {
    if let Some(fd) = host::PidFd::open(id)? {
        while !fd.wait(Duration::from_secs(1)) {}
    }
    // Written before it let the name go, under the name it had then (a rename moves it on).
    if let Some(e) = exit_of(host, name, id) {
        return Ok(e.code);
    }
    // Without one, what held the name was not a VM's process (an `rm` deciding), or it died
    // unrecorded. Only the one waited on is waited for: never a later one under the name.
    let unrecorded = || format!("vm {name}'s process ended without an exit status (killed with SIGKILL, or it crashed)");
    if host.name_locked(name) == Some(true) && host.name_holder(name)?.is_some_and(|h| h != *id) {
        bail!("{}; another process holds the name now", unrecorded());
    }
    if exit_record(host, name).map(|e| e.ident) != before {
        bail!("{}; another vm has run under the name since", unrecorded());
    }
    ended(host, name)
}

/// `id`'s exit record: under `name`, else under whatever name it had last (`rename`).
fn exit_of(host: &Host, name: &str, id: &Ident) -> Option<Exit> {
    if let Some(e) = exit_record(host, name).filter(|e| e.ident == *id) {
        return Some(e);
    }
    std::fs::read_dir(host.run.join("vms")).into_iter().flatten().flatten().find_map(|e| {
        let file = e.file_name().into_string().ok()?;
        let n = file.strip_suffix(".exit").filter(|n| !n.starts_with('.'))?;
        exit_record(host, n).filter(|e| e.ident == *id)
    })
}

/// The status of `name` with no process running it.
fn ended(host: &Host, name: &str) -> Result<i32> {
    let has = |ext: &str| host.has_record(name, ext);
    let record = exit_record(host, name);
    // A holder that died without unlocking left its identity: unless the record is its own, it
    // ended unrecorded (SIGKILL, a crash), and the record is an earlier instance's.
    let crashed = host.name_holder(name).ok().flatten().filter(|h| record.as_ref().is_none_or(|r| r.ident != *h));
    if crashed.is_some() && !has("failed") && !has("lost") {
        bail!("vm {name} ended without an exit status (killed with SIGKILL, or its process crashed); see {}", host.vms(name, "log")?.display());
    }
    match record {
        Some(r) if crashed.is_none() => Ok(r.code),
        _ if crashed.is_none() && host.is_suspended(name) => Ok(STOPPED),
        // Its command or app exited (`app::Exited`), its own record gone (a sweep's).
        _ if crashed.is_none() && has("exited") => Ok(crate::app::Exited::read(&host.vms(name, "exited")?)?.status),
        _ if has("failed") || has("lost") => Ok(crate::vmproc::DIED),
        _ => bail!("no vm named {name:?}"),
    }
}

/// Whether anything is left of `name` here: a process, a stopped VM, or a record of its end.
fn known(host: &Host, name: &str) -> bool {
    host.alive(name) || host.is_suspended(name) || ["failed", "lost", "exited"].iter().any(|ext| host.has_record(name, ext))
}

/// Writes to stdout: false once its reader is gone.
fn out(data: &[u8]) -> Result<bool> {
    let mut o = std::io::stdout().lock();
    match o.write_all(data).and_then(|()| o.flush()) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The last `n` lines of `files` one after another, each as long as it was (`usize::MAX`: all of them),
/// read back from their ends in blocks: no more than those lines (and a block) is read.
fn tail_files(files: &[(&std::fs::File, u64)], n: usize) -> Result<Vec<u8>> {
    let (mut blocks, mut breaks, mut last) = (Vec::new(), 0, None);
    'files: for &(f, len) in files.iter().rev() {
        let mut end = len;
        while end > 0 {
            // Breaks before the last line: a last newline ends it, it does not start one.
            if breaks - usize::from(last == Some(b'\n')) >= n {
                break 'files;
            }
            let start = end.saturating_sub(64 << 10);
            let mut b = vec![0; (end - start) as usize];
            match std::os::unix::fs::FileExt::read_exact_at(f, &mut b, start) {
                // Truncated meanwhile: what was read is all of it (following rewinds it).
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break 'files,
                r => r?,
            }
            last = last.or(b.last().copied());
            breaks += b.iter().filter(|&&c| c == b'\n').count();
            blocks.push(b);
            end = start;
        }
    }
    blocks.reverse();
    Ok(tail(&blocks.concat(), n).to_vec())
}

/// The last `n` lines of `data` (a last line without its newline counts).
pub fn tail(data: &[u8], n: usize) -> &[u8] {
    if n == 0 {
        return &data[data.len()..];
    }
    let body = data.strip_suffix(b"\n").unwrap_or(data);
    match body.iter().enumerate().rev().filter(|(_, &b)| b == b'\n').nth(n - 1) {
        Some((i, _)) => &data[i + 1..],
        None => data,
    }
}

/// How often `logs -f` looks for more.
const FOLLOW_EVERY: Duration = Duration::from_millis(200);

/// `logs [-f] [--tail N] NAME`: `NAME.log.1` (the log before its last rotation), then `NAME.log`.
/// Following, it reads on across rotations (it finishes the log rotated away, then starts on the
/// new one) and restarts (a resumed VM appends to its log); it ends once no process runs the VM and
/// it is not stopped (it exited, or `rm`, `kill`), as docker's does, or its reader is gone.
pub fn logs(host: &Host, name: &str, follow: bool, lines: Option<usize>) -> Result<()> {
    host::check_name(name)?;
    let (path, prev) = (host.vms(name, "log")?, host.vms(name, "log.1")?);
    let open = || std::fs::File::open(&path).ok();
    // Who held the name as it was first read (`removed`, where there is no birth time).
    let holder = host.name_holder(name).ok().flatten();
    // The current log first: one rotated meanwhile is then the previous one read below.
    let mut cur = open();
    let ino = |f: &std::fs::File| f.metadata().ok().map(|m| (m.dev(), m.ino()));
    let old = std::fs::File::open(&prev).ok().filter(|o| cur.as_ref().is_none_or(|c| ino(c) != ino(o)));
    let files: Vec<_> = [old.as_ref(), cur.as_ref()].into_iter().flatten().map(|f| (f, f.metadata().map_or(0, |m| m.len()))).collect();
    if cur.is_none() && files.iter().all(|&(_, len)| len == 0) && !known(host, name) {
        bail!("no vm named {name:?}");
    }
    let first = tail_files(&files, lines.unwrap_or(usize::MAX))?;
    // Followed from where that was read to.
    let end = files.last().map(|&(_, len)| len).filter(|_| cur.is_some());
    if let (Some(f), Some(end)) = (cur.as_mut(), end) {
        f.seek(std::io::SeekFrom::Start(end))?;
    }
    if !out(&first)? || !follow {
        return Ok(());
    }
    let mut buf = vec![0; 64 << 10];
    let mut drain = |f: &mut std::fs::File| -> Result<bool> {
        loop {
            match f.read(&mut buf)? {
                0 => return Ok(true),
                n if !out(&buf[..n])? => return Ok(false),
                _ => {}
            }
        }
    };
    let mut gone_since: Option<Instant> = None;
    loop {
        std::thread::sleep(FOLLOW_EVERY);
        if let Some(f) = cur.as_mut() {
            if !drain(f)? {
                return Ok(());
            }
            // Truncated by hand: from its start.
            if f.metadata().is_ok_and(|m| m.len() < f.stream_position().unwrap_or(0)) {
                f.rewind()?;
            }
        }
        // Removed with its VM (`rm`): whatever is at its path now is a later VM's.
        if cur.as_ref().is_some_and(|f| removed(f, &prev, || host.name_holder(name).ok().flatten() != holder)) {
            return Ok(());
        }
        // Rotated (or removed and made again): what was written before the rename is drained, then the new one.
        let now = std::fs::metadata(&path).ok().map(|m| (m.dev(), m.ino()));
        if now.is_some() && now != cur.as_ref().and_then(ino) {
            if let Some(f) = cur.as_mut() {
                if !drain(f)? {
                    return Ok(());
                }
            }
            let was = cur.as_ref().and_then(ino);
            cur = open();
            // Rotated twice since: the one in between is the previous log now, whole.
            if let Ok(mut between) = std::fs::File::open(&prev) {
                let b = ino(&between);
                if b.is_some() && b != was && b != cur.as_ref().and_then(ino) && !drain(&mut between)? {
                    return Ok(());
                }
            }
            continue;
        }
        // Ended for a while (not a restart's moment between its stop and start).
        match (host.alive(name) || host.is_suspended(name), gone_since) {
            (true, _) => gone_since = None,
            (false, None) => gone_since = Some(Instant::now()),
            (false, Some(t)) if t.elapsed() > Duration::from_secs(1) => return Ok(()),
            (false, Some(_)) => {}
        }
    }
}

/// Whether `cur` was unlinked by `rm`, not a second rotation. A rotation unlinks it only by
/// renaming over it the log made after it, which is `prev` (born before) from then on; `rm`
/// removes `prev` too, so any `prev` there now was made after (a later VM's). Where the file
/// system keeps no birth time: removed once the name has another holder than it had (`moved_on`).
fn removed(cur: &std::fs::File, prev: &Path, moved_on: impl FnOnce() -> bool) -> bool {
    let Ok(m) = cur.metadata() else { return false };
    if m.nlink() > 0 {
        return false;
    }
    let unlinked = std::time::UNIX_EPOCH + Duration::new(m.ctime().max(0) as u64, m.ctime_nsec().clamp(0, 999_999_999) as u32);
    by_rm(unlinked, std::fs::metadata(prev).map(|p| p.created()), moved_on)
}

/// `removed`'s decision, given when the log was unlinked and `prev`'s birth time (if it is there).
fn by_rm(unlinked: std::time::SystemTime, prev_born: std::io::Result<std::io::Result<std::time::SystemTime>>, moved_on: impl FnOnce() -> bool) -> bool {
    match prev_born {
        Err(_) => true,
        Ok(born) => born.map_or_else(|_| moved_on(), |born| born >= unlinked),
    }
}

/// `inspect NAME...`: an array of one object per VM, as docker prints: what `ps --json` says
/// of it, and its `config`.
pub fn inspect(host: &Host, paths: &template::Paths, names: &[String]) -> Result<()> {
    let vms = crate::vms(host);
    let (mut found, mut missing) = (Vec::new(), Vec::new());
    for n in names {
        match host::check_name(n).ok().and_then(|()| vms.iter().find(|v| v["name"] == n.as_str())) {
            Some(v) => found.push(described(host, paths, n, v.clone())),
            None => missing.push(n.as_str()),
        }
    }
    crate::print(json!(found))?;
    match missing.as_slice() {
        [] => Ok(()),
        [one] => bail!("no vm named {one:?}"),
        many => bail!("no vms named {}", many.iter().map(|n| format!("{n:?}")).collect::<Vec<_>>().join(", ")),
    }
}

fn described(host: &Host, paths: &template::Paths, name: &str, mut v: Value) -> Value {
    let running = !crate::stopped(&v);
    let path = |ext: &str| host.vms(name, ext).ok().map(|p| p.display().to_string());
    let mut config = json!({
        "image": v["template"].as_str().map(template::image_of),
        "template": v["template"],
        "template_id": v["template_id"],
        "ip": v["ip"],
        "vcpus": v["vcpus"],
        "cpus": v["cpus"],
        "max_mib": v["max_mib"],
        "cmd": v["cmd"],
        "log": path("log"),
        "socket": if running { json!(path("sock")) } else { Value::Null },
        "checkpoint": host.is_suspended(name).then(|| host.suspended(name).ok()).flatten(),
    });
    if let Some(id) = v["template_id"].as_str() {
        if let Some(i) = template::describe_id(paths, id) {
            for k in ["source", "digest", "app", "warm", "mem_mib"] {
                if !i[k].is_null() {
                    config[k] = i[k].clone();
                }
            }
        }
    }
    // Its ports and run settings: a running VM's registry entry has them, a stopped one's
    // checkpoint, an exited one's record (with what it ran, as `start` runs it again).
    config["ports"] = v.get("ports").cloned().unwrap_or_else(|| json!([]));
    config["run"] = v.get("spec").cloned().unwrap_or_else(|| json!({}));
    if let Some(spec) = host.is_suspended(name).then(|| host.suspended(name).ok().and_then(|d| crate::lifecycle::read_spec(&d).ok())).flatten() {
        config["run"] = json!(spec);
    }
    if let Some(e) = host.vms(name, "exited").ok().filter(|_| v["state"] == "exited").and_then(|p| crate::app::Exited::read(&p).ok()) {
        config["image"] = json!(template::image_of(&e.template));
        config["template"] = json!(e.template);
        (config["run"], config["cmd"]) = (json!(e.spec), json!(e.cmd));
        config["cpus"] = json!(e.resources.cpus);
        v["exit_code"] = json!(e.status);
    }
    // Its `-p` ports as its run settings keep them (`RunSpec`), else those bound now.
    if let Some(ports) = config["run"].get("ports").filter(|p| p.as_array().is_some_and(|a| !a.is_empty())).cloned() {
        config["ports"] = ports;
    }
    if !running {
        if let Some(e) = exit_record(host, name) {
            v["exit_code"] = json!(e.code);
        }
    }
    v["config"] = config;
    v
}

/// `rename OLD NEW`: a running VM's process renames itself (`Proc::rename`); a stopped one is
/// renamed here, holding both names.
pub fn rename(host: &Host, from: &str, to: &str) -> Result<()> {
    host::check_name(from)?;
    host::check_new_name(to)?;
    if from == to {
        bail!("vm {from} is named {to} already");
    }
    if host.alive(from) {
        crate::vmproc::call(host, from, json!({"op": "rename", "to": to}), Some(Instant::now() + Duration::from_secs(30)))?;
        return crate::output(format_args!("{to}\n"));
    }
    rename_stopped(host, from, to)?;
    crate::output(format_args!("{to}\n"))
}

/// A suspended (or quarantined) VM: its checkpoint directory, the claim on its address (which a
/// sweep reads by the name: `Host::held`), its logs and its exit status move to `to`. Both names
/// are held throughout, so no start of either runs meanwhile; the directory and the claim move
/// together under the host lock, so no sweep or claim sees one moved without the other.
fn rename_stopped(host: &Host, from: &str, to: &str) -> Result<()> {
    if !host.is_suspended(from) && host.has_record(from, "exited") {
        return rename_exited(host, from, to);
    }
    if !host.is_suspended(from) {
        return Err(match ["failed", "lost"].iter().find(|ext| host.has_record(from, ext)) {
            Some(ext) => format!("vm {from} is {ext}: only a running, stopped or exited vm can be renamed").into(),
            None => format!("no vm named {from:?}").into(),
        });
    }
    let _from = take_rename_name(host, from)?;
    // Taking the name removed what an interrupted suspend, resume or discard left.
    if !host.is_suspended(from) {
        bail!("no vm named {from:?}");
    }
    let _to = host.take_unrecorded_name(to)?;
    let (dir, dest) = (host.suspended(from)?, host.suspended(to)?);
    let ip = crate::checkpoint::read_manifest(&dir).ok().map(|m| m.ip);
    {
        let l = host.lock()?;
        // A crash past the move (before the claim follows) leaves the journal: the claim stays
        // held by the directory at `to`, and the next to take `to` moves it (`Host::finish_rename`).
        let (journal, parent) = (host.rename_journal(to)?, host.state.join("suspended"));
        // Readers of the stopped VMs' records (`host::recorded_template_users`) see it at one name or the other.
        let _moves = host::suspended_moves(&host.state, libc::LOCK_EX)?;
        crate::util::write_file(&parent, &journal.file_name().unwrap_or_default().to_string_lossy(), from.as_bytes(), true)?;
        let moved = std::fs::rename(&dir, &dest).map_err(|e| format!("renaming {} to {}: {e}", dir.display(), dest.display()));
        if let Err(e) = moved.and_then(|()| crate::util::sync_dir(&parent).map_err(|e| format!("syncing {}: {e}", parent.display()))) {
            let _ = crate::util::unlink_durably(&journal);
            return Err(e.into());
        }
        if let Some(ip) = ip {
            if let Err(e) = host.rename_holder(&l, ip, from, to, None) {
                // Moved back: the claim still names `from`.
                let back = std::fs::rename(&dest, &dir).and_then(|()| crate::util::sync_dir(&parent));
                if back.is_ok() {
                    let _ = crate::util::unlink_durably(&journal);
                }
                return Err(format!(
                    "vm {from}: moving the claim on {ip} to {to}: {e}{}",
                    back.err().map_or(String::new(), |b| format!("; moving it back: {b}"))
                )
                .into());
            }
        }
        crate::util::unlink_durably(&journal)?;
    }
    move_records(host, from, to)
}

/// An exited VM (`app::Exited`): no checkpoint or address claim, only its record (what `start`
/// runs again), logs and exit status move, both names held.
fn rename_exited(host: &Host, from: &str, to: &str) -> Result<()> {
    let _from = take_rename_name(host, from)?;
    if !host.has_record(from, "exited") || host.is_suspended(from) {
        bail!("vm {from} changed meanwhile: try again");
    }
    // Refuses a `failed`, `lost` or `exited` record of `to`, and a stopped vm of it.
    let _to = host.take_unrecorded_name(to)?;
    move_records(host, from, to)
}

/// Hold the old name, reporting a concurrent start consistently for stopped and exited VMs.
fn take_rename_name(host: &Host, from: &str) -> Result<host::NameLock> {
    host.take_name(from, true).map_err(|e| match host.alive(from) {
        true => format!("vm {from} started meanwhile: try again").into(),
        false => e,
    })
}

/// Its logs and exit records, under the logs lock shared, as a
/// start opens a log: a sweep never decides on a log midway.
fn move_records(host: &Host, from: &str, to: &str) -> Result<()> {
    let _logs = host.logs_lock(libc::LOCK_SH)?;
    for ext in ["log", "log.1", "exit", "exited"] {
        let (a, b) = (host.vms(from, ext)?, host.vms(to, ext)?);
        match std::fs::rename(&a, &b) {
            Ok(()) => {}
            // None to move: none of an earlier vm of the new name stays either.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => drop(std::fs::remove_file(&b)),
            Err(e) => bail!("renaming {} to {}: {e}", a.display(), b.display()),
        }
    }
    Ok(())
}

/// Every name this process's VM had, in order: a VM's own main command reattaches by its
/// current name (`renamed`).
static NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The name `name` has now, if this process's VM was renamed from it.
pub fn renamed(name: &str) -> String {
    let names = NAMES.lock().unwrap_or_else(|e| e.into_inner());
    match names.iter().position(|n| n == name) {
        Some(_) => names.last().cloned().unwrap_or_else(|| name.into()),
        None => name.into(),
    }
}

/// How long a running VM's rename waits for `op`.
const RENAME_WAIT: Duration = Duration::from_secs(2);

impl Proc {
    /// `rename` of this running VM, holding `op` (refused at once while a checkpoint, migration
    /// or suspend has it). Not while a migration's outcome or an arrival's pages are pending,
    /// nor once it is ending: their records name the VM. The new name is taken first, so its
    /// claim on the address (read by the name, `Host::held`) is the VM's under either name.
    pub fn rename(&self, to: &str) -> Result<Value> {
        let vm = self.vm();
        // A moment's holder (a start finishing, a resize) is waited out; a checkpoint, migration or
        // suspend is refused, not waited for.
        let deadline = Instant::now() + RENAME_WAIT;
        let _op = loop {
            match self.op_now() {
                Some(op) => break op,
                None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                None => bail!("vm {} is busy (a checkpoint, migration or suspend is under way): try again once it is done", vm.name),
            }
        };
        self.not_destroyed()?;
        let from = self.name();
        host::check_new_name(to)?;
        if from == to {
            bail!("vm {from} is named {to} already");
        }
        match vm.state() {
            State::Running | State::Paused => {}
            s => bail!("vm {from} is {}: not renaming it", s.name()),
        }
        if *self.suspending.lock().unwrap() != Suspend::Idle {
            bail!("vm {from} is being stopped: not renaming it");
        }
        if self.consumed.lock().unwrap().is_some() {
            bail!("vm {from} is still paging in its checkpoint (it was started from it): try again once it is all here");
        }
        if self.arrived.lock().unwrap().is_some() {
            bail!("vm {from} is still arriving by migration (its memory is still coming): try again once it is all here");
        }
        if self.reconciling.lock().unwrap().is_some() || self.is_leaving() {
            bail!("vm {from} is the source of a migration whose outcome is pending: not renaming it");
        }
        let new = self.host.take_unrecorded_name(to)?;
        let (sock, new_sock) = (self.host.sock(&from)?, self.host.sock(to)?);
        std::fs::rename(&sock, &new_sock).map_err(|e| format!("vm {from}: moving its control socket: {e}"))?;
        let moved = (|| -> Result<()> {
            let l = self.host.lock()?;
            let mut addr = self.addr.lock().unwrap();
            if let Some(a) = addr.as_mut() {
                self.host.rename_holder(&l, a.ip, &from, to, Some(&self.ident))?;
                a.rename(to);
            }
            Ok(())
        })();
        if let Err(e) = moved {
            let _ = std::fs::rename(&new_sock, &sock);
            return Err(format!("vm {from}: moving its address's claim: {e}").into());
        }
        // Its output goes to the new log from here: none is written to the old one in between.
        let (log, new_log) = (self.host.vms(&from, "log")?, self.host.vms(to, "log")?);
        if let Err(e) = crate::util::output::moved(&log, &new_log, || move_records(&self.host, &from, to).map_err(std::io::Error::other)) {
            crate::log!("vm {from}: moving its log to {}: {e}", new_log.display());
        }
        {
            let mut names = NAMES.lock().unwrap_or_else(|e| e.into_inner());
            if names.is_empty() {
                names.push(from.clone());
            }
            names.push(to.into());
        }
        vm.name.set(to);
        let old = self.name.lock().unwrap().replace(new);
        self.publish();
        // Its registry entry and lock go (its socket moved already).
        drop(old);
        if vm.state() == State::Running {
            vm.set_hostname(to);
        }
        crate::info!("vm {from}: renamed {to}");
        Ok(json!({"name": to, "was": from}))
    }
}

/// `ps --filter key=value`: the same key given again is either value, different keys all of them
/// (as docker does).
#[derive(Debug, Default)]
pub struct Filters(Vec<(String, Vec<String>)>);

const FILTER_KEYS: [&str; 4] = ["name", "status", "image", "ip"];

impl Filters {
    pub fn parse(given: &[String]) -> Result<Filters> {
        let mut f = Filters::default();
        for g in given {
            let Some((k, v)) = g.split_once('=') else {
                bail!("bad --filter {g:?}: give key=value (key: {})", FILTER_KEYS.join(", "));
            };
            let k = k.trim().to_ascii_lowercase();
            if !FILTER_KEYS.contains(&k.as_str()) {
                bail!("bad --filter {g:?}: no key {k:?} (key: {})", FILTER_KEYS.join(", "));
            }
            match f.0.iter_mut().find(|(key, _)| *key == k) {
                Some((_, vs)) => vs.push(v.into()),
                None => f.0.push((k, vec![v.into()])),
            }
        }
        Ok(f)
    }

    /// A status filter lists stopped VMs too, without `-a`.
    pub fn has_status(&self) -> bool {
        self.0.iter().any(|(k, _)| k == "status")
    }

    pub fn matches(&self, v: &Value) -> bool {
        let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
        let image = v["template"].as_str().map(template::image_of).unwrap_or_default();
        self.0.iter().all(|(k, vs)| {
            vs.iter().any(|want| match k.as_str() {
                // A part of the name, as docker's.
                "name" => s("name").contains(want.as_str()),
                // `stopped`: any state no process runs.
                "status" => s("state") == *want || (want == "stopped" && crate::stopped(v)),
                "image" => {
                    let want_image = template::name_of(want).map(|n| template::image_of(&n));
                    image == *want || s("template") == *want || want_image.is_ok_and(|w| w == image)
                }
                "ip" => s("ip") == *want,
                _ => false,
            })
        })
    }
}

/// `ps --format`: `json` (an object per line, as docker's), `table` (the default listing), or a
/// template: text with `{{.Field}}`s (and `{{json .}}`, the whole object), `\t` and `\n` escapes,
/// and `table ` in front for a header and aligned columns.
#[derive(Debug, PartialEq)]
pub enum Format {
    Json,
    Template { table: bool, parts: Vec<Part>, fields: Fields },
}

/// A template's field names, and the keys of the JSON objects they name.
pub type Fields = &'static [(&'static str, &'static str)];

#[derive(Debug, PartialEq)]
pub enum Part {
    Text(String),
    Field(&'static str),
    Whole,
}

/// The fields a template may name, and what `ps --json` calls them.
const FIELDS: [(&str, &str); 14] = [
    ("Name", "name"),
    ("IP", "ip"),
    ("Image", "image"),
    ("State", "state"),
    ("Status", "state"),
    ("PID", "pid"),
    ("CPUs", "cpus"),
    ("VCPUs", "vcpus"),
    ("RSS", "rss_mib"),
    ("MaxMiB", "max_mib"),
    ("Starved", "starved"),
    ("Template", "template"),
    ("TemplateID", "template_id"),
    ("Error", "error"),
];

impl Format {
    pub fn parse(f: &str) -> Result<Format> {
        Format::parse_with(f, &FIELDS)
    }

    pub fn parse_with(f: &str, fields: Fields) -> Result<Format> {
        if f.trim() == "json" {
            return Ok(Format::Json);
        }
        let (table, body) = match f.strip_prefix("table ") {
            Some(rest) => (true, rest),
            None => (false, f),
        };
        let mut parts = Vec::new();
        let mut rest = body;
        while let Some(at) = rest.find("{{") {
            if at > 0 {
                parts.push(Part::Text(unescape(&rest[..at])));
            }
            let end = rest[at..].find("}}").ok_or_else(|| format!("bad --format {f:?}: an unclosed {{{{"))? + at;
            let action = rest[at + 2..end].trim();
            parts.push(match action {
                "json ." => Part::Whole,
                a => match a.strip_prefix('.').and_then(|field| fields.iter().find(|(n, _)| n.eq_ignore_ascii_case(field))) {
                    Some((name, _)) => Part::Field(name),
                    None => bail!(
                        "bad --format {f:?}: {{{{{a}}}}} is not a field (fields: {}, or {{{{json .}}}})",
                        fields.iter().map(|(n, _)| format!(".{n}")).collect::<Vec<_>>().join(" ")
                    ),
                },
            });
            rest = &rest[end + 2..];
        }
        if !rest.is_empty() {
            parts.push(Part::Text(unescape(rest)));
        }
        Ok(Format::Template { table, parts, fields })
    }

    /// One line per VM.
    pub fn render(&self, vms: &[Value]) -> Result<String> {
        match self {
            Format::Json => Ok(vms.iter().map(|v| Ok(serde_json::to_string(v)? + "\n")).collect::<Result<String>>()?),
            Format::Template { table, parts, fields } => {
                let line = |v: Option<&Value>| -> Result<String> {
                    let mut s = String::new();
                    for p in parts {
                        match (p, v) {
                            (Part::Text(t), _) => s.push_str(t),
                            (Part::Field(name), None) => s.push_str(&name.to_ascii_uppercase()),
                            (Part::Field(name), Some(v)) => s.push_str(&field_in(v, name, fields)),
                            (Part::Whole, None) => s.push_str("JSON"),
                            (Part::Whole, Some(v)) => s.push_str(&serde_json::to_string(v)?),
                        }
                    }
                    Ok(s + "\n")
                };
                let mut text = String::new();
                if *table {
                    text += &line(None)?;
                }
                for v in vms {
                    text += &line(Some(v))?;
                }
                Ok(if *table { align(&text) } else { text })
            }
        }
    }
}

/// A row's field as `ps` shows it.
pub fn field(v: &Value, name: &str) -> String {
    field_in(v, name, &FIELDS)
}

fn field_in(v: &Value, name: &str, fields: Fields) -> String {
    let key = fields.iter().find(|(n, _)| *n == name).map_or(name, |(_, k)| k);
    match key {
        "image" => v["template"].as_str().map(template::image_of).unwrap_or_default(),
        // The --cpus cap, else its vCPUs.
        "cpus" if v["cpus"].is_null() => field(v, "VCPUs"),
        "starved" => if v["starved"] == true { "yes" } else { "" }.into(),
        k => match &v[k] {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        },
    }
}

fn unescape(s: &str) -> String {
    s.replace("\\t", "\t").replace("\\n", "\n")
}

/// Tab-separated cells padded into columns (three spaces apart), as docker's `table` does.
fn align(text: &str) -> String {
    let rows: Vec<Vec<&str>> = text.lines().map(|l| l.split('\t').collect()).collect();
    let mut widths: Vec<usize> = Vec::new();
    for r in &rows {
        for (i, c) in r.iter().enumerate().take(r.len().saturating_sub(1)) {
            let w = c.chars().count();
            match widths.get_mut(i) {
                Some(m) => *m = (*m).max(w),
                None => widths.push(w),
            }
        }
    }
    let mut out = String::new();
    for r in rows {
        let last = r.len().saturating_sub(1);
        for (i, c) in r.iter().enumerate() {
            out.push_str(c);
            if i < last {
                out.push_str(&" ".repeat(widths[i] - c.chars().count() + 3));
            }
        }
        out.push('\n');
    }
    out
}

/// What gc keeps: an exit record of a name with nothing else left, once it is `ttl` old, goes.
pub fn stale_exit(host: &Host, name: &str, path: &Path, ttl: Duration) -> bool {
    let old = std::fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|a| a > ttl);
    let logs = ["log", "log.1"].iter().any(|ext| host.has_record(name, ext));
    let exited = host.has_record(name, "exited");
    old && host.holder_gone(name) && !host.suspended(name).is_ok_and(|d| d.exists()) && !logs && !exited
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn row(name: &str, state: &str, ip: &str, template: &str) -> Value {
        json!({"name": name, "state": state, "ip": ip, "template": template, "vcpus": 2, "pid": 42, "rss_mib": 10, "max_mib": 512, "starved": false})
    }

    #[test]
    fn tail_takes_the_last_lines() {
        assert_eq!(tail(b"a\nb\nc\n", 2), b"b\nc\n");
        assert_eq!(tail(b"a\nb\nc", 2), b"b\nc");
        assert_eq!(tail(b"a\nb\n", 5), b"a\nb\n");
        assert_eq!(tail(b"a\nb\n", 0), b"");
        assert_eq!(tail(b"", 3), b"");
        assert_eq!(tail(b"one", 1), b"one");
    }

    #[test]
    fn tail_files_reads_back_across_blocks_and_files() {
        let root = TempDir::new("tail-files");
        let mut data = Vec::new();
        for i in 0..3000 {
            data.extend(format!("line {i} {}\n", "x".repeat(i % 97)).as_bytes());
        }
        data.extend(vec![b'y'; 100 << 10]);
        data.extend(b"\nlast");
        for split in [0, 1, 70_000, data.len() - 3, data.len()] {
            let (a, b) = (root.join("a"), root.join("b"));
            std::fs::write(&a, &data[..split]).unwrap();
            std::fs::write(&b, &data[split..]).unwrap();
            let (a, b) = (std::fs::File::open(a).unwrap(), std::fs::File::open(b).unwrap());
            let files = [(&a, split as u64), (&b, (data.len() - split) as u64)];
            for n in [0, 1, 2, 3, 50, 2999, 3001, 3002, 5000, usize::MAX] {
                assert_eq!(tail_files(&files, n).unwrap(), tail(&data, n), "split {split}, {n} lines");
            }
        }
        // Each only as long as it was: what was written since is the follower's.
        std::fs::write(root.join("c"), b"a\nb\nc\n").unwrap();
        let f = std::fs::File::open(root.join("c")).unwrap();
        assert_eq!(tail_files(&[(&f, 3)], 5).unwrap(), b"a\nb");
        // Shorter than it was: no error.
        assert_eq!(tail_files(&[(&f, 1 << 20)], 5).unwrap(), b"");
    }

    #[test]
    fn logs_follow_ends_for_a_vm_that_exited() {
        let root = TempDir::new("logs-exited");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        std::fs::write(host.vms("job", "log").unwrap(), b"done\n").unwrap();
        let rec = crate::app::Exited::new(3, "t".into(), None, Default::default(), Default::default(), 0);
        crate::host::write_record(&host.vms("job", "exited").unwrap(), &serde_json::to_vec(&rec).unwrap()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(logs(&host, "job", true, Some(1)).is_ok()));
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)), Ok(true), "logs -f of an exited vm ends");
    }

    #[test]
    fn logs_follow_of_a_removed_vm_ends_before_its_name_runs_again() {
        let root = TempDir::new("logs-removed");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let name = host.take_name("job", false).unwrap();
        std::fs::write(host.vms("job", "log").unwrap(), b"old\n").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let follower = host.clone();
        std::thread::spawn(move || tx.send(logs(&follower, "job", true, Some(1)).is_ok()));
        std::thread::sleep(FOLLOW_EVERY * 2);
        // `rm -f`: the VM ends, its logs go; a new VM of the name starts a fresh log soon after.
        drop(name);
        std::fs::remove_file(host.vms("job", "log").unwrap()).unwrap();
        let _again = host.take_name("job", false).unwrap();
        std::fs::write(host.vms("job", "log").unwrap(), b"new\n").unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)), Ok(true), "logs -f of a removed vm ends");
    }

    #[test]
    fn logs_follow_reads_on_across_two_rotations_and_a_new_holder() {
        let root = TempDir::new("logs-rotated-twice");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let (log, prev) = (host.vms("job", "log").unwrap(), host.vms("job", "log.1").unwrap());
        let name = host.take_name("job", false).unwrap();
        std::fs::write(&log, b"first\n").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let follower = host.clone();
        std::thread::spawn(move || tx.send(logs(&follower, "job", true, Some(1)).is_ok()));
        std::thread::sleep(FOLLOW_EVERY * 2);
        // Rotated twice (the follower may see either), and the name passes to a resume's process.
        std::fs::rename(&log, &prev).unwrap();
        std::fs::write(&log, b"between\n").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::rename(&log, &prev).unwrap();
        std::fs::write(&log, b"third\n").unwrap();
        let other = Ident { pid: 1, start: 1, boot: host::boot_id().into() };
        std::fs::write(host.vms("job", "lock").unwrap(), serde_json::to_vec(&other).unwrap()).unwrap();
        assert!(rx.recv_timeout(FOLLOW_EVERY * 4).is_err(), "a rotated log is followed on, not taken for a removed one");
        drop(name);
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)), Ok(true), "and ends with its vm");
    }

    #[test]
    fn a_removed_log_is_told_from_a_rotated_one() {
        let at = std::time::SystemTime::now();
        let (before, after) = (at - Duration::from_millis(5), at + Duration::from_millis(5));
        let unsupported = || std::io::Error::from(std::io::ErrorKind::Unsupported);
        assert!(by_rm(at, Err(std::io::ErrorKind::NotFound.into()), || false), "no log.1: rm took it");
        assert!(!by_rm(at, Ok(Ok(before)), || true), "log.1 born before: a second rotation");
        assert!(by_rm(at, Ok(Ok(after)), || false), "log.1 born after: a later vm's");
        assert!(by_rm(at, Ok(Ok(at)), || false), "born then: a later vm's");
        // No birth time: the name's holder decides.
        assert!(!by_rm(at, Ok(Err(unsupported())), || false), "the same holder: a rotation");
        assert!(by_rm(at, Ok(Err(unsupported())), || true), "another holder: removed");
    }

    #[test]
    fn filters_and_within_a_key_or_across_keys() {
        let web = row("web-1", "running", "10.0.0.2", "nginx_latest");
        let db = row("db", "suspended", "10.0.0.3", "postgres_16");
        let f = |given: &[&str]| Filters::parse(&given.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        assert!(f(&["name=web"]).matches(&web) && !f(&["name=web"]).matches(&db), "a part of the name");
        assert!(f(&["name=web", "name=db"]).matches(&db), "either value of one key");
        assert!(!f(&["name=web", "status=suspended"]).matches(&web), "both keys");
        assert!(f(&["status=stopped"]).matches(&db) && !f(&["status=stopped"]).matches(&web), "stopped: any state no process runs");
        let job = json!({"name": "job", "state": "exited", "status": 3, "template": "ci"});
        assert!(f(&["status=exited"]).matches(&job) && !f(&["status=exited"]).matches(&db), "exited: that state alone");
        assert!(f(&["status=stopped"]).matches(&job));
        assert!(f(&["ip=10.0.0.3"]).matches(&db) && !f(&["ip=10.0.0.30"]).matches(&db));
        assert!(f(&["status=running"]).has_status() && !f(&["ip=1.2.3.4"]).has_status());
        for bad in ["name", "color=red", ""] {
            assert!(Filters::parse(&[bad.to_string()]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn image_filters_take_the_image_as_given_or_its_template() {
        let name = template::name_of("nginx").unwrap();
        let web = row("web", "running", "10.0.0.2", &name);
        let image = template::image_of(&name);
        for given in ["nginx", image.as_str(), name.as_str()] {
            assert!(Filters::parse(&[format!("image={given}")]).unwrap().matches(&web), "{given}");
        }
        assert!(!Filters::parse(&["image=redis".into()]).unwrap().matches(&web));
    }

    #[test]
    fn templates_name_fields_and_escapes() {
        let vms = [row("web", "running", "10.0.0.2", "nginx_latest"), json!({"name": "db", "state": "failed", "error": "died"})];
        let f = Format::parse("{{.Name}}\\t{{ .IP }}").unwrap();
        assert_eq!(f.render(&vms).unwrap(), "web\t10.0.0.2\ndb\t\n");
        assert_eq!(Format::parse("{{.name}}:{{.cpus}}").unwrap().render(&vms[..1]).unwrap(), "web:2\n", "any case; CPUs falls back to vCPUs");
        assert_eq!(Format::parse("{{.Status}} {{.Error}}").unwrap().render(&vms[1..]).unwrap(), "failed died\n");
        let table = Format::parse("table {{.Name}}\\t{{.State}}").unwrap().render(&vms).unwrap();
        assert_eq!(table, "NAME   STATE\nweb    running\ndb     failed\n");
        assert_eq!(Format::parse("json").unwrap().render(&vms[1..]).unwrap(), "{\"error\":\"died\",\"name\":\"db\",\"state\":\"failed\"}\n");
        assert_eq!(Format::parse("{{json .}}").unwrap().render(&vms[1..]).unwrap(), "{\"error\":\"died\",\"name\":\"db\",\"state\":\"failed\"}\n");
        assert!(Format::parse("{{.Nope}}").is_err());
        assert!(Format::parse("{{.Name").is_err());
    }

    fn host(tag: &str) -> (TempDir, Host) {
        let d = TempDir::new(&format!("containers-{tag}"));
        let host = Host::open(&d.join("state"), &d.join("run")).unwrap();
        (d, host)
    }

    #[test]
    fn wait_reads_a_gone_vms_record_or_its_state() {
        let (_d, host) = host("wait");
        assert!(wait(&host, "nobody").unwrap_err().to_string().contains("no vm named"));
        let gone = Ident { pid: 1, start: 1, boot: "another boot".into() };
        record_exit(&host, "web", &gone, 3);
        assert_eq!(wait(&host, "web").unwrap(), 3, "its record");
        std::fs::write(host.vms("db", "failed").unwrap(), "died").unwrap();
        assert_eq!(wait(&host, "db").unwrap(), crate::vmproc::DIED);
        // A holder that died holding the name, unrecorded: the record is an earlier instance's.
        std::fs::create_dir_all(host.vms("web", "lock").unwrap().parent().unwrap()).unwrap();
        let crashed = Ident { pid: 2, start: 2, boot: "another boot".into() };
        std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(&crashed).unwrap()).unwrap();
        assert!(wait(&host, "web").unwrap_err().to_string().contains("without an exit status"));
        std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(&gone).unwrap()).unwrap();
        assert_eq!(wait(&host, "web").unwrap(), 3, "the record is the dead holder's own");
        forget_exit(&host, "web");
        assert!(exit_record(&host, "web").is_none());
    }

    #[test]
    fn wait_blocks_until_the_holder_ends_and_takes_its_record() {
        use crate::test_util::{asleep, sleeper, wait_until, JoinWithin, WAIT};

        let (_d, host) = host("wait-live");
        // Held here, as a VM process holds its name: the holder it names is a child, waited on by its pidfd.
        let lock = host.take_name("job", false).unwrap();
        let mut child = sleeper(60);
        let id = Ident::of(child.id()).unwrap();
        std::fs::write(host.vms("job", "lock").unwrap(), serde_json::to_vec(&id).unwrap()).unwrap();
        record_exit(&host, "job", &Ident { pid: 1, start: 1, boot: "b".into() }, 1);
        let h = host.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            tx.send(unsafe { libc::gettid() }).unwrap();
            wait(&h, "job")
        });
        let tid = rx.recv_timeout(WAIT).unwrap();
        // With a populated lock record, the waiter blocks on the holder's pidfd.
        wait_until("the waiter to block on the holder", || {
            assert!(!waiter.is_finished(), "an earlier instance's record is not this one's");
            asleep(tid)
        });
        record_exit(&host, "job", &id, 5);
        assert!(!waiter.is_finished(), "it must wait for the holder's process even with its exit record present");
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(waiter.join_within().unwrap().unwrap(), 5);
        drop(lock);
    }

    #[test]
    fn wait_finds_a_renamed_record_when_the_holder_is_already_gone() {
        let (_d, host) = host("wait-renamed-gone");
        let _lock = host.take_name("job", false).unwrap();
        let id = Ident { pid: 1, start: 1, boot: "another boot".into() };
        std::fs::write(host.vms("job", "lock").unwrap(), serde_json::to_vec(&id).unwrap()).unwrap();
        record_exit(&host, "job-new", &id, 143);
        assert_eq!(wait(&host, "job").unwrap(), 143);
    }

    #[test]
    fn wait_never_takes_a_later_holder_or_its_status() {
        let (_d, host) = host("wait-later");
        let lock = host.take_name("job", false).unwrap();
        let path = host.vms("job", "lock").unwrap();
        let spawn = || {
            let c = std::process::Command::new("sleep").arg("30").spawn().unwrap();
            let id = Ident::of(c.id()).unwrap();
            (c, id)
        };
        // Select the holder before spawning the waiter; scheduling cannot select a later one.
        let waiter = || {
            let (h, id, before) = (host.clone(), host.name_holder("job").unwrap().unwrap(), exit_record(&host, "job").map(|e| e.ident));
            std::thread::spawn(move || wait_for(&h, "job", &id, before))
        };
        // Its holder dies unrecorded and another holds the name by then: an error, not a wait on it.
        let ((mut first, id), (mut later, later_id)) = (spawn(), spawn());
        std::fs::write(&path, serde_json::to_vec(&id).unwrap()).unwrap();
        let waiting = waiter();
        std::fs::write(&path, serde_json::to_vec(&later_id).unwrap()).unwrap();
        first.kill().unwrap();
        first.wait().unwrap();
        let e = waiting.join().unwrap().unwrap_err().to_string();
        assert!(e.contains("without an exit status") && e.contains("holds the name now"), "{e}");
        later.kill().unwrap();
        later.wait().unwrap();
        // A later instance's record (it ran and ended meanwhile) is not the one waited on.
        let (mut again, id) = spawn();
        std::fs::write(&path, serde_json::to_vec(&id).unwrap()).unwrap();
        let waiting = waiter();
        record_exit(&host, "job", &later_id, 0);
        again.kill().unwrap();
        again.wait().unwrap();
        let e = waiting.join().unwrap().unwrap_err().to_string();
        assert!(e.contains("another vm has run under the name since"), "{e}");
        // Renamed while waited on: its record is found under its new name.
        let (mut renamed, id) = spawn();
        std::fs::write(&path, serde_json::to_vec(&id).unwrap()).unwrap();
        let waiting = waiter();
        record_exit(&host, "job-new", &id, 143);
        renamed.kill().unwrap();
        renamed.wait().unwrap();
        assert_eq!(waiting.join().unwrap().unwrap(), 143);
        drop(lock);
    }

    #[test]
    fn a_rename_cut_short_keeps_the_claim_and_is_finished_by_the_next_taker() {
        let (_d, host) = host("rename-journal");
        let ip: std::net::Ipv4Addr = "10.0.0.7".parse().unwrap();
        suspended_vm(&host, "old", "10.0.0.7");
        // Moved, the claim not yet: as a renamer killed between the two leaves it.
        std::fs::write(host.rename_journal("new").unwrap(), "old").unwrap();
        std::fs::rename(host.suspended("old").unwrap(), host.suspended("new").unwrap()).unwrap();
        let l = host.lock().unwrap();
        assert_eq!(host.holder(&l, ip).unwrap().as_deref(), Some("old"), "still held: the journal names where it went");
        drop(l);
        drop(host.take_name("new", true).unwrap());
        let l = host.lock().unwrap();
        assert_eq!(host.holder(&l, ip).unwrap().as_deref(), Some("new"));
        drop(l);
        assert!(!host.rename_journal("new").unwrap().exists() && host.is_suspended("new"));
        // A journal of a rename that never moved anything is only forgotten.
        std::fs::write(host.rename_journal("other").unwrap(), "new").unwrap();
        drop(host.take_name("other", false).unwrap());
        assert!(!host.rename_journal("other").unwrap().exists() && host.is_suspended("new"));
    }

    #[test]
    fn a_new_name_with_a_record_is_refused_and_the_record_kept() {
        const CHILD: &str = "FLEXVM_TEST_UNRECORDED_NAME";
        if std::env::var_os(CHILD).is_none() {
            // A refused name closes its flock without an explicit unlock. Another
            // test's fork can inherit that descriptor until exec, making alive()
            // briefly true even though these Host directories are unique.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "containers::tests::a_new_name_with_a_record_is_refused_and_the_record_kept"])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "unrecorded name child: {status}");
            return;
        }
        let (_d, host) = host("unrecorded");
        std::fs::write(host.vms("db", "lost").unwrap(), "rebooted").unwrap();
        assert!(host.take_unrecorded_name("db").err().unwrap().to_string().contains("lost"));
        assert!(host.vms("db", "lost").unwrap().exists() && !host.alive("db"));
        drop(host.take_unrecorded_name("free").unwrap());
    }

    /// A suspended VM `name` at `ip`, its claim held by a process gone (as a suspend leaves it).
    fn suspended_vm(host: &Host, name: &str, ip: &str) {
        let dir = host.suspended(name).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let body = serde_json::to_vec(&json!({
            "format": crate::checkpoint::FORMAT, "created_unix_ms": 0, "name": name, "ip": ip,
            "template": "tpl", "template_id": "id", "saved_msrs": [], "saved_tsc_khz": 2000000, "vcpus": 1, "mem_mib": 1, "max_mib": 1,
            "hotplug_mib": 0, "guest_pages": 256, "data_pages": 0, "zero_pages": 0, "files": {}
        }))
        .unwrap();
        let mut hash = template::Hash::new();
        hash.update(&body);
        std::fs::write(dir.join("manifest.json"), [format!("{}\n", hash.finish()).as_bytes(), &body].concat()).unwrap();
        std::fs::write(dir.join("GEN"), "1").unwrap();
        let gone = Ident { pid: 1, start: 1, boot: "another boot".into() };
        let a = host::Addr { seen: 1, held: 1, holder: Some(name.into()), holder_id: Some(gone), ..host::Addr::default() };
        std::fs::create_dir_all(host.state.join("addrs")).unwrap();
        host::store(&host.state.join("addrs").join(ip), &a, true).unwrap();
    }

    #[test]
    fn a_stopped_vm_is_renamed_with_its_checkpoint_claim_and_logs() {
        let (_d, host) = host("rename");
        let dir = host.suspended("old").unwrap();
        suspended_vm(&host, "old", "10.0.0.9");
        std::fs::write(host.vms("old", "log").unwrap(), "hello\n").unwrap();
        std::fs::write(host.vms("new", "log.1").unwrap(), "an earlier vm's\n").unwrap();
        record_exit(&host, "old", &Ident { pid: 1, start: 1, boot: "b".into() }, STOPPED);
        std::fs::write(host.vms("taken", "failed").unwrap(), "died").unwrap();
        assert!(rename_stopped(&host, "old", "taken").unwrap_err().to_string().contains("taken"));
        rename_stopped(&host, "old", "new").unwrap();
        assert!(!dir.exists() && host.is_suspended("new"));
        assert_eq!(std::fs::read_to_string(host.vms("new", "log").unwrap()).unwrap(), "hello\n");
        assert!(!host.vms("new", "log.1").unwrap().exists(), "the earlier vm's log does not pass for its");
        assert_eq!(exit_record(&host, "new").unwrap().code, STOPPED);
        let l = host.lock().unwrap();
        assert_eq!(host.holder(&l, "10.0.0.9".parse().unwrap()).unwrap().as_deref(), Some("new"));
        drop(l);
        assert!(rename_stopped(&host, "old", "other").unwrap_err().to_string().contains("no vm named"));
        assert!(rename_stopped(&host, "taken", "other").unwrap_err().to_string().contains("failed"));
    }

    /// An exited VM's record (`app::Exited`), as a background VM whose app exited leaves it.
    fn exited_vm(host: &Host, name: &str, status: i32) {
        let spec =
            serde_json::from_value(json!({"env": ["A=1"], "stdin": true, "tty": true, "ports": ["127.0.0.1:8080:80".parse::<crate::ports::Port>().unwrap()]}))
                .unwrap();
        let rec = crate::app::Exited::new(status, "ci".into(), Some("make".into()), Default::default(), spec, 1);
        std::fs::write(host.vms(name, "exited").unwrap(), serde_json::to_vec(&rec).unwrap()).unwrap();
    }

    #[test]
    fn an_exited_vm_is_waited_logged_inspected_and_renamed() {
        let (d, host) = host("exited");
        exited_vm(&host, "job", 3);
        std::fs::write(host.vms("job", "log").unwrap(), "out\n").unwrap();
        assert_eq!(wait(&host, "job").unwrap(), 3, "its record's status, its own exit record gone");
        assert!(known(&host, "job"), "logs reads (and follows) an exited vm's log");
        let paths = template::Paths::new(&d.join("state"));
        let listed = crate::vms(&host).into_iter().find(|v| v["name"] == "job").unwrap();
        let v = described(&host, &paths, "job", listed);
        assert_eq!((v["state"].as_str(), v["exit_code"].as_i64()), (Some("exited"), Some(3)), "{v}");
        let c = &v["config"];
        assert_eq!(c["ports"][0]["host_port"], 8080, "{c}");
        assert!(c["run"]["stdin"] == true && c["run"]["tty"] == true, "-i and -t: {c}");
        assert_eq!((c["run"]["env"][0].as_str(), c["cmd"].as_str(), c["template"].as_str()), (Some("A=1"), Some("make"), Some("ci")), "{c}");
        // A name an exited vm keeps is refused; renamed, its record, log and status move.
        exited_vm(&host, "other", 0);
        assert!(rename_stopped(&host, "job", "other").unwrap_err().to_string().contains("exited"));
        rename_stopped(&host, "job", "job2").unwrap();
        assert!(!host.vms("job", "exited").unwrap().exists() && crate::app::Exited::read(&host.vms("job2", "exited").unwrap()).unwrap().status == 3);
        assert_eq!(std::fs::read_to_string(host.vms("job2", "log").unwrap()).unwrap(), "out\n");
        assert!(host.vms("other", "exited").unwrap().exists(), "the refused name's record stays");
    }

    #[test]
    fn a_vms_own_command_follows_its_renames() {
        assert_eq!(renamed("x-never"), "x-never");
        NAMES.lock().unwrap().extend(["first".to_string(), "second".into(), "third".into()]);
        assert_eq!(renamed("first"), "third");
        assert_eq!(renamed("second"), "third");
        assert_eq!(renamed("other"), "other");
        NAMES.lock().unwrap().clear();
    }
}
