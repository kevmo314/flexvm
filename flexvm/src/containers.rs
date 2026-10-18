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
    loop {
        if host.name_locked(name) == Some(true) {
            // Empty while a start writes it: read again.
            let Some(id) = host.name_holder(name)? else {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            };
            if let Some(fd) = host::PidFd::open(&id)? {
                while !fd.wait(Duration::from_secs(1)) {}
            }
            // Written before it let the name go. Without one, whatever held the name was not a
            // VM's process (an `rm` deciding) or it died unrecorded: the records decide.
            if let Some(e) = exit_record(host, name).filter(|e| e.ident == id) {
                return Ok(e.code);
            }
            if host.name_locked(name) == Some(true) && host.name_holder(name)?.is_some_and(|h| h != id) {
                continue;
            }
        }
        return ended(host, name);
    }
}

/// The status of `name` with no process running it.
fn ended(host: &Host, name: &str) -> Result<i32> {
    let has = |ext: &str| host.vms(name, ext).is_ok_and(|p| p.exists());
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
    host.alive(name) || host.is_suspended(name) || ["failed", "lost", "exited"].iter().any(|ext| host.vms(name, ext).is_ok_and(|p| p.exists()))
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
/// new one) and restarts (a resumed VM appends to its log); it ends once nothing of the VM is left
/// (`rm`, `kill`, or a `run -- CMD` that ended), or its reader is gone.
pub fn logs(host: &Host, name: &str, follow: bool, lines: Option<usize>) -> Result<()> {
    host::check_name(name)?;
    let (path, prev) = (host.vms(name, "log")?, host.vms(name, "log.1")?);
    let open = || std::fs::File::open(&path).ok();
    // The current log first: one rotated meanwhile is then the previous one read below.
    let mut cur = open();
    let (mut old, old_ino) = match std::fs::File::open(&prev) {
        Ok(mut f) => {
            let mut b = Vec::new();
            f.read_to_end(&mut b)?;
            (b, f.metadata().ok().map(|m| (m.dev(), m.ino())))
        }
        Err(_) => (Vec::new(), None),
    };
    let ino = |f: &std::fs::File| f.metadata().ok().map(|m| (m.dev(), m.ino()));
    if cur.as_ref().is_some_and(|f| ino(f) == old_ino) {
        old.clear();
    }
    if cur.is_none() && old.is_empty() && !known(host, name) {
        bail!("no vm named {name:?}");
    }
    let mut first = old;
    if let Some(f) = cur.as_mut() {
        f.read_to_end(&mut first)?;
    }
    let first = lines.map_or(&first[..], |n| tail(&first, n));
    if !out(first)? || !follow {
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
        // Rotated (or removed and made again): what was written before the rename is drained, then the new one.
        let now = std::fs::metadata(&path).ok().map(|m| (m.dev(), m.ino()));
        if now.is_some() && now != cur.as_ref().and_then(ino) {
            if let Some(f) = cur.as_mut() {
                if !drain(f)? {
                    return Ok(());
                }
            }
            cur = open();
            continue;
        }
        // Gone for a while (not a restart's moment between its stop and start).
        match (known(host, name), gone_since) {
            (true, _) => gone_since = None,
            (false, None) => gone_since = Some(Instant::now()),
            (false, Some(t)) if t.elapsed() > Duration::from_secs(1) => return Ok(()),
            (false, Some(_)) => {}
        }
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
    host::check_name(to)?;
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

/// A failed or lost VM's record keeps its name: refused, as docker refuses a name in use.
fn refuse_recorded(host: &Host, to: &str) -> Result<()> {
    for ext in ["failed", "lost"] {
        if host.vms(to, ext)?.exists() {
            bail!("vm name {to:?} is taken (a {ext} vm, see flexvm ps -a): flexvm rm {to} first");
        }
    }
    Ok(())
}

/// A suspended (or quarantined) VM: its checkpoint directory, the claim on its address (which a
/// sweep reads by the name: `Host::held`), its logs and its exit status move to `to`. Both names
/// are held throughout, so no start of either runs meanwhile; the directory and the claim move
/// together under the host lock, so no sweep or claim sees one moved without the other.
fn rename_stopped(host: &Host, from: &str, to: &str) -> Result<()> {
    if !host.is_suspended(from) {
        return Err(match ["failed", "lost"].iter().find(|ext| host.vms(from, ext).is_ok_and(|p| p.exists())) {
            Some(ext) => format!("vm {from} is {ext}: only a running or stopped vm can be renamed").into(),
            None => format!("no vm named {from:?}").into(),
        });
    }
    let _from = host.take_name(from, true).map_err(|e| match host.alive(from) {
        true => format!("vm {from} started meanwhile: try again").into(),
        false => e,
    })?;
    // Taking the name removed what an interrupted suspend, resume or discard left.
    if !host.is_suspended(from) {
        bail!("no vm named {from:?}");
    }
    refuse_recorded(host, to)?;
    let _to = host.take_name(to, false)?;
    let (dir, dest) = (host.suspended(from)?, host.suspended(to)?);
    let ip = crate::checkpoint::read_manifest(&dir).ok().map(|m| m.ip);
    {
        let l = host.lock()?;
        std::fs::rename(&dir, &dest).map_err(|e| format!("renaming {} to {}: {e}", dir.display(), dest.display()))?;
        crate::util::sync_dir(&host.state.join("suspended"))?;
        if let Some(ip) = ip {
            if let Err(e) = host.rename_holder(&l, ip, from, to, None) {
                // Moved back: the claim still names `from`.
                let back = std::fs::rename(&dest, &dir).and_then(|()| crate::util::sync_dir(&host.state.join("suspended")));
                return Err(format!(
                    "vm {from}: moving the claim on {ip} to {to}: {e}{}",
                    back.err().map_or(String::new(), |b| format!("; moving it back: {b}"))
                )
                .into());
            }
        }
    }
    move_records(host, from, to)
}

/// Its logs (and the writers' locks with them) and exit status, under the logs lock shared, as a
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

impl Proc {
    /// `rename` of this running VM, holding `op` (refused at once while a checkpoint, migration
    /// or suspend has it). Not while a migration's outcome or an arrival's pages are pending,
    /// nor once it is ending: their records name the VM. The new name is taken first, so its
    /// claim on the address (read by the name, `Host::held`) is the VM's under either name.
    pub fn rename(&self, to: &str) -> Result<Value> {
        let vm = self.vm();
        let Some(_op) = self.op_now() else {
            bail!("vm {} is busy (a checkpoint, migration or suspend is under way): try again once it is done", vm.name);
        };
        self.not_destroyed()?;
        let from = self.name();
        host::check_name(to)?;
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
        if self.arrived.lock().unwrap().is_some() {
            bail!("vm {from} is still arriving by migration (its memory is still coming): try again once it is all here");
        }
        if self.reconciling.lock().unwrap().is_some() || self.is_leaving() {
            bail!("vm {from} is the source of a migration whose outcome is pending: not renaming it");
        }
        refuse_recorded(&self.host, to)?;
        let new = self.host.take_name(to, false)?;
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
        crate::log!("vm {from}: renamed {to}");
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
    Table,
    Template { table: bool, parts: Vec<Part> },
}

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
        match f.trim() {
            "json" => return Ok(Format::Json),
            "table" => return Ok(Format::Table),
            _ => {}
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
                a => match a.strip_prefix('.').and_then(|field| FIELDS.iter().find(|(n, _)| n.eq_ignore_ascii_case(field))) {
                    Some((name, _)) => Part::Field(name),
                    None => bail!(
                        "bad --format {f:?}: {{{{{a}}}}} is not a field (fields: {}, or {{{{json .}}}})",
                        FIELDS.iter().map(|(n, _)| format!(".{n}")).collect::<Vec<_>>().join(" ")
                    ),
                },
            });
            rest = &rest[end + 2..];
        }
        if !rest.is_empty() {
            parts.push(Part::Text(unescape(rest)));
        }
        Ok(Format::Template { table, parts })
    }

    /// One line per VM (none for `Table`, which the caller prints).
    pub fn render(&self, vms: &[Value]) -> Result<String> {
        match self {
            Format::Table => Ok(String::new()),
            Format::Json => Ok(vms.iter().map(|v| Ok(serde_json::to_string(v)? + "\n")).collect::<Result<String>>()?),
            Format::Template { table, parts } => {
                let line = |v: Option<&Value>| -> Result<String> {
                    let mut s = String::new();
                    for p in parts {
                        match (p, v) {
                            (Part::Text(t), _) => s.push_str(t),
                            (Part::Field(name), None) => s.push_str(&name.to_ascii_uppercase()),
                            (Part::Field(name), Some(v)) => s.push_str(&field(v, name)),
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
    let key = FIELDS.iter().find(|(n, _)| *n == name).map_or(name, |(_, k)| k);
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
    let logs = ["log", "log.1"].iter().any(|ext| host.vms(name, ext).is_ok_and(|p| p.exists()));
    let exited = host.vms(name, "exited").is_ok_and(|p| p.exists());
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
    fn filters_and_within_a_key_or_across_keys() {
        let web = row("web-1", "running", "10.0.0.2", "nginx_latest");
        let db = row("db", "suspended", "10.0.0.3", "postgres_16");
        let f = |given: &[&str]| Filters::parse(&given.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        assert!(f(&["name=web"]).matches(&web) && !f(&["name=web"]).matches(&db), "a part of the name");
        assert!(f(&["name=web", "name=db"]).matches(&db), "either value of one key");
        assert!(!f(&["name=web", "status=suspended"]).matches(&web), "both keys");
        assert!(f(&["status=exited"]).matches(&db) && !f(&["status=exited"]).matches(&web));
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
        assert_eq!(Format::parse("table").unwrap(), Format::Table);
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
        let (_d, host) = host("wait-live");
        // Held here, as a VM process holds its name: the holder it names is a child, waited on by its pidfd.
        let lock = host.take_name("job", false).unwrap();
        let mut child = std::process::Command::new("sleep").arg("0.3").spawn().unwrap();
        let id = Ident::of(child.id()).unwrap();
        std::fs::write(host.vms("job", "lock").unwrap(), serde_json::to_vec(&id).unwrap()).unwrap();
        record_exit(&host, "job", &Ident { pid: 1, start: 1, boot: "b".into() }, 1);
        let h = host.clone();
        let started = Instant::now();
        let waiter = std::thread::spawn(move || wait(&h, "job"));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!waiter.is_finished(), "an earlier instance's record is not this one's");
        record_exit(&host, "job", &id, 5);
        child.wait().unwrap();
        assert_eq!(waiter.join().unwrap().unwrap(), 5);
        assert!(started.elapsed() >= Duration::from_millis(200), "it waited for the holder's process");
        drop(lock);
    }

    /// A suspended VM `name` at `ip`, its claim held by a process gone (as a suspend leaves it).
    fn suspended_vm(host: &Host, name: &str, ip: &str) {
        let dir = host.suspended(name).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let body = serde_json::to_vec(&json!({
            "format": crate::checkpoint::FORMAT, "created_unix_ms": 0, "name": name, "ip": ip,
            "template": "tpl", "template_id": "id", "vcpus": 1, "mem_mib": 1, "max_mib": 1,
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
