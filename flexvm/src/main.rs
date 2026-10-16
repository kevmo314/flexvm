#![deny(clippy::print_stderr)]

mod bench;
mod checkpoint;
mod compat;
mod cow;
mod crc32c;
mod fc;
mod gc;
mod guest;
mod hold;
mod host;
mod image;
mod lifecycle;
mod limit;
mod listen;
mod migrate;
mod net;
mod socket;
mod standby;
mod template;
mod uffd;
mod util;
mod vm;
mod vmproc;

use std::io::{BufReader, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::host::Host;
use crate::template::Paths;
use crate::util::{proc_kb, recv_json, Result};
use crate::vmproc::Start;

const USAGE: &str = "\
flexvm: elastic Firecracker microVMs with post-copy live migration

  flexvm run NAME [--template T] [--ip IP] [-d] [-- CMD...]
                                     start a VM; the process is the VM (-d: in the background)
  flexvm ls [--json]                 list VMs (with their pids)
  flexvm exec NAME CMD...            run a shell command in a VM
  kill -TSTP PID / kill -CONT PID    pause / resume a VM (Ctrl-Z works in the foreground)
  kill PID                           suspend a VM to disk (SIGTERM); its memory is freed
  flexvm resume NAME [-d]            bring a suspended VM back
  flexvm kill NAME                   destroy a VM, running or suspended (Ctrl-C or Ctrl-\\ works too)
  flexvm checkpoint NAME DIR [--stop] [--incremental]
                                     write the VM's state to DIR (a new directory)
  flexvm restore DIR [--name N] [--ip IP|auto] [--paused] [-d]
                                     start a VM from a checkpoint
  flexvm migrate NAME HOST:PORT      live-migrate a VM to the host listening there
  flexvm reclaim IP [--force]        take back an address lent out with a VM that migrated away,
                                     once its target is gone for good (without --force: say what)
  flexvm config [--peer HOST:PORT]... [--vm-ips CIDR|FIRST-LAST] [--dns IP] [--underlay IP]
                [--announce-dev IFACE|none] [--reserve MIB] [--evict-at MIB]
                                     set this host's settings, live (no flags: show them and what is
                                     derived for those unset); --peer replaces the list, '' unsets
  flexvm listen [ADDR]               take migrations from peers (no ADDR: saved or socket-activated address)
  flexvm standby [--template T] [N]  keep N VMs restored and paused, so run takes ~5 ms (no N: show)
  flexvm template NAME [--vcpus N] [--mem MIB] [--max MIB] [--plug MIB] [--image REF [--init PATH] ...]
                                     build a template (see README)
  flexvm bench ...                   latency benchmarks (see README)

options: --state DIR (/var/lib/flexvm: artifacts, templates, images, VMs), --run DIR (/run/flexvm),
         --version
Each state directory is bound to its first run directory; a different --run is refused.
run, resume and restore exit with the VM's command's status, 128+signal, 125 when flexvm
fails, 124 when the VM dies
";

const SWITCHES: &[&str] = &["warm", "stop", "paused", "incremental", "standby", "incoming", "json", "detach", "force", "help", "version"];

/// `--flag value`s: last wins. `rest` follows `--` (or `exec NAME`).
pub struct Args {
    positional: Vec<String>,
    flags: Vec<(String, String)>,
    rest: Vec<String>,
    child_args: Vec<String>,
}

impl Args {
    #[cfg(test)]
    fn parse(it: impl IntoIterator<Item = String>) -> Result<Args> {
        let (a, e) = Args::parse_partly(it);
        e.map_or(Ok(a), Err)
    }

    /// The first error, and everything parsed around it: the command decides the exit status, wherever it is.
    fn parse_partly(it: impl IntoIterator<Item = String>) -> (Args, Option<util::Error>) {
        let mut a = Args { positional: Vec::new(), flags: Vec::new(), rest: Vec::new(), child_args: Vec::new() };
        let mut first = None;
        let mut it = it.into_iter();
        while let Err(e) = a.parse_into(&mut it) {
            first.get_or_insert(e);
        }
        (a, first)
    }

    /// Up to an error; called again, it goes on after it.
    fn parse_into(&mut self, it: &mut impl Iterator<Item = String>) -> Result<()> {
        let a = self;
        while let Some(arg) = it.next() {
            if arg != "-d" && arg != "--detach" {
                a.child_args.push(arg.clone());
            }
            match arg.strip_prefix("--") {
                Some("") => {
                    a.rest.extend(it.by_ref());
                    a.child_args.extend(a.rest.iter().cloned());
                }
                Some(f) => {
                    let value = if SWITCHES.contains(&f) {
                        "1".into()
                    } else if GLOBAL.contains(&f) || IMAGE_FLAGS.contains(&f) || COMMANDS.iter().any(|(_, _, flags)| flags.contains(&f)) {
                        let value = it.next().ok_or_else(|| format!("--{f} needs a value"))?;
                        a.child_args.push(value.clone());
                        value
                    } else {
                        bail!("unknown option --{f} (see flexvm --help)");
                    };
                    a.flags.push((f.into(), value));
                }
                None if arg == "-d" => a.flags.push(("detach".into(), "1".into())),
                None if arg == "-h" => a.flags.push(("help".into(), "1".into())),
                None if arg.starts_with('-') => bail!("unknown option {arg} (see flexvm --help)"),
                None => {
                    a.positional.push(arg);
                    if a.positional.len() == 2 && a.positional[0] == "exec" {
                        // `exec NAME -- CMD` too, as with run.
                        let mut cmd = it.by_ref().peekable();
                        cmd.next_if_eq("--");
                        a.rest.extend(cmd);
                        a.child_args.extend(a.rest.iter().cloned());
                    }
                }
            }
        }
        Ok(())
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.flags.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.flags.iter().filter(|(k, _)| k == name).map(|(_, v)| v.clone()).collect()
    }

    pub fn parse_or<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T> {
        self.get(name).map_or(Ok(default), |v| v.parse().map_err(|_| format!("bad --{name} {v:?}").into()))
    }
}

/// A VM's command's statuses are its own: flexvm's failures there exit 125.
fn main() {
    // A panic's message is queued after the lines before it, and written
    // (bounded: a stalled stderr does not keep the process from aborting).
    std::panic::set_hook(Box::new(|p| {
        let bt = std::backtrace::Backtrace::capture();
        let bt = if bt.status() == std::backtrace::BacktraceStatus::Captured { format!("\nstack backtrace:\n{bt}") } else { String::new() };
        util::log_final(format!("thread '{}' {p}{bt}\n", std::thread::current().name().unwrap_or("<unnamed>")), false);
        // The abort follows: a VM process's relays get the message to its log first. An unwinding
        // build's process may live on, so its output is left where it is.
        if cfg!(panic = "abort") {
            util::output::drain();
        }
    }));
    let (args, error) = Args::parse_partly(std::env::args().skip(1));
    let vm = matches!(args.positional.first().map(String::as_str), Some("run" | "resume" | "restore"));
    let result = error.map_or_else(|| real_main(&args), Err);
    if let Some(sig) = template::interrupted_signal() {
        util::raise_signal(sig);
    }
    if let Err(e) = result {
        util::log_final(format!("flexvm: {e}\n"), true);
        if vm {
            // A VM process's output may still be in its relays (`output::guard`).
            util::output::drain();
        }
        std::process::exit(if vm { vmproc::FAILED } else { 1 });
    }
    util::exit(0)
}

/// Flags every command takes.
const GLOBAL: &[&str] = &["state", "run", "help", "version"];

/// What `template --image` takes.
const IMAGE_FLAGS: &[&str] = &[
    "init",
    "entrypoint",
    "cmd",
    "env",
    "workdir",
    "user",
    "warm",
    "ready-port",
    "ready-cmd",
    "ready-timeout",
    "max-download-mib",
    "max-unpacked-mib",
    "max-file-mib",
    "max-entries",
];

/// Each command's words (itself included) at most, and its flags besides `GLOBAL`.
const COMMANDS: &[(&str, usize, &[&str])] = &[
    ("run", 2, &["template", "ip", "detach", "standby", "incoming"]),
    ("ls", 1, &["json"]),
    ("exec", 2, &[]),
    ("resume", 2, &["detach"]),
    ("kill", 2, &[]),
    ("checkpoint", 3, &["stop", "incremental"]),
    ("restore", 2, &["name", "ip", "paused", "detach"]),
    ("migrate", 3, &[]),
    ("reclaim", 2, &["force"]),
    ("listen", 2, &[]),
    ("config", 1, CONFIG_FLAGS),
    ("standby", 2, &["template"]),
    ("template", 2, &["vcpus", "mem", "max", "plug", "image"]),
    (
        "bench",
        1,
        &["template", "to", "to-state", "to-run", "timeout", "lifecycle", "iterations", "warmup", "dirty-mib", "settle-ms", "ready-port", "ready-http"],
    ),
    ("debug", 4, &[]),
];

/// Flags and words a command does not take are errors, never ignored.
fn check_applies(args: &Args) -> Result<()> {
    let Some(cmd) = args.positional.first() else { return Ok(()) };
    let Some(&(_, most, flags)) = COMMANDS.iter().find(|(c, ..)| c == cmd) else {
        bail!("unknown command {cmd:?} (see flexvm --help)");
    };
    if matches!(cmd.as_str(), "run" | "resume" | "exec" | "kill" | "checkpoint" | "migrate" | "template")
        && !(cmd == "run" && (args.has("standby") || args.has("incoming")))
        && args.positional.get(1).is_none_or(|name| name.is_empty())
    {
        bail!("{cmd} needs NAME");
    }
    let image = cmd == "template" && args.has("image");
    if let Some((f, _)) = args.flags.iter().find(|(f, _)| ![GLOBAL, flags, if image { IMAGE_FLAGS } else { &[] }].concat().contains(&f.as_str())) {
        if cmd == "template" && IMAGE_FLAGS.contains(&f.as_str()) {
            bail!("--{f} needs --image");
        }
        bail!("--{f} does not apply to {cmd} (see flexvm --help)");
    }
    if let Some(extra) = args.positional.get(most) {
        let hint = match cmd.as_str() {
            "run" => format!("; a command goes after --: flexvm run {} -- {extra} ...", args.positional[1]),
            _ => " (see flexvm --help)".into(),
        };
        bail!("{cmd} does not take {extra:?}{hint}");
    }
    if !args.rest.is_empty() && cmd != "run" && cmd != "exec" {
        bail!("{cmd} takes no -- CMD");
    }
    Ok(())
}

fn state(args: &Args) -> Result<PathBuf> {
    Ok(std::path::absolute(args.get("state").unwrap_or("/var/lib/flexvm"))?)
}

pub fn open_host(args: &Args) -> Result<Host> {
    Host::open(&state(args)?, Path::new(args.get("run").unwrap_or("/run/flexvm")))
}

fn paths(args: &Args) -> Result<Paths> {
    Ok(Paths::new(&state(args)?))
}

fn real_main(args: &Args) -> Result<()> {
    if args.has("help") {
        return output(format_args!("{USAGE}"));
    }
    if args.has("version") {
        return output(format_args!("flexvm {}\n", env!("CARGO_PKG_VERSION")));
    }
    check_applies(args)?;
    let pos: Vec<&str> = args.positional.iter().map(|s| s.as_str()).collect();
    let (name, arg2) = (pos.get(1).copied().unwrap_or(""), pos.get(2).copied());
    let template = args.get("template").unwrap_or("default");
    let call = |req: Value| print(vmproc::call(&open_host(args)?, name, req, None)?);
    match pos.first().copied() {
        Some("template") => build_template(args, name),
        Some("run") if args.has("standby") => vmproc::main(open_host(args)?, paths(args)?, Start::Standby { template: template.into() }, notify_fd()),
        Some("run") if args.has("incoming") => {
            let req: Value = serde_json::from_str(&std::env::var("FLEXVM_INCOMING").map_err(|_| "run --incoming is the listener's, for migrations")?)?;
            unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) };
            // Told once committed or refused: the listener holds an arrival slot until then.
            vmproc::main(open_host(args)?, paths(args)?, Start::Incoming { req }, notify_fd())
        }
        Some("run") => run(args, name, template),
        Some("resume") if resume(&open_host(args)?, name)? => Ok(()),
        Some("resume") => start(args, name, Start::Resume { name: name.into() }),
        Some("restore") => {
            let dir = std::path::absolute(pos.get(1).ok_or("restore needs DIR")?)?;
            // A detached restore logs to the VM's name, which the checkpoint has without --name.
            let label = match args.get("name") {
                Some(name) => name.to_string(),
                None if args.has("detach") => checkpoint::read_manifest(&dir)?.name,
                None => String::new(),
            };
            start(
                args,
                &label,
                Start::Restore { dir, name: args.get("name").map(String::from), ip: args.get("ip").map(String::from), paused: args.has("paused") },
            )
        }
        Some("ls") => list(&open_host(args)?, args.has("json")),
        Some("exec") => util::exit(exec(&open_host(args)?, name, &args.rest.join(" "))?),
        Some("kill") => kill(&open_host(args)?, name),
        Some("reclaim") => reclaim(&open_host(args)?, name, args.has("force")),
        Some("checkpoint") => {
            let dir = std::path::absolute(arg2.ok_or("checkpoint needs NAME DIR")?)?;
            call(json!({"op": "checkpoint", "dir": dir, "stop": args.has("stop"), "incremental": args.has("incremental")}))
        }
        Some("migrate") => call(json!({"op": "migrate", "to": arg2.ok_or("migrate needs NAME HOST:PORT")?})),
        Some("listen") => {
            // Before any thread that would take these signals is started.
            util::on_signal(&[libc::SIGTERM, libc::SIGINT, libc::SIGHUP], |sig| util::raise_signal(sig));
            let mut host = open_host(args)?;
            let listener = configure_listener(&mut host, pos.get(1).copied(), listen::activated())?;
            listen::main(host, listener)
        }
        Some("config") => {
            let mut host = open_host(args)?;
            if CONFIG_FLAGS.iter().any(|f| args.has(f)) {
                host.configure(|c| configure(c, args))?;
            }
            let c = &host.cfg;
            let derived = json!({"prefix": host.tap_prefix(), "underlay": c.underlay(), "announce_dev": c.announce_dev(), "reserve_mib": c.reserve(), "evict_at_mib": c.evict_at()});
            print(json!({"set": c, "derived": derived}))
        }
        Some("standby") if name.is_empty() => print(standby::show(&open_host(args)?)),
        Some("standby") => {
            let host = open_host(args)?;
            template::check_name(template)?;
            let n = name.parse().map_err(|_| "standby wants a count")?;
            // Check before saving a positive count, or an unreadable template would be retried forever.
            if n > 0 {
                template::Template::open(&paths(args)?, template)?;
            }
            print(standby::set(&host, template, n)?)
        }
        Some("bench") => bench::run(args),
        // Test hooks: arm a fault for MS ms (0 disarms), hash a checkpoint, or ask a VM.
        Some("debug") => match name {
            "gc" => {
                let host = open_host(args)?;
                gc::sweep(&host);
                Ok(())
            }
            "fault" => host::arm(&open_host(args)?, arg2.ok_or("debug fault NAME MS")?, pos.get(3).and_then(|m| m.parse().ok()).unwrap_or(1000)),
            "ckhash" => print(lifecycle::ckhash(&paths(args)?, std::path::Path::new(arg2.ok_or("debug ckhash DIR")?))?),
            "" => Err("debug fault|ckhash|gc|VM ...".into()),
            _ => call(json!({"op": "debug", "what": arg2.unwrap_or("status")})),
        },
        _ => {
            util::log_line(USAGE.to_string());
            util::exit(2)
        }
    }
}

/// Bind and validate before publishing any host configuration.
fn configure_listener(host: &mut Host, addr: Option<&str>, activated: Option<std::net::TcpListener>) -> Result<std::net::TcpListener> {
    let mut listener = None;
    host.configure(|c| {
        if let Some(a) = addr {
            c.listen = Some(a.into());
        }
        let bound = match activated {
            // Without ADDR, an activated socket says where this host listens; ADDR must be where it does.
            Some(l) => {
                let local = l.local_addr()?;
                match addr {
                    Some(a) => activated_at(a, local, listen::v6only(&l))?,
                    None => c.listen = Some(local.to_string()),
                }
                l
            }
            None => {
                let addr = c.listen.as_deref().ok_or("listen needs an address (flexvm listen ADDR)")?;
                std::net::TcpListener::bind(addr).map_err(|e| format!("listen on {addr}: {e}"))?
            }
        };
        listen::validate(&bound, c)?;
        listener = Some(bound);
        Ok(())
    })?;
    Ok(listener.unwrap())
}

/// An ADDR given with an activated socket is what peers are told (they fetch a
/// migration's memory from it): one the socket does not listen on is refused.
fn activated_at(addr: &str, local: std::net::SocketAddr, v6only: bool) -> Result<()> {
    let at = |a: &std::net::SocketAddr| a.port() == local.port() && takes(local, v6only, a.ip());
    let resolved = util::resolve(addr, Instant::now() + Duration::from_secs(2)).map_err(|e| format!("listen address {addr}: {e}"))?;
    if !resolved.iter().any(at) {
        bail!("the activated socket listens on {local}, not {addr}: run flexvm listen without ADDR, or give the socket's address");
    }
    Ok(())
}

/// Whether a socket bound at `local` takes connections to `ip`: its own address, or for a
/// wildcard one any of its family (an IPv6 one IPv4 too, unless IPV6_V6ONLY).
fn takes(local: std::net::SocketAddr, v6only: bool, ip: std::net::IpAddr) -> bool {
    let (ip, bound) = (ip.to_canonical(), local.ip().to_canonical());
    match (bound.is_unspecified(), local.ip()) {
        (false, _) => ip == bound,
        (true, std::net::IpAddr::V4(_)) => ip.is_ipv4(),
        (true, std::net::IpAddr::V6(_)) => ip.is_ipv6() || !v6only,
    }
}

/// What `configure` sets.
const CONFIG_FLAGS: &[&str] = &["peer", "vm-ips", "underlay", "announce-dev", "dns", "reserve", "evict-at"];

/// Flags not given keep their configured values; an empty one unsets it
/// (derived again where used). --peers replace the list (`--peer ''` empties
/// it); `--announce-dev none` turns announcements off.
fn configure(c: &mut host::Config, args: &Args) -> Result<()> {
    if args.has("peer") {
        c.peers = args.all("peer").into_iter().filter(|p| !p.is_empty()).collect();
        if let Some(p) = c.peers.iter().find(|p| !host::is_endpoint(p)) {
            bail!("bad --peer {p:?}: give HOST:PORT, a peer's flexvm listen address");
        }
    }
    if let Some(r) = args.get("vm-ips") {
        c.vm_ips = if r.is_empty() { host::Config::default().vm_ips } else { r.into() };
        net::IpRange::parse(&c.vm_ips)?;
    }
    if let Some(u) = args.get("underlay") {
        c.underlay = (!u.is_empty()).then(|| u.parse()).transpose().map_err(|_| format!("bad --underlay {u:?}"))?;
    }
    if let Some(d) = args.get("announce-dev") {
        if !d.is_empty() && d != "none" {
            net::ifindex(d)?;
        }
        c.announce_dev = (!d.is_empty()).then(|| d.into());
    }
    if let Some(d) = args.get("dns") {
        c.dns = (!d.is_empty()).then(|| d.parse::<std::net::Ipv4Addr>().map(|_| d.into())).transpose().map_err(|_| format!("bad --dns {d:?}"))?;
    }
    for (flag, v) in [("reserve", &mut c.reserve_mib), ("evict-at", &mut c.evict_mib)] {
        if args.has(flag) {
            *v = (args.get(flag) != Some("")).then(|| args.parse_or(flag, 0)).transpose()?;
        }
    }
    let total = proc_kb("/proc/meminfo", "MemTotal").map_or(u64::MAX, |b| b >> 20);
    if let Some(r) = c.reserve_mib.filter(|&r| r > total) {
        bail!("--reserve {r} MiB is more than this host's {total} MiB of RAM");
    }
    if let Some(e) = c.evict_mib.filter(|&e| e < c.reserve()) {
        crate::log!("flexvm: the eviction mark {e} MiB is under the {} MiB reserve: eviction starts at the reserve", c.reserve());
    }
    if !c.peers.is_empty() && c.vm_ips == host::Config::default().vm_ips {
        crate::log!("flexvm: warning: --vm-ips is the default {}; each peer needs a range of its own", c.vm_ips);
    }
    Ok(())
}

/// Claims a standby VM if there is one, else becomes the VM.
fn run(args: &Args, name: &str, template: &str) -> Result<()> {
    let (host, paths) = (open_host(args)?, paths(args)?);
    let ip = args.get("ip").filter(|&s| s != "auto");
    let ip: Option<std::net::Ipv4Addr> = ip.map(|s| s.parse().map_err(|_| format!("bad --ip {s:?}"))).transpose()?;
    let cmd = (!args.rest.is_empty()).then(|| args.rest.join(" "));
    host::check_name(name)?;
    let req = json!({"op": "claim", "name": name, "ip": ip.map(|i| i.to_string()), "cmd": cmd});
    // A claimed standby VM writes where this process would, to opens made here (`own`).
    let log = args.has("detach").then(|| log_file(&host, name)).transpose()?;
    let fds = log.as_ref().map_or([1, 2], |f| [f.as_raw_fd(); 2]).map(|fd| unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned());
    let outs = fds.into_iter().map(|f| Ok(util::output::own(f?.into()))).collect::<std::io::Result<Vec<_>>>()?;
    // A detached run's VM process (it answers on FLEXVM_NOTIFY_FD): its parent tried them.
    let tried = std::env::var_os("FLEXVM_NOTIFY_FD").is_some();
    // A foreground claim's signals wait from before it is sent: the VM it makes gets them
    // (`follow`), as a cold start would, never orphaned by this process dying mid-claim.
    let set = (!tried && log.is_none()).then(|| util::block_signals(&FOLLOW_SIGNALS));
    let taken = if tried { None } else { standby::take(&host, &paths, template, &req, &outs.iter().map(|f| f.as_raw_fd()).collect::<Vec<_>>())? };
    if let (None, Some(set)) = (&taken, &set) {
        // No claim: this process becomes the VM, and one pending kills it as before.
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, set, std::ptr::null_mut()) };
    }
    match (taken, log) {
        (Some((v, _)), Some(_)) => print(v),
        (Some((v, conn)), None) => {
            crate::log!("{v}");
            let id = host::Ident { pid: v["pid"].as_u64().unwrap_or(0) as u32, start: v["start"].as_u64().unwrap_or(0), boot: host::boot_id().into() };
            follow(conn, id)
        }
        (None, Some(log)) => spawn_detached(&host, name, args, &log),
        (None, None) => vmproc::main(host, paths, Start::Run { name: name.into(), template: template.into(), ip, cmd }, notify_fd()),
    }
}

/// What a foreground `run` that claimed a standby VM forwards to it (SIGHUP is ignored).
const FOLLOW_SIGNALS: [i32; 6] = [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGCONT, libc::SIGHUP];

fn start(args: &Args, name: &str, s: Start) -> Result<()> {
    if args.has("detach") {
        let host = open_host(args)?;
        return spawn_detached(&host, name, args, &log_file(&host, name)?);
    }
    vmproc::main(open_host(args)?, paths(args)?, s, notify_fd())
}

fn log_file(host: &Host, name: &str) -> Result<std::fs::File> {
    host::check_name(name)?;
    // Opened and marked written holding the logs lock (shared): garbage
    // collection removes only a quiet log, holding it exclusively.
    let _logs = host.logs_lock(libc::LOCK_SH)?;
    let f = std::fs::OpenOptions::new().create(true).append(true).open(host.vms(name, "log")?)?;
    f.set_modified(std::time::SystemTime::now())?;
    Ok(f)
}

fn spawn_detached(host: &Host, name: &str, args: &Args, log: &std::fs::File) -> Result<()> {
    let log_path = host.vms(name, "log")?;
    let (r, w) = std::os::unix::net::UnixStream::pair()?;
    util::spawn_self(&args.child_args, log, w.as_raw_fd(), &[("FLEXVM_NOTIFY_FD", "3")])?;
    drop(w);
    let reply = recv_json(&mut BufReader::new(r))?.ok_or_else(|| format!("the vm process failed to start (see {})", log_path.display()))?;
    if reply["ok"] != json!(true) {
        return Err(reply["error"].as_str().unwrap_or("failed").to_string().into());
    }
    print(reply["result"].clone())
}

fn notify_fd() -> Option<std::fs::File> {
    let fd: i32 = std::env::var("FLEXVM_NOTIFY_FD").ok()?.parse().ok()?;
    std::env::remove_var("FLEXVM_NOTIFY_FD");
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    Some(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// A foreground `run` that claimed a standby VM: forwards signals, exits with its status.
fn follow(mut conn: BufReader<std::os::unix::net::UnixStream>, id: host::Ident) -> Result<()> {
    // Blocked since before the claim (`run`): any that came meanwhile are pending, and forwarded.
    let set = util::block_signals(&FOLLOW_SIGNALS);
    // A fast command's process may be gone already: its exit frame is buffered.
    if let Ok(Some(vm)) = host::PidFd::open(&id) {
        std::thread::spawn(move || loop {
            match util::wait_signal(&set) {
                libc::SIGHUP => {}
                sig => drop(vm.signal(sig)),
            }
        });
    }
    let reply = recv_json(&mut conn).ok().flatten();
    util::exit(reply.and_then(|r| r["exit"].as_i64()).map_or(vmproc::FAILED, |c| c as i32))
}

/// A running VM's process resumes it (true); a suspended one a new process. A
/// suspend coming (a SIGTERM sent before) is waited out: the VM then runs here
/// (it failed) or is suspended. Never true unless its process said so, once the
/// VM runs: a resume that fails, or a destroy meanwhile, is an error.
fn resume(host: &Host, name: &str) -> Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let req = json!({"op": "resume"});
        let reply = vmproc::connect(host, name, &req, &[], Instant::now() + Duration::from_secs(10))
            .map(|c| recv_json(&mut BufReader::new(util::By { s: c, at: Instant::now() + RESUME_ANSWER })));
        match reply {
            Ok(Ok(Some(v))) if v["ok"] == true && v["result"]["suspending"] == true => {}
            Ok(Ok(Some(v))) if v["ok"] == true => return Ok(true),
            // Its control connections are all taken: asked again.
            Ok(Ok(Some(v))) if v["error"] == "busy" && Instant::now() < deadline => {}
            Ok(Ok(Some(v))) => return Err(v["error"].as_str().unwrap_or("resume refused").to_string().into()),
            Ok(Err(e)) if host.alive(name) => return Err(format!("vm {name}: its resume was not confirmed: {e}").into()),
            // It took the request: whatever ended it meanwhile ended the resume too.
            Ok(_) => {
                return Err(format!(
                    "vm {name} ended before its resume was confirmed (killed or suspended meanwhile?); see {}",
                    host.vms(name, "log")?.display()
                )
                .into())
            }
            Err(_) if host.entry(name).is_err() => return Ok(false),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// How long `resume` waits for the VM process's answer: longer than it waits for the resume.
const RESUME_ANSWER: Duration = Duration::from_secs(75);

fn kill(host: &Host, name: &str) -> Result<()> {
    host::check_name(name)?;
    // Reconciling sources accept SIGINT too; the process records the owed outcome before ending.
    if host.entry(name).is_ok_and(|e| e.state == "source") {
        return Err(format!("vm {name} is the source of a migration in progress; it ends once the target has its memory (kill it where it runs)").into());
    }
    if let Ok(vm) = host.signal(name, libc::SIGINT) {
        if !vm.wait(Duration::from_secs(30)) {
            return Err(format!("vm {name} is still there; see {}", host.vms(name, "log")?.display()).into());
        }
        // A suspend that finished first is undone: the kill wins.
        if !host.suspended(name)?.exists() {
            return Ok(());
        }
    }
    if host.suspended(name)?.exists() {
        let _lock = host.take_name(name, true)?;
        // Taking the name removed it if it was not a suspended VM (an interrupted suspend's or resume's).
        if !host.suspended(name)?.exists() {
            return Ok(());
        }
        return lifecycle::revoke(host, name)?;
    }
    if !host.alive(name) && std::fs::remove_file(host.vms(name, "failed")?).is_ok() {
        return Ok(());
    }
    if host.alive(name) {
        return Err(format!(
            "vm {name:?} is starting or its registry is unavailable; retry flexvm kill {name} once it is ready, or see {}",
            host.vms(name, "log")?.display()
        )
        .into());
    }
    match std::fs::read_to_string(host.vms(name, "moved")?) {
        Ok(to) => Err(format!("vm {name} moved to {to}; kill it there").into()),
        Err(_) => Err(format!("no vm named {name:?}").into()),
    }
}

/// Withdraws the generation an address was lent out with, everywhere, and forgets what
/// outcome was owed for it: only for a target gone for good, so `--force` it is.
fn reclaim(host: &Host, ip: &str, force: bool) -> Result<()> {
    let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| format!("reclaim takes the address (an IPv4 address), not {ip:?}"))?;
    let Some((gen, owed)) = host.lent_to(ip)? else { return Err(format!("{ip} is not lent out").into()) };
    let whom = match owed.as_slice() {
        [] => "a vm that migrated away".to_string(),
        o => o.iter().map(|(id, to)| format!("migration {id} to {to}, whose outcome is unknown")).collect::<Vec<_>>().join(", "),
    };
    if !force {
        return Err(format!(
            "{ip} is lent out (generation {gen}) with {whom}. Reclaiming withdraws that generation everywhere and lets {ip} be handed out here again: \
             first make sure no host runs that vm any more (kill it there, or know the host is gone for good), or two vms will share {ip}. \
             Then: flexvm reclaim {ip} --force"
        )
        .into());
    }
    let (gen, forgot) = host.reclaim(ip)?;
    vmproc::tell_peers(host, json!({"op": "route", "ip": ip.to_string(), "gen": gen}));
    util::log_line(format!(
        "WARNING: {ip} reclaimed (generation {gen} withdrawn, lent with {whom}); if that vm still runs anywhere, it shares {ip} with the next vm given it"
    ));
    print(json!({"ip": ip.to_string(), "withdrawn_gen": gen, "forgot_migrations": forgot.iter().map(|(id, _)| id).collect::<Vec<_>>()}))
}

fn list(host: &Host, as_json: bool) -> Result<()> {
    let rss = |pid: Option<u32>| pid.and_then(|p| proc_kb(&format!("/proc/{p}/status"), "VmRSS")).unwrap_or(0) >> 20;
    let mut vms: Vec<Value> = host
        .entries()
        .into_iter()
        .map(|e| {
            let mut v = serde_json::to_value(&e).unwrap_or_default();
            v["rss_mib"] = json!(rss(e.firecracker));
            v
        })
        .collect();
    let names = |dir: PathBuf| std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.file_name().to_string_lossy().into_owned());
    vms.extend(names(host.state.join("suspended")).filter(|n| !n.starts_with('.') && !host.alive(n)).filter_map(|n| lifecycle::describe_suspended(host, &n)));
    for n in names(host.run.join("vms")).filter_map(|n| n.strip_suffix(".failed").map(String::from)).filter(|n| !host.alive(n)) {
        let Ok(failed) = host.vms(&n, "failed") else { continue };
        vms.push(json!({"name": n, "state": "failed", "error": std::fs::read_to_string(failed).unwrap_or_default()}));
    }
    if as_json {
        return print(json!(vms));
    }
    let row =
        |c: [&str; 9]| output(format_args!("{:<16} {:<15} {:<10} {:<12} {:>8} {:>4} {:>8} {:>8} {}\n", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8]));
    // STARVED: refused memory here and throttled (moved to a peer if there is one).
    row(["NAME", "IP", "TEMPLATE", "STATE", "PID", "VCPU", "RSS MiB", "MAX MiB", "STARVED"])?;
    for v in &vms {
        let s = |k: &str| v[k].as_str().map(String::from).or_else(|| v[k].as_u64().map(|n| n.to_string())).unwrap_or_default();
        let [a, b, c, d, e, f, g, h] = ["name", "ip", "template", "state", "pid", "vcpus", "rss_mib", "max_mib"].map(s);
        let starved = if v["starved"].as_bool() == Some(true) { "yes" } else { "" };
        row([&a, &b, &c, &d, &e, &f, &g, &h, starved])?;
    }
    Ok(())
}

pub fn print(v: Value) -> Result<()> {
    output(format_args!("{}\n", serde_json::to_string_pretty(&v)?))
}

/// CLI output may be piped to a reader that exits early.
fn output(text: std::fmt::Arguments<'_>) -> Result<()> {
    match std::io::stdout().lock().write_fmt(text) {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(e.into()),
        _ => Ok(()),
    }
}

// Firecracker wants 1 or an even count of vCPUs, at most 32.
fn template_vcpus(args: &Args) -> Result<u32> {
    let cpus = util::host_cpus().min(32) as u32;
    let cpus = args.parse_or("vcpus", if cpus > 1 { cpus & !1 } else { 1 })?;
    if cpus != 1 && (cpus == 0 || cpus > 32 || cpus % 2 != 0) {
        bail!("--vcpus must be 1 or an even count up to 32");
    }
    Ok(cpus)
}

fn build_template(args: &Args, name: &str) -> Result<()> {
    host::check_name(name)?;
    let cpus = template_vcpus(args)?;
    if unsafe { libc::geteuid() } != 0 {
        bail!("run flexvm as root");
    }
    util::check_kvm()?;
    // Interrupted, the build stops at its next step and removes its tap and staging (gigabytes:
    // an image's unpacked tree and rootfs too); a second signal ends flexvm at once, and the next
    // build removes the staging. Blocked before the image's download threads start.
    util::on_signal(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP], |sig| {
        log!("flexvm: stopping the template build; it cleans up first");
        template::interrupt(sig);
        loop {
            std::thread::park();
        }
    });
    let mut paths = paths(args)?;
    let opts = image_options(args)?;
    let max = args.parse_or("max", proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0) >> 20)?;
    let (mem, plug) = (args.parse_or("mem", template::base_mib(max))?, args.parse_or("plug", template::PLUG_MIB)?);
    let host = open_host(args)?;
    let me = host::Ident::me();
    host::clear_taps(&host.run, &me);
    let tap = template::tap(&host.tap_prefix());
    net::create_tap(&tap, &host::tap_alias(&host.run, &me))?;
    let res = (|| {
        let image = opts
            .map(|opts| {
                let init = args.get("init").map_or(paths.kernel.with_file_name("flexvm-init"), PathBuf::from);
                let (rootfs, meta) = image::prepare(&state(args)?.join("images"), &init, &opts)?;
                paths.rootfs = rootfs;
                Ok::<_, util::Error>(meta)
            })
            .transpose()?;
        template::create(&paths, name, cpus, mem, max, plug, image, &tap)
    })();
    net::delete_tap(&tap);
    res
}

fn image_options(args: &Args) -> Result<Option<image::Options>> {
    let Some(src) = args.get("image") else {
        // `check_applies` refused the image's flags.
        return Ok(None);
    };
    let warm = args.has("warm");
    let ready = match (args.get("ready-port"), args.get("ready-cmd")) {
        (Some(_), Some(_)) => return Err("pass --ready-port or --ready-cmd, not both".into()),
        (Some(_), None) => Some(image::Ready::Port(args.parse_or("ready-port", 0)?)),
        (None, Some(c)) => Some(image::Ready::Cmd(c.into())),
        (None, None) => None,
    };
    if ready.is_some() && !warm {
        return Err("--ready-port and --ready-cmd only apply with --warm".into());
    }
    let d = image::Limits::default();
    let bytes =
        |flag, default| -> Result<u64> { args.parse_or::<u64>(flag, default)?.checked_mul(1 << 20).ok_or_else(|| format!("--{flag} is too large").into()) };
    Ok(Some(image::Options {
        image: src.into(),
        entrypoint: args.get("entrypoint").map(image::parse_argv).transpose()?,
        cmd: args.get("cmd").map(image::parse_argv).transpose()?,
        env: args.all("env"),
        workdir: args.get("workdir").map(String::from),
        user: args.get("user").map(String::from),
        warm,
        ready,
        ready_timeout: Duration::from_secs(args.parse_or::<u32>("ready-timeout", 120)?.into()),
        staging: state(args)?.join("staging"),
        limits: image::Limits {
            download: bytes("max-download-mib", d.download >> 20)?,
            unpacked: bytes("max-unpacked-mib", d.unpacked >> 20)?,
            file: bytes("max-file-mib", d.file >> 20)?,
            entries: args.parse_or("max-entries", d.entries)?,
        },
    }))
}

/// A command's session in the guest: its id, whether the guest took it, and
/// how much of its output was written out (a reattach goes on from there).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: String,
    pub started: bool,
    pub offset: u64,
    /// Its exit status, once the guest sent it (a suspend records it too).
    #[serde(default)]
    pub exit: Option<i32>,
}

impl Session {
    pub fn new() -> Result<Session> {
        Ok(Session { id: util::random_hex(16)?, started: false, offset: 0, exit: None })
    }
}

/// Reattaches when the connection drops (a checkpoint's pause resets vsock).
pub fn exec(host: &Host, name: &str, cmd: &str) -> Result<i32> {
    let session: &'static Mutex<Session> = Box::leak(Box::new(Mutex::new(Session::new()?)));
    let id = session.lock().unwrap().id.clone();
    let close = {
        let (host, name, id) = (host.clone(), name.to_string(), id.clone());
        let once = move || -> Result<()> {
            let c = vmproc::connect(&host, &name, &json!({"op": "exec", "session": id, "action": "close"}), &[], Instant::now() + Duration::from_secs(5))?;
            c.set_read_timeout(Some(Duration::from_secs(5)))?;
            util::answer(recv_json(&mut BufReader::new(c))?, "vm", "session close failed").map(drop)
        };
        // A checkpoint turns it away for a few seconds: it is tried again meanwhile.
        move || -> Result<()> {
            let until = Instant::now() + Duration::from_secs(10);
            loop {
                match once() {
                    Err(e) if e.to_string().contains(vm::CHECKPOINTING) && Instant::now() < until => std::thread::sleep(Duration::from_millis(200)),
                    res => return res,
                }
            }
        }
    };
    // Interrupted, the command is stopped: left running, it would hold one of the guest's session slots.
    let (stop, vm) = (close.clone(), name.to_string());
    util::on_signal(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP], move |sig| {
        // Held until exit, so the stopped command's status is not reported; not waited for long, as
        // a write to a stalled stdout holds it.
        let deadline = Instant::now() + Duration::from_secs(1);
        let _s = loop {
            match session.try_lock() {
                Ok(s) => break Some(s),
                Err(std::sync::TryLockError::Poisoned(e)) => break Some(e.into_inner()),
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break None,
            }
        };
        if let Err(e) = stop() {
            crate::log!("flexvm: the command may still be running in vm {vm}: {e}");
        }
        util::raise_signal(sig);
    });
    let result = exec_session(host, name, cmd, session, false);
    // Completed sessions are acknowledged on their attachment. Errors (including a closed
    // stdout, as with `| head`) still need CLOSE to stop a command that may be running.
    if result.is_err() {
        let _ = close();
    }
    match result {
        Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe) => Ok(0),
        result => result,
    }
}

/// `exec` of a session that may have started already. Output is written,
/// and its offset counted, under the session's lock: whoever holds it knows
/// exactly what was written (a suspend records it for the resumed VM). The
/// session is left open: a VM's main command may be reattached after a
/// suspend, and its VM goes with it anyway. `patient` (a VM's main command):
/// a paused or checkpointing VM is waited for even before the command started.
pub fn exec_session(host: &Host, name: &str, cmd: &str, session: &Mutex<Session>, patient: bool) -> Result<i32> {
    let id = session.lock().unwrap().id.clone();
    let mut error = String::new();
    let mut deadline = Instant::now() + Duration::from_secs(30);
    // The VM the first request reached: only it is attached to, or asked to start the command again.
    let mut vm = None;
    while Instant::now() < deadline {
        let (started, offset) = {
            let s = session.lock().unwrap();
            if let Some(code) = s.exit {
                return Ok(code);
            }
            (s.started, s.offset)
        };
        let req = json!({"op": "exec", "session": id, "action": if started { "attach" } else { "start" }, "offset": offset, "cmd": cmd});
        let at = Instant::now() + Duration::from_secs(5);
        let stream = connect_same(host, name, &req, at, &mut vm).and_then(|c| exec_stream(c, at));
        // Locked per write, never across a read: a checkpoint takes stdout's lock too.
        match stream.map(|mut r| {
            // Test fault `exec_lose_echo`: the connection is lost before the session id comes back (the guest has the command).
            if !started && crate::host::tripped("exec_lose_echo") {
                return Ok(StreamEnd::Disconnected("injected fault: lost before the session id".into()));
            }
            let result = exec_frames(&mut r, session, &mut std::io::stdout(), &mut std::io::stderr(), &mut deadline);
            if !patient && matches!(result, Ok(StreamEnd::Exit(_))) {
                let _ = r.get_mut().write_all(&[guest::SESSION_DONE]);
            }
            result
        }) {
            Ok(Err(e)) => return Err(e),
            Ok(Ok(StreamEnd::Exit(code))) => return Ok(code),
            Ok(Ok(StreamEnd::Disconnected(why))) => error = why,
            Err(e) if e.is::<Replaced>() => return Err(format!("{e} (session {id})").into()),
            Err(e) => {
                // A new interactive command fails at once; a running one (or a VM's
                // main command) waits for its VM to resume, or for a checkpoint (a
                // suspend's too) to finish.
                let msg = e.to_string();
                if msg.contains(" is paused; ") || msg.contains(vm::CHECKPOINTING) {
                    if !started && !patient {
                        return Err(e);
                    }
                    deadline = Instant::now() + Duration::from_secs(30);
                }
                if !host.alive(name) {
                    if let Ok(to) = std::fs::read_to_string(host.vms(name, "moved")?) {
                        return Err(format!("vm {name} moved to {to}; the command keeps running there (session {id})").into());
                    }
                    if !started || !host.suspended(name)?.is_dir() {
                        return Err(e);
                    }
                }
                error = msg;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
        // Test gate `exec_retry`: the next try waits while a test changes the VM under it.
        if crate::host::fault("exec_retry") {
            crate::host::gate("exec_retry");
            deadline = Instant::now() + Duration::from_secs(30);
        }
    }
    Err(format!("exec recovery timed out: {error}").into())
}

/// Which VM a command runs in: its address and that address's generation. A
/// suspend and resume, or a migration, keeps both; a VM made again under the
/// name (after a kill) has a new generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Instance {
    ip: std::net::Ipv4Addr,
    gen: u64,
}

/// The VM under the name is another than the one a command's request reached first.
#[derive(Debug)]
struct Replaced(String);

impl std::fmt::Display for Replaced {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Replaced {}

/// Connects to `name`'s VM process and sends `req` once it is known to run the
/// VM `vm` names (recorded by the first connection): one made under the name
/// since is refused (`Replaced`) before the request reaches it, and one that
/// cannot be told yet (its registry entry not published) is an error retried.
fn connect_same(host: &Host, name: &str, req: &Value, at: Instant, vm: &mut Option<Instance>) -> Result<std::os::unix::net::UnixStream> {
    let c = util::connect_unix(&host.sock(name)?, at.saturating_duration_since(Instant::now())).map_err(|e| {
        if host.alive(name) {
            format!("vm {name:?} is starting or its control socket is unavailable; retry once it is ready: {e}")
        } else if host.is_suspended(name) {
            format!("vm {name:?} is suspended; use flexvm resume {name} first")
        } else {
            format!("no vm named {name:?}")
        }
    })?;
    // The process that listens; a VM's own main command needs no check: no other takes the name while it holds it.
    let pid = util::peer_pid(&c)?;
    if pid != std::process::id() {
        let now = host.entry(name).ok().filter(|e| e.ident.pid == pid && e.gen != 0).and_then(|e| Some(Instance { ip: e.ip?, gen: e.gen }));
        same_instance(name, now.ok_or_else(|| format!("vm {name:?} is starting or its registry entry is unavailable; retry once it is ready"))?, vm)?;
    }
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    util::send_with_fds(&c, &line, &[], at)?;
    c.set_read_timeout(None)?;
    c.set_write_timeout(None)?;
    Ok(c)
}

/// Records the first VM reached; any later one must be it.
fn same_instance(name: &str, now: Instance, vm: &mut Option<Instance>) -> Result<()> {
    match vm {
        None => *vm = Some(now),
        Some(v) if *v == now => {}
        Some(v) => {
            return Err(Box::new(Replaced(format!(
                "vm {name} was killed and made again since the command was sent ({} generation {}, now {} generation {}); \
                 not starting it again in the new vm, it may have run in the old one",
                v.ip, v.gen, now.ip, now.gen
            ))))
        }
    }
    Ok(())
}

/// Keeps frames read ahead with the reply, then switches from its deadline to heartbeat timeouts.
fn exec_stream<S: util::Timed>(c: S, at: Instant) -> Result<BufReader<S>> {
    let mut r = util::By { s: BufReader::new(c), at };
    util::answer(recv_json(&mut r)?, "vm", "exec failed")?;
    r.s.get_ref().read_timeout(Duration::from_secs(3))?;
    Ok(r.s)
}

enum StreamEnd {
    Exit(i32),
    Disconnected(String),
}

/// Tracks the session's offset so a reattach resumes without duplicates.
fn exec_frames(r: &mut impl Read, session: &Mutex<Session>, stdout: &mut impl Write, stderr: &mut impl Write, deadline: &mut Instant) -> Result<StreamEnd> {
    let id = session.lock().unwrap().id.clone();
    let mut echoed = false;
    loop {
        let (kind, data) = match guest::read_frame(r) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(StreamEnd::Disconnected("the vm closed the stream".into())),
            Err(e) => return Ok(StreamEnd::Disconnected(e.to_string())),
        };
        let mut s = session.lock().unwrap();
        match kind {
            guest::FRAME_STDOUT | guest::FRAME_STDERR if s.started => {
                let bytes = guest::session_output(&data, s.offset)?;
                let out: &mut dyn Write = if kind == guest::FRAME_STDOUT { stdout } else { stderr };
                out.write_all(bytes)?;
                out.flush()?;
                s.offset += bytes.len() as u64;
            }
            guest::FRAME_STDOUT | guest::FRAME_STDERR => return Err("session output before session id".into()),
            guest::FRAME_EXIT => {
                let code = guest::session_exit(&data, s.offset)?;
                s.exit = Some(code);
                return Ok(StreamEnd::Exit(code));
            }
            guest::FRAME_LOST => {
                let start = u64::from_le_bytes(data.as_slice().try_into().map_err(|_| "bad output-lost frame")?);
                return Err(format!("session output lost: needed offset {}, retained output starts at {start}", s.offset).into());
            }
            guest::FRAME_MSG if data == id.as_bytes() => (s.started, echoed) = (true, true),
            // A reattach after the connection was lost, to a session closed meanwhile (acknowledged, or reclaimed).
            guest::FRAME_MSG if s.started && !echoed && data == b"error: session closed" => {
                return Err(
                    format!("lost the connection to the vm after byte {} of output; the session has since been closed and the rest is gone", s.offset).into()
                )
            }
            guest::FRAME_MSG if data == b"waiting" && s.started => {}
            // Before the id echo the request itself failed: not retried.
            guest::FRAME_MSG if !s.started => return Err(guest::refusal(&data).into()),
            guest::FRAME_MSG => return Ok(StreamEnd::Disconnected(String::from_utf8_lossy(&data).into_owned())),
            _ => return Err(format!("unknown session frame {kind}").into()),
        }
        *deadline = Instant::now() + Duration::from_secs(30);
    }
}

#[cfg(test)]
mod exec_tests {
    use super::*;

    fn parse(args: &[&str]) -> Args {
        Args::parse(args.iter().map(|a| a.to_string())).unwrap()
    }

    #[test]
    fn numeric_flags_reject_overflow_and_invalid_cpu_counts() {
        for flag in ["max-download-mib", "max-unpacked-mib", "max-file-mib"] {
            for value in ["17592186044416", "18446744073709551615"] {
                assert!(image_options(&parse(&["--image", "busybox", &format!("--{flag}"), value])).is_err(), "{flag}={value}");
            }
            let opts = image_options(&parse(&["--image", "busybox", &format!("--{flag}"), "17592186044415"])).unwrap().unwrap();
            let bytes = match flag {
                "max-download-mib" => opts.limits.download,
                "max-unpacked-mib" => opts.limits.unpacked,
                _ => opts.limits.file,
            };
            assert_eq!(bytes, (u64::MAX >> 20) << 20);
        }
        assert!(image_options(&parse(&["--image", "busybox", "--ready-timeout", "18446744073709551615"])).is_err());
        let opts = image_options(&parse(&["--image", "busybox", "--ready-timeout", "4294967295"])).unwrap().unwrap();
        assert_eq!(opts.ready_timeout.as_secs(), u32::MAX as u64);
        for value in ["0", "3", "33", "4294967296", "4294967297", "18446744073709551615"] {
            assert!(template_vcpus(&parse(&["--vcpus", value])).is_err(), "{value}");
        }
        for value in ["1", "2", "32"] {
            assert_eq!(template_vcpus(&parse(&["--vcpus", value])).unwrap().to_string(), value);
        }
    }

    #[test]
    fn kill_validates_names_before_touching_files() {
        let root = crate::test_util::TempDir::new("kill-name");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let failed = root.join("victim.failed");
        std::fs::write(&failed, "keep").unwrap();
        for name in ["../../victim", "", ".hidden", "/tmp/x"] {
            assert_eq!(kill(&host, name).unwrap_err().to_string(), host::check_name(name).unwrap_err().to_string());
        }
        assert_eq!(std::fs::read_to_string(failed).unwrap(), "keep");
    }

    #[test]
    fn invalid_announce_device_is_not_saved() {
        let root = crate::test_util::TempDir::new("announce-device");
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        host.configure(|_| Ok(())).unwrap();
        let before = std::fs::read(host.state.join("host.json")).unwrap();
        let args = parse(&["--announce-dev", "flexvm-no-such-interface"]);
        assert!(host.configure(|c| configure(c, &args)).is_err());
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        assert!(host.cfg.announce_dev.is_none());
    }

    #[test]
    fn standby_zero_validates_template_name_before_saving() {
        let root = crate::test_util::TempDir::new("standby-name");
        let args =
            parse(&["--state", root.join("state").to_str().unwrap(), "--run", root.join("run").to_str().unwrap(), "standby", "--template", ".typo", "0"]);
        assert!(real_main(&args).unwrap_err().to_string().contains("bad template name"));
        assert!(!root.join("state/standby/.typo").exists());
    }

    #[test]
    fn standby_zero_needs_no_artifacts() {
        let root = crate::test_util::TempDir::new("standby-zero");
        let args = parse(&["--state", root.join("state").to_str().unwrap(), "--run", root.join("run").to_str().unwrap(), "standby", "0"]);
        real_main(&args).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("state/standby/default")).unwrap(), "0");
        assert!(!root.join("state/artifacts").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detach_only_removes_flexvm_options_from_child_arguments() {
        let args = parse(&["run", "web", "-d", "--detach", "--cmd", "-d", "--", "tool", "-d", "--detach", "--unknown"]);
        assert!(args.has("detach"));
        assert_eq!(args.get("cmd"), Some("-d"));
        assert_eq!(args.rest, ["tool", "-d", "--detach", "--unknown"]);
        assert_eq!(args.child_args, ["run", "web", "--cmd", "-d", "--", "tool", "-d", "--detach", "--unknown"]);
        let child = Args::parse(args.child_args).unwrap();
        assert!(!child.has("detach"));
        assert_eq!(child.rest, args.rest);
    }

    #[test]
    fn exec_preserves_guest_flags_without_a_separator() {
        let args = parse(&["--state", "/tmp/state", "exec", "web", "tool", "-d", "--detach", "--unknown"]);
        assert_eq!(args.get("state"), Some("/tmp/state"));
        assert!(!args.has("detach"));
        assert_eq!(args.positional, ["exec", "web"]);
        assert_eq!(args.rest, ["tool", "-d", "--detach", "--unknown"]);
        assert_eq!(args.child_args, ["--state", "/tmp/state", "exec", "web", "tool", "-d", "--detach", "--unknown"]);
    }

    #[test]
    fn exec_drops_one_separator() {
        let args = parse(&["exec", "web", "--", "ls", "--", "-d"]);
        assert_eq!(args.rest, ["ls", "--", "-d"]);
    }

    #[test]
    fn missing_or_empty_names_name_the_command() {
        for cmd in ["run", "resume", "exec", "kill", "checkpoint", "migrate", "template"] {
            for argv in [vec![cmd], vec![cmd, ""]] {
                assert_eq!(real_main(&parse(&argv)).unwrap_err().to_string(), format!("{cmd} needs NAME"));
            }
        }
        for flag in ["--standby", "--incoming"] {
            check_applies(&parse(&["run", flag])).unwrap();
        }
    }

    #[test]
    fn unknown_command_names_the_bad_word() {
        assert_eq!(real_main(&parse(&["rnu", "web"])).unwrap_err().to_string(), r#"unknown command "rnu" (see flexvm --help)"#);
    }

    #[test]
    fn unknown_options_and_missing_values_are_errors() {
        for option in ["--typo", "--listen", "-x", "--detach=yes", "--keep-running"] {
            let error = Args::parse(["run", option, "web"].map(String::from)).err().unwrap();
            assert_eq!(error.to_string(), format!("unknown option {option} (see flexvm --help)"));
        }
        let error = Args::parse(["run", "web", "--ip"].map(String::from)).err().unwrap();
        assert_eq!(error.to_string(), "--ip needs a value");
    }

    #[test]
    fn switches_repeated_values_and_internal_flags_parse() {
        let args = parse(&["listen", "--peer", "a:1", "--json", "--peer", "b:2", "--reserve", "123", "--reserve", "456"]);
        assert!(args.has("json"));
        assert_eq!(args.all("peer"), ["a:1", "b:2"]);
        assert_eq!(args.parse_or::<u64>("reserve", 0).unwrap(), 456);
        let args = parse(&["run", "--incoming", "--standby", "--paused"]);
        assert!(args.has("incoming") && args.has("standby") && args.has("paused"));
        assert!(args.rest.is_empty());
    }

    #[test]
    fn a_parse_error_still_finds_its_command() {
        for argv in [&["--bogus", "run", "job"][..], &["run", "job", "--bogus"], &["-x", "resume", "job"], &["--bogus", "restore", "/x", "--ip"]] {
            let (args, e) = Args::parse_partly(argv.iter().map(|a| a.to_string()));
            assert!(e.is_some() && ["run", "resume", "restore"].contains(&args.positional[0].as_str()), "{argv:?}");
        }
        let (args, e) = Args::parse_partly(["--state", "run", "ls"].map(String::from));
        assert!(e.is_none() && args.positional == ["ls"]);
    }

    #[test]
    fn flags_and_words_a_command_does_not_take_are_errors() {
        let err = |a: &[&str]| check_applies(&parse(a)).err().map(|e| e.to_string());
        assert_eq!(err(&["run", "web", "--mem", "512"]).unwrap(), "--mem does not apply to run (see flexvm --help)");
        assert!(err(&["run", "job", "make", "test"]).unwrap().contains("flexvm run job -- make ..."));
        assert!(err(&["resume", "web", "--ip", "10.0.0.1"]).is_some());
        assert!(err(&["restore", "/d", "--template", "t"]).is_some());
        assert!(err(&["kill", "web", "--", "x"]).is_some());
        assert_eq!(err(&["template", "t", "--warm"]).unwrap(), "--warm needs --image");
        assert_eq!(err(&["template", "t", "--init", "/x"]).unwrap(), "--init needs --image");
        assert_eq!(err(&["listen", "1.2.3.4:7070", "--peer", "a:1"]).unwrap(), "--peer does not apply to listen (see flexvm --help)");
        for ok in [
            &["--state", "/s", "run", "web", "--template", "t", "-d", "--", "make", "test"][..],
            &["exec", "web", "ls", "-l"],
            &["template", "t", "--image", "busybox", "--warm", "--ready-port", "80"],
            &["listen", "1.2.3.4:7070"],
            &["config", "--peer", "a:1", "--evict-at", ""],
            &["config"],
            &["restore", "/d", "--ip", "auto", "--paused"],
        ] {
            assert_eq!(err(ok), None, "{ok:?}");
        }
    }

    #[test]
    fn peers_are_validated_and_an_empty_one_clears_them() {
        for good in ["10.0.0.2:7070", "host-b:7070", "[2001:db8::2]:7070"] {
            assert!(host::is_endpoint(good), "{good}");
        }
        for bad in ["10.0.0.2", "notahost", "10.0.0.2:0", "2001:db8::2", "[foo]:1", ":7070", "a:b"] {
            assert!(!host::is_endpoint(bad), "{bad}");
        }
        let mut c = host::Config::default();
        assert!(configure(&mut c, &parse(&["--peer", "192.168.1.11"])).is_err());
        configure(&mut c, &parse(&["--peer", "a:1", "--peer", "b:2", "--evict-at", "5000", "--reserve", "300", "--announce-dev", "none"])).unwrap();
        assert_eq!((c.peers.len(), c.evict_mib, c.reserve_mib), (2, Some(5000), Some(300)));
        // `none`: no announcements, whatever would be derived.
        assert_eq!((c.announce_dev.as_deref(), c.announce_dev()), (Some("none"), None));
        configure(&mut c, &parse(&["--vm-ips", "10.9.0.0/24"])).unwrap();
        assert_eq!((c.peers.len(), c.reserve_mib), (2, Some(300)), "flags not given are kept");
        configure(&mut c, &parse(&["--peer", "", "--evict-at", "", "--reserve", "", "--announce-dev", ""])).unwrap();
        assert!(c.peers.is_empty() && c.evict_mib.is_none() && c.reserve_mib.is_none() && c.announce_dev.is_none());
        assert_eq!(c.reserve(), host::default_reserve());
        // An empty --vm-ips is the default again; DNS is IPv4 (the guest's resolver is set over IPv4).
        configure(&mut c, &parse(&["--vm-ips", "", "--dns", "1.1.1.1"])).unwrap();
        assert_eq!((c.vm_ips.as_str(), c.dns.as_deref()), (host::Config::default().vm_ips.as_str(), Some("1.1.1.1")));
        assert!(configure(&mut c, &parse(&["--dns", "::1"])).is_err());
        // Never a reserve above RAM, nor one that would overflow.
        let total = proc_kb("/proc/meminfo", "MemTotal").unwrap() >> 20;
        configure(&mut c, &parse(&["--reserve", &total.to_string()])).unwrap();
        for over in [total + 1, u64::MAX] {
            let e = configure(&mut c, &parse(&["--reserve", &over.to_string()])).unwrap_err().to_string();
            assert!(e.contains("more than this host's"), "{e}");
        }
    }

    #[test]
    fn listener_configuration_is_published_only_after_binding_and_validation() {
        use std::net::TcpListener;
        let root = crate::test_util::TempDir::new("listen-config");
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        host.configure(|c| {
            c.reserve_mib = Some(321);
            Ok(())
        })
        .unwrap();
        let before = std::fs::read(host.state.join("host.json")).unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = occupied.local_addr().unwrap().to_string();
        assert!(configure_listener(&mut host, Some(&addr), None).is_err());
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        // An activated socket supplies the endpoint even without ADDR; the settings stay.
        let listener = configure_listener(&mut host, None, Some(occupied)).unwrap();
        let saved = Host::open(&host.state, &host.run).unwrap();
        assert_eq!(saved.cfg.listen.as_deref(), Some(addr.as_str()));
        assert_eq!(saved.cfg.advertise().unwrap().as_deref(), Some(addr.as_str()));
        assert_eq!(saved.cfg.underlay(), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(saved.cfg.reserve_mib, Some(321));
        drop(listener);
        // A wildcard one's underlay is derived: loopback with no peers elsewhere, and
        // none with one whose address is unknown (never loopback): refused.
        let wildcard = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = wildcard.local_addr().unwrap().port();
        drop(configure_listener(&mut host, None, Some(wildcard)).unwrap());
        assert_eq!(host.cfg.advertise().unwrap(), Some(format!("127.0.0.1:{port}")));
        host.configure(|c| configure(c, &parse(&["--peer", "flexvm-no-such-host.invalid:7070"]))).unwrap();
        let before = std::fs::read(host.state.join("host.json")).unwrap();
        let wildcard = TcpListener::bind("0.0.0.0:0").unwrap();
        assert!(configure_listener(&mut host, None, Some(wildcard)).unwrap_err().to_string().contains("--underlay"));
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        // An ADDR other than the activated socket's is refused, saving nothing; its own is kept.
        let before = std::fs::read(host.state.join("host.json")).unwrap();
        let activated = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
        let e = configure_listener(&mut host, Some(&other), Some(activated)).unwrap_err().to_string();
        assert!(e.contains("the activated socket listens on 127.0.0.1:") && e.contains(&other), "{e}");
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        let activated = TcpListener::bind("127.0.0.1:0").unwrap();
        let own = activated.local_addr().unwrap().to_string();
        drop(configure_listener(&mut host, Some(&own), Some(activated)).unwrap());
        assert_eq!(host.cfg.listen.as_deref(), Some(own.as_str()));
        // A wildcard socket listens on every address with its port.
        let wildcard = std::net::SocketAddr::from(([0, 0, 0, 0], 7070));
        assert!(activated_at("10.1.2.3:7070", wildcard, false).is_ok());
        assert!(activated_at("10.1.2.3:7071", wildcard, false).is_err());
        assert!(activated_at("127.0.0.1:7070", std::net::SocketAddr::from(([10, 1, 2, 3], 7070)), false).is_err());
        // An IPv4 wildcard takes no IPv6 connections; an IPv6 one IPv4 ones only without IPV6_V6ONLY.
        assert!(activated_at("[::1]:7070", wildcard, false).is_err());
        let v6 = "[::]:7070".parse().unwrap();
        assert!(activated_at("[::1]:7070", v6, true).is_ok());
        assert!(activated_at("10.1.2.3:7070", v6, false).is_ok());
        assert!(activated_at("10.1.2.3:7070", v6, true).is_err());
        assert!(activated_at("[::ffff:10.1.2.3]:7070", wildcard, false).is_ok());
        // An IPv6 listener needs no IPv4 underlay.
        if let Ok(v6) = TcpListener::bind("[::1]:0") {
            drop(configure_listener(&mut host, None, Some(v6)).unwrap());
        }
        // Port 0 binds, but peers could not be told the port.
        assert!(configure_listener(&mut host, Some("127.0.0.1:0"), None).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn kill_refuses_a_committed_source_but_signals_a_reconciling_one() {
        use std::os::unix::process::ExitStatusExt;
        let root = crate::test_util::TempDir::new("kill-source");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let name = host.take_name("moving", false).unwrap();
        let mut child = std::process::Command::new("sleep");
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut child, || {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                Ok(())
            });
        }
        let mut child = child.arg("60").spawn().unwrap();
        let mut entry = host::Entry { name: "moving".into(), ident: host::Ident::of(child.id()).unwrap(), state: "source".into(), ..host::Entry::default() };
        // Hold the name on the child's behalf, with its identity in both records.
        std::fs::write(host.vms("moving", "lock").unwrap(), serde_json::to_vec(&entry.ident).unwrap()).unwrap();
        name.publish(&entry).unwrap();
        let refused = kill(&host, "moving").unwrap_err().to_string();
        assert_eq!(refused, "vm moving is the source of a migration in progress; it ends once the target has its memory (kill it where it runs)");
        assert!(child.try_wait().unwrap().is_none());
        entry.state = "reconciling".into();
        name.publish(&entry).unwrap();
        let result = kill(&host, "moving");
        // Reap even on failure, so a failed assertion does not leave the child behind.
        let _ = child.kill();
        let status = child.wait().unwrap();
        result.unwrap();
        assert_eq!(status.signal(), Some(libc::SIGINT));
        drop(name);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn frames(fs: &[(u8, &[u8])]) -> Vec<u8> {
        fs.iter().flat_map(|(kind, data)| [&[*kind][..], &(data.len() as u32).to_le_bytes(), data].concat()).collect()
    }

    #[derive(Debug)]
    struct ExecInput {
        bytes: std::io::Cursor<Vec<u8>>,
        reads: usize,
        timeouts: std::cell::RefCell<Vec<Duration>>,
    }

    impl ExecInput {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes: std::io::Cursor::new(bytes), reads: 0, timeouts: Default::default() }
        }
    }

    impl Read for ExecInput {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            self.bytes.read(buf)
        }
    }

    impl util::Timed for ExecInput {
        fn read_timeout(&self, t: Duration) -> std::io::Result<()> {
            self.timeouts.borrow_mut().push(t);
            Ok(())
        }
        fn write_timeout(&self, _: Duration) -> std::io::Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn exec_reply_keeps_buffered_frames_and_switches_timeouts() {
        let session = Mutex::new(Session { id: "test-id".into(), started: false, offset: 0, exit: None });
        let data = frames(&[
            (guest::FRAME_MSG, b"test-id"),
            (guest::FRAME_STDOUT, &[&0u64.to_le_bytes()[..], b"hello"].concat()),
            (guest::FRAME_EXIT, &[&5u64.to_le_bytes()[..], &7i32.to_le_bytes()].concat()),
        ]);
        let input = ExecInput::new([b"{\"ok\":true}\n", data.as_slice()].concat());
        let mut r = exec_stream(input, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(r.buffer(), data, "the reply and frames should be read together");
        assert_eq!(r.get_ref().timeouts.borrow().as_slice().len(), 2);
        assert_eq!(r.get_ref().timeouts.borrow().last(), Some(&Duration::from_secs(3)));
        let mut stdout = Vec::new();
        let result = exec_frames(&mut r, &session, &mut stdout, &mut Vec::new(), &mut Instant::now()).unwrap();
        assert!(matches!(result, StreamEnd::Exit(7)));
        assert_eq!(stdout, b"hello");
        assert_eq!(r.get_ref().reads, 1, "reply and frames need just one underlying read");
    }

    #[test]
    fn exec_reply_obeys_deadline_and_reports_refusals() {
        let err = exec_stream(ExecInput::new(Vec::new()), Instant::now()).unwrap_err();
        assert!(err.to_string().contains("deadline passed"));
        let input = ExecInput::new(b"{\"ok\":false,\"error\":\"refused\"}\n".to_vec());
        assert_eq!(exec_stream(input, Instant::now() + Duration::from_secs(1)).unwrap_err().to_string(), "refused");
    }

    #[test]
    fn started_session_fails_promptly_when_vm_is_gone() {
        let root = crate::test_util::TempDir::new("exec-dead");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let session = Mutex::new(Session { id: "test-id".into(), started: true, offset: 0, exit: None });
        let start = Instant::now();
        let error = exec_session(&host, "gone", "true", &session, false).unwrap_err();
        assert!(!error.to_string().contains("recovery timed out"), "{error}");
        assert!(start.elapsed() < Duration::from_secs(5));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_refuses_a_vm_made_again_under_the_name() {
        let ip = "10.0.0.2".parse().unwrap();
        let mut vm = None;
        same_instance("web", Instance { ip, gen: 7 }, &mut vm).unwrap();
        // A suspend and resume, or a migration, keeps the address's generation.
        same_instance("web", Instance { ip, gen: 7 }, &mut vm).unwrap();
        let e = same_instance("web", Instance { ip, gen: 8 }, &mut vm).unwrap_err();
        assert!(e.is::<Replaced>() && e.to_string().contains("generation 7, now 10.0.0.2 generation 8"), "{e}");
        assert!(same_instance("web", Instance { ip: "10.0.0.3".parse().unwrap(), gen: 7 }, &mut vm).unwrap_err().is::<Replaced>());
        assert_eq!(vm, Some(Instance { ip, gen: 7 }), "the first stays");
    }

    #[test]
    fn a_vm_whose_registry_entry_is_not_its_listeners_is_not_sent_the_request() {
        use std::io::BufRead;
        use std::os::unix::net::UnixListener;
        let root = crate::test_util::TempDir::new("exec-same");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let _name = host.take_name("own", false).unwrap();
        let l = UnixListener::bind(host.sock("own").unwrap()).unwrap();
        // This process listens: a VM's own main command, sent without a check.
        let mut vm = None;
        let c = connect_same(&host, "own", &json!({"op": "x"}), Instant::now() + Duration::from_secs(5), &mut vm).unwrap();
        assert_eq!(util::peer_pid(&c).unwrap(), std::process::id());
        let mut line = String::new();
        BufReader::new(l.accept().unwrap().0).read_line(&mut line).unwrap();
        assert_eq!(line, "{\"op\":\"x\"}\n");
        assert_eq!(vm, None);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resumes_partial_frame_without_duplicates() {
        let at = |o: u64, d: &[u8]| [&o.to_le_bytes()[..], d].concat();
        let mut first = frames(&[(guest::FRAME_MSG, b"test-id"), (guest::FRAME_STDOUT, &at(0, b"abc"))]);
        first.extend_from_slice(&[guest::FRAME_STDERR, 11, 0, 0, 0]);
        first.extend_from_slice(&at(3, b"d"));
        let session = Mutex::new(Session { id: "test-id".into(), started: false, offset: 0, exit: None });
        let (mut stdout, mut stderr, mut deadline) = (Vec::new(), Vec::new(), Instant::now());
        let mut run = |input: Vec<u8>| exec_frames(&mut input.as_slice(), &session, &mut stdout, &mut stderr, &mut deadline).unwrap();
        assert!(matches!(run(first), StreamEnd::Disconnected(_)));
        let resumed = frames(&[
            (guest::FRAME_MSG, b"test-id"),
            (guest::FRAME_STDERR, &at(3, b"def")),
            (guest::FRAME_EXIT, &[&6u64.to_le_bytes()[..], &7i32.to_le_bytes()].concat()),
        ]);
        assert!(matches!(run(resumed), StreamEnd::Exit(7)));
        let s = session.lock().unwrap();
        assert!(s.started && s.offset == 6 && s.exit == Some(7) && stdout == b"abc" && stderr == b"def");
    }

    #[test]
    fn a_reattach_to_a_closed_session_ends_at_once() {
        let session = Mutex::new(Session { id: "test-id".into(), started: true, offset: 5, exit: None });
        // Within one attachment, a closed session is only a lost connection, retried.
        let input = frames(&[(guest::FRAME_MSG, b"test-id"), (guest::FRAME_MSG, b"error: session closed")]);
        let end = exec_frames(&mut input.as_slice(), &session, &mut Vec::new(), &mut Vec::new(), &mut Instant::now()).unwrap();
        assert!(matches!(end, StreamEnd::Disconnected(_)));
        let input = frames(&[(guest::FRAME_MSG, b"error: session closed")]);
        let e = exec_frames(&mut input.as_slice(), &session, &mut Vec::new(), &mut Vec::new(), &mut Instant::now()).err().unwrap();
        assert!(e.to_string().contains("after byte 5 of output"), "{e}");
    }

    #[test]
    fn an_agent_without_sessions_says_to_rebuild() {
        let session = Mutex::new(Session { id: "test-id".into(), started: false, offset: 0, exit: None });
        let input = frames(&[(guest::FRAME_MSG, b"unknown request \"SESSION\"")]);
        let e = exec_frames(&mut input.as_slice(), &session, &mut Vec::new(), &mut Vec::new(), &mut Instant::now()).err().unwrap();
        assert_eq!(e.to_string(), "unknown request \"SESSION\"; rebuild the rootfs and its templates");
    }
}

#[cfg(test)]
mod test_util;
