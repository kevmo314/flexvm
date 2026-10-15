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
use std::path::PathBuf;
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
  flexvm listen [ADDR] [--peer HOST:PORT]... [--vm-ips CIDR|FIRST-LAST] [--underlay IP]
                [--announce-dev IFACE] [--dns IP] [--reserve MIB] [--evict-at MIB] [--prefix P]
                                     configure this host and take migrations from peers
  flexvm config [--peer HOST:PORT]... [--vm-ips ...] [--underlay IP] [--announce-dev IFACE] [--dns IP]
                [--reserve MIB] [--evict-at MIB] [--prefix P]
                                     configure this host without a listener (no flags: show it);
                                     --peer replaces the list, an empty value unsets a setting
  flexvm standby [--template T] [N]  keep N VMs restored and paused, so run takes ~5 ms (no N: show)
  flexvm template NAME [--vcpus N] [--mem MIB] [--max MIB] [--plug MIB] [--image REF ...]
                                     build a template (see README)
  flexvm bench ...                   latency benchmarks (see README)

options: --state DIR (FLEXVM_STATE, /var/lib/flexvm), --run DIR (FLEXVM_RUN, /run/flexvm),
         --artifacts DIR (FLEXVM_ARTIFACTS, ./artifacts), --templates DIR (FLEXVM_TEMPLATES),
         --image-cache DIR, --version
run, resume and restore exit with the VM's command's status, 128+signal, 125 when flexvm
fails, 124 when the VM dies
";

const SWITCHES: &[&str] = &["warm", "stop", "paused", "incremental", "standby", "incoming", "json", "detach", "force", "help", "version"];

const VALUE_FLAGS: &[&str] = &[
    "state",
    "run",
    "artifacts",
    "templates",
    "image-cache",
    "template",
    "ip",
    "name",
    "peer",
    "vm-ips",
    "underlay",
    "announce-dev",
    "dns",
    "reserve",
    "evict-at",
    "prefix",
    "vcpus",
    "mem",
    "max",
    "plug",
    "image",
    "init",
    "entrypoint",
    "cmd",
    "env",
    "workdir",
    "user",
    "ready-port",
    "ready-cmd",
    "ready-timeout",
    "image-staging",
    "max-download-mib",
    "max-unpacked-mib",
    "max-file-mib",
    "max-entries",
    "to",
    "to-state",
    "to-run",
    "timeout",
    "lifecycle",
    "iterations",
    "warmup",
    "dirty-mib",
    "settle-ms",
    "ready-http",
];

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
                    } else if VALUE_FLAGS.contains(&f) {
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

    fn path(&self, flag: &str, env: &str, default: &str) -> PathBuf {
        self.get(flag).map(PathBuf::from).or_else(|| std::env::var_os(env).map(PathBuf::from)).unwrap_or_else(|| default.into())
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
    if let Err(e) = error.map_or_else(|| real_main(&args), Err) {
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
const GLOBAL: &[&str] = &["state", "run", "artifacts", "templates", "image-cache", "help", "version"];

/// What `template --image` takes.
const IMAGE_FLAGS: &[&str] = &[
    "entrypoint",
    "cmd",
    "env",
    "workdir",
    "user",
    "warm",
    "ready-port",
    "ready-cmd",
    "ready-timeout",
    "image-staging",
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
    ("listen", 2, CONFIG_FLAGS),
    ("config", 1, CONFIG_FLAGS),
    ("standby", 2, &["template"]),
    ("template", 2, &["vcpus", "mem", "max", "plug", "image", "init"]),
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
    let Some(&(_, most, flags)) = COMMANDS.iter().find(|(c, ..)| c == cmd) else { return Ok(()) };
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
            "config" => "; the listen address is flexvm listen's".into(),
            _ => " (see flexvm --help)".into(),
        };
        bail!("{cmd} does not take {extra:?}{hint}");
    }
    if !args.rest.is_empty() && cmd != "run" && cmd != "exec" {
        bail!("{cmd} takes no -- CMD");
    }
    Ok(())
}

pub fn open_host(args: &Args) -> Result<Host> {
    Host::open(&args.path("state", "FLEXVM_STATE", "/var/lib/flexvm"), &args.path("run", "FLEXVM_RUN", "/run/flexvm"))
}

/// Exported for the VM processes this one starts.
fn paths(args: &Args) -> Result<Paths> {
    let artifacts = args.path("artifacts", "FLEXVM_ARTIFACTS", "artifacts");
    let templates = args.get("templates").map(PathBuf::from).or_else(|| std::env::var_os("FLEXVM_TEMPLATES").map(PathBuf::from));
    std::env::set_var("FLEXVM_ARTIFACTS", std::path::absolute(&artifacts)?);
    if let Some(t) = &templates {
        std::env::set_var("FLEXVM_TEMPLATES", std::path::absolute(t)?);
    }
    Paths::new(&artifacts, templates)
}

fn real_main(args: &Args) -> Result<()> {
    if args.has("help") {
        print!("{USAGE}");
        return Ok(());
    }
    if args.has("version") {
        println!("flexvm {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    check_applies(args)?;
    let _ = paths(args);
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
            vmproc::main(open_host(args)?, paths(args)?, Start::Incoming { req }, None)
        }
        Some("run") => run(args, name, template),
        // A paused VM gets SIGCONT; a suspended one a new process.
        Some("resume") if open_host(args)?.signal(name, libc::SIGCONT).is_ok() => Ok(()),
        Some("resume") => start(args, name, Start::Resume { name: name.into() }),
        Some("restore") => {
            let dir = std::path::absolute(pos.get(1).ok_or("restore needs DIR")?)?;
            // A detached restore logs to the VM's name, which the checkpoint has without --name.
            let label = match args.get("name") {
                Some(name) => name.to_string(),
                None if args.has("detach") => checkpoint::Checkpoint::open(&dir)?.manifest.name,
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
            util::flush_log_on(&[libc::SIGTERM, libc::SIGINT, libc::SIGHUP]);
            let mut host = open_host(args)?;
            let listener = configure_listener(&mut host, args, pos.get(1).copied(), listen::activated())?;
            listen::main(host, listener)
        }
        Some("config") => {
            let mut host = open_host(args)?;
            // A prefix change is refused while any VM process or tap may use the old one (`Host::configure`).
            if CONFIG_FLAGS.iter().any(|f| args.has(f)) {
                host.configure(|c| configure(c, args, None))?;
            }
            print(serde_json::to_value(&host.cfg)?)
        }
        Some("standby") if name.is_empty() => print(standby::show(&open_host(args)?)),
        Some("standby") => {
            let host = open_host(args)?;
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
fn configure_listener(host: &mut Host, args: &Args, addr: Option<&str>, activated: Option<std::net::TcpListener>) -> Result<std::net::TcpListener> {
    let mut listener = None;
    host.configure(|c| {
        configure(c, args, addr)?;
        let bound = match activated {
            // Without ADDR, an activated socket says where this host listens.
            Some(l) => {
                if addr.is_none() {
                    c.listen = Some(l.local_addr()?.to_string());
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

/// What `configure` sets, besides the listen address.
const CONFIG_FLAGS: &[&str] = &["peer", "vm-ips", "underlay", "announce-dev", "dns", "reserve", "evict-at", "prefix"];

/// Flags not given keep their configured values; an empty --underlay,
/// --announce-dev, --dns or --evict-at unsets it. --peers replace the list
/// (`--peer ''` empties it).
fn configure(c: &mut host::Config, args: &Args, addr: Option<&str>) -> Result<()> {
    if let Some(a) = addr {
        c.listen = Some(a.into());
    }
    if args.has("peer") {
        c.peers = args.all("peer").into_iter().filter(|p| !p.is_empty()).collect();
        if let Some(p) = c.peers.iter().find(|p| !host::is_endpoint(p)) {
            bail!("bad --peer {p:?}: give HOST:PORT, a peer's flexvm listen address");
        }
    }
    if let Some(r) = args.get("vm-ips") {
        net::IpRange::parse(r)?;
        c.vm_ips = r.into();
    }
    if let Some(u) = args.get("underlay") {
        c.underlay = (!u.is_empty()).then(|| u.parse()).transpose().map_err(|_| format!("bad --underlay {u:?}"))?;
    }
    if let Some(d) = args.get("announce-dev") {
        c.announce_dev = (!d.is_empty()).then(|| d.into());
    }
    if let Some(d) = args.get("dns") {
        c.dns = (!d.is_empty()).then(|| d.parse::<std::net::IpAddr>().map(|_| d.into())).transpose().map_err(|_| format!("bad --dns {d:?}"))?;
    }
    c.reserve_mib = args.parse_or("reserve", c.reserve_mib)?;
    if args.has("evict-at") {
        c.evict_mib = (args.get("evict-at") != Some("")).then(|| args.parse_or("evict-at", 0)).transpose()?;
    }
    if let Some(e) = c.evict_mib.filter(|&e| e < c.reserve_mib) {
        crate::log!("flexvm: the eviction mark {e} MiB is under the {} MiB reserve: eviction starts at the reserve", c.reserve_mib);
    }
    if !c.peers.is_empty() && c.vm_ips == host::Config::default().vm_ips {
        crate::log!("flexvm: warning: --vm-ips is the default {}; each peer needs a range of its own", c.vm_ips);
    }
    if let Some(p) = args.get("prefix") {
        host::check_prefix(p).map_err(|e| format!("--prefix: {e}"))?;
        c.prefix = p.into();
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
    match taken {
        Some((v, _)) if log.is_some() => print(v),
        Some((v, conn)) => {
            crate::log!("{v}");
            let id = host::Ident { pid: v["pid"].as_u64().unwrap_or(0) as u32, start: v["start"].as_u64().unwrap_or(0), boot: host::boot_id().into() };
            follow(conn, id)
        }
        None if log.is_some() => spawn_detached(&host, name, args),
        None => vmproc::main(host, paths, Start::Run { name: name.into(), template: template.into(), ip, cmd }, notify_fd()),
    }
}

/// What a foreground `run` that claimed a standby VM forwards to it (SIGHUP is ignored).
const FOLLOW_SIGNALS: [i32; 6] = [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGCONT, libc::SIGHUP];

fn start(args: &Args, name: &str, s: Start) -> Result<()> {
    if args.has("detach") {
        return spawn_detached(&open_host(args)?, name, args);
    }
    vmproc::main(open_host(args)?, paths(args)?, s, notify_fd())
}

fn log_file(host: &Host, name: &str) -> Result<std::fs::File> {
    host::check_name(name)?;
    // Opened and marked written holding the logs lock (shared): garbage
    // collection removes only a quiet log, holding it exclusively.
    let _logs = host.logs_lock(libc::LOCK_SH)?;
    let f = std::fs::OpenOptions::new().create(true).append(true).open(host.vms(name, "log"))?;
    f.set_modified(std::time::SystemTime::now())?;
    Ok(f)
}

fn spawn_detached(host: &Host, name: &str, args: &Args) -> Result<()> {
    let (r, w) = std::os::unix::net::UnixStream::pair()?;
    util::spawn_self(&args.child_args, &log_file(host, name)?, w.as_raw_fd(), &[("FLEXVM_NOTIFY_FD", "3")])?;
    drop(w);
    let reply = recv_json(&mut BufReader::new(r))?.ok_or_else(|| format!("the vm process failed to start (see {})", host.vms(name, "log").display()))?;
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

fn kill(host: &Host, name: &str) -> Result<()> {
    // Reconciling sources accept SIGINT too; the process records the owed outcome before ending.
    if host.entry(name).is_ok_and(|e| e.state == "source") {
        return Err(format!("vm {name} is the source of a migration in progress; it ends once the target has its memory (kill it where it runs)").into());
    }
    if let Ok(vm) = host.signal(name, libc::SIGINT) {
        if !vm.wait(Duration::from_secs(30)) {
            return Err(format!("vm {name} is still there; see {}", host.vms(name, "log").display()).into());
        }
        // A suspend that finished first is undone: the kill wins.
        if !host.suspended(name).exists() {
            return Ok(());
        }
    }
    if host.suspended(name).exists() {
        let _lock = host.take_name(name, true)?;
        // Taking the name removed it if it was not a suspended VM (an interrupted suspend's or resume's).
        if !host.suspended(name).exists() {
            return Ok(());
        }
        return lifecycle::revoke(host, name)?;
    }
    if !host.alive(name) && std::fs::remove_file(host.vms(name, "failed")).is_ok() {
        return Ok(());
    }
    if host.alive(name) {
        return Err(format!(
            "vm {name:?} is starting or its registry is unavailable; retry flexvm kill {name} once it is ready, or see {}",
            host.vms(name, "log").display()
        )
        .into());
    }
    match std::fs::read_to_string(host.vms(name, "moved")) {
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
        vms.push(json!({"name": n, "state": "failed", "error": std::fs::read_to_string(host.vms(&n, "failed")).unwrap_or_default()}));
    }
    if as_json {
        return print(json!(vms));
    }
    let row = |c: [&str; 9]| println!("{:<16} {:<15} {:<10} {:<12} {:>8} {:>4} {:>8} {:>8} {}", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8]);
    // STARVED: refused memory here and throttled (moved to a peer if there is one).
    row(["NAME", "IP", "TEMPLATE", "STATE", "PID", "VCPU", "RSS MiB", "MAX MiB", "STARVED"]);
    for v in &vms {
        let s = |k: &str| v[k].as_str().map(String::from).or_else(|| v[k].as_u64().map(|n| n.to_string())).unwrap_or_default();
        let [a, b, c, d, e, f, g, h] = ["name", "ip", "template", "state", "pid", "vcpus", "rss_mib", "max_mib"].map(s);
        let starved = if v["starved"].as_bool() == Some(true) { "yes" } else { "" };
        row([&a, &b, &c, &d, &e, &f, &g, &h, starved]);
    }
    Ok(())
}

pub fn print(v: Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

fn build_template(args: &Args, name: &str) -> Result<()> {
    host::check_name(name)?;
    // Firecracker wants 1 or an even count of vCPUs, at most 32.
    let cpus = (util::host_cpus() as u64).min(32);
    let cpus = if cpus > 1 { cpus & !1 } else { 1 };
    let mut paths = paths(args)?;
    let image = image_options(args)?
        .map(|opts| {
            let artifacts = paths.kernel.parent().ok_or("bad artifacts dir")?.to_path_buf();
            let cache = args.get("image-cache").map_or(artifacts.join("images"), PathBuf::from);
            let init = args.get("init").map_or(artifacts.join("flexvm-init"), PathBuf::from);
            let (rootfs, meta) = image::prepare(&cache, &init, &opts)?;
            paths.rootfs = rootfs;
            Ok::<_, util::Error>(meta)
        })
        .transpose()?;
    let max = args.parse_or("max", proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0) >> 20)?;
    let (cpus, mem, plug) = (args.parse_or("vcpus", cpus)? as u32, args.parse_or("mem", template::base_mib(max))?, args.parse_or("plug", template::PLUG_MIB)?);
    // Named and made under the host lock, so a prefix change sees it (`Host::prefix_in_use`).
    let host = open_host(args)?;
    let me = host::Ident::me();
    // Unlocked, as these are this host's taps of dead processes (by their alias).
    host::clear_taps(&host.run, &me);
    // Interrupted, the build stops at its next step and removes its tap and staging (gigabytes);
    // a second signal ends flexvm at once, and the next build removes the staging.
    let set = util::block_signals(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP]);
    std::thread::spawn(move || {
        let sig = util::wait_signal(&set);
        log!("flexvm: stopping the template build; it cleans up first");
        template::interrupt(sig);
        // Kept alive to take the next one, now with its default action.
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
        loop {
            std::thread::park();
        }
    });
    let tap = {
        let _l = host.lock()?;
        let tap = template::tap(&host.tap_prefix()?);
        let root = if unsafe { libc::geteuid() } == 0 { "" } else { " (run flexvm as root)" };
        net::create_tap(&tap, &host::tap_alias(&host.run, &me)).map_err(|e| format!("{e}{root}"))?;
        tap
    };
    template::create(&paths, name, cpus, mem, max, plug, image, &tap)
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
    Ok(Some(image::Options {
        image: src.into(),
        entrypoint: args.get("entrypoint").map(image::parse_argv).transpose()?,
        cmd: args.get("cmd").map(image::parse_argv).transpose()?,
        env: args.all("env"),
        workdir: args.get("workdir").map(String::from),
        user: args.get("user").map(String::from),
        warm,
        ready,
        ready_timeout: Duration::from_secs(args.parse_or("ready-timeout", 120)?),
        staging: args.get("image-staging").unwrap_or(image::STAGING).into(),
        limits: image::Limits {
            download: args.parse_or("max-download-mib", d.download >> 20)? << 20,
            unpacked: args.parse_or("max-unpacked-mib", d.unpacked >> 20)? << 20,
            file: args.parse_or("max-file-mib", d.file >> 20)? << 20,
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
        Ok(Session { id: guest::session_id()?, started: false, offset: 0, exit: None })
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
            match recv_json(&mut BufReader::new(c))? {
                Some(r) if r["ok"] == json!(true) => Ok(()),
                Some(r) => Err(r["error"].as_str().unwrap_or("session close failed").into()),
                None => Err("vm hung up".into()),
            }
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
    let set = util::block_signals(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP]);
    let (stop, vm) = (close.clone(), name.to_string());
    std::thread::spawn(move || {
        let sig = util::wait_signal(&set);
        // A second one ends flexvm at once.
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
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
            let e = e.to_string();
            let why = if e.contains("session still running") { "its guest agent is too old to stop it; rebuild the rootfs" } else { &e };
            log!("flexvm: the command may still be running in vm {vm}: {why}");
        }
        util::exit(128 + sig);
    });
    let result = exec_session(host, name, cmd, session, false);
    // On an error too (a closed stdout, as with `| head`): the command would run on, holding its slot.
    // Best effort: the guest closes a session whose client left anyway, a minute after it finished
    // (ten, if it still runs).
    let _ = close();
    result
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
        let stream = vmproc::connect(host, name, &req, &[], at).and_then(|c| {
            // Byte by byte: the frames after it stay unread.
            let reply = recv_json(&mut BufReader::with_capacity(1, util::By { s: &c, at }))?.ok_or("vm hung up")?;
            if reply["ok"] != json!(true) {
                return Err(reply["error"].as_str().unwrap_or("exec failed").to_string().into());
            }
            // The guest heartbeats every second, even for silent commands.
            c.set_read_timeout(Some(Duration::from_secs(3)))?;
            Ok(BufReader::new(c))
        });
        // Locked per write, never across a read: a checkpoint takes stdout's lock too.
        match stream.map(|mut r| exec_frames(&mut r, session, &mut std::io::stdout(), &mut std::io::stderr(), &mut deadline)) {
            Ok(Err(e)) => return Err(e),
            Ok(Ok(StreamEnd::Exit(code))) => return Ok(code),
            Ok(Ok(StreamEnd::Disconnected(why))) => error = why,
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
                    if let Ok(to) = std::fs::read_to_string(host.vms(name, "moved")) {
                        return Err(format!("vm {name} moved to {to}; the command keeps running there (session {id})").into());
                    }
                    if !started {
                        return Err(e);
                    }
                }
                error = msg;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!("exec recovery timed out: {error}").into())
}

enum StreamEnd {
    Exit(i32),
    Disconnected(String),
}

/// Tracks the session's offset so a reattach resumes without duplicates.
fn exec_frames(r: &mut impl Read, session: &Mutex<Session>, stdout: &mut impl Write, stderr: &mut impl Write, deadline: &mut Instant) -> Result<StreamEnd> {
    let id = session.lock().unwrap().id.clone();
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
            guest::FRAME_MSG if data == id.as_bytes() => s.started = true,
            guest::FRAME_MSG if data == b"waiting" && s.started => {}
            // Before the id echo the request itself failed: not retried.
            guest::FRAME_MSG if !s.started => return Err(String::from_utf8_lossy(&data).into_owned().into()),
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
    fn standby_zero_needs_no_artifacts() {
        let root = std::env::temp_dir().join(format!("flexvm-standby-zero-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let args = parse(&[
            "--state",
            root.join("state").to_str().unwrap(),
            "--run",
            root.join("run").to_str().unwrap(),
            "--artifacts",
            root.join("missing").to_str().unwrap(),
            "standby",
            "0",
        ]);
        real_main(&args).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("state/standby/default")).unwrap(), "0");
        assert!(!root.join("missing").exists());
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
    fn unknown_options_and_missing_values_are_errors() {
        for option in ["--typo", "-x", "--detach=yes", "--keep-running"] {
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
        for ok in [
            &["--state", "/s", "run", "web", "--template", "t", "-d", "--", "make", "test"][..],
            &["exec", "web", "ls", "-l"],
            &["template", "t", "--image", "busybox", "--warm", "--ready-port", "80", "--image-cache", "/c"],
            &["listen", "1.2.3.4:7070", "--peer", "a:1", "--evict-at", ""],
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
        assert!(configure(&mut c, &parse(&["--peer", "192.168.1.11"]), None).is_err());
        configure(&mut c, &parse(&["--peer", "a:1", "--peer", "b:2", "--evict-at", "5000"]), None).unwrap();
        assert_eq!((c.peers.len(), c.evict_mib), (2, Some(5000)));
        configure(&mut c, &parse(&["--peer", "", "--evict-at", ""]), None).unwrap();
        assert!(c.peers.is_empty() && c.evict_mib.is_none());
    }

    #[test]
    fn listener_configuration_is_published_only_after_binding_and_validation() {
        use std::net::TcpListener;
        let root = std::env::temp_dir().join(format!("flexvm-listen-config-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        host.configure(|c| {
            c.reserve_mib = 321;
            Ok(())
        })
        .unwrap();
        let before = std::fs::read(host.state.join("host.json")).unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = occupied.local_addr().unwrap().to_string();
        let args = parse(&["--reserve", "456"]);
        assert!(configure_listener(&mut host, &args, Some(&addr), None).is_err());
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        assert_eq!(host.cfg.reserve_mib, 321);
        // An activated socket supplies the endpoint even without ADDR.
        let listener = configure_listener(&mut host, &args, None, Some(occupied)).unwrap();
        let saved = Host::open(&host.state, &host.run).unwrap();
        assert_eq!(saved.cfg.listen.as_deref(), Some(addr.as_str()));
        assert_eq!(saved.cfg.advertise().unwrap().as_deref(), Some(addr.as_str()));
        assert_eq!(saved.cfg.underlay(), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(saved.cfg.reserve_mib, 456);
        drop(listener);
        let before = std::fs::read(host.state.join("host.json")).unwrap();
        let wildcard = TcpListener::bind("0.0.0.0:0").unwrap();
        assert!(configure_listener(&mut host, &args, None, Some(wildcard)).is_err());
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        // Port 0 binds, but peers could not be told the port.
        assert!(configure_listener(&mut host, &args, Some("127.0.0.1:0"), None).is_err());
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn kill_refuses_a_committed_source_but_signals_a_reconciling_one() {
        use std::os::unix::process::ExitStatusExt;
        let root = std::env::temp_dir().join(format!("flexvm-kill-source-{}", std::process::id()));
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
        std::fs::write(host.vms("moving", "lock"), serde_json::to_vec(&entry.ident).unwrap()).unwrap();
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
}
