mod bench;
mod checkpoint;
mod compat;
mod cow;
mod crc32c;
mod fc;
mod guest;
mod hold;
mod host;
mod image;
mod lifecycle;
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
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
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
  flexvm ls                          list VMs (with their pids)
  flexvm exec NAME CMD...            run a shell command in a VM
  kill -TSTP PID / kill -CONT PID    pause / resume a VM (Ctrl-Z works in the foreground)
  kill PID                           suspend a VM to disk (SIGTERM); its memory is freed
  flexvm resume NAME [-d]            bring a suspended VM back
  flexvm kill NAME                   destroy a VM, running or suspended (Ctrl-C works too)
  flexvm checkpoint NAME DIR [--stop] [--incremental]
                                     write the VM's state to DIR (a new directory)
  flexvm restore DIR [--name N] [--ip IP|auto] [--paused] [-d]
                                     start a VM from a checkpoint
  flexvm migrate NAME HOST:PORT      live-migrate a VM to the host listening there
  flexvm listen [ADDR] [--peer ADDR]... [--vm-ips CIDR|FIRST-LAST] [--underlay IP]
                [--announce-dev IFACE] [--dns IP] [--reserve MIB] [--prefix P]
                                     configure this host and take migrations from peers
  flexvm standby [--template T] N    keep N VMs restored and paused, so run takes ~5 ms
  flexvm template NAME [--vcpus N] [--mem MIB] [--max MIB] [--plug MIB] [--image REF ...]
                                     build a template (see README)
  flexvm bench ...                   latency benchmarks (see README)

options: --state DIR (FLEXVM_STATE, /var/lib/flexvm), --run DIR (FLEXVM_RUN, /run/flexvm),
         --artifacts DIR (FLEXVM_ARTIFACTS, ./artifacts), --templates DIR, --image-cache DIR
";

/// Flags that take no value.
const SWITCHES: &[&str] = &["warm", "stop", "paused", "incremental", "standby", "incoming", "json"];

pub struct Args {
    positional: Vec<String>,
    flags: Vec<(String, String)>,
    /// What follows `--` (or `exec NAME`).
    rest: Vec<String>,
}

impl Args {
    fn parse() -> Args {
        let mut a = Args { positional: Vec::new(), flags: Vec::new(), rest: Vec::new() };
        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            if arg == "--" {
                a.rest.extend(it.by_ref());
            } else if arg == "-d" {
                a.flags.push(("detach".into(), "1".into()));
            } else if let Some(flag) = arg.strip_prefix("--") {
                let value = if SWITCHES.contains(&flag) { "1".into() } else { it.next().unwrap_or_default() };
                a.flags.push((flag.to_string(), value));
            } else {
                a.positional.push(arg);
                // Everything after `exec NAME` is the guest command.
                if a.positional.len() == 2 && a.positional[0] == "exec" {
                    a.rest.extend(it.by_ref());
                }
            }
        }
        a
    }

    pub fn has(&self, name: &str) -> bool {
        self.flags.iter().any(|(k, _)| k == name)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.flags.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.flags.iter().filter(|(k, _)| k == name).map(|(_, v)| v.clone()).collect()
    }

    pub fn num(&self, name: &str, default: u64) -> Result<u64> {
        match self.get(name) {
            Some(v) => Ok(v.parse().map_err(|_| format!("--{name} wants a number, got {v:?}"))?),
            None => Ok(default),
        }
    }
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("flexvm: {e}");
        std::process::exit(1);
    }
}

pub fn dirs(args: &Args) -> (PathBuf, PathBuf) {
    let pick = |flag, env, default| args.get(flag).map(PathBuf::from).or_else(|| std::env::var_os(env).map(PathBuf::from)).unwrap_or_else(|| PathBuf::from(default));
    (pick("state", "FLEXVM_STATE", "/var/lib/flexvm"), pick("run", "FLEXVM_RUN", "/run/flexvm"))
}

pub fn open_host(args: &Args) -> Result<Host> {
    let (state, run) = dirs(args);
    Host::open(&state, &run)
}

fn paths(args: &Args) -> Result<Paths> {
    let artifacts = args
        .get("artifacts")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("FLEXVM_ARTIFACTS").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("artifacts"));
    let templates = args.get("templates").map(PathBuf::from).or_else(|| std::env::var_os("FLEXVM_TEMPLATES").map(PathBuf::from));
    // The VM processes this one starts (migrations in, standby VMs) find them too.
    std::env::set_var("FLEXVM_ARTIFACTS", std::path::absolute(&artifacts)?);
    if let Some(t) = &templates {
        std::env::set_var("FLEXVM_TEMPLATES", std::path::absolute(t)?);
    }
    Paths::new(&artifacts, templates)
}

fn real_main() -> Result<()> {
    let args = Args::parse();
    // Exported for the VM processes this one may start.
    let _ = paths(&args);
    let pos: Vec<&str> = args.positional.iter().map(|s| s.as_str()).collect();
    let name = pos.get(1).copied().unwrap_or("");
    let template = args.get("template").unwrap_or("default");
    match pos.first().copied() {
        Some("template") => build_template(&args, name),
        Some("run") if args.has("standby") => {
            let start = Start::Standby { template: template.into() };
            vmproc::main(open_host(&args)?, paths(&args)?, start, notify_fd())
        }
        Some("run") if args.has("incoming") => {
            let req: Value = serde_json::from_str(&std::env::var("FLEXVM_INCOMING")?)?;
            set_cloexec(3);
            vmproc::main(open_host(&args)?, paths(&args)?, Start::Incoming { req }, None)
        }
        Some("run") => run(&args, name, template),
        Some("resume") => {
            let host = open_host(&args)?;
            // A paused VM.
            if host.signal(name, libc::SIGCONT).is_ok() {
                return Ok(());
            }
            start(&args, &host, name, Start::Resume { name: name.into() })
        }
        Some("restore") => {
            let dir = std::path::absolute(pos.get(1).ok_or("restore needs DIR")?)?;
            let host = open_host(&args)?;
            let label = match args.get("name") {
                Some(n) => n.to_string(),
                None => format!("restore-{}", std::process::id()),
            };
            let s = Start::Restore { dir, name: args.get("name").map(String::from), ip: args.get("ip").map(String::from), paused: args.has("paused") };
            start(&args, &host, &label, s)
        }
        Some("ls") => list(&open_host(&args)?, args.has("json")),
        Some("exec") => {
            let code = exec(&open_host(&args)?, name, &args.rest.join(" "))?;
            std::process::exit(code);
        }
        Some("kill") => kill(&open_host(&args)?, name),
        Some("checkpoint") => {
            let dir = std::path::absolute(pos.get(2).ok_or("checkpoint needs NAME DIR")?)?;
            let req = json!({"op": "checkpoint", "dir": dir, "stop": args.has("stop"), "incremental": args.has("incremental")});
            print(vmproc::call(&open_host(&args)?, name, req)?)
        }
        Some("migrate") => {
            let to = pos.get(2).ok_or("migrate needs NAME HOST:PORT")?;
            print(vmproc::call(&open_host(&args)?, name, json!({"op": "migrate", "to": to}))?)
        }
        Some("listen") => {
            let mut host = open_host(&args)?;
            configure(&mut host, &args, pos.get(1).copied())?;
            // For the VM processes it starts.
            paths(&args)?;
            listen::main(host)
        }
        Some("standby") => {
            let n: usize = pos.get(1).ok_or("standby needs a count")?.parse().map_err(|_| "standby wants a number")?;
            print(standby::set(&open_host(&args)?, template, n)?)
        }
        Some("bench") => bench::run(&args),
        Some("debug") => debug(&args, &pos),
        _ => {
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }
}

/// `listen`'s flags are the host's configuration (`STATE/host.json`); the
/// ones not given keep their values.
fn configure(host: &mut Host, args: &Args, addr: Option<&str>) -> Result<()> {
    host.configure(|c| set_config(c, args, addr))
}

fn set_config(c: &mut host::Config, args: &Args, addr: Option<&str>) -> Result<()> {
    if let Some(a) = addr {
        c.listen = Some(a.into());
    }
    if args.has("peer") {
        c.peers = args.all("peer");
    }
    if let Some(r) = args.get("vm-ips") {
        net::IpRange::parse(r)?;
        c.vm_ips = r.into();
    }
    if let Some(u) = args.get("underlay") {
        c.underlay = Some(u.parse().map_err(|_| format!("bad --underlay {u:?}"))?);
    }
    if let Some(d) = args.get("announce-dev") {
        c.announce_dev = Some(d.into());
    }
    if let Some(d) = args.get("dns") {
        c.dns = Some(d.into());
    }
    c.reserve_mib = args.num("reserve", c.reserve_mib)?;
    if let Some(p) = args.get("prefix") {
        c.prefix = p.into();
    }
    if c.listen.as_deref().is_some_and(|l| l.starts_with("0.0.0.0")) && c.underlay.is_none() {
        return Err("listening on 0.0.0.0 needs --underlay (the address peers route VMs to)".into());
    }
    Ok(())
}

/// `run NAME`: claims a standby VM if there is one, else becomes the VM.
fn run(args: &Args, name: &str, template: &str) -> Result<()> {
    let host = open_host(args)?;
    let paths = paths(args)?;
    let ip: Option<std::net::Ipv4Addr> = args.get("ip").map(|s| s.parse()).transpose().map_err(|_| "bad --ip")?;
    let cmd = (!args.rest.is_empty()).then(|| args.rest.join(" "));
    let detach = args.has("detach");
    host::check_name(name)?;
    let req = json!({"op": "claim", "name": name, "ip": ip.map(|i| i.to_string()), "cmd": cmd});
    // A claimed standby VM writes where this process would.
    let log = detach.then(|| log_file(&host, name)).transpose()?;
    let fds: Vec<i32> = match &log {
        Some(f) => vec![f.as_raw_fd(), f.as_raw_fd()],
        None => vec![1, 2],
    };
    if let Some((v, conn)) = standby::take(&host, &paths, template, &req, &fds)? {
        if detach {
            return print(v);
        }
        eprintln!("{v}");
        let id = host::Ident { pid: v["pid"].as_u64().unwrap_or(0) as u32, start: v["start"].as_u64().unwrap_or(0) };
        return follow(conn, id);
    }
    if detach {
        return spawn_detached(&host, name);
    }
    vmproc::main(host, paths, Start::Run { name: name.into(), template: template.into(), ip, cmd }, notify_fd())
}

fn start(args: &Args, host: &Host, name: &str, s: Start) -> Result<()> {
    if args.has("detach") {
        return spawn_detached(host, name);
    }
    vmproc::main(open_host(args)?, paths(args)?, s, notify_fd())
}

fn log_file(host: &Host, name: &str) -> Result<std::fs::File> {
    host::check_name(name)?;
    Ok(std::fs::OpenOptions::new().create(true).append(true).open(host.run.join("vms").join(format!("{name}.log")))?)
}

/// `-d`: runs this same command in the background (in its own session,
/// output to `RUN/vms/NAME.log`), and prints what it says once the VM is up.
fn spawn_detached(host: &Host, name: &str) -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).filter(|a| a != "-d").collect();
    let (r, w) = std::os::unix::net::UnixStream::pair()?;
    util::spawn_self(&argv, &log_file(host, name)?, w.as_raw_fd(), &[("FLEXVM_NOTIFY_FD", "3")])?;
    drop(w);
    let log = host.run.join("vms").join(format!("{name}.log"));
    let reply = recv_json(&mut BufReader::new(r))?.ok_or_else(|| format!("the vm process failed to start (see {})", log.display()))?;
    if reply["ok"] != json!(true) {
        return Err(reply["error"].as_str().unwrap_or("failed").to_string().into());
    }
    print(reply["result"].clone())
}

/// The readiness pipe a parent gave this process (`FLEXVM_NOTIFY_FD`).
fn notify_fd() -> Option<std::fs::File> {
    let fd: i32 = std::env::var("FLEXVM_NOTIFY_FD").ok()?.parse().ok()?;
    std::env::remove_var("FLEXVM_NOTIFY_FD");
    set_cloexec(fd);
    Some(unsafe { std::fs::File::from_raw_fd(fd) })
}

fn set_cloexec(fd: i32) {
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
}

/// A foreground `run` that claimed a standby VM: passes its signals on to
/// the VM process and exits with its status.
fn follow(conn: std::os::unix::net::UnixStream, id: host::Ident) -> Result<()> {
    let set = util::block_signals(&[libc::SIGTERM, libc::SIGINT, libc::SIGTSTP, libc::SIGCONT, libc::SIGHUP]);
    let vm = host::PidFd::open(id)?.ok_or("the vm process is gone")?;
    std::thread::spawn(move || loop {
        let sig = util::wait_signal(&set);
        if sig != libc::SIGHUP {
            let _ = vm.signal(sig);
        }
    });
    let reply = recv_json(&mut BufReader::new(conn)).ok().flatten();
    std::process::exit(reply.and_then(|r| r["exit"].as_i64()).unwrap_or(1) as i32)
}

/// `kill NAME`: destroys a VM, live (SIGINT, then waits for it to go) or
/// suspended.
fn kill(host: &Host, name: &str) -> Result<()> {
    if host.entry(name).is_ok_and(|e| e.state == "source") {
        return Err(format!("vm {name} is the source of a migration in progress; it ends once the target has its memory (kill it where it runs)").into());
    }
    if let Ok(vm) = host.signal(name, libc::SIGINT) {
        if !vm.wait(Duration::from_secs(30)) {
            return Err(format!("vm {name} is still there; see its log").into());
        }
        return Ok(());
    }
    if host.suspended(name).exists() {
        let _lock = host.take_name(name, true)?;
        return lifecycle::discard(host, name);
    }
    Err(format!("no vm named {name:?}").into())
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
    for e in std::fs::read_dir(host.state.join("suspended")).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if !n.starts_with('.') && !host.alive(&n) {
            if let Some(v) = lifecycle::describe_suspended(host, &n) {
                vms.push(v);
            }
        }
    }
    if as_json {
        return print(json!(vms));
    }
    println!("{:<16} {:<15} {:<10} {:<12} {:>8} {:>4} {:>8} {:>8}", "NAME", "IP", "TEMPLATE", "STATE", "PID", "VCPU", "RSS MiB", "MAX MiB");
    for v in &vms {
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        let n = |k: &str| v[k].as_u64().map(|n| n.to_string()).unwrap_or_default();
        println!("{:<16} {:<15} {:<10} {:<12} {:>8} {:>4} {:>8} {:>8}", s("name"), s("ip"), s("template"), s("state"), n("pid"), n("vcpus"), n("rss_mib"), n("max_mib"));
    }
    Ok(())
}

pub fn print(v: Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

/// Test hooks: `debug fault NAME MS` arms a fault on this host for MS ms
/// (0 disarms; VM processes see it with FLEXVM_FAULTS=1), `debug ckhash DIR`
/// hashes what a checkpoint restores, `debug VM memhash|status` asks a VM.
fn debug(args: &Args, pos: &[&str]) -> Result<()> {
    match pos.get(1).copied() {
        Some("fault") => {
            let ms = pos.get(3).and_then(|m| m.parse().ok()).unwrap_or(1000);
            host::arm(&open_host(args)?, pos.get(2).ok_or("debug fault NAME MS")?, ms)
        }
        Some("ckhash") => print(lifecycle::ckhash(&paths(args)?, std::path::Path::new(pos.get(2).ok_or("debug ckhash DIR")?))?),
        Some(vm) => print(vmproc::call(&open_host(args)?, vm, json!({"op": "debug", "what": pos.get(2).unwrap_or(&"status")}))?),
        None => Err("debug fault|ckhash|VM ...".into()),
    }
}

fn build_template(args: &Args, name: &str) -> Result<()> {
    if name.is_empty() {
        return Err("template needs a NAME".into());
    }
    // Default: every host CPU (Firecracker wants 1 or an even count, at most 32)
    // and a ceiling of all host memory. Neither is reserved up front.
    let cpus = (util::host_cpus() as u64).min(32);
    let cpus = if cpus > 1 { cpus & !1 } else { 1 };
    let host_mib = proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0) >> 20;
    let mut paths = paths(args)?;
    let image = image_options(args)?
        .map(|opts| {
            let artifacts = paths.kernel.parent().ok_or("bad artifacts dir")?.to_path_buf();
            let cache = args.get("image-cache").map(PathBuf::from).unwrap_or_else(|| artifacts.join("images"));
            let init = args.get("init").map(PathBuf::from).unwrap_or_else(|| artifacts.join("flexvm-init"));
            let (rootfs, meta) = image::prepare(&cache, &init, &opts)?;
            paths.rootfs = rootfs;
            Ok::<_, util::Error>(meta)
        })
        .transpose()?;
    let max = args.num("max", host_mib)?;
    let (cpus, mem, plug) = (args.num("vcpus", cpus)? as u32, args.num("mem", template::base_mib(max))?, args.num("plug", template::PLUG_MIB)?);
    template::create(&paths, name, cpus, mem, max, plug, image)
}

/// `template --image` and its overrides, or None for a plain template.
fn image_options(args: &Args) -> Result<Option<image::Options>> {
    let Some(src) = args.get("image") else {
        for f in ["entrypoint", "cmd", "env", "workdir", "user", "warm", "ready-port", "ready-cmd"] {
            if args.get(f).is_some() {
                return Err(format!("--{f} needs --image").into());
            }
        }
        return Ok(None);
    };
    let warm = args.get("warm").is_some();
    let ready = match (args.get("ready-port"), args.get("ready-cmd")) {
        (Some(_), Some(_)) => return Err("pass --ready-port or --ready-cmd, not both".into()),
        (Some(p), None) => Some(image::Ready::Port(p.parse().map_err(|_| format!("bad --ready-port {p:?}"))?)),
        (None, Some(c)) => Some(image::Ready::Cmd(c.into())),
        (None, None) => None,
    };
    if ready.is_some() && !warm {
        return Err("--ready-port and --ready-cmd only apply with --warm".into());
    }
    Ok(Some(image::Options {
        image: src.into(),
        entrypoint: args.get("entrypoint").map(image::parse_argv).transpose()?,
        cmd: args.get("cmd").map(image::parse_argv).transpose()?,
        env: args.all("env"),
        workdir: args.get("workdir").map(String::from),
        user: args.get("user").map(String::from),
        warm,
        ready,
        ready_timeout: Duration::from_secs(args.num("ready-timeout", 120)?),
        staging: args.get("image-staging").unwrap_or(image::STAGING).into(),
        limits: {
            let d = image::Limits::default();
            image::Limits {
                download: args.num("max-download-mib", d.download >> 20)? << 20,
                unpacked: args.num("max-unpacked-mib", d.unpacked >> 20)? << 20,
                file: args.num("max-file-mib", d.file >> 20)? << 20,
                entries: args.num("max-entries", d.entries)?,
            }
        },
    }))
}

/// Runs `cmd` in VM `name` as a resumable session, streaming its output, and
/// returns its exit status. Reattaches when the connection drops (a
/// checkpoint's pause resets vsock); a VM that migrated away ends it.
pub fn exec(host: &Host, name: &str, cmd: &str) -> Result<i32> {
    exec_session(host, name, cmd, &mut std::io::stdout().lock(), &mut std::io::stderr().lock())
}

fn exec_session(host: &Host, name: &str, cmd: &str, stdout: &mut impl Write, stderr: &mut impl Write) -> Result<i32> {
    let mut random = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let id: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let (mut offset, mut started) = (0, false);
    let mut deadline = Instant::now() + Duration::from_secs(30);
    let mut error = String::new();
    loop {
        if Instant::now() >= deadline {
            return Err(format!("exec recovery timed out: {error}").into());
        }
        let req = json!({"op": "exec", "session": id, "action": if started { "attach" } else { "start" }, "offset": offset, "cmd": cmd});
        let stream = vmproc::connect(host, name, &req, &[]).and_then(|c| {
            c.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut r = BufReader::new(c);
            let reply = recv_json(&mut r)?.ok_or("vm hung up")?;
            if reply["ok"] != json!(true) {
                return Err(reply["error"].as_str().unwrap_or("exec failed").to_string().into());
            }
            // The guest emits a heartbeat every second even for silent commands.
            r.get_ref().set_read_timeout(Some(Duration::from_secs(3)))?;
            Ok(r)
        });
        match stream {
            Ok(mut r) => match exec_frames(&mut r, &id, &mut started, &mut offset, stdout, stderr, &mut deadline)? {
                StreamEnd::Exit(code) => {
                    // Fire and forget: the guest closes a finished session a minute
                    // after its client leaves anyway.
                    let _ = vmproc::connect(host, name, &json!({"op": "exec", "session": id, "action": "close"}), &[]);
                    return Ok(code);
                }
                StreamEnd::Disconnected(reason) => error = reason,
            },
            Err(e) => {
                if !host.alive(name) {
                    if let Ok(to) = std::fs::read_to_string(host.run.join("vms").join(format!("{name}.moved"))) {
                        return Err(format!("vm {name} moved to {to}; the command keeps running there (session {id})").into());
                    }
                    if !started {
                        return Err(e);
                    }
                }
                error = e.to_string();
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub enum StreamEnd {
    Exit(i32),
    Disconnected(String),
}

pub fn exec_frames(
    r: &mut impl Read, id: &str, started: &mut bool, offset: &mut u64,
    stdout: &mut impl Write, stderr: &mut impl Write, deadline: &mut Instant,
) -> Result<StreamEnd> {
    loop {
        let (kind, data) = match guest::read_frame(r) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(StreamEnd::Disconnected("the vm closed the stream".into())),
            Err(e) => return Ok(StreamEnd::Disconnected(e.to_string())),
        };
        match kind {
            guest::FRAME_STDOUT | guest::FRAME_STDERR => {
                if !*started { return Err("session output before session id".into()); }
                let bytes = guest::session_output(&data, *offset)?;
                if kind == guest::FRAME_STDOUT {
                    stdout.write_all(bytes)?;
                    stdout.flush()?;
                } else {
                    stderr.write_all(bytes)?;
                    stderr.flush()?;
                }
                *offset += bytes.len() as u64;
            }
            guest::FRAME_EXIT => return Ok(StreamEnd::Exit(guest::session_exit(&data, *offset)?)),
            guest::FRAME_LOST => {
                let start = u64::from_le_bytes(data.as_slice().try_into().map_err(|_| "bad output-lost frame")?);
                return Err(format!("session output lost: needed offset {offset}, retained output starts at {start}").into());
            }
            guest::FRAME_MSG if data == id.as_bytes() => { *started = true; continue; }
            guest::FRAME_MSG if data == b"waiting" && *started => {}
            // Before the ID echo the request itself failed (bad command, old agent): don't retry it.
            guest::FRAME_MSG if !*started => return Err(String::from_utf8_lossy(&data).into_owned().into()),
            guest::FRAME_MSG => return Ok(StreamEnd::Disconnected(String::from_utf8_lossy(&data).into_owned())),
            _ => return Err(format!("unknown session frame {kind}").into()),
        }
        *deadline = Instant::now() + Duration::from_secs(30);
    }
}

#[cfg(test)]
mod exec_tests {
    use super::*;

    fn frame(w: &mut Vec<u8>, kind: u8, data: &[u8]) {
        w.push(kind);
        w.extend_from_slice(&(data.len() as u32).to_le_bytes());
        w.extend_from_slice(data);
    }

    #[test]
    fn resumes_partial_frame_without_duplicates() {
        let mut first = Vec::new();
        frame(&mut first, guest::FRAME_MSG, b"test-id");
        frame(&mut first, guest::FRAME_STDOUT, &[0u64.to_le_bytes().as_slice(), b"abc"].concat());
        first.extend_from_slice(&[guest::FRAME_STDERR, 11, 0, 0, 0]);
        first.extend_from_slice(&3u64.to_le_bytes());
        first.extend_from_slice(b"d");
        let mut offset = 0;
        let mut started = false;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut deadline = Instant::now();
        assert!(matches!(exec_frames(&mut first.as_slice(), "test-id", &mut started, &mut offset,
            &mut stdout, &mut stderr, &mut deadline).unwrap(), StreamEnd::Disconnected(_)));
        assert!(started);
        assert_eq!(offset, 3);
        let mut resumed = Vec::new();
        frame(&mut resumed, guest::FRAME_MSG, b"test-id");
        frame(&mut resumed, guest::FRAME_STDERR, &[3u64.to_le_bytes().as_slice(), b"def"].concat());
        frame(&mut resumed, guest::FRAME_EXIT, &[6u64.to_le_bytes().as_slice(), &7i32.to_le_bytes()].concat());
        assert!(matches!(exec_frames(&mut resumed.as_slice(), "test-id", &mut started, &mut offset,
            &mut stdout, &mut stderr, &mut deadline).unwrap(), StreamEnd::Exit(7)));
        assert_eq!(stdout, b"abc");
        assert_eq!(stderr, b"def");
        assert_eq!(offset, 6);
    }
}
