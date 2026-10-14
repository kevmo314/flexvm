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

const SWITCHES: &[&str] = &["warm", "stop", "paused", "incremental", "standby", "incoming", "json", "detach", "help"];

const VALUE_FLAGS: &[&str] = &[
    "state", "run", "artifacts", "templates", "image-cache", "template", "ip", "name",
    "peer", "vm-ips", "underlay", "announce-dev", "dns", "reserve", "prefix",
    "vcpus", "mem", "max", "plug", "image", "init", "entrypoint", "cmd", "env",
    "workdir", "user", "ready-port", "ready-cmd", "ready-timeout", "image-staging",
    "max-download-mib", "max-unpacked-mib", "max-file-mib", "max-entries",
    "to", "to-state", "to-run", "timeout", "lifecycle", "iterations", "warmup",
    "dirty-mib", "settle-ms", "ready-http",
];

/// `--flag value`s: last wins. `rest` follows `--` (or `exec NAME`).
pub struct Args {
    positional: Vec<String>,
    flags: Vec<(String, String)>,
    rest: Vec<String>,
    child_args: Vec<String>,
}

impl Args {
    fn parse(it: impl IntoIterator<Item = String>) -> Result<Args> {
        let mut a = Args { positional: Vec::new(), flags: Vec::new(), rest: Vec::new(), child_args: Vec::new() };
        let mut it = it.into_iter();
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
        Ok(a)
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

    pub fn num(&self, name: &str, default: u64) -> Result<u64> {
        self.parse_or(name, default)
    }

    fn path(&self, flag: &str, env: &str, default: &str) -> PathBuf {
        self.get(flag).map(PathBuf::from).or_else(|| std::env::var_os(env).map(PathBuf::from)).unwrap_or_else(|| default.into())
    }
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("flexvm: {e}");
        std::process::exit(1);
    }
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

fn real_main() -> Result<()> {
    let args = Args::parse(std::env::args().skip(1))?;
    if args.has("help") {
        print!("{USAGE}");
        return Ok(());
    }
    let _ = paths(&args);
    let pos: Vec<&str> = args.positional.iter().map(|s| s.as_str()).collect();
    let (name, arg2) = (pos.get(1).copied().unwrap_or(""), pos.get(2).copied());
    let template = args.get("template").unwrap_or("default");
    let call = |req: Value| print(vmproc::call(&open_host(&args)?, name, req)?);
    match pos.first().copied() {
        Some("template") => build_template(&args, name),
        Some("run") if args.has("standby") => vmproc::main(open_host(&args)?, paths(&args)?, Start::Standby { template: template.into() }, notify_fd()),
        Some("run") if args.has("incoming") => {
            let req: Value = serde_json::from_str(&std::env::var("FLEXVM_INCOMING")?)?;
            unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) };
            vmproc::main(open_host(&args)?, paths(&args)?, Start::Incoming { req }, None)
        }
        Some("run") => run(&args, name, template),
        // A paused VM gets SIGCONT; a suspended one a new process.
        Some("resume") if open_host(&args)?.signal(name, libc::SIGCONT).is_ok() => Ok(()),
        Some("resume") => start(&args, name, Start::Resume { name: name.into() }),
        Some("restore") => {
            let dir = std::path::absolute(pos.get(1).ok_or("restore needs DIR")?)?;
            // A detached restore logs to the VM's name, which the checkpoint has without --name.
            let label = match args.get("name") {
                Some(name) => name.to_string(),
                None if args.has("detach") => checkpoint::Checkpoint::open(&dir)?.manifest.name,
                None => String::new(),
            };
            start(&args, &label, Start::Restore { dir, name: args.get("name").map(String::from), ip: args.get("ip").map(String::from), paused: args.has("paused") })
        }
        Some("ls") => list(&open_host(&args)?, args.has("json")),
        Some("exec") => std::process::exit(exec(&open_host(&args)?, name, &args.rest.join(" "))?),
        Some("kill") => kill(&open_host(&args)?, name),
        Some("checkpoint") => {
            let dir = std::path::absolute(arg2.ok_or("checkpoint needs NAME DIR")?)?;
            call(json!({"op": "checkpoint", "dir": dir, "stop": args.has("stop"), "incremental": args.has("incremental")}))
        }
        Some("migrate") => call(json!({"op": "migrate", "to": arg2.ok_or("migrate needs NAME HOST:PORT")?})),
        Some("listen") => {
            let mut host = open_host(&args)?;
            let listener = configure_listener(&mut host, &args, pos.get(1).copied(), listen::activated())?;
            listen::main(host, listener)
        }
        Some("standby") => print(standby::set(&open_host(&args)?, template, name.parse().map_err(|_| "standby wants a count")?)?),
        Some("bench") => bench::run(&args),
        // Test hooks: arm a fault for MS ms (0 disarms), hash a checkpoint, or ask a VM.
        Some("debug") => match name {
            "fault" => host::arm(&open_host(&args)?, arg2.ok_or("debug fault NAME MS")?, pos.get(3).and_then(|m| m.parse().ok()).unwrap_or(1000)),
            "ckhash" => print(lifecycle::ckhash(&paths(&args)?, std::path::Path::new(arg2.ok_or("debug ckhash DIR")?))?),
            "" => Err("debug fault|ckhash|VM ...".into()),
            _ => call(json!({"op": "debug", "what": arg2.unwrap_or("status")})),
        },
        _ => {
            eprint!("{USAGE}");
            std::process::exit(2);
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

/// Flags not given keep their configured values.
fn configure(c: &mut host::Config, args: &Args, addr: Option<&str>) -> Result<()> {
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
    c.underlay = args.get("underlay").map(|u| u.parse()).transpose().map_err(|_| "bad --underlay")?.or(c.underlay);
    c.announce_dev = args.get("announce-dev").map(String::from).or(c.announce_dev.take());
    c.dns = args.get("dns").map(String::from).or(c.dns.take());
    c.reserve_mib = args.num("reserve", c.reserve_mib)?;
    c.prefix = args.get("prefix").map_or(c.prefix.clone(), String::from);
    Ok(())
}

/// Claims a standby VM if there is one, else becomes the VM.
fn run(args: &Args, name: &str, template: &str) -> Result<()> {
    let (host, paths) = (open_host(args)?, paths(args)?);
    let ip: Option<std::net::Ipv4Addr> = args.get("ip").map(|s| s.parse()).transpose().map_err(|_| "bad --ip")?;
    let cmd = (!args.rest.is_empty()).then(|| args.rest.join(" "));
    host::check_name(name)?;
    let req = json!({"op": "claim", "name": name, "ip": ip.map(|i| i.to_string()), "cmd": cmd});
    // A claimed standby VM writes where this process would.
    let log = args.has("detach").then(|| log_file(&host, name)).transpose()?;
    let fds = log.as_ref().map_or([1, 2], |f| [f.as_raw_fd(); 2]);
    match standby::take(&host, &paths, template, &req, &fds)? {
        Some((v, _)) if log.is_some() => print(v),
        Some((v, conn)) => {
            eprintln!("{v}");
            let id = host::Ident { pid: v["pid"].as_u64().unwrap_or(0) as u32, start: v["start"].as_u64().unwrap_or(0), boot: host::boot_id().into() };
            follow(conn, id)
        }
        None if log.is_some() => spawn_detached(&host, name, args),
        None => vmproc::main(host, paths, Start::Run { name: name.into(), template: template.into(), ip, cmd }, notify_fd()),
    }
}

fn start(args: &Args, name: &str, s: Start) -> Result<()> {
    if args.has("detach") {
        return spawn_detached(&open_host(args)?, name, args);
    }
    vmproc::main(open_host(args)?, paths(args)?, s, notify_fd())
}

fn log_file(host: &Host, name: &str) -> Result<std::fs::File> {
    host::check_name(name)?;
    Ok(std::fs::OpenOptions::new().create(true).append(true).open(host.vms(name, "log"))?)
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
    let set = util::block_signals(&[libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGCONT, libc::SIGHUP]);
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
    std::process::exit(reply.and_then(|r| r["exit"].as_i64()).map_or(vmproc::FAILED, |c| c as i32))
}

fn kill(host: &Host, name: &str) -> Result<()> {
    if host.entry(name).is_ok_and(|e| e.state == "source") {
        return Err(format!("vm {name} is the source of a migration in progress; it ends once the target has its memory (kill it where it runs)").into());
    }
    if let Ok(vm) = host.signal(name, libc::SIGINT) {
        if !vm.wait(Duration::from_secs(30)) {
            return Err(format!("vm {name} is still there; see its log").into());
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
        return lifecycle::discard(host, name);
    }
    if !host.alive(name) && std::fs::remove_file(host.vms(name, "failed")).is_ok() {
        return Ok(());
    }
    if host.alive(name) {
        return Err(format!("vm {name:?} is starting or its registry is unavailable; retry flexvm kill {name} once it is ready, or see {}", host.vms(name, "log").display()).into());
    }
    Err(format!("no vm named {name:?}").into())
}

fn list(host: &Host, as_json: bool) -> Result<()> {
    let rss = |pid: Option<u32>| pid.and_then(|p| proc_kb(&format!("/proc/{p}/status"), "VmRSS")).unwrap_or(0) >> 20;
    let mut vms: Vec<Value> = host.entries().into_iter().map(|e| {
        let mut v = serde_json::to_value(&e).unwrap_or_default();
        v["rss_mib"] = json!(rss(e.firecracker));
        v
    }).collect();
    let names = |dir: PathBuf| std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.file_name().to_string_lossy().into_owned());
    vms.extend(names(host.state.join("suspended")).filter(|n| !n.starts_with('.') && !host.alive(n)).filter_map(|n| lifecycle::describe_suspended(host, &n)));
    for n in names(host.run.join("vms")).filter_map(|n| n.strip_suffix(".failed").map(String::from)).filter(|n| !host.alive(n)) {
        vms.push(json!({"name": n, "state": "failed", "error": std::fs::read_to_string(host.vms(&n, "failed")).unwrap_or_default()}));
    }
    if as_json {
        return print(json!(vms));
    }
    let row = |c: [&str; 8]| println!("{:<16} {:<15} {:<10} {:<12} {:>8} {:>4} {:>8} {:>8}", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]);
    row(["NAME", "IP", "TEMPLATE", "STATE", "PID", "VCPU", "RSS MiB", "MAX MiB"]);
    for v in &vms {
        let s = |k: &str| v[k].as_str().map(String::from).or_else(|| v[k].as_u64().map(|n| n.to_string())).unwrap_or_default();
        row(["name", "ip", "template", "state", "pid", "vcpus", "rss_mib", "max_mib"].map(s).each_ref().map(|s| s.as_str()));
    }
    Ok(())
}

pub fn print(v: Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

fn build_template(args: &Args, name: &str) -> Result<()> {
    if name.is_empty() {
        return Err("template needs a NAME".into());
    }
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
    let max = args.num("max", proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0) >> 20)?;
    let (cpus, mem, plug) = (args.num("vcpus", cpus)? as u32, args.num("mem", template::base_mib(max))?, args.num("plug", template::PLUG_MIB)?);
    template::create(&paths, name, cpus, mem, max, plug, image)
}

fn image_options(args: &Args) -> Result<Option<image::Options>> {
    let Some(src) = args.get("image") else {
        if let Some(f) = ["entrypoint", "cmd", "env", "workdir", "user", "warm", "ready-port", "ready-cmd"].iter().find(|f| args.has(f)) {
            return Err(format!("--{f} needs --image").into());
        }
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
        ready_timeout: Duration::from_secs(args.num("ready-timeout", 120)?),
        staging: args.get("image-staging").unwrap_or(image::STAGING).into(),
        limits: image::Limits {
            download: args.num("max-download-mib", d.download >> 20)? << 20,
            unpacked: args.num("max-unpacked-mib", d.unpacked >> 20)? << 20,
            file: args.num("max-file-mib", d.file >> 20)? << 20,
            entries: args.num("max-entries", d.entries)?,
        },
    }))
}

/// Reattaches when the connection drops (a checkpoint's pause resets vsock).
pub fn exec(host: &Host, name: &str, cmd: &str) -> Result<i32> {
    let (stdout, stderr) = (&mut std::io::stdout().lock(), &mut std::io::stderr().lock());
    let id = guest::session_id()?;
    let (mut offset, mut started, mut error) = (0, false, String::new());
    let mut deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let req = json!({"op": "exec", "session": id, "action": if started { "attach" } else { "start" }, "offset": offset, "cmd": cmd});
        let stream = vmproc::connect(host, name, &req, &[]).and_then(|c| {
            c.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut r = BufReader::new(c);
            let reply = recv_json(&mut r)?.ok_or("vm hung up")?;
            if reply["ok"] != json!(true) {
                return Err(reply["error"].as_str().unwrap_or("exec failed").to_string().into());
            }
            // The guest heartbeats every second, even for silent commands.
            r.get_ref().set_read_timeout(Some(Duration::from_secs(3)))?;
            Ok(r)
        });
        match stream.map(|mut r| exec_frames(&mut r, &id, &mut started, &mut offset, stdout, stderr, &mut deadline)) {
            Ok(Err(e)) => return Err(e),
            Ok(Ok(StreamEnd::Exit(code))) => {
                // Best effort: the guest closes it a minute after its client leaves anyway.
                let _ = vmproc::connect(host, name, &json!({"op": "exec", "session": id, "action": "close"}), &[]);
                return Ok(code);
            }
            Ok(Ok(StreamEnd::Disconnected(why))) => error = why,
            Err(e) => {
                // A new command fails at once; a running one waits for its VM to resume.
                if e.to_string().contains(" is paused; ") {
                    if !started {
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
                error = e.to_string();
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

/// Tracks `offset` so a reattach resumes without duplicates.
fn exec_frames(r: &mut impl Read, id: &str, started: &mut bool, offset: &mut u64, stdout: &mut impl Write, stderr: &mut impl Write, deadline: &mut Instant) -> Result<StreamEnd> {
    loop {
        let (kind, data) = match guest::read_frame(r) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(StreamEnd::Disconnected("the vm closed the stream".into())),
            Err(e) => return Ok(StreamEnd::Disconnected(e.to_string())),
        };
        match kind {
            guest::FRAME_STDOUT | guest::FRAME_STDERR if *started => {
                let bytes = guest::session_output(&data, *offset)?;
                let out: &mut dyn Write = if kind == guest::FRAME_STDOUT { stdout } else { stderr };
                out.write_all(bytes)?;
                out.flush()?;
                *offset += bytes.len() as u64;
            }
            guest::FRAME_STDOUT | guest::FRAME_STDERR => return Err("session output before session id".into()),
            guest::FRAME_EXIT => return Ok(StreamEnd::Exit(guest::session_exit(&data, *offset)?)),
            guest::FRAME_LOST => {
                let start = u64::from_le_bytes(data.as_slice().try_into().map_err(|_| "bad output-lost frame")?);
                return Err(format!("session output lost: needed offset {offset}, retained output starts at {start}").into());
            }
            guest::FRAME_MSG if data == id.as_bytes() => *started = true,
            guest::FRAME_MSG if data == b"waiting" && *started => {}
            // Before the id echo the request itself failed: not retried.
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

    fn parse(args: &[&str]) -> Args {
        Args::parse(args.iter().map(|a| a.to_string())).unwrap()
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
        assert_eq!(args.num("reserve", 0).unwrap(), 456);
        let args = parse(&["run", "--incoming", "--standby", "--paused"]);
        assert!(args.has("incoming") && args.has("standby") && args.has("paused"));
        assert!(args.rest.is_empty());
    }

    #[test]
    fn listener_configuration_is_published_only_after_binding_and_validation() {
        use std::net::TcpListener;
        let root = std::env::temp_dir().join(format!("flexvm-listen-config-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        host.configure(|c| { c.reserve_mib = 321; Ok(()) }).unwrap();
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

    fn frames(fs: &[(u8, &[u8])]) -> Vec<u8> {
        fs.iter().flat_map(|(kind, data)| [&[*kind][..], &(data.len() as u32).to_le_bytes(), data].concat()).collect()
    }

    #[test]
    fn resumes_partial_frame_without_duplicates() {
        let at = |o: u64, d: &[u8]| [&o.to_le_bytes()[..], d].concat();
        let mut first = frames(&[(guest::FRAME_MSG, b"test-id"), (guest::FRAME_STDOUT, &at(0, b"abc"))]);
        first.extend_from_slice(&[guest::FRAME_STDERR, 11, 0, 0, 0]);
        first.extend_from_slice(&at(3, b"d"));
        let (mut offset, mut started, mut stdout, mut stderr, mut deadline) = (0, false, Vec::new(), Vec::new(), Instant::now());
        let mut run = |input: Vec<u8>| exec_frames(&mut input.as_slice(), "test-id", &mut started, &mut offset, &mut stdout, &mut stderr, &mut deadline).unwrap();
        assert!(matches!(run(first), StreamEnd::Disconnected(_)));
        let resumed = frames(&[(guest::FRAME_MSG, b"test-id"), (guest::FRAME_STDERR, &at(3, b"def")), (guest::FRAME_EXIT, &[&6u64.to_le_bytes()[..], &7i32.to_le_bytes()].concat())]);
        assert!(matches!(run(resumed), StreamEnd::Exit(7)));
        assert!(started && offset == 6 && stdout == b"abc" && stderr == b"def");
    }
}
