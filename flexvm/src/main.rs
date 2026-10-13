mod bench;
mod bench_lifecycle;
mod checkpoint;
mod crc32c;
mod daemon;
mod fc;
mod guest;
mod image;
mod hot;
mod net;
mod template;
mod uffd;
mod util;
mod vm;

use std::io::{BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::template::Paths;
use crate::util::{proc_kb, recv_json, send_json, Result};

const USAGE: &str = "\
flexvm: elastic Firecracker microVMs with post-copy live migration

usage:
  flexvm template NAME [--vcpus N] [--mem MIB] [--max MIB]   cold-boot and snapshot a template (root)
                [--image REF|ARCHIVE|DIR] [--entrypoint ARGV] [--cmd ARGV]
                [--env K=V]... [--workdir DIR] [--user USER[:GROUP]]
                [--warm [--ready-port N | --ready-cmd CMD] [--ready-timeout S]]
                [--max-download-mib N] [--max-unpacked-mib N] [--max-file-mib N] [--max-entries N]
                [--image-staging DIR]
                                                             ... from a container image
  flexvm daemon [--listen ADDR] [--advertise ADDR] [--run DIR]
                [--peer ADDR]... [--reserve MIB] [--pool N]
                [--hot N] [--hot-mib MIB]
                [--vm-ips CIDR|FIRST-LAST] [--underlay IP]
                [--announce-dev IFACE] [--dns IP] [--state-dir DIR]  run the host daemon (root)
  flexvm run NAME [--template T] [--ip IP]                   start a VM from a template
  flexvm ls                                                  list VMs
  flexvm exec NAME CMD...                                    run a shell command in a VM
  flexvm logs NAME [-f]                                      an image app's output (-f: follow)
  flexvm migrate NAME --to ADDR                              live-migrate a VM to another daemon
  flexvm pause NAME | resume NAME                            stop / restart a VM's vCPUs (memory kept)
  flexvm suspend NAME                                        checkpoint to the daemon's --state-dir and free
                                                             the VM's memory; `resume` restores it lazily
  flexvm checkpoint NAME DIR [--keep-running | --stop]       write the VM's full state to DIR (new directory)
  flexvm restore DIR [--name N] [--ip IP|auto] [--paused]    start a VM from a checkpoint (same template id)
  flexvm bench [--to ADDR] [--iterations N] [--dirty-mib N]  per-phase run/migrate latency into bench/
               [--template T] [--ready-port N | --ready-http N]  ... and until an image app answers
  flexvm bench --lifecycle DIR [--to ADDR] [--dirty-mib N,N..] pause/checkpoint/restore/suspend latency into bench/
  flexvm kill NAME                                           stop a VM
  flexvm unlend IP                                           free an address lent to a VM that migrated away

options:
  --host ADDR        daemon to talk to (env FLEXVM_HOST, default 127.0.0.1:7070)
  --artifacts DIR    firecracker, vmlinux, rootfs.ext4 (env FLEXVM_ARTIFACTS, default ./artifacts)
  --templates DIR    template store (default ARTIFACTS/templates)
  --image-cache DIR  image blobs and root filesystems (default ARTIFACTS/images)
";

/// Flags that take no value.
const SWITCHES: &[&str] = &["warm", "follow", "stop", "keep-running", "paused"];

struct Args {
    positional: Vec<String>,
    flags: Vec<(String, String)>,
}

impl Args {
    fn parse() -> Args {
        let mut positional = Vec::new();
        let mut flags = Vec::new();
        let mut it = std::env::args().skip(1);
        while let Some(a) = it.next() {
            if let Some(flag) = a.strip_prefix("--") {
                let value = if SWITCHES.contains(&flag) { "1".into() } else { it.next().unwrap_or_default() };
                flags.push((flag.to_string(), value));
            } else {
                positional.push(a);
                // Everything after `exec NAME` is the guest command.
                if positional.len() == 2 && positional[0] == "exec" {
                    positional.extend(it.by_ref());
                }
            }
        }
        Args { positional, flags }
    }

    fn has(&self, name: &str) -> bool {
        self.flags.iter().any(|(k, _)| k == name)
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.flags.iter().filter(|(k, _)| k == name).map(|(_, v)| v.clone()).collect()
    }

    fn num(&self, name: &str, default: u64) -> Result<u64> {
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

fn real_main() -> Result<()> {
    let args = Args::parse();
    let host = args
        .get("host")
        .map(String::from)
        .or_else(|| std::env::var("FLEXVM_HOST").ok())
        .unwrap_or_else(|| "127.0.0.1:7070".into());
    let paths = || {
        let artifacts = args
            .get("artifacts")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("FLEXVM_ARTIFACTS").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("artifacts"));
        Paths::new(&artifacts, args.get("templates").map(PathBuf::from))
    };
    let pos: Vec<&str> = args.positional.iter().map(|s| s.as_str()).collect();
    let name = pos.get(1).copied().unwrap_or("");
    match pos.first().copied() {
        Some("template") => {
            if name.is_empty() {
                return Err("template needs a NAME".into());
            }
            // Default: every host CPU (Firecracker wants 1 or an even count, at most 32)
            // and a ceiling of all host memory. Neither is reserved up front.
            let cpus = (util::host_cpus() as u64).min(32);
            let cpus = if cpus > 1 { cpus & !1 } else { 1 };
            let host_mib = proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0) >> 20;
            let mut paths = paths()?;
            let image = image_options(&args)?
                .map(|opts| {
                    let artifacts = paths.kernel.parent().ok_or("bad artifacts dir")?.to_path_buf();
                    let cache = args.get("image-cache").map(PathBuf::from).unwrap_or_else(|| artifacts.join("images"));
                    let init = args.get("init").map(PathBuf::from).unwrap_or_else(|| artifacts.join("flexvm-init"));
                    let (rootfs, meta) = image::prepare(&cache, &init, &opts)?;
                    paths.rootfs = rootfs;
                    Ok::<_, util::Error>(meta)
                })
                .transpose()?;
            template::create(
                &paths,
                name,
                args.num("vcpus", cpus)? as u32,
                args.num("mem", 256)?,
                args.num("max", host_mib)?,
                image,
            )
        }
        Some("daemon") => {
            let listen = args.get("listen").unwrap_or("127.0.0.1:7070").to_string();
            let advertise = args.get("advertise").map(String::from).unwrap_or_else(|| listen.clone());
            daemon::run(daemon::Config {
                paths: paths()?,
                advertise: advertise.clone(),
                run_dir: args
                    .get("run")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(format!("/run/flexvm/{}", listen.replace(':', "_")))),
                state_dir: args.get("state-dir").map(PathBuf::from).unwrap_or_else(|| {
                    PathBuf::from(format!("/var/lib/flexvm/{}", listen.replace([':', '.', '[', ']'], "_")))
                }),
                listen,
                peers: args.all("peer"),
                reserve_mib: args.num("reserve", 1024)?,
                pool: args.num("pool", 2)? as usize,
                hot: args.num("hot", 2)? as usize,
                hot_mib: args.num("hot-mib", 512)?,
                vm_ips: net::IpRange::parse(args.get("vm-ips").unwrap_or("10.200.0.0/16"))?,
                underlay: match args.get("underlay") {
                    Some(ip) => ip.parse().map_err(|_| format!("bad --underlay {ip:?}"))?,
                    None => advertise.rsplit_once(':').map(|(h, _)| h).unwrap_or(&advertise).parse().map_err(|_| {
                        "--underlay is required when --advertise is not an IPv4 address".to_string()
                    })?,
                },
                announce_dev: args.get("announce-dev").map(String::from),
                dns: args.get("dns").map(String::from),
            })
        }
        Some("bench") => match args.get("lifecycle") {
            Some(dir) => bench_lifecycle::run(&host, &args, dir),
            None => bench::run(&host, &args),
        },
        Some("run") => print(call(
            &host,
            json!({"op": "run", "name": name, "template": args.get("template").unwrap_or("default"), "ip": args.get("ip")}),
        )?),
        Some("ls") => list(call(&host, json!({"op": "ls"}))?),
        Some("unlend") => print(call(&host, json!({"op": "unlend", "ip": name}))?),
        Some("kill") => print(call(&host, json!({"op": "kill", "name": name}))?),
        Some(op @ ("pause" | "resume" | "suspend")) => print(call(&host, json!({"op": op, "name": name}))?),
        Some("checkpoint") => {
            let dir = pos.get(2).ok_or("checkpoint needs NAME DIR")?;
            if args.has("stop") && args.has("keep-running") {
                return Err("--stop and --keep-running are exclusive".into());
            }
            let dir = std::path::absolute(dir)?;
            print(call(&host, json!({"op": "checkpoint", "name": name, "dir": dir, "stop": args.has("stop")}))?)
        }
        Some("restore") => {
            let dir = std::path::absolute(pos.get(1).ok_or("restore needs DIR")?)?;
            print(call(&host, json!({"op": "restore", "dir": dir, "name": args.get("name"), "ip": args.get("ip"), "paused": args.has("paused")}))?)
        }
        Some("migrate") => {
            let to = args.get("to").ok_or("migrate needs --to ADDR")?;
            print(call(&host, json!({"op": "migrate", "name": name, "to": to}))?)
        }
        Some("logs") => {
            let follow = args.get("follow").is_some() || pos.get(2) == Some(&"-f");
            logs(&host, name, follow)
        }
        Some("exec") => {
            let code = exec(&host, name, &pos[2..].join(" "))?;
            std::process::exit(code);
        }
        _ => {
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }
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

/// Prints an image app's output. With `follow`, keeps printing until the app
/// exits, reconnecting from the same offset if the connection drops.
fn logs(host: &str, name: &str, follow: bool) -> Result<()> {
    let mut offset = 0u64;
    let mut retries = 0;
    loop {
        let mut c = TcpStream::connect(host)?;
        send_json(&mut c, &json!({"op": "logs", "name": name, "offset": offset, "follow": follow}))?;
        let mut r = BufReader::new(c);
        let reply = recv_json(&mut r)?.ok_or("daemon hung up")?;
        if reply["ok"] != json!(true) {
            return Err(reply["error"].as_str().unwrap_or("logs failed").to_string().into());
        }
        while let Some((kind, data)) = guest::read_frame(&mut r)? {
            if kind == guest::FRAME_MSG {
                // `<status> <next offset>`
                let status = String::from_utf8_lossy(&data);
                let status = status.rsplit_once(' ').map(|(s, _)| s).unwrap_or(&status);
                if !status.starts_with("running") {
                    eprintln!("[app {status}]");
                }
                return Ok(());
            }
            std::io::stdout().write_all(&data)?;
            std::io::stdout().flush()?;
            offset += data.len() as u64;
            retries = 0;
        }
        // vsock connections reset when the VM migrates or pauses.
        retries += 1;
        if !follow || retries > 25 {
            return Err("connection to the guest closed".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn call(host: &str, req: Value) -> Result<Value> {
    let c = TcpStream::connect(host).map_err(|e| format!("connect to daemon at {host}: {e}"))?;
    rpc_reply(c, req)
}

fn call_with_timeout(host: &str, req: Value, timeout: Duration) -> Result<Value> {
    let mut error = None;
    for addr in host.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(c) => {
                c.set_read_timeout(Some(timeout))?;
                c.set_write_timeout(Some(timeout))?;
                return rpc_reply(c, req);
            }
            Err(e) => error = Some(e),
        }
    }
    Err(format!("connect to daemon at {host}: {}", error.map(|e| e.to_string()).unwrap_or_else(|| "no addresses".into())).into())
}

fn rpc_reply(mut c: TcpStream, req: Value) -> Result<Value> {
    send_json(&mut c, &req)?;
    let reply = recv_json(&mut BufReader::new(c))?.ok_or("daemon hung up")?;
    if reply["ok"] != json!(true) {
        return Err(reply["error"].as_str().unwrap_or("request failed").to_string().into());
    }
    Ok(reply["result"].clone())
}

fn print(v: Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

fn list(v: Value) -> Result<()> {
    println!(
        "{:<16} {:<15} {:<10} {:<8} {:>4} {:>8} {:>9} {:>8} {:>8} {:>16}",
        "NAME", "IP", "TEMPLATE", "STATE", "VCPU", "RSS MiB", "GUEST MiB", "MAX MiB", "PULL MiB", "TEMPLATE ID"
    );
    let n = |v: &Value| v.as_u64().unwrap_or(0);
    for vm in v.as_array().into_iter().flatten() {
        println!(
            "{:<16} {:<15} {:<10} {:<8} {:>4} {:>8} {:>9} {:>8} {:>8} {:>16}",
            vm["name"].as_str().unwrap_or(""),
            vm["ip"].as_str().unwrap_or(""),
            vm["template"].as_str().unwrap_or(""),
            vm["state"].as_str().unwrap_or(""),
            n(&vm["vcpus"]),
            n(&vm["rss_mib"]),
            n(&vm["guest_mib"]),
            n(&vm["max_mib"]),
            n(&vm["pages_mib"]["remote"]),
            vm["template_id"].as_str().unwrap_or(""),
        );
    }
    Ok(())
}

/// Connect with bounded I/O so a dead host cannot stall session recovery.
fn exec_stream(host: &str, req: Value, timeout: Duration) -> Result<BufReader<TcpStream>> {
    let mut error = "no addresses".to_string();
    for addr in host.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(mut c) => {
                c.set_read_timeout(Some(timeout))?;
                c.set_write_timeout(Some(timeout))?;
                send_json(&mut c, &req)?;
                let mut r = BufReader::new(c);
                let reply = recv_json(&mut r)?.ok_or("daemon hung up")?;
                if reply["ok"] != json!(true) {
                    return Err(reply["error"].as_str().unwrap_or("exec failed").to_string().into());
                }
                // The guest emits a heartbeat every second even for silent commands.
                r.get_ref().set_read_timeout(Some(Duration::from_secs(3)))?;
                return Ok(r);
            }
            Err(e) => error = e.to_string(),
        }
    }
    Err(error.into())
}

fn exec(host: &str, name: &str, cmd: &str) -> Result<i32> {
    exec_session(host, name, cmd, &mut std::io::stdout().lock(), &mut std::io::stderr().lock())
}

fn exec_session(host: &str, name: &str, cmd: &str, stdout: &mut impl Write, stderr: &mut impl Write) -> Result<i32> {
    let mut random = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let id: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let mut hosts = vec![host.to_string()];
    let mut offset = 0;
    let mut started = false;
    let mut deadline = Instant::now() + Duration::from_secs(30);
    let mut error = String::new();
    for i in 0.. {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(format!("exec recovery timed out: {error}").into()); }
        // A VM that no daemon knows was never there; one mid-migration is known to both.
        if !started && i == hosts.len() && error.starts_with("no vm named") {
            return Err(error.into());
        }
        if i > 0 && i % hosts.len() == 0 {
            std::thread::sleep(Duration::from_millis(200));
        }
        let target = hosts[i % hosts.len()].clone();
        let req = json!({"op": "exec", "name": name, "session": id,
            "action": if started { "attach" } else { "start" }, "offset": offset, "cmd": cmd});
        match exec_stream(&target, req, remaining.min(Duration::from_secs(2))) {
            Ok(mut r) => match exec_frames(&mut r, &id, &mut started, &mut offset, stdout, stderr, &mut deadline)? {
                StreamEnd::Exit(code) => {
                    // Fire and forget: the daemon acts on it after we hang up, and a lost
                    // acknowledgement is harmless since finished sessions expire after five minutes.
                    if let Some(addr) = target.to_socket_addrs().ok().and_then(|mut a| a.next()) {
                        if let Ok(mut c) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
                            let _ = send_json(&mut c, &json!({"op": "exec", "name": name, "session": id, "action": "close"}));
                        }
                    }
                    return Ok(code);
                }
                StreamEnd::Disconnected(reason) => error = reason,
            },
            Err(e) => error = e.to_string(),
        }
        // Peers are only needed once the VM may have moved; the host it was on knows them.
        for h in [&target, host] {
            if let Ok(info) = call_with_timeout(h, json!({"op": "info"}), Duration::from_secs(1)) {
                add_peers(&mut hosts, &info);
                break;
            }
        }
    }
    unreachable!()
}

enum StreamEnd {
    Exit(i32),
    Disconnected(String),
}

fn exec_frames(
    r: &mut impl Read, id: &str, started: &mut bool, offset: &mut u64,
    stdout: &mut impl Write, stderr: &mut impl Write, deadline: &mut Instant,
) -> Result<StreamEnd> {
    loop {
        let (kind, data) = match guest::read_frame(r) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(StreamEnd::Disconnected("daemon closed the stream".into())),
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

fn add_peers(hosts: &mut Vec<String>, info: &Value) {
    for peer in info["peers"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if !hosts.iter().any(|host| host == peer) {
            hosts.push(peer.to_string());
        }
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
        let mut hosts = vec!["original".to_string()];
        add_peers(&mut hosts, &json!({"peers": ["original", "target", "target"]}));
        assert_eq!(hosts, ["original", "target"]);
    }
}
