mod bench;
mod daemon;
mod fc;
mod guest;
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
  flexvm daemon [--listen ADDR] [--advertise ADDR] [--run DIR]
                [--peer ADDR]... [--reserve MIB] [--pool N]
                [--vm-ips CIDR|FIRST-LAST] [--underlay IP]
                [--announce-dev IFACE] [--dns IP]            run the host daemon (root)
  flexvm run NAME [--template T] [--ip IP]                   start a VM from a template
  flexvm ls                                                  list VMs
  flexvm exec NAME CMD...                                    run a shell command in a VM
  flexvm migrate NAME --to ADDR                              live-migrate a VM to another daemon
  flexvm bench [--to ADDR] [--iterations N] [--dirty-mib N]  per-phase run/migrate latency into bench/
  flexvm kill NAME                                           stop a VM

options:
  --host ADDR        daemon to talk to (env FLEXVM_HOST, default 127.0.0.1:7070)
  --artifacts DIR    firecracker, vmlinux, rootfs.ext4 (env FLEXVM_ARTIFACTS, default ./artifacts)
  --templates DIR    template store (default ARTIFACTS/templates)
";

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
                flags.push((flag.to_string(), it.next().unwrap_or_default()));
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
            template::create(
                &paths()?,
                name,
                args.num("vcpus", cpus)? as u32,
                args.num("mem", 256)?,
                args.num("max", host_mib)?,
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
                listen,
                peers: args.all("peer"),
                reserve_mib: args.num("reserve", 1024)?,
                pool: args.num("pool", 2)? as usize,
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
        Some("bench") => bench::run(&host, &args),
        Some("run") => print(call(
            &host,
            json!({"op": "run", "name": name, "template": args.get("template").unwrap_or("default"), "ip": args.get("ip")}),
        )?),
        Some("ls") => list(call(&host, json!({"op": "ls"}))?),
        Some("kill") => print(call(&host, json!({"op": "kill", "name": name}))?),
        Some("migrate") => {
            let to = args.get("to").ok_or("migrate needs --to ADDR")?;
            print(call(&host, json!({"op": "migrate", "name": name, "to": to}))?)
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
    // Cache peers before starting: the original host may disappear with the connection.
    if let Ok(info) = call_with_timeout(host, json!({"op": "info"}), Duration::from_secs(1)) {
        add_peers(&mut hosts, &info);
    }
    let mut offset = 0;
    let mut started = false;
    let mut deadline = Instant::now() + Duration::from_secs(30);
    let mut error = String::new();
    loop {
        for target in hosts.clone() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { return Err(format!("exec recovery timed out: {error}").into()); }
            let req = json!({"op": "exec", "name": name, "session": id,
                "action": if started { "attach" } else { "start" }, "offset": offset, "cmd": cmd});
            let mut r = match exec_stream(&target, req, remaining.min(Duration::from_secs(2))) {
                Ok(r) => r,
                Err(e) => { error = e.to_string(); continue; }
            };
            match exec_frames(&mut r, &id, &mut started, &mut offset, stdout, stderr, &mut deadline)? {
                StreamEnd::Exit(code) => {
                    // A failed acknowledgement is harmless: finished sessions expire after five minutes.
                    let _ = call_with_timeout(&target, json!({"op": "exec", "name": name,
                        "session": id, "action": "close"}), Duration::from_secs(2));
                    return Ok(code);
                }
                StreamEnd::Disconnected(reason) => error = reason,
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(format!("exec recovery timed out: {error}").into()); }
        if let Ok(info) = call_with_timeout(host, json!({"op": "info"}), remaining.min(Duration::from_secs(1))) {
            add_peers(&mut hosts, &info);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
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
