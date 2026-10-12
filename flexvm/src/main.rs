mod daemon;
mod fc;
mod guest;
mod net;
mod template;
mod uffd;
mod util;
mod vm;

use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;

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
    let mut c = TcpStream::connect(host).map_err(|e| format!("connect to daemon at {host}: {e}"))?;
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
        "{:<16} {:<15} {:<10} {:<8} {:>4} {:>8} {:>9} {:>8} {:>8}",
        "NAME", "IP", "TEMPLATE", "STATE", "VCPU", "RSS MiB", "GUEST MiB", "MAX MiB", "PULL MiB"
    );
    let n = |v: &Value| v.as_u64().unwrap_or(0);
    for vm in v.as_array().into_iter().flatten() {
        println!(
            "{:<16} {:<15} {:<10} {:<8} {:>4} {:>8} {:>9} {:>8} {:>8}",
            vm["name"].as_str().unwrap_or(""),
            vm["ip"].as_str().unwrap_or(""),
            vm["template"].as_str().unwrap_or(""),
            vm["state"].as_str().unwrap_or(""),
            n(&vm["vcpus"]),
            n(&vm["rss_mib"]),
            n(&vm["guest_mib"]),
            n(&vm["max_mib"]),
            n(&vm["pages_mib"]["remote"]),
        );
    }
    Ok(())
}

fn exec(host: &str, name: &str, cmd: &str) -> Result<i32> {
    let mut c = TcpStream::connect(host)?;
    send_json(&mut c, &json!({"op": "exec", "name": name, "cmd": cmd}))?;
    let mut r = BufReader::new(c);
    let reply = recv_json(&mut r)?.ok_or("daemon hung up")?;
    if reply["ok"] != json!(true) {
        return Err(reply["error"].as_str().unwrap_or("exec failed").to_string().into());
    }
    while let Some((kind, data)) = guest::read_frame(&mut r)? {
        match kind {
            guest::FRAME_STDOUT => std::io::stdout().write_all(&data)?,
            guest::FRAME_STDERR => std::io::stderr().write_all(&data)?,
            guest::FRAME_EXIT => return Ok(i32::from_le_bytes(data[..4].try_into()?)),
            _ => eprintln!("{}", String::from_utf8_lossy(&data)),
        }
    }
    Err("guest closed the connection before the command exited".into())
}
