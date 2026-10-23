//! Containers: a VM is one, under its name. Its id is the name's (`id_of`), so it needs no record of
//! its own: what `ps -a` and `inspect` say of it is what docker's listing and inspect say, in docker's
//! shapes, its states mapped to docker's (`state`).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Request, Response, StatusCode};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use super::{channel, images, lifecycle, ok, rfc3339_secs, Api, Error, Query, Reply};

/// Docker's zero time, for a time not known.
const NEVER: &str = "0001-01-01T00:00:00Z";

/// A container's id: its name's SHA-256, so the same name is the same container to clients across
/// `stop` and `start`, reruns and migrations (and a rename makes it another).
pub fn id_of(name: &str) -> String {
    Sha256::digest(format!("flexvm container {name}")).iter().map(|b| format!("{b:02x}")).collect()
}

/// The VM `key` names as docker resolves one: its whole id, its name (with or without docker's `/`),
/// or a prefix of only one id.
pub fn find<'a>(vms: &'a [Value], key: &str) -> Result<&'a Value, Error> {
    let name = key.strip_prefix('/').unwrap_or(key);
    let named = |v: &&Value| v["name"].as_str() == Some(name);
    if let Some(v) = vms.iter().find(|v| v["name"].as_str().is_some_and(|n| id_of(n) == key)).or_else(|| vms.iter().find(named)) {
        return Ok(v);
    }
    let prefixed: Vec<&Value> = vms
        .iter()
        .filter(|v| !key.is_empty() && key.bytes().all(|b| b.is_ascii_hexdigit()) && v["name"].as_str().is_some_and(|n| id_of(n).starts_with(key)))
        .collect();
    match prefixed.as_slice() {
        [one] => Ok(one),
        [] => Err(Error::missing(format!("No such container: {key}"))),
        _ => Err(Error::missing(format!("multiple containers match {key:?}: give more of the id"))),
    }
}

/// The VMs, as `ps -a` lists them, and the containers created and not started yet (`create::merge`).
pub async fn all(api: &Arc<Api>) -> Result<Vec<Value>, Error> {
    api.blocking(|api| Ok(super::create::merge(api, crate::vms(&api.host)))).await
}

/// The name of the VM `key` names.
pub async fn resolve(api: &Arc<Api>, key: &str) -> Result<String, Error> {
    let vms = all(api).await?;
    Ok(find(&vms, key)?["name"].as_str().unwrap_or_default().to_string())
}

/// A VM's state as docker's.
#[derive(Debug, PartialEq)]
pub struct State {
    pub status: &'static str,
    pub running: bool,
    pub paused: bool,
    pub dead: bool,
    pub exit_code: i64,
    pub error: String,
}

pub fn state(v: &Value) -> State {
    let s = |status, running, paused, dead, exit_code| State { status, running, paused, dead, exit_code, error: String::new() };
    let error = v["error"].as_str().unwrap_or_default().to_string();
    let mut st = match v["state"].as_str().unwrap_or("") {
        "paused" => s("paused", true, true, false, 0),
        // Docker's stop: its process ended as SIGTERM ends one (`flexvm wait` says 143). Its memory is on disk,
        // so `start` resumes it where it was.
        "suspended" => s("exited", false, false, false, 128 + libc::SIGTERM as i64),
        "exited" => s("exited", false, false, false, v["status"].as_i64().unwrap_or(0)),
        // Stopped, but kept from starting (`quarantined`), failed or lost (a reboot): as `flexvm wait` says.
        "quarantined" | "failed" | "lost" | "unknown" => s("dead", false, false, true, crate::vmproc::DIED as i64),
        "created" => s("created", false, false, false, 0),
        // Running, checkpointing, suspending, migrating: its process runs it.
        _ => s("running", true, false, false, 0),
    };
    st.error = error;
    st
}

/// Seconds since the epoch of the start of the process that runs the VM (`Ident::start`, in clock ticks
/// since boot), if it is running.
fn started(v: &Value) -> Option<u64> {
    let ticks = v["start"].as_u64().filter(|&t| t > 0)?;
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    let btime = std::fs::read_to_string("/proc/stat").ok()?.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse::<u64>().ok())?;
    Some(btime + ticks / hz)
}

/// When a VM stopped running: an exited one's record says, a stopped one's checkpoint was written then.
fn finished(api: &Api, v: &Value) -> Option<u64> {
    if let Some(at) = v["exited_at"].as_u64() {
        return Some(at);
    }
    let name = v["name"].as_str()?;
    let dir = api.host.is_suspended(name).then(|| api.host.suspended(name).ok()).flatten()?;
    Some(std::fs::metadata(dir).ok()?.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_secs())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// How long `secs` is, as docker says it (`Up 5 minutes`, `Exited (0) About an hour ago`).
pub fn human(secs: u64) -> String {
    let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    match secs {
        0 => "Less than a second".into(),
        s if s < 60 => plural(s, "second"),
        s if s < 120 => "About a minute".into(),
        s if s < 3600 => plural(s / 60, "minute"),
        s if s < 7200 => "About an hour".into(),
        s if s < 48 * 3600 => plural(s / 3600, "hour"),
        s if s < 14 * 86400 => plural(s / 86400, "day"),
        s if s < 60 * 86400 => plural(s / (7 * 86400), "week"),
        s if s < 730 * 86400 => plural(s / (30 * 86400), "month"),
        s => plural(s / (365 * 86400), "year"),
    }
}

/// Docker's one-line status.
fn status_line(st: &State, started: Option<u64>, finished: Option<u64>) -> String {
    let ago = |t: Option<u64>| t.map(|t| human(now().saturating_sub(t)));
    match st.status {
        "running" => format!("Up {}", ago(started).unwrap_or_else(|| "Less than a second".into())),
        "paused" => format!("Up {} (Paused)", ago(started).unwrap_or_else(|| "Less than a second".into())),
        "exited" => match ago(finished) {
            Some(a) => format!("Exited ({}) {a} ago", st.exit_code),
            None => format!("Exited ({})", st.exit_code),
        },
        "created" => "Created".into(),
        _ => "Dead".into(),
    }
}

/// What a VM runs and was run with, read once for its listing and its inspect.
pub struct Detail {
    pub name: String,
    pub vm: Value,
    /// `inspect`'s `config`.
    pub config: Value,
    pub state: State,
    pub image: String,
    pub image_id: String,
    /// Docker's `Entrypoint` and `Cmd`: what the app is.
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub labels: Map<String, Value>,
    pub workdir: String,
    pub user: String,
    pub started: Option<u64>,
    pub finished: Option<u64>,
    /// When docker's create made it, if it did.
    pub created: Option<u64>,
    /// Docker's settings, if it was created through the API.
    pub record: Option<super::create::Record>,
}

impl Detail {
    pub fn read(api: &Api, vm: &Value) -> Detail {
        let name = vm["name"].as_str().unwrap_or_default().to_string();
        let record: Option<super::create::Record> = serde_json::from_value(vm["docker"].clone()).ok();
        let created = vm["state"] == "created";
        // A created container has no VM yet: what it will run is its record's.
        let described = match (&record, created) {
            (Some(r), true) => {
                let ports: Vec<crate::ports::Port> = r.run.windows(2).filter(|w| w[0] == "--publish").filter_map(|w| w[1].parse().ok()).collect();
                let id = images::linked(api, &r.template);
                json!({"name": name, "state": "created", "config": {"image": r.image, "template": r.template, "template_id": id, "ports": ports, "run": {}}})
            }
            _ => crate::containers::described(&api.host, &api.paths, &name, vm.clone()),
        };
        let config = described["config"].clone();
        let image_id = config["template_id"].as_str().or(vm["template_id"].as_str()).unwrap_or_default().to_string();
        let meta = images::meta(api, &image_id);
        let image_config = meta.as_ref().and_then(|m| images::config(api, m));
        let argv: Vec<String> = meta.as_ref().and_then(|m| m.image.as_ref()).map(|i| i.argv.clone()).unwrap_or_default();
        let run = &config["run"];
        let (mut entrypoint, mut cmd) = images::app(&argv, image_config.as_ref());
        // `--entrypoint` is the app's whole argv; `run IMAGE CMD`'s command is a shell's.
        if let Some(e) = run["entrypoint"].as_array() {
            (entrypoint, cmd) = (images::strings(&json!(e)), Vec::new());
        } else if let Some(c) = config["cmd"].as_str() {
            (entrypoint, cmd) = (Vec::new(), vec!["sh".into(), "-c".into(), c.into()]);
        }
        let ic = image_config.unwrap_or(Value::Null);
        let mut env = images::strings(&ic["Env"]);
        for kv in images::strings(&run["env"]) {
            let key = kv.split('=').next().unwrap_or_default().to_string();
            env.retain(|e| e.split('=').next() != Some(&key));
            env.push(kv);
        }
        let mut labels = ic["Labels"].as_object().cloned().unwrap_or_default();
        if let Some(r) = &record {
            labels.extend(r.config["Labels"].as_object().cloned().unwrap_or_default());
            if created {
                for kv in images::strings(&r.config["Env"]).into_iter().filter(|kv| kv.contains('=')) {
                    let key = kv.split('=').next().unwrap_or_default().to_string();
                    env.retain(|e| e.split('=').next() != Some(&key));
                    env.push(kv);
                }
                let (e, c) =
                    (r.config["Entrypoint"].as_array().map(|e| images::strings(&json!(e))), r.config["Cmd"].as_array().map(|c| images::strings(&json!(c))));
                if e.is_some() || c.is_some() {
                    cmd = c.unwrap_or(if e.is_some() { Vec::new() } else { cmd });
                    entrypoint = e.unwrap_or(entrypoint);
                }
            }
        }
        let template = config["template"].as_str().or(vm["template"].as_str()).unwrap_or_default();
        Detail {
            state: state(&described),
            image: config["image"].as_str().map_or_else(|| crate::template::image_of(template), String::from),
            image_id: if image_id.is_empty() { String::new() } else { format!("sha256:{image_id}") },
            entrypoint,
            cmd,
            env,
            labels,
            workdir: ic["WorkingDir"].as_str().unwrap_or_default().into(),
            user: ic["User"].as_str().unwrap_or_default().into(),
            started: started(vm),
            finished: finished(api, vm),
            created: record.as_ref().map(|r| r.created),
            record,
            name,
            vm: described,
            config,
        }
    }

    pub fn id(&self) -> String {
        id_of(&self.name)
    }

    fn ports(&self) -> Vec<crate::ports::Port> {
        serde_json::from_value(self.config["ports"].clone()).unwrap_or_default()
    }

    /// The listing's `Ports`: a forward per address it binds (both families for one given none, as docker's).
    fn port_list(&self) -> Vec<Value> {
        let mut out = Vec::new();
        for p in self.ports() {
            let proto = if p.protocol == crate::ports::Protocol::Udp { "udp" } else { "tcp" };
            let ips = p.ip.map_or_else(|| vec!["0.0.0.0".to_string(), "::".to_string()], |ip| vec![ip.to_string()]);
            for ip in ips {
                out.push(json!({"IP": ip, "PrivatePort": p.vm_port, "PublicPort": p.host_port, "Type": proto}));
            }
        }
        out
    }

    /// `NetworkSettings.Ports` and `HostConfig.PortBindings`: `"80/tcp": [{"HostIp", "HostPort"}]`.
    fn port_map(&self) -> Map<String, Value> {
        let mut out = Map::new();
        for p in self.ports() {
            let proto = if p.protocol == crate::ports::Protocol::Udp { "udp" } else { "tcp" };
            let ips = p.ip.map_or_else(|| vec!["0.0.0.0".to_string(), "::".to_string()], |ip| vec![ip.to_string()]);
            let entry = out.entry(format!("{}/{proto}", p.vm_port)).or_insert_with(|| json!([]));
            for ip in ips {
                entry.as_array_mut().unwrap().push(json!({"HostIp": ip, "HostPort": p.host_port.to_string()}));
            }
        }
        out
    }

    fn argv(&self) -> Vec<String> {
        self.entrypoint.iter().chain(&self.cmd).cloned().collect()
    }

    /// The network as docker's default bridge network: one flat routed network every VM is on.
    fn networks(&self) -> Value {
        let ip = self.vm["ip"].as_str().unwrap_or_default();
        json!({"bridge": {
            "IPAMConfig": null, "Links": null, "Aliases": null, "MacAddress": "", "NetworkID": "flexvm", "EndpointID": if ip.is_empty() { "" } else { "flexvm" },
            "Gateway": "", "IPAddress": ip, "IPPrefixLen": if ip.is_empty() { 0 } else { 32 }, "IPv6Gateway": "", "GlobalIPv6Address": "",
            "GlobalIPv6PrefixLen": 0, "DriverOpts": null, "DNSNames": null,
        }})
    }

    /// An entry of `GET /containers/json`.
    pub fn summary(&self) -> Value {
        json!({
            "Id": self.id(),
            "Names": [format!("/{}", self.name)],
            "Image": self.image,
            "ImageID": self.image_id,
            "Command": shell_words(&self.argv()),
            "Created": self.created.or(self.started).or(self.finished).unwrap_or(0),
            "Ports": self.port_list(),
            "Labels": self.labels,
            "State": self.state.status,
            "Status": status_line(&self.state, self.started, self.finished),
            "HostConfig": {"NetworkMode": "bridge"},
            "NetworkSettings": {"Networks": self.networks()},
            "Mounts": [],
        })
    }

    /// `GET /containers/{id}/json`.
    pub fn inspect(&self) -> Value {
        let argv = self.argv();
        let st = &self.state;
        let run = &self.config["run"];
        let cpus = self.config["cpus"].as_f64();
        let time = |t: Option<u64>| t.map_or_else(|| NEVER.to_string(), rfc3339_secs);
        let pid = if st.running { self.vm["pid"].as_u64().unwrap_or(0) } else { 0 };
        let given = self.record.as_ref().map(|r| &r.config);
        let tty = run["tty"] == true || given.is_some_and(|c| c["Tty"] == true);
        let stdin = run["stdin"] == true || given.is_some_and(|c| c["OpenStdin"] == true);
        let mut v = json!({
            "Id": self.id(),
            "Created": time(self.created.or(self.started).or(self.finished)),
            "Path": argv.first().cloned().unwrap_or_default(),
            "Args": argv.get(1..).unwrap_or_default(),
            "State": {
                "Status": st.status, "Running": st.running, "Paused": st.paused, "Restarting": false, "OOMKilled": false, "Dead": st.dead,
                "Pid": pid, "ExitCode": st.exit_code, "Error": st.error,
                "StartedAt": time(self.started), "FinishedAt": if st.running { NEVER.to_string() } else { time(self.finished) },
            },
            "Image": self.image_id,
            "ResolvConfPath": "",
            "HostnamePath": "",
            "HostsPath": "",
            "LogPath": self.config["log"].as_str().unwrap_or_default(),
            "Name": format!("/{}", self.name),
            "RestartCount": 0,
            "Driver": "flexvm",
            "Platform": "linux",
            "MountLabel": "",
            "ProcessLabel": "",
            "AppArmorProfile": "",
            "ExecIDs": null,
            "HostConfig": {
                "NetworkMode": "bridge",
                "PortBindings": self.port_map(),
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "AutoRemove": run["rm"] == true,
                "NanoCpus": cpus.map_or(0, |c| (c * 1e9) as u64),
                "Memory": self.config["max_mib"].as_u64().map_or(0, |m| m << 20),
                "LogConfig": {"Type": "json-file", "Config": {}},
                "Binds": null,
                "Mounts": [],
                "Privileged": false,
                "Init": false,
            },
            "GraphDriver": {"Name": "flexvm", "Data": {"Template": self.config["template"], "TemplateId": self.config["template_id"]}},
            "Mounts": [],
            "Config": {
                "Hostname": self.name,
                "Domainname": "",
                "User": self.user,
                "AttachStdin": false,
                "AttachStdout": false,
                "AttachStderr": false,
                "ExposedPorts": self.port_map().keys().map(|k| (k.clone(), json!({}))).collect::<Map<_, _>>(),
                "Tty": tty,
                "OpenStdin": stdin,
                "StdinOnce": false,
                "Env": self.env,
                "Cmd": self.cmd,
                "Image": self.image,
                "Volumes": null,
                "WorkingDir": self.workdir,
                "Entrypoint": if self.entrypoint.is_empty() { Value::Null } else { json!(self.entrypoint) },
                "OnBuild": null,
                "Labels": self.labels,
            },
            "NetworkSettings": {
                "Bridge": "",
                "SandboxID": "",
                "SandboxKey": "",
                "Ports": self.port_map(),
                "IPAddress": self.vm["ip"].as_str().unwrap_or_default(),
                "IPPrefixLen": if self.vm["ip"].is_string() { 32 } else { 0 },
                "Gateway": "",
                "MacAddress": "",
                "Networks": self.networks(),
            },
            "Flexvm": self.vm,
        });
        // Docker's settings as given, under what flexvm says.
        if let Some(given) = self.record.as_ref().and_then(|r| r.host_config.as_object()) {
            let mut host_config = given.clone();
            host_config.extend(v["HostConfig"].as_object().cloned().unwrap_or_default());
            v["HostConfig"] = Value::Object(host_config);
        }
        v
    }
}

/// An argv as one line, quoting words a shell would split (docker's listing shows a command so).
pub(crate) fn shell_words(argv: &[String]) -> String {
    let word = |w: &String| match !w.is_empty() && w.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./=:,@%+".contains(&b)) {
        true => w.clone(),
        false => format!("'{}'", w.replace('\'', "'\\''")),
    };
    argv.iter().map(word).collect::<Vec<_>>().join(" ")
}

/// A `filters` key and value against a container, as docker matches them.
fn matches(d: &Detail, key: &str, value: &str) -> Result<bool, Error> {
    Ok(match key {
        "id" => d.id().starts_with(value),
        // Docker's is a regular expression: a part of the name, `^` and `$` anchoring it (with or without its `/`).
        "name" => {
            let (start, rest) = value.strip_prefix('^').map_or((false, value), |r| (true, r));
            let (end, part) = rest.strip_suffix('$').map_or((false, rest), |r| (true, r));
            let part = if start { part.strip_prefix('/').unwrap_or(part) } else { part };
            let name = d.name.as_str();
            match (start, end) {
                (true, true) => name == part,
                (true, false) => name.starts_with(part),
                (false, true) => name.ends_with(part),
                (false, false) => format!("/{name}").contains(part),
            }
        }
        "status" => match value {
            "created" | "restarting" | "running" | "removing" | "paused" | "exited" | "dead" => d.state.status == value,
            _ => return Err(Error::bad(format!("invalid filter 'status={value}'"))),
        },
        "exited" => {
            let code: i64 = value.parse().map_err(|_| Error::bad(format!("invalid filter 'exited={value}'")))?;
            d.state.status == "exited" && d.state.exit_code == code
        }
        "label" => match value.split_once('=') {
            Some((k, v)) => d.labels.get(k).and_then(Value::as_str) == Some(v),
            None => d.labels.contains_key(value),
        },
        "ancestor" => {
            let image = crate::template::name_of(value).ok();
            let mine = crate::template::name_of(&d.image).ok();
            (image.is_some() && image == mine)
                || (!value.is_empty() && d.image_id.trim_start_matches("sha256:").starts_with(value.trim_start_matches("sha256:")))
        }
        "network" => matches!(value, "bridge" | "flexvm"),
        _ => return Err(Error::bad(format!("invalid filter '{key}': flexvm takes id, name, status, exited, label, ancestor and network"))),
    })
}

/// `GET /containers/json?all&limit&filters`.
pub async fn list(api: &Arc<Api>, q: Query) -> Reply {
    let (all, limit, filters) = (q.flag("all", false)?, q.number::<i64>("limit")?, q.filters()?);
    let details = api.blocking(|api| Ok(super::create::merge(api, crate::vms(&api.host)).iter().map(|v| Detail::read(api, v)).collect::<Vec<_>>())).await?;
    let mut out = Vec::new();
    for d in &details {
        let mut keep = all || d.state.running || filters.iter().any(|(k, _)| k == "status" || k == "exited");
        // Values of one key: any of them; keys: each of them.
        let mut keys: Vec<&str> = filters.iter().map(|(k, _)| k.as_str()).collect();
        keys.dedup();
        for key in keys {
            let mut any = false;
            for (_, v) in filters.iter().filter(|(k, _)| k == key) {
                any |= matches(d, key, v)?;
            }
            keep &= any;
        }
        if keep {
            out.push(d.summary());
        }
    }
    if let Some(n) = limit.filter(|&n| n > 0) {
        out.truncate(n as usize);
    }
    ok(&json!(out))
}

/// `GET /containers/{id}/json`.
pub async fn inspect(api: &Arc<Api>, key: &str) -> Reply {
    let key = key.to_string();
    let d = api.blocking(move |api| Ok(find(&super::create::merge(api, crate::vms(&api.host)), &key).map(|v| Detail::read(api, v)))).await??;
    ok(&d.inspect())
}

/// A frame of docker's multiplexed stream: `[stream, 0, 0, 0, len u32 BE]`, then the bytes.
pub fn frame(stream: u8, data: &[u8]) -> bytes::Bytes {
    let mut b = Vec::with_capacity(8 + data.len());
    b.extend_from_slice(&[stream, 0, 0, 0]);
    b.extend_from_slice(&(data.len() as u32).to_be_bytes());
    b.extend_from_slice(data);
    b.into()
}

/// The content type of a container's output: raw on a pty, else multiplexed (stdout and stderr framed).
pub fn stream_type(tty: bool) -> HeaderValue {
    HeaderValue::from_static(if tty { "application/vnd.docker.raw-stream" } else { "application/vnd.docker.multiplexed-stream" })
}

/// `GET /containers/{id}/logs?follow&tail&stdout&stderr`: `flexvm logs`. Its log keeps no streams apart nor
/// times, so it all comes as stdout, and `since`, `until` and `timestamps` are refused.
pub async fn logs(api: &Arc<Api>, key: &str, q: Query) -> Reply {
    let (stdout, stderr) = (q.flag("stdout", false)?, q.flag("stderr", false)?);
    if !stdout && !stderr {
        return Err(Error::bad("you must choose at least one stream"));
    }
    if q.flag("timestamps", false)? {
        return Err(Error::unsupported("logs with timestamps (the log keeps none)"));
    }
    for k in ["since", "until"] {
        if q.get(k).is_some_and(|v| !v.is_empty() && v != "0") {
            return Err(Error::unsupported(format!("logs {k} a time (the log keeps no times)")));
        }
    }
    let tail = match q.get("tail").filter(|t| !t.is_empty() && *t != "all") {
        Some(t) => Some(t.parse::<i64>().map_err(|_| Error::bad(format!("bad tail {t:?}")))?).filter(|&n| n >= 0),
        None => None,
    };
    let vms = all(api).await?;
    let vm = find(&vms, key)?;
    let name = vm["name"].as_str().unwrap_or_default().to_string();
    let tty = vm["spec"]["tty"] == true;
    let mut words = vec!["logs".to_string()];
    if q.flag("follow", false)? {
        words.push("--follow".into());
    }
    if let Some(n) = tail {
        words.extend(["--tail".into(), n.to_string()]);
    }
    words.extend(["--".into(), name]);
    let mut child = api.command(&words).spawn()?;
    let mut out = child.stdout.take().ok_or_else(|| Error::from(crate::util::Error::from("logs: no stdout")))?;
    let (tx, body) = channel();
    tokio::spawn(async move {
        let mut buf = vec![0; 32 << 10];
        loop {
            match out.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = match (tty, stdout) {
                        (true, _) => bytes::Bytes::copy_from_slice(&buf[..n]),
                        (false, true) => frame(1, &buf[..n]),
                        // Stderr alone: the log has none apart.
                        (false, false) => continue,
                    };
                    if tx.send(data).await.is_err() {
                        break;
                    }
                }
            }
        }
        // Its client gone (or done): `kill_on_drop` ends a follow.
        drop(child);
    });
    let mut res = Response::new(body);
    res.headers_mut().insert(CONTENT_TYPE, stream_type(tty));
    Ok(res)
}

/// `POST /containers/{id}/wait?condition=not-running|next-exit|removed`: `flexvm wait`. The reply's head
/// goes at once and its body once the VM's process ends (`next-exit`: one that runs or starts later;
/// `removed`: then until nothing is left of it).
pub async fn wait(api: &Arc<Api>, key: &str, q: Query) -> Reply {
    let condition = q.get("condition").filter(|c| !c.is_empty()).unwrap_or("not-running").to_string();
    if !matches!(condition.as_str(), "not-running" | "next-exit" | "removed") {
        return Err(Error::bad(format!("invalid condition {condition:?}")));
    }
    let name = resolve(api, key).await?;
    let (tx, body) = channel();
    let api = api.clone();
    tokio::spawn(async move {
        let host = api.host.clone();
        if condition == "next-exit" {
            while !host.alive(&name) && !tx.is_closed() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        let reply = match api.run(&["wait", "--", &name]).await {
            Ok(out) => {
                let code = String::from_utf8_lossy(&out.stdout).trim().parse::<i64>().unwrap_or(-1);
                json!({"StatusCode": code, "Error": null})
            }
            Err(e) => json!({"StatusCode": -1, "Error": {"Message": e.message}}),
        };
        if condition == "removed" {
            loop {
                let name = name.clone();
                let gone = api.blocking(move |api| Ok(!crate::vms(&api.host).iter().any(|v| v["name"] == name.as_str()))).await.unwrap_or(true);
                if gone || tx.is_closed() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        let _ = tx.send(serde_json::to_vec(&reply).unwrap_or_default().into()).await;
    });
    let mut res = Response::new(body);
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    *res.status_mut() = StatusCode::OK;
    Ok(res)
}

/// The requests this module serves, by path (after `/containers`).
pub async fn route(api: &Arc<Api>, req: Request<Incoming>, words: &[&str]) -> Option<Reply> {
    let q = Query::of(&req);
    let method = req.method().clone();
    Some(match (method, words) {
        (hyper::Method::GET, ["json"]) => list(api, q).await,
        (hyper::Method::GET, [id, "json"]) => inspect(api, id).await,
        (hyper::Method::GET, [id, "logs"]) => logs(api, id, q).await,
        (hyper::Method::POST, [id, "wait"]) => wait(api, id, q).await,
        (hyper::Method::POST, ["create"]) => match super::body_json(req).await {
            Ok(body) => lifecycle::create(api, q, body).await,
            Err(e) => Err(e),
        },
        (hyper::Method::POST, ["prune"]) => lifecycle::prune(api, q).await,
        (hyper::Method::POST, [id, "start"]) => lifecycle::start(api, id, q).await,
        (hyper::Method::POST, [id, "stop"]) => lifecycle::stop(api, id, q).await,
        (hyper::Method::POST, [id, "restart"]) => lifecycle::restart(api, id).await,
        (hyper::Method::POST, [id, "kill"]) => lifecycle::kill(api, id, q).await,
        (hyper::Method::POST, [id, "pause"]) => lifecycle::pause(api, id, true).await,
        (hyper::Method::POST, [id, "unpause"]) => lifecycle::pause(api, id, false).await,
        (hyper::Method::POST, [id, "rename"]) => lifecycle::rename(api, id, q).await,
        (hyper::Method::DELETE, [id]) => lifecycle::remove(api, id, q).await,
        (hyper::Method::POST, [id, "attach"]) => super::streams::attach(api, id, req).await,
        (hyper::Method::POST, [id, "resize"]) => super::streams::resize_container(api, id, q).await,
        (hyper::Method::POST, [id, "exec"]) => match super::body_json(req).await {
            Ok(body) => super::streams::exec_create(api, id, body).await,
            Err(e) => Err(e),
        },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(name: &str, state: &str) -> Value {
        json!({"name": name, "state": state, "status": 3})
    }

    #[test]
    fn containers_are_found_by_id_name_or_prefix() {
        let vms = vec![vm("web", "running"), vm("db", "suspended")];
        let id = id_of("web");
        assert_eq!(id.len(), 64);
        assert_eq!(find(&vms, &id).unwrap()["name"], "web");
        assert_eq!(find(&vms, "/db").unwrap()["name"], "db");
        assert_eq!(find(&vms, &id[..12]).unwrap()["name"], "web");
        assert_eq!(find(&vms, "nope").unwrap_err().status, StatusCode::NOT_FOUND);
        assert!(find(&vms, "").is_err());
        // A name that looks like another's id prefix is a name first.
        let tricky = vec![vm(&id_of("x")[..8], "running"), vm("x", "running")];
        assert_eq!(find(&tricky, &id_of("x")[..8]).unwrap()["name"], id_of("x")[..8]);
    }

    #[test]
    fn states_map_to_dockers() {
        let st = |s| state(&vm("v", s));
        assert_eq!((st("running").status, st("running").running), ("running", true));
        assert_eq!((st("suspending").status, st("checkpointing").status, st("source").status), ("running", "running", "running"));
        assert_eq!((st("paused").status, st("paused").paused, st("paused").running), ("paused", true, true));
        assert_eq!((st("suspended").status, st("suspended").exit_code), ("exited", 143));
        assert_eq!((st("exited").status, st("exited").exit_code), ("exited", 3));
        assert_eq!((st("lost").status, st("lost").dead, st("failed").exit_code), ("dead", true, 124));
        assert_eq!(status_line(&st("exited"), None, Some(now() - 300)), "Exited (3) 5 minutes ago");
        assert_eq!(status_line(&st("running"), Some(now() - 7300), None), "Up 2 hours");
        assert_eq!(status_line(&st("paused"), Some(now()), None), "Up Less than a second (Paused)");
    }

    #[test]
    fn durations_read_as_dockers() {
        for (s, want) in [
            (0, "Less than a second"),
            (1, "1 second"),
            (59, "59 seconds"),
            (60, "About a minute"),
            (180, "3 minutes"),
            (3600, "About an hour"),
            (86400, "24 hours"),
            (3 * 86400, "3 days"),
            (20 * 86400, "2 weeks"),
            (90 * 86400, "3 months"),
            (800 * 86400, "2 years"),
        ] {
            assert_eq!(human(s), want, "{s}");
        }
    }

    #[test]
    fn commands_are_quoted_as_a_shell_would_split_them() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(shell_words(&argv(&["nginx", "-g", "daemon off;"])), "nginx -g 'daemon off;'");
        assert_eq!(shell_words(&argv(&["sh", "-c", "echo 'hi'", ""])), "sh -c 'echo '\\''hi'\\''' ''");
    }

    #[test]
    fn frames_are_dockers() {
        assert_eq!(&frame(2, b"hi")[..], &[2, 0, 0, 0, 0, 0, 0, 2, b'h', b'i']);
    }
}
