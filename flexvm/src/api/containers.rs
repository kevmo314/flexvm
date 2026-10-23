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
    api.blocking(|api| Ok(super::create::merge(api))).await
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
        // Its restart policy runs it again soon (`restart_due_ms`): docker's restarting.
        "exited" if v["restart_due_ms"].is_u64() => s("restarting", false, false, false, v["status"].as_i64().unwrap_or(0)),
        "exited" => s("exited", false, false, false, v["status"].as_i64().unwrap_or(0)),
        // Stopped, but kept from starting (`quarantined`), failed or lost (a reboot): as `flexvm wait` says.
        "quarantined" | "failed" | "lost" | "unknown" => s("dead", false, false, true, crate::vmproc::DIED as i64),
        "created" => s("created", false, false, false, 0),
        // Its process holds the name, its VM not registered yet: docker's restarting (a rerun, a start).
        "starting" => s("restarting", false, false, false, 0),
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
        "restarting" => match ago(finished) {
            Some(a) => format!("Restarting ({}) {a} ago", st.exit_code),
            None => format!("Restarting ({})", st.exit_code),
        },
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
    /// When docker's create made it, or else its log directory, start or finish.
    pub created: Option<u64>,
    pub started: Option<u64>,
    pub finished: Option<u64>,
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
                let id = if r.generation.is_empty() { images::linked(api, &r.template) } else { Some(r.generation.clone()) };
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
        let (mut entrypoint, mut cmd, _) = images::app(&argv, image_config.as_ref());
        // `--entrypoint` is the app's whole argv; `run IMAGE CMD`'s command is a shell's.
        if run["entrypoint"].is_array() {
            (entrypoint, cmd) = (images::strings(&run["entrypoint"]), Vec::new());
        } else if let Some(c) = config["cmd"].as_str() {
            (entrypoint, cmd) = (Vec::new(), vec!["sh".into(), "-c".into(), c.into()]);
        }
        let ic = image_config.unwrap_or(Value::Null);
        let mut env = images::strings(&ic["Env"]);
        let overrides = record.as_ref().filter(|_| created).map(|r| &r.config);
        for kv in images::strings(&run["env"]).into_iter().chain(overrides.into_iter().flat_map(|c| images::strings(&c["Env"])).filter(|kv| kv.contains('='))) {
            let key = kv.split('=').next().unwrap_or_default();
            env.retain(|e| e.split('=').next() != Some(key));
            env.push(kv);
        }
        let mut labels = ic["Labels"].as_object().cloned().unwrap_or_default();
        if let Some(r) = &record {
            labels.extend(r.config["Labels"].as_object().cloned().unwrap_or_default());
        }
        if let Some(config) = overrides {
            (entrypoint, cmd) = super::create::app(config, entrypoint, cmd);
        }
        let template = config["template"].as_str().or(vm["template"].as_str()).unwrap_or_default();
        let started = started(vm);
        let finished = finished(api, vm);
        Detail {
            state: state(&described),
            image: record
                .as_ref()
                .map(|r| r.image.clone())
                .unwrap_or_else(|| config["image"].as_str().map_or_else(|| crate::template::image_of(template), String::from)),
            image_id: if image_id.is_empty() { String::new() } else { format!("sha256:{image_id}") },
            entrypoint,
            cmd,
            env,
            labels,
            workdir: ic["WorkingDir"].as_str().unwrap_or_default().into(),
            user: ic["User"].as_str().unwrap_or_default().into(),
            // Docker's create made it then, if it did; else the log directory survives stop/start and exit
            // (rotation only replaces its files).
            created: record.as_ref().map(|r| r.created).or(api
                .host
                .vms(&name, "logs")
                .ok()
                .and_then(|p| std::fs::metadata(p).ok())
                .and_then(|m| m.created().ok())
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .or(started)
                .or(finished)),
            started,
            finished,
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

    fn bindings(&self) -> Vec<(crate::ports::Port, &'static str, String)> {
        self.ports()
            .into_iter()
            .flat_map(|p| {
                let proto = if p.protocol == crate::ports::Protocol::Udp { "udp" } else { "tcp" };
                let ips = p.ip.map_or_else(|| vec!["0.0.0.0".to_string(), "::".to_string()], |ip| vec![ip.to_string()]);
                ips.into_iter().map(move |ip| (p.clone(), proto, ip))
            })
            .collect()
    }

    /// The listing's `Ports`: a forward per address it binds (both families for one given none, as docker's).
    fn port_list(&self) -> Vec<Value> {
        let mut out = Vec::new();
        for (p, proto, ip) in self.bindings() {
            out.push(json!({"IP": ip, "PrivatePort": p.vm_port, "PublicPort": p.host_port, "Type": proto}));
        }
        out
    }

    /// `NetworkSettings.Ports` and `HostConfig.PortBindings`: `"80/tcp": [{"HostIp", "HostPort"}]`.
    fn port_map(&self) -> Map<String, Value> {
        let mut out = Map::new();
        for (p, proto, ip) in self.bindings() {
            let entry = out.entry(format!("{}/{proto}", p.vm_port)).or_insert_with(|| json!([]));
            entry.as_array_mut().unwrap().push(json!({"HostIp": ip, "HostPort": p.host_port.to_string()}));
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
            "Created": self.created.unwrap_or(0),
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
        let ports = self.port_map();
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
            "Created": time(self.created),
            "Path": argv.first().cloned().unwrap_or_default(),
            "Args": argv.get(1..).unwrap_or_default(),
            "State": {
                "Status": st.status, "Running": st.running, "Paused": st.paused, "Restarting": st.status == "restarting", "OOMKilled": false, "Dead": st.dead,
                "Pid": pid, "ExitCode": st.exit_code, "Error": st.error,
                "StartedAt": time(self.started), "FinishedAt": if st.running { NEVER.to_string() } else { time(self.finished) },
            },
            "Image": self.image_id,
            "ResolvConfPath": "",
            "HostnamePath": "",
            "HostsPath": "",
            "LogPath": self.config["log"].as_str().unwrap_or_default(),
            "Name": format!("/{}", self.name),
            "RestartCount": run["restart"]["count"].as_u64().unwrap_or(0),
            "Driver": "flexvm",
            "Platform": "linux",
            "MountLabel": "",
            "ProcessLabel": "",
            "AppArmorProfile": "",
            "ExecIDs": null,
            "HostConfig": {
                "NetworkMode": "bridge",
                "PortBindings": ports,
                "RestartPolicy": {"Name": run["restart"]["policy"].as_str().unwrap_or("no"), "MaximumRetryCount": run["restart"]["max"].as_u64().unwrap_or(0)},
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
                "ExposedPorts": ports.keys().map(|k| (k.clone(), json!({}))).collect::<Map<_, _>>(),
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
                "Ports": ports,
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

fn validate_name(value: &str) -> Result<(), Error> {
    let part = value.strip_prefix('^').unwrap_or(value);
    let part = part.strip_suffix('$').unwrap_or(part);
    if part.contains(['*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '\\', '^', '$']) {
        return Err(Error::bad("name filters support literal text, dots and ^/$ anchors only"));
    }
    Ok(())
}

/// A `filters` key and value against a container, as docker matches them.
fn matches(d: &Detail, key: &str, value: &str) -> Result<bool, Error> {
    Ok(match key {
        "id" => d.id().starts_with(value),
        // Docker matches against the name including its leading `/`.
        "name" => {
            let (start, rest) = value.strip_prefix('^').map_or((false, value), |r| (true, r));
            let (end, part) = rest.strip_suffix('$').map_or((false, rest), |r| (true, r));
            let name: Vec<char> = format!("/{}", d.name).chars().collect();
            let part: Vec<char> = part.chars().collect();
            (0..=name.len()).any(|offset| {
                (!start || offset == 0)
                    && (!end || offset + part.len() == name.len())
                    && name.get(offset..offset + part.len()).is_some_and(|text| part.iter().zip(text).all(|(&p, &c)| p == '.' || p == c))
            })
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
    for (_, value) in filters.iter().filter(|(k, _)| k == "name") {
        validate_name(value)?;
    }
    let details = api.blocking(|api| Ok(super::create::merge(api).iter().map(|v| Detail::read(api, v)).collect::<Vec<_>>())).await?;
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
    out.sort_by(|a, b| b["Created"].as_u64().cmp(&a["Created"].as_u64()).then_with(|| a["Id"].as_str().cmp(&b["Id"].as_str())));
    if let Some(n) = limit.filter(|&n| n > 0) {
        out.truncate(n as usize);
    }
    ok(&json!(out))
}

/// `GET /containers/{id}/json`.
pub async fn inspect(api: &Arc<Api>, key: &str) -> Reply {
    let key = key.to_string();
    let d = api.blocking(move |api| Ok(find(&super::create::merge(api), &key).map(|v| Detail::read(api, v)))).await??;
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

/// Dropping the body cancels even an idle child operation.
async fn connected<T>(tx: &tokio::sync::mpsc::Sender<bytes::Bytes>, work: impl std::future::Future<Output = T>) -> Option<T> {
    tokio::select! {
        biased;
        _ = tx.closed() => None,
        result = work => Some(result),
    }
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
    let vm = vm.clone();
    let log_name = name.clone();
    let tty = api.blocking(move |api| Ok(crate::containers::described(&api.host, &api.paths, &log_name, vm)["config"]["run"]["tty"] == true)).await?;
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
            let Some(read) = connected(&tx, out.read(&mut buf)).await else { break };
            match read {
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

/// An exit after registration, even if its whole run happened between observations.
fn next_exit(
    host: &crate::host::Host,
    name: &str,
    before: Option<&crate::host::Ident>,
    pinned: Option<&crate::host::Ident>,
) -> crate::util::Result<Option<i64>> {
    if let Some(id) = pinned {
        if let Some((_, e)) = crate::containers::last_name(host, name, id) {
            return Ok(Some(e.code as i64));
        }
        if id.liveness() == crate::host::Liveness::Gone {
            return Err("container process ended without an exit status".into());
        }
    } else if let Some(e) = crate::containers::exit_record(host, name).filter(|e| Some(&e.ident) != before) {
        return Ok(Some(e.code as i64));
    }
    Ok(None)
}

/// A lock record can be incomplete while a concurrent start writes it.
fn live_holder(host: &crate::host::Host, name: &str) -> Option<crate::host::Ident> {
    host.name_holder(name).ok().flatten().filter(|id| id.liveness() == crate::host::Liveness::Alive)
}

async fn wait_next(api: &Arc<Api>, name: &str, before: Option<crate::host::Ident>, mut pinned: Option<crate::host::Ident>) -> Result<i64, Error> {
    loop {
        if let Some(id) = pinned {
            let ident = id.clone();
            let fd = api.blocking(move |_| crate::host::PidFd::open(&ident)).await?;
            if let Some(fd) = fd {
                // SAFETY: PidFd owns its descriptor and keeps it unchanged until dropped.
                let fd = unsafe { tokio::io::unix::AsyncFd::register(fd) }.map_err(std::io::Error::from)?;
                let _ = fd.readable().await?;
            }
            let name = name.to_string();
            return api
                .blocking(move |api| next_exit(&api.host, &name, None, Some(&id))?.ok_or_else(|| "container process ended without an exit status".into()))
                .await;
        }
        let name = name.to_string();
        let before = before.clone();
        // The holder first: a run that ends and is followed between the two reads is still seen by its record.
        let (holder, code) = api
            .blocking(move |api| {
                let holder = live_holder(&api.host, &name);
                let code = next_exit(&api.host, &name, before.as_ref(), None)?;
                let gone = removed(api, &name);
                let code = code.or_else(|| (gone && holder.is_none()).then_some(0));
                Ok((holder, code))
            })
            .await?;
        if let Some(code) = code {
            return Ok(code);
        }
        pinned = holder;
        if pinned.is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Read only this container, without collecting stale Docker records as listing does.
fn removed(api: &Api, name: &str) -> bool {
    let created = super::create::load(api, name).is_some_and(|r| !r.started);
    !created && !api.host.alive(name) && api.host.entry(name).is_err() && !crate::host::Records::read(&api.host, name).recorded()
}

async fn wait_removed(api: &Arc<Api>, name: &str, code: i64) -> Result<i64, Error> {
    loop {
        let name = name.to_string();
        if api.blocking(move |api| Ok(removed(api, &name))).await? {
            return Ok(code);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `POST /containers/{id}/wait?condition=not-running|next-exit|removed`: `flexvm wait`. The reply's head
/// goes at once and its body once the VM's process ends (`next-exit`: one that runs or starts later;
/// `removed`: then until nothing is left of it).
pub async fn wait(api: &Arc<Api>, key: &str, q: Query) -> Reply {
    let condition = q.get("condition").filter(|c| !c.is_empty()).unwrap_or("not-running").to_string();
    if !matches!(condition.as_str(), "not-running" | "next-exit" | "removed") {
        return Err(Error::bad(format!("invalid condition {condition:?}")));
    }
    let vms = all(api).await?;
    let vm = find(&vms, key)?;
    let created = vm["state"] == "created";
    let initial_code = state(vm).exit_code;
    let name = vm["name"].as_str().unwrap_or_default().to_string();
    // Register before returning the head, not when the spawned task first runs.
    let registered_name = name.clone();
    let (before, pinned) = api
        .blocking(move |api| {
            let before = crate::containers::exit_record(&api.host, &registered_name).map(|e| e.ident);
            let pinned = live_holder(&api.host, &registered_name);
            Ok((before, pinned))
        })
        .await?;
    let (tx, body) = channel();
    let api = api.clone();
    tokio::spawn(async move {
        let Some(result) = connected(&tx, async {
            if condition == "removed" {
                // `rm -f` deletes the exit record it races us for, and a killed VM leaves none; docker reports 137.
                let code = if created || pinned.is_some() { wait_next(&api, &name, before, pinned).await.unwrap_or(137) } else { initial_code };
                wait_removed(&api, &name, code).await
            } else if condition == "next-exit" {
                wait_next(&api, &name, before, pinned).await
            } else if created {
                Ok(0)
            } else {
                api.run(&["wait", "--", &name]).await.map(|out| String::from_utf8_lossy(&out.stdout).trim().parse::<i64>().unwrap_or(-1))
            }
        })
        .await
        else {
            return;
        };
        let reply = match result {
            Ok(code) => json!({"StatusCode": code, "Error": null}),
            Err(e) => json!({"StatusCode": -1, "Error": {"Message": e.message}}),
        };
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
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(name: &str, state: &str) -> Value {
        json!({"name": name, "state": state, "status": 3})
    }

    fn fixture() -> (crate::test_util::TempDir, Arc<Api>) {
        let d = crate::test_util::TempDir::new("api-containers");
        let host = crate::host::Host::open(&d.join("state"), &d.join("run")).unwrap();
        let api = Arc::new(Api { host, paths: crate::template::Paths::new(&d.join("state")), globals: vec![], renames: Default::default() });
        (d, api)
    }

    #[tokio::test]
    async fn created_wait_conditions_follow_docker_state_wait() {
        use super::super::create;
        use http_body_util::BodyExt;
        let (_d, api) = create::tests::fixture();
        for condition in ["", "not-running", "next-exit", "removed"] {
            let r = create::translate(&api, "web", &json!({"Image": "image"})).unwrap();
            create::store(&api, &r, false).unwrap();
            let response = wait(&api, "web", Query::parse(&format!("condition={condition}"))).await.unwrap();
            let body = response.into_body().collect();
            tokio::pin!(body);
            if matches!(condition, "next-exit" | "removed") {
                assert!(tokio::time::timeout(Duration::from_millis(50), &mut body).await.is_err());
                create::remove(&api, "web");
            }
            let bytes = tokio::time::timeout(Duration::from_secs(2), body).await.unwrap().unwrap().to_bytes();
            assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), json!({"StatusCode": 0, "Error": null}));
        }
    }

    #[tokio::test]
    async fn removed_wait_keeps_the_status_of_a_created_container_that_later_exits() {
        use super::super::create;
        let (_d, api) = create::tests::fixture();
        let r = create::translate(&api, "web", &json!({"Image": "image"})).unwrap();
        create::store(&api, &r, true).unwrap();
        let id = crate::host::Ident { pid: 999_999_999, start: 1, boot: "old".into(), ns: None };
        crate::containers::record_exit(&api.host, "web", &id, 7, true);
        // Complete the exit phase before erasing its record; no timing window between polls.
        let code = wait_next(&api, "web", None, None).await.unwrap();
        assert_eq!(code, 7);
        std::fs::remove_file(api.host.vms("web", "exit").unwrap()).unwrap();
        create::remove(&api, "web");
        assert_eq!(wait_removed(&api, "web", code).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn next_exit_on_created_observes_a_whole_run_between_polls() {
        use super::super::create;
        use http_body_util::BodyExt;
        let (_d, api) = create::tests::fixture();
        let r = create::translate(&api, "web", &json!({"Image": "image"})).unwrap();
        create::store(&api, &r, true).unwrap();
        let response = wait(&api, "web", Query::parse("condition=next-exit")).await.unwrap();
        let body = response.into_body().collect();
        tokio::pin!(body);
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut body).await.is_err());
        let id = crate::host::Ident { pid: 999_999_999, start: 1, boot: "old".into(), ns: None };
        crate::containers::record_exit(&api.host, "web", &id, 7, true);
        let bytes = tokio::time::timeout(Duration::from_secs(2), body).await.unwrap().unwrap().to_bytes();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), json!({"StatusCode": 7, "Error": null}));
    }

    #[tokio::test]
    async fn disconnect_cancels_idle_reads_and_waits() {
        for read in [true, false] {
            let (tx, body) = channel();
            let mut child = tokio::process::Command::new("sleep").arg("60").stdout(std::process::Stdio::piped()).kill_on_drop(true).spawn().unwrap();
            let id = crate::host::Ident::of(child.id().unwrap()).unwrap();
            let task = tokio::spawn(async move {
                if read {
                    let mut out = child.stdout.take().unwrap();
                    let mut buf = [0; 1];
                    assert!(connected(&tx, out.read(&mut buf)).await.is_none());
                } else {
                    assert!(connected(&tx, child.wait()).await.is_none());
                }
            });
            tokio::task::yield_now().await;
            drop(body);
            tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while id.liveness() != crate::host::Liveness::Gone {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
    }

    #[test]
    fn name_filters_reject_unsupported_regexes() {
        for name in ["web.*", "web[12]", "(web|db)", "web+", "web?", "a\\b", "a^b", "a$b"] {
            assert_eq!(validate_name(name).unwrap_err().status, StatusCode::BAD_REQUEST);
        }
        for name in ["web", "^/web$", "^web", "web$", "api.v2"] {
            validate_name(name).unwrap();
        }
    }

    #[test]
    fn name_filters_match_dots_and_the_leading_slash() {
        let (_d, api) = fixture();
        let web = Detail::read(&api, &vm("web", "running"));
        for pattern in ["web", "/web$", "^/web$", "^/w.b$", "web$", "", "^", "$"] {
            assert!(matches(&web, "name", pattern).unwrap(), "{pattern}");
        }
        for pattern in ["^web", "^web$", "^/we$", "^/web.$", "/web/$"] {
            assert!(!matches(&web, "name", pattern).unwrap(), "{pattern}");
        }
        for name in ["api.v2", "api-v2"] {
            let d = Detail::read(&api, &vm(name, "running"));
            assert!(matches(&d, "name", "api.v2").unwrap());
        }
    }

    #[test]
    fn creation_without_logs_falls_back_to_start_then_finish() {
        let (_d, api) = fixture();
        let mut v = vm("web", "exited");
        v["exited_at"] = json!(100);
        let d = Detail::read(&api, &v);
        assert_eq!(d.created, Some(100));
        assert_eq!(d.summary()["Created"], 100);
        v["start"] = json!(1);
        let d = Detail::read(&api, &v);
        assert!(d.started.is_some());
        assert_eq!(d.created, d.started);
    }

    #[tokio::test]
    async fn pinned_wait_reads_the_renamed_exit_after_process_death() {
        let (_d, api) = fixture();
        let mut child = tokio::process::Command::new("sleep").arg("60").kill_on_drop(true).spawn().unwrap();
        let id = crate::host::Ident::of(child.id().unwrap()).unwrap();
        let waiter = wait_next(&api, "web", None, Some(id.clone()));
        tokio::pin!(waiter);
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut waiter).await.is_err());
        crate::containers::record_exit(&api.host, "renamed", &id, 7, true);
        // A record alone must not finish a wait while the pinned process still runs.
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut waiter).await.is_err());
        child.kill().await.unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), waiter).await.unwrap().unwrap(), 7);
    }

    #[test]
    fn incomplete_and_stale_holders_are_not_pinned() {
        let (_d, api) = fixture();
        let path = api.host.vms("web", "lock").unwrap();
        std::fs::write(&path, b"{").unwrap();
        assert!(live_holder(&api.host, "web").is_none());
        let id = crate::host::Ident { pid: 999_999_999, start: 1, boot: "old".into(), ns: None };
        std::fs::write(path, serde_json::to_vec(&id).unwrap()).unwrap();
        assert!(live_holder(&api.host, "web").is_none());
    }

    #[test]
    fn next_exit_sees_short_runs_and_never_attaches_to_a_later_run() {
        let (_d, api) = fixture();
        let id = |start| crate::host::Ident { pid: 999_999_999, start, boot: "old".into(), ns: None };
        crate::containers::record_exit(&api.host, "web", &id(1), 1, true);
        assert_eq!(next_exit(&api.host, "web", Some(&id(1)), None).unwrap(), None);
        crate::containers::record_exit(&api.host, "web", &id(2), 7, true);
        assert_eq!(next_exit(&api.host, "web", Some(&id(1)), None).unwrap(), Some(7));
        assert_eq!(next_exit(&api.host, "web", Some(&id(1)), Some(&id(2))).unwrap(), Some(7));
        crate::containers::record_exit(&api.host, "web", &id(3), 9, true);
        assert!(next_exit(&api.host, "web", Some(&id(1)), Some(&id(2))).is_err());
    }

    #[test]
    fn suspended_tty_uses_the_checkpoint_spec() {
        let (_d, api) = fixture();
        let dir = api.host.suspended("web").unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), b"").unwrap();
        std::fs::write(dir.join("SPEC"), br#"{"tty":true}"#).unwrap();
        let d = Detail::read(&api, &vm("web", "suspended"));
        assert_eq!(d.config["run"]["tty"], true);
        assert_eq!(d.inspect()["Config"]["Tty"], true);
        assert_eq!(stream_type(d.config["run"]["tty"] == true), "application/vnd.docker.raw-stream");
    }

    #[test]
    fn exited_settings_and_port_shapes_are_restored() {
        let (_d, api) = fixture();
        let spec = serde_json::from_value(json!({"tty": true, "ports": ["8080:80".parse::<crate::ports::Port>().unwrap(),
            "127.0.0.1:5353:53/udp".parse::<crate::ports::Port>().unwrap()]}))
        .unwrap();
        let mut rec = crate::app::Exited::new(0, "image".into(), None, Default::default(), spec, 100);
        rec.template_id = Some("abcd".into());
        let blob = serde_json::to_vec(&json!({"config": {"Cmd": ["serve"], "Env": ["A=image"], "Labels": {"role": "web"},
            "User": "app", "WorkingDir": "/srv"}}))
        .unwrap();
        let digest = crate::image::registry::sha256_hex(&blob);
        let blob_path = crate::image::registry::blob_path(&api.host.state.join("images/blobs"), &digest).unwrap();
        std::fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
        std::fs::write(&blob_path, blob).unwrap();
        let generation = api.paths.templates.join(crate::template::GENERATIONS).join("abcd");
        std::fs::create_dir_all(&generation).unwrap();
        let meta = json!({
            "compatibility": {"cpu": "", "tsc_khz": 0, "tsc_control": false, "msrs": [], "firecracker": "", "features": {}, "xsave": {}},
            "vcpus": 1, "mem_mib": 1, "max_mib": 1, "plugged_mib": 0, "kernel": "", "rootfs": "", "id": "abcd", "components": {},
            "image": {"source": "image", "digest": "sha256:source", "config_digest": digest, "app_conf": "", "argv": ["serve"], "warm": false}
        });
        std::fs::write(generation.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
        let path = api.host.vms("web", "exited").unwrap();
        std::fs::write(&path, serde_json::to_vec(&rec).unwrap()).unwrap();
        let d = Detail::read(&api, &vm("web", "exited"));
        assert_eq!(d.image_id, "sha256:abcd");
        assert_eq!(d.config["source"], "image");
        assert_eq!(d.config["digest"], "sha256:source");
        assert!(!d.config["app"].is_null());
        assert!(matches(&d, "name", "^/web$").unwrap());
        assert!(!matches(&d, "name", "^db$").unwrap());
        assert!(matches(&d, "ancestor", "abcd").unwrap());
        assert_eq!(stream_type(d.config["run"]["tty"] == true), stream_type(true));
        let inspect = d.inspect();
        assert_eq!(inspect["Config"]["Tty"], true);
        assert_eq!(inspect["Config"]["Cmd"], json!(["serve"]));
        assert_eq!(inspect["Config"]["Env"], json!(["A=image"]));
        assert_eq!(inspect["Config"]["User"], "app");
        assert_eq!(inspect["Config"]["WorkingDir"], "/srv");
        assert!(matches(&d, "label", "role=web").unwrap());
        std::fs::write(&blob_path, b"corrupt").unwrap();
        assert!(images::config(&api, &images::meta(&api, "abcd").unwrap()).is_none());
        assert_eq!(d.port_list().len(), 3);
        assert_eq!(inspect["HostConfig"]["PortBindings"], inspect["NetworkSettings"]["Ports"]);
        assert_eq!(inspect["NetworkSettings"]["Ports"]["80/tcp"].as_array().unwrap().len(), 2);
        let mut old = serde_json::to_value(rec).unwrap();
        old.as_object_mut().unwrap().remove("template_id");
        assert!(serde_json::from_value::<crate::app::Exited>(old).unwrap().template_id.is_none());
    }

    #[tokio::test]
    async fn list_limits_newest_first() {
        use http_body_util::BodyExt;
        let (_d, api) = fixture();
        let req = Request::builder().uri("/containers/json?filters=%7B%22name%22:%5B%22web.*%22%5D%7D").body(()).unwrap();
        assert_eq!(list(&api, Query::of(&req)).await.unwrap_err().status, StatusCode::BAD_REQUEST);
        for name in ["older", "newer"] {
            std::fs::create_dir_all(api.host.vms(name, "logs").unwrap()).unwrap();
            let rec = crate::app::Exited::new(0, "image".into(), None, Default::default(), Default::default(), 1);
            std::fs::write(api.host.vms(name, "exited").unwrap(), serde_json::to_vec(&rec).unwrap()).unwrap();
            if name == "older" {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        let req = Request::builder().uri("/containers/json?all=1&limit=1").body(()).unwrap();
        let response = list(&api, Query::of(&req)).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rows: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows[0]["Names"][0], "/newer");
        assert_eq!(rows.as_array().unwrap().len(), 1);
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
        assert_eq!(st("starting").status, "restarting");
        let due = state(&json!({"name": "v", "state": "exited", "status": 1, "restart_due_ms": 5}));
        assert_eq!((due.status, due.exit_code, status_line(&due, None, None)), ("restarting", 1, "Restarting (1)".to_string()));
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
