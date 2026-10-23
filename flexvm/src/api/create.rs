//! `POST /containers/create`: docker's create, then start, as flexvm's one `run -d`. A created container is
//! a record (`STATE/api/containers/NAME.json`) of what `run` it starts with, translated from docker's
//! settings when it is created (a setting flexvm cannot honour is refused then), and of docker's settings
//! as given, which `inspect` shows (its labels, say) as long as its VM is there. A record whose VM is gone
//! (removed with `flexvm rm`, an `--rm` one that exited) goes as it is next read.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{images, Api, Error};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub name: String,
    /// Seconds since the epoch.
    pub created: u64,
    /// `run -d --name NAME` takes these next: flags, then IMAGE, then CMD.
    pub run: Vec<String>,
    /// The image as given, and its template.
    pub image: String,
    pub template: String,
    /// Docker's `Config` and `HostConfig`, as given.
    pub config: Value,
    pub host_config: Value,
    /// Its VM was started (`run`): from then on the VM is the container, and this record only adds docker's
    /// settings to what flexvm says of it.
    #[serde(default)]
    pub started: bool,
}

fn dir(api: &Api) -> PathBuf {
    api.host.state.join("api").join("containers")
}

pub fn load(api: &Api, name: &str) -> Option<Record> {
    crate::host::check_name(name).ok()?;
    serde_json::from_slice(&std::fs::read(dir(api).join(format!("{name}.json"))).ok()?).ok()
}

/// Every record, by name; one that cannot be read (cut short by a crash) is removed.
pub fn load_all(api: &Api) -> Vec<Record> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir(api)).into_iter().flatten().flatten() {
        let file = e.file_name().to_string_lossy().into_owned();
        let Some(name) = file.strip_suffix(".json").filter(|n| !n.starts_with('.')) else { continue };
        match load(api, name) {
            Some(r) if r.name == name => out.push(r),
            _ => drop(std::fs::remove_file(e.path())),
        }
    }
    out.sort_by(|a, b| b.created.cmp(&a.created));
    out
}

/// Written whole (to a temporary file, renamed into place); `new`: only if there is none of the name yet.
pub fn store(api: &Api, r: &Record, new: bool) -> crate::util::Result<bool> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = dir(api);
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    let tmp = dir.join(format!(".{}.{}", r.name, crate::util::random_hex(8)?));
    std::fs::write(&tmp, serde_json::to_vec_pretty(r)?)?;
    let path = dir.join(format!("{}.json", r.name));
    let placed = match new {
        true => crate::util::rename_noreplace(&tmp, &path),
        false => std::fs::rename(&tmp, &path).map(|()| true),
    };
    if !matches!(placed, Ok(true)) {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(placed?)
}

pub fn remove(api: &Api, name: &str) {
    if crate::host::check_name(name).is_ok() {
        let _ = std::fs::remove_file(dir(api).join(format!("{name}.json")));
    }
}

/// `vms` (`ps -a`'s) with each record: a VM's under `docker`, a container not started yet as one `created`.
pub fn merge(api: &Api, mut vms: Vec<Value>) -> Vec<Value> {
    for r in load_all(api) {
        match vms.iter_mut().find(|v| v["name"] == r.name.as_str()) {
            Some(v) => v["docker"] = json!(r),
            None if !r.started => {
                let created = json!({"name": r.name, "state": "created", "template": r.template, "created": r.created, "docker": r});
                vms.insert(0, created);
            }
            // Its VM is gone, or one holds the name and is not listed yet (starting): gone only if not that.
            None if !api.host.alive(&r.name) => remove(api, &r.name),
            None => {}
        }
    }
    vms
}

fn strings(v: &Value) -> Option<Vec<String>> {
    v.as_array().map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
}

/// Whether docker's setting `v` is its default (absent, null, false, 0, empty).
fn unset(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/// A port of this host's that is free now (bound and let go), for docker's "any host port".
fn free_port(ip: Option<std::net::IpAddr>, udp: bool) -> Result<u16, Error> {
    let ip = ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let port = match udp {
        true => std::net::UdpSocket::bind((ip, 0)).and_then(|s| s.local_addr()),
        false => std::net::TcpListener::bind((ip, 0)).and_then(|s| s.local_addr()),
    };
    Ok(port.map_err(|e| Error::bad(format!("no free port on {ip}: {e}")))?.port())
}

/// `-p` mappings from `PortBindings` (and `PublishAllPorts`: each exposed port to a free one).
fn ports(host_config: &Value, exposed: &[String]) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    let mut bindings: Vec<(String, Value)> =
        host_config["PortBindings"].as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
    if host_config["PublishAllPorts"] == true {
        for p in exposed {
            if !bindings.iter().any(|(k, _)| k == p) {
                bindings.push((p.clone(), json!([{}])));
            }
        }
    }
    for (port, binds) in bindings {
        let (vm, proto) = port.split_once('/').unwrap_or((&port, "tcp"));
        if !matches!(proto, "tcp" | "udp") {
            return Err(Error::unsupported(format!("port {port} ({proto}: flexvm forwards tcp and udp)")));
        }
        let vm: u16 = vm.parse().map_err(|_| Error::unsupported(format!("port {port} (a range or a bad port)")))?;
        let binds = binds.as_array().cloned().unwrap_or_default();
        for b in if binds.is_empty() { vec![json!({})] } else { binds } {
            let ip = b["HostIp"].as_str().filter(|i| !i.is_empty());
            let ip: Option<std::net::IpAddr> =
                ip.map(|i| i.trim_matches(['[', ']']).parse().map_err(|_| Error::bad(format!("bad HostIp {i:?}")))).transpose()?;
            let host = match b["HostPort"].as_str().filter(|p| !p.is_empty() && *p != "0") {
                Some(h) => h.parse::<u16>().map_err(|_| Error::unsupported(format!("host port {h:?} (a range or a bad port)")))?,
                None => free_port(ip, proto == "udp")?,
            };
            let bind = match ip {
                Some(std::net::IpAddr::V6(v6)) => format!("[{v6}]:"),
                Some(v4) => format!("{v4}:"),
                None => String::new(),
            };
            out.push(format!("{bind}{host}:{vm}/{proto}"));
        }
    }
    Ok(out)
}

/// `HostConfig.RestartPolicy` as `run --restart`'s value (None: `no`).
fn restart(policy: &Value) -> Result<Option<String>, Error> {
    let max = policy["MaximumRetryCount"].as_u64().unwrap_or(0);
    let name = policy["Name"].as_str().unwrap_or("");
    let value = match name {
        "" | "no" => None,
        "always" | "unless-stopped" | "on-failure" => Some(name.to_string()),
        p => return Err(Error::bad(format!("invalid restart policy {p:?}"))),
    };
    match (value, max) {
        (v, 0) => Ok(v),
        (Some(v), n) if v == "on-failure" => Ok(Some(format!("on-failure:{n}"))),
        _ => Err(Error::bad(format!("invalid restart policy: maximum retry count can only be used with 'on-failure' ({name:?})"))),
    }
}

/// What docker's settings ask that flexvm has nothing for: refused, never ignored.
fn refuse_unsupported(config: &Value, host_config: &Value, name: &str) -> Result<(), Error> {
    let host = |k: &str| &host_config[k];
    for (key, what) in [
        ("Binds", "bind mounts"),
        ("Mounts", "mounts"),
        ("VolumesFrom", "volumes"),
        ("Devices", "devices"),
        ("DeviceRequests", "device requests"),
        ("Dns", "DNS servers"),
        ("DnsSearch", "DNS search domains"),
        ("DnsOptions", "DNS options"),
        ("ExtraHosts", "extra hosts"),
        ("Links", "links"),
        ("CapDrop", "dropping capabilities"),
        ("ReadonlyRootfs", "a read-only root filesystem"),
        ("CpuShares", "CPU shares"),
        ("CpusetCpus", "CPU sets"),
        ("CpusetMems", "memory node sets"),
        ("MemoryReservation", "memory reservations"),
        ("MemorySwap", "swap limits"),
        ("KernelMemory", "kernel memory limits"),
        ("PidsLimit", "pids limits"),
        ("Ulimits", "ulimits"),
        ("Sysctls", "sysctls"),
        ("Tmpfs", "tmpfs mounts"),
        ("ShmSize", "a shm size"),
        ("BlkioWeight", "block I/O weights"),
        ("OomKillDisable", "disabling the OOM killer"),
        ("StorageOpt", "storage options"),
    ] {
        // Docker's "no limit" for swap and pids is -1.
        let v = host(key);
        let unlimited = matches!(key, "MemorySwap" | "PidsLimit") && v.as_i64() == Some(-1);
        if !unset(v) && !unlimited {
            return Err(Error::unsupported(format!("{what} ({key})")));
        }
    }
    match host("NetworkMode").as_str().unwrap_or("") {
        "" | "default" | "bridge" => {}
        mode => return Err(Error::unsupported(format!("network mode {mode:?}: every VM is on flexvm's one network (bridge)"))),
    }
    for (key, ok) in
        [("IpcMode", &["", "private", "shareable"][..]), ("PidMode", &[""]), ("UTSMode", &[""]), ("UsernsMode", &[""]), ("CgroupnsMode", &["", "private"])]
    {
        let v = host(key).as_str().unwrap_or("");
        if !ok.contains(&v) {
            return Err(Error::unsupported(format!("{key} {v:?}")));
        }
    }
    match host("LogConfig")["Type"].as_str().unwrap_or("") {
        "" | "json-file" | "local" => {}
        t => return Err(Error::unsupported(format!("log driver {t:?}: a VM's output goes to its log"))),
    }
    match host("Runtime").as_str().unwrap_or("") {
        "" | "flexvm" => {}
        r => return Err(Error::unsupported(format!("runtime {r:?}"))),
    }
    // `restart` builds the `--restart` it becomes; any other policy name is docker's error too.
    restart(host("RestartPolicy"))?;
    for (key, what) in
        [("Volumes", "volumes"), ("Healthcheck", "health checks"), ("MacAddress", "MAC addresses"), ("NetworkDisabled", "a VM without its network")]
    {
        let v = &config[key];
        // A health check of NONE is none.
        let none = key == "Healthcheck" && strings(&v["Test"]).is_some_and(|t| t.first().map(String::as_str) == Some("NONE"));
        if !unset(v) && !none {
            return Err(Error::unsupported(format!("{what} ({key})")));
        }
    }
    if let Some(h) = config["Hostname"].as_str().filter(|h| !h.is_empty() && *h != name) {
        return Err(Error::unsupported(format!("hostname {h:?}: a VM's hostname is its name")));
    }
    if config["Domainname"].as_str().is_some_and(|d| !d.is_empty()) {
        return Err(Error::unsupported("a domain name (Domainname)"));
    }
    Ok(())
}

/// The record of a container `name` created with docker's `body`: its `run` translated, checked against
/// its image (`template`, pulled: else docker's "No such image", which docker's CLI answers with a pull).
pub fn translate(api: &Api, name: &str, body: &Value) -> Result<Record, Error> {
    let mut config = body.clone();
    if let Some(c) = config.as_object_mut() {
        c.remove("HostConfig");
        c.remove("NetworkingConfig");
    }
    let host_config = body["HostConfig"].clone();
    let image = config["Image"].as_str().filter(|i| !i.is_empty()).ok_or_else(|| Error::bad("config has no Image"))?.to_string();
    let template = crate::template::name_of(&image).map_err(|e| Error::bad(e.to_string()))?;
    let tpl = images::linked(api, &template).and_then(|id| images::meta(api, &id)).ok_or_else(|| Error::missing(format!("No such image: {image}")))?;
    refuse_unsupported(&config, &host_config, name)?;
    let meta = tpl.image.as_ref();
    let image_config = images::config(api, &tpl);
    let argv: Vec<String> = meta.map(|i| i.argv.clone()).unwrap_or_default();
    let (image_entrypoint, image_cmd) = images::app(&argv, image_config.as_ref());
    for (key, flag) in [("WorkingDir", "a working directory"), ("User", "a user")] {
        let image = image_config.as_ref().and_then(|c| c[key].as_str()).unwrap_or("");
        if let Some(v) = config[key].as_str().filter(|v| !v.is_empty() && *v != image) {
            return Err(Error::unsupported(format!("{flag} for the app ({key} {v:?}): give it to flexvm pull")));
        }
    }
    let mut run = Vec::new();
    let mut cmd_words = Vec::new();
    // Docker's Entrypoint and Cmd: given (an empty Entrypoint clears the image's), else the image's; a new
    // entrypoint drops the image's command.
    let (entrypoint, cmd) = (strings(&config["Entrypoint"]), strings(&config["Cmd"]));
    if entrypoint.is_some() || cmd.is_some() {
        let e = entrypoint.clone().map(|e| e.into_iter().filter(|w| !w.is_empty()).collect::<Vec<_>>()).unwrap_or(image_entrypoint);
        let c = cmd.unwrap_or(if entrypoint.is_some() { Vec::new() } else { image_cmd });
        let app: Vec<String> = e.into_iter().chain(c).collect();
        match (app == argv, app.is_empty(), meta.is_some()) {
            (true, _, _) => {}
            (false, true, _) => return Err(Error::unsupported("an empty command over an image's app: a VM's app is its image's or a command")),
            (false, false, true) => run.extend(["--entrypoint".to_string(), serde_json::to_string(&app).unwrap_or_default()]),
            // A template of no image's has no app to replace: the VM follows the command, run by a shell.
            (false, false, false) => cmd_words = vec![super::containers::shell_words(&app)],
        }
    }
    for kv in config["Env"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        // A bare `K`: docker's CLI sends none (unset here, it leaves it out); this server's own would be the wrong one.
        if kv.contains('=') {
            run.extend(["-e".to_string(), kv.to_string()]);
        }
    }
    if config["OpenStdin"] == true {
        run.push("--interactive".into());
    }
    if config["Tty"] == true {
        run.push("--tty".into());
    }
    if host_config["AutoRemove"] == true {
        run.push("--rm".into());
    }
    if let Some(r) = restart(&host_config["RestartPolicy"])? {
        run.extend(["--restart".to_string(), r]);
    }
    if let Some(m) = host_config["Memory"].as_u64().filter(|&m| m > 0) {
        run.extend(["--memory".to_string(), m.to_string()]);
    }
    let cpus = match (host_config["NanoCpus"].as_u64().filter(|&n| n > 0), host_config["CpuQuota"].as_i64().filter(|&q| q > 0)) {
        (Some(n), _) => Some(n as f64 / 1e9),
        (None, Some(q)) => Some(q as f64 / host_config["CpuPeriod"].as_i64().filter(|&p| p > 0).unwrap_or(100_000) as f64),
        _ => None,
    };
    if let Some(c) = cpus {
        run.extend(["--cpus".to_string(), c.to_string()]);
    }
    let mut exposed: Vec<String> = config["ExposedPorts"].as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
    exposed.extend(image_config.as_ref().and_then(|c| c["ExposedPorts"].as_object()).map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default());
    exposed.sort();
    exposed.dedup();
    for p in ports(&host_config, &exposed)? {
        run.extend(["--publish".to_string(), p]);
    }
    let endpoints = body["NetworkingConfig"]["EndpointsConfig"].as_object().cloned().unwrap_or_default();
    for (net, e) in &endpoints {
        if !matches!(net.as_str(), "bridge" | "flexvm" | "default") {
            return Err(Error::unsupported(format!("network {net:?}: every VM is on flexvm's one network (bridge)")));
        }
        if let Some(ip) = e["IPAMConfig"]["IPv4Address"].as_str().filter(|i| !i.is_empty()) {
            run.extend(["--ip".to_string(), ip.to_string()]);
        }
    }
    run.push(template.clone());
    if !cmd_words.is_empty() {
        run.push("--".into());
        run.extend(cmd_words);
    }
    let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    Ok(Record { name: name.to_string(), created, run, image, template, config, host_config, started: false })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_bindings_become_publish_flags() {
        let hc = json!({"PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}], "53/udp": [{"HostIp": "127.0.0.1", "HostPort": "5353"}],
            "443/tcp": [{"HostIp": "::1", "HostPort": "8443"}]}});
        let mut got = ports(&hc, &[]).unwrap();
        got.sort();
        assert_eq!(got, ["127.0.0.1:5353:53/udp", "8080:80/tcp", "[::1]:8443:443/tcp"]);
        // Any host port: a free one now.
        let any = ports(&json!({"PortBindings": {"80/tcp": [{"HostPort": ""}]}}), &[]).unwrap();
        assert!(any[0].ends_with(":80/tcp") && !any[0].starts_with("0:"), "{any:?}");
        let all = ports(&json!({"PublishAllPorts": true}), &["9000/tcp".into()]).unwrap();
        assert!(all.len() == 1 && all[0].ends_with(":9000/tcp"), "{all:?}");
        assert_eq!(ports(&json!({"PortBindings": {"80/sctp": null}}), &[]).unwrap_err().status, hyper::StatusCode::NOT_IMPLEMENTED);
        assert!(ports(&json!({"PortBindings": {"80/tcp": [{"HostPort": "8000-8010"}]}}), &[]).is_err());
    }

    #[test]
    fn what_flexvm_cannot_honour_is_refused() {
        // What docker's CLI sends for a plain `docker run`: nothing refused.
        let config = json!({"Hostname": "", "Domainname": "", "User": "", "Env": [], "Cmd": null, "Image": "busybox", "Volumes": {}, "Labels": {}});
        let hc = json!({"Binds": null, "NetworkMode": "default", "PortBindings": {}, "RestartPolicy": {"Name": "no"}, "AutoRemove": false,
            "LogConfig": {"Type": "", "Config": {}}, "CapAdd": null, "CapDrop": null, "Dns": [], "PidsLimit": null, "MemorySwap": 0,
            "OomKillDisable": false, "IpcMode": "", "CgroupnsMode": "", "Mounts": []});
        refuse_unsupported(&config, &hc, "web").unwrap();
        refuse_unsupported(&json!({"Hostname": "web"}), &json!({"MemorySwap": -1, "PidsLimit": -1}), "web").unwrap();
        for (c, h, what) in [
            (json!({}), json!({"Binds": ["/a:/b"]}), "bind mounts"),
            (json!({}), json!({"NetworkMode": "host"}), "network mode"),
            (json!({"Volumes": {"/data": {}}}), json!({}), "volumes"),
            (json!({"Hostname": "other"}), json!({}), "hostname"),
            (json!({"Healthcheck": {"Test": ["CMD", "true"]}}), json!({}), "health checks"),
            (json!({}), json!({"LogConfig": {"Type": "syslog"}}), "log driver"),
        ] {
            let e = refuse_unsupported(&c, &h, "web").unwrap_err();
            assert!(e.status == hyper::StatusCode::NOT_IMPLEMENTED && e.message.contains(what), "{what}: {e:?}");
        }
        refuse_unsupported(&json!({"Healthcheck": {"Test": ["NONE"]}}), &json!({}), "web").unwrap();
    }

    #[test]
    fn restart_policies_become_run_restart() {
        let r = |p: Value| restart(&p);
        assert_eq!(r(json!(null)).unwrap(), None);
        assert_eq!(r(json!({"Name": "no"})).unwrap(), None);
        assert_eq!(r(json!({"Name": "always"})).unwrap().as_deref(), Some("always"));
        assert_eq!(r(json!({"Name": "unless-stopped", "MaximumRetryCount": 0})).unwrap().as_deref(), Some("unless-stopped"));
        assert_eq!(r(json!({"Name": "on-failure", "MaximumRetryCount": 3})).unwrap().as_deref(), Some("on-failure:3"));
        assert_eq!(r(json!({"Name": "always", "MaximumRetryCount": 3})).unwrap_err().status, hyper::StatusCode::BAD_REQUEST);
        assert_eq!(r(json!({"Name": "sometimes"})).unwrap_err().status, hyper::StatusCode::BAD_REQUEST);
    }
}
