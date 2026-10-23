//! `POST /containers/create`: docker's create, then start, as flexvm's one `run -d`. A created container is
//! a record (`STATE/api/containers/NAME.json`) of what `run` it starts with, translated from docker's
//! settings when it is created (a setting flexvm cannot honour is refused then), and of docker's settings
//! as given, which `inspect` shows (its labels, say) as long as its VM is there. A record whose VM is gone
//! (removed with `flexvm rm`, an `--rm` one that exited) goes as it is next read.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{images, Api, Error};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub name: String,
    /// Seconds since the epoch.
    pub created: u64,
    /// `run -d --name NAME` takes these next: flags, then IMAGE, then CMD.
    pub run: Vec<String>,
    /// The image as given, and its template.
    pub image: String,
    pub template: String,
    /// The immutable generation selected at create time.
    #[serde(default)]
    pub generation: String,
    /// A rename holds this destination until the VM and record have moved.
    #[serde(default)]
    pub reserved: bool,
    #[serde(default)]
    pub reservation_owner: Option<crate::host::Ident>,
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
    for mut r in load_all(api) {
        if r.reserved {
            if r.reservation_owner.as_ref().is_some_and(|id| id.liveness() != crate::host::Liveness::Gone) {
                // The VM may have moved even though publication (and rollback) failed. Keep its
                // settings visible while the owner lives, without releasing an active reservation.
                if !r.image.is_empty() {
                    if let Some(v) = vms.iter_mut().find(|v| v["name"] == r.name.as_str()) {
                        r.reserved = false;
                        r.reservation_owner = None;
                        r.started = true;
                        v["docker"] = json!(r);
                    }
                }
                continue;
            }
            if r.image.is_empty() || (!vms.iter().any(|v| v["name"] == r.name.as_str()) && !api.host.alive(&r.name)) {
                remove(api, &r.name);
                continue;
            }
            // The owner died after moving the VM: retain its Docker settings at the destination.
            r.reserved = false;
            r.reservation_owner = None;
            r.started = true;
            let _ = store(api, &r, false);
        }
        match vms.iter_mut().find(|v| v["name"] == r.name.as_str()) {
            Some(v) => v["docker"] = json!(r),
            None if !r.started => {
                let created = json!({"name": r.name, "state": "created", "template": r.template, "created": r.created, "docker": r});
                vms.insert(0, created);
            }
            // Its VM is gone, or one holds the name and is not listed yet (starting): gone only if not that.
            None if !api.host.alive(&r.name) => remove(api, &r.name),
            // Starting under its name, not registered yet (a restart policy's rerun, a start): still the container.
            None => vms.push(json!({"name": r.name, "state": "starting", "template": r.template, "docker": r})),
        }
    }
    vms
}

/// Resolve Docker's optional app overrides, preserving empty argv words. `[]` and `[""]` clear
/// an entrypoint; a nonempty supplied entrypoint also drops the image's default command.
/// An empty supplied command inherits the image's command when the supplied entrypoint is empty.
pub fn app(config: &Value, entrypoint: Vec<String>, cmd: Vec<String>) -> (Vec<String>, Vec<String>) {
    let e = config["Entrypoint"].as_array().map(|_| images::strings(&config["Entrypoint"]));
    let c = config["Cmd"].as_array().map(|_| images::strings(&config["Cmd"]));
    let cmd = c.filter(|c| !c.is_empty()).unwrap_or(if e.as_ref().is_some_and(|e| !e.is_empty()) { Vec::new() } else { cmd });
    let entrypoint = e.map(|e| if e == [""] { Vec::new() } else { e }).unwrap_or(entrypoint);
    (entrypoint, cmd)
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
        let none = key == "Healthcheck" && v["Test"].as_array().is_some_and(|t| t.first().and_then(Value::as_str) == Some("NONE"));
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
    let template = crate::template::name_of(&image).ok();
    let linked = template.as_ref().and_then(|name| images::linked(api, name));
    let generation = match linked.clone() {
        Some(id) => id,
        None => crate::template::generation_by_prefix(&api.paths, image.strip_prefix("sha256:").unwrap_or(&image)).map_err(|e| {
            if e.to_string().contains("is the start of") {
                Error::bad(format!("ambiguous reference: multiple IDs found with provided prefix: {image}"))
            } else {
                Error::missing(format!("No such image: {image}"))
            }
        })?,
    };
    let template = if linked.is_some() { template.unwrap() } else { generation.clone() };
    let tpl = images::meta(api, &generation).ok_or_else(|| Error::missing(format!("No such image: {image}")))?;
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
    if config["Entrypoint"].is_array() || config["Cmd"].is_array() {
        let (e, c) = app(&config, image_entrypoint, image_cmd);
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
    run.push(generation.clone());
    if !cmd_words.is_empty() {
        run.push("--".into());
        run.extend(cmd_words);
    }
    let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    Ok(Record { name: name.to_string(), created, run, image, template, generation, config, host_config, ..Record::default() })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub fn fixture() -> (crate::test_util::TempDir, std::sync::Arc<Api>) {
        let d = crate::test_util::TempDir::new("api-create");
        let host = crate::host::Host::open(&d.join("state"), &d.join("run")).unwrap();
        let api = std::sync::Arc::new(Api { host, paths: crate::template::Paths::new(&d.join("state")), globals: vec![] });
        image(&api, "aaaa1111", json!({"Entrypoint": ["/bin/sh", "-c", ""], "Cmd": ["default"], "Labels": {"keep": "image"}, "Env": ["A=image", "B=image"]}));
        std::os::unix::fs::symlink(".gen/aaaa1111", api.paths.templates.join("image")).unwrap();
        (d, api)
    }

    pub fn image(api: &Api, id: &str, config: Value) {
        let blob = serde_json::to_vec(&json!({"config": config})).unwrap();
        let digest = crate::image::registry::sha256_hex(&blob);
        let path = crate::image::registry::blob_path(&api.host.state.join("images/blobs"), &digest).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, blob).unwrap();
        let generation = api.paths.templates.join(crate::template::GENERATIONS).join(id);
        std::fs::create_dir_all(&generation).unwrap();
        let argv: Vec<_> = images::strings(&config["Entrypoint"]).into_iter().chain(images::strings(&config["Cmd"])).collect();
        let meta = json!({
            "compatibility": {"cpu": "", "tsc_khz": 0, "tsc_control": false, "msrs": [], "firecracker": "", "features": {}, "xsave": {}},
            "vcpus": 1, "mem_mib": 1, "max_mib": 1, "plugged_mib": 0, "kernel": "", "rootfs": "", "id": id, "components": {},
            "image": {"source": "image", "digest": "sha256:source", "config_digest": digest, "app_conf": "", "argv": argv, "warm": false}
        });
        std::fs::write(generation.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
    }

    #[test]
    fn abandoned_reservations_release_names_and_preserve_moved_configs() {
        let (_d, api) = fixture();
        let mut r = translate(&api, "web", &json!({"Image": "image"})).unwrap();
        r.reserved = true;
        r.reservation_owner = Some(crate::host::Ident { boot: "old".into(), ..Default::default() });
        store(&api, &r, true).unwrap();
        assert!(merge(&api, vec![]).is_empty());
        assert!(load(&api, "web").is_none());
        store(&api, &r, true).unwrap();
        let rows = merge(&api, vec![json!({"name": "web", "state": "running"})]);
        assert_eq!(rows[0]["docker"]["config"], r.config);
        assert!(!load(&api, "web").unwrap().reserved);
    }

    #[test]
    fn abandoned_reservation_without_docker_config_is_removed() {
        let (_d, api) = fixture();
        let r = Record {
            name: "web".into(),
            reserved: true,
            started: true,
            reservation_owner: Some(crate::host::Ident { boot: "old".into(), ..Default::default() }),
            ..Record::default()
        };
        store(&api, &r, true).unwrap();
        let vm = json!({"name": "web", "state": "running"});
        assert_eq!(merge(&api, vec![vm.clone()]), vec![vm]);
        assert!(load(&api, "web").is_none());
    }

    #[test]
    fn app_overrides_distinguish_null_empty_arrays_and_the_clearing_sentinel() {
        let entrypoint = vec!["sh".into(), "-c".into(), "".into()];
        let cmd = vec!["default".into()];
        for config in [json!({}), json!({"Entrypoint": null, "Cmd": null})] {
            assert_eq!(app(&config, entrypoint.clone(), cmd.clone()), (entrypoint.clone(), cmd.clone()));
        }
        assert_eq!(app(&json!({"Entrypoint": []}), entrypoint.clone(), cmd.clone()), (vec![], cmd.clone()));
        for e in [json!([]), json!([""])] {
            assert_eq!(app(&json!({"Entrypoint": e, "Cmd": ["echo", ""]}), entrypoint.clone(), cmd.clone()), (vec![], vec!["echo".into(), "".into()]));
        }
        assert_eq!(app(&json!({"Entrypoint": ["sh", "-c", ""]}), vec![], cmd.clone()), (entrypoint.clone(), vec![]));
        assert_eq!(app(&json!({"Cmd": []}), entrypoint.clone(), cmd.clone()), (entrypoint.clone(), cmd.clone()));
        assert_eq!(app(&json!({"Entrypoint": [], "Cmd": []}), entrypoint.clone(), cmd.clone()), (vec![], cmd.clone()));
        for e in [json!(["other"]), json!([""])] {
            let expected = if e == json!([""]) { vec![] } else { vec!["other".into()] };
            assert_eq!(app(&json!({"Entrypoint": e, "Cmd": []}), entrypoint.clone(), cmd.clone()), (expected, vec![]));
        }
    }

    #[test]
    fn create_accepts_names_and_local_ids_but_not_ambiguous_prefixes() {
        let (_d, api) = fixture();
        for image in ["image", "aaaa1111", "aaaa", "sha256:aaaa1111", "sha256:aaaa"] {
            let r = translate(&api, "web", &json!({"Image": image})).unwrap();
            assert_eq!(r.generation, "aaaa1111");
            assert_eq!(r.run.last().unwrap(), "aaaa1111");
            assert_eq!(crate::template::name_of(r.run.last().unwrap()).unwrap(), "aaaa1111");
        }
        image(&api, "aaaa2222", json!({"Cmd": ["other"]}));
        for image in ["aaaa", "sha256:aaaa"] {
            let e = translate(&api, "web", &json!({"Image": image})).unwrap_err();
            assert_eq!(e.status, hyper::StatusCode::BAD_REQUEST);
            assert_eq!(e.message, format!("ambiguous reference: multiple IDs found with provided prefix: {image}"));
        }
        for image in ["bbbb", "missing"] {
            assert_eq!(translate(&api, "web", &json!({"Image": image})).unwrap_err().status, hyper::StatusCode::NOT_FOUND);
        }
    }

    #[test]
    fn created_generation_survives_retagging_and_is_released_on_removal() {
        let (_d, api) = fixture();
        let r = translate(&api, "web", &json!({"Image": "image"})).unwrap();
        assert!(store(&api, &r, true).unwrap());
        image(&api, "bbbb2222", json!({"Cmd": ["other"]}));
        std::fs::remove_file(api.paths.templates.join("image")).unwrap();
        std::os::unix::fs::symlink(".gen/bbbb2222", api.paths.templates.join("image")).unwrap();
        let r = load(&api, "web").unwrap();
        assert_eq!(r.run.last().unwrap(), "aaaa1111");
        assert_eq!(crate::template::Template::resolve(&api.paths, r.run.last().unwrap()).unwrap(), api.paths.templates.join(".gen/aaaa1111"));
        assert!(api.host.template_users().contains("aaaa1111"));
        assert!(crate::host::recorded_template_users(&api.host.state, "shared").contains("aaaa1111"));
        assert!(crate::template::prune(&api.paths, Some("aaaa1111"), &|| api.host.template_users(), false).unwrap().is_empty());
        let v = merge(&api, vec![]).pop().unwrap();
        let d = super::super::containers::Detail::read(&api, &v);
        assert_eq!(d.image_id, "sha256:aaaa1111");
        assert_eq!(d.entrypoint, ["/bin/sh", "-c", ""]);
        remove(&api, "web");
        assert!(!api.host.template_users().contains("aaaa1111"));
    }

    #[test]
    fn create_and_inspect_share_optional_app_overrides_and_empty_arguments() {
        let (_d, api) = fixture();
        for (overrides, expected) in [
            (json!({"Cmd": ["override", ""]}), vec!["/bin/sh", "-c", "", "override", ""]),
            (json!({"Entrypoint": ["/bin/sh", "-c", ""]}), vec!["/bin/sh", "-c", ""]),
            (json!({"Entrypoint": [""], "Cmd": ["echo", ""]}), vec!["echo", ""]),
            (json!({"Entrypoint": [], "Cmd": ["echo"]}), vec!["echo"]),
            (json!({"Entrypoint": null, "Cmd": null}), vec!["/bin/sh", "-c", "", "default"]),
            (json!({"Cmd": []}), vec!["/bin/sh", "-c", "", "default"]),
            (json!({"Entrypoint": [], "Cmd": []}), vec!["default"]),
        ] {
            let mut body = overrides;
            body["Image"] = json!("image");
            body["Env"] = json!(["A=container", "B", "C=new"]);
            let r = translate(&api, "web", &body).unwrap();
            let d = super::super::containers::Detail::read(&api, &json!({"name": "web", "state": "created", "docker": r}));
            assert_eq!(d.entrypoint.iter().chain(&d.cmd).map(String::as_str).collect::<Vec<_>>(), expected);
            assert_eq!(d.env, ["B=image", "A=container", "C=new"]);
            if let Some(words) = r.run.windows(2).find(|w| w[0] == "--entrypoint") {
                assert_eq!(serde_json::from_str::<Vec<String>>(&words[1]).unwrap(), expected);
            } else {
                assert_eq!(expected, ["/bin/sh", "-c", "", "default"]);
            }
        }
    }

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
