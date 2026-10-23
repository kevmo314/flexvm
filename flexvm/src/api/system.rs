//! `_ping`, `version` and `info`: what a client asks first, from what `flexvm info` and `version` say.

use std::sync::Arc;

use hyper::header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use hyper::{Method, Response, StatusCode};
use serde_json::{json, Value};

use super::{full, ok, Api, Reply, API_VERSION, MIN_API_VERSION};

/// `GET|HEAD /_ping`: `OK`, and (in every reply's headers) the API version a client negotiates down to.
pub fn ping(method: &Method) -> Reply {
    let mut res = Response::new(full(if method == Method::HEAD { "" } else { "OK" }));
    let h = res.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache, no-store, must-revalidate"));
    h.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    *res.status_mut() = StatusCode::OK;
    Ok(res)
}

/// The kernel's release, as `uname -r`.
pub fn kernel() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy().into_owned()
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// `GET /version`: flexvm's version as the engine's, with its Firecracker and kernel as components.
pub async fn version(api: &Arc<Api>) -> Reply {
    let kernel = kernel();
    let (fc, vmlinux) = (api.paths.firecracker.display().to_string(), api.paths.kernel.display().to_string());
    ok(&json!({
        "Platform": {"Name": "flexvm"},
        "Components": [
            {"Name": "Engine", "Version": env!("CARGO_PKG_VERSION"), "Details": {
                "ApiVersion": API_VERSION, "MinAPIVersion": MIN_API_VERSION, "GitCommit": env!("FLEXVM_GIT_COMMIT"), "Os": "linux", "Arch": "amd64",
                "KernelVersion": kernel, "Experimental": "false"}},
            {"Name": "firecracker", "Version": option_env!("FLEXVM_PIN_FIRECRACKER").unwrap_or("unpinned"), "Details": {"Path": fc}},
            {"Name": "guest kernel", "Version": option_env!("FLEXVM_PIN_VMLINUX").unwrap_or("unpinned"), "Details": {"Path": vmlinux}},
        ],
        "Version": env!("CARGO_PKG_VERSION"),
        "ApiVersion": API_VERSION,
        "MinAPIVersion": MIN_API_VERSION,
        "GitCommit": env!("FLEXVM_GIT_COMMIT"),
        "GoVersion": "",
        "Os": "linux",
        "Arch": "amd64",
        "KernelVersion": kernel,
    }))
}

/// Counts of containers by docker's states, from `ps -a`'s (`vms`).
pub fn counts(vms: &[Value]) -> (usize, usize, usize) {
    let paused = vms.iter().filter(|v| v["state"] == "paused").count();
    let stopped = vms.iter().filter(|v| crate::stopped(v)).count();
    (vms.len() - paused - stopped, paused, stopped)
}

/// `GET /info`: the host as `flexvm info` and `ps -a` see it.
pub async fn info(api: &Arc<Api>) -> Reply {
    let (vms, images, warnings) = api
        .blocking(|api| {
            let images = crate::template::images(&api.paths).map(|i| i.len()).unwrap_or(0);
            Ok((crate::vms(&api.host), images, api.host.config_now().warnings()))
        })
        .await?;
    let (running, paused, stopped) = counts(&vms);
    let mem = crate::util::proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0);
    let mut v = json!({
        "ID": crate::host::boot_id(),
        "Containers": vms.len(),
        "ContainersRunning": running,
        "ContainersPaused": paused,
        "ContainersStopped": stopped,
        "Images": images,
        "Driver": "flexvm",
        "DriverStatus": [["State directory", api.host.state.display().to_string()], ["Run directory", api.host.run.display().to_string()]],
        "Plugins": {"Volume": [], "Network": [], "Authorization": null, "Log": []},
        "MemoryLimit": true,
        "SwapLimit": false,
        "CpuCfsPeriod": true,
        "CpuCfsQuota": true,
        "CPUShares": false,
        "CPUSet": false,
        "PidsLimit": false,
        "OomKillDisable": false,
        "IPv4Forwarding": true,
        "Debug": crate::util::verbose(),
        "NFd": 0,
        "NGoroutines": 0,
        "SystemTime": super::rfc3339(std::time::SystemTime::now()),
        "LoggingDriver": "json-file",
        "CgroupDriver": "cgroupfs",
        "CgroupVersion": "2",
        "NEventsListener": 0,
    });
    let more = json!({
        "KernelVersion": kernel(),
        "OperatingSystem": "flexvm",
        "OSVersion": env!("CARGO_PKG_VERSION"),
        "OSType": "linux",
        "Architecture": "x86_64",
        "NCPU": crate::util::host_cpus(),
        "MemTotal": mem,
        "IndexServerAddress": "https://index.docker.io/v1/",
        "RegistryConfig": {"IndexConfigs": {}, "InsecureRegistryCIDRs": [], "Mirrors": []},
        "GenericResources": null,
        "DockerRootDir": api.host.state.display().to_string(),
        "HttpProxy": std::env::var("HTTP_PROXY").unwrap_or_default(),
        "HttpsProxy": std::env::var("HTTPS_PROXY").unwrap_or_default(),
        "NoProxy": std::env::var("NO_PROXY").unwrap_or_default(),
        "Name": hostname(),
        "Labels": [],
        "ExperimentalBuild": false,
        "ServerVersion": env!("CARGO_PKG_VERSION"),
        "Runtimes": {"flexvm": {"path": std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default()}},
        "DefaultRuntime": "flexvm",
        "Swarm": {"LocalNodeState": "inactive", "ControlAvailable": false, "NodeID": "", "NodeAddr": "", "RemoteManagers": null, "Error": ""},
        "LiveRestoreEnabled": false,
        "Isolation": "",
        "InitBinary": "",
        "SecurityOptions": [],
        "Warnings": warnings,
    });
    if let (Some(v), Value::Object(more)) = (v.as_object_mut(), more) {
        v.extend(more);
    }
    ok(&v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn warnings_follow_host_config() {
        let root = crate::test_util::TempDir::new("api-info");
        let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
        let api = Arc::new(Api { paths: crate::template::Paths::new(&host.state), host, globals: Vec::new(), streams: Default::default() });
        let warnings = |host: &crate::host::Host| crate::info(host)["warnings"].clone();
        let before = warnings(&api.host);
        let body = info(&api).await.unwrap().into_body().collect().await.unwrap().to_bytes();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["Warnings"], before);
        let mut other = api.host.clone();
        other
            .configure(|c| {
                c.peers = vec!["192.0.2.1:7070".into()];
                Ok(())
            })
            .unwrap();
        let after = warnings(&other);
        assert_ne!(before, after);
        let body = info(&api).await.unwrap().into_body().collect().await.unwrap().to_bytes();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["Warnings"], after);
    }
}
