//! `flexvm api`: the Docker Engine API on a Unix socket, so docker's CLI, Compose and the SDKs drive
//! flexvm's VMs as containers. It keeps no state that matters: what it answers comes from the records in
//! the state and run directories (as `ps` and `inspect` read them), and what it changes it changes as the
//! commands do, by running them (this binary, with this process's `--state` and `--run`). Killed and
//! started again, it has lost nothing; socket-activated, it starts at the first connection.
//!
//! An endpoint is served only where flexvm has the machinery under it: the rest answer 501, saying so.

mod system;

use std::convert::Infallible;
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use serde_json::{json, Value};

use crate::host::Host;
use crate::template::Paths;
use crate::util::Result;

/// The newest API version served: its requests' and replies' shapes. Clients negotiate down to it (`_ping`).
pub const API_VERSION: &str = "1.47";
/// The oldest one a client may ask for.
pub const MIN_API_VERSION: &str = "1.24";
pub type Body = BoxBody<Bytes, std::io::Error>;

/// What a request failed with: docker's `{"message": ...}` under `status`.
#[derive(Debug)]
pub struct Error {
    pub status: StatusCode,
    pub message: String,
}

impl Error {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Error {
        Error { status, message: message.into() }
    }

    pub fn bad(message: impl Into<String>) -> Error {
        Error::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn missing(message: impl Into<String>) -> Error {
        Error::new(StatusCode::NOT_FOUND, message)
    }

    /// An endpoint (or a setting) flexvm has no machinery for.
    pub fn unsupported(what: impl std::fmt::Display) -> Error {
        Error::new(StatusCode::NOT_IMPLEMENTED, format!("{what} is not supported by flexvm"))
    }
}

impl From<crate::util::Error> for Error {
    fn from(e: crate::util::Error) -> Error {
        Error::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

pub type Reply = std::result::Result<Response<Body>, Error>;

/// What every handler has: the host as the commands open it, and how to run them.
pub struct Api {
    pub host: Host,
    pub paths: Paths,
}

impl Api {
    /// `f` on a blocking thread: the records are read with the commands' own (blocking) code.
    pub async fn blocking<T: Send + 'static>(self: &Arc<Self>, f: impl FnOnce(&Api) -> Result<T> + Send + 'static) -> std::result::Result<T, Error> {
        let api = self.clone();
        tokio::task::spawn_blocking(move || f(&api)).await.map_err(|e| Error::from(crate::util::Error::from(e.to_string())))?.map_err(Error::from)
    }
}

/// `flexvm api [SOCKET]`: serves on SOCKET (default `RUN/docker.sock`), or on the socket systemd passed
/// (`LISTEN_FDS`), until killed.
pub fn main(host: Host, paths: Paths, socket: Option<&str>) -> Result<()> {
    let activated = activated();
    let (listener, at) = match activated {
        Some(l) => (l, None),
        None => {
            let path = socket.map_or_else(|| host.run.join("docker.sock"), PathBuf::from);
            (bind(&path)?, Some(path))
        }
    };
    if let Some(at) = &at {
        crate::log!("flexvm api: serving the Docker Engine API (v{API_VERSION}) on unix://{}", at.display());
    }
    listener.set_nonblocking(true)?;
    let api = Arc::new(Api { host, paths });
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).max_blocking_threads(64).enable_all().build()?;
    rt.block_on(async { serve(tokio::net::UnixListener::from_std(listener)?, api).await })
}

/// The Unix socket systemd passed as fd 3, if it passed one.
fn activated() -> Option<std::os::unix::net::UnixListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let n: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    // Close-on-exec: no command it runs inherits it.
    (pid == std::process::id() && n >= 1 && unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } == 0)
        .then(|| unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) })
}

/// Bound at a private name in a 0700 directory beside `path`, made 0600 there and moved to `path`: never
/// reachable by another user (it is root's, as docker's socket is root's and its group's). A server that
/// answers there already is never replaced; a socket nothing answers on is.
fn bind(path: &Path) -> Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    crate::socket::check(path)?;
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        crate::bail!("{} is served already (another flexvm api, or docker?): give another SOCKET", path.display());
    }
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let private = dir.join(".api");
    match std::fs::DirBuilder::new().mode(0o700).create(&private) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(format!("{}: {e}", private.display()).into()),
        _ => {}
    }
    let m = std::fs::symlink_metadata(&private)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        crate::bail!("{} must be a directory of this user's, closed to others", private.display());
    }
    let short = private.join(format!(".{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&short);
    let listener = std::os::unix::net::UnixListener::bind(&short)?;
    let placed = std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o600)).and_then(|()| std::fs::rename(&short, path));
    if let Err(e) = placed {
        let _ = std::fs::remove_file(&short);
        return Err(format!("{}: {e}", path.display()).into());
    }
    Ok(listener)
}

async fn serve(listener: tokio::net::UnixListener, api: Arc<Api>) -> Result<()> {
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            // Out of fds, say: the next one may get through.
            Err(e) => {
                crate::log!("flexvm api: accepting a connection: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let api = api.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let api = api.clone();
                async move { Ok::<_, Infallible>(respond(&api, req).await) }
            });
            let conn = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), service).with_upgrades();
            if let Err(e) = conn.await {
                crate::info!("flexvm api: connection: {e}");
            }
        });
    }
}

/// A request's reply, with the headers docker's carry: an error as `{"message": ...}`.
async fn respond(api: &Arc<Api>, req: Request<Incoming>) -> Response<Body> {
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    let mut res = match route(api, req).await {
        Ok(r) => r,
        Err(e) => {
            crate::info!("flexvm api: {method} {path}: {} {}", e.status.as_u16(), e.message);
            json(e.status, &json!({"message": e.message}))
        }
    };
    let h = res.headers_mut();
    h.insert("Api-Version", HeaderValue::from_static(API_VERSION));
    h.insert("Docker-Experimental", HeaderValue::from_static("false"));
    h.insert("Ostype", HeaderValue::from_static("linux"));
    h.insert("Server", HeaderValue::from_static(concat!("flexvm/", env!("CARGO_PKG_VERSION"), " (linux)")));
    res
}

/// The path without its `/vMAJOR.MINOR` prefix, and the version it asked for (None: none).
fn versioned(path: &str) -> std::result::Result<(&str, Option<&str>), Error> {
    let Some(rest) = path.strip_prefix("/v") else { return Ok((path, None)) };
    let (version, tail) = rest.split_once('/').map_or((rest, ""), |(v, t)| (v, &path[path.len() - t.len() - 1..]));
    if parse_version(version).is_none() {
        return Ok((path, None));
    }
    if cmp_version(version, API_VERSION).is_gt() {
        return Err(Error::bad(format!("client version {version} is too new. Maximum supported API version is {API_VERSION}")));
    }
    if cmp_version(version, MIN_API_VERSION).is_lt() {
        return Err(Error::bad(format!(
            "client version {version} is too old. Minimum supported API version is {MIN_API_VERSION}, please upgrade your client to a newer version"
        )));
    }
    Ok((if tail.is_empty() { "/" } else { tail }, Some(version)))
}

fn parse_version(v: &str) -> Option<(u32, u32)> {
    let (major, minor) = v.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

pub fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
    parse_version(a).cmp(&parse_version(b))
}

async fn route(api: &Arc<Api>, req: Request<Incoming>) -> Reply {
    let path = req.uri().path().to_string();
    let (path, _version) = versioned(&path)?;
    let words: Vec<&str> = path.trim_matches('/').split('/').collect();
    let method = req.method().clone();
    match (&method, words.as_slice()) {
        (&Method::GET | &Method::HEAD, ["_ping"]) => system::ping(&method),
        (&Method::GET, ["version"]) => system::version(api).await,
        (&Method::GET, ["info"]) => system::info(api).await,
        _ => Err(unrouted(&method, path)),
    }
}

/// Docker's endpoints flexvm does not serve (swarm, plugins, builds, volumes, ...): 501, saying which; any
/// other path is docker's 404.
fn unrouted(method: &Method, path: &str) -> Error {
    const DOCKERS: &[&str] = &[
        "containers",
        "images",
        "build",
        "networks",
        "volumes",
        "exec",
        "swarm",
        "nodes",
        "services",
        "tasks",
        "secrets",
        "configs",
        "plugins",
        "system",
        "events",
        "auth",
        "commit",
        "session",
        "distribution",
        "grpc",
    ];
    match path.trim_start_matches('/').split('/').next() {
        Some(first) if DOCKERS.contains(&first) => Error::unsupported(format!("{method} {path}")),
        _ => Error::missing(format!("page not found: {method} {path}")),
    }
}

/// A JSON reply.
pub fn json(status: StatusCode, v: &Value) -> Response<Body> {
    let mut res = Response::new(full(serde_json::to_vec(v).unwrap_or_default()));
    *res.status_mut() = status;
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    res
}

/// 200 with `v`.
pub fn ok(v: &Value) -> Reply {
    Ok(json(StatusCode::OK, v))
}

pub fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into()).map_err(|e: Infallible| match e {}).boxed()
}

/// `t` in UTC as docker writes times (RFC 3339, nanoseconds); the epoch for a time before it.
pub fn rfc3339(t: std::time::SystemTime) -> String {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let (days, secs) = ((d.as_secs() / 86400) as i64, d.as_secs() % 86400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z", secs / 3600, secs / 60 % 60, secs % 60, d.subsec_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_stripped_and_bounded() {
        assert_eq!(versioned("/v1.47/containers/json").unwrap(), ("/containers/json", Some("1.47")));
        assert_eq!(versioned("/v1.41/_ping").unwrap(), ("/_ping", Some("1.41")));
        assert_eq!(versioned("/containers/json").unwrap(), ("/containers/json", None));
        assert_eq!(versioned("/v1.47").unwrap(), ("/", Some("1.47")));
        // Not a version: a path like any other.
        assert_eq!(versioned("/volumes").unwrap(), ("/volumes", None));
        assert_eq!(versioned("/vx.y/info").unwrap(), ("/vx.y/info", None));
        let new = versioned("/v1.99/info").unwrap_err();
        assert!(new.status == StatusCode::BAD_REQUEST && new.message.contains("too new"), "{new:?}");
        assert!(versioned("/v1.12/info").unwrap_err().message.contains("too old"));
        assert!(cmp_version("1.9", "1.10").is_lt(), "by number, not as text");
    }

    #[test]
    fn times_are_rfc3339_in_utc() {
        let secs = |s| rfc3339(std::time::UNIX_EPOCH + std::time::Duration::from_secs(s));
        assert_eq!(secs(0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(secs(951782400), "2000-02-29T00:00:00.000000000Z");
        assert_eq!(secs(1792713600 + 3661), "2026-10-23T01:01:01.000000000Z");
        assert_eq!(rfc3339(std::time::UNIX_EPOCH + std::time::Duration::new(86399, 5)), "1970-01-01T23:59:59.000000005Z");
    }
}
