//! `flexvm api`: the Docker Engine API on a Unix socket, so docker's CLI, Compose and the SDKs drive
//! flexvm's VMs as containers. It keeps no state that matters: what it answers comes from the records in
//! the state and run directories (as `ps` and `inspect` read them), and what it changes it changes as the
//! commands do, by running them (this binary, with this process's `--state` and `--run`). Killed and
//! started again, it has lost nothing; socket-activated, it starts at the first connection.
//!
//! An endpoint is served only where flexvm has the machinery under it: the rest answer 501, saying so.

mod cli;
mod containers;
pub(crate) mod create;
mod images;
mod lifecycle;
mod system;

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
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
/// The most a JSON request body may hold.
const MAX_JSON: usize = 4 << 20;

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

    pub fn conflict(message: impl Into<String>) -> Error {
        Error::new(StatusCode::CONFLICT, message)
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
    /// `--state`, `--run` (and `--verbose`) as this process was given them: a command it runs gets them first.
    pub globals: Vec<String>,
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
pub fn main(host: Host, paths: Paths, globals: Vec<String>, socket: Option<&str>) -> Result<()> {
    let activated = activated();
    let (listener, at, _lock) = match activated {
        Some(l) => (l, None, None),
        None => {
            let path = socket.map_or_else(|| host.run.join("docker.sock"), PathBuf::from);
            let (listener, lock) = bind(&path)?;
            (listener, Some(path), Some(lock))
        }
    };
    if let Some(at) = &at {
        crate::log!("flexvm api: serving the Docker Engine API (v{API_VERSION}) on unix://{}", at.display());
    }
    listener.set_nonblocking(true)?;
    let api = Arc::new(Api { host, paths, globals });
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).max_blocking_threads(64).enable_all().build()?;
    rt.block_on(async { serve(tokio::net::UnixListener::from_std(listener)?, api).await })
}

/// The Unix socket systemd passed as fd 3, if it passed one.
fn activated() -> Option<std::os::unix::net::UnixListener> {
    crate::socket::activated().map(Into::into)
}

/// Published at 0600 from a private directory. Only stale sockets are replaced; the path's lock
/// stays with the server so concurrent starts cannot publish over each other.
fn bind(path: &Path) -> Result<(std::os::unix::net::UnixListener, crate::host::Flock)> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
    crate::socket::check(path)?;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let m = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let uid = unsafe { libc::geteuid() };
    if !m.is_dir() || (m.uid() != 0 && m.uid() != uid) || m.mode() & 0o022 != 0 {
        crate::bail!("{} must be a directory owned by root or this user, not writable by group or others", dir.display());
    }
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let file = std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|e| format!("{}: opening socket lock: {e}", path.display()))?;
    let served = || format!("{} is served already (another flexvm api, or docker?): give another SOCKET", path.display());
    let lock = crate::host::Flock::new(file, libc::LOCK_EX | libc::LOCK_NB).map_err(|e| match e.kind() {
        std::io::ErrorKind::WouldBlock => served(),
        _ => format!("{}: locking socket: {e}", path.display()),
    })?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_socket() => crate::bail!("{} is not a socket", path.display()),
        Ok(_) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => return Err(served().into()),
            Err(e) if matches!(e.raw_os_error(), Some(libc::ECONNREFUSED | libc::ENOENT)) => {}
            Err(e) => return Err(format!("{}: {e}", path.display()).into()),
        },
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(e) => return Err(format!("{}: {e}", path.display()).into()),
    }
    // bind_private checks the opened directory is this user's and closed to others.
    let private = dir.join(".api");
    match std::fs::DirBuilder::new().mode(0o700).create(&private) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(format!("{}: {e}", private.display()).into()),
        _ => {}
    }
    let listener = crate::socket::bind_private(&private.join(crate::socket::private_name()), path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((listener, lock))
}

async fn serve(listener: tokio::net::UnixListener, api: Arc<Api>) -> Result<()> {
    let connections = Arc::new(tokio::sync::Semaphore::new(256));
    loop {
        let permit = connections.clone().acquire_owned().await?;
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
            let _permit = permit;
            let service = hyper::service::service_fn(move |req| {
                let api = api.clone();
                async move { Ok::<_, Infallible>(respond(&api, req).await) }
            });
            // With a timer, hyper closes a connection idle 30 s between requests (its header timeout).
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .with_upgrades();
            match conn.await {
                Err(e) if !e.is_timeout() => crate::info!("flexvm api: connection: {e}"),
                _ => {}
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
        (_, ["containers", rest @ ..]) => match containers::route(api, req, rest).await {
            Some(r) => r,
            None => Err(unrouted(&method, path)),
        },
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

/// A reply with no body (204, or 304 for "already so").
pub fn empty(status: StatusCode) -> Reply {
    let mut res = Response::new(full(Vec::new()));
    *res.status_mut() = status;
    Ok(res)
}

pub fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into()).map_err(|e: Infallible| match e {}).boxed()
}

/// A body written as it goes (a stream's output, an answer that waits): what is sent on the sender, until
/// it is dropped. A sender whose send fails knows its client is gone.
pub fn channel() -> (tokio::sync::mpsc::Sender<Bytes>, Body) {
    struct Channel(tokio::sync::mpsc::Receiver<Bytes>);
    impl hyper::body::Body for Channel {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
            self.0.poll_recv(cx).map(|b| b.map(|b| Ok(hyper::body::Frame::data(b))))
        }
    }
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    (tx, Channel(rx).boxed())
}

/// A request's JSON body (none, or an empty one: `null`).
pub async fn body_json(req: Request<Incoming>) -> std::result::Result<Value, Error> {
    let bytes = Limited::new(req.into_body(), MAX_JSON).collect().await.map_err(|e| Error::bad(format!("reading the request: {e}")))?.to_bytes();
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes).map_err(|e| Error::bad(format!("bad JSON in the request: {e}")))
}

/// A request's query parameters, decoded, in order.
pub struct Query(Vec<(String, String)>);

impl Query {
    pub fn of<B>(req: &Request<B>) -> Query {
        Query::parse(req.uri().query().unwrap_or(""))
    }

    pub fn parse(q: &str) -> Query {
        Query(q.split('&').filter(|p| !p.is_empty()).map(|p| p.split_once('=').unwrap_or((p, ""))).map(|(k, v)| (decode(k), decode(v))).collect())
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// Docker's booleans: `1`, `true` or `True` (any case); absent, `default`.
    pub fn flag(&self, key: &str, default: bool) -> std::result::Result<bool, Error> {
        match self.get(key).map(str::to_ascii_lowercase).as_deref() {
            None | Some("") => Ok(default),
            Some("1" | "true" | "yes") => Ok(true),
            Some("0" | "false" | "no") => Ok(false),
            Some(v) => Err(Error::bad(format!("bad boolean {key}={v}"))),
        }
    }

    pub fn number<T: std::str::FromStr>(&self, key: &str) -> std::result::Result<Option<T>, Error> {
        self.get(key).filter(|v| !v.is_empty()).map(|v| v.parse().map_err(|_| Error::bad(format!("bad number {key}={v}")))).transpose()
    }

    /// `filters`: docker's JSON map of a key to its values (`{"name": ["web"]}`, or an older client's
    /// `{"name": {"web": true}}`).
    pub fn filters(&self) -> std::result::Result<Vec<(String, String)>, Error> {
        let Some(raw) = self.get("filters").filter(|f| !f.is_empty()) else { return Ok(Vec::new()) };
        let v: Value = serde_json::from_str(raw).map_err(|e| Error::bad(format!("bad filters {raw}: {e}")))?;
        let mut out = Vec::new();
        for (key, values) in v.as_object().ok_or_else(|| Error::bad(format!("bad filters {raw}: not an object")))? {
            match values {
                Value::Array(a) => out.extend(a.iter().filter_map(Value::as_str).map(|s| (key.clone(), s.to_string()))),
                Value::Object(o) => out.extend(o.iter().filter(|(_, on)| on.as_bool() == Some(true)).map(|(s, _)| (key.clone(), s.clone()))),
                _ => return Err(Error::bad(format!("bad filters {raw}: {key}'s values"))),
            }
        }
        Ok(out)
    }
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

/// Seconds since the epoch, as `rfc3339`.
pub fn rfc3339_secs(secs: u64) -> String {
    rfc3339(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

/// Percent-decoding, `+` as a space (form encoding, as Go's query parser).
fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut i) = (Vec::with_capacity(b.len()), 0);
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            // Two hex digits (from_str_radix alone would take a sign).
            b'%' => match b
                .get(i + 1..i + 3)
                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok())
            {
                Some(v) => {
                    out.push(v);
                    i += 3;
                    continue;
                }
                None => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};

    fn fixture() -> crate::test_util::TempDir {
        let target = Path::new("../target");
        fs::create_dir_all(target).unwrap();
        crate::test_util::TempDir::new_in(target, "api")
    }

    fn refused(path: &Path, message: &str) {
        let error = bind(path).err().expect("bind must fail").to_string();
        assert!(error.contains(&path.display().to_string()) && error.contains(message), "{error}");
    }

    #[test]
    fn non_sockets_are_left_intact() {
        let t = fixture();
        let path = t.join("docker.sock");
        fs::write(&path, b"keep").unwrap();
        refused(&path, "not a socket");
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        refused(&path, "not a socket");
        fs::remove_dir(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        refused(&path, "not a socket");
        assert_eq!(fs::read_link(&path).unwrap(), Path::new("missing"));
    }

    #[test]
    fn stale_socket_is_replaced() {
        let t = fixture();
        let path = t.join("docker.sock");
        drop(UnixListener::bind(&path).unwrap());
        let old = fs::metadata(&path).unwrap().ino();
        let (_listener, _lock) = bind(&path).unwrap();
        assert_ne!(fs::metadata(&path).unwrap().ino(), old);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        UnixStream::connect(&path).unwrap();
    }

    #[test]
    fn live_server_is_refused() {
        let t = fixture();
        let path = t.join("docker.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        let old = fs::metadata(&path).unwrap().ino();
        refused(&path, "is served already");
        assert_eq!(fs::metadata(&path).unwrap().ino(), old);
    }

    #[test]
    fn concurrent_bind_is_refused_while_lock_is_held() {
        use crate::test_util::JoinWithin;
        let t = fixture();
        let path = t.join("docker.sock");
        let (listener, lock) = bind(&path).unwrap();
        let other = path.clone();
        std::thread::spawn(move || refused(&other, "is served already")).join_within().unwrap();
        // The lock also protects a server whose published name was removed.
        fs::remove_file(&path).unwrap();
        refused(&path, "is served already");
        drop((listener, lock));
        let (_listener, _lock) = bind(&path).unwrap();
    }

    #[test]
    fn writable_parent_is_refused_even_when_sticky() {
        let t = fixture();
        let path = t.join("docker.sock");
        for mode in [0o720, 0o702, 0o1777] {
            fs::set_permissions(&t, fs::Permissions::from_mode(mode)).unwrap();
            let error = bind(&path).err().expect("bind must fail").to_string();
            assert!(error.contains(&t.display().to_string()) && error.contains("not writable"), "{error}");
            assert!(!path.exists() && !t.join(".api").exists() && !t.join("docker.sock.lock").exists());
        }
        fs::set_permissions(&t, fs::Permissions::from_mode(0o700)).unwrap();
    }

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
    fn queries_decode_as_go_does() {
        let q = Query::parse("all=1&filters=%7B%22name%22%3A%5B%22web%22%5D%7D&x=a+b&bad=%zz&t=True&f=0&e=");
        assert_eq!(q.get("x"), Some("a b"));
        assert_eq!(q.get("bad"), Some("%zz"));
        assert_eq!((q.flag("all", false).unwrap(), q.flag("t", false).unwrap(), q.flag("f", true).unwrap()), (true, true, false));
        assert_eq!((q.flag("e", true).unwrap(), q.flag("none", true).unwrap()), (true, true));
        assert!(q.flag("x", false).is_err());
        assert_eq!(q.filters().unwrap(), [("name".to_string(), "web".to_string())]);
        let old = Query::parse("filters=%7B%22status%22%3A%7B%22running%22%3Atrue%2C%22paused%22%3Afalse%7D%7D");
        assert_eq!(old.filters().unwrap(), [("status".to_string(), "running".to_string())]);
        assert!(Query::parse("filters=%5B%5D").filters().is_err());
        assert_eq!(decode("%41%4a%4B"), "AJK");
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%4"), "%4");
        assert_eq!(decode("%-1"), "%-1", "two hex digits, not a sign");
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
