//! Elastic memory, guest side.
//!
//! The host plugs virtio-mem memory ahead of demand, but it only samples the
//! guest once a second. This keeps a fast allocation burst from reaching the
//! OOM killer in between:
//!
//! - Overcommit is always allowed, so one allocation bigger than the memory
//!   plugged so far succeeds; the host plugs more as it is touched.
//! - Everything flexvm-init starts runs under one memory cgroup (`/vm`) whose
//!   `memory.high` sits `headroom(MemTotal)` below MemTotal, the same mark the
//!   host keeps free: commands and the app in `/vm/work`, readiness checks in
//!   their own groups under `/vm`. flexvm-init itself stays outside, so the
//!   throttle never slows the thread that has to lift it.
//! - Crossing the mark wakes this thread at once (a `memory.events`
//!   notification, no polling), which asks the host for memory over vsock.
//!   Allocations that outrun the plug are throttled by the kernel instead of
//!   OOM-killed.
//! - Plugs and unplugs move the mark (memory block uevents, subscribed to
//!   before the first read of MemTotal). If the host cannot grow the VM, or
//!   nothing arrives within `GIVE_UP`, the throttle is lifted so the guest
//!   behaves as it would without it.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

/// Host (CID 2) port for memory requests; the host listens on `<vsock uds>_53`.
const HOST_PORT: u32 = 53;
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// The throttled parent: its `memory.high` is the mark.
const CGROUP: &str = "/sys/fs/cgroup/vm";
const WORK: &str = "/sys/fs/cgroup/vm/work";
/// Lift the throttle when no memory has arrived this long after asking.
const GIVE_UP: Duration = Duration::from_secs(3);
/// Minimum gap between requests while still over the mark.
const RETRY: Duration = Duration::from_millis(250);

/// `<WORK>/cgroup.procs`, once the cgroups are set up.
static WORK_PROCS: OnceLock<CString> = OnceLock::new();

/// Free memory (MiB) the host keeps plugged for a guest with `total` MiB.
/// Must match `headroom` in flexvm/src/daemon.rs.
fn headroom(total: u64) -> u64 {
    (total / 4).max(1024.min(total / 2))
}

/// Sets up the cgroups and the watcher. Returns once the watcher is
/// subscribed to memory changes, so none can be missed after readiness.
pub fn start() {
    let _ = std::fs::write("/proc/sys/vm/overcommit_memory", "1");
    match setup() {
        Ok((events, uev)) => {
            let _ = WORK_PROCS.set(CString::new(format!("{WORK}/cgroup.procs")).unwrap());
            thread::spawn(move || watch(events, uev));
        }
        Err(e) => eprintln!("flexvm-init: memory cgroup setup failed: {e}"),
    }
}

/// `cgroup.procs` of the throttled group for workloads, for a child to move
/// itself into before exec (and before dropping privileges).
pub fn work_procs() -> Option<CString> {
    WORK_PROCS.get().cloned()
}

/// Where other groups that should share the mark go (readiness checks).
pub fn parent() -> Option<&'static str> {
    WORK_PROCS.get().map(|_| CGROUP)
}

/// Puts `cmd`'s child into the throttled group before exec, unless an
/// earlier `pre_exec` already moved it out of the root cgroup.
pub fn contain(cmd: &mut Command) {
    let Some(procs) = work_procs() else { return };
    unsafe {
        cmd.pre_exec(move || {
            // Raw syscalls only, after fork. Failing to move must not fail the spawn.
            let mut buf = [0u8; 16];
            let fd = libc::open(c"/proc/self/cgroup".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Ok(());
            }
            let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
            libc::close(fd);
            if n == 5 && &buf[..5] == b"0::/\n" {
                let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if fd >= 0 {
                    libc::write(fd, b"0".as_ptr().cast(), 1);
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }
}

/// Creates the groups and subscribes to memory block uevents, then sets the
/// mark from MemTotal (in that order: a plug in between still gets an event).
/// Returns `/vm/memory.events`, which the kernel flags when the mark is crossed.
fn setup() -> io::Result<(File, OwnedFd)> {
    std::fs::create_dir_all(CGROUP_ROOT)?;
    let rc = unsafe {
        libc::mount(c"cgroup2".as_ptr(), c"/sys/fs/cgroup".as_ptr(), c"cgroup2".as_ptr(), 0, std::ptr::null())
    };
    if rc != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EBUSY) {
        return Err(io::Error::last_os_error());
    }
    std::fs::write(format!("{CGROUP_ROOT}/cgroup.subtree_control"), "+memory")?;
    std::fs::create_dir_all(WORK)?;
    let uev = uevents()?;
    set_high(meminfo().0)?;
    Ok((File::open(format!("{CGROUP}/memory.events"))?, uev))
}

/// (MemTotal, MemAvailable) in KiB.
fn meminfo() -> (u64, u64) {
    let (mut total, mut avail) = (0, 0);
    if let Ok(f) = File::open("/proc/meminfo") {
        for line in BufReader::new(f).lines().map_while(|l| l.ok()) {
            let kib = || line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
            if line.starts_with("MemTotal:") {
                total = kib();
            } else if line.starts_with("MemAvailable:") {
                avail = kib();
                break;
            }
        }
    }
    (total, avail)
}

fn set_high(total_kib: u64) -> io::Result<()> {
    let total = total_kib >> 10;
    std::fs::write(format!("{CGROUP}/memory.high"), ((total - headroom(total)) << 20).to_string())
}

fn lift() {
    let _ = std::fs::write(format!("{CGROUP}/memory.high"), "max");
}

/// The `high` counter of memory.events.
fn high_events(f: &File) -> u64 {
    let mut buf = [0u8; 256];
    let n = f.read_at(&mut buf, 0).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n])
        .lines()
        .find_map(|l| l.strip_prefix("high ").and_then(|v| v.trim().parse().ok()))
        .unwrap_or(0)
}

/// A socket that receives the kernel's device uevents.
fn uevents() -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, libc::NETLINK_KOBJECT_UEVENT)
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as _;
    addr.nl_groups = 1;
    let rc = unsafe {
        libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_nl).cast(), std::mem::size_of_val(&addr) as _)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Drains pending uevents; true if any was about a memory block.
fn memory_changed(fd: &OwnedFd) -> bool {
    let mut buf = [0u8; 4096];
    let mut changed = false;
    loop {
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            return changed;
        }
        changed |= buf[..n as usize].split(|&b| b == 0).any(|f| f == b"SUBSYSTEM=memory");
    }
}

fn watch(events: File, uev: OwnedFd) {
    let mut seen = high_events(&events);
    let mut asked: Option<Instant> = None;
    // Since when we have been over the mark, waiting for memory from the host.
    let mut waiting: Option<Instant> = None;
    loop {
        let mut fds = [
            libc::pollfd { fd: events.as_raw_fd(), events: libc::POLLPRI, revents: 0 },
            libc::pollfd { fd: uev.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        let timeout = if waiting.is_some() { RETRY.as_millis() as i32 } else { -1 };
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) } < 0 {
            continue;
        }
        if fds[1].revents & libc::POLLIN != 0 && memory_changed(&uev) {
            // Plugged or unplugged: move the mark. Memory arriving ends a wait.
            let _ = set_high(meminfo().0);
            waiting = None;
        }
        let now = Instant::now();
        let high = high_events(&events);
        if high != seen && asked.is_none_or(|t| now - t >= RETRY) {
            seen = high;
            asked = Some(now);
            match ask() {
                Reply::Full => {
                    lift();
                    waiting = None;
                    continue;
                }
                Reply::Asked => waiting = waiting.or(Some(now)),
                Reply::Enough => waiting = None,
            }
        }
        if waiting.is_some_and(|t| now - t >= GIVE_UP) {
            lift();
            waiting = None;
        } else if waiting.is_some() || asked == Some(now) {
            // Reconcile with what is plugged now, in case an event was lost.
            let _ = set_high(meminfo().0);
        }
    }
}

#[derive(PartialEq)]
enum Reply {
    /// The host is plugging more (or could not be reached; retry).
    Asked,
    /// The host sees enough free memory; the mark was crossed by reclaimable memory.
    Enough,
    /// The host cannot grow this VM.
    Full,
}

/// Tells the host how much memory is left: `MEM <available KiB> <total KiB>`.
/// It answers `grow`, `busy` (a plug is in flight), `ok` or `full`.
fn ask() -> Reply {
    let (total, avail) = meminfo();
    let reply = (|| -> io::Result<String> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut s = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        addr.svm_family = libc::AF_VSOCK as _;
        addr.svm_port = HOST_PORT;
        addr.svm_cid = libc::VMADDR_CID_HOST;
        let timeout = libc::timeval { tv_sec: 2, tv_usec: 0 };
        let opt = (&timeout as *const libc::timeval).cast();
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, opt, std::mem::size_of_val(&timeout) as _) };
        let rc = unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_vm).cast(), std::mem::size_of_val(&addr) as _) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        s.write_all(format!("MEM {avail} {total}\n").as_bytes())?;
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
    })();
    match reply {
        Ok(r) if r.starts_with("full") => Reply::Full,
        Ok(r) if r.starts_with("ok") => Reply::Enough,
        _ => Reply::Asked,
    }
}
