//! Elastic memory, guest side. The host plugs virtio-mem ahead of demand but samples only once a
//! second, so this keeps a burst from the OOM killer: overcommit is on; everything flexvm-init starts runs
//! under `/vm`, whose `memory.high` sits `headroom(MemTotal)` below MemTotal (flexvm-init stays outside,
//! so the throttle never slows the thread that lifts it); crossing it wakes the watcher, which asks the
//! host for memory while allocations are throttled. Memory block uevents move the mark; if the VM is
//! at its ceiling or nothing arrives within `GIVE_UP`, the throttle is lifted. A plug the host's
//! reserve refuses keeps it (`ok`): slow, not OOM-killed, until a plug or relief comes.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::os;

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// The throttled parent: its `memory.high` is the mark.
pub const CGROUP: &str = "/sys/fs/cgroup/vm";
const WORK: &str = "/sys/fs/cgroup/vm/work";
const GIVE_UP: Duration = Duration::from_secs(3);
const RETRY: Duration = Duration::from_millis(250);

static WORK_PROCS: OnceLock<CString> = OnceLock::new();

/// Sets up the cgroups and the watcher, subscribed to memory changes before it returns.
pub fn start() {
    let _ = std::fs::write("/proc/sys/vm/overcommit_memory", "1");
    match setup() {
        Ok((events, uev, high)) => {
            let _ = WORK_PROCS.set(CString::new(format!("{WORK}/cgroup.procs")).unwrap());
            thread::spawn(move || watch(events, uev, high));
        }
        Err(e) => eprintln!("flexvm-init: memory cgroup setup failed: {e}"),
    }
}

pub fn work_procs() -> Option<CString> {
    WORK_PROCS.get().cloned()
}

/// Moves the child into `procs`' group before exec (and before dropping privileges); fails the spawn only if `required`.
pub fn enter(cmd: &mut Command, procs: CString, required: bool) {
    unsafe {
        cmd.pre_exec(move || {
            // "0" moves the writing process; only raw syscalls after fork.
            let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            let moved = fd >= 0 && libc::write(fd, b"0".as_ptr().cast(), 1) == 1;
            if fd >= 0 {
                libc::close(fd);
            }
            if moved || !required {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
}

/// Subscribes to uevents before reading MemTotal, so a plug in between still gets an event.
fn setup() -> io::Result<(File, OwnedFd, High)> {
    std::fs::create_dir_all(CGROUP_ROOT)?;
    crate::mount("cgroup2", CGROUP_ROOT, "cgroup2", 0, "")?;
    std::fs::write(format!("{CGROUP_ROOT}/cgroup.subtree_control"), "+memory")?;
    std::fs::create_dir_all(WORK)?;
    let uev = uevents()?;
    let total = meminfo().map(|(total, _)| total);
    if let Some(total) = total {
        write_high(Some(high_limit(total)), false)?;
    }
    let high = High::new(total, write_high);
    Ok((File::open(format!("{CGROUP}/memory.events"))?, uev, high))
}

fn meminfo() -> Option<(u64, u64)> {
    read_meminfo(File::open("/proc/meminfo").ok()?)
}

fn read_meminfo(reader: impl Read) -> Option<(u64, u64)> {
    let text = io::read_to_string(reader).ok()?;
    let kib = |key| text.lines().find_map(|l| l.strip_prefix(key)?.split_whitespace().next()?.parse::<u64>().ok());
    let total = kib("MemTotal:").filter(|&total| total != 0)?;
    Some((total, kib("MemAvailable:").unwrap_or(0)))
}

fn high_limit(total_kib: u64) -> u64 {
    let total = total_kib >> 10;
    (total - crate::proto::headroom(total)) << 20
}

/// Writes `value` (None: max) unless it is installed already or, with
/// `raise_only`, would lower the mark. Separate opens keep a raise
/// independent of a worker blocked in reclaim.
fn write_high(value: Option<u64>, raise_only: bool) -> io::Result<()> {
    let path = format!("{CGROUP}/memory.high");
    let installed = std::fs::read_to_string(&path)?.trim().parse().unwrap_or(u64::MAX);
    let value = value.unwrap_or(u64::MAX);
    if value != installed && !(raise_only && value < installed) {
        std::fs::write(path, if value == u64::MAX { "max".to_string() } else { value.to_string() })?;
    }
    Ok(())
}

type WriteHigh = dyn Fn(Option<u64>, bool) -> io::Result<()> + Send + Sync;

/// Lowering the mark can reclaim synchronously (Linux 6.1), so a worker makes
/// those writes, coalesced; raises and lifts bypass it.
struct High {
    total_kib: Option<u64>,
    desired: Arc<Mutex<Option<u64>>>,
    changed: mpsc::Sender<()>,
    pending: Arc<AtomicUsize>,
    write: Arc<WriteHigh>,
}

impl High {
    fn new(total_kib: Option<u64>, write: impl Fn(Option<u64>, bool) -> io::Result<()> + Send + Sync + 'static) -> Self {
        let (desired, pending, write) = (Arc::new(Mutex::new(total_kib.map(high_limit))), Arc::new(AtomicUsize::new(0)), Arc::new(write));
        let (latest, outstanding, writer) = (desired.clone(), pending.clone(), write.clone());
        let (changed, changes) = mpsc::channel();
        thread::spawn(move || {
            while changes.recv().is_ok() {
                let count = 1 + changes.try_iter().count();
                let value = *latest.lock().unwrap();
                if let Err(e) = writer(value, false) {
                    eprintln!("flexvm-init: memory.high write failed: {e}");
                }
                outstanding.fetch_sub(count, Ordering::Relaxed);
            }
        });
        Self { total_kib, desired, changed, pending, write }
    }

    fn set_total(&mut self, total_kib: Option<u64>) {
        let Some(total_kib) = total_kib else { return };
        let (old, value) = (self.total_kib.map(high_limit), high_limit(total_kib));
        self.total_kib = Some(total_kib);
        if old != Some(value) {
            *self.desired.lock().unwrap() = Some(value);
            self.relieve();
            self.notify();
        }
    }

    fn notify(&self) {
        self.pending.fetch_add(1, Ordering::Relaxed);
        if self.changed.send(()).is_err() {
            self.pending.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn busy(&self) -> bool {
        self.pending.load(Ordering::Relaxed) != 0
    }

    /// Installs the newest mark at once if it is above the one in place,
    /// also after a stale lower write by the worker.
    fn relieve(&self) {
        let value = *self.desired.lock().unwrap();
        if let Err(e) = (self.write)(value, true) {
            eprintln!("flexvm-init: memory.high raise failed: {e}");
        }
    }

    fn lift(&self) {
        let changed = self.desired.lock().unwrap().take().is_some();
        self.relieve();
        if changed {
            // Supersedes queued numeric updates and reconciles an in-flight one.
            self.notify();
        }
    }
}

fn high_events(f: &File) -> u64 {
    let mut buf = [0u8; 256];
    let n = f.read_at(&mut buf, 0).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).lines().find_map(|l| l.strip_prefix("high ")?.trim().parse().ok()).unwrap_or(0)
}

fn uevents() -> io::Result<OwnedFd> {
    let flags = libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    let fd = unsafe { OwnedFd::from_raw_fd(os(libc::socket(libc::AF_NETLINK, flags, libc::NETLINK_KOBJECT_UEVENT))?) };
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    (addr.nl_family, addr.nl_groups) = (libc::AF_NETLINK as _, 1);
    os(unsafe { libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_nl).cast(), std::mem::size_of_val(&addr) as _) })?;
    Ok(fd)
}

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

fn watch(events: File, uev: OwnedFd, mut limit: High) {
    let mut seen = high_events(&events);
    let mut asked: Option<Instant> = None;
    let mut waiting: Option<Instant> = None;
    loop {
        let mut fds = [
            libc::pollfd { fd: events.as_raw_fd(), events: libc::POLLPRI, revents: 0 },
            libc::pollfd { fd: uev.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        let timeout = if waiting.is_some() || limit.busy() { RETRY.as_millis() as i32 } else { -1 };
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) } < 0 {
            continue;
        }
        // A lowering write that started just after a raise or lift may be blocked in reclaim.
        if limit.busy() {
            limit.relieve();
        }
        if fds[1].revents & libc::POLLIN != 0 && memory_changed(&uev) {
            // Plugged or unplugged: move the mark. Memory arriving ends a wait.
            limit.set_total(meminfo().map(|(total, _)| total));
            waiting = None;
        }
        let now = Instant::now();
        let high = high_events(&events);
        if high != seen && asked.is_none_or(|t| now - t >= RETRY) {
            seen = high;
            asked = Some(now);
            match ask() {
                Reply::Full => {
                    limit.lift();
                    waiting = None;
                    continue;
                }
                Reply::Asked => waiting = waiting.or(Some(now)),
                Reply::Enough => waiting = None,
            }
        }
        if waiting.is_some_and(|t| now - t >= GIVE_UP) {
            limit.lift();
            waiting = None;
        } else if waiting.is_some() || asked == Some(now) {
            // Reconcile with what is plugged now, in case an event was lost.
            limit.set_total(meminfo().map(|(total, _)| total));
        }
    }
}

#[derive(PartialEq)]
enum Reply {
    /// The host is plugging more (or could not be reached; retry).
    Asked,
    /// The host sees enough free memory (the mark was crossed by reclaimable memory), or its
    /// reserve refused a plug: either way the throttle stays, asked again as it is crossed.
    Enough,
    /// At the VM's ceiling: nothing more will come.
    Full,
}

/// Sends `MEM <available KiB> <total KiB>`; the host answers `grow`, `busy` (plug in flight), `ok`
/// (also when refused) or `full` (at the ceiling).
fn ask() -> Reply {
    let Some((total, avail)) = meminfo() else { return Reply::Asked };
    let reply = (|| -> io::Result<String> {
        let mut s = File::from(crate::vsock_socket()?);
        let addr = crate::vsock_addr(libc::VMADDR_CID_HOST, crate::proto::MEM_PORT);
        crate::sock_timeout(s.as_raw_fd(), libc::SO_RCVTIMEO, Duration::from_secs(2));
        os(unsafe { libc::connect(s.as_raw_fd(), (&addr as *const libc::sockaddr_vm).cast(), std::mem::size_of_val(&addr) as _) })?;
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

#[cfg(test)]
mod tests {
    use super::*;

    type Writes = mpsc::Receiver<&'static str>;

    /// A 4 GiB `High` over a memory.high that honors `raise_only`. The worker's
    /// write of `low` pauses (until resumed) before installing and again "in
    /// reclaim"; other writes report "raised".
    fn high(low: u64) -> (High, Writes, mpsc::Sender<()>, Arc<Mutex<Option<u64>>>) {
        let (sent, writes) = mpsc::channel();
        let (resume, blocked) = mpsc::channel::<()>();
        let blocked = Mutex::new(blocked);
        let installed = Arc::new(Mutex::new(Some(high_limit(4096 << 10))));
        let current = Arc::clone(&installed);
        let high = High::new(Some(4096 << 10), move |value, raise_only| {
            let now = *current.lock().unwrap();
            if value == now || (raise_only && value.unwrap_or(u64::MAX) < now.unwrap_or(u64::MAX)) {
                return Ok(());
            }
            if value == Some(low) {
                let _ = sent.send("starting");
                let _ = blocked.lock().unwrap().recv();
                *current.lock().unwrap() = value;
                let _ = sent.send("reclaiming");
                let _ = blocked.lock().unwrap().recv();
            } else {
                *current.lock().unwrap() = value;
                let _ = sent.send("raised");
            }
            Ok(())
        });
        (high, writes, resume, installed)
    }

    fn next(writes: &Writes) -> &'static str {
        writes.recv_timeout(Duration::from_secs(1)).unwrap()
    }

    fn settle(high: &High) {
        let end = Instant::now() + Duration::from_secs(1);
        while high.busy() {
            assert!(Instant::now() < end);
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn invalid_meminfo_leaves_high_unchanged() {
        // A directory opens successfully but cannot be read as meminfo.
        let unreadable = File::open(std::env::temp_dir()).unwrap();
        let readings = [
            read_meminfo(unreadable),
            read_meminfo(&b"MemTotal: 0 kB\nMemAvailable: 0 kB\n"[..]),
            read_meminfo(&b"MemAvailable: 1024 kB\n"[..]),
            read_meminfo(&b"MemTotal: invalid kB\n"[..]),
        ];
        let (mut high, writes, _resume, installed) = high(0);
        let initial = Some(high_limit(4096 << 10));
        for reading in readings {
            assert_eq!(reading, None);
            high.set_total(reading.map(|(total, _)| total));
            assert!(!high.busy());
            assert_eq!(high.total_kib, Some(4096 << 10));
            assert_eq!(*high.desired.lock().unwrap(), initial);
            assert_eq!(*installed.lock().unwrap(), initial);
            assert!(writes.try_recv().is_err());
        }
    }

    #[test]
    fn meminfo_requires_total_but_available_can_be_missing() {
        assert_eq!(read_meminfo(&b"MemTotal: 4194304 kB\nMemAvailable: 1024 kB\n"[..]), Some((4194304, 1024)));
        assert_eq!(read_meminfo(&b"MemTotal: 4194304 kB\n"[..]), Some((4194304, 0)));
    }

    #[test]
    fn unknown_initial_total_waits_for_a_valid_reading() {
        let (sent, writes) = mpsc::channel();
        let mut high = High::new(None, move |value, _| {
            sent.send(value).unwrap();
            Ok(())
        });
        high.set_total(None);
        assert!(!high.busy());
        assert!(writes.try_recv().is_err());
        high.set_total(Some(4096 << 10));
        settle(&high);
        assert_eq!(high.total_kib, Some(4096 << 10));
        assert_eq!(*high.desired.lock().unwrap(), Some(high_limit(4096 << 10)));
        assert_eq!(writes.try_recv().unwrap(), Some(high_limit(4096 << 10)));
        assert!(writes.try_iter().all(|value| value == Some(high_limit(4096 << 10))));
    }

    #[test]
    fn unchanged_total_does_not_write_or_rearm_after_lift() {
        let (mut high, writes, _resume, installed) = high(0);
        high.set_total(Some(4096 << 10));
        high.set_total(Some((4096 << 10) + 1));
        assert!(writes.try_recv().is_err());
        high.lift();
        assert_eq!((next(&writes), *installed.lock().unwrap()), ("raised", None));
        high.set_total(Some((4096 << 10) + 2));
        assert_eq!(*high.desired.lock().unwrap(), None);
    }

    #[test]
    fn lift_bypasses_and_repairs_a_blocked_numeric_write() {
        let (mut high, writes, resume, installed) = high(high_limit(2048 << 10));
        high.set_total(Some(2048 << 10));
        assert_eq!(next(&writes), "starting");
        // GIVE_UP's lift supersedes the queued numeric update.
        high.set_total(Some(1024 << 10));
        high.lift();
        assert_eq!(next(&writes), "raised");
        // The blocked write lands late; the watcher repairs it while it reclaims.
        resume.send(()).unwrap();
        assert_eq!(next(&writes), "reclaiming");
        assert_eq!(*installed.lock().unwrap(), Some(high_limit(2048 << 10)));
        assert!(high.busy());
        high.relieve();
        assert_eq!(*installed.lock().unwrap(), None);
        resume.send(()).unwrap();
        settle(&high);
        assert_eq!(*installed.lock().unwrap(), None);
    }

    #[test]
    fn raises_bypass_a_blocked_lowering_write_but_never_lower_the_mark() {
        let (mut high, writes, resume, installed) = high(high_limit(2048 << 10));
        high.set_total(Some(2048 << 10));
        assert_eq!(next(&writes), "starting");
        // Above the last desired mark but below the installed one: a direct
        // write would reclaim on the watcher, so the worker gets it.
        high.set_total(Some(1024 << 10));
        high.set_total(Some(3072 << 10));
        assert!(writes.try_recv().is_err());
        assert_eq!(*installed.lock().unwrap(), Some(high_limit(4096 << 10)));
        high.set_total(Some(8192 << 10));
        assert_eq!(next(&writes), "raised");
        resume.send(()).unwrap();
        assert_eq!(next(&writes), "reclaiming");
        high.relieve();
        assert_eq!(*installed.lock().unwrap(), Some(high_limit(8192 << 10)));
        assert_eq!(next(&writes), "raised");
        resume.send(()).unwrap();
        settle(&high);
        assert_eq!(*installed.lock().unwrap(), Some(high_limit(8192 << 10)));
    }
}
