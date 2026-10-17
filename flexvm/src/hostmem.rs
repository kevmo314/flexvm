//! Host memory state the VM processes share (#648), in `RUN/.locks/memory-v2-BOOT`, mapped by each.
//!
//! - The room rescue memory, hot pages' memory and writer buffers grow within (`cow::Room`): one for the host, so VMs
//!   copying at once share it rather than each spending all of it.
//! - Requests that the VM processes release the memory they keep for their next checkpoint (`release_kept`): it is
//!   not admitted like a guest's, so before admission refuses a grant, or eviction or the standby pool reacts to the
//!   host running short, every VM process lets its kept memory go and MemAvailable is read again. Kept memory never
//!   causes a refusal or an eviction then.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// VM processes that can be asked at once; one past them keeps its memory (but for its own controller's release when
/// the host is short, `Pager::host_memory`).
const MEMBERS: usize = 1020;

/// How long a release request waits for the VM processes to answer.
pub const RELEASE_WAIT: Duration = Duration::from_millis(200);

/// How long after a release request another one is not made: the memory kept went back then, and callers queued on
/// the host lock would each wait again.
const RELEASE_GAP_MS: u64 = 1000;

#[repr(C)]
pub struct Shared {
    /// `cow::Room`'s word and when it was last refreshed (boottime ms).
    pub room: AtomicU64,
    pub stamp: AtomicU64,
    /// Bumped by each release request; the VM processes wait on it (a futex).
    release: AtomicU32,
    _pad: u32,
    /// When the last release request was made (boottime ms).
    released: AtomicU64,
    members: [Member; MEMBERS],
}

#[repr(C)]
struct Member {
    /// One word, so claiming the slot, reserving, and reclaiming it from a process gone are each one compare-and-swap
    /// (#674): a reclaim succeeds only on the word it saw, never on a new owner's. Its process's tag (`tag_of`; 0 for
    /// a free slot) above `PEND_BITS`, and below them the MiB that process took from the room (`cow::Room::take`)
    /// and has yet to populate: MemAvailable still shows that memory, so a refresh and admission count it as used
    /// until then (#672).
    word: AtomicU64,
    /// The last release request it answered.
    ack: AtomicU32,
    _pad: u32,
}

const PEND_BITS: u32 = 24;
const PEND: u64 = (1 << PEND_BITS) - 1;
const PID_BITS: u32 = 22;

/// A process's tag: its pid (at most 2^22, Linux's limit) and the low bits of its start time, so another that got
/// its pid is not taken for it.
fn tag_of(pid: u32, start: u64) -> u64 {
    (pid as u64 & ((1 << PID_BITS) - 1)) | (start & ((1 << (64 - PEND_BITS - PID_BITS)) - 1)) << PID_BITS
}

fn tag(w: u64) -> u64 {
    w >> PEND_BITS
}

fn pend(w: u64) -> u64 {
    w & PEND
}

fn me() -> u64 {
    let id = crate::host::Ident::me();
    tag_of(id.pid, id.start)
}

/// Whether the process tagged `t` still runs (not another that got its pid), and whether it is stopped (it cannot
/// answer then). None if it is gone.
fn running(t: u64) -> Option<bool> {
    let pid = (t & ((1 << PID_BITS) - 1)) as u32;
    if t == 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let (state, start) = (*fields.first()?, fields.get(19)?.parse::<u64>().ok()?);
    (state != "Z" && tag_of(pid, start) == t).then_some(!matches!(state, "T" | "t"))
}

fn alive(t: u64) -> bool {
    running(t).is_some()
}

fn futex(word: &AtomicU32, op: libc::c_int, val: u32, timeout: Option<Duration>) {
    let ts = timeout.map(|t| libc::timespec { tv_sec: t.as_secs() as _, tv_nsec: t.subsec_nanos() as _ });
    let tp = ts.as_ref().map_or(std::ptr::null(), |t| t as *const libc::timespec);
    // Shared (not FUTEX_PRIVATE): the word is in a file mapped by other processes.
    unsafe { libc::syscall(libc::SYS_futex, word.as_ptr(), op, val, tp, std::ptr::null::<u32>(), 0) };
}

/// Mappings by path, made once a process: `&'static`, never unmapped.
static MAPPED: Mutex<Vec<(PathBuf, &'static Shared)>> = Mutex::new(Vec::new());

/// The host's, under its RUN directory `run`.
pub fn at(run: &Path) -> std::io::Result<&'static Shared> {
    let path = crate::host::locks(run).join(format!("memory-v2-{}", crate::host::boot_id()));
    let mut mapped = MAPPED.lock().unwrap();
    if let Some(&(_, s)) = mapped.iter().find(|(p, _)| *p == path) {
        return Ok(s);
    }
    let s = map(&path)?;
    mapped.push((path, s));
    Ok(s)
}

/// Maps `path` (made, zeroed, if missing). Zero is a valid state throughout: no room known yet, no member. Refused
/// unless it is a regular file of this user's (or root's) that no one else may write, with no other link and of the
/// size mapped: another could change the room, or truncate it under the VMs (which would then fault on it).
fn map(path: &Path) -> std::io::Result<&'static Shared> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let f = crate::host::private_file(path)?;
    let len = std::mem::size_of::<Shared>() as u64;
    if f.metadata()?.len() == 0 {
        f.set_len(len)?;
    }
    let m = f.metadata()?;
    let euid = unsafe { libc::geteuid() };
    let bad = |why: &str| Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("{}: {why}", path.display())));
    if !m.file_type().is_file() {
        return bad("not a regular file");
    }
    if m.uid() != 0 && m.uid() != euid {
        return bad("owned by another user");
    }
    if m.mode() & 0o022 != 0 {
        return bad("writable by others");
    }
    if m.nlink() != 1 {
        return bad("linked elsewhere");
    }
    if m.len() != len {
        return bad(&format!("{} bytes, not {len}", m.len()));
    }
    let p = unsafe { libc::mmap(std::ptr::null_mut(), len as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, f.as_raw_fd(), 0) };
    if p == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    // Page-aligned, and all atomics (any bytes are some state).
    Ok(unsafe { &*(p as *const Shared) })
}

impl Shared {
    /// This process's member slot: its own, or one free or left by a process that is gone (claimed with nothing
    /// reserved). None if every one is another's that runs.
    pub fn slot(&self) -> Option<usize> {
        let me = me();
        if let Some(i) = self.members.iter().position(|m| tag(m.word.load(Ordering::SeqCst)) == me) {
            return Some(i);
        }
        self.members.iter().position(|m| {
            let w = m.word.load(Ordering::SeqCst);
            (w == 0 || !alive(tag(w))) && m.word.compare_exchange(w, me << PEND_BITS, Ordering::SeqCst, Ordering::SeqCst).is_ok()
        })
    }

    /// Counts `mib` more (or, not `more`, fewer) taken by this process, in its slot `slot`, and not yet populated.
    /// False if the slot is not its own (any more): nothing is counted.
    pub fn reserve(&self, slot: usize, mib: u64, more: bool) -> bool {
        let me = me();
        let mib = mib.min(PEND);
        let r = self.members[slot].word.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |w| {
            (tag(w) == me).then(|| me << PEND_BITS | if more { (pend(w) + mib).min(PEND) } else { pend(w).saturating_sub(mib) })
        });
        r.is_ok()
    }

    /// Frees `m` if it still holds `w`, the word of a process gone (with what it had reserved): a new owner's is left.
    fn reclaim(m: &Member, w: u64) {
        let _ = m.word.compare_exchange(w, 0, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// MiB taken from the room and not yet populated by processes still running; the slots of those gone are
    /// reclaimed, their reservations with them.
    pub fn outstanding(&self) -> u64 {
        let mut sum = 0;
        for m in &self.members {
            let w = m.word.load(Ordering::SeqCst);
            if pend(w) == 0 {
                continue;
            }
            match alive(tag(w)) {
                true => sum += pend(w),
                false => Shared::reclaim(m, w),
            }
        }
        sum
    }

    /// Every slot another running process's (init's).
    #[cfg(test)]
    pub fn occupy_all(&self) {
        let init = tag_of(1, crate::host::starttime(1).unwrap());
        self.members.iter().for_each(|m| m.word.store(init << PEND_BITS, Ordering::SeqCst));
    }

    #[cfg(test)]
    pub fn free(&self, slot: usize) {
        self.members[slot].word.store(0, Ordering::SeqCst);
    }

    /// Whether this process answers release requests (`serve`).
    #[cfg(test)]
    pub fn joined(&self) -> bool {
        let me = me();
        self.members.iter().any(|m| tag(m.word.load(Ordering::SeqCst)) == me)
    }

    /// Answers release requests for the life of this process, calling `release` for each (one at a time). Returns at
    /// once if there is no slot left for it.
    pub fn serve(&self, release: impl Fn()) {
        let Some(m) = self.slot().map(|i| &self.members[i]) else {
            crate::log!("hostmem: no slot left: memory kept for checkpoints is not released on request");
            return;
        };
        // Requests made before it joined have no kept memory of its to ask for.
        m.ack.store(self.release.load(Ordering::SeqCst), Ordering::SeqCst);
        loop {
            let g = self.release.load(Ordering::SeqCst);
            if m.ack.load(Ordering::SeqCst) != g {
                release();
                m.ack.store(g, Ordering::SeqCst);
            }
            // Timed only so a lost wake costs a second, never forever.
            futex(&self.release, libc::FUTEX_WAIT, g, Some(Duration::from_secs(1)));
        }
    }

    /// Asks every VM process to release the memory it keeps for its next checkpoint, and waits until each that runs
    /// has, or `deadline`. Not for those stopped (they cannot answer), and the slots of those gone are freed. Whether
    /// every one answered.
    pub fn release_kept(&self, deadline: Instant) -> bool {
        self.released.store(crate::host::boottime_ms(), Ordering::SeqCst);
        let g = self.release.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
        futex(&self.release, libc::FUTEX_WAKE, i32::MAX as u32, None);
        let answered = |m: &Member| (m.ack.load(Ordering::SeqCst).wrapping_sub(g) as i32) >= 0;
        let mut all = true;
        for m in &self.members {
            let w = m.word.load(Ordering::SeqCst);
            if w == 0 || answered(m) {
                continue;
            }
            match running(tag(w)) {
                None => {
                    Shared::reclaim(m, w);
                    continue;
                }
                Some(false) => {
                    all = false;
                    continue;
                }
                Some(true) => {}
            }
            while !answered(m) && tag(m.word.load(Ordering::SeqCst)) == tag(w) {
                if Instant::now() >= deadline {
                    all = false;
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        all
    }

    /// `release_kept`, unless a request was made within `RELEASE_GAP_MS`: false then, as for one not answered.
    pub fn release_kept_once(&self, deadline: Instant) -> bool {
        let (now, last) = (crate::host::boottime_ms(), self.released.load(Ordering::SeqCst));
        if last != 0 && now.wrapping_sub(last) < RELEASE_GAP_MS || self.released.compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return false;
        }
        self.release_kept(deadline)
    }

    /// Forgets the last release request, so the next one is made at once.
    #[cfg(test)]
    pub fn forget_release(&self) {
        self.released.store(0, Ordering::SeqCst);
    }
}

/// `Shared::outstanding` for the host under `run`; 0 if it cannot be mapped (nothing could reserve there then).
pub fn outstanding(run: &Path) -> u64 {
    at(run).map_or(0, |s| s.outstanding())
}

/// Asks the VM processes of the host under `run` to release the memory they keep for their next checkpoint
/// (`Shared::release_kept_once`), waiting up to `RELEASE_WAIT` (or `deadline`, if sooner). Callers read MemAvailable
/// again after it whatever it found: some may have answered.
pub fn release_kept(run: &Path, deadline: Option<Instant>) {
    let by = Instant::now() + RELEASE_WAIT;
    match at(run) {
        Ok(s) => drop(s.release_kept_once(deadline.map_or(by, |d| d.min(by)))),
        Err(e) => crate::log!("hostmem: cannot ask for kept memory back: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    #[test]
    fn a_release_request_waits_for_every_member_to_release() {
        let dir = crate::test_util::TempDir::new("hostmem");
        let s = at(&dir).unwrap();
        // Mapped once a process: the same memory again.
        assert!(std::ptr::eq(s, at(&dir).unwrap()));
        // Nobody to ask: answered at once.
        let t = Instant::now();
        assert!(s.release_kept(t + Duration::from_secs(5)));
        assert!(t.elapsed() < Duration::from_secs(1));
        let released = Arc::new(AtomicUsize::new(0));
        let r = released.clone();
        std::thread::spawn(move || {
            s.serve(|| {
                std::thread::sleep(Duration::from_millis(20));
                r.fetch_add(1, Ordering::SeqCst);
            })
        });
        let t = Instant::now();
        while !s.joined() {
            assert!(t.elapsed() < Duration::from_secs(5), "joined");
            std::thread::sleep(Duration::from_millis(1));
        }
        // Waits for the release (20 ms), not for the deadline.
        assert!(s.release_kept(Instant::now() + Duration::from_secs(5)));
        assert_eq!(released.load(Ordering::SeqCst), 1);
        assert!(s.release_kept(Instant::now() + Duration::from_secs(5)));
        assert_eq!(released.load(Ordering::SeqCst), 2);
        // Another mapping of the file (as another process has) sees the same state.
        let other = map(&crate::host::locks(&dir).join(format!("memory-v2-{}", crate::host::boot_id()))).unwrap();
        assert!(!std::ptr::eq(s, other));
        assert_eq!(other.release.load(Ordering::SeqCst), s.release.load(Ordering::SeqCst));
        // A member that does not answer in time: the request gives up at its deadline.
        other.members[MEMBERS - 1].word.store(me() << PEND_BITS, Ordering::SeqCst);
        let t = Instant::now();
        assert!(!s.release_kept(Instant::now() + Duration::from_millis(50)), "the silent one did not answer");
        assert!(t.elapsed() < Duration::from_secs(2));
        // Gone (no such process): not waited for, and its slot freed.
        other.members[MEMBERS - 1].word.store(gone(1) << PEND_BITS, Ordering::SeqCst);
        assert!(s.release_kept(Instant::now() + Duration::from_secs(5)));
        assert_eq!(other.members[MEMBERS - 1].word.load(Ordering::SeqCst), 0, "pruned");
        // Stopped: it cannot answer, so it is not waited for (but it keeps its slot).
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
        let t = Instant::now();
        let stopped = loop {
            if let Some(false) = crate::host::starttime(pid).and_then(|st| running(tag_of(pid, st))) {
                break tag_of(pid, crate::host::starttime(pid).unwrap());
            }
            assert!(t.elapsed() < Duration::from_secs(5), "stopped");
            std::thread::sleep(Duration::from_millis(1));
        };
        other.members[MEMBERS - 1].word.store(stopped << PEND_BITS, Ordering::SeqCst);
        let t = Instant::now();
        assert!(!s.release_kept(Instant::now() + Duration::from_secs(5)), "not every one answered");
        assert!(t.elapsed() < Duration::from_secs(2), "not waited for");
        assert_eq!(tag(other.members[MEMBERS - 1].word.load(Ordering::SeqCst)), stopped);
        other.members[MEMBERS - 1].word.store(0, Ordering::SeqCst);
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A tag no running process has: a pid past any here.
    fn gone(n: u64) -> u64 {
        tag_of((1 << PID_BITS) - 2, n)
    }

    /// What a process took from the room and has yet to populate counts while it runs; once it is gone its slot is
    /// reclaimed with its reservations (#672), and a slot claimed starts with none.
    #[test]
    fn reservations_of_processes_gone_are_reclaimed() {
        let dir = crate::test_util::TempDir::new("hostmem-reserved");
        let s = at(&dir).unwrap();
        let mine = s.slot().unwrap();
        assert!(s.reserve(mine, 30, true));
        let dead = MEMBERS - 2;
        s.members[dead].word.store(gone(1) << PEND_BITS | 50, Ordering::SeqCst);
        assert_eq!(s.outstanding(), 30, "only the running one's");
        assert_eq!(s.members[dead].word.load(Ordering::SeqCst), 0, "reclaimed");
        assert!(s.reserve(mine, 10, false));
        assert_eq!(s.outstanding(), 20);
        assert!(s.reserve(mine, 100, false));
        assert_eq!(s.outstanding(), 0, "never below none");
        // Not its own slot: nothing counted.
        assert!(!s.reserve(dead, 5, true));
        assert_eq!(s.members[dead].word.load(Ordering::SeqCst), 0);
        // A slot claimed from a process gone starts with nothing reserved.
        s.members[mine].word.store(0, Ordering::SeqCst);
        s.members[dead].word.store(gone(2) << PEND_BITS | 70, Ordering::SeqCst);
        let init = tag_of(1, crate::host::starttime(1).unwrap());
        (0..MEMBERS).filter(|&i| i != dead).for_each(|i| s.members[i].word.store(init << PEND_BITS, Ordering::SeqCst));
        assert_eq!(s.slot(), Some(dead));
        assert_eq!(s.members[dead].word.load(Ordering::SeqCst), me() << PEND_BITS);
    }

    /// A reclaim of a slot whose process it saw gone never takes a new owner's claim or reservation (#674): it frees
    /// the slot only if it still holds the word it saw.
    #[test]
    fn a_reclaim_leaves_a_new_owner_alone() {
        let dir = crate::test_util::TempDir::new("hostmem-reclaim");
        let s = at(&dir).unwrap();
        let m = &s.members[3];
        let seen = gone(1) << PEND_BITS | 50;
        m.word.store(seen, Ordering::SeqCst);
        // Claimed and reserved by a new owner after the reclaim saw it.
        assert!(m.word.compare_exchange(seen, me() << PEND_BITS, Ordering::SeqCst, Ordering::SeqCst).is_ok());
        assert!(s.reserve(3, 30, true));
        Shared::reclaim(m, seen);
        assert_eq!(m.word.load(Ordering::SeqCst), me() << PEND_BITS | 30, "the new owner's, as it was");
        assert_eq!(s.outstanding(), 30);
        m.word.store(0, Ordering::SeqCst);
    }

    /// With every slot another running process's, none is had (and a room then attaches to none, `cow::Room`); one
    /// freed later is.
    #[test]
    fn with_every_slot_taken_none_is_had() {
        let dir = crate::test_util::TempDir::new("hostmem-full");
        let s = at(&dir).unwrap();
        s.occupy_all();
        assert_eq!(s.slot(), None);
        s.free(7);
        assert_eq!(s.slot(), Some(7));
    }

    /// Callers queued on the host lock do not each ask (and wait) again: once a second at most.
    #[test]
    fn release_requests_come_once_a_second_at_most() {
        let dir = crate::test_util::TempDir::new("hostmem-once");
        let s = at(&dir).unwrap();
        let g = s.release.load(Ordering::SeqCst);
        assert!(s.release_kept_once(Instant::now() + Duration::from_secs(5)));
        assert_eq!(s.release.load(Ordering::SeqCst), g.wrapping_add(1));
        assert!(!s.release_kept_once(Instant::now() + Duration::from_secs(5)), "skipped");
        assert_eq!(s.release.load(Ordering::SeqCst), g.wrapping_add(1), "nobody asked again");
        s.released.store(crate::host::boottime_ms() - RELEASE_GAP_MS, Ordering::SeqCst);
        assert!(s.release_kept_once(Instant::now() + Duration::from_secs(5)));
        assert_eq!(s.release.load(Ordering::SeqCst), g.wrapping_add(2));
    }

    /// The mapping is refused unless only this user (or root) can change it: another could change the room, or
    /// truncate it under the VMs.
    #[test]
    fn a_file_others_can_change_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_util::TempDir::new("hostmem-check");
        crate::host::private_dir(&crate::host::locks(&dir)).unwrap();
        let path = crate::host::locks(&dir).join("m");
        let len = std::mem::size_of::<Shared>() as u64;
        let refused = |why: &str| {
            let e = map(&path).map(drop).unwrap_err();
            assert!(e.to_string().contains(why), "{e}");
        };
        std::fs::File::create(&path).unwrap().set_len(len).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        refused("writable by others");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, dir.join("elsewhere")).unwrap();
        refused("linked elsewhere");
        std::fs::remove_file(dir.join("elsewhere")).unwrap();
        std::fs::File::options().write(true).open(&path).unwrap().set_len(len + 1).unwrap();
        refused("bytes, not");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(map(&path).is_err(), "a directory");
        std::fs::remove_dir(&path).unwrap();
        // Made here: fine, and so again.
        assert!(map(&path).is_ok() && map(&path).is_ok());
    }
}
