//! Parallel guest-page classification, aligned writes and pagemap construction.
use super::{
    check,
    format::{DATA, MAGIC, TEMPLATE, ZERO},
};
use crate::{
    cow::Room,
    crc32c,
    template::Template,
    uffd::{Pager, Runs, REMOTE},
    util::{Result, PAGE_SIZE},
};
use std::{
    fs::File,
    io,
    os::fd::AsRawFd,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    sync::Mutex,
};

const UNIT: usize = 256;
/// Most writer threads. A few saturate the disk: past 4-6 the copy is no faster and each
/// writer only adds lock contention in the filesystem (4 GiB guest here: 12 writers spend
/// about 7% more CPU than 6 for the same time).
const MAX_WRITERS: usize = 6;

pub(crate) trait GuestPages: Sync {
    fn region_end(&self, page: usize) -> Option<usize>;
    fn read(&self, page: usize, buf: &mut [u8]) -> Result<()>;
    /// A page someone waits on, whose unit to write next.
    fn wanted(&self) -> Option<usize> {
        None
    }
}

impl GuestPages for Pager {
    fn region_end(&self, page: usize) -> Option<usize> {
        Pager::region_end(self, page)
    }

    fn read(&self, page: usize, buf: &mut [u8]) -> Result<()> {
        self.read_guest((page * PAGE_SIZE) as u64, buf)
    }
}

pub(super) fn writer_threads() -> usize {
    crate::util::host_cpus().clamp(1, MAX_WRITERS)
}

pub(super) struct Written {
    pub(super) map: Vec<u8>,
    pub(super) data: u64,
    pub(super) zero: u64,
}

const BASE: u8 = 0;

pub(super) fn classify(template: &Template, page: usize, bytes: &[u8]) -> (u8, u32) {
    let tpl = template.has_data(page);
    if tpl && bytes == template.pages(page, 1) {
        return (BASE, 0);
    }
    match crc32c::page(bytes) {
        (_, true) if tpl => (ZERO as u8, 0),
        (_, true) => (BASE, 0),
        (sum, false) => (DATA as u8, sum),
    }
}

struct Unit {
    first: usize,
    kinds: Vec<u8>,
    sums: Vec<u32>,
    at: u64,
}

pub(super) struct PagesFile {
    pub(super) file: File,
    allocated: AtomicUsize,
}

impl PagesFile {
    pub(super) fn new(file: File) -> PagesFile {
        let _ = direct(&file, true);
        PagesFile { file, allocated: AtomicUsize::new(0) }
    }

    /// Allocates room for `pages` pages so writes run in parallel (ext4 with O_DIRECT).
    /// A unit at a time: ext4 takes each request on its own, and one larger than the free
    /// extents near its goal falls through to scanning every group for space (with a
    /// bitmap prefetch over all of them each time). On a fragmented disk that cost 1-1.6 s
    /// of CPU for 2 GiB in one call, against 0.2-0.8 s in 1 MiB requests, which find their
    /// goal or a free extent of their size straight away. On a disk with room each continues
    /// the last one's extent: 2 GiB took 15-20 ms against 6-8 ms in one call, in as few extents.
    pub(super) fn reserve(&self, pages: usize) {
        let fd = self.file.as_raw_fd();
        let mut have = self.allocated.load(Ordering::Relaxed);
        while have < pages {
            let n = UNIT.min(pages - have);
            if unsafe { libc::fallocate(fd, 0, (have * PAGE_SIZE) as libc::off_t, (n * PAGE_SIZE) as libc::off_t) } != 0 {
                break;
            }
            have += n;
            self.allocated.store(have, Ordering::Relaxed);
        }
    }

    /// Safety: `iov` is page-aligned whole pages the caller keeps alive and unchanged until return.
    fn write(&self, iov: &mut [libc::iovec], scratch: &mut Vec<libc::iovec>, off: u64) -> io::Result<()> {
        scratch.clear();
        scratch.extend_from_slice(iov);
        match pwritev_all(&self.file, scratch, off) {
            // O_DIRECT does not work here after all.
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => direct(&self.file, false).and_then(|()| pwritev_all(&self.file, iov, off)),
            r => r,
        }
    }
}

pub(super) fn direct(file: &File, on: bool) -> io::Result<()> {
    let (fd, flag) = (file.as_raw_fd(), libc::O_DIRECT);
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    check(unsafe { libc::fcntl(fd, libc::F_SETFL, if on { flags | flag } else { flags & !flag }) })
}

// Each iovec points into initialized storage the caller keeps alive and
// unchanged throughout; advancing one stays within its allocation.
fn pwritev_all(file: &File, mut iov: &mut [libc::iovec], mut off: u64) -> io::Result<()> {
    while !iov.is_empty() {
        let cnt = iov.len().min(libc::UIO_MAXIOV as usize) as libc::c_int;
        let n = crate::util::eintr(|| unsafe { libc::pwritev(file.as_raw_fd(), iov.as_ptr(), cnt, off as libc::off_t) })?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        off += n as u64;
        let mut n = n as usize;
        while let Some(first) = iov.first_mut() {
            if n < first.iov_len {
                first.iov_base = unsafe { first.iov_base.add(n) };
                first.iov_len -= n;
                break;
            }
            n -= first.iov_len;
            iov = &mut iov[1..];
        }
    }
    Ok(())
}

/// A writer's buffer: `UNIT` pages at the start of a 2 MiB-aligned mapping, backed by a
/// transparent huge page where the host allows (`madvise` mode included). Each direct write
/// then pins one folio rather than every page and goes out in fewer, larger segments: on a
/// 4 GiB guest here the copy took about 12% less CPU and 30% less time. The huge page is
/// all of the rounded-up mapping, which counts against the host's memory room as rescued
/// copies do (`cow::Room`); without that much room the buffer is ordinary pages, just `UNIT`.
pub(crate) struct Buf {
    ptr: *mut u8,
    map: usize,
    len: usize,
}

// Its mapping is its own alone (unmapped on drop): a writer thread may be handed it.
unsafe impl Send for Buf {}

#[cfg(test)]
thread_local! {
    /// Tests: the next `Buf::map` on this thread fails.
    static FAIL_MAP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Tests: the next `populate` on this thread finds the kernel cannot (as before 5.14).
    static FAIL_POPULATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

const HUGE: usize = 2 << 20;
const MADV_POPULATE_WRITE: libc::c_int = 23;

/// Faults in `len` bytes from `ptr` for writing: at once where the kernel can, else a write to each page.
fn populate(ptr: *mut u8, len: usize) {
    #[cfg(test)]
    let fail = FAIL_POPULATE.with(|f| f.replace(false));
    #[cfg(not(test))]
    let fail = false;
    if fail || unsafe { libc::madvise(ptr.cast(), len, MADV_POPULATE_WRITE) } != 0 {
        (0..len).step_by(PAGE_SIZE).for_each(|o| unsafe { ptr.add(o).write_volatile(0) });
    }
}

impl Buf {
    #[cfg(test)]
    fn new(room: &Room) -> io::Result<Buf> {
        let b = Buf::many(room, 1)?.pop().unwrap();
        b.populate();
        Ok(b)
    }

    /// Buffers for `n` writers: huge ones for as many as the room shows space for, in one take (a checkpoint's
    /// writers take the host lock once, not each: a fault may be trying for it, #677), the rest ordinary. Each
    /// writer populates its own (`populate`) as it starts, which the take's debit counts until MemAvailable shows it.
    fn many(room: &Room, n: usize) -> io::Result<Vec<Buf>> {
        let (len, huge) = (UNIT * PAGE_SIZE, (UNIT * PAGE_SIZE).next_multiple_of(HUGE));
        let mib = (huge >> 20) as u64;
        let fit = n.min(usize::try_from(room.get() / mib).unwrap_or(usize::MAX));
        let one = || -> io::Result<Buf> {
            let ptr = Buf::map(huge, len, HUGE)?;
            // Only a hint: without it the buffer is ordinary pages.
            unsafe { libc::madvise(ptr.cast(), huge, libc::MADV_HUGEPAGE) };
            Ok(Buf { ptr, map: huge, len })
        };
        let mut out = match fit {
            0 => Vec::new(),
            k => room.take(k as u64 * mib, || (0..k).map(|_| one()).collect::<io::Result<Vec<Buf>>>()).transpose()?.unwrap_or_default(),
        };
        while out.len() < n {
            out.push(Buf::plain(UNIT)?);
        }
        Ok(out)
    }

    /// Faults a huge one in at once, before its first write (#672); an ordinary one faults in as it is written.
    fn populate(&self) {
        if self.map == HUGE {
            populate(self.ptr, self.map);
        }
    }

    /// Ordinary page-aligned storage, taking no room.
    pub(crate) fn plain(pages: usize) -> io::Result<Buf> {
        let len = pages * PAGE_SIZE;
        Buf::map(len, len, 0).map(|ptr| Buf { ptr, map: len, len })
    }

    /// `map` bytes of anonymous memory, at a multiple of `align` (0: anywhere).
    fn map(map: usize, len: usize, align: usize) -> io::Result<*mut u8> {
        let full = map + align;
        #[cfg(test)]
        if FAIL_MAP.with(|f| f.replace(false)) {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "injected: cannot allocate checkpoint buffer"));
        }
        let raw = unsafe { libc::mmap(std::ptr::null_mut(), full, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, format!("cannot allocate checkpoint buffer of {len} bytes")));
        }
        let raw = raw as usize;
        let start = if align == 0 { raw } else { raw.next_multiple_of(align) };
        // The excess around the aligned start, unmapped again.
        unsafe {
            if start > raw {
                libc::munmap(raw as *mut _, start - raw);
            }
            if raw + full > start + map {
                libc::munmap((start + map) as *mut _, raw + full - start - map);
            }
        }
        Ok(start as *mut u8)
    }

    pub(crate) fn bytes(&mut self) -> &mut [u8] {
        // Mapped, initialized (zero) and ours alone.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr.cast(), self.map) };
    }
}

/// Writes the REMOTE pages of `runs` into `out` and builds the page map; with `explicit`
/// (a delta), listed template pages get TEMPLATE runs.
/// Writer buffers take `room` (see `Buf`).
pub(super) fn write_pages(
    template: &Template,
    src: &dyn GuestPages,
    runs: &Runs,
    out: &PagesFile,
    threads: usize,
    explicit: bool,
    room: &Room,
) -> Result<Written> {
    let mut units: Vec<(usize, usize)> = Vec::new();
    for &(first, count, _) in runs.iter().filter(|r| r.2 == REMOTE) {
        let (mut p, end) = (first as usize, (first + count) as usize);
        while p < end {
            let region_end = src.region_end(p).ok_or_else(|| format!("page {p} outside guest memory"))?;
            let n = UNIT.min(end - p).min(region_end - p);
            units.push((p, n));
            p += n;
        }
    }
    out.reserve(units.iter().map(|u| u.1).sum());
    let done: Vec<Mutex<Option<Unit>>> = units.iter().map(|_| Mutex::new(None)).collect();
    let taken: Vec<AtomicBool> = units.iter().map(|_| AtomicBool::new(false)).collect();
    let (next, placed, failed) = (AtomicUsize::new(0), AtomicU64::new(0), AtomicBool::new(false));
    let pick = || -> Option<usize> {
        while let Some(p) = src.wanted() {
            let k = units.partition_point(|u| u.0 <= p).checked_sub(1);
            if let Some(k) = k.filter(|&k| p < units[k].0 + units[k].1 && !taken[k].swap(true, Ordering::SeqCst)) {
                return Some(k);
            }
        }
        (0..).map(|_| next.fetch_add(1, Ordering::Relaxed)).take_while(|&k| k < units.len()).find(|&k| !taken[k].swap(true, Ordering::SeqCst))
    };
    let threads = threads.min(units.len()).max(1);
    let bufs = Mutex::new(Buf::many(room, threads)?);
    let work = || -> Result<()> {
        let mut buf = bufs.lock().unwrap().pop().map_or_else(|| Buf::plain(UNIT), Ok)?;
        buf.populate();
        let mut iov: Vec<libc::iovec> = Vec::with_capacity(UNIT);
        let mut scratch = Vec::with_capacity(UNIT);
        loop {
            if failed.load(Ordering::Relaxed) {
                return Ok(());
            }
            let Some(k) = pick() else { return Ok(()) };
            let (first, n) = units[k];
            let bytes = &mut buf.bytes()[..n * PAGE_SIZE];
            src.read(first, bytes)?;
            let mut unit = Unit { first, kinds: Vec::with_capacity(n), sums: Vec::new(), at: 0 };
            iov.clear();
            // Whole pages of this one allocation, not reused until `write` returns.
            for (i, page) in bytes.chunks(PAGE_SIZE).enumerate() {
                let (kind, sum) = classify(template, first + i, page);
                unit.kinds.push(kind);
                if kind != DATA as u8 {
                    continue;
                }
                unit.sums.push(sum);
                match iov.last_mut() {
                    Some(v) if unsafe { (v.iov_base as *const u8).add(v.iov_len) } == page.as_ptr() => v.iov_len += PAGE_SIZE,
                    _ => iov.push(libc::iovec { iov_base: page.as_ptr() as *mut _, iov_len: PAGE_SIZE }),
                }
            }
            unit.at = placed.fetch_add(unit.sums.len() as u64, Ordering::Relaxed);
            if !iov.is_empty() {
                out.write(&mut iov, &mut scratch, unit.at * PAGE_SIZE as u64)?;
            }
            *done[k].lock().unwrap() = Some(unit);
        }
    };
    let work = || work().inspect_err(|_| failed.store(true, Ordering::Relaxed));
    std::thread::scope(|s| {
        // Helpers as many as can be had (a failed spawn must not panic, which aborts with
        // the VM paused): this thread works too, so the copy goes on with fewer.
        let helpers: Vec<_> = (1..threads).map_while(|_| std::thread::Builder::new().spawn_scoped(s, work).ok()).collect();
        let here = work();
        helpers.into_iter().map(|h| h.join().unwrap()).fold(here, Result::and)
    })?;
    let data = placed.into_inner();
    let mut sums = vec![0u32; data as usize];
    let mut w = Written { map: MAGIC.to_vec(), data, zero: 0 };
    let mut map: Vec<[u64; 4]> = Vec::new();
    let mut push = |page: u64, count: u64, kind: u64, at: u64| {
        if count == 0 {
            return;
        }
        let kind = match kind {
            ZERO | DATA => kind,
            _ if explicit => TEMPLATE,
            _ => return,
        };
        w.zero += if kind == ZERO { count } else { 0 };
        match map.last_mut() {
            Some([f, n, k, a]) if *k == kind && *f + *n == page && (kind != DATA || *a + *n == at) => *n += count,
            _ => map.push([page, count, kind, at]),
        }
    };
    let mut done = done.into_iter().map(|u| u.into_inner().unwrap().unwrap()).peekable();
    for &(first, count, state) in runs {
        if state == REMOTE {
            while let Some(u) = done.next_if(|u| u.first < (first + count) as usize) {
                let mut at = u.at;
                for (i, &kind) in u.kinds.iter().enumerate() {
                    push((u.first + i) as u64, 1, kind as u64, at);
                    at += (kind as u64 == DATA) as u64;
                }
                sums[u.at as usize..u.at as usize + u.sums.len()].copy_from_slice(&u.sums);
            }
            continue;
        }
        if state != crate::uffd::ZERO {
            push(first, count, BASE as u64, 0);
            continue;
        }
        // Discarded pages read as zero, which a template hole already is.
        for p in first..first + count {
            push(p, 1, if template.has_data(p as usize) { ZERO } else { BASE as u64 }, 0);
        }
    }
    out.file.set_len(data * PAGE_SIZE as u64)?;
    let words = [map.len() as u64, data].into_iter().chain(map.into_iter().flatten());
    w.map.extend(words.flat_map(u64::to_le_bytes));
    w.map.extend(sums.iter().flat_map(|s| s.to_le_bytes()));
    Ok(w)
}

#[cfg(test)]
mod buf_tests {
    use super::*;

    #[test]
    fn writer_buffers_are_huge_only_with_room_for_the_whole_huge_page() {
        for (have, huge, left) in [(0, false, 0), (1, false, 1), (5, true, 3)] {
            let room = Room::default();
            room.set(have);
            let b = Buf::new(&room).unwrap();
            assert_eq!((b.map == HUGE, room.get()), (huge, left), "room {have} MiB");
            // A huge one is all of an aligned 2 MiB; an ordinary one only what it holds,
            // which no huge page fits in.
            if !huge {
                assert_eq!(b.map, UNIT * PAGE_SIZE);
            }
            assert_eq!(b.ptr as usize % if huge { HUGE } else { PAGE_SIZE }, 0);
            let mut b = b;
            let bytes = b.bytes();
            assert_eq!(bytes.len(), UNIT * PAGE_SIZE);
            assert!(bytes.iter().all(|&x| x == 0));
            bytes.fill(7);
            if !huge {
                assert_eq!(anon_huge_kib(b.ptr as usize), 0, "an ordinary buffer took a huge page");
            }
        }
        // No bound: huge.
        assert_eq!(Buf::new(&Room::default()).unwrap().map, HUGE);
    }

    /// A checkpoint's writers take their huge buffers in one take, as many as the room shows space for (#677).
    #[test]
    fn writer_buffers_are_taken_together() {
        let room = Room::default();
        room.set(5);
        let bufs = Buf::many(&room, 4).unwrap();
        assert_eq!(bufs.iter().map(|b| b.map == HUGE).collect::<Vec<_>>(), [true, true, false, false]);
        assert_eq!(room.get(), 1);
        assert_eq!(Buf::many(&room, 3).unwrap().iter().filter(|b| b.map == HUGE).count(), 0, "no room left");
    }

    #[test]
    fn a_failed_buffer_map_fails_the_buffer() {
        let room = Room::default();
        room.set(5);
        FAIL_MAP.with(|f| f.set(true));
        assert!(Buf::new(&room).is_err());
        // And the next one maps (huge) as usual.
        assert_eq!(Buf::new(&room).unwrap().map, HUGE);
    }

    /// A writer buffer is populated before its first write, also where the kernel cannot populate it at once (#674):
    /// every page is in.
    #[test]
    fn a_writer_buffer_is_populated_before_its_first_write() {
        let room = Room::default();
        FAIL_POPULATE.with(|f| f.set(true));
        let b = Buf::new(&room).unwrap();
        assert!(b.map == HUGE && !FAIL_POPULATE.with(|f| f.get()), "huge, and the populate failed");
        let mut vec = vec![0u8; b.map / PAGE_SIZE];
        assert_eq!(unsafe { libc::mincore(b.ptr.cast(), b.map, vec.as_mut_ptr()) }, 0);
        assert!(vec.iter().all(|&v| v & 1 == 1), "every page in");
    }

    /// AnonHugePages of the mapping starting at `addr`, from /proc/self/smaps.
    fn anon_huge_kib(addr: usize) -> u64 {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        // The mapping holding `addr`: another test's plain buffer mapped next to it may have merged with it.
        let range = |l: &str| -> Option<(usize, usize)> {
            let (s, e) = l.split(' ').next()?.split_once('-')?;
            Some((usize::from_str_radix(s, 16).ok()?, usize::from_str_radix(e, 16).ok()?))
        };
        let holds = |l: &str| range(l).is_some_and(|(s, e)| (s..e).contains(&addr));
        let mut lines = smaps.lines().skip_while(|l| !holds(l)).skip(1);
        let line = lines.find(|l| l.starts_with("AnonHugePages:")).expect("mapping in smaps");
        line.split_whitespace().nth(1).unwrap().parse().unwrap()
    }
}
