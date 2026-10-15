//! Parallel guest-page classification, aligned writes and pagemap construction.
use super::{
    check,
    format::{DATA, MAGIC, TEMPLATE, ZERO},
};
use crate::{
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
/// Most writer threads; a few saturate the disk.
const MAX_WRITERS: usize = 12;

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
    let n = std::env::var("FLEXVM_CKPT_THREADS").ok().and_then(|v| v.parse().ok());
    n.unwrap_or_else(crate::util::host_cpus).clamp(1, MAX_WRITERS)
}

pub(super) struct Written {
    pub(super) map: Vec<u8>,
    pub(super) data: u64,
    pub(super) zero: u64,
    pub(super) sums: Vec<u32>,
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
    pub(super) fn reserve(&self, pages: usize) {
        let have = self.allocated.load(Ordering::Relaxed);
        let (off, len) = ((have * PAGE_SIZE) as libc::off_t, (pages.saturating_sub(have) * PAGE_SIZE) as libc::off_t);
        if pages > have && unsafe { libc::fallocate(self.file.as_raw_fd(), 0, off, len) } == 0 {
            self.allocated.store(pages, Ordering::Relaxed);
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

fn direct(file: &File, on: bool) -> io::Result<()> {
    let (fd, flag) = (file.as_raw_fd(), libc::O_DIRECT);
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    check(unsafe { libc::fcntl(fd, libc::F_SETFL, if on { flags | flag } else { flags & !flag }) })
}

// Each iovec points into initialized storage the caller keeps alive and
// unchanged throughout; advancing one stays within its allocation.
fn pwritev_all(file: &File, mut iov: &mut [libc::iovec], mut off: u64) -> io::Result<()> {
    while !iov.is_empty() {
        let cnt = iov.len().min(libc::UIO_MAXIOV as usize) as libc::c_int;
        let n = unsafe { libc::pwritev(file.as_raw_fd(), iov.as_ptr(), cnt, off as libc::off_t) };
        let e = (n <= 0).then(|| if n < 0 { io::Error::last_os_error() } else { io::ErrorKind::WriteZero.into() });
        match e {
            Some(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Some(e) => return Err(e),
            None => {}
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

/// One page, aligned for O_DIRECT.
#[derive(Clone)]
#[repr(C, align(4096))]
pub(super) struct Page([u8; PAGE_SIZE]);

pub(super) fn aligned(n: usize) -> io::Result<Vec<Page>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "cannot allocate checkpoint buffer"))?;
    v.resize(n, Page([0; PAGE_SIZE]));
    Ok(v)
}

pub(super) fn as_bytes(pages: &mut [Page]) -> &mut [u8] {
    // `Page` is PAGE_SIZE initialized bytes with no padding.
    unsafe { std::slice::from_raw_parts_mut(pages.as_mut_ptr().cast(), std::mem::size_of_val(pages)) }
}

/// Writes the REMOTE pages of `runs` into `out` and builds the page map; with `explicit`
/// (a delta), listed template pages get TEMPLATE runs.
pub(super) fn write_pages(template: &Template, src: &dyn GuestPages, runs: &Runs, out: &PagesFile, threads: usize, explicit: bool) -> Result<Written> {
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
    let work = || -> Result<()> {
        let mut buf = aligned(UNIT)?;
        let mut iov: Vec<libc::iovec> = Vec::with_capacity(UNIT);
        let mut scratch = Vec::with_capacity(UNIT);
        loop {
            if failed.load(Ordering::Relaxed) {
                return Ok(());
            }
            let Some(k) = pick() else { return Ok(()) };
            let (first, n) = units[k];
            let bytes = &mut as_bytes(&mut buf)[..n * PAGE_SIZE];
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
    let threads = threads.min(units.len()).max(1);
    std::thread::scope(|s| {
        // A failed spawn must not panic (that aborts with the VM paused): stop the rest and report it.
        let mut spawned: Result<()> = Ok(());
        let handles: Vec<_> = (0..threads)
            .map_while(|_| {
                let h = std::thread::Builder::new().spawn_scoped(s, || work().inspect_err(|_| failed.store(true, Ordering::Relaxed)));
                h.map_err(|e| (failed.store(true, Ordering::Relaxed), spawned = Err(e.into()))).ok()
            })
            .collect();
        let joined = handles.into_iter().try_for_each(|h| h.join().unwrap());
        spawned.and(joined)
    })?;
    let data = placed.into_inner();
    let mut w = Written { map: MAGIC.to_vec(), data, zero: 0, sums: vec![0; data as usize] };
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
                w.sums[u.at as usize..u.at as usize + u.sums.len()].copy_from_slice(&u.sums);
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
    w.map.extend(w.sums.iter().flat_map(|s| s.to_le_bytes()));
    Ok(w)
}
