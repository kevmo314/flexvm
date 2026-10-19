//! Guest memory that was mapped in Firecracker before its userfaultfd covered it (#949).
//!
//! Firecracker maps guest memory and only then registers it with the userfaultfd it hands the pager. A process that
//! reads Firecracker's memory in between (`/proc/PID/mem`, `process_vm_readv`: a debugger, a memory scanner; GitHub's
//! runners have an agent that does) faults pages in as for any anonymous memory: the zero page, or, with THP enabled,
//! the huge zero page for a whole 2 MiB chunk. Registering the range later leaves them mapped, so the guest never
//! faults on them and the pager never installs them: the guest reads zeroes where the template has data. Firecracker's
//! own write of its vmclock page then copies the huge zero page into a zeroed huge page, and with it the guest's DSDT
//! (in the same first 2 MiB) is gone: the VMGenID notification never runs and the guest never reseeds its RNG.
//!
//! Such pages are mapped while the pager has them BASE or REMOTE (it installs every other page itself, through the
//! userfaultfd), or turn up as EEXIST when it installs them (`Pages::preset`). `Pager::foreign_pages` looks for both
//! once a load is done and before the guest first runs, so the load can be retried on a fresh Firecracker.

use super::{Pager, BASE, INFLIGHT, PAGE_SIZE, REMOTE};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// `PAGEMAP_SCAN` (`_IOWR('f', 16, struct pm_scan_arg)`, Linux 6.7) and its page categories.
const PAGEMAP_SCAN: libc::c_ulong = 0xC060_6610;
const PAGE_IS_PRESENT: u64 = 1 << 3;
const PAGE_IS_SWAPPED: u64 = 1 << 4;
/// Pagemap entry bits: present, swapped out.
const PM_PRESENT: u64 = 1 << 63;
const PM_SWAP: u64 = 1 << 62;
/// Regions per `PAGEMAP_SCAN` call, and pages per pagemap read where it is missing.
const SCAN_REGIONS: usize = 512;
const READ_PAGES: usize = 64 << 10;
/// How long `foreign_pages` waits for claimed pages it finds mapped to settle.
const INFLIGHT_WAIT: Duration = Duration::from_secs(2);

#[repr(C)]
#[derive(Default)]
struct PmScanArg {
    size: u64,
    flags: u64,
    start: u64,
    end: u64,
    walk_end: u64,
    vec: u64,
    vec_len: u64,
    max_pages: u64,
    category_inverted: u64,
    category_mask: u64,
    category_anyof_mask: u64,
    return_mask: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PageRegion {
    start: u64,
    end: u64,
    categories: u64,
}

/// The pages in `[start, start + len)` (host addresses, page aligned) that `pagemap` (some process's
/// `/proc/PID/pagemap`) has mapped or swapped out, as `[first, end)` page offsets from `start`.
pub(super) fn mapped_runs(pagemap: &std::fs::File, start: u64, len: u64) -> io::Result<Vec<(usize, usize)>> {
    match scan_runs(pagemap, start, len) {
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTTY | libc::EINVAL | libc::EOPNOTSUPP)) => read_runs(pagemap, start, len),
        r => r,
    }
}

fn scan_runs(pagemap: &std::fs::File, start: u64, len: u64) -> io::Result<Vec<(usize, usize)>> {
    let (end, mut at, mut runs) = (start + len, start, Vec::new());
    let mut regions = [PageRegion::default(); SCAN_REGIONS];
    while at < end {
        let mut arg = PmScanArg {
            size: std::mem::size_of::<PmScanArg>() as u64,
            start: at,
            end,
            vec: regions.as_mut_ptr() as u64,
            vec_len: SCAN_REGIONS as u64,
            category_anyof_mask: PAGE_IS_PRESENT | PAGE_IS_SWAPPED,
            return_mask: PAGE_IS_PRESENT | PAGE_IS_SWAPPED,
            ..PmScanArg::default()
        };
        // The struct and the regions array outlive the call; the kernel writes only `walk_end` and the regions.
        let n = unsafe { libc::ioctl(pagemap.as_raw_fd(), PAGEMAP_SCAN, &mut arg as *mut PmScanArg) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        for r in &regions[..n as usize] {
            push_run(&mut runs, ((r.start - start) / PAGE_SIZE as u64) as usize, ((r.end - start) / PAGE_SIZE as u64) as usize);
        }
        if arg.walk_end <= at {
            break;
        }
        at = arg.walk_end;
    }
    Ok(runs)
}

/// `scan_runs` for kernels before 6.7: the pagemap entries themselves.
fn read_runs(pagemap: &std::fs::File, start: u64, len: u64) -> io::Result<Vec<(usize, usize)>> {
    let pages = (len / PAGE_SIZE as u64) as usize;
    let (mut runs, mut raw) = (Vec::new(), vec![0u8; READ_PAGES.min(pages) * 8]);
    let mut first = 0;
    while first < pages {
        let n = READ_PAGES.min(pages - first);
        std::os::unix::fs::FileExt::read_exact_at(pagemap, &mut raw[..n * 8], (start / PAGE_SIZE as u64 + first as u64) * 8)?;
        for (i, e) in raw[..n * 8].chunks(8).enumerate() {
            if u64::from_le_bytes(e.try_into().unwrap()) & (PM_PRESENT | PM_SWAP) != 0 {
                push_run(&mut runs, first + i, first + i + 1);
            }
        }
        first += n;
    }
    Ok(runs)
}

fn push_run(runs: &mut Vec<(usize, usize)>, a: usize, b: usize) {
    match runs.last_mut() {
        Some(last) if last.1 == a => last.1 = b,
        _ => runs.push((a, b)),
    }
}

/// Whether a page in `state` that Firecracker has mapped holds what the guest should not see: the pager installs
/// every page it moves out of BASE or REMOTE, so mapped in either means mapped behind its back. A template hole
/// (BASE, no data) is zero either way. ZERO is not checked: a REMOVE already applied may not have zapped it yet.
fn foreign(state: u8, has_data: bool) -> bool {
    state == REMOTE || state == BASE && has_data
}

impl Pager {
    /// How many guest pages Firecracker has mapped that the pager never installed and that should hold template or
    /// migrated data (see the module docs). For a load that is done, before the guest first runs.
    pub fn foreign_pages(&self) -> io::Result<(usize, Option<usize>)> {
        let pagemap = self.pagemap_file()?;
        let pages = self.pages();
        let (mut found, mut first_found) = (0, None);
        let mut note = |p: usize| {
            found += 1;
            first_found = first_found.or(Some(p));
        };
        // Mapped while claimed: by the claimant's own copy (it settles at once), or before the claim (its copy
        // gets EEXIST, noted in `preset`). Either way, known once it settles.
        let mut inflight = Vec::new();
        for m in self.mappings() {
            let first = m.span().0;
            for (a, b) in mapped_runs(pagemap, m.base_host_virt_addr, m.size as u64)? {
                for p in (first + a..first + b).filter(|&p| p < pages.len()) {
                    match pages.get(p) {
                        INFLIGHT => inflight.push(p),
                        s if foreign(s, self.base.has_data(p)) => note(p),
                        _ => {}
                    }
                }
            }
        }
        let deadline = Instant::now() + INFLIGHT_WAIT;
        while !inflight.is_empty() && Instant::now() < deadline {
            inflight.retain(|&p| pages.get(p) == INFLIGHT);
            std::thread::sleep(Duration::from_millis(1));
        }
        // Still claimed: no copy of ours mapped it, as a copy settles right after.
        inflight.iter().filter(|&&p| pages.get(p) == INFLIGHT).for_each(|&p| note(p));
        // Settled PRESENT since, by an install that hit EEXIST.
        pages.preset.lock().unwrap().iter().filter(|&&(p, from)| foreign(from, self.base.has_data(p))).for_each(|&(p, _)| note(p));
        Ok((found + pages.preset_more.load(Ordering::Relaxed), first_found))
    }

    /// `foreign_pages` as a load's check: an error, which retrying on a fresh Firecracker gets past, if there are any.
    pub fn check_foreign(&self) -> crate::util::Result<()> {
        match self.foreign_pages() {
            Ok((0, _)) => Ok(()),
            Ok((n, first)) => Err(format!(
                "{FOREIGN}: {n} pages ({} KiB, from guest memory offset {:#x}) were mapped before its userfaultfd covered them",
                n * PAGE_SIZE / 1024,
                first.unwrap_or(0) * PAGE_SIZE
            )
            .into()),
            Err(e) => Err(format!("checking firecracker's guest memory: {e}").into()),
        }
    }
}

/// How `check_foreign`'s error starts.
pub const FOREIGN: &str = "another process read firecracker's guest memory while it was being mapped";

#[cfg(test)]
mod tests {
    use super::*;

    /// An anonymous mapping of `pages`, of which those in `touch` are read (mapping the zero page) or written.
    fn mapping(pages: usize, read: &[usize], write: &[usize]) -> (*mut u8, usize) {
        let len = pages * PAGE_SIZE;
        let p = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
        assert_ne!(p, libc::MAP_FAILED);
        // 4 KiB pages only: one huge page would map all of them.
        unsafe { libc::madvise(p, len, libc::MADV_NOHUGEPAGE) };
        let p = p as *mut u8;
        for &i in read {
            unsafe { std::ptr::read_volatile(p.add(i * PAGE_SIZE)) };
        }
        for &i in write {
            unsafe { std::ptr::write_volatile(p.add(i * PAGE_SIZE + 7), 1) };
        }
        (p, len)
    }

    #[test]
    fn mapped_runs_see_zero_pages_and_written_ones() {
        let (p, len) = mapping(64, &[3, 4, 5, 40], &[10, 11, 63]);
        let pagemap = std::fs::File::open("/proc/self/pagemap").unwrap();
        let want = vec![(3, 6), (10, 12), (40, 41), (63, 64)];
        assert_eq!(mapped_runs(&pagemap, p as u64, len as u64).unwrap(), want);
        // The pagemap reads give the same answer as PAGEMAP_SCAN (or are what answered).
        assert_eq!(read_runs(&pagemap, p as u64, len as u64).unwrap(), want);
        // A range from the middle reports offsets from its own start.
        assert_eq!(mapped_runs(&pagemap, p as u64 + 4 * PAGE_SIZE as u64, 8 * PAGE_SIZE as u64).unwrap(), vec![(0, 2), (6, 8)]);
        unsafe { libc::munmap(p.cast(), len) };
    }

    #[test]
    fn mapped_runs_of_many_regions_go_on_past_a_full_vector() {
        // Every other page: more regions than one PAGEMAP_SCAN call returns.
        let n = 3 * SCAN_REGIONS;
        let read: Vec<usize> = (0..n).step_by(2).collect();
        let (p, len) = mapping(n, &read, &[]);
        let pagemap = std::fs::File::open("/proc/self/pagemap").unwrap();
        let runs = mapped_runs(&pagemap, p as u64, len as u64).unwrap();
        assert_eq!(runs, read.iter().map(|&i| (i, i + 1)).collect::<Vec<_>>());
        unsafe { libc::munmap(p.cast(), len) };
    }

    #[test]
    fn only_data_the_pager_never_installed_is_foreign() {
        use super::super::{DISCARDED, INFLIGHT, PRESENT, ZERO};
        assert!(foreign(BASE, true));
        assert!(foreign(REMOTE, false));
        assert!(foreign(REMOTE, true));
        // A template hole is zero anyway; the pager's own pages, and ZERO, are not looked at.
        assert!(!foreign(BASE, false));
        for s in [PRESENT, ZERO, INFLIGHT, DISCARDED] {
            assert!(!foreign(s, true));
        }
    }

    #[test]
    fn installs_that_find_a_page_mapped_note_it() {
        use super::super::{Pages, ZERO};
        let pages = Pages::new(8);
        let eexist = || Err(io::Error::from_raw_os_error(libc::EEXIST));
        assert_eq!(pages.claim(0, 2, BASE, |_| true), 2);
        let _ = pages.install(0, 2, BASE, None, |p, _| if p == 1 { eexist() } else { Ok(1) });
        let mut pages = pages;
        pages.fill(4, 2, REMOTE);
        pages.fill(6, 1, ZERO);
        assert_eq!(pages.claim(4, 2, REMOTE, |_| true), 2);
        let _ = pages.install(4, 2, REMOTE, None, |_, _| eexist());
        // A zero-fill that finds the page mapped is the zap race `Pages` describes, not a foreign page.
        assert_eq!(pages.claim(6, 1, ZERO, |_| true), 1);
        let _ = pages.install(6, 1, ZERO, None, |_, _| eexist());
        assert_eq!(*pages.preset.lock().unwrap(), vec![(1, BASE), (4, REMOTE), (5, REMOTE)]);
        // A template hole found mapped is zero either way: not noted, nor counted past the kept ones.
        let _ = pages.base_data.set(Box::new(|p| p != 2));
        pages.fill(2, 2, BASE);
        assert_eq!(pages.claim(2, 2, BASE, |_| true), 2);
        let _ = pages.install(2, 2, BASE, None, |_, _| eexist());
        assert_eq!(*pages.preset.lock().unwrap(), vec![(1, BASE), (4, REMOTE), (5, REMOTE), (3, BASE)]);
        assert_eq!(pages.preset_more.load(Ordering::Relaxed), 0);
    }
}
