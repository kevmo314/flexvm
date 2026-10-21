//! Budgeted chain opening, overlay flattening and checked page reads.
use super::{
    bail,
    format::{parse_manifest, parse_pagemap, sum, Canon, Manifest, Run, DATA, FORMAT, FORMAT_INCREMENTAL, MAX_VMSTATE, TEMPLATE},
    fstat, open_at, open_dir_at,
    write::{direct, Buf},
};
use crate::{
    crc32c,
    template::Template,
    uffd::{Runs, REMOTE},
    util::{Result, PAGE_SIZE},
};
use std::{
    ffi::CString,
    fs::File,
    io::{self, Read},
    os::fd::{AsRawFd, RawFd},
    os::unix::ffi::OsStrExt,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub const MAX_CHAIN: usize = 64;
const MAX_CHAIN_META: u64 = 256 << 20;

/// Most metadata (manifests, VM states, page maps) opening a chain may read:
/// it scales with the host, never with what a (possibly forged) manifest
/// claims. A page map costs at most 36 bytes per guest page, under 1% of it.
pub fn chain_meta_budget() -> u64 {
    MAX_CHAIN_META.max(crate::util::proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0) / 16)
}

pub struct Checkpoint {
    pub dir: PathBuf,
    pub manifest: Manifest,
    /// The manifest's checksum, by which a child names its parent.
    pub id: String,
    /// The verified VM state: load these bytes, not the file, which may have changed.
    pub vmstate: Vec<u8>,
    /// Initial page states for the pager: DATA pages are REMOTE, read from `file`.
    pub runs: Runs,
    pub file: Arc<PageFile>,
    /// Its ancestors, nearest first.
    pub chain: Vec<PathBuf>,
    pub chain_ids: Vec<String>,
    pub meta_left: u64,
}

pub(super) fn read_at(dir: RawFd, name: &str, max: u64) -> io::Result<(File, Vec<u8>)> {
    let f = open_at(dir, name)?;
    let st = fstat(f.as_raw_fd())?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    io::Read::take(&f, max).read_to_end(&mut bytes)?;
    Ok((f, bytes))
}

pub(super) struct Link {
    pub(super) dir: PathBuf,
    pub(super) manifest: Manifest,
    pub(super) id: String,
    vmstate: Vec<u8>,
    map: Vec<Run>,
    file: Option<File>,
    sums: Vec<u32>,
}

/// Read only the bounded, checksummed manifest, without opening its ancestors or page data.
pub fn read_manifest(dir: &Path) -> Result<Manifest> {
    Ok(Link::open(dir, 0, None)?.manifest)
}

/// `read_manifest`, with the manifest's id (its checksum, which names a store entry).
pub(super) fn read_manifest_id(dir: &Path) -> Result<(String, Manifest)> {
    let link = Link::open(dir, 0, None)?;
    Ok((link.id, link.manifest))
}

impl Link {
    /// With `meta_left`, also reads and checks the rest within that budget (debited) and opens `pages`.
    pub(super) fn open(dir: &Path, ck: usize, meta_left: Option<&mut u64>) -> Result<Link> {
        let dir = dir.canonicalize().map_err(|e| format!("checkpoint {}: {e}", dir.display()))?;
        let bad = |why: String| format!("checkpoint {} is invalid: {why}", dir.display());
        let dfd = open_dir_at(libc::AT_FDCWD, &CString::new(dir.as_os_str().as_bytes())?).map_err(|e| bad(e.to_string()))?;
        let (_, text) = read_at(dfd.as_raw_fd(), "manifest.json", 1 << 20).map_err(|e| bad(format!("manifest.json: {e}")))?;
        let (id, manifest) = parse_manifest(&text).map_err(|e| bad(e.to_string()))?;
        match (manifest.format, &manifest.parent) {
            (FORMAT, None) | (FORMAT_INCREMENTAL, Some(_)) => {}
            (f, _) => bail!("{}", bad(format!("format {f}; this flexvm reads formats {FORMAT} and {FORMAT_INCREMENTAL}"))),
        }
        let Some(meta_left) = meta_left else {
            return Ok(Link { dir, manifest, id, vmstate: Vec::new(), map: Vec::new(), file: None, sums: Vec::new() });
        };
        // Bound what we read: a page map has at most a run (32 bytes) and a checksum (4) per page.
        let len = |name: &str| manifest.files.get(name).map_or(0, |f| f.len);
        let map_max = manifest.guest_pages.checked_mul(36).and_then(|n| n.checked_add(24));
        ensure!(len("vmstate") <= MAX_VMSTATE && map_max.is_some_and(|m| len("pagemap") <= m), "{}", bad("vmstate or pagemap is too long".into()));
        let cost = (text.len() as u64 + len("vmstate")).saturating_add(len("pagemap"));
        *meta_left = meta_left.checked_sub(cost).ok_or_else(|| bad(format!("its chain has more than {} bytes of metadata", chain_meta_budget())))?;
        let read_checked = |name: &str| -> Result<Vec<u8>> {
            let want = manifest.files.get(name).ok_or_else(|| bad(format!("manifest lists no {name}")))?;
            let (_, bytes) = read_at(dfd.as_raw_fd(), name, want.len + 1).map_err(|e| bad(format!("{name}: {e}")))?;
            ensure!(bytes.len() as u64 == want.len && sum(&bytes) == want.hash, "{}", bad(format!("{name} does not match its checksum")));
            Ok(bytes)
        };
        // Ancestors supply memory pages only: their manifests authenticate the pagemap
        // and its page checksums. Only the head supplies VM state to restore.
        let vmstate = if ck == 0 { read_checked("vmstate")? } else { Vec::new() };
        let (map, sums) = parse_pagemap(&read_checked("pagemap")?, manifest.guest_pages, manifest.parent.is_some(), ck).map_err(|e| bad(e.to_string()))?;
        let data: u64 = map.iter().filter(|r| r.2 == DATA).map(|r| r.1).sum();
        ensure!(
            data == manifest.data_pages && manifest.files.get("pages").map(|f| f.len) == Some(data * PAGE_SIZE as u64),
            "{}",
            bad("page counts do not add up".into())
        );
        let (file, _) = read_at(dfd.as_raw_fd(), "pages", 0).map_err(|e| bad(format!("pages: {e}")))?;
        ensure!(file.metadata()?.len() == data * PAGE_SIZE as u64, "{}", bad("pages has the wrong length".into()));
        // This descriptor is dedicated to page data; metadata reads use separate files.
        // Some filesystems reject O_DIRECT here (reads stay buffered); others reject it on the first read.
        let _ = direct(&file, true);
        Ok(Link { dir, manifest, id, vmstate, map, file: Some(file), sums })
    }
}

/// The chain ending at `dir`, nearest first; `full` verifies all metadata within
/// `chain_meta_budget` (returning what is left), except unused ancestor VM states;
/// else only manifests.
pub(super) fn open_chain(dir: &Path, full: bool) -> Result<(Vec<Link>, u64)> {
    let mut meta_left = chain_meta_budget();
    let mut links = vec![Link::open(dir, 0, full.then_some(&mut meta_left))?];
    while let Some(parent) = links.last().unwrap().manifest.parent.clone() {
        let child = links.last().unwrap();
        ensure!(links.len() < MAX_CHAIN, "checkpoint {} is more than {MAX_CHAIN} deltas deep", dir.display());
        let link = Link::open(&child.dir.join(&parent.path), links.len(), full.then_some(&mut meta_left))
            .map_err(|e| format!("parent of {}: {e}", child.dir.display()))?;
        ensure!(
            link.id == parent.id,
            "checkpoint {}: its parent {} has changed (id {} is not {})",
            child.dir.display(),
            link.dir.display(),
            link.id,
            parent.id
        );
        ensure!(
            child.manifest.template_id == link.manifest.template_id && child.manifest.guest_pages == link.manifest.guest_pages,
            "checkpoint {}: its parent {} is of another template or size",
            child.dir.display(),
            link.dir.display()
        );
        links.push(link);
    }
    Ok((links, meta_left))
}

pub fn chain_ids(dir: &Path) -> Result<Vec<String>> {
    Ok(open_chain(dir, false)?.0.into_iter().map(|l| l.id).collect())
}

pub fn parent_path(child: &Path, parent: &Path) -> PathBuf {
    match (child.parent(), parent.parent(), parent.file_name()) {
        (Some(a), Some(b), Some(name)) if a == b => Path::new("..").join(name),
        _ => parent.to_path_buf(),
    }
}

impl Checkpoint {
    /// Opens the chain ending at `dir`, verifying restore metadata; page data is checked as read.
    pub fn open(dir: &Path) -> Result<Checkpoint> {
        let (mut links, meta_left) = open_chain(dir, true)?;
        let layers: Vec<Vec<Run>> = links.iter_mut().rev().map(|l| std::mem::take(&mut l.map)).collect();
        let (files, sums) = links.iter_mut().map(|l| (l.file.take().unwrap(), std::mem::take(&mut l.sums))).unzip();
        let mut links = links.into_iter();
        let Link { dir, manifest, id, vmstate, .. } = links.next().unwrap();
        let (chain, chain_ids) = links.map(|l| (l.dir, l.id)).unzip();
        let (runs, file) = flatten(&layers, files, sums);
        Ok(Checkpoint { dir, manifest, id, vmstate, runs, file: Arc::new(file), chain, chain_ids, meta_left })
    }

    fn each_page(&self, drop_cache: bool, mut f: impl FnMut(usize, &[u8])) -> Result<()> {
        let mut storage = Buf::plain(256)?;
        let buf = storage.bytes();
        for &(first, count, state) in &self.runs {
            for p in (first as usize..(first + count) as usize).step_by(256) {
                let n = ((first + count) as usize - p).min(256);
                if state != REMOTE {
                    (p..p + n).for_each(|p| f(p, &[]));
                    continue;
                }
                let b = &mut buf[..n * PAGE_SIZE];
                self.file.read(p, b, drop_cache)?;
                b.chunks(PAGE_SIZE).enumerate().for_each(|(i, page)| f(p + i, page));
            }
        }
        Ok(())
    }

    pub fn verify_data(&self) -> Result<()> {
        self.each_page(true, |_, _| {})
    }

    pub fn data_pages(&self) -> u64 {
        self.file.runs.iter().map(|r| r.1).sum()
    }

    /// DATA is pulled in full; prefetch only allocates working-set pages left BASE.
    pub fn restore_mib(&self, working_set: &[(u64, u64)]) -> u64 {
        (restore_pages(self.data_pages(), &self.runs, working_set) * PAGE_SIZE as u64) >> 20
    }

    pub fn content_hash(&self, template: &Template) -> Result<String> {
        let mut canon = Canon::new(template);
        self.each_page(false, |p, b| canon.page(p, b))?;
        Ok(canon.finish())
    }
}

fn restore_pages(data: u64, runs: &Runs, working_set: &[(u64, u64)]) -> u64 {
    let mut sorted = working_set.to_vec();
    sorted.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (first, count) in sorted {
        let end = first + count;
        match merged.last_mut() {
            Some((_, last)) if first <= *last => *last = (*last).max(end),
            _ => merged.push((first, end)),
        }
    }
    let mut pages = data;
    let mut at = 0;
    for (first, end) in merged {
        pages += end - first;
        while at < runs.len() && runs[at].0 + runs[at].1 <= first {
            at += 1;
        }
        for &(f, n, kind) in runs[at..].iter().take_while(|r| r.0 < end) {
            if kind != crate::uffd::BASE {
                pages -= end.min(f + n) - first.max(f);
            }
        }
    }
    pages
}

pub(super) fn overlay(base: &[Run], top: &[Run]) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::with_capacity(base.len() + top.len());
    for &(first, count, kind, ck, at) in base {
        let end = first + count;
        let mut pos = first;
        let mut t = top.partition_point(|r| r.0 + r.1 <= first);
        while pos < end {
            let next = top.get(t).filter(|r| r.0 < end);
            let gap_end = next.map_or(end, |r| r.0.max(pos));
            if gap_end > pos {
                let skip = pos - first;
                out.push((pos, gap_end - pos, kind, ck, if kind == DATA { at + skip } else { 0 }));
            }
            pos = next.map_or(end, |r| (r.0 + r.1).max(pos));
            t += 1;
        }
    }
    out.extend_from_slice(top);
    out.sort_unstable_by_key(|r| r.0);
    out
}

pub(super) fn flatten(layers: &[Vec<Run>], files: Vec<File>, sums: Vec<Vec<u32>>) -> (Runs, PageFile) {
    let mut runs: Vec<Run> = Vec::new();
    for layer in layers {
        runs = overlay(&runs, layer);
    }
    let mut states: Runs = Vec::new();
    let mut data = Vec::new();
    for (first, count, kind, ck, at) in runs.into_iter().filter(|r| r.2 != TEMPLATE) {
        if kind == DATA {
            data.push((first, count, ck, at));
        }
        states.push((first, count, if kind == DATA { REMOTE } else { crate::uffd::ZERO }));
    }
    let files = files
        .into_iter()
        .map(|f| {
            let cached = AtomicBool::new(buffered(&f));
            (f, cached)
        })
        .collect();
    (states, PageFile { files, runs: data, sums })
}

pub struct PageFile {
    /// Dedicated page descriptors and whether they use the page cache; only EINVAL fallback changes the mode.
    files: Vec<(File, AtomicBool)>,
    /// DATA runs: (first guest page, pages, file, index of the first in it).
    runs: Vec<(u64, u64, usize, u64)>,
    sums: Vec<Vec<u32>>,
}

fn corrupt(why: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("checkpoint page file: {why}"))
}

impl PageFile {
    /// Reads whole pages into a page-aligned buffer, evicting them after with `drop_cache` where reads are buffered.
    /// Errors are InvalidData, which the pager treats as fatal.
    pub fn read(&self, page: usize, buf: &mut [u8], drop_cache: bool) -> io::Result<()> {
        let n = buf.len() / PAGE_SIZE;
        let mut done = 0;
        while done < n {
            let p = (page + done) as u64;
            let r = self.runs.partition_point(|r| r.0 <= p);
            let (first, count, f, d) = match r.checked_sub(1).map(|r| self.runs[r]) {
                Some(run) if p < run.0 + run.1 => run,
                _ => return Err(corrupt(format!("page {p} is not stored"))),
            };
            let (k, d) = (((first + count - p) as usize).min(n - done), d + p - first);
            let (file, cached) = &self.files[f];
            let (out, off) = (&mut buf[done * PAGE_SIZE..(done + k) * PAGE_SIZE], d * PAGE_SIZE as u64);
            read_with_fallback(file, cached, || file.read_exact_at(out, off)).map_err(|e| corrupt(format!("read at {off}: {e}")))?;
            if drop_cache && cached.load(Ordering::Relaxed) {
                unsafe { libc::posix_fadvise(file.as_raw_fd(), off as i64, out.len() as i64, libc::POSIX_FADV_DONTNEED) };
            }
            for (i, page) in out.chunks(PAGE_SIZE).enumerate() {
                let d = d as usize + i;
                if crc32c::page(page).0 != self.sums[f][d] {
                    return Err(corrupt(format!("data page {d} does not match its checksum")));
                }
            }
            done += k;
        }
        Ok(())
    }

    /// Whether any file is read through the page cache (its filesystem refused O_DIRECT).
    pub fn buffered(&self) -> bool {
        self.files.iter().any(|(_, cached)| cached.load(Ordering::Relaxed))
    }

    /// Evicts the files read through the page cache.
    pub fn drop_cache(&self) {
        for (f, _) in self.files.iter().filter(|(_, cached)| cached.load(Ordering::Relaxed)) {
            unsafe { libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        }
    }
}

fn buffered(file: &File) -> bool {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    flags & libc::O_DIRECT == 0
}

/// EINVAL can be reported on I/O even if enabling O_DIRECT succeeded (e.g. tmpfs).
/// Disabling it on the shared descriptor also makes subsequent readers use the fallback.
pub(super) fn read_with_fallback(file: &File, cached: &AtomicBool, mut read: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    match read() {
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
            direct(file, false)?;
            cached.store(true, Ordering::Relaxed);
            read()
        }
        r => r,
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn restore_counts_data_and_only_merged_base_working_set() {
        use crate::uffd::ZERO;
        let runs = vec![(100, 300, REMOTE), (500, 100, ZERO), (700, 100, REMOTE)];
        assert_eq!(restore_pages(400, &runs, &[(350, 200), (50, 200), (200, 250), (700, 100)]), 550);
        assert_eq!(restore_pages(400, &runs, &[]), 400);
        assert_eq!(restore_pages(400, &runs, &[(100, 300), (100, 300)]), 400);
        // A 2 GiB DATA checkpoint already supplies its 1 GiB working set.
        assert_eq!(restore_pages(524288, &vec![(0, 524288, REMOTE)], &[(0, 262144), (0, 262144)]), 524288);
    }
}
