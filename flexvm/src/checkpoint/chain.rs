//! Budgeted chain opening, overlay flattening and checked page reads.
use super::{
    bail,
    format::{parse_pagemap, sum, sums_sum, Canon, Manifest, Run, DATA, FORMAT, FORMAT_INCREMENTAL, MAX_VMSTATE, TEMPLATE},
    fstat, open_at, open_dir_at,
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
    sync::Arc,
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
    dir: PathBuf,
    manifest: Manifest,
    id: String,
    vmstate: Vec<u8>,
    map: Vec<Run>,
    file: Option<File>,
    sums: Vec<u32>,
}

impl Link {
    /// With `meta_left`, also reads and checks the rest within that budget (debited) and opens `pages`.
    pub(super) fn open(dir: &Path, ck: usize, meta_left: Option<&mut u64>) -> Result<Link> {
        let dir = dir.canonicalize().map_err(|e| format!("checkpoint {}: {e}", dir.display()))?;
        let bad = |why: String| format!("checkpoint {} is invalid: {why}", dir.display());
        let dfd = open_dir_at(libc::AT_FDCWD, &CString::new(dir.as_os_str().as_bytes())?).map_err(|e| bad(e.to_string()))?;
        let (_, text) = read_at(dfd.as_raw_fd(), "manifest.json", 1 << 20).map_err(|e| bad(format!("manifest.json: {e}")))?;
        let split = text.iter().position(|&b| b == b'\n').ok_or_else(|| bad("manifest has no checksum".into()))?;
        ensure!(text[..split] == *sum(&text[split + 1..]).as_bytes(), "{}", bad("manifest checksum mismatch".into()));
        let manifest: Manifest = serde_json::from_slice(&text[split + 1..]).map_err(|e| bad(format!("manifest: {e}")))?;
        let id = String::from_utf8_lossy(&text[..split]).into_owned();
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
        let vmstate = read_checked("vmstate")?;
        let (map, sums) = parse_pagemap(&read_checked("pagemap")?, manifest.guest_pages, manifest.parent.is_some(), ck).map_err(|e| bad(e.to_string()))?;
        let data: u64 = map.iter().filter(|r| r.2 == DATA).map(|r| r.1).sum();
        ensure!(
            data == manifest.data_pages && manifest.files.get("pages").map(|f| f.len) == Some(data * PAGE_SIZE as u64),
            "{}",
            bad("page counts do not add up".into())
        );
        ensure!(manifest.files["pages"].hash == sums_sum(&sums), "{}", bad("page checksums do not match the manifest".into()));
        let (file, _) = read_at(dfd.as_raw_fd(), "pages", 0).map_err(|e| bad(format!("pages: {e}")))?;
        ensure!(file.metadata()?.len() == data * PAGE_SIZE as u64, "{}", bad("pages has the wrong length".into()));
        Ok(Link { dir, manifest, id, vmstate, map, file: Some(file), sums })
    }
}

/// The chain ending at `dir`, nearest first; `full` verifies all metadata within
/// `chain_meta_budget` (returning what is left), else only manifests.
fn open_chain(dir: &Path, full: bool) -> Result<(Vec<Link>, u64)> {
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

pub fn parent_path(child: &Path, parent: &Path) -> String {
    match (child.parent(), parent.parent(), parent.file_name()) {
        (Some(a), Some(b), Some(name)) if a == b => format!("../{}", name.to_string_lossy()),
        _ => parent.to_string_lossy().into_owned(),
    }
}

impl Checkpoint {
    /// Opens the chain ending at `dir`, verifying all but page data, which is checked as read.
    pub fn open(dir: &Path) -> Result<Checkpoint> {
        let (mut links, meta_left) = open_chain(dir, true)?;
        let layers: Vec<Vec<Run>> = links.iter_mut().rev().map(|l| std::mem::take(&mut l.map)).collect();
        let (mut files, mut sums, mut rest) = (Vec::new(), Vec::new(), Vec::new());
        for l in links {
            files.push(l.file.unwrap());
            sums.push(l.sums);
            rest.push((l.dir, l.manifest, l.id, l.vmstate));
        }
        let mut rest = rest.into_iter();
        let (dir, manifest, id, vmstate) = rest.next().unwrap();
        let (chain, chain_ids) = rest.map(|(dir, _, id, _)| (dir, id)).unzip();
        let (runs, file) = flatten(&layers, files, sums);
        Ok(Checkpoint { dir, manifest, id, vmstate, runs, file: Arc::new(file), chain, chain_ids, meta_left })
    }

    fn each_page(&self, drop_cache: bool, mut f: impl FnMut(usize, &[u8])) -> Result<()> {
        let mut buf = vec![0u8; 256 * PAGE_SIZE];
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

    pub fn content_hash(&self, template: &Template) -> Result<String> {
        let mut canon = Canon::new(template);
        self.each_page(false, |p, b| canon.page(p, b))?;
        Ok(canon.finish())
    }
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
    (states, PageFile { files, runs: data, sums })
}

pub struct PageFile {
    files: Vec<File>,
    /// DATA runs: (first guest page, pages, file, index of the first in it).
    runs: Vec<(u64, u64, usize, u64)>,
    sums: Vec<Vec<u32>>,
}

fn corrupt(why: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("checkpoint page file: {why}"))
}

impl PageFile {
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
            let (out, off, file) = (&mut buf[done * PAGE_SIZE..(done + k) * PAGE_SIZE], d * PAGE_SIZE as u64, &self.files[f]);
            file.read_exact_at(out, off).map_err(|e| corrupt(format!("read at {off}: {e}")))?;
            if drop_cache {
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

    pub fn drop_cache(&self) {
        for f in &self.files {
            unsafe { libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        }
    }
}
