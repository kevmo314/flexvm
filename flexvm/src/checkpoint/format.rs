//! On-disk manifest and pagemap parsing, and canonical memory hashes.
use super::bail;
use crate::{
    template::{Hash, Template},
    util::{Result, PAGE_SIZE},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

pub const FORMAT: u64 = 2;
pub const FORMAT_INCREMENTAL: u64 = 3;
pub(super) const MAGIC: &[u8; 8] = b"FVPGMAP2";
pub(super) const DATA: u64 = 1;
pub(super) const ZERO: u64 = 2;
pub(super) const TEMPLATE: u64 = 3;
pub(super) const MAX_VMSTATE: u64 = 64 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSum {
    pub len: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u64,
    pub created_unix_ms: u64,
    pub name: String,
    pub ip: Ipv4Addr,
    pub template: String,
    pub template_id: String,
    /// MSRs selected by Firecracker on the host saving this VM state, not its template.
    /// Missing in older checkpoints; never substitute the template's set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_msrs: Option<BTreeSet<u32>>,
    /// Effective vCPU rate in this VM state, which can differ from its template's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_tsc_khz: Option<u32>,
    pub vcpus: u32,
    pub mem_mib: u64,
    pub max_mib: u64,
    pub hotplug_mib: u64,
    pub guest_pages: u64,
    pub data_pages: u64,
    pub zero_pages: u64,
    pub files: BTreeMap<String, FileSum>,
    /// The checkpoint this one is a delta against (format 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Parent>,
    /// How much of the guest's app log the VM process had passed on: a
    /// restore follows it from there, not from the start of the ring again.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub app_log: u64,
}

impl Manifest {
    pub fn saved_cpu(&self) -> Result<(u32, &BTreeSet<u32>)> {
        let rate = self
            .saved_tsc_khz
            .filter(|&khz| khz != 0)
            .ok_or("this checkpoint or suspended VM was made with an older flexvm without an effective vCPU TSC rate record and cannot be restored")?;
        let msrs = self
            .saved_msrs
            .as_ref()
            .ok_or("this checkpoint or suspended VM was made with an older flexvm without a saving host MSR record and cannot be restored")?;
        Ok((rate, msrs))
    }

    #[cfg(test)]
    pub fn check_compatibility(&self, template: &Template, host: &crate::compat::Compat) -> Result<u32> {
        let (rate, msrs) = self.saved_cpu()?;
        template.meta.compatibility.check_saved(host, rate, msrs)?;
        Ok(rate)
    }
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parent {
    /// Relative to this checkpoint's directory, or absolute.
    #[serde(with = "parent_path")]
    pub path: std::path::PathBuf,
    pub id: String,
}

// Keep existing UTF-8 manifests readable, while preserving arbitrary Unix path bytes.
mod parent_path {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::{
        ffi::OsString,
        os::unix::ffi::{OsStrExt, OsStringExt},
        path::{Path, PathBuf},
    };

    pub fn serialize<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
        match path.to_str() {
            Some(path) => path.serialize(serializer),
            None => path.as_os_str().as_bytes().serialize(serializer),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Text(String),
            Bytes(Vec<u8>),
        }
        Ok(match Repr::deserialize(deserializer)? {
            Repr::Text(path) => path.into(),
            Repr::Bytes(path) => OsString::from_vec(path).into(),
        })
    }
}

pub(super) fn sum(bytes: &[u8]) -> String {
    let mut h = Hash::new();
    h.update(bytes);
    h.finish()
}

/// A hash of guest memory independent of how it is stored: every page that
/// is neither the template's nor zero over a template hole, with its number,
/// in page order. A paused VM and a checkpoint of it hash the same.
pub struct Canon<'a> {
    template: &'a Template,
    hash: Hash,
    pages: u64,
}

impl<'a> Canon<'a> {
    pub fn new(template: &'a Template) -> Canon<'a> {
        Canon { template, hash: Hash::new(), pages: 0 }
    }

    /// Adds page `p` with contents `bytes` (empty: a zero page). Call in page order.
    pub fn page(&mut self, p: usize, bytes: &[u8]) {
        static ZEROES: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
        let bytes = if bytes.is_empty() { &ZEROES[..] } else { bytes };
        let base: &[u8] = if self.template.has_data(p) { self.template.pages(p, 1) } else { &ZEROES };
        if bytes != base {
            self.hash.word(p as u64);
            self.hash.update(bytes);
            self.pages += 1;
        }
    }

    pub fn finish(self) -> String {
        format!("{}/{}", self.hash.finish(), self.pages)
    }
}

/// A page map run: (first page, count, kind, checkpoint's index in its
/// chain, index of the first in that checkpoint's `pages`).
pub(super) type Run = (u64, u64, u64, usize, u64);

/// TEMPLATE runs are allowed only in a delta.
pub(super) fn parse_pagemap(map: &[u8], guest_pages: u64, delta: bool, ck: usize) -> Result<(Vec<Run>, Vec<u32>)> {
    let word = |i: usize| -> Result<u64> { Ok(u64::from_le_bytes(map.get(i * 8..i * 8 + 8).ok_or("pagemap truncated")?.try_into()?)) };
    ensure!(map.len() >= 24 && &map[..8] == MAGIC, "bad pagemap header");
    let (nruns, ndata) = (word(1)?, word(2)?);
    ensure!(Some(map.len() as u64) == nruns.checked_mul(32).zip(ndata.checked_mul(4)).and_then(|(r, d)| (24 + r).checked_add(d)), "bad pagemap length");
    let nruns = nruns as usize;
    let (mut runs, mut next) = (Vec::with_capacity(nruns), 0u64);
    for r in 0..nruns {
        let [first, count, kind, at] = [0, 1, 2, 3].map(|i| word(3 + 4 * r + i));
        let (first, count, kind, at) = (first?, count?, kind?, at?);
        let end = first.checked_add(count).filter(|&e| count > 0 && first >= next && e <= guest_pages);
        let Some(end) = end else { bail!("page run {r} out of order or bounds") };
        next = end;
        match kind {
            DATA | ZERO => runs.push((first, count, kind, ck, at)),
            TEMPLATE if delta => runs.push((first, count, kind, ck, 0)),
            k => bail!("page run {r} has kind {k}"),
        }
    }
    let mut tiles: Vec<(u64, u64)> = runs.iter().filter(|r| r.2 == DATA).map(|r| (r.4, r.1)).collect();
    tiles.sort_unstable();
    let end = tiles.iter().try_fold(0u64, |pos, &(at, n)| (at == pos).then_some(pos + n));
    ensure!(end == Some(ndata), "data runs do not cover the {ndata} stored pages exactly once");
    let sums = map[24 + 32 * nruns..].chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    Ok((runs, sums))
}
