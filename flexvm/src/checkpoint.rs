//! Durable checkpoints: a VM's state as a delta against its template, restored lazily.
//! A directory (format 2): manifest.json (checksum line, then the `Manifest`), vmstate,
//! pagemap ("FVPGMAP2", run count, data page count, runs of (first page, count, kind, index
//! in `pages`) as u64 LE, then each stored page's CRC32C as u32 LE) and pages (DATA pages).
//! A page is BASE (template's, or zero over a hole; not stored), ZERO or DATA; a delta
//! (format 3) names a `parent` and adds TEMPLATE runs. Directories are staged root-only,
//! fsynced and renamed into place, never over anything: complete or absent, never changed.

use crate::bail;
use crate::util::{check, cname, fstat, open_dir_at, openat};
use std::{fs::File, io, os::fd::RawFd};

macro_rules! ensure {
    ($ok:expr, $($why:tt)*) => { if !$ok { crate::bail!($($why)*) } };
}
mod chain;
pub mod export;
mod format;
mod staging;
pub mod store;
mod write;

pub use chain::{chain_ids, chain_meta_budget, parent_path, read_manifest, Checkpoint, PageFile, MAX_CHAIN};
pub use format::{Canon, FileSum, Manifest, Parent, FORMAT, FORMAT_INCREMENTAL};
pub(crate) use staging::sweep_staging;
pub use staging::{CommitError, Staging};
pub(crate) use write::{Buf, GuestPages};

/// The checkpoints flexvm keeps itself (`STATE/checkpoints/ID`, #775): their generations stay
/// (`Host::template_users`). None while the directory is missing. One that cannot be read, or
/// whose manifest is not its `ID`'s (renamed by hand), is an error: it is still there.
/// A listing failure is an error at the directory path, even after some entries were read.
pub fn managed(state: &std::path::Path) -> impl Iterator<Item = crate::util::Result<(std::path::PathBuf, crate::util::Result<Manifest>)>> {
    let dir = state.join("checkpoints");
    managed_entries(entries(&dir))
}

fn managed_entries(
    entries: impl Iterator<Item = crate::util::Result<std::path::PathBuf>>,
) -> impl Iterator<Item = crate::util::Result<(std::path::PathBuf, crate::util::Result<Manifest>)>> {
    entries.filter_map(move |entry| {
        let path = match entry {
            Ok(path) => path,
            Err(e) => return Some(Err(e)),
        };
        let id = path.file_name()?.to_str().filter(|n| store::is_id(n))?;
        let read = chain::read_manifest_id(&path).and_then(|(found, m)| {
            ensure!(found == id, "checkpoint {} is invalid: its manifest's id is {found}", path.display());
            Ok(m)
        });
        present(&path, read).map(|m| Ok((path, m)))
    })
}

/// Only a missing directory is empty; even a partial listing must report its errors.
pub(crate) fn entries(dir: &std::path::Path) -> impl Iterator<Item = crate::util::Result<std::path::PathBuf>> {
    let path = dir.to_path_buf();
    listing(std::fs::read_dir(dir)).map(move |e| e.map(|e| e.path()).map_err(|e| format!("listing {}: {e}", path.display()).into()))
}

fn listing<T>(read: io::Result<impl Iterator<Item = io::Result<T>>>) -> impl Iterator<Item = io::Result<T>> {
    let (entries, error) = match read {
        Ok(entries) => (Some(entries), None),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => (None, None),
        Err(e) => (None, Some(Err(e))),
    };
    entries.into_iter().flatten().chain(error)
}

/// The manifest of the checkpoint record `dir` (a suspended VM's): None if it has none, a revoked
/// publication or a record being removed; any other error is an unreadable record.
pub(crate) fn record(dir: &std::path::Path) -> Option<crate::util::Result<Manifest>> {
    present(dir, read_manifest(dir))
}

fn present(dir: &std::path::Path, read: crate::util::Result<Manifest>) -> Option<crate::util::Result<Manifest>> {
    let missing = || std::fs::symlink_metadata(dir.join("manifest.json")).is_err_and(|e| e.kind() == io::ErrorKind::NotFound);
    (read.is_ok() || !missing()).then_some(read)
}

fn create_at(dir: RawFd, name: &str) -> io::Result<File> {
    openat(dir, &cname(name), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW).map(File::from)
}

/// Opens file `name` in `dir` for reading. O_NONBLOCK: a FIFO planted in its
/// place must not block (callers check for a regular file).
fn open_at(dir: RawFd, name: &str) -> io::Result<File> {
    openat(dir, &cname(name), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW).map(File::from)
}

#[cfg(test)]
mod tests;
