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
pub use staging::{CommitError, Staging};
pub(crate) use write::{Buf, GuestPages};

/// The checkpoints flexvm keeps itself (`STATE/checkpoints/ID`, #775): their generations stay
/// (`Host::template_users`). None while the directory is missing.
pub fn managed(state: &std::path::Path) -> impl Iterator<Item = (std::path::PathBuf, Manifest)> {
    std::fs::read_dir(state.join("checkpoints")).into_iter().flatten().flatten().filter_map(|e| Some((e.path(), read_manifest(&e.path()).ok()?)))
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
