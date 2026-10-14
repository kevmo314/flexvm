//! Durable checkpoints: a VM's state as a delta against its template, restored lazily.
//! A directory (format 2): manifest.json (checksum line, then the `Manifest`), vmstate,
//! pagemap ("FVPGMAP2", run count, data page count, runs of (first page, count, kind, index
//! in `pages`) as u64 LE, then each stored page's CRC32C as u32 LE) and pages (DATA pages).
//! A page is BASE (template's, or zero over a hole; not stored), ZERO or DATA; a delta
//! (format 3) names a `parent` and adds TEMPLATE runs. Directories are staged root-only,
//! fsynced and renamed into place, never over anything: complete or absent, never changed.

use crate::bail;
use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    os::fd::{FromRawFd, OwnedFd, RawFd},
};

macro_rules! ensure {
    ($ok:expr, $($why:tt)*) => { if !$ok { crate::bail!($($why)*) } };
}
mod chain;
mod format;
mod staging;
mod write;

pub use chain::{chain_ids, chain_meta_budget, parent_path, Checkpoint, PageFile, MAX_CHAIN};
pub use format::{Canon, FileSum, Manifest, Parent, FORMAT, FORMAT_INCREMENTAL};
pub use staging::{CommitError, Staging};
pub(crate) use write::GuestPages;

fn cname(name: &str) -> CString {
    CString::new(name).expect("no NUL in file names")
}

fn check(rc: libc::c_int) -> io::Result<()> {
    (rc >= 0).then_some(()).ok_or_else(io::Error::last_os_error)
}

/// Opens `name` in `dir`, never through a symlink (O_NOFOLLOW is added).
fn openat(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
    check(fd)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_dir_at(dir: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    openat(dir, name, libc::O_RDONLY | libc::O_DIRECTORY)
}

fn create_at(dir: RawFd, name: &str) -> io::Result<File> {
    openat(dir, &cname(name), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL).map(File::from)
}

/// Opens file `name` in `dir` for reading. O_NONBLOCK: a FIFO planted in its
/// place must not block (callers check for a regular file).
fn open_at(dir: RawFd, name: &str) -> io::Result<File> {
    openat(dir, &cname(name), libc::O_RDONLY | libc::O_NONBLOCK).map(File::from)
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

#[cfg(test)]
mod tests;
