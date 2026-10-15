//! Private staging, overlapping fsyncs, publication and revocation.
use super::{
    chain_meta_budget, check, cname, create_at,
    format::{sum, sums_sum, MAX_VMSTATE},
    fstat, open_dir_at,
    write::{write_pages, writer_threads, GuestPages, PagesFile},
    FileSum, Manifest, Parent, FORMAT, FORMAT_INCREMENTAL,
};
use crate::{
    uffd::Runs,
    util::{Error, Phases, Result, PAGE_SIZE},
    vm::Vm,
};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, OwnedFd, RawFd},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) fn publish_permissions(files: &[RawFd], dir: RawFd, owner: &libc::stat) -> io::Result<()> {
    for (fd, mode) in files.iter().copied().map(|fd| (fd, 0o600)).chain(std::iter::once((dir, 0o700))) {
        check(unsafe { libc::fchown(fd, owner.st_uid, owner.st_gid) })?;
        check(unsafe { libc::fchmod(fd, mode) })?;
    }
    Ok(())
}

pub(super) const STAGING_PREFIX: &str = ".flexvm-staging-";

pub enum CommitError {
    /// Nothing was published (or what was is durably unusable): the VM may resume.
    Failed(Error),
    /// Published, maybe not durably, and not revocable: the VM must not
    /// resume, or a stale checkpoint could later restore.
    Uncertain(Error),
}

impl<E: Into<Error>> From<E> for CommitError {
    fn from(e: E) -> Self {
        CommitError::Failed(e.into())
    }
}

/// A checkpoint being written: published as `dest` once complete and durable, else removed.
/// We run as root under a directory a user may own, so nothing follows a path they can change:
/// dirs are pinned by fd, files created O_EXCL|O_NOFOLLOW in root-only staging, renamed fd to fd.
pub struct Staging {
    dest: PathBuf,
    pub(super) parent: OwnedFd,
    base: CString,
    /// The root-only staging directory in `parent`, and "ck" in it, published as `dest`.
    outer: OwnedFd,
    outer_name: CString,
    pub(super) ck: OwnedFd,
    vmstate: PathBuf,
    pages: Option<PagesFile>,
    published: bool,
    pub meta_left: u64,
    /// `Manifest::app_log`.
    pub app_log: u64,
}

impl Staging {
    /// Firecracker writes the VM state to `vmstate`, a path only root controls.
    pub fn new(dest: &Path, vmstate: PathBuf, work: &Path) -> Result<Staging> {
        let parent = dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let base = dest.file_name().ok_or_else(|| format!("bad checkpoint path {}", dest.display()))?;
        let parent_path = parent.canonicalize().map_err(|e| format!("checkpoint directory {}: {e}", parent.display()))?;
        let dest = parent_path.join(base);
        let pfd = open_dir_at(libc::AT_FDCWD, &CString::new(parent_path.as_os_str().as_bytes())?)
            .map_err(|e| format!("checkpoint directory {}: {e}", parent_path.display()))?;
        let base = CString::new(base.as_bytes())?;
        ensure!(crate::util::stat_at(pfd.as_raw_fd(), &base).is_none(), "{} already exists; checkpoints are never overwritten", dest.display());
        // Its directory's own entry, up to the root, ahead of the pause; `commit` walks again, as then.
        crate::util::sync_ancestors_fd(pfd.as_raw_fd()).map_err(|e| format!("checkpoint directory {}: {e}", parent_path.display()))?;
        // Record before creating anything: gc can find debris even if we die during setup.
        std::fs::write(work.join("checkpoint-staging"), parent_path.as_os_str().as_bytes())?;
        check(unsafe { libc::flock(pfd.as_raw_fd(), libc::LOCK_EX) })?;
        clear_stale_fd(&pfd);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
        let outer_name = cname(&format!("{STAGING_PREFIX}{}-{nanos:x}", std::process::id()));
        check(unsafe { libc::mkdirat(pfd.as_raw_fd(), outer_name.as_ptr(), 0o700) })?;
        let outer = open_dir_at(pfd.as_raw_fd(), &outer_name).inspect_err(|_| remove_staging(pfd.as_raw_fd(), &outer_name, -1, None))?;
        let ck = (|| -> Result<_> {
            check(unsafe { libc::flock(outer.as_raw_fd(), libc::LOCK_EX) })?;
            check(unsafe { libc::flock(pfd.as_raw_fd(), libc::LOCK_UN) })?;
            ensure!(private_dir(outer.as_raw_fd()), "staging directory in {} was replaced", parent_path.display());
            check(unsafe { libc::mkdirat(outer.as_raw_fd(), c"ck".as_ptr(), 0o700) })?;
            Ok(open_dir_at(outer.as_raw_fd(), c"ck")?)
        })()
        .inspect_err(|_| remove_staging(pfd.as_raw_fd(), &outer_name, outer.as_raw_fd(), None))?;
        let _ = std::fs::remove_file(&vmstate);
        Ok(Staging { dest, parent: pfd, base, outer, outer_name, ck, vmstate, pages: None, published: false, meta_left: chain_meta_budget(), app_log: 0 })
    }

    pub fn dest(&self) -> &Path {
        &self.dest
    }

    /// A path to the destination's directory as pinned; valid while this lives.
    pub fn pinned_dir(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.parent.as_raw_fd()))
    }

    pub fn vmstate(&self) -> PathBuf {
        self.vmstate.clone()
    }

    pub fn create(&self, name: &str) -> io::Result<File> {
        let f = create_at(self.ck.as_raw_fd(), name)?;
        // Set ownership before any data sync, so the inode's permissions are durable too.
        publish_permissions(&[f.as_raw_fd()], self.ck.as_raw_fd(), &fstat(self.parent.as_raw_fd())?)?;
        Ok(f)
    }

    pub fn add_file(&self, name: &str, bytes: &[u8]) -> io::Result<File> {
        let f = self.create(name)?;
        (&f).write_all(bytes)?;
        f.sync_all()?;
        Ok(f)
    }

    /// The map depends on the page copy, but its write can overlap the pages' fsync.
    pub(super) fn sync_pages_and_pagemap(&self, pages: &File, map: &[u8]) -> Result<File> {
        std::thread::scope(|s| {
            let syncing = std::thread::Builder::new().spawn_scoped(s, || pages.sync_all())?;
            let pagemap = self.add_file("pagemap", map);
            syncing.join().map_err(|_| "pages fsync thread panicked")??;
            Ok(pagemap?)
        })
    }

    /// Allocates disk space ahead of the pause.
    pub fn preallocate(&mut self, pages: usize) -> Result<()> {
        let file = PagesFile::new(self.create("pages")?);
        file.reserve(pages);
        self.pages = Some(file);
        Ok(())
    }

    /// Writes `runs` (read from `src`) and metadata, then publishes. With a `parent`, `runs`
    /// lists only what changed since it (BASE runs explicit): a delta.
    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        mut self,
        vm: &Vm,
        src: &dyn GuestPages,
        runs: &Runs,
        parent: Option<Parent>,
        hotplug_mib: u64,
        t: &mut Phases,
        still_valid: impl FnOnce() -> Result<()>,
    ) -> std::result::Result<(Manifest, String), CommitError> {
        let pages = if let Some(p) = self.pages.take() { p } else { PagesFile::new(self.create("pages")?) };
        // The scope joins every writer before the manifest, including on failure.
        let (out, vmstate) = std::thread::scope(|s| -> Result<_> {
            let state = std::thread::Builder::new().spawn_scoped(s, || -> Result<_> {
                let vmstate = std::fs::read(&self.vmstate)?;
                ensure!(vmstate.len() as u64 <= MAX_VMSTATE, "its vmstate is over {MAX_VMSTATE} bytes");
                self.add_file("vmstate", &vmstate)?;
                Ok(vmstate)
            })?;
            let copied = write_pages(&vm.template, src, runs, &pages, writer_threads(), parent.is_some()).and_then(|out| {
                t.mark("write_pages");
                self.sync_pages_and_pagemap(&pages.file, &out.map)?;
                Ok(out)
            });
            let state = state.join().map_err(|_| "vmstate writer thread panicked")?;
            // The copy's error says more than the VM state's.
            Ok((copied?, state?))
        })?;
        let map = &out.map;
        let files = BTreeMap::from([
            ("vmstate".into(), FileSum { len: vmstate.len() as u64, hash: sum(&vmstate) }),
            ("pagemap".into(), FileSum { len: map.len() as u64, hash: sum(map) }),
            ("pages".into(), FileSum { len: out.data * PAGE_SIZE as u64, hash: sums_sum(&out.sums) }),
        ]);
        let meta = &vm.template.meta;
        let manifest = Manifest {
            format: if parent.is_some() { FORMAT_INCREMENTAL } else { FORMAT },
            created_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
            name: vm.name.clone(),
            ip: vm.ip,
            template: vm.template.name.clone(),
            template_id: meta.id.clone(),
            vcpus: meta.vcpus,
            mem_mib: meta.mem_mib,
            max_mib: meta.max_mib,
            hotplug_mib,
            guest_pages: vm.pager.total_pages() as u64,
            data_pages: out.data,
            zero_pages: out.zero,
            files,
            parent,
            app_log: self.app_log,
        };
        let body = serde_json::to_vec_pretty(&manifest)?;
        let id = sum(&body);
        let text = [format!("{id}\n").as_bytes(), &body].concat();
        if (text.len() + vmstate.len() + map.len()) as u64 > self.meta_left {
            let budget = chain_meta_budget();
            return Err(match manifest.parent {
                Some(_) => format!("its chain would have more than {budget} bytes of metadata; take a full one"),
                None => format!("it would have more than {budget} bytes of metadata"),
            }
            .into());
        }
        self.add_file("manifest.json", &text)?;
        check(unsafe { libc::fsync(self.ck.as_raw_fd()) })?;
        still_valid()?;
        // The pinned directory must still be the one `dest` names.
        use std::os::unix::fs::MetadataExt;
        let moved = format!("the directory of {} was moved or replaced during the checkpoint", self.dest.display());
        let named = std::fs::metadata(self.dest.parent().unwrap_or(Path::new("/"))).map_err(|e| format!("{moved}: {e}"))?;
        let pinned = fstat(self.parent.as_raw_fd())?;
        if named.dev() != pinned.st_dev as u64 || named.ino() != pinned.st_ino as u64 {
            return Err(moved.into());
        }
        // Again from the pinned directory: an ancestor may have been moved since (cheap if not).
        crate::util::sync_ancestors_fd(self.parent.as_raw_fd())?;
        t.mark("fsync");
        let (outer, parent) = (self.outer.as_raw_fd(), self.parent.as_raw_fd());
        check(unsafe { libc::renameat2(outer, c"ck".as_ptr(), parent, self.base.as_ptr(), libc::RENAME_NOREPLACE) })
            .map_err(|e| format!("publish checkpoint at {}: {e}", self.dest.display()))?;
        self.published = true;
        let synced = match crate::host::fault("publish_fsync") {
            true => Err(io::Error::other("injected fault: fsync failed")),
            false => check(unsafe { libc::fsync(parent) }),
        };
        if let Err(e) = synced {
            // A crash could bring it back after the VM ran on: revoke it, durably.
            let revoked = self.revoke();
            let e = format!("making checkpoint {} durable: {e}", self.dest.display());
            return Err(match revoked {
                Ok(Ok(())) => CommitError::Failed(format!("{e} (revoked it)").into()),
                // Unloadable for good; in the way of that path until removed (a suspend's, by the name's next holder).
                Ok(Err(r)) => CommitError::Failed(
                    format!("{e} (revoked it, but removing its directory failed: {r}; remove {} by hand if it stays)", self.dest.display()).into(),
                ),
                Err(r) => CommitError::Uncertain(format!("{e}; revoking it failed too: {r}").into()),
            });
        }
        t.mark("publish");
        Ok((manifest, id))
    }

    /// Unpublishes `dest`. The outer error: its manifest (what makes it a
    /// checkpoint) may still be there. Once that is durably gone, the rest
    /// goes, durably; the inner error: some of it may stay, or come back
    /// after a crash, as a directory without a manifest (debris, which a
    /// suspended VM's name's next holder removes).
    fn revoke(&self) -> io::Result<io::Result<()>> {
        let ck = self.ck.as_raw_fd();
        check(unsafe { libc::unlinkat(ck, c"manifest.json".as_ptr(), 0) })?;
        check(unsafe { libc::fsync(ck) })?;
        let parent = self.parent.as_raw_fd();
        let removed = (|| {
            if crate::host::fault("revoke_cleanup") {
                return Err(io::Error::other("injected fault: removal failed"));
            }
            empty_dir(ck)?;
            check(unsafe { libc::unlinkat(parent, self.base.as_ptr(), libc::AT_REMOVEDIR) })?;
            check(unsafe { libc::fsync(parent) })
        })();
        Ok(removed)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let ck = (!self.published).then(|| self.ck.as_raw_fd());
        remove_staging(self.parent.as_raw_fd(), &self.outer_name, self.outer.as_raw_fd(), ck);
        let _ = std::fs::remove_file(&self.vmstate);
    }
}

fn remove_staging(parent: RawFd, name: &CStr, outer: RawFd, ck: Option<RawFd>) {
    if let Some(ck) = ck {
        let _ = empty_dir(ck);
    }
    unsafe { libc::unlinkat(outer, c"ck".as_ptr(), libc::AT_REMOVEDIR) };
    unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) };
}

/// Every file in it (only we write there; `add_file` adds more than the four).
fn empty_dir(dir: RawFd) -> io::Result<()> {
    for f in std::fs::read_dir(format!("/proc/self/fd/{dir}"))? {
        check(unsafe { libc::unlinkat(dir, cname(&f?.file_name().to_string_lossy()).as_ptr(), 0) })?;
    }
    Ok(())
}

/// Whether `fd` is ours and nobody else may enter it, as staging is made.
fn private_dir(fd: RawFd) -> bool {
    fstat(fd).is_ok_and(|st| st.st_uid == unsafe { libc::geteuid() } && st.st_mode & 0o077 == 0)
}

/// For gc: clears the stale staging a dead process left in `path`, a directory it recorded. Returns false if that
/// should be tried again later (another process holds the directory's lock). The directory may be a user's, who may
/// have changed the path since: it is walked from `/` without following a symlink, and nothing but root-only staging
/// in it is removed. The lock is only tried, never waited for: a user may hold it for as long as they like.
pub fn clear_stale(path: &Path) -> bool {
    use std::path::Component;
    if !path.is_absolute() {
        return true;
    }
    let mut dir = match open_dir_at(libc::AT_FDCWD, c"/") {
        Ok(d) => d,
        Err(_) => return true,
    };
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(name) => {
                let Ok(name) = CString::new(name.as_bytes()) else { return true };
                match open_dir_at(dir.as_raw_fd(), &name) {
                    Ok(d) => dir = d,
                    Err(_) => return true,
                }
            }
            _ => return true,
        }
    }
    for _ in 0..50 {
        if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            clear_stale_fd(&dir);
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    false
}

fn clear_stale_fd(parent: &OwnedFd) {
    let Ok(dir) = std::fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd())) else { return };
    for e in dir.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with(STAGING_PREFIX) {
            continue;
        }
        let Ok(outer) = open_dir_at(parent.as_raw_fd(), &cname(&name)) else { continue };
        if !private_dir(outer.as_raw_fd()) || unsafe { libc::flock(outer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            continue;
        }
        let ck = open_dir_at(outer.as_raw_fd(), c"ck").ok();
        remove_staging(parent.as_raw_fd(), &cname(&name), outer.as_raw_fd(), ck.as_ref().map(|c| c.as_raw_fd()));
    }
}
