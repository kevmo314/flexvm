//! Templates: a VM cold-booted once and snapshotted right after the guest
//! agent came up. Every VM is a UFFD restore of a template, so "boot" costs a
//! snapshot load and pages are copied in only as the guest touches them.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::bail;
use crate::fc::Firecracker;
use crate::guest;
use crate::uffd::Pager;
use crate::util::{ms, retry, Result, PAGE_SIZE};

pub const BOOT_ARGS: &str = "console=ttyS0 quiet reboot=k panic=1 pci=off \
    i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd \
    rootflags=dax init=/sbin/flexvm-init memhp_default_state=online_movable psi=1";

/// KVM memslot size for the virtio-mem region (MiB). Restores pay per slot,
/// and plugged but untouched memory costs the host nothing, so slots are big.
pub const SLOT_MIB: u64 = 1024;
/// Step the controller grows and shrinks guests by (MiB).
pub const STEP_MIB: u64 = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub vcpus: u32,
    pub mem_mib: u64,
    pub max_mib: u64,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
}

/// Paths shared by everything that creates or runs VMs.
#[derive(Debug, Clone)]
pub struct Paths {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub templates: PathBuf,
}

impl Paths {
    pub fn new(artifacts: &Path, templates: Option<PathBuf>) -> Result<Self> {
        let a = artifacts.canonicalize().map_err(|e| format!("artifacts dir {artifacts:?}: {e}"))?;
        Ok(Paths {
            firecracker: a.join("firecracker"),
            kernel: a.join("vmlinux"),
            rootfs: a.join("rootfs.ext4"),
            templates: templates.unwrap_or_else(|| a.join("templates")),
        })
    }
}

pub struct Template {
    pub name: String,
    pub dir: PathBuf,
    pub meta: Meta,
    /// Pages a fresh VM touches on its way to ready, as `(first_page, count)`.
    pub working_set: Vec<(u64, u64)>,
    map: *const u8,
    len: usize,
    /// Bitmap of pages that hold data in the memory file (the rest are holes).
    data: Vec<u64>,
}

unsafe impl Send for Template {}
unsafe impl Sync for Template {}

impl Template {
    pub fn open(paths: &Paths, name: &str) -> Result<Arc<Template>> {
        let dir = paths.templates.join(name);
        let meta: Meta = serde_json::from_slice(
            &std::fs::read(dir.join("meta.json")).map_err(|e| format!("template {name:?}: {e}"))?,
        )?;
        let file = File::open(dir.join("mem"))?;
        let len = file.metadata()?.len() as usize;
        let map = unsafe {
            libc::mmap(std::ptr::null_mut(), len.max(1), libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0)
        };
        if map == libc::MAP_FAILED {
            bail!("mmap template memory: {}", std::io::Error::last_os_error());
        }
        let data = data_bitmap(&file, len)?;
        let working_set = std::fs::read(dir.join("wset"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Ok(Arc::new(Template { name: name.into(), dir, meta, working_set, map: map as *const u8, len, data }))
    }

    pub fn vmstate(&self) -> PathBuf {
        self.dir.join("vmstate")
    }

    pub fn has_data(&self, page: usize) -> bool {
        self.data.get(page / 64).is_some_and(|w| w & (1 << (page % 64)) != 0)
    }

    /// The template's bytes for `n` pages starting at `page`. They must all have data.
    pub fn pages(&self, page: usize, n: usize) -> &[u8] {
        let start = page * PAGE_SIZE;
        assert!(start + n * PAGE_SIZE <= self.len);
        unsafe { std::slice::from_raw_parts(self.map.add(start), n * PAGE_SIZE) }
    }
}

impl Drop for Template {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.map as *mut _, self.len.max(1)) };
    }
}

/// Finds the data extents of a sparse file with SEEK_DATA / SEEK_HOLE.
fn data_bitmap(file: &File, len: usize) -> Result<Vec<u64>> {
    let pages = len.div_ceil(PAGE_SIZE);
    let mut bits = vec![0u64; pages.div_ceil(64)];
    let fd = file.as_raw_fd();
    let mut off: i64 = 0;
    while (off as usize) < len {
        let data = unsafe { libc::lseek(fd, off, libc::SEEK_DATA) };
        if data < 0 {
            // ENXIO: no data past `off`. Anything else would silently zero real pages.
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(e.into());
        }
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let end = hole;
        for p in (data as usize / PAGE_SIZE)..(end as usize).div_ceil(PAGE_SIZE).min(pages) {
            bits[p / 64] |= 1 << (p % 64);
        }
        off = end;
    }
    Ok(bits)
}

/// Punches holes over all-zero pages so they cost nothing to store or serve.
fn sparsify(path: &Path) -> Result<u64> {
    use std::os::unix::fs::FileExt;
    let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    let len = f.metadata()?.len() as i64;
    let fd = f.as_raw_fd();
    let mut buf = vec![0u8; PAGE_SIZE];
    let mut punched = 0u64;
    let mut off: i64 = 0;
    while off < len {
        let data = unsafe { libc::lseek(fd, off, libc::SEEK_DATA) };
        if data < 0 {
            break;
        }
        let end = match unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) } {
            h if h < 0 => len,
            h => h,
        };
        let mut p = data;
        while p < end {
            let n = f.read_at(&mut buf, p as u64)?;
            if n > 0 && buf[..n].iter().all(|&b| b == 0) {
                let rc = unsafe {
                    libc::fallocate(fd, libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, p, n as i64)
                };
                if rc == 0 {
                    punched += n as u64;
                }
            }
            p += PAGE_SIZE as i64;
        }
        off = end;
    }
    Ok(punched)
}

/// Restores the template once and records which pages the guest touches
/// until its agent answers; restores prefetch exactly those.
fn record_working_set(paths: &Paths, name: &str, tap: &str) -> Result<usize> {
    let tpl = Template::open(paths, name)?;
    let run = tpl.dir.join("record");
    std::fs::create_dir_all(&run)?;
    let pager = Pager::start(&run.join("uffd.sock"), tpl.clone(), None)?;
    let fc = Firecracker::spawn(&paths.firecracker, &run)?;
    pager.set_pid(fc.pid());
    fc.put(
        "/snapshot/load",
        json!({
            "snapshot_path": tpl.vmstate(),
            "mem_backend": {"backend_type": "Uffd", "backend_path": run.join("uffd.sock")},
            "vsock_override": {"uds_path": run.join("v.sock")},
            "network_overrides": [{"iface_id": "eth0", "host_dev_name": tap}],
            // Like the daemon's restores: stepping the clock touches pages of its own.
            "clock_realtime": true,
            "resume_vm": true,
        }),
    )?;
    retry(Duration::from_secs(10), || guest::ping(&run.join("v.sock")))?;
    guest::net(&run.join("v.sock"), "10.255.255.254".parse()?, None)?;
    guest::exec(&run.join("v.sock"), "true")?;
    fc.pause()?;
    let runs = pager.present_runs();
    pager.stop();
    drop(fc);
    let _ = std::fs::remove_dir_all(&run);
    std::fs::write(tpl.dir.join("wset"), serde_json::to_vec(&runs)?)?;
    Ok(runs.iter().map(|r| r.1 as usize).sum::<usize>() * PAGE_SIZE)
}

/// Cold-boots a VM and snapshots it into `paths.templates/name`.
pub fn create(paths: &Paths, name: &str, vcpus: u32, mem_mib: u64, max_mib: u64) -> Result<()> {
    // Restores swap in each VM's own tap; this one only exists while building.
    let tap = format!("fvtpl{}", std::process::id());
    crate::net::create_tap(&tap)?;
    let res = build(paths, name, vcpus, mem_mib, max_mib, &tap);
    crate::net::delete_tap(&tap);
    res
}

fn build(paths: &Paths, name: &str, vcpus: u32, mem_mib: u64, max_mib: u64, tap: &str) -> Result<()> {
    let dir = paths.templates.join(name);
    std::fs::create_dir_all(&dir)?;
    let run = dir.join("boot");
    std::fs::create_dir_all(&run)?;
    let vsock = run.join("v.sock");
    let _ = std::fs::remove_file(&vsock);

    let start = Instant::now();
    let fc = Firecracker::spawn(&paths.firecracker, &run)?;
    fc.put("/boot-source", json!({"kernel_image_path": paths.kernel, "boot_args": BOOT_ARGS}))?;
    fc.put("/machine-config", json!({"vcpu_count": vcpus, "mem_size_mib": mem_mib}))?;
    fc.put("/pmem/root", json!({"id": "root", "path_on_host": paths.rootfs, "root_device": true, "read_only": true}))?;
    fc.put(
        "/balloon",
        json!({"amount_mib": 0, "deflate_on_oom": false, "stats_polling_interval_s": 1, "free_page_reporting": true}),
    )?;
    let hotplug = max_mib.saturating_sub(mem_mib) / SLOT_MIB * SLOT_MIB;
    if hotplug > 0 {
        fc.put("/hotplug/memory", json!({"total_size_mib": hotplug, "slot_size_mib": SLOT_MIB}))?;
    }
    fc.put("/vsock", json!({"guest_cid": 3, "uds_path": vsock}))?;
    fc.put(
        "/network-interfaces/eth0",
        json!({"iface_id": "eth0", "host_dev_name": tap, "guest_mac": crate::net::GUEST_MAC}),
    )?;
    fc.put("/entropy", json!({}))?;
    fc.put("/actions", json!({"action_type": "InstanceStart"}))?;
    retry(Duration::from_secs(30), || guest::ping(&vsock))?;
    let booted = start.elapsed();

    // Leave as little as possible in the snapshot.
    guest::exec(&vsock, "sync; echo 3 > /proc/sys/vm/drop_caches; echo 1 > /proc/sys/vm/compact_memory")?;
    fc.pause()?;
    fc.put(
        "/snapshot/create",
        json!({"snapshot_type": "Full", "snapshot_path": dir.join("vmstate"), "mem_file_path": dir.join("mem")}),
    )?;
    drop(fc);
    let punched = sparsify(&dir.join("mem"))?;
    let _ = std::fs::remove_dir_all(&run);

    let meta = Meta {
        vcpus,
        mem_mib,
        max_mib: mem_mib + hotplug,
        kernel: paths.kernel.clone(),
        rootfs: paths.rootfs.clone(),
    };
    std::fs::write(dir.join("meta.json"), serde_json::to_vec_pretty(&meta)?)?;
    let _ = std::fs::remove_file(dir.join("wset"));
    let wset = record_working_set(paths, name, tap)?;
    let size = std::fs::metadata(dir.join("mem"))?.len();
    println!(
        "template {name}: {vcpus} vCPUs, {mem_mib} MiB base + {hotplug} MiB hotplug, booted in {} ms, \
         memory file {} MiB ({} MiB of zeroes punched out), working set {} MiB",
        ms(booted),
        size >> 20,
        punched >> 20,
        wset >> 20
    );
    Ok(())
}
