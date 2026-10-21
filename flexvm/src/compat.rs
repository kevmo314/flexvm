//! Snapshot compatibility preflight. A template records its build host's CPU model, the
//! features KVM offered (passed through: no CPU template), XSAVE layout, TSC rate,
//! saved MSR set and Firecracker. Checkpoints and migrations pin their template and check
//! the saving host's MSRs and effective TSC rate. Topology, cache and leaf-limit words are
//! not compared: Firecracker rewrites the first, the rest do not change what the guest can run.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::template::{hash_file, Stamp};
use crate::{bail, util::Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Compat {
    pub cpu: String,
    /// Default vCPU TSC rate used when building this template.
    pub tsc_khz: u32,
    /// Target KVM can scale a restored TSC rate.
    pub tsc_control: bool,
    /// KVM MSRs selected by Firecracker for serialization.
    pub msrs: BTreeSet<u32>,
    /// `firecracker --version` and the binary's content hash.
    pub firecracker: String,
    /// By "leaf.subleaf.register".
    pub features: BTreeMap<String, u32>,
    /// Component -> [size, offset].
    pub xsave: BTreeMap<u32, [u32; 2]>,
}

/// CPUID words that are feature bitmaps: (leaf, subleaf, registers).
const FEATURES: [(u32, u32, &[usize]); 11] = [
    (0x1, 0, &[2, 3]),
    (0x7, 0, &[1, 2, 3]),
    (0x7, 1, &[0, 3]),
    (0x7, 2, &[3]),
    (0xd, 0, &[0, 3]),
    (0xd, 1, &[0, 2, 3]),
    (0x4000_0001, 0, &[0]),
    (0x8000_0001, 0, &[2, 3]),
    (0x8000_0007, 0, &[3]),
    (0x8000_0008, 0, &[1]),
    (0x8000_0021, 0, &[0]),
];
const REGS: [&str; 4] = ["eax", "ebx", "ecx", "edx"];

impl Compat {
    pub fn check(&self, host: &Self) -> Result<()> {
        self.check_saved(host, self.tsc_khz, &self.msrs).map(drop)
    }

    /// Later snapshots save the effective vCPU rate and the saving host's MSRs. Returns the
    /// effective restored rate: Firecracker keeps the host default within 250 ppm, else scales.
    pub fn check_saved(&self, host: &Self, tsc_khz: u32, msrs: &BTreeSet<u32>) -> Result<u32> {
        let hints = ["every host needs the same CPU model", "copy one Firecracker binary to every host; templates built with another must be rebuilt"];
        for ((what, snapshot, here), hint) in [("CPU", &self.cpu, &host.cpu), ("Firecracker", &self.firecracker, &host.firecracker)].into_iter().zip(hints) {
            if snapshot != here {
                bail!("snapshot incompatible with this host: {what} differs (snapshot: {snapshot}; host: {here}): {hint}");
            }
        }
        check_tsc(tsc_khz, host)?;
        check_msrs(msrs, &host.msrs)?;
        for (word, &want) in &self.features {
            let missing = want & !host.features.get(word).copied().unwrap_or(0);
            if missing != 0 {
                bail!("snapshot incompatible with this host: CPU lacks features CPUID {word} {missing:#x} that the guest may use");
            }
        }
        for (c, want) in &self.xsave {
            if host.xsave.get(c) != Some(want) {
                bail!("snapshot incompatible with this host: XSAVE component {c} layout differs (snapshot: {want:?}; host: {:?})", host.xsave.get(c));
            }
        }
        Ok(if tsc_scaling_required(tsc_khz, host.tsc_khz) { tsc_khz } else { host.tsc_khz })
    }

    fn of_cpuid(entries: &[[u32; 6]], firecracker: String) -> Result<Self> {
        let word = |leaf, sub, reg: usize| entries.iter().find(|e| e[0] == leaf && e[1] == sub).map(|e| e[2 + reg]);
        let vendor: Vec<u8> = [1, 3, 2].iter().flat_map(|&r| word(0, 0, r).unwrap_or(0).to_le_bytes()).collect();
        let sig = word(1, 0, 0).ok_or("KVM CPUID has no leaf 1")?;
        let (family, model) = ((sig >> 8) & 0xf, (sig >> 4) & 0xf);
        let family = family + if family == 0xf { (sig >> 20) & 0xff } else { 0 };
        let model = model | if family >= 6 { (sig >> 12) & 0xf0 } else { 0 };
        Ok(Compat {
            cpu: format!("{} family {family:#x} model {model:#x}", String::from_utf8_lossy(&vendor)),
            firecracker,
            tsc_khz: 0,
            tsc_control: false,
            msrs: BTreeSet::new(),
            features: FEATURES
                .iter()
                .flat_map(|&(l, s, regs)| regs.iter().map(move |&r| (l, s, r)))
                .filter_map(|(l, s, r)| Some((format!("{l:#x}.{s}.{}", REGS[r]), word(l, s, r)?)))
                .collect(),
            xsave: entries.iter().filter(|e| e[0] == 0xd && e[1] >= 2 && e[2] != 0).map(|e| (e[1], [e[2], e[3]])).collect(),
        })
    }
}

/// Identity of the host probe: this boot, this flexvm and Firecracker, and the KVM device
/// and modules by (device, inode), which a module reload changes and a ctime touch does not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct HostKey {
    boot_id: String,
    flexvm: Stamp,
    firecracker: Stamp,
    kvm: (u64, u64),
    modules: [Option<(u64, u64)>; 3],
}

fn node(m: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (m.dev(), m.ino())
}

impl HostKey {
    fn local(firecracker: Stamp) -> Result<Self> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        if boot_id.trim().is_empty() {
            bail!("empty boot id");
        }
        let mut modules = [None, None, None];
        for (slot, name) in modules.iter_mut().zip(["kvm", "kvm_intel", "kvm_amd"]) {
            match std::fs::metadata(format!("/sys/module/{name}")) {
                Ok(m) => *slot = Some(node(&m)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let flexvm = Stamp::of(&std::fs::metadata("/proc/self/exe")?);
        Ok(Self { boot_id, flexvm, firecracker, kvm: node(&std::fs::metadata("/dev/kvm")?), modules })
    }
}

#[derive(Serialize, Deserialize)]
struct HostCache {
    key: HostKey,
    compat: Compat,
}

/// Cache failures only cost another probe. Version the probe as well as its inputs
/// so a future change to the CPUID/MSR selection can invalidate older results.
fn host_compat(run: Option<&Path>, key: Option<&HostKey>, probe: impl FnOnce() -> Result<Compat>) -> Result<Compat> {
    let read = run.and_then(|d| std::fs::read(d.join("compat.json")).ok()).and_then(|b| serde_json::from_slice::<HostCache>(&b).ok());
    if let Some(cached) = read.filter(|c| Some(&c.key) == key) {
        return Ok(cached.compat);
    }
    let compat = probe()?;
    if let (Some(run), Some(key)) = (run, key) {
        let cached = HostCache { key: key.clone(), compat: compat.clone() };
        let _ = crate::util::write_file(run, "compat.json", &serde_json::to_vec(&cached)?, false);
    }
    Ok(compat)
}

/// Shared across VM processes and cached in-process while the host key is unchanged.
pub fn local(pid: u32) -> Result<Compat> {
    local_binary(&PathBuf::from(format!("/proc/{pid}/exe")))
}

/// Probe the host without starting a VM, using the binary a pull would boot.
pub fn local_binary(firecracker: &Path) -> Result<Compat> {
    static CACHE: Mutex<Option<(HostKey, Compat)>> = Mutex::new(None);
    let stamp = Stamp::of(&std::fs::metadata(firecracker)?);
    // If an identity cannot be read, probe rather than trust an unverifiable cache.
    let key = HostKey::local(stamp).ok();
    let mut cache = CACHE.lock().unwrap();
    if let Some((_, c)) = cache.as_ref().filter(|(k, _)| Some(k) == key.as_ref()) {
        return Ok(c.clone());
    }
    let run = crate::host::run_dir();
    let compat = host_compat(run, key.as_ref(), || {
        let (_, binary) = firecracker_id(firecracker, run)?;
        let kvm = File::open("/dev/kvm").map_err(|e| format!("/dev/kvm: {e}"))?;
        let mut compat = Compat::of_cpuid(&supported_cpuid(&kvm)?, binary)?;
        compat.tsc_khz = tsc_khz(&kvm)?;
        compat.tsc_control = ioctl(&kvm, 0xae03, 60, "KVM_CHECK_EXTENSION(TSC_CONTROL)")? > 0;
        compat.msrs = saved_msrs(&kvm)?;
        Ok(compat)
    })?;
    *cache = key.map(|key| (key, compat.clone()));
    Ok(compat)
}

/// Shared across VM processes; an unreadable cache is only a miss.
fn firecracker_id(path: &Path, run: Option<&Path>) -> Result<(Stamp, String)> {
    let stamp = Stamp::of(&std::fs::metadata(path)?);
    if let Some(cached) = run
        .and_then(|d| std::fs::read(d.join("firecracker.json")).ok())
        .and_then(|b| serde_json::from_slice::<(Stamp, String)>(&b).ok())
        .filter(|(s, _)| *s == stamp)
    {
        return Ok(cached);
    }
    // As a VM process spawns Firecracker: signals unblocked, its open-file limit as found.
    let version = crate::util::unblock_signals_in(std::process::Command::new(path).arg("--version")).output()?;
    let version = String::from_utf8_lossy(&version.stdout);
    let version = version.lines().next().filter(|v| !v.is_empty()).ok_or("firecracker --version printed nothing")?;
    let binary = hash_file(path)?;
    let cached = (binary.metadata, format!("{version} (content {})", binary.hash));
    if let Some(run) = run {
        let _ = crate::util::write_file(run, "firecracker.json", &serde_json::to_vec(&cached)?, false);
    }
    Ok(cached)
}

/// Match Firecracker's is_tsc_scaling_required: tolerance is relative to the saved rate.
pub fn check_tsc(saved_khz: u32, host: &Compat) -> Result<()> {
    if saved_khz == 0 || host.tsc_khz == 0 {
        bail!("snapshot incompatible with this host: missing TSC rate; rebuild the template");
    }
    if tsc_scaling_required(saved_khz, host.tsc_khz) && !host.tsc_control {
        bail!(
            "snapshot incompatible with this host: TSC rate differs (snapshot: {} kHz; host: {} kHz), beyond 250 ppm and target lacks KVM TSC scaling",
            saved_khz,
            host.tsc_khz
        );
    }
    Ok(())
}

fn tsc_scaling_required(saved_khz: u32, host_khz: u32) -> bool {
    u64::from(saved_khz.abs_diff(host_khz)) > u64::from(saved_khz) * 250 / 1_000_000
}

/// Firecracker saves the MSRs of the host that took the snapshot, not the template's: a VM
/// that moved to a host with more brings them along, and a load on a host without them fails.
pub fn check_msrs(saved: &BTreeSet<u32>, host: &BTreeSet<u32>) -> Result<()> {
    let missing: Vec<_> = saved.difference(host).map(|index| format!("{index:#x}")).collect();
    if !missing.is_empty() {
        bail!("snapshot incompatible with this host: KVM lacks saved MSRs {}", missing.join(", "));
    }
    Ok(())
}

/// KVM_GET_SUPPORTED_CPUID as [function, index, eax, ebx, ecx, edx].
fn supported_cpuid(kvm: &File) -> Result<Vec<[u32; 6]>> {
    const MAX: usize = 256;
    // struct kvm_cpuid2 { u32 nent, padding; struct kvm_cpuid_entry2 entries[] },
    // each entry { function, index, flags, eax, ebx, ecx, edx, padding[3] }.
    let mut buf = vec![0u32; 2 + MAX * 10];
    buf[0] = MAX as u32;
    crate::syscall_check!(unsafe { libc::ioctl(kvm.as_raw_fd(), 0xc008_ae05, buf.as_mut_ptr()) } < 0, "KVM_GET_SUPPORTED_CPUID");
    let n = (buf[0] as usize).min(MAX);
    Ok(buf[2..2 + n * 10].chunks(10).map(|e| [e[0], e[1], e[3], e[4], e[5], e[6]]).collect())
}

/// An unstarted vCPU uses the same default TSC rate as a freshly built template.
/// No memory, guest code, or KVM_RUN: these probe descriptors are immediately closed.
fn tsc_khz(kvm: &File) -> Result<u32> {
    let vm = unsafe { OwnedFd::from_raw_fd(ioctl(kvm, 0xae01, 0, "KVM_CREATE_VM")?) };
    let vcpu = unsafe { OwnedFd::from_raw_fd(ioctl(&vm, 0xae41, 0, "KVM_CREATE_VCPU")?) };
    let khz = ioctl(&vcpu, 0xaea3, 0, "KVM_GET_TSC_KHZ")? as u32;
    // Destroying a VM waits out RCU grace periods: 20-40 ms under nested virtualization,
    // which every start, restore and migration target would otherwise wait for.
    std::thread::spawn(move || drop((vcpu, vm)));
    if khz == 0 {
        bail!("KVM_GET_TSC_KHZ returned zero");
    }
    Ok(khz)
}

fn ioctl(fd: &impl AsRawFd, request: libc::c_ulong, arg: libc::c_ulong, name: &str) -> Result<i32> {
    let value = unsafe { libc::ioctl(fd.as_raw_fd(), request, arg) };
    crate::syscall_check!(value < 0, "{name}");
    Ok(value)
}

fn saved_msrs(kvm: &File) -> Result<BTreeSet<u32>> {
    // KVM reports the required size with E2BIG. Do not silently truncate a future kernel's list.
    let mut buf = vec![0u32; 1];
    let result = unsafe { libc::ioctl(kvm.as_raw_fd(), 0xc004_ae02, buf.as_mut_ptr()) };
    crate::syscall_check!(result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::E2BIG), "KVM_GET_MSR_INDEX_LIST");
    buf.resize(1 + buf[0] as usize, 0);
    crate::syscall_check!(unsafe { libc::ioctl(kvm.as_raw_fd(), 0xc004_ae02, buf.as_mut_ptr()) } < 0, "KVM_GET_MSR_INDEX_LIST");
    Ok(buf[1..].iter().copied().filter(|&index| msr_should_serialize(index)).collect())
}

/// Firecracker v1.17.0 arch/x86_64/msr.rs SERIALIZABLE_MSR_RANGES,
/// including IA32_XSS. Keep in sync when changing Firecracker's save filter.
fn msr_should_serialize(index: u32) -> bool {
    const RANGES: &[(u32, u32)] = &[
        (0x0, 0x1),          // MSR_IA32_P5_MC_ADDR
        (0x1, 0x1),          // MSR_IA32_P5_MC_TYPE
        (0x10, 0x1),         // MSR_IA32_TSC
        (0x17, 0x1),         // MSR_IA32_PLATFORM_ID
        (0x1b, 0x1),         // MSR_IA32_APICBASE
        (0x2a, 0x1),         // MSR_IA32_EBL_CR_POWERON
        (0x2c, 0x1),         // MSR_EBC_FREQUENCY_ID
        (0x34, 0x1),         // MSR_SMI_COUNT
        (0x3a, 0x1),         // MSR_IA32_FEAT_CTL
        (0x3b, 0x1),         // MSR_IA32_TSC_ADJUST
        (0x48, 0x1),         // MSR_IA32_SPEC_CTRL
        (0x49, 0x1),         // MSR_IA32_PRED_CMD
        (0x79, 0x1),         // MSR_IA32_UCODE_WRITE
        (0x8b, 0x1),         // MSR_IA32_UCODE_REV
        (0x9e, 0x1),         // MSR_IA32_SMBASE
        (0xcd, 0x1),         // MSR_FSB_FREQ
        (0xce, 0x1),         // MSR_PLATFORM_INFO
        (0xe2, 0x1),         // MSR_PKG_CST_CONFIG_CONTROL
        (0xe7, 0x1),         // MSR_IA32_MPERF
        (0xe8, 0x1),         // MSR_IA32_APERF
        (0xfe, 0x1),         // MSR_MTRRcap
        (0x11e, 0x1),        // MSR_IA32_BBL_CR_CTL3
        (0x174, 0x1),        // MSR_IA32_SYSENTER_CS
        (0x175, 0x1),        // MSR_IA32_SYSENTER_ESP
        (0x176, 0x1),        // MSR_IA32_SYSENTER_EIP
        (0x179, 0x1),        // MSR_IA32_MCG_CAP
        (0x17a, 0x1),        // MSR_IA32_MCG_STATUS
        (0x17b, 0x1),        // MSR_IA32_MCG_CTL
        (0x198, 0x1),        // MSR_IA32_PERF_STATUS
        (0x1a0, 0x1),        // MSR_IA32_MISC_ENABLE
        (0x1a4, 0x1),        // MSR_MISC_FEATURE_CONTROL
        (0x1aa, 0x1),        // MSR_MISC_PWR_MGMT
        (0x1ad, 0x1),        // MSR_TURBO_RATIO_LIMIT
        (0x1ae, 0x1),        // MSR_TURBO_RATIO_LIMIT1
        (0x1d9, 0x1),        // MSR_IA32_DEBUGCTLMSR
        (0x1db, 0x1),        // MSR_IA32_LASTBRANCHFROMIP
        (0x1dc, 0x1),        // MSR_IA32_LASTBRANCHTOIP
        (0x1dd, 0x1),        // MSR_IA32_LASTINTFROMIP
        (0x1de, 0x1),        // MSR_IA32_LASTINTTOIP
        (0x1fc, 0x1),        // MSR_IA32_POWER_CTL
        (0x200, 0x100),      // 0x200
        (0x3fc, 0x3),        // MSR_CORE_C3_RESIDENCY
        (0x400, 0x80),       // MSR_IA32_MC0_CTL
        (0x606, 0x1),        // MSR_RAPL_POWER_UNIT
        (0x60a, 0x3),        // MSR_PKGC3_IRTL
        (0x610, 0x1),        // MSR_PKG_POWER_LIMIT
        (0x611, 0x1),        // MSR_PKG_ENERGY_STATUS
        (0x613, 0x1),        // MSR_PKG_PERF_STATUS
        (0x614, 0x1),        // MSR_PKG_POWER_INFO
        (0x618, 0x1),        // MSR_DRAM_POWER_LIMIT
        (0x619, 0x1),        // MSR_DRAM_ENERGY_STATUS
        (0x61b, 0x1),        // MSR_DRAM_PERF_STATUS
        (0x61c, 0x1),        // MSR_DRAM_POWER_INFO
        (0x648, 0x1),        // MSR_CONFIG_TDP_NOMINAL
        (0x649, 0x1),        // MSR_CONFIG_TDP_LEVEL_1
        (0x64a, 0x1),        // MSR_CONFIG_TDP_LEVEL_2
        (0x64b, 0x1),        // MSR_CONFIG_TDP_CONTROL
        (0x64c, 0x1),        // MSR_TURBO_ACTIVATION_RATIO
        (0x6e0, 0x1),        // MSR_IA32_TSC_DEADLINE
        (0x800, 0x400),      // APIC_BASE_MSR
        (0xc0000080, 0x1),   // MSR_EFER
        (0xc0000081, 0x1),   // MSR_STAR
        (0xc0000082, 0x1),   // MSR_LSTAR
        (0xc0000083, 0x1),   // MSR_CSTAR
        (0xc0000084, 0x1),   // MSR_SYSCALL_MASK
        (0xc0000100, 0x1),   // MSR_FS_BASE
        (0xc0000101, 0x1),   // MSR_GS_BASE
        (0xc0000102, 0x1),   // MSR_KERNEL_GS_BASE
        (0xc0000103, 0x1),   // MSR_TSC_AUX
        (0x140, 0x1),        // MSR_MISC_FEATURES_ENABLES
        (0xc0010015, 0x1),   // MSR_K7_HWCR
        (0x122, 0x1),        // MSR_IA32_TSX_CTRL
        (0xda0, 0x1),        // MSR_IA32_XSS
        (0x4b564d00, 0x100), // MSR_KVM_RANGE_START
    ];
    index != 0x17b && RANGES.iter().any(|&(base, count)| index >= base && index - base < count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Compat {
        let entries = [
            [0, 0, 0xd, 0x6874_7541, 0x444d_4163, 0x6974_6e65],
            [1, 0, 0x0087_0f10, 0x1320_0800, 0xf7f8_3203, 0x078b_fbff],
            [7, 0, 0, 0x219c_01ab, 0x0040_0004, 0xa800_0000],
            [0x8000_0007, 0, 0, 0, 0, 1 << 8],
            [0xd, 2, 0x100, 0x240, 0, 0],
        ];
        let mut h = Compat::of_cpuid(&entries, "Firecracker v1.17.0 (content a)".into()).unwrap();
        h.tsc_khz = 2_000_000;
        h.msrs = [0x10, 0x122, 0xda0].into();
        h
    }

    fn host_key(root: &Path) -> HostKey {
        let m = std::fs::metadata(root).unwrap();
        let stamp = Stamp::of(&m);
        HostKey { boot_id: "boot-a".into(), flexvm: stamp.clone(), firecracker: stamp, kvm: node(&m), modules: [Some(node(&m)), None, None] }
    }

    /// How many times `host_compat` probed the host (as `host()`) for `key`.
    fn probes(root: &Path, key: &HostKey) -> usize {
        let calls = std::cell::Cell::new(0);
        let compat = host_compat(Some(root), Some(key), || {
            calls.set(calls.get() + 1);
            Ok(host())
        });
        assert_eq!(compat.unwrap(), host());
        calls.get()
    }

    #[test]
    fn host_cache_miss_probes_and_hit_skips_probe() {
        let root = crate::test_util::TempDir::new("host-compat");
        let key = host_key(&root);
        let expected = host();
        assert_eq!(host_compat(Some(&root), Some(&key), || Ok(expected.clone())).unwrap(), expected);
        assert!(root.join("compat.json").is_file());
        assert_eq!(host_compat(Some(&root), Some(&key), || panic!("cache hit must not probe KVM")).unwrap(), expected);
        // A missing run directory or unverifiable host identity must still work.
        assert_eq!(host_compat(None, Some(&key), || Ok(expected.clone())).unwrap(), expected);
        let mut changed = expected.clone();
        changed.tsc_khz += 1;
        assert_eq!(host_compat(Some(&root), None, || Ok(changed.clone())).unwrap(), changed);
        assert_eq!(host_compat(Some(&root), Some(&key), || panic!("missing identity must not overwrite cache")).unwrap(), expected);
    }

    #[test]
    fn host_cache_invalidates_each_host_identity() {
        let root = crate::test_util::TempDir::new("host-compat-key");
        let key = host_key(&root);
        // A different inode provides a distinct stamp without relying on clock resolution.
        let replacement = root.join("replacement");
        std::fs::write(&replacement, b"replacement").unwrap();
        let m = std::fs::metadata(replacement).unwrap();
        let (stamp, inode) = (Stamp::of(&m), node(&m));
        let mut keys = vec![key.clone(); 8];
        keys[0].boot_id = "boot-b".into();
        keys[1].firecracker = stamp.clone();
        keys[2].kvm = inode;
        keys[3].modules[0] = Some(inode);
        keys[4].modules[1] = Some(inode);
        keys[5].modules[2] = Some(inode);
        keys[6].modules[0] = None;
        keys[7].flexvm = stamp;
        for changed in keys {
            host_compat(Some(&root), Some(&key), || Ok(host())).unwrap();
            assert_eq!(probes(&root, &changed), 1, "{changed:?}");
            host_compat(Some(&root), Some(&changed), || panic!("replacement must be cached")).unwrap();
        }
    }

    #[test]
    fn a_ctime_change_alone_keeps_the_node_identity() {
        let root = crate::test_util::TempDir::new("host-compat-ctime");
        let before = node(&std::fs::metadata(&root).unwrap());
        // chmod changes the ctime, not the device or inode.
        std::fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        assert_eq!(node(&std::fs::metadata(&root).unwrap()), before);
    }

    #[test]
    fn host_cache_reprobes_corrupt_and_incomplete_entries() {
        let root = crate::test_util::TempDir::new("host-compat-invalid");
        let key = host_key(&root);
        let cached = HostCache { key: key.clone(), compat: host() };
        let valid = serde_json::to_value(&cached).unwrap();
        let mut invalid = vec![b"broken".to_vec(), b"{}".to_vec()];
        for field in ["tsc_khz", "tsc_control", "msrs", "features", "xsave", "cpu", "firecracker"] {
            let mut value = valid.clone();
            value["compat"].as_object_mut().unwrap().remove(field);
            invalid.push(serde_json::to_vec(&value).unwrap());
        }
        for bytes in invalid {
            std::fs::write(root.join("compat.json"), bytes).unwrap();
            assert_eq!(probes(&root, &key), 1);
            host_compat(Some(&root), Some(&key), || panic!("repaired cache must hit")).unwrap();
        }
        std::fs::remove_file(root.join("compat.json")).unwrap();
        assert!(host_compat(Some(&root), Some(&key), || bail!("probe failed")).is_err());
        assert!(!root.join("compat.json").exists());
        std::fs::create_dir(root.join("compat.json")).unwrap();
        assert_eq!(host_compat(Some(&root), Some(&key), || Ok(host())).unwrap(), host());
    }

    #[test]
    fn tsc_tolerance_and_target_scaling() {
        let snapshot = host();
        for delta in [-501, -500, 0, 500, 501] {
            let mut target = snapshot.clone();
            target.tsc_khz = (i64::from(snapshot.tsc_khz) + delta) as u32;
            assert_eq!(snapshot.check(&target).is_ok(), delta.abs() <= 500);
            target.tsc_control = true;
            snapshot.check(&target).unwrap();
        }
        let mut source_with_scaling = snapshot.clone();
        source_with_scaling.tsc_control = true;
        let mut target = snapshot.clone();
        target.tsc_khz = 2_300_000;
        let error = source_with_scaling.check(&target).unwrap_err().to_string();
        assert!(error.contains("TSC rate differs"), "{error}");
        assert!(error.contains("2000000") && error.contains("2300000"), "{error}");
        target.tsc_control = true;
        source_with_scaling.check(&target).unwrap();
        target.tsc_khz = 0;
        assert!(snapshot.check(&target).unwrap_err().to_string().contains("missing TSC rate"));
        // Large rates must not overflow the ppm calculation.
        let mut large = snapshot.clone();
        large.tsc_khz = u32::MAX;
        large.check(&large).unwrap();
    }

    #[test]
    fn later_snapshot_uses_effective_rate_instead_of_template_rate() {
        let template = host();
        let mut source = template.clone();
        source.tsc_khz = 1_999_600;
        let mut target = template.clone();
        target.tsc_khz = 2_000_400;
        template.check(&source).unwrap();
        template.check(&target).unwrap();
        let saved = template.check_saved(&source, template.tsc_khz, &template.msrs).unwrap();
        assert_eq!(saved, 1_999_600);
        let error = template.check_saved(&target, saved, &source.msrs).unwrap_err().to_string();
        assert!(error.contains("1999600") && error.contains("2000400"), "{error}");
        for delta in [-500, -499, 499, 500] {
            target.tsc_khz = (i64::from(saved) + delta) as u32;
            assert_eq!(template.check_saved(&target, saved, &source.msrs).is_ok(), delta.abs() <= 499);
        }
        target.tsc_khz = 2_000_400;
        target.tsc_control = true;
        template.check_saved(&target, saved, &source.msrs).unwrap();
        assert_eq!(template.check_saved(&target, saved, &source.msrs).unwrap(), saved);
        target.tsc_control = false;
        target.tsc_khz = 1_999_101;
        assert!(template.check(&target).is_err());
        template.check_saved(&target, saved, &source.msrs).unwrap();
    }

    #[test]
    fn effective_rate_follows_scaling_rule_at_each_restore() {
        let mut target = host();
        for delta in [-501, -500, 0, 500, 501] {
            target.tsc_khz = (2_000_000i64 + delta) as u32;
            target.tsc_control = false;
            assert_eq!(check_tsc(2_000_000, &target).is_ok(), delta.abs() <= 500);
            target.tsc_control = true;
            let want = if delta.abs() <= 500 { target.tsc_khz } else { 2_000_000 };
            assert_eq!(target.check_saved(&target, 2_000_000, &target.msrs).unwrap(), want);
        }
        assert!(check_tsc(0, &target).is_err());
        target.tsc_khz = 0;
        assert!(check_tsc(2_000_000, &target).is_err());
    }

    #[test]
    fn invariant_tsc_is_required_only_when_snapshot_exposes_it() {
        let snapshot = host();
        let mut target = snapshot.clone();
        target.features.insert("0x80000007.0.edx".into(), 0);
        let error = snapshot.check(&target).unwrap_err().to_string();
        assert!(error.contains("CPUID 0x80000007.0.edx 0x100"), "{error}");
        target.check(&snapshot).unwrap();
        target.features.remove("0x80000007.0.edx");
        assert!(snapshot.check(&target).is_err());
    }

    #[test]
    fn saved_msrs_must_be_a_subset_and_errors_name_all_missing_indices() {
        let snapshot = host();
        let mut target = snapshot.clone();
        target.msrs.insert(0x3b);
        snapshot.check(&target).unwrap();
        target.msrs.remove(&0x122);
        target.msrs.remove(&0xda0);
        let error = snapshot.check(&target).unwrap_err().to_string();
        assert!(error.contains("saved MSRs 0x122, 0xda0"), "{error}");
        // A source host with more than the template: what it saves is checked on its own.
        let source: BTreeSet<u32> = [0x10, 0x3b].into();
        check_msrs(&source, &snapshot.msrs).unwrap_err();
        check_msrs(&source, &target.msrs).unwrap();
    }

    #[test]
    fn save_filter_matches_firecracker_ranges_and_exclusions() {
        for index in [0x10, 0x122, 0xda0, 0x200, 0x2ff, 0x400, 0x47f, 0x800, 0xbff, 0x4b564dff] {
            assert!(msr_should_serialize(index), "{index:#x}");
        }
        for index in [0x17b, 0xc1, 0x300, 0x480, 0xc00, 0x4b564e00, u32::MAX] {
            assert!(!msr_should_serialize(index), "{index:#x}");
        }
    }

    #[test]
    fn firecracker_cache_hits_and_invalidates_on_stamp_changes() {
        use std::os::unix::fs::PermissionsExt;

        let root = crate::test_util::TempDir::new("compat");
        let binary = root.join("firecracker");
        let calls = root.join("firecracker.calls");
        let write = |version| {
            let temp = root.join("firecracker.tmp");
            std::fs::write(&temp, format!("#!/bin/sh\necho {version}\necho called >> \"$0.calls\"\n")).unwrap();
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o700)).unwrap();
            // Publish the executable only after closing its write descriptor.
            std::fs::rename(&temp, &binary).unwrap();
        };
        write("v1");
        let first = firecracker_id(&binary, Some(&root)).unwrap();
        assert!(first.1.starts_with("v1 (content "));
        assert_eq!(firecracker_id(&binary, Some(&root)).unwrap(), first);
        assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 1);
        // A replacement inode invalidates the cache even with identical bytes.
        std::fs::rename(&binary, root.join("old")).unwrap();
        write("v1");
        let replaced = firecracker_id(&binary, Some(&root)).unwrap();
        assert_ne!(replaced.0, first.0);
        assert_eq!(replaced.1, first.1);
        write("v2-longer");
        let changed = firecracker_id(&binary, Some(&root)).unwrap();
        assert_ne!(changed.0, replaced.0);
        assert!(changed.1.starts_with("v2-longer (content "));
        assert_eq!(firecracker_id(&binary, Some(&root)).unwrap(), changed);
        assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 3);
        std::fs::write(root.join("firecracker.json"), b"broken").unwrap();
        assert_eq!(firecracker_id(&binary, Some(&root)).unwrap(), changed);
        std::fs::remove_file(root.join("firecracker.json")).unwrap();
        std::fs::create_dir(root.join("firecracker.json")).unwrap();
        assert_eq!(firecracker_id(&binary, Some(&root)).unwrap(), changed);
        assert_eq!(std::fs::read_to_string(calls).unwrap().lines().count(), 5);
    }

    #[test]
    fn decodes_cpu_and_words() {
        let h = host();
        assert_eq!(h.cpu, "AuthenticAMD family 0x17 model 0x71");
        assert_eq!(h.features["0x7.0.ebx"], 0x219c_01ab);
        assert!(!h.features.contains_key("0x7.1.eax"));
        assert_eq!(h.xsave[&2], [0x100, 0x240]);
        assert_eq!(serde_json::from_slice::<Compat>(&serde_json::to_vec(&h).unwrap()).unwrap(), h);
    }

    #[test]
    fn accepts_same_host_and_extra_features() {
        let snapshot = host();
        snapshot.check(&snapshot).unwrap();
        let mut more = snapshot.clone();
        *more.features.get_mut("0x7.0.ebx").unwrap() |= 1 << 31;
        more.features.insert("0x7.1.eax".into(), 0x10);
        more.xsave.insert(9, [8, 0xa80]);
        snapshot.check(&more).unwrap();
        assert!(more.check(&snapshot).is_err());
    }

    #[test]
    fn rejects_each_mismatch_with_its_name() {
        let snapshot = host();
        type Change = fn(&mut Compat);
        let cases: [(Change, &str); 5] = [
            (|h| h.cpu = "GenuineIntel family 0x6 model 0x55".into(), "CPU differs"),
            (|h| h.firecracker = "Firecracker v1.18.0 (content a)".into(), "Firecracker differs"),
            (|h| *h.features.get_mut("0x1.0.ecx").unwrap() &= !1, "CPUID 0x1.0.ecx 0x1 "),
            (
                |h| {
                    h.features.remove("0x7.0.ebx");
                },
                "CPUID 0x7.0.ebx 0x219c01ab",
            ),
            (
                |h| {
                    h.xsave.insert(2, [0x100, 0x400]);
                },
                "XSAVE component 2",
            ),
        ];
        for (change, expected) in cases {
            let mut h = snapshot.clone();
            change(&mut h);
            let e = snapshot.check(&h).unwrap_err().to_string();
            assert!(e.contains(expected), "{e}");
        }
    }
}
