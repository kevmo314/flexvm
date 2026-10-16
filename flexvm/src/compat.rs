//! Snapshot compatibility preflight. A template records its build host's CPU model, the
//! features KVM offered (passed through: no CPU template), XSAVE layout, TSC rate,
//! saved MSR set and Firecracker;
//! checkpoints and migrations pin their template, so this covers them too. Topology, cache
//! and leaf-limit words are not compared: Firecracker rewrites the first, the rest do not
//! change what the guest can run.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::template::{hash_file, Stamp, Template};
use crate::{bail, util::Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Compat {
    pub cpu: String,
    /// Default vCPU TSC rate, inherited by snapshots from this template.
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
        let hints = ["every host needs the same CPU model", "copy one Firecracker binary to every host; templates built with another must be rebuilt"];
        for ((what, snapshot, here), hint) in [("CPU", &self.cpu, &host.cpu), ("Firecracker", &self.firecracker, &host.firecracker)].into_iter().zip(hints) {
            if snapshot != here {
                bail!("snapshot incompatible with this host: {what} differs (snapshot: {snapshot}; host: {here}): {hint}");
            }
        }
        if self.tsc_khz == 0 || host.tsc_khz == 0 {
            bail!("snapshot incompatible with this host: missing TSC rate; rebuild the template");
        }
        // Match Firecracker's is_tsc_scaling_required: tolerance is relative to the snapshot.
        let tolerance = u64::from(self.tsc_khz) * 250 / 1_000_000;
        if u64::from(self.tsc_khz.abs_diff(host.tsc_khz)) > tolerance && !host.tsc_control {
            bail!(
                "snapshot incompatible with this host: TSC rate differs (snapshot: {} kHz; host: {} kHz), beyond 250 ppm and target lacks KVM TSC scaling",
                self.tsc_khz,
                host.tsc_khz
            );
        }
        check_msrs(&self.msrs, &host.msrs)?;
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
        Ok(())
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

/// Cached while the Firecracker binary is unchanged.
pub fn local(pid: u32) -> Result<Compat> {
    static CACHE: Mutex<Option<(Stamp, Compat)>> = Mutex::new(None);
    let firecracker = PathBuf::from(format!("/proc/{pid}/exe"));
    let stamp = Stamp::of(&std::fs::metadata(&firecracker)?);
    let mut cache = CACHE.lock().unwrap();
    if let Some((_, c)) = cache.as_ref().filter(|(s, _)| *s == stamp) {
        return Ok(c.clone());
    }
    let (stamp, binary) = firecracker_id(&firecracker, crate::host::run_dir())?;
    let kvm = File::open("/dev/kvm").map_err(|e| format!("/dev/kvm: {e}"))?;
    let mut compat = Compat::of_cpuid(&supported_cpuid(&kvm)?, binary)?;
    compat.tsc_khz = tsc_khz(&kvm)?;
    compat.tsc_control = ioctl(&kvm, 0xae03, 60, "KVM_CHECK_EXTENSION(TSC_CONTROL)")? > 0;
    compat.msrs = saved_msrs(&kvm)?;
    *cache = Some((stamp, compat.clone()));
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
    let version = std::process::Command::new(path).arg("--version").output()?;
    let version = String::from_utf8_lossy(&version.stdout);
    let version = version.lines().next().filter(|v| !v.is_empty()).ok_or("firecracker --version printed nothing")?;
    let binary = hash_file(path)?;
    let cached = (binary.metadata, format!("{version} (content {})", binary.hash));
    if let Some(run) = run {
        let _ = crate::util::write_file(run, "firecracker.json", &serde_json::to_vec(&cached)?, false);
    }
    Ok(cached)
}

pub fn check(template: &Template, pid: u32) -> Result<()> {
    template.meta.compatibility.check(&local(pid)?)
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
    if unsafe { libc::ioctl(kvm.as_raw_fd(), 0xc008_ae05, buf.as_mut_ptr()) } < 0 {
        bail!("KVM_GET_SUPPORTED_CPUID: {}", std::io::Error::last_os_error());
    }
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
    if value < 0 {
        bail!("{name}: {}", std::io::Error::last_os_error());
    }
    Ok(value)
}

fn saved_msrs(kvm: &File) -> Result<BTreeSet<u32>> {
    // KVM reports the required size with E2BIG. Do not silently truncate a future kernel's list.
    let mut buf = vec![0u32; 1];
    let result = unsafe { libc::ioctl(kvm.as_raw_fd(), 0xc004_ae02, buf.as_mut_ptr()) };
    if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::E2BIG) {
        bail!("KVM_GET_MSR_INDEX_LIST: {}", std::io::Error::last_os_error());
    }
    buf.resize(1 + buf[0] as usize, 0);
    if unsafe { libc::ioctl(kvm.as_raw_fd(), 0xc004_ae02, buf.as_mut_ptr()) } < 0 {
        bail!("KVM_GET_MSR_INDEX_LIST: {}", std::io::Error::last_os_error());
    }
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
    fn older_metadata_cannot_silently_skip_new_checks() {
        for field in ["tsc_khz", "tsc_control", "msrs"] {
            let mut value = serde_json::to_value(host()).unwrap();
            value.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Compat>(value).is_err(), "{field}");
        }
    }

    #[test]
    fn firecracker_cache_hits_and_invalidates_on_stamp_changes() {
        use std::os::unix::fs::PermissionsExt;

        let root = crate::test_util::TempDir::new("compat");
        let binary = root.join("firecracker");
        let calls = root.join("firecracker.calls");
        let write = |version| {
            std::fs::write(&binary, format!("#!/bin/sh\necho {version}\necho called >> \"$0.calls\"\n")).unwrap();
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
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
        std::fs::remove_dir_all(root).unwrap();
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
