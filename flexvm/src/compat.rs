//! Snapshot compatibility preflight. A template records its build host's CPU model, the
//! features KVM offered (passed through: no CPU template), XSAVE layout and Firecracker;
//! checkpoints and migrations pin their template, so this covers them too. Topology, cache
//! and leaf-limit words are not compared: Firecracker rewrites the first, the rest do not
//! change what the guest can run.
use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::template::{hash_file, Stamp, Template};
use crate::{bail, util::Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Compat {
    pub cpu: String,
    /// `firecracker --version` and the binary's content hash.
    pub firecracker: String,
    /// By "leaf.subleaf.register".
    pub features: BTreeMap<String, u32>,
    /// Component -> [size, offset].
    pub xsave: BTreeMap<u32, [u32; 2]>,
}

/// CPUID words that are feature bitmaps: (leaf, subleaf, registers).
const FEATURES: [(u32, u32, &[usize]); 10] = [
    (0x1, 0, &[2, 3]),
    (0x7, 0, &[1, 2, 3]),
    (0x7, 1, &[0, 3]),
    (0x7, 2, &[3]),
    (0xd, 0, &[0, 3]),
    (0xd, 1, &[0, 2, 3]),
    (0x4000_0001, 0, &[0]),
    (0x8000_0001, 0, &[2, 3]),
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
    let compat = Compat::of_cpuid(&supported_cpuid()?, binary)?;
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

/// KVM_GET_SUPPORTED_CPUID as [function, index, eax, ebx, ecx, edx].
fn supported_cpuid() -> Result<Vec<[u32; 6]>> {
    const MAX: usize = 256;
    // struct kvm_cpuid2 { u32 nent, padding; struct kvm_cpuid_entry2 entries[] },
    // each entry { function, index, flags, eax, ebx, ecx, edx, padding[3] }.
    let mut buf = vec![0u32; 2 + MAX * 10];
    buf[0] = MAX as u32;
    let kvm = File::open("/dev/kvm").map_err(|e| format!("/dev/kvm: {e}"))?;
    if unsafe { libc::ioctl(kvm.as_raw_fd(), 0xc008_ae05, buf.as_mut_ptr()) } < 0 {
        bail!("KVM_GET_SUPPORTED_CPUID: {}", std::io::Error::last_os_error());
    }
    let n = (buf[0] as usize).min(MAX);
    Ok(buf[2..2 + n * 10].chunks(10).map(|e| [e[0], e[1], e[3], e[4], e[5], e[6]]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Compat {
        let entries = [
            [0, 0, 0xd, 0x6874_7541, 0x444d_4163, 0x6974_6e65],
            [1, 0, 0x0087_0f10, 0x1320_0800, 0xf7f8_3203, 0x078b_fbff],
            [7, 0, 0, 0x219c_01ab, 0x0040_0004, 0xa800_0000],
            [0xd, 2, 0x100, 0x240, 0, 0],
        ];
        Compat::of_cpuid(&entries, "Firecracker v1.17.0 (content a)".into()).unwrap()
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
