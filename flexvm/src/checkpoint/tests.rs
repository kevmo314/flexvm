use super::{
    chain::{flatten, overlay, read_at, read_with_fallback, Link},
    format::{parse_pagemap, sum, Run, DATA, MAGIC, MAX_VMSTATE, TEMPLATE, ZERO},
    staging::STAGING_PREFIX,
    write::{classify, direct, write_pages, Buf, PagesFile},
    *,
};
use crate::{
    cow::Room,
    template::{Paths, Template},
    uffd::{Runs, BASE as P_BASE, REMOTE, ZERO as P_ZERO},
    util::{stat_at, Result, PAGE_SIZE},
};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::FileExt,
    path::Path,
    sync::Arc,
};

fn tmp(name: &str) -> crate::test_util::TempDir {
    crate::test_util::TempDir::new(name)
}

fn manifest(guest_pages: usize, parent: Option<Parent>, files: serde_json::Value) -> Manifest {
    serde_json::from_value(json!({
        "format": if parent.is_some() { FORMAT_INCREMENTAL } else { FORMAT }, "created_unix_ms": 0, "name": "x",
        "ip": "10.0.0.1", "template": "tpl", "template_id": "id", "saved_msrs": [], "saved_tsc_khz": 2000000, "vcpus": 1, "mem_mib": 1, "max_mib": 1,
        "hotplug_mib": 0, "guest_pages": guest_pages, "data_pages": 0, "zero_pages": 0, "parent": parent, "files": files,
    }))
    .unwrap()
}

/// A 256-page checkpoint with nothing stored, its manifest changed by `edit`; returns its id.
fn link(dir: &Path, parent: Option<Parent>, edit: impl FnOnce(&mut Manifest)) -> String {
    fs::create_dir_all(dir).unwrap();
    let map = [MAGIC.as_slice(), &[0; 16]].concat();
    for (name, bytes) in [("vmstate", &b"s"[..]), ("pagemap", &map), ("pages", &[])] {
        fs::write(dir.join(name), bytes).unwrap();
    }
    let files = json!({"vmstate": {"len": 1, "hash": sum(b"s")}, "pagemap": {"len": map.len(), "hash": sum(&map)}, "pages": {"len": 0}});
    let mut m = manifest(256, parent, files);
    edit(&mut m);
    let body = serde_json::to_vec(&m).unwrap();
    fs::write(dir.join("manifest.json"), [format!("{}\n", sum(&body)).as_bytes(), &body].concat()).unwrap();
    sum(&body)
}

/// `dir/ck0` and `n - 1` deltas over it, each `ck{i}` over `ck{i-1}`; returns their ids, newest first.
fn chain(dir: &Path, n: usize) -> Vec<String> {
    let (mut parent, mut ids) = (None, Vec::new());
    for i in 0..n {
        let id = link(&dir.join(format!("ck{i}")), parent, |_| {});
        ids.insert(0, id.clone());
        parent = Some(Parent { path: format!("../ck{i}").into(), id });
    }
    ids
}

#[test]
fn saved_host_msrs_survive_manifest_roundtrip_and_are_checked() {
    let dir = tmp("saved-msrs");
    let tpl = template(&dir, &[None; 256]);
    let mut host = tpl.meta.compatibility.clone();
    // Template host A has only TSC; host B added TSX_CTRL and XSS before saving.
    let a: std::collections::BTreeSet<u32> = [0x10].into();
    host.msrs = a.clone();
    let b = [0x10, 0x122, 0xda0].into();
    link(&dir, None, |m| m.saved_msrs = b);
    let ck = Checkpoint::open(&dir).unwrap();
    let error = ck.manifest.check_compatibility(&tpl, &host).unwrap_err().to_string();
    assert!(error.contains("saved MSRs 0x122, 0xda0"), "{error}");
    host.msrs = [0x10, 0x122, 0xda0, 0x3b].into();
    ck.manifest.check_compatibility(&tpl, &host).unwrap();

    // Only the newest VM state is loaded; ancestor manifests supply memory only.
    let child = dir.join("child");
    link(&child, Some(Parent { path: dir.to_path_buf(), id: ck.id }), |m| m.saved_msrs = a.clone());
    host.msrs = a;
    Checkpoint::open(&child).unwrap().manifest.check_compatibility(&tpl, &host).unwrap();
}

#[test]
fn saved_tsc_survives_roundtrip_and_checks_only_newest_vmstate() {
    let dir = tmp("saved-tsc");
    let tpl = template(&dir, &[None; 256]);
    let mut host = tpl.meta.compatibility.clone();
    host.tsc_khz = 2_000_400;
    tpl.meta.compatibility.check(&host).unwrap();
    link(&dir.join("ck"), None, |m| m.saved_tsc_khz = 1_999_600);
    let ck = Checkpoint::open(&dir.join("ck")).unwrap();
    assert_eq!(ck.manifest.saved_tsc_khz, 1_999_600);
    assert!(ck.manifest.check_compatibility(&tpl, &host).unwrap_err().to_string().contains("TSC rate differs"));
    host.tsc_control = true;
    assert_eq!(ck.manifest.check_compatibility(&tpl, &host).unwrap(), 1_999_600);
    host.tsc_control = false;
    let child = dir.join("child");
    link(&child, Some(Parent { path: dir.join("ck"), id: ck.id }), |m| m.saved_tsc_khz = host.tsc_khz);
    Checkpoint::open(&child).unwrap().manifest.check_compatibility(&tpl, &host).unwrap();
}

#[test]
fn zero_saved_tsc_rate_cannot_be_restored() {
    let dir = tmp("zero-saved-tsc");
    let tpl = template(&dir, &[None; 256]);
    link(&dir, None, |m| m.saved_tsc_khz = 0);
    let ck = Checkpoint::open(&dir).unwrap();
    let error = ck.manifest.check_compatibility(&tpl, &tpl.meta.compatibility).unwrap_err().to_string();
    assert!(error.contains("checkpoint or suspended VM") && error.contains("TSC rate") && error.contains("cannot be restored"), "{error}");
}

#[test]
fn manifest_covers_pagemap_without_a_pages_hash() {
    let dir = tmp("map-integrity");
    link(&dir, None, |_| {});
    let ck = Checkpoint::open(&dir).unwrap();
    let manifest = serde_json::to_value(&ck.manifest).unwrap();
    assert!(manifest["files"]["pages"].get("hash").is_none());
    assert_eq!(manifest["files"]["pagemap"]["hash"], sum(&fs::read(dir.join("pagemap")).unwrap()));
    let mut map = fs::read(dir.join("pagemap")).unwrap();
    *map.last_mut().unwrap() ^= 1;
    fs::write(dir.join("pagemap"), map).unwrap();
    assert!(Checkpoint::open(&dir).err().unwrap().to_string().contains("pagemap does not match its checksum"));
}

#[test]
fn metadata_is_bounded_before_reading() {
    let dir = tmp("lengths");
    type Edit = fn(&mut Manifest);
    let cases: [(Edit, &str); 5] = [
        (|m| m.files.get_mut("vmstate").unwrap().len = MAX_VMSTATE + 1, "too long"),
        (|m| m.files.get_mut("vmstate").unwrap().len = u64::MAX, "too long"),
        (|m| m.files.get_mut("pagemap").unwrap().len = 24 + 36 * 256 + 1, "too long"),
        (|m| (m.guest_pages, m.files.get_mut("pagemap").unwrap().len) = (u64::MAX, u64::MAX), "too long"),
        (|m| (m.guest_pages, m.files.get_mut("pagemap").unwrap().len) = (1 << 40, 1 << 40), "bytes of metadata"),
    ];
    for (edit, want) in cases {
        link(&dir.join("bad"), None, edit);
        let e = Checkpoint::open(&dir.join("bad")).err().unwrap().to_string();
        assert!(e.contains(want), "{e}");
    }
    // A chain reads at most its budget: the base is refused once it runs out.
    let ids = chain(&dir, 3);
    let top = dir.join("ck2");
    let ck = Checkpoint::open(&top).unwrap();
    assert_eq!((ck.chain.len(), &ck.chain_ids[..], chain_ids(&top).unwrap()), (2, &ids[1..], ids.clone()));
    let cost = chain_meta_budget() - ck.meta_left;
    Link::open(&top, 0, Some(&mut { cost })).unwrap();
    let mut left = cost - 1;
    let e = (0..3).rev().try_for_each(|i| Link::open(&dir.join(format!("ck{i}")), 0, Some(&mut left)).map(drop));
    assert!(e.err().unwrap().to_string().contains("bytes of metadata"));
}

fn template(dir: &Path, pages: &[Option<u8>]) -> Arc<Template> {
    let tdir = dir.join(".gen/a");
    fs::create_dir_all(&tdir).unwrap();
    std::os::unix::fs::symlink(".gen/a", dir.join("tpl")).unwrap();
    let meta = json!({
        "compatibility": {"cpu": "test", "tsc_khz": 2000000, "tsc_control": false, "msrs": [], "firecracker": "test", "features": {}, "xsave": {}},
        "vcpus": 1, "mem_mib": 1, "max_mib": 1, "plugged_mib": 0,
        "kernel": "/k", "rootfs": "/r", "id": "a", "components": {}
    });
    fs::write(tdir.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
    let mem = File::create(tdir.join("mem")).unwrap();
    mem.set_len((pages.len() * PAGE_SIZE) as u64).unwrap();
    for (i, b) in pages.iter().enumerate().filter_map(|(i, p)| Some((i, (*p)?))) {
        mem.write_all_at(&[b; PAGE_SIZE], (i * PAGE_SIZE) as u64).unwrap();
    }
    let paths = Paths { firecracker: "/f".into(), kernel: "/k".into(), templates: dir.into(), images: dir.join("images") };
    Template::open(&paths, "tpl").unwrap()
}

fn page(seed: usize) -> Vec<u8> {
    (0..PAGE_SIZE).map(|i| (i * 31 + seed * 7 + 1) as u8).collect()
}

fn pages_file(path: &Path) -> PagesFile {
    let dir = File::open(path.parent().unwrap()).unwrap();
    PagesFile::new(create_at(dir.as_raw_fd(), path.file_name().unwrap().to_str().unwrap()).unwrap())
}

/// Guest memory: pages, in regions of `.1` pages; reading page `.2` fails.
struct Guest(Vec<Vec<u8>>, usize, Option<usize>);

impl GuestPages for Guest {
    fn region_end(&self, page: usize) -> Option<usize> {
        (page < self.0.len()).then(|| ((page / self.1 + 1) * self.1).min(self.0.len()))
    }

    fn read(&self, page: usize, buf: &mut [u8]) -> Result<()> {
        for (i, b) in buf.chunks_mut(PAGE_SIZE).enumerate() {
            if Some(page + i) == self.2 {
                bail!("cannot read page {}", page + i);
            }
            b.copy_from_slice(&self.0[page + i]);
        }
        Ok(())
    }
}

fn runs_of(ps: impl IntoIterator<Item = (usize, u8)>) -> Runs {
    let mut out: Runs = Vec::new();
    for (p, s) in ps {
        match out.last_mut() {
            Some((f, n, st)) if *st == s && *f + *n == p as u64 => *n += 1,
            _ => out.push((p as u64, 1, s)),
        }
    }
    out
}

fn restore(tpl: &Template, n: usize, runs: &Runs, file: &PageFile) -> Vec<(u8, Vec<u8>)> {
    let mut state = vec![P_BASE; n];
    runs.iter().for_each(|&(f, c, s)| state[f as usize..(f + c) as usize].fill(s));
    let mut b = vec![0; PAGE_SIZE];
    let mut read = |i: usize, st: u8| match st {
        P_BASE if tpl.has_data(i) => tpl.pages(i, 1).to_vec(),
        P_BASE | P_ZERO => vec![0; PAGE_SIZE],
        _ => file.read(i, &mut b, false).map(|()| b.clone()).unwrap(),
    };
    state.into_iter().enumerate().map(|(i, st)| (st, read(i, st))).collect()
}

#[test]
fn pages_roundtrip_against_the_template() {
    let dir = tmp("ckpt");
    let n = 1000;
    let tpl_pages: Vec<Option<u8>> = (0..n).map(|i| (i % 2 == 0).then_some(i as u8 | 1)).collect();
    let tpl = template(&dir, &tpl_pages);
    let zero = || vec![0; PAGE_SIZE];
    let pages: Vec<Vec<u8>> =
        (0..n).map(|i| [tpl_pages[i].map_or(zero(), |b| vec![b; PAGE_SIZE]), zero()].get(i % 5).cloned().unwrap_or_else(|| page(i))).collect();
    // Pages 7 and 300..320 were discarded by the guest; 900.. were never touched.
    let discarded = |i: usize| i == 7 || (300..320).contains(&i);
    let input = runs_of((0..n).map(|i| {
        (
            i,
            if i >= 900 {
                P_BASE
            } else if discarded(i) {
                P_ZERO
            } else {
                REMOTE
            },
        )
    }));
    let want = |i: usize| {
        if discarded(i) {
            zero()
        } else if i < 900 {
            pages[i].clone()
        } else {
            tpl.pages(i, 1).to_vec()
        }
    };
    let guest = Guest(pages.clone(), 333, None);
    let want_data = (0..900).filter(|&i| i % 5 >= 2 && !discarded(i)).count() as u64;
    let want_zero = (0..900).filter(|&i| i % 2 == 0 && (i % 5 == 1 || discarded(i))).count() as u64;
    let mut last = None;
    // Room for every writer's huge-page buffer, for one of them (2 MiB) only, and for none:
    // the others write through ordinary buffers, the same pages.
    for (threads, room_mib, left) in [(8, u64::MAX, u64::MAX), (3, 3, 1), (1, 0, 0)] {
        let path = dir.join(format!("pages-{threads}"));
        let room = Room::default();
        room.set(room_mib);
        let w = write_pages(&tpl, &guest, &input, &pages_file(&path), threads, false, &room).unwrap();
        assert_eq!(room.get(), left, "{threads} writers");
        assert_eq!((w.data, w.zero, fs::metadata(&path).unwrap().len()), (want_data, want_zero, w.data * PAGE_SIZE as u64));
        let (map, sums) = parse_pagemap(&w.map, n as u64, false, 0).unwrap();
        // Runs past the guest's end, a truncated map, and a DATA run pointing anywhere but its place.
        let mut bad = w.map.clone();
        let r = (0..map.len()).find(|&r| bad[24 + 32 * r + 16] == DATA as u8).unwrap();
        bad[24 + 32 * r + 24] ^= 1;
        for (map, pages) in [(&w.map[..], 899), (&w.map[..w.map.len() - 4], n as u64), (&bad[..], n as u64)] {
            assert!(parse_pagemap(map, pages, false, 0).is_err());
        }
        let (runs, file) = flatten(&[map], vec![File::open(&path).unwrap()], vec![sums]);
        let got = restore(&tpl, n, &runs, &file);
        for (i, (st, page)) in got.iter().enumerate() {
            assert!(*page == want(i), "page {i} (state {st}, {threads} threads)");
        }
        last = Some((runs, got, file, path));
    }
    let (runs, got, file, path) = last.unwrap();
    let (f, c, _) = runs.iter().copied().filter(|r| r.2 == REMOTE).max_by_key(|r| r.1).unwrap();
    let mut b = vec![0; c as usize * PAGE_SIZE];
    file.read(f as usize, &mut b, true).unwrap();
    assert_eq!(&b[(c as usize - 1) * PAGE_SIZE..], &want((f + c) as usize - 1)[..]);
    // Pages that are not stored, and exactly the corrupt page, are InvalidData.
    let mut one = zero();
    assert_eq!(file.read(0, &mut one, false).unwrap_err().kind(), io::ErrorKind::InvalidData);
    fs::OpenOptions::new().write(true).open(&path).unwrap().write_all_at(&[0xff], (5 * PAGE_SIZE + 5) as u64).unwrap();
    let bad: Vec<_> = (0..n).filter_map(|i| (got[i].0 == REMOTE).then(|| file.read(i, &mut one, false).err()).flatten()).collect();
    assert_eq!(bad.iter().map(|e| e.kind()).collect::<Vec<_>>(), [io::ErrorKind::InvalidData]);
    // A failed read fails the whole write instead of hanging the other writers.
    assert!(write_pages(&tpl, &Guest(pages, 333, Some(500)), &input, &pages_file(&dir.join("pages-fail")), 4, false, &Room::default()).is_err());
}

#[test]
fn deltas_flatten_over_their_parents() {
    let dir = tmp("delta");
    let n = 300;
    let tpl_pages: Vec<Option<u8>> = (0..n).map(|i| (i % 3 == 0).then_some(i as u8 | 1)).collect();
    let tpl = template(&dir, &tpl_pages);
    let tpl_page = |i: usize| tpl_pages[i].map_or(vec![0; PAGE_SIZE], |b| vec![b; PAGE_SIZE]);
    let v1: Vec<Vec<u8>> = (0..n).map(|i| if i < 200 { page(i) } else { tpl_page(i) }).collect();
    let w1 =
        write_pages(&tpl, &Guest(v1.clone(), 128, None), &runs_of((0..200).map(|i| (i, REMOTE))), &pages_file(&dir.join("p1")), 3, false, &Room::default())
            .unwrap();
    // Generation 2: new data, back to the template's, zero, discarded, and populated since (BASE before).
    let (mut v2, mut dirty) = (v1, Vec::new());
    type Change<'a> = (&'a [usize], u8, &'a dyn Fn(usize) -> Vec<u8>);
    let changes: [Change; 5] = [
        (&[5, 6, 7, 50, 199, 251], REMOTE, &|i| page(i + 1000)),
        (&[9, 10], REMOTE, &tpl_page),
        (&[20], REMOTE, &|_| vec![0; PAGE_SIZE]),
        (&[30, 31, 32, 33], P_ZERO, &|_| vec![0; PAGE_SIZE]),
        (&[250, 260, 261, 262, 263, 264, 265], P_BASE, &tpl_page),
    ];
    for (pages, state, bytes) in changes {
        for &i in pages {
            v2[i] = bytes(i);
            dirty.push((i, state));
        }
    }
    dirty.sort();
    let w2 = write_pages(&tpl, &Guest(v2.clone(), 128, None), &runs_of(dirty), &pages_file(&dir.join("p2")), 2, true, &Room::default()).unwrap();
    assert_eq!(w2.data, 6, "only the changed data pages are stored");
    let (m1, s1) = parse_pagemap(&w1.map, n as u64, false, 1).unwrap();
    let (m2, s2) = parse_pagemap(&w2.map, n as u64, true, 0).unwrap();
    assert!(parse_pagemap(&w2.map, n as u64, false, 0).is_err(), "TEMPLATE runs only in a delta");
    assert!(m2.contains(&(260, 6, TEMPLATE, 0, 0)));
    let files = vec![File::open(dir.join("p2")).unwrap(), File::open(dir.join("p1")).unwrap()];
    let (runs, file) = flatten(&[m1, m2], files, vec![s2, s1]);
    for (i, (st, page)) in restore(&tpl, n, &runs, &file).into_iter().enumerate() {
        assert!(page == v2[i], "page {i} (state {st})");
    }
    let mut want = Canon::new(&tpl);
    v2.iter().enumerate().for_each(|(i, p)| want.page(i, p));
    let (manifest, file) = (manifest(n, None, json!({})), Arc::new(file));
    let ck =
        Checkpoint { dir: dir.clone(), manifest, id: String::new(), vmstate: Vec::new(), runs, file, chain: Vec::new(), chain_ids: Vec::new(), meta_left: 0 };
    assert_eq!(ck.content_hash(&tpl).unwrap(), want.finish());
    ck.verify_data().unwrap();
}

#[test]
fn overlays_buffers_and_parent_paths() {
    let base: Vec<Run> = vec![(0, 10, DATA, 1, 100), (20, 5, ZERO, 1, 0)];
    let top: Vec<Run> = vec![(2, 2, ZERO, 0, 0), (5, 1, TEMPLATE, 0, 0), (9, 13, DATA, 0, 7)];
    let want = [
        (0, 2, DATA, 1, 100),
        (2, 2, ZERO, 0, 0),
        (4, 1, DATA, 1, 104),
        (5, 1, TEMPLATE, 0, 0),
        (6, 3, DATA, 1, 106),
        (9, 13, DATA, 0, 7),
        (22, 3, ZERO, 1, 0),
    ];
    assert_eq!(overlay(&base, &top), want);
    assert_eq!(parent_path(Path::new("/d/ck2"), Path::new("/d/ck1")), Path::new("../ck1"));
    assert_eq!(parent_path(Path::new("/e/ck2"), Path::new("/d/ck1")), Path::new("/d/ck1"));
    // Writer buffers are aligned and zeroed; one larger than Linux can map fails, even with overcommit.
    let mut buf = Buf::plain(2).unwrap();
    assert_eq!(buf.bytes().as_ptr() as usize % PAGE_SIZE, 0);
    assert!(buf.bytes().len() == 2 * PAGE_SIZE && buf.bytes().iter().all(|&b| b == 0));
    assert_eq!(Buf::plain(isize::MAX as usize / PAGE_SIZE).err().unwrap().kind(), io::ErrorKind::OutOfMemory);
}

#[test]
fn page_sync_and_pagemap_errors_leave_staging_unpublished() {
    let dir = tmp("parallel-sync");
    let dest = dir.join("ck");
    {
        let s = Staging::new(&dest, dir.join("vmstate.private")).unwrap();
        let pages = s.create("pages").unwrap();
        (&pages).write_all(b"pages").unwrap();
        let map = s.sync_pages_and_pagemap(&pages, b"map").unwrap();
        assert_eq!(map.metadata().unwrap().len(), 3);
        assert_eq!(read_at(s.ck.as_raw_fd(), "pagemap", 10).unwrap().1, b"map");
        // O_EXCL failure must still join the pages' fsync.
        assert!(s.sync_pages_and_pagemap(&pages, b"replacement").is_err());
        assert!(stat_at(s.ck.as_raw_fd(), c"manifest.json").is_none());
        assert!(!dest.exists());
    }
    {
        let s = Staging::new(&dest, dir.join("vmstate.private")).unwrap();
        // /dev/null accepts writes but cannot be fsynced: propagate the worker's error.
        let pages = File::options().write(true).open("/dev/null").unwrap();
        assert!(s.sync_pages_and_pagemap(&pages, b"map").is_err());
        assert!(stat_at(s.ck.as_raw_fd(), c"manifest.json").is_none());
        assert!(!dest.exists());
    }
}

#[test]
fn staging_is_private_never_overwrites_and_cleans_up() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    let dir = tmp("stage");
    let dest = dir.join("ck");
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    // Staging left by a process that is gone is cleared if it is private like ours; anything else is left alone.
    let (stale, foreign) = (dir.join(format!("{STAGING_PREFIX}{}-stale", std::process::id())), dir.join(format!("{STAGING_PREFIX}999999998-1")));
    fs::create_dir_all(stale.join("ck")).unwrap();
    fs::write(stale.join("ck/pages"), b"x").unwrap();
    fs::write(stale.join("ck/GEN"), b"generation").unwrap();
    fs::create_dir_all(&foreign).unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755)).unwrap();
    let s = Staging::new(&dest, dir.join("vmstate.private")).unwrap();
    assert!(!stale.exists() && foreign.exists());
    let other = Staging::new(&dir.join("other"), dir.join("other.vmstate")).unwrap();
    drop(other);
    let ours = format!("{STAGING_PREFIX}{}", std::process::id());
    let mine =
        || fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(&ours)).collect::<Vec<_>>();
    assert_eq!(mine().iter().map(|p| mode(p)).collect::<Vec<_>>(), [0o700]);
    drop(s.create("pages").unwrap());
    assert!(s.create("pages").is_err());
    symlink("/etc/hostname", dir.join("link")).unwrap();
    assert!(create_at(s.parent.as_raw_fd(), "link").is_err() && open_at(s.parent.as_raw_fd(), "link").is_err());
    let files: Vec<_> = ["vmstate", "pagemap", "manifest.json"].map(|f| s.create(f).unwrap()).into();
    s.add_file("GEN", b"generation").unwrap();
    let owner = fstat(s.parent.as_raw_fd()).unwrap();
    for m in files.iter().map(|f| f.metadata().unwrap()) {
        assert_eq!((m.permissions().mode() & 0o777, m.uid(), m.gid()), (0o600, owner.st_uid, owner.st_gid));
    }
    assert_eq!(mode(&mine()[0].join("ck")), 0o700);
    drop(s);
    assert!(!dest.exists() && mine().is_empty());
    fs::create_dir_all(&dest).unwrap();
    assert!(Staging::new(&dest, dir.join("vmstate.private")).is_err());
}

/// The page map as built before BASE runs were pushed whole: a page at a time.
fn per_page_map(tpl: &Template, guest: &Guest, runs: &Runs, explicit: bool) -> (Vec<[u64; 4]>, u64, Vec<u32>) {
    let (mut map, mut zero, mut at, mut sums): (Vec<[u64; 4]>, u64, u64, Vec<u32>) = (Vec::new(), 0, 0, Vec::new());
    let mut push = |page: usize, kind: u64, at: u64| {
        let kind = match kind {
            ZERO | DATA => kind,
            _ if explicit => TEMPLATE,
            _ => return,
        };
        zero += (kind == ZERO) as u64;
        match map.last_mut() {
            Some([f, n, k, a]) if *k == kind && *f + *n == page as u64 && (kind != DATA || *a + *n == at) => *n += 1,
            _ => map.push([page as u64, 1, kind, at]),
        }
    };
    for &(first, count, state) in runs {
        for p in (first..first + count).map(|p| p as usize) {
            let (kind, sum) = match state {
                REMOTE => classify(tpl, p, &guest.0[p]),
                P_ZERO if tpl.has_data(p) => (ZERO as u8, 0),
                _ => (P_BASE, 0),
            };
            let kind = kind as u64;
            push(p, kind, if state == REMOTE { at } else { 0 });
            if kind == DATA {
                sums.push(sum);
                at += 1;
            }
        }
    }
    (map, zero, sums)
}

#[test]
fn whole_base_runs_build_the_per_page_map() {
    let dir = tmp("baseruns");
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let n = 700;
    let tpl_pages: Vec<Option<u8>> = (0..n).map(|i| (rand(3) != 0).then_some(i as u8 | 1)).collect();
    let tpl = template(&dir, &tpl_pages);
    let states = [P_BASE, crate::uffd::PRESENT, P_ZERO, REMOTE];
    for round in 0..300 {
        let pages: Vec<Vec<u8>> = (0..n)
            .map(|i| match rand(3) {
                0 => tpl_pages[i].map_or(vec![0; PAGE_SIZE], |b| vec![b; PAGE_SIZE]),
                1 => vec![0; PAGE_SIZE],
                _ => page(i + round),
            })
            .collect();
        let guest = Guest(pages, 1 + rand(300) as usize, None);
        // Random runs, sometimes adjacent with the same state, sometimes with gaps.
        let (mut runs, mut p): (Runs, u64) = (Vec::new(), rand(5));
        while p < n as u64 {
            let long = rand(4) == 0;
            let count = (1 + rand(if long { 200 } else { 8 })).min(n as u64 - p);
            runs.push((p, count, states[rand(4) as usize]));
            let gap = rand(3) == 0;
            p += count + if gap { rand(10) } else { 0 };
        }
        let explicit = round % 2 == 1;
        let w = write_pages(&tpl, &guest, &runs, &pages_file(&dir.join(format!("p{round}"))), 1, explicit, &Room::default()).unwrap();
        let (map, zero, sums) = per_page_map(&tpl, &guest, &runs, explicit);
        let mut want = MAGIC.to_vec();
        let words = [map.len() as u64, w.data].into_iter().chain(map.into_iter().flatten());
        want.extend(words.flat_map(u64::to_le_bytes));
        want.extend(sums.iter().flat_map(|s| s.to_le_bytes()));
        assert!(w.map == want && w.zero == zero, "round {round}: runs {runs:?}");
        fs::remove_file(dir.join(format!("p{round}"))).unwrap();
    }
}

#[test]
fn ancestor_vmstate_is_unused_but_metadata_and_pages_remain_checked() {
    let dir = tmp("ancestor-vmstate");
    let base = dir.join("base");
    let head = dir.join("head");
    let page = vec![7; PAGE_SIZE];
    let mut map = MAGIC.to_vec();
    for word in [1u64, 1, 0, 1, DATA, 0] {
        map.extend_from_slice(&word.to_le_bytes());
    }
    map.extend_from_slice(&crate::crc32c::page(&page).0.to_le_bytes());
    let id = link(&base, None, |m| {
        fs::write(base.join("pages"), &page).unwrap();
        fs::write(base.join("pagemap"), &map).unwrap();
        m.data_pages = 1;
        m.files.get_mut("pages").unwrap().len = PAGE_SIZE as u64;
        let info = m.files.get_mut("pagemap").unwrap();
        info.len = map.len() as u64;
        info.hash = sum(&map);
    });
    link(&head, Some(Parent { path: parent_path(&head, &base), id }), |_| {});
    let budget = Checkpoint::open(&head).unwrap().meta_left;
    // Not even opening an ancestor's VM state: only its memory participates in restore.
    fs::remove_file(base.join("vmstate")).unwrap();
    let ck = Checkpoint::open(&head).unwrap();
    assert_eq!(ck.vmstate, b"s");
    assert_eq!(ck.meta_left, budget);
    let mut storage = Buf::plain(1).unwrap();
    let restored = storage.bytes();
    ck.file.read(0, restored, false).unwrap();
    assert_eq!(restored, page.as_slice());
    fs::write(base.join("pages"), vec![8; PAGE_SIZE]).unwrap();
    assert_eq!(ck.file.read(0, restored, false).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert!(Checkpoint::open(&base).is_err(), "the head's VM state is still required");
    fs::write(head.join("vmstate"), b"x").unwrap();
    assert!(Checkpoint::open(&head).err().unwrap().to_string().contains("vmstate does not match"));
    fs::write(head.join("vmstate"), b"s").unwrap();
    fs::write(base.join("pagemap"), b"bad").unwrap();
    assert!(Checkpoint::open(&head).err().unwrap().to_string().contains("pagemap does not match"));
}

#[test]
fn non_utf8_parent_paths_roundtrip_and_open() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
    let dir = tmp("parent-bytes");
    let base = dir.join(OsStr::from_bytes(b"base-\xff"));
    let id = link(&base, None, |_| {});
    for head in [dir.join("head"), dir.join("nested/head")] {
        let parent = Parent { path: parent_path(&head, &base), id: id.clone() };
        let encoded = serde_json::to_vec(&parent).unwrap();
        let decoded: Parent = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.path, parent.path);
        link(&head, Some(decoded), |_| {});
        assert_eq!(Checkpoint::open(&head).unwrap().chain, [base.canonicalize().unwrap()]);
    }
    let old: Parent = serde_json::from_str(r#"{"path":"../base","id":"id"}"#).unwrap();
    assert_eq!(serde_json::to_value(old).unwrap()["path"], "../base");
}

#[test]
fn suspended_description_checks_manifest_and_saturates_sizes() {
    let root = tmp("suspended-description");
    let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
    let dir = host.suspended("x").unwrap();
    link(&dir, Some(Parent { path: "missing-parent".into(), id: "missing".into() }), |m| {
        m.mem_mib = u64::MAX;
        m.hotplug_mib = 1;
        m.data_pages = u64::MAX;
    });
    // Listing reads only this manifest, even if ancestors and page data are unavailable.
    fs::remove_file(dir.join("pages")).unwrap();
    let description = crate::lifecycle::describe_suspended(&host, "x").unwrap();
    assert_eq!(description["guest_mib"], u64::MAX);
    assert_eq!(description["checkpoint_mib"], u64::MAX >> 20);
    assert_eq!(read_manifest(&dir).unwrap().name, "x");
    fs::write(dir.join("manifest.json"), b"bad checksum\n{}").unwrap();
    assert!(crate::lifecycle::describe_suspended(&host, "x").is_none());
    fs::write(dir.join("manifest.json"), vec![b' '; (1 << 20) + 1]).unwrap();
    assert!(crate::lifecycle::describe_suspended(&host, "x").is_none());
}

#[test]
fn direct_page_reads_are_aligned_across_file_boundaries() {
    let dir = tmp("direct-reads");
    let (mut files, mut sums, mut buffered) = (Vec::new(), Vec::new(), false);
    for i in 0..2 {
        let path = dir.join(format!("pages{i}"));
        // The stored run starts at a nonzero file offset.
        let data = [page(0), page(i + 1), page(i + 2)].concat();
        fs::write(&path, &data).unwrap();
        let file = File::open(path).unwrap();
        match direct(&file, true) {
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => buffered = true,
            r => r.unwrap(),
        }
        files.push(file);
        sums.push(data.chunks(PAGE_SIZE).map(|p| crate::crc32c::page(p).0).collect());
    }
    let (_, file) = flatten(&[vec![(0, 2, DATA, 0, 1), (2, 2, DATA, 1, 1)]], files, sums);
    let mut storage = Buf::plain(4).unwrap();
    let bytes = storage.bytes();
    assert_eq!(bytes.as_ptr() as usize % PAGE_SIZE, 0);
    assert_eq!(bytes[2 * PAGE_SIZE..].as_ptr() as usize % PAGE_SIZE, 0);
    file.read(0, bytes, false).unwrap();
    assert_eq!(bytes, [page(1), page(2), page(2), page(3)].concat());
    // Only reads through the page cache are evicted.
    assert_eq!(file.buffered(), buffered);
}

#[test]
fn direct_read_falls_back_only_on_einval_and_propagates_retry_errors() {
    let dir = tmp("direct-fallback");
    let path = dir.join("pages");
    fs::write(&path, page(7)).unwrap();
    let file = File::open(path).unwrap();
    let _ = direct(&file, true);
    let mut calls = 0;
    let mut buf = vec![0; PAGE_SIZE];
    read_with_fallback(&file, || {
        calls += 1;
        if calls == 1 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        assert_eq!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_DIRECT, 0);
        file.read_exact_at(&mut buf, 0)
    })
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(buf, page(7));
    for (first, expected_calls) in [(libc::EIO, 1), (libc::EINVAL, 2)] {
        let mut calls = 0;
        let err = read_with_fallback(&file, || {
            calls += 1;
            Err(io::Error::from_raw_os_error(if calls == 1 { first } else { libc::EIO }))
        })
        .unwrap_err();
        assert_eq!(calls, expected_calls);
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
    }
}

#[test]
fn tmpfs_page_reads_work_without_direct_io_support() {
    // A memfd is backed by tmpfs without needing a writable /dev/shm mount.
    let fd = unsafe { libc::memfd_create(c"checkpoint-tmpfs".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0, "{}", io::Error::last_os_error());
    let file = unsafe { File::from_raw_fd(fd) };
    let data = page(9);
    file.write_all_at(&data, 0).unwrap();
    match direct(&file, true) {
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {}
        r => r.unwrap(),
    }
    let (_, file) = flatten(&[vec![(0, 1, DATA, 0, 0)]], vec![file], vec![vec![crate::crc32c::page(&data).0]]);
    let mut storage = Buf::plain(1).unwrap();
    let bytes = storage.bytes();
    file.read(0, bytes, true).unwrap();
    assert_eq!(bytes, data);
    file.drop_cache();
}

#[test]
fn chains_open_to_their_depth_limit_and_refuse_incompatible_parents() {
    let dir = tmp("chain-limits");
    // MAX_CHAIN checkpoints (a base and its deltas) open; one more delta on top is refused.
    let ids = chain(&dir, MAX_CHAIN + 1);
    let at_limit = dir.join(format!("ck{}", MAX_CHAIN - 1));
    let ck = Checkpoint::open(&at_limit).unwrap();
    assert_eq!((ck.chain.len(), &ck.chain_ids[..]), (MAX_CHAIN - 1, &ids[2..]));
    assert_eq!(chain_ids(&at_limit).unwrap(), ids[1..]);
    let past = dir.join(format!("ck{MAX_CHAIN}"));
    for e in [Checkpoint::open(&past).err().unwrap().to_string(), chain_ids(&past).err().unwrap().to_string()] {
        assert!(e.contains(&format!("more than {MAX_CHAIN} deltas deep")), "{e}");
    }
    // A parent whose id (its manifest's checksum) matches, but of another template or guest size.
    type Edit = fn(&mut Manifest);
    let edits: [Edit; 2] = [|m| m.template_id = "other".into(), |m| m.guest_pages = 512];
    for (i, edit) in edits.into_iter().enumerate() {
        let (base, head) = (dir.join(format!("base{i}")), dir.join(format!("head{i}")));
        let id = link(&base, None, edit);
        Checkpoint::open(&base).unwrap();
        link(&head, Some(Parent { path: parent_path(&head, &base), id }), |_| {});
        for e in [Checkpoint::open(&head).err().unwrap().to_string(), chain_ids(&head).err().unwrap().to_string()] {
            assert!(e.contains("is of another template or size"), "{e}");
        }
    }
}

/// Two instances with different run directories that write checkpoints into one
/// directory share its lock: it is the host's, by the directory's (dev, inode).
#[test]
fn instances_with_different_run_directories_share_a_destinations_lock() {
    let root = tmp("ck-shared-lock");
    let dest = root.join("dest");
    fs::create_dir(&dest).unwrap();
    let (one, two) = (root.join("one"), root.join("two"));
    let _a = crate::host::Host::open(&one.join("state"), &one.join("run")).unwrap();
    let _b = crate::host::Host::open(&two.join("state"), &two.join("run")).unwrap();
    let st = |p: &std::path::Path| {
        let f = fs::File::open(p).unwrap();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(std::os::fd::AsRawFd::as_raw_fd(&f), &mut st) }, 0);
        st
    };
    let held = super::staging::parent_lock(&st(&dest), libc::LOCK_EX).unwrap();
    // As the other instance would take it, through another path to the same directory.
    std::os::unix::fs::symlink(&dest, root.join("alias")).unwrap();
    let e = super::staging::parent_lock(&st(&root.join("alias")), libc::LOCK_EX | libc::LOCK_NB).err().unwrap();
    assert_eq!(e.raw_os_error(), Some(libc::EWOULDBLOCK));
    for run in [&one, &two] {
        assert!(!run.join("run/.locks/checkpoints").exists(), "not a run directory's");
    }
    drop(held);
    drop(super::staging::parent_lock(&st(&dest), libc::LOCK_EX | libc::LOCK_NB).unwrap());
}

/// #631: what `rmi` reads under a generation's exclusive use lock. A suspended VM has no process,
/// so its record is all that keeps its generation; one being resumed (its name held by a live
/// process that may not have opened its template yet) counts too, while `ps` lists it as the process.
#[test]
fn template_users_count_every_suspended_vm() {
    let root = tmp("template-users");
    let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
    for (name, id) in [("a", "aaaa1111"), ("b", "bbbb2222"), ("c", "cccc3333")] {
        link(&host.suspended(name).unwrap(), None, |m| m.template_id = id.into());
    }
    // A resume's own, consumed (marked STARTED): its process holds the generation itself.
    fs::write(host.suspended("c").unwrap().join("STARTED"), b"").unwrap();
    let _resuming = host.take_name("b", true).unwrap();
    assert!(host.alive("b"));
    let want: std::collections::BTreeSet<String> = ["aaaa1111", "bbbb2222"].map(String::from).into();
    assert_eq!(host.template_users(), want);
    // flexvm's own checkpoints (#775) keep theirs; a directory there without one is no checkpoint.
    let new = host.state.join("checkpoints/.new");
    let id = link(&new, None, |m| m.template_id = "dddd4444".into());
    fs::rename(&new, host.state.join("checkpoints").join(id)).unwrap();
    fs::create_dir_all(host.state.join("checkpoints/.staging")).unwrap();
    let want: std::collections::BTreeSet<String> = ["aaaa1111", "bbbb2222", "dddd4444"].map(String::from).into();
    assert_eq!(host.template_users(), want);
}

#[test]
fn reserve_allocates_in_units_up_to_what_is_asked() {
    use std::os::unix::fs::MetadataExt;
    let dir = tmp("reserve");
    let path = dir.join("pages");
    let file = pages_file(&path);
    let allocated = |f: &PagesFile| f.file.metadata().unwrap().blocks() * 512;
    // Not a whole number of units, then more on top: what was there stays, the rest is added.
    file.reserve(600);
    assert!(allocated(&file) >= 600 * PAGE_SIZE as u64, "{}", allocated(&file));
    file.reserve(100);
    file.reserve(1000);
    assert!(allocated(&file) >= 1000 * PAGE_SIZE as u64, "{}", allocated(&file));
    assert_eq!(file.file.metadata().unwrap().len(), 1000 * PAGE_SIZE as u64);
}

/// A stored checkpoint (`store::dir(state)/ID`), a delta on `parent`'s if given, made at `ms`.
fn stored(state: &Path, parent: Option<&str>, ms: u64) -> String {
    let new = store::dir(state).join(".new");
    let id = link(&new, parent.map(|p| Parent { path: format!("../{p}").into(), id: p.into() }), |m| m.created_unix_ms = ms);
    fs::rename(&new, store::dir(state).join(&id)).unwrap();
    id
}

#[test]
fn the_store_names_lists_and_removes_dependants_first() {
    let state = tmp("store");
    drop(store::lock(&state, libc::LOCK_SH).unwrap());
    let ids = || store::list(&state).into_iter().map(|e| e.id).collect::<Vec<_>>();
    let gone = |id: &str| json!({"deleted": id, "name": null});
    let (a, d) = (stored(&state, None, 1), stored(&state, None, 4));
    let b = stored(&state, Some(&a), 2);
    let c = stored(&state, Some(&b), 3);
    store::link(&state, "base", &a).unwrap();
    assert!(store::link(&state, "base", &d).is_err(), "a name is one checkpoint's");
    assert!(["", ".x", "a/b", &"x".repeat(65)].iter().all(|n| store::check_free(&state, n).is_err()));
    // Neither staging nor what a removal left is listed (nor anything not named by an id).
    fs::create_dir_all(store::dir(&state).join(".flexvm-staging-1/ck")).unwrap();
    link(&store::dir(&state).join(".removed-0123456789abcdef"), None, |_| {});
    let revoked = store::dir(&state).join("fedcba9876543210");
    fs::create_dir_all(&revoked).unwrap();
    fs::write(revoked.join("vmstate"), b"s").unwrap();
    assert_eq!(ids(), [&a, &b, &c, &d].map(String::clone), "oldest first");
    let all = store::list(&state);
    assert_eq!((all[0].name.as_deref(), store::find(&all, "base").unwrap().id.as_str()), (Some("base"), a.as_str()));
    assert_eq!(store::find(&all, &d[..6]).unwrap().id, d);
    assert!(store::find(&all, "nope").is_err() && store::find(&all, &d[..3]).is_err(), "a prefix has 4 digits or more");
    // A restore of a stored one (by any path to it) holds its store, whichever state's; one elsewhere none.
    let held = store::holding(&state.join("checkpoints/../checkpoints").join(&a)).unwrap();
    assert!(held.is_some() && store::lock(&state, libc::LOCK_EX | libc::LOCK_NB).is_err());
    drop(held);
    assert!(store::holding(&state).unwrap().is_none());
    let rows = store::rows(&state, &[json!({"name": "busybox:1.36", "id": "id"})]);
    assert_eq!(
        (&rows[0]["template"], &rows[0]["vm"], &rows[1]["parent"], &rows[2]["parent"]),
        (&json!("busybox:1.36"), &json!("x"), &json!("base"), &json!(b))
    );
    // Refused while one not removed with it builds on it; together, dependants go first.
    let err = store::remove(&state, &["base".into()], false).unwrap_err().to_string();
    assert!(err.contains("checkpoint base has checkpoints built on it") && err.contains(&b), "{err}");
    assert_eq!(ids().len(), 4);
    assert_eq!(store::remove(&state, &[b.clone(), c.clone()], false).unwrap(), [gone(&c), gone(&b)]);
    assert!(!store::dir(&state).join(".removed-0123456789abcdef").exists() && !revoked.exists(), "a removal clears what an earlier one or a revocation left");
    // -f: with all that builds on it, transitively; its name goes with it.
    let b = stored(&state, Some(&a), 5);
    let c = stored(&state, Some(&b), 6);
    let removed = store::remove(&state, &["base".into()], true).unwrap();
    assert_eq!(removed, [gone(&c), gone(&b), json!({"deleted": a, "name": "base"})]);
    assert_eq!(ids(), [d.clone()]);
    assert!(fs::read_dir(store::dir(&state).join("names")).unwrap().next().is_none());
    store::link(&state, "base", &d).unwrap();
    // prune: what is older, unless a kept one builds on it.
    let x = stored(&state, None, 10);
    let y = stored(&state, Some(&x), 20);
    let z = stored(&state, None, 15);
    assert_eq!(store::prune(&state, Some(18)).unwrap(), [json!({"deleted": d, "name": "base"}), gone(&z)]);
    assert_eq!(store::prune(&state, None).unwrap(), [gone(&y), gone(&x)]);
    assert!(ids().is_empty());
}

#[test]
fn store_unreadable_children_block_removal_and_prune() {
    for damage in ["checksum", "format", "io"] {
        let state = tmp("store-unreadable");
        drop(store::lock(&state, libc::LOCK_SH).unwrap());
        let a = stored(&state, None, 1);
        let b = stored(&state, Some(&a), 2);
        let c = stored(&state, Some(&b), 3);
        let unrelated = stored(&state, None, 4);
        let dir = store::dir(&state).join(&c);
        let path = dir.join("manifest.json");
        match damage {
            "checksum" => fs::write(&path, b"bad checksum\n{}").unwrap(),
            "format" => {
                link(&dir, None, |m| m.format = 999);
            }
            _ => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
        }
        store::link(&state, "broken", &c).unwrap();
        assert!(store::list(&state).iter().find(|e| e.id == c).unwrap().manifest.is_err());
        assert!(store::rows(&state, &[]).iter().any(|r| r["id"] == c && r["error"].is_string()));
        for result in [
            store::remove(&state, std::slice::from_ref(&b), false),
            store::remove(&state, std::slice::from_ref(&b), true),
            store::remove(&state, std::slice::from_ref(&unrelated), false),
            store::remove(&state, &["broken".into()], false),
            store::prune(&state, None),
            store::prune(&state, Some(2)),
        ] {
            let err = result.unwrap_err().to_string();
            assert!(err.contains(&dir.display().to_string()), "{err}");
        }
        assert!([&a, &b, &c, &unrelated].iter().all(|id| store::dir(&state).join(id).exists()));
        // Its parent is not known: only it goes.
        assert_eq!(store::remove(&state, &["broken".into()], true).unwrap(), [json!({"deleted": c, "name": "broken"})]);
        assert!(!dir.exists() && [&a, &b, &unrelated].iter().all(|id| store::dir(&state).join(id).exists()));
        assert_eq!(store::prune(&state, None).unwrap().len(), 3);
    }
}

#[test]
fn store_entries_renamed_by_hand_are_unreadable_until_removed_with_force() {
    let state = tmp("store-renamed");
    drop(store::lock(&state, libc::LOCK_SH).unwrap());
    let a = stored(&state, None, 1);
    let b = stored(&state, Some(&a), 2);
    let unrelated = stored(&state, None, 3);
    // a's manifest now builds on b: not a's id, so no cycle, and a builds on nothing.
    link(&store::dir(&state).join(&a), Some(Parent { path: format!("../{b}").into(), id: b.clone() }), |_| {});
    let exists = |id: &&String| store::dir(&state).join(id).exists();
    for result in [store::remove(&state, std::slice::from_ref(&unrelated), true), store::prune(&state, None)] {
        let err = result.unwrap_err().to_string();
        assert!(err.contains("its manifest's id is") && err.contains(&format!("checkpoint rm -f {a}")), "{err}");
        assert!([&a, &b, &unrelated].iter().all(exists));
    }
    let gone: Vec<serde_json::Value> = [&b, &a].iter().map(|id| json!({"deleted": id, "name": null})).collect();
    assert_eq!(store::remove(&state, std::slice::from_ref(&a), true).unwrap(), gone, "b built on a as it was");
    assert_eq!(store::remove(&state, &[unrelated], false).unwrap().len(), 1);
}

#[test]
fn store_cycles_refuse_before_deleting_anything() {
    let (a, b, c) = ("aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc");
    let entry = |id: &str, parent: Option<&str>| {
        let m = manifest(1, parent.map(|p| Parent { path: format!("../{p}").into(), id: p.into() }), json!({}));
        store::Entry { id: id.into(), name: None, dir: format!("/nonexistent/{id}").into(), manifest: Ok(m) }
    };
    let all = [entry(a, Some(b)), entry(b, Some(a)), entry(c, None)];
    for result in [store::removal(&all, &[a.into()], true), store::pruning(&all, None)] {
        let err = result.unwrap_err().to_string();
        assert_eq!(err, format!("nothing removed: checkpoints {a}, {b} build on each other in a cycle"));
    }
    assert_eq!(store::removal(&all, &[c.into()], false).unwrap(), [2]);
}

#[test]
fn host_template_users_keep_every_generation_for_unreadable_records() {
    let root = tmp("host-unreadable");
    let host = crate::host::Host::open(&root.join("state"), &root.join("run")).unwrap();
    let keep_all = |why: &str| {
        let users = host.template_users();
        let all: Vec<&str> = users.iter().filter_map(|u| u.strip_prefix(crate::template::KEEP_ALL)).collect();
        assert!(all.len() == 1 && all[0].starts_with("a checkpoint here cannot be read") && all[0].contains(why), "{users:?} for {why:?}");
    };
    for dir in [host.suspended("bad").unwrap(), host.state.join("checkpoints/0123456789abcdef")] {
        fs::create_dir_all(&dir).unwrap();
        assert!(host.template_users().is_empty(), "a missing manifest is revoked");
        fs::write(dir.join("manifest.json"), b"bad checksum\n{}").unwrap();
        keep_all("manifest checksum mismatch");
        link(&dir, None, |m| m.format = 999);
        keep_all("format 999");
        for marker in ["STARTED", "DISCARDED"] {
            if dir.starts_with(host.state.join("suspended")) {
                fs::write(dir.join(marker), b"").unwrap();
                assert!(host.template_users().is_empty(), "consumed records do not count");
                fs::remove_file(dir.join(marker)).unwrap();
            }
        }
        fs::remove_file(dir.join("manifest.json")).unwrap();
        fs::create_dir(dir.join("manifest.json")).unwrap();
        keep_all("manifest.json");
        fs::remove_dir_all(&dir).unwrap();
    }
    // A store entry is its manifest's id: one under another id is no checkpoint of its own.
    let dir = host.state.join("checkpoints/0123456789abcdef");
    link(&dir, None, |m| m.template_id = "aaaa1111".into());
    keep_all("its manifest's id is");
}

#[test]
fn store_cleanup_propagates_manifest_permission_errors() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        return; // Root can traverse a directory without search permission.
    }
    let state = tmp("store-permissions");
    drop(store::lock(&state, libc::LOCK_SH).unwrap());
    let id = stored(&state, None, 1);
    let checkpoint = state.join("contents");
    fs::rename(store::dir(&state).join(&id), &checkpoint).unwrap();
    // Removing a symlink would succeed even though looking up its manifest fails.
    std::os::unix::fs::symlink(&checkpoint, store::dir(&state).join(&id)).unwrap();
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o600)).unwrap();
    let result = store::prune(&state, None);
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o700)).unwrap();
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&id), "{err}");
    assert!(fs::symlink_metadata(store::dir(&state).join(&id)).unwrap().is_symlink());
    assert!(checkpoint.join("manifest.json").is_file());
}

#[test]
fn store_leaf_queue_preserves_order_across_branches() {
    let state = tmp("store-branches");
    drop(store::lock(&state, libc::LOCK_SH).unwrap());
    let a = stored(&state, None, 1);
    let b = stored(&state, Some(&a), 2);
    let c = stored(&state, Some(&a), 3);
    let d = stored(&state, Some(&b), 4);
    let z = stored(&state, None, 5);
    let removed = store::remove(&state, &[a.clone(), z.clone()], true).unwrap();
    assert_eq!(removed, [c, d, b, a, z].map(|id| json!({"deleted": id, "name": null})));
}

#[test]
fn store_prune_keeps_every_ancestor_of_a_kept_leaf() {
    let state = tmp("store-prune-chain");
    drop(store::lock(&state, libc::LOCK_SH).unwrap());
    let mut ids = vec![stored(&state, None, 100)];
    for ms in (93..100).rev() {
        ids.push(stored(&state, ids.last().map(String::as_str), ms));
    }
    ids.push(stored(&state, ids.last().map(String::as_str), 200));
    let unrelated = stored(&state, None, 1);
    assert_eq!(store::prune(&state, Some(150)).unwrap(), [json!({"deleted": unrelated, "name": null})]);
    let removed = store::prune(&state, None).unwrap();
    assert_eq!(removed, ids.into_iter().rev().map(|id| json!({"deleted": id, "name": null})).collect::<Vec<_>>());
}

/// `remove` and `prune` as they were before the dependency index (#804), for comparison.
mod scan {
    use super::super::store::{find, Entry};
    use crate::{bail, util::Result};
    use std::collections::BTreeSet;

    fn builds_on(e: &Entry, id: &str) -> bool {
        e.manifest.as_ref().unwrap().parent.as_ref().is_some_and(|p| p.id == id)
    }

    fn label(e: &Entry) -> &str {
        e.name.as_deref().unwrap_or(&e.id)
    }

    pub fn remove(all: &[Entry], whats: &[String], force: bool) -> Result<Vec<String>> {
        let mut doomed: BTreeSet<&str> = whats.iter().map(|w| Ok(find(all, w)?.id.as_str())).collect::<Result<_>>()?;
        loop {
            let more: Vec<&Entry> = all.iter().filter(|e| !doomed.contains(e.id.as_str()) && doomed.iter().any(|d| builds_on(e, d))).collect();
            let Some(first) = more.first() else { break };
            if !force {
                let parent = all.iter().find(|p| builds_on(first, &p.id)).map_or("", label);
                let children: Vec<&str> = more.iter().map(|e| label(e)).collect();
                bail!("checkpoint {parent} has checkpoints built on it ({}): remove them first, or -f removes them too", children.join(", "));
            }
            doomed.extend(more.iter().map(|e| e.id.as_str()));
        }
        delete(all, doomed)
    }

    pub fn prune(all: &[Entry], before: Option<u64>) -> Result<Vec<String>> {
        let mut doomed: BTreeSet<&str> =
            all.iter().filter(|e| before.is_none_or(|b| e.manifest.as_ref().unwrap().created_unix_ms < b)).map(|e| e.id.as_str()).collect();
        while let Some(kept) = all.iter().find(|p| doomed.contains(p.id.as_str()) && all.iter().any(|e| !doomed.contains(e.id.as_str()) && builds_on(e, &p.id)))
        {
            doomed.remove(kept.id.as_str());
        }
        delete(all, doomed)
    }

    fn delete(all: &[Entry], mut doomed: BTreeSet<&str>) -> Result<Vec<String>> {
        let mut out = vec![];
        while let Some(e) = all.iter().find(|e| doomed.contains(e.id.as_str()) && !all.iter().any(|c| doomed.contains(c.id.as_str()) && builds_on(c, &e.id))) {
            doomed.remove(e.id.as_str());
            out.push(e.id.clone());
        }
        if !doomed.is_empty() {
            let stuck: Vec<&str> = all.iter().filter(|e| doomed.contains(e.id.as_str())).map(label).collect();
            bail!("nothing removed: checkpoints {} build on each other in a cycle", stuck.join(", "));
        }
        Ok(out)
    }
}

#[test]
fn store_dependency_index_matches_the_scan_on_every_small_graph() {
    // Each checkpoint's parent: none, one not in the store, itself, or any other (so cycles and
    // children listed before their parents too): every graph of up to 4, every 7th of 5.
    let mut graphs = 0;
    for n in 1..=5usize {
        let choices = n + 2;
        for code in (0..choices.pow(n as u32)).step_by(if n < 5 { 1 } else { 7 }) {
            let id = |i: usize| format!("{i:016x}");
            let all: Vec<store::Entry> = (0..n)
                .map(|i| {
                    let parent = match code / choices.pow(i as u32) % choices {
                        0 => None,
                        1 => Some("ffffffffffffffff".to_string()),
                        c => Some(id(c - 2)),
                    };
                    let mut m = manifest(1, parent.map(|p| Parent { path: format!("../{p}").into(), id: p }), json!({}));
                    m.created_unix_ms = i as u64 * 10;
                    store::Entry { id: id(i), name: (i % 2 == 1).then(|| format!("n{i}")), dir: format!("/nonexistent/{i}").into(), manifest: Ok(m) }
                })
                .collect();
            let ids = |order: Vec<usize>| order.into_iter().map(|i| all[i].id.clone()).collect::<Vec<_>>();
            for subset in 0..1usize << n {
                let whats: Vec<String> = (0..n).filter(|i| subset >> i & 1 == 1).map(|i| if i % 2 == 1 { format!("n{i}") } else { id(i) }).collect();
                for force in [false, true] {
                    let new = store::removal(&all, &whats, force).map(ids).map_err(|e| e.to_string());
                    let old = scan::remove(&all, &whats, force).map_err(|e| e.to_string());
                    assert_eq!(new, old, "remove {whats:?} force={force} from {code} of {n}");
                }
            }
            for before in std::iter::once(None).chain((0..=n as u64).map(|i| Some(i * 10))) {
                assert_eq!(
                    store::pruning(&all, before).map(ids).map_err(|e| e.to_string()),
                    scan::prune(&all, before).map_err(|e| e.to_string()),
                    "prune {before:?} from {code} of {n}"
                );
            }
            graphs += 1;
        }
    }
    assert_eq!(graphs, 3 + 16 + 125 + 1296 + 2401);
}
