use super::{
    chain::{flatten, overlay, read_at, Link},
    format::{parse_pagemap, sum, sums_sum, Run, DATA, MAGIC, MAX_VMSTATE, TEMPLATE, ZERO},
    staging::{publish_permissions, STAGING_PREFIX},
    write::{aligned, as_bytes, classify, write_pages, PagesFile},
    *,
};
use crate::{
    template::{Paths, Template},
    uffd::{Runs, BASE as P_BASE, REMOTE, ZERO as P_ZERO},
    util::{stat_at, Result, PAGE_SIZE},
};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::fd::AsRawFd,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    sync::Arc,
};

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("flexvm-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn manifest(guest_pages: usize, parent: Option<Parent>, files: serde_json::Value) -> Manifest {
    serde_json::from_value(json!({
        "format": if parent.is_some() { FORMAT_INCREMENTAL } else { FORMAT }, "created_unix_ms": 0, "name": "x",
        "ip": "10.0.0.1", "template": "tpl", "template_id": "id", "vcpus": 1, "mem_mib": 1, "max_mib": 1,
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
    let files = json!({"vmstate": {"len": 1, "hash": sum(b"s")}, "pagemap": {"len": map.len(), "hash": sum(&map)}, "pages": {"len": 0, "hash": sums_sum(&[])}});
    let mut m = manifest(256, parent, files);
    edit(&mut m);
    let body = serde_json::to_vec(&m).unwrap();
    fs::write(dir.join("manifest.json"), [format!("{}\n", sum(&body)).as_bytes(), &body].concat()).unwrap();
    sum(&body)
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
    let (mut parent, mut ids) = (None, Vec::new());
    for i in 0..3 {
        let id = link(&dir.join(format!("ck{i}")), parent, |_| {});
        ids.insert(0, id.clone());
        parent = Some(Parent { path: format!("../ck{i}"), id });
    }
    let top = dir.join("ck2");
    let ck = Checkpoint::open(&top).unwrap();
    assert_eq!((ck.chain.len(), &ck.chain_ids[..], chain_ids(&top).unwrap()), (2, &ids[1..], ids.clone()));
    let cost = chain_meta_budget() - ck.meta_left;
    Link::open(&top, 0, Some(&mut { cost })).unwrap();
    let mut left = cost - 1;
    let e = (0..3).rev().try_for_each(|i| Link::open(&dir.join(format!("ck{i}")), 0, Some(&mut left)).map(drop));
    assert!(e.err().unwrap().to_string().contains("bytes of metadata"));
    fs::remove_dir_all(&dir).unwrap();
}

fn template(dir: &Path, pages: &[Option<u8>]) -> Arc<Template> {
    let tdir = dir.join("tpl");
    fs::create_dir_all(&tdir).unwrap();
    fs::write(tdir.join("meta.json"), r#"{"vcpus": 1, "mem_mib": 1, "max_mib": 1, "kernel": "/k", "rootfs": "/r"}"#).unwrap();
    let mem = File::create(tdir.join("mem")).unwrap();
    mem.set_len((pages.len() * PAGE_SIZE) as u64).unwrap();
    for (i, b) in pages.iter().enumerate().filter_map(|(i, p)| Some((i, (*p)?))) {
        mem.write_all_at(&[b; PAGE_SIZE], (i * PAGE_SIZE) as u64).unwrap();
    }
    let paths = Paths { firecracker: "/f".into(), kernel: "/k".into(), rootfs: "/r".into(), templates: dir.into() };
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
    for threads in [8, 3, 1] {
        let path = dir.join(format!("pages-{threads}"));
        let w = write_pages(&tpl, &guest, &input, &pages_file(&path), threads, false).unwrap();
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
    assert!(write_pages(&tpl, &Guest(pages, 333, Some(500)), &input, &pages_file(&dir.join("pages-fail")), 4, false).is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn deltas_flatten_over_their_parents() {
    let dir = tmp("delta");
    let n = 300;
    let tpl_pages: Vec<Option<u8>> = (0..n).map(|i| (i % 3 == 0).then_some(i as u8 | 1)).collect();
    let tpl = template(&dir, &tpl_pages);
    let tpl_page = |i: usize| tpl_pages[i].map_or(vec![0; PAGE_SIZE], |b| vec![b; PAGE_SIZE]);
    let v1: Vec<Vec<u8>> = (0..n).map(|i| if i < 200 { page(i) } else { tpl_page(i) }).collect();
    let w1 = write_pages(&tpl, &Guest(v1.clone(), 128, None), &runs_of((0..200).map(|i| (i, REMOTE))), &pages_file(&dir.join("p1")), 3, false).unwrap();
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
    let w2 = write_pages(&tpl, &Guest(v2.clone(), 128, None), &runs_of(dirty), &pages_file(&dir.join("p2")), 2, true).unwrap();
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
    fs::remove_dir_all(&dir).unwrap();
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
    assert_eq!(parent_path(Path::new("/d/ck2"), Path::new("/d/ck1")), "../ck1");
    assert_eq!(parent_path(Path::new("/e/ck2"), Path::new("/d/ck1")), "/d/ck1");
    // Writer buffers are aligned and zeroed; one larger than Linux can map fails, even with overcommit.
    let mut buf = aligned(2).unwrap();
    assert_eq!(buf.as_ptr() as usize % PAGE_SIZE, 0);
    assert!(as_bytes(&mut buf).len() == 2 * PAGE_SIZE && as_bytes(&mut buf).iter().all(|&b| b == 0));
    assert_eq!(aligned(isize::MAX as usize / PAGE_SIZE).err().unwrap().kind(), io::ErrorKind::OutOfMemory);
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
    fs::remove_dir_all(&dir).unwrap();
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
    publish_permissions(&files.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>(), s.ck.as_raw_fd(), &owner).unwrap();
    for m in files.iter().map(|f| f.metadata().unwrap()) {
        assert_eq!((m.permissions().mode() & 0o777, m.uid(), m.gid()), (0o600, owner.st_uid, owner.st_gid));
    }
    assert_eq!(mode(&mine()[0].join("ck")), 0o700);
    drop(s);
    assert!(!dest.exists() && mine().is_empty());
    fs::create_dir_all(&dest).unwrap();
    assert!(Staging::new(&dest, dir.join("vmstate.private")).is_err());
    fs::remove_dir_all(&dir).unwrap();
}

/// The page map as built before BASE runs were pushed whole: a page at a time.
fn per_page_map(tpl: &Template, guest: &Guest, runs: &Runs, explicit: bool) -> (Vec<[u64; 4]>, u64) {
    let (mut map, mut zero, mut at): (Vec<[u64; 4]>, u64, u64) = (Vec::new(), 0, 0);
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
            let kind = match state {
                REMOTE => classify(tpl, p, &guest.0[p]).0 as u64,
                P_ZERO if tpl.has_data(p) => ZERO,
                _ => P_BASE as u64,
            };
            push(p, kind, if state == REMOTE { at } else { 0 });
            at += (kind == DATA) as u64;
        }
    }
    (map, zero)
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
        let w = write_pages(&tpl, &guest, &runs, &pages_file(&dir.join(format!("p{round}"))), 1, explicit).unwrap();
        let (map, zero) = per_page_map(&tpl, &guest, &runs, explicit);
        let mut want = MAGIC.to_vec();
        let words = [map.len() as u64, w.data].into_iter().chain(map.into_iter().flatten());
        want.extend(words.flat_map(u64::to_le_bytes));
        want.extend(w.sums.iter().flat_map(|s| s.to_le_bytes()));
        assert!(w.map == want && w.zero == zero, "round {round}: runs {runs:?}");
        fs::remove_file(dir.join(format!("p{round}"))).unwrap();
    }
    fs::remove_dir_all(&dir).unwrap();
}
