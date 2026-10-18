//! flexvm's own checkpoints (#775): `STATE/checkpoints/ID`, each published whole by
//! `Staging::in_store` under its manifest's id, and `names/NAME`, links to `../ID`. The store's
//! lock is held shared while a checkpoint is written into it (a delta's parent must stay) and
//! while a restore opens one (its files stay readable once open), exclusively while any is
//! removed. A removal unlinks the name, then renames the checkpoint `.removed-ID` (durably,
//! dependants before what they build on) and deletes that; what a crash leaves, the next removal
//! does, and so an `ID` without a manifest (a revoked publication's: one is published whole).
use super::{managed, Manifest};
use crate::{bail, host::Flock, util::Result};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const NAMES: &str = "names";
const REMOVED: &str = ".removed-";

pub fn dir(state: &Path) -> PathBuf {
    state.join("checkpoints")
}

/// The store's lock, held `how` (`LOCK_SH` or `LOCK_EX`); the store is made if missing.
pub fn lock(state: &Path, how: i32) -> Result<Flock> {
    let dir = dir(state);
    crate::host::host_dir(&dir.join(NAMES), 0o700)?;
    Ok(Flock::new(crate::host::private_file(&crate::host::locks(&dir).join("store"))?, how)?)
}

/// The lock (shared) of the store `dir` is in, whichever state's: none for a directory elsewhere.
pub fn holding(dir: &Path) -> Result<Option<Flock>> {
    let store = dir.canonicalize().ok().and_then(|d| d.parent().filter(|p| p.ends_with("checkpoints") && p.join(NAMES).is_dir()).map(Path::to_path_buf));
    store.map(|s| lock(s.parent().unwrap_or(Path::new("/")), libc::LOCK_SH)).transpose()
}

pub struct Entry {
    pub id: String,
    pub name: Option<String>,
    pub dir: PathBuf,
    pub manifest: Manifest,
}

impl Entry {
    fn label(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }
}

/// Dependency links by position in `list`, so leaf selection keeps its ordering.
struct Index<'a> {
    ids: BTreeMap<&'a str, usize>,
    parents: Vec<Option<usize>>,
    children: Vec<Vec<usize>>,
}

impl<'a> Index<'a> {
    fn new(all: &'a [Entry]) -> Self {
        let ids: BTreeMap<&str, usize> = all.iter().enumerate().map(|(i, e)| (e.id.as_str(), i)).collect();
        let parents: Vec<Option<usize>> = all.iter().map(|e| e.manifest.parent.as_ref().and_then(|p| ids.get(p.id.as_str()).copied())).collect();
        let mut children = vec![vec![]; all.len()];
        for (i, parent) in parents.iter().enumerate() {
            if let Some(p) = parent {
                children[*p].push(i);
            }
        }
        Self { ids, parents, children }
    }
}

/// Every stored checkpoint, oldest first, with its name: staging and removed ones are not.
pub fn list(state: &Path) -> Vec<Entry> {
    let mut names: BTreeMap<String, String> = std::fs::read_dir(dir(state).join(NAMES))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| Some((std::fs::read_link(e.path()).ok()?.file_name()?.to_str()?.to_string(), e.file_name().into_string().ok()?)))
        .collect();
    let mut all: Vec<Entry> = managed(state)
        .filter_map(|(dir, manifest)| {
            let id = dir.file_name()?.to_str().filter(|id| is_id(id))?.to_string();
            Some(Entry { name: names.remove(&id), id, dir, manifest })
        })
        .collect();
    all.sort_by(|a, b| (a.manifest.created_unix_ms, &a.id).cmp(&(b.manifest.created_unix_ms, &b.id)));
    all
}

fn is_id(name: &str) -> bool {
    name.len() == 16 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The checkpoint `what` names: by its name, else its id or the start of one (4 or more digits).
pub fn find<'a>(all: &'a [Entry], what: &str) -> Result<&'a Entry> {
    if let Some(e) = all.iter().find(|e| e.name.as_deref() == Some(what)) {
        return Ok(e);
    }
    let found: Vec<&Entry> = all.iter().filter(|e| what.len() >= 4 && e.id.starts_with(what)).collect();
    match found[..] {
        [e] => Ok(e),
        [] => bail!("no checkpoint {what:?} (see flexvm checkpoint ls)"),
        _ => bail!("{what:?} is the start of {} checkpoint ids; give more of it", found.len()),
    }
}

/// Refused if `name` is no checkpoint name or is taken.
pub fn check_free(state: &Path, name: &str) -> Result<()> {
    if crate::host::check_name(name).is_err() {
        bail!("bad checkpoint name {name:?}: up to 64 letters, digits, '-', '_' or '.', not starting with '.'");
    }
    if std::fs::symlink_metadata(dir(state).join(NAMES).join(name)).is_ok() {
        bail!("checkpoint name {name:?} is taken (see flexvm checkpoint ls)");
    }
    Ok(())
}

/// Names checkpoint `id`, under the lock; refused if the name was taken meanwhile.
pub fn link(state: &Path, name: &str, id: &str) -> Result<()> {
    check_free(state, name)?;
    let names = dir(state).join(NAMES);
    std::os::unix::fs::symlink(Path::new("..").join(id), names.join(name)).map_err(|e| format!("naming checkpoint {id} {name}: {e}"))?;
    Ok(crate::util::sync_dir(&names)?)
}

/// `checkpoint rm`: refused while a checkpoint not removed with them builds on one, unless
/// `force`, which removes those too.
pub fn remove(state: &Path, whats: &[String], force: bool) -> Result<Vec<Value>> {
    let _lock = lock(state, libc::LOCK_EX)?;
    let all = list(state);
    let index = Index::new(&all);
    let mut doomed: BTreeSet<usize> = whats.iter().map(|w| Ok(index.ids[find(&all, w)?.id.as_str()])).collect::<Result<_>>()?;
    let more: BTreeSet<usize> = doomed.iter().flat_map(|i| &index.children[*i]).copied().filter(|i| !doomed.contains(i)).collect();
    if let Some(&first) = more.first().filter(|_| !force) {
        let parent = index.parents[first].map_or("", |p| all[p].label());
        let children: Vec<&str> = more.iter().map(|i| all[*i].label()).collect();
        bail!("checkpoint {parent} has checkpoints built on it ({}): remove them first, or -f removes them too", children.join(", "));
    }
    let mut pending: Vec<usize> = more.into_iter().collect();
    while let Some(i) = pending.pop() {
        if doomed.insert(i) {
            pending.extend(&index.children[i]);
        }
    }
    delete(state, &all, &index, doomed)
}

/// `checkpoint prune`: every checkpoint created before `before` (Unix ms; all without), unless
/// one kept builds on it.
pub fn prune(state: &Path, before: Option<u64>) -> Result<Vec<Value>> {
    let _lock = lock(state, libc::LOCK_EX)?;
    let all = list(state);
    let index = Index::new(&all);
    let mut doomed: BTreeSet<usize> = all.iter().enumerate().filter(|(_, e)| before.is_none_or(|b| e.manifest.created_unix_ms < b)).map(|(i, _)| i).collect();
    let mut kept: Vec<usize> = (0..all.len()).filter(|i| !doomed.contains(i)).collect();
    while let Some(i) = kept.pop() {
        if let Some(p) = index.parents[i].filter(|p| doomed.remove(p)) {
            kept.push(p);
        }
    }
    delete(state, &all, &index, doomed)
}

/// Leaf-first, under the lock: a crash midway leaves whole chains.
fn delete(state: &Path, all: &[Entry], index: &Index<'_>, doomed: BTreeSet<usize>) -> Result<Vec<Value>> {
    let store = dir(state);
    for e in std::fs::read_dir(&store)?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let revoked = if is_id(&name) {
            match std::fs::symlink_metadata(e.path().join("manifest.json")) {
                Ok(_) => false,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                Err(e) => return Err(e.into()),
            }
        } else {
            false
        };
        if name.starts_with(REMOVED) || revoked {
            std::fs::remove_dir_all(e.path())?;
        }
    }
    let mut out = vec![];
    let mut children: Vec<usize> = index.children.iter().map(|cs| cs.iter().filter(|c| doomed.contains(c)).count()).collect();
    let mut leaves: BTreeSet<usize> = doomed.iter().copied().filter(|i| children[*i] == 0).collect();
    while let Some(i) = leaves.pop_first() {
        let e = &all[i];
        if let Some(name) = &e.name {
            crate::util::unlink_durably(&store.join(NAMES).join(name))?;
        }
        let gone = store.join(format!("{REMOVED}{}", e.id));
        std::fs::rename(&e.dir, &gone)?;
        crate::util::sync_dir(&store)?;
        std::fs::remove_dir_all(&gone)?;
        if let Some(p) = index.parents[i].filter(|p| doomed.contains(p)) {
            children[p] -= 1;
            if children[p] == 0 {
                leaves.insert(p);
            }
        }
        out.push(json!({"deleted": e.id, "name": e.name}));
    }
    Ok(out)
}

/// `checkpoint ls`'s rows (as `--format json` prints them): the template is the image name
/// linking to its generation now (null if none does), the parent its name or id.
pub fn rows(state: &Path, templates: &[Value]) -> Vec<Value> {
    let all = list(state);
    let image = |id: &str| templates.iter().find(|t| t["id"] == id && t["name"].is_string()).map(|t| t["name"].clone());
    all.iter()
        .map(|e| {
            let m = &e.manifest;
            let parent = m.parent.as_ref().map(|p| all.iter().find(|a| a.id == p.id).map_or(p.id.as_str(), Entry::label));
            let size = crate::management::disk_usage(&e.dir, &mut BTreeSet::new()).unwrap_or(0);
            json!({"name": e.name, "id": e.id, "vm": m.name, "template": image(&m.template_id), "template_id": m.template_id,
                   "parent": parent, "size": size, "created": m.created_unix_ms / 1000})
        })
        .collect()
}
