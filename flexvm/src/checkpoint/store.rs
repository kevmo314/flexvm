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
    pub names: Vec<String>,
    pub dir: PathBuf,
    pub manifest: Result<Manifest>,
}

impl Entry {
    fn label(&self) -> &str {
        self.names.first().map_or(&self.id, String::as_str)
    }
}

/// Dependency links by position in `list`, so leaf selection keeps its ordering.
struct Index<'a> {
    all: &'a [Entry],
    ids: BTreeMap<&'a str, usize>,
    parents: Vec<Option<usize>>,
    children: Vec<Vec<usize>>,
}

impl<'a> Index<'a> {
    fn new(all: &'a [Entry]) -> Self {
        let ids: BTreeMap<&str, usize> = all.iter().enumerate().map(|(i, e)| (e.id.as_str(), i)).collect();
        let parents: Vec<Option<usize>> =
            all.iter().map(|e| e.manifest.as_ref().ok().and_then(|m| m.parent.as_ref()).and_then(|p| ids.get(p.id.as_str()).copied())).collect();
        let mut children = vec![vec![]; all.len()];
        for (i, parent) in parents.iter().enumerate() {
            if let Some(p) = parent {
                children[*p].push(i);
            }
        }
        Self { all, ids, parents, children }
    }

    /// `doomed`, each after every doomed checkpoint built on it; among those ready, first in `list`.
    fn leaf_first(&self, doomed: &BTreeSet<usize>) -> Result<Vec<usize>> {
        let mut waiting: Vec<usize> = self.children.iter().map(|cs| cs.iter().filter(|c| doomed.contains(c)).count()).collect();
        let mut ready: BTreeSet<usize> = doomed.iter().copied().filter(|i| waiting[*i] == 0).collect();
        let mut order = vec![];
        while let Some(i) = ready.pop_first() {
            order.push(i);
            if let Some(p) = self.parents[i].filter(|p| doomed.contains(p)) {
                waiting[p] -= 1;
                if waiting[p] == 0 {
                    ready.insert(p);
                }
            }
        }
        if order.len() < doomed.len() {
            // Only a manifest's id names its entry (`managed`), so this takes a hash collision.
            let stuck: Vec<&str> = doomed.iter().filter(|i| !order.contains(i)).map(|i| self.all[*i].label()).collect();
            bail!("nothing removed: checkpoints {} build on each other in a cycle", stuck.join(", "));
        }
        Ok(order)
    }
}

/// A partial listing is useful for `ls` and exact lookups, never for removal or prefixes.
#[derive(Default)]
pub struct Listing {
    pub entries: Vec<Entry>,
    pub errors: Vec<crate::util::Error>,
}

impl Listing {
    fn complete(&self) -> Result<()> {
        if let Some(e) = self.errors.first() {
            bail!("incomplete checkpoint listing: {e}");
        }
        Ok(())
    }
}

/// Every stored checkpoint, oldest first, with all its names; staging and removed ones are not.
pub fn list(state: &Path) -> Listing {
    listed(managed(state), super::entries(&dir(state).join(NAMES)))
}

pub(super) fn listed(checkpoints: impl Iterator<Item = Result<(PathBuf, Result<Manifest>)>>, links: impl Iterator<Item = Result<PathBuf>>) -> Listing {
    let mut all = Listing::default();
    let mut names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for link in links {
        let read = (|| -> Result<_> {
            let path = link?;
            let target = std::fs::read_link(&path).map_err(|e| format!("reading checkpoint name {}: {e}", path.display()))?;
            let name = path.file_name().and_then(|n| n.to_str());
            let id = target.file_name().and_then(|n| n.to_str()).filter(|id| is_id(id));
            match (name, id) {
                (Some(name), Some(id)) => Ok((id.to_string(), name.to_string())),
                _ => bail!("invalid checkpoint name {} -> {}", path.display(), target.display()),
            }
        })();
        match read {
            Ok((id, name)) => names.entry(id).or_default().push(name),
            Err(e) => all.errors.push(e),
        }
    }
    for checkpoint in checkpoints {
        match checkpoint {
            Ok((dir, manifest)) => {
                let id = dir.file_name().unwrap().to_string_lossy().into_owned();
                let mut names = names.remove(&id).unwrap_or_default();
                names.sort();
                all.entries.push(Entry { names, id, dir, manifest });
            }
            Err(e) => all.errors.push(e),
        }
    }
    all.entries
        .sort_by(|a, b| (a.manifest.as_ref().map_or(0, |m| m.created_unix_ms), &a.id).cmp(&(b.manifest.as_ref().map_or(0, |m| m.created_unix_ms), &b.id)));
    all
}

pub(crate) fn is_id(name: &str) -> bool {
    name.len() == 16 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The checkpoint `what` names: by its name, else its id or the start of one (4 or more digits).
pub fn find<'a>(all: &'a Listing, what: &str) -> Result<&'a Entry> {
    if let Some(e) = all.entries.iter().find(|e| e.names.iter().any(|n| n == what)) {
        return Ok(e);
    }
    if let Some(e) = all.entries.iter().find(|e| is_id(what) && e.id == what) {
        return Ok(e);
    }
    all.complete().map_err(|e| format!("cannot resolve checkpoint {what:?}: {e}"))?;
    let found: Vec<&Entry> = all.entries.iter().filter(|e| what.len() >= 4 && e.id.starts_with(what)).collect();
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
    let order = removal(&all, whats, force)?;
    delete(state, &all.entries, order)
}

/// `checkpoint prune`: every checkpoint created before `before` (Unix ms; all without), unless
/// one kept builds on it.
pub fn prune(state: &Path, before: Option<u64>) -> Result<Vec<Value>> {
    let _lock = lock(state, libc::LOCK_EX)?;
    let all = list(state);
    let order = pruning(&all, before)?;
    delete(state, &all.entries, order)
}

/// What `remove` deletes, as positions in `all`, in the order it deletes them.
pub(super) fn removal(all: &Listing, whats: &[String], force: bool) -> Result<Vec<usize>> {
    all.complete().map_err(|e| format!("nothing removed: {e}"))?;
    let index = Index::new(&all.entries);
    let mut doomed: BTreeSet<usize> = whats.iter().map(|w| Ok(index.ids[find(all, w)?.id.as_str()])).collect::<Result<_>>()?;
    let all = &all.entries;
    readable_or_removed(all, &doomed, force)?;
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
    index.leaf_first(&doomed)
}

/// What `prune` deletes, as positions in `all`, in the order it deletes them.
pub(super) fn pruning(all: &Listing, before: Option<u64>) -> Result<Vec<usize>> {
    all.complete().map_err(|e| format!("nothing removed: {e}"))?;
    let all = &all.entries;
    readable_or_removed(all, &BTreeSet::new(), false)?;
    let index = Index::new(all);
    let mut doomed: BTreeSet<usize> =
        (0..all.len()).filter(|i| before.is_none_or(|b| all[*i].manifest.as_ref().is_ok_and(|m| m.created_unix_ms < b))).collect();
    let mut kept: Vec<usize> = (0..all.len()).filter(|i| !doomed.contains(i)).collect();
    while let Some(i) = kept.pop() {
        if let Some(p) = index.parents[i].filter(|p| doomed.remove(p)) {
            kept.push(p);
        }
    }
    index.leaf_first(&doomed)
}

/// An unreadable checkpoint may build on any other: refused while one is kept (only `rm -f` of
/// it removes it). Nothing is removed, so a passing error (EMFILE) fails only this command.
fn readable_or_removed(all: &[Entry], doomed: &BTreeSet<usize>, force: bool) -> Result<()> {
    let unreadable: Vec<&Entry> = all.iter().enumerate().filter(|(i, e)| e.manifest.is_err() && !(force && doomed.contains(i))).map(|(_, e)| e).collect();
    if unreadable.is_empty() {
        return Ok(());
    }
    let errors: Vec<String> = unreadable.iter().filter_map(|e| e.manifest.as_ref().err()).map(|e| e.to_string()).collect();
    let labels: Vec<&str> = unreadable.iter().map(|e| e.label()).collect();
    bail!(
        "nothing removed: unreadable checkpoints may build on what this would remove ({}); if that persists, remove them first: flexvm checkpoint rm -f {}",
        errors.join("; "),
        labels.join(" ")
    )
}

/// Leaf-first, under the lock: a crash midway leaves whole chains.
fn delete(state: &Path, all: &[Entry], order: Vec<usize>) -> Result<Vec<Value>> {
    let store = dir(state);
    for e in std::fs::read_dir(&store)?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // Only a missing manifest is a revoked publication: any other error keeps it (`list` showed
        // it unreadable, and only its own `rm -f` gets here then).
        let revoked = is_id(&name) && std::fs::symlink_metadata(e.path().join("manifest.json")).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
        if name.starts_with(REMOVED) || revoked {
            std::fs::remove_dir_all(e.path())?;
        }
    }
    let mut out = vec![];
    for e in order.into_iter().map(|i| &all[i]) {
        for name in &e.names {
            crate::util::unlink_durably(&store.join(NAMES).join(name))?;
        }
        let gone = store.join(format!("{REMOVED}{}", e.id));
        std::fs::rename(&e.dir, &gone)?;
        crate::util::sync_dir(&store)?;
        std::fs::remove_dir_all(&gone)?;
        out.push(json!({"deleted": e.id, "name": display_names(e)}));
    }
    Ok(out)
}

/// Removes checkpoints `ids` (dependants first), which no name links to, under the lock the caller
/// holds exclusively: what a failed `checkpoint load` published. As `delete` removes one.
pub(super) fn unpublish(state: &Path, ids: &[String]) -> Result<()> {
    let store = dir(state);
    for id in ids {
        let gone = store.join(format!("{REMOVED}{id}"));
        std::fs::rename(store.join(id), &gone)?;
        crate::util::sync_dir(&store)?;
        std::fs::remove_dir_all(&gone)?;
    }
    Ok(())
}

/// `checkpoint ls`'s rows (as `--format json` prints them): the template is the image name
/// linking to its generation now (null if none does), the parent its name or id.
pub fn rows(state: &Path, templates: &[Value]) -> Vec<Value> {
    let all = list(state);
    let image = |id: &str| templates.iter().find(|t| t["id"] == id && t["name"].is_string()).map(|t| t["name"].clone());
    all.entries
        .iter()
        .map(|e| {
            let m = match &e.manifest {
                Ok(m) => m,
                Err(err) => return json!({"name": display_names(e), "id": e.id, "error": err.to_string()}),
            };
            let parent = m.parent.as_ref().map(|p| all.entries.iter().find(|a| a.id == p.id).map_or(p.id.as_str(), Entry::label));
            let size = crate::management::disk_usage(&e.dir, &mut BTreeSet::new()).unwrap_or(0);
            json!({"name": display_names(e), "id": e.id, "vm": m.name, "template": image(&m.template_id), "template_id": m.template_id,
                   "parent": parent, "size": size, "created": m.created_unix_ms / 1000})
        })
        .chain(all.errors.iter().map(|e| json!({"error": e.to_string()})))
        .collect()
}

fn display_names(e: &Entry) -> Option<String> {
    (!e.names.is_empty()).then(|| e.names.join(", "))
}
