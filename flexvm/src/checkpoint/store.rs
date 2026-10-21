//! flexvm's own checkpoints (#775): `STATE/checkpoints/ID`, each published whole by
//! `Staging::in_store` under its manifest's id, and `names/NAME`, links to `../ID`. The store's
//! lock is held shared while a checkpoint is written into it (a delta's parent must stay) and
//! while a restore opens one (its files stay readable once open), exclusively while any is
//! removed. A create's requested name is `claim`ed from its check until it is linked. A removal
//! unlinks the name, then renames the checkpoint `.removed-ID` (durably, dependants before what they
//! build on) and deletes that; what a crash leaves, the next removal does, and so an `ID` without a manifest (a revoked publication's: one is published whole).
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

/// A partial listing is useful for `ls` and exact lookups, never for checkpoint removal or prefixes.
#[derive(Default)]
pub struct Listing {
    pub entries: Vec<Entry>,
    pub errors: Vec<crate::util::Error>,
    /// Directories corresponding to `errors`.
    pub(super) error_dirs: Vec<PathBuf>,
    pub(super) malformed: BTreeMap<PathBuf, crate::util::Error>,
    /// Names whose checkpoint is not listed: gone (left by a removal before #862), or hidden by an error.
    pub dangling: Vec<String>,
    /// `names`, probed for a name the listing may have missed.
    pub(super) names: PathBuf,
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
    let names = dir(state).join(NAMES);
    listed(managed(state), super::entries(&names), names)
}

pub(super) fn listed(
    checkpoints: impl Iterator<Item = Result<(PathBuf, Result<Manifest>)>>,
    links: impl Iterator<Item = Result<PathBuf>>,
    names_dir: PathBuf,
) -> Listing {
    let mut all = Listing { names: names_dir, ..Listing::default() };
    let mut names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for link in links {
        let path = match link {
            Ok(path) => path,
            Err(e) => {
                all.error_dirs.push(all.names.clone());
                all.errors.push(e);
                continue;
            }
        };
        let target = match std::fs::read_link(&path) {
            Ok(target) => target,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                all.malformed.insert(path.clone(), format!("checkpoint name {} is not a symlink: {e}", path.display()).into());
                continue;
            }
            Err(e) => {
                all.error_dirs.push(all.names.clone());
                all.errors.push(format!("reading checkpoint name {}: {e}", path.display()).into());
                continue;
            }
        };
        let name = path.file_name().and_then(|n| n.to_str());
        let id = target.file_name().and_then(|n| n.to_str()).filter(|id| is_id(id) && target == Path::new("..").join(id));
        match (name, id) {
            (Some(name), Some(id)) => names.entry(id.to_string()).or_default().push(name.to_string()),
            _ => {
                all.malformed.insert(path.clone(), format!("invalid checkpoint name {} -> {}", path.display(), target.display()).into());
            }
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
            Err(e) => {
                all.error_dirs.push(all.names.parent().unwrap_or(Path::new(".")).to_path_buf());
                all.errors.push(e);
            }
        }
    }
    all.dangling = names.into_values().flatten().collect();
    all.dangling.sort();
    all.entries
        .sort_by(|a, b| (a.manifest.as_ref().map_or(0, |m| m.created_unix_ms), &a.id).cmp(&(b.manifest.as_ref().map_or(0, |m| m.created_unix_ms), &b.id)));
    all
}

pub(crate) fn is_id(name: &str) -> bool {
    name.len() == 16 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The checkpoint `what` names: by its name, else its id or the start of one (4 or more digits).
/// A name and an id of two checkpoints (a name given before #862 may look like an id) is refused,
/// as is an id while a name the listing missed may be it, or an id-shaped name while a checkpoint
/// the listing missed may have that id.
pub fn find<'a>(all: &'a Listing, what: &str) -> Result<&'a Entry> {
    if let Some(e) = all.malformed.get(&all.names.join(what)) {
        bail!("{e}; flexvm checkpoint rm -f {what} removes the name entry");
    }
    let named = all.entries.iter().find(|e| e.names.iter().any(|n| n == what));
    let by_id = all.entries.iter().find(|e| is_id(what) && e.id == what);
    if named.is_none() && all.dangling.iter().any(|n| n == what) {
        all.complete().map_err(|e| format!("cannot resolve checkpoint {what:?}: {e}"))?;
        bail!("checkpoint name {what:?} is of a checkpoint no longer here: flexvm checkpoint rm {what} removes the name");
    }
    match (named, by_id) {
        (Some(n), Some(i)) if n.id != i.id => bail!("{what:?} is a name of checkpoint {} and the id of another; give that one's name, or rename", n.id),
        // An id-shaped name (one given before #862): the checkpoint with that id may be one the listing missed.
        (Some(n), None) if is_id(what) && !all.errors.is_empty() => {
            bail!("cannot resolve checkpoint {what:?}: it is a name of checkpoint {}, and may be the id of one the listing missed ({})", n.id, all.errors[0])
        }
        (Some(e), _) => return Ok(e),
        (None, Some(e)) => {
            let Some(missed) = all.errors.first() else { return Ok(e) };
            // A name `what` the listing missed, or one of a checkpoint it missed, may be another's.
            let hidden = match std::fs::symlink_metadata(all.names.join(what)) {
                Ok(_) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ENOTDIR) => Ok(false),
                Err(err) => Err(err),
            };
            match hidden {
                Ok(false) => return Ok(e),
                Ok(true) => bail!("cannot resolve checkpoint {what:?}: it is also a checkpoint name, of one the listing missed ({missed})"),
                Err(err) => bail!(
                    "cannot resolve checkpoint {what:?}: whether it is also a checkpoint name is not known ({err}), as the listing is incomplete ({missed})"
                ),
            }
        }
        (None, None) => {}
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
    if crate::host::check_new_name(name).is_err() || is_id(name) {
        bail!("bad checkpoint name {name:?}: up to 64 letters, digits, '-', '_' or '.', not starting with '.' or '-', and not 16 hex digits (an id)");
    }
    if std::fs::symlink_metadata(dir(state).join(NAMES).join(name)).is_ok() {
        bail!("checkpoint name {name:?} is taken (see flexvm checkpoint ls)");
    }
    Ok(())
}

/// A requested name, held from its check until it is linked (`link`), so a concurrent create of the
/// same name is refused at once, before it saves anything. Its lock file, `.locks/name-NAME`, goes
/// with it; whoever then opens it again checks it is still the one there.
pub struct NameClaim {
    path: PathBuf,
    _lock: Flock,
}

impl Drop for NameClaim {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `check_free`, then the claim on `name`: refused while another create holds it.
pub fn claim(state: &Path, name: &str) -> Result<NameClaim> {
    use std::os::unix::fs::MetadataExt;
    check_free(state, name)?;
    let path = crate::host::locks(&dir(state)).join(format!("name-{name}"));
    let lock = loop {
        let f = crate::host::private_file(&path)?;
        let ino = f.metadata()?.ino();
        let lock = match Flock::new(f, libc::LOCK_EX | libc::LOCK_NB) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => bail!("checkpoint name {name:?} is being taken by another checkpoint create"),
            held => held?,
        };
        // Its last holder may have removed it before this took it.
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.ino() == ino) {
            break lock;
        }
    };
    let claim = NameClaim { path, _lock: lock };
    // Taken by a create that held it before.
    check_free(state, name)?;
    Ok(claim)
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
    super::staging::clear_stale(&dir(state));
    let all = list(state);
    // Names removed alone cannot affect a checkpoint's dependants.
    let (names, whats): (Vec<String>, Vec<String>) =
        whats.iter().cloned().partition(|w| all.dangling.contains(w) || (force && all.malformed.contains_key(&all.names.join(w))));
    // A dangling name may be one of a checkpoint the listing missed; a malformed one is no checkpoint's.
    if names.iter().any(|n| all.dangling.contains(n)) {
        all.complete().map_err(|e| format!("nothing removed: {e}"))?;
    }
    let names: Vec<PathBuf> = names.iter().map(|n| all.names.join(n)).collect();
    if whats.is_empty() {
        return unname(&names);
    }
    let order = removal(&all, &whats, force)?;
    let mut out = unname(&names)?;
    out.extend(delete(state, &all.entries, order)?);
    Ok(out)
}

/// Removes name entries alone, under the lock, without following their targets.
fn unname(names: &[PathBuf]) -> Result<Vec<Value>> {
    names
        .iter()
        .map(|path| {
            if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
                std::fs::remove_dir_all(path)?;
                crate::util::sync_dir(path.parent().unwrap())?;
            } else {
                crate::util::unlink_durably(path)?;
            }
            Ok(json!({"deleted": null, "name": path.file_name().unwrap().to_string_lossy()}))
        })
        .collect()
}

/// `checkpoint prune`: every checkpoint created before `before` (Unix ms; all without), unless
/// one kept builds on it.
pub fn prune(state: &Path, before: Option<u64>) -> Result<Vec<Value>> {
    let _lock = lock(state, libc::LOCK_EX)?;
    super::staging::clear_stale(&dir(state));
    let all = list(state);
    let order = pruning(&all, before)?;
    let names: Vec<PathBuf> = all.dangling.iter().map(|n| all.names.join(n)).chain(all.malformed.keys().cloned()).collect();
    let mut out = unname(&names)?;
    out.extend(delete(state, &all.entries, order)?);
    Ok(out)
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
                Err(err) => return json!({"name": e.names.first(), "names": e.names, "id": e.id, "directory": e.dir.to_string_lossy(), "error": err.to_string()}),
            };
            let parent = m.parent.as_ref().map(|p| all.entries.iter().find(|a| a.id == p.id).map_or(p.id.as_str(), Entry::label));
            let size = crate::management::disk_usage(&e.dir, &mut BTreeSet::new()).unwrap_or(0);
            json!({"name": e.names.first(), "names": e.names, "id": e.id, "directory": e.dir.to_string_lossy(), "vm": m.name, "template": image(&m.template_id), "template_id": m.template_id,
                   "parent": parent, "size": size, "created": m.created_unix_ms / 1000})
        })
        .chain(all.errors.iter().enumerate().map(|(i, e)| json!({"directory": all.error_dirs.get(i).map(|p| p.to_string_lossy()), "error": e.to_string()})))
        .chain(all.malformed.iter().map(|(path, e)| json!({"directory": path.to_string_lossy(), "error": e.to_string()})))
        .collect()
}

fn display_names(e: &Entry) -> Option<String> {
    (!e.names.is_empty()).then(|| e.names.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    fn unreadable(state: &Path) -> PathBuf {
        drop(lock(state, libc::LOCK_SH).unwrap());
        let checkpoint = dir(state).join("0123456789abcdef");
        fs::create_dir(&checkpoint).unwrap();
        fs::write(checkpoint.join("manifest.json"), b"invalid").unwrap();
        checkpoint
    }

    #[test]
    fn dangling_names_go_without_touching_unreadable_checkpoints_or_leftovers() {
        let state = crate::test_util::TempDir::new("dangling-unreadable");
        let checkpoint = unreadable(&state);
        let leftover = dir(&state).join(".removed-leftover");
        fs::create_dir(&leftover).unwrap();
        for force in [false, true] {
            let name = dir(&state).join("names/old");
            symlink("../aaaaaaaaaaaaaaaa", &name).unwrap();
            assert_eq!(remove(&state, &["old".into()], force).unwrap(), [json!({"deleted": null, "name": "old"})]);
            assert!(fs::symlink_metadata(name).is_err());
            assert!(checkpoint.exists());
            assert!(leftover.exists());
        }
    }

    #[test]
    fn a_name_whose_checkpoint_the_listing_missed_stays() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // Root lists a directory without read permission.
        }
        let state = crate::test_util::TempDir::new("dangling-hidden");
        let checkpoint = unreadable(&state);
        link(&state, "live", "0123456789abcdef").unwrap();
        let store = dir(&state);
        fs::set_permissions(&store, fs::Permissions::from_mode(0o300)).unwrap();
        let all = list(&state);
        let result = remove(&state, &["live".into()], true);
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!all.errors.is_empty() && all.dangling == ["live"]);
        assert!(result.unwrap_err().to_string().contains("incomplete checkpoint listing"));
        assert!(fs::symlink_metadata(store.join("names/live")).is_ok());
        assert!(checkpoint.exists());
    }

    #[test]
    fn malformed_names_can_be_removed_without_following_targets() {
        let state = crate::test_util::TempDir::new("malformed-names");
        let checkpoint = unreadable(&state);
        let names = dir(&state).join(NAMES);
        for kind in ["file", "directory", "target", "outside"] {
            let path = names.join("bad");
            match kind {
                "file" => fs::write(&path, b"not a link").unwrap(),
                "directory" => {
                    fs::create_dir(&path).unwrap();
                    symlink(&checkpoint, path.join("keep")).unwrap();
                }
                "target" => symlink("..", &path).unwrap(),
                _ => symlink(&checkpoint, &path).unwrap(),
            }
            assert_eq!(list(&state).malformed.len(), 1);
            assert!(remove(&state, &["bad".into()], false).is_err());
            assert_eq!(remove(&state, &["bad".into()], true).unwrap(), [json!({"deleted": null, "name": "bad"})]);
            assert!(fs::symlink_metadata(&path).is_err());
            assert!(checkpoint.join("manifest.json").exists());
        }
        // Once there are no unreadable checkpoints, prune clears malformed names too.
        fs::remove_dir_all(&checkpoint).unwrap();
        fs::write(names.join("bad"), b"not a link").unwrap();
        symlink("..", names.join("broken")).unwrap();
        use std::os::unix::ffi::OsStrExt;
        fs::write(names.join(std::ffi::OsStr::from_bytes(b"bad\xff")), b"not a link").unwrap();
        assert_eq!(rows(&state, &[]).len(), 3);
        assert_eq!(prune(&state, Some(0)).unwrap().len(), 3);
        assert_eq!(fs::read_dir(names).unwrap().count(), 0);
    }

    #[test]
    fn rows_keep_individual_names_and_listing_error_directories() {
        let state = crate::test_util::TempDir::new("checkpoint-rows");
        let checkpoint = unreadable(&state);
        for name in ["z", "a"] {
            link(&state, name, "0123456789abcdef").unwrap();
        }
        let row = &rows(&state, &[])[0];
        assert_eq!(row["name"], "a");
        assert_eq!(row["names"], json!(["a", "z"]));
        assert_eq!(row["directory"], checkpoint.to_str().unwrap());
        assert!(row["error"].is_string());
        let names = dir(&state).join(NAMES);
        fs::remove_dir_all(&names).unwrap();
        fs::write(&names, b"not a directory").unwrap();
        let rows = rows(&state, &[]);
        let error = rows.iter().find(|row| row["id"].is_null()).unwrap();
        assert_eq!(error["directory"], names.to_str().unwrap());
        assert!(error["error"].as_str().unwrap().contains("listing"));
    }
}
