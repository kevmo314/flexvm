//! Containers created, started, stopped, killed, paused, renamed and removed: each a command (`run -d`,
//! `start`, `stop`, `kill`, `pause`, `unpause`, `restart`, `rename`, `rm`), as docker's are.

use std::sync::Arc;

use hyper::StatusCode;
use serde_json::{json, Value};

use super::containers::{all, id_of, state};
use super::create::{self, Record};
use super::{empty, ok, Api, Error, Query, Reply};

/// The container `key` names: its name and how it is now.
async fn found(api: &Arc<Api>, key: &str) -> Result<(String, Value), Error> {
    let vms = all(api).await?;
    let v = super::containers::find(&vms, key)?.clone();
    Ok((v["name"].as_str().unwrap_or_default().to_string(), v))
}

/// `POST /containers/create?name=NAME`: the record of a `run` to come (`create::translate`), under NAME or
/// a name made up as `run` makes one up.
pub async fn create(api: &Arc<Api>, q: Query, body: Value) -> Reply {
    if let Some(p) = q.get("platform").filter(|p| !p.is_empty() && !matches!(*p, "linux" | "linux/amd64")) {
        return Err(Error::bad(format!("platform {p:?}: flexvm runs linux/amd64")));
    }
    let given = q.get("name").filter(|n| !n.is_empty()).map(|n| n.strip_prefix('/').unwrap_or(n).to_string());
    if let Some(n) = &given {
        crate::host::check_new_name(n).map_err(|e| Error::bad(e.to_string()))?;
    }
    let record = api
        .blocking(move |api| {
            std::fs::create_dir_all(&api.paths.templates)?;
            let _templates = crate::template::templates_lock(&api.paths, libc::LOCK_SH)?;
            for _ in 0..20 {
                let name = match &given {
                    Some(n) => n.clone(),
                    None => crate::host::generated_name(&api.host)?,
                };
                let taken = api.host.alive(&name) || create::merge(api, crate::vms(&api.host)).iter().any(|v| v["name"] == name.as_str());
                if !taken {
                    let r = match create::translate(api, &name, &body) {
                        Ok(r) => r,
                        Err(e) => return Ok(Err(e)),
                    };
                    if create::store(api, &r, true)? {
                        return Ok(Ok(r));
                    }
                }
                if given.is_some() {
                    return Ok(Err(Error::conflict(format!(
                        "Conflict. The container name \"/{name}\" is already in use by container \"{}\". You have to remove (or rename) that container to be able to reuse that name.",
                        id_of(&name)
                    ))));
                }
            }
            Ok(Err(Error::conflict("every name made up was taken meanwhile: give one")))
        })
        .await??;
    Ok(super::json(StatusCode::CREATED, &json!({"Id": id_of(&record.name), "Warnings": []})))
}

/// `run -d` of a created container's record; then the record says it started.
async fn run_created(api: &Arc<Api>, mut r: Record) -> Result<(), Error> {
    let mut words: Vec<String> = vec!["run".into(), "--detach".into(), "--name".into(), r.name.clone()];
    words.extend(r.run.iter().cloned());
    api.run(&words).await?;
    r.started = true;
    api.blocking(move |api| create::store(api, &r, false).map(drop)).await
}

/// `POST /containers/{id}/start`: a created container's `run -d`, a stopped or exited one's `start`.
pub async fn start(api: &Arc<Api>, key: &str, q: Query) -> Reply {
    if q.get("checkpoint").is_some_and(|c| !c.is_empty()) {
        return Err(Error::unsupported("start from a checkpoint"));
    }
    let (name, v) = found(api, key).await?;
    match v["state"].as_str().unwrap_or("") {
        "created" => {
            let r: Record = serde_json::from_value(v["docker"].clone()).map_err(|e| Error::from(crate::util::Error::from(e.to_string())))?;
            run_created(api, r).await?;
        }
        "paused" => return Err(Error::conflict(format!("cannot start a paused container {name}, try unpause instead"))),
        _ if state(&v).running => return empty(StatusCode::NOT_MODIFIED),
        _ => drop(api.run(&["start", "--", &name]).await?),
    }
    empty(StatusCode::NO_CONTENT)
}

/// `POST /containers/{id}/stop`: `flexvm stop`, which suspends it to disk (docker's next `start` resumes
/// it where it was). Its `t` is not needed: a suspend takes what it takes.
pub async fn stop(api: &Arc<Api>, key: &str, q: Query) -> Reply {
    if let Some(s) = q.get("signal").filter(|s| !s.is_empty()) {
        if crate::app::parse_signal(s).map_err(|e| Error::bad(e.to_string()))? != libc::SIGTERM {
            return Err(Error::unsupported(format!("stop with {s}: a stop suspends the VM (as SIGTERM to its process does)")));
        }
    }
    let (name, v) = found(api, key).await?;
    // A restarting one is stopped too: `flexvm stop` ends its restarts.
    let st = state(&v);
    if !st.running && st.status != "restarting" {
        return empty(StatusCode::NOT_MODIFIED);
    }
    api.run(&["stop", "--", &name]).await?;
    empty(StatusCode::NO_CONTENT)
}

/// `POST /containers/{id}/restart`: `flexvm restart` (a created container is started).
pub async fn restart(api: &Arc<Api>, key: &str) -> Reply {
    let (name, v) = found(api, key).await?;
    match v["state"].as_str() {
        Some("created") => return start(api, key, Query::parse("")).await,
        _ => drop(api.run(&["restart", "--", &name]).await?),
    }
    empty(StatusCode::NO_CONTENT)
}

/// `POST /containers/{id}/kill?signal=`: SIGKILL (docker's default) destroys the VM (`flexvm kill`); any
/// other signal goes to its app (`kill -s`).
pub async fn kill(api: &Arc<Api>, key: &str, q: Query) -> Reply {
    let signal = q.get("signal").filter(|s| !s.is_empty()).unwrap_or("KILL");
    let sig = crate::app::parse_signal(signal).map_err(|e| Error::bad(e.to_string()))?;
    let (name, v) = found(api, key).await?;
    if !state(&v).running {
        return Err(Error::conflict(format!("Cannot kill container: {name}: container {} is not running", id_of(&name))));
    }
    match sig {
        libc::SIGKILL => api.run(&["kill", "--", &name]).await?,
        _ => api.run(&["kill", "--signal", &sig.to_string(), "--", &name]).await?,
    };
    empty(StatusCode::NO_CONTENT)
}

/// `POST /containers/{id}/pause` and `unpause`.
pub async fn pause(api: &Arc<Api>, key: &str, pause: bool) -> Reply {
    let (name, v) = found(api, key).await?;
    let st = state(&v);
    match (pause, st.paused) {
        (true, true) => return Err(Error::conflict(format!("container {} is already paused", id_of(&name)))),
        (false, false) => return Err(Error::conflict(format!("container {} is not paused", id_of(&name)))),
        _ if !st.running => return Err(Error::conflict(format!("container {} is not running", id_of(&name)))),
        _ => {}
    }
    api.run(&[if pause { "pause" } else { "unpause" }, "--", &name]).await?;
    empty(StatusCode::NO_CONTENT)
}

/// `POST /containers/{id}/rename?name=NEW`: `flexvm rename`, its record moved with it.
pub async fn rename(api: &Arc<Api>, key: &str, q: Query) -> Reply {
    let to = q.get("name").filter(|n| !n.is_empty()).ok_or_else(|| Error::bad("rename needs name"))?;
    let to = to.strip_prefix('/').unwrap_or(to).to_string();
    crate::host::check_new_name(&to).map_err(|e| Error::bad(e.to_string()))?;
    let (name, v) = found(api, key).await?;
    if name == to {
        return empty(StatusCode::NO_CONTENT);
    }
    let api = api.clone();
    tokio::spawn(async move {
        rename_to(&api, name, &v, to, |from, to| {
            let api = api.clone();
            async move { api.run(&["rename", "--", &from, &to]).await.map(drop) }
        })
        .await
    })
    .await
    .map_err(|e| Error::from(crate::util::Error::from(e.to_string())))?
}

async fn rename_to<F, Fut>(api: &Arc<Api>, name: String, v: &Value, to: String, move_vm: F) -> Reply
where
    F: Fn(String, String) -> Fut + Send,
    Fut: std::future::Future<Output = Result<(), Error>> + Send,
{
    // Reserve before touching the VM, including for VMs that have no Docker record.
    let record: Option<Record> = serde_json::from_value(v["docker"].clone()).ok();
    let mut reserved = record.clone().unwrap_or(Record { started: true, ..Record::default() });
    reserved.name = to.clone();
    reserved.reserved = true;
    reserved.reservation_owner = Some(crate::host::Ident::me());
    let reservation = reserved.clone();
    api.blocking(move |api| {
        let vms = create::merge(api, crate::vms(&api.host));
        let taken = api.host.alive(&reservation.name) || vms.iter().any(|v| v["name"] == reservation.name);
        if taken || !create::store(api, &reservation, true)? {
            return Ok(Err(Error::conflict(format!("Conflict. The container name \"/{}\" is already in use", reservation.name))));
        }
        Ok(Ok(()))
    })
    .await??;
    let moved = v["state"] != "created";
    let mut stranded = false;
    let result = async {
        if moved {
            move_vm(name.clone(), to.clone()).await?;
        }
        reserved.reserved = false;
        reserved.reservation_owner = None;
        let published = reserved.clone();
        if record.is_some() {
            if let Err(e) = api.blocking(move |api| create::store(api, &published, false).map(drop)).await {
                if moved {
                    if let Err(rollback) = move_vm(to.clone(), name.clone()).await {
                        stranded = true;
                        // Keep the destination config even if publication is still unavailable.
                        api.blocking(move |api| create::store(api, &reserved, false).map(drop)).await?;
                        return Err(rollback);
                    }
                }
                return Err(e);
            }
        }
        Ok(())
    }
    .await;
    let success = result.is_ok();
    api.blocking(move |api| {
        if (!success && !stranded) || record.is_none() {
            create::remove(api, &to);
        }
        if success {
            create::remove(api, &name);
        }
        Ok(())
    })
    .await?;
    result?;
    empty(StatusCode::NO_CONTENT)
}

/// `DELETE /containers/{id}?force`: `flexvm rm [-f]`; a created container's record alone.
pub async fn remove(api: &Arc<Api>, key: &str, q: Query) -> Reply {
    if q.flag("link", false)? {
        return Err(Error::unsupported("links"));
    }
    let force = q.flag("force", false)?;
    let (name, v) = found(api, key).await?;
    if v["state"] != "created" {
        if state(&v).running && !force {
            return Err(Error::conflict(format!(
                "cannot remove container \"/{name}\": container is running: stop the container before removing or force remove"
            )));
        }
        let mut words = vec!["rm"];
        if force {
            words.push("--force");
        }
        words.extend(["--", &name]);
        api.run(&words).await?;
    }
    api.blocking(move |api| {
        create::remove(api, &name);
        Ok(())
    })
    .await?;
    empty(StatusCode::NO_CONTENT)
}

/// `POST /containers/prune`: every container that is not running (exited, dead or created), as `rm` removes
/// each; `filters` by `label` only.
pub async fn prune(api: &Arc<Api>, q: Query) -> Reply {
    let filters = q.filters()?;
    if let Some((k, _)) = filters.iter().find(|(k, _)| !matches!(k.as_str(), "label" | "label!")) {
        return Err(Error::unsupported(format!("prune filter {k:?}")));
    }
    let vms = all(api).await?;
    let candidates = api
        .blocking(move |api| {
            Ok(vms
                .into_iter()
                .filter(|v| !state(v).running)
                .map(|v| {
                    let labels = super::containers::Detail::read(api, &v).labels;
                    (v, labels)
                })
                .collect::<Vec<_>>())
        })
        .await?;
    let mut deleted = Vec::new();
    for (v, labels) in candidates {
        let has = |l: &str| match l.split_once('=') {
            Some((k, val)) => labels.get(k).and_then(Value::as_str) == Some(val),
            None => labels.contains_key(l),
        };
        if !filters.iter().all(|(k, l)| (k == "label") == has(l)) {
            continue;
        }
        let name = v["name"].as_str().unwrap_or_default();
        if remove(api, name, Query::parse("")).await.is_ok() {
            deleted.push(id_of(name));
        }
    }
    ok(&json!({"ContainersDeleted": deleted, "SpaceReclaimed": 0}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use create::tests::fixture;

    #[tokio::test]
    async fn rename_reserves_created_names_before_moving_any_vm() {
        let (_d, api) = fixture();
        let a = create::translate(&api, "a", &json!({"Image": "image"})).unwrap();
        let b = create::translate(&api, "b", &json!({"Image": "image", "Labels": {"owner": "b"}})).unwrap();
        create::store(&api, &a, true).unwrap();
        create::store(&api, &b, true).unwrap();
        for docker in [json!(a), Value::Null] {
            let v = json!({"name": "a", "state": "running", "docker": docker});
            let e = rename_to(&api, "a".into(), &v, "b".into(), |_, _| async { panic!("must not move VM") }).await.unwrap_err();
            assert_eq!(e.status, StatusCode::CONFLICT);
            assert_eq!(create::load(&api, "a"), Some(a.clone()));
            assert_eq!(create::load(&api, "b"), Some(b.clone()));
        }
    }

    #[tokio::test]
    async fn rename_releases_reservation_on_cli_failure_and_rolls_back_store_failure() {
        let (_d, api) = fixture();
        let a = create::translate(&api, "a", &json!({"Image": "image"})).unwrap();
        create::store(&api, &a, true).unwrap();
        let v = json!({"name": "a", "state": "running", "docker": a});
        let e = rename_to(&api, "a".into(), &v, "b".into(), |_, _| async {
            assert!(create::load(&api, "b").unwrap().reserved);
            assert!(create::merge(&api, vec![]).iter().all(|v| v["name"] != "b"));
            assert!(create::load(&api, "b").is_some(), "listing must not remove the reservation");
            Err(Error::bad("CLI failed"))
        })
        .await
        .unwrap_err();
        assert_eq!(e.message, "CLI failed");
        assert_eq!(create::load(&api, "a"), Some(a.clone()));
        assert!(create::load(&api, "b").is_none());

        let calls = std::sync::Mutex::new(Vec::new());
        let path = api.host.state.join("api/containers/b.json");
        rename_to(&api, "a".into(), &v, "b".into(), |from, to| {
            let (calls, path) = (&calls, &path);
            async move {
                calls.lock().unwrap().push((from.to_string(), to.to_string()));
                if from == "a" {
                    std::fs::remove_file(path).unwrap();
                    std::fs::create_dir(path).unwrap(); // Force final record publication to fail.
                } else {
                    std::fs::remove_dir(path).unwrap();
                }
                Ok(())
            }
        })
        .await
        .unwrap_err();
        assert_eq!(*calls.lock().unwrap(), [("a".into(), "b".into()), ("b".into(), "a".into())]);
        assert_eq!(create::load(&api, "a"), Some(a));
        assert!(create::load(&api, "b").is_none());
    }

    #[tokio::test]
    async fn failed_rename_rollback_keeps_the_destination_config() {
        let (_d, api) = fixture();
        let a = create::translate(&api, "a", &json!({"Image": "image", "Labels": {"keep": "config"}})).unwrap();
        create::store(&api, &a, true).unwrap();
        let v = json!({"name": "a", "state": "running", "docker": a});
        let path = api.host.state.join("api/containers/b.json");
        let e = rename_to(&api, "a".into(), &v, "b".into(), |from, _| {
            let path = &path;
            async move {
                if from == "a" {
                    std::fs::remove_file(path).unwrap();
                    std::fs::create_dir(path).unwrap();
                    Ok(())
                } else {
                    std::fs::remove_dir(path).unwrap();
                    Err(Error::bad("rollback failed"))
                }
            }
        })
        .await
        .unwrap_err();
        assert_eq!(e.message, "rollback failed");
        let b = create::load(&api, "b").unwrap();
        assert_eq!(b.config, a.config);
        assert!(!b.reserved);
    }

    #[tokio::test]
    async fn rename_moves_created_records_without_a_vm() {
        let (_d, api) = fixture();
        let a = create::translate(&api, "a", &json!({"Image": "image"})).unwrap();
        create::store(&api, &a, true).unwrap();
        rename(&api, "a", Query::parse("name=b")).await.unwrap();
        assert!(create::load(&api, "a").is_none());
        let mut b = a;
        b.name = "b".into();
        assert_eq!(create::load(&api, "b"), Some(b));
    }

    #[tokio::test]
    async fn prune_uses_image_labels_and_container_overrides() {
        let (_d, api) = fixture();
        for (name, labels) in [("inherited", json!({})), ("overridden", json!({"keep": "container"}))] {
            let r = create::translate(&api, name, &json!({"Image": "image", "Labels": labels})).unwrap();
            create::store(&api, &r, true).unwrap();
        }
        prune(&api, Query::parse(r#"filters={"label!":["keep"]}"#)).await.unwrap();
        assert!(create::load(&api, "inherited").is_some());
        assert!(create::load(&api, "overridden").is_some());
        prune(&api, Query::parse(r#"filters={"label":["keep=image"]}"#)).await.unwrap();
        assert!(create::load(&api, "inherited").is_none());
        assert!(create::load(&api, "overridden").is_some());
        prune(&api, Query::parse(r#"filters={"label!":["keep=image"]}"#)).await.unwrap();
        assert!(create::load(&api, "overridden").is_none());
    }
}
