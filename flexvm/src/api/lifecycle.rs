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
    let record: Option<Record> = serde_json::from_value(v["docker"].clone()).ok();
    if v["state"] != "created" {
        api.run(&["rename", "--", &name, &to]).await?;
    }
    if let Some(mut r) = record {
        let created = v["state"] == "created";
        api.blocking(move |api| {
            let taken = api.host.alive(&to) || create::merge(api, crate::vms(&api.host)).iter().any(|v| v["name"] == to.as_str());
            if created && taken {
                return Ok(Err(Error::conflict(format!("Conflict. The container name \"/{to}\" is already in use"))));
            }
            r.name = to;
            if !create::store(api, &r, true)? {
                return Ok(Err(Error::conflict(format!("Conflict. The container name \"/{}\" is already in use", r.name))));
            }
            create::remove(api, &name);
            Ok(Ok(()))
        })
        .await??;
    }
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
    let mut deleted = Vec::new();
    for v in vms.iter().filter(|v| !state(v).running) {
        let labels = v["docker"]["config"]["Labels"].as_object().cloned().unwrap_or_default();
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
