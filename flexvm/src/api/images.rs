//! Images as docker sees them: a template is an image, its generation's content id the image's id.

use crate::image::registry::{blob_path, sha256_hex};
use serde_json::Value;

use super::Api;
use crate::template::{Meta, Template};

/// A generation's metadata, if it is here.
pub fn meta(api: &Api, id: &str) -> Option<Meta> {
    let dir = Template::generation(&api.paths, id)?;
    serde_json::from_slice(&std::fs::read(dir.join("meta.json")).ok()?).ok()
}

/// The generation the template `name` links to now.
pub fn linked(api: &Api, name: &str) -> Option<String> {
    let link = std::fs::read_link(api.paths.templates.join(name)).ok()?;
    Some(link.file_name()?.to_string_lossy().into_owned())
}

/// What the image's config says of its app (`Env`, `Entrypoint`, `Cmd`, `WorkingDir`, `Labels`, ...), from its
/// config blob while the layer cache keeps it (`system prune` removes it) and it is the one pulled.
pub fn config(api: &Api, meta: &Meta) -> Option<Value> {
    let digest = &meta.image.as_ref()?.config_digest;
    let blob = std::fs::read(blob_path(&api.host.state.join("images/blobs"), digest).ok()?).ok()?;
    let config: Value = serde_json::from_slice(&blob).ok().filter(|_| sha256_hex(&blob) == *digest)?;
    Some(config["config"].clone())
}

pub fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect()
}

/// The app's argv as docker's `Entrypoint` and `Cmd`: the config's, when they are what the template runs
/// (a pull's `--entrypoint` or `--cmd` changed it otherwise); else it is all `Cmd`, as an image without an
/// entrypoint's.
pub fn app(argv: &[String], config: Option<&Value>) -> (Vec<String>, Vec<String>) {
    if let Some(c) = config {
        let (entrypoint, cmd) = (strings(&c["Entrypoint"]), strings(&c["Cmd"]));
        if entrypoint.iter().chain(&cmd).eq(argv) {
            return (entrypoint, cmd);
        }
    }
    (Vec::new(), argv.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_app_splits_as_its_config_does() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let c = json!({"Entrypoint": ["/docker-entrypoint.sh"], "Cmd": ["nginx", "-g", "daemon off;"]});
        let (e, cmd) = app(&argv(&["/docker-entrypoint.sh", "nginx", "-g", "daemon off;"]), Some(&c));
        assert_eq!((e, cmd), (argv(&["/docker-entrypoint.sh"]), argv(&["nginx", "-g", "daemon off;"])));
        // A pull's --cmd: no longer the config's.
        let (e, cmd) = app(&argv(&["/docker-entrypoint.sh", "sh"]), Some(&c));
        assert_eq!((e, cmd), (vec![], argv(&["/docker-entrypoint.sh", "sh"])));
        assert_eq!(app(&argv(&["sh"]), None), (vec![], argv(&["sh"])));
        assert_eq!(app(&[], Some(&json!({"Entrypoint": null, "Cmd": null}))), (vec![], vec![]));
    }
}
