//! Registry references, with Docker's defaulting rules:
//! `nginx` = `docker.io/library/nginx:latest`.

use crate::bail;
use crate::util::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Host (and port) to talk to, e.g. `registry-1.docker.io` or `ghcr.io`.
    pub registry: String,
    pub repository: String,
    /// A tag or a `sha256:` digest.
    pub reference: String,
}

impl Reference {
    pub fn parse(s: &str) -> Result<Reference> {
        let (name, digest) = match s.split_once('@') {
            Some((n, d)) => (n, Some(d)),
            None => (s, None),
        };
        let (name, tag) = match name.rsplit_once(':') {
            Some((n, t)) if !t.contains('/') => (n, Some(t)),
            _ => (name, None),
        };
        let (domain, path) = match name.split_once('/') {
            Some((d, p)) if d.contains('.') || d.contains(':') || d == "localhost" => (d, p.to_string()),
            _ => ("docker.io", name.to_string()),
        };
        let (registry, repository) = match domain {
            "docker.io" | "index.docker.io" | "registry-1.docker.io" => {
                let repo = if path.contains('/') { path } else { format!("library/{path}") };
                ("registry-1.docker.io".to_string(), repo)
            }
            d => (d.to_string(), path),
        };
        if repository.is_empty()
            || !repository.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-/".contains(c))
        {
            bail!("bad image reference {s:?}");
        }
        let reference = match (digest, tag) {
            (Some(d), _) => {
                if !d.starts_with("sha256:") || d.len() != 71 {
                    bail!("bad digest in {s:?}: only sha256 digests are supported");
                }
                d.to_string()
            }
            (None, Some(t)) => t.to_string(),
            (None, None) => "latest".to_string(),
        };
        Ok(Reference { registry, repository, reference })
    }

    /// Base URL of the registry API. Plain HTTP only for local registries.
    pub fn base_url(&self) -> String {
        let host = self.registry.split(':').next().unwrap_or("");
        let scheme = if host == "localhost" || host == "127.0.0.1" { "http" } else { "https" };
        format!("{scheme}://{}/v2/{}", self.registry, self.repository)
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sep = if self.reference.starts_with("sha256:") { '@' } else { ':' };
        write!(f, "{}/{}{sep}{}", self.registry, self.repository, self.reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> (String, String, String) {
        let r = Reference::parse(s).unwrap();
        (r.registry, r.repository, r.reference)
    }

    #[test]
    fn defaults() {
        let hub = |repo: &str, r: &str| ("registry-1.docker.io".to_string(), repo.to_string(), r.to_string());
        assert_eq!(p("nginx"), hub("library/nginx", "latest"));
        assert_eq!(p("nginx:1.27"), hub("library/nginx", "1.27"));
        assert_eq!(p("docker.io/traefik/whoami"), hub("traefik/whoami", "latest"));
        let d = "sha256:".to_string() + &"a".repeat(64);
        assert_eq!(p(&format!("ghcr.io/org/app@{d}")), ("ghcr.io".into(), "org/app".into(), d.clone()));
        assert_eq!(p(&format!("ghcr.io/org/app:v1@{d}")).2, d);
        assert_eq!(p("localhost:5000/x:y"), ("localhost:5000".into(), "x".into(), "y".into()));
        assert_eq!(p("gcr.io/distroless/static"), ("gcr.io".into(), "distroless/static".into(), "latest".into()));
        assert!(Reference::parse("Nginx").is_err());
        assert!(Reference::parse("nginx@sha256:abc").is_err());
    }
}
