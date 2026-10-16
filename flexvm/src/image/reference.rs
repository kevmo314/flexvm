//! Registry references, with Docker's defaulting rules: `nginx` = `docker.io/library/nginx:latest`.

use crate::bail;
use crate::util::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    pub reference: String,
}

impl Reference {
    pub fn parse(s: &str) -> Result<Reference> {
        let (name, digest) = s.split_once('@').map_or((s, None), |(n, d)| (n, Some(d)));
        let (name, tag) = name.rsplit_once(':').filter(|(_, t)| !t.contains('/')).map_or((name, None), |(n, t)| (n, Some(t)));
        if let Some(t) = tag {
            if t.is_empty() || t.len() > 128 || !t.bytes().enumerate().all(|(i, c)| c.is_ascii_alphanumeric() || c == b'_' || (i > 0 && b".-".contains(&c))) {
                bail!("bad tag in {s:?}");
            }
        }
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
        if repository.is_empty() || !repository.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-/".contains(c)) {
            bail!("bad image reference {s:?}");
        }
        let reference = match (digest, tag) {
            (Some(d), _) if !d.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit())) => {
                bail!("bad digest in {s:?}: only sha256 digests are supported")
            }
            (d, t) => d.or(t).unwrap_or("latest").to_string(),
        };
        Ok(Reference { registry, repository, reference })
    }

    /// Docker's short form of the repository: `nginx` for Docker Hub's `library/nginx`,
    /// `traefik/whoami` for its other repositories, `ghcr.io/org/app` elsewhere.
    pub fn familiar_repository(&self) -> String {
        match self.registry.as_str() {
            "registry-1.docker.io" => self.repository.strip_prefix("library/").filter(|r| !r.contains('/')).unwrap_or(&self.repository).to_string(),
            r => format!("{r}/{}", self.repository),
        }
    }

    pub fn is_digest(&self) -> bool {
        self.reference.starts_with("sha256:")
    }

    /// `ubuntu:24.04`, `nginx:latest`, `ghcr.io/org/app@sha256:...`.
    pub fn familiar(&self) -> String {
        let sep = if self.is_digest() { '@' } else { ':' };
        format!("{}{sep}{}", self.familiar_repository(), self.reference)
    }

    /// The name of the template pulled from this reference: its familiar form without a
    /// `:latest` tag, with `/` written `+` (which no reference has), so it is one file name
    /// and `from_template_name` gives the reference back.
    pub fn template_name(&self) -> String {
        let name = match self.reference.as_str() {
            "latest" => self.familiar_repository(),
            _ => self.familiar(),
        };
        name.replace('/', "+")
    }

    pub fn from_template_name(name: &str) -> Result<Reference> {
        Reference::parse(&name.replace('+', "/"))
    }

    /// The registry's host, without its port (or an IPv6 literal's brackets).
    pub fn host(&self) -> &str {
        match self.registry.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or(""),
            None => self.registry.split(':').next().unwrap_or(""),
        }
    }

    /// Base URL of the registry API. Plain HTTP only for this host's own: `localhost` or a loopback address.
    pub fn base_url(&self) -> String {
        let host = self.host();
        let loopback = host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
        let scheme = if loopback { "http" } else { "https" };
        format!("{scheme}://{}/v2/{}", self.registry, self.repository)
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sep = if self.is_digest() { '@' } else { ':' };
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
        let v6 = Reference::parse("[::1]:5000/x:y").unwrap();
        assert_eq!((v6.registry.as_str(), v6.repository.as_str(), v6.reference.as_str(), v6.host()), ("[::1]:5000", "x", "y", "::1"));
        assert_eq!(v6.base_url(), "http://[::1]:5000/v2/x");
        assert_eq!(Reference::parse("[::1]/x").unwrap().base_url(), "http://[::1]/v2/x");
        assert_eq!(Reference::parse("[2001:db8::1]:5000/x").unwrap().base_url(), "https://[2001:db8::1]:5000/v2/x");
        assert_eq!(Reference::parse("127.0.0.1:5000/x").unwrap().base_url(), "http://127.0.0.1:5000/v2/x");
        assert_eq!(Reference::parse("localhost/x").unwrap().base_url(), "http://localhost/v2/x");
        assert_eq!(Reference::parse("ghcr.io/o/a").unwrap().base_url(), "https://ghcr.io/v2/o/a");
        assert!(Reference::parse("nginx@sha256:abc").is_err());
    }

    #[test]
    fn tags_and_digests_follow_the_oci_grammar() {
        for tag in ["1.0+build1", "", ".x", "-x", "é", &"a".repeat(129)] {
            assert!(Reference::parse(&format!("app:{tag}")).is_err(), "{tag}");
            assert!(Reference::parse(&format!("app:{tag}@sha256:{}", "a".repeat(64))).is_err(), "{tag}");
        }
        for tag in ["_", "V1.0_build-1", &"a".repeat(128)] {
            let r = Reference::parse(&format!("app:{tag}")).unwrap();
            assert_eq!(Reference::from_template_name(&r.template_name()).unwrap(), r);
        }
        for hex in ["a".repeat(63), "a".repeat(65), format!("{}g", "a".repeat(63)), format!("{}/", "a".repeat(63)), format!("{}.", "a".repeat(63))] {
            assert!(Reference::parse(&format!("app@sha256:{hex}")).is_err(), "{hex}");
        }
        assert!(Reference::parse(&format!("app@sha256:{}", "aB09".repeat(16))).is_ok());
    }

    #[test]
    fn template_names_are_familiar_file_names_and_reversible() {
        let d = "sha256:".to_string() + &"b".repeat(64);
        let digest = format!("ghcr.io+org+app@{d}");
        for (r, name) in [
            ("ubuntu:24.04", "ubuntu:24.04"),
            ("docker.io/library/ubuntu:24.04", "ubuntu:24.04"),
            ("index.docker.io/ubuntu:24.04", "ubuntu:24.04"),
            ("nginx", "nginx"),
            ("nginx:latest", "nginx"),
            ("ci", "ci"),
            ("docker.io/traefik/whoami:v1", "traefik+whoami:v1"),
            ("ghcr.io/org/app:V1.2", "ghcr.io+org+app:V1.2"),
            (&format!("ghcr.io/org/app:v1@{d}"), &digest),
            ("localhost:5000/x", "localhost:5000+x"),
            ("localhost/x/y:z", "localhost+x+y:z"),
            ("public.ecr.aws/docker/library/busybox:1.36", "public.ecr.aws+docker+library+busybox:1.36"),
        ] {
            let parsed = Reference::parse(r).unwrap();
            assert_eq!(parsed.template_name(), name, "{r}");
            assert!(!name.contains('/'));
            assert_eq!(Reference::from_template_name(name).unwrap(), parsed, "{r}");
            assert_eq!(Reference::parse(&parsed.familiar()).unwrap(), parsed, "{r}");
        }
        assert_eq!(Reference::parse("nginx").unwrap().familiar(), "nginx:latest");
        assert_eq!(Reference::parse("quay.io/a/b").unwrap().familiar(), "quay.io/a/b:latest");
    }
}
