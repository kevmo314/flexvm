//! flexvm's registry credentials. Only verified credentials are published, atomically and root-only.
use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use base64::Engine;
use serde_json::{json, Value};

use super::registry::Registry;
use super::Reference;
use crate::util::Result;
use crate::{bail, output};

fn registry(name: &str) -> Result<String> {
    let name = if name.is_empty() { "docker.io" } else { name };
    if name.contains(['/', '@', '?', '#']) || name.chars().any(char::is_whitespace) {
        bail!("registry must be a host with an optional port");
    }
    let reference = Reference::parse(&format!("{name}/login"))?;
    if reference.registry != name && !["docker.io", "index.docker.io", "registry-1.docker.io"].contains(&name) {
        bail!("bad registry {name:?}");
    }
    Ok(reference.registry)
}

fn read(state: &Path) -> Result<Value> {
    let file = match File::options().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(state.join("auth.json")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(json!({"auths": {}})),
        f => f?,
    };
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o7777 != 0o600 {
        bail!("auth.json must be a regular file owned by root with mode 0600");
    }
    Ok(serde_json::from_reader(file.take(1 << 20))?)
}

pub(super) fn credentials(state: &Path, registry: &str) -> Result<Option<String>> {
    Ok(read(state)?["auths"][registry]["auth"].as_str().map(String::from))
}

fn update(state: &Path, registry: &str, auth: Option<&str>) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("run flexvm as root to save credentials");
    }
    let parent = crate::host::Directory::open(state)?;
    let key = crate::host::keyed("registry-auth", &parent.stat()?, "");
    let _lock = crate::host::lock_at(crate::host::host_locks()?, &key, libc::LOCK_EX)?;
    let mut config = read(&parent.path)?;
    let auths = config["auths"].as_object_mut().ok_or("auth.json has no auths object")?;
    match auth {
        Some(auth) => {
            auths.insert(registry.into(), json!({"auth": auth}));
        }
        None => {
            auths.remove(registry);
        }
    }
    let tmp = parent.path.join(format!(".auth-{}", crate::util::random_hex(8)?));
    let result = (|| -> Result<()> {
        let mut file = File::options().write(true).create_new(true).mode(0o600).open(&tmp)?;
        // The umask can restrict creation further; the published mode is exactly 0600.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(&serde_json::to_vec(&config)?)?;
        file.sync_all()?;
        std::fs::rename(&tmp, parent.path.join("auth.json"))?;
        crate::util::sync_dir(&parent.path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

/// Restore terminal echo even if reading the password fails.
struct Echo {
    fd: i32,
    old: libc::termios,
}
impl Drop for Echo {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.old);
        }
    }
}

fn prompt(label: &str, secret: bool) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!("login needs --username and --password-stdin without a terminal");
    }
    output(format_args!("{label}: "))?;
    std::io::stdout().flush()?;
    let fd = std::io::stdin().as_raw_fd();
    let echo = if secret {
        let mut old = std::mem::MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(fd, old.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let old = unsafe { old.assume_init() };
        let mut new = old;
        new.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &new) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Some(Echo { fd, old })
    } else {
        None
    };
    let mut value = String::new();
    let result = std::io::stdin().read_line(&mut value);
    drop(echo);
    if secret {
        output(format_args!("\n"))?;
    }
    result?;
    Ok(value.trim_end_matches(['\r', '\n']).into())
}

pub fn login(state: &Path, name: &str, username: Option<&str>, password_stdin: bool) -> Result<()> {
    let registry = registry(name)?;
    let user = match username {
        Some(u) => u.into(),
        None => prompt("Username", false)?,
    };
    if user.is_empty() || user.contains([':', '\r', '\n']) {
        bail!("username must be nonempty and contain no colon or newline");
    }
    let password = if password_stdin {
        let mut value = String::new();
        std::io::stdin().take((1 << 20) + 1).read_to_string(&mut value)?;
        if value.len() > 1 << 20 {
            bail!("password exceeds 1 MiB");
        }
        value.trim_end_matches(['\r', '\n']).to_string()
    } else {
        prompt("Password", true)?
    };
    if password.is_empty() {
        bail!("password is empty");
    }
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    Registry::verify(&registry, &auth)?;
    update(state, &registry, Some(&auth))?;
    output(format_args!("Login succeeded for {registry}\n"))
}

pub fn logout(state: &Path, name: &str) -> Result<()> {
    let registry = registry(name)?;
    update(state, &registry, None)?;
    output(format_args!("Removed credentials for {registry}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_names_and_http_credentials() {
        assert_eq!(registry("").unwrap(), "registry-1.docker.io");
        assert_eq!(registry("index.docker.io").unwrap(), "registry-1.docker.io");
        assert_eq!(registry("ghcr.io:443").unwrap(), "ghcr.io:443");
        for name in ["https://ghcr.io", "ghcr.io/path", "a@b", "ghcr.io?x"] {
            assert!(registry(name).is_err());
        }
        assert!(Registry::verify("localhost:5000", "secret").unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn unsafe_auth_files_are_errors_and_http_never_loads_credentials() {
        let dir = crate::test_util::TempDir::new("unsafe-auth");
        std::fs::write(dir.join("auth.json"), b"not JSON").unwrap();
        assert!(credentials(&dir, "ghcr.io").is_err());
        assert!(Registry::with_state(Reference::parse("ghcr.io/o/a").unwrap(), &dir).is_err());
        assert!(Registry::with_state(Reference::parse("localhost:5000/a").unwrap(), &dir).is_ok());
        assert!(read(&dir).is_err());
    }

    #[test]
    fn credentials_are_private_and_logout_preserves_other_registries() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = crate::test_util::TempDir::new("auth");
        update(&dir, "ghcr.io", Some("first")).unwrap();
        update(&dir, "registry-1.docker.io", Some("second")).unwrap();
        assert_eq!(dir.join("auth.json").metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(credentials(&dir, "ghcr.io").unwrap().as_deref(), Some("first"));
        update(&dir, "ghcr.io", None).unwrap();
        assert_eq!(credentials(&dir, "ghcr.io").unwrap(), None);
        assert_eq!(credentials(&dir, "registry-1.docker.io").unwrap().as_deref(), Some("second"));
        std::fs::set_permissions(dir.join("auth.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&dir).is_err());
        std::fs::remove_file(dir.join("auth.json")).unwrap();
        std::os::unix::fs::symlink("missing", dir.join("auth.json")).unwrap();
        assert!(read(&dir).is_err());
    }
}
