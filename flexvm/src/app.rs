//! A VM follows its image's app (its entrypoint and command): when the app exits, the VM exits with
//! its status, unless `run --keep`. A background VM leaves an `exited` record (`RUN/vms/NAME.exited`,
//! `Exited`) that `ps -a` lists, `rm` removes and `start` runs again; `run --rm` leaves none.
//!
//! A VM has no disk of its own: its root is the image's read-only filesystem with an overlay in guest
//! memory, so what it wrote ends with it (a suspend keeps it, in its memory). `start` of an exited VM
//! is therefore a new run of its image's current template, under its name, with what it was run with
//! (`RunSpec`, its `-p` ports included, its command, `--cpus`/`--memory`).

use std::net::Ipv4Addr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::bail;
use crate::image::ImageMeta;
use crate::util::Result;

/// What `run` was given for the VM beyond its image: kept with the VM as a unit (in a suspended
/// checkpoint, a migration, a claim of a standby VM and its exited record).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunSpec {
    /// `-e K=V` and `--env-file`: over the image's environment, by key.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// `--entrypoint`: the app's argv instead of the image's entrypoint and command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// `--keep`: the VM stays up once its app exits.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub keep: bool,
    /// `--rm`: a background VM leaves no exited record.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub rm: bool,
    /// `--ip`: the address asked for (a rerun asks for it again; otherwise it gets the next free one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<Ipv4Addr>,
    /// `-p`: forwarded while the VM runs on this host. Neither a migration (`moving`) nor a
    /// restore of a checkpoint (`run --checkpoint` gives its own) takes them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<crate::ports::Port>,
    /// `-i`: the app's stdin stays open, for `attach` (and the foreground `run -i` that is one).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stdin: bool,
    /// `-t`: the app runs on a pty.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub tty: bool,
}

/// The most of the app's settings sent to the guest (hex-encoded on its request line).
const MAX_SETTINGS: usize = 64 << 10;

impl RunSpec {
    pub fn is_default(&self) -> bool {
        *self == RunSpec::default()
    }

    /// The app's settings in app.conf's form (`arg`, `env` lines), as the guest's `APP` takes them.
    pub fn app_settings(&self) -> String {
        let mut s = String::new();
        for a in self.entrypoint.iter().flatten() {
            s += &format!("arg {}\n", crate::image::escape(a));
        }
        for kv in &self.env {
            s += &format!("env {}\n", crate::image::escape(kv));
        }
        for (on, line) in [(self.stdin, "stdin\n"), (self.tty, "tty\n")] {
            if on {
                s += line;
            }
        }
        s
    }

    /// What goes with the VM to another host: its forwards stay here, as host-local proxies.
    pub fn moving(&self) -> RunSpec {
        RunSpec { ports: Vec::new(), ..self.clone() }
    }

    pub fn changes_app(&self) -> bool {
        self.entrypoint.is_some() || !self.env.is_empty() || self.stdin || self.tty
    }

    /// Whether the VM has an app to follow (and start at run).
    pub fn has_app(&self, image: Option<&ImageMeta>) -> bool {
        self.entrypoint.is_some() || image.is_some_and(|i| i.has_app())
    }

    /// Whether `run` starts the app (an image's warm app runs already, in the snapshot).
    pub fn starts_app(&self, image: Option<&ImageMeta>) -> bool {
        self.entrypoint.is_some() || image.is_some_and(|i| i.starts_at_run())
    }

    /// Refused before anything starts: what the template's app cannot take.
    pub fn check(&self, image: Option<&ImageMeta>) -> Result<()> {
        if self.entrypoint.as_ref().is_some_and(|e| e.is_empty() || e[0].is_empty()) {
            bail!("--entrypoint needs a program");
        }
        for kv in &self.env {
            validate_env(kv)?;
        }
        if !self.changes_app() {
            return Ok(());
        }
        match image {
            None => bail!("-e, --env-file, --entrypoint, -i and -t apply to an image's app; this template is not an image's"),
            Some(i) if i.warm => {
                bail!("the image's app starts before its snapshot (pull --warm), so -e, --env-file, --entrypoint, -i and -t cannot change it per run")
            }
            Some(i) if (self.stdin || self.tty) && !self.has_app(Some(i)) => bail!("-i and -t apply to the image's app, and it has none: give CMD"),
            Some(_) if self.app_settings().len() > MAX_SETTINGS => bail!("-e, --env-file and --entrypoint come to more than {} KiB", MAX_SETTINGS >> 10),
            Some(_) => Ok(()),
        }
    }

    /// The program the app runs, for the hint.
    pub fn program(&self, image: Option<&ImageMeta>) -> String {
        let argv = self.entrypoint.as_deref().or(image.map(|i| i.argv.as_slice())).unwrap_or_default();
        let first = argv.first().map(String::as_str).unwrap_or("the app");
        first.rsplit('/').next().unwrap_or(first).to_string()
    }
}

/// The status of the guest's app log's last message (`exited <code> <offset>`), if it exited.
pub fn exit_status(status: &str) -> Option<i32> {
    status.strip_prefix("exited ")?.split_whitespace().next()?.parse().ok()
}

/// An app that exits this soon after it started may have wanted a terminal (a shell, say).
pub const AT_ONCE: Duration = Duration::from_millis(1200);

/// Said when the app exited at once without a terminal (`AT_ONCE`).
pub fn hint(program: &str, image: &str) -> String {
    format!("{program} exited at once (it needs a terminal?): use flexvm run -it {image}")
}

/// `RUN/vms/NAME.exited`: a background VM whose command or app exited, and how to run it again.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Exited {
    /// Its command's or app's exit status (128+signal for a signal).
    pub status: i32,
    pub template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    pub resources: crate::vm::Resources,
    /// Its `-p` ports included: forwarded again when it runs again.
    pub spec: RunSpec,
    /// When it exited (seconds since the epoch).
    pub at: u64,
}

impl Exited {
    pub fn new(status: i32, template: String, cmd: Option<String>, resources: crate::vm::Resources, spec: RunSpec, at: u64) -> Exited {
        Exited { status, template, cmd, resources, spec, at }
    }

    pub fn read(path: &std::path::Path) -> Result<Exited> {
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()).into())
    }
}

/// Environment overrides: a nonempty key, with or without a value; neither may contain NUL.
pub fn validate_env(kv: &str) -> Result<()> {
    if kv.split('=').next().is_none_or(str::is_empty) || kv.contains('\0') {
        bail!("bad environment variable {kv:?}: give K or K=V");
    }
    Ok(())
}

/// `--env-file`: docker's form. `K=V` lines; `#` comment lines and blank ones are skipped; a bare
/// `K` takes `K` from this environment (`lookup`), and is left out if it has none there.
pub fn parse_env_file(text: &str, lookup: impl Fn(&str) -> Option<String>) -> Result<Vec<String>> {
    let mut env = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_once('=') {
            Some((k, _)) if k.is_empty() || k.contains(char::is_whitespace) => bail!("line {}: bad variable name {k:?}", i + 1),
            Some(_) => env.push(line.to_string()),
            None if line.trim_end().contains(char::is_whitespace) => bail!("line {}: bad variable name {:?}", i + 1, line.trim_end()),
            None => env.extend(lookup(line.trim_end()).map(|v| format!("{}={v}", line.trim_end()))),
        }
    }
    Ok(env)
}

/// `kill -s`: a signal's name (`TERM`, `SIGTERM`, any case) or number.
pub fn parse_signal(s: &str) -> Result<i32> {
    const NAMES: &[(&str, i32)] = &[
        ("HUP", libc::SIGHUP),
        ("INT", libc::SIGINT),
        ("QUIT", libc::SIGQUIT),
        ("ILL", libc::SIGILL),
        ("TRAP", libc::SIGTRAP),
        ("ABRT", libc::SIGABRT),
        ("IOT", libc::SIGIOT),
        ("BUS", libc::SIGBUS),
        ("FPE", libc::SIGFPE),
        ("KILL", libc::SIGKILL),
        ("USR1", libc::SIGUSR1),
        ("SEGV", libc::SIGSEGV),
        ("USR2", libc::SIGUSR2),
        ("PIPE", libc::SIGPIPE),
        ("ALRM", libc::SIGALRM),
        ("TERM", libc::SIGTERM),
        ("STKFLT", libc::SIGSTKFLT),
        ("CHLD", libc::SIGCHLD),
        ("CONT", libc::SIGCONT),
        ("STOP", libc::SIGSTOP),
        ("TSTP", libc::SIGTSTP),
        ("TTIN", libc::SIGTTIN),
        ("TTOU", libc::SIGTTOU),
        ("URG", libc::SIGURG),
        ("XCPU", libc::SIGXCPU),
        ("XFSZ", libc::SIGXFSZ),
        ("VTALRM", libc::SIGVTALRM),
        ("PROF", libc::SIGPROF),
        ("WINCH", libc::SIGWINCH),
        ("IO", libc::SIGIO),
        ("POLL", libc::SIGPOLL),
        ("PWR", libc::SIGPWR),
        ("SYS", libc::SIGSYS),
    ];
    if let Ok(n) = s.parse::<i32>() {
        return match n {
            1..=64 => Ok(n),
            _ => bail!("bad signal {s:?}: 1 to 64"),
        };
    }
    let upper = s.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    NAMES.iter().find(|(n, _)| *n == name).map(|&(_, sig)| sig).ok_or_else(|| format!("bad signal {s:?}: give a name (TERM, HUP, ...) or a number").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(argv: &[&str], warm: bool) -> ImageMeta {
        serde_json::from_value(serde_json::json!({
            "source": "x", "digest": "d", "config_digest": "c", "app_conf": "", "argv": argv, "warm": warm,
        }))
        .unwrap()
    }

    #[test]
    fn settings_are_app_conf_lines_escaped() {
        let s = RunSpec {
            env: vec!["A=1".into(), "B=x\ny\\z".into()],
            entrypoint: Some(vec!["/bin/sh".into(), "-c".into(), "echo a\nb".into()]),
            ..Default::default()
        };
        assert_eq!(s.app_settings(), "arg /bin/sh\narg -c\narg echo a\\nb\nenv A=1\nenv B=x\\ny\\\\z\n");
        assert_eq!(RunSpec::default().app_settings(), "");
        assert_eq!(RunSpec { stdin: true, tty: true, ..Default::default() }.app_settings(), "stdin\ntty\n");
    }

    #[test]
    fn the_app_is_the_entrypoint_or_the_images() {
        let (none, nginx, warm) = (image(&[], false), image(&["/usr/sbin/nginx", "-g"], false), image(&["srv"], true));
        let plain = RunSpec::default();
        let entry = RunSpec { entrypoint: Some(vec!["/bin/sleep".into(), "1".into()]), ..Default::default() };
        assert!(!plain.has_app(Some(&none)) && !plain.starts_app(Some(&none)), "no entrypoint and no command: it idles");
        assert!(plain.has_app(Some(&nginx)) && plain.starts_app(Some(&nginx)));
        assert!(plain.has_app(Some(&warm)) && !plain.starts_app(Some(&warm)), "a warm app runs already");
        assert!(entry.has_app(Some(&none)) && entry.starts_app(Some(&none)));
        assert_eq!((plain.program(Some(&nginx)), entry.program(Some(&nginx)), plain.program(Some(&none))), ("nginx".into(), "sleep".into(), "the app".into()));
        assert_eq!(hint("bash", "ubuntu:24.04"), "bash exited at once (it needs a terminal?): use flexvm run -it ubuntu:24.04");
    }

    #[test]
    fn what_a_template_cannot_take_is_refused() {
        let env = RunSpec { env: vec!["A=1".into()], ..Default::default() };
        assert!(env.check(Some(&image(&["x"], false))).is_ok());
        assert!(env.check(Some(&image(&["x"], true))).unwrap_err().to_string().contains("--warm"));
        assert!(env.check(None).unwrap_err().to_string().contains("not an image's"));
        let it = RunSpec { stdin: true, tty: true, ..Default::default() };
        assert!(it.check(Some(&image(&["bash"], false))).is_ok());
        assert!(it.check(Some(&image(&["bash"], true))).unwrap_err().to_string().contains("--warm"));
        assert!(it.check(Some(&image(&[], false))).unwrap_err().to_string().contains("give CMD"), "no app to talk to");
        assert!(RunSpec { keep: true, rm: true, ..Default::default() }.check(None).is_ok(), "only app settings need an image");
        for bad in [vec![], vec![String::new()]] {
            assert!(RunSpec { entrypoint: Some(bad), ..Default::default() }.check(Some(&image(&[], false))).is_err());
        }
        for bad in ["=1", "", "=", "K\0", "K=bad\0value", "NOVALUE"] {
            let r = RunSpec { env: vec![bad.into()], ..Default::default() }.check(Some(&image(&[], false)));
            assert_eq!(r.is_err(), bad != "NOVALUE", "{bad:?}");
        }
        let huge = RunSpec { env: vec![format!("A={}", "x".repeat(MAX_SETTINGS))], ..Default::default() };
        assert!(huge.check(Some(&image(&[], false))).unwrap_err().to_string().contains("KiB"));
    }

    #[test]
    fn the_spec_and_record_round_trip_and_default() {
        let ports: Vec<crate::ports::Port> = vec!["8080:80".parse().unwrap(), "127.0.0.1:53:53/udp".parse().unwrap()];
        let s = RunSpec {
            env: vec!["A=1".into()],
            entrypoint: Some(vec!["x".into()]),
            keep: true,
            rm: true,
            ip: Some("10.0.0.9".parse().unwrap()),
            ports: ports.clone(),
            stdin: true,
            tty: true,
        };
        assert_eq!(serde_json::from_value::<RunSpec>(serde_json::to_value(&s).unwrap()).unwrap(), s);
        assert_eq!(serde_json::to_string(&RunSpec::default()).unwrap(), "{}");
        assert_eq!(serde_json::from_str::<RunSpec>("{}").unwrap(), RunSpec::default());
        // A migration takes everything but the forwards.
        assert_eq!(s.moving(), RunSpec { ports: Vec::new(), ..s.clone() });
        assert_eq!(RunSpec { ports: ports.clone(), ..Default::default() }.moving(), RunSpec::default());
        let e = Exited::new(3, "t".into(), None, Default::default(), s.clone(), 5);
        let dir = crate::test_util::TempDir::new("exited-record");
        std::fs::write(dir.join("x.exited"), serde_json::to_vec(&e).unwrap()).unwrap();
        assert_eq!(Exited::read(&dir.join("x.exited")).unwrap(), e);
        assert!(serde_json::to_value(&e).unwrap().get("ports").is_none(), "the ports are written once, in the spec");
        std::fs::write(dir.join("z.exited"), "garbage").unwrap();
        assert!(Exited::read(&dir.join("z.exited")).is_err());
    }

    #[test]
    fn env_files_read_as_docker_reads_them() {
        let lookup = |k: &str| (k == "HOME_SET").then(|| "/root".to_string());
        let env = parse_env_file("# comment\n\nA=1\n  B=two words\nC=\nD==x\nHOME_SET\nUNSET\nE=#not a comment\n", lookup).unwrap();
        assert_eq!(env, ["A=1", "B=two words", "C=", "D==x", "HOME_SET=/root", "E=#not a comment"]);
        assert!(parse_env_file("=1\n", lookup).unwrap_err().to_string().contains("line 1"));
        assert!(parse_env_file("A=1\nBAD KEY=1\n", lookup).unwrap_err().to_string().contains("line 2"));
        assert!(parse_env_file("BAD KEY\n", lookup).is_err());
    }

    #[test]
    fn an_exit_is_told_by_the_logs_last_message() {
        assert_eq!(exit_status("exited 3 1234"), Some(3));
        assert_eq!(exit_status("exited 143 0"), Some(143));
        for other in ["idle 0", "running 5 10", "exited", "exited x 1", ""] {
            assert_eq!(exit_status(other), None, "{other}");
        }
    }

    #[test]
    fn signals_by_name_or_number() {
        for (s, want) in
            [("TERM", libc::SIGTERM), ("sigterm", libc::SIGTERM), ("SIGHUP", libc::SIGHUP), ("kill", 9), ("9", 9), ("usr1", libc::SIGUSR1), ("64", 64)]
        {
            assert_eq!(parse_signal(s).unwrap(), want, "{s}");
        }
        for bad in ["0", "65", "-1", "", "SIG", "TERMX", "SIGSIGTERM"] {
            assert!(parse_signal(bad).is_err(), "{bad}");
        }
    }
}
