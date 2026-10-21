#![deny(clippy::print_stderr)]

mod app;
mod artifacts;
mod attach;
mod bench;
mod checkpoint;
mod compat;
mod containers;
mod cow;
mod crc32c;
mod fc;
mod gc;
mod guest;
mod hold;
mod host;
mod hostmem;
mod image;
mod lifecycle;
mod limit;
mod listen;
mod management;
mod migrate;
mod net;
mod ports;
mod socket;
mod standby;
mod template;
mod uffd;
mod util;
mod vm;
mod vmproc;

use std::io::{BufReader, IsTerminal, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::host::Host;
use crate::template::Paths;
use crate::util::{proc_kb, recv_json, Result};
use crate::vmproc::Start;

const USAGE: &str = concat!(
    "\
flexvm: elastic Firecracker microVMs with post-copy live migration

  flexvm run [OPTIONS] IMAGE [CMD...]
                                     start a VM of IMAGE (pulled first if missing); the process is the VM
      --name NAME                    its name (without: one is made up, as docker does)
      -d, --detach                   in the background: prints {\"name\", \"ip\", \"pid\", ...} once it runs
      -i, --interactive              keep the app's stdin open, and attach this one to it (with CMD, CMD
                                     is the app: its argv, as docker's); -t, --tty: on a pty, this terminal
                                     raw (Ctrl-P Ctrl-Q detaches); with -d, to attach to later
      -p [IP:]HOST_PORT:VM_PORT[/tcp|/udp]
                                     forward a host port here (repeatable; default 0.0.0.0 and [::], TCP)
                                     IP: IPv4 or [IPv6]; IPv4 alone if IPv6 is unavailable
      --ip IP                        its address (without: the next free one)
      --cpus N                       cap its CPU time at N CPUs (1.5: one and a half); its vCPUs are IMAGE's
      -m, --memory SIZE              cap its memory growth (512m, 2g; plain bytes, as docker): from IMAGE's
                                     boot memory plus what its snapshot plugged, up to its ceiling
      -e, --env K=V                  set an environment variable of IMAGE's app (again for more; a bare K
                                     takes this one's); --env-file FILE: docker's KEY=VALUE lines
      --entrypoint CMD               the app to run instead of IMAGE's entrypoint and command (words, or
                                     a JSON array)
      --keep                         stay up once the app exits (without: the VM exits with it, with its
                                     status; a background one is then listed exited until rm or start)
      --rm                           leave no exited record once a background VM exits
      --checkpoint NAME|ID           start it from a stored checkpoint instead of IMAGE (its name and
                                     address unless --name and --ip IP|auto), or from a checkpoint
                                     directory (a path, with a '/'); --paused holds it until unpause
  flexvm ps [-a] [-q] [--json] [-f, --filter KEY=VALUE]... [--format FORMAT]
                                     list running VMs (-a: stopped ones too; -q: names only);
                                     --filter name=PART|status=STATE|image=IMAGE|ip=IP (a key again:
                                     either value; a status filter lists stopped VMs too);
                                     --format json (an object per line) or a template, as
                                     '{{.Name}}\t{{.IP}}' ('table ' first: with a header, aligned)
  flexvm exec [OPTIONS] NAME CMD...  run argv in a VM (-d, -e K[=V], -w DIR, -u USER[:GROUP]; -i: stdin
                                     too; -t: on a pty, this terminal raw, Ctrl-P Ctrl-Q detaches)
  flexvm attach NAME                 a running VM's app: its output from now on, and stdin if run -i
  flexvm cp SRC DST                  copy files or directories between the host and a VM (NAME:PATH, as
                                     docker cp; - for a tar on stdin or stdout); into the VM as root
  flexvm logs [-f] [-n, --tail N] NAME
                                     a VM's output (its log, the one before its last rotation first);
                                     -f follows it, across rotations and restarts, until the VM exits or is removed
  flexvm inspect NAME...             a JSON array: per VM, what ps --json says and its config
  flexvm wait NAME...                wait until each VM's process ends, and print its exit status
                                     (a stopped one: 143; an exited one: its status; failed or lost: 124)
  flexvm stop NAME...                suspend a VM to disk, freeing its memory (as SIGTERM to its process)
  flexvm start [-a] NAME...          resume a stopped VM in the background (-a: in the foreground); an
                                     exited one runs again from its image (its writes were in its memory)
  flexvm pause NAME...               pause a VM's vCPUs, keeping its memory (as SIGTSTP; Ctrl-Z works too)
  flexvm unpause NAME...             resume a paused VM
  flexvm restart NAME...             stop, then start a VM (a stopped one is started, an exited one rerun)
  flexvm rename OLD NEW              rename a running, stopped or exited VM (not while it checkpoints or migrates)
  flexvm kill NAME...                destroy a running VM (Ctrl-C or Ctrl-\\ in the foreground)
  flexvm kill -s SIGNAL NAME...      send SIGNAL (TERM, HUP, 9, ...) to the VM's app instead
  flexvm rm [-f] NAME...             remove a stopped VM (suspended, quarantined, exited, failed or lost);
                                     -f: a running one too
  flexvm checkpoint create VM [NAME] [--stop] [--incremental]
                                     store the VM's state in STATE/checkpoints, named NAME if given;
                                     --incremental: as a delta on its last stored checkpoint
  flexvm checkpoint ls [-q] [--format FORMAT] [--filter name=NAME|vm=NAME|template=IMAGE|ID]...
                                     list stored checkpoints (-q: ids only; FORMAT as for ps)
  flexvm checkpoint rm [-f] NAME|ID...
                                     remove stored checkpoints (-f: and those built on them)
  flexvm checkpoint prune [--older-than AGE] [-f]
                                     remove stored checkpoints (older than AGE: 30m, 24h, 7d) no kept
                                     one builds on (-f: without asking)
  flexvm checkpoint save NAME|ID [-o FILE]
                                     write a stored checkpoint, its chain and its template as one
                                     tar, to stdout unless -o (save web | ssh b flexvm checkpoint load)
  flexvm checkpoint load [-i FILE|DIR] [--name NAME] [--sha256 HEX]
                                     store a save (from stdin unless -i) or a checkpoint directory,
                                     verified first (--sha256: only the save whose SHA-256 save
                                     printed); its template by content id, unnamed, if not here
  flexvm migrate NAME HOST:PORT      live-migrate a VM to the host listening there
  flexvm pull IMAGE[:TAG|@DIGEST] [--tag NAME] [--vcpus N] [--mem MIB] [--max MIB] [--plug MIB]
              [--standby N] ...      pull an image and build its template (an archive or OCI layout
                                     directory needs --tag; see README); again: rebuilt if it changed;
                                     --standby N keeps N of its VMs restored and paused (run: ~5 ms);
                                     of an image pulled here, alone it only sets that count
  flexvm images [-q] [--json] [--filter reference=PATTERN|dangling=true|false]
                                     list pulled images (-q: unique generation IDs)
  flexvm tag SRC DST                 name a pulled generation again, without rebuilding
  flexvm image prune [-f] [--force-shared]
                                     remove <none> generations no VM here, or in a state sharing
                                     the templates, uses (-f: without asking; --force-shared: trust
                                     the record of those states, forgetting any that are gone)
  flexvm system prune [-f] [--force-shared]
                                     also failed and lost VM records and the layer blob cache
  flexvm system df                   disk space by images, templates, blobs, VMs and checkpoints
  flexvm version                     version, commit and artifact information
  flexvm login [REGISTRY] [--username USER] [--password-stdin]
                                     verify and save registry credentials in STATE/auth.json
  flexvm logout [REGISTRY]           remove saved credentials (default registry: Docker Hub)
  flexvm rmi IMAGE|ID                remove an image no VM here uses
  flexvm listen [ADDR]               take migrations from peers (no ADDR: saved or socket-activated address)
  flexvm info                        this host's settings (STATE/host.json, edited by hand) and what is
                                     derived for those unset
  flexvm reclaim IP [--force GEN]    take back an address lent out with a VM that migrated away,
                                     once its target is gone for good (without --force: say what)
  flexvm bench ...                   latency benchmarks; needs a Git checkout, writes bench/ at its top level
      --timeout SECONDS              state/pull/readiness waits (default 120, minimum 1)
      --iterations N                 measured trials (positive, default 50; lifecycle: default 5, minimum 1)
      --warmup N                     unmeasured run trials (default 3; unused with --lifecycle)
      --settle-ms MS                 sleep after each run trial (default 100; unused with --lifecycle)
      --ready-port PORT              wait for TCP after run (unused with --lifecycle)
      --ready-http PORT              GET / and wait for a response byte (unused with --lifecycle);
                                     mutually exclusive with --ready-port; see README for other flags

options: --state DIR (",
    env!("FLEXVM_DEFAULT_STATE"),
    ": artifacts, templates, images, VMs, host.json), --run DIR
         (/run/flexvm, or /run/flexvm-PREFIX for another --state), --version, --verbose/-v
Each state directory is bound to its first run directory; a different --run is refused (and so is
none, if it is bound to another than its default); /run/flexvm is /var/lib/flexvm's alone.
run and start -a exit with the VM's command's (or else its app's) status, 128+signal, 125 when
flexvm fails, 124 when the VM dies; exec returns the command's status, 127 when it is not found,
126 when it cannot run, or 125 when flexvm fails
"
);

/// Flags that take no value (`-a`, `-f` and `--standby` depend on the command: `takes_value`).
const SWITCHES: &[&str] = &[
    "warm",
    "force-shared",
    "stop",
    "paused",
    "incremental",
    "incoming",
    "json",
    "detach",
    "interactive",
    "tty",
    "all",
    "attach",
    "keep",
    "rm",
    "help",
    "version",
    "quiet",
    "password-stdin",
    "follow",
    "verbose",
    "lifecycle",
];

/// `--flag value`s: last wins. `rest` follows `--`, `exec NAME` or `run IMAGE`;
/// run and exec still take their IMAGE or NAME after `--`.
pub struct Args {
    positional: Vec<String>,
    flags: Vec<(String, String)>,
    rest: Vec<String>,
    child_args: Vec<String>,
}

/// Whether `--flag` takes a value: `--force GEN` is reclaim's (rm's is a switch), `--standby N`
/// pull's (run's is the internal standby VM's switch).
fn takes_value(flag: &str, cmd: Option<&str>) -> Option<bool> {
    match flag {
        "force" => cmd.map(|c| c == "reclaim"),
        "standby" => cmd.map(|c| c == "pull"),
        f if SWITCHES.contains(&f) => Some(false),
        f if GLOBAL.contains(&f) || IMAGE_FLAGS.contains(&f) || COMMANDS.iter().any(|(_, _, flags)| flags.contains(&f)) => Some(true),
        _ => None,
    }
}

/// A value that is itself a flag (or `--`) is a forgotten value, as in `--state --run X`; any
/// other is taken as is, so argv-style ones can start with `--` (`--cmd "--port 8080"`).
fn is_flag(v: &str) -> bool {
    v == "--"
        || v.strip_prefix("--").is_some_and(|f| {
            let f = f.split_once('=').map_or(f, |(f, _)| f);
            matches!(f, "force" | "standby") || takes_value(f, None).is_some()
        })
}

/// Short switches, with the command's meaning of overloaded letters.
fn short_switch(flag: u8, cmd: Option<&str>) -> Option<&'static str> {
    match flag {
        b'd' => Some("detach"),
        b'h' if cmd != Some("run") => Some("help"),
        b'q' => Some("quiet"),
        b'v' if cmd != Some("run") => Some("verbose"),
        b'a' => Some(if cmd == Some("start") { "attach" } else { "all" }),
        b'i' if matches!(cmd, Some("run" | "exec")) => Some("interactive"),
        b't' if matches!(cmd, Some("run" | "exec")) => Some("tty"),
        b'f' if matches!(cmd, Some("rm" | "image" | "system" | "checkpoint")) => Some("force"),
        b'f' if cmd == Some("logs") => Some("follow"),
        _ => None,
    }
}

impl Args {
    #[cfg(test)]
    fn parse(it: impl IntoIterator<Item = String>) -> Result<Args> {
        let (a, e) = Args::parse_partly(it);
        e.map_or(Ok(a), Err)
    }

    /// The first error, and everything parsed around it: the command decides the exit status, wherever it is.
    fn parse_partly(it: impl IntoIterator<Item = String>) -> (Args, Option<util::Error>) {
        let mut a = Args { positional: Vec::new(), flags: Vec::new(), rest: Vec::new(), child_args: Vec::new() };
        let mut first = None;
        let mut it = it.into_iter();
        while let Err(e) = a.parse_into(&mut it) {
            first.get_or_insert(e);
        }
        (a, first)
    }

    /// Up to an error; called again, it goes on after it.
    fn parse_into(&mut self, it: &mut impl Iterator<Item = String>) -> Result<()> {
        let a = self;
        while let Some(mut arg) = it.next() {
            let cmd = a.positional.first().map(String::as_str);
            // Short switches can be bundled, followed by a valued flag (`-aq`, `-itp 80:80`).
            if arg.starts_with('-') && !arg.starts_with("--") {
                let mut n = 0;
                for b in arg.bytes().skip(1) {
                    let Some(f) = short_switch(b, cmd) else { break };
                    if f != "detach" {
                        a.child_args.push(format!("-{}", b as char));
                    }
                    a.flags.push((f.into(), "1".into()));
                    n += 1;
                }
                if n > 0 {
                    if arg.len() == n + 1 {
                        continue;
                    }
                    arg = format!("-{}", &arg[n + 1..]);
                }
            }
            if arg != "--detach" {
                a.child_args.push(arg.clone());
            }
            // Docker's hostname and volumes must not silently become help or verbose output.
            if cmd == Some("run") {
                match arg.as_str() {
                    "-h" => bail!("hostname (-h) is not supported; the hostname is the VM's name (--name); use --help for help"),
                    "-v" => bail!("volumes (-v) are not supported (#717); for verbose output, -v or --verbose goes before the command"),
                    _ => {}
                }
            }
            // Short flags with a value read as their long ones.
            let (option, attached) = if arg.starts_with("--") {
                arg.split_once('=').map_or((arg.as_str(), None), |(f, v)| (f, Some(v)))
            } else if arg.starts_with('-') && arg.len() > 2 && arg.is_char_boundary(2) {
                (&arg[..2], Some(arg[2..].strip_prefix('=').unwrap_or(&arg[2..])))
            } else {
                (arg.as_str(), None)
            };
            let valued = match option {
                "-p" => Some("publish"),
                "-m" if cmd == Some("run") => Some("memory"),
                "-n" if cmd == Some("logs") => Some("tail"),
                "-f" if cmd == Some("ps") => Some("filter"),
                "-e" if matches!(cmd, Some("run" | "exec")) => Some("env"),
                "-w" if cmd == Some("exec") => Some("workdir"),
                "-u" if cmd == Some("exec") => Some("user"),
                "-s" if cmd == Some("kill") => Some("signal"),
                "-o" if cmd == Some("checkpoint") => Some("output"),
                "-i" if cmd == Some("checkpoint") => Some("input"),
                _ => None,
            };
            match valued.or_else(|| option.strip_prefix("--")) {
                Some("") if attached.is_none() => {
                    // Before the command, the words after it would be taken as one.
                    if cmd.is_none() {
                        bail!("-- must follow the command");
                    }
                    if matches!(cmd, Some("run" | "exec")) {
                        // `run -- IMAGE` and `exec -- NAME`: the first word is still IMAGE or NAME,
                        // and as without the `--`, a `--` right after it is dropped.
                        let mut words = it.by_ref().peekable();
                        // `run --checkpoint DIR` has no IMAGE: the words are a (refused) CMD.
                        if a.positional.len() == 1 && !a.has("checkpoint") {
                            if let Some(word) = words.next() {
                                a.child_args.push(word.clone());
                                a.positional.push(word);
                                if let Some(dashdash) = words.next_if_eq("--") {
                                    a.child_args.push(dashdash);
                                }
                            }
                        }
                        a.rest.extend(words);
                        a.child_args.extend(a.rest.iter().cloned());
                    } else {
                        let words: Vec<_> = it.by_ref().collect();
                        a.child_args.extend(words.iter().cloned());
                        a.positional.extend(words);
                    }
                }
                Some(f) => {
                    if cmd.is_none() && matches!(f, "force" | "standby") {
                        bail!("--{f} must follow the command");
                    }
                    let value = match (takes_value(f, cmd), attached) {
                        (Some(false), Some(_)) => bail!("--{f} does not take a value"),
                        (Some(false), None) => "1".into(),
                        (Some(true), Some(v)) => v.into(),
                        (Some(true), None) => {
                            let value = it.next().filter(|v| if arg == "-p" { !v.starts_with('-') } else { !is_flag(v) }).ok_or_else(|| match f {
                                "publish" if arg == "-p" => "-p needs a port mapping".to_string(),
                                "force" => "--force needs a generation; run flexvm reclaim IP to see GEN".to_string(),
                                _ => format!("--{f} needs a value"),
                            })?;
                            a.child_args.push(value.clone());
                            value
                        }
                        (None, _) => bail!("unknown option --{f} (see flexvm --help)"),
                    };
                    a.flags.push((f.into(), value));
                }
                // `-` alone is a word: cp's stdin or stdout.
                None if arg.starts_with('-') && arg != "-" => bail!("unknown option {arg} (see flexvm --help)"),
                None => {
                    a.positional.push(arg);
                    // `exec NAME CMD` and `run IMAGE CMD`: the rest is the command's (a `--` first is dropped).
                    if a.positional.len() == 2 && matches!(a.positional[0].as_str(), "exec" | "run") {
                        let mut cmd = it.by_ref().peekable();
                        // Kept in child_args, so the VM process drops the same one.
                        if let Some(dashdash) = cmd.next_if_eq("--") {
                            a.child_args.push(dashdash);
                        }
                        a.rest.extend(cmd);
                        a.child_args.extend(a.rest.iter().cloned());
                    }
                }
            }
        }
        Ok(())
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.flags.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.flags.iter().filter(|(k, _)| k == name).map(|(_, v)| v.clone()).collect()
    }

    pub fn parse_or<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T> {
        self.get(name).map_or(Ok(default), |v| v.parse().map_err(|_| format!("bad --{name} {v:?}").into()))
    }

    /// The words after the command: its names.
    fn names(&self) -> &[String] {
        self.positional.get(1..).unwrap_or_default()
    }
}

/// A VM's command's statuses are its own: flexvm's failures there exit 125.
fn main() {
    // The logs a `run` handed this process, by token: read before any thread starts, and kept
    // from every process of this one's own.
    host::handed();
    std::env::remove_var(host::HANDOFF_ENV);
    // A panic's message is queued after the lines before it, and written
    // (bounded: a stalled stderr does not keep the process from aborting).
    std::panic::set_hook(Box::new(|p| {
        attach::restore_terminal();
        let bt = std::backtrace::Backtrace::capture();
        let bt = if bt.status() == std::backtrace::BacktraceStatus::Captured { format!("\nstack backtrace:\n{bt}") } else { String::new() };
        util::log_final(format!("thread '{}' {p}{bt}\n", std::thread::current().name().unwrap_or("<unnamed>")), false);
        // The abort follows: a VM process's relays get the message to its log first. An unwinding
        // build's process may live on, so its output is left where it is.
        if cfg!(panic = "abort") {
            util::output::drain();
        }
    }));
    let (args, error) = Args::parse_partly(std::env::args().skip(1));
    // A listener's, an arrival's and a standby's stderr is a log: it keeps what they did (a claim sets its claimer's).
    let logged = match args.positional.first().map(String::as_str) {
        Some("listen") => true,
        Some("run") => args.has("incoming") || args.has("standby"),
        _ => false,
    };
    util::set_verbose(args.has("verbose") || logged);
    let vm = matches!(args.positional.first().map(String::as_str), Some("run" | "start" | "exec"));
    let result = error.map_or_else(|| real_main(&args), Err);
    if let Some(sig) = template::interrupted_signal() {
        util::raise_signal(sig);
    }
    if let Err(e) = result {
        util::log_final(format!("flexvm: {e}\n"), true);
        if vm {
            // A VM process's output may still be in its relays (`output::guard`).
            util::output::drain();
        }
        std::process::exit(if vm { vmproc::exit_code(&e) } else { 1 });
    }
    util::exit(0)
}

/// Flags every command takes.
const GLOBAL: &[&str] = &["state", "run", "help", "version", "verbose"];

/// What `pull` takes besides the sizes.
const IMAGE_FLAGS: &[&str] = &[
    "init",
    "entrypoint",
    "cmd",
    "env",
    "workdir",
    "user",
    "warm",
    "ready-port",
    "ready-cmd",
    "ready-timeout",
    "max-download-mib",
    "max-unpacked-mib",
    "max-file-mib",
    "max-entries",
];

/// Any number of names.
const NAMES: usize = usize::MAX;

/// Each command's words (itself included) at most, and its flags besides `GLOBAL`.
const COMMANDS: &[(&str, usize, &[&str])] = &[
    (
        "run",
        2,
        &[
            "name",
            "detach",
            "interactive",
            "tty",
            "ip",
            "cpus",
            "memory",
            "env",
            "env-file",
            "entrypoint",
            "keep",
            "rm",
            "checkpoint",
            "paused",
            "standby",
            "incoming",
            "publish",
        ],
    ),
    ("standby-refill", 2, &[]), // Internal delayed refill worker.
    ("ps", 1, &["all", "json", "quiet", "filter", "format"]),
    ("exec", 2, &["detach", "interactive", "tty", "env", "workdir", "user"]),
    ("attach", 2, &[]),
    ("cp", 3, &[]),
    ("logs", 2, &["follow", "tail"]),
    ("inspect", NAMES, &[]),
    ("wait", NAMES, &[]),
    ("restart", NAMES, &[]),
    ("rename", 3, &[]),
    ("stop", NAMES, &[]),
    ("start", NAMES, &["attach"]),
    ("pause", NAMES, &[]),
    ("unpause", NAMES, &[]),
    ("kill", NAMES, &["signal"]),
    ("rm", NAMES, &["force"]),
    ("checkpoint", NAMES, &["stop", "incremental", "quiet", "format", "filter", "force", "older-than", "output", "input", "name", "sha256"]),
    ("migrate", 3, &[]),
    ("reclaim", 2, &["force"]),
    ("listen", 2, &[]),
    ("info", 1, &[]),
    ("pull", 2, &["tag", "vcpus", "mem", "max", "plug", "standby"]),
    ("images", 1, &["json", "quiet", "filter"]),
    ("tag", 3, &[]),
    ("image", 2, &["force", "force-shared"]),
    ("system", 2, &["force", "force-shared"]),
    ("version", 1, &[]),
    ("login", 2, &["username", "password-stdin"]),
    ("logout", 2, &[]),
    ("rmi", 2, &[]),
    (
        "bench",
        1,
        &["template", "to", "to-state", "to-run", "timeout", "lifecycle", "iterations", "warmup", "dirty-mib", "settle-ms", "ready-port", "ready-http"],
    ),
    ("debug", 4, &[]),
];

/// Flags and words a command does not take are errors, never ignored.
fn check_applies(args: &Args) -> Result<()> {
    let Some(cmd) = args.positional.first() else { return Ok(()) };
    let Some(&(_, most, flags)) = COMMANDS.iter().find(|(c, ..)| c == cmd) else {
        bail!("unknown command {cmd:?} (see flexvm --help)");
    };
    let first = args.positional.get(1).filter(|w| !w.is_empty());
    let internal = cmd == "run" && (args.has("standby") || args.has("incoming"));
    if cmd == "run" && args.has("checkpoint") {
        if let Some(image) = first {
            bail!("run --checkpoint takes no IMAGE ({image:?}): the checkpoint has its own");
        }
        if !args.rest.is_empty() {
            bail!("run --checkpoint takes no CMD: the checkpoint's command cannot be replaced");
        }
        if let Some(f) = ["env", "env-file", "entrypoint", "keep", "rm", "interactive", "tty"].into_iter().find(|f| args.has(f)) {
            bail!("--{f} does not apply to run --checkpoint: the checkpoint's app runs already");
        }
    } else if cmd == "run" && args.has("paused") {
        bail!("--paused applies to run --checkpoint");
    } else if !internal && first.is_none() {
        match cmd.as_str() {
            "run" | "pull" | "rmi" => bail!("{cmd} needs IMAGE"),
            "exec" | "attach" | "stop" | "start" | "pause" | "unpause" | "kill" | "rm" | "migrate" | "logs" | "inspect" | "wait" | "restart" => {
                bail!("{cmd} needs NAME")
            }
            "rename" => bail!("rename needs OLD NEW"),
            "cp" => bail!("cp needs SRC DST"),
            _ => {}
        }
    }
    match cmd.as_str() {
        "tag" if args.names().len() != 2 => bail!("tag needs SRC DST"),
        "cp" if args.names().len() != 2 => bail!("cp needs SRC DST"),
        "image" if first.map(String::as_str) != Some("prune") => bail!("image needs prune"),
        "system" if !matches!(first.map(String::as_str), Some("prune" | "df")) => bail!("system needs prune or df"),
        "system" if first.map(String::as_str) == Some("df") && args.has("force") => bail!("system df takes no -f"),
        "system" if first.map(String::as_str) == Some("df") && args.has("force-shared") => bail!("system df takes no --force-shared"),
        "images" if args.has("quiet") && args.has("json") => bail!("images takes -q or --json, not both"),
        "debug" => {
            let op = first.ok_or("debug fault|ckhash|gc|VM ...")?;
            let (least, most, words) = match op.as_str() {
                "gc" => (2, 2, "no arguments"),
                "fault" => (3, 4, "NAME [MS]"),
                "ckhash" => (3, 3, "DIR"),
                _ => (2, 3, "[WHAT]"),
            };
            if !(least..=most).contains(&args.positional.len()) {
                bail!("debug {op} takes {words}");
            }
        }
        "checkpoint" => {
            let (op, most, flags): (_, _, &[&str]) = match first.map(String::as_str) {
                Some(op @ "create") => (op, 4, &["stop", "incremental"]),
                Some(op @ "ls") => (op, 2, &["quiet", "format", "filter"]),
                Some(op @ "rm") => (op, NAMES, &["force"]),
                Some(op @ "prune") => (op, 2, &["older-than", "force"]),
                Some(op @ "save") => (op, 3, &["output"]),
                Some(op @ "load") => (op, 2, &["input", "name", "sha256"]),
                // `checkpoint VM DIR`, before #775.
                _ => bail!("checkpoint needs create, ls, rm, prune, save or load: flexvm checkpoint create VM [NAME] keeps a VM's checkpoint in STATE/checkpoints (it took a DIR before), and run --checkpoint NAME restores it"),
            };
            if let Some((f, _)) = args.flags.iter().find(|(f, _)| !GLOBAL.contains(&f.as_str()) && !flags.contains(&f.as_str())) {
                bail!("--{f} does not apply to checkpoint {op} (see flexvm --help)");
            }
            if let Some(extra) = args.positional.get(most) {
                bail!("checkpoint {op} does not take {extra:?} (see flexvm --help)");
            }
            match op {
                "ls" if args.has("quiet") && args.has("format") => bail!("checkpoint ls takes -q or --format, not both"),
                "create" if args.positional.len() < 3 => bail!("checkpoint create needs VM"),
                "rm" if args.positional.len() < 3 => bail!("checkpoint rm needs NAME|ID"),
                "save" if args.positional.len() < 3 => bail!("checkpoint save needs NAME|ID"),
                _ => {}
            }
        }
        _ => {}
    }
    let image = cmd == "pull";
    if let Some((f, _)) = args.flags.iter().find(|(f, _)| ![GLOBAL, flags, if image { IMAGE_FLAGS } else { &[] }].concat().contains(&f.as_str())) {
        bail!("--{f} does not apply to {cmd} (see flexvm --help)");
    }
    if let Some(extra) = args.positional.get(most) {
        bail!("{cmd} does not take {extra:?} (see flexvm --help)");
    }
    if let Some(empty) = args.names().iter().find(|n| n.is_empty()) {
        bail!("{cmd} takes no empty word {empty:?}");
    }
    let interactive = args.has("interactive") || args.has("tty");
    if cmd == "run" && args.has("keep") && !args.rest.is_empty() && !interactive {
        bail!("--keep applies to the image's app: with CMD, the vm ends with CMD");
    }
    if cmd == "run" && interactive && args.has("entrypoint") && !args.rest.is_empty() {
        bail!("-i and -t make CMD the app: give --entrypoint or CMD");
    }
    if cmd == "start" && args.has("attach") && args.names().len() > 1 {
        bail!("start -a takes one NAME");
    }
    if cmd == "rename" && args.positional.len() < 3 {
        bail!("rename needs OLD NEW");
    }
    if cmd == "ps" && args.has("quiet") {
        if let Some(f) = ["json", "format"].into_iter().find(|f| args.has(f)) {
            bail!("ps takes -q or --{f}, not both");
        }
    }
    if cmd == "ps" && args.has("json") && args.has("format") {
        bail!("ps takes --json or --format, not both");
    }
    Ok(())
}

fn state(args: &Args) -> Result<PathBuf> {
    Ok(std::path::absolute(args.get("state").unwrap_or(host::DEFAULT_STATE))?)
}

/// The host, recovered first until this boot's recovery is complete (`gc::after_boot`): a VM
/// process and a template build only its local part (they leave the rest to a full pass), the
/// listener the rest after this; any other command all of it here.
pub fn open_host(args: &Args) -> Result<Host> {
    let state = state(args)?;
    let run = match args.get("run") {
        Some(run) => PathBuf::from(run),
        None => host::default_run(&state)?,
    };
    let host = Host::open(&state, &run)?;
    let partly = matches!(args.positional.first().map(String::as_str), Some("run" | "start" | "listen" | "pull"));
    if let Err(e) = gc::after_boot(&host, !partly) {
        if gc::first_boot_warning(&host, host::boot_id()) {
            crate::log!("flexvm: recovering after boot: {e}");
        }
    }
    Ok(host)
}

fn paths(args: &Args) -> Result<Paths> {
    Ok(Paths::new(&state(args)?))
}

fn real_main(args: &Args) -> Result<()> {
    if args.has("help") {
        return output(format_args!("{USAGE}"));
    }
    if args.has("version") {
        return output(format_args!("flexvm {}\n", env!("CARGO_PKG_VERSION")));
    }
    check_applies(args)?;
    let pos: Vec<&str> = args.positional.iter().map(|s| s.as_str()).collect();
    let (name, arg2) = (pos.get(1).copied().unwrap_or(""), pos.get(2).copied());
    let call = |req: Value| print(vmproc::call(&open_host(args)?, name, req, None)?);
    match pos.first().copied() {
        Some("standby-refill") => standby::retry(&open_host(args)?, &template::name_of(name)?),
        Some("pull") => pull(args, name),
        Some("images") => images(&open_host(args)?, &paths(args)?, args),
        Some("tag") => print(template::tag(&paths(args)?, name, arg2.ok_or("tag needs SRC DST")?)?),
        Some("image" | "system") => management::system(args, name),
        Some("version") => management::version(&paths(args)?),
        Some("login") => image::auth::login(&open_host(args)?.state, name, args.get("username"), args.has("password-stdin")),
        Some("logout") => image::auth::logout(&open_host(args)?.state, name),
        Some("rmi") => rmi(&open_host(args)?, &paths(args)?, name),
        Some("run") if args.has("standby") => {
            let template = template::name_of(name)?;
            vmproc::main(open_host(args)?, paths(args)?, Start::Standby { template }, notify_fd())
        }
        Some("run") if args.has("incoming") => {
            let req: Value = serde_json::from_str(&std::env::var("FLEXVM_INCOMING").map_err(|_| "run --incoming is the listener's, for migrations")?)?;
            let log = std::env::var_os("FLEXVM_INCOMING_LOG").map(PathBuf::from);
            std::env::remove_var("FLEXVM_INCOMING");
            std::env::remove_var("FLEXVM_INCOMING_LOG");
            unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) };
            // Told once committed or refused: the listener holds an arrival slot until then.
            vmproc::main(open_host(args)?, paths(args)?, Start::Incoming { req, log }, notify_fd())
        }
        Some("run") if args.has("checkpoint") => run_checkpoint(args),
        Some("run") => run(args, name),
        Some("start") if args.has("attach") => {
            // A detached start's VM process (`start -a`, answering on FLEXVM_NOTIFY_FD) must answer
            // its parent through vmproc, even if another start won meanwhile.
            let host = open_host(args)?;
            if std::env::var_os("FLEXVM_NOTIFY_FD").is_none() {
                stopped_to_attach(&host, name)?;
                // Nothing to start: said before taking the name, which would clear a moved VM's hint.
                if !host.alive(name) && !host.suspended(name)?.exists() && !host.has_record(name, "exited") {
                    return Err(no_vm(&host, name));
                }
            }
            let start = rerun(&host, name)?.unwrap_or(Start::Resume { name: name.into() });
            vmproc::main(host, paths(args)?, start, notify_fd())
        }
        Some("start") => {
            let host = open_host(args)?;
            each(args.names(), |n| start(&host, args, n))
        }
        Some("ps") => ps(&open_host(args)?, args),
        Some("exec") => {
            let cmd = exec_command(args)?;
            util::exit(exec(&open_host(args)?, name, &cmd)?)
        }
        Some("attach") => {
            let host = open_host(args)?;
            util::exit(attach::attach(&host, name, None)?)
        }
        Some("cp") => {
            let host = open_host(args)?;
            util::exit(attach::cp(&host, name, arg2.unwrap_or_default())?)
        }
        Some("logs") => {
            let tail = args
                .get("tail")
                .filter(|&t| t != "all")
                .map(|t| t.parse().map_err(|_| format!("bad --tail {t:?}: give a count of lines, or all")))
                .transpose()?;
            containers::logs(&open_host(args)?, name, args.has("follow"), tail)
        }
        Some("inspect") => containers::inspect(&open_host(args)?, &paths(args)?, args.names()),
        Some("wait") => {
            let host = open_host(args)?;
            each(args.names(), |n| output(format_args!("{}\n", containers::wait(&host, n)?)))
        }
        Some("rename") => containers::rename(&open_host(args)?, name, arg2.unwrap_or_default()),
        Some("stop") => {
            let host = open_host(args)?;
            each(args.names(), |n| stop(&host, n).and_then(|_| output(format_args!("{n}\n"))))
        }
        Some("restart") => {
            let host = open_host(args)?;
            // Started under the name it has last: a rename as it was stopped moved it on (#1189).
            each(args.names(), |n| {
                let last = stop(&host, n)?;
                start(&host, args, &last)
            })
        }
        Some("pause") => {
            let host = open_host(args)?;
            each(args.names(), |n| pause(&host, n))
        }
        Some("unpause") => {
            let host = open_host(args)?;
            each(args.names(), |n| match resume(&host, n)? {
                true => output(format_args!("{n}\n")),
                false => Err(not_running(&host, n)),
            })
        }
        Some("kill") if args.has("signal") => {
            let sig = app::parse_signal(args.get("signal").unwrap_or_default())?;
            let host = open_host(args)?;
            each(args.names(), |n| signal_app(&host, n, sig))
        }
        Some("kill") => {
            let host = open_host(args)?;
            each(args.names(), |n| remove(&host, n, true, false))
        }
        Some("rm") => {
            let host = open_host(args)?;
            each(args.names(), |n| remove(&host, n, args.has("force"), true))
        }
        Some("reclaim") => {
            let gen = args.get("force").map(|v| v.parse().map_err(|_| format!("bad --force generation {v:?}"))).transpose()?;
            reclaim(&open_host(args)?, name, gen)
        }
        Some("checkpoint") if name == "create" => {
            let req = json!({"op": "checkpoint", "name": pos.get(3), "stop": args.has("stop"), "incremental": args.has("incremental")});
            print(vmproc::call(&open_host(args)?, arg2.unwrap_or_default(), req, None)?)
        }
        Some("checkpoint") => management::checkpoints(args, name),
        Some("migrate") => call(json!({"op": "migrate", "to": arg2.ok_or("migrate needs NAME HOST:PORT")?})),
        Some("listen") => {
            // Before any thread that would take these signals is started.
            util::on_signal(&[libc::SIGTERM, libc::SIGINT, libc::SIGHUP], |sig| util::raise_signal(sig));
            let mut host = open_host(args)?;
            let (listeners, validated) = configure_listener(&mut host, pos.get(1).copied(), listen::activated())?;
            listen::main(host, listeners, validated)
        }
        Some("info") => print(info(&open_host(args)?)),
        Some("bench") => bench::run(args),
        // Test hooks: arm a fault for MS ms (0 disarms), hash a checkpoint, or ask a VM.
        Some("debug") => match name {
            "gc" => {
                let host = open_host(args)?;
                gc::sweep_now(&host)
            }
            "fault" => {
                let ms = pos.get(3).map_or(Ok(1000), |m| m.parse().map_err(|_| format!("bad fault MS {m:?}")))?;
                host::arm(&open_host(args)?, arg2.ok_or("debug fault NAME MS")?, ms)
            }
            "ckhash" => print(lifecycle::ckhash(&paths(args)?, std::path::Path::new(arg2.ok_or("debug ckhash DIR")?))?),
            "" => Err("debug fault|ckhash|gc|VM ...".into()),
            _ => call(json!({"op": "debug", "what": arg2.unwrap_or("status")})),
        },
        _ => {
            util::log_line(USAGE.to_string());
            util::exit(2)
        }
    }
}

/// `f` for each name, going on past a failure as docker does; one name's failure is its error.
fn each(names: &[String], mut f: impl FnMut(&str) -> Result<()>) -> Result<()> {
    if let [one] = names {
        return f(one);
    }
    let failed = names.iter().filter(|n| f(n).inspect_err(|e| crate::log!("flexvm: {n}: {e}")).is_err()).count();
    if failed > 0 {
        bail!("{failed} of {} failed", names.len());
    }
    Ok(())
}

/// The global flags, then `words`: a command this process runs as a child.
fn child_args(args: &Args, words: &[&str]) -> Vec<String> {
    let mut v = Vec::new();
    for flag in ["state", "run"] {
        if let Some(value) = args.get(flag) {
            v.extend([format!("--{flag}"), value.into()]);
        }
    }
    if args.has("verbose") {
        v.push("--verbose".into());
    }
    v.extend(words.iter().map(|w| w.to_string()));
    v
}

/// `info`: host.json as set, what is derived for the rest, and what looks like a mistake.
fn info(host: &Host) -> Value {
    let c = &host.cfg;
    let derived = json!({"prefix": host.tap_prefix(), "cluster_ips": c.effective_cluster_ips(), "underlay": c.underlay(), "announce_dev": c.announce_dev(), "reserve_mib": c.reserve(), "evict_at_mib": c.evict_at()});
    json!({"version": env!("CARGO_PKG_VERSION"), "config": host.state.join("host.json"), "set": c, "derived": derived, "warnings": c.warnings()})
}

/// Bind and validate before publishing any host configuration.
fn configure_listener(host: &mut Host, addr: Option<&str>, activated: Option<std::net::TcpListener>) -> Result<(Vec<std::net::TcpListener>, listen::Cached)> {
    let mut listener = None;
    host.configure(|c| {
        if let Some(a) = addr {
            c.listen = Some(a.into());
        }
        let bound = match activated {
            // Without ADDR, an activated socket says where this host listens; ADDR must be where it does.
            Some(l) => {
                let local = l.local_addr()?;
                match addr {
                    Some(a) => activated_at(a, local, listen::v6only(&l))?,
                    None => c.listen = Some(local.to_string()),
                }
                vec![l]
            }
            None => {
                let addr = c.listen.as_deref().ok_or("listen needs an address (flexvm listen ADDR)")?;
                // Under the host lock: a hostname's lookup is bounded, as `activated_at`'s.
                // Peers may pick any of a name's addresses, so each gets a socket.
                bind_each(addr, &resolve_listener(addr)?)?
            }
        };
        let validated = listen::validate(&bound, c)?;
        listener = Some((bound, validated));
        Ok(())
    })?;
    for warning in host.cfg.warnings() {
        crate::log!("{warning}");
    }
    Ok(listener.unwrap())
}

/// An ADDR given with an activated socket is what peers are told (they fetch a
/// migration's memory from it): every address it names must be one the socket takes.
fn activated_at(addr: &str, local: std::net::SocketAddr, v6only: bool) -> Result<()> {
    if !covers(local, v6only, &resolve_listener(addr)?) {
        bail!("the activated socket listens on {local}, not on every address of {addr}: run flexvm listen without ADDR, or give the socket's address");
    }
    Ok(())
}

/// Whether a socket bound at `local` takes connections to each of `addrs`.
fn covers(local: std::net::SocketAddr, v6only: bool, addrs: &[std::net::SocketAddr]) -> bool {
    addrs.iter().all(|a| a.port() == local.port() && takes(local, v6only, a.ip()))
}

/// Whether a socket bound at `local` takes connections to `ip`: its own address, or for a
/// wildcard one any of its family (an IPv6 one IPv4 too, unless IPV6_V6ONLY).
fn takes(local: std::net::SocketAddr, v6only: bool, ip: std::net::IpAddr) -> bool {
    let (ip, bound) = (ip.to_canonical(), local.ip().to_canonical());
    // By the canonical family: a mapped wildcard ([::ffff:0.0.0.0]) takes IPv4 only.
    match (bound.is_unspecified(), bound) {
        (false, _) => ip == bound,
        (true, std::net::IpAddr::V4(_)) => ip.is_ipv4(),
        (true, std::net::IpAddr::V6(_)) => ip.is_ipv6() || !v6only,
    }
}

/// A socket on each of `addrs`, or none if one fails: a peer could pick the one missing.
fn bind_each(addr: &str, addrs: &[std::net::SocketAddr]) -> Result<Vec<std::net::TcpListener>> {
    addrs.iter().map(|a| std::net::TcpListener::bind(a).map_err(|e| format!("listen on {addr} ({a}): {e}").into())).collect()
}

fn resolve_listener(addr: &str) -> Result<Vec<std::net::SocketAddr>> {
    let resolved = util::resolve(addr, Instant::now() + Duration::from_secs(2)).map_err(|e| format!("listen address {addr}: {e}"))?;
    listener_addresses(addr, resolved)
}

/// A name's distinct addresses, in the resolver's order: peers may choose any of them. An IPv4-mapped
/// one is its IPv4 address: the two share one binding, so binding both would fail.
fn listener_addresses(addr: &str, resolved: Vec<std::net::SocketAddr>) -> Result<Vec<std::net::SocketAddr>> {
    let mut out: Vec<std::net::SocketAddr> = Vec::new();
    for a in resolved {
        let a = match a.ip().to_canonical() {
            std::net::IpAddr::V4(v4) => std::net::SocketAddr::from((v4, a.port())),
            std::net::IpAddr::V6(_) => a,
        };
        if a.port() == 0 {
            bail!("listening on {addr}: give a port; peers are told it");
        }
        if !out.contains(&a) {
            out.push(a);
        }
    }
    if out.is_empty() {
        bail!("listen address {addr}: no addresses");
    }
    Ok(out)
}

/// `--cpus` and `--memory`.
fn resources(args: &Args) -> Result<vm::Resources> {
    let cpus = args.get("cpus").map(|v| v.parse::<f64>().ok().filter(|c| c.is_finite() && *c > 0.0).ok_or_else(|| format!("bad --cpus {v:?}"))).transpose()?;
    Ok(vm::Resources { cpus, memory_mib: args.get("memory").map(memory_mib).transpose()? })
}

/// A size as docker takes it: bytes, or a number (with a fraction) and a unit of b, k, m, g or
/// t (kb, mb, ... too; powers of 1024), any case. In MiB, rounded down.
fn memory_mib(v: &str) -> Result<u64> {
    let bad = || format!("bad --memory {v:?}: give a size, as 512m or 2g");
    let lower = v.trim().to_ascii_lowercase();
    let number = lower.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let shift = match &lower[number.len()..] {
        "" | "b" => 0,
        "k" | "kb" | "kib" => 10,
        "m" | "mb" | "mib" => 20,
        "g" | "gb" | "gib" => 30,
        "t" | "tb" | "tib" => 40,
        _ => return Err(bad().into()),
    };
    // Digits, and perhaps a fraction: not f64's signs, exponents or bare points.
    if !number.splitn(2, '.').all(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())) {
        return Err(bad().into());
    }
    let n: f64 = number.parse().ok().filter(|n: &f64| n.is_finite() && *n >= 0.0).ok_or_else(bad)?;
    let mib = n * (1u64 << shift) as f64 / (1u64 << 20) as f64;
    if mib >= u64::MAX as f64 {
        return Err(bad().into());
    }
    if shift == 0 && mib < 1.0 {
        bail!("--memory {v} is {v} bytes: give a unit, as {v}m");
    }
    Ok(mib as u64)
}

/// `run IMAGE`: claims a standby VM if there is one, else becomes the VM.
fn run(args: &Args, image: &str) -> Result<()> {
    let (host, paths) = (open_host(args)?, paths(args)?);
    let template = template::name_of(image)?;
    let resources = resources(args)?;
    let ip = args.get("ip").filter(|&s| s != "auto");
    let ip: Option<std::net::Ipv4Addr> = ip.map(|s| s.parse().map_err(|_| format!("bad --ip {s:?}"))).transpose()?;
    if let Some(name) = args.get("name") {
        host::check_new_name(name)?;
    }
    // Parsed once (its `-p` ports included), before a pull: a bad one is refused at once.
    let spec = run_spec(args, ip)?;
    // Pulled the first time, as docker does (a detached run's VM process finds it there).
    if std::fs::symlink_metadata(paths.templates.join(&template)).is_err() {
        pull_missing(args, &template)?;
    }
    let interactive = args.has("interactive") || args.has("tty");
    // With -i or -t, CMD is the app (`run_spec`), which they are for.
    let cmd = (!args.rest.is_empty() && !interactive).then(|| args.rest.join(" "));
    if args.has("interactive") && args.has("tty") && !args.has("detach") && !std::io::stdin().is_terminal() && std::env::var_os("FLEXVM_NOTIFY_FD").is_none() {
        bail!("the input device is not a TTY");
    }
    // Only settings for the app need the template's (a standby VM's claim is ~5 ms).
    match spec.changes_app() {
        true => spec.check(template::Template::open(&paths, &template)?.meta.image.as_ref())?,
        false => spec.check(None)?,
    }
    // A made-up name is only checked free here: one another run took meanwhile is made up
    // again (a cold foreground run's VM process does that itself, `Proc::run`).
    for _ in 0..20 {
        let name = match args.get("name") {
            Some(name) => name.to_string(),
            None => host::generated_name(&host)?,
        };
        match run_as(args, &host, &paths, &template, name, ip, cmd.clone(), resources, &spec) {
            Err(e) if args.get("name").is_none() && host::name_taken(&e) => continue,
            r => return r,
        }
    }
    bail!("every name made up was taken meanwhile: give one with --name")
}

/// `run` of VM `name`: a standby's claim, or this process becomes the VM.
#[allow(clippy::too_many_arguments)]
fn run_as(
    args: &Args,
    host: &Host,
    paths: &Paths,
    template: &str,
    name: String,
    ip: Option<std::net::Ipv4Addr>,
    cmd: Option<String>,
    resources: vm::Resources,
    spec: &app::RunSpec,
) -> Result<()> {
    // A detached run's VM process (it answers on FLEXVM_NOTIFY_FD): its parent tried them.
    let tried = std::env::var_os("FLEXVM_NOTIFY_FD").is_some();
    // A foreground -i or -t runs it in the background, and attaches to it (as `attach`).
    let attached = (args.has("interactive") || args.has("tty")) && !args.has("detach") && !tried;
    // A claimed standby VM writes where this process would, to opens made here (`own`).
    let log = (args.has("detach") || attached).then(|| new_run_log(host, &name)).transpose()?;
    // Attached: a foreground claimer follows the VM, which goes if it hangs up (killed), as a cold run's would.
    // And joins this process's cgroup, where a cold run's VM process (this one) would be.
    let cgroup = log.is_none().then(util::my_cgroup).flatten();
    let tty = log.is_none() && std::io::stdin().is_terminal();
    let req = json!({"op": "claim", "name": name, "ip": ip.map(|i| i.to_string()), "cmd": cmd, "resources": resources, "spec": spec, "tty": tty, "verbose": util::verbose(), "attached": log.is_none(), "attacher": attached, "logs_handoff": log.as_ref().map(|l| l.token.as_str())});
    let fds = log.as_ref().map_or([1, 2], |f| [f.as_raw_fd(); 2]).map(|fd| unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned());
    let outs = fds.into_iter().map(|f| Ok(util::output::own(f?.into()))).collect::<std::io::Result<Vec<_>>>()?;
    // A foreground claim's signals wait from before it is sent: the VM it makes gets them
    // (`follow`), as a cold start would, never orphaned by this process dying mid-claim.
    let set = (!tried && log.is_none()).then(|| util::block_signals(&FOLLOW_SIGNALS));
    let fds: Vec<_> = outs.iter().map(|f| f.as_raw_fd()).chain(cgroup.iter().map(|f| f.as_raw_fd())).collect();
    let taken = if tried { None } else { standby::take(host, paths, template, &req, &fds)? };
    drop(cgroup);
    if let (None, Some(set)) = (&taken, &set) {
        // No claim: this process becomes the VM, and one pending kills it as before.
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, set, std::ptr::null_mut()) };
    }
    match (taken, log) {
        (Some(_), Some(_)) if attached => run_attached(host, &name, args.has("keep")),
        (Some((v, _)), Some(_)) => print(v),
        (Some((v, conn)), None) => {
            // Its terminal gone, this client's own output is dropped: only the VM's process
            // writes the VM's logs.
            crate::info!("{v}");
            // Its pid is the one it has in its PID namespace (`pidns`), found here by that (#1139);
            // an earlier build's reply names none, judged by its pid here.
            let id = host::Ident {
                pid: v["pid"].as_u64().unwrap_or(0) as u32,
                start: v["start"].as_u64().unwrap_or(0),
                boot: host::boot_id().into(),
                ns: v["pidns"].as_u64(),
            };
            follow(conn, id)
        }
        (None, Some(log)) => {
            // The child takes the name made up here.
            let child = [&["--name".to_string(), name.clone()][..], &args.child_args].concat();
            let v = spawn_detached(host, &name, &child, &log, attached)?;
            match attached {
                true => run_attached(host, &name, args.has("keep")),
                false => print(v),
            }
        }
        (None, None) => {
            let generated = args.get("name").is_none();
            let (spec, rerun) = (spec.clone(), false);
            // Its child args have no -d either way: its parent says whether it attaches.
            let attacher = std::env::var_os("FLEXVM_ATTACHER").is_some();
            std::env::remove_var("FLEXVM_ATTACHER");
            vmproc::main(
                host.clone(),
                paths.clone(),
                Start::Run { name, template: template.into(), ip, cmd, resources, generated, spec, tty, rerun, attacher },
                notify_fd(),
            )
        }
    }
}

/// A foreground `run -i`/`-t`: attached to its app from its first byte, it exits with it. As a foreground run's,
/// its VM leaves no exited record (unless detached from, when it is a background VM's like any other).
fn run_attached(host: &Host, name: &str, keep: bool) -> Result<()> {
    let code = attach::attach(host, name, Some(0))?;
    let until = Instant::now() + Duration::from_secs(10);
    while !keep && host.alive(name) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    if !keep && !host.alive(name) && host.vms(name, "exited")?.exists() {
        // Its log stays, as a foreground run's without a terminal (its diagnostics are there alone).
        let _ = remove_stopped(host, name, true, false, None, false);
    }
    util::exit(code)
}

fn port_specs(args: &Args) -> Result<Vec<ports::Port>> {
    let mut ports = Vec::new();
    for s in args.all("publish") {
        let p: ports::Port = s.parse()?;
        if let Some(old) = ports.iter().find(|old: &&ports::Port| old.overlaps(&p)) {
            crate::bail!("duplicate port mapping {p}: {old} already publishes that host address and port");
        }
        ports.push(p);
    }
    Ok(ports)
}

/// A bare env key takes this environment's value, if present, for run, exec and pull.
fn env_flags(args: &Args) -> Result<Vec<String>> {
    let env = args.all("env");
    for kv in &env {
        app::validate_env(kv)?;
    }
    Ok(env
        .into_iter()
        .filter_map(|kv| match kv.contains('=') {
            true => Some(kv),
            false => std::env::var(&kv).ok().map(|v| format!("{kv}={v}")),
        })
        .collect())
}

/// `-e`, `--env-file`, `--entrypoint`, `--keep`, `--rm`, `-p` (and the `--ip` asked for, for a rerun).
fn run_spec(args: &Args, ip: Option<std::net::Ipv4Addr>) -> Result<app::RunSpec> {
    let lookup = |k: &str| std::env::var(k).ok();
    let mut env = Vec::new();
    for f in args.all("env-file") {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("--env-file {f}: {e}"))?;
        env.extend(app::parse_env_file(&text, lookup).map_err(|e| format!("--env-file {f}: {e}"))?);
    }
    // After the files, as docker: `-e` wins. A bare `K` is this environment's, if it has one.
    env.extend(env_flags(args)?);
    let (stdin, tty) = (args.has("interactive"), args.has("tty"));
    let entrypoint = match args.get("entrypoint") {
        Some(e) => Some(image::parse_argv(e)?),
        // docker's CMD, whole: images' entrypoints are not kept apart from their commands.
        None if (stdin || tty) && !args.rest.is_empty() => Some(args.rest.clone()),
        None => None,
    };
    Ok(app::RunSpec { env, entrypoint, keep: args.has("keep"), rm: args.has("rm"), ip, ports: port_specs(args)?, stdin, tty })
}

/// `start` of an exited VM (`app::Exited`): a new run under its name, as its record (read under
/// the name, `Proc::run`) says it was run.
fn rerun(host: &Host, name: &str) -> Result<Option<Start>> {
    host::check_name(name)?;
    if host.suspended(name)?.exists() || !host.has_record(name, "exited") {
        return Ok(None);
    }
    let (template, resources, spec) = (String::new(), vm::Resources::default(), app::RunSpec::default());
    Ok(Some(Start::Run {
        name: name.into(),
        template,
        ip: None,
        cmd: None,
        resources,
        generated: false,
        spec,
        tty: std::io::stdin().is_terminal(),
        rerun: true,
        attacher: false,
    }))
}

/// `kill -s SIGNAL NAME`: to its app.
fn signal_app(host: &Host, name: &str, sig: i32) -> Result<()> {
    host::check_name(name)?;
    if !host.alive(name) {
        return Err(not_running(host, name));
    }
    vmproc::call(host, name, json!({"op": "signal", "signal": sig}), None)?;
    output(format_args!("{name}\n"))
}

/// `run --checkpoint DIR`: the checkpoint's name and address unless `--name`, `--ip`.
fn run_checkpoint(args: &Args) -> Result<()> {
    let what = args.get("checkpoint").unwrap_or_default();
    // A path (v0.1.0's checkpoints, a stopped VM's) as it is; else a stored one.
    let dir = match what.contains('/') {
        true => std::path::absolute(what)?,
        false => match checkpoint::store::find(&checkpoint::store::list(&state(args)?), what) {
            Ok(e) => e.dir.clone(),
            Err(e) if std::path::Path::new(what).is_dir() => bail!("{e}; a checkpoint directory is given by its path: ./{what}"),
            Err(e) => Err(e)?,
        },
    };
    let resources = resources(args)?;
    let s = Start::Restore {
        dir: dir.clone(),
        name: args.get("name").map(String::from),
        ip: args.get("ip").map(String::from),
        paused: args.has("paused"),
        resources,
        ports: port_specs(args)?,
    };
    if args.has("detach") {
        let host = open_host(args)?;
        // A detached restore logs to the VM's name, which the checkpoint has without --name.
        let own = checkpoint::read_manifest(&dir)?.name;
        let name = args.get("name").map_or_else(|| own.clone(), String::from);
        return print(spawn_detached(&host, &name, &args.child_args, &restore_run_log(&host, &name, name == own)?, false)?);
    }
    vmproc::main(open_host(args)?, paths(args)?, s, notify_fd())
}

/// What a foreground `run` that claimed a standby VM forwards to it (SIGHUP is ignored).
const FOLLOW_SIGNALS: [i32; 6] = [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGCONT, libc::SIGHUP];

/// A log a `run` opened for the VM process it starts (`Host::own_logs`), and the token that
/// process keeps it by as it takes the name (whether or not this one is still there).
#[derive(Debug)]
struct RunLog {
    file: std::fs::File,
    token: String,
}

impl std::ops::Deref for RunLog {
    type Target = std::fs::File;
    fn deref(&self) -> &std::fs::File {
        &self.file
    }
}

impl std::ops::DerefMut for RunLog {
    fn deref_mut(&mut self) -> &mut std::fs::File {
        &mut self.file
    }
}

fn new_run_log(host: &Host, name: &str) -> Result<RunLog> {
    // Refuse a taken name and clear a failed VM's logs before opening it for the child.
    let _name = host.take_name(name, false)?;
    log_file(host, name)
}

/// `new_run_log` of a detached restore: under the checkpoint's own name (`own`), the VM goes on
/// in its logs (`Host::take_restoring_name`). The name is held until the log is open, so no
/// other VM's logs are taken for it meanwhile.
fn restore_run_log(host: &Host, name: &str, own: bool) -> Result<RunLog> {
    let _name = host.take_restoring_name(name, own)?;
    log_file(host, name)
}

fn log_file(host: &Host, name: &str) -> Result<RunLog> {
    host::check_name(name)?;
    let token = util::random_hex(16)?;
    // Opened and marked written holding the logs lock (shared): garbage
    // collection removes only a quiet log, holding it exclusively.
    let _logs = host.logs_lock(libc::LOCK_SH)?;
    let f = util::output::open_in(&host.own_logs(name, Some(&token))?, c"log", libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT)?;
    f.set_modified(std::time::SystemTime::now())?;
    Ok(RunLog { file: f, token })
}

/// Starts `child` (this binary's arguments) in the background, and prints its VM's answer.
/// `attacher`: a foreground `run -i`/`-t` attaches to it (`Proc::attacher`).
/// The child keeps `log`'s directory by its token (`host::HANDOFF_ENV`).
fn spawn_detached(host: &Host, name: &str, child: &[String], log: &RunLog, attacher: bool) -> Result<Value> {
    let log_path = host.vms(name, "log")?;
    let (r, w) = std::os::unix::net::UnixStream::pair()?;
    let env = [("FLEXVM_NOTIFY_FD", "3"), (host::HANDOFF_ENV, log.token.as_str()), ("FLEXVM_ATTACHER", "1")];
    util::spawn_self(child, &log.file, w.as_raw_fd(), &env[..2 + usize::from(attacher)])?;
    drop(w);
    let reply = recv_json(&mut BufReader::new(r))?.ok_or_else(|| format!("the vm process failed to start (see {})", log_path.display()))?;
    if reply["ok"] != json!(true) {
        return Err(vmproc::start_error(&reply, "failed"));
    }
    Ok(reply["result"].clone())
}

fn notify_fd() -> Option<std::fs::File> {
    let fd: i32 = std::env::var("FLEXVM_NOTIFY_FD").ok()?.parse().ok()?;
    std::env::remove_var("FLEXVM_NOTIFY_FD");
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    Some(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// A foreground `run` that claimed a standby VM: forwards signals, exits with its status.
fn follow(mut conn: BufReader<std::os::unix::net::UnixStream>, id: host::Ident) -> Result<()> {
    // Blocked since before the claim (`run`): any that came meanwhile are pending, and forwarded.
    let set = util::block_signals(&FOLLOW_SIGNALS);
    // A fast command's process may be gone already: its exit frame is buffered.
    if let Ok(Some(vm)) = host::PidFd::open(&id) {
        std::thread::spawn(move || loop {
            match util::wait_signal(&set) {
                libc::SIGHUP => {}
                sig => drop(vm.signal(sig)),
            }
        });
    }
    // No status: its process (the VM, started) ended without one, so it died under this run.
    let reply = recv_json(&mut conn).ok().flatten();
    util::exit(reply.and_then(|r| r["exit"].as_i64()).map_or(vmproc::DIED, |c| c as i32))
}

/// `start` (and `restart`): a running VM's process resumes it, a stopped or exited one a new
/// process. A start that lost the name to another meanwhile (two `start`s at once) is that one's:
/// done once it runs, as resuming a running VM is.
fn start(host: &Host, args: &Args, name: &str) -> Result<()> {
    if resume(host, name)? {
        return output(format_args!("{name}\n"));
    }
    // Nothing to start (no process, no stopped or exited VM): said here, before a process is
    // spawned whose taking the name would clear a moved VM's hint.
    if !host.alive(name) && !host.suspended(name)?.exists() && !host.has_record(name, "exited") {
        return Err(no_vm(host, name));
    }
    match spawn_detached(host, name, &child_args(args, &["start", "--attach", "--", name]), &log_file(host, name)?, false) {
        Ok(v) => print(v),
        Err(e) if host::name_taken(&e) || host.alive(name) => match started_meanwhile(host, name, Instant::now() + Duration::from_secs(60))? {
            true => output(format_args!("{name}\n")),
            false => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// Whether a VM another process holds `name` for runs by `deadline`: its process resumes it (a
/// no-op once it runs). False once nothing holds the name (that start failed), or at `deadline`.
fn started_meanwhile(host: &Host, name: &str, deadline: Instant) -> Result<bool> {
    loop {
        if resume(host, name)? {
            return Ok(true);
        }
        if !host.alive(name) || Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A running VM's process resumes it (true); a suspended one a new process. A
/// suspend coming (a SIGTERM sent before) is waited out: the VM then runs here
/// (it failed) or is suspended. Never true unless its process said so, once the
/// VM runs: a resume that fails, or a destroy meanwhile, is an error.
fn resume(host: &Host, name: &str) -> Result<bool> {
    // A suspend is waited out as long as `stop` waits for one: its copy of the VM's memory to disk.
    resume_by(host, name, Instant::now() + Duration::from_secs(30), Instant::now() + STOP_WAIT)
}

fn resume_by(host: &Host, name: &str, deadline: Instant, suspend_by: Instant) -> Result<bool> {
    host::check_name(name)?;
    loop {
        let req = json!({"op": "resume"});
        let reply = vmproc::connect(host, name, &req, &[], Instant::now() + Duration::from_secs(10), None)
            .map(|c| recv_json(&mut BufReader::new(util::By { s: c, at: Instant::now() + RESUME_ANSWER })));
        match reply {
            Ok(Ok(Some(v))) if v["ok"] == true && v["result"]["suspending"] == true => {
                if Instant::now() >= suspend_by {
                    bail!("vm {name}: timed out waiting for suspend; see {}; retry when it finishes", host.vms(name, "log")?.display());
                }
            }
            Ok(Ok(Some(v))) if v["ok"] == true => return Ok(true),
            // Its control connections are all taken, or its process has no VM yet (a resume or
            // restore that bound its socket first, another `start`'s): asked again.
            Ok(Ok(Some(v))) if (v["error"] == "busy" || v["busy"] == true) && Instant::now() < deadline => {}
            Ok(Ok(Some(v))) => return Err(v["error"].as_str().unwrap_or("resume refused").to_string().into()),
            Ok(Err(e)) if host.alive(name) => return Err(format!("vm {name}: its resume was not confirmed: {e}").into()),
            // It took the request: whatever ended it meanwhile ended the resume too.
            Ok(_) => {
                return Err(
                    format!("vm {name} ended before its resume was confirmed (killed or stopped meanwhile?); see {}", host.vms(name, "log")?.display()).into()
                )
            }
            Err(_) if host.entry(name).is_err() => return Ok(false),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// How long `resume` waits for the VM process's answer: longer than it waits for the resume.
const RESUME_ANSWER: Duration = Duration::from_secs(75);

/// `start -a` attaches to a VM it starts, so only a stopped one: a stop under way is waited out,
/// a paused or running VM refused (its command's output and status are its own process's).
fn stopped_to_attach(host: &Host, name: &str) -> Result<()> {
    host::check_name(name)?;
    let deadline = Instant::now() + STOP_WAIT;
    while host.alive(name) {
        match host.entry(name).map(|e| e.state) {
            Ok(s) if s == "paused" => bail!("vm {name} is paused, not stopped: flexvm unpause {name} resumes it (start -a attaches only to a vm it starts)"),
            // Stopping, or starting (not published yet): what it ends as decides.
            Ok(s) if s == "suspending" && Instant::now() < deadline => {}
            Err(_) if Instant::now() < deadline => {}
            Ok(s) => bail!("vm {name} is {s}, not stopped: start -a attaches only to a vm it starts"),
            Err(e) => return Err(e),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// Why a VM with no process cannot be paused or unpaused.
fn not_running(host: &Host, name: &str) -> util::Error {
    no_process(host, name, "no running vm named")
}

/// What is left of `name`, which no process runs: a stopped, exited, failed or lost VM, where
/// it moved, or nothing (no vm named it).
pub fn no_vm(host: &Host, name: &str) -> util::Error {
    no_process(host, name, "no vm named")
}

fn no_process(host: &Host, name: &str, none: &str) -> util::Error {
    // A stopped VM's checkpoint, not debris (consumed by a resume, or being discarded).
    match host.is_suspended(name) {
        true => format!("vm {name} is stopped: flexvm start {name}").into(),
        _ if host.has_record(name, "exited") => format!("vm {name} has exited: flexvm start {name} runs it again").into(),
        _ if host.has_record(name, "failed") => format!("vm {name} has failed: see flexvm ps -a; flexvm rm {name} clears it").into(),
        _ if host.has_record(name, "lost") => format!("vm {name} is lost: see flexvm ps -a; flexvm rm {name} clears it").into(),
        _ => match std::fs::read_to_string(host.vms(name, "moved").unwrap_or_default()) {
            Ok(to) => format!("vm {name} moved to {to}; it runs there").into(),
            Err(_) => format!("{none} {name:?}").into(),
        },
    }
}

/// Signals the instance registered under `name`, returning its pidfd and identity: None when
/// there is none (no registry entry, or its process gone meanwhile). Anything else that keeps
/// it from being signalled (a process this one cannot see or tell apart, a refused signal) is
/// an error, never "not running". `check` refuses an entry before it is signalled (its error returned).
fn signal_entry(host: &Host, name: &str, sig: i32, check: &dyn Fn(&host::Entry) -> Result<()>) -> Result<Option<(host::PidFd, host::Ident)>> {
    let Ok(e) = host.entry(name) else { return Ok(None) };
    check(&e)?;
    let Some(fd) = host::PidFd::open(&e.ident)? else { return Ok(None) };
    match fd.signal(sig) {
        Ok(()) => Ok(Some((fd, e.ident))),
        Err(_) if !e.ident.alive() => Ok(None),
        Err(e) => Err(format!("vm {name}: {e}").into()),
    }
}

/// How long `stop`, `pause`, `kill` and `rm -f` wait for a VM that holds its name but is not registered yet (starting).
const START_WAIT: Duration = Duration::from_secs(if cfg!(test) { 3 } else { 60 });

/// `signal_entry`, waiting (as `stopped_to_attach` does) while the name is held with no entry
/// (a VM starting, or an `rm` or sweep deciding): None once nothing holds it.
fn signal_ready(host: &Host, name: &str, sig: i32, check: &dyn Fn(&host::Entry) -> Result<()>) -> Result<Option<(host::PidFd, host::Ident)>> {
    let deadline = Instant::now() + START_WAIT;
    loop {
        if let Some(v) = signal_entry(host, name, sig, check)? {
            return Ok(Some(v));
        }
        if !host.alive(name) {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            bail!("vm {name:?} is starting or its registry is unavailable; try again once it is ready, or see {}", host.vms(name, "log")?.display());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A VM whose process runs in a PID namespace this one cannot see (`host::Unseen`): never signalled by its pid.
fn unseen(name: &str, e: util::Error) -> util::Error {
    host::Unseen(format!("vm {name}: {e}")).into()
}

/// How long `stop` waits for a suspend: its copy of the VM's memory to disk.
const STOP_WAIT: Duration = Duration::from_secs(600);

/// SIGTERM, and waits until the VM is suspended (its process gone). Stopped or exited: a no-op.
/// Returns the name the VM has last (a rename as it was signalled moves it on: `restart` starts that).
fn stop(host: &Host, name: &str) -> Result<String> {
    host::check_name(name)?;
    // The instance signalled, its identity and pidfd from one read of the registry: its exit status
    // tells an app that exited first (`--rm` or attached VMs leave no exited record).
    let (vm, ident) = match signal_ready(host, name, libc::SIGTERM, &|_| Ok(())) {
        Ok(Some(v)) => v,
        Err(e) if e.is::<host::Unseen>() => return Err(unseen(name, e)),
        Err(e) => return Err(e),
        // A stopped VM's checkpoint, not debris (a consumed or discarded one) under its name.
        Ok(None) if host.is_suspended(name) || host.has_record(name, "exited") => return Ok(name.into()),
        Ok(None) => return Err(not_running(host, name)),
    };
    // Followed by its identity, under whatever name it has: a rename that held its op as the
    // signal landed moves it on (#1178).
    let (start, mut seen, mut last) = (Instant::now(), false, name.to_string());
    while !vm.wait(Duration::from_millis(100)) {
        let entry = host.entry(&last).ok().filter(|e| e.ident == ident).or_else(|| host.entries().into_iter().find(|e| e.ident == ident));
        if let Some(e) = &entry {
            last.clone_from(&e.name);
        }
        let state = entry.map(|e| e.state).unwrap_or_default();
        seen |= state == "suspending" || state == "checkpointing";
        // Back to running: the suspend failed, and the VM runs on (its log says why).
        let gave_up = seen && matches!(state.as_str(), "running" | "paused");
        if gave_up || start.elapsed() > STOP_WAIT || (!seen && start.elapsed() > Duration::from_secs(10) && !matches!(state.as_str(), "source" | "reconciling"))
        {
            let name = renamed_as(name, &last);
            return Err(format!("vm {name} did not suspend (it runs on); see {}", host.vms(&last, "log")?.display()).into());
        }
    }
    // Its records are under the name it had last, as its exit record says (written before it let
    // the name go), else the last one seen.
    let (last, exit) = match containers::last_name(host, &last, &ident) {
        Some((n, e)) => (n, Some(e)),
        None => (last, None),
    };
    let shown = renamed_as(name, &last);
    let name = last.as_str();
    // Suspended by the instance signalled, as its checkpoint's OWNER says: never debris (a checkpoint
    // consumed by a resume that then died) or another instance's.
    if host.is_suspended(name) && host.suspended(name).ok().and_then(|d| lifecycle::read_owner(&d)).is_some_and(|o| o == ident) {
        return Ok(last);
    }
    // Its app exited first (the VM was ending, so took no suspend): stopped all the same.
    if host.has_record(name, "exited") {
        return Ok(last);
    }
    if let Ok(to) = std::fs::read_to_string(host.vms(name, "moved")?) {
        return Err(format!("vm {shown} moved to {to} before it was stopped; stop it there").into());
    }
    let died = ["failed", "lost"].iter().any(|ext| host.has_record(name, ext));
    // Its own exit record, as read and checked (a later instance of the name may replace it since).
    match !died && app_exited(exit.as_ref(), &ident) {
        true => Ok(last),
        false => Err(format!("vm {shown} ended without suspending; see {}", host.vms(name, "log")?.display()).into()),
    }
}

/// `name`, as a message names it, renamed `last` meanwhile.
fn renamed_as(name: &str, last: &str) -> String {
    match name == last {
        true => name.into(),
        false => format!("{name} (renamed {last})"),
    }
}

/// An `--rm` or attached VM's app exited: only its exit status is left. It must be the status of
/// `ident`, the instance signalled (never an earlier one's), and not that of a kill or a death.
/// A record from before it said whose status it is: a status flexvm gives is taken as not the app's.
fn app_exited(exit: Option<&containers::Exit>, ident: &host::Ident) -> bool {
    exit.is_some_and(|e| e.ident == *ident && e.app.unwrap_or(![vmproc::DIED, 128 + libc::SIGINT, 128 + libc::SIGQUIT].contains(&e.code)))
}

/// SIGTSTP, and waits until its vCPUs are paused: the instance signalled, followed by its
/// identity under whatever name it has (a rename that held its op as the signal landed).
fn pause(host: &Host, name: &str) -> Result<()> {
    host::check_name(name)?;
    let (vm, ident) = match signal_ready(host, name, libc::SIGTSTP, &|_| Ok(())) {
        Ok(Some(v)) => v,
        Ok(None) => return Err(not_running(host, name)),
        Err(e) if e.is::<host::Unseen>() => return Err(unseen(name, e)),
        Err(e) => return Err(e),
    };
    let (deadline, mut last) = (Instant::now() + Duration::from_secs(30), name.to_string());
    loop {
        let entry = host.entry(&last).ok().filter(|e| e.ident == ident).or_else(|| host.entries().into_iter().find(|e| e.ident == ident));
        if let Some(e) = &entry {
            last.clone_from(&e.name);
        }
        let shown = renamed_as(name, &last);
        match entry.map(|e| e.state) {
            Some(s) if s == "paused" => return output(format_args!("{name}\n")),
            Some(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Some(s) => bail!("vm {shown} is still {s}; see {}", host.vms(&last, "log")?.display()),
            // Not registered for a moment (its entry rewritten), or ended: its pidfd tells.
            None if !vm.wait(Duration::ZERO) && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            None => bail!("vm {shown} ended before it paused; see {}", host.vms(&last, "log")?.display()),
        }
    }
}

/// `kill` (`running`) destroys a running VM; `rm` (`stopped`) removes a stopped one (suspended,
/// failed or lost), and with -f a running one too.
fn remove(host: &Host, name: &str, running: bool, stopped: bool) -> Result<()> {
    host::check_name(name)?;
    let alive = host.alive(name);
    if alive && !running {
        bail!("vm {name} is running: stop or kill it first, or flexvm rm -f {name}");
    }
    // Its tap and route go now, not at a sweep; best effort, as taking the name reaps again where it must.
    let _ = host.reap_dead_holder(name);
    let records = || -> Result<bool> { Ok(host.suspended(name)?.exists() || ["failed", "lost", "exited"].iter().any(|ext| host.has_record(name, ext))) };
    if !alive && !stopped && records()? {
        bail!("vm {name} is not running (see flexvm ps -a); flexvm rm {name} removes it");
    }
    let done = || output(format_args!("{name}\n"));
    if !running {
        return remove_stopped(host, name, records()?, true, None, false).and_then(|()| done());
    }
    // Reconciling sources accept SIGINT too; the process records the owed outcome before ending.
    let not_source = |e: &host::Entry| -> Result<()> {
        match e.state == "source" {
            true => Err(format!("vm {name} is the source of a migration in progress; it ends once the target has its memory (kill it where it runs)").into()),
            false => Ok(()),
        }
    };
    // A VM starting (holding the name, not registered yet) is waited for, as `stop` waits (#1189).
    let killed = match signal_ready(host, name, libc::SIGINT, &not_source) {
        Err(e) if e.is::<host::Unseen>() => return Err(unseen(name, e)),
        r => r?,
    };
    // Test gate `kill_gate`: the name's lock probed (`alive`), the VM signalled if it had an entry.
    host::gate("kill_gate");
    if let Some((vm, ident)) = &killed {
        if !vm.wait(Duration::from_secs(30)) {
            return Err(format!("vm {name} is still there; see {}", host.vms(name, "log")?.display()).into());
        }
        // Only what the instance signalled left is undone or removed (`owns`): its records are
        // under the name it had last, as its exit record says (written before it let the name go).
        let last = containers::last_name(host, name, ident).map_or_else(|| name.to_string(), |(n, _)| n);
        let shown = renamed_as(name, &last);
        // A migration past its pause refused the kill, and the VM runs on at its target (#567).
        if let Ok(to) = std::fs::read_to_string(host.vms(&last, "moved")?) {
            return Err(format!("vm {shown} moved to {to} before the kill took; kill it there").into());
        }
        // `rm -f` also removes logs and any exit or suspend record that won the race, under its name.
        if stopped {
            return remove_stopped(host, &last, true, true, Some(ident), true).and_then(|()| done());
        }
        // A suspend that finished before the kill took is undone: the kill wins.
        if host.suspended(&last)?.exists() {
            let lock = host.take_name(&last, true)?;
            // Taking the name removed it if it was not a suspended VM (an interrupted suspend's or resume's).
            if host.suspended(&last)?.exists() {
                match owns(host, &lock, ident, true) {
                    Some(true) => lifecycle::revoke(host, &last)??,
                    // Another instance's, or not shown whose: left as found, its dead holder's record too (#1185).
                    Some(false) => lock.release_to_prior(),
                    None => {
                        lock.release_to_prior();
                        return Err(unconfirmed(&shown, &last));
                    }
                }
            } else {
                lock.release_to_prior();
            }
        }
        return done();
    }
    if stopped {
        return remove_stopped(host, name, records()?, true, None, true).and_then(|()| done());
    }
    // Nothing signalled: what held the name (`alive`) was no registered VM, or let it go since (a
    // start whose resume failed, a sweep, an `rm` deciding). A stopped or ended VM's records stay:
    // `kill` is for a running VM.
    if host.alive(name) {
        return Err(
            format!("vm {name:?} is starting or its registry is unavailable; try again once it is ready, or see {}", host.vms(name, "log")?.display()).into()
        );
    }
    if records()? {
        bail!("vm {name} is not running (see flexvm ps -a); flexvm rm {name} removes it");
    }
    nothing_to_remove(host, name)
}

/// Whether what is under the name `lock` holds is what `ident` left, decided holding the name; None
/// when nothing shows whose it is. A stopped VM (`checkpoint`): who suspended it, as its checkpoint
/// says. Its other records: a holder that died holding the name (the newest one to hold it) is
/// theirs; else its exit record's instance is (a rename into the name, or another VM's end under
/// it, replaces that record; a sweep, or taking the name, removes one a later holder's death made stale).
fn owns(host: &Host, lock: &host::NameLock, ident: &host::Ident, checkpoint: bool) -> Option<bool> {
    if checkpoint {
        if let Some(owner) = host.suspended(&lock.name).ok().and_then(|d| lifecycle::read_owner(&d)) {
            return Some(owner == *ident);
        }
    }
    if let Some(prior) = &lock.prior {
        return Some(prior == ident);
    }
    containers::exit_record(host, &lock.name).map(|e| e.ident == *ident)
}

/// What is under `last` now may not be what the VM killed left: left as it is.
fn unconfirmed(shown: &str, last: &str) -> util::Error {
    format!("vm {shown} was killed, but could not confirm that what is under the name now is what it left (stopped or ended before the kill took?): left as it is; flexvm rm {last} removes it").into()
}

/// `rm` (after killing a running VM for -f): under the name, so a `start` meanwhile either
/// wins first (and this is refused: the VM runs) or waits until it is gone; signals nothing.
/// `had`: a stopped VM's records were there before, or -f just killed its process. `logs`: its logs
/// and exit status go too (`rm`, so a new VM of the name starts a fresh one). `of`: only the records that
/// instance left go (`rm -f` of the one it killed), none of another VM's under the name since.
/// With nothing recorded (`!had`), what a VM that died recording nothing (SIGKILLed) left goes too:
/// its dead holder's lock and its logs (`Host::left_unrecorded`), decided again holding the name (#1187).
/// `force`: an `rm -f`, never told to `rm -f`.
fn remove_stopped(host: &Host, name: &str, had: bool, logs: bool, of: Option<&host::Ident>, force: bool) -> Result<()> {
    if !had && (host.alive(name) || host.has_record(name, "moved") || !host.left_unrecorded(name)?) {
        return nothing_to_remove(host, name);
    }
    remove_held(host, name, had, logs, of, force)
}

/// `remove_stopped` past its checks, which it takes the name for. With nothing recorded before
/// (`!had`), what those checks found is checked again holding it: a VM that took the name since
/// may have moved away (its hint and logs kept: it runs there) or ended (its records left for a
/// `rm` that sees them), and then nothing is removed.
fn remove_held(host: &Host, name: &str, had: bool, logs: bool, of: Option<&host::Ident>, force: bool) -> Result<()> {
    let lock = match host.take_name(name, true) {
        Ok(lock) => lock,
        // A VM of the name started meanwhile: `rm -f` (which killed or found none) is tried again.
        Err(_) if host.alive(name) && force => bail!("vm {name} started meanwhile: try again"),
        Err(_) if host.alive(name) => bail!("vm {name} is running: stop or kill it first, or flexvm rm -f {name}"),
        Err(e) => return Err(e),
    };
    if !had {
        let recorded = host.suspended(name)?.exists() || ["exited", "failed", "lost"].iter().any(|ext| host.has_record(name, ext));
        let moved = std::fs::read_to_string(host.vms(name, "moved")?);
        if moved.is_ok() || host.has_record(name, "moved") || recorded {
            lock.release_to_prior();
            return Err(match moved {
                Ok(to) => format!("vm {name} moved to {to}; kill it there").into(),
                Err(_) if host.has_record(name, "moved") => format!("vm {name} moved away; kill it where it runs").into(),
                Err(_) => format!("vm {name} ended meanwhile (see flexvm ps -a): left as it is; flexvm rm {name} removes it").into(),
            });
        }
    }
    if let Some(id) = of {
        let checkpoint = host.suspended(name)?.exists();
        match owns(host, &lock, id, checkpoint) {
            Some(true) => {}
            // Another instance's: left as found, its dead holder's record too (#1185).
            Some(false) => {
                lock.release_to_prior();
                return Ok(());
            }
            // Nothing left of any VM under the name: nothing to remove.
            None if !checkpoint && !["exited", "failed", "lost", "log"].iter().any(|ext| host.has_record(name, ext)) => return Ok(()),
            None => return Err(unconfirmed(name, name)),
        }
    }
    // Taking the name removed it if it was not a suspended VM (an interrupted suspend's or resume's).
    if host.suspended(name)?.exists() {
        lifecycle::revoke(host, name)??;
    }
    if logs && had {
        lock.remove_logs()?;
    } else if logs {
        // Holding the name: its holder, if any, proven dead by its full identity (`take_name` reaps
        // only on `Liveness::Gone`, and a live one, in any PID namespace, holds the lock). Logs a
        // live `run` prepares for the VM it starts are its own, and stay.
        if !lock.remove_unowned_logs()? && lock.prior.is_none() {
            drop(lock);
            return nothing_to_remove(host, name);
        }
    }
    // Its exit status too (`rm`: a removed VM has none left to wait for), held under the name and
    // only once it is known to be the instance's whose records go: never a later VM's of the name.
    let exts: &[&str] = if logs { &["exited", "failed", "lost", "exit"] } else { &["exited", "failed", "lost"] };
    for ext in exts {
        match std::fs::remove_file(host.vms(name, ext)?) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("vm {name}: removing its {ext} record: {e}").into()),
            _ => {}
        }
    }
    Ok(())
}

/// Why there is nothing under `name` to remove: a VM starting (holding the name, or a `run`
/// preparing its logs), one that moved away, or no VM at all.
fn nothing_to_remove(host: &Host, name: &str) -> Result<()> {
    if host.alive(name) || host.has_record(name, "logs") && !host.left_unrecorded(name)? {
        bail!("vm {name:?} is starting or its registry is unavailable; try again once it is ready, or see {}", host.vms(name, "log")?.display());
    }
    match std::fs::read_to_string(host.vms(name, "moved")?) {
        Ok(to) => Err(format!("vm {name} moved to {to}; kill it there").into()),
        Err(_) => Err(format!("no vm named {name:?}").into()),
    }
}

/// Withdraws the generation an address was lent out with, everywhere, and forgets what
/// outcome was owed for it: only for a target gone for good, so `--force` it is.
fn reclaim(host: &Host, ip: &str, force: Option<u64>) -> Result<()> {
    let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| format!("reclaim takes the address (an IPv4 address), not {ip:?}"))?;
    let Some((gen, owed)) = host.lent_to(ip)? else { return Err(format!("{ip} is not lent out").into()) };
    let whom = match owed.as_slice() {
        [] => "a vm that migrated away".to_string(),
        o => o.iter().map(|(id, to)| format!("migration {id} to {to}, whose outcome is unknown")).collect::<Vec<_>>().join(", "),
    };
    let Some(expected) = force else {
        return Err(format!(
            "{ip} is lent out (generation {gen}) with {whom}. Reclaiming withdraws that generation everywhere and lets {ip} be handed out here again: \
             first make sure no host runs that vm any more (kill it there, or know the host is gone for good), or two vms will share {ip}. \
             Then: flexvm reclaim {ip} --force {gen}"
        )
        .into());
    };
    let (gen, forgot) = host.reclaim(ip, expected)?;
    // The operator's word that no host runs it: past whichever peer it is routed via there.
    vmproc::tell_peers(host, json!({"op": "route", "ip": ip.to_string(), "gen": gen, "rev": u64::MAX}));
    util::log_line(format!(
        "WARNING: {ip} reclaimed (generation {gen} withdrawn, lent with {whom}); if that vm still runs anywhere, it shares {ip} with the next vm given it"
    ));
    print(json!({"ip": ip.to_string(), "withdrawn_gen": gen, "forgot_migrations": forgot.iter().map(|(id, _)| id).collect::<Vec<_>>()}))
}

/// The VMs `ps -a` lists: registered, suspended, failed and lost.
fn vms(host: &Host) -> Vec<Value> {
    let mut vms: Vec<Value> = host
        .entries()
        .into_iter()
        .map(|e| {
            let mut v = serde_json::to_value(&e).unwrap_or_default();
            v["rss_mib"] = json!(e.rss_mib());
            v
        })
        .collect();
    vms.extend(lifecycle::unreadable_running(host, &vms));
    let names = |dir: PathBuf| std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.file_name().to_string_lossy().into_owned());
    // A name lock alone need not mean a registered VM: a resume may not have published yet.
    for n in names(host.state.join("suspended")).filter(|n| !n.starts_with('.')) {
        if !vms.iter().any(|v| v["name"] == n) {
            vms.extend(lifecycle::describe_suspended(host, &n));
        }
    }
    // Failed, then exited, then lost (with the host, `Host::after_boot`), each in directory order.
    const RECORDS: [&str; 3] = ["failed", "exited", "lost"];
    let mut records: Vec<(usize, String)> = names(host.run.join("vms"))
        .filter_map(|f| f.rsplit_once('.').and_then(|(n, ext)| Some((RECORDS.iter().position(|&r| r == ext)?, n.to_string()))))
        .filter(|(_, n)| !host.alive(n))
        .collect();
    records.sort_by_key(|r| r.0);
    for (state, n) in records.into_iter().map(|(i, n)| (RECORDS[i], n)) {
        let Ok(path) = host.vms(&n, state) else { continue };
        let error = match state {
            "exited" => match app::Exited::read(&path) {
                Ok(r) => {
                    vms.push(json!({"name": n, "state": state, "status": r.status, "template": r.template, "exited_at": r.at, "ports": r.spec.ports}));
                    continue;
                }
                Err(e) => e.to_string(),
            },
            // Unless a record of its failure says more.
            "lost" if host.has_record(&n, "failed") => continue,
            _ => std::fs::read_to_string(path).unwrap_or_default(),
        };
        vms.push(json!({"name": n, "state": state, "error": error}));
    }
    vms
}

/// The states `ps` leaves out without `-a`: no process runs them.
fn stopped(v: &Value) -> bool {
    matches!(v["state"].as_str(), Some("suspended" | "quarantined" | "exited" | "failed" | "lost"))
}

/// `ps`: `-a`, `-q`, `--json`, `--filter`s and `--format` (`containers`).
fn ps(host: &Host, args: &Args) -> Result<()> {
    let filters = containers::Filters::parse(&args.all("filter"))?;
    let format = args.get("format").filter(|f| f.trim() != "table").map(containers::Format::parse).transpose()?;
    let all = args.has("all") || filters.has_status();
    let vms: Vec<Value> = vms(host).into_iter().filter(|v| (all || !stopped(v)) && filters.matches(v)).collect();
    if args.has("quiet") {
        return vms.iter().try_for_each(|v| output(format_args!("{}\n", containers::field(v, "Name"))));
    }
    if args.has("json") {
        return print(json!(vms));
    }
    if let Some(f) = format {
        return output(format_args!("{}", f.render(&vms)?));
    }
    let row = |c: [&str; 10]| {
        output(format_args!("{:<24} {:<15} {:<16} {:<12} {:>8} {:>5} {:>8} {:>8} {} {}\n", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9]))
    };
    // STARVED: refused memory here and throttled (moved to a peer if there is one).
    row(["NAME", "IP", "IMAGE", "STATE", "PID", "CPUS", "RSS MiB", "MAX MiB", "STARVED", "PORTS"])?;
    for v in &vms {
        let [a, b, image, mut d, e, g, h, starved] = ["Name", "IP", "Image", "State", "PID", "RSS", "MaxMiB", "Starved"].map(|k| containers::field(v, k));
        if let Some(status) = v["status"].as_i64().filter(|_| d == "exited") {
            d = format!("exited ({status})");
        }
        let cpus = v["cpus"].as_f64().map_or_else(|| containers::field(v, "VCPUs"), |c| c.to_string());
        let ports: Vec<ports::Port> = serde_json::from_value(v["ports"].clone()).unwrap_or_default();
        let ports = ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        row([&a, &b, &image, &d, &e, &cpus, &g, &h, &starved, &ports])?;
    }
    Ok(())
}

pub fn print(v: Value) -> Result<()> {
    output(format_args!("{}\n", serde_json::to_string_pretty(&v)?))
}

/// CLI output may be piped to a reader that exits early.
fn output(text: std::fmt::Arguments<'_>) -> Result<()> {
    match std::io::stdout().lock().write_fmt(text) {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(e.into()),
        _ => Ok(()),
    }
}

// Firecracker wants 1 or an even count of vCPUs, at most 32.
fn template_vcpus(args: &Args) -> Result<u32> {
    let cpus = util::host_cpus().min(32) as u32;
    let cpus = args.parse_or("vcpus", if cpus > 1 { cpus & !1 } else { 1 })?;
    if cpus != 1 && (cpus == 0 || cpus > 32 || cpus % 2 != 0) {
        bail!("--vcpus must be 1 or an even count up to 32");
    }
    Ok(cpus)
}

fn pull_missing_args(args: &Args, name: &str) -> Vec<String> {
    child_args(args, &["pull", &template::image_of(name)])
}

/// `run IMAGE` of an image not pulled here: `flexvm pull IMAGE` first, its output on stderr.
fn pull_missing(args: &Args, name: &str) -> Result<()> {
    let image = template::image_of(name);
    crate::log!("flexvm: unable to find image {image} here; pulling it");
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.args(pull_missing_args(args, name));
    let status = cmd.stdout(std::io::stderr()).status()?;
    if !status.success() {
        bail!("pulling {image} failed ({status})");
    }
    Ok(())
}

/// Whether a pull only adjusts the standby count, leaving its template options intact.
fn only_standby(args: &Args) -> bool {
    args.flags.iter().all(|(f, _)| GLOBAL.contains(&f.as_str()) || matches!(f.as_str(), "standby" | "tag"))
}

/// `--max` is the host's memory unless given (at most what a peer takes, and never below `--mem`:
/// then there is no hotplug); either given past what a peer takes is refused, as is `--max` below `--mem`.
fn pull_size(args: &Args) -> Result<template::Size> {
    let ram = (proc_kb("/proc/meminfo", "MemTotal").unwrap_or(0) >> 20).min(template::MAX_MEM_MIB);
    let max = args.parse_or("max", ram)?;
    let (mem, plug) = (args.parse_or("mem", template::base_mib(max))?, args.parse_or("plug", template::PLUG_MIB)?);
    for (flag, mib) in [("max", max), ("mem", mem)] {
        if mib > template::MAX_MEM_MIB {
            bail!("--{flag} must be at most {} MiB", template::MAX_MEM_MIB);
        }
    }
    if max < mem && args.has("max") {
        bail!("--max must be at least --mem ({mem} MiB)");
    }
    Ok(template::Size { vcpus: template_vcpus(args)?, mem_mib: mem, max_mib: max.max(mem), plug_mib: plug })
}

/// `pull SRC`: the template named after the image (or `--tag`), built unless it is up to date;
/// then `--standby N`, its count of standby VMs.
fn pull(args: &Args, src: &str) -> Result<()> {
    let name = match args.get("tag") {
        Some(tag) => template::name_of(tag)?,
        None if std::path::Path::new(src).exists() => bail!("{src} is a file or directory: name its image with --tag NAME[:TAG]"),
        None => template::name_of(src)?,
    };
    let size = pull_size(args)?;
    let standby = args.get("standby").map(|n| n.parse::<usize>().map_err(|_| format!("bad --standby {n:?}: give a count"))).transpose()?;
    if unsafe { libc::geteuid() } != 0 {
        bail!("run flexvm as root");
    }
    // Of an image pulled here, `--standby N` alone (and its --tag) only sets the count: the
    // pull's other options would have to be given again, or it would be rebuilt without them.
    if let (Some(n), true) = (standby, only_standby(args)) {
        if std::fs::symlink_metadata(paths(args)?.templates.join(&name)).is_ok() {
            return print(standby::set(&open_host(args)?, &name, n)?);
        }
    }
    util::check_kvm()?;
    // Interrupted, the build stops at its next step and removes its tap and staging (gigabytes:
    // an image's unpacked tree and rootfs too); a second signal ends flexvm at once, and the next
    // build removes the staging. Blocked before the image's download threads start.
    util::on_signal(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP], |sig| {
        log!("flexvm: stopping the template build; it cleans up first");
        template::interrupt(sig);
        loop {
            std::thread::park();
        }
    });
    let paths = paths(args)?;
    let opts = image_options(args, src)?;
    let host = open_host(args)?;
    let _pull = template::pull_lock(&paths, &name)?;
    let me = host::Ident::me();
    host::clear_taps(&host.run, &me);
    let tap = template::tap(&host.tap_prefix());
    let tap = net::create_free_tap(&tap, &host::tap_alias(&host.run, &me))?;
    let res = (|| {
        let init = args.get("init").map(PathBuf::from);
        // Held until the template is published: `rmi` leaves the root filesystem to this build.
        let (rootfs, meta, _reserved, _cache_lock) = image::prepare(&state(args)?.join("images"), init.as_deref(), &opts)?;
        if let Some(id) = template::up_to_date(&paths, &name, size, &rootfs, &meta) {
            output(format_args!("image {} is up to date (template {name}, id {id})\n", template::image_of(&name)))?;
            return Ok(None);
        }
        template::create(&host, &paths, &name, size, &rootfs, meta, &tap)
    })();
    net::delete_tap(&tap);
    // The generation the name linked to before, unless a VM here (or another name) still uses it.
    if let Some(old) = res? {
        standby::superseded(&host, &name);
        // Published already: a failed prune leaves the old generation to `image prune`.
        match template::prune(&paths, Some(&old), &|| host.template_users(), false) {
            Ok(removed) => {
                for removed in removed {
                    output(format_args!("{removed}\n"))?;
                }
            }
            Err(e) => crate::log!("flexvm: pull {name}: the superseded generation stays for image prune: {e}"),
        }
    }
    match standby {
        // Kept per image (`STATE/standby/NAME`): refilled now, and by every listener and VM process.
        Some(n) => print(standby::set(&host, &name, n)?),
        // A pool it superseded (or one short) comes back from the generation now linked.
        None => {
            if let Err(e) = standby::refill_later(&host, &name) {
                crate::log!("flexvm: pull {name}: standby refill: {e}");
            }
            Ok(())
        }
    }
}

/// `images`: a row per image (`template::images`), with its standby count.
fn images(host: &Host, paths: &Paths, args: &Args) -> Result<()> {
    let filters = management::Filters::parse(&args.all("filter"))?;
    let mut images = template::images(paths)?;
    images.retain(|v| filters.matches(v));
    if args.has("quiet") {
        let ids: std::collections::BTreeSet<_> = images.iter().filter_map(|v| v["id"].as_str()).collect();
        for id in ids {
            output(format_args!("{id}\n"))?;
        }
        return Ok(());
    }
    for v in &mut images {
        if let Some(name) = v["name"].as_str().map(String::from) {
            v["standby"] = json!(standby::target(host, &name));
        }
    }
    if args.has("json") {
        return print(json!(images));
    }
    let row = |c: [&str; 8]| output(format_args!("{:<32} {:<16} {:<16} {:>4} {:>8} {:>8} {:>7} {}\n", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]));
    row(["REPOSITORY", "TAG", "ID", "VCPU", "MAX MiB", "SIZE MiB", "STANDBY", "CREATED"])?;
    for v in &images {
        let s = |k: &str| v[k].as_str().map(String::from).or_else(|| v[k].as_u64().map(|n| n.to_string())).unwrap_or_default();
        let ago = ago(v["created"].as_u64());
        let tag = s("tag");
        let tag = if tag.starts_with("sha256:") { tag[..19].to_string() } else { tag };
        row([&s("repository"), &tag, &s("id"), &s("vcpus"), &s("max_mib"), &s("size_mib"), &s("standby"), &ago])?;
    }
    Ok(())
}

/// How long ago Unix time `secs` was, as `images` says it.
fn ago(secs: Option<u64>) -> String {
    let created = secs.map(|t| std::time::UNIX_EPOCH + Duration::from_secs(t)).and_then(|t| t.elapsed().ok());
    created.map_or(String::new(), |d| match d.as_secs() {
        s if s < 120 => format!("{s} seconds ago"),
        s if s < 7200 => format!("{} minutes ago", s / 60),
        s if s < 172800 => format!("{} hours ago", s / 3600),
        s => format!("{} days ago", s / 86400),
    })
}

/// `rmi IMAGE|ID`: refused while a VM here (running, paused or suspended) uses it. Its standby
/// VMs go first (its count set to 0).
fn rmi(host: &Host, paths: &Paths, what: &str) -> Result<()> {
    let in_use = || host.template_users();
    let linked = template::name_of(what).ok().filter(|n| std::fs::symlink_metadata(paths.templates.join(n)).is_ok());
    let Some(name) = linked else {
        let id = template::generation_by_prefix(paths, what).map_err(|e| format!("{e} (see flexvm images)"))?;
        return print(template::remove(paths, None, &id, &in_use)?);
    };
    let vms = vms(host);
    let users: Vec<&str> = vms.iter().filter(|v| v["template"].as_str() == Some(name.as_str())).filter_map(|v| v["name"].as_str()).collect();
    if !users.is_empty() {
        bail!("image {} is used by {}: remove them first (flexvm rm -f)", template::image_of(&name), users.join(", "));
    }
    let id = std::fs::read_link(paths.templates.join(&name))?.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let result = standby::removing(host, paths, &name, |paths| template::remove_locked(paths, Some(&name), &id, &in_use));
    // A failed removal kept its count: its pool comes back.
    if let Err(e) = standby::refill_later(host, &name) {
        crate::log!("flexvm: rmi {name}: standby refill: {e}");
    }
    print(result?)
}

fn image_options(args: &Args, src: &str) -> Result<image::Options> {
    let warm = args.has("warm");
    let ready = match (args.get("ready-port"), args.get("ready-cmd")) {
        (Some(_), Some(_)) => return Err("pass --ready-port or --ready-cmd, not both".into()),
        (Some(_), None) => {
            let port = args.parse_or::<u16>("ready-port", 0)?;
            if port == 0 {
                bail!("--ready-port must be 1..65535");
            }
            Some(image::Ready::Port(port))
        }
        (None, Some(c)) => Some(image::Ready::Cmd(c.into())),
        (None, None) => None,
    };
    if ready.is_some() && !warm {
        return Err("--ready-port and --ready-cmd only apply with --warm".into());
    }
    let d = image::Limits::default();
    let bytes =
        |flag, default| -> Result<u64> { args.parse_or::<u64>(flag, default)?.checked_mul(1 << 20).ok_or_else(|| format!("--{flag} is too large").into()) };
    Ok(image::Options {
        image: src.into(),
        entrypoint: args.get("entrypoint").map(image::parse_argv).transpose()?,
        cmd: args.get("cmd").map(image::parse_argv).transpose()?,
        env: env_flags(args)?,
        workdir: args.get("workdir").map(String::from),
        user: args.get("user").map(String::from),
        warm,
        ready,
        ready_timeout: Duration::from_secs(args.parse_or::<u32>("ready-timeout", 120)?.into()),
        staging: state(args)?.join("staging"),
        limits: image::Limits {
            download: bytes("max-download-mib", d.download >> 20)?,
            unpacked: bytes("max-unpacked-mib", d.unpacked >> 20)?,
            file: bytes("max-file-mib", d.file >> 20)?,
            entries: args.parse_or("max-entries", d.entries)?,
        },
    })
}

/// A command's session in the guest: its id, whether the guest took it, and
/// how much of its output was written out (a reattach goes on from there).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: String,
    pub started: bool,
    pub offset: u64,
    /// Its exit status, once the guest sent it (a suspend records it too).
    #[serde(default)]
    pub exit: Option<i32>,
}

impl Session {
    pub fn new() -> Result<Session> {
        Ok(Session { id: util::random_hex(16)?, started: false, offset: 0, exit: None })
    }
}

/// CLI exec has no implicit shell; options are serialized with the argv.
fn exec_command(args: &Args) -> Result<Value> {
    if args.rest.first().is_none_or(|s| s.is_empty()) {
        bail!("exec needs CMD");
    }
    let env = env_flags(args)?;
    // As with docker exec; a relative one would be resolved against a directory the user cannot see.
    if args.get("workdir").is_some_and(|w| !w.starts_with('/')) {
        bail!("exec -w needs an absolute path");
    }
    let (stdin, tty) = (args.has("interactive"), args.has("tty"));
    // As docker's: a terminal's keys, or none.
    if stdin && tty && !std::io::stdin().is_terminal() {
        bail!("the input device is not a TTY");
    }
    let size = tty.then(attach::size).flatten().map(|(rows, cols)| [rows, cols]);
    let cmd = json!({"argv": args.rest, "env": env, "workdir": args.get("workdir"), "user": args.get("user"), "detach": args.has("detach"),
        "stdin": stdin, "tty": tty, "size": size});
    guest::command_body(&cmd)?;
    Ok(cmd)
}

/// `-i`: stdin goes to the command; `-t`: on a pty, this terminal raw and its size followed.
pub fn exec(host: &Host, name: &str, cmd: &Value) -> Result<i32> {
    let (stdin, tty) = (cmd["stdin"] == true, cmd["tty"] == true);
    let keys = stdin && tty && std::io::stdin().is_terminal();
    let feed = match cmd["detach"] != true && (stdin || tty) {
        true => Some(attach::Feed::start(stdin.then(|| Box::new(std::io::stdin()) as Box<dyn Read + Send>), tty, keys, attach::detach_later)?),
        false => None,
    };
    let _raw = keys.then(attach::raw).transpose()?;
    exec_with(host, name, cmd, &mut std::io::stdout(), feed)
}

/// Reattaches when the connection drops (a checkpoint's pause resets vsock); `feed`, the command's stdin
/// (and pty size), is sent again from what the guest took.
pub fn exec_with(host: &Host, name: &str, cmd: &Value, out: &mut dyn Write, feed: Option<std::sync::Arc<attach::Feed>>) -> Result<i32> {
    let session: &'static Mutex<Session> = Box::leak(Box::new(Mutex::new(Session::new()?)));
    // The VM the command went to: found again under the name it has now, by its cleanup too.
    let pin: &'static Mutex<Pin> = Box::leak(Box::new(Mutex::new(Pin::default())));
    if cmd["detach"] == true {
        return exec_request(host, name, cmd, session, false, out, None, pin);
    }
    let id = session.lock().unwrap().id.clone();
    let close = {
        let (host, name, id) = (host.clone(), name.to_string(), id.clone());
        let once = move || -> Result<()> {
            let name = pin.lock().unwrap_or_else(|e| e.into_inner()).name(&host, &name);
            let c =
                vmproc::connect(&host, &name, &json!({"op": "exec", "session": id, "action": "close"}), &[], Instant::now() + Duration::from_secs(5), None)?;
            c.set_read_timeout(Some(Duration::from_secs(5)))?;
            util::answer(recv_json(&mut BufReader::new(c))?, "vm", "session close failed").map(drop)
        };
        // A checkpoint turns it away for a few seconds: it is tried again meanwhile.
        move || -> Result<()> {
            let until = Instant::now() + Duration::from_secs(10);
            loop {
                match once() {
                    Err(e) if e.to_string().contains(vm::CHECKPOINTING) && Instant::now() < until => std::thread::sleep(Duration::from_millis(200)),
                    res => return res,
                }
            }
        }
    };
    // Interrupted, the command is stopped: left running, it would hold one of the guest's session slots.
    let (stop, vm, cleanup_host) = (close.clone(), name.to_string(), host.clone());
    util::on_signal(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP], move |sig| {
        attach::restore_terminal();
        // Held until exit, so the stopped command's status is not reported; not waited for long, as
        // a write to a stalled stdout holds it.
        let deadline = Instant::now() + Duration::from_secs(1);
        let _s = loop {
            match session.try_lock() {
                Ok(s) => break Some(s),
                Err(std::sync::TryLockError::Poisoned(e)) => break Some(e.into_inner()),
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break None,
            }
        };
        if let Err(e) = stop() {
            let vm = pin.lock().unwrap_or_else(|e| e.into_inner()).name(&cleanup_host, &vm);
            crate::log!("flexvm: the command may still be running in vm {vm}: {e}");
        }
        util::raise_signal(sig);
    });
    let result = exec_request(host, name, cmd, session, false, out, feed.as_ref(), pin);
    // Completed sessions are acknowledged on their attachment. Errors (including a closed
    // stdout, as with `| head`) still need CLOSE to stop a command that may be running.
    if result.is_err() {
        let _ = close();
    }
    match result {
        Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe) => Ok(0),
        result => result,
    }
}

/// `exec` of a session that may have started already. Output is written,
/// and its offset counted, under the session's lock: whoever holds it knows
/// exactly what was written (a suspend records it for the resumed VM). The
/// session is left open: a VM's main command may be reattached after a
/// suspend, and its VM goes with it anyway. `patient` (a VM's main command):
/// a paused or checkpointing VM is waited for even before the command started.
pub fn exec_session(host: &Host, name: &str, cmd: &str, session: &Mutex<Session>, patient: bool) -> Result<i32> {
    exec_request(host, name, &json!(cmd), session, patient, &mut std::io::stdout(), None, &Mutex::default())
}

#[allow(clippy::too_many_arguments)]
fn exec_request(
    host: &Host,
    name: &str,
    cmd: &Value,
    session: &Mutex<Session>,
    patient: bool,
    stdout: &mut dyn Write,
    feed: Option<&std::sync::Arc<attach::Feed>>,
    pin: &Mutex<Pin>,
) -> Result<i32> {
    // Check the actual wire body before trying the VM.
    guest::fits(&guest::command_body(cmd)?)?;
    let detached = cmd["detach"] == true;
    let id = session.lock().unwrap().id.clone();
    let mut error = String::new();
    let mut deadline = Instant::now() + Duration::from_secs(30);
    // The VM the first request reached (`pin`): only it is attached to, or asked to start the command again.
    while Instant::now() < deadline {
        // Under the name it has now: a VM's own main command, and a separate client, follow its renames.
        let mut vm = pin.lock().unwrap().clone();
        let name = &vm.name(host, name);
        let (started, offset) = {
            let s = session.lock().unwrap();
            if let Some(code) = s.exit {
                return Ok(code);
            }
            (s.started, s.offset)
        };
        let action = if started { "attach" } else { "start" };
        let req = json!({"op": "exec", "session": id, "action": action, "offset": offset, "cmd": cmd, "interactive": feed.is_some()});
        let at = Instant::now() + Duration::from_secs(5);
        let conn = connect_same(host, name, &req, at, &mut vm);
        *pin.lock().unwrap() = vm.clone();
        let stream = conn.and_then(|c| exec_stream(c, at));
        // Locked per write, never across a read: a checkpoint takes stdout's lock too.
        match stream.map(|mut r| {
            // Test fault `exec_lose_echo`: the connection is lost before the session id comes back (the guest has the command).
            if !started && crate::host::tripped("exec_lose_echo") {
                return Ok(StreamEnd::Disconnected("injected fault: lost before the session id".into()));
            }
            if detached {
                return match guest::read_frame(&mut r) {
                    Ok(Some((guest::FRAME_MSG, m))) if m == id.as_bytes() => Ok(StreamEnd::Exit(0)),
                    Ok(Some((guest::FRAME_MSG, m))) if guest::transient(&String::from_utf8_lossy(&m)) => {
                        Ok(StreamEnd::Disconnected(String::from_utf8_lossy(&m).into_owned()))
                    }
                    Ok(Some((guest::FRAME_MSG, m))) => cannot_run(&m, &mut std::io::stderr()),
                    _ => Ok(StreamEnd::Disconnected("lost detached start acknowledgement".into())),
                };
            }
            // Stopped (and the connection shut down) when dropped, at the end of this attachment.
            let writer = feed.map(|f| r.get_ref().try_clone().map_err(util::Error::from).and_then(|c| f.serve(c))).transpose()?;
            let result = exec_frames(&mut r, session, &mut *stdout, &mut std::io::stderr(), &mut deadline, feed);
            if !patient && matches!(result, Ok(StreamEnd::Exit(_))) {
                match (feed, &writer) {
                    (Some(f), Some(w)) => f.done(w),
                    _ => drop(r.get_mut().write_all(&[guest::SESSION_DONE])),
                }
            }
            result
        }) {
            Ok(Err(e)) => return Err(e),
            Ok(Ok(StreamEnd::Exit(code))) => return Ok(code),
            // The guest took its IN_DETACH (sent again on each attachment until then): the command runs on.
            Ok(Ok(StreamEnd::Detached)) => return Ok(0),
            Ok(Ok(StreamEnd::Disconnected(why))) => error = why,
            Err(e) if e.is::<Replaced>() => return Err(format!("{e} (session {id})").into()),
            Err(e) if e.is::<host::Unseen>() => return Err(e),
            Err(e) => {
                // A new interactive command fails at once; a running one (or a VM's
                // main command) waits for its VM to resume, or for a checkpoint (a
                // suspend's too) to finish.
                let msg = e.to_string();
                if guest::transient(&msg) {
                    if !started && !patient {
                        return Err(e);
                    }
                    deadline = Instant::now() + Duration::from_secs(30);
                }
                // Renamed meanwhile: asked again under its new name.
                if !host.alive(name) && vm.name(host, name) == *name {
                    if let Ok(to) = std::fs::read_to_string(host.vms(name, "moved")?) {
                        return Err(format!("vm {name} moved to {to}; the command keeps running there (session {id})").into());
                    }
                    if !started || !host.suspended(name)?.is_dir() {
                        return Err(e);
                    }
                }
                error = msg;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
        // Test gate `exec_retry`: the next try waits while a test changes the VM under it.
        if crate::host::fault("exec_retry") {
            crate::host::gate("exec_retry");
            deadline = Instant::now() + Duration::from_secs(30);
        }
    }
    Err(format!("exec recovery timed out: {error}").into())
}

/// Which VM a command runs in: its address and that address's generation. A
/// suspend and resume, or a migration, keeps both; a VM made again under the
/// name (after a kill) has a new generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Instance {
    ip: std::net::Ipv4Addr,
    gen: u64,
}

/// The VM under the name is another than the one a command's request reached first.
#[derive(Debug)]
pub(crate) struct Replaced(String);

impl std::fmt::Display for Replaced {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Replaced {}

/// Connects to `name`'s VM process and sends `req` once it is known to run the
/// VM `vm` names (recorded by the first connection): one made under the name
/// since is refused (`Replaced`) before the request reaches it, and one that
/// cannot be told yet (its registry entry not published) is an error retried.
pub(crate) fn connect_same(host: &Host, name: &str, req: &Value, at: Instant, pin: &mut Pin) -> Result<std::os::unix::net::UnixStream> {
    let mut check = |c: &std::os::unix::net::UnixStream| {
        // The process that listens; a VM's own main command needs no check: no other takes the name while it holds it.
        let pid = util::peer_pid(c)?;
        if pid != std::process::id() {
            // Its pid as this process sees it: in another PID namespace, not the one it has there.
            // One this process cannot see (a sibling container's) is not waited for: it never will.
            let entry = host.entry(name).ok().filter(|e| e.gen != 0);
            if let Some(Err(e)) = entry.as_ref().filter(|e| !e.ident.is(pid)).map(|e| e.ident.local_pid()) {
                if e.is::<host::Unseen>() {
                    return Err(unseen(name, e));
                }
            }
            let entry = entry.filter(|e| e.ident.is(pid));
            let now = entry.as_ref().and_then(|e| Some(Instance { ip: e.ip?, gen: e.gen }));
            same_instance(
                name,
                now.ok_or_else(|| format!("vm {name:?} is starting or its registry entry is unavailable; retry once it is ready"))?,
                &mut pin.vm,
            )?;
            pin.process = entry.map(|e| e.ident);
        }
        Ok(())
    };
    vmproc::connect(host, name, req, &[], at, Some(&mut check))
}

/// What a client knows of the VM it follows: the instance its first connection reached, the process it
/// reached last running it (a resume or a migration makes another), and the name it last had.
#[derive(Clone, Debug, Default)]
pub(crate) struct Pin {
    vm: Option<Instance>,
    pub(crate) process: Option<host::Ident>,
    renamed: Option<String>,
}

impl Pin {
    /// The name `name`'s VM has now: this process's own VM's (`containers::renamed`), or, once a connection
    /// pinned it, the holder of its address's generation, which a rename moves to the new name. Remembered:
    /// once the VM ended (its claim let go) its records are still under the last name it had.
    pub(crate) fn name(&mut self, host: &Host, name: &str) -> String {
        if let Some(now) = self.vm.and_then(|v| host.holder_of(v.ip, v.gen)) {
            self.renamed = Some(now);
        }
        self.renamed.clone().unwrap_or_else(|| containers::renamed(name))
    }
}

/// Records the first VM reached; any later one must be it.
fn same_instance(name: &str, now: Instance, vm: &mut Option<Instance>) -> Result<()> {
    match vm {
        None => *vm = Some(now),
        Some(v) if *v == now => {}
        Some(v) => {
            return Err(Box::new(Replaced(format!(
                "vm {name} was killed and made again since the command was sent ({} generation {}, now {} generation {}); \
                 not starting it again in the new vm, it may have run in the old one",
                v.ip, v.gen, now.ip, now.gen
            ))))
        }
    }
    Ok(())
}

/// Keeps frames read ahead with the reply, then switches from its deadline to heartbeat timeouts. Reads no
/// further ahead than a frame header: the exit stays queued until all output before it is written out, so the
/// relay's SIOCOUTQ tells when its acknowledgement is due (#1047).
fn exec_stream<S: util::Timed>(c: S, at: Instant) -> Result<BufReader<S>> {
    let mut r = util::By { s: BufReader::with_capacity(READ_AHEAD, c), at };
    util::answer(recv_json(&mut r)?, "vm", "exec failed")?;
    r.s.get_ref().read_timeout(Duration::from_secs(3))?;
    Ok(r.s)
}

/// A refusal before the command started: one that could not be run (`EXIT_STATUS`) is told on
/// `stderr` and ends with its status, as with docker exec; any other is flexvm's failure.
fn cannot_run(m: &[u8], stderr: &mut impl Write) -> Result<StreamEnd> {
    let m = guest::refusal(m);
    match guest::refusal_status(&m) {
        Some((code, why)) => {
            writeln!(stderr, "flexvm: {}", why.strip_prefix("error: ").unwrap_or(why))?;
            Ok(StreamEnd::Exit(code))
        }
        None => Err(m.into()),
    }
}

/// An exec client's read-ahead: one frame header (a frame's body is read straight into it).
const READ_AHEAD: usize = 5;

enum StreamEnd {
    Exit(i32),
    Detached,
    Disconnected(String),
}

/// Tracks the session's offset so a reattach resumes without duplicates.
fn exec_frames(
    r: &mut impl Read,
    session: &Mutex<Session>,
    stdout: &mut dyn Write,
    stderr: &mut impl Write,
    deadline: &mut Instant,
    feed: Option<&std::sync::Arc<attach::Feed>>,
) -> Result<StreamEnd> {
    let id = session.lock().unwrap().id.clone();
    let mut echoed = false;
    loop {
        let (kind, data) = match guest::read_frame(r) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(StreamEnd::Disconnected("the vm closed the stream".into())),
            Err(e) => return Ok(StreamEnd::Disconnected(e.to_string())),
        };
        let mut s = session.lock().unwrap();
        match kind {
            guest::FRAME_STDOUT | guest::FRAME_STDERR if s.started => {
                let bytes = guest::session_output(&data, s.offset)?;
                let out: &mut dyn Write = if kind == guest::FRAME_STDOUT { stdout } else { stderr };
                out.write_all(bytes)?;
                out.flush()?;
                s.offset += bytes.len() as u64;
            }
            guest::FRAME_STDOUT | guest::FRAME_STDERR => return Err("session output before session id".into()),
            guest::FRAME_ACK if s.started => {
                let taken = u64::from_le_bytes(data.as_slice().try_into().map_err(|_| "bad stdin acknowledgement")?);
                feed.ok_or("stdin acknowledged, but none was sent")?.ack(taken);
            }
            guest::FRAME_EXIT => {
                let code = guest::session_exit(&data, s.offset)?;
                s.exit = Some(code);
                return Ok(StreamEnd::Exit(code));
            }
            guest::FRAME_LOST => {
                let start = u64::from_le_bytes(data.as_slice().try_into().map_err(|_| "bad output-lost frame")?);
                return Err(format!("session output lost: needed offset {}, retained output starts at {start}", s.offset).into());
            }
            guest::FRAME_MSG if data == id.as_bytes() => (s.started, echoed) = (true, true),
            // A reattach after the connection was lost, to a session closed meanwhile (acknowledged, or reclaimed).
            guest::FRAME_MSG if s.started && !echoed && data == b"error: session closed" => {
                return Err(
                    format!("lost the connection to the vm after byte {} of output; the session has since been closed and the rest is gone", s.offset).into()
                )
            }
            guest::FRAME_MSG if data == b"waiting" && s.started => {}
            guest::FRAME_MSG if data == b"detached" && s.started && feed.is_some_and(|f| f.detached()) => return Ok(StreamEnd::Detached),
            // Before the id echo the request itself failed: not retried, unless the guest was only busy
            // (it never took the command, so it is started again).
            guest::FRAME_MSG if !s.started && guest::transient(&String::from_utf8_lossy(&data)) => {
                return Ok(StreamEnd::Disconnected(String::from_utf8_lossy(&data).into_owned()))
            }
            guest::FRAME_MSG if !s.started => {
                let end = cannot_run(&data, stderr);
                if let Ok(StreamEnd::Exit(code)) = end {
                    s.exit = Some(code);
                }
                return end;
            }
            guest::FRAME_MSG => return Ok(StreamEnd::Disconnected(String::from_utf8_lossy(&data).into_owned())),
            _ => return Err(format!("unknown session frame {kind}").into()),
        }
        *deadline = Instant::now() + Duration::from_secs(30);
    }
}

#[cfg(test)]
mod exec_tests {
    use super::*;

    fn parse(args: &[&str]) -> Args {
        Args::parse(args.iter().map(|a| a.to_string())).unwrap()
    }

    #[test]
    fn stop_takes_only_the_signalled_instances_app_exit() {
        let me = host::Ident::me();
        let earlier = host::Ident { pid: me.pid.wrapping_add(1), ..me.clone() };
        let exit = |ident: &host::Ident, code, app| containers::Exit { ident: ident.clone(), code, app };
        for code in [0, 4, vmproc::DIED, 130, 131] {
            assert!(app_exited(Some(&exit(&me, code, Some(true))), &me), "the app's own {code}");
            assert!(!app_exited(Some(&exit(&me, code, Some(false))), &me), "flexvm's {code}");
        }
        assert!(app_exited(Some(&exit(&me, 0, None)), &me));
        assert!(app_exited(Some(&exit(&me, 4, None)), &me));
        // An earlier instance's status (one that exited before a new one took the name, which then died unrecorded).
        assert!(!app_exited(Some(&exit(&earlier, 0, Some(true))), &me));
        assert!(!app_exited(None, &me));
        // A record from before `app`: flexvm's statuses are not taken as the app's.
        for code in [vmproc::DIED, 130, 131] {
            assert!(!app_exited(Some(&exit(&me, code, None)), &me), "{code}");
        }
    }

    #[test]
    fn ambiguous_options_must_follow_the_command() {
        for (flag, cmd, word) in [("force", "reclaim", "10.9.0.2"), ("standby", "pull", "img")] {
            assert_eq!(takes_value(flag, None), None);
            for option in [format!("--{flag}"), format!("--{flag}=1")] {
                let (args, error) = Args::parse_partly([option, cmd.into(), word.into()]);
                assert_eq!(error.unwrap().to_string(), format!("--{flag} must follow the command"));
                assert!(!args.has(flag));
            }
        }
        assert_eq!(parse(&["pull", "img", "--standby", "5"]).get("standby"), Some("5"));
        assert!(parse(&["rm", "--force", "vm"]).has("force"));
    }

    #[test]
    fn output_flags_are_exclusive() {
        for (argv, message) in [
            (&["ps", "-q", "--json"][..], "ps takes -q or --json, not both"),
            (&["ps", "--format", "table", "-q"], "ps takes -q or --format, not both"),
            (&["ps", "--json", "--format", "json"], "ps takes --json or --format, not both"),
            (&["images", "--json", "-q"], "images takes -q or --json, not both"),
            (&["checkpoint", "ls", "-q", "--format", "json"], "checkpoint ls takes -q or --format, not both"),
        ] {
            assert_eq!(check_applies(&parse(argv)).unwrap_err().to_string(), message);
        }
    }

    #[test]
    fn pull_refuses_invalid_memory_before_kvm() {
        for (max, mem, message) in [
            ("255", "256", "--max must be at least --mem (256 MiB)"),
            ("2097153", "256", "--max must be at most 2097152 MiB"),
            ("18446744073709551615", "256", "--max must be at most 2097152 MiB"),
        ] {
            let args = parse(&["pull", "busybox", "--max", max, "--mem", mem]);
            assert_eq!(real_main(&args).unwrap_err().to_string(), message);
        }
        for max in ["256", "2097152"] {
            let size = pull_size(&parse(&["pull", "busybox", "--max", max, "--mem", "256"])).unwrap();
            assert_eq!(size.max_mib.to_string(), max);
        }
    }

    #[test]
    fn debug_arities() {
        for (op, least, most, words) in [("gc", 0, 0, "no arguments"), ("fault", 1, 2, "NAME [MS]"), ("ckhash", 1, 1, "DIR"), ("vm", 0, 1, "[WHAT]")] {
            for count in 0..=4 {
                for dashdash in [false, true] {
                    let mut argv = vec!["debug", op];
                    if dashdash {
                        argv.push("--");
                    }
                    argv.extend(std::iter::repeat_n("stray", count));
                    let args = parse(&argv);
                    if (least..=most).contains(&count) {
                        check_applies(&args).unwrap();
                    } else {
                        assert_eq!(real_main(&args).unwrap_err().to_string(), format!("debug {op} takes {words}"), "{argv:?}");
                    }
                }
            }
        }
        assert_eq!(check_applies(&parse(&["debug"])).unwrap_err().to_string(), "debug fault|ckhash|gc|VM ...");
    }

    #[test]
    fn debug_fault_refuses_invalid_ms() {
        for ms in ["bad", "-1", "18446744073709551616"] {
            assert_eq!(real_main(&parse(&["debug", "fault", "test", "--", ms])).unwrap_err().to_string(), format!("bad fault MS {ms:?}"));
        }
    }

    #[test]
    fn new_names_refuse_flags_but_rm_parses_legacy_names() {
        for name in ["-f", "--force", "-"] {
            host::check_name(name).unwrap();
            assert!(host::check_new_name(name).is_err());
            let args = parse(&["rm", "--", name]);
            check_applies(&args).unwrap();
            assert_eq!(args.names(), &[name]);
            assert!(!args.has("force"));
        }
        host::check_new_name("vm-1").unwrap();
        // start's VM process, re-run as `start --attach -- NAME`, takes such a name too.
        let child = parse(&["start", "--attach", "--", "-f"]);
        check_applies(&child).unwrap();
        assert!(child.has("attach") && child.names() == ["-f"]);
    }

    #[test]
    fn a_bare_dashdash_must_follow_the_command() {
        for argv in [&["--", "run", "img", "sh"][..], &["--", "rm", "x"], &["--state", "/s", "--"]] {
            let (_, error) = Args::parse_partly(argv.iter().map(|a| a.to_string()));
            assert_eq!(error.unwrap().to_string(), "-- must follow the command", "{argv:?}");
        }
        assert_eq!(parse(&["run", "img", "--", "sh", "--", "-x"]).rest, ["sh", "--", "-x"]);
        assert_eq!(parse(&["exec", "web", "--", "-x"]).rest, ["-x"]);
        let cp = parse(&["cp", "--", "-", "web:/x"]);
        check_applies(&cp).unwrap();
        assert_eq!(cp.names(), ["-", "web:/x"]);
        assert!(cp.rest.is_empty());
    }

    #[test]
    fn pull_max_defaults_to_the_host_and_never_below_mem() {
        let size = pull_size(&parse(&["pull", "busybox"])).unwrap();
        assert!(size.max_mib <= template::MAX_MEM_MIB && size.mem_mib <= size.max_mib);
        let size = pull_size(&parse(&["pull", "busybox", "--mem", "2097152"])).unwrap();
        assert_eq!((size.mem_mib, size.max_mib), (2097152, 2097152), "--mem past the host's memory: no hotplug");
        assert_eq!(pull_size(&parse(&["pull", "busybox", "--mem", "2097153"])).unwrap_err().to_string(), "--mem must be at most 2097152 MiB");
    }

    #[test]
    fn rm_removes_legacy_names_and_creation_and_rename_refuse_them() {
        let root = crate::test_util::TempDir::new("legacy-name");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        for name in ["-f", "--force", "-"] {
            assert!(host.take_name(name, false).is_err());
            assert!(containers::rename(&host, "old", name).is_err());
            let path = host.vms(name, "failed").unwrap();
            std::fs::write(&path, "died").unwrap();
            let args = parse(&["rm", "--", name]);
            check_applies(&args).unwrap();
            assert_eq!(args.names(), &[name]);
            assert!(!args.has("force"));
            each(args.names(), |n| remove(&host, n, false, true)).unwrap();
            assert!(!path.exists());
        }
    }

    #[test]
    fn verbose_is_global_and_preserved_for_children_but_not_app_arguments() {
        for argv in [&["-v", "start", "web"][..], &["start", "--verbose", "web"]] {
            let args = parse(argv);
            assert!(args.has("verbose"));
            assert!(check_applies(&args).is_ok());
            assert_eq!(child_args(&args, &["start", "--attach", "web"]), ["--verbose", "start", "--attach", "web"]);
        }
        let args = parse(&["run", "image", "--verbose", "-v"]);
        assert!(!args.has("verbose"));
        assert_eq!(args.rest, ["--verbose", "-v"]);
        assert!(parse(&["-v", "run", "-d", "image"]).child_args.contains(&"-v".into()));
        let refused = Args::parse(["run", "-v", "/src:/dst", "image"].map(String::from)).err().unwrap().to_string();
        assert!(refused.contains("volumes (-v) are not supported"), "{refused}");
    }

    #[test]
    fn run_hostname_short_flag_is_refused_without_showing_help() {
        for flag in ["-h", "-dh"] {
            let (args, error) = Args::parse_partly(["run", flag, "host", "image"].map(String::from));
            assert!(error.unwrap().to_string().contains("hostname (-h) is not supported"));
            assert!(!args.has("help"));
        }
        assert!(parse(&["-h", "run"]).has("help"));
        assert!(parse(&["run", "--help"]).has("help"));
        assert!(parse(&["ps", "-h"]).has("help"));
        assert_eq!(parse(&["run", "image", "-h"]).rest, ["-h"]);
    }

    #[test]
    fn short_bundles_and_value_aliases_follow_the_command() {
        for (bundled, separate) in [
            (vec!["ps", "-aq"], vec!["ps", "-a", "-q"]),
            (vec!["ps", "-qafname=web"], vec!["ps", "-q", "-a", "--filter", "name=web"]),
            (vec!["ps", "-f", "name=web"], vec!["ps", "--filter", "name=web"]),
            (vec!["run", "-dm512m", "img"], vec!["run", "-d", "--memory", "512m", "img"]),
            (vec!["run", "-m", "512m", "img"], vec!["run", "--memory", "512m", "img"]),
            (vec!["logs", "-fn20", "web"], vec!["logs", "-f", "--tail", "20", "web"]),
            (vec!["logs", "-n", "20", "web"], vec!["logs", "--tail", "20", "web"]),
            (vec!["rm", "-fv", "web"], vec!["rm", "-f", "-v", "web"]),
        ] {
            let (a, b) = (parse(&bundled), parse(&separate));
            check_applies(&a).unwrap();
            assert_eq!(a.flags, b.flags, "{bundled:?}");
            assert_eq!(a.positional, b.positional);
            let child = Args::parse(a.child_args).unwrap();
            assert!(!child.has("detach"));
            for (flag, value) in &a.flags {
                if flag != "detach" {
                    assert_eq!(child.get(flag), Some(value.as_str()));
                }
            }
        }
        for words in [vec!["ps", "-ax"], vec!["run", "-m"], vec!["logs", "-n"], vec!["ps", "-f"]] {
            assert!(Args::parse(words.into_iter().map(String::from)).is_err());
        }
        for words in [vec!["ps", "-m", "512m"], vec!["run", "-n", "20", "img"], vec!["exec", "-f", "x", "true"]] {
            assert!(Args::parse(words.into_iter().map(String::from)).is_err());
        }
    }

    #[test]
    fn interactive_flags_combine_as_dockers() {
        let args = parse(&["run", "-dit", "--name", "x", "image", "sh", "-it"]);
        assert!(args.has("detach") && args.has("interactive") && args.has("tty"));
        assert_eq!(args.rest, ["sh", "-it"], "CMD's own words are its own");
        assert_eq!(args.child_args, ["run", "-i", "-t", "--name", "x", "image", "sh", "-it"], "a detached run's VM process is not detached again");
        check_applies(&args).unwrap();
        let spec = run_spec(&args, None).unwrap();
        assert!(spec.stdin && spec.tty);
        assert_eq!(spec.entrypoint.as_deref(), Some(&["sh".to_string(), "-it".to_string()][..]), "with -i or -t, CMD is the app");
        assert!(run_spec(&parse(&["run", "image", "sh"]), None).unwrap().entrypoint.is_none(), "without, CMD is the vm's command");
        let exec = parse(&["exec", "-ti", "vm", "bash"]);
        assert!(exec.has("interactive") && exec.has("tty") && exec.rest == ["bash"]);
        assert!(check_applies(&parse(&["run", "-it", "--keep", "image", "sh"])).is_ok(), "CMD is the app, which --keep is for");
        assert!(check_applies(&parse(&["run", "-it", "--entrypoint", "sh", "image", "x"])).is_err());
        assert!(check_applies(&parse(&["run", "--checkpoint", "/c", "-i"])).is_err());
        assert!(Args::parse(["ps", "-it"].map(String::from)).is_err());
        assert!(check_applies(&parse(&["attach"])).unwrap_err().to_string().contains("needs NAME"));
        check_applies(&parse(&["cp", "-", "vm:/tmp"])).unwrap();
        assert!(check_applies(&parse(&["cp", "vm:/x"])).unwrap_err().to_string().contains("SRC DST"));
    }

    #[test]
    fn published_ports_repeat_and_survive_detaching_and_checkpoint_arguments() {
        let args = parse(&["run", "-d", "-p", "8080:80", "--publish", "127.0.0.1:5353:53/udp", "image"]);
        check_applies(&args).unwrap();
        let ports = port_specs(&args).unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].protocol, ports::Protocol::Tcp);
        assert_eq!(ports[1].protocol, ports::Protocol::Udp);
        let child = Args::parse(args.child_args.clone()).unwrap();
        assert!(!child.has("detach"));
        assert_eq!(port_specs(&child).unwrap(), ports);
        let restored = parse(&["run", "--checkpoint", "/checkpoint", "-p", "8080:80"]);
        check_applies(&restored).unwrap();
        assert_eq!(port_specs(&restored).unwrap(), ports[..1]);
        assert!(port_specs(&parse(&["run", "--checkpoint", "/checkpoint"])).unwrap().is_empty());
        assert!(Args::parse(["run", "-p"].map(String::from)).is_err());
        assert!(check_applies(&parse(&["start", "-p", "8080:80", "vm"])).is_err());
        let command = parse(&["run", "-p", "8080:80", "image", "echo", "-p", "123"]);
        assert_eq!(command.rest, ["echo", "-p", "123"]);
        assert_eq!(port_specs(&command).unwrap().len(), 1);
        // They are the run's settings, which travel with the VM as a unit.
        assert_eq!(run_spec(&args, None).unwrap().ports, ports);
        assert!(run_spec(&parse(&["run", "-p", "80", "image"]), None).is_err());
    }

    #[test]
    fn auto_pull_uses_the_resolved_templates_reference() {
        let args = Args::parse(["--state", "/s", "run", "ghcr.io+org+app"].map(String::from)).unwrap();
        for input in ["ghcr.io+org+app", "ghcr.io/org/app", "ghcr.io+org+app:v1", "nginx"] {
            let name = template::name_of(input).unwrap();
            let words = pull_missing_args(&args, &name);
            assert_eq!(&words[..3], ["--state", "/s", "pull"]);
            let reference = image::Reference::parse(&words[3]).unwrap();
            assert_eq!(reference.template_name(), name);
            if input == "ghcr.io+org+app" {
                assert_eq!(words[3], "ghcr.io/org/app:latest");
            }
        }
    }

    #[test]
    fn info_shows_the_effective_allowlist() {
        let root = crate::test_util::TempDir::new("config-allowlist");
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let output = info(&host);
        assert!(output["set"]["cluster_ips"].is_null());
        assert_eq!(output["derived"]["cluster_ips"], host.cfg.vm_ips);
        host.configure(|c| {
            c.cluster_ips = Some("10.200.0.0/15".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(info(&host)["derived"]["cluster_ips"], "10.200.0.0/15");
    }

    #[test]
    fn numeric_flags_reject_overflow_and_invalid_cpu_counts() {
        for flag in ["max-download-mib", "max-unpacked-mib", "max-file-mib"] {
            for value in ["17592186044416", "18446744073709551615"] {
                assert!(image_options(&parse(&[&format!("--{flag}"), value]), "busybox").is_err(), "{flag}={value}");
            }
            let opts = image_options(&parse(&[&format!("--{flag}"), "17592186044415"]), "busybox").unwrap();
            let bytes = match flag {
                "max-download-mib" => opts.limits.download,
                "max-unpacked-mib" => opts.limits.unpacked,
                _ => opts.limits.file,
            };
            assert_eq!(bytes, (u64::MAX >> 20) << 20);
        }
        assert!(image_options(&parse(&["--ready-timeout", "18446744073709551615"]), "busybox").is_err());
        let opts = image_options(&parse(&["--ready-timeout", "4294967295"]), "busybox").unwrap();
        assert_eq!(opts.ready_timeout.as_secs(), u32::MAX as u64);
        for value in ["0", "3", "33", "4294967296", "4294967297", "18446744073709551615"] {
            assert!(template_vcpus(&parse(&["--vcpus", value])).is_err(), "{value}");
        }
        for value in ["1", "2", "32"] {
            assert_eq!(template_vcpus(&parse(&["--vcpus", value])).unwrap().to_string(), value);
        }
    }

    #[test]
    fn a_detached_run_checks_the_name_before_opening_its_log() {
        let root = crate::test_util::TempDir::new("run-log");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let name = host.take_name("web", false).unwrap();
        let log = host.vms("web", "log").unwrap();
        assert!(host::name_taken(&new_run_log(&host, "web").unwrap_err()));
        assert!(!log.exists());
        std::fs::write(&log, "other vm").unwrap();
        assert!(new_run_log(&host, "web").is_err());
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "other vm");
        drop(name);
        for record in ["failed", "lost"] {
            std::fs::write(host.vms("web", record).unwrap(), "old vm").unwrap();
            host.write_log("web", "log.1", "older vm");
            let mut out = new_run_log(&host, "web").unwrap();
            let _name = host.take_name("web", false).unwrap();
            out.write_all(b"new vm").unwrap();
            assert_eq!(std::fs::read_to_string(&log).unwrap(), "new vm");
            assert!(!host.has_record("web", "log.1"));
        }
    }

    fn tokens(owner: &host::LogsOwner) -> Vec<String> {
        owner.to.clone()
    }

    /// The `run` SIGKILLed after starting its VM process, before that takes the name: the VM
    /// process keeps the logs it was handed (and writes to) by their token, not by the `run`.
    #[test]
    fn a_detached_runs_log_is_kept_by_its_vm_if_the_run_dies_mid_handoff() {
        let root = crate::test_util::TempDir::new("run-log-handoff");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let dir = host.vms("web", "logs").unwrap();
        for (theirs, kept) in [(true, true), (false, false)] {
            let mut out = new_run_log(&host, "web").unwrap();
            let held = util::output::open_dir(&dir).unwrap();
            let mut owner = host::logs_owner(&held).unwrap();
            assert_eq!(tokens(&owner), [out.token.clone()]);
            owner.id = host::Ident { pid: u32::MAX, start: 1, ..host::Ident::me() };
            owner.by = vec![Some(owner.id.clone())];
            std::fs::write(dir.join(".owner"), serde_json::to_vec(&owner).unwrap()).unwrap();
            let token = if theirs { out.token.clone() } else { "another".into() };
            let name = host.take_handed_name("web", Some(&token)).unwrap();
            assert_eq!(std::os::unix::fs::MetadataExt::nlink(&held.metadata().unwrap()) != 0, kept, "{theirs}");
            out.write_all(b"its output").unwrap();
            assert_eq!(std::fs::read_to_string(dir.join("log")).ok().as_deref(), kept.then_some("its output"), "{theirs}");
            drop(name);
            host.retire_logs("web").unwrap();
        }
    }

    /// Two detached runs of a free name prepare its logs before either's VM process takes it,
    /// and both die: the first's VM process (or the second's) still keeps them by its token;
    /// the second's never replaced the first's.
    #[test]
    fn concurrent_detached_runs_keep_each_others_pending_handoff() {
        let root = crate::test_util::TempDir::new("run-log-two");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let dir = host.vms("web", "logs").unwrap();
        for winner in [0, 1] {
            let mut outs = [new_run_log(&host, "web").unwrap(), new_run_log(&host, "web").unwrap()];
            let held = util::output::open_dir(&dir).unwrap();
            let mut owner = host::logs_owner(&held).unwrap();
            assert_eq!(tokens(&owner), [outs[0].token.clone(), outs[1].token.clone()]);
            // Both runs SIGKILLed: their identities, the second's last recorded, are gone.
            owner.id = host::Ident { pid: u32::MAX, start: 1, ..host::Ident::me() };
            owner.by.iter_mut().for_each(|b| *b = Some(owner.id.clone()));
            std::fs::write(dir.join(".owner"), serde_json::to_vec(&owner).unwrap()).unwrap();
            let name = host.take_handed_name("web", Some(&outs[winner].token.clone())).unwrap();
            assert_ne!(std::os::unix::fs::MetadataExt::nlink(&held.metadata().unwrap()), 0, "{winner}");
            outs[winner].write_all(b"its output").unwrap();
            assert_eq!(std::fs::read_to_string(dir.join("log")).unwrap(), "its output");
            drop(name);
            host.retire_logs("web").unwrap();
        }
    }

    /// A detached restore of a name a VM runs under: refused, that VM's logs left as they are;
    /// of a free one, its log opened holding the name (let go of once open).
    #[test]
    fn a_detached_restore_opens_its_log_holding_the_name() {
        let root = crate::test_util::TempDir::new("restore-log");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let running = host.take_name("web", false).unwrap();
        let logs = host.own_logs("web", None).unwrap();
        let before = host::logs_owner(&logs);
        for own in [true, false] {
            assert!(host::name_taken(&restore_run_log(&host, "web", own).unwrap_err()));
            assert_eq!(host::logs_owner(&logs), before);
        }
        drop(running);
        let out = restore_run_log(&host, "web", true).unwrap();
        assert_eq!(tokens(&host::logs_owner(&logs).unwrap()), [out.token.clone()], "the stopped vm's logs, handed on");
        drop(host.take_name("web", true).unwrap());
    }

    #[test]
    fn detached_log_refuses_symlinks() {
        let root = crate::test_util::TempDir::new("log-link");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let victim = root.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        // Its logs' directory, or the log in it, a link elsewhere: refused.
        std::os::unix::fs::symlink(root.join("elsewhere"), host.vms("vm", "logs").unwrap()).unwrap();
        std::fs::create_dir(root.join("elsewhere")).unwrap();
        assert!(log_file(&host, "vm").is_err());
        std::fs::remove_file(host.vms("vm", "logs").unwrap()).unwrap();
        drop(host.open_logs("vm").unwrap());
        std::os::unix::fs::symlink(&victim, host.vms("vm", "logs").unwrap().join("log")).unwrap();
        assert!(log_file(&host, "vm").is_err());
        assert_eq!(std::fs::read_to_string(victim).unwrap(), "keep");
        assert!(!root.join("elsewhere/log").exists());
    }

    #[test]
    fn kill_and_rm_validate_names_before_touching_files() {
        let root = crate::test_util::TempDir::new("kill-name");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let failed = root.join("victim.failed");
        std::fs::write(&failed, "keep").unwrap();
        for name in ["../../victim", "", ".hidden", "/tmp/x"] {
            for (running, stopped) in [(true, false), (true, true), (false, true)] {
                assert_eq!(remove(&host, name, running, stopped).unwrap_err().to_string(), host::check_name(name).unwrap_err().to_string());
            }
            assert!(stop(&host, name).is_err() && pause(&host, name).is_err() && resume(&host, name).is_err());
        }
        assert_eq!(std::fs::read_to_string(failed).unwrap(), "keep");
    }

    #[test]
    fn stop_of_stopped_or_exited_is_a_noop_and_failed_or_lost_are_named() {
        let root = crate::test_util::TempDir::new("stop-records");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let suspended = host.suspended("stopped").unwrap();
        std::fs::create_dir_all(&suspended).unwrap();
        std::fs::write(suspended.join("manifest.json"), "{}").unwrap();
        stop(&host, "stopped").unwrap();
        assert!(suspended.exists());
        let exited = host.vms("done", "exited").unwrap();
        std::fs::write(&exited, "saved exit").unwrap();
        for _ in 0..2 {
            stop(&host, "done").unwrap();
            assert_eq!(std::fs::read_to_string(&exited).unwrap(), "saved exit");
        }
        for state in ["failed", "lost"] {
            let record = host.vms(state, state).unwrap();
            std::fs::write(&record, "reason").unwrap();
            let error = stop(&host, state).unwrap_err().to_string();
            assert!(error.contains(state) && error.contains(&format!("flexvm rm {state}")), "{error}");
            // Restart first calls stop, before it tries to restore or spawn anything.
            let args = parse(&["--state", host.state.to_str().unwrap(), "--run", host.run.to_str().unwrap(), "restart", state]);
            assert_eq!(real_main(&args).unwrap_err().to_string(), error);
            assert_eq!(std::fs::read_to_string(record).unwrap(), "reason");
        }
        assert_eq!(stop(&host, "missing").unwrap_err().to_string(), r#"no running vm named "missing""#);
    }

    #[test]
    fn kill_leaves_the_records_of_a_vm_starting_under_its_name() {
        let root = crate::test_util::TempDir::new("kill-rerun");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let exited = host.vms("job", "exited").unwrap();
        std::fs::write(&exited, "its run").unwrap();
        // A rerun holds the name, reading its record, and has not published itself yet (#1151).
        let rerun = host.take_name("job", true).unwrap();
        let e = remove(&host, "job", true, false).unwrap_err().to_string();
        assert!(e.contains("is starting"), "{e}");
        assert_eq!(std::fs::read_to_string(&exited).unwrap(), "its run");
        drop(rerun);
        // Once it is gone (it failed: the VM is still exited), plain rm removes the record.
        remove(&host, "job", false, true).unwrap();
        assert!(!exited.exists());
    }

    /// #1189: `kill` of a VM starting (holding its name, not registered yet) waits for it, as `stop`
    /// does, and kills it once it is there; `rm -f` of one that never registers is refused as starting,
    /// never told to `rm -f`, and the records it saw stay.
    #[test]
    fn kill_and_rm_f_wait_for_a_vm_starting_under_its_name() {
        let root = crate::test_util::TempDir::new("kill-starting");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let lock = host.take_name("app", false).unwrap();
        let mut app = crate::test_util::sleeper(60);
        let ident = host::Ident::of(app.id()).unwrap();
        std::fs::write(host.vms("app", "lock").unwrap(), serde_json::to_vec(&ident).unwrap()).unwrap();
        let entry = host::Entry { name: "app".into(), ident, state: "running".into(), ..host::Entry::default() };
        let publisher = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            lock.publish(&entry).unwrap();
            lock
        });
        remove(&host, "app", true, false).unwrap();
        let status = app.wait().unwrap();
        assert_eq!(std::os::unix::process::ExitStatusExt::signal(&status), Some(libc::SIGINT), "killed once registered");
        drop(publisher.join().unwrap());

        let exited = host.vms("job", "exited").unwrap();
        std::fs::write(&exited, "its run").unwrap();
        let rerun = host.take_name("job", true).unwrap();
        let e = remove(&host, "job", true, true).unwrap_err().to_string();
        assert!(e.contains("is starting") && !e.contains("rm -f"), "{e}");
        assert_eq!(std::fs::read_to_string(&exited).unwrap(), "its run");
        drop(rerun);
    }

    /// #1189: `stop` of a VM whose process is gone is done only for a stopped VM: a checkpoint a resume
    /// consumed (STARTED: its VM died paging in) or one being discarded is not one.
    #[test]
    fn stop_of_a_vm_with_only_a_consumed_checkpoint_is_not_running() {
        let root = crate::test_util::TempDir::new("stop-consumed");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let dir = host.suspended("app").unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), "{}").unwrap();
        assert_eq!(stop(&host, "app").unwrap(), "app");
        for marker in ["STARTED", "DISCARDED"] {
            std::fs::write(dir.join(marker), "").unwrap();
            let e = stop(&host, "app").unwrap_err().to_string();
            assert!(e.contains("no running vm named"), "{marker}: {e}");
            std::fs::remove_file(dir.join(marker)).unwrap();
        }
    }

    #[test]
    fn stop_of_a_vm_whose_app_exits_meanwhile_is_done() {
        let root = crate::test_util::TempDir::new("stop-exit");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let lock = host.take_name("app", false).unwrap();
        let mut app = crate::test_util::sleeper(60);
        let ident = host::Ident::of(app.id()).unwrap();
        std::fs::write(host.vms("app", "lock").unwrap(), serde_json::to_vec(&ident).unwrap()).unwrap();
        lock.publish(&host::Entry { name: "app".into(), ident, state: "running".into(), ..host::Entry::default() }).unwrap();
        // Its app exited first: the VM, ending, takes no suspend and leaves its exited record (#1151).
        std::fs::write(host.vms("app", "exited").unwrap(), "its run").unwrap();
        stop(&host, "app").unwrap();
        assert!(app.wait().is_ok());
        drop(lock);
    }

    #[test]
    fn stop_of_a_vm_renamed_as_it_was_signalled_reads_its_new_name() {
        let root = crate::test_util::TempDir::new("stop-renamed");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        for moved in [false, true] {
            let lock = host.take_name("app", false).unwrap();
            let mut app = crate::test_util::sleeper(60);
            let ident = host::Ident::of(app.id()).unwrap();
            std::fs::write(host.vms("app", "lock").unwrap(), serde_json::to_vec(&ident).unwrap()).unwrap();
            lock.publish(&host::Entry { name: "app".into(), ident: ident.clone(), state: "running".into(), ..host::Entry::default() }).unwrap();
            // A rename that held its op as the SIGTERM landed: its records are under the new name (#1178).
            containers::record_exit(&host, "app-new", &ident, 128 + libc::SIGTERM, false);
            let r = match moved {
                false => {
                    let dir = host.suspended("app-new").unwrap();
                    std::fs::create_dir_all(&dir).unwrap();
                    std::fs::write(dir.join("manifest.json"), "{}").unwrap();
                    std::fs::write(dir.join("OWNER"), serde_json::to_vec(&ident).unwrap()).unwrap();
                    stop(&host, "app").map_err(|e| e.to_string())
                }
                true => {
                    std::fs::remove_dir_all(host.suspended("app-new").unwrap()).unwrap();
                    std::fs::write(host.vms("app-new", "moved").unwrap(), "elsewhere").unwrap();
                    stop(&host, "app").map_err(|e| e.to_string())
                }
            };
            assert!(app.wait().is_ok());
            drop(lock);
            match moved {
                // `restart` starts it under the name stop returns (#1189).
                false => assert_eq!(r.unwrap(), "app-new"),
                true => {
                    let e = r.unwrap_err();
                    assert!(e.contains("vm app (renamed app-new) moved to elsewhere"), "{e}");
                    assert!(host.has_record("app-new", "moved"), "the hint is kept");
                }
            }
        }
    }

    #[test]
    fn kill_leaves_a_stopped_vm_to_rm() {
        let root = crate::test_util::TempDir::new("kill-stopped");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        std::fs::write(host.vms("gone", "failed").unwrap(), "died").unwrap();
        let e = remove(&host, "gone", true, false).unwrap_err().to_string();
        assert!(e.contains("not running") && e.contains("flexvm rm gone"), "{e}");
        remove(&host, "gone", false, true).unwrap();
        assert!(!host.vms("gone", "failed").unwrap().exists());
        assert_eq!(remove(&host, "gone", false, true).unwrap_err().to_string(), "no vm named \"gone\"");
    }

    #[test]
    fn rm_removes_both_logs_before_a_detached_run_reuses_the_name() {
        let root = crate::test_util::TempDir::new("rm-logs");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        for force in [false, true] {
            for record in ["failed", "lost", "exited", "suspended"] {
                if record == "suspended" {
                    let dir = host.suspended("web").unwrap();
                    std::fs::create_dir_all(&dir).unwrap();
                    std::fs::write(dir.join("manifest.json"), "{}").unwrap();
                } else {
                    std::fs::write(host.vms("web", record).unwrap(), "old vm").unwrap();
                }
                for ext in ["log", "log.1"] {
                    std::fs::write(host.vms("web", ext).unwrap(), "old vm").unwrap();
                }
                remove(&host, "web", force, true).unwrap();
                assert!(!host.suspended("web").unwrap().exists());
                for ext in ["failed", "lost", "exited", "log", "log.1"] {
                    assert!(!host.has_record("web", ext), "{record}, force={force}: {ext}");
                }
                // The parent opens the log first; taking the name in the child must keep that file.
                let mut out = new_run_log(&host, "web").unwrap();
                let _name = host.take_name("web", false).unwrap();
                out.write_all(b"new vm").unwrap();
                assert_eq!(std::fs::read_to_string(host.vms("web", "log").unwrap()).unwrap(), "new vm");
            }
        }
        // Missing logs are fine too.
        std::fs::remove_file(host.vms("web", "log").unwrap()).unwrap();
        std::fs::write(host.vms("web", "exited").unwrap(), "{}").unwrap();
        remove(&host, "web", false, true).unwrap();
    }

    /// A process's identity, the process gone (a VM that died holding its name, unrecorded).
    fn dead_ident() -> host::Ident {
        let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
        let id = host::Ident::of(child.id()).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        id
    }

    /// #1183: what a delayed `kill` or `rm -f` of instance `a` may undo under the name. A stopped
    /// VM's checkpoint says who suspended it, whatever a sweep took; a holder that died holding the
    /// name is newer than any exit record; with neither, nothing shows whose the records are.
    #[test]
    fn a_delayed_kill_owns_only_what_its_instance_left() {
        let root = crate::test_util::TempDir::new("kill-owns");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let (a, b) = (dead_ident(), dead_ident());
        let take = |prior: Option<&host::Ident>| {
            match prior {
                Some(p) => std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(p).unwrap()).unwrap(),
                None => drop(std::fs::remove_file(host.vms("web", "lock").unwrap())),
            }
            let lock = host.take_name("web", true).unwrap();
            assert_eq!(lock.prior.as_ref(), prior);
            lock
        };
        let checkpoint = |owner: Option<&host::Ident>| {
            let dir = host.suspended("web").unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("manifest.json"), "{}").unwrap();
            if let Some(o) = owner {
                std::fs::write(dir.join("OWNER"), serde_json::to_vec(o).unwrap()).unwrap();
            }
        };
        // A ended, its exit record left; then B ran under the name and died holding it, unrecorded.
        containers::record_exit(&host, "web", &a, 130, false);
        checkpoint(None);
        let lock = take(Some(&b));
        assert_eq!(owns(&host, &lock, &a, true), Some(false), "a later holder's death outranks an older exit record");
        assert_eq!(owns(&host, &lock, &b, true), Some(true));
        drop(lock);
        checkpoint(Some(&b));
        let lock = take(Some(&b));
        assert_eq!(owns(&host, &lock, &a, true), Some(false));
        drop(lock);
        // A suspended, then died before recording its exit; a sweep took its lock (and the stale
        // record, as taking B's did: #1185).
        assert!(containers::exit_record(&host, "web").is_none(), "taking a dead holder's name drops an earlier instance's exit status");
        checkpoint(Some(&a));
        let lock = take(None);
        assert_eq!(owns(&host, &lock, &a, true), Some(true), "its checkpoint says it suspended it");
        assert_eq!(owns(&host, &lock, &b, true), Some(false));
        assert_eq!(owns(&host, &lock, &a, false), None, "its other records: nothing shows whose");
        drop(lock);
        // `rm -f` of A removes its checkpoint; of B leaves it; unknown, it refuses.
        checkpoint(Some(&a));
        remove_stopped(&host, "web", true, true, Some(&b), true).unwrap();
        assert!(host.suspended("web").unwrap().exists());
        checkpoint(None);
        let e = remove_stopped(&host, "web", true, true, Some(&a), true).unwrap_err().to_string();
        assert!(e.contains("could not confirm"), "{e}");
        assert!(host.suspended("web").unwrap().exists());
        // B ran under the name after A and exited (no `exited` record: `--rm`, or killed): a delayed
        // `rm -f` of A leaves B's exit status for `flexvm wait`; one of B removes it.
        std::fs::remove_dir_all(host.suspended("web").unwrap()).unwrap();
        containers::record_exit(&host, "web", &b, 3, true);
        remove_stopped(&host, "web", true, true, Some(&a), true).unwrap();
        assert_eq!(containers::exit_record(&host, "web").map(|e| e.ident), Some(b.clone()), "a later vm's exit status is kept");
        remove_stopped(&host, "web", true, true, Some(&b), true).unwrap();
        assert!(containers::exit_record(&host, "web").is_none());
    }

    /// #1187: a VM SIGKILLed before it recorded anything leaves its logs and a dead holder's lock
    /// (or, swept, only its logs). `ps -a` lists no VM of the name, and `rm` and `rm -f` remove what
    /// it left, judging its holder dead holding the name; never a live holder's, a starting `run`'s
    /// logs, or a moved hint.
    #[test]
    fn rm_removes_what_a_vm_that_recorded_nothing_left() {
        let root = crate::test_util::TempDir::new("rm-unrecorded");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let listed = |n: &str| vms(&host).iter().any(|v| v["name"] == n);
        for force in [false, true] {
            for swept in [false, true] {
                if !swept {
                    std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(&dead_ident()).unwrap()).unwrap();
                }
                host.write_log("web", "log", "killed vm");
                assert!(!listed("web"));
                // `kill` is for a running VM: what it left stays.
                assert_eq!(remove(&host, "web", true, false).unwrap_err().to_string(), "no vm named \"web\"");
                assert!(host.has_record("web", "log"));
                remove(&host, "web", force, true).unwrap();
                assert!(!host.has_record("web", "log") && !host.has_record("web", "logs"), "force={force} swept={swept}");
                assert_eq!(host.name_holder("web").unwrap(), None, "the name is free");
                assert!(!listed("web"));
                assert_eq!(remove(&host, "web", force, true).unwrap_err().to_string(), "no vm named \"web\"");
            }
        }
        // A holder not proven dead (alive, as one of another PID namespace may be told) is never reaped.
        let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
        std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(&host::Ident::of(child.id()).unwrap()).unwrap()).unwrap();
        host.write_log("web", "log", "live vm");
        assert!(remove(&host, "web", true, true).is_err());
        assert!(host.has_record("web", "log"));
        child.kill().unwrap();
        child.wait().unwrap();
        remove(&host, "web", false, true).unwrap();
        // Logs a live `run` prepares for the VM it starts stay theirs.
        drop(host.own_logs("web", Some("token")).unwrap());
        host.write_log("web", "log", "starting vm");
        let e = remove(&host, "web", false, true).unwrap_err().to_string();
        assert!(e.contains("is starting"), "{e}");
        assert!(host.has_record("web", "log"));
        host.retire_logs("web").unwrap();
        // A moved hint stays.
        std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(&dead_ident()).unwrap()).unwrap();
        std::fs::write(host.vms("web", "moved").unwrap(), "peer").unwrap();
        let e = remove(&host, "web", true, true).unwrap_err().to_string();
        assert!(e.contains("moved to peer"), "{e}");
        assert!(host.has_record("web", "moved"));
    }

    /// #1188 review: a removal of only a SIGKILLed VM's logs that took the name late finds what a VM
    /// that took it meanwhile left (moved away, or ended): checked again holding the name, nothing
    /// of it is removed.
    #[test]
    fn a_late_rm_of_unrecorded_logs_keeps_what_a_later_vm_left() {
        let root = crate::test_util::TempDir::new("rm-unrecorded-late");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        for (record, err) in [("moved", "moved to peer; kill it there"), ("exited", "ended meanwhile"), ("failed", "ended meanwhile")] {
            for force in [false, true] {
                // `remove_stopped`'s checks passed (only orphaned logs); the later VM then left these.
                host.write_log("web", "log", "later vm");
                std::fs::write(host.vms("web", record).unwrap(), if record == "moved" { "peer" } else { "{}" }).unwrap();
                let dead = dead_ident();
                containers::record_exit(&host, "web", &dead, 0, true);
                std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(&dead).unwrap()).unwrap();
                let e = remove_held(&host, "web", false, true, None, false).unwrap_err().to_string();
                assert!(e.contains(err), "{record}, force={force}: {e}");
                for ext in [record, "log", "exit"] {
                    assert!(host.has_record("web", ext), "{record}: its {ext} is kept");
                }
                assert_eq!(host.name_holder("web").unwrap(), Some(dead), "left as found");
                if record == "moved" {
                    host.retire_logs("web").unwrap();
                    for ext in ["moved", "exit", "lock"] {
                        std::fs::remove_file(host.vms("web", ext).unwrap()).unwrap();
                    }
                } else {
                    // Seen now: `rm` removes it.
                    remove(&host, "web", force, true).unwrap();
                    assert!(!host.has_record("web", record) && !host.has_record("web", "log"));
                }
            }
        }
    }

    /// #1185: a delayed `rm -f` signalled A; B took the name and crashed holding it, unrecorded. The
    /// removal rejects B's records, and letting the name go leaves the proof of that: `wait` never
    /// gives A's status as B's, and a second delayed removal of A never takes B's logs for A's.
    #[test]
    fn a_rejected_delayed_rm_leaves_a_crashed_replacements_records_its_own() {
        let root = crate::test_util::TempDir::new("rm-rejects");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let (a, b) = (dead_ident(), dead_ident());
        containers::record_exit(&host, "web", &a, 130, false);
        std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(&b).unwrap()).unwrap();
        std::fs::write(host.vms("web", "log").unwrap(), "b's log").unwrap();
        for _ in 0..2 {
            remove_stopped(&host, "web", true, true, Some(&a), true).unwrap();
            assert_eq!(std::fs::read_to_string(host.vms("web", "log").unwrap()).unwrap(), "b's log", "b's logs are kept");
            assert_eq!(host.name_holder("web").unwrap(), Some(b.clone()), "b's death is still on record");
            let e = containers::wait(&host, "web").unwrap_err().to_string();
            assert!(e.contains("without an exit status"), "never a's status: {e}");
        }
        // Even with the dead holder's record gone after all (a sweep), the stale exit is too.
        std::fs::remove_file(host.vms("web", "lock").unwrap()).unwrap();
        assert!(containers::exit_record(&host, "web").is_none());
        let e = remove_stopped(&host, "web", true, true, Some(&a), true).unwrap_err().to_string();
        assert!(e.contains("could not confirm"), "{e}");
        assert!(host.has_record("web", "log"));
        // B's own removal takes them.
        std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(&b).unwrap()).unwrap();
        remove_stopped(&host, "web", true, true, Some(&b), true).unwrap();
        assert!(!host.has_record("web", "log"));
    }

    #[test]
    fn force_rm_clears_a_running_vms_logs_but_kill_keeps_them() {
        use crate::test_util::JoinWithin;
        use std::os::unix::process::ExitStatusExt;
        let root = crate::test_util::TempDir::new("force-rm-logs");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        for (force, record) in [(false, "none"), (true, "none"), (true, "exited"), (true, "suspended")] {
            // The fake VM holds its name itself, as a real one does: its lock goes with its
            // process, before the pidfd `remove` waits on is readable. Held by a thread of this
            // process instead, it outlived the process by whatever the load made it (#1103).
            let lock = host::lock_path(&host.vms("web", "lock").unwrap(), libc::LOCK_EX | libc::LOCK_NB).unwrap();
            let fd = lock.as_raw_fd();
            let mut command = std::process::Command::new("sleep");
            unsafe {
                std::os::unix::process::CommandExt::pre_exec(&mut command, move || {
                    libc::signal(libc::SIGINT, libc::SIG_DFL);
                    // Kept across exec: the child shares the lock's open file description.
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = crate::test_util::ChildGuard(command.arg("60").spawn().unwrap());
            drop(lock);
            let entry = host::Entry { name: "web".into(), ident: host::Ident::of(child.id()).unwrap(), state: "running".into(), ..host::Entry::default() };
            std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(&entry.ident).unwrap()).unwrap();
            host::store_private(&host.vms("web", "json").unwrap(), &entry, false).unwrap();
            for ext in ["log", "log.1"] {
                std::fs::write(host.vms("web", ext).unwrap(), "old vm").unwrap();
            }
            // Model an app exit or a suspend winning the race with the kill: recorded by the
            // VM before its process ends, so before `remove` sees it gone.
            if record == "exited" {
                std::fs::write(host.vms("web", "exited").unwrap(), "{}").unwrap();
            } else if record == "suspended" {
                let dir = host.suspended("web").unwrap();
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("manifest.json"), "{}").unwrap();
            }
            let ended = std::thread::spawn(move || child.wait().unwrap());
            let result = remove(&host, "web", true, force);
            let status = ended.join_within().unwrap();
            result.unwrap();
            assert_eq!(status.signal(), Some(libc::SIGINT));
            for ext in ["log", "log.1"] {
                assert_eq!(host.has_record("web", ext), !force, "{record}, force={force}: {ext}");
            }
            assert!(!host.has_record("web", "exited"));
            assert!(!host.suspended("web").unwrap().exists());
        }
    }

    #[test]
    fn ps_lists_a_suspended_vm_while_its_name_is_held() {
        let root = crate::test_util::TempDir::new("ps-held");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let dir = host.suspended("vm").unwrap();
        std::fs::create_dir(&dir).unwrap();
        let body = serde_json::to_vec(&json!({
            "format": checkpoint::FORMAT, "created_unix_ms": 0, "name": "vm", "ip": "10.0.0.1",
            "template": "tpl", "template_id": "id", "saved_msrs": [], "saved_tsc_khz": 2000000, "vcpus": 1, "mem_mib": 1, "max_mib": 1,
            "hotplug_mib": 0, "guest_pages": 256, "data_pages": 0, "zero_pages": 0, "files": {}
        }))
        .unwrap();
        let mut hash = template::Hash::new();
        hash.update(&body);
        std::fs::write(dir.join("manifest.json"), [format!("{}\n", hash.finish()).as_bytes(), &body].concat()).unwrap();
        std::fs::write(dir.join("GEN"), "1").unwrap();
        let suspended = vms(&host);
        assert_eq!(suspended.len(), 1);
        assert_eq!(suspended[0]["state"], "suspended");

        let name = host.take_name("vm", true).unwrap();
        assert!(host.alive("vm") && host.entries().is_empty());
        assert_eq!(vms(&host), suspended);
        assert!(remove(&host, "vm", false, true).unwrap_err().to_string().contains("is running"));
        assert_eq!(host.take_name("vm", true).err().unwrap().to_string(), "vm name \"vm\" is taken");
        assert!(host.is_suspended("vm"));

        name.publish(&host::Entry { name: "vm".into(), ident: host::Ident::me(), state: "starting".into(), ..host::Entry::default() }).unwrap();
        let listed = vms(&host);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["name"], "vm");
        assert_eq!(listed[0]["state"], "starting");
        drop(name);
        assert_eq!(vms(&host), suspended);
    }

    #[test]
    fn standby_only_pulls_allow_global_flags() {
        for global in ["-v", "--verbose", "--help", "--version"] {
            let args = parse(&[global, "--state", "/state", "--run", "/run", "pull", "nginx", "--standby", "3", "--tag", "web"]);
            assert!(only_standby(&args), "{global}");
        }
        for option in ["--mem=512", "--warm", "--ready-port=80", "--vcpus=2"] {
            assert!(!only_standby(&parse(&["-v", "pull", "nginx", "--standby=3", option])), "{option}");
        }
    }

    #[test]
    fn attached_option_values_preserve_commands_and_child_args() {
        let args = parse(&["run", "-dit", "--name=web", "--memory=1g", "-p8080:80", "-eA=one=two", "--env=B=", "-ip=1:1", "nginx", "--name=app"]);
        check_applies(&args).unwrap();
        assert_eq!((args.get("name"), args.get("memory")), (Some("web"), Some("1g")));
        assert_eq!((args.all("publish"), args.all("env")), (vec!["8080:80".to_string(), "1:1".into()], vec!["A=one=two".to_string(), "B=".into()]));
        assert!(args.has("detach") && args.has("interactive") && args.has("tty"));
        assert_eq!(args.rest, ["--name=app"]);
        let child = parse(&args.child_args.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!((child.has("detach"), child.flags.len()), (false, args.flags.len() - 1));
        let args = parse(&["exec", "-itu", "app", "-w/srv", "-eA=B", "web", "sh", "-c", "true"]);
        assert_eq!((args.get("workdir"), args.get("user"), args.get("env")), (Some("/srv"), Some("app"), Some("A=B")));
        assert_eq!(parse(&["kill", "-sTERM", "web"]).get("signal"), Some("TERM"));
        for option in ["--detach=true", "-dtrue", "-itx", "-dv", "-é", "--unknown=value"] {
            assert!(Args::parse(["run", option, "nginx"].map(String::from)).is_err(), "{option}");
        }
        assert!(Args::parse(["run", "--name", "--memory=1g", "nginx"].map(String::from)).is_err());
    }

    #[test]
    fn memory_sizes_are_dockers() {
        for (v, mib) in
            [("512m", 512), ("512M", 512), ("2g", 2048), ("2GB", 2048), ("1.5g", 1536), ("1048576", 1), ("1t", 1 << 20), ("1536k", 1), ("4096mib", 4096)]
        {
            assert_eq!(memory_mib(v).unwrap(), mib, "{v}");
        }
        for v in ["", "m", "x", "2q", "-1g", "nang", "1e30t", "1e3m", "+2g", ".5g", "1.g", "1.2.3g", "1e-3g", "1e+3m"] {
            assert!(memory_mib(v).is_err(), "{v}");
        }
        assert_eq!(memory_mib("2048").unwrap_err().to_string(), "--memory 2048 is 2048 bytes: give a unit, as 2048m");
        assert!(resources(&parse(&["--cpus", "0"])).is_err() && resources(&parse(&["--cpus", "x"])).is_err());
        let r = resources(&parse(&["--cpus", "1.5", "--memory", "1g"])).unwrap();
        assert_eq!((r.cpus, r.memory_mib), (Some(1.5), Some(1024)));
    }

    #[test]
    fn resources_fit_the_template() {
        let meta: crate::template::Meta = serde_json::from_value(json!({
            "compatibility": {"cpu": "test", "tsc_khz": 2000000, "tsc_control": false, "msrs": [], "firecracker": "test", "features": {}, "xsave": {}},
            "vcpus": 4, "mem_mib": 384, "max_mib": 384 + 8192, "plugged_mib": 4096, "kernel": "/k", "rootfs": "/r", "id": "a", "components": {}
        }))
        .unwrap();
        let r = |cpus: Option<f64>, memory_mib: Option<u64>| vm::Resources { cpus, memory_mib };
        r(Some(4.0), Some(384 + 4096)).check(&meta).unwrap();
        r(Some(0.5), Some(384 + 8192)).check(&meta).unwrap();
        assert!(r(Some(4.5), None).check(&meta).unwrap_err().to_string().contains("4 vCPUs"));
        let e = r(None, Some(1024)).check(&meta).unwrap_err().to_string();
        assert!(e.contains("384 + 4096 MiB") && e.contains("4480m"), "{e}");
        assert!(r(None, Some(384 + 8193)).check(&meta).unwrap_err().to_string().contains("ceiling"));
        // Growth stops at the cap, in whole steps.
        assert_eq!(r(None, Some(384 + 5000)).hotplug_cap(&meta), 4992);
        assert_eq!(r(None, None).hotplug_cap(&meta), 8192);
        // A stopped VM's, from its manifest's sizes (`ps -a`).
        assert_eq!((r(None, Some(384 + 5000)).ceiling(384, 384 + 8192), r(None, None).ceiling(384, 384 + 8192)), (384 + 4992, 384 + 8192));
        assert_eq!((r(Some(1.5), None).cpu_max(), r(None, None).cpu_max()), ("150000 100000".to_string(), "max 100000".to_string()));
    }

    #[test]
    fn a_held_name_is_taken_and_plain_rm_or_start_a_leave_its_vm_alone() {
        let root = crate::test_util::TempDir::new("held-name");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let lock = host.take_name("web", false).unwrap();
        // Made up again when taken (`run`, `Proc::run`); an explicit name's error stays.
        assert!(host::name_taken(&host.take_name("web", false).err().unwrap()));
        assert!(!host::name_taken(&host::check_name(".x").unwrap_err()));
        // A VM started meanwhile holds its name: a plain rm takes it to remove, so is refused,
        // signalling nothing; the record it saw stays.
        std::fs::write(host.vms("web", "failed").unwrap(), "died").unwrap();
        for ext in ["log", "log.1"] {
            std::fs::write(host.vms("web", ext).unwrap(), "running vm").unwrap();
        }
        let e = remove_stopped(&host, "web", true, true, None, false).unwrap_err().to_string();
        assert!(e.contains("is running") && e.contains("rm -f web"), "{e}");
        assert!(host.vms("web", "failed").unwrap().exists());
        for ext in ["log", "log.1"] {
            assert_eq!(std::fs::read_to_string(host.vms("web", ext).unwrap()).unwrap(), "running vm");
        }
        // start -a: a paused VM is unpaused, not attached to.
        let entry = host::Entry { name: "web".into(), ident: host::Ident::me(), state: "paused".into(), ..host::Entry::default() };
        std::fs::write(host.vms("web", "lock").unwrap(), serde_json::to_vec(&entry.ident).unwrap()).unwrap();
        lock.publish(&entry).unwrap();
        let e = stopped_to_attach(&host, "web").unwrap_err().to_string();
        assert!(e.contains("flexvm unpause web"), "{e}");
        drop(lock);
        stopped_to_attach(&host, "web").unwrap();
    }

    #[test]
    fn cpus_need_the_cpu_controller() {
        let root = crate::test_util::TempDir::new("cpu-controller");
        assert!(vmproc::cpu_controller(None).unwrap_err().to_string().contains("cgroup"));
        std::fs::write(root.join("cgroup.subtree_control"), "memory cpuset\n").unwrap();
        assert!(vmproc::cpu_controller(Some(&root)).unwrap_err().to_string().contains("cpu controller"));
        std::fs::write(root.join("cgroup.subtree_control"), "cpuset cpu memory\n").unwrap();
        vmproc::cpu_controller(Some(&root)).unwrap();
    }

    #[test]
    fn generated_names_are_free_and_valid() {
        let root = crate::test_util::TempDir::new("names");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        for _ in 0..20 {
            let n = host::generated_name(&host).unwrap();
            host::check_name(&n).unwrap();
            assert!(n.contains('_'), "{n}");
        }
    }

    #[test]
    fn detach_only_removes_flexvm_options_from_child_arguments() {
        let args = parse(&["run", "-d", "--detach", "--name", "web", "--ip", "10.0.0.2", "ubuntu", "tool", "-d", "--detach", "--unknown"]);
        assert!(args.has("detach"));
        assert_eq!(args.positional, ["run", "ubuntu"]);
        assert_eq!(args.rest, ["tool", "-d", "--detach", "--unknown"]);
        assert_eq!(args.child_args, ["run", "--name", "web", "--ip", "10.0.0.2", "ubuntu", "tool", "-d", "--detach", "--unknown"]);
        let child = Args::parse(args.child_args).unwrap();
        assert!(!child.has("detach"));
        assert_eq!(child.rest, args.rest);
        // A `--` after IMAGE is dropped, as after exec NAME.
        assert_eq!(parse(&["run", "ubuntu", "--", "ls", "--", "-d"]).rest, ["ls", "--", "-d"]);
        assert_eq!(child_args(&parse(&["--state", "/s", "start", "x"]), &["start", "--attach", "x"]), ["--state", "/s", "start", "--attach", "x"]);
    }

    #[test]
    fn exec_options_preserve_argv_and_repeated_env() {
        let args = parse(&[
            "exec",
            "-d",
            "-e",
            "K=first",
            "--env",
            "K=last=two",
            "-w",
            "/srv",
            "-u",
            "app:staff",
            "vm",
            "printf",
            "%s",
            "",
            "a b",
            "$HOME",
            ";",
            "-d",
        ]);
        check_applies(&args).unwrap();
        let cmd = exec_command(&args).unwrap();
        assert_eq!(cmd["argv"], json!(["printf", "%s", "", "a b", "$HOME", ";", "-d"]));
        assert_eq!(cmd["env"], json!(["K=first", "K=last=two"]));
        assert_eq!(cmd["workdir"], "/srv");
        assert_eq!(cmd["user"], "app:staff");
        assert_eq!(cmd["detach"], true);
        for words in [&["exec", "vm"][..], &["exec", "vm", ""], &["exec", "-e", "=bad", "vm", "true"]] {
            assert!(exec_command(&parse(words)).is_err());
        }
        for flag in ["-e", "-w", "-u"] {
            assert!(Args::parse(["exec", flag].map(String::from)).is_err());
        }
    }

    #[test]
    fn run_exec_and_pull_share_bare_environment_keys() {
        // Read an existing variable: no process-wide environment mutation while tests run.
        let key = "PATH";
        let value = std::env::var(key).unwrap();
        let options = ["-e", "PATH=first", "-e", key, "-e", "FLEXVM_TEST_UNSET_VAR", "-e", "EMPTY=", "-e", "PATH=last"];
        let run = parse(&[&["run"][..], &options, &["img"]].concat());
        let exec = parse(&[&["exec"][..], &options, &["vm", "true"]].concat());
        let expected = vec!["PATH=first".to_string(), format!("PATH={value}"), "EMPTY=".into(), "PATH=last".into()];
        assert_eq!(run_spec(&run, None).unwrap().env, expected);
        assert_eq!(exec_command(&exec).unwrap()["env"], json!(expected));
        let options: Vec<_> = options.iter().map(|v| if *v == "-e" { "--env" } else { *v }).collect();
        let pull = parse(&[&["pull", "img"][..], &options].concat());
        assert_eq!(image_options(&pull, "img").unwrap().env, expected);
        let pull = parse(&["pull", "--env", key, "--env", "FLEXVM_TEST_UNSET_VAR", "img"]);
        assert_eq!(image_options(&pull, "img").unwrap().env, [format!("PATH={value}")]);
        for value in ["", "=bad", "K\0", "K=bad\0value"] {
            assert!(exec_command(&parse(&["exec", "-e", value, "vm", "true"])).is_err());
            assert!(run_spec(&parse(&["run", "-e", value, "img"]), None).is_err());
            assert!(image_options(&parse(&["pull", "--env", value, "img"]), "img").is_err());
        }
    }

    #[test]
    fn separator_before_run_image_or_exec_name() {
        for (words, positional, rest) in [
            (vec!["exec", "--", "web", "ls", "--all"], vec!["exec", "web"], vec!["ls", "--all"]),
            (vec!["run", "--rm", "--", "alpine", "echo", "hi"], vec!["run", "alpine"], vec!["echo", "hi"]),
            (vec!["run", "--", "--image", "--", "hi"], vec!["run", "--image"], vec!["hi"]),
            (vec!["exec", "--", "web", "--", "--", "-x"], vec!["exec", "web"], vec!["--", "-x"]),
            (vec!["exec", "web", "--", "--", "-x"], vec!["exec", "web"], vec!["--", "-x"]),
            (vec!["exec", "web", "--", "-flag"], vec!["exec", "web"], vec!["-flag"]),
            (vec!["run", "img", "--", "cmd"], vec!["run", "img"], vec!["cmd"]),
            (vec!["exec", "--", "web"], vec!["exec", "web"], vec![]),
            (vec!["run", "--"], vec!["run"], vec![]),
        ] {
            let args = parse(&words);
            assert_eq!(args.positional, positional);
            assert_eq!(args.rest, rest);
            assert_eq!(args.child_args, words);
            // A detached run's VM process parses its child_args to the same command.
            let child = Args::parse(args.child_args.clone()).unwrap();
            assert_eq!((child.positional, child.rest), (args.positional, args.rest));
        }
    }

    #[test]
    fn pull_ready_port_must_be_nonzero() {
        for port in ["0", "65536", "-1", "bad"] {
            assert!(image_options(&parse(&["pull", "--warm", "--ready-port", port, "img"]), "img").is_err(), "{port}");
        }
        for port in [1, 65535] {
            let options = image_options(&parse(&["pull", "--warm", "--ready-port", &port.to_string(), "img"]), "img").unwrap();
            assert!(matches!(options.ready, Some(image::Ready::Port(p)) if p == port));
        }
    }

    #[test]
    fn exec_preserves_guest_flags_and_drops_only_one_separator() {
        let args = parse(&["--state", "/tmp/state", "exec", "web", "tool", "-d", "--detach", "--unknown"]);
        assert_eq!(args.get("state"), Some("/tmp/state"));
        assert!(!args.has("detach"));
        assert_eq!(args.positional, ["exec", "web"]);
        assert_eq!(args.rest, ["tool", "-d", "--detach", "--unknown"]);
        assert_eq!(args.child_args, ["--state", "/tmp/state", "exec", "web", "tool", "-d", "--detach", "--unknown"]);
        let args = parse(&["exec", "web", "--", "ls", "--", "-d"]);
        assert_eq!(args.rest, ["ls", "--", "-d"]);
    }

    #[test]
    fn missing_or_empty_names_name_the_command() {
        for cmd in ["run", "exec", "stop", "start", "pause", "unpause", "kill", "rm", "migrate", "pull", "rmi"] {
            let what = if matches!(cmd, "run" | "pull" | "rmi") { "IMAGE" } else { "NAME" };
            for argv in [vec![cmd], vec![cmd, ""]] {
                assert_eq!(real_main(&parse(&argv)).unwrap_err().to_string(), format!("{cmd} needs {what}"));
            }
        }
        for argv in [&["run", "--standby", "t"][..], &["run", "--incoming"], &["run", "--checkpoint", "/d"]] {
            check_applies(&parse(argv)).unwrap();
        }
        assert!(check_applies(&parse(&["stop", "a", ""])).is_err());
    }

    #[test]
    fn checkpoint_subcommands_take_their_own_words_and_flags() {
        for argv in [
            &["checkpoint", "create", "web"][..],
            &["checkpoint", "create", "web", "base", "--stop", "--incremental"],
            &["checkpoint", "ls", "--filter", "vm=web", "--format", "{{.ID}}"],
            &["checkpoint", "rm", "-f", "a", "b"],
            &["checkpoint", "prune", "--older-than", "24h", "-f"],
            &["checkpoint", "save", "web"],
            &["checkpoint", "save", "web", "-o", "web.tar"],
            &["checkpoint", "save", "-oweb.tar", "web"],
            &["checkpoint", "load"],
            &["checkpoint", "load", "-i", "web.tar", "--name", "w", "--sha256", "ab"],
        ] {
            check_applies(&parse(argv)).unwrap();
        }
        let p = parse(&["checkpoint", "save", "web", "-o", "out.tar"]);
        assert_eq!((p.get("output"), p.names()), (Some("out.tar"), &["save".to_string(), "web".into()][..]));
        assert_eq!(parse(&["checkpoint", "load", "-i", "/d"]).get("input"), Some("/d"));
        let err = |argv: &[&str]| check_applies(&parse(argv)).unwrap_err().to_string();
        assert!(err(&["checkpoint", "web", "/tmp/ck"]).contains("flexvm checkpoint create VM [NAME]"), "the form before #775");
        assert!(err(&["checkpoint"]).contains("needs create, ls, rm, prune, save or load"));
        assert_eq!(err(&["checkpoint", "create"]), "checkpoint create needs VM");
        assert_eq!(err(&["checkpoint", "rm"]), "checkpoint rm needs NAME|ID");
        assert!(err(&["checkpoint", "ls", "--stop"]).contains("--stop does not apply to checkpoint ls"));
        assert!(err(&["checkpoint", "create", "web", "a", "b"]).contains("does not take \"b\""));
        assert!(err(&["checkpoint", "prune", "x"]).contains("does not take"));
        assert_eq!(err(&["checkpoint", "save"]), "checkpoint save needs NAME|ID");
        assert!(err(&["checkpoint", "save", "a", "b"]).contains("does not take \"b\""));
        assert!(err(&["checkpoint", "load", "x"]).contains("does not take"));
        assert!(err(&["checkpoint", "load", "-o", "x"]).contains("--output does not apply to checkpoint load"));
        assert!(err(&["checkpoint", "save", "web", "--name", "x"]).contains("--name does not apply to checkpoint save"));
        assert!(err(&["checkpoint", "create", "web", "-i", "x"]).contains("--input does not apply"));
        let age = |s| util::parse_age(s).map(|d| d.as_secs());
        assert_eq!(["90s", "30m", "24h", "7d", "0d"].map(age), [Some(90), Some(1800), Some(86400), Some(604800), Some(0)]);
        assert!(["", "h", "1", "1w", "-1h", "1.5h"].into_iter().all(|s| age(s).is_none()));
    }

    #[test]
    fn image_and_system_command_options_apply_narrowly() {
        for argv in [
            vec!["images", "-q", "--filter", "reference=app:*", "--filter", "dangling=false"],
            vec!["tag", "src", "dst"],
            vec!["image", "prune", "-f"],
            vec!["system", "prune", "--force"],
            vec!["system", "df"],
            vec!["version"],
            vec!["login", "ghcr.io", "--username", "alice", "--password-stdin"],
            vec!["logout"],
        ] {
            check_applies(&parse(&argv)).unwrap();
        }
        for argv in [
            vec!["tag", "src"],
            vec!["tag", "src", "dst", "extra"],
            vec!["image", "df"],
            vec!["system", "df", "-f"],
            vec!["system", "df", "-a"],
            vec!["image", "prune", "-a"],
            vec!["system"],
            vec!["images", "-q", "--json"],
            vec!["version", "--filter", "x=y"],
            vec!["logout", "--username", "alice"],
            vec!["logout", "-q"],
            vec!["images", "--password-stdin"],
        ] {
            assert!(check_applies(&parse(&argv)).is_err(), "{argv:?}");
        }
        assert_eq!(parse(&["images", "--filter", "reference=a*", "--filter", "reference=b*"]).all("filter").len(), 2);
    }

    #[test]
    fn unknown_command_names_the_bad_word() {
        assert_eq!(real_main(&parse(&["rnu", "web"])).unwrap_err().to_string(), r#"unknown command "rnu" (see flexvm --help)"#);
    }

    #[test]
    fn unknown_options_and_missing_values_are_errors() {
        for option in ["--typo", "--listen", "-x", "--keep-running"] {
            let error = Args::parse(["run", option, "web"].map(String::from)).err().unwrap();
            assert_eq!(error.to_string(), format!("unknown option {option} (see flexvm --help)"));
        }
        let error = Args::parse(["run", "--detach=yes", "web"].map(String::from)).err().unwrap();
        assert_eq!(error.to_string(), "--detach does not take a value");
        let error = Args::parse(["run", "--ip"].map(String::from)).err().unwrap();
        assert_eq!(error.to_string(), "--ip needs a value");
    }

    #[test]
    fn option_values_cannot_be_flags() {
        for option in ["--state", "--run", "--ip", "--tag", "--cmd", "--name"] {
            for value in ["--run", "--detach", "--standby", "--"] {
                let error = Args::parse([option, value, "X"].map(String::from)).err().unwrap();
                assert_eq!(error.to_string(), format!("{option} needs a value"));
            }
        }
        let error = Args::parse(["reclaim", "--force", "--state", "X"].map(String::from)).err().unwrap();
        assert_eq!(error.to_string(), "--force needs a generation; run flexvm reclaim IP to see GEN");
        // Argv-style values may start with `--`: a binary entrypoint's flag-only arguments.
        let args = parse(&["pull", "app", "--cmd", "--port 8080", "--entrypoint", "--x", "--ready-cmd", "--check", "--warm"]);
        assert_eq!((args.get("cmd"), args.get("entrypoint"), args.get("ready-cmd")), (Some("--port 8080"), Some("--x"), Some("--check")));
        check_applies(&args).unwrap();
        assert_eq!(image_options(&args, "app").unwrap().cmd, Some(vec!["--port".to_string(), "8080".to_string()]));
    }

    #[test]
    fn reclaim_force_requires_a_generation() {
        let error = Args::parse(["reclaim", "10.9.0.2", "--force"].map(String::from)).err().unwrap();
        assert_eq!(error.to_string(), "--force needs a generation; run flexvm reclaim IP to see GEN");
        let args = parse(&["reclaim", "10.9.0.2", "--force", "42"]);
        check_applies(&args).unwrap();
        assert_eq!(args.get("force"), Some("42"));
        for gen in ["1", "42"] {
            let option = format!("--force={gen}");
            let args = parse(&["reclaim", "10.9.0.2", &option]);
            check_applies(&args).unwrap();
            assert_eq!(args.get("force"), Some(gen));
        }
        for gen in ["", "bad", "-1", "18446744073709551616"] {
            let args = parse(&["reclaim", "10.9.0.2", "--force", gen]);
            assert_eq!(real_main(&args).unwrap_err().to_string(), format!("bad --force generation {gen:?}"));
        }
    }

    #[test]
    fn switches_repeated_values_and_internal_flags_parse() {
        let args = parse(&["pull", "x", "--env", "A=1", "--json", "--env", "B=2", "--standby", "3", "--max", "456", "--max", "789"]);
        assert!(args.has("json"));
        assert_eq!(args.all("env"), ["A=1", "B=2"]);
        assert_eq!((args.get("standby"), args.parse_or::<u64>("max", 0).unwrap()), (Some("3"), 789));
        let args = parse(&["run", "--incoming", "--standby", "--paused"]);
        assert!(args.has("incoming") && args.has("standby") && args.has("paused"));
        assert!(args.rest.is_empty());
        // -a is start's --attach and ps's --all; -f is rm's --force only.
        assert!(parse(&["start", "-a", "x"]).has("attach") && parse(&["ps", "-a"]).has("all") && parse(&["rm", "-f", "x"]).has("force"));
        assert!(Args::parse(["reclaim", "10.0.0.2", "-f"].map(String::from)).is_err());
    }

    #[test]
    fn a_parse_error_still_finds_its_command() {
        for argv in [&["--bogus", "run", "job"][..], &["run", "--bogus", "job"], &["-x", "start", "job"], &["--bogus", "run", "--checkpoint", "/x", "--ip"]] {
            let (args, e) = Args::parse_partly(argv.iter().map(|a| a.to_string()));
            assert!(e.is_some() && ["run", "start"].contains(&args.positional[0].as_str()), "{argv:?}");
        }
        let (args, e) = Args::parse_partly(["--state", "run", "ps"].map(String::from));
        assert!(e.is_none() && args.positional == ["ps"]);
    }

    #[test]
    fn run_takes_app_settings_and_kill_a_signal() {
        let a = parse(&["run", "-e", "A=1", "--env", "B=2", "--env-file", "f", "--entrypoint", "[\"sh\", \"-c\"]", "--rm", "-d", "img", "-e", "x"]);
        check_applies(&a).unwrap();
        assert_eq!((a.all("env"), a.get("env-file"), a.has("rm")), (vec!["A=1".to_string(), "B=2".into()], Some("f"), true));
        assert!(parse(&["run", "--keep", "img"]).has("keep") && check_applies(&parse(&["run", "--keep", "img"])).is_ok());
        assert_eq!(a.rest, ["-e", "x"], "after IMAGE, the command's");
        // A detached run's VM process parses its words again.
        assert_eq!(a.child_args, ["run", "-e", "A=1", "--env", "B=2", "--env-file", "f", "--entrypoint", "[\"sh\", \"-c\"]", "--rm", "img", "-e", "x"]);
        let spec = run_spec(&parse(&["run", "-e", "A=1", "-e", "FLEXVM_TEST_UNSET_VAR", "--entrypoint", "sleep 1", "img"]), None).unwrap();
        assert_eq!(spec, app::RunSpec { env: vec!["A=1".into()], entrypoint: Some(vec!["sleep".into(), "1".into()]), ..Default::default() });
        let dir = test_util::TempDir::new("env-file-flag");
        std::fs::write(dir.join("env"), "A=file\nC=3\n").unwrap();
        let file = dir.join("env").to_string_lossy().into_owned();
        let spec = run_spec(&parse(&["run", "--env-file", &file, "-e", "A=flag", "--ip", "10.0.0.5", "img"]), Some("10.0.0.5".parse().unwrap())).unwrap();
        assert_eq!(
            (spec.env, spec.ip),
            (vec!["A=file".to_string(), "C=3".into(), "A=flag".into()], Some("10.0.0.5".parse().unwrap())),
            "-e after the files: it wins"
        );
        assert!(run_spec(&parse(&["run", "--env-file", "/nonexistent/env", "img"]), None).unwrap_err().to_string().contains("--env-file"));
        let k = parse(&["kill", "-s", "TERM", "a", "b"]);
        check_applies(&k).unwrap();
        assert_eq!((k.get("signal"), k.names()), (Some("TERM"), &["a".to_string(), "b".into()][..]));
        let err = |a: &[&str]| check_applies(&parse(a)).err().map(|e| e.to_string());
        assert!(Args::parse(["kill", "-s"].map(String::from)).is_err(), "-s needs a signal");
        assert!(err(&["stop", "--signal", "TERM", "a"]).is_some());
        assert!(err(&["run", "--checkpoint", "/d", "-e", "A=1"]).unwrap().contains("--checkpoint"));
        assert!(err(&["run", "--checkpoint", "/d", "--keep"]).unwrap().contains("--checkpoint"));
        assert!(err(&["pull", "img", "--keep"]).is_some());
        assert!(err(&["run", "--keep", "img", "make"]).unwrap().contains("CMD"));
    }

    #[test]
    fn container_commands_take_their_flags_and_words() {
        let err = |a: &[&str]| check_applies(&parse(a)).err().map(|e| e.to_string());
        for ok in [
            &["logs", "-f", "--tail", "20", "web"][..],
            &["logs", "--follow", "web"],
            &["inspect", "a", "b"],
            &["wait", "a", "b"],
            &["restart", "a", "b"],
            &["rename", "a", "b"],
            &["ps", "-a", "--filter", "name=web", "--filter", "status=running", "--format", "{{.Name}}"],
        ] {
            assert_eq!(err(ok), None, "{ok:?}");
        }
        let logs = parse(&["logs", "-f", "web"]);
        assert!(logs.has("follow") && !logs.has("force"), "-f is logs' follow");
        assert!(parse(&["rm", "-f", "web"]).has("force"), "and rm's force");
        assert_eq!(parse(&["ps", "--filter", "a=1", "--filter", "b=2"]).all("filter"), ["a=1", "b=2"]);
        assert_eq!(err(&["rename", "a"]).unwrap(), "rename needs OLD NEW");
        assert!(err(&["rename", "a", "b", "c"]).is_some());
        assert_eq!(err(&["logs"]).unwrap(), "logs needs NAME");
        assert!(err(&["logs", "a", "b"]).is_some(), "one NAME");
        assert_eq!(err(&["wait"]).unwrap(), "wait needs NAME");
        assert_eq!(err(&["inspect"]).unwrap(), "inspect needs NAME");
        assert_eq!(err(&["restart"]).unwrap(), "restart needs NAME");
        assert!(err(&["stop", "-q", "a"]).unwrap().contains("--quiet does not apply"));
        assert!(err(&["ps", "--tail", "3"]).is_some());
        assert!(err(&["ps", "--json", "--format", "json"]).unwrap().contains("not both"));
        assert!(Args::parse(["kill", "-f", "a"].map(String::from)).is_err(), "-f is only rm's and logs'");
    }

    #[test]
    fn flags_and_words_a_command_does_not_take_are_errors() {
        let err = |a: &[&str]| check_applies(&parse(a)).err().map(|e| e.to_string());
        assert_eq!(err(&["run", "--mem", "512", "web"]).unwrap(), "--mem does not apply to run (see flexvm --help)");
        assert!(err(&["start", "--ip", "10.0.0.1", "web"]).is_some());
        assert!(err(&["run", "--checkpoint", "/d", "ubuntu"]).unwrap().contains("takes no IMAGE"));
        assert_eq!(
            err(&["run", "--checkpoint", "saved", "--", "/bin/sh"]).unwrap(),
            "run --checkpoint takes no CMD: the checkpoint's command cannot be replaced"
        );
        assert_eq!(err(&["run", "--paused", "ubuntu"]).unwrap(), "--paused applies to run --checkpoint");
        assert_eq!(err(&["kill", "web", "--", "x"]), None);
        assert_eq!(err(&["run", "--warm", "t"]).unwrap(), "--warm does not apply to run (see flexvm --help)");
        assert_eq!(err(&["images", "--tag", "x"]).unwrap(), "--tag does not apply to images (see flexvm --help)");
        assert!(err(&["rmi", "a", "b"]).is_some());
        assert!(err(&["start", "-a", "a", "b"]).unwrap().contains("one NAME"));
        assert!(err(&["config"]).unwrap().contains("unknown command"));
        assert!(err(&["recover"]).unwrap().contains("unknown command"));
        assert!(Args::parse(["listen", "1.2.3.4:7070", "--peer", "a:1"].map(String::from)).is_err());
        for ok in [
            &["--state", "/s", "run", "--name", "web", "-d", "--cpus", "1.5", "--memory", "1g", "ubuntu:24.04", "make", "test"][..],
            &["run", "ubuntu", "--name", "--x"],
            &["exec", "web", "ls", "-l"],
            &["pull", "busybox", "--tag", "t", "--vcpus", "2", "--warm", "--ready-port", "80", "--standby", "2"],
            &["images", "--json"],
            &["ps", "-a", "--json"],
            &["stop", "a", "b"],
            &["start", "a", "b"],
            &["start", "-a", "a"],
            &["pause", "a"],
            &["unpause", "a"],
            &["kill", "a", "b"],
            &["rm", "-f", "a", "b"],
            &["rmi", "ubuntu:24.04"],
            &["listen", "1.2.3.4:7070"],
            &["info"],
            &["run", "--checkpoint", "/d", "--ip", "auto", "--paused", "--name", "w"],
        ] {
            assert_eq!(err(ok), None, "{ok:?}");
        }
    }

    #[test]
    fn listener_names_bind_each_distinct_address() {
        let v4: std::net::SocketAddr = "127.0.0.1:7070".parse().unwrap();
        let v6: std::net::SocketAddr = "[::1]:7070".parse().unwrap();
        assert_eq!(listener_addresses("host:7070", vec![v4]).unwrap(), [v4]);
        assert_eq!(listener_addresses("host:7070", vec![v4, v4]).unwrap(), [v4]);
        assert_eq!(listener_addresses("host:7070", vec![v6, v4, v6]).unwrap(), [v6, v4]);
        // A mapped address is its IPv4 one, so the pair binds once; a plain IPv6 one keeps its scope.
        let mapped: std::net::SocketAddr = "[::ffff:127.0.0.1]:7070".parse().unwrap();
        assert_eq!(listener_addresses("host:7070", vec![v4, mapped]).unwrap(), [v4]);
        assert_eq!(listener_addresses("host:7070", vec![mapped, v4]).unwrap(), [v4]);
        let scoped: std::net::SocketAddr = "[fe80::1%3]:7070".parse().unwrap();
        assert_eq!(listener_addresses("host:7070", vec![scoped]).unwrap()[0].to_string(), "[fe80::1%3]:7070");
        assert!(listener_addresses("host:7070", vec![]).is_err());
        assert!(listener_addresses("host:0", vec!["127.0.0.1:0".parse().unwrap()]).is_err());
        // Every address gets its own socket, taking connections; one that cannot be bound fails them all.
        let second: std::net::SocketAddr = "127.0.0.2:7070".parse().unwrap();
        let mut two = listener_addresses("host", vec![v4, mapped, second]).unwrap();
        assert_eq!(two, [v4, second]);
        // Let the kernel allocate ports at bind time, with no probe/drop/rebind gap.
        // Resolution rejects port 0 above; bind_each itself can use it for this test.
        for a in &mut two {
            a.set_port(0);
        }
        let bound = bind_each("host", &two).unwrap();
        assert_eq!(bound.len(), 2);
        for (l, a) in bound.iter().zip(&mut two) {
            let local = l.local_addr().unwrap();
            assert_eq!(local.ip(), a.ip());
            assert_ne!(local.port(), 0);
            *a = local;
        }
        for (l, a) in bound.iter().zip(&two) {
            let _c = std::net::TcpStream::connect(a).unwrap();
            l.accept().unwrap();
        }
        let held = bound.into_iter().nth(1).unwrap();
        // Only the held second address may fail; the first gets a fresh port.
        two[0].set_port(0);
        let e = bind_each("host", &two).unwrap_err().to_string();
        assert!(e.starts_with(&format!("listen on host ({}): ", two[1])), "{e}");
        drop(held);
    }

    #[test]
    fn an_activated_socket_must_take_every_address_of_its_name() {
        let a = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        // A wildcard socket listens on every address with its port.
        let wildcard = a("0.0.0.0:7070");
        assert!(activated_at("10.1.2.3:7070", wildcard, false).is_ok());
        assert!(activated_at("10.1.2.3:7071", wildcard, false).is_err());
        assert!(activated_at("127.0.0.1:7070", a("10.1.2.3:7070"), false).is_err());
        // An IPv4 wildcard takes no IPv6 connections; an IPv6 one IPv4 ones only without IPV6_V6ONLY.
        assert!(activated_at("[::1]:7070", wildcard, false).is_err());
        let v6 = a("[::]:7070");
        assert!(activated_at("[::1]:7070", v6, true).is_ok());
        assert!(activated_at("10.1.2.3:7070", v6, false).is_ok());
        assert!(activated_at("10.1.2.3:7070", v6, true).is_err());
        assert!(activated_at("[::ffff:10.1.2.3]:7070", wildcard, false).is_ok());
        // A mapped wildcard binds IPv4 only, whatever IPV6_V6ONLY says.
        let mapped = a("[::ffff:0.0.0.0]:7070");
        for v6only in [false, true] {
            assert!(activated_at("10.1.2.3:7070", mapped, v6only).is_ok());
            assert!(activated_at("[::1]:7070", mapped, v6only).is_err());
            assert!(!covers(mapped, v6only, &[a("[::1]:7070"), a("127.0.0.1:7070")]));
        }
        // A name's addresses must all be taken, not only one of them (#826).
        let both = [a("[::1]:7070"), a("127.0.0.1:7070")];
        assert!(!covers(a("127.0.0.1:7070"), false, &both));
        assert!(!covers(a("[::1]:7070"), false, &both));
        assert!(!covers(v6, true, &both));
        assert!(covers(v6, false, &both));
        let e = activated_at("10.1.2.3:7070", a("10.1.2.4:7070"), false).unwrap_err().to_string();
        assert!(e.contains("not on every address of 10.1.2.3:7070"), "{e}");
    }

    #[test]
    fn listener_configuration_is_published_only_after_binding_and_validation() {
        use std::net::TcpListener;
        let root = crate::test_util::TempDir::new("listen-config");
        let mut host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        host.configure(|c| {
            c.reserve_mib = Some(321);
            Ok(())
        })
        .unwrap();
        let before = std::fs::read(host.state.join("host.json")).unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = occupied.local_addr().unwrap().to_string();
        assert!(configure_listener(&mut host, Some(&addr), None).is_err());
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        // An activated socket supplies the endpoint even without ADDR; the settings stay.
        let listener = configure_listener(&mut host, None, Some(occupied)).unwrap();
        let saved = Host::open(&host.state, &host.run).unwrap();
        assert_eq!(saved.cfg.listen.as_deref(), Some(addr.as_str()));
        assert_eq!(saved.cfg.advertise().unwrap().as_deref(), Some(addr.as_str()));
        assert_eq!(saved.cfg.underlay(), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(saved.cfg.reserve_mib, Some(321));
        drop(listener);
        // A wildcard one's underlay is derived: loopback with no peers elsewhere, and
        // none with one whose address is unknown (never loopback): refused.
        let wildcard = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = wildcard.local_addr().unwrap().port();
        drop(configure_listener(&mut host, None, Some(wildcard)).unwrap());
        assert_eq!(host.cfg.advertise().unwrap(), Some(format!("127.0.0.1:{port}")));
        host.configure(|c| {
            c.peers = vec!["flexvm-no-such-host.invalid:7070".into()];
            Ok(())
        })
        .unwrap();
        let before = std::fs::read(host.state.join("host.json")).unwrap();
        let wildcard = TcpListener::bind("0.0.0.0:0").unwrap();
        assert!(configure_listener(&mut host, None, Some(wildcard)).unwrap_err().to_string().contains("underlay"));
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        // An ADDR other than the activated socket's is refused, saving nothing; its own is kept.
        let before = std::fs::read(host.state.join("host.json")).unwrap();
        let activated = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
        let e = configure_listener(&mut host, Some(&other), Some(activated)).unwrap_err().to_string();
        assert!(e.contains("the activated socket listens on 127.0.0.1:") && e.contains(&other), "{e}");
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        let activated = TcpListener::bind("127.0.0.1:0").unwrap();
        let own = activated.local_addr().unwrap().to_string();
        drop(configure_listener(&mut host, Some(&own), Some(activated)).unwrap());
        assert_eq!(host.cfg.listen.as_deref(), Some(own.as_str()));
        // An IPv6 listener needs no IPv4 underlay.
        if let Ok(v6) = TcpListener::bind("[::1]:0") {
            drop(configure_listener(&mut host, None, Some(v6)).unwrap());
        }
        // A name gets a socket on each of its addresses, and peers are told the name.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let name = format!("localhost:{port}");
        let want = resolve_listener(&name).unwrap();
        let (bound, _) = configure_listener(&mut host, Some(&name), None).unwrap();
        assert_eq!(bound.iter().map(|l| l.local_addr().unwrap()).collect::<Vec<_>>(), want);
        assert_eq!(host.cfg.listen.as_deref(), Some(name.as_str()));
        assert_eq!(host.cfg.advertise().unwrap().as_deref(), Some(name.as_str()));
        drop(bound);
        // Port 0 binds, but peers could not be told the port.
        for addr in ["127.0.0.1:0", "localhost:0"] {
            let before = std::fs::read(host.state.join("host.json")).unwrap();
            assert!(configure_listener(&mut host, Some(addr), None).is_err());
            assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
        }
        // A hostname is looked up within a bound, and one with no address saves nothing.
        let before = std::fs::read(host.state.join("host.json")).unwrap();
        let e = configure_listener(&mut host, Some("flexvm-no-such-host.invalid:7070"), None).unwrap_err().to_string();
        assert!(e.starts_with("listen address flexvm-no-such-host.invalid:7070: DNS lookup"), "{e}");
        assert_eq!(std::fs::read(host.state.join("host.json")).unwrap(), before);
    }

    #[test]
    fn kill_never_removes_a_stopped_vm_whose_name_something_else_holds() {
        let root = crate::test_util::TempDir::new("kill-held");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        // Held with no registry entry (a start whose resume then fails, a sweep, an `rm` deciding).
        let held = host.take_name("web", false).unwrap();
        let dir = host.suspended("web").unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.json"), b"{}").unwrap();
        std::fs::write(host.vms("web", "exited").unwrap(), b"{}").unwrap();
        let refused = remove(&host, "web", true, false).unwrap_err().to_string();
        assert!(refused.contains("is starting"), "{refused}");
        drop(held);
        // Let go of meanwhile: nothing was signalled, so nothing is undone.
        let refused = remove(&host, "web", true, false).unwrap_err().to_string();
        assert!(refused.contains("is not running"), "{refused}");
        assert!(dir.join("manifest.json").exists() && !dir.join("DISCARDED").exists());
        assert!(host.has_record("web", "exited"));
    }

    #[test]
    fn start_of_a_moved_vm_says_where_and_keeps_the_hint() {
        let root = crate::test_util::TempDir::new("start-moved");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        std::fs::write(host.vms("web", "moved").unwrap(), b"b:7070").unwrap();
        let args = parse(&["start", "web"]);
        assert_eq!(start(&host, &args, "web").unwrap_err().to_string(), "vm web moved to b:7070; it runs there");
        assert!(host.has_record("web", "moved"));
        assert_eq!(start(&host, &args, "nobody").unwrap_err().to_string(), r#"no vm named "nobody""#);
    }

    #[test]
    fn kill_refuses_a_committed_source_but_signals_a_reconciling_one() {
        use std::os::unix::process::ExitStatusExt;
        let root = crate::test_util::TempDir::new("kill-source");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let name = host.take_name("moving", false).unwrap();
        let mut child = std::process::Command::new("sleep");
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut child, || {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                Ok(())
            });
        }
        let mut child = crate::test_util::ChildGuard(child.arg("60").spawn().unwrap());
        let mut entry = host::Entry { name: "moving".into(), ident: host::Ident::of(child.id()).unwrap(), state: "source".into(), ..host::Entry::default() };
        // Hold the name on the child's behalf, with its identity in both records.
        std::fs::write(host.vms("moving", "lock").unwrap(), serde_json::to_vec(&entry.ident).unwrap()).unwrap();
        name.publish(&entry).unwrap();
        let refused = remove(&host, "moving", true, false).unwrap_err().to_string();
        assert_eq!(refused, "vm moving is the source of a migration in progress; it ends once the target has its memory (kill it where it runs)");
        assert!(child.try_wait().unwrap().is_none());
        entry.state = "reconciling".into();
        name.publish(&entry).unwrap();
        let result = remove(&host, "moving", true, false);
        // Reap even on failure, so a failed assertion does not leave the child behind.
        let _ = child.kill();
        let status = child.wait().unwrap();
        result.unwrap();
        assert_eq!(status.signal(), Some(libc::SIGINT));
        drop(name);
    }

    fn frames(fs: &[(u8, &[u8])]) -> Vec<u8> {
        fs.iter().flat_map(|(kind, data)| [&[*kind][..], &(data.len() as u32).to_le_bytes(), data].concat()).collect()
    }

    #[derive(Debug)]
    struct ExecInput {
        bytes: std::io::Cursor<Vec<u8>>,
        reads: usize,
        timeouts: std::cell::RefCell<Vec<Duration>>,
    }

    impl ExecInput {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes: std::io::Cursor::new(bytes), reads: 0, timeouts: Default::default() }
        }
    }

    impl Read for ExecInput {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            self.bytes.read(buf)
        }
    }

    impl util::Timed for ExecInput {
        fn read_timeout(&self, t: Duration) -> std::io::Result<()> {
            self.timeouts.borrow_mut().push(t);
            Ok(())
        }
        fn write_timeout(&self, _: Duration) -> std::io::Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn exec_reply_keeps_buffered_frames_and_switches_timeouts() {
        let session = Mutex::new(Session { id: "test-id".into(), started: false, offset: 0, exit: None });
        let data = frames(&[
            (guest::FRAME_MSG, b"test-id"),
            (guest::FRAME_STDOUT, &[&0u64.to_le_bytes()[..], b"hello"].concat()),
            (guest::FRAME_EXIT, &[&5u64.to_le_bytes()[..], &7i32.to_le_bytes()].concat()),
        ]);
        let input = ExecInput::new([b"{\"ok\":true}\n", data.as_slice()].concat());
        let mut r = exec_stream(input, Instant::now() + Duration::from_secs(1)).unwrap();
        assert!(r.buffer().len() < READ_AHEAD && data.starts_with(r.buffer()), "read ahead: {:?}", r.buffer());
        assert_eq!(r.get_ref().timeouts.borrow().last(), Some(&Duration::from_secs(3)));
        let mut stdout = Vec::new();
        let result = exec_frames(&mut r, &session, &mut stdout, &mut Vec::new(), &mut Instant::now(), None).unwrap();
        assert!(matches!(result, StreamEnd::Exit(7)));
        assert_eq!(stdout, b"hello");
    }

    /// #1047: a client blocked writing out output must not have read its exit already: the relay takes an
    /// empty socket queue (SIOCOUTQ) for the client having taken the exit, after all before it.
    #[test]
    fn exec_frames_are_not_read_ahead_past_a_header() {
        let (relay, client) = std::os::unix::net::UnixStream::pair().unwrap();
        let exit = guest::frame(guest::FRAME_EXIT, &[&5u64.to_le_bytes()[..], &0i32.to_le_bytes()]);
        let small = frames(&[(guest::FRAME_MSG, b"id"), (guest::FRAME_MSG, b"waiting")]);
        (&relay)
            .write_all(&[b"{\"ok\":true}\n", &small[..], &guest::frame(guest::FRAME_STDOUT, &[&0u64.to_le_bytes()[..], b"hello"]), &exit].concat())
            .unwrap();
        let mut r = exec_stream(&client, Instant::now() + Duration::from_secs(1)).unwrap();
        for _ in 0..3 {
            guest::read_frame(&mut r).unwrap().unwrap();
        }
        // The client is where it would write out "hello": its exit is still queued, all but a few bytes.
        let mut queued: libc::c_int = 0;
        assert_eq!(unsafe { libc::ioctl(relay.as_raw_fd(), libc::TIOCOUTQ as _, &mut queued) }, 0);
        assert!(queued as usize > exit.len() - READ_AHEAD, "{queued} of the exit's {} bytes queued", exit.len());
        assert_eq!(guest::read_frame(&mut r).unwrap().unwrap().0, guest::FRAME_EXIT);
    }

    #[test]
    fn exec_reply_obeys_deadline_and_reports_refusals() {
        let err = exec_stream(ExecInput::new(Vec::new()), Instant::now()).unwrap_err();
        assert!(err.to_string().contains("deadline passed"));
        let input = ExecInput::new(b"{\"ok\":false,\"error\":\"refused\"}\n".to_vec());
        assert_eq!(exec_stream(input, Instant::now() + Duration::from_secs(1)).unwrap_err().to_string(), "refused");
    }

    #[test]
    fn started_session_fails_promptly_when_vm_is_gone() {
        let root = crate::test_util::TempDir::new("exec-dead");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let session = Mutex::new(Session { id: "test-id".into(), started: true, offset: 0, exit: None });
        let start = Instant::now();
        let error = exec_session(&host, "gone", "true", &session, false).unwrap_err();
        assert!(!error.to_string().contains("recovery timed out"), "{error}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_separate_client_finds_its_vm_under_its_new_name() {
        let root = crate::test_util::TempDir::new("exec-renamed");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let l = host.lock().unwrap();
        let c = host.claim_new(&l, "old", None).unwrap();
        let vm = Instance { ip: c.ip, gen: c.gen };
        assert_eq!(Pin::default().name(&host, "old"), "old", "not pinned yet: as given");
        let mut pin = Pin { vm: Some(vm), ..Pin::default() };
        assert_eq!(pin.name(&host, "old"), "old");
        host.rename_holder(&l, c.ip, "old", "new", None).unwrap();
        assert_eq!(pin.name(&host, "old"), "new");
        // Ended, its claim let go: its records are still under the name it had last.
        host.release(&l, c.ip, "new", None).unwrap();
        assert_eq!(host.holder_of(c.ip, c.gen), None);
        assert_eq!(pin.name(&host, "old"), "new");
        // Another generation of the address is not it: the name as given (and connect_same refuses another VM).
        assert_eq!(Pin { vm: Some(Instance { gen: c.gen + 1, ..vm }), ..Pin::default() }.name(&host, "old"), "old");
        c.keep();
    }

    #[test]
    fn recovery_refuses_a_vm_made_again_under_the_name() {
        let ip = "10.0.0.2".parse().unwrap();
        let mut vm = None;
        same_instance("web", Instance { ip, gen: 7 }, &mut vm).unwrap();
        // A suspend and resume, or a migration, keeps the address's generation.
        same_instance("web", Instance { ip, gen: 7 }, &mut vm).unwrap();
        let e = same_instance("web", Instance { ip, gen: 8 }, &mut vm).unwrap_err();
        assert!(e.is::<Replaced>() && e.to_string().contains("generation 7, now 10.0.0.2 generation 8"), "{e}");
        assert!(same_instance("web", Instance { ip: "10.0.0.3".parse().unwrap(), gen: 7 }, &mut vm).unwrap_err().is::<Replaced>());
        assert_eq!(vm, Some(Instance { ip, gen: 7 }), "the first stays");
    }

    #[test]
    fn resume_times_out_while_suspending() {
        let root = crate::test_util::TempDir::new("resume-timeout");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let _name = host.take_name("own", false).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(host.sock("own").unwrap()).unwrap();
        let server = std::thread::spawn(move || {
            let mut conn = listener.accept().unwrap().0;
            assert_eq!(recv_json(&mut BufReader::new(&mut conn)).unwrap().unwrap()["op"], "resume");
            util::send_json(&mut conn, &json!({"ok": true, "result": {"suspending": true}})).unwrap();
        });
        let error = resume_by(&host, "own", Instant::now() + Duration::from_secs(30), Instant::now()).unwrap_err().to_string();
        server.join().unwrap();
        assert!(error.contains("timed out waiting for suspend"), "{error}");
        assert!(error.contains("retry when it finishes") && error.contains("log"), "{error}");
    }

    #[test]
    fn a_vm_whose_registry_entry_is_not_its_listeners_is_not_sent_the_request() {
        use std::io::BufRead;
        use std::os::unix::net::UnixListener;
        let root = crate::test_util::TempDir::new("exec-same");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let _name = host.take_name("own", false).unwrap();
        let l = UnixListener::bind(host.sock("own").unwrap()).unwrap();
        // This process listens: a VM's own main command, sent without a check.
        let mut vm = Pin::default();
        let c = connect_same(&host, "own", &json!({"op": "x"}), Instant::now() + Duration::from_secs(5), &mut vm).unwrap();
        assert_eq!(util::peer_pid(&c).unwrap(), std::process::id());
        let mut line = String::new();
        BufReader::new(l.accept().unwrap().0).read_line(&mut line).unwrap();
        assert_eq!(line, "{\"op\":\"x\"}\n");
        assert_eq!((vm.vm, vm.process), (None, None));
    }

    #[test]
    fn resumes_partial_frame_without_duplicates() {
        let at = |o: u64, d: &[u8]| [&o.to_le_bytes()[..], d].concat();
        let mut first = frames(&[(guest::FRAME_MSG, b"test-id"), (guest::FRAME_STDOUT, &at(0, b"abc"))]);
        first.extend_from_slice(&[guest::FRAME_STDERR, 11, 0, 0, 0]);
        first.extend_from_slice(&at(3, b"d"));
        let session = Mutex::new(Session { id: "test-id".into(), started: false, offset: 0, exit: None });
        let (mut stdout, mut stderr, mut deadline) = (Vec::new(), Vec::new(), Instant::now());
        let mut run = |input: Vec<u8>| exec_frames(&mut input.as_slice(), &session, &mut stdout, &mut stderr, &mut deadline, None).unwrap();
        assert!(matches!(run(first), StreamEnd::Disconnected(_)));
        let resumed = frames(&[
            (guest::FRAME_MSG, b"test-id"),
            (guest::FRAME_STDERR, &at(3, b"def")),
            (guest::FRAME_EXIT, &[&6u64.to_le_bytes()[..], &7i32.to_le_bytes()].concat()),
        ]);
        assert!(matches!(run(resumed), StreamEnd::Exit(7)));
        let s = session.lock().unwrap();
        assert!(s.started && s.offset == 6 && s.exit == Some(7) && stdout == b"abc" && stderr == b"def");
    }

    #[test]
    fn a_reattach_to_a_closed_session_ends_at_once() {
        let session = Mutex::new(Session { id: "test-id".into(), started: true, offset: 5, exit: None });
        // Within one attachment, a closed session is only a lost connection, retried.
        let input = frames(&[(guest::FRAME_MSG, b"test-id"), (guest::FRAME_MSG, b"error: session closed")]);
        let end = exec_frames(&mut input.as_slice(), &session, &mut Vec::new(), &mut Vec::new(), &mut Instant::now(), None).unwrap();
        assert!(matches!(end, StreamEnd::Disconnected(_)));
        let input = frames(&[(guest::FRAME_MSG, b"error: session closed")]);
        let e = exec_frames(&mut input.as_slice(), &session, &mut Vec::new(), &mut Vec::new(), &mut Instant::now(), None).err().unwrap();
        assert!(e.to_string().contains("after byte 5 of output"), "{e}");
    }

    #[test]
    fn detached_exec_retries_busy_then_returns_on_start_without_an_exit_frame() {
        use std::os::unix::net::UnixListener;
        let root = crate::test_util::TempDir::new("exec-detached");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let _name = host.take_name("own", false).unwrap();
        let listener = UnixListener::bind(host.sock("own").unwrap()).unwrap();
        let cmd = json!({"argv": ["sleep", "100"], "detach": true});
        let expected = cmd.clone();
        let server = std::thread::spawn(move || {
            for busy in [true, false] {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let req = recv_json(&mut BufReader::new(&stream)).unwrap().unwrap();
                assert_eq!(req["cmd"], expected);
                assert_eq!(req["action"], "start");
                util::send_json(&mut stream, &json!({"ok": true})).unwrap();
                let msg = if busy { format!("error: busy{}", guest::TRY_AGAIN) } else { req["session"].as_str().unwrap().to_owned() };
                guest::write_frame(&mut stream, guest::FRAME_MSG, msg.as_bytes()).unwrap();
            }
        });
        let session = Mutex::new(Session::new().unwrap());
        assert_eq!(exec_request(&host, "own", &cmd, &session, false, &mut std::io::stdout(), None, &Mutex::default()).unwrap(), 0);
        server.join().unwrap();
        assert!(!session.lock().unwrap().started);
    }

    #[test]
    fn a_busy_agent_is_asked_again_and_other_refusals_are_final() {
        let session = Mutex::new(Session { id: "test-id".into(), started: false, offset: 0, exit: None });
        // As flexvm-init words it when all its body readers are taken.
        let busy = format!("error: too many commands arriving at once{}", guest::TRY_AGAIN);
        let input = frames(&[(guest::FRAME_MSG, busy.as_bytes())]);
        let end = exec_frames(&mut input.as_slice(), &session, &mut Vec::new(), &mut Vec::new(), &mut Instant::now(), None).unwrap();
        assert!(matches!(end, StreamEnd::Disconnected(ref why) if *why == busy));
        // Never taken by the guest, so the retry starts it again.
        assert!(!session.lock().unwrap().started);
        let input = frames(&[(guest::FRAME_MSG, b"error: too many sessions: 64 commands are running or awaiting their client")]);
        assert!(exec_frames(&mut input.as_slice(), &session, &mut Vec::new(), &mut Vec::new(), &mut Instant::now(), None).is_err());
    }

    #[test]
    fn a_command_that_cannot_run_exits_with_its_status() {
        for code in [126, 127] {
            let session = Mutex::new(Session { id: "test-id".into(), started: false, offset: 0, exit: None });
            let refusal = format!("error: cannot run nope: No such file or directory (os error 2){}{code}", guest::EXIT_STATUS);
            let input = frames(&[(guest::FRAME_MSG, refusal.as_bytes())]);
            let mut stderr = Vec::new();
            let end = exec_frames(&mut input.as_slice(), &session, &mut Vec::new(), &mut stderr, &mut Instant::now(), None).unwrap();
            assert!(matches!(end, StreamEnd::Exit(c) if c == code));
            assert_eq!(session.lock().unwrap().exit, Some(code));
            assert_eq!(String::from_utf8(stderr).unwrap(), "flexvm: cannot run nope: No such file or directory (os error 2)\n");
        }
    }

    #[test]
    fn exec_needs_an_absolute_workdir() {
        let e = exec_command(&parse(&["exec", "-w", "srv", "vm", "true"])).unwrap_err();
        assert!(e.to_string().contains("absolute"), "{e}");
    }

    #[test]
    fn an_oversized_command_fails_before_any_request() {
        let session = Mutex::new(Session { id: "test-id".into(), started: false, offset: 0, exit: None });
        let root = crate::test_util::TempDir::new("exec-oversized");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let start = Instant::now();
        let e = exec_session(&host, "vm", &"x".repeat(guest::MAX_BODY + 1), &session, false).unwrap_err();
        assert!(e.to_string().contains("the guest takes at most"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn an_agent_without_sessions_says_to_rebuild() {
        let session = Mutex::new(Session { id: "test-id".into(), started: false, offset: 0, exit: None });
        let input = frames(&[(guest::FRAME_MSG, b"unknown request \"SESSION\"")]);
        let e = exec_frames(&mut input.as_slice(), &session, &mut Vec::new(), &mut Vec::new(), &mut Instant::now(), None).err().unwrap();
        assert_eq!(e.to_string(), "unknown request \"SESSION\"; rebuild the rootfs and its templates");
    }
}

#[cfg(test)]
mod test_util;
