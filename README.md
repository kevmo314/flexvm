# flexvm

Elastic Firecracker microVMs. By default, a VM sees the host's CPUs, capped at
32 and rounded down to even (1 on a single-CPU host), and a memory ceiling of
host RAM, but only uses what it touches. It starts in about 5 ms, pauses,
checkpoints and suspends to disk, and live-migrates to another host
(post-copy) in tens of milliseconds, keeping its address and TCP connections.

There is no daemon. `flexvm run` starts a process that *is* the VM: kill the
process and the VM is gone, send it a signal and the VM pauses or suspends.

## Setup

Everything flexvm keeps lives in its state directory, `/var/lib/flexvm`: the
artifacts (`artifacts/`), templates (`templates/`), pulled images
(`images/`), VMs and the host's configuration (`host.json`). To build a
binary with another default, set `FLEXVM_STATE_DIR` to an absolute path when
building (`FLEXVM_STATE_DIR=/srv/flexvm cargo build --release`); `--state`
still overrides it at run time. This README writes `/var/lib/flexvm` for
whichever default the binary was built with, except in the run-path rules
below. The test and lab scripts
(`e2e.py`, `faults.py`, `test-image.py`, `netlab.sh`, `nettest.sh`, `fetch.sh`,
`build-firecracker.sh`) take `FLEXVM_STATE_DIR` from the environment too;
`fetch.sh` and `build-firecracker.sh` also take `--state`, which overrides it.

Each state directory is bound to one canonical run directory on first open:
`STATE/run.json` records its run path, and `RUN/state.json` records its state.
Using either with a different partner is refused, including after a reboot.
Without `--run`, the run path follows from the state's path alone:
`/run/flexvm` for the literal `/var/lib/flexvm`, and `/run/flexvm-PREFIX`
(its tap prefix) for any other state. A state bound to a different run path
must be given that `--run`. `/run/flexvm` belongs to `/var/lib/flexvm` alone,
whatever default the binary was built with; any other state is refused it,
even with `--run`. A binary built with another default therefore uses
`/run/flexvm-PREFIX`, while an existing `/var/lib/flexvm` keeps working with
`--state /var/lib/flexvm`, so both can be used side by side.

```sh
cargo build --release && sudo install target/release/flexvm /usr/local/bin/
sudo flexvm pull ubuntu:24.04    # pull an image; its template is a cold boot of it, snapshotted (needs e2fsprogs)
sudo flexvm run ubuntu:24.04 uname -a   # a VM of it (pulled first if missing), in the foreground: runs
                                       # the command and exits with it
```

flexvm-init (the guest's PID 1 and agent) is built by the same `cargo build`
and embedded in the binary. The patched Firecracker and the guest kernel are
prebuilt: the first command that needs them downloads them into
`artifacts/` from the release this build pins (`ARTIFACTS_TAG` in
`scripts/versions.sh`) and checks them against the sha256 pinned in
`scripts/checksums.sha256`. A file already there is never downloaded or
replaced, and a build that pins it accepts only the pinned file, also when a
VM starts: anything else is refused, never run (a corrupted or replaced
download, a copy cut short, an older release's after an upgrade, one built
here). Remove such a file to download the pinned one, and pull the templates
built with it again. A build that pins no release (between a release's tag and
its pin) goes by the record instead: `NAME.sha256` beside the file holds the
sha256 of a file that flexvm downloaded, or that the scripts below built or
fetched and verified. Copying artifacts to another host takes the `.sha256`
files along.

For a host without network access, put the files in `artifacts/` first (the
scripts install with sudo; give them `--state DIR` for another state
directory, then copy it over). A Firecracker built here runs only with a build
pinning no release, as after a change to the patches (which bumps
`ARTIFACTS_TAG`, see [Releasing the artifacts](#releasing-the-artifacts)):

```sh
./scripts/build-firecracker.sh   # patched firecracker (needs musl-tools, libseccomp-dev)
./scripts/fetch.sh               # guest kernel, the pinned release's firecracker (else a recorded build, else the stock one), and the tests' base rootfs
```

`FLEXVM_ARTIFACTS_URL` points the download at a mirror of the release (the
same pins apply). How a release is cut: [Releasing the
artifacts](#releasing-the-artifacts).

The host needs Linux 5.16+: Firecracker patch `0004` uses `KVM_VCPU_TSC_OFFSET`.

Hosts that migrate or restore each other's VMs need the same CPU model and
a byte-identical Firecracker: a snapshot records both (the binary by its
content hash), and any difference refuses it ("Firecracker differs"). Builds
pinning the same release download the same binary; a Firecracker of your own (for a build pinning none)
is built once and copied to every host (`/var/lib/flexvm/artifacts`) rather than
built on each. Replacing the binary also invalidates every template
built with the old one: pull them again. Templates themselves must be identical
too (pull once and copy `/var/lib/flexvm/templates` and `images/rootfs`, or pull
the same image by digest with the same options). A template pins its image's
root filesystem by path, so one pulled into another state directory must be
pulled again.

flexvm runs as root (KVM, userfaultfd, routes, cgroups); commands below
assume that.

### Releasing the artifacts

Releases use semver tags `vMAJOR.MINOR.PATCH`: `artifacts-5` was the last
`artifacts-N` release, and `v0.1.0` the first source release (whose
Firecracker came from `artifacts-1`), so the first semver artifacts release is
`v0.2.0`. The version in `flexvm/Cargo.toml` and `guest/Cargo.toml` is the tag
without its `v` (`scripts/pin-artifacts.sh --check` fails otherwise).
A release (`ARTIFACTS_TAG` in `scripts/versions.sh`) is built from what
`scripts/pin-artifacts.sh --inputs` lists: Firecracker's version, the commit
its tag names (`FC_COMMIT`; the build refuses any other), the patches, the
recipe (`.github/workflows/release.yml` and the scripts it runs:
`scripts/release-assets.sh`, `scripts/build-firecracker.sh`,
`scripts/fetch.sh`, and their shared `scripts/versions.sh`) and the kernel. That list is
the release's `inputs.txt`, and its assets never change. So a change to any
of those inputs bumps `ARTIFACTS_TAG` in the same pull request; CI fails it
otherwise. Then:

1. Merge it. Main now names a pending tag: flexvm builds from it download
   nothing until step 3 (build.rs warns), and CI warns.
2. Push the tag at that commit on main:
   `git tag vX.Y.Z <commit> && git push origin vX.Y.Z`, with the
   `ARTIFACTS_TAG` it names.
   `.github/workflows/release.yml` checks that `versions.sh` there names it,
   builds the assets with `scripts/release-assets.sh` in a read-only job
   (Firecracker uses `cargo build --locked`). A separate job downloads that
   job's uploaded artifact, attests the three assets and publishes them;
   only it has write and signing permissions.
3. Run `scripts/pin-artifacts.sh` on main once the release exists. It checks
   that the tag's commit is in your history, verifies the attestations
   (release.yml at that tag and commit, on a GitHub-hosted runner), and checks
   that `inputs.txt` matches the checkout. It then writes the three pins to
   `scripts/checksums.sha256` by atomic replacement. Merge that commit.

`fetch.sh` falls back to upstream assets only when their release pins are
absent. A malformed or duplicate pin fails instead; `fetch.sh` and
`pin-artifacts.sh` share the validator in `versions.sh`.

CI's "Pinned artifacts release" check fails any change whose inputs differ
from the pinned release's, or from those at the commit a pending tag names if it is
tagged already. It also fails if the tag can't be looked up. A pending tag is a
warning on pull requests. On main (pushes and the nightly run) it is an error
once more than 24 hours (`RELEASE_WINDOW_HOURS`) have passed since the tag
was named on main (first-parent history: when the pull request merged). The
release flow never fails CI: the bump merges with a warning, the tag push
runs only release.yml, and the pin commit matches.

## Run a VM

The commands follow Docker's where they can. There is no daemon: `run` is
the VM's process, and the other commands find VMs by name in the state
directory.

```sh
flexvm run nginx:1.27                        # foreground: the app's output here, Ctrl-Z pauses, Ctrl-C destroys
flexvm run -d --name web nginx:1.27          # in the background; prints {"name", "ip", "pid", ...} once it runs
flexvm run --name job ubuntu:24.04 make test # runs one command; exits with its status, the VM goes with it
flexvm run -d --ip 10.200.0.9 --cpus 2 --memory 8g nginx:1.27
flexvm run -d -e PORT=8080 --env-file app.env --entrypoint "python3 -m http.server" python:3.12
flexvm run -d --keep busybox                 # stays up once its app exits, for exec
```

A VM follows its image's app (its entrypoint and command), as a container
does: when the app exits, the VM exits with the app's status. In the
foreground `run` returns that status. With `-d` the VM becomes an `exited`
record: `ps -a` lists it with its status, its output stays in its log, `rm`
removes it and `start` runs it again. `--rm` leaves no record (its log goes
at a sweep once unwritten for an hour). `--keep` keeps the VM up once its
app exits, to `exec` into. An image with no entrypoint and no command has no app: its VMs idle
until told what to run (`exec`, `run IMAGE CMD`), and so does
`run -d IMAGE sleep infinity`. With CMD, the VM follows CMD instead (the
image's app, if any, still starts, but its exit does not end the VM). When the
app exits within about a second and stdin is not a terminal, `run` says
`bash exited at once (it needs a terminal?): use flexvm run -it ubuntu:24.04`:
a shell with no terminal reads end-of-file and exits.

```sh
flexvm run -d --restart on-failure:5 --name worker myjob:1   # run again when it fails, at most 5 times
flexvm run -d --restart always --name web nginx:1.27         # run again whenever it exits, and after a reboot
```

`--restart POLICY` (with `-d`) runs a background VM again when its app (or
CMD) exits, as docker's restart policies do: `always`; `unless-stopped`
(the same, but after a reboot only if it was not stopped); `on-failure`
(on a status other than 0), `on-failure:N` at most N times; `no`, the
default. It runs again from its image, as `start` of an exited VM does,
after a backoff of 100 ms that doubles with each restart up to a minute,
and starts from 100 ms again once its app ran 10 s. Meanwhile `ps -a`
lists it `exited (STATUS), restarting`; `inspect` shows its policy, its
count and its last backoff under `config.run.restart`. There is no daemon:
the exiting VM's process leaves a worker of its own behind (in its own
session and cgroup, as a VM process is) that waits out the backoff and
starts it. A `stop` (also of one waiting to restart), `kill`, `rm`,
`rename` or another `start` of it meanwhile ends that: a VM asked to stop
is not run again, and `start` by hand begins its count again. A start that
fails (its image removed, the host short of memory) is tried again with a
growing backoff while it waits. A VM with a policy keeps what runs it again
in the state directory too (`STATE/restart/NAME.json`), so the first full
recovery after a reboot (see [Under systemd](#under-systemd); any command
run as root does it) runs again those the reboot lost (as lost: status 124),
and starts `always`'s stopped ones, as docker does when its daemon starts.
A VM that fails (its Firecracker dies) is not restarted: its `failed`
record stays for a post-mortem. `--restart` conflicts with `--rm`.

`-e K=V` (again for more; a bare `-e K` takes `K` from this environment, and
is left out if it has none), `--env-file FILE` (Docker's form: `K=V` lines,
`#` comments; `-e` wins over it) and `--entrypoint CMD` (words, or a JSON
array; it drops the image's command too, as in Docker) set the app's
environment and program for this run, as `pull`'s options do for every run.
The guest's agent applies them as it starts the app, so a standby VM's claim
carries them; a `--warm` image's app is running already in its snapshot, so
it refuses them. They stay with the VM through `stop`/`start` and migrations.

`run` pulls an image it does not find here first, as `docker run` does.
Without `--name` it makes one up (`epic_yalow`, as Docker does; one
another run takes meanwhile is made up again); the
JSON `-d` prints, and `flexvm ps`, give it. The options go before the image:
every word after it is the command.

`--cpus N` caps the VM's CPU time at N CPUs (`1.5`: one and a half; a
`cpu.max` quota on its Firecracker's cgroup, set before the VM runs); it
still has its image's vCPUs. A host without the cgroup cpu controller refuses
a start (or an arrival) with `--cpus` rather than run it uncapped.
`-m` / `--memory SIZE` (`512m`, `2g`; a plain number is bytes, as in Docker) caps
how far the VM grows: from its image's boot memory plus what its snapshot
plugged (a VM never shrinks below that) up to the image's ceiling. A value
outside that is refused, saying the range. vCPU count and boot memory are
fixed in the snapshot, so they are pull options (see Images). Both caps stay
with the VM through `stop`/`start`, checkpoints and migrations; `run
--checkpoint` with either sets that one anew.

```sh
flexvm ps                       # running VMs; -a: stopped ones too; --json: all of it
NAME                     IP              IMAGE            STATE             PID  CPUS  RSS MiB  MAX MiB STARVED PORTS
web                      10.200.0.1      nginx:1.27       running         41522     2       27     8192
flexvm ps -q                    # names only
flexvm ps --filter name=web --filter status=paused   # both; a key again: either value
flexvm ps --format '{{.Name}}\t{{.IP}}'               # a Go-template subset; 'table ...': a header, aligned
flexvm ps --format json         # an object per line, as docker's
flexvm inspect web db           # a JSON array: per VM, what ps --json says and its config
```

`-f` / `--filter` keys are `name` (a part of it, as docker's), `status` (a state
below, as `exited`, or `stopped` for any no process runs; a status filter
lists stopped and exited VMs without `-a`), `image` (as `pull` took it, or its template name)
and `ip`. `--format` fields are `.Name`, `.IP`, `.Image`, `.State` (or
`.Status`), `.PID`, `.CPUs`, `.VCPUs`, `.RSS`, `.MaxMiB`, `.Starved`,
`.Template`, `.TemplateID` and `.Error`, any case; `{{json .}}` is the whole
object; `\t` and `\n` are a tab and a newline. `inspect` adds `config` to
what `ps --json` says of each VM: its image, template and the image's app,
caps, ports (`ports`), run settings (`run`: `-e`, `--entrypoint`, `--keep`,
`--rm`, `--ip`, `-p`, `-i` as `stdin`, `-t` as `tty`), its log, and its control socket (running) or checkpoint
directory (stopped); a stopped or exited one has its `exit_code` too. A name that is not a VM
fails `inspect` once the others are printed. A corrupt suspended manifest stays visible
as `suspended`; a corrupt record with a live name lock stays visible as `unknown`.
Both carry an `error` in `ps --json` and `inspect`.

| state | meaning |
|---|---|
| `running` | its vCPUs run |
| `paused` | stopped by `flexvm pause`, SIGTSTP or Ctrl-Z (or held by `run --checkpoint --paused`); `flexvm unpause` resumes it |
| `checkpointing` | paused to save a checkpoint; without `--stop`, returns to `running` for the page copy |
| `suspending` | suspending to disk (`flexvm stop`, SIGTERM); the process exits once the copy is complete |
| `source` | migrating away: paused here until the target has its memory |
| `reconciling` | migration outcome unknown: paused here while asking the target whether it committed |
| `suspended` | stopped: on disk, no process (`flexvm stop`, SIGTERM); `flexvm start` brings it back |
| `quarantined` | a stopped VM that cannot be started (its address generation is unknown); `run --checkpoint` its directory with a new name and `--ip auto`, or `flexvm rm` it |
| `exited` | its app (or CMD) exited in the background, with the status `ps` shows; `flexvm start` runs it again, `flexvm rm` removes it |
| `failed` | died under its process (exit 124); `ps -a --json` (or `/run/flexvm/vms/NAME.failed`) gives the reason and Firecracker's post-mortem summary (last lines, plus the start of a guest crash report); `flexvm logs NAME` has the full tail (up to 64 KiB), until `flexvm rm` |
| `lost` | ran here when the host went down, recorded during post-reboot recovery; its address is withdrawn, until `flexvm rm` |

The last five are stopped: `ps` lists them with `-a`. Standby VMs are not
listed: `flexvm images` shows their configured count in `STANDBY`.

```sh
flexvm exec web free -m        # argv passed as-is; exits with the command's status
flexvm exec web sh -c 'free -m; echo done'  # explicitly request a shell
flexvm exec -d -e MODE=worker -w /srv -u app:staff web ./worker
```

`exec [OPTIONS] NAME CMD...` preserves each argument, including spaces and empty
arguments. Options go before NAME: `-d` / `--detach` starts the command and returns
0 without output; `-e` / `--env K[=V]` is repeatable; a bare key takes its
value from this environment and is left out if unset; `-w` / `--workdir DIR` and
`-u` / `--user USER[:GROUP]` override the run's effective config for this command.
Users and groups are resolved inside the guest as `pull` resolves the image's
`User` (a numeric uid or gid need no entry; supplementary groups only without an
explicit group), and `-u` sets `HOME` to that user's. Exec otherwise runs as the
run's user, with its environment (including `run -e`) and working directory.
Use `sh -c '...'` for pipelines, redirects and shell syntax.

```sh
flexvm exec -it web bash                   # a shell on a pty; Ctrl-P Ctrl-Q detaches, leaving it running
tar -c data | flexvm exec -i web tar -x -C /srv   # -i: stdin, to its EOF
flexvm run -it ubuntu:24.04                # the image's app (bash) on this terminal; the VM exits with it
flexvm run -it busybox sh                  # with -i or -t, CMD is the app (its argv, as docker's)
flexvm run -d -it --name dev ubuntu:24.04 && flexvm attach dev
flexvm cp ./site web:/srv                  # and web:/var/log/app.log ., or - for a tar on stdin/stdout
```

`-i` sends stdin to the command (or with `run`, keeps the app's stdin open, for
this run or a later `attach`); `-t` runs it on a pty in the guest, with this
terminal raw (keys, Ctrl-C and Ctrl-Z too, go to the guest; restored however
flexvm ends) and its size followed. As with docker, `-it` needs a terminal.
Stdin survives what exec does: a pause, a checkpoint, an aborted migration
reconnect it, and the guest takes each byte once, as numbered. A stop or a
migration ends the client (the app keeps its stdin: `attach` again after `start`,
or on the target). `attach NAME` shows the app's output from then on; it also
feeds the app's stdin when the app's stdin is open (`run -i`). `cp` streams a tar through flexvm-init (images need
no `tar`): guest paths are resolved in the guest, files land there as root, and
what comes out is unpacked without following its links, setuid bits or devices.
A DST that is itself a link is followed only if root or the user unpacking (on
the host, the user flexvm runs as) made it, as a merged /usr's /bin: one someone
else planted is refused; give its target instead.
A copy stays on its source's filesystem: `cp web:/ -` has /proc, /sys and /dev
as empty directories.

As with ssh, the words of `run IMAGE CMD` are joined with spaces for the guest's
shell, so quote a command that has its own quoting:
`flexvm run ubuntu:24.04 "sh -c 'echo -d'"`. Flags after IMAGE (or after `exec NAME`)
belong to CMD; a `--` there is dropped.

A background VM's output (an image app's stdout and stderr, flexvm's own
messages) goes to `/run/flexvm/vms/web.log` (a link into `web.logs/`). Logs live on tmpfs: past
8 MiB, `NAME.log` becomes `NAME.log.1` (replacing the one before) and a new
one is started; the logs of a name with nothing left on
the host (no VM, stopped VM, `exited`, `failed`, `lost` or moved record) are removed once
unwritten for an hour, by sweeps that run when a VM starts and about every
30 s while a listener or any VM process runs. Logs do not survive a reboot.

```sh
flexvm logs web                 # its log: NAME.log.1 (before the last rotation), then NAME.log
flexvm logs -n 20 web           # the last 20 lines
flexvm logs -f web              # and follow it, until the VM exits, is removed or renamed
```

`-n` / `--tail N` selects the last N lines. Short switches can be bundled
(for example, `ps -aq` or `logs -fn 20 web`).

`logs -f` reads on across rotations (it finishes the rotated log, then
starts on the new one) and restarts (a VM started again appends to its log);
it ends once the VM exits, is removed or is renamed (`logs -f` of the new
name follows it there), or its reader is gone. An exited
VM's log stays available to read until `rm`. `rm` (including `rm -f` of a
running VM) deletes both `NAME.log` and `NAME.log.1`, as `docker rm` does, so a
new VM with the same name starts with a fresh log. For a post-mortem, read
`logs` before `rm`, or `kill` first: `kill` keeps the log (with what the VM
wrote as it ended) until `rm`, the name's next VM (which starts a fresh
log), or the sweep of a log unwritten for an hour. A foreground `run -i`/`-t`
leaves its log too. A foreground VM's output is its terminal's, so its log
holds only what came after a closed terminal. Foreground `run`,
`start -a` and `attach` print only the app's output, errors and warnings;
flexvm's and flexvm-init's informational messages go to the log alone, and
also to stderr with the global `--verbose` (`-v`) or `FLEXVM_LOG=debug`.
After `run`, `-v` is docker's volume flag, which flexvm refuses (volumes are
not supported yet, #717): put `-v` before the command (`flexvm -v run ...`).

After `run`, `-h` is Docker's hostname flag and is refused: use `--name`
to set the VM's name and hostname, and `--help` for help.

The guest's hostname is the VM's name (`root@web` in a shell's prompt), with
an /etc/hosts entry for it; a rename sets it in the guest too. Templates pulled
before this need pulling again for it.

## Forward host ports

```sh
flexvm run -d --name web -p 8080:80 -p 127.0.0.1:5353:53/udp ubuntu:24.04 sleep infinity
```

`run -p [IP:]HOST_PORT:VM_PORT[/tcp|/udp]` forwards a host port to
its VM's address. Repeat `-p` for more ports. IP is IPv4 or bracketed IPv6
(`-p '[::1]:8080:80'`). With none, it binds both `0.0.0.0` and `[::]`, as
Docker does, or IPv4 alone on a host without IPv6. The default protocol is TCP.
Ports must be 1–65535. A port already bound by an application or another
VM is refused at `run`, before anything starts, including overlapping
wildcard binds; TCP and UDP can use the same number. `ps` shows a PORTS
column; `ps --json` and `run -d` return `ports` objects with `ip`, `host_port`, `vm_port`, and `protocol`, one per bound address.

These are single-host userspace proxies in the VM process. The guest sees
the host as the client. Each mapping uses one thread, with up to 256 TCP
connections or UDP client sessions; UDP sessions expire after 60 idle
seconds. At the TCP cap, a new client can replace the connection idle
longest if it has been idle for at least 60 seconds. TCP buffers are bounded
and support half-close. Killing or removing the VM closes its listeners and
resets (RST) TCP connections not yet finished, so a cut-off stream never
reads as a clean end. Process death closes them in the kernel immediately,
so garbage collection has no forwarding rules or reservations left to remove.

`stop` releases the ports and saves their configuration with the stopped
VM, as an exited VM's record does. `start` binds them again, and refuses if
they have been taken meanwhile. A checkpoint restore uses only ports
explicitly given with `run -p` again, even when restoring a stopped VM's
checkpoint. Migration does **not** recreate the forwards on the target. The
source keeps them, reaching the VM through its route to the target, until
the target has all the VM's memory, and drops them then; a migration that
aborts before that leaves the VM here with its forwards. Existing proxied
connections end with them (unfinished TCP forwards are reset); use routed VM
addresses for services that must remain reachable through migration.

## Stop, start, pause, kill, rm

```sh
flexvm stop web                 # suspend to disk and free its memory; the process exits (as SIGTERM)
flexvm start web                # bring it back, in the background (-a: in the foreground)
flexvm pause web                # pause the vCPUs, memory kept (as SIGTSTP; Ctrl-Z in the foreground)
flexvm unpause web              # resume them (as SIGCONT)
flexvm kill web                 # destroy a running VM (as SIGINT; Ctrl-C or Ctrl-\ in the foreground)
flexvm kill -s HUP web          # send a signal (name or number) to its app instead
flexvm rm web                   # remove a stopped VM (suspended, quarantined, exited, failed, lost)
flexvm rm -f web                # destroy it, running or not
flexvm restart web              # stop, then start (a stopped VM is started, an exited one run again)
flexvm wait web                 # block until its process ends; print its exit status
flexvm rename web web2          # a running or stopped VM
```

`wait` takes several names and prints each one's status in turn: its
process's (as `run`'s, below: 143 for a stop, 130 for a kill, 124 when it
died, CMD's or the app's when it exits), and at once for one with no process
(a stopped VM: 143; an exited one: its status; `failed` or `lost`: 124). It needs no daemon: it waits on
a pidfd of the process holding the name, then reads `RUN/vms/NAME.exit`,
which the VM's process writes as it ends; a process that ended without one
(SIGKILLed) is an error. `rm` removes the record.

`rename` keeps everything but the name: a running VM's own process takes the
new name (its registry entry, control socket, the claim on its address and
its log move, and its command and execs go on under it); a stopped VM's
checkpoint, address claim and logs move; an exited VM's record (what `start`
runs again) and logs move. It refuses a name in use (a VM,
stopped or not, or an `exited`, `failed` or `lost` record: `rm` that first), and a VM
that is checkpointing, migrating (either way, or still pulling its memory
after an arrival), being stopped, or `failed` or `lost`. An `exec` started
before keeps its stream, but cannot reattach (after a checkpoint or a stop)
under the old name.

As in Docker, `kill` is for a running VM and `rm` for a stopped one: `kill`
of a stopped VM and `rm` of a running one are refused, saying so, and `rm -f`
does either. `stop`, `start`, `pause`, `unpause`, `kill` and `rm` take
several names, go on past one that fails, and print each name done (`start`
prints the VM's JSON when restoring a stopped VM, and its name when already
running or paused). A VM is its process, so the signals in
parentheses work as well, sent to the pid `ps` shows.

`stop` of an already stopped or exited VM succeeds without changing it.
`restart` of a failed or lost VM names that state and points to `ps -a` and `rm`.
A VM process SIGKILLed records nothing (`lost` is only for VMs found dead
after a reboot); `rm NAME` removes the name lock and logs it left.

A stopped VM keeps its name and address. `start` restores it in a new
process, in the background whether it first ran in the foreground or with
`-d`; `start -a` brings it back in the foreground. A `run IMAGE CMD` VM stops with its
command, which keeps running once started again: `start -a` prints the rest
of its output and exits with its status. `start` of a paused VM unpauses it;
`start -a` attaches only to a VM it starts, so it refuses a running or paused
one (`unpause` that), after waiting out a stop under way.

`start` of an `exited` VM runs it again: a new VM of its image under its
name, with what it was run with (its command, `-p`, `-e`, `--entrypoint`, `--keep`,
`--cpus`, `--memory`, and its `--ip` if one was given; an `--rm` VM leaves no
`exited` record to run again). A VM has no
disk of its own: its root is the image's read-only filesystem with an overlay
in the guest's memory, so what it wrote ends when it exits (a `stop` keeps it,
in the memory it saves). The rerun starts from the image's current template,
so a pull since then is what it runs; `start -a` runs it in the foreground,
and its exit leaves the record again.

`kill -s SIGNAL` sends SIGNAL (`TERM`, `SIGHUP`, `9`, ...) to the VM's app
(its process alone, as `docker kill -s` does) and leaves the VM to follow it;
plain `kill` destroys the VM. A VM with no app refuses it.

A closed terminal (SIGHUP) leaves a foreground VM running; its output then
goes to `/run/flexvm/vms/NAME.log`.

Exit statuses of `flexvm run` and `flexvm start -a`: with CMD, CMD's own;
without, its app's;
128 + the signal that ended it (130: destroyed by SIGINT, Ctrl-C or
`flexvm kill`; 143: stopped, by `flexvm stop` or SIGTERM); 0 when it
migrated away or `checkpoint create VM --stop` stopped it. flexvm's own failures use
the range shells and container runtimes keep for themselves: 125 when it
could not start the VM (or gave it up; also for `run -d` and `start`), 124
when the VM died under it, even before its start was done (`flexvm ps -a` then shows it `failed`, and `ps -a
--json` why, until `flexvm rm`). For a VM with neither they are the same, so a script
can tell a VM that never ran (125) from one that did. `flexvm exec` returns
the command's status, 127 when it is not found, 126 when it cannot be run (or
its `-u` user or `-w` directory is missing), or 125 for flexvm's own failures. Other commands exit
1 when they fail.

`flexvm reclaim IP` explains the loan and prints `flexvm reclaim IP --force GEN`
with its current generation. After checking that no host still runs that VM,
use that command to withdraw the loan. It refuses if the lent generation changed.

A VM migrating away stays paused on its source until the target has all its
memory; `flexvm kill` refuses that copy (kill the VM where it runs), and
`kill -KILL PID` gives it up (the target loses the pages it has not pulled).

## Checkpoint and restore

```sh
flexvm checkpoint create web base                   # the VM runs on (paused ~20 ms); named base
flexvm checkpoint create web --incremental          # only what changed since its last one
flexvm checkpoint create web last --stop            # and destroy it
flexvm checkpoint ls                                # name, id, VM, template, parent, size, age
flexvm run --checkpoint base                        # same name and address
flexvm run -d --checkpoint base --name web2 --ip auto   # a fork, with a new address
flexvm run --checkpoint 3f2a --paused               # by the start of its id; held until unpause
flexvm checkpoint rm base                           # refused while another builds on it
flexvm checkpoint prune --older-than 7d             # asks first on a terminal (-f: not)
flexvm checkpoint save base | ssh b flexvm checkpoint load   # to another host, template and all
flexvm checkpoint save base -o base.tar             # to a file; checkpoint load -i base.tar reads it
```

flexvm keeps checkpoints in `STATE/checkpoints`, each under its id (the
checksum of its manifest), and a name, given at `create`, links to one.
Names are unique: `create` with a taken one is refused, as is one of 16 hex
digits (an id); a checkpoint loaded again under another name has both. One being written is
not listed, restored or built on until it is complete. `--incremental` stores
a delta on the VM's last checkpoint, taken here since it last started, was
restored or migrated, that it ran on after; with that one removed, take a
full one. `checkpoint rm NAME|ID...` (an id's first 4 or more digits will do)
is refused while a checkpoint not removed with it builds on it; `-f` removes
those too. `checkpoint prune` removes every checkpoint, or with
`--older-than AGE` (`90s`, `30m`, `24h`, `7d`) those older, except what a kept one
builds on; it lists what it removed. A name whose checkpoint is gone resolves to
none until `rm NAME` or `prune` removes it. Removing a name alone works even
while another checkpoint is unreadable. Malformed name entries are removed by
`rm -f NAME` or `prune`. While the store cannot be listed whole, removal (of a
name whose checkpoint is gone too) and an id's start are refused; a name or a whole id still works.
Both wait for checkpoints being written and for restores still opening one. A
VM restored from a checkpoint runs on after the checkpoint is removed. `ls -q`
prints ids; `--filter name=NAME` (an exact match of any name), `vm=NAME` and
`template=IMAGE|ID` select (a key again: either value); `--format` takes `json`
or a template of `.Name` (the first name, usable with `run --checkpoint`),
`.Names` (all names joined with `, `), `.ID`, `.VM`, `.Template`,
`.TemplateID`, `.Parent`, `.Size` (bytes), `.Created` (Unix seconds),
`.Directory` and `.Error`, as `ps --format` does. JSON keeps `names` as an
array. Listing failures show the directory and error; with a text format or
`-q`, they are warnings on stderr instead of empty rows. The template column is
the image that names the checkpoint's template generation now, or `<none>`,
with the start of the generation's id. A stored checkpoint keeps its generation
through pulls, `image prune` and `rmi` (see Images); `system df` counts stored
checkpoints.

A checkpoint restores on any host with the same template (by content id).
Restored on another host with its own address, the VM borrows the address
from its home host, which refuses one in use or lent out; `--ip auto` picks
a new one. `run --checkpoint PATH` (any argument with a `/`) restores a
checkpoint directory as it is: one written by flexvm 0.1.0's `flexvm checkpoint
VM DIR` (which `checkpoint create` replaces, and now refuses), another state's
stored one (`STATE/checkpoints/ID`), or a stopped VM's. Its template generation
must be here.

`checkpoint save NAME|ID` moves a stored checkpoint to another host: it writes one
self-contained tar, to stdout (never a terminal) or with `-o FILE` to that file once
it is whole. The tar holds the checkpoint, the chain it builds on, and the template
generation it was taken on: its memory file's data (holes stay holes), metadata and
root filesystem; and the run settings each was taken with (`--keep`, `--rm`, `-e`,
`--entrypoint`), which a restore on the other host keeps. Stored checkpoints themselves stay lean, sharing the template.
`checkpoint load` reads a save from stdin, or `-i FILE`, and stores it under the
same ids and name (`--name NAME` gives another; a name another checkpoint has is
refused before anything is read). A new name is claimed until publication, so a
concurrent checkpoint create or load cannot take it. Everything is verified before anything is
published, so a damaged or truncated save stores nothing (nor does a load that fails
as it publishes): each checkpoint by its
id and checksums, and the template by its content id and the SHA-256 digests the
checkpoint records. Those ids and checksums catch damage, not forgery: `save` prints
the save's SHA-256 (of every checkpoint file; on stderr when the tar goes to stdout)
and `load` prints what it read, and `load --sha256 HEX` stores only the save with that
SHA-256. A checkpoint this host has under one of the ids is used only if its files are
the same, byte for byte. The template is stored unnamed, unless this host has a
generation of that content id already; no image name here is read or moved, as the
saving host's `:latest` may be another build than this host's. `run --checkpoint NAME`
then restores it on that generation. A checkpoint taken on a template built by
flexvm 0.1.0 records no digests: its save leaves the template out, so the loading
host must have it. `checkpoint load -i DIR` stores a checkpoint directory (flexvm
0.1.0's, or any of the above) with its chain; it holds no template.

## Configuration

A host's settings are `STATE/host.json` (`/var/lib/flexvm/host.json`),
edited by hand. Running VM processes and listeners read it again when it
changes (by mtime or inode), so edits apply live. A missing file, or a
missing key, takes the default or derives the value where it is used.
`flexvm info` prints what is set, what is derived for the rest, and
warnings about likely mistakes.

```json
{
  "peers": ["192.168.1.11:7070"],
  "vm_ips": "192.168.1.128-192.168.1.191",
  "cluster_ips": "192.168.1.128-192.168.1.250",
  "dns": "192.168.1.1"
}
```

| key | default | what |
|---|---|---|
| `peers` | none | the other hosts' listen addresses, `HOST:PORT`: the only hosts this one takes migrations and routes from |
| `vm_ips` | `10.200.0.0/16` | this host's VM addresses (CIDR or `FIRST-LAST`); disjoint from every peer's |
| `cluster_ips` | `vm_ips` | every host's VM addresses: a peer's VM may have, route or borrow only one in it |
| `dns` | none | the guests' DNS server (IPv4) |
| `underlay` | derived | the address peers route this host's VMs through |
| `peer_underlays` | none | `{"HOST:PORT": ["IP", ...]}`: a peer's next hops besides its `peers` address |
| `announce_dev` | derived | where the host answers ARP for its VMs and announces arrivals; `"none"`: off |
| `reserve_mib` | a sixteenth of RAM, 256 MiB to 4 GiB | memory kept free |
| `evict_mib` | the reserve plus the reserve or 512 | below this much available, VMs move to peers |
| `listen` | none | this host's listen address, `HOST:PORT` with a nonzero port; `flexvm listen ADDR` saves it. A name is listened on at each address it resolves to (peers may pick any), and an activated socket given with ADDR must take them all |

Every command checks the file as it loads it (`Config::validate`): a key it
does not know, a malformed address or range, a `peers` entry that is not
`HOST:PORT`, a `peer_underlays` address that is loopback or not unicast, a
non-IPv4 `dns`, a `listen` address without a nonzero port, or a `vm_ips`
not inside `cluster_ips` makes every command refuse to start, naming the
file and the problem, until it is fixed. An explicit `underlay` that is
loopback or not unicast is refused on write; on read it is ignored with a
warning and the underlay is derived instead. A running process keeps the
last valid configuration meanwhile, so an edit
mid-write is never taken. Write it whole (an editor's save, or a temporary
file renamed over it); it must be a regular file, not a link, that no one
but its owner (root) may write. A new `vm_ips` or `dns` applies to
addresses handed out and guests set up after it (standby VMs' claims
included); running VMs keep theirs. Whether a peer underlay is local depends
on the current interfaces: `info` and the listener (after writing its config)
warn if it is local or the interface lookup fails, without refusing commands
or configuration reloads.

There is no `config` command: the file is the interface, and a reload is
how every process already picks up changes, so a command would only write
the same JSON. `info` covers what a command added: the derived values and
the warnings.

## Migrate

Each host that takes migrations runs a listener, which takes only its peers'
addresses and can be socket-activated:

```sh
# host A (192.168.1.10) and host B (192.168.1.11) on one LAN; VMs use spare LAN addresses
# A's host.json: {"peers": ["192.168.1.11:7070"], "vm_ips": "192.168.1.128-192.168.1.191", "cluster_ips": "192.168.1.128-192.168.1.250", "dns": "192.168.1.1"}
# B's host.json: {"peers": ["192.168.1.10:7070"], "vm_ips": "192.168.1.192-192.168.1.250", "cluster_ips": "192.168.1.128-192.168.1.250", "dns": "192.168.1.1"}
flexvm listen 192.168.1.10:7070          # on A
flexvm listen 192.168.1.11:7070          # on B

flexvm migrate web 192.168.1.11:7070      # on A: web now runs on B, same address, connections intact
```

The target need not have pulled the image: the source sends it the VM's
template generation first (`template_push` in the output), by content id,
while the VM runs. A target that pulled another build under the same tag
(`:latest` moved, or the same image pulled separately) gets the source's too,
unnamed: its own tag stays as it was, and `images` shows the sent one as
`<none>` (`image prune` removes it once no VM uses it).

Networking is routed IPv4: flexvm provides no NAT or automatic internet
egress. Arrange upstream routes or NAT yourself if guests need it. There is
no default DNS server; set `dns`.

Every host's `vm_ips` must be disjoint and inside `cluster_ips`, the
same range on every host covering all of them: a peer's VM may have, route or
borrow only an address in it (unset, only this host's `vm_ips`, so
migrations between hosts are refused). `info` and `listen` warn when
peers are configured without `cluster_ips`; `info` shows the effective
allowlist in `derived.cluster_ips`. Withdrawals of previously recorded
addresses remain accepted after the allowlist narrows. A generation routed
via a peer is withdrawn only by that peer (its addresses and
`peer_underlays`), or by one that had the VM later (a newer revision of the
generation: it migrated on) or a newer generation. A peer announces routes
via its own addresses only (its `peers` address, or its `peer_underlays`),
never via another host. While a VM here holds an address, no peer brings a
newer generation of it, and only the host it is migrating to moves or
withdraws its generation (a VM arriving here, once it commits: only the host
it came from, until its pull is done); for an address of this host's own
`vm_ips`, which only this host hands out, no peer brings a newer generation
while it is lent from here. After a reboot, no generation newer than its
record here is accepted until the first `next_gen` allocation; after that,
any generation below this boot's allocation cursor may be taken, even if
issued for another address. Arriving VMs face the same checks. A refused
update is retried by its sender, so one that comes before the withdrawal it
follows is taken once that has. The hosts must list each
other in `peers` (each peer's listen address): a listener serves its peers'
addresses only, and tells any other it is not a peer. A reported route next
hop (including a migration target's underlay) must be the connection's peer
address or a configured peer's known address (or `peer_underlays`), and
unicast. A peer's address local to this host, as with hosts sharing a
network namespace, is taken but installs no route. Saved routes are checked
again before reinstalling them. The default range, `10.200.0.0/16`, is the
same on every host, so give each host its own once it has peers (`info`
warns until then). Derived values:

- `underlay`, the address peers route this host's VMs through: the listen
  address, or for a wildcard one the source address of the kernel's route
  toward the first peer not on this machine (`ip route get`, policy routing
  included). With every peer on this machine (loopback, or one of its
  addresses) it is loopback; with peers elsewhere, never. Peers take it as
  one of the addresses they know this host by (its `peers` address, or one
  its name resolves to); an underlay on another network than that address
  (a separate data-plane network) is listed on each peer in
  `peer_underlays`.
- `peer_underlays`: a peer's next hops besides its `peers` address, its
  `underlay` on another network. Only these, set here, are trusted: never an
  address because it is on-link. Each must be non-loopback and unicast;
  a local address is accepted with a warning.
  Entries for a host no longer in `peers` are ignored (`info` warns).
- `announce_dev`, where the host answers ARP for its VMs (`proxy_arp`) and
  announces a VM that arrives: that route's device, none for peers on this
  machine. `"none"` turns this off, for routed or WireGuard links.
- `reserve_mib`, the memory a host keeps free (starts and growth that would
  take it below are refused): a sixteenth of the host's RAM, from 256 MiB to
  4 GiB. Hot-page buffers of VMs taking keep-running checkpoints are
  allocated without admission and can take up to 128 MiB per such VM out of
  the reserve. One above the host's RAM refuses every start (`info` warns).
- `evict_mib`: VMs start moving to peers with room once the host has less
  than this available, the fastest growing first, until it is back above the
  mark by half the mark's height over the reserve. Default: the reserve plus
  the reserve or 512, whichever is more. A peer takes such a VM only if it
  stays above its own mark, and a host refills standby VMs only above its
  own; a mark under the reserve counts as the reserve. Before moving VMs,
  the host asks for kept checkpoint memory back. Without peers, the
  controller retains that memory until available memory falls below the
  reserve (or the VM is starved); admission can still ask for it before
  refusing a grant.

Derived values are never saved: they follow the routes, the peers and the
host's RAM. A wildcard listener with peers elsewhere and no route toward them
fails, asking for `underlay`.

Every VM process and listener sets `net.ipv4.ip_forward=1`, and
`proxy_arp` on the announce device, and never reverts them: the host routes
between all its interfaces from then on, so check its `FORWARD` policy.

A host that only runs VMs needs no listener, but see below for what recovers it after a reboot.

Taps are named after the state directory (`f` and five characters of its
hash, then the owning process's pid), so hosts on separate state directories
read apart. Each tap's alias (`ip link show`) names its owner, `flexvm
pidns:NS PID START RUN-DIR`, NS being its PID namespace's inode: hosts sharing
a network namespace only ever sweep their own taps, also from different PID
namespaces (containers on the host's network), whose taps they never judge by
pid. Once a PID namespace has no process left (a killed container), a flexvm in
the initial PID namespace (the host's, which sees every process) sweeps its
taps and Firecracker cgroups; a flexvm in any other PID namespace (a
replacement container, WSL's distribution) cannot tell, and leaves them. Taps
of earlier builds (`flexvm PID START RUN-DIR`) name no PID namespace and are
judged by their run directory alone, so hosts on separate PID namespaces must
not share one while such taps remain. After an upgrade, earlier builds cannot
read the new names: what a VM process of this version leaves when it is
SIGKILLed (its taps and their routes, its Firecracker cgroups) stays until a
flexvm of this version sweeps.

### Under systemd

Run the listener as a socket-activated service (after writing `host.json`);
without ADDR it takes its address from the socket:

```ini
# /etc/systemd/system/flexvm-listen.socket
[Socket]
ListenStream=192.168.1.10:7070

[Install]
WantedBy=sockets.target
```

```ini
# /etc/systemd/system/flexvm-listen.service
[Unit]
Requires=flexvm-listen.socket
After=flexvm-listen.socket

[Service]
ExecStart=/usr/local/bin/flexvm listen
Restart=on-failure
# The default KillMode=control-group is right: see below.

[Install]
WantedBy=multi-user.target
```

`systemctl enable --now flexvm-listen.socket flexvm-listen.service` starts the
listener at boot too, not only when a peer connects: VMs do not survive a
reboot, and flexvm processes recover the host after one (each tries until a
pass completes, marked by `/run/flexvm/.boot`). It
withdraws the addresses of the VMs it lost (telling the peers, so a home host
takes back an address it lent), lists those VMs as `lost`, puts back the
routes to VMs on peers, settles migrations the reboot interrupted, and
refills the standby VMs. The listener does this as it starts, and so does
the first other flexvm command run as root (`flexvm ps`, say); a VM process
or a pull does the local part. So a host without a listener recovers at its
first command after a boot; to have that happen at boot, run any root
command from a oneshot unit (`ExecStart=/usr/local/bin/flexvm ps`).

The VM processes a listener starts (arrivals, standby VMs) move into
cgroups of their own (`/sys/fs/cgroup/flexvm/vm-PID-START-NS`) as they start, and so
do VMs started with `-d` (`run -d`, `start`, `run -d --checkpoint`) and
standby VMs from any command. So stopping or restarting the unit, with the default
`KillMode=control-group`, stops only the listener; `KillMode=process` is not
needed. Likewise logind's `KillUserProcesses`, or the end of a
`Type=oneshot` unit that runs `flexvm run -d IMAGE`, leaves those VMs
running. A foreground `flexvm run IMAGE` (or `start -a`) stays in its
caller's cgroup, so a service whose `ExecStart` is one is supervised like any
process: stopping it sends SIGTERM, which suspends the VM to disk (give it
`TimeoutStopSec` for that), and `KillSignal=SIGINT` destroys it instead. A
foreground run that claims a standby VM moves that VM's process into its
cgroup, so this holds for it too, and killing the run (SIGKILL) destroys the
VM, as it would a cold run's. These cgroups need no controllers: a host that
cannot enable the memory controller in `/sys/fs/cgroup/flexvm` still makes
them, and only goes without the per-VM memory limits (`--cpus` likewise needs
the cpu controller there). A foreground run put in the background
keeps running under `stty tostop`: its VM process ignores SIGTTOU and SIGTTIN.

Hosts in different PID namespaces should not share `/sys/fs/cgroup/flexvm`.
Cgroup owners are recorded by PID and start time in the creator's PID namespace.
Firecracker cgroups (`idle-PID-START-N-NS`) and a VM process's own
(`vm-PID-START-NS`) also name that namespace, and garbage collection leaves
another namespace's alone until that namespace is proven gone (as taps, above),
but an earlier build's (`idle-PID-START-N`, `vm-PID-START`) are judged by this
namespace's processes and may have their Firecrackers killed, or be removed
once empty. Give each PID namespace its own cgroup subtree, mounted so
that its `/sys/fs/cgroup` is rooted there; a new cgroup namespace or a second
cgroup2 mount alone still sees the shared hierarchy. Separate state and run
directories alone do not isolate cgroup collection. What flexvm names after a
process in directories hosts may share (temporary files in a shared templates
directory, VM processes' socket directories under `/run/flexvm/s` or
`/tmp/flexvm-s-UID`) names its PID namespace too, so processes of different
namespaces with the same pid and start time never write to one another's.

A VM process records its PID namespace with its pid (`pidns` in `ps --json`;
`pid` is the one it has there). A flexvm sharing its run directory from an
ancestor namespace (the host, for a VM run in a container) finds it by that
namespace, its pid there and its start time, and controls it by the pid it has
here: `exec`, `stop`, `pause`, `kill` and `rm -f` work, and garbage collection
judges it by that process. A flexvm in a namespace that cannot see it (a
sibling container) refuses to signal it (`process 1 of PID namespace NS cannot
be seen from this one`), and never takes it for gone. Commands that only talk
to its control socket (`checkpoint`, `unpause`, `kill -s`) work from either.
A flexvm whose `/proc` is not its own PID namespace's (`unshare --pid` without
`--mount-proc`: `/proc/self/status` lists more than one `NSpid`) refuses to
signal any VM and never takes one for gone. Standby VMs, memory debits,
eviction backoffs and release answers are named by PID namespace too; a
standby VM is claimed only by a `run` it can see (in its own PID namespace or
one below it), or by a `-d` or `-i`/`-t` one (whose VM joins no cgroup of its)
from any other. A plain foreground `run` from an ancestor namespace starts
cold on a cgroup2 host: its VM joins its cgroup, which the standby cannot prove the claimer's (it reads its
pid as 0, and a pidfd passed gives no pid there, nor can be signalled from
there). A flexvm whose `/proc` is not its own starts no VM at all (`/proc is
not this PID namespace's`): what it reads there of its Firecrackers (their
executable, fds, memory maps, threads, network namespace) would be other
processes'. A build from before #1139 reads a standby's lock by pid and start
time alone, and may signal a process of another PID namespace with both; run
one build on hosts that share a run directory across namespaces.

## Fast starts

```sh
flexvm pull ubuntu:24.04 --standby 2     # keep 2 of its VMs restored and paused
flexvm pull nginx:1.27 --standby 1
flexvm pull ubuntu:24.04 --standby 0     # none
```

`run` takes one (resume and set the address: ~5 ms) and a replacement starts.
Without one, `run` loads the snapshot (~50-100 ms). The count is kept per
image (`STATE/standby/NAME`; `images` shows it) and refilled by every
listener and VM process, retried each minute (errors in `standby.log` in
`RUN/standby/HASH/`). `--standby N` alone (with `--tag` at most) on an image
already pulled only sets the count: no registry is asked and nothing is
rebuilt, which a pull with other options than the image's first would do.
With other options, the pull runs first and then sets it. `rmi` sets it to 0
first. Standby sockets are `RUN/standby/HASH/PID.NS.sock`, where HASH is the
16-hex hash of the template's name and NS the standby's PID namespace inode in
hex. Claims carry the generation key, the
VM's `--cpus`/`--memory` caps (checked against the standby's template), and
`.locks/PID-START-NS.lock` identifies the process while it lives. Socket paths
must be under 108 bytes.

## Images

```sh
flexvm pull nginx:1.27                                  # any registry: Docker Hub, ghcr.io, gcr.io, ...
flexvm pull ghcr.io/org/app@sha256:...                  # by digest
flexvm pull ./app.tar --tag app --env PORT=8080         # `docker save` output or an OCI archive, named with --tag
flexvm pull ./oci-layout --tag py --cmd "python3 -m http.server 8000"
flexvm pull nginx:1.27 --tag web-warm --warm            # snapshot the app running and ready
flexvm run -d --name web1 nginx:1.27 && curl http://<ip>/
flexvm images                                           # what is pulled (--json: all of it)
flexvm images -q --filter 'reference=nginx:*'           # unique generation IDs
flexvm images --filter dangling=true                    # generations with no name
flexvm tag nginx:1.27 app:production                    # another name, without a build
flexvm image prune -f                                   # unused <none> generations
flexvm system prune -f                                  # also failed/lost VM records and layer blobs
flexvm system df                                        # allocated disk bytes by kind
flexvm version                                          # version, commit and artifact pins
flexvm rmi nginx:1.27                                   # refused while a VM here uses it
```

`pull` fetches an image (a native registry client; no docker needed), builds
its root filesystem with flexvm-init as PID 1, cold-boots a VM of it and
snapshots it once its agent answers: that snapshot, the image's *template*,
is what every `run` restores. The image's entrypoint and command start at
`run`, and the VM exits when the app does (see Run a VM); an image with
neither has no app, and its VMs idle until told what to run (`exec`,
`run IMAGE CMD`). ubuntu:24.04's command is `bash`, which exits at once
without a terminal, and its VM with it, saying so; `run -d ubuntu:24.04 sleep
infinity` (or `--keep`) gives an idle machine to `exec` into.

**Names.** A template is named after its image reference, resolved as
`docker pull` does (`ubuntu` is `docker.io/library/ubuntu:latest`), in
Docker's short form without a `:latest` tag and with `/` written `+` (which no
reference has, so the name gives the reference back): `ubuntu:24.04`,
`nginx`, `ghcr.io+org+app:v1`, `ghcr.io+org+app@sha256:...`. `run` and
`rmi` take any spelling of the reference, or the name. `--tag NAME[:TAG]`
names it otherwise: an archive or layout directory needs one, and so does an
image built with other options alongside its plain pull. `tag SRC DST` gives
an already pulled generation another name using those same naming rules;
SRC can also be a generation ID or unique prefix. An existing DST moves to
that generation; the previous generation remains available to its users.
Pulling either name again moves only that name.
`images -q` prints each selected generation ID once, even with several names.
`--filter reference=PATTERN` matches the familiar reference (`nginx:latest`,
for example) with shell wildcards (`*`, `?`, brackets); quote it in the shell.
A repository without a tag matches all its tags. Repeated reference filters
match any pattern. `dangling=true|false` selects
unnamed or named generations and combines with the reference filters.

**Pulling again** asks the registry again. If the image (its manifest), the
options, the sizes, the kernel, Firecracker and flexvm's build recipe are the
same, the template is up to date and nothing is built. Otherwise (a tag that
moved, say) a new template generation is built and the name moves to it.
Standby VMs of the old one are replaced from the new, and the pull deletes the
old generation and the root filesystem only it used, printing what it removed
(as `image prune` does), unless another name links to it or a VM here
(running, paused, stopped, standby, or migrating in or out) or a checkpoint in
`STATE/checkpoints` uses it. Those name it by content id, so it stays for
them, listed as `<none>` by `images`, until `image prune` or `rmi ID` removes
it once they are gone. Checkpoint directories elsewhere (flexvm 0.1.0's, restored by
path) are not tracked, as with `image prune`: once their generation is deleted
they cannot be restored here. Nor can VMs of it elsewhere migrate here. A templates directory
that other states link to (see Paths and knobs) may hold generations their VMs
use, so pulls through it leave the old generation to `image prune`.

**Removing.** `rmi IMAGE` removes the name and, unless a VM here still uses
them, its generation and its root filesystem (`images/rootfs/`); `rmi ID` (or
a unique prefix of it) removes a `<none>` generation. Both are refused while a
VM here (running, paused or stopped) uses the image; `rmi IMAGE` sets its
standby count to 0 and waits for its standby VMs to go first. A generation a
stored checkpoint uses stays: `rmi IMAGE` removes only the name, and `rmi ID`
is refused until `checkpoint rm`. Checkpoints in other directories than
`STATE/checkpoints` that pin a removed generation cannot be restored here any more. Layer blobs (`images/blobs/`)
are a download cache and stay until `system prune`.

To share an images cache, symlink `STATE/images` to it in every state. Each
root filesystem records the states whose generations use it, and `rmi` and
`image prune` remove it only after the last of them goes. One an older flexvm
built in a shared cache is kept until `image prune --force-shared` (when no
generation here uses it), which also forgets states whose templates directory
is gone (see
[Container images](docs/images.md)).

`image prune` removes each `<none>` generation as `rmi ID` would: those a
VM here (running, paused, standby or stopped) or a checkpoint in
`STATE/checkpoints` uses stay, and, as with `rmi`, checkpoints elsewhere that
pin a pruned generation cannot be restored here any more. In a templates
directory other states share, `image prune` and `rmi ID` also keep what their
stopped VMs and stored checkpoints use (each state that uses the directory is
recorded in `templates/.states/` when opened; running VMs of any state are seen
on this host anyway), and every `<none>` generation while one of those states
cannot be read or is gone (moved or removed). One marked shared by an older
flexvm (an empty `templates/.shared`) may have states linked to it that were
never recorded: both keep every `<none>` generation there. Once each such state
has run a flexvm command, or after removing a state that used the directory,
`image prune --force-shared` takes the record as right: it forgets states that
are gone, marks the directory up to date and prunes. `system prune` also removes failed and lost VM records and the layer
blob cache (left alone while a pull runs). Both list what they remove and the
bytes reclaimed, and ask first on a terminal; without one they need `-f`.
`system df` reports allocated bytes for image root filesystems, templates,
blobs, VM records and logs, and checkpoints (stored ones and stopped VMs'),
counting hard links once.

**Registry credentials.** `flexvm login [REGISTRY]` defaults to Docker Hub.
It verifies the supplied credentials over HTTPS before saving them in
`STATE/auth.json`, owned by root with mode 0600. Use `--username USER` and
`--password-stdin` for scripts; on a terminal missing values are prompted
for, with password echo disabled. For example:

```sh
printf '%s\n' "$REGISTRY_PASSWORD" | sudo flexvm login ghcr.io --username alice --password-stdin
sudo flexvm logout ghcr.io
```

Pulls try these credentials before `$DOCKER_CONFIG/config.json`,
`~/.docker/config.json`, or the invoking sudo user's Docker config.
`logout [REGISTRY]` removes only flexvm's saved entry; Docker credentials
can still be used as a fallback. Credentials never travel over plain HTTP,
including loopback registries; login refuses those endpoints. `version`
shows the flexvm version, build commit, artifact release,
installed Firecracker/kernel paths and pinned digests without downloading
or executing them; `--version` keeps its one-line version output.

**Sizes** are fixed in the snapshot, so they are pull options (`run --cpus`
and `--memory` cap a VM below them):

| option | default | what |
|---|---|---|
| `--vcpus N` | host CPUs, at most 32, rounded down to even | vCPUs (Firecracker cannot add vCPUs to a running VM) |
| `--max MIB` | host RAM | memory ceiling: boot memory plus the hot-plug region, in whole 1 GiB slots |
| `--mem MIB` | 256 + max/32, rounded up to 128 | boot memory, which holds kernel memory for the whole ceiling |
| `--plug MIB` | 4096 | plugged in the snapshot (free until touched); a VM never shrinks below it |

Overrides follow `docker run`: `--entrypoint`, `--cmd`, `--env K[=V]`
(repeatable; a bare key takes the host's value, or is left out if unset),
`--workdir`, `--user` (`run` takes `-e`, `--env-file` and `--entrypoint` per VM). `--warm` snapshots the app once it is ready
(`--ready-port N`, 1–65535, or `--ready-cmd CMD`); every VM from a warm template starts
with the same userland state (RNG seeds, keys), so use it only for apps that
hold no secrets at startup. Details: [docs/images.md](docs/images.md).

## Docker API

`flexvm api` serves the Docker Engine API (v1.47; clients negotiate down to
it) on a Unix socket, so docker's CLI, Compose and the SDKs drive flexvm's
VMs as containers:

```sh
sudo flexvm api &                                 # on /run/flexvm/docker.sock (another --state: its run directory's)
export DOCKER_HOST=unix:///run/flexvm/docker.sock # or: docker context create flexvm --docker host=unix:///run/flexvm/docker.sock
docker version && docker info
```

It is no daemon in docker's sense: it keeps nothing a restart would lose.
What it answers comes from the records the commands read (`ps -a`,
`inspect`, `images`), and what it changes it changes by running the commands,
this binary with its own `--state` and `--run`; VMs it starts are VM
processes like any other, which outlive it. `flexvm api SOCKET` serves
elsewhere; a socket another server answers on is refused, a stale one
replaced. The socket is root's alone (0600), as anyone who can use it can do
what root can; to open it to a group, socket-activate it:

```ini
# /etc/systemd/system/flexvm-api.socket
[Socket]
ListenStream=/run/flexvm/docker.sock
SocketMode=0660
SocketGroup=docker

[Install]
WantedBy=sockets.target
```

```ini
# /etc/systemd/system/flexvm-api.service
[Unit]
Requires=flexvm-api.socket
After=flexvm-api.socket

[Service]
ExecStart=/usr/local/bin/flexvm api
```

An endpoint is served where flexvm has the machinery under it. Docker's
others (swarm, plugins, builds, volumes, networks, ...) answer 501, saying
so, and a setting that cannot be honoured is refused, never ignored.

| endpoints | served from |
|---|---|
| `GET /_ping`, `/version`, `/info` | `flexvm version`, `info` and `ps -a`'s counts |
| `GET /containers/json`, `/containers/{id}/json` | `ps -a` and `inspect`, in docker's shapes |
| `GET /containers/{id}/logs` | `logs [-f] [--tail N]` |
| `POST /containers/{id}/wait` | `wait` |

A container is a VM, under its name; its id is the name's SHA-256, so it
needs no record of its own (and a rename makes it another). Docker's states
are flexvm's: a stopped (suspended) VM is `exited` with status 143, as
`flexvm wait` says, but `docker start` resumes it where it was; a failed,
lost or quarantined one is `dead`. Its `Entrypoint` and `Cmd` are its
image config's while the layer cache keeps that (`system prune` drops it),
else its app is all `Cmd`; `Config.Labels` are its image's. Every VM is on
one flat routed network, listed as docker's `bridge`, with its address as
`IPAddress`. A VM's log keeps neither its streams apart nor times: `logs`
gives all of it as stdout, and refuses `--since`, `--until` and
`--timestamps`. `ps --filter` takes `id`, `name`, `status`, `exited`,
`label`, `ancestor` and `network`.

## Paths and knobs

| flag | default | what |
|---|---|---|
| `--state DIR` | `/var/lib/flexvm` (or `FLEXVM_STATE_DIR` at build time) | everything on disk: `host.json` (see Configuration), `artifacts/` (`firecracker`, `vmlinux`; `base.squashfs`, the tests' base rootfs), `templates/` (a link per image name to its current generation in `templates/.gen/`), `images/` (layer blobs and image root filesystems), `staging/` (where image layers unpack: root-owned, see [docs/images.md](docs/images.md)), addresses, stopped VMs |
| `--run DIR` | `/run/flexvm` (another `--state`'s: `/run/flexvm-PREFIX`) | registry, sockets, logs, exit statuses (tmpfs) |

`pull` writes the flexvm-init built into flexvm into the image as PID 1 (`--init PATH`
for another). Several hosts on one machine (tests, benchmarks) each take a `--state` and
`--run` of their own; their `artifacts` and `templates` can be symlinks to one
host's. A state whose `templates` is a link marks its target shared when opened, and
records itself (and the state the directory belongs to) in it, so `image prune`
there can read each one's stopped VMs and checkpoints; pulls through a shared
one leave old generations to `image prune` (see Images);
after upgrading to this release, run a command with each such state (`flexvm --state S
ps`) before pulling, or a stopped VM there may lose its generation.

Admission ledgers are per RUN directory, not machine-wide. Co-located hosts
with different RUN directories admit against the same `MemAvailable` without
seeing each other's pending grants or holds. They can over-commit within the
10-second grant window, or longer while a start, restore or arrival is still
paging memory in. Use one host per machine when relying on admission to protect
the memory reserve.

The state/run directory binding and defaults are described in [Setup](#setup).
`FLEXVM_FAULTS=1` enables test fault injection only. The state layout is in
[docs/process-per-vm.md](docs/process-per-vm.md#on-disk-state).

## Benchmarks

For flexvm's development:

```sh
flexvm bench --template small                                     # standby and cold run latency
flexvm bench --to 127.0.0.1:7131 --to-state S --to-run R --dirty-mib 500   # run + migrate to another host on this machine
flexvm bench --lifecycle --to-state S --to-run R                 # pause, checkpoint, restore, suspend
```

The other host's state (S) holds the same artifacts and templates (symlinks
to this host's do). Run `bench` from inside a Git checkout; it fails outside
one and writes reports to `bench/` at the Git top level. With `--dirty-mib`,
the guest reads its memory back before and right after the migration; `post_copy` has the difference
(`stall`) and the target's fault service per kind, including write-protect faults.
Run percentiles are split into `run_standby` and `run_cold` (with matching
`*_client` groups, and `ready_standby`/`ready_cold` with `--ready-port`); an
absent population is omitted. Phase percentiles use only
samples containing that phase and include a `count`. Lifecycle `pause_client`
and `resume_client` include signal dispatch and state polling at 1 ms intervals;
they are client-observed times, with each trial reporting ten cycles' median.
Lifecycle checkpoint sizes are in `checkpoint_data_mib`, grouped by dirty-memory
size with one value per completed trial, outside `summary_ms` and `samples_ms`.
A lifecycle `--dirty-mib` list that repeats a size is rejected. `host_context` has the
host's `loadavg` after the run and `loadavg_before` it.
On a failed trial or SIGINT/SIGTERM, bench cleans up owned VMs and checkpoints,
writes completed measured samples with `status: failed` and an `error`, then exits
with an error. Guest execs run in separate client processes, stopped and reaped on
cancellation; their signal waiters cannot bypass bench cleanup or accumulate in bench.
Guest read timings include the exec client's startup and exit.
Reports use `{date}-{sha7}-{run-id}[-lifecycle].json`, so same-second runs keep
separate reports. Successful reports have `status: ok`; warmups are never included.

| option | default | what |
|---|---|---|
| `--timeout SECONDS` | 120 (minimum 1) | timeout for state waits, background pulls and app readiness |
| `--iterations N` | 50; 5 with `--lifecycle` | measured trials (positive in both modes) |
| `--warmup N` | 3 | unmeasured trials before run benchmarks; rejected with `--lifecycle` |
| `--settle-ms MS` | 100 | sleep after each run trial, including warmups; rejected with `--lifecycle` |
| `--ready-port PORT` | none | wait for a TCP connection after each run; rejected with `--lifecycle` |
| `--ready-http PORT` | none | send `GET /` and wait for a response byte after each run; rejected with `--lifecycle`; mutually exclusive with `--ready-port` |

## Tests

`sudo scripts/e2e.py` is what CI runs on a KVM runner: the commands above
and a selection of `scripts/faults.py` scenarios (every failure path of
migration, checkpoints and suspend, by injected faults), in `--jobs` lanes at
once, each with two hosts of its own on loopback. Its `--shard` picks the
selection: `pr` (`main` and `recovery`: listener restarts, timeouts) runs on
every change, in four `--split`s side by side, `heavy` (GiB-scale guests)
nightly. A scenario that
finds the host lacks what it tests reports SKIP, never PASS; `--no-skips`
fails on one, as CI does. Its templates are pulled from the test image,
which `scripts/test-image.py` makes from the base root filesystem `fetch.sh`
downloads (Firecracker CI's ubuntu 24.04, with the python3, socat and
iproute2 the guests run) as an OCI layout with no command. `scripts/faults.py`,
`nettest.sh` and `test.sh` take a template of it, `small` by default (as the
`bench` example above does):

```sh
sudo scripts/test-image.py /var/lib/flexvm-test-image
sudo flexvm pull /var/lib/flexvm-test-image --tag small --vcpus 2 --max 2048
```
This root-owned location is also `e2e.py`'s default. Keep custom test image
paths under a root-owned directory so another user cannot supply the image.
`test-image.py` refuses non-empty output directories unless they contain both
`oci-layout` and `source.sha256`; it builds beside the output before replacing it.

`scripts/nettest.sh` migrates a VM back and forth under TCP and UDP traffic
between network namespaces and fails on a lost datagram or a long stall.

## How it works

- **A VM is a process.** It spawns its Firecracker (which dies with it), runs
  the userfaultfd pager that serves guest memory, owns its tap and route,
  and answers on a control socket (`/run/flexvm/vms/NAME.sock`: exec,
  checkpoint, migrate). Host-wide state (which names and addresses are in
  use, address generations, migration records) is in small flock-guarded
  files under `/var/lib/flexvm` and `/run/flexvm`.
- **Start** restores a template snapshot; memory is faulted in from a shared
  sparse image. Standby VMs are restored ahead of time.
- **Memory**: templates come with 4 GiB plugged (free until touched); past
  that the guest asks for more over vsock the moment it runs low, admitted
  against the host's reserve. The host holds each VM to what it admitted
  (`memory.high` on its cgroup), raised a step at a time as the guest touches
  memory: a VM refused more is throttled there, not killed, and moved to a
  peer with room. Freed pages go back through free page reporting.
- **Migration** is post-copy: the target is prepared first, then the source
  pauses, sends only vCPU and device state (~20-200 KiB), the target resumes
  and pulls pages on fault and in the background. Packets that arrive during
  the downtime are held and delivered. The source resumes only if the target
  says the migration aborted.
- **Checkpoints** write only pages that differ from the template, while the
  VM runs (copy-on-write through userfaultfd write protection).
- **Networking**: each VM has a /32 routed to its tap; peers get a route,
  the LAN a gratuitous ARP (proxy ARP), when it moves.

Design and internals: [docs/process-per-vm.md](docs/process-per-vm.md)
(processes, state, migration protocol, invariants) and
[docs/internals.md](docs/internals.md) (pager, checkpoint format,
copy-on-write, packet holds, clocks, Firecracker patches, measurements).

## Limits

- Until a migrated VM has pulled all its memory (~1 s per GB) it depends on
  both hosts.
- IPv4 only; peers form a full mesh; address ranges are per host and set by hand.
- The peer protocol is plain TCP, served to the peers' addresses only, without
  authentication: trusted networks only. A listed peer can claim any VM
  address for itself (as a newer revision or generation; see Migrate) and
  reserve this host's addresses and disk. It cannot point a route at another
  host, take an address a VM here holds, or bring this host's own addresses
  a generation this host did not hand out; only owner-signed generations
  would stop the rest.
- An address lent to a restore elsewhere expires if the restore does not
  claim it within five minutes; a peer can hold at most 64 loans whose VMs are
  not running yet. A claimed loan (or one to a host older than this release,
  which cannot claim) stays lent if the restore's host dies before it starts
  the VM: a leak, never a collision, and it counts against that limit.
- `exec` reaches VMs on this host; one that migrates away ends its exec
  saying where it went and exits 125 (the command keeps running there).
- Templates must be identical on every host (checked by content id), as
  must the CPU model and the Firecracker binary (see Setup).
- The templates directory is trusted like the binaries: whoever can write in
  it decides what VMs boot, by pointing `templates/NAME` elsewhere or editing a
  generation's `meta.json` (whose recorded hashes and file stamps decide what
  is re-hashed). Keep it, and its parents, root-owned and not group- or
  world-writable.
- `net.ipv4.ip_forward` is turned on host-wide and left on.
