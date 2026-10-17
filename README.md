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
(`images/`), VMs and the host's configuration (`host.json`).

```sh
cargo build --release && sudo install target/release/flexvm /usr/local/bin/
sudo flexvm pull ubuntu:24.04    # pull an image; its template is a cold boot of it, snapshotted (needs e2fsprogs)
sudo flexvm run ubuntu:24.04     # a VM of it (pulled first if missing), in the foreground
```

flexvm-init (the guest's PID 1 and agent) is built by the same `cargo build`
and embedded in the binary. The patched Firecracker and the guest kernel are
prebuilt: the first command that needs them downloads them into
`artifacts/` from the release this build pins (`ARTIFACTS_TAG` in
`scripts/versions.sh`) and checks them against the sha256 pinned in
`scripts/checksums.sha256`. A file already there is never downloaded or
replaced.

To build your own, or for a host without network access, put the files in
`artifacts/` first (the scripts install with sudo; give them `--state DIR`
for another state directory, then copy it over):

```sh
./scripts/build-firecracker.sh   # patched firecracker (needs musl-tools, libseccomp-dev)
./scripts/fetch.sh               # guest kernel and the release's firecracker (if none is built), and the tests' base rootfs
```

`FLEXVM_ARTIFACTS_URL` points the download at a mirror of the release (the
same pins apply). A new release of the artifacts is cut by pushing the tag
`scripts/versions.sh` names (`.github/workflows/release.yml` builds and
publishes it), then pinning it with `scripts/pin-artifacts.sh` in a
follow-up commit.

The host needs Linux 5.16+: Firecracker patch `0004` uses `KVM_VCPU_TSC_OFFSET`.

Hosts that migrate or restore each other's VMs need the same CPU model and
a byte-identical Firecracker: a snapshot records both (the binary by its
content hash), and any difference refuses it ("Firecracker differs"). Builds
pinning the same release download the same binary; a Firecracker of your own
is built once and copied to every host (`/var/lib/flexvm/artifacts`) rather than
built on each. Replacing the binary also invalidates every template
built with the old one: pull them again. Templates themselves must be identical
too (pull once and copy `/var/lib/flexvm/templates` and `images/rootfs`, or pull
the same image by digest with the same options). A template pins its image's
root filesystem by path, so one pulled into another state directory must be
pulled again.

flexvm runs as root (KVM, userfaultfd, routes, cgroups); commands below
assume that.

## Run a VM

The commands follow Docker's where they can. There is no daemon: `run` is
the VM's process, and the other commands find VMs by name in the state
directory.

```sh
flexvm run ubuntu:24.04                      # foreground: the VM's output here, Ctrl-Z pauses, Ctrl-C destroys
flexvm run -d --name web nginx:1.27          # in the background; prints {"name", "ip", "pid", ...} once it runs
flexvm run --name job ubuntu:24.04 make test # runs one command; exits with its status, the VM goes with it
flexvm run -d --ip 10.200.0.9 --cpus 2 --memory 8g nginx:1.27
```

`run` pulls an image it does not find here first, as `docker run` does.
Without `--name` it makes one up (`epic_yalow`, as Docker does; one
another run takes meanwhile is made up again); the
JSON `-d` prints, and `flexvm ps`, give it. The options go before the image:
every word after it is the command.

`--cpus N` caps the VM's CPU time at N CPUs (`1.5`: one and a half; a
`cpu.max` quota on its Firecracker's cgroup, set before the VM runs); it
still has its image's vCPUs. A host without the cgroup cpu controller refuses
a start (or an arrival) with `--cpus` rather than run it uncapped.
`--memory SIZE` (`512m`, `2g`; a plain number is bytes, as in Docker) caps
how far the VM grows: from its image's boot memory plus what its snapshot
plugged (a VM never shrinks below that) up to the image's ceiling. A value
outside that is refused, saying the range. vCPU count and boot memory are
fixed in the snapshot, so they are pull options (see Images). Both caps stay
with the VM through `stop`/`start`, checkpoints and migrations; `run
--checkpoint` with either sets that one anew.

```sh
flexvm ps                       # running VMs; -a: stopped ones too; --json: all of it
NAME                     IP              IMAGE            STATE             PID  CPUS  RSS MiB  MAX MiB STARVED
web                      10.200.0.1      nginx:1.27       running         41522     2       27     8192
```

| state | meaning |
|---|---|
| `running` | its vCPUs run |
| `paused` | stopped by `flexvm pause`, SIGTSTP or Ctrl-Z (or held by `run --checkpoint --paused`); `flexvm unpause` resumes it |
| `checkpointing` | paused for a checkpoint's or a suspend's copy |
| `source` | migrating away: paused here until the target has its memory |
| `suspended` | stopped: on disk, no process (`flexvm stop`, SIGTERM); `flexvm start` brings it back |
| `quarantined` | a stopped VM that cannot be started (its address generation is unknown); `run --checkpoint` its directory with a new name and `--ip auto`, or `flexvm rm` it |
| `failed` | died under its process (exit 124); `ps -a --json` (or `/run/flexvm/vms/NAME.failed`) says why, until `flexvm rm` |
| `lost` | ran here when the host went down (a reboot, or its process was SIGKILLed); its address is withdrawn, until `flexvm rm` |

The last four are stopped: `ps` lists them with `-a`. Standby VMs are not
listed: `flexvm images` counts them.

```sh
flexvm exec web 'free -m'       # a shell command in the guest; exits with its status
```

As with ssh, the words of `run IMAGE CMD` and `exec NAME CMD` are joined
with spaces for the guest's shell, so quote a command that has its own
quoting: `flexvm run ubuntu:24.04 "sh -c 'echo -d'"`. Flags after IMAGE (or
after `exec NAME`) belong to CMD; a `--` there is dropped.

A background VM's output (an image app's stdout and stderr, flexvm's own
messages) goes to `/run/flexvm/vms/web.log`. Logs live on tmpfs: past
8 MiB, `NAME.log` becomes `NAME.log.1` (replacing the one before) and a new
one is started; the logs of a name with nothing left on
the host (no VM, stopped VM, `failed` or moved record) are removed once
unwritten for an hour, by sweeps that run when a VM starts and about every
30 s while a listener or any VM process runs. Logs do not survive a reboot.

## Stop, start, pause, kill, rm

```sh
flexvm stop web                 # suspend to disk and free its memory; the process exits (as SIGTERM)
flexvm start web                # bring it back, in the background (-a: in the foreground)
flexvm pause web                # pause the vCPUs, memory kept (as SIGTSTP; Ctrl-Z in the foreground)
flexvm unpause web              # resume them (as SIGCONT)
flexvm kill web                 # destroy a running VM (as SIGINT; Ctrl-C or Ctrl-\ in the foreground)
flexvm rm web                   # remove a stopped VM (suspended, quarantined, failed, lost)
flexvm rm -f web                # destroy it, running or not
```

As in Docker, `kill` is for a running VM and `rm` for a stopped one: `kill`
of a stopped VM and `rm` of a running one are refused, saying so, and `rm -f`
does either. `stop`, `start`, `pause`, `unpause`, `kill` and `rm` take
several names, go on past one that fails, and print each name done (`start`
prints the VM's JSON instead). A VM is its process, so the signals in
parentheses work as well, sent to the pid `ps` shows.

A stopped VM keeps its name and address. `start` restores it in a new
process, in the background whether it first ran in the foreground or with
`-d`; `start -a` brings it back in the foreground. A `run IMAGE CMD` VM stops with its
command, which keeps running once started again: `start -a` prints the rest
of its output and exits with its status. `start` of a paused VM unpauses it;
`start -a` attaches only to a VM it starts, so it refuses a running or paused
one (`unpause` that), after waiting out a stop under way.

A closed terminal (SIGHUP) leaves a foreground VM running; its output then
goes to `/run/flexvm/vms/NAME.log`.

Exit statuses of `flexvm run` and `flexvm start -a`: with CMD, CMD's own;
128 + the signal that ended it (130: destroyed by SIGINT, Ctrl-C or
`flexvm kill`; 143: stopped, by `flexvm stop` or SIGTERM); 0 when it
migrated away or `checkpoint --stop` stopped it. flexvm's own failures use
the range shells and container runtimes keep for themselves: 125 when it
could not start the VM (or gave it up; also for `run -d` and `start`), 124
when the VM died under it (`flexvm ps -a` then shows it `failed`, and `ps -a
--json` why, until `flexvm rm`). Without CMD they are the same, so a script
can tell a VM that never ran (125) from one that did. `flexvm exec` returns
the command's status, or 125 for flexvm's own failures. Other commands exit
1 when they fail.

`flexvm reclaim IP` explains the loan and prints `flexvm reclaim IP --force GEN`
with its current generation. After checking that no host still runs that VM,
use that command to withdraw the loan. It refuses if the lent generation changed.

A VM migrating away stays paused on its source until the target has all its
memory; `flexvm kill` refuses that copy (kill the VM where it runs), and
`kill -KILL PID` gives it up (the target loses the pages it has not pulled).

## Checkpoint and restore

```sh
flexvm checkpoint web /data/web-1                   # the VM runs on (paused ~20 ms)
flexvm checkpoint web /data/web-2 --incremental     # only what changed since the last one
flexvm checkpoint web /data/web-3 --stop            # and destroy it
flexvm run --checkpoint /data/web-1                 # same name and address
flexvm run -d --checkpoint /data/web-1 --name web2 --ip auto   # a fork, with a new address
flexvm run --checkpoint /data/web-1 --paused        # held until flexvm unpause
```

A checkpoint restores on any host with the same template (by content id).
Restored on another host with its own address, the VM borrows the address
from its home host, which refuses one in use or lent out; `--ip auto` picks
a new one.

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
| `listen` | none | this host's listen address; `flexvm listen ADDR` saves it |

Every command checks the file as it loads it (`Config::validate`): a key it
does not know, a malformed address or range, a `peers` entry that is not
`HOST:PORT`, a `peer_underlays` address that is local or not unicast, a
non-IPv4 `dns`, or a `vm_ips` not inside `cluster_ips` makes every command
refuse to start, naming the file and the problem, until it is fixed. A
running process keeps the last valid configuration meanwhile, so an edit
mid-write is never taken. Write it whole (an editor's save, or a temporary
file renamed over it); it must be a regular file, not a link, that no one
but its owner (root) may write. A new `vm_ips` or `dns` applies to
addresses handed out and guests set up after it (standby VMs' claims
included); running VMs keep theirs.

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
generation: it migrated on) or a newer generation. The hosts must list each
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
  address because it is on-link. Each must be unicast and not this host's.
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
  own; a mark under the reserve counts as the reserve.

Derived values are never saved: they follow the routes, the peers and the
host's RAM. A wildcard listener with peers elsewhere and no route toward them
fails, asking for `underlay`.

Every VM process and listener sets `net.ipv4.ip_forward=1`, and
`proxy_arp` on the announce device, and never reverts them: the host routes
between all its interfaces from then on, so check its `FORWARD` policy.

A host that only runs VMs needs no listener, but see below for what recovers it after a reboot.

Taps are named after the state directory (`f` and five characters of its
hash, then the owning process's pid), so hosts on separate state directories
read apart. Each tap's alias (`ip link show`) names its owner, `flexvm PID
START RUN-DIR`: hosts sharing a network namespace only ever sweep their own taps.

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
cgroups of their own (`/sys/fs/cgroup/flexvm/vm-PID-START`) as they start, and so
do VMs started with `-d` (`run -d`, `start`, `run -d --checkpoint`) and
standby VMs from any command. So stopping or restarting the unit, with the default
`KillMode=control-group`, stops only the listener; `KillMode=process` is not
needed. Likewise logind's `KillUserProcesses`, or the end of a
`Type=oneshot` unit that runs `flexvm run -d IMAGE`, leaves those VMs
running. A foreground `flexvm run IMAGE` (or `start -a`) stays in its
caller's cgroup, so a service whose `ExecStart` is one is supervised like any
process: stopping it sends SIGTERM, which suspends the VM to disk (give it
`TimeoutStopSec` for that), and `KillSignal=SIGINT` destroys it instead.

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
first. Standby sockets are `RUN/standby/HASH/PID.sock`, where HASH is the
16-hex hash of the template's name. Claims carry the generation key, the
VM's `--cpus`/`--memory` caps (checked against the standby's template), and
`.locks/PID-START.lock` identifies the process while it lives. Socket paths
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
flexvm rmi nginx:1.27                                   # refused while a VM here uses it
```

`pull` fetches an image (a native registry client; no docker needed), builds
its root filesystem with flexvm-init as PID 1, cold-boots a VM of it and
snapshots it once its agent answers: that snapshot, the image's *template*,
is what every `run` restores. The image's entrypoint and command start at
`run`; an image with neither has no app, and its VMs idle until told what to
run (`exec`, `run IMAGE CMD`). ubuntu:24.04's command is `bash`, which exits at
once without a terminal: its VMs log that and idle.

**Names.** A template is named after its image reference, resolved as
`docker pull` does (`ubuntu` is `docker.io/library/ubuntu:latest`), in
Docker's short form without a `:latest` tag and with `/` written `+` (which no
reference has, so the name gives the reference back): `ubuntu:24.04`,
`nginx`, `ghcr.io+org+app:v1`, `ghcr.io+org+app@sha256:...`. `run` and
`rmi` take any spelling of the reference, or the name. `--tag NAME[:TAG]`
names it otherwise: an archive or layout directory needs one, and so does an
image built with other options alongside its plain pull.

**Pulling again** asks the registry again. If the image (its manifest), the
options, the sizes, the kernel, Firecracker and flexvm's build recipe are the
same, the template is up to date and nothing is built. Otherwise (a tag that
moved, say) a new template generation is built and the name moves to it:
running and suspended VMs, checkpoints and migrations of the old one keep
using it (they name it by content id), and standby VMs of the old one are
replaced from the new. The old generation stays, listed as `<none>` by
`images`, until `flexvm rmi ID` removes it.

**Removing.** `rmi IMAGE` removes the name and, unless a VM here still uses
them, its generation and its root filesystem (`images/rootfs/`); `rmi ID` (or
a unique prefix of it) removes a `<none>` generation. Both are refused while a
VM here (running, paused or stopped) uses the image; `rmi IMAGE` sets its
standby count to 0 and waits for its standby VMs to go first. Checkpoints elsewhere that pin a removed
generation cannot be restored here any more. Layer blobs (`images/blobs/`)
are a download cache and stay.

**Sizes** are fixed in the snapshot, so they are pull options (`run --cpus`
and `--memory` cap a VM below them):

| option | default | what |
|---|---|---|
| `--vcpus N` | host CPUs, at most 32, rounded down to even | vCPUs (Firecracker cannot add vCPUs to a running VM) |
| `--max MIB` | host RAM | memory ceiling: boot memory plus the hot-plug region, in whole 1 GiB slots |
| `--mem MIB` | 256 + max/32, rounded up to 128 | boot memory, which holds kernel memory for the whole ceiling |
| `--plug MIB` | 4096 | plugged in the snapshot (free until touched); a VM never shrinks below it |

Overrides follow `docker run`: `--entrypoint`, `--cmd`, `--env K=V`,
`--workdir`, `--user`. `--warm` snapshots the app once it is ready
(`--ready-port N` or `--ready-cmd CMD`); every VM from a warm template starts
with the same userland state (RNG seeds, keys), so use it only for apps that
hold no secrets at startup. Details: [docs/images.md](docs/images.md).

## Paths and knobs

| flag | default | what |
|---|---|---|
| `--state DIR` | `/var/lib/flexvm` | everything on disk: `host.json` (see Configuration), `artifacts/` (`firecracker`, `vmlinux`; `base.squashfs`, the tests' base rootfs), `templates/` (a link per image name to its current generation in `templates/.gen/`), `images/` (layer blobs and image root filesystems), `staging/` (where image layers unpack: root-owned, see [docs/images.md](docs/images.md)), addresses, stopped VMs |
| `--run DIR` | `/run/flexvm` (another `--state`'s: `/run/flexvm-PREFIX`) | registry, sockets, logs (tmpfs) |

`pull` writes the flexvm-init built into flexvm into the image as PID 1 (`--init PATH`
for another). Several hosts on one machine (tests, benchmarks) each take a `--state` and
`--run` of their own; their `artifacts` and `templates` can be symlinks to one
host's. On first open, each state directory permanently records its canonical run
path in `run.json`, and the run directory records its state in `state.json`; using
either with a different partner is refused. Without `--run`, the run directory follows
from the state's path alone (`/run/flexvm` for `/var/lib/flexvm`, `/run/flexvm-PREFIX` for
any other), so after a reboot no state defaults into another's; a state bound to any other
run directory must be given it. `/run/flexvm` belongs to `/var/lib/flexvm` alone: any other state is
refused it, even with `--run`.
`FLEXVM_FAULTS=1` enables test fault injection only. The state layout is in
[docs/process-per-vm.md](docs/process-per-vm.md#on-disk-state).

## Benchmarks

For flexvm's development:

```sh
flexvm bench --template small                                     # standby and cold run latency
flexvm bench --to 127.0.0.1:7131 --to-state S --to-run R --dirty-mib 500   # run + migrate to another host on this machine
flexvm bench --lifecycle /data/ckpt --to-state S --to-run R      # pause, checkpoint, restore, suspend
```

The other host's state (S) holds the same artifacts and templates (symlinks
to this host's do). Reports land in `bench/`. With `--dirty-mib`, the guest reads its memory
back before and right after the migration; `post_copy` has the difference
(`stall`) and the target's fault service per kind, including write-protect faults.
Run percentiles are split into `run_standby` and `run_cold` (with matching
`*_client` groups, and `ready_standby`/`ready_cold` with `--ready-port`); an
absent population is omitted. Phase percentiles use only
samples containing that phase and include a `count`. Lifecycle `pause_client`
and `resume_client` include signal dispatch and state polling at 1 ms intervals;
they are client-observed times, with each trial reporting ten cycles' median.

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
sudo scripts/test-image.py /var/tmp/test-image
sudo flexvm pull /var/tmp/test-image --tag small --vcpus 2 --max 2048
```
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
  authentication: trusted networks only.
- An address lent to a restore elsewhere stays lent if that restore's host
  dies before it starts the VM (a leak, never a collision).
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
