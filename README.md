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
(`images/`) and VMs. The scripts install into it (with sudo); give them
`--state DIR` for another.

```sh
./scripts/build-firecracker.sh   # patched firecracker (needs musl-tools, libseccomp-dev)
./scripts/fetch.sh               # guest kernel 6.1, ubuntu 24.04 base (and stock firecracker, if none is built)
./scripts/build-rootfs.sh        # rootfs.ext4, and flexvm-init for image templates (needs squashfs-tools, e2fsprogs)
cargo build --release && sudo install target/release/flexvm /usr/local/bin/
sudo flexvm template default     # cold-boot and snapshot a template (default CPUs, ceiling = host RAM, 4 GiB plugged)
sudo flexvm run web
```

The host needs Linux 5.16+: Firecracker patch `0004` uses `KVM_VCPU_TSC_OFFSET`.

Hosts that migrate or restore each other's VMs need the same CPU model and
a byte-identical Firecracker: a snapshot records both (the binary by its
content hash), and any difference refuses it ("Firecracker differs"). Build
Firecracker once and copy `/var/lib/flexvm/artifacts` to every host rather than
building it on each. Replacing the binary also invalidates every template
built with the old one: rebuild them. Templates themselves must be identical
too (build once and copy `/var/lib/flexvm/templates`, or build from the same
inputs). A template pins its rootfs by path, so one built before the state
directory held the artifacts must be rebuilt.

flexvm runs as root (KVM, userfaultfd, routes, cgroups); commands below
assume that.

## Run a VM

```sh
flexvm run web                  # foreground: the VM's output here, Ctrl-Z pauses, Ctrl-C destroys
flexvm run web -d               # in the background; prints {"name", "ip", "pid", ...} once it answers
flexvm run job -- make test     # runs one command; exits with its status, the VM goes with it
flexvm run web --ip 10.200.0.9 --template small
```

```sh
flexvm ls                      # --json prints the list as JSON
NAME             IP              TEMPLATE   STATE             PID VCPU  RSS MiB  MAX MiB STARVED
web              10.200.0.1      default    running        41522   24       27    32000
```

| state | meaning |
|---|---|
| `running` | its vCPUs run |
| `paused` | stopped by SIGTSTP or Ctrl-Z (or held by `restore --paused`); SIGCONT resumes it |
| `checkpointing` | paused for a checkpoint's or a suspend's copy |
| `source` | migrating away: paused here until the target has its memory |
| `suspended` | on disk, no process (SIGTERM); `flexvm resume` brings it back |
| `quarantined` | a suspended VM that cannot be resumed (its address generation is unknown); `restore` its directory with a new name and `--ip auto`, or `flexvm kill` it |
| `failed` | died under its process (exit 124); `ls --json` (or `/run/flexvm/vms/NAME.failed`) says why, until `flexvm kill` |
| `lost` | ran here when the host went down (a reboot, or its process was SIGKILLed); its address is withdrawn, until `flexvm kill` |

Standby VMs are not listed: `flexvm standby` shows them.

```sh
flexvm exec web 'free -m'       # a shell command in the guest; exits with its status
```

As with ssh, the words of `run -- CMD` and `exec NAME CMD` are joined with
spaces for the guest's shell, so quote a command that has its own quoting:
`flexvm run job -- "sh -c 'echo -d'"`. Flags after `--` (or after `exec NAME`)
belong to CMD.

`-d` and `--detach` are equivalent for `run`, `restore`, and `resume`.

A background VM's output (an image app's stdout and stderr, flexvm's own
messages) goes to `/run/flexvm/vms/web.log`. Logs live on tmpfs: past
8 MiB, `NAME.log` becomes `NAME.log.1` (replacing the one before) and a new
one is started; the logs of a name with nothing left on
the host (no VM, suspended VM, `failed` or moved record) are removed once
unwritten for an hour, by sweeps that run when a VM starts and about every
30 s while a listener or any VM process runs. Logs do not survive a reboot.

## Pause, suspend, destroy

A VM is its process, so the usual signals work:

```sh
kill -TSTP 41522                # pause the vCPUs (memory kept); Ctrl-Z in the foreground
kill -CONT 41522                # resume; `flexvm resume web` does the same
kill 41522                      # SIGTERM: suspend to disk, free its memory, exit
flexvm resume web               # bring a suspended VM back (in a new process)
flexvm kill web                 # destroy it, running or suspended; Ctrl-C in the foreground
```

Ctrl-\ (SIGQUIT) destroys the VM like Ctrl-C. A VM paused with Ctrl-Z keeps
its terminal: resume it from another one with `flexvm resume web`.

A closed terminal (SIGHUP) leaves a foreground VM running; its output then
goes to `/run/flexvm/vms/NAME.log`.

Exit statuses of `flexvm run`: with `-- CMD`, CMD's own; 128 + the signal
that ended it (130: destroyed by SIGINT, Ctrl-C or `flexvm kill`; 143:
suspended by SIGTERM); 0 when it migrated away or `checkpoint --stop`
stopped it. flexvm's own failures use the range shells and container
runtimes keep for themselves: 125 when it could not start the VM (or gave it
up), 124 when the VM died under it (`flexvm ls` then shows it `failed`, and
`flexvm ls --json` why, until `flexvm kill`). Without `-- CMD` they are
the same, so a script can tell a VM that never ran (125) from one that did.

A VM migrating away stays paused on its source until the target has all its
memory; `flexvm kill` refuses that copy (kill the VM where it runs), and
`kill -KILL PID` gives it up (the target loses the pages it has not pulled).

A suspended VM keeps its name and address; `ls` shows it `suspended`.
`resume` restores a suspended VM in the foreground, even if it was originally
started with `-d`; use `flexvm resume web -d` to detach it again. A
`run -- CMD` VM suspends with its command, which keeps running once resumed:
the resumed process prints the rest of its output and exits with its status.
Resuming a paused VM leaves its existing process in place.

## Checkpoint and restore

```sh
flexvm checkpoint web /data/web-1                   # the VM runs on (paused ~20 ms)
flexvm checkpoint web /data/web-2 --incremental     # only what changed since the last one
flexvm checkpoint web /data/web-3 --stop            # and destroy it
flexvm restore /data/web-1                          # same name and address
flexvm restore /data/web-1 --name web2 --ip auto    # a fork, with a new address
flexvm restore /data/web-1 --paused                 # held until SIGCONT
```

A checkpoint restores on any host with the same template (by content id).
Restored on another host with its own address, the VM borrows the address
from its home host, which refuses one in use or lent out; `--ip auto` picks
a new one.

## Migrate

A host's settings are `flexvm config`'s, kept in `STATE/host.json` and
applied live: running VM processes and listeners pick up changes. A new
`--vm-ips` or `--dns` applies to addresses handed out and guests set up after
it (standby VMs' claims included); running VMs keep theirs. Each host
that takes migrations then runs a listener, which takes only its address
and can be socket-activated:

```sh
# host A (192.168.1.10) and host B (192.168.1.11) on one LAN; VMs use spare LAN addresses
flexvm config --peer 192.168.1.11:7070 --vm-ips 192.168.1.128-192.168.1.191 --dns 192.168.1.1   # on A
flexvm config --peer 192.168.1.10:7070 --vm-ips 192.168.1.192-192.168.1.250 --dns 192.168.1.1   # on B
flexvm listen 192.168.1.10:7070          # on A
flexvm listen 192.168.1.11:7070          # on B

flexvm migrate web 192.168.1.11:7070      # on A: web now runs on B, same address, connections intact
```

Networking is routed IPv4: flexvm provides no NAT or automatic internet
egress. Arrange upstream routes or NAT yourself if guests need it. There is
no default DNS server; configure one with `--dns IP`.

Every host's `--vm-ips` must be disjoint, and the hosts must list each other
with `--peer HOST:PORT` (each peer's listen address): a listener serves its
peers' addresses only, and tells any other it is not a peer. The default
range, `10.200.0.0/16`, is the same on every host, so give each host its own
once it has peers (`config` warns until then). `--peer` replaces the whole
list; an empty value (`--peer ''`, `--reserve ''`, ...) unsets a setting.
`flexvm config` alone prints what is set and what is derived for the rest:

- `--underlay IP`, the address peers route this host's VMs through: the listen
  address, or for a wildcard one the source address of the kernel's route
  toward the first peer not on this machine (`ip route get`, policy routing
  included). With every peer on this machine (loopback, or one of its
  addresses) it is loopback; with peers elsewhere, never.
- `--announce-dev IFACE`, where the host answers ARP for its VMs
  (`proxy_arp`) and announces a VM that arrives: that route's device, none
  for peers on this machine. `--announce-dev none` turns this off, for
  routed or WireGuard links.
- `--reserve MIB`, the memory a host keeps free (starts and growth that would
  take it below are refused): a sixteenth of the host's RAM, from 256 MiB to 4 GiB.
- `--evict-at MIB`: VMs start moving to peers with room once the host has less
  than this available, the fastest growing first, until it is back above the
  mark by half the mark's height over the reserve. Default: the reserve plus
  the reserve or 512, whichever is more. A peer takes such a VM only if it
  stays above its own mark; a mark under the reserve counts as the reserve.

Derived values are never saved: they follow the routes, the peers and the
host's RAM. A wildcard listener with peers elsewhere and no route toward them
fails, asking for `--underlay`.

Every VM process and listener sets `net.ipv4.ip_forward=1`, and
`proxy_arp` on the announce device, and never reverts them: the host routes
between all its interfaces from then on, so check its `FORWARD` policy.

A host that only runs VMs needs no listener, but see below for what recovers it after a reboot.

Taps are named after the state directory (`f` and five characters of its
hash, then the owning process's pid), so hosts on separate state directories
read apart. Each tap's alias (`ip link show`) names its owner, `flexvm PID
START RUN-DIR`: hosts sharing a network namespace only ever sweep their own taps.

### Under systemd

Run the listener as a socket-activated service (after `flexvm config`); without
ADDR it takes its address from the socket:

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
reboot, and the first flexvm process after one recovers the host. It
withdraws the addresses of the VMs it lost (telling the peers, so a home host
takes back an address it lent), lists those VMs as `lost`, puts back the
routes to VMs on peers, settles migrations the reboot interrupted, and
refills the standby VMs. Any flexvm command run as root does this too, but a
quiet host needs something to start; one without a listener can run
`flexvm recover` at boot:

```ini
# /etc/systemd/system/flexvm-recover.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/flexvm recover

[Install]
WantedBy=multi-user.target
```

The VM processes a listener starts (arrivals, standby VMs) move into
cgroups of their own (`/sys/fs/cgroup/flexvm/vm-PID-START`) as they start, and so
do VMs started with `-d` (`run`, `resume`, `restore`) and standby VMs from
any command. So stopping or restarting the unit, with the default
`KillMode=control-group`, stops only the listener; `KillMode=process` is not
needed. Likewise logind's `KillUserProcesses`, or the end of a
`Type=oneshot` unit that runs `flexvm run NAME -d`, leaves those VMs
running. A foreground `flexvm run NAME` stays in its caller's cgroup, so a
service whose `ExecStart` is one is supervised like any process: stopping it
sends SIGTERM, which suspends the VM to disk (give it `TimeoutStopSec` for
that), and `KillSignal=SIGINT` destroys it instead.

## Fast starts

```sh
flexvm standby 2                 # keep 2 VMs of the default template restored and paused
flexvm standby --template web 1
flexvm standby 0                 # none
```

`run` takes one (resume and set the address: ~5 ms) and a replacement starts.
Without one, `run` loads the snapshot (~50-100 ms). `flexvm standby` with no
count shows each template's count and how many standby VMs it has now. The
template must exist: a count is kept and refilled by every listener and VM
process, retried each minute (errors in `standby.log` in the `dir` that `flexvm standby` shows).
Standby sockets are `RUN/standby/HASH/PID.sock`, where HASH is the 16-hex hash
of the template's name. Claims carry the generation key; `.locks/PID-START.lock`
identifies the process while it lives. Socket paths must be under 108 bytes.

## Templates from container images

```sh
flexvm template web --image nginx:1.27                       # any registry
flexvm template app --image ./app.tar --env PORT=8080        # `docker save` output or an OCI archive
flexvm template py --image ./oci-layout --cmd "python3 -m http.server 8000"
flexvm template web-warm --image nginx:1.27 --warm           # snapshot the app running and ready
flexvm run web1 --template web -d && curl http://<ip>/
```

Overrides follow `docker run`: `--entrypoint`, `--cmd`, `--env K=V`,
`--workdir`, `--user`. `--warm` snapshots the app once it is ready
(`--ready-port N` or `--ready-cmd CMD`); every VM from a warm template starts
with the same userland state (RNG seeds, keys), so use it only for apps that
hold no secrets at startup. Details: [docs/images.md](docs/images.md).

## Paths and knobs

| flag | default | what |
|---|---|---|
| `--state DIR` | `/var/lib/flexvm` | everything on disk: `artifacts/` (`firecracker`, `vmlinux`, `rootfs.ext4`, `flexvm-init`), `templates/`, `images/` (pulled container images), `staging/` (where image layers unpack: root-owned, see [docs/images.md](docs/images.md)), host configuration, addresses, suspended VMs |
| `--run DIR` | `/run/flexvm` (another `--state`'s: `/run/flexvm-PREFIX`) | registry, sockets, logs (tmpfs) |

`template --image` runs `STATE/artifacts/flexvm-init` as PID 1 (`--init PATH`
for another). Several hosts on one machine (tests, benchmarks) each take a `--state` and
`--run` of their own; their `artifacts` and `templates` can be symlinks to one
host's. On first open, each state directory permanently records its canonical run
path in `run.json`, and the run directory records its state in `state.json`; using
either with a different partner is refused. Without `--run`, a state uses the run
directory its `run.json` names, so after a reboot another state never takes it.
`FLEXVM_FAULTS=1` enables test fault injection only. The state layout is in
[docs/process-per-vm.md](docs/process-per-vm.md#on-disk-state).

## Benchmarks

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
fails on one, as CI does.
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
  saying where it went and exits 1 (the command keeps running there).
- Templates must be identical on every host (checked by content id), as
  must the CPU model and the Firecracker binary (see Setup).
- The templates directory is trusted like the binaries: whoever can write in
  it decides what VMs boot, by pointing `templates/NAME` elsewhere or editing a
  generation's `meta.json` (whose recorded hashes and file stamps decide what
  is re-hashed). Keep it, and its parents, root-owned and not group- or
  world-writable.
- `net.ipv4.ip_forward` is turned on host-wide and left on.
