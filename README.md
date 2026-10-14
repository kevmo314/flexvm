# flexvm

Elastic Firecracker microVMs. A VM sees every host CPU and a memory ceiling of
host RAM, but only uses what it touches. It starts in about 5 ms, pauses,
checkpoints and suspends to disk, and live-migrates to another host
(post-copy) in tens of milliseconds, keeping its address and TCP connections.

There is no daemon. `flexvm run` starts a process that *is* the VM: kill the
process and the VM is gone, send it a signal and the VM pauses or suspends.

## Setup

```sh
./scripts/fetch.sh               # firecracker, guest kernel 6.1, ubuntu 24.04 base
./scripts/build-firecracker.sh   # patched firecracker -> artifacts/firecracker (needs musl-tools, libseccomp-dev)
./scripts/build-rootfs.sh        # artifacts/rootfs.ext4, and artifacts/flexvm-init for image templates
cargo build --release
sudo ./target/release/flexvm template default   # cold-boot and snapshot a template (all CPUs, ceiling = host RAM, 4 GiB plugged)
```

flexvm runs as root (KVM, userfaultfd, routes, cgroups). Commands below
assume `flexvm` is on the PATH and `FLEXVM_ARTIFACTS` points at `artifacts/`.
sudo drops `FLEXVM_ARTIFACTS`: keep it with `sudo --preserve-env=FLEXVM_ARTIFACTS`
(`sudo -E` is refused by some sudo builds, e.g. sudo-rs), or pass `--artifacts DIR`;
without either, the default is `./artifacts` relative to the working directory.

## Run a VM

```sh
flexvm run web                  # foreground: the VM's output here, Ctrl-Z pauses, Ctrl-C destroys
flexvm run web -d               # in the background; prints {"name", "ip", "pid", ...} once it answers
flexvm run job -- make test     # runs one command; exits with its status, the VM goes with it
flexvm run web --ip 10.200.0.9 --template small
```

```sh
flexvm ls                      # --json prints the list as JSON
NAME             IP              TEMPLATE   STATE             PID VCPU  RSS MiB  MAX MiB
web              10.200.0.1      default    running        41522   24       27    32000
```

```sh
flexvm exec web 'free -m'       # a shell command in the guest; exits with its status
```

As with ssh, the words of `run -- CMD` and `exec NAME CMD` are joined with
spaces for the guest's shell, so quote a command that has its own quoting:
`flexvm run job -- "sh -c 'echo -d'"`. Flags after `--` (or after `exec NAME`)
belong to CMD.

`-d` and `--detach` are equivalent for `run`, `restore`, and `resume`.

A background VM's output (an image app's stdout and stderr, flexvm's own
messages) goes to `/run/flexvm/vms/web.log`.

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
why, until `flexvm kill`).

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

Each host that takes migrations runs a listener; its flags are the host's
configuration (kept in `/var/lib/flexvm/host.json`). It is an optional
helper, and can be socket-activated:

```sh
# host A (192.168.1.10) and host B (192.168.1.11) on one LAN; VMs use spare LAN addresses
flexvm listen 192.168.1.10:7070 --peer 192.168.1.11:7070 --announce-dev eth0 \
    --vm-ips 192.168.1.128-192.168.1.191 --dns 192.168.1.1
flexvm listen 192.168.1.11:7070 --peer 192.168.1.10:7070 --announce-dev eth0 \
    --vm-ips 192.168.1.192-192.168.1.250 --dns 192.168.1.1

flexvm migrate web 192.168.1.11:7070      # on A: web now runs on B, same address, connections intact
```

Networking is routed IPv4: flexvm provides no NAT or automatic internet
egress. Arrange upstream routes or NAT yourself if guests need it. There is
no default DNS server; configure one with `flexvm listen ... --dns IP`.

Every host's `--vm-ips` must be disjoint, and the hosts must list each other
with `--peer`: a listener serves its peers' addresses only. `--reserve MIB`
(default 1024) is the memory a host keeps free: starts and growth that would
take it below are refused. VMs start moving to peers with room earlier, once
the host has less than `--evict-at MIB` available (default: the reserve
plus the reserve or 512, whichever is more), the fastest growing first,
until it is back above the mark by half the mark's height over the reserve. Running VMs pick up both from
`host.json` as it changes.

## Fast starts

```sh
flexvm standby 2                 # keep 2 VMs of the default template restored and paused
flexvm standby --template web 1
flexvm standby 0                 # none
```

`run` takes one (resume and set the address: ~5 ms) and a replacement starts.
Without one, `run` loads the snapshot (~50-100 ms).

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

## Benchmarks

```sh
flexvm bench --template small                                     # run latency
flexvm bench --to 127.0.0.1:7131 --to-state S --to-run R --dirty-mib 500   # run + migrate to another host on this machine
flexvm bench --lifecycle /data/ckpt --to-state S --to-run R      # pause, checkpoint, restore, suspend
```

Reports land in `bench/`. With `--dirty-mib`, the guest reads its memory
back before and right after the migration; `post_copy` has the difference
(`stall`) and the target's fault service per kind.

## Tests

`sudo scripts/e2e.py` is what CI runs on a KVM runner: the commands above
and a selection of `scripts/faults.py` scenarios (every failure path of
migration, checkpoints and suspend, by injected faults), in `--jobs` lanes at
once, each with two hosts of its own on loopback.
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
- Templates must be identical on every host (checked by content id).
