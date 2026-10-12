# flexvm

Elastic Firecracker microVMs. A VM never reserves a size: it sees every host
CPU and a memory ceiling equal to host RAM, but only uses what it touches.
When a host gets tight, the VM is live-migrated (post-copy) to a roomier host
in tens of milliseconds.

## How it works

| Concern | Mechanism |
|---|---|
| CPU | vCPUs = host cores (FC max 32). Idle vCPUs halt and cost nothing; fairness via a per-VM cgroup (`cpu.weight`). |
| Memory growth | 256 MiB base + a virtio-mem region up to host RAM. The daemon hot-plugs 128 MiB slots when the guest's available memory drops below 25% (min 256 MiB), and unplugs when it has lots spare. |
| Memory return | virtio-balloon **free page reporting**: pages the guest frees go back to the host within seconds. |
| Root filesystem | One read-only ext4 image on virtio-pmem with DAX, shared by every VM through the host page cache. Writes go to a tmpfs overlay inside the guest, so they migrate with memory. |
| Start | Every VM is a **UFFD restore of a template snapshot** into a pre-spawned, pre-cgrouped Firecracker. The template's recorded working set is copied in bulk; everything else is faulted in lazily from a shared, sparse template image. |
| Migration | **Post-copy**: pause, save vCPU and device state only (~20–200 KiB), resume on the target, then the target's pager fetches pages from the paused source on fault and in the background. The source releases the VM once every page has arrived, and never resumes it once the target may own it. |
| Pressure | If a VM needs to grow and the host would drop below `--reserve`, or the host is already below it, the daemon migrates that VM to the peer with the most spare memory. |
| Network | Each VM has its own IPv4 /32 routed to a per-VM tap. The address moves with the VM, so open TCP connections survive migration. See below. |
| Container images | `flexvm template NAME --image REF` builds the root filesystem from an OCI/Docker image; flexvm-init runs and supervises its entrypoint. See below. |

### Pages

The userfaultfd pager (`flexvm/src/uffd.rs`) tracks every guest page as
`BASE` (template), `ZERO` (discarded by balloon or virtio-mem), `REMOTE` (on
the migration source), `INFLIGHT` or `PRESENT`. A migration target needs only
the run-length list of PRESENT and ZERO pages; the source serves PRESENT pages
straight out of the paused Firecracker with `process_vm_readv`. No memory file
is written, so the pause does not grow with VM size.

Every install (fault, prefetch, background pull) first claims its pages
(`INFLIGHT`). A balloon or virtio-mem REMOVE on a claimed page marks it
`DISCARDED`, so the installer skips it instead of copying stale bytes in or
marking it PRESENT; failed fetches and copies give their claims back. Copies
hold a lock that REMOVE handling takes exclusively, and the kernel fails copies
while a REMOVE is queued, so no data lands in a page the guest has just given
back. The kernel's zap itself can still come after a page settled PRESENT, so a
fault on a PRESENT page zero-fills it if it is missing. A checkpoint stops prefetch and waits for claims to
settle before exporting page states, so they match the saved vmstate. If the
migration source stays unreachable for 10 s (fetches reconnect with backoff
until then), the target kills the VM and reports it `failed`.

Pausing Firecracker stops only the vCPUs, so before the state-only snapshot the
source also brings the VM's tap down (no RX into guest memory), closes host
exec sessions (vsock) and parks the balloon statistics timer; the target and an
aborted source put the timer back.

### Lifecycle: pause, checkpoint, restore, suspend

```
starting -> running <-> paused                     (pause / resume)
running | paused -> checkpointing -> running | paused | gone   (checkpoint [--stop])
running | paused -> checkpointing -> suspended -> running      (suspend / resume)
running | paused -> source (migrating) -> gone, or back if the target aborted
any -> failed (memory lost) -> gone                (kill)
```

Every lifecycle operation (and each controller resize) first reserves the
VM's name, so operations on one VM never interleave; the controller skips a
VM that is busy, paused or suspended.

- **pause / resume** stop and restart the vCPUs; memory and devices stay.
  Both take under a millisecond (2 vCPU) to 1.5 ms (24 vCPU).
- **checkpoint NAME DIR** pauses the VM, quiesces its devices and pager like a
  migration source does (a VM still pulling memory from a migration source or
  checkpoint finishes that first), saves the vCPU/device state and writes
  every page that differs from the template into DIR, then resumes the VM
  (`--keep-running`, the default) or kills it (`--stop`). The pause lasts as
  long as the write (about 0.4 GB/s here).
- **restore DIR** works on any host whose template has the same content id.
  It loads the saved state into a pooled Firecracker whose pager takes
  pages from the checkpoint's page file: on fault, and in the background
  (the template's working set first) until all are in, so the VM is ready
  in about the time of a `run`. By default the VM keeps its name and
  address; a restore refuses an address a peer is using (`--ip auto` picks a
  new one, which also makes a restore a fork of a running VM).
- **suspend** checkpoints into the daemon's `--state-dir` (default
  `/var/lib/flexvm/<listen>`; it must be on disk, not tmpfs) and then kills
  Firecracker, so the VM costs no memory. Memory is released only once the
  checkpoint is durable, and the pager is stopped before Firecracker dies,
  so no discard event can mark a saved page as zero. `resume` restores it
  lazily like `restore`, and deletes the checkpoint once every page is in. Suspended
  VMs survive a daemon restart.
- **Clock.** A restored guest's wall clock resumes from when it was saved: the
  guest uses the TSC clocksource, whose saved value Firecracker restores
  (`clock_realtime` only moves kvmclock). A restore or a suspended VM's
  resume steps the guest clock to the host's (measured with one bracketed
  exec, corrected relative to the guest's own clock, residual error of a few
  ms). Across a plain pause the TSC keeps counting, so the clock stays right
  (measured: 0 ms drift after 20 s); `resume` still checks it in the
  background. A paused VM can also be **migrated**: it stays paused on the
  target, which pulls all its pages from the source with nothing faulting.

#### Checkpoint format (version 1)

A checkpoint is a directory that is written in full or not at all. Every file
goes into a fresh `.NAME.partial-<pid>-<n>` directory next to the target and is
fsynced. The directory is then renamed into place (`RENAME_NOREPLACE`;
checkpoints are never overwritten or modified) and the parent fsynced. A
later checkpoint to the same place clears partial directories that a dead
daemon left behind.

| file | contents |
|---|---|
| `manifest.json` | line 1: checksum of the rest; then JSON with the format version, name, address, template name and content id, machine (vCPUs, base/max/hotplugged MiB), guest page count, page counts and the length and checksum of each file |
| `vmstate` | Firecracker's state-only snapshot |
| `pagemap` | `FVPGMAP1`, then runs `(first page, count, DATA\|ZERO)` and one checksum per 64-page block of `pages` |
| `pages` | DATA pages back to back, in guest page order |

Pages the pager has PRESENT are a superset of what changed (template pages
read in by prefetch are PRESENT too). The writer therefore compares each page
with the template and with zero. A page equal to the template (or zero over a
template hole) is BASE and is not stored. Zero over template data is a ZERO
run, and anything else is DATA. A restore checks the manifest, `vmstate` and
`pagemap` before it loads anything, and checks every block of `pages` as it
reads it. A bad block fails the VM (it is killed) rather than letting it run on wrong memory. The
checksum is the 64-bit content hash used for template ids. It catches
corruption, but not deliberate tampering. A checkpoint belongs to the owner of
the directory it was written into.

### Migration ownership

Each migration has a random id. Once the target may have received the vmstate,
the source never resumes on its own: it resumes only on an explicit refusal, or
when the target, asked about that id, says it aborted (asking also fences the
id off, so it can never start later). If the target committed, the source stays
paused and serves memory until the target releases it with the same id;
release is idempotent and ignores any other VM by that name. If the target
cannot be asked, the VM stays paused on the source until it can. A daemon
locks its run directory (refusing to start if another daemon uses it, or one
inside or around it) and kills any Firecracker a previous instance left there,
confirming each is dead, before it answers anything, so "never seen this id" is true of a restarted target too
(a source resuming then rolls the VM back to the pause point; it never runs
twice).

`FLEXVM_FAULTS=1` lets a daemon accept `{"op": "fault", "fault": F, "ms": N}`
(`pages`, `route`, `lost_ack`, `status`); `scripts/faults.py` uses it to check
each failure path.

### Networking

```
 guest eth0 192.168.100.128/32 ── tap (host) ── route 192.168.100.128/32 dev tap
   gateway 169.254.1.1, MAC pinned           peers: route 192.168.100.128/32 via <host>
   (identical in every VM)                   LAN:   host answers ARP for it (proxy ARP)
```

- Every guest's network setup is the same except for its address. The gateway
  is a fixed link-local address whose MAC is pinned in the guest, and every
  tap uses that MAC. So clones of one template need no per-VM changes beyond
  `NET <ip>`, which the guest agent applies with one rtnetlink message.
- Taps are created ahead of time with the pooled Firecracker processes. The
  host route and a permanent neighbour entry are set with rtnetlink while the
  snapshot loads, so networking adds nothing to start time.
- Addresses come from the daemon's `--vm-ips` range. Before handing one out,
  the daemon checks it against its peers' addresses. `flexvm run --ip` picks
  one explicitly.
- Reachability:
  - **Peers** get a route pushed to them: `<vm-ip>/32 via <host underlay ip>`.
  - **The LAN** (`--announce-dev eth0`): the host answers ARP for its VMs
    (proxy ARP) and sends a gratuitous ARP whenever a VM arrives. Other
    machines on the LAN therefore follow a migrated VM without any
    configuration. Give VMs addresses from the LAN's subnet and they can use
    the LAN's normal gateway for internet access.
- On migration, the target routes the address to its new tap before the VM
  resumes and then announces it. The source points its own route at the
  target as soon as the target answers. The guest keeps its address and TCP
  state, so connections continue. Packets in flight during the downtime are
  lost, so the client stalls for one retransmit timeout (~200 ms on Linux).

### Firecracker patch

`firecracker/0001-snapshot-state-only.patch`: an empty `mem_file_path` in
`PUT /snapshot/create` saves only the microVM state. Stock Firecracker always
writes all guest memory, which would make migration downtime proportional to
RAM and double memory use on a host that is already short.

## Measured (WSL2, Ryzen 9 3900X, nested KVM)

| | |
|---|---|
| Template cold boot (one time) | 250 ms (2 vCPU), 420 ms (24 vCPU) |
| `run` → guest agent answering with its address set | **36–56 ms** (22–50 ms before the network device was added; host was also busier) |
| of which Firecracker snapshot load | 22–50 ms (mostly KVM memslot setup, which is slow under nested virt) |
| Migration downtime | **36–62 ms** (2 vCPU), **56–63 ms** (24 vCPU, 500 MB live data) |
| TCP connection through two migrations | no errors, worst stall 217 ms (one client retransmit) |
| nginx image, `run` → first HTTP response from the host | **205 ms** p50 (run 56 + nginx startup 144); `--warm`: **55 ms** p50 (run 31 + first request 22) |
| Background memory pull | ~1.1 GB/s over loopback TCP |
| Idle VM host RSS | 13–35 MiB |
| pause / resume (daemon side; RPC round trip ~2.3 ms) | **0.6 / 0.7 ms** (2 vCPU), 1.5 ms resume (24 vCPU) |
| checkpoint, by memory touched: 0 / 256 / 1024 MiB written in the guest | 133 / 616 / 2609 ms paused (p50; 3 / 268 / 1055 MiB stored) |
| restore → guest agent answering | **33 / 27 / 67 ms** (snapshot load 28 / 24 / 63 ms); whole checkpoint paged in after 39 / 153 / 509 ms |
| suspend (checkpoint + free) / resume of a suspended VM to ready | 127 / 448 / 2012 ms; 27 / 28 / 36 ms |
| suspended VM host RSS | 0 (Firecracker gone) |

Lifecycle numbers are from `flexvm bench --lifecycle` with the 2-vCPU template,
5 trials per size, restoring on the second daemon of the same host
(`bench/*-lifecycle.json`). The guest clock step after a restore adds another
35–100 ms after ready.

## Quickstart

```sh
./scripts/fetch.sh               # firecracker, guest kernel 6.1, ubuntu 24.04 base
./scripts/build-firecracker.sh   # patched firecracker -> artifacts/firecracker (needs musl-tools, libseccomp-dev)
./scripts/build-rootfs.sh        # artifacts/rootfs.ext4, and artifacts/flexvm-init for image templates
cargo build --release

sudo ./target/release/flexvm template default             # all CPUs, ceiling = host RAM

# host A (192.168.1.10) and host B (192.168.1.11) on one LAN; VMs use spare LAN addresses
sudo flexvm daemon --listen 192.168.1.10:7070 --peer 192.168.1.11:7070 \
    --announce-dev eth0 --vm-ips 192.168.1.128-192.168.1.191 --dns 192.168.1.1
sudo flexvm daemon --listen 192.168.1.11:7070 --peer 192.168.1.10:7070 \
    --announce-dev eth0 --vm-ips 192.168.1.192-192.168.1.250 --dns 192.168.1.1

export FLEXVM_HOST=192.168.1.10:7070
flexvm run web                                  # -> 192.168.1.128
flexvm exec web 'free -m'
flexvm ls
flexvm migrate web --to 192.168.1.11:7070       # address and connections follow
export FLEXVM_HOST=192.168.1.11:7070
flexvm pause web; flexvm resume web             # vCPUs stopped, memory kept
flexvm suspend web; flexvm resume web           # state to local disk, memory freed; lazy restore
flexvm checkpoint web /data/web-1 --stop        # complete state to disk; VM stops
flexvm --host 192.168.1.10:7070 restore /data/web-1   # same template id needed; same name and address
flexvm --host 192.168.1.10:7070 kill web
```

`scripts/netlab.sh up && scripts/netlab.sh daemons` builds the same setup on
one machine out of network namespaces: two hosts and a client on a simulated
LAN.

The daemon must run as root: it uses `/dev/kvm`, privileged userfaultfd,
`process_vm_readv` on Firecracker and cgroup v2.

## Container images

```sh
sudo flexvm template web --image nginx:1.27                    # any registry: Docker Hub, ghcr.io, gcr.io, ...
sudo flexvm template app --image ./app.tar --env PORT=8080     # `docker save` output or an OCI archive
sudo flexvm template py  --image ./oci-layout --cmd "python3 -m http.server 8000"
sudo flexvm template web-warm --image nginx:1.27 --warm        # snapshot nginx running and ready
flexvm run web1 --template web
curl http://<ip>/
flexvm logs web1 -f
```

`REF` is a registry reference (`nginx`, `ghcr.io/org/app@sha256:…`), an
uncompressed `docker save` / OCI archive, or an OCI image layout directory.
Overrides follow `docker run`: `--entrypoint` and `--cmd` (words, or a JSON
array; a new entrypoint drops the image's command), `--env K=V` (repeatable),
`--workdir`, `--user name|uid[:group|gid]`.

Images are untrusted input processed as root. Every document and blob is
checked against its digest before use (layers once more right before they are
unpacked, and their uncompressed contents against the config's `diff_ids`
while unpacking), and builds are bounded: `--max-download-mib` (8192, all
layers compressed), `--max-unpacked-mib` (16384), `--max-file-mib` (4096),
`--max-entries` (1,000,000), plus 4 MiB per manifest or config and 1 MiB per
tar entry's metadata (PAX records and GNU long names together, one of each).
Readiness commands run as the app does (same user and restrictions) in a
cgroup of their own that is killed and checked empty when the check ends; a
failed cleanup fails the check. Non-root checks need cgroup2 with
`cgroup.kill` and fail closed without it. Root checks are trusted (root in
the guest can leave any cgroup); without cgroup2 their session is killed.

- **Pull.** Native registry v2 client (no docker or skopeo): anonymous bearer
  tokens, or basic credentials from `$DOCKER_CONFIG`, `~/.docker/config.json`
  or, under sudo, the invoking user's. Indexes resolve to linux/amd64. Blobs
  are streamed to `ARTIFACTS/images/blobs/sha256/` and checked against their
  digests; gzip, zstd and uncompressed layers are supported. Archives are read
  in place (layers are located inside the tarball, not extracted). Registry
  credentials go only over HTTPS to the registry itself or its token service
  (auth.docker.io for Docker Hub); redirects to blob storage carry none.
- **Root filesystem.** Layers are applied in order as root, with whiteouts and
  opaque directories, ownership, modes, xattrs, device nodes, symlinks and
  hard links. Every path resolves inside the image (`openat2(RESOLVE_IN_ROOT)`),
  so absolute symlinks behave as in a container and a layer cannot write
  outside it; whiteouts must name one entry, and removal walks directory fds.
  Layers are unpacked in `--image-staging` (default `/var/lib/flexvm/staging`),
  which must be root-owned and 0700 with an ancestry only root can change, and
  is used through a descriptor, so other users can neither reach the image's
  setuid files and device nodes nor swap the directory mid-build. The image
  cache is trusted by whoever can write it (it is reused as is); writes into it
  never follow symlinks. flexvm adds `/sbin/flexvm-init`, its mount points,
  `/etc/flexvm/app.conf` (argv, env, workdir, uid/gid/groups resolved against
  the image's own `/etc/passwd` and `/etc/group`), an `/etc/hosts`, and an
  empty `/etc/resolv.conf` if the image has none (the daemon's `--dns` fills
  it at `run`). `mkfs.ext4 -d` writes the read-only image. Built filesystems
  are cached in `ARTIFACTS/images/rootfs/` by image config digest, flexvm-init
  and overrides, and templates attach the cached file in place, so templates of
  one image share one copy in the page cache (it is never rewritten; deleting it
  breaks those templates). Cache entries are published with fsync and rename
  and only count once their `.ok` marker exists. The template's content ID covers that file as its
  `rootfs` component plus the image's manifest and config digests and the
  app config, so it differs whenever the image does.
- **Process.** flexvm-init stays PID 1. It starts the entrypoint in its own
  session with the image's env, workdir and credentials, reaps it and records
  its exit status, and keeps its stdout and stderr (interleaved) in a 1 MiB
  ring: `flexvm logs NAME` prints it and the status, `-f` follows until the
  app exits. There is no restart policy. Nothing beyond the entrypoint is
  assumed: distroless and scratch images work, and `flexvm exec` on an image
  without `/bin/sh` exits 127 with a message saying so. `/dev/stdout` and
  friends exist, so images that log to them work. With a non-root `--user`
  (or image `User`), the app runs with `no_new_privs` and no capabilities in
  its bounding set, so setuid binaries and file capabilities in the image do
  not work for it (and cannot make it root again); flexvm-init is not
  dumpable, so the app cannot ptrace or read it.
- **When the app starts.** By default at `run`: the snapshot is an idle booted
  guest and `run` sends `APP` after the address is set (`app_start`, ~17 ms
  for nginx), then the app starts as it would anywhere. With `--warm` the
  template starts the app, waits until it is ready (`--ready-port N`: something
  accepts on 127.0.0.1:N in the guest, default the first exposed TCP port;
  `--ready-cmd CMD`: a shell command exits 0, killed when the deadline passes; `--ready-timeout S`, default 120)
  and snapshots it running.

> **`--warm` clones share userland state.** Every VM restored from a warm
> template starts from the same memory: anything the app generated before the
> snapshot (RNG seeds, session and TLS keys, UUIDs, tokens, caches) is
> identical in every clone. Firecracker's VMGenID makes the guest kernel
> reseed its RNG on restore, but nothing tells the app. Only use `--warm` for
> apps that hold no secrets or per-instance identity at startup, or that
> regenerate them per connection from the kernel RNG.

## Benchmarks

```sh
flexvm --host 192.168.1.10:7070 bench                                        # run
flexvm --host 192.168.1.10:7070 bench --to 192.168.1.11:7070 --dirty-mib 500 # run + migrate
flexvm --host 192.168.1.10:7070 bench --template web --ready-http 80           # run until the app answers
flexvm --host 192.168.1.10:7070 bench --lifecycle /data/ckpt --to 192.168.1.11:7070 --dirty-mib 0,256,1024
```

`--ready-port N` / `--ready-http N` add a `client` group: `run_rpc` as the
client sees it, then `app_ready` until the VM accepts a TCP connection on N
(or answers `GET /`), and their `total`.

`--lifecycle DIR` runs, for each memory size, VMs that are paused and resumed
ten times, checkpointed into DIR with `--stop`, restored on `--to`, then
suspended and resumed there. The report covers every phase, including the
background page-in.

Each trial runs a fresh VM, optionally writes N MiB into its /tmp and migrates
it (waiting for the full pull), then kills it. Phases are back-to-back daemon
timings that sum to `total`; the report lands in `bench/<date>-<sha>.json` with
p50/p90/p99/max per phase, raw samples and host context.

## Layout

```
flexvm/src/
  daemon.rs    RPC, migration, elastic memory controller, pressure policy
  lifecycle.rs pause/resume, checkpoint, restore, suspend; per-VM operation lock
  checkpoint.rs checkpoint format: crash-consistent writer, verified page-file reader
  uffd.rs      userfaultfd pager (template / zero / migration source / checkpoint file) + page server
  template.rs  cold boot, snapshot, sparse image, working-set recording
  vm.rs        restore into a pooled Firecracker, checkpoint, stats
  net.rs       taps, rtnetlink routes and neighbours, gratuitous ARP, address ranges
  fc.rs        Firecracker process, API client, warm pool
  guest.rs     vsock client for flexvm-init
  image/       container images: references, registry client, archives and
               layouts, layer unpacking, root filesystem build
guest/src/main.rs   flexvm-init: PID 1, overlay root, vsock exec agent
guest/src/app.rs    image entrypoint: start, supervision, log ring, readiness probe
guest/src/net.rs    guest network setup with ioctls and rtnetlink (no iproute2 needed)
firecracker/        patches on top of Firecracker v1.17.0
```

## Limitations / next steps

- **Post-copy risk**: until the background pull finishes (~1 s per GB), the
  VM's memory is split across two hosts, and losing either one loses the VM.
- **Networking is IPv4 only.** Peers form a full mesh (every daemon lists
  every other one). Address allocation is per-host ranges plus a check
  against peers, not real cluster-wide address management.
- **Packets in flight during a migration are dropped.** The source could
  buffer them and forward them to the target to avoid the ~200 ms client
  retransmit stall.
- **NAT on a host would break connections on migration**, because the
  translation state stays behind. Use routable VM addresses (as above) or do
  NAT at a dedicated gateway.
- **Restoring through the userfaultfd pager costs ~20 ms more** than a plain
  file-backed restore here. Fresh VMs could be restored straight from the
  template file (sharing unmodified pages between VMs too), with the pager
  kept for migration targets.
- **vsock connections reset on migration.** `flexvm exec` reconnects for up
  to 30 seconds, trying the original daemon and its peers. Guest commands keep
  running; each session retains up to 4 MiB of recent output (at most 4096 chunks).
  Output waits for an attached client, and for 30 seconds after it drops; past
  that the buffer wraps and exec reports output loss explicitly. Finished sessions
  retain their exit until CLOSE or a five-minute expiry.
- **Templates must be identical on every host.** Creation records a content ID
  and component hashes in `meta.json`; migration checks the ID before pausing
  and again on arrival. Copy the template and its artifacts to each host;
  independently booted snapshots generally have different IDs. Older templates
  without IDs must be recreated. Keep template files and artifacts immutable
  while VMs use them. Files are rehashed (before pausing) only when their
  size, mtime, ctime or inode changed; IDs are a 64-bit non-cryptographic hash
  that detects accidental differences on trusted hosts, not tampering.
- The control channel is plain TCP with no authentication; it must not be
  exposed outside a trusted network.
- **Container images**: linux/amd64 only; no Docker credential helpers; no
  restart policy, health checks, volumes or stop signal; stdout and stderr
  share one ring; `logs -f` stops when the VM migrates away (vsock resets).
  Building needs root (to keep ownership) and an uncompressed archive.
- The controller samples guest memory once a second (balloon stats). A very
  fast allocation burst can still hit the in-guest OOM killer; guest PSI
  triggers over vsock would react faster.
- **Checkpoints pause the VM for the whole write** (about 0.4 GB/s: reading
  memory out of Firecracker, comparing with the template, checksumming,
  fsync). Copy-on-write or pre-copy (#8) would make the pause independent of
  memory size. Checkpoints are full each time, not incremental.
- **The restore working set is the template's** (pages a fresh VM touches to
  become ready), not the checkpointed VM's own recent working set. This host
  has no idle page tracking to record that. Everything else is paged in
  address order in the background.
- A checkpoint, including a suspended VM, needs the template it was made
  from, and the template's content id must match. Rebuilding a template
  strands its checkpoints, so keep old templates while their checkpoints
  matter.
- **Fresh `run`s and migration targets keep the guest clock they were saved
  with**: the template's snapshot time, and the downtime lost on each
  migration. Only lifecycle restores and resumes step the clock (the same
  `Vm::sync_clock` could run after `run`, off the critical path).
- A guest that gets a different address on restore keeps its old one too,
  unless it has iproute2 to drop it.
- Snapshot load is dominated by KVM memslot creation in this nested
  environment; expect much lower numbers on bare metal.

### Resumable exec protocol

Legacy `EXEC <len>`, `SPAWN <len>`, `PING` and `NET` retain their wire format.
Sessions use `SESSION <id> <len>\n` followed by exactly `len` command bytes,
`ATTACH <id> <offset>\n`, or `CLOSE <id>\n`. The client chooses a random ID;
retrying SESSION with the same ID and command attaches to the existing process
from offset zero. Reusing an ID for another command fails. IDs contain up to
64 ASCII letters, digits, underscores or hyphens; commands are at most 1 MiB.

Frames retain `[kind u8][payload length u32 LE][payload]`. SESSION and ATTACH
first return kind 4 with the session ID. Session stdout/stderr (kinds 1/2)
prefix their bytes with an absolute `u64 LE` offset in the combined output
stream. Kind 3 contains the final `u64 LE` offset and `i32 LE` exit code.
Kind 5 contains the earliest retained `u64 LE` offset and reports output loss;
clients must not silently skip it. Kind 4 also carries `waiting` heartbeats,
`error: ...` failures, or `closed` for CLOSE. Socket writes happen outside the
output ring mutex. Reading an exit does not discard it: the CLI sends CLOSE
after receiving it, and the guest retains the ID as a tombstone until expiry
so a delayed creation retry cannot execute the command again.

The daemon JSON exec request adds `session`, `action` (`start`, `attach`, or
`close`), and `offset`; start also supplies `cmd`. Start/attach return the usual
JSON success reply followed by session frames; close returns a JSON reply.
Daemon info includes `peers` for recovery discovery.
