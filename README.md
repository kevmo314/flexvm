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
./scripts/build-rootfs.sh        # artifacts/rootfs.ext4 with flexvm-init
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

## Benchmarks

```sh
flexvm --host 192.168.1.10:7070 bench                                        # run
flexvm --host 192.168.1.10:7070 bench --to 192.168.1.11:7070 --dirty-mib 500 # run + migrate
flexvm --host 192.168.1.10:7070 bench --lifecycle /data/ckpt --to 192.168.1.11:7070 --dirty-mib 0,256,1024
```

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
guest/src/main.rs   flexvm-init: PID 1, overlay root, vsock exec agent
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
- **vsock connections reset on migration**, so host↔guest sessions must
  reconnect. Guest processes are unaffected.
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
