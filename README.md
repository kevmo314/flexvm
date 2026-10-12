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
flexvm --host 192.168.1.11:7070 kill web
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
```

Each trial runs a fresh VM, optionally writes N MiB into its /tmp and migrates
it (waiting for the full pull), then kills it. Phases are back-to-back daemon
timings that sum to `total`; the report lands in `bench/<date>-<sha>.json` with
p50/p90/p99/max per phase, raw samples and host context.

## Layout

```
flexvm/src/
  daemon.rs    RPC, migration, elastic memory controller, pressure policy
  uffd.rs      userfaultfd pager + page server
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
- **Templates must be identical on every host** (same name, same files). They
  should be content-addressed and distributed.
- The control channel is plain TCP with no authentication; it must not be
  exposed outside a trusted network.
- The controller samples guest memory once a second (balloon stats). A very
  fast allocation burst can still hit the in-guest OOM killer; guest PSI
  triggers over vsock would react faster.
- Snapshot load is dominated by KVM memslot creation in this nested
  environment; expect much lower numbers on bare metal.
