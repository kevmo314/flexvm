# Internals

How flexvm works underneath the commands. The process model, host state and
migration protocol are in [process-per-vm.md](process-per-vm.md).

## Overview

| Concern | Mechanism |
|---|---|
| CPU | vCPUs = host cores, rounded down to an even count (Firecracker takes 1 or an even count, at most 32; `pull --vcpus` overrides). Idle vCPUs halt and cost nothing. Each VM's Firecracker runs in a cgroup of its own with the `cpu` controller on, all at the default `cpu.weight`, so busy VMs share contended CPU equally however many threads each runs. |
| Memory growth | Boot memory (256 MiB + 1/32 of the ceiling) + a virtio-mem region up to host RAM, of which 4 GiB is already plugged in the template. Past that the guest asks for more over vsock the moment it runs low, and its VM process keeps a quarter of the guest (at least 1 GiB) free. See [Memory](#memory). |
| Memory return | virtio-balloon **free page reporting**: pages the guest frees go back to the host within seconds. |
| Root filesystem | One read-only ext4 image on virtio-pmem with DAX, shared by every VM through the host page cache. Writes go to a tmpfs overlay inside the guest, so they migrate with memory. Snapshots name it `rootfs`, a file in each Firecracker's directory that every load links to the generation's own (`template::ROOTFS`): a generation's root filesystem can be anywhere, so a migration target need not have pulled the image (generations built by v0.1.0 name it by its path, which a target must then hold). |
| Start | Every VM is a **UFFD restore of a template snapshot** into a pre-spawned, pre-cgrouped Firecracker. The template's recorded working set is copied in bulk; everything else is faulted in lazily from a shared, sparse template image. **Standby VMs** are already restored and paused, so `run` is usually just a resume. |
| Migration | **Post-copy**: the target gets everything ready first (template, address, a Firecracker with the template's VM structure already built); then pause, save vCPU and device state only (~20–200 KiB), load it and resume on the target, then the target's pager fetches pages from the paused source on fault and in the background. The source releases the VM once every page has arrived, and never resumes it once the target may own it. |
| Pressure | If a VM needs to grow and the host would drop below its reserve (`reserve_mib`), or the host is already below it, that VM is migrated to a peer with room. |
| Network | Each VM has its own IPv4 /32 routed to a per-VM tap. The address moves with the VM, so open TCP connections survive migration. The tap's ingress (a clsact classic BPF filter) passes only IPv4 from that /32 and ARP naming it, so a guest cannot spoof another's address; it follows the address on a readdress, restore or migration. See below. |
| Container images | `flexvm pull IMAGE` builds the root filesystem from an OCI/Docker image and snapshots a VM of it as the image's template; flexvm-init runs and supervises its entrypoint. See [images.md](images.md). |

## Memory

A VM never needs a memory size: it must be able to grow to host RAM without
the guest OOM killer firing first. Growth by hot-plug is reactive, though,
and a guest can allocate faster than a 1 s controller notices. So growth does
not wait on the host:

- **Pre-plugged.** Templates are snapshotted with `PLUG_MIB` (4 GiB) of
  virtio-mem already plugged, so a VM starts with ~5 GiB of RAM. The memory
  is free in the snapshot (holes in the template file), and guest pages cost
  the host only once touched. Only the page structs (1/64) are data: the
  template's memory file grows from 48 to 131 MiB. The controller never
  shrinks a VM below this, because unplugging means offlining, which walks
  the page structs.
- **Overcommit.** The guest runs with `vm.overcommit_memory=1`, so one
  allocation larger than the guest's current RAM succeeds and grows as it is
  touched. Under the default heuristic, `bytearray(1 << 30)` in a 230 MiB
  guest failed with ENOMEM before touching a page, which no host reaction
  could fix.
- **Asking, not polling.** flexvm-init (`guest/src/mem.rs`) runs everything
  it starts under a memory cgroup, `/vm`, whose `memory.high` sits
  `headroom(MemTotal)` below MemTotal. That is the same mark the VM process keeps
  free (a quarter of the guest, at least 1 GiB). Commands and the image app
  go in `/vm/work` and readiness checks in their own groups under `/vm`;
  flexvm-init itself stays outside, so the throttle never slows the thread
  that lifts it. Crossing the mark wakes the agent (a `memory.events`
  notification, no timer), which sends `MEM <available KiB> <total KiB>` to
  the host on vsock port 53. The VM process resizes at once instead of waiting
  for its next tick.
- **The guest is untrusted.** A request may be at most 128 bytes and must
  arrive within 500 ms; malformed ones are dropped. Requests are acted on at
  most every 50 ms per VM; the rest get `busy`. The guest's size comes from
  Firecracker, not from the guest; what it says is free only steers growth.
  Each step grows by at most a quarter of the guest. All growth, from guest
  requests and ticks alike, is admitted against the reserve (`reserve_mib`) under the host
  lock, with the last 10 s of grants (`RUN/grants-BOOTID`, every VM process's) counted as used (plugged memory shows up
  in MemAvailable only once touched). A refused guest is told `full` and
  marked starved. Before it refuses, every VM process is asked to release
  the memory it keeps for its next checkpoint: the request is a number in
  `RUN/.locks/release-BOOT`, raised under the host lock, which each VM
  process looks for every 100 ms, answering in its own file in
  `RUN/.locks/released-BOOT/`. Admission waits for the host lock to ask as it
  does to admit: until its deadline, or until it has it without one (#1081); a
  VM's controller or a standby, which look again next tick, give up on it after
  200 ms. The response wait starts after taking the lock. The request waits up to 200 ms for each that
  runs (not for one that is stopped; the files of those proven gone are
  removed), and MemAvailable is read again whoever answered: that memory is
  not admitted, so it never refuses a grant (#648, #677). Eviction and the
  standby pool ask the same before they react to the host running short. A
  request within a second of the last is not made again (the memory went
  back then), so callers queued on the host lock do not each wait.
  Checkpoint memory (below) is taken under the same lock against the same
  count, so the two never spend the same memory above the reserve. Admission is not enforcement: a guest can still fill memory
  that is already plugged, the 4 GiB pre-plug included (#54).
- **Wait, don't die.** Allocations that outrun the plug are throttled by the
  kernel at `memory.high` rather than OOM-killed. Memory block uevents move
  the mark as memory arrives. The agent subscribes to them before it first
  reads MemTotal, and re-reads it on every reply and retry. If the host answers `full` (at the ceiling), or
  nothing arrives within 3 s, the agent lifts the throttle, and the guest
  behaves as it would without it.
- **Kernel memory.** Page structs of every plugged block (1/64 of it) and
  other kernel allocations need non-movable memory. Plugged blocks online
  auto-movable: movable only while kernel memory is at least 1/20 of it, so
  kernel memory grows with the plug instead of filling boot memory (a 256 MiB
  base onlining all movable panicked near 13 GiB, #97). The default base is
  256 MiB + 1/32 of the ceiling (1280 MiB on a 32 GiB host; untouched, it
  costs nothing). The boot command line is part of the snapshot: templates
  built before this, and their checkpoints, keep the old onlining; rebuild
  them. Unplug takes movable blocks first; kernel blocks may not unplug, but
  their free pages go back through free page reporting.
- **Shrinking** is free page reporting (freed pages go back within seconds,
  plugged or not), plus unplugging memory above the template's plug once a
  guest has had more than three times its headroom free for 10 s. A shrink
  the guest cannot finish never blocks growth: a guest that runs short
  cancels it and grows from what is plugged, and a resize still unfinished
  after 10 s settles at what is plugged (`shrink_stall`).
- **Host accounting.** A VM is starved (and migrated by the pressure policy)
  only when it is actually short of free memory and cannot grow here: at its
  ceiling, or refused admission. Plugged-but-free memory is not counted as
  use, and the pressure policy still picks VMs by host RSS.
- **Resizes stay out of lifecycle operations.** A resize, whether from a
  controller tick or from the guest asking, holds the VM's operation lock, like
  migrations, checkpoints and pauses do, and only touches a running VM. A
  guest that asks during one is told `busy`, with one exception: while a
  copy-on-write checkpoint copies a running VM, it may grow (never shrink).
  The copy only reads pages the VM had at the pause, and memory plugged
  later was unplugged then, so the copy never reads it. The checkpoint keeps
  the plugged size it saved. Growth since the pause is dirty for the next
  incremental checkpoint. Before, a guest that grew during a long copy was
  OOM-killed (`cow_grow` in `scripts/faults.py`). A migration also waits for any
  plug in flight to settle (`Vm::settle_hotplug`). The target refuses a
  vmstate whose memory regions differ from its own.

Measured with the 2 vCPU template (WSL2, loaded host), a fresh VM per trial,
with each burst run right after `run`:

| Burst right after `run` | before | now |
|---|---|---|
| 1 GiB in one buffer (`python3 -c 'b=bytearray(1<<30)'`, `dd bs=1G`) | ENOMEM 11/11 | ok 40/40 |
| 1 GiB in 64 MiB chunks, to /dev/shm, or from 4 parallel writers | ok 9/9 (first touch is slow here) | ok 60/60 |
| 3 GiB in one buffer, in chunks, or to /dev/shm | ENOMEM 2/2 (one buffer) | ok 19/19 |
| 300 MiB with the controller slowed to 4 s (as if the guest were 4× faster) | OOM-killed 4/8 | - |
| 2 GiB, 4 s controller, template with nothing pre-plugged | - | ok 14/14 (grown on guest requests) |

Memory still goes back to the host. A VM's host RSS went from 19 MiB idle to
2630 MiB holding 2.5 GiB in /dev/shm, then back to 96 MiB 15 s after the
file was deleted. What stays resident is the page structs of the touched
memory (1/64 of it) and small free fragments that free page reporting skips.
Untouched plugged memory stays free:

- Templates do not wait for free page reporting before the snapshot, so each
  VM reports its free memory (~5.6 GB on ubuntu:24.04) over its first ~25 s.
  The walk over its page structs costs ~7 MiB RSS per VM (44 to 51 MiB); waiting
  added ~26 s to every pull, since the guest reports a sixteenth of its free list
  every 2 s. Free page hinting does not help: it leaves the pages unmarked, so
  VMs still report them. Warm templates still wait: memory warm-up freed holds
  data, which would stay in the template (a 1 GiB buffer freed left 1180 MiB of
  memory file, against 159 MiB; hinting, only whole 4 MiB blocks, left 797).
- The pager copies 16 template pages per fault only when faults are
  sequential. Strided reads, such as reporting touching one page struct per
  4 MiB block, used to pull in 16 times what they touched. Recorded working
  sets are padded to 16-page blocks instead, so restores still prefetch
  around what they touch.

Cost, measured against main on the same host. Run latency alternated the two
builds trial by trial (60 runs each); migration used four alternating rounds
of `flexvm bench --dirty-mib 200`, 15 trials each:

| | main | now |
|---|---|---|
| Idle VM host RSS | 18 MiB | 9–23 MiB |
| `run` p50 from the hot pool | 4.7 ms | 4.4 ms |
| `run` p50 with no hot pool (snapshot load) | 38.0 ms (load 26.8) | 39.6 ms (load 26.4) |
| Migration downtime p50 / p90 | 52.5 / 82.5 ms | 48.5 / 59.3 ms |
| Background pull p50 (200 MiB dirty) | 330 ms | 303 ms |

## Host compatibility

A template records the host it was built on: CPU vendor, family and model,
the CPU feature bits KVM offered its guest (including invariant TSC), the XSAVE
layout, TSC rate, saved MSR index set, and the Firecracker version and build.
Checkpoints and migrations pin their template by content id and so carry its
guest CPU. Every snapshot load (run, a standby VM's load, restore, resume, and a migration target before its source pauses)
refuses a host with a different CPU model or Firecracker, a missing feature
bit, another XSAVE layout, or a missing saved MSR, naming the mismatch. TSC
rates may differ by up to 250 ppm (Firecracker’s calibration tolerance); larger
differences require target KVM TSC scaling. Extra feature bits and MSRs are
fine. Firecracker saves the MSRs of the host that takes the snapshot, so a
migration's source also sends its own set, which the target checks before the
source pauses. Checkpoints (including suspended VMs) record the saving host's
MSR set and effective vCPU TSC rate in their manifest and check them before loading
their VM state. A saved VM without either record cannot be restored. Templates built before these records must be rebuilt, and
checkpoints and suspended VMs of such a template cannot be restored. Host
probes are cached per process while the Firecracker binary is unchanged.

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

Each successful copy marks its dirty range a bitmap word at a time before
publishing any of its pages as PRESENT; EEXIST marks its one page too.
Working-set prefetch reuses one scratch buffer per pass, preparing template
bytes before taking the prefetch gate so cold reads cannot hold up export.

One thread reads uffd events, but it never waits for the network or disk:
a fault on a REMOTE page claims a 64-page run and queues it for one of 8
fetcher threads (each with its own connection to the source), so faults on
template and zero pages, and REMOVEs, are served meanwhile. The event thread
writes the run's request on the least busy fetcher's connection as it queues
it (without blocking; the fetcher writes what did not go out), so the request
is on its way while the fetcher wakes, and several can be outstanding on one
connection, answered in order. Fetchers and the
4 background pullers install pages as they arrive (16 at a time), and a
fetcher asks for the faulting page on its own, pipelined ahead of the rest of
its run. Each attempt has 5 s to write its requests and read the reply in
full. An attempt that ran out of time after some pages arrived installs them
and asks for the rest on a new connection, and the source counts as alive. So
a fault's wait is bounded by progress, not by a strict end-to-end deadline:
a 64-page run from a source that delivers one page per attempt can take
about 320 s. Only a source that delivers nothing for 10 s is lost. A REMOTE fault also steers the pullers: they pull
the 32 MiB after its run before going on with their share, as the guest tends
to read on from where it faulted. A fault on a page someone else is installing waits for that copy,
which wakes the faulting thread; installers signal the event thread (an
eventfd) when pages settle, and an install that hits EAGAIN (a REMOVE is
queued) waits until the event thread has read events, instead of polling.
`flexvm debug VM status` reports fault service latency per kind (served
locally, fetched, waited for another installer), measured from reading the
fault to the copy that woke it, plus fetch, queueing and pull times.

**Huge pages after the pull** (`uffd/collapse.rs`, #141). The pager installs 4 KiB
pages, so KVM maps guest memory 4 KiB at a time. After a migration or restore
nothing is mapped in KVM yet, so the guest's first pass over its memory exits once
per page: reading 500 MiB took 1.1 s even with every page pulled, and 50 ms the
second time. Once the pull is done, one thread collapses each 2 MiB chunk whose
pages are all PRESENT into a transparent huge page
(`process_madvise(MADV_COLLAPSE)` on Firecracker), which KVM then maps with one
entry. It uses at most half a core (it sleeps as long as each collapse took CPU).
Before every pause (migration, checkpoint, suspend, `kill -TSTP`, the paused
start of an arriving VM) the VM process holds the pass and waits out a collapse
in flight, so no pause waits behind a collapse's mmap write lock or compaction
(0.05–2.9 ms before the pause, while the guest still runs); a resume lets it go
on. It ends when the pager stops, at a checkpoint or migration barrier, once
write tracking is registered, or when the kernel has no huge page to give
(ENOMEM). Nothing else changes:

- The kernel collapses a chunk of a userfaultfd-registered range only if all 512
  pages are mapped, none of them the zero page and none write-protected. It checks
  this again under the mmap write lock before copying. So a collapse never fills a
  missing page behind the pager's back, and never drops a protection a checkpoint
  relies on. Contents and page states stay the same, and RSS does not grow.
- Write-protecting a huge page protects it whole (arming tracking got faster:
  5–9 ms against 26–37 ms for 500 MiB). A write fault on it is reported for its
  4 KiB page as before, and unprotecting the 64 KiB block splits the huge page.
- Free page reporting and virtio-mem discard 2 MiB-aligned blocks, which free the
  huge page whole. A smaller discard splits it and still raises a REMOVE, and then
  a missing fault, as before.
- `scripts/faults.py cow_collapsed` checks checkpoints, deltas, a restore and free
  page reporting on collapsed memory with the guest rewriting it, and
  `unplug_collapsed` has the guest offline the hotplugged blocks holding the most
  huge pages (virtio-mem unplugs offline blocks first) and checks, with free page
  reports held and from Firecracker's pagemap and kpageflags, that every huge
  page in them is gone after the unplug and the data moved intact.

Pausing Firecracker stops only the vCPUs, so before the state-only snapshot the
source also brings the VM's tap down (no RX into guest memory), closes host
exec sessions (vsock) and parks the balloon statistics timer; the target and an
aborted source put the timer back.

### Migration steps

Only what needs the VM's state happens while it is paused. Everything goes
over one connection, in this order: the target's answer to the prepare
request; the source's header, vmstate and preloaded pages; the target's
answer once it committed and resumed the VM; the held packets (`hold`); the
target's reply to them.

0. Before anything else, on a connection of its own (`template`): the source
   asks whether the target has the template generation, by content id only
   (a name there never counts: it may name another build of the same tag). If
   not, it sends it: `meta.json`, then the vmstate, root filesystem and memory
   file, each as its length, its data extents and their bytes, so holes stay
   holes (ubuntu:24.04's 47 GB memory file and its root filesystem are 236 MiB
   of data, sent in about 0.5 s here). The target's listener receives it into a
   build's staging directory (`template::receive`), checks the content id and
   that each file hashes to its component (its own Firecracker included, which
   `artifacts::ensure` fetches if missing; the kernel is not needed: it is in
   guest memory) and only then renames it into `templates/.gen/ID` under the
   templates lock, like a build, with no name: the target's tags never move,
   and `images` lists it as `<none>`. The root filesystem goes in the
   generation's own directory, which takes it along when it is removed. Two
   arrivals of one template take turns (`template::turn`), so the second sends
   nothing. The content id's hash is no cryptographic check, so every
   generation records SHA-256 digests of its files and of its metadata
   (`Meta::digests`, at its build or its receipt; a received one is marked
   `received`), and checkpoints copy them into their manifest
   (`template_digests`). A restore onto a received generation needs the
   checkpoint's to match: one with none (v0.1.0's, or of a template v0.1.0
   built) restores only onto a generation built here. A target answering that
   it has a received copy sends its digests,
   and the source refuses one that differs from its own; it then sends its
   digests in `migrate_in`, and an arrival opens a received generation only
   for a source whose digests match (so a v0.1.0 source, which sends none,
   is refused one). A push that fails or is killed leaves its staging directory, which
   the next build or push sweeps, never a generation. The listener holds the
   generation open for 17 s, until the arrival has opened it itself, so no
   `rmi` or prune removes it in between; from then on the VM holds it as any
   VM does. Caps: 4 pushes at once (2 from one peer), 64 GiB of data, 2 GiB
   left free on the disk (1 GiB of it for local checkpoints and suspends), and
   a transfer budget of 60 s plus 1 s per 8 MiB transferred, enforced on
   both sender and receiver. A push waits up to 10 minutes for another
   arrival of the same template to finish receiving it (`TURN_WAIT`). Spare
   received generations (unnamed, used by nothing here or in a state sharing the templates, held for an arrival or
   open in no VM process) and pushes under way are budgeted by their allocated
   blocks (templates are sparse): an eighth of the filesystem (4 to 128 GiB) in
   all and a quarter of that per peer, though a push with nothing else charged
   may be larger. A push past the room or the budget first removes spares,
   oldest first, within their hour of grace too, but none received in the last
   5 minutes (its arrival may not hold it yet). A v0.1.0 target
   answers `unknown op`: the migration goes on and needs the generation there,
   as before, and one built since (whose snapshot names `rootfs`, which v0.1.0
   does not link) is refused at once. Disk room is checked and each file's
   blocks allocated (`fallocate`; a templates filesystem without it takes no
   pushes) under one lock, so pushes at once see each other's; a reused v0.1.0 root filesystem's use lock is held through the
   publication; a received memory file must be its guest's size (at most
   2 TiB), and the listener holds at most 16 generations for arrivals. All of this happens while the VM runs: none of it is downtime.
1. Before the pause, over one connection (`migrate_in`): the target checks the
   template, reserves the name and address, spawns a Firecracker and
   starts its pager (the listener started a VM process for it). With `firecracker/0002-*.patch` it also has Firecracker
   prepare the load from the template's snapshot: KVM VM, vCPUs, memory slots,
   guest memory handed to the pager (which then waits for the page states),
   the vsock socket and the pmem mapping. A target that cannot take the VM
   refuses here, before anything happened to it.
2. The source parks the balloon timer, holds the VM's packets, pauses, saves
   the state (taking the tap down alongside: Firecracker serves the snapshot
   from its pause loop, which reads no tap), exports its page states and reads the pages
   of the template's *load set* that it holds: pages Firecracker touches
   while loading and resuming a VM of that template (vCPU clock pages,
   virtqueues), learned from standby VMs' loads (which hold their prefetch
   back until then). Header, vmstate and those pages go out on the open
   connection.
3. The target seeds its pager and loads the state (vCPU, VM and device
   state only, when prepared) with the vCPUs stopped, installing the
   preloaded pages while Firecracker parses the state. Only once every check
   that can still abort has passed (the source's page server answers, the
   pager is healthy, the name is registered) does it record the migration
   committed, and only then resume the VM: a VM that ran on the target is
   never handed back to the source. A source that is gone, or too slow (one
   30 s deadline for everything it sends after the pause), leaves nothing
   behind on the target. Once it answered, it takes in the packets the
   source held and only then announces the VM.

Downtime p50 on an idle host (`flexvm bench`, interleaved runs of 12-15
trials, before process-per-VM): 2 vCPU 37 ms before, 26 ms with steps 1–3 on stock Firecracker,
10 ms with the patch (pause 0.5 ms, snapshot 1.7 ms, transfer 0.1 ms, target
load 4 ms, resume 1.4 ms); 24 vCPU 50 and 25 ms (its load is still 11 ms and
its resume 4 ms: vCPU threads, state parsing).

### Lifecycle: pause, checkpoint, restore, stop

```
starting -> running <-> paused                     (pause / unpause)
running | paused -> checkpointing -> running | paused | gone   (checkpoint create VM [--stop])
running | paused -> suspending -> suspended -> running         (stop / start)
running | paused -> source (migrating) -> gone, or back if the target aborted
any -> failed (memory lost) -> gone                (rm)
```

Every lifecycle operation (and each controller resize) holds the VM process's
`op` mutex, so operations on one VM never interleave; the controller skips a
VM that is busy, paused or suspended.

- **pause / unpause** stop and restart the vCPUs; memory and devices stay.
  Both take under a millisecond (2 vCPU) to 1.5 ms (24 vCPU).
- **checkpoint create VM [NAME]** first waits for any VM still pulling memory (from a
  migration source or its checkpoint), and for virtio-mem to settle (see
  below). It then pauses the VM, quiesces its devices and pager like a
  migration source does, saves the vCPU/device state and writes every page
  that differs from the template into the store (below). Without `--stop` (the
  default) the VM resumes as soon as its memory is write-protected and the
  pages are written copy-on-write while it runs (pause 17–30 ms at any
  size, see below); with `--stop` it stays paused for the write (2–3 GB/s
  here) and is killed. `--incremental` writes only what changed since its
  last checkpoint, as a delta against it.
- **run --checkpoint CKPT|PATH** (a restore) works on any host whose template has the same content id.
  It loads the verified state (copied to the VM's own run directory) into a
  fresh Firecracker, paused. That Firecracker's pager takes pages from the
  checkpoint's page file: on fault, and in the background (the template's
  working set first) until all are in. The VM is ready in about the time of
  a `run`. By default it keeps its name and address. A restore refuses an
  address a peer is using; `--ip auto` picks a new one, which also makes a
  restore a fork of a running VM. `--paused` holds the restored VM paused
  until `unpause`; its memory is still paged in meanwhile. Page files cache
  their buffered/direct mode per descriptor; an EINVAL read fallback disables
  direct I/O and publishes buffered mode for later reads and cache eviction,
  avoiding an `F_GETFL` on each background-read segment.
- **stop** (SIGTERM) checkpoints into `STATE/suspended/NAME` (`/var/lib/flexvm` by
  default; it must be on disk, not tmpfs). Then stop kills Firecracker, so the VM costs no memory. Memory is
  released only once the checkpoint is durable. The pager is stopped before
  Firecracker dies, so no discard event can mark a saved page as zero.
  A suspended VM's checkpoint stays in `suspended/`.
  - **Resume** (`start`) first creates a `STARTED` marker in it and fsyncs it, before
    any vCPU runs, under the host lock of its final address check (the fence):
    marked before it, a crash while waiting for the lock would lose a VM that
    never ran. A failed fence leaves no marker (test fault `resume_fence_fail`). It then restores lazily like `run --checkpoint`, and deletes the
    checkpoint once every page is in. The pager closes the checkpoint's
    files as soon as the last page has settled (readers still busy finish
    first), so the deletion gives the disk space back while the VM runs on.
  - **Removal** (`rm`) creates a `DISCARDED` marker the same way before it answers.
  - **Resume** of a checkpoint marked `STARTED` or `DISCARDED` deletes it
    instead: a resumed or killed VM never comes back.
  - **Failed resume.** If it fails before the resume request reaches
    Firecracker, the VM stays suspended. If it fails after, the checkpoint
    is consumed: the VM is gone, as re-arming it would replay what it did.
    If the `STARTED` marker cannot be made durable, it is removed again and
    the directory fsynced before the VM goes back to suspended. If that
    fails too, the marker may or may not survive a crash: the VM (which
    never ran) is listed `quarantined` (a `QUARANTINE` file with the boot id
    and why). It cannot be resumed; `rm` discards it as usual, and after
    a reboot the disk decides (marker: deleted; none: suspended again, and `ps -a`
    lists it so: a `QUARANTINE` of an earlier boot does not hold). Test faults
    `started_fsync` and `started_unmark` cover both.
- **Device quiescing.** An API pause (`PATCH /vm Paused`) puts Firecracker's
  VMM thread into a loop that serves only API requests until the resume. It
  does not return to its event loop meanwhile, so device emulation stops
  with the vCPUs: no queue, tap, vsock backend or timer is serviced, and the
  events wait for the resume. flexvm builds on that:
  - **Loaded paused.** A load with `resume_vm: false` (a paused migration
    target, `run --checkpoint --paused`) stops only the vCPUs. The VM process follows it
    at once with an API pause, so the devices are held too. The
    `held_restore_frozen` scenario shows the difference: a held restore's
    memory stays bit-identical while frames arrive on its tap, a host vsock
    connection waits and the balloon timer is due. Skip the hold and the
    same activity changes guest memory.
  - **Every checkpoint or migration pauses through the API,** even for a VM
    already paused.
  - **Guest-facing requests happen only before the snapshot.** Requests
    served inside the pause loop can still write guest memory: changing the
    balloon statistics interval writes the stats queue, and balloon or
    virtio-mem size changes send config interrupts. So the only one flexvm
    sends to a paused VM (parking the balloon timer) goes before the
    snapshot. None follows until the pages are captured (checkpoint) or the
    source is released (migration). The controller never touches a VM that
    is not running.
  - **Belt and braces.** The earlier measures stay. Before a pause the
    VM process waits for virtio-mem to carry out the last resize. A checkpoint
    is not published if memory was discarded, or the plugged size changed,
    after the snapshot.
- **Clock.** A restored guest's wall clock resumes from when it was saved.
  The guest uses the TSC clocksource, whose saved value Firecracker
  restores, while `clock_realtime` only moves kvmclock. A restore or a
  suspended VM's resume therefore steps the guest clock under the VM's
  reservation, within a 5 s deadline, with the agent's `CLOCK` (it sets the
  host's time and reports how far off it was), up to three tries, stopping
  at the first whose round trip is under 5 ms; the residual error is a few
  ms. Agents without `CLOCK` get
  no step (logged once): an exec could run late, after a snapshot.
  Across a plain pause the TSC keeps counting, so the clock stays right
  (measured: 0 ms drift after 20 s). `unpause` still checks it in the
  background, at most one check per VM at a time.
- **Paused migration.** A paused VM migrates and stays paused on the
  target, which pulls all its pages from the source. Resuming it there
  waits (up to 30 s) for that pull, so it never runs split across hosts.

#### The checkpoint store (#775)

`checkpoint create` writes into `STATE/checkpoints`, flexvm's own
(`checkpoint::store`), root's and 0700. Each checkpoint is the directory
`ID`, its manifest's checksum: `Staging::in_store` stages it there as below
and, once the manifest is written, publishes it under that id
(`RENAME_NOREPLACE`). A name is a link `names/NAME` to `../ID`, made with
`symlink` (atomic, never over another) after publication: a name taken
meanwhile leaves the checkpoint unnamed (logged), as a `--stop` VM is gone
by then. A delta's parent is `../ID`. Everything listed or referenced is a
complete `ID` with a manifest: staging (`.flexvm-staging-*`) and removed
ones (`.removed-ID`) are not ids. Its generation is kept while it is stored
(`checkpoint::managed`, read by `Host::template_users`).

The store's lock (`checkpoints/.locks/store`, a flock) orders the rest:

- Shared by a VM process from before its checkpoint stages until it is
  named, so the parent of a delta cannot go while the delta is written
  (the delta checks its chain again before publishing, as before).
- Shared by a restore, of the store the checkpoint is in (whichever state's,
  `store::holding`), from before it opens the checkpoint until it has read it
  (`Checkpoint::open`, `SPEC`) and opened its template generation (whose use
  lock then keeps it). From then on it reads only through descriptors, which
  removal leaves readable.
- Exclusive for `checkpoint rm` and `prune`. They first delete what an
  interrupted removal left (`.removed-*`), and any `ID` without a manifest
  (a revoked publication's leftover: a checkpoint is published whole). Then,
  per checkpoint, dependants before what they build on: unlink its name
  durably, rename it `.removed-ID`, fsync the store, delete it. A crash
  leaves whole chains, perhaps one checkpoint unnamed. A checkpoint may have
  several names (`checkpoint load --name`); all go. Names whose `ID` is gone
  (what `rm ID` left before #862) go too: `prune` all, `rm NAME` that one.
  Removing a name alone works even with an unreadable checkpoint kept, not
  with a listing error (its checkpoint may be one the listing missed).
  Malformed name entries (not a symlink to `../ID`, or not UTF-8) go with
  `prune` or `rm -f NAME`; removing a name alone never runs checkpoint deletion.

`store::list` returns a `Listing`: entries, and every error reading the
store or `names` (unreadable entries stay entries), and malformed names
separately. Malformed names do not make the listing incomplete. With a listing
error, checkpoint removal by `rm` or `prune` and an id's start are refused;
a name read resolves, and a whole id does unless `names/ID` exists (a name
before #862 may look like an id; new ones may not), or a name and an id are
two checkpoints'. Listing errors
show their directory and error, as warnings on stderr for text `--format`
and `-q`. `.Name` is the first name, `.Names` all joined with `, `; `name=`
filters match any one name exactly.

`rm` refuses a checkpoint that one not removed with it builds on
(`manifest.parent.id`), unless `-f` adds those too, transitively. `prune`
takes those created before the cutoff (all without one), minus what a kept
one builds on. `run --checkpoint` takes a name, else an id or a unique start
of one (4+ digits); an argument with a `/` is a directory, restored as is
(flexvm 0.1.0 wrote them with `checkpoint VM DIR`, which is refused now).

#### Moving checkpoints: save and load (#775)

`checkpoint save` writes a tar (`checkpoint::export`, GNU headers, regular files
only) whose members are, in order: `flexvm-checkpoint.json` (the `Header`:
the head's id, its name, the chain's ids head first, the template's content id,
whether the template follows, and in `specs` the checkpoints whose run settings
follow, left out when none do); per checkpoint of the chain, oldest first,
`checkpoints/ID/manifest.json`, its run settings `SPEC` if it has them (what a
restore reads for `--keep`, `--rm`, `-e` and `--entrypoint`; not in the manifest,
so not in the id), `vmstate`, `pagemap` and `pages`; then
`template/TEMPLATE_ID`, the generation as a migration pushes it
(`template::Sending`: its metadata, then vmstate, root filesystem and memory
as length, data extents and their bytes; its length is known before it is
written, as a tar header needs). Save opens all of it under the store's lock
(shared) and the generation's use lock, then lets the store lock go: removal
leaves open files readable, so a slow reader holds up no `rm`. It refuses a
template whose digests are not the checkpoint's, and leaves out one whose
checkpoint records none (v0.1.0's), with a warning.

`checkpoint load` reads the members by the names expected next, each within its
limit (header 64 KiB, manifest and run settings 1 MiB each, vmstate as
`MAX_VMSTATE`, a page map 36 bytes per guest page, pages within the store's free
space less 1 GiB, the template within `template::receive`'s): it takes no path
from the archive. It holds one checkpoint's metadata at a time, so it applies no
budget of the chain's: `chain_meta_budget` scales with the loading host's memory,
and would refuse a save from a larger host. A restore applies it (and the load
warns when the chain is over it here). Each member is held whole while checked,
so none may be over it (one that is could not be restored here either): a forged
length exhausts no memory. A publication that fails is undone, except where a
manifest or name may stay (its revocation or removal failed): then the chain it
builds on is kept whole, for `rm` to remove. The header's ids are
checked first (16 hex digits, distinct, at most `MAX_CHAIN`; the template's a
content id), and a name another checkpoint has is refused then. Each checkpoint
is verified as `Link::open` and `PageFile::read` would (its manifest's checksum
is its id, its parent the chain's next, the same template and size, its files'
lengths and checksums, its page map, each page's CRC32C), and staged in the
store (`Staging::import`), its pages' blocks allocated first (`fallocate`; a
filesystem that cannot takes no loads) under the host-wide lock template receipt
takes too (`template::ROOM_LOCK`), so no two loads or pushes count on the same
free space. Those checks are not cryptographic (the id is a 64-bit hash), so
a save also has a SHA-256 (`SaveDigest`: per checkpoint, oldest first, its id
and each file's name, length and SHA-256, `SPEC` among them when it has one, so
a save with none has the SHA-256 it had before they were saved), which `save` prints and `load`
computes from what it read; `--sha256` refuses another before the template is
read. What was sent is verified so even where the store has a checkpoint under
its id; that one is then compared byte for byte with it (its run settings too, or
their absence), and refused if it differs. The compare holds each of its files
open (`Pinned`), so no inode compared is another file's later. A parent is
named `../ID` here: a manifest that names it otherwise (a v0.1.0 directory's) is
rewritten, so it and its descendants get new ids. The template is taken only if
no generation of that content id is here: received by `template::receive` with
the head's `template_digests` as `vouched`, refused before publication unless
they match its files, and after the end of the archive is checked (`finish`:
two zero blocks, then only zero padding, at most 1 MiB, to the end of the input).
A generation here that was received with other digests is refused
(`check_vouched`). No name in `templates/` is read or written: the source's
tags may name other builds. Then, under the store's lock held exclusively (so
no `rm`, `prune` or another load's publication, which may revoke what it
published if its fsync fails, runs meanwhile), the chain is published oldest
first (`publish_as`, `RENAME_NOREPLACE`). Whatever is under an id by then, found
before or published since by another load, is used only if its names still lead
to the inodes compared, else only if each of its files has the SHA-256 of the one
verified here (hashed under the lock only then, so a load of a stored checkpoint
holds up no create or restore for a hash of its pages); an `ID` without a manifest (a revoked
publication's leftover) is cleared first, as `rm` clears it. The head's chain is then
opened by its manifests, as a restore finds it, and named; if any of this fails,
what it published is removed again (dependants first), and so is the template it
received, unless something here uses it by then (`template::prune`); the template stays open (its use lock) until then, so no
prune or `rmi` takes it before a stored checkpoint keeps it. A crash leaves
staging, which the next staging clears, and perhaps an older part of the chain,
whole. `load -i DIR` reads the same members from a checkpoint directory and its
chain (`Checkpoint::open`), through descriptors.

#### Checkpoint format (versions 2 and 3)

A checkpoint is a directory that is written in full or not at all. Its
directory is the store's, or for a suspend `STATE/suspended`. The staging
code still treats it as if it may belong to an unprivileged user (0.1.0 wrote
checkpoints anywhere), so nothing follows a path that user can change:

- **Staging.** The destination's directory is opened and pinned by fd. Files
  are created with `O_EXCL|O_NOFOLLOW` inside a root-only (0700)
  `.flexvm-staging-<pid>-<nonce>/ck` directory in it, also pinned by fd.
  Firecracker writes the VM state into the VM's own run directory, from
  where it is copied in.
- **Ownership.** Files are fchowned to the destination directory's owner.
- **Publish.** Everything is fsynced, then renamed fd to fd into place with
  `RENAME_NOREPLACE` (checkpoints are never overwritten or modified), and
  the destination directory is fsynced.
- **Durability failure.** If that last fsync fails, flexvm revokes the
  checkpoint: its manifest is durably removed, then the rest of the directory.
  For a stopped-copy checkpoint, revocation happens before the VM resumes;
  if revocation fails too, the VM stays paused and is marked failed. A
  keep-running copy-on-write checkpoint has already resumed the VM: it keeps
  running, and if revocation fails the error reports that the checkpoint may
  reappear after a crash.
- **Restore.** Every file is opened with `O_NOFOLLOW` and must be a regular
  file.
- **Leftovers.** A later checkpoint into the same directory clears staging
  that a dead VM process left behind. A revocation's leftover (no manifest),
  the store's next removal does.

| file | contents |
|---|---|
| `manifest.json` | line 1: checksum of the rest; then JSON with the format version, name, address, template name and content id, machine (vCPUs, base/max/hotplugged MiB), guest page count, page counts, the length and checksum of each file, and how much of the app log was passed on (`app_log`, image templates) |
| `vmstate` | Firecracker's state-only snapshot |
| `pagemap` | `FVPGMAP2`, run and data page counts, then runs `(first page, count, DATA\|ZERO, index in pages)` and the CRC32C of every page in `pages` |
| `pages` | DATA pages back to back, in roughly guest page order |

The pager's PRESENT pages are a superset of what changed: template pages
read in by prefetch are PRESENT too. The writer therefore compares each page
with the template and with zero. A page equal to the template, or zero over
a template hole, is BASE and is not stored. A zero page over template data
is a ZERO run. Anything else is DATA.

A restore checks the manifest, `vmstate` and `pagemap` (whose DATA runs
must tile `pages` exactly) before it loads anything, and checks every page
of `pages` against its CRC32C as it reads it. A bad page kills the VM
rather than letting it run on wrong memory. The checksums catch corruption,
not deliberate tampering.

The writer copies each page once and reads it once more to checksum it and
check it for zeroes (plus a template compare where the template has data). Up to 6
threads take 1 MiB units of PRESENT pages in turn. A thread copies its unit
out of Firecracker with `process_vm_readv`, compares each page with the
template (only where the template has data) and computes its CRC32C and
whether it is all zero in the same read (SSE4.2, three interleaved streams).
It then reserves the unit's place at the end of `pages` and writes its DATA
pages there with `pwritev` and `O_DIRECT`, straight from its buffer, so the
page cache is never involved. Units land in the order they finish, which the
page map records, so no thread waits for another. `pages` is created in the
staging directory and preallocated (`fallocate`) in chunks of at most 1 MiB
before the VM pauses, which lets ext4 run the direct writes in parallel.
A full checkpoint reserves every PRESENT page; an incremental checkpoint
reserves the smaller of the PRESENT and dirty page counts. The file is
trimmed to what was written. Each writer uses a 1 MiB buffer backed by a
2 MiB aligned transparent huge page where the host allows it. The whole
2 MiB mapping is charged to the host's memory room and returned on drop;
without enough room, the writer uses an ordinary 1 MiB page-aligned buffer.

An incremental checkpoint (format 3) adds `parent` to the manifest: the
parent's path (`../NAME` when they share a directory, as in the store, else absolute) and id
(its manifest's checksum line). Its page map lists only pages that changed
since the parent's pause, with a third kind, TEMPLATE (the template's page,
a run only). A restore follows the chain (at most 64 deep), checks each
link and that it names the template and size its child does, refuses a
parent that is missing or whose id changed, and flattens the maps: each page
is read from the newest checkpoint that has it. Deleting or rewriting a
parent breaks its children: in the store, `checkpoint rm` refuses it.

#### Copy-on-write and incremental checkpoints

A checkpoint of a VM that runs on (no `--stop`) pauses it only to save
its vCPU/device state and to arm userfaultfd write protection (uffd-wp); the
pages are written while it runs. A guest write to a page not saved yet
faults, the pager saves that page first and only then lets the write
through, so the checkpoint is exactly the memory at the pause.

- **Packets are held during the pause.** Taking the tap down for the
  snapshot deletes the VM's /32, so packets for it would otherwise follow
  the host's default route for the 15–50 ms pause. As in a migration, just
  before the pause the address is pointed at the VM process's hold device; before
  the resume the held packets are injected into the VM's own tap and the
  route goes back to it, so they arrive ahead of newer traffic. A checkpoint
  reports them as `held_packets`. A 1 kHz UDP stream through 6 checkpoints
  lost 59 datagrams (7–11 per pause) before, none now
  (`scripts/faults.py ckpt_packet_hold`). Packets already routed to the hold
  device can still reach it after release (#292). For 30 seconds after the
  route moves on, these stragglers are re-sent through a raw IP socket to
  the address's current route, with TTL reduced by one to prevent loops.
  They can arrive behind newer traffic. An expired TTL, no raw socket, a
  send failure (including exceeding the new route's MTU), or a fragment
  with IP ID zero counts as a drop; packets after a release that did not
  move the route are dropped too. Reports are rate-limited per address:
  `hold IP: re-sent N packets that reached ...`, or
  `hold IP: dropped N packets that reached ..., re-sent M` when any were
  lost. The `dropped N` form is what loss accounting reads.
- **The tap's queue is taken before the pause.** Frames already routed to
  the tap wait in tun's ring until the guest posts rx buffers, and paused
  vCPUs post none, so whatever is queued there at the pause dies with the
  tap when the VM leaves (a migration, `checkpoint create VM --stop`, a suspend),
  uncounted. A guest slow to refill under load leaves hundreds (#136). Once
  the address is held nothing new reaches the tap, so the VM process waits,
  up to 500 ms, for the running guest to empty the ring before pausing it.
  It watches the ring through a copy of Firecracker's tap descriptor
  (`pidfd_getfd`, polled), found once per Firecracker and before the hold,
  as reading a tun fdinfo takes RTNL. What the guest has not taken by then
  stays queued: a VM that resumes (a keep-running checkpoint, an aborted
  migration) gets it from its Firecracker, and one that leaves has it read
  off before its tap is deleted and logged as dropped, so it is counted
  (`ckpt_backlog` keeps Firecracker stopped until the wait gives up and checks
  that a checkpoint loses none). A tap whose queue is full drops frames
  itself and counts them only in its `tx_dropped`, which goes with it: a VM
  reports those beyond what was reported with injected held packets as
  `tap_dropped` in its status and logs them when it leaves.
  `scripts/faults.py same_host_backlog` stops Firecracker for 200 ms at 10k
  datagrams/s and holds the address before it goes on, so every migration
  starts its pause with a queue: about 1,500 datagrams were lost per
  migration before, none now.
- **No Firecracker change for write tracking.** The pager registers write-protect mode
  (`UFFDIO_REGISTER` with `MODE_MISSING|MODE_WP`) on Firecracker's existing
  userfaultfd and its ranges. Nothing has to be requested at `UFFDIO_API`
  time: write-protect faults are reported with `UFFD_PAGEFAULT_FLAG_WP`
  regardless, `WP_UNPOPULATED` is not needed (a page not populated at the
  pause is the template's or zero, which the page map records) and
  `WP_ASYNC` would let writes through unsaved. Checked on 6.18 against a
  context created like Firecracker's (`EVENT_REMOVE` only).
- **Write tracking.** The first keep-running checkpoint registers write
  protection and protects all guest memory while the VM still runs (in 2 MiB
  calls: KVM retries guest faults anywhere in a range the kernel is
  changing, so one call over a region would stall the vCPUs; 70–90 ms
  per GiB populated here). From then on a write fault unprotects a 64 KiB
  block and marks it dirty, as do installs and discards. At each
  checkpoint's pause only the pages dirtied since are protected again, so
  the pause does not grow with memory size. They are protected range by
  range (`protect_ranges` merges gaps of up to 64 pages; ~6–9 µs a call
  here). Above `PROTECT_MAX` (4,096 ranges per region), it widens the merge
  gap fourfold per pass until the count fits or the gap spans the region
  (#293). It never merges across kept hot pages: the real bound is
  `max(PROTECT_MAX, kept_runs + 1)`, up to 16,385 with the default 64 MiB
  hot-page budget if each kept page is isolated. Wider merging trades
  extra refaults for fewer protection calls: KVM drops its mappings of
  everything in a protected range, so the guest would refault all it uses there, clean
  pages too. With a guest reading 256 MiB of a 1 GiB region, protecting
  the whole region cost 66k refaults a checkpoint against 3–17k range by
  range, and no shorter a pause; with nothing of it mapped, at most ~3 ms
  of pause saved per 1,000 ranges.
- **The pause.** Pause through the API, save the state (as for a
  migration), take the dirty pages, re-protect them, arm copy-on-write for
  the pages to save, resume: 17–30 ms here at any size (was 125 ms at 256 MiB
  and 1.5–1.9 s at 4 GiB).
- **The copy.** The parallel writer reads each unsaved page out of
  Firecracker and writes it as before. A write fault on an unsaved page
  copies the unsaved pages of its whole block (16 to 512 pages, as above)
  into memory (a "rescue", about 1 µs a page here) before unprotecting it;
  writers take the rescued copy. Past 256 MiB of rescued copies a fault
  waits for the writers to reach its page instead. Writers never unprotect
  anything, so tracking continues. Each fault costs the guest about 50 µs
  besides its rescue (KVM's exit and refault, waking the pager and the
  vCPU), so a fault saves its whole block rather than 64 pages of it
  (#630): with a guest rewriting 2 × 128 MiB, 1–8 GiB, about 228 faults a
  checkpoint instead of 650–840, and total stall 87–102 ms instead of
  130–142 for incremental checkpoints (97–111 instead of 168–355 for
  full ones), the pause unchanged. Rescues copy
  into 2 MiB chunks of memory (huge pages) kept from one copy for the
  next, as much as the last one held at once, up to the 256 MiB budget, per
  VM taking keep-running checkpoints: fresh memory faulted in here cost
  more than the copy itself (1.3–2.5 µs a page, 60 ms of a 150 ms fault
  budget). Reading on more threads at once was slower. Neither this memory
  nor the hot pages' nor the writers' huge-page buffers is admitted like a
  guest's, so each keeps out of the host's reserve instead: each take is
  checked against MemAvailable less the reserve, the grants guests have
  yet to touch and what was taken lately, and debited, under the host lock
  (`RUN/room-ledger-BOOT`, with the process that took it), so VMs copying
  at once, and admission, see what the others took and never take more
  than there is together (#648). It is populated after the lock goes. A
  debit counts in full until its process marks it populated (under the
  lock again, tried as a take is: else at its next take or controller
  tick), however long that takes, or is proven gone (#691). Linux folds
  each CPU's counter deltas into MemAvailable only every
  `vm.stat_interval` (or past a threshold), so memory populated just now
  may not show for a while: populated debits count, up to twice the
  interval, together for at most what those deltas can hide (the zones'
  thresholds in /proc/zoneinfo, about 15 MiB on 24 CPUs; in full where
  zoneinfo cannot be read). Admission counts them too, and counts again
  after a release (#691). Debits of memory released are not retired: they
  age out, so kept memory taken lately may still count for a while after
  it goes (never less than there is). A take never waits on
  the lock (a fault may be waiting on it): it tries for 1 ms, past another
  take's few tens of µs, and busy past that it takes nothing and the fault
  leaves its pages to the
  writers. A take whose MemAvailable or grants cannot be read takes
  nothing, and so does one whose debits cannot be read until a whole
  window has passed since they were last written. Each VM process's controller samples what is left about every
  second, which faults look at to tell whether a block of copies may still
  be had; a take checks again. Rescue chunks are kept from one copy for
  the next, so most copies take none. A VM process takes nothing before
  its controller has attached its room to the host (its room is closed
  until then). VM processes started by a flexvm before #677 keep its
  mapped `RUN/.locks/memory-v2-BOOT` room, which neither sees these takes
  nor answers these requests, and those started before #691 their own
  `RUN/room-debits-BOOT` ledger: after an upgrade, restart or migrate them;
  until then the reserve may be overcommitted.
  Each writer populates its buffer as it starts (written page by page
  where the kernel cannot). Without room for a block of copies, faults ask the writers for
  their pages and wait for them as over budget, and the pause protects
  pages it would have copied hot; no checkpoint fails for it. Under the
  reserve, under the eviction mark with peers, with the VM starved, or when
  another process asks (admission before it refuses, above), the memory kept for the next
  checkpoint is released (rescue chunks, hot pages' memory, and the last
  checkpoint's hot pages, so the next one writes its hot pages without
  comparing them), and a copy that ends under the reserve keeps none.
- **Hot pages** (#235). Every `UFFDIO_WRITEPROTECT`, protect or unprotect,
  makes KVM zap its mappings of the whole range (6.18 ignores the notifier's
  event type) and flush every vCPU's TLB: after the resume the guest
  refaulted each page it touched (about 2,500 here), and each write fault
  waited for a rescue and an unprotect, one at a time. So the pause first
  copies the pages dirtied both since the last pause and in the interval
  before it (4 threads, about 0.5 µs a page), into memory allocated before
  it, and leaves them unprotected and dirty: the writer takes the copy.
  The next checkpoint copies them again and compares: pages unchanged since
  are left out of a delta (byte for byte what its parent has; only while
  that parent is the last checkpoint taken, which a failure or re-arming
  forgets), and a 64-page block with none changed is protected again. Copies
  as many as its buffer holds, preferring last time's copies, then lower
  page numbers; to bound the pause it looks at no more than four candidates
  per page of buffer (discarded ones included), so it may copy fewer. The
  buffer is allocated before the pause for twice the pages dirty then plus
  4 MiB, up to 64 MiB, and kept for the next checkpoint. Keeps up to twice
  that in memory per VM, allocated without admission but within the host's
  room (as rescue memory is, above), and released like it. Saving
  device state writes guest memory (a vsock transport reset), so the copy
  starts after it. `ckpt_stall`, 2 vCPUs × 4 MiB, 3 runs × 10 checkpoints:
  quiet, stall p50 23.8 → 14.5 ms (p90 30.6 → 22.3), pause 7.1 → 9.4 ms, the
  guest's gap 0.5 ms over it (was 7.5), 64 → 10 write faults, 2,533 → 58 KVM
  page faults; 24 host spinners, 54.3 → 35.3 ms (p90 144.9 → 85.6).
- **KVM and devices.** KVM's own writes to guest memory (kvmclock through
  its pfn cache, steal time and PV EOI through user accesses) go through
  the host page tables, so they fault like the guest's: protecting a range
  invalidates KVM's mappings (MMU notifier), and the cache refills with a
  write fault. Measured: every checkpoint takes write faults on the
  kvmclock page (which only KVM writes) and the steal-time pages right after
  the resume, and its contents equal the memory at the pause. Writes that
  KVM makes without faulting (the preempted flag) fail on a protected page
  and are skipped. Firecracker's device emulation writes through its
  mapping too; a device thread blocked on a fault waits only for the pager,
  which never waits for Firecracker.
- **Discards.** The kernel zaps a page right after the pager reads the
  REMOVE event for it, so a balloon or virtio-mem discard must not be read
  while pages are unsaved. So none is made during the copy:
  - **Free page reports are held.** Before the pause (paused vCPUs do not stop
    Firecracker processing what the guest queued; every checkpoint holds them, a
    fresh VM reports for ~25 s) the VM process sends
    `PATCH /balloon/reporting/hold` (`firecracker/0003`): Firecracker leaves
    the guest's reports in the queue, neither discarding nor acknowledging
    them, until `.../release` after the copy (also on failure) processes
    them. A hold whose answer is lost counts as held, and a release that
    fails for 5 s is retried by the controller, under the VM's
    reservation, until it lands. The guest's reporting worker just waits for the acknowledgement
    (it reports asynchronously; nothing else in the guest waits on it).
    The one batch in flight, 32 blocks of 2 or 4 MiB, stays off the
    guest's free lists meanwhile: 90 MiB measured, and allocating all of
    MemAvailable during a held copy works, without OOM or hung tasks.
  - **Measured** (guest rewriting 1 GiB, two threads allocating, touching
    and freeing 512 MiB every 1.6 s; disk throttled to 300 MB/s so the copy
    takes 6 s at 1.7 GiB and 13–15 s at 4 GiB, long enough for reports;
    3 runs each): without the hold every run with a report during the copy
    stalled all faulting vCPUs once for 1.2–1.3 s (1.7 GiB) or 2.9–3.6 s
    (4 GiB); with it no discard reaches the pager, the worst page write is
    65–96 ms (faults waiting for the slowed writers past the rescue budget,
    as before) and nothing reaches 134 ms; p99.99 is unchanged (0.1–0.5 ms for
    the rewriter, 1–4 ms for the allocating threads, including the
    guest's own page faults). `scripts/faults.py cow_reports_held` checks
    that reports are held during a copy and carried out after it.
  - **Balloon inflate and virtio-mem** happen only on the host's request:
    flexvm's balloon target stays 0 (the guest never inflates on its own,
    and `deflate_on_oom` is off), and virtio-mem resizes need the VM's
    reservation, which the checkpoint holds.
  - **Fallback.** A REMOVE that comes anyway (a Firecracker without the
    patch, where the hold request fails and is logged) is still safe:
    before each read the pager probes for a queued REMOVE (re-protecting an
    unsaved page fails with EAGAIN while one is queued) and first saves
    everything left, in memory with 8 threads if it fits in a quarter of
    available memory, else by waiting for the writers. The guest's faults
    wait meanwhile (the kernel refuses every ioctl until the event is
    read): 1.2–3.6 s stalls here (see below). A REMOVE that slips in between the probe and the
    read, or writers that stall, invalidate the checkpoint instead of
    saving wrong contents.
- **Other operations** wait for the copy: migration, pause, suspend and
  resizes need the VM's reservation, which the checkpoint holds. A kill
  stops the copy (the checkpoint fails). Exec works (the VM is `running`;
  `flexvm debug NAME status` shows `checkpoint_copy`).
- **Failure.** A copy that fails publishes nothing and the VM runs on. A
  VM process that dies leaves only root-only staging.
- **Incremental** (`--incremental`): writes only the pages dirtied since the
  VM's last checkpoint here that it ran on after (taken since it last
  arrived on this host), as a delta that names its parent (format 3). The
  delta is chosen over writing a merged full image because it costs time
  and space in proportion to what changed (35 MiB and 90–110 ms for a 4 GiB
  VM with a small writer, against 4.2 GiB and 1.5–1.9 s); the price is that
  restores read a chain and parents must be kept. Before writing a delta
  the whole chain is verified (and must stay under 64 links), and just
  before publishing it is walked again through the manifests' parent
  references and must have the same ids. The check covers metadata and page
  checksum lists; page data is checked when read, except that a `--stop`
  delta (whose VM is then gone) reads every page it inherits first. Re-arming
  write tracking (after a failed re-protection) forgets the dirty history,
  so the next delta needs a full checkpoint first. A failed checkpoint gives back the
  dirty pages it took, so the last good one stays the base, and every page
  stays either protected or dirty. `--stop` can be incremental too.
  Tracking costs a write fault per 64 KiB block written between
  checkpoints, and the first protect makes KVM refault each page once.

`scripts/faults.py` checks this with `scripts/memwriter.c`, a guest program
that rewrites its memory all the time in a known order, each page stamped
with its iteration and a salt from RDRAND, and checks every page against its
own record before rewriting it, plus all of them on request at an iteration
boundary. A restored copy finds any page saved with contents from after the
pause (or before its last write before it). The VM process also hashes guest
memory during the pause (`ckpt_memhash` test fault), which must equal the
hash of what the checkpoint restores (`ckhash`).

### Migration ownership

Each migration has a random id. Once the target may have received the
vmstate, the source never resumes on its own: it resumes only on an explicit
refusal, or when the target's listener, asked about that id, says it aborted
(asking also fences the id off, so it can never commit later). If the target
committed, the source stays paused and serves memory until the target's
record says released (all pages in, or the VM gone there). The records are on
disk (`STATE/migs`) and outlive the processes and the listener, so a committed
id is never answered as aborted. If the target cannot be asked, the VM stays
paused on the source until it can. See docs/process-per-vm.md for the
invariants this keeps.

Test faults (`flexvm debug fault NAME MS` with FLEXVM_FAULTS=1 in the VM
processes' environment) cover each failure path: migration (`pages`,
`route`, `lost_ack`, `status`, `prepare_fail`, `short_incoming`,
`slow_preload`, `kill_prepared`), restores (`restore_no_hold`,
`restore_before_run`, `restore_after_run`, `resume_kill`, `started_fsync`,
`started_unmark`, `resume_fence_fail`), checkpoints (`prealloc_fail`, `ckpt_memhash`, `ckpt_fail_protect`,
`ckpt_hot_read_fail`, `ckpt_no_hold`, `ckpt_abort`, `ckpt_slow`, `ckpt_fail_write`,
`ckpt_copy_wait`) and guest requests (`guest_drop`, `guest_lose_reply`);
`scripts/faults.py` uses them.

### Standby VMs

`run` takes a standby VM of the template when one is ready: it was restored
exactly like any other VM (same pager, so it migrates and checkpoints like
any other), then paused. Taking it is: route its address to its tap, resume,
`START`. When there is none (or the paused VM's resume never reached its
Firecracker), `run` loads the snapshot itself. A resume that reached it and
failed (an error answer, a timeout, a Firecracker that died) fails the `run`
instead: Firecracker resumes vCPUs one by one, so the guest may have run, and
a second copy could repeat what it did.

A claimed or cold `run` binds its control socket before its registry entry
first says running, so a control call made as soon as the entry appears
connects; a failed bind fails the start. A claim's timings split `neighbour`
(tap and neighbour setup), `fence` (host lock and generation check) and
`route` (the route replacement).

- **Count.** `flexvm pull IMAGE --standby N` keeps N; each claimed one starts
  its replacement, none start unless they leave the host's eviction mark
  available (so a refill never takes the room eviction moves VMs away to
  make), and the memory controller stops them all when the host goes under
  its reserve. A standby VM also checks every 100 ms and leaves by itself
  under the reserve, so a host with no running VM relieves them too. Idle
  standbys share a one-second ranking snapshot per template: a nonblocking
  lock elects one scanner, which atomically publishes fixed-size identities
  sorted oldest first. Each standby binary-searches only its own rank every
  0.5–1 s (spread by pid). A snapshot only keeps a standby: one it ranks extra
  (or misses) rescans under the lock before leaving, so a claim since
  publication cannot retire the wrong one; extras leave within 2 s plus a
  check. A busy ranker
  defers the check, without blocking claims or triggering private scans. The
  lock and snapshot live beside the refill lock, outside the removable pool,
  and work without a listener. Each elected ranker removes its template's
  abandoned snapshot temporary files under the rank lock before publishing.
  Commands and refills still scan live records.
- **Generations.** `flexvm pull` publishes each build as an immutable
  `templates/.gen/<content id>/` and points `templates/NAME` at it with one
  atomic symlink swap, all through the templates directory as opened and
  locked (a build's staging and publication stay in it whatever its path
  names meanwhile). A pull that would build the same template again (same
  image manifest, app, root filesystem, sizes, build recipe, kernel and
  Firecracker; `template::up_to_date`) publishes nothing. VMs, migrations,
  standby VMs and checkpoints refer to generations by content id. Standby VMs
  of an older generation exit; running VMs keep theirs. A pull that moved a
  name waits a few seconds for those standby VMs, then deletes the generation
  the name linked to before as `image prune` would (`template::prune` of that
  id alone), unless the templates directory is shared: a state whose
  `templates` is a link marks its target `.shared` when opened
  (`template::note_shared`, under the templates lock, which the pull's
  decision holds exclusively), since its suspended VMs hold no lock the
  owner could see. Before marking it, each such open records the state, and
  the state the directory is `templates` of (one with `.synced`), in
  `templates/.states/` (a file per state, named by a hash of its canonical
  path), so `image prune` and `rmi ID` (`template::shared_users`, under the
  exclusive templates lock) read those states' suspended VMs and stored
  checkpoints (`host::recorded_template_users`); their running VMs hold the
  use lock, which is per host. One that cannot be read, or is gone (moved
  with its records, or not mounted), keeps every generation; one whose
  `templates` is another directory now counts for none (its record stays). A
  `.shared` without `states` (an older flexvm's) may have unrecorded states,
  and keeps everything too. `image prune --force-shared` takes the record as
  right: it forgets gone states and marks the directory recorded. A stopped
  VM's rename holds `STATE/.locks/suspended-moves` exclusively around its
  directory's move and readers of the records hold it shared (a listing
  during a rename may show neither name). `image
  prune` reads the names, then, 64 at a time, takes each candidate's use lock
  and reads the users (a VM that suspended before its lock was ours published
  its checkpoint first), then the remaining generations' root filesystems once. An incoming migration uses the generation with the source's
  content id, which the source sends first if the host does not have it
  (step 0 above). `flexvm rmi` removes a name and the
  generation and root filesystem nothing uses any more: see below.
- **Image removal: users and locks.** What uses a template generation
  (`templates/.gen/ID`), and what shows it:
  - A running or paused VM: its process holds the generation's use lock
    (`host::use_lock`, by the directory's dev and inode, in the host's lock
    directory) shared for as long as it has it open; its registry entry names
    the content id.
  - A starting VM (cold run, standby claim, restore, resume, arrival): the
    use lock, taken by `Template::open*` right after opening the directory
    and checked against the directory's path, so one renamed away before the
    lock was ours fails the open. Its registry entry comes later.
  - A standby VM: its process, as a running VM. The standby count names only
    the template name. `rmi` takes the pool's refill lock (waiting for any
    refill in progress) and holds it to the end, so no standby starts; then,
    briefly under the exclusive templates lock, saves the count, captures the
    live standby VMs' pidfds and sets the count to 0. With the templates lock
    released (pulls go on), it stops them and waits on their pidfds for process
    exit (their pool lock files disappear before they release the generation's
    use lock), or until one is claimed (a registry entry: a VM now, which
    ignores the stop and keeps its generation as any VM does). Under the
    exclusive templates lock again, it takes a count `set` wrote meanwhile as
    the one to keep, rechecks that no standby VM is live, and removes. It
    deletes the count only after the name's link is gone, or restores it if the
    name survives, including on timeout or a failed removal.
  - An incoming migration: the listener, for 17 s after it said it has the
    generation or received it, then the target's process, from opening the
    source's content id (`open_id`) until it is a running VM.
  - A checkpoint restore: the restoring process, from `open_id`.
  - A stored checkpoint (`checkpoint create`): its manifest in
    `STATE/checkpoints` (any there, removed ones' too, `checkpoint::managed`,
    read with the VM records). Its VM process (which holds the generation
    open) publishes it before it lets go. A checkpoint directory elsewhere
    (0.1.0's, restored by path) does not keep its generation: like an exported
    image it names it by content id, and restoring it after `rmi`, `image
    prune` or a rebuilding pull fails.
  - A suspended VM: no process, only its record, the published checkpoint in
    `STATE/suspended/NAME` (a manifest, neither STARTED nor DISCARDED) whose
    manifest names the content id. A suspend publishes it before its process
    exits and lets go of the use lock, and a resume opens the generation
    before it marks the checkpoint STARTED, so the lock or the record shows it
    at every moment.

  What uses an image root filesystem (`images/rootfs/KEY.ext4`):
  - Generations, by `meta.json`'s `rootfs`; one whose metadata cannot be read
    counts as using every root filesystem.
  - A pull in progress: its key's lock (`image-DEV-INO-KEY.lock`) from the
    cache check through the build and publication, then the root filesystem's
    use lock shared (`image::Cached::reserved`), taken under the key's lock
    and with `.conf` read under it, until the template is published (its
    generation keeps it then) or the pull ends.
  - Tombstones (`templates/.gen/.ID.rm-NONCE`): a removed generation's, kept
    with only its `meta.json` while a pull holds its root filesystem, and
    decided again by every sweep, so a pull that fails leaves nothing that no
    sweep removes.

  The locks, in the order they are taken:
  1. The templates lock (`templates-DEV-INO`): exclusive for `rmi`, sweeps
     and publication (which reads the link it replaces), shared while a build
     makes its staging directory,
     and while `standby::set` checks the name and writes its count. `set` drops
     it before refilling. `rmi` takes the pool's refill lock before it and
     holds that throughout, so no refill starts a standby between its snapshot
     and removal; a refill never takes the templates lock, and nothing takes a
     refill lock under it, so `rmi` never waits for a refill (or for standby
     VMs to exit) holding it.
  2. A generation's use lock: shared by its users (waiting), exclusive for
     `rmi` (never waiting: held, the generation stays).
  3. An image key's lock: exclusive for a pull (waiting, until interrupted),
     and for `rmi` and sweeps (never waiting: held, a pull uses the root
     filesystem).
  4. A root filesystem's use lock: shared by a pull under 3, exclusive for
     `rmi` under 3 (never waiting).

  A VM takes only 2. Only shared holds wait behind a later lock's holder,
  and exclusive holds of 2–4 by `rmi` never wait, so a pull holding 4
  while it waits for 1 (its sweep, staging and publication) deadlocks
  nothing. `rmi` takes 1 exclusively and finishes earlier tombstones (the
  sweep), checks that the name still links to the content id and removes
  the link, and keeps the generation if another name links to it. It then
  takes 2 exclusively, and only with 2 held reads the VMs' records
  (`Host::template_users`: registry entries and every published suspended
  checkpoint, also one whose name a resuming process holds). A VM that
  suspended or started resuming since the command looked shows up there.
  Either a held 2 or a record keeps the generation; otherwise `rmi` renames
  it to a tombstone. If no generation's metadata names the tombstone's root
  filesystem, `rmi` takes 3 and 4 and removes the `.ok` marker first, then
  `.ext4` and `.conf`; if either is held, the tombstone is kept as above.
  Then the tombstone goes. Sweeps, at every build's start and every `rmi`,
  finish tombstones the same way under 1. A pull whose key lock waited for
  an `rmi` finds no marker and builds the root filesystem again.
- **Component identity.** The content id includes the kernel's hash from build
  time, but migration, resume and restore don't check the kernel file again: the
  running kernel is already in guest memory, so replacing `artifacts/vmlinux`
  leaves existing generations usable. `mem`, `vmstate`, rootfs and Firecracker
  are still checked.
- **Settling.** The first run after a restore is slow (Firecracker's first
  resume, the guest catching up and handling the new VMGenID: ~10 ms of extra
  `START` latency here). Each standby VM therefore runs once in the background,
  as long as the reseed below takes plus 50 ms, then is paused. Firecracker
  calls in a load have deadlines, and shutdown kills a load in progress.
- **RNG.** Firecracker gives every snapshot load a new VMGenID; on it, the
  guest kernel reseeds its RNG and then logs `random: crng reseeded due to
  virtual machine fork` (add_vmfork_randomness). The agent's `FORKS` counts
  those lines in `/dev/kmsg`, and a standby VM is only stocked once the count
  is above zero. This relies on templates being cold boots with no reseed
  logged before the snapshot, so no two handed-out VMs share RNG state; until
  then only the idle agent runs. That is what is provable here: this kernel's
  vmgenid sends no uevent, and `/dev/sysgenid` is not ordered against the
  reseed. With an agent that has no `FORKS`, a standby VM is only checked to
  answer (logged once). VMs restored on the fallback path or migrated reseed
  after resume, as before.
- **Clock.** The guests use the TSC clocksource, so Firecracker's
  `clock_realtime` (which adjusts kvmclock) has no effect: a VM's wall clock
  starts at the template's snapshot time, whether standby or not (minutes to
  days behind). The TSC keeps running while a VM is paused, so a pause adds no
  further error. The agent's `START <ip> <unix time> [dns]`
  sets the address and steps `CLOCK_REALTIME` to the host's time, and
  answers only then. A standby VM gets its clock stepped (`CLOCK`) while it
  settles, so `START` at take finds it right and skips `clock_settime`, which
  can take tens of ms in a 24-vCPU guest. A migration target, after resuming,
  and a source that resumes after an aborted migration send `CLOCK` in the
  background (up to three tries, until a round trip is under 5 ms), so the guest gets back
  the downtime too: measured within ±2 ms. If a clock request fails it may
  still be on its way into the guest, so the next migration first waits for
  the agent to answer a ping (it serves requests in order) rather than let it
  land, stale, after the snapshot. An agent that answers `unknown request` to
  any request (`START`, `CLOCK`, `FORKS`, an exec's `SESSION`) is too old: the
  call fails with that answer and a hint to rebuild the rootfs and its templates.
  KVM saves the realtime clock that `clock_realtime` needs only while the VM
  has a master clock, and drops that for good once the vCPUs' TSCs were
  restored more than a second apart: a migration target whose load waited
  on its source for guest memory (each vCPU's kvmclock page faults during
  the load). Firecracker refuses to load such a VM's later snapshots with
  `clock_realtime`, so a restore that gets that error tries once more on a
  fresh Firecracker without it; the clock is stepped afterwards as above. A
  restore also tries once more when its Firecracker died with nothing given
  up, and a standby VM whose Firecracker died is never handed out.
  Retries stop at the resume: snapshots are always loaded with the vCPUs
  stopped and resumed only once loaded, and a failed resume is never
  retried, as the guest may have run (test fault `resume_kill`). A
  migration target whose prepared load fails that way retries on a fresh,
  unprepared Firecracker before it commits (the guest never ran, and the
  paused source still serves every page, the preloaded ones included); once
  committed, a failed resume leaves the VM failed there.

### Networking

```
 guest eth0 192.168.100.128/32 ── tap (host) ── route 192.168.100.128/32 dev tap
   gateway 169.254.1.1, MAC pinned           peers: route 192.168.100.128/32 via <host>
   (identical in every VM)                   LAN:   host answers ARP for it (proxy ARP)
```

- Every guest's network setup is the same except for its address. The gateway
  is a fixed link-local address whose MAC is pinned in the guest, and every
  tap uses that MAC. So clones of one template need no per-VM changes beyond
  the address in `START`, which the guest agent applies with one rtnetlink message.
- Taps are created with each VM's Firecracker (ahead of time for standby VMs). The
  host route and a permanent neighbour entry are set with rtnetlink while the
  snapshot loads, so networking adds nothing to start time.
- TCP port forwards (`ports.rs`) track blocked readers with `TCP_INFO` acknowledgements:
  a reader can drain its kernel queue before the proxy's socket becomes writable.
  Each direction takes a baseline when it first holds unwritten data, then samples
  at most once per second while buffered, including failed queries. Other forwards'
  traffic cannot drive the sampling rate; the one-second poll timeout keeps checks
  running without socket activity. Only writes or advancing ACKs count as progress;
  a reader stalled for four idle periods can give up its slot at the connection cap.
- udev with `MACAddressPolicy=persistent` (systemd's default) can replace a new
  tap's MAC after flexvm set it to the gateway MAC: it read the kernel's random
  one first, and its write lands whenever its worker gets to it. The host then
  drops everything the guest sends (to the gateway MAC), so connections to the VM
  time out (#841). The VM process puts the MAC back (one `RTM_SETLINK`) whenever it
  hands a tap to a VM. Also, when udevd runs and sees flexvm's network namespace,
  `create_tap` subscribes to udev's monitor before it makes the tap and puts the
  MAC back once udev broadcasts that it is done with the tap (checking it every
  5 s until then, for as long as the tap is there). To stop udev touching the
  taps at all, match their state directory's prefix (`f` and five base-36
  digits, followed by the process and tap suffix) in a link file:

  ```ini
  # /etc/systemd/network/10-flexvm-taps.link
  [Match]
  OriginalName=f[0-9a-z][0-9a-z][0-9a-z][0-9a-z][0-9a-z]*

  [Link]
  MACAddressPolicy=none
  ```
- Addresses come from the host's `vm_ips` range, which is authoritative:
  **every host's range must be disjoint** from the others', and only an
  address's home host hands it out, so two hosts can never pick the same
  address. An address whose VM migrated to another host stays reserved
  ("lent", in `STATE/addrs/IP`) until that VM is killed wherever it is (its
  host tells the peers), or it migrates back and has all its memory there again
  (released; an arrival that dies before leaves the loan in place). If that message is lost, the
  address stays taken; removing `lent` from that file frees it. Leaks, never
  collisions. A restore elsewhere that keeps the address borrows it the same
  way (op `lend`). Every address carries a generation that orders the VMs
  that had it, and a revision that orders the places it ran within one;
  messages about older ones are ignored, and the route a peer
  announced for the newest one is put back when a claim here goes without
  its VM running (see process-per-vm.md).
  Set `cluster_ips` (CIDR or FIRST-LAST) in every host's `host.json` to cover
  every host's VM range; each host's `vm_ips` must fit entirely inside it. Only
  addresses in this locally configured allowlist may arrive, be routed or lent.
  Unset, it allows only this host's `vm_ips`; peers configured without it
  produce a warning from both `info` and `listen`. `info` reports the effective
  allowlist as `derived.cluster_ips`. `host.json` is edited by hand; loading or
  reloading it validates it (`Config::validate`: range syntax, containment of
  `vm_ips`, peers, underlays, `dns`, `announce_dev`; unknown keys refused). An
  invalid one refuses every command, and an invalid reload leaves the last
  valid configuration in use. A peer's report
  of its own range never authorizes an address here. Withdrawals of recorded
  generations remain accepted, including retries, after the allowlist narrows.
  A generation routed via a peer is withdrawn (same generation) only by that
  peer: the asking connection's address, and the addresses and
  `peer_underlays` of each configured peer it is one of; or by any peer with a
  newer revision of it than recorded (the VM migrated on and ended there before
  its announcement arrived: withdrawals carry the revision, the durable notice
  the latest one) or a newer generation. A newer revision announced may come
  from any peer.
  Configured `peer_underlays` addresses count as that peer's next hops (and are
  no VM's address); nothing is trusted for being on-link. Boot recovery stays incomplete, and the
  listener's periodic sweep tries it again, while a saved next hop is no known
  peer address and a peer by name has none known yet.
  No VM gets a local, peer, underlay or gateway address (#549), even inside
  `cluster_ips`. What a peer
  asks for (arrival, route, lend) is checked against the listener's own peer
  lookups, briefly waiting for one under way; a restore or resume, root's own,
  against the listener's last-known peer addresses (`RUN/peers.json`) whatever
  their age, with no DNS wait. Reinstall and boot recovery repeat these checks
  and the next-hop check against current configuration, with no DNS wait; a
  boot's pass tries again while a peer by name is not known yet.
  A route's `via` and a migration target's reported underlay must be the
  connection's peer address or one of the configured peers' known addresses,
  or a configured `peer_underlays` address, and unicast (no router check: a cluster VM's
  /32 via a peer's own address sends that VM's traffic to the peer only, which
  any peer may claim by announcing the VM); one local to this network namespace
  (hosts sharing a machine) is taken and installs no route. Route requests use the
  listener's strict peer lookup; migration replies use its last-known peer
  addresses plus the target connection's address.
- Reachability:
  - **Peers** get a route pushed to them: `<vm-ip>/32 via <host underlay ip>`.
    Routes via an address local to the host's network namespace (including
    loopback) are skipped, so test hosts sharing a machine keep each other's
    tap routes; the first skip is logged.
  - **The LAN** (the announce device: the device of the route toward the
    peers, or host.json's `announce_dev`): the host answers ARP for its VMs
    (proxy ARP) and sends a gratuitous ARP whenever a VM arrives. Other
    machines on the LAN therefore follow a migrated VM without any
    configuration. Give VMs addresses from the LAN's subnet and they can use
    the LAN's normal gateway for internet access.
  - Underlay and announce-device derivation uses the listener's last-known
    peer addresses in `RUN/peers.json`, whatever their age, and IP literals
    directly. The listener looks its peers up as it starts (within 2 s, a
    failed lookup keeping the address it last had) and writes the file before
    deriving anything, the address it advertises for a wildcard `ADDR`
    included. Other processes never look up a name the listener has seen,
    one it could not look up (an empty entry) included, so once a listener
    has run nothing waits on DNS; a name added while it runs gets an empty
    entry before its lookup starts. A name with no entry at all (no listener
    has run since a boot) is looked up within 2 s, once per process (a failed
    lookup counts as no addresses until the listener's entry stands), so a VM
    started before the listener still announces its routes. Nothing under the
    host lock or on a migration's downtime starts such a lookup. If a peer elsewhere has no known
    IPv4 address, nothing is derived and a diagnostic is logged, saying to
    start `flexvm listen` when the listener has not looked a peer up (no
    peers, or all local, uses loopback).
    Explicit `underlay` and `announce_dev` settings
    override derivation (`announce_dev` `"none"` disables announcements).
- On migration, the target routes the address to its new tap at the commit,
  right before the VM resumes (its neighbour entry goes on the tap while it
  prepares): an arrival that fails or dies before leaves this host's route
  to the address, say back to its source, as it was. A dead arrival's
  record (`STATE/migs/ID`) names the address, and once it reads as aborted
  the route a peer announced for it is put back, in case it went missing
  (the record stays until that succeeds, so a later query retries it). The guest keeps its address and TCP state, so connections
  continue, and packets that arrive during the downtime are held, not lost
  (`hold.rs`):
  - Just before pausing the VM, the source routes its address to a TUN
    device of its own (`<prefix><pid>h`; the one route this adds). A thread queues
    what arrives there, up to 4 MiB per VM, beyond that dropping and counting.
  - Once the target answers (the VM runs there), the source opens a stream
    on the migration connection and, once the target accepts it, sends the
    queue (u32 BE length, packet), then whatever reached the TUN
    device meanwhile. It waits until the target has injected all of it,
    points its own route at the target, and sends the few packets that were
    still on their way. If that route cannot be set, the TUN's route goes
    too (instead of taking the address's packets with nowhere to send them)
    while the switch is retried. Hosts sharing a network namespace (tests
    on one machine) share that route: the target does not route the
    address at its commit; at the point the source would switch the route,
    it sends `SWITCH`, and the target, with all before it injected, points
    the route at a hold of its own; the source's last packets follow, and
    once the stream ends the target releases its hold into the VM, so the
    held packets stay first and in order (#78). If routing to the target's
    hold fails, it plugs its tap and routes the address there instead; routed
    packets wait behind the source's last held packets until the stream ends.
    If plugging or routing to the tap fails too, it answers `n`: the source
    sends the rest of the held packets, and the target routes the address
    once the stream ends. Releasing a hold into a VM
    here (that target's, an aborted source's, a checkpoint's) never drops
    what it took because the route change was slow (it waits for RTNL,
    which a busy host's tap and TUN teardowns hold): what arrives while the
    route changes is injected as it comes, and once it changed everything
    the TUN device took before is injected, the device read to its end
    (#136; scenario `same_host_slow_route`). A target letting go of its
    hold first plugs its tap's qdisc (`sch_plug`): what the route sends to
    the tap from the switch on waits there, while the held packets go past
    it (the injector's packet socket bypasses the qdisc); then the plug lets
    everything through, in order, as a FIFO; it stays the tap's qdisc,
    a pass-through, for the rest of the VM's life on that tap (instead of
    the default `fq_codel`; a tap never queues there anyway, its driver
    takes every packet into its ring, `TAP_QUEUE`, or drops it). Putting
    the default back would cost more: any root qdisc change on a running
    tap first points it at `noop_qdisc` for an RCU grace period, dropping
    what is routed to the VM meanwhile (about ten packets per change at
    35k packets/s, measured); the plug goes in before the route, when
    nothing does. Only a plug that may be installed is unplugged (also
    after a lost ACK), never after the kernel refused it, and only our
    plug (`1:`, kind `plug`) is ever released or removed, never another
    root qdisc. However late the hand-over after
    the switch runs on a busy host, nothing routed overtakes a held packet
    (scenario `same_host_late_handover`). A source likewise reads its hold
    device itself once the route moved, and hands all of it over, not
    bounded by time. A target that takes
    `SWITCH` says so in its prepare answer (`hold_switch2`); a source sends it
    to no other. Each of these late route changes happens under the host
    lock and only while the address is still this VM's with a current
    generation: a newer VM's route, announced meanwhile, stays. The target takes one stream per migration, on that
    connection, for that VM instance only, and stops it if the VM is killed
    or moves on. Nothing is resent: a stream that breaks off, or a source
    whose answer was lost, loses the rest (counted).
  - The target injects each packet into the guest as an Ethernet frame sent
    out of the VM's tap from an AF_PACKET socket (from the gateway's MAC to
    the guest's): Firecracker reads it like any other frame, byte for byte as
    it arrived, with no host routing involved; packets that are not whole
    IPv4 packets for the VM's address are dropped (and counted). Only when the
    stream ends (or none opens within 250 ms; then none is taken any more)
    does it announce the address (route pushes to peers, gratuitous ARP,
    each only while that VM still runs there), so held packets come before
    traffic sent straight to it.
  - If the migration aborts, the source injects the held packets into the
    VM's own tap before resuming it. If it lost track of the outcome, the
    packets wait for it (even after the paused copy is gone): dropped if the
    VM went to the target, injected into its tap here if it has come back.

  `migrate` reports `held: {packets, kib, dropped, injected, dropped_target}`.
  TCP peers stall for about the downtime instead of a retransmit timeout
  (200 ms, 400+ ms when the retransmit is lost too). Taps carry a host-scope
  address (`169.254.1.2`, not answered in ARP: `arp_ignore=3`), because the
  reverse-path filter drops everything an addressless tap sends once the
  guest's address is routed to the TUN device, even in loose mode (a per-tap
  `rp_filter=0` would not help where `all` is 2, as distributions set it), and
  queue up to 4096 frames, so an injected burst fits while the guest catches up.

### Firecracker patches

`firecracker/0001-snapshot-state-only.patch`: an empty `mem_file_path` in
`PUT /snapshot/create` saves only the microVM state. Stock Firecracker always
writes all guest memory, which would make migration downtime proportional to
RAM and double memory use on a host that is already short.

`firecracker/0002-prepare-snapshot-load.patch`: `PUT /snapshot/prepare`, with
the body of a load, does the part of a snapshot load that does not depend on
the VM being loaded, from the given snapshot (the template's): it creates the
KVM VM, its vCPUs and memory slots, hands guest memory to the UFFD handler,
binds the vsock socket and maps the pmem file into KVM. The next
`PUT /snapshot/load` of a compatible snapshot (same vCPUs, machine
configuration and memory layout; hot-plugged slots are replugged to match)
then only restores vCPU, VM and device state. Under nested virtualization
those prepared steps are most of a load (creating a KVM memory slot alone
takes 3–10 ms on a busy host).

The same patch makes a load refuse a snapshot whose devices are not exactly
the template's (#548): the vmstate comes from a peer or a checkpoint
directory, and Firecracker runs as root without a jail, so a device it adds
(a block device on `/dev/sda`, a net device on another VM's tap) would be
opened on the host. Every load names the template's vmstate as
`device_reference_path` (a prepared load checks against the prepared
snapshot); before anything is opened, Firecracker refuses a snapshot with
any block device, with devices of other kinds, ids, number, guest
addresses or pmem files than the reference's, or with a net device or vsock
whose tap or socket the load's overrides do not name. flexvm needs the
patch: stock Firecracker rejects the field.

The reference itself can be a peer's: a migration target may receive the
template generation from its source (#774). So every load also names, as
`confined_pmem`, the one file a pmem device may open (#788): `rootfs` in
Firecracker's directory (linked to the generation's root filesystem), or
for a generation built by v0.1.0, which names its root filesystem by its
path, that path (for a received one, `template::receive` found it holding
that root filesystem here). Before anything is opened, in a prepare and in
a load, Firecracker refuses a snapshot with a pmem device that is writable
or names any other path, byte for byte (so not `./rootfs`, `rootfs/` or
another file in its directory, such as its log).

`firecracker/0003-hold-free-page-reporting.patch`: `PATCH
/balloon/reporting/hold` and `PATCH /balloon/reporting/release`. While held,
the balloon leaves free page reports in their virtqueue (it consumes the
queue notification but pops nothing); a release processes whatever is
queued. Not saved in snapshots: a restored balloon is not held, and reports
queued at the snapshot are processed at its first resume, which kicks
every queue.

`firecracker/0004-sync-tsc-after-restore.patch`: once every vCPU is restored,
gives every vCPU, vCPU 0 included, vCPU 0's TSC offset (`KVM_VCPU_TSC_OFFSET`,
Linux 5.16+), as they had on the source, so all are in one KVM TSC generation
(the master clock and the pvclock stable flag need it), and sets each one's
TSC deadline, which counts in its TSC, again. Each vCPU's restore writes its TSC. KVM takes such writes as in
sync only if they come within a second of each other, and restoring a vCPU can
take much longer than that: its MSRs map guest pages (kvmclock, steal time),
which a migration target may still be paging in from a source that is slow or
down for a while. The vCPUs' TSCs then ended up apart by that long. The
guest's clocksource is the TSC, so its clock jumped by that much after the
step to host time (#136, `guest_calls`: +3.3 s after a 3 s page server
outage). Without the attribute, loading a snapshot of more than one vCPU
fails, rather than run a guest whose clock may jump.

`firecracker/0005-reraise-pending-interrupts.patch`: every resume raises
again the interrupt of each virtio device whose interrupt status is still
set (raised, not yet acknowledged by the guest). A virtio-mmio interrupt
reaches KVM through an irqfd on an IOAPIC pin, and KVM injects those from a
workqueue, not when Firecracker writes the eventfd. A snapshot taken before
that worker ran saves the device's status set but no interrupt in the IOAPIC
or any LAPIC, and the restored VM never gets it. With `EVENT_IDX` the device
interrupts again only once the guest moves `used_event`, which it does from
that interrupt's handler, so the queue stalls for good: a guest that only
receives (a UDP sink) stops receiving after a migration, restore or resume
until it sends something itself (#149). Measured with a save-time check of
the IOAPIC and LAPIC state, about 1% of saves (19 of ~1,900 under load) had
an interrupt lost that way, mostly the balloon's (flexvm parks the balloon
timer right before the snapshot, which raises one). With a debug Firecracker
(not in the tree) that drops a pending virtio-net interrupt from the saved
LAPIC the same way, `scripts/faults.py rx_stall` stalled 26 of 200
operations without the patch and none with it. One eventfd notification
covers both pending kinds (queue and config), whose status bits are already
set. If the guest already had the interrupt, the re-raise costs it at most
one spurious interrupt per device and resume: the handler reads and
acknowledges the status, finds nothing new and returns. The patch has a
unit test of the re-raise; there is no deterministic end-to-end case, as
losing the interrupt on purpose would need a debug hook in Firecracker.

`firecracker/0006-sparse-full-snapshot.patch`: a full snapshot of anonymous
guest memory with no userfaultfd (the template's boot, the only full snapshot
flexvm takes) seeks over the pages `/proc/self/pagemap` reports neither in RAM
nor swapped out: never touched, or discarded by free page reporting
(`MADV_DONTNEED`). Those read as zero, so the memory file keeps holes there and
is truncated first, so a file left from before reads as zero too. Stock
Firecracker writes every plugged byte: for an ubuntu:24.04 template, ~6 GB, of
which 5.7 GB are zeroes that `sparsify` then punched out again (10-34 s of
snapshot plus 2.5-3 s of punching; with the patch 0.2-1.1 s plus ~30 ms, for
the same bytes: #764). `mincore(2)` would not do: it reports a swapped-out page
as absent. Memory mapped from a file (a restore without UFFD), served by a
userfaultfd handler, or a memfd can hold data where this process maps nothing,
so those, and a Firecracker without `/proc`, still write every page.

`firecracker/0007-unmap-premapped-guest-memory.patch`: Firecracker maps a
restore's guest memory and only then registers it with the userfaultfd it
hands the pager. A process that reads Firecracker's memory in between
(`/proc/PID/mem`, `process_vm_readv`) faults pages in as for any anonymous
memory: the zero page, or with THP the huge zero page for a whole 2 MiB.
Registering leaves them mapped, so the guest never faults on them and the
pager never installs them: the guest reads zeroes where the template has data.
GitHub's runners have an agent that reads every new process this way (#949):
the first 2 MiB went, and with it the DSDT, so the VMGenID notification never
ran and no standby reseeded; Firecracker's vmclock write then copied the huge
zero page into a zeroed huge page. After registering each region the patch
checks it with `mincore(2)` (a zero page counts as resident) and, while
anything of it is mapped, unregisters it, drops it with `MADV_DONTNEED` (no
REMOVE event reaches the pager, the range being unregistered) and registers it
again, up to 16 times (a unit test reads through `/proc/self/mem` before registering). The pager checks for the same thing after every load
(`Pager::foreign_pages`: pages mapped while it has them BASE or REMOTE, and
installs that hit EEXIST), so a Firecracker without the patch fails the load
with a clear error instead of starting a guest with zeroed memory.

### Kernel patches (optional, host kernel)

`kernel/` carries two patches against Linux v6.18 for the host kernel, applied
in order. They only matter for keep-running checkpoints. flexvm runs unchanged
on stock kernels, where every `UFFDIO_WRITEPROTECT` makes KVM drop its mappings
of the whole range, so the guest refaults even pages it only reads (#274).

`kernel/0001-uffd-wp-resolve-skips-secondary-mmu-invalidate.patch`: removing
uffd write protection only grants access, so it no longer fires an mmu-notifier
invalidate. That removes the TLB-flush IPIs to running vCPUs after each
unprotect. Devices that share the page tables without page-fault support (SVA
without PRI) aren't considered; flexvm doesn't use them.

`kernel/0002-kvm-x86-write-protect-sptes-on-uffd-wp-arm.patch`: arming uffd
write protection marks the invalidate as write-protect-only, and x86 KVM's TDP
MMU then clears W on its SPTEs instead of zapping them. The shadow MMU,
hugetlb and PAGEMAP_SCAN arming still zap as before.

Measured on nested KVM (GCE n2, v6.18), per keep-running checkpoint of a
guest reading 512 MiB while one thread rewrites part of it: KVM page faults
144k → 10.4k, TLB-flush IPIs ~1,000 → 0, and guest read time lost in the
second after a checkpoint 856 → 85 ms. The checkpoint and COW fault scenarios
pass on both. The details are in #274.

## Measured (WSL2, Ryzen 9 3900X, nested KVM; before process-per-VM unless noted)

| | |
|---|---|
| Template cold boot (one time) | 250 ms (2 vCPU), 420 ms (24 vCPU) |
| `run` → guest agent answering with its address set, from a standby VM | **4–7 ms** p50, 6–14 ms p90 (resume ~2 ms, `START` ~3 ms; host load ~20) |
| same, no standby VM (snapshot load) | 45–54 ms p50 under the same load (36–56 ms on a quieter host) |
| of which Firecracker snapshot load | 22–50 ms (mostly KVM memslot setup, which is slow under nested virt) |
| Migration downtime, idle VM, idle host | **10 ms** p50, 14 ms p90 (2 vCPU); 25 / 31 ms (24 vCPU) |
| TCP ping-pong through two migrations (`scripts/nettest.sh`, host load ~20 on 24 threads) | worst stall **69–158 ms**, at most 1.6x that round's downtime (12 rounds); before packets were held: 206–220 ms, one retransmit timeout every round |
| UDP stream through the same, 5,000 datagrams/s | **0 lost**, 0–17 reordered per round (12 rounds); before: 184–770 lost per round. At 20,000/s: 0 lost, 0–14 reordered |
| nginx image, `run` → first HTTP response from the host | **205 ms** p50 (run 56 + nginx startup 144); `--warm`: **55 ms** p50 (run 31 + first request 22) |
| Background memory pull | ~1.1 GB/s over loopback TCP |
| Post-copy faults, 500 MiB written then read back right after the migration (host load ~15; 4 interleaved rounds of 8) | REMOTE fault p50 **1.0–1.3 ms** (was 4.2–5.2 ms, fetched on the event thread), p99 2.6–4.2 ms (was 12.6–16.8); template/zero faults p50 41–57 µs (was 1.3–1.6 ms, queued behind fetches); local/remote/wait faults blocked 0.77–0.98 s in all (was 1.33–1.6; historical report omitted write-protect faults). The read itself barely changes here: most of it is KVM mapping each page again under nested virtualization |
| First read of 500 MiB once the pull is done (2 vCPU, 2 × 5 interleaved rounds) | migrated: **59 ms** p50 with huge pages (was 1037–1146 ms; 40–50 ms the second time either way); restored from a checkpoint: **54 ms** (was 1047–1124 ms). The collapse pass: 0.4–0.85 s of CPU for 253 chunks (2–3 ms each; up to 9 ms on a loaded host), 0.9–1.8 s in all. Downtime, pull, restore and checkpoint pauses unchanged; RSS the same |
| Idle VM host RSS | 13–35 MiB |
| pause / resume (client observed) | **1.3 / 1.3 ms** p50 (2 vCPU, 0–1024 MiB written): signal dispatch, entry/lock reads and 1 ms state polling included |
| checkpoint (the VM runs on), 256 / 1024 / 4096 MiB written in the guest: VM paused | **20 / 18 / 24–31 ms** (was 125 / 406–428 / 1456–1923 ms); write protection armed beforehand while it runs (first checkpoint only): 20 / 95–125 / 270–380 ms; whole checkpoint 220–250 / 450–620 / 1900–2200 ms |
| ... with a guest rewriting 2 × 256 MiB during the copy | pause 17–56 ms; 650–2700 write faults, 340–1970 of them saving 20–120 MiB first (120–250 µs each); writer iterations > 100 µs: 4–9k (idle 0.1–1k), worst single stall 35–50 ms at 1 GiB (one 100–150 ms stall before 2 MiB protect chunks); free page reports are held during the copy (they cost 0.35–3.6 s stalls before) |
| incremental checkpoint of a 4 GiB VM (small writer running) | **paused 29–50 ms, 92–112 ms in all, 35 MiB written** (full: 4238 MiB, 1.5–1.9 s) |
| checkpoint `--stop`, by memory touched: 256 / 1024 MiB written in the guest | write_pages 113–249 / 483–521 ms (was 435–480 / 2019–2892 ms); paused 286–430 / 760–816 ms (was 653–703 / 2335–3255), including Firecracker's exit; disk: 4–5 GB/s O_DIRECT, 1 GB/s buffered |
| restore → guest agent answering | **33 / 27 / 67 ms** (snapshot load 28 / 24 / 63 ms); whole checkpoint paged in after 39 / 153 / 509 ms |
| suspend (checkpoint + free) / resume of a suspended VM to ready | 127 / 448 / 2012 ms; 27 / 28 / 36 ms |
| suspended VM host RSS | 0 (Firecracker gone) |

The pause/resume figures from the daemon-era benchmark have been removed.
Current lifecycle reports label those measurements `pause_client` and
`resume_client`; each trial reports the median of ten cycles. Other lifecycle
numbers are historical measurements from `flexvm bench --lifecycle` with the
2-vCPU template, 5 trials per size, restoring on the second host on the same machine
(`bench/*-lifecycle.json`). The guest clock step after a restore adds another
35–100 ms after ready.

### Resumable exec protocol

The guest answers `PING` with `pong`; it does not handle `EXEC` or `SPAWN`.
Sessions use `SESSION <id> <len>\n` followed by exactly `len` command bytes,
`ATTACH <id> <offset>\n`, or `CLOSE <id>\n`. The client chooses a random ID;
retrying SESSION with the same ID and command attaches to the existing process
from offset zero. Reusing an ID for another command fails. IDs contain up to
64 ASCII letters, digits, underscores or hyphens; commands are at most 1 MiB.

`ARGV <id> <len>\n` starts an exec without a shell, with exactly `len` body
bytes. Its body has NUL-terminated fields, each a tag byte followed by its
value: `a` an argument (in order, including empty arguments), `e` an environment
entry (`K=V`), `w` the working directory, `u` `USER[:GROUP]`, `d` detach,
`i` client stdin, `t` a pty, and `s` its initial size (`ROWS COLS`). The `d`,
`i` and `t` fields have no value. IDs, retries and body limits work as for SESSION.

The host's exec relay reads each frame into one owned wire buffer and forwards
it unchanged, retaining the buffer and send offset across partial writes and
checkpoint cuts. Complete frames still queued on a cut connection keep their
wire buffers until forwarded; a partial frame is read again after reattachment.
Readiness RPC cancellation checks run every 50 ms on a watcher whose wait is
woken when the request ends, so fast replies need not wait out that interval.

Frames retain `[kind u8][payload length u32 LE][payload]`. SESSION, ARGV and ATTACH
first return kind 4 with the session ID. A session has at most one attachment
(connection streaming its output): SESSION, ARGV or ATTACH replaces it, and the guest
shuts the previous connection down, so its stream just ends. Session stdout/stderr (kinds 1/2)
prefix their bytes with an absolute `u64 LE` offset in the combined output
stream. Kind 3 contains the final `u64 LE` offset and `i32 LE` exit code.
Kind 5 contains the earliest retained `u64 LE` offset and reports output loss;
clients must not silently skip it. Kind 6 acknowledges the stdin bytes taken
so far (`u64 LE`); the client drops those bytes and resends from that offset
after reattachment. Kind 4 also carries `waiting` heartbeats,
`error: ...` failures, or `closed` for CLOSE. Socket writes happen outside the
output ring mutex. Reading an exit does not discard it: after receiving an
exec's exit, the CLI sends the one-byte `SESSION_DONE` (`d`) on the attachment.
The guest waits up to 2 s for it after sending the exit and closes the session
if acknowledged; otherwise the exit stays available for reattachment. A VM's
main command leaves its session open so it can be reattached after a suspend.
Closed sessions retain the ID as a tombstone until expiry so a delayed
creation retry cannot execute the command again.

`ATTACH <id> <offset> <claim> <epoch>\n` attaches as ATTACH does and records
both the host's claim number and its epoch, a random u64 chosen once per host
process. `REJOIN <id> <offset> <claim> <epoch>\n`, which an exec relay sends
after a checkpoint cut its connection, is refused with
`error: a newer client attached since` if its epoch differs from the recorded
one or its claim is lower. A REJOIN accepted before a checkpoint but not yet
run cannot steal a fresh attachment after restore or migration, even though
the new host process's claim counter starts over. Fresh ATTACHes in the
current host epoch may replace an attachment regardless of claim.

The claim-only forms from #1075, `ATTACH <id> <offset> <claim>\n` and
`REJOIN <id> <offset> <claim>\n`, remain supported. SESSION, ARGV and plain
ATTACH record claim 0 and no epoch; claim-only ATTACH records no epoch either.
When no epoch is recorded, an otherwise valid REJOIN establishes its epoch.
A claim-only REJOIN cannot replace an attachment with a recorded epoch.
Before its first exec attachment, the host serializes initialization per VM
and sends `FENCE\n`, which returns kind 4 `ok <generation>`. The guest starts
at generation 0. The host then sends `FENCE <generation+1> <epoch>\n` and waits
for `ok <generation+1>` before sending any attachment. The guest stores this
VM-wide fence in snapshot memory, under the same lock as attachment admission.
An update must advance the generation; repeating the same generation and epoch
is idempotent. Lower generations or a different epoch at the same generation
fail with `error: a newer client attached since`, so a delayed pre-checkpoint
fence cannot undo the restored host's fence. Such a delayed update can still take
the generation the host read first, so on that refusal the host reads the
generation again and goes past it, up to three tries. Generation overflow fails
closed.
Once fenced, every epoch-bearing ATTACH or REJOIN must match the authorized
epoch, even for a session with no attachment yet. A delayed fresh ATTACH from
the previous process therefore cannot replace the restored host's attachment.
Requests without an epoch retain their legacy behavior.

An older guest's `unknown request "FENCE"` reply skips this initialization;
other refusals, missing replies and malformed acknowledgements fail the exec.
The fresh-ATTACH fence requires FENCE support in the guest. The host then
probes once per VM process with an invalid offset (attaching nothing),
first for epoch support, then for claim-only support. Agents that reject a
form with `error: bad session request` receive the next older form, down to
plain ATTACH for pre-#1075 agents. A REJOIN's form refusal also downgrades the
cached form and retries within the same deadline. Older agents retain their
existing fencing behavior; the cross-process fence requires epoch support.

Interactive input uses the same frame layout on the session connection after
the request, or on an `APPIN` connection. `IN_DATA` (kind 1) carries a `u64 LE`
stdin offset followed by at most 32 KiB of data; the guest takes bytes once,
in order, skipping bytes already taken on a resend. `IN_EOF` (kind 2) carries
the `u64 LE` offset where stdin ends. `IN_RESIZE` (kind 3) carries rows and
columns (`u16 LE` each). `IN_DETACH` (kind 4) leaves an exec running detached.
The client may still send the one-byte `SESSION_DONE` after exit.

At most 64 non-detached sessions are running or still sending output; another
SESSION fails with `error: too many sessions: ...`. Detached commands have
64 slots of their own, reserved at start also for sessions with stdin on a
pty, so those can detach while leaving their command running. An attached
pty-stdin session counts towards both caps until it detaches. Once an exit
is sent, its session counts towards a separate cap of 192 unacknowledged
exits, with the oldest closed to stay within it. All retained output for these sessions uses the shared pool;
the oldest unacknowledged sessions are also closed to make room there. If the
pool still cannot cover a session's output, it keeps counting towards the 64.
A finished session whose client has been gone for a minute is closed by the
guest (checked every minute, and whenever the limit is reached), its output
freed; a running non-detached one is closed after ten minutes, its process
group killed as CLOSE would (a client killed outright never sends CLOSE).
A running detached command has no such timeout. Both waits count only time
the guest ran: across a plain pause the TSC, and so the guest's monotonic
clock, runs on, while a CLI keeps retrying through it. The agent keeps its own clock, which a thread
advances every second by at most 2 s, so a pause of any length counts as about
2 s. Closing a session also shuts down its attached
connection, so a write to a stalled client cannot hold it. Closed sessions leave
tombstones: small records outside that limit that expire five minutes after the
close, and beyond 4096 the oldest one (if at least 30 s old) is dropped. For
sessions running or still sending output, each ring keeps 128 KiB and grows
towards 4 MiB from a shared 56 MiB pool. The base reservations and pool total
64 MiB; when the pool is spent, rings stop growing, and a detached client may
then see kind 5 sooner.

Backpressure: while a client is attached, and for 30 s after it drops, the
command's output waits (its pipe fills and the command blocks) once half the
ring is unsent to the latest attachment's offset, so nothing past that offset
is overwritten. Consecutive output of one kind is stored in blocks of up to
16 KiB however small the command's writes; a ring holds at most 4096 blocks,
and output also waits once 2048 of them are unsent (output alternating between
stdout and stderr in tiny writes), so that limit never drops unsent output
either. Only the latest attachment's offset holds output back: a replaced
client reattaching later gets kind 5 if its offset has meanwhile been
overwritten.

The control socket's exec request carries `session` (required: every exec is a
session the client names), `action` (`start`, `attach`, or `close`), and
`offset`; start also supplies `cmd`. A client acknowledges the exit when done,
or closes its session when interrupted; one that vanishes without closing
leaves the command to the guest's reclaim above. Start/attach return the usual
JSON success reply followed by session frames; close returns a JSON reply.
