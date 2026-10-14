# Internals

How flexvm works underneath the commands. The process model, host state and
migration protocol are in [process-per-vm.md](process-per-vm.md).

## Overview

| Concern | Mechanism |
|---|---|
| CPU | vCPUs = host cores (FC max 32). Idle vCPUs halt and cost nothing. Each VM's Firecracker runs in a cgroup of its own with the `cpu` controller on, all at the default `cpu.weight`, so busy VMs share contended CPU equally however many threads each runs. |
| Memory growth | Boot memory (256 MiB + 1/32 of the ceiling) + a virtio-mem region up to host RAM, of which 4 GiB is already plugged in the template. Past that the guest asks for more over vsock the moment it runs low, and its VM process keeps a quarter of the guest (at least 1 GiB) free. See [Memory](#memory). |
| Memory return | virtio-balloon **free page reporting**: pages the guest frees go back to the host within seconds. |
| Root filesystem | One read-only ext4 image on virtio-pmem with DAX, shared by every VM through the host page cache. Writes go to a tmpfs overlay inside the guest, so they migrate with memory. |
| Start | Every VM is a **UFFD restore of a template snapshot** into a pre-spawned, pre-cgrouped Firecracker. The template's recorded working set is copied in bulk; everything else is faulted in lazily from a shared, sparse template image. **Standby VMs** are already restored and paused, so `run` is usually just a resume. |
| Migration | **Post-copy**: the target gets everything ready first (template, address, a Firecracker with the template's VM structure already built); then pause, save vCPU and device state only (~20–200 KiB), load it and resume on the target, then the target's pager fetches pages from the paused source on fault and in the background. The source releases the VM once every page has arrived, and never resumes it once the target may own it. |
| Pressure | If a VM needs to grow and the host would drop below `--reserve`, or the host is already below it, that VM is migrated to a peer with room. |
| Network | Each VM has its own IPv4 /32 routed to a per-VM tap. The address moves with the VM, so open TCP connections survive migration. See below. |
| Container images | `flexvm template NAME --image REF` builds the root filesystem from an OCI/Docker image; flexvm-init runs and supervises its entrypoint. See below. |

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
  requests and ticks alike, is admitted against `--reserve` under the host
  lock, with the last 10 s of grants (`RUN/grants`, every VM process's) counted as used (plugged memory shows up
  in MemAvailable only once touched). A refused guest is told `full` and
  marked starved. Admission is not enforcement: a guest can still fill memory
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
Two details keep untouched plugged memory free:

- Templates wait for free page reporting to finish before the snapshot.
  Otherwise every VM reports the 4 GiB again after restore, and the walk over
  its page structs costs ~64 MiB RSS per VM.
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
the CPU feature bits KVM offered its guest, the XSAVE layout, and the
Firecracker version and build. Checkpoints and migrations pin their template
by content id and so carry its guest CPU. Every snapshot load (run, a standby
VM's load, restore, resume, and a migration target before its source pauses)
refuses a host with a different CPU model or Firecracker, a missing feature
bit or another XSAVE layout, naming the mismatch. Extra feature bits are
fine. Templates built before this record must be rebuilt.

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

One thread reads uffd events, but it never waits for the network or disk:
a fault on a REMOTE page claims a 64-page run and hands it to one of 8
fetcher threads (each with its own connection to the source), so faults on
template and zero pages, and REMOVEs, are served meanwhile. Fetchers and the
4 background pullers install pages as they arrive (16 at a time), and a
fetcher asks for the faulting page on its own, pipelined ahead of the rest of
its run. A fault on a page someone else is installing waits for that copy,
which wakes the faulting thread; installers signal the event thread (an
eventfd) when pages settle, and an install that hits EAGAIN (a REMOVE is
queued) waits until the event thread has read events, instead of polling.
`flexvm debug VM status` reports fault service latency per kind (served
locally, fetched, waited for another installer), measured from reading the
fault to the copy that woke it, plus fetch, queueing and pull times.

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
- **checkpoint NAME DIR** first waits for any VM still pulling memory (from a
  migration source or its checkpoint), and for virtio-mem to settle (see
  below). It then pauses the VM, quiesces its devices and pager like a
  migration source does, saves the vCPU/device state and writes every page
  that differs from the template into DIR. With `--keep-running` (the
  default) the VM resumes as soon as its memory is write-protected and the
  pages are written copy-on-write while it runs (pause 17–30 ms at any
  size, see below); with `--stop` it stays paused for the write (2–3 GB/s
  here) and is killed. `--incremental` writes only what changed since its
  last checkpoint, as a delta against it.
- **restore DIR** works on any host whose template has the same content id.
  It loads the verified state (copied to the VM's own run directory) into a
  fresh Firecracker, paused. That Firecracker's pager takes pages from the
  checkpoint's page file: on fault, and in the background (the template's
  working set first) until all are in. The VM is ready in about the time of
  a `run`. By default it keeps its name and address. A restore refuses an
  address a peer is using; `--ip auto` picks a new one, which also makes a
  restore a fork of a running VM. `--paused` holds the restored VM paused
  until `resume`; its memory is still paged in meanwhile.
- **suspend** (SIGTERM) checkpoints into `STATE/suspended/NAME` (`/var/lib/flexvm` by
  default; it must be on disk, not tmpfs). Then suspend kills Firecracker, so the VM costs no memory. Memory is
  released only once the checkpoint is durable. The pager is stopped before
  Firecracker dies, so no discard event can mark a saved page as zero.
  A suspended VM's checkpoint stays in `suspended/`.
  - **Resume** first creates a `STARTED` marker in it and fsyncs it, before
    any vCPU runs. It then restores lazily like `restore`, and deletes the
    checkpoint once every page is in. The pager closes the checkpoint's
    files as soon as the last page has settled (readers still busy finish
    first), so the deletion gives the disk space back while the VM runs on.
  - **Kill** creates a `DISCARDED` marker the same way before it answers.
  - **Resume** of a checkpoint marked `STARTED` or `DISCARDED` deletes it
    instead: a resumed or killed VM never comes back.
  - **Failed resume.** If it fails before the resume request reaches
    Firecracker, the VM stays suspended. If it fails after, the checkpoint
    is consumed: the VM is gone, as re-arming it would replay what it did.
    If the `STARTED` marker cannot be made durable, it is removed again and
    the directory fsynced before the VM goes back to suspended. If that
    fails too, the marker may or may not survive a crash: the VM (which
    never ran) is listed `quarantined` (a `QUARANTINE` file with the boot id
    and why). It cannot be resumed; a `kill` discards it as usual, and after
    a reboot the disk decides (marker: deleted; none: suspended again). Test faults
    `started_fsync` and `started_unmark` cover both.
- **Device quiescing.** An API pause (`PATCH /vm Paused`) puts Firecracker's
  VMM thread into a loop that serves only API requests until the resume. It
  does not return to its event loop meanwhile, so device emulation stops
  with the vCPUs: no queue, tap, vsock backend or timer is serviced, and the
  events wait for the resume. flexvm builds on that:
  - **Loaded paused.** A load with `resume_vm: false` (a paused migration
    target, `restore --paused`) stops only the vCPUs. The VM process follows it
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
  (measured: 0 ms drift after 20 s). `resume` still checks it in the
  background, at most one check per VM at a time.
- **Paused migration.** A paused VM migrates and stays paused on the
  target, which pulls all its pages from the source. Resuming it there
  waits (up to 30 s) for that pull, so it never runs split across hosts.

#### Checkpoint format (versions 2 and 3)

A checkpoint is a directory that is written in full or not at all. The
destination's directory may belong to an unprivileged user while flexvm
runs as root, so nothing follows a path that user can change:

- **Staging.** The destination's directory is opened and pinned by fd. Files
  are created with `O_EXCL|O_NOFOLLOW` inside a root-only (0700)
  `.flexvm-staging-<pid>-<n>/ck` directory in it, also pinned by fd.
  Firecracker writes the VM state into the VM's own run directory, from
  where it is copied in.
- **Ownership.** Files are fchowned to the destination directory's owner.
- **Publish.** Everything is fsynced, then renamed fd to fd into place with
  `RENAME_NOREPLACE` (checkpoints are never overwritten or modified), and
  the destination directory is fsynced.
- **Durability failure.** If that last fsync fails, the checkpoint is
  revoked before the VM resumes: its manifest durably removed, then the rest
  of the directory. If that fails too, the VM stays paused and is marked
  failed.
- **Restore.** Every file is opened with `O_NOFOLLOW` and must be a regular
  file.
- **Leftovers.** A later checkpoint into the same directory clears staging
  that a dead VM process left behind.

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
check it for zeroes (plus a template compare where the template has data). Up to 12
threads take 1 MiB units of PRESENT pages in turn. A thread copies its unit
out of Firecracker with `process_vm_readv`, compares each page with the
template (only where the template has data) and computes its CRC32C and
whether it is all zero in the same read (SSE4.2, three interleaved streams).
It then reserves the unit's place at the end of `pages` and writes its DATA
pages there with `pwritev` and `O_DIRECT`, straight from its buffer, so the
page cache is never involved. Units land in the order they finish, which the
page map records, so no thread waits for another. `pages` is created in the
staging directory and preallocated (`fallocate`) for every PRESENT page
before the VM pauses, which is what lets ext4 run the direct writes in
parallel; it is trimmed to what was written.

An incremental checkpoint (format 3) adds `parent` to the manifest: the
parent's path (`../NAME` when they share a directory, else absolute) and id
(its manifest's checksum line). Its page map lists only pages that changed
since the parent's pause, with a third kind, TEMPLATE (the template's page,
a run only). A restore follows the chain (at most 64 deep), checks each
link and that it names the template and size its child does, refuses a
parent that is missing or whose id changed, and flattens the maps: each page
is read from the newest checkpoint that has it. Deleting or rewriting a
parent breaks its children.

#### Copy-on-write and incremental checkpoints

A checkpoint of a VM that runs on (`--keep-running`) pauses it only to save
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
  (`scripts/faults.py ckpt_packet_hold`).
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
  range (ranges closer than 64 pages merged: a call costs about as much as
  walking that many populated pages, ~19 µs here); only when the calls
  would cost more than walking every populated page of the region is the
  whole region protected at once. A guest that rewrote 600 scattered pages
  of 1 GiB written: pause 25–35 ms, protect 11–17 ms (was 49–84 and 34–64
  ms, when more than 256 ranges meant protecting the whole region).
- **The pause.** Pause through the API, save the state (as for a
  migration), take the dirty pages, re-protect them, arm copy-on-write for
  the pages to save, resume: 17–30 ms here at any size (was 125 ms at 256 MiB
  and 1.5–1.9 s at 4 GiB).
- **The copy.** The parallel writer reads each unsaved page out of
  Firecracker and writes it as before. A write fault on an unsaved page
  copies its block into memory (a "rescue": 120–250 µs here, a heavily
  loaded host) before unprotecting it; writers take the rescued copy. Past
  256 MiB of rescued copies a fault waits for the writers to reach its page
  instead. Writers never unprotect anything, so tracking continues.
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
  - **Free page reports are held.** Before the resume the VM process sends
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
`started_unmark`), checkpoints (`ckpt_memhash`, `ckpt_fail_protect`,
`ckpt_no_hold`, `ckpt_abort`, `ckpt_slow`, `ckpt_fail_write`,
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

- **Count.** `flexvm standby [--template T] N` keeps N; each claimed one starts
  its replacement, none start while the host is under its reserve, and the
  memory controller stops them all when the host goes under it.
- **Generations.** `flexvm template` publishes each build as an immutable
  `templates/.gen/<content id>/` and points `templates/NAME` at it with one
  atomic symlink swap. It never deletes a generation: VMs, migrations,
  standby VMs and checkpoints refer to them by content id. Standby VMs of an
  older generation exit; running VMs keep theirs. An incoming migration uses
  the generation with the source's content id if the host has it.
- **Settling.** The first run after a restore is slow (Firecracker's first
  resume, the guest catching up and handling the new VMGenID: ~10 ms of extra
  `NET` latency here). Each standby VM therefore runs once in the background,
  as long as the reseed below takes plus 50 ms, then is paused. Firecracker
  calls in a load have deadlines, and shutdown kills a load in progress.
- **RNG.** Firecracker gives every snapshot load a new VMGenID; on it, the
  guest kernel reseeds its RNG and then logs `random: crng reseeded due to
  virtual machine fork` (add_vmfork_randomness). The agent's `FORKS` counts
  those lines in `/dev/kmsg`, and a standby VM is only stocked once the count
  has gone up, so no two handed-out VMs of a template share RNG state; until
  then only the idle agent runs. That is what is provable here: this kernel's
  vmgenid sends no uevent, and `/dev/sysgenid` is not ordered against the
  reseed. With an agent that has no `FORKS`, a standby VM is only checked to
  answer (logged once). VMs restored on the fallback path or migrated reseed
  after resume, as before.
- **Clock.** The guests use the TSC clocksource, so Firecracker's
  `clock_realtime` (which adjusts kvmclock) has no effect: a VM's wall clock
  starts at the template's snapshot time, whether standby or not (minutes to
  days behind). The TSC keeps running while a VM is paused, so a pause adds no
  further error. The agent's `START <ip> <unix time> [dns]` (sent instead of
  `NET`) sets the address and steps `CLOCK_REALTIME` to the host's time, and
  answers only then. A standby VM gets its clock stepped (`CLOCK`) while it
  settles, so `START` at take finds it right and skips `clock_settime`, which
  can take tens of ms in a 24-vCPU guest. A migration target, after resuming,
  and a source that resumes after an aborted migration send `CLOCK` in the
  background (up to three tries, until a round trip is under 5 ms), so the guest gets back
  the downtime too: measured within ±2 ms. If a clock request fails it may
  still be on its way into the guest, so the next migration first waits for
  the agent to answer a ping (it serves requests in order) rather than let it
  land, stale, after the snapshot. Agents that predate `START` get `NET` and
  keep the stale clock.
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
  `NET <ip>`, which the guest agent applies with one rtnetlink message.
- Taps are created with each VM's Firecracker (ahead of time for standby VMs). The
  host route and a permanent neighbour entry are set with rtnetlink while the
  snapshot loads, so networking adds nothing to start time.
- udev with `MACAddressPolicy=persistent` can replace a new tap's MAC after
  flexvm set it to the gateway MAC, which leaves the guest's pinned
  gateway entry pointing nowhere. The VM process puts the MAC back (one
  `RTM_SETLINK`) whenever it hands a tap to a VM. To stop udev touching the
  taps at all, install a link file:

  ```ini
  # /etc/systemd/network/10-flexvm-taps.link
  [Match]
  OriginalName=fv*

  [Link]
  MACAddressPolicy=none
  ```
- Addresses come from the host's `--vm-ips` range, which is authoritative:
  **every host's range must be disjoint** from the others', and only an
  address's home host hands it out, so two hosts can never pick the same
  address. An address whose VM migrated to another host stays reserved
  ("lent", in `STATE/addrs/IP`) until that VM is killed wherever it is (its
  host tells the peers), or it migrates back and has all its memory there again
  (released; an arrival that dies before leaves the loan in place). If that message is lost, the
  address stays taken; removing `lent` from that file frees it. Leaks, never
  collisions. A restore elsewhere that keeps the address borrows it the same
  way (op `lend`). Every address carries a generation that orders the VMs
  that had it; messages about older ones are ignored, and the route a peer
  announced for the newest one is put back when a claim here goes without
  its VM running (see process-per-vm.md).
- Reachability:
  - **Peers** get a route pushed to them: `<vm-ip>/32 via <host underlay ip>`.
    Routes via an address local to the host's network namespace (including
    loopback) are skipped, so test hosts sharing a machine keep each other's
    tap routes; the first skip is logged.
  - **The LAN** (`--announce-dev eth0`): the host answers ARP for its VMs
    (proxy ARP) and sends a gratuitous ARP whenever a VM arrives. Other
    machines on the LAN therefore follow a migrated VM without any
    configuration. Give VMs addresses from the LAN's subnet and they can use
    the LAN's normal gateway for internet access.
- On migration, the target routes the address to its new tap at the commit,
  right before the VM resumes (its neighbour entry goes on the tap while it
  prepares): an arrival that fails or dies before leaves this host's route
  to the address, say back to its source, as it was. A dead arrival's
  record (`STATE/migs/ID`) names the address, and once it reads as aborted
  the route a peer announced for it is put back, in case it went missing. The guest keeps its address and TCP state, so connections
  continue, and packets that arrive during the downtime are held, not lost
  (`hold.rs`):
  - Just before pausing the VM, the source routes its address to a TUN
    device of its own (`<prefix><pid>h`; the one route this adds). A thread queues
    what arrives there, up to 4 MiB per VM, beyond that dropping and counting.
  - Once the target answers (the VM runs there), the source opens a stream
    on the migration connection and, once the target accepts it, sends the
    queue (length, sequence number, packet), then whatever reached the TUN
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
    held packets stay first and in order (#78). The target takes one stream per migration, on that
    connection, for that VM instance only, and stops it if the VM is killed
    or moves on. Nothing is resent: a stream that breaks off, or a source
    whose answer was lost, loses the rest (counted). Sequence numbers count
    gaps and drop duplicates.
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
takes 3–10 ms on a busy host). Without the patch, Firecracker rejects the
path and flexvm loads the whole snapshot during the pause.

`firecracker/0003-hold-free-page-reporting.patch`: `PATCH
/balloon/reporting/hold` and `PATCH /balloon/reporting/release`. While held,
the balloon leaves free page reports in their virtqueue (it consumes the
queue notification but pops nothing); a release processes whatever is
queued. Not saved in snapshots: a restored balloon is not held, and reports
queued at the snapshot are processed at its first resume, which kicks
every queue.

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
| Post-copy faults, 500 MiB written then read back right after the migration (host load ~15; 4 interleaved rounds of 8) | REMOTE fault p50 **1.0–1.3 ms** (was 4.2–5.2 ms, fetched on the event thread), p99 2.6–4.2 ms (was 12.6–16.8); template/zero faults p50 41–57 µs (was 1.3–1.6 ms, queued behind fetches); all faults blocked 0.77–0.98 s in all (was 1.33–1.6). The read itself barely changes here: most of it is KVM mapping each page again under nested virtualization |
| Idle VM host RSS | 13–35 MiB |
| pause / resume (VM side) | **0.6 / 0.7 ms** (2 vCPU), 1.5 ms resume (24 vCPU) |
| checkpoint `--keep-running`, 256 / 1024 / 4096 MiB written in the guest: VM paused | **20 / 18 / 24–31 ms** (was 125 / 406–428 / 1456–1923 ms); write protection armed beforehand while it runs (first checkpoint only): 20 / 95–125 / 270–380 ms; whole checkpoint 220–250 / 450–620 / 1900–2200 ms |
| ... with a guest rewriting 2 × 256 MiB during the copy | pause 17–56 ms; 650–2700 write faults, 340–1970 of them saving 20–120 MiB first (120–250 µs each); writer iterations > 100 µs: 4–9k (idle 0.1–1k), worst single stall 35–50 ms at 1 GiB (one 100–150 ms stall before 2 MiB protect chunks); free page reports are held during the copy (they cost 0.35–3.6 s stalls before) |
| incremental checkpoint of a 4 GiB VM (small writer running) | **paused 29–50 ms, 92–112 ms in all, 35 MiB written** (full: 4238 MiB, 1.5–1.9 s) |
| checkpoint `--stop`, by memory touched: 256 / 1024 MiB written in the guest | write_pages 113–249 / 483–521 ms (was 435–480 / 2019–2892 ms); paused 286–430 / 760–816 ms (was 653–703 / 2335–3255), including Firecracker's exit; disk: 4–5 GB/s O_DIRECT, 1 GB/s buffered |
| restore → guest agent answering | **33 / 27 / 67 ms** (snapshot load 28 / 24 / 63 ms); whole checkpoint paged in after 39 / 153 / 509 ms |
| suspend (checkpoint + free) / resume of a suspended VM to ready | 127 / 448 / 2012 ms; 27 / 28 / 36 ms |
| suspended VM host RSS | 0 (Firecracker gone) |

Lifecycle numbers are from `flexvm bench --lifecycle` with the 2-vCPU template,
5 trials per size, restoring on the second host on the same machine
(`bench/*-lifecycle.json`). The guest clock step after a restore adds another
35–100 ms after ready.

### Resumable exec protocol

Legacy `EXEC <len>`, `SPAWN <len>`, `PING` and `NET` retain their wire format.
Sessions use `SESSION <id> <len>\n` followed by exactly `len` command bytes,
`ATTACH <id> <offset>\n`, or `CLOSE <id>\n`. The client chooses a random ID;
retrying SESSION with the same ID and command attaches to the existing process
from offset zero. Reusing an ID for another command fails. IDs contain up to
64 ASCII letters, digits, underscores or hyphens; commands are at most 1 MiB.

Frames retain `[kind u8][payload length u32 LE][payload]`. SESSION and ATTACH
first return kind 4 with the session ID. A session has at most one attachment
(connection streaming its output): SESSION or ATTACH replaces it, and the guest
shuts the previous connection down, so its stream just ends. Session stdout/stderr (kinds 1/2)
prefix their bytes with an absolute `u64 LE` offset in the combined output
stream. Kind 3 contains the final `u64 LE` offset and `i32 LE` exit code.
Kind 5 contains the earliest retained `u64 LE` offset and reports output loss;
clients must not silently skip it. Kind 4 also carries `waiting` heartbeats,
`error: ...` failures, or `closed` for CLOSE. Socket writes happen outside the
output ring mutex. Reading an exit does not discard it: the CLI sends CLOSE
after receiving it, and the guest retains the ID as a tombstone until expiry
so a delayed creation retry cannot execute the command again.

At most 64 sessions are live (running, or finished and not yet closed); another
SESSION fails with `error: too many sessions: ...`. A finished session whose
client has been gone for a minute is closed by the guest (checked every minute,
and whenever the limit is reached), its output freed. Closed sessions leave
tombstones: small records outside that limit that expire five minutes after the
close, and beyond 4096 the oldest one (if at least 30 s old) is dropped. Each
live session's output ring keeps 128 KiB and grows towards 4 MiB from a shared
pool, so all rings together hold at most 64 MiB; when the pool is spent, rings
stop growing, and a detached client may then see kind 5 sooner.

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

The control socket's exec request adds `session`, `action` (`start`, `attach`, or
`close`), and `offset`; start also supplies `cmd`. Start/attach return the usual
JSON success reply followed by session frames; close returns a JSON reply.
