# One process per VM

Issue #85. flexvm has no central daemon. `flexvm run NAME` starts a process
that *is* the VM: it owns the Firecracker child, the uffd pager, the tap and
route, packet holds, guest sessions, checkpoints and its side of every
migration. The process exits when the VM is gone. Everything host-wide lives in
small flock-guarded files.

## Process model

```
flexvm run web            # foreground: the process is the VM
flexvm run web -d         # same, detached; prints {"name","ip","pid",...} once ready
```

A VM process:

1. takes its name (an exclusive `flock` on `RUN/vms/NAME.lock`, held for life),
2. claims an address and generation (under the host lock, below),
3. restores the template snapshot into a Firecracker it spawns itself
   (`PR_SET_PDEATHSIG`, so Firecracker never outlives the pager), or takes
   over a standby process (below),
4. writes its registry entry `RUN/vms/NAME.json` and serves its control
   socket `RUN/vms/NAME.sock`,
5. waits for signals and control requests until the VM is gone.

Exit status: 0 when the VM was suspended, migrated away or killed on request;
1 when it failed (memory lost, Firecracker died). With `-- CMD`, the VM runs
CMD in the guest, streams its output, and the process exits with CMD's status
(the VM is destroyed afterwards).

### Signals

| signal | effect |
|---|---|
| SIGTERM | suspend: checkpoint to `STATE/suspended/NAME`, free everything, exit 0. `flexvm resume NAME` restores it in a new process |
| SIGTSTP | pause the vCPUs (the process keeps running and serving pages; Ctrl-Z works) |
| SIGCONT | resume the vCPUs |
| SIGINT | destroy the VM, withdraw its address, exit 0 (Ctrl-C works) |
| SIGSTOP | cannot be caught: freezes the pager, so the guest stalls. Unsupported |

All four are blocked in every thread and taken by one thread with `sigwait`,
so SIGTSTP never stops the process. Every operation on the VM (signal,
control request, controller resize, clock step) holds the VM's operation
mutex, replacing the daemon's per-name reservation map.

## On-disk state

Two directories, both overridable (`--state`/`FLEXVM_STATE`, `--run`/`FLEXVM_RUN`):

```
STATE (default /var/lib/flexvm, on disk)
  host.json              host config: listen, peers, vm_ips, underlay, announce_dev, dns, reserve_mib, prefix
  lock                   the host lock (flock), held for short critical sections only
  addrs/IP               per address: newest generation seen, withdrawn?, lent generation, holder name
  addrs/next             generation high-water mark, reserved 1024 at a time
  suspended/NAME/        a suspended VM's checkpoint (+ GEN, STARTED, DISCARDED markers)
  standby/TEMPLATE       how many standby VMs to keep for a template
RUN (default /run/flexvm, tmpfs)
  vms/NAME.{lock,json,sock,log}   registry entry, liveness lock, control socket, log of -d/standby VMs
  standby/KEY/PID.sock   standby VMs of a template generation
  migs/ID                incoming migration records (fencing)
  faults.json            armed test faults (FLEXVM_FAULTS=1 only)
  w/PID/                 a VM process's Firecracker directory
```

**Liveness** is the name lock: a registry entry whose `.lock` can be locked
belongs to a dead process and is ignored (and removed by whoever notices).
Unlinking a lock file is done holding it, and a taker re-checks after locking
that the path still names the inode it locked.

**Addresses and generations** keep the semantics of the generations work
(#60): only an address's home host (whose `vm_ips` holds it) hands it out,
each time with a new generation from a durable high-water mark; a VM keeps its
generation through migrations and suspends; route announcements and
withdrawals carry it; each host keeps the newest (generation, withdrawn) seen
per address and ignores older messages and announcements of withdrawn
generations; a withdrawal frees a loan of its generation or older. An address
is *taken* if its record names a holder that is alive (locked name) or
suspended here, or it is lent. All of this is decided under the host lock, in
one critical section with the claim. Records with a new generation, a loan or
a withdrawal are fsynced before acting; a live holder change is not (a crash
loses the VM too, and the high-water mark already orders generations).

**Admission** (`reserve_mib`): an incoming migration is refused when
MemAvailable would drop under the reserve; standby refills stop under it.

## Migration, runner to runner

Over one TCP connection, as before (prepare, header + vmstate + preload,
answer, held packets). What changed is who is at each end:

1. The source VM process gets `migrate {to}` on its control socket and
   connects to `to`, the target's peer listener, sending `migrate_in`.
2. The listener spawns `flexvm run --incoming` with the connection as fd 3.
   That process takes the name lock, claims the address with the source's
   generation, creates `RUN/migs/ID` (`pending <pid> <start time>`, refused
   if it exists: an id is seen once), spawns and prepares Firecracker, answers.
3. The source pauses, sends the state; the target loads it, runs every
   check that can abort, then under the record's lock turns `pending` into
   `committed` (refused if it was fenced), and only then resumes.
4. Pages: the target's pager connects to the *source's* listener with
   `pages {name, mig}`; the listener passes the socket (SCM_RIGHTS) to the
   source VM process, which serves it if it is the source of that migration.
5. Release: the source polls `migration {mig}` on the target's listener.
   The listener answers from `RUN/migs/ID`: `pending`, `committed`,
   `released` (the target process wrote it once all pages arrived, or its VM
   is gone, or the process is dead), or `aborted`. An unknown id, or `pending`
   whose process is dead, is fenced: recorded `aborted` first, so it can
   never commit later. The source resumes only on `aborted`, exits on
   `released`, and stays paused (serving pages) otherwise.

So fencing no longer depends on a daemon restart killing orphans: a target
process that dies takes its Firecracker with it (pdeathsig), and its record
says so.

## Peer listener

`flexvm listen [ADDR]` is an optional helper, needed only to receive
migrations (and page requests for VMs migrating away). It is stateless and
socket-activatable (`LISTEN_FDS`, or binds `host.json`'s `listen`). Each
connection's first line (read unbuffered, so nothing after it is consumed) is
one of:

| op | |
|---|---|
| `migrate_in` | spawn `flexvm run --incoming` with the connection |
| `pages` | pass the connection to the VM process named, over its control socket |
| `migration` | report and fence a migration record |
| `route` | a peer's announcement/withdrawal: judge its generation, set or remove the route |

Restarting or not running it loses nothing but the ability to receive.

## Standby pool

`flexvm standby [--template T] N` records N in `STATE/standby/T` and starts
standby VMs until there are N: each is `flexvm run --standby`, a VM process
that restores the template, lets the guest reseed and settle, pauses, and
listens on `RUN/standby/KEY/PID.sock`. `flexvm run` claims one (`claim
{name, ip, cmd}` with its stdout/stderr passed over SCM_RIGHTS): the standby
takes the name and address, routes, resumes, sends `START`, and becomes that
VM. A claimed standby starts its replacement. A foreground `run` that claimed
one forwards its signals to it and exits with the status the VM process sends
back on the claim connection. Under memory pressure standby VMs are SIGINTed
first. The old hot pool's per-template budget, cost learning and back-off go
away: the count is explicit, and refills stop under the reserve.

## Memory controller and eviction

Each VM process resizes its own VM once a second exactly as before
(virtio-mem steps, starved flag). Pressure relief needs one decider per host:
every second each VM process tries `STATE/evict.lock` (non-blocking); the
holder, at most once per 5 s, reads the registry, picks the starved VM first,
else the biggest RSS, and sends it `migrate` with each peer in turn until one
accepts (`migrate_in` refuses when the target would go under its reserve).
This replaces the `info` op the daemon used to find room.

## API

### Wire ops, before (daemon TCP, 23) and after

| op | fate |
|---|---|
| run | process: `flexvm run` (standby: control `claim`) |
| ls | file: registry + `/proc` |
| info | file: `host.json` + registry |
| bench_info | gone: bench reads the host itself |
| kill | signal SIGINT (suspended: `flexvm kill` deletes the checkpoint) |
| pause | signal SIGTSTP |
| resume | signal SIGCONT; suspended: process `flexvm resume` |
| suspend | signal SIGTERM |
| restore | process: `flexvm restore` |
| logs | file: the VM process's stdout / `RUN/vms/NAME.log` |
| unlend | file: remove the loan from `STATE/addrs/IP` by hand |
| migration_status | control `debug` |
| memhash | control `debug` |
| ckhash | local `flexvm debug ckhash` (no VM involved) |
| fault | file: `flexvm debug fault` writes `RUN/faults.json` |
| release | gone: the source polls `migration` |
| exec | kept, control socket |
| checkpoint | kept, control socket |
| migrate | kept, control socket |
| migrate_in | kept, peer |
| pages | kept, peer (forwarded to the VM process with the fd) |
| migration | kept, peer |
| route | kept, peer |

After: control socket `exec`, `checkpoint`, `migrate`, `claim`, `pages`
(from the listener only), `debug` (6); peer `migrate_in`, `pages`,
`migration`, `route` (4). 10 ops, from 23; user-facing ones: 3.

### CLI, before (15 commands) and after (12)

```
flexvm template NAME ...                      (unchanged)
flexvm run NAME [--template T] [--ip IP] [-d] [-- CMD...]
flexvm resume NAME [-d]                       restore a suspended VM (a paused one gets SIGCONT)
flexvm restore DIR [--name N] [--ip IP|auto] [--paused] [-d]
flexvm ls
flexvm exec NAME CMD...
flexvm checkpoint NAME DIR [--stop] [--incremental]
flexvm migrate NAME ADDR
flexvm kill NAME                              destroy (live: SIGINT; suspended: discard)
flexvm standby [--template T] N
flexvm listen [ADDR] [--peer ADDR]... [--vm-ips R] [...]   writes host.json, serves peers
flexvm bench ...
```

Removed: `daemon`, `pause`, `suspend`, `logs`, `unlend`, `--host`.
Pause/suspend are `kill -TSTP` / `kill -TERM` on the pid (`flexvm ls` shows
it), or Ctrl-Z / Ctrl-C on a foreground VM. Test-only inspection is the
hidden `flexvm debug`.

### Exec across hosts

There is no remote control channel any more. An exec whose VM migrates away
ends with `vm NAME moved to HOST (session ID keeps running there)`, exit 255;
reconnection within a host (checkpoint pauses, vsock resets) still works.

## Test plan

- Unit: host state (name locks and stale entries, address claims, generations
  ordering and persistence, loans/withdrawals, migration record fencing).
- `scripts/faults.py` ported: hosts A and B are two state/run dir pairs on
  one machine, each with its own listener (ports 7130/7131). Kept: migration
  fencing (`lost_ack`, `unknown`, `refused`, `status`, `prepare_*`,
  `short_incoming`, `slow_preload`, `kill_prepared`, `prepared_retry`),
  `pages_*`, `route`, `quiet_source`, `resume_kill`, exec/guest call races,
  `guest_hang`, all checkpoint/COW/incremental/hold scenarios, suspend/resume
  and resume marker failures, `held_restore_frozen`, generations. Renamed or
  reshaped: `source_killed` (SIGKILL the source VM process), `target_restart`
  becomes `target_killed` (SIGKILL the target VM process after commit: the
  record says released/dead, the source exits, nothing runs twice),
  `checkpoint_crash`/`cow_crash` (SIGKILL the VM process mid-write: no
  checkpoint appears, staging is cleared by the next one), `hot_budget`
  becomes `standby` (count, refill, claim fallback). Dropped:
  `target_restart_symlink`, `shared_run_dir`, `state_dir_lock` (they tested a
  daemon's run-dir locking and orphan killing on restart; there is no daemon
  to restart, and Firecracker dies with its VM process).
- `scripts/nettest.sh` and `scripts/test.sh`: same checks, VM processes and
  listeners instead of daemons.
- Latency before/after: `run` (standby hit and cold), migration downtime,
  pause/resume, checkpoint keep-running/stop, suspend/resume.

## Phasing

1. Host state module (`host.rs`): dirs, lock, registry, addresses and
   generations, migration records, faults; unit tests.
2. VM process (`vmproc.rs`) from `daemon.rs`/`lifecycle.rs`: run, signals,
   control socket, checkpoint/suspend/resume/restore, controller.
3. Peer listener and migration runner to runner.
4. Standby pool (replaces `hot.rs`'s pool).
5. Eviction.
6. Delete `daemon.rs`, `lifecycle.rs`, the hot pool and dead API; rewrite the
   README around the commands; port scripts and bench.
