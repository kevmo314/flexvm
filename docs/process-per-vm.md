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

1. takes its name (an exclusive `flock` on `RUN/vms/NAME.lock`, held for
   life, its pid and start time written in it),
2. claims an address and generation (under the host lock, below),
3. restores the template snapshot into a Firecracker it spawns itself
   (`PR_SET_PDEATHSIG`, so Firecracker never outlives the pager), or takes
   over a standby process (below),
4. writes its registry entry `RUN/vms/NAME.json` and serves its control
   socket `RUN/vms/NAME.sock`,
5. waits for signals and control requests until the VM is gone.

Exit status: 0 when the VM was suspended, migrated away or killed on request;
1 when it failed to start; 3 when it died under the process (its Firecracker
exited, watched through a pidfd, or its memory was lost): cleaned up as a
kill, with why (Firecracker's exit status and the end of its log, the
guest's console) in `RUN/vms/NAME.failed`, which `ls` shows as `failed`
until `flexvm kill NAME`.

Ownership is held in guards that give back exactly what they took: the name
lock (`NameLock`), the address claim (`AddrClaim`: dropped, it releases the
address; a suspended VM keeps it) and an arrival's migration record
(`MigRecord`: dropped before it commits, the record goes, which reads as
aborted). The process ends one way only, `Proc::finish`, holding the
operation lock: it kills the VM and waits for its Firecracker, settles the
address by how the VM left (`End::Gone` withdraws it, `Suspended` keeps it,
`Moved` releases it, `NotStarted` releases it or, for a generation made for
this VM, withdraws it), deletes a consumed checkpoint, gives up the name, and
tells a waiting client and a standby claimer before it exits. With `-- CMD`, the VM runs
CMD in the guest, streams its output, and the process exits with CMD's status
(the VM is destroyed afterwards).

### Signals

| signal | effect |
|---|---|
| SIGTERM | suspend: checkpoint to `STATE/suspended/NAME`, free everything, exit 0. `flexvm resume NAME` restores it in a new process |
| SIGTSTP | pause the vCPUs (the process keeps running and serving pages; Ctrl-Z works) |
| SIGCONT | resume the vCPUs of a VM paused by SIGTSTP (ignored otherwise: the kernel sends it after any SIGSTOP, systemd after SIGTERM) |
| SIGINT | destroy the VM, withdraw its address, exit 0 (Ctrl-C works) |
| SIGSTOP | cannot be caught: freezes the pager, so the guest stalls. Unsupported |

They (and SIGHUP, ignored: a closed terminal leaves the VM running) are
blocked in every thread and taken by one thread with `sigwait`, so SIGTSTP
never stops the process. Every operation on the VM (starting it, signal,
control request, controller resize, clock step, deleting a consumed
checkpoint) holds the VM's operation mutex. Requests give up after 30 s;
what must not be refused (SIGINT, SIGTERM, a dead VM, the end of a
migration) waits for it, after cancelling a checkpoint in progress.

`kill -KILL` on a migration source is the operator's way to give up its
copy (the target loses the pages it has not pulled); `flexvm kill` refuses.

## On-disk state

Two directories, both overridable (`--state`/`FLEXVM_STATE`, `--run`/`FLEXVM_RUN`):

```
STATE (default /var/lib/flexvm, on disk)
  host.json              host config: listen, peers, vm_ips, underlay, announce_dev, dns, reserve_mib, prefix
  lock                   the host lock (flock), held for short critical sections only
  addrs/IP               per address: newest generation seen, withdrawn?, lent generation, holder name and
                         generation, the route a peer announced for the newest generation
  addrs/.gens            generation high-water mark, reserved 1024 at a time, with the boot id
  suspended/NAME/        a suspended VM's checkpoint, GEN (its address's generation) published with it,
                         + STARTED, DISCARDED, QUARANTINE markers
  standby/TEMPLATE       how many standby VMs to keep for a template
  migs/ID                incoming migration records (fencing), JSON, fsynced
RUN (default /run/flexvm, tmpfs)
  vms/NAME.{lock,json,sock,log}   registry entry, liveness lock, control socket, log of -d/standby VMs
  standby/T/KEY.PID.sock a standby VM of template T, generation KEY (PID.lock while it lives)
  standby/.loadset-ID    pages loads of template ID touch, learned by standby VMs, for migrations to preload
  faults.json            armed test faults (FLEXVM_FAULTS=1 only)
  w/PID/                 a VM process's work directory: `owner` (pid, start time), and per
                         Firecracker a directory with `fc` (its pid and start time)
```

**Liveness** is the name lock: a registry entry whose `.lock` can be locked
belongs to a dead process and is ignored; an entry is believed only for the
process the lock names (pid and start time). Unlinking a lock file is done
holding it, and a taker re-checks after locking that the path still names
the inode it locked. Signals to a VM (`kill`, `resume`, a foreground `run`
forwarding them, eviction of standby VMs) go through a pidfd opened for the
process the registry or lock names, checked after opening.

**Death evidence.** A dead process is taken for gone, its name or address
reusable and its migration settled, only once the Firecrackers it started
have exited: `host::reap` reads them from its work directory (whose `owner`
must be that process), SIGKILLs each through a pidfd and waits for it.
Firecracker also gets `PR_SET_PDEATHSIG` (checked, and the parent checked
alive after it), so they die anyway; reaping makes the order certain.

**The host lock** is a flock taken by one thread of a process at a time and
reentrant within a thread, so a guard dropped under it (an address claim)
never deadlocks.

**Addresses and generations** keep the semantics of the generations work
(#60): only an address's home host (whose `vm_ips` holds it) hands it out,
each time with a new generation from a durable high-water mark; a VM keeps its
generation through migrations and suspends; route announcements and
withdrawals carry it; each host keeps the newest (generation, withdrawn) seen
per address and ignores older messages and announcements of withdrawn
generations; a withdrawal frees a loan of its generation or older. An address
is *taken* if its record names a holder that is alive (locked name, or its
dead process's Firecrackers not yet gone) or suspended here, or it is lent.
All of this is decided under the host lock, in one critical section with the
claim. Records with a new generation, a loan or a withdrawal are fsynced
before acting; a live holder change is not (a crash loses the VM too, and the
high-water mark already orders generations). A record that cannot be read or
parsed is an error, never a free address.

- **Borrowing.** A restore keeping another host's address (its checkpoint's,
  or `--ip`) asks the peers to `lend` it: the home host checks it is free
  (no VM there, not lent), lends it out durably with a new generation and
  answers with it; the restore claims the address with that generation, and
  withdraws it (freeing the loan) if the VM does not start. `run --ip` takes
  only this host's addresses.
- **Routes.** A peer's announcement leaves the route of an address a VM here
  holds with that generation or a newer one, or a migration's paused source,
  alone; a newer one replaces it. The route a peer announced for the newest
  generation is recorded, and put back when a claim or hold here that kept
  the route goes without its VM running here: a superseded migration source,
  an arrival that does not commit.
- **Right before a VM runs** (a restore, a suspended resume, a `--paused`
  restore's or SIGTSTP'd VM's SIGCONT, an arrival's commit) its generation is
  checked again under the host lock, held until the vCPUs run.

**Admission** (`reserve_mib`): growth and incoming migrations are admitted
under the host lock against MemAvailable minus the reserve and the grants of
the last 10 s (`RUN/grants`); standby refills stop under it.

## Migration, runner to runner

Over one TCP connection, as before (prepare, header + vmstate + preload,
answer, held packets). What changed is who is at each end:

1. The source VM process gets `migrate {to}` on its control socket and
   connects to `to`, the target's peer listener, sending `migrate_in`.
2. The listener spawns `flexvm run --incoming` with the connection as fd 3.
   That process takes the name lock, creates `STATE/migs/ID` (`pending`
   with its pid, start time and boot id; refused if it exists: an id is seen
   once), claims the address with the source's generation, spawns and
   prepares Firecracker, answers.
3. The source pauses, sends the state; the target loads it, runs every
   check that can abort, then under the host lock turns `pending` into
   `committed` (refused if it was fenced), and resumes before letting go of
   the lock.
4. Pages: the target's pager connects to the *source's* listener with
   `pages {name, mig}`; the listener passes the socket (SCM_RIGHTS) to the
   source VM process, which serves it if it is the source of that migration.
5. Release: the source polls `migration {mig}` on the target's listener.
   The listener answers from `STATE/migs/ID`: `pending`, `committed`,
   `released` (a live target wrote it once every page arrived, under the VM's
   operation lock so it never races the VM's end; a home host takes its loan back
   only after; retrying
   until it is recorded; or the VM was destroyed on purpose there), or
   `aborted` (no record). A record whose process is dead is removed once its
   Firecrackers are reaped, committed or not: the VM is not on the target,
   and the source's paused copy is the only one left (#105). A record that
   cannot be read answers nothing. The source resumes only on `aborted`, and
   then under the host lock and only if its generation is still current
   (after a commit, from the pause point, announcing the address again); it
   exits only on `released`, telling the target it is `done` with the id
   (the record goes then: retention follows the protocol, not time), and
   stays paused, serving pages, otherwise.

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
| `migration` | report and settle a migration record; `done`: forget a released one |
| `route` | a peer's announcement/withdrawal: judge its generation, set or remove the route |
| `lend` | lend an address of this host's range to a restoring peer, with a new generation |

Only connections from the configured peers' addresses are served. Request
lines are read with a 10 s deadline and capped at 64 KiB; at most 512
requests at once. Restarting or not running it loses nothing but the ability
to receive.

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
first. The count is explicit, and refills stop under the reserve; one refill
of a template runs at a time (`.refill` lock), and waits until the standby
VMs it starts are ready, so concurrent claims never overfill. A claim sent
but not answered (the standby died, or hung up) is an uncertain outcome: the
guest may have run, so `run` reports it (with the standby's socket, and
whether the registry shows the VM) and starts nothing else.

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
`migration`, `route`, `lend` (5). 11 ops, from 23 (the daemon's
`lend_ip` included); user-facing ones: 3.

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

## Invariants

From review pass 6 on #85 and the Codex review of #45/#60; each says
where it is kept and what tests it.

1. **A committed migration id is never forgotten** until its source says it
   is done with it. Records live in `STATE/migs/ID` (disk), typed
   (`pending`, `committed`, `released`), changed only under the host lock
   and fsynced: `committed` is durable before the VM resumes; `released`
   comes only from a live target holding every page (or one that destroyed
   the VM on purpose), so a source never lets go of the only copy; reads
   fail closed. Unit test `host::migrations_are_fenced`; faults `basic`,
   `lost_ack`, `unknown`, `target_killed`, `incoming_killed`.
2. **The old Firecracker is dead before an id is fenced or a name or
   address freed.** Firecracker is spawned from the main thread with
   `PR_SET_PDEATHSIG=SIGKILL` (failure fails the spawn, as does a parent
   gone meanwhile), and recorded in the work directory; a dead process's
   Firecrackers are reaped (killed through pidfds, waited for) before its
   name, address or migration record is settled; `Vm::kill` waits for
   Firecracker to exit. The cgroup move is joined before Firecracker is
   killed, so it never acts on a reused pid or recreates a removed cgroup.
   Unit test `host::a_dead_holders_firecrackers_die_before_its_name_or_address_is_free`;
   faults `source_killed`, `target_killed`, `incoming_killed`, `start_killed`.
3. **Instance identity.** One process is one VM instance, named by pid and
   start time in its name lock and registry entry; an entry is believed only
   for the process holding the name, and signals go through pidfds checked
   against it. Route, hold and announce decisions are made in the process
   that owns the VM, or by the host lock plus the address record's holder
   and generation.
4. **No fire-and-forget work outlives the process.** Withdrawals are sent
   (and joined) before exit; a migration source polls its target until
   released and only then exits; the reroute retry gets a last attempt
   before exit; a resumed checkpoint is deleted at exit if its pull did not
   finish. Announcements are only for a VM that runs, so they may die with it.
5. **Signals.** Startup holds the operation lock, so signals wait for the VM
   to be up. SIGTERM on a migration source is a no-op (it ends once the
   target has its memory); on a target still pulling, the suspend waits for
   the pull (`save` drains, giving up if the VM is being killed). SIGCONT
   resumes only a VM paused by SIGTSTP (or held by `restore --paused`), and
   is ignored once a suspend or kill began: the kernel sends it after any
   SIGSTOP, systemd right after SIGTERM. A destroy refused because the VM is
   migrating away (SIGINT, or `run -- CMD` ending) never ends the process.
6. **Suspend markers and quarantine.** `STARTED` means consumed: `resume`
   deletes such a checkpoint and `ls` does not show it; deleting it holds
   the operation lock, and a suspend deletes it first. Quarantine is a file
   (`QUARANTINE`, with the boot id). Suspended VMs keep name and address with
   no pid, and `ls` lists them.
7. **Address state** is read fresh and changed per change under the host
   lock, durable where it orders anything. The listener's skip-local check
   reads the holder under that lock.
8. **The `migrate_in` hand-off loses no bytes**: the listener reads the first
   line one byte at a time, so nothing is buffered when it passes the
   socket on. Page connections are passed to the VM named, which serves them
   only as the source of the migration id they name.
9. **Shared resources have one owner.** Socket roots, work directories, taps
   (`<prefix><pid>t<n>`) and cgroups (`idle-<pid>-<n>`) are named after the
   owning process and only swept once it is gone; each process has its own
   hold TUN (not persistent: it goes with the process); `unroute` happens
   under the host lock and only for an address the process still holds;
   checkpoint staging is cleared by owner pid; suspended directories are
   never swept.
10. **Load ordering.** Each process opens its own template (its fd paths are
   its own); `Pager::set_pid` runs before any load; a standby claim whose
   resume may have reached Firecracker is never retried (`retry: false`).
11. **Generations** (#60, #94): aborting a migration never resumes a source
   whose address has a newer generation (checked under the host lock, held
   through the route restore and the resume; the copy is destroyed instead,
   and the newer VM's announced route replaces the hold); an arrival must
   carry a generation (0 is refused) no older than the one recorded; a
   suspend writes its generation into the checkpoint (`GEN`) before it is
   published, and a suspended VM without one is quarantined, never given a
   new generation; every VM start rechecks its generation under the host
   lock until it runs. Faults `abort_superseded`, `gen_zero`, `forged_peer`,
   `suspend_gen`, `late_withdrawal`, `checkpoint_restore`, `restore_ip_peer`.
12. **`scripts/faults.py`** is ported to VM processes and listeners (see
   Test plan).

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
  becomes `target_killed` (SIGKILL the target VM process after commit,
  mid-pull: the source is told `aborted` once its Firecracker is dead, and
  runs its copy again; a target that destroys the VM on purpose releases
  its source),
  `checkpoint_crash`/`cow_crash` (SIGKILL the VM process mid-write: no
  checkpoint appears, staging is cleared by the next one), `hot_budget`
  becomes `standby` (count, refill, claim fallback). New: `abort_superseded`,
  `gen_zero`, `suspend_gen`, `signals`, `kill_source`, `forged_peer`,
  `restore_ip_peer`, `late_withdrawal`, and processes SIGKILLed between
  steps at test stalls (`incoming_killed`, `start_killed`, `claim_killed`).
  Dropped:
  `target_restart_symlink`, `shared_run_dir`, `state_dir_lock` (they tested a
  daemon's run-dir locking and orphan killing on restart; there is no daemon
  to restart, and Firecracker dies with its VM process).
- `scripts/e2e.py` (CI): the commands, then a selection of faults.py
  scenarios against its two hosts (`--no-listeners`).
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
