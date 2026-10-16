# One process per VM

flexvm has no central daemon. `flexvm run NAME` starts a process
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

A VM process started in the background (`-d`, an arrival the listener
spawns, a standby VM) is in a session of its own and, between fork and exec,
joins a cgroup of its own, `/sys/fs/cgroup/flexvm/vm-PID-START` (`util::spawn_self`;
named after the instance, so one that exists is refused, never joined),
so stopping its starter's cgroup (a systemd unit's restart with
`KillMode=control-group`, a oneshot unit's end, logind's `KillUserProcesses`)
does not reach it. Its Firecrackers move on to `flexvm/idle-PID-START-N`. Without
cgroup2 it stays where it was started, and says so in its log. A foreground
VM process stays in its caller's cgroup.

Exit status: with `-- CMD`, CMD's; else 0 when it migrated away or was
stopped by `checkpoint --stop`; 128 + the signal when one ended it (130:
SIGINT destroyed it, 143: SIGTERM suspended it); 125 when flexvm failed (it
could not start the VM, or gave it up); 124 when it died under the process
(its Firecracker exited, watched through a pidfd, or its memory was lost):
noticed at once whatever operation is in progress, which is interrupted
rather than waited for (`Vm::mark_dead`: guest calls fail without retrying,
waits on Firecracker give up, the pager stops, a checkpoint is cancelled;
a suspend that published meanwhile is revoked and ends as a death, not a kill),
then cleaned up as a
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
(the VM is destroyed afterwards). The main command waits for a paused or
checkpointing VM at every stage (Ctrl-Z during startup included; early
signals are replayed before it starts), where an interactive `exec` fails
fast. CMD goes along with a suspend: while one runs its stream waits (never
giving up, never ending the VM; the command ending the VM and a suspend
starting exclude each other through `suspending`), and once the VM is paused
the suspend holds its session, recording in the checkpoint (`CMD`) the
command, its guest session, how much of its output was written out and its
exit status if it had one; `flexvm resume` reattaches it from there (or
takes that status) and exits with its status.
Its control socket serves `exec`, `checkpoint` and `migrate`, plus `claim` (a
standby), `pages` (passed on by the listener) and `debug` (tests).

### Signals

| signal | effect |
|---|---|
| SIGTERM | suspend: checkpoint to `STATE/suspended/NAME`, free everything, exit 143. `flexvm resume NAME` restores it in a new process. An unclaimed standby VM has nothing to suspend: it is destroyed, exit 143 |
| SIGTSTP | pause the vCPUs (the process keeps running and serving pages; Ctrl-Z works) |
| SIGCONT | resume the vCPUs of a VM paused by SIGTSTP (ignored otherwise: the kernel sends it after any SIGSTOP, systemd after SIGTERM) |
| SIGINT | destroy the VM, withdraw its address, exit 130 (Ctrl-C works) |
| SIGQUIT | as SIGINT (Ctrl-\ destroys the VM rather than dumping core) |
| SIGUSR1 | stop a standby VM (`flexvm standby`, memory pressure), exit 0; a claimed VM ignores it, so a stop that lands after a claim started never destroys the VM the claim made |
| SIGSTOP | cannot be caught: freezes the pager, so the guest stalls. Unsupported |

They (and SIGHUP, ignored: a closed terminal leaves the VM running) are
blocked in every thread and taken by one thread with `sigwait`, so SIGTSTP
never stops the process. Every operation on the VM (starting it, signal,
control request, controller resize, clock step, deleting a consumed
checkpoint) holds the VM's operation mutex. Requests give up after 30 s;
what must not be refused (SIGINT, SIGTERM, a dead VM, the end of a
migration) waits for it, after cancelling a checkpoint in progress.
SIGTERM's suspend runs off the signal thread, so a SIGINT after it is still
taken. It is reserved before its thread starts: SIGTERMs while one runs are
taken into it, and none starts once a `run -- CMD` command ends the VM
(`suspend_overlap`). SIGINT wins: a suspend that published its checkpoint meanwhile
revokes it (discarded, address withdrawn) and the process exits destroyed,
and `flexvm kill` discards one that finished first (`suspend_killed`).

`kill -KILL` on a migration source is the operator's way to give up its
copy (the target loses the pages it has not pulled); `flexvm kill` refuses.
A source still waiting to learn whether its target resumed the VM (ack
lost, status unavailable) does end on SIGINT or SIGQUIT, but the target may
be running the VM, so nothing is withdrawn: the address stays lent (never
handed out on this host), the newest route a peer announced for it comes
back, and the outcome is owed in `STATE/owed/ID`. Garbage collection asks
the target until it says: `released`, the VM is the target's (told `done`;
the loan is taken back by its own withdrawal, as for any VM that moved);
`aborted`, no copy runs, so the generation is withdrawn then and the address
is free. Meanwhile the listener counts the killed source as still there, so
the target keeps the record it is asked about (`reconcile_kill`). The record
is written (retried a few times) before the process ends: if it cannot be
(a full disk), the kill is refused and the source goes on asking its target,
so a lent address always has a record of whom it is owed to.

A target lost for good (its host gone, never to answer) leaves the address
lent, refused to `run --ip` and automatic allocation alike. `flexvm reclaim
IP` says what it is lent with (the migrations owed for it) and what
reclaiming does; `flexvm reclaim IP --force` withdraws that generation here
and at every peer and forgets the owed records, so the address can be handed
out again. It is the operator's word that no host still runs the VM: one that
does would share the address with the next VM given it, so make sure first
(kill it there, or know its host is gone). It also takes back a loan left by
a source killed with SIGKILL, which records nothing.

## On-disk state

Two directories, both overridable (`--state`, `--run`):
each state directory is bound to one canonical run path on first open.
A different `--run` for the same state directory is refused, including after a reboot.

```
STATE (default /var/lib/flexvm, on disk)
  artifacts/             firecracker, vmlinux, base.squashfs, rootfs-HASH.ext4, rootfs.ext4 (a symlink to
                         the newest) and flexvm-init, as scripts/fetch.sh and build-*.sh install them
  templates/             built templates: NAME -> .gen/ID (see internals.md)
  images/                pulled container images: blobs/sha256/, rootfs/KEY.ext4 (see images.md)
  host.json              host config (`flexvm config`'s; listen is `flexvm listen`'s): listen, peers, vm_ips, underlay, announce_dev, dns, reserve_mib, evict_mib; unset ones are derived where used
  run.json               canonical run path, bound on first open under the state root's flock; fsynced
  lock                   the host lock (flock), held for short critical sections only
  .synced                the root's (dev, inode) once its directories were made durable (`Host::open`)
  addrs/IP               per address: newest generation seen, withdrawn?, lent generation, holder name, instance
                         (pid, start time) and generation, the route a peer announced for the newest generation
                         and the newest revision of it (where the VM is within the generation)
  addrs/.gens            generation high-water mark, reserved 1024 at a time, with the boot id
  addrs/.next            where the next automatic allocation starts looking (a hint, wrapping around)
  suspended/NAME/        a suspended VM's checkpoint, GEN (its address's generation) published with it,
                         + STARTED, DISCARDED, QUARANTINE markers; without a manifest, or STARTED or
                         DISCARDED, it is debris: never listed, removed by the name's next holder
  standby/TEMPLATE       how many standby VMs to keep for a template
  standby.stop.lock      held while pressure stops standby VMs (SIGUSR1)
  migs/ID                incoming migration records (fencing), JSON, fsynced
  owed/ID                migrations away whose source was killed before it knew the outcome: target, address, generation (`Host::settle_owed`)
  evict.lock             one eviction decider at a time (flock)
  evict.worker.lock      held by the thread running an eviction; arrivals by eviction are refused meanwhile
  evict.last             its mtime: when an eviction last started (5 s apart)
  staging/               where image layers unpack (`template --image`); its ancestry must be root-owned
RUN (default /run/flexvm, tmpfs)
  vms/NAME.{lock,json,sock,log}   registry entry, liveness lock, control socket, log of -d/standby VMs
  vms/NAME.{failed,moved}         why a VM died (until `flexvm kill`); where it migrated to (an hour)
  vms/.incoming-LPID-N-PEER.log   an arrival's log until it is accepted (as NAME.log) or refused; locked by the arrival
  state.json             canonical state path, claimed on first open by a hard link (one state wins a race)
  .gc, .gc.lock          when garbage was last swept periodically; one sweep at a time
  .logs.lock             logs are opened holding it shared, swept holding it exclusively
  holds/ID-MIB           memory admitted to a live process, flocked by it (`.ID` while being made)
  grants-BOOTID          recent grants not yet held, counted against the reserve
  evict.active           present while the host is under its eviction mark
  evict.backoff          refused VM and peer pairs and when to try them again
  standby/H/             template T's standby files, H the 16-hex hash of T's name (independent of T's length;
                         `flexvm standby` shows each one's `dir`)
  standby/H/.template    T, the template's name
  standby/H/PID.sock     a standby VM of template T (PID-START.lock while it lives)
  standby/H/PID-START.claim  locked by a standby VM while a claim of it is under way
  standby/H/PID-START.take   locked by a `run` while it tries that standby (others try another first)
  standby/H/.refill      one refill of T at a time (flock)
  standby/H/.failed      its mtime: T's last failed refill (none for a minute after)
  standby/H/standby.log  the standby VMs' output and refill errors
  standby/.pressure      its mtime: when pressure last stopped standby VMs (no refill for a minute)
  standby/.loadset-ID    pages loads of template ID touch, learned by standby VMs, for migrations to preload
                         (one per generation; swept once neither read nor written for a day)
  faults.json            armed test faults (FLEXVM_FAULTS=1 only)
  w/PID-START/           a VM process's work directory, named by its whole identity (a later
                         process with its pid never shares it): `owner` (pid, start time), and per
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
Whether a process is gone has one answer (`Ident::liveness`): alive, gone
on proof (another boot, no such pid, a zombie, another process with its pid),
or unknown (`/proc` or a record could not be read, say out of fds), which
counts as alive everywhere: names, address holders, migration records,
reaping and garbage collection never reclaim on it.
Firecracker also gets `PR_SET_PDEATHSIG` (checked, and the parent checked
alive after it), so they die anyway; reaping makes the order certain.

**Garbage collection** (`host::collect_garbage`, `gc::sweep`) runs from
every listener and VM process about every 30 s, a VM process's first as it
starts (whichever process finds `RUN/.gc` older than that sweeps, so a start
right after another sweep does not; one sweep at a time under
`RUN/.gc.lock`), so a host with no VM starting still sweeps.
What a process owns goes once that process is proven gone: taps
(`<prefix><pid hex>t<n>`, and a template build's `<prefix>x<pid hex>`),
by their alias, never their name: `flexvm PID START RUN`, set before the
tap is made persistent (`host::tap_alias`), so a sweep takes only tun
devices whose alias names its run directory and an owner proven gone
(another host's taps, whatever their names read as under this prefix, and
taps with no such alias, an earlier version's say, are never touched); a
process with a reused pid removes its dead namesake's as it starts, as their
names would be its own (`host::clear_taps`), Firecrackers' cgroups (`idle-<pid>-<start>-<n>`, by the process's identity), work directories, names, a standby
VM's socket (its `PID-START.lock` free) and a lock it died before renaming in place (`.PID-START.lock`), an arrival's log (no lock on it, 5 s
old). A VM process's own cgroup (`vm-PID-START`) goes once empty, never
killed (`rmdir` refuses a populated cgroup). An earlier version's
Firecracker cgroups (`idle-PID-N`, no start time) are left alone. The logs of a name with no
VM, suspended VM, `failed` or `moved` record go once unwritten for an hour,
decided and removed holding `RUN/.logs.lock`, which a start holds (shared)
while it opens and marks its log (whether a VM holds the name is read from its lock's record, never by probing the lock a start takes without waiting); `NAME.moved` goes after an hour.
Released migration records are retired as below. Logs are capped by their
writers, not swept (`output::append_capped`): every write a VM process's
output relay makes to a log in the run directory, whichever process and
stream, is made under `RUN/.rotate.lock` to the file at the
log's path then (reopened if another writer rotated it), and past 8 MiB
renames it `NAME.log.1` and starts a new one. No write goes to a rotated
or removed generation, and none is cut.

**The tap prefix** names taps and hold devices: `f` and five base-36 digits
of a hash of the state directory (`Host::tap_prefix`), so it never changes
and hosts on separate state directories read apart. Names never clash even
when two prefixes do, as each carries its process's pid; garbage collection
goes by a tap's alias, never its name.

**The host lock** is a flock taken by one thread of a process at a time and
reentrant within a thread, so a guard dropped under it (an address claim)
never deadlocks.

**Addresses and generations** keep the semantics of the generations work
(#60): only an address's home host (whose `vm_ips` holds it) hands it out,
each time with a new generation from a durable high-water mark; a VM keeps its
generation through migrations and suspends; route announcements and
withdrawals carry it; each host keeps the newest (generation, withdrawn) seen
per address and ignores older messages and announcements of withdrawn
generations; a withdrawal frees a loan of its generation or older. Within a
generation, each place the VM runs has a revision: a migration's target takes
the source's next one (its own from its commit, recorded once its packets are
handed over), a source that runs again after
an abort the one after that (and announces it), a restore one past the newest
recorded here; announcements carry it, and
one with an older revision of the newest generation is stale, so a source's
delayed announcement never takes a route back from its target (#256). The
record can trail the revision its VM runs at (the target's, until recorded; a
failed write, until retried), so a VM process publishes its revision in
`RUN/live/IP` (tmpfs, replaced atomically, never synced) under the host lock as
it changes, before the record's write: an arrival at its commit. Under the same
lock, an announcement of the generation a VM here holds is judged against the
newer of the record and that file, believed only from the record's holder
instance while it is alive (after a crash the record decides); recording a
newer revision drops a route taken for an older one (#533). An address
is *taken* if its record names a holder instance that is alive (holding the
name, or dead with its Firecrackers not yet gone) or a holder suspended here
with that generation, or it is lent. Another instance of the same name (a
restart after a SIGKILL) does not hold it, and an instance releases only its
own claim.
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

**Admission** (`reserve_mib`): every start (run, restore, resume, standby
claim, arrival: what the VM brings or pages in, and a step), growth and
incoming migrations are admitted under the host lock against MemAvailable
minus the reserve and the grants of the last 10 s (`RUN/grants`); an
arrival's or checkpoint restore's grant (including a suspended resume) is
held past that until all its memory is here, or it ends, as it comes in only
as the pull goes: made with the grant in one critical
section, it is a file (`RUN/holds/ID-MIB`) its process keeps flocked, so it
goes with the process whatever becomes of the file (admission removes one
whose lock is free). A start refused fails before it loads
anything. Standby refills stop under it.

**Memory marks** (`limit.rs`): each VM's Firecracker cgroup has a
`memory.high` at the memory admitted for it plus Firecracker's overhead
(64 MiB + 1/64). It starts at what the start was admitted (a cold run: the
template's working set; a restore or resume: that and the checkpoint's
pages; an arrival: the source's RSS; a claim: the standby's memory, of
which only the step is charged; each plus a step), and a start that never
runs refunds its grant. It is raised a step
(a quarter, 256 MiB to 2 GiB) when the cgroup's usage comes within half a
step of it (its `high` events, or each second), each step admitted first
(the mark's lock is never held across admission, whose host lock a
migration's rollback holds while it restores the mark);
never past the guest's size, raised before a grow's PATCH by what the grow
was charged, lowered only once a shrink settles and never below what is in
use. Refused, the VM is throttled at its mark (the kernel slows its vCPUs;
`memory.high`, never `memory.max`: nothing is OOM-killed) and counts as
starved, so eviction moves it. Its cgroup never swaps (`memory.swap.max`
0): on a host with swap, reclaim at the mark would page the guest out
instead, and a pause would wait for its vCPUs' swap reads, which nothing
can cut short (#136). The pager's installs are charged to the
cgroup but throttled by the VM process's own, so pulls and checkpoint copies
never wait on the mark; a migration (once its target is prepared) or a
checkpoint lifts it right before it pauses the VM, first waiting out vCPUs
already asleep in throttling (the kernel's sleeps last up to 2 s; the wait
gives up after 2.5 s), so the pause is not held up.

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
   check that can abort, then under the host lock routes the address to its
   tap and turns `pending` into `committed` (refused if it was fenced), and
   resumes before letting go of the lock. Until then the host's route to the
   address (a peer's, say the source's) stays; one that a dead arrival's
   host lost is put back once its record reads as aborted. Hosts sharing a
   network namespace route it only after the held packets (`hold.rs`).
4. Pages: the target's pager connects to the *source's* listener (the
   address the source sent: its listen address, or for a wildcard one its
   underlay address with the listen port, derived from the kernel's route toward
   the peers without `--underlay`) with `pages {name, mig}`; the listener passes the socket (SCM_RIGHTS) to the
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
socket-activatable (`LISTEN_FDS`, taking its address from the socket when
no ADDR is given, or binds ADDR or `host.json`'s `listen`); it saves only its
address, once the socket is bound and valid. Settings are `flexvm config`'s;
those unset are derived where used, never saved (`Config::underlay`,
`announce_dev`, `reserve`: the kernel's route toward the first peer elsewhere,
cached for 30 s, and the host's RAM). Proxy ARP on the announce device is enabled
by every VM process too, so it needs no listener. Each
connection's first line (peeked, then consumed exactly through its newline, so nothing after it is consumed) is
one of:

| op | |
|---|---|
| `migrate_in` | spawn `flexvm run --incoming` with the connection |
| `pages` | pass the connection to the VM process named, over its control socket |
| `migration` | report and settle a migration record; `done`: forget a released one |
| `route` | a peer's announcement/withdrawal: judge its generation, set or remove the route |
| `lend` | lend an address of this host's range to a restoring peer, with a new generation |
| `source` | whether a VM process of that name is a migration source here (a target retires a released record when not) |

Only connections from the configured peers' addresses are served, by
host.json as it is now: any other gets `{"ok": false, "error": "IP is not
a peer of ADDR ..."}` from the accept loop, unread and without a slot, and
is closed. Peer names are resolved only by one background thread (at start,
every 30 s, and when a request meets a name not yet resolved); an address
needs no lookup, and a name no longer configured admits nothing. Request
lines must arrive whole within 10 s of the connection being accepted (one deadline, however the line trickles in) and are capped at 64 KiB; at most 512
requests at once. At most 8 incoming migrations are between their start and
their commit or refusal at once, and 4 from any one peer: slots are per peer
address. More are refused at once, before the source pauses, and an arrival
not prepared within 7 s of its accept is refused too. Restarting or not running it loses nothing but the ability
to receive.

## Standby pool

`flexvm standby [--template T] N` records N in `STATE/standby/T` and starts
standby VMs until there are N: each is `flexvm run --standby`, a VM process
that restores the template, lets the guest reseed and settle, pauses, and
listens on `RUN/standby/HASH/PID.sock` (HASH: 16 hex characters of the template's name;
the claim request carries the generation key). `flexvm run` claims one (`claim
{name, ip, cmd, generation}` with its stdout/stderr passed over SCM_RIGHTS): the standby
takes the name and address, routes, resumes, sends `START`, and becomes that
VM. A claimed standby starts its replacement, and every 5 s the listener and
each running VM process refill any pool below its target (skipped while
another refill holds the lock, for a minute after memory pressure stopped
standby VMs, and for a minute after a template's refill failed), so a pool
comes back after a reboot, a template rebuild or a standby's death. A foreground `run` that claimed
one forwards its signals to it and exits with the status the VM process sends
back on the claim connection. Under memory pressure standby VMs are stopped
(SIGUSR1) first. The count is explicit, and refills stop under the reserve; one refill
of a template runs at a time (`.refill` lock), and waits until the standby
VMs it starts are ready (a minute at most each), so concurrent claims never overfill. A claim sent
but not answered (the standby died, or hung up) is an uncertain outcome: the
guest may have run, so `run` reports it (with the standby's socket, and
whether the registry shows the VM) and starts nothing else.

An unclaimed standby VM exits 0 only when it leaves the pool on purpose: the
pool's stop (SIGUSR1), its template changed, the pool is over its target, or
its socket is gone. SIGINT, SIGQUIT and SIGTERM destroy it with 128 + the
signal (SIGTERM too: there is nothing worth suspending), and its Firecracker
dying (or its memory lost) ends it with 124, as for any VM. A claim that
fails and gives the VM up ends it with 125.

## Memory controller and eviction

Each VM process resizes its own VM once a second exactly as before
(virtio-mem steps, starved flag: refused by the host, or throttled at its
mark, and only while it runs here; a guest at its own ceiling is not
starved, as moving it cannot help, nor is a migration's source sitting at its
mark through the pull, whose mark is not raised while lifted or not running),
and publishes how fast its memory
(`memory.current`) grew over the last 5 s (`growth_mib_s`, republished when
it moves to another power of two; an arrival's pull does not count).
Pressure relief needs one decider per host: every second each VM process
whose host is under pressure, or whose VM is starved, tries
`STATE/evict.lock` (non-blocking). Pressure starts when MemAvailable falls
under the high-water mark (`evict_mib`, `config --evict-at`; default the
reserve plus the reserve or 512 MiB, whichever is more; the reserve's default
is a sixteenth of the host's RAM, from 256 MiB to 4 GiB) and lasts until it is
back above the mark by half the mark's height over the reserve (at least
128 MiB), marked by `RUN/evict.active`; the marks (and the reserve that
admission uses) are read from `host.json` as it changes. Under the reserve,
standby VMs are stopped first, under a lock of their own
(`STATE/standby.stop.lock`), so a slow migration holding `evict.lock` does
not hold that up. A refill's grant for each standby is the template's working set (what a cold start
admits), 256 MiB at least. Recovery and a claim's refill start none while `.pressure` is recent, checked under the stop lock before each grant (relief marks it holding the lock), so one that waited behind another refill during relief starts none. A refill holds it shared from each standby's grant until
that standby has created its lock file (it says so on its notify fd), 5 s
at most (its grant gives up on a busy host lock by then; a standby that has not said so by then, or said something else, is killed and reaped before the lock is let go, then its grant is refunded and what it left swept locally, never waiting on peers, and the refill fails), never through its load, and starts none while relief holds it: relief either lists
a standby being started or ran before its grant, and meanwhile holds eviction
off as it does for another process stopping them. Signalling any marks the pressure (`RUN/standby/.pressure`,
no refill for a minute); the controller then checks their pidfds on its
next ticks, never waiting on one, and holds eviction off until one exits
or for a second (a loading or just claimed standby must not hold it longer). The lock's
holder, at most once per 5 s, reads the registry and ranks running VMs: the
starved first, then the fastest growing (by power of two, under 8 MiB/s is
none), then the biggest RSS (without pressure, only starved VMs are
candidates; a `run -- CMD` VM never is: its process ends with CMD's, so
its registry entry says so (`cmd`, set before it is first published, for a
run, a standby claim or a resume), `migrate` with `evict` refuses it as busy
and a plain `migrate` refuses it outright). It runs the eviction on a thread of its own that keeps the lock,
so its controller keeps ticking and its VM's memory requests are answered: it
sends the first candidate `migrate` with each peer in turn until one accepts
(`migrate` with `evict`: the target admits such an arrival only if it
leaves the target's own eviction mark available, read with the reserve
under the host lock, and refuses it while an eviction runs there (its
thread holds `STATE/evict.worker.lock`, taken under the host lock that
admission probes it under), so a VM is not moved straight back), then waits
for that VM's copy here to exit (its target has all its memory), so the next
decision sees the memory freed; all within 60 s, past which it lets go (an
unanswered migration is not a refusal: the VM, still migrating, is busy to
the next decider). The request is `if_idle`: a VM busy with another
operation (a checkpoint's copy, a migration, an arrival not yet settled)
refuses at once and the next VM is tried; eviction never waits for or races
an operation. A refused VM and peer pair is not tried again for 5 s, doubling
to 60 s while refusals continue (`RUN/evict.backoff`). A refused arrival's
log is removed; an accepted one becomes `NAME.log`.
Announcements and `lend` requests go to all peers at once, by the peers
configured now (`Host::config_now`); the listener re-reads them too, so
`flexvm config --peer` reaches running processes.

## Exec across hosts

There is no remote control channel. An exec whose VM migrates away ends
with `vm NAME moved to HOST; the command keeps running there (session ID)`,
exit 1; reconnection within a host (checkpoint pauses, vsock resets) still
works.

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
   killed, so it never acts on a reused pid or recreates a removed cgroup;
   liveness checks never reap (`waitid` with `WNOWAIT`), only that kill does.
   It is reaped only once its pager has stopped, so the pager's reads by pid
   (`process_vm_readv`, `/proc/PID/pagemap`, `/proc/PID/maps`) never meet a
   reused one; each is also believed only if its pidfd shows no exit after it.
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
   migrating away (SIGINT, or `run -- CMD` ending), its target having
committed, never ends the process,
   and takes back the checkpoint cancel it raised (fault
   `kill_refused_checkpoint`).
6. **Suspend markers and quarantine.** `STARTED` means consumed: `resume`
   deletes such a checkpoint and `ls` does not show it; deleting it holds
   the operation lock, and a suspend deletes it first. A suspended directory
   without a manifest (a revoke or a removal cut short), or marked `STARTED`
   (a resume killed outright) or `DISCARDED`, is debris: it holds neither
   name nor address, `ls` does not show it, and whoever takes the name next
   (`run`, `resume`, `restore`, `kill`, an arrival; a suspend for its own
   VM) removes it durably and lets go of its address (without withdrawing
   its generation: a consumed checkpoint's VM may run on elsewhere). A
   revoked checkpoint is removed whole. Unit test
   `host::suspend_debris_is_removed_by_the_names_next_holder`; faults
   `suspend_debris`, `revoked_publication`. Quarantine is a file
   (`QUARANTINE`, with the boot id), held only in that boot by both `resume`
   and `ls` (fault `quarantine_reboot_ls`). Suspended VMs keep name and address with
   no pid, and `ls` lists them.
7. **Address state** is read fresh and changed per change under the host
   lock, durable where it orders anything. The listener's skip-local check
   reads the holder under that lock.
8. **The `migrate_in` hand-off loses no bytes**: the listener peeks at the first
   line and consumes exactly through its newline, so nothing is buffered
   when it passes the socket on. Page connections are passed to the VM named, which serves them
   only as the source of the migration id they name.
9. **Shared resources have one owner.** Socket roots, work directories, taps
   (`<prefix><pid>t<n>`, a template build's `<prefix>x<pid>`, owned by their alias) and cgroups
   (`idle-<pid>-<start>-<n>`; a VM process's own `vm-<pid>-<start>`, swept once empty) are named after the owning process and only swept once it is gone; each process has its own
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
12. **An arrival settles once, before anything else changes owners.** Until
   every page is in and its record is durably `released` (then a home host
   takes its loan back), the arrival is unsettled. Settling happens in one
   place (`Proc::settle_arrival`), under `op`, so it never races the VM's
   end. Every operation that changes who owns the VM (suspend, migrating
   on, `checkpoint --stop`) settles first, waiting a bounded time, and is
   refused as "still arriving" otherwise (or as failed, once the arrival's
   pager has given up on its source); later operations see a settled VM.
   A migration's rollback removes only a loan that migration made. A
   released record whose source never says `done` (killed) is retired once
   the source's listener says no VM process of that name is a migration
   source there (op `source`; asked by garbage collection); a source that cannot be asked keeps it. Faults
   `arrival_overtaken`, `pull_died`, `target_killed`, `source_killed_basic`.
