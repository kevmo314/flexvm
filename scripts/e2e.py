#!/usr/bin/env python3
"""End-to-end checks of flexvm's user-facing commands on one KVM host, as CI
runs them. Run as root, after building flexvm and the patched Firecracker and
fetching the guest kernel and the test image's base (scripts/fetch.sh; see
README.md and .github/workflows/ci.yml).

It makes the test image (scripts/test-image.py) and pulls its templates from it
(the image case's and the app-log scenarios' from --image), then runs the cases below and the selected
scripts/faults.py scenarios, with fresh VMs, in --jobs lanes at once. Each
lane has two flexvm hosts on loopback (A and B: their own listeners, run
directories, state directories and VM address ranges); a lane runs its work
in batches, each a worker process (this script with --worker) that starts the
lane's hosts, runs its cases against them, stops them and checks that nothing
is left. It touches only what it created: its own processes, taps, cgroups
and directories.

usage: sudo scripts/e2e.py [--bin FLEXVM] [--state DIR] [--log-dir DIR]
                           [--port-a N] [--net-a A.B.C] [--net-b A.B.C]
                           [--jobs N] [--lanes "PORT:NET-A:NET-B ..."]
                           [--image REF [--image-cache DIR] | --no-image] [--test-image DIR] [--faults "SCENARIO ..."]
                           [--shard pr|main|recovery|heavy] [--split I/N] [--no-skips] [CASE ...]

Shards (CI runs pr in four splits side by side, heavy on a schedule):
  pr        main and recovery together;
  main      the cases and FAULTS;
  recovery  RECOVERY_FAULTS: the scenarios that restart listeners (run with listeners
            faults.py starts itself, which they check are new processes), the
            terminal's, and the timeout-bound ones;
  heavy     HEAVY_FAULTS: GiB-scale guests and long observation windows; run them
            with --jobs 1.
A scenario that finds this host lacks what it tests ends SKIP, not PASS; with
--no-skips (CI) a SKIP fails the run.
"""
import argparse, glob, hashlib, ipaddress, json, os, re, shutil, signal, socket, subprocess, sys, tempfile, threading, time, traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

p = argparse.ArgumentParser(usage=__doc__)
p.add_argument("--bin", default=os.path.join(ROOT, "target", "release", "flexvm"))
p.add_argument("--state", default="/var/lib/flexvm", help="the state directory whose artifacts/ the scripts installed")
p.add_argument("--log-dir", default="/tmp/fvci-logs", help="listener, VM and Firecracker logs end up here")
p.add_argument("--port-a", type=int, default=7140, help="lane 0's host A listens here, its host B on the next port; "
               "each further lane takes the next two")
p.add_argument("--net-a", default="10.140.0", help="lane 0's host A's VM addresses (.2-.60); B uses --net-b; "
               "each further lane adds 2 to their second octet")
p.add_argument("--net-b", default="10.141.0")
p.add_argument("--jobs", type=int, default=4, help="lanes that run at once")
p.add_argument("--lanes", help="the lanes' ports and address ranges, as PORT:NET-A:NET-B each (overrides --port-a, "
               "--net-a, --net-b and --jobs)")
p.add_argument("--tag", default="fvci", help="prefix of this run's own directories under /run and /var/tmp")
p.add_argument("--template", default="ci", help="name of the template the cases pull (from the test image) and use")
p.add_argument("--test-image", help="the test image's OCI layout: made there (scripts/test-image.py) unless it holds the "
               "image of the state's base.squashfs already (default: in the run's own directory)")
p.add_argument("--image", default="public.ecr.aws/docker/library/busybox:1.36",
               help="container image for the image-template case")
p.add_argument("--no-image", action="store_true", help="skip the image-template case (needs registry access)")
p.add_argument("--image-cache", help="keep the pulled image here as an OCI layout, and build from it when it is there (no registry)")
# The scripts/faults.py scenarios that fit CI time: migration failure paths and fencing, address
# generations and loans, forged peers, processes killed between steps, checkpoint corruption,
# copy-on-write exactness, growth and a checkpoint during a resize (on a template with little
# pre-plugged), held packets and devices, signals, standby VMs, resume failures, admission, the
# exit statuses of foreground runs and image apps' logs.
FAULTS = ("basic route route_abort lost_ack unknown refused pages_blip pages_dead_restore prepared_retry resume_kill exec_race guest_calls exec_background exec_pause_grace "
          "checkpoint_restore checkpoint_fork checkpoint_corrupt held_restore_frozen cow_exact cow_rescue_fail cow_collapsed unplug_collapsed cow_abort ckpt_incremental ckpt_hot "
          "ckpt_failed_stop ckpt_rearm prepare_fail fc_prepare forged_vmstate slow_preload bad_preload pull_enomem ckpt_packet_hold "
          "abort_superseded signals suspend_gen standby standby_vm_ips restore_ip_peer spoof_filter killed_migrated "
          "incoming_killed start_killed claim_killed standby_stalled standby_refill_race standby_lock_timeout standby_stop_claim standby_claim_signal standby_concurrent_claims standby_claim_caps fc_died cow_grow plug_race plug_storm suspend_debris revoked_publication "
          "same_host_order same_host_slow_route same_host_flood same_host_late_handover same_host_hold_route_fail same_host_backlog same_host_bulk_tcp ckpt_backlog ckpt_paused_backlog rx_stall arrival_abort_route arrival_killed_route handoff_superseded delayed_announce delayed_announce_handoff announce_arp_timer prepare_fail_announce reconcile_announce reconcile_kill mem_high mem_high_migrate mem_high_evict mem_refused_headroom mem_refused_fill "
          "sigkill_restart listen_trickle suspend_cmd suspend_slow_cmd suspend_overlap fc_died_busy pause_cmd_start suspend_died evict_latency evict_skips_cmd cmd_flag "
          "refused_admission arrival_grew arrival_grew_admitted meminfo_unreadable checkpoint_hotplug log_cap gc_debris arrival_log template_tap arrival_overtaken "
          "leave_fail capture_fail abort_gen_fail commit_fail commit_fail_routed abort_stay_fail prepare_disconnect prepare_trickle arrival_flood unlend_retry bad_app_log resume_slow_guest resume_readdress_fail resume_unpause_fail abort_link_fail resume_unsettled resume_pull_lock page_conns page_refusals suspend_unaddressed resume_fence_fails "
          "resume_failures resume_mark_fails suspend_killed resume_suspending source_unpublished start_admission standby_admission pause_lost cow_crash ckpt_dir_moved "
          "checkpoint_untrusted_dir run_status unread_output quit_status ctrl_z_long_op app_log warm_ready forged_peer forged_pages ckpt_ancestor_corrupt resume_killed_marked restore_route_fence "
          "resume_outcome exec_recovery_instance pause_resume collapse_abort")
# The ones that restart the listeners (faults.py starts its own for them: LISTENER_FAULTS), the
# terminal's, and the ones bound by timeouts (a guest that never answers; a pager that fails or
# never gets its pages, gated deterministically).
LISTENER_FAULTS = {"suspend_resume", "target_killed", "unit_restart", "wildcard_listen", "peer_by_name", "peer_moved",
                   "peer_unresolvable", "late_withdrawal", "resume_listener_restart", "arrival_cap_restart", "reboot"}
RECOVERY_FAULTS = " ".join(sorted(LISTENER_FAULTS)) + " terminal guest_hang uffd_err fetch_tail_enomem fetch_enomem_stuck cow_wp_race"
# GiB-scale guests (pages_dead, source_killed_basic, which runs source_killed, pull_died, kill_source,
# kill_refused_checkpoint, quiet_source, checkpoint_crash, suspend_disk_freed), long device and
# eviction sequences (cow_reports_held, evict_*), THP collapse cut short by a failed checkpoint
# (collapse_ckpt_fail) and a stalled shrink: scheduled, one at a time (--jobs 1).
HEAVY_FAULTS = ("pages_dead source_killed_basic pull_died kill_source kill_refused_checkpoint quiet_source checkpoint_crash suspend_disk_freed "
                "cow_reports_held collapse_ckpt_fail shrink_stall evict_no_pingpong evict_grower")
SHARDS = {"pr": FAULTS + " " + RECOVERY_FAULTS, "main": FAULTS, "recovery": RECOVERY_FAULTS, "heavy": HEAVY_FAULTS}
p.add_argument("--shard", choices=SHARDS, default="main",
               help="pr, main: the cases and those scenarios; recovery, heavy: only the faults case, with those scenarios")
p.add_argument("--split", help="I/N: run only the I-th of N parts of the selection, balanced by COST (CI runs N side by side)")
p.add_argument("--no-skips", action="store_true", help="a skipped case or scenario fails the run")
p.add_argument("--faults", help="scripts/faults.py scenarios to run against the two hosts ('' for none; default: the shard's)")
# A worker runs its cases on one lane, against templates that are already built.
p.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
p.add_argument("--templates", help=argparse.SUPPRESS)
p.add_argument("--lane", type=int, default=0, help=argparse.SUPPRESS)
p.add_argument("--results", help=argparse.SUPPRESS)
p.add_argument("--own-listeners", action="store_true", help=argparse.SUPPRESS)
p.add_argument("--selftest", action="store_true",
               help="check the scheduler without KVM: fake templates and workers, one worker that cannot be spawned")
p.add_argument("cases", nargs="*", help="cases to run (default: all)")
args = p.parse_args()
if args.faults is None:
    # The self-test schedules every CI shard's scenarios at once: listener-owning batches stay apart.
    args.faults = SHARDS[args.shard] + (" " + RECOVERY_FAULTS if args.selftest else "")
if not args.cases and not args.worker and args.shard not in ("pr", "main"):
    args.cases = ["faults"]
BIN = os.path.abspath(args.bin)
ARTIFACTS = os.path.join(os.path.abspath(args.state), "artifacts")
os.makedirs(args.log_dir, exist_ok=True)


# --- CLI wrapper ---------------------------------------------------------------
# Everything that knows how flexvm is driven lives in this section; the cases
# below only call these methods. A host is a state and a run directory with a
# peer listener (`flexvm listen`) and its settings in STATE/host.json; every VM
# is a process of its own (`flexvm run -d`), paused and resumed with signals
# (SIGTSTP, SIGCONT), stopped (suspended) and started again with `flexvm stop`
# and `flexvm start`, and destroyed with `flexvm kill` (or `rm -f`).


def flexvm(*argv, timeout=180, check=True, env=None):
    """Runs the flexvm CLI; returns the CompletedProcess."""
    # A run directory belongs to one state directory, so BUILD has its own (a Host's --run follows and wins).
    r = subprocess.run([BIN, "--state", BUILD, "--run", os.path.join(RUN, "build"), *argv], capture_output=True, text=True, timeout=timeout,
                       env=env)
    if check and r.returncode != 0:
        raise AssertionError(f"flexvm {' '.join(argv)} exited {r.returncode}: {r.stderr.strip()}")
    return r


def listener_inode(port):
    """Inode of the socket listening on 127.0.0.1:port (or on any address), or None."""
    for line in open("/proc/net/tcp").read().splitlines()[1:]:
        f = line.split()
        addr, lport = f[1].split(":")
        if int(lport, 16) == port and f[3] == "0A" and addr in ("0100007F", "00000000"):
            return f[9]
    return None


def owns_socket(pid, inode):
    try:
        return any(os.readlink(f"/proc/{pid}/fd/{fd}") == f"socket:[{inode}]" for fd in os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return False


def alive(pid):
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


# FLEXVM_FAULTS lets scripts/faults.py inject failures; it changes nothing otherwise.
ENV = {**os.environ, "FLEXVM_FAULTS": "1"}


class Host:
    def __init__(self, label, port, peer_port, net):
        self.label, self.addr = label, f"127.0.0.1:{port}"
        self.peer = f"127.0.0.1:{peer_port}"
        self.port, self.net = port, net
        # Inside this run's own fresh directories (see main).
        self.run_dir = os.path.join(RUN, label)
        self.state_dir = os.path.join(WORK, f"{label}-state")
        self.prefix = None  # of its taps, derived from its state directory (`flexvm info`)
        self.log = os.path.join(args.log_dir, f"listen-{label}.log")
        self.proc = None
        self.vms = set()  # names of the VMs this script created here or moved here
        self.pids = set()  # their processes (pid, start), seen here

    # lifecycle of the host itself
    def start(self):
        if listener_inode(self.port) is not None:
            raise AssertionError(f"port {self.port} is in use; pick other ports with --port-a")
        os.makedirs(self.run_dir, exist_ok=True)
        shared_state(self.state_dir)
        nets = sorted((args.net_a, args.net_b), key=lambda n: ipaddress.IPv4Address(f"{n}.0"))
        self.configure(peers=[self.peer], vm_ips=f"{self.net}.2-{self.net}.60",
                       cluster_ips=f"{nets[0]}.2-{nets[-1]}.254", reserve_mib=256)
        self.prefix = self.info()["derived"]["prefix"]
        cmd = [BIN, "--state", self.state_dir, "--run", self.run_dir, "listen", self.addr]
        self.proc = subprocess.Popen(cmd, stdout=open(self.log, "a"), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     env=ENV, start_new_session=True)
        # Up once our own child holds the listening socket.
        deadline = time.time() + 30
        while not owns_socket(self.proc.pid, listener_inode(self.port)):
            if self.proc.poll() is not None or time.time() > deadline:
                raise AssertionError(f"host {self.label} did not come up; see {self.log}")
            time.sleep(0.2)

    def stop(self, timeout=60):
        """Destroys what VMs are left and stops the listener; raises if it died early."""
        if not self.proc:
            return
        for vm in sorted(self.ps()):
            self.rm(vm, force=True, check=False)
        if self.proc.poll() is not None:
            raise AssertionError(f"host {self.label}'s listener died early (exit {self.proc.returncode}); see {self.log}")
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            raise AssertionError(f"host {self.label}'s listener did not stop within {timeout} s; killed it")

    def cli(self, *argv, **kw):
        return flexvm("--state", self.state_dir, "--run", self.run_dir, *argv, env=ENV, **kw)

    def configure(self, **keys):
        """Sets keys of STATE/host.json (None removes one): read, updated and replaced atomically."""
        path = os.path.join(self.state_dir, "host.json")
        try:
            cfg = json.load(open(path))
        except FileNotFoundError:
            cfg = {}
        for k, v in keys.items():
            if v is None:
                cfg.pop(k, None)
            else:
                cfg[k] = v
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)

    def info(self):
        """`flexvm info`: {"version", "config", "set", "derived", "warnings"}."""
        return json.loads(self.cli("info").stdout)

    def pid(self, vm):
        v = self.ps()[vm]
        self.pids.add((v["pid"], v["start"]))
        return v["pid"]

    def wait_state(self, vm, state, timeout=60):
        assert wait_for(lambda: self.ps().get(vm, {}).get("state") == state, timeout), (vm, self.ps().get(vm))

    # VM commands
    def run_json(self, vm=None, template=None, ip=None):
        """Starts a VM (in the background; without a name flexvm makes one up); returns its JSON."""
        opts = (["--name", vm] if vm else []) + (["--ip", ip] if ip else [])
        r = json.loads(self.cli("run", *opts, "-d", template or args.template).stdout)
        self.vms.add(r["name"])
        self.pids.add((r["pid"], r["start"]))
        return r

    def run(self, vm, template=None, ip=None):
        """Starts a VM (in the background); returns its address."""
        self.vms.add(vm)
        return self.run_json(vm, template, ip)["ip"]

    def exec(self, vm, cmd, timeout=120):
        """Runs a shell command in the VM; returns (exit code, stdout, stderr)."""
        r = self.cli("exec", vm, cmd, check=False, timeout=timeout)
        return r.returncode, r.stdout, r.stderr

    def ps(self, all=True):
        """{name: {"ip", "template", "state", "pid"}} from `flexvm ps -a --json` (without all: `ps --json`,
        which leaves out stopped VMs)."""
        return {v["name"]: v for v in json.loads(self.cli("ps", *(["-a"] if all else []), "--json").stdout)}

    def pause(self, vm):
        t = time.time()
        os.kill(self.pid(vm), signal.SIGTSTP)
        self.wait_state(vm, "paused")
        return {"pause_ms": round((time.time() - t) * 1000, 1)}

    def resume(self, vm):
        """SIGCONT for a paused VM; `flexvm start` for a stopped (suspended) one."""
        if self.ps().get(vm, {}).get("state") == "suspended":
            r = json.loads(self.cli("start", vm).stdout)
            self.pid(vm)
            return r
        t = time.time()
        os.kill(self.pid(vm), signal.SIGCONT)
        self.wait_state(vm, "running")
        return {"resume_ms": round((time.time() - t) * 1000, 1)}

    def suspend(self, vm):
        """`flexvm stop`: the VM is checkpointed to disk and its process exits (as on SIGTERM)."""
        pid, t = self.pid(vm), time.time()
        out = self.cli("stop", vm, timeout=180).stdout
        assert out == f"{vm}\n", f"stop {vm} printed {out!r}"
        assert wait_for(lambda: not alive(pid), 10), f"{vm}'s process outlived its stop"
        return {"suspend_ms": round((time.time() - t) * 1000, 1)}

    def kill(self, vm, check=True):
        """`flexvm kill`: destroys a VM that has a process (a stopped one is refused)."""
        return self.cli("kill", vm, check=check)

    def rm(self, vm, force=False, check=True):
        """`flexvm rm`: removes a stopped VM; with force (-f) one in any state."""
        return self.cli("rm", *(["-f"] if force else []), vm, check=check)

    def checkpoint(self, vm, path, stop=False, incremental=False):
        extra = (["--stop"] if stop else []) + (["--incremental"] if incremental else [])
        r = json.loads(self.cli("checkpoint", vm, path, *extra).stdout)
        if stop:
            assert wait_for(lambda: vm not in self.ps(), 30), f"{vm} still listed after checkpoint --stop"
        return r

    def restore(self, path, name=None, ip=None):
        """`flexvm run --checkpoint PATH -d`: a VM from a checkpoint (its name and address unless given)."""
        extra = (["--name", name] if name else []) + (["--ip", ip] if ip else [])
        r = json.loads(self.cli("run", "--checkpoint", path, *extra, "-d").stdout)
        self.vms.add(r["name"])
        self.pid(r["name"])
        return r

    def migrate(self, vm, to):
        to.vms.add(vm)
        return json.loads(self.cli("migrate", vm, to.addr).stdout)

    def logs(self, vm):
        """A background VM's output (an image app's stdout and stderr)."""
        try:
            return open(os.path.join(self.run_dir, "vms", f"{vm}.log")).read()
        except OSError:
            return ""

    # what the host holds on this machine, to check that it gives it back
    def firecrackers(self):
        """pid -> Firecracker directory, for Firecrackers working in our run directory."""
        out = {}
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                if open(f"/proc/{pid}/comm").read().strip() != "firecracker":
                    continue
                cwd = os.readlink(f"/proc/{pid}/cwd")  # its directory (its output is a pipe)
            except OSError:
                continue
            if cwd.startswith(self.run_dir + "/"):
                out[int(pid)] = cwd
        return out

    def taps(self):
        return [n for n in os.listdir("/sys/class/net") if self.prefix and n.startswith(self.prefix)]

    def cgroups(self):
        # By identity (`idle-PID-START-N`): never a later process's that got a pid.
        return [c for p, start in self.pids for c in glob.glob(f"/sys/fs/cgroup/flexvm/idle-{p}-{start}-*")]

    def processes(self):
        """Processes on this host's state directory: its listener and VM processes."""
        out = []
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                argv = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
            except OSError:
                continue
            if self.state_dir.encode() in argv and alive(pid):
                out.append(int(pid))
        return out

    def leftovers(self):
        """Everything of this host's still on the machine (expected empty once it stopped)."""
        left = [f"firecracker pid {p}" for p in self.firecrackers()] + [f"tap {t}" for t in self.taps()]
        left += [f"cgroup {c}" for c in self.cgroups()]
        left += [f"process {p}" for p in self.processes()]
        locks = os.path.join(self.run_dir, "vms", ".locks")
        left += [f"vm {v}" for v in os.listdir(locks) if v.endswith(".lock")] if os.path.isdir(locks) else []
        return left

    def save_logs(self):
        """Copies the VM and Firecracker logs out of the run directory."""
        for log in glob.glob(f"{self.run_dir}/**/*.log", recursive=True) + glob.glob(f"{self.run_dir}/**/*.log.1", recursive=True):
            dest = os.path.join(args.log_dir, f"run-{self.label}", os.path.relpath(log, self.run_dir))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy(log, dest)


# --- helpers -------------------------------------------------------------------


def vm_resources(ip):
    """The tap the VM's address routes to, the Firecracker holding it and its cgroup."""
    route = subprocess.run(["ip", "-4", "route", "show", "exact", f"{ip}/32"], capture_output=True, text=True).stdout
    m = re.search(r"\bdev (\S+)", route)
    tap = m.group(1) if m else None
    pid = None
    for d in glob.glob("/proc/[0-9]*/fdinfo/*"):
        try:
            if tap and f"iff:\t{tap}\n" in open(d).read():
                pid = int(d.split("/")[2])
                break
        except OSError:
            pass
    cgroup = None
    if pid:
        # Only a leaf of flexvm's own: anything else may be shared, or inherited.
        rel = open(f"/proc/{pid}/cgroup").read().strip().split("::", 1)[-1]
        if rel.startswith("/flexvm/") and rel.count("/") == 2:
            cgroup = "/sys/fs/cgroup" + rel
    return {"route": route.strip(), "tap": tap, "pid": pid, "cgroup": cgroup}


def wait_for(cond, timeout, step=0.1):
    end = time.time() + timeout
    while True:
        v = cond()
        if v or time.time() > end:
            return v
        time.sleep(step)


def must(host, vm, cmd):
    code, out, err = host.exec(vm, cmd)
    assert code == 0, f"{cmd!r} on {vm} exited {code}: {err.strip()}"
    return out.strip()


def fill(host, vm, mib=64):
    """Writes random data into guest RAM (/tmp is tmpfs); returns its md5."""
    return must(host, vm, f"dd if=/dev/urandom of=/tmp/data bs=1M count={mib} status=none && md5sum /tmp/data").split()[0]


def md5(host, vm):
    return must(host, vm, "md5sum /tmp/data").split()[0]


def marker(host, vm):
    """Starts a guest process counting up in /tmp/count; returns (pid, start time)."""
    # Written to a temporary file and renamed, so a read never sees it empty or half written.
    must(host, vm, "rm -f /tmp/count; setsid sh -c 'i=0; while :; do i=$((i+1)); echo $i > /tmp/count.new; "
                   "mv /tmp/count.new /tmp/count; sleep 0.05; done' >/dev/null 2>&1 </dev/null & echo $! > /tmp/marker.pid; "
                   "for i in $(seq 100); do [ -s /tmp/count ] && exit 0; sleep 0.05; done; exit 1")
    return marker_id(host, vm)


def marker_id(host, vm):
    return must(host, vm, 'p=$(cat /tmp/marker.pid); echo "$p $(cut -d" " -f22 /proc/$p/stat)"')


def count(host, vm):
    return int(must(host, vm, "cat /tmp/count"))


def clock_error(host, vm):
    before = time.time()
    out = must(host, vm, "date +%s.%N")
    return float(out) - (before + time.time()) / 2


def echo_server(host, vm, ip, port=7000):
    """Starts a TCP echo server in the guest; returns once it echoes for the host."""
    must(host, vm, f"setsid socat TCP-LISTEN:{port},fork,reuseaddr EXEC:cat >/dev/null 2>&1 </dev/null &")

    def up():
        try:
            with socket.create_connection((ip, port), timeout=1) as s:
                return echo(s, b"ping\n")
        except OSError:
            return False
    assert wait_for(up, 10), f"echo server in {vm} not reachable on {ip}:{port}"


def echo(conn, msg):
    conn.sendall(msg)
    got = b""
    while len(got) < len(msg):
        d = conn.recv(65536)
        if not d:
            break
        got += d
    return got == msg


def where(vm):
    return {h.label: vms[vm]["state"] for h in (A, B) for vms in [h.ps()] if vm in vms}


def ckpt_dir(label):
    """A path for a new checkpoint, inside this run's own work directory."""
    os.makedirs(os.path.join(WORK, "ckpt"), exist_ok=True)
    path = os.path.join(WORK, "ckpt", label)
    assert not os.path.exists(path), path
    return path


# --- cases ---------------------------------------------------------------------

CASES = {}
results = []


def case(fn):
    CASES[fn.__name__] = fn
    return fn


def check(label, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + label + (f"  [{detail}]" if detail and not cond else ""), flush=True)
    if not cond:
        raise AssertionError(label + (f": {detail}" if detail else ""))


@case
def run_exec_ps():
    """run, then exec's stdout, stderr and exit status, and ps; a run without --name."""
    vm = "e2e-exec"
    t = time.time()
    ip = A.run(vm)
    print(f"  run: {ip} in {(time.time() - t) * 1000:.0f} ms")
    check("ip from A's range", ip.startswith(args.net_a + "."), ip)
    vms = A.ps(all=False)
    check("ps: listed running with its address", vms.get(vm, {}).get("state") == "running" and vms[vm]["ip"] == ip, vms)
    check("ps: image", vms[vm]["template"] == args.template, vms[vm])
    code, out, err = A.exec(vm, "echo to-stdout; echo to-stderr >&2; exit 7")
    check("exec: stdout", out == "to-stdout\n", repr(out))
    check("exec: stderr", err == "to-stderr\n", repr(err))
    check("exec: exit status", code == 7, code)
    # Multi-MB output streamed whole through exec and checked on the host.
    code, out, err = A.exec(vm, "head -c 3000000 /dev/zero | tr '\\0' x")
    check("exec: 3 MB of pipeline output, all of it", code == 0 and out == "x" * 3000000,
          (code, len(out), err[-200:]))
    want = subprocess.run(["seq", "1", "800000"], capture_output=True, text=True).stdout
    sha = lambda b: hashlib.sha256(b.encode()).hexdigest()
    code, out, err = A.exec(vm, "seq 1 800000")
    check(f"exec: {len(want) / 1e6:.1f} MB of stdout intact", code == 0 and sha(out) == sha(want),
          (code, len(out), len(want), err[-200:]))
    code, out, err = A.exec(vm, "seq 1 800000 >&2")
    check("exec: the same on stderr", code == 0 and out == "" and sha(err) == sha(want), (code, len(out), len(err)))
    check("exec: guest has its address on eth0", ip in must(A, vm, "ip -4 -o addr show eth0"))
    check("exec: unknown vm fails", A.exec("e2e-no-such-vm", "true")[0] != 0)
    A.kill(vm)
    # Without --name, a made-up docker-style one (adjective_surname), as ps lists it.
    r = A.run_json()
    check("run without --name: a made-up name", re.fullmatch(r"[a-z]+_[a-z]+", r["name"]) is not None, r)
    check("run without --name: listed under it", A.ps(all=False).get(r["name"], {}).get("ip") == r["ip"], A.ps())
    check("kill: prints the name", A.kill(r["name"]).stdout == r["name"] + "\n")


@case
def pause_resume():
    """pause stops the guest and resume continues it: same process, clock right."""
    vm = "e2e-pause"
    A.run(vm)
    proc = marker(A, vm)
    paused_s = 4
    c0, t0 = count(A, vm), time.time()
    A.pause(vm)
    check("pause: ps says paused", A.ps()[vm]["state"] == "paused", A.ps()[vm])
    time.sleep(paused_s)
    r = A.resume(vm)
    check("resume: ps says running", A.ps()[vm]["state"] == "running", A.ps()[vm])
    print(f"  resume: {r.get('resume_ms')} ms")
    c1, t1 = count(A, vm), time.time()
    # The counter ticks at most every 50 ms. Had the guest run through the pause it would
    # have gained ~paused_s / 0.05; paused, only what the reads and RPCs around it took.
    print(f"  counter +{c1 - c0} over {t1 - t0:.1f} s with {paused_s} s paused")
    check("pause: guest stopped while paused", c1 - c0 < (t1 - t0 - paused_s) / 0.05 + paused_s / 0.05 / 2,
          (c0, c1, round(t1 - t0, 2)))
    # The guest runs again some time after the resume: polled until its counter moves, within a functional timeout.
    check("resume: guest process continues", wait_for(lambda: count(A, vm) > c1, 30), (c1, count(A, vm)))
    check("resume: same process (pid, start time)", marker_id(A, vm) == proc)
    err = wait_for(lambda: abs(clock_error(A, vm)) < 0.5, 5)
    check("resume: guest clock right after 3 s paused", err, clock_error(A, vm))
    A.kill(vm)


@case
def migrate():
    """live migration A -> B -> A: process, RAM and an open TCP connection survive."""
    vm = "e2e-migrate"
    ip = A.run(vm)
    m = fill(A, vm)
    proc = marker(A, vm)
    echo_server(A, vm, ip)
    conn = socket.create_connection((ip, 7000), timeout=10)
    check("tcp echo before", echo(conn, b"before\n"))
    for src, dst in ((A, B), (B, A)):
        r = src.migrate(vm, dst)
        print(f"  migrate {src.label} -> {dst.label}: downtime {r.get('downtime_ms')} ms")
        check(f"{src.label} -> {dst.label}: only on {dst.label}, running",
              wait_for(lambda: where(vm) == {dst.label: "running"}, 60), where(vm))
        check(f"{src.label} -> {dst.label}: same address", dst.ps()[vm]["ip"] == ip)
        check(f"{src.label} -> {dst.label}: TCP connection survived", echo(conn, b"after %s\n" % dst.label.encode()))
        check(f"{src.label} -> {dst.label}: RAM intact", md5(dst, vm) == m)
        check(f"{src.label} -> {dst.label}: same process", marker_id(dst, vm) == proc)
    conn.close()
    A.kill(vm)


@case
def checkpoint_restore():
    """checkpoint --stop and run --checkpoint; a keep-running checkpoint restored on B as a fork."""
    vm = "e2e-ckpt"
    ip = A.run(vm)
    m = fill(A, vm)
    proc = marker(A, vm)
    path = ckpt_dir(vm)
    r = A.checkpoint(vm, path, stop=True)
    print(f"  checkpoint --stop: {r.get('checkpoint_ms')} ms, {r.get('data_mib')} MiB")
    check("checkpoint: manifest written", os.path.exists(os.path.join(path, "manifest.json")))
    check("checkpoint --stop: VM gone from A", vm not in A.ps(), A.ps())
    # Its address is A's to give: B borrows it from A, and gives it back when the VM goes.
    r = B.restore(path)
    print(f"  restore: ready in {r.get('ready_ms')} ms")
    check("restore on B: borrows A's address", r.get("ip") == ip and B.ps().get(vm, {}).get("ip") == ip, r)
    B.kill(vm)
    def restore_home():
        try:
            return A.restore(path)
        except AssertionError:
            return None
    check("restore on A once B let it go", wait_for(restore_home, 10))
    check("restore: same name and address", A.ps().get(vm, {}).get("ip") == ip, A.ps())
    check("restore: RAM intact", md5(A, vm) == m)
    check("restore: same process", marker_id(A, vm) == proc)
    c1 = count(A, vm)
    check("restore: process runs on", wait_for(lambda: count(A, vm) > c1, 5))
    check("restore: guest clock right", wait_for(lambda: abs(clock_error(A, vm)) < 0.5, 5), clock_error(A, vm))
    # Keep-running checkpoint: the VM goes on; its copy restores as a second VM.
    path2 = ckpt_dir(vm + "-live")
    A.checkpoint(vm, path2)
    check("checkpoint --keep-running: still running", A.ps()[vm]["state"] == "running")
    must(A, vm, "echo changed > /tmp/after")
    # On B, whose address range the original's address is not from: A would hand it out again.
    fork = vm + "-fork"
    r = B.restore(path2, name=fork, ip="auto")
    check("fork: new address", r["ip"] != ip and B.ps()[fork]["ip"] == r["ip"], r)
    check("fork: RAM as at the checkpoint", md5(B, fork) == m)
    code, out, err = B.exec(fork, "test -e /tmp/after && echo present || echo absent")
    check("fork: later writes not in it", code == 0 and out.strip() == "absent", (code, out, err))
    check("fork: same process", marker_id(B, fork) == proc)
    A.kill(vm)
    B.kill(fork)
    shutil.rmtree(path, ignore_errors=True)
    shutil.rmtree(path2, ignore_errors=True)


@case
def suspend_resume():
    """stop (suspend) frees the VM's Firecracker; start brings back process and RAM; rm removes a stopped VM."""
    vm = "e2e-suspend"
    ip = A.run(vm)
    m = fill(A, vm)
    proc = marker(A, vm)
    res = vm_resources(ip)
    check("found the VM's Firecracker", res["pid"] in A.firecrackers(), res)
    r = A.suspend(vm)
    print(f"  suspend: {r.get('suspend_ms')} ms, {r.get('data_mib')} MiB on disk")
    check("stop: ps -a says suspended", A.ps()[vm]["state"] == "suspended", A.ps()[vm])
    check("stop: ps without -a leaves it out", vm not in A.ps(all=False), A.ps(all=False))
    check("stop: its Firecracker exited", wait_for(lambda: not os.path.exists(f"/proc/{res['pid']}"), 10), res)
    check("stop: exec refused", A.exec(vm, "true", timeout=60)[0] != 0)
    k = A.kill(vm, check=False)
    check("kill: a stopped VM is refused", k.returncode != 0 and f"vm {vm} is not running" in k.stderr
          and f"flexvm rm {vm}" in k.stderr, (k.returncode, k.stderr))
    check("kill: the stopped VM stays", A.ps().get(vm, {}).get("state") == "suspended", A.ps().get(vm))
    r = A.resume(vm)
    print(f"  start: ready in {r.get('ready_ms')} ms")
    check("start: running", A.ps()[vm]["state"] == "running")
    check("start: RAM intact", md5(A, vm) == m)
    check("start: same process", marker_id(A, vm) == proc)
    c1 = count(A, vm)
    check("start: process runs on", wait_for(lambda: count(A, vm) > c1, 5))
    r = A.rm(vm, check=False)
    check("rm: a running VM is refused", r.returncode != 0 and f"vm {vm} is running" in r.stderr, (r.returncode, r.stderr))
    A.suspend(vm)
    check("rm: removes the stopped VM", A.rm(vm).stdout == vm + "\n" and vm not in A.ps(), A.ps().get(vm))


@case
def kill_releases():
    """kill removes the VM and gives back its Firecracker, tap, route, cgroup and address."""
    vm = "e2e-kill"
    ip = A.run(vm)
    res = vm_resources(ip)
    check("found the VM's tap and Firecracker", res["tap"] and res["pid"], res)
    A.kill(vm)
    check("kill: not listed", vm not in A.ps())
    check("kill: its Firecracker exited", wait_for(lambda: not os.path.exists(f"/proc/{res['pid']}"), 10), res)
    check("kill: route gone", vm_resources(ip)["route"] == "", vm_resources(ip))
    taps = A.taps()
    check("kill: tap gone", wait_for(lambda: res["tap"] not in A.taps(), 10), taps)
    if res["cgroup"]:
        check("kill: cgroup gone", wait_for(lambda: not os.path.exists(res["cgroup"]), 10), res["cgroup"])
    check("kill: address free again", A.run(vm, ip=ip) == ip)
    A.kill(vm)
    check("kill: second kill of the name fails", A.kill(vm, check=False).returncode != 0)


# --- the image case's registry pull and its cache --------------------------------
# With --image-cache, the pulled blobs are kept there as an OCI layout of the image
# (oci/REF/), which later runs build from without the registry.
# CI keeps the directory in actions/cache; a cold cache pulls from the registry.


def image_ref():
    """(registry host, repository, tag) of --image, with Docker's defaults."""
    name, _, tag = args.image.rpartition(":") if ":" in args.image.rsplit("/", 1)[-1] else (args.image, "", "latest")
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host, repo = first, rest
    else:
        host, repo = "registry-1.docker.io", name if "/" in name else f"library/{name}"
    return ("registry-1.docker.io" if host in ("docker.io", "index.docker.io") else host), repo, tag


def image_dir():
    return os.path.join(args.image_cache, "oci", re.sub(r"[^A-Za-z0-9._-]", "_", args.image)) if args.image_cache else None


def image_layout():
    d = image_dir()
    return d if d and os.path.exists(os.path.join(d, "index.json")) else None


def image_digest(layout):
    return json.load(open(os.path.join(layout, "index.json")))["manifests"][0]["digest"]


MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, "
                  "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json")


def registry_get(path):
    """(status, headers, body) of GET /v2/REPO/PATH, with an anonymous bearer token if asked for one."""
    import urllib.error, urllib.parse, urllib.request
    host, repo, _ = image_ref()
    scheme = "http" if host.split(":")[0] in ("localhost", "127.0.0.1") else "https"
    url, auth = f"{scheme}://{host}/v2/{repo}/{path}", None
    for _ in range(2):
        req = urllib.request.Request(url, headers={"Accept": MANIFEST_TYPES, **({"Authorization": auth} if auth else {})})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.headers, resp.read(4 << 20)
        except urllib.error.HTTPError as e:
            if e.code != 401 or auth:
                return e.code, e.headers, e.read(300)
            params = dict(re.findall(r'(\w+)="([^"]*)"', e.headers.get("WWW-Authenticate", "")))
            q = urllib.parse.urlencode({k: v for k, v in params.items() if k in ("service", "scope")})
            with urllib.request.urlopen(f"{params.get('realm')}?{q}", timeout=30) as t:
                tok = json.load(t)
            auth = f"Bearer {tok.get('token') or tok.get('access_token')}"
    return 401, {}, b""


def retry_after():
    """Seconds the registry asks a client to wait now (Retry-After on a 429), or None."""
    try:
        status, headers, _ = registry_get(f"manifests/{image_ref()[2]}")
        v = headers.get("Retry-After") if status == 429 else None
        return min(int(v), 300) if v and v.isdigit() else None
    except Exception:
        return None


def pull_template(name, opts):
    """Builds the template from the registry. HTTP 429s are retried with longer and longer
    waits (or what Retry-After asks); a registry that stays rate limited fails as that."""
    waits = (15, 30, 60, 120)
    for i in range(len(waits) + 1):
        r = flexvm("pull", args.image, "--tag", name, *opts, timeout=600, check=False)
        if r.returncode == 0:
            return r
        if "HTTP 429" not in r.stderr:
            raise AssertionError(f"flexvm pull {args.image} exited {r.returncode}: {r.stderr.strip()}")
        if i == len(waits):
            break
        wait = retry_after() or waits[i]
        print(f"  registry rate limited (HTTP 429); retrying in {wait} s", flush=True)
        time.sleep(wait)
    raise AssertionError(f"registry rate-limited: {args.image} still answers HTTP 429 after {len(waits) + 1} tries "
                         f"(not a flexvm failure): {r.stderr.strip()[-300:]}")


def save_layout(stderr):
    """Keeps the pulled image as an OCI layout: its blobs, and its manifest fetched again by digest."""
    d = image_dir()
    m = re.search(r"^image: .* -> (sha256:[0-9a-f]{64})$", stderr, re.M)
    if not d or not m:
        return
    try:
        status, _, body = registry_get(f"manifests/{m.group(1)}")
        if status != 200 or "sha256:" + hashlib.sha256(body).hexdigest() != m.group(1):
            return print(f"  not caching the image: its manifest came back HTTP {status}")
        manifest = json.loads(body)
        tmp = d + ".new"
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(os.path.join(tmp, "blobs", "sha256"))
        for desc in [manifest["config"], *manifest["layers"]]:
            hexd = desc["digest"].split(":", 1)[1]
            shutil.copy(os.path.join(BUILD, "images", "blobs", "sha256", hexd), os.path.join(tmp, "blobs", "sha256", hexd))
        open(os.path.join(tmp, "blobs", "sha256", m.group(1).split(":", 1)[1]), "wb").write(body)
        json.dump({"imageLayoutVersion": "1.0.0"}, open(os.path.join(tmp, "oci-layout"), "w"))
        json.dump({"schemaVersion": 2, "manifests": [{"mediaType": manifest.get("mediaType", "application/vnd.oci.image.manifest.v1+json"),
                                                      "digest": m.group(1), "size": len(body)}]},
                  open(os.path.join(tmp, "index.json"), "w"))
        shutil.rmtree(d, ignore_errors=True)
        os.rename(tmp, d)
        print(f"  cached {args.image} ({m.group(1)}) as an OCI layout")
    except Exception as e:
        print(f"  not caching the image: {e}")


@case
def image_template():
    """pull: a container image becomes a template whose VMs run its entrypoint."""
    if args.no_image:
        print("  skipped (--no-image)")
        return
    name = args.template + "-img"
    t = time.time()
    cmd = ["sh", "-c", "mkdir -p /tmp/www && echo hello-from-image > /tmp/www/index.html && "
                       "echo app-started && exec httpd -f -p 8080 -h /tmp/www"]
    opts = ["--vcpus", "2", "--max", "2048", "--cmd", json.dumps(cmd)]
    layout = image_layout()
    if layout:
        # Cached (CI): the image as an OCI layout of the blobs an earlier pull fetched. No
        # registry; flexvm checks every blob against its digest as it would after a pull.
        flexvm("pull", layout, "--tag", name, *opts, timeout=600)
        print(f"  template from the cached {args.image} ({image_digest(layout)}): {time.time() - t:.1f} s")
    else:
        r = pull_template(name, opts)
        print(f"  template from {args.image}, pulled: {time.time() - t:.1f} s")
        save_layout(r.stderr)
    vm = "e2e-img"
    ip = A.run(vm, template=name)
    check("image vm: app's output in logs", wait_for(lambda: "\napp-started\n" in A.logs(vm), 15), A.logs(vm))
    code, out, err = A.exec(vm, "cat /etc/os-release 2>/dev/null; busybox | head -1")
    check("image vm: image's userland", code == 0 and "BusyBox" in out, out + err)

    def get(path):
        """(status code, body) of an HTTP/1.0 GET from the host, or None."""
        try:
            with socket.create_connection((ip, 8080), timeout=2) as s:
                s.sendall(b"GET %s HTTP/1.0\r\n\r\n" % path)
                data = b""
                while d := s.recv(65536):
                    data += d
        except OSError:
            return None
        head, _, body = data.partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3}) ", head)
        return (int(m.group(1)), body) if m else None
    got = wait_for(lambda: get(b"/index.html"), 15)
    check("image vm: app answers 200 with the file", got == (200, b"hello-from-image\n"),
          (got, A.exec(vm, "ps; netstat -ltn")[1:], A.logs(vm)))
    missing = get(b"/missing")
    check("image vm: 404 for a missing file", missing is not None and missing[0] == 404, missing)
    A.kill(vm)


@case
def faults():
    """The selected scripts/faults.py scenarios against the same two hosts."""
    if not args.faults.split():
        print("  none selected")
        return
    # Growth needs a template that starts with little plugged.
    env = {**os.environ, "COW_GROW_TEMPLATE": GROW, "PLUG_TEMPLATE": GROW, "APP_TEMPLATE": APP,
           "SHRINK_TEMPLATE": args.template, "EVICT_TEMPLATE": args.template}
    # The app-log template is built from the cached image when there is one (CI), not pulled.
    layout = image_layout()
    image = ["--image", layout] if layout else ["--image", args.image]
    # Listeners of this lane's hosts (started by the worker), or, for the scenarios that restart them,
    # faults.py's own on the same addresses and directories (BUILD links this run's artifacts and templates).
    listeners = ["--state", BUILD] if args.own_listeners else ["--no-listeners"]
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "faults.py"), "--a", A.addr, "--b", B.addr,
                        "--a-state", A.state_dir, "--a-run", A.run_dir, "--b-state", B.state_dir, "--b-run", B.run_dir,
                        "--a-listen-log", A.log, "--b-listen-log", B.log,
                        "--a-ips", f"{A.net}.2-{A.net}.60", "--b-ips", f"{B.net}.2-{B.net}.60",
                        *listeners, *(["--no-skips"] if args.no_skips else []), "--bin", BIN, "--template", args.template,
                        "--ckpt-dir", os.path.join(WORK, "faults-ckpt"), *image, *args.faults.split()], timeout=1800, env=env)
    check("faults.py: no failures", r.returncode == 0, f"exit {r.returncode}")


# --- main ------------------------------------------------------------------------

# Directories of this run's own, shared with nothing else: run directories under /run
# (tmpfs), state and checkpoints under /var/tmp (suspend needs a disk).
RUN = tempfile.mkdtemp(prefix=args.tag + "-", dir=None if args.selftest else "/run")
WORK = tempfile.mkdtemp(prefix=args.tag + "-", dir=None if args.selftest else "/var/tmp")
# Templates of this run's own (a worker's are its run's): never another's `ci` or the shared image
# cache. On tmpfs: building one writes out all of the guest's memory and reads it back to hash it,
# which a CI runner's disk makes slow; what stays (sparse) is small.
TEMPLATES = args.templates or tempfile.mkdtemp(prefix=args.tag + "-",
                                            dir="/dev/shm" if not args.selftest and os.path.isdir("/dev/shm") else WORK)


def shared_state(state):
    """A state directory whose artifacts and templates are this run's."""
    os.makedirs(state, exist_ok=True)
    for name, target in (("artifacts", ARTIFACTS), ("templates", TEMPLATES)):
        if not os.path.lexists(os.path.join(state, name)):
            os.symlink(target, os.path.join(state, name))


# Where templates are built (and images pulled, unpacked in its staging/).
BUILD = os.path.join(WORK, "build")
# The OCI layout the cases' templates are pulled from.
TEST_IMAGE = os.path.abspath(args.test_image) if args.test_image else os.path.join(WORK, "test-image")
shared_state(BUILD)
A = Host("a", args.port_a, args.port_a + 1, args.net_a)
GROW = args.template + "-grow"
# The app_log and bad_app_log scenarios' template, built once with the others (lanes that each built
# it on first use would replace it under one another's VMs). Its app as scripts/faults.py's app_template.
APP = args.template + "-applog"
# The template's ceiling: the heavy shard's guests write 1.5 GiB, shrink_stall needs 4 GiB at the start and
# 4 GiB more to grow into, evict_grower's grow past 3 GiB (with the default 4 GiB plugged, free until touched).
TEMPLATE_MAX = "10240" if args.shard == "heavy" else "2048"
APP_FAULTS = ("app_log", "bad_app_log")
APP_OPTS = ["--vcpus", "2", "--max", "2048", "--cmd", json.dumps(
    ["sh", "-c", "head -c 8000000 /dev/zero | tr '\\0' x; echo; i=0; while :; do echo applog-$i; i=$((i+1)); sleep 0.05; done"])]
B = Host("b", args.port_a + 1, args.port_a, args.net_b)


def worker():
    """Runs the given cases against this lane's two hosts; writes their results to --results."""
    failed, clean = [], False
    try:
        # Scenarios that restart the listeners run with faults.py's own (--own-listeners).
        if not args.own_listeners:
            A.start()
            B.start()
        for c in args.cases:
            print(f"--- {c}: {CASES[c].__doc__.strip().splitlines()[0]}", flush=True)
            t = time.time()
            try:
                CASES[c]()
                results.append((c, "PASS", time.time() - t))
            except Exception as e:
                traceback.print_exc()
                results.append((c, "FAIL", time.time() - t))
                failed.append(c)
                # Free the VMs this script made, so the next case starts clean; a
                # failure here must not stop the other cases.
                try:
                    for h in (A, B):
                        for vm in sorted(h.vms & set(h.ps())):
                            h.rm(vm, force=True, check=False)
                except Exception:
                    traceback.print_exc()
        clean = True
    finally:
        # Logs on any failure or interruption (a cancelled run too); teardown whatever that does.
        if failed or not clean:
            for h in (A, B):
                try:
                    h.save_logs()
                except Exception as e:
                    print(f"saving {h.label}'s logs: {e}", flush=True)
        t = time.time()
        problems = []
        # What a SIGKILLed VM process leaves (its tap, its name) is collected by a sweep, which
        # some process on its host runs every 30 s: after scenarios (which kill VM processes
        # so), sweep each host now.
        for h in (A, B):
            try:
                if args.own_listeners and os.path.isdir(h.state_dir):
                    h.prefix = h.info()["derived"]["prefix"]
                if "faults" in args.cases and os.path.isdir(h.state_dir):
                    h.cli("debug", "gc")
            except Exception as e:
                problems.append(f"host {h.label}: collecting garbage: {e}")
        for h in (A, B):
            try:
                h.stop()
            except Exception as e:
                problems.append(str(e))
        wait_for(lambda: not (A.leftovers() + B.leftovers()), 15)
        problems += [f"left behind: {x}" for x in A.leftovers() + B.leftovers()]
        results.append(("hosts stop cleanly, nothing left", "FAIL" if problems else "PASS", time.time() - t))
        if problems:
            failed.append("teardown")
            print("\n".join(problems))
        if args.results:
            json.dump(results, open(args.results, "w"))
    return 1 if failed else 0


# About how many seconds each case and scenario takes on a CI runner (4 lanes; the slowest of a few
# runs, as e2e.py's summary prints them): --split balances by these, the long ones start first, and
# the short ones go in batches of about BATCH_S (each batch is a worker, with hosts of its own).
# Unlisted ones count as 2 s.
COST = {"faults/exec_background": 110, "faults/reboot": 40, "faults/mem_refused_fill": 92, "faults/arrival_overtaken": 78,
        "faults/cow_grow": 65, "faults/reconcile_kill": 64, "faults/plug_race": 45, "faults/guest_hang": 44,
        "faults/exec_pause_grace": 42, "faults/route_abort": 35, "faults/unplug_collapsed": 30,
        "faults/arrival_grew": 25, "faults/pause_resume": 24, "faults/evict_latency": 25, "faults/mem_high": 25, "faults/target_killed": 25,
        "faults/resume_pull_lock": 23, "faults/mem_high_migrate": 22, "faults/cow_collapsed": 21,
        "faults/ckpt_incremental": 20, "faults/arrival_grew_admitted": 19, "faults/held_restore_frozen": 18,
        "faults/mem_refused_headroom": 18, "faults/standby_stalled": 18, "faults/pages_blip": 16,
        "faults/resume_suspending": 16, "image_template": 15, "faults/arrival_flood": 14, "faults/page_conns": 14,
        "faults/page_refusals": 14, "faults/abort_superseded": 13, "faults/cow_rescue_fail": 13, "faults/collapse_abort": 13,
        "faults/arrival_log": 12, "faults/mem_high_evict": 12, "faults/pages_dead_restore": 12,
        "faults/start_admission": 12, "faults/cow_wp_race": 11, "faults/forged_pages": 11,
        "faults/standby_admission": 11, "faults/wildcard_listen": 11, "faults/arrival_abort_route": 10,
        "faults/evict_skips_cmd": 10, "faults/listen_trickle": 10, "faults/pause_lost": 10, "faults/cow_exact": 9,
        "faults/fetch_tail_enomem": 9, "faults/plug_storm": 9, "faults/unknown": 9, "faults/fetch_enomem_stuck": 8,
        "faults/rx_stall": 8, "faults/signals": 8, "faults/spoof_filter": 8, "faults/suspend_overlap": 8,
        "faults/app_log": 7, "faults/checkpoint_corrupt": 7, "faults/ckpt_failed_stop": 7, "faults/ckpt_hot": 7,
        "faults/warm_ready": 7, "faults/guest_calls": 7, "faults/resume_slow_guest": 7, "faults/suspend_cmd": 7, "faults/suspend_resume": 7,
        "faults/bad_app_log": 6, "faults/checkpoint_hotplug": 6, "faults/exec_race": 6, "faults/fc_died_busy": 6,
        "faults/pause_cmd_start": 6, "faults/reconcile_announce": 6, "faults/resume_unpause_fail": 6,
        "faults/same_host_hold_route_fail": 6, "faults/standby_lock_timeout": 6, "faults/standby_refill_race": 6,
        "faults/checkpoint_fork": 5, "faults/checkpoint_restore": 5, "faults/ckpt_backlog": 5,
        "faults/ckpt_dir_moved": 5, "faults/ckpt_rearm": 5, "faults/resume_failures": 5, "faults/resume_kill": 5,
        "faults/source_unpublished": 5, "pause_resume": 5, "faults/bad_preload": 4, "faults/basic": 4,
        "faults/cow_abort": 4, "faults/cow_crash": 4, "faults/ctrl_z_long_op": 4, "faults/handoff_superseded": 4,
        "faults/lost_ack": 4, "faults/meminfo_unreadable": 4, "faults/prepare_fail": 4, "faults/prepared_retry": 4,
        "faults/pull_enomem": 4, "faults/refused": 4, "faults/resume_mark_fails": 4, "faults/resume_readdress_fail": 4,
        "faults/route": 4, "faults/same_host_backlog": 4, "faults/same_host_bulk_tcp": 4, "faults/same_host_flood": 4,
        "faults/same_host_slow_route": 4, "faults/slow_preload": 4, "faults/suspend_killed": 4,
        "faults/suspend_slow_cmd": 4, "faults/unlend_retry": 4, "faults/ckpt_ancestor_corrupt": 3,
        "faults/ckpt_packet_hold": 3, "faults/same_host_order": 3, "faults/suspend_died": 3}
BATCH_S = 20
SELFTEST_SKIP_NAME = "wildcard_listen"


def lanes():
    """(port, net A, net B) of each lane."""
    if args.lanes:
        return [(int(port), a, b) for port, a, b in (lane.split(":") for lane in args.lanes.split())]
    bump = lambda net, i: ".".join(str(int(o) + 2 * i) if k == 1 else o for k, o in enumerate(net.split(".")))
    return [(args.port_a + 2 * i, bump(args.net_a, i), bump(args.net_b, i)) for i in range(max(1, args.jobs))]


def main():
    assert args.selftest or os.geteuid() == 0, "run as root"
    if args.worker:
        return worker()
    selected = args.cases or list(CASES)
    for c in selected:
        assert c in CASES, f"unknown case {c}; have {', '.join(CASES)}"
    scenarios = args.faults.split() if "faults" in selected else []
    # (name, templates it needs, cost): the cases, and each scenario on its own.
    work = [(c, set() if c == "image_template" else {args.template}, COST.get(c, 2)) for c in selected if c != "faults"]
    # Growth (and checkpoint_hotplug, unplug_collapsed and mem_refused_fill, which need room to plug) runs on GROW; fc_prepare needs a second template to mismatch with.
    work += [(f"faults/{s}", ({args.template, GROW} if s in ("cow_grow", "plug_race", "plug_storm", "checkpoint_hotplug", "unplug_collapsed", "fc_prepare", "mem_refused_fill") else {args.template})
              | ({APP} if s in APP_FAULTS else set()),
              COST.get(f"faults/{s}", 2)) for s in scenarios]
    work.sort(key=lambda w: (-w[2], w[0]))
    if args.split:
        # Longest first, each to the part with the least so far: every split computes the same parts.
        i, n = map(int, args.split.split("/"))
        assert 1 <= i <= n, f"--split {args.split}: want I/N with 1 <= I <= N"
        parts = [[] for _ in range(n)]
        for w in work:
            min(parts, key=lambda p: sum(x[2] for x in p)).append(w)
        work = parts[i - 1]
    needed = set().union(*(w[1] for w in work))
    scheduled = list(work)
    lock, out_lock = threading.Condition(), threading.Lock()
    built, broken, procs, summary = set(), set(), [], []
    started = time.time()

    def say(line):
        with out_lock:
            print(line, flush=True)

    def build(name, *extra, image=False):
        t = time.time()
        try:
            layout = image_layout()
            if args.selftest:
                r = None
            elif not image:
                test_image.wait()
                if not test_image.ok:
                    raise AssertionError("no test image")
                r = flexvm("pull", TEST_IMAGE, "--tag", name, *extra, timeout=600)
            else:
                # From the cached image (CI), else pulled, its HTTP 429s retried.
                r = flexvm("pull", layout, "--tag", name, *extra, timeout=600) if layout else pull_template(name, list(extra))
            out, ok = (r.stdout + r.stderr).strip() if r else "(selftest)", True
        except Exception as e:
            out, ok = str(e), False
        with lock:
            (built if ok else broken).add(name)
            summary.append((f"template {name}", "PASS" if ok else "FAIL", time.time() - t, "-"))
            lock.notify_all()
        say(f"{'PASS' if ok else 'FAIL'} template {name} ({time.time() - t:.1f} s): {out}")

    def take():
        """The next batch whose templates are built; None once there is no more."""
        with lock:
            while True:
                for w in [w for w in work if w[1] & broken]:
                    work.remove(w)
                    summary.append((w[0], "FAIL", 0.0, "-"))
                    say(f"FAIL {w[0]}: its template failed")
                ready = [w for w in work if w[1] <= built]
                if ready or not work:
                    break
                lock.wait()
            if not ready:
                return None
            # A batch's worker starts its hosts' listeners, or leaves them to faults.py: never both.
            batch = [ready[0]]
            for w in reversed([w for w in ready[1:] if own(w[0]) == own(ready[0][0])]):
                if sum(b[2] for b in batch) + w[2] > BATCH_S:
                    break
                batch.append(w)
            for w in batch:
                work.remove(w)
            return [w[0] for w in batch]

    spawned = []

    def own(name):
        return name.startswith("faults/") and name.split("/", 1)[1] in LISTENER_FAULTS

    def spawn(cmd, cases, scens, res):
        """A worker process; under --selftest a fake one, and the second spawn fails as with EMFILE."""
        if args.selftest:
            with lock:
                spawned.append((cases, scens))
                if len(spawned) == 2:
                    raise OSError(24, "Too many open files (selftest)")
            # SELFTEST_SKIP's scenario says it skipped, as faults.py does.
            fake = ("import json, sys; c, s, res = json.loads(sys.argv[1]); "
                    f"[print(f'scenario {{x}}: ' + ('SKIPPED (selftest)' if x == {SELFTEST_SKIP_NAME!r} else 'ok') + ' in 0.0 s') for x in s]; "
                    "json.dump([[x, 'PASS', 0.0] for x in c] + ([['faults', 'PASS', 0.0]] if s else []), open(res, 'w'))")
            cmd = [sys.executable, "-c", fake, json.dumps([cases, scens, res])]
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True)

    def run_batch(i, label, batch, port, net_a, net_b):
        """Runs one batch in a worker; returns its results."""
        cases = [c for c in batch if not c.startswith("faults/")]
        scens = [c.split("/", 1)[1] for c in batch if c.startswith("faults/")]
        res = os.path.join(WORK, f"results-{label}.json")
        cmd = [sys.executable, "-u", os.path.abspath(__file__), "--worker", "--lane", str(i), "--bin", BIN,
               "--state", args.state, "--log-dir", os.path.join(args.log_dir, f"lane-{label}"),
               "--port-a", str(port), "--net-a", net_a, "--net-b", net_b, "--tag", args.tag,
               "--template", args.template, "--templates", TEMPLATES, "--image", args.image, "--results", res,
               *(["--image-cache", os.path.abspath(args.image_cache)] if args.image_cache else []),
               "--faults", " ".join(scens), *(["--no-image"] if args.no_image else []),
               *(["--own-listeners"] if any(own(c) for c in batch) else []), *(["--no-skips"] if args.no_skips else []),
               *cases, *(["faults"] if scens else [])]
        say(f"[{label}] {' '.join(batch)}")
        t = time.time()
        p = spawn(cmd, cases, scens, res)
        with lock:
            procs.append(p)
        got = []
        for line in p.stdout:
            say(f"[{label}] {line.rstrip()}")
            m = re.match(r"scenario (\S+): (ok|FAILED|SKIPPED)(?: \(.*\))? in ([\d.]+) s$", line.strip())
            if m:
                st = {"ok": "PASS", "FAILED": "FAIL", "SKIPPED": "SKIP"}[m.group(2)]
                got.append((f"faults/{m.group(1)}", st, float(m.group(3)), label))
        code = p.wait()
        try:
            # The faults case fails for a skip under --no-skips, which its scenario's own line says already.
            skip_only = args.no_skips and any(g[1] == "SKIP" for g in got) and not any(g[1] == "FAIL" for g in got)
            got += [(c, st, d, label) for c, st, d in json.load(open(res)) if c != "faults" or (st == "FAIL" and not skip_only)]
        except (OSError, ValueError):
            got.append((f"worker {label}", "FAIL", time.time() - t, label))
        if code != 0 and not any(g[1] == "FAIL" for g in got):
            got.append((f"worker {label} (exit {code})", "FAIL", time.time() - t, label))
        return got

    def lane(i, port, net_a, net_b):
        n = 0
        while (batch := take()) is not None:
            n += 1
            label = f"{i}.{n}"
            try:
                got = run_batch(i, label, batch, port, net_a, net_b)
            except Exception as e:
                # Whatever went wrong, the batch failed: none of it may pass unrun.
                say(f"[{label}] FAIL batch: {type(e).__name__}: {e}")
                got = [(c, "FAIL", 0.0, label) for c in batch]
            with lock:
                summary.extend(got)

    # The test image, made once for the templates pulled from it (`build`).
    test_image = threading.Event()
    test_image.ok = False

    def make_test_image():
        t = time.time()
        try:
            if not args.selftest:
                r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "test-image.py"), "--state", args.state, TEST_IMAGE],
                                   capture_output=True, text=True, timeout=900)
                if r.returncode != 0:
                    raise AssertionError(f"scripts/test-image.py exited {r.returncode}: {(r.stdout + r.stderr).strip()[-2000:]}")
                say(f"test image ({time.time() - t:.1f} s): {r.stdout.strip()}")
            test_image.ok = True
        except Exception as e:
            say(f"FAIL test image ({time.time() - t:.1f} s): {e}")
        test_image.set()

    # The templates this selection uses, built side by side.
    if args.template in needed or GROW in needed:
        threading.Thread(target=make_test_image, daemon=True).start()
    else:
        test_image.set()
    builders = [threading.Thread(target=build, args=(args.template, "--vcpus", "2", "--max", TEMPLATE_MAX))] if args.template in needed else []
    if GROW in needed:
        # A larger ceiling with little plugged at the start: VMs must grow.
        builders.append(threading.Thread(target=build, args=(GROW, "--vcpus", "2", "--max", "6144", "--plug", "128")))
    if APP in needed:
        builders.append(threading.Thread(target=build, args=(APP, *APP_OPTS), kwargs={"image": True}))
    runners = [threading.Thread(target=lane, args=(i, *l), daemon=True) for i, l in enumerate(lanes())]
    try:
        for t in builders + runners:
            t.start()
        for t in builders + runners:
            t.join()
    finally:
        # Interrupted: the workers tear down what they made.
        with lock:
            for p in procs:
                if p.poll() is None:
                    p.send_signal(signal.SIGINT)
        for p in procs:
            try:
                p.wait(60)
            except subprocess.TimeoutExpired:
                p.kill()
    # Every case and scenario has a result, or it failed (a lane that died, say).
    done = {r[0] for r in summary}
    summary.extend((name, "FAIL", 0.0, "not run") for name, _, _ in scheduled if name not in done)
    summary.sort(key=lambda r: -r[2])
    skipped = [r for r in summary if r[1] == "SKIP"]
    failed = [r for r in summary if r[1] == "FAIL" or (r[1] == "SKIP" and args.no_skips)]
    print("\n" + "\n".join(f"{s} {c} ({d:.1f} s, batch {b})" for c, s, d, b in summary))
    print(f"{len([r for r in summary if r[1] == 'PASS'])} passed, {len(skipped)} skipped{' (failures: --no-skips)' if skipped and args.no_skips else ''}, {len([r for r in summary if r[1] == 'FAIL'])} failed "
          f"in {time.time() - started:.0f} s ({sum(r[2] for r in summary):.0f} s of work in {len(lanes())} lanes)")
    if args.selftest:
        # The second batch could not be spawned: exactly its cases and scenarios fail, the rest pass.
        bad = sorted(r[0] for r in failed)
        want = sorted(spawned[1][0] + [f"faults/{x}" for x in spawned[1][1]]) if len(spawned) > 1 else ["(no second batch)"]
        # Skipped, unless its batch was the one that could not be spawned.
        want_skip = [f"faults/{SELFTEST_SKIP_NAME}"] if len(spawned) > 1 and SELFTEST_SKIP_NAME not in spawned[1][1] else []
        print(f"selftest: failed {bad}, expected {want}; skipped {sorted(r[0] for r in skipped)}, expected {want_skip}")
        mixed = [b for b in spawned if len({s in LISTENER_FAULTS for s in b[1]}) > 1]
        print(f"selftest: batches mixing listener-owning scenarios with others: {mixed}")
        return 0 if (bad == want and len(summary) == len(scheduled) + len(builders) and not mixed
                     and sorted(r[0] for r in skipped) == want_skip) else 1
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
        shutil.rmtree(RUN, ignore_errors=True)
        if not args.templates:
            shutil.rmtree(TEMPLATES, ignore_errors=True)
    sys.exit(code)
