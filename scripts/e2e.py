#!/usr/bin/env python3
"""End-to-end checks of flexvm's user-facing commands on one KVM host, as CI
runs them. Run as root, after building flexvm, the patched Firecracker, the
guest kernel and the rootfs (see README.md and .github/workflows/ci.yml).

It builds a template, starts two flexvm hosts on loopback (A and B: their
own ports, run directories, state directories and VM address ranges), and runs
each case below against them with fresh VMs. It touches only what it created:
its own processes, taps, cgroups and directories.

usage: sudo scripts/e2e.py [--bin FLEXVM] [--artifacts DIR] [--log-dir DIR]
                           [--port-a N] [--net-a A.B.C] [--net-b A.B.C]
                           [--image REF | --no-image] [--faults "SCENARIO ..."]
                           [CASE ...]
"""
import argparse, glob, hashlib, json, os, re, shutil, signal, socket, subprocess, sys, tempfile, time, traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

p = argparse.ArgumentParser(usage=__doc__)
p.add_argument("--bin", default=os.path.join(ROOT, "target", "release", "flexvm"))
p.add_argument("--artifacts", default=os.path.join(ROOT, "artifacts"))
p.add_argument("--log-dir", default="/tmp/fvci-logs", help="daemon and Firecracker logs end up here")
p.add_argument("--port-a", type=int, default=7140, help="host A listens here, host B on the next port")
p.add_argument("--net-a", default="10.140.0", help="host A's VM addresses (.2-.60); B uses --net-b")
p.add_argument("--net-b", default="10.141.0")
p.add_argument("--template", default="ci", help="name of the template the cases build and use")
p.add_argument("--image", default="public.ecr.aws/docker/library/busybox:1.36",
               help="container image for the image-template case")
p.add_argument("--no-image", action="store_true", help="skip the image-template case (needs registry access)")
# The scripts/faults.py scenarios that fit CI time (~2.5 min here): migration failure paths, checkpoint
# corruption, copy-on-write exactness, held packets and devices. Left out: the ones that restart a daemon
# (this script owns them), slow or heavy ones (pages_dead, quiet_source, guest_hang, cow_reports_held), and
# guest_calls: on a 4-vCPU hosted runner an exec started on the source as the VM leaves fails with
# "no vm named" instead of following it to the target (passes on a fast host).
FAULTS = ("basic route lost_ack unknown refused pages_blip pages_dead_restore prepared_retry resume_kill exec_race "
          "checkpoint_fork checkpoint_corrupt held_restore_frozen cow_exact cow_abort ckpt_incremental "
          "ckpt_failed_stop ckpt_rearm prepare_fail fc_prepare slow_preload ckpt_packet_hold")
p.add_argument("--faults", default=FAULTS, help="scripts/faults.py scenarios to run against the two hosts ('' for none)")
p.add_argument("cases", nargs="*", help="cases to run (default: all)")
args = p.parse_args()
BIN = os.path.abspath(args.bin)
ARTIFACTS = os.path.abspath(args.artifacts)
os.makedirs(args.log_dir, exist_ok=True)


# --- CLI wrapper ---------------------------------------------------------------
# Everything that knows how flexvm is driven lives in this section; the cases
# below only call these methods. Today a host is a daemon and every command an
# RPC through the CLI. With one `flexvm run` process per VM (#85) start/stop
# become the migration listener, `run` spawns the VM's process, and pause /
# resume / suspend / kill turn into signals to it (SIGTSTP / SIGCONT / SIGTERM /
# SIGINT).


def flexvm(*argv, timeout=180, check=True, env=None):
    """Runs the flexvm CLI; returns the CompletedProcess."""
    r = subprocess.run([BIN, "--artifacts", ARTIFACTS, *argv], capture_output=True, text=True, timeout=timeout,
                       env=env)
    if check and r.returncode != 0:
        raise AssertionError(f"flexvm {' '.join(argv)} exited {r.returncode}: {r.stderr.strip()}")
    return r


def template(name, *extra, timeout=600):
    """Builds a template (`flexvm template`); returns the CLI's output."""
    return flexvm("template", name, *extra, timeout=timeout).stdout


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


class Host:
    def __init__(self, label, port, peer_port, net):
        self.label, self.addr = label, f"127.0.0.1:{port}"
        self.peer = f"127.0.0.1:{peer_port}"
        self.port, self.net = port, net
        # Inside this run's own fresh directories (see main); the daemon creates them.
        self.run_dir = os.path.join(RUN, label)
        self.state_dir = os.path.join(WORK, f"{label}-state")
        self.log = os.path.join(args.log_dir, f"daemon-{label}.log")
        self.proc = None
        self.vms = set()  # names of the VMs this script created here or moved here

    # lifecycle of the host itself
    def start(self):
        if listener_inode(self.port) is not None:
            raise AssertionError(f"port {self.port} is in use; pick other ports with --port-a")
        cmd = [BIN, "--artifacts", ARTIFACTS, "daemon", "--listen", self.addr, "--peer", self.peer,
               "--run", self.run_dir, "--state-dir", self.state_dir, "--vm-ips", f"{self.net}.2-{self.net}.60",
               "--hot", "1", "--pool", "1", "--reserve", "256"]
        # FLEXVM_FAULTS lets scripts/faults.py inject failures; it changes nothing otherwise.
        self.proc = subprocess.Popen(cmd, stdout=open(self.log, "a"), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     env={**os.environ, "FLEXVM_FAULTS": "1"}, start_new_session=True)
        # Up once our own child holds the listening socket and answers on it.
        deadline = time.time() + 30
        while not (owns_socket(self.proc.pid, listener_inode(self.port))
                   and flexvm("--host", self.addr, "ls", check=False).returncode == 0):
            if self.proc.poll() is not None or time.time() > deadline:
                raise AssertionError(f"host {self.label} did not come up; see {self.log}")
            time.sleep(0.2)

    def stop(self, timeout=60):
        """SIGTERM and wait; raises if it died early, had to be killed or exited with an error."""
        if not self.proc:
            return
        if self.proc.poll() is not None:
            raise AssertionError(f"host {self.label} died early (exit {self.proc.returncode}); see {self.log}")
        self.proc.send_signal(signal.SIGTERM)
        try:
            code = self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            raise AssertionError(f"host {self.label} did not stop within {timeout} s; killed it")
        if code != 0:
            raise AssertionError(f"host {self.label} exited {code} on SIGTERM; see {self.log}")

    def cli(self, *argv, **kw):
        return flexvm("--host", self.addr, *argv, **kw)

    # VM commands
    def run(self, vm, template=None, ip=None):
        """Starts a VM; returns its address."""
        extra = (["--template", template or args.template]) + (["--ip", ip] if ip else [])
        self.vms.add(vm)
        return json.loads(self.cli("run", vm, *extra).stdout)["ip"]

    def exec(self, vm, cmd, timeout=120):
        """Runs a shell command in the VM; returns (exit code, stdout, stderr)."""
        r = self.cli("exec", vm, cmd, check=False, timeout=timeout)
        return r.returncode, r.stdout, r.stderr

    def ls(self):
        """{name: {"ip", "template", "state"}} from `flexvm ls`."""
        rows = self.cli("ls").stdout.splitlines()[1:]
        return {f[0]: {"ip": f[1], "template": f[2], "state": f[3]} for f in (r.split() for r in rows) if len(f) >= 4}

    def pause(self, vm):
        return json.loads(self.cli("pause", vm).stdout)

    def resume(self, vm):
        return json.loads(self.cli("resume", vm).stdout)

    def suspend(self, vm):
        return json.loads(self.cli("suspend", vm).stdout)

    def kill(self, vm, check=True):
        return self.cli("kill", vm, check=check)

    def checkpoint(self, vm, path, stop=False, incremental=False):
        extra = (["--stop"] if stop else []) + (["--incremental"] if incremental else [])
        return json.loads(self.cli("checkpoint", vm, path, *extra).stdout)

    def restore(self, path, name=None, ip=None):
        extra = (["--name", name] if name else []) + (["--ip", ip] if ip else [])
        r = json.loads(self.cli("restore", path, *extra).stdout)
        self.vms.add(r["name"])
        return r

    def migrate(self, vm, to):
        to.vms.add(vm)
        return json.loads(self.cli("migrate", vm, "--to", to.addr).stdout)

    def logs(self, vm):
        return self.cli("logs", vm).stdout

    # what the host holds on this machine, to check that it gives it back
    def firecrackers(self):
        """pid -> Firecracker directory, for Firecrackers logging into our run directory."""
        out = {}
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                if open(f"/proc/{pid}/comm").read().strip() != "firecracker":
                    continue
                log = os.readlink(f"/proc/{pid}/fd/1")
            except OSError:
                continue
            if log.startswith(self.run_dir + "/"):
                out[int(pid)] = os.path.dirname(log)
        return out

    def taps(self):
        links = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True).stdout
        names = [l.split(": ")[1].split("@")[0] for l in links.splitlines()]
        return [n for n in names if n.startswith(f"fv{self.port}")]

    def cgroups(self):
        return glob.glob(f"/sys/fs/cgroup/flexvm/127_0_0_1_{self.port}_ns*")

    def leftovers(self):
        """Everything of this host's still on the machine (expected empty once it stopped)."""
        left = [f"firecracker pid {p}" for p in self.firecrackers()] + [f"tap {t}" for t in self.taps()]
        left += [f"cgroup {c}" for c in self.cgroups()]
        left += [f"dir {d}" for d in (self.run_dir,) if os.path.exists(d)]
        if self.proc and self.proc.poll() is None:
            left.append(f"daemon pid {self.proc.pid}")
        return left

    def save_logs(self):
        """Copies the Firecracker logs out of the run directory (stopping removes it)."""
        for log in glob.glob(f"{self.run_dir}/**/*.log", recursive=True):
            dest = os.path.join(args.log_dir, f"fc-{self.label}", os.path.relpath(log, self.run_dir))
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
        rel = open(f"/proc/{pid}/cgroup").read().strip().split("::", 1)[-1]
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
    return {h.label: ls[vm]["state"] for h in (A, B) for ls in [h.ls()] if vm in ls}


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
def run_exec_ls():
    """run, then exec's stdout, stderr and exit status, and ls."""
    vm = "e2e-exec"
    t = time.time()
    ip = A.run(vm)
    print(f"  run: {ip} in {(time.time() - t) * 1000:.0f} ms")
    check("ip from A's range", ip.startswith(args.net_a + "."), ip)
    ls = A.ls()
    check("ls: listed running with its address", ls.get(vm, {}).get("state") == "running" and ls[vm]["ip"] == ip, ls)
    check("ls: template", ls[vm]["template"] == args.template, ls[vm])
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


@case
def pause_resume():
    """pause stops the guest and resume continues it: same process, clock right."""
    vm = "e2e-pause"
    A.run(vm)
    proc = marker(A, vm)
    paused_s = 4
    c0, t0 = count(A, vm), time.time()
    A.pause(vm)
    check("pause: ls says paused", A.ls()[vm]["state"] == "paused", A.ls()[vm])
    time.sleep(paused_s)
    r = A.resume(vm)
    check("resume: ls says running", A.ls()[vm]["state"] == "running", A.ls()[vm])
    print(f"  resume: {r.get('resume_ms')} ms")
    c1, t1 = count(A, vm), time.time()
    # The counter ticks at most every 50 ms. Had the guest run through the pause it would
    # have gained ~paused_s / 0.05; paused, only what the reads and RPCs around it took.
    print(f"  counter +{c1 - c0} over {t1 - t0:.1f} s with {paused_s} s paused")
    check("pause: guest stopped while paused", c1 - c0 < (t1 - t0 - paused_s) / 0.05 + paused_s / 0.05 / 2,
          (c0, c1, round(t1 - t0, 2)))
    time.sleep(0.5)
    c2 = count(A, vm)
    check("resume: guest process continues", c2 > c1, (c1, c2))
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
        check(f"{src.label} -> {dst.label}: same address", dst.ls()[vm]["ip"] == ip)
        check(f"{src.label} -> {dst.label}: TCP connection survived", echo(conn, b"after %s\n" % dst.label.encode()))
        check(f"{src.label} -> {dst.label}: RAM intact", md5(dst, vm) == m)
        check(f"{src.label} -> {dst.label}: same process", marker_id(dst, vm) == proc)
    conn.close()
    A.kill(vm)


@case
def checkpoint_restore():
    """checkpoint --stop on A, restore on B; keep-running checkpoint restored as a fork."""
    vm = "e2e-ckpt"
    ip = A.run(vm)
    m = fill(A, vm)
    proc = marker(A, vm)
    path = ckpt_dir(vm)
    r = A.checkpoint(vm, path, stop=True)
    print(f"  checkpoint --stop: {r.get('checkpoint_ms')} ms, {r.get('data_mib')} MiB")
    check("checkpoint: manifest written", os.path.exists(os.path.join(path, "manifest.json")))
    check("checkpoint --stop: VM gone from A", vm not in A.ls(), A.ls())
    r = B.restore(path)
    print(f"  restore: ready in {r.get('ready_ms')} ms")
    check("restore: same name and address", B.ls().get(vm, {}).get("ip") == ip, B.ls())
    check("restore: RAM intact", md5(B, vm) == m)
    check("restore: same process", marker_id(B, vm) == proc)
    c1 = count(B, vm)
    check("restore: process runs on", wait_for(lambda: count(B, vm) > c1, 5))
    check("restore: guest clock right", wait_for(lambda: abs(clock_error(B, vm)) < 0.5, 5), clock_error(B, vm))
    # Keep-running checkpoint: the VM goes on; its copy restores as a second VM.
    path2 = ckpt_dir(vm + "-live")
    B.checkpoint(vm, path2)
    check("checkpoint --keep-running: still running", B.ls()[vm]["state"] == "running")
    must(B, vm, "echo changed > /tmp/after")
    # On B, whose address range the original's address is not from: A would hand it out again.
    fork = vm + "-fork"
    r = B.restore(path2, name=fork, ip="auto")
    check("fork: new address", r["ip"] != ip and B.ls()[fork]["ip"] == r["ip"], r)
    check("fork: RAM as at the checkpoint", md5(B, fork) == m)
    check("fork: later writes not in it", B.exec(fork, "test -e /tmp/after")[0] != 0)
    check("fork: same process", marker_id(B, fork) == proc)
    B.kill(vm)
    B.kill(fork)
    shutil.rmtree(path, ignore_errors=True)
    shutil.rmtree(path2, ignore_errors=True)


@case
def suspend_resume():
    """suspend frees the VM's Firecracker; resume brings back process and RAM."""
    vm = "e2e-suspend"
    ip = A.run(vm)
    m = fill(A, vm)
    proc = marker(A, vm)
    res = vm_resources(ip)
    check("found the VM's Firecracker", res["pid"] in A.firecrackers(), res)
    r = A.suspend(vm)
    print(f"  suspend: {r.get('suspend_ms')} ms, {r.get('data_mib')} MiB on disk")
    check("suspend: ls says suspended", A.ls()[vm]["state"] == "suspended", A.ls()[vm])
    check("suspend: its Firecracker exited", wait_for(lambda: not os.path.exists(f"/proc/{res['pid']}"), 10), res)
    check("suspend: exec refused", A.exec(vm, "true", timeout=60)[0] != 0)
    r = A.resume(vm)
    print(f"  resume: ready in {r.get('ready_ms')} ms")
    check("resume: running", A.ls()[vm]["state"] == "running")
    check("resume: RAM intact", md5(A, vm) == m)
    check("resume: same process", marker_id(A, vm) == proc)
    c1 = count(A, vm)
    check("resume: process runs on", wait_for(lambda: count(A, vm) > c1, 5))
    A.kill(vm)


@case
def kill_releases():
    """kill removes the VM and gives back its Firecracker, tap, route, cgroup and address."""
    vm = "e2e-kill"
    ip = A.run(vm)
    res = vm_resources(ip)
    check("found the VM's tap and Firecracker", res["tap"] and res["pid"], res)
    A.kill(vm)
    check("kill: not listed", vm not in A.ls())
    check("kill: its Firecracker exited", wait_for(lambda: not os.path.exists(f"/proc/{res['pid']}"), 10), res)
    check("kill: route gone", vm_resources(ip)["route"] == "", vm_resources(ip))
    taps = A.taps()
    check("kill: tap gone", wait_for(lambda: res["tap"] not in A.taps(), 10), taps)
    if res["cgroup"]:
        check("kill: cgroup gone", wait_for(lambda: not os.path.exists(res["cgroup"]), 10), res["cgroup"])
    check("kill: address free again", A.run(vm, ip=ip) == ip)
    A.kill(vm)
    check("kill: second kill of the name fails", A.kill(vm, check=False).returncode != 0)


@case
def image_template():
    """template --image: a container image becomes a template whose VMs run its entrypoint."""
    if args.no_image:
        print("  skipped (--no-image)")
        return
    name = args.template + "-img"
    t = time.time()
    cmd = ["sh", "-c", "mkdir -p /tmp/www && echo hello-from-image > /tmp/www/index.html && "
                       "echo app-started && exec httpd -f -p 8080 -h /tmp/www"]
    # Anonymous registry pulls get rate limited (HTTP 429); only that is retried.
    for delay in (5, 15, 30, None):
        try:
            template(name, "--image", args.image, "--vcpus", "2", "--max", "2048", "--cmd", json.dumps(cmd))
            break
        except AssertionError as e:
            if delay is None or "HTTP 429" not in str(e):
                raise
            print(f"  registry rate limit; retrying in {delay} s")
            time.sleep(delay)
    print(f"  template from {args.image}: {time.time() - t:.1f} s")
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
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "faults.py"), "--a", A.addr, "--b", B.addr,
                        "--bin", BIN, "--template", args.template, "--log-dir", args.log_dir,
                        "--ckpt-dir", os.path.join(WORK, "faults-ckpt"), *args.faults.split()], timeout=900)
    check("faults.py: no failures", r.returncode == 0, f"exit {r.returncode}")


# --- main ------------------------------------------------------------------------

# Directories of this run's own, shared with nothing else: run directories under /run
# (tmpfs), state and checkpoints under /var/tmp (suspend needs a disk).
RUN = tempfile.mkdtemp(prefix="fvci-", dir="/run")
WORK = tempfile.mkdtemp(prefix="fvci-", dir="/var/tmp")
A = Host("a", args.port_a, args.port_a + 1, args.net_a)
B = Host("b", args.port_a + 1, args.port_a, args.net_b)


def main():
    assert os.geteuid() == 0, "run as root"
    selected = args.cases or list(CASES)
    for c in selected:
        assert c in CASES, f"unknown case {c}; have {', '.join(CASES)}"
    started = time.time()
    failed = []
    try:
        t = time.time()
        template(args.template, "--vcpus", "2", "--max", "2048")
        print(f"PASS template ({time.time() - t:.1f} s)", flush=True)
    except Exception as e:
        print(f"FAIL template: {e}", flush=True)
        return 1
    try:
        A.start()
        B.start()
        for c in selected:
            print(f"--- {c}: {CASES[c].__doc__.strip().splitlines()[0]}", flush=True)
            t = time.time()
            try:
                CASES[c]()
                results.append((c, "PASS", time.time() - t))
            except Exception as e:
                traceback.print_exc()
                results.append((c, "FAIL", time.time() - t))
                failed.append(c)
                for h in (A, B):  # free the VMs this script made, so the next case starts clean
                    for vm in sorted(h.vms & set(h.ls())):
                        h.kill(vm, check=False)
    finally:
        if failed:
            for h in (A, B):
                h.save_logs()
        t = time.time()
        problems = []
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
        shutil.rmtree(WORK, ignore_errors=True)
        shutil.rmtree(RUN, ignore_errors=True)
    print("\n" + "\n".join(f"{s} {c} ({d:.1f} s)" for c, s, d in results))
    print(f"{len(results) - len(failed)} passed, {len(failed)} failed in {time.time() - started:.0f} s")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
        shutil.rmtree(RUN, ignore_errors=True)
    sys.exit(code)
