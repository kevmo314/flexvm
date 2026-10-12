#!/usr/bin/env python3
"""Fault-injection checks for migration between two live daemons, A and B,
started with FLEXVM_FAULTS=1 and peered with each other. Each scenario checks
that the VM ends up running on exactly one host (md5 of a guest file intact)
or cleanly failed.

usage: scripts/faults.py [--a ADDR] [--b ADDR] [--bin FLEXVM] [--log-dir DIR] SCENARIO... | all
  'all' runs the scenarios that leave both daemons running; source_killed,
  target_restart, target_restart_symlink, checkpoint_crash and suspend_resume
  kill a daemon with SIGKILL and restart it with the same command line and
  environment (logging to --log-dir). Checkpoint scenarios write to --ckpt-dir.
"""
import argparse, json, os, socket, subprocess, sys, tempfile, threading, time

p = argparse.ArgumentParser(usage=__doc__)
p.add_argument("--a", default="127.0.0.1:7092")
p.add_argument("--b", default="127.0.0.1:7093")
p.add_argument("--bin", default=os.path.join(os.path.dirname(__file__), "..", "target", "release", "flexvm"))
p.add_argument("--log-dir", default=tempfile.gettempdir())
p.add_argument("--ckpt-dir", default=os.path.join(tempfile.gettempdir(), "flexvm-checkpoints"),
               help="where checkpoint scenarios write checkpoints (on disk; removed afterwards)")
p.add_argument("--template", default="default")
p.add_argument("scenarios", nargs="+")
args = p.parse_args()
A, B, BIN = args.a, args.b, args.bin
failures = 0


def rpc(host, req, timeout=60):
    h, port = host.rsplit(":", 1)
    with socket.create_connection((h, int(port)), timeout=timeout) as s:
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            d = s.recv(65536)
            if not d:
                break
            buf += d
    return json.loads(buf) if buf else {"ok": False, "error": "hung up"}


def ok(host, req):
    r = rpc(host, req)
    assert r["ok"], f"{req} -> {r}"
    return r["result"]


def sh(host, name, cmd):
    r = subprocess.run([BIN, "--host", host, "exec", name, cmd], capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout.strip() + r.stderr.strip()


def vms(host):
    return {v["name"]: v for v in ok(host, {"op": "ls"})}


def where(name):
    return {h: v[name]["state"] for h in (A, B) for v in [vms(h)] if name in v}


def wait_released(host, name, timeout=120):
    end = time.time() + timeout
    while True:
        st = ok(host, {"op": "migration_status", "name": name})
        if st["released"] is not None or time.time() > end:
            return st
        time.sleep(0.1)


def wait_for(cond, timeout):
    end = time.time() + timeout
    while not cond() and time.time() < end:
        time.sleep(0.1)
    return cond()


def fault(host, f, ms):
    ok(host, {"op": "fault", "fault": f, "ms": ms})


def setup(name, host=None, mib=200):
    host = host or A
    ok(host, {"op": "run", "name": name, "template": args.template})
    code, out = sh(host, name, f"dd if=/dev/urandom of=/tmp/f bs=1M count={mib} 2>/dev/null; md5sum /tmp/f")
    assert code == 0, out
    return out.split()[0]


def md5(host, name):
    code, out = sh(host, name, "md5sum /tmp/f")
    return out.split()[0] if code == 0 else out


def cleanup(name):
    for h in (A, B):
        rpc(h, {"op": "kill", "name": name})


def check(label, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + label + (f"  [{detail}]" if detail else ""), flush=True)
    failures += not cond


def proc(pid, what):
    if what == "environ":
        return subprocess.run(["sudo", "cat", f"/proc/{pid}/{what}"], capture_output=True).stdout
    try:
        with open(f"/proc/{pid}/{what}", "rb") as f:
            return f.read()
    except OSError:
        return b""


def alive(pid):
    stat = proc(pid, "stat").decode()
    return bool(stat) and stat.rsplit(")", 1)[1].split()[0] != "Z"


def daemon_pid(host):
    for pid in filter(str.isdigit, os.listdir("/proc")):
        argv = proc(pid, "cmdline").split(b"\0")
        listens = any(a == b"--listen" and v == host.encode() for a, v in zip(argv, argv[1:]))
        if b"daemon" in argv and listens and os.path.basename(argv[0]) not in (b"sudo", b"env", b"setsid"):
            return pid
    raise AssertionError(f"no daemon listening on {host}")


def kill_daemon(host):
    """SIGKILLs the daemon on `host`; returns how to start it again."""
    pid = daemon_pid(host)
    argv = [a.decode() for a in proc(pid, "cmdline").split(b"\0") if a]
    env = [e.decode() for e in proc(pid, "environ").split(b"\0") if e.startswith(b"FLEXVM")]
    subprocess.run(["sudo", "kill", "-9", pid])
    wait_for(lambda: not alive(pid), 5)
    return argv, env


def start_daemon(host, argv, env):
    log = open(os.path.join(args.log_dir, f"flexvm-{host.replace(':', '_')}.log"), "a")
    subprocess.Popen(["sudo", "env", *env, "setsid", *argv], stdout=log, stderr=log, stdin=subprocess.DEVNULL)
    def up():
        try:
            return rpc(host, {"op": "info"}, timeout=15).get("ok")
        except OSError:
            return False

    check(f"restarted daemon on {host}", wait_for(up, 30))


def firecrackers(run_dir):
    """Firecracker pids running out of `run_dir`, with their directories."""
    out = {}
    for pid in subprocess.run(["pgrep", "-x", "firecracker"], capture_output=True, text=True).stdout.split():
        argv = proc(pid, "cmdline").split(b"\0")
        for a in argv:
            d = os.path.realpath(os.path.dirname(a.decode(errors="replace")))
            if d.startswith(os.path.realpath(run_dir) + "/"):
                out[pid] = d
    return out


def run_dir(host):
    argv = proc(daemon_pid(host), "cmdline").split(b"\0")
    return argv[argv.index(b"--run") + 1].decode()


# --- scenarios ---------------------------------------------------------------


def basic():
    n = "ft-basic"
    m = setup(n)
    r = ok(A, {"op": "migrate", "name": n, "to": B})
    st = wait_released(B, n)
    check("basic: released", st["released"] is True, st)
    check("basic: only on B, running", where(n) == {B: "running"}, where(n))
    check("basic: md5 intact on B", md5(B, n) == m)
    # And back: the release of the first migration must not touch the VM now on A.
    r2 = ok(B, {"op": "migrate", "name": n, "to": A})
    wait_released(A, n)
    stale = rpc(A, {"op": "release", "name": n, "mig": r["mig"]})
    check("basic: stale-generation release refused", not stale["ok"], stale)
    again = rpc(B, {"op": "release", "name": n, "mig": r2["mig"]})
    check("basic: repeated release is idempotent", again["ok"], again)
    check("basic: back on A only", where(n) == {A: "running"}, where(n))
    check("basic: md5 intact after round trip", md5(A, n) == m)
    cleanup(n)


def route():
    n = "ft-route"
    m = setup(n)
    fault(A, "route", 1000)
    r = ok(A, {"op": "migrate", "name": n, "to": B})
    check("route: migrate reports reroute error but succeeds", r["reroute_error"] is not None, r["reroute_error"])
    w = where(n)
    check("route: source never resumed", w.get(A) in (None, "source") and w.get(B) == "running", w)
    st = wait_released(B, n)
    check("route: released, only on B", st["released"] is True and where(n) == {B: "running"}, (st, where(n)))
    check("route: md5 intact", md5(B, n) == m)
    cleanup(n)


def lost_ack():
    n = "ft-lost-ack"
    m = setup(n)
    fault(B, "lost_ack", 1000)
    r = rpc(A, {"op": "migrate", "name": n, "to": B})
    check("lost ack: source learns the target committed", r["ok"], r)
    st = wait_released(B, n)
    check("lost ack: only on B", where(n) == {B: "running"}, (where(n), st))
    check("lost ack: md5 intact", md5(B, n) == m)
    cleanup(n)


def unknown():
    n = "ft-unknown"
    m = setup(n)
    fault(B, "lost_ack", 1000)
    fault(B, "status", 5000)
    r = rpc(A, {"op": "migrate", "name": n, "to": B})
    check("unknown: migrate reports unknown outcome", not r["ok"] and "paused" in r["error"], r)
    w = where(n)
    check("unknown: source never resumed", w.get(A) in (None, "source") and w.get(B) == "running", w)
    st = wait_released(B, n)
    check("unknown: reconciled and released", st["released"] is True and where(n) == {B: "running"}, (st, where(n)))
    check("unknown: md5 intact", md5(B, n) == m)
    cleanup(n)


def refused():
    n = "ft-refused"
    m = setup(n)
    ok(B, {"op": "run", "name": n, "template": args.template})
    r = rpc(A, {"op": "migrate", "name": n, "to": B})
    check("refused: migrate fails", not r["ok"], r)
    check("refused: source resumed", where(n) == {A: "running", B: "running"}, where(n))
    check("refused: md5 intact on A", md5(A, n) == m)
    cleanup(n)


def pages_blip():
    n = "ft-pages-blip"
    m = setup(n, mib=400)
    fault(A, "pages", 3000)
    t = time.time()
    ok(A, {"op": "migrate", "name": n, "to": B})
    st = wait_released(B, n)
    check("pages blip: pull recovered", st["released"] is True and st["failed"] is None, f"{st} after {time.time()-t:.1f}s")
    check("pages blip: only on B", where(n) == {B: "running"}, where(n))
    check("pages blip: md5 intact", md5(B, n) == m)
    cleanup(n)


def pages_dead_restore():
    n = "ft-pages-dead-restore"
    m = setup(n)
    fault(A, "pages", 20000)
    r = rpc(A, {"op": "migrate", "name": n, "to": B}, timeout=120)
    check("pages dead at restore: target refuses", not r["ok"], r)
    check("pages dead at restore: source resumed, only on A", where(n) == {A: "running"}, where(n))
    check("pages dead at restore: md5 intact on A", md5(A, n) == m)
    cleanup(n)


def pages_dead():
    n = "ft-pages-dead"
    setup(n, mib=1500)
    ok(A, {"op": "migrate", "name": n, "to": B})
    fault(A, "pages", 30000)
    st = wait_released(B, n)
    check("pages dead: target failed cleanly", st["state"] == "failed" and st["failed"], st)
    check("pages dead: source copy released", st["released"] is True, st)
    check("pages dead: running nowhere", where(n) == {B: "failed"}, where(n))
    cleanup(n)


def quiet_source():
    """While the source is paused, its devices must not touch guest memory:
    no packets reach its tap and host exec sessions are closed."""
    n = "ft-quiet"
    m = setup(n, mib=1500)
    vm = vms(A)[n]
    tap, ip = vm["tap"], vm["ip"]
    stop = threading.Event()

    def flood():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop.is_set():
            try:
                s.sendto(b"x" * 64, (ip, 9))
            except OSError:
                pass
            time.sleep(0.0005)

    threading.Thread(target=flood, daemon=True).start()
    session = subprocess.Popen([BIN, "--host", A, "exec", n, "while :; do echo tick; sleep 0.05; done"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sysfs = f"/sys/class/net/{tap}"
    tx = lambda: int(open(f"{sysfs}/statistics/tx_packets").read())
    # Daemons sharing one host share a routing table, so point the address
    # at the source's tap explicitly (as a stale LAN path would).
    to_tap = lambda: subprocess.run(["sudo", "ip", "route", "replace", f"{ip}/32", "dev", tap], capture_output=True, text=True)
    to_tap()
    t = tx()
    time.sleep(0.3)
    check("quiet source: flood reaches the tap while running", tx() > t + 10, (t, tx()))
    r = ok(A, {"op": "migrate", "name": n, "to": B})
    paused = where(n).get(A) == "source"
    flags = int(open(f"{sysfs}/flags").read(), 16) if os.path.exists(sysfs) else 0
    routed = to_tap()
    t0 = tx() if os.path.exists(sysfs) else None
    time.sleep(0.3)
    t1 = tx() if os.path.exists(sysfs) else None
    check("quiet source: still paused while sampled", paused, where(n))
    check("quiet source: tap down while paused", flags & 1 == 0, hex(flags))
    check("quiet source: cannot route to the tap while paused", routed.returncode != 0, routed.stderr.strip())
    check("quiet source: no packets to the tap while paused", t0 == t1, (t0, t1))
    check("quiet source: exec session closed", wait_for(lambda: session.poll() is not None, 10), session.poll())
    stop.set()
    st = wait_released(B, n)
    check("quiet source: released, only on B", st["released"] is True and where(n) == {B: "running"}, (st, where(n)))
    check("quiet source: md5 intact", md5(B, n) == m)
    check("quiet source: guest still answers", sh(B, n, "echo hi") == (0, "hi"))
    print(f"quiet source: downtime {r['downtime_ms']} ms, checkpoint {r['checkpoint_ms']} ms")
    cleanup(n)


def source_killed():
    """Kills the source daemon mid-pull: the target fails cleanly."""
    n = "ft-source-killed"
    setup(n, mib=1500)
    ok(A, {"op": "migrate", "name": n, "to": B})
    argv, env = kill_daemon(A)
    st = wait_released(B, n)
    check("source killed: target failed cleanly", st["state"] == "failed" and st["failed"], st)
    check("source killed: not running on target", vms(B)[n]["state"] == "failed")
    rpc(B, {"op": "kill", "name": n})
    start_daemon(A, argv, env)


def target_restart():
    """The target restarts after resuming the VM, before the source knew:
    its orphaned Firecracker must die before it answers, so the source may
    resume without a second copy running."""
    n = "ft-target-restart"
    m = setup(n, mib=1500)
    rdir = run_dir(B)
    fault(B, "lost_ack", 2000)
    fault(B, "status", 60000)
    # Once the target has resumed, stall its pull so it cannot finish (and
    # release the source) before it restarts.
    stall = threading.Timer(0.2, lambda: fault(A, "pages", 6000))
    stall.start()
    r = rpc(A, {"op": "migrate", "name": n, "to": B})
    stall.join()
    check("target restart: outcome unknown, source paused", not r["ok"] and where(n).get(A) == "source", (r, where(n)))
    vm_fc = [pid for pid, d in firecrackers(rdir).items() if os.path.exists(os.path.join(d, "vmstate.in"))]
    check("target restart: VM running on target", len(vm_fc) == 1 and alive(vm_fc[0]), vm_fc)
    argv, env = kill_daemon(B)
    check("target restart: orphan outlives its daemon", alive(vm_fc[0]))
    start_daemon(B, argv, env)
    check("target restart: orphan killed before answering", not alive(vm_fc[0]))
    check("target restart: source resumed", wait_for(lambda: where(n) == {A: "running"}, 60), where(n))
    check("target restart: md5 intact on A", md5(A, n) == m)
    cleanup(n)


def shared_run_dir():
    """A second daemon on A's run directory, or one inside it, must refuse to
    start (before binding or killing anything); A's VM keeps running."""
    n = "ft-shared-run"
    m = setup(n)
    argv = [a.decode() for a in proc(daemon_pid(A), "cmdline").split(b"\0") if a]
    rdir = argv[argv.index("--run") + 1]
    for label, other in (("same", rdir), ("nested", os.path.join(rdir, "nested"))):
        bad = argv[:]
        bad[bad.index("--run") + 1] = other
        r = subprocess.run(["sudo", *bad], capture_output=True, text=True, timeout=30)
        check(f"shared run dir ({label}): second daemon refuses", r.returncode != 0 and "overlaps" in r.stderr, r.stderr.strip())
    subprocess.run(["sudo", "rmdir", os.path.join(rdir, "nested")])
    check("shared run dir: VM untouched", where(n) == {A: "running"} and md5(A, n) == m, where(n))
    cleanup(n)


def exec_race():
    """Execs keep starting while the VM migrates there and back: every exec
    finishes or is refused (none hangs), and the VM ends on one host intact."""
    n = "ft-exec-race"
    m = setup(n)
    stop, results = threading.Event(), {"ok": 0, "refused": 0, "cut": 0, "hung": 0}

    def worker():
        while not stop.is_set():
            for h in (A, B):
                try:
                    r = subprocess.run([BIN, "--host", h, "exec", n, "echo hi"], capture_output=True, text=True, timeout=30)
                except subprocess.TimeoutExpired:
                    results["hung"] += 1
                    continue
                if r.returncode == 0 and r.stdout.strip() == "hi":
                    results["ok"] += 1
                elif "not running" in r.stderr or "no vm named" in r.stderr:
                    results["refused"] += 1
                else:
                    results["cut"] += 1

    workers = [threading.Thread(target=worker) for _ in range(6)]
    for w in workers:
        w.start()
    time.sleep(0.5)
    ok(A, {"op": "migrate", "name": n, "to": B})
    wait_released(B, n)
    time.sleep(0.3)
    ok(B, {"op": "migrate", "name": n, "to": A})
    wait_released(A, n)
    time.sleep(0.3)
    stop.set()
    for w in workers:
        w.join()
    check("exec race: no exec hung", results["hung"] == 0, results)
    check("exec race: back on A only", where(n) == {A: "running"}, where(n))
    check("exec race: md5 intact", md5(A, n) == m)
    cleanup(n)


def target_restart_symlink():
    """target_restart with the target's --run given through a symlink."""
    argv, env = kill_daemon(B)
    i = argv.index("--run") + 1
    link = os.path.realpath(argv[i]) + "-link"
    subprocess.run(["sudo", "ln", "-sfn", os.path.realpath(argv[i]), link], check=True)
    start_daemon(B, argv[:i] + [link] + argv[i + 1:], env)
    try:
        target_restart()
    finally:
        kill_daemon(B)
        start_daemon(B, argv, env)
        subprocess.run(["sudo", "rm", "-f", link])


def guest_hang():
    """A guest that never answers its agent (Firecracker stopped) must not
    hold the admission lock forever: execs fail within their deadline, and
    once it is back, the VM still runs and migrates."""
    n = "ft-guest-hang"
    m = setup(n)
    fcs = [pid for pid, d in firecrackers(run_dir(A)).items() if os.path.exists(os.path.join(d, "v.sock"))]
    check("guest hang: found the VM's firecracker", len(fcs) == 1, fcs)
    subprocess.run(["sudo", "kill", "-STOP", fcs[0]])
    times = []

    def one():
        t = time.time()
        try:
            r = subprocess.run([BIN, "--host", A, "exec", n, "echo hi"], capture_output=True, text=True, timeout=60)
            times.append((round(time.time() - t, 1), r.returncode))
        except subprocess.TimeoutExpired:
            times.append((None, None))

    execs = [threading.Thread(target=one) for _ in range(3)]
    for e in execs:
        e.start()
    for e in execs:
        e.join()
    subprocess.run(["sudo", "kill", "-CONT", fcs[0]])
    check("guest hang: every exec gave up within its deadline", all(t is not None and t < 20 and c != 0 for t, c in times), times)
    check("guest hang: exec works again", sh(A, n, "echo hi") == (0, "hi"))
    ok(A, {"op": "migrate", "name": n, "to": B})
    wait_released(B, n)
    check("guest hang: migrates afterwards, md5 intact", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    cleanup(n)


# --- lifecycle: checkpoint / restore / pause / suspend -------------------------


def ckpt_path(label):
    os.makedirs(args.ckpt_dir, exist_ok=True)
    path = os.path.join(args.ckpt_dir, label)
    subprocess.run(["sudo", "rm", "-rf", path])
    return path


def rm_ckpt(path):
    subprocess.run(["sudo", "rm", "-rf", path])


def marker(host, name):
    """Starts a long-lived guest process; returns its (pid, start time)."""
    code, out = sh(host, name, "setsid sleep 424242 >/dev/null 2>&1 < /dev/null & echo $! > /tmp/marker.pid")
    assert code == 0, out
    return marker_id(host, name)


def marker_id(host, name):
    code, out = sh(host, name, 'p=$(cat /tmp/marker.pid); echo "$p $(cut -d" " -f2,22 /proc/$p/stat)"')
    return out if code == 0 else None


def guest_clock_error(host, name):
    """Guest wall clock minus host wall clock, in seconds (+- one exec)."""
    before = time.time()
    code, out = sh(host, name, "date +%s.%N")
    after = time.time()
    return float(out) - (before + after) / 2 if code == 0 else None


def to_tap(host, name):
    """Daemons sharing one host share its routing table, and a peer's route
    for a VM it just announced replaces ours: point the address at the VM's
    tap, as its own host would."""
    time.sleep(0.5)  # let the restoring daemon's announcement land first
    vm = vms(host)[name]
    # Some taps lose the gateway MAC create_tap gave them (udev racing it?),
    # and then the host ignores the guest's frames.
    subprocess.run(["sudo", "ip", "link", "set", "dev", vm["tap"], "address", "06:00:a9:fe:01:01"], check=True)
    subprocess.run(["sudo", "ip", "route", "replace", f"{vm['ip']}/32", "dev", vm["tap"]], check=True)
    return vm["ip"]


def echo(s, msg):
    s.sendall(msg)
    got = b""
    while len(got) < len(msg):
        d = s.recv(65536)
        if not d:
            break
        got += d
    return got == msg


def tcp_server(host, name, port=7000):
    code, out = sh(host, name, f"setsid socat TCP-LISTEN:{port},fork,reuseaddr EXEC:cat >/dev/null 2>&1 < /dev/null &")
    assert code == 0, out
    time.sleep(0.3)


FV_MASK = (1 << 64) - 1


def fv_hash(b):
    """flexvm's content hash (template::Hash), to forge test manifests."""
    def word(h, w):
        x = ((h ^ w) * 0x9E3779B97F4A7C15) & FV_MASK
        return x ^ (x >> 29)
    h = word(0xCBF29CE484222325, len(b))
    n = len(b) // 8
    for i in range(n):
        h = word(h, int.from_bytes(b[i * 8:i * 8 + 8], "little"))
    return f"{word(h, int.from_bytes(b[n * 8:].ljust(8, b'\0'), 'little')):016x}"


def checkpoint_restore():
    """checkpoint --stop on A, restore on B: file contents, a running
    process, the address and an open TCP connection all survive."""
    n, path = "ft-ckpt", ckpt_path("ft-ckpt")
    m = setup(n)
    proc_before = marker(A, n)
    tcp_server(A, n)
    ip = to_tap(A, n)
    conn = socket.create_connection((ip, 7000), timeout=10)
    check("checkpoint: TCP echo before", echo(conn, b"before\n"))
    r = ok(A, {"op": "checkpoint", "name": n, "dir": path, "stop": True})
    print(f"checkpoint: {r['checkpoint_ms']} ms ({r['data_mib']} MiB data), paused {r['paused_ms']} ms")
    leftovers = [f for f in os.listdir(args.ckpt_dir) if f.startswith(".ft-ckpt.partial")]
    check("checkpoint: published, no partial left", os.path.exists(os.path.join(path, "manifest.json")) and not leftovers, leftovers)
    check("checkpoint --stop: gone from A", n not in vms(A), vms(A).get(n))
    r = ok(B, {"op": "restore", "dir": path})
    print(f"restore: ready in {r['ready_ms']} ms (snapshot load {r['restore_ms']} ms), clock was {r['clock_offset_ms']} ms off; {r['timings_ms']}")
    to_tap(B, n)
    check("restore: same address", r["ip"] == ip and sh(B, n, "ip -4 -o addr show eth0")[1].count(ip) == 1, r["ip"])
    check("restore: TCP connection survived", echo(conn, b"after\n"))
    conn.close()
    with socket.create_connection((ip, 7000), timeout=10) as c2:
        check("restore: new TCP connection", echo(c2, b"new\n"))
    check("restore: md5 intact", md5(B, n) == m)
    check("restore: process survived (pid, start time)", marker_id(B, n) == proc_before, (proc_before, marker_id(B, n)))
    err = guest_clock_error(B, n)
    check("restore: guest clock right", err is not None and abs(err) < 0.5, err)
    check("restore: whole checkpoint paged in", wait_for(lambda: vms(B)[n]["pages_mib"]["remote"] == 0, 30), vms(B)[n]["pages_mib"])
    cleanup(n)
    rm_ckpt(path)


def checkpoint_fork():
    """checkpoint --keep-running: the VM goes on; the checkpoint restores as
    a second VM elsewhere, but only under a new address."""
    n, path = "ft-fork", ckpt_path("ft-fork")
    m = setup(n)
    r = ok(A, {"op": "checkpoint", "name": n, "dir": path})
    check("fork: still running on A", r["state"] == "running" and where(n) == {A: "running"}, where(n))
    again = rpc(A, {"op": "checkpoint", "name": n, "dir": path})
    check("fork: a checkpoint is never overwritten", not again["ok"] and "already exists" in again["error"], again)
    check("fork: refused before pausing", where(n) == {A: "running"}, where(n))
    code, _ = sh(A, n, "echo changed >> /tmp/f")
    check("fork: A keeps working", code == 0 and md5(A, n) != m)
    taken = rpc(B, {"op": "restore", "dir": path, "name": "ft-fork2"})
    check("fork: restore refuses an address in use on a peer", not taken["ok"] and "in use" in taken["error"], taken)
    r = ok(B, {"op": "restore", "dir": path, "name": "ft-fork2", "ip": "auto"})
    ip = r["ip"]
    code, out = sh(B, "ft-fork2", "ip -4 -o addr show eth0")
    check("fork: copy has only its new address", ip in out and vms(A)[n]["ip"] not in out, out)
    check("fork: copy has the checkpointed file", md5(B, "ft-fork2") == m)
    cleanup(n)
    cleanup("ft-fork2")
    rm_ckpt(path)


def checkpoint_corrupt():
    """Restores refuse a checkpoint whose metadata does not check out or whose
    template differs, and a VM whose page data turns out corrupt fails
    cleanly instead of running with bad memory."""
    n, path = "ft-corrupt", ckpt_path("ft-corrupt")
    setup(n)
    ok(A, {"op": "checkpoint", "name": n, "dir": path, "stop": True})
    pristine = path + ".orig"
    subprocess.run(["sudo", "cp", "-a", path, pristine], check=True)

    def poke(file, offset):
        subprocess.run(["sudo", "python3", "-c", f"f=open('{path}/{file}','r+b'); f.seek({offset}); b=f.read(1); f.seek({offset}); f.write(bytes([b[0]^1]))"], check=True)

    def reset():
        subprocess.run(["sudo", "rm", "-rf", path], check=True)
        subprocess.run(["sudo", "cp", "-a", pristine, path], check=True)

    poke("vmstate", 100)
    r = rpc(B, {"op": "restore", "dir": path})
    check("corrupt vmstate: refused", not r["ok"] and "checksum" in r["error"], r)
    reset()
    poke("manifest.json", 40)
    r = rpc(B, {"op": "restore", "dir": path})
    check("corrupt manifest: refused", not r["ok"] and "invalid" in r["error"], r)
    reset()
    text = subprocess.run(["sudo", "cat", f"{path}/manifest.json"], capture_output=True, check=True).stdout
    body = json.loads(text.split(b"\n", 1)[1])
    body["template_id"] = "0123456789abcdef"
    forged = json.dumps(body).encode()
    subprocess.run(["sudo", "tee", f"{path}/manifest.json"], input=fv_hash(forged).encode() + b"\n" + forged,
                   stdout=subprocess.DEVNULL, check=True)
    r = rpc(B, {"op": "restore", "dir": path})
    check("other template id: refused", not r["ok"] and "id mismatch" in r["error"], r)
    reset()
    poke("pages", 50 * 1024 * 1024)
    r = rpc(B, {"op": "restore", "dir": path})
    st = lambda: vms(B).get(n, {}).get("state")
    check("corrupt page data: VM fails, never runs on", (not r["ok"]) or wait_for(lambda: st() == "failed", 30), (r, st()))
    rpc(B, {"op": "kill", "name": n})
    rm_ckpt(path)
    rm_ckpt(pristine)


def checkpoint_crash():
    """The daemon dies while writing a checkpoint: no checkpoint appears (not
    even a partial one restores), and the next checkpoint to the same place
    clears the debris and succeeds."""
    n, path = "ft-crash", ckpt_path("ft-crash")
    setup(n, mib=1200)
    t = threading.Thread(target=lambda: rpc(A, {"op": "checkpoint", "name": n, "dir": path}))
    t.start()

    def writing():
        for f in os.listdir(args.ckpt_dir):
            p = os.path.join(args.ckpt_dir, f, "pages")
            if f.startswith(".ft-crash.partial") and os.path.exists(p) and os.path.getsize(p) > 100 << 20:
                return True
        return False

    check("crash: caught the checkpoint mid-write", wait_for(writing, 30))
    argv, env = kill_daemon(A)
    t.join()
    check("crash: no checkpoint published", not os.path.exists(path))
    r = rpc(B, {"op": "restore", "dir": path})
    check("crash: nothing to restore", not r["ok"], r)
    partial = [f for f in os.listdir(args.ckpt_dir) if f.startswith(".ft-crash.partial")]
    for f in partial:
        r = rpc(B, {"op": "restore", "dir": os.path.join(args.ckpt_dir, f)})
        check("crash: the partial directory does not restore", not r["ok"], r)
    start_daemon(A, argv, env)
    check("crash: the VM died with its daemon", n not in vms(A), vms(A).get(n))
    m = setup(n, mib=50)
    ok(A, {"op": "checkpoint", "name": n, "dir": path, "stop": True})
    left = [f for f in os.listdir(args.ckpt_dir) if f.startswith(".ft-crash.partial")]
    check("crash: next checkpoint cleared the debris", not left, left)
    ok(B, {"op": "restore", "dir": path})
    check("crash: next checkpoint restores", md5(B, n) == m)
    cleanup(n)
    rm_ckpt(path)


def pause_resume():
    n = "ft-pause"
    m = setup(n)
    sh(A, n, "date -s @$(date +%s)")  # fresh VMs keep the template's clock; start from a right one
    r = ok(A, {"op": "pause", "name": n})
    check("pause: paused", vms(A)[n]["state"] == "paused", r)
    code, out = sh(A, n, "echo hi")
    check("pause: exec refused while paused", code != 0 and "not running" in out, out)
    time.sleep(0.2)
    controller_quiet = vms(A)[n]["state"] == "paused"
    time.sleep(3)
    r = ok(A, {"op": "resume", "name": n})
    print(f"pause: {r['resume_ms']} ms to resume")
    check("pause: controller left it alone", controller_quiet and r["from"] == "paused")
    check("pause: resumes within 5 ms", r["resume_ms"] < 5, r["resume_ms"])
    time.sleep(0.5)
    err = guest_clock_error(A, n)
    check("pause: guest clock right after 3 s paused", err is not None and abs(err) < 0.5, err)
    check("pause: md5 intact", md5(A, n) == m)
    ok(A, {"op": "pause", "name": n})
    r = ok(A, {"op": "migrate", "name": n, "to": B})
    st = wait_released(B, n)
    check("paused migrate: stays paused on B, source released", where(n) == {B: "paused"} and st["released"] is True, (where(n), st))
    ok(B, {"op": "resume", "name": n})
    check("paused migrate: runs on B after resume, md5 intact", md5(B, n) == m)
    cleanup(n)


def suspend_resume():
    """suspend frees the VM's memory and survives a daemon restart; resume
    pages it back in lazily."""
    n = "ft-suspend"
    m = setup(n)
    proc_before = marker(A, n)
    rdir = run_dir(A)
    before = len(firecrackers(rdir))
    r = ok(A, {"op": "suspend", "name": n})
    print(f"suspend: {r['suspend_ms']} ms, freed {r['freed_rss_mib']} MiB RSS, {r['data_mib']} MiB on disk")
    v = vms(A)[n]
    check("suspend: listed suspended, RSS 0", v["state"] == "suspended" and v["rss_mib"] == 0, v)
    check("suspend: its Firecracker is gone", len(firecrackers(rdir)) == before - 1, (before, firecrackers(rdir)))
    code, out = sh(A, n, "echo hi")
    check("suspend: exec refused", code != 0, out)
    argv, env = kill_daemon(A)
    start_daemon(A, argv, env)
    check("suspend: still suspended after a daemon restart", vms(A).get(n, {}).get("state") == "suspended", vms(A).get(n))
    time.sleep(2)
    r = ok(A, {"op": "resume", "name": n})
    print(f"suspend: resumed, ready in {r['ready_ms']} ms; clock was {r['clock_offset_ms']} ms off")
    check("suspend: md5 intact", md5(A, n) == m)
    check("suspend: process survived", marker_id(A, n) == proc_before, (proc_before, marker_id(A, n)))
    err = guest_clock_error(A, n)
    check("suspend: guest clock right", err is not None and abs(err) < 0.5, err)
    check("suspend: paged back in", wait_for(lambda: vms(A)[n]["pages_mib"]["remote"] == 0, 30), vms(A)[n])
    cleanup(n)


SCENARIOS = dict(basic=basic, route=route, lost_ack=lost_ack, unknown=unknown, refused=refused, pages_blip=pages_blip,
                 pages_dead_restore=pages_dead_restore, pages_dead=pages_dead, quiet_source=quiet_source,
                 shared_run_dir=shared_run_dir, exec_race=exec_race, source_killed=source_killed,
                 target_restart=target_restart, target_restart_symlink=target_restart_symlink, guest_hang=guest_hang,
                 checkpoint_restore=checkpoint_restore, checkpoint_fork=checkpoint_fork,
                 checkpoint_corrupt=checkpoint_corrupt, checkpoint_crash=checkpoint_crash, pause_resume=pause_resume,
                 suspend_resume=suspend_resume)
safe = [s for s in SCENARIOS
        if s not in ("source_killed", "target_restart", "target_restart_symlink", "checkpoint_crash", "suspend_resume")]
names = [n for s in args.scenarios for n in (safe if s == "all" else [s])]
for s in names:
    SCENARIOS[s]()
print("failures:", failures)
sys.exit(1 if failures else 0)
