#!/usr/bin/env python3
"""Fault-injection checks for migration between two live daemons, A and B,
started with FLEXVM_FAULTS=1 and peered with each other. Each scenario checks
that the VM ends up running on exactly one host (md5 of a guest file intact)
or cleanly failed.

usage: scripts/faults.py [--a ADDR] [--b ADDR] [--bin FLEXVM] [--log-dir DIR] SCENARIO... | all
  'all' runs the scenarios that leave both daemons running; source_killed and
  target_restart kill a daemon with SIGKILL and restart it with the same
  command line and environment (logging to --log-dir).
"""
import argparse, json, os, socket, subprocess, sys, tempfile, threading, time

p = argparse.ArgumentParser(usage=__doc__)
p.add_argument("--a", default="127.0.0.1:7092")
p.add_argument("--b", default="127.0.0.1:7093")
p.add_argument("--bin", default=os.path.join(os.path.dirname(__file__), "..", "target", "release", "flexvm"))
p.add_argument("--log-dir", default=tempfile.gettempdir())
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
    ok(host, {"op": "run", "name": name})
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
        if b"daemon" in argv and host.encode() in argv and os.path.basename(argv[0]) not in (b"sudo", b"env", b"setsid"):
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
    check(f"restarted daemon on {host}", wait_for(lambda: rpc(host, {"op": "info"}, timeout=2).get("ok") if can_connect(host) else False, 30))


def can_connect(host):
    try:
        socket.create_connection(tuple([host.rsplit(":", 1)[0], int(host.rsplit(":", 1)[1])]), timeout=1).close()
        return True
    except OSError:
        return False


def firecrackers(run_dir):
    """Firecracker pids running out of `run_dir`, with their directories."""
    out = {}
    for pid in subprocess.run(["pgrep", "-x", "firecracker"], capture_output=True, text=True).stdout.split():
        argv = proc(pid, "cmdline").split(b"\0")
        for a in argv:
            if a.startswith(run_dir.encode() + b"/"):
                out[pid] = os.path.dirname(a.decode())
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
    ok(B, {"op": "run", "name": n})
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


SCENARIOS = dict(basic=basic, route=route, lost_ack=lost_ack, unknown=unknown, refused=refused, pages_blip=pages_blip,
                 pages_dead_restore=pages_dead_restore, pages_dead=pages_dead, quiet_source=quiet_source,
                 source_killed=source_killed, target_restart=target_restart)
safe = [s for s in SCENARIOS if s not in ("source_killed", "target_restart")]
names = [n for s in args.scenarios for n in (safe if s == "all" else [s])]
for s in names:
    SCENARIOS[s]()
print("failures:", failures)
sys.exit(1 if failures else 0)
