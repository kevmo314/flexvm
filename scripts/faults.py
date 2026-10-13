#!/usr/bin/env python3
"""Fault-injection checks for migration between two live daemons, A and B,
started with FLEXVM_FAULTS=1 and peered with each other. Each scenario checks
that the VM ends up running on exactly one host (md5 of a guest file intact)
or cleanly failed.

usage: scripts/faults.py [--a ADDR] [--b ADDR] [--bin FLEXVM] [--log-dir DIR] SCENARIO... | all
  'all' runs the scenarios that leave both daemons running; source_killed,
  target_restart, target_restart_symlink, checkpoint_crash, cow_crash, late_withdrawal, suspend_no_gen,
  suspend_resume, hot_budget and resume_mark_fails kill a daemon with SIGKILL and restart it with the same command line and
  environment (logging to --log-dir). Checkpoint scenarios write to --ckpt-dir.
"""
import argparse, base64, json, os, socket, subprocess, sys, tempfile, threading, time, traceback

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
scenario_vms = set()
scenario_checkpoints = set()


def rpc(host, req, timeout=60):
    if req.get("op") in ("run", "restore") and "name" in req:
        scenario_vms.add(req["name"])
    if req.get("op") == "checkpoint":
        scenario_checkpoints.add(req["dir"])
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


FAULTS = ("pages", "route", "lost_ack", "status", "restore_no_hold", "restore_before_run", "restore_after_run",
          "ckpt_abort", "ckpt_fail_protect", "ckpt_fail_write", "ckpt_memhash", "ckpt_no_hold", "ckpt_slow", "ckpt_crawl", "resume_kill",
          "prepare_fail", "short_incoming", "slow_preload", "kill_prepared", "guest_drop", "guest_lose_reply", "ckpt_copy_wait",
          "hot_low_estimate", "started_fsync", "started_unmark", "ckpt_wp_race", "fetch_tail_enomem", "fetch_enomem_stuck")


def disarm():
    """Disarms every test fault on both daemons, so none outlives its scenario."""
    for h in (A, B):
        try:
            for f in FAULTS:
                rpc(h, {"op": "fault", "fault": f, "ms": 0})
        except Exception as e:
            check(f"disarm on {h}", False, repr(e))


def setup(name, host=None, mib=200, template=None):
    host = host or A
    ok(host, {"op": "run", "name": name, "template": template or args.template})
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
    return cond


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
    """Firecracker pids running out of `run_dir`, with their directories
    there (found by their log, as their sockets live elsewhere)."""
    out = {}
    for pid in subprocess.run(["pgrep", "-x", "firecracker"], capture_output=True, text=True).stdout.split():
        log = subprocess.run(["sudo", "readlink", f"/proc/{pid}/fd/1"], capture_output=True, text=True).stdout.strip()
        d = os.path.dirname(log)
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
    got = md5(B, n)
    check("pages blip: md5 intact", got == m, got)
    # The blip stalled B's snapshot load, restoring the vCPUs' TSCs seconds
    # apart: KVM then keeps no master clock for the VM, so its snapshots have
    # no realtime clock. It must still migrate (issue #50).
    r = rpc(B, {"op": "migrate", "name": n, "to": A}, timeout=120)
    check("pages blip: migrates back", r["ok"], r)
    wait_released(A, n)
    w, back = where(n), md5(A, n)
    check("pages blip: back on A only, md5 intact", w == {A: "running"} and back == m, (w, back))
    cleanup(n)


def pages_dead_restore():
    n = "ft-pages-dead-restore"
    m = setup(n)
    fault(A, "pages", 20000)
    r = rpc(A, {"op": "migrate", "name": n, "to": B}, timeout=120)
    fault(A, "pages", 0)
    check("pages dead at restore: target refuses", not r["ok"], r)
    # Loaded with its vCPUs stopped, it is killed before it ever ran there.
    check("pages dead at restore: never ran on the target",
          "never ran here" in r.get("error", "") or "snapshot/load" in r.get("error", ""), r.get("error"))
    # The page server's refusal reaches the target, not just a hang-up.
    check("pages dead at restore: the source's reason is reported",
          "page server refused: injected fault" in r.get("error", "") or "snapshot/load" in r.get("error", ""), r.get("error"))
    check("pages dead at restore: source resumed, only on A", where(n) == {A: "running"}, where(n))
    check("pages dead at restore: md5 intact on A", md5(A, n) == m)
    cleanup(n)


def pages_dead():
    n = "ft-pages-dead"
    setup(n, mib=1500)
    ok(A, {"op": "migrate", "name": n, "to": B})
    fault(A, "pages", 30000)
    st = wait_released(B, n)
    fault(A, "pages", 0)
    check("pages dead: target failed cleanly", st["state"] == "failed" and st["failed"], st)
    check("pages dead: source copy released", st["released"] is True, st)
    check("pages dead: running nowhere", where(n) == {B: "failed"}, where(n))
    cleanup(n)


def restore_loads(host):
    return ok(host, {"op": "info"})["loads"]


def hot_ready(host):
    ready = ok(host, {"op": "info"})["hot"]["ready"]
    return sum(c for k, c in ready.items() if k.split("@")[0] == args.template)


def resume_kill():
    """Firecracker dies right after a restored VM's resume was sent, so the
    guest may have run: nothing loads the VM again (that could repeat what
    the guest did). A migration target has committed before it resumes, so
    the VM is failed there and the source never resumes its copy; a run from
    the hot pool fails without a fallback load."""
    n = "ft-resume-kill"
    setup(n)
    before = restore_loads(B)
    fault(B, "resume_kill", 60000)
    r = rpc(A, {"op": "migrate", "name": n, "to": B}, timeout=120)
    fault(B, "resume_kill", 0)
    check("resume kill: migration committed", r["ok"], r)
    loads = restore_loads(B) - before
    check("resume kill: target loaded the vm once, no retry", loads == 1, loads)
    st = wait_released(B, n)
    check("resume kill: failed on B, running nowhere", where(n) == {B: "failed"}, (where(n), st))
    cleanup(n)
    n = "ft-resume-kill-hot"
    check("resume kill: a paused vm is ready", wait_for(lambda: hot_ready(A) > 0, 60), ok(A, {"op": "info"})["hot"])
    before = restore_loads(A)
    fault(A, "resume_kill", 60000)
    r = rpc(A, {"op": "run", "name": n, "template": args.template})
    fault(A, "resume_kill", 0)
    check("resume kill: run from the hot pool fails", not r["ok"] and "may have run" in r.get("error", ""), r)
    loads = restore_loads(A) - before
    check("resume kill: no fallback load", loads == 0, loads)
    check("resume kill: no vm left", n not in vms(A), vms(A).get(n))
    check("resume kill: the name runs again", rpc(A, {"op": "run", "name": n, "template": args.template})["ok"])
    cleanup(n)


def prepared_retry():
    """A migration target whose prepared Firecracker dies before the load,
    its pager having seen it go (`kill_prepared`), loads once more on a fresh
    one, before it commits: the
    guest never ran, and the paused source still serves every page,
    including the preloaded ones the dead pager had. The same retry, without
    clock_realtime, takes a VM whose snapshot has no realtime clock (#50)."""
    n = "ft-prepared-retry"
    m = setup(n)
    before = restore_loads(B)
    fault(B, "kill_prepared", 30000)
    r = rpc(A, {"op": "migrate", "name": n, "to": B}, timeout=120)
    fault(B, "kill_prepared", 0)
    check("prepared retry: migration commits", r["ok"], r)
    loads = restore_loads(B) - before
    check("prepared retry: loaded twice (one retry)", loads == 2, loads)
    st = wait_released(B, n)
    w, got = where(n), md5(B, n)
    check("prepared retry: only on B, md5 intact", w == {B: "running"} and got == m, (w, got, st))
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
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    ticks = [0]
    threading.Thread(target=lambda: [ticks.__setitem__(0, ticks[0] + 1) for _ in session.stdout], daemon=True).start()
    sysfs = f"/sys/class/net/{tap}"
    tx = lambda: int(open(f"{sysfs}/statistics/tx_packets").read())
    # While paused, try to point the address back at the source's tap (as a
    # stale LAN path would).
    to_tap = lambda: subprocess.run(["sudo", "ip", "route", "replace", f"{ip}/32", "dev", tap], capture_output=True, text=True)
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
    # The source closed its side; the exec client resumes the session on B.
    after = ticks[0]
    check("quiet source: exec session resumed on the target", wait_for(lambda: ticks[0] > after + 5, 10), (after, ticks[0]))
    session.kill()
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
    if len(vm_fc) != 1:
        rpc(A, {"op": "kill", "name": n})
        try:
            rpc(B, {"op": "kill", "name": n})
        except OSError:
            pass  # B may have died along with its Firecracker.
        return
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
    try:
        time.sleep(0.5)
        ok(A, {"op": "migrate", "name": n, "to": B})
        wait_released(B, n)
        time.sleep(0.3)
        ok(B, {"op": "migrate", "name": n, "to": A})
        wait_released(A, n)
        time.sleep(0.3)
    finally:
        stop.set()
        for w in workers:
            w.join()
    check("exec race: no exec hung", results["hung"] == 0, results)
    check("exec race: back on A only", where(n) == {A: "running"}, where(n))
    check("exec race: md5 intact", md5(A, n) == m)
    cleanup(n)


def guest_calls():
    """Guest calls during and just after a migration: execs started while the
    VM moves (on either host, the source's page server down for a while, so
    the guest is still faulting its memory in) all finish, and the target's
    own clock step goes through although its first guest connections drop."""
    n = "ft-guest-calls"
    m = setup(n)
    # Only the target's clock step after the arrival puts this right (once
    # the clock step that may follow the start is done).
    time.sleep(1)
    code, out = sh(A, n, "date -s @$(( $(date +%s) - 100 )) >/dev/null")
    assert code == 0, out
    stop, results = threading.Event(), {"ok": 0, "failed": []}

    def worker(h):
        while not stop.is_set():
            try:
                code, out = sh(h, n, "echo hi")
            except subprocess.TimeoutExpired:
                code, out = None, "hung"
            if code == 0 and out == "hi":
                results["ok"] += 1
            else:
                results["failed"].append((h, code, out))

    workers = [threading.Thread(target=worker, args=(h,)) for h in (A, B) for _ in range(3)]
    for w in workers:
        w.start()
    time.sleep(0.3)
    fault(A, "pages", 3000)
    fault(B, "guest_drop", 1000)
    ok(A, {"op": "migrate", "name": n, "to": B})
    got = md5(B, n)
    wait_released(B, n)
    time.sleep(0.3)
    stop.set()
    for w in workers:
        w.join()
    check("guest calls: every exec finished", results["ok"] > 0 and not results["failed"], results)
    check("guest calls: md5 intact while paging in", got == m, got)
    check("guest calls: only on B", where(n) == {B: "running"}, where(n))
    err = guest_clock_error(B, n)
    check("guest calls: target stepped the guest clock", err is not None and abs(err) < 0.5, err)
    # A clock step the guest carried out but whose answer was lost goes again.
    before = ok(B, {"op": "info"})["guest_retries"].get("CLOCK", 0)
    ok(B, {"op": "pause", "name": n})
    fault(B, "guest_lose_reply", 300)
    ok(B, {"op": "resume", "name": n})
    retried = lambda: ok(B, {"op": "info"})["guest_retries"].get("CLOCK", 0) > before
    check("guest calls: a clock step with its reply lost went again", wait_for(retried, 10),
          ok(B, {"op": "info"})["guest_retries"])
    check("guest calls: exec after the lost reply", sh(B, n, "echo hi") == (0, "hi"))
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
    # By pid: the run directory also holds idle and hot-pool Firecrackers.
    fcs = [str(vms(A)[n]["pid"])]
    check("guest hang: found the VM's firecracker", fcs[0] in firecrackers(run_dir(A)), fcs)
    subprocess.run(["sudo", "kill", "-STOP", fcs[0]])
    times = []

    def one():
        t = time.time()
        try:
            r = subprocess.run([BIN, "--host", A, "exec", n, "echo hi"], capture_output=True, text=True, timeout=60)
            times.append((round(time.time() - t, 1), r.returncode))
        except subprocess.TimeoutExpired:
            times.append((None, None))

    # The daemon's own answer, which the CLI's 30 s of retries would hide:
    # each exec request fails within the guest timeout (5 s), concurrently.
    raw = []

    def one_raw():
        t = time.time()
        try:
            r = rpc(A, {"op": "exec", "name": n, "session": os.urandom(16).hex(), "action": "start", "cmd": "echo hi"})
            raw.append((round(time.time() - t, 1), r["ok"]))
        except OSError as e:
            raw.append((None, str(e)))

    execs = [threading.Thread(target=f) for f in (one, one, one, one_raw, one_raw, one_raw)]
    for e in execs:
        e.start()
    for e in execs:
        e.join()
    subprocess.run(["sudo", "kill", "-CONT", fcs[0]])
    check("guest hang: the daemon fails each exec within the guest timeout",
          len(raw) == 3 and all(t is not None and t < 12 and r is False for t, r in raw), raw)
    # The CLI keeps retrying a VM its host knows for 30 s, then gives up.
    check("guest hang: every CLI exec gave up within its deadline", all(t is not None and t < 40 and c != 0 for t, c in times), times)
    check("guest hang: exec works again", sh(A, n, "echo hi") == (0, "hi"))
    ok(A, {"op": "migrate", "name": n, "to": B})
    wait_released(B, n)
    check("guest hang: migrates afterwards, md5 intact", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    cleanup(n)


# --- lifecycle: checkpoint / restore / pause / suspend -------------------------


def ckpt_path(label):
    os.makedirs(args.ckpt_dir, exist_ok=True)
    path = os.path.join(args.ckpt_dir, label)
    scenario_checkpoints.add(path)
    subprocess.run(["sudo", "rm", "-rf", path])
    return path


def rm_ckpt(path):
    subprocess.run(["sudo", "rm", "-rf", path], check=True)


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


def vm_ip(host, name):
    return vms(host)[name]["ip"]


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
    ip = vm_ip(A, n)
    conn = socket.create_connection((ip, 7000), timeout=10)
    check("checkpoint: TCP echo before", echo(conn, b"before\n"))
    r = ok(A, {"op": "checkpoint", "name": n, "dir": path, "stop": True})
    print(f"checkpoint: {r['checkpoint_ms']} ms ({r['data_mib']} MiB data), paused {r['paused_ms']} ms")
    leftovers = [f for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging-")]
    check("checkpoint: published, no partial left", os.path.exists(os.path.join(path, "manifest.json")) and not leftovers, leftovers)
    check("checkpoint --stop: gone from A", n not in vms(A), vms(A).get(n))
    r = ok(B, {"op": "restore", "dir": path})
    print(f"restore: ready in {r['ready_ms']} ms (snapshot load {r['restore_ms']} ms), clock was {r['clock_offset_ms']} ms off; {r['timings_ms']}")
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
    # B borrowed the address from A, its home host, with a new generation.
    check("restore: the address is lent out by its home host", ip in ok(A, {"op": "info"})["lent"], ok(A, {"op": "info"})["lent"])
    again = rpc(A, {"op": "restore", "dir": path, "name": n + "-again"})
    check("restore: the home host refuses it while lent", not again["ok"] and "lent" in again.get("error", ""), again)
    cleanup(n)
    check("restore: killing it gives the address back", wait_for(lambda: ip not in ok(A, {"op": "info"})["lent"], 10))
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


_STAGED_MIB = """
import os, sys
d, n = sys.argv[1], 0
for s in os.listdir(d):
    if s.startswith(".flexvm-staging-"):
        try:
            fd = os.open(os.path.join(d, s, "ck", "pages"), os.O_RDONLY)
        except OSError:
            continue
        n += sum(any(os.pread(fd, 4096, o)) for o in range(0, os.fstat(fd).st_size, 1 << 20))
        os.close(fd)
print(n)
"""


def staged_mib():
    """Roughly how many MiB of page data checkpoints staged in --ckpt-dir
    have written (staging is root-only)."""
    out = subprocess.run(["sudo", "python3", "-I", "-c", _STAGED_MIB, args.ckpt_dir], capture_output=True, text=True).stdout
    return int(out or 0)


def checkpoint_crash():
    """The daemon dies while writing a checkpoint: no checkpoint appears (not
    even a partial one restores), and the next checkpoint to the same place
    clears the debris and succeeds."""
    n, path = "ft-crash", ckpt_path("ft-crash")
    setup(n, mib=1200)
    fault(A, "ckpt_slow", 120000)
    t = threading.Thread(target=lambda: rpc(A, {"op": "checkpoint", "name": n, "dir": path}))
    t.start()

    def writing():
        # The pages file is preallocated (fallocate reads back as zeros), so
        # count what was written: MiB-spaced samples of it that hold data.
        return staged_mib() > 100 and vms(A).get(n, {}).get("checkpoint_copy")

    caught = wait_for(writing, 30)
    check("crash: caught the checkpoint mid-write", caught)
    if not caught:
        t.join()
        fault(A, "ckpt_slow", 0)
        cleanup(n)
        rm_ckpt(path)
        return
    argv, env = kill_daemon(A)
    t.join()
    check("crash: no checkpoint published", not os.path.exists(path))
    r = rpc(B, {"op": "restore", "dir": path})
    check("crash: nothing to restore", not r["ok"], r)
    partial = [os.path.join(f, "ck") for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging-")]
    check("crash: staging left behind (root-only)", len(partial) == 1, partial)
    for f in partial:
        r = rpc(B, {"op": "restore", "dir": os.path.join(args.ckpt_dir, f)})
        check("crash: the partial directory does not restore", not r["ok"], r)
    start_daemon(A, argv, env)
    check("crash: the VM died with its daemon", n not in vms(A), vms(A).get(n))
    m = setup(n, mib=50)
    ok(A, {"op": "checkpoint", "name": n, "dir": path, "stop": True})
    left = [f for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging-")]
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
    # Straight to the daemon: the CLI would retry on the peer for a while.
    r = rpc(A, {"op": "exec", "name": n, "cmd": "echo hi"})
    check("pause: exec refused while paused", not r["ok"] and "not running" in r["error"], r)
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
    # Stall the pull: a resume on the target must wait for all its memory.
    fault(A, "pages", 2000)
    t = time.time()
    r = ok(B, {"op": "resume", "name": n})
    waited = time.time() - t
    st = wait_released(B, n)
    check("paused migrate: resume waited for the whole pull", waited > 1.0 and st["background_pull_ms"] is not None
          and st["background_pull_ms"] <= waited * 1000 + 100, (waited, st))
    check("paused migrate: source released, only on B", where(n) == {B: "running"} and st["released"] is True, (where(n), st))
    check("paused migrate: runs on B after resume, md5 intact", md5(B, n) == m)
    cleanup(n)


def busy_guest(host, name):
    """Floods the network (UDP to the gateway) and churns memory (freed
    pages go back through balloon free page reporting) in the background."""
    code, out = sh(host, name, "(while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done | socat -u - UDP:169.254.1.1:9) "
                   ">/dev/null 2>&1 < /dev/null & "
                   "(while :; do head -c 200M /dev/zero > /dev/shm/churn; rm -f /dev/shm/churn; done) "
                   ">/dev/null 2>&1 < /dev/null & echo ok")
    assert code == 0, out


def tap_frames(host, name):
    """Frames the VM's Firecracker has put on its tap (and taken off it)."""
    tap = vms(host)[name]["tap"]
    read = lambda what: int(open(f"/sys/class/net/{tap}/statistics/{what}").read())
    return read("rx_packets"), read("tx_packets")


def guest_healthy(host, name, label, m):
    code, out = sh(host, name, "dmesg | grep -ciE 'virtio.*(error|bad|broken|timeout)|bug:|corrupt' ; true")
    check(f"{label}: guest answers, no virtio errors", code == 0 and out.strip() == "0", out)
    before = tap_frames(host, name)[0]
    time.sleep(0.5)
    check(f"{label}: guest network still sending", tap_frames(host, name)[0] > before + 10, (before, tap_frames(host, name)))
    check(f"{label}: md5 intact", md5(host, name) == m)


def vsock_path(host, name):
    """The vsock socket of `name`'s Firecracker on `host`, its only VM."""
    return os.path.join(os.path.dirname(api_sock(host, name)), "v.sock")


def held_restore_frozen():
    """A checkpoint restored with --paused (loaded with resume_vm:false) is
    held paused with its devices frozen too: while frames arrive on its tap,
    a host vsock connection is pending and the balloon statistics timer is
    due, not a byte of its memory changes and no frame moves. After resume,
    all of it proceeds. With the hold skipped (test fault restore_no_hold),
    the same activity does change guest memory: that is the gap the hold
    closes."""
    n, path = "ft-held", ckpt_path("ft-held")
    m = setup(n)
    busy_guest(A, n)
    time.sleep(0.5)
    old_ip = vms(A)[n]["ip"]
    ok(A, {"op": "checkpoint", "name": n, "dir": path, "stop": True})

    def held(no_hold):
        fault(B, "restore_no_hold", 600000 if no_hold else 0)
        r = ok(B, {"op": "restore", "dir": path, "paused": True})
        fault(B, "restore_no_hold", 0)
        check(f"held{'(no hold)' if no_hold else ''}: restored paused", r["state"] == "paused" and vms(B)[n]["state"] == "paused", r)
        wait_for(lambda: ok(B, {"op": "memhash", "name": n})["remote"] == 0, 30)
        ip = vm_ip(B, n)
        h0, f0 = ok(B, {"op": "memhash", "name": n}), tap_frames(B, n)
        # Pending host activity: frames on the tap, a vsock connection, and
        # the balloon statistics timer (every second).
        conn = subprocess.Popen(["sudo", "python3", "-c",
                                 "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); "
                                 "s.sendall(b'CONNECT 52\\nPING\\n'); s.settimeout(30); d=b''\nwhile b'pong' not in d:\n c=s.recv(200)\n if not c: break\n d+=c\nprint(d)",
                                 vsock_path(B, n)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(30):
            udp.sendto(b"x" * 64, (ip, 9))
            time.sleep(0.1)
        h1, f1 = ok(B, {"op": "memhash", "name": n}), tap_frames(B, n)
        return h0, h1, f0, f1, conn

    h0, h1, f0, f1, conn = held(False)
    check("held: guest memory unchanged under tap, vsock and timer activity", h0 == h1, (h0, h1))
    check("held: no frames moved", f0 == f1, (f0, f1))
    check("held: vsock connection waits", conn.poll() is None)
    t = time.time()
    ok(B, {"op": "resume", "name": n})
    out, _ = conn.communicate(timeout=30)
    check("held: pending vsock connection answered after resume", "OK" in out and "pong" in out, out)
    time.sleep(0.5)
    check("held: pending frames delivered after resume", tap_frames(B, n)[1] > f1[1], (f1, tap_frames(B, n)))
    guest_healthy(B, n, "held after resume", m)
    print(f"held: resumed and answered within {time.time() - t:.2f} s")
    rpc(B, {"op": "kill", "name": n})
    # Held at a new address: the guest takes it on resume (and only then).
    r = ok(B, {"op": "restore", "dir": path, "paused": True, "ip": "auto"})
    refused = rpc(B, {"op": "checkpoint", "name": n, "dir": path + "-x"})
    check("held at a new address: no checkpoint before it takes the address", not refused["ok"], refused)
    ok(B, {"op": "resume", "name": n})
    code, out = sh(B, n, "ip -4 -o addr show eth0")
    check("held at a new address: guest has it, and only it, after resume", r["ip"] in out and old_ip not in out, (r["ip"], old_ip, out))
    rpc(B, {"op": "kill", "name": n})

    h0, h1, f0, f1, conn = held(True)
    check("no hold (control): the same activity changes guest memory", h0 != h1 or f0 != f1, (h0, h1, f0, f1))
    conn.kill()
    rpc(B, {"op": "kill", "name": n})
    rm_ckpt(path)


def api_sock(host, name):
    """The API socket of `name`'s Firecracker on `host`, found by the pid
    `ls` reports (the run directory also holds idle and hot-pool ones)."""
    pid = str(vms(host)[name]["pid"])
    assert pid in firecrackers(run_dir(host)), (pid, firecrackers(run_dir(host)))
    argv = proc(pid, "cmdline").split(b"\0")
    return argv[argv.index(b"--api-sock") + 1].decode()


def fc_api(sock, method, path, body=None):
    cmd = ["sudo", "curl", "-s", "--unix-socket", sock, "-X", method, f"http://localhost{path}"]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else None


def checkpoint_hotplug():
    """A virtio-mem resize still in flight when a checkpoint starts: the
    checkpoint waits for the guest to carry it out (no device request can
    land behind the saved state), and the result restores intact."""
    n, path = "ft-hotplug", ckpt_path("ft-hotplug")
    m = setup(n)
    sock = api_sock(A, n)
    hp = fc_api(sock, "GET", "/hotplug/memory")
    want = hp["plugged_size_mib"] + 1024
    fc_api(sock, "PATCH", "/hotplug/memory", {"requested_size_mib": want})
    r = ok(A, {"op": "checkpoint", "name": n, "dir": path, "stop": True})
    print(f"hotplug: settled in {r['timings_ms']['settle_hotplug']} ms")
    check("hotplug: checkpoint waited for the resize", r["timings_ms"]["settle_hotplug"] > 1, r["timings_ms"])
    text = subprocess.run(["sudo", "cat", f"{path}/manifest.json"], capture_output=True).stdout
    plugged = json.loads(text.split(b"\n", 1)[1])["hotplug_mib"]
    check("hotplug: saved with the resize done", plugged == want, (plugged, want))
    ok(B, {"op": "restore", "dir": path})
    check("hotplug: restores intact", md5(B, n) == m)
    cleanup(n)
    rm_ckpt(path)


def checkpoint_untrusted_dir():
    """Checkpoints into a user's directory: the files are theirs, nothing is
    left behind, and a restore never follows a symlink planted in one."""
    n, path = "ft-user", ckpt_path("ft-user")
    setup(n, mib=20)
    ok(A, {"op": "checkpoint", "name": n, "dir": path, "stop": True})
    st = os.stat(path)
    check("untrusted dir: checkpoint belongs to the directory's owner", st.st_uid == os.getuid(), st.st_uid)
    left = [f for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging")]
    check("untrusted dir: no staging left behind", not left, left)
    os.rename(f"{path}/vmstate", f"{path}/vmstate.real")
    os.symlink(f"{path}/vmstate.real", f"{path}/vmstate")
    r = rpc(B, {"op": "restore", "dir": path})
    check("untrusted dir: restore refuses a symlinked file", not r["ok"] and "vmstate" in r["error"], r)
    os.unlink(f"{path}/vmstate")
    os.rename(f"{path}/vmstate.real", f"{path}/vmstate")
    r = rpc(B, {"op": "restore", "dir": path})
    check("untrusted dir: restores once it is a plain file again", r["ok"], r)
    cleanup(n)
    rm_ckpt(path)


def resume_failures():
    """A suspended VM whose resume fails before its vCPUs ran stays
    suspended; one that fails after they ran is gone, never re-armed (its
    checkpoint would replay what it did)."""
    n = "ft-resume-fail"
    m = setup(n)
    ok(A, {"op": "suspend", "name": n})
    fault(A, "restore_before_run", 60000)
    r = rpc(A, {"op": "resume", "name": n})
    fault(A, "restore_before_run", 0)
    check("resume fails before running: refused", not r["ok"], r)
    check("resume fails before running: still suspended", vms(A).get(n, {}).get("state") == "suspended", vms(A).get(n))
    ok(A, {"op": "resume", "name": n})
    check("resume fails before running: resumes later, md5 intact", md5(A, n) == m)
    ok(A, {"op": "suspend", "name": n})
    fault(A, "restore_after_run", 60000)
    r = rpc(A, {"op": "resume", "name": n})
    fault(A, "restore_after_run", 0)
    check("resume fails after running: refused", not r["ok"] and "consumed" in r["error"], r)
    check("resume fails after running: not re-armed", n not in vms(A), vms(A).get(n))
    r = rpc(A, {"op": "resume", "name": n})
    check("resume fails after running: no second resume", not r["ok"], r)
    cleanup(n)


def state_dir_lock():
    """A second daemon on A's --state-dir (with its own run dir and port)
    refuses to start before touching it; A's suspended VM is unharmed."""
    n = "ft-state-lock"
    m = setup(n, mib=20)
    ok(A, {"op": "suspend", "name": n})
    argv = [a.decode() for a in proc(daemon_pid(A), "cmdline").split(b"\0") if a]
    if "--state-dir" not in argv:
        return check("state dir lock: A runs with --state-dir", False, argv)
    bad = argv[:]
    bad[bad.index("--run") + 1] += "-other"
    host, port = A.rsplit(":", 1)
    bad[bad.index("--listen") + 1] = f"{host}:{int(port) + 50}"
    r = subprocess.run(["sudo", *bad], capture_output=True, text=True, timeout=30)
    check("state dir lock: second daemon refuses", r.returncode != 0 and "overlaps" in r.stderr, r.stderr.strip())
    subprocess.run(["sudo", "rm", "-rf", bad[bad.index("--run") + 1]])
    ok(A, {"op": "resume", "name": n})
    check("state dir lock: suspended VM unharmed", md5(A, n) == m)
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


def open_under(host, path):
    """Files under `path` the daemon on `host` still has open."""
    fds = subprocess.run(["sudo", "find", f"/proc/{daemon_pid(host)}/fd", "-type", "l", "-printf", "%l\n"],
                         capture_output=True, text=True).stdout.split("\n")
    return [f for f in fds if f.startswith(path.rstrip("/") + "/")]


def free_mib(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize >> 20


def suspend_disk_freed():
    """A resumed suspended VM gives its checkpoint's disk space back once
    every page is in (its pager lets go of the page file), while it runs on."""
    n = "ft-susp-disk"
    m = setup(n, mib=1024)
    r = ok(A, {"op": "suspend", "name": n})
    d, data = r["dir"], r["data_mib"]
    state = os.path.dirname(os.path.dirname(d))
    check("disk freed: checkpoint written", data >= 1000, r)
    before = free_mib(state)
    ok(A, {"op": "resume", "name": n})
    check("disk freed: paged back in", wait_for(lambda: vms(A)[n]["pages_mib"]["remote"] == 0, 60), vms(A)[n])
    gone = wait_for(lambda: subprocess.run(["sudo", "test", "-e", d]).returncode != 0, 30)
    check("disk freed: checkpoint deleted", gone)
    released = wait_for(lambda: not open_under(A, d), 10)
    check("disk freed: daemon holds no checkpoint file", released, open_under(A, d))
    after = free_mib(state)
    print(f"disk freed: {data} MiB checkpoint; free space {before} -> {after} MiB (+{after - before})")
    check("disk freed: its space came back", after - before >= data * 0.8, (before, after, data))
    check("disk freed: still running, md5 intact", vms(A)[n]["state"] == "running" and md5(A, n) == m)
    cleanup(n)


def resume_mark_fails():
    """A resume whose STARTED marker cannot be made durable takes it back
    durably and leaves the VM suspended; if taking it back fails too, the VM
    is quarantined (neither resumable nor deleted) until a kill, or until a
    daemon restart goes by what the disk holds."""
    n = "ft-mark-fail"
    m = setup(n, mib=20)
    d = ok(A, {"op": "suspend", "name": n})["dir"]
    exists = lambda f: subprocess.run(["sudo", "test", "-e", os.path.join(d, f)]).returncode == 0

    fault(A, "started_fsync", 60000)
    r = rpc(A, {"op": "resume", "name": n})
    fault(A, "started_fsync", 0)
    check("mark fails: resume refused", not r["ok"] and "quarantined" not in r["error"], r)
    check("mark fails: still suspended", vms(A).get(n, {}).get("state") == "suspended", vms(A).get(n))
    check("mark fails: marker taken back", not exists("STARTED") and exists("manifest.json"))
    ok(A, {"op": "resume", "name": n})
    check("mark fails: resumes later, md5 intact", md5(A, n) == m)

    d = ok(A, {"op": "suspend", "name": n})["dir"]
    fault(A, "started_fsync", 60000)
    fault(A, "started_unmark", 60000)
    r = rpc(A, {"op": "resume", "name": n})
    disarm()
    check("unmark fails: resume refused, quarantined", not r["ok"] and "quarantined" in r["error"], r)
    v = vms(A).get(n, {})
    check("unmark fails: listed quarantined, with why", v.get("state") == "quarantined" and "removing the mark" in (v.get("quarantine") or ""), v)
    r = rpc(A, {"op": "resume", "name": n})
    check("unmark fails: no resume while quarantined", not r["ok"] and "quarantined" in r["error"], r)
    check("unmark fails: checkpoint kept", exists("manifest.json"))
    argv, env = kill_daemon(A)
    start_daemon(A, argv, env)
    check("unmark fails: after a restart, suspended again (no marker on disk)", vms(A).get(n, {}).get("state") == "suspended", vms(A).get(n))
    ok(A, {"op": "resume", "name": n})
    check("unmark fails: then resumes, md5 intact", md5(A, n) == m)

    # The other outcome: the marker did reach the disk (started_unmark
    # unlinks it, so put it back as a crash could have left it). A restart
    # then cannot tell it from a resumed VM's and deletes the checkpoint:
    # the VM is lost, never replayed.
    d = ok(A, {"op": "suspend", "name": n})["dir"]
    fault(A, "started_fsync", 60000)
    fault(A, "started_unmark", 60000)
    rpc(A, {"op": "resume", "name": n})
    disarm()
    check("marker kept: quarantined", vms(A).get(n, {}).get("state") == "quarantined", vms(A).get(n))
    subprocess.run(["sudo", "touch", os.path.join(d, "STARTED")], check=True)
    argv, env = kill_daemon(A)
    start_daemon(A, argv, env)
    check("marker kept: gone after a restart, on both hosts", n not in vms(A) and n not in vms(B), (vms(A).get(n), vms(B).get(n)))
    check("marker kept: checkpoint deleted", subprocess.run(["sudo", "test", "-e", d]).returncode != 0)
    r = rpc(A, {"op": "resume", "name": n})
    check("marker kept: no resume (nothing replays)", not r["ok"], r)
    m = setup(n, mib=20)

    d = ok(A, {"op": "suspend", "name": n})["dir"]
    fault(A, "started_fsync", 60000)
    fault(A, "started_unmark", 60000)
    rpc(A, {"op": "resume", "name": n})
    disarm()
    check("quarantined kill: quarantined", vms(A).get(n, {}).get("state") == "quarantined", vms(A).get(n))
    ok(A, {"op": "kill", "name": n})
    check("quarantined kill: gone", n not in vms(A), vms(A).get(n))
    check("quarantined kill: checkpoint deleted", not exists("manifest.json"))
    r = rpc(A, {"op": "resume", "name": n})
    check("quarantined kill: no resume", not r["ok"], r)
    cleanup(n)


# --- copy-on-write and incremental checkpoints --------------------------------
#
# memwriter (scripts/memwriter.c) rewrites guest memory continuously, each
# page stamped with its iteration and a random salt, and checks every page
# against its own record before rewriting it; on SIGUSR1 each thread stops at
# an iteration boundary and checks all its pages (see the source). A restored
# copy that finds nothing wrong was saved exactly as it was at the pause. The
# daemon's ckpt_memhash fault also hashes guest memory during the pause, which
# must equal the hash of what the checkpoint restores (`ckhash`).

_memwriter = None


def memwriter_b64():
    global _memwriter
    if _memwriter is None:
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "memwriter.c")
        out = os.path.join(tempfile.mkdtemp(prefix="memwriter-"), "memwriter")
        cc = "musl-gcc" if subprocess.run(["which", "musl-gcc"], capture_output=True).returncode == 0 else "gcc"
        subprocess.run([cc, "-O2", "-static", "-mrdrnd", "-pthread", "-o", out, src], check=True)
        _memwriter = base64.b64encode(open(out, "rb").read()).decode()
    return _memwriter


def start_writer(host, name, mib=64, threads=2):
    # Keep each argv entry well below Linux's per-argument limit, including
    # when gcc's static libc makes the payload much larger than musl's.
    payload = memwriter_b64()
    for i in range(0, len(payload), 48000):
        redir = ">" if i == 0 else ">>"
        code, out = sh(host, name, f"printf '%s' '{payload[i:i + 48000]}' {redir} /tmp/memwriter.b64")
        assert code == 0, out
    code, out = sh(host, name, "base64 -d /tmp/memwriter.b64 > /tmp/memwriter && rm /tmp/memwriter.b64 && chmod +x /tmp/memwriter && "
                               f"setsid /tmp/memwriter {mib} {threads} /tmp/mw.status >/dev/null 2>&1 < /dev/null & sleep 1; pidof memwriter")
    assert code == 0 and out.strip(), out


def writer_check(host, name):
    """Has the writer check all its memory at a quiesced instant; returns
    (errors found continuously or in the check, iterations, status text)."""
    code, out = sh(host, name, "p=$(pidof memwriter) || exit 1; s=$(head -1 /tmp/mw.status 2>/dev/null); kill -USR1 $p; "
                               "for i in $(seq 1 600); do t=$(head -1 /tmp/mw.status 2>/dev/null); [ \"$t\" != \"$s\" ] && break; sleep 0.05; done; "
                               "[ \"$t\" != \"$s\" ] && cat /tmp/mw.status")
    rows = [l.split() for l in out.splitlines() if l.startswith("thread")]
    if code != 0 or not rows:
        return None, 0, out
    errors = sum(int(r[r.index("cont_errors") + 1]) + int(r[r.index("full_errors") + 1]) for r in rows)
    return errors, sum(int(r[r.index("k") + 1]) for r in rows), out


def cow_exact():
    """A keep-running checkpoint of a guest that rewrites its memory all the
    time: the VM pauses only briefly and works during the copy, and the
    checkpoint holds exactly its memory at the pause."""
    n, path = "ft-cow", ckpt_path("ft-cow")
    ok(A, {"op": "run", "name": n, "template": args.template})
    start_writer(A, n, mib=64)
    fault(A, "ckpt_memhash", 120000)
    fault(A, "ckpt_slow", 120000)
    res = {}
    t = threading.Thread(target=lambda: res.update(r=rpc(A, {"op": "checkpoint", "name": n, "dir": path}, timeout=300)))
    t.start()
    copying = wait_for(lambda: vms(A).get(n, {}).get("checkpoint_copy"), 30)
    check("cow: copy runs in the background", copying, vms(A).get(n))
    if copying:
        _, k0, _ = writer_check(A, n)
        code, out = sh(A, n, "echo alive")
        _, k1, _ = writer_check(A, n)
        check("cow: the VM runs during the copy (exec, writer progress)", code == 0 and k1 > k0, (code, out, k0, k1))
    t.join()
    fault(A, "ckpt_slow", 0)
    r = res.get("r", {})
    check("cow: checkpoint written", r.get("ok"), r)
    if not r.get("ok"):
        return cleanup(n)
    r = r["result"]
    print(f"cow: paused {r['paused_ms']} ms (with the test hash: {r['timings_ms'].get('memhash')} ms), "
          f"checkpoint {r['checkpoint_ms']} ms; copy {r['copy']}")
    pause = r["paused_ms"] - r["timings_ms"].get("memhash", 0)
    check("cow: paused only for the state save", pause < 200, r["timings_ms"])
    check("cow: guest wrote during the copy (write faults saved pages first)", r["copy"]["rescues"] > 0, r["copy"])
    h = ok(A, {"op": "ckhash", "dir": path})
    check("cow: checkpoint == memory at the pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
    errors, _, out = writer_check(A, n)
    check("cow: the original is intact", errors == 0, out)
    ok(B, {"op": "restore", "dir": path, "name": "ft-cow2", "ip": "auto"})
    errors, _, out = writer_check(B, "ft-cow2")
    check("cow: the restored copy has exactly the pause-time memory", errors == 0, out)
    fault(A, "ckpt_memhash", 0)
    cleanup(n)
    cleanup("ft-cow2")
    rm_ckpt(path)


def cow_grow():
    """A guest that needs more memory while a copy-on-write checkpoint of it
    is being copied gets it (growing does not wait for the copy): it fills
    2 GiB more than it had without an OOM, the checkpoint completes, and it
    holds exactly the memory and size at the pause. COW_GROW_TEMPLATE picks
    a template with little or nothing pre-plugged, so the guest must grow."""
    n, path = "ft-cow-grow", ckpt_path("ft-cow-grow")
    m = setup(n, mib=600, template=os.environ.get("COW_GROW_TEMPLATE"))
    v = vms(A)[n]
    plugged0, fill = v["plugged_mib"], v["guest_mib"] + 2048
    fault(A, "ckpt_memhash", 300000)
    fault(A, "ckpt_crawl", 300000)
    res, seen = {}, {"max": plugged0, "copying": False}
    t = threading.Thread(target=lambda: res.update(r=rpc(A, {"op": "checkpoint", "name": n, "dir": path}, timeout=600)))
    t.start()
    copying = wait_for(lambda: vms(A).get(n, {}).get("checkpoint_copy") and vms(A)[n]["state"] == "running", 60)
    check("cow grow: copy runs in the background", copying, vms(A).get(n))
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            try:
                v = vms(A).get(n, {})
                if v.get("checkpoint_copy"):
                    seen["copying"] = True
                    seen["max"] = max(seen["max"], v.get("plugged_mib") or 0)
            except (OSError, AssertionError):
                pass
            time.sleep(0.2)

    w = threading.Thread(target=watch)
    w.start()
    code, out = sh(A, n, f"python3 -c 'l=[bytearray(64<<20) for _ in range({fill}//64)]; print(len(l)*64)'")
    still = vms(A).get(n, {}).get("checkpoint_copy")
    stop.set()
    w.join()
    check("cow grow: the guest filled 2 GiB more than it had, no OOM", code == 0 and out == str(fill // 64 * 64), (code, out[-200:]))
    check("cow grow: it grew while the copy ran", seen["max"] >= plugged0 + 1024, (plugged0, seen))
    print(f"cow grow: plugged {plugged0} -> {seen['max']} MiB during the copy; copy still running after the fill: {still}")
    t.join()
    fault(A, "ckpt_crawl", 0)
    fault(A, "ckpt_memhash", 0)
    r = res.get("r", {})
    check("cow grow: checkpoint written", r.get("ok"), r)
    if r.get("ok"):
        r = r["result"]
        h = ok(A, {"op": "ckhash", "dir": path})
        check("cow grow: checkpoint == memory at the pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
        ok(B, {"op": "restore", "dir": path, "name": "ft-cow-grow2", "ip": "auto"})
        check("cow grow: restored at the size it had at the pause", vms(B)["ft-cow-grow2"]["plugged_mib"] == plugged0,
              (plugged0, vms(B)["ft-cow-grow2"]["plugged_mib"]))
        check("cow grow: restored file intact", md5(B, "ft-cow-grow2") == m)
        code, out = sh(B, "ft-cow-grow2", "python3 -c 'b=bytearray(512<<20); print(len(b)>>20)'")
        check("cow grow: restored guest can use memory", code == 0 and out == "512", out)
    check("cow grow: original still running, file intact", where(n) == {A: "running"} and md5(A, n) == m, where(n))
    cleanup(n)
    cleanup("ft-cow-grow2")
    rm_ckpt(path)


def cow_abort():
    """A copy that fails half way (and one that a kill cuts short) publishes
    nothing; the VM runs on unharmed, and the next checkpoint is complete."""
    n, path = "ft-cow-abort", ckpt_path("ft-cow-abort")
    ok(A, {"op": "run", "name": n, "template": args.template})
    start_writer(A, n, mib=64)
    ok(A, {"op": "checkpoint", "name": n, "dir": path + "-base"})
    fault(A, "ckpt_abort", 60000)
    r = rpc(A, {"op": "checkpoint", "name": n, "dir": path})
    fault(A, "ckpt_abort", 0)
    check("cow abort: checkpoint failed", not r["ok"] and "abort" in r["error"], r)
    check("cow abort: nothing published", not os.path.exists(path))
    check("cow abort: VM still running", where(n) == {A: "running"} and not vms(A)[n]["checkpoint_copy"], vms(A).get(n))
    errors, _, out = writer_check(A, n)
    check("cow abort: guest memory intact, writes flow", errors == 0, out)
    # The failed copy gave its dirty pages back: the base still holds.
    fault(A, "ckpt_memhash", 60000)
    r = ok(A, {"op": "checkpoint", "name": n, "dir": path, "incremental": True})
    fault(A, "ckpt_memhash", 0)
    check("cow abort: next checkpoint is an exact delta on the old base",
          r["parent"] is not None and ok(A, {"op": "ckhash", "dir": path})["hash"] == r["pause_memhash"], r["parent"])
    # A kill gives the copy up rather than waiting for it.
    fault(A, "ckpt_slow", 60000)
    res = {}
    t = threading.Thread(target=lambda: res.update(r=rpc(A, {"op": "checkpoint", "name": n, "dir": path + "-killed"}, timeout=300)))
    t.start()
    wait_for(lambda: vms(A).get(n, {}).get("checkpoint_copy"), 30)
    start = time.time()
    k = rpc(A, {"op": "kill", "name": n})
    took = time.time() - start
    t.join()
    fault(A, "ckpt_slow", 0)
    check("cow abort: kill during the copy is quick", k["ok"] and took < 10, (k, took))
    check("cow abort: killed copy published nothing", not res["r"]["ok"] and not os.path.exists(path + "-killed"), res)
    for p in (path, path + "-base", path + "-killed"):
        rm_ckpt(p)


def cow_crash():
    """The daemon dies while a running VM's checkpoint is being copied: no
    checkpoint appears, and the next one to the same place succeeds."""
    n, path = "ft-cow-crash", ckpt_path("ft-cow-crash")
    ok(A, {"op": "run", "name": n, "template": args.template})
    start_writer(A, n, mib=64)
    fault(A, "ckpt_slow", 120000)
    t = threading.Thread(target=lambda: rpc(A, {"op": "checkpoint", "name": n, "dir": path}, timeout=300))
    t.start()
    check("cow crash: caught the copy in the background", wait_for(lambda: vms(A).get(n, {}).get("checkpoint_copy"), 30))
    time.sleep(0.5)
    argv, env = kill_daemon(A)
    t.join()
    check("cow crash: no checkpoint published", not os.path.exists(path))
    r = rpc(B, {"op": "restore", "dir": path})
    check("cow crash: nothing to restore", not r["ok"], r)
    partial = [os.path.join(args.ckpt_dir, f, "ck") for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging-")]
    for f in partial:
        r = rpc(B, {"op": "restore", "dir": f})
        check("cow crash: the partial directory does not restore", not r["ok"], r)
    start_daemon(A, argv, env)
    check("cow crash: the VM died with its daemon", n not in vms(A), vms(A).get(n))
    ok(A, {"op": "run", "name": n, "template": args.template})
    start_writer(A, n, mib=16)
    ok(A, {"op": "checkpoint", "name": n, "dir": path})
    left = [f for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging-")]
    check("cow crash: next checkpoint cleared the debris", not left, left)
    ok(B, {"op": "restore", "dir": path, "name": n + "2", "ip": "auto"})
    errors, _, out = writer_check(B, n + "2")
    check("cow crash: next checkpoint restores intact", errors == 0, out)
    cleanup(n)
    cleanup(n + "2")
    rm_ckpt(path)


def ckpt_incremental():
    """A full checkpoint and two deltas of a running VM: each delta stores
    only what changed, each link of the chain restores exactly its pause-time
    memory, and a chain with a missing or replaced parent is refused."""
    n = "ft-inc"
    paths = [ckpt_path(f"ft-inc{i}") for i in range(3)]
    ok(A, {"op": "run", "name": n, "template": args.template})
    r = rpc(A, {"op": "checkpoint", "name": n, "dir": paths[0], "incremental": True})
    check("incremental: refused without a base", not r["ok"] and "build on" in r["error"], r)
    code, out = sh(A, n, "dd if=/dev/urandom of=/tmp/f bs=1M count=200 2>/dev/null; md5sum /tmp/f")
    m = out.split()[0]
    start_writer(A, n, mib=4)
    fault(A, "ckpt_memhash", 120000)
    res = []
    for i, p in enumerate(paths):
        r = ok(A, {"op": "checkpoint", "name": n, "dir": p, "incremental": i > 0})
        res.append(r)
        print(f"incremental {i}: paused {r['paused_ms']} ms, {r['data_mib']} MiB data, dirty {r['dirty_mib']} MiB, parent {r['parent']}")
        time.sleep(1)
    fault(A, "ckpt_memhash", 0)
    check("incremental: deltas store only what changed", all(r["data_mib"] < res[0]["data_mib"] / 4 for r in res[1:]),
          [r["data_mib"] for r in res])
    check("incremental: deltas name their parent", [r["parent"] for r in res] == [None, "../ft-inc0", "../ft-inc1"],
          [r["parent"] for r in res])
    for i, p in enumerate(paths):
        h = ok(A, {"op": "ckhash", "dir": p})
        check(f"incremental: link {i} == memory at its pause", h["hash"] == res[i]["pause_memhash"] and len(h["chain"]) == i, h)
    for i, x in ((2, "ft-inc3"), (1, "ft-inc2")):
        ok(B, {"op": "restore", "dir": paths[i], "name": x, "ip": "auto"})
        errors, _, out = writer_check(B, x)
        check(f"incremental: restore of link {i} intact", errors == 0 and md5(B, x).startswith(m), out)
        cleanup(x)
    # A VM that stops is never stopped onto a chain whose page data is bad.
    pages = os.path.join(paths[0], "pages")
    good = open(pages, "rb").read(4096)
    with open(pages, "r+b") as f:
        f.write(bytes([good[0] ^ 1]) + good[1:])
    r = rpc(A, {"op": "checkpoint", "name": n, "dir": paths[2] + "s", "incremental": True, "stop": True})
    check("incremental: no --stop delta onto corrupt parent data", not r["ok"] and "checksum" in r["error"] and not os.path.exists(paths[2] + "s"), r)
    check("incremental: VM runs on after that refusal", where(n) == {A: "running"}, where(n))
    with open(pages, "r+b") as f:
        f.write(good)
    # No delta onto a chain whose older ancestor has gone.
    os.rename(paths[0], paths[0] + ".moved")
    r = rpc(A, {"op": "checkpoint", "name": n, "dir": paths[2] + "x", "incremental": True})
    check("incremental: no delta onto a broken chain", not r["ok"] and "full one" in r["error"] and not os.path.exists(paths[2] + "x"), r)
    check("incremental: VM runs on after the refusal", where(n) == {A: "running"}, where(n))
    os.rename(paths[0] + ".moved", paths[0])
    # A replaced parent (same path, other contents) and a missing one.
    os.rename(paths[1], paths[1] + ".moved")
    r = rpc(B, {"op": "restore", "dir": paths[2], "name": "ft-inc4", "ip": "auto"})
    check("incremental: missing parent refused", not r["ok"] and "parent" in r["error"], r)
    subprocess.run(["sudo", "cp", "-a", paths[0], paths[1]], check=True)
    r = rpc(B, {"op": "restore", "dir": paths[2], "name": "ft-inc4", "ip": "auto"})
    check("incremental: replaced parent refused", not r["ok"] and "changed" in r["error"], r)
    rm_ckpt(paths[1])
    os.rename(paths[1] + ".moved", paths[1])
    cleanup(n)
    cleanup("ft-inc4")
    for p in paths:
        rm_ckpt(p)



def cow_wp_race():
    """#88: a write fault on a page that a checkpoint writer claims while
    the fault is being handled is retried once the page is saved, not
    dropped (which left the vCPU asleep for good). With the window widened
    (ckpt_wp_race), keep-running checkpoints of a guest rewriting its memory
    must leave every writer thread making progress."""
    n = "ft-wprace"
    ok(A, {"op": "run", "name": n, "template": args.template})
    start_writer(A, n, mib=64, threads=2)
    fault(A, "ckpt_wp_race", 600000)
    for i in range(8):
        path = ckpt_path(f"ft-wprace{i}")
        r = rpc(A, {"op": "checkpoint", "name": n, "dir": path}, timeout=120)
        rm_ckpt(path)
        check(f"wp race {i}: checkpoint written", r.get("ok"), r)
        if not r.get("ok"):
            break
        _, k0, _ = writer_check(A, n)
        time.sleep(0.5)
        errors, k1, out = writer_check(A, n)
        print(f"wp race {i}: paused {r['result']['paused_ms']} ms, copy {r['result']['copy']}")
        if not check(f"wp race {i}: every writer thread still runs, memory intact", errors == 0 and k1 > k0, (k0, k1, out)):
            break
    fault(A, "ckpt_wp_race", 0)
    cleanup(n)


def fetch_tail_enomem():
    """A run fetched for a fault whose tail fails to install (a transient
    error, after its first page went in and the pullers passed it) is
    fetched again rather than left REMOTE: the pull completes and the
    source lets go."""
    n = "ft-tail"
    m = setup(n, mib=200)
    fault(B, "fetch_tail_enomem", 60000)
    ok(A, {"op": "migrate", "name": n, "to": B})
    check("tail: memory intact after the migration", md5(B, n) == m)
    st = wait_released(B, n, 30)
    check("tail: every page arrives and the source lets go",
          st["released"] is True and st["background_pull_ms"] is not None and st["failed"] is None, st)
    fault(B, "fetch_tail_enomem", 0)
    cleanup(n)


def fetch_enomem_stuck():
    """Pages a fault needs that keep failing to install (ENOMEM on every
    copy, the pullers held off) make the target give up within the fault
    deadline and report the VM failed, however the pages get claimed again
    (by the waiting fault or by the requeue), instead of leaving the vCPU
    blocked for good."""
    n = "ft-stuck"
    setup(n, mib=400)
    fault(B, "fetch_enomem_stuck", 60000)
    ok(A, {"op": "migrate", "name": n, "to": B})
    t0 = time.time()
    threading.Thread(target=lambda: sh(B, n, "md5sum /tmp/f"), daemon=True).start()
    st = {}

    def failed():
        st.update(rpc(B, {"op": "migration_status", "name": n}).get("result") or {})
        return st.get("state") == "failed"

    gave_up = wait_for(failed, 20)
    took = time.time() - t0
    fault(B, "fetch_enomem_stuck", 0)
    check(f"stuck: target gave up ({took:.1f} s) and reports the vm failed", gave_up and "installing pages" in (st.get("failed") or ""),
          {k: st.get(k) for k in ("state", "failed", "released")})
    cleanup(n)


def cow_reports_held():
    """Exercise Firecracker's report hold and the pager's REMOVE fallback
    with disk writers gated until the guest has freed memory."""
    n, path = "ft-cow-fpr", ckpt_path("ft-cow-fpr")
    ok(A, {"op": "run", "name": n, "template": args.template})
    start_writer(A, n, mib=16)
    for held in (True, False):
        label = "cow fpr hold" if held else "cow fpr fallback"
        code, out = sh(A, n, "head -c 384M /dev/zero > /dev/shm/big && sleep 2 && head -c 384M /dev/zero > /dev/shm/big2 && echo ok")
        assert code == 0, out
        time.sleep(4)
        fault(A, "ckpt_memhash", 120000)
        fault(A, "ckpt_copy_wait", 120000)
        fault(A, "ckpt_no_hold", 0 if held else 120000)
        res, freed = {}, {}
        t = threading.Thread(target=lambda: res.update(r=rpc(A, {"op": "checkpoint", "name": n, "dir": path}, timeout=300)))
        t.start()
        def copying_and_running():
            vm = vms(A).get(n, {})
            return vm.get("checkpoint_copy") and vm.get("state") == "running"

        copying = wait_for(copying_and_running, 30)
        check(f"{label}: copy armed, guest running", copying, vms(A).get(n))
        if not copying:
            fault(A, "ckpt_copy_wait", 0)
            t.join()
            fault(A, "ckpt_no_hold", 0)
            fault(A, "ckpt_memhash", 0)
            break
        rss0 = vms(A)[n]["rss_mib"]
        free = threading.Thread(target=lambda: freed.update(result=sh(A, n, "rm /dev/shm/big /dev/shm/big2 && echo freed")))
        free.start()
        try:
            if held:
                free.join(timeout=30)
                check(f"{label}: guest frees memory during the copy", freed.get("result") == (0, "freed"), freed)
                # Allow the guest's delayed free-page reporter to enqueue work.
                time.sleep(4)
                vm = vms(A)[n]
                check(f"{label}: freed memory held during the copy",
                      vm.get("checkpoint_copy") and vm["rss_mib"] > rss0 - 256, (rss0, vm))
            else:
                # A queued REMOVE reaches the pager while writers cannot finish.
                observed = wait_for(lambda: (vms(A)[n].get("checkpoint_copy_stats") or {}).get("discards_held", 0) > 0, 30)
                check(f"{label}: discard held while the copy is running", observed and vms(A)[n].get("checkpoint_copy"), vms(A)[n])
                free.join(timeout=30)
                check(f"{label}: guest freed memory before writers were released",
                      freed.get("result") == (0, "freed") and vms(A)[n].get("checkpoint_copy"), freed)
        finally:
            fault(A, "ckpt_copy_wait", 0)
        free.join()
        t.join()
        fault(A, "ckpt_no_hold", 0)
        fault(A, "ckpt_memhash", 0)
        check(f"{label}: guest free completed", freed.get("result") == (0, "freed"), freed)
        r = res.get("r", {})
        check(f"{label}: checkpoint written", r.get("ok"), r)
        if r.get("ok"):
            r = r["result"]
            check(f"{label}: expected discard path exercised",
                  r["copy"]["discards_held"] == 0 if held else r["copy"]["discards_held"] > 0, r["copy"])
            h = ok(A, {"op": "ckhash", "dir": path})
            check(f"{label}: checkpoint == memory at the pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
        check(f"{label}: reports carried out after the copy", wait_for(lambda: vms(A)[n]["rss_mib"] < rss0 - 512, 20),
              (rss0, vms(A)[n]["rss_mib"]))
        rm_ckpt(path)
    code, out = sh(A, n, "head -c 384M /dev/zero > /dev/shm/big && echo ok")
    rss2 = vms(A)[n]["rss_mib"]
    sh(A, n, "rm /dev/shm/big")
    check("cow fpr: reporting returns memory after the copy", code == 0 and wait_for(lambda: vms(A)[n]["rss_mib"] < rss2 - 256, 20),
          (rss2, vms(A)[n]["rss_mib"]))
    errors, _, out = writer_check(A, n)
    check("cow fpr: guest memory intact", errors == 0, out)
    cleanup(n)
    rm_ckpt(path)


def ckpt_failed_stop():
    """A paused (--stop) checkpoint that fails after the freeze must leave
    write tracking whole: pages the guest wrote since the last checkpoint
    stay dirty (they are unprotected), so later checkpoints, full or delta,
    still hold exactly the memory at their pause."""
    n, path = "ft-failstop", ckpt_path("ft-failstop")
    for x in ("-base", "-stop", "-delta", "-full"):
        rm_ckpt(path + x)
    ok(A, {"op": "run", "name": n, "template": args.template})
    start_writer(A, n, mib=32)
    ok(A, {"op": "checkpoint", "name": n, "dir": path + "-base"})
    time.sleep(1)  # the writer unprotects (and dirties) pages
    fault(A, "ckpt_fail_write", 60000)
    r = rpc(A, {"op": "checkpoint", "name": n, "dir": path + "-stop", "stop": True})
    fault(A, "ckpt_fail_write", 0)
    check("failed stop: refused, nothing published", not r["ok"] and "injected" in r["error"] and not os.path.exists(path + "-stop"), r)
    check("failed stop: VM runs on", where(n) == {A: "running"}, where(n))
    time.sleep(1)
    fault(A, "ckpt_memhash", 120000)
    for label, inc in (("delta", True), ("full", False)):
        p = f"{path}-{label}"
        r = ok(A, {"op": "checkpoint", "name": n, "dir": p, "incremental": inc})
        h = ok(A, {"op": "ckhash", "dir": p})
        check(f"failed stop: next {label} checkpoint == memory at its pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
        ok(B, {"op": "restore", "dir": p, "name": n + "2", "ip": "auto"})
        errors, _, out = writer_check(B, n + "2")
        check(f"failed stop: restored {label} intact", errors == 0, out)
        cleanup(n + "2")
    fault(A, "ckpt_memhash", 0)
    cleanup(n)
    for x in ("-base", "-stop", "-delta", "-full"):
        rm_ckpt(path + x)



def ckpt_rearm():
    """A failed re-protection turns write tracking off; the next checkpoint
    re-arms it, which forgets which pages changed since the last good one.
    Even if that checkpoint fails too, no delta may then build on the old
    base: the next is full, and deltas resume from it, exact."""
    n, path = "ft-rearm", ckpt_path("ft-rearm")
    for x in "abcd":
        rm_ckpt(f"{path}-{x}")
    ok(A, {"op": "run", "name": n, "template": args.template})
    start_writer(A, n, mib=32)
    ok(A, {"op": "checkpoint", "name": n, "dir": path + "-a"})
    time.sleep(1)
    fault(A, "ckpt_fail_protect", 60000)
    r = rpc(A, {"op": "checkpoint", "name": n, "dir": path + "-b"})
    fault(A, "ckpt_fail_protect", 0)
    check("rearm: failed re-protection refused", not r["ok"] and "injected" in r["error"], r)
    fault(A, "ckpt_fail_write", 60000)
    r = rpc(A, {"op": "checkpoint", "name": n, "dir": path + "-b"})
    fault(A, "ckpt_fail_write", 0)
    check("rearm: re-armed checkpoint failed as injected", not r["ok"] and "injected" in r["error"], r)
    r = rpc(A, {"op": "checkpoint", "name": n, "dir": path + "-b", "incremental": True})
    check("rearm: no delta on the base from before the re-arm", not r["ok"] and "build on" in r["error"], r)
    fault(A, "ckpt_memhash", 120000)
    for label, inc in (("c", False), ("d", True)):
        r = ok(A, {"op": "checkpoint", "name": n, "dir": path + "-" + label, "incremental": inc})
        h = ok(A, {"op": "ckhash", "dir": path + "-" + label})
        check(f"rearm: {'delta' if inc else 'full'} afterwards == memory at its pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
    fault(A, "ckpt_memhash", 0)
    ok(B, {"op": "restore", "dir": path + "-d", "name": n + "2", "ip": "auto"})
    errors, _, out = writer_check(B, n + "2")
    check("rearm: restored delta intact", errors == 0, out)
    cleanup(n)
    cleanup(n + "2")
    for x in "abcd":
        rm_ckpt(f"{path}-{x}")



def ckpt_dir_moved():
    """The destination's directory is renamed while a checkpoint is written:
    nothing is published (in either place), and a delta checks its parent in
    the directory it is written into, not by a path that moved."""
    n = "ft-moved"
    top = os.path.join(args.ckpt_dir, "moved")
    for d in (top, top + "2"):
        rm_ckpt(d)
    os.makedirs(top)
    ok(A, {"op": "run", "name": n, "template": args.template})
    start_writer(A, n, mib=32)
    ok(A, {"op": "checkpoint", "name": n, "dir": os.path.join(top, "base")})
    fault(A, "ckpt_slow", 120000)
    res = {}
    t = threading.Thread(target=lambda: res.update(r=rpc(A, {"op": "checkpoint", "name": n, "dir": os.path.join(top, "d1"), "incremental": True}, timeout=300)))
    t.start()
    wait_for(lambda: vms(A).get(n, {}).get("checkpoint_copy"), 30)
    os.rename(top, top + "2")
    t.join()
    fault(A, "ckpt_slow", 0)
    r = res.get("r", {})
    check("moved dir: checkpoint refused", not r.get("ok") and "was moved or replaced" in r.get("error", ""), r)
    check("moved dir: nothing published anywhere", not os.path.exists(os.path.join(top, "d1")) and not os.path.exists(os.path.join(top + "2", "d1")))
    check("moved dir: VM runs on", where(n) == {A: "running"}, where(n))
    cleanup(n)
    for d in (top, top + "2"):
        rm_ckpt(d)


# --- two-step migration (migrate_in) ---------------------------------------


def migrate_in_raw(host, name, ip, source, template=None, gen="now"):
    """Asks `host` to prepare an incoming migration as a source would, for a
    VM like `source` (its template id and memory regions, from `source_vm`),
    by default with an address generation newer than any before (the time
    in ms; None sends none). Returns the open socket and the prepare reply."""
    template_id, regions = source
    h, port = host.rsplit(":", 1)
    s = socket.create_connection((h, int(port)), timeout=60)
    mig = int.from_bytes(os.urandom(6), "little")
    req = {"op": "migrate_in", "name": name, "mig": mig, "template": template or args.template, "id": template_id,
           "ip": ip, "source": A, "regions": regions}
    if gen is not None:
        req["gen"] = int(time.time() * 1000) if gen == "now" else gen
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        d = s.recv(65536)
        if not d:
            break
        buf += d
    return s, (json.loads(buf) if buf else {"ok": False, "error": "hung up"}), mig


def nothing_left(label, name, ip):
    """B holds neither the name nor the address after an abandoned migration."""
    check(f"{label}: name free on B", wait_for(lambda: name not in vms(B), 10), vms(B).get(name))
    check(f"{label}: address free on B", wait_for(lambda: ip not in ok(B, {"op": "info"})["ips"], 10))
    # Not B's to hand out, but another migration may bring it.
    s, r, _ = migrate_in_raw(B, name, ip, source_vm())
    check(f"{label}: name and address usable on B", r.get("ok"), r)
    s.close()
    check(f"{label}: and free again", wait_for(lambda: ip not in ok(B, {"op": "info"})["ips"] and name not in vms(B), 10))


def source_vm():
    """The template id and memory regions a source would send for a VM of the template."""
    n = "ft-tplid"
    ok(A, {"op": "run", "name": n, "template": args.template})
    v = vms(A)[n]
    rpc(A, {"op": "kill", "name": n})
    return v["template_id"], v["regions"]


def prepare_disconnect():
    """A source that goes away after the target prepared leaves nothing behind."""
    n, ip = "ft-prep-gone", "10.250.0.7"
    s, r, mig = migrate_in_raw(B, n, ip, source_vm())
    check("prepare disconnect: target prepared", r.get("ok"), r)
    info = ok(B, {"op": "info"})
    check("prepare disconnect: address held while prepared", ip in info["ips"], (info["ips"], vms(B).get(n)))
    s.close()
    nothing_left("prepare disconnect", n, ip)
    st = ok(B, {"op": "migration", "mig": mig})
    check("prepare disconnect: migration fenced as aborted", st["outcome"] == "aborted", st)


def prepare_trickle():
    """A source that trickles its header is cut off by one deadline (here 2 s,
    `short_incoming`), however much it keeps sending."""
    n, ip = "ft-prep-trickle", "10.250.0.8"
    fault(B, "short_incoming", 30000)
    s, r, _ = migrate_in_raw(B, n, ip, source_vm())
    check("prepare trickle: target prepared", r.get("ok"), r)
    start, cut = time.time(), False
    try:
        for c in b'{"runs": [' + b"[1, 1, 3], " * 100:
            s.sendall(bytes([c]))
            time.sleep(0.05)
            if time.time() - start > 15:
                break
    except OSError:
        cut = True
    s.settimeout(10)
    try:
        reply = s.recv(65536)
    except OSError:
        reply = b""
    took = time.time() - start
    s.close()
    fault(B, "short_incoming", 0)
    check("prepare trickle: cut off by the deadline", (cut or b"too slow" in reply) and took < 12, (took, reply[:200]))
    nothing_left("prepare trickle", n, ip)


def prepare_fail():
    """A target that fails once everything is prepared refuses before the
    source pauses; the VM never stops running."""
    n = "ft-prep-fail"
    m = setup(n)
    fault(B, "prepare_fail", 10000)
    r = rpc(A, {"op": "migrate", "name": n, "to": B})
    fault(B, "prepare_fail", 0)
    check("prepare fail: migrate refused", not r["ok"] and "injected fault" in r["error"], r)
    check("prepare fail: running on A only", where(n) == {A: "running"}, where(n))
    check("prepare fail: md5 intact", md5(A, n) == m)
    ip = vms(A)[n]["ip"]
    check("prepare fail: target holds nothing", n not in vms(B) and ip not in ok(B, {"op": "info"})["ips"])
    r = rpc(A, {"op": "migrate", "name": n, "to": B})
    check("prepare fail: a later migration works", r["ok"] and where(n).get(B) == "running", r)
    wait_released(B, n)
    check("prepare fail: md5 intact on B", md5(B, n) == m)
    cleanup(n)


def fc_prepare():
    """Firecracker's prepared load (firecracker/0002-*.patch): refuses a second
    prepare, a snapshot of another layout, and a load after boot config."""
    argv = [a.decode() for a in proc(daemon_pid(A), "cmdline").split(b"\0") if a]
    art = argv[argv.index("--artifacts") + 1] if "--artifacts" in argv else "artifacts"
    tpls = argv[argv.index("--templates") + 1] if "--templates" in argv else os.path.join(art, "templates")
    fc = os.path.join(art, "firecracker")
    other = "small" if args.template != "small" else "default"
    vmstate = lambda t: os.path.join(tpls, t, "vmstate")
    if not os.path.exists(vmstate(other)):
        return print(f"fc prepare: skipped, no template {other!r} to mismatch with")

    def run(label, steps):
        d = tempfile.mkdtemp(prefix="fvp", dir="/tmp")
        os.chmod(d, 0o777)
        uffd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        uffd.bind(f"{d}/u.sock")
        os.chmod(f"{d}/u.sock", 0o777)
        uffd.listen(1)
        held = []
        threading.Thread(target=lambda: held.append(uffd.accept()), daemon=True).start()
        p = subprocess.Popen(["sudo", fc, "--api-sock", f"{d}/api.sock", "--level", "Warn"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for(lambda: os.path.exists(f"{d}/api.sock"), 5)

        def put(path, body):
            r = subprocess.run(["sudo", "curl", "-s", "-o", "/dev/stderr", "-w", "%{http_code}", "--unix-socket",
                                f"{d}/api.sock", "-X", "PUT", f"http://x{path}", "-d", json.dumps(body)],
                               capture_output=True, text=True, timeout=30)
            return int(r.stdout or 0), r.stderr

        load = lambda t: {"snapshot_path": vmstate(t), "mem_backend": {"backend_type": "Uffd", "backend_path": f"{d}/u.sock"},
                          "vsock_override": {"uds_path": f"{d}/v.sock"}}
        try:
            code, body = put("/snapshot/prepare", load(args.template))
            if code == 400 and "Invalid request" in body:
                return print("fc prepare: skipped, Firecracker without the prepare patch (flexvm falls back to a full load)")
            check(f"fc prepare ({label}): prepared", code == 204, (code, body))
            steps(put, load)
        finally:
            subprocess.run(["sudo", "kill", "-9", str(p.pid)])
            p.wait()
            subprocess.run(["sudo", "rm", "-rf", d])

    def twice(put, load):
        code, body = put("/snapshot/prepare", load(args.template))
        check("fc prepare: a second prepare is refused", code == 400, (code, body))

    def mismatch(put, load):
        code, body = put("/snapshot/load", load(other))
        check("fc prepare: a snapshot of another layout is refused", code == 400 and "differs" in body, (code, body))

    def config_between(put, load):
        put("/boot-source", {"kernel_image_path": "/nonexistent"})
        code, body = put("/snapshot/load", load(args.template))
        check("fc prepare: a load after boot config is refused", code == 400, (code, body))

    run("twice", twice)
    run("mismatch", mismatch)
    run("config", config_between)


def slow_preload():
    """The pages preloaded with the vmstate arrive late (`slow_preload`): the
    target's load goes ahead (fetching what it needs itself), but it commits
    and answers only once they are all in, and the held packets still follow
    its answer on the same connection, in order."""
    n = "ft-slow-preload"
    m = setup(n)
    ip = vms(A)[n]["ip"]
    stop = threading.Event()

    def flood():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop.is_set():
            try:
                s.sendto(b"x" * 64, (ip, 9))
            except OSError:
                pass
            time.sleep(0.0005)

    t = threading.Thread(target=flood, daemon=True)
    t.start()
    time.sleep(0.2)
    fault(A, "slow_preload", 10000)
    r = rpc(A, {"op": "migrate", "name": n, "to": B})
    fault(A, "slow_preload", 0)
    stop.set()
    t.join()
    check("slow preload: migrated", r["ok"], r)
    res = r.get("result", {})
    check("slow preload: committed only after the late pages", res.get("downtime_ms", 0) >= 300, res.get("downtime_ms"))
    held = res.get("held") or {}
    check("slow preload: held packets followed the answer intact",
          held.get("packets", 0) > 0 and held.get("injected") == held.get("packets") and held.get("dropped_target") == 0, held)
    st = wait_released(B, n)
    check("slow preload: released, only on B", st["released"] is True and where(n) == {B: "running"}, (st, where(n)))
    check("slow preload: md5 intact", md5(B, n) == m)
    cleanup(n)


def ckpt_packet_hold():
    """Packets for a VM that arrive while a keep-running checkpoint has it
    paused are held and handed to it, not lost on its downed tap: a 1 kHz
    UDP sequence stream across three checkpoints arrives whole, and a TCP
    connection keeps echoing without a retransmit."""
    n = "ft-ckpt-pkt"
    ok(A, {"op": "run", "name": n, "template": args.template})
    ip = vm_ip(A, n)
    code, out = sh(A, n, "setsid socat -u UDP-RECV:9000 OPEN:/tmp/udp,creat,append >/dev/null 2>&1 < /dev/null &")
    assert code == 0, out
    tcp_server(A, n)
    conn = socket.create_connection((ip, 7000), timeout=10)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    stop, sent, echoes = threading.Event(), [0], [True]

    def stream():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop.is_set():
            s.sendto(b"%08d\n" % sent[0], (ip, 9000))
            sent[0] += 1
            time.sleep(0.001)

    def pingpong():
        while not stop.is_set() and echoes[0]:
            echoes[0] = echo(conn, b"x" * 32)
            time.sleep(0.002)

    threads = [threading.Thread(target=stream, daemon=True), threading.Thread(target=pingpong, daemon=True)]
    for t in threads:
        t.start()
    time.sleep(0.5)
    paths, results = [], []
    for i in range(3):
        paths.append(ckpt_path(f"{n}-{i}"))
        results.append(rpc(A, {"op": "checkpoint", "name": n, "dir": paths[-1], "stop": False}, timeout=120))
        time.sleep(0.5)
    stop.set()
    for t in threads:
        t.join(10)
    info = conn.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
    retrans = int.from_bytes(info[100:104], "little")
    conn.close()
    time.sleep(0.3)
    check("ckpt packet hold: checkpoints taken, vm running", all(r["ok"] for r in results) and where(n) == {A: "running"},
          [r.get("error") for r in results])
    held = [(r.get("result") or {}).get("held_packets") or {} for r in results]
    check("ckpt packet hold: packets held during each pause and all injected",
          all(h.get("packets", 0) > 0 and h.get("injected") == h.get("packets") and h.get("dropped") == 0
              and h.get("dropped_target") == 0 for h in held), held)
    code, out = sh(A, n, "sort -u /tmp/udp | wc -l")
    got = int(out) if code == 0 and out.isdigit() else -1
    check("ckpt packet hold: no udp datagram lost", got == sent[0], f"sent {sent[0]}, received {got}")
    check("ckpt packet hold: tcp echoed throughout, no retransmit", echoes[0] and retrans == 0, f"retransmits {retrans}")
    cleanup(n)
    for p in paths:
        rm_ckpt(p)


def hot_budget():
    """A hot pool budget smaller than one paused VM, whose first cost
    estimate is too low (fault hot_low_estimate): the worker loads one, learns
    what it costs and backs off, rather than load and drop VMs in a loop.
    Restarts A with --hot-mib 16 (a paused `small` VM takes ~20 MiB), then
    with its own command line again."""
    argv, env = kill_daemon(A)
    start_daemon(A, argv + ["--hot-mib", "16"], env)
    fault(A, "hot_low_estimate", 60000)
    n = "ft-hot-budget"
    r = rpc(A, {"op": "run", "name": n, "template": "small"})
    fault(A, "hot_low_estimate", 0)
    check("hot budget: run without the pool", r["ok"] and not r["result"]["hot"], r)
    rpc(A, {"op": "kill", "name": n})
    time.sleep(15)
    hot = ok(A, {"op": "info"})["hot"]
    small = [k for k in hot["ready"] if k.startswith("small@")]
    check("hot budget: at most two loads in 15 s, nothing stocked", 1 <= hot["loads"] <= 2 and small
          and hot["ready"][small[0]] == 0, hot)
    check("hot budget: learned that a paused vm exceeds the budget", small and hot["cost_mib"][small[0]] > 16, hot)
    argv2, env2 = kill_daemon(A)
    start_daemon(A, argv, env)


def plug_race():
    """Migrations that start right after a memory hot-plug (or unplug) was
    requested: the plug settles first (or, if it stalls, is cut down to what
    the guest managed), and the VM ends up on B with all its memory usable.
    PLUG_TEMPLATE picks the template; one snapshotted with nothing plugged
    makes the first step plug into a slot that was never mapped."""
    n = "ft-plug-race"
    m = setup(n, mib=50, template=os.environ.get("PLUG_TEMPLATE"))
    # (from, to, MiB to plug, delay before migrating); the last one is more
    # than the guest can online quickly, so the migration has to cut it short.
    steps = [(A, B, 384, 0), (B, A, 1024, 0), (A, B, 2048, 0.05), (B, A, -1024, 0), (A, B, 384, 0.2),
             (B, A, 1024, 0.1), (A, B, 12288, 0), (B, A, None, 0)]
    for i, (src, dst, delta, gap) in enumerate(steps):
        v = vms(src)[n]
        if delta is None:  # everything: takes the guest longer than a migration waits
            delta = v["max_mib"] - (v["guest_mib"] - v["plugged_mib"]) - v["plugged_mib"]
        want = v["plugged_mib"] + delta
        ok(src, {"op": "hotplug", "name": n, "mib": want})
        time.sleep(gap)
        r = rpc(src, {"op": "migrate", "name": n, "to": dst})
        check(f"plug race {i}: migrate succeeds", r["ok"], r.get("error"))
        st = wait_released(dst, n, timeout=60)
        check(f"plug race {i}: pull finished and released", st["released"] is True and st["failed"] is None, st)
        check(f"plug race {i}: only on target, running", where(n) == {dst: "running"}, where(n))
        hp = lambda: (vms(dst)[n]["requested_mib"], vms(dst)[n]["plugged_mib"])
        settled = wait_for(lambda: hp()[0] == hp()[1] and (delta > 8192 or hp()[1] == want), 15)
        check(f"plug race {i}: hot-plug settled on target", settled, (want, hp()))
        check(f"plug race {i}: md5 intact", md5(dst, n) == m)
        code, out = sh(dst, n, "python3 -c 'b=bytearray(512<<20); print(len(b)>>20)'")
        check(f"plug race {i}: guest can use its memory", code == 0 and out == "512", out)
        code, out = sh(dst, n, "grep MemTotal /proc/meminfo")
        print(f"plug race {i}: {hp()} {out}", flush=True)
    cleanup(n)


def plug_storm():
    """The memory controller keeps resizing (here: a hot-plug request every
    20 ms, up and down) while the VM migrates back and forth. Resizes and
    migrations must not interleave: every migration lands intact."""
    n = "ft-plug-storm"
    m = setup(n, mib=50, template=os.environ.get("PLUG_TEMPLATE"))
    stop = threading.Event()

    def storm():
        up = True
        while not stop.is_set():
            for h in (A, B):
                try:
                    v = vms(h).get(n)
                    if v and v["state"] == "running" and v["plugged_mib"] is not None:
                        rpc(h, {"op": "hotplug", "name": n, "mib": max(0, v["plugged_mib"] + (512 if up else -512))}, timeout=10)
                        up = not up
                except (OSError, AssertionError, KeyError):
                    pass
            time.sleep(0.02)

    t = threading.Thread(target=storm)
    t.start()
    for i, (src, dst) in enumerate([(A, B), (B, A)] * 3):
        r = rpc(src, {"op": "migrate", "name": n, "to": dst})
        check(f"plug storm {i}: migrate succeeds", r["ok"], r.get("error"))
        st = wait_released(dst, n, timeout=60)
        check(f"plug storm {i}: pull finished and released", st["released"] is True and st["failed"] is None, st)
        check(f"plug storm {i}: only on target, running", where(n) == {dst: "running"}, where(n))
    stop.set()
    t.join()
    w = where(n)
    check("plug storm: only on one host, running", list(w.values()) == ["running"], (w, {h: vms(h).get(n) for h in (A, B)}))
    dst = B if w.get(B) == "running" else A
    got = md5(dst, n)
    check("plug storm: md5 intact", got == m, (dst, got))
    code, out = sh(dst, n, "python3 -c 'b=bytearray(512<<20); print(len(b)>>20)'")
    check("plug storm: guest can use its memory", code == 0 and out == "512", out)
    cleanup(n)


def kill_source():
    """A migration's paused source copy cannot be killed (the target still
    pulls from it and releases it); the VM lives on at the target."""
    n = "ft-kill-source"
    m = setup(n, mib=1500)
    ok(A, {"op": "migrate", "name": n, "to": B})
    # Keep the pull from finishing (the target retries for 10 s).
    fault(A, "pages", 3000)
    r = rpc(A, {"op": "kill", "name": n})
    check("kill source: refused", not r["ok"] and "source of migration" in r.get("error", ""), r)
    check("kill source: copy still paused on A", vms(A).get(n, {}).get("state") == "source", where(n))
    st = wait_released(B, n)
    check("kill source: target pulled everything and released it",
          st["released"] is True and st["failed"] is None and where(n) == {B: "running"}, (st, where(n)))
    check("kill source: md5 intact on B", md5(B, n) == m)
    cleanup(n)


def raw(host, data, timeout=10):
    """Sends `data` on a new connection; returns everything until EOF."""
    h, port = host.rsplit(":", 1)
    with socket.create_connection((h, int(port)), timeout=timeout) as s:
        try:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        out = b""
        try:
            while d := s.recv(65536):
                out += d
        except OSError:
            pass
    return out


def forged_peer():
    """Peer-sized lengths a forged peer sends (a huge vmstate, too many
    preloaded pages, a huge page request, an endless request line) are refused
    without the daemon dying, and page-server refusals reach the client. An
    arrival without an address generation (none, or 0), or with one older
    than the newest recorded, is refused."""
    tid = source_vm()
    n, ip = "ft-forged-gen", "10.250.0.10"
    gone = lambda: wait_for(lambda: ip not in ok(B, {"op": "info"})["ips"] and n not in vms(B), 10)
    for label, gen in (("none", None), ("zero", 0)):
        s, r, _ = migrate_in_raw(B, n, ip, tid, gen=gen)
        s.close()
        check(f"forged gen {label}: arrival refused", not r.get("ok") and "gen" in r.get("error", ""), r)
    newest = int(time.time() * 1000)
    s, r, _ = migrate_in_raw(B, n, ip, tid, gen=newest)
    s.close()
    check("forged gen: a newer one is taken", r.get("ok") and gone(), r)
    s, r, _ = migrate_in_raw(B, n, ip, tid, gen=newest - 1)
    s.close()
    check("forged gen: an older one than recorded is refused", not r.get("ok") and "newer one" in r.get("error", ""), r)
    gone()
    for label, hdr in (("vmstate", {"runs": [], "vmstate_len": 1 << 40, "preload": []}),
                       ("preload", {"runs": [], "vmstate_len": 0, "preload": list(range(5000))})):
        n, ip = f"ft-forged-{label}", "10.250.0.9"
        s, r, _ = migrate_in_raw(B, n, ip, tid)
        check(f"forged {label}: target prepared", r.get("ok"), r)
        s.sendall((json.dumps(hdr) + "\n").encode())
        s.settimeout(30)
        try:
            reply = s.recv(65536)
        except OSError as e:
            reply = str(e).encode()
        s.close()
        check(f"forged {label}: refused", b'"ok":false' in reply and b"more than" in reply, reply[:300])
        check(f"forged {label}: target still up", rpc(B, {"op": "info"}).get("ok"))
        nothing_left(f"forged {label}", n, ip)
    raw(B, b"x" * (17 << 20))
    check("forged request line: endless line cut off, target still up", rpc(B, {"op": "info"}).get("ok"))
    # The page server answers before its binary protocol, refusals too.
    n = "ft-forged-pages"
    m = setup(n, mib=1500)
    out = raw(A, (json.dumps({"op": "pages", "name": n, "mig": 1}) + "\n").encode())
    try:
        refusal = json.loads(out.split(b"\n")[0])
    except ValueError:
        refusal = {}
    check("forged pages: refusal answered", refusal.get("ok") is False and "not the source" in refusal.get("error", ""), out[:200])
    r = ok(A, {"op": "migrate", "name": n, "to": B})
    h, port = A.rsplit(":", 1)
    with socket.create_connection((h, int(port)), timeout=10) as s:
        req = json.dumps({"op": "pages", "name": n, "mig": r["mig"]}).encode() + b"\n"
        s.sendall(req + (0).to_bytes(8, "little") + (0xFFFFFFFF).to_bytes(4, "little"))
        out = b""
        try:
            while d := s.recv(65536):
                out += d
        except OSError:
            pass
    if out.startswith(b'{"ok":true}\n'):
        check("forged pages: a 4 GiB page request is refused", out == b'{"ok":true}\n\x01', out[:100])
    else:
        print(f"forged pages: pull finished before the forged request ({out[:100]!r}); huge request not exercised")
    check("forged pages: source still up", rpc(A, {"op": "info"}).get("ok"))
    st = wait_released(B, n)
    check("forged pages: migration completed", st["released"] is True and where(n) == {B: "running"}, (st, where(n)))
    check("forged pages: md5 intact", md5(B, n) == m)
    cleanup(n)


def restore_ip_peer():
    """run --ip refuses an address that is not the host's to hand out (a
    peer's, or one from no host's range); restore --ip borrows a peer's from
    its home host, which refuses one in use there."""
    n, path = "ft-rip", ckpt_path("ft-rip")
    ok(A, {"op": "run", "name": n, "template": args.template})
    ok(A, {"op": "checkpoint", "name": n, "dir": path})
    ok(B, {"op": "run", "name": "ft-rip-b", "template": args.template})
    theirs = vms(B)["ft-rip-b"]["ip"]
    r = rpc(A, {"op": "restore", "dir": path, "name": "ft-rip2", "ip": theirs})
    check("restore --ip: a peer's live address is refused by its home host",
          not r["ok"] and "cannot borrow" in r.get("error", "") and B in r.get("error", "") and "in use" in r.get("error", ""), r)
    check("restore --ip: nothing restored", "ft-rip2" not in vms(A) and theirs not in ok(A, {"op": "info"})["ips"])
    r = rpc(A, {"op": "run", "name": "ft-rip3", "template": args.template, "ip": theirs})
    check("run --ip: a peer's live address is refused", not r["ok"] and "not this host's" in r.get("error", ""), r)
    r = rpc(A, {"op": "run", "name": "ft-rip3", "template": args.template, "ip": "10.250.0.5"})
    check("run --ip: an address from no host's range is refused", not r["ok"] and "not this host's" in r.get("error", ""), r)
    r = rpc(A, {"op": "restore", "dir": path, "name": "ft-rip2", "ip": "auto"})
    check("restore --ip auto still works", r["ok"], r)
    for x in (n, "ft-rip-b", "ft-rip2", "ft-rip3"):
        cleanup(x)
    rm_ckpt(path)


def late_withdrawal():
    """Address generations order the VMs that had an address: a late
    withdrawal for a VM long gone cannot free a newer VM's loan of it or
    remove its route, and a late announcement of a withdrawn VM brings no
    route back, also after the host that got them restarts (A, SIGKILL)."""
    lent = lambda: ok(A, {"op": "info"})["lent"]
    n = "ft-late-1"
    setup(n, mib=1)
    ip = vms(A)[n]["ip"]
    ok(A, {"op": "migrate", "name": n, "to": B})
    wait_released(B, n)
    old = lent().get(ip)
    check("late withdrawal: lent while away", old is not None, lent())
    ok(B, {"op": "kill", "name": n})
    check("late withdrawal: its own withdrawal frees it", wait_for(lambda: ip not in lent(), 10), lent())
    n2 = "ft-late-2"
    ok(A, {"op": "run", "name": n2, "template": args.template, "ip": ip})
    ok(A, {"op": "migrate", "name": n2, "to": B})
    wait_released(B, n2)
    new = lent().get(ip)
    check("late withdrawal: lent again, a newer generation", new is not None and old is not None and new > old, (old, new))
    # B announces the route for the second VM in the background.
    time.sleep(1)
    r = ok(A, {"op": "route", "ip": ip, "gen": old})
    check("late withdrawal: the old one frees nothing", not r["freed"] and lent().get(ip) == new, (r, lent()))
    check("late withdrawal: and keeps the newer route", r["stale"], r)
    r = ok(A, {"op": "route", "ip": ip})
    check("late withdrawal: one without a generation frees nothing", not r["freed"] and r["stale"] and lent().get(ip) == new, (r, lent()))
    ok(B, {"op": "kill", "name": n2})
    check("late withdrawal: the newer VM's withdrawal frees it", wait_for(lambda: ip not in lent(), 10), lent())
    time.sleep(0.5)
    late = lambda g: ok(A, {"op": "route", "ip": ip, "via": "127.0.0.1", "gen": g})
    r = late(new)
    check("late announcement: of a withdrawn generation is stale", r["stale"], r)
    r = late(old)
    check("late announcement: of an older generation is stale", r["stale"], r)
    argv, env = kill_daemon(A)
    start_daemon(A, argv, env)
    r = late(new)
    check("late announcement after a restart: still stale", r["stale"], r)
    r = ok(A, {"op": "route", "ip": ip, "gen": old})
    check("late withdrawal after a restart: stale", r["stale"] and not r["freed"], r)
    # The home host's generations keep growing across its restart.
    n3 = "ft-late-3"
    ok(A, {"op": "run", "name": n3, "template": args.template, "ip": ip})
    ok(A, {"op": "migrate", "name": n3, "to": B})
    wait_released(B, n3)
    third = lent().get(ip)
    check("late withdrawal: a restarted home host hands out newer generations", third is not None and third > new, (new, third))
    # The generation it handed out is on disk: after another restart, a
    # repeated withdrawal of the one before it is still stale.
    time.sleep(1)
    argv, env = kill_daemon(A)
    start_daemon(A, argv, env)
    r = ok(A, {"op": "route", "ip": ip, "gen": new})
    check("late withdrawal: repeated after a restart, stale for the newer loan", r["stale"] and not r["freed"] and lent().get(ip) == third, (r, lent()))
    for x in (n, n2, n3):
        cleanup(x)
    check("late withdrawal: the last VM's withdrawal frees it", wait_for(lambda: ip not in lent(), 10), lent())


def log_since(host, offset):
    """The daemon on `host`'s log (its stderr, a file) from byte `offset`
    on; with None, the current length instead."""
    path = subprocess.run(["sudo", "readlink", f"/proc/{daemon_pid(host)}/fd/2"], capture_output=True, text=True).stdout.strip()
    data = subprocess.run(["sudo", "cat", path], capture_output=True).stdout
    return len(data) if offset is None else data[offset:].decode(errors="replace")


def abort_superseded():
    """A migration source whose migration aborts does not resume a VM whose
    address's generation was superseded meanwhile (say the home host handed
    the address to a newer VM): that copy is gone, and the address's route
    is not taken back."""
    n = "ft-abort-superseded"
    m = setup(n, mib=20)
    ip = vms(A)[n]["ip"]
    ok(A, {"op": "migrate", "name": n, "to": B})
    wait_released(B, n)
    check("abort superseded: running on B", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    old = ok(A, {"op": "info"})["lent"].get(ip)
    # A newer generation of the address, as its home host would announce it
    # for a replacement VM: to B first, and to A only once A has prepared to
    # take the VM back (A refuses the arrival anyway: see below).
    newer = old + 100000
    # The replacement's host: any on-link address that is not ours (the
    # default gateway), so the route is really installed. (A and B share one
    # routing table here.)
    gw = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout.split()[2]
    announce = {"op": "route", "ip": ip, "via": gw, "gen": newer}
    r = ok(B, announce)
    check("abort superseded: B takes the newer generation", not r["stale"], r)
    # B's page server refuses, so A refuses the arrival after B paused (and
    # held its packets), and B aborts.
    fault(B, "pages", 30000)
    b_log = log_since(B, None)
    late = threading.Timer(2, lambda: ok(A, announce))
    late.start()
    r = rpc(B, {"op": "migrate", "name": n, "to": A}, timeout=120)
    late.join()
    fault(B, "pages", 0)
    check("abort superseded: migration aborted, copy not resumed", not r["ok"] and "superseded" in r.get("error", ""), r)
    check("abort superseded: running nowhere", where(n) == {}, where(n))
    route = subprocess.run(["ip", "route", "show", f"{ip}/32"], capture_output=True, text=True).stdout.strip()
    check("abort superseded: the address routes to the replacement, not the hold", f"via {gw}" in route, route)
    # A and B share one routing table here, and A's own announcement and
    # failed arrival put the same route in, so the table cannot tell whose it
    # is: B's log says whether B itself put the route back after its abort.
    blog = log_since(B, b_log)
    check("abort superseded: B put the replacement's route back itself",
          f"put back route {ip} via {gw} (generation {newer})" in blog, blog[-500:])
    check("abort superseded: its old loan freed", wait_for(lambda: ip not in ok(A, {"op": "info"})["lent"], 10))
    cleanup(n)
    # Let A, the home host, know the newer generation too, and retire it,
    # so A's later ones for this address are newer still.
    for h in (A, B):
        ok(h, {"op": "route", "ip": ip, "via": "127.0.0.1", "gen": newer})
        ok(h, {"op": "route", "ip": ip, "gen": newer})
    subprocess.run(["sudo", "ip", "route", "del", f"{ip}/32"], capture_output=True)


def suspend_no_gen():
    """A suspended VM whose checkpoint lacks its address generation, while
    the address has one recorded, is quarantined on restart (not brought
    back), and its checkpoint still restores at a new address."""
    n = "ft-suspend-nogen"
    m = setup(n, mib=20)
    ok(A, {"op": "suspend", "name": n})
    argv = [a.decode() for a in proc(daemon_pid(A), "cmdline").split(b"\0") if a]
    d = os.path.join(argv[argv.index("--state-dir") + 1], "suspended", n)
    check("suspend no gen: generation recorded in the checkpoint",
          subprocess.run(["sudo", "test", "-f", f"{d}/GEN"]).returncode == 0, d)
    subprocess.run(["sudo", "rm", "-f", f"{d}/GEN"], check=True)
    argv, env = kill_daemon(A)
    start_daemon(A, argv, env)
    check("suspend no gen: quarantined, not brought back", n not in vms(A), vms(A).get(n))
    r = rpc(A, {"op": "restore", "dir": d, "name": n + "2", "ip": "auto"})
    check("suspend no gen: its checkpoint restores at a new address", r["ok"] and md5(A, n + "2") == m, r)
    cleanup(n + "2")
    subprocess.run(["sudo", "rm", "-rf", d], check=True)


SCENARIOS = dict(plug_race=plug_race, plug_storm=plug_storm, cow_grow=cow_grow, basic=basic, route=route, lost_ack=lost_ack, unknown=unknown, refused=refused, pages_blip=pages_blip,
                 pages_dead_restore=pages_dead_restore, pages_dead=pages_dead, resume_kill=resume_kill, prepared_retry=prepared_retry, quiet_source=quiet_source,
                 shared_run_dir=shared_run_dir, exec_race=exec_race, guest_calls=guest_calls, source_killed=source_killed,
                 target_restart=target_restart, target_restart_symlink=target_restart_symlink, guest_hang=guest_hang,
                 checkpoint_restore=checkpoint_restore, checkpoint_fork=checkpoint_fork,
                 checkpoint_corrupt=checkpoint_corrupt, checkpoint_crash=checkpoint_crash, pause_resume=pause_resume,
                 suspend_resume=suspend_resume, checkpoint_hotplug=checkpoint_hotplug,
                 checkpoint_untrusted_dir=checkpoint_untrusted_dir, resume_failures=resume_failures,
                 state_dir_lock=state_dir_lock, held_restore_frozen=held_restore_frozen,
                 cow_exact=cow_exact, cow_abort=cow_abort, cow_crash=cow_crash, cow_reports_held=cow_reports_held, cow_wp_race=cow_wp_race, fetch_tail_enomem=fetch_tail_enomem, fetch_enomem_stuck=fetch_enomem_stuck, ckpt_incremental=ckpt_incremental,
                 ckpt_failed_stop=ckpt_failed_stop, ckpt_rearm=ckpt_rearm,
                 ckpt_dir_moved=ckpt_dir_moved, prepare_disconnect=prepare_disconnect,
                 prepare_trickle=prepare_trickle, prepare_fail=prepare_fail, fc_prepare=fc_prepare,
                 slow_preload=slow_preload, ckpt_packet_hold=ckpt_packet_hold, hot_budget=hot_budget,
                 suspend_disk_freed=suspend_disk_freed, resume_mark_fails=resume_mark_fails,
                 kill_source=kill_source, forged_peer=forged_peer,
                 restore_ip_peer=restore_ip_peer, late_withdrawal=late_withdrawal, abort_superseded=abort_superseded,
                 suspend_no_gen=suspend_no_gen)
safe = [s for s in SCENARIOS
        if s not in ("source_killed", "target_restart", "target_restart_symlink", "checkpoint_crash", "cow_crash", "late_withdrawal",
                     "suspend_no_gen", "suspend_resume", "hot_budget", "resume_mark_fails")]
names = [n for s in args.scenarios for n in (safe if s == "all" else [s])]
for s in names:
    scenario_vms.clear()
    scenario_checkpoints.clear()
    try:
        SCENARIOS[s]()
    except Exception as e:
        traceback.print_exc()
        check(f"{s}: scenario raised", False, repr(e))
    finally:
        disarm()
        for name in list(scenario_vms):
            for host in (A, B):
                try:
                    rpc(host, {"op": "kill", "name": name}, timeout=10)
                except Exception as e:
                    check(f"{s}: cleanup {name} on {host}", False, repr(e))
        for path in list(scenario_checkpoints):
            try:
                rm_ckpt(path)
            except Exception as e:
                check(f"{s}: cleanup {path}", False, repr(e))
print("failures:", failures)
sys.exit(1 if failures else 0)
