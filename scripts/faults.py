#!/usr/bin/env python3
"""Fault-injection checks for VM processes on two hosts, A and B, each a
state/run directory pair with its peer listener, on this machine. Each
scenario checks that the VM ends up running on exactly one host (md5 of a
guest file intact) or cleanly gone. Run as root.

usage: scripts/faults.py [--a ADDR] [--b ADDR] [--a-dir DIR] [--b-dir DIR]
                         [--bin FLEXVM] [--artifacts DIR] [--ckpt-dir DIR] SCENARIO... | all

The script starts both listeners (FLEXVM_FAULTS=1, VMs log to DIR/run/vms)
and stops them at the end. Checkpoint scenarios write to --ckpt-dir.
"""
import argparse, base64, json, os, signal, socket, subprocess, sys, tempfile, threading, time, traceback

p = argparse.ArgumentParser(usage=__doc__)
p.add_argument("--a", default="127.0.0.1:7130")
p.add_argument("--b", default="127.0.0.1:7131")
p.add_argument("--a-dir", default="/run/fvp-a")
p.add_argument("--b-dir", default="/run/fvp-b")
p.add_argument("--a-ips", default="10.130.0.2-10.130.0.250")
p.add_argument("--b-ips", default="10.131.0.2-10.131.0.250")
p.add_argument("--prefix", default="fvp", help="names of taps and hold devices start with this")
for h in "ab":
    p.add_argument(f"--{h}-state", help=f"host {h.upper()}'s state directory (default: --{h}-dir/state)")
    p.add_argument(f"--{h}-run", help=f"host {h.upper()}'s run directory (default: --{h}-dir/run)")
p.add_argument("--no-listeners", action="store_true", help="use the listeners already running on --a and --b")
p.add_argument("--bin", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target", "release", "flexvm"))
p.add_argument("--artifacts", default=os.environ.get("FLEXVM_ARTIFACTS", "artifacts"))
p.add_argument("--ckpt-dir", default=os.path.join(tempfile.gettempdir(), "flexvm-checkpoints"),
               help="where checkpoint scenarios write checkpoints (removed afterwards)")
p.add_argument("--template", default="small")
p.add_argument("scenarios", nargs="+")
args = p.parse_args()
BIN = os.path.abspath(args.bin)
failures = 0
# What each scenario made, removed after it whatever happened.
scenario_vms, scenario_checkpoints = set(), set()


class Host:
    def __init__(self, addr, d, ips, state=None, run=None):
        self.addr, self.dir, self.ips = addr, d, ips
        self.state, self.run = state or os.path.join(d, "state"), run or os.path.join(d, "run")

    def __repr__(self):
        return self.addr


A = Host(args.a, args.a_dir, args.a_ips, args.a_state, args.a_run)
B = Host(args.b, args.b_dir, args.b_ips, args.b_state, args.b_run)
ENV = dict(os.environ, FLEXVM_FAULTS="1", FLEXVM_ARTIFACTS=os.path.abspath(args.artifacts))
listeners = {}


def cli(host, *a, timeout=120):
    """Runs flexvm against `host`; returns (exit code, stdout, stderr)."""
    r = subprocess.run([BIN, "--state", host.state, "--run", host.run, *a], capture_output=True, text=True, timeout=timeout, env=ENV)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def cli_json(host, *a, timeout=120):
    """`cli`, as the old daemon RPC answered: {"ok", "result" | "error"}."""
    code, out, err = cli(host, *a, timeout=timeout)
    if code != 0:
        return {"ok": False, "error": err or out}
    try:
        return {"ok": True, "result": json.loads(out) if out else None}
    except ValueError:
        return {"ok": True, "result": out}


def ok(r):
    assert r["ok"], r
    return r["result"]


def peer(host, req, timeout=30):
    """One request to `host`'s peer listener."""
    h, port = host.addr.rsplit(":", 1)
    with socket.create_connection((h, int(port)), timeout=timeout) as s:
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            d = s.recv(65536)
            if not d:
                break
            buf += d
    return json.loads(buf) if buf else {"ok": False, "error": "hung up"}


def control(host, name, req, timeout=60):
    """One request on VM `name`'s control socket; its first answer line."""
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(timeout)
        s.connect(os.path.join(host.run, "vms", f"{name}.sock"))
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            d = s.recv(65536)
            if not d:
                break
            buf += d
    return json.loads(buf.split(b"\n")[0]) if buf else {"ok": False, "error": "hung up"}


def run(host, name, ip=None, template=None):
    scenario_vms.add(name)
    a = ["run", name, "--template", template or args.template, "-d"] + (["--ip", ip] if ip else [])
    return cli_json(host, *a)


def kill(host, name):
    return cli_json(host, "kill", name)


def migrate(src, name, dst, timeout=120):
    return cli_json(src, "migrate", name, dst.addr, timeout=timeout)


def checkpoint(host, name, path, stop=False, incremental=False, timeout=300):
    return cli_json(host, "checkpoint", name, path, *(["--stop"] if stop else []), *(["--incremental"] if incremental else []), timeout=timeout)


def restore(host, path, name=None, ip=None, paused=False):
    scenario_vms.add(name or os.path.basename(path))
    a = ["restore", path, "-d"] + (["--name", name] if name else []) + (["--ip", ip] if ip else []) + (["--paused"] if paused else [])
    return cli_json(host, *a)


def sh(host, name, cmd):
    code, out, err = cli(host, "exec", name, cmd)
    return code, (out + err).strip()


def vms(host):
    """ls, with each live VM's own account of itself (`debug VM status`)."""
    code, out, err = cli(host, "ls", "--json")
    assert code == 0, err
    out = {v["name"]: v for v in json.loads(out)}
    for n, v in out.items():
        if v.get("pid"):
            try:
                st = control(host, n, {"op": "debug", "what": "status"}, timeout=10)
            except OSError:
                continue  # gone meanwhile, or not answering
            if st.get("ok"):
                d = st["result"]
                v.update(tap=d["describe"]["tap"], pages_mib=d["describe"]["pages_mib"],
                         checkpoint_copy=d["describe"]["checkpoint_copy"], checkpoint_copy_stats=d["checkpoint_copy_stats"],
                         background_pull_ms=d["background_pull_ms"], failed=d["failed"], guest_retries=d["guest_retries"])
    return out


def where(name):
    return {h: v[name]["state"] for h in (A, B) for v in [vms(h)] if name in v}


def alive(pid):
    try:
        stat = open(f"/proc/{pid}/stat").read()
    except OSError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


def vm_pid(host, name):
    return vms(host)[name]["pid"]


def signal_vm(host, name, sig):
    os.kill(vm_pid(host, name), sig)


def wait_for(cond, timeout):
    end = time.time() + timeout
    while not cond() and time.time() < end:
        time.sleep(0.1)
    return cond()


def wait_released(target, name, source=None, timeout=120):
    """Waits until the source's copy of `name` is gone (its process exits once
    the target has every page, or its VM is gone) and the target's pull ended;
    returns the target's status, as the old migration_status did."""
    source = source or (A if target is B else B)
    end = time.time() + timeout
    while time.time() < end:
        released = name not in vms(source)
        v = vms(target).get(name)
        if released and (v is None or v.get("background_pull_ms") is not None or v.get("failed")):
            return {"released": True, "state": v["state"] if v else "gone", "failed": v.get("failed") if v else "gone",
                    "background_pull_ms": v.get("background_pull_ms") if v else None}
        time.sleep(0.1)
    return {"released": None, "state": None}


def fault(host, f, ms):
    code, out, err = cli(host, "debug", "fault", f, str(ms))
    assert code == 0, err


FAULTS = ("pages", "route", "lost_ack", "status", "restore_no_hold", "restore_before_run", "restore_after_run",
          "ckpt_abort", "ckpt_fail_protect", "ckpt_fail_write", "ckpt_memhash", "ckpt_no_hold", "ckpt_slow", "resume_kill",
          "prepare_fail", "short_incoming", "slow_preload", "kill_prepared", "guest_drop", "guest_lose_reply", "ckpt_copy_wait",
          "started_fsync", "started_unmark")


def disarm():
    """Disarms every test fault on both hosts, so none outlives its scenario."""
    for h in (A, B):
        try:
            os.unlink(os.path.join(h.run, "faults.json"))
        except OSError:
            pass


def setup(name, host=None, mib=200):
    host = host or A
    ok(run(host, name))
    code, out = sh(host, name, f"dd if=/dev/urandom of=/tmp/f bs=1M count={mib} 2>/dev/null; md5sum /tmp/f")
    assert code == 0, out
    return out.split()[0]


def md5(host, name):
    code, out = sh(host, name, "md5sum /tmp/f")
    return out.split()[0] if code == 0 else out


def cleanup(name):
    for h in (A, B):
        kill(h, name)


def check(label, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + label + (f"  [{detail}]" if detail else ""), flush=True)
    failures += not cond
    return cond


def log(host, name):
    """What VM processes named `name` on `host` wrote (incoming ones included)."""
    try:
        return open(os.path.join(host.run, "vms", f"{name}.log")).read()
    except OSError:
        return ""


def clear_log(host, name):
    try:
        os.unlink(os.path.join(host.run, "vms", f"{name}.log"))
    except OSError:
        pass


def addr(host, ip):
    """`host`'s record of address `ip` (generation, loan, holder)."""
    try:
        return json.load(open(os.path.join(host.state, "addrs", ip)))
    except OSError:
        return {}


def start_listeners():
    if args.no_listeners:
        return
    for h, other in ((A, B), (B, A)):
        for d in (h.state, h.run):
            os.makedirs(d, exist_ok=True)
        lg = open(os.path.join(h.run, "listen.log"), "a")
        listeners[h.addr] = subprocess.Popen(
            [BIN, "--state", h.state, "--run", h.run, "listen", h.addr, "--peer", other.addr, "--vm-ips", h.ips,
             "--reserve", "512", "--prefix", args.prefix], stdout=lg, stderr=lg, env=ENV)
    for h in (A, B):
        hp = h.addr.rsplit(":", 1)
        up = lambda: subprocess.run(["bash", "-c", f"exec 3<>/dev/tcp/{hp[0]}/{hp[1]}"], capture_output=True).returncode == 0
        assert wait_for(up, 10), f"listener {h} did not come up"


def stop_listeners():
    for p in listeners.values():
        p.terminate()
        p.wait()


def fc_pid(host, name):
    return vms(host)[name]["firecracker"]


def api_sock(host, name):
    """The API socket of `name`'s Firecracker on `host`."""
    argv = open(f"/proc/{fc_pid(host, name)}/cmdline", "rb").read().split(b"\0")
    return argv[argv.index(b"--api-sock") + 1].decode()


def vsock_path(host, name):
    return os.path.join(os.path.dirname(api_sock(host, name)), "v.sock")


def pause(host, name):
    signal_vm(host, name, signal.SIGTSTP)
    return wait_for(lambda: vms(host)[name]["state"] == "paused", 10)


def resume(host, name):
    """SIGCONT (`flexvm resume` of a paused VM); returns how long until it runs (s)."""
    t = time.time()
    code, out, err = cli(host, "resume", name)
    assert code == 0, err
    wait_for(lambda: vms(host)[name]["state"] == "running", 60)
    return time.time() - t


def suspend(host, name):
    """SIGTERM: the VM process checkpoints to the host's state dir and exits.
    Returns what it printed (suspend_ms, freed_rss_mib, data_mib, dir)."""
    pid = vm_pid(host, name)
    os.kill(pid, signal.SIGTERM)
    assert wait_for(lambda: not alive(pid), 120), "suspend did not finish"
    for line in reversed(log(host, name).splitlines()):
        if line.startswith("{") and '"suspended"' in line:
            return json.loads(line)
    return {"dir": os.path.join(host.state, "suspended", name)}


def resume_suspended(host, name):
    return cli_json(host, "resume", name, "-d")


# --- migration --------------------------------------------------------------


def basic():
    n = "ft-basic"
    m = setup(n)
    r = ok(migrate(A, n, B))
    st = wait_released(B, n)
    check("basic: released", st["released"] is True, st)
    check("basic: only on B, running", where(n) == {B: "running"}, where(n))
    check("basic: md5 intact on B", md5(B, n) == m)
    # And back.
    r2 = ok(migrate(B, n, A))
    wait_released(A, n)
    check("basic: back on A only", where(n) == {A: "running"}, where(n))
    check("basic: md5 intact after round trip", md5(A, n) == m)
    # Both records stay: neither id can be taken for aborted later.
    s1, s2 = peer(B, {"op": "migration", "mig": r["mig"]}), peer(A, {"op": "migration", "mig": r2["mig"]})
    check("basic: committed ids are remembered after their processes left", s1["result"]["outcome"] == "released"
          and s2["result"]["outcome"] == "released", (s1, s2))
    s3 = peer(B, {"op": "migration", "mig": 12345})
    check("basic: an unknown id is fenced as aborted", s3["result"]["outcome"] == "aborted", s3)
    cleanup(n)


def route():
    n = "ft-route"
    m = setup(n)
    fault(A, "route", 1000)
    r = ok(migrate(A, n, B))
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
    r = migrate(A, n, B)
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
    r = migrate(A, n, B)
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
    ok(run(B, n))
    r = migrate(A, n, B)
    check("refused: migrate fails", not r["ok"], r)
    check("refused: source resumed", where(n) == {A: "running", B: "running"}, where(n))
    check("refused: md5 intact on A", md5(A, n) == m)
    cleanup(n)


def pages_blip():
    n = "ft-pages-blip"
    m = setup(n, mib=400)
    fault(A, "pages", 3000)
    t = time.time()
    ok(migrate(A, n, B))
    st = wait_released(B, n)
    check("pages blip: pull recovered", st["released"] is True and st["failed"] is None, f"{st} after {time.time()-t:.1f}s")
    check("pages blip: only on B", where(n) == {B: "running"}, where(n))
    got = md5(B, n)
    check("pages blip: md5 intact", got == m, got)
    # The blip stalled B's snapshot load, restoring the vCPUs' TSCs seconds
    # apart: KVM then keeps no master clock for the VM, so its snapshots have
    # no realtime clock. It must still migrate (issue #50).
    r = migrate(B, n, A)
    check("pages blip: migrates back", r["ok"], r)
    wait_released(A, n)
    w, back = where(n), md5(A, n)
    check("pages blip: back on A only, md5 intact", w == {A: "running"} and back == m, (w, back))
    cleanup(n)


def pages_dead_restore():
    n = "ft-pages-dead-restore"
    m = setup(n)
    fault(A, "pages", 20000)
    r = migrate(A, n, B)
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
    ok(migrate(A, n, B))
    fault(A, "pages", 30000)
    st = wait_released(B, n)
    fault(A, "pages", 0)
    check("pages dead: target failed cleanly, its process gone", st["state"] == "gone" and n not in vms(B), (st, vms(B).get(n)))
    check("pages dead: source copy released", st["released"] is True, st)
    check("pages dead: running nowhere", where(n) == {}, where(n))
    check("pages dead: the target said why", "lost its memory" in log(B, n) or "gone (" in log(B, n), log(B, n)[-300:])


def resume_kill():
    """Firecracker dies right after a restored VM's resume was sent, so the
    guest may have run: nothing loads the VM again (that could repeat what
    the guest did). A migration target has committed before it resumes, so
    the VM is lost there and the source never resumes its copy; a run that
    claims a standby VM fails without a fallback load."""
    n = "ft-resume-kill"
    setup(n)
    clear_log(B, n)
    fault(B, "resume_kill", 60000)
    r = migrate(A, n, B)
    fault(B, "resume_kill", 0)
    check("resume kill: migration committed", r["ok"], r)
    st = wait_released(B, n)
    check("resume kill: target loaded the vm once, no retry", "once more" not in log(B, n), log(B, n)[-300:])
    check("resume kill: running nowhere", where(n) == {}, (where(n), st))
    n = "ft-resume-kill-hot"
    ok(cli_json(A, "standby", "--template", args.template, "1"))
    fault(A, "resume_kill", 60000)
    r = run(A, n)
    fault(A, "resume_kill", 0)
    check("resume kill: a run claiming a standby vm fails", not r["ok"] and "may have run" in r.get("error", ""), r)
    check("resume kill: no vm left", n not in vms(A), vms(A).get(n))
    ok(cli_json(A, "standby", "--template", args.template, "0"))
    r = run(A, n)
    check("resume kill: the name runs again", r["ok"], r)
    cleanup(n)


def prepared_retry():
    """A migration target whose prepared Firecracker dies before the load,
    its pager having seen it go (`kill_prepared`), loads once more on a fresh
    one, before it commits: the guest never ran, and the paused source still
    serves every page, including the preloaded ones the dead pager had."""
    n = "ft-prepared-retry"
    m = setup(n)
    clear_log(B, n)
    fault(B, "kill_prepared", 30000)
    r = migrate(A, n, B)
    fault(B, "kill_prepared", 0)
    check("prepared retry: migration commits", r["ok"], r)
    retries = log(B, n).count("once more")
    check("prepared retry: loaded twice (one retry)", retries == 1, retries)
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
    session = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "exec", n, "while :; do echo tick; sleep 0.05; done"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV)
    sysfs = f"/sys/class/net/{tap}"
    tx = lambda: int(open(f"{sysfs}/statistics/tx_packets").read())
    # While paused, try to point the address back at the source's tap (as a
    # stale LAN path would).
    to_tap = lambda: subprocess.run(["ip", "route", "replace", f"{ip}/32", "dev", tap], capture_output=True, text=True)
    t = tx()
    time.sleep(0.3)
    check("quiet source: flood reaches the tap while running", tx() > t + 10, (t, tx()))
    r = ok(migrate(A, n, B))
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
    # The source closed its side; the exec client, which reaches this host
    # only, ends saying where the VM went (the command runs on there).
    try:
        _, err = session.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        session.kill()
        _, err = session.communicate()
    check("quiet source: exec ends saying the vm moved", session.returncode != 0 and "moved to" in err, err[-300:])
    stop.set()
    st = wait_released(B, n)
    check("quiet source: released, only on B", st["released"] is True and where(n) == {B: "running"}, (st, where(n)))
    check("quiet source: md5 intact", md5(B, n) == m)
    check("quiet source: guest still answers", sh(B, n, "echo hi") == (0, "hi"))
    print(f"quiet source: downtime {r['downtime_ms']} ms, checkpoint {r['checkpoint_ms']} ms")
    cleanup(n)


def source_killed():
    """SIGKILLs the source VM process mid-pull: its Firecracker dies with it,
    and the target fails cleanly."""
    n = "ft-source-killed"
    setup(n, mib=1500)
    src_fc = fc_pid(A, n)
    pid = vm_pid(A, n)
    ok(migrate(A, n, B))
    os.kill(pid, signal.SIGKILL)
    check("source killed: its firecracker died with it", wait_for(lambda: not alive(src_fc), 5), src_fc)
    st = wait_released(B, n)
    wait_for(lambda: n not in vms(B), 30)
    st["state"] = vms(B).get(n, {}).get("state", "gone")
    check("source killed: target failed cleanly", st["state"] == "gone" and n not in vms(B), st)
    check("source killed: running nowhere", where(n) == {}, where(n))


def target_killed():
    """The target VM process is SIGKILLed after it resumed the VM, before
    the source knew: its Firecracker dies with it, the committed record
    survives the process (and the listener), so the source is told
    `released`, never `aborted`: it does not resurrect the VM (that would
    roll it back). The VM is lost, as the host it ran on lost it."""
    n = "ft-target-killed"
    setup(n, mib=1500)
    fault(B, "lost_ack", 2000)
    fault(B, "status", 4000)
    # Once the target has resumed, stall its pull so it cannot finish.
    stall = threading.Timer(0.2, lambda: fault(A, "pages", 6000))
    stall.start()
    r = migrate(A, n, B)
    stall.join()
    check("target killed: outcome unknown, source paused", not r["ok"] and where(n).get(A) == "source", (r, where(n)))
    v = vms(B).get(n)
    check("target killed: VM running on target", v is not None and v["state"] == "running", v)
    if v:
        fc = v["firecracker"]
        os.kill(v["pid"], signal.SIGKILL)
        check("target killed: its firecracker died with it", wait_for(lambda: not alive(fc), 15), fc)
    # The listener restarts too: nothing it knows is in memory.
    stop_listeners()
    start_listeners()
    check("target killed: source let go, never resumed", wait_for(lambda: n not in vms(A), 60), where(n))
    check("target killed: running nowhere", where(n) == {}, where(n))


def exec_race():
    """Execs keep starting while the VM migrates there and back: every exec
    finishes, is refused, or says where the VM moved (none hangs), and the
    VM ends on one host intact."""
    n = "ft-exec-race"
    m = setup(n)
    stop, results = threading.Event(), {"ok": 0, "refused": 0, "moved": 0, "cut": [], "hung": 0}

    def worker():
        while not stop.is_set():
            for h in (A, B):
                try:
                    code, out = sh(h, n, "echo hi")
                except subprocess.TimeoutExpired:
                    results["hung"] += 1
                    continue
                if code == 0 and out == "hi":
                    results["ok"] += 1
                elif "moved to" in out:
                    results["moved"] += 1
                elif "not running" in out or "no vm named" in out:
                    results["refused"] += 1
                else:
                    results["cut"].append(out[-200:])

    workers = [threading.Thread(target=worker) for _ in range(6)]
    for w in workers:
        w.start()
    try:
        time.sleep(0.5)
        ok(migrate(A, n, B))
        wait_released(B, n)
        time.sleep(0.3)
        ok(migrate(B, n, A))
        wait_released(A, n)
        time.sleep(0.3)
    finally:
        stop.set()
        for w in workers:
            w.join()
    check("exec race: no exec hung", results["hung"] == 0, results)
    check("exec race: every exec finished, was refused or moved", not results["cut"] and results["ok"] > 0, results)
    check("exec race: back on A only", where(n) == {A: "running"}, where(n))
    check("exec race: md5 intact", md5(A, n) == m)
    cleanup(n)


def guest_calls():
    """Guest calls during and just after a migration: execs started while the
    VM moves (the source's page server down for a while, so the guest is
    still faulting its memory in) all finish (or are told it moved), and the
    target's own clock step goes through although its first guest
    connections drop."""
    n = "ft-guest-calls"
    m = setup(n)
    time.sleep(1)
    code, out = sh(A, n, "date -s @$(( $(date +%s) - 100 )) >/dev/null")
    assert code == 0, out
    stop, results = threading.Event(), {"ok": 0, "moved": 0, "failed": []}

    def worker(h):
        while not stop.is_set():
            try:
                code, out = sh(h, n, "echo hi")
            except subprocess.TimeoutExpired:
                code, out = None, "hung"
            if code == 0 and out == "hi":
                results["ok"] += 1
            elif "moved to" in out or "no vm named" in out:
                results["moved"] += 1
            else:
                results["failed"].append((h.addr, code, out[-200:]))

    workers = [threading.Thread(target=worker, args=(h,)) for h in (A, B) for _ in range(3)]
    for w in workers:
        w.start()
    time.sleep(0.3)
    fault(A, "pages", 3000)
    fault(B, "guest_drop", 1000)
    ok(migrate(A, n, B))
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
    before = vms(B)[n]["guest_retries"].get("CLOCK", 0)
    pause(B, n)
    fault(B, "guest_lose_reply", 300)
    resume(B, n)
    retried = lambda: vms(B)[n]["guest_retries"].get("CLOCK", 0) > before
    check("guest calls: a clock step with its reply lost went again", wait_for(retried, 10), vms(B)[n]["guest_retries"])
    check("guest calls: exec after the lost reply", sh(B, n, "echo hi") == (0, "hi"))
    cleanup(n)


def guest_hang():
    """A guest that never answers its agent (Firecracker stopped) must not
    hold anything forever: execs fail within their deadline, and once it is
    back, the VM still runs and migrates."""
    n = "ft-guest-hang"
    m = setup(n)
    fc = fc_pid(A, n)
    os.kill(fc, signal.SIGSTOP)
    times, raw = [], []

    def one():
        t = time.time()
        try:
            code, _ = sh(A, n, "echo hi")
            times.append((round(time.time() - t, 1), code))
        except subprocess.TimeoutExpired:
            times.append((None, None))

    # The VM process's own answer, which the CLI's 30 s of retries would hide.
    def one_raw():
        t = time.time()
        try:
            r = control(A, n, {"op": "exec", "session": os.urandom(16).hex(), "action": "start", "cmd": "echo hi"})
            raw.append((round(time.time() - t, 1), r["ok"]))
        except OSError as e:
            raw.append((None, str(e)))

    execs = [threading.Thread(target=f) for f in (one, one, one, one_raw, one_raw, one_raw)]
    for e in execs:
        e.start()
    for e in execs:
        e.join()
    os.kill(fc, signal.SIGCONT)
    check("guest hang: the vm fails each exec within the guest timeout",
          len(raw) == 3 and all(t is not None and t < 12 and r is False for t, r in raw), raw)
    check("guest hang: every CLI exec gave up within its deadline", all(t is not None and t < 40 and c != 0 for t, c in times), times)
    check("guest hang: exec works again", sh(A, n, "echo hi") == (0, "hi"))
    ok(migrate(A, n, B))
    wait_released(B, n)
    check("guest hang: migrates afterwards, md5 intact", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    cleanup(n)


def migrate_in_raw(host, name, ip, template_id, gen=None, template=None):
    """Asks `host` to prepare an incoming migration as a source would.
    Returns the open socket and the prepare reply."""
    h, port = host.addr.rsplit(":", 1)
    s = socket.create_connection((h, int(port)), timeout=60)
    mig = int.from_bytes(os.urandom(6), "little")
    # Newer than any the host has seen for it, as an arriving VM's is.
    gen = addr(host, ip).get("seen", 0) + 1 if gen is None else gen
    req = {"op": "migrate_in", "name": name, "mig": mig, "template": template or args.template, "id": template_id,
           "ip": ip, "gen": gen, "source": A.addr}
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
    # The incoming process holds the name (its lock) until it has given up.
    lock = os.path.join(B.run, "vms", f"{name}.lock")
    check(f"{label}: name free on B", wait_for(lambda: name not in vms(B) and not os.path.exists(lock), 10), vms(B).get(name))
    check(f"{label}: address free on B", wait_for(lambda: not addr(B, ip).get("holder") or name not in vms(B), 10), addr(B, ip))
    r = run(B, name, ip=ip)
    check(f"{label}: name and address usable on B", r["ok"], r)
    kill(B, name)


def template_id():
    n = "ft-tplid"
    ok(run(A, n))
    tid = vms(A)[n]["template_id"]
    kill(A, n)
    return tid


def prepare_disconnect():
    """A source that goes away after the target prepared leaves nothing behind."""
    n, ip = "ft-prep-gone", B.ips.split("-")[1].rsplit(".", 1)[0] + ".200"
    s, r, mig = migrate_in_raw(B, n, ip, template_id())
    check("prepare disconnect: target prepared", r.get("ok"), r)
    check("prepare disconnect: address held while prepared", addr(B, ip).get("holder") == n, addr(B, ip))
    s.close()
    nothing_left("prepare disconnect", n, ip)
    st = ok(peer(B, {"op": "migration", "mig": mig}))
    check("prepare disconnect: migration fenced as aborted", st["outcome"] == "aborted", st)


def prepare_trickle():
    """A source that trickles its header is cut off by one deadline (here 2 s,
    `short_incoming`), however much it keeps sending."""
    n, ip = "ft-prep-trickle", B.ips.split("-")[1].rsplit(".", 1)[0] + ".201"
    fault(B, "short_incoming", 30000)
    s, r, _ = migrate_in_raw(B, n, ip, template_id())
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


def gen_zero():
    """An arrival without a generation (0) is refused: no legacy exemption."""
    n, ip = "ft-gen0", B.ips.split("-")[1].rsplit(".", 1)[0] + ".202"
    s, r, _ = migrate_in_raw(B, n, ip, template_id(), gen=0)
    s.close()
    check("gen zero: refused", not r.get("ok") and "generation" in r.get("error", ""), r)
    r = peer(B, {"op": "route", "ip": ip, "via": "127.0.0.9"})
    check("gen zero: a route message without one is refused", not r.get("ok"), r)


def prepare_fail():
    """A target that fails once everything is prepared refuses before the
    source pauses; the VM never stops running."""
    n = "ft-prep-fail"
    m = setup(n)
    fault(B, "prepare_fail", 10000)
    r = migrate(A, n, B)
    fault(B, "prepare_fail", 0)
    check("prepare fail: migrate refused", not r["ok"] and "injected fault" in r["error"], r)
    check("prepare fail: running on A only", where(n) == {A: "running"}, where(n))
    check("prepare fail: md5 intact", md5(A, n) == m)
    ip = vms(A)[n]["ip"]
    check("prepare fail: target holds nothing", n not in vms(B) and not addr(B, ip).get("holder"), addr(B, ip))
    r = migrate(A, n, B)
    check("prepare fail: a later migration works", r["ok"] and where(n).get(B) == "running", r)
    wait_released(B, n)
    check("prepare fail: md5 intact on B", md5(B, n) == m)
    cleanup(n)


def abort_superseded():
    """A migration that aborts after the source paused does not resume the
    source if a newer generation of its address was recorded meanwhile (the
    address went to another VM): the copy is destroyed instead."""
    n = "ft-superseded"
    setup(n)
    v = vms(A)[n]
    ip, gen = v["ip"], v["gen"]
    fault(A, "pages", 30000)
    res = {}
    t = threading.Thread(target=lambda: res.update(r=migrate(A, n, B)))
    t.start()
    # While the target probes the dead page server, the address moves on.
    wait_for(lambda: vms(A).get(n, {}).get("state") == "source", 20)
    r = peer(A, {"op": "route", "ip": ip, "via": "127.0.0.9", "gen": gen + 1})
    t.join()
    fault(A, "pages", 0)
    r = res.get("r", {})
    check("abort superseded: migration failed", not r.get("ok"), r)
    check("abort superseded: source not resumed, destroyed", "superseded" in r.get("error", "") and
          wait_for(lambda: n not in vms(A), 10), (r, where(n)))
    check("abort superseded: running nowhere", where(n) == {}, where(n))
    subprocess.run(["ip", "route", "del", f"{ip}/32"], capture_output=True)


def fc_prepare():
    """Firecracker's prepared load (firecracker/0002-*.patch): refuses a second
    prepare, a snapshot of another layout, and a load after boot config."""
    art = args.artifacts
    tpls = os.path.join(art, "templates")
    fc = os.path.join(art, "firecracker")
    other = "small" if args.template != "small" else "default"
    vmstate = lambda t: os.path.join(tpls, t, "vmstate")
    if not os.path.exists(vmstate(other)):
        return print(f"fc prepare: skipped, no template {other!r} to mismatch with")

    def run_fc(label, steps):
        d = tempfile.mkdtemp(prefix="fvp", dir="/tmp")
        uffd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        uffd.bind(f"{d}/u.sock")
        uffd.listen(1)
        held = []
        threading.Thread(target=lambda: held.append(uffd.accept()), daemon=True).start()
        p = subprocess.Popen([fc, "--api-sock", f"{d}/api.sock", "--level", "Warn"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for(lambda: os.path.exists(f"{d}/api.sock"), 5)

        def put(path, body):
            r = subprocess.run(["curl", "-s", "-o", "/dev/stderr", "-w", "%{http_code}", "--unix-socket",
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
            p.kill()
            p.wait()
            subprocess.run(["rm", "-rf", d])

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

    run_fc("twice", twice)
    run_fc("mismatch", mismatch)
    run_fc("config", config_between)


def slow_preload():
    """The pages preloaded with the vmstate arrive late (`slow_preload`): the
    target's load goes ahead (fetching what it needs itself), but it commits
    and answers only once they are all in, and the held packets still follow
    its answer on the same connection, in order."""
    n = "ft-slow-preload"
    # Pages to preload: what loads of the template touch, which standby VMs learn.
    for h in (A, B):
        ok(cli_json(h, "standby", "--template", args.template, "1"))
        ok(cli_json(h, "standby", "--template", args.template, "0"))
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
    r = migrate(A, n, B)
    fault(A, "slow_preload", 0)
    stop.set()
    t.join()
    check("slow preload: migrated", r["ok"], r)
    res = r.get("result") or {}
    check("slow preload: committed only after the late pages", res.get("downtime_ms", 0) >= 300, res.get("downtime_ms"))
    held = res.get("held") or {}
    check("slow preload: held packets followed the answer intact",
          held.get("packets", 0) > 0 and held.get("injected") == held.get("packets") and held.get("dropped_target") == 0, held)
    st = wait_released(B, n)
    check("slow preload: released, only on B", st["released"] is True and where(n) == {B: "running"}, (st, where(n)))
    check("slow preload: md5 intact", md5(B, n) == m)
    cleanup(n)


# --- lifecycle: checkpoint / restore / pause / suspend -------------------------


def ckpt_path(label):
    os.makedirs(args.ckpt_dir, exist_ok=True)
    path = os.path.join(args.ckpt_dir, label)
    scenario_checkpoints.add(path)
    subprocess.run(["rm", "-rf", path])
    return path


def rm_ckpt(path):
    subprocess.run(["rm", "-rf", path])


def memhash(host, name):
    return ok(control(host, name, {"op": "debug", "what": "memhash"}))


def ckhash(host, path):
    return ok(cli_json(host, "debug", "ckhash", path))


def marker(host, name):
    """Starts a long-lived guest process; returns its (pid, start time)."""
    code, out = sh(host, name, "setsid sleep 424242 >/dev/null 2>&1 < /dev/null & echo $! > /tmp/marker.pid")
    assert code == 0, out
    return marker_id(host, name)


def marker_id(host, name):
    code, out = sh(host, name, 'p=$(cat /tmp/marker.pid); echo "$p $(cut -d" " -f2,22 /proc/$p/stat)"')
    return out if code == 0 else None


def guest_clock_error(host, name):
    """Guest wall clock minus host wall clock, in seconds (+- half an exec):
    of three readings, the one whose exec took least."""
    best = None
    for _ in range(3):
        before = time.time()
        code, out = sh(host, name, "date +%s.%N")
        after = time.time()
        if code == 0 and (best is None or after - before < best[0]):
            best = (after - before, float(out) - (before + after) / 2)
    return best[1] if best else None


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
    r = ok(checkpoint(A, n, path, stop=True))
    print(f"checkpoint: {r['checkpoint_ms']} ms ({r['data_mib']} MiB data), paused {r['paused_ms']} ms")
    leftovers = [f for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging-")]
    check("checkpoint: published, no partial left", os.path.exists(os.path.join(path, "manifest.json")) and not leftovers, leftovers)
    check("checkpoint --stop: gone from A", wait_for(lambda: n not in vms(A), 10), vms(A).get(n))
    # A's address restored on B: checkpoints restore anywhere with --ip auto,
    # but its own address only on its home host.
    r = restore(B, path)
    check("restore: B refuses A's address", not r["ok"] and "range" in r["error"], r)
    r = ok(restore(A, path))
    print(f"restore: ready in {r['ready_ms']} ms (snapshot load {r['restore_ms']} ms), clock was {r['clock_offset_ms']} ms off; {r['timings_ms']}")
    check("restore: same address", r["ip"] == ip and sh(A, n, "ip -4 -o addr show eth0")[1].count(ip) == 1, r["ip"])
    check("restore: TCP connection survived", echo(conn, b"after\n"))
    conn.close()
    with socket.create_connection((ip, 7000), timeout=10) as c2:
        check("restore: new TCP connection", echo(c2, b"new\n"))
    check("restore: md5 intact", md5(A, n) == m)
    check("restore: process survived (pid, start time)", marker_id(A, n) == proc_before, (proc_before, marker_id(A, n)))
    err = guest_clock_error(A, n)
    check("restore: guest clock right", err is not None and abs(err) < 0.5, err)
    check("restore: whole checkpoint paged in", wait_for(lambda: vms(A)[n]["pages_mib"]["remote"] == 0, 30), vms(A)[n]["pages_mib"])
    cleanup(n)
    check("restore: killing it gives the address back", wait_for(lambda: ip not in ok(A, {"op": "info"})["lent"], 10))
    rm_ckpt(path)


def checkpoint_fork():
    """checkpoint --keep-running: the VM goes on; the checkpoint restores as
    a second VM elsewhere, but only under a new address."""
    n, path = "ft-fork", ckpt_path("ft-fork")
    m = setup(n)
    r = ok(checkpoint(A, n, path))
    check("fork: still running on A", r["state"] == "running" and where(n) == {A: "running"}, where(n))
    again = checkpoint(A, n, path)
    check("fork: a checkpoint is never overwritten", not again["ok"] and "already exists" in again["error"], again)
    check("fork: refused before pausing", where(n) == {A: "running"}, where(n))
    code, _ = sh(A, n, "echo changed >> /tmp/f")
    check("fork: A keeps working", code == 0 and md5(A, n) != m)
    taken = restore(A, path, name="ft-fork2")
    check("fork: restore refuses an address in use", not taken["ok"] and "in use" in taken["error"], taken)
    r = ok(restore(B, path, name="ft-fork2", ip="auto"))
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
    ok(checkpoint(A, n, path, stop=True))
    pristine = path + ".orig"
    subprocess.run(["cp", "-a", path, pristine], check=True)

    def poke(file, offset):
        with open(f"{path}/{file}", "r+b") as f:
            f.seek(offset)
            b = f.read(1)
            f.seek(offset)
            f.write(bytes([b[0] ^ 1]))

    def reset():
        subprocess.run(["rm", "-rf", path], check=True)
        subprocess.run(["cp", "-a", pristine, path], check=True)

    poke("vmstate", 100)
    r = restore(B, path, ip="auto")
    check("corrupt vmstate: refused", not r["ok"] and "checksum" in r["error"], r)
    reset()
    poke("manifest.json", 40)
    r = restore(B, path, ip="auto")
    check("corrupt manifest: refused", not r["ok"] and "invalid" in r["error"], r)
    reset()
    text = open(f"{path}/manifest.json", "rb").read()
    body = json.loads(text.split(b"\n", 1)[1])
    body["template_id"] = "0123456789abcdef"
    forged = json.dumps(body).encode()
    open(f"{path}/manifest.json", "wb").write(fv_hash(forged).encode() + b"\n" + forged)
    r = restore(B, path, ip="auto")
    check("other template id: refused", not r["ok"] and "id mismatch" in r["error"], r)
    reset()
    poke("pages", 50 * 1024 * 1024)
    r = restore(B, path, ip="auto")
    check("corrupt page data: VM fails, never runs on", (not r["ok"]) or wait_for(lambda: n not in vms(B), 30), (r, vms(B).get(n)))
    kill(B, n)
    rm_ckpt(path)
    rm_ckpt(pristine)


def staged_mib():
    """Roughly how many MiB of page data checkpoints staged in --ckpt-dir
    have written."""
    n = 0
    for s in os.listdir(args.ckpt_dir):
        if s.startswith(".flexvm-staging-"):
            try:
                fd = os.open(os.path.join(args.ckpt_dir, s, "ck", "pages"), os.O_RDONLY)
            except OSError:
                continue
            n += sum(any(os.pread(fd, 4096, o)) for o in range(0, os.fstat(fd).st_size, 1 << 20))
            os.close(fd)
    return n


def checkpoint_crash():
    """The VM process dies while writing a checkpoint: no checkpoint appears
    (not even a partial one restores), and the next checkpoint to the same
    place clears the debris and succeeds."""
    n, path = "ft-crash", ckpt_path("ft-crash")
    setup(n, mib=1200)
    fault(A, "ckpt_slow", 120000)
    t = threading.Thread(target=lambda: checkpoint(A, n, path))
    t.start()

    def writing():
        return staged_mib() > 100 and vms(A).get(n, {}).get("checkpoint_copy")

    caught = wait_for(writing, 30)
    check("crash: caught the checkpoint mid-write", caught)
    pid, fc = vm_pid(A, n), fc_pid(A, n)
    os.kill(pid, signal.SIGKILL)
    t.join()
    fault(A, "ckpt_slow", 0)
    check("crash: the VM died with its process", wait_for(lambda: not alive(fc), 15) and n not in vms(A), vms(A).get(n))
    check("crash: no checkpoint published", not os.path.exists(path))
    r = restore(B, path, ip="auto")
    check("crash: nothing to restore", not r["ok"], r)
    partial = [os.path.join(args.ckpt_dir, f, "ck") for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging-")]
    check("crash: staging left behind (root-only)", len(partial) == 1, partial)
    for f in partial:
        r = restore(B, f, ip="auto")
        check("crash: the partial directory does not restore", not r["ok"], r)
    m = setup(n, mib=50)
    ok(checkpoint(A, n, path, stop=True))
    left = [f for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging-")]
    check("crash: next checkpoint cleared the debris", not left, left)
    ok(restore(B, path, ip="auto"))
    check("crash: next checkpoint restores", md5(B, n) == m)
    cleanup(n)
    rm_ckpt(path)


def pause_resume():
    n = "ft-pause"
    m = setup(n)
    sh(A, n, "date -s @$(date +%s)")  # fresh VMs keep the template's clock; start from a right one
    check("pause: SIGTSTP pauses (the process keeps running)", pause(A, n) and alive(vm_pid(A, n)), vms(A)[n])
    r = control(A, n, {"op": "exec", "cmd": "echo hi"})
    check("pause: exec refused while paused", not r["ok"] and "not running" in r["error"], r)
    time.sleep(0.2)
    controller_quiet = vms(A)[n]["state"] == "paused"
    time.sleep(3)
    check("pause: controller left it alone", controller_quiet and vms(A)[n]["state"] == "paused", vms(A)[n]["state"])
    took = resume(A, n)
    print(f"pause: {took * 1000:.1f} ms from SIGCONT to running in the registry")
    check("pause: resumes within 50 ms", took < 0.05, took)
    time.sleep(0.5)
    err = guest_clock_error(A, n)
    check("pause: guest clock right after 3 s paused", err is not None and abs(err) < 0.5, err)
    check("pause: md5 intact", md5(A, n) == m)
    # SIGCONT without a SIGTSTP first (as after any SIGSTOP) does nothing.
    signal_vm(A, n, signal.SIGSTOP)
    signal_vm(A, n, signal.SIGCONT)
    check("pause: a stray SIGSTOP/SIGCONT leaves a running vm running", vms(A)[n]["state"] == "running"
          and sh(A, n, "echo hi") == (0, "hi"), vms(A)[n]["state"])
    pause(A, n)
    ok(migrate(A, n, B))
    # Stall the pull: a resume on the target must wait for all its memory.
    fault(A, "pages", 2000)
    check("paused migrate: stays paused on the target", vms(B)[n]["state"] == "paused", vms(B)[n]["state"])
    waited = resume(B, n)
    st = wait_released(B, n)
    check("paused migrate: resume waited for the whole pull", waited > 1.0 and st["background_pull_ms"] is not None
          and st["background_pull_ms"] <= waited * 1000 + 100, (waited, st))
    check("paused migrate: source released, only on B", where(n) == {B: "running"} and st["released"] is True, (where(n), st))
    check("paused migrate: runs on B after resume, md5 intact", md5(B, n) == m)
    cleanup(n)


def signals():
    """SIGTERM on a migration source waits for the release (no suspend);
    SIGINT destroys; a suspend is not undone by the SIGCONT systemd sends
    after SIGTERM."""
    n = "ft-signals"
    setup(n)
    fault(A, "pages", 3000)
    ok(migrate(A, n, B))
    signal_vm(A, n, signal.SIGTERM)
    st = wait_released(B, n)
    check("signals: SIGTERM on a source: no suspend, released", st["released"] is True and not os.path.exists(
        os.path.join(A.state, "suspended", n)), st)
    pid = vm_pid(B, n)
    os.kill(pid, signal.SIGTERM)
    os.kill(pid, signal.SIGCONT)
    check("signals: SIGTERM + SIGCONT suspends", wait_for(lambda: not alive(pid), 60) and vms(B).get(n, {}).get("state") == "suspended", vms(B).get(n))
    ok(resume_suspended(B, n))
    pid = vm_pid(B, n)
    os.kill(pid, signal.SIGINT)
    check("signals: SIGINT destroys", wait_for(lambda: not alive(pid), 30) and n not in vms(B), vms(B).get(n))


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
    ok(checkpoint(A, n, path, stop=True))
    wait_for(lambda: n not in vms(A), 10)

    def held(no_hold):
        fault(A, "restore_no_hold", 600000 if no_hold else 0)
        r = ok(restore(A, path, paused=True))
        fault(A, "restore_no_hold", 0)
        check(f"held{'(no hold)' if no_hold else ''}: restored paused", r["state"] == "paused" and vms(A)[n]["state"] == "paused", r)
        wait_for(lambda: memhash(A, n)["remote"] == 0, 30)
        ip = vm_ip(A, n)
        h0, f0 = memhash(A, n), tap_frames(A, n)
        conn = subprocess.Popen(["python3", "-c",
                                 "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); "
                                 "s.sendall(b'CONNECT 52\\nPING\\n'); s.settimeout(30); d=b''\nwhile b'pong' not in d:\n c=s.recv(200)\n if not c: break\n d+=c\nprint(d)",
                                 vsock_path(A, n)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(30):
            udp.sendto(b"x" * 64, (ip, 9))
            time.sleep(0.1)
        h1, f1 = memhash(A, n), tap_frames(A, n)
        return h0, h1, f0, f1, conn

    h0, h1, f0, f1, conn = held(False)
    check("held: guest memory unchanged under tap, vsock and timer activity", h0 == h1, (h0, h1))
    check("held: no frames moved", f0 == f1, (f0, f1))
    check("held: vsock connection waits", conn.poll() is None)
    t = time.time()
    resume(A, n)
    out, _ = conn.communicate(timeout=30)
    check("held: pending vsock connection answered after resume", "OK" in out and "pong" in out, out)
    time.sleep(0.5)
    check("held: pending frames delivered after resume", tap_frames(A, n)[1] > f1[1], (f1, tap_frames(A, n)))
    guest_healthy(A, n, "held after resume", m)
    print(f"held: resumed and answered within {time.time() - t:.2f} s")
    kill(A, n)
    # Held at a new address: the guest takes it on resume (and only then).
    r = ok(restore(B, path, paused=True, ip="auto"))
    refused = checkpoint(B, n, path + "-x")
    check("held at a new address: no checkpoint before it takes the address", not refused["ok"], refused)
    rm_ckpt(path + "-x")
    resume(B, n)
    code, out = sh(B, n, "ip -4 -o addr show eth0")
    check("held at a new address: guest has it, and only it, after resume", r["ip"] in out and old_ip not in out, (r["ip"], old_ip, out))
    kill(B, n)

    h0, h1, f0, f1, conn = held(True)
    check("no hold (control): the same activity changes guest memory", h0 != h1 or f0 != f1, (h0, h1, f0, f1))
    conn.kill()
    kill(A, n)
    rm_ckpt(path)


def fc_api(sock, method, path, body=None):
    cmd = ["curl", "-s", "--unix-socket", sock, "-X", method, f"http://localhost{path}"]
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
    r = ok(checkpoint(A, n, path, stop=True))
    print(f"hotplug: settled in {r['timings_ms']['settle_hotplug']} ms")
    check("hotplug: checkpoint waited for the resize", r["timings_ms"]["settle_hotplug"] > 1, r["timings_ms"])
    text = open(f"{path}/manifest.json", "rb").read()
    plugged = json.loads(text.split(b"\n", 1)[1])["hotplug_mib"]
    check("hotplug: saved with the resize done", plugged == want, (plugged, want))
    ok(restore(B, path, ip="auto"))
    check("hotplug: restores intact", md5(B, n) == m)
    cleanup(n)
    rm_ckpt(path)


def checkpoint_untrusted_dir():
    """Checkpoints into a user's directory: the files are theirs, nothing is
    left behind, and a restore never follows a symlink planted in one."""
    n = "ft-user"
    user = int(os.environ.get("SUDO_UID", "65534"))
    d = ckpt_path("user")
    os.makedirs(d)
    os.chown(d, user, user)
    path = os.path.join(d, "ck")
    setup(n, mib=20)
    ok(checkpoint(A, n, path, stop=True))
    st = os.stat(path)
    check("untrusted dir: checkpoint belongs to the directory's owner", st.st_uid == user, st.st_uid)
    left = [f for f in os.listdir(d) if f.startswith(".flexvm-staging")]
    check("untrusted dir: no staging left behind", not left, left)
    os.rename(f"{path}/vmstate", f"{path}/vmstate.real")
    os.symlink(f"{path}/vmstate.real", f"{path}/vmstate")
    r = restore(B, path, ip="auto")
    check("untrusted dir: restore refuses a symlinked file", not r["ok"] and "vmstate" in r["error"], r)
    os.unlink(f"{path}/vmstate")
    os.rename(f"{path}/vmstate.real", f"{path}/vmstate")
    r = restore(B, path, ip="auto")
    check("untrusted dir: restores once it is a plain file again", r["ok"], r)
    cleanup(n)
    rm_ckpt(d)


def resume_failures():
    """A suspended VM whose resume fails before its vCPUs ran stays
    suspended; one that fails after they ran is gone, never re-armed (its
    checkpoint would replay what it did)."""
    n = "ft-resume-fail"
    m = setup(n)
    suspend(A, n)
    fault(A, "restore_before_run", 60000)
    r = resume_suspended(A, n)
    fault(A, "restore_before_run", 0)
    check("resume fails before running: refused", not r["ok"], r)
    check("resume fails before running: still suspended", vms(A).get(n, {}).get("state") == "suspended", vms(A).get(n))
    ok(resume_suspended(A, n))
    check("resume fails before running: resumes later, md5 intact", md5(A, n) == m)
    suspend(A, n)
    fault(A, "restore_after_run", 60000)
    r = resume_suspended(A, n)
    fault(A, "restore_after_run", 0)
    check("resume fails after running: refused", not r["ok"] and "consumed" in r["error"], r)
    check("resume fails after running: not re-armed", n not in vms(A), vms(A).get(n))
    r = resume_suspended(A, n)
    check("resume fails after running: no second resume", not r["ok"], r)
    cleanup(n)


def suspend_resume():
    """SIGTERM suspends: the VM's memory is freed and its process exits;
    `flexvm resume` pages it back in lazily, in a new process."""
    n = "ft-suspend"
    m = setup(n)
    proc_before = marker(A, n)
    fc = fc_pid(A, n)
    r = suspend(A, n)
    print(f"suspend: {r.get('suspend_ms')} ms, freed {r.get('freed_rss_mib')} MiB RSS, {r.get('data_mib')} MiB on disk")
    v = vms(A).get(n, {})
    check("suspend: listed suspended, no pid", v.get("state") == "suspended" and not v.get("pid"), v)
    check("suspend: its Firecracker is gone", not alive(fc), fc)
    code, out = sh(A, n, "echo hi")
    check("suspend: exec refused", code != 0, out)
    r = run(A, n)
    check("suspend: its name stays taken", not r["ok"] and "suspended" in r["error"], r)
    # Nothing about a suspended VM lives in a process: the listeners restart.
    stop_listeners()
    start_listeners()
    check("suspend: still suspended", vms(A).get(n, {}).get("state") == "suspended", vms(A).get(n))
    time.sleep(2)
    r = ok(resume_suspended(A, n))
    print(f"suspend: resumed, ready in {r['ready_ms']} ms; clock was {r['clock_offset_ms']} ms off")
    check("suspend: md5 intact", md5(A, n) == m)
    check("suspend: process survived", marker_id(A, n) == proc_before, (proc_before, marker_id(A, n)))
    err = guest_clock_error(A, n)
    check("suspend: guest clock right", err is not None and abs(err) < 0.5, err)
    check("suspend: paged back in", wait_for(lambda: vms(A)[n]["pages_mib"]["remote"] == 0, 30), vms(A)[n])
    cleanup(n)


def suspend_gen():
    """A suspended VM keeps its address's generation beside its checkpoint;
    one without it is quarantined (never given a new one), and its
    checkpoint still restores with --ip auto."""
    n = "ft-susp-gen"
    m = setup(n, mib=20)
    gen = vms(A)[n]["gen"]
    suspend(A, n)
    genfile = os.path.join(A.state, "suspended", f".gen-{n}")
    check("suspend gen: recorded beside the checkpoint", open(genfile).read().strip() == str(gen), gen)
    os.rename(genfile, genfile + ".x")
    check("suspend gen: without it, listed quarantined", vms(A).get(n, {}).get("state") == "quarantined", vms(A).get(n))
    r = resume_suspended(A, n)
    check("suspend gen: without it, not resumed", not r["ok"] and "quarantined" in r["error"], r)
    os.rename(genfile + ".x", genfile)
    ok(resume_suspended(A, n))
    check("suspend gen: resumes once it is back, md5 intact", md5(A, n) == m)
    cleanup(n)


def open_under(pid, path):
    """Files under `path` that process `pid` has open."""
    out = []
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            t = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if t.startswith(path.rstrip("/") + "/"):
            out.append(t)
    return out


def free_mib(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize >> 20


def suspend_disk_freed():
    """A resumed suspended VM gives its checkpoint's disk space back once
    every page is in (its pager lets go of the page file), while it runs on."""
    n = "ft-susp-disk"
    m = setup(n, mib=1024)
    r = suspend(A, n)
    d, data = r["dir"], r.get("data_mib", 0)
    check("disk freed: checkpoint written", data >= 1000, r)
    before = free_mib(A.state)
    ok(resume_suspended(A, n))
    check("disk freed: paged back in", wait_for(lambda: vms(A)[n]["pages_mib"]["remote"] == 0, 60), vms(A)[n])
    check("disk freed: checkpoint deleted", wait_for(lambda: not os.path.exists(d), 30))
    pid = vm_pid(A, n)
    check("disk freed: the vm process holds no checkpoint file", wait_for(lambda: not open_under(pid, d), 10), open_under(pid, d))
    after = free_mib(A.state)
    print(f"disk freed: {data} MiB checkpoint; free space {before} -> {after} MiB (+{after - before})")
    check("disk freed: its space came back", after - before >= data * 0.8, (before, after, data))
    check("disk freed: still running, md5 intact", vms(A)[n]["state"] == "running" and md5(A, n) == m)
    cleanup(n)


def resume_mark_fails():
    """A resume whose STARTED marker cannot be made durable takes it back
    durably and leaves the VM suspended; if taking it back fails too, the VM
    is quarantined (neither resumable nor deleted) until a kill, or a reboot
    lets the disk decide."""
    n = "ft-mark-fail"
    m = setup(n, mib=20)
    d = suspend(A, n)["dir"]
    exists = lambda f: os.path.exists(os.path.join(d, f))

    fault(A, "started_fsync", 60000)
    r = resume_suspended(A, n)
    fault(A, "started_fsync", 0)
    check("mark fails: resume refused", not r["ok"] and "quarantined" not in r["error"], r)
    check("mark fails: still suspended", vms(A).get(n, {}).get("state") == "suspended", vms(A).get(n))
    check("mark fails: marker taken back", not exists("STARTED") and exists("manifest.json"))
    ok(resume_suspended(A, n))
    check("mark fails: resumes later, md5 intact", md5(A, n) == m)

    d = suspend(A, n)["dir"]
    fault(A, "started_fsync", 60000)
    fault(A, "started_unmark", 60000)
    r = resume_suspended(A, n)
    disarm()
    check("unmark fails: resume refused, quarantined", not r["ok"] and "quarantined" in r["error"], r)
    v = vms(A).get(n, {})
    check("unmark fails: listed quarantined, on disk", v.get("state") == "quarantined" and exists("QUARANTINE"), v)
    r = resume_suspended(A, n)
    check("unmark fails: no resume while quarantined", not r["ok"] and "quarantined" in r["error"], r)
    check("unmark fails: checkpoint kept", exists("manifest.json"))
    # A reboot (another boot id): the disk has no marker, so it is suspended again.
    q = open(os.path.join(d, "QUARANTINE")).read()
    open(os.path.join(d, "QUARANTINE"), "w").write("another-boot " + q.split(" ", 1)[1])
    ok(resume_suspended(A, n))
    check("unmark fails: after a reboot, resumes, md5 intact", md5(A, n) == m)

    # The other outcome: the marker did reach the disk. Resume takes the
    # checkpoint for consumed and deletes it: the VM is lost, never replayed.
    d = suspend(A, n)["dir"]
    fault(A, "started_fsync", 60000)
    fault(A, "started_unmark", 60000)
    resume_suspended(A, n)
    disarm()
    check("marker kept: quarantined", vms(A).get(n, {}).get("state") == "quarantined", vms(A).get(n))
    open(os.path.join(d, "STARTED"), "w").close()
    check("marker kept: no longer listed (consumed)", n not in vms(A), vms(A).get(n))
    r = resume_suspended(A, n)
    check("marker kept: no resume (nothing replays)", not r["ok"], r)
    check("marker kept: checkpoint deleted", not os.path.exists(d))
    m = setup(n, mib=20)

    d = suspend(A, n)["dir"]
    fault(A, "started_fsync", 60000)
    fault(A, "started_unmark", 60000)
    resume_suspended(A, n)
    disarm()
    check("quarantined kill: quarantined", vms(A).get(n, {}).get("state") == "quarantined", vms(A).get(n))
    ok(kill(A, n))
    check("quarantined kill: gone", n not in vms(A), vms(A).get(n))
    check("quarantined kill: checkpoint deleted", not exists("manifest.json"))
    r = resume_suspended(A, n)
    check("quarantined kill: no resume", not r["ok"], r)
    cleanup(n)


def standby():
    """Standby VMs: `run` claims one (a resume and START), its replacement
    comes up, `standby 0` stops them all; without one, run loads cold."""
    t = args.template
    ok(cli_json(A, "standby", "--template", t, "2"))
    live = lambda: len([f for f in os.listdir(os.path.join(A.run, "standby", t)) if f.endswith(".lock") and alive(f[:-5])])
    check("standby: two ready", live() == 2, live())
    r = ok(run(A, "ft-sb1"))
    check("standby: run claims one", r["hot"] is True and r["ready_ms"] < 50, r)
    check("standby: claimed vm works", sh(A, "ft-sb1", "echo hi") == (0, "hi"))
    check("standby: refilled to two", wait_for(lambda: live() == 2, 60), live())
    ok(cli_json(A, "standby", "--template", t, "0"))
    check("standby: 0 stops them", wait_for(lambda: live() == 0, 30), live())
    r = ok(run(A, "ft-sb2"))
    check("standby: without one, a cold run", r["hot"] is False, r)
    cleanup("ft-sb1")
    cleanup("ft-sb2")


# --- copy-on-write and incremental checkpoints --------------------------------
#
# memwriter (scripts/memwriter.c) rewrites guest memory continuously, each
# page stamped with its iteration and a random salt, and checks every page
# against its own record before rewriting it; on SIGUSR1 each thread stops at
# an iteration boundary and checks all its pages (see the source). A restored
# copy that finds nothing wrong was saved exactly as it was at the pause. The
# ckpt_memhash fault also hashes guest memory during the pause, which
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
    ok(run(A, n))
    start_writer(A, n, mib=64)
    fault(A, "ckpt_memhash", 120000)
    fault(A, "ckpt_slow", 120000)
    res = {}
    t = threading.Thread(target=lambda: res.update(r=checkpoint(A, n, path)))
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
    h = ckhash(A, path)
    check("cow: checkpoint == memory at the pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
    errors, _, out = writer_check(A, n)
    check("cow: the original is intact", errors == 0, out)
    ok(restore(B, path, name="ft-cow2", ip="auto"))
    errors, _, out = writer_check(B, "ft-cow2")
    check("cow: the restored copy has exactly the pause-time memory", errors == 0, out)
    fault(A, "ckpt_memhash", 0)
    cleanup(n)
    cleanup("ft-cow2")
    rm_ckpt(path)


def cow_abort():
    """A copy that fails half way (and one that a kill cuts short) publishes
    nothing; the VM runs on unharmed, and the next checkpoint is complete."""
    n, path = "ft-cow-abort", ckpt_path("ft-cow-abort")
    ok(run(A, n))
    start_writer(A, n, mib=64)
    ok(checkpoint(A, n, path + "-base"))
    fault(A, "ckpt_abort", 60000)
    r = checkpoint(A, n, path)
    fault(A, "ckpt_abort", 0)
    check("cow abort: checkpoint failed", not r["ok"] and "abort" in r["error"], r)
    check("cow abort: nothing published", not os.path.exists(path))
    check("cow abort: VM still running", where(n) == {A: "running"} and not vms(A)[n]["checkpoint_copy"], vms(A).get(n))
    errors, _, out = writer_check(A, n)
    check("cow abort: guest memory intact, writes flow", errors == 0, out)
    # The failed copy gave its dirty pages back: the base still holds.
    fault(A, "ckpt_memhash", 60000)
    r = ok(checkpoint(A, n, path, incremental=True))
    fault(A, "ckpt_memhash", 0)
    check("cow abort: next checkpoint is an exact delta on the old base",
          r["parent"] is not None and ckhash(A, path)["hash"] == r["pause_memhash"], r["parent"])
    # A kill gives the copy up rather than waiting for it.
    fault(A, "ckpt_slow", 60000)
    res = {}
    t = threading.Thread(target=lambda: res.update(r=checkpoint(A, n, path + "-killed")))
    t.start()
    wait_for(lambda: vms(A).get(n, {}).get("checkpoint_copy"), 30)
    start = time.time()
    k = kill(A, n)
    took = time.time() - start
    t.join()
    fault(A, "ckpt_slow", 0)
    check("cow abort: kill during the copy is quick", k["ok"] and took < 10, (k, took))
    check("cow abort: killed copy published nothing", not res["r"]["ok"] and not os.path.exists(path + "-killed"), res)
    for p in (path, path + "-base", path + "-killed"):
        rm_ckpt(p)


def cow_crash():
    """The VM process dies while a running VM's checkpoint is being copied:
    no checkpoint appears, and the next one to the same place succeeds."""
    n, path = "ft-cow-crash", ckpt_path("ft-cow-crash")
    ok(run(A, n))
    start_writer(A, n, mib=64)
    fault(A, "ckpt_slow", 120000)
    t = threading.Thread(target=lambda: checkpoint(A, n, path))
    t.start()
    check("cow crash: caught the copy in the background", wait_for(lambda: vms(A).get(n, {}).get("checkpoint_copy"), 30))
    time.sleep(0.5)
    pid, fc = vm_pid(A, n), fc_pid(A, n)
    os.kill(pid, signal.SIGKILL)
    t.join()
    fault(A, "ckpt_slow", 0)
    check("cow crash: no checkpoint published", not os.path.exists(path))
    r = restore(B, path, ip="auto")
    check("cow crash: nothing to restore", not r["ok"], r)
    partial = [os.path.join(args.ckpt_dir, f, "ck") for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging-")]
    for f in partial:
        r = restore(B, f, ip="auto")
        check("cow crash: the partial directory does not restore", not r["ok"], r)
    check("cow crash: the VM died with its process", wait_for(lambda: not alive(fc), 15) and n not in vms(A), vms(A).get(n))
    ok(run(A, n))
    start_writer(A, n, mib=16)
    ok(checkpoint(A, n, path))
    left = [f for f in os.listdir(args.ckpt_dir) if f.startswith(".flexvm-staging-")]
    check("cow crash: next checkpoint cleared the debris", not left, left)
    ok(restore(B, path, name=n + "2", ip="auto"))
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
    ok(run(A, n))
    r = checkpoint(A, n, paths[0], incremental=True)
    check("incremental: refused without a base", not r["ok"] and "build on" in r["error"], r)
    code, out = sh(A, n, "dd if=/dev/urandom of=/tmp/f bs=1M count=200 2>/dev/null; md5sum /tmp/f")
    m = out.split()[0]
    start_writer(A, n, mib=4)
    fault(A, "ckpt_memhash", 120000)
    res = []
    for i, p in enumerate(paths):
        r = ok(checkpoint(A, n, p, incremental=i > 0))
        res.append(r)
        print(f"incremental {i}: paused {r['paused_ms']} ms, {r['data_mib']} MiB data, dirty {r['dirty_mib']} MiB, parent {r['parent']}")
        time.sleep(1)
    fault(A, "ckpt_memhash", 0)
    check("incremental: deltas store only what changed", all(r["data_mib"] < res[0]["data_mib"] / 4 for r in res[1:]),
          [r["data_mib"] for r in res])
    check("incremental: deltas name their parent", [r["parent"] for r in res] == [None, "../ft-inc0", "../ft-inc1"],
          [r["parent"] for r in res])
    for i, p in enumerate(paths):
        h = ckhash(A, p)
        check(f"incremental: link {i} == memory at its pause", h["hash"] == res[i]["pause_memhash"] and len(h["chain"]) == i, h)
    for i, x in ((2, "ft-inc3"), (1, "ft-inc2")):
        ok(restore(B, paths[i], name=x, ip="auto"))
        errors, _, out = writer_check(B, x)
        check(f"incremental: restore of link {i} intact", errors == 0 and md5(B, x).startswith(m), out)
        cleanup(x)
    # A VM that stops is never stopped onto a chain whose page data is bad.
    pages = os.path.join(paths[0], "pages")
    good = open(pages, "rb").read(4096)
    with open(pages, "r+b") as f:
        f.write(bytes([good[0] ^ 1]) + good[1:])
    r = checkpoint(A, n, paths[2] + "s", stop=True, incremental=True)
    check("incremental: no --stop delta onto corrupt parent data", not r["ok"] and "checksum" in r["error"] and not os.path.exists(paths[2] + "s"), r)
    check("incremental: VM runs on after that refusal", where(n) == {A: "running"}, where(n))
    with open(pages, "r+b") as f:
        f.write(good)
    # No delta onto a chain whose older ancestor has gone.
    os.rename(paths[0], paths[0] + ".moved")
    r = checkpoint(A, n, paths[2] + "x", incremental=True)
    check("incremental: no delta onto a broken chain", not r["ok"] and "full one" in r["error"] and not os.path.exists(paths[2] + "x"), r)
    check("incremental: VM runs on after the refusal", where(n) == {A: "running"}, where(n))
    os.rename(paths[0] + ".moved", paths[0])
    # A replaced parent (same path, other contents) and a missing one.
    os.rename(paths[1], paths[1] + ".moved")
    r = restore(B, paths[2], name="ft-inc4", ip="auto")
    check("incremental: missing parent refused", not r["ok"] and "parent" in r["error"], r)
    subprocess.run(["sudo", "cp", "-a", paths[0], paths[1]], check=True)
    r = restore(B, paths[2], name="ft-inc4", ip="auto")
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
    # Copies fail from 0.5 s after the target took the VM on, and the fault
    # deadline is 1 s: nothing (a stalled fetch, a requeue) may stretch it.
    check("stuck: within the fault deadline (< 3 s)", gave_up and took < 3, f"{took:.1f} s")
    cleanup(n)


def cow_reports_held():
    """Exercise Firecracker's report hold and the pager's REMOVE fallback
    with disk writers gated until the guest has freed memory."""
    n, path = "ft-cow-fpr", ckpt_path("ft-cow-fpr")
    ok(run(A, n))
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
        t = threading.Thread(target=lambda: res.update(r=checkpoint(A, n, path)))
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
            h = ckhash(A, path)
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
    ok(run(A, n))
    start_writer(A, n, mib=32)
    ok(checkpoint(A, n, path + "-base"))
    time.sleep(1)  # the writer unprotects (and dirties) pages
    fault(A, "ckpt_fail_write", 60000)
    r = checkpoint(A, n, path + "-stop", stop=True)
    fault(A, "ckpt_fail_write", 0)
    check("failed stop: refused, nothing published", not r["ok"] and "injected" in r["error"] and not os.path.exists(path + "-stop"), r)
    check("failed stop: VM runs on", where(n) == {A: "running"}, where(n))
    time.sleep(1)
    fault(A, "ckpt_memhash", 120000)
    for label, inc in (("delta", True), ("full", False)):
        p = f"{path}-{label}"
        r = ok(checkpoint(A, n, p, incremental=inc))
        h = ckhash(A, p)
        check(f"failed stop: next {label} checkpoint == memory at its pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
        ok(restore(B, p, name=n + "2", ip="auto"))
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
    ok(run(A, n))
    start_writer(A, n, mib=32)
    ok(checkpoint(A, n, path + "-a"))
    time.sleep(1)
    fault(A, "ckpt_fail_protect", 60000)
    r = checkpoint(A, n, path + "-b")
    fault(A, "ckpt_fail_protect", 0)
    check("rearm: failed re-protection refused", not r["ok"] and "injected" in r["error"], r)
    fault(A, "ckpt_fail_write", 60000)
    r = checkpoint(A, n, path + "-b")
    fault(A, "ckpt_fail_write", 0)
    check("rearm: re-armed checkpoint failed as injected", not r["ok"] and "injected" in r["error"], r)
    r = checkpoint(A, n, path + "-b", incremental=True)
    check("rearm: no delta on the base from before the re-arm", not r["ok"] and "build on" in r["error"], r)
    fault(A, "ckpt_memhash", 120000)
    for label, inc in (("c", False), ("d", True)):
        r = ok(checkpoint(A, n, path + "-" + label, incremental=inc))
        h = ckhash(A, path + "-" + label)
        check(f"rearm: {'delta' if inc else 'full'} afterwards == memory at its pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
    fault(A, "ckpt_memhash", 0)
    ok(restore(B, path + "-d", name=n + "2", ip="auto"))
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
    ok(run(A, n))
    start_writer(A, n, mib=32)
    ok(checkpoint(A, n, os.path.join(top, "base")))
    fault(A, "ckpt_slow", 120000)
    res = {}
    t = threading.Thread(target=lambda: res.update(r=checkpoint(A, n, os.path.join(top, "d1"), incremental=True)))
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



def ckpt_packet_hold():
    """Packets for a VM that arrive while a keep-running checkpoint has it
    paused are held and handed to it, not lost on its downed tap: a 1 kHz
    UDP sequence stream across three checkpoints arrives whole, and a TCP
    connection keeps echoing without a retransmit."""
    n = "ft-ckpt-pkt"
    ok(run(A, n))
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
        results.append(checkpoint(A, n, paths[-1]))
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



SCENARIOS = dict(
    basic=basic, route=route, lost_ack=lost_ack, unknown=unknown, refused=refused, pages_blip=pages_blip,
    pages_dead_restore=pages_dead_restore, pages_dead=pages_dead, resume_kill=resume_kill, prepared_retry=prepared_retry,
    quiet_source=quiet_source, exec_race=exec_race, guest_calls=guest_calls, guest_hang=guest_hang,
    source_killed=source_killed, target_killed=target_killed, abort_superseded=abort_superseded, gen_zero=gen_zero,
    checkpoint_restore=checkpoint_restore, checkpoint_fork=checkpoint_fork, checkpoint_corrupt=checkpoint_corrupt,
    checkpoint_crash=checkpoint_crash, pause_resume=pause_resume, signals=signals, suspend_resume=suspend_resume,
    suspend_gen=suspend_gen, checkpoint_hotplug=checkpoint_hotplug, checkpoint_untrusted_dir=checkpoint_untrusted_dir,
    resume_failures=resume_failures, held_restore_frozen=held_restore_frozen, cow_exact=cow_exact, cow_abort=cow_abort,
    cow_crash=cow_crash, cow_reports_held=cow_reports_held, ckpt_incremental=ckpt_incremental,
    ckpt_failed_stop=ckpt_failed_stop, ckpt_rearm=ckpt_rearm, ckpt_dir_moved=ckpt_dir_moved,
    prepare_disconnect=prepare_disconnect, prepare_trickle=prepare_trickle, prepare_fail=prepare_fail,
    fc_prepare=fc_prepare, slow_preload=slow_preload, ckpt_packet_hold=ckpt_packet_hold, standby=standby,
    suspend_disk_freed=suspend_disk_freed, resume_mark_fails=resume_mark_fails)
names = [n for s in args.scenarios for n in (list(SCENARIOS) if s == "all" else [s])]
if os.geteuid() != 0:
    sys.exit("run as root (sudo)")
start_listeners()
# Leftovers of an earlier, interrupted run.
for h in (A, B):
    for n in vms(h):
        if n.startswith("ft-"):
            kill(h, n)
try:
    for s in names:
        scenario_vms.clear()
        scenario_checkpoints.clear()
        try:
            SCENARIOS[s]()
        except Exception as e:
            traceback.print_exc()
            check(f"{s}: raised {type(e).__name__}", False, e)
        finally:
            disarm()
            for n in scenario_vms:
                for h in (A, B):
                    kill(h, n)
            for path in scenario_checkpoints:
                rm_ckpt(path)
finally:
    stop_listeners()
print("failures:", failures)
sys.exit(1 if failures else 0)
