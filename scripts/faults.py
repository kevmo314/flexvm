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
import argparse, base64, json, os, re, signal, socket, subprocess, sys, tempfile, threading, time, traceback

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
p.add_argument("--image", default="public.ecr.aws/docker/library/busybox:1.36",
               help="container image of the app_log scenario's template (APP_TEMPLATE names a built one instead)")
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
                v.update(tap=d["describe"]["tap"], pages_mib=d["describe"]["pages_mib"], regions=d["describe"]["regions"],
                         plugged_mib=d["describe"]["plugged_mib"], requested_mib=d["describe"]["requested_mib"],
                         guest_mib=d["describe"]["guest_mib"], admitted_mib=d["describe"]["admitted_mib"],
                         throttled=d["describe"]["throttled"],
                         checkpoint_copy=d["describe"]["checkpoint_copy"], checkpoint_copy_stats=d["checkpoint_copy_stats"],
                         background_pull_ms=d["background_pull_ms"], failed=d["failed"], guest_retries=d["guest_retries"])
    return out


def where(name):
    """Where `name` is, and in what state (not counting records of VMs that died)."""
    return {h: v[name]["state"] for h in (A, B) for v in [vms(h)] if name in v and v[name].get("pid")}


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
          "started_fsync", "started_unmark", "start_stall", "incoming_stall", "claim_stall", "handoff_stall", "ckpt_wp_race",
          "fetch_tail_enomem", "fetch_enomem_stuck", "publish", "no_evict", "suspend_stall", "uffd_err", "publish_fsync", "revoke_cleanup", "no_admit", "no_meminfo", "release_stall")


def disarm():
    """Disarms every test fault on both hosts, so none outlives its scenario."""
    for h in (A, B):
        try:
            os.unlink(os.path.join(h.run, "faults.json"))
        except OSError:
            pass


def setup(name, host=None, mib=200, template=None):
    host = host or A
    ok(run(host, name, template=template))
    # iflag=fullblock: a short read of /dev/urandom would otherwise make a short file.
    code, out = sh(host, name, f"dd if=/dev/urandom of=/tmp/f bs=1M count={mib} iflag=fullblock 2>/dev/null && wc -c </tmp/f && md5sum /tmp/f")
    assert code == 0, out
    size, digest = out.split()[:2]
    assert int(size) == mib << 20, f"dirty workload wrote {size} bytes, not {mib} MiB"
    return digest


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


def start_listener(h, listen=None, extra=()):
    """`h`'s listener, on `listen` (default: its address) with `extra` flags."""
    other = B if h is A else A
    for d in (h.state, h.run):
        os.makedirs(d, exist_ok=True)
    lg = open(os.path.join(h.run, "listen.log"), "a")
    listeners[h.addr] = subprocess.Popen(
        [BIN, "--state", h.state, "--run", h.run, "listen", listen or h.addr, "--peer", other.addr, "--vm-ips", h.ips,
         "--reserve", "512", "--prefix", args.prefix, *extra], stdout=lg, stderr=lg, env=ENV)
    hp = h.addr.rsplit(":", 1)
    up = lambda: subprocess.run(["bash", "-c", f"exec 3<>/dev/tcp/{hp[0]}/{hp[1]}"], capture_output=True).returncode == 0
    assert wait_for(up, 10), f"listener {h} did not come up"


def start_listeners():
    if args.no_listeners:
        return
    for h in (A, B):
        start_listener(h)


def stop_listener(h):
    p = listeners.pop(h.addr, None)
    if p:
        p.terminate()
        p.wait()


def stop_listeners():
    for h in (A, B):
        stop_listener(h)


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
    # A target forgets a migration only once its source said it is done
    # with it (it never asks again); until then it says released.
    migs = lambda h: os.listdir(os.path.join(h.state, "migs"))
    check("basic: records go once their sources are done", wait_for(lambda: not migs(A) and not migs(B), 10), (migs(A), migs(B)))
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
    """The source's page server stays down mid-pull: the target's VM dies
    without its memory, and the source, never released, runs its copy again."""
    n = "ft-pages-dead"
    m = setup(n, mib=1500)
    ok(migrate(A, n, B))
    fault(A, "pages", 30000)
    check("pages dead: the target's vm died", wait_for(lambda: vms(B).get(n, {}).get("state") == "failed" and not vms(B)[n].get("pid"), 60), vms(B).get(n))
    fault(A, "pages", 0)
    said = log(B, n)
    check("pages dead: the target said why", re.search(r"died: (background pull|fetching pages for a fault)", said), said[-300:])
    check("pages dead: the source runs its copy again", wait_for(lambda: where(n) == {A: "running"}, 60), where(n))
    check("pages dead: md5 intact on A", md5(A, n) == m)
    cleanup(n)


def resume_kill():
    """Firecracker dies right after a restored VM's resume was sent, so the
    guest may have run: nothing loads the VM again there (that could repeat
    what the guest did). A migration target dies before it has its memory,
    so its source, never released, runs its copy (from the pause) again; a
    run that claims a standby VM fails without a fallback load."""
    n = "ft-resume-kill"
    m = setup(n)
    clear_log(B, n)
    fault(B, "resume_kill", 60000)
    r = migrate(A, n, B)
    fault(B, "resume_kill", 0)
    check("resume kill: migration committed", r["ok"], r)
    check("resume kill: the source runs its copy again", wait_for(lambda: where(n) == {A: "running"}, 60), where(n))
    check("resume kill: target loaded the vm once, no retry", "once more" not in log(B, n), log(B, n)[-300:])
    check("resume kill: md5 intact on A", md5(A, n) == m)
    cleanup(n)
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
    check("source killed: target failed cleanly", wait_for(lambda: B not in where(n), 60), where(n))
    check("source killed: running nowhere", where(n) == {}, where(n))
    kill(B, n)


def target_killed():
    """The target VM process is SIGKILLed after it resumed the VM, before it
    had all the memory and before the source knew. The source must never let
    go then: it is told `aborted` (only once the dead process's Firecracker
    is gone, however soon it asks, and also after the listener restarts) and
    runs its paused copy again. A target that destroys the VM on purpose
    mid-pull releases its source instead."""
    n = "ft-target-killed"
    m = setup(n, mib=1500)
    fault(B, "lost_ack", 2000)
    fault(B, "status", 4000)
    # Once the target has resumed, stall its pull so it cannot finish.
    stall = threading.Timer(0.2, lambda: fault(A, "pages", 6000))
    stall.start()
    r = migrate(A, n, B)
    # Killed at once, from its lock and work directory alone (no `ls`): the
    # pull must still be under way.
    holder = json.load(open(os.path.join(B.run, "vms", f"{n}.lock")))
    pid = holder["pid"]
    work = os.path.join(B.run, "w", f"{pid}-{holder['start']}")
    fcs = [json.load(open(os.path.join(work, d, "fc")))["pid"] for d in os.listdir(work) if os.path.exists(os.path.join(work, d, "fc"))]
    os.kill(pid, signal.SIGKILL)
    stall.join()
    # The status fault still keeps the source from hearing anything.
    w = where(n)
    check("target killed: the source still holds its paused copy", not r["ok"] and w.get(A) == "source", (r, w or "gone everywhere"))
    migs = os.path.join(B.state, "migs")
    newest = max(os.listdir(migs), key=lambda m: os.path.getmtime(os.path.join(migs, m)))
    # Asked at once, before the Firecracker can have died of its own accord.
    fault(B, "status", 0)
    st = peer(B, {"op": "migration", "mig": int(newest)})
    check("target killed: aborted, only once its firecracker is dead",
          st.get("ok") and st["result"]["outcome"] == "aborted" and not any(alive(p) for p in fcs), (st, fcs))
    # The listener restarts too: nothing it knows is in memory.
    stop_listeners()
    start_listeners()
    fault(A, "pages", 0)
    check("target killed: the source never lets go, and runs its copy again",
          wait_for(lambda: where(n) == {A: "running"}, 60), where(n))
    check("target killed: md5 intact on A", md5(A, n) == m)
    cleanup(n)
    # Destroyed on purpose on the target mid-pull: the source goes too.
    n = "ft-target-destroyed"
    setup(n, mib=1500)
    stall = threading.Timer(0.2, lambda: fault(A, "pages", 6000))
    stall.start()
    ok(migrate(A, n, B))
    stall.join()
    ok(kill(B, n))
    fault(A, "pages", 0)
    check("target destroyed: the source lets go", wait_for(lambda: n not in vms(A), 60), where(n))
    check("target destroyed: running nowhere", where(n) == {}, where(n))


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
    m = setup(n, mib=64)
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
            elif "moved to" in out:
                results["moved"] += 1
            else:
                results["failed"].append((h.addr, code, out[-200:]))

    workers = [threading.Thread(target=worker, args=(A,)) for _ in range(3)]
    for w in workers:
        w.start()
    try:
        time.sleep(0.3)
        fault(A, "pages", 3000)
        fault(B, "guest_drop", 1000)
        ok(migrate(A, n, B))
        # B can accept execs only after the VM arrives there.
        for _ in range(3):
            w = threading.Thread(target=worker, args=(B,))
            w.start()
            workers.append(w)
        got = md5(B, n)
        wait_released(B, n)
        time.sleep(0.3)
    finally:
        stop.set()
        for w in workers:
            w.join()
    check("guest calls: every exec finished", results["ok"] > 0 and not results["failed"], results)
    check("guest calls: md5 intact while paging in", got == m, got)
    check("guest calls: only on B", where(n) == {B: "running"}, where(n))
    # Its vCPUs' TSCs (the guest's clocksource) in sync, however long restoring one took while
    # the source served no pages; apart, the guest clock jumps by the difference after the step.
    skews = tsc_skews(B, n)
    check("guest calls: the vCPUs' TSCs agree", tscs_agree(skews), skews)
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


def migrate_in_raw(host, name, ip, source, gen=None, template=None):
    """Asks `host` to prepare an incoming migration as a source would, for a
    VM like `source` (its template id and memory regions, from `source_vm`).
    Returns the open socket and the prepare reply."""
    template_id, regions = source
    h, port = host.addr.rsplit(":", 1)
    s = socket.create_connection((h, int(port)), timeout=60)
    mig = int.from_bytes(os.urandom(6), "little")
    # Newer than any the host has seen for it, as an arriving VM's is.
    gen = addr(host, ip).get("seen", 0) + 1 if gen is None else gen
    req = {"op": "migrate_in", "name": name, "mig": mig, "template": template or args.template, "id": template_id,
           "ip": ip, "gen": gen, "source": A.addr, "regions": regions}
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


def source_vm():
    """The template id and memory regions a source would send for a VM of the template."""
    n = "ft-tplid"
    ok(run(A, n))
    v = vms(A)[n]
    kill(A, n)
    return v["template_id"], v["regions"]


def prepare_disconnect():
    """A source that goes away after the target prepared leaves nothing behind."""
    n, ip = "ft-prep-gone", B.ips.split("-")[1].rsplit(".", 1)[0] + ".200"
    s, r, mig = migrate_in_raw(B, n, ip, source_vm())
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


def gen_zero():
    """An arrival without a generation (0) is refused: no legacy exemption."""
    n, ip = "ft-gen0", B.ips.split("-")[1].rsplit(".", 1)[0] + ".202"
    s, r, _ = migrate_in_raw(B, n, ip, source_vm(), gen=0)
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
    address went to another VM): the copy is destroyed instead, and the
    route the newer VM's host announced replaces the hold."""
    n = "ft-superseded"
    setup(n)
    v = vms(A)[n]
    ip, gen = v["ip"], v["gen"]
    # The replacement's host: an on-link address that is not ours (the
    # default gateway), so the route is really installed.
    gw = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout.split()[2]
    fault(A, "pages", 30000)
    res = {}
    t = threading.Thread(target=lambda: res.update(r=migrate(A, n, B)))
    t.start()
    # While the target probes the dead page server, the address moves on.
    wait_for(lambda: vms(A).get(n, {}).get("state") == "source", 20)
    r = peer(A, {"op": "route", "ip": ip, "via": gw, "gen": gen + 1})
    check("abort superseded: the newer generation is taken, the source keeps the route",
          r.get("ok") and not r["result"].get("stale") and r["result"].get("local"), r)
    # The target hears of it too (its arrival does not commit then).
    peer(B, {"op": "route", "ip": ip, "via": gw, "gen": gen + 1})
    t.join()
    fault(A, "pages", 0)
    r = res.get("r", {})
    check("abort superseded: migration failed", not r.get("ok"), r)
    check("abort superseded: source not resumed, destroyed", wait_for(lambda: n not in vms(A), 10), where(n))
    check("abort superseded: says why", "superseded" in log(A, n), log(A, n)[-300:])
    check("abort superseded: running nowhere", where(n) == {}, where(n))
    route = subprocess.run(["ip", "route", "show", f"{ip}/32"], capture_output=True, text=True).stdout.strip()
    check("abort superseded: the address routes to the replacement, not the hold", f"via {gw}" in route, route)
    check("abort superseded: the source put that route back itself", f"put back route {ip} via {gw} (generation {gen + 1})" in log(A, n), log(A, n)[-300:])
    subprocess.run(["ip", "route", "del", f"{ip}/32"], capture_output=True)


def same_host_order():
    """#78: hosts sharing a network namespace share routes, so the target must
    not route the VM's address to its tap before the packets the source's
    hold took first are in. A 1 kHz UDP sequence stream across migrations
    there and back arrives whole and in order."""
    udp_across_migrations("same host order", "ft-same-host")


def same_host_slow_route():
    """#136: the target's own hold, which takes the address over from the
    source's, lets go of it with a route change that can wait long (for RTNL,
    on a busy host: `release_stall` makes it 300 ms). Nothing it held, or that
    reached it meanwhile, is lost, and nothing is reordered."""
    udp_across_migrations("same host slow route", "ft-slow-route", "release_stall")


def same_host_flood():
    """#136: traffic that keeps arriving while the target lets go of its hold
    (10k datagrams/s, its route change made slow by `release_stall`) never
    holds the release up: it ends within a bound, and nothing is lost but
    what flexvm or the guest says it dropped."""
    udp_across_migrations("same host flood", "ft-flood", "release_stall", burst=10)


def udp_receiver(host, n):
    """Starts socat in the guest appending what UDP port 9000 receives to /tmp/udp (its socket
    buffer large enough for any burst of held packets), and waits until the port is bound:
    a datagram sent before would be dropped by the guest (NoPorts)."""
    code, out = sh(host, n, "echo 16777216 > /proc/sys/net/core/rmem_max; "
                   "setsid socat -u UDP-RECV:9000,rcvbuf=16777216 OPEN:/tmp/udp,creat,append >/dev/null 2>&1 < /dev/null & "
                   "for i in $(seq 200); do grep -qs ':2328 ' /proc/net/udp /proc/net/udp6 && exit 0; sleep 0.05; done; exit 1")
    assert code == 0, f"socat did not bind UDP port 9000 in the guest: {out}"


def udp_across_migrations(label, n, target_fault=None, burst=1):
    """A UDP sequence stream to `n` (`burst` datagrams every millisecond)
    across migrations A to B, back and to B again, `target_fault` armed on
    each target, arrives whole and, at 1 kHz, in order. The guest's socket
    buffer is made large enough for any burst of held packets, so a datagram
    missing was lost by flexvm (the guest's own drops are shown)."""
    for h in (A, B):
        clear_log(h, n)
    ok(run(A, n))
    ip = vm_ip(A, n)
    udp_receiver(A, n)
    stop, sent = threading.Event(), [0]

    def stream():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop.is_set():
            for _ in range(burst):
                s.sendto(b"%08d\n" % sent[0], (ip, 9000))
                sent[0] += 1
            time.sleep(0.001)

    t = threading.Thread(target=stream, daemon=True)
    t.start()
    time.sleep(0.5)
    held, at = [], []
    for src, dst in ((A, B), (B, A), (A, B)):
        if target_fault:
            fault(dst, target_fault, 60000)
        at.append(sent[0])
        r = migrate(src, n, dst)
        held.append((r.get("result") or {}).get("held") or r.get("error"))
        wait_released(dst, n, src)
        if target_fault:
            fault(dst, target_fault, 0)
        time.sleep(0.3)
    stop.set()
    t.join(10)
    time.sleep(0.3)
    check(f"{label}: migrated, running on B", where(n) == {B: "running"}, where(n))
    check(f"{label}: packets held each time, all injected",
          all(isinstance(h, dict) and h.get("packets", 0) > 0 and h.get("injected") == h.get("packets") and h.get("dropped") == 0
              and h.get("dropped_target") == 0 for h in held), held)
    code, out = sh(B, n, "cat /tmp/udp")
    got = [int(x) for x in out.split()] if code == 0 else []
    missing = sorted(set(range(sent[0])) - set(got))
    runs = [[a, b] for a, b in zip([m for i, m in enumerate(missing) if i == 0 or missing[i - 1] != m - 1],
                                  [m for i, m in enumerate(missing) if i + 1 == len(missing) or missing[i + 1] != m + 1])]
    udp = sh(B, n, "grep Udp: /proc/net/snmp; pidof socat >/dev/null && echo receiving")[1].splitlines()
    guest = {k: v for k, v in zip(udp[0].split()[1:], udp[1].split()[1:]) if k in ("InDatagrams", "NoPorts", "RcvbufErrors")} if len(udp) >= 2 else udp
    detail = (f"sent {sent[0]}, migrations began at {at}, {len(missing)} missing, runs {runs[:10]}; the guest: {guest}, "
              f"{'socat receiving' if udp[-1:] == ['receiving'] else 'socat gone'}")
    dropped = {h: [l for l in log(h, n).splitlines() if "dropped" in l or "dropping" in l] for h in (A, B)}
    if burst == 1:
        check(f"{label}: no udp datagram lost", not missing, detail)
        late = [got[max(0, i - 3):i + 12] for i, (a, b) in enumerate(zip(got, got[1:])) if b <= a]
        check(f"{label}: none reordered", not late, late[:10])
        for h in (A, B):
            check(f"{label}: no held packets dropped on {h}", not dropped[h], dropped[h][-3:])
    else:
        # Overload may drop, but only what is counted: by the holds, or by the guest's socket.
        said = sum(int(m) for h in (A, B) for l in dropped[h] for m in re.findall(r"dropped (\d+)", l))
        said += int(guest.get("RcvbufErrors", 0)) if isinstance(guest, dict) else 0
        check(f"{label}: nothing lost that was not counted", len(missing) <= said, (detail, dropped))
        let_go = [float(m) for h in (A, B) for m in re.findall(r"let go of \S+ after ([\d.]+) ms", log(h, n))]
        check(f"{label}: each release ended within 2 s of its 300 ms route change", let_go and max(let_go) < 2000, let_go)
    cleanup(n)


def udp_in(host, name):
    """The guest's Udp InDatagrams, or None if it did not answer."""
    code, out = sh(host, name, "grep ^Udp: /proc/net/snmp | tail -1 | cut -d' ' -f2")
    return int(out) if code == 0 and out.isdigit() else None


def receiving(host, name, timeout=3.0):
    """Whether the guest's InDatagrams goes up within `timeout` s."""
    first = udp_in(host, name)
    return first is not None and wait_for(lambda: (udp_in(host, name) or 0) > first + 5, timeout)


def rx_state(host, name):
    """What the guest, its Firecracker and its tap say about the guest's
    receive path (#149)."""
    st = {}
    code, out = sh(host, name, "grep -E '^(Udp|Ip):' /proc/net/snmp; grep -E 'virtio|LOC|SPU' /proc/interrupts; "
                   "cd /sys/class/net/eth0/statistics && for f in rx_packets rx_dropped rx_errors tx_packets; do echo $f $(cat $f); done")
    st["guest"] = out
    try:
        sock = api_sock(host, name)
        fc_api(sock, "PUT", "/actions", {"action_type": "FlushMetrics"})
        fc_dir = os.path.dirname(os.readlink(f"/proc/{fc_pid(host, name)}/fd/1"))  # its firecracker.log
        lines = open(os.path.join(fc_dir, "metrics.json")).read().splitlines()
        # Each flush holds the counts since the previous one: add them up.
        net = {}
        for line in lines:
            for k, v in json.loads(line).get("net", {}).items():
                if isinstance(v, (int, float)):
                    net[k] = net.get(k, 0) + v
        st["fc_net"] = {k: v for k, v in net.items() if v}
        st["fc_flushes"] = len(lines)
    except Exception as e:
        st["fc_net"] = f"unavailable: {e}"
    tap = vms(host)[name].get("tap")
    st["tap"] = subprocess.run(["ip", "-s", "link", "show", tap], capture_output=True, text=True).stdout if tap else None
    return st


def rx_stall():
    """#149: a guest stopped receiving altogether after a handoff. Under a
    steady inbound UDP stream, migrate, checkpoint, checkpoint --stop and
    restore, suspend and resume, and pause and resume a VM over and over;
    after each, the guest's InDatagrams must go up again. On a stall it
    records the guest's, Firecracker's and the tap's view, then has the
    guest send one datagram
    (an interrupt on the same line) to see whether that wakes its receive.
    RX_ITERS (default 25), RX_RATE (datagrams/s, default 2000) and
    RX_TAP_RATE (frames/s written onto its tap, default 1000) scale it."""
    n = "ft-rx-stall"
    iters, rate = int(os.environ.get("RX_ITERS") or 25), int(os.environ.get("RX_RATE") or 2000)
    ok(run(A, n))
    ip = vm_ip(A, n)
    receiver = "setsid socat -u UDP-RECV:9000,rcvbuf=16777216 OPEN:/dev/null >/dev/null 2>&1 < /dev/null &"
    code, out = sh(A, n, receiver)
    assert code == 0, out
    stop, sent = threading.Event(), [0]

    def stream():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        per_ms, tick = max(1, rate // 1000), time.time()
        while not stop.is_set():
            for _ in range(per_ms):
                try:
                    s.sendto(b"%08d\n" % sent[0], (ip, 9000))
                except OSError:
                    pass
                sent[0] += 1
            tick += 0.001
            time.sleep(max(0, tick - time.time()))

    # Frames written straight onto the VM's tap (as a target injects held packets) are
    # not diverted by the hold's route, so they arrive right up to each pause and the
    # device often has an interrupt in flight when the state is saved.
    tap_rate, cur_tap = int(os.environ.get("RX_TAP_RATE") or 1000), [vms(A)[n]["tap"]]

    def tap_stream():
        dst = bytes(int(x, 16) for x in "06:00:ac:10:00:02".split(":"))
        src = bytes(int(x, 16) for x in "06:00:a9:fe:01:01".split(":"))
        payload = b"tap-frame\n"
        udp = (40000).to_bytes(2, "big") + (9000).to_bytes(2, "big") + (8 + len(payload)).to_bytes(2, "big") + b"\0\0" + payload
        hdr = bytearray(b"\x45\0" + (20 + len(udp)).to_bytes(2, "big") + b"\0\0\x40\0\x40\x11\0\0"
                        + socket.inet_aton("169.254.1.1") + socket.inet_aton(ip))
        csum = sum(int.from_bytes(hdr[i:i + 2], "big") for i in range(0, 20, 2))
        csum = (csum & 0xffff) + (csum >> 16)
        hdr[10:12] = (~((csum & 0xffff) + (csum >> 16)) & 0xffff).to_bytes(2, "big")
        frame = dst + src + b"\x08\x00" + bytes(hdr) + udp
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        tick = time.time()
        while not stop.is_set():
            try:
                s.sendto(frame, (cur_tap[0], 0))
            except OSError:
                pass
            tick += 1 / tap_rate
            time.sleep(max(0, tick - time.time()))

    threads = [threading.Thread(target=stream, daemon=True)] + ([threading.Thread(target=tap_stream, daemon=True)] if tap_rate else [])
    for t in threads:
        t.start()
    cur, stalls, done = A, [], {}
    started = receiving(cur, n)
    check("rx stall: receiving at the start", started, "" if started else rx_state(cur, n))
    for i in range(iters):
        op = ("migrate", "checkpoint", "restore", "suspend", "pause")[i % 5]
        other = B if cur is A else A
        if op == "migrate":
            r = migrate(cur, n, other)
            if not r["ok"]:
                check(f"rx stall: migration {i} succeeded", False, r)
                break
            wait_released(other, n, cur)
            cur = other
        elif op == "checkpoint":
            r = checkpoint(cur, n, ckpt_path(f"{n}-{i}"))
        elif op == "restore":
            path = ckpt_path(f"{n}-{i}")
            r = checkpoint(cur, n, path, stop=True)
            if r["ok"]:
                r = restore(cur, path)
        elif op == "suspend":
            suspend(cur, n)
            r = resume_suspended(cur, n)
        else:
            # A plain pause (SIGTSTP) and resume: no snapshot, but the same resume path.
            r = {"ok": pause(cur, n)}
            if r["ok"]:
                time.sleep(0.05)
                resume(cur, n)
        if not r["ok"]:
            check(f"rx stall: {op} {i} succeeded", False, r)
            break
        done[op] = done.get(op, 0) + 1
        cur_tap[0] = vms(cur)[n].get("tap") or cur_tap[0]
        if not receiving(cur, n):
            before = rx_state(cur, n)
            code, out = sh(cur, n, "echo wake | socat -u - UDP-SENDTO:169.254.1.1:9")
            woke = receiving(cur, n)
            stalls.append({"iteration": i, "after": op, "woken_by_guest_send": woke, "state": before,
                           "after_send": rx_state(cur, n)})
            print(f"rx stall after {op} (iteration {i}): {json.dumps(stalls[-1], indent=1)}", flush=True)
            if not woke:
                break
    stop.set()
    for t in threads:
        t.join(10)
    check("rx stall: the guest kept receiving after every operation", not stalls,
          f"{len(stalls)} stalls in {sum(done.values())} operations {done}, sent {sent[0]}")
    cleanup(n)


def handoff_superseded():
    """A same-host arrival routes its address only after the held packets
    (`handoff_stall` delays that by 3 s). A newer generation of the address
    announced meanwhile keeps its route: the late handoff leaves it alone."""
    n = "ft-handoff-superseded"
    ok(run(A, n))
    v = vms(A)[n]
    ip, gen = v["ip"], v["gen"]
    gw = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout.split()[2]
    fault(B, "handoff_stall", 30000)
    clear_log(B, n)
    r = migrate(A, n, B)
    check("handoff superseded: migrated", r["ok"] and where(n).get(B) == "running", (r, where(n)))
    r = peer(B, {"op": "route", "ip": ip, "via": gw, "gen": gen + 1})
    check("handoff superseded: the newer generation is taken", r.get("ok") and not r["result"].get("stale"), r)
    check("handoff superseded: the late handoff says it left the address alone",
          wait_for(lambda: "went to a newer vm" in log(B, n), 10), log(B, n)[-300:])
    fault(B, "handoff_stall", 0)
    time.sleep(0.5)
    check("handoff superseded: the address routes to the newer vm's host", f"via {gw}" in peer_route(ip), peer_route(ip))
    kill(B, n)
    forget_peer_route(ip, gen + 1)


def peer_route(ip):
    """The kernel's route for `ip`: shared by A and B."""
    return subprocess.run(["ip", "route", "show", f"{ip}/32"], capture_output=True, text=True).stdout.strip()


def arrival_with_peer_route(n, ip):
    """B learns that an address of A's is routed via a peer (an on-link
    address that is not ours, the default gateway, so the route is really
    installed), then takes an arrival of it that sends a vmstate that cannot
    load and preloaded pages it never sends. Returns (socket, mig, gateway)."""
    gw = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout.split()[2]
    gen = addr(B, ip).get("seen", 0) + 1
    r = peer(B, {"op": "route", "ip": ip, "via": gw, "gen": gen})
    assert r.get("ok"), r
    assert f"via {gw}" in peer_route(ip), peer_route(ip)
    s, r, mig = migrate_in_raw(B, n, ip, source_vm(), gen=gen)
    assert r.get("ok"), r
    bad = os.urandom(4096)
    s.sendall((json.dumps({"runs": [], "vmstate_len": len(bad), "preload": [0], "paused": False}) + "\n").encode() + bad)
    return s, mig, gw, gen


def forget_peer_route(ip, gen):
    """Withdraws generation `gen` of `ip` on both hosts (so its home host hands
    the address out only with a newer one) and removes its route."""
    for h in (A, B):
        peer(h, {"op": "route", "ip": ip, "gen": gen})
    subprocess.run(["ip", "route", "del", f"{ip}/32"], capture_output=True)


def arrival_abort_route():
    """#90: an arrival that fails before it commits leaves the target host's
    route back to its peer alone; the address never routes to its tap."""
    n, ip = "ft-abort-route", A.ips.split("-")[1].rsplit(".", 1)[0] + ".201"
    scenario_vms.add(n)
    s, mig, gw, gen = arrival_with_peer_route(n, ip)
    seen, lock = set(), os.path.join(B.run, "vms", f"{n}.lock")
    # Until it gives up (its preload never comes), watch the route.
    end = time.time() + 5
    while time.time() < end:
        seen.add(peer_route(ip))
        time.sleep(0.005)
    s.close()
    check("arrival abort route: gone from B", wait_for(lambda: n not in vms(B) and not os.path.exists(lock), 40), vms(B).get(n))
    seen.add(peer_route(ip))
    check("arrival abort route: the route via the peer stayed throughout", seen == {r for r in seen if f"via {gw}" in r}, seen)
    st = ok(peer(B, {"op": "migration", "mig": mig}))
    check("arrival abort route: aborted", st["outcome"] == "aborted", st)
    forget_peer_route(ip, gen)


def arrival_killed_route():
    """#90: an arrival SIGKILLed before it commits (no cleanup runs) leaves
    the route back to its peer; one lost meanwhile is put back once its
    migration reads as aborted."""
    n, ip = "ft-killed-route", A.ips.split("-")[1].rsplit(".", 1)[0] + ".202"
    scenario_vms.add(n)
    s, mig, gw, gen = arrival_with_peer_route(n, ip)
    lock = os.path.join(B.run, "vms", f"{n}.lock")
    pid = json.load(open(lock))["pid"]
    # Its load failed; it waits for the preloaded pages.
    time.sleep(2)
    check("arrival killed route: the route via the peer stays while it waits", f"via {gw}" in peer_route(ip), peer_route(ip))
    subprocess.run(["ip", "route", "del", f"{ip}/32"], capture_output=True)
    os.kill(pid, signal.SIGKILL)
    s.close()
    check("arrival killed route: dead", wait_for(lambda: not alive(pid), 10), pid)
    st = ok(peer(B, {"op": "migration", "mig": mig}))
    check("arrival killed route: aborted", st["outcome"] == "aborted", st)
    check("arrival killed route: the route via the peer is put back", f"via {gw}" in peer_route(ip), (peer_route(ip), addr(B, ip)))
    forget_peer_route(ip, gen)


def fc_prepare():
    """Firecracker's prepared load (firecracker/0002-*.patch): refuses a second
    prepare, a snapshot of another layout, and a load after boot config."""
    art = args.artifacts
    tpls = os.environ.get("FLEXVM_TEMPLATES") or os.path.join(art, "templates")
    fc = os.path.join(art, "firecracker")
    other = next((t for t in sorted(os.listdir(tpls)) if t != args.template and not t.startswith(".")), "") if os.path.isdir(tpls) else ""
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


# For each vCPU k after the first, reads the TSC on vCPU 0, k, 0 (rdtsc, run from an executable
# page), ten times, and prints the tightest bracket: "k skew bracket", in seconds, where skew is
# vCPU k's TSC minus the midpoint of vCPU 0's two readings around it. The read on k happened
# somewhere in the bracket, so the true difference is within bracket/2 of skew.
TSC_SKEW = r"""
import ctypes, mmap, os
buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
buf.write(bytes([0x0f, 0x31, 0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0xc3]))
rdtsc = ctypes.CFUNCTYPE(ctypes.c_uint64)(ctypes.addressof(ctypes.c_char.from_buffer(buf)))
f = "/sys/devices/system/cpu/cpu0/tsc_freq_khz"
hz = int(open(f).read()) * 1e3 if os.path.exists(f) else float(next(l.split(":")[1] for l in open("/proc/cpuinfo") if l.startswith("cpu MHz"))) * 1e6
for k in sorted(os.sched_getaffinity(0) - {0}):
    best = None
    for _ in range(10):
        t = []
        for cpu in (0, k, 0):
            os.sched_setaffinity(0, {cpu})
            t.append(rdtsc())
        if best is None or t[2] - t[0] < best[1]:
            best = ((t[1] - (t[0] + t[2]) / 2) / hz, (t[2] - t[0]) / hz)
    print(k, best[0], best[1])
"""


def tsc_skews(host, name):
    """{vCPU: (its TSC minus vCPU 0's, bracket)} in the guest, in seconds (None if unreadable)."""
    code, out = sh(host, name, f"python3 -c '{TSC_SKEW}'")
    try:
        return {int(k): (float(skew), float(bracket)) for k, skew, bracket in (l.split() for l in out.splitlines())} if code == 0 else None
    except ValueError:
        return None


def tscs_agree(skews, within=0.05):
    """Every vCPU's TSC is within `within` s of vCPU 0's, measured with a bracket narrow enough
    to tell (a read on vCPU k delayed by scheduling widens it, never shifts it past it)."""
    return bool(skews) and all(bracket < within and abs(skew) <= within + bracket / 2 for skew, bracket in skews.values())


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
    process, the address and an open TCP connection all survive. B borrows
    the address from A, its home host, which refuses it while lent."""
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
    r = ok(restore(B, path))
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
    check("restore: whole checkpoint paged in", wait_for(lambda: vms(B)[n].get("pages_mib", {}).get("remote") == 0, 30), vms(B)[n].get("pages_mib"))
    check("restore: the address is lent out by its home host", addr(A, ip).get("lent") == vms(B)[n]["gen"], (addr(A, ip), vms(B)[n]["gen"]))
    again = restore(A, path, name=n + "-again")
    check("restore: the home host refuses it while lent", not again["ok"] and "lent" in again.get("error", ""), again)
    r = restore(B, path, name=n + "-again")
    check("restore: and refuses to lend it twice", not r["ok"] and "cannot borrow" in r.get("error", "") and "lent" in r.get("error", ""), r)
    cleanup(n)
    check("restore: killing it gives the address back", wait_for(lambda: not addr(A, ip).get("lent"), 10), addr(A, ip))
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
    check("corrupt page data: VM fails, never runs on", (not r["ok"]) or wait_for(lambda: B not in where(n), 30), (r, vms(B).get(n)))
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
    check("pause: exec refused while paused", not r["ok"] and "is paused" in r["error"], r)
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
    land behind the saved state), and the result restores intact. The
    template needs unplugged room in its hotplug region: PLUG_TEMPLATE picks
    it (one fully plugged has nothing to resize, issue #145)."""
    n, path = "ft-hotplug", ckpt_path("ft-hotplug")
    m = setup(n, template=os.environ.get("PLUG_TEMPLATE"))
    sock = api_sock(A, n)
    hp = fc_api(sock, "GET", "/hotplug/memory")
    room = hp["total_size_mib"] - hp["plugged_size_mib"]
    assert room >= 256, f"template {os.environ.get('PLUG_TEMPLATE') or args.template} has {room} MiB of hotplug room, too little to resize: {hp}"
    want = hp["plugged_size_mib"] + min(1024, room)
    r = fc_api(sock, "PATCH", "/hotplug/memory", {"requested_size_mib": want})
    assert r is None, f"resize to {want} MiB refused: {r}"
    hp = fc_api(sock, "GET", "/hotplug/memory")
    check("hotplug: resize in flight when the checkpoint starts", hp["plugged_size_mib"] < want, hp)
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
    check("suspend: paged back in", wait_for(lambda: vms(A)[n].get("pages_mib", {}).get("remote") == 0, 30), vms(A)[n])
    cleanup(n)


def suspend_gen():
    """A suspended VM's checkpoint holds its address's generation (GEN); one
    without it is quarantined (never given a new one), and its checkpoint
    still restores with --ip auto."""
    n = "ft-susp-gen"
    m = setup(n, mib=20)
    gen = vms(A)[n]["gen"]
    suspend(A, n)
    genfile = os.path.join(A.state, "suspended", n, "GEN")
    check("suspend gen: recorded in the checkpoint", open(genfile).read().strip() == str(gen), gen)
    os.rename(genfile, genfile + ".x")
    check("suspend gen: without it, listed quarantined", vms(A).get(n, {}).get("state") == "quarantined", vms(A).get(n))
    r = resume_suspended(A, n)
    check("suspend gen: without it, not resumed", not r["ok"] and "quarantined" in r["error"], r)
    os.rename(genfile + ".x", genfile)
    ok(resume_suspended(A, n))
    check("suspend gen: resumes once it is back, md5 intact", md5(A, n) == m)
    suspend(A, n)
    os.unlink(genfile)
    r = restore(A, os.path.join(A.state, "suspended", n), name=n + "2", ip="auto")
    check("suspend gen: without it, its checkpoint restores at a new address", r["ok"] and md5(A, n + "2") == m, r)
    cleanup(n + "2")
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
    check("disk freed: paged back in", wait_for(lambda: vms(A)[n].get("pages_mib", {}).get("remote") == 0, 60), vms(A)[n])
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
    check("standby: run claims one", r["standby"] is True and r["ready_ms"] < 50, r)
    check("standby: claimed vm works", sh(A, "ft-sb1", "echo hi") == (0, "hi"))
    check("standby: refilled to two", wait_for(lambda: live() == 2, 60), live())
    ok(cli_json(A, "standby", "--template", t, "0"))
    check("standby: 0 stops them", wait_for(lambda: live() == 0, 30), live())
    r = ok(run(A, "ft-sb2"))
    check("standby: without one, a cold run", r["standby"] is False, r)
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
    # A VM that stops is never stopped onto a chain whose page data is bad. Every 64th page
    # of the base is: the deltas replace some of its pages, never all of these (/tmp/f's).
    pages = os.path.join(paths[0], "pages")
    good = {}
    with open(pages, "r+b") as f:
        for off in range(0, os.path.getsize(pages), 64 * 4096):
            f.seek(off)
            good[off] = f.read(1)
            f.seek(off)
            f.write(bytes([good[off][0] ^ 1]))
    r = checkpoint(A, n, paths[2] + "s", stop=True, incremental=True)
    check("incremental: no --stop delta onto corrupt parent data", not r["ok"] and "checksum" in r["error"] and not os.path.exists(paths[2] + "s"), r)
    check("incremental: VM runs on after that refusal", where(n) == {A: "running"}, where(n))
    with open(pages, "r+b") as f:
        for off, b in good.items():
            f.seek(off)
            f.write(b)
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
    ok(run(A, n))
    start_writer(A, n, mib=64, threads=2)
    fault(A, "ckpt_wp_race", 600000)
    for i in range(8):
        path = ckpt_path(f"ft-wprace{i}")
        r = checkpoint(A, n, path, timeout=120)
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
    ok(migrate(A, n, B))
    check("tail: memory intact after the migration", md5(B, n) == m)
    st = wait_released(B, n, timeout=30)
    check("tail: every page arrives and the source lets go",
          st["released"] is True and st["background_pull_ms"] is not None and st["failed"] is None, st)
    fault(B, "fetch_tail_enomem", 0)
    cleanup(n)


def fetch_enomem_stuck():
    """Pages a fault needs that keep failing to install (ENOMEM on every
    copy, the pullers held off) make the target give up within the fault
    deadline and report the VM failed, however the pages get claimed again
    (by the waiting fault or by the requeue), instead of leaving the vCPU
    blocked for good. The source, never released, runs its copy again."""
    n = "ft-stuck"
    m = setup(n, mib=400)
    fault(B, "fetch_enomem_stuck", 60000)
    ok(migrate(A, n, B))
    t0 = time.time()
    threading.Thread(target=lambda: sh(B, n, "md5sum /tmp/f"), daemon=True).start()
    st = {}

    def failed():
        st.update(vms(B).get(n) or {})
        return st.get("state") == "failed"

    gave_up = wait_for(failed, 20)
    took = time.time() - t0
    fault(B, "fetch_enomem_stuck", 0)
    why = (st.get("failed") or st.get("error") or "")
    check(f"stuck: target gave up ({took:.1f} s) and reports the vm failed", gave_up and "installing pages" in why, (st.get("state"), why[:300]))
    # Copies fail from 0.5 s after the target took the VM on, and the fault
    # deadline is 1 s: nothing (a stalled fetch, a requeue) may stretch it.
    check("stuck: within the fault deadline (< 3 s)", gave_up and took < 3, f"{took:.1f} s")
    check("stuck: the source runs its copy again", wait_for(lambda: where(n) == {A: "running"}, 60), where(n))
    check("stuck: md5 intact on A", md5(A, n) == m)
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
    udp_receiver(A, n)
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
    # A pause of a few ms can see no datagram of a 1 kHz stream, so only some must hold one.
    check("ckpt packet hold: packets held during the pauses and all injected",
          any(h.get("packets", 0) > 0 for h in held)
          and all(h.get("injected") == h.get("packets") and h.get("dropped") == 0
                  and h.get("dropped_target") == 0 for h in held), held)
    code, out = sh(A, n, "sort -u /tmp/udp | wc -l")
    got = int(out) if code == 0 and out.isdigit() else -1
    check("ckpt packet hold: no udp datagram lost", got == sent[0], f"sent {sent[0]}, received {got}")
    check("ckpt packet hold: tcp echoed throughout, no retransmit", echoes[0] and retrans == 0, f"retransmits {retrans}")
    cleanup(n)
    for p in paths:
        rm_ckpt(p)



def hotplug(host, name, mib):
    """Sets a VM's hotplug size directly, as the controller would."""
    return control(host, name, {"op": "debug", "what": "hotplug", "mib": mib})


def shrink_stall():
    """A shrink the guest does not carry out must not block growth: when the
    guest then needs memory, the controller cancels the shrink and grows,
    instead of answering `busy` until the guest OOMs (#97). Kernel-zone
    blocks pinned by unmovable allocations stall a shrink the same way; here
    the guest's virtio-mem driver is told not to unplug online memory at all.
    PLUG_TEMPLATE picks the template."""
    n = "ft-shrink-stall"
    setup(n, mib=1, template=os.environ.get("PLUG_TEMPLATE"))
    v = vms(A)[n]
    if v["guest_mib"] < 4096 or v["max_mib"] - v["guest_mib"] < 4096:
        print(f"shrink stall: skipped, template too small ({v['guest_mib']} of {v['max_mib']} MiB)", flush=True)
        cleanup(n)
        return
    hold = v["guest_mib"] - 1536
    touch = "b=bytearray({}<<20)\\nfor i in range(0, len(b), 4096): b[i] = 1\\n"
    holder = "python3 -c \"exec('" + touch.format(hold) + "'); open('/tmp/held', 'w').close(); import time; time.sleep(3600)\""
    code, pid = sh(A, n, f"setsid {holder} >/dev/null 2>&1 </dev/null & echo $!")
    check("shrink stall: holder started", code == 0 and pid.isdigit(), pid)
    held = wait_for(lambda: sh(A, n, "test -e /tmp/held")[0] == 0, 120)
    check(f"shrink stall: guest holds {hold} of {v['guest_mib']} MiB", held)
    code, out = sh(A, n, "echo N > /sys/module/virtio_mem/parameters/unplug_online")
    check("shrink stall: guest stops unplugging online memory", code == 0, out)
    hp = lambda: (vms(A)[n]["requested_mib"], vms(A)[n]["plugged_mib"])
    plugged = vms(A)[n]["plugged_mib"]
    ok(hotplug(A, n, plugged - 1024))
    time.sleep(2)
    check("shrink stall: shrink stalled", hp() == (plugged - 1024, plugged), (plugged, hp()))
    code, out = sh(A, n, "python3 -c \"exec('" + touch.format(2048) + "'); print(len(b)>>20)\"")
    check("shrink stall: guest can allocate 2 GiB more", code == 0 and out == "2048", (code, out))
    check("shrink stall: holder not OOM-killed", sh(A, n, f"kill -0 {pid}")[0] == 0,
          sh(A, n, "dmesg | grep -i 'out of memory' | tail -n 2"))
    check("shrink stall: resize settled, guest grew", wait_for(lambda: hp()[0] == hp()[1] > plugged, 60), (plugged, hp()))
    cleanup(n)


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
    t = threading.Thread(target=lambda: res.update(r=checkpoint(A, n, path, timeout=600)))
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
    # The copy needed to crawl only while the guest grew; the rest goes at full speed.
    fault(A, "ckpt_crawl", 0)
    check("cow grow: the guest filled 2 GiB more than it had, no OOM", code == 0 and out == str(fill // 64 * 64), (code, out[-200:]))
    check("cow grow: it grew while the copy ran", seen["max"] >= plugged0 + 1024, (plugged0, seen))
    print(f"cow grow: plugged {plugged0} -> {seen['max']} MiB during the copy; copy still running after the fill: {still}")
    t.join()
    fault(A, "ckpt_memhash", 0)
    r = res.get("r", {})
    check("cow grow: checkpoint written", r.get("ok"), r)
    if r.get("ok"):
        r = r["result"]
        h = ckhash(A, path)
        check("cow grow: checkpoint == memory at the pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
        ok(restore(B, path, name="ft-cow-grow2", ip="auto"))
        check("cow grow: restored at the size it had at the pause", vms(B)["ft-cow-grow2"]["plugged_mib"] == plugged0,
              (plugged0, vms(B)["ft-cow-grow2"]["plugged_mib"]))
        check("cow grow: restored file intact", md5(B, "ft-cow-grow2") == m)
        code, out = sh(B, "ft-cow-grow2", "python3 -c 'b=bytearray(512<<20); print(len(b)>>20)'")
        check("cow grow: restored guest can use memory", code == 0 and out == "512", out)
    check("cow grow: original still running, file intact", where(n) == {A: "running"} and md5(A, n) == m, where(n))
    cleanup(n)
    cleanup("ft-cow-grow2")
    rm_ckpt(path)


def plug_race():
    """Migrations that start right after a memory hot-plug (or unplug) was
    requested: the plug settles first (or, if it stalls, is cut down to what
    the guest managed), and the VM ends up on the target with all its memory
    usable. PLUG_TEMPLATE picks the template; one snapshotted with nothing
    plugged makes the first step plug into a slot that was never mapped."""
    n = "ft-plug-race"
    m = setup(n, mib=50, template=os.environ.get("PLUG_TEMPLATE"))
    # (from, to, MiB to plug, delay before migrating); the last ones are more
    # than the guest can online quickly, so the migration has to cut it short.
    steps = [(A, B, 384, 0), (B, A, 1024, 0), (A, B, 2048, 0.05), (B, A, -1024, 0), (A, B, 384, 0.2),
             (B, A, 1024, 0.1), (A, B, 12288, 0), (B, A, None, 0)]
    for i, (src, dst, delta, gap) in enumerate(steps):
        v = vms(src)[n]
        if delta is None:  # everything: takes the guest longer than a migration waits
            delta = v["max_mib"] - (v["guest_mib"] - v["plugged_mib"]) - v["plugged_mib"]
        want = v["plugged_mib"] + delta
        want = ok(hotplug(src, n, want))  # clamped to the template's hotplug region
        time.sleep(gap)
        r = migrate(src, n, dst)
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
                    if v and v["state"] == "running" and v.get("plugged_mib") is not None:
                        hotplug(h, n, max(0, v["plugged_mib"] + (512 if up else -512)))
                        up = not up
                except (OSError, AssertionError, KeyError, ValueError):
                    pass
            time.sleep(0.02)

    t = threading.Thread(target=storm)
    t.start()
    for i, (src, dst) in enumerate([(A, B), (B, A)] * 3):
        r = migrate(src, n, dst)
        check(f"plug storm {i}: migrate succeeds", r["ok"], r.get("error"))
        st = wait_released(dst, n, timeout=60)
        check(f"plug storm {i}: pull finished and released", st["released"] is True and st["failed"] is None, st)
        check(f"plug storm {i}: only on target, running", where(n) == {dst: "running"}, where(n))
    stop.set()
    t.join()
    w = where(n)
    check("plug storm: only on one host, running", list(w.values()) == ["running"], w)
    dst = B if w.get(B) == "running" else A
    got = md5(dst, n)
    check("plug storm: md5 intact", got == m, (dst, got))
    code, out = sh(dst, n, "python3 -c 'b=bytearray(512<<20); print(len(b)>>20)'")
    check("plug storm: guest can use its memory", code == 0 and out == "512", out)
    cleanup(n)


def cgroup(host, name):
    """`name`'s Firecracker cgroup on `host`: (memory.current MiB, memory.high MiB or None, memory.events)."""
    path = "/sys/fs/cgroup" + open(f"/proc/{fc_pid(host, name)}/cgroup").read().strip().split(":", 2)[2]
    high = open(os.path.join(path, "memory.high")).read().strip()
    events = dict(l.split() for l in open(os.path.join(path, "memory.events")).read().splitlines())
    return int(open(os.path.join(path, "memory.current")).read()) >> 20, None if high == "max" else int(high) >> 20, events


def swapped(host, name):
    """MiB of `name`'s memory in swap (None without swap accounting)."""
    path = "/sys/fs/cgroup" + open(f"/proc/{fc_pid(host, name)}/cgroup").read().strip().split(":", 2)[2]
    try:
        return int(open(os.path.join(path, "memory.swap.current")).read()) >> 20
    except OSError:
        return None


def mem_available():
    return next(int(l.split()[1]) >> 10 for l in open("/proc/meminfo") if l.startswith("MemAvailable:"))


def hog(host, name, mib):
    """Starts a guest program filling `mib` MiB, every page different (so the
    host cannot merge them, as KSM on CI runners does); it touches
    /tmp/hog.done once it has."""
    fill = f"b=bytearray({mib}<<20); [b.__setitem__(slice(i, i + 8), i.to_bytes(8, \"little\")) for i in range(0, len(b), 4096)]"
    code, out = sh(host, name, f"rm -f /tmp/hog.done; setsid python3 -c '{fill}; open(\"/tmp/hog.done\", \"w\").close(); "
                               "import time; time.sleep(3600)' >/dev/null 2>&1 </dev/null & echo started")
    assert code == 0, out


def hog_done(host, name):
    return sh(host, name, "test -e /tmp/hog.done")[0] == 0


def throttle(label, host, n, reserve=512):
    """Fills a VM far beyond what its host admitted while the host refuses it
    more: it stays at its mark (memory.high), the host above its reserve, and
    nothing is killed. Returns how much the guest is filling (MiB)."""
    v = vms(host)[n]
    admitted = v["admitted_mib"]
    if not admitted:
        raise Skip("no per-VM cgroups here")
    used, high, _ = cgroup(host, n)
    fill = v["guest_mib"] - 384
    check(f"{label}: a mark at the admitted size, below the guest's", high is not None and admitted < high < v["guest_mib"], (admitted, high, v["guest_mib"]))
    check(f"{label}: the fill is far beyond it", fill >= 2 * high, (fill, high))
    fault(host, "no_admit", 600000)
    hog(host, n, fill)
    peak, low_avail, seen = 0, mem_available(), []
    for _ in range(40):
        time.sleep(0.25)
        used, high_now, events = cgroup(host, n)
        peak, low_avail = max(peak, used), min(low_avail, mem_available())
        seen.append(used)
    check(f"{label}: throttled at its mark", high_now == high and peak <= high * 1.15 + 32 and events.get("high", "0") != "0",
          (high, peak, seen[::8], events))
    check(f"{label}: the fill did not finish", not hog_done(host, n))
    # Swapped out instead, its vCPUs would wait for swap reads, which a pause cannot cut short.
    check(f"{label}: throttled, not swapped", swapped(host, n) in (0, None), swapped(host, n))
    check(f"{label}: host stays above its reserve", low_avail > reserve, low_avail)
    check(f"{label}: nothing OOM-killed", events.get("oom_kill") == "0" and alive(fc_pid(host, n)) and alive(vm_pid(host, n)), events)
    check(f"{label}: throttled and starved, so the host would move it",
          wait_for(lambda: vms(host)[n].get("starved") and vms(host)[n].get("throttled"), 5), vms(host)[n])
    return fill


class Skip(Exception):
    pass


def skippable(scenario):
    """A scenario that may find this host lacks what it tests: it then passes, saying why."""
    def run_it():
        try:
            scenario()
        except Skip as e:
            print(f"{scenario.__name__}: skipped, {e}", flush=True)
    run_it.__doc__ = scenario.__doc__
    return run_it


def mem_high():
    """A guest filling far beyond its admitted memory while the host refuses
    to admit more is throttled at its mark rather than eating the host's
    reserve, and nothing is killed; admitted again, it grows to what it needs."""
    n = "ft-mem-high"
    m = setup(n, mib=1)
    t = time.time()
    fill = throttle("mem high", A, n)
    fault(A, "no_admit", 0)
    done = wait_for(lambda: hog_done(A, n), 240)
    v = vms(A)[n]
    check("mem high: admitted again, the fill finishes", done, (time.time() - t, v.get("admitted_mib"), cgroup(A, n)))
    used, high, _ = cgroup(A, n)
    check("mem high: its mark grew with it", used >= fill and high >= used, (fill, v["admitted_mib"], used, high))
    check("mem high: no longer throttled", wait_for(lambda: not vms(A)[n].get("throttled"), 5), vms(A)[n])
    check("mem high: md5 intact", md5(A, n) == m)
    cleanup(n)


def mem_high_migrate():
    """A VM throttled at its mark migrates without a stall: its pause is not
    held up by throttled vCPUs, the target pulls all its memory, and there
    (admitted for all of it) it fills what it was refused."""
    n = "ft-mem-high-mig"
    m = setup(n, mib=1)
    throttle("mem high migrate", A, n)
    used = cgroup(A, n)[0]
    r = ok(migrate(A, n, B))
    print(f"mem high migrate: {used} MiB; throttle wait {r['unthrottle_ms']} ms, pause {r['timings_ms']['pause']} ms, "
          f"downtime {r['downtime_ms']} ms", flush=True)
    check("mem high migrate: the pause is not held up", r["timings_ms"]["pause"] < 50 and r["downtime_ms"] < 1000, r["timings_ms"])
    st = wait_released(B, n, timeout=60)
    check("mem high migrate: pulled and released", st["released"] is True and st["failed"] is None and st["background_pull_ms"] < 20000, st)
    check("mem high migrate: the target's mark covers what it pulled", vms(B)[n]["admitted_mib"] >= used, (used, vms(B)[n]["admitted_mib"]))
    check("mem high migrate: the fill finishes there", wait_for(lambda: hog_done(B, n), 240), cgroup(B, n))
    check("mem high migrate: md5 intact, one copy", md5(B, n) == m and where(n) == {B: "running"}, where(n))
    cleanup(n)


def mem_high_evict():
    """A VM its host refuses more memory, throttled at its mark, is moved to
    a peer with room by itself, and grows there."""
    n = "ft-mem-high-evict"
    m = setup(n, mib=1)
    v = vms(A)[n]
    if not v["admitted_mib"]:
        raise Skip("no per-VM cgroups here")
    fault(A, "no_admit", 600000)
    hog(A, n, v["guest_mib"] - 384)
    check("mem high evict: moved to B", wait_for(lambda: where(n) == {B: "running"}, 60), (where(n), log(A, n)[-2000:]))
    st = wait_released(B, n, timeout=60)
    check("mem high evict: pulled and released", st["released"] is True and st["failed"] is None, st)
    holds = lambda: [f for f in os.listdir(os.path.join(B.run, "holds")) if not f.startswith(".")] if os.path.isdir(os.path.join(B.run, "holds")) else []
    check("mem high evict: the arrival's held grant goes once its memory is in", wait_for(lambda: not holds(), 10), holds())
    check("mem high evict: the fill finishes there", wait_for(lambda: hog_done(B, n), 240), cgroup(B, n))
    check("mem high evict: md5 intact", md5(B, n) == m)
    cleanup(n)


class Watch:
    """While eviction runs on `host`: each of `names`' controller ticks (from
    `debug status`) and its memory requests, asked as its guest does (`MEM`,
    for a size it needs no change at) every 250 ms; and MemAvailable."""
    def __init__(self, host, names):
        self.host, self.stop = host, threading.Event()
        self.socks, self.ticks, self.asks, self.avail = {}, {n: [] for n in names}, {n: [] for n in names}, []
        for n in names:
            v = vms(host)[n]
            total = v["guest_mib"]
            headroom = max(total // 4, min(1024, total // 2))
            self.socks[n] = (vsock_path(host, n) + "_53", f"MEM {2 * headroom << 10} {total << 10}\n".encode())
        self.threads = [threading.Thread(target=self.ask, args=(n,), daemon=True) for n in names]
        self.threads += [threading.Thread(target=self.tick, args=(n,), daemon=True) for n in names]
        self.threads.append(threading.Thread(target=self.mem, daemon=True))

    def __enter__(self):
        [t.start() for t in self.threads]
        return self

    def __exit__(self, *_):
        self.stop.set()
        [t.join() for t in self.threads]

    def ask(self, n):
        path, req = self.socks[n]
        while not self.stop.wait(0.25):
            t = time.time()
            try:
                with socket.socket(socket.AF_UNIX) as s:
                    s.settimeout(5)
                    s.connect(path)
                    s.sendall(req)
                    reply = s.recv(64).decode().strip()
            except OSError as e:
                try:
                    here = json.load(open(os.path.join(self.host.run, "vms", f"{n}.json"))).get("state") == "running"
                except (OSError, ValueError):
                    here = False
                if not here:
                    return  # moving away: its source copy serves pages only
                reply = f"error: {e}"
            self.asks[n].append((time.time() - t, reply))

    def tick(self, n):
        while not self.stop.wait(0.25):
            try:
                r = control(self.host, n, {"op": "debug", "what": "status"}, timeout=10)
            except OSError:
                return
            if r.get("ok") and r["result"].get("controller"):
                self.ticks[n].append(r["result"]["controller"])

    def mem(self):
        while not self.stop.wait(0.1):
            self.avail.append((time.time(), mem_available()))

    def report(self, label):
        """Per VM: the longest gap between controller ticks seen, and memory requests answered (max ms)."""
        out = {}
        for n, seen in self.ticks.items():
            # Each tick's gap (by its number) from the polls, from the first poll on, and
            # the longest a tick was seen overdue (one held up never reports its gap).
            gaps = {c["ticks"] - i: g for c in seen for i, g in enumerate(reversed(c["recent_gaps_ms"]))}
            during = [g for t, g in gaps.items() if seen and t > seen[0]["ticks"]]
            overdue = max((c["since_last_ms"] or 0 for c in seen), default=0)
            lat = sorted(a[0] * 1000 for a in self.asks[n])
            out[n] = {"tick_gap_max_ms": round(max(during + [overdue], default=0)), "ticks": len(during),
                      "asks": len(lat), "ask_max_ms": round(max(lat, default=0), 1),
                      "ask_p50_ms": round(lat[len(lat) // 2], 1) if lat else None,
                      "replies": sorted(set(a[1] for a in self.asks[n]))}
        print(f"{label}: {json.dumps(out)}", flush=True)
        return out


def grow(host, name, mib, rate):
    """Starts a guest program growing by `rate` MiB/s to `mib` MiB, every page different."""
    chunk = max(1, rate // 4)
    prog = (f"import time\nbs=[]\nfor i in range({mib} // {chunk}):\n t=time.time()\n b=bytearray({chunk}<<20)\n"
            f" for j in range(0, len(b), 4096): b[j:j+8]=(i*{chunk << 20}+j).to_bytes(8, 'little')\n"
            " bs.append(b)\n time.sleep(max(0, 0.25-(time.time()-t)))\nopen('/tmp/grow.done','w').close()\ntime.sleep(3600)\n")
    code, out = sh(host, name, f"rm -f /tmp/grow.done; echo {base64.b64encode(prog.encode()).decode()} | base64 -d > /tmp/grow.py; "
                               "setsid python3 /tmp/grow.py >/dev/null 2>&1 </dev/null & echo started")
    assert code == 0, out


class marks:
    """`host`'s reserve and eviction high-water mark set to these MiB, in its
    host.json (running VM processes read them from it as it changes)."""
    def __init__(self, reserve, evict_at, host=None):
        self.reserve, self.evict_at, self.cfg = reserve, evict_at, os.path.join((host or A).state, "host.json")

    def write(self, text):
        with open(self.cfg + ".tmp", "w") as f:
            f.write(text)
        os.rename(self.cfg + ".tmp", self.cfg)

    def set(self, reserve=None, evict_at=None):
        c = json.loads(self.saved)
        c.update(reserve_mib=reserve or self.reserve, evict_mib=evict_at or self.evict_at)
        self.write(json.dumps(c))

    def __enter__(self):
        self.saved = open(self.cfg).read()
        self.set()
        return self

    def __exit__(self, *_):
        self.write(self.saved)


class pressure(marks):
    """`host`'s eviction high-water mark kept `over` MiB above MiB available, re-set as that moves (other lanes'
    VMs coming and going on the same machine), so the host stays under pressure however much is freed meanwhile."""
    def __init__(self, reserve, over, host=None):
        super().__init__(reserve, mem_available() + over, host)
        self.over, self.done = over, threading.Event()

    def follow(self):
        while not self.done.wait(0.25):
            want = mem_available() + self.over
            if abs(want - self.evict_at) > 64:
                self.evict_at = want
                self.set()

    def __enter__(self):
        super().__enter__()
        self.thread = threading.Thread(target=self.follow, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.done.set()
        self.thread.join()
        super().__exit__(*a)


def hosts_over(name, secs):
    """Where `name` runs (by the registries), each time that changes, over `secs` s."""
    def here():
        for h in (A, B):
            try:
                if json.load(open(os.path.join(h.run, "vms", f"{name}.json"))).get("state") == "running":
                    return h.addr
            except (OSError, ValueError):
                pass
        return None
    seen, end = [], time.time() + secs
    while time.time() < end:
        h = here()
        if h and (not seen or seen[-1] != h):
            seen.append(h)
        time.sleep(0.05)
    return seen


def evict_no_pingpong():
    """Two hosts near their eviction marks: a VM A evicts is not taken by a
    B it would put under B's own mark (B would only send it back), and once
    B has room it moves there once and stays."""
    n = "ft-pingpong"
    for h in (A, B):
        clear_log(h, n)
    m = setup(n, mib=600)
    time.sleep(11)  # the start's grants age out
    base, rss = mem_available(), cgroup(A, n)[0]
    # B under its own mark (by a margin: this host's MemAvailable moves by a
    # GiB or more as other work comes and goes, and must not give it room):
    # taking the VM would leave it under, and it would only move it back. A's
    # mark is further up, so A keeps trying.
    with marks(512, base + 4000, A), marks(512, base + 3000, B) as b:
        seen = hosts_over(n, 25)
        check("no ping-pong: a peer it would put under its mark refuses it", seen == [A.addr] and where(n) == {A: "running"},
              (seen, where(n), log(A, n)[-1200:]))
        check("no ping-pong: refused for B's eviction mark", "eviction mark" in log(A, n), log(A, n)[-1200:])
        b.set(evict_at=max(600, base - 4 * rss - 1000))
        seen = hosts_over(n, 45)
        check("no ping-pong: with room on B it moves there once, and stays", seen == [A.addr, B.addr] and where(n) == {B: "running"},
              (seen, where(n), log(B, n)[-1200:]))
    check("no ping-pong: md5 intact", md5(B, n) == m)
    cleanup(n)


def evict_grower():
    """Three VMs on a host nearing its eviction high-water mark (above its
    reserve), one of them growing fast: that one is moved to B, ranked over
    two bigger but static ones by its growth, before the host gets to its
    reserve. Meanwhile each VM's controller ticks on and its memory requests
    are answered."""
    g, big = "ft-ev-grow", ["ft-ev-big1", "ft-ev-big2"]
    sums = {g: setup(g, mib=1)}
    if vms(A)[g]["max_mib"] < 3072:
        raise Skip("its guests need room to grow past 2 GiB (one at its ceiling is starved, and moved for that)")
    sums.update({n: setup(n, mib=900) for n in big})
    time.sleep(11)  # the starts' grants age out
    base = mem_available()
    reserve, high = base - 2600, base - 700

    def rss(n):
        try:
            return cgroup(A, n)[0]
        except (OSError, KeyError, TypeError):
            return None
    with Watch(A, big + [g]) as w, marks(reserve, high):
        grow(A, g, 1300, 100)
        moved = None
        end = time.time() + 120
        while time.time() < end:
            try:
                st = json.load(open(os.path.join(A.run, "vms", f"{g}.json"))).get("state")
            except (OSError, ValueError):
                st = None
            if moved is None and st != "running":
                moved = (time.time(), mem_available(), {n: rss(n) for n in big + [g] if n != g or st == "source"})
            if st is None:
                break  # released: its copy here is gone
            time.sleep(0.1)
    released = time.time()
    lows = [a for t, a in w.avail if t <= (moved or (released,))[0]]
    print(f"evict grower: base {base} MiB, high-water {high}, reserve {reserve}; moved at {moved and moved[1]} MiB available "
          f"(memory.current {moved and moved[2]} MiB), lowest before {min(lows, default=None)} MiB, lowest overall {min(a for _, a in w.avail)} MiB", flush=True)
    rep = w.report("evict grower: during the eviction")
    check("evict grower: the grower moved to B", moved is not None and wait_for(lambda: where(g) == {B: "running"}, 30), (where(g), log(A, g)[-1500:]))
    check("evict grower: the bigger, static vms stayed", all(where(n) == {A: "running"} for n in big), {n: where(n) for n in big})
    check("evict grower: moved under the high-water mark, above the reserve", moved is not None and reserve < moved[1] < high + 200, moved)
    check("evict grower: the host never got to its reserve", min(a for _, a in w.avail) > reserve, min(a for _, a in w.avail))
    check("evict grower: every controller ticked within 2.5 s", all(r["tick_gap_max_ms"] < 2500 for r in rep.values()), rep)
    check("evict grower: memory requests answered within the guest's 2 s",
          all(r["asks"] > 0 and r["ask_max_ms"] < 2000 and not any(x.startswith("error") for x in r["replies"]) for r in rep.values()), rep)
    check("evict grower: md5s intact", md5(B, g) == sums[g] and all(md5(A, n) == sums[n] for n in big))
    for n in big + [g]:
        cleanup(n)


def evict_skips_cmd():
    """A host under pressure leaves a `run -- CMD` VM where it is (CMD's end
    there ends it, with CMD's status), even starved, and moves another."""
    n, other = "ft-ev-cmd", "ft-ev-plain"
    scenario_vms.update({n})
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", args.template, "--", "sleep 600"],
                         stdout=subprocess.DEVNULL, stderr=open(os.path.join(A.run, f"{n}.stderr"), "w"), env=ENV, start_new_session=True)
    check("evict cmd: up", wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 30), vms(A).get(n))
    m = setup(other, mib=1)
    with pressure(512, 1000, A):
        moved = wait_for(lambda: where(other) == {B: "running"}, 60)
        time.sleep(8)
    check("evict cmd: the plain vm moved", moved, (where(other), log(A, other)[-800:]))
    check("evict cmd: the cmd vm stayed, running its command", where(n) == {A: "running"} and p.poll() is None, (where(n), p.poll()))
    check("evict cmd: md5 intact", md5(B, other) == m)
    os.kill(p.pid, signal.SIGINT)
    check("evict cmd: its command's end still ends it here", p.wait(timeout=30) == 130)
    cleanup(other)


def evict_latency():
    """Measures each VM's controller ticks and memory requests while a
    starved VM is moved away to a target slow to prepare (3 s): the VM process
    deciding the eviction (the starved one's) ticks on and answers."""
    n, others = "ft-lat-starved", ["ft-lat-a", "ft-lat-b"]
    sums = {n: setup(n, mib=1), **{o: setup(o, mib=100) for o in others}}
    if not vms(A)[n]["admitted_mib"]:
        raise Skip("no per-VM cgroups here")
    with Watch(A, [n] + others) as w:
        time.sleep(3)
        fault(B, "incoming_stall", 600000)
        fault(A, "no_admit", 600000)
        hog(A, n, vms(A)[n]["guest_mib"] - 384)
        moved = wait_for(lambda: where(n) == {B: "running"}, 90)
        time.sleep(1)
    fault(A, "no_admit", 0)
    fault(B, "incoming_stall", 0)
    rep = w.report("evict latency: during the eviction")
    check("evict latency: moved to B", moved, (where(n), log(A, n)[-1500:]))
    check("evict latency: every controller ticked within 2.5 s", all(r["tick_gap_max_ms"] < 2500 for r in rep.values()), rep)
    check("evict latency: memory requests answered within the guest's 2 s",
          all(r["asks"] > 0 and r["ask_max_ms"] < 2000 and not any(x.startswith("error") for x in r["replies"]) for r in rep.values()), rep)
    # Its source, paused at its mark through the pull, is not starved: nothing else moves for it.
    time.sleep(8)
    check("evict latency: the others stay", all(where(o) == {A: "running"} for o in others), {o: where(o) for o in others})
    check("evict latency: md5s intact", md5(B, n) == sums[n] and all(md5(A, o) == sums[o] for o in others))
    for v in [n] + others:
        cleanup(v)


def start_admission():
    """Concurrent starts are admitted against the reserve, each with what it
    brings and a step, so together they cannot take the host below it: with
    room for three steps, at most three of eight start, the rest are refused
    saying why, and a restore is refused the same way."""
    n, path = "ft-admit", ckpt_path("ft-admit")
    setup(n, mib=1)
    # A cold start is admitted for the template's working set (paged in up front) and a step.
    each = vms(A)[n]["admitted_mib"]
    ok(checkpoint(A, n, path))
    cleanup(n)
    names = [f"ft-admit-{i}" for i in range(8)]
    res = {}
    with tight_reserve(3 * each + each // 2):
        threads = [threading.Thread(target=lambda i=i: res.update({i: run(A, i)})) for i in names]
        [t.start() for t in threads]
        [t.join() for t in threads]
        started = [i for i in names if res[i]["ok"]]
        refused = [i for i in names if not res[i]["ok"]]
        check(f"start admission: at most three start ({each} MiB each)", 1 <= len(started) <= 3,
              (started, [res[i].get("error") for i in refused][:2]))
        check("start admission: the others are refused for the reserve",
              all("above the" in res[i]["error"] and "reserve" in res[i]["error"] for i in refused), [res[i]["error"] for i in refused])
        marks = {i: (vms(A)[i]["admitted_mib"], cgroup(A, i)[0]) for i in started}
        check("start admission: each started at its allowance, holding no more", all(a == each and u <= a + 64 for a, u in marks.values()), marks)
        r = restore(A, path, name="ft-admit-r", ip="auto")
        check("start admission: a restore is refused too", not r["ok"] and "reserve" in r["error"], r)
    for i in names + ["ft-admit-r"]:
        kill(A, i)
    rm_ckpt(path)


class tight_reserve:
    """Host A's reserve set to leave `room` MiB above it, once earlier grants aged out."""
    def __init__(self, room):
        self.room, self.cfg = room, os.path.join(A.state, "host.json")

    def __enter__(self):
        self.saved = open(self.cfg).read()
        time.sleep(11)
        c = json.loads(self.saved)
        c["reserve_mib"] = mem_available() - self.room
        with open(self.cfg, "w") as f:
            json.dump(c, f)

    def __exit__(self, *_):
        with open(self.cfg, "w") as f:
            f.write(self.saved)


def grants(host):
    """Admission grants of the last 10 s on `host` (MiB each)."""
    try:
        g = json.load(open(os.path.join(host.run, "grants")))
    except (OSError, ValueError):
        return []
    return [m for t, m, *_ in g if time.time() * 1000 - t <= 10000]


def addr_records():
    """Every address record on both hosts (generations, loans, holders)."""
    out = {}
    for h in (A, B):
        d = os.path.join(h.state, "addrs")
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            out[(h.addr, f)] = open(os.path.join(d, f)).read()
    return out


def refused_admission():
    """A start refused for the reserve is refused before it claims anything:
    a run mints no generation (so none is withdrawn and broadcast), a restore
    borrows no address from its home host, an arrival records no migration."""
    n, path = "ft-refused-adm", ckpt_path("ft-refused-adm")
    m = setup(n, mib=1)
    migs = lambda: sorted(os.listdir(os.path.join(B.state, "migs"))) if os.path.isdir(os.path.join(B.state, "migs")) else []
    # The start announces its generation to B in the background: in before the snapshot.
    v = vms(A)[n]
    check("refused admission: b saw the start", wait_for(lambda: addr(B, v["ip"]).get("seen", 0) >= v["gen"], 10), addr(B, v["ip"]))
    before, recorded = addr_records(), migs()
    fault(B, "no_admit", 600000)
    r = migrate(A, n, B)
    check("refused admission: a migration is refused", not r["ok"] and "not enough memory" in r["error"], r)
    after, now = addr_records(), migs()
    changed = {k: (before.get(k), after.get(k)) for k in before.keys() | after.keys() if before.get(k) != after.get(k)}
    check("refused admission: and records nothing", now == recorded and not changed, (recorded, now, changed))
    check("refused admission: the vm runs on at A", where(n) == {A: "running"} and md5(A, n) == m, where(n))
    ok(checkpoint(A, n, path, stop=True))
    before = addr_records()
    # Its address is A's: a restore on B borrows it.
    r = restore(B, path)
    check("refused admission: a restore is refused", not r["ok"] and "not enough memory" in r["error"], r)
    check("refused admission: and borrows nothing", addr_records() == before, before)
    r = run(B, "ft-refused-adm-run")
    check("refused admission: a run is refused", not r["ok"] and "not enough memory" in r["error"], r)
    check("refused admission: and mints no generation", addr_records() == before)
    fault(B, "no_admit", 0)
    r = restore(B, path)
    check("refused admission: admitted, the restore borrows it", r["ok"] and md5(B, n) == m, r)
    cleanup(n)
    rm_ckpt(path)


def meminfo_unreadable():
    """/proc/meminfo unreadable (injected) is not 0 MiB available: no standby
    is stopped and nothing is evicted, and a start is refused saying why."""
    t, n = args.template, "ft-meminfo"
    setup(n, mib=1)
    pressure = os.path.join(A.run, "standby", ".pressure")
    mtime = lambda p: os.stat(p).st_mtime if os.path.exists(p) else None
    try:
        ok(cli_json(A, "standby", "--template", t, "1"))
        locks = lambda: [f for f in os.listdir(os.path.join(A.run, "standby", t)) if f.endswith(".lock") and alive(f[:-5])]
        check("meminfo: a standby ready", wait_for(lambda: len(locks()) == 1, 60), locks())
        ready, pressed = locks(), mtime(pressure)
        fault(A, "no_meminfo", 600000)
        # The VM process weighs relief every second.
        time.sleep(4)
        check("meminfo: the standby stays", locks() == ready and mtime(pressure) == pressed, (ready, locks()))
        check("meminfo: the vm stays", where(n) == {A: "running"}, where(n))
        r = run(A, "ft-meminfo-run")
        check("meminfo: a start is refused, saying why", not r["ok"] and "MemAvailable" in r["error"], r)
        check("meminfo: still the standby", locks() == ready, locks())
    finally:
        fault(A, "no_meminfo", 0)
        ok(cli_json(A, "standby", "--template", t, "0"))
        cleanup(n)


def standby_admission():
    """A standby claim is charged only the step it may grow by (its memory is
    already in use), so it succeeds with little room above the reserve; a
    claim refused before it starts anything (its name is taken) leaves no grant."""
    t = args.template
    ok(run(A, "ft-sbadm-dup"))
    try:
        ok(cli_json(A, "standby", "--template", t, "1"))
        live = lambda: len([f for f in os.listdir(os.path.join(A.run, "standby", t)) if f.endswith(".lock") and alive(f[:-5])])
        check("standby admission: one ready", wait_for(lambda: live() == 1, 60), live())
        with tight_reserve(256 + 48):
            r = run(A, "ft-sbadm-dup")
            check("standby admission: a taken name is refused", not r["ok"], r)
            check("standby admission: and leaves no grant", grants(A) == [], grants(A))
            r = run(A, "ft-sbadm")
            check("standby admission: claimed with room for a step only", r["ok"] and r["result"]["standby"] is True, r)
    finally:
        ok(cli_json(A, "standby", "--template", t, "0"))
        cleanup("ft-sbadm")
        cleanup("ft-sbadm-dup")


def kill_source():
    """A migration's paused source copy cannot be killed (the target still
    pulls from it and releases it); the VM lives on at the target."""
    n = "ft-kill-source"
    m = setup(n, mib=1500)
    ok(migrate(A, n, B))
    # Keep the pull from finishing (the target retries for 10 s).
    fault(A, "pages", 3000)
    r = kill(A, n)
    check("kill source: refused", not r["ok"] and "source of a migration" in r.get("error", ""), r)
    check("kill source: copy still paused on A", vms(A).get(n, {}).get("state") == "source", where(n))
    st = wait_released(B, n)
    check("kill source: target pulled everything and released it",
          st["released"] is True and st["failed"] is None and where(n) == {B: "running"}, (st, where(n)))
    check("kill source: md5 intact on B", md5(B, n) == m)
    cleanup(n)


def kill_refused_checkpoint():
    """A kill that waited for a migration and was refused (the VM became its
    source) leaves nothing behind: once the target dies mid-pull and the
    source runs its copy again, a checkpoint is not taken for killed."""
    n = "ft-kill-refused"
    clear_log(A, n)
    m = setup(n, mib=1500)
    pid = vm_pid(A, n)
    fault(B, "incoming_stall", 2000)
    r = [None]
    t = threading.Thread(target=lambda: r.__setitem__(0, migrate(A, n, B)))
    t.start()
    # The target stalls preparing; the source holds its operation lock, not yet a source.
    lock = os.path.join(B.run, "vms", f"{n}.lock")
    wait_for(lambda: os.path.exists(lock) and open(lock).read().strip(), 20)
    os.kill(pid, signal.SIGINT)
    t.join()
    check("kill refused: migrated", r[0]["ok"], r[0])
    fault(A, "pages", 6000)  # the pull cannot finish
    tpid = json.load(open(lock))["pid"]
    os.kill(tpid, signal.SIGKILL)
    check("kill refused: the kill was refused for the source",
          wait_for(lambda: "source of a migration" in log(A, n), 10) and alive(pid), log(A, n)[-500:])
    fault(A, "pages", 0)
    check("kill refused: the source runs its copy again", wait_for(lambda: where(n) == {A: "running"}, 60), where(n))
    c = checkpoint(A, n, ckpt_path(n))
    check("kill refused: a checkpoint afterwards succeeds", c["ok"], c)
    check("kill refused: still running, md5 intact", where(n) == {A: "running"} and md5(A, n) == m, where(n))
    cleanup(n)


def dual_stack():
    """Whether a default [::] bind here takes IPv4 connections on loopback."""
    try:
        if open("/proc/sys/net/ipv6/bindv6only").read().strip() != "0":
            return False
        with socket.socket(socket.AF_INET6) as l:
            l.bind(("::", 0))
            l.listen(1)
            with socket.create_connection(("127.0.0.1", l.getsockname()[1]), timeout=2):
                return True
    except OSError:
        return False


def wildcard_listen():
    """A listener on a wildcard address (0.0.0.0, ::, ::ffff:0:0) or a
    link-local one is refused without --underlay, as is port 0; with one,
    migrations from it give the target the underlay address to pull pages
    from, never the wildcard. On a dual-stack [::] listener, IPv4 peers
    (arriving as ::ffff:a.b.c.d) are still peers: pages are pulled from it
    and migrations to it arrive."""
    if args.no_listeners:
        return print("wildcard listen: skipped (--no-listeners)")
    host_ip, port = A.addr.rsplit(":", 1)
    # On a host with no configuration yet (A's keeps the --underlay given below).
    fresh = Host(A.addr, A.dir + "-wildcard", A.ips)
    for bad in (f"0.0.0.0:{port}", f"[::]:{port}", f"[::ffff:0:0]:{port}", f"[fe80::1%1]:{port}"):
        subprocess.run(["rm", "-rf", fresh.dir])
        code, out, err = cli(fresh, "listen", bad, timeout=10)
        check(f"wildcard listen: {bad} without --underlay refused", code != 0 and "--underlay" in err, (code, err))
    subprocess.run(["rm", "-rf", fresh.dir])
    code, out, err = cli(fresh, "listen", f"{host_ip}:0", timeout=10)
    check("wildcard listen: port 0 refused", code != 0 and "port" in err, (code, err))
    subprocess.run(["rm", "-rf", fresh.dir])
    wilds = ["0.0.0.0"] + (["[::]"] if dual_stack() else [])
    if len(wilds) == 1:
        print("wildcard listen: no dual-stack loopback here; [::] not tried")
    for wild in wilds:
        stop_listener(A)
        try:
            start_listener(A, f"{wild}:{port}", ["--underlay", host_ip])
            n = "ft-wildcard"
            clear_log(B, n)
            m = setup(n)
            ok(migrate(A, n, B))
            st = wait_released(B, n)
            check(f"wildcard listen {wild}: released", st["released"] is True and where(n) == {B: "running"}, (st, where(n)))
            pulls = re.findall(r"pull from (\S+) ended", log(B, n))
            check(f"wildcard listen {wild}: the target pulled from the underlay address", pulls == [A.addr], pulls)
            check(f"wildcard listen {wild}: md5 intact", md5(B, n) == m)
            # And back: the wildcard listener takes a migration from its IPv4 peer.
            r = migrate(B, n, A)
            wait_released(A, n)
            check(f"wildcard listen {wild}: a migration to it arrives", r["ok"] and where(n) == {A: "running"}, (r, where(n)))
            check(f"wildcard listen {wild}: md5 intact after the round trip", md5(A, n) == m)
            cleanup(n)
        finally:
            stop_listener(A)
            start_listener(A)


def raw(host, data, timeout=10):
    """Sends `data` on a new connection to `host`'s listener; returns everything until EOF."""
    h, port = host.addr.rsplit(":", 1)
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
    """What a forged or broken peer sends is refused without anything dying:
    arrivals without an address generation (none, 0) or with one older than
    recorded, a huge vmstate, too many preloaded pages, an endless request
    line, a huge page request; page-server refusals reach the client."""
    tid = source_vm()
    n, ip = "ft-forged-gen", B.ips.split("-")[1].rsplit(".", 1)[0] + ".210"
    scenario_vms.add(n)
    for label, gen in (("zero", 0),):
        s, r, _ = migrate_in_raw(B, n, ip, tid, gen=gen)
        s.close()
        check(f"forged gen {label}: arrival refused", not r.get("ok") and "generation" in r.get("error", ""), r)
    newest = addr(B, ip).get("seen", 0) + 10
    s, r, _ = migrate_in_raw(B, n, ip, tid, gen=newest)
    s.close()
    check("forged gen: a newer one is taken", r.get("ok"), r)
    nothing_left("forged gen", n, ip)
    s, r, _ = migrate_in_raw(B, n, ip, tid, gen=newest - 1)
    s.close()
    check("forged gen: an older one than recorded is refused", not r.get("ok") and "newer generation" in r.get("error", ""), r)
    for label, hdr in (("vmstate", {"runs": [], "vmstate_len": 1 << 40, "preload": []}),
                       ("preload", {"runs": [], "vmstate_len": 0, "preload": list(range(5000))})):
        n = f"ft-forged-{label}"
        scenario_vms.add(n)
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
        nothing_left(f"forged {label}", n, ip)
    raw(B, b"x" * (17 << 20))
    check("forged request line: endless line cut off, listener still up", peer(B, {"op": "migration", "mig": 1}).get("ok"))
    # The page server answers before its binary protocol, refusals too.
    n = "ft-forged-pages"
    m = setup(n, mib=1500)
    out = raw(A, (json.dumps({"op": "pages", "name": n, "mig": 1}) + "\n").encode())
    try:
        refusal = json.loads(out.split(b"\n")[0])
    except ValueError:
        refusal = {}
    check("forged pages: refusal answered", refusal.get("ok") is False and "not the source" in refusal.get("error", ""), out[:200])
    r = ok(migrate(A, n, B))
    with socket.create_connection(tuple(A.addr.rsplit(":", 1)[:1]) + (int(A.addr.rsplit(":", 1)[1]),), timeout=10) as s:
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
    st = wait_released(B, n)
    check("forged pages: migration completed", st["released"] is True and where(n) == {B: "running"}, (st, where(n)))
    check("forged pages: md5 intact", md5(B, n) == m)
    cleanup(n)


def restore_ip_peer():
    """run --ip refuses an address that is not the host's to hand out (a
    peer's, or one from no host's range); restore --ip borrows a peer's from
    its home host, which refuses one in use there."""
    n, path = "ft-rip", ckpt_path("ft-rip")
    ok(run(A, n))
    ok(checkpoint(A, n, path))
    ok(run(B, "ft-rip-b"))
    theirs = vms(B)["ft-rip-b"]["ip"]
    r = restore(A, path, name="ft-rip2", ip=theirs)
    check("restore --ip: a peer's live address is refused by its home host",
          not r["ok"] and "cannot borrow" in r.get("error", "") and B.addr in r.get("error", "") and "in use" in r.get("error", ""), r)
    check("restore --ip: nothing restored", "ft-rip2" not in vms(A) and not addr(A, theirs).get("holder"), addr(A, theirs))
    r = run(A, "ft-rip3", ip=theirs)
    check("run --ip: a peer's address is refused", not r["ok"] and "not this host's" in r.get("error", ""), r)
    r = run(A, "ft-rip3", ip="10.250.0.5")
    check("run --ip: an address from no host's range is refused", not r["ok"] and "not this host's" in r.get("error", ""), r)
    r = restore(A, path, name="ft-rip2", ip="auto")
    check("restore --ip auto still works", r["ok"], r)
    rm_ckpt(path)


def late_withdrawal():
    """Address generations order the VMs that had an address: a late
    withdrawal for a VM long gone cannot free a newer VM's loan of it or
    remove its route, and a late announcement of a withdrawn VM brings no
    route back, also after the listener that got them restarts."""
    lent = lambda ip: addr(A, ip).get("lent")
    n = "ft-late-1"
    setup(n, mib=1)
    ip = vms(A)[n]["ip"]
    ok(migrate(A, n, B))
    wait_released(B, n)
    old = lent(ip)
    check("late withdrawal: lent while away", old is not None, addr(A, ip))
    kill(B, n)
    check("late withdrawal: its own withdrawal frees it", wait_for(lambda: not lent(ip), 10), addr(A, ip))
    n2 = "ft-late-2"
    ok(run(A, n2, ip=ip))
    ok(migrate(A, n2, B))
    wait_released(B, n2)
    new = lent(ip)
    check("late withdrawal: lent again, a newer generation", new is not None and old is not None and new > old, (old, new))
    time.sleep(1)
    r = ok(peer(A, {"op": "route", "ip": ip, "gen": old}))
    check("late withdrawal: the old one is stale and frees nothing", r["stale"] and lent(ip) == new, (r, addr(A, ip)))
    r = peer(A, {"op": "route", "ip": ip})
    check("late withdrawal: one without a generation is refused", not r["ok"] and lent(ip) == new, (r, addr(A, ip)))
    kill(B, n2)
    check("late withdrawal: the newer VM's withdrawal frees it", wait_for(lambda: not lent(ip), 10), addr(A, ip))
    late = lambda g: ok(peer(A, {"op": "route", "ip": ip, "via": "127.0.0.1", "gen": g}))
    check("late announcement: of a withdrawn generation is stale", late(new)["stale"])
    check("late announcement: of an older generation is stale", late(old)["stale"])
    stop_listeners()
    start_listeners()
    check("late announcement after a restart: still stale", late(new)["stale"])
    n3 = "ft-late-3"
    ok(run(A, n3, ip=ip))
    third = vms(A)[n3]["gen"]
    check("late withdrawal: newer generations still", third > new, (new, third))
    r = ok(peer(A, {"op": "route", "ip": ip, "gen": new}))
    check("late withdrawal: an older one leaves the newer VM alone", r["stale"] and where(n3) == {A: "running"}, (r, where(n3)))


def incoming_killed():
    """An incoming VM process SIGKILLed after it took the name and address
    (no cleanup runs): both are free again for the next taker once its
    Firecracker is gone, and the migration it began reads as aborted."""
    n, ip = "ft-in-killed", B.ips.split("-")[1].rsplit(".", 1)[0] + ".211"
    scenario_vms.add(n)
    fault(B, "incoming_stall", 10000)
    s, r, mig = [None], [None], [None]
    t = threading.Thread(target=lambda: (lambda x: (s.__setitem__(0, x[0]), r.__setitem__(0, x[1]), mig.__setitem__(0, x[2])))(migrate_in_raw(B, n, ip, source_vm())))
    t.start()
    pid = None
    lock = os.path.join(B.run, "vms", f"{n}.lock")
    wait_for(lambda: os.path.exists(lock) and open(lock).read().strip(), 20)
    holder = json.load(open(lock))
    pid, work = holder["pid"], os.path.join(B.run, "w", f"{holder['pid']}-{holder['start']}")
    time.sleep(1)
    fcs = [json.load(open(os.path.join(d, "fc")))["pid"] for d in
           [os.path.join(work, e) for e in os.listdir(work)] if os.path.exists(os.path.join(d, "fc"))]
    os.kill(pid, signal.SIGKILL)
    t.join()
    fault(B, "incoming_stall", 0)
    check("incoming killed: addressed held at the kill", addr(B, ip).get("holder") == n, addr(B, ip))
    st = peer(B, {"op": "migration", "mig": mig[0]})
    check("incoming killed: its migration is aborted, once its firecracker is gone",
          st.get("ok") and st["result"]["outcome"] == "aborted" and not any(alive(p) for p in fcs), (st, fcs))
    r2 = run(B, n, ip=None)
    check("incoming killed: the name is usable", r2["ok"], r2)
    kill(B, n)


def start_killed():
    """A VM process SIGKILLed between claiming its address and loading the
    VM: the address is free again, for a VM with a newer generation."""
    n = "ft-start-killed"
    scenario_vms.add(n)
    ip = A.ips.split("-")[1]  # the last of the range: free
    fault(A, "start_stall", 10000)
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", args.template, "--ip", ip],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    wait_for(lambda: addr(A, ip).get("holder") == n, 20)
    gen = addr(A, ip).get("held")
    p.kill()
    p.wait()
    fault(A, "start_stall", 0)
    r = run(A, n + "2", ip=ip)
    check("start killed: its address is free again, a newer generation", r["ok"] and vms(A)[n + "2"]["gen"] > gen, (r, gen))
    kill(A, n + "2")
    scenario_vms.add(n + "2")


def sigkill_restart():
    """A VM process SIGKILLed and started again under the same name: its
    address is the new instance's to take (`--ip` the same one), and
    automatic allocations after more crashes leave nothing reserved."""
    n = "ft-sigkill-restart"
    net, last = A.ips.split("-")[1].rsplit(".", 1)
    ip = f"{net}.{int(last) - 1}"  # next to start_killed's, the last of the range
    used = {ip}

    def crash():
        pid = vm_pid(A, n)
        os.kill(pid, signal.SIGKILL)
        return wait_for(lambda: not alive(pid), 10)

    r = run(A, n, ip=ip)
    check("sigkill restart: started", r["ok"], r)
    if not r["ok"]:
        return
    gen = vms(A)[n]["gen"]
    check("sigkill restart: killed", crash())
    r = run(A, n, ip=ip)
    check("sigkill restart: same name, same --ip", r["ok"] and r["result"]["ip"] == ip, r)
    if not r["ok"]:
        return
    check("sigkill restart: a newer generation", vms(A)[n]["gen"] > gen, (vms(A)[n], gen))
    for i in range(3):
        if not check(f"sigkill restart: killed again ({i})", crash()):
            return
        r = run(A, n)
        if not check(f"sigkill restart: restarted with an automatic address ({i})", r["ok"], r):
            return
        used.add(r["result"]["ip"])
    ok(kill(A, n))
    held = {i: addr(A, i) for i in sorted(used)}
    check("sigkill restart: no address held after the kill", all(not a.get("lent") for a in held.values()), held)
    # Every address it ever had is free for another VM.
    for i in sorted(used):
        r = run(A, n + "2", ip=i)
        check(f"sigkill restart: {i} free again", r["ok"], r)
        kill(A, n + "2")


def listen_trickle():
    """A peer that trickles its request line (a byte every 2 s, each within a
    per-read timeout) is cut off by one 10 s deadline for the whole line."""
    h, port = A.addr.rsplit(":", 1)
    s = socket.create_connection((h, int(port)), timeout=5)
    start, closed = time.time(), None
    try:
        for c in b'{"op": "migration", "mig": 1' + b" " * 20:
            s.sendall(bytes([c]))
            s.settimeout(2)
            try:
                if s.recv(1) == b"":
                    closed = time.time() - start
                    break
            except socket.timeout:
                pass
            if time.time() - start > 25:
                break
    except OSError:
        closed = time.time() - start
    s.close()
    check("listen trickle: cut off by the deadline", closed is not None and 9 <= closed <= 15, closed)
    r = peer(A, {"op": "migration", "mig": 1})
    check("listen trickle: the listener still answers", r.get("ok"), r)


def claim_killed():
    """A standby VM SIGKILLed after it resumed the VM for a claim, before it
    answered: `run` says the claim is uncertain and starts nothing else."""
    n = "ft-claim-killed"
    scenario_vms.add(n)
    code, out, err = cli(A, "standby", "--template", args.template, "1")
    check("claim killed: a standby vm", code == 0, err)
    fault(A, "claim_stall", 10000)
    lockdir = os.path.join(A.run, "standby", args.template)
    pids = [json.load(open(os.path.join(lockdir, f)))["pid"] for f in os.listdir(lockdir) if f.endswith(".lock")]
    res = {}
    t = threading.Thread(target=lambda: res.update(r=cli_json(A, "run", n, "--template", args.template, "-d")))
    t.start()
    time.sleep(1.5)
    for p in pids:
        try:
            os.kill(p, signal.SIGKILL)
        except OSError:
            pass
    t.join()
    fault(A, "claim_stall", 0)
    r = res.get("r", {})
    check("claim killed: uncertain, not started again", not r.get("ok") and "may have started" in r.get("error", ""), r)
    check("claim killed: running nowhere", wait_for(lambda: n not in vms(A), 10), vms(A).get(n))
    cli(A, "standby", "--template", args.template, "0")


def fc_died():
    """A VM's Firecracker dies under it (a guest panic, an OOM kill): its
    process notices at once, cleans up as a kill would (address withdrawn,
    route gone), exits with status 124, and `ls` shows it failed, with
    Firecracker's exit status and the end of its log, until `kill`."""
    n = "ft-fc-died"
    scenario_vms.add(n)
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", args.template],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=ENV)
    check("fc died: up", wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 30), vms(A).get(n))
    v = vms(A)[n]
    os.kill(v["firecracker"], signal.SIGKILL)
    t = time.time()
    try:
        code = p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        code = None
    took = time.time() - t
    check("fc died: noticed at once, exit status 124", code == 124 and took < 2, (code, took))
    failed = vms(A).get(n, {})
    check("fc died: ls shows it failed, saying how", failed.get("state") == "failed" and "signal: 9" in failed.get("error", ""), failed)
    check("fc died: address withdrawn", not addr(A, v["ip"]).get("holder") and addr(A, v["ip"]).get("withdrawn"), addr(A, v["ip"]))
    route = subprocess.run(["ip", "route", "show", f"{v['ip']}/32"], capture_output=True, text=True).stdout.strip()
    check("fc died: route gone", route == "", route)
    ok(kill(A, n))
    check("fc died: kill clears it", n not in vms(A), vms(A).get(n))


def fc_died_busy():
    """A Firecracker that dies while an operation holds the VM (a slow
    checkpoint copying its memory) ends the VM at once all the same: the
    death interrupts the operation instead of waiting for it. Exit status
    124, the checkpoint fails and is never published, `ls` shows it failed."""
    n, path = "ft-fc-died-busy", ckpt_path("ft-fc-died-busy")
    scenario_vms.add(n)
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", args.template],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    check("fc died busy: up", wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 30), vms(A).get(n))
    code, out = sh(A, n, "dd if=/dev/urandom of=/tmp/f bs=1M count=300 iflag=fullblock 2>/dev/null && echo ok")
    check("fc died busy: memory written", code == 0, out)
    fault(A, "ckpt_slow", 120000)
    res = {}
    t = threading.Thread(target=lambda: res.update(r=checkpoint(A, n, path)))
    t.start()
    busy = wait_for(lambda: staged_mib() > 20 and vms(A).get(n, {}).get("checkpoint_copy"), 60)
    check("fc died busy: caught the checkpoint copying", busy, vms(A).get(n))
    v = vms(A)[n]
    os.kill(v["firecracker"], signal.SIGKILL)
    started = time.time()
    try:
        code = p.wait(timeout=60)
    except subprocess.TimeoutExpired:
        code = None
    took = time.time() - started
    t.join(60)
    fault(A, "ckpt_slow", 0)
    check("fc died busy: noticed at once, exit status 124", code == 124 and took < 2, (code, took))
    check("fc died busy: the checkpoint failed, nothing published", not res.get("r", {}).get("ok") and not os.path.exists(path), res)
    failed = vms(A).get(n, {})
    check("fc died busy: ls shows it failed", failed.get("state") == "failed" and "signal: 9" in failed.get("error", ""), failed)
    check("fc died busy: address withdrawn", not addr(A, v["ip"]).get("holder") and addr(A, v["ip"]).get("withdrawn"), addr(A, v["ip"]))
    ok(kill(A, n))


def pull_died():
    """An arrival whose Firecracker dies mid-pull never releases its source,
    which runs its copy again. A VM coming home whose arrival dies mid-pull
    leaves its home host's loan in place: the address stays lent while the
    source runs on, and is not handed out again."""
    n = "ft-pull-fc-died"
    m = setup(n, mib=1500)
    stall = threading.Timer(0.2, lambda: fault(A, "pages", 6000))
    stall.start()
    ok(migrate(A, n, B))
    stall.join()
    fc = vms(B)[n]["firecracker"]
    os.kill(fc, signal.SIGKILL)
    check("pull died: the target fails", wait_for(lambda: vms(B).get(n, {}).get("state") == "failed", 10), vms(B).get(n))
    fault(A, "pages", 0)
    check("pull died: the source never lets go, and runs its copy again",
          wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 60), where(n))
    check("pull died: md5 intact on A", md5(A, n) == m)
    kill(B, n)
    cleanup(n)
    n = "ft-home-died"
    m = setup(n, mib=1500)
    ip = vms(A)[n]["ip"]
    ok(migrate(A, n, B))
    wait_released(B, n)
    stall = threading.Timer(0.2, lambda: fault(B, "pages", 6000))
    stall.start()
    ok(migrate(B, n, A))
    stall.join()
    pid = json.load(open(os.path.join(A.run, "vms", f"{n}.lock")))["pid"]
    os.kill(pid, signal.SIGKILL)
    fault(B, "pages", 0)
    check("home died: the source runs its copy again", wait_for(lambda: vms(B).get(n, {}).get("state") == "running", 60), where(n))
    check("home died: md5 intact on B", md5(B, n) == m)
    check("home died: the address is still lent on its home host", addr(A, ip).get("lent") is not None, addr(A, ip))
    r = run(A, "ft-home-x", ip=ip)
    check("home died: and not handed out again", not r["ok"] and "lent" in r.get("error", ""), r)
    cleanup(n)


def arrival_overtaken():
    """Operations that change who owns a VM wait for its arrival to settle
    (every page in, the migration released, a home loan taken back), or are
    refused: a suspend mid-arrival, and migrating on mid-arrival, refused or
    not. Each time one copy runs, and the home host's loan is right."""
    lent = lambda ip: addr(A, ip).get("lent")
    # Suspended mid-arrival on B: it settles first, so A lets go.
    n = "ft-arrive-suspend"
    m = setup(n, mib=1500)
    ip = vms(A)[n]["ip"]
    stall = threading.Timer(0.2, lambda: fault(A, "pages", 3000))
    stall.start()
    ok(migrate(A, n, B))
    stall.join()
    suspend(B, n)
    check("suspend mid-arrival: suspended on B", vms(B).get(n, {}).get("state") == "suspended", vms(B).get(n))
    check("suspend mid-arrival: the source let go", wait_for(lambda: n not in vms(A), 30), vms(A).get(n))
    check("suspend mid-arrival: still lent by its home host", lent(ip) is not None, addr(A, ip))
    ok(resume_suspended(B, n))
    check("suspend mid-arrival: one copy, running on B", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    cleanup(n)
    # Coming home to A, and sent on again before all its memory is back: refused.
    n = "ft-arrive-refused"
    m = setup(n, mib=1500)
    ip = vms(A)[n]["ip"]
    ok(migrate(A, n, B))
    wait_released(B, n)
    stall = threading.Timer(0.2, lambda: fault(B, "pages", 15000))
    stall.start()
    ok(migrate(B, n, A))
    stall.join()
    r = migrate(A, n, B)
    check("migrate on mid-arrival: refused", not r["ok"] and "still arriving" in r.get("error", ""), r)
    check("migrate on mid-arrival: the loan stays until it settles", lent(ip) is not None, addr(A, ip))
    fault(B, "pages", 0)
    wait_released(A, n, source=B)
    check("migrate on mid-arrival: one copy, home on A", where(n) == {A: "running"} and md5(A, n) == m, where(n))
    check("migrate on mid-arrival: home, so no longer lent", wait_for(lambda: lent(ip) is None, 10), addr(A, ip))
    cleanup(n)
    # Sent on again mid-arrival, and it goes once the arrival settled.
    n = "ft-arrive-onward"
    m = setup(n, mib=1500)
    ip = vms(A)[n]["ip"]
    ok(migrate(A, n, B))
    wait_released(B, n)
    stall = threading.Timer(0.2, lambda: fault(B, "pages", 2000))
    stall.start()
    ok(migrate(B, n, A))
    stall.join()
    r = migrate(A, n, B)
    # B may still be letting go of its source copy, holding the name a moment.
    end = time.time() + 30
    while not r["ok"] and "taken" in r.get("error", "") and time.time() < end:
        time.sleep(0.5)
        r = migrate(A, n, B)
    check("migrate on after the arrival: it goes", r["ok"], r)
    wait_released(B, n, source=A)
    check("migrate on after the arrival: one copy, on B", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    check("migrate on after the arrival: lent by its home host", lent(ip) is not None, addr(A, ip))
    cleanup(n)


def terminal():
    """A foreground run as a shell runs it, signalled through its process
    group: Ctrl-Z pauses the VM (Firecracker is not in the group, so it never
    stops), SIGHUP (a closed terminal) is ignored and output to a terminal
    that is gone goes to the VM's log instead of killing it, and Ctrl-C
    destroys it with exit status 130 and nothing left failed."""
    n = "ft-terminal"
    scenario_vms.add(n)
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", args.template],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, start_new_session=True)
    check("terminal: up", wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 30), vms(A).get(n))
    fc = vms(A)[n]["firecracker"]
    check("terminal: firecracker has a process group of its own", os.getpgid(fc) != p.pid, (os.getpgid(fc), p.pid))
    os.killpg(p.pid, signal.SIGTSTP)
    check("terminal: Ctrl-Z pauses the vm", wait_for(lambda: vms(A).get(n, {}).get("state") == "paused", 10), vms(A).get(n))
    state = open(f"/proc/{fc}/stat").read().rsplit(")", 1)[1].split()[0]
    check("terminal: firecracker itself is not stopped", state != "T", state)
    os.killpg(p.pid, signal.SIGCONT)
    check("terminal: resumed", wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 10), vms(A).get(n))
    os.killpg(p.pid, signal.SIGHUP)
    # The terminal is gone: the next line the VM process prints has nowhere to go.
    p.stdout.close()
    p.stderr.close()
    fault(A, "publish", 5000)
    os.killpg(p.pid, signal.SIGTSTP)
    time.sleep(1)
    os.killpg(p.pid, signal.SIGCONT)
    time.sleep(1)
    fault(A, "publish", 0)
    check("terminal: a closed terminal leaves it running", p.poll() is None and alive(fc), p.poll())
    check("terminal: its output then goes to its log", "injected fault: not published" in log(A, n), log(A, n)[-300:])
    os.killpg(p.pid, signal.SIGINT)
    try:
        code = p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        code = None
    check("terminal: Ctrl-C destroys it, exit status 130", code == 130, code)
    check("terminal: nothing left, nothing failed", n not in vms(A) and not alive(fc), vms(A).get(n))


def run_status():
    """`run -- CMD` exits with CMD's status, started cold or claiming a
    standby VM (whose exit frame may arrive before the claimer reads it)."""
    n = "ft-run-status"
    scenario_vms.add(n)
    argv = [BIN, "--state", A.state, "--run", A.run, "run", n, "--template", args.template, "--"]
    r = subprocess.run(argv + ["exit 7"], capture_output=True, text=True, env=ENV, timeout=120)
    check("run status: cold, CMD's own", r.returncode == 7, (r.returncode, r.stderr[-300:]))
    ok(cli_json(A, "standby", "--template", args.template, "1"))
    r = subprocess.run(argv + ["exit 5"], capture_output=True, text=True, env=ENV, timeout=120)
    check("run status: claimed, CMD's own", r.returncode == 5 and '"standby":true' in r.stderr, (r.returncode, r.stderr[-300:]))
    ok(cli_json(A, "standby", "--template", args.template, "0"))


def unread_output():
    """`run -- CMD` whose stdout is a pipe nobody reads (output stuck) still
    ends at once on SIGINT, with status 130: printing never holds it up."""
    n = "ft-unread"
    scenario_vms.add(n)
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", args.template, "--",
                          "head -c 1000000 /dev/zero | tr '\\0' x; sleep 600"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV, start_new_session=True)
    check("unread output: up", wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 30), vms(A).get(n))
    time.sleep(3)
    t = time.time()
    os.kill(p.pid, signal.SIGINT)
    try:
        code = p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        code = None
    took = time.time() - t
    p.stdout.close()
    check("unread output: SIGINT ends it within 2 s, status 130", code == 130 and took < 2.5, (code, took))
    check("unread output: what it printed went to its log", "xxxx" in log(A, n), len(log(A, n)))


def suspend_killed():
    """SIGINT means destroy, and it wins over a suspend: a kill that comes
    while the suspend is publishing its checkpoint revokes the checkpoint
    (no suspended VM is left, its address is withdrawn), and `kill` undoes a
    suspend that finished first."""
    n = "ft-susp-killed"
    setup(n, mib=20)
    ip = vms(A)[n]["ip"]
    pid = vm_pid(A, n)
    fault(A, "suspend_stall", 10000)
    os.kill(pid, signal.SIGTERM)
    d = os.path.join(A.state, "suspended", n)
    check("suspend killed: published", wait_for(lambda: os.path.exists(os.path.join(d, "manifest.json")), 30), d)
    os.kill(pid, signal.SIGINT)
    check("suspend killed: the process ends", wait_for(lambda: not alive(pid), 30), pid)
    fault(A, "suspend_stall", 0)
    check("suspend killed: no suspended vm left", n not in vms(A) and not os.path.exists(d), (vms(A).get(n), os.path.exists(d)))
    check("suspend killed: address withdrawn", not addr(A, ip).get("holder") and addr(A, ip).get("withdrawn"), addr(A, ip))
    # A suspend that is done before the kill: `kill` still destroys it.
    setup(n, mib=20)
    pid = vm_pid(A, n)
    os.kill(pid, signal.SIGTERM)
    r = kill(A, n)
    check("suspend killed: kill after a suspend destroys it", r["ok"] and n not in vms(A) and not os.path.exists(d), (r, vms(A).get(n)))


def suspend_cmd():
    """SIGTERM on a `run -d -- CMD` VM suspends it, CMD and all: the command
    keeps running in the guest's memory, and the process `flexvm resume`
    starts reattaches to it, prints the rest of its output (nothing twice)
    and exits with its status."""
    n = "ft-susp-cmd"
    scenario_vms.add(n)
    # Markers no flexvm message contains (its own lines, such as "guest clock was
    # ... off after resuming", go to the same log), counted as whole lines.
    before, after = "susp-cmd-out-1", "susp-cmd-out-2"
    cmd = f"echo {before}; sleep 6; echo {after}; exit 7"
    clear_log(A, n)
    ok(cli_json(A, "run", n, "--template", args.template, "-d", "--", cmd))
    pid = vm_pid(A, n)
    check("suspend cmd: started", wait_for(lambda: before in log(A, n).splitlines(), 30), log(A, n)[-300:])
    t = time.time()
    os.kill(pid, signal.SIGTERM)
    gone = wait_for(lambda: not alive(pid), 60)
    check("suspend cmd: SIGTERM suspends it", gone and vms(A).get(n, {}).get("state") == "suspended" and time.time() - t < 10,
          (time.time() - t, vms(A).get(n), log(A, n)[-500:]))
    check("suspend cmd: the command was not given up", "timed out" not in log(A, n) and "being killed" not in log(A, n), log(A, n)[-500:])
    r = subprocess.run([BIN, "--state", A.state, "--run", A.run, "resume", n], capture_output=True, text=True, timeout=120, env=ENV)
    check("suspend cmd: resumed, the command's status", r.returncode == 7, (r.returncode, r.stderr[-500:]))
    # Whatever printed it: the suspended process, or the resumed one (if the suspend outlasted the sleep).
    lines = log(A, n).splitlines() + r.stdout.splitlines()
    check("suspend cmd: its output, once", lines.count(before) == 1 and lines.count(after) == 1, (log(A, n), r.stdout))
    check("suspend cmd: the resumed process's stdout is the command's output alone",
          set(r.stdout.splitlines()) <= {after}, r.stdout)
    check("suspend cmd: gone after it", n not in vms(A), vms(A).get(n))


def first_entry(host, name, timeout=60):
    """`name`'s registry entry as first published (polled every 5 ms)."""
    path = os.path.join(host.run, "vms", f"{name}.json")
    end = time.time() + timeout
    while time.time() < end:
        try:
            return json.load(open(path))
        except (OSError, ValueError):
            time.sleep(0.005)
    return None


def cmd_flag():
    """A `run -- CMD` VM is published as one from its first entry, whether it
    claimed a standby VM or was resumed with its command (eviction leaves it
    alone), and `migrate` refuses it, saying why."""
    t = args.template
    n, r = "ft-cmd-flag", "ft-cmd-flag-resumed"
    scenario_vms.update({n, r})
    ok(cli_json(A, "standby", "--template", t, "1"))
    try:
        live = lambda: len([f for f in os.listdir(os.path.join(A.run, "standby", t)) if f.endswith(".lock") and alive(f[:-5])])
        check("cmd flag: a standby ready", wait_for(lambda: live() == 1, 60), live())
        p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", t, "--", "sleep 600"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV, start_new_session=True)
        e = first_entry(A, n)
        check("cmd flag: a claimed standby is published as a cmd vm", e is not None and e.get("cmd") is True, e)
        wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 30)
        m = migrate(A, n, B)
        check("cmd flag: migrate refuses it, saying why", not m["ok"] and "cannot migrate" in m["error"], m)
        os.kill(p.pid, signal.SIGINT)
        check("cmd flag: its command's end still ends it", p.wait(timeout=30) == 130)
    finally:
        ok(cli_json(A, "standby", "--template", t, "0"))
    ok(cli_json(A, "run", r, "--template", t, "-d", "--", "sleep 600"))
    pid = vm_pid(A, r)
    os.kill(pid, signal.SIGTERM)
    check("cmd flag: suspended", wait_for(lambda: not alive(pid), 60) and vms(A).get(r, {}).get("state") == "suspended", vms(A).get(r))
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "resume", r], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         env=ENV, start_new_session=True)
    e = first_entry(A, r)
    check("cmd flag: a resumed one too", e is not None and e.get("cmd") is True, e)
    os.kill(p.pid, signal.SIGINT)
    check("cmd flag: and ends with it", p.wait(timeout=30) == 130)


def pause_cmd_start():
    """Ctrl-Z while a `run -- CMD` VM starts pauses it before its command
    is under way, which waits for the VM instead of failing (and destroying
    it); once resumed, the command runs and the process exits with its status."""
    n = "ft-pause-cmd"
    scenario_vms.add(n)
    # Its start stalls (3 s) once it holds its name: the Ctrl-Z comes before the VM runs.
    fault(A, "start_stall", 10000)
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", args.template, "--",
                          "echo started; exit 9"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV, text=True)
    # Once it holds its name its signals are taken (blocked from its first instruction).
    lock = os.path.join(A.run, "vms", f"{n}.lock")
    check("pause cmd: starting", wait_for(lambda: os.path.exists(lock) and open(lock).read().strip(), 30))
    os.kill(p.pid, signal.SIGTSTP)
    fault(A, "start_stall", 0)
    check("pause cmd: paused", wait_for(lambda: vms(A).get(n, {}).get("state") == "paused", 30), vms(A).get(n))
    time.sleep(2)
    check("pause cmd: still there, paused", p.poll() is None and vms(A).get(n, {}).get("state") == "paused", (p.poll(), vms(A).get(n)))
    code, out, err = cli(A, "resume", n)
    check("pause cmd: resumed", code == 0, err)
    try:
        code = p.wait(timeout=60)
    except subprocess.TimeoutExpired:
        code = None
    out = p.stdout.read()
    check("pause cmd: the command ran, its status", code == 9 and out.count("started") == 1, (code, out))


def suspend_died():
    """A Firecracker that dies after a suspend published its checkpoint (but
    before the suspend ended) is a death, not a kill: the checkpoint is
    revoked and the process exits 124 with why in `.failed`, not 130."""
    n = "ft-susp-died"
    scenario_vms.add(n)
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", args.template],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    check("suspend died: up", wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 30), vms(A).get(n))
    v = vms(A)[n]
    fault(A, "suspend_stall", 10000)
    os.kill(p.pid, signal.SIGTERM)
    d = os.path.join(A.state, "suspended", n)
    check("suspend died: published", wait_for(lambda: os.path.exists(os.path.join(d, "manifest.json")), 30), d)
    os.kill(v["firecracker"], signal.SIGKILL)
    try:
        code = p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        code = None
    fault(A, "suspend_stall", 0)
    check("suspend died: exit status 124", code == 124, code)
    failed = vms(A).get(n, {})
    check("suspend died: ls shows it failed, no suspended vm", failed.get("state") == "failed" and not os.path.exists(d), (failed, os.path.exists(d)))
    check("suspend died: address withdrawn", not addr(A, v["ip"]).get("holder") and addr(A, v["ip"]).get("withdrawn"), addr(A, v["ip"]))
    ok(kill(A, n))


def suspend_debris():
    """A suspend directory that is not a suspended VM (no manifest: a revoke
    or a removal cut short; or marked STARTED by a resume killed outright) is
    debris: `ls` never lists it, and the name's next holder removes it, so
    run, suspend, resume and kill of that name work as if it were not there."""
    n = "ft-debris"
    d = os.path.join(A.state, "suspended", n)
    gone = lambda: not os.path.exists(d)

    def plant(*files):
        os.makedirs(d, exist_ok=True)
        for f in files:
            open(os.path.join(d, f), "w").write("1")

    plant("GEN", "pages")
    check("debris: not listed", n not in vms(A), vms(A).get(n))
    m = setup(n, mib=20)
    check("debris: run takes the name and removes it", gone(), os.listdir(d) if not gone() else None)
    plant("GEN", "pages")
    s = suspend(A, n)
    check("debris: suspend over it", vms(A).get(n, {}).get("state") == "suspended", (s, vms(A).get(n)))
    ok(resume_suspended(A, n))
    check("debris: resumes, md5 intact", md5(A, n) == m)
    suspend(A, n)
    os.unlink(os.path.join(d, "manifest.json"))
    check("debris: a suspended vm without its manifest is not listed", n not in vms(A), vms(A).get(n))
    r = resume_suspended(A, n)
    check("debris: resume says there is none and removes it", not r["ok"] and "no vm named" in r["error"] and gone(), r)
    plant("GEN")
    r = kill(A, n)
    check("debris: kill removes it", r["ok"] and gone(), r)
    # A resume SIGKILLed after it marked the checkpoint STARTED: consumed.
    m = setup(n, mib=20)
    ip = vms(A)[n]["ip"]
    suspend(A, n)
    open(os.path.join(d, "STARTED"), "w").close()
    check("debris: a consumed checkpoint is not listed", n not in vms(A), vms(A).get(n))
    r = run(A, n + "-ip", ip=ip)
    check("debris: nor does it hold its address", r["ok"] and vms(A).get(n + "-ip", {}).get("ip") == ip, r)
    cleanup(n + "-ip")
    r = run(A, n)
    check("debris: run of the name removes it", r["ok"] and gone(), (r, os.path.exists(d)))
    cleanup(n)


def revoked_publication():
    """A checkpoint published but not made durable (the directory's fsync
    fails) is revoked, the whole directory removed: a suspend fails with the
    VM running on and nothing left in the name's way; a checkpoint fails with
    nothing at its path. Both work once the fault is gone. If removing the
    revoked directory fails too, that is said; what is left never loads, is
    not listed, and the next suspend of the name removes it."""
    n = "ft-revoked"
    m = setup(n, mib=20)
    d = os.path.join(A.state, "suspended", n)
    pid = vm_pid(A, n)
    seen = len(log(A, n))
    fault(A, "publish_fsync", 120000)
    os.kill(pid, signal.SIGTERM)
    check("revoked suspend: reported", wait_for(lambda: "revoked it" in log(A, n)[seen:], 60), log(A, n)[-2000:])
    check("revoked suspend: the vm runs on", alive(pid) and vms(A).get(n, {}).get("state") == "running" and md5(A, n) == m, vms(A).get(n))
    check("revoked suspend: its directory is gone", not os.path.exists(d), os.listdir(d) if os.path.exists(d) else None)
    path = ckpt_path("revoked")
    r = checkpoint(A, n, path)
    check("revoked checkpoint: refused, nothing left", not r["ok"] and "revoked it" in r["error"] and not os.path.exists(path), r)
    leftovers = [f for f in os.listdir(os.path.dirname(path)) if f.startswith(".flexvm-staging-")]
    check("revoked checkpoint: no staging left", not leftovers, leftovers)
    fault(A, "revoke_cleanup", 120000)
    seen = len(log(A, n))
    os.kill(pid, signal.SIGTERM)
    check("revoked, not removed: reported", wait_for(lambda: "removing its directory failed" in log(A, n)[seen:], 60), log(A, n)[-2000:])
    check("revoked, not removed: the vm runs on", alive(pid) and vms(A).get(n, {}).get("state") == "running", vms(A).get(n))
    check("revoked, not removed: no manifest left, not listed",
          os.path.isdir(d) and not os.path.exists(os.path.join(d, "manifest.json")) and n not in [k for k, v in vms(A).items() if not v.get("pid")],
          os.listdir(d) if os.path.exists(d) else None)
    left = ckpt_path("revoked-left")
    r = checkpoint(A, n, left)
    check("revoked checkpoint, not removed: reported", not r["ok"] and "removing its directory failed" in r["error"], r)
    r = restore(A, left, name=n + "-left", ip="auto")
    check("revoked checkpoint, not removed: does not restore", not r["ok"], r)
    fault(A, "revoke_cleanup", 0)
    fault(A, "publish_fsync", 0)
    ok(checkpoint(A, n, path))
    suspend(A, n)
    check("revoked: suspends once it can, over what was left", vms(A).get(n, {}).get("state") == "suspended", vms(A).get(n))
    ok(resume_suspended(A, n))
    check("revoked: resumes, md5 intact", md5(A, n) == m)
    cleanup(n)


def app_template():
    """A template whose app floods its log past the guest's 1 MiB ring, then
    prints numbered lines (built from --image, cached in IMAGE_CACHE if set)."""
    name = os.environ.get("APP_TEMPLATE")
    if name:
        return name
    name = args.template + "-applog"
    templates = os.environ.get("FLEXVM_TEMPLATES") or os.path.join(os.path.abspath(args.artifacts), "templates")
    if not os.path.isdir(os.path.join(templates, name)):
        cmd = ["sh", "-c", "head -c 8000000 /dev/zero | tr '\\0' x; echo; i=0; while :; do echo applog-$i; i=$((i+1)); sleep 0.05; done"]
        cache = ["--image-cache", os.environ["IMAGE_CACHE"]] if os.environ.get("IMAGE_CACHE") else []
        code, out, err = cli(A, "template", name, "--image", args.image, *cache, "--vcpus", "2", "--max", "2048", "--cmd", json.dumps(cmd), timeout=600)
        assert code == 0, err or out
    return name


def app_lines(text):
    return [int(x) for x in re.findall(r"^applog-(\d+)$", text, re.M)]


def app_log():
    """An app's output is never repeated in its VM's log across a suspend and
    resume, or a checkpoint --stop and restore (the offset in the guest's log
    ring is saved with the checkpoint), nor after the host's reader fell
    behind the ring (it goes on from where the ring does); a fork restored
    from a running VM's checkpoint goes on from the pause."""
    n = "ft-applog"
    tpl = app_template()
    clear_log(A, n)
    clear_log(B, n)
    ok(run(A, n, template=tpl))
    upto = lambda k: wait_for(lambda: max(app_lines(log(A, n)), default=-1) >= k, 60)
    check("app log: printing", upto(20), log(A, n)[-500:])
    suspend(A, n)
    ok(resume_suspended(A, n))
    last = max(app_lines(log(A, n)))
    check("app log: printing after a resume", upto(last + 20), log(A, n)[-500:])
    path = ckpt_path("applog-stop")
    ok(checkpoint(A, n, path, stop=True))
    ok(restore(A, path, name=n))  # without --name its output goes to restore-PID.log
    last = max(app_lines(log(A, n)))
    check("app log: printing after a restore", upto(last + 20), log(A, n)[-500:])
    text = log(A, n)
    lines = app_lines(text)
    dups = sorted({x for x in lines if lines.count(x) > 1})
    check("app log: no line printed twice", not dups, dups[:20])
    missing = sorted(set(range(min(lines), max(lines) + 1)) - set(lines))
    check("app log: none lost", min(lines) == 0 and not missing, (min(lines), missing[:20]))
    check("app log: the flood printed once", text.count("x" * 1000) <= 8000000 // 1000 + 1 and "x" * 1000 in text)
    print(f"app log: {len(lines)} lines; reader fell behind: {'bytes of app output lost' in text}")
    # A fork of a running VM goes on from the pause: nothing from before it.
    path = ckpt_path("applog-cow")
    ok(checkpoint(A, n, path))
    fork = n + "-fork"
    clear_log(A, fork)
    ok(restore(A, path, name=fork, ip="auto"))
    check("app log: the fork prints", wait_for(lambda: app_lines(log(A, fork)), 30), log(A, fork)[-500:])
    first = min(app_lines(log(A, fork)))
    check("app log: the fork starts at the pause", first >= last and "x" * 1000 not in log(A, fork), (first, last))
    cleanup(fork)
    # Migrated, the target goes on where the source stopped.
    ok(migrate(A, n, B))
    wait_released(B, n)
    last = max(app_lines(log(A, n)))
    check("app log: printing after a migration", wait_for(lambda: max(app_lines(log(B, n)), default=-1) >= last + 20, 60), log(B, n)[-500:])
    lines = app_lines(log(A, n)) + app_lines(log(B, n))
    dups = sorted({x for x in lines if lines.count(x) > 1})
    check("app log: no line printed twice across the migration", not dups, dups[:20])
    missing = sorted(set(range(min(lines), max(lines) + 1)) - set(lines))
    check("app log: none lost across the migration", not missing, missing[:20])
    cleanup(n)


def no_evict(scenario):
    """Runs a scenario that grows guests on purpose with pressure eviction
    off on both hosts: how much the host has free must not move its VMs."""
    def run_it():
        for h in (A, B):
            fault(h, "no_evict", 3_600_000)
        try:
            scenario()
        finally:
            for h in (A, B):
                fault(h, "no_evict", 0)
    run_it.__doc__ = scenario.__doc__
    return run_it


def source_unpublished():
    """A released record stays while its source process lives, whatever the
    source's registry says: with its state never published (still `running`)
    and the target's status answers held back, garbage collection on the
    target (a VM starting there) keeps the record, and the source, once it
    hears `released`, goes; one copy runs."""
    n = "ft-unpublished"
    m = setup(n, mib=200)
    migs = lambda: os.listdir(os.path.join(B.state, "migs"))
    fault(A, "publish", 60000)
    fault(B, "status", 60000)
    ok(migrate(A, n, B))
    check("unpublished: the source's registry still says running", vms(A).get(n, {}).get("state") == "running", vms(A).get(n))
    check("unpublished: released on the target", wait_for(lambda: vms(B).get(n, {}).get("background_pull_ms") is not None, 30), vms(B).get(n))
    before = migs()
    setup("ft-unpublished-gc", host=B, mib=1)
    time.sleep(2)
    check("unpublished: garbage collection kept the record", migs() == before and before, (before, migs()))
    fault(A, "publish", 0)
    fault(B, "status", 0)
    check("unpublished: the source let go", wait_for(lambda: n not in vms(A), 30), vms(A).get(n))
    check("unpublished: one copy, on B", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    check("unpublished: the record goes once the source is done", wait_for(lambda: not migs(), 10), migs())
    cleanup(n)
    cleanup("ft-unpublished-gc")


def source_killed_basic():
    """A target whose source was killed after the release (no `done` ever
    comes) forgets the record once the source's listener says no such source
    is left: `basic` after `source_killed`, on the same state, finds none."""
    source_killed()
    basic()


# --- what a unit's cgroup and garbage collection leave alone, and what they take ---

def cgroup_of(pid):
    try:
        return open(f"/proc/{pid}/cgroup").read().strip().split("::", 1)[-1]
    except OSError:
        return None


def in_cgroup(cg):
    """A preexec_fn: the child joins cgroup `cg` (as a unit's processes are)."""
    return lambda: open(os.path.join(cg, "cgroup.procs"), "w").write("0")


def standby_pids(host, t):
    d = os.path.join(host.run, "standby", t)
    pids = []
    for f in os.listdir(d) if os.path.isdir(d) else []:
        if f.endswith(".lock"):
            try:
                pids.append(json.load(open(os.path.join(d, f)))["pid"])
            except (OSError, ValueError, KeyError):
                pass
    return [p for p in pids if alive(p)]


def unit_restart():
    """A systemd unit restarted with KillMode=control-group, emulated: B's
    listener, a `run -d` and a `standby` started from the unit's cgroup, and
    everything in that cgroup killed (cgroup.kill). The VM that migrated in
    through the listener, the detached VM and the standby are each in a
    cgroup of their own (flexvm/vm-PID-START), so they run on; a new listener
    takes them back."""
    t, n, d = args.template, "ft-unit-in", "ft-unit-d"
    unit = f"/sys/fs/cgroup/{args.prefix}-unit-{os.getpid()}"
    if not os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
        print("SKIP unit restart: no cgroup2 hierarchy")
        return
    os.mkdir(unit)
    scenario_vms.update([n, d])
    try:
        stop_listener(B)
        lg = open(os.path.join(B.run, "listen.log"), "a")
        listeners[B.addr] = subprocess.Popen(
            [BIN, "--state", B.state, "--run", B.run, "listen", B.addr, "--peer", A.addr, "--vm-ips", B.ips,
             "--reserve", "512", "--prefix", args.prefix], stdout=lg, stderr=lg, env=ENV, preexec_fn=in_cgroup(unit))
        hp = B.addr.rsplit(":", 1)
        up = lambda: subprocess.run(["bash", "-c", f"exec 3<>/dev/tcp/{hp[0]}/{hp[1]}"], capture_output=True).returncode == 0
        check("unit restart: listener up in the unit", wait_for(up, 10) and cgroup_of(listeners[B.addr].pid) == unit[len("/sys/fs/cgroup"):])
        m = setup(n, mib=50)
        ok(migrate(A, n, B))
        check("unit restart: migrated in", wait_for(lambda: where(n) == {B: "running"}, 60), where(n))
        r = subprocess.run([BIN, "--state", B.state, "--run", B.run, "run", d, "--template", t, "-d"], capture_output=True,
                           text=True, timeout=120, env=ENV, preexec_fn=in_cgroup(unit))
        check("unit restart: run -d from the unit", r.returncode == 0, r.stderr)
        try:
            r = subprocess.run([BIN, "--state", B.state, "--run", B.run, "standby", "--template", t, "1"], capture_output=True,
                               text=True, timeout=120, env=ENV, preexec_fn=in_cgroup(unit))
            check("unit restart: standby from the unit", r.returncode == 0, r.stderr)
            sbs = standby_pids(B, t)
            pids = {n: vm_pid(B, n), d: vm_pid(B, d), "standby": sbs[0] if sbs else None}
            cgs = {k: cgroup_of(p) for k, p in pids.items()}
            check("unit restart: each in a cgroup of its own", all((cg or "").startswith(f"/flexvm/vm-{pids[k]}-") for k, cg in cgs.items()), cgs)
            open(os.path.join(unit, "cgroup.kill"), "w").write("1")
            listeners.pop(B.addr).wait(timeout=10)
            time.sleep(1)
            check("unit restart: all of them run on", all(p and alive(p) for p in pids.values()), pids)
            check("unit restart: the arrival intact", where(n) == {B: "running"} and md5(B, n) == m, where(n))
            check("unit restart: the detached vm answers", sh(B, d, "echo hi") == (0, "hi"))
            start_listener(B)
            ok(migrate(B, n, A))
            check("unit restart: a new listener serves it", wait_for(lambda: where(n) == {A: "running"}, 60) and md5(A, n) == m, where(n))
            ok(kill(B, d))
            swept = lambda: ok(cli_json(B, "debug", "gc")) is None and not os.path.exists(f"/sys/fs/cgroup{cgs[d]}")
            check("unit restart: an empty cgroup is swept", wait_for(swept, 10), cgs[d])
            check("unit restart: a populated one is kept", os.path.exists(f"/sys/fs/cgroup{cgs['standby']}"), cgs["standby"])
        finally:
            cli_json(B, "standby", "--template", t, "0")
            wait_for(lambda: not standby_pids(B, t), 30)
    finally:
        if B.addr not in listeners:
            start_listener(B)
        cleanup(n)
        cleanup(d)
        wait_for(lambda: not open(os.path.join(unit, "cgroup.procs")).read().strip(), 10)
        os.rmdir(unit)


def log_cap():
    """A detached VM's log is capped by its writer: past 8 MiB, NAME.log
    becomes NAME.log.1 and a new one goes on. Every line of the output is in
    one or the other, whole and in order, up to the rotations."""
    n = "ft-logcap"
    scenario_vms.add(n)
    vd = os.path.join(A.run, "vms")
    for f in (f"{n}.log", f"{n}.log.1"):
        if os.path.exists(os.path.join(vd, f)):
            os.unlink(os.path.join(vd, f))
    lines = 1_500_000  # ~11 MiB
    r = cli_json(A, "run", n, "--template", args.template, "-d", "--", f"seq 1 {lines}")
    check("log cap: started", r["ok"], r)
    pid = r["result"]["pid"] if r["ok"] else None
    check("log cap: its command ran out", wait_for(lambda: not alive(pid), 120), pid)
    log, prev = os.path.join(vd, f"{n}.log"), os.path.join(vd, f"{n}.log.1")
    size = lambda p: os.path.getsize(p) if os.path.exists(p) else None
    check("log cap: rotated, neither past the cap", size(prev) is not None and size(prev) <= (8 << 20) + 65536 and size(log) <= 8 << 20,
          (size(prev), size(log)))
    nums = [l for l in (open(prev).read() + open(log).read()).splitlines() if l.isdigit()]
    tail = [int(x) for x in nums]
    check("log cap: whole lines, in order, through the last", tail and tail[-1] == lines and tail == list(range(tail[0], lines + 1)),
          (tail[:1], tail[-1:], len(tail)))
    # A migrated VM's log (its arrival's, published) is capped too: the lock the arrival held on it is gone. Past the
    # cap, the next write rotates it: here, what it logs as it migrates back (its end on SIGINT prints nothing). That migration is served only once its arrival is done and the log published, however long the
    # arrival's tail (held packets, route) takes, so the pad never lands before publication matters.
    m = "ft-logcap-moved"
    for f in (f"{m}.log", f"{m}.log.1"):
        if os.path.exists(os.path.join(B.run, "vms", f)):
            os.unlink(os.path.join(B.run, "vms", f))
    ok(run(A, m))
    ok(migrate(A, m, B))
    moved = os.path.join(B.run, "vms", f"{m}.log")
    pid = vm_pid(B, m)
    # migrate can return before B publishes the arrival's log (renamed over NAME.log): pad only once it is there.
    check("log cap: the arrival's log published", wait_for(lambda: os.path.exists(moved), 30), moved)
    with open(moved, "a") as f:
        f.write("pad\n" * (2 << 20))
    wait_released(B, m)
    ok(migrate(B, m, A))
    check("log cap: the migrated vm moved on", wait_for(lambda: not alive(pid), 60), pid)
    check("log cap: a migrated vm's log rotates", size(moved + ".1") is not None and size(moved + ".1") > 8 << 20 and (size(moved) or 0) < 65536,
          (size(moved), size(moved + ".1")))
    after = (open(moved + ".1", "rb").read()[-4096:] if size(moved + ".1") else b"") + (open(moved, "rb").read() if size(moved) else b"")
    check("log cap: its move logged after the padding", b"moved to" in after.split(b"pad\n")[-1], after[-300:])


def gc_debris():
    """What the sweep removes and what it keeps: old `.moved` markers, the
    log of a name with nothing left here once quiet, a SIGKILLed standby's
    socket; not a fresh log or a live VM's log."""
    vd = os.path.join(A.run, "vms")
    old = time.time() - 7200
    def made(path, t=None):
        open(path, "w").close()
        if t:
            os.utime(path, (t, t))
        return path
    n = "ft-gc-live"
    ok(run(A, n))
    os.utime(os.path.join(vd, f"{n}.log"), (old, old))
    moved, moved_new = made(os.path.join(vd, "ft-gc-moved.moved"), old), made(os.path.join(vd, "ft-gc-moved2.moved"))
    orphan, fresh = made(os.path.join(vd, "ft-gc-orphan.log"), old), made(os.path.join(vd, "ft-gc-fresh.log"))
    sbd = os.path.join(A.run, "standby", args.template)
    os.makedirs(sbd, exist_ok=True)
    sock = made(os.path.join(sbd, "deadbeef.999999990.sock"))
    ok(cli_json(A, "debug", "gc"))
    gone = lambda p: not os.path.exists(p)
    check("gc: an old .moved marker goes, a recent one stays", gone(moved) and not gone(moved_new))
    check("gc: a quiet orphan log goes, a fresh one stays", gone(orphan) and not gone(fresh))
    check("gc: a live vm's log stays", not gone(os.path.join(vd, f"{n}.log")))
    check("gc: a dead standby's socket goes", gone(sock))
    for p in (moved_new, fresh):
        if os.path.exists(p):
            os.unlink(p)
    cleanup(n)


def prefix_change():
    """The tap prefix (which garbage collection reads taps' owners by) does
    not change while a VM process runs, through `config` or `listen`; once
    none runs, it does, and back."""
    n = "ft-prefix"
    try:
        prefix = json.load(open(os.path.join(A.state, "host.json")))["prefix"]
    except (OSError, ValueError, KeyError):
        prefix = "fv"
    other = prefix[:-1] + ("y" if prefix.endswith("z") else "z")
    ok(run(A, n))
    r = cli_json(A, "config", "--prefix", other)
    check("prefix change: refused while a vm runs", not r["ok"] and "cannot change the tap prefix" in r["error"], r)
    r = cli_json(A, "listen", "127.0.0.1:1", "--prefix", other)
    check("prefix change: through listen too", not r["ok"] and "cannot change the tap prefix" in r["error"], r)
    cfg = ok(cli_json(A, "config"))
    check("prefix change: unchanged", cfg["prefix"] == prefix, cfg)
    ok(kill(A, n))
    ok(cli_json(A, "debug", "gc"))
    r = cli_json(A, "config", "--prefix", other)
    check("prefix change: made once none runs", r["ok"] and r["result"]["prefix"] == other, r)
    r = cli_json(A, "config", "--prefix", prefix)
    check("prefix change: and back", r["ok"] and r["result"]["prefix"] == prefix, r)


def arrival_log():
    """An arrival's log stays while it runs and goes once it is killed (it
    is never published as NAME.log): the sweep tells them apart by the
    lock the arrival holds on it."""
    n, ip = "ft-arrival-log", B.ips.split("-")[1].rsplit(".", 1)[0] + ".212"
    scenario_vms.add(n)
    src = source_vm()
    vd = os.path.join(B.run, "vms")
    arrivals = lambda: {f for f in os.listdir(vd) if f.startswith(".incoming-")}
    before = arrivals()
    fault(B, "incoming_stall", 20000)
    res = {}
    t = threading.Thread(target=lambda: res.update(r=migrate_in_raw(B, n, ip, src)))
    t.start()
    lock = os.path.join(vd, f"{n}.lock")
    wait_for(lambda: os.path.exists(lock) and open(lock).read().strip(), 20)
    pid = json.load(open(lock))["pid"]
    mine = arrivals() - before
    time.sleep(6)
    ok(cli_json(B, "debug", "gc"))
    check("arrival log: a live arrival's log stays", len(mine) == 1 and mine <= arrivals(), (mine, arrivals()))
    os.kill(pid, signal.SIGKILL)
    t.join()
    fault(B, "incoming_stall", 0)
    check("arrival log: left by the killed arrival", mine <= arrivals(), arrivals())
    check("arrival log: never published as its name's", not os.path.exists(os.path.join(vd, f"{n}.log")))
    time.sleep(6)
    ok(cli_json(B, "debug", "gc"))
    check("arrival log: swept once its arrival is dead", not (mine & arrivals()), arrivals())
    if "r" in res:
        res["r"][0].close()


def template_tap():
    """A template build SIGKILLed after making its tap (PREFIX x PID): a sweep
    removes the tap once the pid is gone (any process's periodic sweep may be
    first, so it is not looked for in between). A build tap whose pid lives
    is kept."""
    name = f"ft-tpltap-{os.getpid()}"
    tdir = os.environ.get("FLEXVM_TEMPLATES") or os.path.join(os.path.abspath(args.artifacts), "templates")
    try:
        prefix = json.load(open(os.path.join(A.state, "host.json")))["prefix"]
    except (OSError, ValueError, KeyError):
        prefix = "fv"
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "template", name, "--vcpus", "1", "--max", "512"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    tap = f"{prefix}x{p.pid:x}"
    up = wait_for(lambda: os.path.exists(f"/sys/class/net/{tap}"), 30)
    p.kill()
    p.wait()
    check("template tap: made by the build", up, tap)
    live = f"{prefix}x{os.getpid():x}"
    subprocess.run(["ip", "tuntap", "add", "dev", live, "mode", "tap"], check=True)
    try:
        ok(cli_json(A, "debug", "gc"))
        check("template tap: swept once its build is gone", not os.path.exists(f"/sys/class/net/{tap}"))
        check("template tap: a live build's kept", os.path.exists(f"/sys/class/net/{live}"))
    finally:
        subprocess.run(["ip", "link", "del", live], capture_output=True)
        subprocess.run(["ip", "link", "del", tap], capture_output=True)
        subprocess.run(["rm", "-rf", os.path.join(tdir, f".{name}.new-{p.pid}")])


def uffd_err():
    """The pager's userfaultfd stops being pollable (POLLERR): the pager
    fails, saying why, rather than stopping silently with every vCPU left
    waiting for pages; the VM is reported failed at once, not hung."""
    n = "ft-uffd-err"
    scenario_vms.add(n)
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", args.template],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=ENV)
    check("uffd err: up", wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 30), vms(A).get(n))
    fault(A, "uffd_err", 2000)
    t = time.time()
    try:
        code = p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        code = None
    took = time.time() - t
    fault(A, "uffd_err", 0)
    check("uffd err: noticed at once, exit status 124", code == 124 and took < 3, (code, took))
    failed = vms(A).get(n, {})
    check("uffd err: ls shows it failed, saying why", failed.get("state") == "failed" and "userfaultfd" in failed.get("error", ""), failed)
    ok(kill(A, n))
    check("uffd err: kill clears it", n not in vms(A), vms(A).get(n))


SCENARIOS = dict(
    unread_output=unread_output,
    run_status=run_status,
    terminal=terminal,
    suspend_killed=suspend_killed,
    suspend_debris=suspend_debris,
    revoked_publication=revoked_publication,
    app_log=app_log,
    source_unpublished=source_unpublished,
    source_killed_basic=source_killed_basic,
    arrival_overtaken=arrival_overtaken,
    pull_died=pull_died,
    uffd_err=uffd_err,
    mem_high=no_evict(skippable(mem_high)), mem_high_migrate=no_evict(skippable(mem_high_migrate)),
    mem_high_evict=skippable(mem_high_evict), evict_grower=skippable(evict_grower), evict_no_pingpong=evict_no_pingpong, evict_skips_cmd=evict_skips_cmd, cmd_flag=cmd_flag, evict_latency=skippable(evict_latency),
    start_admission=start_admission, standby_admission=standby_admission,
    refused_admission=refused_admission, meminfo_unreadable=meminfo_unreadable,
    cow_grow=no_evict(cow_grow), plug_race=no_evict(plug_race), shrink_stall=no_evict(shrink_stall), plug_storm=no_evict(plug_storm),
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
    suspend_disk_freed=suspend_disk_freed, resume_mark_fails=resume_mark_fails, kill_source=kill_source,
    kill_refused_checkpoint=no_evict(kill_refused_checkpoint), wildcard_listen=wildcard_listen,
    forged_peer=forged_peer, restore_ip_peer=restore_ip_peer, late_withdrawal=late_withdrawal,
    unit_restart=unit_restart, log_cap=log_cap, gc_debris=gc_debris, prefix_change=prefix_change, arrival_log=arrival_log, template_tap=template_tap,
    incoming_killed=incoming_killed, start_killed=start_killed, claim_killed=claim_killed, fc_died=fc_died,
    sigkill_restart=sigkill_restart, listen_trickle=listen_trickle,
    cow_wp_race=cow_wp_race, fetch_tail_enomem=fetch_tail_enomem, fetch_enomem_stuck=fetch_enomem_stuck,
    same_host_order=same_host_order, same_host_slow_route=same_host_slow_route, same_host_flood=same_host_flood, rx_stall=rx_stall, arrival_abort_route=arrival_abort_route, arrival_killed_route=arrival_killed_route,
    handoff_superseded=handoff_superseded, suspend_cmd=suspend_cmd, fc_died_busy=fc_died_busy, pause_cmd_start=pause_cmd_start, suspend_died=suspend_died)
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
        started, before = time.time(), failures
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
            print(f"scenario {s}: {'ok' if failures == before else 'FAILED'} in {time.time() - started:.1f} s", flush=True)
finally:
    stop_listeners()
print("failures:", failures)
sys.exit(1 if failures else 0)
