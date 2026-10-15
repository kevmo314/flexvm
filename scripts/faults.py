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
import argparse, base64, json, struct, os, re, signal, socket, subprocess, sys, tempfile, threading, time, traceback

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
               help="container image of the app_log and bad_app_log scenarios' template (APP_TEMPLATE names a built one instead)")
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


def peer(host, req, timeout=30, source=None):
    """One request to `host`'s peer listener (from address `source`, if given)."""
    h, port = host.addr.rsplit(":", 1)
    with socket.create_connection((h, int(port)), timeout=timeout, source_address=source and (source, 0)) as s:
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
                         throttled=d["describe"]["throttled"], tap_dropped=d["describe"].get("tap_dropped"),
                         checkpoint_copy=d["describe"]["checkpoint_copy"], checkpoint_copy_stats=d["checkpoint_copy_stats"],
                         background_pull_ms=d["background_pull_ms"], failed=d["failed"], guest_retries=d["guest_retries"],
                         remote_left=d["remote_left"], settling=d.get("settling"))
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
          "prepare_fail", "short_incoming", "slow_preload", "bad_preload", "bad_app_log", "kill_prepared", "guest_drop", "guest_lose_reply", "ckpt_copy_wait",
          "started_fsync", "started_unmark", "start_stall", "incoming_stall", "claim_stall", "standby_lock_stall", "standby_lock_hang", "handoff_stall", "ckpt_wp_race", "ckpt_rescue_fail",
          "fetch_tail_enomem", "fetch_enomem_stuck", "pull_enomem", "publish", "no_evict", "suspend_stall", "uffd_err", "publish_fsync", "revoke_cleanup", "no_admit", "no_meminfo", "release_stall", "release_late", "no_plug", "pause_lost", "tap_backlog", "tap_backlog_stuck", "pause_unknown", "restore_unpause_fail", "resume_link_fail", "resume_partial", "repause_fail", "pause_fail", "restore_ping_slow", "readdress_fail", "no_collapse", "collapse_slow", "pages_slow", "unlend_fail", "route_stall", "suspend_slow", "owe_fail")


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


def md5(host, name, tries=1):
    """The md5 of the guest's /tmp/f or, if exec never gave one in `tries`
    tries (a second apart), what it answered instead."""
    for i in range(tries):
        code, out = sh(host, name, "md5sum /tmp/f")
        if code == 0:
            return out.split()[0]
        if i + 1 < tries:
            time.sleep(1)
    return out


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


def start_listener(h, listen=None, extra=(), peer=None, wait=True):
    """`h`'s listener, on `listen` (default: its address) with `extra` flags,
    peered with `peer` (default: the other host's address); `wait`: until it
    takes connections."""
    other = B if h is A else A
    for d in (h.state, h.run):
        os.makedirs(d, exist_ok=True)
    lg = open(os.path.join(h.run, "listen.log"), "a")
    listeners[h.addr] = subprocess.Popen(
        [BIN, "--state", h.state, "--run", h.run, "listen", listen or h.addr, "--peer", peer or other.addr, "--vm-ips", h.ips,
         "--reserve", "512", "--prefix", args.prefix, *extra], stdout=lg, stderr=lg, env=ENV)
    if not wait:
        return
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
    # Paused, waiting to learn the outcome: reconciling (#358), or gone once it has.
    check("unknown: source never resumed", w.get(A) in (None, "reconciling") and w.get(B) == "running", w)
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
    # A connection from an address that is not a peer is told why.
    if A.addr.startswith("127."):
        r = peer(A, {"op": "migration", "id": 1}, source="127.0.0.2")
        check("refused: a non-peer is told it is not one", not r["ok"] and "is not a peer of" in r.get("error", ""), r)


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
    check("target killed: the source still holds its paused copy", not r["ok"] and w.get(A) == "reconciling", (r, w or "gone everywhere"))
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


def exec_background():
    """An exec whose command leaves a background process holding its output returns once the
    shell exits (the process keeps running), and such execs never use up the guest agent's 64
    session slots; nor do interrupted ones (SIGINT stops the command), or abandoned sessions
    whose client disconnected or was killed outright."""
    n = "ft-exec-bg"
    ok(run(A, n))
    # Processes whose command line starts with `cmd` (the ^ keeps grep from counting itself).
    count = lambda cmd: sh(A, n, f"for f in /proc/[0-9]*/cmdline; do tr '\\0' ' ' <$f; echo; done | grep -c '^{cmd} ' || :")
    t = time.time()
    r = sh(A, n, "echo started; sleep 1000 &")
    took = time.time() - t
    check("exec bg: returns once the shell exits", r == (0, "started") and took < 15, (r, took))
    check("exec bg: the background process keeps running", count("sleep 1000") == (0, "1"), count("sleep 1000"))
    r = sh(A, n, "(sleep 4; echo late; echo late >&2; touch /tmp/bg-wrote) &")
    wrote = wait_for(lambda: sh(A, n, "test -e /tmp/bg-wrote") == (0, ""), 15)
    check("exec bg: a background process writing after the exec ended lives on", r == (0, "") and wrote, r)
    results = []

    def worker():
        for _ in range(7):
            results.append(sh(A, n, "sleep 1000 &"))

    workers = [threading.Thread(target=worker) for _ in range(10)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    bad = [r for r in results if r != (0, "")]
    check("exec bg: 70 more such execs all return", len(results) == 70 and not bad, bad[:3])
    check("exec bg: execs still start after them", sh(A, n, "echo hi") == (0, "hi"))
    interrupted = []
    for _ in range(70):
        p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "exec", n, "echo ready; sleep 1001; echo after"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV)
        line = p.stdout.readline().strip()
        p.send_signal(signal.SIGINT)
        try:
            _, err = p.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
            _, err = p.communicate()
        interrupted.append((line, p.returncode, err.strip()[-200:]))
    bad = [r for r in interrupted if r[:2] != ("ready", 130) or r[2]]
    check("exec bg: 70 interrupted execs end at once with 130", not bad, bad[:3])
    stopped = wait_for(lambda: count("sleep 1001") == (0, "0"), 10)
    check("exec bg: an interrupted exec's command is stopped", stopped, count("sleep 1001"))
    check("exec bg: execs still start after the interrupted ones", sh(A, n, "echo hi") == (0, "hi"))
    # `flexvm exec VM yes | head -n1`: once head exits, the CLI's stdout is broken; it must still
    # close the session, or `yes` runs on holding a slot and 64 of these use them all up.
    piped = []
    for _ in range(70):
        p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "exec", n, "yes"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV)
        head = subprocess.Popen(["head", "-n1"], stdin=p.stdout, stdout=subprocess.PIPE, text=True)
        p.stdout.close()
        out = head.communicate(timeout=30)[0].strip()
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            out = "hung"
        piped.append(out)
    bad = [o for o in piped if o != "y"]
    check("exec bg: 70 execs piped into head -n1 end", not bad, bad[:3])
    stopped = wait_for(lambda: count("yes") == (0, "0"), 10)
    check("exec bg: a piped exec's command is stopped once its stdout breaks", stopped, count("yes"))
    check("exec bg: execs still start after the piped ones", sh(A, n, "echo hi") == (0, "hi"))
    knob = "/run/flexvm-test-abandoned-running-secs"
    check("exec bg: the abandoned-session wait is shortened", sh(A, n, f"echo 3 > {knob}") == (0, ""))
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(30)
        s.connect(os.path.join(A.run, "vms", f"{n}.sock"))
        s.sendall((json.dumps({"op": "exec", "session": os.urandom(16).hex(), "action": "start", "cmd": "echo ready; sleep 1002"}) + "\n").encode())
        buf = b""
        while b"ready" not in buf:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    check("exec bg: a resumable exec started", b"ready" in buf, buf[-200:])
    # The guest's sweeper reads the knob only between its sweeps, which come a minute apart without it.
    stopped = wait_for(lambda: count("sleep 1002") == (0, "0"), 90)
    check("exec bg: a disconnected exec's command is reclaimed", stopped, count("sleep 1002"))
    # A client killed outright (SIGKILL: no close) leaves its command running. Once the client has been
    # gone long enough (ten minutes; 3 s through the agent's test knob), the guest stops the command and
    # frees its slot, so 70 of these never use up the 64.
    killed = []

    # As `timeout -s KILL 2 flexvm exec ...`, whose own exit status differs between coreutils versions.
    def killer():
        for _ in range(7):
            p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "exec", n, "sleep infinity"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=ENV)
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()
            killed.append((p.wait(), p.stderr.read().strip()[-200:]))

    killers = [threading.Thread(target=killer) for _ in range(10)]
    for k in killers:
        k.start()
    for k in killers:
        k.join()
    # Killed (-9), so it ran until then; "too many sessions" would end it at once.
    bad = [k for k in killed if k != (-signal.SIGKILL, "")]
    check("exec bg: 70 execs killed outright all ran until killed", len(killed) == 70 and not bad, bad[:3])
    check("exec bg: execs still start after them", sh(A, n, "echo hi") == (0, "hi"))
    stopped = wait_for(lambda: count("sleep infinity") == (0, "0"), 90)
    check("exec bg: an abandoned exec's command is stopped", stopped, count("sleep infinity"))
    # Only time the guest ran counts towards that wait: across a plain pause the TSC, and so the
    # guest's monotonic clock, runs on, but a CLI keeps retrying through a pause of any length. A
    # client gone just before a pause longer than the wait still reattaches after the resume (with
    # the knob set, a sweep comes every second, so right after the resume too).
    check("exec bg: the abandoned-session wait is set to 8 s", sh(A, n, f"echo 8 > {knob}") == (0, ""))
    sid = os.urandom(16).hex()
    sock = os.path.join(A.run, "vms", f"{n}.sock")

    def session(req, until):
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(30)
            s.connect(sock)
            s.sendall((json.dumps({"op": "exec", "session": sid, **req}) + "\n").encode())
            buf = b""
            while until not in buf:
                d = s.recv(65536)
                if not d:
                    break
                buf += d
            return buf

    started = session({"action": "start", "cmd": "echo ready; sleep 8; echo done"}, b"ready")
    check("exec bg: a session started, then its client left", b"ready" in started, started[-200:])
    # Heartbeats find the client gone within about 2 s.
    time.sleep(4)
    uptime = lambda: float(sh(A, n, "cut -d' ' -f1 /proc/uptime")[1])
    before = uptime()
    check("exec bg: paused", pause(A, n))
    time.sleep(20)
    resume(A, n)
    counted = uptime() - before
    check("exec bg: the guest's clock counted the pause", counted >= 20, counted)
    out = session({"action": "attach", "offset": 0}, b"done")
    check("exec bg: a session whose client left just before a long pause reattaches after it", b"done" in out, out[-200:])
    sh(A, n, f"rm -f {knob}")
    cleanup(n)


def exec_pause_grace():
    """#388: output waits 30 s for a dropped client, counting only time the guest ran. A command whose
    output overflows its session's ring, whose client left just before a pause longer than that, loses
    nothing: once resumed, it still waits, and the client that reattaches gets every byte."""
    n = "ft-exec-grace"
    ok(run(A, n))
    sid, lines = os.urandom(16).hex(), 3_000_000
    sock = os.path.join(A.run, "vms", f"{n}.sock")

    def attach(req, until_ready=False):
        """The frames of one attachment, as [(kind, payload)]: to its end, or to the "ready" output."""
        frames = []
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(30)
            s.connect(sock)
            s.sendall((json.dumps({"op": "exec", "session": sid, **req}) + "\n").encode())
            f = s.makefile("rb")
            reply = json.loads(f.readline() or b"{}")
            assert reply.get("ok"), reply
            while (head := f.read(5)) and len(head) == 5:
                kind, size = struct.unpack("<BI", head)
                frames.append((kind, f.read(size)))
                if kind in (3, 5) or until_ready and kind == 1 and b"ready" in frames[-1][1]:
                    break
        return frames

    def output(frames):
        """(offset after the contiguous stdout, its bytes, exit code or None, offsets that did not follow on)."""
        at, data, code, gaps = None, [], None, []
        for kind, p in frames:
            if kind in (1, 2):
                off = struct.unpack("<Q", p[:8])[0]
                if at is not None and off != at:
                    gaps.append((at, off))
                at = off + len(p) - 8
                data.append(p[8:])
            elif kind == 3:
                code = struct.unpack("<i", p[8:12])[0]
            elif kind == 5:
                gaps.append(("lost", struct.unpack("<Q", p)[0]))
        return at, b"".join(data), code, gaps

    first = attach({"action": "start", "cmd": f"echo ready; sleep 5; seq 1 {lines}"}, until_ready=True)
    offset, head, _, _ = output(first)
    check("exec grace: a session started, then its client left", head == b"ready\n" and offset == 6, first[-3:])
    # The guest finds the client gone within about 2 s; then seq fills half the ring and waits.
    time.sleep(8)
    seqs = lambda: sh(A, n, "for f in /proc/[0-9]*/comm; do cat $f; done 2>/dev/null | grep -cx seq || :")
    check("exec grace: the output waits for the client", seqs() == (0, "1"), seqs())
    check("exec grace: paused", pause(A, n))
    time.sleep(40)
    resume(A, n)
    # Past the grace on the wall clock, well within it on the guest's own: it must still be waiting.
    time.sleep(5)
    check("exec grace: still waiting after a 40 s pause", seqs() == (0, "1"), seqs())
    end, data, code, gaps = output(attach({"action": "attach", "offset": offset}))
    expected = b"".join(b"%d\n" % i for i in range(1, lines + 1))
    check("exec grace: the reattached client gets all of it, nothing lost", not gaps and data == expected,
          (gaps[:3], len(data), len(expected)))
    check("exec grace: then the exit", code == 0 and end == 6 + len(expected), (code, end))
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
           "ip": ip, "gen": gen, "rev": 0, "source": A.addr, "regions": regions}
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        d = s.recv(65536)
        if not d:
            break
        buf += d
    return s, (json.loads(buf) if buf else {"ok": False, "error": "hung up"}), mig


def spare(h, k):
    """The k-th address down from the top of h's range, which h hands out,
    clear of the low ones `run` picks first."""
    net, last = h.ips.split("-")[1].rsplit(".", 1)
    return f"{net}.{int(last) - k}"


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
    n, ip = "ft-prep-gone", spare(B, 0)
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
    n, ip = "ft-prep-trickle", spare(B, 1)
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
    r = peer(A, {"op": "route", "ip": ip, "via": gw, "gen": gen + 1, "rev": 0})
    check("abort superseded: the newer generation is taken, the source keeps the route",
          r.get("ok") and not r["result"].get("stale") and r["result"].get("local"), r)
    # The target hears of it too (its arrival does not commit then).
    peer(B, {"op": "route", "ip": ip, "via": gw, "gen": gen + 1, "rev": 0})
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


def same_host_late_handover():
    """#136: when the target lets go of its hold, packets routed to the VM
    from the switch on wait in the kernel until the hold has handed over
    what reached it just before, however late that is (`release_late` holds
    the hand-over up from 20 ms before the switch to 30 ms after it, so
    packets taken before the switch are still held when routed ones reach
    the tap): none overtakes them. (With `no_plug` armed as well, the
    scenario reorders.)"""
    udp_across_migrations("same host late handover", "ft-late", "release_late")


def same_host_flood():
    """#136: traffic that keeps arriving while the target lets go of its hold
    (10k datagrams/s, its route change made slow by `release_stall`) never
    holds the release up: it ends within a bound, and nothing is lost but
    what flexvm or the guest says it dropped."""
    udp_across_migrations("same host flood", "ft-flood", "release_stall", burst=10)


def same_host_backlog():
    """#136: frames queued on the source's tap when its VM pauses went with the tap,
    uncounted. `tap_backlog` stops the source's Firecracker for 200 ms at 10k datagrams/s
    (more than the guest has buffers for), and on until frames are queued on its tap, and
    holds the address before it goes on, so each migration starts its pause with a queue
    (seen while Firecracker is still stopped, so a guest quick to take it is not missed):
    the guest takes it first, and nothing is lost that was not counted (a loaded guest can
    still fill a tap, which counts that)."""
    udp_across_migrations("same host backlog", "ft-backlog", burst=10, source_fault="tap_backlog")


def ckpt_backlog():
    """#136: a keep-running checkpoint whose VM is paused with frames still queued on its
    tap (`tap_backlog_stuck`: its Firecracker stopped until the wait for the guest to take
    them has given up) loses none of them: they are left for it to take after the resume,
    not discarded (that happens only when a VM leaves its tap for good). At 2k datagrams/s,
    so that queue and the packets held meanwhile fit the tap's together."""
    n = "ft-ckpt-backlog"
    clear_log(A, n)
    ok(run(A, n))
    ip = vm_ip(A, n)
    udp_receiver(A, n)
    stop, sent = threading.Event(), [0]

    def stream():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop.is_set():
            for _ in range(2):
                s.sendto(b"%08d\n" % sent[0], (ip, 9000))
                sent[0] += 1
            time.sleep(0.001)

    t = threading.Thread(target=stream, daemon=True)
    t.start()
    time.sleep(0.5)
    results = []
    for i in range(3):
        fault(A, "tap_backlog_stuck", 60000)
        results.append(checkpoint(A, n, ckpt_path(f"{n}-{i}")))
        fault(A, "tap_backlog_stuck", 0)
        time.sleep(0.3)
    stop.set()
    t.join(10)
    time.sleep(0.5)
    check("ckpt backlog: checkpoints written, still running", all(r["ok"] for r in results) and where(n) == {A: "running"}, (results, where(n)))
    code, out = sh(A, n, "cat /tmp/udp")
    got = set(int(x) for x in out.split()) if code == 0 else set()
    missing = sorted(set(range(sent[0])) - got)
    vm_log = log(A, n)
    check("ckpt backlog: no udp datagram lost", not missing,
          (sent[0], len(missing), missing[:5], [(r.get("result") or {}).get("held_packets") for r in results], vms(A).get(n, {}).get("tap_dropped")))
    check("ckpt backlog: each pause came with a queue on its tap, which the wait gave up on",
          vm_log.count("injected fault: stopping firecracker") == 3 and vm_log.count("frames still queued on its tap") == 3,
          [l for l in vm_log.splitlines() if "tap" in l][-8:])
    check("ckpt backlog: nothing discarded from its tap", "dropped" not in vm_log, [l for l in vm_log.splitlines() if "dropped" in l])
    cleanup(n)


def ckpt_paused_backlog():
    """A paused VM's checkpoint (#207): its Firecracker reads nothing from the tap while paused, so frames sent to it
    stay queued, and the drain does not wait for them (#219); the checkpoint returns it to paused with them still there,
    and a kill afterwards counts them as dropped rather than forgetting them."""
    n, path = "ft-ckpt-pbacklog", ckpt_path("ft-ckpt-pbacklog")
    rm_ckpt(path)
    clear_log(A, n)
    ok(run(A, n))
    ip = vm_ip(A, n)
    check("paused backlog: paused", pause(A, n), vms(A)[n])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(100):
        s.sendto(b"%08d\n" % i, (ip, 9000))
    s.close()
    time.sleep(0.2)
    r = checkpoint(A, n, path)
    check("paused backlog: checkpoint written, still paused", r["ok"] and r["result"]["state"] == "paused" and vms(A)[n]["state"] == "paused", (r, vms(A).get(n)))
    check("paused backlog: the drain did not wait for its tap's queue", "frames still queued on its tap, which its paused guest does not take" in log(A, n), log(A, n)[-2000:])
    ok(kill(A, n))
    left = re.compile(r"dropped (\d+) frames still queued on its tap when it left")
    found = wait_for(lambda: left.search(log(A, n)), 10)
    check("paused backlog: the kill counts what was left on its tap", found and int(left.search(log(A, n)).group(1)) > 0,
          [l for l in log(A, n).splitlines() if "tap" in l][-6:])
    rm_ckpt(path)
    cleanup(n)


def udp_receiver(host, n):
    """Starts socat in the guest appending what UDP port 9000 receives to /tmp/udp (its socket
    buffer large enough for any burst of held packets), and waits until the port is bound:
    a datagram sent before would be dropped by the guest (NoPorts)."""
    code, out = sh(host, n, "echo 16777216 > /proc/sys/net/core/rmem_max; "
                   "setsid socat -u UDP-RECV:9000,rcvbuf=16777216 OPEN:/tmp/udp,creat,append >/dev/null 2>&1 < /dev/null & "
                   "for i in $(seq 200); do grep -qs ':2328 ' /proc/net/udp /proc/net/udp6 && exit 0; sleep 0.05; done; exit 1")
    assert code == 0, f"socat did not bind UDP port 9000 in the guest: {out}"


def udp_across_migrations(label, n, target_fault=None, burst=1, source_fault=None):
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
    held, at, took, logs = [], [], [], []
    hops = ((A, B), (B, A), (A, B))
    for i, (src, dst) in enumerate(hops):
        if target_fault:
            fault(dst, target_fault, 60000)
        if source_fault:
            fault(src, source_fault, 60000)
        at.append(sent[0])
        r = migrate(src, n, dst)
        if source_fault:
            fault(src, source_fault, 0)
        held.append((r.get("result") or {}).get("held") or r.get("error"))
        wait_released(dst, n, src)
        # The source's log once its process is gone (what it dropped as it left is in it),
        # before the VM arrives there again and starts a new one (each host's last log is
        # read at the end).
        src_log = log(src, n)
        if any(d is src for _, d in hops[i + 1:]):
            logs.append(src_log)
        if source_fault:
            took.append([l for l in src_log.splitlines() if "took what was queued on its tap" in l])
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
    dropped["earlier sources"] = [l for t in logs for l in t.splitlines() if "dropped" in l or "dropping" in l]
    if burst == 1:
        check(f"{label}: no udp datagram lost", not missing, detail)
        late = [got[max(0, i - 3):i + 12] for i, (a, b) in enumerate(zip(got, got[1:])) if b <= a]
        check(f"{label}: none reordered", not late, late[:10])
        for h in dropped:
            # A tap's own drops are no held packets; one of the stream's would be missing above.
            held_drops = [l for l in dropped[h] if "its tap dropped" not in l]
            check(f"{label}: no held packets dropped on {h}", not held_drops, held_drops[-3:])
    else:
        # Overload may drop, but only what is counted: by the holds, the guest's socket or a tap.
        said = sum(int(m) for ls in dropped.values() for l in ls for m in re.findall(r"dropped (\d+)", l))
        said += int(guest.get("RcvbufErrors", 0)) if isinstance(guest, dict) else 0
        # Or by its tap, full (a guest not keeping up), beyond what was reported with injected
        # packets: the VM logs it as it leaves a tap, so only the last one's is asked for here.
        said += vms(B).get(n, {}).get("tap_dropped") or 0
        diag = {}
        if len(missing) > said:
            diag = rx_state(B, n)
            diag["lines"] = sh(B, n, "wc -l < /tmp/udp; cat /proc/net/softnet_stat")[1]
        check(f"{label}: nothing lost that was not counted", len(missing) <= said, (detail, dropped, diag))
        if source_fault:
            check(f"{label}: each source paused with a queue on its tap, which its guest took first", all(len(t) == 1 for t in took), took)
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
    r = peer(B, {"op": "route", "ip": ip, "via": gw, "gen": gen + 1, "rev": 0})
    check("handoff superseded: the newer generation is taken", r.get("ok") and not r["result"].get("stale"), r)
    check("handoff superseded: the late handoff says it left the address alone",
          wait_for(lambda: "went to a newer vm" in log(B, n), 10), log(B, n)[-300:])
    fault(B, "handoff_stall", 0)
    time.sleep(0.5)
    check("handoff superseded: the address routes to the newer vm's host", f"via {gw}" in peer_route(ip), peer_route(ip))
    kill(B, n)
    forget_peer_route(ip, gen + 1)


def delayed_announce():
    """#256: the source's announcement of a VM that reaches a peer only after
    its migration committed (held up in B's listener by `route_stall`; B
    stands in for a third peer, which the two hosts here leave none for) is
    an older revision of the same generation: stale, it routes nothing back
    to the source. The destination's announcement is taken by the source's host."""
    n = "ft-delayed-announce"
    fault(B, "route_stall", 60000)
    ok(run(A, n))
    v = vms(A)[n]
    ip, gen = v["ip"], v["gen"]
    check("delayed announce: B holds up A's announcement", wait_for(lambda: conns(B) == 1, 10), conns(B))
    r = migrate(A, n, B)
    check("delayed announce: migrated", r["ok"] and where(n).get(B) == "running", (r, where(n)))
    wait_released(B, n)
    check("delayed announce: B took the next revision", addr(B, ip).get("rev") == 1, addr(B, ip))
    check("delayed announce: A heard of it", wait_for(lambda: addr(A, ip).get("rev") == 1, 10), addr(A, ip))
    fault(B, "route_stall", 0)
    check("delayed announce: B handled it", wait_for(lambda: conns(B) == 0, 10), conns(B))
    a = addr(B, ip)
    check("delayed announce: A's late one is stale, the route stays off A",
          a.get("seen") == gen and a.get("rev") == 1 and a.get("via") is None, a)
    check("delayed announce: running on B", where(n) == {B: "running"}, where(n))
    kill(B, n)


def announce_arp_timer():
    """#311: a VM's second gratuitous ARP goes out about 200 ms after its first,
    on a timer of its own: a peer that holds up the announcement (B, with
    `route_stall`; `tell`'s retry would keep it about 5 s) does not delay it.
    A's announce device is a dummy link, the ARPs captured on it."""
    n, dev = "ft-arp-timer", f"garp{A.addr.rsplit(':', 1)[1]}"
    was = ok(cli_json(A, "config")).get("announce_dev") or ""
    arps, cap = [], socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    subprocess.run(["ip", "link", "del", dev], capture_output=True)
    subprocess.run(["ip", "link", "add", dev, "up", "type", "dummy"], check=True)
    try:
        cap.bind((dev, 0))
        cap.settimeout(0.2)
        code, out, err = cli(A, "config", "--announce-dev", dev)
        assert code == 0, err
        fault(B, "route_stall", 60000)
        ok(run(A, n))
        ip = socket.inet_aton(vms(A)[n]["ip"])
        end = time.time() + 10
        while len(arps) < 2 and time.time() < end:
            try:
                f = cap.recv(64)
            except socket.timeout:
                continue
            if f[12:14] == b"\x08\x06" and f[38:42] == ip:
                arps.append(time.monotonic())
        check("announce arp timer: B holds up A's announcement", conns(B) >= 1, conns(B))
    finally:
        # Each step whatever the one before did (B gone, a CLI failing): the host as found.
        try:
            fault(B, "route_stall", 0)
        finally:
            try:
                cli(A, "config", "--announce-dev", was)
            finally:
                cap.close()
                subprocess.run(["ip", "link", "del", dev], capture_output=True)
    check("announce arp timer: both ARPs went out", len(arps) == 2, arps)
    if len(arps) == 2:
        gap = arps[1] - arps[0]
        check("announce arp timer: the second within 1 s of the first", 0.15 < gap < 1, f"{gap:.2f} s")
    check("announce arp timer: B handled it", wait_for(lambda: conns(B) == 0, 10), conns(B))
    kill(A, n)


def prepare_fail_announce():
    """#256: a target that claims the next revision and then fails to prepare
    never outranks its running source: the source's announcement, held up in
    B's listener until after, is still taken."""
    n = "ft-prep-announce"
    fault(B, "route_stall", 60000)
    ok(run(A, n))
    ip = vms(A)[n]["ip"]
    check("prepare fail announce: B holds up A's announcement", wait_for(lambda: conns(B) == 1, 10), conns(B))
    fault(B, "prepare_fail", 10000)
    r = migrate(A, n, B)
    fault(B, "prepare_fail", 0)
    check("prepare fail announce: migrate refused", not r["ok"] and "injected fault" in r["error"], r)
    fault(B, "route_stall", 0)
    check("prepare fail announce: B handled it", wait_for(lambda: conns(B) == 0, 10), conns(B))
    a = addr(B, ip)
    check("prepare fail announce: taken, routed to A", a.get("via") == "127.0.0.1" and a.get("rev") == 0 and not a.get("holder"), a)
    check("prepare fail announce: running on A", where(n) == {A: "running"}, where(n))
    kill(A, n)


def reconcile_announce():
    """#256: a source that never heard its target commit (ack lost, status
    unavailable) runs again once the target dies mid-pull (`pages_slow` keeps
    it pulling), and announces itself past the revision the target took."""
    n = "ft-reconcile-announce"
    setup(n, mib=100)
    ip = vms(A)[n]["ip"]
    fault(A, "pages_slow", 120000)
    # Long enough for the slow pages the commit waits on.
    fault(B, "lost_ack", 30000)
    fault(B, "status", 30000)
    r = migrate(A, n, B)
    fault(B, "lost_ack", 0)
    check("reconcile announce: outcome unknown, the source paused", not r["ok"] and vms(A).get(n, {}).get("state") == "reconciling", (r, where(n)))
    check("reconcile announce: B committed the next revision", addr(B, ip).get("rev") == 1, addr(B, ip))
    os.kill(json.load(open(os.path.join(B.run, "vms", f"{n}.lock")))["pid"], signal.SIGKILL)
    fault(B, "status", 0)
    check("reconcile announce: runs on A again", wait_for(lambda: where(n) == {A: "running"}, 60), where(n))
    fault(A, "pages_slow", 0)
    check("reconcile announce: announced past B's revision",
          wait_for(lambda: addr(B, ip).get("rev") == 2 and addr(B, ip).get("via") == "127.0.0.1", 10), addr(B, ip))
    kill(A, n)


def owed(host):
    """Migration ids whose outcome `host` still owes (a source killed before it knew)."""
    d = os.path.join(host.state, "owed")
    return sorted(f for f in os.listdir(d) if f.isdigit()) if os.path.isdir(d) else []


def reconcile_kill():
    """#350, #358: SIGINT, SIGQUIT and flexvm kill end a source that never heard its target's
    outcome (ack lost, status unavailable) within seconds, as they do a VM
    anywhere else. The target may be running the VM, so nothing is withdrawn:
    the address stays lent, never handed out on the source's host, until the
    target says. Pulling from the dead source, the target's copy ends; its
    record reads aborted, and gc on the source's host then withdraws the
    generation and frees the address. A target that already had every page
    keeps running with it: told `done`, it keeps the loan until it is killed
    there, and only then does the address run again on the source's host."""
    def unknown_then_kill(n, sig, slow, refuse_first=False, use_cli=False):
        what = f"reconcile kill ({n})"
        m = setup(n, mib=100)
        ip, pid = vms(A)[n]["ip"], vm_pid(A, n)
        gen = addr(A, ip)["seen"]
        if slow:
            fault(A, "pages_slow", 120000)
        fault(B, "lost_ack", 30000)
        fault(B, "status", 30000)
        r = migrate(A, n, B)
        fault(B, "lost_ack", 0)
        check(f"{what}: outcome unknown, the source paused", not r["ok"] and vms(A).get(n, {}).get("state") == "reconciling", (r, where(n)))
        check(f"{what}: lent while it waits", addr(A, ip).get("lent") == gen, addr(A, ip))
        if not slow:
            check(f"{what}: the target has every page", wait_for(lambda: vms(B).get(n, {}).get("background_pull_ms") is not None, 30), vms(B).get(n))
        if refuse_first:
            # Its outcome cannot be recorded as owed (`owe_fail`, a full disk, say): the kill is refused.
            fault(A, "owe_fail", 60000)
            os.kill(pid, sig)
            check(f"{what}: unrecorded, the kill is refused and the source goes on",
                  wait_for(lambda: "is not killed" in log(A, n), 10) and alive(pid) and not owed(A), (alive(pid), owed(A), log(A, n)[-400:]))
            fault(A, "owe_fail", 0)
        t = time.time()
        if use_cli:
            code, out, err = cli(A, "kill", n, timeout=10)
            check(f"{what}: flexvm kill succeeds", code == 0, (code, out, err))
        else:
            os.kill(pid, sig)
        gone = wait_for(lambda: not alive(pid), 5)
        check(f"{what}: the source exits within 5 s", gone, f"{time.time() - t:.1f} s; " + log(A, n)[-400:])
        if not gone:
            os.kill(pid, signal.SIGKILL)
            return None
        check(f"{what}: says the target may still run it", "may still be running it" in log(A, n), log(A, n)[-400:])
        a = addr(A, ip)
        check(f"{what}: still lent, not withdrawn, no holder here",
              a.get("seen") == gen and not a.get("withdrawn") and a.get("lent") == gen and not a.get("holder"), a)
        check(f"{what}: the outcome is owed", len(owed(A)) == 1, owed(A))
        r2 = run(A, n + "-again", ip=ip)
        check(f"{what}: the address is not handed out here meanwhile", not r2["ok"] and "lent" in r2["error"], r2)
        return ip, gen, m, (owed(A) or [None])[0]

    # The target still pulls when the source is killed: it cannot finish, and the outcome is aborted.
    for sig in (signal.SIGINT, signal.SIGQUIT):
        n = f"ft-reconcile-kill-{signal.Signals(sig).name.lower()}"
        got = unknown_then_kill(n, sig, True, refuse_first=sig == signal.SIGINT)
        if not got:
            continue
        ip, gen, _, mig = got
        what = f"reconcile kill ({n})"
        fault(B, "status", 0)
        fault(A, "pages_slow", 0)
        check(f"{what}: the target's copy ends", wait_for(lambda: where(n) == {}, 90), where(n))
        check(f"{what}: gc settles it: withdrawn, no longer lent",
              wait_for(lambda: cli(A, "debug", "gc")[0] == 0 and not owed(A), 30), (owed(A), addr(A, ip)))
        a, b = addr(A, ip), addr(B, ip)
        check(f"{what}: withdrawn here and at B, free", a.get("withdrawn") and a.get("lent") is None and b.get("seen") == gen and b.get("withdrawn"), (a, b))
        r2 = run(A, n + "-again", ip=ip)
        check(f"{what}: the address runs again on A, with a newer generation", r2["ok"] and addr(A, ip).get("seen", 0) > gen, (r2, addr(A, ip)))
        kill(A, n + "-again")
        kill(B, n)

    # The target is lost for good (killed, its status never available): nothing settles it, and
    # the operator reclaims the address, warned first, then with --force.
    n = "ft-reconcile-kill-lost"
    what = f"reconcile kill ({n})"
    got = unknown_then_kill(n, signal.SIGINT, True, use_cli=True)
    if got:
        ip, gen, _, mig = got
        os.kill(json.load(open(os.path.join(B.run, "vms", f"{n}.lock")))["pid"], signal.SIGKILL)
        cli(A, "debug", "gc")
        check(f"{what}: unsettled while the target cannot say", len(owed(A)) == 1 and addr(A, ip).get("lent") == gen, (owed(A), addr(A, ip)))
        code, out, err = cli(A, "reclaim", ip)
        check(f"{what}: reclaim without --force says what it would do, and does nothing",
              code != 0 and "make sure no host runs that vm" in err and "--force" in err and len(owed(A)) == 1 and addr(A, ip).get("lent") == gen, (code, err))
        code, out, err = cli(A, "reclaim", ip, "--force")
        r = json.loads(out) if code == 0 else {}
        check(f"{what}: reclaim --force withdraws it and forgets the owed outcome, warning",
              code == 0 and r.get("withdrawn_gen") == gen and len(r.get("forgot_migrations", [])) == 1 and "WARNING" in err and not owed(A), (code, out, err))
        a = addr(A, ip)
        check(f"{what}: withdrawn here and at B, no longer lent",
              a.get("withdrawn") and a.get("lent") is None and wait_for(lambda: addr(B, ip).get("withdrawn") and addr(B, ip).get("seen") == gen, 10), (a, addr(B, ip)))
        r2 = run(A, n + "-again", ip=ip)
        check(f"{what}: the address runs again on A", r2["ok"] and addr(A, ip).get("seen", 0) > gen, (r2, addr(A, ip)))
        kill(A, n + "-again")
        # Nothing asks B about it any more (the owed record went with the reclaim): B's record of its
        # dead arrival reads aborted when asked (here, or by its own retirement), and goes then.
        fault(B, "status", 0)
        st = peer(B, {"op": "migration", "mig": int(mig)}) if mig else {}
        check(f"{what}: B's record of the lost arrival reads aborted, and goes",
              st.get("result", {}).get("outcome") == "aborted" and mig not in os.listdir(os.path.join(B.state, "migs")), (st, mig))
    fault(B, "status", 0)
    fault(A, "pages_slow", 0)
    kill(B, n)

    # A SIGINT taken while the migration still holds the operation lock (the target stalls preparing):
    # it waits, the outcome turns out unknown, and the wait ends the source all the same.
    n = "ft-reconcile-kill-waiting"
    what = f"reconcile kill ({n})"
    setup(n, mib=100)
    ip, pid = vms(A)[n]["ip"], vm_pid(A, n)
    gen = addr(A, ip)["seen"]
    fault(A, "pages_slow", 120000)
    fault(B, "incoming_stall", 2000)
    fault(B, "lost_ack", 30000)
    fault(B, "status", 30000)
    r = [None]
    th = threading.Thread(target=lambda: r.__setitem__(0, migrate(A, n, B)))
    th.start()
    lock = os.path.join(B.run, "vms", f"{n}.lock")
    wait_for(lambda: os.path.exists(lock) and open(lock).read().strip(), 20)
    os.kill(pid, signal.SIGINT)
    th.join()
    fault(B, "lost_ack", 0)
    gone = wait_for(lambda: not alive(pid), 10)
    check(f"{what}: the waiting SIGINT ends the source once the outcome is unknown", gone and len(owed(A)) == 1,
          (r[0], owed(A), log(A, n)[-400:]))
    if not gone:
        os.kill(pid, signal.SIGKILL)
    check(f"{what}: still lent meanwhile", addr(A, ip).get("lent") == gen and not addr(A, ip).get("withdrawn"), addr(A, ip))
    fault(B, "status", 0)
    fault(A, "pages_slow", 0)
    check(f"{what}: settled once the target's copy ends", wait_for(lambda: where(n) == {} and cli(A, "debug", "gc")[0] == 0 and not owed(A), 90),
          (where(n), owed(A), addr(A, ip)))
    check(f"{what}: then free", addr(A, ip).get("lent") is None and addr(A, ip).get("withdrawn"), addr(A, ip))
    kill(B, n)

    # The target already has every page (its ack lost, its status unavailable): it runs on with the address.
    n = "ft-reconcile-kill-pulled"
    what = f"reconcile kill ({n})"
    got = unknown_then_kill(n, signal.SIGINT, False)
    if not got:
        return
    ip, gen, m, mig = got
    check(f"{what}: the VM runs on at B, md5 intact", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    fault(B, "status", 0)
    check(f"{what}: gc settles it as B's", wait_for(lambda: cli(A, "debug", "gc")[0] == 0 and not owed(A), 30), owed(A))
    migs = os.path.join(B.state, "migs")
    # Its own record: B's others (an earlier case's) go by their own retirement.
    check(f"{what}: B was told done, its record gone", mig is not None and wait_for(lambda: mig not in os.listdir(migs), 10), (mig, os.listdir(migs)))
    check(f"{what}: still lent to B", addr(A, ip).get("lent") == gen and not addr(A, ip).get("withdrawn"), addr(A, ip))
    r2 = run(A, n + "-again", ip=ip)
    check(f"{what}: still not handed out here", not r2["ok"] and "lent" in r2["error"], r2)
    ok(kill(B, n))
    check(f"{what}: once killed at B, the loan is taken back", wait_for(lambda: addr(A, ip).get("lent") is None, 10), addr(A, ip))
    r2 = run(A, n + "-again", ip=ip)
    check(f"{what}: then the address runs again on A", r2["ok"] and addr(A, ip).get("seen", 0) > gen, (r2, addr(A, ip)))
    kill(A, n + "-again")


def resume_pull_lock():
    """#334: resuming an arriving VM waits for its pages (`pages_slow` keeps
    them coming) before it takes the host lock, so other operations on that
    host that need the lock (a run claiming an address) do not stall for it."""
    n, other = "ft-resume-pull-lock", "ft-resume-pull-lock-2"
    m = setup(n, mib=400)
    fault(A, "pages_slow", 120000)
    ok(migrate(A, n, B))
    arriving = lambda: (lambda v: v.get("remote_left", 0) > 0 and not v.get("failed"))(vms(B).get(n, {}))
    check("resume pull lock: caught arriving on B", arriving(), vms(B).get(n))
    check("resume pull lock: paused mid-arrival", pause(B, n), vms(B).get(n))
    signal_vm(B, n, signal.SIGCONT)
    time.sleep(1)
    t = time.time()
    r = run(B, other)
    took = time.time() - t
    check("resume pull lock: a run on B is not held up by the resume's wait", r["ok"] and took < 15, (r, f"{took:.1f}s"))
    check("resume pull lock: the resume was still waiting meanwhile", vms(B)[n]["state"] == "paused" and arriving(), vms(B).get(n))
    fault(A, "pages_slow", 0)
    wait_released(B, n)
    if not wait_for(lambda: vms(B)[n]["state"] == "running", 35):
        resume(B, n)
    check("resume pull lock: runs on B only, md5 intact", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    cleanup(n)
    cleanup(other)


def page_conns():
    """#335: a peer that knows the migration holds many page connections open
    (more than the 256 control connections a VM process takes): page
    connections have a budget of their own, the one idle longest making room,
    so a local control request is still answered, a new page connection (as
    a target's pager reconnects) is still served, and the target still
    faults pages in and finishes its pull."""
    n = "ft-page-conns"
    m = setup(n, mib=400)
    _, head = sh(A, n, "head -c 4194304 /tmp/f | md5sum")
    fault(A, "pages_slow", 120000)
    r = ok(migrate(A, n, B))
    hello = json.dumps({"op": "pages", "name": n, "mig": r["mig"]}).encode() + b"\n"
    h, port = A.addr.rsplit(":", 1)

    def page_conn():
        s = socket.create_connection((h, int(port)), timeout=10)
        s.sendall(hello)
        got = b""
        try:
            while not got.endswith(b"\n") and (d := s.recv(1)):
                got += d
        except OSError:
            pass
        return s, got

    held, answered = [], 0
    try:
        for _ in range(300):
            s, got = page_conn()
            held.append(s)
            answered += got == b'{"ok":true}\n'
        check("page conns: idle page connections opened", answered >= 200, f"{answered} of 300 answered")
        t = time.time()
        try:
            st = control(A, n, {"op": "debug", "what": "status"}, timeout=10)
        except OSError as e:
            st = {"ok": False, "error": str(e)}
        check("page conns: a local control request is answered", st.get("ok") and time.time() - t < 5, st.get("error"))
        s, got = page_conn()
        held.append(s)
        reply = b""
        if got == b'{"ok":true}\n':
            s.settimeout(10)
            s.sendall((0).to_bytes(8, "little") + (4096).to_bytes(4, "little"))
            try:
                while len(reply) < 4097 and (d := s.recv(65536)):
                    reply += d
            except OSError:
                pass
        check("page conns: a new page connection is admitted and served", len(reply) == 4097 and reply[0] == 0, (got, reply[:20]))
        # At full speed (an exec at a second per reply times out), the connections still held.
        fault(A, "pages_slow", 0)
        code, out = sh(B, n, "head -c 4194304 /tmp/f | md5sum")
        check("page conns: the target still faults pages in", code == 0 and out == head, (code, out, head))
    finally:
        for s in held:
            s.close()
    st = wait_released(B, n)
    check("page conns: migration completed, md5 intact", st["released"] is True and where(n) == {B: "running"} and md5(B, n) == m, (st, where(n)))
    cleanup(n)


def page_refusals():
    """#352: 64 page requests for a migration that is not this VM's, each
    then trickling a byte just under a second apart (a per-read timeout
    never ends their drain): each refusal ends by one deadline and holds no
    page slot, so a valid page connection still gets in and is served, and
    the migration completes."""
    n = "ft-page-refusals"
    m = setup(n)
    fault(A, "pages_slow", 120000)
    r = ok(migrate(A, n, B))
    h, port = A.addr.rsplit(":", 1)
    hello = lambda mig: json.dumps({"op": "pages", "name": n, "mig": mig}).encode() + b"\n"

    def page_conn(mig):
        s = socket.create_connection((h, int(port)), timeout=10)
        s.sendall(hello(mig))
        got = b""
        try:
            while not got.endswith(b"\n") and (d := s.recv(1)):
                got += d
        except OSError:
            pass
        return s, got

    refused, lasted, stop = [], [], threading.Event()

    def trickle():
        try:
            s, got = page_conn(r["mig"] + 1000)
        except OSError:
            return refused.append(False)
        refused.append(b"is not the source of migration" in got)
        t = time.time()
        try:
            while not stop.is_set() and time.time() - t < 20:
                s.sendall(b"x")
                time.sleep(0.9)
        except OSError:
            pass
        lasted.append(time.time() - t)
        s.close()

    threads = [threading.Thread(target=trickle) for _ in range(64)]
    for t in threads:
        t.start()
    wait_for(lambda: len(refused) == 64, 20)
    check("page refusals: all 64 told why", refused.count(True) == 64, f"{refused.count(True)} of {len(refused)}")
    s, got = page_conn(r["mig"])
    reply = b""
    try:
        if got == b'{"ok":true}\n':
            s.settimeout(10)
            s.sendall((0).to_bytes(8, "little") + (4096).to_bytes(4, "little"))
            try:
                while len(reply) < 4097 and (d := s.recv(65536)):
                    reply += d
            except OSError:
                pass
    finally:
        s.close()
    check("page refusals: a valid page connection is admitted and served", len(reply) == 4097 and reply[0] == 0, (got, reply[:20]))
    for t in threads:
        t.join(30)
    stop.set()
    # Closed by the 1 s deadline; the client learns it at its next send or two.
    check("page refusals: each trickling refusal ends by its deadline", len(lasted) == 64 and max(lasted) < 6, (len(lasted), max(lasted, default=None)))
    fault(A, "pages_slow", 0)
    st = wait_released(B, n)
    check("page refusals: migration completed, md5 intact", st["released"] is True and where(n) == {B: "running"} and md5(B, n) == m, (st, where(n)))
    cleanup(n)


def conns(host):
    """Connections `host`'s listener has yet to answer (established, or closed by the peer)."""
    port = int(host.addr.rsplit(":", 1)[1])
    rows = [r.split() for r in open("/proc/net/tcp").read().splitlines()[1:]]
    return sum(int(r[1].split(":")[1], 16) == port and r[3] in ("01", "08") for r in rows)


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
    r = peer(B, {"op": "route", "ip": ip, "via": gw, "gen": gen, "rev": 0})
    assert r.get("ok"), r
    assert f"via {gw}" in peer_route(ip), peer_route(ip)
    s, r, mig = migrate_in_raw(B, n, ip, source_vm(), gen=gen)
    assert r.get("ok"), r
    bad = os.urandom(4096)
    # A valid header (the preloaded page is a REMOTE one, as a source sends): only the vmstate is bad.
    s.sendall((json.dumps({"runs": [[0, 1, 3]], "vmstate_len": len(bad), "preload": [0], "paused": False}) + "\n").encode() + bad)
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


def bad_preload():
    """A source whose header names a preload page past guest memory (page
    u64::MAX, `bad_preload`): the target refuses the header at once, rather
    than hanging on it, and the VM runs on at the source."""
    n = "ft-bad-preload"
    m = setup(n)
    fault(A, "bad_preload", 10000)
    started = time.time()
    r = migrate(A, n, B)
    took = time.time() - started
    fault(A, "bad_preload", 0)
    check("bad preload: migrate fails", not r["ok"], r)
    check("bad preload: refused for the preload list", "preload page" in r.get("error", ""), r.get("error"))
    check("bad preload: refused promptly", took < 20, took)
    check("bad preload: running on A only", where(n) == {A: "running"}, where(n))
    check("bad preload: its loan is undone", not addr(A, vms(A)[n]["ip"]).get("lent"), addr(A, vms(A)[n]["ip"]))
    check("bad preload: md5 intact on A", md5(A, n) == m)
    r = migrate(A, n, B)
    check("bad preload: a later migration works", r["ok"] and where(n).get(B) == "running", r)
    wait_released(B, n)
    check("bad preload: md5 intact on B", md5(B, n) == m)
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


def tcp_retrans(conn):
    """A connection's retransmits and the duplicates its peer reported (DSACKs: retransmits it
    had already received, so spurious) from TCP_INFO (tcpi_total_retrans, tcpi_dsack_dups)."""
    info = conn.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 232)
    field = lambda at: int.from_bytes(info[at:at + 4], "little") if len(info) >= at + 4 else 0
    return field(100), field(216)


def guest_tcp_counters(host, name):
    """The guest's TCP RetransSegs and TCPDSACKRecv (retransmits its peers reported as duplicates)."""
    code, out = sh(host, name, "cat /proc/net/snmp /proc/net/netstat")
    assert code == 0, out
    # Each table is a line of names then a line of values, both "Tcp: ..." (or "TcpExt: ...").
    stats, lines = {}, [l.split() for l in out.splitlines()]
    for names, values in zip(lines[::2], lines[1::2]):
        stats.update(zip(names[1:], values[1:]))
    return int(stats["RetransSegs"]), int(stats.get("TCPDSACKRecv", 0))


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
    r = control(A, n, {"op": "exec", "session": os.urandom(16).hex(), "action": "start", "cmd": "echo hi"})
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


def pause_lost():
    """A pause whose answer is lost (it landed all the same): the VM process asks Firecracker which state it is in and
    records it, so a SIGCONT resumes it, instead of believing it runs while it sits paused for good."""
    n = "ft-pause-lost"
    m = setup(n)
    sock = api_sock(A, n)
    fault(A, "pause_lost", 30000)
    try:
        check("pause lost: SIGTSTP still records the pause", pause(A, n), vms(A)[n])
        check("pause lost: Firecracker is paused", fc_api(sock, "GET", "/")["state"] == "Paused", fc_api(sock, "GET", "/"))
    finally:
        fault(A, "pause_lost", 0)
    signal_vm(A, n, signal.SIGCONT)
    check("pause lost: SIGCONT resumes it", wait_for(lambda: vms(A)[n]["state"] == "running", 10), vms(A)[n])
    check("pause lost: running and intact", fc_api(sock, "GET", "/")["state"] == "Running" and md5(A, n) == m, fc_api(sock, "GET", "/"))
    # Neither the answer nor Firecracker's state can be had (#191): it stays recorded as running, but unsure, so a
    # SIGCONT still resumes it.
    for f in ("pause_lost", "pause_unknown"):
        fault(A, f, 30000)
    try:
        signal_vm(A, n, signal.SIGTSTP)
        check("pause unknown: Firecracker is paused", wait_for(lambda: fc_api(sock, "GET", "/")["state"] == "Paused", 10), fc_api(sock, "GET", "/"))
        time.sleep(0.5)
    finally:
        for f in ("pause_lost", "pause_unknown"):
            fault(A, f, 0)
    signal_vm(A, n, signal.SIGCONT)
    check("pause unknown: SIGCONT resumes it", wait_for(lambda: fc_api(sock, "GET", "/")["state"] == "Running", 10), fc_api(sock, "GET", "/"))
    check("pause unknown: running and intact", vms(A)[n]["state"] == "running" and md5(A, n) == m, vms(A)[n])
    # And a pause and resume after it work as ever.
    check("pause unknown: pauses again", pause(A, n) and fc_api(sock, "GET", "/")["state"] == "Paused", vms(A)[n])
    ok(cli_json(A, "resume", n))
    check("pause unknown: resumes again", fc_api(sock, "GET", "/")["state"] == "Running" and md5(A, n) == m, vms(A)[n])
    # A checkpoint or migration after an unknown pause asks Firecracker too (#207): refused while it cannot say, then
    # the checkpoint leaves the VM paused (not resumed) and the migration's target starts it paused.
    path = ckpt_path("ft-pause-lost")
    rm_ckpt(path)

    def unknown_pause(label):
        for f in ("pause_lost", "pause_unknown"):
            fault(A, f, 60000)
        signal_vm(A, n, signal.SIGTSTP)
        check(f"{label}: Firecracker is paused, recorded as running", wait_for(lambda: fc_api(sock, "GET", "/")["state"] == "Paused", 10)
              and vms(A)[n]["state"] == "running", (fc_api(sock, "GET", "/"), vms(A)[n]))
        time.sleep(0.5)
        fault(A, "pause_lost", 0)

    try:
        unknown_pause("unknown before a checkpoint")
        r = checkpoint(A, n, path)
        check("unknown before a checkpoint: refused while Firecracker cannot say", not r["ok"] and "ended unknown" in r["error"] and not os.path.exists(path), r)
        st = control(A, n, {"op": "debug", "what": "status"})["result"]["describe"]
        check("unknown before a checkpoint: refused before arming write tracking (#219)", st["write_tracking"] is False, st)
        r = migrate(A, n, B)
        check("unknown before a migration: refused too", not r["ok"] and "ended unknown" in r["error"] and where(n) == {A: "running"}, (r, where(n)))
        check("unknown before a migration: nothing lent", not addr(A, vms(A)[n]["ip"]).get("lent"), addr(A, vms(A)[n]["ip"]))
    finally:
        fault(A, "pause_unknown", 0)
    r = checkpoint(A, n, path)
    check("unknown before a checkpoint: it leaves the VM paused", r["ok"] and r["result"]["state"] == "paused" and vms(A)[n]["state"] == "paused"
          and fc_api(sock, "GET", "/")["state"] == "Paused", (r, vms(A)[n], fc_api(sock, "GET", "/")))
    ok(cli_json(A, "resume", n))
    check("unknown before a checkpoint: resumes after it", fc_api(sock, "GET", "/")["state"] == "Running" and md5(A, n) == m, vms(A)[n])
    try:
        unknown_pause("unknown before a migration")
    finally:
        fault(A, "pause_unknown", 0)
    r = migrate(A, n, B)
    check("unknown before a migration: migrated", r["ok"], r)
    st = wait_released(B, n)
    check("unknown before a migration: its target keeps it paused", st["released"] and where(n) == {B: "paused"}, (st, where(n)))
    ok(cli_json(B, "resume", n))
    check("unknown before a migration: resumes there, intact", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    rm_ckpt(path)
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
    pages go back through balloon free page reporting) in the background.
    The churn file takes at most half of what the guest has available (200
    MiB at most): tmpfs cannot be reclaimed, so more would have the guest's
    OOM killer take the guest's own processes, or panic it, on a template
    without hot-plugged memory (#189)."""
    # The kernel log starts empty, so guest_healthy counts only what this run logs, not the template's.
    code, out = sh(host, name, "dmesg -c >/dev/null; (while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done | socat -u - UDP:169.254.1.1:9) "
                   ">/dev/null 2>&1 < /dev/null & "
                   "c=$(awk '/MemAvailable/ { m = int($2 / 2048); print (m < 200 ? m : 200) }' /proc/meminfo); "
                   "(while :; do head -c ${c}M /dev/zero > /dev/shm/churn; rm -f /dev/shm/churn; done) "
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
    # An exec that fails (a timeout, the guest gone) is not a wrong hash: say which it was.
    got = md5(host, name, tries=3)
    if re.fullmatch(r"[0-9a-f]{32}", got):
        check(f"{label}: md5 intact", got == m, f"want {m}, got {got}")
    else:
        died = [l for l in log(host, name).splitlines() if "died" in l]
        check(f"{label}: md5 intact", False, f"md5sum gave no hash: {got!r}" + (f"; {died[-1]}" if died else ""))
    code, out = sh(host, name, "dmesg | grep -c 'Out of memory' ; true")
    check(f"{label}: no OOM kills in the guest", code == 0 and out.strip() == "0", out)


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


def resume_slow_guest():
    """A resumed suspended VM whose guest agent answers its first ping late
    (past the 2 s deadline) runs on, the delay reported; its checkpoint stays
    until all its memory is in, and is deleted then."""
    n = "ft-resume-slow"
    m = setup(n)
    suspend(A, n)
    d = os.path.join(A.state, "suspended", n)
    fault(A, "restore_ping_slow", 60000)
    r = resume_suspended(A, n)
    fault(A, "restore_ping_slow", 0)
    check("slow guest: resume succeeds", r.get("ok"), r)
    res = r.get("result", {})
    check("slow guest: the late agent is reported", res.get("guest_error") and res.get("ready_ms") is None, res)
    check("slow guest: still running", vms(A).get(n, {}).get("state") == "running", vms(A).get(n))
    check("slow guest: md5 intact", md5(A, n, tries=5) == m)
    check("slow guest: the late answer is logged", wait_for(lambda: "guest agent answered" in log(A, n), 30), log(A, n)[-2000:])
    check("slow guest: paged in", wait_for(lambda: vms(A)[n].get("pages_mib", {}).get("remote") == 0, 60), vms(A)[n])
    check("slow guest: checkpoint deleted once all is in", wait_for(lambda: not os.path.exists(d), 30), d)
    check("slow guest: deleted only once completely paged in", "paged in from" in log(A, n) and "(complete: true" in log(A, n), log(A, n)[-2000:])
    check("slow guest: still running after", vms(A).get(n, {}).get("state") == "running", vms(A).get(n))
    cleanup(n)


def resume_readdress_fail():
    """A restore at a new address whose readdress fails runs on with the
    address pending (no checkpoint meanwhile), held (--paused) or not: each
    `flexvm resume` retries it, and so does the process in the background
    until it is set."""
    n = "ft-readdr"
    m = setup(n, mib=20)
    old_ip = vms(A)[n]["ip"]
    path = ckpt_path("readdr")
    ok(checkpoint(A, n, path, stop=True))

    def has(ip):
        code, out = sh(B, n, "ip -4 -o addr show eth0")
        return code == 0 and ip in out and old_ip not in out

    sigcont_failed = lambda: log(B, n).count("signal 18: vm ft-readdr runs, but setting its address")
    for paused in (True, False):
        what = "held" if paused else "running"
        clear_log(B, n)
        fault(B, "readdress_fail", 120000)
        if paused:
            r = ok(restore(B, path, paused=True, ip="auto"))
            code, out, err = cli(B, "resume", n)
            check(f"readdress fails ({what}): resume sent", code == 0, err)
            check(f"readdress fails ({what}): logged", wait_for(lambda: sigcont_failed() == 1, 30), log(B, n)[-2000:])
        else:
            r = ok(restore(B, path, ip="auto"))
            check(f"readdress fails ({what}): reported", "setting its address" in (r.get("address_error") or ""), r)
        check(f"readdress fails ({what}): running", vms(B).get(n, {}).get("state") == "running", vms(B).get(n))
        check(f"readdress fails ({what}): guest lacks the new address", not has(r["ip"]))
        refused = checkpoint(B, n, path + "-x")
        check(f"readdress fails ({what}): no checkpoint while pending", not refused["ok"] and "address" in refused.get("error", ""), refused)
        rm_ckpt(path + "-x")
        # A SIGCONT is let through while the address is pending: it tries again.
        before = sigcont_failed()
        code, out, err = cli(B, "resume", n)
        check(f"readdress fails ({what}): another resume tries again", code == 0 and wait_for(lambda: sigcont_failed() > before, 30), log(B, n)[-2000:])
        check(f"readdress fails ({what}): the background retries too", wait_for(lambda: "trying again" in log(B, n), 30), log(B, n)[-2000:])
        fault(B, "readdress_fail", 0)
        check(f"readdress fails ({what}): set once it can be, unasked", wait_for(lambda: has(r["ip"]), 30), sh(B, n, "ip -4 -o addr show eth0"))
        check(f"readdress fails ({what}): logged as taken", "took its address" in log(B, n), log(B, n)[-2000:])
        check(f"readdress fails ({what}): md5 intact", md5(B, n) == m)
        r2 = checkpoint(B, n, path + "-x")
        check(f"readdress fails ({what}): checkpoints again", r2["ok"], r2)
        rm_ckpt(path + "-x")
        kill(B, n)
    rm_ckpt(path)


def resume_unpause_fail():
    """A suspended VM whose vCPUs fail to resume may have run some of them:
    its checkpoint is not resumed again, but the VM, paused again, is kept
    and `flexvm resume` runs it."""
    n = "ft-unpause-fail"
    m = setup(n)
    proc = marker(A, n)
    suspend(A, n)
    fault(A, "restore_unpause_fail", 60000)
    r = resume_suspended(A, n)
    fault(A, "restore_unpause_fail", 0)
    res = r.get("result") or {}
    check("unpause fails: resume answers, paused", r["ok"] and res.get("state") == "paused" and "resuming its vCPUs failed" in (res.get("resume_error") or ""), r)
    check("unpause fails: kept, paused", vms(A).get(n, {}).get("state") == "paused", vms(A).get(n))
    d = os.path.join(A.state, "suspended", n)
    check("unpause fails: its checkpoint is consumed (STARTED, or deleted once paged in)",
          not os.path.exists(d) or os.path.exists(os.path.join(d, "STARTED")), os.listdir(d) if os.path.exists(d) else None)
    resume(A, n)
    check("unpause fails: flexvm resume runs it", vms(A).get(n, {}).get("state") == "running", vms(A).get(n))
    check("unpause fails: md5 intact, same processes", md5(A, n) == m and marker_id(A, n) == proc, (proc, marker_id(A, n)))
    cleanup(n)


def resume_unsettled():
    """A resume that failed part way (some vCPUs may run, Firecracker still
    says Paused) and whose pause after it failed too stays unsure: a later
    pause that fails is not taken for paused because Firecracker says Paused,
    and nothing leaves the VM meanwhile. Once a pause succeeds it is known
    again, and resumes."""
    n = "ft-unsettled"
    m = setup(n, mib=20)
    sock = api_sock(A, n)
    unsure = lambda: control(A, n, {"op": "debug", "what": "status"})["result"]["describe"]["state_unsure"]
    check("unsettled: paused", pause(A, n))
    for f in ("resume_partial", "repause_fail"):
        fault(A, f, 60000)
    signal_vm(A, n, signal.SIGCONT)
    check("unsettled: the resume fails part way", wait_for(lambda: "resume failed part way" in log(A, n), 10), log(A, n)[-1000:])
    check("unsettled: unsure", unsure())
    fault(A, "resume_partial", 0)
    fault(A, "pause_fail", 60000)
    signal_vm(A, n, signal.SIGTSTP)
    check("unsettled: a later pause fails too", wait_for(lambda: "pause failed part way" in log(A, n), 10), log(A, n)[-1000:])
    check("unsettled: Firecracker says Paused, yet still unsure", fc_api(sock, "GET", "/")["state"] == "Paused" and unsure(), fc_api(sock, "GET", "/"))
    path = ckpt_path("ft-unsettled")
    r = checkpoint(A, n, path)
    check("unsettled: no checkpoint while unsure", not r["ok"] and "ended unknown" in r.get("error", "") and not os.path.exists(path), r)
    for f in ("pause_fail", "repause_fail"):
        fault(A, f, 0)
    resume(A, n)
    check("unsettled: paused explicitly, then resumed", vms(A)[n]["state"] == "running" and not unsure() and fc_api(sock, "GET", "/")["state"] == "Running", vms(A)[n])
    check("unsettled: md5 intact", md5(A, n) == m)
    r = checkpoint(A, n, path)
    check("unsettled: checkpoints again", r["ok"], r)
    cleanup(n)
    rm_ckpt(path)


def abort_link_fail():
    """Raising a VM's tap fails as it resumes after an aborted migration or a
    checkpoint: it is left paused (as Firecracker has it), never failed, and
    `flexvm resume` runs it."""
    n = "ft-link-fail"
    m = setup(n, mib=20)
    for f in ("bad_preload", "resume_link_fail"):
        fault(A, f, 60000)
    r = migrate(A, n, B)
    for f in ("bad_preload", "resume_link_fail"):
        fault(A, f, 0)
    check("link fails after an abort: migrate fails, saying so", not r["ok"] and "resuming it here failed too" in r.get("error", ""), r)
    check("link fails after an abort: paused on A only, not failed", where(n) == {A: "paused"}, where(n))
    check("link fails after an abort: Firecracker paused", fc_api(api_sock(A, n), "GET", "/")["state"] == "Paused")
    resume(A, n)
    check("link fails after an abort: flexvm resume runs it", where(n) == {A: "running"} and md5(A, n) == m, where(n))
    path = ckpt_path("ft-link-fail")
    fault(A, "resume_link_fail", 60000)
    r = checkpoint(A, n, path)
    fault(A, "resume_link_fail", 0)
    check("link fails after a checkpoint: it fails, saying so", not r["ok"] and "after its checkpoint failed" in r.get("error", ""), r)
    check("link fails after a checkpoint: paused, not failed", vms(A)[n]["state"] == "paused", vms(A)[n])
    resume(A, n)
    check("link fails after a checkpoint: flexvm resume runs it", vms(A)[n]["state"] == "running" and md5(A, n) == m, vms(A)[n])
    r = migrate(A, n, B)
    check("link fails: a later migration works", r["ok"] and where(n).get(B) == "running", r)
    wait_released(B, n)
    check("link fails: md5 intact on B", md5(B, n) == m)
    cleanup(n)
    rm_ckpt(path)


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
    live = lambda: len([f for f in os.listdir(os.path.join(A.run, "standby", t)) if f.endswith(".lock") and alive(f[:-5].split("-")[0])])
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
    cleanup("ft-cow2")
    # Again, with write tracking on since the first: the writer rewrites more than a pause copies (#235), so its pages
    # are all protected and copied on write, as before (`ckpt_hot` checks hot pages).
    path2 = ckpt_path("ft-cow-again")
    r = ok(checkpoint(A, n, path2))
    print(f"cow again: paused {r['paused_ms']} ms, hot {r['hot']}, copy {r['copy']}")
    check("cow again: too many hot pages to copy during the pause", r["hot"]["copied_mib"] == 0 and r["copy"]["rescues"] > 0, r)
    h = ckhash(A, path2)
    check("cow again: checkpoint == memory at the pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
    ok(restore(B, path2, name="ft-cow3", ip="auto"))
    errors, _, out = writer_check(B, "ft-cow3")
    check("cow again: the restored copy has exactly the pause-time memory", errors == 0, out)
    fault(A, "ckpt_memhash", 0)
    cleanup(n)
    cleanup("ft-cow3")
    rm_ckpt(path)
    rm_ckpt(path2)


def cow_rescue_fail():
    """#310: a rescue that fails gives its pages back, still protected, and a writer that found one of them RESCUING
    reads it itself rather than failing the checkpoint. With every other rescue failing (ckpt_rescue_fail), keep-running
    checkpoints of a guest rewriting its memory are written, hold exactly the memory at their pause, and restore."""
    n = "ft-rescuefail"
    ok(run(A, n))
    start_writer(A, n, mib=64)
    fault(A, "ckpt_memhash", 300000)
    fault(A, "ckpt_slow", 300000)
    fault(A, "ckpt_rescue_fail", 300000)
    given_back, i = 0, 0
    while i < 6 and (i < 2 or given_back == 0):
        path = ckpt_path(f"ft-rescuefail{i}")
        r = checkpoint(A, n, path, timeout=180)
        check(f"rescue fail {i}: checkpoint written", r.get("ok"), r)
        if not r.get("ok"):
            break
        r = r["result"]
        print(f"rescue fail {i}: paused {r['paused_ms']} ms, copy {r['copy']}")
        given_back += r["copy"]["given_back"]
        check(f"rescue fail {i}: rescues failed", r["copy"]["rescue_failures"] > 0, r["copy"])
        h = ckhash(A, path)
        check(f"rescue fail {i}: checkpoint == memory at the pause", h["hash"] == r["pause_memhash"], (h["hash"], r["pause_memhash"]))
        if r["copy"]["given_back"] > 0:
            ok(restore(B, path, name="ft-rescuefail2", ip="auto"))
            errors, _, out = writer_check(B, "ft-rescuefail2")
            check(f"rescue fail {i}: the restored copy has exactly the pause-time memory", errors == 0, out)
            cleanup("ft-rescuefail2")
        rm_ckpt(path)
        i += 1
    check("rescue fail: a writer read pages a failed rescue gave back", given_back > 0, given_back)
    for f in ("ckpt_rescue_fail", "ckpt_slow", "ckpt_memhash"):
        fault(A, f, 0)
    errors, _, out = writer_check(A, n)
    check("rescue fail: the original is intact", errors == 0, out)
    cleanup(n)


def huge_mib(host, name):
    """MiB of guest memory Firecracker holds in transparent huge pages, and its RSS."""
    out = {}
    for l in open(f"/proc/{fc_pid(host, name)}/smaps_rollup"):
        k, _, v = l.partition(":")
        if k in ("Rss", "AnonHugePages"):
            out[k] = int(v.split()[0]) // 1024
    return out.get("AnonHugePages", 0), out.get("Rss", 0)


def collapse_report(host, name):
    r = control(host, name, {"op": "debug", "what": "status"}, timeout=10)
    return r.get("result", {}).get("collapse") if r.get("ok") else None


def cow_collapsed():
    """Memory a migration paged in is collapsed into huge pages once the pull is done (#141), and keeps what 4 KiB
    pages guarantee: with the guest rewriting it, a keep-running checkpoint and a delta each hold exactly the memory at
    their pause, the restored copy (collapsed in turn) is intact, and free page reporting still returns memory."""
    if "[never]" in open("/sys/kernel/mm/transparent_hugepage/enabled").read():
        raise Skip("transparent huge pages are disabled here")
    n, paths = "ft-huge", [ckpt_path("ft-huge0"), ckpt_path("ft-huge1")]
    ok(run(A, n))
    code, out = sh(A, n, "dd if=/dev/urandom of=/tmp/f bs=1M count=200 2>/dev/null; md5sum /tmp/f")
    m = out.split()[0]
    start_writer(A, n, mib=64)
    ok(migrate(A, n, B))
    st = wait_released(B, n)
    check("huge: migrated and pulled", st["released"] and st["state"] == "running", st)
    wait_for(lambda: collapse_report(B, n) is not None, 60)
    c = collapse_report(B, n)
    huge, _ = huge_mib(B, n)
    print(f"huge: collapse {c}, {huge} MiB in huge pages")
    check("huge: paged-in memory collapsed into huge pages", c and c["collapsed"] >= 100 and huge >= 200, (c, huge))
    errors, _, out = writer_check(B, n)
    check("huge: guest memory intact after the collapse", errors == 0 and md5(B, n) == m, out)
    fault(B, "ckpt_memhash", 120000)
    res = [ok(checkpoint(B, n, paths[0]))]
    time.sleep(1)
    res.append(ok(checkpoint(B, n, paths[1], incremental=True)))
    fault(B, "ckpt_memhash", 0)
    print(f"huge: checkpoints paused {[r['paused_ms'] for r in res]} ms, rescues {[r['copy'].get('rescues') for r in res]}")
    for i, p in enumerate(paths):
        h = ckhash(B, p)
        check(f"huge: checkpoint {i} == memory at its pause", h["hash"] == res[i]["pause_memhash"], (h["hash"], res[i]["pause_memhash"]))
    errors, _, out = writer_check(B, n)
    check("huge: the original is intact after the checkpoints", errors == 0, out)
    ok(restore(A, paths[1], name="ft-huge2", ip="auto"))
    wait_for(lambda: collapse_report(A, "ft-huge2") is not None, 60)
    c = collapse_report(A, "ft-huge2")
    errors, _, out = writer_check(A, "ft-huge2")
    check("huge: the restored copy collapsed and intact", c and c["collapsed"] > 0 and errors == 0 and md5(A, "ft-huge2") == m, (c, out))
    # Free page reporting discards whole 2 MiB blocks, each a whole huge page: RSS falls as before.
    huge0, rss0 = huge_mib(A, "ft-huge2")
    sh(A, "ft-huge2", "rm /tmp/f")
    returned = wait_for(lambda: huge_mib(A, "ft-huge2")[1] < rss0 - 150, 30)
    huge1, rss1 = huge_mib(A, "ft-huge2")
    check("huge: freed memory goes back to the host", returned and huge1 < huge0, (rss0, rss1, huge0, huge1))
    errors, _, out = writer_check(A, "ft-huge2")
    check("huge: guest memory intact after the discards", errors == 0, out)
    cleanup(n)
    cleanup("ft-huge2")
    for p in paths:
        rm_ckpt(p)


def collapse_abort():
    """A migration that aborts after its source paused, its collapse pass mid-way (#191): the source runs its copy
    again, and the pass goes on to the end instead of leaving the VM on 4 KiB pages for good."""
    if "[never]" in open("/sys/kernel/mm/transparent_hugepage/enabled").read():
        raise Skip("transparent huge pages are disabled here")
    n = "ft-collapse-abort"
    m = setup(n, mib=600)
    ok(migrate(A, n, B))
    st = wait_released(B, n)
    check("collapse abort: migrated and pulled", st["released"] and st["state"] == "running", st)
    # Hundreds of chunks: the pass runs for seconds, so it is still going when the migration back pauses the VM.
    mid = collapse_report(B, n)
    fault(A, "resume_kill", 60000)
    r = migrate(B, n, A)
    fault(A, "resume_kill", 0)
    check("collapse abort: migration committed, then the target died", r["ok"], r)
    check("collapse abort: the source runs its copy again", wait_for(lambda: where(n) == {B: "running"}, 60), where(n))
    wait_for(lambda: collapse_report(B, n) is not None, 120)
    c = collapse_report(B, n)
    huge, _ = huge_mib(B, n)
    print(f"collapse abort: before the migration {mid}, after {c}, {huge} MiB in huge pages")
    check("collapse abort: the pass was mid-way when the source paused", mid is None, mid)
    check("collapse abort: the pass went on to the end", c and c["stopped"] is None and c["collapsed"] >= 200 and huge >= 400, (c, huge))
    check("collapse abort: md5 intact", md5(B, n) == m)
    cleanup(n)


def collapse_ckpt_fail():
    """A `checkpoint --stop` that fails while writing, its quiesce having ended the collapse pass mid-way (#207): the VM
    runs on and the pass starts again and goes on to the end, as after an aborted migration."""
    if "[never]" in open("/sys/kernel/mm/transparent_hugepage/enabled").read():
        raise Skip("transparent huge pages are disabled here")
    n, path = "ft-collapse-ckpt", ckpt_path("ft-collapse-ckpt")
    rm_ckpt(path)
    m = setup(n, mib=600)
    # Slowed (300 ms after each call, about 20 calls), the pass is still going when the checkpoint pauses the VM.
    fault(B, "collapse_slow", 60000)
    clear_log(B, n)
    ok(migrate(A, n, B))
    st = wait_released(B, n)
    check("collapse ckpt fail: migrated and pulled", st["released"] and st["state"] == "running", st)
    mid = collapse_report(B, n)
    fault(B, "ckpt_fail_write", 60000)
    r = checkpoint(B, n, path, stop=True)
    fault(B, "ckpt_fail_write", 0)
    fault(B, "collapse_slow", 0)
    check("collapse ckpt fail: refused as injected, VM runs on", not r["ok"] and "injected" in r["error"] and where(n) == {B: "running"}, (r, where(n)))
    passes = lambda: [l for l in log(B, n).splitlines() if "huge pages in" in l]
    check("collapse ckpt fail: the checkpoint stopped the pass mid-way", wait_for(lambda: passes(), 10) and passes()[0].endswith("stopped: checkpoint or migration"),
          passes())
    wait_for(lambda: collapse_report(B, n) is not None, 120)
    c = collapse_report(B, n)
    huge, _ = huge_mib(B, n)
    print(f"collapse ckpt fail: before the checkpoint {mid}, after {c}, {huge} MiB in huge pages")
    check("collapse ckpt fail: the pass was mid-way when the checkpoint paused", mid is None, mid)
    check("collapse ckpt fail: the pass went on to the end", c and c["stopped"] is None and c["collapsed"] >= 200 and huge >= 400, (c, huge))
    check("collapse ckpt fail: md5 intact", md5(B, n) == m)
    rm_ckpt(path)
    cleanup(n)


def guest_chunks(host, name):
    """Firecracker's guest memory by 2 MiB chunk (of its userfaultfd-registered mappings): those backed by one
    transparent huge page (512 present pages on contiguous PFNs from a 2 MiB-aligned one, each flagged THP), those with
    nothing mapped, and those Firecracker made inaccessible (unplugged slots)."""
    pid = fc_pid(host, name)
    vmas, cur = [], None
    for l in open(f"/proc/{pid}/smaps"):
        head = l.split()
        if "-" in head[0] and ":" not in head[0]:
            cur = (*(int(x, 16) for x in head[0].split("-")), head[1].startswith("---"))
        elif l.startswith("VmFlags:") and " um" in l:
            vmas.append(cur)
    huge, empty, unplugged = set(), set(), set()
    with open(f"/proc/{pid}/pagemap", "rb") as pm, open("/proc/kpageflags", "rb") as kf:
        for a, b, none in vmas:
            for c in range((a + (2 << 20) - 1) & ~((2 << 20) - 1), b - (2 << 20) + 1, 2 << 20):
                if none:
                    unplugged.add(c)
                pm.seek(c // 4096 * 8)
                entries = struct.unpack("512Q", pm.read(512 * 8))
                if not any(e >> 63 & 1 or e >> 62 & 1 for e in entries):
                    empty.add(c)
                    continue
                pfn = entries[0] & ((1 << 55) - 1)
                if pfn % 512 or not all(e >> 63 & 1 and e & ((1 << 55) - 1) == pfn + i for i, e in enumerate(entries)):
                    continue
                kf.seek(pfn * 8)
                if all(f >> 22 & 1 for f in struct.unpack("512Q", kf.read(512 * 8))):  # KPF_THP, every page
                    huge.add(c)
    return huge, empty, unplugged


def settle_rss(host, name, timeout=60):
    """Waits for Firecracker's RSS to hold still for 3 s (free page reporting done)."""
    last, since, end = None, time.time(), time.time() + timeout
    while time.time() < end:
        rss = huge_mib(host, name)[1]
        if last is None or abs(rss - last) > 4:
            last, since = rss, time.time()
        elif time.time() - since >= 3:
            return rss
        time.sleep(0.5)
    return last


def guest_blocks(host, name):
    """The guest's hotplugged memory blocks: (hotplug region's guest address, block size, online block ids)."""
    code, out = sh(host, name, "cat /proc/iomem; echo; cat /sys/devices/system/memory/block_size_bytes; "
                               "for d in /sys/devices/system/memory/memory*; do echo $d $(cat $d/state); done")
    assert code == 0, out
    lines = out.splitlines()
    i = next(i for i, l in enumerate(lines) if "(virtio_mem)" in l)
    base = int(next(l for l in reversed(lines[:i]) if not l.startswith(" ")).split("-")[0], 16)
    bs = int(next(l for l in lines if re.fullmatch(r"[0-9a-f]+", l.strip())), 16)
    online = [int(l.split()[0].rsplit("memory", 1)[1]) for l in lines if l.startswith("/sys/") and l.endswith(" online")]
    return base, bs, sorted(b for b in online if b * bs >= base)


def unplug_collapsed():
    """virtio-mem unplug of memory collapsed into huge pages after a migration (#141): the guest moves the data out of
    the blocks it gives back, Firecracker discards them (2 MiB blocks, whole huge pages), every huge page in them is
    gone, and the guest's memory stays intact. Deterministic: the guest offlines the hotplugged blocks that hold the
    most huge pages, and virtio-mem unplugs offline blocks first. PLUG_TEMPLATE picks a template with at least
    1.5 GiB of unplugged hotplug room."""
    n = "ft-huge-unplug"
    m = setup(n, template=os.environ.get("PLUG_TEMPLATE"))
    v = vms(A)[n]
    plugged = v["plugged_mib"]
    if v["max_mib"] - v["guest_mib"] < 1536:
        cleanup(n)
        raise Skip(f"template too small to plug 1.5 GiB more ({v['guest_mib']} of {v['max_mib']} MiB)")
    ok(hotplug(A, n, plugged + 1536))
    grown = wait_for(lambda: (vms(A)[n]["requested_mib"], vms(A)[n]["plugged_mib"]) == (plugged + 1536,) * 2, 60)
    check("huge unplug: plugged 1.5 GiB more", grown, vms(A)[n])
    code, out = sh(A, n, "dd if=/dev/urandom of=/tmp/g bs=1M count=500 2>/dev/null && md5sum /tmp/g")
    check("huge unplug: guest wrote 500 MiB more", code == 0, out)
    g = out.split()[0] if code == 0 else None
    start_writer(A, n, mib=64)
    ok(migrate(A, n, B))
    st = wait_released(B, n)
    check("huge unplug: migrated and pulled", st["released"] and st["state"] == "running", st)
    wait_for(lambda: collapse_report(B, n) is not None, 120)
    c = collapse_report(B, n)
    check("huge unplug: memory collapsed", c and c["collapsed"] >= 100, c)
    rss0 = settle_rss(B, n)
    # Host address of each hotplugged block (the hotplug region is the last guest memory region).
    offset, _, host_base = control(B, n, {"op": "debug", "what": "status"})["result"]["host_regions"][-1]
    hp_gpa, bs, online = guest_blocks(B, n)
    chunks_of = lambda blk: {host_base + blk * bs - hp_gpa + i for i in range(0, bs, 2 << 20)}
    # Growth is refused meanwhile (and eviction is off), so the controller never plugs back what the test takes away.
    fault(B, "no_admit", 120000)
    sock = api_sock(B, n)
    # Free page reports are held (firecracker/0003) across the unplug: every chunk that empties then is the unplug's.
    held = fc_api(sock, "PATCH", "/balloon/reporting/hold")
    try:
        check("huge unplug: free page reports held", held is None, held)
        huge0, empty0, _ = guest_chunks(B, n)
        ranked = sorted(online, key=lambda blk: -len(chunks_of(blk) & huge0))
        chosen = []
        for blk in ranked[:6]:
            if len(chunks_of(blk) & huge0) >= 16 and len(chosen) < 2:
                code, out = sh(B, n, f"echo offline > /sys/devices/system/memory/memory{blk}/state")
                if code == 0:
                    chosen.append(blk)
        target = {c for blk in chosen for c in chunks_of(blk)} & huge0
        print(f"huge unplug: blocks of {bs >> 20} MiB at {hp_gpa:#x}; offlined {chosen}, holding {len(target) * 2} MiB of huge pages "
              f"(of {len(huge0) * 2} MiB)")
        check("huge unplug: offlined blocks that hold huge pages", chosen and len(target) * 2 >= 64, (chosen, ranked[:6]))
        now = vms(B)[n]["plugged_mib"]
        ok(hotplug(B, n, now - len(chosen) * (bs >> 20)))
        hp = lambda: (vms(B)[n]["requested_mib"], vms(B)[n]["plugged_mib"])
        done = wait_for(lambda: hp() == (now - len(chosen) * (bs >> 20),) * 2, 60)
        gone = all(sh(B, n, f"test -e /sys/devices/system/memory/memory{blk}")[0] != 0 for blk in chosen)
        st = control(B, n, {"op": "debug", "what": "status"})["result"]
        huge1, empty1, _ = guest_chunks(B, n)
    finally:
        released = fc_api(sock, "PATCH", "/balloon/reporting/release")
        fault(B, "no_admit", 0)
    rss1 = settle_rss(B, n)
    print(f"huge unplug: plugged {now} -> {hp()[1]} MiB (settled: {done}, blocks gone: {gone}); {len(target - empty1) * 2} MiB of the "
          f"targeted huge pages still mapped; {len(empty1 - empty0) * 2} MiB emptied in all; RSS {rss0} -> {rss1} MiB")
    check("huge unplug: the offlined blocks were unplugged", done and gone and not st["failed"] and released is None,
          (hp(), gone, st["failed"], released))
    check("huge unplug: every huge page in them is gone", target and not target - empty1, (len(target), len(target - empty1)))
    check("huge unplug: data moved, not copied (RSS did not grow)", rss1 <= rss0 + 64, (rss0, rss1))
    errors, _, out = writer_check(B, n)
    check("huge unplug: guest memory intact", errors == 0 and md5(B, n) == m and sh(B, n, "md5sum /tmp/g")[1].split()[0] == g, out)
    cleanup(n)


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


def ckpt_hot():
    """#235: a keep-running checkpoint copies the pages the guest keeps writing
    (hot pages) during the pause and leaves them unprotected; the next one
    leaves out of its delta those whose contents did not change since. A chain
    of deltas of a guest that rewrites memory, some of it back to what it had
    at the last checkpoint: each link restores exactly its pause-time memory,
    across a failed checkpoint (which drops what the next compares with)."""
    n = "ft-hot"
    paths = [ckpt_path(f"ft-hot{i}") for i in range(6)]
    ok(run(A, n))
    start_writer(A, n, mib=8)
    # 1024 pages rewritten all the time, alternately all with one byte and the other.
    flip = "import time\nb = bytearray(4 << 20)\nk = 0\nwhile True:\n    b[:] = bytes([k % 2]) * len(b)\n    k += 1\n    time.sleep(0.05)\n"
    code, out = sh(A, n, f"printf '{flip.replace('%', '%%')}' > /tmp/flip.py && (setsid python3 /tmp/flip.py >/dev/null 2>&1 </dev/null &) && sleep 0.5 && pgrep -f flip.py")
    check("hot: flipper started", code == 0 and out.strip(), out)
    fault(A, "ckpt_memhash", 120000)
    res = []
    for i, p in enumerate(paths):
        if i == 3:
            failed = ckpt_path("ft-hot-failed")
            fault(A, "ckpt_fail_write", 60000)
            r = checkpoint(A, n, failed, incremental=True)
            fault(A, "ckpt_fail_write", 0)
            check("hot: the injected failure fails a checkpoint", not r["ok"], r)
            time.sleep(0.3)
        r = ok(checkpoint(A, n, p, incremental=i > 0))
        res.append(r)
        print(f"hot {i}: paused {r['paused_ms']} ms, {r['data_mib']} MiB data, dirty {r['dirty_mib']} MiB, hot {r['hot']}, "
              f"{r['copy']['faults']} faults", flush=True)
        time.sleep(0.3)
    fault(A, "ckpt_memhash", 0)
    hot = [r["hot"] for r in res]
    check("hot: checkpoints after the first two copy hot pages during the pause", all(h["mib"] > 0 for h in hot[2:]), hot)
    check("hot: unchanged hot pages are left out of deltas", any(h["unchanged_mib"] > 0 for h in hot[2:]), hot)
    for i, p in enumerate(paths):
        h = ckhash(A, p)
        check(f"hot: link {i} == memory at its pause", h["hash"] == res[i]["pause_memhash"] and len(h["chain"]) == i, h)
    ok(restore(B, paths[-1], name="ft-hot2", ip="auto"))
    errors, _, out = writer_check(B, "ft-hot2")
    check("hot: the restored last link is intact", errors == 0, out)
    errors, _, out = writer_check(A, n)
    check("hot: the original is intact", errors == 0, out)
    cleanup(n)
    cleanup("ft-hot2")


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


def pull_enomem():
    """Background pull copies that fail for a while (ENOMEM, a transient
    error) are retried as a fault's are, within the fault deadline, instead
    of failing the VM at the first: the pull completes and the source lets
    go."""
    n = "ft-pullnomem"
    m = setup(n, mib=200)
    clear_log(B, n)
    fault(B, "pull_enomem", 60000)
    ok(migrate(A, n, B))
    st = wait_released(B, n, timeout=30)
    fault(B, "pull_enomem", 0)
    check("pull enomem: every page arrives and the source lets go",
          st["released"] is True and st["background_pull_ms"] is not None and st["failed"] is None, st)
    check("pull enomem: the pullers retried", "background pull" in log(B, n) and "retrying" in log(B, n), log(B, n)[-500:])
    check("pull enomem: memory intact", md5(B, n) == m)
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
    # Its own process, reaped here: once started, an exec waits 30 s for a VM
    # that went away, longer than the hosts' teardown waits for leftovers.
    reader = subprocess.Popen([BIN, "--state", B.state, "--run", B.run, "exec", n, "md5sum /tmp/f"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    try:
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
    finally:
        reader.kill()
        reader.wait()
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
    connection keeps echoing and loses nothing. The guest runs slowly for a
    while after each pause (its first writes fault on the write protection
    of the copy), so on a loaded host an echo can take longer than the
    retransmit timeout: a retransmit the receiver reports as a duplicate
    (DSACK) is spurious and allowed, one it does not would be a lost segment."""
    n = "ft-ckpt-pkt"
    ok(run(A, n))
    ip = vm_ip(A, n)
    udp_receiver(A, n)
    tcp_server(A, n)
    guest0 = guest_tcp_counters(A, n)
    conn = socket.create_connection((ip, 7000), timeout=10)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    stop, sent, echoes, slowest = threading.Event(), [0], [True], [0.0]

    def stream():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop.is_set():
            s.sendto(b"%08d\n" % sent[0], (ip, 9000))
            sent[0] += 1
            time.sleep(0.001)

    def pingpong():
        while not stop.is_set() and echoes[0]:
            t = time.monotonic()
            echoes[0] = echo(conn, b"x" * 32)
            slowest[0] = max(slowest[0], time.monotonic() - t)
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
    retrans, dsacks = tcp_retrans(conn)
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
    guest = [b - a for a, b in zip(guest0, guest_tcp_counters(A, n))]
    pauses = [(r.get("result") or {}).get("paused_ms") for r in results]
    check("ckpt packet hold: tcp echoed throughout, no segment lost (any retransmit a duplicate)",
          echoes[0] and retrans <= dsacks and guest[0] <= guest[1],
          f"retransmits {retrans} (duplicates {dsacks}), the guest's {guest[0]} (duplicates {guest[1]}); "
          f"slowest echo {slowest[0] * 1e3:.0f} ms, pauses {pauses} ms")
    cleanup(n)
    for p in paths:
        rm_ckpt(p)


_stallprobe = None


def start_probe(host, name, kib, threads):
    """Starts scripts/stallprobe.c in the guest (see there)."""
    global _stallprobe
    if _stallprobe is None:
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stallprobe.c")
        out = os.path.join(tempfile.mkdtemp(prefix="stallprobe-"), "stallprobe")
        cc = "musl-gcc" if subprocess.run(["which", "musl-gcc"], capture_output=True).returncode == 0 else "gcc"
        subprocess.run([cc, "-O2", "-static", "-pthread", "-o", out, src], check=True)
        _stallprobe = base64.b64encode(open(out, "rb").read()).decode()
    for i in range(0, len(_stallprobe), 48000):
        code, out = sh(host, name, f"printf '%s' '{_stallprobe[i:i + 48000]}' {'>' if i == 0 else '>>'} /tmp/sp.b64")
        assert code == 0, out
    code, out = sh(host, name, "base64 -d /tmp/sp.b64 > /tmp/stallprobe && rm /tmp/sp.b64 && chmod +x /tmp/stallprobe && "
                               f"setsid /tmp/stallprobe {kib} {threads} /tmp/sp.out >/dev/null 2>&1 < /dev/null & sleep 1; pidof stallprobe")
    assert code == 0 and out.strip(), out


def probe_dump(host, name):
    """The probe's markers and, per thread, its gaps as (start, len), in ns."""
    code, out = sh(host, name, "rm -f /tmp/sp.out; kill -USR1 $(pidof stallprobe); "
                               "for i in $(seq 1 200); do [ -f /tmp/sp.out ] && break; sleep 0.05; done; cat /tmp/sp.out")
    assert code == 0 and out.endswith("done"), out[-500:]
    markers, gaps = [], {}
    for line in out.splitlines():
        f = line.split()
        if f[0] == "m":
            markers.append(int(f[1]))
        elif f[0] == "g":
            gaps.setdefault(int(f[1]), []).append((int(f[2]), int(f[3])))
    return markers, gaps


def stall_of(gaps, marker, until, window=300e6):
    """For one thread's gaps around a checkpoint between `marker` and `until`: the longest gap (the pause, as the
    guest saw it), and the time the thread lost to gaps in the `window` after it, less what it lost in as long before
    it."""
    near = [g for g in gaps if marker <= g[0] < until]
    if not near:
        return None
    pause = max(near, key=lambda g: g[1])
    end = pause[0] + pause[1]
    post = [l for s, l in gaps if end <= s < end + window]
    before = sum(l for s, l in gaps if pause[0] - window - 50e6 <= s < pause[0] - 50e6)
    return pause[1] / 1e6, max(0, sum(post) - before) / 1e6, post


KVM_DEBUG = "/sys/kernel/debug/kvm"


def kvm_vms():
    """KVM's debugfs directories, one per VM (named by a pid this namespace may not see)."""
    return {e for e in os.listdir(KVM_DEBUG) if "-" in e} if os.path.isdir(KVM_DEBUG) else set()


def kvm_stats(d, names=("pf_taken", "pf_fixed", "exits", "remote_tlb_flush")):
    """KVM's counters for the VM of debugfs directory `d`, if known."""
    try:
        return {k: int(open(f"{KVM_DEBUG}/{d}/{k}").read()) for k in names} if d else {}
    except OSError:
        return {}


def uffd_cpu_ms(pid):
    """CPU time the VM process's uffd thread has used, in ms (None if not found)."""
    for t in os.listdir(f"/proc/{pid}/task"):
        try:
            if open(f"/proc/{pid}/task/{t}/comm").read().strip() == "uffd":
                return int(open(f"/proc/{pid}/task/{t}/schedstat").read().split()[0]) / 1e6
        except OSError:
            pass
    return None


def ckpt_stall():
    """#214: how long a keep-running checkpoint stops the guest as the guest
    sees it: the pause, and the time it loses after the resume to write
    faults on pages protected for the copy. A probe in the guest (STALL_THREADS
    threads, 2, one per vCPU) spins writing its working set (STALL_KIB per
    thread, 4 MiB) and logs every gap in its progress; STALL_N checkpoints (8),
    STALL_LOAD host spinners (0) meanwhile. Prints a table, with the CPU time
    the uffd thread used over each checkpoint; checks only that the
    checkpoints are written and the guest goes on."""
    n = "ft-stall"
    count, load = int(os.environ.get("STALL_N", "8")), int(os.environ.get("STALL_LOAD", "0"))
    kvms = kvm_vms()
    ok(run(A, n))
    # Its KVM counters, if it is the only VM that came meanwhile.
    new = kvm_vms() - kvms
    kvm = new.pop() if len(new) == 1 else None
    threads = int(os.environ.get("STALL_THREADS", "2"))
    start_probe(A, n, int(os.environ.get("STALL_KIB", "4096")), threads)
    pid = vm_pid(A, n)
    spinners = [subprocess.Popen(["sh", "-c", "while :; do :; done"]) for _ in range(load)]
    rows = []
    try:
        time.sleep(1)
        for i in range(count):
            sh(A, n, "kill -USR2 $(pidof stallprobe)")
            time.sleep(0.5)
            before = control(A, n, {"op": "debug", "what": "status"})["result"]["faults"]["wp"]
            k0 = kvm_stats(kvm)
            path = ckpt_path(f"{n}-{i}")
            c0 = uffd_cpu_ms(pid)
            r = checkpoint(A, n, path)
            c1 = uffd_cpu_ms(pid)
            time.sleep(1)
            after = control(A, n, {"op": "debug", "what": "status"})["result"]["faults"]["wp"]
            k1 = kvm_stats(kvm)
            rm_ckpt(path)
            if not check(f"stall {i}: checkpoint written", r.get("ok"), r):
                break
            res = r["result"]
            rows.append({"paused_ms": res["paused_ms"], "wp_faults": after["count"] - before["count"],
                         "wp_serve_ms": round(after["sum_ms"] - before["sum_ms"], 2), "copy": res.get("copy") or {},
                         "kvm": {k: k1[k] - k0.get(k, 0) for k in k1}, "dirty_mib": res.get("dirty_mib"),
                         "uffd_ms": c1 - c0 if c0 is not None and c1 is not None else float("nan")})
    finally:
        for s in spinners:
            s.kill()
            s.wait()
    markers, gaps = probe_dump(A, n)
    check("stall: a marker per checkpoint, gaps logged", len(markers) >= len(rows) and gaps, (len(markers), len(rows)))
    print(f"{'#':>2} {'paused_ms':>9} {'guest_gap':>9} {'lost_ms':>8} {'stall_ms':>8} {'wp_faults':>9} {'serve_ms':>8} "
          f"{'rescues':>7} {'retries':>7} {'dirty':>5} {'kvm_pf':>6} {'tlb_fl':>6} {'uffd_ms':>7}")
    tot, posts = [], []
    for i, row in enumerate(rows):
        until = markers[i + 1] if i + 1 < len(markers) else float("inf")
        per = [s for s in (stall_of(g, markers[i], until) for g in gaps.values()) if s]
        if not per:
            continue
        gap, lost = max(p[0] for p in per), max(p[1] for p in per)
        post = sorted(l for p in per for l in p[2])
        posts.extend(post)
        # What the guest lost in all: the gap of the slowest thread, and what it lost after.
        stall = max(p[0] + p[1] for p in per)
        tot.append((row["paused_ms"], gap, lost, stall, row["uffd_ms"], (row["copy"] or {}).get("retries", 0)))
        c = row["copy"]
        print(f"{i:>2} {row['paused_ms']:>9.1f} {gap:>9.1f} {lost:>8.1f} {stall:>8.1f} {row['wp_faults']:>9} "
              f"{row['wp_serve_ms']:>8.1f} {c.get('rescues', 0):>7} {c.get('retries', 0):>7} {row['dirty_mib']:>5} "
              f"{row['kvm'].get('pf_taken', '-'):>6} {row['kvm'].get('remote_tlb_flush', '-'):>6} {row['uffd_ms']:>7.1f}")
    if tot:
        med = lambda xs: sorted(xs)[len(xs) // 2]
        print("median: paused %.1f ms, guest gap %.1f ms, lost after resume %.1f ms, stall %.1f ms (max %.1f), "
              "uffd thread %.1f ms CPU, %d retries"
              % (med([t[0] for t in tot]), med([t[1] for t in tot]), med([t[2] for t in tot]), med([t[3] for t in tot]),
                 max(t[3] for t in tot), med([t[4] for t in tot]), med([t[5] for t in tot])))
    if posts:
        posts.sort()
        q = lambda f: posts[min(len(posts) - 1, int(len(posts) * f))] / 1e3
        print(f"guest gaps > 20 us in the 300 ms after each resume, per thread: {len(posts) / max(1, len(tot)) / 2:.0f} a "
              f"checkpoint, p50 {q(0.5):.0f} us, p90 {q(0.9):.0f} us, p99 {q(0.99):.0f} us, sum {sum(posts) / 1e6 / max(1, len(tot)):.1f} ms")
    check("stall: the guest runs on", where(n) == {A: "running"} and sh(A, n, "pidof stallprobe")[0] == 0)
    cleanup(n)


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


def mem_refused_headroom():
    """A VM refused a step while it still has headroom below its mark is not
    throttled or starved, so its host does not move it; only at its mark is it."""
    n = "ft-mem-headroom"
    m = setup(n, mib=1)
    v = vms(A)[n]
    admitted = v["admitted_mib"]
    if not admitted:
        raise Skip("no per-VM cgroups here")
    _, high, _ = cgroup(A, n)
    # flexvm asks for a step (limit.rs `step`) within half of one of its mark, and
    # counts a refusal as throttling only within 16 MiB of it.
    half = (-(-min(max(admitted // 4, 256), 2048) // 128) * 128) // 2
    lo, hi = high - half + 8, high - 40
    check("mem headroom: room between asking and the mark", hi - lo >= 48, (admitted, high, half))
    fault(A, "no_admit", 600000)
    # Filled in pieces up to just past where it asks, never to the mark.
    for _ in range(4):
        used = cgroup(A, n)[0]
        if used >= lo:
            break
        hog(A, n, max(8, (lo + hi) // 2 - used - 16))
        check("mem headroom: the fill finishes", wait_for(lambda: hog_done(A, n), 60), cgroup(A, n))
        time.sleep(1)
    used, high_now, _ = cgroup(A, n)
    check("mem headroom: within half a step of its mark, short of it", lo <= used <= hi and high_now == high, (lo, used, hi, high_now))
    # Asked and refused each tick; the host's eviction pass (every 5 s) leaves it be.
    seen = []
    for _ in range(12):
        time.sleep(1)
        x = vms(A).get(n, {})
        seen.append((x.get("throttled"), x.get("starved"), x.get("admitted_mib"), cgroup(A, n)[0] if x.get("pid") else None))
    check("mem headroom: refused, not raised", all(s[2] == admitted for s in seen), seen)
    check("mem headroom: never throttled or starved", not any(s[0] or s[1] for s in seen), seen)
    check("mem headroom: not moved", where(n) == {A: "running"}, (where(n), log(A, n)[-1500:]))
    # At its mark, the same refusal is starvation, and the host moves it.
    hog(A, n, v["guest_mib"] - 384)
    check("mem headroom: at its mark it is moved", wait_for(lambda: where(n) == {B: "running"}, 60), (where(n), log(A, n)[-1500:]))
    fault(A, "no_admit", 0)
    wait_released(B, n, timeout=60)
    check("mem headroom: md5 intact", md5(B, n) == m)
    cleanup(n)


def guest_mem(host, name):
    """The guest's view: (MemTotal MiB, /vm memory.high MiB or None, the fill's pid alive, OOM kills in its kernel log)."""
    code, out = sh(host, name, "awk '/MemTotal/{print $2}' /proc/meminfo; cat /sys/fs/cgroup/vm/memory.high; "
                               "kill -0 $(cat /tmp/hog.pid) 2>/dev/null && echo alive || echo dead; dmesg | grep -c -i 'killed process'; true")
    if code != 0 or len(out.split()) != 4:
        return None
    total, high, live, kills = out.split()
    return int(total) >> 10, None if high == "max" else int(high) >> 20, live == "alive", int(kills)


def fill(host, name, mib):
    """`hog`, its pid in the guest's /tmp/hog.pid."""
    prog = f"b=bytearray({mib}<<20); [b.__setitem__(slice(i, i + 8), i.to_bytes(8, \"little\")) for i in range(0, len(b), 4096)]"
    code, out = sh(host, name, f"rm -f /tmp/hog.done; setsid python3 -c '{prog}; open(\"/tmp/hog.done\", \"w\").close(); "
                               "import time; time.sleep(3600)' >/dev/null 2>&1 </dev/null & echo $! >/tmp/hog.pid; echo started")
    assert code == 0, out


def mem_refused_fill():
    """A guest filling past its plugged memory whose host refuses it more
    partway (no plug, no step) is not OOM-killed: it stays throttled at its
    own mark in the guest, never lifted, and counts as starved; relief then
    moves it to a peer, where the fill finishes. PLUG_TEMPLATE: a template
    with little plugged and room to grow."""
    n = "ft-refused-fill"
    m = setup(n, mib=1, template=os.environ.get("PLUG_TEMPLATE"))
    v = vms(A)[n]
    if not v["admitted_mib"]:
        raise Skip("no per-VM cgroups here")
    mib = 2560
    if v["max_mib"] < mib + 1536:
        raise Skip(f"its template grows to {v['max_mib']} MiB, too little to fill {mib} MiB")
    plugged0 = v["plugged_mib"]
    fault(A, "no_evict", 600000)
    fill(A, n, mib)
    # Refused partway: once the guest has grown by 768 MiB.
    grew = wait_for(lambda: vms(A)[n]["plugged_mib"] >= plugged0 + 768, 60)
    fault(A, "no_admit", 600000)
    check("refused fill: it grew before it was refused", grew, vms(A)[n])
    seen = []
    for _ in range(15):
        time.sleep(1)
        x = vms(A).get(n, {})
        seen.append((x.get("plugged_mib"), x.get("requested_mib"), x.get("starved"), guest_mem(A, n)))
    print(f"refused fill: (plugged, requested, starved, (MemTotal, /vm high, alive, kills)) each second: {seen}", flush=True)
    g = seen[-1][3]
    check("refused fill: the fill is alive, nothing OOM-killed", g is not None and g[2] and g[3] == 0,
          (g, sh(A, n, "dmesg | grep -i -A2 oom | tail -20")[1], log(A, n)[-1500:]))
    check("refused fill: throttled in the guest at its mark, never lifted", all(s[3] and s[3][1] is not None for s in seen), seen)
    check("refused fill: not finished", not hog_done(A, n))
    check("refused fill: starved, so the host would move it", any(s[2] for s in seen[-5:]), seen[-5:])
    check("refused fill: the host's cgroup saw no OOM", cgroup(A, n)[2].get("oom_kill") == "0", cgroup(A, n)[2])
    said = log(A, n).count("starved: the host's reserve refused")
    check("refused fill: its starving is logged once, not at each retry", said == 1, log(A, n)[-1500:])
    rows = [l.split() for l in cli(A, "ls")[1].splitlines()]
    check("refused fill: plain ls shows it starved", rows[0][-1] == "STARVED" and any(r[0] == n and r[-1] == "yes" for r in rows[1:]), rows)
    # Relief: moved to B, where it grows.
    fault(A, "no_evict", 0)
    check("refused fill: moved to B", wait_for(lambda: where(n) == {B: "running"}, 60), (where(n), log(A, n)[-1500:]))
    st = wait_released(B, n, timeout=60)
    check("refused fill: pulled and released", st["released"] is True and st["failed"] is None, st)
    check("refused fill: the fill finishes there", wait_for(lambda: hog_done(B, n), 240), (guest_mem(B, n), vms(B).get(n)))
    g = guest_mem(B, n)
    check("refused fill: the same fill, nothing OOM-killed", g is not None and g[2] and g[3] == 0, g)
    check("refused fill: md5 intact", md5(B, n) == m)
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
        boot = open("/proc/sys/kernel/random/boot_id").read().strip()
        g = json.load(open(os.path.join(host.run, f"grants-{boot}")))
    except (OSError, ValueError):
        return []
    return [m for t, m, *_ in g if time.clock_gettime(time.CLOCK_BOOTTIME) * 1000 - t <= 10000]


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
        locks = lambda: [f for f in os.listdir(os.path.join(A.run, "standby", t)) if f.endswith(".lock") and alive(f[:-5].split("-")[0])]
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
        live = lambda: len([f for f in os.listdir(os.path.join(A.run, "standby", t)) if f.endswith(".lock") and alive(f[:-5].split("-")[0])])
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


def peer_by_name():
    """A peer configured by name (localhost:PORT) is admitted by a listener
    just restarted, its lookup of the name not finished yet: the first
    request, queued while the listener starts, is served, not refused."""
    if args.no_listeners:
        return print("peer by name: skipped (--no-listeners)")
    stop_listener(B)
    try:
        start_listener(B, peer="localhost:" + A.addr.rsplit(":", 1)[1], wait=False)
        r, deadline = None, time.time() + 10
        while r is None and time.time() < deadline:
            try:
                r = peer(B, {"op": "migration", "mig": 1})
            except ConnectionRefusedError:
                time.sleep(0.005)
        check("peer by name: the first request after a restart is admitted", r is not None and r.get("ok"), r)
        r = peer(B, {"op": "migration", "mig": 1}, source="127.0.0.2")
        check("peer by name: a non-peer is still refused", not r["ok"] and "is not a peer of" in r.get("error", ""), r)
    finally:
        stop_listener(B)
        start_listener(B)


def peer_moved():
    """#311: a peer configured by name that comes back on a new address
    (DHCP) has its route messages accepted at once, not refused until the
    listener's 30 s refresh: a source it would refuse starts a lookup of a
    name not looked up lately, and waits for it. Names resolve through the
    test hook RUN/hosts.json."""
    if args.no_listeners:
        return print("peer moved: skipped (--no-listeners)")
    name = "pr352-peer.test:" + A.addr.rsplit(":", 1)[1]
    hosts = os.path.join(B.run, "hosts.json")
    resolve = lambda ip: json.dump({name: [f"{ip}:{A.addr.rsplit(':', 1)[1]}"]}, open(hosts + ".tmp", "w")) or os.replace(hosts + ".tmp", hosts)
    ip = A.ips.split("-")[0].rsplit(".", 1)[0] + ".204"
    withdraw = lambda source: peer(B, {"op": "route", "ip": ip, "gen": addr(B, ip).get("seen", 0) + 1}, source=source)
    if not A.addr.startswith("127."):
        return print("peer moved: skipped (not on loopback)")
    stop_listener(B)
    try:
        resolve("127.0.0.3")
        start_listener(B, peer=name)
        r, deadline = None, time.time() + 10
        while not (r and r.get("ok")) and time.time() < deadline:
            r = withdraw("127.0.0.3")
        check("peer moved: admitted at its first address", r is not None and r.get("ok"), r)
        # Past LOOKUP_EVERY since that lookup, as when a peer comes back on a new lease.
        time.sleep(2.5)
        resolve("127.0.0.4")
        t = time.time()
        r = withdraw("127.0.0.4")
        check("peer moved: a route message from its new address is accepted at once", r.get("ok") and time.time() - t < 2, (r, f"{time.time() - t:.2f}s"))
        r = withdraw("127.0.0.3")
        check("peer moved: its old address is no longer a peer", not r["ok"] and "is not a peer of" in r.get("error", ""), r)
        r = peer(B, {"op": "migration", "mig": 1}, source="127.0.0.5")
        check("peer moved: a non-peer is still refused", not r["ok"] and "is not a peer of" in r.get("error", ""), r)
    finally:
        stop_listener(B)
        try:
            os.unlink(hosts)
        except OSError:
            pass
        start_listener(B)


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
    n, ip = "ft-forged-gen", spare(B, 2)
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
    # A template name and id are file names in the templates directory, never paths.
    n, (good_id, regions) = "ft-forged-tpl", tid
    scenario_vms.add(n)
    for label, tpl, tpl_id in (("absolute name", "/tmp", good_id), ("parent name", "../" + args.template, good_id),
                               ("name with a slash", f"{args.template}/x", good_id),
                               ("parent id", args.template, ".."), ("path id", args.template, "../../tmp")):
        s, r, _ = migrate_in_raw(B, n, ip, (tpl_id, regions), template=tpl)
        s.close()
        check(f"forged template {label}: refused", not r.get("ok") and "bad template" in r.get("error", ""), r)
        nothing_left(f"forged template {label}", n, ip)
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
    its home host, which refuses one in use there. A guest restored at a new
    address (also from a checkpoint of a restored VM) has only that one."""
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
    r = r["result"]
    old = vms(A)[n]["ip"]
    has = lambda out, ip: f"inet {ip}/" in out
    only = lambda h, vm, ip, *gone: (lambda out: has(out, ip) and not any(has(out, g) for g in gone))(sh(h, vm, "ip -4 -o addr show eth0")[1])
    check("restore --ip auto: the guest has only its new address", only(A, "ft-rip2", r["ip"], old), sh(A, "ft-rip2", "ip -4 -o addr show eth0"))
    # A checkpoint of the restored VM (its agent set the address in an earlier session) restored at a third address.
    path2 = ckpt_path("ft-rip2")
    ok(checkpoint(A, "ft-rip2", path2))
    r3 = ok(restore(B, path2, name="ft-rip5", ip="auto"))
    check("restore of a restored VM's checkpoint: only the newest address", only(B, "ft-rip5", r3["ip"], old, r["ip"]), sh(B, "ft-rip5", "ip -4 -o addr show eth0"))
    # A peer's address, once free there, is borrowed, and the guest has only it.
    kill(B, "ft-rip-b")
    check("restore --ip: the peer's address is free once its VM is gone", wait_for(lambda: not addr(B, theirs).get("holder"), 10), addr(B, theirs))
    r4 = restore(A, path, name="ft-rip4", ip=theirs)
    check("restore --ip: a peer's free address is borrowed", r4["ok"] and r4["result"]["ip"] == theirs and addr(B, theirs).get("lent"), (r4, addr(B, theirs)))
    check("restore --ip: the guest has only the borrowed address", r4["ok"] and only(A, "ft-rip4", theirs, old), sh(A, "ft-rip4", "ip -4 -o addr show eth0"))
    for vm in (n, "ft-rip2", "ft-rip4", "ft-rip5"):
        cleanup(vm)
    rm_ckpt(path)
    rm_ckpt(path2)


def spoof_filter():
    """#362: what a guest sends leaves its tap only from its own address. A datagram from
    another VM's address (or from one no VM has) is dropped at the tap, while the guest's own
    gets through; a VM restored at a new address (readdressed at its resume) passes only that
    one, the old one filtered, and so does its tap after a migration."""
    n, n2, other = "ft-spoof", "ft-spoof2", "ft-spoof-b"
    path = ckpt_path(n)
    ok(run(A, n))
    ok(run(B, other))
    mine, theirs = vm_ip(A, n), vm_ip(B, other)
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("0.0.0.0", 0))
    rx.settimeout(0.2)
    port = rx.getsockname()[1]

    def send(h, vm, sources):
        """From each source (added to eth0 for the send if the guest lacks it), three datagrams
        to the host's tap address; returns {source: what the host got from where}."""
        cmd = "; ".join(f"ip addr add {src}/32 dev eth0 2>/dev/null && added=1 || added=0; "
                        f"for i in 1 2 3; do echo {src} | socat -u - UDP-SENDTO:169.254.1.2:{port},bind={src}; done; "
                        f"[ $added = 1 ] && ip addr del {src}/32 dev eth0" for src in sources) + "; true"
        code, out = sh(h, vm, cmd)
        assert code == 0, out
        got, end = {}, time.time() + 1.5
        while time.time() < end:
            try:
                data, frm = rx.recvfrom(100)
            except socket.timeout:
                continue
            got.setdefault(data.decode().strip(), set()).add(frm[0])
        return got

    nowhere = "10.250.0.5"
    got = send(A, n, [mine, theirs, nowhere])
    check("spoof: the guest's own address gets through", got.get(mine) == {mine}, got)
    check("spoof: another VM's address is dropped at the tap", theirs not in got, got)
    check("spoof: an address no VM has is dropped", nowhere not in got, got)
    # Restored at a new address, held, and readdressed at its resume.
    ok(checkpoint(A, n, path))
    r = ok(restore(A, path, name=n2, ip="auto", paused=True))
    new = r["ip"]
    code, out, err = cli(A, "resume", n2)
    check("spoof: restored at a new address and resumed", code == 0 and new != mine, (r, err))
    check("spoof: readdressed", wait_for(lambda: f"inet {new}/" in sh(A, n2, "ip -4 -o addr show eth0")[1], 30), sh(A, n2, "ip -4 -o addr show eth0"))
    got = send(A, n2, [new, mine, theirs])
    check("spoof: after a readdress the new address gets through", got.get(new) == {new}, got)
    check("spoof: after a readdress the old address is dropped", mine not in got and theirs not in got, got)
    got = send(A, n, [mine])
    check("spoof: the original VM still sends from its own", got.get(mine) == {mine}, got)
    ok(migrate(A, n2, B))
    wait_released(B, n2)
    got = send(B, n2, [new, mine, theirs])
    check("spoof: after a migration its address gets through", got.get(new) == {new}, got)
    check("spoof: after a migration others are dropped", mine not in got and theirs not in got, got)
    rx.close()
    for vm in (n, n2, other):
        cleanup(vm)
    rm_ckpt(path)


def unlend_retry():
    """An aborted migration whose unlend fails keeps its loan (#257): the next
    attempt undoes it, and so does the VM's end."""
    n = "ft-unlend"
    m = setup(n)
    ip, gen = vms(A)[n]["ip"], vms(A)[n]["gen"]
    lent = lambda: addr(A, ip).get("lent")
    try:
        fault(A, "bad_preload", 60000)
        fault(A, "unlend_fail", 60000)
        r = migrate(A, n, B)
        check("unlend retry: aborted, still lent", not r["ok"] and where(n) == {A: "running"} and lent() == gen, (r, where(n), addr(A, ip)))
        fault(A, "unlend_fail", 0)
        r = migrate(A, n, B)
        check("unlend retry: a second abort undoes the loan", not r["ok"] and where(n) == {A: "running"} and not lent(), (r, where(n), addr(A, ip)))
        fault(A, "unlend_fail", 60000)
        r = migrate(A, n, B)
        check("unlend retry: aborted again, still lent", not r["ok"] and lent() == gen, (r, addr(A, ip)))
    finally:
        fault(A, "bad_preload", 0)
        fault(A, "unlend_fail", 0)
    check("unlend retry: md5 intact on A", md5(A, n) == m)
    kill(A, n)
    check("unlend retry: its end undoes the loan", wait_for(lambda: not lent(), 10), addr(A, ip))
    cleanup(n)


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
    late = lambda g: ok(peer(A, {"op": "route", "ip": ip, "via": "127.0.0.1", "gen": g, "rev": 0}))
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


def killed_migrated():
    """#361: a VM process SIGKILLed after its VM migrated (as a panic would end
    it) never withdraws the address: a sweep on its host does, so its home host
    takes back the loan and the peers drop their route. One suspended after
    migrating keeps its address through the sweep and resumes with it."""
    lent = lambda ip: addr(A, ip).get("lent")
    route = lambda ip: subprocess.run(["ip", "route", "show", ip], capture_output=True, text=True).stdout.strip()
    n = "ft-killed-migrated"
    m = setup(n, mib=1)
    ip = vms(A)[n]["ip"]
    ok(migrate(A, n, B))
    wait_released(B, n)
    check("killed migrated: lent while away", lent(ip) is not None, addr(A, ip))
    check("killed migrated: A routes it via B", wait_for(lambda: addr(A, ip).get("via") is not None, 10), addr(A, ip))
    check("killed migrated: md5 intact on B", md5(B, n) == m)
    pid, fc = vm_pid(B, n), fc_pid(B, n)
    os.kill(pid, signal.SIGKILL)
    check("killed migrated: its process and firecracker die", wait_for(lambda: not alive(pid) and not alive(fc), 10), (pid, fc))
    ok(cli_json(B, "debug", "gc"))
    check("killed migrated: B withdrew it", addr(B, ip).get("withdrawn") is True and addr(B, ip).get("holder") is None, addr(B, ip))
    check("killed migrated: A takes back its loan and drops the route",
          wait_for(lambda: not lent(ip) and addr(A, ip).get("withdrawn") is True and addr(A, ip).get("via") is None, 15), addr(A, ip))
    check("killed migrated: no route left", wait_for(lambda: route(ip) == "", 10), route(ip))
    n2 = "ft-killed-migrated-2"
    ok(run(A, n2, ip=ip))
    check("killed migrated: the address runs a new vm on A", where(n2) == {A: "running"} and sh(A, n2, "echo hi") == (0, "hi"), where(n2))
    ok(cli_json(A, "debug", "gc"))
    check("killed migrated: a sweep leaves a live vm's address alone", addr(A, ip).get("holder") == n2 and not addr(A, ip).get("withdrawn"), addr(A, ip))
    cleanup(n2)
    # Suspended after migrating: its process is gone, but its checkpoint keeps the address.
    n3 = "ft-suspended-migrated"
    m3 = setup(n3, mib=1)
    ip3 = vms(A)[n3]["ip"]
    ok(migrate(A, n3, B))
    wait_released(B, n3)
    suspend(B, n3)
    ok(cli_json(B, "debug", "gc"))
    check("suspended migrated: still lent, still B's", lent(ip3) is not None and addr(B, ip3).get("holder") == n3 and not addr(B, ip3).get("withdrawn"),
          (addr(A, ip3), addr(B, ip3)))
    ok(resume_suspended(B, n3))
    check("suspended migrated: resumes on B with its data", where(n3) == {B: "running"} and md5(B, n3) == m3, where(n3))
    cleanup(n3)
    check("suspended migrated: its kill frees the address", wait_for(lambda: not lent(ip3), 15), addr(A, ip3))
    # A home host that cannot be told at the time (down) hears on a later sweep: the withdrawal is recorded first.
    n4 = "ft-killed-migrated-4"
    setup(n4, mib=1)
    ip4 = vms(A)[n4]["ip"]
    ok(migrate(A, n4, B))
    wait_released(B, n4)
    pid, fc = vm_pid(B, n4), fc_pid(B, n4)
    fault(A, "route_refuse", 60000)
    os.kill(pid, signal.SIGKILL)
    wait_for(lambda: not alive(pid) and not alive(fc), 10)
    ok(cli_json(B, "debug", "gc"))
    notice = os.path.join(B.state, "withdrawals", ip4)
    check("killed migrated, home down: withdrawn on B, still lent on A, the notice kept",
          addr(B, ip4).get("withdrawn") is True and lent(ip4) is not None and os.path.exists(notice), (addr(A, ip4), addr(B, ip4)))
    fault(A, "route_refuse", 0)
    # As a sweep would once its backoff passed.
    n = json.load(open(notice))
    for u in n["peers"]:
        u["next_ms"] = 0
    json.dump(n, open(notice, "w"))
    ok(cli_json(B, "debug", "gc"))
    check("killed migrated, home back: a later sweep tells it, and it takes back its loan",
          wait_for(lambda: not lent(ip4) and addr(A, ip4).get("withdrawn") is True, 15) and not os.path.exists(notice), (addr(A, ip4), os.path.exists(notice)))
    n5 = "ft-killed-migrated-5"
    ok(run(A, n5, ip=ip4))
    check("killed migrated, home back: the address runs a new vm on A", where(n5) == {A: "running"}, where(n5))
    cleanup(n5)


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


def standby_stop_claim():
    """A standby VM stopped (`standby 0`) while a claim of it is under way:
    the VM the claim made runs on, and SIGTERM suspends it. The stop reaches
    the process after the claim started (it is listed until the claim is
    done), and must not be taken for a kill of the claimed VM."""
    t, n = args.template, "ft-sb-stop-claim"
    scenario_vms.add(n)
    ok(cli_json(A, "standby", "--template", t, "1"))
    res = {}
    try:
        check("standby stop claim: a standby ready", wait_for(lambda: len(standby_pids(A, t)) == 1, 60))
        # The claim stalls 3 s once the VM is set, before the standby lets go of its lock.
        fault(A, "claim_stall", 10000)
        th = threading.Thread(target=lambda: res.update(r=cli_json(A, "run", n, "--template", t, "-d", "--", "sleep 600")))
        th.start()
        time.sleep(1)
        ok(cli_json(A, "standby", "--template", t, "0"))
        th.join()
    finally:
        fault(A, "claim_stall", 0)
        cli(A, "standby", "--template", t, "0")
    r = res.get("r", {})
    check("standby stop claim: claimed", r.get("ok") and r["result"].get("standby") is True, r)
    time.sleep(0.5)
    check("standby stop claim: still running after the stop", vms(A).get(n, {}).get("state") == "running", (vms(A).get(n), log(A, n)[-1500:]))
    pid = vms(A).get(n, {}).get("pid")
    if pid:
        os.kill(pid, signal.SIGTERM)
        check("standby stop claim: SIGTERM suspends it", wait_for(lambda: not alive(pid), 60) and vms(A).get(n, {}).get("state") == "suspended",
              (vms(A).get(n), log(A, n)[-1500:]))
    cleanup(n)


def standby_claim_signal():
    """A foreground `run` interrupted (SIGINT), or killed, while its claim of a
    standby VM is under way: the VM the claim made goes, as a cold foreground
    run's would, and is not left running with no one to stop it."""
    t = args.template
    ok(cli_json(A, "standby", "--template", t, "1"))
    try:
        for sig, n in ((signal.SIGINT, "ft-sb-sigint"), (signal.SIGKILL, "ft-sb-sigkill")):
            scenario_vms.add(n)
            what = signal.Signals(sig).name
            check(f"standby claim {what}: a standby ready", wait_for(lambda: len(standby_socks(A, t)) == 1, 60), standby_pids(A, t))
            # The claim stalls 3 s once the VM runs, before the standby answers.
            fault(A, "claim_stall", 10000)
            # Output to a file: an orphaned VM would hold a pipe open, and reading it would never end.
            out = tempfile.TemporaryFile("w+")
            p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "run", n, "--template", t, "--", "sleep 600"],
                                 stdin=subprocess.DEVNULL, stdout=out, stderr=out, text=True, env=ENV)
            # Inside the stall: the claim has started the VM, its answer is yet to come.
            time.sleep(1.5)
            p.send_signal(sig)
            try:
                p.wait(timeout=60)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
            out.seek(0)
            err = out.read()
            fault(A, "claim_stall", 0)
            if sig == signal.SIGINT:
                check("standby claim SIGINT: the claim finishes, then the VM gets the signal", '"standby":true' in err.replace(" ", ""), err[-800:])
            else:
                # Once its stall is over, the standby answers, finds the claimer gone and ends the VM.
                sblog = lambda: open(os.path.join(A.run, "standby", t, "standby.log"), errors="replace").read()
                check("standby claim SIGKILL: the standby finds its claimer gone", wait_for(lambda: f"the claimer of {n} is gone" in sblog(), 30),
                      (err[-800:], sblog()[-1500:]))
            check(f"standby claim {what}: the claimed vm is gone, not orphaned", wait_for(lambda: n not in vms(A), 30),
                  (vms(A).get(n), log(A, n)[-1500:]))
            cleanup(n)
    finally:
        fault(A, "claim_stall", 0)
        cli(A, "standby", "--template", t, "0")


def standby_socks(host, t):
    """The listening sockets of `host`'s standby VMs of `t`: those loaded, claimable."""
    d = os.path.join(host.run, "standby", t)
    return [f for f in os.listdir(d) if f.endswith(".sock")] if os.path.isdir(d) else []


def standby_concurrent_claims():
    """Concurrent runs claim different standby VMs at once: none queues on
    another's claim (each claim stalls 3 s)."""
    t, names = args.template, ("ft-sb-cc1", "ft-sb-cc2")
    ok(cli_json(A, "standby", "--template", t, "2"))
    res = {}
    try:
        check("standby concurrent: two ready", wait_for(lambda: len(standby_socks(A, t)) == 2, 90), standby_pids(A, t))
        ready = set(standby_pids(A, t))
        fault(A, "claim_stall", 15000)

        def claim(n):
            start = time.time()
            res[n] = (run(A, n), time.time() - start)

        ths = [threading.Thread(target=claim, args=(n,)) for n in names]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
    finally:
        fault(A, "claim_stall", 0)
        cli(A, "standby", "--template", t, "0")
    rs = [res.get(n, ({}, 0)) for n in names]
    check("standby concurrent: both claimed standbys", all(r.get("ok") and r["result"].get("standby") is True for r, _ in rs), rs)
    pids = {r.get("result", {}).get("pid") for r, _ in rs}
    check("standby concurrent: different ones, both ready before", len(pids) == 2 and pids <= ready, (pids, ready))
    # In one stall each, side by side; queued, the second would take two.
    check("standby concurrent: neither waited for the other", max(d for _, d in rs) < 5.5, [round(d, 2) for _, d in rs])
    for n in names:
        cleanup(n)


def standby_stalled():
    """A claimer that connects and stops before sending its request keeps no
    standby VM from stopping; a stopped standby VM keeps no `run` waiting
    (it starts cold once the handshake times out). Under the reserve, one that
    cannot exit yet (as a loading one acts on the stop only once loaded) still
    marks the pressure, so it is not refilled once it exits, and holds off
    neither eviction nor a controller's ticks."""
    t, n = args.template, "ft-sb-stalled"
    ok(cli_json(A, "standby", "--template", t, "1"))
    check("standby stalled: one ready", wait_for(lambda: len(standby_pids(A, t)) == 1, 60))
    pid = standby_pids(A, t)[0]
    d = os.path.join(A.run, "standby", t)
    c = socket.socket(socket.AF_UNIX)
    c.connect(os.path.join(d, next(f for f in os.listdir(d) if f.endswith(".sock") and f.split(".")[-2].split("-")[0] == str(pid))))
    c.send(b'{"name"')
    time.sleep(0.5)
    os.kill(pid, signal.SIGTERM)
    check("standby stalled: stops under a half-sent claim", wait_for(lambda: not alive(pid), 10))
    c.close()
    ok(cli_json(A, "standby", "--template", t, "1"))
    check("standby stalled: another ready", wait_for(lambda: len(standby_pids(A, t)) == 1, 60))
    pid = standby_pids(A, t)[0]
    os.kill(pid, signal.SIGSTOP)
    try:
        start = time.time()
        r = run(A, n)
        check("standby stalled: run starts cold past a stopped one", r.get("ok") and r["result"]["standby"] is False, r)
        check("standby stalled: within the handshake's bound", time.time() - start < 15, time.time() - start)
        pressure, active = os.path.join(A.run, "standby", ".pressure"), os.path.join(A.run, "evict.active")
        mtime = lambda p: os.stat(p).st_mtime if os.path.exists(p) else None
        before = mtime(pressure)
        fault(A, "no_evict", 600000)
        try:
            avail = mem_available()
            with Watch(A, [n]) as w, marks(avail + 4096, avail + 4608):
                marked = wait_for(lambda: mtime(pressure) != before, 10)
                evicting = wait_for(lambda: os.path.exists(active), 10)
                time.sleep(4)
        finally:
            fault(A, "no_evict", 0)
        rep = w.report("standby stalled: under the reserve")
        check("standby stalled: under the reserve, one that cannot exit still marks the pressure", marked and alive(pid), (before, mtime(pressure)))
        check("standby stalled: and holds eviction off no longer", evicting)
        check("standby stalled: the controller ticks on meanwhile", all(r["tick_gap_max_ms"] < 1600 for r in rep.values()), rep)
    finally:
        os.kill(pid, signal.SIGCONT)
    check("standby stalled: it exits once it can", wait_for(lambda: not alive(pid), 10))
    time.sleep(7)
    live = [p for p in standby_pids(A, t) if alive(p)]
    check("standby stalled: and is not refilled under the pressure mark", not live, live)
    try:
        os.remove(os.path.join(A.run, "standby", ".pressure"))
    except FileNotFoundError:
        pass
    cli(A, "standby", "--template", t, "0")
    check("standby stalled: stopped", wait_for(lambda: not standby_pids(A, t), 30))
    cleanup(n)


def standby_refill_race():
    """A refill granted just before pressure starts, whose standby has not
    created its lock file yet (`standby_lock_stall`, 3 s): relief does not
    pass it by, but holds eviction off until the standby is listed, then
    signals it and marks the pressure, before any eviction starts."""
    t, n = args.template, "ft-sb-refill-race"
    ok(run(A, n))
    pressure, active = os.path.join(A.run, "standby", ".pressure"), os.path.join(A.run, "evict.active")
    for f in (pressure, active):
        if os.path.exists(f):
            os.remove(f)
    fault(A, "no_evict", 600000)
    fault(A, "standby_lock_stall", 2000)
    res, seen = {}, {}
    th = threading.Thread(target=lambda: res.update(r=cli_json(A, "standby", "--template", t, "1")))
    th.start()
    try:
        time.sleep(1)
        avail = mem_available()
        with marks(avail + 4096, avail + 4608):
            start = time.time()
            while time.time() - start < 15 and len(seen) < 2:
                for k, f in (("pressure", pressure), ("active", active)):
                    if k not in seen and os.path.exists(f):
                        seen[k] = time.time() - start
                time.sleep(0.05)
            pids = standby_pids(A, t)
            th.join()
    finally:
        fault(A, "standby_lock_stall", 0)
        fault(A, "no_evict", 0)
    check("standby refill race: the standby being started is stopped, and marks the pressure", "pressure" in seen, seen)
    check("standby refill race: eviction waits for it", "active" in seen and "pressure" in seen and seen["active"] > seen["pressure"], seen)
    check("standby refill race: it exits", wait_for(lambda: not [p for p in pids + standby_pids(A, t) if alive(p)], 30), (pids, res))
    try:
        os.remove(pressure)
    except FileNotFoundError:
        pass
    cli(A, "standby", "--template", t, "0")
    cleanup(n)


def standby_starting(host):
    """(pid, start) of each `run --standby` process of `host` alive now, listed or not."""
    out = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            argv = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
            stat = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if host.state.encode() in argv and b"--standby" in argv and stat[0] != "Z":
            out.append((int(pid), int(stat[19])))
    return out


def standby_lock_timeout():
    """A refill's standby that does not create its lock file within
    LOCKED_TIMEOUT (`standby_lock_hang`, held past it) while the host is under
    its reserve: the refill kills and reaps it before letting relief in, so it
    never gets listed or loads; relief, finding no standby to stop, starts
    eviction only once it is gone; the refill fails, and the child leaves
    nothing behind (its cgroup, work directory, standby files)."""
    t, n = args.template, "ft-sb-lock-timeout"
    ok(run(A, n))
    d = os.path.join(A.run, "standby", t)
    pressure, active = os.path.join(A.run, "standby", ".pressure"), os.path.join(A.run, "evict.active")
    for f in (pressure, active):
        if os.path.exists(f):
            os.remove(f)
    fault(A, "no_evict", 600000)
    fault(A, "standby_lock_hang", 30000)
    res, seen, began = {}, {}, time.time()
    th = threading.Thread(target=lambda: res.update(r=cli_json(A, "standby", "--template", t, "1"), took=time.time() - began))
    th.start()
    child = None
    try:
        wait_for(lambda: standby_starting(A), 5)
        child = (standby_starting(A) or [None])[0]
        avail = mem_available()
        with marks(avail + 4096, avail + 4608):
            start = time.time()
            while time.time() - start < 20 and "active" not in seen:
                gone = child is not None and not alive(child[0])
                if gone and "gone" not in seen:
                    seen["gone"] = time.time() - start
                if os.path.exists(active):
                    seen["active"] = time.time() - start
                    seen["gone at active"] = gone
                time.sleep(0.05)
            th.join(30)
            listed = standby_pids(A, t)
            marked = os.path.exists(pressure)
    finally:
        fault(A, "standby_lock_hang", 0)
        fault(A, "no_evict", 0)
    check("standby lock timeout: the hung standby was seen starting", child is not None)
    r = res.get("r", {})
    check("standby lock timeout: the refill fails, its lock unacknowledged, within the timeout",
          not r.get("ok", True) and "acknowledge its lock" in r.get("error", "") and res.get("took", 99) < 12, res)
    check("standby lock timeout: killed and reaped by the refill", child is not None and not alive(child[0]), (child, seen))
    check("standby lock timeout: it was never listed, so relief marked no pressure", not listed and not marked, (listed, marked))
    check("standby lock timeout: eviction starts, only once it is gone", seen.get("gone at active") is True, seen)
    if child:
        key = f"{child[0]}-{child[1]}"
        left = lambda: [p for p in [f"/sys/fs/cgroup/flexvm/vm-{key}", os.path.join(A.run, "w", key)] if os.path.exists(p)] + \
            [f for f in (os.listdir(d) if os.path.isdir(d) else []) if key in f]
        check("standby lock timeout: nothing left behind (the refill sweeps)", wait_for(lambda: not left(), 5), left())
    cli(A, "standby", "--template", t, "0")
    check("standby lock timeout: no standby left", wait_for(lambda: not standby_starting(A), 30), standby_starting(A))
    try:
        os.remove(pressure)
    except FileNotFoundError:
        pass
    cleanup(n)


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


def route_abort():
    """#231: a source whose route switch failed retries it in the background. Its target
    then dies mid-pull, so the source aborts and runs its copy again; the retry, which the
    abort left with the same holder and generation, must not route the address to the dead
    target afterwards. B advertises an underlay that is not a local address (the default
    gateway), so the source's switch is a real route the kernel keeps. The source's page
    server is slowed from the start (`pages_slow`: every reply comes, a second late), not
    stopped on a timer: the target's probe of it still succeeds, and its 1000 MiB take
    minutes to pull, so it is killed mid-pull however loaded the host (#294)."""
    n = "ft-route-abort"
    scenario_vms.add(n)
    gw = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout.split()[2]
    code, out, err = cli(B, "config", "--underlay", gw)
    assert code == 0, err
    ip = None
    try:
        m = setup(n, mib=1000)
        ip = vm_ip(A, n)
        tcp_server(A, n)
        fault(A, "route", 120000)
        fault(A, "pages_slow", 120000)
        r = ok(migrate(A, n, B))
        check("route abort: the route switch failed, so it is retried", r["reroute_error"] is not None, r["reroute_error"])
        os.kill(vms(B)[n]["firecracker"], signal.SIGKILL)
        check("route abort: the target fails", wait_for(lambda: vms(B).get(n, {}).get("state") == "failed", 10), vms(B).get(n))
        fault(A, "pages_slow", 0)
        check("route abort: the source runs its copy again", wait_for(lambda: vms(A).get(n, {}).get("state") == "running", 60), where(n))
        # The retry's next try (at most 5 s away) goes through now; watch past it.
        fault(A, "route", 0)
        routes, unreached, end = set(), [], time.time() + 12
        while time.time() < end:
            routes.add(peer_route(ip))
            try:
                with socket.create_connection((ip, 7000), timeout=1) as c:
                    c.settimeout(1)
                    if not echo(c, b"ping\n"):
                        unreached.append(round(end - time.time(), 1))
            except OSError:
                unreached.append(round(end - time.time(), 1))
            time.sleep(0.2)
        check("route abort: the address never routes to the dead target", not any(f"via {gw}" in r for r in routes), routes)
        check("route abort: the resumed vm stays reachable", not unreached, unreached)
        check("route abort: the retry stopped with the abort", "dropped, migration" in log(A, n), log(A, n)[-1500:])
        check("route abort: md5 intact on A", md5(A, n) == m)
    finally:
        cli(B, "config", "--underlay", "")
        if ip and f"via {gw}" in peer_route(ip):
            subprocess.run(["ip", "route", "del", f"{ip}/32"], capture_output=True)


def arrival_overtaken():
    """Operations that change who owns a VM wait for its arrival to settle
    (every page in, the migration released, a home loan taken back), or are
    refused: a suspend mid-arrival, and migrating on mid-arrival, refused or
    not. Each time one copy runs, and the home host's loan is right.
    The source's page server is slowed (`pages_slow`: every reply comes, a
    second late), not stopped, so the arrival stays unfinished for as long as
    a step needs without its source ever looking lost. Each operation is
    caught waiting for the arrival (`settling`) before the slowing ends."""
    lent = lambda ip: addr(A, ip).get("lent")
    arriving = lambda h, n: (lambda v: v.get("remote_left", 0) > 0 and not v.get("failed"))(vms(h).get(n, {}))
    settling = lambda h, n: vms(h).get(n, {}).get("settling")
    mib = 400
    # Suspended mid-arrival on B: it settles first, so A lets go.
    n = "ft-arrive-suspend"
    m = setup(n, mib=mib)
    ip = vms(A)[n]["ip"]
    fault(A, "pages_slow", 120000)
    ok(migrate(A, n, B))
    check("suspend mid-arrival: caught arriving on B", arriving(B, n), vms(B).get(n))
    pid = vm_pid(B, n)
    os.kill(pid, signal.SIGTERM)
    check("suspend mid-arrival: the suspend waits for the arrival", wait_for(lambda: settling(B, n), 30), vms(B).get(n))
    fault(A, "pages_slow", 0)
    check("suspend mid-arrival: the suspend finishes", wait_for(lambda: not alive(pid), 120), vms(B).get(n))
    check("suspend mid-arrival: suspended on B", vms(B).get(n, {}).get("state") == "suspended", vms(B).get(n))
    check("suspend mid-arrival: the source let go", wait_for(lambda: n not in vms(A), 30), vms(A).get(n))
    check("suspend mid-arrival: still lent by its home host", lent(ip) is not None, addr(A, ip))
    ok(resume_suspended(B, n))
    check("suspend mid-arrival: one copy, running on B", where(n) == {B: "running"} and md5(B, n) == m, where(n))
    cleanup(n)
    # Coming home to A, and sent on again before all its memory is back: refused.
    n = "ft-arrive-refused"
    m = setup(n, mib=mib)
    ip = vms(A)[n]["ip"]
    ok(migrate(A, n, B))
    wait_released(B, n)
    fault(B, "pages_slow", 120000)
    ok(migrate(B, n, A))
    check("migrate on mid-arrival: caught arriving on A", arriving(A, n), vms(A).get(n))
    r = migrate(A, n, B)
    check("migrate on mid-arrival: refused", not r["ok"] and "still arriving" in r.get("error", ""), r)
    check("migrate on mid-arrival: the arrival goes on", arriving(A, n), vms(A).get(n))
    check("migrate on mid-arrival: the loan stays until it settles", lent(ip) is not None, addr(A, ip))
    fault(B, "pages_slow", 0)
    wait_released(A, n, source=B)
    check("migrate on mid-arrival: one copy, home on A", where(n) == {A: "running"} and md5(A, n) == m, where(n))
    check("migrate on mid-arrival: home, so no longer lent", wait_for(lambda: lent(ip) is None, 10), addr(A, ip))
    cleanup(n)
    # Sent on again mid-arrival, and it goes once the arrival settled.
    n = "ft-arrive-onward"
    m = setup(n, mib=mib)
    ip = vms(A)[n]["ip"]
    ok(migrate(A, n, B))
    wait_released(B, n)
    fault(B, "pages_slow", 120000)
    ok(migrate(B, n, A))
    check("migrate on after the arrival: caught arriving on A", arriving(A, n), vms(A).get(n))
    res = {}

    def onward():
        r = migrate(A, n, B)
        # B may still be letting go of its source copy, holding the name a moment.
        end = time.time() + 30
        while not r["ok"] and "taken" in r.get("error", "") and time.time() < end:
            time.sleep(0.5)
            r = migrate(A, n, B)
        res["r"] = r

    t = threading.Thread(target=onward)
    t.start()
    check("migrate on after the arrival: it waits for the arrival", wait_for(lambda: settling(A, n), 30), vms(A).get(n))
    fault(B, "pages_slow", 0)
    t.join(180)
    check("migrate on after the arrival: it goes", res.get("r", {}).get("ok"), res)
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
    # flexvm's own failures are 125, never a status CMD could have.
    for bad in (["--template", "ft-no-such-template"], ["--ip", "bad"], ["--mem", "512"]):
        r = subprocess.run(argv[:-1] + bad + ["--", "exit 0"], capture_output=True, text=True, env=ENV, timeout=120)
        check(f"run status: {bad[0]} {bad[1]} fails with 125", r.returncode == 125, (r.returncode, r.stderr[-300:]))
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


def suspend_overlap():
    """#351: SIGTERMs that overlap make one suspend at a time, the rest taken
    into it. Each fails (`ckpt_fail_write`, after `suspend_slow` holds the
    operation lock a while), leaving the VM running with its command; once
    the command ends, its process ends the VM and exits, never deadlocked
    between a waiting suspend and the command's kill."""
    n = "ft-susp-overlap"
    scenario_vms.add(n)
    clear_log(A, n)
    ok(cli_json(A, "run", n, "--template", args.template, "-d", "--", "echo susp-overlap-start; sleep 8; exit 5"))
    pid = vm_pid(A, n)
    ip = vms(A)[n]["ip"]
    check("suspend overlap: started", wait_for(lambda: "susp-overlap-start" in log(A, n).splitlines(), 30), log(A, n)[-300:])
    fault(A, "ckpt_fail_write", 60000)
    # Each suspend holds the VM's operation lock a while: the command likely ends with one waiting.
    fault(A, "suspend_slow", 60000)
    # Bursts of SIGTERMs, until the process is gone or long after the command's end.
    end, sent = time.time() + 40, 0
    while alive(pid) and time.time() < end:
        for _ in range(3):
            try:
                os.kill(pid, signal.SIGTERM)
                sent += 1
            except ProcessLookupError:
                break
        time.sleep(0.15)
    gone = wait_for(lambda: not alive(pid), 10)
    check("suspend overlap: the process exits once the command ends", gone, f"{sent} SIGTERMs; " + log(A, n)[-800:])
    if not gone:
        os.kill(pid, signal.SIGKILL)
        return
    fault(A, "ckpt_fail_write", 0)
    fault(A, "suspend_slow", 0)
    check("suspend overlap: suspends failed meanwhile", "injected fault: writing the checkpoint failed" in log(A, n), log(A, n)[-500:])
    check("suspend overlap: overlapping SIGTERMs were taken into one suspend", "already under way" in log(A, n), log(A, n)[-500:])
    check("suspend overlap: not suspended, not listed", n not in vms(A) and not os.path.exists(os.path.join(A.state, "suspended", n)), vms(A).get(n))
    a = addr(A, ip)
    check("suspend overlap: its address withdrawn, no holder", a.get("withdrawn") and not a.get("holder"), a)


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
        live = lambda: len([f for f in os.listdir(os.path.join(A.run, "standby", t)) if f.endswith(".lock") and alive(f[:-5].split("-")[0])])
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
    clear_log(A, r)
    started = ok(cli_json(A, "run", r, "--template", t, "-d", "--", "sleep 600"))
    pid = vm_pid(A, r)
    os.kill(pid, signal.SIGTERM)
    standby_log = os.path.join(A.run, "standby", t, "standby.log")
    check("cmd flag: suspended", wait_for(lambda: not alive(pid), 60) and vms(A).get(r, {}).get("state") == "suspended",
          (vms(A).get(r), started, log(A, r)[-1500:], open(standby_log).read()[-1500:] if os.path.exists(standby_log) else ""))
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


def bad_app_log():
    """A source whose header claims more app output than the guest has
    (u64::MAX, `bad_app_log`): the target goes on from the end of the
    guest's output, saying the offset was past it, rather than silently."""
    n = "ft-bad-applog"
    tpl = app_template()
    clear_log(A, n)
    clear_log(B, n)
    ok(run(A, n, template=tpl))
    check("bad app log: printing", wait_for(lambda: max(app_lines(log(A, n)), default=-1) >= 5, 60), log(A, n)[-500:])
    fault(A, "bad_app_log", 10000)
    r = migrate(A, n, B)
    fault(A, "bad_app_log", 0)
    check("bad app log: migrated", r["ok"], r)
    wait_released(B, n)
    last = max(app_lines(log(A, n)))
    check("bad app log: printing after the migration", wait_for(lambda: max(app_lines(log(B, n)), default=-1) >= last + 20, 60), log(B, n)[-500:])
    check("bad app log: the skip is logged", "is past the guest's end" in log(B, n), log(B, n)[-500:])
    lines = app_lines(log(A, n)) + app_lines(log(B, n))
    dups = sorted({x for x in lines if lines.count(x) > 1})
    check("bad app log: no line printed twice", not dups, dups[:20])
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
    sock = made(os.path.join(sbd, "deadbeef.999999990-1.sock"))
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
    # A VM process killed during a checkpoint leaves its root-only staging in the checkpoint's directory: gc leaves it
    # (#329), and the next checkpoint into that directory clears it.
    n, d = "ft-gc-ck", ckpt_path("ft-gc-ckdir")
    os.makedirs(d)
    ok(run(A, n))
    fault(A, "ckpt_slow", 120000)
    t = threading.Thread(target=lambda: checkpoint(A, n, os.path.join(d, "ck"), timeout=60))
    t.start()
    staged = lambda: [e for e in os.listdir(d) if e.startswith(".flexvm-staging-")]
    copying = wait_for(lambda: vms(A).get(n, {}).get("checkpoint_copy") and staged(), 30)
    check("gc: a checkpoint is staging", copying, (vms(A).get(n), os.listdir(d)))
    signal_vm(A, n, signal.SIGKILL)
    t.join()
    fault(A, "ckpt_slow", 0)
    ok(cli_json(A, "debug", "gc"))
    check("gc: the killed checkpoint's staging stays through a sweep", staged(), os.listdir(d))
    n2 = "ft-gc-ck2"
    ok(run(A, n2))
    ok(checkpoint(A, n2, os.path.join(d, "ck2")))
    check("gc: the next checkpoint into the directory clears the dead one's staging", not staged() and not os.path.exists(os.path.join(d, "ck")), os.listdir(d))
    cleanup(n2)
    cleanup(n)
    rm_ckpt(d)


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
    """A template build SIGKILLed after making its tap (PREFIX x PID, its
    owner in its alias): a sweep removes the tap once the build is gone (any
    process's periodic sweep may be first, so it is not looked for in
    between). A sweep goes by a tap's alias, never its name: one whose owner
    lives is kept, as are another host's (a prefix extending this one's,
    #193) and a tap with no owner, whatever their names read as."""
    name = f"ft-tpltap-{os.getpid()}"
    tdir = os.environ.get("FLEXVM_TEMPLATES") or os.path.join(os.path.abspath(args.artifacts), "templates")
    try:
        prefix = json.load(open(os.path.join(A.state, "host.json")))["prefix"]
    except (OSError, ValueError, KeyError):
        prefix = "fv"
    p = subprocess.Popen([BIN, "--state", A.state, "--run", A.run, "template", name, "--vcpus", "1", "--max", "512"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    tap = f"{prefix}x{p.pid:x}"
    def ifalias(dev):
        try:
            return open(f"/sys/class/net/{dev}/ifalias").read().strip()
        except OSError:
            return None
    # Its alias is set just after the tap is made.
    up = wait_for(lambda: ifalias(tap), 30)
    start, alias = starttime_of(p.pid), ifalias(tap)
    p.kill()
    p.wait()
    run = os.path.realpath(A.run)
    check("template tap: made by the build", up, tap)
    check("template tap: its alias names the build and this host", alias == f"flexvm {p.pid} {start} {run}", alias)
    me = f"{os.getpid()} {starttime_of(os.getpid())}"
    dead = f"{p.pid} 1"
    # (name, alias, kept): this script lives; another host's and an unowned tap read as dead pids here.
    made = [(f"{prefix}x{os.getpid():x}", f"flexvm {me} {run}", True),
            (f"{prefix}1t0", f"flexvm {dead} {run}.other", True),
            (f"{prefix}2t0", "", True),
            (f"{prefix}3t0", f"flexvm {dead} {run}", False)]
    try:
        for dev, al, _ in made:
            subprocess.run(["ip", "tuntap", "add", "dev", dev, "mode", "tap"], check=True)
            if al:
                subprocess.run(["ip", "link", "set", "dev", dev, "alias", al], check=True)
        ok(cli_json(A, "debug", "gc"))
        check("template tap: swept once its build is gone", not os.path.exists(f"/sys/class/net/{tap}"))
        for dev, al, kept in made:
            check(f"template tap: {dev} ({al or 'no alias'}) {'kept' if kept else 'swept'}", os.path.exists(f"/sys/class/net/{dev}") == kept)
    finally:
        for dev, _, _ in made:
            subprocess.run(["ip", "link", "del", dev], capture_output=True)
        subprocess.run(["ip", "link", "del", tap], capture_output=True)
        subprocess.run(["rm", "-rf", os.path.join(tdir, f".{name}.new-{p.pid}")])


def starttime_of(pid):
    try:
        return int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


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
    killed_migrated=killed_migrated,
    unread_output=unread_output,
    run_status=run_status,
    terminal=terminal,
    suspend_killed=suspend_killed,
    suspend_debris=suspend_debris,
    revoked_publication=revoked_publication,
    app_log=app_log, bad_app_log=bad_app_log,
    source_unpublished=source_unpublished,
    source_killed_basic=source_killed_basic,
    arrival_overtaken=arrival_overtaken,
    pull_died=pull_died,
    route_abort=route_abort,
    uffd_err=uffd_err,
    mem_high=no_evict(skippable(mem_high)), mem_high_migrate=no_evict(skippable(mem_high_migrate)),
    mem_high_evict=skippable(mem_high_evict), mem_refused_headroom=skippable(mem_refused_headroom), mem_refused_fill=skippable(mem_refused_fill), evict_grower=skippable(evict_grower), evict_no_pingpong=evict_no_pingpong, evict_skips_cmd=evict_skips_cmd, cmd_flag=cmd_flag, standby_stop_claim=standby_stop_claim, standby_claim_signal=standby_claim_signal, standby_concurrent_claims=standby_concurrent_claims, evict_latency=skippable(evict_latency),
    start_admission=start_admission, standby_admission=standby_admission,
    refused_admission=refused_admission, meminfo_unreadable=meminfo_unreadable,
    cow_grow=no_evict(cow_grow), plug_race=no_evict(plug_race), shrink_stall=no_evict(shrink_stall), plug_storm=no_evict(plug_storm),
    basic=basic, route=route, lost_ack=lost_ack, unknown=unknown, refused=refused, pages_blip=pages_blip,
    pages_dead_restore=pages_dead_restore, pages_dead=pages_dead, resume_kill=resume_kill, prepared_retry=prepared_retry,
    quiet_source=quiet_source, exec_race=exec_race, guest_calls=guest_calls, exec_background=exec_background, exec_pause_grace=exec_pause_grace, guest_hang=guest_hang,
    source_killed=source_killed, target_killed=target_killed, abort_superseded=abort_superseded, gen_zero=gen_zero,
    checkpoint_restore=checkpoint_restore, checkpoint_fork=checkpoint_fork, checkpoint_corrupt=checkpoint_corrupt,
    checkpoint_crash=checkpoint_crash, pause_resume=pause_resume, signals=signals, pause_lost=pause_lost, suspend_resume=suspend_resume,
    suspend_gen=suspend_gen, checkpoint_hotplug=checkpoint_hotplug, checkpoint_untrusted_dir=checkpoint_untrusted_dir,
    resume_failures=resume_failures, resume_unpause_fail=resume_unpause_fail, abort_link_fail=abort_link_fail, resume_unsettled=resume_unsettled, resume_slow_guest=resume_slow_guest, resume_readdress_fail=resume_readdress_fail, held_restore_frozen=held_restore_frozen, cow_exact=cow_exact, cow_rescue_fail=cow_rescue_fail, cow_collapsed=skippable(cow_collapsed), unplug_collapsed=no_evict(skippable(unplug_collapsed)), cow_abort=cow_abort,
    cow_crash=cow_crash, cow_reports_held=cow_reports_held, ckpt_incremental=ckpt_incremental, ckpt_hot=ckpt_hot,
    ckpt_failed_stop=ckpt_failed_stop, ckpt_rearm=ckpt_rearm, ckpt_dir_moved=ckpt_dir_moved,
    prepare_disconnect=prepare_disconnect, prepare_trickle=prepare_trickle, prepare_fail=prepare_fail,
    fc_prepare=fc_prepare, slow_preload=slow_preload, bad_preload=bad_preload, ckpt_packet_hold=ckpt_packet_hold, ckpt_stall=ckpt_stall, standby=standby,
    suspend_disk_freed=suspend_disk_freed, resume_mark_fails=resume_mark_fails, kill_source=kill_source,
    kill_refused_checkpoint=no_evict(kill_refused_checkpoint), wildcard_listen=wildcard_listen, peer_by_name=peer_by_name, peer_moved=peer_moved, page_refusals=page_refusals,
    forged_peer=forged_peer, restore_ip_peer=restore_ip_peer, spoof_filter=spoof_filter, spoof_csum=spoof_csum, late_withdrawal=late_withdrawal, unlend_retry=unlend_retry,
    unit_restart=unit_restart, log_cap=log_cap, gc_debris=gc_debris, prefix_change=prefix_change, arrival_log=arrival_log, template_tap=template_tap,
    incoming_killed=incoming_killed, start_killed=start_killed, claim_killed=claim_killed, standby_stalled=standby_stalled, standby_refill_race=standby_refill_race, standby_lock_timeout=standby_lock_timeout, fc_died=fc_died,
    sigkill_restart=sigkill_restart, listen_trickle=listen_trickle,
    cow_wp_race=cow_wp_race, fetch_tail_enomem=fetch_tail_enomem, fetch_enomem_stuck=fetch_enomem_stuck, pull_enomem=pull_enomem,
    collapse_abort=collapse_abort, collapse_ckpt_fail=collapse_ckpt_fail, ckpt_paused_backlog=ckpt_paused_backlog, same_host_order=same_host_order, same_host_slow_route=same_host_slow_route, same_host_flood=same_host_flood, same_host_late_handover=same_host_late_handover, same_host_backlog=same_host_backlog, ckpt_backlog=ckpt_backlog, rx_stall=rx_stall, arrival_abort_route=arrival_abort_route, arrival_killed_route=arrival_killed_route,
    handoff_superseded=handoff_superseded, delayed_announce=delayed_announce, announce_arp_timer=announce_arp_timer,
    prepare_fail_announce=prepare_fail_announce, reconcile_announce=reconcile_announce, reconcile_kill=reconcile_kill, resume_pull_lock=resume_pull_lock, page_conns=page_conns, suspend_cmd=suspend_cmd, suspend_overlap=suspend_overlap, fc_died_busy=fc_died_busy, pause_cmd_start=pause_cmd_start, suspend_died=suspend_died)
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

