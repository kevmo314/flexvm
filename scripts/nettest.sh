#!/usr/bin/env bash
# Measures what a TCP connection and a UDP stream see while a VM migrates
# A -> B -> A, in a private network-namespace lab that only touches its own
# namespaces, processes, state directories and cgroups. Run as root.
#
#   ${P}A   $NET.1   host A, VM addresses $NET.128-$NET.191
#   ${P}B   $NET.2   host B, VM addresses $NET.192-$NET.250
#   ${P}C   $NET.10  client: a TCP ping-pong and a sequence-numbered UDP stream
#
# Fails if a TCP round trip stalls longer than twice the longer migration
# downtime of its round (a lost packet costs a retransmit timeout, >= 200 ms)
# or the UDP stream loses more than MAX_UDP_LOSS datagrams in a round.
# Reordered datagrams are reported, not checked.
#
# env: FLEXVM (binary), STATE (whose artifacts and templates to use), P (namespace prefix, default fv5), NET
#      (default 192.168.155), ROUNDS (default 3), UDP_PPS (default 5000),
#      MAX_UDP_LOSS (default 0), PORT (listeners, default 7070), WORK (keep logs under this
#      directory, default /tmp), TEMPLATE (default default)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
flexvm=${FLEXVM:-$root/target/release/flexvm}
state=$(realpath -m "${STATE:-/var/lib/flexvm}")
P=${P:-fv5}
NET=${NET:-192.168.155}
ROUNDS=${ROUNDS:-3}
UDP_PPS=${UDP_PPS:-5000}
MAX_UDP_LOSS=${MAX_UDP_LOSS:-0}
PORT=${PORT:-7070}
host_A=$NET.1:$PORT
host_B=$NET.2:$PORT
dir_A=/run/$P-a
dir_B=/run/$P-b
name=nettest-$$
work=${WORK:+$(mkdir -p "$WORK" && mktemp -d "$WORK/nettest.XXXXXX")}
work=${work:-$(mktemp -d /tmp/flexvm-nettest.XXXXXX)}
listener_pids=()
bg_pids=()
failed=0

say() { printf '%s\n' "$*" >&2; }
die() { say "FAIL: $*"; exit 1; }

# flexvm on host A or B, in its namespace (with the cgroup2 hierarchy that
# `ip netns exec`'s fresh sysfs lacks).
cli() {
    local ns=$1 dir=$2
    shift 2
    timeout 60s ip netns exec "$ns" sh -c 'mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null; exec "$@"' sh \
        "$flexvm" --state "$dir/state" --run "$dir/run" "$@"
}

wait_for() {
    local deadline=$((SECONDS + 60))
    until "$@" >/dev/null 2>&1; do
        (( SECONDS < deadline )) || die "timed out waiting for: $*"
        sleep 0.2
    done
}

# Our processes: listeners and VM processes, by the state directories on
# their command lines (their Firecrackers die with them).
our_processes() {
    local p
    for p in /proc/[0-9]*; do
        { tr '\0' ' ' < "$p/cmdline"; } 2>/dev/null | grep -qE -- "--state ($dir_A|$dir_B)/state" && echo "${p#/proc/}"
    done
}

teardown() {
    local pid cg pids ids=
    trap - EXIT INT TERM
    set +e
    for pid in "${bg_pids[@]}"; do kill "$pid" 2>/dev/null; done
    for pid in "${bg_pids[@]}"; do wait "$pid" 2>/dev/null; done
    pids=$(our_processes)
    # PID-START, read before the kill: the cgroups are named after the instance.
    for pid in $pids; do ids+=" $pid-$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f20)"; done
    for pid in $pids; do kill -9 "$pid" 2>/dev/null; done
    sleep 1
    for ns in "${P}A" "${P}B" "${P}C" "${P}lan"; do ip netns del "$ns" 2>/dev/null; done
    # Each VM process's Firecracker had a cgroup named after the process (`idle-PID-START-N`).
    for pid in $ids; do
        for cg in /sys/fs/cgroup/flexvm/idle-"$pid"-*; do
            [[ -d $cg ]] && rmdir "$cg" 2>/dev/null
        done
    done
    cp "$dir_A"/run/vms/*.log "$dir_B"/run/vms/*.log "$work"/ 2>/dev/null
    rm -rf "$dir_A" "$dir_B"
    if (( failed )); then say "logs kept in $work"; else rm -rf "$work"; fi
}

[[ $EUID == 0 ]] || die 'run as root'
[[ -x $flexvm ]] || die "no flexvm binary at $flexvm"
for ns in "${P}A" "${P}B" "${P}C" "${P}lan"; do
    ip netns list | awk -v ns="$ns" '$1==ns {f=1} END {exit !f}' && die "namespace $ns exists; another nettest is running or left it behind"
done
trap 'failed=1; teardown' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ip netns add "${P}lan"
ip -n "${P}lan" link add br0 type bridge
ip -n "${P}lan" link set br0 up
for spec in A:1 B:2 C:10; do
    h=${spec%%:*}
    ip netns add "$P$h"
    ip link add eth0 netns "$P$h" type veth peer name "p$h" netns "${P}lan"
    ip -n "${P}lan" link set "p$h" master br0 up
    ip -n "$P$h" addr add "$NET.${spec#*:}/24" dev eth0
    ip -n "$P$h" link set eth0 up
    ip -n "$P$h" link set lo up
done
start_listener() {
    local ns=$1 dir=$2 listen=$3 peer=$4 ips=$5
    mkdir -p "$dir/state" "$dir/run"
    ln -sfn "$state/artifacts" "$dir/state/artifacts"
    ln -sfn "$state/templates" "$dir/state/templates"
    cli "$ns" "$dir" config --peer "$peer" --vm-ips "$ips" --cluster-ips "$NET.128-$NET.250" > /dev/null
    cli "$ns" "$dir" listen "$listen" > "$work/listen-$ns.log" 2>&1 &
    listener_pids+=($!)
}
start_listener "${P}A" "$dir_A" "$host_A" "$host_B" "$NET.128-$NET.191"
start_listener "${P}B" "$dir_B" "$host_B" "$host_A" "$NET.192-$NET.250"
wait_for test -f "$dir_A/state/host.json"
wait_for test -f "$dir_B/state/host.json"
sleep 0.5

addr=$(cli "${P}A" "$dir_A" run "$name" --template "${TEMPLATE:-default}" -d | python3 -c 'import json,sys; print(json.load(sys.stdin)["ip"])')
say "vm $name at $addr"

cat > "$work/server.py" <<'PY'
import json, socket, threading

# TCP echo for the ping-pong, one connection per round.
def tcp():
    with socket.socket() as l:
        l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        l.bind(("0.0.0.0", 19012))
        l.listen(4)
        while True:
            conn, _ = l.accept()
            def echo(conn):
                with conn:
                    while data := conn.recv(4096):
                        conn.sendall(data)
            threading.Thread(target=echo, args=(conn,), daemon=True).start()

# UDP sequence receiver: 8-byte sequence numbers; "STOP <sent>" ends a round
# and writes its counts to /tmp/udp-<round>.json.
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
    s.bind(("0.0.0.0", 19013))
    seen, top, reordered, dups, done, gaps = set(), -1, 0, 0, set(), []
    while True:
        d, _ = s.recvfrom(2048)
        if d.startswith(b"STOP"):
            _, rnd, sent = d.split()
            sent = int(sent)
            if rnd in done:
                continue
            done.add(rnd)
            with open(f"/tmp/udp-{rnd.decode()}.json", "w") as f:
                missing = sorted(set(range(sent)) - seen)
                runs = []
                for m in missing:
                    if runs and runs[-1][1] == m:
                        runs[-1][1] = m + 1
                    else:
                        runs.append([m, m + 1])
                json.dump({"sent": sent, "received": len(seen), "lost": len(missing), "reordered": reordered, "duplicates": dups,
                           "lost_runs": [f"{a}..{b}" for a, b in runs[:5]], "late": gaps[:5]}, f)
            seen, top, reordered, dups, gaps = set(), -1, 0, 0, []
            continue
        n = int.from_bytes(d[:8], "big")
        if n in seen:
            dups += 1
        elif n < top:
            reordered += 1
            if len(gaps) < 5:
                gaps.append(f"{n}<{top}")
        seen.add(n)
        top = max(top, n)

threading.Thread(target=tcp, daemon=True).start()
open("/tmp/fv-server-ready", "w").write("ready")
udp()
PY
cli "${P}A" "$dir_A" exec "$name" "sysctl -qw net.core.rmem_max=33554432 2>/dev/null || echo 33554432 > /proc/sys/net/core/rmem_max; cat > /tmp/fv-server.py <<'PY'
$(cat "$work/server.py")
PY
python3 /tmp/fv-server.py </dev/null >/tmp/fv-server.log 2>&1 &"
wait_for cli "${P}A" "$dir_A" exec "$name" 'test -f /tmp/fv-server-ready'

cat > "$work/client.py" <<'PY'
import pathlib, socket, struct, sys, time

address, directory, rnd, pps = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3], int(sys.argv[4])
stop = directory / "stop"

def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    n, start = 0, time.monotonic()
    while not stop.exists():
        due = start + n / pps
        while time.monotonic() < due:
            pass
        s.sendto(n.to_bytes(8, "big") + int(time.time() * 1e6).to_bytes(8, "big") + bytes(48), (address, 19013))
        n += 1
    time.sleep(1)  # let stragglers arrive
    for _ in range(5):
        s.sendto(f"STOP {rnd} {n}".encode(), (address, 19013))
        time.sleep(0.05)
    print(f"UDP sent {n}", flush=True)

if sys.argv[5] == "udp":
    udp()
    sys.exit()
worst, count, stalls = 0.0, 0, []
try:
    with socket.create_connection((address, 19012), timeout=15) as conn:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while not stop.exists():
            payload = struct.pack("!Q", count)
            start = time.monotonic()
            conn.sendall(payload)
            reply = b""
            while len(reply) < len(payload):
                chunk = conn.recv(len(payload) - len(reply))
                if not chunk:
                    raise RuntimeError("unexpected EOF")
                reply += chunk
            if reply != payload:
                raise RuntimeError("payload mismatch")
            took = time.monotonic() - start
            worst = max(worst, took)
            if took > 0.03:
                stalls.append(f"{took * 1000:.0f}")
            count += 1
            (directory / "progress.new").write_text(str(count))
            (directory / "progress.new").replace(directory / "progress")
            time.sleep(0.01)
finally:
    print(f"stalls over 30 ms: {' '.join(stalls) or 'none'}", flush=True)
    print(f"TCP {count} round trips, worst stall {worst * 1000:.1f} ms", flush=True)
    stop.touch()
PY

progress_after() {
    kill -0 "$client_pid" 2>/dev/null || { cat "$work/client-$round.log" >&2; die 'client exited early'; }
    [[ -f $work/progress ]] && (( $(cat "$work/progress") > $1 ))
}
absent() {
    local listing
    listing=$(cli "$1" "$2" ls) || return 1
    awk -v n="$name" 'NR>1 && $1==n {f=1} END {exit f}' <<< "$listing"
}
running() { cli "$1" "$2" ls | awk -v n="$name" 'NR>1 && $1==n && $4=="running" {f=1} END {exit !f}'; }
migrate() {
    local res
    res=$(cli "$1" "$2" migrate "$name" "$3") || die "migrate to $3 failed"
    python3 -c 'import json,sys; r=json.load(sys.stdin); print("  migrate downtime %s ms, rerouted %s ms, held %s" % (r["downtime_ms"], r["rerouted_ms"], r.get("held")))' <<< "$res" >&2
    python3 -c 'import json,sys; print(json.load(sys.stdin)["downtime_ms"])' <<< "$res" >> "$work/downtime-$round"
    wait_for running "$4" "$5"
    wait_for absent "$1" "$2"
}

failures=0
for round in $(seq 1 "$ROUNDS"); do
    rm -f "$work/stop" "$work/progress"
    # TCP first: once it runs, the client has resolved the VM's address (proxy ARP).
    ip netns exec "${P}C" python3 "$work/client.py" "$addr" "$work" "$round" "$UDP_PPS" tcp > "$work/client-$round.log" 2>&1 &
    client_pid=$!
    bg_pids+=("$client_pid")
    wait_for progress_after 0
    ip netns exec "${P}C" python3 "$work/client.py" "$addr" "$work" "$round" "$UDP_PPS" udp > "$work/udp-$round.log" 2>&1 &
    udp_pid=$!
    bg_pids+=("$udp_pid")
    sleep 0.5
    migrate "${P}A" "$dir_A" "$host_B" "${P}B" "$dir_B"
    before=$(cat "$work/progress"); wait_for progress_after "$before"
    sleep 0.5
    migrate "${P}B" "$dir_B" "$host_A" "${P}A" "$dir_A"
    before=$(cat "$work/progress"); wait_for progress_after "$before"
    sleep 0.5
    touch "$work/stop"
    wait "$client_pid" || { cat "$work/client-$round.log" >&2; die 'client failed'; }
    wait "$udp_pid" || { cat "$work/udp-$round.log" >&2; die 'udp sender failed'; }
    wait_for cli "${P}A" "$dir_A" exec "$name" "test -f /tmp/udp-$round.json"
    udp=$(cli "${P}A" "$dir_A" exec "$name" "cat /tmp/udp-$round.json")
    sed -n 's/^stalls/  TCP stalls/p' "$work/client-$round.log" >&2
    python3 - "$work/client-$round.log" "$work/downtime-$round" "$udp" "$MAX_UDP_LOSS" "$round" <<'PY' || failures=$((failures + 1))
import json, re, sys
log, downtimes, udp, max_loss, rnd = sys.argv[1:]
stall = float(re.search(r"worst stall ([\d.]+) ms", open(log).read()).group(1))
downtime = max(float(x) for x in open(downtimes).read().split())
udp = json.loads(udp)
ok = stall <= 2 * downtime and udp["lost"] <= int(max_loss)
print(f"round {rnd}: {'ok' if ok else 'FAIL'}: TCP worst stall {stall:.0f} ms (longer downtime {downtime:.0f} ms); "
      f"UDP {udp['sent']} sent, {udp['lost']} lost, {udp['reordered']} reordered")
if udp["lost"] or udp["reordered"]:
    print(f"  UDP lost {udp['lost_runs']}, late {udp['late']}")
sys.exit(not ok)
PY
done
(( failures == 0 )) || die "$failures of $ROUNDS rounds"
echo PASS
trap - EXIT
teardown
