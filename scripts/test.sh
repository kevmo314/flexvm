#!/usr/bin/env bash
# Root/KVM integration test. Build artifacts and the default template as in README.md first.
# netlab down stops ALL flexvm/firecracker processes: use a dedicated test host.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
flexvm=$root/target/release/flexvm
netlab=$root/scripts/netlab.sh
host_A=192.168.100.1:7070
host_B=192.168.100.2:7070
name=fv-test-$$
checks=('lab setup' 'run/exec/kill and address release' 'four migrations preserve RAM and process' 'TCP through two migrations' 'pressure migration' 'teardown leaves no resources')
results=(SKIP SKIP SKIP SKIP SKIP SKIP)
current=0
work=
client_pid=
lab_started=0

fail() { echo "$*" >&2; exit 1; }
pass() { results[current]=PASS; printf 'PASS: %s\n' "${checks[current]}"; }

cli() {
    local ns=$1 host=$2
    shift 2
    timeout 60s ip netns exec "$ns" "$flexvm" --host "$host" "$@"
}

# main.rs prints run as JSON, ls as NAME IP TEMPLATE STATE ... (one header row),
# and exec streams guest stdout/stderr and returns the guest exit status.
run_ip() {
    python3 -c 'import ipaddress,json,sys; print(ipaddress.IPv4Address(json.load(sys.stdin)["ip"]))'
}
listed() {
    local listing
    listing=$(cli "$1" "$2" ls) || return 1
    awk -v name="$name" -v addr="$3" 'NR>1 && $1==name && $2==addr && $4=="running" {found=1} END {exit !found}' <<< "$listing"
}
absent() {
    local listing
    listing=$(cli "$1" "$2" ls) || return 1
    awk -v name="$name" 'NR>1 && $1==name {found=1} END {exit found}' <<< "$listing"
}
wait_for() {
    local deadline=$((SECONDS + 60))
    until "$@"; do
        (( SECONDS < deadline )) || fail "Timed out waiting for: $*"
        sleep 0.2
    done
}

resources_gone() {
    local links children ns
    if pgrep -x firecracker >/dev/null; then return 1; fi
    links=$(ip -o link show) || return 1
    if awk -F ': ' '$2 ~ /^fv/ {found=1} END {exit !found}' <<< "$links"; then return 1; fi
    # Also inspect any remaining named namespaces, not only the initial namespace.
    while read -r ns _; do
        [[ -n "$ns" ]] || continue
        links=$(ip -n "$ns" -o link show) || return 1
        if awk -F ': ' '$2 ~ /^fv/ {found=1} END {exit !found}' <<< "$links"; then return 1; fi
        case "$ns" in fvA|fvB|fvC|fvlan) return 1 ;; esac
    done < <(ip netns list)
    if [[ -d /sys/fs/cgroup/flexvm ]]; then
        # Daemon-level directories may remain, but no VM or idle-pool children may.
        children=$(find /sys/fs/cgroup/flexvm -mindepth 2 -type d) || return 1
        [[ -z "$children" ]] || return 1
    fi
}

finish() {
    local status=$? deadline i passed=0 failed=0 skipped=0
    trap - EXIT INT TERM
    set +e
    if (( status != 0 )); then
        results[current]=FAIL
        printf 'FAIL: %s (exit %s)\n' "${checks[current]}" "$status"
    fi
    if [[ -n "$client_pid" ]]; then
        kill "$client_pid" 2>/dev/null
        wait "$client_pid" 2>/dev/null
    fi
    if (( lab_started )); then
        if ! "$netlab" down; then
            results[5]=FAIL
            echo 'FAIL: netlab.sh down'
        fi
        deadline=$((SECONDS + 10))
        until resources_gone; do
            (( SECONDS < deadline )) || break
            sleep 0.2
        done
        if resources_gone && [[ ${results[5]} != FAIL ]]; then
            results[5]=PASS
            printf 'PASS: %s\n' "${checks[5]}"
        else
            results[5]=FAIL
            printf 'FAIL: %s\n' "${checks[5]}"
            pgrep -ax firecracker
            ip -o link show
            if [[ -d /sys/fs/cgroup/flexvm ]]; then
                find /sys/fs/cgroup/flexvm -mindepth 2 -type d
            fi
        fi
    fi
    for i in "${!checks[@]}"; do
        case ${results[i]} in
            PASS) passed=$((passed + 1)) ;;
            FAIL) failed=$((failed + 1)) ;;
            SKIP)
                skipped=$((skipped + 1))
                if (( i == 4 )); then
                    echo 'SKIP: pressure migration (namespaces share host RAM; forcing pressure risks host OOM)'
                else
                    printf 'SKIP: %s (prerequisite failed)\n' "${checks[i]}"
                fi ;;
        esac
    done
    printf 'Summary: %d PASS, %d FAIL, %d SKIP\n' "$passed" "$failed" "$skipped"
    if (( failed != 0 || status != 0 )); then
        echo "See $root/daemon-A.log and $root/daemon-B.log for daemon diagnostics." >&2
        if [[ -n "$work" ]]; then echo "Test diagnostics retained in $work" >&2; fi
        exit 1
    fi
    if [[ -n "$work" ]]; then rm -rf -- "$work"; fi
}

# Do not tear down an existing lab when prerequisites have not been met.
[[ $EUID == 0 ]] || fail 'Run scripts/test.sh as root on a dedicated KVM host.'
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || fail 'Readable/writable /dev/kvm is required.'
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for tool in ip python3 timeout pgrep pkill awk find; do
    command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool"
done
[[ -x "$flexvm" ]] || fail 'Build target/release/flexvm first.'
[[ -x "$netlab" ]] || fail 'scripts/netlab.sh must be executable.'
for ns in fvA fvB fvC fvlan; do
    if ip netns list | awk -v ns="$ns" '$1==ns {found=1} END {exit !found}'; then
        fail "Existing namespace $ns; tear down the old lab first."
    fi
done
work=$(mktemp -d /tmp/flexvm-test.XXXXXX)
lab_started=1
"$netlab" up
"$netlab" daemons
wait_for cli fvA "$host_A" ls
wait_for cli fvB "$host_B" ls
pass

current=1
addr=$(cli fvA "$host_A" run "$name" | run_ip)
listed fvA "$host_A" "$addr" || fail 'ls did not report the new VM and address.'
[[ $(cli fvA "$host_A" exec "$name" 'printf flexvm-exec-ok') == flexvm-exec-ok ]] || fail 'Guest exec output mismatch.'
if cli fvA "$host_A" exec "$name" 'exit 7'; then
    fail 'exec did not propagate a guest failure.'
else
    code=$?
    [[ $code == 7 ]] || fail "exec returned $code instead of guest exit 7."
fi
cli fvA "$host_A" kill "$name"
absent fvA "$host_A" || fail 'Killed VM is still listed.'
# Reclaim the exact address, rather than assuming the allocator reuses its first slot.
reclaimed=$(cli fvA "$host_A" run "$name" --ip "$addr" | run_ip)
[[ $reclaimed == "$addr" ]] || fail 'Killed VM address was not released.'
pass

current=2
cli fvA "$host_A" exec "$name" 'set -e; dd if=/dev/urandom of=/tmp/fv-data bs=1M count=200 status=none; sleep 1000 </dev/null >/tmp/fv-sleep.log 2>&1 & echo $! > /tmp/fv-sleep.pid'
checksum=$(cli fvA "$host_A" exec "$name" 'md5sum /tmp/fv-data')
process=$(cli fvA "$host_A" exec "$name" 'p=$(cat /tmp/fv-sleep.pid); kill -0 "$p"; cat /proc/"$p"/stat')
# PID plus /proc start time distinguish the original process from PID reuse.
identity=$(awk '{print $1, $22}' <<< "$process")
verify_guest() {
    local actual
    [[ $(cli "$1" "$2" exec "$name" 'md5sum /tmp/fv-data') == "$checksum" ]] || fail 'Guest RAM file checksum changed.'
    actual=$(cli "$1" "$2" exec "$name" 'set -e; p=$(cat /tmp/fv-sleep.pid); kill -0 "$p"; test "$(cat /proc/"$p"/comm)" = sleep; cat /proc/"$p"/stat')
    [[ $(awk '{print $1, $22}' <<< "$actual") == "$identity" ]] || fail 'Background process identity changed.'
    [[ $(awk '{print $3}' <<< "$actual") != Z ]] || fail 'Background process became a zombie.'
}
migrate() {
    local source=$1 source_host=$2 target=$3 target_host=$4
    cli "$source" "$source_host" migrate "$name" --to "$target_host"
    wait_for listed "$target" "$target_host" "$addr"
    # Post-copy returns before release. Wait for source removal before reusing its name.
    wait_for absent "$source" "$source_host"
}
for round in 1 2; do
    migrate fvA "$host_A" fvB "$host_B"
    verify_guest fvB "$host_B"
    migrate fvB "$host_B" fvA "$host_A"
    verify_guest fvA "$host_A"
done
pass

current=3
cat > "$work/server.py" <<'PY'
import socket

with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 19012))
    listener.listen(1)
    with open("/tmp/fv-server-ready", "w") as ready:
        ready.write("ready")
    # Exactly one accepted connection: there is no reconnect path.
    conn, _ = listener.accept()
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)
PY
cli fvA "$host_A" exec "$name" "cat > /tmp/fv-server.py <<'PY'
$(cat "$work/server.py")
PY
python3 /tmp/fv-server.py </dev/null >/tmp/fv-server.log 2>&1 &"
wait_for cli fvA "$host_A" exec "$name" 'test -f /tmp/fv-server-ready'
cat > "$work/client.py" <<'PY'
import pathlib
import socket
import struct
import sys
import time

address, directory = sys.argv[1:]
work = pathlib.Path(directory)
worst = 0.0
count = 0
# A single connect attempt; any timeout, EOF, mismatch or socket error is fatal.
try:
    with socket.create_connection((address, 19012), timeout=15) as conn:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while not (work / "stop").exists():
            payload = struct.pack("!Q", count)
            start = time.monotonic()
            conn.sendall(payload)
            reply = b""
            while len(reply) < len(payload):
                chunk = conn.recv(len(payload) - len(reply))
                if not chunk:
                    raise RuntimeError("unexpected EOF; reconnect forbidden")
                reply += chunk
            if reply != payload:
                raise RuntimeError("ping-pong payload mismatch")
            worst = max(worst, time.monotonic() - start)
            count += 1
            (work / "progress.new").write_text(str(count))
            (work / "progress.new").replace(work / "progress")
            time.sleep(0.01)
finally:
    print(f"TCP: {count} round trips, worst stall {worst * 1000:.3f} ms", flush=True)
PY
ip netns exec fvC python3 "$work/client.py" "$addr" "$work" > "$work/client.log" 2>&1 &
client_pid=$!
progress_after() {
    kill -0 "$client_pid" 2>/dev/null || { cat "$work/client.log" >&2; fail 'TCP client exited prematurely.'; }
    [[ -f "$work/progress" ]] && (( $(cat "$work/progress") > $1 ))
}
wait_for progress_after 0
migrate fvA "$host_A" fvB "$host_B"
before=$(cat "$work/progress")
wait_for progress_after "$before"
migrate fvB "$host_B" fvA "$host_A"
before=$(cat "$work/progress")
wait_for progress_after "$before"
touch "$work/stop"
if wait "$client_pid"; then
    client_pid=
else
    client_pid=
    cat "$work/client.log" >&2
    fail 'TCP ping-pong failed.'
fi
cat "$work/client.log"
verify_guest fvA "$host_A"
pass
# Leave the VM and warm pool alive: the EXIT trap must prove down cleans them up.
current=5
