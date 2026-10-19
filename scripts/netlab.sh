#!/usr/bin/env bash
# Simulates a LAN with two flexvm hosts and a client, using network namespaces:
#
#   fvA  192.168.100.1   host A, hands out VM addresses .128-.191
#   fvB  192.168.100.2   host B, hands out VM addresses .192-.250
#   fvC  192.168.100.10  a plain client machine
#
# usage: netlab.sh up | down | listeners | stop | fv A|B ARGS...
# The hosts use the artifacts and templates of STATE (default $FLEXVM_STATE_DIR, else /var/lib/flexvm).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
flexvm=$root/target/release/flexvm
state=$(realpath -m "${STATE:-${FLEXVM_STATE_DIR:-/var/lib/flexvm}}")
source "$root/scripts/net-common.sh"

up() (
  created=()
  trap 'for ns in "${created[@]}"; do ip netns del "$ns" 2>/dev/null || true; done' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  ip netns add fvlan
  created+=(fvlan)
  ip -n fvlan link add br0 type bridge
  ip -n fvlan link set br0 up
  for spec in A:192.168.100.1 B:192.168.100.2 C:192.168.100.10; do
    h=${spec%%:*} addr=${spec#*:}
    ip netns add "fv$h"
    created=("fv$h" "${created[@]}")
    ip link add eth0 netns "fv$h" type veth peer name "p$h" netns fvlan
    ip -n fvlan link set "p$h" master br0 up
    ip -n "fv$h" addr add "$addr/24" dev eth0
    ip -n "fv$h" link set eth0 up
    ip -n "fv$h" link set lo up
  done
  trap - EXIT INT TERM
)

down() {
  stop || true
  for ns in fvA fvB fvC fvlan; do ip netns del "$ns" 2>/dev/null || true; done
}

# flexvm on host A or B (STATE/RUN under /run/flexvm-lab-<host>), in its
# namespace, with the cgroup2 hierarchy that `ip netns exec`'s sysfs lacks.
fv() {
  local h=$1
  shift
  ip netns exec "fv$h" sh -c 'mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null; exec "$@"' sh \
    "$flexvm" --state "/run/flexvm-lab-$h/state" --run "/run/flexvm-lab-$h/run" "$@"
}

# Host $1's STATE/host.json, written whole and atomically (a fresh lab has none to merge with).
host_json() {
  local f=/run/flexvm-lab-$1/state/host.json
  printf '%s\n' "$2" > "$f.tmp"
  chmod 644 "$f.tmp"
  mv -f "$f.tmp" "$f"
}

listeners() {
  for h in A B; do
    mkdir -p "/run/flexvm-lab-$h/state"
    ln -sfn "$state/artifacts" "/run/flexvm-lab-$h/state/artifacts"
    ln -sfn "$state/templates" "/run/flexvm-lab-$h/state/templates"
  done
  host_json A '{"peers": ["192.168.100.2:7070"], "vm_ips": "192.168.100.128-192.168.100.191", "cluster_ips": "192.168.100.128-192.168.100.250"}'
  host_json B '{"peers": ["192.168.100.1:7070"], "vm_ips": "192.168.100.192-192.168.100.250", "cluster_ips": "192.168.100.128-192.168.100.250"}'
  fv A listen 192.168.100.1:7070 > "$root/listen-A.log" 2>&1 &
  fv B listen 192.168.100.2:7070 > "$root/listen-B.log" 2>&1 &
  sleep 1
}

stop() {
  stop_states /run/flexvm-lab-A /run/flexvm-lab-B
  forget_states /run/flexvm-lab-A /run/flexvm-lab-B
  rm -rf /run/flexvm-lab-A /run/flexvm-lab-B
}

case "${1:-up}" in
  up|down|listeners|stop)
    if (( $# > 1 )); then echo 'usage: netlab.sh up | down | listeners | stop | fv A|B ARGS...' >&2; exit 2; fi
    "${1:-up}"
    ;;
  fv)
    shift
    if [[ ${1:-} != A && ${1:-} != B ]]; then echo 'usage: netlab.sh fv A|B ARGS...' >&2; exit 2; fi
    fv "$@"
    ;;
  *) echo 'usage: netlab.sh up | down | listeners | stop | fv A|B ARGS...' >&2; exit 2 ;;
esac
