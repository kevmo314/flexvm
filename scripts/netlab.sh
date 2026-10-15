#!/usr/bin/env bash
# Simulates a LAN with two flexvm hosts and a client, using network namespaces:
#
#   fvA  192.168.100.1   host A, hands out VM addresses .128-.191
#   fvB  192.168.100.2   host B, hands out VM addresses .192-.250
#   fvC  192.168.100.10  a plain client machine
#
# usage: netlab.sh up | down | listeners | stop | fv A|B ARGS...
# The hosts use the artifacts and templates of STATE (default /var/lib/flexvm).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
flexvm=$root/target/release/flexvm
state=$(realpath -m "${STATE:-/var/lib/flexvm}")

up() {
  ip netns add fvlan
  ip -n fvlan link add br0 type bridge
  ip -n fvlan link set br0 up
  for spec in A:192.168.100.1 B:192.168.100.2 C:192.168.100.10; do
    h=${spec%%:*} addr=${spec#*:}
    ip netns add "fv$h"
    ip link add eth0 netns "fv$h" type veth peer name "p$h" netns fvlan
    ip -n fvlan link set "p$h" master br0 up
    ip -n "fv$h" addr add "$addr/24" dev eth0
    ip -n "fv$h" link set eth0 up
    ip -n "fv$h" link set lo up
  done
}

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

listeners() {
  for h in A B; do
    mkdir -p "/run/flexvm-lab-$h/state"
    ln -sfn "$state/artifacts" "/run/flexvm-lab-$h/state/artifacts"
    ln -sfn "$state/templates" "/run/flexvm-lab-$h/state/templates"
  done
  fv A listen 192.168.100.1:7070 --peer 192.168.100.2:7070 \
    --announce-dev eth0 --vm-ips 192.168.100.128-192.168.100.191 > "$root/listen-A.log" 2>&1 &
  fv B listen 192.168.100.2:7070 --peer 192.168.100.1:7070 \
    --announce-dev eth0 --vm-ips 192.168.100.192-192.168.100.250 > "$root/listen-B.log" 2>&1 &
  sleep 1
}

stop() {
  # The lab's listeners and VM processes, by their state directories (each
  # VM's Firecracker dies with its process).
  local p pids= ids=
  for p in /proc/[0-9]*; do
    { tr '\0' ' ' < "$p/cmdline"; } 2>/dev/null | grep -q -- "--state /run/flexvm-lab-" && pids+=" ${p#/proc/}"
  done
  # PID-START, read before the kill: the cgroups are named after the instance (`idle-PID-START-N`).
  for p in $pids; do ids+=" $p-$(sed 's/.*) //' "/proc/$p/stat" 2>/dev/null | cut -d' ' -f20)"; done
  for p in $pids; do kill -9 "$p" 2>/dev/null || true; done
  sleep 1
  for p in $ids; do
    for cg in /sys/fs/cgroup/flexvm/idle-"$p"-*; do
      [[ -d $cg ]] && rmdir "$cg" 2>/dev/null || true
    done
  done
  rm -rf /run/flexvm-lab-A /run/flexvm-lab-B
}

"${@:-up}"
