#!/usr/bin/env bash
# Simulates a LAN with two flexvm hosts and a client, using network namespaces:
#
#   fvA  192.168.100.1   host A, hands out VM addresses .128-.191
#   fvB  192.168.100.2   host B, hands out VM addresses .192-.250
#   fvC  192.168.100.10  a plain client machine
#
# usage: netlab.sh up | down | daemons | stop
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
flexvm=$root/target/release/flexvm

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

daemons() {
  # ip netns exec remounts sysfs; restore the host cgroup2 hierarchy there.
  ip netns exec fvA sh -c 'mount -t cgroup2 none /sys/fs/cgroup && exec "$@"' sh "$flexvm" daemon --listen 192.168.100.1:7070 --peer 192.168.100.2:7070 \
    --announce-dev eth0 --vm-ips 192.168.100.128-192.168.100.191 > "$root/daemon-A.log" 2>&1 &
  ip netns exec fvB sh -c 'mount -t cgroup2 none /sys/fs/cgroup && exec "$@"' sh "$flexvm" daemon --listen 192.168.100.2:7070 --peer 192.168.100.1:7070 \
    --announce-dev eth0 --vm-ips 192.168.100.192-192.168.100.250 > "$root/daemon-B.log" 2>&1 &
  sleep 1
}

stop() {
  pkill -x flexvm || true
  pkill -x firecracker || true
  # Capture each netns inode before down removes the namespace.
  local h inode cg
  for h in A B; do
    inode=$(stat -L -c %i "/run/netns/fv$h" 2>/dev/null) || continue
    if [[ $h == A ]]; then
      cg=/sys/fs/cgroup/flexvm/192_168_100_1_7070_ns$inode
    else
      cg=/sys/fs/cgroup/flexvm/192_168_100_2_7070_ns$inode
    fi
    [[ -d $cg ]] || continue
    echo 1 > "$cg/cgroup.kill" 2>/dev/null || true
    find "$cg" -mindepth 1 -depth -type d -exec rmdir {} + 2>/dev/null || true
    rmdir "$cg" 2>/dev/null || true
  done
}

"${1:-up}"
