#!/usr/bin/env bash
# Rootless regression tests; no flexvm processes or VMs are started.
set -euo pipefail
source "$(dirname "$0")/net-common.sh"
work=$(mktemp -d)
pids=()
trap 'for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; rm -rf "$work"' EXIT
state=$work/state
flexvm=$(command -v bash)
mkfifo "$work/wait"
exec 3<>"$work/wait"

# A matching executable, a different executable with the same arguments, and
# matching executables whose state is merely a substring or part of another argument.
"$flexvm" -c 'read -r -t 30 <&3 || true' --state "$work/a/state" &
ours=$!
pids+=("$ours")
python3 -c 'import time; time.sleep(30)' --state "$work/a/state" &
pids+=("$!")
"$flexvm" -c 'read -r -t 30 <&3 || true' --state "$work/a/state-extra" &
pids+=("$!")
"$flexvm" -c 'read -r -t 30 <&3 || true' "--state $work/a/state" &
pids+=("$!")
sleep 0.1
[[ $(state_processes "$work/a") == "$ours" ]]

# A rebuild must not hide processes still running the old executable.
cp "$flexvm" "$work/flexvm"
flexvm=$work/flexvm
"$flexvm" -c 'read -r -t 30 <&3 || true' --state "$work/a/state" &
old=$!
pids+=("$old")
sleep 0.1
[[ $(state_processes "$work/a") == "$old" ]]
rm "$flexvm"
[[ $(state_processes "$work/a") == "$old" ]]

mkdir -p "$state/templates/.states"
printf '%s\n' "$work/a/state" > "$state/templates/.states/a"
printf '%s\n' "$work/ab/state" > "$state/templates/.states/ab"
forget_states "$work/a"
[[ ! -e $state/templates/.states/a && -f $state/templates/.states/ab ]]

# Exercise shared teardown against fake cgroups and a mock kill, never /sys or a VM.
(
    mkdir "$work/vm-123-456" "$work/idle-123-456-0"
    state_processes() { echo 123; }
    process_cgroups() {
        [[ $1 == 123 ]]
        printf '%s\n' "$work/vm-123-456" "$work/idle-123-456-0"
    }
    kill() { [[ $1 == -9 && $2 == 123 ]]; touch "$work/killed"; }
    sleep() { :; }
    stop_states "$work/a"
    [[ -f $work/killed && ! -d $work/vm-123-456 && ! -d $work/idle-123-456-0 ]]
)
echo 'PASS: network cleanup helpers'
