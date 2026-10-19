# Shared cleanup for netlab.sh, nettest.sh and test.sh. Sourced with `state` and `flexvm` set.

# Forget states below each DIR as users of STATE's templates (#869).
forget_states() {
    local f d
    for f in "$state"/templates/.states/*; do
        [[ -f $f ]] || continue
        for d in "$@"; do
            if [[ $(cat "$f" 2>/dev/null) == "$(realpath -m "$d")"/* ]]; then
                rm -f "$f"
            fi
        done
    done
    return 0
}

# Match the executable and a whole --state argument, not text inside another program's command line.
state_processes() {
    local p arg prev d exe expected
    expected=$(realpath -m "$flexvm")
    for p in /proc/[0-9]*; do
        if [[ ! $p/exe -ef $flexvm ]]; then
            # A rebuild can replace the binary while the lab is still running.
            exe=$(readlink "$p/exe" 2>/dev/null) || continue
            [[ $exe == "$expected (deleted)" ]] || continue
        fi
        prev=
        while IFS= read -r -d '' arg; do
            if [[ $prev == --state ]]; then
                for d in "$@"; do
                    if [[ $arg == "$d/state" ]]; then
                        echo "${p#/proc/}"
                        break 2
                    fi
                done
            fi
            prev=$arg
        done < "$p/cmdline" 2>/dev/null || true
    done
    return 0
}

# Read PID-START before killing: both the VM's scope and its Firecrackers' idle groups use it.
process_cgroups() {
    local pid start cg
    for pid in "$@"; do
        start=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f20) || continue
        [[ $start =~ ^[0-9]+$ ]] || continue
        for cg in /sys/fs/cgroup/flexvm/vm-"$pid-$start" /sys/fs/cgroup/flexvm/idle-"$pid-$start"-*; do
            [[ ! -d $cg ]] || echo "$cg"
        done
    done
    return 0
}

stop_states() {
    local pid cg
    local -a pids cgroups
    mapfile -t pids < <(state_processes "$@")
    mapfile -t cgroups < <(process_cgroups "${pids[@]}")
    for pid in "${pids[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
    sleep 1
    for cg in "${cgroups[@]}"; do rmdir "$cg" 2>/dev/null || true; done
}
