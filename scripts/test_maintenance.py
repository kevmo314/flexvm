#!/usr/bin/env python3
"""Regression checks for lab cleanup without running VMs or touching processes."""
import ast
from pathlib import Path
import subprocess
import unittest

SCRIPTS = Path(__file__).resolve().parent


class MaintenanceTests(unittest.TestCase):
    def test_fault_runner_continues_and_cleans_up_after_failure(self):
        tree = ast.parse((SCRIPTS / "faults.py").read_text())
        loop = next(node for node in tree.body if isinstance(node, ast.For)
                    and isinstance(node.target, ast.Name) and node.target.id == "s")
        events = []
        state = dict(names=["bad", "good"], scenario_vms=set(),
                     scenario_checkpoints=set(), A="A", B="B", failures=0)

        def bad():
            state["scenario_vms"].add("vm")
            state["scenario_checkpoints"].add("checkpoint")
            raise AssertionError("injected failure")

        def check(label, cond, detail):
            state["failures"] += not cond

        state.update(SCENARIOS=dict(bad=bad, good=lambda: events.append("good")),
                     check=check, disarm=lambda: events.append("disarm"),
                     rpc=lambda host, req, timeout: events.append((host, req["name"])),
                     rm_ckpt=lambda path: events.append(path))
        exec(compile(ast.Module(body=[loop], type_ignores=[]), "fault runner", "exec"), state)
        self.assertEqual(state["failures"], 1)
        self.assertEqual(events, ["disarm", ("A", "vm"), ("B", "vm"), "checkpoint", "good", "disarm"])

    def test_netlab_kills_only_processes_from_lab_namespaces(self):
        # Override commands in a child shell; no real namespace or process changes.
        command = r'''
        ip() {
          if [[ $1 == netns && $2 == pids ]]; then
            case "$3" in fvA) echo 11;; fvB) echo 12;; esac
          fi
        }
        cat() { case "$1" in /proc/11/comm) echo firecracker;; /proc/12/comm) echo flexvm;; esac; }
        kill() { echo "kill $1"; }
        pkill() { echo "UNSCOPED KILL"; }
        stat() { return 1; }
        export -f ip cat kill pkill stat
        bash "$1" stop
        '''
        result = subprocess.run(["bash", "-c", command, "test", str(SCRIPTS / "netlab.sh")],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.splitlines(), ["kill 11", "kill 12"])


if __name__ == "__main__":
    unittest.main()
