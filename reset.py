#!/usr/bin/env python3
"""reset.py."""

from __future__ import annotations

from scripts.rrlib import ROOT, banner, docker_compose, info, load_config, run, step, virsh


def restore_snapshot(vm_name: str, snapshot_name: str) -> None:
    if virsh(["dominfo", vm_name], check=False).returncode != 0:
        info(f"VM {vm_name} does not exist; cannot restore snapshot.")
        return

    step(f"Restoring {vm_name} to snapshot {snapshot_name}")
    virsh(["destroy", vm_name], check=False)
    virsh(["snapshot-revert", vm_name, snapshot_name, "--running"])


def main() -> int:
    config = load_config()
    banner("ReuseRupture Reset", "Restoring the clean lab snapshot and verifying readiness.")
    snapshot_name = config["demo"]["snapshot_name"]

    restore_snapshot(config["windows"]["vm_name"], snapshot_name)

    step("Restarting attacker container")
    docker_compose(["up", "-d", "--build", "attacker"])

    run([str(ROOT / "vm/wait-for-windows.py")])
    return run([str(ROOT / "scripts/verify-lab.py")], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
