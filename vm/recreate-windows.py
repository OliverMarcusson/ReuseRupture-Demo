#!/usr/bin/env python3
"""Recreate only the Windows VM, preserving attacker container state and cached ISOs."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rrlib import ROOT, banner, load_config, run, step, virsh, warn


def main() -> int:
    cfg = load_config()
    vm_name = cfg["windows"]["vm_name"]
    disk = Path(f"/var/lib/libvirt/images/{vm_name}.qcow2")

    banner("Recreate Windows VM", "This removes only the generated Windows VM and disk.")
    answer = input(f"Type RECREATE-WINDOWS to delete {vm_name} and reinstall it: ")
    if answer != "RECREATE-WINDOWS":
        return 130

    step(f"Removing Windows VM {vm_name}")
    virsh(["destroy", vm_name], check=False)
    virsh(["undefine", vm_name, "--snapshots-metadata"], check=False)

    if disk.exists():
        step(f"Deleting generated Windows disk {disk}")
        run(["rm", "-f", str(disk)], sudo=True)
    else:
        warn(f"Windows disk was not present: {disk}")

    step("Starting fresh Windows installation")
    run([str(ROOT / "vm/create-windows.py")])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
