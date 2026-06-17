#!/usr/bin/env python3
"""vm/create-lab.py."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rrlib import ROOT, load_config, ok, run, step, virsh


def main() -> int:
    cfg = load_config()
    step("Preparing isolated libvirt network")
    run([str(ROOT / "vm/create-network.py")])
    step("Preparing Windows domain controller VM")
    run([str(ROOT / "vm/create-windows.py")])
    step("Starting Windows VM")
    virsh(["start", cfg["windows"]["vm_name"]], check=False)
    ok("Windows VM start command issued")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
