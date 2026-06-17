#!/usr/bin/env python3
"""vm/wait-for-kali.py."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rrlib import cold_boot_domain, ensure_domain_running, load_config, set_domain_boot_to_disk, step, wait_for_vm_tcp, warn


def main() -> int:
    cfg = load_config()
    vm_name = cfg["kali"]["vm_name"]
    boot_config_changed = set_domain_boot_to_disk(vm_name)

    if boot_config_changed:
        warn("Kali still had installer direct-kernel boot configured.")
        step("Forcing one cold boot now so Kali starts from the installed disk")
        cold_boot_domain(vm_name)
    else:
        ensure_domain_running(vm_name)

    return 0 if wait_for_vm_tcp(vm_name, cfg["kali"]["ip"], int(cfg["kali"]["ssh_port"]), 900, boot_from_disk=True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
