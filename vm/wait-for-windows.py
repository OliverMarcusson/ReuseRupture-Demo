#!/usr/bin/env python3
"""vm/wait-for-windows.py."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rrlib import ensure_domain_running, load_config, set_domain_boot_to_disk, set_domain_interface_model, wait_for_vm_tcp, warn


def main() -> int:
    cfg = load_config()
    vm_name = cfg["windows"]["vm_name"]
    set_domain_boot_to_disk(vm_name)
    if set_domain_interface_model(vm_name, "e1000e"):
        warn("Windows VM network adapter was changed to e1000e for stock Windows driver support.")
        warn("The change applies after the next full VM restart.")
    ensure_domain_running(vm_name)
    return 0 if wait_for_vm_tcp(vm_name, cfg["windows"]["ip"], int(cfg["windows"]["winrm_port"]), 1800, boot_from_disk=True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
