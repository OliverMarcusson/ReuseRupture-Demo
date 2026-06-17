#!/usr/bin/env python3
"""vm/create-network.py."""

from __future__ import annotations

import tempfile
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rrlib import info, load_config, ok, virsh


def main() -> int:
    cfg = load_config()
    name = cfg["network"]["name"]
    if virsh(["net-info", name], check=False, capture=True).returncode == 0:
        info(f"Network {name} already exists; reusing it")
        virsh(["net-start", name], check=False)
        virsh(["net-autostart", name])
        ok(f"Network {name} is active")
        return 0
    info(f"Defining network {name} on {cfg['network']['subnet']}")
    xml = f"""<network>
  <name>{name}</name>
  <bridge name='virbr-rr' stp='on' delay='0'/>
  <ip address='{cfg["network"]["gateway"]}' netmask='{cfg["network"]["netmask"]}'/>
</network>
"""
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write(xml)
        path = fh.name
    virsh(["net-define", path])
    virsh(["net-start", name])
    virsh(["net-autostart", name])
    ok(f"Network {name} created and marked autostart")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
