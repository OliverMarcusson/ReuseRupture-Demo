#!/usr/bin/env -S PYTHONPATH=. python3
"""vm/create-network.py."""


import tempfile
from pathlib import Path

from scripts.rrlib import info, load_config, ok, virsh


def main():
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
    try:
        virsh(["net-define", path])
    finally:
        Path(path).unlink(missing_ok=True)
    virsh(["net-start", name])
    virsh(["net-autostart", name])
    ok(f"Network {name} created and marked autostart")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
