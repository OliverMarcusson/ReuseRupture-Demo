#!/usr/bin/env -S PYTHONPATH=. python3
"""vm/wait-for-windows.py."""


from scripts.rrlib import cold_boot_domain, ensure_domain_running, load_config, set_domain_boot_to_disk, set_domain_interface_model, wait_for_vm_tcp, windows_nic_model


def main():
    cfg = load_config()
    vm_name = cfg["windows"]["vm_name"]
    set_domain_boot_to_disk(vm_name)
    if set_domain_interface_model(vm_name, windows_nic_model(cfg)):
        cold_boot_domain(vm_name)
    else:
        ensure_domain_running(vm_name)
    return 0 if wait_for_vm_tcp(vm_name, cfg["windows"]["ip"], int(cfg["windows"]["winrm_port"]), 1800, boot_from_disk=True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
