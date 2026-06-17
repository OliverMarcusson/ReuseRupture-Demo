#!/usr/bin/env python3
"""destroy.py."""


from pathlib import Path

from scripts.rrlib import cfg_path, docker_compose, info, load_config, ok, run, step, virsh


def destroy_vm(vm_name):
    if virsh(["dominfo", vm_name], check=False).returncode != 0:
        return

    step(f"Destroying VM {vm_name}")
    virsh(["destroy", vm_name], check=False)
    virsh(["undefine", vm_name, "--snapshots-metadata"], check=False)


def delete_generated_disk(vm_name):
    disk_path = Path(f"/var/lib/libvirt/images/{vm_name}.qcow2")
    if disk_path.exists():
        step(f"Deleting generated VM disk {disk_path}")
        run(["rm", "-f", str(disk_path)], sudo=True)


def main():
    config = load_config()
    answer = input("Destroy ReuseRupture Windows VM, attacker container, and libvirt network? Type DESTROY: ")
    if answer != "DESTROY":
        return 130

    step("Stopping attacker container")
    docker_compose(["down"], check=False)
    destroy_vm(config["windows"]["vm_name"])
    delete_generated_disk(config["windows"]["vm_name"])

    network_name = config["network"]["name"]
    if virsh(["net-info", network_name], check=False).returncode == 0:
        virsh(["net-destroy", network_name], check=False)
        virsh(["net-undefine", network_name])

    virtio_iso = cfg_path(config["windows"].get("virtio", {}).get("iso_path", "iso/virtio-win.iso"))
    if virtio_iso.exists():
        delete_iso = input(f"Delete cached VirtIO ISO at {virtio_iso}? [y/N] ").strip().lower()
        if delete_iso in {"y", "yes"}:
            virtio_iso.unlink()
            ok("Deleted cached VirtIO ISO")
        else:
            info("Keeping cached VirtIO ISO")

    print("Destroyed generated lab resources. The Windows ISO was not touched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
