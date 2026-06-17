#!/usr/bin/env python3
"""vm/create-kali.py."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rrlib import ROOT, cfg_path, info, load_config, ok, resolve_vm_resources, run, set_domain_boot_to_disk, start_viewer, step, virt_install, virsh


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def preseed(cfg: dict) -> str:
    kali = cfg["kali"]
    win = cfg["windows"]
    net = cfg["network"]
    ad = cfg["active_directory"]
    user = kali["username"]
    return f"""d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select se
d-i keyboard-configuration/layoutcode string se
d-i console-keymaps-at/keymap select se
d-i netcfg/choose_interface select auto
d-i netcfg/disable_autoconfig boolean true
d-i netcfg/get_ipaddress string {kali["ip"]}
d-i netcfg/get_netmask string {net["netmask"]}
d-i netcfg/get_gateway string {net["gateway"]}
d-i netcfg/get_nameservers string {win["ip"]}
d-i netcfg/get_hostname string {kali["hostname"]}
d-i netcfg/get_domain string {ad["domain_name"]}
d-i mirror/country string manual
d-i mirror/http/hostname string {kali["mirror_hostname"]}
d-i mirror/http/directory string {kali["mirror_directory"]}
d-i mirror/http/proxy string
d-i passwd/root-login boolean false
d-i passwd/user-fullname string Kali
d-i passwd/username string {user}
d-i passwd/user-password password {kali["password"]}
d-i passwd/user-password-again password {kali["password"]}
d-i clock-setup/utc boolean true
d-i time/zone string Europe/Stockholm
d-i partman-auto/disk string /dev/vda
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i apt-setup/non-free-firmware boolean true
tasksel tasksel/first multiselect standard, ssh-server
d-i pkgsel/include string openssh-server sudo python3 python3-venv python3-pip curl git
d-i pkgsel/upgrade select none
popularity-contest popularity-contest/participate boolean false
d-i grub-installer/only_debian boolean true
d-i grub-installer/with_other_os boolean true
d-i grub-installer/bootdev string /dev/vda
grub-pc grub-pc/install_devices multiselect /dev/vda
grub-pc grub-pc/install_devices_empty boolean false
d-i debian-installer/exit/poweroff boolean false
d-i finish-install/reboot_in_progress note
d-i preseed/late_command string in-target /bin/sh -c "echo '{user} ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/reuserupture"; in-target chmod 0440 /etc/sudoers.d/reuserupture; in-target systemctl enable ssh; in-target localectl set-keymap se; in-target localectl set-x11-keymap se; umount /cdrom || true; eject /cdrom || true
"""


def patch_installer_entry(text: str) -> str:
    """Point Kali boot menus at our preseed and make the default entry automatic."""
    text = text.replace(
        "preseed/file=/cdrom/simple-cdd/default.preseed",
        "preseed/file=/cdrom/preseed.cfg auto=true priority=critical",
    )
    return text


def patch_grub_config(text: str) -> str:
    text = patch_installer_entry(text)
    if "set timeout=" not in text:
        text = "set default=0\nset timeout=3\n" + text
    return text


def patch_isolinux_config(text: str) -> str:
    text = text.replace("timeout 0", "timeout 30")
    if "default installgui" not in text:
        text = text.replace("default vesamenu.c32", "default installgui")
    return text


def extract_text_from_iso(iso: Path, iso_path: str, destination: Path) -> str:
    run([
        "xorriso",
        "-osirrox",
        "on",
        "-indev",
        str(iso),
        "-extract",
        iso_path,
        str(destination),
    ])
    return destination.read_text(encoding="utf-8")


def build_autoinstall_iso(source_iso: Path, cfg: dict) -> Path:
    """Create a Kali ISO that boots the installer normally with our preseed."""
    kali = cfg["kali"]
    output_iso = cfg_path(kali.get("autoinstall_iso_path", "iso/kali-reuserupture-autoinstall.iso"))

    step("Building Kali autoinstall ISO")
    work_dir = ROOT / ".cache/kali-autoinstall"
    run(["rm", "-rf", str(work_dir)], check=False)
    work_dir.mkdir(parents=True, exist_ok=True)

    preseed_file = work_dir / "preseed.cfg"
    isolinux_cfg = work_dir / "isolinux.cfg"
    isolinux_gtk = work_dir / "gtk.cfg"
    grub_cfg = work_dir / "grub.cfg"

    preseed_file.write_text(preseed(cfg), encoding="utf-8")
    isolinux_cfg.write_text(
        patch_isolinux_config(extract_text_from_iso(source_iso, "/isolinux/isolinux.cfg", work_dir / "isolinux.cfg.orig")),
        encoding="utf-8",
    )
    isolinux_gtk.write_text(
        patch_installer_entry(extract_text_from_iso(source_iso, "/isolinux/gtk.cfg", work_dir / "gtk.cfg.orig")),
        encoding="utf-8",
    )
    grub_cfg.write_text(
        patch_grub_config(extract_text_from_iso(source_iso, "/boot/grub/grub.cfg", work_dir / "grub.cfg.orig")),
        encoding="utf-8",
    )

    output_iso.parent.mkdir(parents=True, exist_ok=True)
    output_iso.unlink(missing_ok=True)
    run([
        "xorriso",
        "-indev",
        str(source_iso),
        "-outdev",
        str(output_iso),
        "-map",
        str(preseed_file),
        "/preseed.cfg",
        "-map",
        str(isolinux_cfg),
        "/isolinux/isolinux.cfg",
        "-map",
        str(isolinux_gtk),
        "/isolinux/gtk.cfg",
        "-map",
        str(grub_cfg),
        "/boot/grub/grub.cfg",
        "-boot_image",
        "any",
        "replay",
    ])
    ok(f"Kali autoinstall ISO written to {output_iso}")
    return output_iso


def main() -> int:
    cfg = load_config()
    kali = cfg["kali"]
    memory_mb, vcpus = resolve_vm_resources(cfg, "kali")
    if virsh(["dominfo", kali["vm_name"]], check=False, capture=True).returncode == 0:
        ok(f"Kali VM {kali['vm_name']} already exists; reusing it")
        return 0

    disk = Path(f"/var/lib/libvirt/images/{kali['vm_name']}.qcow2")
    image_path = str(kali.get("image_path") or "")
    if image_path and Path(image_path).exists():
        step("Importing Kali qcow2 image")
        info(f"Source image: {image_path}")
        run(["cp", image_path, str(disk)], sudo=True)
        virt_install(["--name", kali["vm_name"], "--memory", str(memory_mb), "--vcpus", str(vcpus), "--disk", f"path={disk},format=qcow2,bus=virtio", "--os-variant", "debian12", "--network", f"network={cfg['network']['name']},model=virtio", "--import", "--noautoconsole"])
        start_viewer(kali["vm_name"])
        return 0

    iso = cfg_path(kali["iso_path"])
    if not iso.exists():
        if not kali.get("download_iso", True):
            raise SystemExit(f"Kali ISO not found: {iso}")
        iso.parent.mkdir(parents=True, exist_ok=True)
        step("Downloading Kali installer ISO")
        info(kali["iso_url"])
        run([
            "aria2c",
            "--continue=true",
            "--max-connection-per-server=8",
            "--split=8",
            "--summary-interval=5",
            "--dir",
            str(iso.parent),
            "--out",
            iso.name,
            kali["iso_url"],
        ])
    else:
        info(f"Using local Kali ISO: {iso}")
    if iso.exists():
        step("Verifying Kali ISO checksum")
        if sha256(iso).lower() != str(kali["iso_sha256"]).lower():
            raise SystemExit(f"Kali ISO SHA-256 mismatch: {iso}")
        ok("Kali ISO checksum verified")

    autoinstall_iso = build_autoinstall_iso(iso, cfg)

    if disk.exists():
        info(f"Reusing existing Kali disk: {disk}")
    else:
        step("Creating Kali VM disk")
        run(["qemu-img", "create", "-f", "qcow2", str(disk), f"{kali['disk_gb']}G"], sudo=True)
    step("Starting unattended Kali installation")
    virt_install([
        "--name",
        kali["vm_name"],
        "--memory",
        str(memory_mb),
        "--vcpus",
        str(vcpus),
        "--disk",
        f"path={disk},format=qcow2,bus=virtio",
        "--cdrom",
        str(autoinstall_iso),
        "--os-variant",
        "debian12",
        "--network",
        f"network={cfg['network']['name']},model=virtio",
        "--boot",
        "cdrom,hd",
        "--graphics",
        "spice",
        "--noautoconsole",
    ])
    set_domain_boot_to_disk(kali["vm_name"])
    start_viewer(kali["vm_name"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
