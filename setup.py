#!/usr/bin/env python3
"""setup.py."""

from __future__ import annotations

import argparse
import shutil
import subprocess

from scripts.rrlib import (
    ROOT,
    banner,
    cfg_path,
    docker_compose,
    download_url,
    ensure_config_exists,
    info,
    load_config,
    ok,
    render_inventory,
    require_cmds,
    run,
    step,
    warn,
)


# Commands setup.py needs on the host. If they are all present we skip package
# installation entirely.
REQUIRED_COMMANDS = [
    "python3", "pip3", "ansible", "ansible-galaxy", "ansible-playbook",
    "docker", "virsh", "virt-install", "virt-xml", "qemu-img",
    "curl", "sha256sum", "xorriso", "cpio", "gzip", "aria2c",
]

# Per-distro package sets, keyed by the package-manager binary we detect.
# `update` runs first (optional); `install` is the install command prefix;
# `available` is a read-only query (package name appended) whose exit code tells
# us whether the package is installable on this system.
#
# A package entry is either a single name, or a tuple of alternatives in
# preference order — the first installable name wins. Alternatives absorb the
# package renames that happen across distro releases (for example
# `freerdp2-x11` becoming `freerdp3-x11` on newer Ubuntu, or the transitional
# `qemu-kvm` becoming `qemu-system-x86`).
PACKAGE_MANAGERS = {
    "apt-get": {
        "label": "Debian/Ubuntu (apt)",
        "update": ["apt-get", "update"],
        "install": ["apt-get", "install", "-y"],
        "available": ["apt-cache", "show"],
        "packages": [
            "ansible", "coreutils", "cpio", "curl", "docker.io",
            ("docker-compose-v2", "docker-compose-plugin", "docker-compose"),
            ("freerdp3-x11", "freerdp2-x11"), "gzip", "libvirt-clients",
            "libvirt-daemon-system", "python3", "python3-pip", "python3-winrm",
            "python3-yaml", ("qemu-system-x86", "qemu-kvm"), "qemu-utils",
            "sshpass", "virtinst", "xorriso", "aria2",
        ],
    },
    "dnf": {
        "label": "Fedora (dnf)",
        "install": ["dnf", "install", "-y"],
        "available": ["dnf", "list"],
        "packages": [
            "ansible", "coreutils", "cpio", "curl", "docker",
            ("docker-compose", "docker-compose-plugin"), "freerdp", "gzip",
            "libvirt", "python3", "python3-pip", "python3-winrm",
            "python3-PyYAML", "qemu-img", "qemu-kvm", "sshpass",
            "virt-install", "xorriso", "aria2",
        ],
    },
    "pacman": {
        "label": "Arch (pacman)",
        "install": ["pacman", "-S", "--needed", "--noconfirm"],
        "available": ["pacman", "-Si"],
        "packages": [
            "ansible", "coreutils", "cpio", "curl", "docker", "docker-compose",
            "freerdp", "gzip", "libvirt", "libvirt-glib", "make", "gcc",
            "python", "python-pip", "python-pywinrm", "python-yaml",
            "qemu-desktop", "sshpass", "virt-install", "xorriso", "aria2",
        ],
    },
}


def resolve_packages(spec: dict) -> tuple[list[str], list[str]]:
    """Resolve the package list against what this package manager can install.

    Returns ``(to_install, skipped)``. For tuple entries the first installable
    alternative is chosen; entries with no installable candidate are reported as
    skipped instead of aborting the whole install.
    """
    test = spec.get("available")
    to_install: list[str] = []
    skipped: list[str] = []
    for entry in spec["packages"]:
        candidates = [entry] if isinstance(entry, str) else list(entry)
        if test is None:
            to_install.append(candidates[0])
            continue
        chosen = next(
            (c for c in candidates
             if run([*test, c], check=False, capture=True).returncode == 0),
            None,
        )
        if chosen is not None:
            to_install.append(chosen)
        else:
            skipped.append("/".join(candidates))
    return to_install, skipped


def install_host_dependencies() -> None:
    step("Checking host dependencies")
    if require_cmds(REQUIRED_COMMANDS):
        ok("Host dependencies are already installed")
        return

    for binary, spec in PACKAGE_MANAGERS.items():
        if not shutil.which(binary):
            continue
        info(f"Installing host packages with {spec['label']}")
        if spec.get("update"):
            run(spec["update"], sudo=True)

        packages, skipped = resolve_packages(spec)
        if skipped:
            warn("Skipping packages not available in this distro's repositories: " + ", ".join(skipped))
            warn("If a later step reports a missing tool, install the equivalent package manually.")

        if packages and run([*spec["install"], *packages], sudo=True, check=False).returncode != 0:
            warn("Batch package install failed; retrying packages individually.")
            failed = [
                pkg for pkg in packages
                if run([*spec["install"], pkg], sudo=True, check=False).returncode != 0
            ]
            if failed:
                warn("Packages that could not be installed: " + ", ".join(failed))
        break
    else:
        raise SystemExit(
            "Unsupported package manager. Install these manually: libvirt, qemu, "
            "virt-install, Ansible, PyYAML, curl, xorriso, cpio, gzip."
        )

    if require_cmds(REQUIRED_COMMANDS):
        ok("Host dependencies installed")
    else:
        warn("Some required commands are still missing after package installation.")
        warn("Install the equivalents for your distribution, then rerun ./setup.py.")


def ensure_virtio_iso() -> None:
    cfg = load_config()
    virtio = cfg.get("windows", {}).get("virtio", {})
    if not virtio.get("enabled", True):
        info("VirtIO is disabled in config; skipping VirtIO ISO preparation")
        return
    iso = cfg_path(virtio.get("iso_path", "iso/virtio-win.iso"))
    if iso.exists():
        ok(f"VirtIO ISO already present: {iso}")
        return
    if not virtio.get("download_iso", True):
        raise SystemExit(f"VirtIO ISO is missing and windows.virtio.download_iso is false: {iso}")
    step("Downloading VirtIO Windows driver ISO")
    download_url(str(virtio["iso_url"]), iso, str(virtio.get("iso_sha256") or ""))
    ok(f"VirtIO ISO downloaded: {iso}")


def start_docker_services() -> None:
    if not shutil.which("systemctl"):
        return
    step("Starting Docker service")
    run(["systemctl", "enable", "--now", "docker.service"], check=False, sudo=True)
    ok("Docker service startup attempted")


def prepare_attacker_container() -> None:
    cfg = load_config()
    step("Building and starting Docker attacker")
    docker_compose(["up", "-d", "--build", "attacker"])
    host_line = f"{cfg['windows']['ip']} {cfg['windows']['hostname']} {cfg['windows']['hostname']}.{cfg['active_directory']['domain_name']}"
    docker_compose(["exec", "-T", "attacker", "sh", "-c", f"grep -q ' {cfg['windows']['hostname']}\\.' /etc/hosts || echo '{host_line}' >> /etc/hosts"])
    check = docker_compose(["exec", "-T", "attacker", "reuserupture", "--help"], check=False, capture=True)
    if check.returncode != 0:
        warn((check.stdout + check.stderr).strip())
        raise SystemExit("Attacker container started, but reuserupture --help failed.")
    ok("Docker attacker is ready")


def start_libvirt_services() -> None:
    if not shutil.which("systemctl"):
        return
    step("Starting libvirt services")
    units = [
        "libvirtd.service", "virtqemud.service", "virtqemud.socket",
        "virtnetworkd.service", "virtnetworkd.socket", "virtstoraged.service",
        "virtstoraged.socket", "virtlogd.service", "virtlogd.socket",
    ]
    for unit in units:
        if run(["systemctl", "list-unit-files", unit], check=False, capture=True).returncode == 0:
            run(["systemctl", "enable", "--now", unit], check=False, sudo=True)
    ok("Libvirt service startup attempted")


def wait_for_management_services() -> int:
    step("Waiting for VM management services")
    checks = [
        ("Windows WinRM", ROOT / "vm/wait-for-windows.py"),
    ]

    for label, script in checks:
        result = run([str(script)], check=False)
        if result.returncode != 0:
            warn(f"{label} did not become reachable in time.")
            warn("Setup is stopping cleanly so you can inspect the VM windows.")
            warn("Useful checks:")
            warn("  virsh -c qemu:///system list --all")
            warn("After fixing the VM state, continue with:")
            warn("  ./setup.py --ansible-only")
            return result.returncode

    ok("VM management services are reachable")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-vm-creation", action="store_true")
    parser.add_argument("--ansible-only", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    banner("ReuseRupture Lab Setup", "This prepares the VMs, Active Directory, attack tooling, and flag callback.")
    ensure_config_exists()
    install_host_dependencies()
    start_docker_services()
    start_libvirt_services()

    if args.verify_only:
        step("Verify-only mode selected")
        render_inventory()
        return run([str(ROOT / "scripts/verify-lab.py")], check=False).returncode

    render_inventory()
    ensure_virtio_iso()
    prepare_attacker_container()

    if not args.skip_vm_creation and not args.ansible_only:
        step("Creating or reusing lab VM")
        result = run([str(ROOT / "vm/create-lab.py")], check=False)
        if result.returncode != 0:
            warn("VM setup failed. Inspect the VM state with 'virsh -c qemu:///system list --all' and rerun ./setup.py when ready.")
            return result.returncode
    else:
        info("Skipping VM creation")

    if not args.ansible_only:
        wait_rc = wait_for_management_services()
        if wait_rc != 0:
            return wait_rc

    try:
        step("Installing required Ansible collections")
        run(["ansible-galaxy", "collection", "install", "-r", str(ROOT / "requirements.yml")])
        step("Running Ansible lab configuration")
        run(["ansible-playbook", "-i", str(ROOT / "inventory/hosts.yml"), str(ROOT / "playbooks/site.yml")])
        step("Running final lab verification")
        rc = run([str(ROOT / "scripts/verify-lab.py")], check=False).returncode
    except subprocess.CalledProcessError as exc:
        warn(f"Setup command failed: {' '.join(map(str, exc.cmd))}")
        warn("Fix the issue above, then rerun ./setup.py or ./setup.py --ansible-only.")
        return exc.returncode
    if rc == 0:
        banner("Setup Complete", "Start the demonstration with: ./demo.py --yes")
    else:
        banner("Setup Finished With Verification Failures", "Review the failed checks above before running the demo.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
