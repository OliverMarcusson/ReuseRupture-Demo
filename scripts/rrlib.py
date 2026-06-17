#!/usr/bin/env python3
"""Shared Python helpers for ReuseRupture lab scripts."""

from __future__ import annotations

import json
import os
import hashlib
import shutil
import socket
import subprocess
import sys
import time
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONFIG_FILE = Path(os.environ.get("CONFIG_FILE", ROOT / "config.yml"))
LIBVIRT_URI = os.environ.get("RR_LIBVIRT_URI", "qemu:///system")


def utc_stamp(fmt: str = "%Y%m%dT%H%M%SZ") -> str:
    return datetime.now(timezone.utc).strftime(fmt)


def banner(title: str, subtitle: str | None = None) -> None:
    line = "=" * 72
    print(f"\n{line}")
    print(title)
    if subtitle:
        print(subtitle)
    print(f"{line}\n")


def step(message: str) -> None:
    print(f"\n[>] {message}", flush=True)


def info(message: str) -> None:
    print(f"    {message}", flush=True)


def ok(message: str) -> None:
    print(f"[OK] {message}", flush=True)


def warn(message: str) -> None:
    print(f"[WARN] {message}", file=sys.stderr, flush=True)


def run(cmd: list[str], *, check: bool = True, cwd: Path | None = None, capture: bool = False, sudo: bool = False) -> subprocess.CompletedProcess:
    full = ["sudo", *cmd] if sudo else cmd
    kwargs = {
        "cwd": str(cwd or ROOT),
        "text": True,
        "check": check,
    }
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    return subprocess.run(full, **kwargs)  # type: ignore[arg-type]


def invoking_uid_gid() -> tuple[str, str]:
    """Return the real user's uid/gid, even when a script was launched by sudo."""
    return (
        os.environ.get("SUDO_UID") or str(os.getuid()),
        os.environ.get("SUDO_GID") or str(os.getgid()),
    )


def ensure_repo_writable_dir(path: Path) -> None:
    """Create a repo-local directory and repair common sudo ownership drift.

    Fresh Ubuntu installs often need sudo for Docker/libvirt until group
    membership has been applied. That can leave bind-mounted generated
    directories such as evidence/, inventory/, or iso/ owned by root, causing
    the next non-sudo run to fail with PermissionError. Limit the repair to
    paths inside this repository.
    """
    path = path.resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise SystemExit(f"Refusing to repair permissions outside the repo: {path}") from exc

    try:
        path.mkdir(parents=True, exist_ok=True)
        test = path / ".rr-write-test"
        test.write_text("", encoding="utf-8")
        test.unlink(missing_ok=True)
        return
    except OSError:
        uid, gid = invoking_uid_gid()
        run(["mkdir", "-p", str(path)], sudo=True)
        run(["chown", "-R", f"{uid}:{gid}", str(path)], sudo=True)
        path.mkdir(parents=True, exist_ok=True)
        test = path / ".rr-write-test"
        test.write_text("", encoding="utf-8")
        test.unlink(missing_ok=True)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def require_cmds(commands: Iterable[str]) -> bool:
    ok = True
    for cmd in commands:
        if not command_exists(cmd):
            print(f"Missing required command: {cmd}", file=sys.stderr)
            ok = False
    return ok


_docker_sudo: bool | None = None


def docker_prefix() -> list[str]:
    """Command prefix that lets docker reach the daemon socket.

    On a fresh install the user is not yet in the ``docker`` group, so the
    unprivileged client gets the classic "permission denied" on the socket.
    When that happens we fall back to ``sudo`` (if it can reach the daemon) so
    the current run still works; group membership only takes effect after the
    user logs in again. The decision is cached for the process.
    """
    global _docker_sudo
    if _docker_sudo is None:
        if not command_exists("docker"):
            _docker_sudo = False
        elif run(["docker", "info"], check=False, capture=True).returncode == 0:
            _docker_sudo = False
        else:
            _docker_sudo = run(["sudo", "docker", "info"], check=False, capture=True).returncode == 0
    return ["sudo"] if _docker_sudo else []


def docker_compose_base() -> list[str]:
    prefix = docker_prefix()
    if command_exists("docker") and run([*prefix, "docker", "compose", "version"], check=False, capture=True).returncode == 0:
        return [*prefix, "docker", "compose"]
    if command_exists("docker-compose"):
        return [*prefix, "docker-compose"]
    return [*prefix, "docker", "compose"]


def docker_compose(args: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return run([*docker_compose_base(), *args], check=check, capture=capture)


def attacker_exec(args: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return docker_compose(["exec", "-T", "attacker", *args], check=check, capture=capture)


def attacker_cmd(*args: str) -> list[str]:
    """Build a command list that runs `args` inside the attacker container."""
    return [*docker_compose_base(), "exec", "-T", "attacker", *args]


def container_path(path: Path) -> str:
    """Translate a host path under ROOT to its path inside the attacker container."""
    return "/opt/reuserupture/" + str(path.relative_to(ROOT))


def demo_auth_target(config: dict) -> str:
    """Build the `domain/user:password@ip` string the CLI expects."""
    ad = config["active_directory"]
    return f"{ad['domain_name']}/{ad['demo_username']}:{ad['demo_password']}@{config['windows']['ip']}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_url(url: str, output: Path, expected_sha256: str = "") -> None:
    try:
        output.parent.resolve().relative_to(ROOT)
    except ValueError:
        output.parent.mkdir(parents=True, exist_ok=True)
    else:
        ensure_repo_writable_dir(output.parent)
    tmp = output.with_suffix(output.suffix + ".part")
    downloader = ["curl", "-L", "--fail", "--progress-bar", "-o", str(tmp), url]
    if command_exists("aria2c"):
        downloader = ["aria2c", "--allow-overwrite=true", "--file-allocation=none", "-o", tmp.name, "-d", str(tmp.parent), url]
    run(downloader)
    if expected_sha256:
        actual = sha256_file(tmp)
        if actual.lower() != expected_sha256.lower():
            tmp.unlink(missing_ok=True)
            raise SystemExit(f"Checksum mismatch for {output}: expected {expected_sha256}, got {actual}")
    tmp.replace(output)


def ensure_config_exists() -> None:
    if CONFIG_FILE.exists():
        return
    warn("config.yml not found; creating it from config.example.yml.")
    shutil.copyfile(ROOT / "config.example.yml", CONFIG_FILE)


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config() -> dict:
    example = yaml.safe_load((ROOT / "config.example.yml").read_text(encoding="utf-8")) or {}
    user = yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) if CONFIG_FILE.exists() else {}
    return _deep_merge(example, user or {})


def cfg_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def render_inventory() -> None:
    step("Rendering Ansible inventory from config.yml")
    ensure_repo_writable_dir(ROOT / "inventory")
    ensure_repo_writable_dir(ROOT / "inventory/group_vars")
    inventory = run([str(ROOT / "scripts/render-config.py"), "--config", str(CONFIG_FILE), "--format", "inventory", "--validate"], capture=True)
    (ROOT / "inventory/hosts.yml").write_text(inventory.stdout, encoding="utf-8")
    all_vars = run([str(ROOT / "scripts/render-config.py"), "--config", str(CONFIG_FILE), "--format", "all-vars", "--validate"], capture=True)
    (ROOT / "inventory/group_vars/all.yml").write_text(all_vars.stdout, encoding="utf-8")
    ok("Inventory written to inventory/hosts.yml")


def redacted_config_json() -> str:
    return run([str(ROOT / "scripts/render-config.py"), "--config", str(CONFIG_FILE), "--format", "redacted-json", "--validate"], capture=True).stdout


def port_is_open(host: str, port: int, timeout: float = 2) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_tcp(host: str, port: int, timeout: int = 300) -> bool:
    info(f"Waiting up to {timeout}s for {host}:{port}")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_is_open(host, port):
            ok(f"{host}:{port} is reachable")
            return True
        time.sleep(5)
    print(f"Timed out waiting for {host}:{port}", file=sys.stderr)
    return False


def wait_for_vm_tcp(vm_name: str, host: str, port: int, timeout: int = 300, *, boot_from_disk: bool = False) -> bool:
    """Wait for a VM service and restart the VM if an installer left it shut off."""
    info(f"Waiting up to {timeout}s for {vm_name} at {host}:{port}")
    deadline = time.monotonic() + timeout
    last_state = ""
    next_state_check = 0.0

    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_state_check:
            state = virsh(["domstate", vm_name], check=False, capture=True)
            current_state = state.stdout.strip().lower() if state.returncode == 0 else "missing"

            if current_state != last_state:
                info(f"{vm_name} state: {current_state}")
                last_state = current_state

            if current_state in {"shut off", "shutdown", "crashed", "pmsuspended"}:
                if boot_from_disk:
                    set_domain_boot_to_disk(vm_name)
                step(f"Starting {vm_name}; the installer appears to have powered it off")
                virsh(["start", vm_name], check=False)

            next_state_check = now + 10

        try:
            with socket.create_connection((host, int(port)), timeout=2):
                ok(f"{host}:{port} is reachable")
                return True
        except OSError:
            time.sleep(5)

    print(f"Timed out waiting for {vm_name} at {host}:{port}", file=sys.stderr)
    return False


def virsh(args: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    base = ["virsh", "-c", LIBVIRT_URI, *args]
    if run(["virsh", "-c", LIBVIRT_URI, "list", "--all"], check=False, capture=True).returncode == 0:
        return run(base, check=check, capture=capture)
    return run(base, check=check, capture=capture, sudo=True)


def qemu_system_user() -> str | None:
    """The user QEMU runs as under qemu:///system, or None when it runs as root.

    Debian/Ubuntu run QEMU as the unprivileged `libvirt-qemu` user, which cannot
    read VM media that lives under a `0750` home directory. Distros that run
    QEMU as root (e.g. a default Arch install) have no such problem.
    """
    conf = Path("/etc/libvirt/qemu.conf")
    if conf.exists():
        try:
            lines = conf.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            warn(f"Could not read {conf}: {exc}. Falling back to QEMU account detection.")
        else:
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("user") and "=" in stripped:
                    user = stripped.split("=", 1)[1].strip().strip('"')
                    return None if user in ("", "root") else user
    for candidate in ("libvirt-qemu", "qemu"):
        if run(["getent", "passwd", candidate], check=False, capture=True).returncode == 0:
            return candidate
    return None


def grant_qemu_media_access(path: Path) -> None:
    """Let the qemu:///system user read `path` even when it lives outside the
    libvirt-managed directories (e.g. an ISO under the user's home, which is
    mode 0750 on Ubuntu so `libvirt-qemu` cannot traverse into it).

    Uses ACLs to grant traverse (x) on each ancestor directory and read (r) on
    the file itself — the minimal, targeted grant for a single service user.
    """
    if "system" not in LIBVIRT_URI:
        return
    user = qemu_system_user()
    if not user:
        return
    if not command_exists("setfacl"):
        warn(f"setfacl not found; QEMU ({user}) may be unable to read {path}.")
        warn(f"Install the 'acl' package, or grant access manually for {user}.")
        return
    path = path.resolve()
    run(["setfacl", "-m", f"u:{user}:r", str(path)], check=False, sudo=True)
    for parent in path.parents:
        if parent == Path("/"):
            break
        run(["setfacl", "-m", f"u:{user}:x", str(parent)], check=False, sudo=True)


def virt_install(args: list[str]) -> subprocess.CompletedProcess:
    base = ["virt-install", "--connect", LIBVIRT_URI, *args]
    if run(["virsh", "-c", LIBVIRT_URI, "list", "--all"], check=False, capture=True).returncode == 0:
        return run(base)
    return run(base, sudo=True)


def virt_xml(args: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    base = ["virt-xml", "--connect", LIBVIRT_URI, *args]
    if run(["virsh", "-c", LIBVIRT_URI, "list", "--all"], check=False, capture=True).returncode == 0:
        return run(base, check=check, capture=capture)
    return run(base, check=check, capture=capture, sudo=True)


def set_domain_boot_to_disk(vm_name: str) -> bool:
    """Remove direct installer kernel boot and make the VM boot from disk."""
    dump = virsh(["dumpxml", "--inactive", vm_name], check=False, capture=True)
    if dump.returncode != 0:
        warn(f"Could not read inactive libvirt XML for {vm_name}.")
        return False

    root = ET.fromstring(dump.stdout)
    os_node = root.find("os")
    if os_node is None:
        warn(f"Domain {vm_name} has no <os> XML node.")
        return False

    changed = False

    for tag in ["kernel", "initrd", "cmdline"]:
        for node in list(os_node.findall(tag)):
            os_node.remove(node)
            changed = True

    for node in list(os_node.findall("boot")):
        if node.get("dev") != "hd":
            changed = True
        os_node.remove(node)

    ET.SubElement(os_node, "boot", {"dev": "hd"})
    xml_text = ET.tostring(root, encoding="unicode")

    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
        handle.write(xml_text)
        xml_path = handle.name

    try:
        define = virsh(["define", xml_path], check=False, capture=True)
        if define.returncode != 0:
            warn(f"Could not redefine {vm_name} to boot from disk.")
            warn((define.stderr or define.stdout).strip())
            return False
        ok(f"{vm_name} persistent boot target is now the installed disk")
        return changed
    finally:
        Path(xml_path).unlink(missing_ok=True)


def set_domain_interface_model(vm_name: str, model: str) -> bool:
    """Set the first libvirt network interface model in persistent XML."""
    dump = virsh(["dumpxml", "--inactive", vm_name], check=False, capture=True)
    if dump.returncode != 0:
        warn(f"Could not read inactive libvirt XML for {vm_name}.")
        return False

    root = ET.fromstring(dump.stdout)
    interface = root.find("./devices/interface[@type='network']")
    if interface is None:
        warn(f"Domain {vm_name} has no libvirt network interface.")
        return False

    model_node = interface.find("model")
    if model_node is None:
        model_node = ET.SubElement(interface, "model")

    if model_node.get("type") == model:
        return False

    model_node.set("type", model)
    xml_text = ET.tostring(root, encoding="unicode")

    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
        handle.write(xml_text)
        xml_path = handle.name

    try:
        define = virsh(["define", xml_path], check=False, capture=True)
        if define.returncode != 0:
            warn(f"Could not redefine {vm_name} network model as {model}.")
            warn((define.stderr or define.stdout).strip())
            return False
        ok(f"{vm_name} persistent network adapter model is now {model}")
        return True
    finally:
        Path(xml_path).unlink(missing_ok=True)


def ensure_domain_running(vm_name: str) -> None:
    state = virsh(["domstate", vm_name], check=False, capture=True)
    if state.returncode != 0:
        warn(f"VM {vm_name} does not exist yet.")
        return

    if state.stdout.strip().lower() == "running":
        return

    step(f"Starting VM {vm_name}")
    virsh(["start", vm_name], check=False)


def cold_boot_domain(vm_name: str) -> None:
    """Force a full QEMU restart so inactive XML changes take effect."""
    state = virsh(["domstate", vm_name], check=False, capture=True)
    if state.returncode == 0 and state.stdout.strip().lower() == "running":
        step(f"Powering off {vm_name} so updated boot settings take effect")
        virsh(["destroy", vm_name], check=False)
        time.sleep(2)

    step(f"Starting {vm_name}")
    virsh(["start", vm_name], check=False)


def save_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def host_cpu_count() -> int:
    return os.cpu_count() or 2


def host_memory_mb() -> int:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return 8192
    for line in meminfo.read_text(encoding="utf-8").splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) // 1024
    return 8192


def value_is_auto(value: object) -> bool:
    return value is None or str(value).strip().lower() == "auto"


def resolve_vm_resources(config: dict, vm_key: str) -> tuple[int, int]:
    """Return memory_mb, vcpus for a VM using host-aware auto sizing."""
    vm = config[vm_key]
    total_ram_mb = host_memory_mb()
    total_cpus = host_cpu_count()

    if vm_key == "windows":
        suggested_memory = min(12288, max(6144, int(total_ram_mb * 0.45)))
        suggested_vcpus = min(4, max(2, total_cpus // 2))
    else:
        suggested_memory = min(6144, max(3072, int(total_ram_mb * 0.25)))
        suggested_vcpus = min(4, max(2, total_cpus // 3))

    # Keep enough room for the host and the other VM. This is intentionally
    # conservative because setup runs both VMs at once.
    max_memory_for_one_vm = max(2048, total_ram_mb - 4096)
    memory_mb = suggested_memory if value_is_auto(vm.get("memory_mb")) else int(vm["memory_mb"])
    vcpus = suggested_vcpus if value_is_auto(vm.get("vcpus")) else int(vm["vcpus"])

    memory_mb = min(memory_mb, max_memory_for_one_vm)
    vcpus = min(vcpus, max(1, total_cpus - 1))

    info(
        f"{vm_key} resources: {memory_mb} MiB RAM, {vcpus} vCPU "
        f"(host: {total_ram_mb} MiB RAM, {total_cpus} CPU threads)"
    )
    return memory_mb, vcpus
