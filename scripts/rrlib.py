#!/usr/bin/env python3
"""Shared Python helpers for ReuseRupture lab scripts."""


import json
import os
import shutil
import socket
import subprocess
import sys
import time
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_FILE = Path(os.environ.get("CONFIG_FILE", ROOT / "config.yml"))
LIBVIRT_URI = os.environ.get("RR_LIBVIRT_URI", "qemu:///system")


def utc_stamp(fmt = "%Y%m%dT%H%M%SZ"):
    return datetime.now(timezone.utc).strftime(fmt)


def banner(title, subtitle = None):
    line = "=" * 72
    print(f"\n{line}")
    print(title)
    if subtitle:
        print(subtitle)
    print(f"{line}\n")


def step(message):
    print(f"\n[>] {message}", flush=True)


def info(message):
    print(f"    {message}", flush=True)


def ok(message):
    print(f"[OK] {message}", flush=True)


def warn(message):
    print(f"[WARN] {message}", file=sys.stderr, flush=True)


def run(
    cmd,
    *,
    check = True,
    cwd = None,
    capture = False,
    sudo = False,
):
    full = ["sudo", *cmd] if sudo else cmd
    kwargs = {
        "cwd": str(cwd or ROOT),
        "text": True,
        "check": check,
    }
    env = os.environ.copy()
    pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(ROOT) if not pythonpath else str(ROOT) + os.pathsep + pythonpath
    )
    kwargs["env"] = env
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    return subprocess.run(full, **kwargs)


def invoking_uid_gid():
    """Return the real user's uid/gid, even when a script was launched by sudo."""
    return (
        os.environ.get("SUDO_UID") or str(os.getuid()),
        os.environ.get("SUDO_GID") or str(os.getgid()),
    )


def ensure_repo_writable_dir(path):
    """Create a repo-local directory and fail clearly if it is not writable."""
    path = path.resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise SystemExit(
            f"Refusing to repair permissions outside the repo: {path}"
        ) from exc

    path.mkdir(parents=True, exist_ok=True)
    test = path / ".rr-write-test"
    try:
        test.write_text("", encoding="utf-8")
    except OSError as exc:
        raise SystemExit(
            f"{path} is not writable by the current user. Fix ownership and rerun setup."
        ) from exc
    finally:
        test.unlink(missing_ok=True)


def command_exists(name):
    return shutil.which(name) is not None


def require_cmds(commands):
    return not missing_cmds(commands)


def missing_cmds(commands):
    missing = []
    for cmd in commands:
        if not command_exists(cmd):
            print(f"Missing required command: {cmd}", file=sys.stderr)
            missing.append(cmd)
    return missing


_docker_sudo = None
_libvirt_sudo = None


def env_truthy(name):
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def env_falsey(name):
    return os.environ.get(name, "").strip().lower() in {"0", "false", "no", "off"}


def ensure_container_user_env():
    uid, gid = invoking_uid_gid()
    os.environ.setdefault("RR_UID", uid)
    os.environ.setdefault("RR_GID", gid)


def configure_compose_env(config):
    windows = config["windows"]
    ad = config["active_directory"]
    os.environ["RR_WINDOWS_IP"] = str(windows["ip"])
    os.environ["RR_WINDOWS_HOSTNAME"] = str(windows["hostname"])
    os.environ["RR_WINDOWS_FQDN"] = f"{windows['hostname']}.{ad['domain_name']}"


def docker_sudo_env():
    names = [
        "RR_UID",
        "RR_GID",
        "RR_WINDOWS_IP",
        "RR_WINDOWS_HOSTNAME",
        "RR_WINDOWS_FQDN",
    ]
    return [f"{name}={os.environ[name]}" for name in names if name in os.environ]


def docker_prefix():
    """Command prefix for Docker, without mutating host groups or sessions."""
    global _docker_sudo
    if _docker_sudo is None:
        if env_truthy("RR_DOCKER_SUDO"):
            _docker_sudo = True
        elif env_falsey("RR_DOCKER_SUDO") or not command_exists("docker"):
            _docker_sudo = False
        elif run(["docker", "info"], check=False, capture=True).returncode == 0:
            _docker_sudo = False
        elif run(["sudo", "docker", "info"], check=False, capture=True).returncode == 0:
            warn("Docker is not reachable as this user; using sudo for Docker commands.")
            warn("Set RR_DOCKER_SUDO=0 to require unprivileged Docker access.")
            _docker_sudo = True
        else:
            _docker_sudo = False
    return ["sudo", "env", *docker_sudo_env()] if _docker_sudo else []


def docker_compose_base():
    ensure_container_user_env()
    prefix = docker_prefix()
    if (
        command_exists("docker")
        and run(
            [*prefix, "docker", "compose", "version"], check=False, capture=True
        ).returncode
        == 0
    ):
        return [*prefix, "docker", "compose"]
    if command_exists("docker-compose"):
        return [*prefix, "docker-compose"]
    return [*prefix, "docker", "compose"]


def libvirt_prefix():
    """Command prefix for libvirt system operations."""
    global _libvirt_sudo
    if _libvirt_sudo is None:
        if env_truthy("RR_LIBVIRT_SUDO"):
            _libvirt_sudo = True
        elif env_falsey("RR_LIBVIRT_SUDO"):
            _libvirt_sudo = False
        else:
            _libvirt_sudo = "system" in LIBVIRT_URI
    return ["sudo"] if _libvirt_sudo else []


def docker_compose(
    args, *, check = True, capture = False
):
    return run([*docker_compose_base(), *args], check=check, capture=capture)


def attacker_exec(
    args, *, check = True, capture = False
):
    return docker_compose(
        ["exec", "-T", "attacker", *args], check=check, capture=capture
    )


def attacker_cmd(*args):
    """Build a command list that runs `args` inside the attacker container."""
    return [*docker_compose_base(), "exec", "-T", "attacker", *args]


def container_path(path):
    """Translate a host path under ROOT to its path inside the attacker container."""
    return "/opt/reuserupture/" + str(path.relative_to(ROOT))


def demo_auth_target(config):
    """Build the `domain/user:password@ip` string the CLI expects."""
    ad = config["active_directory"]
    return f"{ad['domain_name']}/{ad['demo_username']}:{ad['demo_password']}@{config['windows']['ip']}"


def download_url(url, output):
    try:
        output.parent.resolve().relative_to(ROOT)
    except ValueError:
        output.parent.mkdir(parents=True, exist_ok=True)
    else:
        ensure_repo_writable_dir(output.parent)
    tmp = output.with_suffix(output.suffix + ".part")
    downloader = ["curl", "-L", "--fail", "--progress-bar", "-o", str(tmp), url]
    if command_exists("aria2c"):
        downloader = [
            "aria2c",
            "--allow-overwrite=true",
            "--file-allocation=none",
            "-o",
            tmp.name,
            "-d",
            str(tmp.parent),
            url,
        ]
    run(downloader)
    tmp.replace(output)


def ensure_config_exists():
    if CONFIG_FILE.exists():
        return
    warn("config.yml not found; creating it from config.example.yml.")
    shutil.copyfile(ROOT / "config.example.yml", CONFIG_FILE)


def _deep_merge(base, override):
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config():
    import yaml

    example = (
        yaml.safe_load((ROOT / "config.example.yml").read_text(encoding="utf-8")) or {}
    )
    user = (
        yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8"))
        if CONFIG_FILE.exists()
        else {}
    )
    return _deep_merge(example, user or {})


def cfg_path(value):
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def render_inventory():
    step("Rendering Ansible inventory from config.yml")
    ensure_repo_writable_dir(ROOT / "inventory")
    ensure_repo_writable_dir(ROOT / "inventory/group_vars")
    inventory = run(
        [
            str(ROOT / "scripts/render-config.py"),
            "--config",
            str(CONFIG_FILE),
            "--format",
            "inventory",
            "--validate",
        ],
        capture=True,
    )
    (ROOT / "inventory/hosts.yml").write_text(inventory.stdout, encoding="utf-8")
    all_vars = run(
        [
            str(ROOT / "scripts/render-config.py"),
            "--config",
            str(CONFIG_FILE),
            "--format",
            "all-vars",
            "--validate",
        ],
        capture=True,
    )
    (ROOT / "inventory/group_vars/all.yml").write_text(
        all_vars.stdout, encoding="utf-8"
    )
    ok("Inventory written to inventory/hosts.yml")


def redacted_config_json():
    return run(
        [
            str(ROOT / "scripts/render-config.py"),
            "--config",
            str(CONFIG_FILE),
            "--format",
            "redacted-json",
            "--validate",
        ],
        capture=True,
    ).stdout


def port_is_open(host, port, timeout = 2):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_tcp(host, port, timeout = 300):
    info(f"Waiting up to {timeout}s for {host}:{port}")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_is_open(host, port):
            ok(f"{host}:{port} is reachable")
            return True
        time.sleep(5)
    print(f"Timed out waiting for {host}:{port}", file=sys.stderr)
    return False


def wait_for_vm_tcp(
    vm_name,
    host,
    port,
    timeout = 300,
    *,
    boot_from_disk = False,
):
    """Wait for a VM service and restart the VM if an installer left it shut off."""
    info(f"Waiting up to {timeout}s for {vm_name} at {host}:{port}")
    deadline = time.monotonic() + timeout
    last_state = ""
    next_state_check = 0.0

    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_state_check:
            state = virsh(["domstate", vm_name], check=False, capture=True)
            current_state = (
                state.stdout.strip().lower() if state.returncode == 0 else "missing"
            )

            if current_state != last_state:
                info(f"{vm_name} state: {current_state}")
                last_state = current_state

            if current_state in {"shut off", "shutdown", "crashed", "pmsuspended"}:
                if boot_from_disk:
                    set_domain_boot_to_disk(vm_name)
                step(
                    f"Starting {vm_name}; the installer appears to have powered it off"
                )
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


def virsh(
    args, *, check = True, capture = False
):
    base = ["virsh", "-c", LIBVIRT_URI, *args]
    return run([*libvirt_prefix(), *base], check=check, capture=capture)


def stage_libvirt_media(path):
    """Copy install media into libvirt storage instead of changing source ACLs."""
    path = path.resolve()
    if "system" not in LIBVIRT_URI:
        return path
    media_dir = Path("/var/lib/libvirt/images/reuserupture-media")
    staged = media_dir / path.name
    run(["mkdir", "-p", str(media_dir)], sudo=True)
    run(["install", "-m", "0644", str(path), str(staged)], sudo=True)
    return staged


def virt_install(args):
    base = ["virt-install", "--connect", LIBVIRT_URI, *args]
    return run([*libvirt_prefix(), *base])


def virt_xml(
    args, *, check = True, capture = False
):
    base = ["virt-xml", "--connect", LIBVIRT_URI, *args]
    return run([*libvirt_prefix(), *base], check=check, capture=capture)


def remove_missing_removable_media(root):
    """Drop stale installer media references that prevent a VM from starting."""
    changed = False
    devices = root.find("devices")
    if devices is None:
        return False

    for disk in list(devices.findall("disk")):
        if disk.get("device") not in {"cdrom", "floppy"}:
            continue
        source = disk.find("source")
        if source is None:
            continue
        path = source.get("file") or source.get("dev")
        if path and not Path(path).exists():
            devices.remove(disk)
            changed = True

    return changed


def set_domain_boot_to_disk(vm_name):
    """Remove installer boot settings and stale media, then boot from disk."""
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
    changed = remove_missing_removable_media(root) or changed
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


def set_domain_interface_model(vm_name, model):
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


def ensure_domain_running(vm_name):
    state = virsh(["domstate", vm_name], check=False, capture=True)
    if state.returncode != 0:
        warn(f"VM {vm_name} does not exist yet.")
        return

    if state.stdout.strip().lower() == "running":
        return

    step(f"Starting VM {vm_name}")
    virsh(["start", vm_name], check=False)


def cold_boot_domain(vm_name):
    """Force a full QEMU restart so inactive XML changes take effect."""
    state = virsh(["domstate", vm_name], check=False, capture=True)
    if state.returncode == 0 and state.stdout.strip().lower() == "running":
        step(f"Powering off {vm_name} so updated boot settings take effect")
        virsh(["destroy", vm_name], check=False)
        time.sleep(2)

    step(f"Starting {vm_name}")
    virsh(["start", vm_name], check=False)


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def host_cpu_count():
    return os.cpu_count() or 2


def host_memory_mb():
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return 8192
    for line in meminfo.read_text(encoding="utf-8").splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) // 1024
    return 8192


def value_is_auto(value):
    return value is None or str(value).strip().lower() == "auto"


def resolve_vm_resources(config, vm_key):
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
    memory_mb = (
        suggested_memory if value_is_auto(vm.get("memory_mb")) else int(vm["memory_mb"])
    )
    vcpus = suggested_vcpus if value_is_auto(vm.get("vcpus")) else int(vm["vcpus"])

    memory_mb = min(memory_mb, max_memory_for_one_vm)
    vcpus = min(vcpus, max(1, total_cpus - 1))

    info(
        f"{vm_key} resources: {memory_mb} MiB RAM, {vcpus} vCPU "
        f"(host: {total_ram_mb} MiB RAM, {total_cpus} CPU threads)"
    )
    return memory_mb, vcpus
