#!/usr/bin/env python3
"""vm/create-windows.py."""

from __future__ import annotations

import sys
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory, NamedTemporaryFile
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rrlib import ROOT, cfg_path, download_url, grant_qemu_media_access, info, load_config, ok, resolve_vm_resources, run, set_domain_boot_to_disk, set_domain_interface_model, step, virt_install, virsh, warn

VIRTIO_DRIVER_SPECS = {
    "viostor": "viostor.inf",
    "NetKVM": "netkvm.inf",
}
MEDIA_LETTERS = ["D", "E", "F", "G", "H", "I", "J", "K"]


def local_iso_candidates() -> list[Path]:
    candidates = []
    for path in ROOT.rglob("*.iso"):
        if "kali" not in path.name.lower():
            candidates.append(path)
    for path in ROOT.rglob("*.ISO"):
        if "kali" not in path.name.lower():
            candidates.append(path)
    return sorted(set(candidates))


def iso_path_exists(iso: Path, path: str) -> bool:
    return run(["xorriso", "-indev", str(iso), "-find", path, "-maxdepth", "0"], check=False, capture=True).returncode == 0


def select_virtio_driver_payload(virtio_iso: Path, folders: list[str]) -> dict[str, str]:
    selected = {}
    for driver_root, inf_name in VIRTIO_DRIVER_SPECS.items():
        for folder in folders:
            iso_driver_path = f"/{driver_root}/{folder}/amd64"
            if iso_path_exists(virtio_iso, f"{iso_driver_path}/{inf_name}"):
                selected[driver_root] = folder
                break
        else:
            choices = ", ".join(f"{driver_root}/{folder}/amd64" for folder in folders)
            raise SystemExit(f"VirtIO driver {inf_name} was not found in {virtio_iso}. Checked: {choices}")
    return selected


def extract_virtio_driver_payload(virtio_iso: Path, media_dir: Path, selected: dict[str, str]) -> list[str]:
    media_paths = []
    for driver_root, folder in selected.items():
        source = f"/{driver_root}/{folder}/amd64"
        target = media_dir / "drivers" / driver_root / folder / "amd64"
        target.parent.mkdir(parents=True, exist_ok=True)
        run(["xorriso", "-osirrox", "on", "-indev", str(virtio_iso), "-extract", source, str(target)])
        media_paths.append(f"drivers\\{driver_root}\\{folder}\\amd64")
        info(f"Staged VirtIO driver: {driver_root}/{folder}/amd64")
    return media_paths


def virtio_drvload_commands(letters: list[str], selected: dict[str, str]) -> str:
    commands = []
    order = 1
    for driver_root, inf_name in VIRTIO_DRIVER_SPECS.items():
        folder = selected[driver_root]
        relative_inf = f"drivers\\{driver_root}\\{folder}\\amd64\\{inf_name}"
        command = f"cmd.exe /c for %D in ({' '.join(letters)}) do if exist %D:\\{relative_inf} drvload %D:\\{relative_inf}"
        commands.extend(
            [
                "      <RunSynchronousCommand>",
                f"        <Order>{order}</Order>",
                f"        <Description>Load VirtIO {driver_root} driver</Description>",
                f"        <Path>{escape(command)}</Path>",
                "      </RunSynchronousCommand>",
            ]
        )
        order += 1
    return "      <RunSynchronous>\n" + "\n".join(commands) + "\n      </RunSynchronous>"


def virtio_offline_servicing(letters: list[str], selected: dict[str, str]) -> str:
    # Inject the VirtIO drivers into the *offline* (installed) image so the
    # finished OS owns viostor (boot-critical, or it bugchecks with
    # INACCESSIBLE_BOOT_DEVICE / 0x7B) and NetKVM (or it has no working NIC for
    # WinRM). This is a separate pass and a separate driver store from the
    # windowsPE drvload, so it does not re-trigger the "driver already present"
    # 0x80070103 failure. The driver media drive letter is not known ahead of
    # time, so every candidate letter is listed; offlineServicing ignores the
    # paths that do not resolve.
    paths = []
    for driver_root, folder in selected.items():
        media_path = f"drivers\\{driver_root}\\{folder}\\amd64"
        for letter in letters:
            paths.append(f"{letter}:\\{media_path}")

    lines = [
        '  <settings pass="offlineServicing">',
        '    <component name="Microsoft-Windows-PnpCustomizationsNonWinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">',
        "      <DriverPaths>",
    ]
    for index, path in enumerate(paths, start=1):
        lines.extend(
            [
                f'        <PathAndCredentials wcm:action="add" wcm:keyValue="{index}" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">',
                f"          <Path>{path}</Path>",
                "        </PathAndCredentials>",
            ]
        )
    lines.extend(["      </DriverPaths>", "    </component>", "  </settings>"])
    return "\n".join(lines)


def inject_windows_pe_virtio(text: str, selected: dict[str, str]) -> str:
    # Load VirtIO storage/network drivers with drvload during windowsPE so Setup
    # can see the VirtIO disk to install onto.
    #
    # The Windows Server 2025 / Windows 11 24H2 setup engine fails with
    # "0x80070103 - 0x40031" (ERROR_NO_MORE_ITEMS, "driver already present")
    # when the same driver is offered to it more than once, and it rejects
    # drivers injected through <DriverPaths>/PnpCustomizationsWinPE outright.
    # drvload is the programmatic equivalent of manually loading the driver in
    # WinPE, which the new setup still accepts. drvload only affects the live
    # WinPE, so the drivers are also injected into the installed image via the
    # offlineServicing pass below.
    run_sync_xml = virtio_drvload_commands(MEDIA_LETTERS, selected)
    text = text.replace("      <DiskConfiguration>", run_sync_xml + "\n      <DiskConfiguration>", 1)
    offline_xml = virtio_offline_servicing(MEDIA_LETTERS, selected)
    text = text.replace('  <settings pass="specialize">', offline_xml + '\n  <settings pass="specialize">', 1)
    return text


def explain_missing_windows_iso(configured_iso: Path) -> str:
    candidates = local_iso_candidates()
    lines = [
        f"Windows ISO is not available at: {configured_iso}",
        "",
        "To use a local ISO, edit config.yml:",
        "  windows:",
        f"    iso_path: {configured_iso.name}",
        "    download_iso: false",
        "",
        "To download, make sure windows.iso_url is a public downloadable link.",
    ]
    if candidates:
        lines.append("")
        lines.append("Local non-Kali ISO files found:")
        lines.extend(f"  - {path}" for path in candidates)
    return "\n".join(lines)


def main() -> int:
    cfg = load_config()
    win = cfg["windows"]
    virtio = win.get("virtio", {})
    virtio_enabled = bool(virtio.get("enabled", True))
    use_virtio_devices = virtio_enabled
    memory_mb, vcpus = resolve_vm_resources(cfg, "windows")
    if virsh(["dominfo", win["vm_name"]], check=False, capture=True).returncode == 0:
        ok(f"Windows VM {win['vm_name']} already exists; reusing it")
        set_domain_boot_to_disk(win["vm_name"])
        desired_model = "virtio" if use_virtio_devices else "e1000e"
        if set_domain_interface_model(win["vm_name"], desired_model):
            warn(f"Existing Windows VM network model was changed to {desired_model}.")
            warn("If WinRM still does not answer, fully power off and start the VM once.")
        return 0

    iso = cfg_path(win["iso_path"])
    if iso.exists():
        info(f"Using local Windows ISO: {iso}")
    elif win.get("iso_url"):
        if not win.get("download_iso", True):
            warn(f"Local Windows ISO is missing even though download_iso is false: {iso}")
            warn("Falling back to the configured download URL so setup can continue.")
        step("Downloading Windows Server evaluation ISO")
        info(win["iso_url"])
        try:
            run([str(ROOT / "scripts/download-google-drive-file.py"), "--url", win["iso_url"], "--output", str(iso), "--sha256", str(win.get("iso_sha256") or "")])
        except subprocess.CalledProcessError as exc:
            raise SystemExit(explain_missing_windows_iso(iso)) from exc
    else:
        raise SystemExit(explain_missing_windows_iso(iso))

    virtio_iso = None
    if virtio_enabled:
        virtio_iso = cfg_path(virtio.get("iso_path", "iso/virtio-win.iso"))
        if virtio_iso.exists():
            info(f"Using local VirtIO ISO: {virtio_iso}")
        elif virtio.get("download_iso", True):
            step("Downloading VirtIO Windows driver ISO")
            download_url(str(virtio["iso_url"]), virtio_iso, str(virtio.get("iso_sha256") or ""))
        else:
            raise SystemExit(f"VirtIO ISO is missing and download is disabled: {virtio_iso}")

    step("Generating Windows Autounattend media")
    with TemporaryDirectory(prefix="reuserupture-autounattend.") as answer_dir:
        selected_drivers = {}
        if use_virtio_devices:
            folders = [str(item) for item in virtio.get("driver_folders", ["2k25", "2k22", "w11", "w10"])]
            selected_drivers = select_virtio_driver_payload(virtio_iso, folders)
            extract_virtio_driver_payload(virtio_iso, Path(answer_dir), selected_drivers)
        answer_path = Path(answer_dir) / "Autounattend.xml"
        text = (ROOT / "vm/autounattend/Autounattend.xml").read_text(encoding="utf-8")
        text = text.replace("<ComputerName>DC01</ComputerName>", f"<ComputerName>{escape(win['hostname'])}</ComputerName>")
        text = text.replace("<Value>ChangeMe-Admin-2026!</Value>", f"<Value>{escape(cfg['active_directory']['administrator_password'])}</Value>")
        text = text.replace("<Value>Windows Server 2025 Standard Evaluation (Desktop Experience)</Value>", f"<Value>{escape(win['edition'])}</Value>")
        if use_virtio_devices:
            text = inject_windows_pe_virtio(text, selected_drivers)
        answer_path.write_text(text, encoding="utf-8")
        bootstrap = (ROOT / "vm/autounattend/bootstrap-winrm.ps1").read_text(encoding="utf-8")
        bootstrap = bootstrap.replace("__RR_WINDOWS_IP__", str(win["ip"]))
        bootstrap = bootstrap.replace("__RR_NETWORK_PREFIX__", str(cfg["network"]["prefix"]))
        bootstrap = bootstrap.replace("__RR_NETWORK_GATEWAY__", str(cfg["network"]["gateway"]))
        bootstrap_path = Path(answer_dir) / "bootstrap-winrm.ps1"
        bootstrap_path.write_text(bootstrap, encoding="utf-8")
        with NamedTemporaryFile(prefix="reuserupture-autounattend.", suffix=".iso", delete=False) as fh:
            answer_iso = Path(fh.name)
        run(["xorriso", "-as", "mkisofs", "-quiet", "-J", "-r", "-V", "RRWINRM", "-o", str(answer_iso), answer_dir])
    ok("Autounattend ISO generated")

    disk = Path(f"/var/lib/libvirt/images/{win['vm_name']}.qcow2")
    if disk.exists():
        info(f"Reusing existing Windows disk: {disk}")
    else:
        step("Creating Windows VM disk")
        run(["qemu-img", "create", "-f", "qcow2", str(disk), f"{win['disk_gb']}G"], sudo=True)
    disk_bus = "virtio" if use_virtio_devices else "sata"
    nic_model = "virtio" if use_virtio_devices else "e1000e"
    install_args = [
        "--name",
        win["vm_name"],
        "--memory",
        str(memory_mb),
        "--vcpus",
        str(vcpus),
        "--disk",
        f"path={disk},format=qcow2,bus={disk_bus}",
        "--disk",
        f"path={answer_iso},device=cdrom,readonly=on,bus=sata",
        "--cdrom",
        str(iso),
        "--os-variant",
        "win2k22",
        "--network",
        f"network={cfg['network']['name']},model={nic_model}",
        "--graphics",
        "spice",
        "--noautoconsole",
    ]
    # Under qemu:///system the QEMU user (e.g. libvirt-qemu on Ubuntu) must be
    # able to read the install media even though it lives under the user's home.
    for media in (iso, answer_iso, *( [virtio_iso] if virtio_iso else [] )):
        grant_qemu_media_access(media)

    step("Starting Windows installation")
    virt_install(install_args)
    ok("Windows installer launched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
