#!/usr/bin/env python3
"""scripts/verify-lab.py."""


import json
import socket
import time

from rrlib import ROOT, attacker_exec, load_config, render_inventory, run, wait_for_tcp


passed = 0
failed = 0


def check(name, command):
    global passed, failed
    try:
        ok = command()
    except Exception as exc:
        ok = False
        detail = str(exc)
    else:
        detail = ""

    if ok:
        print(f"[PASS] {name}")
        passed += 1
    else:
        print(f"[FAIL] {name}")
        if detail:
            print(f"       {detail}")
        failed += 1


def ansible_ok(args):
    result = run(["ansible", "-i", str(ROOT / "inventory/hosts.yml"), *args], check=False, capture=True)
    if result.returncode != 0:
        print((result.stdout + result.stderr).strip())
    return result.returncode == 0


def attacker_ok(args):
    result = attacker_exec(args, check=False, capture=True)
    if result.returncode != 0:
        print((result.stdout + result.stderr).strip())
    return result.returncode == 0


def retry_ok(predicate, attempts = 5, delay = 3):
    # A single DNS/UDP query against the DC can time out transiently even when
    # the lab is healthy, so retry before declaring failure. A genuinely broken
    # service still fails every attempt.
    for attempt in range(1, attempts + 1):
        if predicate():
            return True
        if attempt < attempts:
            time.sleep(delay)
    return False


def dns_resolves_dc(fqdn, dc_ip):
    # Query the DC's DNS service directly instead of going through the container
    # resolver. Docker copies the host's /etc/resolv.conf, which on this host is
    # a 127.0.0.53 systemd-resolved stub that does not exist inside the
    # container, so getent/NSS lookups fail unless an /etc/hosts entry happens
    # to be present (added by setup.py and lost whenever the container is
    # recreated). A directed query tests what the demo depends on: the DC
    # answering DNS for its own name.
    result = attacker_exec(["dig", "+short", f"@{dc_ip}", fqdn, "A"], check=False, capture=True)
    if dc_ip not in result.stdout:
        print((result.stdout + result.stderr).strip())
        return False
    return True


def port_can_bind(port):
    sock = socket.socket()
    try:
        sock.bind(("0.0.0.0", port))
        return True
    finally:
        sock.close()


def main():
    config = load_config()
    render_inventory()

    check("Docker attacker ready", lambda: attacker_ok(["reuserupture", "--help"]))
    check("Windows WinRM reachable", lambda: wait_for_tcp(config["windows"]["ip"], int(config["windows"]["winrm_port"]), 10))
    check("DNS resolves DC", lambda: retry_ok(lambda: dns_resolves_dc(f"{config['windows']['hostname']}.{config['active_directory']['domain_name']}", config["windows"]["ip"])))
    check("Kerberos reachable", lambda: attacker_ok(["nc", "-zw3", config["windows"]["ip"], "88"]))
    check("LDAP reachable", lambda: attacker_ok(["nc", "-zw3", config["windows"]["ip"], "389"]))
    check("demo-user exists", lambda: ansible_ok(["domain_controller", "-m", "ansible.windows.win_powershell", "-a", json.dumps({"script": f"Get-ADUser -Identity '{config['active_directory']['demo_username']}' | Out-Null"})]))
    check("legacy-user exists", lambda: ansible_ok(["domain_controller", "-m", "ansible.windows.win_powershell", "-a", json.dumps({"script": f"Get-ADUser -Identity '{config['active_directory']['asrep_username']}' | Out-Null"})]))
    check("startup flag task exists", lambda: ansible_ok(["domain_controller", "-m", "ansible.windows.win_powershell", "-a", json.dumps({"script": "Get-ScheduledTask -TaskName 'ReuseRupture Flag Callback' | Out-Null"})]))
    check("merged tool installed in attacker", lambda: attacker_ok(["test", "-x", "/usr/local/bin/reuserupture"]))
    check("merged tool CLI works in attacker", lambda: attacker_ok(["reuserupture", "--help"]))
    check("flag listener can bind", lambda: port_can_bind(int(config["flag"]["listener_port"])))

    virtio_script = r"""
$drivers = Get-CimInstance Win32_PnPSignedDriver |
  Where-Object { $_.DeviceClass -in @('NET','HDC','SCSIAdapter') } |
  Select-Object DeviceName, Manufacturer, DriverProviderName
$drivers | ConvertTo-Json -Compress
if (($drivers | Where-Object { ($_.Manufacturer + $_.DriverProviderName + $_.DeviceName) -match 'Red Hat|VirtIO|VirtIO' }).Count -lt 1) {
  Write-Warning 'No active VirtIO storage or network driver was detected.'
}
"""
    check("Windows driver diagnostics collected", lambda: ansible_ok(["domain_controller", "-m", "ansible.windows.win_powershell", "-a", json.dumps({"script": virtio_script})]))

    print(f"\nVerification summary: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
