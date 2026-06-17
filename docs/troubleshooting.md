# Troubleshooting

## Missing Virtualization Support

Enable VT-x/AMD-V in firmware. Check `lsmod | grep kvm` and `virsh list`.

## Docker Permission Denied

```text
permission denied while trying to connect to the Docker daemon socket
```

A fresh Docker install leaves your user outside the `docker` group. `setup.py`
adds you automatically and then re-executes itself under the `docker` group
(via `sg docker`) so the rest of the run can talk to Docker directly — no
re-login required. If `sg` is unavailable it falls back to `sudo` for Docker.

To use Docker without any of this afterwards, start a new login session (or run
`newgrp docker`) so the new group membership applies to your shell:

```bash
sudo usermod -aG docker "$USER"   # setup.py already does this
newgrp docker                     # or log out and back in
```

If a Docker step ever appears to hang with no output, it may be `sudo` waiting
for a password (its cached credentials expire during the long image build).
The `sg docker` re-exec above avoids this; ensure the `sg` command is installed
(`util-linux` / `passwd` package).

## Libvirt Bridge Permission Errors

If setup fails with:

```text
error creating bridge interface virbr-rr: Operation not permitted
```

the VM network was being created without system libvirt privileges. The scripts
use `qemu:///system` and fall back to `sudo` for libvirt operations. Rerun:

```bash
./setup.py
```

For future passwordless runs, add your user to the libvirt group and log out/in:

```bash
sudo usermod -aG libvirt "$USER"
```

If a failed rootless network was left behind, it is harmless because the lab now
uses the system libvirt connection. You can inspect it with:

```bash
virsh -c qemu:///session net-list --all
virsh -c qemu:///system net-list --all
```

## Missing virtnetworkd Socket

If setup fails with:

```text
Failed to connect socket to '/var/run/libvirt/virtnetworkd-sock'
```

the modular libvirt network daemon is not running. Setup now tries to start it
automatically. To check manually:

```bash
sudo systemctl enable --now virtnetworkd.socket virtnetworkd.service
sudo systemctl enable --now virtqemud.socket virtqemud.service virtlogd.socket
virsh -c qemu:///system net-list --all
```

On Debian systems using monolithic libvirt, this is usually:

```bash
sudo systemctl enable --now libvirtd
```

## Windows ISO Path Errors

If `windows.iso_path` exists, setup uses it and skips download. If it does not
exist, keep `windows.download_iso: true` to fetch the configured Google Drive
ISO, or set `windows.iso_path` to a valid local file.

## Unattended Windows Installation Fails

Error `0x80070103 - 0x40031` during Windows PE is `ERROR_NO_MORE_ITEMS`
("driver already present"). The Windows Server 2025 / Windows 11 24H2 setup
engine fails fatally when the same VirtIO storage driver is offered more than
once, and it rejects drivers injected through the unattend
`<DriverPaths>`/`PnpCustomizationsWinPE` mechanism.

`create-windows.py` therefore loads `viostor` (the VirtIO block driver matching
the `bus=virtio` disk) with a single `drvload` command in the `windowsPE` pass —
the programmatic equivalent of manually loading the driver, which the new setup
still accepts. `drvload` only affects the live WinPE, so the same drivers are
also injected into the installed image through the `offlineServicing` pass
(`Microsoft-Windows-PnpCustomizationsNonWinPE`).

Ensure `windows.virtio.enabled: true` in `config.yml` and that
`iso/virtio-win.iso` is present (or `windows.virtio.download_iso: true`).

### INACCESSIBLE_BOOT_DEVICE (0x7B) after first reboot

Windows installs but bugchecks `0x7B` on first boot when the installed image is
missing the `viostor` boot driver — i.e. the disk driver was loaded only in
WinPE and never injected into the offline image. The `offlineServicing` pass in
the generated `Autounattend.xml` fixes this; recreate the VM with
`./vm/recreate-windows.py` so the new answer file takes effect.

If Windows setup still fails, use `vm/autounattend/Autounattend.xml` as a
reference, finish setup manually, enable WinRM, then run
`./setup.py --skip-vm-creation`.

## WinRM Failures

The Windows VM must have a Windows-native network adapter and a static IP before
Ansible can connect. Current setup uses `e1000e` instead of VirtIO because a
stock Windows Server ISO does not include VirtIO network drivers.

If the VM was installed before this fix, recreate only Windows:

```bash
./vm/recreate-windows.py
./setup.py
```

After first boot, the bootstrap log should be available at:

```text
C:\ReuseRuptureDemo\winrm-bootstrap.log
```

Confirm WinRM HTTPS listens on port `5986` and Windows Firewall allows it.

## Interface Alias Mismatch

On Windows, run `Get-NetAdapter` and set `windows.interface_alias` accordingly.

## Domain Promotion Reconnect Issues

Wait several minutes after promotion, then rerun `./setup.py --ansible-only`.

## DNS Failures

Check that the attacker container uses `192.168.56.10` as DNS and that
`/etc/hosts` contains the fallback `DC01.reuserupture.local` entry.

## Kerberos Clock Skew

Synchronize the host and Windows clocks. Kerberos commonly fails with more
than five minutes of skew.

## Scanner Errors

Verify SMB/RPC access to the DC and that `demo-user` credentials are correct.

## Exploit Errors

If the malformed request is rejected, the target build may be patched.

## DC Never Becomes Unavailable

Confirm the scanner reported vulnerable behavior before exploit. Check
`evidence/<timestamp>/exploit.log`.

## DC Reboots But No Flag Arrives

Check `C:\ReuseRuptureDemo\flag-callback.log`, Windows Firewall, the listener
port, and `C:\ReuseRuptureDemo\armed-run-id.txt`.

## Listener Port Conflicts

Change `flag.listener_port` in `config.yml` or stop the process using the port.

## Stale Run IDs

The listener ignores callbacks whose `run_id` does not match the current run.
Delete old `armed-run-id*.txt` files if needed.

## Scheduled Task Failures

Run `Get-ScheduledTask -TaskName "ReuseRupture Flag Callback"` and inspect
Task Scheduler history.
