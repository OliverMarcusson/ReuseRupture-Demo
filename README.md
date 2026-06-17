# ReuseRupture Demonstration Lab

ReuseRupture is an isolated university cybersecurity demo for an authenticated
Windows Server 2025 domain controller denial-of-service path. The lab uses a
Docker Compose attacker container, a vulnerable Windows Server 2025 AD domain controller, a
merged scanner/exploit CLI, and a reboot-time CTF flag callback.

The flag callback proves that the domain controller rebooted after the demo was
armed. It does not prove remote code execution from the exploit.

## Architecture

Default network:

```text
192.168.56.0/24
DC01       192.168.56.10  Windows Server 2025 domain controller
ATTACKER01 host network   Docker attacker container
```

Default domain:

```text
DNS domain: reuserupture.local
NetBIOS:    REUSERUPTURE
```

## Prerequisites

Supported reference host path: Linux with Docker, libvirt/KVM, Vagrant, and
`virt-install`.

You need:

- Hardware virtualization enabled.
- Debian/Ubuntu, Fedora, or Arch Linux.
- Enough disk/time for `setup.py` to build the attacker image and install
  Windows, or local ISO files configured in `config.yml`.

`setup.py` installs required host packages using `apt`, `dnf`, or `pacman`.
It does not redistribute ISOs in the repository.

## Quick Start

```bash
./setup.py
./demo.py
```

If `config.yml` is missing, `setup.py` creates it from `config.example.yml`.
By default it downloads the configured Windows Server evaluation ISO and the
VirtIO driver ISO, then builds the Docker attacker. To use local ISOs instead,
set:

```yaml
windows:
  iso_path: /path/to/windows-server-2025.iso
  download_iso: false

  virtio:
    iso_path: /path/to/virtio-win.iso
    download_iso: false

attacker:
  container_name: reuserupture-attacker
```

VM CPU and memory default to `auto`. Setup detects host RAM/CPU and allocates
more to Windows on capable machines while keeping a reserve for the host.
Override with fixed numbers in `config.yml` if needed.

Python equivalents are provided for the shell entry points:

```bash
./setup.py
./demo.py --yes
./reset.py
./destroy.py
```

The Python versions are intentionally more verbose and easier to read. Matching
copies also exist under `vm/` and `scripts/`, for example
`vm/create-windows.py` and `scripts/verify-lab.py`.

During Windows VM installation, setup opens a best-effort read-only
`virt-viewer` window so you can monitor progress without interacting with the
installer.

Useful setup modes:

```bash
./setup.py --skip-vm-creation
./setup.py --ansible-only
./setup.py --verify-only
```

## Default Credentials

These are intentionally weak credentials for an isolated academic lab:

```text
Domain administrator: Administrator / ChangeMe-Admin-2026!
Normal domain user:  demo-user     / DemoUser-2026!
AS-REP user:         legacy-user   / Password123!
```

Override all values in `config.yml`.

## Scanner and Exploit

The original supplied scripts are preserved in `tool/supplied/`.

The merged tool is `tool/reuserupture.py`:

```bash
docker compose exec -T attacker reuserupture scan 'reuserupture.local/demo-user:DemoUser-2026!@192.168.56.10'
docker compose exec -T attacker reuserupture exploit 'reuserupture.local/demo-user:DemoUser-2026!@192.168.56.10'
docker compose exec -T attacker reuserupture auto --yes 'reuserupture.local/demo-user:DemoUser-2026!@192.168.56.10'
```

The scanner preserves the supplied safe SAMR probe and reports vulnerable
behavior when the helper returns `STATUS_OBJECT_NAME_INVALID`. The exploit
preserves the supplied malformed SID request and reports success only when the
SAMR pipe breaks.

## Flag Behavior

Before each run, `demo.py` generates a random run ID and writes it to
`C:\ReuseRuptureDemo\armed-run-id.txt` on the domain controller. A scheduled
task runs at startup as `SYSTEM`; it sends an HTTP JSON callback to the attacker
listener only when that arming file exists.

Default flag:

```text
EP284U{REUSERUPTURE_DC_REBOOT_CONFIRMED}
```

The attacker listener accepts only the expected run ID, saves the callback in the
evidence directory, and prints the flag.

## Reset and Destroy

Create a clean snapshot after setup:

```bash
virsh snapshot-create-as reuserupture-dc reuserupture-ready
```

Restore it:

```bash
./reset.py
```

Remove generated lab resources:

```bash
./destroy.py
```

`destroy.py` stops the attacker container and does not remove the Windows ISO.

## Limitations

The attacker runs in Docker with host networking. Evidence is bind-mounted from
the host `evidence/` directory into `/opt/reuserupture/evidence`.

Windows is installed from `windows.iso_path`. If that file is missing and
`windows.download_iso` is true, setup downloads the configured Google Drive
evaluation ISO. Set `windows.iso_sha256` when you know the trusted checksum.

Windows unattended installation varies by ISO and VirtIO driver setup. The
reference `vm/autounattend/Autounattend.xml` is included, but if installation
does not complete unattended, finish Windows setup manually, enable WinRM, and
rerun `./setup.py --skip-vm-creation`.

The exploit is not modified or improved. The lab assumes an intentionally
vulnerable Windows Server 2025 build in an isolated network.
