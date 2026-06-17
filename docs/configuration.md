# Configuration

`config.yml` is the source of truth. `setup.py` renders:

- `inventory/hosts.yml`
- `inventory/group_vars/all.yml`
- shell environment variables used by scripts

Important values:

- `windows.iso_path`: user-supplied Windows Server ISO.
- `windows.download_iso`, `windows.iso_url`, `windows.iso_sha256`: Windows ISO
  download/cache/verification settings. If `windows.iso_path` exists locally,
  setup uses it and skips download.
- `kali.image_path`: optional prepared Kali qcow2 import path.
- `kali.iso_path`, `kali.iso_url`, `kali.iso_sha256`: Kali installer ISO
  cache/download/verification settings used when `kali.image_path` is empty.
- `windows.interface_alias`: Windows interface name, usually `Ethernet`.
- `windows.memory_mb`, `windows.vcpus`, `kali.memory_mb`, `kali.vcpus`:
  set to `auto` for host-aware sizing, or use explicit numbers to force fixed
  resources.
- `active_directory.*`: domain name and demo users.
- `flag.*`: callback flag value, listener IP, port, delay and retry settings.
- `demo.snapshot_name`: clean snapshot name used by `reset.py`.

Do not edit generated inventory files directly unless you intentionally bypass
the central configuration flow.
