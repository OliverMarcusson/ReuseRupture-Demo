# Installation

1. Use Debian/Ubuntu, Fedora, or Arch Linux with hardware virtualization
   enabled.
2. Run setup:

   ```bash
   ./setup.py
   ```

   Or use the more readable Python equivalent:

   ```bash
   ./setup.py
   ```

   If `config.yml` is missing, setup creates it from `config.example.yml`.
   It then installs host dependencies with `apt`, `dnf`, or `pacman`.

3. By default, setup downloads the configured Kali installer ISO and Windows
   Server evaluation ISO if they are not already present.

4. Setup also downloads Python package wheels into `wheelhouse/tool/` on the
   host. The Kali VM installs the ReuseRupture tool dependencies from that
   copied wheelhouse because the lab VMs are intentionally isolated from the
   internet.

5. To use local ISOs instead, edit `config.yml` before running setup:

   ```yaml
   windows:
     iso_path: /path/to/windows-server-2025.iso
     download_iso: false

   kali:
     iso_path: /path/to/kali-installer.iso
     download_iso: false
   ```

If VM creation is already done manually:

```bash
./setup.py --skip-vm-creation
```

If only Ansible configuration is needed:

```bash
./setup.py --ansible-only
```
