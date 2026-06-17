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

3. By default, setup downloads the configured Windows Server evaluation ISO if
   it is not already present. The attacker is a Docker container whose Python
   tool dependencies are installed at image-build time.

4. To use a local Windows ISO instead, edit `config.yml` before running setup:

   ```yaml
   windows:
     iso_path: /path/to/windows-server-2025.iso
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
