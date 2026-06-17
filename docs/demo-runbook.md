# Demo Runbook

1. Restore the clean snapshot:

   ```bash
   ./reset.py
   ```

2. Show that both VMs are running:

   ```bash
   virsh list
   ```

3. Verify the lab:

   ```bash
   ./scripts/verify-lab.py
   ```

4. Show the current domain controller boot time:

   ```bash
   ansible -i inventory/hosts.yml domain_controller -m ansible.windows.win_powershell -a "script=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"
   ```

5. Run the demo:

   ```bash
   ./demo.py --yes
   ```

6. Point out the scanner result. It must show `VULNERABLE_BEHAVIOR`.
7. Point out the authenticated exploit command and the SAMR pipe break.
8. Show the target availability log as the DC becomes unavailable.
9. Show the VM returning after reboot.
10. Show the flag arriving from `DC01`.
11. Show that the received run ID matches the current run.
12. Show the evidence directory printed by `demo.py`.

The startup task was installed before the exploit and is armed by `demo.py`.
It exists only to prove the domain controller rebooted during the current run.
It is not code execution obtained through the exploit.
