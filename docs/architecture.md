# Architecture

ReuseRupture uses one isolated libvirt network, one Kali attacker VM, and one
Windows Server 2025 domain controller VM.

```text
Kali ATTACKER01 192.168.56.20
  -> authenticated SAMR scan
  -> authenticated SAMR exploit

Windows DC01 192.168.56.10
  -> LSASS crash and reboot on vulnerable builds
  -> startup scheduled task sends armed flag callback
```

The flag callback is preinstalled by Ansible. It is only a reboot proof. It is
not payload execution from the exploit.
