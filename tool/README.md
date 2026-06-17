# ReuseRupture Tool

`reuserupture.py` merges the supplied scanner and exploit into one CLI while
preserving their SAMR request structures.

The scanner mode sends the original safe 6-subauthority SID probe. A vulnerable
target is reported when the response classification is `VULNERABLE_BEHAVIOR`.

The exploit mode sends the original 15-subauthority SID request. It reports
success only when the SAMR pipe breaks in the same way as the supplied exploit
script.

Examples:

```bash
python3 reuserupture.py scan 'reuserupture.local/demo-user:DemoUser-2026!@192.168.56.10'
python3 reuserupture.py exploit 'reuserupture.local/demo-user:DemoUser-2026!@192.168.56.10'
python3 reuserupture.py auto --yes 'reuserupture.local/demo-user:DemoUser-2026!@192.168.56.10'
```
