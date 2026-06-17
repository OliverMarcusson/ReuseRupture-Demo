#!/usr/bin/env python3
"""scripts/monitor-target.py."""


import socket
import time
from datetime import datetime, timezone

from rrlib import load_config


def is_port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def main():
    config = load_config()
    host = config["windows"]["ip"]
    port = int(config["windows"]["winrm_port"])

    while True:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        state = "up" if is_port_open(host, port) else "down"
        print(f"{timestamp} {state}", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
