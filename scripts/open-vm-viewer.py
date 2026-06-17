#!/usr/bin/env python3
"""Open a read-only libvirt viewer for a VM."""

from __future__ import annotations

import argparse

from rrlib import start_viewer


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vm_name")
    args = parser.parse_args()
    start_viewer(args.vm_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
