#!/usr/bin/env python3
"""scripts/start-flag-listener.py."""


import argparse
from pathlib import Path

from rrlib import ROOT, attacker_cmd, container_path, ensure_repo_writable_dir, load_config, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id", nargs="?", default="")
    parser.add_argument("evidence_dir", nargs="?")
    args = parser.parse_args()

    config = load_config()
    evidence_root = ROOT / Path(config["demo"]["evidence_root"])
    evidence_dir = Path(args.evidence_dir) if args.evidence_dir else evidence_root / "manual-listener"
    if not evidence_dir.is_absolute():
        evidence_dir = ROOT / evidence_dir
    ensure_repo_writable_dir(evidence_dir)

    return run(
        attacker_cmd(
            "python3",
            "/opt/reuserupture/flag/flag-listener.py",
            "--port",
            str(config["flag"]["listener_port"]),
            "--expected-run-id",
            args.run_id,
            "--evidence-dir",
            container_path(evidence_dir),
        ),
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
