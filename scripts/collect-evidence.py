#!/usr/bin/env python3
"""scripts/collect-evidence.py."""


import argparse
from datetime import datetime, timezone
from pathlib import Path

from rrlib import ROOT, attacker_exec, ensure_repo_writable_dir, load_config, redacted_config_json, render_inventory, run


def main():
    config = load_config()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    default_output = ROOT / config["demo"]["evidence_root"] / f"manual-{timestamp}"

    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", nargs="?", default=str(default_output))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir
    try:
        output_dir.resolve().relative_to(ROOT)
    except ValueError:
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        ensure_repo_writable_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    render_inventory()
    (output_dir / "config.redacted.json").write_text(redacted_config_json(), encoding="utf-8")

    diagnostics = run(
        [
            "ansible",
            "-i",
            str(ROOT / "inventory/hosts.yml"),
            "domain_controller",
            "-m",
            "ansible.windows.win_powershell",
            "-a",
            r"script=C:\ReuseRuptureDemo\diagnostics.ps1",
        ],
        check=False,
        capture=True,
    )
    (output_dir / "windows-diagnostics.txt").write_text(diagnostics.stdout + diagnostics.stderr, encoding="utf-8")

    tool_help = attacker_exec(
        ["reuserupture", "--help"],
        check=False,
        capture=True,
    )
    (output_dir / "tool-help.txt").write_text(tool_help.stdout + tool_help.stderr, encoding="utf-8")
    print(f"Collected evidence in {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
