#!/usr/bin/env python3
"""scripts/run-attack.py."""


from rrlib import attacker_cmd, demo_auth_target, load_config, run


def main():
    config = load_config()
    return run(
        attacker_cmd("reuserupture", "auto", "--yes", demo_auth_target(config)),
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
