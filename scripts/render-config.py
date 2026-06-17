#!/usr/bin/env python3
"""Render ReuseRupture config as shell env, Ansible inventory, or JSON."""


import argparse
import copy
import json
import shlex
import sys
from pathlib import Path

import yaml


SECRET_KEYS = {"password", "administrator_password", "demo_password", "asrep_password"}


def deep_merge(base, override):
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path):
    example = Path("config.example.yml")
    if not example.exists():
        raise SystemExit("config.example.yml is missing")
    base = yaml.safe_load(example.read_text(encoding="utf-8")) or {}
    if not path.exists():
        raise SystemExit(f"{path} is missing; run: cp config.example.yml config.yml")
    user = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return deep_merge(base, user)


def validate(config):
    required = [
        ("windows", "iso_path"),
        ("windows", "ip"),
        ("active_directory", "domain_name"),
        ("active_directory", "administrator_password"),
    ]
    missing = [f"{section}.{key}" for section, key in required if not config.get(section, {}).get(key)]
    if missing:
        raise SystemExit("missing required config values: " + ", ".join(missing))


def flatten(prefix, value, out):
    if isinstance(value, dict):
        for key, child in value.items():
            flatten(f"{prefix}_{key}" if prefix else key, child, out)
    else:
        out[prefix.upper()] = value


def render_env(config):
    flat = {}
    flatten("", config, flat)
    lines = []
    for key in sorted(flat):
        value = flat[key]
        if isinstance(value, bool):
            value = "true" if value else "false"
        lines.append(f"export RR_{key}={shlex.quote(str(value))}")
    return "\n".join(lines) + "\n"


def inventory(config):
    win = config["windows"]
    ad = config["active_directory"]
    return {
        "all": {
            "children": {
                "attacker": {
                    "hosts": {
                        config.get("attacker", {}).get("hostname", "ATTACKER01"): {
                            "ansible_connection": "local",
                            "ansible_python_interpreter": sys.executable,
                        }
                    }
                },
                "domain_controller": {
                    "hosts": {
                        win["hostname"]: {
                            "ansible_host": win["ip"],
                            "ansible_user": win.get("username", "Administrator"),
                            "ansible_password": ad["administrator_password"],
                            "ansible_connection": "winrm",
                            "ansible_winrm_transport": "ntlm",
                            "ansible_winrm_server_cert_validation": "ignore",
                            "ansible_port": win.get("winrm_port", 5986),
                        }
                    }
                },
            }
        }
    }


def all_vars(config):
    return {"rr": config}


def redact(value, key = ""):
    if isinstance(value, dict):
        return {k: redact(v, k) for k, v in value.items()}
    if key in SECRET_KEYS or key.endswith("_password"):
        return "REDACTED"
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yml")
    parser.add_argument("--format", choices=["env", "inventory", "all-vars", "json", "redacted-json"], required=True)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    config = load_config(Path(args.config))
    if args.validate:
        validate(config)
    if args.format == "env":
        sys.stdout.write(render_env(config))
    elif args.format == "inventory":
        yaml.safe_dump(inventory(config), sys.stdout, sort_keys=False)
    elif args.format == "all-vars":
        yaml.safe_dump(all_vars(config), sys.stdout, sort_keys=False)
    elif args.format == "redacted-json":
        json.dump(redact(config), sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        json.dump(config, sys.stdout, indent=2, sort_keys=True)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
