#!/usr/bin/env python3
"""Safe non-admin behavioral scanner for CVE-2026-33826."""

import argparse
import getpass
import json
import sys

from impacket.dcerpc.v5 import samr, transport
from impacket.dcerpc.v5.dtypes import BOOL, RPC_SID, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.examples.utils import parse_target


STATUS_SUCCESS = 0x00000000
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_OBJECT_NAME_INVALID = 0xC0000033

# Six subauthorities produce a 32-byte SID. The vulnerable destination has
# 36 bytes available, so this probe does not overflow it.
SAFE_SUBAUTHORITY_COUNT = 6
SAFE_SID_LENGTH = 8 + 4 * SAFE_SUBAUTHORITY_COUNT


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


def build_safe_probe_sid():
    sid = RPC_SID()
    sid.fromCanonical("S-1-5-21-1-2-3-4-5")
    return sid


def parse_hashes(value):
    if not value:
        return "", ""
    if ":" not in value:
        raise ValueError("--hashes must use LMHASH:NTHASH format")
    return value.split(":", 1)


def classify(status):
    if status == STATUS_INVALID_PARAMETER:
        return (
            "PATCHED_BEHAVIOR",
            "The validating helper rejected the safe 32-byte SID.",
        )
    if status == STATUS_OBJECT_NAME_INVALID:
        return (
            "VULNERABLE_BEHAVIOR",
            "The legacy helper accepted the safe 32-byte SID and continued to lookup.",
        )
    return (
        "UNKNOWN",
        f"Unexpected NTSTATUS 0x{status:08x}; no vulnerability conclusion.",
    )


def scan_target(target, hashes=None):
    domain, username, password, address = parse_target(target)
    if not username:
        raise ValueError("an authenticated domain account is required")
    if password == "" and hashes is None:
        password = getpass.getpass(f"Password for {domain}/{username}@{address}: ")

    lmhash, nthash = parse_hashes(hashes)
    rpc_transport = transport.DCERPCTransportFactory(
        rf"ncacn_np:{address}[\pipe\samr]"
    )
    rpc_transport.set_credentials(username, password, domain, lmhash, nthash)

    dce = rpc_transport.get_dce_rpc()
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)

    connect = samr.hSamrConnect5(dce)
    request = SamrValidateComputerAccountReuseAttempt()
    request["ServerHandle"] = connect["ServerHandle"]
    request["ComputerSid"] = build_safe_probe_sid()
    response = dce.request(request, checkError=False)

    status = int(response["ErrorCode"])
    classification, reason = classify(status)
    return {
        "target": address,
        "classification": classification,
        "ntstatus": f"0x{status:08x}",
        "result": int(response["Result"]),
        "safe_sid": "S-1-5-21-1-2-3-4-5",
        "safe_sid_length": SAFE_SID_LENGTH,
        "reason": reason,
    }


def print_human(result):
    print(f"[{result['classification']}] {result['target']}")
    if "ntstatus" in result:
        print(f"  NTSTATUS: {result['ntstatus']}")
    if "safe_sid_length" in result:
        print(f"  Probe SID length: {result['safe_sid_length']} bytes")
    print(f"  Assessment: {result['reason']}")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Safely distinguish patched and vulnerable CVE-2026-33826 behavior "
            "using a non-overflowing authenticated SAMR request."
        )
    )
    parser.add_argument(
        "--target",
        action="append",
        required=True,
        help="[[domain/]username[:password]@]<host>; may be repeated",
    )
    parser.add_argument("--hashes", metavar="LMHASH:NTHASH")
    parser.add_argument("--json", action="store_true", help="emit JSON lines")
    args = parser.parse_args()

    exit_code = 0
    for target in args.target:
        try:
            result = scan_target(target, hashes=args.hashes)
        except Exception as exc:
            result = {
                "target": target,
                "classification": "ERROR",
                "reason": f"{type(exc).__name__}: {exc}",
            }
            exit_code = 2

        if result["classification"] == "VULNERABLE_BEHAVIOR":
            exit_code = 1

        if args.json:
            print(json.dumps(result, sort_keys=True))
        else:
            print_human(result)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
