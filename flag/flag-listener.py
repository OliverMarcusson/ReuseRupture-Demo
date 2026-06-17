#!/usr/bin/env python3
"""HTTP listener for the ReuseRupture reboot proof flag."""


import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class FlagState:
    def __init__(self, expected_run_id, evidence_dir):
        self.expected_run_id = expected_run_id
        self.evidence_dir = evidence_dir
        self.received = False
        self.payload = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ReuseRuptureFlagListener/1.0"

    def do_POST(self):
        state = self.server.state
        if self.path != "/flag":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_error(400, "invalid JSON")
            return

        run_id = str(payload.get("run_id", ""))
        if state.expected_run_id and run_id != state.expected_run_id:
            print(f"Ignoring stale flag callback with run_id={run_id!r}", flush=True)
            self.send_response(202)
            self.end_headers()
            self.wfile.write(b"ignored stale run_id\n")
            return

        state.evidence_dir.mkdir(parents=True, exist_ok=True)
        callback_path = state.evidence_dir / "flag-callback.json"
        callback_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        state.payload = payload
        state.received = True
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)


def print_flag(payload):
    print("=" * 60)
    print("FLAG RECEIVED FROM DOMAIN CONTROLLER")
    print(payload.get("flag", "<missing flag>"))
    print(f"Host: {payload.get('hostname', '<unknown>')}")
    print(f"Boot time: {payload.get('boot_time', '<unknown>')}")
    print(f"Run ID: {payload.get('run_id', '<missing>')}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Receive the ReuseRupture CTF flag callback")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--expected-run-id")
    parser.add_argument("--evidence-dir", default="evidence/current")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    state = FlagState(args.expected_run_id, Path(args.evidence_dir))
    server = HTTPServer((args.host, args.port), Handler)
    server.state = state
    server.timeout = 1
    deadline = time.monotonic() + args.timeout
    print(f"Listening for flag callback on {args.host}:{args.port}", flush=True)
    while time.monotonic() < deadline:
        server.handle_request()
        if state.received and state.payload:
            print_flag(state.payload)
            return 0
    print(f"Timed out after {args.timeout}s waiting for matching flag callback", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
