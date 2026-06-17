#!/usr/bin/env python3
"""Download a public Google Drive file using only the Python standard library."""


import argparse
import html.parser
import http.cookiejar
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class ConfirmFormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_form = False
        self.form_action = None
        self.inputs = {}

    def handle_starttag(self, tag, attrs):
        attr = {k: v or "" for k, v in attrs}
        if tag == "form" and ("download" in attr.get("action", "") or "uc" in attr.get("action", "")):
            self.in_form = True
            self.form_action = attr.get("action")
        elif self.in_form and tag == "input" and attr.get("name"):
            self.inputs[attr["name"]] = attr.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self.in_form:
            self.in_form = False


def file_id_from(value):
    if re.fullmatch(r"[-_A-Za-z0-9]+", value):
        return value
    parsed = urllib.parse.urlparse(value)
    match = re.search(r"/file/d/([^/]+)", parsed.path)
    if match:
        return match.group(1)
    query_id = urllib.parse.parse_qs(parsed.query).get("id", [""])[0]
    if query_id:
        return query_id
    raise SystemExit(f"Could not extract Google Drive file id from: {value}")


def opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def open_url(op, url):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 ReuseRuptureLab/1.0",
            "Accept": "text/html,application/octet-stream,*/*",
        },
    )
    return op.open(request, timeout=60)


def candidate_urls(file_id):
    query = urllib.parse.urlencode({"export": "download", "id": file_id})
    return [
        f"https://drive.google.com/uc?{query}",
        f"https://drive.google.com/uc?{query}&confirm=t",
        f"https://drive.usercontent.google.com/download?{query}&confirm=t",
    ]


def extract_download_url(body):
    match = re.search(r'"downloadUrl"\s*:\s*"([^"]+)"', body)
    if not match:
        return None
    # Google embeds the URL as a JSON string with escaped slashes and unicode.
    return json.loads(f'"{match.group(1)}"')


def maybe_confirm(op, response):
    content_type = response.headers.get("Content-Type", "")
    if "text/html" not in content_type:
        return response

    body = response.read().decode("utf-8", errors="replace")
    parser = ConfirmFormParser()
    parser.feed(body)
    embedded_url = extract_download_url(body)
    if embedded_url:
        return open_url(op, embedded_url)

    if not parser.form_action:
        if "404" in body or "not found" in body.lower():
            raise SystemExit("Google Drive reported that the file was not found or is not public")
        raise SystemExit("Google Drive returned HTML without a downloadable confirmation form")

    action = urllib.parse.urljoin(response.url, parser.form_action)
    separator = "&" if urllib.parse.urlparse(action).query else "?"
    url = action + separator + urllib.parse.urlencode(parser.inputs)
    return open_url(op, url)


def resolve_download_url(url_or_id):
    file_id = file_id_from(url_or_id)
    op = opener()
    last_error = None
    for url in candidate_urls(file_id):
        try:
            response = maybe_confirm(op, open_url(op, url))
            return response.url, file_id
        except (urllib.error.HTTPError, urllib.error.URLError, SystemExit) as exc:
            last_error = exc
    raise SystemExit(
        "Could not resolve the Google Drive download URL. "
        "Confirm the sharing link is public and the file still exists.\n"
        f"File id: {file_id}\n"
        f"Last error: {last_error}"
    )


def download(url_or_id, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    resolved_url, file_id = resolve_download_url(url_or_id)
    print(f"Downloading Google Drive file {file_id} to {output}")
    subprocess.run(
        [
            "aria2c",
            "--continue=true",
            "--max-connection-per-server=4",
            "--split=4",
            "--summary-interval=5",
            "--dir",
            str(output.parent),
            "--out",
            output.name,
            resolved_url,
        ],
        check=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    download(args.url, Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
