"""Passively check external script tags for Subresource Integrity metadata."""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from utils.http_client import ScanHTTPClient


class _ScriptParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.sources = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        attributes = {name.lower(): value for name, value in attrs}
        src = attributes.get("src")
        if src:
            integrity = attributes.get("integrity")
            self.sources.append((src, bool(integrity and integrity.strip())))


def check(url: str, aggressive: bool = False) -> list:
    try:
        with ScanHTTPClient(url) as client:
            response = client.get(url, allow_redirects=False)
    except requests.RequestException as error:
        return [{
            "module": "Software Supply Chain",
            "severity": "info",
            "title": "Could not inspect script integrity metadata",
            "detail": str(error),
        }]

    parser = _ScriptParser()
    parser.feed(response.text[:500_000])
    origin_host = urlparse(response.url or url).hostname
    findings = []

    for source, has_integrity in parser.sources:
        absolute_url = urljoin(response.url or url, source)
        parsed = urlparse(absolute_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            continue
        if parsed.hostname.lower() == (origin_host or "").lower() or has_integrity:
            continue

        findings.append({
            "module": "Software Supply Chain",
            "severity": "low",
            "title": "External script has no Subresource Integrity metadata",
            "detail": (
                f"A script is loaded from external host {parsed.hostname} "
                "without an integrity attribute. Verify whether SRI is supported "
                "and appropriate for this resource."
            ),
        })

    return findings
