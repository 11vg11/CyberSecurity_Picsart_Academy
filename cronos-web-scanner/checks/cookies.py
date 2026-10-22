"""Passively inspect cookie attributes returned by the supplied URL."""
from urllib.parse import urlparse

import requests

from utils.http_client import ScanHTTPClient


def _cookie_attribute(cookie, name: str) -> bool:
    return cookie.has_nonstandard_attr(name)


def check(url: str, aggressive: bool = False) -> list:
    try:
        with ScanHTTPClient(url) as client:
            response = client.get(url, allow_redirects=False)
    except requests.RequestException as error:
        return [{
            "module": "Cookie Security",
            "severity": "info",
            "title": "Could not inspect response cookies",
            "detail": str(error),
        }]

    findings = []
    secure_origin = urlparse(response.url or url).scheme.lower() == "https"
    for cookie in response.cookies:
        missing = []
        if secure_origin and not cookie.secure:
            missing.append("Secure")
        if not _cookie_attribute(cookie, "HttpOnly"):
            missing.append("HttpOnly")
        if not _cookie_attribute(cookie, "SameSite"):
            missing.append("SameSite")
        if not missing:
            continue

        findings.append({
            "module": "Cookie Security",
            "severity": "low",
            "title": f"Cookie missing security attributes: {cookie.name}",
            "detail": (
                f"The response cookie is missing: {', '.join(missing)}. "
                "Review whether these attributes are appropriate for this cookie."
            ),
        })

    return findings
