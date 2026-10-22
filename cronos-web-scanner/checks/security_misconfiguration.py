"""Passively identify common framework debug pages in the supplied response."""
import re

import requests

from utils.http_client import ScanHTTPClient


DEBUG_SIGNATURES = (
    ("Django debug page", re.compile(r"You're seeing this error because you have DEBUG\s*=\s*True", re.I)),
    ("Werkzeug interactive debugger", re.compile(r"Werkzeug Debugger|werkzeug\.debug", re.I)),
    ("Laravel Whoops error page", re.compile(r"Whoops! There was an error|Whoops, looks like something went wrong", re.I)),
    ("ASP.NET detailed error page", re.compile(r"Server Error in '/' Application|yellow screen of death", re.I)),
)


def check(url: str, aggressive: bool = False) -> list:
    try:
        with ScanHTTPClient(url) as client:
            response = client.get(url, allow_redirects=False)
    except requests.RequestException as error:
        return [{
            "module": "Security Misconfiguration",
            "severity": "info",
            "title": "Could not inspect response for debug-page indicators",
            "detail": str(error),
        }]

    body = response.text[:500_000]
    for name, signature in DEBUG_SIGNATURES:
        if signature.search(body):
            return [{
                "module": "Security Misconfiguration",
                "severity": "medium",
                "title": f"Possible exposed framework debug page: {name}",
                "detail": (
                    "The supplied URL returned content matching a common "
                    "framework debug-page signature. Verify the response and "
                    "disable detailed errors in production."
                ),
            }]
    return []
