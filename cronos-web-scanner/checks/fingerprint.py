"""Identify technologies from the target's normal HTTP response."""
import requests

from fingerprint.detector import FingerprintEngine


def check(url: str, aggressive: bool = False) -> list:
    try:
        response = requests.get(url, timeout=10, allow_redirects=False)
    except requests.RequestException as error:
        return [{
            "module": "Software Fingerprinting",
            "severity": "info",
            "title": "Could not fingerprint target",
            "detail": str(error),
        }]

    cookies = {cookie.name: cookie.value for cookie in response.cookies}
    technologies = FingerprintEngine().analyze(
        headers=dict(response.headers),
        html=response.text,
        cookies=cookies,
    )

    return [
        {
            "module": "Software Fingerprinting",
            "severity": "info",
            "title": f"Technology detected: {technology['technology']}",
            "detail": (
                f"Category: {technology['category']}; "
                f"version: {technology['version']}; "
                f"signal confidence: {technology['confidence']}%; "
                f"evidence: {', '.join(technology['evidence'])}."
            ),
            "technology": technology["technology"],
            "version": technology["version"],
            "confidence": technology["confidence"],
            "evidence": technology["evidence"],
            "cpe_vendor": technology.get("cpe_vendor"),
            "cpe_product": technology.get("cpe_product"),
        }
        for technology in technologies
    ]
