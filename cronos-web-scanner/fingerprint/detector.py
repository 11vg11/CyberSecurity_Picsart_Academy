"""Multi-signal technology fingerprinting (Wappalyzer-style).

Combines HTTP headers, HTML body patterns, and cookie names, each
contributing to a cumulative confidence score per technology. Version
strings are extracted via regex capture groups when present.
"""
import re
import json
import os
from typing import Dict, List, Any

DEFAULT_SIGNATURES_PATH = os.path.join(os.path.dirname(__file__), "signatures.json")


class FingerprintEngine:
    def __init__(self, signatures_path: str = DEFAULT_SIGNATURES_PATH):
        with open(signatures_path, encoding="utf-8") as f:
            self.signatures = json.load(f)
        for technology, rules in self.signatures.items():
            for signal in ("headers", "html", "cookies"):
                patterns = rules.get(signal, {})
                patterns = patterns.values() if isinstance(patterns, dict) else patterns
                for pattern in patterns:
                    re.compile(pattern, re.IGNORECASE)

    def analyze(self, headers: Dict[str, str], html: str, cookies: Dict[str, str]) -> List[Dict[str, Any]]:
        results = []
        normalized_headers = {key.lower(): value for key, value in headers.items()}
        normalized_cookies = {key.lower() for key in cookies}

        for tech, rules in self.signatures.items():
            evidence = []
            detected_version = None

            if "headers" in rules:
                for header_name, pattern in rules["headers"].items():
                    header_value = normalized_headers.get(header_name.lower(), "")
                    if header_value:
                        match = re.search(pattern, header_value, re.IGNORECASE)
                        if match:
                            evidence.append(("headers", 40))
                            if match.groups() and match.group(1):
                                detected_version = match.group(1)
                            break

            if "html" in rules and html:
                for pattern in rules["html"]:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        evidence.append(("html", 30))
                        if match.groups() and match.group(1) and not detected_version:
                            detected_version = match.group(1)
                        break

            for cookie_pattern in rules.get("cookies", []):
                if any(
                    re.search(cookie_pattern, cookie_name, re.IGNORECASE)
                    for cookie_name in normalized_cookies
                ):
                    evidence.append(("cookies", 30))
                    break

            confidence = min(sum(weight for _, weight in evidence), 100)
            if confidence >= 30:
                result = {
                    "technology": tech,
                    "category": rules.get("category", "Unknown"),
                    "version": detected_version or "Unknown",
                    "confidence": min(confidence, 100),
                    "evidence": [signal for signal, _ in evidence],
                }
                if rules.get("cpe_vendor") and rules.get("cpe_product"):
                    result["cpe_vendor"] = rules["cpe_vendor"]
                    result["cpe_product"] = rules["cpe_product"]
                results.append(result)

        results.sort(key=lambda r: r["confidence"], reverse=True)
        return results
