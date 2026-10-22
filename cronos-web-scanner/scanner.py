#!/usr/bin/env python3
"""
Cronos - Authorized Web Application Vulnerability Scanner
=========================================================
A lightweight, educational web-app security assessment tool intended
for use ONLY on systems you own or are explicitly authorized to test
(e.g. via a signed penetration testing engagement / rules of engagement).

Unauthorized scanning of systems you do not own or have permission to
test is illegal in most jurisdictions (e.g. Computer Fraud and Abuse
Act in the US, Computer Misuse Act in the UK). This tool enforces an
explicit authorization confirmation before running any checks.

Usage:
    python scanner.py --url https://target.example.com
    python scanner.py --url https://target.example.com --output report.html
"""

import argparse
import datetime
import json
import os
import sys
from collections.abc import Callable
from urllib.parse import urlparse

from checks import cookies, fingerprint, headers, sbom, security_misconfiguration, sensitive_files, sri, ssl_check
from checks.cve_lookup import CVELookup, risk_rank
from reports import html_report, sarif_report


BANNER = r"""
 __        __   _     __   __       _   ____
 \ \      / /__| |__  \ \ / /   _ _| |_/ ___|  ___ __ _ _ __
  \ \ /\ / / _ \ '_ \  \ V / | | | | | \___ \ / __/ _` | '_ \
   \ V  V /  __/ |_) |  | || |_| | | | |___) | (_| (_| | | | |
    \_/\_/ \___|_.__/   |_| \__,_|_|_|____/ \___\__,_|_| |_|

  Cronos - Authorized Web Application Security Scanner
"""


def confirm_authorization(target: str) -> bool:
    """Require explicit, typed confirmation that the user is authorized
    to test the target before any network requests are made."""
    print(BANNER)
    print(f"Target: {target}\n")
    print("LEGAL / ETHICAL NOTICE")
    print("-" * 60)
    print(
        "This tool will send HTTP requests to inspect headers, TLS,\n"
        "technology indicators, and common public paths. Only run this\n"
        "against systems you own or have EXPLICIT WRITTEN AUTHORIZATION\n"
        "to test.\n"
    )
    resp = input(
        'Type "I AM AUTHORIZED" to confirm you have permission to scan '
        "this target: "
    )
    return resp.strip() == "I AM AUTHORIZED"


def run_scan(
    url: str,
    aggressive: bool = False,
    include_sbom: bool = True,
    passive_only: bool = False,
    selected_checks: set[str] | None = None,
    progress_callback: Callable[[str, int, int], None] | None = None,
    include_advisories: bool = False,
) -> dict:
    """Run all checks against the target and collect results."""
    results = {
        "target": url,
        "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "findings": [],
        "errors": [],
    }

    available_checks = [
        ("headers", "HTTP Security Headers", headers.check),
        ("tls", "SSL/TLS Configuration", ssl_check.check),
        ("cookies", "Cookie Security", cookies.check),
        ("debug", "Security Misconfiguration", security_misconfiguration.check),
        ("sri", "Subresource Integrity", sri.check),
        ("fingerprint", "Software Fingerprinting", fingerprint.check),
    ]
    if not passive_only:
        available_checks.append(
            ("sensitive_files", "Sensitive Files & Directories", sensitive_files.check)
        )
        if include_sbom:
            available_checks.append(
                ("sbom", "SBOM & Dependency Mapping", sbom.check)
            )
    modules = [
        (key, name, check)
        for key, name, check in available_checks
        if selected_checks is None or key in selected_checks
    ]

    total = len(modules) + int(include_advisories)
    for index, (key, name, func) in enumerate(modules, start=1):
        if progress_callback:
            progress_callback(name, index, total)
        print(f"[*] Running: {name} ...")
        try:
            if key == "tls" and passive_only:
                findings = func(
                    url,
                    aggressive=aggressive,
                    check_legacy_protocols=False,
                )
            else:
                findings = func(url, aggressive=aggressive)
            results["findings"].extend(findings)
            print(f"    -> {len(findings)} finding(s)")
        except Exception as e:
            print(f"    -> check failed: {type(e).__name__}: {e}")
            results["errors"].append({
                "module": name,
                "error_type": type(e).__name__,
                "message": str(e),
            })

    fingerprint_enabled = selected_checks is None or "fingerprint" in selected_checks
    if fingerprint_enabled:
        detected = []
        for finding in results["findings"]:
            if finding.get("module") != "Software Fingerprinting":
                continue
            detected.append(finding)
        results["technologies"] = detected

    if include_advisories and results.get("technologies"):
        if progress_callback:
            progress_callback("NVD/EPSS advisory lookup", total, total)
        cve_lookup = CVELookup(api_key=os.environ.get("NVD_API_KEY"))
        seen_products = set()
        for technology in results["technologies"]:
            vendor = technology.get("cpe_vendor")
            product = technology.get("cpe_product")
            version = technology.get("version")
            if (
                not vendor
                or not product
                or not version
                or version == "Unknown"
                or technology.get("confidence", 0) < 70
                or (vendor, product, version) in seen_products
            ):
                continue
            seen_products.add((vendor, product, version))
            try:
                advisories = risk_rank(
                    cve_lookup.query_cpe(vendor, product, version)
                )
            except Exception as error:
                results["errors"].append({
                    "module": f"Advisory lookup: {technology['technology']}",
                    "error_type": type(error).__name__,
                    "message": str(error),
                })
                continue
            for advisory in advisories:
                severity = str(advisory.get("cvss_severity", "info")).lower()
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    severity = "info"
                results["findings"].append({
                    "module": "Known Vulnerability Advisory",
                    "severity": severity,
                    "title": f"{advisory['cve_id']} may affect {technology['technology']} {version}",
                    "detail": (
                        f"NVD lists this CVE for the detected product/version. "
                        f"Detection confidence is {technology['confidence']}%; "
                        "verify the product mapping, affected-version range, "
                        "configuration, and vendor advisory before treating it "
                        "as applicable. "
                        f"{advisory.get('summary', '')}"
                    ),
                    "cvss_score": advisory.get("cvss_score"),
                    "epss_score": advisory.get("epss_score"),
                    "reference": advisory.get("reference"),
                    "confidence": technology["confidence"],
                })

    return results


def print_summary(results: dict):
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(results["findings"], key=lambda f: sev_order.get(f["severity"], 5))

    print("\n" + "=" * 60)
    print(f"SCAN SUMMARY for {results['target']}")
    print("=" * 60)
    if not findings:
        print("No findings.")
    else:
        for f in findings:
            print(f"[{f['severity'].upper():8}] {f['title']}")
            if f.get("detail"):
                print(f"           {f['detail']}")
        print("=" * 60)
        print(f"Total findings: {len(findings)}")

    if results.get("errors"):
        print(f"Checks failed: {len(results['errors'])}")
        for error in results["errors"]:
            print(f"  [!] {error['module']}: {error['error_type']}: {error['message']}")


def main():
    parser = argparse.ArgumentParser(description="Cronos authorized web application security scanner")
    parser.add_argument("--url", required=True, help="Target base URL, e.g. https://example.com")
    parser.add_argument("--output", help="Write report to file (.json or .html based on extension)")
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Check the extended list of common sensitive-file paths",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive confirmation (only use in pre-authorized CI/CD pipelines)",
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        help="CI/CD security-gate mode: also writes SARIF, and exits non-zero if --fail-on-severity is met",
    )
    parser.add_argument(
        "--fail-on-severity",
        default="high",
        choices=["info", "low", "medium", "high", "critical"],
        help="With --gate, exit non-zero if any finding is at or above this severity (default: high)",
    )
    parser.add_argument(
        "--sarif",
        help="Also write a SARIF report to this path (for GitHub/GitLab/SonarQube ingestion)",
    )
    parser.add_argument(
        "--advisories",
        action="store_true",
        help="Opt in to NVD/EPSS lookups for high-confidence, versioned product detections.",
    )
    args = parser.parse_args()

    try:
        parsed = urlparse(args.url)
        valid_url = (
            parsed.scheme in ("http", "https")
            and parsed.hostname is not None
            and parsed.username is None
            and parsed.password is None
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except ValueError:
        valid_url = False
    if not valid_url:
        print("Error: --url must be a valid HTTP(S) URL without embedded credentials.")
        sys.exit(1)

    if not args.yes:
        if not confirm_authorization(args.url):
            print("Authorization not confirmed. Exiting.")
            sys.exit(1)
    else:
        print("[*] --yes flag set: skipping interactive confirmation (ensure authorization is on file).")

    results = run_scan(
        args.url,
        aggressive=args.aggressive,
        include_advisories=args.advisories,
    )
    print_summary(results)

    if args.output:
        if args.output.endswith(".json"):
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] JSON report written to {args.output}")
        elif args.output.endswith(".html"):
            html_report.write(results, args.output)
            print(f"\n[+] HTML report written to {args.output}")
        else:
            print("\n[!] Unknown output extension, writing JSON by default.")
            with open(args.output + ".json", "w") as f:
                json.dump(results, f, indent=2)

    if args.sarif or args.gate:
        sarif_path = args.sarif or "cronos.sarif"
        sarif_report.write(results, sarif_path)
        print(f"[+] SARIF report written to {sarif_path}")

    if args.gate:
        if results.get("errors"):
            print("\n[GATE] FAILED: one or more checks did not complete.")
            sys.exit(2)
        if sarif_report.should_fail_build(results, args.fail_on_severity):
            print(f"\n[GATE] FAILED: findings at or above '{args.fail_on_severity}' severity detected.")
            sys.exit(2)
        else:
            print(f"\n[GATE] PASSED: no findings at or above '{args.fail_on_severity}' severity.")


if __name__ != "__main__":
    __all__ = ["confirm_authorization", "main", "print_summary", "run_scan"]


if __name__ == "__main__":
    main()
