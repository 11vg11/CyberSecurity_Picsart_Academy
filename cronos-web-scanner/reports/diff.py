"""Compare two JSON scan reports to show drift over time: newly introduced
findings, resolved findings, and unchanged ones. Run as:

    python -m reports.diff old_report.json new_report.json
"""
import json
import sys


def _key(finding: dict) -> str:
    # Title + module is a reasonable identity for a finding across scans;
    # exact detail text often varies run to run (e.g. "expires in 13 days"
    # vs "12 days") so we don't key on it.
    return f"{finding.get('module')}::{finding.get('title')}"


def diff_reports(old: dict, new: dict) -> dict:
    old_findings = {_key(f): f for f in old.get("findings", [])}
    new_findings = {_key(f): f for f in new.get("findings", [])}

    old_keys = set(old_findings)
    new_keys = set(new_findings)

    return {
        "target": new.get("target", old.get("target")),
        "old_scan_time": old.get("scan_time"),
        "new_scan_time": new.get("scan_time"),
        "newly_introduced": [new_findings[k] for k in sorted(new_keys - old_keys)],
        "resolved": [old_findings[k] for k in sorted(old_keys - new_keys)],
        "still_present": [new_findings[k] for k in sorted(old_keys & new_keys)],
    }


def print_diff(diff: dict):
    print(f"Scan drift report for {diff['target']}")
    print(f"  {diff['old_scan_time']}  ->  {diff['new_scan_time']}")
    print()
    print(f"NEW findings since last scan ({len(diff['newly_introduced'])}):")
    for f in diff["newly_introduced"]:
        print(f"  [+] [{f['severity'].upper()}] {f['title']}")
    print()
    print(f"RESOLVED since last scan ({len(diff['resolved'])}):")
    for f in diff["resolved"]:
        print(f"  [-] [{f['severity'].upper()}] {f['title']}")
    print()
    print(f"Still present ({len(diff['still_present'])}) — unchanged, see full report for detail.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python -m reports.diff old_report.json new_report.json")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        old_report = json.load(f)
    with open(sys.argv[2]) as f:
        new_report = json.load(f)

    result = diff_reports(old_report, new_report)
    print_diff(result)
