"""SARIF (Static Analysis Results Interchange Format) output.

SARIF is the format GitHub Code Scanning, GitLab, and SonarQube natively
ingest, so writing it lets scan results show up directly as PR annotations
instead of needing a custom parser on the CI side.
"""
import json

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def write(results: dict, path: str):
    rules = {}
    sarif_results = []

    for f in results["findings"]:
        rule_id = f["title"].replace(" ", "_")[:80]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f.get("detail", f["title"])},
                "helpUri": f.get("reference", "https://owasp.org"),
            }

        sarif_results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF_LEVEL.get(f.get("severity", "info"), "note"),
            "message": {"text": f.get("detail", f["title"])},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": results["target"]}
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Cronos",
                    "version": "1.0.0",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }

    with open(path, "w") as f:
        json.dump(sarif, f, indent=2)


def should_fail_build(results: dict, fail_on_severity: str) -> bool:
    """Used by --gate mode: returns True if any finding meets or exceeds
    the configured severity threshold, so the CI job can exit non-zero."""
    if results.get("errors"):
        return True
    order = ["info", "low", "medium", "high", "critical"]
    threshold_idx = order.index(fail_on_severity.lower())
    for f in results["findings"]:
        sev = f.get("severity", "info").lower()
        if sev in order and order.index(sev) >= threshold_idx:
            return True
    return False
