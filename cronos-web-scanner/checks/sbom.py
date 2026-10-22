"""Software Bill of Materials discovery.

Checks for commonly *accidentally exposed* dependency manifests
(package.json, requirements.txt, composer.lock, yarn.lock, Gemfile.lock)
at the web root. If found, parses them and cross-references named
packages/versions against OSV.dev (open, free, no-API-key vulnerability
database covering npm, PyPI, Composer, RubyGems, Maven, Go, crates.io).

This is read-only: it never attempts to fetch private source repos, only
checks whether a manifest file is reachable over HTTP, which is itself a
finding worth reporting regardless of what it contains.
"""
import json
import re
import requests
from urllib.parse import urljoin
from typing import List, Dict, Any

MANIFESTS = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "requirements.txt": "PyPI",
    "composer.json": "Packagist",
    "composer.lock": "Packagist",
    "Gemfile.lock": "RubyGems",
    "go.mod": "Go",
}

OSV_API = "https://api.osv.dev/v1/querybatch"


def _parse_package_json(text: str) -> List[Dict[str, str]]:
    deps = []
    try:
        data = json.loads(text)
        for section in ("dependencies", "devDependencies"):
            for name, version in data.get(section, {}).items():
                clean_version = re.sub(r"[^0-9.]", "", version.split("||")[0])
                if clean_version:
                    deps.append({"name": name, "version": clean_version, "ecosystem": "npm"})
    except json.JSONDecodeError:
        pass
    return deps


def _parse_requirements_txt(text: str) -> List[Dict[str, str]]:
    deps = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9A-Za-z.\-]+)", line)
        if match:
            deps.append({"name": match.group(1), "version": match.group(2), "ecosystem": "PyPI"})
    return deps


PARSERS = {
    "package.json": _parse_package_json,
    "requirements.txt": _parse_requirements_txt,
}


def _query_osv(deps: List[Dict[str, str]]) -> Dict[str, List[Dict[str, Any]]]:
    """Batch-query OSV.dev for known vulnerabilities in the given
    package@version list. Returns {package_key: [vuln, ...]}."""
    if not deps:
        return {}
    queries = [
        {"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]}
        for d in deps
    ]
    try:
        resp = requests.post(OSV_API, json={"queries": queries}, timeout=15)
        if resp.status_code != 200:
            return {}
        results = resp.json().get("results", [])
    except requests.RequestException:
        return {}

    out = {}
    for dep, result in zip(deps, results):
        vulns = result.get("vulns", [])
        if vulns:
            out[f"{dep['name']}@{dep['version']}"] = vulns
    return out


def check(url: str, aggressive: bool = False) -> list:
    findings = []
    base = url if url.endswith("/") else url + "/"

    all_deps = []
    for manifest, ecosystem in MANIFESTS.items():
        manifest_url = urljoin(base, manifest)
        try:
            resp = requests.get(manifest_url, timeout=8, allow_redirects=False)
        except requests.RequestException:
            continue
        if resp.status_code != 200 or len(resp.content) < 5:
            continue

        findings.append({
            "module": "SBOM & Dependency Mapping",
            "severity": "medium",
            "title": f"Exposed dependency manifest: /{manifest}",
            "detail": f"{manifest} is publicly accessible at {manifest_url}. This leaks your exact "
                      f"dependency tree to attackers, letting them target known CVEs precisely. "
                      f"Should be excluded from the web root / blocked at the reverse proxy.",
        })

        parser = PARSERS.get(manifest)
        if parser:
            all_deps.extend(parser(resp.text))

    if all_deps:
        vuln_map = _query_osv(all_deps)
        for pkg_key, vulns in vuln_map.items():
            ids = ", ".join(v.get("id", "?") for v in vulns[:5])
            findings.append({
                "module": "SBOM & Dependency Mapping",
                "severity": "high",
                "title": f"Vulnerable dependency detected: {pkg_key}",
                "detail": f"OSV.dev lists {len(vulns)} known advisory(ies) for this exact version: {ids}. "
                          f"See https://osv.dev for full details.",
            })

    return findings
