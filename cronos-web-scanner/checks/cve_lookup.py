"""Optional NVD and EPSS lookups for explicitly mapped product versions."""
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"


class CVELookup:
    def __init__(
        self,
        cache_dir: str | Path | None = None,
        api_key: str | None = None,
        cache_ttl_days: int = 7,
        timeout: float = 8.0,
    ):
        self.cache_dir = Path(
            cache_dir or Path.home() / ".cache" / "cronos" / "cve"
        )
        self.api_key = api_key
        self.cache_ttl_days = max(0, cache_ttl_days)
        self.timeout = timeout

    def _cache_path(self, vendor: str, product: str, version: str) -> Path:
        cache_key = f"{vendor}:{product}:{version}".encode("utf-8")
        digest = hashlib.sha256(cache_key).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _read_cache(self, path: Path) -> list[dict[str, Any]] | None:
        if not path.is_file():
            return None
        age_days = (time.time() - path.stat().st_mtime) / 86400
        if age_days >= self.cache_ttl_days:
            return None
        with path.open(encoding="utf-8") as cache_file:
            cached = json.load(cache_file)
        if not isinstance(cached, list):
            raise ValueError(f"Invalid CVE cache format: {path}")
        return cached

    def query_cpe(
        self, vendor: str, product: str, version: str
    ) -> list[dict[str, Any]]:
        if not vendor or not product or not version or version == "Unknown":
            return []
        cache_path = self._cache_path(vendor, product, version)
        cached = self._read_cache(cache_path)
        if cached is not None:
            return cached

        cpe_name = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        response = requests.get(
            NVD_URL,
            params={"cpeName": cpe_name},
            headers=headers,
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise RuntimeError("NVD rate limit reached; retry later.")
        response.raise_for_status()

        vulnerabilities = self._parse_nvd(response.json())
        if vulnerabilities:
            self._enrich_with_epss(vulnerabilities)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        temporary_path = cache_path.with_suffix(".tmp")
        with temporary_path.open("w", encoding="utf-8") as cache_file:
            json.dump(vulnerabilities, cache_file, indent=2)
        temporary_path.replace(cache_path)
        return vulnerabilities

    @staticmethod
    def _parse_nvd(data: dict[str, Any]) -> list[dict[str, Any]]:
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss_metric = (
                metrics.get("cvssMetricV40")
                or metrics.get("cvssMetricV31")
                or metrics.get("cvssMetricV30")
                or metrics.get("cvssMetricV2")
                or [{}]
            )[0]
            cvss_data = cvss_metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = (
                cvss_metric.get("baseSeverity")
                or cvss_data.get("baseSeverity")
                or "UNKNOWN"
            )
            if severity == "UNKNOWN" and isinstance(cvss_score, (int, float)):
                if cvss_score >= 9:
                    severity = "CRITICAL"
                elif cvss_score >= 7:
                    severity = "HIGH"
                elif cvss_score >= 4:
                    severity = "MEDIUM"
                elif cvss_score > 0:
                    severity = "LOW"
            descriptions = cve.get("descriptions", [])
            english_description = next(
                (
                    description.get("value", "")
                    for description in descriptions
                    if description.get("lang") == "en"
                ),
                "",
            )
            cve_id = cve.get("id")
            if not cve_id:
                continue
            results.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "cvss_severity": severity,
                "epss_score": None,
                "epss_percentile": None,
                "summary": english_description,
                "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return results

    def _enrich_with_epss(self, vulnerabilities: list[dict[str, Any]]) -> None:
        cve_ids = [item["cve_id"] for item in vulnerabilities if item.get("cve_id")]
        if not cve_ids:
            return
        try:
            response = requests.get(
                EPSS_URL,
                params={"cve": ",".join(cve_ids)},
                timeout=self.timeout,
            )
        except requests.RequestException:
            return
        if response.status_code != 200:
            return
        rows = response.json().get("data", [])
        epss_data = {row["cve"]: row for row in rows if row.get("cve")}
        for vulnerability in vulnerabilities:
            row = epss_data.get(vulnerability["cve_id"])
            if row:
                vulnerability["epss_score"] = float(row.get("epss", 0))
                vulnerability["epss_percentile"] = float(row.get("percentile", 0))


def risk_rank(
    vulnerabilities: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    def score(vulnerability: dict[str, Any]) -> float:
        cvss = vulnerability.get("cvss_score") or 0.0
        epss = vulnerability.get("epss_score") or 0.0
        return (epss * 0.7) + ((cvss / 10) * 0.3)

    return sorted(vulnerabilities, key=score, reverse=True)
