import tempfile
from pathlib import Path
from unittest.mock import patch

import responses

import scanner
from checks.cve_lookup import CVELookup, EPSS_URL, NVD_URL, risk_rank


@responses.activate
def test_cve_lookup_maps_nvd_records_and_caches_empty_or_populated_results():
    with tempfile.TemporaryDirectory() as cache_dir:
        responses.add(
            responses.GET,
            NVD_URL,
            json={
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-2025-1234",
                        "descriptions": [{"lang": "en", "value": "Example advisory"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {
                                    "baseScore": 8.1,
                                    "baseSeverity": "HIGH",
                                }
                            }]
                        },
                    }
                }]
            },
            status=200,
        )
        responses.add(
            responses.GET,
            EPSS_URL,
            json={"data": [{"cve": "CVE-2025-1234", "epss": "0.42", "percentile": "0.8"}]},
            status=200,
        )
        lookup = CVELookup(cache_dir=cache_dir)
        findings = lookup.query_cpe("nginx", "nginx", "1.2.3")

        assert findings[0]["cve_id"] == "CVE-2025-1234"
        assert findings[0]["cvss_score"] == 8.1
        assert findings[0]["epss_score"] == 0.42
        assert findings[0]["summary"] == "Example advisory"
        assert len(responses.calls) == 2
        assert lookup.query_cpe("nginx", "nginx", "1.2.3") == findings
        assert len(responses.calls) == 2
        assert len(list(Path(cache_dir).glob("*.json"))) == 1


def test_cve_lookup_skips_unknown_versions_without_network():
    with tempfile.TemporaryDirectory() as cache_dir:
        lookup = CVELookup(cache_dir=cache_dir)
        with patch("checks.cve_lookup.requests.get") as get:
            assert lookup.query_cpe("nginx", "nginx", "Unknown") == []
        get.assert_not_called()


def test_risk_rank_is_stable_for_higher_epSS_scores():
    items = [
        {"cve_id": "LOW", "cvss_score": 9.0, "epss_score": 0.01},
        {"cve_id": "ACTIVE", "cvss_score": 6.0, "epss_score": 0.9},
    ]

    assert [item["cve_id"] for item in risk_rank(items)] == ["ACTIVE", "LOW"]


@patch("scanner.CVELookup")
@patch("scanner.fingerprint.check")
def test_advisory_enrichment_requires_high_confidence_versioned_cpe(
    fingerprint_check, lookup_class
):
    fingerprint_check.return_value = [
        {
            "module": "Software Fingerprinting",
            "technology": "Nginx",
            "version": "1.2.3",
            "confidence": 80,
            "cpe_vendor": "f5",
            "cpe_product": "nginx",
            "title": "Technology detected: Nginx",
            "detail": "Detected Nginx.",
        },
        {
            "module": "Software Fingerprinting",
            "technology": "Apache",
            "version": "2.4",
            "confidence": 40,
            "cpe_vendor": "apache",
            "cpe_product": "http_server",
            "title": "Technology detected: Apache",
            "detail": "Detected Apache.",
        },
    ]
    lookup_class.return_value.query_cpe.return_value = [{
        "cve_id": "CVE-2025-1234",
        "cvss_score": 8.0,
        "cvss_severity": "HIGH",
        "epss_score": 0.1,
        "summary": "Example advisory.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-1234",
    }]

    results = scanner.run_scan(
        "https://authorized.example",
        selected_checks={"fingerprint"},
        include_advisories=True,
    )

    lookup_class.return_value.query_cpe.assert_called_once_with(
        "f5", "nginx", "1.2.3"
    )
    advisory_findings = [
        item for item in results["findings"]
        if item["module"] == "Known Vulnerability Advisory"
    ]
    assert len(advisory_findings) == 1
    assert "verify the product mapping" in advisory_findings[0]["detail"]


def test_empty_cve_response_parser_returns_empty_list():
    assert CVELookup._parse_nvd({"vulnerabilities": []}) == []


def test_cache_file_name_is_not_derived_from_untrusted_path_parts():
    with tempfile.TemporaryDirectory() as cache_dir:
        lookup = CVELookup(cache_dir=cache_dir)
        path = lookup._cache_path("../../outside", "product/../../x", "1.0")

    assert path.parent == Path(cache_dir)
    assert path.name.endswith(".json")
    assert ".." not in path.name
