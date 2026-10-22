import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import scanner
from checks import fingerprint
from fingerprint.detector import FingerprintEngine
from reports import diff, html_report, sarif_report


class FingerprintTests(unittest.TestCase):
    def test_engine_detects_versions_from_headers_and_html(self):
        results = FingerprintEngine().analyze(
            headers={"Server": "nginx/1.24.0"},
            html='<meta name="generator" content="WordPress 6.4.1">',
            cookies={},
        )

        by_name = {item["technology"]: item for item in results}
        self.assertEqual(by_name["Nginx"]["version"], "1.24.0")
        self.assertEqual(by_name["Nginx"]["evidence"], ["headers"])
        self.assertEqual(by_name["WordPress"]["version"], "6.4.1")
        self.assertGreaterEqual(by_name["WordPress"]["confidence"], 30)

    def test_signature_database_regexes_are_valid(self):
        engine = FingerprintEngine()
        self.assertTrue(engine.signatures)
        for rules in engine.signatures.values():
            for patterns in (rules.get("html", []), rules.get("cookies", [])):
                for pattern in patterns:
                    re.compile(pattern, re.IGNORECASE)
            for pattern in rules.get("headers", {}).values():
                re.compile(pattern, re.IGNORECASE)

    def test_fingerprint_header_matching_is_case_insensitive_and_not_double_counted(self):
        result = FingerprintEngine().analyze(
            headers={"sErVeR": "nginx/1.24.0"},
            html="",
            cookies={},
        )
        nginx = next(item for item in result if item["technology"] == "Nginx")

        self.assertEqual(nginx["evidence"], ["headers"])
        self.assertEqual(nginx["confidence"], 40)

    def test_clean_response_has_no_technology_false_positive(self):
        results = FingerprintEngine().analyze(
            headers={"Content-Type": "text/html"},
            html="<html><body>Welcome</body></html>",
            cookies={},
        )

        self.assertEqual(results, [])

    @patch("checks.fingerprint.requests.get")
    def test_check_uses_the_http_response_for_fingerprinting(self, get):
        get.return_value = SimpleNamespace(
            headers={"Server": "nginx/1.24.0"},
            text="",
            cookies=[],
        )

        findings = fingerprint.check("https://authorized.example")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "Technology detected: Nginx")
        get.assert_called_once_with(
            "https://authorized.example", timeout=10, allow_redirects=False
        )


class ReportTests(unittest.TestCase):
    def test_html_report_escapes_untrusted_values(self):
        results = {
            "target": "https://example.test/<script>",
            "scan_time": "2026-01-01T00:00:00Z",
            "findings": [{
                "module": "test",
                "severity": "high",
                "title": "<img src=x>",
                "detail": "message <script>alert(1)</script>",
            }],
        }

        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "report.html"
            html_report.write(results, str(report_path))
            output = report_path.read_text(encoding="utf-8")

        self.assertIn("&lt;script&gt;", output)
        self.assertIn("&lt;img src=x&gt;", output)
        self.assertNotIn("<script>alert(1)</script>", output)

    def test_html_report_displays_check_errors_safely(self):
        results = {
            "target": "https://example.test",
            "scan_time": "2026-01-01T00:00:00Z",
            "findings": [],
            "errors": [{
                "module": "Headers",
                "error_type": "RuntimeError",
                "message": "<script>failed</script>",
            }],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "report.html"
            html_report.write(results, str(report_path))
            output = report_path.read_text(encoding="utf-8")

        self.assertIn("Checks that failed", output)
        self.assertIn("&lt;script&gt;failed&lt;/script&gt;", output)
        self.assertNotIn("<script>failed</script>", output)

    def test_html_report_has_severity_filters_guidance_and_safe_references(self):
        results = {
            "target": "https://example.test",
            "scan_time": "2026-01-01T00:00:00Z",
            "findings": [{
                "module": "Known Vulnerability Advisory",
                "severity": "high",
                "title": "CVE-2025-1234",
                "detail": "Verify the affected release.",
                "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-1234",
                "confidence": 80,
            }],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "report.html"
            html_report.write(results, str(report_path))
            output = report_path.read_text(encoding="utf-8")

        self.assertIn("severity-filter", output)
        self.assertIn("Search findings", output)
        self.assertIn("80%", output)
        self.assertIn("Remediation guidance", output)
        self.assertIn('href="https://nvd.nist.gov/vuln/detail/CVE-2025-1234"', output)

    def test_html_report_does_not_link_unsafe_reference_schemes(self):
        results = {
            "target": "https://example.test",
            "findings": [{
                "module": "headers",
                "severity": "low",
                "title": "A finding",
                "reference": "javascript:alert(1)",
            }],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "report.html"
            html_report.write(results, str(report_path))
            output = report_path.read_text(encoding="utf-8")

        self.assertNotIn('href="javascript:', output)

    def test_sarif_output_and_severity_gate(self):
        results = {
            "target": "https://authorized.example",
            "findings": [{
                "module": "headers",
                "severity": "high",
                "title": "Missing CSP",
                "detail": "CSP is missing",
            }],
        }

        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "report.sarif"
            sarif_report.write(results, str(report_path))
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(report["runs"][0]["tool"]["driver"]["name"], "Cronos")
        self.assertEqual(report["runs"][0]["results"][0]["level"], "error")
        self.assertTrue(sarif_report.should_fail_build(results, "high"))
        self.assertFalse(sarif_report.should_fail_build(results, "critical"))
        self.assertTrue(sarif_report.should_fail_build(
            {"findings": [], "errors": [{"module": "headers"}]}, "critical"
        ))

    def test_diff_reports_classifies_findings(self):
        old = {"findings": [
            {"module": "headers", "title": "Old", "severity": "low"},
            {"module": "tls", "title": "Still here", "severity": "medium"},
        ]}
        new = {"target": "https://authorized.example", "findings": [
            {"module": "tls", "title": "Still here", "severity": "medium"},
            {"module": "headers", "title": "New", "severity": "high"},
        ]}

        result = diff.diff_reports(old, new)

        self.assertEqual(
            [finding["title"] for finding in result["newly_introduced"]], ["New"]
        )
        self.assertEqual(
            [finding["title"] for finding in result["resolved"]], ["Old"]
        )
        self.assertEqual(
            [finding["title"] for finding in result["still_present"]], ["Still here"]
        )


class ScannerTests(unittest.TestCase):
    @patch("scanner.sbom.check", return_value=[])
    @patch("scanner.fingerprint.check", return_value=[])
    @patch("scanner.sensitive_files.check", return_value=[])
    @patch("scanner.ssl_check.check", return_value=[])
    @patch("scanner.sri.check", return_value=[])
    @patch("scanner.security_misconfiguration.check", return_value=[])
    @patch("scanner.cookies.check", return_value=[])
    @patch("scanner.headers.check", return_value=[])
    def test_run_scan_uses_implemented_checks(
        self, headers_check, cookies_check, misconfiguration_check, sri_check,
        ssl_check, sensitive_check, fingerprint_check, sbom_check
    ):
        results = scanner.run_scan("https://authorized.example")

        self.assertEqual(results["target"], "https://authorized.example")
        self.assertEqual(results["findings"], [])
        for check in (
            headers_check,
            cookies_check,
            misconfiguration_check,
            sri_check,
            ssl_check,
            sensitive_check,
            fingerprint_check,
            sbom_check,
        ):
            check.assert_called_once_with("https://authorized.example", aggressive=False)

    @patch("scanner.sbom.check", return_value=[])
    @patch("scanner.fingerprint.check", return_value=[])
    @patch("scanner.sensitive_files.check", return_value=[])
    @patch("scanner.sri.check", return_value=[])
    @patch("scanner.security_misconfiguration.check", return_value=[])
    @patch("scanner.cookies.check", return_value=[])
    @patch("scanner.ssl_check.check", return_value=[])
    @patch("scanner.headers.check", return_value=[])
    def test_selected_checks_and_progress_callback(
        self,
        headers_check,
        ssl_check,
        cookies_check,
        misconfiguration_check,
        sri_check,
        sensitive_check,
        fingerprint_check,
        sbom_check,
    ):
        progress = []
        results = scanner.run_scan(
            "http://localhost",
            selected_checks={"headers", "cookies"},
            progress_callback=lambda name, index, total: progress.append(
                (name, index, total)
            ),
        )

        headers_check.assert_called_once()
        cookies_check.assert_called_once()
        ssl_check.assert_not_called()
        fingerprint_check.assert_not_called()
        self.assertEqual(
            progress,
            [
                ("HTTP Security Headers", 1, 2),
                ("Cookie Security", 2, 2),
            ],
        )
        self.assertEqual(results["errors"], [])
        self.assertNotIn("technologies", results)

    @patch("scanner.sbom.check")
    @patch("scanner.sensitive_files.check")
    @patch("scanner.fingerprint.check", return_value=[])
    @patch("scanner.sri.check", return_value=[])
    @patch("scanner.security_misconfiguration.check", return_value=[])
    @patch("scanner.cookies.check", return_value=[])
    @patch("scanner.ssl_check.check", return_value=[])
    @patch("scanner.headers.check", return_value=[])
    def test_passive_only_scan_skips_path_and_external_advisory_checks(
        self,
        headers_check,
        ssl_check,
        cookies_check,
        misconfiguration_check,
        sri_check,
        fingerprint_check,
        sensitive_check,
        sbom_check,
    ):
        scanner.run_scan("https://authorized.example", passive_only=True)

        for check in (
            headers_check,
            ssl_check,
            cookies_check,
            misconfiguration_check,
            sri_check,
            fingerprint_check,
        ):
            check.assert_called_once()
        sensitive_check.assert_not_called()
        sbom_check.assert_not_called()
        ssl_check.assert_called_once_with(
            "https://authorized.example",
            aggressive=False,
            check_legacy_protocols=False,
        )

    def test_cli_help_starts_without_network_access(self):
        scanner_path = Path(__file__).resolve().parents[1] / "scanner.py"
        completed = subprocess.run(
            [sys.executable, str(scanner_path), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Cronos", completed.stdout)
        self.assertIn("--fail-on-severity", completed.stdout)

    @patch("scanner.sbom.check", return_value=[])
    @patch("scanner.fingerprint.check", return_value=[])
    @patch("scanner.sensitive_files.check", return_value=[])
    @patch("scanner.sri.check", return_value=[])
    @patch("scanner.security_misconfiguration.check", return_value=[])
    @patch("scanner.cookies.check", return_value=[])
    @patch("scanner.ssl_check.check", return_value=[])
    @patch("scanner.headers.check", side_effect=RuntimeError("network unavailable"))
    def test_module_errors_are_separate_from_security_findings(
        self,
        headers_check,
        ssl_check,
        cookies_check,
        misconfiguration_check,
        sri_check,
        sensitive_check,
        fingerprint_check,
        sbom_check,
    ):
        results = scanner.run_scan("https://authorized.example")

        self.assertEqual(results["findings"], [])
        self.assertEqual(len(results["errors"]), 1)
        self.assertEqual(results["errors"][0]["module"], "HTTP Security Headers")
        self.assertEqual(results["errors"][0]["message"], "network unavailable")

    def test_print_summary_does_not_hide_errors_when_findings_are_empty(self):
        results = {
            "target": "https://authorized.example",
            "findings": [],
            "errors": [{
                "module": "Headers",
                "error_type": "Timeout",
                "message": "request timed out",
            }],
        }

        with patch("builtins.print") as output:
            scanner.print_summary(results)

        printed = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn("No findings.", printed)
        self.assertIn("Checks failed: 1", printed)
        self.assertIn("request timed out", printed)


if __name__ == "__main__":
    unittest.main()
