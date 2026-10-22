# Cronos

Cronos is a Python command-line and desktop tool for identifying selected,
externally observable web-security issues. It is intended for coursework,
local development labs, and systems that you own or are explicitly authorized
to assess.

Cronos is a **lightweight triage scanner**, not a penetration-testing
framework or a guarantee that a site is secure. A finding is an indicator to
review, not proof of exploitability. Cronos does not execute exploits, log in,
attempt password guesses, or modify target data.

## Choose the right mode

| Mode | Network access | What it does |
|---|---|---|
| GUI offline demo | None | Displays simulated sample findings so you can explore the interface. It does not test an application. |
| GUI local lab | Requests the local service | Checks a Docker-published service or other local app at `localhost`, `127.0.0.1`, or `::1`. Internet access is not required. |
| GUI public website | HTTPS to the given URL | Runs passive checks on that page only, after the URL resolves exclusively to globally routable addresses. It does not enumerate paths or call external vulnerability databases. |
| CLI scan | Requests the URL and configured check paths | Runs all implemented checks, including common exposed-path checks and optional dependency advisory lookups. Use only within an approved scope. |

All live modes require an authorized target. The GUI requires an explicit
confirmation checkbox. The CLI asks you to type `I AM AUTHORIZED`, unless
`--yes` is used for a pre-authorized automation workflow.

### Docker or local lab

Publish the container port to the host when starting the lab. For example,
`-p 3000:80` maps container port 80 to port 3000 on your computer. In the GUI,
choose **Scan a local Docker or home lab** and enter:

```text
http://127.0.0.1:3000
```

Use the host port from your own Docker configuration; it may differ from
`3000`. Cronos does not start or manage the container for you.

### Public website

Choose **Check an authorized public website**, enter an HTTPS URL, confirm
authorization, and run the check. This mode inspects only the provided page:
HTTP response headers, TLS certificate status, cookies, technology indicators,
framework debug-page signatures, and third-party script SRI metadata. It does
not follow redirects or request additional paths. If the hostname resolves to
any local/private address, the GUI rejects it.

DNS validation is a precaution, not a substitute for scope review; DNS records
can change after validation. Only scan a hostname explicitly included in your
authorization.

## Requirements and installation

- Python 3.10 or later is recommended.
- `requests` for the scanner.
- Tkinter for the desktop GUI (usually included with Python; some Linux
  distributions package it separately).

From the repository root:

```bash
cd cronos-web-scanner
python3 -m pip install -r requirements.txt
```

For editable installation with `cronos-scan` and `cronos-gui` commands:

```bash
python3 -m pip install -e .
cronos-gui
cronos-scan --help
```

Launch the GUI:

```bash
python3 gui.py
```

If Tkinter is missing on Linux, install the Tk package supplied by your
distribution (commonly named `python3-tk`).

## Command-line use

Start an interactive scan of an authorized target:

```bash
python3 scanner.py --url https://your-authorized-target.example
```

Write a report:

```bash
python3 scanner.py --url https://your-authorized-target.example --output report.json
python3 scanner.py --url https://your-authorized-target.example --output report.html
```

`--aggressive` extends the common exposed-path list. It does not enable
exploitation, but it does make additional requests to the target:

```bash
python3 scanner.py --url https://your-authorized-target.example --aggressive
```

Optional NVD/EPSS advisory matching requires internet access. It is limited to
versioned detections with at least 70% signal confidence and reviewed CPE
mappings in the signature data:

```bash
python3 scanner.py --url https://your-authorized-target.example --advisories
```

If you have an NVD API key, set it in `NVD_API_KEY` before running to improve
NVD request limits. Detected product/version data is sent to NVD and matching
CVE IDs are sent to FIRST.org for EPSS enrichment. Advisory matches are
unconfirmed indicators; verify affected-version ranges with the vendor.

For an approved CI job, `--yes` skips the interactive prompt. `--gate` writes
a SARIF report and returns exit status 2 if a finding meets the selected
severity threshold **or if any check failed**:

```bash
python3 scanner.py \
  --url https://staging.example \
  --yes \
  --gate \
  --fail-on-severity high \
  --sarif cronos.sarif \
  --output report.json
```

Available severity thresholds are `info`, `low`, `medium`, `high`, and
`critical`; the default is `high`. Without `--sarif`, `--gate` writes
`cronos.sarif`. See all CLI options with:

```bash
python3 scanner.py --help
```

## What Cronos checks

| Check | Current behavior | Limitations |
|---|---|---|
| HTTP security headers | Flags missing recommended headers and exposed server/version banners. | Missing a header is a hardening observation, not proof of a vulnerability. |
| TLS and certificate | Checks certificate verification and expiry, probes whether TLS 1.0/1.1 handshakes are accepted in standard scans, and reports when the requested URL uses HTTP. Public GUI mode skips legacy protocol probes. | Does not audit all cipher suites, HSTS preload status, or application cryptography. Legacy protocol availability can depend on the local OpenSSL policy. |
| Cookie attributes | Reviews cookies returned by the supplied page for `Secure`, `HttpOnly`, and `SameSite`. | Cookie requirements depend on how each cookie is used; findings need context. |
| Framework debug indicators | Matches a small set of known Django, Werkzeug, Laravel, and ASP.NET debug-page signatures in the supplied page response. | Signature matching can miss customized errors or produce false positives. |
| Script SRI | Reports third-party scripts in the supplied page without a non-empty `integrity` attribute. | Does not fetch or verify script contents; SRI is not appropriate for every dynamic script. |
| Technology fingerprinting | Matches response headers, cookies, and HTML against `fingerprint/signatures.json`; extracts versions where a signature provides one. | Only detects technologies that expose a known signature. Version matching may be incomplete. |
| Common exposed paths | Requests a bounded list of common file paths; `--aggressive` adds more paths. | HTTP 200 responses may be catch-all pages. Verify any exposure manually. |
| Dependency manifests | The CLI checks common public manifest paths. Supported package manifests can be queried against OSV.dev for known advisories. | Only exposed and supported manifests are considered. Advisory lookups need internet access; a match is not proof that the deployed code is exploitable. |

The GUI lets you choose checks. Public-site mode automatically skips path and
dependency-manifest checks; local-lab mode can run those checks when selected.
Dependency manifest lookups contact OSV.dev. NVD/EPSS lookups are an explicit
CLI-only `--advisories` option.

The signature database currently provides CPE mappings for a small set of
products (WordPress, Nginx, Apache HTTP Server, and PHP). Advisory matching is
not run by default and requires a version plus at least 70% signal confidence.
The confidence score represents matched fingerprint signal categories, not a
statistical probability that a component is vulnerable.

## Understanding reports and errors

Reports contain the target, scan time, findings, and a separate `errors` list.
Findings describe observations. Errors mean a check did not complete; they are
not vulnerabilities and are displayed separately in the terminal, GUI, and
HTML report. The CI gate fails if errors are present so an incomplete scan is
not silently reported as a clean result.

Supported output formats:

- **JSON** — structured scan data for scripts and other tools.
- **HTML** — readable report with severity counts, text/severity filters,
  confidence where available, references, and general remediation pointers.
- **SARIF 2.1.0** — findings for compatible code-scanning/reporting platforms.

Compare two JSON reports from `cronos-web-scanner`:

```bash
python3 -m reports.diff old_report.json new_report.json
```

## Roadmap

Recently added:

- HTML severity summaries, filters, confidence display, advisory references,
  and general remediation pointers.
- GUI check selection, per-check progress, JSON/HTML export, and opening a
  saved report.
- Signature regex validation, case-insensitive header matching, and signal
  evidence in fingerprint results.
- Opt-in NVD/EPSS matching for high-confidence detections with explicit CPE
  mappings and a local cache.
- Editable installation and `cronos-scan` / `cronos-gui` commands.

Still planned:

- Expand and independently review technology signatures, including broader
  version-pattern coverage and regression fixtures.
- Improve false-positive detection for single-page-app catch-all routes and
  dependency manifests.
- Add more robust check-level cancellation and progress reporting for long
  advisory lookups.
- Further improve keyboard navigation, screen-reader labels, and contrast in
  the desktop interface.
- Keep OWASP coverage notes aligned with each implemented check.

Any future active checks remain subject to explicit authorization and must be
bounded, non-destructive, and transparent. Cronos will not add automated
exploitation, credential guessing, data extraction, or security-control
evasion.

## Tests

Tests use pytest and mocked HTTP responses; they do not scan live systems.
Create a virtual environment if the system Python does not allow package
installation:

```bash
cd cronos-web-scanner
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

## Project layout

```text
cronos-web-scanner/
├── scanner.py
├── gui.py
├── pyproject.toml
├── checks/
│   ├── cookies.py
│   ├── cve_lookup.py
│   ├── fingerprint.py
│   ├── headers.py
│   ├── sbom.py
│   ├── security_misconfiguration.py
│   ├── sensitive_files.py
│   ├── sri.py
│   └── ssl_check.py
├── fingerprint/
│   ├── detector.py
│   └── signatures.json
├── reports/
│   ├── diff.py
│   ├── html_report.py
│   └── sarif_report.py
├── tests/
│   ├── test_advisories.py
│   ├── test_gui.py
│   ├── test_passive_checks.py
│   ├── test_project.py
│   └── test_tls.py
└── utils/
    └── http_client.py
```

## Safety, privacy, and limitations

- Run scans only on assets you own or have explicit written permission to test.
  Follow the engagement scope, timing, rate, and reporting requirements.
- Cronos is not an exploit validator. It does not test IDOR, authentication
  bypass, SQL/command injection, SSRF, rate-limit resistance, or business
  logic.
- Password hashing, access-control policy, internal audit logging, and other
  server-side controls cannot generally be established from an external HTTP
  response.
- Public GUI mode rejects non-HTTPS URLs, redirect following, and hostnames
  that resolve to non-public addresses. It is a limited passive check, not a
  substitute for the CLI or a professional assessment.
- The CLI and local GUI can contact OSV.dev when a supported dependency
  manifest is exposed and parsed. Package names and versions are sent to that
  service for advisory matching.
- Scan results can contain target URLs, response-derived technology/version
  data, and error messages. Store and share generated reports according to
  your organization's data-handling rules.

Cronos is an early-stage project. Review the code and its scope before using
it in coursework, CI, or an assessment.
