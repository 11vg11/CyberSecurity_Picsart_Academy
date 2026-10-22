"""Check for commonly exposed sensitive files and directories.

Only checks well-known, non-guessable-secret paths that commonly get
left exposed by misconfiguration (NOT a brute-force directory buster).
"""
import requests
from urllib.parse import urljoin

COMMON_PATHS = [
    ".env",
    ".git/config",
    ".git/HEAD",
    "wp-config.php.bak",
    "config.php.bak",
    ".DS_Store",
    "backup.zip",
    "backup.sql",
    "database.sql",
    ".aws/credentials",
    "web.config",
    "server-status",
    "phpinfo.php",
    ".htaccess",
    "composer.json",
    "package.json",
    "id_rsa",
    "debug.log",
    "error_log",
]


def check(url: str, aggressive: bool = False) -> list:
    findings = []
    base = url if url.endswith("/") else url + "/"

    paths_to_check = COMMON_PATHS if aggressive else COMMON_PATHS[:10]

    for path in paths_to_check:
        test_url = urljoin(base, path)
        try:
            resp = requests.get(test_url, timeout=8, allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                # Avoid false positives where server returns 200 for everything (SPA catch-all)
                findings.append({
                    "module": "Sensitive Files & Directories",
                    "severity": "high" if path in (".env", ".git/config", "id_rsa", ".aws/credentials") else "medium",
                    "title": f"Potentially exposed file: /{path}",
                    "detail": f"HTTP {resp.status_code} returned for {test_url} — verify manually, this may be a false positive on SPA/catch-all routes.",
                })
        except requests.RequestException:
            continue

    return findings
