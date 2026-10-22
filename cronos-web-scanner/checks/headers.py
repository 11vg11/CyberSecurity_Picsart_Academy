"""Check for missing or misconfigured HTTP security headers."""
import requests

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "detail": "HSTS header missing. Site may be vulnerable to protocol downgrade / SSL stripping attacks.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "detail": "CSP header missing. Increases risk/impact of XSS attacks.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "detail": "X-Content-Type-Options missing (should be 'nosniff'). Allows MIME-type sniffing attacks.",
    },
    "X-Frame-Options": {
        "severity": "low",
        "detail": "X-Frame-Options missing. Site may be vulnerable to clickjacking.",
    },
    "Referrer-Policy": {
        "severity": "info",
        "detail": "Referrer-Policy not set. Referrer data may leak to third parties.",
    },
    "Permissions-Policy": {
        "severity": "info",
        "detail": "Permissions-Policy not set. Browser features are not explicitly restricted.",
    },
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def check(url: str, aggressive: bool = False) -> list:
    findings = []
    try:
        resp = requests.get(url, timeout=10, allow_redirects=False)
    except requests.RequestException as e:
        return [{
            "module": "HTTP Security Headers",
            "severity": "info",
            "title": "Could not connect to target",
            "detail": str(e),
        }]

    h = resp.headers

    for header, meta in RECOMMENDED_HEADERS.items():
        if header not in h:
            findings.append({
                "module": "HTTP Security Headers",
                "severity": meta["severity"],
                "title": f"Missing header: {header}",
                "detail": meta["detail"],
            })

    for header in LEAKY_HEADERS:
        if header in h:
            findings.append({
                "module": "HTTP Security Headers",
                "severity": "info",
                "title": f"Information disclosure via {header} header",
                "detail": f"{header}: {h[header]} — consider suppressing version/server banners.",
            })

    if "Set-Cookie" in h and "secure" not in h.get("Set-Cookie", "").lower() and url.startswith("https"):
        findings.append({
            "module": "HTTP Security Headers",
            "severity": "medium",
            "title": "Cookie set without Secure flag over HTTPS",
            "detail": "A Set-Cookie header was observed without the Secure attribute on an HTTPS site.",
        })

    return findings
