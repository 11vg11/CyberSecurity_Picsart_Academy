"""Check basic SSL/TLS configuration: cert expiry, protocol support."""
import socket
import ssl
import datetime
import warnings
from urllib.parse import urlparse


WEAK_TLS_PROTOCOLS = (
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
)


def _supports_protocol(host: str, port: int, version: ssl.TLSVersion) -> bool:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
        with socket.create_connection((host, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except (OSError, ssl.SSLError, ValueError):
        return False


def check(
    url: str,
    aggressive: bool = False,
    check_legacy_protocols: bool = True,
) -> list:
    findings = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        findings.append({
            "module": "SSL/TLS Configuration",
            "severity": "high",
            "title": "Site not served over HTTPS",
            "detail": "The target URL uses plain HTTP. All traffic, including credentials, may be intercepted.",
        })
        return findings

    host = parsed.hostname
    port = parsed.port or 443

    # Certificate expiry check
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    days_left = (
                        expiry - datetime.datetime.now(datetime.timezone.utc)
                    ).days
                    if days_left < 0:
                        findings.append({
                            "module": "SSL/TLS Configuration",
                            "severity": "critical",
                            "title": "TLS certificate has expired",
                            "detail": f"Certificate expired on {not_after}.",
                        })
                    elif days_left < 14:
                        findings.append({
                            "module": "SSL/TLS Configuration",
                            "severity": "medium",
                            "title": "TLS certificate expiring soon",
                            "detail": f"Certificate expires in {days_left} day(s) on {not_after}.",
                        })
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "module": "SSL/TLS Configuration",
            "severity": "high",
            "title": "TLS certificate verification failed",
            "detail": str(e),
        })
    except (OSError, ssl.SSLError, ValueError) as e:
        findings.append({
            "module": "SSL/TLS Configuration",
            "severity": "info",
            "title": "Could not inspect TLS certificate",
            "detail": str(e),
        })

    if not check_legacy_protocols:
        return findings

    for name, version in WEAK_TLS_PROTOCOLS:
        if _supports_protocol(host, port, version):
            findings.append({
                "module": "SSL/TLS Configuration",
                "severity": "medium",
                "title": f"Weak TLS protocol accepted: {name}",
                "detail": (
                    f"The server completed a handshake restricted to {name}. "
                    "Disable obsolete TLS versions and require TLS 1.2 or later."
                ),
            })

    return findings
