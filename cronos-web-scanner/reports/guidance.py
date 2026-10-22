"""Short, general remediation pointers for common finding groups."""

GUIDANCE = {
    "HTTP Security Headers": (
        "Review the recommended header with your application owner and deploy "
        "a policy suited to the site. Test changes in staging first."
    ),
    "SSL/TLS Configuration": (
        "Review certificate renewal and TLS configuration with your hosting "
        "provider; require modern TLS and verify the full certificate chain."
    ),
    "Cookie Security": (
        "Set cookie attributes according to the cookie's purpose; use Secure "
        "on HTTPS, HttpOnly where JavaScript access is unnecessary, and an "
        "appropriate SameSite policy."
    ),
    "Security Misconfiguration": (
        "Verify the response and disable detailed framework errors on "
        "production systems."
    ),
    "Software Supply Chain": (
        "Review whether the third-party script is required and whether a "
        "stable, integrity-pinned resource is supported."
    ),
    "Sensitive Files & Directories": (
        "Verify that the response is the actual file, then remove it from the "
        "web root or deny access at the server."
    ),
    "Software Fingerprinting": (
        "Treat this as informational. Avoid exposing unnecessary version "
        "banners and keep identified components updated."
    ),
    "SBOM & Dependency Mapping": (
        "Remove public manifests if they are not intended to be public; verify "
        "advisories with the package maintainer and your lockfile."
    ),
    "Known Vulnerability Advisory": (
        "Confirm that the detected product and exact version match the "
        "advisory's affected range, then follow the vendor's remediation guidance."
    ),
}


def remediation_for(module: str) -> str:
    return GUIDANCE.get(
        module,
        "Review this indicator with the system owner and verify it before taking action.",
    )
