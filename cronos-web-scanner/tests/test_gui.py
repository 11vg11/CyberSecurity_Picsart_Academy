import socket

from gui import is_loopback_url, is_public_https_url, offline_demo_report


def test_loopback_validator_accepts_local_addresses():
    assert is_loopback_url("http://localhost:8000")
    assert is_loopback_url("https://127.0.0.1/path")
    assert is_loopback_url("http://[::1]:8080")


def test_loopback_validator_rejects_non_local_and_invalid_urls():
    assert not is_loopback_url("https://example.com")
    assert not is_loopback_url("http://192.168.1.20")
    assert not is_loopback_url("file:///etc/passwd")
    assert not is_loopback_url("http://localhost:invalid")
    assert not is_loopback_url("http://user:password@localhost")


def test_offline_demo_is_labeled_and_contains_sample_findings():
    report = offline_demo_report()

    assert "Offline demo" in report["target"]
    assert report["findings"]
    assert all(
        "illustrative demo data" in finding["detail"]
        for finding in report["findings"]
    )


def test_public_url_requires_https_and_public_resolution(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ],
    )

    assert is_public_https_url("https://example.test")
    assert not is_public_https_url("http://example.test")


def test_public_url_rejects_private_or_mixed_dns_results(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ],
    )

    assert not is_public_https_url("https://example.test")


def test_public_url_rejects_invalid_and_credential_urls():
    assert not is_public_https_url("https://user:pass@example.test")
    assert not is_public_https_url("https://127.0.0.1")
    assert not is_public_https_url("https://[::1]")
