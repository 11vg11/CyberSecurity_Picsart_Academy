import responses

from checks import cookies, security_misconfiguration, sri
from utils.http_client import ScanHTTPClient, WAFState


TARGET = "https://authorized.example/"


def _disable_throttle(monkeypatch):
    monkeypatch.setattr(ScanHTTPClient, "_throttle", lambda self: None)


@responses.activate
def test_sri_flags_external_script_without_integrity(monkeypatch):
    _disable_throttle(monkeypatch)
    responses.add(
        responses.GET,
        TARGET,
        body=(
            '<script src="/app.js"></script>'
            '<script src="https://cdn.example/library.js"></script>'
            '<script src="https://static.example/verified.js" integrity="sha384-test"></script>'
        ),
        status=200,
    )

    findings = sri.check(TARGET)

    assert len(findings) == 1
    assert findings[0]["module"] == "Software Supply Chain"
    assert "cdn.example" in findings[0]["detail"]


@responses.activate
def test_sri_has_no_false_positive_for_integrity_and_same_origin_scripts(monkeypatch):
    _disable_throttle(monkeypatch)
    responses.add(
        responses.GET,
        TARGET,
        body=(
            '<script src="/app.js"></script>'
            '<script src="https://cdn.example/library.js" integrity="sha384-test"></script>'
        ),
        status=200,
    )

    assert sri.check(TARGET) == []


@responses.activate
def test_sri_flags_empty_integrity_attribute(monkeypatch):
    _disable_throttle(monkeypatch)
    responses.add(
        responses.GET,
        TARGET,
        body='<script src="https://cdn.example/library.js" integrity=""></script>',
        status=200,
    )

    assert len(sri.check(TARGET)) == 1


@responses.activate
def test_debug_page_signature_is_reported(monkeypatch):
    _disable_throttle(monkeypatch)
    responses.add(
        responses.GET,
        TARGET,
        body="You're seeing this error because you have DEBUG = True",
        status=200,
    )

    findings = security_misconfiguration.check(TARGET)

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "Django debug page" in findings[0]["title"]


@responses.activate
def test_clean_page_has_no_debug_page_finding(monkeypatch):
    _disable_throttle(monkeypatch)
    responses.add(
        responses.GET,
        TARGET,
        body="<html><title>Welcome</title><body>Service is available.</body></html>",
        status=200,
    )

    assert security_misconfiguration.check(TARGET) == []


@responses.activate
def test_cookie_attributes_are_checked_from_response(monkeypatch):
    _disable_throttle(monkeypatch)
    responses.add(
        responses.GET,
        TARGET,
        body="ok",
        status=200,
        headers={"Set-Cookie": "session=abc; Path=/"},
    )

    findings = cookies.check(TARGET)

    assert len(findings) == 1
    assert findings[0]["title"] == "Cookie missing security attributes: session"
    assert all(
        flag in findings[0]["detail"]
        for flag in ("Secure", "HttpOnly", "SameSite")
    )


@responses.activate
def test_cookie_with_security_attributes_has_no_false_positive(monkeypatch):
    _disable_throttle(monkeypatch)
    responses.add(
        responses.GET,
        TARGET,
        body="ok",
        status=200,
        headers={
            "Set-Cookie": "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
        },
    )

    assert cookies.check(TARGET) == []


def test_waf_state_detects_block_responses_without_changing_user_agent():
    state = WAFState(window=3, block_threshold=2)
    state.record(403)
    assert not state.is_triggered()
    state.record(429)
    assert state.is_triggered()
