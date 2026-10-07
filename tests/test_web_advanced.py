import time

import httpx
import pytest
from PySide6.QtWidgets import QApplication

from cyberintel.config import Config
from cyberintel.models import ValidationError
from cyberintel.ui import MainWindow
from cyberintel.web_assessment import assess_web, fetch, header_findings


def run(handler, **kwargs):
    return assess_web("https://example.com/app", True, False, False, httpx.MockTransport(handler), **kwargs)


def test_cors_reflection_and_advertised_methods_are_review_not_exploits():
    requests = []
    def handler(request):
        requests.append(request)
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={"Allow": "GET, HEAD, PUT, DELETE, TRACE"})
        origin = request.headers.get("origin")
        return httpx.Response(200, headers={"access-control-allow-origin": origin, "access-control-allow-credentials": "true"} if origin else {})
    result = run(handler, check_cors=True, check_methods=True)
    rows = {row["check"]: row for row in result.data["records"]}
    assert rows["CORS origin policy"]["status"] == "review"
    assert "authenticated impact has not been tested" in rows["CORS origin policy"]["recommendation"]
    assert rows["Advertised HTTP methods"]["status"] == "review"
    assert {request.method for request in requests} == {"GET", "OPTIONS"}
    assert len(requests) == 4
    assert result.data["selected_checks"]["cors"]
    assert result.data["summary"]["findings"] == len(result.data["records"])


@pytest.mark.parametrize("allowed,credentials,expected", [("*", "false", "observed"), ("*", "true", "review"),
                                                         ("https://trusted.example", "true", "observed"), ("", "", "observed")])
def test_cors_observations_do_not_overclaim(allowed, credentials, expected):
    result = run(lambda _: httpx.Response(200, headers={"access-control-allow-origin": allowed,
                                                       "access-control-allow-credentials": credentials}), check_cors=True)
    row = next(row for row in result.data["records"] if row["check"] == "CORS origin policy")
    assert row["status"] == expected
    if allowed == "*" and credentials == "true":
        assert "rejected by browsers" in row["recommendation"]


def test_disabled_optional_checks_make_no_extra_requests():
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200)
    result = run(handler)
    assert len(requests) == 1 and requests[0].method == "GET"
    assert "cors_observations" not in result.data
    assert "advertised_methods" not in result.data


def test_options_failure_retains_header_findings():
    result = run(lambda request: httpx.Response(501 if request.method == "OPTIONS" else 200), check_methods=True)
    assert result.status == "live" and result.data["records"]
    assert "HTTP 501" in result.error
    assert result.data["summary"]["warning_count"] == 1


def test_cors_cross_host_redirect_rejected():
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://other.example/"}) if request.headers.get("origin") else httpx.Response(200)
    result = run(handler, check_cors=True)
    assert result.status == "live" and "authorized host" in result.error
    assert all(url.startswith("https://example.com/") for url in calls)


def test_duplicate_csp_uses_first_policy_and_reports_ambiguity():
    rows = {row["check"]: row for row in header_findings(httpx.Headers({
        "content-security-policy": "frame-ancestors *; frame-ancestors 'none'; script-src * 'unsafe-eval'"}))}
    assert rows["Framing protection"]["status"] == "review"
    assert rows["CSP duplicate directives"]["status"] == "review"
    assert "unsafe-eval" in rows["CSP script sources"]["evidence"]


def test_report_only_and_invalid_cookie_prefixes():
    rows = {row["check"]: row for row in header_findings(httpx.Headers([
        ("content-security-policy-report-only", "default-src 'self'"),
        ("set-cookie", "__Host-session=hidden; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=example.com"),
        ("set-cookie", "__Secure-session=hidden; HttpOnly; SameSite=Strict")]))}
    assert rows["CSP report-only mode"]["status"] == "observed"
    assert rows["Cookie prefix: __Host-session"]["status"] == "review"
    assert rows["Cookie prefix: __Secure-session"]["status"] == "review"
    assert "hidden" not in str(rows)


def test_expired_request_budget_does_not_send_request():
    with pytest.raises(ValidationError, match="time budget"):
        fetch("https://example.com/", "https://example.com/", httpx.MockTransport(lambda _: pytest.fail("No request")), deadline=time.monotonic() - 1)
    with pytest.raises(ValidationError, match="GET and OPTIONS"):
        fetch("https://example.com/", "https://example.com/", method="DELETE")


def test_ui_advanced_options_and_summary(session, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(session.store.home), session)
    monkeypatch.setattr(window, "start_job", lambda label, task, done: done(task()))
    def assess(value, authorized, tls, disclosure, **kwargs):
        assert kwargs == {"check_cors": True, "check_methods": True}
        return run(lambda _: httpx.Response(200, headers={"allow": "GET, HEAD"}), **kwargs)
    monkeypatch.setattr("cyberintel.ui.assess_web", assess)
    try:
        assert not window.web_cors.isChecked() and not window.web_methods.isChecked()
        window.web_cors.setChecked(True)
        window.web_methods.setChecked(True)
        window.web_target.setText("https://example.com/app")
        window.web_authorized.setChecked(True)
        window.run_web_assessment()
        assert "review items" in window.web_controls["status"].text()
        assert window.last_results["web"].data["selected_checks"]["cors"]
    finally:
        window.close()
