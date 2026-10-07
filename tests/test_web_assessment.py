import json
import ssl

import httpx
import pytest
from PySide6.QtWidgets import QApplication

from cyberintel.config import Config
from cyberintel.models import ValidationError
from cyberintel.web_assessment import assess_web, header_findings, target_url, tls_details
from cyberintel.ui import MainWindow


@pytest.mark.parametrize("url", ["http://example.com", "https://user:secret@example.com/", "https://example.com:8443/",
    "https://example.com/?secret=token", "https://example.com/#secret", "https://example.com/a\nb", "--script=all"])
def test_invalid_targets(url):
    with pytest.raises(ValidationError):
        target_url(url)


def test_no_requests_without_permission():
    with pytest.raises(ValidationError, match="permission"):
        assess_web("https://example.com", transport=httpx.MockTransport(lambda _: pytest.fail("No request")))


def tls_fixture(host):
    return {"protocol": "TLSv1.3", "cipher": "fixture", "days_remaining": 90,
            "expires_at": "2099-01-01T00:00:00Z", "hostname_and_chain_verified": True}


def handler(request):
    if request.url.path == "/.well-known/security.txt":
        return httpx.Response(200, text="Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\n", headers={"content-type": "text/plain"})
    return httpx.Response(200, text="PRIVATE BODY", headers=[
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Set-Cookie", "session=SECRET_COOKIE; Secure; HttpOnly; SameSite=Lax"),
        ("Set-Cookie", "preferences=SECOND_SECRET; Path=/"),
    ])


def test_full_assessment_redacts_values_and_body():
    result = assess_web("https://example.com", True, transport=httpx.MockTransport(handler), tls_probe=tls_fixture)
    assert result.status == "live" and not result.error
    rows = {row["check"]: row for row in result.data["records"]}
    assert rows["HSTS"]["status"] == "present"
    assert rows["Framing protection"]["status"] == "present"
    assert rows["Cookie: session"]["status"] == "present"
    assert rows["Cookie: preferences"]["status"] == "review"
    assert rows["TLS certificate"]["status"] == "verified"
    assert rows["security.txt"]["status"] == "present"
    for secret in ("SECRET_COOKIE", "SECOND_SECRET", "PRIVATE BODY"):
        assert secret not in json.dumps(result.to_dict())


@pytest.mark.parametrize("headers", [{}, {"strict-transport-security": "max-age=0"},
    {"content-security-policy": "frame-ancestors *", "x-frame-options": "DENY"}])
def test_weak_or_missing_headers_require_review(headers):
    rows = {row["check"]: row for row in header_findings(httpx.Headers(headers))}
    assert rows["HSTS"]["status"] == "review"
    assert rows["Framing protection"]["status"] == "review"


def test_cross_host_redirect_not_requested():
    calls = []
    def redirect(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://other.example/"})
    result = assess_web("https://example.com/", True, False, False, httpx.MockTransport(redirect))
    assert result.status == "unavailable" and "authorized host" in result.error
    assert calls == ["https://example.com/"]


def test_same_host_redirect_and_error_pages():
    calls = []
    def redirect(request):
        calls.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/app"})
        return httpx.Response(403)
    result = assess_web("https://example.com/", True, False, False, httpx.MockTransport(redirect))
    assert result.status == "unavailable" and "HTTP 403" in result.error
    assert calls == ["/", "/app"]
    assert result.data["records"] == []


def test_failures_keep_successful_checks():
    def partial(request):
        if request.url.path == "/.well-known/security.txt":
            raise httpx.ConnectError("Unavailable")
        return httpx.Response(200)
    def fail_tls(host):
        raise ssl.SSLCertVerificationError("Invalid chain")
    result = assess_web("https://example.com/", True, transport=httpx.MockTransport(partial), tls_probe=fail_tls)
    assert result.status == "live" and result.data["records"]
    assert "TLS certificate" in result.error and "security.txt" in result.error


@pytest.mark.parametrize("body", ["Contact: \nExpires: 2099-01-01T00:00:00Z", "Contact: mailto:a@example.com\nExpires: 2000-01-01T00:00:00Z", "<html>not disclosure metadata</html>"])
def test_invalid_disclosure_data_is_review(body):
    result = assess_web("https://example.com/", True, False, True,
        httpx.MockTransport(lambda request: httpx.Response(200, text=body, headers={"content-type": "text/plain"})))
    row = next(row for row in result.data["records"] if row["check"] == "security.txt")
    assert row["status"] == "review"


def test_missing_disclosure_is_information_only():
    def missing(request):
        return httpx.Response(404 if request.url.path.endswith("security.txt") else 200)
    result = assess_web("https://example.com/", True, False, True, httpx.MockTransport(missing))
    row = next(row for row in result.data["records"] if row["check"] == "security.txt")
    assert row["severity"] == "info" and row["status"] == "not published"


def test_private_addresses_blocked_and_tls_not_bypassed(monkeypatch):
    monkeypatch.setattr("cyberintel.connectors.socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    monkeypatch.setattr("cyberintel.web_assessment.socket.create_connection", lambda *a, **k: pytest.fail("No connection"))
    result = assess_web("https://example.com/", True)
    assert result.status == "unavailable" and "public Internet" in result.error
    with pytest.raises(ValidationError):
        tls_details("example.com")


def test_ui_case_save_restore_and_exports(session, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(session.store.home), session)
    monkeypatch.setattr(window, "start_job", lambda label, task, done: done(task()))
    monkeypatch.setattr("cyberintel.ui.assess_web", lambda value, authorized, tls, disclosure, **kwargs:
        assess_web(value, authorized, tls, disclosure, httpx.MockTransport(handler), tls_fixture, **kwargs))
    try:
        case = session.create_case("Web review fixture")
        window.reload_cases(case)
        window.web_target.setText("https://example.com/")
        with pytest.raises(ValidationError):
            window.run_web_assessment()
        window.web_authorized.setChecked(True)
        window.run_web_assessment()
        assert window.web_controls["table"].model.rows
        assert session.rows("findings", case)[0]["module"] == "web"
        window.findings_table.view.selectRow(0)
        window.restore_finding()
        assert window.navigation.currentRow() == 14
        for kind in ("json", "csv"):
            path = tmp_path / ("web." + kind)
            monkeypatch.setattr("cyberintel.ui.QFileDialog.getSaveFileName", lambda *a, **k: (str(path), ""))
            window.export_module("web", kind)
            assert path.stat().st_size > 0
            assert "SECRET_COOKIE" not in path.read_text()
        assert session.verify_audit()
    finally:
        window.close()
