import json

import httpx
import pytest

from cyberrecon.cli import main
from cyberrecon.network import ScopedHTTP, clean_url
from cyberrecon.scanner import scan
from cyberrecon.scope import Scope
from cyberrecon.storage import Repository, compare_snapshots


@pytest.mark.parametrize("target,allowed", [("example.org", True), ("a.example.org", True),
    ("blocked.example.org", False), ("example.org.attacker.org", False), ("notexample.org", False),
    ("192.0.2.4", True), ("192.0.3.4", False)])
def test_scope(target, allowed):
    scope = Scope(("example.org", "*.example.org", "192.0.2.0/24"), ("blocked.example.org",))
    assert scope.allows(target) == allowed


def test_wildcard_does_not_authorize_apex():
    scope = Scope(("*.example.org",))
    assert not scope.allows("example.org")
    assert scope.allows("example.org", passive=True)


def test_url_rule_is_not_silently_broadened_to_whole_domain():
    with pytest.raises(ValueError, match="not scope rules"):
        Scope(("https://example.org/limited-path/",))


def test_passive_enumeration_rejects_ipv6_before_engine(monkeypatch):
    from cyberrecon.engines import passive_domains
    calls = []
    monkeypatch.setattr("cyberrecon.engines.run_process", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match="needs a domain"):
        passive_domains("subfinder", "2001:db8::1", Scope(("2001:db8::1",)))
    assert not calls


def test_url_redaction():
    assert clean_url("https://example.org/a?token=secret&token=second&q=x#frag") == "https://example.org/a?q=&token="
    with pytest.raises(ValueError):
        clean_url("https://user:pass@example.org/")


def test_scope_before_transport():
    calls = []
    client = ScopedHTTP(lambda: Scope(("example.org",)), transport=httpx.MockTransport(lambda req: calls.append(req)))
    with pytest.raises(ValueError, match="OUT OF SCOPE"):
        client.fetch("https://other.org")
    assert not calls


def test_redirect_rechecks_scope():
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://other.org/"})
    client = ScopedHTTP(lambda: Scope(("example.org",)), transport=httpx.MockTransport(handler), rate=10)
    with pytest.raises(ValueError, match="OUT OF SCOPE"):
        client.fetch("https://example.org/")
    assert len(calls) == 1


def test_excluded_public_address_blocks_domain_connection(monkeypatch):
    import socket
    monkeypatch.setattr("cyberrecon.network.socket.getaddrinfo", lambda *args, **kwargs:
                        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))])
    client = ScopedHTTP(lambda: Scope(("example.org",), ("8.8.8.8",)))
    with pytest.raises(ValueError, match="explicitly excluded"):
        client.fetch("https://example.org")


def test_workflow_storage_and_comparison(tmp_path):
    repo = Repository(tmp_path)
    project = repo.create_project("Lab", ["example.org"], authority="Test fixture")
    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html", "set-cookie": "session=secret"},
                              text='<a href="/api/users?token=secret">API</a><a href="https://excluded.org/">Outside</a>')
    first = scan(repo, project, "example.org", transport=httpx.MockTransport(handler))
    snapshot = repo.snapshot(first)
    assert snapshot["scan"]["status"] == "complete"
    assert snapshot["apis"][0]["url"] == "https://example.org/api/users?token="
    assert "secret" not in json.dumps(snapshot)
    assert not any("excluded.org" in row["key"] for row in snapshot["urls"])
    second = repo.start_scan(project, "example.org", {})
    repo.save(second, "assets", "new.example.org", {}, "fixture")
    repo.finish(second, [])
    changes = compare_snapshots(snapshot, repo.snapshot(second))
    assert {row["status"] for row in changes} == {"NEW", "REMOVED"}
    assert (tmp_path / "scans" / first / "apis.json").exists()
    with pytest.raises(ValueError):
        repo.evidence("../../escape", "raw.txt", b"test")


def test_out_of_scope_scan_creates_nothing(tmp_path):
    repo = Repository(tmp_path)
    project = repo.create_project("Lab", ["example.org"], authority="Test")
    with pytest.raises(ValueError):
        scan(repo, project, "other.org")
    assert repo.scans(project) == []


def test_cli_doctor(capsys):
    assert main(["--doctor"]) == 0
    assert "tools" in json.loads(capsys.readouterr().out)


def test_gui_browses_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from cyberrecon.gui import Window
    app = QApplication.instance() or QApplication([])
    repo = Repository(tmp_path)
    repo.create_project("Lab", ["example.org"], authority="Test")
    window = Window(repo)
    assert window.projects.count() == 1
    assert "example.org" in window.views["scope"].toPlainText()
    window.close()
    app.processEvents()
