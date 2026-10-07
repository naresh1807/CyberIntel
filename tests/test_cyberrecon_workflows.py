import json
import threading

import httpx
import pytest

from cyberrecon.intelligence import enrich_cves, normalized_cpe
from cyberrecon.scanner import scan
from cyberrecon.storage import Repository


def test_cve_candidates_are_not_confirmed(tmp_path):
    repo = Repository(tmp_path)
    project = repo.create_project("Lab", ["example.org"], authority="Fixture")
    identifier = repo.start_scan(project, "example.org", {})
    repo.save(identifier, "technologies", "nginx", {"cpe": ["cpe:/a:nginx:nginx:1.24.0"]}, "Nmap")
    def handler(request):
        assert request.url.host == "services.nvd.nist.gov"
        assert "example.org" not in str(request.url)
        return httpx.Response(200, json={"totalResults": 1, "vulnerabilities": [{"cve": {
            "id": "CVE-2026-12345", "descriptions": [{"lang": "en", "value": "Fixture advisory"}]}}]})
    assert enrich_cves(repo, identifier, transport=httpx.MockTransport(handler)) == []
    finding = repo.snapshot(identifier)["findings"][0]
    assert not finding["confirmed_vulnerability"]
    assert finding["confidence"] == "candidate-requires-validation"
    assert normalized_cpe("cpe:/a:nginx:nginx:*") is None


def test_javascript_redacted_findings_and_content_paths(tmp_path):
    repo = Repository(tmp_path)
    project = repo.create_project("Lab", ["example.org"], authority="Fixture")
    def handler(request):
        if request.url.path.endswith(".js"):
            return httpx.Response(200, headers={"content-type": "application/javascript"},
                                 text='const api_key="TOPSECRET123456789"; const url="/api/users?token=secret"; //# sourceMappingURL=app.js.map')
        return httpx.Response(200, headers={"content-type": "text/html"}, text='<script src="/app.js"></script>')
    result = repo.snapshot(scan(repo, project, "example.org", words=["app.js"], transport=httpx.MockTransport(handler)))
    assert result["javascript"][0]["potential_sensitive_assignments"] == 1
    assert "TOPSECRET" not in json.dumps(result)
    assert result["javascript"][0]["source_map_candidates"] == ["https://example.org/app.js.map"]
    assert any(row["classification"] == "configuration-review" for row in result["findings"])
    with pytest.raises(ValueError):
        scan(repo, project, "example.org", words=["../../etc/passwd"])


def test_cancelled_scan_status(tmp_path):
    repo = Repository(tmp_path)
    project = repo.create_project("Lab", ["example.org"], authority="Fixture")
    cancelled = threading.Event()
    cancelled.set()
    identifier = scan(repo, project, "example.org", cancel=cancelled)
    assert repo.snapshot(identifier)["scan"]["status"] == "cancelled"


def test_service_normalization(tmp_path, monkeypatch):
    repo = Repository(tmp_path)
    project = repo.create_project("Lab", ["192.0.2.4"], authority="Fixture")
    record = {"ip": "192.0.2.4", "port": 443, "protocol": "tcp", "state": "open", "service": "https",
              "product": "nginx", "version": "1.24.0", "cpe": []}
    monkeypatch.setattr("cyberrecon.engines.port_scan", lambda *args: ({"records": [record], "hosts": []}, b"fixture XML"))
    identifier = scan(repo, project, "192.0.2.4", ports="443", transport=httpx.MockTransport(lambda req: httpx.Response(200)))
    result = repo.snapshot(identifier)
    assert result["ports"][0]["port"] == 443
    assert result["services"][0]["version"] == "1.24.0"
    assert result["technologies"][0]["lifecycle"] == "UNKNOWN"
    assert any(row["from_node"] == "ip:192.0.2.4" and row["relation"] == "serves" for row in result["relationships"])


def test_table_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from cyberrecon.gui import ObservationTable
    app = QApplication.instance() or QApplication([])
    table = ObservationTable()
    table.setPlainText('[{"host":"example.org"},{"host":"other.org"}]')
    table.filter.setText("example")
    assert sum(not table.table.isRowHidden(index) for index in range(2)) == 1
    table.close()
    app.processEvents()
