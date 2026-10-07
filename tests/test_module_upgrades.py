import csv
import json
from datetime import datetime, timedelta, timezone

import pytest
from PySide6.QtWidgets import QApplication, QPushButton

from cyberintel.config import Config
from cyberintel.diagnostics import readiness
from cyberintel.models import AccessDenied, Result, ValidationError
from cyberintel.reporting import export_result
from cyberintel.ui import MainWindow


def test_readiness_reports_missing_tools_without_exposing_keys(monkeypatch):
    monkeypatch.setattr("cyberintel.diagnostics.shutil.which", lambda name: "/usr/bin/nmap" if name == "nmap" else None)
    keys = {"hibp": "private-secret", "twilio_account_sid": "sid-only"}
    rows = readiness(keys)
    by_name = {row["component"]: row for row in rows}
    assert by_name["nmap"]["status"] == "available"
    assert by_name["tshark"]["status"] == "missing"
    assert by_name["HIBP exposure"]["status"] == "configured"
    assert by_name["Twilio"]["status"] == "not configured"
    assert "private-secret" not in json.dumps(rows)
    assert "sid-only" not in json.dumps(rows)


def test_result_exports_keep_provenance_and_protect_formulas(session, tmp_path):
    result = Result("fixture", "fixture://records", "target", {"summary": "full data"}, status="synthetic")
    path = tmp_path / "result.csv"
    export_result(session, "test", result, path, "csv", [{"value": "=SUM(1,2)", "nested": [1, 2]}])
    with path.open() as file:
        row = next(csv.DictReader(file))
    assert row["value"] == "'=SUM(1,2)"
    assert json.loads(row["nested"]) == [1, 2]
    assert row["_collected_at"] == result.collected_at
    assert row["_status"] == "synthetic" and row["_source"] == "fixture"
    path = tmp_path / "result.json"
    export_result(session, "test", result, path)
    exported = json.loads(path.read_text())
    assert exported == {"module": "test", "result": result.to_dict()}
    assert session.verify_audit()


def test_export_empty_unavailable_result_retains_error(session, tmp_path):
    result = Result("fixture", "fixture", "target", None, status="unavailable", error="No access", freshness="unknown")
    path = tmp_path / "unavailable.csv"
    export_result(session, "test", result, path, "csv", [])
    with path.open() as file:
        rows = list(csv.DictReader(file))
    assert len(rows) == 1 and rows[0]["_error"] == "No access"
    assert rows[0]["_status"] == "unavailable"


def test_export_validation_atomicity_and_permissions(session, tmp_path):
    result = Result("fixture", "fixture", "target", {"number": float("nan")})
    path = tmp_path / "existing.json"
    path.write_text("preserved")
    with pytest.raises(ValueError):
        export_result(session, "test", result, path)
    assert path.read_text() == "preserved"
    assert not list(tmp_path.glob(".cyberintel-export-*"))
    with pytest.raises(ValidationError, match="overwrite"):
        export_result(session, "test", result, session.store.path)
    with pytest.raises(ValidationError, match="conflict"):
        export_result(session, "test", result, path, "csv", [{"_source": "forged"}])
    with pytest.raises(ValidationError):
        export_result(session, "test", result, path, "xlsx")
    with session.store.connection() as db:
        db.execute("DELETE FROM users WHERE name=?", (session.actor,))
    with pytest.raises(AccessDenied):
        export_result(session, "test", result, path)


@pytest.mark.parametrize("key", ["osint", "breach", "threat", "cdr", "network", "geo", "phone", "subdomains", "nmap", "wifi", "web"])
def test_every_module_exports_filtered_table_and_full_result(session, tmp_path, monkeypatch, key):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(session.store.home), session)
    data = {"records": [{"value": "keep"}, {"value": "discard"}], "hourly_calls_utc": {},
            "subdomain_count": 2, "device_count": 2, "mac_available_count": 0, "hosts": []}
    if key == "nmap":
        data["records"] = [{"value": "keep", "state": "open"}, {"value": "discard", "state": "closed"}]
    result = Result("fixture", "fixture", "target", data, status="synthetic")
    monkeypatch.setattr(window, "start_job", lambda label, task, done: done(task()))
    try:
        window.show_result(key, result)
        getattr(window, key + "_controls")["table"].filter.setText("keep")
        for kind in ("csv", "json"):
            path = tmp_path / f"{key}.{kind}"
            monkeypatch.setattr("cyberintel.ui.QFileDialog.getSaveFileName", lambda *a, **k: (str(path), ""))
            window.export_module(key, kind)
            if kind == "csv":
                with path.open() as file:
                    rows = list(csv.DictReader(file))
                assert len(rows) == 1 and rows[0]["value"] == "keep"
            else:
                assert json.loads(path.read_text())["result"]["data"]["records"] == data["records"]
        exports = [button.text() for button in window.pages.widget(window.PAGE_NAMES.index({
            "osint": "Live OSINT", "breach": "Breach intelligence", "threat": "Threat intelligence",
            "cdr": "CDR analysis", "network": "Network forensics", "geo": "Geospatial",
            "phone": "Phone region estimate", "subdomains": "Subdomain discovery",
            "nmap": "Nmap IP scan", "wifi": "Wi-Fi / LAN devices", "web": "Web application assessment"}[key])).findChildren(QPushButton)]
        assert "Export full JSON" in exports and "Export filtered CSV" in exports
    finally:
        window.close()


def test_settings_readiness_and_device_handoff(session, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(session.store.home), session)
    monkeypatch.setattr(window, "start_job", lambda label, task, done: done(task()))
    try:
        window.check_readiness()
        assert window.readiness_table.model.rows
        data = {"device_count": 1, "mac_available_count": 0, "records": [{"ip": "192.168.1.3", "mac": "Unavailable"}]}
        window.show_result("wifi", Result("fixture", "fixture", "192.168.1.0/24", data, status="synthetic"))
        window.wifi_controls["table"].view.selectRow(0)
        window.nmap_vulnerabilities.setChecked(True)
        window.nmap_authorized.setChecked(True)
        window.inspect_wifi_device()
        assert window.navigation.currentRow() == 12
        assert window.nmap_targets.text() == "192.168.1.3"
        assert not window.nmap_authorized.isChecked()
        assert not window.nmap_vulnerabilities.isChecked()
    finally:
        window.close()


@pytest.mark.parametrize("age,original_freshness", [(7200, "fresh"), (-7200, "fresh"), (0, "stale")])
def test_restored_cached_findings_do_not_claim_freshness(session, age, original_freshness):
    app = QApplication.instance() or QApplication([])
    case = session.create_case("Freshness review")
    result = Result("fixture", "fixture", "target", {"value": "historical"}, status="cached",
                    collected_at=(datetime.now(timezone.utc) - timedelta(seconds=age)).isoformat(),
                    freshness=original_freshness)
    session.save_finding(case, "osint", result)
    window = MainWindow(Config(session.store.home), session)
    try:
        window.reload_cases(case)
        window.findings_table.view.selectRow(0)
        window.restore_finding()
        assert window.last_results["osint"].freshness == "stale"
        stored = json.loads(session.rows("findings", case)[0]["result"])
        assert stored["freshness"] == original_freshness
    finally:
        window.close()


def test_workspace_log_failure_is_actionable(tmp_path, monkeypatch, capsys):
    from cyberintel import app as desktop
    def fail(*args, **kwargs):
        raise PermissionError("Log path not writable")
    monkeypatch.setattr(desktop, "RotatingFileHandler", fail)
    monkeypatch.setattr("sys.argv", ["cyberintel", "--data-dir", str(tmp_path)])
    assert desktop.main() == 1
    assert "Unable to open the workspace log" in capsys.readouterr().err
