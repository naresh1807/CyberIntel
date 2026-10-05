"""Regressions identified during the full workflow/function review."""
import json
import time
from pathlib import Path

import httpx
import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from cyberintel.analysis import analyze_cdr, analyze_geo, read_table, location_map, relationship_graph
from cyberintel.config import Config
from cyberintel.connectors import Collector
from cyberintel.models import AccessDenied, Result, ValidationError
from cyberintel.reporting import export_csv, export_pdf
from cyberintel.security import Vault
from cyberintel.storage import Store
from cyberintel.ui import DataTable, MainWindow


def pump(app, window):
    deadline = time.monotonic() + 8
    while window.busy and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.01)
    assert not window.busy


@pytest.mark.parametrize("raw", [b"", b"12345", b"0" * 16])
def test_empty_or_truncated_vault_rejected(tmp_path, raw):
    path = tmp_path / "vault.enc"
    path.write_bytes(raw)
    with pytest.raises(ValidationError, match="Damaged"):
        Vault(path, "long-passphrase-123")
    assert path.read_bytes() == raw


def test_vault_save_failure_preserves_memory_and_disk(tmp_path, monkeypatch):
    path = tmp_path / "vault.enc"
    vault = Vault(path, "long-passphrase-123")
    vault.save({"otx": "old-secret"})
    before = path.read_bytes()
    def fail(*args):
        raise OSError("simulated disk failure")
    monkeypatch.setattr(Path, "replace", fail)
    with pytest.raises(OSError):
        vault.save({"otx": "new-secret"})
    assert vault.get("otx") == "old-secret" and path.read_bytes() == before
    assert not list(tmp_path.glob(".cyberintel-vault-*"))


def test_lockout_expiry_resets_failure_budget(session):
    with session.store.connection() as db:
        db.execute("UPDATE users SET failures=5,locked_until='2020-01-01T00:00:00+00:00' WHERE name='admin'")
    with pytest.raises(AccessDenied):
        session.store.login("admin", "bad-password")
    with session.store.connection() as db:
        row = db.execute("SELECT failures,locked_until FROM users WHERE name='admin'").fetchone()
        assert row[0] == 1 and row[1] is None
    assert session.store.login("admin", "test-password-long")


def test_corrupt_cache_is_discarded(session):
    with session.store.connection() as db:
        db.execute("INSERT INTO cache VALUES('broken','not json')")
    assert session.store.cache_get("broken") is None


def test_newer_schema_not_downgraded(session):
    with session.store.connection() as db:
        db.execute("PRAGMA user_version=2")
    with pytest.raises(ValidationError, match="newer"):
        Store(session.store.home)
    with session.store.connection() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2


@pytest.mark.parametrize("data", [[], {"endpoints": []}, {"endpoints": {"ct": "http://crt.sh"}}, {"cache_seconds": "bad"}, {"endpoints": {"ct": "https://user:key@crt.sh"}}])
def test_invalid_configuration_is_actionable(tmp_path, data):
    (tmp_path / "config.json").write_text(json.dumps(data))
    with pytest.raises(ValidationError, match="Invalid configuration"):
        Config.load(str(tmp_path))


def test_bom_configuration_supported(tmp_path):
    (tmp_path / "config.json").write_text('{"cache_seconds":120}', encoding="utf-8-sig")
    assert Config.load(str(tmp_path)).cache_seconds == 120


@pytest.mark.parametrize("source,payload", [
    ("hibp_domain", []), ("hibp_domain", {"alias": "Adobe"}), ("hibp_catalog", ["bad"]),
    ("otx", []), ("otx", {"pulse_info": None}), ("otx", {"pulse_info": {"count": "2"}}),
    ("urlhaus", []), ("urlhaus", {"query_status": "ok", "urls": None}),
])
def test_malformed_provider_response_not_empty_success(session, source, payload):
    client = Collector(Config(session.store.home), session.store, {"hibp": "test", "otx": "test", "urlhaus": "test"},
                       transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload)), sleeper=lambda _: None)
    result = client.collect(source, "example.com")
    assert result.status == "unavailable" and "Malformed" in result.error


def test_hibp_catalog_404_is_source_failure_domain_404_is_empty(session):
    client = Collector(Config(session.store.home), session.store, {"hibp": "test"},
                       transport=httpx.MockTransport(lambda _: httpx.Response(404)), sleeper=lambda _: None)
    assert client.collect("hibp_catalog").status == "unavailable"
    result = client.collect("hibp_domain", "example.com")
    assert result.status == "live" and result.data["affected_alias_count"] == 0


def test_long_cooldown_prevents_immediate_repeat_request(session):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(429, headers={"Retry-After": "120"})
    client = Collector(Config(session.store.home), session.store, transport=httpx.MockTransport(handler), sleeper=lambda _: None)
    assert client.collect("hibp_catalog").status == "unavailable"
    assert client.collect("hibp_catalog", force=True).status == "unavailable"
    assert len(requests) == 1


@pytest.mark.parametrize("retry", ["NaN", "inf", "-1"])
def test_invalid_retry_after_bounded(session, retry):
    delays = []
    client = Collector(Config(session.store.home), session.store,
                       transport=httpx.MockTransport(lambda _: httpx.Response(429, headers={"Retry-After": retry})), sleeper=delays.append)
    assert client.collect("hibp_catalog").status == "unavailable"
    assert all(0 <= delay <= 30 for delay in delays)


def test_duplicate_watch_and_over_limit_rejected(session):
    case = session.create_case("Watch test")
    session.add_watch(case, "domain", "EXAMPLE.COM")
    with pytest.raises(ValidationError, match="already exists"):
        session.add_watch(case, "domain", "example.com")
    for i in range(24):
        session.add_watch(case, "email", f"test{i}@example.com")
    with pytest.raises(ValidationError, match="25"):
        session.add_watch(case, "email", "extra@example.com")
    assert len(session.rows("watchlist", case)) == 25


@pytest.mark.parametrize("kind", ["csv", "xlsx"])
def test_duplicate_columns_rejected_before_pandas_mangles(tmp_path, kind):
    path = tmp_path / ("bad." + kind)
    if kind == "csv":
        path.write_text("caller,caller\n1234,5678\n")
    else:
        import openpyxl
        workbook = openpyxl.Workbook()
        workbook.active.append(["caller", "caller"])
        workbook.active.append(["1234", "5678"])
        workbook.save(path)
    with pytest.raises(ValidationError, match="Duplicate"):
        read_table(path)


def test_large_graph_without_scipy(tmp_path):
    result = Result("fixture", "fixture", "fixture", {"provenance_kind": "synthetic", "relationships":
                    [{"caller": str(i), "callee": str(i + 1), "calls": 1} for i in range(501)]}, status="synthetic")
    relationship_graph(result, tmp_path / "large.html")
    assert (tmp_path / "large.html").stat().st_size > 1000


def test_map_popup_cannot_interpolate_javascript(tmp_path):
    result = Result("fixture", "fixture", "fixture", {"records": [
        {"latitude": 28, "longitude": 77, "source": "${alert(1)}`<script>x</script>", "record_kind": "synthetic"}]})
    location_map(result, tmp_path / "map.html")
    body = (tmp_path / "map.html").read_text(encoding="utf-8")
    assert "${alert(1)}" not in body
    assert "&#36;{alert(1)}&#96;" in body


@pytest.mark.parametrize("exporter", [export_csv, export_pdf])
def test_export_cannot_overwrite_evidence_or_database(session, examples, exporter):
    case = session.create_case("Export guard")
    session.add_evidence(case, examples / "synthetic_cdr.csv", "Fixture", "2026-10-01T00:00:00Z", "synthetic")
    path = Path(session.rows("evidence", case)[0]["path"])
    before = path.read_bytes()
    for destination in [path, session.store.path, session.store.home / "vault.enc"]:
        with pytest.raises(ValidationError, match="overwrite"):
            exporter(session, case, destination)
    assert path.read_bytes() == before
    assert session.verify_evidence(case)[0]["valid"]


def test_failed_pdf_preserves_existing_report(session, tmp_path, monkeypatch):
    case = session.create_case("Atomic report")
    path = tmp_path / "report.pdf"
    path.write_bytes(b"previous report")
    def fail(*args, **kwargs):
        raise RuntimeError("simulated PDF failure")
    monkeypatch.setattr("cyberintel.reporting.SimpleDocTemplate.build", fail)
    with pytest.raises(RuntimeError):
        export_pdf(session, case, path)
    assert path.read_bytes() == b"previous report"
    assert not list(tmp_path.glob(".cyberintel-export-*"))


def test_table_numeric_sort():
    app = QApplication.instance() or QApplication([])
    table = DataTable()
    table.set_rows([{"count": 10}, {"count": 2}, {"count": 1}])
    table.proxy.sort(0, Qt.AscendingOrder)
    assert [table.proxy.index(i, 0).data() for i in range(3)] == ["1", "2", "10"]


def test_case_switch_clears_results_and_running_job_locks_selector(session, tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    first = session.create_case("First")
    second = session.create_case("Second")
    window.reload_cases(first)
    window.show_result("phone", Result("fixture", "fixture", "number", {"country": "test"}))
    window.case_selector.setCurrentIndex(window.case_selector.findData(second))
    assert window.last_results == {}
    assert window.phone_controls["table"].model.rowCount() == 0
    window.start_job("Wait", lambda: time.sleep(.05), lambda _: None)
    assert not window.case_selector.isEnabled()
    pump(app, window)
    assert window.case_selector.isEnabled()
    window.close()


def test_failed_job_resets_busy_state(session, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    errors = []
    monkeypatch.setattr(window, "error", errors.append)
    def fail():
        raise ValidationError("controlled failure")
    window.start_job("Fail", fail, lambda _: pytest.fail("must not invoke success"))
    pump(app, window)
    assert errors == ["controlled failure"] and not window.jobs
    assert window.case_selector.isEnabled()
    window.close()


def test_role_revocation_updates_ui_and_backend(session, tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    with session.store.connection() as db:
        db.execute("UPDATE users SET role='viewer' WHERE name='admin'")
    window.refresh()
    assert session.role == "viewer"
    assert window.user_table.model.rowCount() == 0
    with pytest.raises(AccessDenied):
        session.create_case("Denied after revocation")
    window.close()


def test_oversized_table_rejected_before_read(tmp_path):
    path = tmp_path / "large.csv"
    with path.open("wb") as file:
        file.truncate(50 * 1024 * 1024 + 1)
    with pytest.raises(ValidationError, match="50 MiB"):
        read_table(path)


def test_xlsx_macro_content_rejected(tmp_path):
    import zipfile
    path = tmp_path / "macros.xlsx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/vbaProject.bin", b"synthetic macro marker")
    with pytest.raises(ValidationError, match="Macro"):
        read_table(path)


def test_invalid_config_cli_has_nonzero_status_and_clear_error(tmp_path):
    import subprocess
    import sys
    (tmp_path / "config.json").write_text("broken json")
    result = subprocess.run([sys.executable, "-m", "cyberintel", "--data-dir", str(tmp_path)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "Invalid configuration" in result.stderr and "Traceback" not in result.stderr
