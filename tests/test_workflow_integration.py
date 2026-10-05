"""Exercise actual desktop action handlers with controlled dialogs and provider fixtures."""
import json
import time
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication, QCheckBox, QDialog, QLineEdit

from cyberintel.analysis import analyze_cdr
from cyberintel.config import Config
from cyberintel.models import Result, utcnow
from cyberintel.ui import LoginDialog, MainWindow
from cyberintel.storage import Store


def wait_job(app, window):
    deadline = time.monotonic() + 8
    while window.busy and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.01)
    assert not window.busy


def test_login_bootstrap_and_existing_user_dialog(tmp_path):
    app = QApplication.instance() or QApplication([])
    store = Store(tmp_path)
    for _ in range(2):
        login = LoginDialog(store)
        login.name.setText("test-admin")
        login.password.setText("test-password-long")
        login.submit()
        assert login.result() == QDialog.Accepted
        assert login.session.role == "admin"
        assert not login.password.text()


def test_desktop_case_import_analysis_visuals_reports(session, examples, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    errors, urls = [], []
    monkeypatch.setattr(window, "error", errors.append)
    monkeypatch.setattr("cyberintel.ui.QInputDialog.getText", lambda *a, **k: ("Workflow test case", True))
    monkeypatch.setattr("cyberintel.ui.QInputDialog.getMultiLineText", lambda *a, **k: ("Synthetic workflow only", True))
    window.create_case()
    case = window.active_case()
    assert case
    def accept_provenance(dialog):
        fields = dialog.findChildren(QLineEdit)
        fields[0].setText("Synthetic workflow fixture")
        for checkbox in dialog.findChildren(QCheckBox):
            checkbox.setChecked(True)
        return QDialog.Accepted
    monkeypatch.setattr(QDialog, "exec", accept_provenance)
    monkeypatch.setattr("cyberintel.ui.QDesktopServices.openUrl", lambda url: urls.append(url.toLocalFile()) or True)
    for name, module in [("synthetic_cdr.csv", "cdr"), ("synthetic_gps.csv", "geo")]:
        original = (examples / name).read_bytes()
        monkeypatch.setattr("cyberintel.ui.QFileDialog.getOpenFileName", lambda *a, **k: (str(examples / name), ""))
        window.import_evidence()
        wait_job(app, window)
        controls = getattr(window, module + "_controls")
        index = next(i for i in range(controls["selector"].count()) if controls["selector"].itemData(i)["name"] == name)
        controls["selector"].setCurrentIndex(index)
        window.run_analysis(module)
        wait_job(app, window)
        assert window.last_results[module].status == "synthetic"
        assert window.last_results[module].reference.startswith("evidence:")
        window.open_visual(module)
        wait_job(app, window)
        assert Path(urls[-1]).is_file()
        assert (examples / name).read_bytes() == original
    for kind in ["csv", "pdf"]:
        destination = tmp_path / ("workflow-report." + kind)
        monkeypatch.setattr("cyberintel.ui.QFileDialog.getSaveFileName", lambda *a, **k: (str(destination), ""))
        window.export_report(kind)
        wait_job(app, window)
        assert destination.stat().st_size > 100
    assert not errors
    assert len(session.rows("evidence", case)) == 2
    assert len(session.rows("findings", case)) == 2
    assert session.verify_audit()
    window.close()


def test_desktop_vault_and_add_user(session, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    errors = []
    monkeypatch.setattr(window, "error", errors.append)
    monkeypatch.setattr("cyberintel.ui.QInputDialog.getText", lambda *a, **k: ("vault-passphrase-long", True))
    window.unlock_vault()
    window.key_fields["otx"].setText("synthetic-api-key")
    window.save_keys()
    assert window.collector.keys["otx"] == "synthetic-api-key"
    window.lock_vault()
    assert window.collector.keys == {} and not window.key_fields["otx"].text()
    window.unlock_vault()
    assert window.key_fields["otx"].text() == "synthetic-api-key"
    values = iter([("test-viewer", True), ("viewer-password-long", True)])
    monkeypatch.setattr("cyberintel.ui.QInputDialog.getText", lambda *a, **k: next(values))
    monkeypatch.setattr("cyberintel.ui.QInputDialog.getItem", lambda *a, **k: ("viewer", True))
    window.add_user()
    assert session.store.login("test-viewer", "viewer-password-long").role == "viewer"
    assert not errors
    window.close()


def test_breach_monitor_baseline_new_names_counts_and_failures(session, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    case = session.create_case("Watch workflow")
    window.reload_cases(case)
    session.add_watch(case, "domain", "example.com")
    replies = iter([
        Result("HIBP", "source", "example.com", {"breach_counts": {"Adobe": 1}}),
        Result("HIBP", "source", "example.com", {"breach_counts": {"Adobe": 2, "NewBreach": 1}}),
        Result("HIBP", "source", "example.com", None, status="unavailable", error="No key")
    ])
    monkeypatch.setattr(window.collector, "collect", lambda *a, **k: next(replies))
    alerts = []
    monkeypatch.setattr("cyberintel.ui.QMessageBox.information", lambda *args: alerts.append(args[-1]))
    window.poll_watchlist()
    wait_job(app, window)
    assert not alerts
    window.poll_watchlist()
    wait_job(app, window)
    assert "NewBreach" in alerts[0] and "1 → 2" in alerts[0]
    previous_check = session.rows("watchlist", case)[0]["last_checked"]
    window.poll_watchlist()
    wait_job(app, window)
    assert session.rows("watchlist", case)[0]["last_checked"] == previous_check
    assert "1 unavailable" in window.notice.text()
    assert len(session.rows("findings", case)) == 3
    window.close()


def test_feed_job_and_restore_saved_analysis(session, examples, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    case = session.create_case("Feed workflow")
    window.reload_cases(case)
    reply = Result("URLhaus fixture", "fixture", "recent", {"indicators": [{"host": "example.com"}]}, status="synthetic")
    monkeypatch.setattr(window.collector, "collect", lambda *a, **k: reply)
    window.poll_feed()
    wait_job(app, window)
    assert session.rows("findings", case)[0]["module"] == "threat"
    cdr = analyze_cdr(examples / "synthetic_cdr.csv", "synthetic")
    session.save_finding(case, "cdr", cdr)
    window.refresh()
    table = window.findings_table
    index = next(i for i in range(table.proxy.rowCount()) if table.proxy.index(i, 2).data() == "cdr")
    table.view.selectRow(index)
    window.restore_finding()
    assert window.navigation.currentRow() == 4
    assert window.last_results["cdr"].data["total_calls"] == 6
    window.close()
