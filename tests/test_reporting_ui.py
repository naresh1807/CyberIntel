import csv
import json

from PySide6.QtWidgets import QApplication

from cyberintel.analysis import analyze_cdr
from cyberintel.config import Config
from cyberintel.reporting import csv_safe, export_csv, export_pdf
from cyberintel.ui import MainWindow, STYLE


def test_case_report_roundtrip(session, examples, tmp_path):
    case_id = session.create_case("Synthetic case", "Authorized test report")
    session.add_evidence(case_id, examples / "synthetic_cdr.csv", "Synthetic test fixture", "2026-10-01T00:00:00Z", "synthetic")
    session.save_finding(case_id, "cdr", analyze_cdr(examples / "synthetic_cdr.csv", "synthetic"))
    pdf = tmp_path / "report.pdf"
    csv_file = tmp_path / "report.csv"
    export_pdf(session, case_id, pdf)
    export_csv(session, case_id, csv_file)
    assert pdf.read_bytes().startswith(b"%PDF")
    with csv_file.open(encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    assert {r["record_type"] for r in rows} == {"case", "evidence", "cdr", "integrity"}
    assert "synthetic" in csv_file.read_text()
    assert csv_safe("=CMD()") == "'=CMD()"


def test_gui_navigation_and_persistence(session, examples, tmp_path):
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(STYLE)
    window = MainWindow(Config(tmp_path), session)
    assert window.pages.count() == 13
    case_id = session.create_case("UI synthetic investigation")
    session.add_evidence(case_id, examples / "synthetic_cdr.csv", "Fixture", "2026-10-01T00:00:00Z", "synthetic")
    window.reload_cases(case_id)
    assert window.active_case() == case_id
    assert window.cdr_controls["selector"].count() == 1
    for index in range(12):
        window.navigation.setCurrentRow(index)
        assert window.pages.currentIndex() == index
    result = analyze_cdr(examples / "synthetic_cdr.csv", "synthetic")
    window.show_result("cdr", result)
    assert window.cdr_controls["table"].model.rowCount() == 5
    window.show()
    app.processEvents()
    window.grab().save(str(tmp_path / "dashboard.png"))
    window.close()


def test_background_worker_returns_on_gui_thread(session, tmp_path):
    import time
    from PySide6.QtCore import QThread
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    received = []
    window.start_job("Test worker", lambda: 42, lambda value: received.append((value, QThread.currentThread() == app.thread())))
    deadline = time.monotonic() + 5
    while window.busy and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.01)
    assert received == [(42, True)]
    assert not window.busy
    window.close()
