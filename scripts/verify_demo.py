"""Reproducible visual QA, using only explicitly labeled synthetic evidence."""
import os
import secrets
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtCore import QSize
from PySide6.QtGui import QFontDatabase, QImage, QPainter
from PySide6.QtPdf import QPdfDocument
from PySide6.QtWidgets import QApplication

from cyberintel.analysis import analyze_cdr, analyze_geo, location_map, relationship_graph
from cyberintel.config import Config
from cyberintel.reporting import export_csv, export_pdf
from cyberintel.phone import estimate_phone_region
from cyberintel.models import Result, utcnow
from cyberintel.storage import Store
from cyberintel.ui import MainWindow, STYLE


def main():
    root = Path(__file__).resolve().parents[1]
    artifacts = root / "artifacts"
    artifacts.mkdir(exist_ok=True)
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        store = Store(home)
        password = secrets.token_urlsafe(24)
        store.bootstrap("qa-admin", password)
        session = store.login("qa-admin", password)
        case_id = session.create_case("Synthetic communication review", "QA fixture only. No real subscriber records or location history.")
        for name in ("synthetic_cdr.csv", "synthetic_gps.csv"):
            session.add_evidence(case_id, root / "examples" / name, "Synthetic QA fixture", "2026-10-01T00:00:00Z", "synthetic")
        cdr = analyze_cdr(root / "examples" / "synthetic_cdr.csv", "synthetic")
        geo = analyze_geo(root / "examples" / "synthetic_gps.csv", data_kind="synthetic")
        for module, result in (("cdr", cdr), ("geo", geo)):
            session.save_finding(case_id, module, result)
        app = QApplication.instance() or QApplication([])
        if not QFontDatabase.families() and os.name == "nt":
            for name in ("segoeui.ttf", "segoeuib.ttf", "arial.ttf"):
                QFontDatabase.addApplicationFont("C:/Windows/Fonts/" + name)
        app.setStyle("Fusion")
        app.setStyleSheet(STYLE)
        window = MainWindow(Config(home), session)
        window.reload_cases(case_id)
        window.show()
        app.processEvents()
        window.grab().save(str(artifacts / "dashboard.png"))
        window.show_result("cdr", cdr)
        window.navigation.setCurrentRow(4)
        app.processEvents()
        window.grab().save(str(artifacts / "cdr-analysis.png"))
        # Library example: allocation metadata, not subscriber tracking.
        import phonenumbers
        number = phonenumbers.example_number_for_type("IN", phonenumbers.PhoneNumberType.MOBILE)
        phone = estimate_phone_region(phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164))
        window.show_result("phone", phone)
        window.navigation.setCurrentRow(7)
        app.processEvents()
        window.grab().save(str(artifacts / "phone-region-estimate.png"))
        fixture_time = utcnow()
        fixture_names = ["api.example.com", "mail.example.com", "www.example.com"]
        fixture = Result("Synthetic CT/DNS fixture", "fixture://synthetic-certificate-names", "example.com",
                         {"subdomains": fixture_names, "subdomain_count": len(fixture_names), "wildcard_patterns": ["*.dev.example.com"],
                          "records": [{"subdomain": name, "discovery_source": "Synthetic CT/DNS fixture", "source_reference": "fixture://synthetic-certificate-names",
                                       "observed_at": fixture_time, "dns_status": "resolved", "ipv4": ["192.0.2.10"], "ipv6": [] if name.startswith("mail") else ["2001:db8::10"],
                                       "ipv4_status": "resolved", "ipv6_status": "no record" if name.startswith("mail") else "resolved",
                                       "dns_checked_at": fixture_time, "dns_error": ""} for name in fixture_names],
                          "note": "Synthetic visual QA only. Reserved documentation addresses; no live discoveries or DNS verification claimed."}, status="synthetic", collected_at=fixture_time)
        window.subdomain_target.setText("example.com")
        window.show_result("subdomains", fixture)
        window.navigation.setCurrentRow(11)
        app.processEvents()
        window.grab().save(str(artifacts / "subdomain-discovery-synthetic.png"))
        export_pdf(session, case_id, artifacts / "synthetic-case-report.pdf")
        export_csv(session, case_id, artifacts / "synthetic-case-report.csv")
        relationship_graph(cdr, artifacts / "synthetic-relationships.html")
        location_map(geo, artifacts / "synthetic-map.html")
        document = QPdfDocument(app)
        document.load(str(artifacts / "synthetic-case-report.pdf"))
        assert document.pageCount() > 0
        for index in range(document.pageCount()):
            image = QImage(794, 1123, QImage.Format_RGB32)
            image.fill(0xffffffff)
            painter = QPainter(image)
            painter.drawImage(0, 0, document.render(index, QSize(794, 1123)))
            painter.end()
            image.save(str(artifacts / f"report-page-{index + 1}.png"))
        print(f"Visual QA artifacts generated. PDF pages: {document.pageCount()}; audit valid: {session.verify_audit()}")
        document.close()
        window.close()


if __name__ == "__main__":
    main()
