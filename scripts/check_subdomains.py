"""Live verification on example.com only; saves public results and a desktop preview."""
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import QApplication
from cyberintel.config import Config
from cyberintel.connectors import Collector
from cyberintel.storage import Store
from cyberintel.subdomains import discover_subdomains, verify_subdomains, export_subdomains
from cyberintel.ui import MainWindow, STYLE


def main():
    artifacts = Path(__file__).resolve().parents[1] / "artifacts"
    artifacts.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        config = Config(Path(directory), timeout_seconds=10)
        store = Store(config.home)
        result = discover_subdomains(Collector(config, store), "example.com", force=True)
        if result.data and result.data["subdomains"]:
            result = verify_subdomains(result, result.data["subdomains"][:3])
        (artifacts / "live-subdomain-check.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(json.dumps({"status": result.status, "error": result.error, "subdomain_count": result.data.get("subdomain_count") if result.data else None}), flush=True)
        if result.data is None:
            return
        export_subdomains(result, artifacts / "example-com-subdomains.csv")
        password = secrets.token_urlsafe(24)
        store.bootstrap("qa-admin", password)
        session = store.login("qa-admin", password)
        app = QApplication.instance() or QApplication([])
        if not QFontDatabase.families() and os.name == "nt":
            for name in ("segoeui.ttf", "segoeuib.ttf", "arial.ttf"):
                QFontDatabase.addApplicationFont("C:/Windows/Fonts/" + name)
        app.setStyle("Fusion")
        app.setStyleSheet(STYLE)
        window = MainWindow(config, session)
        window.subdomain_target.setText("example.com")
        window.show_result("subdomains", result)
        window.navigation.setCurrentRow(11)
        window.show()
        app.processEvents()
        window.grab().save(str(artifacts / "subdomain-discovery.png"))
        window.close()


if __name__ == "__main__":
    main()
