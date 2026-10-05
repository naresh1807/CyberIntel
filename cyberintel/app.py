import argparse
import logging
import os
import sys
import sqlite3
from logging.handlers import RotatingFileHandler

from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from .config import Config
from .storage import Store
from .ui import LoginDialog, MainWindow, STYLE


def main():
    parser = argparse.ArgumentParser(description="CyberIntel Suite desktop")
    parser.add_argument("--data-dir", help="Private workspace directory (default ~/.local/share/cyberintel)")
    args = parser.parse_args()
    if os.name == "posix":
        os.umask(0o077)
    try:
        config = Config.load(args.data_dir)
    except (ValueError, OSError) as exc:
        print(f"CyberIntel Suite could not start: {exc}", file=sys.stderr)
        return 1
    handler = RotatingFileHandler(config.home / "application.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger = logging.getLogger("cyberintel")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    os.chmod(config.home / "application.log", 0o600)
    app = QApplication(sys.argv[:1])
    app.setApplicationName("CyberIntel Suite")
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    try:
        store = Store(config.home)
    except (sqlite3.Error, ValueError, OSError) as exc:
        logger.error("Workspace initialization failed (%s)", type(exc).__name__)
        QMessageBox.critical(None, "CyberIntel Suite could not start", f"Unable to open this workspace: {exc}")
        return 1
    login = LoginDialog(store)
    if login.exec() != QDialog.Accepted:
        return
    window = MainWindow(config, login.session)
    window.show()
    logger.info("Desktop started")
    sys.exit(app.exec())
