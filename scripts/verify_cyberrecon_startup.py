#!/usr/bin/env python3
"""Check desktop startup/event-loop shutdown with an isolated empty workspace."""
import argparse
import os
import sys
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', action='store_true', help='Import the installed /usr/share/cyberrecon payload')
    args = parser.parse_args()
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    sys.path.insert(0, '/usr/share/cyberrecon' if args.package else str(Path(__file__).resolve().parent.parent))
    from PySide6.QtCore import QTimer, QThreadPool
    from PySide6.QtWidgets import QApplication
    from cyberrecon.gui import Window
    from cyberrecon.storage import Repository
    with tempfile.TemporaryDirectory(prefix='cyberrecon-startup-') as temporary:
        app = QApplication.instance() or QApplication([])
        repo = Repository(temporary)
        repo.create_project('Startup fixture', ['127.0.0.1'], authority='Own local synthetic fixture')
        window = Window(repo)
        window.show()
        assert window.projects.count() == 2
        assert all(name in window.views for name in ('scope', 'assets', 'dns', 'ports', 'services', 'technologies', 'apis', 'errors', 'doctor'))
        QTimer.singleShot(200, app.quit)
        assert app.exec() == 0
        window.close()
        QThreadPool.globalInstance().waitForDone(45000)
        app.processEvents()
        print('GUI startup and event-loop shutdown: PASS (offscreen)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
