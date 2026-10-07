#!/usr/bin/env python3
"""Exercise the real GUI on a desktop; isolated synthetic workspace, no reboot.

Requires a live X11/Wayland session. This does not qualify a fresh installed VM.
Screenshots capture only CyberRecon's window, never the surrounding desktop.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='artifacts/desktop-qualification')
    args = parser.parse_args()
    if os.geteuid() == 0 or not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
        parser.error('A non-root real desktop session is required.')
    os.environ.pop('QT_QPA_PLATFORM', None)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from PySide6.QtCore import QTimer
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QMessageBox
    from cyberrecon.cli import main as cli_main
    from cyberrecon.gui import Window, ObservationTable
    from cyberrecon.storage import Repository

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    home = output / 'workspace'
    repo = Repository(home)
    if repo.projects():
        parser.error('Use a new output directory; synthetic fixtures must not modify existing data.')
    project = repo.create_project('Synthetic desktop qualification', ['127.0.0.1'], authority='Own local verification server')
    scan = repo.start_scan(project, '127.0.0.1', {})
    for index in range(1100):
        repo.save(scan, 'assets', str(index), {'host': '127.0.0.1', 'synthetic_index': index}, 'Synthetic desktop fixture')
    repo.finish(scan, [])
    report = {'status': 'RUNNING', 'uid': os.geteuid(), 'os_release': Path('/etc/os-release').read_text(),
              'mode': 'Source GUI, actual desktop; installed VM/reboot NOT TESTED', 'checks': {}}
    errors = []
    app = QApplication([])
    report['qt_platform'] = app.platformName()
    if app.platformName() in ('offscreen', 'minimal'):
        parser.error('An actual desktop Qt backend is required.')
    previous_warning = QMessageBox.warning
    warnings = []
    QMessageBox.warning = lambda *a: warnings.append(str(a[-1]))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            try:
                self.wfile.write(b'<h1>Owned synthetic desktop lab</h1>')
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def probe():
        try:
            window = next(w for w in app.topLevelWidgets() if isinstance(w, Window))
            assert window.isVisible() and not window.windowIcon().isNull()
            assert app.styleSheet()
            report['checks']['rendering-theme-icon'] = 'PASS'
            for name, view in window.views.items():
                window.tabs.setCurrentWidget(view)
                QTest.qWait(15)
                assert view.isVisible(), name
            report['checks']['tab-navigation'] = list(window.views)
            report['sidebar'] = 'NOT IMPLEMENTED: current navigation is tabs'
            view = window.views['assets']
            assert isinstance(view, ObservationTable) and view.table.rowCount() == 1000
            view.table.verticalScrollBar().setValue(view.table.verticalScrollBar().maximum())
            view.filter.setText('synthetic_index_not_present')
            assert all(view.table.isRowHidden(i) for i in range(view.table.rowCount()))
            view.filter.clear()
            start = time.monotonic()
            window.show_scan()
            report['large_refresh_seconds'] = round(time.monotonic() - start, 3)
            report['large_refresh'] = 'MEASURED; synchronous population remains a limitation'
            report['checks']['table-scroll-filter-cap'] = 'PASS'
            window.tabs.setCurrentWidget(window.views['dashboard'])
            QTest.qWait(100)
            assert window.grab().save(str(output / 'dashboard.png'))
            window.tabs.setCurrentWidget(view)
            QTest.qWait(100)
            assert window.grab().save(str(output / 'assets.png'))
            window.includes.setText('127.0.0.1')
            window.excludes.setText('127.0.0.1')
            window.target.setText('http://127.0.0.1:' + str(server.server_port))
            window.start_scan()
            assert warnings and window.worker is None
            report['checks']['scope-error-displayed'] = 'PASS'
            window.excludes.clear()
            window.start_scan()
            assert window.worker is not None
            window.cancel_scan()
            deadline = time.monotonic() + 30
            while window.worker is not None and time.monotonic() < deadline:
                QTest.qWait(50)
            assert window.worker is None and window.start.isEnabled()
            current = repo.scans(project)[0]
            assert current['status'] == 'cancelled', current
            report['checks']['native-scan-cancellation'] = 'PASS'
            from cyberrecon.reporting import export_reports
            destination = export_reports(repo, scan, output / 'reports')
            assert Path(destination, 'graph.html').is_file()
            report['checks']['report-graph-generation'] = 'PASS; browser/menu handoff NOT TESTED'
            window.close()
            reopened = Repository(home)
            assert len(reopened.snapshot(scan)['assets']) == 1100
            with reopened.connection() as db:
                assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            report['checks']['close-reopen-persistence'] = 'PASS; reboot NOT TESTED'
            report['status'] = 'PASS'
        except Exception as exc:
            errors.append(type(exc).__name__ + ': ' + str(exc))
            report['status'] = 'FAIL'
            report['errors'] = errors
        finally:
            app.quit()

    QTimer.singleShot(500, probe)
    try:
        result = cli_main(['--home', str(home)])
        from PySide6.QtCore import QThreadPool
        QThreadPool.globalInstance().waitForDone(45000)
        app.processEvents()
        assert result == 0
    finally:
        QMessageBox.warning = previous_warning
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        (output / 'desktop.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
