"""Desktop project, scan and observation browser."""
import json
import threading

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, QUrl, Qt
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPushButton, QTabWidget, QTextEdit, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QInputDialog, QListWidget, QStackedWidget, QProgressBar)

from .cli import doctor
from .scanner import scan
from .storage import KINDS, compare_snapshots


DASHBOARD_STYLE = """
QWidget { background: #0b1220; color: #dce7f5; font-size: 13px; }
QLineEdit, QComboBox, QTextEdit, QTableWidget { background: #111e30; border: 1px solid #25364c; border-radius: 6px; padding: 7px; selection-background-color: #164e63; }
QPushButton { background: #1b2d43; border: 1px solid #30445f; padding: 10px 16px; border-radius: 6px; }
QPushButton:hover { background: #26445e; }
QPushButton:disabled { color: #758397; }
QPushButton#analyzeButton { background: #087f8c; color: white; font-weight: bold; padding: 15px 25px; }
QLineEdit#targetInput { font-size: 16px; padding: 15px; }
QListWidget { background: #0e1929; border: none; border-radius: 8px; }
QListWidget::item { padding: 12px; }
QListWidget::item:selected { background: #164357; color: #63e5db; border-left: 3px solid #36d4bf; }
QHeaderView::section { background: #1b2d43; padding: 8px; border: none; }
QTableWidget { alternate-background-color: #142339; gridline-color: #26384d; }
QProgressBar { background: #182b3e; border: none; }
QProgressBar::chunk { background: #36d4bf; }
QTabBar::tab { padding: 8px; }
"""


class ObservationTable(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter observations across all columns")
        self.filter.textChanged.connect(self.apply_filter)
        layout.addWidget(self.filter)
        self.table = QTableWidget()
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.cellDoubleClicked.connect(self.details)
        layout.addWidget(self.table)
        self.summary = QLabel()
        layout.addWidget(self.summary)
        self.rows = []

    def setPlainText(self, text):
        records = json.loads(text)
        self.rows = records[:1000]
        columns = list(dict.fromkeys(key for record in self.rows for key in record))
        self.table.setSortingEnabled(False)
        self.table.clear()
        self.table.setRowCount(len(self.rows))
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels([key.replace("_", " ").title() for key in columns])
        for index, record in enumerate(self.rows):
            for column, key in enumerate(columns):
                value = record.get(key, "")
                text = json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict)) else str(value)
                item = QTableWidgetItem(text[:500])
                item.setData(Qt.UserRole, record)
                item.setToolTip(text[:10000])
                self.table.setItem(index, column, item)
        self.table.resizeColumnsToContents()
        for column in range(len(columns)):
            self.table.setColumnWidth(column, min(350, max(100, self.table.columnWidth(column))))
        self.table.setSortingEnabled(True)
        self.summary.setText(f"{len(records)} observations • showing up to 1,000 • double-click for evidence" if records else "No observations recorded. Check Overview and Evidence & Errors for coverage limitations.")
        self.apply_filter()

    def clear(self):
        self.setPlainText("[]")

    def apply_filter(self):
        query = self.filter.text().casefold()
        for row in range(self.table.rowCount()):
            self.table.setRowHidden(row, bool(query) and not any(query in self.table.item(row, column).text().casefold()
                                    for column in range(self.table.columnCount())))

    def details(self, row, column):
        dialog = QDialog(self)
        dialog.setWindowTitle("Observation details")
        dialog.resize(800, 500)
        layout = QVBoxLayout(dialog)
        view = QTextEdit()
        view.setReadOnly(True)
        values = self.table.item(row, column).data(Qt.UserRole)
        view.setPlainText(json.dumps(values, indent=2))
        layout.addWidget(view)
        dialog.exec()


class Signals(QObject):
    done = Signal(str)
    error = Signal(str)
    progress = Signal(str)


class Worker(QRunnable):
    def __init__(self, repo, project, target, settings, cancel):
        super().__init__()
        self.args = repo, project, target
        self.settings, self.cancel = settings, cancel
        self.signals = Signals()

    def run(self):
        try:
            self.signals.done.emit(scan(*self.args, **self.settings, cancel=self.cancel, progress=self.signals.progress.emit))
        except Exception as exc:
            self.signals.error.emit(str(exc))


class ProviderWorker(QRunnable):
    def __init__(self, repo, project, target, provider, cancel):
        super().__init__()
        self.args = repo, project, target, provider
        self.cancel = cancel
        self.signals = Signals()

    def run(self):
        try:
            from .providers import host_lookup
            self.signals.done.emit(host_lookup(*self.args, cancel=self.cancel))
        except Exception as exc:
            self.signals.error.emit(str(exc))


class LocalWorker(QRunnable):
    """Keep local diagnostics and potentially large report/graph work off the UI."""
    def __init__(self, operation):
        super().__init__()
        self.operation = operation
        self.signals = Signals()

    def run(self):
        try:
            self.signals.done.emit(self.operation())
        except Exception as exc:
            self.signals.error.emit(type(exc).__name__ + ": local operation failed.")


class Window(QMainWindow):
    def __init__(self, repo):
        super().__init__()
        self.repo, self.cancel, self.worker = repo, threading.Event(), None
        self.setWindowTitle("CyberRecon — Authorized Reconnaissance")
        from pathlib import Path
        self.setWindowIcon(QIcon(str(Path(__file__).parent / 'assets/cyberrecon.svg')))
        self.resize(1280, 850)
        self.setStyleSheet(DASHBOARD_STYLE)
        self.local_jobs = []
        self.advanced = QDialog(self)
        self.advanced.setWindowTitle("Authorization and advanced settings")
        self.advanced.resize(820, 720)
        advanced_layout = QVBoxLayout(self.advanced)
        form = QFormLayout()
        self.includes, self.excludes, self.authority = QLineEdit(), QLineEdit(), QLineEdit()
        self.includes.setPlaceholderText("Blank = exact target only")
        self.excludes.setPlaceholderText("Comma-separated exclusions; override allowed scope")
        self.authority.setPlaceholderText("Ownership or written authorization reference")
        self.passive, self.history = QComboBox(), QComboBox()
        self.passive.addItems(["None", "ct", "subfinder", "assetfinder", "amass"])
        self.history.addItems(["None", "gau", "waybackurls"])
        self.lifecycle, self.go_dns = QCheckBox("Upstream lifecycle lookup"), QCheckBox("Go DNS worker")
        self.enable_ports = QCheckBox("Nmap TCP inventory for explicitly authorized IP targets")
        self.enable_ports.setChecked(True)
        self.port_list = QLineEdit("22,80,443,8080,8443")
        self.udp, self.cve = QCheckBox("UDP (requires suitable privileges)"), QCheckBox("NVD candidates; not confirmed vulnerabilities")
        self.wordlist, self.ca_bundle = QLineEdit(), QLineEdit()
        self.crawl = QCheckBox("Bounded crawl: 30 pages, depth 2")
        self.crawl.setChecked(True)
        for label, widget in (("Allowed scope", self.includes), ("Exclusions", self.excludes),
                ("Authorization", self.authority), ("Passive discovery", self.passive),
                ("Historical URLs", self.history), ("Lifecycle", self.lifecycle), ("DNS worker", self.go_dns),
                ("Ports", self.enable_ports), ("TCP port selection", self.port_list), ("UDP", self.udp),
                ("CVE lookup", self.cve), ("Content wordlist", self.wordlist), ("Trusted lab CA", self.ca_bundle),
                ("Web discovery", self.crawl)):
            form.addRow(label, widget)
        advanced_layout.addLayout(form)
        self.tabs, self.views = QTabWidget(), {}
        for name in ("scope", "settings", "doctor", "comparison"):
            view = QTextEdit()
            view.setReadOnly(True)
            self.views[name] = view
            self.tabs.addTab(view, name.title())
        advanced_layout.addWidget(self.tabs)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.advanced.reject)
        advanced_layout.addWidget(buttons)
        self.views["settings"].setPlainText(
            "Bounded profile: exact authorized target; 30 hosts, 30 pages, depth 2, 100 HTTP requests, 2 requests/second.\n"
            "TLS verification and exclusions apply to every request. Discovered IPs/subdomains do not expand authorization.\n"
            "Nmap uses a bounded TCP inventory. OS detection and intrusive scripts are not enabled.\n"
            "External passive/lifecycle/NVD providers are opt-in. Host intelligence uses configured environment credentials; keys are never saved here.")
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(24, 20, 24, 20)
        header = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(self.windowIcon().pixmap(48, 48))
        header.addWidget(logo)
        title = QLabel("<b style='font-size:26px'>CyberRecon</b><br>Automated Security Reconnaissance")
        header.addWidget(title, 1)
        settings = QPushButton("Scope && settings")
        settings.clicked.connect(self.advanced.show)
        header.addWidget(settings)
        about = QPushButton("About")
        about.clicked.connect(self.about)
        header.addWidget(about)
        layout.addLayout(header)
        target_row = QHBoxLayout()
        self.target = QLineEdit()
        self.target.setObjectName("targetInput")
        self.target.setPlaceholderText("Enter an authorized URL, domain, or IP address")
        self.target.returnPressed.connect(self.start_scan)
        target_row.addWidget(self.target, 1)
        self.start = QPushButton("Analyze Target")
        self.start.setObjectName("analyzeButton")
        self.start.clicked.connect(self.start_scan)
        target_row.addWidget(self.start)
        self.stop = QPushButton("Cancel")
        self.stop.setEnabled(False)
        self.stop.clicked.connect(self.cancel_scan)
        target_row.addWidget(self.stop)
        layout.addLayout(target_row)
        self.status = QLabel("Ready • bounded reconnaissance • authorization required before active requests")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setMaximumHeight(5)
        layout.addWidget(self.progress)
        body = QHBoxLayout()
        self.navigation, self.pages = QListWidget(), QStackedWidget()
        self.navigation.setFixedWidth(220)
        self.navigation.currentRowChanged.connect(self.pages.setCurrentIndex)
        body.addWidget(self.navigation)
        body.addWidget(self.pages, 1)
        layout.addLayout(body, 1)
        from .dashboard import SECTIONS
        self.result_views = {}
        for key, label in SECTIONS:
            self.navigation.addItem(label)
            if key == "overview":
                view = QTextEdit()
                view.setReadOnly(True)
                self.overview = view
            elif key == "history":
                view = QWidget()
                history_layout = QVBoxLayout(view)
                self.projects, self.scans = QComboBox(), QComboBox()
                self.projects.currentIndexChanged.connect(self.refresh_scans)
                self.scans.currentIndexChanged.connect(self.show_scan)
                history_layout.addWidget(QLabel("Saved authorization scopes"))
                history_layout.addWidget(self.projects)
                history_layout.addWidget(self.scans)
                self.views["scan_history"] = ObservationTable()
                history_layout.addWidget(self.views["scan_history"])
                for text, action in (("Edit scope", self.edit_scope), ("Compare previous scan", self.compare)):
                    button = QPushButton(text)
                    button.clicked.connect(action)
                    history_layout.addWidget(button)
            elif key == "export":
                view = QWidget()
                exports = QVBoxLayout(view)
                info = QLabel("Export the selected scan with its recorded scope, timestamps, settings, evidence and errors.\nJSON, CSV, HTML, PDF and relationship graph are available. Select a scan in History to export older results.")
                info.setWordWrap(True)
                exports.addWidget(info)
                for text, action in (("Export reports", self.export), ("Open relationship graph", self.open_graph),
                                     ("Configured host intelligence", self.host_intelligence)):
                    button = QPushButton(text)
                    button.clicked.connect(action)
                    exports.addWidget(button)
                exports.addStretch()
            else:
                view = ObservationTable()
                self.result_views[key] = view
            self.pages.addWidget(view)
        # Preserve integrations that refer to the original observation view names.
        from .dashboard import VIEW_ALIASES
        for name, key in VIEW_ALIASES.items():
            self.views[name] = self.result_views[key]
        self.views["dashboard"] = self.overview
        self.navigation.setCurrentRow(0)
        self.setCentralWidget(root)
        self.views["doctor"].setPlainText("Checking local dependencies and tool versions…")
        self.doctor_worker = LocalWorker(lambda: json.dumps(doctor(repo.home), indent=2))
        self.doctor_worker.signals.done.connect(self.views["doctor"].setPlainText)
        self.doctor_worker.signals.error.connect(self.views["doctor"].setPlainText)
        QThreadPool.globalInstance().start(self.doctor_worker)
        self.refresh_projects()

    def about(self):
        from . import __version__
        QMessageBox.information(self, 'About CyberRecon',
            f'CyberRecon {__version__}\nAuthorized, scope-controlled reconnaissance.\nMIT License • CyberRecon contributors\nDesktop and production release gates are documented in the repository.')

    def refresh_projects(self, preferred=None):
        self.projects.blockSignals(True)
        self.projects.clear()
        for item in self.repo.projects():
            self.projects.addItem(item["name"], item["id"])
        self.projects.addItem("New scan", None)
        if preferred:
            self.projects.setCurrentIndex(self.projects.findData(preferred))
        self.projects.blockSignals(False)
        self.refresh_scans()

    def refresh_scans(self):
        self.scans.blockSignals(True)
        self.scans.clear()
        project = self.projects.currentData()
        if project:
            scope = self.repo.scope(project)
            self.includes.setText(", ".join(scope.include))
            self.excludes.setText(", ".join(scope.exclude))
            self.authority.setText(self.repo.project(project)["authority"])
            self.views["scope"].setPlainText(json.dumps(self.repo.scope(project).to_dict(), indent=2))
            for item in self.repo.scans(project):
                self.scans.addItem(item["started_at"] + " • " + item["status"] + " • " + item["target"], item["id"])
            self.views["scan_history"].setPlainText(json.dumps(self.repo.scans(project)))
        else:
            self.includes.clear()
            self.excludes.clear()
            self.authority.clear()
            self.views["scope"].clear()
            self.views["scan_history"].clear()
        self.scans.blockSignals(False)
        self.show_scan()

    def show_scan(self):
        from .dashboard import dashboard_rows, overview_html
        identifier = self.scans.currentData()
        if not identifier:
            for view in self.result_views.values():
                view.clear()
            self.overview.setHtml("<h1>Your reconnaissance workspace</h1><p>Enter a target to begin. Results, evidence and coverage limitations appear here.</p><p>Active requests require an authorization reference and explicit scope.</p>")
            return
        snapshot = self.repo.snapshot(identifier)
        for key, rows in dashboard_rows(snapshot).items():
            self.result_views[key].setPlainText(json.dumps(rows))
        self.overview.setHtml(overview_html(snapshot))

    def scan_context(self):
        """Create/reuse the internal history context directly from scan inputs."""
        from .scope import Scope, host_of
        from .dashboard import normalize_target
        target = normalize_target(self.target.text())
        self.target.setText(target)
        split = lambda text: [value.strip() for value in text.split(",") if value.strip()]
        scope = Scope(tuple(split(self.includes.text()) or [host_of(target)]), tuple(split(self.excludes.text())))
        host = scope.require(target, passive=True)
        authority = self.authority.text().strip()
        if not authority:
            raise ValueError("Enter an authorization reference, such as My own system or the program scope URL.")
        for project in self.repo.projects():
            if project["authority"] == authority and json.loads(project["scope"]) == scope.to_dict():
                identifier = project["id"]
                break
        else:
            identifier = self.repo.create_project(host, scope.include, scope.exclude, authority)
        self.refresh_projects(identifier)
        return identifier

    def start_scan(self):
        if self.worker:
            return
        from .dashboard import normalize_target, applicable_ports
        try:
            self.target.setText(normalize_target(self.target.text()))
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid target", str(exc))
            return
        if not self.authority.text().strip():
            reference, accepted = QInputDialog.getText(self, "Authorize target", "Ownership or written authorization reference for this target:")
            if not accepted or not reference.strip():
                self.status.setText("Scan not started: authorization reference required.")
                return
            self.authority.setText(reference.strip())
        self.cancel.clear()
        settings = {"crawl": self.crawl.isChecked(), "passive": self.passive.currentText() if self.passive.currentIndex() else None,
                    "history": self.history.currentText() if self.history.currentIndex() else None,
                    "lifecycle": self.lifecycle.isChecked(), "go_dns": self.go_dns.isChecked(),
                    "ports": applicable_ports(self.target.text(), self.port_list.text()) if self.enable_ports.isChecked() else None,
                    "udp": self.udp.isChecked() and applicable_ports(self.target.text(), self.port_list.text()) is not None, "cve": self.cve.isChecked(), "ca_bundle": self.ca_bundle.text() or None, "nmap_unprivileged": not self.udp.isChecked()}
        if self.wordlist.text():
            from pathlib import Path
            try:
                path = Path(self.wordlist.text())
                if path.stat().st_size > 64 * 1024:
                    raise ValueError("Wordlist exceeds 64 KiB.")
                settings["words"] = path.read_text().splitlines()
            except (ValueError, OSError) as exc:
                QMessageBox.warning(self, "Wordlist failed", str(exc))
                return
        try:
            project = self.scan_context()
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Check scan scope", str(exc))
            return
        self.worker = Worker(self.repo, project, self.target.text(), settings, self.cancel)
        self.worker.signals.done.connect(self.finished)
        self.worker.signals.error.connect(self.finished)
        self.worker.signals.progress.connect(self.status.setText)
        self.projects.setEnabled(False)
        self.scans.setEnabled(False)
        self.start.setEnabled(False)
        self.target.setEnabled(False)
        self.stop.setEnabled(True)
        self.progress.setRange(0, 0)
        self.status.setText("Scanning; rate 2 requests/second, bounded requests, scope checked before requests.")
        QThreadPool.globalInstance().start(self.worker)

    def edit_scope(self):
        project = self.projects.currentData()
        if not project:
            return
        scope = self.repo.scope(project)
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit authorized scope")
        form = QFormLayout(dialog)
        include, exclude = QLineEdit(", ".join(scope.include)), QLineEdit(", ".join(scope.exclude))
        form.addRow("Include rules", include)
        form.addRow("Exclude rules (override inclusions)", exclude)
        form.addRow("Authorization reference", QLabel(self.repo.project(project)["authority"]))
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() == QDialog.Accepted:
            try:
                split = lambda text: [rule.strip() for rule in text.split(",") if rule.strip()]
                self.repo.update_scope(project, split(include.text()), split(exclude.text()))
                if self.worker:
                    self.cancel_scan()
                self.refresh_scans()
                self.status.setText("Scope updated and recorded in history. A running scan was cancelled; start a new scan with this scope." if self.worker else
                                    "Scope updated and recorded in history.")
            except (ValueError, OSError) as exc:
                QMessageBox.warning(self, "Scope update failed", str(exc))

    def finished(self, message):
        self.worker = None
        self.projects.setEnabled(True)
        self.scans.setEnabled(True)
        self.start.setEnabled(True)
        self.target.setEnabled(True)
        self.stop.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.status.setText("Scan ended: " + message)
        if any(row["id"] == message for row in self.repo.scans(self.projects.currentData())):
            self.status.setText("Scan " + self.repo.snapshot(message)["scan"]["status"] + " • review coverage and evidence below")
        self.refresh_scans()
        self.navigation.setCurrentRow(0)

    def cancel_scan(self):
        self.cancel.set()
        if self.worker:
            self.status.setText("Cancellation requested; waiting for the current bounded operation to stop.")

    def host_intelligence(self):
        if self.worker:
            return
        provider, accepted = QInputDialog.getItem(self, "Host intelligence", "Read existing observations for the entered authorized public IP (may consume account credits):",
                                                 ["shodan", "censys"], 0, False)
        if not accepted:
            return
        try:
            project = self.scan_context()
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Check scan scope", str(exc))
            return
        self.cancel.clear()
        self.worker = ProviderWorker(self.repo, project, self.target.text(), provider, self.cancel)
        self.worker.signals.done.connect(self.finished)
        self.worker.signals.error.connect(self.finished)
        self.projects.setEnabled(False)
        self.scans.setEnabled(False)
        self.start.setEnabled(False)
        self.target.setEnabled(False)
        self.stop.setEnabled(True)
        self.progress.setRange(0, 0)
        self.status.setText("Reading existing " + provider + " host observations; no target scan initiated.")
        QThreadPool.globalInstance().start(self.worker)

    def local_task(self, operation, done):
        job = LocalWorker(operation)
        self.local_jobs.append(job)
        job.signals.done.connect(done)
        job.signals.error.connect(self.status.setText)
        # Bound simultaneous local work so repeated clicks cannot exhaust memory.
        job.signals.done.connect(lambda _: self.local_jobs.remove(job))
        job.signals.error.connect(lambda _: self.local_jobs.remove(job))
        QThreadPool.globalInstance().start(job)

    def export(self):
        identifier = self.scans.currentData()
        if identifier and not self.local_jobs:
            destination = QFileDialog.getExistingDirectory(self, "Export directory")
            if destination:
                from .reporting import export_reports
                self.status.setText("Generating reports…")
                self.local_task(lambda: export_reports(self.repo, identifier, destination),
                                lambda path: self.status.setText("Exported to " + path))

    def compare(self):
        index = self.scans.currentIndex()
        if index >= 0 and index + 1 < self.scans.count():
            changes = compare_snapshots(self.repo.snapshot(self.scans.itemData(index + 1)), self.repo.snapshot(self.scans.currentData()))
            self.views["comparison"].setPlainText(json.dumps(changes, indent=2))
            self.tabs.setCurrentWidget(self.views["comparison"])
            self.advanced.show()
        else:
            self.status.setText("A previous scan from this project is required.")

    def open_graph(self):
        identifier = self.scans.currentData()
        if identifier and not self.local_jobs:
            from .graph import export_graph
            destination = self.repo.managed_directory("scans", identifier) / "graph.html"
            self.status.setText("Generating graph…")
            self.local_task(lambda: export_graph(self.repo.snapshot(identifier), destination),
                            lambda path: QDesktopServices.openUrl(QUrl.fromLocalFile(path)))

    def closeEvent(self, event):
        self.cancel.set()
        super().closeEvent(event)


def launch(repository):
    app = QApplication.instance() or QApplication([])
    # Window owns the dashboard theme; do not change other application windows.
    window = Window(repository)
    window.show()
    return app.exec()
