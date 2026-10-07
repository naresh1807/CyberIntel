"""Desktop project, scan and observation browser."""
import json
import threading

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, QUrl, Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPushButton, QTabWidget, QTextEdit, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QInputDialog)

from .cli import doctor
from .scanner import scan
from .storage import KINDS, compare_snapshots


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
        self.summary.setText(f"{len(records)} observations • showing up to 1,000 • double-click for row details")
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
        self.resize(1150, 800)
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.addWidget(QLabel("CyberRecon  •  Scope → Discovery → Evidence → Comparison"))
        row = QHBoxLayout()
        self.projects = QComboBox()
        self.projects.currentIndexChanged.connect(self.refresh_scans)
        row.addWidget(self.projects, 1)
        create = QPushButton("New project")
        create.clicked.connect(self.create_project)
        row.addWidget(create)
        edit_scope = QPushButton("Edit scope")
        edit_scope.clicked.connect(self.edit_scope)
        row.addWidget(edit_scope)
        layout.addLayout(row)
        options = QHBoxLayout()
        options.addWidget(QLabel("Passive discovery"))
        self.passive = QComboBox()
        self.passive.addItems(["None", "ct", "subfinder", "assetfinder", "amass"])
        options.addWidget(self.passive)
        options.addWidget(QLabel("Historical URLs"))
        self.history = QComboBox()
        self.history.addItems(["None", "gau", "waybackurls"])
        options.addWidget(self.history)
        self.lifecycle = QCheckBox("Lifecycle lookup (endoflife.date)")
        options.addWidget(self.lifecycle)
        self.go_dns = QCheckBox("Go DNS worker")
        options.addWidget(self.go_dns)
        layout.addLayout(options)
        engines_row = QHBoxLayout()
        self.enable_ports = QCheckBox("Nmap (explicit IP target)")
        engines_row.addWidget(self.enable_ports)
        self.port_list = QLineEdit()
        self.port_list.setPlaceholderText("Ports, e.g. 22,80,443; blank = top 100")
        engines_row.addWidget(self.port_list)
        self.udp = QCheckBox("UDP")
        engines_row.addWidget(self.udp)
        self.cve = QCheckBox("NVD CPE candidates")
        self.cve.setToolTip("Sends up to three detected versioned CPEs to NVD; never confirms a vulnerability.")
        engines_row.addWidget(self.cve)
        self.wordlist = QLineEdit()
        self.wordlist.setPlaceholderText("Optional local content wordlist path")
        engines_row.addWidget(self.wordlist)
        self.ca_bundle = QLineEdit()
        self.ca_bundle.setPlaceholderText("Optional trusted lab CA PEM path")
        engines_row.addWidget(self.ca_bundle)
        layout.addLayout(engines_row)
        row = QHBoxLayout()
        self.target = QLineEdit()
        self.target.setPlaceholderText("Authorized domain, IP or HTTP(S) URL")
        row.addWidget(self.target)
        self.crawl = QCheckBox("Crawl (30 pages, depth 2)")
        row.addWidget(self.crawl)
        self.start = QPushButton("Start scan")
        self.start.clicked.connect(self.start_scan)
        row.addWidget(self.start)
        stop = QPushButton("Cancel")
        stop.clicked.connect(self.cancel_scan)
        row.addWidget(stop)
        layout.addLayout(row)
        self.status = QLabel("Create a project with an authorization reference before scanning.")
        layout.addWidget(self.status)
        row = QHBoxLayout()
        self.scans = QComboBox()
        self.scans.currentIndexChanged.connect(self.show_scan)
        row.addWidget(self.scans)
        export = QPushButton("Export reports")
        export.clicked.connect(self.export)
        row.addWidget(export)
        compare = QPushButton("Compare previous scan")
        compare.clicked.connect(self.compare)
        row.addWidget(compare)
        graph = QPushButton("Open graph")
        graph.clicked.connect(self.open_graph)
        row.addWidget(graph)
        intel = QPushButton("Host intelligence")
        intel.clicked.connect(self.host_intelligence)
        row.addWidget(intel)
        layout.addLayout(row)
        self.tabs, self.views = QTabWidget(), {}
        for name in ("dashboard", "scope", *KINDS, "hosts", "scan_history", "comparison", "settings", "doctor"):
            view = ObservationTable() if name in (*KINDS, "hosts", "scan_history") else QTextEdit()
            if isinstance(view, QTextEdit):
                view.setReadOnly(True)
            self.views[name] = view
            labels = {"dns": "DNS", "http": "HTTP", "urls": "URLs", "apis": "APIs", "javascript": "JavaScript"}
            self.tabs.addTab(view, labels.get(name, name.title()))
        self.views["doctor"].setPlainText("Checking local dependencies and tool versions…")
        self.doctor_worker = LocalWorker(lambda: json.dumps(doctor(repo.home), indent=2))
        self.doctor_worker.signals.done.connect(self.views["doctor"].setPlainText)
        self.doctor_worker.signals.error.connect(self.views["doctor"].setPlainText)
        QThreadPool.globalInstance().start(self.doctor_worker)
        self.local_jobs = []
        self.views["settings"].setPlainText("Scan limits: 30 hosts, 30 pages per host, depth 2, 100 HTTP requests, 2 requests/second.\n\n"
            "Native requests verify TLS and pin DNS addresses. Private addresses need explicit IP scope.\n\n"
            "Host intelligence uses SHODAN_API_KEY or CENSYS_PLATFORM_TOKEN and optional CENSYS_ORGANIZATION_ID from the launch environment. "
            "Keys are not saved in the workspace. Provider queries may consume account credits.\n\n"
            "Use Doctor to inspect bounded local version probes and compatibility families.")
        layout.addWidget(self.tabs)
        self.setCentralWidget(root)
        self.refresh_projects()

    def refresh_projects(self):
        self.projects.blockSignals(True)
        self.projects.clear()
        for item in self.repo.projects():
            self.projects.addItem(item["name"], item["id"])
        self.projects.blockSignals(False)
        self.refresh_scans()
        if self.projects.count():
            self.status.setText("Project ready. Review Scope, enter an authorized target, then start a bounded scan.")

    def refresh_scans(self):
        self.scans.blockSignals(True)
        self.scans.clear()
        project = self.projects.currentData()
        if project:
            self.views["scope"].setPlainText(json.dumps(self.repo.scope(project).to_dict(), indent=2))
            for item in self.repo.scans(project):
                self.scans.addItem(item["started_at"] + " • " + item["status"] + " • " + item["target"], item["id"])
            self.views["scan_history"].setPlainText(json.dumps(self.repo.scans(project)))
        else:
            self.views["scan_history"].clear()
        self.scans.blockSignals(False)
        self.show_scan()

    def show_scan(self):
        identifier = self.scans.currentData()
        if not identifier:
            for name in ("dashboard", *KINDS, "hosts", "comparison"):
                self.views[name].clear()
            return
        snapshot = self.repo.snapshot(identifier)
        for kind in KINDS:
            self.views[kind].setPlainText(json.dumps(snapshot[kind], indent=2))
        self.views["hosts"].setPlainText(json.dumps(snapshot["assets"]))
        self.views["dashboard"].setPlainText(json.dumps({"scan": snapshot["scan"],
            "counts": {kind: len(snapshot[kind]) for kind in KINDS}}, indent=2))

    def create_project(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Authorized project")
        form = QFormLayout(dialog)
        fields = [QLineEdit() for _ in range(4)]
        for label, field in zip(("Name", "Include rules (comma separated)", "Exclude rules (comma separated)", "Authorization reference"), fields):
            form.addRow(label, field)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() == QDialog.Accepted:
            try:
                name, includes, excludes, authority = [field.text() for field in fields]
                split = lambda text: [value.strip() for value in text.split(",") if value.strip()]
                self.repo.create_project(name, split(includes), split(excludes), authority)
                self.refresh_projects()
            except ValueError as exc:
                QMessageBox.warning(self, "Invalid project", str(exc))

    def start_scan(self):
        if self.worker:
            return
        project = self.projects.currentData()
        if not project:
            QMessageBox.warning(self, "Project required", "Create an authorized project first.")
            return
        self.cancel.clear()
        settings = {"crawl": self.crawl.isChecked(), "passive": self.passive.currentText() if self.passive.currentIndex() else None,
                    "history": self.history.currentText() if self.history.currentIndex() else None,
                    "lifecycle": self.lifecycle.isChecked(), "go_dns": self.go_dns.isChecked(),
                    "ports": self.port_list.text() if self.enable_ports.isChecked() else None,
                    "udp": self.udp.isChecked(), "cve": self.cve.isChecked(), "ca_bundle": self.ca_bundle.text() or None}
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
        self.worker = Worker(self.repo, project, self.target.text(), settings, self.cancel)
        self.worker.signals.done.connect(self.finished)
        self.worker.signals.error.connect(self.finished)
        self.worker.signals.progress.connect(self.status.setText)
        self.start.setEnabled(False)
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
        self.start.setEnabled(True)
        self.status.setText("Scan ended: " + message)
        self.refresh_scans()

    def cancel_scan(self):
        self.cancel.set()
        if self.worker:
            self.status.setText("Cancellation requested; waiting for the current bounded operation to stop.")

    def host_intelligence(self):
        if self.worker or not self.projects.currentData():
            return
        provider, accepted = QInputDialog.getItem(self, "Host intelligence", "Read existing observations for the entered authorized public IP (may consume account credits):",
                                                 ["shodan", "censys"], 0, False)
        if not accepted:
            return
        self.cancel.clear()
        self.worker = ProviderWorker(self.repo, self.projects.currentData(), self.target.text(), provider, self.cancel)
        self.worker.signals.done.connect(self.finished)
        self.worker.signals.error.connect(self.finished)
        self.start.setEnabled(False)
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
    app.setStyleSheet("QWidget { background: #101827; color: #e5edf6; font-size: 13px; } QLineEdit,QTextEdit,QComboBox { background: #192638; padding: 6px; } QPushButton { background: #245a7b; padding: 8px; } QTabBar::tab { padding: 8px; }")
    window = Window(repository)
    window.show()
    return app.exec()
