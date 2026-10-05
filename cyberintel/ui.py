import json
import logging
import uuid
from pathlib import Path

import numpy as np
import pyqtgraph as pg
from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QRunnable, QSortFilterProxyModel, Qt, QThreadPool, QTimer, Signal, Slot, QUrl
from PySide6.QtGui import QDesktopServices, QFont, QIcon, QPixmap
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QInputDialog,
    QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox, QProgressBar, QPushButton,
    QSplitter, QStackedWidget, QTableView, QTextEdit, QVBoxLayout, QWidget)

from .analysis import analyze_cdr, analyze_geo, analyze_pcap, location_map, relationship_graph
from .connectors import Collector, domain, email
from .models import Result, ValidationError, utcnow
from .phone import estimate_phone_region
from .nmap_scan import scan_ips
from .subdomains import discover_subdomains, verify_subdomains, enrich_subdomains, export_subdomains
from .output import validate_export_destination
from .reporting import export_csv, export_pdf
from .security import LocalCredentials

STYLE = """
QWidget { background: #0c101c; color: #dce3f3; font-family: 'Segoe UI', 'DejaVu Sans'; font-size: 13px; }
QMainWindow { background: #0c101c; }
QFrame#sidebar { background: #111626; border-right: 1px solid #25304a; }
QFrame#card { background: #141b2e; border: 1px solid #28334d; border-radius: 10px; }
QFrame#card QLabel { background: transparent; }
QLabel#brand { color: #c4afff; font-size: 21px; font-weight: 700; }
QLabel#title { font-size: 26px; font-weight: 700; }
QLabel#muted { color: #93a2bc; }
QLabel#metric { color: #eef0ff; font-size: 32px; font-weight: 700; }
QLabel#accent { color: #b59bff; font-weight: 600; }
QListWidget { background: transparent; border: none; outline: none; padding: 6px; }
QListWidget::item { padding: 14px 12px; margin: 3px 0; border-radius: 7px; color: #9eacc7; }
QListWidget::item:selected { background: #30264d; color: #d6c6ff; border-left: 3px solid #a78bfa; }
QPushButton { background: #242e47; border: 1px solid #3a4967; padding: 9px 16px; border-radius: 6px; }
QPushButton:hover { background: #374568; }
QPushButton#primary { background: #7452cf; border: 1px solid #9472ea; color: white; font-weight: 600; }
QPushButton#primary:hover { background: #8763e0; }
QPushButton:disabled { background: #1c2334; color: #67758e; border-color: #293249; }
QLineEdit, QComboBox, QTextEdit { background: #111827; border: 1px solid #33415c; border-radius: 5px; padding: 8px; selection-background-color: #7452cf; }
QTableView { background: #101726; alternate-background-color: #151e31; gridline-color: #26324a; border: 1px solid #2a3650; selection-background-color: #343464; }
QHeaderView::section { background: #1c2740; color: #a8b7d2; padding: 9px; border: none; border-right: 1px solid #2b3650; }
QProgressBar { border: none; background: #1e2940; border-radius: 3px; height: 5px; }
QProgressBar::chunk { background: #a78bfa; }
QCheckBox { spacing: 8px; }
QSplitter::handle { background: #26324a; }
QToolTip { background: #26324a; color: white; border: 1px solid #657494; }
"""


def credential_eye_icon(visible=False):
    strike = '<path d="M3 3L21 21"/>' if visible else ''
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" '
           'fill="none" stroke="#b59bff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
           '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/>'
           '<circle cx="12" cy="12" r="3"/>' + strike + '</svg>')
    pixmap = QPixmap()
    pixmap.loadFromData(svg.encode(), "SVG")
    return QIcon(pixmap)


class TableModel(QAbstractTableModel):
    def __init__(self, rows):
        super().__init__()
        self.rows = rows
        self.columns = list(dict.fromkeys(k for row in rows for k in row))

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        value = self.rows[index.row()].get(self.columns[index.column()], "")
        if role == Qt.UserRole:
            return value if isinstance(value, (int, float)) else str(value)
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            if self.columns[index.column()] in {"ipv4", "ipv6"} and isinstance(value, list):
                if value:
                    return ", ".join(value)
                family = self.columns[index.column()]
                status = self.rows[index.row()].get(family + "_status", self.rows[index.row()].get("dns_status", "not checked"))
                return {"no record": "No A record" if family == "ipv4" else "No AAAA record",
                        "nxdomain": "Name does not exist", "lookup failed": "DNS lookup failed",
                        "error": "DNS lookup failed", "no address records": "No address record",
                        "resolved": "No A record" if family == "ipv4" else "No AAAA record"}.get(status, "Not checked")
            return json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            return self.columns[section].replace("_", " ").upper() if orientation == Qt.Horizontal else section + 1


class DataTable(QWidget):
    def __init__(self, placeholder="Filter records…"):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText(placeholder)
        self.view = QTableView()
        self.view.setAlternatingRowColors(True)
        self.view.setSortingEnabled(True)
        self.view.setSelectionBehavior(QTableView.SelectRows)
        self.view.setSelectionMode(QTableView.SingleSelection)
        self.view.setEditTriggers(QTableView.NoEditTriggers)
        self.view.verticalHeader().hide()
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSortRole(Qt.UserRole)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.view.setModel(self.proxy)
        self.filter.textChanged.connect(self.proxy.setFilterFixedString)
        layout.addWidget(self.filter)
        layout.addWidget(self.view)
        self.set_rows([])

    def set_rows(self, rows):
        self.model = TableModel(rows)
        self.proxy.setSourceModel(self.model)
        self.view.resizeColumnsToContents()
        for index in range(self.model.columnCount()):
            self.view.setColumnWidth(index, min(360, max(110, self.view.columnWidth(index))))
        self.view.horizontalHeader().setStretchLastSection(True)

    def selected(self):
        indexes = self.view.selectionModel().selectedRows()
        if indexes:
            source = self.proxy.mapToSource(indexes[0])
            return self.model.rows[source.row()]
        return None


class JobSignals(QObject):
    success = Signal(str, object)
    failure = Signal(str, str)


class Job(QRunnable):
    def __init__(self, identifier, function):
        super().__init__()
        self.identifier, self.function = identifier, function
        self.signals = JobSignals()

    def run(self):
        try:
            self.signals.success.emit(self.identifier, self.function())
        except Exception as exc:
            # Avoid logging input arguments or provider response bodies containing private data.
            logging.getLogger("cyberintel").error("Background job failed (%s)", type(exc).__name__)
            self.signals.failure.emit(self.identifier, str(exc))


class MainWindow(QMainWindow):
    collection_progress = Signal(str, object)
    PAGE_NAMES = ["Overview", "Live OSINT", "Breach intelligence", "Threat intelligence", "CDR analysis", "Network forensics", "Geospatial", "Phone region estimate", "Cases & evidence", "Reports & audit", "Settings", "Subdomain discovery", "Nmap IP scan"]

    def __init__(self, config, session):
        super().__init__()
        self.config, self.session = config, session
        self.credentials = LocalCredentials(config.home / "api-credentials.json")
        self.collector = Collector(config, session.store, keys=self.credentials.values)
        self.jobs = {}
        self.busy = False
        self.last_results = {}
        self.collection_progress.connect(self.show_collection_progress)
        self.display_case = None
        self.setWindowTitle("CyberIntel Suite • Intelligence & Digital Forensics")
        self.resize(1440, 940)
        self.setMinimumSize(1080, 740)
        root = QWidget()
        self.setCentralWidget(root)
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(235)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(16, 26, 16, 20)
        brand = QLabel("CYBERINTEL")
        brand.setObjectName("brand")
        side.addWidget(brand)
        subtitle = QLabel("INTELLIGENCE / FORENSICS")
        subtitle.setObjectName("muted")
        side.addWidget(subtitle)
        side.addSpacing(28)
        self.navigation = QListWidget()
        for name in self.PAGE_NAMES:
            self.navigation.addItem(name)
        side.addWidget(self.navigation, 1)
        identity = QLabel("LOCAL WORKSPACE\nDIRECT ACCESS")
        identity.setObjectName("muted")
        side.addWidget(identity)
        shell.addWidget(sidebar)
        content = QVBoxLayout()
        content.setContentsMargins(30, 24, 30, 20)
        shell.addLayout(content, 1)
        top = QHBoxLayout()
        self.heading = QLabel("Investigation overview")
        self.heading.setObjectName("title")
        top.addWidget(self.heading, 1)
        top.addWidget(QLabel("ACTIVE CASE"))
        self.case_selector = QComboBox()
        self.case_selector.setMinimumWidth(260)
        self.case_selector.currentIndexChanged.connect(self.refresh)
        top.addWidget(self.case_selector)
        content.addLayout(top)
        self.case_hint = QLabel("Select or create a case to retain findings and evidence.")
        self.case_hint.setObjectName("muted")
        content.addWidget(self.case_hint)
        self.pages = QStackedWidget()
        content.addWidget(self.pages, 1)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        content.addWidget(self.progress)
        self.notice = QLabel("Ready • No sample data is loaded automatically")
        self.notice.setObjectName("muted")
        self.notice.setWordWrap(True)
        content.addWidget(self.notice)
        self.build_dashboard()
        self.build_connector_page("osint", "Public infrastructure intelligence", [
            ("DNS records", "dns"), ("RDAP registration", "rdap"), ("CT / public subdomains", "ct"), ("Website metadata", "website")], "Domain or IP address (e.g. example.com)")
        self.build_connector_page("breach", "Breach exposure & public incident timelines", [
            ("Public breach catalog", "hibp_catalog"), ("Authorized email exposure", "hibp_email"), ("Verified domain exposure", "hibp_domain")], "Email or verified domain; catalog needs no target", watch=True)
        self.build_connector_page("threat", "Threat indicator enrichment", [
            ("URLhaus indicator", "urlhaus"), ("AlienVault OTX indicator", "otx"), ("URLhaus recent feed", "urlhaus_recent")], "IP, domain or URL • indicator URLs are never visited", feed=True)
        self.build_analysis_page("cdr", "CDR communication patterns", "Required columns: caller, callee, timestamp, duration_seconds, direction. Timestamps need UTC offsets.")
        self.build_analysis_page("network", "Offline network forensics", "PCAP / PCAPNG • TShark runs with -n and -r; no live capture or DNS resolution.")
        self.build_analysis_page("geo", "Location records & infrastructure", "GPS: latitude, longitude, timestamp, source, record_kind. Towers: tower_id, latitude, longitude, source.")
        self.build_phone_page()
        self.build_cases()
        self.build_reports()
        self.build_settings()
        self.build_subdomains_page()
        self.build_nmap_page()
        self.navigation.currentRowChanged.connect(self.navigate)
        self.navigation.setCurrentRow(0)
        self.reload_cases()
        self.monitor = QTimer(self)
        self.monitor.setInterval(15 * 60 * 1000)
        self.monitor.timeout.connect(lambda: self.poll_watchlist() if self.active_case() else None)
        self.feed_timer = QTimer(self)
        self.feed_timer.setInterval(15 * 60 * 1000)
        self.feed_timer.timeout.connect(self.poll_feed)

    def page(self, subtitle):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 18, 0, 0)
        description = QLabel(subtitle)
        description.setWordWrap(True)
        description.setObjectName("muted")
        layout.addWidget(description)
        self.pages.addWidget(widget)
        return layout

    def button(self, text, callback, primary=False):
        button = QPushButton(text)
        if primary:
            button.setObjectName("primary")
        button.clicked.connect(callback)
        return button

    def navigate(self, index):
        self.pages.setCurrentIndex(index)
        self.heading.setText("Investigation overview" if index == 0 else self.PAGE_NAMES[index])
        self.refresh()

    def build_dashboard(self):
        layout = self.page("Case-backed intelligence, traceable sources and offline evidence analysis")
        cards = QHBoxLayout()
        self.metrics = {}
        for key, label, note in [("cases", "Investigation cases", "Local case repository"), ("evidence", "Evidence files", "SHA-256 acquisition records"), ("findings", "Saved findings", "Case-linked collection history"), ("sources", "Available data", "Live / cached / offline / test")]:
            card = QFrame()
            card.setObjectName("card")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(20, 18, 20, 18)
            card_layout.addWidget(QLabel(label))
            metric = QLabel("0")
            metric.setObjectName("metric")
            card_layout.addWidget(metric)
            muted = QLabel(note)
            muted.setObjectName("muted")
            muted.setWordWrap(True)
            card_layout.addWidget(muted)
            cards.addWidget(card)
            self.metrics[key] = metric
        layout.addLayout(cards)
        actions = QHBoxLayout()
        actions.addWidget(self.button("+ New investigation", self.create_case, True))
        actions.addWidget(self.button("Import evidence", self.import_evidence))
        actions.addWidget(self.button("Verify evidence hashes", self.verify_evidence))
        actions.addStretch()
        layout.addLayout(actions)
        self.dashboard_plot = pg.PlotWidget()
        self.dashboard_plot.setBackground("#101726")
        self.dashboard_plot.setLabel("left", "Stored collections")
        self.dashboard_plot.setTitle("Collection activity • UTC dates", color="#a8b7d2", size="13pt")
        self.dashboard_plot.showGrid(y=True, alpha=0.15)
        self.dashboard_plot.setMinimumHeight(190)
        layout.addWidget(self.dashboard_plot, 1)
        section = QLabel("RECENT CASE FINDINGS")
        section.setObjectName("accent")
        layout.addWidget(section)
        self.recent_table = DataTable()
        layout.addWidget(self.recent_table, 2)

    def build_connector_page(self, key, subtitle, operations, placeholder, watch=False, feed=False):
        layout = self.page(subtitle)
        controls = QHBoxLayout()
        operation = QComboBox()
        for label, value in operations:
            operation.addItem(label, value)
        target = QLineEdit()
        target.setPlaceholderText(placeholder)
        force = QCheckBox("Refresh cache")
        controls.addWidget(operation)
        controls.addWidget(target, 1)
        controls.addWidget(force)
        controls.addWidget(self.button("Collect", lambda: self.run_collection(key), True))
        layout.addLayout(controls)
        authorization = QCheckBox("I am authorized to check this account/domain or collect metadata from this website")
        if key in {"osint", "breach"}:
            layout.addWidget(authorization)
        status = QLabel("No collection yet • API credentials are configured in Settings")
        status.setObjectName("muted")
        status.setWordWrap(True)
        layout.addWidget(status)
        table = DataTable()
        raw = QTextEdit()
        raw.setReadOnly(True)
        raw.setPlaceholderText("Normalized source result and provenance will appear here.")
        split = QSplitter(Qt.Vertical)
        split.addWidget(table)
        split.addWidget(raw)
        split.setSizes([400, 180])
        layout.addWidget(split, 1)
        setattr(self, key + "_controls", {"operation": operation, "target": target, "force": force,
                                        "authorization": authorization, "status": status, "table": table, "raw": raw})
        if watch:
            row = QHBoxLayout()
            row.addWidget(self.button("Add authorized exposure watch", self.add_watch))
            row.addWidget(self.button("Check watches now", self.poll_watchlist))
            self.watch_enabled = QCheckBox("Monitor while open • every 15 minutes")
            self.watch_enabled.toggled.connect(lambda checked: self.monitor.start() if checked else self.monitor.stop())
            row.addWidget(self.watch_enabled)
            layout.addLayout(row)
            self.watch_table = DataTable("Filter authorized exposure watches…")
            self.watch_table.setMaximumHeight(155)
            layout.addWidget(self.watch_table)
            layout.addWidget(self.button("Remove selected watch", self.remove_watch))
        if feed:
            self.feed_enabled = QCheckBox("Update URLhaus recent feed for active case every 15 minutes while open")
            self.feed_enabled.toggled.connect(lambda checked: self.feed_timer.start() if checked else self.feed_timer.stop())
            layout.addWidget(self.feed_enabled)

    def build_nmap_page(self):
        layout = self.page("Active TCP scanning with Nmap: ports, services, product versions and potential vulnerability matches. Requires Nmap on PATH.")
        form = QFormLayout()
        self.nmap_targets = QLineEdit()
        self.nmap_targets.setPlaceholderText("Up to 16 IP addresses separated by commas; one address family per batch")
        self.nmap_ports = QLineEdit()
        self.nmap_ports.setPlaceholderText("Blank: top 100 TCP ports. Custom: 22,80,443,8000-8010 (max 1000)")
        form.addRow("Target IPs", self.nmap_targets)
        form.addRow("TCP ports", self.nmap_ports)
        layout.addLayout(form)
        self.nmap_authorized = QCheckBox("I own these systems or have permission to scan them")
        self.nmap_vulnerabilities = QCheckBox("Vulners lookup: send detected service/version/CPE to vulners.com for potential vulnerability matches")
        layout.addWidget(self.nmap_authorized)
        layout.addWidget(self.nmap_vulnerabilities)
        layout.addWidget(self.button("Scan IPs", self.run_nmap_scan, True))
        status = QLabel("Ready. Versions may be incomplete; potential matches require validation. Scans run in the background, up to 120 seconds per host plus script overhead.")
        status.setWordWrap(True)
        table, raw = DataTable("Filter IP, port, service, version or findings"), QTextEdit()
        raw.setReadOnly(True)
        split = QSplitter(Qt.Vertical)
        split.addWidget(table)
        split.addWidget(raw)
        split.setSizes([450, 150])
        layout.addWidget(status)
        layout.addWidget(split, 1)
        self.nmap_controls = {"status": status, "table": table, "raw": raw}

    def run_nmap_scan(self):
        targets, ports = self.nmap_targets.text(), self.nmap_ports.text()
        authorized, vulnerabilities = self.nmap_authorized.isChecked(), self.nmap_vulnerabilities.isChecked()
        case_id = self.active_case()
        def task():
            self.session.check("collect")
            result = scan_ips(targets, ports, vulnerabilities, authorized)
            if case_id:
                self.session.save_finding(case_id, "nmap", result)
            else:
                self.session.audit("nmap_scan", result.query + "; no case selected")
            return result
        self.start_job("Nmap TCP service and version scan", task, lambda result: self.show_result("nmap", result))

    def build_subdomains_page(self):
        layout = self.page("Find public subdomains from crt.sh, with automatic Cert Spotter fallback. Public queries are rate limited by providers.")
        row = QHBoxLayout()
        self.subdomain_target = QLineEdit()
        self.subdomain_target.setPlaceholderText("Root domain, e.g. example.com")
        self.subdomain_force = QCheckBox("Refresh cache")
        self.subdomain_auto_dns = QCheckBox("Resolve IPs (first 100)")
        self.subdomain_auto_dns.setChecked(True)
        row.addWidget(self.subdomain_target, 1)
        row.addWidget(self.subdomain_force)
        row.addWidget(self.subdomain_auto_dns)
        row.addWidget(self.button("Find subdomains", self.run_subdomain_discovery, True))
        layout.addLayout(row)
        status = QLabel("DNS addresses resolve automatically for the first 100 names. A hostname may have no IPv6 record. DNS resolution does not prove a website is active.")
        status.setWordWrap(True)
        status.setObjectName("muted")
        layout.addWidget(status)
        table = DataTable("Filter discovered names or DNS status…")
        raw = QTextEdit()
        raw.setReadOnly(True)
        split = QSplitter(Qt.Vertical)
        split.addWidget(table)
        split.addWidget(raw)
        split.setSizes([450, 150])
        layout.addWidget(split, 1)
        actions = QHBoxLayout()
        actions.addWidget(self.button("Check DNS for filtered names (max 100)", self.run_subdomain_dns))
        actions.addWidget(self.button("Export filtered CSV", self.export_subdomain_csv))
        actions.addStretch()
        layout.addLayout(actions)
        self.subdomains_controls = {"status": status, "table": table, "raw": raw}

    def filtered_subdomain_names(self):
        table = self.subdomains_controls["table"]
        return [table.model.rows[table.proxy.mapToSource(table.proxy.index(i, 0)).row()]["subdomain"]
                for i in range(table.proxy.rowCount())]

    def run_subdomain_discovery(self):
        value, force = self.subdomain_target.text(), self.subdomain_force.isChecked()
        resolve_ips = self.subdomain_auto_dns.isChecked()
        case_id = self.active_case()
        def task():
            self.session.check("collect")
            result = discover_subdomains(self.collector, value, force)
            if resolve_ips:
                if result.data and result.data.get("records"):
                    self.collection_progress.emit("subdomains", result)
                result = enrich_subdomains(result)
            if case_id:
                self.session.save_finding(case_id, "subdomains", result)
            else:
                self.session.audit("subdomain_discovery", "Public CT lookup; no case selected")
            return result
        self.start_job("Finding subdomains and resolving IPv4/IPv6 (up to 100)" if resolve_ips else "Finding public subdomains", task,
                       lambda result: self.show_result("subdomains", result))

    def run_subdomain_dns(self):
        result = self.last_results.get("subdomains")
        if not result or result.data is None:
            return self.error("Discover subdomains first.")
        names, case_id = self.filtered_subdomain_names(), self.active_case()
        def task():
            self.session.check("collect")
            checked = verify_subdomains(result, names)
            if case_id:
                self.session.save_finding(case_id, "subdomains", checked)
            else:
                self.session.audit("subdomain_dns_verified", f"{len(names)} names; no case selected")
            return checked
        self.start_job("Checking discovered names through DNS", task, lambda checked: self.show_result("subdomains", checked))

    def export_subdomain_csv(self):
        result = self.last_results.get("subdomains")
        if not result or result.data is None:
            return self.error("Discover subdomains first.")
        names = self.filtered_subdomain_names()
        path, _ = QFileDialog.getSaveFileName(self, "Export filtered subdomains", "subdomains.csv", "CSV (*.csv)")
        if not path:
            return
        if not path.lower().endswith(".csv"):
            path += ".csv"
        def task():
            self.session.check("report")
            validate_export_destination(self.session, path)
            exported = export_subdomains(result, path, names)
            self.session.audit("subdomains_exported", f"{len(names)} filtered names")
            return exported
        self.start_job("Exporting subdomains", task, lambda exported: self.notice.setText("Subdomains CSV written: " + exported))

    def build_phone_page(self):
        layout = self.page("Offline numbering-region estimates or authorized Twilio validation and carrier/type lookup.")
        description = QLabel("A phone number cannot reveal a phone's current location. Area/carrier labels describe numbering allocations; portability and roaming can make these associations inaccurate. Actual location analysis requires authorized GPS or tower records in Geospatial.")
        description.setWordWrap(True)
        layout.addWidget(description)
        row = QHBoxLayout()
        self.phone_number = QLineEdit()
        self.phone_number.setPlaceholderText("Mobile or landline number in +country-code format")
        self.phone_region = QLineEdit()
        self.phone_region.setPlaceholderText("Country: IN / US / GB")
        self.phone_region.setMaxLength(2)
        self.phone_region.setMaximumWidth(190)
        row.addWidget(self.phone_number, 1)
        row.addWidget(self.phone_region)
        row.addWidget(self.button("Estimate numbering region", self.run_phone_estimate, True))
        layout.addLayout(row)
        self.phone_authorized = QCheckBox("I am authorized to send this phone number to Twilio for lookup")
        self.phone_paid_carrier = QCheckBox("Include carrier/type lookup (Twilio charges and coverage restrictions may apply)")
        layout.addWidget(self.phone_authorized)
        layout.addWidget(self.phone_paid_carrier)
        layout.addWidget(self.button("Twilio phone lookup", self.run_twilio_phone))
        status = QLabel("Ready. Region estimates are offline; Twilio lookup sends the number to the provider. No device tracking or coordinates.")
        status.setWordWrap(True)
        status.setObjectName("muted")
        layout.addWidget(status)
        table = DataTable()
        raw = QTextEdit()
        raw.setReadOnly(True)
        split = QSplitter(Qt.Vertical)
        split.addWidget(table)
        split.addWidget(raw)
        split.setSizes([450, 180])
        layout.addWidget(split, 1)
        self.phone_controls = {"status": status, "table": table, "raw": raw}

    def run_twilio_phone(self):
        if not self.phone_authorized.isChecked():
            return self.error("Confirm authorization to send the number to Twilio.")
        value = self.phone_number.text()
        source = "twilio_phone_carrier" if self.phone_paid_carrier.isChecked() else "twilio_phone"
        case_id = self.active_case()
        def task():
            self.session.check("collect")
            result = self.collector.collect(source, value)
            if case_id:
                self.session.save_finding(case_id, "phone", result)
            else:
                self.session.audit("twilio_phone_lookup", result.status + "; no case selected")
            return result
        self.start_job("Twilio phone lookup", task, lambda result: self.show_result("phone", result))

    def run_phone_estimate(self):
        value, region = self.phone_number.text(), self.phone_region.text()
        case_id = self.active_case()
        def task():
            self.session.check("collect")
            result = estimate_phone_region(value, region)
            if case_id:
                self.session.save_finding(case_id, "phone", result)
            else:
                self.session.audit("phone_region_estimated", "Offline numbering metadata; no case selected")
            return result
        self.start_job("Estimating phone numbering region", task, lambda result: self.show_result("phone", result))

    def run_collection(self, key):
        controls = getattr(self, key + "_controls")
        source, target = controls["operation"].currentData(), controls["target"].text().strip()
        if source in {"website", "hibp_email", "hibp_domain"} and not controls["authorization"].isChecked():
            return self.error("Confirm authorization using the checkbox before this collection.")
        try:
            self.session.check("collect")
        except Exception as exc:
            return self.error(str(exc))
        case_id = self.active_case()
        force = controls["force"].isChecked()
        def task():
            self.session.check("collect")
            if source == "ct":
                result = discover_subdomains(self.collector, target, force)
                if result.data and result.data.get("records"):
                    self.collection_progress.emit(key, result)
                result = enrich_subdomains(result)
            else:
                result = self.collector.collect(source, target, force)
            if case_id:
                self.session.save_finding(case_id, key, result)
            else:
                self.session.audit("collection", f"{source}: {result.status} (no case selected)")
            return result
        self.start_job("Collecting from " + source, task, lambda result: self.show_result(key, result))

    def result_rows(self, result):
        data = result.data
        if isinstance(data, list):
            return [row if isinstance(row, dict) else {"value": row} for row in data]
        if isinstance(data, dict):
            for name in ["relationships", "records", "connections", "indicators", "dns_queries"]:
                if isinstance(data.get(name), list):
                    if name == "records" and data[name] and "subdomain" in data[name][0]:
                        first = ["subdomain", "ipv4", "ipv6", "dns_status", "ipv4_status", "ipv6_status"]
                        return [{**{field: row.get(field, [] if field in {"ipv4", "ipv6"} else "not checked") for field in first},
                                 **{field: value for field, value in row.items() if field not in first}} for row in data[name]]
                    return data[name]
            if "subdomains" in data:
                return [{"subdomain": name} for name in data["subdomains"]]
            return [{"field": k, "value": v} for k, v in data.items()]
        return []

    @Slot(str, object)
    def show_collection_progress(self, key, result):
        if not self.busy:
            return
        self.show_result(key, result)
        self.notice.setText("Subdomains found; IPv4/IPv6 checks are still running. Final results will be saved when complete.")

    def show_result(self, key, result):
        self.last_results[key] = result
        controls = getattr(self, key + "_controls")
        controls["table"].set_rows(self.result_rows(result))
        controls["raw"].setPlainText(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        controls["status"].setText(f"{result.status.upper()} • {result.freshness} • {result.source} • {result.collected_at}" + (f" • {result.error}" if result.error else ""))
        if key == "nmap" and result.data:
            rows = result.data["records"]
            opened = sum(row["state"] == "open" for row in rows)
            timeouts = sum(host["timed_out"] for host in result.data["hosts"])
            controls["status"].setText(controls["status"].text() + f" • {opened} open TCP ports • {timeouts} timed-out hosts; host summaries and script findings in details")
        if key == "subdomains" and result.data is not None:
            controls["status"].setText(controls["status"].text() + f" • {result.data['subdomain_count']} concrete names • {len(result.data.get('wildcard_patterns', []))} wildcard patterns (see details)")
        if key in {"osint", "subdomains"} and isinstance(result.data, dict) and result.data.get("records") and "subdomain" in result.data["records"][0]:
            checked = sum(bool(row.get("dns_checked_at")) for row in result.data["records"])
            controls["status"].setText(controls["status"].text() + f" • DNS checked: {checked}/{len(result.data['records'])}; filter and check remaining names")
        if key in {"osint", "subdomains"} and isinstance(result.data, dict) and result.data.get("truncated"):
            controls["status"].setText(controls["status"].text() + " • Partial discovery; see warnings in details")
        if key == "cdr":
            plot = controls["plot"]
            plot.clear()
            counts = result.data["hourly_calls_utc"]
            plot.addItem(pg.BarGraphItem(x=list(range(24)), height=[counts.get(str(h), 0) for h in range(24)], width=.7, brush="#a78bfa"))
        self.notice.setText("Collection complete • " + result.status + (" • " + result.error if result.error else ""))
        self.refresh()

    def build_analysis_page(self, key, subtitle, schema):
        layout = self.page(subtitle + " • " + schema)
        controls = QHBoxLayout()
        selector = QComboBox()
        selector.setMinimumWidth(260)
        controls.addWidget(selector, 1)
        mode = QComboBox()
        if key == "geo":
            mode.addItem("GPS / location records", "gps")
            mode.addItem("Cell tower inventory", "towers")
            controls.addWidget(mode)
        controls.addWidget(self.button("Import file", self.import_evidence))
        controls.addWidget(self.button("Analyze evidence", lambda: self.run_analysis(key), True))
        if key == "cdr":
            controls.addWidget(self.button("Open relationship graph", lambda: self.open_visual("cdr")))
        if key == "geo":
            controls.addWidget(self.button("Open location map", lambda: self.open_visual("geo")))
        layout.addLayout(controls)
        status = QLabel("Select evidence attached to the active case. Synthetic evidence is explicitly labeled.")
        status.setObjectName("muted")
        status.setWordWrap(True)
        layout.addWidget(status)
        table = DataTable()
        raw = QTextEdit()
        raw.setReadOnly(True)
        split = QSplitter(Qt.Vertical)
        split.addWidget(table)
        split.addWidget(raw)
        split.setSizes([400, 160])
        layout.addWidget(split, 1)
        info = {"selector": selector, "mode": mode, "status": status, "table": table, "raw": raw}
        if key == "cdr":
            plot = pg.PlotWidget()
            plot.setBackground("#101726")
            plot.setLabel("bottom", "Hour (UTC)")
            plot.setLabel("left", "Calls")
            plot.setMaximumHeight(170)
            layout.addWidget(plot)
            info["plot"] = plot
        if key == "geo":
            tiles = QCheckBox("Use OpenStreetMap tiles (browser requests external map tiles)")
            layout.addWidget(tiles)
            info["tiles"] = tiles
        setattr(self, key + "_controls", info)

    def run_analysis(self, key):
        case_id = self.need_case()
        if not case_id:
            return
        controls = getattr(self, key + "_controls")
        evidence = controls["selector"].currentData()
        if not evidence:
            return self.error("Import and select an evidence file first.")
        mode = controls["mode"].currentData()
        def task():
            self.session.check("collect")
            from .analysis import sha256
            if sha256(evidence["path"]) != evidence["sha256"]:
                raise ValidationError("Evidence hash mismatch. Analysis refused.")
            if key == "cdr":
                result = analyze_cdr(evidence["path"], evidence["data_kind"])
            elif key == "network":
                result = analyze_pcap(evidence["path"], data_kind=evidence["data_kind"])
            else:
                result = analyze_geo(evidence["path"], mode, evidence["data_kind"])
            result.reference = "evidence:" + evidence["id"]
            result.query = evidence["name"]
            result.data["evidence_source"] = evidence["source"]
            result.data["acquired_at"] = evidence["acquired_at"]
            self.session.save_finding(case_id, key, result)
            return result
        self.start_job("Analyzing offline evidence", task, lambda result: self.show_result(key, result))

    def open_visual(self, key):
        result = self.last_results.get(key)
        if not result:
            return self.error("Analyze an evidence file first.")
        try:
            self.session.check("report")
        except Exception as exc:
            return self.error(str(exc))
        destination = self.config.home / "exports"
        destination.mkdir(exist_ok=True, mode=0o700)
        file = destination / (key + "-" + str(uuid.uuid4()) + ".html")
        online = self.geo_controls["tiles"].isChecked() if key == "geo" else False
        self.start_job("Preparing visualization", lambda: relationship_graph(result, file) if key == "cdr" else location_map(result, file, online),
                       lambda path: QDesktopServices.openUrl(QUrl.fromLocalFile(path)))

    def build_cases(self):
        layout = self.page("Managed evidence copies retain source, acquisition time and SHA-256; originals are read only.")
        row = QHBoxLayout()
        row.addWidget(self.button("+ New case", self.create_case, True))
        row.addWidget(self.button("Attach evidence", self.import_evidence))
        row.addWidget(self.button("Verify hashes", self.verify_evidence))
        row.addStretch()
        layout.addLayout(row)
        self.case_table, self.evidence_table = DataTable(), DataTable()
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.case_table)
        split.addWidget(self.evidence_table)
        layout.addWidget(split)

    def create_case(self):
        if self.busy:
            self.notice.setText("Wait for the running task before creating or changing cases.")
            return
        title, ok = QInputDialog.getText(self, "New investigation", "Case title:")
        if not ok:
            return
        description, ok = QInputDialog.getMultiLineText(self, "Case scope", "Scope, authority and investigation notes:")
        if not ok:
            return
        try:
            identifier = self.session.create_case(title, description)
            self.reload_cases(identifier)
            self.notice.setText("Case created • " + title)
        except Exception as exc:
            self.error(str(exc))

    def import_evidence(self):
        case_id = self.need_case()
        if not case_id:
            return
        try:
            self.session.check("evidence")
        except Exception as exc:
            return self.error(str(exc))
        path, _ = QFileDialog.getOpenFileName(self, "Import authorized evidence", "", "Evidence (*.csv *.xlsx *.pcap *.pcapng *.json *.txt *.pdf)")
        if not path:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Evidence provenance")
        form = QFormLayout(dialog)
        source, acquired, kind = QLineEdit(), QLineEdit(utcnow()), QComboBox()
        source.setPlaceholderText("Provider, acquisition method, or legal authority")
        kind.addItems(["actual", "inferred", "synthetic"])
        if "synthetic" in Path(path).name.lower():
            kind.setCurrentText("synthetic")
        form.addRow("Source", source)
        form.addRow("Acquired (ISO 8601 + timezone)", acquired)
        form.addRow("Data kind", kind)
        authorized = QCheckBox("I am authorized to possess and analyze this file")
        form.addRow(authorized)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        form.addRow(buttons)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        if dialog.exec() != QDialog.Accepted:
            return
        if not authorized.isChecked():
            return self.error("Confirm authorization before importing evidence.")
        values = (source.text(), acquired.text(), kind.currentText())
        self.start_job("Copying and hashing evidence", lambda: self.session.add_evidence(case_id, path, *values),
                       lambda _: self.refresh())

    def verify_evidence(self):
        case_id = self.need_case()
        if case_id:
            self.start_job("Verifying evidence", lambda: self.session.verify_evidence(case_id),
                           lambda rows: QMessageBox.information(self, "Evidence integrity", "\n".join(f"{r['name']}: {'OK' if r['valid'] else 'MISMATCH / MISSING'}" for r in rows) or "No evidence files attached."))

    def build_reports(self):
        layout = self.page("Case reports contain saved findings, source references, collection times and an evidence integrity check.")
        buttons = QHBoxLayout()
        buttons.addWidget(self.button("Export case PDF", lambda: self.export_report("pdf"), True))
        buttons.addWidget(self.button("Export case CSV", lambda: self.export_report("csv")))
        buttons.addWidget(self.button("Verify audit chain", self.verify_audit))
        buttons.addStretch()
        layout.addLayout(buttons)
        self.findings_table, self.audit_table = DataTable(), DataTable()
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.findings_table)
        split.addWidget(self.audit_table)
        layout.addWidget(split)
        buttons2 = QHBoxLayout()
        buttons2.addWidget(self.button("View selected finding", self.view_finding))
        buttons2.addWidget(self.button("Restore selected analysis to module", self.restore_finding))
        buttons2.addStretch()
        layout.addLayout(buttons2)

    def view_finding(self):
        row = self.findings_table.selected()
        if not row:
            return self.error("Select a saved finding first.")
        dialog = QDialog(self)
        dialog.setWindowTitle("Stored finding and provenance")
        dialog.resize(900, 650)
        layout = QVBoxLayout(dialog)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(json.dumps(json.loads(row["result"]), indent=2, ensure_ascii=False))
        layout.addWidget(text)
        dialog.exec()

    def restore_finding(self):
        if self.busy:
            self.notice.setText("Wait for the running task before restoring a finding.")
            return
        row = self.findings_table.selected()
        if not row or row["module"] not in {"cdr", "network", "geo", "osint", "breach", "threat", "phone", "subdomains", "nmap"}:
            return self.error("Select a module finding first.")
        key = row["module"]
        result = Result(**json.loads(row["result"]))
        if result.status == "live":
            from datetime import datetime, timezone
            result.status = "cached"
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(result.collected_at)).total_seconds()
            result.freshness = "stale" if age >= self.config.cache_seconds else "fresh"
        self.show_result(key, result)
        self.navigation.setCurrentRow({"osint": 1, "breach": 2, "threat": 3, "cdr": 4, "network": 5, "geo": 6, "phone": 7, "subdomains": 11, "nmap": 12}[key])

    def export_report(self, kind):
        case_id = self.need_case()
        if not case_id:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export case report", f"cyberintel-case.{kind}", f"{kind.upper()} (*.{kind})")
        if path:
            if not path.lower().endswith("." + kind):
                path += "." + kind
            self.start_job("Generating case report", lambda: (export_pdf if kind == "pdf" else export_csv)(self.session, case_id, path),
                           lambda result: self.notice.setText("Report written: " + result))

    def verify_audit(self):
        self.start_job("Verifying audit chain", self.session.verify_audit,
                       lambda valid: QMessageBox.information(self, "Audit integrity", "Retained audit entries are consistent. Chain is not externally anchored." if valid else "Audit chain mismatch detected."))

    def build_settings(self):
        layout = self.page("Enter API credentials directly and save. Stored locally without encryption; no vault passphrase is required.")
        form = QFormLayout()
        self.key_fields = {}
        self.key_visibility = {}
        for key, title in [("hibp", "HIBP subscription key"), ("otx", "OTX API key"), ("urlhaus", "URLhaus Auth-Key"),
                           ("twilio_account_sid", "Twilio Account SID (AC...)"), ("twilio_key_sid", "Twilio API key SID (SK...)"),
                           ("twilio_key_secret", "Twilio API key secret (replacement key)")]:
            field = QLineEdit()
            field.setEchoMode(QLineEdit.Password)
            field.setText(self.credentials.get(key))
            eye = field.addAction(credential_eye_icon(), QLineEdit.TrailingPosition)
            eye.setCheckable(True)
            eye.setEnabled(True)
            eye.setText("Show " + title)
            eye.setToolTip("Show credential")
            eye.toggled.connect(lambda visible, field=field, eye=eye, title=title:
                                self.toggle_credential_visibility(field, eye, title, visible))
            self.key_visibility[key] = eye
            self.key_fields[key] = field
            form.addRow(title, field)
        layout.addLayout(form)
        self.save_keys_button = self.button("Save credentials", self.save_keys)
        layout.addWidget(self.save_keys_button)
        endpoints = QLabel("Connector endpoint configuration: " + str(self.config.home / "config.json") + "\n" +
                          "\n".join(f"{k}: {v}" for k, v in self.config.endpoints.items()))
        endpoints.setWordWrap(True)
        endpoints.setObjectName("muted")
        layout.addWidget(endpoints)
        layout.addStretch()

    def toggle_credential_visibility(self, field, eye, title, visible):
        field.setEchoMode(QLineEdit.Normal if visible else QLineEdit.Password)
        eye.setIcon(credential_eye_icon(visible))
        eye.setText(("Hide " if visible else "Show ") + title)
        eye.setToolTip("Hide credential" if visible else "Show credential")

    def clear_credentials_from_memory(self):
        self.collector.keys = {}
        self.credentials.values = {}
        for name, field in self.key_fields.items():
            self.key_visibility[name].setChecked(False)
            field.setEchoMode(QLineEdit.Password)
            field.clear()

    def save_keys(self):
        if self.busy:
            self.notice.setText("Wait for the running task before changing credentials.")
            return
        try:
            self.session.check("settings")
            self.credentials.save({name: field.text() for name, field in self.key_fields.items()})
            self.collector.keys = dict(self.credentials.values)
            self.session.audit("credentials_updated", "Local API credentials saved")
            self.notice.setText("Credentials saved")
        except Exception as exc:
            self.error(str(exc))

    def add_watch(self):
        case_id = self.need_case()
        if not case_id:
            return
        controls = self.breach_controls
        if not controls["authorization"].isChecked():
            return self.error("Confirm authorization using the exposure checkbox.")
        operation = controls["operation"].currentData()
        try:
            if operation not in {"hibp_email", "hibp_domain"}:
                raise ValidationError("Select email or domain exposure before adding a watch.")
            target = (email if operation == "hibp_email" else domain)(controls["target"].text())
            self.session.add_watch(case_id, "email" if operation == "hibp_email" else "domain", target)
            self.refresh()
            self.notice.setText("Exposure watch added to active case")
        except Exception as exc:
            self.error(str(exc))

    def remove_watch(self):
        row = self.watch_table.selected()
        if not row:
            return self.error("Select a watch first.")
        try:
            self.session.remove_watch(row["id"])
            self.refresh()
        except Exception as exc:
            self.error(str(exc))

    def poll_watchlist(self):
        if self.busy:
            return
        case_id = self.need_case()
        if not case_id:
            return
        def task():
            self.session.check("collect")
            watches = self.session.rows("watchlist", case_id)
            if len(watches) > 25:
                raise ValidationError("Monitor limit is 25 watches per case.")
            results = []
            previous_findings = self.session.rows("findings", case_id)
            changes = []
            for watch in watches:
                previous = next((json.loads(row["result"]) for row in previous_findings
                                 if row["module"] == "breach" and json.loads(row["result"])["query"] == watch["target"]
                                 and json.loads(row["result"])["status"] not in {"unavailable"}), None)
                result = self.collector.collect("hibp_" + watch["kind"], watch["target"], force=True)
                if result.status == "live" and previous:
                    def names(data):
                        return set(data.get("breach_counts", {})) if isinstance(data, dict) else {r.get("Name") for r in data or []}
                    added = names(result.data) - names(previous["data"])
                    if added:
                        changes.append(f"{watch['target']}: new breaches {', '.join(sorted(added))}")
                    if isinstance(result.data, dict) and isinstance(previous["data"], dict):
                        for breach, count in result.data.get("breach_counts", {}).items():
                            old_count = previous["data"].get("breach_counts", {}).get(breach, 0)
                            if breach not in added and count > old_count:
                                changes.append(f"{watch['target']}: {breach} exposure count increased {old_count} → {count}")
                self.session.save_finding(case_id, "breach", result)
                if result.status == "live":
                    with self.session.store.connection() as db:
                        db.execute("UPDATE watchlist SET last_checked=? WHERE id=?", (utcnow(), watch["id"]))
                results.append(result)
            return results, changes
        def complete(payload):
            results, changes = payload
            if results:
                self.show_result("breach", results[-1])
            self.notice.setText(f"Checked {len(results)} exposure watches • {sum(r.status == 'unavailable' for r in results)} unavailable • {sum(r.freshness == 'stale' for r in results)} stale • results saved to case")
            if changes:
                QMessageBox.information(self, "New breach exposure observed", "\n".join(changes))
        self.start_job("Checking authorized exposure watches", task, complete)

    def poll_feed(self):
        if self.busy or not self.active_case():
            return
        case_id = self.active_case()
        def task():
            self.session.check("collect")
            result = self.collector.collect("urlhaus_recent", force=True)
            self.session.save_finding(case_id, "threat", result)
            return result
        self.start_job("Updating URLhaus feed", task, lambda result: self.show_result("threat", result))

    def active_case(self):
        return self.case_selector.currentData()

    def need_case(self):
        case_id = self.active_case()
        if not case_id:
            self.error("Create or select an investigation case first.")
        return case_id

    def reload_cases(self, selected=None):
        selected = selected or self.active_case()
        self.case_selector.blockSignals(True)
        self.case_selector.clear()
        self.case_selector.addItem("No case selected", None)
        for row in self.session.rows("cases"):
            self.case_selector.addItem(row["title"], row["id"])
        index = self.case_selector.findData(selected)
        self.case_selector.setCurrentIndex(max(0, index))
        self.case_selector.blockSignals(False)
        self.refresh()

    def refresh(self, *_):
        if not hasattr(self, "evidence_table"):
            return
        case_id = self.active_case()
        if case_id != self.display_case:
            for key in list(self.last_results):
                controls = getattr(self, key + "_controls")
                controls["table"].set_rows([])
                controls["raw"].clear()
                controls["status"].setText("Case changed. Collect or restore a finding for this case.")
                if "plot" in controls:
                    controls["plot"].clear()
            self.last_results.clear()
            self.display_case = case_id
        cases = self.session.rows("cases")
        evidence = self.session.rows("evidence", case_id) if case_id else []
        findings = self.session.rows("findings", case_id) if case_id else []
        self.case_table.set_rows(cases)
        self.evidence_table.set_rows(evidence)
        self.watch_table.set_rows(self.session.rows("watchlist", case_id) if case_id else [])
        self.findings_table.set_rows(findings)
        self.audit_table.set_rows(self.session.rows("audit")[:1000])
        self.metrics["cases"].setText(str(len(cases)))
        self.metrics["evidence"].setText(str(len(evidence)))
        self.metrics["findings"].setText(str(len(findings)))
        valid = 0
        recent = []
        days = {}
        for row in findings:
            result = json.loads(row["result"])
            valid += result["status"] != "unavailable"
            recent.append({"module": row["module"], "query": result["query"], "source": result["source"], "status": result["status"], "freshness": result["freshness"], "collected_at": result["collected_at"]})
            day = row["created_at"][:10]
            days[day] = days.get(day, 0) + 1
        self.metrics["sources"].setText(str(valid))
        self.recent_table.set_rows(recent[:100])
        self.dashboard_plot.clear()
        ordered = sorted(days.items())[-14:]
        if ordered:
            self.dashboard_plot.addItem(pg.BarGraphItem(x=list(range(len(ordered))), height=[c for _, c in ordered], width=.55, brush="#8e75de"))
        self.dashboard_plot.getAxis("bottom").setTicks([[(i, day[5:]) for i, (day, _) in enumerate(ordered)]])
        for key in ("cdr", "network", "geo"):
            selector = getattr(self, key + "_controls")["selector"]
            selected = selector.currentData()
            selected_id = selected["id"] if selected else None
            selector.clear()
            suffixes = {".pcap", ".pcapng"} if key == "network" else {".csv", ".xlsx"}
            for item in evidence:
                if Path(item["name"]).suffix.lower() in suffixes:
                    selector.addItem(item["name"] + " • " + item["data_kind"], item)
                    if item["id"] == selected_id:
                        selector.setCurrentIndex(selector.count() - 1)
        self.case_hint.setText("Active case: " + self.case_selector.currentText() if case_id else "No case selected • Collections can be viewed, but saving findings requires a case")

    def start_job(self, label, function, callback):
        if self.busy:
            self.notice.setText("A task is already running. Wait for it to finish.")
            return
        self.busy = True
        self.case_selector.setEnabled(False)
        self.progress.setRange(0, 0)
        self.notice.setText(label + "…")
        identifier = str(uuid.uuid4())
        job = Job(identifier, function)
        self.jobs[identifier] = (job, callback)
        job.signals.success.connect(self.job_success)
        job.signals.failure.connect(self.job_failure)
        QThreadPool.globalInstance().start(job)

    def finish_job(self, identifier):
        job, callback = self.jobs.pop(identifier)
        self.busy = False
        self.case_selector.setEnabled(True)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        return callback

    @Slot(str, object)
    def job_success(self, identifier, result):
        callback = self.finish_job(identifier)
        self.notice.setText("Task complete")
        try:
            callback(result)
            self.refresh()
        except Exception as exc:
            self.error(str(exc))

    @Slot(str, str)
    def job_failure(self, identifier, message):
        self.finish_job(identifier)
        self.error(message)

    def error(self, message):
        self.notice.setText("Action could not complete • " + message)
        QMessageBox.warning(self, "CyberIntel Suite", message)

    def closeEvent(self, event):
        if self.busy:
            self.notice.setText("Wait for the running task to complete before closing.")
            event.ignore()
            return
        self.monitor.stop()
        self.feed_timer.stop()
        self.clear_credentials_from_memory()
        super().closeEvent(event)
