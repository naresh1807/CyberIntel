import csv
import ipaddress
import json
import subprocess
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from cyberintel.config import Config
from cyberintel.models import ValidationError
from cyberintel.reporting import export_csv
from cyberintel.ui import MainWindow
from cyberintel.wifi_scan import discovery_network, export_devices, local_networks, neighbor_macs, parse_devices, scan_devices

XML = b'''<nmaprun><host><status state="up" reason="arp-response"/>
<address addr="192.168.1.10" addrtype="ipv4"/><address addr="aa:bb:cc:dd:ee:10" addrtype="mac" vendor="Example"/></host>
<host><status state="down"/><address addr="192.168.1.2" addrtype="ipv4"/></host>
<host><status state="up" reason="localhost-response"/><address addr="192.168.1.3" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="192.168.1.4" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="192.168.1.5" addrtype="ipv4"/></host>
<runstats><finished exit="success"/></runstats></nmaprun>'''


@pytest.mark.parametrize("value", ["8.8.8.0/24", "127.0.0.0/24", "224.0.0.0/24", "192.168.0.0/16", "example.com", "192.168.1.1", "::1/128", "--script=all", "192.168.1.0/24;whoami"])
def test_invalid_discovery_network(value):
    with pytest.raises(ValidationError):
        discovery_network(value)


def test_private_network_bounds():
    assert str(discovery_network("192.168.1.10/24")) == "192.168.1.0/24"
    assert discovery_network("10.0.0.0/22").num_addresses == 1024
    assert str(discovery_network("172.16.1.0/24")) == "172.16.1.0/24"


def test_devices_count_sorted_up_only_and_missing_mac():
    rows = parse_devices(XML, ipaddress.IPv4Network("192.168.1.0/24"))
    assert [row["ip"] for row in rows] == ["192.168.1.3", "192.168.1.4", "192.168.1.5", "192.168.1.10"]
    assert rows[0]["mac"] == "Unavailable"
    assert rows[-1]["mac"] == "AA:BB:CC:DD:EE:10"
    assert rows[-1]["vendor"] == "Example"
    for payload in [XML.replace(b'192.168.1.10', b'10.0.0.1'), XML.replace(b'exit="success"', b'exit="error"'), b'<!ENTITY x "bad"><nmaprun/>']:
        with pytest.raises(ValidationError):
            parse_devices(payload, ipaddress.IPv4Network("192.168.1.0/24"))


def test_interface_and_neighbor_detection(monkeypatch):
    monkeypatch.setattr("cyberintel.wifi_scan.shutil.which", lambda _: "/usr/sbin/ip")
    def run(args, **kwargs):
        if "neigh" in args:
            payload = [{"dst": "192.168.1.10", "lladdr": "aa-bb-cc-dd-ee-10", "state": ["STALE"]},
                       {"dst": "192.168.1.2", "lladdr": "aa:bb:cc:dd:ee:02", "state": ["FAILED"]}]
        else:
            payload = [{"ifname": "wlan0", "address": "aa:bb:cc:dd:ee:03", "addr_info": [
                {"family": "inet", "local": "192.168.1.3", "prefixlen": 24}]},
                {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]}]
        return subprocess.CompletedProcess(args, 0, json.dumps(payload).encode())
    monkeypatch.setattr("cyberintel.wifi_scan.subprocess.run", run)
    assert local_networks() == [{"network": "192.168.1.0/24", "interface": "wlan0", "ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:03"}]
    assert neighbor_macs() == {"192.168.1.10": "AA:BB:CC:DD:EE:10"}


def test_detector_unavailable_or_corrupt(monkeypatch):
    monkeypatch.setattr("cyberintel.wifi_scan.shutil.which", lambda _: None)
    with pytest.raises(ValidationError, match="manually"):
        local_networks()
    assert neighbor_macs() == {}
    monkeypatch.setattr("cyberintel.wifi_scan.shutil.which", lambda _: "ip")
    monkeypatch.setattr("cyberintel.wifi_scan.subprocess.run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, b'not json'))
    with pytest.raises(ValidationError, match="manually"):
        local_networks()
    assert neighbor_macs() == {}


def mock_scan(monkeypatch):
    monkeypatch.setattr("cyberintel.wifi_scan.shutil.which", lambda _: "nmap")
    def run(args, **kwargs):
        assert "-sn" in args and "-n" in args
        assert "-sV" not in args and "--script" not in args
        assert kwargs["shell"] is False and kwargs["timeout"] == 120
        assert args[-1] == "192.168.1.0/24"
        Path(args[args.index("-oX") + 1]).write_bytes(XML)
        return subprocess.CompletedProcess(args, 0)
    monkeypatch.setattr("cyberintel.wifi_scan.subprocess.run", run)
    monkeypatch.setattr("cyberintel.wifi_scan.neighbor_macs", lambda: {"192.168.1.4": "AA:BB:CC:DD:EE:04", "192.168.1.2": "AA:BB:CC:DD:EE:02"})
    monkeypatch.setattr("cyberintel.wifi_scan.local_networks", lambda: [{"ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:03"}])


def test_runner_enrichment_count_and_export(monkeypatch, tmp_path):
    mock_scan(monkeypatch)
    result = scan_devices("192.168.1.0/24", authorized=True)
    assert result.data["device_count"] == 4
    assert result.data["mac_available_count"] == 3
    assert result.data["records"][0]["mac_source"] == "local interface"
    assert result.data["records"][1]["mac_source"] == "neighbor cache (may be stale)"
    assert result.data["records"][2]["mac"] == "Unavailable"
    path = tmp_path / "devices.csv"
    export_devices(result, path)
    with path.open() as file:
        rows = list(csv.DictReader(file))
    assert len(rows) == 4 and rows[0]["observed_at"] == result.collected_at


def test_runner_permission_dependency_timeout_and_failure(monkeypatch):
    with pytest.raises(ValidationError, match="permission"):
        scan_devices("192.168.1.0/24")
    monkeypatch.setattr("cyberintel.wifi_scan.shutil.which", lambda _: None)
    with pytest.raises(ValidationError, match="Nmap is required"):
        scan_devices("192.168.1.0/24", True)
    monkeypatch.setattr("cyberintel.wifi_scan.shutil.which", lambda _: "nmap")
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("nmap", 120)
    monkeypatch.setattr("cyberintel.wifi_scan.subprocess.run", timeout)
    with pytest.raises(ValidationError, match="120 seconds"):
        scan_devices("192.168.1.0/24", True)
    monkeypatch.setattr("cyberintel.wifi_scan.subprocess.run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 1))
    with pytest.raises(ValidationError, match="failed"):
        scan_devices("192.168.1.0/24", True)


def test_ui_save_restore_export_and_case_switch(session, monkeypatch, tmp_path):
    mock_scan(monkeypatch)
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(session.store.home), session)
    case = session.create_case("Wi-Fi discovery fixture")
    window.reload_cases(case)
    monkeypatch.setattr(window, "start_job", lambda label, task, done: done(task()))
    monkeypatch.setattr("cyberintel.ui.local_networks", lambda: [{"network": "192.168.1.0/24", "interface": "wlan0", "ip": "192.168.1.3"}])
    try:
        window.detect_wifi_networks()
        assert window.wifi_subnet.currentText() == "192.168.1.0/24"
        with pytest.raises(ValidationError, match="permission"):
            window.run_wifi_scan()
        window.wifi_authorized.setChecked(True)
        window.run_wifi_scan()
        assert "4 discovered devices" in window.wifi_controls["status"].text()
        findings = session.rows("findings", case)
        assert len(findings) == 1 and findings[0]["module"] == "wifi"
        window.findings_table.view.selectRow(0)
        window.restore_finding()
        assert window.navigation.currentRow() == 13
        path = tmp_path / "wifi.csv"
        monkeypatch.setattr("cyberintel.ui.QFileDialog.getSaveFileName", lambda *a, **k: (str(path), ""))
        window.export_wifi_csv()
        assert path.is_file()
        export_csv(session, case, tmp_path / "case.csv")
        assert "AA:BB:CC:DD:EE:10" in (tmp_path / "case.csv").read_text()
        evidence = session.store.home / "evidence" / "reserved.csv"
        monkeypatch.setattr("cyberintel.ui.QFileDialog.getSaveFileName", lambda *a, **k: (str(evidence), ""))
        with pytest.raises(ValidationError, match="overwrite"):
            window.export_wifi_csv()
        other = session.create_case("Other case")
        window.reload_cases(other)
        assert "wifi" not in window.last_results
        assert window.wifi_controls["table"].model.rows == []
        assert session.verify_audit()
    finally:
        window.close()
