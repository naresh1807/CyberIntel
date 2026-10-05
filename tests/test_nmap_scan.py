import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication

from cyberintel.config import Config
from cyberintel.models import ValidationError
from cyberintel.nmap_scan import parse_scan, scan_arguments, scan_ips
from cyberintel.ui import MainWindow

XML = b'''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun version="7.95"><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><extraports state="closed" count="99"/><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Example server" version="1.2" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:example:server:1.2</cpe></service><script id="vulners" output="Potential CVE match"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'''


@pytest.mark.parametrize("target", ["--script=all", "example.com", "127.0.0.1/24", "0.0.0.0", "224.0.0.1", "127.0.0.1,::1", ""])
def test_reject_bad_targets(target):
    with pytest.raises(ValidationError):
        scan_arguments(target)


@pytest.mark.parametrize("ports", ["0", "65536", "1-2000", "443 --script all", "80;whoami", "100-20"])
def test_reject_bad_ports(ports):
    with pytest.raises(ValidationError):
        scan_arguments("127.0.0.1", ports)


def test_arguments_and_parser():
    args, targets = scan_arguments("::1,::1", "443,80,8000-8001", True)
    assert targets == ["::1"] and "-6" in args
    assert args[args.index("-p") + 1] == "80,443,8000,8001"
    assert args[-2:] == ["--script", "vulners"]
    data = parse_scan(XML)
    assert data["records"][0]["version"] == "1.2"
    assert data["records"][0]["port"] == 443
    assert data["records"][0]["script_findings"][0]["id"] == "vulners"
    assert data["hosts"][0]["port_summary"][0]["count"] == "99"
    with pytest.raises(ValidationError):
        parse_scan(XML.replace(b'exit="success"', b'exit="error"'))
    with pytest.raises(ValidationError):
        parse_scan(b'<!ENTITY x "bad"><nmaprun/>')


def test_runner_missing_permission_dependency_and_timeout(monkeypatch):
    with pytest.raises(ValidationError, match="permission"):
        scan_ips("127.0.0.1")
    monkeypatch.setattr("cyberintel.nmap_scan.shutil.which", lambda _: None)
    with pytest.raises(ValidationError, match="not installed"):
        scan_ips("127.0.0.1", authorized=True)
    monkeypatch.setattr("cyberintel.nmap_scan.shutil.which", lambda _: "nmap")
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("nmap", 180)
    monkeypatch.setattr("cyberintel.nmap_scan.subprocess.run", timeout)
    with pytest.raises(ValidationError, match="time limit"):
        scan_ips("127.0.0.1", authorized=True)


def test_runner_ui_and_case_persistence(monkeypatch, session):
    monkeypatch.setattr("cyberintel.nmap_scan.shutil.which", lambda _: "nmap")
    def run(args, **kwargs):
        assert kwargs["shell"] is False
        assert args[-1] == "127.0.0.1"
        Path(args[args.index("-oX") + 1]).write_bytes(XML)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr("cyberintel.nmap_scan.subprocess.run", run)
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(session.store.home), session)
    case = session.create_case("Nmap test", "Authorized localhost")
    window.reload_cases()
    window.case_selector.setCurrentIndex(window.case_selector.findData(case))
    window.nmap_targets.setText("127.0.0.1")
    window.nmap_authorized.setChecked(True)
    monkeypatch.setattr(window, "start_job", lambda label, task, done: done(task()))
    window.run_nmap_scan()
    assert window.nmap_controls["table"].model.rows[0]["product"] == "Example server"
    assert window.last_results["nmap"].data["external_disclosure"] == "None"
    assert session.rows("findings", case)[0]["module"] == "nmap"
    window.close()
