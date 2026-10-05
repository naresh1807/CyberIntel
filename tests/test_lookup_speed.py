import copy
import threading
import time

import httpx
import pytest
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QThreadPool

from cyberintel.config import Config
from cyberintel.connectors import Collector
from cyberintel.ui import MainWindow


def test_primary_outage_switches_without_retries(session):
    primary = []
    def handler(request):
        if request.url.host == "crt.sh":
            primary.append(request)
            assert request.extensions["timeout"]["read"] <= 8
            return httpx.Response(502)
        return httpx.Response(200, json=[])
    collector = Collector(Config(session.store.home), session.store,
                          transport=httpx.MockTransport(handler), sleeper=lambda _: None)
    assert "Cert Spotter" in collector.collect("ct", "example.com").source
    assert len(primary) == 1


@pytest.mark.parametrize("key", ["subdomains", "osint"])
def test_names_visible_before_dns_finishes_and_saved_once(session, monkeypatch, key):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(session.store.home), session)
    case = session.create_case("Progressive result test")
    window.reload_cases()
    window.case_selector.setCurrentIndex(window.case_selector.findData(case))
    window.collector = Collector(Config(session.store.home), session.store,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[{"name_value": "www.example.com"}])), sleeper=lambda _: None)
    release = threading.Event()
    def slow_dns(result):
        assert release.wait(5), "test did not release DNS job"
        result = copy.deepcopy(result)
        row = result.data["records"][0]
        row.update(ipv4=["192.0.2.10"], ipv4_status="resolved", dns_status="resolved")
        return result
    monkeypatch.setattr("cyberintel.ui.enrich_subdomains", slow_dns)
    try:
        if key == "subdomains":
            window.subdomain_target.setText("example.com")
            window.run_subdomain_discovery()
        else:
            controls = window.osint_controls
            controls["operation"].setCurrentIndex(controls["operation"].findData("ct"))
            controls["target"].setText("example.com")
            window.run_collection(key)
        deadline = time.monotonic() + 3
        while key not in window.last_results and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(.01)
        assert window.busy
        assert getattr(window, key + "_controls")["table"].model.rows[0]["subdomain"] == "www.example.com"
        assert not session.rows("findings", case)
        assert not window.case_selector.isEnabled()
        release.set()
        deadline = time.monotonic() + 3
        while window.busy and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(.01)
        assert not window.busy
        assert window.last_results[key].data["records"][0]["ipv4"] == ["192.0.2.10"]
        assert len(session.rows("findings", case)) == 1
    finally:
        release.set()
        QThreadPool.globalInstance().waitForDone()
        app.processEvents()
        window.close()
