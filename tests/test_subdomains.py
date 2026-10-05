import csv
import json
import time

import dns.resolver
import httpx
import pytest
from PySide6.QtWidgets import QApplication

from cyberintel.config import Config
from cyberintel.connectors import Collector
from cyberintel.models import Result, ValidationError
from cyberintel.subdomains import discover_subdomains, verify_subdomains, enrich_subdomains, export_subdomains
from cyberintel.ui import MainWindow


def client(session, payload):
    return Collector(Config(session.store.home), session.store,
                     transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload)), sleeper=lambda _: None)


def test_discovery_excludes_apex_wildcards_and_out_of_scope(session):
    c = client(session, [{"name_value": "example.com\n*.dev.example.com\nWWW.Example.com.\nwww.example.com\nevil-example.com\nhttps://bad.example.com\na..example.com"}])
    result = discover_subdomains(c, "Example.com")
    assert result.data["subdomains"] == ["www.example.com"]
    assert result.data["wildcard_patterns"] == ["*.dev.example.com"]
    assert result.data["records"][0]["dns_status"] == "not checked"
    assert result.data["records"][0]["observed_at"] == result.collected_at
    assert discover_subdomains(c, "example.com").status == "cached"


def test_empty_discovery_and_malformed_source(session):
    result = discover_subdomains(client(session, []), "example.com")
    assert result.status == "live" and result.data["subdomain_count"] == 0
    bad = discover_subdomains(client(session, {"error": "not records"}), "example.org")
    assert bad.status == "unavailable"


class Answer:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class Resolver:
    nameservers = ["192.0.2.53"]

    def resolve(self, name, record_type, **kwargs):
        if name.startswith("missing."):
            raise dns.resolver.NXDOMAIN()
        if name.startswith("timeout."):
            raise dns.exception.Timeout()
        if name.startswith("empty."):
            raise dns.resolver.NoAnswer()
        return [Answer("192.0.2.10" if record_type == "A" else "2001:db8::10")]


def test_dns_outcomes_do_not_rewrite_collection_time(session, tmp_path):
    names = ["ok.example.com", "missing.example.com", "timeout.example.com", "empty.example.com"]
    original = discover_subdomains(client(session, [{"name_value": "\n".join(names)}]), "example.com")
    checked = verify_subdomains(original, names, Resolver)
    rows = {r["subdomain"]: r for r in checked.data["records"]}
    assert rows["ok.example.com"]["dns_status"] == "resolved"
    assert rows["missing.example.com"]["dns_status"] == "nxdomain"
    assert rows["timeout.example.com"]["dns_status"] == "error"
    assert rows["empty.example.com"]["dns_status"] == "no address records"
    assert rows["ok.example.com"]["ipv6"] == ["2001:db8::10"]
    assert checked.collected_at == original.collected_at
    assert all(r["dns_checked_at"] for r in checked.data["records"])
    assert all(r["dns_status"] == "not checked" for r in original.data["records"])
    path = tmp_path / "names.csv"
    export_subdomains(checked, path, ["ok.example.com"])
    with path.open(encoding="utf-8") as file:
        exported = list(csv.DictReader(file))
    assert len(exported) == 1 and exported[0]["ipv4"] == "192.0.2.10"
    assert exported[0]["source_reference"].startswith("https://crt.sh")


def test_dns_rejects_unknown_names_and_large_batch(session):
    result = discover_subdomains(client(session, [{"name_value": "ok.example.com"}]), "example.com")
    for names in ([], ["evil.org"], [f"n{i}.example.com" for i in range(101)]):
        with pytest.raises(ValidationError):
            verify_subdomains(result, names, Resolver)


def test_stale_source_preserved(session):
    c = client(session, [{"name_value": "ok.example.com"}])
    first = discover_subdomains(c, "example.com")
    c.transport = httpx.MockTransport(lambda _: httpx.Response(503))
    stale = discover_subdomains(c, "example.com", force=True)
    assert stale.status == "cached" and stale.freshness == "stale"
    assert stale.collected_at == first.collected_at and stale.error


def test_legacy_cache_does_not_invent_concrete_names(session):
    c = client(session, [])
    legacy = Result("CT", "https://crt.sh", "example.com", {"subdomains": ["dev.example.com"]})
    import hashlib
    scope = hashlib.sha256(json.dumps(c.keys, sort_keys=True).encode()).hexdigest()
    key = hashlib.sha256(json.dumps(["ct", "example.com", scope, c.config.endpoints], sort_keys=True).encode()).hexdigest()
    c.store.cache_put(key, legacy)
    c.transport = httpx.MockTransport(lambda _: httpx.Response(503))
    result = discover_subdomains(c, "example.com")
    assert result.status == "unavailable" and result.data is None


def test_subdomain_ui_collection_filter_and_case_save(session, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    case = session.create_case("Subdomain test")
    window.reload_cases(case)
    window.collector = client(session, [{"name_value": "www.example.com\nmail.example.com"}])
    monkeypatch.setattr("cyberintel.subdomains.dns.resolver.Resolver", Resolver)
    window.subdomain_target.setText("example.com")
    window.run_subdomain_discovery()
    deadline = time.monotonic() + 5
    while window.busy and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.01)
    assert not window.busy
    window.subdomains_controls["table"].filter.setText("mail.")
    assert window.filtered_subdomain_names() == ["mail.example.com"]
    saved = session.rows("findings", case)[0]
    assert saved["module"] == "subdomains"
    assert json.loads(saved["result"])["data"]["subdomain_count"] == 2
    assert window.last_results["subdomains"].data["records"][0]["ipv4"] == ["192.0.2.10"]
    assert window.last_results["subdomains"].data["records"][0]["ipv6"] == ["2001:db8::10"]
    window.close()


def test_missing_ipv6_has_explicit_label(session):
    from cyberintel.ui import DataTable
    class IPv4Only(Resolver):
        def resolve(self, name, record_type, **kwargs):
            assert name.endswith(".") and kwargs["search"] is False
            if record_type == "AAAA":
                raise dns.resolver.NoAnswer()
            return [Answer("192.0.2.10")]
    result = enrich_subdomains(discover_subdomains(client(session, [{"name_value": "www.example.com"}]), "example.com"), IPv4Only)
    row = result.data["records"][0]
    assert row["ipv4"] == ["192.0.2.10"] and row["ipv6"] == []
    assert row["ipv6_status"] == "no record"
    app = QApplication.instance() or QApplication([])
    table = DataTable()
    table.set_rows([row])
    assert table.model.columns[:3] == ["subdomain", "ipv4", "ipv6"]
    assert table.model.index(0, 1).data() == "192.0.2.10"
    assert table.model.index(0, 2).data() == "No AAAA record"


def test_auto_dns_batch_bound_and_remaining_status(session):
    names = [f"host{i:03d}.example.com" for i in range(101)]
    result = enrich_subdomains(discover_subdomains(client(session, [{"name_value": "\n".join(names)}]), "example.com"), Resolver)
    assert result.data["last_dns_batch_count"] == 100
    assert result.data["auto_dns_unchecked_count"] == 1
    assert result.data["records"][-1]["dns_status"] == "not checked"


def test_bad_resolver_configuration_keeps_discovered_names(session):
    def bad_factory():
        raise dns.resolver.NoResolverConfiguration()
    result = enrich_subdomains(discover_subdomains(client(session, [{"name_value": "www.example.com"}]), "example.com"), bad_factory)
    row = result.data["records"][0]
    assert row["subdomain"] == "www.example.com" and row["dns_status"] == "error"
    assert row["ipv4_status"] == row["ipv6_status"] == "lookup failed"


def test_osint_ct_also_displays_addresses(session, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Config(tmp_path), session)
    monkeypatch.setattr("cyberintel.subdomains.dns.resolver.Resolver", Resolver)
    window.collector = client(session, [{"name_value": "www.example.com"}])
    controls = window.osint_controls
    controls["operation"].setCurrentIndex(controls["operation"].findData("ct"))
    controls["target"].setText("example.com")
    window.run_collection("osint")
    deadline = time.monotonic() + 5
    while window.busy and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.01)
    assert not window.busy
    assert controls["table"].model.columns[:3] == ["subdomain", "ipv4", "ipv6"]
    assert controls["table"].model.index(0, 2).data() == "2001:db8::10"
    window.close()
