"""Regression cases from the October repository review; no live providers."""
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import dns.resolver
import httpx
import pytest
from PySide6.QtWidgets import QApplication

from cyberintel.analysis import analyze_geo, analyze_pcap, read_table
from cyberintel.config import Config
from cyberintel.connectors import Collector, domain, indicator
from cyberintel.models import Result, ValidationError
from cyberintel.nmap_scan import parse_scan
from cyberintel.subdomains import verify_subdomains
from cyberintel.ui import MainWindow


def client(session, handler):
    return Collector(Config(session.store.home), session.store,
                     keys={"hibp": "fixture", "urlhaus": "fixture"},
                     transport=httpx.MockTransport(handler), sleeper=lambda _: None)


def test_final_attempt_preserves_provider_cooldown(session):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "120"})
    collector = client(session, handler)
    with pytest.raises(RuntimeError, match="120"):
        collector._request("GET", "https://example.com", attempts=1)
    with pytest.raises(RuntimeError, match="Rate limited"):
        collector._request("GET", "https://example.com", attempts=1)
    assert len(calls) == 1


def test_future_cache_timestamp_requires_refresh(session):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=[])
    collector = client(session, handler)
    result = collector.collect("hibp_catalog")
    result.collected_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    with session.store.connection() as db:
        db.execute("UPDATE cache SET result=?", (json.dumps(result.to_dict()),))
    assert collector.collect("hibp_catalog").status == "live"
    assert len(calls) == 2


def test_unicode_top_level_domain_and_invalid_idna():
    assert domain("例子.中国") == "xn--fsqu00a.xn--fiqs8s"
    with pytest.raises(ValidationError):
        domain("a" * 64 + ".com")


@pytest.mark.parametrize("value", ["https://example.com:bad/path", "https://example.com:65536/", "https://example.com/\npath"])
def test_invalid_indicator_url(value):
    with pytest.raises(ValidationError):
        indicator(value)


def test_missing_certificate_names_are_unavailable(session):
    collector = client(session, lambda _: httpx.Response(200, json=[{}]))
    result = collector.collect("ct", "example.com")
    assert result.status == "unavailable" and "Malformed" in result.error


def test_malformed_hibp_dates_are_unavailable(session):
    result = client(session, lambda _: httpx.Response(200, json=[
        {"Name": "One", "BreachDate": None}, {"Name": "Two", "BreachDate": "2020-01-01"}
    ])).collect("hibp_catalog")
    assert result.status == "unavailable" and "Malformed" in result.error


def test_malformed_urlhaus_status_does_not_raise(session):
    result = client(session, lambda _: httpx.Response(200, json={"query_status": []})).collect("urlhaus", "example.com")
    assert result.status == "unavailable"


def test_case_insensitive_content_type(session):
    result = client(session, lambda _: httpx.Response(200, text='<title>Test</title>',
        headers={"Content-Type": "Text/HTML; charset=UTF-8"})).collect("website", "example.com")
    assert result.status == "live" and result.data["title"] == "Test"


def test_dns_lookup_is_absolute(session, monkeypatch):
    queries = []
    class Resolver:
        nameservers = ["192.0.2.1"]
        def resolve(self, host, kind, *, search):
            queries.append((host, search))
            raise dns.resolver.NoAnswer()
    monkeypatch.setattr("cyberintel.connectors.dns.resolver.Resolver", Resolver)
    result = client(session, lambda _: pytest.fail("No HTTP request expected")).collect("dns", "example.com")
    assert result.status == "live"
    assert queries == [("example.com.", False)] * 7


def test_inferred_import_keeps_synthetic_rows(tmp_path):
    path = tmp_path / "gps.csv"
    path.write_text("latitude,longitude,timestamp,source,record_kind\n"
                    "1,2,2026-10-01T00:00:00Z,fixture,synthetic\n"
                    "3,4,2026-10-01T00:00:00Z,fixture,actual\n")
    result = analyze_geo(path, data_kind="inferred")
    assert [row["record_kind"] for row in result.data["records"]] == ["synthetic", "inferred"]


@pytest.mark.parametrize("kind", ["csv", "xlsx"])
def test_blank_headers_rejected(tmp_path, kind):
    path = tmp_path / ("bad." + kind)
    if kind == "csv":
        path.write_text("named,\n1,2\n")
    else:
        import openpyxl
        workbook = openpyxl.Workbook()
        workbook.active.append(["named", None])
        workbook.active.append([1, 2])
        workbook.save(path)
        workbook.close()
    with pytest.raises(ValidationError, match="nonempty"):
        read_table(path)


@pytest.mark.parametrize("output", [b'bad,row\n',
    b'1,nan,71,DNS,192.0.2.1,,192.0.2.2,,,,,53,example.com,,\n',
    b'1,1790816400,-71,DNS,192.0.2.1,,192.0.2.2,,,,,53,example.com,,\n'])
def test_malformed_capture_output_refuses_analysis(tmp_path, monkeypatch, output):
    path = tmp_path / "test.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1")
    monkeypatch.setattr("cyberintel.analysis.shutil.which", lambda _: "tshark")
    def run(command, stdout, **kwargs):
        stdout.write(output)
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr("cyberintel.analysis.subprocess.run", run)
    with pytest.raises(ValidationError, match="TShark returned"):
        analyze_pcap(path)


def test_capture_launch_error_is_actionable(tmp_path, monkeypatch):
    path = tmp_path / "test.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1")
    monkeypatch.setattr("cyberintel.analysis.shutil.which", lambda _: "tshark")
    def fail(*args, **kwargs):
        raise PermissionError()
    monkeypatch.setattr("cyberintel.analysis.subprocess.run", fail)
    with pytest.raises(ValidationError, match="launch"):
        analyze_pcap(path)


def test_analysis_rejects_evidence_changed_during_processing(session, examples, monkeypatch):
    app = QApplication.instance() or QApplication([])
    case = session.create_case("Integrity regression")
    session.add_evidence(case, examples / "synthetic_cdr.csv", "fixture", "2026-10-01T00:00:00Z", "synthetic")
    window = MainWindow(Config(session.store.home), session)
    window.reload_cases(case)
    from cyberintel.analysis import analyze_cdr
    def changed(path, kind):
        result = analyze_cdr(path, kind)
        with open(path, "a") as file:
            file.write("\n")
        return result
    monkeypatch.setattr("cyberintel.ui.analyze_cdr", changed)
    monkeypatch.setattr(window, "start_job", lambda label, task, done: done(task()))
    try:
        with pytest.raises(ValidationError, match="changed during"):
            window.run_analysis("cdr")
        assert not session.rows("findings", case)
    finally:
        window.close()


def test_concurrent_workspace_open_preserves_audit_chain(session):
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: session.store.open_workspace(), range(20)))
    assert session.verify_audit()


def test_watch_requires_existing_case(session):
    with pytest.raises(ValidationError, match="existing case"):
        session.add_watch("missing", "domain", "example.com")


def test_invalid_acquisition_date_is_actionable(session, examples):
    case = session.create_case("Bad date")
    with pytest.raises(ValidationError, match="valid timestamp"):
        session.add_evidence(case, examples / "synthetic_cdr.csv", "fixture", "invalid")
    assert not session.rows("evidence", case)


@pytest.mark.parametrize("port", ["", "bad", "0", "65536"])
def test_invalid_nmap_port_is_actionable(port):
    payload = f'<nmaprun><host><ports><port portid="{port}"/></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'.encode()
    with pytest.raises(ValidationError, match="port number"):
        parse_scan(payload)


def test_dns_socket_error_keeps_other_address_family():
    class Resolver:
        nameservers = ["192.0.2.1"]
        def resolve(self, host, kind, **kwargs):
            if kind == "A":
                raise OSError("Network unreachable")
            raise dns.resolver.NoAnswer()
    result = Result("fixture", "fixture", "example.com", {"records": [{"subdomain": "www.example.com"}]})
    checked = verify_subdomains(result, ["www.example.com"], Resolver)
    row = checked.data["records"][0]
    assert row["ipv4_status"] == "lookup failed"
    assert row["ipv6_status"] == "no record"
    assert row["dns_status"] == "error"


@pytest.mark.parametrize("payload", [{}, {"pulse_info": {}}])
def test_missing_otx_association_data_is_unavailable(session, payload):
    collector = client(session, lambda _: httpx.Response(200, json=payload))
    collector.keys["otx"] = "fixture"
    result = collector.collect("otx", "example.com")
    assert result.status == "unavailable" and "Malformed" in result.error


@pytest.mark.parametrize("setting", ["cache_seconds", "timeout_seconds"])
def test_overflowing_configuration_is_actionable(tmp_path, setting):
    (tmp_path / "config.json").write_text('{"' + setting + '": 1e999}')
    with pytest.raises(ValidationError, match="Invalid configuration"):
        Config.load(str(tmp_path))


def test_dns_network_error_is_unavailable(session, monkeypatch):
    def fail():
        raise OSError("Network unavailable")
    monkeypatch.setattr("cyberintel.connectors.dns.resolver.Resolver", fail)
    result = client(session, lambda _: pytest.fail("No HTTP request expected")).collect("dns", "example.com")
    assert result.status == "unavailable" and "Network unavailable" in result.error
