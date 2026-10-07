import copy
import json

import dns.resolver
import httpx
import pytest

from cyberintel.analysis import analyze_cdr, analyze_geo, location_map, relationship_graph
from cyberintel.config import Config
from cyberintel.connectors import Collector
from cyberintel.models import Result


def collector(session, handler, keys=None):
    return Collector(Config(session.store.home), session.store, keys or {},
                     transport=httpx.MockTransport(handler), sleeper=lambda _: None)


def test_public_cache_survives_credentials_and_target_format_changes(session):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=[{"name_value": "www.example.com"}])
    client = collector(session, handler, {"otx": "old"})
    assert client.collect("ct", " Example.COM. ").status == "live"
    client.keys = {"otx": "new", "hibp": "new"}
    assert client.collect("ct", "example.com").status == "cached"
    assert len(calls) == 1
    client.transport = httpx.MockTransport(lambda _: httpx.Response(503))
    stale = client.collect("ct", "EXAMPLE.com", force=True)
    assert stale.status == "cached" and stale.freshness == "stale"
    assert stale.data["concrete_names"] == ["www.example.com"]


def test_privileged_cache_only_changes_for_its_provider_key(session):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=[])
    client = collector(session, handler, {"hibp": "old", "otx": "one"})
    assert client.collect("hibp_email", "Person@Example.COM").status == "live"
    client.keys["otx"] = "two"
    assert client.collect("hibp_email", "Person@example.com").status == "cached"
    client.keys["hibp"] = "new"
    assert client.collect("hibp_email", "Person@example.com").status == "live"
    assert len(calls) == 2


def test_catalog_never_sends_unneeded_subscription_key(session):
    def handler(request):
        assert "hibp-api-key" not in request.headers
        return httpx.Response(200, json=[])
    assert collector(session, handler, {"hibp": "secret"}).collect("hibp_catalog").status == "live"


def test_dns_retains_answer_after_another_family_socket_error(session, monkeypatch):
    class Answer:
        def to_text(self):
            return "192.0.2.10"
    class Resolver:
        nameservers = ["192.0.2.1"]
        def resolve(self, name, kind, **kwargs):
            if kind == "A":
                return [Answer()]
            if kind == "AAAA":
                raise OSError("IPv6 unavailable")
            raise dns.resolver.NoAnswer()
    monkeypatch.setattr("cyberintel.connectors.dns.resolver.Resolver", Resolver)
    result = collector(session, lambda _: pytest.fail("No HTTP")).collect("dns", "example.com")
    assert result.status == "live"
    assert result.data["records"]["A"] == ["192.0.2.10"]
    assert result.data["errors"]["AAAA"] == "OSError"


@pytest.mark.parametrize("delimiter", [";", "\t"])
def test_cdr_and_geospatial_accept_common_csv_delimiters(examples, tmp_path, delimiter):
    for source, analyze in [("synthetic_cdr.csv", analyze_cdr), ("synthetic_gps.csv", analyze_geo)]:
        path = tmp_path / source
        path.write_text((examples / source).read_text().replace(",", delimiter))
        result = analyze(path, data_kind="synthetic")
        assert result.status == "synthetic" and result.data["file_sha256"]


def test_large_graph_uses_highest_counts_and_keeps_full_data(tmp_path):
    rows = [{"caller": f"{10000 + i}", "callee": "99999", "calls": i + 1} for i in range(2001)]
    result = Result("fixture", "fixture", "fixture", {"relationships": rows, "provenance_kind": "synthetic"}, status="synthetic")
    before = copy.deepcopy(result.to_dict())
    destination = tmp_path / "graph.html"
    relationship_graph(result, destination)
    text = destination.read_text()
    assert "showing 2,000 of 2,001" in text
    assert '"12000"' in text
    assert result.to_dict() == before


def test_large_map_labels_sampling_and_keeps_full_data(tmp_path, monkeypatch):
    result = Result("fixture", "fixture", "fixture", {"records": [
        {"latitude": 1, "longitude": 2, "record_kind": "synthetic", "source": str(i)} for i in range(10001)]})
    # Exercise sample selection without writing ten thousand real JS markers.
    markers = []
    class Marker:
        def __init__(self, *args, **kwargs):
            markers.append(kwargs)
        def add_to(self, map_):
            return self
    monkeypatch.setattr("cyberintel.analysis.folium.CircleMarker", Marker)
    destination = tmp_path / "map.html"
    location_map(result, destination)
    assert len(markers) == 10000
    assert "Sample: 10,000 of 10,001" in destination.read_text()
    assert len(result.data["records"]) == 10001


def test_whitespace_and_friendly_headers_preserve_valid_analysis(tmp_path):
    path = tmp_path / "cdr.csv"
    path.write_text("Caller;Callee;Timestamp;Duration Seconds;Direction\n"
                    " 12345 ; 54321 ; 2026-10-01T00:00:00Z ; 30 ; Outgoing \n")
    result = analyze_cdr(path)
    assert result.data["total_calls"] == 1
    assert result.data["relationships"][0]["caller"] == "12345"
    path = tmp_path / "gps.csv"
    path.write_text("Latitude,Longitude,Timestamp,Source,Record Kind\n"
                    "1,2,2026-10-01T00:00:00Z, fixture , Synthetic \n")
    assert analyze_geo(path).data["records"][0]["record_kind"] == "synthetic"


def test_large_local_network_suggests_bounded_batch(monkeypatch):
    import subprocess
    from cyberintel.wifi_scan import local_networks
    monkeypatch.setattr("cyberintel.wifi_scan.shutil.which", lambda _: "ip")
    payload = [{"ifname": "wlan0", "addr_info": [{"family": "inet", "local": "10.10.3.5", "prefixlen": 16}]}]
    monkeypatch.setattr("cyberintel.wifi_scan.subprocess.run", lambda *a, **k: subprocess.CompletedProcess(a, 0, json.dumps(payload).encode()))
    row = local_networks()[0]
    assert row["network"] == "10.10.3.0/24"
    assert row["detected_network"] == "10.10.0.0/16"
    assert "other batches are not scanned" in row["scope_note"]
