import httpx
import pytest

from cyberintel.config import Config
from cyberintel.connectors import Collector
from cyberintel.subdomains import discover_subdomains


def client(session, handler):
    return Collector(Config(session.store.home), session.store,
                     transport=httpx.MockTransport(handler), sleeper=lambda _: None)


def test_502_fallback_pagination_scope_wildcards_and_cache(session):
    calls = []
    def handler(request):
        calls.append(request)
        if request.url.host == "crt.sh":
            return httpx.Response(502)
        assert request.url.host == "api.certspotter.com"
        assert request.url.params["include_subdomains"] == "true"
        if "after" not in request.url.params:
            return httpx.Response(200, json=[{"id": "cursor/1", "dns_names": ["example.com", "www.example.com", "*.dev.example.com", "evil-example.com"]}])
        assert request.url.params["after"] == "cursor/1"
        return httpx.Response(200, json=[])
    collector = client(session, handler)
    result = discover_subdomains(collector, "example.com")
    assert result.status == "live" and "Cert Spotter" in result.source
    assert result.data["subdomains"] == ["www.example.com"]
    assert result.data["wildcard_patterns"] == ["*.dev.example.com"]
    assert not result.data["truncated"]
    assert "502" in result.data["provider_errors"]["crt.sh"]
    before = len(calls)
    assert discover_subdomains(collector, "example.com").status == "cached"
    assert len(calls) == before


def test_primary_success_does_not_call_fallback(session):
    def handler(request):
        assert request.url.host == "crt.sh"
        return httpx.Response(200, json=[])
    assert client(session, handler).collect("ct", "example.com").data["concrete_names"] == []


@pytest.mark.parametrize("payload", [{"error": "unavailable"}, [{"dns_names": "bad"}], [{"dns_names": [None]}]])
def test_malformed_fallback_unavailable(session, payload):
    def handler(request):
        return httpx.Response(502) if request.url.host == "crt.sh" else httpx.Response(200, json=payload)
    result = client(session, handler).collect("ct", "example.com")
    assert result.status == "unavailable" and result.data is None
    assert "crt.sh" in result.error and "Malformed Cert Spotter" in result.error


def test_later_page_failure_keeps_partial_names(session):
    def handler(request):
        if request.url.host == "crt.sh":
            return httpx.Response(502)
        if "after" in request.url.params:
            return httpx.Response(429, headers={"Retry-After": "120"})
        return httpx.Response(200, json=[{"id": "1", "dns_names": ["www.example.com"]}])
    result = client(session, handler).collect("ct", "example.com")
    assert result.data["truncated"] and result.data["concrete_names"] == ["www.example.com"]
    assert "120" in result.data["warnings"][0]


def test_page_limit_and_dual_failure_stale_cache(session):
    def handler(request):
        if request.url.host == "crt.sh":
            return httpx.Response(502)
        cursor = int(request.url.params.get("after", "0")) + 1
        return httpx.Response(200, json=[{"id": str(cursor), "dns_names": [f"host{cursor}.example.com"]}])
    collector = client(session, handler)
    first = collector.collect("ct", "example.com")
    assert first.data["truncated"] and first.data["certificate_count"] == 5
    collector.transport = httpx.MockTransport(lambda _: httpx.Response(503))
    stale = collector.collect("ct", "example.com", force=True)
    assert stale.status == "cached" and stale.freshness == "stale"
    assert stale.collected_at == first.collected_at
    assert "crt.sh" in stale.error and "Cert Spotter" in stale.error
