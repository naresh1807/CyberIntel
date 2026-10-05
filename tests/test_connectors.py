import json

import httpx
import pytest

from cyberintel.config import Config
from cyberintel.connectors import Collector, domain, email, indicator


def collector(session, handler, keys=None):
    return Collector(Config(session.store.home), session.store, keys=keys,
                     transport=httpx.MockTransport(handler), sleeper=lambda _: None)


def test_ct_cache_and_stale_fallback(session):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=[{"name_value": "www.example.com\n*.example.com\nevil.org", "id": 1}])
    client = collector(session, handler)
    first = client.collect("ct", "example.com")
    assert first.status == "live"
    assert first.data["subdomains"] == ["example.com", "www.example.com"]
    assert client.collect("ct", "example.com").status == "cached"
    assert len(calls) == 1
    client.transport = httpx.MockTransport(lambda _: httpx.Response(503))
    stale = client.collect("ct", "example.com", force=True)
    assert stale.status == "cached" and stale.freshness == "stale"
    assert stale.collected_at == first.collected_at


def test_rate_limit_retries(session):
    attempts = []
    def handler(request):
        attempts.append(1)
        return httpx.Response(429, headers={"Retry-After": "0"}) if len(attempts) == 1 else httpx.Response(200, json=[])
    result = collector(session, handler).collect("hibp_catalog")
    assert result.status == "live" and len(attempts) == 2


def test_long_retry_after_is_not_ignored(session):
    result = collector(session, lambda _: httpx.Response(429, headers={"Retry-After": "120"})).collect("hibp_catalog")
    assert result.status == "unavailable" and "120" in result.error


def test_missing_credentials_not_empty_exposure(session):
    result = collector(session, lambda _: pytest.fail("must not send")).collect("hibp_email", "person@example.com")
    assert result.status == "unavailable"
    assert result.data is None


def test_hibp_404_is_empty_and_domain_aliases_not_stored(session):
    def handler(request):
        assert request.headers["hibp-api-key"] == "key"
        if "/breachedaccount/" in str(request.url):
            return httpx.Response(404)
        return httpx.Response(200, json={"private.person": ["Adobe", "LinkedIn"], "second.person": ["Adobe"]})
    client = collector(session, handler, {"hibp": "key"})
    assert client.collect("hibp_email", "person@example.com").data == []
    result = client.collect("hibp_domain", "example.com")
    assert result.data["breach_counts"] == {"Adobe": 2, "LinkedIn": 1}
    assert "private.person" not in json.dumps(result.to_dict())


def test_authenticated_redirect_rejected(session):
    client = collector(session, lambda _: httpx.Response(302, headers={"Location": "https://evil.example/key"}), {"hibp": "key"})
    assert client.collect("hibp_email", "person@example.com").status == "unavailable"


def test_urlhaus_metadata_only_and_severity(session):
    def handler(request):
        assert request.method == "POST"
        assert request.headers["Auth-Key"] == "key"
        return httpx.Response(200, json={"query_status": "ok", "url": "http://example.com/bad", "url_status": "online", "threat": "malware_download", "payloads": [{"urlhaus_download": "forbidden"}]})
    result = collector(session, handler, {"urlhaus": "key"}).collect("urlhaus", "http://example.com/bad")
    assert result.data["severity"] == "high"
    assert "payloads" not in json.dumps(result.to_dict())


def test_validation():
    assert domain("Example.COM.") == "example.com"
    assert indicator("2001:4860:4860::8888")[0] == "IPv6"
    for value in ["https://example.com", "localhost", "../example.com"]:
        with pytest.raises(ValueError):
            domain(value)
    with pytest.raises(ValueError):
        email("bad@example.com/path")


def test_private_http_target_rejected(monkeypatch):
    from cyberintel.connectors import public_address
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(ValueError, match="public"):
        public_address("example.com")


def test_website_metadata_parser_no_script_execution(session):
    body = '<html><title>Example &amp; Public</title><meta name="description" content="Public metadata"><script>doNotExecute()</script></html>'
    client = collector(session, lambda _: httpx.Response(200, text=body, headers={"content-type": "text/html", "server": "test"}))
    result = client.collect("website", "example.com")
    assert result.data["title"] == "Example & Public"
    assert result.data["meta"]["description"] == "Public metadata"
    assert "doNotExecute" not in json.dumps(result.to_dict())


def test_otx_indicator_request_and_rationale(session):
    def handler(request):
        assert request.headers["X-OTX-API-KEY"] == "key"
        assert "/indicators/IPv4/8.8.8.8/general" in str(request.url)
        return httpx.Response(200, json={"pulse_info": {"count": 2}})
    result = collector(session, handler, {"otx": "key"}).collect("otx", "8.8.8.8")
    assert result.data["severity"] == "medium"
    assert "unverified" in result.data["rationale"]


def test_cache_isolated_when_api_key_changes(session):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=[])
    client = collector(session, handler, {"hibp": "first-key"})
    assert client.collect("hibp_email", "person@example.com").status == "live"
    client.keys = {"hibp": "different-key"}
    assert client.collect("hibp_email", "person@example.com").status == "live"
    assert len(requests) == 2


def test_response_bounds(session):
    client = collector(session, lambda _: httpx.Response(200, content=b"x" * (8 * 1024 * 1024 + 1)))
    result = client.collect("ct", "example.com")
    assert result.status == "unavailable" and "8 MiB" in result.error
