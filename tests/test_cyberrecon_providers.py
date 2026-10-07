import json

import httpx
import pytest

from cyberrecon.network import ScopedHTTP
from cyberrecon.providers import host_lookup
from cyberrecon.scope import Scope
from cyberrecon.storage import Repository


@pytest.mark.parametrize("provider", ["shodan", "censys"])
def test_provider_normalization_omits_credentials_and_contact_data(tmp_path, monkeypatch, provider):
    repo = Repository(tmp_path)
    project = repo.create_project("Synthetic fixture", ["8.8.8.8"], authority="Mock requests only")
    monkeypatch.setenv("SHODAN_API_KEY", "FAKE_SECRET_API_KEY")
    monkeypatch.setenv("CENSYS_PLATFORM_TOKEN", "FAKE_SECRET_BEARER_TOKEN")
    def handler(request):
        if provider == "shodan":
            assert request.url.params["key"] == "FAKE_SECRET_API_KEY"
            assert request.url.params["minify"] == "true"
            payload = {"ip_str": "8.8.8.8", "ports": [443], "contacts": "PRIVATE_CONTACT"}
        else:
            assert request.headers["authorization"] == "Bearer FAKE_SECRET_BEARER_TOKEN"
            payload = {"result": {"resource": {"ip": "8.8.8.8", "services": [{"port": 443, "transport_protocol": "tcp", "protocol": "HTTPS"}], "whois": "PRIVATE_CONTACT"}}}
        return httpx.Response(200, json=payload)
    identifier = host_lookup(repo, project, "8.8.8.8", provider, transport=httpx.MockTransport(handler))
    snapshot = repo.snapshot(identifier)
    assert snapshot["ports"][0]["port"] == 443
    assert snapshot["ports"][0]["observation_status"] == "HISTORICAL"
    assert "FAKE_SECRET" not in json.dumps(snapshot)
    assert "PRIVATE_CONTACT" not in json.dumps(snapshot)


def test_lookup_checks_scope_before_provider(tmp_path):
    repo = Repository(tmp_path)
    project = repo.create_project("Fixture", ["1.1.1.1"], authority="Mock")
    with pytest.raises(ValueError, match="OUT OF SCOPE"):
        host_lookup(repo, project, "8.8.8.8", "shodan")
    assert repo.scans(project) == []


def test_credentialled_redirect_never_reaches_other_host():
    calls = []
    def handler(request):
        calls.append(request.url.host)
        return httpx.Response(302, headers={"location": "https://other.org/"})
    client = ScopedHTTP(lambda: Scope(("example.org", "other.org")), transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="cannot follow cross-host"):
        client.fetch("https://example.org/", request_headers={"Authorization": "Bearer FAKE_TOKEN"})
    assert calls == ["example.org"]
