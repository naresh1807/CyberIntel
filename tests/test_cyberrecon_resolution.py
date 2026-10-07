import socket

import pytest

from cyberintel.connectors import public_address
from cyberrecon.network import ScopedHTTP
from cyberrecon.scope import Scope


def test_provider_resolution_uses_absolute_name(monkeypatch):
    requested = []
    def resolve(host, *args, **kwargs):
        requested.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    monkeypatch.setattr("socket.getaddrinfo", resolve)
    assert public_address("example.org") == "8.8.8.8"
    assert requested == ["example.org."]
    public_address("8.8.8.8")
    assert requested[-1] == "8.8.8.8"


def test_native_resolution_uses_absolute_name(monkeypatch):
    requested = []
    def resolve(host, *args, **kwargs):
        requested.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    monkeypatch.setattr("socket.getaddrinfo", resolve)
    with pytest.raises(ValueError, match="OUT OF SCOPE"):
        ScopedHTTP(lambda: Scope(("example.org",))).fetch("https://example.org/")
    assert requested == ["example.org."]
