import gzip

import httpx
import pytest

from cyberrecon.network import ScopedHTTP
from cyberrecon.scope import Scope


def test_compressed_response_is_decoded_with_bounded_output():
    payload = gzip.compress(b"A" * (2 * 1024 * 1024))
    def handler(request):
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, headers={"content-encoding": "gzip"}, stream=httpx.ByteStream(payload))
    client = ScopedHTTP(lambda: Scope(("example.org",)), transport=httpx.MockTransport(handler))
    result = client.fetch("https://example.org/")
    assert result["truncated"]
    assert result["bytes_read"] == 512 * 1024


def test_missing_redirect_destination():
    client = ScopedHTTP(lambda: Scope(("example.org",)), transport=httpx.MockTransport(lambda req: httpx.Response(302)))
    with pytest.raises(ValueError, match="no destination"):
        client.fetch("https://example.org/")


def test_nonce_and_digest_challenge_values_are_not_retained():
    client = ScopedHTTP(lambda: Scope(("example.org",)), transport=httpx.MockTransport(lambda request:
        httpx.Response(200, headers={"content-security-policy": "script-src 'nonce-SECRET_NONCE'",
                                    "www-authenticate": 'Digest nonce="SECRET_NONCE"'}, text="body")))
    result = client.fetch("https://example.org/")
    assert "SECRET_NONCE" not in str(result)
    assert result["headers"]["www-authenticate"] == "Digest"


def test_tls_verification_cannot_be_disabled():
    with pytest.raises(ValueError, match="cannot be disabled"):
        ScopedHTTP(lambda: Scope(("example.org",)), verify=False)
