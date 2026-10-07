import json

from cyberrecon.api import extract
from cyberrecon.scope import Scope


def test_openapi_keeps_names_not_examples():
    response = {"url": "https://example.org/openapi.json", "status_code": 200,
                "headers": {"content-type": "application/json"}, "truncated": False}
    body = json.dumps({"openapi": "3.1.0", "servers": [{"url": "https://other.org/"}, {"url": "/v1"}],
                       "paths": {"/users": {"post": {"parameters": [{"name": "token", "example": "SECRET"}], "security": [{"Bearer": []}]}}}})
    result = extract(response, body, Scope(("example.org",)))
    endpoint = next(row for row in result if row.get("methods"))
    assert endpoint["url"] == "https://example.org/v1/users"
    assert endpoint["methods"] == ["POST"]
    assert endpoint["parameter_names"] == ["token"]
    assert endpoint["declares_security"]
    assert "SECRET" not in json.dumps(result)


def test_auth_surface_is_not_a_vulnerability():
    response = {"url": "https://example.org/private", "status_code": 401,
                "headers": {"www-authenticate": 'Bearer realm="private"'}, "truncated": False}
    result = extract(response, "", Scope(("example.org",)))
    assert result[0]["challenge_scheme"] == "Bearer"
