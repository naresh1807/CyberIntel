import json

import pytest

from cyberrecon.importers import import_jsonl
from cyberrecon.storage import Repository


@pytest.mark.parametrize("engine,row,kind", [
    ("httpx", {"url": "https://example.org/?token=secret", "status_code": 200, "body": "secret"}, "http"),
    ("katana", {"request": {"endpoint": "https://example.org/api?key=secret"}}, "urls"),
    ("dnsx", {"host": "example.org", "a": ["192.0.2.3"], "txt": ["secret"]}, "dns"),
    ("naabu", {"ip": "192.0.2.3", "port": 443}, "ports"),
])
def test_import(engine, row, kind, tmp_path):
    repo = Repository(tmp_path / "workspace")
    project = repo.create_project("Lab", ["example.org", "192.0.2.3"], authority="Fixture")
    path = tmp_path / "engine.jsonl"
    path.write_text(json.dumps(row) + '\n{"url":"https://other.org/"}\n')
    identifier = import_jsonl(repo, project, "example.org", engine, path)
    result = repo.snapshot(identifier)
    assert len(result[kind]) == 1
    assert "secret" not in json.dumps(result)
    assert result["scan"]["status"] == "partial"
