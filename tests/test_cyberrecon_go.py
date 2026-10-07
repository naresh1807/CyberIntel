from pathlib import Path

import pytest

from cyberrecon.go_worker import resolve_hosts
from cyberrecon.scope import Scope


def test_compiled_worker_python_protocol():
    worker = Path(__file__).resolve().parent.parent / "dist/cyberrecon-dns"
    if not worker.exists():
        pytest.skip("Build Go worker before running the cross-language integration test")
    rows = resolve_hosts(["192.0.2.4"], Scope(("192.0.2.0/24",)))
    assert rows == [{"id": "dns", "host": "192.0.2.4", "addresses": ["192.0.2.4"]}]


def test_worker_rejects_out_of_scope_before_process(monkeypatch):
    monkeypatch.setattr("cyberrecon.go_worker.shutil.which", lambda name: "/fixture/worker")
    calls = []
    monkeypatch.setattr("cyberrecon.go_worker.run_process", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match="OUT OF SCOPE"):
        resolve_hosts(["other.org"], Scope(("example.org",)))
    assert not calls
