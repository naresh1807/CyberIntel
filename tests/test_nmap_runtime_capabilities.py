import importlib.util
from pathlib import Path
import struct
import pytest


spec = importlib.util.spec_from_file_location('nmap_runtime', Path(__file__).resolve().parents[1] / 'scripts/qualify_nmap_runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def test_effective_file_capabilities_exceed_container_bounding_set():
    requested = (1 << 10) | (1 << 12) | (1 << 13)
    for revision in (0x02000000, 0x03000000):
        data = struct.pack('<5I', revision | 1, requested, 0, 0, 0)
        if revision == 0x03000000:
            data += struct.pack('<I', 1000)
        assert runtime.missing_capabilities(data, requested & ~(1 << 12)) == 1 << 12
        assert runtime.missing_capabilities(data, requested) == 0


def test_no_effective_capability_conflict_is_not_repaired():
    assert runtime.missing_capabilities(b'', 0) == 0
    assert runtime.missing_capabilities(struct.pack('<5I', 0x02000000, 1 << 12, 0, 0, 0), 0) == 0


def test_runtime_fix_refuses_an_unmarked_nonroot_host(monkeypatch):
    monkeypatch.setattr(runtime.os, 'geteuid', lambda: 1000)
    monkeypatch.setattr(runtime.subprocess, 'run', lambda *a, **kw: pytest.fail('Must not execute host commands'))
    with pytest.raises(RuntimeError, match='marked disposable root'):
        runtime.main()
