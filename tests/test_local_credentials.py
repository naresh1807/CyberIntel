from pathlib import Path

import pytest

from cyberintel.models import ValidationError
from cyberintel.output import validate_export_destination
from cyberintel.security import LocalCredentials


def test_direct_credentials_persist_and_clear_without_passphrase(tmp_path):
    path = tmp_path / "api-credentials.json"
    credentials = LocalCredentials(path)
    credentials.save({"otx": "synthetic-secret", "hibp": ""})
    assert LocalCredentials(path).get("otx") == "synthetic-secret"
    credentials.save({})
    assert LocalCredentials(path).values == {}


def test_failed_save_preserves_previous_keys(tmp_path, monkeypatch):
    path = tmp_path / "api-credentials.json"
    credentials = LocalCredentials(path)
    credentials.save({"otx": "old-synthetic-value"})
    before = path.read_bytes()
    def fail(*args):
        raise OSError("Controlled write failure")
    monkeypatch.setattr(Path, "replace", fail)
    with pytest.raises(OSError):
        credentials.save({"otx": "new-synthetic-value"})
    assert credentials.get("otx") == "old-synthetic-value" and path.read_bytes() == before
    assert not list(tmp_path.glob(".cyberintel-credentials-*"))


def test_corrupt_credentials_rejected_and_export_protected(session):
    path = session.store.home / "api-credentials.json"
    path.write_text('{"otx": 1}')
    with pytest.raises(ValidationError):
        LocalCredentials(path)
    with pytest.raises(ValidationError):
        validate_export_destination(session, path)
