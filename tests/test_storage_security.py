import sqlite3

import pytest

from cyberintel.models import AccessDenied, Result, ValidationError
from cyberintel.security import Vault


def test_authentication_and_roles(session):
    session.add_user("viewer", "viewer-password-long", "viewer")
    viewer = session.store.login("viewer", "viewer-password-long")
    assert viewer.rows("cases") == []
    with pytest.raises(AccessDenied):
        viewer.create_case("not permitted")
    with pytest.raises(AccessDenied):
        viewer.save_finding("missing", "OSINT", Result("source", "url", "query", {}))
    with pytest.raises(AccessDenied):
        viewer.rows("users")
    with pytest.raises(AccessDenied):
        session.store.bootstrap("another", "another-password-long")


def test_login_lockout(session):
    for _ in range(5):
        with pytest.raises(AccessDenied):
            session.store.login("admin", "wrong")
    with pytest.raises(AccessDenied, match="locked"):
        session.store.login("admin", "test-password-long")
    with session.store.connection() as db:
        assert db.execute("SELECT failures FROM users WHERE name='admin'").fetchone()[0] == 5


def test_evidence_copy_hash_and_tamper(session, examples):
    identifier = session.create_case("Synthetic investigation")
    session.add_evidence(identifier, examples / "synthetic_cdr.csv", "Test fixture", "2026-10-01T00:00:00Z", "synthetic")
    assert session.verify_evidence(identifier)[0]["valid"]
    evidence = session.rows("evidence", identifier)[0]
    from pathlib import Path
    Path(evidence["path"]).write_text("tampered")
    assert not session.verify_evidence(identifier)[0]["valid"]
    assert session.verify_audit()
    with session.store.connection() as db:
        db.execute("UPDATE audit SET detail='tampered' WHERE id=1")
    assert not session.verify_audit()


def test_bad_evidence_does_not_create_record(session, examples):
    identifier = session.create_case("Case")
    with pytest.raises(ValidationError, match="timezone"):
        session.add_evidence(identifier, examples / "synthetic_cdr.csv", "fixture", "2026-10-01T00:00:00")
    assert not session.rows("evidence", identifier)


def test_vault_encrypted_and_wrong_password(tmp_path):
    path = tmp_path / "vault.enc"
    vault = Vault(path, "vault-password-long")
    vault.save({"hibp": "secret-api-key"})
    assert b"secret-api-key" not in path.read_bytes()
    assert Vault(path, "vault-password-long").get("hibp") == "secret-api-key"
    with pytest.raises(ValidationError):
        Vault(path, "wrong-password-long")
