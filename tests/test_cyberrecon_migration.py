import json
import sqlite3

import pytest

from cyberrecon.storage import Repository


def test_scope_history_migrates_and_records_replacements(tmp_path):
    repo = Repository(tmp_path)
    project = repo.create_project("Fixture", ["example.org"], authority="Fixture")
    with sqlite3.connect(repo.path) as db:
        db.execute("DROP TABLE scope_history")
        db.execute("PRAGMA user_version=1")
    reopened = Repository(tmp_path)
    assert reopened.scope_history(project)[0]["scope"]["include"] == ["example.org"]
    assert "migration" in reopened.scope_history(project)[0]["reason"]
    reopened.update_scope(project, ["other.org"], ["excluded.other.org"])
    history = reopened.scope_history(project)
    assert history[-1]["scope"]["include"] == ["other.org"]
    with sqlite3.connect(reopened.path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2


def test_invalid_scan_export_has_no_directory_side_effect(tmp_path):
    repo = Repository(tmp_path / "workspace")
    destination = tmp_path / "output"
    with pytest.raises(ValueError):
        repo.export_json("missing-scan", destination)
    assert not destination.exists()
