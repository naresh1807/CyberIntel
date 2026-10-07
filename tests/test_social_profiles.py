import csv
import json

import pytest
from PySide6.QtWidgets import QApplication

from cyberintel.config import Config
from cyberintel.models import ValidationError
from cyberintel.social_profiles import lookup_profiles, normalize_contact, profile_link
from cyberintel.ui import MainWindow


def directory(tmp_path):
    path = tmp_path / "contacts.csv"
    with path.open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["email", "phone", "display_name", "profile_url", "private_note"])
        writer.writerow(["Alex@Example.COM", "+1 (415) 555-0123", "Fixture Alex", "https://github.com/example", "OMIT_THIS"])
        writer.writerow(["alex@example.com", "+14155550123", "Fixture Alex", "https://github.com/example", "OMIT_THIS"])
        writer.writerow(["other@example.com", "+14155550124", "Unrelated Person", "https://x.com/example", "PRIVATE_OTHER"])
    return path


def test_email_phone_matching_deduplicates_without_exposing_other_rows(tmp_path):
    path = directory(tmp_path)
    for query, kind in [(" alex@example.com ", "email"), ("+1 415 555 0123", "phone")]:
        result = lookup_profiles(path, query, kind, True, "synthetic")
        assert result.status == "synthetic" and result.data["match_count"] == 1
        row = result.data["records"][0]
        assert row["platform"] == "GitHub" and row["source_rows"] == [2, 3]
        assert row["ownership_confirmed"] is False
        for secret in ("OMIT_THIS", "PRIVATE_OTHER", "other@example.com", "Unrelated Person"):
            assert secret not in json.dumps(result.to_dict())


def test_no_match_is_directory_absence_only(tmp_path):
    result = lookup_profiles(directory(tmp_path), "absent@example.com", authorized=True)
    assert result.status == "offline" and result.data["records"] == []
    assert "not absence of an account" in result.data["note"]


def test_invalid_links_and_contacts_are_visible_warnings(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("email,profile_url\nalex@example.com,https://evil.example/alex\nbad-email,https://x.com/example\n")
    result = lookup_profiles(path, "alex@example.com", authorized=True)
    assert result.data["match_count"] == 0 and len(result.data["warnings"]) == 2
    assert "unsupported or invalid" in result.error
    assert "malformed email" in result.error


@pytest.mark.parametrize("value,kind", [("4155550123", "phone"), ("+123", "phone"), ("abc@example.com", "unknown"), ("bad", "email")])
def test_invalid_contact_query(value, kind):
    with pytest.raises(ValidationError):
        normalize_contact(value, kind)


@pytest.mark.parametrize("url", ["https://github.com.evil.example/user", "http://github.com/user", "https://user:secret@github.com/user",
    "https://github.com/user?token=secret", "https://github.com/", "https://github.com:8443/user", "https://github.com/user\nother"])
def test_profile_links_are_validated(url):
    with pytest.raises(ValidationError):
        profile_link(url)


def test_requires_permission_and_columns(tmp_path):
    with pytest.raises(ValidationError, match="authorized"):
        lookup_profiles(directory(tmp_path), "alex@example.com")
    path = tmp_path / "wrong.csv"
    path.write_text("email,name\nalex@example.com,Fixture\n")
    with pytest.raises(ValidationError, match="profile_url"):
        lookup_profiles(path, "alex@example.com", authorized=True)


def test_xlsx_and_phone_only_directory(tmp_path):
    import pandas as pd
    path = tmp_path / "phone.xlsx"
    pd.DataFrame([{"phone": "+14155550123", "profile_url": "https://www.linkedin.com/in/example"}]).to_excel(path, index=False)
    result = lookup_profiles(path, "+14155550123", "phone", True)
    assert result.data["records"][0]["platform"] == "LinkedIn"


def test_ui_case_integrity_restore_and_export(session, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    case = session.create_case("Contact fixture lookup")
    session.add_evidence(case, directory(tmp_path), "Authorized synthetic directory", "2026-10-01T00:00:00Z", "synthetic")
    window = MainWindow(Config(session.store.home), session)
    monkeypatch.setattr(window, "start_job", lambda label, task, done: done(task()))
    try:
        window.reload_cases(case)
        assert window.profiles_controls["selector"].count() == 1
        window.profile_query.setText("alex@example.com")
        with pytest.raises(ValidationError, match="authorized"):
            window.run_profile_lookup()
        window.profile_authorized.setChecked(True)
        window.run_profile_lookup()
        assert "1 supplied profile links" in window.profiles_controls["status"].text()
        result = window.last_results["profiles"]
        assert result.reference.startswith("evidence:")
        assert result.data["evidence_source"] == "Authorized synthetic directory"
        opened = []
        monkeypatch.setattr("cyberintel.ui.QDesktopServices.openUrl", lambda url: opened.append(url.toString()) or True)
        window.profiles_controls["table"].view.selectRow(0)
        window.open_profile_link()
        assert opened == ["https://github.com/example"]
        window.findings_table.view.selectRow(0)
        window.restore_finding()
        assert window.navigation.currentRow() == 15
        for kind in ("csv", "json"):
            path = tmp_path / ("profiles." + kind)
            monkeypatch.setattr("cyberintel.ui.QFileDialog.getSaveFileName", lambda *a, **k: (str(path), ""))
            window.export_module("profiles", kind)
            assert "https://github.com/example" in path.read_text()
        from pathlib import Path
        evidence = session.rows("evidence", case)[0]
        Path(evidence["path"]).write_text("tampered")
        with pytest.raises(ValidationError, match="hash mismatch"):
            window.run_profile_lookup()
        assert len(session.rows("findings", case)) == 1
        assert session.verify_audit()
    finally:
        window.close()
