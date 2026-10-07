import json

from cyberrecon.cli import main
from cyberrecon.reporting import export_reports
from cyberrecon.storage import Repository


def test_reports_escape_and_export(tmp_path):
    repo = Repository(tmp_path / "workspace")
    project = repo.create_project("<script>alert(1)</script>", ["example.org"], authority="Fixture")
    scan = repo.start_scan(project, "example.org", {})
    repo.save(scan, "findings", "=HYPERLINK(1)", {"note": "<img src=x onerror=alert(1)>"}, "fixture")
    repo.finish(scan, [])
    destination = tmp_path / "reports"
    export_reports(repo, scan, destination)
    report = (destination / "report.html").read_text()
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "'=HYPERLINK" in (destination / "observations.csv").read_text()
    assert (destination / "report.pdf").read_bytes().startswith(b"%PDF")
    assert (destination / "graph.html").exists()


def test_scope_import_preserves_scan_scope(tmp_path, capsys):
    repo = Repository(tmp_path / "workspace")
    project = repo.create_project("Lab", ["example.org"], authority="Fixture")
    scan = repo.start_scan(project, "example.org", {})
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({"include": ["other.org"], "exclude": []}))
    assert main(["--home", str(repo.home), "scope-import", project, str(scope_file)]) == 0
    assert repo.scope(project).allows("other.org")
    assert repo.snapshot(scan)["scan"]["scope"]["include"] == ["example.org"]
