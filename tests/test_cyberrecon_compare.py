from cyberrecon.storage import Repository, compare_snapshots


def test_comparison_ignores_scan_evidence_paths_and_control_urls(tmp_path):
    repo = Repository(tmp_path)
    project = repo.create_project("Lab", ["example.org"], authority="Fixture")
    identifiers = []
    for index in range(2):
        identifier = repo.start_scan(project, "example.org", {})
        identifiers.append(identifier)
        repo.save(identifier, "ports", "example.org:443", {"port": 443, "state": "open",
                  "evidence": {"path": identifier + "/nmap.xml", "sha256": str(index)}}, "Nmap")
        repo.save(identifier, "http", "https://example.org/cyberrecon-missing-" + identifier,
                  {"purpose": "content discovery negative control"}, "fixture")
        repo.finish(identifier, [])
    assert compare_snapshots(repo.snapshot(identifiers[0]), repo.snapshot(identifiers[1])) == []
    repo.save(identifiers[1], "ports", "example.org:443", {"port": 443, "state": "closed"}, "Nmap")
    assert compare_snapshots(repo.snapshot(identifiers[0]), repo.snapshot(identifiers[1]))[0]["status"] == "CHANGED"
