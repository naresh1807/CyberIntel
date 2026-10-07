import argparse
import json
import shutil
import sqlite3
import sys

from . import __version__
from .engines import TOOLS
from .storage import Repository, compare_snapshots


def doctor():
    return {"version": __version__, "python": sys.version.split()[0],
            "tools": {name: {"on_path": bool(shutil.which(name)), "capability": capability}
                      for name, capability in TOOLS.items()},
            "notes": ["PATH presence does not establish compatible engine versions (especially the two unrelated httpx executables).",
                      "JSONL import supports dnsx, ProjectDiscovery httpx, naabu and katana; imports are unverified.",
                      "No personal-data lookup or automatic exploitation is included."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="CyberRecon: authorized, bounded reconnaissance")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--home", help="Workspace directory")
    commands = parser.add_subparsers(dest="command")
    project = commands.add_parser("project", help="Create an authorized scope")
    project.add_argument("name")
    project.add_argument("--include", action="append", required=True)
    project.add_argument("--exclude", action="append", default=[])
    project.add_argument("--authority", required=True)
    commands.add_parser("projects")
    provider = commands.add_parser("host-intel", help="Read existing Shodan/Censys observations for an explicitly authorized public IP")
    provider.add_argument("provider", choices=["shodan", "censys"])
    provider.add_argument("ip")
    provider.add_argument("--project", required=True)
    imported = commands.add_parser("import-engine", help="Import scoped external engine JSONL; no active requests")
    imported.add_argument("engine", choices=["dnsx", "httpx", "naabu", "katana"])
    imported.add_argument("file")
    imported.add_argument("--project", required=True)
    imported.add_argument("--target", required=True)
    scope_import = commands.add_parser("scope-import", help="Replace project scope from JSON include/exclude arrays")
    scope_import.add_argument("project")
    scope_import.add_argument("file")
    run = commands.add_parser("scan")
    run.add_argument("target")
    run.add_argument("--project", required=True)
    run.add_argument("--passive", choices=["ct", "subfinder", "assetfinder", "amass"])
    run.add_argument("--history", choices=["gau", "waybackurls"])
    run.add_argument("--crawl", action="store_true")
    run.add_argument("--lifecycle", action="store_true", help="Send detected product names to endoflife.date for upstream lifecycle metadata")
    run.add_argument("--go-dns", action="store_true", help="Use the bounded Go A/AAAA resolution worker")
    run.add_argument("--wordlist", help="Up to 200 relative content paths; subject to the 30-page limit")
    run.add_argument("--cve", action="store_true", help="Send up to three observed versioned CPEs to NVD; results remain unconfirmed candidates")
    run.add_argument("--ca-bundle", help="Additional trusted PEM CA certificates for an authorized lab; TLS verification stays enabled")
    run.add_argument("--ports", default=None, help="Explicit IP targets only; empty string selects top 100 TCP ports")
    run.add_argument("--udp", action="store_true")
    listing = commands.add_parser("scans")
    listing.add_argument("project")
    export = commands.add_parser("export")
    export.add_argument("scan")
    export.add_argument("directory")
    compare = commands.add_parser("compare")
    compare.add_argument("before")
    compare.add_argument("after")
    args = parser.parse_args(argv)
    if args.doctor:
        print(json.dumps(doctor(), indent=2))
        return 0
    try:
        repo = Repository(args.home)
        if args.command == "project":
            result = repo.create_project(args.name, args.include, args.exclude, args.authority)
        elif args.command == "projects":
            result = repo.projects()
        elif args.command == "host-intel":
            from .providers import host_lookup
            result = host_lookup(repo, args.project, args.ip, args.provider)
        elif args.command == "import-engine":
            from .importers import import_jsonl
            result = import_jsonl(repo, args.project, args.target, args.engine, args.file)
        elif args.command == "scans":
            result = repo.scans(args.project)
        elif args.command == "scope-import":
            from pathlib import Path
            path = Path(args.file)
            if path.stat().st_size > 1024 * 1024:
                raise ValueError("Scope file exceeds 1 MiB.")
            data = json.loads(path.read_text())
            if not isinstance(data, dict) or not isinstance(data.get("include"), list) or not isinstance(data.get("exclude", []), list):
                raise ValueError("Scope JSON requires include and optional exclude arrays.")
            if any(not isinstance(rule, str) for rule in data["include"] + data.get("exclude", [])):
                raise ValueError("Scope rules must be strings.")
            repo.update_scope(args.project, data["include"], data.get("exclude", []))
            result = repo.scope(args.project).to_dict()
        elif args.command == "scan":
            from .scanner import scan
            words = None
            if args.wordlist:
                from pathlib import Path
                path = Path(args.wordlist)
                if path.stat().st_size > 64 * 1024:
                    raise ValueError("Wordlist exceeds 64 KiB.")
                words = path.read_text().splitlines()
            result = scan(repo, args.project, args.target, args.passive, args.crawl, args.history, args.ports, args.udp,
                          lifecycle=args.lifecycle, go_dns=args.go_dns, words=words, cve=args.cve, ca_bundle=args.ca_bundle)
            print(json.dumps(repo.snapshot(result)["scan"], indent=2))
            return 0 if repo.snapshot(result)["scan"]["status"] == "complete" else 1
        elif args.command == "export":
            from .reporting import export_reports
            result = export_reports(repo, args.scan, args.directory)
        elif args.command == "compare":
            result = compare_snapshots(repo.snapshot(args.before), repo.snapshot(args.after))
        else:
            from .gui import launch
            return launch(repo)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, RecursionError, sqlite3.Error) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
