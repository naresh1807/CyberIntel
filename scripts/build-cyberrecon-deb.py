#!/usr/bin/env python3
"""Build a distribution package without installing or modifying the host."""
import argparse
import importlib.util
import os
import shutil
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def build(output, worker=None, maintainer=None, production=False):
    if production and (not maintainer or not re.fullmatch(r"[^<>\r\n]+ <[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+>", maintainer) or "invalid.example" in maintainer):
        raise ValueError("MAINTAINER IDENTITY REQUIRED: provide a real public Name <email>.")
    if maintainer and any(c in maintainer for c in ("\r", "\n")):
        raise ValueError("Invalid maintainer metadata.")
    maintainer = maintainer or "CyberRecon contributors (development identity unconfigured)"
    if not (ROOT / "LICENSE").is_file():
        raise ValueError("LICENSE REQUIRED.")
    spec = importlib.util.spec_from_file_location("cyberrecon_version", ROOT / "cyberrecon/__init__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    version = module.__version__
    architecture = subprocess.check_output(["dpkg", "--print-architecture"], text=True, timeout=10).strip() if worker else "all"
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"cyberrecon_{version}-5_{architecture}.deb"
    if destination.is_symlink():
        raise ValueError("Package destination cannot be a symlink.")
    with tempfile.TemporaryDirectory(prefix="cyberrecon-deb-") as temporary:
        stage = Path(temporary)
        control = stage / "DEBIAN"
        control.mkdir()
        # Package-owned Python imports can create caches when launched as root.
        # Debian's helper cleans only bytecode for this package's listed files.
        prerm = control / "prerm"
        prerm.write_text('#!/bin/sh\nset -e\ncase "${1:-}" in\n  remove|upgrade|deconfigure) py3clean -p cyberrecon ;;\nesac\nexit 0\n')
        prerm.chmod(0o755)
        application = stage / "usr/share/cyberrecon"
        application.mkdir(parents=True)
        shutil.copytree(ROOT / "cyberrecon", application / "cyberrecon", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        # Only compatibility utilities used by CyberRecon, not the CyberIntel GUI.
        support = application / "cyberintel"
        support.mkdir()
        for name in ("__init__.py", "models.py", "output.py", "connectors.py", "nmap_scan.py", "web_assessment.py"):
            shutil.copy2(ROOT / "cyberintel" / name, support / name)
        binaries = stage / "usr/bin"
        binaries.mkdir(parents=True)
        launcher = binaries / "cyberrecon"
        launcher.write_text("#!/usr/bin/python3\nimport sys\nsys.path.insert(0, '/usr/share/cyberrecon')\nfrom cyberrecon.cli import main\nraise SystemExit(main())\n")
        launcher.chmod(0o755)
        if worker:
            shutil.copy2(worker, binaries / "cyberrecon-dns")
            (binaries / "cyberrecon-dns").chmod(0o755)
        desktop = stage / "usr/share/applications"
        desktop.mkdir(parents=True)
        (desktop / "cyberrecon.desktop").write_text("[Desktop Entry]\nType=Application\nName=CyberRecon\nComment=Authorized reconnaissance and reporting\nExec=/usr/bin/cyberrecon\nTryExec=/usr/bin/cyberrecon\nIcon=cyberrecon\nTerminal=false\nCategories=Network;Security;\n")
        icons = stage / "usr/share/icons/hicolor/scalable/apps"
        icons.mkdir(parents=True)
        shutil.copy2(ROOT / "cyberrecon/assets/cyberrecon.svg", icons / "cyberrecon.svg")
        documentation = stage / "usr/share/doc/cyberrecon"
        documentation.mkdir(parents=True)
        shutil.copy2(ROOT / "CYBERRECON.md", documentation / "README.md")
        # Evidence hashes describe the finished archive and cannot be embedded
        # recursively inside that same archive.
        shutil.copytree(ROOT / "docs", documentation / "docs", ignore=shutil.ignore_patterns("release-evidence", "APT_RELEASE_REPORT.md", "__pycache__", "*.pyc"))
        (documentation / "workers").mkdir()
        shutil.copy2(ROOT / "workers/README.md", documentation / "workers/README.md")
        shutil.copy2(ROOT / "LICENSE", documentation / "copyright")
        (control / "control").write_text(f"Package: cyberrecon\nVersion: {version}-5\nSection: net\nPriority: optional\nArchitecture: {architecture}\nMaintainer: {maintainer}\nHomepage: https://github.com/naresh1807/CyberIntel\nDepends: python3 (>= 3.12), python3-httpx (>= 0.28), python3-dnspython (>= 2.7), python3-pyside6.qtwidgets (>= 6.8), python3-networkx (>= 3.2.1), python3-numpy (>= 1:2.0), python3-plotly (>= 5.20), python3-reportlab (>= 4.3)\nRecommends: nmap, subfinder, whatweb, ffuf\nDescription: Authorized reconnaissance project and scan workspace\n Scope-controlled discovery, observation storage, comparisons and reports.\n This development package requires Kali/Parrot installation validation.\n")
        # Host umask and source group-writable modes must never reach /usr.
        executables = {launcher, control / 'prerm'}
        if worker:
            executables.add(binaries / 'cyberrecon-dns')
        stage.chmod(0o755)
        epoch = os.environ.get('SOURCE_DATE_EPOCH')
        if epoch is not None:
            if not epoch.isdecimal():
                raise ValueError('SOURCE_DATE_EPOCH must be a nonnegative integer.')
            epoch = int(epoch)
            os.utime(stage, (epoch, epoch))
        for path in stage.rglob('*'):
            if path.is_symlink():
                raise ValueError('Symlinks are not allowed in this package payload.')
            path.chmod(0o755 if path.is_dir() or path in executables else 0o644)
            if epoch is not None:
                os.utime(path, (epoch, epoch))
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(destination)], check=True, timeout=120)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(ROOT / "dist"))
    parser.add_argument("--worker", help="Optional compiled Go worker for the build host architecture")
    parser.add_argument("--maintainer", help="Real public Name <email>; required for production")
    parser.add_argument("--production", action="store_true", help="Fail closed on missing release identity")
    args = parser.parse_args()
    print(build(args.output, args.worker, args.maintainer, args.production))
