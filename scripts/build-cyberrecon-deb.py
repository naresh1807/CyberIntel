#!/usr/bin/env python3
"""Build a distribution package without installing or modifying the host."""
import argparse
import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def build(output, worker=None):
    spec = importlib.util.spec_from_file_location("cyberrecon_version", ROOT / "cyberrecon/__init__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    version = module.__version__
    architecture = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip() if worker else "all"
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"cyberrecon_{version}-1_{architecture}.deb"
    if destination.is_symlink():
        raise ValueError("Package destination cannot be a symlink.")
    with tempfile.TemporaryDirectory(prefix="cyberrecon-deb-") as temporary:
        stage = Path(temporary)
        control = stage / "DEBIAN"
        control.mkdir()
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
        (desktop / "cyberrecon.desktop").write_text("[Desktop Entry]\nType=Application\nName=CyberRecon\nComment=Authorized reconnaissance and reporting\nExec=cyberrecon\nTerminal=false\nCategories=Network;Security;\n")
        documentation = stage / "usr/share/doc/cyberrecon"
        documentation.mkdir(parents=True)
        shutil.copy2(ROOT / "CYBERRECON.md", documentation / "README.md")
        (documentation / "copyright").write_text("CyberRecon development package.\nProject licensing must be finalized before public redistribution.\n")
        (control / "control").write_text(f"Package: cyberrecon\nVersion: {version}-1\nSection: net\nPriority: optional\nArchitecture: {architecture}\nMaintainer: CyberRecon development team <development@invalid.example>\nDepends: python3 (>= 3.12), python3-httpx (>= 0.28), python3-dnspython, python3-pyside6.qtwidgets, python3-networkx, python3-plotly, python3-reportlab\nRecommends: nmap, subfinder, whatweb, ffuf\nDescription: Authorized reconnaissance project and scan workspace\n Scope-controlled discovery, observation storage, comparisons and reports.\n This development package requires Kali/Parrot installation validation.\n")
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(destination)], check=True)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(ROOT / "dist"))
    parser.add_argument("--worker", help="Optional compiled Go worker for the build host architecture")
    args = parser.parse_args()
    print(build(args.output, args.worker))
