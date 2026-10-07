"""Bounded, local readiness probes. No installation, provider calls or secrets."""
import importlib
import importlib.metadata
import importlib.util
import os
import re
import shutil
import sys
from pathlib import Path

from . import __version__
from .engines import TOOLS, ToolError, run_process

# Conservative CLI families used by the fixed builders/import formats.
# Matching this range does not certify every provider/plugin or engine option.
PROBES = {
    "subfinder": (["-version"], (2, 6), 3),
    "assetfinder": (None, None, None),  # no dependable version-only interface
    "amass": (["-version"], (3, 0), 4),
    "nmap": (["--version"], (7, 0), 8),
    "ffuf": (["-V"], (2, 0), 3),
    "whatweb": (["--version"], (0, 5), 1),
    "gau": (["--version"], (2, 0), 3),
    "waybackurls": (None, None, None),
    "dnsx": (["-version"], (1, 0), 2),
    "httpx": (["-version"], (1, 0), 2),
    "naabu": (["-version"], (2, 0), 3),
    "katana": (["-version"], (1, 0), 2),
    "gobuster": (["version"], (3, 0), 4),
    "cyberrecon-dns": (["--version"], (0, 2), 1),
}
DEPENDENCIES = {"httpx": "httpx", "dnspython": "dns", "PySide6": "PySide6.QtWidgets",
                "networkx": "networkx", "numpy": "numpy", "plotly": "plotly", "reportlab": "reportlab"}
DEPENDENCY_RANGES = {"httpx": ((0, 28), 1), "dnspython": ((2, 7), 3), "PySide6": ((6, 8), 7),
                     "networkx": ((3, 2, 1), 4), "numpy": ((2, 0), 3), "plotly": ((5, 20), 8), "reportlab": ((4, 3), 6)}


def tool_status(name, capability):
    executable = shutil.which(name)
    on_path = bool(executable)
    if name == "cyberrecon-dns" and not executable:
        from .go_worker import worker_path
        executable = worker_path()
    flags, minimum, upper = PROBES[name]
    supported = f">={'.'.join(map(str, minimum))}, <{upper}.0 (CLI family only)" if minimum else "version not detectable"
    result = {"on_path": on_path, "installed": bool(executable), "path": str(Path(executable).absolute()) if executable else None,
              "version": None, "minimum_supported_version": ".".join(map(str, minimum)) if minimum else None,
              "supported_version": supported, "compatibility": "unknown", "status": "OPTIONAL",
              "requirement": "Recommended for port scanning" if name == "nmap" else "Optional",
              "capability": capability, "recommended_action": "Install only if this optional capability is needed."}
    if not executable:
        for directory in os.get_exec_path():
            candidate = Path(directory) / name
            if candidate.is_file() and not os.access(candidate, os.X_OK):
                result.update(installed=True, path=str(candidate.absolute()), status="PERMISSION_DENIED", recommended_action="Check executable permissions.")
                break
        return result
    if not os.access(executable, os.X_OK):
        result.update(status="PERMISSION_DENIED", recommended_action="Check executable permissions.")
        return result
    if not flags:
        result.update(status="REVIEW", recommended_action="Version interface unavailable; verify installation manually.")
        return result
    try:
        raw = run_process([executable, *flags], timeout=3, max_output=65536, combine_stderr=True)
    except (ToolError, OSError, ValueError) as exc:
        code = exc.code.upper() if isinstance(exc, ToolError) else "BROKEN"
        result.update(status=code, recommended_action="Executable probe failed; inspect local installation.")
        return result
    # Some engines print their version to stderr; run_process combines it only
    # for explicitly requested local probes (never for parser output).
    text = raw.decode("utf-8", errors="replace")
    match = re.search(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?\b", text)
    if not match or (name == "httpx" and "httpx" not in text.lower()):
        result.update(status="REVIEW", recommended_action="Unrecognized version output; check executable identity (especially Python httpx).")
        return result
    version = tuple(int(value or 0) for value in match.groups())
    compatible = version[:2] >= minimum and version[0] < upper
    result.update(version=".".join(map(str, version)), compatibility="CLI family match" if compatible else "unsupported",
                  status="READY" if compatible else "UNSUPPORTED",
                  recommended_action="Run authorized local integration validation before release." if compatible else "Use a supported CLI family or the native/import fallback.")
    return result


def doctor(home=None, wordlist=None):
    tools = {name: tool_status(name, capability) for name, capability in
             {**TOOLS, "cyberrecon-dns": "Optional bounded DNS worker"}.items()}
    dependencies = {}
    for package, module in DEPENDENCIES.items():
        installed, version = False, None
        try:
            installed = importlib.util.find_spec(module) is not None
            version = importlib.metadata.version(package) if installed else None
            status = "MISSING"
            if installed:
                importlib.import_module(module)
                match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", version)
                minimum, upper = DEPENDENCY_RANGES[package]
                numbers = tuple(int(part or 0) for part in match.groups()) if match else None
                status = "READY" if numbers and numbers >= minimum and numbers[0] < upper else "UNSUPPORTED"
            dependencies[package] = {"installed": installed, "version": version, "status": status}
        except (ImportError, ValueError, OSError, importlib.metadata.PackageNotFoundError):
            dependencies[package] = {"installed": installed, "version": version, "status": "BROKEN"}
    for package, result in dependencies.items():
        minimum, upper = DEPENDENCY_RANGES[package]
        result.update(requirement="Required", minimum_supported_version=".".join(map(str, minimum)),
                      supported_version=">=" + ".".join(map(str, minimum)) + ", <" + str(upper),
                      compatibility="Supported version" if result["status"] == "READY" else "Not ready",
                      recommended_action="No action required." if result["status"] == "READY" else
                      "Resolve this required dependency through the supported distro package or virtual environment.")
    root = Path(home or os.environ.get("CYBERRECON_HOME") or Path.home() / ".local/share/cyberrecon").expanduser()
    ancestor = root
    while not ancestor.exists() and ancestor != ancestor.parent:
        ancestor = ancestor.parent
    workspace_ok = ancestor.is_dir() and os.access(ancestor, os.W_OK | os.X_OK)
    database_status = "NOT_CREATED"
    if workspace_ok:
        try:
            for name in ("cyberrecon.db", "cyberrecon.db-wal", "cyberrecon.db-shm"):
                candidate = root / name
                if candidate.is_symlink() or candidate.exists() and not candidate.is_file():
                    database_status = "UNSAFE_DATABASE_PATH"
                    break
            else:
                database = root / "cyberrecon.db"
                if database.exists():
                    with database.open("rb") as stream:
                        database_status = "HEADER_VALID" if stream.read(16) == b"SQLite format 3\x00" else "INVALID_DATABASE_HEADER"
        except OSError:
            database_status = "DATABASE_PERMISSION_ERROR"
    path = Path(wordlist).expanduser() if wordlist else None
    wordlist_status = "NOT_CONFIGURED"
    if path:
        wordlist_status = "READY" if path.is_file() and os.access(path, os.R_OK) and path.stat().st_size <= 65536 else "MISSING_OR_INVALID"
    return {"version": __version__, "python": sys.version.split()[0],
            "python_status": "READY" if sys.version_info >= (3, 12) else "UNSUPPORTED", "supported_python": ">=3.12",
            "tools": tools, "dependencies": dependencies,
            "configuration": {"workspace": "READY" if workspace_ok else "PERMISSION_OR_PATH_ERROR", "wordlist": wordlist_status, "database": database_status},
            "notes": ["Local version probes have 3-second and 64-KiB limits; no tools are installed.",
                      "READY indicates a CLI family match, not full external engine qualification.",
                      "dnsx/httpx/naabu/katana are imports; Gobuster is not wired; ffuf/WhatWeb active collection uses native safety.",
                      "Assetfinder and waybackurls require manual version verification."]}
