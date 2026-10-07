"""Local readiness checks; never submit keys or make provider requests."""
import importlib.metadata
import shutil
import sys


def readiness(keys):
    rows = [{"component": "Python", "status": "ready" if sys.version_info >= (3, 11) else "unsupported",
             "detail": sys.version.split()[0]}]
    for package in ("PySide6", "httpx", "cryptography", "pandas", "numpy", "networkx", "pyqtgraph",
                    "plotly", "folium", "dnspython", "openpyxl", "reportlab", "phonenumbers"):
        try:
            version = importlib.metadata.version(package)
            rows.append({"component": package, "status": "installed", "detail": version})
        except importlib.metadata.PackageNotFoundError:
            rows.append({"component": package, "status": "missing", "detail": "Install project dependencies in this Python environment."})
    for executable, purpose in (("nmap", "Nmap IP scans and Wi-Fi/LAN discovery"),
                                ("tshark", "Offline PCAP analysis"), ("ip", "Automatic Linux subnet and MAC detection")):
        path = shutil.which(executable)
        rows.append({"component": executable, "status": "available" if path else "missing",
                     "detail": path or purpose + ": executable not found on PATH"})
    for provider, names in (("HIBP exposure", ("hibp",)), ("OTX", ("otx",)), ("URLhaus", ("urlhaus",)),
                            ("Twilio", ("twilio_account_sid", "twilio_key_sid", "twilio_key_secret"))):
        configured = all(str(keys.get(name, "")).strip() for name in names)
        rows.append({"component": provider, "status": "configured" if configured else "not configured",
                     "detail": "Credentials present; provider access not tested" if configured else "Enter and save credentials in Settings"})
    rows.append({"component": "Public DNS/RDAP/CT/website/HIBP catalog", "status": "no key required",
                 "detail": "Live availability depends on connectivity and the provider"})
    return rows
