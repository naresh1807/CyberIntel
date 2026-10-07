import ipaddress
import json
import shutil
from pathlib import Path

from .engines import run_process


def worker_path():
    executable = shutil.which("cyberrecon-dns")
    if not executable:
        candidate = Path(__file__).resolve().parent.parent / "dist" / "cyberrecon-dns"
        if candidate.is_file():
            executable = str(candidate)
    return executable


def resolve_hosts(hosts, scope, cancel=None):
    executable = worker_path()
    if not executable:
        raise ValueError("Go worker unavailable; build workers/dns or install cyberrecon-dns on PATH.")
    hosts = list(dict.fromkeys(scope.require(host) for host in hosts))[:30]
    if not hosts:
        return []
    job = {"id": "dns", "hosts": hosts, **scope.to_dict(), "concurrency": 4}
    raw = run_process([executable], input_bytes=json.dumps(job).encode(), timeout=90, cancel=cancel)
    records = []
    for line in raw.decode().splitlines():
        row = json.loads(line)
        if row.get("id") != "dns" or row.get("host") not in hosts:
            raise ValueError("Go worker returned unexpected job/host.")
        row["addresses"] = [str(ipaddress.ip_address(value)) for value in row.get("addresses", [])[:100]]
        records.append(row)
    if len(records) != len(hosts) or len({row["host"] for row in records}) != len(hosts):
        raise ValueError("Go worker returned incomplete or duplicate host results.")
    return records
