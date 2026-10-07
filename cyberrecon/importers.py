"""Bounded imports of existing authorized external engine observations."""
import json
from pathlib import Path

from .network import clean_url
from .normalization import dns_attributes, dns_key
from .scope import host_of

ENGINES = {"dnsx", "httpx", "naabu", "katana"}


def import_jsonl(repository, project, target, engine, filename):
    if engine not in ENGINES:
        raise ValueError("Supported JSONL engines: " + ", ".join(sorted(ENGINES)))
    path = Path(filename)
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Import exceeds 16 MiB.")
    scope = repository.scope(project)
    scope.require(target, passive=True)
    records, rejected = [], 0
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if number > 5000:
                raise ValueError("Import exceeds 5000 lines.")
            if not line.strip():
                continue
            try:
                pending = []
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("Expected object")
                if engine == "katana":
                    url = clean_url(row["request"]["endpoint"])
                    scope.require(url)
                    pending.append(("urls", url, {"url": url, "verified": False}))
                elif engine == "httpx":
                    url = clean_url(row["url"])
                    scope.require(url)
                    status = int(row["status_code"]) if row.get("status_code") is not None else None
                    if status is not None and not 100 <= status <= 599:
                        raise ValueError("Invalid HTTP status")
                    pending.append(("http", url, {"url": url, "status_code": status,
                                   "technologies": [str(value)[:100] for value in row.get("tech", [])[:50]]}))
                elif engine == "dnsx":
                    host = host_of(row["host"])
                    scope.require(host)
                    for family in ("a", "aaaa", "cname", "mx", "ns"):
                        values = row.get(family, [])
                        if not isinstance(values, list):
                            raise ValueError("DNS values must be arrays")
                        for value in values[:100]:
                            if not isinstance(value, str) or len(value) > 512:
                                raise ValueError("Invalid DNS value")
                            attributes = dns_attributes(family, value)
                            key = dns_key(host, family, attributes["value"])
                            pending.append(("dns", key, {"host": host, "type": family.upper(), **attributes}))
                else:
                    host = host_of(row.get("ip") or row["host"])
                    scope.require(host)
                    port = int(row["port"])
                    if not 1 <= port <= 65535:
                        raise ValueError("Invalid port")
                    protocol = row.get("protocol", "tcp")
                    if protocol not in {"tcp", "udp"}:
                        raise ValueError("Invalid protocol")
                    pending.append(("ports", f"{host}:{protocol}:{port}", {"host": host, "port": port, "protocol": protocol}))
                records.extend(pending)
            except (ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError):
                rejected += 1
            if len(records) > 10000:
                raise ValueError("Import exceeds 10000 normalized observations.")
    identifier = repository.start_scan(project, target, {"import_engine": engine, "active_requests": 0})
    try:
        for kind, key, value in records:
            # Recheck after parsing: scope can change while an import is read.
            repository.scope(project).require(value.get("url") or value["host"])
            repository.save(identifier, kind, key, value, engine + " imported JSONL", confidence="imported-unverified")
    except Exception as exc:
        repository.finish(identifier, ["Import failed during persistence: " + str(exc)], failed=True)
        raise
    warnings = [f"Rejected {rejected} invalid or out-of-scope input rows."] if rejected else []
    warnings.append("Imported observations were not independently verified by CyberRecon.")
    repository.finish(identifier, warnings)
    return identifier
