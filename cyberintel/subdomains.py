"""Passive CT discovery with optional DNS checks; no host scans or brute force."""
import copy
import csv
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import dns.resolver

from .connectors import domain
from .models import Result, ValidationError, utcnow
from .reporting import csv_safe
from .output import atomic_output

DNS_LIMIT = 100


def discover_subdomains(collector, target, force=False):
    target = domain(target)
    result = collector.collect("ct", target, force)
    if result.data is None:
        return result
    # Refresh legacy cache rather than inventing wildcard/concrete provenance.
    if "concrete_names" not in result.data:
        result = collector.collect("ct", target, force=True)
        if result.data is None:
            return result
        if "concrete_names" not in result.data:
            return Result(result.source, result.reference, target, None, status="unavailable", freshness="unknown",
                          error="Cached CT data predates wildcard provenance. Refresh when the source is available.")
    result = copy.deepcopy(result)
    names = sorted({domain(name) for name in result.data["concrete_names"] if name != target and name.endswith("." + target)})
    result.data["subdomains"] = names
    result.data["records"] = [{"subdomain": name, "ipv4": [], "ipv6": [], "dns_status": "not checked",
                               "ipv4_status": "not checked", "ipv6_status": "not checked", "discovery_source": result.source,
                               "source_reference": result.reference, "observed_at": result.collected_at,
                               "dns_checked_at": "", "dns_error": ""}
                              for name in names]
    result.data["subdomain_count"] = len(names)
    result.data["note"] = "Passive certificate observations only; not exhaustive. Wildcard patterns do not identify concrete hosts. DNS resolution does not prove website availability, ownership, or absence of wildcard DNS."
    return result


def _resolve_record(row, resolver_factory):
    row = dict(row)
    try:
        resolver = resolver_factory()
    except (dns.exception.DNSException, OSError) as exc:
        row.update(ipv4=[], ipv6=[], ipv4_status="lookup failed", ipv6_status="lookup failed",
                   dns_status="error", dns_error="Resolver configuration: " + type(exc).__name__,
                   dns_checked_at=utcnow(), dns_source="unavailable")
        return row
    resolver.lifetime = resolver.timeout = 3
    errors, nxdomain = [], False
    row["ipv4"], row["ipv6"] = [], []
    for record_type, field in (("A", "ipv4"), ("AAAA", "ipv6")):
        try:
            row[field] = sorted({answer.to_text() for answer in resolver.resolve(row["subdomain"] + ".", record_type, search=False)})
            row[field + "_status"] = "resolved" if row[field] else "no record"
        except dns.resolver.NXDOMAIN:
            nxdomain = True
            for family in ("ipv4", "ipv6"):
                if not row[family]:
                    row[family + "_status"] = "nxdomain"
            break
        except dns.resolver.NoAnswer:
            row[field + "_status"] = "no record"
        except (dns.exception.DNSException, OSError) as exc:
            row[field + "_status"] = "lookup failed"
            errors.append(record_type + ": " + type(exc).__name__)
    row["dns_status"] = "resolved" if row["ipv4"] or row["ipv6"] else "nxdomain" if nxdomain else "error" if errors else "no address records"
    row["dns_error"] = "; ".join(errors)
    row["dns_checked_at"] = utcnow()
    row["dns_source"] = "dns://" + ",".join(str(server) for server in resolver.nameservers)
    return row


def verify_subdomains(result, names, resolver_factory=None):
    if not result.data or "records" not in result.data:
        raise ValidationError("Discover subdomains first.")
    names = set(names)
    if not names or len(names) > DNS_LIMIT:
        raise ValidationError(f"Choose between 1 and {DNS_LIMIT} names. Filter the table to reduce the batch.")
    known = {row["subdomain"]: row for row in result.data["records"]}
    if names - known.keys():
        raise ValidationError("DNS verification accepts only discovered names.")
    parent = domain(result.query)
    for name in names:
        if domain(name) == parent or not name.endswith("." + parent):
            raise ValidationError("A discovered name is outside the requested domain.")
    result = copy.deepcopy(result)
    resolver_factory = resolver_factory or dns.resolver.Resolver
    with ThreadPoolExecutor(max_workers=8) as pool:
        checked = list(pool.map(lambda row: _resolve_record(row, resolver_factory), [known[name] for name in sorted(names)]))
    updates = {row["subdomain"]: row for row in checked}
    result.data["records"] = [updates.get(row["subdomain"], row) for row in result.data["records"]]
    result.data["dns_verification_at"] = utcnow()
    result.data["last_dns_batch_count"] = len(checked)
    return result


def enrich_subdomains(result, resolver_factory=None):
    """Automatically resolve a bounded batch without discarding unavailable/empty results."""
    if not result.data or not result.data.get("records"):
        return result
    names = [row["subdomain"] for row in result.data["records"][:DNS_LIMIT]]
    enriched = verify_subdomains(result, names, resolver_factory)
    enriched.data["auto_dns_unchecked_count"] = len(result.data["records"]) - len(names)
    return enriched


def export_subdomains(result, destination, names=None):
    if not result.data or "records" not in result.data:
        raise ValidationError("Discover subdomains before exporting.")
    selected = set(names) if names is not None else None
    fields = ["subdomain", "ipv4", "ipv6", "dns_status", "ipv4_status", "ipv6_status", "discovery_source", "source_reference", "observed_at", "dns_checked_at", "dns_source", "dns_error"]
    with atomic_output(destination) as temporary, temporary.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for row in result.data["records"]:
            if selected is not None and row["subdomain"] not in selected:
                continue
            writer.writerow({field: csv_safe(", ".join(row.get(field, [])) if field in {"ipv4", "ipv6"} else row.get(field, "")) for field in fields})
    return str(destination)
