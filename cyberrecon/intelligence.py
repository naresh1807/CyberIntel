"""Optional release lifecycle enrichment; never confirms vulnerabilities."""
import json
import re

from cyberintel.models import utcnow
from .network import ScopedHTTP
from .scope import Scope

PRODUCTS = {"nginx": "nginx", "apache": "apache-http-server", "php": "php", "mysql": "mysql",
            "postgresql": "postgresql", "openssl": "openssl", "node.js": "nodejs", "nodejs": "nodejs"}


def identify(record):
    product, version = record.get("product", "").lower(), record.get("version", "")
    if not product:
        match = re.match(r"^([a-zA-Z0-9_.-]+)/([0-9]+(?:\.[0-9]+){1,3})(?:\b|$)", record.get("banner", ""))
        if match:
            product, version = match.group(1).lower(), match.group(2)
    return PRODUCTS.get(product), version


def assess(product, version, payload):
    result = {"product": product, "version": version, "status": "UNKNOWN", "confidence": "unknown",
              "retrieved_at": utcnow(), "source": "https://endoflife.date/api/v1/products/" + product,
              "reason": "No matching release cycle or usable version evidence.",
              "next_step": "Verify installed package, vendor support policy and distribution backports. EOL is not proof of a CVE."}
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
        return result
    data = payload.get("result", {})
    if data.get("name") != product:
        return result
    matches = [entry for entry in data.get("releases", []) if
               isinstance(entry, dict) and isinstance(entry.get("name"), str) and
               (version == entry["name"] or version.startswith(entry["name"] + "."))]
    if not matches:
        return result
    cycle = max(matches, key=lambda entry: len(entry["name"]))
    state = cycle.get("isEol")
    if not isinstance(state, bool):
        return result
    result.update(status="EOL" if state else "NOT_EOL", confidence="release-cycle-match",
                  cycle=cycle["name"], eol_date=cycle.get("eolFrom"), intelligence_generated_at=payload.get("generated_at"),
                  reason="Upstream lifecycle provider matched the observed version to a release cycle; installed package is unverified.")
    return result


def enrich(repository, scan, transport=None, cancel=None):
    client = ScopedHTTP(lambda: Scope(("endoflife.date",)), rate=2, max_requests=20, transport=transport, cancel=cancel)
    cached, warnings = {}, []
    for record in repository.snapshot(scan)["technologies"][:100]:
        product, version = identify(record)
        if not product:
            continue
        try:
            if product not in cached:
                response = client.fetch("https://endoflife.date/api/v1/products/" + product)
                if response["status_code"] != 200 or response["truncated"]:
                    raise ValueError("Lifecycle provider returned unavailable or oversized data.")
                cached[product] = json.loads(response["text"])
            assessment = assess(product, version, cached[product])
            repository.save(scan, "technologies", record["key"], {**record, "lifecycle": assessment},
                            record["source"], confidence=record["confidence"])
        except Exception as exc:
            warnings.append(f"Lifecycle {product}: {exc}")
    return warnings


def normalized_cpe(value):
    """Conservative subset; ambiguous/escaped versions remain unknown."""
    if value.startswith("cpe:/"):
        fields = value[5:].split(":")
        if len(fields) != 4:
            return None
        value = "cpe:2.3:" + ":".join(fields + ["*"] * 7)
    fields = value.split(":")
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"] or fields[2] not in {"a", "o", "h"}:
        return None
    if any(not re.fullmatch(r"[a-zA-Z0-9_.-]+", field) for field in fields[3:6]):
        return None
    if fields[5] == "-" or any(not re.fullmatch(r"[a-zA-Z0-9_.*-]+", field) for field in fields[6:]):
        return None
    return value


def enrich_cves(repository, scan, transport=None, cancel=None):
    from types import SimpleNamespace
    from urllib.parse import urlencode
    from cyberintel.connectors import Collector
    collector = Collector(SimpleNamespace(timeout_seconds=8), None, transport=transport)
    candidates = {}
    for record in repository.snapshot(scan)["technologies"]:
        for value in record.get("cpe", []):
            cpe = normalized_cpe(value)
            if cpe:
                candidates.setdefault(cpe, []).append(record["key"])
    warnings = []
    if len(candidates) > 3:
        warnings.append("NVD enrichment limited to three distinct versioned CPEs.")
    for index, (cpe, assets) in enumerate(list(candidates.items())[:3]):
        if cancel and cancel.is_set():
            break
        if index and transport is None:
            import time
            if cancel:
                if cancel.wait(6):
                    break
            else:
                time.sleep(6)
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode({"cpeName": cpe, "isVulnerable": "", "resultsPerPage": 50})
        try:
            payload, _, _ = collector._request("GET", url, attempts=1, timeout_seconds=8)
            if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                raise ValueError("Malformed NVD response.")
            if payload.get("totalResults", 0) > 50:
                warnings.append("NVD coverage truncated to 50 candidates for " + cpe)
            for entry in payload["vulnerabilities"][:50]:
                cve = entry["cve"]
                identifier = cve["id"]
                if not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier) or cve.get("vulnStatus") == "Rejected":
                    continue
                description = next((item["value"][:1500] for item in cve.get("descriptions", []) if item.get("lang") == "en"), "")
                repository.save(scan, "findings", identifier + ":" + cpe, {
                    "cve_id": identifier, "description": description, "matched_cpe": cpe, "technology_keys": assets,
                    "classification": "CVE candidate", "confirmed_vulnerability": False,
                    "published": cve.get("published"), "intel_last_modified": cve.get("lastModified"),
                    "reference": "https://nvd.nist.gov/vuln/detail/" + identifier,
                    "reason": "NVD associated an observed versioned CPE with this advisory; installed package and applicability are unverified.",
                    "next_step": "Verify vendor advisory, installed package, configuration, affected ranges and distribution backports."},
                    "NVD CVE API 2.0", confidence="candidate-requires-validation")
        except Exception as exc:
            warnings.append("NVD: " + str(exc))
    if not candidates:
        warnings.append("NVD skipped: no usable versioned CPE evidence; absence of a match does not establish safety.")
    return warnings
