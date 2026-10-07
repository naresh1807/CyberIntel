"""Passive bounded API/documentation extraction from already fetched responses."""
import json
import re
from urllib.parse import parse_qsl, urlsplit

from .network import clean_url


def extract(response, body, scope):
    url = response["url"]
    path = urlsplit(url).path
    records = []
    if re.search(r"/(api|graphql|swagger|openapi)(/|\.|$)", path, re.I) or response["status_code"] in {401, 403}:
        challenge = response["headers"].get("www-authenticate", "").split(" ", 1)[0]
        records.append({"url": url, "classification": "observed HTTP surface", "status_code": response["status_code"],
                        "parameter_names": sorted({key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)}),
                        "challenge_scheme": challenge if challenge.lower() in {"basic", "bearer", "digest", "negotiate"} else "unknown",
                        "note": "Authentication behavior and business impact have not been tested."})
    if "json" not in response["headers"].get("content-type", "").lower() or response["truncated"]:
        return records
    try:
        data = json.loads(body)
    except ValueError:
        return records
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict) or not (data.get("openapi") or data.get("swagger")):
        return records
    base = url
    servers = data.get("servers", [])
    for server in (servers if isinstance(servers, list) else [])[:10]:
        try:
            candidate = clean_url(server["url"], url)
            if scope.allows(candidate):
                base = candidate.rstrip("/") + "/"
                break
        except (ValueError, KeyError, TypeError):
            continue
    if data.get("swagger") and isinstance(data.get("basePath"), str):
        try:
            parts = urlsplit(url)
            host = data.get("host", parts.netloc)
            if not isinstance(host, str):
                raise ValueError("Invalid Swagger host")
            candidate = clean_url(parts.scheme + "://" + host + data["basePath"].rstrip("/") + "/")
            if scope.allows(candidate):
                base = candidate
        except ValueError:
            pass
    for path, operations in list(data["paths"].items())[:500]:
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(operations, dict):
            continue
        try:
            endpoint = clean_url(base.rstrip("/") + path if base != url else path, base)
            scope.require(endpoint)
        except ValueError:
            continue
        methods = sorted(method.upper() for method in operations if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"})
        names = set()
        for method in methods:
            operation = operations.get(method.lower(), {})
            if not isinstance(operation, dict):
                continue
            parameters = operation.get("parameters", [])
            inherited = operations.get("parameters", [])
            parameters = (parameters if isinstance(parameters, list) else []) + (inherited if isinstance(inherited, list) else [])
            for parameter in parameters[:100]:
                if isinstance(parameter, dict) and isinstance(parameter.get("name"), str):
                    names.add(parameter["name"][:200])
        records.append({"url": endpoint, "classification": "documented endpoint (unverified)", "methods": methods,
                        "parameter_names": sorted(names), "documentation_url": url,
                        "spec_version": str(data.get("openapi") or data.get("swagger"))[:30],
                        "declares_security": any(bool(operations[method.lower()].get("security", data.get("security")))
                                                 for method in methods if isinstance(operations.get(method.lower()), dict)),
                        "note": "Documented methods and schemas do not establish reachable or vulnerable endpoints."})
    return records
