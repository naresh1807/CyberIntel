"""Bounded, scope checked native reconnaissance workflow."""
import hashlib
import ipaddress
import json
import re
import ssl
import threading
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit
from pathlib import Path

import dns.resolver
import httpx

from . import engines
from .errors import operation_error
from .network import ScopedHTTP, clean_url
from .normalization import dns_attributes, dns_key
from .scope import host_of


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if value and (name == "href" or tag == "script" and name == "src" or tag == "form" and name == "action"):
                self.links.append((value, tag))


def scan(repository, project, target, passive=None, crawl=False, history=None,
         ports=None, udp=False, transport=None, cancel=None, lifecycle=False, go_dns=False, words=None, cve=False, progress=None, ca_bundle=None):
    cancel = cancel or threading.Event()
    words = list(dict.fromkeys(word.strip().lstrip("/") for word in words or [] if word.strip()))
    if len(words) > 200 or any(not re.fullmatch(r"[a-zA-Z0-9_./-]{1,100}", word) or ".." in word for word in words):
        raise ValueError("Content discovery accepts at most 200 relative paths without traversal or parameters.")
    if udp and ports is None:
        raise ValueError("UDP requires an explicit --ports selection.")
    if ports is not None:
        root = repository.scope(project).require(target)
        engines.scan_arguments(root, ports)
    verification, ca_digest = True, None
    if ca_bundle:
        path = Path(ca_bundle)
        if not path.is_file():
            raise ValueError("CA bundle must be a regular PEM certificate file.")
        with path.open("rb") as stream:
            data = stream.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("CA bundle exceeds 2 MiB.")
        verification = ssl.create_default_context()
        verification.load_verify_locations(cadata=data.decode("ascii"))
        ca_digest = hashlib.sha256(data).hexdigest()
    settings = dict(passive=passive, crawl=crawl, history=history, ports=ports, udp=udp,
                    max_pages=30, max_hosts=30, requests=100, rate=2, lifecycle=lifecycle, go_dns=go_dns, content_paths=words, cve=cve, ca_bundle_sha256=ca_digest)
    identifier = repository.start_scan(project, target, settings)
    warnings = []
    verified_urls = set()
    progress = progress or (lambda message: None)
    scope = lambda: repository.scope(project)
    save = lambda kind, key, value, source, **kw: repository.save(identifier, kind, key, value, source, **kw)
    def warn(message, exc=None):
        code, detail = operation_error(exc) if exc is not None else ("coverage_warning", message)
        message = message + ": " + detail if exc is not None else message
        warnings.append(message)
        save("errors", str(len(warnings)), {"code": code, "message": message}, "scan workflow", confidence="diagnostic")

    def edge(left, right, relation):
        save("relationships", left + "|" + relation + "|" + right,
             dict(from_node=left, to_node=right, relation=relation), "correlation")
    def host_node(host):
        try:
            ipaddress.ip_address(host)
            return "ip:" + host
        except ValueError:
            return "host:" + host
    try:
        root = scope().require(target, passive=True)
        hosts = {root} if scope().allows(root) else set()
        if passive and not cancel.is_set():
            progress("Passive discovery: " + passive)
            try:
                names, metadata = engines.passive_domains(passive, root, scope(), cancel)
                if passive == "ct":
                    details = json.loads(metadata)
                    warnings.extend(details["warnings"])
                    if details["truncated"]:
                        warn("Certificate provider coverage is incomplete.")
            except Exception as exc:
                warn(f"Passive discovery {passive}", exc)
                names = []
            hosts.update(names)
            for host in names:
                save("subdomains", host, {"host": host, "verified_current": False}, passive, historical=passive == "ct")
                edge("domain:" + root, "host:" + host, "contains")
        if len(hosts) > 30:
            warn("Host budget reached; only the first 30 sorted hosts were processed.")
        http = ScopedHTTP(scope, transport=transport, cancel=cancel, verify=verification)
        effective_go_dns = False
        if go_dns and hosts and not cancel.is_set():
            from .go_worker import resolve_hosts
            progress("Go DNS resolution")
            try:
                go_results = resolve_hosts(sorted(hosts)[:30], scope(), cancel)
                effective_go_dns = True
            except Exception as exc:
                warn("Go DNS unavailable; using the Python resolver", exc)
                go_results = []
            for row in go_results:
                scope().require(row["host"])
                if row.get("error"):
                    warn("Go DNS " + row["host"] + ": " + row["error"])
                for value in row["addresses"]:
                    family = "A" if ipaddress.ip_address(value).version == 4 else "AAAA"
                    save("dns", dns_key(row["host"], family, value),
                         {"host": row["host"], "type": family, "value": value}, "Go DNS worker")
                    edge("host:" + row["host"], "ip:" + value, "resolves_to")
        for host in sorted(hosts)[:30]:
            if cancel.is_set():
                break
            scope().require(host)
            progress("Processing host: " + host)
            save("assets", host, {"host": host, "active_verified": False}, "scope")
            try:
                ipaddress.ip_address(host)
                literal_ip = True
            except ValueError:
                literal_ip = False
            if transport is None and not literal_ip:
                resolver = dns.resolver.Resolver()
                resolver.lifetime = 3
                for family in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"):
                    if cancel.is_set():
                        break
                    if effective_go_dns and family in {"A", "AAAA"}:
                        continue
                    try:
                        scope().require(host)
                        answer = resolver.resolve(host + ".", family, search=False)
                        for entry in answer:
                            value = str(entry)
                            stored = {"host": host, "type": family, "ttl": answer.rrset.ttl}
                            stored.update({"sha256": hashlib.sha256(value.encode()).hexdigest(), "redacted": True}
                                          if family == "TXT" else dns_attributes(family, value))
                            key_value = stored.get("value", value)
                            save("dns", dns_key(host, family, key_value), stored, "DNS resolver")
                            if family in {"A", "AAAA"}:
                                edge("host:" + host, "ip:" + value, "resolves_to")
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        continue
                    except Exception as exc:
                        warn(f"DNS {host} {family}", exc)
            initial = clean_url(target) if "://" in target and host == root else "https://" + (f"[{host}]" if ":" in host else host) + "/"
            queue, seen = deque([(initial, 0)]), set()
            baseline = None
            if words and not cancel.is_set():
                try:
                    control = clean_url("cyberrecon-missing-" + identifier, initial)
                    control_response = http.fetch(control)
                    baseline = {"url": control_response["url"], "status_code": control_response["status_code"],
                                "bytes_read": control_response["bytes_read"], "body_sha256": control_response["body_sha256"]}
                    save("http", control_response["url"], {**baseline, "purpose": "content discovery negative control"}, "scoped HTTP")
                except Exception as exc:
                    warn("Content discovery calibration unavailable", exc)
            for word in words:
                queue.append((clean_url(word, initial.rstrip("/") + "/"), 2))
            while queue and len(seen) < 30 and not cancel.is_set():
                url, depth = queue.popleft()
                if url in seen:
                    continue
                seen.add(url)
                progress(f"HTTP {http.count}/{http.maximum}: {url}")
                try:
                    result = http.fetch(url)
                    body = result.pop("text")
                    cookies = result.pop("cookie_headers")
                    save("http", result["url"], result, "scoped HTTP")
                    from .api import extract
                    for api in extract(result, body, scope()):
                        save("apis", api["url"], api, "HTTP/API document extraction")
                        edge("url:" + result["url"], "api:" + api["url"], "describes")
                        for name in api["parameter_names"]:
                            edge("api:" + api["url"], "parameter:" + api["url"] + ":" + name, "documents_parameter")
                    save("assets", host, {"host": host, "active_verified": True}, "scoped HTTP")
                    verified_urls.add(result["url"])
                    content_notes = {}
                    if words and depth == 2:
                        content_notes = {"negative_control": baseline, "requires_validation": True,
                                         "possible_wildcard_response": bool(baseline and baseline["status_code"] == result["status_code"] and
                                                                           baseline["body_sha256"] == result["body_sha256"]),
                                         "note": "Compare the negative control and application behavior; response success is not proof of exposure."}
                    save("urls", result["url"], {"url": result["url"], "status_code": result["status_code"], "verified": True, **content_notes}, "scoped HTTP")
                    actual_host = host_of(result["url"])
                    if actual_host != host:
                        save("assets", actual_host, {"host": actual_host, "active_verified": True}, "scoped HTTP")
                    edge(host_node(actual_host), "url:" + result["url"], "serves")
                    for redirect in result["redirect_chain"]:
                        edge("url:" + redirect["from"], "url:" + redirect["to"], "redirects_to")
                    for key, _ in parse_qsl(urlsplit(result["url"]).query, keep_blank_values=True):
                        edge("url:" + result["url"], "parameter:" + result["url"] + ":" + key, "accepts_parameter")
                    for header in ("server", "x-powered-by"):
                        value = result["headers"].get(header)
                        if value:
                            save("technologies", result["url"] + ":" + header,
                                 {"banner": value, "url": result["url"], "lifecycle": "UNKNOWN",
                                  "note": "A self-reported banner is not proof of a vulnerability or exact package version."}, "HTTP " + header,
                                 confidence="self-reported")
                            edge("url:" + result["url"], "technology:" + result["url"] + ":" + header, "reports")
                    if "html" in result["headers"].get("content-type", "").lower():
                        if 200 <= result["status_code"] < 300:
                            from cyberintel.web_assessment import header_findings
                            headers = httpx.Headers(list(result["headers"].items()) + [("set-cookie", value) for value in cookies])
                            for finding in header_findings(headers):
                                if finding["status"] == "review":
                                    save("findings", result["url"] + ":" + finding["check"],
                                         {**finding, "url": result["url"], "classification": "configuration-review",
                                          "confirmed_vulnerability": False, "evidence_sha256": result["body_sha256"]},
                                         "HTTP configuration review", confidence="requires-validation")
                        parser = Links()
                        parser.feed(body)
                        candidates = parser.links
                    elif "javascript" in result["headers"].get("content-type", "").lower() or urlsplit(url).path.lower().endswith(".js"):
                        maps = []
                        for match in re.findall(r"sourceMappingURL=([^\s*]+)", body)[:20]:
                            try:
                                source_map = clean_url(match, result["url"])
                                if scope().allows(source_map):
                                    maps.append(source_map)
                                    save("urls", source_map, {"url": source_map, "verified": False}, "JavaScript source map comment")
                            except ValueError:
                                continue
                        potential = [match.start() for match in re.finditer(r'''(?i)(?:api[_-]?key|secret|access[_-]?token)\s*[:=]\s*["'][^"']{16,}["']''', body)][:100]
                        save("javascript", result["url"], {"url": result["url"], "sha256": result["body_sha256"],
                             "truncated": result["truncated"], "source_map_candidates": maps,
                             "potential_sensitive_assignments": len(potential), "values_retained": False}, "scoped HTTP")
                        edge("url:" + result["url"], "content-sha256:" + result["body_sha256"], "has_content")
                        if potential:
                            save("findings", result["url"] + ":sensitive-assignment-candidates", {"url": result["url"],
                                 "classification": "review", "confirmed_vulnerability": False,
                                 "count": len(potential), "character_offsets": potential, "evidence_sha256": result["body_sha256"],
                                 "note": "Pattern matches may be public keys or placeholders. Values are omitted; verify ownership and intended exposure."},
                                 "JavaScript static patterns", confidence="requires-validation")
                        candidates = [(value, "javascript") for value in re.findall(r'["\'](/[^"\'\s<>]{1,500})["\']', body)[:200]]
                    else:
                        candidates = []
                    for value, tag in candidates[:200]:
                        try:
                            link = clean_url(value, result["url"])
                            if not scope().allows(link):
                                continue
                            if link not in verified_urls:
                                save("urls", link, {"url": link, "discovered_by": tag, "verified": False}, "page extraction")
                            edge("url:" + result["url"], "url:" + link, "links_to")
                            if link not in verified_urls and re.search(r"/(api|graphql|swagger|openapi)(/|\.|$)", urlsplit(link).path, re.I):
                                save("apis", link, {"url": link, "classification": "candidate", "note": "Endpoint requires validation."}, "page extraction")
                            if crawl and depth < 2 and len(queue) < 100 and link not in seen:
                                queue.append((link, depth + 1))
                        except ValueError:
                            continue
                except Exception as exc:
                    warn(f"HTTP {url}", exc)
            if queue:
                warn(f"Crawl page limit reached for {host}.")
        if history and not cancel.is_set():
            progress("Historical URLs: " + history)
            try:
                urls, _ = engines.historical_urls(history, root, scope(), cancel)
            except Exception as exc:
                warn(f"Historical {history}", exc)
                urls = []
            for url in urls[:5000]:
                save("historical", url, {"url": url, "verified_current": url in verified_urls}, history, historical=True)
            if len(urls) > 5000:
                warn("Historical URL limit reached.")
        if ports is not None and not cancel.is_set():
            progress("Nmap service inventory: " + root)
            try:
                records, raw = engines.port_scan(root, scope(), ports, udp, cancel)
                evidence = repository.evidence(identifier, "nmap.xml", raw)
            except Exception as exc:
                warn("Nmap unavailable or incomplete", exc)
                records, evidence = {"records": [], "hosts": []}, None
            for row in records["records"]:
                key = f'{row["ip"]}:{row["protocol"]}:{row["port"]}'
                save("ports", key, {"host": row["ip"], "port": row["port"], "protocol": row["protocol"], "state": row["state"], "evidence": evidence}, "Nmap")
                save("services", key, {**row, "evidence": evidence}, "Nmap", confidence="engine-observed")
                edge("ip:" + row["ip"], "port:" + key, "exposes")
                edge("port:" + key, "service:" + key + ":" + row["service"], "runs")
                if row["product"]:
                    save("technologies", key, {"product": row["product"], "version": row["version"],
                         "cpe": row["cpe"], "lifecycle": "UNKNOWN", "note": "Validate version and distribution backports before assessing CVEs."}, "Nmap", confidence="engine-observed")
                    edge("service:" + key + ":" + row["service"], "technology:" + key, "reports")
            for row in records["hosts"]:
                if row["timed_out"]:
                    warn("Nmap host timed out; port inventory may be incomplete: " + row["ip"])
        if not hosts:
            warn("No active hosts authorized/discovered. Wildcard scope does not authorize its apex.")
        if lifecycle and not cancel.is_set():
            progress("Upstream release lifecycle lookup")
            from .intelligence import enrich
            warnings.extend(enrich(repository, identifier, cancel=cancel))
        if cve and not cancel.is_set():
            progress("NVD CPE candidate lookup")
            from .intelligence import enrich_cves
            warnings.extend(enrich_cves(repository, identifier, cancel=cancel))
    except KeyboardInterrupt:
        repository.finish(identifier, warnings + ["Interrupted by operator."], cancelled=True)
        raise
    except Exception as exc:
        warn("Workflow", exc)
        repository.finish(identifier, warnings, failed=True, cancelled=cancel.is_set())
        return identifier
    repository.finish(identifier, warnings, cancelled=cancel.is_set())
    return identifier
