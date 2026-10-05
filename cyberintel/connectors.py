"""Read-only public connectors. Never visits threat URLs or downloads payloads."""
import hashlib
import ipaddress
import json
import math
import re
import socket
import threading
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlsplit

import dns.resolver
import httpx

from .models import Result, ValidationError


def domain(value):
    value = value.strip().rstrip(".").encode("idna").decode().lower()
    if len(value) > 253 or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        raise ValidationError("Enter a valid fully qualified domain, without a URL or path.")
    return value


def indicator(value):
    value = value.strip()
    if value.startswith(("http://", "https://")):
        parts = urlsplit(value)
        if not parts.hostname or parts.username or parts.password or len(value) > 2048:
            raise ValidationError("Invalid indicator URL.")
        try:
            ipaddress.ip_address(parts.hostname)
        except ValueError:
            domain(parts.hostname)
        return "url", value
    try:
        ip = ipaddress.ip_address(value)
        return "IPv4" if ip.version == 4 else "IPv6", str(ip)
    except ValueError:
        return "domain", domain(value)


def email(value):
    value = value.strip()
    if len(value) > 254 or not re.fullmatch(r"[^\s@/]+@[^\s@/]+", value):
        raise ValidationError("Enter a valid email address.")
    local, host = value.rsplit("@", 1)
    return local + "@" + domain(host)


def public_address(host):
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        raise ValidationError("HTTP collection permits only public Internet addresses.")
    return addresses[0][4][0]


class MetadataParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title = ""
        self.meta = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag == "meta":
            key = attributes.get("name") or attributes.get("property")
            if key and attributes.get("content"):
                self.meta[key[:100]] = attributes["content"][:1000]

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title = (self.title + data)[:500]


class Collector:
    def __init__(self, config, store, keys=None, transport=None, sleeper=time.sleep):
        self.config, self.store = config, store
        self.keys = dict(keys or {})
        self.transport, self.sleep = transport, sleeper
        self._lock = threading.Lock()
        self._next_request = {}

    def _request(self, method, url, headers=None, data=None, not_found_empty=False, empty_payload=None):
        """Pin public address to prevent DNS rebinding; TLS still verifies original host."""
        original = url
        for redirect in range(5):
            parts = urlsplit(url)
            if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port not in (None, 443):
                raise ValidationError("Connector endpoints must use HTTPS on port 443 without credentials.")
            host = parts.hostname
            if self.transport is None:
                address = public_address(host)
                netloc = f"[{address}]" if ":" in address else address
                pinned = parts._replace(netloc=netloc).geturl()
            else:
                pinned = url  # deterministic injected test transport, never used by the UI
            request_headers = {"User-Agent": "CyberIntelSuite/0.1 (public intelligence)", "Host": host}
            request_headers.update(headers or {})
            with httpx.Client(timeout=self.config.timeout_seconds, trust_env=False,
                              follow_redirects=False, transport=self.transport) as client:
                for attempt in range(3):
                    with self._lock:
                        delay = self._next_request.get(host, 0) - time.monotonic()
                        if delay > 30:
                            raise RuntimeError(f"Rate limited; retry after {math.ceil(delay)} seconds.")
                        if delay > 0:
                            self.sleep(delay)
                        self._next_request[host] = time.monotonic() + (6 if "haveibeenpwned" in host else 1)
                    try:
                        with client.stream(method, pinned, headers=request_headers, data=data,
                                           extensions={"sni_hostname": host}) as response:
                            status = response.status_code
                            if status in (429, 500, 502, 503, 504):
                                if attempt == 2:
                                    raise RuntimeError(f"Source unavailable (HTTP {status}).")
                                retry = response.headers.get("Retry-After", "")
                                try:
                                    delay = float(retry)
                                except ValueError:
                                    try:
                                        from email.utils import parsedate_to_datetime
                                        delay = (parsedate_to_datetime(retry) - datetime.now(timezone.utc)).total_seconds()
                                    except (TypeError, ValueError):
                                        delay = 2 ** attempt
                                if not math.isfinite(delay) or delay < 0:
                                    delay = 2 ** attempt
                                with self._lock:
                                    self._next_request[host] = max(self._next_request.get(host, 0), time.monotonic() + delay)
                                if delay > 30:
                                    raise RuntimeError(f"Rate limited; retry after {int(delay)} seconds.")
                                self.sleep(max(0, delay))
                                continue
                            if status in (301, 302, 303, 307, 308):
                                destination = urljoin(url, response.headers.get("Location", ""))
                                if urlsplit(destination).hostname != host:
                                    if headers:
                                        raise RuntimeError("Authenticated cross-host redirect rejected.")
                                url = destination
                                break
                            if status == 404 and not_found_empty:
                                return ([] if empty_payload is None else empty_payload), original, {}
                            if status in (401, 403):
                                raise RuntimeError("Source requires a valid API key, subscription or verified domain.")
                            if status >= 400:
                                raise RuntimeError(f"Source returned HTTP {status}.")
                            body = bytearray()
                            for chunk in response.iter_bytes():
                                body.extend(chunk)
                                if len(body) > 8 * 1024 * 1024:
                                    raise RuntimeError("Source response exceeded 8 MiB limit.")
                            content_type = response.headers.get("content-type", "")
                            if "json" in content_type:
                                payload = json.loads(body)
                            else:
                                payload = body.decode("utf-8", errors="replace")
                            return payload, original, dict(response.headers)
                    except httpx.TransportError:
                        if attempt == 2:
                            raise RuntimeError("Network or TLS connection failed.") from None
                        self.sleep(2 ** attempt)
                else:
                    raise RuntimeError("Retry budget exhausted.")
        raise RuntimeError("Too many source redirects.")

    def endpoint(self, name):
        return self.config.endpoints[name].rstrip("/")

    def collect(self, source, target="", force=False):
        # Key fingerprint isolates cached privileged results when credentials change.
        scope = hashlib.sha256(json.dumps(self.keys, sort_keys=True).encode()).hexdigest()
        key = hashlib.sha256(json.dumps([source, target, scope, self.config.endpoints], sort_keys=True).encode()).hexdigest()
        cached = self.store.cache_get(key)
        if cached:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(cached.collected_at)).total_seconds()
            if not force and age < self.config.cache_seconds:
                cached.status = "cached"
                return cached
        try:
            result = self._collect(source, target)
            self.store.cache_put(key, result)
            return result
        except (RuntimeError, ValueError, socket.gaierror, dns.exception.DNSException, KeyError) as exc:
            if cached:
                cached.status, cached.freshness, cached.error = "cached", "stale", str(exc)
                return cached
            return Result(source, self.config.endpoints.get(source, ""), target, None,
                          status="unavailable", freshness="unknown", error=str(exc))

    def _collect(self, source, target):
        if source == "dns":
            host = domain(target)
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            records, errors = {}, {}
            for record_type in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"):
                try:
                    records[record_type] = [r.to_text() for r in resolver.resolve(host, record_type)]
                except dns.resolver.NoAnswer:
                    records[record_type] = []
                except dns.exception.DNSException as exc:
                    errors[record_type] = type(exc).__name__
            if not records:
                raise RuntimeError("DNS lookup failed: " + json.dumps(errors))
            return Result("DNS", "dns://" + ",".join(str(s) for s in resolver.nameservers), host,
                          {"records": records, "errors": errors})
        if source == "rdap":
            kind, target = indicator(target)
            if kind == "url":
                raise ValidationError("RDAP accepts a domain or IP address.")
            url = self.endpoint(source) + ("/ip/" if kind.startswith("IPv") else "/domain/") + quote(target, safe="")
            data, reference, _ = self._request("GET", url)
            if not isinstance(data, dict):
                raise RuntimeError("Malformed RDAP response.")
            return Result("RDAP", reference, target, data)
        if source == "ct":
            target = domain(target)
            try:
                return self._collect("ct_primary", target)
            except (RuntimeError, ValueError, socket.gaierror, KeyError) as primary_error:
                try:
                    result = self._collect("certspotter", target)
                    result.data["provider_errors"] = {"crt.sh": str(primary_error)}
                    return result
                except (RuntimeError, ValueError, socket.gaierror, KeyError) as fallback_error:
                    raise RuntimeError(f"Certificate sources unavailable. crt.sh: {primary_error}; Cert Spotter: {fallback_error}. Retry later; provider rate limits may apply.") from None
        if source in {"ct_primary", "certspotter"}:
            target = domain(target)
            truncated, warnings = False, []
            if source == "ct_primary":
                url = self.endpoint("ct") + "/?q=" + quote("%." + target) + "&output=json"
                data, ref, _ = self._request("GET", url)
                provider = "Certificate Transparency / crt.sh"
            else:
                url = self.endpoint("certspotter") + "/issuances?domain=" + quote(target) + "&include_subdomains=true&expand=dns_names"
                data, after, seen = [], "", set()
                provider, ref = "Certificate Transparency / Cert Spotter", url
                for page in range(5):
                    try:
                        batch, _, _ = self._request("GET", url + ("&after=" + quote(after, safe="") if after else ""))
                        if not isinstance(batch, list) or any(not isinstance(row, dict) or not isinstance(row.get("dns_names"), list)
                                or any(not isinstance(name, str) for name in row["dns_names"]) for row in batch):
                            raise RuntimeError("Malformed Cert Spotter response.")
                    except (RuntimeError, ValueError, socket.gaierror, KeyError) as exc:
                        if not data:
                            raise
                        truncated = True
                        warnings.append("Incomplete pagination: " + str(exc))
                        break
                    if not batch:
                        break
                    data.extend({"name_value": "\n".join(row["dns_names"])} for row in batch)
                    after = batch[-1].get("id")
                    if not isinstance(after, str) or not after or after in seen:
                        truncated = True
                        warnings.append("Provider omitted or repeated the pagination cursor.")
                        break
                    seen.add(after)
                else:
                    truncated = True
                    warnings.append("Stopped at the five-page request limit.")
            if isinstance(data, str):
                data = json.loads(data)
            if not isinstance(data, list) or any(not isinstance(row, dict) or not isinstance(row.get("name_value", ""), str) for row in data):
                raise RuntimeError("Malformed certificate transparency response.")
            names = set()
            concrete, wildcards = set(), set()
            for row in data:
                for name in row.get("name_value", "").splitlines():
                    wildcard = name.strip().startswith("*.")
                    try:
                        name = domain(name.strip().removeprefix("*."))
                    except ValueError:
                        continue
                    if name == target or name.endswith("." + target):
                        names.add(name)
                        (wildcards if wildcard else concrete).add(name)
            return Result(provider, ref, target,
                          {"subdomains": sorted(names), "certificate_count": len(data),
                           "concrete_names": sorted(concrete), "wildcard_patterns": ["*." + name for name in sorted(wildcards)],
                           "truncated": truncated, "warnings": warnings,
                           "note": "Certificate observations do not establish that a host is currently active."})
        if source == "website":
            target = domain(target)
            data, ref, headers = self._request("GET", "https://" + target + "/")
            if not isinstance(data, str) or "html" not in headers.get("content-type", ""):
                raise RuntimeError("The website did not return HTML.")
            parser = MetadataParser()
            parser.feed(data)
            return Result("Public website metadata", ref, target,
                          {"title": parser.title, "meta": parser.meta, "server": headers.get("server", ""),
                           "content_type": headers.get("content-type", "")})
        if source.startswith("hibp"):
            key = self.keys.get("hibp", "")
            headers = {"hibp-api-key": key} if key else {}
            if source == "hibp_catalog":
                url = self.endpoint("hibp") + "/breaches"
            else:
                if not key:
                    raise RuntimeError("HIBP exposure checks require an authorized API subscription key.")
                if source == "hibp_email":
                    target = email(target)
                    url = self.endpoint("hibp") + "/breachedaccount/" + quote(target, safe="") + "?truncateResponse=false"
                elif source == "hibp_domain":
                    target = domain(target)
                    url = self.endpoint("hibp") + "/breachedDomain/" + quote(target, safe="")
                else:
                    raise ValidationError("Unknown HIBP operation.")
            data, ref, _ = self._request("GET", url, headers=headers, not_found_empty=source != "hibp_catalog",
                                         empty_payload={} if source == "hibp_domain" else None)
            if source == "hibp_domain":
                if not isinstance(data, dict) or any(not isinstance(names, list) or any(not isinstance(name, str) for name in names) for names in data.values()):
                    raise RuntimeError("Malformed HIBP domain response.")
                # Store breach-name counts only; omit the returned private email aliases.
                counts = {}
                for names in data.values() if isinstance(data, dict) else []:
                    for name in names:
                        counts[name] = counts.get(name, 0) + 1
                data = {"breach_counts": counts, "affected_alias_count": len(data), "aliases_stored": False}
            else:
                if not isinstance(data, list) or any(not isinstance(row, dict) or not isinstance(row.get("Name"), str) for row in data):
                    raise RuntimeError("Malformed HIBP response.")
                fields = {"Name", "Title", "Domain", "BreachDate", "AddedDate", "ModifiedDate", "PwnCount", "Description", "DataClasses", "IsVerified"}
                data = [{k: v for k, v in row.items() if k in fields} for row in data]
                data.sort(key=lambda row: row.get("BreachDate", ""))
            return Result("Have I Been Pwned", ref, target or "public breach catalog", data)
        if source == "otx":
            kind, target = indicator(target)
            if not self.keys.get("otx"):
                raise RuntimeError("Configure an OTX API key.")
            url = self.endpoint(source) + "/indicators/" + kind + "/" + quote(target, safe="") + "/general"
            data, ref, _ = self._request("GET", url, headers={"X-OTX-API-KEY": self.keys["otx"]})
            if not isinstance(data, dict) or not isinstance(data.get("pulse_info", {}), dict):
                raise RuntimeError("Malformed OTX response.")
            count = data.get("pulse_info", {}).get("count", 0)
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise RuntimeError("Malformed OTX pulse count.")
            return Result("AlienVault OTX", ref, target,
                          {"severity": "medium" if count else "unknown", "rationale": f"{count} community pulse references; unverified association, not a verdict.", "indicator": data})
        if source in {"urlhaus", "urlhaus_recent"}:
            if not self.keys.get("urlhaus"):
                raise RuntimeError("URLhaus requires an Auth-Key.")
            if source == "urlhaus_recent":
                url = self.endpoint("urlhaus") + "/urls/recent/limit/100/"
                data, ref, _ = self._request("GET", url, headers={"Auth-Key": self.keys["urlhaus"]})
            else:
                kind, target = indicator(target)
                operation = "url" if kind == "url" else "host"
                url = self.endpoint("urlhaus") + "/" + operation + "/"
                data, ref, _ = self._request("POST", url, headers={"Auth-Key": self.keys["urlhaus"]}, data={operation: target})
            if not isinstance(data, dict):
                raise RuntimeError("Malformed URLhaus response.")
            status = data.get("query_status")
            if status not in {"ok", "no_results"}:
                raise RuntimeError("URLhaus rejected the query: " + str(status))
            entries = data.get("urls", [data] if data.get("url") else [])
            if not isinstance(entries, list) or any(not isinstance(row, dict) for row in entries):
                raise RuntimeError("Malformed URLhaus indicator list.")
            online = any(row.get("url_status") == "online" and row.get("threat") == "malware_download" for row in entries)
            # Explicit allowlist: metadata only; no payload URLs or sample records.
            fields = {"id", "url", "urlhaus_reference", "url_status", "host", "date_added", "threat", "tags"}
            normalized = [{k: v for k, v in row.items() if k in fields} for row in entries]
            return Result("URLhaus", ref, target or "recent public indicators",
                          {"severity": "high" if online else "medium" if normalized else "unknown",
                           "rationale": "Active malware distribution reported" if online else "Historical association" if normalized else "No source match; does not establish safety",
                           "query_status": status, "indicators": normalized})
        raise ValidationError("Unknown connector.")
