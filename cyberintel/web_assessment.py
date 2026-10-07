"""Bounded, same-origin HTTPS configuration review for authorized public sites."""
import re
import socket
import ssl
import time
from collections import Counter
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urljoin, urlsplit

import httpx

from .connectors import public_address
from .models import Result, ValidationError

REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"


def target_url(value):
    value = value.strip()
    if not value.startswith("https://"):
        raise ValidationError("Enter a public HTTPS URL, for example https://example.com/.")
    try:
        parts = urlsplit(value)
        if not parts.hostname or parts.port not in (None, 443) or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError()
        if len(value) > 2048 or any(c.isspace() or ord(c) < 32 for c in value):
            raise ValueError()
        host = parts.hostname.encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        raise ValidationError("Use HTTPS/443 without credentials, query parameters or fragments.") from None
    netloc = f"[{host}]" if ":" in host else host
    return parts._replace(netloc=netloc, path=parts.path or "/").geturl()


def fetch(url, origin, transport=None, method="GET", extra_headers=None, deadline=None):
    if method not in {"GET", "OPTIONS"}:
        raise ValidationError("Web review only supports GET and OPTIONS.")
    for _ in range(4):
        remaining_time = (deadline - time.monotonic()) if deadline is not None else 10
        if remaining_time <= 0:
            raise ValidationError("Web assessment time budget exhausted; remaining checks were not completed.")
        url = target_url(url)
        parts = urlsplit(url)
        if parts.hostname != urlsplit(origin).hostname:
            raise ValidationError("Redirect leaves the authorized host. Assess that host separately.")
        if transport is None:
            address = public_address(parts.hostname)
            pinned = parts._replace(netloc=f"[{address}]" if ":" in address else address).geturl()
        else:
            pinned = url
        if deadline is not None:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise ValidationError("Web assessment time budget exhausted after address resolution.")
        with httpx.Client(transport=transport, timeout=min(10, remaining_time), trust_env=False, follow_redirects=False) as client:
            with client.stream(method, pinned, headers={"Host": parts.hostname, "User-Agent": "CyberIntelSuite/0.1 (authorized web review)", **(extra_headers or {})},
                               extensions={"sni_hostname": parts.hostname}) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise ValidationError("Redirect response has no Location header.")
                    url = urljoin(url, location)
                    continue
                body = bytearray()
                truncated = False
                for chunk in response.iter_bytes():
                    if deadline is not None and time.monotonic() >= deadline:
                        raise ValidationError("Web assessment time budget exhausted while reading a response.")
                    remaining = 256 * 1024 - len(body)
                    body.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
                return response.status_code, response.headers, body.decode("utf-8", errors="replace"), url, truncated
    raise ValidationError("Too many redirects during web review.")


def tls_details(host):
    address = public_address(host)
    context = ssl.create_default_context()
    with socket.create_connection((address, 443), timeout=5) as connection:
        with context.wrap_socket(connection, server_hostname=host) as secure:
            certificate = secure.getpeercert()
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), timezone.utc)
            return {"protocol": secure.version(), "cipher": secure.cipher()[0],
                    "expires_at": expires.isoformat(),
                    "days_remaining": int((expires - datetime.now(timezone.utc)).total_seconds() // 86400),
                    "hostname_and_chain_verified": True}


def header_findings(headers):
    rows = []
    def add(check, status, severity, evidence, recommendation):
        rows.append({"check": check, "status": status, "severity": severity,
                     "evidence": evidence, "recommendation": recommendation})
    hsts = headers.get("strict-transport-security", "")
    match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
    enabled = bool(match and int(match[1]) > 0)
    add("HSTS", "present" if enabled else "review", "info" if enabled else "review", hsts or "Missing",
        "Review a positive max-age policy after verifying HTTPS support." if not enabled else "Review policy duration and subdomain coverage.")
    csp = headers.get("content-security-policy", "")
    add("Content Security Policy", "present" if csp else "review", "info" if csp else "review", csp or "Missing",
        "Review an enforced CSP appropriate to the application's scripts and resources.")
    directives = {}
    duplicates = []
    for part in csp.split(";"):
        if part.strip():
            name, *sources = part.strip().split()
            name = name.lower()
            if name in directives:
                duplicates.append(name)
            directives.setdefault(name, sources)
    if duplicates:
        add("CSP duplicate directives", "review", "review", ", ".join(sorted(set(duplicates))),
            "Browsers use the first occurrence. Remove ambiguous duplicate directives.")
    if not csp and headers.get("content-security-policy-report-only"):
        add("CSP report-only mode", "observed", "review", "Report-only policy observed; no enforced CSP header",
            "Report-only policies monitor violations without enforcing them.")
    scripts = directives.get("script-src", directives.get("default-src", []))
    elements = directives.get("script-src-elem", scripts)
    broad = sorted(set(scripts + elements) & {"*", "http:", "https:", "'unsafe-inline'", "'unsafe-eval'"})
    if broad:
        add("CSP script sources", "review", "review", ", ".join(broad),
            "Review broad script permissions in context. Nonces/hashes and browser support affect inline-policy behavior; no XSS is confirmed.")
    frame = headers.get("x-frame-options", "").strip().lower()
    ancestors = directives.get("frame-ancestors")
    framed = bool(ancestors) and "*" not in ancestors if ancestors is not None else frame in {"deny", "sameorigin"}
    add("Framing protection", "present" if framed else "review", "info" if framed else "review",
        "CSP frame-ancestors present" if directives.get("frame-ancestors") else frame or "Missing",
        "Review frame-ancestors/X-Frame-Options according to embedding requirements.")
    nosniff = headers.get("x-content-type-options", "").strip().lower() == "nosniff"
    add("MIME sniffing protection", "present" if nosniff else "review", "info" if nosniff else "review",
        headers.get("x-content-type-options", "Missing"), "Use nosniff with correct response Content-Type values.")
    for header in ("referrer-policy", "permissions-policy"):
        value = headers.get(header, "")
        add(header, "present" if value else "review", "info" if value else "review", value or "Missing",
            "Review policy values against application requirements; presence alone does not validate the policy.")
    if headers.get("server") or headers.get("x-powered-by"):
        add("Server disclosure", "observed", "info",
            "; ".join(f"{key}: {headers[key]}" for key in ("server", "x-powered-by") if key in headers),
            "Review unnecessary version disclosures; banners do not prove a vulnerability.")
    for index, raw in enumerate(headers.get_list("set-cookie"), 1):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            cookie.clear()
        if not cookie:
            add(f"Cookie {index}", "review", "review", "Cookie attributes could not be parsed; value omitted", "Review cookie configuration manually.")
        for name, morsel in cookie.items():
            flags = {"Secure": bool(morsel["secure"]), "HttpOnly": bool(morsel["httponly"]), "SameSite": morsel["samesite"] or "missing"}
            complete = flags["Secure"] and flags["HttpOnly"] and str(flags["SameSite"]).lower() in {"lax", "strict", "none"}
            add("Cookie: " + name, "present" if complete else "review", "info" if complete else "review", str(flags),
                "Review attributes by cookie purpose. JavaScript-accessible cookies may intentionally omit HttpOnly; values are not stored.")
            if name.startswith("__Host-") and (not flags["Secure"] or morsel["path"] != "/" or morsel["domain"]):
                add("Cookie prefix: " + name, "review", "review", "__Host- requirements not satisfied",
                    "Use Secure, Path=/ and no Domain for __Host- cookies; cookie value omitted.")
            elif name.startswith("__Secure-") and not flags["Secure"]:
                add("Cookie prefix: " + name, "review", "review", "__Secure- without Secure", "Set Secure for __Secure- cookies.")
    return rows


def cors_findings(url, transport, deadline):
    probes = []
    for origin in ("https://cyberintel-check.invalid", "https://cyberintel-second.invalid"):
        status, headers, _, _, _ = fetch(url, url, transport, extra_headers={"Origin": origin}, deadline=deadline)
        if not 200 <= status < 300:
            raise ValidationError(f"CORS observation unavailable: HTTP {status}.")
        probes.append({"sent_origin": origin, "allowed_origin": headers.get("access-control-allow-origin", ""),
                       "allow_credentials": headers.get("access-control-allow-credentials", ""), "vary": headers.get("vary", "")})
    reflected = all(probe["allowed_origin"] == probe["sent_origin"] for probe in probes)
    credentials = any(probe["allow_credentials"].strip() == "true" for probe in probes)
    wildcard = any(probe["allowed_origin"] == "*" for probe in probes)
    review = reflected or (wildcard and credentials)
    recommendation = ("Two reserved test origins were reflected. Review origin allowlisting and sensitive responses; authenticated impact has not been tested."
                      if reflected else "Wildcard with credentials is rejected by browsers; review configuration, not proof of credential theft."
                      if wildcard and credentials else "Observed policy applies only to these unauthenticated GETs. Public wildcard sharing can be intentional.")
    return [{"check": "CORS origin policy", "status": "review" if review else "observed", "severity": "review" if review else "info",
             "evidence": str(probes), "recommendation": recommendation}], probes


def method_findings(url, transport, deadline):
    status, headers, _, _, _ = fetch(url, url, transport, method="OPTIONS", deadline=deadline)
    if not (200 <= status < 300 or status == 405):
        raise ValidationError(f"HTTP method observation unavailable: HTTP {status}.")
    advertised = headers.get("allow", "")
    methods = sorted({value.strip() for value in advertised.split(",") if re.fullmatch(r"[A-Z]{1,30}", value.strip())})
    attention = sorted(set(methods) & {"TRACE", "CONNECT", "PUT", "DELETE"})
    return [{"check": "Advertised HTTP methods", "status": "review" if attention else "observed", "severity": "review" if attention else "info",
             "evidence": ", ".join(methods) or "No Allow methods advertised",
             "recommendation": "Review method authorization and application requirements. OPTIONS advertises capabilities; no write, TRACE or CONNECT request was sent."}], methods


def assess_web(value, authorized=False, check_tls=True, check_security_txt=True, transport=None, tls_probe=None,
               check_cors=False, check_methods=False):
    if not authorized:
        raise ValidationError("Confirm you own this web application or have permission to assess it.")
    url = target_url(value)
    deadline = time.monotonic() + 120
    records, warnings, details = [], [], {}
    try:
        status, headers, _, final, truncated = fetch(url, url, transport, deadline=deadline)
        details.update(http_status=status, final_url=final, response_body_truncated=truncated)
        if 200 <= status < 300:
            records.extend(header_findings(headers))
        else:
            warnings.append(f"HTTP {status}: application-page header/cookie conclusions were skipped.")
    except (ValueError, OSError, httpx.HTTPError) as exc:
        warnings.append("HTTP assessment unavailable: " + str(exc))
    if check_tls:
        try:
            if time.monotonic() >= deadline:
                raise ValidationError("Assessment time budget exhausted before TLS check.")
            details["tls"] = (tls_probe or tls_details)(urlsplit(url).hostname)
            days = details["tls"]["days_remaining"]
            records.append({"check": "TLS certificate", "status": "verified" if days > 30 else "review", "severity": "info" if days > 30 else "review",
                            "evidence": f"Verified hostname/chain; expires {details['tls']['expires_at']}; {days} days remaining",
                            "recommendation": "Review renewal when close to expiry. This is one negotiated connection, not a TLS cipher-suite audit."})
        except (ValueError, OSError, KeyError) as exc:
            warnings.append("TLS certificate assessment unavailable: " + str(exc))
    if check_security_txt:
        endpoint = urlsplit(url)._replace(path="/.well-known/security.txt").geturl()
        try:
            status, headers, text, _, truncated = fetch(endpoint, url, transport, deadline=deadline)
            details["security_txt_status"] = status
            if status == 404:
                records.append({"check": "security.txt", "status": "not published", "severity": "info", "evidence": "HTTP 404", "recommendation": "Consider publishing vulnerability disclosure contacts."})
            elif status == 200 and "text/plain" in headers.get("content-type", "").lower() and not truncated:
                fields = {}
                for line in text.splitlines():
                    if ":" in line and not line.startswith("#"):
                        name, entry = line.split(":", 1)
                        fields.setdefault(name.strip().lower(), []).append(entry.strip())
                valid = any(entry.startswith(("mailto:", "https://")) and len(entry.split(":", 1)[1]) > 0
                            for entry in fields.get("contact", [])) and len(fields.get("expires", [])) == 1
                try:
                    expires = datetime.fromisoformat(fields["expires"][0].replace("Z", "+00:00"))
                    valid = valid and expires.tzinfo is not None and expires > datetime.now(timezone.utc)
                except (ValueError, KeyError, IndexError):
                    valid = False
                records.append({"check": "security.txt", "status": "present" if valid else "review", "severity": "info" if valid else "review",
                                "evidence": f"Contact entries: {len(fields.get('contact', []))}; nonexpired Expires: {valid}",
                                "recommendation": "Review RFC 9116 format and disclosure contacts; this is a basic field check, not full conformance validation."})
            else:
                warnings.append(f"security.txt not assessed: HTTP {status}, wrong content type or truncated body.")
        except (ValueError, OSError, httpx.HTTPError) as exc:
            warnings.append("security.txt assessment unavailable: " + str(exc))
    for enabled, label, operation, detail_key in ((check_cors, "CORS", cors_findings, "cors_observations"),
                                                  (check_methods, "HTTP methods", method_findings, "advertised_methods")):
        if enabled:
            try:
                findings, observation = operation(url, transport, deadline)
                records.extend(findings)
                details[detail_key] = observation
            except (ValueError, OSError, httpx.HTTPError) as exc:
                warnings.append(label + " assessment unavailable: " + str(exc))
    details["summary"] = {"findings": len(records), "review_items": sum(row["status"] == "review" for row in records),
                          "statuses": dict(Counter(row["status"] for row in records)), "warning_count": len(warnings)}
    details["selected_checks"] = {"headers_and_cookies": True, "tls": check_tls, "security_txt": check_security_txt,
                                  "cors": check_cors, "http_methods": check_methods}
    details.update(records=records, warnings=warnings, scope="Public HTTPS/443; same-host GET/optional OPTIONS; nominal 120-second request budget; no login, crawling or exploit payloads",
                   note="Configuration observations require analyst review. Missing headers are not proof of exploitable vulnerabilities; present headers are not proof of security.")
    return Result("Authorized web configuration assessment", REFERENCE, url, details,
                  status="live" if records else "unavailable", freshness="fresh" if records else "unknown",
                  error="; ".join(warnings) or None)
