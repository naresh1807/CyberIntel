import hashlib
import ipaddress
import queue
import re
import socket
import ssl
import threading
import time
import zlib
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

import httpx

from cyberintel.models import ValidationError

_resolution_slots = threading.BoundedSemaphore(4)


def resolve_addresses(host, port, cancel=None, timeout=5):
    """Bound libc resolution without growing an unbounded pool of stuck threads.

    A timed-out libc call cannot be killed safely; at most four daemon calls can
    remain in flight, and subsequent requests fail closed when capacity is full.
    """
    if not _resolution_slots.acquire(blocking=False):
        raise ValidationError("DNS resolution concurrency limit reached.")
    result = queue.Queue(maxsize=1)
    def resolve():
        try:
            result.put((True, socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except Exception as exc:
            result.put((False, exc))
        finally:
            _resolution_slots.release()
    threading.Thread(target=resolve, daemon=True).start()
    deadline = time.monotonic() + timeout
    while True:
        if cancel and cancel.is_set():
            raise ValidationError("Scan cancelled.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("DNS resolution timed out.")
        try:
            successful, value = result.get(timeout=min(.05, remaining))
        except queue.Empty:
            continue
        if not successful:
            raise value
        return value


def tls_metadata(response):
    stream = response.extensions.get("network_stream")
    if not stream:
        return None
    try:
        ssl_object = stream.get_extra_info("ssl_object")
        if not ssl_object:
            return None
        certificate = ssl_object.getpeercert()
        return {"verified": True, "protocol": ssl_object.version(), "cipher": ssl_object.cipher()[0],
                "certificate_sha256": hashlib.sha256(ssl_object.getpeercert(True)).hexdigest(),
                "not_before": certificate.get("notBefore"), "not_after": certificate.get("notAfter")}
    except (AttributeError, OSError, ValueError, TypeError, IndexError):
        # Optional transport metadata must not discard a valid HTTP observation.
        return None


def clean_url(value, base=None):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in value):
        raise ValidationError("Invalid URL.")
    parts = urlsplit(urljoin(base, value) if base else value)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise ValidationError("Only HTTP(S) URLs without credentials are supported.")
    if len(value) > 4096 or any(ord(c) < 32 or c.isspace() for c in value):
        raise ValidationError("Invalid URL.")
    try:
        port = parts.port
    except ValueError:
        raise ValidationError("Invalid URL port.") from None
    if port is not None and not 1 <= port <= 65535:
        raise ValidationError("Invalid HTTP port.")
    from .scope import host_of
    host = host_of(parts.hostname)
    if port == (443 if parts.scheme == "https" else 80):
        port = None
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc += ":" + str(port)
    # Retain parameter names, never values, including in scheduled requests.
    query = urlencode([(key, "") for key in sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True)})])
    return parts._replace(netloc=netloc, path=parts.path or "/", query=query, fragment="").geturl()


class ScopedHTTP:
    def __init__(self, scope_loader, rate=2, max_requests=100, transport=None, cancel=None, verify=True):
        self.scope_loader = scope_loader
        self.rate = max(1, min(10, rate))
        self.maximum = max(1, min(500, max_requests))
        self.transport, self.cancel = transport, cancel or threading.Event()
        if verify is not True and (not isinstance(verify, ssl.SSLContext) or not verify.check_hostname or verify.verify_mode != ssl.CERT_REQUIRED):
            raise ValidationError("TLS certificate and hostname verification cannot be disabled.")
        self.verify = verify
        self.lock = threading.Lock()
        self.count, self.next_request = 0, 0

    def slot(self):
        with self.lock:
            if self.cancel.is_set():
                raise ValidationError("Scan cancelled.")
            if self.count >= self.maximum:
                raise ValidationError("Scan HTTP request budget exhausted.")
            self.count += 1
            delay = max(0, self.next_request - time.monotonic())
            if self.cancel.wait(delay):
                raise ValidationError("Scan cancelled.")
            self.next_request = time.monotonic() + 1 / self.rate

    def fetch(self, value, method="GET", parameters=None, request_headers=None):
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValidationError("Unsupported reconnaissance method.")
        url, redirects = clean_url(value), []
        extra = dict(request_headers or {})
        if any(key.lower() not in {"authorization", "accept", "x-organization-id"} for key in extra):
            raise ValidationError("Unsupported provider request header.")
        if any(not isinstance(value, str) or len(value) > 8192 or "\r" in value or "\n" in value for value in extra.values()):
            raise ValidationError("Invalid provider header value.")
        query = urlencode(parameters) if parameters else None
        if query:
            url = clean_url(urlsplit(url)._replace(query=query).geturl())
        for step in range(5):
            self.slot()
            scope = self.scope_loader()
            host = scope.require(url)
            parts = urlsplit(url)
            wire_parts = parts._replace(query=query) if query is not None and step == 0 else parts
            pinned = wire_parts.geturl()
            if self.transport is None:
                try:
                    ipaddress.ip_address(host)
                    dns_host = host
                except ValueError:
                    dns_host = host + "."
                addresses = resolve_addresses(dns_host, parts.port or (443 if parts.scheme == "https" else 80), self.cancel)
                scope = self.scope_loader()
                scope.require(url)
                if not addresses:
                    raise ValidationError("No connection address found.")
                for address in addresses:
                    ip = ipaddress.ip_address(address[4][0])
                    if scope.denies(str(ip)):
                        raise ValidationError("Resolved address is explicitly excluded: " + str(ip))
                    if not ip.is_global:
                        # Private/lab destinations need separate explicit IP authorization.
                        scope.require(str(ip))
                    if ip.is_multicast or ip.is_unspecified:
                        raise ValidationError("Multicast/unspecified connection addresses are prohibited.")
                selected = next((row[4][0] for row in addresses if row[0] == socket.AF_INET), addresses[0][4][0])
                netloc = f"[{selected}]" if ":" in selected else selected
                netloc += ":" + str(parts.port or (443 if parts.scheme == "https" else 80))
                pinned = wire_parts._replace(netloc=netloc).geturl()
            with httpx.Client(timeout=10, verify=self.verify, trust_env=False, follow_redirects=False, transport=self.transport) as client:
                with client.stream(method, pinned, headers={"Host": parts.netloc, "User-Agent": "CyberRecon/0.2 authorized recon", "Accept-Encoding": "identity", **extra},
                                   extensions={"sni_hostname": host}) as response:
                    tls = tls_metadata(response) if parts.scheme == "https" else None
                    if response.status_code in {301, 302, 303, 307, 308}:
                        if not response.headers.get("location"):
                            raise ValidationError("Redirect has no destination.")
                        destination = clean_url(response.headers.get("location", ""), url)
                        scope.require(destination)
                        def origin(parsed):
                            return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
                        if (extra or query) and origin(urlsplit(destination)) != origin(parts):
                            raise ValidationError("Provider credentials/parameters cannot follow cross-host redirects.")
                        if parts.scheme == "https" and urlsplit(destination).scheme != "https":
                            raise ValidationError("TLS downgrade redirect blocked.")
                        redirects.append({"from": url, "to": destination, "status": response.status_code})
                        url = destination
                        continue
                    body = bytearray()
                    truncated = False
                    deadline = time.monotonic() + 20
                    encoding = response.headers.get("content-encoding", "").strip().lower()
                    if encoding not in {"", "identity", "gzip"}:
                        raise ValidationError("Unsupported response compression; identity encoding was requested.")
                    cached = self.transport is not None and response.is_stream_consumed
                    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" and not cached else None
                    chunks = [response.content] if cached else response.iter_raw()
                    raw_bytes = 0
                    for chunk in chunks:
                        if self.cancel.is_set():
                            raise ValidationError("Scan cancelled.")
                        if time.monotonic() > deadline:
                            raise ValidationError("Response body duration limit reached.")
                        raw_available = 512 * 1024 - raw_bytes
                        raw_bytes += len(chunk)
                        raw_truncated = len(chunk) > raw_available
                        chunk = chunk[:raw_available]
                        available = 512 * 1024 - len(body)
                        if decoder:
                            chunk = decoder.decompress(chunk, available + 1)
                        body.extend(chunk[:available])
                        if len(chunk) > available or raw_truncated or decoder and decoder.unused_data:
                            truncated = True
                            break
                    if decoder and not truncated and not decoder.eof:
                        raise ValidationError("Incomplete gzip response.")
                    allow = {"content-type", "server", "x-powered-by", "strict-transport-security", "content-security-policy",
                             "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "allow", "www-authenticate"}
                    headers = {k: v for k, v in response.headers.items() if k in allow}
                    if "www-authenticate" in headers:
                        headers["www-authenticate"] = headers["www-authenticate"].split(" ", 1)[0]
                    if "content-security-policy" in headers:
                        headers["content-security-policy"] = re.sub(r"'nonce-[^']+'", "'nonce-[redacted]'", headers["content-security-policy"], flags=re.I)
                    return {"url": url, "status_code": response.status_code, "headers": headers, "tls": tls,
                            "redirect_chain": redirects, "body_sha256": hashlib.sha256(body).hexdigest(),
                            "bytes_read": len(body), "truncated": truncated, "text": body.decode("utf-8", errors="replace"),
                            "cookie_headers": response.headers.get_list("set-cookie")}
        raise ValidationError("Redirect limit reached.")
