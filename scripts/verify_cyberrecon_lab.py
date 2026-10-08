#!/usr/bin/env python3
"""Exercise native collection and real Nmap against this script's loopback server."""
import argparse
import os
import re
import json
import shutil
import ssl
import sys
import threading
import tempfile
import ipaddress
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

class Handler(BaseHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            # Normal when a service-detection probe closes an idle connection.
            pass

    def do_GET(self):
        if self.path == "/app.js":
            content_type = "application/javascript"
            body = b'const endpoint="/api/status"; //# sourceMappingURL=app.js.map'
        elif self.path == "/openapi.json":
            content_type = "application/json"
            body = json.dumps({"openapi": "3.1.0", "paths": {"/api/status": {"get": {"parameters": [{"name": "query", "in": "query"}]}}}}).encode()
        elif self.path == "/api/status":
            content_type, body = "application/json", b'{"status":"synthetic lab"}'
        elif self.path == "/":
            content_type = "text/html"
            body = b'<h1>Synthetic CyberRecon lab</h1><script src="/app.js"></script><a href="/openapi.json">OpenAPI</a>'
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", default="artifacts/cyberrecon-lab")
    parser.add_argument("--no-nmap", action="store_true")
    parser.add_argument("--tls", action="store_true", help="Verify pinned HTTPS with an ephemeral script-owned lab certificate")
    parser.add_argument("--package", action="store_true", help="Exercise installed /usr/share/cyberrecon payload instead of source")
    parser.add_argument("--require-nmap", action="store_true", help="Fail instead of silently falling back when Nmap is absent")
    args = parser.parse_args()
    sys.path.insert(0, '/usr/share/cyberrecon' if args.package else str(Path(__file__).resolve().parent.parent))
    from cyberrecon.reporting import export_reports
    from cyberrecon.scanner import scan
    from cyberrecon.storage import Repository
    if args.package:
        import cyberrecon
        assert Path(cyberrecon.__file__).resolve().is_relative_to(Path('/usr/share/cyberrecon'))
    if args.require_nmap and (args.no_nmap or not shutil.which('nmap')):
        parser.error('Release qualification requires real Nmap.')
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    temporary = tempfile.TemporaryDirectory(prefix="cyberrecon-lab-cert-")
    ca_bundle = None
    if args.tls:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CyberRecon synthetic local lab")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
        ca_bundle = Path(temporary.name) / "certificate.pem"
        private = Path(temporary.name) / "private.pem"
        ca_bundle.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(ca_bundle), str(private))
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        repo = Repository(args.home)
        project = repo.create_project("Synthetic local lab", ["127.0.0.1"],
                                     authority="Loopback service created and owned by this verification script")
        use_nmap = not args.no_nmap and bool(shutil.which("nmap"))
        nmap_diagnostic = None
        if use_nmap:
            from cyberrecon.doctor import tool_status
            capabilities = []
            status = Path("/proc/self/status")
            if status.is_file():
                capabilities = [line for line in status.read_text().splitlines() if line.startswith(("CapEff:", "CapBnd:", "NoNewPrivs:"))]
            print(json.dumps({"nmap": tool_status("nmap", "Local TCP fixture"),
                              "effective_uid": os.geteuid() if hasattr(os, "geteuid") else None,
                              "capabilities": capabilities, "mode": "unprivileged TCP-connect; owned loopback only"}), flush=True)
            def nmap_diagnostic(record):
                # Only this script's fixed loopback fixture is logged; never env/key material.
                for name in ("stdout", "stderr"):
                    record[name] = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", record[name])
                print(json.dumps({"local_nmap_process": record}), flush=True)
        scheme = "https" if args.tls else "http"
        identifier = scan(repo, project, f"{scheme}://127.0.0.1:{server.server_port}/", crawl=True,
                          ports=str(server.server_port) if use_nmap else None, ca_bundle=ca_bundle,
                          nmap_unprivileged=True, nmap_diagnostic=nmap_diagnostic)
        snapshot = repo.snapshot(identifier)
        assert snapshot["http"] and snapshot["javascript"] and snapshot["apis"], snapshot["scan"]["warnings"]
        if use_nmap:
            assert any(row["state"] == "open" and row["port"] == server.server_port for row in snapshot["ports"]), snapshot["scan"]["warnings"]
        if args.tls:
            assert all(row["tls"] and row["tls"]["verified"] for row in snapshot["http"]), snapshot["scan"]["warnings"]
        directory = export_reports(repo, identifier, repo.home / "reports" / identifier)
        print(json.dumps({"scan": identifier, "status": snapshot["scan"]["status"], "real_nmap": use_nmap, "tls_verified": args.tls,
                          "counts": {kind: len(snapshot[kind]) for kind in ("http", "ports", "apis", "javascript")}, "reports": directory}, indent=2))
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
