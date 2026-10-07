"""Controlled external engine adapters and normalized imports."""
import json
import ipaddress
import os
import re
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path

from cyberintel.models import ValidationError
from cyberintel.nmap_scan import parse_scan, scan_arguments
from .scope import host_of

TOOLS = {"subfinder": "Passive discovery adapter", "assetfinder": "Passive discovery adapter",
         "amass": "Passive discovery adapter (v3 CLI; verify installed version)", "nmap": "TCP/UDP service adapter",
         "ffuf": "Controlled content adapter", "whatweb": "Fingerprint adapter",
         "gau": "Historical URL adapter", "waybackurls": "Historical URL adapter",
         "dnsx": "Optional normalized JSONL import", "httpx": "ProjectDiscovery JSONL import (not Python httpx CLI)",
         "naabu": "Optional normalized JSONL import", "katana": "Optional normalized JSONL import",
         "gobuster": "Planned integration (not implemented)"}


def run_process(args, input_bytes=None, timeout=120, cancel=None):
    executable = shutil.which(args[0])
    if not executable:
        raise ValidationError(args[0] + " is not installed or not on PATH.")
    # Direct argv only. No user supplied extra flags, shell commands or proxy inheritance.
    environment = {key: value for key, value in os.environ.items() if key.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as stdin:
        if input_bytes:
            stdin.write(input_bytes)
            stdin.seek(0)
        process = subprocess.Popen([executable, *args[1:]], stdin=stdin, stdout=output, stderr=errors, env=environment,
                                   shell=False, start_new_session=os.name == "posix")
        def stop():
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait()
        import time
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if (cancel and cancel.is_set()) or time.monotonic() >= deadline or output.seek(0, 2) > 16 * 1024 * 1024 or errors.seek(0, 2) > 16 * 1024 * 1024:
                    stop()
                    raise ValidationError(args[0] + " cancelled, timed out or exceeded output limits.")
                time.sleep(.1)
            if process.returncode:
                raise ValidationError(args[0] + " failed; verify its version, provider configuration and permissions.")
            if output.seek(0, 2) > 16 * 1024 * 1024:
                raise ValidationError("Tool output exceeds 16 MiB.")
            output.seek(0)
            return output.read()
        finally:
            if process.poll() is None:
                stop()


def passive_domains(engine, target, scope, cancel=None):
    target = scope.require(target, passive=True)
    try:
        ipaddress.ip_address(target)
    except ValueError:
        is_ip = False
    else:
        is_ip = True
    if is_ip:
        raise ValidationError("Passive enumeration needs a domain.")
    if engine == "ct":
        from types import SimpleNamespace
        from cyberintel.connectors import Collector
        config = SimpleNamespace(timeout_seconds=5, endpoints={"ct": "https://crt.sh", "certspotter": "https://api.certspotter.com/v1"})
        result = Collector(config, None)._collect("ct", target)
        if cancel and cancel.is_set():
            raise ValidationError("Certificate collection cancelled.")
        names = [host for host in result.data["concrete_names"] if scope.allows(host)]
        metadata = {"source": result.source, "reference": result.reference,
                    "warnings": result.data["warnings"], "truncated": result.data["truncated"]}
        return names, json.dumps(metadata).encode()
    commands = {"subfinder": ["subfinder", "-d", target, "-silent", "-duc", "-rl", "2", "-timeout", "10", "-max-time", "1"],
                "assetfinder": ["assetfinder", "--subs-only", target],
                "amass": ["amass", "enum", "-passive", "-d", target, "-timeout", "1"]}
    if engine not in commands:
        raise ValidationError("Unsupported passive engine.")
    raw = run_process(commands[engine], cancel=cancel)
    names = set()
    for line in raw.decode("utf-8", errors="replace").splitlines():
        try:
            host = host_of(line)
            if scope.allows(host) and (host == target or host.endswith("." + target)):
                names.add(host)
        except ValueError:
            continue
    return sorted(names), raw


def port_scan(target, scope, ports="", udp=False, cancel=None):
    scope.require(target)
    # Strict IP-only target; DNS resolution never implicitly authorizes Nmap.
    args, addresses = scan_arguments(target, ports)
    for address in addresses:
        scope.require(address)
    if udp:
        args[args.index("-sT")] = "-sU"
        if os.name == "posix" and os.geteuid() != 0:
            raise ValidationError("UDP Nmap requires appropriate privileges; CyberRecon does not elevate itself.")
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "nmap.xml"
        run_process(["nmap", *args, "-oX", str(output), *addresses], timeout=180, cancel=cancel)
        if not output.exists() or output.stat().st_size > 16 * 1024 * 1024:
            raise ValidationError("Nmap output missing or oversized.")
        payload = output.read_bytes()
    return parse_scan(payload), payload


def historical_urls(engine, target, scope, cancel=None):
    target = scope.require(target, passive=True)
    if engine == "gau":
        raw = run_process(["gau", "--threads", "1", "--timeout", "10", target], cancel=cancel)
    elif engine == "waybackurls":
        raw = run_process(["waybackurls"], (target + "\n").encode(), cancel=cancel)
    else:
        raise ValidationError("Unsupported historical URL engine.")
    from .network import clean_url
    urls = set()
    for value in raw.decode(errors="replace").splitlines():
        try:
            value = clean_url(value)
            if scope.allows(value):
                urls.add(value)
        except ValueError:
            continue
    # Historical raw URLs can contain credentials/tokens; preserve sanitized output only.
    return sorted(urls), ("\n".join(sorted(urls))).encode()


def fingerprint(url, scope, cancel=None):
    scope.require(url)
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "whatweb.json"
        run_process(["whatweb", "--aggression=1", "--follow-redirect=never", "--no-cookies", "--max-threads=1",
                     "--open-timeout=5", "--read-timeout=10", "--log-json=" + str(output), url], cancel=cancel)
        if not output.exists() or output.stat().st_size > 16 * 1024 * 1024:
            raise ValidationError("WhatWeb output missing or oversized.")
        data = json.loads(output.read_text())
    records = []
    for page in data:
        for product, fields in page.get("plugins", {}).items():
            # Do not retain plugin strings/cookies/config literals which may contain secrets.
            records.append({"product": product, "version": ", ".join(str(value) for value in fields.get("version", [])), "url": url})
    return records


def content_scan(url, scope, words, rate=2, cancel=None):
    from .network import clean_url
    url = clean_url(url)
    scope.require(url)
    words = list(dict.fromkeys(word.strip().lstrip("/") for word in words if word.strip()))
    if not 1 <= len(words) <= 200 or any(not re.fullmatch(r"[a-zA-Z0-9_./-]{1,100}", word) or ".." in word for word in words):
        raise ValidationError("Use 1–200 relative paths with no traversal, query or hostname fuzzing.")
    with tempfile.TemporaryDirectory() as directory:
        wordlist, output = Path(directory) / "words.txt", Path(directory) / "ffuf.json"
        wordlist.write_text("\n".join(words))
        # Redirects are disabled. Only the path FUZZ placeholder is allowed.
        run_process(["ffuf", "-u", url.split("?", 1)[0].rstrip("/") + "/FUZZ", "-w", str(wordlist),
                     "-rate", str(max(1, min(10, rate))), "-t", "2", "-timeout", "10", "-maxtime", "120", "-noninteractive",
                     "-mc", "all", "-fc", "404", "-of", "json", "-o", str(output)], cancel=cancel, timeout=130)
        if not output.exists() or output.stat().st_size > 16 * 1024 * 1024:
            raise ValidationError("ffuf output missing or oversized.")
        payload = json.loads(output.read_text())
    records = []
    for row in payload.get("results", []):
        target = clean_url(row["url"])
        scope.require(target)
        records.append({"url": target, "status_code": row["status"], "length": row["length"],
                        "note": "May be a soft-404 or wildcard response; not proof of exposed content."})
    return records
