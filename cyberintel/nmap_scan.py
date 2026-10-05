"""Bounded, explicit Nmap TCP inventory for authorized IP addresses."""
import ipaddress
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Result, ValidationError


def scan_arguments(targets, ports="", vulnerabilities=False):
    values = re.split(r"[\s,]+", targets.strip())
    try:
        addresses = list(dict.fromkeys(str(ipaddress.ip_address(value)) for value in values))
    except ValueError as exc:
        raise ValidationError("Enter individual IPv4 or IPv6 addresses separated by commas. No ranges or hostnames.") from exc
    if not 1 <= len(addresses) <= 16:
        raise ValidationError("Choose between 1 and 16 IP addresses.")
    families = {ipaddress.ip_address(value).version for value in addresses}
    if len(families) != 1:
        raise ValidationError("Scan IPv4 and IPv6 in separate batches.")
    if any(ipaddress.ip_address(value).is_multicast or ipaddress.ip_address(value).is_unspecified for value in addresses):
        raise ValidationError("Multicast and unspecified addresses cannot be scanned.")
    args = ["-sT", "-sV", "--version-light", "-n", "-Pn", "-T3", "--max-retries", "1",
            "--host-timeout", "120s", "--script-timeout", "30s"]
    if families == {6}:
        args.append("-6")
    if ports.strip():
        selected = set()
        for part in ports.strip().split(","):
            if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", part.strip()):
                raise ValidationError("Ports must be numbers or ranges, for example 22,80,443,8000-8010.")
            bounds = [int(value) for value in part.split("-")]
            start, end = bounds[0], bounds[-1]
            if not 1 <= start <= end <= 65535 or end - start >= 1000:
                raise ValidationError("Select valid ports from 1 to 65535, at most 1000 total.")
            selected.update(range(start, end + 1))
        if len(selected) > 1000:
            raise ValidationError("Select at most 1000 ports.")
        args += ["-p", ",".join(str(port) for port in sorted(selected))]
    else:
        args += ["--top-ports", "100"]
    if vulnerabilities:
        args += ["--script", "vulners"]
    return args, addresses


def parse_scan(payload):
    if len(payload) > 16 * 1024 * 1024 or b"<!ENTITY" in payload.upper():
        raise ValidationError("Nmap output exceeds limits or contains XML entities.")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ValidationError("Nmap did not produce valid XML output.") from exc
    if root.tag != "nmaprun":
        raise ValidationError("This is not Nmap XML output.")
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValidationError("Nmap scan did not finish successfully.")
    records, hosts = [], []
    for host in root.findall("host"):
        addresses = [a.get("addr", "") for a in host.findall("address") if a.get("addrtype") in {"ipv4", "ipv6"}]
        address = ", ".join(addresses)
        hosts.append({"ip": address, "status": host.find("status").get("state", "unknown") if host.find("status") is not None else "unknown",
                      "timed_out": host.get("timedout") == "true",
                      "port_summary": [item.attrib for item in host.findall("ports/extraports")]})
        for port in host.findall("ports/port"):
            try:
                port_number = int(port.get("portid", ""))
                if not 1 <= port_number <= 65535:
                    raise ValueError()
            except ValueError:
                raise ValidationError("Nmap returned an invalid port number.") from None
            service = port.find("service")
            state = port.find("state")
            attrs = service.attrib if service is not None else {}
            scripts = [{"id": item.get("id"), "output": item.get("output", "")} for item in port.findall("script")]
            records.append({"ip": address, "port": port_number, "protocol": port.get("protocol"),
                            "state": state.get("state", "unknown") if state is not None else "unknown",
                            "service": attrs.get("name", "unknown"), "product": attrs.get("product", ""),
                            "version": attrs.get("version", ""), "extra_info": attrs.get("extrainfo", ""),
                            "tunnel": attrs.get("tunnel", ""), "os_hint": attrs.get("ostype", ""),
                            "confidence": attrs.get("conf", ""), "detection_method": attrs.get("method", ""),
                            "cpe": [item.text for item in service.findall("cpe")] if service is not None else [],
                            "script_findings": scripts})
    return {"records": records, "hosts": hosts, "nmap_version": root.get("version", ""),
            "note": "Service versions and OS hints are observations, not proof. Vulners matches are potential vulnerabilities requiring validation; no matches does not establish safety. Host timeouts can leave incomplete results. UDP and full OS fingerprinting are not included."}


def scan_ips(targets, ports="", vulnerabilities=False, authorized=False):
    if not authorized:
        raise ValidationError("Confirm you own these systems or have permission to scan them.")
    args, addresses = scan_arguments(targets, ports, vulnerabilities)
    executable = shutil.which("nmap")
    if not executable:
        raise ValidationError("Nmap is not installed or is missing from PATH. Install Nmap from nmap.org/download.html and restart the app.")
    with tempfile.TemporaryDirectory(prefix="cyberintel-nmap-") as directory:
        output = Path(directory) / "scan.xml"
        with (Path(directory) / "stderr.txt").open("wb") as error_file:
            try:
                process = subprocess.run([executable, *args, "-oX", str(output), *addresses],
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=error_file, timeout=180 * len(addresses), shell=False)
            except subprocess.TimeoutExpired as exc:
                raise ValidationError("Nmap exceeded the scan time limit. Reduce targets or ports and retry.") from exc
            except OSError as exc:
                raise ValidationError("Unable to launch Nmap. Check its installation.") from exc
        if process.returncode != 0:
            with (Path(directory) / "stderr.txt").open("rb") as error_file:
                detail = error_file.read(2000).decode("utf-8", errors="replace")
            raise ValidationError("Nmap failed: " + detail)
        if not output.exists() or output.stat().st_size > 16 * 1024 * 1024:
            raise ValidationError("Nmap output is missing or exceeds the size limit.")
        data = parse_scan(output.read_bytes())
    data.update(targets=addresses, options=args, vulnerability_lookup=vulnerabilities,
                external_disclosure="Service/version/CPE sent by vulners to vulners.com" if vulnerabilities else "None")
    return Result("Nmap active TCP scan", "https://nmap.org/", ", ".join(addresses), data)
