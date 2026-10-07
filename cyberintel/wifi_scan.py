"""Bounded local IPv4 discovery; Wi-Fi association lists require router access."""
import csv
import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Result, ValidationError
from .nmap_scan import parse_scan
from .output import atomic_output
from .reporting import csv_safe

NOTE = ("Counts show responding IPv4 devices on the scanned Wi-Fi/LAN, including this computer and the router when detected. "
        "Wired devices may be included, and one device can have multiple IP addresses. Sleeping devices, firewalls and Wi-Fi client isolation can hide devices. "
        "MAC addresses are available only when exposed on the local network; unavailable values are not guessed. "
        "Use your router's client list for the authoritative list of associated Wi-Fi clients.")


def local_networks():
    """Read active Linux interfaces without sending traffic."""
    executable = shutil.which("ip")
    if not executable:
        raise ValidationError("Automatic detection needs Linux iproute2. Enter your local IPv4 subnet manually, for example 192.168.1.0/24.")
    try:
        process = subprocess.run([executable, "-j", "-4", "address", "show", "up"],
                                 capture_output=True, timeout=10, check=False, shell=False)
        if process.returncode or len(process.stdout) > 1024 * 1024:
            raise ValueError()
        interfaces = json.loads(process.stdout)
        if not isinstance(interfaces, list):
            raise ValueError()
        networks = []
        for interface in interfaces:
            for address in interface.get("addr_info", []):
                if address.get("family") != "inet":
                    continue
                local = ipaddress.IPv4Interface(f"{address['local']}/{address['prefixlen']}")
                try:
                    network = discovery_network(str(local.network))
                except ValidationError:
                    # Keep detection useful on larger LANs while retaining scan limits.
                    try:
                        network = discovery_network(str(ipaddress.IPv4Network(f"{local.ip}/24", strict=False)))
                    except ValidationError:
                        continue
                networks.append({"network": str(network), "interface": interface["ifname"],
                                 "ip": str(local.ip), "mac": normalize_mac(interface.get("address", ""))})
                if network != local.network:
                    networks[-1]["detected_network"] = str(local.network)
                    networks[-1]["scope_note"] = "Suggested /24 batch within a larger local network; other batches are not scanned."
        return networks
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, KeyError, AttributeError):
        raise ValidationError("Unable to read local interfaces. Enter your local IPv4 subnet manually.") from None


def discovery_network(value):
    try:
        if "/" not in value:
            raise ValueError()
        network = ipaddress.IPv4Network(value.strip(), strict=False)
    except ValueError:
        raise ValidationError("Enter an IPv4 subnet with a prefix, for example 192.168.1.0/24.") from None
    private_ranges = [ipaddress.IPv4Network(prefix) for prefix in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if not any(network.subnet_of(private) for private in private_ranges):
        raise ValidationError("Device discovery accepts only private local IPv4 subnets (10.x, 172.16–31.x or 192.168.x).")
    if network.num_addresses > 1024:
        raise ValidationError("Scan at most 1,024 addresses per batch: /22 or a smaller subnet.")
    return network


def normalize_mac(value):
    value = str(value).replace("-", ":").upper()
    return value if re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", value) and value != "00:00:00:00:00:00" else ""


def neighbor_macs():
    """Optional Linux neighbor cache; enrich only hosts that answered this scan."""
    executable = shutil.which("ip")
    if not executable:
        return {}
    try:
        process = subprocess.run([executable, "-j", "-4", "neigh", "show"],
                                 capture_output=True, timeout=10, check=False, shell=False)
        if process.returncode or len(process.stdout) > 1024 * 1024:
            return {}
        rows = json.loads(process.stdout)
        result = {}
        for row in rows:
            if set(row.get("state", [])) & {"FAILED", "INCOMPLETE"}:
                continue
            mac = normalize_mac(row.get("lladdr", ""))
            if mac:
                result[str(ipaddress.IPv4Address(row["dst"]))] = mac
        return result
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, KeyError, AttributeError):
        return {}


def parse_devices(payload, network):
    # Reuse the bounded XML/entity and successful-run validation of the scan adapter.
    parse_scan(payload)
    records = {}
    for host in ET.fromstring(payload).findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up" or host.get("timedout") == "true":
            continue
        mac_node = next((node for node in host.findall("address") if node.get("addrtype") == "mac"), None)
        mac = normalize_mac(mac_node.get("addr", "")) if mac_node is not None else ""
        for node in host.findall("address"):
            if node.get("addrtype") != "ipv4":
                continue
            try:
                address = ipaddress.IPv4Address(node.get("addr", ""))
            except ValueError:
                raise ValidationError("Nmap returned an invalid device IP address.") from None
            if address not in network:
                raise ValidationError("Nmap returned a device outside the selected subnet.")
            records[str(address)] = {"ip": str(address), "mac": mac or "Unavailable",
                                     "vendor": mac_node.get("vendor", "") if mac_node is not None else "",
                                     "status": "up", "discovery_reason": status.get("reason", ""),
                                     "mac_source": "Nmap" if mac else "unavailable"}
    return sorted(records.values(), key=lambda row: int(ipaddress.IPv4Address(row["ip"])))


def scan_devices(subnet, authorized=False):
    if not authorized:
        raise ValidationError("Confirm you own this Wi-Fi/LAN or have permission to discover its devices.")
    network = discovery_network(subnet)
    executable = shutil.which("nmap")
    if not executable:
        raise ValidationError("Nmap is required for device discovery. Install Nmap and restart the application.")
    options = ["-sn", "-n", "--max-retries", "1", "--host-timeout", "5s"]
    with tempfile.TemporaryDirectory(prefix="cyberintel-devices-") as directory:
        output = Path(directory) / "devices.xml"
        with (Path(directory) / "stderr.txt").open("wb") as errors:
            try:
                process = subprocess.run([executable, *options, "-oX", str(output), str(network)],
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=errors, timeout=120, shell=False)
            except subprocess.TimeoutExpired:
                raise ValidationError("Device discovery exceeded 120 seconds. Choose a smaller subnet.") from None
            except OSError:
                raise ValidationError("Unable to launch Nmap. Check its installation.") from None
        if process.returncode:
            raise ValidationError("Nmap device discovery failed. Check network access and Nmap permissions.")
        if not output.is_file() or output.stat().st_size > 16 * 1024 * 1024:
            raise ValidationError("Nmap discovery output is missing or exceeds the size limit.")
        records = parse_devices(output.read_bytes(), network)
    neighbors = neighbor_macs()
    try:
        own = {row["ip"]: row["mac"] for row in local_networks() if row["mac"]}
    except ValidationError:
        own = {}
    for row in records:
        if row["mac"] == "Unavailable":
            mac = own.get(row["ip"]) or neighbors.get(row["ip"])
            if mac:
                row.update(mac=mac, mac_source="local interface" if row["ip"] in own else "neighbor cache (may be stale)")
    return Result("Nmap Wi-Fi/LAN device discovery", "https://nmap.org/", str(network),
                  {"network": str(network), "device_count": len(records),
                   "mac_available_count": sum(row["mac"] != "Unavailable" for row in records),
                   "records": records, "options": options, "note": NOTE})


def export_devices(result, destination):
    if not isinstance(result.data, dict) or "records" not in result.data:
        raise ValidationError("Discover devices before exporting.")
    fields = ["ip", "mac", "vendor", "status", "discovery_reason", "mac_source", "network", "observed_at"]
    with atomic_output(destination) as temporary, temporary.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for row in result.data["records"]:
            row = {**row, "network": result.query, "observed_at": result.collected_at}
            writer.writerow({field: csv_safe(row.get(field, "")) for field in fields})
    return str(destination)
