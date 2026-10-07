"""Read existing provider observations for explicitly authorized public IPs."""
import ipaddress
import json
import os
import uuid

from .network import ScopedHTTP
from .scope import Scope


def host_lookup(repository, project, target, provider, transport=None, cancel=None):
    address = str(ipaddress.ip_address(target.strip()))
    repository.scope(project).require(address)
    if not ipaddress.ip_address(address).is_global:
        raise ValueError("External host intelligence requires an authorized public IP.")
    if provider == "shodan":
        key = os.environ.get("SHODAN_API_KEY", "")
        if not key:
            raise ValueError("Set SHODAN_API_KEY in the environment; it is never stored in the workspace.")
        hostname = "api.shodan.io"
        endpoint = "https://" + hostname + "/shodan/host/" + address
        parameters, headers = {"key": key, "minify": "true"}, {"Accept": "application/json"}
        reference = "https://developer.shodan.io/api"
    elif provider == "censys":
        key = os.environ.get("CENSYS_PLATFORM_TOKEN", "")
        if not key:
            raise ValueError("Set CENSYS_PLATFORM_TOKEN in the environment; it is never stored in the workspace.")
        hostname = "api.platform.censys.io"
        endpoint = "https://" + hostname + "/v3/global/asset/host/" + address
        headers = {"Authorization": "Bearer " + key, "Accept": "application/vnd.censys.api.v3.host.v1+json"}
        parameters = {}
        organization = os.environ.get("CENSYS_ORGANIZATION_ID", "")
        if organization:
            parameters["organization_id"] = str(uuid.UUID(organization))
        reference = "https://docs.censys.com/reference/v3-globaldata-asset-host"
    else:
        raise ValueError("Provider must be shodan or censys.")
    repository.scope(project).require(address)
    response = ScopedHTTP(lambda: Scope((hostname,)), max_requests=1, transport=transport, cancel=cancel).fetch(
        endpoint, parameters=parameters, request_headers=headers)
    if response["status_code"] != 200 or response["truncated"]:
        raise ValueError(f"{provider} unavailable (HTTP {response['status_code']}) or response exceeded limits; check account access and retry later.")
    data = json.loads(response["text"])
    if not isinstance(data, dict):
        raise ValueError("Malformed provider response.")
    records = []
    def timestamp(value):
        return value[:100] if isinstance(value, str) else None
    if provider == "shodan":
        if data.get("ip_str") != address or not isinstance(data.get("ports"), list):
            raise ValueError("Provider returned an unexpected IP or malformed port list.")
        for port in data["ports"][:1000]:
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError("Malformed provider port.")
            records.append({"host": address, "port": port, "protocol": "unknown", "provider_observed_at": timestamp(data.get("last_update"))})
    else:
        result = data.get("result", {})
        resource = result.get("resource", {}) if isinstance(result, dict) else {}
        if not isinstance(resource, dict):
            raise ValueError("Malformed provider resource.")
        if resource.get("ip") != address or not isinstance(resource.get("services"), list):
            raise ValueError("Provider returned an unexpected IP or malformed service list.")
        for service in resource["services"][:1000]:
            if not isinstance(service, dict) or service.get("ip", address) != address:
                raise ValueError("Malformed or mismatched provider service.")
            port, protocol = service.get("port"), service.get("transport_protocol")
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or protocol not in {"tcp", "udp"}:
                raise ValueError("Malformed provider service.")
            records.append({"host": address, "port": port, "protocol": protocol,
                            "service": str(service.get("protocol", "unknown"))[:100], "provider_observed_at": timestamp(service.get("scan_time"))})
    identifier = repository.start_scan(project, address, {"provider": provider, "active_requests_to_target": 0})
    try:
        repository.scope(project).require(address)
        for row in records:
            repository.save(identifier, "ports", f'{address}:{row["protocol"]}:{row["port"]}',
                {**row, "reference": reference, "verified_current": False}, provider,
                confidence="provider-observed-unverified", historical=True)
            repository.save(identifier, "relationships", f'{address}:{row["protocol"]}:{row["port"]}',
                {"from_node": "ip:" + address, "to_node": f'port:{address}:{row["protocol"]}:{row["port"]}',
                 "relation": "provider_observed_service"}, provider, confidence="provider-observed-unverified", historical=True)
        repository.finish(identifier, ["Provider observations are not independently verified current services. No target scan was initiated."])
    except Exception:
        repository.finish(identifier, ["Provider import interrupted by a scope or storage error."], failed=True)
        raise
    return identifier
