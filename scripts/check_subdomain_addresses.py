"""Live A/AAAA smoke check on a known public hostname, independent of CT availability."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyberintel.models import Result
from cyberintel.subdomains import enrich_subdomains

result = Result("Manual DNS smoke check (not a CT discovery)", "https://example.com", "example.com",
                {"records": [{"subdomain": "www.example.com", "ipv4": [], "ipv6": [], "dns_status": "not checked"}]}, status="offline")
result = enrich_subdomains(result)
artifacts = Path(__file__).resolve().parents[1] / "artifacts"
artifacts.mkdir(exist_ok=True)
(artifacts / "subdomain-address-check.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
print(json.dumps(result.data["records"][0]))
