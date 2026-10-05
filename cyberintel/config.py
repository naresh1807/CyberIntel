import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .models import ValidationError

DEFAULT_ENDPOINTS = {
    "rdap": "https://rdap.org",
    "ct": "https://crt.sh",
    "certspotter": "https://api.certspotter.com/v1",
    "hibp": "https://haveibeenpwned.com/api/v3",
    "otx": "https://otx.alienvault.com/api/v1",
    "urlhaus": "https://urlhaus-api.abuse.ch/v1",
}


@dataclass
class Config:
    home: Path
    endpoints: dict = field(default_factory=lambda: DEFAULT_ENDPOINTS.copy())
    cache_seconds: int = 3600
    timeout_seconds: int = 20

    @classmethod
    def load(cls, home: str | None = None):
        root = Path(home or os.environ.get("CYBERINTEL_HOME", "") or
                    Path.home() / ".local" / "share" / "cyberintel").expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        config = cls(root)
        file = root / "config.json"
        if file.exists():
            try:
                data = json.loads(file.read_text(encoding="utf-8-sig"))
                if not isinstance(data, dict) or not isinstance(data.get("endpoints", {}), dict):
                    raise ValueError("Expected a JSON object with an endpoints object")
                for name, endpoint in data.get("endpoints", {}).items():
                    if name not in DEFAULT_ENDPOINTS or not isinstance(endpoint, str):
                        raise ValueError("Unknown connector or non-text endpoint")
                    parts = urlsplit(endpoint)
                    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port not in (None, 443) or parts.query or parts.fragment:
                        raise ValueError("Endpoints must use HTTPS/443 without credentials, query or fragment")
                config.endpoints.update(data.get("endpoints", {}))
                config.cache_seconds = max(60, int(data.get("cache_seconds", 3600)))
                config.timeout_seconds = min(60, max(5, int(data.get("timeout_seconds", 20))))
            except (ValueError, TypeError) as exc:
                raise ValidationError(f"Invalid configuration in {file}: {exc}") from None
        return config
