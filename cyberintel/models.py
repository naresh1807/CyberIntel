from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Result:
    source: str
    reference: str
    query: str
    data: Any
    status: str = "live"
    collected_at: str = field(default_factory=utcnow)
    error: str | None = None
    freshness: str = "fresh"

    def to_dict(self):
        return asdict(self)


class ValidationError(ValueError):
    pass


class AccessDenied(PermissionError):
    pass
