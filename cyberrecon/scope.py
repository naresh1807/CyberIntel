import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from cyberintel.connectors import domain
from cyberintel.models import ValidationError


def host_of(value):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValidationError("Invalid target text or control characters.")
    value = value.strip()
    if "://" in value:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or parts.username or parts.password or not parts.hostname:
            raise ValidationError("Use an HTTP(S) target without credentials.")
        try:
            port = parts.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError("Invalid port")
        except ValueError:
            raise ValidationError("Invalid target port.") from None
        value = parts.hostname
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return domain(value)


def rule(value):
    if not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValidationError("Scope rules must be text without control characters.")
    value = value.strip()
    if "://" in value:
        raise ValidationError("Scope rules must be domain names, IPs or CIDRs. Enter URLs as scan targets, not scope rules.")
    if value.startswith("*."):
        return "*." + domain(value[2:])
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return host_of(value)


def matches(host, pattern):
    if pattern.startswith("*."):
        return host.endswith("." + pattern[2:]) and host != pattern[2:]
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return host == pattern


@dataclass(frozen=True)
class Scope:
    include: tuple
    exclude: tuple = ()

    def __post_init__(self):
        if not isinstance(self.include, (tuple, list)) or not isinstance(self.exclude, (tuple, list)) or len(self.include) + len(self.exclude) > 2048:
            raise ValidationError("Scope requires rule lists with at most 2048 entries.")
        object.__setattr__(self, "include", tuple(dict.fromkeys(rule(value) for value in self.include)))
        object.__setattr__(self, "exclude", tuple(dict.fromkeys(rule(value) for value in self.exclude)))
        if not self.include:
            raise ValidationError("At least one explicit scope inclusion is required.")
        if "0.0.0.0/0" in self.include or "::/0" in self.include:
            raise ValidationError("Internet-wide scopes are prohibited.")

    def allows(self, value, passive=False):
        host = host_of(value)
        if self.denies(host):
            return False
        return any(matches(host, pattern) or (passive and pattern == "*." + host) for pattern in self.include)

    def denies(self, value):
        host = host_of(value)
        return any(matches(host, pattern) for pattern in self.exclude)

    def require(self, value, passive=False):
        if not self.allows(value, passive):
            raise ValidationError("OUT OF SCOPE: " + host_of(value))
        return host_of(value)

    def to_dict(self):
        return {"include": list(self.include), "exclude": list(self.exclude)}
