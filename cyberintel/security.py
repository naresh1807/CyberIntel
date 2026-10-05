"""Password authentication, service authorization and encrypted credential storage."""
import base64
import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .models import AccessDenied, ValidationError

PERMISSIONS = {
    "viewer": {"read", "report"},
    "analyst": {"read", "report", "collect", "case", "evidence"},
    "admin": {"read", "report", "collect", "case", "evidence", "users", "settings"},
}


def require(role: str, permission: str):
    if permission not in PERMISSIONS.get(role, set()):
        raise AccessDenied(f"The {role} role cannot perform {permission} operations.")


def password_hash(password: str, salt: bytes | None = None) -> str:
    if len(password) < 12:
        raise ValidationError("Use a password of at least 12 characters.")
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return base64.b64encode(salt + digest).decode()


def password_matches(password: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored, validate=True)
        digest = hashlib.scrypt(password.encode(), salt=raw[:16], n=16384, r=8, p=1)
        return hmac.compare_digest(raw[16:], digest)
    except (ValueError, TypeError):
        return False


class Vault:
    """Fernet vault; key derived from a separate unlock passphrase, never saved."""
    def __init__(self, path: Path, passphrase: str):
        if len(passphrase) < 12:
            raise ValidationError("Vault passphrase must contain at least 12 characters.")
        self.path = path
        if path.exists():
            raw = path.read_bytes()
            if len(raw) < 17 or len(raw) > 1024 * 1024:
                raise ValidationError("Damaged credential vault; existing contents were not replaced.")
            salt, token = raw[:16], raw[16:]
        else:
            salt, token = os.urandom(16), None
        key = hashlib.scrypt(passphrase.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        self.cipher = Fernet(base64.urlsafe_b64encode(key))
        self.salt = salt
        try:
            self.values = json.loads(self.cipher.decrypt(token)) if token else {}
            if not isinstance(self.values, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in self.values.items()):
                raise ValueError("Invalid vault structure")
        except (InvalidToken, ValueError):
            raise ValidationError("Incorrect vault passphrase or damaged vault.") from None

    def get(self, name: str) -> str:
        return self.values.get(name, "")

    def save(self, values: dict):
        new_values = {k: str(v).strip() for k, v in values.items() if str(v).strip()}
        descriptor, name = tempfile.mkstemp(prefix=".cyberintel-vault-", dir=self.path.parent)
        tmp = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as file:
                file.write(self.salt + self.cipher.encrypt(json.dumps(new_values).encode()))
            tmp.replace(self.path)
            self.values = new_values
        finally:
            tmp.unlink(missing_ok=True)


def username(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", value):
        raise ValidationError("Username must be 3–64 letters, numbers, dots, dashes or underscores.")
    return value


class LocalCredentials:
    """Direct local credential storage, without passphrase or encryption."""

    def __init__(self, path: Path):
        self.path = path
        self.values = {}
        if path.exists():
            try:
                if path.stat().st_size > 1024 * 1024:
                    raise ValueError()
                values = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(values, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in values.items()):
                    raise ValueError()
                self.values = values
                os.chmod(path, 0o600)
            except (ValueError, UnicodeError):
                raise ValidationError("Invalid local API credential file. Existing contents were not replaced.") from None

    def get(self, name):
        return self.values.get(name, "")

    def save(self, values):
        new_values = {name: str(value).strip() for name, value in values.items() if str(value).strip()}
        descriptor, name = tempfile.mkstemp(prefix=".cyberintel-credentials-", dir=self.path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as file:
                json.dump(new_values, file)
            os.chmod(temporary, 0o600)
            temporary.replace(self.path)
            self.values = new_values
        finally:
            temporary.unlink(missing_ok=True)
