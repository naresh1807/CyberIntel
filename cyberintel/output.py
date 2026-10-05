"""Protect managed evidence/state and commit exports only when fully generated."""
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .models import ValidationError


def validate_export_destination(session, destination):
    path = Path(destination).resolve()
    home = session.store.home.resolve()
    evidence = home / "evidence"
    reserved = {"cyberintel.sqlite", "cyberintel.sqlite-wal", "cyberintel.sqlite-shm", "vault.enc", "config.json", "application.log"}
    if path == evidence or evidence in path.parents or (path.parent == home and (path.name in reserved or path.name.startswith("application.log."))):
        raise ValidationError("Exports cannot overwrite managed evidence, credentials or application state.")
    return path


@contextmanager
def atomic_output(destination):
    destination = Path(destination)
    descriptor, name = tempfile.mkstemp(prefix=".cyberintel-export-", suffix=destination.suffix, dir=destination.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        yield temporary
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
