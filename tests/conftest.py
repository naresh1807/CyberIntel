import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from cyberintel.storage import Store


@pytest.fixture
def session(tmp_path):
    store = Store(tmp_path)
    store.bootstrap("admin", "test-password-long")
    return store.login("admin", "test-password-long")


@pytest.fixture
def examples():
    return Path(__file__).resolve().parents[1] / "examples"
