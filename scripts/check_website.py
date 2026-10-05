"""Optional live website-metadata verification on the public example.com site."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyberintel.config import Config
from cyberintel.connectors import Collector
from cyberintel.storage import Store


with tempfile.TemporaryDirectory() as directory:
    config = Config(Path(directory), timeout_seconds=10)
    result = Collector(config, Store(config.home)).collect("website", "example.com")
    artifacts = Path(__file__).resolve().parents[1] / "artifacts"
    artifacts.mkdir(exist_ok=True)
    (artifacts / "website-source-check.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    print(json.dumps({"status": result.status, "title": result.data.get("title") if result.data else None, "error": result.error}))
