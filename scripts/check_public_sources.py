"""Optional live smoke check; uses example.com and public breach metadata only."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyberintel.config import Config
from cyberintel.connectors import Collector
from cyberintel.storage import Store


def main():
    results = []
    with tempfile.TemporaryDirectory() as directory:
        config = Config(Path(directory), timeout_seconds=10)
        collector = Collector(config, Store(config.home))
        for source, query in (("dns", "example.com"), ("rdap", "example.com"), ("ct", "example.com"), ("hibp_catalog", "")):
            result = collector.collect(source, query)
            summary = {"source": result.source, "status": result.status, "collected_at": result.collected_at,
                       "reference": result.reference, "error": result.error,
                       "response_type": type(result.data).__name__}
            results.append(summary)
            print(json.dumps(summary), flush=True)
    artifacts = Path(__file__).resolve().parents[1] / "artifacts"
    artifacts.mkdir(exist_ok=True)
    (artifacts / "live-source-checks.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
