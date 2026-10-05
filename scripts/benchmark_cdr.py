"""Bounded synthetic CDR workload; not a claim about every target machine."""
import csv
import json
import platform
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyberintel.analysis import analyze_cdr
from cyberintel.models import utcnow


with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "synthetic-large-cdr.csv"
    with path.open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["caller", "callee", "timestamp", "duration_seconds", "direction"])
        for i in range(100000):
            writer.writerow([f"+1555{i % 1000:07d}", f"+1555{(i + 1) % 1000:07d}", "2026-10-01T09:00:00Z", 60, "outgoing"])
    started = time.perf_counter()
    result = analyze_cdr(path, "synthetic")
    elapsed = time.perf_counter() - started
    assert result.data["total_calls"] == 100000
    assert result.data["total_duration_seconds"] == 6000000
    summary = {"collected_at": utcnow(), "platform": platform.platform(), "python": platform.python_version(),
               "synthetic_rows": 100000, "relationships": len(result.data["relationships"]),
               "elapsed_seconds": round(elapsed, 3), "correct_totals": True}
    artifacts = Path(__file__).resolve().parents[1] / "artifacts"
    artifacts.mkdir(exist_ok=True)
    (artifacts / "performance-checks.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary))
