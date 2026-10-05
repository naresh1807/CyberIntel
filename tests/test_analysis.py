import json
import struct
from pathlib import Path

import pytest

from cyberintel.analysis import analyze_cdr, analyze_geo, analyze_pcap, location_map, relationship_graph
from cyberintel.models import ValidationError


def test_cdr_summary_and_graph(examples, tmp_path):
    result = analyze_cdr(examples / "synthetic_cdr.csv", "synthetic")
    assert result.status == "synthetic"
    assert result.data["total_calls"] == 6
    assert result.data["total_duration_seconds"] == 735
    assert result.data["unique_numbers"] == 3
    edge = next(r for r in result.data["relationships"] if r["caller"] == "+15550100001" and r["callee"] == "+15550100002")
    assert edge["calls"] == 2
    path = relationship_graph(result, tmp_path / "graph.html")
    assert "plotly" in Path(path).read_text(encoding="utf-8").lower()


@pytest.mark.parametrize("duration", ["-1", "NaN", "inf", "bad"])
def test_bad_cdr_duration(tmp_path, duration):
    path = tmp_path / "bad.csv"
    path.write_text(f"caller,callee,timestamp,duration_seconds,direction\n12345,54321,2026-10-01T00:00:00Z,{duration},outgoing\n")
    with pytest.raises(ValidationError):
        analyze_cdr(path)


def test_bad_timestamp(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("caller,callee,timestamp,duration_seconds,direction\n12345,54321,2026-10-01T00:00:00,30,outgoing\n")
    with pytest.raises(ValidationError, match="UTC offset"):
        analyze_cdr(path)


def test_geo_map_preserves_provenance(examples, tmp_path):
    result = analyze_geo(examples / "synthetic_gps.csv", data_kind="synthetic")
    assert result.data["record_count"] == 3
    assert {r["record_kind"] for r in result.data["records"]} == {"synthetic"}
    path = location_map(result, tmp_path / "map.html")
    body = Path(path).read_text(encoding="utf-8")
    assert "Synthetic fixture" in body
    assert "tile.openstreetmap.org" not in body
    towers = analyze_geo(examples / "synthetic_towers.csv", "towers", "synthetic")
    assert towers.data["mode"] == "towers"


def test_geo_rejects_bad_coordinates(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("latitude,longitude,tower_id,source\n999,77,T1,test\n")
    with pytest.raises(ValidationError):
        analyze_geo(path, "towers")


def test_pcap_magic_and_missing_tshark(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"not pcap")
    with pytest.raises(ValidationError, match="recognized"):
        analyze_pcap(path)
    path.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    with pytest.raises(ValidationError, match="unavailable"):
        analyze_pcap(path, tshark="cyberintel-no-such-binary")


def test_xlsx_import(examples, tmp_path):
    import pandas as pd
    frame = pd.read_csv(examples / "synthetic_cdr.csv", dtype=str)
    path = tmp_path / "cdr.xlsx"
    frame.to_excel(path, index=False)
    assert analyze_cdr(path, "synthetic").data["total_calls"] == 6
