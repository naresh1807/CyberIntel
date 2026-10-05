"""Bounded, offline analysis of authorized tabular and network evidence."""
import csv
import hashlib
import html
import json
import math
import re
import shutil
import subprocess
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

import folium
import networkx as nx
import numpy as np
import pandas as pd
import plotly.graph_objects as go

from .models import Result, ValidationError
from .output import atomic_output

MAX_ROWS = 100_000


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_table(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 50 * 1024 * 1024:
        raise ValidationError("Use a regular CSV/XLSX file no larger than 50 MiB.")
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as file:
            header = next(csv.reader(file), [])
        normalized = [name.strip().lower() for name in header]
        if not normalized or any(not name for name in normalized):
            raise ValidationError("Every table column needs a nonempty name.")
        if len(set(normalized)) != len(normalized):
            raise ValidationError("Duplicate column names after normalization.")
        frame = pd.read_csv(path, dtype=str, keep_default_na=False, nrows=MAX_ROWS + 1)
    elif path.suffix.lower() == ".xlsx":
        with zipfile.ZipFile(path) as archive:
            if sum(i.file_size for i in archive.infolist()) > 150 * 1024 * 1024:
                raise ValidationError("Expanded XLSX exceeds 150 MiB.")
            if any("vbaProject" in i.filename for i in archive.infolist()):
                raise ValidationError("Macro-enabled workbooks are not accepted.")
        import openpyxl
        workbook = openpyxl.load_workbook(path, read_only=True, data_only=True)
        try:
            header = next(workbook.worksheets[0].iter_rows(min_row=1, max_row=1, values_only=True), ())
            normalized = [str(name).strip().lower() for name in header]
            if not normalized or any(name is None or not str(name).strip() for name in header):
                raise ValidationError("Every table column needs a nonempty name.")
            if len(set(normalized)) != len(normalized):
                raise ValidationError("Duplicate column names after normalization.")
        finally:
            workbook.close()
        frame = pd.read_excel(path, dtype=str, keep_default_na=False, nrows=MAX_ROWS + 1, engine="openpyxl")
    else:
        raise ValidationError("Only CSV and XLSX are supported.")
    if len(frame) > MAX_ROWS:
        raise ValidationError(f"Table exceeds {MAX_ROWS:,} rows; split the dataset first.")
    if frame.empty:
        raise ValidationError("File contains no data rows.")
    frame.columns = [str(c).strip().lower() for c in frame.columns]
    if len(set(frame.columns)) != len(frame.columns):
        raise ValidationError("Duplicate column names after normalization.")
    return frame


def require_columns(frame, names):
    missing = set(names) - set(frame.columns)
    if missing:
        raise ValidationError("Missing columns: " + ", ".join(sorted(missing)))


def timestamps(values):
    for value in values:
        if not re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", value.strip()):
            raise ValidationError("Every timestamp must include Z or a numeric UTC offset.")
    try:
        return pd.to_datetime(values, utc=True, format="mixed", errors="raise")
    except ValueError:
        raise ValidationError("Invalid timestamp in dataset.") from None


def analyze_cdr(path, data_kind="actual"):
    if data_kind not in {"actual", "inferred", "synthetic"}:
        raise ValidationError("Invalid provenance kind.")
    frame = read_table(path)
    require_columns(frame, {"caller", "callee", "timestamp", "duration_seconds", "direction"})
    for column in ("caller", "callee"):
        if not frame[column].str.fullmatch(r"\+?[0-9]{3,20}").all():
            raise ValidationError("Phone numbers must be 3–20 digits with an optional leading +.")
    frame["direction"] = frame["direction"].str.lower().str.strip()
    if not frame["direction"].isin(["incoming", "outgoing"]).all():
        raise ValidationError("direction must be incoming or outgoing.")
    try:
        duration = pd.to_numeric(frame["duration_seconds"], errors="raise")
    except ValueError:
        raise ValidationError("duration_seconds must be numeric.") from None
    if not np.isfinite(duration.to_numpy(dtype=float)).all() or (duration < 0).any() or (duration > 604800).any():
        raise ValidationError("Call duration must be finite and between 0 and 604800 seconds.")
    frame["duration_seconds"] = duration
    dates = timestamps(frame["timestamp"])
    edges = frame.groupby(["caller", "callee"], sort=True).agg(
        calls=("duration_seconds", "size"), duration_seconds=("duration_seconds", "sum")).reset_index()
    hours = dates.dt.hour.value_counts().sort_index()
    days = dates.dt.strftime("%Y-%m-%d").value_counts().sort_index()
    graph = nx.DiGraph()
    for row in edges.to_dict("records"):
        graph.add_edge(row["caller"], row["callee"], weight=row["calls"], duration=row["duration_seconds"])
    data = {
        "provenance_kind": data_kind, "file_sha256": sha256(path),
        "total_calls": len(frame), "total_duration_seconds": float(duration.sum()),
        "mean_duration_seconds": float(duration.mean()),
        "unique_numbers": graph.number_of_nodes(),
        "incoming_calls": int((frame["direction"] == "incoming").sum()),
        "outgoing_calls": int((frame["direction"] == "outgoing").sum()),
        "start_utc": dates.min().isoformat(), "end_utc": dates.max().isoformat(),
        "hourly_calls_utc": {str(k): int(v) for k, v in hours.items()},
        "daily_calls_utc": {str(k): int(v) for k, v in days.items()},
        "relationships": edges.to_dict("records"),
        "note": "Caller-to-callee edges describe supplied records; they do not establish identity or intent."
    }
    return Result("Authorized CDR import", Path(path).name, Path(path).name, data, status="synthetic" if data_kind == "synthetic" else "offline")


def relationship_graph(result, destination):
    graph = nx.DiGraph()
    edges = result.data.get("relationships", [])
    if len(edges) > 2000:
        raise ValidationError("Graph rendering is limited to 2,000 relationships. Filter the source dataset first.")
    for row in edges:
        graph.add_edge(row["caller"], row["callee"], weight=row["calls"])
    # NetworkX's large spring layout requires SciPy, which is not a suite dependency.
    # Circular layout is deterministic, fast, and keeps the full bounded graph available.
    positions = nx.circular_layout(graph) if graph.number_of_nodes() >= 500 else nx.spring_layout(graph, seed=42, iterations=30)
    edge_x, edge_y = [], []
    for a, b in graph.edges:
        edge_x += [positions[a][0], positions[b][0], None]
        edge_y += [positions[a][1], positions[b][1], None]
    nodes = list(graph)
    figure = go.Figure([
        go.Scatter(x=edge_x, y=edge_y, mode="lines", line=dict(color="#7184c8", width=1), hoverinfo="skip"),
        go.Scatter(x=[positions[n][0] for n in nodes], y=[positions[n][1] for n in nodes],
                   mode="markers+text", text=nodes, textposition="top center",
                   marker=dict(size=14, color="#a78bfa"),
                   hovertext=[f"{n}: {graph.degree(n)} relationships" for n in nodes], hoverinfo="text")
    ])
    figure.update_layout(template="plotly_dark", title="CDR relationships · " + result.data["provenance_kind"] + " · edges show associations; see table for direction",
                         showlegend=False, xaxis=dict(visible=False), yaxis=dict(visible=False))
    with atomic_output(destination) as temporary:
        figure.write_html(str(temporary), include_plotlyjs=True, auto_open=False)
    return str(destination)


def analyze_geo(path, mode="gps", data_kind="actual"):
    if data_kind not in {"actual", "inferred", "synthetic"}:
        raise ValidationError("Invalid provenance kind.")
    frame = read_table(path)
    if mode not in {"gps", "towers"}:
        raise ValidationError("Select GPS records or tower inventory.")
    required = {"latitude", "longitude", "source"} | ({"timestamp", "record_kind"} if mode == "gps" else {"tower_id"})
    require_columns(frame, required)
    try:
        latitude = pd.to_numeric(frame["latitude"], errors="raise")
        longitude = pd.to_numeric(frame["longitude"], errors="raise")
    except ValueError:
        raise ValidationError("Coordinates must be numeric.") from None
    if not latitude.between(-90, 90).all() or not longitude.between(-180, 180).all():
        raise ValidationError("Coordinates are outside valid latitude/longitude ranges.")
    if not frame["source"].str.strip().astype(bool).all():
        raise ValidationError("Every location row needs a source.")
    frame["latitude"], frame["longitude"] = latitude, longitude
    if mode == "gps":
        frame["timestamp"] = timestamps(frame["timestamp"]).astype(str)
        if not frame["record_kind"].isin(["actual", "inferred", "synthetic"]).all():
            raise ValidationError("record_kind must be actual, inferred or synthetic.")
        if data_kind == "synthetic":
            frame["record_kind"] = "synthetic"
        elif data_kind == "inferred":
            frame.loc[frame["record_kind"] != "synthetic", "record_kind"] = "inferred"
    else:
        if not frame["tower_id"].str.strip().astype(bool).all():
            raise ValidationError("Every tower row needs a tower_id.")
        frame["record_kind"] = "synthetic" if data_kind == "synthetic" else "tower_inventory"
    return Result("Authorized geospatial import", Path(path).name, Path(path).name,
                  {"file_sha256": sha256(path), "mode": mode, "provenance_kind": data_kind,
                   "record_count": len(frame), "records": frame.to_dict("records"),
                   "note": "Tower coordinates represent infrastructure, not a subscriber location. Inferred records are estimates."},
                  status="synthetic" if data_kind == "synthetic" else "offline")


def location_map(result, destination, online_tiles=False):
    records = result.data["records"]
    if not records:
        raise ValidationError("There are no location records to map.")
    if len(records) > 10000:
        raise ValidationError("Map is limited to 10,000 records. Split the dataset first.")
    center = [float(np.mean([r["latitude"] for r in records])), float(np.mean([r["longitude"] for r in records]))]
    map_ = folium.Map(location=center, zoom_start=10, tiles="OpenStreetMap" if online_tiles else None)
    colors = {"actual": "blue", "inferred": "orange", "synthetic": "purple", "tower_inventory": "green"}
    for row in records:
        # Folium inserts popup HTML into JavaScript template literals.
        text = "<br>".join(html.escape(f"{k}: {v}").replace("`", "&#96;").replace("$", "&#36;") for k, v in row.items())
        folium.CircleMarker([row["latitude"], row["longitude"]], radius=6,
                            color=colors[row["record_kind"]], fill=True, popup=folium.Popup(text, max_width=400)).add_to(map_)
    if len(records) > 1:
        map_.fit_bounds([[min(r["latitude"] for r in records), min(r["longitude"] for r in records)],
                         [max(r["latitude"] for r in records), max(r["longitude"] for r in records)]])
    title = '<div style="position:fixed;top:10px;left:50px;z-index:9999;background:white;padding:12px;font:14px sans-serif">CyberIntel • blue: actual • orange: inferred • purple: synthetic • green: tower inventory</div>'
    map_.get_root().html.add_child(folium.Element(title))
    with atomic_output(destination) as temporary:
        map_.save(str(temporary))
    return str(destination)


def analyze_pcap(path, tshark="tshark", data_kind="actual"):
    if data_kind not in {"actual", "inferred", "synthetic"}:
        raise ValidationError("Invalid provenance kind.")
    if Path(path).is_symlink():
        raise ValidationError("Use a regular capture file, not a symlink.")
    path = Path(path).resolve()
    if not path.is_file() or path.stat().st_size > 200 * 1024 * 1024:
        raise ValidationError("PCAP must be a regular file no larger than 200 MiB.")
    with path.open("rb") as file:
        magic = file.read(4)
    if magic not in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}:
        raise ValidationError("File is not a recognized PCAP/PCAPNG capture.")
    executable = shutil.which(tshark)
    if not executable:
        raise ValidationError("TShark is unavailable. Install tshark for offline network analysis.")
    fields = ["frame.number", "frame.time_epoch", "frame.len", "_ws.col.Protocol", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "dns.qry.name", "tcp.flags.syn", "tcp.flags.ack"]
    command = [executable, "-n", "-r", str(path), "-c", "500001", "-T", "fields", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
    for field in fields:
        command += ["-e", field]
    protocols, dns_names, connections, syn_counts = Counter(), Counter(), Counter(), Counter()
    packets = total_bytes = 0
    start = end = None
    # Redirect potentially large subprocess output to disk rather than buffering RAM.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            completed = subprocess.run(command, stdout=output, stderr=errors, timeout=120, check=False,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired:
            raise ValidationError("TShark exceeded the 120-second limit; use a smaller capture.") from None
        except OSError:
            raise ValidationError("Unable to launch TShark. Check its installation.") from None
        if completed.returncode:
            raise ValidationError("TShark could not parse the capture. Verify the file with Wireshark.")
        output.seek(0)
        import io
        for row in csv.reader(io.TextIOWrapper(output, encoding="utf-8", errors="replace")):
            if len(row) != len(fields):
                raise ValidationError("TShark returned malformed packet fields; analysis refused.")
            packets += 1
            if packets > 500000:
                raise ValidationError("Capture exceeds 500,000 packets; split it with editcap first.")
            try:
                packet_bytes = int(row[2])
                epoch = float(row[1])
                if packet_bytes < 0 or not math.isfinite(epoch):
                    raise ValueError()
            except ValueError:
                raise ValidationError("TShark returned invalid packet length or timestamp; analysis refused.") from None
            total_bytes += packet_bytes
            protocols[row[3]] += 1
            start = epoch if start is None else min(start, epoch)
            end = epoch if end is None else max(end, epoch)
            source, destination = row[4] or row[5], row[6] or row[7]
            if source and destination:
                connections[(source, destination, row[10] or row[11])] += 1
            if row[12]:
                dns_names[row[12]] += 1
            if row[13] in {"1", "True"} and row[14] in {"0", "False"}:
                syn_counts[source] += 1
    suspicious = [{"indicator": source, "severity": "review", "reason": f"{count} initial TCP SYN packets; threshold >100, heuristic only"}
                  for source, count in syn_counts.items() if count > 100]
    suspicious += [{"indicator": name, "severity": "review", "reason": "DNS name exceeds 100 characters; heuristic only"} for name in dns_names if len(name) > 100]
    return Result("Offline TShark", path.name, path.name,
                  {"file_sha256": sha256(path), "provenance_kind": data_kind, "packets": packets,
                   "bytes": total_bytes, "start_epoch": start, "end_epoch": end, "protocols": dict(protocols),
                   "dns_queries": [{"query": q, "count": c} for q, c in dns_names.most_common(5000)],
                   "connections": [{"source": s, "destination": d, "destination_port": p, "packets": c}
                                   for (s, d, p), c in connections.most_common(5000)],
                   "review_indicators": suspicious, "note": "Heuristics do not establish malicious activity. DNS/connection display is limited to the top 5,000 entries."},
                  status="synthetic" if data_kind == "synthetic" else "offline")
