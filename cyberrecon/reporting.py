"""Escaped, atomic exports from a scan snapshot."""
import csv
import html
import json
from pathlib import Path

from cyberintel.output import atomic_output
from .storage import KINDS


def export_reports(repository, scan, directory):
    directory = Path(repository.export_json(scan, directory))
    snapshot = repository.snapshot(scan)
    rows = [(kind, row) for kind in KINDS for row in snapshot[kind]]
    for filename in ("observations.csv", "report.html", "report.pdf"):
        if (directory / filename).is_symlink():
            raise ValueError("Report destinations cannot be symlinks.")
    with atomic_output(directory / "observations.csv") as temporary:
        with temporary.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["kind", "key", "source", "confidence", "status", "details"])
            for kind, row in rows:
                values = [kind, row["key"], row["source"], row["confidence"], row["observation_status"], json.dumps(row, ensure_ascii=False)]
                writer.writerow(["'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value for value in values])
    sections = ["<!doctype html><html lang='en'><meta charset='utf-8'><title>CyberRecon report</title>",
                "<style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}h2{border-bottom:1px solid #aaa}</style>",
                "<h1>CyberRecon report</h1><p>Observations require validation. Missing observations do not prove removal.</p>"]
    for kind in ("project", "scan", *KINDS):
        sections.append("<h2>" + html.escape(kind.title()) + "</h2><pre>" + html.escape(json.dumps(snapshot[kind], indent=2, ensure_ascii=False)) + "</pre>")
    sections.append("</html>")
    with atomic_output(directory / "report.html") as temporary:
        temporary.write_text("\n".join(sections), encoding="utf-8")
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    styles = getSampleStyleSheet()
    content = [Paragraph("CyberRecon report", styles["Title"]),
               Paragraph("Observations require validation; missing observations do not prove removal.", styles["BodyText"])]
    for kind in ("project", "scan", *KINDS):
        content.extend([Spacer(1, 12), Paragraph(kind.title(), styles["Heading2"])])
        items = snapshot[kind] if isinstance(snapshot[kind], list) else [snapshot[kind]]
        for item in items:
            content.append(Paragraph(html.escape(json.dumps(item, ensure_ascii=True)), styles["BodyText"]))
    with atomic_output(directory / "report.pdf") as temporary:
        SimpleDocTemplate(str(temporary)).build(content)
    from .graph import export_graph
    export_graph(snapshot, directory / "graph.html")
    return str(directory)
