"""Case reports with evidence inventory, provenance and stored findings."""
import csv
import json
import textwrap
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted

from .models import ValidationError, utcnow
from .output import atomic_output, validate_export_destination


def csv_safe(value):
    value = str(value)
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value


def case_snapshot(session, case_id):
    session.check("report")
    case = next((r for r in session.rows("cases") if r["id"] == case_id), None)
    if not case:
        raise ValidationError("Select an existing case for reporting.")
    return {"case": case, "generated_at": utcnow(), "generated_by": session.actor,
            "evidence": session.rows("evidence", case_id), "findings": session.rows("findings", case_id),
            "integrity": session.verify_evidence(case_id), "audit_chain_valid": session.verify_audit()}


def export_csv(session, case_id, destination):
    destination = validate_export_destination(session, destination)
    snapshot = case_snapshot(session, case_id)
    fields = ["case_id", "record_type", "identifier", "source", "collected_at", "status", "sha256", "data"]
    with atomic_output(destination) as temporary, temporary.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        def write(row):
            writer.writerow({k: csv_safe(v) for k, v in row.items()})
        write({"case_id": case_id, "record_type": "case", "identifier": case_id,
               "collected_at": snapshot["generated_at"], "data": json.dumps(snapshot["case"])})
        for row in snapshot["evidence"]:
            write({"case_id": case_id, "record_type": "evidence", "identifier": row["id"],
                   "source": row["source"], "collected_at": row["acquired_at"], "status": row["data_kind"],
                   "sha256": row["sha256"], "data": json.dumps({k: v for k, v in row.items() if k != "path"})})
        for row in snapshot["findings"]:
            result = json.loads(row["result"])
            write({"case_id": case_id, "record_type": row["module"], "identifier": row["id"],
                   "source": result["reference"], "collected_at": result["collected_at"],
                   "status": result["status"], "data": json.dumps(result)})
        write({"case_id": case_id, "record_type": "integrity", "data": json.dumps(snapshot["integrity"]),
               "status": str(snapshot["audit_chain_valid"])})
    session.audit("report_exported", f"{case_id}: CSV")
    return str(destination)


def export_pdf(session, case_id, destination):
    destination = validate_export_destination(session, destination)
    snapshot = case_snapshot(session, case_id)
    styles = getSampleStyleSheet()
    styles["BodyText"].fontSize = 9
    styles["BodyText"].leading = 13
    story = []
    def paragraph(text, style="BodyText"):
        story.append(Paragraph(escape(str(text)), styles[style]))
        story.append(Spacer(1, 6))
    paragraph("CYBERINTEL SUITE", "Title")
    paragraph(snapshot["case"]["title"], "Heading1")
    paragraph("Case ID: " + case_id)
    paragraph("Generated (UTC): " + snapshot["generated_at"] + " · Analyst: " + session.actor)
    paragraph(snapshot["case"]["description"])
    paragraph("Evidence integrity", "Heading2")
    for row in snapshot["integrity"]:
        paragraph(f"{row['name']}: {'VERIFIED' if row['valid'] else 'MISMATCH / MISSING'}")
    paragraph("Audit hash chain: " + ("consistent" if snapshot["audit_chain_valid"] else "FAILED"))
    paragraph("The local audit chain detects edits to retained entries; it is not externally anchored and cannot prove that a database administrator has not rewritten or truncated the history.")
    paragraph("Evidence inventory", "Heading2")
    for row in snapshot["evidence"]:
        paragraph(f"{row['name']} · {row['data_kind']} · {row['size']} bytes", "Heading3")
        paragraph(f"Source: {row['source']} | Acquired: {row['acquired_at']} | Imported: {row['imported_at']}")
        paragraph("SHA-256: " + row["sha256"])
    paragraph("Findings and source references", "Heading2")
    for row in snapshot["findings"]:
        result = json.loads(row["result"])
        paragraph(row["module"], "Heading3")
        paragraph(f"Query: {result['query']} | Status: {result['status']} | Freshness: {result['freshness']}")
        paragraph(f"Source: {result['source']} | Reference: {result['reference']} | Collected: {result['collected_at']}")
        if result.get("error"):
            paragraph("Source warning: " + result["error"])
        # Full, bounded chunks avoid pathological single paragraphs and keep page layout stable.
        lines = []
        for line in json.dumps(result["data"], ensure_ascii=True, indent=2).splitlines():
            lines.extend(textwrap.wrap(line, width=95, break_long_words=True, replace_whitespace=False) or [""])
        story.append(Preformatted("\n".join(lines), ParagraphStyle("ResultJSON", fontName="Courier", fontSize=7.5, leading=10)))
        story.append(Spacer(1, 12))
    def footer(canvas, doc):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(0.65 * inch, 0.4 * inch, "CyberIntel Suite · Authorized investigation records")
        canvas.drawRightString(7.6 * inch, 0.4 * inch, str(doc.page))
    with atomic_output(destination) as temporary:
        SimpleDocTemplate(str(temporary), pagesize=(8.27 * inch, 11.69 * inch),
                          rightMargin=0.65 * inch, leftMargin=0.65 * inch,
                          topMargin=0.65 * inch, bottomMargin=0.65 * inch).build(story, onFirstPage=footer, onLaterPages=footer)
    session.audit("report_exported", f"{case_id}: PDF")
    return str(destination)
