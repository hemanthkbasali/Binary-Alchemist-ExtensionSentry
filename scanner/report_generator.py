from __future__ import annotations

from pathlib import Path
import textwrap

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except ImportError:  # pragma: no cover - exercised only when dependency is unavailable
    colors = None
    letter = None
    getSampleStyleSheet = None
    Paragraph = None
    SimpleDocTemplate = None
    Spacer = None
    Table = None
    TableStyle = None


def generate_pdf_report(scan_result: dict, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if SimpleDocTemplate is None:
        _write_minimal_pdf(scan_result, output_path)
        return output_path
    _write_reportlab_pdf(scan_result, output_path)
    return output_path


def _write_reportlab_pdf(scan_result: dict, output_path: Path) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(output_path), pagesize=letter, title="ExtensionSentry Forensic Report")
    story = []
    story.append(Paragraph("ExtensionSentry Forensic Intelligence Report", styles["Title"]))
    story.append(Spacer(1, 12))
    summary = scan_result.get("score", {})
    artifact = scan_result.get("metadata", {}).get("artifact", {})
    manifest = scan_result.get("metadata", {}).get("manifest", {})
    rows = [
        ["Extension", manifest.get("name", "Unknown")],
        ["Version", manifest.get("version", "Unknown")],
        ["Archive", artifact.get("original_name", "upload.zip")],
        ["SHA256", artifact.get("archive_sha256", "")],
        ["Risk Score", f"{summary.get('risk_score', 0)}/100"],
        ["Threat Level", summary.get("threat_level", "unknown").upper()],
        ["Verdict", summary.get("verdict", "")],
    ]
    table = Table(rows, colWidths=[120, 380])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#67e8f9")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#94a3b8")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 16))
    story.append(Paragraph("Executive Narrative", styles["Heading2"]))
    story.append(Paragraph(summary.get("narrative", "No narrative available."), styles["BodyText"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Findings", styles["Heading2"]))
    findings = scan_result.get("findings", [])
    if not findings:
        story.append(Paragraph("No static indicators were detected.", styles["BodyText"]))
    for item in findings[:60]:
        title = f"{item.get('severity', 'info').upper()} - {item.get('title', 'Finding')}"
        story.append(Paragraph(title, styles["Heading3"]))
        story.append(Paragraph(item.get("description", ""), styles["BodyText"]))
        story.append(Paragraph(f"Recommendation: {item.get('recommendation', '')}", styles["BodyText"]))
        story.append(Spacer(1, 8))
    doc.build(story)


def _write_minimal_pdf(scan_result: dict, output_path: Path) -> None:
    lines = [
        "ExtensionSentry Forensic Intelligence Report",
        f"Risk score: {scan_result.get('score', {}).get('risk_score', 0)}/100",
        f"Verdict: {scan_result.get('score', {}).get('verdict', '')}",
        f"SHA256: {scan_result.get('metadata', {}).get('artifact', {}).get('archive_sha256', '')}",
        "",
        "Findings:",
    ]
    for item in scan_result.get("findings", [])[:40]:
        lines.append(f"- {item.get('severity', 'info').upper()}: {item.get('title', '')}")
    text = "\n".join(lines)
    stream_lines = []
    y = 760
    for raw_line in text.splitlines():
        for line in textwrap.wrap(raw_line, width=88) or [""]:
            stream_lines.append(f"BT /F1 9 Tf 40 {y} Td ({_pdf_escape(line)}) Tj ET")
            y -= 13
            if y < 40:
                break
        if y < 40:
            break
    stream = "\n".join(stream_lines).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode("ascii")
    )
    output_path.write_bytes(bytes(pdf))


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
