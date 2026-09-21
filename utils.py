"""
Utility functions for DFEMS:
- generate_file_hash: computes SHA-256 of a file (read in chunks, so large files are fine)
- generate_report_pdf: builds a simple PDF report for a case using reportlab
"""

import hashlib
import os


def generate_file_hash(filepath):
    """Return SHA-256 hex digest of the file at filepath."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(8192), b""):
            sha256.update(block)
    return sha256.hexdigest()


def generate_report_pdf(case, evidence_with_logs, base_dir):
    """
    Build a PDF report for a case: case info, each evidence item, its hash,
    and its chain-of-custody log. Returns the path to the generated PDF.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )

    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, f"case_{case['_id']}_report.pdf")

    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=18)
    heading_style = styles["Heading2"]
    normal = styles["Normal"]

    story = []
    story.append(Paragraph("Digital Forensic Evidence Management System", title_style))
    story.append(Paragraph("Case Investigation Report", styles["Heading3"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph(f"<b>Case Title:</b> {case['title']}", normal))
    story.append(Paragraph(f"<b>Description:</b> {case['description'] or '-'}", normal))
    story.append(Paragraph(f"<b>Created By:</b> {case['created_by']}", normal))
    story.append(Paragraph(f"<b>Created At:</b> {case['created_at']}", normal))
    story.append(Spacer(1, 16))

    if not evidence_with_logs:
        story.append(Paragraph("No evidence has been uploaded for this case.", normal))

    for ev, custody in evidence_with_logs:
        story.append(Paragraph(f"Evidence: {ev['original_filename']}", heading_style))
        story.append(Paragraph(f"<b>SHA-256 Hash:</b> {ev['file_hash']}", normal))
        story.append(Paragraph(f"<b>Uploaded By:</b> {ev['uploader']}", normal))
        story.append(Paragraph(f"<b>Uploaded At:</b> {ev['uploaded_at']}", normal))
        story.append(Spacer(1, 8))

        if custody:
            table_data = [["Timestamp", "User", "Action"]]
            for c in custody:
                table_data.append([c["timestamp"], c["username"], c["action"]])
            t = Table(table_data, colWidths=[130, 100, 220])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
            ]))
            story.append(t)
        story.append(Spacer(1, 16))

    doc.build(story)
    return pdf_path
