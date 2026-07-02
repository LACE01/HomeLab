"""Compliance coverage summary + PDF export."""
import io

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from db import db
from auth_utils import get_current_user
from routes.common import now_iso

router = APIRouter()


@router.get("/v1/compliance/summary")
async def compliance_summary(user: dict = Depends(get_current_user)):
    from compliance import compute_compliance_summary
    return await compute_compliance_summary(db)


@router.get("/v1/compliance/controls/{control_id}/findings")
async def compliance_control_findings(control_id: str, user: dict = Depends(get_current_user)):
    from compliance import get_control_findings
    return await get_control_findings(db, control_id)


@router.get("/v1/reports/pdf/compliance")
async def export_compliance_pdf(user: dict = Depends(get_current_user)):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from pdf_charts import bar_chart
    from compliance import compute_compliance_summary

    summary = await compute_compliance_summary(db)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#0D1117"))
    elements: list = []
    elements.append(Paragraph("VulnOps — Compliance Coverage Report", title_style))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"Generated: {now_iso()}", styles["Normal"]))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(summary["methodology_note"], styles["Italic"]))
    elements.append(Spacer(1, 12))

    coverage_str = f"{summary['coverage_pct']}%" if summary.get("coverage_pct") is not None else "No data yet"
    elements.append(Paragraph(f"<b>CIS Controls v8 Coverage:</b> {coverage_str} of mapped controls with no Critical/High gaps", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    if summary["controls"]:
        elements.append(Paragraph("<b>CIS Controls — Open Findings by Control</b>", styles["Heading3"]))
        elements.append(bar_chart(
            [c["id"] for c in summary["controls"]],
            [c["critical"] + c["high"] for c in summary["controls"]],
            bar_color="#ef4444"))
        elements.append(Spacer(1, 6))
        rows = [["Control", "Name", "Critical", "High", "Medium", "Low", "Status"]]
        for c in summary["controls"]:
            rows.append([c["id"], c["name"], str(c["critical"]), str(c["high"]), str(c["medium"]), str(c["low"]), c["status"].replace("_", " ").title()])
        t = Table(rows, hAlign="LEFT", colWidths=[45, 175, 45, 40, 50, 40, 55])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363D")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 12))

    if summary["unmapped_clean_controls"]:
        elements.append(Paragraph("<b>Controls with no findings currently mapped</b>", styles["Heading3"]))
        for c in summary["unmapped_clean_controls"]:
            elements.append(Paragraph(f"• {c['id']} — {c['name']}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    if summary["nist_functions"]:
        elements.append(Paragraph("<b>NIST CSF 2.0 Functions</b>", styles["Heading3"]))
        rows2 = [["Function", "Critical", "High", "Total Open"]]
        for n in summary["nist_functions"]:
            rows2.append([f"{n['function']} — {n['label']}", str(n["critical"]), str(n["high"]), str(n["total"])])
        t2 = Table(rows2, hAlign="LEFT")
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363D")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        elements.append(t2)

    doc.build(elements)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf",
                              headers={"Content-Disposition": "attachment; filename=compliance-coverage.pdf"})
