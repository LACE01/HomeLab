"""Reports routes: CSV export, PDF executive report, report catalog, prebuilt + custom report runner."""
import csv
import io
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user
from routes.common import now_iso
from routes.dashboards import dashboard_executive
from reports import REPORT_CATALOG, GROUP_FIELDS, run_prebuilt, run_custom

router = APIRouter()


@router.get("/v1/reports/csv/findings")
async def export_findings_csv(user: dict = Depends(get_current_user),
                              severity: Optional[str] = None, status: Optional[str] = None):
    flt: dict = {}
    if severity:
        flt["severity"] = severity
    if status:
        flt["status"] = status
    items = await db.findings.find(flt, {"_id": 0}).limit(5000).to_list(5000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "CVE", "QID", "Title", "Severity", "CVSS", "EPSS", "KEV",
        "Risk Score", "Status", "Asset", "IP", "Owner Team", "First Seen", "Due", "Source",
    ])
    for f in items:
        writer.writerow([
            f.get("id"), f.get("cve") or "", f.get("source_native_id") or "", f.get("title"),
            f.get("severity"), f.get("cvss_score"), f.get("epss_score"),
            "YES" if f.get("kev_flag") else "NO", f.get("risk_score"),
            f.get("status"), f.get("asset_hostname"), f.get("asset_ip") or "",
            f.get("owner_team"), f.get("first_seen_at"), f.get("due_at"), f.get("source_tool"),
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@router.get("/v1/reports/pdf/executive")
async def export_executive_pdf(user: dict = Depends(get_current_user)):
    from reportlab.platypus import Paragraph, Spacer
    import pdf_theme as theme
    from pdf_charts import trend_line_chart, bar_chart

    dash = await dashboard_executive(user)
    styles = theme.get_styles()

    buffer = io.BytesIO()
    doc, elements = theme.build_doc(buffer, "Executive Security Report")
    elements.append(Paragraph("Executive Security Report", styles["title"]))
    elements.append(Paragraph(f"Generated {now_iso()[:19].replace('T', ' ')} UTC", styles["subtitle"]))

    score_str = f"{dash['current_score']} / 100" if dash.get("current_score") is not None else "—"
    sla_str = f"{dash['sla_compliance']}%" if dash.get("sla_compliance") is not None else "—"
    mttr_str = f"{dash['mttr_days']}d" if dash.get("mttr_days") is not None else "—"
    elements.append(theme.stat_cards([
        {"label": "Security Score", "value": score_str, "color": "#2F81F7"},
        {"label": "SLA Compliance", "value": sla_str, "color": "#22c55e"},
        {"label": "Mean Time to Remediate", "value": mttr_str, "color": "#f59e0b"},
    ]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(dash["narrative"], styles["body"]))

    if dash.get("snapshots"):
        elements.append(Paragraph("Score / SLA Trend", styles["h2"]))
        elements.append(trend_line_chart(
            dash["snapshots"], [{"key": "org_score", "label": "Score", "color": "#2F81F7"},
                                 {"key": "sla_compliance", "label": "SLA %", "color": "#f59e0b"}]))

    elements.append(Paragraph("Critical/High Open Findings by Product", styles["h2"]))
    if dash["by_product"]:
        elements.append(bar_chart(
            [p["name"] for p in dash["by_product"]],
            [p.get("critical_open", 0) for p in dash["by_product"]],
            bar_color="#ef4444"))
        elements.append(Spacer(1, 8))
    rows = [[p["name"], p.get("critical_open", 0)] for p in dash["by_product"]]
    elements.append(theme.styled_table(["Product", "Critical/High Open"], rows, numeric_cols=(1,)))

    if dash["score_factors"]:
        elements.append(Paragraph("Key Score Factors", styles["h2"]))
        for sf in dash["score_factors"]:
            elements.append(Paragraph(f"&#8226; <b>{sf['factor']}</b> ({sf['impact']}) — {sf['reason']}", styles["bullet"]))

    theme.build(doc, elements)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf",
                             headers={"Content-Disposition": "attachment; filename=executive-report.pdf"})


# --------------------------- REPORT BUILDER ---------------------------
@router.get("/v1/reports/catalog")
async def reports_catalog(user: dict = Depends(get_current_user)):
    return {"items": REPORT_CATALOG, "group_fields": GROUP_FIELDS,
            "filter_fields": ["severity", "status", "kev_flag", "internet_facing", "owner_team", "product_name", "asset_environment"],
            "metrics": [{"id": "count", "label": "Count of Findings"}, {"id": "risk_sum", "label": "Sum of Risk Score"}],
            "date_fields": ["first_seen_at", "last_seen_at", "due_at", "last_changed_at"]}


@router.get("/v1/reports/run/{report_id}")
async def run_report(report_id: str, fmt: str = "pdf", user: dict = Depends(get_current_user)):
    if fmt not in ("pdf", "csv"):
        raise HTTPException(400, "fmt must be 'pdf' or 'csv'")
    result = await run_prebuilt(db, report_id, fmt)
    if result is None:
        raise HTTPException(404, f"Unknown report_id: {report_id}")
    return result


class CustomReportBody(BaseModel):
    fmt: str = "pdf"
    group_by: str = "severity"
    metric: str = "count"
    filters: dict = {}
    date_field: Optional[str] = "first_seen_at"
    date_from: Optional[str] = None
    date_to: Optional[str] = None


@router.post("/v1/reports/run-custom")
async def run_custom_report(body: CustomReportBody, user: dict = Depends(get_current_user)):
    if body.fmt not in ("pdf", "csv"):
        raise HTTPException(400, "fmt must be 'pdf' or 'csv'")
    return await run_custom(db, body.model_dump(), body.fmt)
