"""Compliance coverage summary + PDF export."""
import io

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from db import db
from rbac import require_module
from auth_utils import get_current_user
from routes.common import now_iso

router = APIRouter()


@router.get("/v1/compliance/summary")
async def compliance_summary(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/compliance"))):
    from compliance import compute_compliance_summary, compute_operational_controls
    summary = await compute_compliance_summary(db)
    summary["operational_controls"] = await compute_operational_controls(db)
    return summary


@router.get("/v1/compliance/controls/{control_id}/findings")
async def compliance_control_findings(control_id: str, user: dict = Depends(get_current_user)):
    from compliance import get_control_findings
    return await get_control_findings(db, control_id)


@router.get("/v1/reports/pdf/compliance")
async def export_compliance_pdf(user: dict = Depends(get_current_user)):
    from reportlab.platypus import Paragraph, Spacer
    import pdf_theme as theme
    from pdf_charts import bar_chart
    from compliance import compute_compliance_summary, compute_operational_controls

    summary = await compute_compliance_summary(db)
    operational_controls = await compute_operational_controls(db)
    styles = theme.get_styles()

    buffer = io.BytesIO()
    doc, elements = theme.build_doc(buffer, "Compliance Coverage Report")
    elements.append(Paragraph("Compliance Coverage Report", styles["title"]))
    elements.append(Paragraph(f"Generated {now_iso()[:19].replace('T', ' ')} UTC", styles["subtitle"]))
    elements.append(Paragraph(summary["methodology_note"], styles["muted"]))
    elements.append(Spacer(1, 10))

    coverage_str = f"{summary['coverage_pct']}%" if summary.get("coverage_pct") is not None else "—"
    gap_count = len([c for c in summary["controls"] if c["status"] == "gap"])
    at_risk_count = len([c for c in summary["controls"] if c["status"] == "at_risk"])
    pci_coverage_str = f"{summary['pci_dss_coverage_pct']}%" if summary.get("pci_dss_coverage_pct") is not None else "—"
    elements.append(theme.stat_cards([
        {"label": "CIS Controls Coverage", "value": coverage_str, "color": "#2F81F7"},
        {"label": "PCI-DSS Coverage", "value": pci_coverage_str, "color": "#a855f7"},
        {"label": "Controls with a Gap", "value": str(gap_count), "color": "#ef4444"},
        {"label": "Open Findings", "value": str(summary.get("total_open_findings", 0)), "color": "#64748b"},
    ]))

    if summary["controls"]:
        elements.append(Paragraph("CIS Controls — Open Findings by Control", styles["h2"]))
        elements.append(bar_chart(
            [c["id"] for c in summary["controls"]],
            [c["critical"] + c["high"] for c in summary["controls"]],
            bar_color="#ef4444"))
        elements.append(Spacer(1, 8))
        rows = [[c["id"], c["name"], c["critical"], c["high"], c["medium"], c["low"],
                 c["status"].replace("_", " ").title()] for c in summary["controls"]]
        elements.append(theme.styled_table(
            ["Control", "Name", "Crit", "High", "Med", "Low", "Status"], rows,
            col_widths=[42, 168, 32, 32, 32, 32, 58], numeric_cols=(2, 3, 4, 5)))

    if summary["unmapped_clean_controls"]:
        elements.append(Paragraph("Controls with no findings currently mapped", styles["h2"]))
        for c in summary["unmapped_clean_controls"]:
            elements.append(Paragraph(f"&#8226; <b>{c['id']}</b> — {c['name']}", styles["bullet"]))

    if summary["nist_functions"]:
        elements.append(Paragraph("NIST CSF 2.0 Functions", styles["h2"]))
        rows2 = [[f"{n['function']} — {n['label']}", n["critical"], n["high"], n["total"]] for n in summary["nist_functions"]]
        elements.append(theme.styled_table(["Function", "Critical", "High", "Total Open"], rows2, numeric_cols=(1, 2, 3)))

    if summary.get("pci_dss_requirements"):
        pci_coverage_str = f"{summary['pci_dss_coverage_pct']}%" if summary.get("pci_dss_coverage_pct") is not None else "—"
        elements.append(Paragraph(f"PCI-DSS v4.0 Requirements — Coverage {pci_coverage_str}", styles["h2"]))
        rows_pci = [[c["id"].replace("PCI-", "Req "), c["name"], c["critical"], c["high"], c["medium"], c["low"],
                     c["status"].replace("_", " ").title()] for c in summary["pci_dss_requirements"]]
        elements.append(theme.styled_table(
            ["Requirement", "Name", "Crit", "High", "Med", "Low", "Status"], rows_pci,
            col_widths=[48, 162, 32, 32, 32, 32, 58], numeric_cols=(2, 3, 4, 5)))
        if summary.get("unmapped_clean_pci_dss"):
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(
                "Requirements with no equivalent signal in VulnOps (e.g. Requirement 9, physical access controls) "
                "-- shown as unmapped rather than a false clean bill of health:", styles["muted"]))
            for c in summary["unmapped_clean_pci_dss"]:
                elements.append(Paragraph(f"&#8226; <b>{c['id'].replace('PCI-', 'Req ')}</b> — {c['name']}", styles["bullet"]))

    if operational_controls:
        elements.append(Paragraph("ISO 27001:2022 / SOC 2 / PCI-DSS — Operational Controls", styles["h2"]))
        elements.append(Paragraph(
            "Capability- and usage-based controls (is the feature in place, is it actually being used) rather than "
            "finding counts -- closer to what an auditor's control questionnaire asks.", styles["muted"]))
        elements.append(Spacer(1, 6))
        rows3 = [[c["label"], ", ".join(c["iso27001"]), ", ".join(c["soc2"]),
                  ", ".join(r.replace("PCI-", "") for r in c.get("pci_dss", [])) or "—",
                  c["status"].replace("_", " ").title()]
                 for c in operational_controls]
        elements.append(theme.styled_table(["Control", "ISO 27001", "SOC 2", "PCI-DSS", "Status"], rows3,
                                             col_widths=[150, 62, 55, 55, 88]))

    theme.build(doc, elements)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf",
                              headers={"Content-Disposition": "attachment; filename=compliance-coverage.pdf"})
