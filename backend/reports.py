"""Report engine: pre-built report catalog + dynamic builder + CSV/PDF formatting."""
import io
import csv
from datetime import datetime, timezone, timedelta
from typing import Optional


REPORT_CATALOG = [
    {"id": "open_by_severity", "name": "Open Findings by Severity",
     "description": "Count of open findings grouped by severity. Best for executive sit-reps.",
     "category": "executive", "default_format": "pdf"},
    {"id": "sla_compliance_trend", "name": "SLA Compliance Trend (30d)",
     "description": "Daily SLA on-time percentage over the last 30 days.",
     "category": "executive", "default_format": "pdf"},
    {"id": "top_risk_assets", "name": "Top 25 Highest Risk Assets",
     "description": "Ranked by sum of risk score across open findings.",
     "category": "operational", "default_format": "csv"},
    {"id": "aging_report", "name": "Aging Report by Severity",
     "description": "Open findings bucketed by age (0-7, 8-30, 31-60, 61-90, 90+) split by severity.",
     "category": "operational", "default_format": "pdf"},
    {"id": "throughput", "name": "Throughput — Opened vs Closed (30d)",
     "description": "New findings vs resolved per day for the last 30 days.",
     "category": "operational", "default_format": "csv"},
    {"id": "critical_by_bu", "name": "Critical/High by Business Unit",
     "description": "Critical and High severity exposure per product / business unit.",
     "category": "executive", "default_format": "pdf"},
    {"id": "kev_exposure", "name": "KEV Exposure Report",
     "description": "All findings flagged as Known Exploited Vulnerabilities by CISA KEV.",
     "category": "security", "default_format": "csv"},
    {"id": "open_exceptions", "name": "Open Risk Acceptances",
     "description": "Active exceptions with rationale, approver, and expiration dates.",
     "category": "compliance", "default_format": "csv"},
    {"id": "reopened", "name": "Reopened Findings",
     "description": "Findings that regressed — were closed but detected again.",
     "category": "operational", "default_format": "csv"},
    {"id": "overdue_critical", "name": "Overdue Critical / High",
     "description": "Findings past SLA due date at Critical or High severity.",
     "category": "operational", "default_format": "csv"},
]


GROUP_FIELDS = ["severity", "status", "owner_team", "product_name", "asset_environment",
                "asset_criticality", "source_tool", "cve", "asset_hostname"]


def _now():
    return datetime.now(timezone.utc)


async def _open_findings_filter():
    return {"status": {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]}}


def _csv_response(rows: list, headers: list, filename: str):
    from fastapi.responses import StreamingResponse
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(headers)
    for r in rows:
        w.writerow([r.get(h, "") if isinstance(r, dict) else r[i] for i, h in enumerate(headers)])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={filename}.csv"})


def _pdf_response(title: str, sections: list, filename: str):
    """sections: list of dicts: {type:'text', value:'...'} or {type:'table', headers:[], rows:[[]]}"""
    from fastapi.responses import StreamingResponse
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("t", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#0D1117"))
    elements = [Paragraph(f"VulnOps — {title}", title_style), Spacer(1, 6),
                Paragraph(f"Generated: {_now().isoformat()}", styles["Normal"]), Spacer(1, 12)]
    for sec in sections:
        if sec["type"] == "text":
            elements.append(Paragraph(sec["value"], styles["Normal"]))
            elements.append(Spacer(1, 6))
        elif sec["type"] == "heading":
            elements.append(Paragraph(f"<b>{sec['value']}</b>", styles["Heading3"]))
        elif sec["type"] == "table":
            data = [sec["headers"]] + sec["rows"]
            t = Table(data, hAlign="LEFT")
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1117")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363D")),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 10))
    doc.build(elements)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f"attachment; filename={filename}.pdf"})


async def run_prebuilt(db, report_id: str, fmt: str):
    open_flt = await _open_findings_filter()

    if report_id == "open_by_severity":
        pipeline = [{"$match": open_flt}, {"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
        agg = {r["_id"]: r["count"] async for r in db.findings.aggregate(pipeline)}
        order = ["Critical", "High", "Medium", "Low", "Info"]
        rows = [[s, agg.get(s, 0)] for s in order]
        if fmt == "csv":
            return _csv_response([{"severity": r[0], "count": r[1]} for r in rows], ["severity", "count"], "open-by-severity")
        return _pdf_response("Open Findings by Severity",
                             [{"type": "table", "headers": ["Severity", "Open Count"], "rows": rows}],
                             "open-by-severity")

    if report_id == "top_risk_assets":
        pipeline = [{"$match": open_flt},
                    {"$group": {"_id": {"asset_id": "$asset_id", "hostname": "$asset_hostname"},
                                "total_risk": {"$sum": "$risk_score"}, "count": {"$sum": 1},
                                "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "Critical"]}, 1, 0]}}}},
                    {"$sort": {"total_risk": -1}}, {"$limit": 25}]
        rows = []
        async for r in db.findings.aggregate(pipeline):
            rows.append([r["_id"]["hostname"], r["count"], r["critical"], round(r["total_risk"], 1)])
        if fmt == "csv":
            return _csv_response(
                [{"hostname": r[0], "open_findings": r[1], "critical": r[2], "risk_score_sum": r[3]} for r in rows],
                ["hostname", "open_findings", "critical", "risk_score_sum"], "top-risk-assets")
        return _pdf_response("Top 25 Highest Risk Assets",
                             [{"type": "table", "headers": ["Hostname", "Open", "Critical", "Risk Sum"], "rows": rows}],
                             "top-risk-assets")

    if report_id == "aging_report":
        now_dt = _now()
        buckets = {"0-7": {}, "8-30": {}, "31-60": {}, "61-90": {}, "90+": {}}
        async for f in db.findings.find(open_flt, {"_id": 0, "first_seen_at": 1, "severity": 1}):
            try:
                fs = datetime.fromisoformat(f.get("first_seen_at", "").replace("Z", "+00:00"))
                age = (now_dt - fs).days
                key = "0-7" if age <= 7 else "8-30" if age <= 30 else "31-60" if age <= 60 else "61-90" if age <= 90 else "90+"
                sev = f.get("severity", "Info")
                buckets[key][sev] = buckets[key].get(sev, 0) + 1
            except Exception:
                pass
        severities = ["Critical", "High", "Medium", "Low", "Info"]
        rows = [[b] + [buckets[b].get(s, 0) for s in severities] for b in buckets]
        if fmt == "csv":
            return _csv_response(
                [dict(zip(["bucket"] + severities, r)) for r in rows], ["bucket"] + severities, "aging-report")
        return _pdf_response("Aging Report by Severity",
                             [{"type": "table", "headers": ["Age (days)"] + severities, "rows": rows}],
                             "aging-report")

    if report_id == "throughput":
        rows = []
        for d in range(29, -1, -1):
            day = _now() - timedelta(days=d)
            start = day.replace(hour=0, minute=0, second=0).isoformat()
            end = (day + timedelta(days=1)).replace(hour=0, minute=0, second=0).isoformat()
            opened = await db.findings.count_documents({"first_seen_at": {"$gte": start, "$lt": end}})
            closed = await db.findings.count_documents({"last_changed_at": {"$gte": start, "$lt": end},
                                                        "status": {"$in": ["Fixed validated", "Mitigated", "Closed administratively"]}})
            rows.append([day.strftime("%Y-%m-%d"), opened, closed, opened - closed])
        if fmt == "csv":
            return _csv_response([dict(zip(["date", "opened", "closed", "net"], r)) for r in rows],
                                 ["date", "opened", "closed", "net"], "throughput")
        return _pdf_response("Throughput — Opened vs Closed (30d)",
                             [{"type": "table", "headers": ["Date", "Opened", "Closed", "Net"], "rows": rows}],
                             "throughput")

    if report_id == "critical_by_bu":
        pipeline = [{"$match": {**open_flt, "severity": {"$in": ["Critical", "High"]}}},
                    {"$group": {"_id": "$product_name", "count": {"$sum": 1},
                                "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "Critical"]}, 1, 0]}}}}]
        rows = []
        async for r in db.findings.aggregate(pipeline):
            rows.append([r["_id"] or "Unassigned", r["critical"], r["count"] - r["critical"], r["count"]])
        rows.sort(key=lambda x: -x[3])
        if fmt == "csv":
            return _csv_response([dict(zip(["business_unit", "critical", "high", "total"], r)) for r in rows],
                                 ["business_unit", "critical", "high", "total"], "critical-by-bu")
        return _pdf_response("Critical / High by Business Unit",
                             [{"type": "table", "headers": ["Business Unit", "Critical", "High", "Total"], "rows": rows}],
                             "critical-by-bu")

    if report_id == "kev_exposure":
        items = await db.findings.find({"kev_flag": True, **open_flt}, {"_id": 0}).sort("risk_score", -1).to_list(2000)
        if fmt == "csv":
            rows = [{"cve": f.get("cve"), "title": f.get("title"), "severity": f.get("severity"),
                     "risk_score": f.get("risk_score"), "asset": f.get("asset_hostname"),
                     "owner": f.get("owner_team"), "status": f.get("status"),
                     "first_seen": f.get("first_seen_at"), "due": f.get("due_at")} for f in items]
            return _csv_response(rows, ["cve", "title", "severity", "risk_score", "asset", "owner", "status", "first_seen", "due"], "kev-exposure")
        rows = [[f.get("cve") or "—", (f.get("title") or "")[:60], f.get("severity"),
                 f.get("risk_score"), f.get("asset_hostname"), f.get("owner_team")] for f in items[:60]]
        return _pdf_response("KEV (Known Exploited) Exposure",
                             [{"type": "text", "value": f"{len(items)} KEV findings open. Showing top {len(rows)}."},
                              {"type": "table", "headers": ["CVE", "Title", "Sev", "Risk", "Asset", "Owner"], "rows": rows}],
                             "kev-exposure")

    if report_id == "open_exceptions":
        items = await db.exceptions.find({"status": "active"}, {"_id": 0}).to_list(500)
        for e in items:
            f = await db.findings.find_one({"id": e["finding_id"]}, {"_id": 0, "title": 1, "severity": 1, "asset_hostname": 1})
            if f:
                e["finding_title"] = f.get("title"); e["severity"] = f.get("severity"); e["asset_hostname"] = f.get("asset_hostname")
        rows = [{"finding_title": e.get("finding_title"), "severity": e.get("severity"),
                 "asset": e.get("asset_hostname"), "approver": e.get("approver"),
                 "approved_at": e.get("approved_at"), "expires_at": e.get("expires_at"),
                 "rationale": e.get("rationale")} for e in items]
        if fmt == "csv":
            return _csv_response(rows, ["finding_title", "severity", "asset", "approver", "approved_at", "expires_at", "rationale"], "open-exceptions")
        table_rows = [[r["finding_title"][:50] if r.get("finding_title") else "", r.get("severity") or "", r.get("asset") or "", r.get("approver") or "", (r.get("expires_at") or "")[:10]] for r in rows]
        return _pdf_response("Open Risk Acceptances",
                             [{"type": "table", "headers": ["Finding", "Sev", "Asset", "Approver", "Expires"], "rows": table_rows}],
                             "open-exceptions")

    if report_id == "reopened":
        items = await db.findings.find({"status": "Reopened"}, {"_id": 0}).sort("risk_score", -1).to_list(1000)
        rows = [{"cve": f.get("cve"), "title": f.get("title"), "severity": f.get("severity"),
                 "asset": f.get("asset_hostname"), "owner": f.get("owner_team"),
                 "reopened_count": f.get("reopened_count"), "first_seen": f.get("first_seen_at"),
                 "last_seen": f.get("last_seen_at")} for f in items]
        if fmt == "csv":
            return _csv_response(rows, ["cve", "title", "severity", "asset", "owner", "reopened_count", "first_seen", "last_seen"], "reopened")
        table_rows = [[r.get("cve") or "—", (r.get("title") or "")[:50], r.get("severity"), r.get("asset"), r.get("owner"), r.get("reopened_count")] for r in rows]
        return _pdf_response("Reopened Findings",
                             [{"type": "text", "value": f"{len(items)} findings have regressed after closure."},
                              {"type": "table", "headers": ["CVE", "Title", "Sev", "Asset", "Owner", "x Reopened"], "rows": table_rows}],
                             "reopened")

    if report_id == "overdue_critical":
        now_iso = _now().isoformat()
        items = await db.findings.find({"due_at": {"$lt": now_iso},
                                        "severity": {"$in": ["Critical", "High"]}, **open_flt},
                                       {"_id": 0}).sort("due_at", 1).to_list(2000)
        rows = [{"cve": f.get("cve"), "title": f.get("title"), "severity": f.get("severity"),
                 "asset": f.get("asset_hostname"), "owner": f.get("owner_team"),
                 "due_at": f.get("due_at"), "days_overdue": (datetime.now(timezone.utc) - datetime.fromisoformat(f["due_at"].replace("Z","+00:00"))).days if f.get("due_at") else None}
                for f in items]
        if fmt == "csv":
            return _csv_response(rows, ["cve", "title", "severity", "asset", "owner", "due_at", "days_overdue"], "overdue-critical-high")
        table_rows = [[r.get("cve") or "—", (r.get("title") or "")[:50], r.get("severity"), r.get("asset"), r.get("owner"), r.get("days_overdue")] for r in rows[:80]]
        return _pdf_response("Overdue Critical / High",
                             [{"type": "table", "headers": ["CVE", "Title", "Sev", "Asset", "Owner", "Days Overdue"], "rows": table_rows}],
                             "overdue-critical-high")

    if report_id == "sla_compliance_trend":
        snaps = await db.score_snapshots.find({}, {"_id": 0}).sort("date", 1).to_list(60)
        rows = [{"date": s.get("date", "")[:10], "sla_compliance": s.get("sla_compliance"),
                 "mttr_days": s.get("mttr_days"), "org_score": s.get("org_score")} for s in snaps]
        if fmt == "csv":
            return _csv_response(rows, ["date", "sla_compliance", "mttr_days", "org_score"], "sla-trend")
        table_rows = [[r["date"], f"{r['sla_compliance']}%", r["mttr_days"], r["org_score"]] for r in rows]
        return _pdf_response("SLA Compliance Trend",
                             [{"type": "table", "headers": ["Date", "SLA %", "MTTR (d)", "Score"], "rows": table_rows}],
                             "sla-trend")

    return None


async def run_custom(db, body: dict, fmt: str):
    """Dynamic builder. Body: {filters:{}, group_by:str, metric:'count'|'risk_sum', date_field:str, date_from:str, date_to:str}"""
    filters: dict = {}
    raw = body.get("filters") or {}
    if raw.get("severity"):
        filters["severity"] = {"$in": raw["severity"]} if isinstance(raw["severity"], list) else raw["severity"]
    if raw.get("status"):
        filters["status"] = {"$in": raw["status"]} if isinstance(raw["status"], list) else raw["status"]
    if raw.get("kev_flag") is not None:
        filters["kev_flag"] = raw["kev_flag"]
    if raw.get("internet_facing") is not None:
        filters["internet_facing"] = raw["internet_facing"]
    if raw.get("owner_team"):
        filters["owner_team"] = raw["owner_team"]
    if raw.get("product_name"):
        filters["product_name"] = raw["product_name"]
    if raw.get("asset_environment"):
        filters["asset_environment"] = raw["asset_environment"]

    date_field = body.get("date_field", "first_seen_at")
    if body.get("date_from"):
        filters.setdefault(date_field, {})["$gte"] = body["date_from"]
    if body.get("date_to"):
        filters.setdefault(date_field, {})["$lt"] = body["date_to"]

    group_by = body.get("group_by") or "severity"
    if group_by not in GROUP_FIELDS:
        from fastapi import HTTPException
        raise HTTPException(400, f"group_by must be one of {GROUP_FIELDS}")

    metric = body.get("metric", "count")
    metric_expr = {"$sum": 1} if metric == "count" else {"$sum": "$risk_score"}

    pipeline = [{"$match": filters},
                {"$group": {"_id": f"${group_by}", "metric": metric_expr, "count": {"$sum": 1},
                            "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "Critical"]}, 1, 0]}}}},
                {"$sort": {"metric": -1}}, {"$limit": 200}]
    rows = []
    async for r in db.findings.aggregate(pipeline):
        rows.append([r["_id"] or "—", r["count"], r["critical"], round(r["metric"], 1)])

    metric_label = "Count" if metric == "count" else "Risk Sum"
    if fmt == "csv":
        csv_rows = [dict(zip([group_by, "count", "critical", metric_label.lower().replace(" ", "_")], r)) for r in rows]
        return _csv_response(csv_rows, [group_by, "count", "critical", metric_label.lower().replace(" ", "_")], "custom-report")
    title = f"Custom Report — by {group_by}"
    return _pdf_response(title,
                         [{"type": "text", "value": f"Metric: {metric_label} · Filters: {filters or 'none'}"},
                          {"type": "table", "headers": [group_by, "Count", "Critical", metric_label], "rows": rows}],
                         "custom-report")
