"""Scheduled report delivery -- periodically generate one of the existing prebuilt
or custom reports (see reports.py, already used interactively from the Reports
page) and email it as an attachment to a fixed recipient list, without anyone
needing to remember to log in and click "export" on a cadence.

Reuses reports.run_prebuilt / reports.run_custom exactly as the interactive
/v1/reports/* routes do -- same report logic, same PDF/CSV rendering -- so a
scheduled report always matches what you'd get clicking the same report by hand.
Those functions return a plain fastapi.Response (see reports.py's _csv_response/
_pdf_response) whose .body is the fully-rendered file bytes; this module just
reads that instead of returning it over HTTP, and emails it instead.

Cadence check follows the same "elapsed hours since last send" pattern already
used by notifier.run_digest_dispatch for notification-rule digests, called from
the same hourly digest_dispatch_loop -- hourly is plenty precise for
daily/weekly/monthly schedules and avoids needing a second, dedicated scheduler
loop just for this.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

FREQUENCY_HOURS = {"daily": 24, "weekly": 24 * 7, "monthly": 24 * 30}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def list_scheduled_reports(db) -> list:
    return await db.scheduled_reports.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)


async def get_scheduled_report(db, report_id: str) -> Optional[dict]:
    return await db.scheduled_reports.find_one({"id": report_id}, {"_id": 0})


async def create_scheduled_report(db, body: dict, actor: str) -> dict:
    if body.get("frequency") not in FREQUENCY_HOURS:
        raise ValueError(f"frequency must be one of {list(FREQUENCY_HOURS)}")
    if body.get("source") == "prebuilt":
        from reports import REPORT_CATALOG
        if not any(r["id"] == body.get("report_id") for r in REPORT_CATALOG):
            raise ValueError(f"Unknown report_id: {body.get('report_id')}")
    elif body.get("source") != "custom":
        raise ValueError("source must be 'prebuilt' or 'custom'")
    recipients = [r.strip() for r in (body.get("recipients") or []) if r.strip()]
    if not recipients:
        raise ValueError("At least one recipient email is required")

    doc = {
        "id": str(uuid.uuid4()), "name": body.get("name") or "Untitled scheduled report",
        "source": body["source"], "report_id": body.get("report_id"),
        "custom_config": body.get("custom_config"),  # {group_by, metric, filters, date_field, date_from, date_to}
        "fmt": body.get("fmt") or "pdf", "frequency": body["frequency"],
        "recipients": recipients, "enabled": body.get("enabled", True),
        "last_sent_at": None, "last_send_error": None,
        "created_by": actor, "created_at": _now_iso(),
    }
    await db.scheduled_reports.insert_one(doc)
    from routes.common import _clean
    return _clean(doc)


async def update_scheduled_report(db, report_id: str, body: dict) -> Optional[dict]:
    existing = await get_scheduled_report(db, report_id)
    if not existing:
        return None
    if "frequency" in body and body["frequency"] not in FREQUENCY_HOURS:
        raise ValueError(f"frequency must be one of {list(FREQUENCY_HOURS)}")
    if "recipients" in body:
        body["recipients"] = [r.strip() for r in (body.get("recipients") or []) if r.strip()]
        if not body["recipients"]:
            raise ValueError("At least one recipient email is required")
    update = {k: v for k, v in body.items() if k in (
        "name", "source", "report_id", "custom_config", "fmt", "frequency", "recipients", "enabled",
    )}
    await db.scheduled_reports.update_one({"id": report_id}, {"$set": update})
    return await get_scheduled_report(db, report_id)


async def delete_scheduled_report(db, report_id: str) -> bool:
    result = await db.scheduled_reports.delete_one({"id": report_id})
    return getattr(result, "deleted_count", 0) > 0


async def _generate_report_bytes(db, schedule: dict) -> tuple:
    """Returns (content_bytes, filename, content_type) using the exact same report
    engine the interactive Reports page calls."""
    from reports import run_prebuilt, run_custom
    fmt = schedule.get("fmt") or "pdf"
    if schedule["source"] == "prebuilt":
        resp = await run_prebuilt(db, schedule["report_id"], fmt)
        if resp is None:
            raise ValueError(f"Unknown report_id: {schedule['report_id']}")
    else:
        resp = await run_custom(db, schedule.get("custom_config") or {}, fmt)

    content_disposition = resp.headers.get("content-disposition", "")
    filename = "report"
    if "filename=" in content_disposition:
        filename = content_disposition.split("filename=", 1)[1].strip('"')
    return resp.body, filename, resp.media_type


async def send_scheduled_report_now(db, report_id: str) -> dict:
    """Generates and emails a scheduled report immediately, regardless of whether
    its cadence window has elapsed -- used by both the "Send now" admin action and
    the actual due-check dispatcher below."""
    schedule = await get_scheduled_report(db, report_id)
    if not schedule:
        raise ValueError("Scheduled report not found")

    try:
        content, filename, content_type = await _generate_report_bytes(db, schedule)
    except Exception as e:
        await db.scheduled_reports.update_one(
            {"id": report_id}, {"$set": {"last_send_error": f"Report generation failed: {e}"}})
        raise

    from notifier import send_email_with_attachment
    subject = f"Nightwatch scheduled report: {schedule['name']}"
    body = (
        f"Your scheduled report \"{schedule['name']}\" is attached ({filename}).\n\n"
        f"Frequency: {schedule['frequency']}\n"
        f"Generated: {_now_iso()[:19].replace('T', ' ')} UTC\n\n"
        f"This is an automated delivery from Nightwatch. Manage this schedule under Admin -> Reports."
    )
    sent, errors = [], []
    for addr in schedule["recipients"]:
        result = await send_email_with_attachment(
            addr, subject, body, [{"filename": filename, "content": content, "content_type": content_type}]
        )
        if result.get("ok"):
            sent.append(addr)
        else:
            errors.append(f"{addr}: {result.get('text')}")

    now = _now_iso()
    await db.scheduled_reports.update_one(
        {"id": report_id},
        {"$set": {"last_sent_at": now, "last_send_error": "; ".join(errors) if errors else None}},
    )
    return {"ok": len(errors) == 0, "sent_to": sent, "errors": errors, "filename": filename}


async def run_due_scheduled_reports(db) -> dict:
    """Called from the hourly digest_dispatch_loop. Checks every enabled schedule's
    elapsed time since last_sent_at against its frequency window and sends the ones
    that are due -- a schedule that's never been sent is always due immediately
    (matches run_digest_dispatch's same "never sent = due now" behavior)."""
    schedules = await db.scheduled_reports.find({"enabled": {"$ne": False}}, {"_id": 0}).to_list(500)
    now = datetime.now(timezone.utc)
    sent, failed = 0, 0
    for schedule in schedules:
        window_hours = FREQUENCY_HOURS.get(schedule.get("frequency"), 24)
        last_sent = schedule.get("last_sent_at")
        due = True
        if last_sent:
            try:
                last_dt = datetime.fromisoformat(last_sent.replace("Z", "+00:00"))
                due = (now - last_dt).total_seconds() >= window_hours * 3600
            except Exception:
                due = True
        if not due:
            continue
        try:
            result = await send_scheduled_report_now(db, schedule["id"])
            sent += 1 if result["ok"] else 0
            failed += 0 if result["ok"] else 1
        except Exception:
            failed += 1
    return {"schedules_checked": len(schedules), "sent": sent, "failed": failed}
