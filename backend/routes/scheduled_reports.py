"""Scheduled report delivery: CRUD + manual "send now" trigger. Reuses the
same report catalog/custom-builder config shape the interactive /v1/reports/*
routes already use (see routes/reports_routes.py, reports.py)."""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from scheduled_reports import (
    list_scheduled_reports, get_scheduled_report, create_scheduled_report,
    update_scheduled_report, delete_scheduled_report, send_scheduled_report_now,
)

router = APIRouter()


class ScheduledReportBody(BaseModel):
    name: str
    source: str  # "prebuilt" | "custom"
    report_id: Optional[str] = None  # required if source == "prebuilt"
    custom_config: Optional[dict] = None  # required if source == "custom"
    fmt: str = "pdf"
    frequency: str  # "daily" | "weekly" | "monthly"
    recipients: List[str]
    enabled: bool = True


class ScheduledReportUpdate(BaseModel):
    name: Optional[str] = None
    report_id: Optional[str] = None
    custom_config: Optional[dict] = None
    fmt: Optional[str] = None
    frequency: Optional[str] = None
    recipients: Optional[List[str]] = None
    enabled: Optional[bool] = None


@router.get("/v1/reports/scheduled")
async def list_scheduled(user: dict = Depends(require_module("/reports"))):
    return {"items": await list_scheduled_reports(db)}


@router.post("/v1/reports/scheduled")
async def create_scheduled(body: ScheduledReportBody, user: dict = Depends(require_module("/reports", level="edit"))):
    try:
        return await create_scheduled_report(db, body.model_dump(), actor=user["email"])
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.patch("/v1/reports/scheduled/{report_id}")
async def update_scheduled(report_id: str, body: ScheduledReportUpdate,
                            user: dict = Depends(require_module("/reports", level="edit"))):
    try:
        updated = await update_scheduled_report(db, report_id, {k: v for k, v in body.model_dump().items() if v is not None})
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not updated:
        raise HTTPException(404, "Scheduled report not found")
    return updated


@router.delete("/v1/reports/scheduled/{report_id}")
async def delete_scheduled(report_id: str, user: dict = Depends(require_module("/reports", level="edit"))):
    ok = await delete_scheduled_report(db, report_id)
    if not ok:
        raise HTTPException(404, "Scheduled report not found")
    return {"ok": True}


@router.post("/v1/reports/scheduled/{report_id}/send-now")
async def send_now(report_id: str, user: dict = Depends(require_module("/reports", level="edit"))):
    try:
        return await send_scheduled_report_now(db, report_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
