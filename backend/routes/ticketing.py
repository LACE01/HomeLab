"""Ticketing / SOAR config -- Jira connection (singleton) + generic webhook
destinations (list). See ticketing.py for the actual send logic; this is just
the admin-facing CRUD, mirroring the Splunk/Wazuh config pattern (secrets never
echoed back, blank-on-update keeps the existing value)."""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from rbac import require_module
from auth_utils import get_current_user
from routes.common import now_iso, _clean

router = APIRouter()


class JiraConfigBody(BaseModel):
    base_url: str = ""
    email: str = ""
    api_token: str = ""
    project_key: str = ""
    issue_type: str = "Task"
    enabled: bool = True


@router.get("/v1/admin/ticketing/jira-config")
async def get_jira_config(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ticketing"))):
    cfg = await db.jira_config.find_one({"id": "singleton"}, {"_id": 0})
    if not cfg:
        return {"id": "singleton", "base_url": "", "email": "", "project_key": "", "issue_type": "Task", "enabled": False, "configured": False}
    configured = bool(cfg.get("api_token"))
    cfg.pop("api_token", None)
    return {**cfg, "configured": configured}


@router.put("/v1/admin/ticketing/jira-config")
async def put_jira_config(body: JiraConfigBody, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ticketing", level="edit"))):
    existing = await db.jira_config.find_one({"id": "singleton"}, {"_id": 0})
    api_token = body.api_token.strip() or (existing or {}).get("api_token", "")
    doc = {
        "id": "singleton", "base_url": body.base_url.strip(), "email": body.email.strip(),
        "api_token": api_token, "project_key": body.project_key.strip(),
        "issue_type": body.issue_type.strip() or "Task", "enabled": body.enabled,
        "updated_at": now_iso(), "updated_by": user["email"],
    }
    await db.jira_config.update_one({"id": "singleton"}, {"$set": doc}, upsert=True)
    return {**doc, "api_token": None, "configured": bool(api_token)}


class WebhookBody(BaseModel):
    name: str
    url: str
    secret: Optional[str] = None
    enabled: bool = True


@router.get("/v1/admin/ticketing/webhooks")
async def list_webhooks(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ticketing"))):
    items = await db.webhook_destinations.find({}, {"_id": 0, "secret": 0}).sort("created_at", -1).to_list(200)
    return {"items": items}


@router.post("/v1/admin/ticketing/webhooks")
async def create_webhook(body: WebhookBody, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ticketing", level="edit"))):
    if not body.name.strip() or not body.url.strip():
        raise HTTPException(400, "Name and URL are required")
    doc = {
        "id": str(uuid.uuid4()), "name": body.name.strip(), "url": body.url.strip(),
        "secret": body.secret or None, "enabled": body.enabled,
        "created_at": now_iso(), "created_by": user["email"],
    }
    await db.webhook_destinations.insert_one(doc)
    return {**_clean(doc), "secret": None}


@router.put("/v1/admin/ticketing/webhooks/{webhook_id}")
async def update_webhook(webhook_id: str, body: WebhookBody, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ticketing", level="edit"))):
    existing = await db.webhook_destinations.find_one({"id": webhook_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Webhook not found")
    secret = body.secret if body.secret else existing.get("secret")
    update = {"name": body.name.strip(), "url": body.url.strip(), "secret": secret, "enabled": body.enabled}
    await db.webhook_destinations.update_one({"id": webhook_id}, {"$set": update})
    return {**_clean({**existing, **update}), "secret": None}


@router.delete("/v1/admin/ticketing/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/ticketing", level="edit"))):
    result = await db.webhook_destinations.delete_one({"id": webhook_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Webhook not found")
    return {"ok": True}
