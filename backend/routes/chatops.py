"""Slack ChatOps: the inbound slash-command webhook (public, signature-verified) and
the admin config endpoints (authenticated)."""
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from pydantic import BaseModel

from db import db
from auth_utils import require_role
from routes.common import now_iso

router = APIRouter()

CONFIG_ID = "slack_chatops"  # singleton config doc


class ChatOpsConfigBody(BaseModel):
    signing_secret: str
    enabled: bool = True
    workspace_label: Optional[str] = None


@router.get("/v1/admin/chatops/config")
async def get_chatops_config(user: dict = Depends(require_role("admin"))):
    cfg = await db.chatops_config.find_one({"id": CONFIG_ID}, {"_id": 0})
    if not cfg:
        return {"configured": False, "enabled": False}
    return {
        "configured": True, "enabled": cfg.get("enabled", False),
        "workspace_label": cfg.get("workspace_label"),
        # Never echo the signing secret back -- masked, same convention as other
        # integration credentials in this app.
        "signing_secret_set": bool(cfg.get("signing_secret")),
        "endpoint_hint": "POST this app's public URL + /api/v1/chatops/slack/command as your Slack slash command's Request URL.",
    }


@router.put("/v1/admin/chatops/config")
async def set_chatops_config(body: ChatOpsConfigBody, user: dict = Depends(require_role("admin"))):
    if not body.signing_secret or len(body.signing_secret) < 10:
        raise HTTPException(400, "That doesn't look like a valid Slack signing secret")
    await db.chatops_config.update_one(
        {"id": CONFIG_ID},
        {"$set": {
            "id": CONFIG_ID, "signing_secret": body.signing_secret, "enabled": body.enabled,
            "workspace_label": body.workspace_label, "updated_at": now_iso(), "updated_by": user["email"],
        }},
        upsert=True,
    )
    return {"ok": True}


@router.post("/v1/admin/chatops/config/disable")
async def disable_chatops(user: dict = Depends(require_role("admin"))):
    await db.chatops_config.update_one({"id": CONFIG_ID}, {"$set": {"enabled": False}})
    return {"ok": True}


@router.post("/v1/chatops/slack/command")
async def slack_command(
    request: Request,
    command: str = Form(...),
    text: str = Form(""),
    user_name: str = Form(""),
    channel_id: str = Form(""),
):
    """Public endpoint -- Slack calls this directly, so trust comes entirely from the
    signature check below, not from session auth. Reject anything that doesn't verify."""
    from chatops import verify_slack_signature, handle_command

    cfg = await db.chatops_config.find_one({"id": CONFIG_ID}, {"_id": 0})
    if not cfg or not cfg.get("enabled") or not cfg.get("signing_secret"):
        raise HTTPException(404, "ChatOps isn't configured")

    raw_body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    if not verify_slack_signature(cfg["signing_secret"], timestamp, raw_body.decode("utf-8", errors="replace"), signature):
        raise HTTPException(401, "Invalid signature")

    result = await handle_command(db, text, user_name)
    return result
