"""Notification engine — Discord / Slack / Teams / Webhook / Email (simulated).

Rules trigger on events; matching rules dispatch messages via configured channels.
"""
import os
import uuid
import json as _json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

logger = logging.getLogger("vulnops.notify")


TRIGGERS = [
    "finding_created_critical", "finding_created_high", "finding_assigned",
    "ticket_sla_warning", "ticket_overdue", "ticket_reassigned",
    "comment_mention", "exception_expiring", "finding_reopened", "kev_match",
]

CHANNELS = ["email", "discord", "slack", "teams", "webhook"]


# --- Message templates (Markdown / plain text) ---
TEMPLATES = {
    "new_assignment": {
        "subject": "[VulnOps] New assignment: {severity} {title} on {asset}",
        "body": (
            "A {severity} severity finding has been assigned to your team.\n\n"
            "• **Title:** {title}\n• **CVE:** {cve}\n• **Asset:** {asset}\n"
            "• **Owner Team:** {owner_team}\n• **Risk Score:** {risk_score}/100\n"
            "• **Due:** {due_at}\n\nOpen: {url}"
        ),
    },
    "sla_warning": {
        "subject": "[VulnOps] SLA warning: {title} due in {days_left}d",
        "body": (
            "⚠️ The following {severity} finding is approaching its SLA deadline.\n\n"
            "• **Title:** {title}\n• **Asset:** {asset}\n• **Due:** {due_at} ({days_left} days left)\n"
            "• **Owner:** {owner_team}\n\nOpen: {url}"
        ),
    },
    "overdue": {
        "subject": "[VulnOps] OVERDUE: {severity} {title} on {asset}",
        "body": (
            "🚨 This finding has exceeded its SLA deadline by {days_overdue} day(s).\n\n"
            "• **Title:** {title}\n• **CVE:** {cve}\n• **Asset:** {asset}\n"
            "• **Owner Team:** {owner_team}\n• **Due:** {due_at}\n\nOpen: {url}"
        ),
    },
    "daily_digest": {
        "subject": "[VulnOps] Daily digest — {date}",
        "body": (
            "📊 Daily security digest for {date}\n\n"
            "• Open critical: {open_critical}\n• New today: {new_today}\n"
            "• Closed today: {closed_today}\n• Overdue: {overdue}\n• KEV findings: {kev}\n"
            "\nDashboard: {url}"
        ),
    },
    "exception_expiring": {
        "subject": "[VulnOps] Risk acceptance expiring: {title}",
        "body": (
            "⏰ A risk acceptance is expiring in {days_left} day(s).\n\n"
            "• **Finding:** {title}\n• **Asset:** {asset}\n"
            "• **Approver:** {approver}\n• **Expires:** {expires_at}\n\n"
            "Decide: renew, accept the new risk, or remediate. Open: {url}"
        ),
    },
}


def render(template_id: str, ctx: dict) -> dict:
    """Return {subject, body} after substituting ctx into TEMPLATES[template_id]."""
    tpl = TEMPLATES.get(template_id) or TEMPLATES["new_assignment"]
    safe = {k: ctx.get(k, "—") for k in [
        "severity", "title", "cve", "asset", "owner_team", "risk_score", "due_at",
        "url", "days_left", "days_overdue", "date", "open_critical", "new_today",
        "closed_today", "overdue", "kev", "approver", "expires_at",
    ]}
    return {"subject": tpl["subject"].format(**safe), "body": tpl["body"].format(**safe)}


async def _send_discord(webhook_url: str, subject: str, body: str) -> dict:
    """Discord incoming webhook — uses content + embed."""
    payload = {
        "username": "VulnOps",
        "embeds": [{"title": subject[:256], "description": body[:4000], "color": 0xEF4444}],
    }
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(webhook_url, json=payload)
    return {"status_code": r.status_code, "ok": 200 <= r.status_code < 300, "text": r.text[:200]}


async def _send_slack(webhook_url: str, subject: str, body: str) -> dict:
    payload = {"text": f"*{subject}*\n{body}"}
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(webhook_url, json=payload)
    return {"status_code": r.status_code, "ok": 200 <= r.status_code < 300, "text": r.text[:200]}


async def _send_teams(webhook_url: str, subject: str, body: str) -> dict:
    payload = {
        "@type": "MessageCard", "@context": "https://schema.org/extensions",
        "themeColor": "EF4444", "title": subject, "text": body,
    }
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(webhook_url, json=payload)
    return {"status_code": r.status_code, "ok": 200 <= r.status_code < 300, "text": r.text[:200]}


async def _send_webhook(webhook_url: str, subject: str, body: str, ctx: dict) -> dict:
    payload = {"subject": subject, "body": body, "context": ctx, "source": "vulnops"}
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(webhook_url, json=payload)
    return {"status_code": r.status_code, "ok": 200 <= r.status_code < 300, "text": r.text[:200]}


async def deliver(channel: dict, template_id: str, ctx: dict, db) -> dict:
    """Render + deliver. Always writes to notifications_outbox regardless of channel."""
    msg = render(template_id, ctx)
    record = {
        "id": str(uuid.uuid4()), "channel_id": channel.get("id"),
        "channel_type": channel["type"], "channel_name": channel.get("name"),
        "to": channel.get("to") or channel.get("webhook_url") or "n/a",
        "template_id": template_id, "subject": msg["subject"], "body": msg["body"],
        "context": ctx, "created_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        if channel["type"] == "discord":
            result = await _send_discord(channel["webhook_url"], msg["subject"], msg["body"])
        elif channel["type"] == "slack":
            result = await _send_slack(channel["webhook_url"], msg["subject"], msg["body"])
        elif channel["type"] == "teams":
            result = await _send_teams(channel["webhook_url"], msg["subject"], msg["body"])
        elif channel["type"] == "webhook":
            result = await _send_webhook(channel["webhook_url"], msg["subject"], msg["body"], ctx)
        elif channel["type"] == "email":
            # Simulated — no API key wired. Will be sent for real once Resend key is set.
            api_key = os.environ.get("RESEND_API_KEY")
            if api_key:
                # Real send (kept simple — main agent can extend)
                async with httpx.AsyncClient(timeout=10) as c:
                    r = await c.post("https://api.resend.com/emails",
                                     headers={"Authorization": f"Bearer {api_key}"},
                                     json={"from": "VulnOps <noreply@vulnops.io>",
                                           "to": [channel.get("to")], "subject": msg["subject"],
                                           "html": msg["body"].replace("\n", "<br>")})
                result = {"status_code": r.status_code, "ok": 200 <= r.status_code < 300, "text": r.text[:200]}
            else:
                result = {"status_code": 0, "ok": True, "text": "SIMULATED (no Resend API key configured)"}
        else:
            result = {"status_code": 0, "ok": False, "text": f"Unknown channel type: {channel['type']}"}
    except Exception as e:
        logger.exception("Delivery failed")
        result = {"status_code": 0, "ok": False, "text": f"Error: {e}"}

    record["delivered"] = result["ok"]
    record["status_code"] = result.get("status_code", 0)
    record["response"] = result.get("text", "")
    await db.notifications_outbox.insert_one(record)
    return record


async def dispatch(trigger: str, ctx: dict, db) -> int:
    """Find all enabled rules matching `trigger` and ctx, then deliver via each rule's channels.
    Returns count of deliveries attempted."""
    rules = await db.notification_rules.find({"trigger": trigger, "active": True}, {"_id": 0}).to_list(200)
    sent = 0
    for rule in rules:
        # Severity filter
        sevs = rule.get("severity_in") or []
        if sevs and ctx.get("severity") not in sevs:
            continue
        # Owner team filter
        team = rule.get("owner_team")
        if team and ctx.get("owner_team") != team:
            continue
        template_id = rule.get("template_id") or "new_assignment"
        for ch_id in rule.get("channel_ids", []):
            channel = await db.notification_channels.find_one({"id": ch_id, "enabled": {"$ne": False}}, {"_id": 0})
            if not channel:
                continue
            try:
                await deliver(channel, template_id, ctx, db)
                sent += 1
            except Exception as e:
                logger.exception(f"Auto-dispatch failed for rule {rule.get('id')} channel {ch_id}: {e}")
    return sent
