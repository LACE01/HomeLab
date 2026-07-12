"""Ticketing / SOAR interoperability -- pushes a security_events record out to an
external system so it can be worked as a ticket (Jira) or picked up by an
automation platform (a generic outbound webhook), instead of alerts only ever
living inside VulnOps.

Two independent destinations, either can be used per-event:
- Jira: creates a real issue via the REST API (Basic Auth, email + API token --
  the standard way Jira Cloud does app auth). Config lives in its own singleton
  doc (db.jira_config) rather than the generic Integrations catalog entry, because
  Jira needs a few fields (project key, issue type, email) that catalog entry's
  generic endpoint/api_key form doesn't have room for.
- Generic webhook: POSTs a JSON payload of the event to any URL -- a SOAR
  platform, a Zapier/n8n endpoint, an internal automation, whatever's on the
  other end. Optionally HMAC-SHA256 signs the body (header X-VulnOps-Signature)
  if a shared secret is configured, the same convention GitHub/Stripe use, so
  the receiving side can verify it actually came from this app.

Both record what happened back onto the security_events doc under "tickets": a
list of {system, ref, url, sent_at} so the Security Alerts UI can show "already
sent to Jira as PROJ-123" instead of letting someone double-file the same alert.
"""
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event_summary(event: dict) -> str:
    return f"[VulnOps] {event.get('severity', 'Info')}: {event.get('title', 'Security event')}"


def _event_description_text(event: dict) -> str:
    lines = [
        event.get("description") or "(no description)",
        "",
        f"Source: {event.get('source')}",
        f"Event type: {event.get('event_type')}",
        f"Severity: {event.get('severity')}",
    ]
    if event.get("entity_label") or event.get("entity_id"):
        lines.append(f"Entity: {event.get('entity_label') or event.get('entity_id')}")
    if event.get("occurrence_count", 1) > 1:
        lines.append(f"Occurrences: {event['occurrence_count']}")
    lines.append(f"First seen: {event.get('created_at')}")
    lines.append(f"VulnOps event ID: {event.get('id')}")
    return "\n".join(lines)


async def create_jira_issue(db, event: dict) -> dict:
    import httpx
    cfg = await db.jira_config.find_one({"id": "singleton"}, {"_id": 0})
    if not cfg or not cfg.get("enabled"):
        raise ValueError("Jira isn't configured yet -- set it up under Ticketing / SOAR first.")
    missing = [k for k in ("base_url", "email", "api_token", "project_key") if not cfg.get(k)]
    if missing:
        raise ValueError(f"Jira config is missing: {', '.join(missing)}")

    url = f"{cfg['base_url'].rstrip('/')}/rest/api/3/issue"
    body = {
        "fields": {
            "project": {"key": cfg["project_key"]},
            "summary": _event_summary(event)[:255],
            "description": {
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph", "content": [
                    {"type": "text", "text": _event_description_text(event)},
                ]}],
            },
            "issuetype": {"name": cfg.get("issue_type") or "Task"},
        }
    }
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(url, json=body, auth=(cfg["email"], cfg["api_token"]))
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach Jira: {e}")
    if r.status_code == 401:
        raise RuntimeError("Jira rejected these credentials (401) -- check the email/API token under Ticketing / SOAR.")
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Jira HTTP {r.status_code}: {r.text[:300]}")
    data = r.json()
    key = data.get("key")
    issue_url = f"{cfg['base_url'].rstrip('/')}/browse/{key}" if key else None
    ticket = {"system": "jira", "ref": key, "url": issue_url, "sent_at": _now_iso()}
    await db.security_events.update_one({"id": event["id"]}, {"$push": {"tickets": ticket}})
    return ticket


def _sign(secret: str, body_bytes: bytes) -> str:
    return hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()


async def send_to_webhook(db, event: dict, webhook_id: str) -> dict:
    import httpx
    dest = await db.webhook_destinations.find_one({"id": webhook_id}, {"_id": 0})
    if not dest:
        raise ValueError("Webhook destination not found")
    if not dest.get("enabled", True):
        raise ValueError(f"Webhook '{dest['name']}' is disabled")

    payload = {
        "event": "security_alert", "vulnops_event_id": event.get("id"),
        "severity": event.get("severity"), "source": event.get("source"),
        "event_type": event.get("event_type"), "title": event.get("title"),
        "description": event.get("description"), "entity_type": event.get("entity_type"),
        "entity_id": event.get("entity_id"), "entity_label": event.get("entity_label"),
        "occurrence_count": event.get("occurrence_count", 1),
        "created_at": event.get("created_at"), "last_seen_at": event.get("last_seen_at"),
        "raw": event.get("raw"),
    }
    body_bytes = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if dest.get("secret"):
        headers["X-VulnOps-Signature"] = f"sha256={_sign(dest['secret'], body_bytes)}"

    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(dest["url"], content=body_bytes, headers=headers)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach webhook '{dest['name']}': {e}")
    if r.status_code >= 400:
        raise RuntimeError(f"Webhook '{dest['name']}' returned HTTP {r.status_code}: {r.text[:300]}")

    ticket = {"system": "webhook", "ref": dest["name"], "url": dest["url"], "sent_at": _now_iso()}
    await db.security_events.update_one({"id": event["id"]}, {"$push": {"tickets": ticket}})
    return ticket
