"""Notification engine — Discord / Slack / Teams / Webhook / Email.

Rules trigger on events; matching rules dispatch messages via configured channels.
Email prefers plain SMTP (SMTP_HOST env var) so a self-hosted deployment can point at
its own mail server or a free provider without needing a third-party API key; it falls
back to Resend (RESEND_API_KEY) if that's what's configured, then simulates if neither is set.
"""
import os
import smtplib
import ssl as ssl_lib
import uuid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
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
    "tls_cert_expiring", "exception_revoked", "exception_risk_escalated",
    "osint_exposure_found", "ir_case_opened", "ir_obligation_notify",
    "albert_allowlist_review_due", "vendor_compromise_found", "vendor_contract_renewal_due",
    "stale_accounts_found", "edr_high_risk_device_found", "email_auth_issue",
]

CHANNELS = ["email", "discord", "slack", "teams", "webhook", "sms"]


# --- Message templates (Markdown / plain text) ---
TEMPLATES = {
    "new_assignment": {
        "subject": "[Nightwatch] New assignment: {severity} {title} on {asset}",
        "body": (
            "A {severity} severity finding has been assigned to your team.\n\n"
            "• **Title:** {title}\n• **CVE:** {cve}\n• **Asset:** {asset}\n"
            "• **Owner Team:** {owner_team}\n• **Risk Score:** {risk_score}/100\n"
            "• **Due:** {due_at}\n\nOpen: {url}"
        ),
    },
    "sla_warning": {
        "subject": "[Nightwatch] SLA warning: {title} due in {days_left}d",
        "body": (
            "⚠️ The following {severity} finding is approaching its SLA deadline.\n\n"
            "• **Title:** {title}\n• **Asset:** {asset}\n• **Due:** {due_at} ({days_left} days left)\n"
            "• **Owner:** {owner_team}\n\nOpen: {url}"
        ),
    },
    "overdue": {
        "subject": "[Nightwatch] OVERDUE: {severity} {title} on {asset}",
        "body": (
            "🚨 This finding has exceeded its SLA deadline by {days_overdue} day(s).\n\n"
            "• **Title:** {title}\n• **CVE:** {cve}\n• **Asset:** {asset}\n"
            "• **Owner Team:** {owner_team}\n• **Due:** {due_at}\n\nOpen: {url}"
        ),
    },
    "daily_digest": {
        "subject": "[Nightwatch] Daily digest — {date}",
        "body": (
            "📊 Daily security digest for {date}\n\n"
            "• Open critical: {open_critical}\n• New today: {new_today}\n"
            "• Closed today: {closed_today}\n• Overdue: {overdue}\n• KEV findings: {kev}\n"
            "\nDashboard: {url}"
        ),
    },
    "exception_expiring": {
        "subject": "[Nightwatch] Risk acceptance expiring: {title}",
        "body": (
            "⏰ A risk acceptance is expiring in {days_left} day(s).\n\n"
            "• **Finding:** {title}\n• **Asset:** {asset}\n"
            "• **Approver:** {approver}\n• **Expires:** {expires_at}\n\n"
            "Decide: renew, accept the new risk, or remediate. Open: {url}"
        ),
    },
    "exception_revoked": {
        "subject": "[Nightwatch] Risk acceptance revoked: {title}",
        "body": (
            "⛔ A previously-approved risk acceptance has been revoked before its normal expiry.\n\n"
            "• **Covers:** {title}\n• **Revoked by:** {revoked_by}\n• **Reason:** {reason}\n"
            "• **Findings reopened:** {finding_count}\n\nOpen: {url}"
        ),
    },
    "exception_risk_escalated": {
        "subject": "[Nightwatch] Risk acceptance needs a second look: {title}",
        "body": (
            "📈 Threat activity around this accepted risk has escalated since it was approved.\n\n"
            "• **Covers:** {title}\n• **What changed:** {escalation_reason}\n"
            "• **Expires:** {expires_at}\n\nConsider revoking or re-confirming this acceptance. Open: {url}"
        ),
    },
    "albert_allowlist_review_due": {
        "subject": "[Nightwatch] Albert allowlist entry needs review: {label}",
        "body": (
            "⏰ A known-good Albert allowlist entry is past its review date, and its suppression has been "
            "paused until it's re-confirmed -- alerts it used to suppress may start showing up again.\n\n"
            "• **Source IP:** {source_ip}\n• **Destination IP:** {destination_ip}\n"
            "• **Added by:** {added_by}\n• **Review was due:** {review_by}\n\n"
            "Confirm it's still valid, or remove it, on the Albert dashboard. Open: {url}"
        ),
    },
    "osint_exposure_found": {
        "subject": "[Nightwatch] OSINT exposure found: {label}",
        "body": (
            "🕵️ A recon-ng OSINT module found something worth a look.\n\n"
            "• **Module:** {module}\n• **Target:** {target}\n• **Finding:** {label}\n"
            "• **Detail:** {detail}\n\nOpen: {url}"
        ),
    },
    "vendor_compromise_found": {
        "subject": "[Nightwatch] Vendor compromise signal: {vendor_name}",
        "body": (
            "🚨 A compromise-monitoring module found something worth a look on a tracked vendor's domain.\n\n"
            "• **Vendor:** {vendor_name}\n• **Module:** {module}\n• **Domain:** {target}\n"
            "• **Finding:** {label}\n• **Detail:** {detail}\n\nOpen: {url}"
        ),
    },
    "vendor_contract_renewal_due": {
        "subject": "[Nightwatch] Vendor contract renewal due: {vendor_name}",
        "body": (
            "📅 A tracked vendor's contract renewal date has arrived or is approaching.\n\n"
            "• **Vendor:** {vendor_name}\n• **Renewal date:** {renewal_date}\n"
            "• **Contract owner:** {contract_owner}\n• **DPA status:** {dpa_status}\n"
            "• **Security questionnaire:** {questionnaire_status}\n\nOpen: {url}"
        ),
    },
    "stale_accounts_found": {
        "subject": "[Nightwatch] {count} stale account(s) found in Entra ID",
        "body": (
            "👤 The nightly directory sync found enabled accounts with no sign-in activity "
            "in the last {stale_days} days (or that have never signed in at all).\n\n"
            "• **Stale, enabled accounts:** {count}\n\n"
            "Review and consider disabling unused accounts. Open: {url}"
        ),
    },
    "edr_high_risk_device_found": {
        "subject": "[Nightwatch] Defender for Endpoint: {count} high-risk device(s)",
        "body": (
            "🛡️ The Defender for Endpoint sync found device(s) flagged with elevated risk.\n\n"
            "• **High-risk devices:** {count}\n\n"
            "Open: {url}"
        ),
    },
    "tls_cert_expiring": {
        "subject": "[Nightwatch] TLS certificate expiring: {hostname}",
        "body": (
            "🔒 The TLS certificate for {hostname} {expiry_phrase}.\n\n"
            "• **Severity:** {severity}\n• **Port:** {port}\n"
            "• **Days left:** {days_left}\n• **Reason:** {reason}\n\nOpen: {url}"
        ),
    },
    "email_auth_issue": {
        "subject": "[Nightwatch] Email authentication issue ({check_type}): {domain}",
        "body": (
            "📧 An email authentication issue was found for {domain}.\n\n"
            "• **Check:** {check_type}\n• **Severity:** {severity}\n"
            "• **Reason:** {reason}\n\nOpen: {url}"
        ),
    },
    "ir_case_opened": {
        "subject": "[Nightwatch] IR case opened: {case_number} — {title}",
        "body": (
            "\U0001F6A8 A new incident response case was opened.\n\n"
            "• **Case:** {case_number}\n• **Title:** {title}\n"
            "• **Classification:** {classification}\n• **Likely category:** {category}\n"
            "• **Confidence:** {confidence_pct}%\n\nOpen: {url}"
        ),
    },
    "digest_list": {
        "subject": "[Nightwatch] {cadence} digest — {rule_name} ({count})",
        "body": (
            "Rolled-up notifications for rule \"{rule_name}\" ({cadence}, {count} item(s) since the last digest):\n\n"
            "{items_text}"
        ),
    },
    "ir_obligation_notify": {
        "subject": "[Nightwatch IR] {obligation_name} — {case_number}: {title}",
        "body": (
            "This is a notification for a reporting obligation attached to IR case {case_number}.\n\n"
            "• **Obligation:** {obligation_name}\n• **Trigger:** {trigger_description}\n"
            "• **Reporting target:** {reporting_target}\n• **Timeline:** {timeline_text}\n\n"
            "• **Case:** {title} ({classification})\n• **Summary:** {summary}\n\nOpen: {url}"
        ),
    },
}


class _SafeCtx(dict):
    """dict subclass for str.format_map() -- any template placeholder not present in
    ctx renders as an em dash instead of raising KeyError. Fixes a real bug: the
    previous implementation used a hardcoded whitelist of ctx keys that was never
    kept in sync as new templates were added (osint_exposure_found, tls_cert_expiring,
    albert_allowlist_review_due, exception_revoked, exception_risk_escalated, and both
    new vendor_* templates below all reference keys the whitelist didn't have),
    which meant render() either dropped real values silently or raised KeyError
    outright for any of those triggers -- immediate-frequency dispatch swallowed the
    KeyError per-channel (so it just looked like nothing was ever delivered), but the
    digest-queue path in dispatch() calls render() with no try/except at all, so a
    digest-frequency rule on any of those triggers would have crashed the caller."""
    def __missing__(self, key):
        return "—"


def render(template_id: str, ctx: dict) -> dict:
    """Return {subject, body} after substituting ctx into TEMPLATES[template_id]."""
    tpl = TEMPLATES.get(template_id) or TEMPLATES["new_assignment"]
    safe = _SafeCtx(ctx)
    return {"subject": tpl["subject"].format_map(safe), "body": tpl["body"].format_map(safe)}


async def _send_discord(webhook_url: str, subject: str, body: str) -> dict:
    """Discord incoming webhook — uses content + embed."""
    payload = {
        "username": "Nightwatch",
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


async def _send_smtp(to_addr: str, subject: str, body: str, attachments: Optional[list] = None) -> dict:
    """Plain SMTP via stdlib smtplib. Blocking, so it runs in a thread -- this is a
    once-per-notification call, not a hot path, so a thread per send is plenty.

    attachments (optional): list of {"filename": str, "content": bytes, "content_type": str}
    -- used by scheduled_reports.py to attach a generated PDF/CSV report."""
    import asyncio
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    from_addr = os.environ.get("SMTP_FROM", "Nightwatch <noreply@vulnops.local>")
    use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() not in ("false", "0", "no")

    def _send():
        if attachments:
            msg = MIMEMultipart()
            msg.attach(MIMEText(body, "plain"))
            for att in attachments:
                part = MIMEApplication(att["content"], Name=att["filename"])
                part["Content-Disposition"] = f'attachment; filename="{att["filename"]}"'
                msg.attach(part)
        else:
            msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        with smtplib.SMTP(host, port, timeout=10) as server:
            if use_tls:
                server.starttls(context=ssl_lib.create_default_context())
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, [to_addr], msg.as_string())

    await asyncio.get_running_loop().run_in_executor(None, _send)
    return {"status_code": 250, "ok": True, "text": f"Sent via SMTP ({host}:{port})"}


async def _send_sms(to_number: str, subject: str, body: str) -> dict:
    """Cell/SMS delivery -- generic HTTP relay so a self-hosted deployment can point
    at whatever SMS gateway they already have (Twilio's messages endpoint accepts a
    simple form-encoded POST, most other providers accept a JSON POST) without this
    app taking a hard dependency on one vendor's SDK. Same simulate-if-unconfigured
    fallback as email so IR obligation notify still works (with a clear outbox
    record) before a real gateway is wired up."""
    if not to_number:
        return {"status_code": 0, "ok": False, "text": "Contact has no phone/cell number configured"}

    webhook_url = os.environ.get("SMS_WEBHOOK_URL")
    if webhook_url:
        text = f"{subject}\n{body}"[:1500]  # most SMS gateways truncate long bodies anyway
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.post(webhook_url, json={"to": to_number, "body": text, "source": "vulnops"})
            return {"status_code": r.status_code, "ok": 200 <= r.status_code < 300, "text": r.text[:200]}
        except Exception as e:
            return {"status_code": 0, "ok": False, "text": f"SMS webhook error: {e}"}

    return {"status_code": 0, "ok": True, "simulated": True,
            "text": "SIMULATED -- no SMS_WEBHOOK_URL configured, so nothing was actually texted. "
                    "Point SMS_WEBHOOK_URL at your SMS gateway's HTTP API (Twilio, etc.) to send real texts."}


async def _send_email(to_addr: str, subject: str, body: str, attachments: Optional[list] = None) -> dict:
    """Prefers plain SMTP (SMTP_HOST) since that's the self-hosted-friendly option --
    falls back to Resend's API if that's what's configured, then simulates.

    attachments (optional): list of {"filename": str, "content": bytes, "content_type": str}."""
    if not to_addr:
        return {"status_code": 0, "ok": False, "text": "Channel has no 'to' address configured"}

    smtp_host = os.environ.get("SMTP_HOST")
    if smtp_host:
        try:
            return await _send_smtp(to_addr, subject, body, attachments=attachments)
        except Exception as e:
            logger.exception("SMTP send failed")
            return {"status_code": 0, "ok": False, "text": f"SMTP error: {e}"}

    api_key = os.environ.get("RESEND_API_KEY")
    if api_key:
        import base64
        payload = {"from": "Nightwatch <noreply@vulnops.io>",
                   "to": [to_addr], "subject": subject,
                   "html": body.replace("\n", "<br>")}
        if attachments:
            # Resend's documented attachment shape: base64-encoded content, keyed
            # by "filename"/"content" -- https://resend.com/docs/api-reference/emails/send-email
            payload["attachments"] = [
                {"filename": a["filename"], "content": base64.b64encode(a["content"]).decode("ascii")}
                for a in attachments
            ]
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post("https://api.resend.com/emails",
                             headers={"Authorization": f"Bearer {api_key}"},
                             json=payload)
        return {"status_code": r.status_code, "ok": 200 <= r.status_code < 300, "text": r.text[:200]}

    return {"status_code": 0, "ok": True, "simulated": True,
            "text": "SIMULATED -- no SMTP_HOST or RESEND_API_KEY configured, so nothing was actually sent. "
                    "Set SMTP_HOST/SMTP_USERNAME/SMTP_PASSWORD in your .env to send real email."
                    + (f" ({len(attachments)} attachment(s) would have been included.)" if attachments else "")}


async def send_email_with_attachment(to_addr: str, subject: str, body: str, attachments: list) -> dict:
    """Public entry point for anything outside the template/channel-based notification
    system that needs to send a plain email with a file attached -- currently just
    scheduled_reports.py. Deliberately bypasses the channel/template machinery (no
    notification_channels doc, no TEMPLATES rendering) since a scheduled report's
    recipient list and body are just plain config, not an event-driven notification
    rule."""
    return await _send_email(to_addr, subject, body, attachments=attachments)


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
            result = await _send_email(channel.get("to"), msg["subject"], msg["body"])
        elif channel["type"] == "sms":
            result = await _send_sms(channel.get("to"), msg["subject"], msg["body"])
        else:
            result = {"status_code": 0, "ok": False, "text": f"Unknown channel type: {channel['type']}"}
    except Exception as e:
        logger.exception("Delivery failed")
        result = {"status_code": 0, "ok": False, "text": f"Error: {e}"}

    record["delivered"] = result["ok"]
    record["simulated"] = result.get("simulated", False)
    record["status_code"] = result.get("status_code", 0)
    record["response"] = result.get("text", "")
    await db.notifications_outbox.insert_one(record)
    return record


async def dispatch(trigger: str, ctx: dict, db) -> int:
    """Find all enabled rules matching `trigger` and ctx. Immediate-frequency rules deliver
    right away; daily/weekly rules queue the event instead and get rolled up into a single
    digest message by run_digest_dispatch(). Returns count of immediate deliveries attempted
    (queued items aren't counted here since nothing was sent yet)."""
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
        frequency = rule.get("frequency") or "immediate"
        if frequency != "immediate":
            msg = render(template_id, ctx)
            await db.notification_queue.insert_one({
                "id": str(uuid.uuid4()), "rule_id": rule["id"], "trigger": trigger,
                "subject": msg["subject"], "context": ctx,
                "queued_at": datetime.now(timezone.utc).isoformat(),
            })
            continue
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


FREQUENCY_HOURS = {"hourly": 1, "daily": 24, "weekly": 24 * 7}


async def run_digest_dispatch(db) -> dict:
    """Roll up queued events for daily/weekly rules into one digest message per rule per
    channel, once the cadence window has elapsed. Called on a regular loop (hourly is
    plenty precise for daily/weekly windows) rather than tied to any single trigger."""
    rules = await db.notification_rules.find(
        {"active": True, "frequency": {"$in": list(FREQUENCY_HOURS.keys())}}, {"_id": 0}
    ).to_list(200)
    now = datetime.now(timezone.utc)
    digests_sent = 0
    for rule in rules:
        window_hours = FREQUENCY_HOURS.get(rule.get("frequency"), 24)
        last_sent = rule.get("last_digest_sent_at")
        due = True
        if last_sent:
            try:
                last_dt = datetime.fromisoformat(last_sent.replace("Z", "+00:00"))
                due = (now - last_dt).total_seconds() >= window_hours * 3600
            except Exception:
                due = True
        if not due:
            continue

        items = await db.notification_queue.find({"rule_id": rule["id"]}, {"_id": 0}).to_list(500)
        if items:
            items_text = "\n".join(f"• {i['subject']}" for i in items[:50])
            if len(items) > 50:
                items_text += f"\n… and {len(items) - 50} more."
            digest_ctx = {
                "cadence": rule.get("frequency"), "rule_name": rule.get("name"),
                "count": len(items), "items_text": items_text,
            }
            for ch_id in rule.get("channel_ids", []):
                channel = await db.notification_channels.find_one({"id": ch_id, "enabled": {"$ne": False}}, {"_id": 0})
                if not channel:
                    continue
                try:
                    await deliver(channel, "digest_list", digest_ctx, db)
                    digests_sent += 1
                except Exception as e:
                    logger.exception(f"Digest dispatch failed for rule {rule.get('id')} channel {ch_id}: {e}")
            await db.notification_queue.delete_many({"rule_id": rule["id"]})
        # Advance the window regardless of whether there was anything to send, so an
        # empty period doesn't cause it to fire again next hour.
        await db.notification_rules.update_one(
            {"id": rule["id"]}, {"$set": {"last_digest_sent_at": now.isoformat()}})
    return {"rules_checked": len(rules), "digests_sent": digests_sent}
