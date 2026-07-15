"""ChatOps -- a `/vulnops` Slack slash command for quick triage without leaving chat.

Slack-only (not Discord) deliberately: Slack slash commands are a plain HTTPS webhook
your existing nginx reverse proxy already fronts, so this needs zero new long-running
infrastructure. A Discord bot needs a persistent websocket Gateway connection, which is
a meaningfully bigger piece of infra for a self-hosted single-container app.

There's no per-Slack-user identity mapping back to Nightwatch accounts (that would need
Slack OAuth + an account-linking flow) -- anyone who can run the slash command in the
configured workspace gets admin-level read/write on findings, scoped only by whichever
channel your team restricts the command to. That trust boundary is spelled out in the
admin setup page; treat the signing secret like a credential.
"""
import hashlib
import hmac
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

VERIFICATION_WINDOW_DAYS = 3
MAX_TIMESTAMP_SKEW_SECONDS = 60 * 5

HELP_TEXT = (
    "*Nightwatch commands*\n"
    "`/vulnops status` — open finding counts + current security score\n"
    "`/vulnops top [n]` — top N open findings by risk score (default 5)\n"
    "`/vulnops find <query>` — natural-language search, e.g. `critical kev on windows`\n"
    "`/vulnops assign <id> <team>` — assign a finding to an owner team\n"
    "`/vulnops fix <id>` — mark a finding Fixed pending validation\n"
    "`/vulnops help` — this message\n"
    "\nFor `<id>`, the first 6-8 characters of a finding ID are enough as long as they're unambiguous."
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def verify_slack_signature(signing_secret: str, timestamp: str, raw_body: str, signature: str) -> bool:
    """Per Slack's request-signing spec: https://api.slack.com/authentication/verifying-requests-from-slack"""
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        if abs(time.time() - int(timestamp)) > MAX_TIMESTAMP_SKEW_SECONDS:
            return False
    except ValueError:
        return False
    basestring = f"v0:{timestamp}:{raw_body}".encode()
    computed = "v0=" + hmac.new(signing_secret.encode(), basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)


async def _resolve_finding(db, ref: str):
    ref = (ref or "").strip()
    if not ref:
        return None, "Give me a finding ID (or the first few characters of one)."
    exact = await db.findings.find_one({"id": ref}, {"_id": 0})
    if exact:
        return exact, None
    if not re.match(r"^[a-fA-F0-9\-]{4,36}$", ref):
        return None, f"'{ref}' doesn't look like a finding ID."
    matches = await db.findings.find({"id": {"$regex": f"^{re.escape(ref)}", "$options": "i"}}, {"_id": 0}).to_list(6)
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, f"'{ref}' matches {len(matches)} findings — use a few more characters to narrow it down."
    return None, f"No finding found starting with '{ref}'."


def _short(finding_id: str) -> str:
    return finding_id[:8]


async def cmd_status(db) -> dict:
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    counts = {}
    for sev in ["Critical", "High", "Medium", "Low"]:
        counts[sev] = await db.findings.count_documents({"status": {"$in": open_states}, "severity": sev})
    latest = await db.score_snapshots.find_one({}, {"_id": 0}, sort=[("date", -1)])
    score = (latest or {}).get("org_score")
    score_str = f"{score}/100" if score is not None else "no data yet"
    text = (
        f"*Nightwatch status*\n"
        f"Security score: *{score_str}*\n"
        f"Open findings: *{counts['Critical']}* Critical · *{counts['High']}* High · "
        f"{counts['Medium']} Medium · {counts['Low']} Low"
    )
    return {"response_type": "ephemeral", "text": text}


async def cmd_top(db, n: int = 5) -> dict:
    n = max(1, min(n, 20))
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    items = await db.findings.find(
        {"status": {"$in": open_states}},
        {"_id": 0, "id": 1, "title": 1, "severity": 1, "risk_score": 1, "asset_hostname": 1, "cve": 1},
    ).sort("risk_score", -1).to_list(n)
    if not items:
        return {"response_type": "ephemeral", "text": "No open findings. 🎉"}
    lines = [f"*Top {len(items)} open findings by risk score:*"]
    for f in items:
        cve = f" ({f['cve']})" if f.get("cve") else ""
        lines.append(f"• `{_short(f['id'])}` *[{f['severity']}]* {f['title']}{cve} — risk {f.get('risk_score', '?')} on {f.get('asset_hostname', 'unknown')}")
    return {"response_type": "ephemeral", "text": "\n".join(lines)}


async def cmd_find(db, query_text: str) -> dict:
    if not query_text.strip():
        return {"response_type": "ephemeral", "text": "Try `/vulnops find critical kev on windows`."}
    from nl_query import parse_nl_query
    from routes.findings import list_findings
    teams = [t for t in await db.assets.distinct("owner_team") if t and t != "Unassigned"]
    parsed = parse_nl_query(query_text, teams)
    f = parsed["filters"]
    # ChatOps has no per-Slack-user identity mapping back to a Nightwatch account, so
    # queries run with full (admin-equivalent) visibility rather than team-scoped --
    # see the module docstring for that tradeoff.
    result = await list_findings(
        user={"role": "admin"}, q=f.get("q"), severity=f.get("severity"), status=f.get("status"),
        kev=f.get("kev"), internet_facing=f.get("internet_facing"), owner_team=f.get("owner_team"),
        cve=f.get("cve"), cwe=f.get("cwe"), view=f.get("view"), platform=f.get("platform"),
        min_risk_score=f.get("min_risk_score"), limit=8,
    )
    items = result.get("items", [])
    interpreted = ", ".join(parsed["interpreted"])
    if not items:
        return {"response_type": "ephemeral", "text": f"_Interpreted as: {interpreted}_\nNo matching findings."}
    lines = [f"_Interpreted as: {interpreted}_", f"*{result.get('total', len(items))} match(es), showing {len(items)}:*"]
    for it in items:
        lines.append(f"• `{_short(it['id'])}` *[{it['severity']}]* {it['title']} — {it.get('asset_hostname', 'unknown')}")
    return {"response_type": "ephemeral", "text": "\n".join(lines)}


async def cmd_assign(db, ref: str, team: str, actor_email: str) -> dict:
    if not team:
        return {"response_type": "ephemeral", "text": "Usage: `/vulnops assign <id> <team>`"}
    finding, err = await _resolve_finding(db, ref)
    if err:
        return {"response_type": "ephemeral", "text": err}
    now = _now_iso()
    await db.findings.update_one({"id": finding["id"]}, {"$set": {
        "owner_team": team, "ownership_confidence": 1.0, "ownership_confirmed_at": now,
        "ownership_rationale": f"Assigned to {team} via Slack ChatOps by {actor_email}",
        "last_changed_at": now,
    }})
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": finding["id"],
        "action": "chatops_assign", "actor": actor_email, "timestamp": now,
        "details": f"Owner team set to {team} via Slack",
    })
    return {"response_type": "in_channel", "text": f"👤 Assigned `{_short(finding['id'])}` ({finding['title']}) to *{team}*."}


async def cmd_fix(db, ref: str, actor_email: str) -> dict:
    finding, err = await _resolve_finding(db, ref)
    if err:
        return {"response_type": "ephemeral", "text": err}
    now = _now_iso()
    due = (datetime.now(timezone.utc) + timedelta(days=VERIFICATION_WINDOW_DAYS)).isoformat()
    await db.findings.update_one({"id": finding["id"]}, {"$set": {
        "status": "Fixed pending validation", "last_changed_at": now,
        "verification_status": "pending", "verification_due_at": due,
        "fixed_marked_at": now, "verification_note": None,
    }})
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "finding", "entity_id": finding["id"],
        "action": "chatops_status_change", "actor": actor_email, "timestamp": now,
        "details": "Status set to Fixed pending validation via Slack",
    })
    return {"response_type": "in_channel", "text": f"✅ `{_short(finding['id'])}` ({finding['title']}) marked *Fixed pending validation* — will auto-verify within {VERIFICATION_WINDOW_DAYS} days if evidence confirms it."}


async def handle_command(db, text: str, user_name: str, user_email_fallback: str = "slack") -> dict:
    text = (text or "").strip()
    if not text:
        return await cmd_status(db)
    parts = text.split(maxsplit=1)
    sub = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ""
    actor = f"slack:{user_name}" if user_name else user_email_fallback

    if sub in ("help", "?"):
        return {"response_type": "ephemeral", "text": HELP_TEXT}
    if sub == "status":
        return await cmd_status(db)
    if sub == "top":
        try:
            n = int(rest.strip()) if rest.strip() else 5
        except ValueError:
            n = 5
        return await cmd_top(db, n)
    if sub == "find":
        return await cmd_find(db, rest)
    if sub == "assign":
        args = rest.split(maxsplit=1)
        ref = args[0] if args else ""
        team = args[1].strip() if len(args) > 1 else ""
        return await cmd_assign(db, ref, team, actor)
    if sub == "fix":
        return await cmd_fix(db, rest.strip(), actor)
    return {"response_type": "ephemeral", "text": f"Unknown command '{sub}'.\n\n{HELP_TEXT}"}
