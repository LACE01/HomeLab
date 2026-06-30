"""Minimal seed — operational scaffolding only.

Seeds:
  - Super admin user
  - Default assignment rules
  - One Discord notification channel
  - One API ingest key
  - Connector integrations marked "not_configured" except those with explicit credentials

DOES NOT seed: findings, assets, products, observations, tickets, exceptions, engagements,
import_jobs, score_snapshots, comments, activity_log, rescoring_runs. Real data is pulled
live from connectors (Qualys VMDR is the first wired up; others require user-supplied keys).
"""
import uuid
from datetime import datetime, timezone

from auth_utils import hash_password


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _id() -> str:
    return str(uuid.uuid4())


SCANNERS = [
    {"name": "Qualys VMDR",                 "type": "infrastructure", "logo": "qualys"},
    {"name": "Tenable Nessus",              "type": "infrastructure", "logo": "tenable"},
    {"name": "CrowdStrike Falcon Spotlight","type": "endpoint",       "logo": "crowdstrike"},
    {"name": "Microsoft Defender",          "type": "endpoint",       "logo": "microsoft"},
    {"name": "Wiz",                         "type": "cloud",          "logo": "wiz"},
    {"name": "GitHub Advanced Security",    "type": "appsec",         "logo": "github"},
    {"name": "Snyk",                        "type": "appsec",         "logo": "snyk"},
]

WORKFLOW_CONNECTORS = [
    {"name": "Jira",          "type": "ticketing",    "logo": "jira"},
    {"name": "ServiceNow",    "type": "ticketing",    "logo": "servicenow"},
    {"name": "GitHub",        "type": "vcs",          "logo": "github"},
    {"name": "GitLab",        "type": "vcs",          "logo": "gitlab"},
    {"name": "Azure DevOps",  "type": "vcs",          "logo": "azure"},
    {"name": "OpenCTI",       "type": "threat_intel", "logo": "opencti"},
]


# Demo data collections we must NEVER repopulate after wiping.
_DEMO_COLLECTIONS = (
    "findings", "observations", "tickets", "exceptions", "engagements",
    "import_jobs", "activity_log", "score_snapshots", "comments", "rescoring_runs",
    "assets", "products",
)


async def _ensure_user(db, now_iso_str: str):
    if await db.users.count_documents({}) > 0:
        return
    await db.users.insert_many([
        {"id": _id(), "email": "luisarce731@outlook.com", "name": "Luis Arce",
         "role": "admin", "team": None, "department": "Security",
         "password_hash": hash_password("vz7NOHcP64WRBEOg3C2I"),
         "created_at": now_iso_str, "active": True},
    ])


async def _ensure_assignment_rules(db, now_iso_str: str):
    if await db.assignment_rules.count_documents({}) > 0:
        return
    await db.assignment_rules.insert_many([
        {"id": _id(), "name": "Internet-facing → NetSec",     "priority": 10, "field": "exposure",    "operator": "equals", "value": "internet",     "assign_team": "NetSec",       "active": True, "created_at": now_iso_str},
        {"id": _id(), "name": "Crown jewel → DBA Team",       "priority": 20, "field": "criticality", "operator": "equals", "value": "crown_jewel",  "assign_team": "DBA Team",     "active": True, "created_at": now_iso_str},
        {"id": _id(), "name": "Windows hosts → IT Ops",       "priority": 30, "field": "platform",    "operator": "equals", "value": "Windows",      "assign_team": "IT Ops",       "active": True, "created_at": now_iso_str},
        {"id": _id(), "name": "Code repos → Platform Eng",    "priority": 40, "field": "platform",    "operator": "equals", "value": "Code",         "assign_team": "Platform Eng", "active": True, "created_at": now_iso_str},
        {"id": _id(), "name": "Production Linux → Platform Eng", "priority": 50, "field": "environment", "operator": "equals", "value": "production", "assign_team": "Platform Eng", "active": True, "created_at": now_iso_str},
    ])


async def _ensure_notification_channel(db, now_iso_str: str):
    if await db.notification_channels.count_documents({}) > 0:
        return
    await db.notification_channels.insert_one({
        "id": _id(), "name": "Discord #vulnops", "type": "discord",
        "webhook_url": "https://discord.com/api/webhooks/1521206679675469974/6hD5ksMOW3QlCzXVR5V3uCeNMp50AnDfzNtM70eajuOMwv-Ae6Uu1gH0NodYarEPjwPw",
        "enabled": True, "created_at": now_iso_str,
    })


async def _ensure_api_key(db, now_iso_str: str):
    if await db.api_keys.count_documents({}) > 0:
        return
    await db.api_keys.insert_one({
        "id": _id(), "key": "vulnops_ingest_demo_key_2026",
        "name": "Default Ingestion Key", "active": True,
        "created_at": now_iso_str, "last_used_at": None,
    })


async def _ensure_integrations(db, now_iso_str: str):
    """Insert any missing connector cards; do NOT clobber existing config rows."""
    existing = {i["name"] async for i in db.integrations.find({}, {"_id": 0, "name": 1})}
    to_insert = []
    for sc in SCANNERS + WORKFLOW_CONNECTORS:
        if sc["name"] in existing:
            continue
        to_insert.append({
            "id": _id(), "name": sc["name"], "type": sc["type"], "logo": sc["logo"],
            "status": "not_configured",
            "last_sync_at": None, "sync_errors": 0, "retry_count": 0,
            "config": {},  # user fills in via Integrations UI
            "created_at": now_iso_str,
        })
    if to_insert:
        await db.integrations.insert_many(to_insert)


async def seed_all(db):
    """Idempotent operational scaffolding seed. Safe to call on every startup."""
    now_iso_str = iso(datetime.now(timezone.utc))
    await _ensure_user(db, now_iso_str)
    await _ensure_assignment_rules(db, now_iso_str)
    await _ensure_notification_channel(db, now_iso_str)
    await _ensure_api_key(db, now_iso_str)
    await _ensure_integrations(db, now_iso_str)


async def wipe_demo_data(db) -> dict:
    """Delete every collection that holds demo / live operational data.
    Returns a count of deleted documents per collection."""
    deleted: dict = {}
    for col in _DEMO_COLLECTIONS:
        res = await db[col].delete_many({})
        deleted[col] = res.deleted_count
    return deleted
