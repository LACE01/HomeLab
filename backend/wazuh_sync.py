"""Wazuh pull connector -- polls the Wazuh Indexer's OpenSearch-compatible search
API for new alerts above a severity floor and normalizes each into a
security_events row. Same pull-based philosophy as splunk_sync.py (see that
module's docstring for the reasoning) -- reaches out to Wazuh on our schedule,
no receiver/webhook needed on this end.

Talks to the INDEXER (default port 9200), not the Wazuh Manager API (port
55000): alerts themselves live in the indexer's wazuh-alerts-* indices, and the
Manager API is mostly agent/rule/configuration management, not alert search. A
dedicated read-only indexer user (rather than the admin account) is the
recommended credential to hand this connector, same as you would for any
external tool querying Wazuh's data.

Unlike Splunk's oneshot search (where the user writes their own time bound into
the SPL), this connector time-bounds itself: it remembers the timestamp of the
newest alert it has already ingested (`last_synced_at`, stored on the config
document) and only asks for alerts newer than that on each poll, so the same
alert never gets re-ingested run after run. First run with no cursor yet
defaults to the last 15 minutes.
"""
from datetime import datetime, timezone, timedelta

import httpx

from security_events import emit_event

# Wazuh's own rule.level scale is 0-15; this mapping follows Wazuh's documented
# severity bands (their docs group 12-15 as critical/red, 7-11 as high/orange,
# etc.) rather than inventing a new one.
def _map_severity(level) -> str:
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "Medium"
    if level >= 12:
        return "Critical"
    if level >= 7:
        return "High"
    if level >= 4:
        return "Medium"
    return "Low"


async def run_wazuh_sync(
    db, *, endpoint: str, username: str, password: str, index_pattern: str = "wazuh-alerts-*",
    min_level: int = 7, verify_ssl: bool = True, timeout_sec: int = 60,
    last_synced_at: str | None = None,
) -> dict:
    since = last_synced_at or (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
    url = endpoint.rstrip("/") + f"/{index_pattern}/_search"
    body = {
        "size": 200,
        "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"filter": [
            {"range": {"timestamp": {"gt": since}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]}},
    }

    async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout_sec, auth=(username, password)) as client:
        r = await client.post(url, json=body)
        r.raise_for_status()
        data = r.json()

    hits = (data.get("hits") or {}).get("hits") or []
    max_ts = since
    events_created = 0
    for hit in hits:
        src = hit.get("_source") or {}
        ts = src.get("timestamp")
        if ts and ts > max_ts:
            max_ts = ts
        rule = src.get("rule") or {}
        agent = src.get("agent") or {}
        level = rule.get("level", 0)
        entity_id = agent.get("id") or agent.get("name")
        entity_label = agent.get("name") or entity_id
        await emit_event(
            db, source="wazuh", event_type="wazuh_alert", severity=_map_severity(level),
            title=f"Wazuh: {rule.get('description') or 'alert'} (level {level}) on {entity_label or 'unknown host'}",
            entity_type="asset", entity_id=entity_id, entity_label=entity_label,
            description=src.get("full_log") or rule.get("description") or "",
            raw=src,
        )
        events_created += 1

    return {"ok": True, "hits_seen": len(hits), "events_created": events_created, "last_synced_at": max_ts}
