"""Splunk pull connector -- polls a saved SPL search on a schedule and normalizes
each result row into a security_events row (see security_events.py). Pull, not
push: this reaches out to Splunk's own REST API on our schedule, the same pattern
every other connector in this app already uses (Qualys, Shodan, Censys, etc.),
rather than standing up a webhook/HEC receiver for Splunk to push into -- that's a
real architecture difference (inbound endpoint vs outbound poll) and pull was the
explicit choice for this first pass; a push-based receiver is a plausible fast
follow once this bus has proven itself, not a redesign of it.

Uses Splunk's "oneshot" search/jobs/export endpoint (POST, output_mode=json) --
supported by every Splunk Enterprise/Cloud version, and returns results directly
in the same request instead of the create-job/poll-until-done/fetch-results dance
a "normal" search job requires. Good enough for a periodic pull of a bounded time
window; if a search is expensive enough to need real job management, that's a
sign the search itself should be tightened, not that this needs the extra
complexity.
"""
import json
import re

import httpx

from security_events import emit_event

# Splunk's own field names for how bad it thinks something is -- checked in this
# order since different Splunk apps/TAs (ES, Enterprise Security's own risk
# framework, generic alerts) use different conventions and there's no single
# universal field.
_SEVERITY_FIELDS = ["severity", "urgency", "priority", "risk_severity"]
_SEVERITY_MAP = {
    "critical": "Critical", "high": "High", "medium": "Medium", "med": "Medium",
    "low": "Low", "informational": "Info", "info": "Info",
}


def _map_severity(result: dict) -> str:
    for field in _SEVERITY_FIELDS:
        raw = str(result.get(field, "")).strip().lower()
        if raw in _SEVERITY_MAP:
            return _SEVERITY_MAP[raw]
    return "Medium"


def _entity_from_result(result: dict):
    for field in ("host", "dest", "dest_ip", "src", "src_ip", "user"):
        val = result.get(field)
        if val:
            return field, val
    return None, None


def validate_search(search: str) -> str:
    search = (search or "").strip()
    if not search:
        raise ValueError("Search query is required")
    # Splunk accepts a leading "search" keyword or not -- normalize so the sync
    # function always sends a well-formed SPL string either way.
    if not re.match(r"^\s*(search\b|\|)", search, re.IGNORECASE):
        search = f"search {search}"
    return search


async def run_splunk_sync(db, endpoint: str, token: str, search: str, verify_ssl: bool = True, timeout_sec: int = 60) -> dict:
    search = validate_search(search)
    url = endpoint.rstrip("/") + "/services/search/jobs/export"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"search": search, "output_mode": "json", "exec_mode": "oneshot"}

    async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout_sec) as client:
        r = await client.post(url, headers=headers, data=data)
        r.raise_for_status()

    events_created = 0
    rows_seen = 0
    for line in r.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = obj.get("result")
        if not result:
            continue
        rows_seen += 1
        entity_type, entity_value = _entity_from_result(result)
        raw_text = result.get("_raw", "")
        title = (raw_text[:180] if raw_text else result.get("_time", "Splunk event"))
        await emit_event(
            db, source="splunk", event_type="splunk_search_result", severity=_map_severity(result),
            title=f"Splunk: {title}",
            entity_type=entity_type, entity_id=entity_value, entity_label=entity_value,
            description=raw_text or json.dumps(result)[:500],
            raw=result,
        )
        events_created += 1

    return {"ok": True, "rows_seen": rows_seen, "events_created": events_created}
