"""Security event bus -- the normalized "something happened here" record every
module can write to, and the one place correlation/alerting reads from.

Why this exists: Findings, EASM, YARA, Nikto/Nmap scans, login_audit, and (new)
Splunk/Wazuh ingestion each have their own collection with their own shape --
there was no shared vocabulary for "this asset/user/IP had something notable
happen" across them, which made it impossible to ask a question like "does this
asset have an open critical finding AND a suspicious login AND a YARA hit right
now" without hand-writing a one-off join every time. Every emitter writes the
same handful of fields here; `correlate()` is the one thing that has to
understand all of them, instead of every consumer needing to.

Coverage note, same spirit as rbac.py's: this wires a representative set of
emitters (login lockouts, new critical/high findings, YARA hits, EASM new
internet exposure), not literally every code path that could be interesting.
Adding a new emitter anywhere else is just one `emit_event(...)` call using the
same shape -- see the call sites already wired for the pattern to copy.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0


async def emit_event(
    db, *, source: str, event_type: str, severity: str, title: str,
    description: str = "", entity_type: Optional[str] = None, entity_id: Optional[str] = None,
    entity_label: Optional[str] = None, raw: Optional[dict] = None,
    dedupe_window_minutes: int = 60,
) -> dict:
    """Writes one normalized event. If an event with the same (source, event_type,
    entity_id) is still open and was last seen within dedupe_window_minutes, this
    bumps its last_seen_at/occurrence_count instead of inserting a new row -- a
    persistently-true condition (e.g. an asset that's been internet-exposed for a
    week) shouldn't flood the queue with a fresh row every time something re-checks
    it. A closed/acknowledged event does NOT get bumped -- if it recurs after
    someone closed it, that's worth a fresh row, not silently merged into history.
    """
    dedupe_key = f"{source}:{event_type}:{entity_id or ''}"
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=dedupe_window_minutes)).isoformat()
    existing = await db.security_events.find_one({
        "dedupe_key": dedupe_key, "status": "open", "last_seen_at": {"$gte": cutoff},
    })
    if existing:
        await db.security_events.update_one({"id": existing["id"]}, {"$set": {
            "last_seen_at": _now_iso(), "severity": severity, "title": title, "description": description,
            "raw": raw,
        }, "$inc": {"occurrence_count": 1}})
        event = {**existing, "last_seen_at": _now_iso(), "occurrence_count": existing.get("occurrence_count", 1) + 1}
    else:
        event = {
            "id": str(uuid.uuid4()), "source": source, "event_type": event_type, "severity": severity,
            "title": title, "description": description,
            "entity_type": entity_type, "entity_id": entity_id, "entity_label": entity_label,
            "raw": raw, "dedupe_key": dedupe_key, "occurrence_count": 1,
            "status": "open", "created_at": _now_iso(), "last_seen_at": _now_iso(),
            "correlation_id": None,
        }
        await db.security_events.insert_one(event)
        # Only run correlation on a genuinely new event -- a dedupe bump doesn't
        # change the set of sources touching this entity, so there's nothing new to
        # correlate.
        if entity_id:
            await _correlate(db, entity_id, entity_type)
    return event


async def _correlate(db, entity_id: str, entity_type: Optional[str]) -> None:
    """If 2+ distinct sources have an open event on the same entity within the last
    24h, raise (or refresh) a single 'correlated_alert' event tying them together --
    e.g. an asset with both an open critical Qualys finding and a fresh YARA hit is a
    much stronger signal than either alone, and worth surfacing as one elevated
    alert instead of two unrelated rows an analyst has to notice are related."""
    window = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    related = await db.security_events.find({
        "entity_id": entity_id, "status": "open", "created_at": {"$gte": window},
        "event_type": {"$ne": "correlated_alert"},
    }, {"_id": 0}).to_list(50)
    sources = sorted({e["source"] for e in related})
    if len(sources) < 2:
        return
    worst = max((e["severity"] for e in related), key=_severity_rank)
    summary = "; ".join(f"{e['source']}: {e['title']}" for e in related[:6])
    dedupe_key = f"correlated:{entity_id}"
    existing = await db.security_events.find_one({"dedupe_key": dedupe_key, "status": "open"})
    payload = {
        "severity": worst, "title": f"Correlated activity on {related[0].get('entity_label') or entity_id}",
        "description": f"{len(related)} open event(s) across {len(sources)} source(s): {summary}",
        "last_seen_at": _now_iso(), "raw": {"related_event_ids": [e["id"] for e in related]},
    }
    if existing:
        await db.security_events.update_one({"id": existing["id"]}, {"$set": payload})
    else:
        await db.security_events.insert_one({
            "id": str(uuid.uuid4()), "source": "correlation", "event_type": "correlated_alert",
            "entity_type": entity_type, "entity_id": entity_id,
            "entity_label": related[0].get("entity_label"), "dedupe_key": dedupe_key,
            "occurrence_count": 1, "status": "open", "created_at": _now_iso(),
            "correlation_id": None, **payload,
        })
