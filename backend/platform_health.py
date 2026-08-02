"""Does the platform work, and can it tell you when it doesn't?

Earned by a real outage. The backend was up, its port was open, docker said
`Up (unhealthy)`, and it was answering nothing. The log went quiet, which reads
like "no traffic" rather than "nothing is being served". Four rounds of debugging
went into a question the platform should have been able to answer about itself.

Three things live here:

  OBSERVABILITY -- one screen with event-loop lag, per-connector last success and
  the ACTUAL error text, background-loop heartbeats, queue depth and database
  reachability. All of these existed in pieces; none of them were anywhere a
  person would look during an incident.

  CIRCUIT BREAKERS -- after N consecutive failures a connector is marked degraded
  and stops being retried every cycle. A connector that has failed 400 times in a
  row is not a transient problem, and hammering it produces log noise that buries
  everything else. Degraded state is visible and requires either a fix or an
  explicit reset, so a permanently broken integration cannot masquerade as a
  working one that just happens to have no data.

  SELF-CHECK -- the platform tests itself the way it tests everything else: can it
  reach its database, can it authenticate, are its loops alive, is the queue
  draining. Failures become findings, in the same table as every other finding.
  A security operations tool that cannot hold itself to its own standard is
  making an argument it does not believe.

WHAT "HEALTHY" MEANS HERE

Not "no errors". A platform with a dead feed and no errors is worse than one that
is loudly failing, because the first looks fine. So every check reports one of:
ok / degraded / failed / UNKNOWN -- and unknown is treated as a problem, because
"we could not determine this" is not the same as "this is fine".
"""
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("vulnops.health")

BREAKER_THRESHOLD = 5          # consecutive failures before a connector is cut off
BREAKER_COOLDOWN = timedelta(hours=1)
LOOP_STALE_MULTIPLIER = 2.5    # a loop is late if it misses this many intervals

OK, DEGRADED, FAILED, UNKNOWN = "ok", "degraded", "failed", "unknown"


def _now():
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _age_seconds(iso: str) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (_now() - dt).total_seconds()


def _check(name, status, summary, *, detail=None, action=None) -> dict:
    return {"name": name, "status": status, "summary": summary,
            "detail": detail or {}, "action": action}


# ---------------------------------------------------------------------------
# Circuit breakers
# ---------------------------------------------------------------------------
async def record_success(db, integration: str) -> None:
    await db.connector_state.update_one(
        {"integration": integration},
        {"$set": {"integration": integration, "consecutive_failures": 0,
                   "state": OK, "last_success_at": _now_iso(), "last_error": None}},
        upsert=True)


async def record_failure(db, integration: str, error: str) -> dict:
    """Count a failure and trip the breaker if this is now chronic.

    The error TEXT is kept, not just a count. 'It failed' sends you to the logs;
    'it failed 47 times with DNS resolution failure' is the answer.
    """
    state = await db.connector_state.find_one({"integration": integration}, {"_id": 0}) or {}
    fails = (state.get("consecutive_failures") or 0) + 1
    tripped = fails >= BREAKER_THRESHOLD
    patch = {
        "integration": integration,
        "consecutive_failures": fails,
        "last_failure_at": _now_iso(),
        "last_error": (error or "")[:1000],
        "state": DEGRADED if tripped else OK,
    }
    if tripped and state.get("state") != DEGRADED:
        patch["degraded_since"] = _now_iso()
        logger.warning("Circuit breaker OPEN for %s after %d consecutive failures: %s",
                        integration, fails, (error or "")[:200])
    await db.connector_state.update_one({"integration": integration},
                                         {"$set": patch}, upsert=True)
    return {"consecutive_failures": fails, "degraded": tripped}


async def should_run(db, integration: str) -> dict:
    """Whether a connector should be attempted this cycle.

    A degraded connector is retried once per cooldown rather than every cycle:
    often enough to notice recovery, rarely enough that a broken integration
    stops drowning the log.
    """
    state = await db.connector_state.find_one({"integration": integration}, {"_id": 0})
    if not state or state.get("state") != DEGRADED:
        return {"run": True, "reason": None}
    age = _age_seconds(state.get("last_failure_at"))
    if age is not None and age >= BREAKER_COOLDOWN.total_seconds():
        return {"run": True, "reason": "cooldown elapsed; retrying once to test for recovery"}
    return {"run": False,
            "reason": (f"Circuit breaker open: {state.get('consecutive_failures')} consecutive "
                        f"failures. Last error: {state.get('last_error')}"),
            "retry_in_seconds": int(BREAKER_COOLDOWN.total_seconds() - (age or 0))}


async def reset_breaker(db, integration: str) -> dict:
    await db.connector_state.update_one(
        {"integration": integration},
        {"$set": {"state": OK, "consecutive_failures": 0, "degraded_since": None}},
        upsert=True)
    return {"reset": integration}


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------
async def _check_database(db) -> dict:
    try:
        await db.command("ping")
    except Exception as e:
        return _check("Database", FAILED, "Cannot reach MongoDB.",
                       detail={"error": str(e)},
                       action="Check the mongo container: docker compose logs mongo")
    return _check("Database", OK, "MongoDB is reachable.")


async def _check_loops(db) -> dict:
    """Background loops that stopped reporting.

    This is the check that would have caught the outage: the loops went silent
    because the event loop was blocked, and nothing anywhere said so.

    Reads heartbeat.py's existing loop_heartbeats collection and its KNOWN_LOOPS
    registry, so a loop that crashed before its first heartbeat shows as
    "never ran" rather than simply not appearing -- an absent row and a healthy
    row look identical if you only iterate what exists.
    """
    from heartbeat import KNOWN_LOOPS
    rows = {h["name"]: h for h in
            await db.loop_heartbeats.find({}, {"_id": 0}).to_list(200)}
    if not rows:
        return _check("Background loops", UNKNOWN,
                       "No loop has ever recorded a heartbeat.",
                       action=("If the backend has been up more than a few minutes the loops are "
                               "not starting — check the backend log for an exception during "
                               "startup."))

    never_ran, late, dead = [], [], []
    for name, meta in KNOWN_LOOPS.items():
        hb = rows.get(name)
        interval = (meta.get("expected_interval_hours") or 24) * 3600
        if not hb:
            never_ran.append({"loop": name, "label": meta.get("label")})
            continue
        age = _age_seconds(hb.get("last_run_at"))
        if age is None:
            continue
        entry = {"loop": name, "label": meta.get("label"),
                 "last_seen_minutes_ago": round(age / 60), "status": hb.get("status")}
        if age > interval * 5:
            dead.append(entry)
        elif age > interval * LOOP_STALE_MULTIPLIER:
            late.append(entry)

    if dead:
        return _check("Background loops", FAILED,
                       f"{len(dead)} loop(s) have not reported in a long time.",
                       detail={"dead": dead, "late": late, "never_ran": never_ran},
                       action=("A loop that stops reporting usually means the event loop is "
                               "blocked or the task died. Check the backend log for "
                               "'EVENT LOOP BLOCKED'."))
    if never_ran:
        return _check("Background loops", DEGRADED,
                       f"{len(never_ran)} loop(s) have never run.",
                       detail={"never_ran": never_ran, "late": late},
                       action="These are registered but have never recorded a pass.")
    if late:
        return _check("Background loops", DEGRADED, f"{len(late)} loop(s) are running late.",
                       detail={"late": late})
    return _check("Background loops", OK, f"All {len(rows)} loops reporting on schedule.")


async def _check_connectors(db) -> dict:
    states = await db.connector_state.find({}, {"_id": 0}).to_list(200)
    if not states:
        return _check("Connectors", UNKNOWN, "No connector has reported a result yet.")
    degraded = [s for s in states if s.get("state") == DEGRADED]
    stale = [s for s in states
             if s.get("state") != DEGRADED
             and (_age_seconds(s.get("last_success_at")) or 0) > 3 * 86400]
    if degraded:
        return _check("Connectors", FAILED,
                       f"{len(degraded)} connector(s) are cut off after repeated failures.",
                       detail={"degraded": [{"integration": d["integration"],
                                              "consecutive_failures": d.get("consecutive_failures"),
                                              "last_error": d.get("last_error"),
                                              "degraded_since": d.get("degraded_since")}
                                             for d in degraded]},
                       action=("Fix the cause, then POST /v1/health/connectors/{name}/reset. They "
                               "are not being retried every cycle on purpose."))
    if stale:
        return _check("Connectors", DEGRADED,
                       f"{len(stale)} connector(s) have not succeeded in over 3 days.",
                       detail={"stale": [s["integration"] for s in stale]},
                       action="No errors, but no data either — which looks identical to 'nothing "
                              "to report' on every other screen.")
    return _check("Connectors", OK, f"All {len(states)} connectors reporting successfully.")


async def _check_queue(db) -> dict:
    import jobqueue as jq
    s = await jq.stats(db)
    queued, running = s["counts"]["queued"], s["counts"]["running"]
    oldest_age = _age_seconds(s.get("oldest_queued_at"))
    if queued and not running and (oldest_age or 0) > 900:
        return _check("Job queue", FAILED,
                       f"{queued} job(s) queued and nothing running for "
                       f"{round((oldest_age or 0) / 60)} minutes.",
                       detail=s["counts"],
                       action="No worker is consuming the queue. Check: docker compose ps worker")
    if s["counts"]["failed"]:
        return _check("Job queue", DEGRADED,
                       f"{s['counts']['failed']} job(s) failed permanently.",
                       detail={"recent_failures": s["recent_failures"]})
    return _check("Job queue", OK, f"{queued} queued, {running} running.")


async def _check_data_freshness(db) -> dict:
    """Is data actually arriving?

    The most valuable check and the least obvious: every component can be 'up'
    while nothing new has been ingested for a week. Errors are easy to notice;
    silence is not.
    """
    newest = await db.findings.find({}, {"_id": 0, "last_seen_at": 1, "first_seen_at": 1}).sort(
        "last_seen_at", -1).to_list(1)
    if not newest:
        return _check("Data freshness", UNKNOWN, "No findings at all.")
    age = _age_seconds(newest[0].get("last_seen_at") or newest[0].get("first_seen_at"))
    if age is None:
        return _check("Data freshness", UNKNOWN, "Could not read a timestamp from the newest finding.")
    days = age / 86400
    if days > 7:
        return _check("Data freshness", FAILED,
                       f"No finding has been seen or updated in {round(days)} days.",
                       action=("Every component can look healthy while nothing is being ingested. "
                               "Check the scanner connectors' last successful sync."))
    if days > 2:
        return _check("Data freshness", DEGRADED,
                       f"Newest finding activity is {round(days)} days old.")
    return _check("Data freshness", OK, f"Findings updated within the last {round(age / 3600)}h.")


async def snapshot(db) -> dict:
    """The whole health picture, for one screen."""
    checks = [
        await _check_database(db),
        await _check_loops(db),
        await _check_connectors(db),
        await _check_queue(db),
        await _check_data_freshness(db),
    ]
    worst = OK
    for c in checks:
        if c["status"] == FAILED:
            worst = FAILED
            break
        if c["status"] in (DEGRADED, UNKNOWN) and worst == OK:
            worst = DEGRADED
    problems = [c for c in checks if c["status"] != OK]
    return {
        "status": worst,
        "checked_at": _now_iso(),
        "checks": checks,
        "summary": ("Everything is reporting normally."
                     if worst == OK else
                     "; ".join(f"{c['name']}: {c['summary']}" for c in problems)),
        "note": ("'unknown' is counted as a problem on purpose: 'we could not determine this' is "
                  "not the same as 'this is fine', and treating them the same is how a dead feed "
                  "goes unnoticed for a month."),
    }


# ---------------------------------------------------------------------------
# Self-check: the platform's own failures become findings
# ---------------------------------------------------------------------------
async def run_self_check(db) -> dict:
    """Raise the platform's own problems as findings.

    A security operations tool that cannot hold itself to its own standard is
    making an argument it does not believe. These land in the same table, with
    the same lifecycle, as everything else -- so they appear in the same queue a
    person already reads instead of on a page nobody opens.
    """
    import uuid
    snap = await snapshot(db)
    created, resolved = 0, 0

    for check in snap["checks"]:
        key = f"platform:self-check:{check['name'].lower().replace(' ', '-')}"
        existing = await db.findings.find_one({"canonical_key": key}, {"_id": 0})
        broken = check["status"] in (FAILED, DEGRADED, UNKNOWN)

        if broken and not existing:
            await db.findings.insert_one({
                "id": str(uuid.uuid4()),
                "canonical_key": key,
                "source_tool": "Nightwatch self-check",
                "title": f"Platform health: {check['name']} — {check['summary']}",
                "description": (check["summary"] + " "
                                 + (check.get("action") or "")),
                "severity": "High" if check["status"] == FAILED else "Medium",
                "status": "New",
                "asset_hostname": "Nightwatch platform",
                "detection_logic": "Self-check",
                "remediation": check.get("action") or "Investigate the platform component named.",
                "first_seen_at": _now_iso(),
                "last_seen_at": _now_iso(),
                "self_check": True,
                "self_check_detail": check.get("detail"),
            })
            created += 1
        elif broken and existing:
            await db.findings.update_one({"canonical_key": key}, {"$set": {
                "last_seen_at": _now_iso(),
                "title": f"Platform health: {check['name']} — {check['summary']}",
                "self_check_detail": check.get("detail")}})
        elif not broken and existing and existing.get("status") not in (
                "Fixed validated", "Closed"):
            await db.findings.update_one({"canonical_key": key}, {"$set": {
                "status": "Fixed validated",
                "verification_note": "Self-check now passes; auto-closed.",
                "last_seen_at": _now_iso()}})
            resolved += 1

    return {"status": snap["status"], "findings_created": created,
            "findings_resolved": resolved, "checks": len(snap["checks"])}
