"""End-of-life software/OS tracking, backed by the community-maintained
endoflife.date API (https://endoflife.date/api/{product}.json -- no API key,
free, public). A vulnerability scanner tells you about CVEs in what's
installed; it doesn't tell you "this entire OS/runtime version stopped
receiving ANY security updates months ago" -- that's a distinct, often more
urgent signal (every future CVE against it is now permanent), and this module
closes that specific gap.

NOTE on the upstream API: endoflife.date has been migrating its API to a new
v1 schema that renames some fields (`cycle` -> `release`, etc.) while keeping
the legacy `/api/{product}.json` shape available via redirect for backward
compatibility. Since this integration wasn't built against a live sample of
whichever shape is being served at deploy time, every read below is written
defensively against BOTH the legacy and v1 field names (see `_cycle_of`/
`_eol_of`) rather than assuming one -- if endoflife.date ever fully removes
the legacy shape and the redirect starts returning something these helpers
don't recognize, `fetch_product_cycles` raises a clear, actionable error
rather than silently misreporting a product's status.

Scope: any product/cycle combination endoflife.date tracks can be watched
manually (same watch-target CRUD pattern as cert_monitor.py/
domain_email_security.py). Automatic detection from `assets.os` free-text is
intentionally limited to Ubuntu, Debian, CentOS, and RHEL, where the OS's own
version string IS the endoflife.date cycle with no ambiguity (e.g. "Ubuntu
20.04" -> cycle "20.04"). Windows, macOS, and language/runtime stacks are not
auto-detected -- their cycle identifiers are feature-update codenames or
require SBOM-level component parsing this app doesn't have a reliable source
for, so guessing would risk silently tracking the wrong cycle. Add those as
manual watch targets instead; the check itself works identically either way.
"""
import logging
import re
import uuid
from datetime import date, datetime, timezone

import httpx

logger = logging.getLogger("vulnops")

EOL_API_BASE = "https://endoflife.date/api"
WARN_DAYS = 90  # flag an upcoming EOL this far in advance
OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cycle_of(entry: dict):
    """endoflife.date's v1 API rename in progress: `cycle` (legacy) vs `release`
    (v1). Accept either, str()'d for tolerant comparison against a user-supplied
    cycle like "20.04" vs a possible numeric 20.04 in the JSON."""
    val = entry.get("cycle", entry.get("release"))
    return str(val) if val is not None else None


def _eol_of(entry: dict):
    """The `eol` field name itself hasn't changed across the legacy/v1 schemas
    per endoflife.date's own docs -- only `cycle`/`release` did. Value is either
    `false` (still supported, no EOL date set), `true` (already EOL, no specific
    date published), or an ISO date string."""
    return entry.get("eol")


async def fetch_product_cycles(product: str) -> list:
    """GETs every release-cycle entry for a product. Raises ValueError with a
    clear, actionable message (not a raw HTTP error) for an unknown product or
    an unreachable API -- both are common, expected first-run mistakes (typo'd
    product slug) rather than exceptional conditions."""
    url = f"{EOL_API_BASE}/{product}.json"
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(url)
    except httpx.HTTPError as e:
        raise ValueError(f"Couldn't reach endoflife.date: {e}")
    if r.status_code == 404:
        raise ValueError(
            f"Unknown product '{product}' -- check the exact identifier at "
            f"https://endoflife.date/{product} (product slugs are case-sensitive, e.g. 'ubuntu' not 'Ubuntu')"
        )
    if r.status_code != 200:
        raise ValueError(f"endoflife.date returned HTTP {r.status_code} for '{product}'")
    try:
        data = r.json()
    except Exception as e:
        raise ValueError(f"endoflife.date returned an unreadable response for '{product}': {e}")
    if not isinstance(data, list):
        raise ValueError(
            f"endoflife.date's response for '{product}' wasn't in the expected shape (list of release "
            f"cycles) -- the upstream API may have changed; see this module's docstring."
        )
    return data


def classify_eol(entry: dict) -> tuple:
    """Returns (severity, reason) or (None, None) if this cycle is still
    comfortably supported."""
    eol_val = _eol_of(entry)
    cycle = _cycle_of(entry) or "?"

    if eol_val is False or eol_val is None:
        return None, None
    if eol_val is True:
        return "High", f"Cycle {cycle} is marked end-of-life by the vendor with no specific date published."

    try:
        eol_date = date.fromisoformat(str(eol_val)[:10])
    except Exception:
        return None, None  # unparsable date -- don't guess, treat as unknown/healthy

    today = datetime.now(timezone.utc).date()
    days_left = (eol_date - today).days
    if days_left < 0:
        overdue = abs(days_left)
        severity = "Critical" if overdue > 365 else "High"
        return severity, f"Cycle {cycle} reached end-of-life on {eol_date.isoformat()} ({overdue} day(s) ago) -- no further security updates are being published for it."
    if days_left <= WARN_DAYS:
        return "Medium", f"Cycle {cycle} reaches end-of-life on {eol_date.isoformat()} (in {days_left} day(s)) -- plan the upgrade before support ends."
    return None, None


async def _notify_eol_issue(db, product, cycle, severity, reason, finding_id):
    from notifier import dispatch
    try:
        await dispatch("eol_software_issue", {
            "product": product, "cycle": cycle, "severity": severity, "reason": reason,
            "url": f"/findings/{finding_id}",
        }, db)
    except Exception:
        pass


async def run_eol_check(db, product: str, cycle: str, asset_id: str = None, label: str = None) -> dict:
    """Checks one product/cycle, upserts the raw entry into eol_software_status,
    and creates/updates/auto-resolves a finding based on current status.
    Idempotent -- re-running just updates the existing record/finding."""
    now = _now_iso()
    key = f"{product}:{cycle}"

    cycles = await fetch_product_cycles(product)
    entry = next((e for e in cycles if _cycle_of(e) == str(cycle)), None)
    if entry is None:
        raise ValueError(
            f"Cycle '{cycle}' not found for product '{product}' -- available cycles: "
            f"{', '.join(sorted({_cycle_of(e) for e in cycles if _cycle_of(e)})[:15])}"
        )

    severity, reason = classify_eol(entry)
    result = {
        "id": key, "product": product, "cycle": cycle, "asset_id": asset_id, "label": label,
        "eol": _eol_of(entry), "latest": entry.get("latest"), "lts": entry.get("lts"),
        "severity": severity, "reason": reason, "checked_at": now,
    }
    await db.eol_software_status.update_one({"id": key}, {"$set": result}, upsert=True)

    canonical_key = f"eol:{product}:{cycle}"
    existing = await db.findings.find_one({"canonical_key": canonical_key}, {"_id": 0})

    if severity:
        if existing and existing.get("status") in OPEN_STATES:
            was_severity = existing.get("severity")
            await db.findings.update_one({"id": existing["id"]}, {"$set": {
                "severity": severity, "description": reason, "last_seen_at": now,
            }})
            if severity in ("Critical", "High") and was_severity not in ("Critical", "High"):
                await _notify_eol_issue(db, product, cycle, severity, reason, existing["id"])
        elif not existing:
            asset = await db.assets.find_one({"id": asset_id}, {"_id": 0}) if asset_id else None
            finding = {
                "id": str(uuid.uuid4()), "canonical_key": canonical_key,
                "title": f"End-of-life software -- {product} {cycle}",
                "description": reason, "severity": severity, "status": "New",
                "source_tool": "EOL Tracker", "source_tool_type": "Software Lifecycle Monitoring",
                "detection_channel": "Scheduled EOL check",
                "asset_id": asset_id, "asset_hostname": (asset or {}).get("hostname") or label or product,
                "asset_ip": (asset or {}).get("ip"), "asset_criticality": (asset or {}).get("criticality"),
                "asset_exposure": (asset or {}).get("exposure"),
                "component_name": product, "component_version": cycle,
                "first_seen_at": now, "last_seen_at": now, "rti": [],
            }
            await db.findings.insert_one(finding)
            await _notify_eol_issue(db, product, cycle, severity, reason, finding["id"])
        # Already fixed/accepted -- leave it; a human closed it, don't reopen automatically.
    elif existing and existing.get("status") in OPEN_STATES:
        await db.findings.update_one({"id": existing["id"]}, {"$set": {
            "status": "Fixed validated", "resolved_at": now,
            "resolution_note": "No longer end-of-life (or an upgraded cycle was watched instead) on re-check.",
        }})

    return result


async def eol_monitor_loop(db, interval_hours: int = 24):
    """Background poll -- checks all enabled watch targets once per interval.
    Gated by the eol_nightly_check feature flag (default on) -- manual "Check
    now"/"Check all"/"Scan assets" actions from the UI are never gated, only
    this automatic sweep, same convention as the other Scheduled Syncs flags."""
    import asyncio
    from heartbeat import record_heartbeat
    from feature_flags import is_enabled
    await asyncio.sleep(55)  # let other startup tasks settle first
    while True:
        ok, detail = True, {}
        try:
            if await is_enabled(db, "eol_nightly_check"):
                result = await run_all_eol_checks(db)
                logger.info(f"EOL check: {result}")
                detail = result
            else:
                detail = {"skipped": "disabled in Settings"}
        except Exception as e:
            logger.exception(f"EOL check failed: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "eol_monitor_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)


async def run_all_eol_checks(db) -> dict:
    """Runs every enabled watch target once, concurrency-capped like the other
    scheduled-check loops in this app (cert/domain monitoring) -- these are
    lightweight HTTP GETs against a single public API, not a scan, but a home-
    lab-scale watch list could still be dozens of entries."""
    import asyncio
    targets = await db.eol_watch_targets.find({"enabled": True}, {"_id": 0}).to_list(500)
    sem = asyncio.Semaphore(5)

    async def _one(t):
        async with sem:
            try:
                return await run_eol_check(db, t["product"], t["cycle"], t.get("asset_id"), t.get("label"))
            except Exception as e:
                return {"product": t["product"], "cycle": t.get("cycle"), "error": str(e)}

    results = await asyncio.gather(*[_one(t) for t in targets])
    checked = len(results)
    issues = len([r for r in results if r.get("severity") and "error" not in r])
    return {"checked": checked, "issues": issues, "synced_at": _now_iso()}


# --- Auto-detection from assets.os -- see module docstring for why this is
# intentionally limited to a few OS families with an unambiguous cycle mapping. ---
_OS_AUTODETECT_PATTERNS = [
    ("ubuntu", re.compile(r"ubuntu\s+(\d{2}\.\d{2})", re.IGNORECASE)),
    ("debian", re.compile(r"debian(?:\s+gnu/linux)?\s+(\d+)", re.IGNORECASE)),
    ("centos", re.compile(r"centos(?:\s+linux)?\s+(\d+)", re.IGNORECASE)),
    ("rhel", re.compile(r"red\s*hat\s+enterprise\s+linux\s+(\d+)", re.IGNORECASE)),
]


def parse_os_to_product_cycle(os_text: str):
    """Best-effort: returns (product, cycle) for a handful of OS families whose
    version string unambiguously IS the endoflife.date cycle, or None for
    anything else (including every Windows/macOS variant -- see docstring)."""
    if not os_text:
        return None
    for product, pattern in _OS_AUTODETECT_PATTERNS:
        m = pattern.search(os_text)
        if m:
            return product, m.group(1)
    return None


async def scan_assets_for_eol(db) -> dict:
    """Scans every asset's `os` field, auto-adds a watch target (source=auto)
    for whichever ones map cleanly to a product/cycle, then checks all enabled
    targets (auto and manual together). Never removes or duplicates an
    already-existing watch target for the same product/cycle, whether it was
    added manually or by a previous auto-scan."""
    assets = await db.assets.find({}, {"_id": 0, "id": 1, "os": 1}).to_list(50000)
    existing_targets = await db.eol_watch_targets.find({}, {"_id": 0, "product": 1, "cycle": 1}).to_list(1000)
    existing_keys = {(t["product"], t["cycle"]) for t in existing_targets}

    detected, added = 0, 0
    for a in assets:
        parsed = parse_os_to_product_cycle(a.get("os") or "")
        if not parsed:
            continue
        detected += 1
        product, cycle = parsed
        if (product, cycle) in existing_keys:
            continue
        await db.eol_watch_targets.insert_one({
            "id": str(uuid.uuid4()), "product": product, "cycle": cycle,
            "label": f"Auto-detected from {a.get('os')}", "asset_id": a.get("id"),
            "enabled": True, "source": "auto", "created_at": _now_iso(), "created_by": "system",
        })
        existing_keys.add((product, cycle))
        added += 1

    check_result = await run_all_eol_checks(db)
    return {"assets_scanned": len(assets), "os_strings_matched": detected, "watch_targets_added": added, **check_result}
