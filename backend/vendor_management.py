"""Vendor & Third-Party Risk Management -- tracks the hardware manufacturers,
software publishers, and cloud/SaaS providers this org actually depends on, and
answers three questions an auditor or exec will ask: what's our exposure to
this vendor's own vulnerabilities, how critical is this vendor to us, and
would we know if the vendor itself got breached.

Deliberately distinct from routes/inventory.py's "Products" concept -- a
Product is an *internal* business application grouping of our own assets
(e.g. "Payroll System"); a Vendor here is an *external* party whose own
security posture we're tracking, which may have nothing to do with how our
asset inventory is organized.

"What's linked to this vendor" is computed via a transparent, editable list of
match_terms (free-text substrings) checked against several real data sources
rather than a rigid foreign key:
  - asset hardware_info (Qualys GAV's combined manufacturer/model string --
    real, structured data for hardware vendors like HP/Dell/Lenovo)
  - asset os (catches OS vendors -- Windows assets link to "Microsoft", etc.)
  - finding titles (vulnerability titles routinely name the affected product,
    e.g. "Adobe Acrobat Reader DC Multiple Vulnerabilities" -- this is what
    lets a pure-software vendor like Adobe, which has no asset-level presence,
    still show real linked findings)
  - db.software_inventory, when populated by the Microsoft Defender for
    Endpoint EDR connector (see defender_sync.py) -- real, agent-reported
    "this software is installed on this specific asset" facts, not a
    substring guess. This is the one source that isn't an inference; without
    Defender for Endpoint configured, this app still has no dedicated
    per-asset software inventory and the substring-matching sources above
    remain the only signal, which is honest about what's actually available
    rather than pretending otherwise.

Risk scoring reuses routes.risk_register's exact 5x5 likelihood x impact
matrix (_score/_band) rather than inventing a second scoring system:
likelihood is auto-derived from the vendor's own real open-finding severity
mix (a vendor with open Critical/KEV findings scores likelihood 5), impact is
the org-set criticality (how much this vendor matters to us specifically).

Compromise/breach monitoring reuses the existing recon-ng OSINT module runner
(reconng.py) rather than a new paid breach-lookup API: a vendor with a domain
can have OTX/abuse.ch/OpenCTI domain lookups + certificate-transparency
scheduled against it, same as any other recon-ng target, and results land in
the existing db.osint_findings collection (keyed by target=domain) and fire
the existing "osint_exposure_found" notification -- no new plumbing needed.
"""
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

CATEGORIES = ["Hardware", "Software", "Cloud Service / SaaS", "MSP / Service Provider", "Other"]

# Contract/compliance tracking -- the "vendor management" half of this module, not
# just risk tracking: knowing a DPA is missing or a contract is about to lapse is as
# much a gap as an unpatched CVE. Kept as simple enums rather than a full CLM.
DPA_STATUSES = ["not_required", "requested", "in_review", "signed"]
QUESTIONNAIRE_STATUSES = ["not_started", "in_progress", "completed"]

# How many days out a renewal_date counts as "due" for the reminder sweep and the
# /v1/vendors/renewals list -- mirrors cert_monitor.py's WARN_DAYS for TLS expiry.
RENEWAL_WARN_DAYS = 30

# Domain-targeted recon-ng modules safe to auto-schedule for compromise
# monitoring -- all requires_keys=[] (work unauthenticated or read config from
# Integrations rather than requiring a per-call key), and all meaningfully
# breach/exposure-relevant. hibp_breach is deliberately excluded: it targets
# an email, not a domain, so it doesn't fit "monitor this vendor's domain".
MONITOR_MODULE_IDS = ["otx_domain", "abusech_domain", "opencti_domain", "certificate_transparency"]

# Small, honest seed list for the OS-vendor auto-suggestion -- these are real,
# common OS-family-to-vendor mappings, not a guess. Substring-matched against
# each asset's `os` field, case-insensitive.
OS_VENDOR_MAP = [
    ("windows", "Microsoft"), ("macos", "Apple"), ("mac os", "Apple"), ("os x", "Apple"),
    ("ubuntu", "Canonical"), ("debian", "Debian Project"), ("red hat", "Red Hat"),
    ("rhel", "Red Hat"), ("centos", "CentOS Project"), ("fedora", "Red Hat"),
    ("suse", "SUSE"), ("vmware", "VMware"), ("esxi", "VMware"),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(d: dict) -> dict:
    d = dict(d)
    d.pop("_id", None)
    return d


async def _log(db, action: str, vendor_id: str, actor: Optional[str], details: str) -> None:
    await db.activity_log.insert_one({
        "id": str(uuid.uuid4()), "entity_type": "vendor", "entity_id": vendor_id,
        "action": f"vendor_{action}", "actor": actor or "system",
        "timestamp": _now_iso(), "details": details,
    })


def _first_token(text: str) -> Optional[str]:
    text = (text or "").strip()
    if not text:
        return None
    token = text.split()[0].strip(",.;:")
    # Skip obviously non-brand first tokens (generic model-number-looking junk)
    if len(token) < 2 or token.isdigit():
        return None
    return token


async def suggest_vendors(db) -> list:
    """Scans assets for candidate vendor names not already tracked -- hardware
    manufacturer (first token of hardware_info) and OS vendor (from
    OS_VENDOR_MAP). Returns [{name, category, source, asset_count}], sorted by
    asset_count desc, excluding anything that already matches an existing
    vendor's name or match_terms."""
    existing = await db.vendors.find({}, {"_id": 0, "name": 1, "match_terms": 1}).to_list(2000)
    existing_terms = set()
    for v in existing:
        existing_terms.add((v.get("name") or "").strip().lower())
        for t in v.get("match_terms") or []:
            existing_terms.add(t.strip().lower())

    assets = await db.assets.find({}, {"_id": 0, "hardware_info": 1, "os": 1}).to_list(50000)
    hw_counts: dict = {}
    os_counts: dict = {}
    for a in assets:
        hw = _first_token(a.get("hardware_info"))
        if hw and hw.lower() not in existing_terms:
            hw_counts[hw] = hw_counts.get(hw, 0) + 1
        os_text = (a.get("os") or "").lower()
        for needle, vendor_name in OS_VENDOR_MAP:
            if needle in os_text and vendor_name.lower() not in existing_terms:
                os_counts[vendor_name] = os_counts.get(vendor_name, 0) + 1

    # Real per-asset installed-software vendors (Defender for Endpoint), grouped by
    # vendor name -> the set of distinct assets running software from that vendor.
    # asset_id is only set on defender_device rows (per-machine); defender_org rows
    # (asset_id=None, the org-wide software list) are deliberately excluded here --
    # an asset_count needs real per-asset backing to mean anything, and a candidate
    # surfaced with asset_count=0 would just be confusing.
    sw_asset_sets: dict = {}
    cursor = db.software_inventory.find(
        {"source": "defender_device", "asset_id": {"$ne": None}},
        {"_id": 0, "vendor": 1, "asset_id": 1},
    )
    async for row in cursor:
        vendor = (row.get("vendor") or "").strip()
        if not vendor or vendor.lower() in existing_terms:
            continue
        sw_asset_sets.setdefault(vendor, set()).add(row["asset_id"])

    suggestions = [
        {"name": name, "category": "Hardware", "source": "asset_hardware_info", "asset_count": count}
        for name, count in hw_counts.items()
    ] + [
        {"name": name, "category": "Software", "source": "asset_os", "asset_count": count}
        for name, count in os_counts.items()
    ] + [
        {"name": name, "category": "Software", "source": "edr_software_inventory", "asset_count": len(ids)}
        for name, ids in sw_asset_sets.items()
    ]
    suggestions.sort(key=lambda s: -s["asset_count"])
    return suggestions


async def _linked_assets(db, vendor: dict) -> list:
    terms = [vendor.get("name")] + (vendor.get("match_terms") or [])
    terms = [t for t in terms if t]
    if not terms:
        return []
    ors = []
    for t in terms:
        ors.append({"hardware_info": {"$regex": t, "$options": "i"}})
        ors.append({"os": {"$regex": t, "$options": "i"}})
        ors.append({"hostname": {"$regex": t, "$options": "i"}})
    assets = await db.assets.find({"$or": ors}, {"_id": 0}).to_list(1000)

    # Real per-asset software-vendor linkage (Defender for Endpoint), when available --
    # picks up assets running this vendor's software even when nothing about the
    # asset's hardware_info/os/hostname happens to match, which is exactly the
    # precision gap the substring approach above can't close on its own.
    matched_ids = {a["id"] for a in assets}
    sw_ors = [{"vendor": {"$regex": t, "$options": "i"}} for t in terms]
    sw_rows = await db.software_inventory.find(
        {"source": "defender_device", "asset_id": {"$ne": None}, "$or": sw_ors},
        {"_id": 0, "asset_id": 1},
    ).to_list(5000)
    extra_ids = {r["asset_id"] for r in sw_rows} - matched_ids
    if extra_ids:
        assets += await db.assets.find({"id": {"$in": list(extra_ids)}}, {"_id": 0}).to_list(1000)
    return assets


async def _linked_findings(db, vendor: dict, asset_ids: list) -> list:
    """Matches on finding title (works for any finding) and, when present, the more
    precise component_name field that sbom.py stamps onto SBOM/OSV.dev-sourced
    findings (e.g. component_name="log4j-core" vs. a title string) -- a genuine
    precision improvement for software vendors whose package names show up in SBOMs,
    still honest substring matching rather than a real installed-software-to-vendor
    inventory (which this app doesn't have)."""
    terms = [vendor.get("name")] + (vendor.get("match_terms") or [])
    terms = [t for t in terms if t]
    ors = []
    for t in terms:
        ors.append({"title": {"$regex": t, "$options": "i"}})
        ors.append({"component_name": {"$regex": t, "$options": "i"}})
    if asset_ids:
        ors.append({"asset_id": {"$in": asset_ids}})
    if not ors:
        return []
    return await db.findings.find({"$or": ors}, {"_id": 0}).to_list(5000)


def _inherent_likelihood(findings: list) -> int:
    """Buckets the vendor's real, currently-open vulnerability exposure into
    the same 1-5 likelihood scale routes.risk_register uses -- a vendor with
    an open Critical or KEV-listed finding is as likely to bite us as any
    other Critical risk, so it scores the same way."""
    open_statuses = {"New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"}
    open_findings = [f for f in findings if f.get("status") in open_statuses]
    if any(f.get("kev_flag") or f.get("severity") == "Critical" for f in open_findings):
        return 5
    if any(f.get("severity") == "High" for f in open_findings):
        return 4
    if any(f.get("severity") == "Medium" for f in open_findings):
        return 3
    if open_findings:
        return 2
    return 1


async def compute_vendor_risk(db, vendor: dict) -> dict:
    """Pure computation over already-fetched linked assets/findings, using the
    exact scoring engine routes.risk_register already uses (imported lazily to
    avoid a hard import-order dependency between the two route modules)."""
    from routes.risk_register import _score, _band
    assets = await _linked_assets(db, vendor)
    asset_ids = [a["id"] for a in assets]
    findings = await _linked_findings(db, vendor, asset_ids)
    likelihood = _inherent_likelihood(findings)
    impact = vendor.get("org_criticality") or 3
    score = _score(likelihood, impact)
    band = _band(score)
    sev_counts: dict = {}
    for f in findings:
        sev = f.get("severity") or "Unknown"
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    return {
        "assets": assets, "findings": findings, "asset_count": len(assets), "finding_count": len(findings),
        "severity_counts": sev_counts, "inherent_likelihood": likelihood, "org_criticality": impact,
        "risk_score": score, "risk_band": band,
    }


async def check_vendor_compromise(db, vendor: dict) -> list:
    """Runs the monitoring modules against vendor['domain'] right now (the
    "Check now" button) and returns per-module status, mirroring
    albert_enrichment.enrich_ip's 4-state pattern (not_configured/error/clean/
    found) since it's the same class of "best-effort OSINT lookup" problem."""
    import reconng
    domain = vendor.get("domain")
    if not domain:
        return []
    results = []
    for module_id in MONITOR_MODULE_IDS:
        mod = reconng.MODULE_BY_ID.get(module_id)
        if not mod:
            continue
        try:
            summary = await reconng.run_module(db, module_id, domain)
            hits = summary.get("osint_findings_created", 0) + summary.get("easm_candidates_created", 0)
            status = "found" if hits > 0 else "clean"
        except ValueError:
            status = "not_configured"
        except Exception:
            status = "error"
        results.append({"module_id": module_id, "module_label": mod["label"], "status": status})
    return results


async def enable_vendor_monitoring(db, vendor: dict, interval_hours: int = 24) -> int:
    """Creates (or leaves alone, if already present) a recon_schedules entry
    per monitoring module for this vendor's domain -- reuses the exact
    collection/document shape routes/reconng.py's schedule endpoints already
    read/write, so these show up in the normal Recon & OSINT schedules list
    too, not a shadow copy."""
    domain = vendor.get("domain")
    if not domain:
        return 0
    created = 0
    for module_id in MONITOR_MODULE_IDS:
        existing = await db.recon_schedules.find_one({"module_id": module_id, "target": domain}, {"_id": 0})
        if existing:
            continue
        await db.recon_schedules.insert_one({
            "id": str(uuid.uuid4()), "module_id": module_id, "target": domain,
            "interval_hours": interval_hours, "enabled": True, "last_run_at": None,
            "created_at": _now_iso(), "created_by": f"vendor:{vendor['id']}",
        })
        created += 1
    return created


async def disable_vendor_monitoring(db, vendor: dict) -> int:
    domain = vendor.get("domain")
    if not domain:
        return 0
    result = await db.recon_schedules.delete_many({"module_id": {"$in": MONITOR_MODULE_IDS}, "target": domain})
    return getattr(result, "deleted_count", 0)


async def check_vendor_renewals(db) -> dict:
    """Nightly sweep, same shape as albert_allowlist.check_allowlist_reviews and
    cert_monitor's TLS expiry check: finds vendors whose renewal_date has arrived or
    is within RENEWAL_WARN_DAYS and haven't already been reminded for *this* renewal
    date, dispatches vendor_contract_renewal_due, and marks the reminder sent so it
    doesn't repeat every night. Editing renewal_date via PATCH resets the reminder
    flag (see routes/vendors.py's update_vendor) so a pushed-out renewal re-reminds
    on its own new schedule instead of going silent forever."""
    from notifier import dispatch
    now = _now_iso()
    warn_cutoff = (datetime.now(timezone.utc) + timedelta(days=RENEWAL_WARN_DAYS)).isoformat()
    vendors = await db.vendors.find({
        "renewal_date": {"$ne": None, "$lte": warn_cutoff},
        "renewal_reminder_sent": {"$ne": True},
    }, {"_id": 0}).to_list(2000)
    reminded = 0
    for v in vendors:
        if not v.get("renewal_date"):
            continue
        await dispatch("vendor_contract_renewal_due", {
            "vendor_name": v["name"], "renewal_date": v["renewal_date"],
            "contract_owner": v.get("contract_owner") or "Unassigned",
            "dpa_status": v.get("dpa_status") or "not_required",
            "questionnaire_status": v.get("security_questionnaire_status") or "not_started",
            "url": f"/vendors/{v['id']}",
        }, db)
        await db.vendors.update_one({"id": v["id"]}, {"$set": {"renewal_reminder_sent": True, "updated_at": now}})
        await _log(db, "renewal_reminder_sent", v["id"], None, f"Renewal reminder sent (renewal_date={v['renewal_date']})")
        reminded += 1
    return {"checked": len(vendors), "reminded": reminded}


async def snapshot_vendor_risk_history(db) -> dict:
    """Nightly snapshot of every vendor's computed risk score/band into
    db.vendor_risk_history, one row per (vendor_id, date) -- risk_score itself is
    always computed live (compute_vendor_risk), never stored on the vendor doc, so
    without this sweep there'd be no way to show a trend over time, only today's
    snapshot. Upserts on (vendor_id, date) so re-running the same day (e.g. after a
    restart) doesn't create duplicate points on the chart."""
    today = datetime.now(timezone.utc).date().isoformat()
    vendors = await db.vendors.find({}, {"_id": 0}).to_list(2000)
    written = 0
    for v in vendors:
        risk = await compute_vendor_risk(db, v)
        await db.vendor_risk_history.update_one(
            {"vendor_id": v["id"], "date": today},
            {"$set": {
                "id": str(uuid.uuid4()), "vendor_id": v["id"], "date": today,
                "risk_score": risk["risk_score"], "risk_band": risk["risk_band"],
                "asset_count": risk["asset_count"], "finding_count": risk["finding_count"],
                "recorded_at": _now_iso(),
            }},
            upsert=True,
        )
        written += 1
    return {"vendors": len(vendors), "snapshots_written": written, "date": today}


async def get_vendor_risk_history(db, vendor_id: str, days: int = 180) -> list:
    since = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()
    items = await db.vendor_risk_history.find(
        {"vendor_id": vendor_id, "date": {"$gte": since}}, {"_id": 0}
    ).sort("date", 1).to_list(2000)
    return items


async def scan_vendor_candidates(db) -> dict:
    """Runs suggest_vendors() (asset hardware_info/os detection) and upserts each
    hit into db.vendor_candidates as a pending approval -- the actual approve/deny
    queue this drives, rather than the old "select checkboxes and instantly create
    vendors" flow. A prior denial is remembered and excluded from future scans
    (the whole point of a deny action); a still-pending candidate just gets its
    asset_count/last_seen_at refreshed rather than duplicated."""
    suggestions = await suggest_vendors(db)
    existing = await db.vendor_candidates.find({}, {"_id": 0, "name": 1, "status": 1}).to_list(5000)
    denied_names = {c["name"].strip().lower() for c in existing if c["status"] == "denied"}
    pending_names = {c["name"].strip().lower() for c in existing if c["status"] == "pending"}

    created = 0
    refreshed = 0
    now = _now_iso()
    for s in suggestions:
        key = s["name"].strip().lower()
        if key in denied_names:
            continue
        if key in pending_names:
            await db.vendor_candidates.update_one(
                {"name": {"$regex": f"^{re.escape(s['name'])}$", "$options": "i"}, "status": "pending"},
                {"$set": {"asset_count": s["asset_count"], "last_seen_at": now}},
            )
            refreshed += 1
        else:
            await db.vendor_candidates.insert_one({
                "id": str(uuid.uuid4()), "name": s["name"], "category": s["category"],
                "source": s["source"], "asset_count": s["asset_count"], "status": "pending",
                "detected_at": now, "last_seen_at": now, "decided_at": None, "decided_by": None,
            })
            created += 1
    return {"scanned": len(suggestions), "created": created, "refreshed": refreshed}


async def deny_vendor_candidate(db, candidate_id: str, actor) -> Optional[dict]:
    c = await db.vendor_candidates.find_one({"id": candidate_id}, {"_id": 0})
    if not c:
        return None
    await db.vendor_candidates.update_one(
        {"id": candidate_id},
        {"$set": {"status": "denied", "decided_at": _now_iso(), "decided_by": actor}},
    )
    await _log(db, "candidate_denied", candidate_id, actor, f"Denied vendor candidate: {c['name']}")
    return {**c, "status": "denied"}
