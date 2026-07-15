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

Because this app has no dedicated per-asset software inventory (no agent-based
installed-application feed), "what's linked to this vendor" is computed via a
transparent, editable list of match_terms (free-text substrings) checked
against three real data sources rather than a rigid foreign key:
  - asset hardware_info (Qualys GAV's combined manufacturer/model string --
    real, structured data for hardware vendors like HP/Dell/Lenovo)
  - asset os (catches OS vendors -- Windows assets link to "Microsoft", etc.)
  - finding titles (vulnerability titles routinely name the affected product,
    e.g. "Adobe Acrobat Reader DC Multiple Vulnerabilities" -- this is what
    lets a pure-software vendor like Adobe, which has no asset-level presence,
    still show real linked findings)
This is honest about the data this app actually has, rather than pretending
to a software-inventory integration that doesn't exist.

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
import uuid
from datetime import datetime, timezone
from typing import Optional

CATEGORIES = ["Hardware", "Software", "Cloud Service / SaaS", "MSP / Service Provider", "Other"]

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

    suggestions = [
        {"name": name, "category": "Hardware", "source": "asset_hardware_info", "asset_count": count}
        for name, count in hw_counts.items()
    ] + [
        {"name": name, "category": "Software", "source": "asset_os", "asset_count": count}
        for name, count in os_counts.items()
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
    return await db.assets.find({"$or": ors}, {"_id": 0}).to_list(1000)


async def _linked_findings(db, vendor: dict, asset_ids: list) -> list:
    terms = [vendor.get("name")] + (vendor.get("match_terms") or [])
    terms = [t for t in terms if t]
    ors = []
    for t in terms:
        ors.append({"title": {"$regex": t, "$options": "i"}})
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
