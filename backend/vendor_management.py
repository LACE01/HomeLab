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
    Endpoint EDR connector (see defender_sync.py) OR Qualys GAV/CSAM (see
    qualys_gav.py) -- real, agent-/scanner-reported "this software is
    installed on this specific asset" facts, not a substring guess (Qualys's
    own per-software `publisher` field is used directly as the vendor, same
    as Defender's). See DEVICE_SOFTWARE_SOURCES below for the exact list of
    source values this covers. This is the one source that isn't an
    inference; without at least one of those connectors configured, this app
    still has no dedicated per-asset software inventory and the
    substring-matching sources above remain the only signal, which is honest
    about what's actually available rather than pretending otherwise.

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

# db.software_inventory sources that represent a REAL per-device installed-software
# fact (not the Defender org-wide "this software exists somewhere" list, which has
# no asset_id and isn't reliable per-asset signal on its own) -- both entries here
# are agent-/scanner-reported, not substring-inferred. Add a new connector's source
# name here (and nowhere else) to make it count for vendor detection, the Asset
# Detail software panel, and _linked_assets' structural asset matching all at once.
DEVICE_SOFTWARE_SOURCES = ["defender_device", "qualys_device"]

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

# Common named software vendors/publishers that routinely show up in
# vulnerability-scanner finding titles (Qualys/Nessus-style "Adobe Acrobat
# Reader DC Multiple Vulnerabilities", "Oracle Java SE Multiple
# Vulnerabilities") and SBOM component_name/ecosystem strings. There's no
# structured "vendor" field on a finding to read directly -- this is
# necessarily a curated heuristic, same as OS_VENDOR_MAP above, matched as a
# case-insensitive substring against `title` + `component_name`. If a match
# is wrong or too broad for your environment, approve it and edit the
# resulting vendor's match_terms (or deny it so it never resurfaces).
SOFTWARE_VENDOR_KEYWORDS = [
    ("adobe", "Adobe"), ("acrobat", "Adobe"), ("photoshop", "Adobe"), ("flash player", "Adobe"),
    ("coldfusion", "Adobe"),
    ("oracle", "Oracle"), ("java se", "Oracle"), ("java runtime", "Oracle"), ("jre ", "Oracle"),
    ("jdk ", "Oracle"), ("mysql", "Oracle"), ("weblogic", "Oracle"), ("virtualbox", "Oracle"),
    ("google chrome", "Google"), ("chromium", "Google"), ("android", "Google"),
    ("mozilla", "Mozilla"), ("firefox", "Mozilla"), ("thunderbird", "Mozilla"),
    ("apple", "Apple"), ("safari", "Apple"), ("itunes", "Apple"), ("quicktime", "Apple"),
    ("ios ", "Apple"), ("macos", "Apple"),
    ("cisco", "Cisco"), ("citrix", "Citrix"), ("fortinet", "Fortinet"), ("fortigate", "Fortinet"),
    ("palo alto", "Palo Alto Networks"), ("juniper", "Juniper Networks"),
    ("f5 ", "F5"), ("big-ip", "F5"), ("sap ", "SAP"), ("ibm ", "IBM"),
    ("symantec", "Symantec"), ("mcafee", "McAfee"), ("trend micro", "Trend Micro"),
    ("zoom", "Zoom"), ("slack", "Slack"), ("atlassian", "Atlassian"), ("jira", "Atlassian"),
    ("confluence", "Atlassian"), ("bitbucket", "Atlassian"),
    ("docker", "Docker"), ("gitlab", "GitLab"), ("splunk", "Splunk"),
    ("elasticsearch", "Elastic"), ("kibana", "Elastic"), ("logstash", "Elastic"),
    ("mongodb", "MongoDB Inc"), ("postgresql", "PostgreSQL Global Development Group"),
    ("apache ", "Apache Software Foundation"), ("openssl", "OpenSSL Project"),
    ("php ", "PHP Group"), ("7-zip", "7-Zip"), ("winrar", "RARLAB"), ("putty", "PuTTY"),
    ("notepad++", "Notepad++"), ("teamviewer", "TeamViewer"), ("anydesk", "AnyDesk"),
    ("dropbox", "Dropbox"),
    ("microsoft", "Microsoft"), ("windows", "Microsoft"), (" office", "Microsoft"),
    ("exchange server", "Microsoft"), ("sharepoint", "Microsoft"), ("sql server", "Microsoft"),
    ("internet explorer", "Microsoft"), (" edge", "Microsoft"), (".net framework", "Microsoft"),
    ("outlook", "Microsoft"), ("powershell", "Microsoft"),
    ("vmware", "VMware"), ("esxi", "VMware"),
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
    """Scans assets, findings, and (when configured) real EDR software inventory
    for candidate vendor names not already tracked:
      - asset hardware manufacturer (first token of hardware_info)
      - asset OS vendor (OS_VENDOR_MAP)
      - finding title / SBOM component_name (SOFTWARE_VENDOR_KEYWORDS) -- this is
        what surfaces a vendor from actual vulnerability data, e.g. a Qualys/Nessus
        finding titled "Adobe Acrobat Reader DC Multiple Vulnerabilities" suggests
        "Adobe" even though no asset's hardware_info/os ever mentions it
      - db.software_inventory (Microsoft Defender for Endpoint's per-device sync,
        when that connector is configured)
    Every source is merged into ONE candidate per vendor name via a shared set of
    asset_ids, so a vendor detected through multiple sources (e.g. "Microsoft" from
    both asset_os AND a finding title) gets a single, correctly-deduplicated
    asset_count rather than one inflated or duplicated entry per source. Returns
    [{name, category, source, asset_count}], sorted by asset_count desc, excluding
    anything that already matches an existing vendor's name or match_terms."""
    existing = await db.vendors.find({}, {"_id": 0, "name": 1, "match_terms": 1}).to_list(2000)
    existing_terms = set()
    for v in existing:
        existing_terms.add((v.get("name") or "").strip().lower())
        for t in v.get("match_terms") or []:
            existing_terms.add(t.strip().lower())

    # name -> {"category": "Hardware"|"Software", "asset_ids": set(), "sources": set()}
    candidates: dict = {}

    def _add(name: str, category: str, asset_id, source: str):
        name = (name or "").strip()
        if not name or name.lower() in existing_terms:
            return
        entry = candidates.setdefault(name, {"category": category, "asset_ids": set(), "sources": set()})
        if asset_id:
            entry["asset_ids"].add(asset_id)
        entry["sources"].add(source)
        if category == "Hardware":
            entry["category"] = "Hardware"  # hardware presence always wins the displayed category

    from feature_flags import is_enabled
    detect_hw = await is_enabled(db, "vendor_detect_hardware")
    detect_os = await is_enabled(db, "vendor_detect_os")
    detect_findings = await is_enabled(db, "vendor_detect_findings")
    detect_edr = await is_enabled(db, "vendor_detect_edr_software")

    if detect_hw or detect_os:
        assets = await db.assets.find({}, {"_id": 0, "id": 1, "hardware_info": 1, "os": 1}).to_list(50000)
        for a in assets:
            if detect_hw:
                hw = _first_token(a.get("hardware_info"))
                if hw:
                    _add(hw, "Hardware", a.get("id"), "asset_hardware_info")
            if detect_os:
                os_text = (a.get("os") or "").lower()
                for needle, vendor_name in OS_VENDOR_MAP:
                    if needle in os_text:
                        _add(vendor_name, "Software", a.get("id"), "asset_os")

    # Findings/vulnerabilities routinely name the affected product in their title
    # (scanner convention, not this app's own data) or, for SBOM-sourced findings,
    # in component_name -- this is the source that makes "software vulnerabilities
    # imply a vendor" actually work, not just hardware/OS presence.
    if detect_findings:
        findings_cursor = db.findings.find({}, {"_id": 0, "title": 1, "component_name": 1, "asset_id": 1})
        async for f in findings_cursor:
            haystack = f"{f.get('title') or ''} {f.get('component_name') or ''}".lower()
            for needle, vendor_name in SOFTWARE_VENDOR_KEYWORDS:
                if needle in haystack:
                    _add(vendor_name, "Software", f.get("asset_id"), "finding_title")

    # Real per-asset installed-software vendors (Defender for Endpoint AND/OR
    # Qualys GAV/CSAM -- see DEVICE_SOFTWARE_SOURCES). asset_id is only set on
    # per-device rows; Defender's org-wide rows (asset_id=None, the org-wide
    # software list) are deliberately excluded here -- an asset_count needs real
    # per-asset backing to mean anything.
    if detect_edr:
        sw_cursor = db.software_inventory.find(
            {"source": {"$in": DEVICE_SOFTWARE_SOURCES}, "asset_id": {"$ne": None}},
            {"_id": 0, "vendor": 1, "asset_id": 1},
        )
        async for row in sw_cursor:
            _add(row.get("vendor"), "Software", row.get("asset_id"), "device_software_inventory")

    suggestions = [
        {"name": name, "category": v["category"], "source": "/".join(sorted(v["sources"])), "asset_count": len(v["asset_ids"])}
        for name, v in candidates.items()
        if v["asset_ids"]  # a candidate with zero real linked assets (e.g. an
                            # asset-less SBOM upload's component_name match) isn't
                            # something worth putting in front of a human to approve
    ]
    suggestions.sort(key=lambda s: -s["asset_count"])
    return suggestions


async def _linked_assets(db, vendor: dict) -> tuple:
    """Returns (assets, structural_asset_ids). structural_asset_ids is the subset of
    linked asset ids where the WHOLE asset genuinely belongs to / runs this vendor's
    product (hardware_info/os/hostname match, or real per-device EDR software
    inventory) -- for those, it's fair to attribute every finding on the asset to
    this vendor's risk surface. Assets linked ONLY via a single matching finding
    title (see below) are deliberately excluded from structural_asset_ids: an asset
    that happens to have one Adobe finding among many unrelated ones doesn't mean
    every other finding on it is Adobe's problem too. _linked_findings uses this
    distinction to avoid over-attributing unrelated findings to a vendor that was
    only ever linked to an asset through one specific finding."""
    terms = [vendor.get("name")] + (vendor.get("match_terms") or [])
    terms = [t for t in terms if t]
    if not terms:
        return [], []
    ors = []
    for t in terms:
        ors.append({"hardware_info": {"$regex": t, "$options": "i"}})
        ors.append({"os": {"$regex": t, "$options": "i"}})
        ors.append({"hostname": {"$regex": t, "$options": "i"}})
    assets = await db.assets.find({"$or": ors}, {"_id": 0}).to_list(1000)

    # Real per-asset software-vendor linkage (Defender for Endpoint and/or Qualys
    # GAV/CSAM -- see DEVICE_SOFTWARE_SOURCES), when available -- picks up assets
    # running this vendor's software even when nothing about the asset's
    # hardware_info/os/hostname happens to match, which is exactly the precision
    # gap the substring approach above can't close on its own.
    structural_ids = {a["id"] for a in assets}
    sw_ors = [{"vendor": {"$regex": t, "$options": "i"}} for t in terms]
    sw_rows = await db.software_inventory.find(
        {"source": {"$in": DEVICE_SOFTWARE_SOURCES}, "asset_id": {"$ne": None}, "$or": sw_ors},
        {"_id": 0, "asset_id": 1},
    ).to_list(5000)
    extra_ids = {r["asset_id"] for r in sw_rows} - structural_ids
    if extra_ids:
        assets += await db.assets.find({"id": {"$in": list(extra_ids)}}, {"_id": 0}).to_list(1000)
        structural_ids |= extra_ids

    # Finding-based linkage -- an asset with a finding whose title/component_name
    # names this vendor (e.g. "Adobe Acrobat Reader DC Multiple Vulnerabilities") is
    # a real, vulnerability-driven vendor relationship even when the asset's own
    # hardware_info/os/hostname says nothing about it -- this is what makes a
    # pure-software vendor detected via suggest_vendors() (see SOFTWARE_VENDOR_
    # KEYWORDS) show a non-zero asset_count once approved, instead of contradicting
    # the very detection that suggested it in the first place. NOT added to
    # structural_ids -- see docstring above.
    finding_ors = []
    for t in terms:
        finding_ors.append({"title": {"$regex": t, "$options": "i"}})
        finding_ors.append({"component_name": {"$regex": t, "$options": "i"}})
    finding_asset_ids = await db.findings.distinct("asset_id", {"$or": finding_ors, "asset_id": {"$ne": None}})
    extra_finding_ids = set(finding_asset_ids) - structural_ids
    if extra_finding_ids:
        assets += await db.assets.find({"id": {"$in": list(extra_finding_ids)}}, {"_id": 0}).to_list(1000)
    return assets, sorted(structural_ids)


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
    assets, structural_asset_ids = await _linked_assets(db, vendor)
    findings = await _linked_findings(db, vendor, structural_asset_ids)
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
        hits = 0
        findings = []
        try:
            summary = await reconng.run_module(db, module_id, domain)
            hits = summary.get("osint_findings_created", 0) + summary.get("easm_candidates_created", 0)
            status = "found" if hits > 0 else "clean"
            if hits > 0:
                # Return the actual finding content alongside the status, so the
                # "Check now" panel can show WHAT was found (pulse names, IOC
                # detail, CT certificates, ...) instead of a bare "Hit" chip the
                # analyst can't drill into.
                findings = await db.osint_findings.find(
                    {"module": module_id, "target": domain}, {"_id": 0, "raw": 0},
                ).sort("found_at", -1).to_list(10)
        except ValueError:
            status = "not_configured"
        except Exception:
            status = "error"
        results.append({"module_id": module_id, "module_label": mod["label"], "status": status,
                        "hits": hits, "findings": findings})
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
        risk = await refresh_vendor_risk_cache(db, v)
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


async def refresh_vendor_risk_cache(db, vendor: dict) -> dict:
    """Computes this vendor's risk live and persists the result onto the vendor
    document as `risk_cache`, so list/summary views (list_vendors, vendor_stats) can
    read a cheap precomputed number instead of re-running the full asset/finding
    scan for every vendor on every page load. At real-world scale (hundreds of
    linked assets, thousands of linked findings for a vendor like "Microsoft") that
    scan is expensive enough on its own, and list_vendors/vendor_stats were EACH
    independently re-running it per vendor -- doubling the cost for zero benefit,
    since both endpoints load together when the Vendor & Third-Party Risk page opens.
    The single-vendor detail view (GET /v1/vendors/{id}) still computes and returns
    a fully live value on every call (that's the one place "authoritative, this
    exact second" actually matters) -- it just also writes the same result here as
    a side effect, so the list view reflects it immediately afterward instead of
    waiting for the next nightly sweep."""
    risk = await compute_vendor_risk(db, vendor)
    cache = {
        "asset_count": risk["asset_count"], "finding_count": risk["finding_count"],
        "severity_counts": risk["severity_counts"], "risk_score": risk["risk_score"],
        "risk_band": risk["risk_band"], "computed_at": _now_iso(),
    }
    await db.vendors.update_one({"id": vendor["id"]}, {"$set": {"risk_cache": cache}})
    return risk


async def scan_vendor_candidates(db) -> dict:
    """Runs suggest_vendors() (asset hardware_info/os, finding/vulnerability titles,
    SBOM component_name, and real EDR software inventory when configured) and upserts each
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
