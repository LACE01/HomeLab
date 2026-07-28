"""Security Reviews -- Phase 2/3 machinery: the four remaining auto-fill hooks,
auto-answered questions, the six additional playbooks, pre-drafted findings and
report language, vendor questionnaire compilation, suggested risk scoring,
external checks automation, and the re-review/re-validation lifecycle.

Kept separate from security_reviews.py (Phase 1 core: data model, seeds v1,
banding math) so the Phase 1 module stays the readable "what is a review"
reference and this stays the "what the platform fills in for you" layer.

Auto-fill philosophy (per spec, repeated here because it's the design rule
every function in this file follows): wherever the platform already knows
something, populate it WITH A VISIBLE SOURCE TAG, and the analyst can always
override -- auto-filled data is a head start, never an unappealable verdict.
"""
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from security_reviews import (
    SAAS_PLAYBOOK_V1, SAAS_QUESTIONNAIRE_V1, risk_band, _now_iso,
)

OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

# Residual-band -> months until re-review (Phase 3 lifecycle). Critical residual
# shouldn't normally be approved at all, but if it is, it gets the shortest leash.
REREVIEW_MONTHS = {"Critical": 6, "High": 12, "Medium": 24, "Low": 36}


def _tag(source: str) -> str:
    return f"Pulled from {source}, {datetime.now(timezone.utc).date().isoformat()}"


# =========================================================================
# Auto-fill hooks (Phase 2): asset_inventory_check, open_findings_pull,
# osint_compromise_pull, governance_crosswalk
# =========================================================================

async def asset_inventory_check(db, review: dict) -> dict:
    """Is the thing under review ALREADY on the network? Matches the entity name
    against asset hostnames/OS strings and the per-device installed-software
    inventory. A 'new' tool already present = shadow deployment -> auto-draft
    finding (status='draft', analyst accepts/edits/deletes)."""
    name = (review.get("entity_name") or "").strip()
    out = {"source_tag": _tag("Asset Inventory"), "assets": [], "software_hits": [],
           "linked_assets": [], "shadow_deployment": False}
    linked_ids = review.get("linked_asset_ids") or []
    if linked_ids:
        out["linked_assets"] = await db.assets.find(
            {"id": {"$in": linked_ids}},
            {"_id": 0, "id": 1, "hostname": 1, "os": 1, "criticality": 1, "owner_team": 1, "internet_facing": 1},
        ).to_list(50)
    if not name:
        return out
    rx = {"$regex": re.escape(name), "$options": "i"}
    out["assets"] = await db.assets.find(
        {"$or": [{"hostname": rx}, {"os": rx}, {"hardware_info": rx}]},
        {"_id": 0, "id": 1, "hostname": 1, "os": 1, "criticality": 1, "owner_team": 1},
    ).to_list(20)
    out["software_hits"] = await db.software_inventory.find(
        {"$or": [{"name": rx}, {"vendor": rx}]},
        {"_id": 0, "vendor": 1, "name": 1, "version": 1, "asset_id": 1, "source": 1},
    ).to_list(50)
    if out["software_hits"] or out["assets"]:
        out["shadow_deployment"] = True
        existing = await db.security_review_findings.find_one(
            {"review_id": review["id"], "shadow_deployment_auto": True}, {"_id": 0, "id": 1})
        if not existing:
            hosts = len({s.get("asset_id") for s in out["software_hits"] if s.get("asset_id")})
            await db.security_review_findings.insert_one({
                "id": str(uuid.uuid4()), "review_id": review["id"],
                "description": f"Shadow deployment: \"{name}\" already appears in the environment "
                               f"({len(out['software_hits'])} installed-software record(s) across ~{hosts or '?'} host(s), "
                               f"{len(out['assets'])} matching asset(s)) before this review approved it.",
                "severity": "Medium", "category": "Governance", "affected_component": name,
                "cis_mapping": "2.1", "recommendation": "Confirm scope of existing installs; either fold them into "
                               "this review's approval or remove them pending the decision.",
                "owner": review.get("assignee") or "", "due_date": None, "status": "draft",
                "is_condition_of_approval": False, "condition_met": None, "condition_deadline": None,
                "promoted_to_risk_register_id": None, "shadow_deployment_auto": True,
                "source_tag": out["source_tag"],
                "created_by": "auto-fill", "created_at": _now_iso(),
            })
    return out


async def open_findings_pull(db, review: dict) -> dict:
    """Open-vulnerability state of the in-scope internal assets (linked_asset_ids):
    severity counts, top QIDs, SLA-overdue count. The 'is the environment this
    lands in itself healthy' half of the risk picture."""
    out = {"source_tag": _tag("Findings"), "severity_counts": {}, "top_qids": [],
           "overdue": 0, "total_open": 0, "asset_count": len(review.get("linked_asset_ids") or [])}
    linked_ids = review.get("linked_asset_ids") or []
    if not linked_ids:
        return out
    flt = {"asset_id": {"$in": linked_ids}, "status": {"$in": OPEN_STATES}}
    findings = await db.findings.find(
        flt, {"_id": 0, "severity": 1, "qid": 1, "title": 1, "due_at": 1}).to_list(2000)
    out["total_open"] = len(findings)
    now = _now_iso()
    qid_counts: dict = {}
    for f in findings:
        sev = f.get("severity") or "Unknown"
        out["severity_counts"][sev] = out["severity_counts"].get(sev, 0) + 1
        if f.get("due_at") and f["due_at"] < now:
            out["overdue"] += 1
        if f.get("qid"):
            qid_counts.setdefault(f["qid"], {"qid": f["qid"], "title": f.get("title"), "count": 0})
            qid_counts[f["qid"]]["count"] += 1
    out["top_qids"] = sorted(qid_counts.values(), key=lambda x: -x["count"])[:10]
    return out


async def osint_compromise_pull(db, review: dict) -> dict:
    """Compromise-monitoring / OSINT exposure history for the vendor domain --
    full finding docs (label/detail/raw) so each hit is drillable in the review
    workspace exactly like it is on the Vendor Detail page."""
    out = {"source_tag": _tag("OSINT / Compromise Monitoring"), "hits": [], "vendor_id": None}
    domain = (review.get("entity_domain") or "").lower()
    if not domain:
        return out
    out["hits"] = await db.osint_findings.find(
        {"target": domain}, {"_id": 0}).sort("found_at", -1).to_list(50)
    vendor = await db.vendors.find_one({"domain": domain}, {"_id": 0, "id": 1})
    if vendor:
        out["vendor_id"] = vendor["id"]
    return out


# Static config mapping (per spec: "Can be a static config mapping initially").
GOVERNANCE_CROSSWALK = {
    "CJIS": [
        "CJIS Security Addendum signed by the vendor",
        "Vendor personnel screening meets CJIS requirements",
        "Data storage location satisfies CJIS (U.S., access-controlled)",
        "Audit trail of access to CJI available",
    ],
    "PHI / HIPAA": [
        "Business Associate Agreement (BAA) executed BEFORE go-live",
        "Minimum-necessary access model documented",
        "Vendor breach-notification terms meet HIPAA timing",
    ],
    "PCI": [
        "Cardholder-data scope determination documented (does this change scope?)",
        "SAQ impact assessed",
        "Cardholder data flows through the product mapped",
    ],
    "PII (Colorado)": [
        "Reasonable safeguards obligation addressed (C.R.S. 6-1-713.5)",
        "Breach-notification path defined (C.R.S. 6-1-716)",
        "Data minimization: only required PII fields go in",
    ],
    "Elections data": [
        "Elections security standard applies -- confirm compliance",
        "Segmentation from elections systems verified",
    ],
}

REVIEW_TYPE_CROSSWALK = {
    "AI tool adoption": [
        "AI usage policy compliance confirmed (training-data usage, retention, output handling)",
    ],
    "Browser extension / plugin / script": [
        "Extension permission manifest reviewed against allowlist policy",
    ],
}


async def governance_crosswalk(db, review: dict) -> dict:
    """Applicable policy/regulatory checklist derived from review type + data
    classifications. Each item is confirmable in the UI or convertible to a
    finding -- the hook just supplies the list."""
    items = []
    for cls in review.get("data_classifications") or []:
        for req in GOVERNANCE_CROSSWALK.get(cls, []):
            items.append({"classification": cls, "requirement": req})
    for req in REVIEW_TYPE_CROSSWALK.get(review.get("review_type") or "", []):
        items.append({"classification": review.get("review_type"), "requirement": req})
    return {"source_tag": _tag("Governance Crosswalk"), "items": items}


AUTOFILL_HOOKS = {
    "asset_inventory_check": asset_inventory_check,
    "open_findings_pull": open_findings_pull,
    "osint_compromise_pull": osint_compromise_pull,
    "governance_crosswalk": governance_crosswalk,
}


# =========================================================================
# Auto-answered questions (Phase 2)
# =========================================================================

async def auto_answer_questions(db, review: dict, template: dict) -> list:
    """Answer every question in the template that carries an auto_answer_hook,
    from platform data. Never overwrites an analyst's answer; marks its own rows
    auto_answered=True with a source tag so the UI renders them distinctly."""
    answered = []
    for q in template.get("questions", []):
        hook = q.get("auto_answer_hook")
        if not hook:
            continue
        existing = await db.security_review_responses.find_one(
            {"review_id": review["id"], "question_order": q["order"]}, {"_id": 0})
        if existing and not existing.get("auto_answered"):
            continue  # analyst already answered -- their word stands
        if hook == "open_findings_pull":
            data = await open_findings_pull(db, review)
            crits = data["severity_counts"].get("Critical", 0) + data["severity_counts"].get("High", 0)
            if not review.get("linked_asset_ids"):
                answer, evidence = "na", "No internal assets linked to this review."
            elif crits > 0:
                answer = "no"
                evidence = (f"{crits} open Critical/High finding(s) across {data['asset_count']} linked asset(s); "
                            f"{data['overdue']} past SLA. Top QIDs: "
                            + ", ".join(t["qid"] for t in data["top_qids"][:5]))
            else:
                answer, evidence = "yes", f"No open Critical/High findings on the {data['asset_count']} linked asset(s)."
            source_tag = data["source_tag"]
        else:
            continue
        doc = {
            "review_id": review["id"], "question_order": q["order"], "answer": answer,
            "evidence_text": evidence, "attachments": [], "auto_answered": True,
            "source_tag": source_tag, "analyst_overridden": False,
            "answered_by": "auto-fill", "answered_at": _now_iso(),
        }
        if existing:
            await db.security_review_responses.update_one(
                {"review_id": review["id"], "question_order": q["order"]}, {"$set": doc})
        else:
            doc["id"] = str(uuid.uuid4())
            await db.security_review_responses.insert_one(dict(doc))
        answered.append({"question_order": q["order"], "answer": answer, "source_tag": source_tag})
    return answered


# =========================================================================
# Pre-drafted findings + report language (Phase 2)
# =========================================================================

DOMAIN_RECOMMENDATIONS = {
    "Identity & Access": "Require the identity gap be closed (SSO/MFA/RBAC/SCIM as applicable) via configuration or contract term before go-live.",
    "Data Protection": "Add contractual data-protection terms (encryption, residency, deletion on termination, no secondary use) and verify technically where possible.",
    "Network & Attack Surface": "Minimize exposure: restrict inbound access, scope integration credentials read-only, and segment any installed agent.",
    "Logging & Monitoring": "Require audit-log export to the SIEM and at least 12-month retention as an adoption condition.",
    "Vendor Security Program": "Request the missing program evidence (certification, patching SLAs, IR plan) and set a remediation deadline as a condition of approval.",
    "Resilience": "Document the outage fallback for this product and validate the vendor's RTO/RPO claims against the business need.",
    "Compliance": "Do not go live until the regulatory prerequisite is executed and verified.",
}


def draft_finding_from_answer(review_id: str, q: dict, answer: str) -> Optional[dict]:
    """No/Partial on a heavily-weighted question -> a draft finding the analyst
    edits/accepts/deletes. weight 5 + 'no' -> High; weight >=4 otherwise Medium."""
    if answer not in ("no", "partial") or q.get("risk_weight", 0) < 4:
        return None
    severity = "High" if (q["risk_weight"] >= 5 and answer == "no") else "Medium"
    return {
        "id": str(uuid.uuid4()), "review_id": review_id,
        "description": f"Q{q['order']} answered {answer.upper()}: {q['text']}",
        "severity": severity, "category": q.get("domain") or "General",
        "affected_component": "", "cis_mapping": q.get("cis_mapping") or "",
        "recommendation": DOMAIN_RECOMMENDATIONS.get(q.get("domain"), "Remediate or accept with documented rationale."),
        "owner": "", "due_date": None, "status": "draft",
        "is_condition_of_approval": False, "condition_met": None, "condition_deadline": None,
        "promoted_to_risk_register_id": None, "from_question_order": q["order"],
        "source_tag": _tag("Questionnaire"),
        "created_by": "auto-draft", "created_at": _now_iso(),
    }


def draft_executive_summary(review: dict, findings: list) -> str:
    """Plain-English boilerplate the analyst edits before publishing -- severity +
    category driven, deliberately jargon-light."""
    name = review.get("entity_name") or review.get("title") or "The reviewed item"
    inh = (review.get("inherent_risk") or {}).get("band")
    res = (review.get("residual_risk") or {}).get("band")
    real = [f for f in findings if f.get("status") != "draft"]
    crit_high = [f for f in real if f.get("severity") in ("Critical", "High")]
    conditions = [f for f in real if f.get("is_condition_of_approval")]
    parts = []
    parts.append(f"{name} was reviewed for {review.get('review_type', 'adoption').lower()}.")
    if inh and res:
        if inh != res:
            parts.append(f"Used as-is, the risk is {inh}; with the required controls in place it drops to {res}.")
        else:
            parts.append(f"The assessed risk is {inh}, with or without additional controls.")
    elif inh:
        parts.append(f"The assessed risk if adopted as-is is {inh}.")
    if crit_high:
        cats = sorted({f.get("category") or "general" for f in crit_high})
        parts.append(f"The most significant concerns are in {', '.join(cats)} "
                     f"({len(crit_high)} Critical/High finding(s)).")
    elif real:
        parts.append(f"{len(real)} lower-severity finding(s) were noted; none block adoption on their own.")
    else:
        parts.append("No significant security findings were identified.")
    if conditions:
        parts.append(f"Approval carries {len(conditions)} condition(s) that must be completed by their deadlines.")
    classifications = [c for c in (review.get("data_classifications") or []) if c != "Public-only / none"]
    if classifications:
        parts.append(f"The system will handle {', '.join(classifications)} data, which drove the compliance requirements in this review.")
    return " ".join(parts)


# =========================================================================
# Vendor questionnaire compilation (Phase 2)
# =========================================================================

def compile_vendor_questionnaire(review: dict, template: dict, responses: list) -> dict:
    """Vendor-facing question list: every vendor_facing question that applies to
    this review's classifications, plus any question the platform couldn't
    auto-answer -- formatted for copy-paste into an email."""
    resp_by_order = {r["question_order"]: r for r in responses}
    classifications = review.get("data_classifications") or []
    questions = []
    for q in template.get("questions", []):
        cond = q.get("conditional_on")
        if cond and not cond.startswith("q") and cond not in classifications:
            continue
        r = resp_by_order.get(q["order"])
        include = q.get("vendor_facing") or (r and r.get("auto_answered") and r.get("answer") == "na")
        if include:
            questions.append({"order": q["order"], "domain": q["domain"], "text": q["text"]})
    lines = [f"Security questionnaire — {review.get('entity_name') or review.get('title')} "
             f"({review.get('review_number')})", ""]
    current_domain = None
    n = 0
    for q in questions:
        if q["domain"] != current_domain:
            current_domain = q["domain"]
            lines.append(f"## {current_domain}")
        n += 1
        lines.append(f"{n}. {q['text']}")
    return {"questions": questions, "text": "\n".join(lines)}


# =========================================================================
# Suggested risk scoring (Phase 3) -- never auto-finalized
# =========================================================================

async def suggest_risk(db, review: dict, template: dict, responses: list) -> dict:
    """Suggested inherent risk from weighted questionnaire answers + enrichment
    signals. The analyst accepts or overrides (override requires justification --
    enforced at save when the frontend echoes back the suggestion it displayed)."""
    resp_by_order = {r["question_order"]: r for r in responses}
    weight_total, weight_bad = 0, 0.0
    for q in template.get("questions", []):
        r = resp_by_order.get(q["order"])
        if not r or r["answer"] == "na":
            continue
        w = q.get("risk_weight", 1)
        weight_total += w
        if r["answer"] == "no":
            weight_bad += w
        elif r["answer"] == "partial":
            weight_bad += w * 0.5
    ratio = (weight_bad / weight_total) if weight_total else 0.0

    rationale = []
    likelihood = 2
    if ratio >= 0.5:
        likelihood += 2
        rationale.append(f"{int(ratio*100)}% of weighted questionnaire answers are No/Partial")
    elif ratio >= 0.25:
        likelihood += 1
        rationale.append(f"{int(ratio*100)}% of weighted questionnaire answers are No/Partial")
    findings_data = await open_findings_pull(db, review)
    crits = findings_data["severity_counts"].get("Critical", 0) + findings_data["severity_counts"].get("High", 0)
    if crits:
        likelihood += 1
        rationale.append(f"{crits} open Critical/High finding(s) on in-scope assets")
    osint = await osint_compromise_pull(db, review)
    if osint["hits"]:
        likelihood += 1
        rationale.append(f"{len(osint['hits'])} OSINT/compromise hit(s) on the vendor domain")
    likelihood = min(5, likelihood)

    classifications = review.get("data_classifications") or []
    heavy = any(c in classifications for c in ("CJIS", "PHI / HIPAA", "PCI", "Elections data"))
    conf_impact = 5 if heavy else 4 if "PII (Colorado)" in classifications else 2
    if heavy:
        rationale.append("regulated data classes selected (drives confidentiality/compliance impact)")
    elif "PII (Colorado)" in classifications:
        rationale.append("PII selected (drives confidentiality impact)")
    impacts = {"confidentiality": conf_impact, "integrity": 3, "availability": 3,
               "compliance_legal": conf_impact, "reputational": 3}
    max_impact = max(impacts.values())
    return {
        "likelihood": likelihood, "impacts": impacts,
        "band": risk_band(likelihood, max_impact),
        "score": likelihood * max_impact,
        "answered_weight_ratio_bad": round(ratio, 2),
        "rationale": rationale,
        "source_tag": _tag("Questionnaire + Findings + OSINT"),
    }


# =========================================================================
# External checks automation (Phase 3) -- best-effort, degrade to manual
# =========================================================================

SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"]


async def run_external_checks(db, review: dict) -> dict:
    """Breach-history signal, CVE keyword lookup, and TLS/security-header scan of
    the vendor domain. Every result carries a source tag; a failed check degrades
    to a 'manual' status instead of blocking the others."""
    import httpx
    domain = (review.get("entity_domain") or "").lower()
    name = review.get("entity_name") or ""
    results = []

    # (a) TLS / security headers on the vendor's site
    if domain:
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
                r = await c.get(f"https://{domain}")
            present = [h for h in SECURITY_HEADERS if h in {k.lower() for k in r.headers.keys()}]
            missing = [h for h in SECURITY_HEADERS if h not in present]
            results.append({
                "check": "tls_security_headers", "status": "ok" if not missing else "attention",
                "summary": f"HTTPS reachable; {len(present)}/{len(SECURITY_HEADERS)} security headers present"
                           + (f" (missing: {', '.join(missing)})" if missing else ""),
                "detail": {"present": present, "missing": missing, "final_url": str(r.url)},
                "source_tag": _tag(f"https://{domain}"),
            })
        except Exception as e:
            results.append({"check": "tls_security_headers", "status": "manual",
                            "summary": f"Could not scan https://{domain} ({type(e).__name__}) -- check manually.",
                            "detail": None, "source_tag": _tag("live scan")})
    else:
        results.append({"check": "tls_security_headers", "status": "manual",
                        "summary": "No vendor domain set -- add one to enable the TLS scan.",
                        "detail": None, "source_tag": _tag("live scan")})

    # (b) Breach-history signal: OSINT hits + security-news name matches already on file
    osint_count = await db.osint_findings.count_documents({"target": domain}) if domain else 0
    news = []
    try:
        from security_news import get_vendor_news
        if name:
            news = await get_vendor_news(db, name, days=365, limit=5)
    except Exception:
        pass
    results.append({
        "check": "breach_history", "status": "attention" if (osint_count or news) else "ok",
        "summary": f"{osint_count} OSINT/compromise hit(s) on the domain; {len(news)} security-news mention(s) in the last year.",
        "detail": {"osint_hits": osint_count, "news": [{"title": n.get("title"), "link": n.get("link")} for n in news]},
        "source_tag": _tag("OSINT + Security News"),
    })

    # (c) CVE keyword lookup against NVD (best-effort, unauthenticated)
    if name:
        try:
            import httpx as _hx
            async with _hx.AsyncClient(timeout=20) as c:
                r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                 params={"keywordSearch": name, "resultsPerPage": 5})
            if r.status_code == 200:
                data = r.json()
                total = data.get("totalResults", 0)
                cves = [v["cve"]["id"] for v in data.get("vulnerabilities", [])][:5]
                results.append({
                    "check": "cve_lookup", "status": "attention" if total else "ok",
                    "summary": f"{total} CVE(s) match \"{name}\" on NVD" + (f" (e.g. {', '.join(cves)})" if cves else ""),
                    "detail": {"total": total, "sample": cves}, "source_tag": _tag("NVD"),
                })
            else:
                results.append({"check": "cve_lookup", "status": "manual",
                                "summary": f"NVD returned HTTP {r.status_code} -- check CVEs manually.",
                                "detail": None, "source_tag": _tag("NVD")})
        except Exception as e:
            results.append({"check": "cve_lookup", "status": "manual",
                            "summary": f"NVD lookup failed ({type(e).__name__}) -- check CVEs manually.",
                            "detail": None, "source_tag": _tag("NVD")})

    payload = {"ran_at": _now_iso(), "results": results}
    await db.security_reviews.update_one({"id": review["id"]}, {"$set": {"external_checks": payload}})
    return payload


# =========================================================================
# Re-validation clone (Phase 3 lightweight re-review path)
# =========================================================================

async def clone_for_revalidation(db, review: dict, actor: str) -> dict:
    """Clone a decided/closed review into a fresh 'what changed?' re-validation:
    same entity/classifications/scope, prior responses copied with a prior-review
    source tag (analyst re-confirms rather than re-types), steps reset."""
    from security_reviews import next_review_number, latest_playbook_for_type, instantiate_steps, audit
    new = {k: v for k, v in review.items() if k not in ("_id",)}
    new.update({
        "id": str(uuid.uuid4()), "review_number": await next_review_number(db),
        "status": "Requested", "created_at": _now_iso(), "updated_at": _now_iso(),
        "sla_paused_at": None, "sla_paused_total_seconds": 0,
        "decision": None, "closed_at": None, "external_checks": None,
        "inherent_risk": None, "residual_risk": None, "risk_of_not_adopting": None,
        "revalidation_of": review["id"], "assignee": actor,
        "title": f"Re-validation: {review.get('title')}",
    })
    await db.security_reviews.insert_one(dict(new))
    playbook = await latest_playbook_for_type(db, new.get("review_type"))
    if playbook:
        await instantiate_steps(db, new, playbook)
    prior_responses = await db.security_review_responses.find(
        {"review_id": review["id"]}, {"_id": 0}).to_list(200)
    for r in prior_responses:
        r = dict(r)
        r.update({"id": str(uuid.uuid4()), "review_id": new["id"], "auto_answered": True,
                  "source_tag": f"Prior review {review.get('review_number')}",
                  "analyst_overridden": False})
        await db.security_review_responses.insert_one(r)
    await audit(db, new["id"], "created", actor,
                f"Re-validation of {review.get('review_number')} -- confirm what changed")
    return {k: v for k, v in new.items() if k != "_id"}


# =========================================================================
# SEED DATA -- Phase 2: questionnaire v2 (adds the auto-answered question) and
# the six additional playbooks, each the SaaS spine + type-specific steps.
# =========================================================================

SAAS_QUESTIONNAIRE_V2 = {
    "key": "saas_acquisition_internal",
    "name": "Internal Questionnaire — SaaS Acquisition",
    "version": 2,
    "questions": SAAS_QUESTIONNAIRE_V1["questions"] + [
        {"order": 28, "domain": "Network & Attack Surface", "cis_mapping": "7.1", "risk_weight": 4,
         "vendor_facing": False, "conditional_on": None,
         "auto_answer_hook": "open_findings_pull",
         "text": "Are the in-scope internal assets free of open Critical/High vulnerabilities?"},
    ],
}


def _typed_playbook(key: str, name: str, review_types: list, extra_steps: list) -> dict:
    """Each additional playbook = the SaaS 13-step spine with type-specific steps
    spliced in after the external-posture step (order 5), renumbered."""
    base = [dict(s) for s in SAAS_PLAYBOOK_V1["steps"]]
    head = [s for s in base if s["order"] <= 5]
    tail = [s for s in base if s["order"] > 5]
    merged = head + [dict(s) for s in extra_steps] + tail
    for i, s in enumerate(merged, start=1):
        s["order"] = i
    return {"key": key, "name": name, "version": 1, "review_types": review_types, "steps": merged}


def _step(title: str, guidance: str, expected: str, allows_na: bool = True) -> dict:
    return {"order": 0, "step_type": "task", "autofill_hook": None, "conditional_on": None,
            "allows_na": allows_na, "title": title, "guidance": guidance, "expected_output": expected}


EXTRA_PLAYBOOKS = [
    _typed_playbook("hardware_acquisition", "Hardware Acquisition", ["New hardware"], [
        _step("Firmware update process", "Confirm how firmware updates are delivered and applied (signed? automatic? EOL policy?). Unpatchable or abandoned firmware is a standing risk.", "Firmware/update posture documented."),
        _step("Physical placement & segmentation", "Where does this device sit physically and on the network? Confirm VLAN/segment, management-interface isolation, and who has physical access.", "Placement + segmentation plan documented."),
        _step("Default credential check", "Verify default credentials are changed/disabled before deployment, and confirm no undocumented accounts exist (check vendor docs and CISA advisories for the model).", "Credential hardening confirmed."),
    ]),
    _typed_playbook("feature_enablement", "Feature Enablement", ["Feature enablement on an existing platform"], [
        _step("New data flows & egress", "This platform is already approved -- what NEW data flows, storage locations, or egress does enabling this feature create? Review the feature's docs and admin settings for data-sharing toggles.", "Delta data-flow note; only the delta is being reviewed."),
    ]),
    _typed_playbook("integration_api", "Integration / API Connection", ["New integration / API connection"], [
        _step("Authentication model & scopes", "How does the integration authenticate (OAuth app, API key, service account)? Confirm least-privilege scopes, read-only where possible, and where the credential is stored.", "Auth model + scopes documented."),
        _step("Data flow mapping", "Map exactly which fields/objects flow in each direction and how often. Anything syncing outbound is a disclosure surface.", "Bidirectional data-flow map attached."),
    ]),
    _typed_playbook("config_change", "Configuration / Architecture Change", ["Configuration or architecture change"], [
        _step("Blast radius & rollback", "What breaks if this change misbehaves, and how fast can it be reverted? A firewall rule/port opening/VPN tunnel should have an explicit rollback and an expiry/review date.", "Blast-radius note + rollback plan."),
    ]),
    _typed_playbook("ai_tool", "AI Tool Adoption", ["AI tool adoption"], [
        _step("Training-data usage", "Is our data used to train the vendor's models (or 'improve services')? Get the answer in writing and confirm the opt-out is contractual, not a dashboard toggle that can silently change.", "Training-data position documented in writing."),
        _step("Prompt & data retention", "How long are prompts/outputs retained, where, and who at the vendor can see them? Zero-retention or short-retention tiers exist for most serious vendors.", "Retention terms documented."),
        _step("Output handling & policy", "How will staff use outputs (decisions? public content? code?), and does that use comply with the AI usage policy? Confirm human-review requirements for consequential outputs.", "Output-handling guidance written; AI usage policy cited."),
    ]),
    _typed_playbook("browser_extension", "Browser Extension / Plugin", ["Browser extension / plugin / script"], [
        _step("Permission manifest review", "Read the extension's requested permissions ('read and change all your data on all websites' is a full compromise of everything in the browser). Confirm the minimum-permission version suffices.", "Permissions reviewed and justified."),
        _step("Publisher reputation & update channel", "Who publishes it, how long has it existed, and what's the update cadence? Extensions get sold and turned malicious -- check ownership history and reviews.", "Publisher assessment documented."),
    ]),
]


async def ensure_phase2_seeded(db) -> None:
    """Idempotently seed questionnaire v2 + the six additional playbooks."""
    docs = [SAAS_QUESTIONNAIRE_V2]
    for d in docs:
        existing = await db.review_questionnaires.find_one({"key": d["key"], "version": d["version"]}, {"_id": 0, "id": 1})
        if not existing:
            await db.review_questionnaires.insert_one({"id": str(uuid.uuid4()), "created_at": _now_iso(), **d})
    for pb in EXTRA_PLAYBOOKS:
        existing = await db.review_playbooks.find_one({"key": pb["key"], "version": pb["version"]}, {"_id": 0, "id": 1})
        if not existing:
            await db.review_playbooks.insert_one({"id": str(uuid.uuid4()), "created_at": _now_iso(), **pb})
