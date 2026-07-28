"""Security Reviews -- a guided, playbook-driven investigation/case-management
module for "we want to buy/enable/change X -- is it secure, what's the risk?"
requests. Phase 1 scope (per the build spec this was implemented from): intake ->
guided playbook steps -> questionnaire -> manual 5x5 risk scoring -> findings/
conditions -> decision record -> print-styled executive report, with the
prior-reviews lookup as the only auto-fill hook. Playbooks and questionnaires
are versioned DB records (db.review_playbooks / db.review_questionnaires), NOT
code -- methodology changes are new version documents, and every review pins the
exact playbook_version_id/template_version_id it ran under.

Collections:
  security_reviews          one doc per review (SR-YYYY-NNN ids), embeds risk
                            scoring + decision + SLA clock fields
  security_review_steps     per-review instances of the playbook's steps
  security_review_responses per-review questionnaire answers
  security_review_findings  findings/conditions-of-approval (with the
                            promoted_to_risk_register_id linkage -- the Risk
                            Register already exists in this app, so promotion is
                            wired now rather than deferred)
  security_review_notes     timestamped internal working notes (never rendered
                            into shared reports)
  security_review_audit     every material action: status change, override, N/A,
                            decision, evidence upload -- actor + timestamp
  reviewed_entities         vendor/system/product catalog: current rating, last
                            review, next review date, certifications
  review_playbooks          versioned playbook documents (seeded below)
  review_questionnaires     versioned questionnaire templates (seeded below)

Immutability: once a review's status is "Closed", every mutating endpoint in
routes/security_reviews.py refuses with 409 -- the review is the audit package.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

REVIEW_TYPES = [
    "New software purchase (SaaS / COTS / on-prem)",
    "New hardware",
    "Feature enablement on an existing platform",
    "New integration / API connection",
    "Configuration or architecture change",
    "AI tool adoption",
    "Browser extension / plugin / script",
    "Existing system or application review",
    "Incident-driven investigation",
    "Ad-hoc investigation",
]

DATA_CLASSIFICATIONS = ["PII (Colorado)", "CJIS", "PHI / HIPAA", "PCI", "Elections data", "Public-only / none"]

REVIEW_STATUSES = [
    "Requested", "Scoped", "In Assessment", "Pending Info", "Risk Rated",
    "Report Drafted", "Decision Issued", "Closed", "In Follow-up",
]

STEP_STATUSES = ["Not started", "In progress", "Blocked", "Done", "N/A"]

DECISION_OUTCOMES = ["Approved", "Approved with Conditions", "Rejected", "Deferred — More Info Needed"]

URGENCIES = ["Low", "Normal", "High", "Critical"]

RISK_BANDS = ["Low", "Medium", "High", "Critical"]

IMPACT_DIMENSIONS = ["confidentiality", "integrity", "availability", "compliance_legal", "reputational"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def risk_band(likelihood: int, impact: int) -> str:
    """Standard 5x5 banding: score = likelihood x impact (each clamped 1-5).
    1-4 Low, 5-9 Medium, 10-16 High, 17-25 Critical."""
    score = max(1, min(5, likelihood or 1)) * max(1, min(5, impact or 1))
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 16:
        return "High"
    return "Critical"


def score_rating(likelihood: int, impacts: dict) -> dict:
    """Impact is scored per dimension (confidentiality/integrity/availability/
    compliance_legal/reputational); the MAX impact drives the rating, per spec."""
    vals = [int(impacts.get(d) or 0) for d in IMPACT_DIMENSIONS]
    max_impact = max(vals) if any(vals) else 0
    if not max_impact or not likelihood:
        return {"likelihood": likelihood, "impacts": impacts, "max_impact": max_impact,
                "score": None, "band": None}
    return {"likelihood": likelihood, "impacts": impacts, "max_impact": max_impact,
            "score": max(1, min(5, likelihood)) * max(1, min(5, max_impact)),
            "band": risk_band(likelihood, max_impact)}


async def next_review_number(db) -> str:
    year = datetime.now(timezone.utc).year
    prefix = f"SR-{year}-"
    count = await db.security_reviews.count_documents({"review_number": {"$regex": f"^{prefix}"}})
    return f"{prefix}{count + 1:03d}"


async def audit(db, review_id: str, action: str, actor: str, details: str = "") -> None:
    await db.security_review_audit.insert_one({
        "id": str(uuid.uuid4()), "review_id": review_id, "action": action,
        "actor": actor, "details": details, "at": _now_iso(),
    })


async def review_is_closed(db, review_id: str) -> bool:
    r = await db.security_reviews.find_one({"id": review_id}, {"_id": 0, "status": 1})
    return bool(r and r.get("status") == "Closed")


# =========================================================================
# SEED DATA -- SaaS / Software Acquisition playbook v1 + questionnaire v1.
# Stored as DB documents on first boot (idempotent by (key, version)); edits to
# methodology should be NEW version documents, not edits to these dicts.
# =========================================================================

SAAS_PLAYBOOK_V1 = {
    "key": "saas_acquisition",
    "name": "SaaS / Software Acquisition",
    "version": 1,
    "review_types": ["New software purchase (SaaS / COTS / on-prem)"],
    "steps": [
        {"order": 1, "step_type": "task", "autofill_hook": None, "conditional_on": None, "allows_na": False,
         "title": "Validate the request",
         "guidance": "Confirm scope with the requestor before doing anything else. Get: vendor name, product name and URL, what business problem it solves, which departments/users will use it, what data will be put into it (ask for a sample or field list), and how it will be accessed (browser, installed client, agent, API). If the answer to 'what data goes in it' is vague, stop and get specifics — the data classification drives the entire review.",
         "expected_output": "Completed scope statement field."},
        {"order": 2, "step_type": "task", "autofill_hook": None, "conditional_on": None, "allows_na": False,
         "title": "Classify the data",
         "guidance": "Select every classification that applies based on the actual data going into the system, not what the vendor markets it for. When in doubt, classify up. This selection unlocks additional required steps and sign-offs.",
         "expected_output": "Data classifications selected on the review."},
        {"order": 3, "step_type": "auto-fill", "autofill_hook": "prior_reviews_lookup", "conditional_on": None, "allows_na": False,
         "title": "Check internal precedent",
         "guidance": "Review any prior evaluations of this vendor or product. Check whether prior conditions were actually met. If a valid, unexpired approval exists for the same use case and data scope, consider the lightweight re-validation path instead of a full review.",
         "expected_output": "Prior-review panel reviewed; note added confirming precedent status."},
        {"order": 4, "step_type": "auto-fill", "autofill_hook": "osint_compromise_pull", "conditional_on": None, "allows_na": False,
         "title": "Vendor exposure check",
         "guidance": "Review OSINT/compromise-monitoring hits for the vendor's domain(s). For each hit, mark relevant or not relevant with a one-line note. A hit is not automatically disqualifying — what matters is the vendor's response history and whether the exposure type intersects with our intended use.",
         "expected_output": "Each hit dispositioned; relevant hits attached as evidence."},
        {"order": 5, "step_type": "task", "autofill_hook": None, "conditional_on": None, "allows_na": False,
         "title": "External posture check",
         "guidance": "Check: (a) public breach history for the vendor; (b) known CVEs against the product and how quickly the vendor patched; (c) TLS/security headers on the vendor's login and app endpoints; (d) request current SOC 2 Type II or ISO 27001 certificate and note the expiration date; (e) review the vendor's trust/security page and subprocessor list. Attach findings as evidence with links.",
         "expected_output": "Evidence attached; SOC 2/ISO status and expiration recorded on the vendor entity."},
        {"order": 6, "step_type": "task", "autofill_hook": None, "conditional_on": None, "allows_na": False,
         "title": "Send vendor questionnaire",
         "guidance": "Compile and send the vendor-facing question set. Record the date sent. The SLA clock pauses while awaiting the vendor (set the review to Pending Info). Chase at 10 business days.",
         "expected_output": "Sent date recorded; responses attached on receipt."},
        {"order": 7, "step_type": "auto-fill", "autofill_hook": "asset_inventory_check", "conditional_on": "internal_assets_in_scope", "allows_na": True,
         "title": "Internal environment check",
         "guidance": "Review the current state of any internal assets this product will touch. Note whether the environment it lands in is itself healthy — open criticals or blown SLAs on a host that will run this vendor's agent belong in the risk picture.",
         "expected_output": "Environment-state note; any environment findings drafted."},
        {"order": 8, "step_type": "auto-fill", "autofill_hook": "governance_crosswalk", "conditional_on": "classification", "allows_na": True,
         "title": "Compliance crosswalk",
         "guidance": "Confirm each applicable requirement is addressed or open a finding. CJIS: security addendum, personnel screening, data location. HIPAA/PHI: BAA executed before go-live. PCI: does this change cardholder-data scope. Colorado PII: notification and safeguard obligations. Elections data: elections security standard applies.",
         "expected_output": "Each crosswalk item confirmed or converted to a finding."},
        {"order": 9, "step_type": "questionnaire-block", "autofill_hook": None, "conditional_on": None, "allows_na": False,
         "title": "Complete internal questionnaire",
         "guidance": "Answer all remaining internal questions using vendor responses and evidence gathered. Override any auto-answered item that doesn't match reality, with a note.",
         "expected_output": "Questionnaire 100% answered or N/A'd with reasons."},
        {"order": 10, "step_type": "decision", "autofill_hook": None, "conditional_on": None, "allows_na": False,
         "title": "Score the risk",
         "guidance": "Score inherent risk of adopting as-is across confidentiality, integrity, availability, compliance/legal, and reputational impact — the max drives the rating. Then document compensating controls (SSO/MFA enforcement, segmentation, DLP, contract terms, data minimization) and score residual risk assuming those controls are implemented. Optionally score the risk of NOT adopting if this replaces something worse. If your final rating differs from the suggested rating, justify the override.",
         "expected_output": "Inherent + residual ratings set with justification."},
        {"order": 11, "step_type": "task", "autofill_hook": None, "conditional_on": None, "allows_na": False,
         "title": "Draft findings and conditions",
         "guidance": "Review pre-drafted findings from No/Partial answers. Keep only what's real. Convert must-fix items into conditions of approval with owners and deadlines. Every condition needs a way to verify it was met.",
         "expected_output": "Final findings list; conditions flagged with deadlines."},
        {"order": 12, "step_type": "task", "autofill_hook": None, "conditional_on": None, "allows_na": False,
         "title": "Generate report and route for decision",
         "guidance": "Generate the executive summary and technical appendix. Sanity-check the plain-English summary reads correctly to a non-technical audience. Record the decision, decision maker, rationale, and expiration. If Approved with Conditions, confirm the requestor acknowledges the conditions.",
         "expected_output": "Report generated; decision recorded."},
        {"order": 13, "step_type": "task", "autofill_hook": None, "conditional_on": None, "allows_na": False,
         "title": "Close and schedule re-review",
         "guidance": "Set the re-review date based on residual risk tier. Verify all evidence is attached — the review becomes the audit package for this acquisition. Close the review; evidence locks on close.",
         "expected_output": "Review closed; next_review_date set on the vendor entity."},
    ],
}

# Questions: [CIS v8 safeguard] (risk weight 1-5, 5 = most severe if No)
# (vendor_facing) (conditional_on data classification, or None)
SAAS_QUESTIONNAIRE_V1 = {
    "key": "saas_acquisition_internal",
    "name": "Internal Questionnaire — SaaS Acquisition",
    "version": 1,
    "questions": [
        # Identity & Access
        {"order": 1, "domain": "Identity & Access", "cis_mapping": "6.7", "risk_weight": 4, "vendor_facing": True, "conditional_on": None,
         "text": "Does the product support SSO via our identity provider (SAML/OIDC)?"},
        {"order": 2, "domain": "Identity & Access", "cis_mapping": "6.5", "risk_weight": 5, "vendor_facing": True, "conditional_on": None,
         "text": "Can MFA be enforced for all users, including admins?"},
        {"order": 3, "domain": "Identity & Access", "cis_mapping": "6.8", "risk_weight": 3, "vendor_facing": True, "conditional_on": None,
         "text": "Does it support role-based access control granular enough for least privilege?"},
        {"order": 4, "domain": "Identity & Access", "cis_mapping": "6.2", "risk_weight": 3, "vendor_facing": True, "conditional_on": None,
         "text": "Can we automatically deprovision users (SCIM or directory sync)?"},
        {"order": 5, "domain": "Identity & Access", "cis_mapping": "6.1", "risk_weight": 3, "vendor_facing": True, "conditional_on": None,
         "text": "Are vendor-side admin/support accesses to our tenant logged and disclosed?"},
        # Data Protection
        {"order": 6, "domain": "Data Protection", "cis_mapping": "3.10, 3.11", "risk_weight": 5, "vendor_facing": True, "conditional_on": None,
         "text": "Is data encrypted in transit (TLS 1.2+) and at rest?"},
        {"order": 7, "domain": "Data Protection", "cis_mapping": "3.1", "risk_weight": 4, "vendor_facing": True, "conditional_on": None,
         "text": "Where is data stored geographically, and can storage be restricted to the U.S.?"},
        {"order": 8, "domain": "Data Protection", "cis_mapping": "3.1", "risk_weight": 3, "vendor_facing": True, "conditional_on": None,
         "text": "Can we export all our data in a usable format at any time?"},
        {"order": 9, "domain": "Data Protection", "cis_mapping": "3.5", "risk_weight": 4, "vendor_facing": True, "conditional_on": None,
         "text": "Is our data deleted on contract termination, with written confirmation?"},
        {"order": 10, "domain": "Data Protection", "cis_mapping": "3.3", "risk_weight": 5, "vendor_facing": True, "conditional_on": None,
         "text": "Is customer data used for vendor analytics, model training, or shared with third parties?"},
        {"order": 11, "domain": "Data Protection", "cis_mapping": "15.4", "risk_weight": 3, "vendor_facing": True, "conditional_on": None,
         "text": "Does the vendor maintain a current subprocessor list and notify on changes?"},
        # Network & Attack Surface
        {"order": 12, "domain": "Network & Attack Surface", "cis_mapping": "12.2", "risk_weight": 4, "vendor_facing": False, "conditional_on": None,
         "text": "Does adoption create new inbound connections, open ports, or internet-facing services on our network?"},
        {"order": 13, "domain": "Network & Attack Surface", "cis_mapping": "4.1", "risk_weight": 4, "vendor_facing": True, "conditional_on": None,
         "text": "Does the product require an installed agent or client, and what privileges does it run with?"},
        {"order": 14, "domain": "Network & Attack Surface", "cis_mapping": "12.2", "risk_weight": 3, "vendor_facing": False, "conditional_on": None,
         "text": "Are integrations/API connections to our existing systems required, and are they scoped read-only where possible?"},
        # Logging & Monitoring
        {"order": 15, "domain": "Logging & Monitoring", "cis_mapping": "8.2, 8.9", "risk_weight": 3, "vendor_facing": True, "conditional_on": None,
         "text": "Are audit logs available for user and admin activity, exportable to our SIEM?"},
        {"order": 16, "domain": "Logging & Monitoring", "cis_mapping": "8.10", "risk_weight": 2, "vendor_facing": True, "conditional_on": None,
         "text": "What is the log retention period, and is it at least 12 months?"},
        # Vendor Security Program
        {"order": 17, "domain": "Vendor Security Program", "cis_mapping": "15.5", "risk_weight": 4, "vendor_facing": True, "conditional_on": None,
         "text": "Does the vendor hold a current SOC 2 Type II or ISO 27001 certification?"},
        {"order": 18, "domain": "Vendor Security Program", "cis_mapping": "7.1", "risk_weight": 3, "vendor_facing": True, "conditional_on": None,
         "text": "Does the vendor have a documented vulnerability management and patching program with SLAs?"},
        {"order": 19, "domain": "Vendor Security Program", "cis_mapping": "17.1", "risk_weight": 4, "vendor_facing": True, "conditional_on": None,
         "text": "Does the vendor have a documented incident response plan and a customer breach-notification commitment with a defined timeframe?"},
        {"order": 20, "domain": "Vendor Security Program", "cis_mapping": "15.5", "risk_weight": 3, "vendor_facing": False, "conditional_on": None,
         "text": "Has the vendor had a public breach in the last 3 years? If so, how was it handled?"},
        # Resilience
        {"order": 21, "domain": "Resilience", "cis_mapping": "11.1", "risk_weight": 2, "vendor_facing": True, "conditional_on": None,
         "text": "What are the vendor's uptime SLA and published DR/backup capabilities (RTO/RPO)?"},
        {"order": 22, "domain": "Resilience", "cis_mapping": "11.1", "risk_weight": 3, "vendor_facing": False, "conditional_on": None,
         "text": "If this vendor is unavailable for 72 hours, is a critical county function blocked?"},
        # Compliance (conditional)
        {"order": 23, "domain": "Compliance", "cis_mapping": "regulatory", "risk_weight": 5, "vendor_facing": True, "conditional_on": "CJIS",
         "text": "(CJIS) Will the vendor sign the CJIS Security Addendum, and does it meet CJIS personnel and data-location requirements?"},
        {"order": 24, "domain": "Compliance", "cis_mapping": "regulatory", "risk_weight": 5, "vendor_facing": True, "conditional_on": "PHI / HIPAA",
         "text": "(PHI) Will the vendor execute a BAA before go-live?"},
        {"order": 25, "domain": "Compliance", "cis_mapping": "regulatory", "risk_weight": 4, "vendor_facing": False, "conditional_on": "PCI",
         "text": "(PCI) Does this product store, process, or transmit cardholder data or change PCI scope?"},
        {"order": 26, "domain": "Compliance", "cis_mapping": "regulatory", "risk_weight": 5, "vendor_facing": False, "conditional_on": "Elections data",
         "text": "(Elections) Does this product touch elections systems or data, triggering the elections security standard?"},
        {"order": 27, "domain": "Compliance", "cis_mapping": "policy", "risk_weight": 4, "vendor_facing": True, "conditional_on": None,
         "text": "(AI features) If the product includes AI features: is our data used for training, can AI features be disabled, and does usage comply with the AI usage policy?"},
    ],
}


async def ensure_seeded(db) -> None:
    """Idempotently seed the v1 playbook + questionnaire as versioned DB records."""
    for coll, doc in ((db.review_playbooks, SAAS_PLAYBOOK_V1), (db.review_questionnaires, SAAS_QUESTIONNAIRE_V1)):
        existing = await coll.find_one({"key": doc["key"], "version": doc["version"]}, {"_id": 0, "id": 1})
        if not existing:
            await coll.insert_one({"id": str(uuid.uuid4()), "created_at": _now_iso(), **doc})


async def latest_playbook_for_type(db, review_type: str) -> Optional[dict]:
    """Highest-version playbook whose review_types covers this type, falling back
    to the SaaS playbook (Phase 1 only ships one) so every review gets a guided
    checklist rather than an empty workspace."""
    docs = await db.review_playbooks.find(
        {"review_types": review_type}, {"_id": 0}).sort("version", -1).to_list(5)
    if docs:
        return docs[0]
    docs = await db.review_playbooks.find(
        {"key": "saas_acquisition"}, {"_id": 0}).sort("version", -1).to_list(1)
    return docs[0] if docs else None


async def latest_questionnaire(db, key: str = "saas_acquisition_internal") -> Optional[dict]:
    docs = await db.review_questionnaires.find({"key": key}, {"_id": 0}).sort("version", -1).to_list(1)
    return docs[0] if docs else None


async def instantiate_steps(db, review: dict, playbook: dict) -> int:
    """Create per-review step instances from the playbook definition. Conditional
    steps still get instances (an analyst can always N/A them); the conditional_on
    tag is carried through so the UI can visually mark why a step applies."""
    created = 0
    for step in playbook.get("steps", []):
        await db.security_review_steps.insert_one({
            "id": str(uuid.uuid4()), "review_id": review["id"], "order": step["order"],
            "title": step["title"], "guidance": step["guidance"],
            "expected_output": step.get("expected_output"), "step_type": step.get("step_type", "task"),
            "autofill_hook": step.get("autofill_hook"), "conditional_on": step.get("conditional_on"),
            "allows_na": step.get("allows_na", False),
            "status": "Not started", "na_reason": None, "blocked_on": None, "blocked_date": None,
            "notes": "", "evidence": [], "completed_by": None, "completed_at": None,
        })
        created += 1
    return created


async def upsert_reviewed_entity(db, *, name: str, entity_type: str = "vendor",
                                  domain: Optional[str] = None) -> dict:
    """Find-or-create in the reviewed_entities catalog (matched case-insensitively
    by name). Returns the entity doc."""
    existing = await db.reviewed_entities.find_one(
        {"name": {"$regex": f"^{__import__('re').escape(name)}$", "$options": "i"}}, {"_id": 0})
    if existing:
        if domain and not existing.get("domain"):
            await db.reviewed_entities.update_one({"id": existing["id"]}, {"$set": {"domain": domain}})
            existing["domain"] = domain
        return existing
    doc = {
        "id": str(uuid.uuid4()), "name": name, "type": entity_type, "domain": domain,
        "current_rating": None, "last_review_id": None, "next_review_date": None,
        "certifications": [], "created_at": _now_iso(),
    }
    await db.reviewed_entities.insert_one(doc)
    return {k: v for k, v in doc.items() if k != "_id"}


async def prior_reviews_lookup(db, *, entity_name: Optional[str], domain: Optional[str],
                                exclude_review_id: Optional[str] = None) -> dict:
    """The one Phase 1 auto-fill hook: everything the platform already knows about
    this vendor/product from previous reviews -- prior ratings, decisions, unmet
    conditions, expired approvals. Also folds in the vendor-management module's
    view of the same domain (OSINT exposure count) since that data already exists."""
    import re as _re
    out = {"prior_reviews": [], "unmet_conditions": [], "expired_approvals": [],
           "entity": None, "vendor_osint_findings": 0}
    or_clauses = []
    if entity_name:
        or_clauses.append({"entity_name": {"$regex": f"^{_re.escape(entity_name)}$", "$options": "i"}})
    if domain:
        or_clauses.append({"entity_domain": {"$regex": f"^{_re.escape(domain)}$", "$options": "i"}})
    if not or_clauses:
        return out

    flt: dict = {"$or": or_clauses}
    if exclude_review_id:
        flt["id"] = {"$ne": exclude_review_id}
    priors = await db.security_reviews.find(flt, {"_id": 0}).sort("created_at", -1).to_list(20)
    now = _now_iso()
    for p in priors:
        decision = p.get("decision") or {}
        summary = {
            "id": p["id"], "review_number": p.get("review_number"), "title": p.get("title"),
            "status": p.get("status"), "created_at": p.get("created_at"),
            "inherent_risk": (p.get("inherent_risk") or {}).get("band"),
            "residual_risk": (p.get("residual_risk") or {}).get("band"),
            "decision_outcome": decision.get("outcome"), "decision_date": decision.get("decision_date"),
            "decision_expiration": decision.get("expiration_date"),
        }
        out["prior_reviews"].append(summary)
        if decision.get("expiration_date") and decision["expiration_date"] < now:
            out["expired_approvals"].append(summary)
        conds = await db.security_review_findings.find(
            {"review_id": p["id"], "is_condition_of_approval": True,
             "condition_met": {"$ne": "met"}}, {"_id": 0}).to_list(50)
        for c in conds:
            out["unmet_conditions"].append({
                "review_number": p.get("review_number"), "finding_id": c["id"],
                "description": c.get("description"), "condition_deadline": c.get("condition_deadline"),
                "condition_met": c.get("condition_met"),
            })

    if entity_name:
        out["entity"] = await db.reviewed_entities.find_one(
            {"name": {"$regex": f"^{_re.escape(entity_name)}$", "$options": "i"}}, {"_id": 0})
    if domain:
        out["vendor_osint_findings"] = await db.osint_findings.count_documents({"target": domain.lower()})
    return out
