"""Adaptive, capability-gated questionnaire engine (item 28) -- Internal
Questionnaire v3.

The problem with v1/v2: one flat SaaS questionnaire asked every question of
every review, so reviewing (say) enabling RCS messaging on an existing Verizon
account produced a wall of N/As that told nobody anything, and the resulting
"score" was computed over questions that never applied.

v3 fixes that structurally:

  Section 0 -- Capability Profile. Ten yes/no flags describing WHAT THE THING IS
  (does it have user accounts, does it store our data, does it create network
  exposure, ...). Pre-seeded from the playbook type so the analyst usually just
  confirms, and always overridable.

  Modules gated by those flags. Identity & Access only appears if
  has_user_accounts. Records & Retention only if touches_records. Hardware
  lifecycle only if is_hardware. And so on -- a question that doesn't apply is
  never asked rather than being asked and N/A'd.

  Three N/A reason codes instead of one:
    na_by_design    -- genuinely doesn't apply; EXCLUDED from scoring entirely
    unknown         -- we couldn't determine it; counts against CONFIDENCE
    pending_vendor  -- awaiting the vendor; counts against confidence and ties
                       into the SLA pause
  A single undifferentiated "N/A" hid the difference between "irrelevant" and
  "we have no idea", which are opposite signals.

  Scoring over APPLICABLE questions only, plus a confidence percentage, so a
  rating reads "Residual: Low, confidence 78%, 4 unknowns" rather than implying
  a precision the evidence doesn't support.

  is_existing_platform_feature deserves special mention: when set, the review is
  scoped to the DELTA (what changes by enabling this) and the modules that would
  re-review the already-approved base platform are suppressed.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

CAPABILITY_FLAGS = [
    {"key": "has_user_accounts", "label": "Has user accounts / logins",
     "help": "Anyone signs in to it — drives the whole Identity & Access module."},
    {"key": "stores_our_data", "label": "Stores or processes our data",
     "help": "Our data lives in it or passes through it, at rest or in transit."},
    {"key": "creates_network_exposure", "label": "Creates network exposure",
     "help": "New inbound connections, open ports, internet-facing services, or tunnels."},
    {"key": "installs_software", "label": "Installs software or an agent",
     "help": "Anything that runs on our endpoints or servers, including browser extensions."},
    {"key": "is_comms_channel", "label": "Is a communications channel",
     "help": "Messaging, email, voice, SMS/RCS, conferencing — anything carrying conversations."},
    {"key": "is_hardware", "label": "Is hardware / an appliance",
     "help": "Physical device with firmware and a lifecycle of its own."},
    {"key": "has_ai_features", "label": "Has AI / ML features",
     "help": "Model-backed features, whether that's the whole product or a bolt-on."},
    {"key": "has_vendor_relationship", "label": "Involves a third-party vendor",
     "help": "A vendor we contract with. Off for purely internal changes."},
    {"key": "touches_records", "label": "Touches official records",
     "help": "Creates or holds records subject to retention schedules or CORA/public-records requests."},
    {"key": "is_existing_platform_feature", "label": "Is a feature on an already-approved platform",
     "help": "e.g. enabling RCS on an existing carrier account. The review covers the DELTA only — "
             "the base platform isn't re-reviewed."},
]

# Per-playbook capability presets. The analyst confirms/overrides; this just
# means the common case starts correct instead of blank.
CAPABILITY_PRESETS = {
    "saas_acquisition": ["has_user_accounts", "stores_our_data", "has_vendor_relationship"],
    "hardware_acquisition": ["is_hardware", "creates_network_exposure", "has_vendor_relationship"],
    "feature_enablement": ["is_existing_platform_feature", "stores_our_data", "has_vendor_relationship"],
    "integration_api": ["stores_our_data", "creates_network_exposure", "has_vendor_relationship"],
    "config_change": ["creates_network_exposure"],
    "ai_tool": ["has_ai_features", "stores_our_data", "has_user_accounts", "has_vendor_relationship"],
    "browser_extension": ["installs_software", "stores_our_data", "has_vendor_relationship"],
}

NA_REASON_CODES = {
    "na_by_design": {
        "label": "N/A by design",
        "help": "Genuinely doesn't apply to this thing. Excluded from scoring entirely.",
        "counts_against_confidence": False,
    },
    "unknown": {
        "label": "Unknown — could not determine",
        "help": "It applies, but we couldn't establish the answer. Counts against confidence.",
        "counts_against_confidence": True,
    },
    "pending_vendor": {
        "label": "Pending — awaiting vendor",
        "help": "Sent to the vendor, no answer yet. Counts against confidence; pairs with the SLA pause.",
        "counts_against_confidence": True,
    },
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _q(order, module, gate, text, cis, weight, vendor_facing=False, classification=None):
    """gate: capability flag required for this question to apply. None = always.
    classification: additionally requires that data classification on the review."""
    return {"order": order, "domain": module, "requires_capability": gate,
            "text": text, "cis_mapping": cis, "risk_weight": weight,
            "vendor_facing": vendor_facing, "conditional_on": classification}


# ---------------------------------------------------------------------------
# The v3 question bank. Ordering is by module; `requires_capability` is what
# makes the questionnaire adaptive.
# ---------------------------------------------------------------------------
_QUESTIONS = [
    # --- Identity & Access (has_user_accounts) ---
    _q(1, "Identity & Access", "has_user_accounts",
       "Does the product support SSO via our identity provider (SAML/OIDC)?", "6.7", 4, True),
    _q(2, "Identity & Access", "has_user_accounts",
       "Can MFA be enforced for all users, including admins?", "6.5", 5, True),
    _q(3, "Identity & Access", "has_user_accounts",
       "Does it support role-based access control granular enough for least privilege?", "6.8", 3, True),
    _q(4, "Identity & Access", "has_user_accounts",
       "Can we automatically deprovision users (SCIM or directory sync)?", "6.2", 3, True),
    _q(5, "Identity & Access", "has_user_accounts",
       "Are vendor-side admin/support accesses to our tenant logged and disclosed?", "6.1", 3, True),

    # --- Data Protection (stores_our_data) ---
    _q(6, "Data Protection", "stores_our_data",
       "Is data encrypted in transit (TLS 1.2+) and at rest?", "3.10, 3.11", 5, True),
    _q(7, "Data Protection", "stores_our_data",
       "Where is data stored geographically, and can storage be restricted to the U.S.?", "3.1", 4, True),
    _q(8, "Data Protection", "stores_our_data",
       "Can we export all our data in a usable format at any time?", "3.1", 3, True),
    _q(9, "Data Protection", "stores_our_data",
       "Is our data deleted on contract termination, with written confirmation?", "3.5", 4, True),
    _q(10, "Data Protection", "stores_our_data",
        "Is customer data used for vendor analytics, model training, or shared with third parties?", "3.3", 5, True),

    # --- Network & Attack Surface (creates_network_exposure) ---
    _q(11, "Network & Attack Surface", "creates_network_exposure",
        "Does adoption create new inbound connections, open ports, or internet-facing services?", "12.2", 4),
    _q(12, "Network & Attack Surface", "creates_network_exposure",
        "Are integrations/API connections scoped read-only where possible, with rotatable credentials?", "12.2", 3),
    _q(13, "Network & Attack Surface", "creates_network_exposure",
        "Can the exposure be restricted by IP allowlist, VPN, or private connectivity?", "12.3", 3, True),

    # --- Endpoint / MDM Control (NEW -- installs_software) ---
    _q(14, "Endpoint & MDM Control", "installs_software",
        "What privileges does the installed agent/client run with, and is it least-privilege?", "4.1", 4, True),
    _q(15, "Endpoint & MDM Control", "installs_software",
        "Can we deploy, update, and remove it centrally through our MDM/endpoint management?", "4.1", 3),
    _q(16, "Endpoint & MDM Control", "installs_software",
        "Is the software code-signed, and does it auto-update from a verified source?", "2.5", 4, True),
    _q(17, "Endpoint & MDM Control", "installs_software",
        "Does it request permissions beyond what its function requires (screen capture, keyboard, all-site access)?", "2.3", 4, True),

    # --- Communications Security (NEW -- is_comms_channel) ---
    _q(18, "Communications Security", "is_comms_channel",
        "Is message content encrypted in transit, and is it end-to-end encrypted?", "3.10", 4, True),
    _q(19, "Communications Security", "is_comms_channel",
        "Can conversations be retained, exported, and searched to satisfy legal hold and records requests?", "3.1", 4, True),
    _q(20, "Communications Security", "is_comms_channel",
        "Can the channel reach external parties, and can that be restricted or monitored?", "9.2", 3),
    _q(21, "Communications Security", "is_comms_channel",
        "What metadata (numbers, participants, timestamps, location) does the carrier/vendor retain, and for how long?", "3.1", 3, True),
    _q(22, "Communications Security", "is_comms_channel",
        "Is there a phishing/impersonation risk to residents or staff from this channel (spoofable sender, unverified branding)?", "9.2", 4),

    # --- Records & Retention / CORA (NEW -- touches_records) ---
    _q(23, "Records & Retention", "touches_records",
        "Are records created here subject to our retention schedule, and can that schedule be enforced in-product?", "3.1", 4),
    _q(24, "Records & Retention", "touches_records",
        "Can we produce a complete, defensible export in response to a CORA/public-records request?", "3.1", 5),
    _q(25, "Records & Retention", "touches_records",
        "Can records be placed on legal hold, exempt from automatic deletion?", "3.1", 4, True),
    _q(26, "Records & Retention", "touches_records",
        "Is there an audit trail showing who created, altered, or deleted a record?", "8.5", 4, True),

    # --- Hardware & Firmware Lifecycle (NEW -- is_hardware) ---
    _q(27, "Hardware & Firmware Lifecycle", "is_hardware",
        "How is firmware updated, is it signed, and what is the vendor's patch cadence?", "7.3", 4, True),
    _q(28, "Hardware & Firmware Lifecycle", "is_hardware",
        "What is the published end-of-support date for this model?", "2.2", 4, True),
    _q(29, "Hardware & Firmware Lifecycle", "is_hardware",
        "Are default credentials changed/disabled, and are there undocumented accounts or backdoors known for this model?", "4.7", 5, True),
    _q(30, "Hardware & Firmware Lifecycle", "is_hardware",
        "Where does the device sit physically and on the network, and is its management interface isolated?", "12.2", 4),
    _q(31, "Hardware & Firmware Lifecycle", "is_hardware",
        "What is the secure-disposal path for the device at end of life (data sanitization)?", "3.5", 3),

    # --- Logging & Monitoring (has_user_accounts OR stores_our_data) ---
    _q(32, "Logging & Monitoring", "has_user_accounts",
        "Are audit logs available for user and admin activity, exportable to our SIEM?", "8.2, 8.9", 3, True),
    _q(33, "Logging & Monitoring", "stores_our_data",
        "What is the log retention period, and is it at least 12 months?", "8.10", 2, True),

    # --- Vendor Security Program (has_vendor_relationship) ---
    _q(34, "Vendor Security Program", "has_vendor_relationship",
        "Does the vendor hold a current SOC 2 Type II or ISO 27001 certification?", "15.5", 4, True),
    _q(35, "Vendor Security Program", "has_vendor_relationship",
        "Does the vendor have a documented vulnerability management and patching program with SLAs?", "7.1", 3, True),
    _q(36, "Vendor Security Program", "has_vendor_relationship",
        "Does the vendor have an incident response plan and a breach-notification commitment with a defined timeframe?", "17.1", 4, True),
    _q(37, "Vendor Security Program", "has_vendor_relationship",
        "Has the vendor had a public breach in the last 3 years? If so, how was it handled?", "15.5", 3),
    _q(38, "Vendor Security Program", "has_vendor_relationship",
        "Does the vendor maintain a current subprocessor list and notify on changes?", "15.4", 3, True),

    # --- Resilience (stores_our_data) ---
    _q(39, "Resilience", "stores_our_data",
        "What are the uptime SLA and published DR/backup capabilities (RTO/RPO)?", "11.1", 2, True),
    _q(40, "Resilience", None,
        "If this is unavailable for 72 hours, is a critical county function blocked?", "11.1", 3),

    # --- AI Features (has_ai_features) ---
    _q(41, "AI Features", "has_ai_features",
        "Is our data used to train the vendor's models, and is opting out contractual rather than a toggle?", "3.3", 5, True),
    _q(42, "AI Features", "has_ai_features",
        "How long are prompts and outputs retained, where, and who at the vendor can see them?", "3.1", 4, True),
    _q(43, "AI Features", "has_ai_features",
        "Can AI features be disabled entirely, and does intended use comply with the AI usage policy?", "policy", 4, True),
    _q(44, "AI Features", "has_ai_features",
        "Is there human review for consequential AI-influenced decisions?", "policy", 4),

    # --- Compliance (classification-gated, always capability-agnostic) ---
    _q(45, "Compliance", None,
        "(CJIS) Will the vendor sign the CJIS Security Addendum and meet personnel/data-location requirements?",
        "regulatory", 5, True, "CJIS"),
    _q(46, "Compliance", None,
        "(PHI) Will the vendor execute a BAA before go-live?", "regulatory", 5, True, "PHI / HIPAA"),
    _q(47, "Compliance", None,
        "(PCI) Does this store, process, or transmit cardholder data or change PCI scope?",
        "regulatory", 4, False, "PCI"),
    _q(48, "Compliance", None,
        "(Elections) Does this touch elections systems or data, triggering the elections security standard?",
        "regulatory", 5, False, "Elections data"),
    _q(49, "Compliance", None,
        "(Colorado PII) Are the statutory safeguard and breach-notification obligations addressed?",
        "regulatory", 4, False, "PII (Colorado)"),

    # --- Delta scope (is_existing_platform_feature) ---
    _q(50, "Delta Scope", "is_existing_platform_feature",
        "What NEW data flows, storage locations, or egress does enabling this create on the existing platform?",
        "12.2", 4),
    _q(51, "Delta Scope", "is_existing_platform_feature",
        "Does enabling this change the platform's existing contractual, retention, or compliance posture?",
        "15.4", 4, True),

    # --- Auto-answered from platform data (see security_reviews_hooks) ---
    {"order": 52, "domain": "Network & Attack Surface", "requires_capability": None,
     "text": "Are the in-scope internal assets free of open Critical/High vulnerabilities?",
     "cis_mapping": "7.1", "risk_weight": 4, "vendor_facing": False, "conditional_on": None,
     "auto_answer_hook": "open_findings_pull"},

    # --- Standing final question, always asked ---
    _q(99, "Review Quality", None,
       "What did this questionnaire fail to capture about this particular thing?", "n/a", 0),
]

QUESTIONNAIRE_V3 = {
    "key": "adaptive_internal",
    "name": "Internal Questionnaire (adaptive)",
    "version": 3,
    "engine": "capability_gated",
    "capability_flags": CAPABILITY_FLAGS,
    "na_reason_codes": NA_REASON_CODES,
    "questions": _QUESTIONS,
}


def default_capabilities(playbook_key: Optional[str]) -> dict:
    """Pre-seed the capability profile from the playbook type."""
    on = set(CAPABILITY_PRESETS.get(playbook_key or "", CAPABILITY_PRESETS["saas_acquisition"]))
    return {f["key"]: (f["key"] in on) for f in CAPABILITY_FLAGS}


def applicable_questions(template: dict, capabilities: dict, classifications: list) -> list:
    """The heart of the engine: which questions actually apply to THIS review.

    A question applies when its capability gate is satisfied (or it has none) AND
    its data-classification gate is satisfied (or it has none). When the review is
    scoped to a feature on an already-approved platform, the modules that would
    re-review the base platform are suppressed -- that's the RCS case: reviewing
    the delta, not re-reviewing Verizon."""
    caps = capabilities or {}
    classifications = classifications or []
    delta_only = bool(caps.get("is_existing_platform_feature"))
    # Modules whose questions interrogate the base platform rather than the delta.
    SUPPRESSED_IN_DELTA = {"Vendor Security Program", "Resilience"}

    out = []
    for q in template.get("questions", []):
        gate = q.get("requires_capability")
        if gate and not caps.get(gate):
            continue
        cond = q.get("conditional_on")
        if cond and cond not in classifications:
            continue
        if delta_only and q.get("domain") in SUPPRESSED_IN_DELTA:
            continue
        out.append(q)
    return out


def score_questionnaire(applicable: list, responses: list) -> dict:
    """Score over APPLICABLE questions only, and report confidence separately.

    weighted_bad_ratio drives suggested risk (unchanged in spirit from v2), but
    the denominator is now only the questions that actually applied and were
    actually answered. Confidence is the share of applicable weight we have a
    real answer for -- 'unknown' and 'pending_vendor' subtract from it,
    'na_by_design' is removed from the picture entirely."""
    by_order = {r["question_order"]: r for r in responses}
    total_weight = 0          # applicable, excluding na_by_design
    answered_weight = 0       # of that, actually answered yes/no/partial
    bad_weight = 0.0
    unknowns, pending, unanswered = [], [], []

    for q in applicable:
        w = q.get("risk_weight", 0) or 0
        if w == 0:
            continue  # free-text/meta questions don't score
        r = by_order.get(q["order"])
        if r and r.get("answer") == "na":
            code = r.get("na_reason_code") or "na_by_design"
            if code == "na_by_design":
                continue                      # excluded from scoring entirely
            total_weight += w
            (unknowns if code == "unknown" else pending).append(q["order"])
            continue
        total_weight += w
        if not r or not r.get("answer"):
            unanswered.append(q["order"])
            continue
        answered_weight += w
        if r["answer"] == "no":
            bad_weight += w
        elif r["answer"] == "partial":
            bad_weight += w * 0.5

    ratio = (bad_weight / answered_weight) if answered_weight else 0.0
    confidence = round(100 * answered_weight / total_weight) if total_weight else 100
    return {
        "applicable_questions": len([q for q in applicable if (q.get("risk_weight") or 0) > 0]),
        "scored_weight": total_weight,
        "answered_weight": answered_weight,
        "weighted_bad_ratio": round(ratio, 3),
        "confidence_pct": confidence,
        "unknown_count": len(unknowns),
        "pending_vendor_count": len(pending),
        "unanswered_count": len(unanswered),
        "unknown_orders": unknowns,
        "pending_orders": pending,
    }


def confidence_note(score: dict, band: Optional[str]) -> str:
    """The one-line human summary the spec asks for:
    'Residual risk: Low, confidence 78%, 4 unknowns'."""
    parts = [f"{band or 'Not scored'}", f"confidence {score['confidence_pct']}%"]
    if score["unknown_count"]:
        parts.append(f"{score['unknown_count']} unknown{'s' if score['unknown_count'] != 1 else ''}")
    if score["pending_vendor_count"]:
        parts.append(f"{score['pending_vendor_count']} pending vendor")
    if score["unanswered_count"]:
        parts.append(f"{score['unanswered_count']} unanswered")
    return ", ".join(parts)


async def ensure_v3_seeded(db) -> None:
    existing = await db.review_questionnaires.find_one(
        {"key": QUESTIONNAIRE_V3["key"], "version": 3}, {"_id": 0, "id": 1})
    if not existing:
        await db.review_questionnaires.insert_one(
            {"id": str(uuid.uuid4()), "created_at": _now_iso(), **QUESTIONNAIRE_V3})


async def custom_questions_for(db, review_id: str) -> list:
    """Per-review custom questions, numbered above the bank so they never collide
    with template orders."""
    items = await db.security_review_custom_questions.find(
        {"review_id": review_id}, {"_id": 0}).sort("order", 1).to_list(100)
    return items
