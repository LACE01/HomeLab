"""Threat Modeling -- interactive STRIDE-based threat modeling, auto-populated
from the platform's own asset/findings data wherever possible (per the task
spec's general principle: automate and reuse existing platform data rather than
requiring manual re-entry).

Concepts:
  db.threat_models          one doc per model: name/description + the DFD
                            (elements[] + flows[]) saved as embedded arrays --
                            the diagram is one logical object, saved atomically
                            from the canvas.
  db.threat_model_threats   one doc per threat: linked to an element (or flow),
                            STRIDE category, optional parent_threat_id (that's
                            the attack tree -- a threat's children are the
                            sub-goals/steps an attacker chains to reach it),
                            DREAD scores, 5x5 likelihood/impact + band,
                            mitigations[], linked_finding_ids.

DFD element types and which STRIDE categories genuinely apply to each (the
classic per-element applicability matrix -- suggesting all six for everything
teaches people to rubber-stamp; suggesting the right subset teaches the model):
  process          S T R I D E   (full exposure -- code that runs)
  datastore          T R I D     (stores can't be "spoofed" in the STRIDE sense;
                                  R applies via log stores)
  external         S R           (you can't control an external entity's
                                  tampering/info-disclosure -- you control what
                                  you accept from it and whether you can prove
                                  what it did)
  flow               T   I D     (data in motion: tamper, sniff, sever)
  boundary         (none -- boundaries organize the diagram; threats live on
                    what crosses them)

Auto-population:
  bootstrap_model_from_assets() builds a starter DFD from the asset inventory
  (internet-facing assets in an "Internet" trust context, everything else
  grouped by owner team) and drafts threats from open findings on those assets
  (CWE -> STRIDE category mapping below, severity -> impact, KEV -> likelihood
  bump). Every auto-drafted threat carries source="auto" + the finding link so
  an analyst can verify the chain end-to-end.
"""
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

STRIDE = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
          "Denial of Service", "Elevation of Privilege"]

ELEMENT_TYPES = ["process", "datastore", "external", "boundary"]

STRIDE_BY_ELEMENT = {
    "process": STRIDE,
    "datastore": ["Tampering", "Repudiation", "Information Disclosure", "Denial of Service"],
    "external": ["Spoofing", "Repudiation"],
    "flow": ["Tampering", "Information Disclosure", "Denial of Service"],
    "boundary": [],
}

# Per-category boilerplate examples, instantiated with the element name so the
# "add threat" flow starts from something concrete instead of a blank box.
STRIDE_EXAMPLES = {
    "Spoofing": "An attacker impersonates {name} (stolen credentials, forged tokens, DNS/ARP tricks) to gain its access.",
    "Tampering": "Data handled by {name} is modified in transit or at rest (parameter tampering, injected content, direct DB writes).",
    "Repudiation": "Actions taken via {name} can't be attributed afterwards -- logs missing, unsigned, or mutable.",
    "Information Disclosure": "Sensitive data in {name} is exposed to parties who shouldn't see it (sniffing, over-broad permissions, verbose errors, backups).",
    "Denial of Service": "{name} is made unavailable (resource exhaustion, crash-loop input, dependency outage).",
    "Elevation of Privilege": "A low-privilege actor uses {name} to gain higher privileges (missing authz checks, injection to code execution, confused deputy).",
}

# CWE -> STRIDE mapping for auto-drafting threats from findings. Deliberately
# coarse -- a finding's CWE tells you the WEAKNESS class, which maps naturally
# onto the STRIDE category an exploit of it would realize.
CWE_TO_STRIDE = {
    # Spoofing: broken/missing authentication
    "CWE-287": "Spoofing", "CWE-290": "Spoofing", "CWE-294": "Spoofing",
    "CWE-306": "Spoofing", "CWE-798": "Spoofing", "CWE-521": "Spoofing",
    # Tampering: injection / integrity
    "CWE-79": "Tampering", "CWE-89": "Tampering", "CWE-78": "Tampering",
    "CWE-502": "Tampering", "CWE-434": "Tampering", "CWE-494": "Tampering",
    "CWE-352": "Tampering",
    # Repudiation: logging gaps
    "CWE-778": "Repudiation", "CWE-117": "Repudiation",
    # Information Disclosure
    "CWE-200": "Information Disclosure", "CWE-209": "Information Disclosure",
    "CWE-311": "Information Disclosure", "CWE-319": "Information Disclosure",
    "CWE-312": "Information Disclosure", "CWE-522": "Information Disclosure",
    # Denial of Service
    "CWE-400": "Denial of Service", "CWE-770": "Denial of Service",
    "CWE-835": "Denial of Service",
    # Elevation of Privilege
    "CWE-269": "Elevation of Privilege", "CWE-250": "Elevation of Privilege",
    "CWE-862": "Elevation of Privilege", "CWE-863": "Elevation of Privilege",
    "CWE-284": "Elevation of Privilege", "CWE-94": "Elevation of Privilege",
    "CWE-787": "Elevation of Privilege", "CWE-416": "Elevation of Privilege",
}

SEVERITY_TO_IMPACT = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def risk_band(likelihood: int, impact: int) -> str:
    score = max(1, min(5, likelihood or 1)) * max(1, min(5, impact or 1))
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 16:
        return "High"
    return "Critical"


def dread_score(d: dict) -> Optional[float]:
    """Classic DREAD: mean of the five 1-10 components. None until all five set."""
    keys = ("damage", "reproducibility", "exploitability", "affected_users", "discoverability")
    vals = [d.get(k) for k in keys]
    if any(v is None for v in vals):
        return None
    return round(sum(max(1, min(10, int(v))) for v in vals) / 5, 1)


def dread_to_5x5(d: dict) -> Optional[dict]:
    """Suggested 5x5 placement from DREAD: likelihood from how easy/repeatable/
    findable the attack is (R, E, D), impact from how bad it lands (Da, A).
    A suggestion for the analyst -- never auto-applied."""
    if dread_score(d) is None:
        return None
    likelihood = round((d["reproducibility"] + d["exploitability"] + d["discoverability"]) / 3 / 2)
    impact = round((d["damage"] + d["affected_users"]) / 2 / 2)
    likelihood = max(1, min(5, likelihood))
    impact = max(1, min(5, impact))
    return {"likelihood": likelihood, "impact": impact, "band": risk_band(likelihood, impact)}


def new_threat_doc(model_id: str, *, element_id: Optional[str], stride: str, title: str,
                    description: str = "", parent_threat_id: Optional[str] = None,
                    likelihood: int = 3, impact: int = 3, source: str = "manual",
                    linked_finding_ids: Optional[list] = None, created_by: str = "") -> dict:
    return {
        "id": str(uuid.uuid4()), "model_id": model_id, "element_id": element_id,
        "stride": stride, "title": title, "description": description,
        "parent_threat_id": parent_threat_id,
        "dread": {"damage": None, "reproducibility": None, "exploitability": None,
                   "affected_users": None, "discoverability": None},
        "dread_score": None,
        "likelihood": likelihood, "impact": impact, "band": risk_band(likelihood, impact),
        "status": "open", "mitigations": [],
        "linked_finding_ids": linked_finding_ids or [], "source": source,
        "created_by": created_by, "created_at": _now_iso(), "updated_at": _now_iso(),
    }


async def bootstrap_model_from_assets(db, *, name: str, owner_team: Optional[str] = None,
                                       created_by: str = "") -> dict:
    """Build a starter model from live platform data:
    - one 'Internet' external entity,
    - internet-facing assets as processes inside a DMZ boundary, with flows
      from the Internet,
    - remaining assets grouped by owner team as processes in per-team
      boundaries,
    - one auto-drafted threat per (asset, STRIDE category) pair that open
      findings on that asset map onto -- each carrying its finding links.
    Capped to keep the canvas usable (30 assets); the analyst adds detail from
    there rather than drowning in a 500-node hairball."""
    flt: dict = {}
    if owner_team:
        flt["owner_team"] = owner_team
    assets = await db.assets.find(flt, {"_id": 0, "id": 1, "hostname": 1, "os": 1,
                                          "criticality": 1, "owner_team": 1, "internet_facing": 1}).to_list(500)
    # highest-signal first: internet-facing, then criticality
    crit_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    assets.sort(key=lambda a: (not a.get("internet_facing"), crit_rank.get(a.get("criticality"), 4)))
    assets = assets[:30]

    elements, flows = [], []
    internet_id = str(uuid.uuid4())
    elements.append({"id": internet_id, "type": "external", "name": "Internet", "x": 60, "y": 60, "asset_id": None})

    inet_assets = [a for a in assets if a.get("internet_facing")]
    other_assets = [a for a in assets if not a.get("internet_facing")]

    if inet_assets:
        elements.append({"id": str(uuid.uuid4()), "type": "boundary", "name": "Internet-facing (DMZ)",
                          "x": 220, "y": 30, "w": 340, "h": 60 + 90 * ((len(inet_assets) + 2) // 3), "asset_id": None})
    for i, a in enumerate(inet_assets):
        el_id = str(uuid.uuid4())
        elements.append({"id": el_id, "type": "process", "name": a["hostname"], "asset_id": a["id"],
                          "x": 250 + (i % 3) * 110, "y": 70 + (i // 3) * 90})
        flows.append({"id": str(uuid.uuid4()), "from_id": internet_id, "to_id": el_id, "label": "inbound"})

    teams: dict = {}
    for a in other_assets:
        teams.setdefault(a.get("owner_team") or "Unassigned", []).append(a)
    y_base = 60 + (90 * ((len(inet_assets) + 2) // 3) + 80 if inet_assets else 0)
    for t_idx, (team, team_assets) in enumerate(sorted(teams.items())):
        rows = (len(team_assets) + 2) // 3
        elements.append({"id": str(uuid.uuid4()), "type": "boundary", "name": f"{team} network",
                          "x": 220, "y": y_base - 30, "w": 340, "h": 60 + 90 * rows, "asset_id": None})
        for i, a in enumerate(team_assets):
            elements.append({"id": str(uuid.uuid4()), "type": "process", "name": a["hostname"],
                              "asset_id": a["id"], "x": 250 + (i % 3) * 110, "y": y_base + (i // 3) * 90})
        y_base += 60 + 90 * rows + 50

    model = {
        "id": str(uuid.uuid4()), "name": name,
        "description": f"Bootstrapped from asset inventory ({len(assets)} asset(s)"
                       + (f", team {owner_team}" if owner_team else "") + ") -- source-tagged auto threats "
                       "drafted from open findings; refine from here.",
        "elements": elements, "flows": flows,
        "created_by": created_by, "created_at": _now_iso(), "updated_at": _now_iso(),
    }
    await db.threat_models.insert_one(dict(model))

    # Auto-draft threats from open findings, grouped per (asset element, STRIDE)
    el_by_asset = {e["asset_id"]: e for e in elements if e.get("asset_id")}
    threats_created = 0
    if el_by_asset:
        findings = await db.findings.find(
            {"asset_id": {"$in": list(el_by_asset.keys())}, "status": {"$in": OPEN_STATES}},
            {"_id": 0, "id": 1, "asset_id": 1, "cwe": 1, "severity": 1, "title": 1, "kev_flag": 1},
        ).to_list(3000)
        grouped: dict = {}
        for f in findings:
            stride = CWE_TO_STRIDE.get((f.get("cwe") or "").strip())
            if not stride:
                # no CWE signal -- a Critical/High finding still evidences EoP risk
                if f.get("severity") in ("Critical", "High"):
                    stride = "Elevation of Privilege"
                else:
                    continue
            key = (f["asset_id"], stride)
            grouped.setdefault(key, []).append(f)
        for (asset_id, stride), fs in grouped.items():
            el = el_by_asset[asset_id]
            worst = max(fs, key=lambda f: SEVERITY_TO_IMPACT.get(f.get("severity"), 0))
            impact = SEVERITY_TO_IMPACT.get(worst.get("severity"), 3)
            likelihood = 4 if any(f.get("kev_flag") for f in fs) else 3
            doc = new_threat_doc(
                model["id"], element_id=el["id"], stride=stride,
                title=f"{stride} via open findings on {el['name']}",
                description=f"{len(fs)} open finding(s) on {el['name']} map to {stride} "
                            f"(worst: [{worst.get('severity')}] {worst.get('title')})."
                            + (" At least one is on the CISA KEV list (actively exploited)." if likelihood >= 4 else ""),
                likelihood=likelihood, impact=impact, source="auto",
                linked_finding_ids=[f["id"] for f in fs][:20], created_by=created_by,
            )
            await db.threat_model_threats.insert_one(dict(doc))
            threats_created += 1

    model["auto_threats_created"] = threats_created
    return {k: v for k, v in model.items() if k != "_id"}
