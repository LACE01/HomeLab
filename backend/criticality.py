"""Rule-based, admin-adjustable asset criticality scoring.

Asset criticality used to be a single manual field, set once at creation (usually
defaulting to "medium" via the Nmap/Nikto/EASM import pipelines) and never revisited --
so a database server discovered by Nmap scored identically to a dev sandbox unless
someone remembered to go fix it by hand. This engine derives criticality from what's
actually detected running on the host (open ports/services, exposure, environment,
tags, asset type) instead, using a set of scoring rules that are fully editable in the
UI -- every org's definition of "crown jewel" is different (a hospital and a fintech
won't agree on which ports matter), so the rule set here is a reasonable starting
point, not a fixed policy.

Score = sum of points from every enabled rule whose condition matches the asset. The
resulting score is mapped to a tier via admin-adjustable thresholds (crown_jewel >
critical > high > medium > low, first one whose threshold the score clears wins).

An asset can be locked to a manual criticality at any time (criticality_locked=True) --
recompute_asset_criticality then leaves it alone until unlocked, so "we know this one
is special for a reason none of the rules capture" always wins over the scoring.
"""
import uuid
from datetime import datetime, timezone

TIERS = ["crown_jewel", "critical", "high", "medium", "low"]

FIELD_META = {
    "port": {"label": "Open port", "match_kind": "port", "placeholder": "e.g. 3389, 1433, 6443"},
    "service": {"label": "Detected service name contains", "match_kind": "text_multi", "placeholder": "e.g. mysql, rdp"},
    "product": {"label": "Detected product/banner contains", "match_kind": "text_multi", "placeholder": "e.g. MongoDB, Jenkins"},
    "hostname": {"label": "Hostname/FQDN contains", "match_kind": "text_single", "placeholder": "e.g. prod, payroll"},
    "os": {"label": "OS/platform contains", "match_kind": "text_single", "placeholder": "e.g. Windows Server"},
    "tag": {"label": "Tag is", "match_kind": "exact_multi", "placeholder": "e.g. crown-jewel, pci"},
    "asset_type": {"label": "Asset type is", "match_kind": "exact_single", "placeholder": "e.g. web_application"},
    "exposure": {"label": "Exposure is", "match_kind": "exact_single", "placeholder": "e.g. internet"},
    "environment": {"label": "Environment is", "match_kind": "exact_single", "placeholder": "e.g. production"},
}

DEFAULT_THRESHOLDS = {"crown_jewel": 70, "critical": 45, "high": 25, "medium": 10}


def _default_rules(now_iso_str: str) -> list:
    def r(name, field, values, points):
        return {"id": str(uuid.uuid4()), "name": name, "enabled": True, "field": field,
                "values": values, "points": points, "created_at": now_iso_str}
    return [
        r("Database / data-store ports", "port", ["1433", "3306", "5432", "27017", "6379", "9200", "5984", "9042"], 20),
        r("Domain controller / directory services", "port", ["88", "389", "636"], 25),
        r("Kubernetes / container orchestration API", "port", ["6443", "2379", "10250"], 20),
        r("Remote admin access exposed", "port", ["3389", "5900"], 10),
        r("SSH management access", "port", ["22"], 5),
        r("Web application server", "port", ["80", "443", "8080", "8443"], 5),
        r("Internet-facing exposure", "exposure", ["internet", "external"], 15),
        r("Production environment", "environment", ["production"], 10),
        r("Crown-jewel / compliance tag", "tag", ["crown-jewel", "crown_jewel", "pci", "hipaa", "critical"], 30),
        r("Web application asset (Nikto-discovered)", "asset_type", ["web_application"], 5),
    ]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _values_lower(rule: dict) -> list:
    return [str(v).strip().lower() for v in (rule.get("values") or []) if str(v).strip()]


def _rule_matches(asset: dict, rule: dict) -> bool:
    field = rule.get("field")
    values = _values_lower(rule)
    if not values:
        return False
    meta = FIELD_META.get(field)
    if not meta:
        return False
    kind = meta["match_kind"]

    if kind == "port":
        open_ports = asset.get("open_ports") or []
        asset_ports = {str(p.get("port")) for p in open_ports if p.get("port") is not None}
        return bool(asset_ports & set(values))

    if kind == "text_multi":
        # service / product -- substring match against any open port's field
        open_ports = asset.get("open_ports") or []
        haystacks = [(p.get(field) or "").lower() for p in open_ports]
        return any(v in h for v in values for h in haystacks if h)

    if kind == "text_single":
        if field == "hostname":
            haystack = f"{asset.get('hostname') or ''} {asset.get('fqdn') or ''}".lower()
        else:  # os
            haystack = f"{asset.get('operating_system') or ''} {asset.get('detected_os') or ''} {asset.get('platform') or ''}".lower()
        return any(v in haystack for v in values)

    if kind == "exact_multi":
        asset_values = {str(t).strip().lower() for t in (asset.get("tags") or [])}
        return bool(asset_values & set(values))

    if kind == "exact_single":
        current = str(asset.get(field) or "").strip().lower()
        return current in values

    return False


def compute_score(asset: dict, rules: list) -> tuple:
    """Returns (score:int, matched:[{rule_id, name, points}])."""
    score = 0
    matched = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if _rule_matches(asset, rule):
            score += rule.get("points", 0)
            matched.append({"rule_id": rule.get("id"), "name": rule.get("name"), "points": rule.get("points", 0)})
    return score, matched


def tier_for_score(score: int, thresholds: dict) -> str:
    for tier in ("crown_jewel", "critical", "high", "medium"):
        if score >= thresholds.get(tier, DEFAULT_THRESHOLDS[tier]):
            return tier
    return "low"


async def recompute_asset_criticality(db, asset_id: str) -> dict:
    """Recomputes and persists criticality for one asset unless it's manually locked.
    Safe to call opportunistically after any import that touched this asset's ports/
    exposure/tags -- it's a handful of in-memory comparisons, no network calls."""
    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    if not asset:
        return {"skipped": True, "reason": "asset not found"}
    if asset.get("criticality_locked"):
        return {"skipped": True, "reason": "manually locked"}

    rules = await db.criticality_rules.find({}, {"_id": 0}).to_list(500)
    thresholds_doc = await db.criticality_config.find_one({}, {"_id": 0})
    thresholds = (thresholds_doc or {}).get("thresholds") or DEFAULT_THRESHOLDS

    score, matched = compute_score(asset, rules)
    tier = tier_for_score(score, thresholds)
    prev_tier = asset.get("criticality")

    update = {
        "criticality": tier, "criticality_score": score,
        "criticality_rationale": matched, "criticality_computed_at": _now_iso(),
    }
    await db.assets.update_one({"id": asset_id}, {"$set": update})
    return {"skipped": False, "criticality": tier, "score": score, "matched": matched, "changed": prev_tier != tier}


async def recompute_all(db) -> dict:
    """Bulk recompute for every non-locked asset -- used by the manual 'Recompute all'
    admin action and safe to run any time (idempotent, no side effects beyond the
    assets collection itself)."""
    checked = changed = skipped_locked = 0
    async for asset in db.assets.find({}, {"_id": 0, "id": 1, "criticality_locked": 1}):
        checked += 1
        if asset.get("criticality_locked"):
            skipped_locked += 1
            continue
        result = await recompute_asset_criticality(db, asset["id"])
        if result.get("changed"):
            changed += 1
    return {"checked": checked, "changed": changed, "skipped_locked": skipped_locked}
