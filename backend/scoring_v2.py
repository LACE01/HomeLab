"""KRI / ZDES / BII methodology from KRI & RiskBridge papers.

KRI  = EPSS × CVSS_weight × CWE_weight        (impact-weighted risk)
ZDES = (1 − KEV) × Recency                    (zero-day exposure simulation)
BII  = (Risk / Effort) × AssetCriticality     (business impact index / patch ROI)

Plus: Critical Indicators panel + Empirical percentile (cohort-based).
"""
from datetime import datetime, timezone
import math


CRITICALITY_NUM = {"crown_jewel": 1.0, "critical": 0.85, "high": 0.65, "medium": 0.45, "low": 0.25}


def _cvss_weight(cvss: float | None) -> float:
    """Normalize CVSS to 0.5–1.5 weight band."""
    if not cvss:
        return 0.8
    return 0.5 + (min(cvss, 10.0) / 10.0)


def _recency_weight(first_seen_iso: str | None) -> float:
    if not first_seen_iso:
        return 0.5
    try:
        dt = datetime.fromisoformat(first_seen_iso.replace("Z", "+00:00"))
        days = max(0, (datetime.now(timezone.utc) - dt).days)
        # 1.0 at age 0, decays to ~0.2 over 90 days
        return max(0.2, math.exp(-days / 45))
    except Exception:
        return 0.5


def compute_kri(finding: dict, cwe_weight: float = 1.0) -> dict:
    epss = finding.get("epss_score") or 0.01
    cvss_w = _cvss_weight(finding.get("cvss_score"))
    kri = epss * cvss_w * cwe_weight
    return {
        "kri_score": round(kri, 4),
        "kri_components": {"epss": epss, "cvss_weight": round(cvss_w, 3), "cwe_weight": round(cwe_weight, 3)},
    }


def compute_zdes(finding: dict) -> dict:
    kev = 1 if finding.get("kev_flag") else 0
    recency = _recency_weight(finding.get("first_seen_at"))
    cvss_w = _cvss_weight(finding.get("cvss_score"))
    zdes = (1 - kev) * recency * cvss_w
    return {"zdes_score": round(zdes, 4),
            "zdes_components": {"is_kev": bool(kev), "recency": round(recency, 3), "cvss_weight": round(cvss_w, 3)}}


def compute_bii(finding: dict, asset_criticality: str, patch_hours_estimated: float = 4.0) -> dict:
    risk = (finding.get("risk_score") or 50) / 100.0
    effort = max(0.5, patch_hours_estimated)
    crit = CRITICALITY_NUM.get((asset_criticality or "medium").lower(), 0.45)
    bii = (risk / effort) * crit * 10  # scale to a readable 0–20 range
    return {"bii_score": round(bii, 3),
            "bii_components": {"risk": round(risk, 3), "effort_hours": effort, "asset_criticality_weight": crit}}


def urgency_tier(kri: float, kev: bool, risk_score: float) -> str:
    if kev or risk_score >= 85 or kri >= 0.6:
        return "Urgent"
    if risk_score >= 60 or kri >= 0.2:
        return "Standard"
    return "Deferred"


def critical_indicators(finding: dict) -> list:
    """Empirical-style indicator panel. Each: {key, label, signal, trend}.
    signal: high | medium | low | none. trend: up | down | flat | unknown."""
    rti = finding.get("rti") or []
    has_exploit_links = bool(finding.get("exploit_references"))
    has_advisory = bool(finding.get("advisory_links"))
    return [
        {"key": "chatter", "label": "Chatter",
         "signal": "high" if "active_attacks" in rti else "medium" if finding.get("kev_flag") else "low",
         "trend": "up" if "active_attacks" in rti else "flat"},
        {"key": "exploit_code", "label": "Exploit Code",
         "signal": "high" if ("public_exploit" in rti or has_exploit_links) else "low",
         "trend": "up" if "public_exploit" in rti else "flat"},
        {"key": "exploitation", "label": "Exploitation",
         "signal": "high" if finding.get("kev_flag") or "active_attacks" in rti else
                   "medium" if "exploit_kit" in rti else "low",
         "trend": "up" if finding.get("kev_flag") else "flat"},
        {"key": "threat_intel", "label": "Threat Intel",
         "signal": "high" if any(x in rti for x in ["active_attacks", "malware_association", "exploit_kit"]) else "medium",
         "trend": "flat"},
        {"key": "vendor", "label": "Vendor",
         "signal": "medium" if has_advisory else "low",
         "trend": "down" if finding.get("patch_available") else "flat"},
        {"key": "references", "label": "References",
         "signal": "medium" if has_advisory or has_exploit_links else "low",
         "trend": "down"},
        {"key": "vuln_attrs", "label": "Vuln Attributes",
         "signal": "high" if (finding.get("cvss_score") or 0) >= 9 else
                   "medium" if (finding.get("cvss_score") or 0) >= 7 else "low",
         "trend": "up"},
    ]


def empirical_percentile(kri_score: float, cohort_scores: list[float]) -> dict:
    """What % of the cohort scores at or below this one, plus a histogram of the
    cohort's score distribution.

    Item 32 -- the histogram used to render as a single visible bar. The cause
    was the bucketing: indices were computed as `s * 20 / max(cohort_scores)`,
    i.e. normalized to the cohort's own maximum. KRI scores are already on a
    fixed 0..1 scale and in practice cluster tightly (most of a severity cohort
    lands within a narrow band), so dividing by the max pushed nearly every
    finding into the same high bucket and left nineteen empty ones.

    Now the histogram bins over the FIXED 0..1 KRI domain, so the bars show
    where this cohort actually sits on the scale, and each bucket carries its
    range + count so the UI can label and tooltip it. `my_bucket` is computed
    here too -- the frontend was deriving it with an unrelated formula."""
    if not cohort_scores:
        return {"pct": 0, "top_pct": 100, "distribution": [], "buckets": [],
                "cohort_size": 0, "my_bucket": None}
    below = sum(1 for s in cohort_scores if s <= kri_score)
    pct = round((below / len(cohort_scores)) * 100, 1)

    N = 20
    counts = [0] * N
    for s in cohort_scores:
        idx = min(N - 1, max(0, int(s * N)))   # fixed 0..1 domain
        counts[idx] += 1
    buckets = [{
        "index": i,
        "from": round(i / N, 2),
        "to": round((i + 1) / N, 2),
        "count": counts[i],
    } for i in range(N)]
    my_bucket = min(N - 1, max(0, int(kri_score * N)))
    return {
        "pct": pct, "top_pct": round(100 - pct, 1),
        "distribution": counts,          # kept for any existing consumer
        "buckets": buckets,
        "cohort_size": len(cohort_scores),
        "my_bucket": my_bucket,
        "cohort_min": round(min(cohort_scores), 3),
        "cohort_max": round(max(cohort_scores), 3),
    }


async def cwe_prevalence_map(db) -> dict:
    """Compute organization-local CWE frequency. Returns {cwe: weight} where weight is 0.8–1.5."""
    cursor = db.findings.aggregate([
        {"$match": {"cwe": {"$ne": None}}},
        {"$group": {"_id": "$cwe", "count": {"$sum": 1}}},
    ])
    counts = {r["_id"]: r["count"] async for r in cursor}
    if not counts:
        return {}
    max_count = max(counts.values())
    return {cwe: round(0.8 + (c / max_count) * 0.7, 3) for cwe, c in counts.items()}
