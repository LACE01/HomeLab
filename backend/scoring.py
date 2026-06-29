"""Prioritization / risk scoring engine.

Combines CVSS, EPSS, KEV, RTI, exposure, asset criticality, age, recurrence.
Returns a 0-100 risk score with a transparent breakdown.
"""
from datetime import datetime, timezone


CRITICALITY_WEIGHT = {"crown_jewel": 1.0, "critical": 0.9, "high": 0.75, "medium": 0.5, "low": 0.3}
EXPOSURE_WEIGHT = {"internet": 1.0, "external": 0.85, "dmz": 0.7, "internal": 0.4, "isolated": 0.2}
SEVERITY_BASELINE = {"Critical": 90, "High": 70, "Medium": 50, "Low": 30, "Info": 10}


def _parse_dt(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def compute_risk(finding: dict, asset: dict | None = None) -> dict:
    """Return {score: int, breakdown: [{factor, points, reason}]}"""
    breakdown = []

    # 1) Severity baseline
    sev = finding.get("severity") or "Medium"
    base = SEVERITY_BASELINE.get(sev, 50)
    breakdown.append({"factor": "Severity", "points": base, "reason": f"Base for {sev}"})

    # 2) CVSS adjustment
    cvss = finding.get("cvss_score") or 0
    cvss_pts = round((cvss - 5) * 2, 1) if cvss else 0
    if cvss_pts:
        breakdown.append({"factor": "CVSS", "points": cvss_pts, "reason": f"CVSS {cvss}"})

    # 3) EPSS
    epss = finding.get("epss_score") or 0
    epss_pts = round(epss * 20, 1)
    if epss_pts:
        breakdown.append({"factor": "EPSS", "points": epss_pts, "reason": f"EPSS {epss:.2f}"})

    # 4) KEV
    if finding.get("kev_flag"):
        breakdown.append({"factor": "KEV", "points": 15, "reason": "Known Exploited Vulnerability (CISA KEV)"})

    # 5) RTI / vendor threat intel
    rti = finding.get("rti", []) or []
    if "active_attacks" in rti:
        breakdown.append({"factor": "RTI", "points": 12, "reason": "Active attacks in the wild"})
    if "zero_day" in rti:
        breakdown.append({"factor": "RTI", "points": 12, "reason": "Zero-day"})
    if "wormable" in rti:
        breakdown.append({"factor": "RTI", "points": 8, "reason": "Wormable"})
    if "public_exploit" in rti:
        breakdown.append({"factor": "RTI", "points": 6, "reason": "Public exploit available"})
    if "easy_exploit" in rti:
        breakdown.append({"factor": "RTI", "points": 4, "reason": "Easy to exploit"})
    if "remote_code_execution" in rti:
        breakdown.append({"factor": "RTI", "points": 6, "reason": "Remote code execution"})

    # 6) Asset criticality
    if asset:
        crit = asset.get("criticality", "medium").lower()
        crit_pts = round(CRITICALITY_WEIGHT.get(crit, 0.5) * 10, 1)
        breakdown.append({"factor": "Asset Criticality", "points": crit_pts, "reason": f"Asset is {crit}"})

        exp = asset.get("exposure", "internal").lower()
        exp_pts = round(EXPOSURE_WEIGHT.get(exp, 0.4) * 10, 1)
        breakdown.append({"factor": "Exposure", "points": exp_pts, "reason": f"{exp} exposure"})

        if finding.get("internet_facing") or asset.get("exposure") in ("internet", "external"):
            breakdown.append({"factor": "Internet Facing", "points": 8, "reason": "Asset is internet facing"})

    # 7) Age / recurrence
    first_seen = _parse_dt(finding.get("first_seen_at"))
    if first_seen:
        age_days = (datetime.now(timezone.utc) - first_seen).days
        if age_days > 90:
            breakdown.append({"factor": "Aging", "points": 6, "reason": f"Open {age_days} days"})
        elif age_days > 30:
            breakdown.append({"factor": "Aging", "points": 3, "reason": f"Open {age_days} days"})

    reopened = finding.get("reopened_count", 0) or 0
    if reopened > 0:
        breakdown.append({"factor": "Recurrence", "points": min(reopened * 3, 10), "reason": f"Reopened {reopened}x"})

    # 8) Patch availability
    if finding.get("patch_available") is False:
        breakdown.append({"factor": "No Patch", "points": 5, "reason": "Patch not available"})

    total = sum(b["points"] for b in breakdown)
    total = max(0, min(100, round(total, 1)))
    return {"score": total, "breakdown": breakdown}


SLA_DAYS = {
    "Critical": {"crown_jewel": 3, "critical": 7, "high": 14, "medium": 21, "low": 30},
    "High": {"crown_jewel": 7, "critical": 14, "high": 21, "medium": 30, "low": 45},
    "Medium": {"crown_jewel": 14, "critical": 30, "high": 45, "medium": 60, "low": 90},
    "Low": {"crown_jewel": 30, "critical": 60, "high": 90, "medium": 120, "low": 180},
    "Info": {"crown_jewel": 90, "critical": 90, "high": 180, "medium": 180, "low": 365},
}


def compute_sla_days(severity: str, criticality: str) -> int:
    return SLA_DAYS.get(severity, SLA_DAYS["Medium"]).get(criticality.lower(), 30)
