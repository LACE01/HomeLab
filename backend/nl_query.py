"""Natural-language search for Findings -- rule-based keyword/pattern parsing, no LLM
call and no ongoing token cost. Intentionally transparent: it returns exactly which
filters it inferred alongside the results, so it never behaves like an opaque black box.
Deliberately simple (regex + keyword tables) rather than a model -- it covers the common
phrasing security teams actually type ("critical kev findings on windows owned by
AppSec") without adding an external dependency or a per-query cost to a self-hosted app.
"""
import re

SEVERITY_WORDS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
PLATFORM_WORDS = {"windows": "Windows", "linux": "Linux", "macos": "Mac", "mac": "Mac", "ubuntu": "Linux",
                   "cloud": "Cloud", "kubernetes": "Cloud", "k8s": "Cloud"}

CVE_RE = re.compile(r"cve-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_RE = re.compile(r"cwe-\d{1,4}", re.IGNORECASE)
RISK_RE = re.compile(r"risk(?:\s*score)?\s*(?:over|above|>=|greater than|at least)\s*(\d{1,3})", re.IGNORECASE)


def parse_nl_query(text: str, known_teams: list) -> dict:
    t = (text or "").lower()
    filters: dict = {}
    interpreted: list = []

    for word, val in SEVERITY_WORDS.items():
        if re.search(rf"\b{word}\b", t):
            filters["severity"] = val
            interpreted.append(f"severity = {val}")
            break

    if re.search(r"\bkev\b|actively exploited|known exploited", t):
        filters["kev"] = True
        interpreted.append("KEV (known exploited) = true")
    elif re.search(r"\bexploited\b", t):
        filters["kev"] = True
        interpreted.append("KEV (known exploited) = true")

    if re.search(r"active.?attack", t):
        filters["view"] = "active_attacks"
        interpreted.append("active attacks = true")
    elif re.search(r"internet.?facing|\bexposed\b|external.?facing", t):
        filters["internet_facing"] = True
        interpreted.append("internet-facing = true")
    elif re.search(r"\bunassigned\b|no owner|no team|not owned", t):
        filters["view"] = "unassigned"
        interpreted.append("unassigned (no owner team)")
    elif re.search(r"\boverdue\b|past.?due|\blate\b", t):
        filters["view"] = "overdue"
        interpreted.append("overdue (past SLA)")
    elif re.search(r"reopen", t):
        filters["status"] = "Reopened"
        interpreted.append("status = Reopened")
    elif re.search(r"no patch|patch unavailable|without a patch|unpatchable", t):
        filters["view"] = "patch_unavailable"
        interpreted.append("no patch available")

    for word, val in PLATFORM_WORDS.items():
        if re.search(rf"\b{word}\b", t):
            filters["platform"] = val
            interpreted.append(f"platform ~ {val}")
            break

    for team in known_teams:
        if team and re.search(rf"\b{re.escape(team.lower())}\b", t):
            filters["owner_team"] = team
            interpreted.append(f"owner team = {team}")
            break

    cve_match = CVE_RE.search(text or "")
    if cve_match:
        filters["cve"] = cve_match.group(0).upper()
        interpreted.append(f"CVE = {filters['cve']}")

    cwe_match = CWE_RE.search(text or "")
    if cwe_match:
        filters["cwe"] = cwe_match.group(0).upper()
        interpreted.append(f"CWE = {filters['cwe']}")

    risk_match = RISK_RE.search(t)
    if risk_match:
        filters["min_risk_score"] = int(risk_match.group(1))
        interpreted.append(f"risk score ≥ {risk_match.group(1)}")

    # Whatever free text is left after removing the exact spans we understood (CVE/CWE/
    # risk-threshold matches) and the keyword vocabulary still gets used as a plain-text
    # search over title/CVE/hostname, so nothing typed is silently discarded -- it either
    # becomes a structured filter or a text search.
    leftover = t
    if cve_match:
        leftover = leftover.replace(cve_match.group(0).lower(), " ")
    if cwe_match:
        leftover = leftover.replace(cwe_match.group(0).lower(), " ")
    if risk_match:
        leftover = leftover.replace(risk_match.group(0).lower(), " ")
    for word in list(SEVERITY_WORDS.keys()) + list(PLATFORM_WORDS.keys()) + [
        "kev", "exploited", "actively", "known", "active", "attack", "internet", "facing",
        "exposed", "external", "unassigned", "owner", "team", "not", "owned", "no",
        "overdue", "past", "due", "late", "reopen", "reopened", "patch", "unavailable",
        "available", "severity", "without", "a", "unpatchable", "on", "findings", "finding",
        "with", "risk", "score", "over", "above", "greater", "than", "at", "least", "show",
        "me", "find", "search", "for", "and", "the", "of", "cve", "cwe",
    ] + [tm.lower() for tm in known_teams if tm]:
        leftover = re.sub(rf"\b{re.escape(word)}\b", " ", leftover)
    leftover = re.sub(r"[^a-z0-9\-\. ]", " ", leftover)
    leftover = re.sub(r"\s+", " ", leftover).strip()
    if leftover and len(leftover) >= 3:
        filters["q"] = leftover
        interpreted.append(f'free text = "{leftover}"')

    if not filters:
        filters["q"] = text
        interpreted.append(f'free text = "{text}"')

    return {"filters": filters, "interpreted": interpreted}
