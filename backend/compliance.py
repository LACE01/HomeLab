"""Compliance framework coverage -- maps open findings to CIS Controls v8 and NIST
CSF 2.0 so you have something more concrete than a raw finding count to hand to an
auditor or use for prioritization.

This is a heuristic classification (CWE, source tool, and service/port signals), not
a certified compliance assessment -- there's no framework-certified scanner input
here, just a reasonable best-effort mapping of what VulnOps already tracks onto
recognizable control language. That caveat is included directly in the summary output
so it's never presented as more authoritative than it is.
"""
from datetime import datetime, timezone

CIS_CONTROLS = {
    "CIS-1": "Inventory and Control of Enterprise Assets",
    "CIS-2": "Inventory and Control of Software Assets",
    "CIS-3": "Data Protection",
    "CIS-4": "Secure Configuration of Enterprise Assets and Software",
    "CIS-5": "Account Management",
    "CIS-6": "Access Control Management",
    "CIS-7": "Continuous Vulnerability Management",
    "CIS-12": "Network Infrastructure Management",
    "CIS-13": "Network Monitoring and Defense",
    "CIS-16": "Application Software Security",
}

NIST_FUNCTIONS = {"GV": "Govern", "ID": "Identify", "PR": "Protect", "DE": "Detect", "RS": "Respond", "RC": "Recover"}

CATEGORY_META = {
    "vuln_management": {"label": "Vulnerability Management", "cis": ["CIS-7"], "nist": "ID"},
    "asset_inventory": {"label": "Asset Inventory", "cis": ["CIS-1"], "nist": "ID"},
    "software_composition": {"label": "Software Composition / Dependencies", "cis": ["CIS-2", "CIS-16"], "nist": "PR"},
    "app_security": {"label": "Application Security", "cis": ["CIS-16"], "nist": "PR"},
    "identity_access": {"label": "Identity & Access", "cis": ["CIS-5", "CIS-6"], "nist": "PR"},
    "network_security": {"label": "Network Security", "cis": ["CIS-12", "CIS-13"], "nist": "PR"},
    "crypto_pki": {"label": "Cryptography / PKI", "cis": ["CIS-3"], "nist": "PR"},
    "config_management": {"label": "Secure Configuration", "cis": ["CIS-4"], "nist": "PR"},
    "other": {"label": "Other / Uncategorized", "cis": [], "nist": None},
}

CWE_CATEGORY = {
    "CWE-79": "app_security", "CWE-89": "app_security", "CWE-94": "app_security", "CWE-352": "app_security",
    "CWE-200": "app_security", "CWE-611": "app_security", "CWE-918": "app_security",
    "CWE-295": "crypto_pki", "CWE-326": "crypto_pki", "CWE-327": "crypto_pki", "CWE-330": "crypto_pki",
    "CWE-798": "identity_access", "CWE-732": "identity_access", "CWE-276": "identity_access",
    "CWE-287": "identity_access", "CWE-306": "identity_access", "CWE-522": "identity_access",
}
UNAUTH_SERVICE_KEYWORDS = ["redis", "mongodb", "elasticsearch", "mysql", "postgres", "mssql", "rdp", "vnc", "smb", "ftp", "telnet"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def classify_finding(f: dict) -> str:
    cwe = (f.get("cwe") or "").upper()
    if cwe in CWE_CATEGORY:
        return CWE_CATEGORY[cwe]
    source_tool_type = f.get("source_tool_type") or ""
    source_tool = f.get("source_tool") or ""
    title = (f.get("title") or "").lower()
    if source_tool_type == "Software Composition Analysis":
        return "software_composition"
    if source_tool == "TLS Cert Monitor":
        return "crypto_pki"
    if source_tool == "EASM" or "easm" in title or "attack surface" in title:
        return "asset_inventory"
    if "exposure mismatch" in title:
        return "config_management"
    if source_tool.lower().startswith("nmap") or f.get("port"):
        if any(s in title for s in UNAUTH_SERVICE_KEYWORDS):
            return "identity_access"
        return "network_security"
    if f.get("cve"):
        return "vuln_management"
    return "other"


async def compute_compliance_summary(db) -> dict:
    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    findings = await db.findings.find(
        {"status": {"$in": open_states}},
        {"_id": 0, "cwe": 1, "source_tool_type": 1, "source_tool": 1, "title": 1, "severity": 1, "port": 1, "cve": 1},
    ).to_list(200000)

    category_counts = {cat: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "total": 0} for cat in CATEGORY_META}
    for f in findings:
        cat = classify_finding(f)
        sev = f.get("severity") or "Medium"
        bucket = category_counts.setdefault(cat, {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "total": 0})
        bucket[sev] = bucket.get(sev, 0) + 1
        bucket["total"] += 1

    controls: dict = {}
    for cat, meta in CATEGORY_META.items():
        counts = category_counts.get(cat, {"total": 0})
        for cis_id in meta["cis"]:
            c = controls.setdefault(cis_id, {
                "id": cis_id, "name": CIS_CONTROLS.get(cis_id, cis_id), "categories": [],
                "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0,
            })
            c["categories"].append(meta["label"])
            c["critical"] += counts.get("Critical", 0)
            c["high"] += counts.get("High", 0)
            c["medium"] += counts.get("Medium", 0)
            c["low"] += counts.get("Low", 0)
            c["total"] += counts.get("total", 0)

    for c in controls.values():
        if c["critical"] > 0:
            c["status"] = "gap"
        elif c["high"] > 0:
            c["status"] = "at_risk"
        elif c["total"] > 0:
            c["status"] = "monitor"
        else:
            c["status"] = "clean"

    unmapped_clean = [{"id": cid, "name": name} for cid, name in CIS_CONTROLS.items() if cid not in controls]
    clean_or_monitor = len([c for c in controls.values() if c["status"] in ("clean", "monitor")]) + len(unmapped_clean)
    coverage_pct = round(100 * clean_or_monitor / len(CIS_CONTROLS), 1) if CIS_CONTROLS else None

    nist_functions: dict = {}
    for cat, meta in CATEGORY_META.items():
        if not meta["nist"]:
            continue
        counts = category_counts.get(cat, {"total": 0})
        n = nist_functions.setdefault(meta["nist"], {
            "function": meta["nist"], "label": NIST_FUNCTIONS[meta["nist"]], "critical": 0, "high": 0, "total": 0,
        })
        n["critical"] += counts.get("Critical", 0)
        n["high"] += counts.get("High", 0)
        n["total"] += counts.get("total", 0)

    return {
        "coverage_pct": coverage_pct,
        "controls": sorted(controls.values(), key=lambda c: c["id"]),
        "unmapped_clean_controls": unmapped_clean,
        "nist_functions": sorted(nist_functions.values(), key=lambda f: f["function"]),
        "categories": [{"category": cat, "label": meta["label"], **category_counts.get(cat, {})} for cat, meta in CATEGORY_META.items()],
        "total_open_findings": len(findings),
        "generated_at": _now_iso(),
        "methodology_note": (
            "Findings are heuristically classified by CWE, source tool, and service/port signals into a small "
            "set of security categories, then mapped to CIS Controls v8 and NIST CSF 2.0 functions. This is a "
            "coverage indicator to help prioritize work, not a certified compliance assessment."
        ),
    }
