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


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


async def get_control_findings(db, control_id: str, limit: int = 300) -> dict:
    """Drill-down for a single CIS control: the actual open findings that make up its
    counts on the summary page, so 'CIS-7 -- 4701 open' is something you can click into
    rather than just a number."""
    categories = [cat for cat, meta in CATEGORY_META.items() if control_id in meta.get("cis", [])]
    if not categories:
        return {"control_id": control_id, "name": CIS_CONTROLS.get(control_id, control_id), "items": [], "total": 0}

    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    findings = await db.findings.find(
        {"status": {"$in": open_states}},
        {"_id": 0, "id": 1, "title": 1, "severity": 1, "cve": 1, "cwe": 1, "source_tool_type": 1,
         "source_tool": 1, "port": 1, "asset_hostname": 1, "asset_id": 1, "status": 1, "risk_score": 1},
    ).to_list(200000)

    matched = [f for f in findings if classify_finding(f) in categories]
    matched.sort(key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 5), -(f.get("risk_score") or 0)))

    return {
        "control_id": control_id, "name": CIS_CONTROLS.get(control_id, control_id),
        "total": len(matched), "items": matched[:limit],
    }


# --------------------------------------------------------------------------
# Operational control mapping (ISO 27001:2022 Annex A / SOC 2 Trust Services
# Criteria) -- unlike the finding-based CIS/NIST mapping above, these checks
# look at whether a *capability* is actually in place and being used (MFA
# adoption, session revocation, threat intel feed populated, IR cases
# actually opened, etc.), which is closer to what an auditor's control
# questionnaire actually asks ("is MFA enforced", "is there an incident
# response process") than a pure vulnerability count is. Still a heuristic,
# still not a certified assessment -- same caveat applies.
# --------------------------------------------------------------------------

OPERATIONAL_CONTROLS = [
    {"id": "mfa", "label": "Multi-factor authentication", "iso27001": ["A.8.5"], "soc2": ["CC6.1"]},
    {"id": "session_management", "label": "Session revocation & management", "iso27001": ["A.8.5"], "soc2": ["CC6.1"]},
    {"id": "login_lockout", "label": "Brute-force / account lockout protection", "iso27001": ["A.8.5"], "soc2": ["CC6.1"]},
    {"id": "audit_logging", "label": "Authentication audit logging", "iso27001": ["A.8.15"], "soc2": ["CC7.2"]},
    {"id": "security_monitoring", "label": "Security event monitoring & correlation", "iso27001": ["A.8.16"], "soc2": ["CC7.1"]},
    {"id": "ueba", "label": "User & entity behavior analytics", "iso27001": ["A.8.16"], "soc2": ["CC7.2"]},
    {"id": "threat_intelligence", "label": "Threat intelligence program", "iso27001": ["A.5.7"], "soc2": ["CC7.1"]},
    {"id": "malware_protection", "label": "Malware detection", "iso27001": ["A.8.7"], "soc2": ["CC6.8"]},
    {"id": "vulnerability_management", "label": "Technical vulnerability management", "iso27001": ["A.8.8"], "soc2": ["CC7.1"]},
    {"id": "incident_response", "label": "Incident response process", "iso27001": ["A.5.24"], "soc2": ["CC7.4"]},
    {"id": "crypto_pki", "label": "Cryptography / certificate management", "iso27001": ["A.8.24"], "soc2": ["CC6.7"]},
    {"id": "backup_continuity", "label": "Backup & business continuity", "iso27001": ["A.5.30"], "soc2": ["A1.2"]},
    {"id": "ticketing_soar", "label": "Incident ticketing / SOAR integration", "iso27001": ["A.5.24"], "soc2": ["CC7.4"]},
]


async def compute_operational_controls(db) -> list:
    import os
    results = []

    total_users = await db.users.count_documents({})
    mfa_users = await db.users.count_documents({"mfa_enabled": True})
    mfa_pct = round((mfa_users / total_users) * 100, 1) if total_users else 0
    if mfa_pct >= 80:
        status, evidence = "implemented", f"{mfa_pct}% of users ({mfa_users}/{total_users}) have MFA enabled."
    elif mfa_pct > 0:
        status, evidence = "partial", f"Only {mfa_pct}% of users ({mfa_users}/{total_users}) have MFA enabled."
    else:
        status, evidence = "partial", f"MFA is available but no users ({0}/{total_users}) have enabled it yet."
    results.append({"id": "mfa", "status": status, "evidence": evidence})

    active_sessions = await db.active_sessions.count_documents({"revoked": {"$ne": True}})
    results.append({"id": "session_management", "status": "implemented",
                     "evidence": f"Sessions are individually revocable (JWT + session store); {active_sessions} active session(s) currently tracked."})

    brute_force_blocked = await db.security_events.count_documents({"source": "login_audit", "event_type": {"$in": ["brute_force_ip", "brute_force_account"]}})
    results.append({"id": "login_lockout", "status": "implemented",
                     "evidence": f"Per-account and per-IP lockout enforced on repeated failures; {brute_force_blocked} lockout event(s) recorded to date."})

    audit_count = await db.login_audit.count_documents({})
    if audit_count > 0:
        status, evidence = "implemented", f"{audit_count} authentication event(s) logged."
    else:
        status, evidence = "partial", "Audit logging is wired up but no login attempts have been recorded yet."
    results.append({"id": "audit_logging", "status": status, "evidence": evidence})

    event_count = await db.security_events.count_documents({})
    correlated_count = await db.security_events.count_documents({"event_type": "correlated_alert"})
    if event_count > 0:
        status = "implemented"
        evidence = f"{event_count} security event(s) recorded; {correlated_count} correlated across multiple sources."
    else:
        status, evidence = "partial", "The security event bus is wired up but hasn't recorded any events yet."
    results.append({"id": "security_monitoring", "status": status, "evidence": evidence})

    ueba_count = await db.security_events.count_documents({"source": "ueba"})
    if ueba_count > 0:
        status, evidence = "implemented", f"{ueba_count} behavioral signal(s) detected (new IP/country, impossible travel)."
    else:
        status, evidence = "partial", "UEBA is enabled but hasn't flagged any behavioral signals yet."
    results.append({"id": "ueba", "status": status, "evidence": evidence})

    watchlist_count = await db.ioc_watchlist.count_documents({})
    if watchlist_count > 0:
        status, evidence = "implemented", f"{watchlist_count} indicator(s) of compromise tracked on the watchlist."
    else:
        status, evidence = "partial", "The threat intel watchlist exists but has no IOCs loaded yet."
    results.append({"id": "threat_intelligence", "status": status, "evidence": evidence})

    yara_count = await db.yara_scan_history.count_documents({})
    if yara_count > 0:
        status, evidence = "implemented", f"{yara_count} file scan(s) performed via YARA."
    else:
        status, evidence = "partial", "YARA scanning is available but hasn't been run yet."
    results.append({"id": "malware_protection", "status": status, "evidence": evidence})

    open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    open_critical = await db.findings.count_documents({"status": {"$in": open_states}, "severity": "Critical"})
    total_findings = await db.findings.count_documents({})
    if total_findings == 0:
        status, evidence = "partial", "No findings have been ingested yet -- vulnerability scanning isn't active."
    elif open_critical > 0:
        status, evidence = "gap", f"{open_critical} open Critical-severity finding(s) require remediation."
    else:
        status, evidence = "implemented", f"{total_findings} finding(s) tracked; no open Critical-severity findings."
    results.append({"id": "vulnerability_management", "status": status, "evidence": evidence})

    ir_count = await db.ir_cases.count_documents({})
    if ir_count > 0:
        open_ir = await db.ir_cases.count_documents({"status": "open"})
        status, evidence = "implemented", f"{ir_count} incident response case(s) opened to date ({open_ir} currently open)."
    else:
        status, evidence = "partial", "The incident response module is available but no cases have been opened yet."
    results.append({"id": "incident_response", "status": status, "evidence": evidence})

    cert_count = await db.tls_certificates.count_documents({})
    if cert_count > 0:
        expiring = await db.tls_certificates.count_documents({"days_until_expiry": {"$lt": 30}})
        status = "implemented" if expiring == 0 else "at_risk"
        evidence = f"{cert_count} certificate(s) monitored" + (f"; {expiring} expiring within 30 days." if expiring else ".")
    else:
        status, evidence = "partial", "TLS certificate monitoring is available but no certificates are tracked yet."
    results.append({"id": "crypto_pki", "status": status, "evidence": evidence})

    backup_enabled = os.environ.get("BACKUP_SCHEDULE_ENABLED", "false").lower() in ("true", "1", "yes")
    if backup_enabled:
        status, evidence = "implemented", "Scheduled database backups are enabled."
    else:
        status, evidence = "not_implemented", "Scheduled backups are not enabled (set BACKUP_SCHEDULE_ENABLED=true)."
    results.append({"id": "backup_continuity", "status": status, "evidence": evidence})

    jira_cfg = await db.jira_config.find_one({"id": "singleton"}, {"_id": 0})
    webhook_count = await db.webhook_destinations.count_documents({"enabled": True})
    jira_on = bool(jira_cfg and jira_cfg.get("enabled") and jira_cfg.get("api_token"))
    if jira_on or webhook_count > 0:
        parts = []
        if jira_on:
            parts.append("Jira")
        if webhook_count:
            parts.append(f"{webhook_count} webhook destination(s)")
        status, evidence = "implemented", f"Configured: {', '.join(parts)}."
    else:
        status, evidence = "partial", "Ticketing/SOAR export is available but no Jira connection or webhook destinations are configured yet."
    results.append({"id": "ticketing_soar", "status": status, "evidence": evidence})

    by_id = {r["id"]: r for r in results}
    return [{**ctrl, **by_id.get(ctrl["id"], {"status": "not_implemented", "evidence": "Not evaluated."})} for ctrl in OPERATIONAL_CONTROLS]
