"""Best-fit CWE -> MITRE ATT&CK (Enterprise) mapping.

There is no single authoritative CWE->ATT&CK crosswalk -- CWE describes a code-level
weakness while ATT&CK describes attacker behavior, so a weakness can map to more than
one technique depending on how it's actually abused. This table uses the mapping
security teams commonly apply in practice (several of these, like SQL injection, XSS,
path traversal and buffer overflows, are the literal textbook examples MITRE itself
lists under T1190 "Exploit Public-Facing Application"). It's a heuristic best-fit, not
a guarantee -- shown in the UI as a suggested mapping so analysts can override it with
their own judgement.

Computed live from the finding's `cwe` field rather than cached on the document, so it
never goes stale if a finding's CWE gets corrected later.
"""

CWE_MITRE_MAP = {
    "CWE-79":   {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},
    "CWE-89":   {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},
    "CWE-22":   {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},
    "CWE-502":  {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},
    "CWE-918":  {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},
    "CWE-787":  {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},
    "CWE-611":  {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},
    "CWE-77":   {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},
    "CWE-78":   {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},
    "CWE-434":  {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},

    "CWE-287":  {"tactic": "Initial Access",       "technique_id": "T1078",   "technique": "Valid Accounts"},
    "CWE-306":  {"tactic": "Initial Access",       "technique_id": "T1078",   "technique": "Valid Accounts"},
    "CWE-798":  {"tactic": "Credential Access",    "technique_id": "T1552.001", "technique": "Unsecured Credentials: Credentials In Files"},
    "CWE-522":  {"tactic": "Credential Access",    "technique_id": "T1552.001", "technique": "Unsecured Credentials: Credentials In Files"},
    "CWE-521":  {"tactic": "Credential Access",    "technique_id": "T1110",   "technique": "Brute Force"},
    "CWE-307":  {"tactic": "Credential Access",    "technique_id": "T1110",   "technique": "Brute Force"},

    "CWE-284":  {"tactic": "Privilege Escalation", "technique_id": "T1068",   "technique": "Exploitation for Privilege Escalation"},
    "CWE-269":  {"tactic": "Privilege Escalation", "technique_id": "T1068",   "technique": "Exploitation for Privilege Escalation"},
    "CWE-863":  {"tactic": "Privilege Escalation", "technique_id": "T1068",   "technique": "Exploitation for Privilege Escalation"},
    "CWE-732":  {"tactic": "Privilege Escalation", "technique_id": "T1222",   "technique": "File and Directory Permissions Modification"},

    "CWE-327":  {"tactic": "Defense Evasion",      "technique_id": "T1600",   "technique": "Weaken Encryption"},
    "CWE-326":  {"tactic": "Defense Evasion",      "technique_id": "T1600",   "technique": "Weaken Encryption"},
    "CWE-295":  {"tactic": "Defense Evasion",      "technique_id": "T1600",   "technique": "Weaken Encryption"},
    "CWE-693":  {"tactic": "Defense Evasion",      "technique_id": "T1562",   "technique": "Impair Defenses"},
    "CWE-1104": {"tactic": "Initial Access",       "technique_id": "T1195.002", "technique": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"},

    "CWE-352":  {"tactic": "Collection",           "technique_id": "T1185",   "technique": "Browser Session Hijacking"},
    "CWE-601":  {"tactic": "Initial Access",       "technique_id": "T1189",   "technique": "Drive-by Compromise"},
    "CWE-20":   {"tactic": "Initial Access",       "technique_id": "T1190",   "technique": "Exploit Public-Facing Application"},
    "CWE-200":  {"tactic": "Reconnaissance",       "technique_id": "T1592",   "technique": "Gather Victim Host Information"},
    "CWE-16":   {"tactic": "Defense Evasion",      "technique_id": "T1562",   "technique": "Impair Defenses"},
}


def mitre_for_cwe(cwe):
    if not cwe:
        return None
    return CWE_MITRE_MAP.get(cwe.strip().upper())


def apply_mitre_mapping(finding: dict) -> dict:
    """Returns the finding dict with mitre_tactic/mitre_technique/mitre_technique_id
    filled in (live, best-fit) whenever the finding doesn't already carry an explicit
    analyst-set mapping. Safe to call on a doc that already has these fields -- it
    won't overwrite a value that's already present."""
    if finding.get("mitre_tactic") or finding.get("mitre_technique"):
        return finding
    m = mitre_for_cwe(finding.get("cwe"))
    if m:
        finding["mitre_tactic"] = m["tactic"]
        finding["mitre_technique"] = f'{m["technique"]} ({m["technique_id"]})'
        finding["mitre_technique_id"] = m["technique_id"]
        finding["mitre_mapping_source"] = "heuristic"
    return finding
