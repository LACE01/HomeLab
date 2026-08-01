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


# Additional CWE classes seen in real Qualys/Nessus KB data that had no entry,
# which is the other half of why the panel looked permanently empty.
CWE_MITRE_MAP.update({
    "CWE-94":   {"tactic": "Execution",            "technique_id": "T1059",     "technique": "Command and Scripting Interpreter"},
    "CWE-119":  {"tactic": "Initial Access",       "technique_id": "T1190",     "technique": "Exploit Public-Facing Application"},
    "CWE-120":  {"tactic": "Initial Access",       "technique_id": "T1190",     "technique": "Exploit Public-Facing Application"},
    "CWE-125":  {"tactic": "Initial Access",       "technique_id": "T1190",     "technique": "Exploit Public-Facing Application"},
    "CWE-190":  {"tactic": "Initial Access",       "technique_id": "T1190",     "technique": "Exploit Public-Facing Application"},
    "CWE-416":  {"tactic": "Initial Access",       "technique_id": "T1190",     "technique": "Exploit Public-Facing Application"},
    "CWE-476":  {"tactic": "Impact",               "technique_id": "T1499.004", "technique": "Endpoint Denial of Service: Application or System Exploitation"},
    "CWE-400":  {"tactic": "Impact",               "technique_id": "T1499",     "technique": "Endpoint Denial of Service"},
    "CWE-770":  {"tactic": "Impact",               "technique_id": "T1499",     "technique": "Endpoint Denial of Service"},
    "CWE-835":  {"tactic": "Impact",               "technique_id": "T1499",     "technique": "Endpoint Denial of Service"},
    "CWE-319":  {"tactic": "Credential Access",    "technique_id": "T1040",     "technique": "Network Sniffing"},
    "CWE-311":  {"tactic": "Credential Access",    "technique_id": "T1040",     "technique": "Network Sniffing"},
    "CWE-312":  {"tactic": "Credential Access",    "technique_id": "T1552",     "technique": "Unsecured Credentials"},
    "CWE-256":  {"tactic": "Credential Access",    "technique_id": "T1552",     "technique": "Unsecured Credentials"},
    "CWE-863":  {"tactic": "Privilege Escalation", "technique_id": "T1068",     "technique": "Exploitation for Privilege Escalation"},
    "CWE-862":  {"tactic": "Privilege Escalation", "technique_id": "T1068",     "technique": "Exploitation for Privilege Escalation"},
    "CWE-250":  {"tactic": "Privilege Escalation", "technique_id": "T1068",     "technique": "Exploitation for Privilege Escalation"},
    "CWE-59":   {"tactic": "Privilege Escalation", "technique_id": "T1547.009", "technique": "Boot or Logon Autostart Execution: Shortcut Modification"},
    "CWE-427":  {"tactic": "Persistence",          "technique_id": "T1574.007", "technique": "Hijack Execution Flow: Path Interception by PATH Environment Variable"},
    "CWE-426":  {"tactic": "Persistence",          "technique_id": "T1574",     "technique": "Hijack Execution Flow"},
    "CWE-1188": {"tactic": "Initial Access",       "technique_id": "T1078.001", "technique": "Valid Accounts: Default Accounts"},
    "CWE-1392": {"tactic": "Initial Access",       "technique_id": "T1078.001", "technique": "Valid Accounts: Default Accounts"},
    "CWE-798":  {"tactic": "Credential Access",    "technique_id": "T1552.001", "technique": "Unsecured Credentials: Credentials In Files"},
    "CWE-1021": {"tactic": "Collection",           "technique_id": "T1185",     "technique": "Browser Session Hijacking"},
    "CWE-444":  {"tactic": "Defense Evasion",      "technique_id": "T1090",     "technique": "Proxy"},
    "CWE-113":  {"tactic": "Defense Evasion",      "technique_id": "T1090",     "technique": "Proxy"},
    "CWE-345":  {"tactic": "Defense Evasion",      "technique_id": "T1036",     "technique": "Masquerading"},
    "CWE-347":  {"tactic": "Defense Evasion",      "technique_id": "T1036",     "technique": "Masquerading"},
    "CWE-829":  {"tactic": "Initial Access",       "technique_id": "T1195.002", "technique": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"},
    "CWE-1035": {"tactic": "Initial Access",       "technique_id": "T1195.002", "technique": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"},
    "CWE-937":  {"tactic": "Initial Access",       "technique_id": "T1195.002", "technique": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"},
})


def normalize_cwe(raw):
    """Canonicalize whatever a scanner handed us into 'CWE-<n>'.

    Item 33 -- this is the main reason the ATT&CK panel never populated. Qualys'
    knowledgebase returns the bare integer ("89"), Nessus sometimes returns
    "CWE-89", NVD returns "NVD-CWE-noinfo" placeholders, and some sources return
    a comma/space separated list. The lookup table is keyed "CWE-89", so every
    bare-number value silently missed and the panel stayed empty forever.

    Accepts: 89, "89", "CWE-89", "cwe-89", "CWE-89, CWE-79", ["CWE-89"].
    Returns the first usable canonical id, or None."""
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        for item in raw:
            got = normalize_cwe(item)
            if got:
                return got
        return None
    text = str(raw).strip()
    if not text:
        return None
    import re as _re
    # NVD emits placeholders like NVD-CWE-noinfo / NVD-CWE-Other -- not real CWEs
    if "noinfo" in text.lower() or text.lower().endswith("-other"):
        return None
    # \d+ rather than a bounded quantifier: a bounded one silently TRUNCATES
    # ids longer than the bound (CWE-99999 -> CWE-9999), which would make an
    # unmapped CWE masquerade as a different, possibly mapped, one.
    m = _re.search(r"(?:cwe[-_\s]*)?(\d+)", text, _re.I)
    if not m:
        return None
    return f"CWE-{int(m.group(1))}"


def mitre_for_cwe(cwe):
    key = normalize_cwe(cwe)
    if not key:
        return None
    return CWE_MITRE_MAP.get(key)


def coverage_from_findings(findings: list) -> dict:
    """Coverage measured the way the product actually maps, i.e. across every
    layer -- not just CWE.

    The old figure ("0.8%") measured only the CWE table and so described a
    limitation of one input rather than what the feature delivers. It also gave a
    misleading instruction: "extend the CWE table", when the CWE table was never
    going to reach findings that have no CWE.
    """
    by_basis: dict = {}
    unmapped_examples = []
    unmapped_categories: dict = {}
    techniques: dict = {}
    tactics: dict = {}
    for f in findings:
        r = resolve_mitre(f)
        by_basis[r["basis"]] = by_basis.get(r["basis"], 0) + 1
        if r["technique_id"]:
            key = (r["technique_id"], r["technique"])
            techniques[key] = techniques.get(key, 0) + 1
            tactics[r["tactic"]] = tactics.get(r["tactic"], 0) + 1
        else:
            cat = (f.get("detection_logic") or "uncategorized").strip() or "uncategorized"
            unmapped_categories[cat] = unmapped_categories.get(cat, 0) + 1
            if len(unmapped_examples) < 10:
                unmapped_examples.append({"id": f.get("id"), "title": f.get("title"),
                                           "category": f.get("detection_logic")})
    total = len(findings)
    mapped = total - by_basis.get("none", 0)
    return {
        "findings_total": total,
        "findings_mapped": mapped,
        "coverage_pct": round(100 * mapped / total, 1) if total else 0.0,
        "by_basis": [
            {"basis": b, "count": c, "confidence": CONFIDENCE.get(b, "none")}
            for b, c in sorted(by_basis.items(), key=lambda x: -x[1]) if b != "none"
        ],
        "unmapped_count": by_basis.get("none", 0),
        "top_techniques": [
            {"technique_id": tid, "technique": name, "count": c,
             "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"}
            for (tid, name), c in sorted(techniques.items(), key=lambda x: -x[1])[:12]
        ],
        "tactics": [{"tactic": t, "count": c}
                     for t, c in sorted(tactics.items(), key=lambda x: -x[1])],
        "top_unmapped_categories": [
            {"category": k, "count": v}
            for k, v in sorted(unmapped_categories.items(), key=lambda x: -x[1])[:10]
        ],
        "unmapped_examples": unmapped_examples,
        "table_size": len(CWE_MITRE_MAP),
    }


def mapping_coverage(cwe_counts: dict) -> dict:
    """Item 33's coverage indicator: given {cwe: finding_count}, how much of the
    backlog we can actually map, and which unmapped CWEs are costing us the most
    coverage -- so the table can be extended where it pays."""
    total = 0
    mapped = 0
    no_cwe = cwe_counts.get(None, 0) + cwe_counts.get("", 0)
    unmapped: dict = {}
    for raw, count in cwe_counts.items():
        if raw in (None, ""):
            continue
        total += count
        key = normalize_cwe(raw)
        if key and key in CWE_MITRE_MAP:
            mapped += count
        else:
            label = key or str(raw)
            unmapped[label] = unmapped.get(label, 0) + count
    grand_total = total + no_cwe
    return {
        "findings_total": grand_total,
        "findings_with_cwe": total,
        "findings_without_cwe": no_cwe,
        "findings_mapped": mapped,
        "coverage_pct_of_all": round(100 * mapped / grand_total, 1) if grand_total else 0.0,
        "coverage_pct_of_cwe_bearing": round(100 * mapped / total, 1) if total else 0.0,
        "table_size": len(CWE_MITRE_MAP),
        "top_unmapped": sorted(({"cwe": k, "count": v} for k, v in unmapped.items()),
                                key=lambda x: -x["count"])[:15],
    }


# ---------------------------------------------------------------------------
# The layered resolver. See mitre_signals.py for why CWE alone is not enough:
# 7,441 of 7,501 open findings in a real backlog carry no CWE, so a CWE-only
# mapping renders "-" on 99% of the product.
# ---------------------------------------------------------------------------
# Sources this module produces itself. "heuristic" is the pre-layering marker and
# is deliberately included: those mappings SHOULD be recomputed, since recomputing
# is the upgrade.
INFERRED_SOURCES = {"cwe", "signature", "category", "exposure", "heuristic"}

CONFIDENCE = {
    "analyst": "confirmed",
    "cwe": "high",
    "signature": "medium",
    "category": "low",
    "exposure": "low",
}


def resolve_mitre(finding: dict) -> dict:
    """Best available ATT&CK mapping for a finding, WITH the basis for it.

    Always returns a dict. When nothing maps, `technique_id` is None and
    `explanation` says what was looked at -- an honest "we could not determine
    this from what the scanner gave us" is a different statement from a silent
    dash, and it tells the analyst whether to go add evidence or move on.
    """
    from mitre_signals import match_signature, match_category

    # 1. an analyst's own mapping outranks every inference.
    #    "analyst" means "not produced by a layer below". Mappings stored before
    #    this field existed have no source at all, and clobbering those would
    #    silently discard human decisions -- so anything whose source is not one of
    #    our own inference labels is treated as human.
    existing = finding.get("mitre_technique_id") or finding.get("mitre_technique")
    if existing and finding.get("mitre_mapping_source") not in INFERRED_SOURCES:
        return {
            "tactic": finding.get("mitre_tactic"),
            "technique_id": finding["mitre_technique_id"],
            "technique": finding.get("mitre_technique"),
            "basis": "analyst", "confidence": "confirmed",
            "explanation": "Set explicitly by an analyst on this finding.",
            "matched": None,
        }

    # 2. CWE, when the scanner gave us one
    cwe = normalize_cwe(finding.get("cwe")) or normalize_cwe(
        finding.get("cwes") or (finding.get("raw") or {}).get("cwe"))
    if cwe:
        m = CWE_MITRE_MAP.get(cwe)
        if m:
            return {**m, "basis": "cwe", "confidence": "high",
                    "explanation": f"Mapped from {cwe}, the weakness class the scanner recorded.",
                    "matched": cwe}

    # 3. what the finding SAYS -- the layer that covers the CWE-less majority
    sig = match_signature(finding)
    if sig:
        mapping, label, matched = sig
        return {**mapping, "basis": "signature", "confidence": "medium",
                "explanation": (f"No CWE on this finding, so it was matched on what it describes: "
                                 f"{label}."),
                "matched": matched}

    # 4. the scanner's own category -- coarse but rarely wrong about the domain
    cat = match_category(finding)
    if cat:
        mapping, label = cat
        return {**mapping, "basis": "category", "confidence": "low",
                "explanation": (f"Inferred from the scanner category alone ({label}); no CWE and no "
                                 "recognizable pattern in the finding text. Treat as a starting point."),
                "matched": finding.get("detection_logic")}

    # 5. position, as a last resort
    if finding.get("internet_facing") and (finding.get("severity") in ("Critical", "High")
                                            or finding.get("kev_flag")):
        return {"tactic": "Initial Access", "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "basis": "exposure", "confidence": "low",
                "explanation": ("Nothing in the finding text identified a technique. Mapped on position "
                                 "alone: a serious weakness on an internet-facing asset is reachable "
                                 "from outside, whatever the mechanism."),
                "matched": "internet-facing"}

    return {"tactic": None, "technique_id": None, "technique": None,
            "basis": "none", "confidence": "none",
            "explanation": ("Could not determine a technique: this finding has no CWE, no scanner "
                             "category, and nothing in its title or description matched a known "
                             "behaviour pattern. Set one manually if you recognize it."),
            "matched": None}


def apply_mitre_mapping(finding: dict) -> dict:
    """Returns the finding dict with mitre_tactic/mitre_technique/mitre_technique_id
    filled in (live, best-fit) whenever the finding doesn't already carry an explicit
    analyst-set mapping. Safe to call on a doc that already has these fields -- it
    won't overwrite a value that's already present."""
    if ((finding.get("mitre_technique_id") or finding.get("mitre_technique"))
            and finding.get("mitre_mapping_source") not in INFERRED_SOURCES):
        return finding
    r = resolve_mitre(finding)
    # Always attach the reasoning, even when nothing mapped: "we looked at X, Y
    # and Z and could not tell" is useful; a bare dash is not.
    finding["mitre_basis"] = r["basis"]
    finding["mitre_confidence"] = r["confidence"]
    finding["mitre_explanation"] = r["explanation"]
    finding["mitre_matched"] = r.get("matched")
    if r["technique_id"]:
        finding["mitre_tactic"] = r["tactic"]
        finding["mitre_technique"] = f'{r["technique"]} ({r["technique_id"]})'
        finding["mitre_technique_id"] = r["technique_id"]
        finding["mitre_technique_name"] = r["technique"]
        finding["mitre_url"] = (
            "https://attack.mitre.org/techniques/" + r["technique_id"].replace(".", "/") + "/")
        finding.setdefault("mitre_mapping_source", r["basis"])
    return finding
