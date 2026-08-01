"""ATT&CK mapping must work on findings that have no CWE.

The panel showed "—" on 99% of the backlog: 58 of 7,501 open findings mapped,
because 7,441 carried no CWE. That is not bad data -- Qualys omits CWE on
configuration and informational checks by design, and those dominate any real VM
backlog. Mapping only from CWE therefore measured a limitation of one input while
presenting itself as a product feature.

The finding still says what it is, in words. These tests use REAL scanner titles
and assert that each resolves to the technique an analyst would pick, that the
basis and confidence travel with it, and that a guess is never dressed up as a
lookup.
"""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_mitre_signals"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_mitre_signals"]

from mitre_mapping import resolve_mitre, apply_mitre_mapping, coverage_from_findings
import mitre_signals

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


# ============ real, CWE-less scanner titles ============

# Titles taken from the shape Qualys actually emits for configuration checks --
# every one of these previously rendered a dash.
CASES = [
    ("SSL/TLS Server Supports Deprecated Protocol SSLv3", "T1600"),
    ("SSL Server Supports Weak Cipher Suites (RC4)", "T1600"),
    ("SSL Certificate - Self-Signed Certificate", "T1557"),
    ("SSL Certificate - Expired", "T1557"),
    ("Microsoft Windows SMBv1 Protocol Enabled", "T1021.002"),
    ("SMB Signing Not Required", "T1557.001"),
    ("Microsoft Windows Remote Desktop Protocol Weak Encryption", "T1021.001"),
    ("Telnet Service Detected on Port 23", "T1040"),
    ("FTP Server Allows Anonymous Login", "T1078"),
    ("Enabled Default Password for Administrator Account", "T1078.001"),
    ("Password Complexity Policy Not Enforced", "T1110"),
    ("SNMP Agent Responds to Default 'public' Community String", "T1046"),
    ("DNS Server Allows Zone Transfer (AXFR)", "T1590.002"),
    ("Web Server Directory Listing Enabled", "T1595.003"),
    ("Web Server Version Banner Disclosure", "T1592.002"),
    ("Windows Firewall Is Disabled on the Public Profile", "T1562.001"),
    ("Audit Policy Logging Is Not Enabled", "T1562.001"),
    ("BitLocker Drive Encryption Not Enabled", "T1562"),
    ("Microsoft Windows Unquoted Service Path Vulnerability", "T1574.009"),
    ("World Writable Files Detected in System Directory", "T1222"),
    ("Apache Struts Remote Code Execution Vulnerability", "T1203"),
    ("Apache Log4j Deserialization Vulnerability (Log4Shell)", "T1190"),
    ("Local Privilege Escalation via Insecure Service Permissions", "T1068"),
    ("EOL/Obsolete Software: Windows Server 2012 R2 Detected", "T1190"),
    ("Missing Security Update KB5034441", "T1190"),
    ("Session Cookie Missing HttpOnly and Secure Flags", "T1539"),
    ("Cross-Site Request Forgery (CSRF) Vulnerability", "T1185"),
    ("Open Redirect Vulnerability in Login Page", "T1189"),
    ("Hard-coded Credentials Found in Configuration File", "T1552.001"),
    ("SPF Record Missing for Domain", "T1566"),
    ("Kerberos Pre-Authentication Disabled (AS-REP Roasting)", "T1558"),
    ("SSH Server Supports Protocol 1", "T1021.004"),
]

for title, expected in CASES:
    r = resolve_mitre({"title": title})
    assert r["technique_id"] == expected, f"{title!r} -> {r['technique_id']} (expected {expected})"
    assert r["basis"] == "signature", f"{title!r} resolved via {r['basis']}"
    assert r["confidence"] == "medium"
    assert r["matched"], f"{title!r} did not report what it matched on"
    assert r["tactic"], f"{title!r} has a technique but no tactic"
print(f"PASS: all {len(CASES)} real CWE-less scanner titles resolve to the technique an analyst would "
      "pick, from the finding's own words")

# and each one reports WHAT it recognized, so the inference is inspectable
r = resolve_mitre({"title": "Telnet Service Detected on Port 23"})
assert "no cwe" in r["explanation"].lower()
assert "cleartext remote-access protocol" in r["explanation"]
assert r["matched"] == "telnet"
print("PASS: a signature match explains itself — names the missing CWE, what it recognized, and the "
      "exact text it matched on")


# ============ layer precedence: a stronger basis always wins ============

# CWE beats a title keyword
r = resolve_mitre({"title": "Telnet Service Detected", "cwe": "CWE-89"})
assert r["basis"] == "cwe" and r["technique_id"] == "T1190" and r["confidence"] == "high"
print("PASS: when a CWE exists it outranks the title heuristic")

# an analyst's own mapping outranks everything
r = resolve_mitre({"title": "Telnet Service Detected", "cwe": "CWE-89",
                    "mitre_technique_id": "T1499", "mitre_tactic": "Impact",
                    "mitre_technique": "Endpoint Denial of Service",
                    "mitre_mapping_source": "analyst"})
assert r["basis"] == "analyst" and r["technique_id"] == "T1499" and r["confidence"] == "confirmed"
print("PASS: an analyst's explicit mapping is never overwritten by any inference")

# a CWE with no table entry falls THROUGH to the title, rather than giving up
r = resolve_mitre({"title": "Telnet Service Detected", "cwe": "CWE-99999"})
assert r["basis"] == "signature" and r["technique_id"] == "T1040"
print("PASS: an unmapped CWE falls through to the next layer instead of returning nothing — the old "
      "behaviour dead-ended on exactly these")

# category only when the text says nothing recognizable
r = resolve_mitre({"title": "Some vendor-specific check 12345", "detection_logic": "Web Application"})
assert r["basis"] == "category" and r["technique_id"] == "T1190" and r["confidence"] == "low"
assert "starting point" in r["explanation"]
print("PASS: the scanner's own category is used only as a fallback, and is labelled low confidence "
      "with that said out loud")

# position, as the last resort
r = resolve_mitre({"title": "zzz unrecognizable", "internet_facing": True, "severity": "Critical"})
assert r["basis"] == "exposure" and r["technique_id"] == "T1190"
assert "position alone" in r["explanation"]
print("PASS: a serious internet-facing finding maps on position when nothing else identifies it, and "
      "says that is what it did")


# ============ when nothing maps, say what was tried ============

r = resolve_mitre({"title": "zzz unrecognizable", "severity": "Low"})
assert r["technique_id"] is None and r["basis"] == "none"
for phrase in ("no CWE", "no scanner category", "behaviour pattern", "Set one manually"):
    assert phrase in r["explanation"], phrase
print("PASS: an unmappable finding explains what was examined and what to do — not a bare dash")


# ============ apply_mitre_mapping attaches the reasoning to the document ============

f = apply_mitre_mapping({"title": "Microsoft Windows SMBv1 Protocol Enabled"})
assert f["mitre_technique_id"] == "T1021.002"
assert f["mitre_technique"] == "Remote Services: SMB/Windows Admin Shares (T1021.002)"
assert f["mitre_tactic"] == "Lateral Movement"
assert f["mitre_url"] == "https://attack.mitre.org/techniques/T1021/002/", f["mitre_url"]
assert f["mitre_confidence"] == "medium" and f["mitre_basis"] == "signature"
assert f["mitre_explanation"]
print("PASS: apply_mitre_mapping fills tactic, technique, confidence, basis, explanation and a "
      "sub-technique URL that resolves correctly (T1021.002 -> /techniques/T1021/002/)")

# an analyst mapping survives a re-apply
f = apply_mitre_mapping({"title": "Telnet Service Detected", "mitre_technique_id": "T1499",
                          "mitre_mapping_source": "analyst", "mitre_tactic": "Impact"})
assert f["mitre_technique_id"] == "T1499" and f["mitre_tactic"] == "Impact"
print("PASS: re-running the mapper never clobbers a human's decision")


# ============ coverage measured across every layer ============

backlog = (
    [{"title": "SSL/TLS Server Supports Deprecated Protocol SSLv3"}] * 40
    + [{"title": "Telnet Service Detected"}] * 25
    + [{"title": "SQL injection in login form", "cwe": "CWE-89"}] * 5
    + [{"title": "vendor check xyz", "detection_logic": "Web Application"}] * 20
    + [{"title": "zzz nothing recognizable", "detection_logic": "Custom"}] * 10
)
cov = coverage_from_findings(backlog)
assert cov["findings_total"] == 100
assert cov["findings_mapped"] == 90 and cov["coverage_pct"] == 90.0
assert cov["unmapped_count"] == 10
bases = {b["basis"]: b["count"] for b in cov["by_basis"]}
assert bases == {"signature": 65, "cwe": 5, "category": 20}, bases
assert all(b["confidence"] for b in cov["by_basis"])
print(f"PASS: coverage is measured across all layers — {cov['coverage_pct']}% of this backlog maps, "
      "broken down by basis, where a CWE-only count would have reported 5%")

top = cov["top_techniques"][0]
assert top["technique_id"] == "T1600" and top["count"] == 40
assert top["url"] == "https://attack.mitre.org/techniques/T1600/"
assert cov["tactics"][0]["count"] >= 40
print("PASS: coverage also returns the most common techniques and tactics in the backlog, each with a "
      "working ATT&CK link — the backlog described as attacker behaviour, not CWE numbers")

assert cov["top_unmapped_categories"][0] == {"category": "Custom", "count": 10}
assert len(cov["unmapped_examples"]) == 10 and cov["unmapped_examples"][0]["title"]
print("PASS: what remains unmapped is reported by category with examples, so the next rule to write "
      "is obvious instead of guessed")


# ============ the rules themselves are sane ============

import re
for pattern, mapping, label in mitre_signals.SIGNATURE_RULES:
    assert mapping["technique_id"].startswith("T"), mapping
    assert mapping["tactic"] and mapping["technique"], mapping
    # Labels are interpolated into "...matched on what it describes: {label}." so
    # they must read as a clause, not a sentence: no trailing period, and starting
    # lowercase unless the first word is an acronym (SQL, DNS, SNMP).
    assert label and not label.endswith("."), f"label should not be a sentence: {label!r}"
    first = label.split()[0]
    assert first.islower() or first.isupper(), f"label should read as a clause: {label!r}"
    assert isinstance(pattern, re.Pattern)
print(f"PASS: all {len(mitre_signals.SIGNATURE_RULES)} behaviour rules are well-formed and carry a "
      "human-readable reason")

# ordering matters: a specific rule must not be shadowed by a general one
r = resolve_mitre({"title": "Enabled Default Password for Administrator Account"})
assert r["technique_id"] == "T1078.001", "the generic Valid Accounts rule shadowed the Default Accounts one"
r = resolve_mitre({"title": "SMB Signing Not Required"})
assert r["technique_id"] == "T1557.001", "the generic SMB rule shadowed the relay-specific one"
print("PASS: specific rules are matched before the general ones they would otherwise be swallowed by")
