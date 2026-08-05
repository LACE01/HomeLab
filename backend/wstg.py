"""OWASP Web Security Testing Guide (WSTG) as a structured test-case library.

WSTG is a methodology, not a tool: a catalogue of ~100 named test cases, each with
a stable id (WSTG-INPV-05 = "Testing for SQL Injection"), grouped into eleven
categories. Building it in gives the platform two things it did not have:

  1. FROM A FINDING TO THE METHOD. A scanner says "SQL injection on /login". WSTG
     says exactly how to confirm and characterise it (WSTG-INPV-05), what the
     adjacent tests are, and where it sits in a complete web assessment. That
     turns a single alert into a place in a repeatable methodology.

  2. COVERAGE, HONESTLY. Given the findings on an app, which WSTG categories have
     evidence and which have NONE. A category with zero findings is not "clean" --
     it is usually "not tested", and those are opposite conclusions. The library
     makes that distinction visible, which is the whole reason a testing GUIDE
     beats an ad-hoc checklist.

HOW MAPPING WORKS -- same two anchors as the ATT&CK mapping, deliberately:

  * CWE, when the finding has one. Precise: CWE-89 is WSTG-INPV-05, full stop.
  * the finding's TEXT otherwise, because most configuration findings carry no
    CWE. "SSL/TLS Server Supports Deprecated Protocol" has no CWE but is
    unmistakably WSTG-CRYP-01.

Every mapping records WHICH of the two produced it, so a keyword inference is
never presented as a precise CWE lookup.

Scope note: WSTG covers WEB application testing. A finding that is not web-facing
(a kernel CVE on an internal host, say) legitimately maps to nothing here, and
that is reported as "out of WSTG scope", not as an untested gap.
"""
import re

# The eleven WSTG categories, in assessment order.
CATEGORIES = [
    ("INFO", "Information Gathering"),
    ("CONF", "Configuration & Deployment Management"),
    ("IDNT", "Identity Management"),
    ("ATHN", "Authentication"),
    ("ATHZ", "Authorization"),
    ("SESS", "Session Management"),
    ("INPV", "Input Validation"),
    ("ERRH", "Error Handling"),
    ("CRYP", "Cryptography"),
    ("BUSL", "Business Logic"),
    ("CLNT", "Client-side"),
]
CATEGORY_NAME = dict(CATEGORIES)

# The catalogue. Each test: id, name, the CWEs it corresponds to, and keyword
# patterns matched against a finding's text. A representative, real subset of
# WSTG v4.2 weighted toward the tests scanners actually produce findings for.
def _t(id, name, cwes=None, keywords=None):
    return {"id": id, "category": id.split("-")[1], "name": name,
            "cwes": [f"CWE-{c}" if isinstance(c, int) else c for c in (cwes or [])],
            "keywords": keywords or []}

TESTS = [
    # --- Information Gathering ---
    _t("WSTG-INFO-02", "Fingerprint Web Server", [200], ["server banner", "server version", "http header disclos"]),
    _t("WSTG-INFO-05", "Review Webpage Content for Information Leakage", [200], ["information disclosure", "comment leak", "metadata"]),
    _t("WSTG-INFO-08", "Fingerprint Web Application Framework", [200], ["framework version", "x-powered-by"]),
    _t("WSTG-INFO-10", "Map Application Architecture", [], ["directory listing", "directory index", "directory browsing"]),

    # --- Configuration & Deployment Management ---
    _t("WSTG-CONF-01", "Test Network Infrastructure Configuration", [16], ["insecure configuration", "default configuration"]),
    _t("WSTG-CONF-02", "Test Application Platform Configuration", [16], ["default page", "sample application", "example servlet"]),
    _t("WSTG-CONF-03", "Test File Extensions Handling", [], ["backup file", "old file", ".bak", ".old"]),
    _t("WSTG-CONF-05", "Enumerate Infrastructure and Application Admin Interfaces", [], ["admin interface", "management console", "phpmyadmin"]),
    _t("WSTG-CONF-06", "Test HTTP Methods", [650], ["http methods", "trace method", "options method", "webdav", "put method"]),
    _t("WSTG-CONF-07", "Test HTTP Strict Transport Security", [523], ["hsts", "strict-transport-security", "strict transport security"]),
    _t("WSTG-CONF-08", "Test RIA Cross Domain Policy", [], ["crossdomain.xml", "clientaccesspolicy"]),
    _t("WSTG-CONF-11", "Test Cloud Storage", [], ["s3 bucket", "open bucket", "azure blob public"]),

    # --- Identity Management ---
    _t("WSTG-IDNT-04", "Testing for Account Enumeration", [204], ["user enumeration", "username enumeration", "account enumeration"]),
    _t("WSTG-IDNT-05", "Testing for Weak or Unenforced Username Policy", [], ["predictable username"]),

    # --- Authentication ---
    _t("WSTG-ATHN-01", "Testing for Credentials Transported over an Encrypted Channel", [319, 523], ["cleartext credential", "credentials over http", "plaintext password transmission", "basic auth over http"]),
    _t("WSTG-ATHN-02", "Testing for Default Credentials", [1392, 798], ["default password", "default credential", "factory default"]),
    _t("WSTG-ATHN-03", "Testing for Weak Lock Out Mechanism", [307], ["lockout", "no account lockout", "brute force protection"]),
    _t("WSTG-ATHN-04", "Testing for Bypassing Authentication Schema", [287, 306], ["authentication bypass", "auth bypass", "missing authentication"]),
    _t("WSTG-ATHN-07", "Testing for Weak Password Policy", [521], ["password policy", "password complexity", "weak password requirement"]),
    _t("WSTG-ATHN-09", "Testing for Weak Password Change or Reset", [640], ["password reset", "forgot password", "insecure password recovery"]),

    # --- Authorization ---
    _t("WSTG-ATHZ-01", "Testing Directory Traversal / File Include", [22, 98], ["directory traversal", "path traversal", "local file inclusion", "lfi", "remote file inclusion", "rfi"]),
    _t("WSTG-ATHZ-02", "Testing for Bypassing Authorization Schema", [285, 862], ["authorization bypass", "access control", "missing authorization", "forced browsing"]),
    _t("WSTG-ATHZ-03", "Testing for Privilege Escalation", [269], ["privilege escalation", "elevation of privilege"]),
    _t("WSTG-ATHZ-04", "Testing for Insecure Direct Object References", [639], ["idor", "insecure direct object", "direct object reference"]),

    # --- Session Management ---
    _t("WSTG-SESS-01", "Testing for Session Management Schema", [384], ["session fixation", "predictable session"]),
    _t("WSTG-SESS-02", "Testing for Cookies Attributes", [614, 1004], ["cookie", "httponly", "samesite", "secure flag", "cookie attribute"]),
    _t("WSTG-SESS-03", "Testing for Session Fixation", [384], ["session fixation"]),
    _t("WSTG-SESS-05", "Testing for Cross Site Request Forgery", [352], ["csrf", "cross-site request forgery", "cross site request forgery"]),
    _t("WSTG-SESS-06", "Testing for Logout Functionality", [613], ["session timeout", "logout", "session expiration"]),

    # --- Input Validation ---
    _t("WSTG-INPV-01", "Testing for Reflected Cross Site Scripting", [79], ["reflected xss", "cross-site scripting", "cross site scripting", "xss"]),
    _t("WSTG-INPV-02", "Testing for Stored Cross Site Scripting", [79], ["stored xss", "persistent xss"]),
    _t("WSTG-INPV-03", "Testing for HTTP Verb Tampering", [], ["verb tampering"]),
    _t("WSTG-INPV-04", "Testing for HTTP Parameter Pollution", [], ["parameter pollution"]),
    _t("WSTG-INPV-05", "Testing for SQL Injection", [89], ["sql injection", "sqli"]),
    _t("WSTG-INPV-07", "Testing for XML Injection", [91, 611], ["xml injection", "xxe", "xml external entity"]),
    _t("WSTG-INPV-11", "Testing for Code Injection", [94, 95], ["code injection", "eval injection"]),
    _t("WSTG-INPV-12", "Testing for Command Injection", [77, 78], ["command injection", "os command", "shell injection"]),
    _t("WSTG-INPV-13", "Testing for Format String Injection", [134], ["format string"]),
    _t("WSTG-INPV-16", "Testing for HTTP Splitting/Smuggling", [113], ["request smuggling", "response splitting", "http splitting"]),
    _t("WSTG-INPV-19", "Testing for Server-Side Request Forgery", [918], ["ssrf", "server-side request forgery", "server side request forgery"]),
    _t("WSTG-INPV-18", "Testing for Server-Side Template Injection", [1336, 94], ["template injection", "ssti", "spring4shell", "expression language injection"]),

    # --- Error Handling ---
    _t("WSTG-ERRH-01", "Testing for Improper Error Handling", [209, 210], ["verbose error", "stack trace", "detailed error message", "debug information"]),

    # --- Cryptography ---
    _t("WSTG-CRYP-01", "Testing for Weak Transport Layer Security", [326, 327, 319], ["sslv2", "sslv3", "tls 1.0", "tls 1.1", "weak cipher", "poodle", "beast", "rc4", "3des", "sweet32", "deprecated protocol", "weak tls"]),
    _t("WSTG-CRYP-02", "Testing for Padding Oracle", [], ["padding oracle"]),
    _t("WSTG-CRYP-03", "Testing for Sensitive Information Sent via Unencrypted Channels", [319], ["unencrypted", "cleartext transmission", "plaintext transmission"]),
    _t("WSTG-CRYP-04", "Testing for Weak Encryption", [326, 327, 328], ["weak encryption", "weak hash", "md5", "sha-1 signature", "weak certificate signature"]),

    # --- Business Logic ---
    _t("WSTG-BUSL-01", "Test Business Logic Data Validation", [840], ["business logic"]),
    _t("WSTG-BUSL-07", "Test Defenses Against Application Misuse", [799], ["rate limit", "anti-automation"]),

    # --- Client-side ---
    _t("WSTG-CLNT-01", "Testing for DOM-Based Cross Site Scripting", [79], ["dom xss", "dom-based xss"]),
    _t("WSTG-CLNT-09", "Testing for Clickjacking", [1021], ["clickjacking", "x-frame-options", "frame options"]),
    _t("WSTG-CLNT-11", "Testing Web Messaging", [], ["postmessage", "web messaging"]),
    _t("WSTG-CLNT-12", "Testing Browser Storage", [922], ["localstorage", "sensitive data in browser"]),
    _t("WSTG-CLNT-04", "Testing for Client-side URL Redirect", [601], ["open redirect", "unvalidated redirect"]),
    _t("WSTG-CLNT-08", "Testing for CSS Injection", [], ["css injection"]),
    _t("WSTG-CONF-10", "Test for Subdomain Takeover", [], ["subdomain takeover", "dangling dns"]),
    _t("WSTG-CLNT-13", "Testing for Cross Origin Resource Sharing", [942], ["cors", "cross-origin resource sharing", "access-control-allow-origin"]),
]

TEST_BY_ID = {t["id"]: t for t in TESTS}
_CWE_INDEX = {}
for _t_ in TESTS:
    for _c in _t_["cwes"]:
        _CWE_INDEX.setdefault(_c, []).append(_t_["id"])

_KW = [(re.compile(re.escape(kw), re.I), t["id"]) for t in TESTS for kw in t["keywords"]]

# Which questionnaire domains (questionnaire_v3 `domain`) correspond to which WSTG
# categories -- so a Security Review's technical questions can point at the
# matching methodology, and vice versa.
DOMAIN_TO_CATEGORIES = {
    "authentication": ["ATHN", "IDNT", "SESS"],
    "authorization": ["ATHZ"],
    "data_protection": ["CRYP"],
    "application_security": ["INPV", "ERRH", "CLNT", "BUSL"],
    "infrastructure": ["CONF", "INFO"],
    "network": ["CONF", "INFO"],
}


def _normalize_cwe(raw):
    if not raw:
        return None
    m = re.search(r"(\d+)", str(raw))
    return f"CWE-{int(m.group(1))}" if m else None


def _text(finding):
    parts = [finding.get("title"), finding.get("description"), finding.get("consequence"),
             finding.get("detection_logic"), finding.get("remediation")]
    return " ".join(str(p) for p in parts if p).lower()


def tests_for_finding(finding):
    """Which WSTG test cases this finding is evidence for.

    Returns a list of {id, name, category, basis} -- basis is 'cwe' (precise) or
    'signature' (matched on the finding's text). Empty when the finding maps to
    nothing web-related, which is a legitimate outcome, not a gap.
    """
    hits = {}
    cwe = _normalize_cwe(finding.get("cwe"))
    if cwe and cwe in _CWE_INDEX:
        for tid in _CWE_INDEX[cwe]:
            hits[tid] = "cwe"
    hay = _text(finding)
    for pattern, tid in _KW:
        if tid not in hits and pattern.search(hay):
            hits[tid] = "signature"
    return [{"id": tid, "name": TEST_BY_ID[tid]["name"],
             "category": TEST_BY_ID[tid]["category"],
             "category_name": CATEGORY_NAME[TEST_BY_ID[tid]["category"]],
             "basis": basis,
             "url": f"https://owasp.org/www-project-web-security-testing-guide/latest/"}
            for tid, basis in hits.items()]


def coverage(findings):
    """WSTG coverage across a set of findings.

    For each category: how many of its test cases have at least one finding as
    evidence, and how many have none. A category with zero evidenced tests is
    flagged 'no evidence' -- which on a methodology means 'not tested', the
    opposite of 'clean'.
    """
    evidenced = {}   # test id -> count of findings
    for f in findings:
        for hit in tests_for_finding(f):
            evidenced[hit["id"]] = evidenced.get(hit["id"], 0) + 1

    cats = []
    for code, name in CATEGORIES:
        tests_in_cat = [t for t in TESTS if t["category"] == code]
        with_evidence = [t for t in tests_in_cat if t["id"] in evidenced]
        cats.append({
            "category": code, "name": name,
            "tests_total": len(tests_in_cat),
            "tests_with_evidence": len(with_evidence),
            "evidenced_tests": [{"id": t["id"], "name": t["name"],
                                  "findings": evidenced[t["id"]]} for t in with_evidence],
            "status": ("evidence" if with_evidence else "no_evidence"),
        })
    total = len(TESTS)
    covered = len(evidenced)
    return {
        "tests_total": total,
        "tests_with_evidence": covered,
        "coverage_pct": round(100 * covered / total, 1) if total else 0.0,
        "categories": cats,
        "note": ("A category with no evidence usually means it was not tested, not that it is "
                  "clean. WSTG is a methodology -- absence of a finding is absence of a test, "
                  "unless a manual assessment recorded otherwise."),
    }


def tests_for_domain(domain):
    """The WSTG tests a Security Review questionnaire domain maps to."""
    cats = DOMAIN_TO_CATEGORIES.get(domain, [])
    return [t for t in TESTS if t["category"] in cats]


def catalogue():
    """The whole library, grouped by category, for the reference view."""
    return [{
        "category": code, "name": name,
        "tests": [{"id": t["id"], "name": t["name"], "cwes": t["cwes"]}
                   for t in TESTS if t["category"] == code],
    } for code, name in CATEGORIES]
