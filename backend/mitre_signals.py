"""Map a finding to ATT&CK using every signal the finding already carries.

THE PROBLEM THIS SOLVES

Mapping only from CWE covered 0.8% of the backlog: 58 of 7,501 open findings,
because 7,441 of them carry no CWE at all. That is not a data-quality accident --
Qualys deliberately omits CWE on configuration and informational checks, and those
are the majority of any real VM backlog. A panel that says "—" on 99% of findings
is not a mapping feature, it is a blank field with extra steps.

But "no CWE" is not "no information". The finding already tells us, in plain
words, what the weakness is: "SSL/TLS Server Supports Deprecated Protocol
SSLv3", "Microsoft Windows SMBv1 Enabled", "Telnet Service Detected". A human
analyst reads that title and knows the technique immediately. So does a table.

HOW IT RESOLVES, IN ORDER

  1. analyst      an explicit mapping a human set. Always wins, never overwritten.
  2. cwe          the CWE->technique table. Precise when a CWE exists.
  3. signature    the finding's TITLE and description, matched against behaviour
                  patterns. This is the layer that covers the missing 99%.
  4. category     the scanner's own category (Qualys CATEGORY, stored as
                  detection_logic) -- coarse, but never wrong about the domain.
  5. exposure     last resort: an internet-facing exploitable finding is
                  T1190 by definition of where it sits.

EVERY RESULT CARRIES ITS BASIS AND CONFIDENCE. A title-keyword inference is not
the same claim as a CWE lookup, and presenting them identically would launder a
guess into a fact. The UI shows which layer produced the answer and what matched,
so an analyst can judge it -- and override it, which then becomes layer 1.

WHY NOT JUST BACKFILL CWEs?

Because for a configuration finding there often isn't one. "SMB signing not
required" is not a code weakness; no CWE describes it well. ATT&CK does:
T1557.001. Mapping behaviour to behaviour is the more faithful model anyway.
"""
import re

# ---------------------------------------------------------------------------
# Layer 3: behaviour signatures.
#
# Ordered — first match wins — so specific patterns MUST precede general ones.
# Each rule is (compiled pattern, mapping, human label naming what was recognized).
# Patterns are matched against title + description + remediation, lowercased.
# ---------------------------------------------------------------------------
def _t(tactic, tid, technique):
    return {"tactic": tactic, "technique_id": tid, "technique": technique}


# One place that knows every way a scanner writes "this control is off".
_OFF = r"(is |are |been )?(disabled|not enabled|not configured|not running|turned off|switched off|is off|not set|not required|missing)"

_RULES_RAW = [
    # --- credentials and authentication -------------------------------------
    (r"default (password|credential|account)|factory default|well.known password",
     _t("Initial Access", "T1078.001", "Valid Accounts: Default Accounts"),
     "a default or factory-set credential"),
    (r"anonymous (login|access|ftp|bind)|null session|guest account (enabled|is enabled)",
     _t("Initial Access", "T1078", "Valid Accounts"),
     "anonymous or unauthenticated access to a service"),
    (r"blank password|empty password|no password (is )?(set|required)",
     _t("Initial Access", "T1078", "Valid Accounts"),
     "an account with no password"),
    (r"password (policy|complexity|length|age|history)|lockout (policy|threshold)",
     _t("Credential Access", "T1110", "Brute Force"),
     "a weak password or lockout policy, which is what makes guessing viable"),
    (r"\bntlmv?1\b|lan manager|lm hash|ntlm relay|smb signing",
     _t("Credential Access", "T1557.001",
        "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"),
     "a legacy or unsigned Windows authentication protocol"),
    (r"kerberos|kerberoast|as-rep|spn\b",
     _t("Credential Access", "T1558", "Steal or Forge Kerberos Tickets"),
     "a Kerberos weakness"),
    (r"cached (credential|logon)|lsass|credential guard|wdigest",
     _t("Credential Access", "T1003", "OS Credential Dumping"),
     "credentials recoverable from memory or cache"),

    # --- cleartext / interception -------------------------------------------
    (r"\btelnet\b|\brlogin\b|\brsh\b|\btftp\b",
     _t("Credential Access", "T1040", "Network Sniffing"),
     "a cleartext remote-access protocol"),
    (r"cleartext|clear text|unencrypted|plain.?text (transmission|credential|password)|"
     r"http (basic )?authentication over http\b",
     _t("Credential Access", "T1040", "Network Sniffing"),
     "credentials or data sent without encryption"),
    (r"sslv2|sslv3|tls ?1\.0|tls ?1\.1|poodle|beast|freak|logjam|drown|sweet32|"
     r"weak cipher|null cipher|export cipher|anonymous cipher|rc4|3des|md5 signature|sha-?1 (signature|certificate)",
     _t("Defense Evasion", "T1600", "Weaken Encryption"),
     "a deprecated protocol or weak cipher that downgrades the channel"),
    # The separator is deliberately loose: scanners title these every possible way
    # -- "SSL Certificate - Expired", "Certificate has expired", "Expired SSL
    # Certificate". A rule that only matches one phrasing quietly covers a third
    # of what it should.
    (r"self.signed certificate|certificate\W{0,3}(has\s+)?expired|expired\W{0,3}(ssl\s+)?certificate|"
     r"certificate\W{0,3}name mismatch|untrusted\W{0,3}(ca|certificate)|certificate\W{0,3}(is\s+)?not trusted",
     _t("Credential Access", "T1557", "Adversary-in-the-Middle"),
     "a certificate that cannot prove the server's identity"),

    # --- remote services and lateral movement --------------------------------
    (r"remote desktop|\brdp\b|terminal serv|bluekeep",
     _t("Lateral Movement", "T1021.001", "Remote Services: Remote Desktop Protocol"),
     "an exposed or vulnerable Remote Desktop service"),
    (r"\bsmbv1\b|smb ?1\.0|\bmS17-010\b|eternalblue|netbios|\bsmb\b.*(share|enabled|enumerat)",
     _t("Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
     "legacy or over-exposed SMB/NetBIOS"),
    (r"\bssh\b.*(weak|deprecated|version|protocol 1|host key)",
     _t("Lateral Movement", "T1021.004", "Remote Services: SSH"),
     "a weak SSH configuration"),
    (r"\bvnc\b|\bwinrm\b|\bpsexec\b|\bwmi\b.*remote|remote (management|administration) (enabled|service)",
     _t("Lateral Movement", "T1021", "Remote Services"),
     "a remote administration service reachable over the network"),
    (r"\bwinbox\b|\bipmi\b|\bilo\b|\bidrac\b|\bbmc\b|out.of.band management",
     _t("Lateral Movement", "T1021", "Remote Services"),
     "an out-of-band management interface"),

    # --- exploitation of a software flaw -------------------------------------
    (r"sql injection|\bsqli\b", _t("Initial Access", "T1190", "Exploit Public-Facing Application"),
     "SQL injection"),
    (r"cross.site scripting|\bxss\b", _t("Initial Access", "T1190", "Exploit Public-Facing Application"),
     "cross-site scripting"),
    (r"(directory|path) traversal|local file inclusion|remote file inclusion|\blfi\b|\brfi\b",
     _t("Initial Access", "T1190", "Exploit Public-Facing Application"), "path traversal"),
    (r"deserializ|log4j|log4shell|spring4shell|expression language injection",
     _t("Initial Access", "T1190", "Exploit Public-Facing Application"),
     "an object-deserialization or template-injection flaw"),
    (r"remote code execution|\brce\b|arbitrary code execution|command injection|code injection",
     _t("Execution", "T1203", "Exploitation for Client Execution"),
     "remote code execution"),
    (r"buffer overflow|heap overflow|stack overflow|use.after.free|memory corruption|out.of.bounds",
     _t("Initial Access", "T1190", "Exploit Public-Facing Application"),
     "a memory-corruption flaw"),
    (r"(privilege|permission) escalation|elevation of privilege|\beop\b|local privilege",
     _t("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
     "privilege escalation"),
    (r"denial of service|\bdos\b vulnerability|resource exhaustion|crash the",
     _t("Impact", "T1499", "Endpoint Denial of Service"), "a denial-of-service condition"),
    (r"server.side request forgery|\bssrf\b",
     _t("Discovery", "T1046", "Network Service Discovery"),
     "server-side request forgery, which lets an attacker probe the internal network"),

    # --- unsupported / unpatched software ------------------------------------
    (r"end.of.(life|support)|\beol\b|\beos\b|no longer supported|unsupported version|obsolete version|"
     r"has reached end",
     _t("Initial Access", "T1190", "Exploit Public-Facing Application"),
     "software past end-of-support, which will never receive another fix"),
    (r"security update|cumulative update|patch (is )?(missing|not installed)|missing (patch|update)|"
     r"\bkb\d{6,}\b|out of date|outdated version",
     _t("Initial Access", "T1190", "Exploit Public-Facing Application"),
     "a missing vendor patch"),

    # --- defensive controls turned off ----------------------------------------
    # "X is disabled", "X disabled", "X is not enabled", "X turned off" are all the
    # same finding. _OFF captures the variants once so each control doesn't need
    # its own spelling of them.
    (r"(audit(ing)?|logging|log|antivirus|anti-virus|defender|firewall|uac|"
     r"exploit protection|attack surface reduction|asr|screen ?lock|auto ?update)"
     r"\b[^.]{0,40}?" + _OFF,
     _t("Defense Evasion", "T1562.001", "Impair Defenses: Disable or Modify Tools"),
     "a security control that is disabled or not configured"),
    (r"(secure boot|bitlocker|disk encryption|filevault)\b[^.]{0,40}?" + _OFF,
     _t("Defense Evasion", "T1562", "Impair Defenses"),
     "an integrity or encryption control that is turned off"),

    # --- information exposure / recon ------------------------------------------
    (r"directory (listing|indexing|browsing)|\bdirectory index\b",
     _t("Reconnaissance", "T1595.003", "Active Scanning: Wordlist Scanning"),
     "a browsable directory listing"),
    (r"zone transfer|\baxfr\b", _t("Reconnaissance", "T1590.002", "Gather Victim Network Information: DNS"),
     "a DNS zone transfer that discloses the internal namespace"),
    (r"snmp.*(public|private|default community)|community string",
     _t("Discovery", "T1046", "Network Service Discovery"),
     "SNMP readable with a default community string"),
    (r"(banner|version) disclosure|server (banner|version|signature)|"
     r"(discloses|reveals|leaks) (the )?(version|internal|path|software)|"
     r"information (disclosure|leak|exposure)|verbose error|stack trace|debug (mode|information)",
     _t("Reconnaissance", "T1592.002", "Gather Victim Host Information: Software"),
     "the service disclosing its own version or internals"),
    (r"open port|service (detection|detected|enumeration)|port scan|\bnmap\b|listening on",
     _t("Discovery", "T1046", "Network Service Discovery"),
     "an exposed listening service"),
    (r"user enumeration|username enumeration|account enumeration|enumerate (users|accounts|shares)",
     _t("Discovery", "T1087", "Account Discovery"),
     "the service letting an attacker enumerate valid accounts"),

    # --- web session handling ---------------------------------------------------
    (r"cross.site request forgery|\bcsrf\b",
     _t("Collection", "T1185", "Browser Session Hijacking"), "cross-site request forgery"),
    (r"(cookie|session).*(secure|httponly|samesite|not set|missing)|session fixation|"
     r"session (id|token) (in url|predictable)",
     _t("Credential Access", "T1539", "Steal Web Session Cookie"),
     "session cookies that can be stolen or fixed"),
    (r"clickjack|x-frame-options|content.security.policy|security header",
     _t("Initial Access", "T1189", "Drive-by Compromise"),
     "missing browser-side protections"),
    (r"open redirect|unvalidated redirect",
     _t("Initial Access", "T1189", "Drive-by Compromise"), "an open redirect"),

    # --- supply chain / secrets ------------------------------------------------
    (r"(hard.?coded|embedded) (password|credential|key|secret)|api key (exposed|in source)|"
     r"private key (exposed|readable|world)",
     _t("Credential Access", "T1552.001", "Unsecured Credentials: Credentials In Files"),
     "a credential stored where it can be read"),
    (r"(vulnerable|outdated) (dependency|library|package|component)|known vulnerable component|"
     r"npm audit|supply chain",
     _t("Initial Access", "T1195.002",
        "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"),
     "a vulnerable third-party dependency"),

    # --- mail --------------------------------------------------------------------
    (r"open relay|spf (record )?(missing|not|soft)|dmarc|dkim|email spoof",
     _t("Initial Access", "T1566", "Phishing"),
     "mail authentication gaps that let someone spoof this domain"),

    # --- file/share permissions ----------------------------------------------------
    (r"(world|everyone|anonymous).?(readable|writable|writeable)|weak (file|folder|share|registry) permission|"
     r"insecure (acl|permission)|writable by",
     _t("Privilege Escalation", "T1222", "File and Directory Permissions Modification"),
     "permissions that let the wrong principal write"),
    (r"unquoted service path|writable service|service binary",
     _t("Privilege Escalation", "T1574.009", "Hijack Execution Flow: Path Interception by Unquoted Path"),
     "a service path an attacker can hijack"),
]

SIGNATURE_RULES = [(re.compile(p, re.I), m, label) for p, m, label in _RULES_RAW]


# ---------------------------------------------------------------------------
# Layer 4: the scanner's own category. Coarse, but it is the scanner telling us
# what domain the check belongs to, and it is present on nearly every finding.
# ---------------------------------------------------------------------------
CATEGORY_MAP = {
    "web application": (_t("Initial Access", "T1190", "Exploit Public-Facing Application"),
                        "a web-application check"),
    "cgi": (_t("Initial Access", "T1190", "Exploit Public-Facing Application"), "a web/CGI check"),
    "database": (_t("Initial Access", "T1190", "Exploit Public-Facing Application"), "a database check"),
    "firewall": (_t("Discovery", "T1046", "Network Service Discovery"), "a firewall/perimeter check"),
    "tcp/ip": (_t("Discovery", "T1046", "Network Service Discovery"), "a network-stack check"),
    "general remote services": (_t("Lateral Movement", "T1021", "Remote Services"),
                                 "a remote-services check"),
    "rpc": (_t("Lateral Movement", "T1021", "Remote Services"), "an RPC check"),
    "smb / netbios": (_t("Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
                       "an SMB/NetBIOS check"),
    "mail services": (_t("Initial Access", "T1566", "Phishing"), "a mail-services check"),
    "dns and bind": (_t("Reconnaissance", "T1590.002",
                         "Gather Victim Network Information: DNS"), "a DNS check"),
    "information gathering": (_t("Reconnaissance", "T1592", "Gather Victim Host Information"),
                               "an information-gathering check"),
    "security policy": (_t("Defense Evasion", "T1562", "Impair Defenses"), "a security-policy check"),
    "local": (_t("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
              "a local-host check"),
    "windows": (_t("Initial Access", "T1190", "Exploit Public-Facing Application"), "a Windows check"),
    "office application": (_t("Execution", "T1203", "Exploitation for Client Execution"),
                            "a client-application check"),
    "backdoors and trojan horses": (_t("Persistence", "T1505", "Server Software Component"),
                                     "a backdoor check"),
    "brute force attack": (_t("Credential Access", "T1110", "Brute Force"), "a brute-force check"),
}


def _haystack(finding: dict) -> str:
    parts = [
        finding.get("title"), finding.get("description"), finding.get("consequence"),
        finding.get("remediation"), finding.get("business_impact"),
    ]
    return " ".join(str(p) for p in parts if p).lower()


def match_signature(finding: dict):
    """First behaviour rule that recognizes this finding, or None.

    Returns (mapping, label, matched_text) so the UI can show WHAT was
    recognized -- an inference the analyst can't inspect is one they can't trust.
    """
    hay = _haystack(finding)
    if not hay:
        return None
    for pattern, mapping, label in SIGNATURE_RULES:
        m = pattern.search(hay)
        if m:
            return mapping, label, m.group(0)
    return None


def match_category(finding: dict):
    """The scanner's own category. Qualys' CATEGORY is stored as detection_logic."""
    raw = (finding.get("detection_logic") or finding.get("category") or "").strip().lower()
    if not raw:
        return None
    if raw in CATEGORY_MAP:
        return CATEGORY_MAP[raw]
    for key, value in CATEGORY_MAP.items():
        if key in raw:
            return value
    return None
