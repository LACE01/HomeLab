"""Seed demo data — realistic vulnerability operations dataset."""
import uuid
import random
from datetime import datetime, timezone, timedelta
from auth_utils import hash_password
from scoring import compute_risk, compute_sla_days


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _id() -> str:
    return str(uuid.uuid4())


SCANNERS = [
    {"name": "Qualys VMDR", "type": "infrastructure", "logo": "qualys"},
    {"name": "Tenable Nessus", "type": "infrastructure", "logo": "tenable"},
    {"name": "CrowdStrike Falcon Spotlight", "type": "endpoint", "logo": "crowdstrike"},
    {"name": "Microsoft Defender", "type": "endpoint", "logo": "microsoft"},
    {"name": "Wiz", "type": "cloud", "logo": "wiz"},
    {"name": "GitHub Advanced Security", "type": "appsec", "logo": "github"},
    {"name": "Snyk", "type": "appsec", "logo": "snyk"},
    {"name": "Manual / Pentest", "type": "manual", "logo": "manual"},
]


VULN_TEMPLATES = [
    {
        "title": "Apache Log4j Remote Code Execution (Log4Shell)",
        "cve": "CVE-2021-44228", "cwe": "CWE-502", "qid": "376160",
        "severity": "Critical", "cvss": 10.0, "epss": 0.97444, "kev": True,
        "rti": ["active_attacks", "public_exploit", "easy_exploit", "remote_code_execution", "wormable", "high_lateral_movement"],
        "mitre_tactic": "TA0001 Initial Access", "mitre_technique": "T1190 Exploit Public-Facing Application",
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
        "consequence": "An unauthenticated remote attacker can execute arbitrary code on the server, leading to full system compromise, lateral movement, data exfiltration, and ransomware deployment.",
        "business_impact": "Critical — affected systems can be fully compromised remotely. Active mass exploitation in the wild.",
        "remediation": "Upgrade Log4j to 2.17.1+. If immediate upgrade is impossible, set log4j2.formatMsgNoLookups=true or remove JndiLookup class from the classpath.",
        "detection_logic": "Qualys QID 376160: Authenticated scan checks installed Log4j version against vulnerable range using file fingerprint of org/apache/logging/log4j/core/lookup/JndiLookup.class.",
        "patch_available": True,
    },
    {
        "title": "OpenSSL Buffer Overrun in X.509 Email Address Verification",
        "cve": "CVE-2022-3602", "cwe": "CWE-121", "qid": "377564",
        "severity": "High", "cvss": 7.5, "epss": 0.0489, "kev": False,
        "rti": ["public_exploit", "remote_code_execution"],
        "mitre_tactic": "TA0002 Execution", "mitre_technique": "T1203 Exploitation for Client Execution",
        "description": "A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification.",
        "consequence": "An attacker can craft a malicious email address in a certificate to overflow four attacker-controlled bytes on the stack, potentially leading to crash or remote code execution.",
        "business_impact": "High — TLS/SSL services using vulnerable OpenSSL versions may be exploited.",
        "remediation": "Upgrade OpenSSL to 3.0.7 or later.",
        "detection_logic": "Nessus plugin 166684: Banner-based OpenSSL version detection, confirmed via installed package query on Linux endpoints.",
        "patch_available": True,
    },
    {
        "title": "Microsoft Exchange Server Remote Code Execution (ProxyNotShell)",
        "cve": "CVE-2022-41040", "cwe": "CWE-918", "qid": "50121",
        "severity": "Critical", "cvss": 8.8, "epss": 0.94221, "kev": True,
        "rti": ["active_attacks", "public_exploit", "remote_code_execution", "exploit_kit", "high_data_loss"],
        "mitre_tactic": "TA0001 Initial Access", "mitre_technique": "T1190 Exploit Public-Facing Application",
        "description": "A Microsoft Exchange Server remote code execution vulnerability. The attacker must be authenticated to exploit; chains with CVE-2022-41082.",
        "consequence": "Authenticated attacker can pivot to RCE, deploy webshells, exfiltrate mailboxes, and establish persistence inside the network.",
        "business_impact": "Critical — exposes corporate email, calendar, and identity data. Frequently chained with NTLM relay attacks.",
        "remediation": "Apply Exchange November 2022 security updates. Implement URL rewrite rules as interim mitigation.",
        "detection_logic": "Qualys QID 50121: Authenticated check of Exchange CU build number and security update KB installation status.",
        "patch_available": True,
    },
    {
        "title": "VMware vCenter Server File Upload Vulnerability",
        "cve": "CVE-2021-21972", "cwe": "CWE-434", "qid": "216266",
        "severity": "Critical", "cvss": 9.8, "epss": 0.97361, "kev": True,
        "rti": ["active_attacks", "public_exploit", "easy_exploit", "remote_code_execution", "unauthenticated"],
        "mitre_tactic": "TA0001 Initial Access", "mitre_technique": "T1190 Exploit Public-Facing Application",
        "description": "The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin.",
        "consequence": "An unauthenticated attacker with network access to port 443 may exploit this to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.",
        "business_impact": "Critical — full compromise of virtualization control plane.",
        "remediation": "Upgrade vCenter Server to 6.5 U3n, 6.7 U3l, or 7.0 U1c. Disable vRealize Operations plugin if patching is not possible.",
        "detection_logic": "Network-based unauthenticated probe of /ui/vropspluginui/rest/services/uploadova endpoint.",
        "patch_available": True,
    },
    {
        "title": "Spring Framework RCE via Data Binding (Spring4Shell)",
        "cve": "CVE-2022-22965", "cwe": "CWE-94", "qid": "730218",
        "severity": "Critical", "cvss": 9.8, "epss": 0.96891, "kev": True,
        "rti": ["active_attacks", "public_exploit", "easy_exploit", "remote_code_execution"],
        "mitre_tactic": "TA0001 Initial Access", "mitre_technique": "T1190 Exploit Public-Facing Application",
        "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.",
        "consequence": "Unauthenticated attacker writes a JSP webshell to the application root, achieving full RCE.",
        "business_impact": "Critical — Spring is ubiquitous in Java apps. Mass scanning observed within hours of disclosure.",
        "remediation": "Upgrade Spring Framework to 5.3.18 or 5.2.20+. Disable binding to disallowedFields=[class.*,Class.*,*.class.*,*.Class.*].",
        "detection_logic": "Authenticated check of installed spring-beans JAR version; supplemented by network probe sending crafted POST request.",
        "patch_available": True,
    },
    {
        "title": "OpenSSH User Enumeration",
        "cve": "CVE-2018-15473", "cwe": "CWE-203", "qid": "38738",
        "severity": "Medium", "cvss": 5.3, "epss": 0.4521, "kev": False,
        "rti": ["public_exploit"],
        "mitre_tactic": "TA0007 Discovery", "mitre_technique": "T1087 Account Discovery",
        "description": "OpenSSH through 7.7 is vulnerable to user enumeration via malformed packets in authentication requests.",
        "consequence": "Attacker can determine valid usernames, facilitating brute-force and credential-stuffing attacks against SSH services.",
        "business_impact": "Medium — supports reconnaissance phase of attacks against bastion hosts and Linux fleet.",
        "remediation": "Upgrade OpenSSH to 7.8 or later. Restrict SSH access with firewall rules.",
        "detection_logic": "Network banner grab of SSH service; version compared against vulnerable range.",
        "patch_available": True,
    },
    {
        "title": "TLS 1.0/1.1 Protocol Deprecation",
        "cve": None, "cwe": "CWE-326", "qid": "38628",
        "severity": "Medium", "cvss": 5.9, "epss": 0.012, "kev": False,
        "rti": [],
        "mitre_tactic": "TA0006 Credential Access", "mitre_technique": "T1040 Network Sniffing",
        "description": "The remote service accepts connections encrypted using TLS 1.0 or 1.1 which are deprecated and contain known cryptographic flaws.",
        "consequence": "Adversary with network position may downgrade TLS and exploit BEAST/POODLE-class weaknesses against encrypted traffic.",
        "business_impact": "Medium — fails PCI-DSS 4.0 and FedRAMP encryption baselines.",
        "remediation": "Disable TLS 1.0 and TLS 1.1. Allow only TLS 1.2 with strong ciphers and TLS 1.3.",
        "detection_logic": "Network probe sending TLS handshake with deprecated protocol versions.",
        "patch_available": True,
    },
    {
        "title": "Apache HTTP Server Path Traversal (CVE-2021-41773)",
        "cve": "CVE-2021-41773", "cwe": "CWE-22", "qid": "150441",
        "severity": "High", "cvss": 7.5, "epss": 0.97432, "kev": True,
        "rti": ["active_attacks", "public_exploit", "easy_exploit", "unauthenticated"],
        "mitre_tactic": "TA0001 Initial Access", "mitre_technique": "T1190 Exploit Public-Facing Application",
        "description": "A flaw in Apache HTTP Server 2.4.49 enables an attacker to map URLs outside of the documented document root.",
        "consequence": "Attacker may read arbitrary files, leak source code, and in some configurations achieve RCE via CGI execution.",
        "business_impact": "High — actively exploited; affects web tier on customer-facing properties.",
        "remediation": "Upgrade Apache HTTPD to 2.4.51 or later. Ensure 'Require all denied' is set on filesystem locations.",
        "detection_logic": "Network probe sending crafted URL with %2e%2e/ sequences to /icons/ alias.",
        "patch_available": True,
    },
    {
        "title": "Weak SSL Cipher Suites Supported",
        "cve": None, "cwe": "CWE-327", "qid": "38601",
        "severity": "Low", "cvss": 3.7, "epss": 0.005, "kev": False,
        "rti": [],
        "mitre_tactic": "TA0006 Credential Access", "mitre_technique": "T1040 Network Sniffing",
        "description": "The remote host supports the use of weak SSL ciphers (RC4, DES, NULL, EXPORT).",
        "consequence": "An attacker may exploit weak cryptography to decrypt or forge traffic against the service.",
        "business_impact": "Low — does not allow immediate compromise but violates baseline crypto policies.",
        "remediation": "Reconfigure the affected application to avoid using weak ciphers. Limit to AES-GCM and ChaCha20-Poly1305 suites.",
        "detection_logic": "Network probe enumerating supported cipher suites.",
        "patch_available": True,
    },
    {
        "title": "Hardcoded AWS Credentials in Repository",
        "cve": None, "cwe": "CWE-798", "qid": "GH-SECRET-AWS",
        "severity": "High", "cvss": 8.0, "epss": 0.0, "kev": False,
        "rti": ["high_data_loss"],
        "mitre_tactic": "TA0006 Credential Access", "mitre_technique": "T1552 Unsecured Credentials",
        "description": "GitHub secret scanning detected an AWS access key committed to the repository.",
        "consequence": "Anyone with repo access (potentially the public Internet if repo is public) can assume the AWS identity and access cloud resources.",
        "business_impact": "High — direct cloud blast radius. Rotation, audit, and access-key revocation required.",
        "remediation": "Revoke the AWS access key immediately. Rotate dependent secrets. Use IAM roles or short-lived credentials via OIDC.",
        "detection_logic": "GitHub Advanced Security secret scanning regex match for AKIA[0-9A-Z]{16}.",
        "patch_available": False,
    },
]


HOSTS = [
    ("web-prod-01", "10.0.10.11", "prod-web.acme.io", "production", "critical", "internet", "Linux", "Ubuntu 20.04", "Platform Eng"),
    ("web-prod-02", "10.0.10.12", "prod-web2.acme.io", "production", "critical", "internet", "Linux", "Ubuntu 20.04", "Platform Eng"),
    ("db-prod-01", "10.0.20.21", "db-prod.acme.io", "production", "crown_jewel", "internal", "Linux", "RHEL 8", "DBA Team"),
    ("api-prod-01", "10.0.30.31", "api.acme.io", "production", "critical", "internet", "Linux", "Amazon Linux 2", "Backend Team"),
    ("exchange-01", "10.0.40.41", "mail.acme.io", "production", "critical", "external", "Windows", "Windows Server 2019", "IT Ops"),
    ("vcenter-01", "10.0.50.51", "vcenter.acme.local", "production", "crown_jewel", "internal", "VMware", "vCenter 7.0", "Virtualization"),
    ("dev-jenkins-01", "10.0.60.61", "ci.acme.local", "development", "high", "dmz", "Linux", "Ubuntu 22.04", "DevOps"),
    ("workstation-024", "10.10.5.124", "ws-024.corp.acme", "corporate", "medium", "internal", "Windows", "Windows 11", "IT Helpdesk"),
    ("k8s-node-01", "10.0.70.71", "k8s01.acme.local", "production", "high", "internal", "Linux", "Bottlerocket", "Platform Eng"),
    ("fw-edge-01", "10.0.0.1", "fw-edge-01.acme.io", "production", "crown_jewel", "internet", "PaloAlto", "PAN-OS 10.2", "NetSec"),
    ("repo-payments", None, None, "production", "critical", "external", "Code", "GitHub Repo", "Payments Squad"),
    ("repo-platform", None, None, "production", "high", "external", "Code", "GitHub Repo", "Platform Eng"),
]


PRODUCTS = [
    ("Acme Payments Platform", "Payment processing services", "critical", "Payments Squad"),
    ("Acme Web Storefront", "Customer-facing e-commerce", "critical", "Frontend Guild"),
    ("Corporate IT Infrastructure", "Internal IT systems", "high", "IT Ops"),
    ("Data Platform", "Analytics and data lake", "high", "Data Eng"),
    ("Edge & Network", "Perimeter and network", "crown_jewel", "NetSec"),
]


async def seed_all(db):
    # If already seeded, skip
    if await db.users.count_documents({}) > 0 and await db.findings.count_documents({}) > 50:
        return

    # Wipe existing demo data (idempotent)
    for col in ["users", "api_keys", "assets", "products", "findings", "observations",
                "tickets", "exceptions", "engagements", "integrations", "import_jobs",
                "activity_log", "score_snapshots", "ownership_mappings", "comments",
                "assignment_rules", "user_sessions"]:
        await db[col].delete_many({})

    now = datetime.now(timezone.utc)

    # Users
    users = [
        {"id": _id(), "email": "admin@vulnops.io", "name": "Site Admin", "role": "admin", "team": None, "department": "Security", "password_hash": hash_password("admin123"), "created_at": iso(now)},
        {"id": _id(), "email": "analyst@vulnops.io", "name": "Alex Analyst", "role": "analyst", "team": "Platform Eng", "department": "Engineering", "password_hash": hash_password("analyst123"), "created_at": iso(now)},
        {"id": _id(), "email": "manager@vulnops.io", "name": "Morgan Manager", "role": "manager", "team": "Payments Squad", "department": "Engineering", "password_hash": hash_password("manager123"), "created_at": iso(now)},
        {"id": _id(), "email": "exec@vulnops.io", "name": "Erin Executive", "role": "executive", "team": None, "department": "Executive", "password_hash": hash_password("exec123"), "created_at": iso(now)},
    ]
    await db.users.insert_many(users)

    # Default assignment rules
    default_rules = [
        {"id": _id(), "name": "Internet-facing → NetSec", "priority": 10, "field": "exposure", "operator": "equals", "value": "internet", "assign_team": "NetSec", "active": True, "created_at": iso(now)},
        {"id": _id(), "name": "Crown jewel → DBA Team", "priority": 20, "field": "criticality", "operator": "equals", "value": "crown_jewel", "assign_team": "DBA Team", "active": True, "created_at": iso(now)},
        {"id": _id(), "name": "Windows hosts → IT Ops", "priority": 30, "field": "platform", "operator": "equals", "value": "Windows", "assign_team": "IT Ops", "active": True, "created_at": iso(now)},
        {"id": _id(), "name": "Code repos → Platform Eng", "priority": 40, "field": "platform", "operator": "equals", "value": "Code", "assign_team": "Platform Eng", "active": True, "created_at": iso(now)},
        {"id": _id(), "name": "Production Linux → Platform Eng", "priority": 50, "field": "environment", "operator": "equals", "value": "production", "assign_team": "Platform Eng", "active": True, "created_at": iso(now)},
    ]
    await db.assignment_rules.insert_many(default_rules)

    # API Keys
    await db.api_keys.insert_one({
        "id": _id(), "key": "vulnops_ingest_demo_key_2026", "name": "Default Ingestion Key",
        "active": True, "created_at": iso(now), "last_used_at": None,
    })

    # Products
    products = []
    for name, desc, crit, owner in PRODUCTS:
        products.append({
            "id": _id(), "name": name, "description": desc, "criticality": crit,
            "business_owner": owner, "technical_owner": owner, "tags": [crit, owner.lower().replace(" ", "-")],
            "environments": ["production", "staging"], "sla_profile": "default",
            "created_at": iso(now),
        })
    await db.products.insert_many(products)

    # Assets
    assets = []
    for hostname, ip, fqdn, env, crit, exp, platform, os_name, team in HOSTS:
        product = random.choice(products)
        asset_type = "code_repo" if platform == "Code" else ("network_device" if "PAN-OS" in (os_name or "") else ("workstation" if "Windows 11" in (os_name or "") else "server"))
        asset = {
            "id": _id(), "hostname": hostname, "fqdn": fqdn, "ip": ip,
            "environment": env, "criticality": crit, "exposure": exp,
            "platform": platform, "operating_system": os_name,
            "asset_type": asset_type,
            "owner_team": team, "business_owner": team, "technical_owner": team,
            "product_id": product["id"], "product_name": product["name"],
            "tags": [env, crit, team.lower().replace(" ", "-"), exp],
            "status": "active", "created_at": iso(now - timedelta(days=180)),
            "ownership_confidence": round(random.uniform(0.6, 1.0), 2),
            "ownership_rationale": f"Matched via tag rule: env={env}, team={team}",
        }
        assets.append(asset)
    await db.assets.insert_many(assets)

    # Integrations
    integrations = []
    for sc in SCANNERS:
        integrations.append({
            "id": _id(), "name": sc["name"], "type": sc["type"], "logo": sc["logo"],
            "status": random.choice(["healthy", "healthy", "healthy", "degraded", "healthy"]),
            "last_sync_at": iso(now - timedelta(hours=random.randint(1, 48))),
            "sync_errors": 0 if random.random() > 0.2 else random.randint(1, 5),
            "retry_count": 0,
            "config": {"endpoint": f"https://{sc['logo']}.example.com/api", "auth": "api_key"},
            "created_at": iso(now - timedelta(days=90)),
        })
    # Ticket/connector integrations
    for n, t, lg in [("Jira", "ticketing", "jira"), ("ServiceNow", "ticketing", "servicenow"),
                     ("GitHub", "vcs", "github"), ("GitLab", "vcs", "gitlab"), ("Azure DevOps", "vcs", "azure")]:
        integrations.append({
            "id": _id(), "name": n, "type": t, "logo": lg, "status": "healthy",
            "last_sync_at": iso(now - timedelta(hours=random.randint(1, 6))),
            "sync_errors": 0, "retry_count": 0,
            "config": {"endpoint": f"https://{lg}.example.com", "auth": "oauth"},
            "created_at": iso(now - timedelta(days=90)),
        })
    await db.integrations.insert_many(integrations)

    # Engagements (scan runs)
    engagements = []
    for i in range(8):
        scanner = random.choice(SCANNERS[:5])
        started = now - timedelta(days=random.randint(0, 14), hours=random.randint(0, 23))
        engagements.append({
            "id": _id(),
            "name": f"{scanner['name']} {('Weekly' if i % 2 else 'Daily')} Scan #{1000+i}",
            "scanner": scanner["name"], "scan_type": "authenticated" if i % 2 else "unauthenticated",
            "scan_method": "agent" if "Agent" in scanner["name"] or scanner["type"] == "endpoint" else "network",
            "started_at": iso(started), "finished_at": iso(started + timedelta(hours=2)),
            "status": "completed", "assets_scanned": random.randint(50, 500),
            "findings_created": random.randint(20, 80), "findings_updated": random.randint(10, 40),
        })
    await db.engagements.insert_many(engagements)

    # Findings
    findings = []
    observations = []
    tickets = []
    activity = []

    finding_count_target = 120
    for i in range(finding_count_target):
        tpl = VULN_TEMPLATES[i % len(VULN_TEMPLATES)]
        asset = random.choice(assets)
        scanner = random.choice(SCANNERS[:5])
        first_seen = now - timedelta(days=random.randint(0, 180))
        last_seen = first_seen + timedelta(days=random.randint(0, 30))

        # Status distribution
        rand = random.random()
        if rand < 0.45:
            status = "New" if (now - first_seen).days < 3 else "Valid"
            validation_status = "pending"
        elif rand < 0.55:
            status = "Needs triage"
            validation_status = "pending"
        elif rand < 0.65:
            status = "Fixed pending validation"
            validation_status = "pending_rescan"
        elif rand < 0.75:
            status = "Fixed validated"
            validation_status = "validated"
        elif rand < 0.82:
            status = "Accepted risk"
            validation_status = "n/a"
        elif rand < 0.88:
            status = "False positive"
            validation_status = "n/a"
        elif rand < 0.92:
            status = "Mitigated"
            validation_status = "validated"
        elif rand < 0.96:
            status = "Reopened"
            validation_status = "pending"
        else:
            status = "Duplicate"
            validation_status = "n/a"

        reopened = 1 if status == "Reopened" else 0

        sla_days = compute_sla_days(tpl["severity"], asset["criticality"])
        due_at = first_seen + timedelta(days=sla_days)

        finding = {
            "id": _id(),
            "canonical_key": f"{tpl['cve'] or tpl['qid']}::{asset['hostname']}",
            "source_observation_id": f"OBS-{random.randint(100000, 999999)}",
            "source_tool": scanner["name"], "source_tool_type": scanner["type"],
            "source_native_id": tpl["qid"],
            "qid": tpl["qid"] if "QID" not in tpl["qid"] and tpl["qid"].isdigit() else None,
            "plugin_id": tpl["qid"] if scanner["name"].startswith("Tenable") else None,
            "cve": tpl["cve"], "cwe": tpl["cwe"],
            "title": tpl["title"], "description": tpl["description"],
            "business_impact": tpl["business_impact"], "consequence": tpl["consequence"],
            "remediation": tpl["remediation"], "detection_logic": tpl["detection_logic"],
            "detection_summary": f"Detected on {asset['hostname']} by {scanner['name']}",
            "mitre_tactic": tpl["mitre_tactic"], "mitre_technique": tpl["mitre_technique"],
            "cvss_score": tpl["cvss"], "cvss_v3_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if tpl["cvss"] >= 9 else "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_v4_score": None,
            "severity": tpl["severity"], "epss_score": tpl["epss"], "epss_percentile": min(tpl["epss"] * 100, 99.9),
            "kev_flag": tpl["kev"], "rti": tpl["rti"],
            "internet_facing": asset["exposure"] in ("internet", "external"),
            "asset_id": asset["id"], "asset_hostname": asset["hostname"],
            "asset_ip": asset["ip"], "asset_criticality": asset["criticality"],
            "asset_exposure": asset["exposure"], "asset_environment": asset["environment"],
            "product_id": asset["product_id"], "product_name": asset["product_name"],
            "owner_team": asset["owner_team"], "assigned_to": None,
            "ownership_confidence": asset["ownership_confidence"],
            "compliance_scope": random.choice([["PCI-DSS"], ["SOC2"], ["PCI-DSS", "SOC2"], ["HIPAA"], []]),
            "patch_available": tpl["patch_available"], "workaround": None, "compensating_controls": None,
            "advisory_links": [f"https://nvd.nist.gov/vuln/detail/{tpl['cve']}"] if tpl["cve"] else [],
            "exploit_references": ["https://github.com/exploit-db/poc"] if tpl["kev"] else [],
            "evidence_attachments": [],
            "first_seen_at": iso(first_seen), "last_seen_at": iso(last_seen),
            "last_changed_at": iso(last_seen), "reopened_count": reopened,
            "due_at": iso(due_at), "sla_days": sla_days,
            "days_open": (now - first_seen).days, "days_to_assignment": None,
            "days_to_ticket": None, "days_to_remediation": None,
            "status": status, "validation_status": validation_status,
            "tags": asset["tags"], "scan_authenticated": True, "scan_method": scanner["type"],
            "detection_channel": "scanner_import", "parser_type": scanner["name"], "parser_version": "1.0",
            "imported_at": iso(last_seen),
        }
        # Compute risk score
        risk = compute_risk(finding, asset)
        finding["risk_score"] = risk["score"]
        finding["risk_breakdown"] = risk["breakdown"]
        findings.append(finding)

        # Observation
        observations.append({
            "id": _id(), "finding_id": finding["id"], "asset_id": asset["id"],
            "source_tool": scanner["name"], "source_record_id": finding["source_observation_id"],
            "qid": finding["qid"], "plugin_id": finding["plugin_id"],
            "detection_logic": finding["detection_logic"], "detection_summary": finding["detection_summary"],
            "scan_type": "authenticated", "scan_method": scanner["type"],
            "auth_state": "authenticated", "agent_or_network": "agent" if "Agent" in scanner["name"] else "network",
            "raw_severity": tpl["severity"], "normalized_severity": tpl["severity"],
            "observed_at": iso(last_seen), "imported_at": iso(last_seen),
        })

        # Tickets for some findings
        if status in ("Valid", "Fixed pending validation", "Fixed validated", "Reopened") and random.random() < 0.6:
            ticket_state = "in_progress" if status == "Valid" else ("done" if "Fixed" in status else "in_progress")
            tickets.append({
                "id": _id(), "finding_id": finding["id"], "asset_id": asset["id"],
                "external_id": f"VULN-{random.randint(1000, 9999)}",
                "system": random.choice(["Jira", "ServiceNow", "GitHub"]),
                "title": f"Remediate: {finding['title'][:60]}",
                "assignee": finding["owner_team"], "status": ticket_state,
                "created_at": iso(first_seen + timedelta(days=1)),
                "updated_at": iso(last_seen),
                "url": f"https://jira.example.com/browse/VULN-{random.randint(1000, 9999)}",
            })

        # Activity log
        activity.append({
            "id": _id(), "entity_type": "finding", "entity_id": finding["id"],
            "action": "created", "actor": "system", "timestamp": iso(first_seen),
            "details": f"Imported from {scanner['name']}",
        })
        if status in ("Fixed validated", "Mitigated"):
            activity.append({
                "id": _id(), "entity_type": "finding", "entity_id": finding["id"],
                "action": "status_changed", "actor": "analyst@vulnops.io",
                "timestamp": iso(last_seen),
                "details": f"Status: {status}",
            })

    await db.findings.insert_many(findings)
    await db.observations.insert_many(observations)
    if tickets:
        await db.tickets.insert_many(tickets)
    if activity:
        await db.activity_log.insert_many(activity)

    # Exceptions / risk acceptances
    exceptions = []
    for f in findings[:8]:
        if f["status"] == "Accepted risk":
            exceptions.append({
                "id": _id(), "finding_id": f["id"], "asset_id": f["asset_id"],
                "rationale": "Compensating control: WAF rule deployed blocking exploitation path. Patch scheduled for next maintenance window.",
                "approver": "manager@vulnops.io", "approved_at": iso(now - timedelta(days=10)),
                "expires_at": iso(now + timedelta(days=80)), "renewal_history": [],
                "compensating_controls": ["WAF rule WAF-2024-1142", "Network segmentation"],
                "evidence_files": [], "status": "active",
            })
    if exceptions:
        await db.exceptions.insert_many(exceptions)

    # Import jobs (recent ingestion history)
    import_jobs = []
    for i in range(10):
        started = now - timedelta(days=i, hours=random.randint(0, 23))
        scanner = random.choice(SCANNERS)
        created = random.randint(5, 80)
        updated = random.randint(10, 60)
        dedup = random.randint(20, 120)
        failed = 0 if random.random() > 0.15 else random.randint(1, 4)
        import_jobs.append({
            "id": _id(), "source_name": scanner["name"], "mode": "reimport" if i % 2 else "import",
            "status": "failed" if failed > 2 else "success", "request_id": f"req_{uuid.uuid4().hex[:12]}",
            "started_at": iso(started), "finished_at": iso(started + timedelta(minutes=random.randint(2, 30))),
            "created_count": created, "updated_count": updated, "deduplicated_count": dedup,
            "failed_count": failed, "retry_count": 0,
            "errors": [] if failed == 0 else [{"row": random.randint(1, 100), "error": "asset hostname missing"} for _ in range(failed)],
        })
    await db.import_jobs.insert_many(import_jobs)

    # Score snapshots (trend data)
    snapshots = []
    for d in range(30, 0, -1):
        date = now - timedelta(days=d)
        org_score = 72 + random.randint(-8, 8) + (30 - d) * 0.3
        snapshots.append({
            "id": _id(), "date": iso(date), "org_score": round(min(100, max(0, org_score)), 1),
            "open_critical": random.randint(8, 25), "open_high": random.randint(20, 60),
            "sla_compliance": round(random.uniform(78, 95), 1),
            "mttr_days": round(random.uniform(8, 22), 1),
        })
    await db.score_snapshots.insert_many(snapshots)
