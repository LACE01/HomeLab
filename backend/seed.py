"""Minimal seed — operational scaffolding only.

Seeds:
  - Super admin user
  - Default assignment rules
  - One Discord notification channel
  - One API ingest key
  - Connector integrations marked "not_configured" except those with explicit credentials

DOES NOT seed: findings, assets, observations, tickets, exceptions, engagements,
import_jobs, score_snapshots, comments, activity_log, rescoring_runs. Real data is pulled
live from connectors (Qualys VMDR is the first wired up; others require user-supplied keys).
Products gets a light starter seed (a few unassigned example records) since there is no
other way to populate that page until an admin assigns real assets to them.
"""
import uuid
from datetime import datetime, timezone

from auth_utils import hash_password


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _id() -> str:
    return str(uuid.uuid4())


SCANNERS = [
    {"name": "Qualys VMDR",                 "type": "infrastructure", "logo": "qualys"},
    {"name": "Tenable Nessus",              "type": "infrastructure", "logo": "tenable"},
    {"name": "CrowdStrike Falcon Spotlight","type": "endpoint",       "logo": "crowdstrike"},
    {"name": "Microsoft Defender",          "type": "endpoint",       "logo": "microsoft"},
    {"name": "Wiz",                         "type": "cloud",          "logo": "wiz"},
    {"name": "GitHub Advanced Security",    "type": "appsec",         "logo": "github"},
    {"name": "Snyk",                        "type": "appsec",         "logo": "snyk"},
]

WORKFLOW_CONNECTORS = [
    {"name": "Jira",          "type": "ticketing",    "logo": "jira"},
    {"name": "ServiceNow",    "type": "ticketing",    "logo": "servicenow"},
    {"name": "GitHub",        "type": "vcs",          "logo": "github"},
    {"name": "GitLab",        "type": "vcs",          "logo": "gitlab"},
    {"name": "Azure DevOps",  "type": "vcs",          "logo": "azure"},
    {"name": "OpenCTI",       "type": "threat_intel", "logo": "opencti"},
]

# Exposure/threat-intel enrichment connectors -- Shodan/Censys enrich asset exposure
# data (ports/services/flagged vulns) for internet-facing IPs; GreyNoise/AlienVault
# OTX/abuse.ch (ThreatFox) are on-demand lookup sources surfaced in the Recon & OSINT
# hub (see reconng.py's run_greynoise_lookup/run_otx_lookup/run_abusech_lookup),
# mirroring how OpenCTI is already wired up there. All need their own API key, entered
# here under Integrations, same as every other connector card.
ENRICHMENT_CONNECTORS = [
    {"name": "Shodan",   "type": "exposure_intel", "logo": "shodan",
     "default_config": {"endpoint": "https://api.shodan.io"}},
    {"name": "Censys",   "type": "exposure_intel", "logo": "censys",
     "default_config": {"endpoint": "https://api.platform.censys.io"}},
    {"name": "GreyNoise", "type": "threat_intel", "logo": "greynoise",
     "default_config": {"endpoint": "https://api.greynoise.io"}},
    {"name": "AlienVault OTX", "type": "threat_intel", "logo": "otx",
     "default_config": {"endpoint": "https://otx.alienvault.com"}},
    {"name": "abuse.ch (ThreatFox)", "type": "threat_intel", "logo": "abusech",
     "default_config": {"endpoint": "https://threatfox-api.abuse.ch"}},
]


# Demo data collections we must NEVER repopulate after wiping.
_DEMO_COLLECTIONS = (
    "findings", "observations", "tickets", "exceptions", "engagements",
    "import_jobs", "activity_log", "score_snapshots", "comments", "rescoring_runs",
    "assets", "products",
)


async def _ensure_user(db, now_iso_str: str):
    if await db.users.count_documents({}) > 0:
        return
    import os
    import secrets
    import logging
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        admin_password = secrets.token_urlsafe(16)
        logging.getLogger("vulnops.seed").warning(
            "ADMIN_PASSWORD not set - generated a random initial admin password. "
            "Set ADMIN_EMAIL / ADMIN_PASSWORD env vars for a predictable login. "
            "Generated password (save this now, it will not be shown again): %s",
            admin_password,
        )
    await db.users.insert_many([
        {"id": _id(), "email": admin_email, "name": "Admin",
         "role": "admin", "team": None, "department": "Security",
         "password_hash": hash_password(admin_password),
         "created_at": now_iso_str, "active": True},
    ])


async def _ensure_criticality_defaults(db, now_iso_str: str):
    if await db.criticality_rules.count_documents({}) == 0:
        from criticality import _default_rules
        await db.criticality_rules.insert_many(_default_rules(now_iso_str))
    if await db.criticality_config.count_documents({}) == 0:
        from criticality import DEFAULT_THRESHOLDS
        await db.criticality_config.insert_one({"thresholds": DEFAULT_THRESHOLDS, "created_at": now_iso_str})


async def _ensure_assignment_rules(db, now_iso_str: str):
    if await db.assignment_rules.count_documents({}) > 0:
        return
    await db.assignment_rules.insert_many([
        {"id": _id(), "name": "Internet-facing → NetSec",     "priority": 10, "field": "exposure",    "operator": "equals", "value": "internet",     "assign_team": "NetSec",       "active": True, "created_at": now_iso_str},
        {"id": _id(), "name": "Crown jewel → DBA Team",       "priority": 20, "field": "criticality", "operator": "equals", "value": "crown_jewel",  "assign_team": "DBA Team",     "active": True, "created_at": now_iso_str},
        {"id": _id(), "name": "Windows hosts → IT Ops",       "priority": 30, "field": "platform",    "operator": "equals", "value": "Windows",      "assign_team": "IT Ops",       "active": True, "created_at": now_iso_str},
        {"id": _id(), "name": "Code repos → Platform Eng",    "priority": 40, "field": "platform",    "operator": "equals", "value": "Code",         "assign_team": "Platform Eng", "active": True, "created_at": now_iso_str},
        {"id": _id(), "name": "Production Linux → Platform Eng", "priority": 50, "field": "environment", "operator": "equals", "value": "production", "assign_team": "Platform Eng", "active": True, "created_at": now_iso_str},
    ])


async def _ensure_notification_channel(db, now_iso_str: str):
    """SECURITY NOTE: this used to insert a real, live Discord webhook URL hardcoded
    directly in source (already committed to git history) -- the same class of bug as
    the hardcoded admin password fixed earlier. Anyone with read access to that repo
    could have posted to that Discord channel. That webhook should be treated as
    compromised: regenerate it in Discord's channel integration settings (this deletes
    the old one). Going forward, a channel is only seeded if DISCORD_WEBHOOK_URL (or a
    generic NOTIFY_WEBHOOK_URL) is set in the environment -- nothing sensitive lives in
    source anymore."""
    if await db.notification_channels.count_documents({}) > 0:
        return
    import os
    webhook = os.environ.get("DISCORD_WEBHOOK_URL")
    if webhook:
        await db.notification_channels.insert_one({
            "id": _id(), "name": "Discord #vulnops", "type": "discord",
            "webhook_url": webhook, "enabled": True, "created_at": now_iso_str,
        })
    # else: no default channel. Set one up from Admin > Notification Channels.


async def _ensure_api_key(db, now_iso_str: str):
    if await db.api_keys.count_documents({}) > 0:
        return
    # Randomly generated per-deployment (not a hardcoded/guessable value) -- an earlier
    # version of this seed used a fixed string ("vulnops_ingest_demo_key_2026") that
    # ended up published in the public repo source, which defeats the point of an API
    # key. Existing deployments that already have that key seeded won't be silently
    # rotated (would break anything already configured to push with it) -- rotate it
    # yourself from Admin > API Keys > Regenerate if you're on an older seed.
    import secrets
    await db.api_keys.insert_one({
        "id": _id(), "key": f"vulnops_{secrets.token_urlsafe(32)}",
        "name": "Default Ingestion Key", "active": True,
        "created_at": now_iso_str, "last_used_at": None,
    })


async def _ensure_products(db, now_iso_str: str):
    """A handful of starter Business Service / Product records so the Products page
    isn't empty on a fresh install. These are unassigned shells -- admins attach real
    assets to them from the Products or Assets page (POST /v1/assets/{id}/product)."""
    if await db.products.count_documents({}) > 0:
        return
    starters = [
        {"name": "Citizen Portal", "description": "Public-facing web portal for resident services.",
         "business_owner": "Digital Services", "criticality": "crown_jewel",
         "sla_profile": "expedited", "environments": ["production"]},
        {"name": "Internal ERP", "description": "Finance, HR, and procurement system of record.",
         "business_owner": "IT Ops", "criticality": "critical",
         "sla_profile": "standard", "environments": ["production", "staging"]},
        {"name": "Email & Collaboration", "description": "Mail, calendaring, and file sharing infrastructure.",
         "business_owner": "IT Ops", "criticality": "critical",
         "sla_profile": "standard", "environments": ["production"]},
    ]
    await db.products.insert_many([
        {"id": _id(), **s, "created_at": now_iso_str} for s in starters
    ])


async def _ensure_playbooks(db, now_iso_str: str):
    """A library of playbooks for the vuln classes that show up in almost every
    environment. CWE-level playbooks apply to every finding of that weakness class
    until someone attaches a more specific CVE-level playbook. `category` drives the
    icon/color used on the Playbooks board.

    Inserted per-title rather than gated on "collection is empty" so re-running seed
    (e.g. after an upgrade) fills in newly-added playbooks without duplicating ones
    an admin may have already edited."""
    starters = [
        {
            "title": "Remote Code Execution via unpatched OS component",
            "category": "patching",
            "description": "General playbook for critical Windows/Linux OS-level RCE findings (missing security update).",
            "cve": None, "cwe": "CWE-787",
            "steps": [
                "Confirm the affected package/component and installed version against the advisory.",
                "Snapshot or take a backup of the asset (or its config) before patching.",
                "Apply the vendor security update via your patch management tool (WSUS/SCCM, yum/apt, etc.) in a maintenance window.",
                "Reboot if the update requires it, and confirm the service comes back healthy.",
                "Re-scan the asset to confirm the finding no longer reports vulnerable.",
            ],
            "rollback_notes": "If the patch breaks a dependent service, restore from the pre-patch snapshot/backup and re-open this finding with 'Deferred' status pending vendor guidance or a hotfix.",
            "validation_checks": [
                "Vulnerability scanner no longer flags the CVE on this asset.",
                "Affected service starts cleanly and passes its health check.",
                "No new errors in the service's logs in the 24h after patching.",
            ],
        },
        {
            "title": "SQL Injection remediation",
            "category": "appsec",
            "description": "Playbook for CWE-89 findings in first-party web applications.",
            "cve": None, "cwe": "CWE-89",
            "steps": [
                "Identify the vulnerable query/endpoint from the scanner's proof-of-concept request.",
                "Replace string-concatenated SQL with parameterized queries / prepared statements.",
                "Add input validation on the affected parameter(s) as defense in depth.",
                "Deploy the fix through your normal CI/CD pipeline with code review.",
                "Re-run the scanner (or the specific test case) against the patched endpoint.",
            ],
            "rollback_notes": "Revert the deploy via your standard rollback process if the fix breaks functionality; the finding stays open until a corrected fix ships.",
            "validation_checks": [
                "Automated scanner no longer reproduces the injection.",
                "Manual test with a known payload (e.g. ' OR '1'='1) returns a safe response.",
                "Existing unit/integration tests for the endpoint still pass.",
            ],
        },
        {
            "title": "Cross-Site Scripting (XSS) remediation",
            "category": "appsec",
            "description": "Playbook for CWE-79 findings — reflected, stored, or DOM-based XSS in web applications.",
            "cve": None, "cwe": "CWE-79",
            "steps": [
                "Identify the vulnerable input, sink, and output context from the scanner's proof-of-concept.",
                "Apply context-aware output encoding (HTML, attribute, JS, or URL encoding as appropriate).",
                "Add or tighten a Content-Security-Policy header to limit inline script execution as defense in depth.",
                "Deploy the fix through your normal CI/CD pipeline with code review.",
                "Re-run the scanner or the known payload against the patched page/endpoint.",
            ],
            "rollback_notes": "Revert the deploy via your standard rollback process if encoding changes break legitimate rendering; keep the finding open until a corrected fix ships.",
            "validation_checks": [
                "Scanner no longer reproduces the XSS payload.",
                "Manual test with a benign alert() payload confirms it no longer executes.",
                "CSP header is present and doesn't allow 'unsafe-inline' for scripts.",
            ],
        },
        {
            "title": "Exposed credentials / hardcoded secrets",
            "category": "identity",
            "description": "Playbook for CWE-798 — API keys, passwords, or tokens committed to source, config files, or container images.",
            "cve": None, "cwe": "CWE-798",
            "steps": [
                "Treat the exposed credential as compromised immediately — do not wait for remediation to rotate it.",
                "Rotate/revoke the secret at the source system (IdP, cloud provider, database, third-party API).",
                "Remove the secret from source control history (not just the latest commit) or rebuild the image without it.",
                "Move the credential to a secrets manager (Vault, AWS Secrets Manager, etc.) or environment-injected config.",
                "Audit access/usage logs for the exposed credential's window of exposure for signs of misuse.",
            ],
            "rollback_notes": "If rotation breaks a dependent integration, coordinate a synchronized credential update on both sides rather than reverting to the old secret.",
            "validation_checks": [
                "Old credential no longer authenticates against the source system.",
                "Secret scanning tool no longer flags the repo/image.",
                "No suspicious activity found in the exposure-window audit log review.",
            ],
        },
        {
            "title": "Publicly exposed cloud storage bucket",
            "category": "cloud",
            "description": "Playbook for misconfigured object storage (S3/Blob/GCS) with public read or write access.",
            "cve": None, "cwe": "CWE-284",
            "steps": [
                "Determine what data is in the bucket/container and whether it's sensitive (classify before acting).",
                "Restrict the bucket policy/ACL to remove public access; scope access to specific roles or a private endpoint.",
                "If sensitive data was exposed, treat it as a potential breach and follow your incident response / disclosure process.",
                "Enable access logging and versioning on the bucket if not already on, to support future audits.",
                "Add the bucket to automated policy-as-code scanning so this can't silently reoccur.",
            ],
            "rollback_notes": "If a legitimate integration relied on public access, replace it with signed URLs or a scoped service-account role rather than reopening public access.",
            "validation_checks": [
                "Cloud security posture scanner confirms the bucket is no longer publicly accessible.",
                "Anonymous request to the bucket/object returns access denied.",
                "Policy-as-code guardrail is in place to catch regressions.",
            ],
        },
        {
            "title": "Outdated TLS / weak cryptography",
            "category": "crypto",
            "description": "Playbook for CWE-327 — deprecated TLS versions (SSLv3/TLS1.0/1.1), weak cipher suites, or weak key sizes.",
            "cve": None, "cwe": "CWE-327",
            "steps": [
                "Confirm the current TLS version/cipher configuration on the affected service.",
                "Update the web server / load balancer TLS config to require TLS 1.2+ with modern cipher suites.",
                "Disable legacy protocol support (SSLv3, TLS 1.0/1.1) and weak ciphers (RC4, export-grade, NULL).",
                "Reload/restart the affected service in a maintenance window and confirm client compatibility.",
                "Re-scan with an SSL/TLS analyzer (e.g. testssl.sh) to confirm the weak configuration is gone.",
            ],
            "rollback_notes": "If a legacy client breaks after the change, add a time-boxed exception for that client rather than reverting the whole service to weak TLS.",
            "validation_checks": [
                "TLS scanner reports no support for deprecated protocols or weak ciphers.",
                "Certificate and handshake still validate correctly for supported clients.",
                "No spike in client connection failures after the change.",
            ],
        },
        {
            "title": "Server-Side Request Forgery (SSRF) remediation",
            "category": "appsec",
            "description": "Playbook for CWE-918 findings where an application can be tricked into making requests to internal/unintended destinations.",
            "cve": None, "cwe": "CWE-918",
            "steps": [
                "Identify the vulnerable parameter/feature that accepts a URL or triggers an outbound request.",
                "Implement an allow-list of permitted destination hosts/schemes instead of a deny-list.",
                "Block requests to internal/link-local address ranges (169.254.0.0/16, RFC1918, cloud metadata endpoints) at the app layer.",
                "Add network-level egress filtering from the application tier as defense in depth.",
                "Deploy the fix and re-run the scanner's SSRF probes against the endpoint.",
            ],
            "rollback_notes": "If the allow-list breaks a legitimate integration, add that specific destination to the allow-list rather than removing the filter.",
            "validation_checks": [
                "Scanner can no longer reach internal targets or the cloud metadata endpoint via the vulnerable parameter.",
                "Legitimate outbound integrations still function.",
                "Egress logs show the block taking effect for out-of-allow-list attempts.",
            ],
        },
        {
            "title": "Privilege escalation / improper access control",
            "category": "identity",
            "description": "Playbook for CWE-269 findings — a user or service can reach functionality or data beyond their intended privilege level.",
            "cve": None, "cwe": "CWE-269",
            "steps": [
                "Reproduce the escalation path from the scanner/pentest finding to confirm the exact broken check.",
                "Add or fix the server-side authorization check (never rely on client-side/UI hiding alone).",
                "Apply least-privilege review to the affected role/service account definitions.",
                "Deploy the fix through your normal CI/CD pipeline with code review from a second engineer.",
                "Re-test with a low-privilege account to confirm the escalation path is closed.",
            ],
            "rollback_notes": "Revert via your standard rollback process if the authorization fix blocks legitimate access; keep the finding open until a corrected fix ships.",
            "validation_checks": [
                "Low-privilege test account can no longer reach the restricted function/data.",
                "Legitimate privileged workflows still work end-to-end.",
                "Access control test case added to the regression suite.",
            ],
        },
        {
            "title": "Default or weak credentials",
            "category": "identity",
            "description": "Playbook for assets/services found running with vendor-default, blank, or trivially guessable credentials.",
            "cve": None, "cwe": "CWE-521",
            "steps": [
                "Confirm which account(s) are using default/weak credentials and what they have access to.",
                "Rotate the credential immediately to a strong, unique value (or disable the account if unused).",
                "Enforce a password policy (length/complexity/rotation) or move the service to key-based/SSO auth where possible.",
                "Check access logs for the account's history for signs of unauthorized use.",
                "Add the asset/service to a periodic default-credential scan so this doesn't silently recur.",
            ],
            "rollback_notes": "If disabling the account breaks an automated integration, rotate to a strong credential and update the integration's config rather than leaving the default in place.",
            "validation_checks": [
                "Login attempt with the old default/weak credential fails.",
                "Account now meets password policy or uses key-based/SSO auth.",
                "No suspicious activity found in the account's access log review.",
            ],
        },
        {
            "title": "Known-exploited CVE in a third-party / open-source component",
            "category": "patching",
            "description": "General playbook for CVEs in vendored libraries or dependencies, especially ones on the CISA KEV list. Matches by CWE-1104 (use of unmaintained third-party components) when no CVE-specific playbook exists.",
            "cve": None, "cwe": "CWE-1104",
            "steps": [
                "Check whether the CVE is CISA KEV-listed or has public exploit code — treat those as top priority regardless of CVSS.",
                "Identify the exact dependency version pulling in the vulnerable component (direct or transitive).",
                "Upgrade to the patched version, or apply the vendor's documented mitigation if no patch exists yet.",
                "Run your test suite / staging validation before promoting to production.",
                "Re-scan (SCA/vulnerability scanner) to confirm the CVE no longer resolves against the deployed version.",
            ],
            "rollback_notes": "If the upgrade introduces a breaking change, pin to the latest patched version within the same major line, or apply the vendor's interim mitigation while a compatibility fix is planned.",
            "validation_checks": [
                "SCA/vulnerability scanner no longer flags the CVE for this component.",
                "Application starts and passes smoke tests on the upgraded dependency.",
                "No new CVEs introduced by the version bump (check the diff).",
            ],
        },
        {
            "title": "Insecure deserialization",
            "category": "appsec",
            "description": "Playbook for CWE-502 findings — untrusted data deserialized into objects, enabling remote code execution or object injection.",
            "cve": None, "cwe": "CWE-502",
            "steps": [
                "Identify the deserialization sink and confirm whether the input is attacker-controlled.",
                "Switch to a safe data format (JSON with a strict schema) instead of native object serialization where possible.",
                "If native deserialization must stay, implement type allow-listing so only expected classes can be instantiated.",
                "Patch the deserialization library to the latest version, since many gadgets rely on library-specific bugs.",
                "Deploy the fix and re-run the scanner's deserialization payloads against the endpoint.",
            ],
            "rollback_notes": "Revert via your standard rollback process if the schema/allow-list change breaks a legitimate integration; keep the finding open until a corrected fix ships.",
            "validation_checks": [
                "Known deserialization payload no longer executes or errors safely.",
                "Legitimate serialized payloads still deserialize correctly.",
                "Deserialization library is on a patched version.",
            ],
        },
        {
            "title": "Broken authentication / session management",
            "category": "identity",
            "description": "Playbook for CWE-287 findings — weak session tokens, missing session expiry, or authentication bypass.",
            "cve": None, "cwe": "CWE-287",
            "steps": [
                "Confirm the specific weakness: predictable/long-lived session tokens, missing re-auth on sensitive actions, or a bypass path.",
                "Regenerate session tokens on login and privilege change; use a cryptographically secure random generator.",
                "Set appropriate session expiry/idle timeout and invalidate sessions server-side on logout.",
                "Require re-authentication for sensitive actions (password change, payment, admin actions).",
                "Deploy the fix and re-test the specific bypass/weakness that was reported.",
            ],
            "rollback_notes": "Revert via your standard rollback process if session changes lock out legitimate users; keep the finding open until a corrected fix ships.",
            "validation_checks": [
                "Session tokens are unpredictable and rotate on privilege change.",
                "Idle/expired sessions are rejected server-side.",
                "The originally reported bypass no longer works.",
            ],
        },
        {
            "title": "Path traversal remediation",
            "category": "appsec",
            "description": "Playbook for CWE-22 findings — user-controlled file paths allowing access outside the intended directory.",
            "cve": None, "cwe": "CWE-22",
            "steps": [
                "Identify the vulnerable parameter and confirm the traversal payload from the scanner's proof-of-concept.",
                "Resolve the requested path and verify it stays within an allow-listed base directory before use.",
                "Reject path input containing traversal sequences (../, encoded variants) rather than trying to sanitize them.",
                "Deploy the fix through your normal CI/CD pipeline with code review.",
                "Re-run the scanner (or the specific payload) against the patched endpoint.",
            ],
            "rollback_notes": "Revert via your standard rollback process if the base-directory check breaks legitimate file access; keep the finding open until a corrected fix ships.",
            "validation_checks": [
                "Scanner no longer reproduces the traversal.",
                "Manual test with a traversal payload (e.g. ../../etc/passwd) returns a safe response.",
                "Legitimate file access for the feature still works.",
            ],
        },
        {
            "title": "Missing security headers / clickjacking exposure",
            "category": "appsec",
            "description": "Playbook for CWE-693 findings — missing X-Frame-Options/CSP frame-ancestors, HSTS, or other protective headers.",
            "cve": None, "cwe": "CWE-693",
            "steps": [
                "Confirm which headers are missing via the scanner report or a manual response header check.",
                "Add X-Frame-Options (or CSP frame-ancestors) to prevent clickjacking on pages handling sensitive actions.",
                "Add Strict-Transport-Security, X-Content-Type-Options, and a baseline Content-Security-Policy.",
                "Deploy the header changes (often at the reverse proxy/load balancer, not the app) in a maintenance window.",
                "Re-scan to confirm all expected headers are now present on the affected responses.",
            ],
            "rollback_notes": "If a strict CSP breaks page functionality, relax it incrementally (report-only mode first) rather than removing it entirely.",
            "validation_checks": [
                "Response headers include the expected security headers.",
                "Framing test confirms the page can no longer be embedded from an untrusted origin.",
                "No functional regressions from the CSP on the affected pages.",
            ],
        },
    ]
    for s in starters:
        exists = await db.playbooks.find_one({"title": s["title"]})
        if exists:
            continue
        await db.playbooks.insert_one({"id": _id(), **s, "created_at": now_iso_str, "created_by": "system"})

async def _ensure_integrations(db, now_iso_str: str):
    """Insert any missing connector cards; do NOT clobber existing config rows."""
    existing = {i["name"] async for i in db.integrations.find({}, {"_id": 0, "name": 1})}
    to_insert = []
    for sc in SCANNERS + WORKFLOW_CONNECTORS + ENRICHMENT_CONNECTORS:
        if sc["name"] in existing:
            continue
        to_insert.append({
            "id": _id(), "name": sc["name"], "type": sc["type"], "logo": sc["logo"],
            "status": "not_configured",
            "last_sync_at": None, "sync_errors": 0, "retry_count": 0,
            # A pre-filled default endpoint (fixed, public API hosts) saves the user
            "config": dict(sc.get("default_config") or {}),
            "created_at": now_iso_str,
        })
    if to_insert:
        await db.integrations.insert_many(to_insert)


# Two intentionally small, safe example rules so the YARA pipeline is provably working
# the moment the Rules tab is opened -- not a real detection rule pack (see yara_scan.py
# docstring for why one isn't bundled). EICAR is the industry-standard harmless AV test
# string; the webshell heuristic is a generic, commonly-published pattern, not a real
# vendor signature.
YARA_STARTER_RULES = [
    {
        "name": "EICAR Test File (starter rule)",
        "description": "Detects the standard EICAR antivirus test string. Not malware -- a harmless "
                        "file used to verify a scanner actually fires. Upload a file containing the "
                        "EICAR string (search 'eicar test file string' for the exact text) to confirm "
                        "this pipeline works end to end.",
        "source": r"""rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test string -- confirms the scan pipeline works"
        severity = "Low"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
""",
        "enabled": True,
    },
    {
        "name": "Generic PHP webshell heuristic (starter rule)",
        "description": "Broad heuristic for a common webshell shape (eval/system/exec called on "
                        "user-controlled input, often base64-wrapped). Meant as a starting point to "
                        "replace or refine, not a production-grade signature -- expect some false "
                        "positives on legitimate code that happens to combine these primitives.",
        "source": r"""rule Generic_PHP_Webshell_Heuristic
{
    meta:
        description = "Eval/system/exec on request-controlled input -- common webshell shape"
        severity = "High"
    strings:
        $exec1 = "eval(" nocase
        $exec2 = "system(" nocase
        $exec3 = "exec(" nocase
        $exec4 = "shell_exec(" nocase
        $src1 = "$_REQUEST"
        $src2 = "$_POST"
        $src3 = "$_GET"
        $enc = "base64_decode(" nocase
    condition:
        1 of ($exec*) and 1 of ($src*) and $enc
}
""",
        "enabled": True,
    },
]


async def _ensure_yara_rules(db, now_iso_str: str):
    for r in YARA_STARTER_RULES:
        exists = await db.yara_rules.find_one({"name": r["name"]})
        if exists:
            continue
        await db.yara_rules.insert_one({
            "id": _id(), **r, "valid": True, "compile_error": None,
            "created_at": now_iso_str, "created_by": "system",
        })


async def seed_all(db):
    """Idempotent operational scaffolding seed. Safe to call on every startup."""
    now_iso_str = iso(datetime.now(timezone.utc))
    await _ensure_user(db, now_iso_str)
    await _ensure_assignment_rules(db, now_iso_str)
    await _ensure_notification_channel(db, now_iso_str)
    await _ensure_api_key(db, now_iso_str)
    await _ensure_integrations(db, now_iso_str)
    await _ensure_yara_rules(db, now_iso_str)
    await _ensure_products(db, now_iso_str)
    await _ensure_playbooks(db, now_iso_str)
    await _ensure_criticality_defaults(db, now_iso_str)


async def wipe_demo_data(db) -> dict:
    """Delete every collection that holds demo / live operational data.
    Returns a count of deleted documents per collection."""
    deleted: dict = {}
    for col in _DEMO_COLLECTIONS:
        res = await db[col].delete_many({})
        deleted[col] = res.deleted_count
    return deleted
