"""Feature flags -- lets an admin turn specific optional behaviors on or off from
the UI without a code change or redeploy. Every flag defaults to ON (matching this
app's behavior before flags existed at all) -- this is an opt-OUT mechanism for
behaviors a given deployment might find too noisy, too aggressive, or simply
unwanted, not an opt-in gate hiding half-finished functionality.

Storage: db.feature_flags, one doc per key that's ever been explicitly set (never
pre-seeded with every registry entry -- a flag with no stored doc just means
"still at its default"). FLAG_REGISTRY is the single source of truth for what
flags exist, their labels/descriptions/grouping, and their default -- add a new
togglable behavior by adding an entry here and gating the relevant code path with
is_enabled(), nothing else needs to change.
"""
from datetime import datetime, timezone

FLAG_REGISTRY = [
    {"key": "vendor_detect_hardware", "group": "Vendor Detection", "default": True,
     "label": "Detect vendors from asset hardware",
     "description": "Suggests a vendor candidate from each asset's hardware_info manufacturer (e.g. \"HP\", \"Dell\")."},
    {"key": "vendor_detect_os", "group": "Vendor Detection", "default": True,
     "label": "Detect vendors from asset OS",
     "description": "Suggests a vendor candidate from each asset's operating system (e.g. Windows -> Microsoft)."},
    {"key": "vendor_detect_findings", "group": "Vendor Detection", "default": True,
     "label": "Detect vendors from vulnerability findings",
     "description": "Suggests a vendor candidate when a finding's title or SBOM component name names a known software publisher (e.g. \"Adobe Acrobat Reader DC Multiple Vulnerabilities\")."},
    {"key": "vendor_detect_edr_software", "group": "Vendor Detection", "default": True,
     "label": "Detect vendors from EDR software inventory",
     "description": "Suggests a vendor candidate from real per-device installed software reported by Microsoft Defender for Endpoint, when configured."},
    {"key": "hibp_domain_nightly_sync", "group": "Scheduled Syncs", "default": True,
     "label": "Nightly HaveIBeenPwned domain breach check",
     "description": "Automatically checks your org's verified domain against HIBP every night, when HaveIBeenPwned is configured."},
    {"key": "security_news_nightly_sync", "group": "Scheduled Syncs", "default": True,
     "label": "Nightly security news sync",
     "description": "Automatically refreshes cached articles from BleepingComputer/Krebs/The Hacker News/Dark Reading/SecurityWeek every 12 hours."},
    {"key": "albert_allowlist_nightly_review", "group": "Scheduled Syncs", "default": True,
     "label": "Nightly Albert allowlist review sweep",
     "description": "Automatically checks for allowlist entries past their review date and re-applies suppression. Manual allowlist management is unaffected either way."},
    {"key": "ueba_login_anomaly_detection", "group": "Detection Behaviors", "default": True,
     "label": "Login anomaly detection (UEBA)",
     "description": "Flags a new IP, new country, or impossible-travel pattern on a user's login to this app."},
    {"key": "auto_hash_virustotal_check", "group": "Detection Behaviors", "default": True,
     "label": "Automatic VirusTotal hash reputation checks",
     "description": "Automatically checks every YARA-scanned file's hash against VirusTotal (in addition to your local rules and IOC watchlist) and runs a small nightly backlog sweep for hashes scanned before VirusTotal was configured."},
    {"key": "hibp_stealer_log_nightly_sync", "group": "Scheduled Syncs", "default": True,
     "label": "Nightly HaveIBeenPwned stealer-log check",
     "description": "Automatically checks your org's verified domain for stealer-log-exposed credentials every night, when HaveIBeenPwned is configured."},
    {"key": "scheduled_report_delivery", "group": "Scheduled Syncs", "default": True,
     "label": "Scheduled report delivery",
     "description": "Sends any reports configured under Admin -> Reports on their configured schedule (daily/weekly/monthly). Individual reports can still be paused independently."},
    {"key": "email_auth_nightly_check", "group": "Scheduled Syncs", "default": True,
     "label": "Nightly SPF/DKIM/DMARC domain check",
     "description": "Automatically re-checks every watched domain's email authentication records once a day and raises/clears findings on change."},
    {"key": "eol_nightly_check", "group": "Scheduled Syncs", "default": True,
     "label": "Nightly end-of-life software check",
     "description": "Automatically re-checks every watched product/cycle against endoflife.date once a day and raises/clears findings on change."},
    {"key": "container_image_nightly_scan", "group": "Scheduled Syncs", "default": True,
     "label": "Nightly container image scan",
     "description": "Automatically re-scans every watched container image once a day (new CVEs get published against unchanged image tags constantly) and raises/clears findings on change."},
    {"key": "secrets_scan_nightly_check", "group": "Scheduled Syncs", "default": True,
     "label": "Nightly secrets/credential leak scan",
     "description": "Automatically re-scans every watched git repository once a day for hardcoded credentials and raises/clears findings on change."},
    {"key": "tenable_nightly_sync", "group": "Scheduled Syncs", "default": True,
     "label": "Nightly Tenable Nessus sync",
     "description": "Automatically pulls the latest completed scan results from Tenable Nessus every hour, when configured. Manual \"Sync now\" from Integrations is unaffected either way."},
]
FLAG_KEYS = {f["key"] for f in FLAG_REGISTRY}
FLAG_BY_KEY = {f["key"]: f for f in FLAG_REGISTRY}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def is_enabled(db, key: str) -> bool:
    """Reads one flag's current value. An unknown key (typo, or a flag that's
    since been removed from the registry) fails OPEN -- returns True -- so a
    stale/bad key can never silently disable a behavior nobody actually meant to
    turn off."""
    default = FLAG_BY_KEY.get(key, {}).get("default", True)
    doc = await db.feature_flags.find_one({"key": key}, {"_id": 0, "enabled": 1})
    if doc is None:
        return default
    return bool(doc.get("enabled", default))


async def get_all_flags(db) -> list:
    overrides = {}
    async for d in db.feature_flags.find({}, {"_id": 0}):
        overrides[d["key"]] = d
    out = []
    for f in FLAG_REGISTRY:
        override = overrides.get(f["key"])
        out.append({
            **f,
            "enabled": override["enabled"] if override else f["default"],
            "updated_at": override.get("updated_at") if override else None,
            "updated_by": override.get("updated_by") if override else None,
        })
    return out


async def set_flag(db, key: str, enabled: bool, actor: str) -> dict:
    if key not in FLAG_KEYS:
        raise ValueError(f"Unknown feature flag: {key}")
    doc = {"key": key, "enabled": enabled, "updated_at": _now_iso(), "updated_by": actor}
    await db.feature_flags.update_one({"key": key}, {"$set": doc}, upsert=True)
    return {**FLAG_BY_KEY[key], **doc}
