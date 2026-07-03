"""Nikto web-application scanner integration -- mirrors the trust model and execution
pattern already established for active Nmap scans (nmap_scan.py / routes/nmap.py):
VulnOps shells out to a real scanner binary against targets you explicitly configure
and authorize, parses the results, and turns them into findings. Same reasoning
applies here as it does for Nmap -- this makes the container originate real HTTP
traffic against the target, so every config requires an explicit authorization
checkbox, execution always goes through asyncio.create_subprocess_exec (argv list,
never a shell), and there's a hard timeout.

Nikto covers the class of web-application-layer issues Nmap/Qualys-style scanners
don't really get at -- missing security headers, dangerous HTTP methods, outdated
server banners, default/interesting files, etc. -- which is why the web team asked
for it specifically as a complement to the infra-focused scanners already wired up.
"""
import asyncio
import json
import re
import shlex
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from scoring import compute_risk, compute_sla_days

URL_RE = re.compile(r"^https?://[a-zA-Z0-9][a-zA-Z0-9\-.]*(:\d{1,5})?(/.*)?$")


def validate_target_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("Target URL is required")
    if not URL_RE.match(url):
        raise ValueError(f"'{url}' doesn't look like a valid http(s) URL (e.g. https://app.example.com)")
    return url


# Keyword-based severity + CWE classification for Nikto's free-text finding messages.
# Nikto doesn't emit CVE/CWE/CVSS itself -- these are the standard security-header and
# HTTP-hygiene issues it's built to catch, matched by the substrings Nikto's own
# database consistently uses in its messages.
CLASSIFY_RULES = [
    # (substring to match in the message, lowercase, severity, cwe, short title)
    ("x-frame-options", "Low", "CWE-1021", "Missing X-Frame-Options header (clickjacking)"),
    ("x-content-type-options", "Low", "CWE-16", "Missing X-Content-Type-Options header"),
    ("strict-transport-security", "Low", "CWE-319", "Missing HTTP Strict-Transport-Security (HSTS) header"),
    ("content-security-policy", "Low", "CWE-1021", "Missing Content-Security-Policy header"),
    ("trace", "Medium", "CWE-16", "HTTP TRACE method enabled"),
    ("put", "Medium", "CWE-16", "HTTP PUT method enabled"),
    ("options", "Low", "CWE-16", "Verbose HTTP OPTIONS response"),
    ("shellshock", "Critical", "CWE-78", "Possible Shellshock (CVE-2014-6271) exposure"),
    ("sql injection", "High", "CWE-89", "Possible SQL injection indicator"),
    ("cross site scripting", "High", "CWE-79", "Possible cross-site scripting (XSS) indicator"),
    ("xss", "High", "CWE-79", "Possible cross-site scripting (XSS) indicator"),
    ("directory indexing", "Medium", "CWE-548", "Directory indexing enabled"),
    ("backup", "Medium", "CWE-530", "Backup/config file possibly exposed"),
    ("default", "Medium", "CWE-1188", "Default file or credential possibly present"),
    ("outdated", "Medium", "CWE-1104", "Outdated server/software version detected"),
    ("server leaks", "Low", "CWE-200", "Server version/banner disclosure"),
    ("cookie", "Low", "CWE-614", "Cookie set without a secure attribute"),
    ("robots.txt", "Low", "CWE-200", "robots.txt reveals internal paths"),
]
DEFAULT_SEVERITY, DEFAULT_CWE, DEFAULT_TITLE = "Low", "CWE-16", "Nikto finding"


def _classify(msg: str) -> tuple:
    low = (msg or "").lower()
    for needle, severity, cwe, title in CLASSIFY_RULES:
        if needle in low:
            return severity, cwe, title
    return DEFAULT_SEVERITY, DEFAULT_CWE, DEFAULT_TITLE


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def run_nikto_scan(target_url: str, timeout_sec: int = 600, tuning: str | None = None) -> bytes:
    """Shells out to the nikto binary, returns its raw JSON report bytes."""
    url = validate_target_url(target_url)
    cmd = ["nikto", "-h", url, "-Format", "json", "-output", "-", "-ask", "no"]
    if tuning:
        # Tuning codes are a single alphanumeric string (e.g. "1259bcx") -- Nikto's own
        # "-Tuning" flag syntax. Reject anything that isn't that shape rather than
        # passing arbitrary user input to the subprocess.
        if not re.match(r"^[0-9a-zx]{1,20}$", tuning):
            raise ValueError(f"'{tuning}' isn't a valid Nikto tuning spec")
        cmd += ["-Tuning", tuning]

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"Nikto scan exceeded {timeout_sec}s and was killed: {' '.join(shlex.quote(c) for c in cmd)}")
    # Nikto exits non-zero in some versions even on a normal completed scan (e.g. when
    # it finds issues), so don't treat returncode alone as failure -- only a genuinely
    # empty/unparseable stdout means something actually went wrong.
    if not stdout.strip():
        raise RuntimeError(f"Nikto produced no output (exit {proc.returncode}): {stderr.decode(errors='replace')[:500]}")
    return stdout


def parse_nikto_json(content: bytes) -> dict:
    """Returns {"host": str, "ip": str|None, "port": str|None, "vulnerabilities": [...]}.
    Raises ValueError on malformed/unrecognized output."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Not valid Nikto JSON output: {e}")
    # Some Nikto versions wrap the report in a list, some return a single object.
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        raise ValueError("Unrecognized Nikto JSON shape")
    vulns = data.get("vulnerabilities") or []
    return {
        "host": data.get("host") or data.get("targetip"),
        "ip": data.get("ip"),
        "port": str(data.get("port")) if data.get("port") is not None else None,
        "vulnerabilities": [
            {"id": v.get("id"), "method": v.get("method"), "url": v.get("url"), "msg": v.get("msg") or v.get("message")}
            for v in vulns if isinstance(v, dict) and (v.get("msg") or v.get("message"))
        ],
    }


async def _find_or_create_web_asset(db, target_url: str) -> dict:
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url
    asset = await db.assets.find_one({"hostname": hostname}, {"_id": 0})
    if asset:
        return asset
    asset = {
        "id": str(uuid.uuid4()), "hostname": hostname, "ip": None, "fqdn": hostname,
        "environment": "unknown", "criticality": "medium", "exposure": "internet",
        "platform": "web", "operating_system": "unknown", "asset_type": "web_application",
        "owner_team": "Unassigned", "product_id": None, "product_name": None,
        "tags": ["nikto", "web-app"], "status": "active", "created_at": _now_iso(),
        "ownership_confidence": 0.3,
        "ownership_rationale": "Auto-created from a Nikto web scan target (no existing asset matched by hostname).",
    }
    await db.assets.insert_one(asset)
    return asset


async def _dedup_finding(db, asset_id: str, canonical_key: str) -> bool:
    existing = await db.findings.find_one({
        "asset_id": asset_id, "canonical_key": canonical_key,
        "status": {"$nin": ["Fixed validated", "Closed administratively", "False positive"]},
    })
    return existing is not None


async def import_nikto_results(db, target_url: str, parsed: dict, source_label: str | None = None) -> dict:
    asset = await _find_or_create_web_asset(db, target_url)
    from criticality import recompute_asset_criticality
    await recompute_asset_criticality(db, asset["id"])
    started = _now_iso()
    findings_created = 0
    seen_titles = set()

    for v in parsed.get("vulnerabilities", []):
        severity, cwe, title = _classify(v.get("msg", ""))
        canonical_key = f"nikto:{asset['id']}:{title}:{v.get('url','')}"
        seen_titles.add(title)
        if await _dedup_finding(db, asset["id"], canonical_key):
            continue
        now = _now_iso()
        finding = {
            "id": str(uuid.uuid4()), "canonical_key": canonical_key,
            "source_tool": "Nikto", "source_observation_id": v.get("id"), "source_native_id": v.get("id"),
            "qid": None, "plugin_id": v.get("id"),
            "title": title, "description": f"{v.get('msg','').strip()} (Detected on {v.get('method','GET')} {v.get('url','/')})",
            "severity": severity, "cve": None, "cwe": cwe, "cvss_score": None, "cvss_vector": None,
            "epss_score": 0, "kev_flag": False, "rti": [],
            "port": None, "protocol": "http", "service": "http", "service_product": None, "service_version": None,
            "remediation": "Review this web application finding and apply the relevant header/configuration/patch fix for the issue described above.",
            "asset_id": asset["id"], "asset_hostname": asset["hostname"], "asset_ip": asset.get("ip"),
            "asset_criticality": asset["criticality"], "asset_exposure": asset["exposure"],
            "asset_environment": asset["environment"], "asset_os": asset.get("operating_system"),
            "internet_facing": asset.get("exposure") in ("internet", "external"), "owner_team": asset.get("owner_team"),
            "ownership_confidence": asset.get("ownership_confidence", 0.3),
            "product_id": asset.get("product_id"), "product_name": asset.get("product_name"),
            "status": "New", "validation_status": "pending", "reopened_count": 0,
            "first_seen_at": now, "last_seen_at": now, "last_changed_at": now, "imported_at": now,
            "detection_channel": "nikto_scan", "tags": asset.get("tags", []),
            "compliance_scope": [], "advisory_links": [], "exploit_references": [],
            "patch_available": None, "url": v.get("url"),
        }
        sla_days = compute_sla_days(severity, asset["criticality"])
        try:
            due_dt = datetime.fromisoformat(now.replace("Z", "+00:00"))
        except Exception:
            due_dt = datetime.now(timezone.utc)
        from datetime import timedelta
        finding["sla_days"] = sla_days
        finding["due_at"] = (due_dt + timedelta(days=sla_days)).isoformat()
        risk = compute_risk(finding, asset)
        finding["risk_score"] = risk["score"]
        finding["risk_breakdown"] = risk["breakdown"]
        await db.findings.insert_one(finding)
        findings_created += 1

    await db.import_jobs.insert_one({
        "id": str(uuid.uuid4()), "source_name": "Nikto", "status": "success",
        "started_at": started, "finished_at": _now_iso(),
        "created_count": findings_created, "updated_count": 0, "deduplicated_count": 0,
        "label": source_label or f"Nikto scan ({target_url})",
    })

    return {
        "asset_id": asset["id"], "hostname": asset["hostname"],
        "issues_found": len(parsed.get("vulnerabilities", [])),
        "findings_created": findings_created, "distinct_issue_types": len(seen_titles),
    }
