"""Attack Surface Telemetry / Live Exploitation Monitoring (items 37 + 38).

Ingests Cloudflare web-request telemetry, decodes and classifies the payloads,
correlates them against everything the platform already knows, scores them, and
closes the loop into defensive rules.

WHY THE INGESTION JOB IS THE SYSTEM OF RECORD
Cloudflare's Free/Pro plans keep firewall events for ~24 hours and HTTP requests
for ~7 days, and Logpush is Enterprise-only. Both datasets we need
(firewallEventsAdaptive, httpRequestsAdaptive) ARE available on every plan via
the GraphQL Analytics API. So the poller writes everything into our own
collection and builds unlimited history from a short retention window -- which
means missing a poll cycle loses data permanently. The loop therefore polls
frequently, tracks a per-zone cursor, and queries the GraphQL `settings` node to
discover each zone's actual retention limits rather than assuming them.

PIPELINE
  ingest    -- both datasets, cursor-based, per zone
  classify  -- decode (URL/base64/hex/unicode escapes) then match against
               SQLi/XSS/traversal/command-injection/scanner signatures, mapped
               to ATT&CK techniques (reusing the item-33 mapping vocabulary)
  correlate -- target host -> our asset inventory; is there a matching OPEN
               finding for the technique on that host; enrich the source IP
               from OSINT/watchlist/Shodan
  score     -- Business Risk Score combining classification confidence, whether
               the request actually reached origin, target asset criticality,
               matching-vulnerability presence, and source reputation
  act       -- draft Cloudflare WAF rules (never auto-applied), draft findings,
               feed the security-event bus

GUARDRAILS (deliberate, and load-bearing)
  * Never auto-block on classification alone. Rules are DRAFTED for human
    approval; the only auto-eligible case is high confidence AND a repeat
    offender, and even that only marks a rule as auto-eligible.
  * Source IPs run through an allowlist FIRST (our own scanners, partners,
    office egress) so the platform never flags itself.
  * Auto-created IP indicators are confidence-tagged with the full "why" so a
    false positive can be downgraded rather than silently poisoning the
    watchlist.
  * Logs contain IPs and URLs -- personal data. There's a deliberate retention
    window and the module is access-scoped like everything else.
"""
import asyncio
import base64
import binascii
import hashlib
import ipaddress
import logging
import re
import urllib.parse
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("vulnops.attack_telemetry")

CF_GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"

# Deliberate retention window for request telemetry (IPs + URLs = personal data).
DEFAULT_RETENTION_DAYS = 90

OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


# =========================================================================
# Decoding -- attackers nest encodings specifically to defeat naive matching
# =========================================================================

def decode_payload(raw: str, max_rounds: int = 3) -> str:
    """Recursively decode a request string until it stops changing.

    Handles URL-encoding (including double-encoding), HTML entities, unicode
    escapes, hex escapes, and base64 chunks. Signature matching runs on the
    DECODED text, because `%2527%2520union` and `' union` are the same attack."""
    text = raw or ""
    for _ in range(max_rounds):
        before = text
        try:
            text = urllib.parse.unquote_plus(text)
        except Exception:
            pass
        text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'")
        text = re.sub(r"\\u00([0-9a-fA-F]{2})",
                      lambda m: chr(int(m.group(1), 16)), text)
        text = re.sub(r"\\x([0-9a-fA-F]{2})",
                      lambda m: chr(int(m.group(1), 16)), text)
        # base64 chunks long enough to be meaningful
        for chunk in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
            try:
                decoded = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
                as_text = decoded.decode("utf-8", errors="strict")
                if sum(c.isprintable() for c in as_text) / max(1, len(as_text)) > 0.85:
                    text = text.replace(chunk, as_text)
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
        if text == before:
            break
    return text


# =========================================================================
# Classification
# =========================================================================

SIGNATURES = [
    # (attack_type, regex, weight, attack_technique, tactic)
    ("sql_injection", r"(?i)\b(union\s+all\s+select|union\s+select|select\s+.*\bfrom\b.*\bwhere\b)", 5,
     "T1190", "Initial Access"),
    ("sql_injection", r"(?i)(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", 4, "T1190", "Initial Access"),
    ("sql_injection", r"(?i)(sleep\(\s*\d+\s*\)|benchmark\(|pg_sleep\(|waitfor\s+delay)", 5, "T1190", "Initial Access"),
    ("sql_injection", r"(?i)(information_schema|sysobjects|@@version|xp_cmdshell)", 5, "T1190", "Initial Access"),
    ("sql_injection", r"(?i)(--\s|#|;)\s*(drop|insert|update|delete)\s+", 5, "T1190", "Initial Access"),

    ("xss", r"(?i)<\s*script[^>]*>", 5, "T1059.007", "Execution"),
    ("xss", r"(?i)javascript\s*:", 3, "T1059.007", "Execution"),
    ("xss", r"(?i)on(error|load|click|mouseover|focus)\s*=", 4, "T1059.007", "Execution"),
    ("xss", r"(?i)(document\.cookie|window\.location|eval\s*\(|atob\s*\()", 4, "T1059.007", "Execution"),
    ("xss", r"(?i)<\s*(img|svg|iframe|body)[^>]+on\w+\s*=", 5, "T1059.007", "Execution"),

    ("path_traversal", r"(\.\./){2,}|(\.\.\\){2,}", 5, "T1083", "Discovery"),
    ("path_traversal", r"(?i)/etc/(passwd|shadow|hosts)\b", 5, "T1083", "Discovery"),
    ("path_traversal", r"(?i)(boot\.ini|win\.ini|windows/system32)", 5, "T1083", "Discovery"),
    ("path_traversal", r"(?i)(file|php|zip|data)://", 4, "T1083", "Discovery"),

    ("command_injection", r"(?i)[;|&`]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell)\b", 5,
     "T1059", "Execution"),
    ("command_injection", r"(?i)\$\(.*\)|`[^`]+`", 4, "T1059", "Execution"),
    ("command_injection", r"(?i)(/bin/(ba)?sh|cmd\.exe|powershell\s+-enc)", 5, "T1059", "Execution"),

    ("ssrf", r"(?i)(169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data)", 5, "T1190", "Initial Access"),
    ("ssti", r"(\{\{.*\}\}|\$\{.*\})", 3, "T1190", "Initial Access"),
    ("log4shell", r"(?i)\$\{jndi:(ldap|rmi|dns)", 5, "T1190", "Initial Access"),
    ("xxe", r"(?i)<!ENTITY|SYSTEM\s+[\"']file:", 5, "T1190", "Initial Access"),
    ("deserialization", r"(?i)(rO0AB|aced0005|O:\d+:\")", 5, "T1190", "Initial Access"),

    ("scanner", r"(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|havij|dirbuster|gobuster|wpscan|zgrab)", 3,
     "T1595", "Reconnaissance"),
    ("sensitive_path_probe", r"(?i)/(\.git/|\.env\b|wp-login\.php|phpmyadmin|\.aws/credentials|\.ssh/id_rsa)", 4,
     "T1595.003", "Reconnaissance"),
]

_COMPILED = [(t, re.compile(p), w, tech, tac) for (t, p, w, tech, tac) in SIGNATURES]

ATTACK_SEVERITY = {
    "sql_injection": "Critical", "command_injection": "Critical", "log4shell": "Critical",
    "deserialization": "Critical", "xxe": "High", "ssrf": "High", "path_traversal": "High",
    "xss": "High", "ssti": "High", "sensitive_path_probe": "Medium", "scanner": "Low",
}


def classify_request(url: str, user_agent: str = "", query: str = "",
                      body_sample: str = "") -> Optional[dict]:
    """Classify a request as an exploitation attempt, or return None.

    Confidence rises with the strength of the matched signature and the number
    of independent signature families that hit -- one weak match on a long URL
    is a very different thing from three families agreeing."""
    haystack_raw = " ".join(x for x in (url, query, body_sample, user_agent) if x)
    decoded = decode_payload(haystack_raw)
    was_encoded = decoded.strip() != haystack_raw.strip()

    hits = []
    for attack_type, rx, weight, technique, tactic in _COMPILED:
        m = rx.search(decoded)
        if m:
            hits.append({"attack_type": attack_type, "weight": weight, "technique": technique,
                         "tactic": tactic, "matched": m.group(0)[:120]})
    if not hits:
        return None

    families = {h["attack_type"] for h in hits}
    primary = max(hits, key=lambda h: h["weight"])
    max_weight = primary["weight"]

    confidence = min(0.98, 0.35 + 0.11 * max_weight + 0.08 * (len(families) - 1))
    if was_encoded:
        # obfuscation is itself evidence of intent, not of a false positive
        confidence = min(0.98, confidence + 0.05)
    if families == {"scanner"}:
        confidence = min(confidence, 0.6)

    return {
        "attack_type": primary["attack_type"],
        "attack_types": sorted(families),
        "attack_technique": primary["technique"],
        "attack_tactic": primary["tactic"],
        "severity": ATTACK_SEVERITY.get(primary["attack_type"], "Medium"),
        "confidence": round(confidence, 2),
        "matched_signatures": hits[:8],
        "decoded_payload": decoded[:1000],
        "was_encoded": was_encoded,
    }


# =========================================================================
# Cloudflare GraphQL ingestion
# =========================================================================

async def _cf_config(db) -> dict:
    integration = await db.integrations.find_one({"name": "Cloudflare"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    if not cfg.get("api_key"):
        raise ValueError("Cloudflare isn't configured -- add an API token and zone ID under "
                          "Integrations -> Cloudflare.")
    if not cfg.get("zone_id"):
        raise ValueError("Cloudflare zone ID is missing -- add it under Integrations -> Cloudflare.")
    return cfg


async def _graphql(cfg: dict, query: str, variables: dict) -> dict:
    import httpx
    headers = {"Authorization": f"Bearer {cfg['api_key']}", "Content-Type": "application/json"}
    endpoint = cfg.get("endpoint") or CF_GRAPHQL_URL
    async with httpx.AsyncClient(timeout=45) as c:
        r = await c.post(endpoint, headers=headers, json={"query": query, "variables": variables})
    if r.status_code == 401:
        raise RuntimeError("Cloudflare rejected the API token (401) -- it needs Analytics:Read on the zone.")
    if r.status_code != 200:
        raise RuntimeError(f"Cloudflare GraphQL HTTP {r.status_code}: {r.text[:500]}")
    data = r.json()
    if data.get("errors"):
        raise RuntimeError(f"Cloudflare GraphQL error: {data['errors'][0].get('message', data['errors'])}")
    return data.get("data") or {}


RETENTION_QUERY = """
query Retention($zoneTag: String!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      settings {
        firewallEventsAdaptiveMaxDuration: httpRequestsAdaptiveGroupsMaxDuration
        httpRequestsAdaptiveMaxDuration: httpRequestsAdaptiveGroupsMaxDuration
      }
    }
  }
}
"""

FIREWALL_QUERY = """
query FirewallEvents($zoneTag: String!, $since: Time!, $until: Time!, $limit: Int!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(
        filter: {datetime_geq: $since, datetime_lt: $until}
        limit: $limit
        orderBy: [datetime_ASC]
      ) {
        action datetime clientIP clientAsn clientCountryName
        clientRequestHTTPHost clientRequestPath clientRequestQuery
        clientRequestHTTPMethodName clientRequestScheme
        userAgent ruleId source matchIndex originResponseStatus edgeResponseStatus
      }
    }
  }
}
"""

HTTP_QUERY = """
query HttpRequests($zoneTag: String!, $since: Time!, $until: Time!, $limit: Int!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequestsAdaptive(
        filter: {datetime_geq: $since, datetime_lt: $until}
        limit: $limit
        orderBy: [datetime_ASC]
      ) {
        datetime clientIP clientAsn clientCountryName
        clientRequestHTTPHost clientRequestPath
        clientRequestHTTPMethodName userAgent
        edgeResponseStatus originResponseStatus cacheStatus
      }
    }
  }
}
"""


async def discover_retention(db) -> dict:
    """Query the zone's own settings to learn the real retention window and pick
    a safe polling interval, instead of hard-coding plan assumptions that go
    stale the moment the plan changes."""
    cfg = await _cf_config(db)
    try:
        data = await _graphql(cfg, RETENTION_QUERY, {"zoneTag": cfg["zone_id"]})
        zones = ((data.get("viewer") or {}).get("zones") or [])
        settings = (zones[0].get("settings") if zones else {}) or {}
    except Exception as e:
        logger.warning("Could not read Cloudflare retention settings: %s", e)
        settings = {}

    # Conservative defaults matching Free/Pro when the settings node is
    # unavailable: firewall events ~24h, http requests ~7d.
    fw_hours = int(settings.get("firewallEventsAdaptiveMaxDuration") or 24)
    http_hours = int(settings.get("httpRequestsAdaptiveMaxDuration") or 24 * 7)
    tightest = min(fw_hours, http_hours)
    # Poll at a quarter of the tightest window, clamped to 5-60 minutes, so a
    # missed cycle never costs data that has already aged out.
    interval_minutes = max(5, min(60, int(tightest * 60 / 4)))
    return {
        "firewall_events_retention_hours": fw_hours,
        "http_requests_retention_hours": http_hours,
        "recommended_poll_minutes": interval_minutes,
        "checked_at": _now_iso(),
    }


async def _cursor(db, dataset: str) -> datetime:
    doc = await db.attack_telemetry_cursors.find_one({"dataset": dataset}, {"_id": 0})
    if doc and doc.get("last_datetime"):
        try:
            return datetime.fromisoformat(doc["last_datetime"])
        except Exception:
            pass
    return _now() - timedelta(hours=1)


async def _save_cursor(db, dataset: str, dt: datetime) -> None:
    await db.attack_telemetry_cursors.update_one(
        {"dataset": dataset},
        {"$set": {"dataset": dataset, "last_datetime": dt.isoformat(), "updated_at": _now_iso()}},
        upsert=True)


def _dedupe_key(row: dict) -> str:
    """High-volume scanners hammer the same path thousands of times. Collapse on
    (ip, host, path, attack_type) so the queue shows attackers, not packets."""
    basis = "|".join([
        row.get("source_ip") or "", row.get("host") or "",
        (row.get("path") or "")[:200], row.get("attack_type") or "",
    ])
    return hashlib.sha256(basis.encode()).hexdigest()[:32]


async def ingest_cloudflare(db, minutes: int = 60, limit: int = 2000) -> dict:
    """Poll both datasets, classify, correlate, store. Returns a summary."""
    cfg = await _cf_config(db)
    until = _now()
    summary = {"firewall_events": 0, "http_requests": 0, "classified": 0,
                "observations_created": 0, "observations_merged": 0, "errors": []}

    for dataset, query, is_firewall in (("firewallEventsAdaptive", FIREWALL_QUERY, True),
                                          ("httpRequestsAdaptive", HTTP_QUERY, False)):
        since = await _cursor(db, dataset)
        if (until - since) > timedelta(minutes=minutes * 4):
            since = until - timedelta(minutes=minutes)
        try:
            data = await _graphql(cfg, query, {
                "zoneTag": cfg["zone_id"], "since": since.isoformat(),
                "until": until.isoformat(), "limit": limit})
        except Exception as e:
            summary["errors"].append(f"{dataset}: {e}")
            continue

        zones = ((data.get("viewer") or {}).get("zones") or [])
        rows = (zones[0].get(dataset) if zones else []) or []
        summary["firewall_events" if is_firewall else "http_requests"] += len(rows)

        newest = since
        for row in rows:
            try:
                dt = datetime.fromisoformat((row.get("datetime") or "").replace("Z", "+00:00"))
                newest = max(newest, dt)
            except Exception:
                dt = until

            url = f"{row.get('clientRequestHTTPHost', '')}{row.get('clientRequestPath', '')}"
            classification = classify_request(
                url=url, user_agent=row.get("userAgent") or "",
                query=row.get("clientRequestQuery") or "")
            if not classification:
                continue
            summary["classified"] += 1

            observation = {
                "source_ip": row.get("clientIP"),
                "asn": row.get("clientAsn"),
                "country": row.get("clientCountryName"),
                "host": row.get("clientRequestHTTPHost"),
                "path": row.get("clientRequestPath"),
                "query": row.get("clientRequestQuery"),
                "method": row.get("clientRequestHTTPMethodName"),
                "user_agent": row.get("userAgent"),
                "cf_action": row.get("action") if is_firewall else "logged",
                "cf_rule_id": row.get("ruleId"),
                "edge_status": row.get("edgeResponseStatus"),
                "origin_status": row.get("originResponseStatus"),
                "dataset": dataset,
                "observed_at": dt.isoformat(),
                **classification,
            }
            created = await _upsert_observation(db, observation)
            summary["observations_created" if created else "observations_merged"] += 1

        await _save_cursor(db, dataset, newest)

    await prune_old_telemetry(db)
    return summary


async def _upsert_observation(db, obs: dict) -> bool:
    """Dedupe on (ip, host, path, attack_type); returns True when newly created."""
    key = _dedupe_key(obs)
    existing = await db.attack_observations.find_one({"dedupe_key": key}, {"_id": 0})
    if existing:
        await db.attack_observations.update_one({"dedupe_key": key}, {
            "$inc": {"hit_count": 1},
            "$set": {"last_seen_at": obs["observed_at"],
                     "last_edge_status": obs.get("edge_status"),
                     "last_origin_status": obs.get("origin_status")},
        })
        return False

    enrichment = await correlate_observation(db, obs)
    doc = {
        "id": str(uuid.uuid4()), "dedupe_key": key, **obs, **enrichment,
        "hit_count": 1, "first_seen_at": obs["observed_at"], "last_seen_at": obs["observed_at"],
        "last_edge_status": obs.get("edge_status"), "last_origin_status": obs.get("origin_status"),
        "status": "new", "created_at": _now_iso(),
    }
    doc["business_risk_score"] = score_observation(doc)
    await db.attack_observations.insert_one(dict(doc))
    await _post_create_actions(db, doc)
    return True


# =========================================================================
# Correlation + item 38's auto-enrichment closed loop
# =========================================================================

DEFAULT_ALLOWLIST_NOTE = ("Allowlisted source -- our own scanners, partners, or office egress. "
                          "Classified traffic from these is recorded but never escalated.")


async def is_allowlisted(db, ip: str) -> Optional[dict]:
    """Item 38 guardrail: run source IPs against an allowlist BEFORE any
    enrichment or indicator creation, so the platform never flags its own
    scanners, a partner's integration, or the office egress IP."""
    if not ip:
        return None
    entries = await db.attack_ip_allowlist.find({}, {"_id": 0}).to_list(500)
    for e in entries:
        value = (e.get("value") or "").strip()
        if not value:
            continue
        try:
            if "/" in value:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False):
                    return e
            elif value == ip:
                return e
        except ValueError:
            continue
    return None


async def correlate_observation(db, obs: dict) -> dict:
    """Target host -> our asset; matching open finding for the technique; source
    IP reputation from what we already hold."""
    out = {"asset_id": None, "asset_hostname": None, "asset_criticality": None,
           "matching_finding_ids": [], "has_matching_vulnerability": False,
           "source_reputation": {}, "allowlisted": False}

    host = (obs.get("host") or "").lower()
    if host:
        asset = await db.assets.find_one(
            {"$or": [{"hostname": host}, {"hostname": {"$regex": f"^{re.escape(host)}$", "$options": "i"}}]},
            {"_id": 0, "id": 1, "hostname": 1, "criticality": 1})
        if asset:
            out["asset_id"] = asset["id"]
            out["asset_hostname"] = asset.get("hostname")
            out["asset_criticality"] = asset.get("criticality")
            # Does this host actually have an open vulnerability this attack
            # could exploit? That's the difference between noise and an
            # attempted exploitation of something real.
            technique = obs.get("attack_technique")
            findings = await db.findings.find(
                {"asset_id": asset["id"], "status": {"$in": OPEN_STATES}},
                {"_id": 0, "id": 1, "cwe": 1, "title": 1, "severity": 1}).to_list(500)
            from mitre_mapping import mitre_for_cwe
            matched = []
            for f in findings:
                m = mitre_for_cwe(f.get("cwe"))
                if m and m["technique_id"] == technique:
                    matched.append(f["id"])
            out["matching_finding_ids"] = matched[:20]
            out["has_matching_vulnerability"] = bool(matched)

    ip = obs.get("source_ip")
    allow = await is_allowlisted(db, ip)
    if allow:
        out["allowlisted"] = True
        out["source_reputation"] = {"allowlisted": True, "reason": allow.get("reason") or DEFAULT_ALLOWLIST_NOTE}
        return out

    rep = {}
    if ip:
        watch = await db.ioc_watchlist.find_one({"value": ip.lower()}, {"_id": 0})
        if watch:
            rep["watchlist"] = {"severity": watch.get("severity"), "source": watch.get("source"),
                                 "notes": watch.get("notes")}
        osint = await db.osint_findings.count_documents({"target": ip.lower()})
        if osint:
            rep["osint_hits"] = osint
        shodan_asset = await db.assets.find_one({"ip": ip}, {"_id": 0, "shodan_ports": 1})
        if shodan_asset and shodan_asset.get("shodan_ports"):
            rep["shodan_ports"] = shodan_asset["shodan_ports"]
        prior = await db.attack_observations.count_documents({"source_ip": ip})
        if prior:
            rep["prior_observations"] = prior
    out["source_reputation"] = rep
    return out


def score_observation(obs: dict) -> int:
    """Business Risk Score 0-100. Deliberately weights "did it reach origin" and
    "is there a real matching vulnerability" heavily -- a blocked probe against a
    patched host is not the same event as an unblocked exploit against a
    vulnerable, business-critical one."""
    score = 0
    sev = {"Critical": 30, "High": 22, "Medium": 12, "Low": 5}.get(obs.get("severity"), 10)
    score += sev
    score += int(obs.get("confidence", 0) * 20)

    # Did it actually reach the origin? Cloudflare blocking is a mitigating fact.
    action = (obs.get("cf_action") or "").lower()
    origin_status = obs.get("origin_status")
    if action in ("block", "drop", "challenge", "managed_challenge", "jschallenge"):
        score -= 12
    elif origin_status:
        score += 15
        if isinstance(origin_status, int) and 200 <= origin_status < 400:
            # origin answered successfully -- the request was served
            score += 10

    if obs.get("has_matching_vulnerability"):
        score += 25
    crit = {"Critical": 12, "High": 8, "Medium": 4, "Low": 1}.get(obs.get("asset_criticality"), 0)
    score += crit
    if obs.get("asset_id"):
        score += 5

    rep = obs.get("source_reputation") or {}
    if rep.get("watchlist"):
        score += 10
    if rep.get("osint_hits"):
        score += 5
    if (rep.get("prior_observations") or 0) > 20:
        score += 5
    if obs.get("allowlisted"):
        score = min(score, 10)
    return max(0, min(100, score))


async def _post_create_actions(db, obs: dict) -> None:
    """Item 38's closed loop: enrich or create the source IP indicator, attach
    the attack to the targeted asset, emit an event, and draft a WAF rule."""
    if obs.get("allowlisted"):
        return

    ip = obs.get("source_ip")
    if ip and obs.get("confidence", 0) >= 0.6:
        existing = await db.ioc_watchlist.find_one({"value": ip.lower()}, {"_id": 0})
        if not existing:
            # Auto-created indicators are CONFIDENCE-TAGGED with the complete
            # "why", so a false positive can be reviewed and downgraded rather
            # than quietly poisoning the watchlist.
            await db.ioc_watchlist.insert_one({
                "id": str(uuid.uuid4()), "ioc_type": "ip", "value": ip.lower(),
                "source": "auto/cf-exploit", "severity": obs.get("severity", "Medium"),
                "confidence": obs.get("confidence"),
                "auto_created": True, "review_status": "unreviewed",
                "notes": f"Auto-added from a classified {obs.get('attack_type')} attempt against "
                         f"{obs.get('host')}{obs.get('path') or ''}",
                "detail": {
                    "why": "Observed sending an exploit-classified request through Cloudflare",
                    "attack_type": obs.get("attack_type"),
                    "attack_types": obs.get("attack_types"),
                    "attack_technique": obs.get("attack_technique"),
                    "attack_tactic": obs.get("attack_tactic"),
                    "target_host": obs.get("host"), "target_path": obs.get("path"),
                    "decoded_payload": (obs.get("decoded_payload") or "")[:500],
                    "matched_signatures": obs.get("matched_signatures"),
                    "observed_at": obs.get("observed_at"),
                    "confidence": obs.get("confidence"),
                    "cf_action": obs.get("cf_action"),
                    "observation_id": obs["id"],
                },
                "added_by": None, "added_at": _now_iso(), "hits": 0, "last_hit_at": None,
            })
        else:
            await db.ioc_watchlist.update_one({"value": ip.lower()}, {"$set": {
                "last_attack_observation_id": obs["id"],
                "last_attack_seen_at": obs.get("observed_at")}})

    from security_events import emit_event
    await emit_event(
        db, source="attack_telemetry", event_type="exploit_attempt",
        severity=obs.get("severity", "Medium"),
        title=f"{obs.get('attack_type', 'exploit').replace('_', ' ').title()} attempt against "
              f"{obs.get('host')}{obs.get('path') or ''}",
        entity_type="asset" if obs.get("asset_id") else "host",
        entity_id=obs.get("asset_id") or obs.get("host") or "unknown",
        entity_label=obs.get("asset_hostname") or obs.get("host"),
        description=f"{obs.get('source_ip')} ({obs.get('country') or '?'}) sent a "
                    f"{obs.get('attack_type')} payload (confidence {obs.get('confidence')}). "
                    f"Cloudflare action: {obs.get('cf_action')}."
                    + (" A matching open vulnerability exists on this host."
                       if obs.get("has_matching_vulnerability") else ""),
        raw={"observation_id": obs["id"], "business_risk_score": obs.get("business_risk_score")},
    )
    await draft_waf_rule(db, obs)


# =========================================================================
# Act -- drafted WAF rules (never auto-applied)
# =========================================================================

async def draft_waf_rule(db, obs: dict) -> Optional[dict]:
    """Draft a Cloudflare WAF expression for human review.

    NEVER auto-applied. `auto_eligible` marks the narrow case the spec allows --
    high confidence AND a repeat offender -- and even then a human presses the
    button. Blocking traffic on a regex match alone is how you take your own
    site down."""
    if obs.get("allowlisted") or obs.get("confidence", 0) < 0.7:
        return None
    ip = obs.get("source_ip")
    if not ip:
        return None
    existing = await db.attack_waf_rules.find_one(
        {"source_ip": ip, "status": {"$in": ["draft", "approved"]}}, {"_id": 0})
    if existing:
        await db.attack_waf_rules.update_one({"id": existing["id"]}, {
            "$inc": {"observation_count": 1},
            "$set": {"updated_at": _now_iso()}})
        return existing

    prior = await db.attack_observations.count_documents({"source_ip": ip})
    repeat_offender = prior >= 5
    doc = {
        "id": str(uuid.uuid4()),
        "source_ip": ip,
        "expression": f'(ip.src eq {ip})',
        "action": "block",
        "description": f"Block {ip} — {obs.get('attack_type')} attempts against "
                       f"{obs.get('host')} (confidence {obs.get('confidence')})",
        "rationale": {
            "attack_type": obs.get("attack_type"),
            "attack_technique": obs.get("attack_technique"),
            "confidence": obs.get("confidence"),
            "target_host": obs.get("host"),
            "prior_observations": prior,
            "has_matching_vulnerability": obs.get("has_matching_vulnerability"),
        },
        "status": "draft",
        # The ONLY auto-eligible case, and it still requires a human click.
        "auto_eligible": bool(obs.get("confidence", 0) >= 0.9 and repeat_offender),
        "observation_id": obs["id"], "observation_count": 1,
        "created_at": _now_iso(), "updated_at": _now_iso(),
        "applied_at": None, "applied_by": None,
    }
    await db.attack_waf_rules.insert_one(dict(doc))
    return doc


async def prune_old_telemetry(db, retention_days: int = DEFAULT_RETENTION_DAYS) -> int:
    """Deliberate retention window -- these records contain client IPs and full
    request URLs, which is personal data. Observations that never mattered age
    out; anything promoted to a finding or an indicator survives independently."""
    cutoff = (_now() - timedelta(days=retention_days)).isoformat()
    result = await db.attack_observations.delete_many({
        "last_seen_at": {"$lt": cutoff},
        "status": {"$in": ["new", "dismissed"]},
        "business_risk_score": {"$lt": 60},
    })
    return result.deleted_count


async def attack_telemetry_loop(db, interval_minutes: Optional[int] = None):
    """Frequent poll -- Cloudflare's Free/Pro retention is short and Logpush is
    Enterprise-only, so OUR copy is the system of record and a missed window is
    permanent data loss. The interval is derived from the zone's own reported
    retention rather than assumed."""
    await asyncio.sleep(180)
    while True:
        minutes = interval_minutes
        try:
            if minutes is None:
                retention = await discover_retention(db)
                minutes = retention["recommended_poll_minutes"]
        except ValueError:
            minutes = 15          # not configured yet -- quiet, expected
        except Exception as e:
            logger.warning("Cloudflare retention discovery failed: %s", e)
            minutes = 15
        try:
            result = await ingest_cloudflare(db, minutes=minutes)
            logger.info("Attack telemetry ingest: %s", result)
        except ValueError:
            pass                   # not configured -- expected/quiet
        except Exception as e:
            logger.warning("Attack telemetry ingest failed: %s", e)
        await asyncio.sleep(max(5, minutes) * 60)
