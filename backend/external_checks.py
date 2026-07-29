"""Item 30 -- External Checks split into two panels keyed off the reviewed entity.

  Company Posture   -- is this a real, stable company we can hold to a contract?
                       corporate registration (OpenCorporates / CO SoS),
                       breach & incident reputation (ransomware.live leak sites,
                       HIBP, security news), certification status (SOC 2 / ISO
                       expiry tracked on the entity), and viability signals.

  Technical Posture -- is the thing they run actually secure? TLS/security
                       headers and NVD CVEs (kept from the original), plus
                       SPF/DKIM/DMARC, Shodan exposure, certificate transparency,
                       DNS/WHOIS hygiene, and a typosquat scan of their domain.

Every technical check reuses a capability the platform already has (item 19's
CTI module, domain_email_security, shodan_sync) scoped to the vendor's domain
rather than reimplementing it -- that's the "build the OSINT integrations once"
requirement. Each check reports its own status so one failure degrades that
check alone, never the panel.

Prerequisite handling is explicit: with no domain the technical panel says what
it needs rather than silently returning nothing, and with no legal company name
the corporate-registration check does the same.
"""
import asyncio
import re
from datetime import datetime, timezone, timedelta
from typing import Optional

OPENCORPORATES_URL = "https://api.opencorporates.com/v0.4/companies/search"
SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                    "x-frame-options", "x-content-type-options", "referrer-policy"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tag(source: str) -> str:
    return f"Pulled from {source}, {datetime.now(timezone.utc).date().isoformat()}"


def _result(check: str, status: str, summary: str, detail=None, source: str = "") -> dict:
    """status: ok | attention | manual | not_configured"""
    return {"check": check, "status": status, "summary": summary,
            "detail": detail, "source_tag": _tag(source or check)}


# =========================================================================
# Company Posture
# =========================================================================

async def _corporate_registration(db, entity: dict) -> dict:
    """OpenCorporates search for the legal company name. Free tier works without
    a key at low volume; a key from Integrations -> OpenCorporates raises limits.
    A company that doesn't appear at all, or appears dissolved, is a real
    contracting risk -- not a technical one, which is exactly why this panel
    exists separately."""
    import httpx
    name = (entity.get("legal_name") or entity.get("name") or "").strip()
    if not name:
        return _result("corporate_registration", "manual",
                       "No legal company name on the entity — add one to enable the registry lookup.",
                       source="OpenCorporates")
    integration = await db.integrations.find_one({"name": "OpenCorporates"}, {"_id": 0})
    api_key = ((integration or {}).get("config") or {}).get("api_key")
    params = {"q": name, "per_page": 5}
    if api_key:
        params["api_token"] = api_key
    if entity.get("jurisdiction"):
        params["jurisdiction_code"] = entity["jurisdiction"]
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            r = await c.get(OPENCORPORATES_URL, params=params)
    except Exception as e:
        return _result("corporate_registration", "manual",
                       f"Could not reach OpenCorporates ({type(e).__name__}) — check the registry manually.",
                       source="OpenCorporates")
    if r.status_code == 401:
        return _result("corporate_registration", "not_configured",
                       "OpenCorporates rejected the request (401) — add or refresh the API token under "
                       "Integrations → OpenCorporates.", source="OpenCorporates")
    if r.status_code != 200:
        return _result("corporate_registration", "manual",
                       f"OpenCorporates HTTP {r.status_code} — check the registry manually.",
                       source="OpenCorporates")
    try:
        companies = (r.json().get("results") or {}).get("companies") or []
    except Exception:
        return _result("corporate_registration", "manual",
                       "OpenCorporates returned an unexpected payload.", source="OpenCorporates")
    if not companies:
        return _result("corporate_registration", "attention",
                       f'No registered company matching "{name}" was found. Confirm the legal entity name '
                       "before contracting.", {"query": name}, source="OpenCorporates")
    hits = [c["company"] for c in companies if c.get("company")]
    inactive = [h for h in hits if (h.get("current_status") or "").lower() not in
                ("active", "good standing", "in good standing", "")]
    top = hits[0]
    status = "attention" if inactive and len(inactive) == len(hits) else "ok"
    summary = (f'{len(hits)} registry match(es); top: {top.get("name")} '
               f'({top.get("jurisdiction_code", "?").upper()}, {top.get("current_status") or "status unknown"}, '
               f'incorporated {top.get("incorporation_date") or "?"})')
    if status == "attention":
        summary += " — no ACTIVE registration found, which is a contracting risk."
    return _result("corporate_registration", status, summary,
                   {"matches": [{"name": h.get("name"), "jurisdiction": h.get("jurisdiction_code"),
                                 "status": h.get("current_status"),
                                 "incorporated": h.get("incorporation_date"),
                                 "url": h.get("opencorporates_url")} for h in hits[:5]]},
                   source="OpenCorporates")


async def _breach_reputation(db, entity: dict) -> dict:
    """Has this vendor been in the news, on a leak site, or in a breach corpus?
    Reads what the CTI module already collected (item 19) rather than re-fetching:
    ransomware.live victim rows, OSINT/compromise findings on the domain, and
    security-news name matches."""
    name = entity.get("name") or ""
    domain = (entity.get("domain") or "").lower()
    ransom = await db.cti_ransomware_victims.find(
        {"$or": [{"victim_domain": domain}, {"victim": {"$regex": f"^{re.escape(name)}$", "$options": "i"}}]},
        {"_id": 0, "victim": 1, "group": 1, "discovered": 1, "post_url": 1}).to_list(20) if (name or domain) else []
    osint_count = await db.osint_findings.count_documents({"target": domain}) if domain else 0
    news = []
    try:
        from security_news import get_vendor_news
        if name:
            news = await get_vendor_news(db, name, days=730, limit=8)
    except Exception:
        news = []
    hibp = await db.hibp_breaches.count_documents({"domain": domain}) if domain else 0

    signals = len(ransom) + osint_count + len(news) + hibp
    status = "attention" if (ransom or osint_count or hibp) else ("attention" if news else "ok")
    parts = []
    if ransom:
        parts.append(f"{len(ransom)} ransomware leak-site posting(s) ({', '.join(sorted({r['group'] for r in ransom if r.get('group')}))})")
    if hibp:
        parts.append(f"{hibp} breach record(s) for this domain")
    if osint_count:
        parts.append(f"{osint_count} OSINT/compromise hit(s)")
    if news:
        parts.append(f"{len(news)} security-news mention(s) in 24 months")
    summary = "; ".join(parts) if parts else "No breach, leak-site, or adverse-news signals on file."
    return _result("breach_reputation", status, summary, {
        "ransomware": ransom,
        "news": [{"title": n.get("title"), "link": n.get("link"), "source": n.get("source")} for n in news],
        "osint_hits": osint_count, "hibp_breaches": hibp, "signal_count": signals,
    }, source="ransomware.live + OSINT + Security News + HIBP")


async def _certification_status(db, entity: dict) -> dict:
    """SOC 2 / ISO certificates recorded on the reviewed entity, with expiry.
    An expired certificate is worse than none, because it usually means nobody
    re-checked."""
    certs = entity.get("certifications") or []
    if not certs:
        return _result("certification_status", "attention",
                       "No SOC 2 / ISO 27001 certificate recorded for this vendor. Request one and record "
                       "its expiration on the entity.", source="Reviewed entity record")
    today = datetime.now(timezone.utc).date().isoformat()
    soon = (datetime.now(timezone.utc) + timedelta(days=60)).date().isoformat()
    expired = [c for c in certs if c.get("expires_at") and c["expires_at"] < today]
    expiring = [c for c in certs if c.get("expires_at") and today <= c["expires_at"] <= soon]
    status = "attention" if (expired or expiring) else "ok"
    if expired:
        summary = f"{len(expired)} certificate(s) EXPIRED: " + ", ".join(
            f"{c.get('name')} ({c.get('expires_at')})" for c in expired)
    elif expiring:
        summary = f"{len(expiring)} certificate(s) expiring within 60 days: " + ", ".join(
            f"{c.get('name')} ({c.get('expires_at')})" for c in expiring)
    else:
        summary = "Current: " + ", ".join(f"{c.get('name')} (to {c.get('expires_at') or '?'})" for c in certs)
    return _result("certification_status", status, summary, {"certifications": certs},
                   source="Reviewed entity record")


async def _viability_signals(db, entity: dict) -> dict:
    """Cheap, honest viability signals from what we already know: how long this
    vendor has been in our own environment, how many reviews they've had, and
    whether prior approvals lapsed. Deliberately NOT a credit rating -- we don't
    have that data and shouldn't pretend to."""
    name = entity.get("name") or ""
    prior = await db.security_reviews.count_documents(
        {"entity_name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}}) if name else 0
    vendor = await db.vendors.find_one(
        {"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}}, {"_id": 0}) if name else None
    bits = []
    if prior:
        bits.append(f"{prior} prior security review(s) on file")
    if vendor:
        bits.append(f"tracked as a vendor since {(vendor.get('created_at') or '?')[:10]}"
                    + (f", criticality {vendor.get('criticality')}" if vendor.get("criticality") else ""))
    if entity.get("last_review_id"):
        bits.append(f"current rating {entity.get('current_rating') or 'unrated'}")
    if not bits:
        return _result("viability_signals", "manual",
                       "No internal history for this vendor — first engagement. Financial/viability review "
                       "is a manual step (registry age, references, public filings).",
                       source="Internal history")
    return _result("viability_signals", "ok", "; ".join(bits),
                   {"prior_reviews": prior, "known_vendor": bool(vendor)}, source="Internal history")


async def company_posture(db, entity: dict) -> dict:
    checks = await asyncio.gather(
        _corporate_registration(db, entity),
        _breach_reputation(db, entity),
        _certification_status(db, entity),
        _viability_signals(db, entity),
        return_exceptions=True,
    )
    out = []
    for c in checks:
        if isinstance(c, Exception):
            out.append(_result("unknown_check", "manual", f"Check failed: {type(c).__name__}"))
        else:
            out.append(c)
    return {"panel": "company_posture", "ran_at": _now_iso(), "results": out}


# =========================================================================
# Technical Posture
# =========================================================================

async def _tls_headers(entity: dict) -> dict:
    import httpx
    domain = (entity.get("domain") or "").lower()
    if not domain:
        return _result("tls_security_headers", "manual",
                       "No vendor domain on the entity — add one to enable the TLS/header scan.",
                       source="live scan")
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
            r = await c.get(f"https://{domain}")
    except Exception as e:
        return _result("tls_security_headers", "manual",
                       f"Could not reach https://{domain} ({type(e).__name__}) — check manually.",
                       source=f"https://{domain}")
    present = [h for h in SECURITY_HEADERS if h in {k.lower() for k in r.headers.keys()}]
    missing = [h for h in SECURITY_HEADERS if h not in present]
    return _result("tls_security_headers", "ok" if not missing else "attention",
                   f"HTTPS reachable; {len(present)}/{len(SECURITY_HEADERS)} security headers present"
                   + (f" (missing: {', '.join(missing)})" if missing else ""),
                   {"present": present, "missing": missing, "final_url": str(r.url)},
                   source=f"https://{domain}")


async def _cve_lookup(entity: dict) -> dict:
    import httpx
    name = entity.get("name") or ""
    if not name:
        return _result("cve_lookup", "manual", "No entity name to search NVD with.", source="NVD")
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                             params={"keywordSearch": name, "resultsPerPage": 5})
    except Exception as e:
        return _result("cve_lookup", "manual", f"NVD lookup failed ({type(e).__name__}).", source="NVD")
    if r.status_code != 200:
        return _result("cve_lookup", "manual", f"NVD returned HTTP {r.status_code}.", source="NVD")
    data = r.json()
    total = data.get("totalResults", 0)
    cves = [v["cve"]["id"] for v in data.get("vulnerabilities", [])][:5]
    return _result("cve_lookup", "attention" if total else "ok",
                   f'{total} CVE(s) match "{name}" on NVD' + (f" (e.g. {', '.join(cves)})" if cves else ""),
                   {"total": total, "sample": cves}, source="NVD")


async def _email_auth(db, entity: dict) -> dict:
    """SPF/DKIM/DMARC on the vendor's domain -- reuses domain_email_security's
    checker rather than a second DNS implementation. A vendor with no DMARC is a
    vendor whose name is trivially spoofable at our users."""
    domain = (entity.get("domain") or "").lower()
    if not domain:
        return _result("email_authentication", "manual",
                       "No vendor domain on the entity — add one to check SPF/DKIM/DMARC.",
                       source="DNS")
    try:
        from domain_email_security import run_domain_check
        result = await run_domain_check(db, domain, label=f"vendor:{domain}")
    except Exception as e:
        return _result("email_authentication", "manual",
                       f"Email-auth check failed ({type(e).__name__}).", source="DNS")
    problems = []
    for axis in ("spf", "dkim", "dmarc"):
        axis_result = (result or {}).get(axis) or {}
        if axis_result.get("status") not in ("pass", "ok", "present", None):
            problems.append(f"{axis.upper()}: {axis_result.get('status') or 'missing'}")
    return _result("email_authentication", "attention" if problems else "ok",
                   ("Issues — " + "; ".join(problems)) if problems
                   else "SPF, DKIM, and DMARC all look configured.",
                   result, source=f"DNS ({domain})")


async def _shodan_exposure(db, entity: dict) -> dict:
    """What Shodan already knows about the vendor's domain, via whatever assets
    we've enriched. Deliberately does NOT actively scan the vendor -- that's
    their infrastructure, not ours."""
    domain = (entity.get("domain") or "").lower()
    if not domain:
        return _result("shodan_exposure", "manual", "No vendor domain to correlate.", source="Shodan")
    integration = await db.integrations.find_one({"name": "Shodan"}, {"_id": 0})
    if not ((integration or {}).get("config") or {}).get("api_key"):
        return _result("shodan_exposure", "not_configured",
                       "Shodan isn't configured — add an API key under Integrations → Shodan.",
                       source="Shodan")
    import httpx
    try:
        endpoint = (integration.get("config") or {}).get("endpoint") or "https://api.shodan.io"
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(f"{endpoint.rstrip('/')}/shodan/host/search",
                             params={"key": integration["config"]["api_key"],
                                     "query": f"hostname:{domain}", "minify": "true"})
    except Exception as e:
        return _result("shodan_exposure", "manual", f"Shodan query failed ({type(e).__name__}).",
                       source="Shodan")
    if r.status_code == 401:
        return _result("shodan_exposure", "not_configured", "Shodan rejected the API key (401).", source="Shodan")
    if r.status_code != 200:
        return _result("shodan_exposure", "manual", f"Shodan HTTP {r.status_code}.", source="Shodan")
    data = r.json()
    total = data.get("total", 0)
    ports, vulns = set(), set()
    for m in (data.get("matches") or [])[:50]:
        if m.get("port"):
            ports.add(m["port"])
        for v in (m.get("vulns") or []):
            vulns.add(v)
    return _result("shodan_exposure", "attention" if vulns else "ok",
                   f"{total} internet-facing host record(s) for {domain}"
                   + (f"; ports {', '.join(str(p) for p in sorted(ports)[:12])}" if ports else "")
                   + (f"; Shodan flags {len(vulns)} CVE(s)" if vulns else ""),
                   {"total": total, "ports": sorted(ports), "vulns": sorted(vulns)}, source="Shodan")


async def _ct_logs(db, entity: dict) -> dict:
    """Certificate transparency for the vendor domain -- reuses the shared CT
    service (item 35) so there's one crt.sh client in the codebase."""
    domain = (entity.get("domain") or "").lower()
    if not domain:
        return _result("certificate_transparency", "manual", "No vendor domain to query CT logs for.",
                       source="crt.sh")
    try:
        from ct_service import fetch_certificates
        certs = await fetch_certificates(domain)
    except Exception as e:
        return _result("certificate_transparency", "manual",
                       f"CT lookup failed ({type(e).__name__}).", source="crt.sh")
    names = set()
    issuers = set()
    for c in certs[:300]:
        for n in (c.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n:
                names.add(n)
        if c.get("issuer_name"):
            issuers.add(c["issuer_name"].split(",")[-1].strip())
    return _result("certificate_transparency", "ok",
                   f"{len(certs)} certificate(s) in CT logs covering {len(names)} hostname(s)"
                   + (f"; issuers include {', '.join(sorted(issuers)[:3])}" if issuers else ""),
                   {"cert_count": len(certs), "hostnames": sorted(names)[:50],
                    "issuers": sorted(issuers)[:10]}, source="crt.sh")


async def _dns_whois(entity: dict) -> dict:
    """DNS hygiene + domain age. A vendor domain registered three weeks ago is a
    different proposition from one registered in 2009, and that single fact
    catches a surprising amount."""
    domain = (entity.get("domain") or "").lower()
    if not domain:
        return _result("dns_whois", "manual", "No vendor domain to inspect.", source="DNS/WHOIS")
    detail = {}
    problems = []
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver.lifetime = 4
        for rtype in ("A", "NS", "MX"):
            try:
                detail[rtype] = [a.to_text() for a in resolver.resolve(domain, rtype)]
            except Exception:
                detail[rtype] = []
        if not detail.get("A"):
            problems.append("no A record resolves")
        if len(detail.get("NS") or []) < 2:
            problems.append("fewer than 2 nameservers (single point of failure)")
        if not detail.get("MX"):
            problems.append("no MX record (mail from this domain may be unverifiable)")
    except Exception as e:
        return _result("dns_whois", "manual", f"DNS lookup failed ({type(e).__name__}).", source="DNS")
    try:
        import whois  # optional dependency; degrade cleanly if absent
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            detail["created"] = str(created)[:10]
            age_days = (datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc)).days
            detail["age_days"] = age_days
            if age_days < 180:
                problems.append(f"domain registered only {age_days} days ago")
    except Exception:
        detail["whois"] = "unavailable (whois module or lookup not available)"
    return _result("dns_whois", "attention" if problems else "ok",
                   ("Issues — " + "; ".join(problems)) if problems
                   else f"DNS looks healthy ({len(detail.get('NS') or [])} nameservers, MX present)"
                        + (f", domain registered {detail.get('created')}" if detail.get("created") else ""),
                   detail, source="DNS/WHOIS")


async def _typosquat(db, entity: dict) -> dict:
    """Lookalikes of the VENDOR's domain -- someone squatting a vendor we're
    about to route staff and payments through is our problem too."""
    domain = (entity.get("domain") or "").lower()
    if not domain:
        return _result("typosquat", "manual", "No vendor domain to permute.", source="DNS")
    try:
        from cti import scan_typosquats
        result = await scan_typosquats(db, domain, max_checks=120)
    except Exception as e:
        return _result("typosquat", "manual", f"Typosquat scan failed ({type(e).__name__}).", source="DNS")
    registered = result.get("registered", 0)
    return _result("typosquat", "attention" if registered else "ok",
                   f"{result.get('checked', 0)} permutations checked; {registered} registered lookalike(s)"
                   + (f", {result.get('new', 0)} newly discovered" if result.get("new") else ""),
                   {"items": result.get("items", [])[:20]}, source="DNS permutation scan")


async def technical_posture(db, entity: dict) -> dict:
    checks = await asyncio.gather(
        _tls_headers(entity),
        _cve_lookup(entity),
        _email_auth(db, entity),
        _shodan_exposure(db, entity),
        _ct_logs(db, entity),
        _dns_whois(entity),
        _typosquat(db, entity),
        return_exceptions=True,
    )
    out = []
    for c in checks:
        if isinstance(c, Exception):
            out.append(_result("unknown_check", "manual", f"Check failed: {type(c).__name__}"))
        else:
            out.append(c)
    return {"panel": "technical_posture", "ran_at": _now_iso(), "results": out}


async def run_external_checks(db, review: dict, panel: Optional[str] = None) -> dict:
    """Runs one or both panels for a review's entity, and persists the result on
    the review so the workspace and report can show it without re-running."""
    entity = None
    if review.get("entity_id"):
        entity = await db.reviewed_entities.find_one({"id": review["entity_id"]}, {"_id": 0})
    if not entity:
        entity = {"name": review.get("entity_name"), "domain": review.get("entity_domain")}
    # the review's own fields win if the entity record is thinner
    entity = {**entity,
              "name": entity.get("name") or review.get("entity_name"),
              "domain": entity.get("domain") or review.get("entity_domain")}

    payload = {"ran_at": _now_iso(), "entity": {k: entity.get(k) for k in
               ("name", "legal_name", "domain", "jurisdiction")}}
    prereqs = []
    if not entity.get("domain"):
        prereqs.append("Set the vendor's domain on the entity to enable the technical checks.")
    if not (entity.get("legal_name") or entity.get("name")):
        prereqs.append("Set the legal company name to enable the corporate-registration check.")
    payload["prerequisites"] = prereqs

    if panel in (None, "company"):
        payload["company_posture"] = await company_posture(db, entity)
    if panel in (None, "technical"):
        payload["technical_posture"] = await technical_posture(db, entity)

    await db.security_reviews.update_one({"id": review["id"]}, {"$set": {"external_checks": payload}})
    return payload
