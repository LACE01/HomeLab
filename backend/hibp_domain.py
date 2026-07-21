"""HaveIBeenPwned domain-wide breach monitoring for the org's OWN domain -- distinct
from the per-email hibp_breach/hibp_paste lookups added to reconng.py (those check
ONE address you type in, on demand, from the Recon & OSINT hub). This checks every
account HIBP has ever indexed under your verified domain in a single call and reports
back which of your employees' breach exposure actually needs following up on --
meant to run nightly, not on demand.

Real HIBP API contract (verified against Have I Been Pwned's own v3 API docs, not
guessed):
  GET https://haveibeenpwned.com/api/v3/breacheddomain/{domain}
  header: hibp-api-key: <subscription key>
  200 -> {"alias1": ["Adobe"], "alias2": ["Adobe", "Gawker"], ...} -- alias is the
         local-part of the email address (before the @), mapped to the names of every
         breach it appeared in.
  404 -> domain verified, zero breached accounts on record (genuinely good news).
  403 -> the domain has NOT been verified for Domain Search under this API key yet.

Domain verification is a one-time MANUAL step this app cannot do for you: go to
haveibeenpwned.com -> Domain search, add the domain, and add the DNS TXT record it
gives you to prove ownership. There is no API for that step -- HIBP deliberately
keeps it a human, out-of-band action so a leaked API key alone can never be used to
enumerate an arbitrary company's breach exposure. Once verified, this sync just works
on its own, same as every other nightly job.
"""
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("vulnops.hibp_domain")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def sync_hibp_stealer_logs(db) -> dict:
    """HaveIBeenPwned's stealer-log domain search -- distinct from breacheddomain
    above. Breach records come from known, named data breaches; stealer logs come
    from malware (infostealers like RedLine/Raccoon/Vidar) that harvested
    credentials directly off infected machines and had them show up in a
    known stealer-log dump, regardless of whether the SITE they logged into was
    ever itself breached. A stealer-log hit is a strong signal that a specific
    employee's own device was compromised, not just that some third-party service
    they used got breached.

    Real HIBP API contract (verified against the API's own published Node client
    docs, since HIBP's own site is heavy on client-rendered content that doesn't
    reliably fetch as plain HTML -- same endpoint naming/shape the official
    haveibeenpwned.com/API/v3 docs describe):
      GET https://haveibeenpwned.com/api/v3/stealerlogsbyemaildomain/{domain}
      header: hibp-api-key: <subscription key>
      200 -> {"alias1": ["netflix.com", "spotify.com"], ...} -- alias is the
             local-part of the email address, mapped to the external website
             domains that alias's stolen credentials were found logged into.
      404 -> domain verified, zero stealer-log hits on record (good news).
      403 -> either the domain isn't verified for Domain Search yet, OR this API
             key's subscription tier doesn't include stealer log data (it's a
             separate entitlement from base Domain Search -- see
             SubscriptionStatus.IncludesStealerLogs).

    Uses the same Integrations -> HaveIBeenPwned api_key/domain config as
    sync_hibp_domain_breaches -- one HIBP subscription key covers both."""
    integration = await db.integrations.find_one({"name": "HaveIBeenPwned"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint") or "https://haveibeenpwned.com/api/v3"
    api_key = cfg.get("api_key")
    domain = (cfg.get("domain") or "").strip().lower()
    if not api_key:
        raise RuntimeError("HaveIBeenPwned isn't configured yet -- add an API key under Integrations → HaveIBeenPwned.")
    if not domain:
        raise RuntimeError("No domain set -- add your org's verified domain (e.g. example.com) under Integrations → HaveIBeenPwned → Domain.")

    url = f"{endpoint.rstrip('/')}/stealerlogsbyemaildomain/{domain}"
    headers = {"hibp-api-key": api_key, "user-agent": "Nightwatch-VulnMgmt"}
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(url, headers=headers)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach HaveIBeenPwned: {e}")

    if r.status_code == 403:
        raise RuntimeError(
            f"HaveIBeenPwned rejected this request (403) -- either '{domain}' hasn't been verified for "
            f"Domain Search yet, or this API key's subscription tier doesn't include stealer log data "
            f"(it's a separate entitlement from base Domain Search). Check your plan at "
            f"haveibeenpwned.com → API Key."
        )
    if r.status_code == 401:
        raise RuntimeError("HaveIBeenPwned rejected this API key (401) -- check it under Integrations → HaveIBeenPwned.")
    if r.status_code == 429:
        raise RuntimeError("HaveIBeenPwned rate limit hit (429) -- wait a moment and retry.")
    if r.status_code == 404:
        alias_map = {}
    elif r.status_code != 200:
        raise RuntimeError(f"HaveIBeenPwned HTTP {r.status_code}: {r.text[:200]}")
    else:
        alias_map = r.json() or {}

    from reconng import _ingest_osint_rows
    mod = {"id": "hibp_stealer_logs", "label": "HaveIBeenPwned — Stealer Logs", "category": "threat-intel"}
    rows = []
    for alias, sites in alias_map.items():
        if not alias:
            continue
        email = f"{alias}@{domain}"
        site_list = ", ".join(sorted(str(s) for s in (sites or [])))
        # Same reasoning as sync_hibp_domain_breaches: bake the affected sites into
        # the label so a NEW site showing up for an already-flagged alias is
        # correctly treated as a new, separately-notifiable finding.
        rows.append({
            "name": f"HaveIBeenPwned stealer log: {email} — credentials found for {site_list}",
            "resource": email,
            "detail": f"{email}'s credentials were found in a stealer log, harvested while logging into: "
                      f"{site_list or 'an unnamed site'}. This indicates the device itself was infected with "
                      f"credential-stealing malware, not just that a third-party service was breached -- "
                      f"treat as a likely-compromised endpoint/account until investigated.",
        })
    created = await _ingest_osint_rows(db, mod, domain, rows)

    return {
        "domain": domain, "stealer_log_accounts_found": len(alias_map),
        "osint_findings_created": created, "synced_at": _now_iso(),
    }


async def sync_hibp_domain_breaches(db) -> dict:
    integration = await db.integrations.find_one({"name": "HaveIBeenPwned"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint") or "https://haveibeenpwned.com/api/v3"
    api_key = cfg.get("api_key")
    domain = (cfg.get("domain") or "").strip().lower()
    if not api_key:
        raise RuntimeError("HaveIBeenPwned isn't configured yet -- add an API key under Integrations → HaveIBeenPwned.")
    if not domain:
        raise RuntimeError("No domain set -- add your org's verified domain (e.g. example.com) under Integrations → HaveIBeenPwned → Domain.")

    url = f"{endpoint.rstrip('/')}/breacheddomain/{domain}"
    headers = {"hibp-api-key": api_key, "user-agent": "Nightwatch-VulnMgmt"}
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(url, headers=headers)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach HaveIBeenPwned: {e}")

    if r.status_code == 403:
        raise RuntimeError(
            f"HaveIBeenPwned rejected this request (403) -- '{domain}' hasn't been verified for "
            f"Domain Search under this API key yet. Go to haveibeenpwned.com → Domain search, add "
            f"'{domain}', and add the DNS TXT record it gives you to prove ownership (a one-time "
            f"manual step -- there's no API for it). Once verified, re-run this sync."
        )
    if r.status_code == 401:
        raise RuntimeError("HaveIBeenPwned rejected this API key (401) -- check it under Integrations → HaveIBeenPwned.")
    if r.status_code == 429:
        raise RuntimeError("HaveIBeenPwned rate limit hit (429) -- wait a moment and retry.")
    if r.status_code == 404:
        # HIBP returns 404 (not an empty 200) when the verified domain has zero
        # breached accounts on record -- genuinely good news, not an error.
        alias_map = {}
    elif r.status_code != 200:
        raise RuntimeError(f"HaveIBeenPwned HTTP {r.status_code}: {r.text[:200]}")
    else:
        alias_map = r.json() or {}

    from reconng import _ingest_osint_rows
    mod = {"id": "hibp_domain", "label": "HaveIBeenPwned — Domain Search", "category": "threat-intel"}
    rows = []
    for alias, breaches in alias_map.items():
        if not alias:
            continue
        email = f"{alias}@{domain}"
        breach_names = ", ".join(sorted(str(b) for b in (breaches or [])))
        # Breach names are baked into the label (not just "detail") on purpose: the
        # ingest dedup key is `{module}:{target}:{label}`, so if the same alias later
        # turns up in an ADDITIONAL breach, the label -- and therefore the key --
        # changes, and it's correctly treated as a new, separately-notifiable finding
        # instead of silently merging into the original one and never re-alerting.
        rows.append({
            "name": f"HaveIBeenPwned: {email} — {breach_names}",
            "resource": email,
            "detail": f"{email} appears in: {breach_names or 'unnamed breach(es)'}",
        })
    created = await _ingest_osint_rows(db, mod, domain, rows)

    return {
        "domain": domain, "breached_accounts_found": len(alias_map),
        "osint_findings_created": created, "synced_at": _now_iso(),
    }
