"""Shared OAuth2 client-credentials helper for the three Azure-AD-backed connectors
(Microsoft Entra ID, Microsoft Defender for Endpoint, Microsoft Intune -- see
entra_sync.py / defender_sync.py / intune_sync.py). All three authenticate the same
way (an Azure AD app registration's tenant_id/client_id/client_secret, client-
credentials grant against the v2.0 token endpoint) but request a token for a
different resource/scope: Entra ID and Intune both go through Microsoft Graph
(scope=https://graph.microsoft.com/.default), Defender for Endpoint uses its own
separate API surface with its own token audience
(scope=https://api.security.microsoft.com/.default). A token minted for one is not
valid against the other -- there is no shared "Microsoft token" here.

Not verified against a live Azure tenant in this sandbox (no test tenant available
here). The token request shape below matches Microsoft's own documented client-
credentials flow exactly, but treat the first real sync the same way reconng.py's
docstring already asks you to treat a first recon-ng run: as a smoke test. If Azure
AD rejects the request, the `error_description` it returns is surfaced verbatim in
the raised exception -- usually enough to tell whether it's a wrong secret
(AADSTS7000215), a client/app not found in the tenant (AADSTS700016), or an API
permission that hasn't been granted (and admin-consented) to the app registration yet
(commonly AADSTS65001 / AADSTS500011 / AADSTS90002-family errors), without needing to
dig through Azure's portal blind.
"""
import logging
import time

import httpx

logger = logging.getLogger("vulnops.msgraph")

# In-process token cache: (tenant_id, client_id, scope) -> (access_token, expires_at_epoch).
# Deliberately in-process rather than persisted to Mongo -- an access token is only
# ever useful to whichever process holds it for the next ~55 minutes, and caching it
# in the database would mean writing a live bearer credential to disk for no benefit.
_TOKEN_CACHE: dict = {}

TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


async def get_client_credentials_token(db, integration_name: str, scope: str, force_refresh: bool = False) -> str:
    """Returns a cached-if-fresh access token for the named integration's Azure AD
    app registration, transparently refreshing when the cached one is expired (or
    about to be within 60s). force_refresh=True skips the cache entirely -- used by
    the Integrations "Test" button so a stale cached failure can never mask a secret
    that was just fixed."""
    integration = await db.integrations.find_one({"name": integration_name}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    tenant_id, client_id, client_secret = cfg.get("tenant_id"), cfg.get("client_id"), cfg.get("client_secret")
    if not (tenant_id and client_id and client_secret):
        raise ValueError(
            f"{integration_name} isn't configured yet -- add tenant ID, client ID, and "
            f"client secret under Integrations → {integration_name}."
        )

    cache_key = (tenant_id, client_id, scope)
    if not force_refresh:
        cached = _TOKEN_CACHE.get(cache_key)
        if cached and cached[1] > time.time() + 60:
            return cached[0]

    url = TOKEN_URL_TMPL.format(tenant_id=tenant_id)
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
        "grant_type": "client_credentials",
    }
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(url, data=data)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach the Azure AD token endpoint for {integration_name}: {e}")

    try:
        body = r.json()
    except Exception:
        body = {}

    if r.status_code != 200:
        detail = body.get("error_description") or body.get("error") or r.text[:300] or f"HTTP {r.status_code}"
        raise RuntimeError(f"Azure AD rejected the {integration_name} app registration: {detail}")

    token = body.get("access_token")
    expires_in = body.get("expires_in", 3600)
    if not token:
        raise RuntimeError(f"Azure AD token response for {integration_name} had no access_token: {body}")

    _TOKEN_CACHE[cache_key] = (token, time.time() + expires_in)
    return token


async def graph_get_paginated(token: str, url: str, params: dict | None = None, timeout: int = 30, max_pages: int = 50) -> list:
    """GETs a Graph/Defender-style paginated endpoint, following @odata.nextLink until
    exhausted or max_pages is hit -- a hard cap so a single sync can't run away
    against an enormous tenant (50 pages at Graph's default ~100-999 rows/page is
    already tens of thousands of records, far beyond what a home-lab-scale asset
    inventory needs to cross-reference against). Returns the concatenated `value`
    arrays from every page it fetched."""
    items: list = []
    headers = {"Authorization": f"Bearer {token}"}
    next_url = url
    next_params = params
    pages = 0
    async with httpx.AsyncClient(timeout=timeout) as c:
        while next_url and pages < max_pages:
            r = await c.get(next_url, headers=headers, params=next_params)
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code} from {next_url}: {r.text[:300]}")
            data = r.json()
            items.extend(data.get("value") or [])
            next_url = data.get("@odata.nextLink")
            next_params = None  # nextLink already carries every query param baked in
            pages += 1
    return items
