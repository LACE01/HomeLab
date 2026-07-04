"""Censys enrichment -- same idea as shodan_sync.py (a second independent vantage
point on what's exposed on your internet-facing assets), against the newer Censys
Platform API (not the older, now-deprecated v2 Search API with API-ID/API-Secret
Basic auth). Enrichment-only: never creates assets or findings.

Auth: a single Personal Access Token as a Bearer header, plus an optional
organization ID (only Starter/Enterprise Censys accounts have one -- Free-tier
accounts omit it and the API falls back to the free-tier permissions). The
`api_key` config field holds the PAT; `api_secret` (reused, not actually a secret
here) holds the optional organization ID -- this reuses the existing IntegrationConfig
shape instead of needing a new field just for this one connector.
"""
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("vulnops.censys")

ACCEPT_HEADER = "application/vnd.censys.api.v3.host.v1+json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _lookup_host(endpoint: str, token: str, org_id: str | None, ip: str) -> dict | None:
    url = f"{endpoint.rstrip('/')}/v3/global/asset/host/{ip}"
    headers = {"Authorization": f"Bearer {token}", "Accept": ACCEPT_HEADER}
    params = {}
    if org_id:
        params["organization_id"] = org_id
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(url, headers=headers, params=params)
    if r.status_code == 404:
        return None  # not found for this org's data-access tier -- not an error
    if r.status_code == 401:
        raise RuntimeError("Censys rejected this Personal Access Token (401) -- check it under Integrations → Censys.")
    if r.status_code == 403:
        raise RuntimeError("Censys API returned 403 -- your account may be missing the API Access role, "
                            "or your plan doesn't include host lookups.")
    if r.status_code == 422:
        raise RuntimeError(f"Censys API returned 422: {r.text[:200]} -- often means a missing/invalid organization ID.")
    if r.status_code != 200:
        raise RuntimeError(f"Censys API error: HTTP {r.status_code}: {r.text[:200]}")
    return r.json()


async def sync_censys_assets(db, max_assets: int = 300) -> dict:
    integration = await db.integrations.find_one({"name": "Censys"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint") or "https://api.platform.censys.io"
    token, org_id = cfg.get("api_key"), cfg.get("api_secret")
    if not token:
        raise RuntimeError("Censys isn't configured yet -- add a Personal Access Token under Integrations → Censys "
                            "(the API Key field), and your organization ID in the API Secret field if you have one.")

    assets = await db.assets.find(
        {"ip": {"$exists": True, "$ne": None}, "exposure": {"$in": ["internet", "external"]}},
        {"_id": 0, "id": 1, "ip": 1},
    ).to_list(max_assets)

    checked = 0
    enriched = 0
    for a in assets:
        checked += 1
        try:
            data = await _lookup_host(endpoint, token, org_id, a["ip"])
        except RuntimeError:
            raise
        except Exception as e:
            logger.warning(f"Censys lookup failed for {a['ip']}: {e}")
            continue
        if not data:
            continue
        resource = (data.get("result") or {}).get("resource") or {}
        services = resource.get("services") or []
        asn = resource.get("autonomous_system") or {}
        patch = {
            "censys_synced_at": _now_iso(),
            "censys_service_count": resource.get("service_count", len(services)),
            "censys_ports": sorted({s.get("port") for s in services if s.get("port") is not None}),
            "censys_protocols": sorted({s.get("protocol") for s in services if s.get("protocol")}),
            "censys_asn_name": asn.get("name") or asn.get("description"),
        }
        await db.assets.update_one({"id": a["id"]}, {"$set": patch})
        enriched += 1

    return {"assets_checked": checked, "assets_enriched": enriched}
