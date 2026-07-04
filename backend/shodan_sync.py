"""Shodan enrichment -- for every asset with a public IP, pulls what Shodan sees
exposed on it (open ports, service banners, and anything Shodan itself flags as a
known vulnerability) and stamps it on the asset. This is deliberately enrichment-only:
it never creates new assets or new findings, since Qualys/Nmap/Nikto already own
finding-creation and duplicating that here would just create dedup headaches. Shodan
is instead a second, independent vantage point ("what does the outside internet
actually see on this host") layered onto assets you already track.

Auth: a single API key as a query parameter -- much simpler than the other
connectors here. Real host lookups (GET /shodan/host/{ip}) require a paid Shodan
membership; Shodan's free `internetdb.shodan.io/{ip}` endpoint covers ports/vulns/
hostnames/tags without a key at all, but since this connector is meant to be
configured with an API key under Integrations, it calls the real paid endpoint.
"""
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("vulnops.shodan")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _lookup_host(endpoint: str, api_key: str, ip: str) -> dict | None:
    url = f"{endpoint.rstrip('/')}/shodan/host/{ip}"
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(url, params={"key": api_key, "minify": "false"})
    if r.status_code == 404:
        return None  # Shodan has never seen this IP -- not an error, just nothing to add
    if r.status_code == 401:
        raise RuntimeError("Shodan rejected this API key (401) -- check the key under Integrations → Shodan.")
    if r.status_code == 403:
        raise RuntimeError("Shodan API returned 403 -- this usually means the key's plan doesn't include host lookups "
                            "(the free API tier only covers search credits, not the /shodan/host endpoint).")
    if r.status_code == 429:
        raise RuntimeError("Shodan rate limit hit (429) -- your plan's query credits are exhausted for now.")
    if r.status_code != 200:
        raise RuntimeError(f"Shodan API error: HTTP {r.status_code}: {r.text[:200]}")
    return r.json()


async def sync_shodan_assets(db, max_assets: int = 300) -> dict:
    """Best-effort pass over assets that have a public IP recorded. Caps how many it
    checks per run (max_assets) since each one costs a Shodan query credit -- this
    isn't meant to burn through a whole plan's credits in one sync."""
    integration = await db.integrations.find_one({"name": "Shodan"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint, api_key = cfg.get("endpoint") or "https://api.shodan.io", cfg.get("api_key")
    if not api_key:
        raise RuntimeError("Shodan isn't configured yet -- add an API key under Integrations → Shodan.")

    # Only assets flagged as internet-facing are worth checking against Shodan --
    # querying Shodan about a purely internal RFC1918 address will just come back
    # empty (or worse, match an unrelated host if that address happens to be public
    # elsewhere), so this only spends credits where there's a real signal to find.
    assets = await db.assets.find(
        {"ip": {"$exists": True, "$ne": None}, "exposure": {"$in": ["internet", "external"]}},
        {"_id": 0, "id": 1, "ip": 1},
    ).to_list(max_assets)

    checked = 0
    enriched = 0
    for a in assets:
        checked += 1
        try:
            data = await _lookup_host(endpoint, api_key, a["ip"])
        except RuntimeError:
            raise  # config/auth problems should stop the run and surface clearly
        except Exception as e:
            logger.warning(f"Shodan lookup failed for {a['ip']}: {e}")
            continue
        if not data:
            continue
        vulns = sorted((data.get("vulns") or {}).keys())
        patch = {
            "shodan_synced_at": _now_iso(),
            "shodan_ports": sorted(data.get("ports") or []),
            "shodan_org": data.get("org"),
            "shodan_hostnames": data.get("hostnames") or [],
            "shodan_tags": data.get("tags") or [],
            "shodan_vulns": vulns,
        }
        await db.assets.update_one({"id": a["id"]}, {"$set": patch})
        enriched += 1

    return {"assets_checked": checked, "assets_enriched": enriched}
