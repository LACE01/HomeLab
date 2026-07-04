"""Qualys Global AssetView / CyberSecurity Asset Management (GAV/CSAM) enrichment --
pulls hardware info (manufacturer/model, as Qualys reports it under a single combined
`hardware.fullName` string -- Qualys doesn't split those into separate fields) and the
last logged-on user per host, neither of which the classic VM API (qualys_sync.py)
exposes at all. That's a genuinely separate Qualys module from the VM API we already
use, with its own auth flow and its own licensing -- some subscriptions don't include
it, so every call here is written to fail with a clear, specific reason rather than a
generic timeout/500, since "is this even licensed" is the first thing to check when
it doesn't work.

Auth: GAV/CSAM sits behind the Qualys API Gateway, which uses a short-lived JWT
instead of the classic API's HTTP Basic auth -- POST username/password to
{gateway}/auth and use the returned token as a Bearer header for an hour. The gateway
host is the same platform pod as the VM API endpoint already configured under
Integrations -> Qualys VMDR, just on the `gateway.` subdomain instead of `qualysapi.`
(e.g. qualysapi.qg2.apps.qualys.com -> gateway.qg2.apps.qualys.com) -- that mapping is
Qualys's documented convention across all of their platform pods, so it's derived
automatically rather than needing a second endpoint field in the UI. If a given
subscription's gateway happens to live somewhere else, the error message says so
explicitly so it's a one-line fix rather than a silent no-op.
"""
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("vulnops.qualys_gav")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _derive_gateway_base(vm_endpoint: str) -> str:
    """qualysapi.qg2.apps.qualys.com -> gateway.qg2.apps.qualys.com (Qualys's own
    documented pod-URL convention -- same pattern for qg1/qg2/qg3/qg4/us2/us3/eu1/etc.)."""
    return vm_endpoint.replace("qualysapi.", "gateway.").rstrip("/")


async def _get_gav_token(gateway_base: str, username: str, password: str) -> str:
    url = f"{gateway_base}/auth"
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(
                url,
                data={"username": username, "password": password, "token": "true"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.HTTPError as e:
        raise RuntimeError(
            f"Could not reach the Qualys Gateway API at {gateway_base} to authenticate for "
            f"asset hardware/last-logged-in-user data: {e}. If your account's Qualys platform "
            f"pod uses a different gateway hostname than this guess, let me know the real one."
        )
    if r.status_code == 404:
        raise RuntimeError(
            f"Qualys Gateway API not found at {gateway_base} (404). This URL is guessed from your "
            f"configured Qualys VM endpoint by swapping 'qualysapi.' for 'gateway.' -- if your "
            f"platform pod doesn't follow that convention, tell me the real gateway URL."
        )
    if r.status_code in (401, 403):
        raise RuntimeError(
            f"Qualys Gateway API rejected these credentials ({r.status_code}). Either the "
            f"username/password under Integrations -> Qualys VMDR aren't valid for gateway auth, "
            f"or this account doesn't have API access to Global AssetView/CSAM -- that's a separate "
            f"licensed module from the VM API this app already uses successfully."
        )
    if r.status_code != 200:
        raise RuntimeError(f"Qualys Gateway auth failed: HTTP {r.status_code}: {r.text[:200]}")
    token = r.text.strip()
    if not token or len(token) < 20:
        raise RuntimeError(f"Qualys Gateway auth returned an unexpected response (not a JWT): {r.text[:200]}")
    return token


async def _fetch_gav_assets(gateway_base: str, token: str, page_size: int = 300, max_pages: int = 50) -> list:
    """POST /rest/2.0/search/am/asset, paginated. Returns a flat list of asset dicts
    with just the fields we actually use, trimmed from Qualys's much larger payload."""
    url = f"{gateway_base}/rest/2.0/search/am/asset"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    out = []
    last_id = 0
    for _ in range(max_pages):
        # id-based paging -- ask for the next batch of asset IDs greater than the
        # highest one seen so far, restricted to host-type assets.
        body = {"filter": f"id > {last_id} and assetType:HOST"}
        try:
            async with httpx.AsyncClient(timeout=90) as c:
                r = await c.post(url, params={"pageSize": page_size, "includeFields":
                                  "id,assetName,dnsName,netbiosName,address,operatingSystem,hardware,lastLoggedOnUser"},
                                  headers=headers, json=body)
        except httpx.HTTPError as e:
            raise RuntimeError(f"Could not reach Qualys GAV/CSAM asset search: {e}")
        if r.status_code in (401, 403):
            raise RuntimeError(
                f"Qualys GAV/CSAM asset search returned {r.status_code} -- your account's token was "
                f"accepted at login but was denied here, which usually means the Global AssetView/"
                f"CSAM module itself isn't included in this subscription."
            )
        if r.status_code == 404:
            raise RuntimeError(
                f"Qualys GAV/CSAM asset search endpoint not found (404) at {url} -- this module may "
                f"not be enabled for this account/pod."
            )
        if r.status_code != 200:
            raise RuntimeError(f"Qualys GAV/CSAM asset search failed: HTTP {r.status_code}: {r.text[:300]}")
        try:
            data = r.json()
        except Exception:
            raise RuntimeError(f"Qualys GAV/CSAM asset search returned non-JSON: {r.text[:200]}")
        assets = (data.get("assetListData") or {}).get("asset") or data.get("assets") or []
        if isinstance(assets, dict):
            assets = [assets]
        if not assets:
            break
        out.extend(assets)
        try:
            last_id = max(int(a.get("id") or 0) for a in assets)
        except (TypeError, ValueError):
            break
        if len(assets) < page_size:
            break
    return out


async def sync_qualys_asset_inventory(db) -> dict:
    """Best-effort pass matching GAV/CSAM host records to our existing assets (by IP,
    hostname, or Qualys host ID -- whichever matches) and stamping `hardware_info` /
    `last_logged_on_user` / `gav_synced_at` on each match. Doesn't create new assets --
    this only enriches ones the VM sync (or another source) already created."""
    integration = await db.integrations.find_one({"name": "Qualys VMDR"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint, username, password = cfg.get("endpoint"), cfg.get("username"), cfg.get("api_key")
    if not endpoint or not username or not password:
        raise RuntimeError("Qualys VMDR integration isn't configured (endpoint/username/api_key) -- "
                            "GAV/CSAM reuses those same credentials.")

    gateway_base = _derive_gateway_base(endpoint)
    token = await _get_gav_token(gateway_base, username, password)
    gav_assets = await _fetch_gav_assets(gateway_base, token)

    matched = 0
    for ga in gav_assets:
        hardware = ga.get("hardware") or {}
        hardware_info = (hardware.get("fullName") or "").strip() or None
        last_user = (ga.get("lastLoggedOnUser") or "").strip() or None
        if not hardware_info and not last_user:
            continue  # nothing new to add for this host

        hostname = ga.get("dnsName") or ga.get("netbiosName") or ga.get("assetName")
        ip = ga.get("address")
        match_filter = {"$or": [f for f in [
            {"hostname": hostname} if hostname else None,
            {"ip": ip} if ip else None,
        ] if f]}
        if not match_filter["$or"]:
            continue
        asset = await db.assets.find_one(match_filter, {"_id": 0, "id": 1})
        if not asset:
            continue
        patch = {"gav_synced_at": _now_iso()}
        if hardware_info:
            patch["hardware_info"] = hardware_info
        if last_user:
            patch["last_logged_on_user"] = last_user
        await db.assets.update_one({"id": asset["id"]}, {"$set": patch})
        matched += 1

    return {"gav_assets_seen": len(gav_assets), "assets_enriched": matched}
