"""Microsoft Entra ID (Azure AD) directory sync -- pulls real users and groups via
Microsoft Graph, closing the gap where this app previously had no per-employee
identity data at all (no user list, no group membership, no way to answer "which
enabled accounts haven't been used in months"). Flags stale accounts (enabled, but no
recorded sign-in within STALE_DAYS -- or never signed in and older than STALE_DAYS)
since that's one of the highest-value, lowest-effort findings an identity sync can
surface for a security team.

Auth: client-credentials via msgraph.py, scope https://graph.microsoft.com/.default.
Required Graph application permissions (grant + admin-consent on the app registration
before syncing): User.Read.All (for the user list itself), and additionally
AuditLog.Read.All + Organization.Read.All if you want signInActivity (last sign-in)
populated. Without those two, users still sync fine and is_stale falls back to
account-age-based detection -- signInActivity is the single most commonly-forgotten
permission grant for exactly this scenario, so this degrades gracefully instead of
failing the whole sync over it.

Groups are synced without per-group membership counts on purpose -- fetching every
member of every group is a call-per-group operation that doesn't scale predictably
across tenants of very different sizes, and isn't needed for what this app actually
uses group data for (an overview list + name matching, not access-review tooling).

Not verified against a live tenant in this sandbox -- see msgraph.py's docstring for
what an AADSTS error usually means if the first real sync fails.
"""
import logging
from datetime import datetime, timezone, timedelta

from msgraph import get_client_credentials_token, graph_get_paginated

logger = logging.getLogger("vulnops.entra")

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
STALE_DAYS = 45


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


async def sync_entra_directory(db) -> dict:
    integration = await db.integrations.find_one({"name": "Microsoft Entra ID"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    base = (cfg.get("endpoint") or "https://graph.microsoft.com/v1.0").rstrip("/")

    token = await get_client_credentials_token(db, "Microsoft Entra ID", GRAPH_SCOPE)

    users_raw = await graph_get_paginated(
        token, f"{base}/users",
        params={"$select": "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,signInActivity", "$top": "999"},
    )

    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=STALE_DAYS)
    now_iso = now.isoformat()

    users_synced = 0
    stale_count = 0
    disabled_count = 0
    signin_data_available = False
    for u in users_raw:
        signin = u.get("signInActivity") or {}
        last_signin = signin.get("lastSignInDateTime") or signin.get("lastNonInteractiveSignInDateTime")
        if last_signin:
            signin_data_available = True
        is_enabled = bool(u.get("accountEnabled"))
        if not is_enabled:
            disabled_count += 1

        is_stale = False
        if is_enabled:
            last_dt = _parse_dt(last_signin)
            if last_dt:
                is_stale = last_dt < stale_cutoff
            elif not last_signin:
                # No sign-in activity recorded at all -- either the permission grant
                # is missing (see docstring) or the account has genuinely never signed
                # in. Fall back to account age so a long-dormant/never-used account
                # still surfaces as stale even without AuditLog.Read.All.
                created_dt = _parse_dt(u.get("createdDateTime"))
                if created_dt:
                    is_stale = created_dt < stale_cutoff
        if is_stale:
            stale_count += 1

        await db.directory_users.update_one(
            {"id": u["id"]},
            {"$set": {
                "id": u["id"], "display_name": u.get("displayName"),
                "upn": u.get("userPrincipalName"), "email": u.get("mail"),
                "enabled": is_enabled,
                "created_at": u.get("createdDateTime"),
                "last_sign_in_at": last_signin,
                "is_stale": is_stale,
                "synced_at": now_iso, "source": "entra_id",
            }},
            upsert=True,
        )
        users_synced += 1

    groups_raw = await graph_get_paginated(
        token, f"{base}/groups",
        params={"$select": "id,displayName,securityEnabled,mailEnabled,groupTypes", "$top": "999"},
    )
    groups_synced = 0
    for g in groups_raw:
        await db.directory_groups.update_one(
            {"id": g["id"]},
            {"$set": {
                "id": g["id"], "display_name": g.get("displayName"),
                "security_enabled": bool(g.get("securityEnabled")),
                "mail_enabled": bool(g.get("mailEnabled")),
                "group_types": g.get("groupTypes") or [],
                "synced_at": now_iso, "source": "entra_id",
            }},
            upsert=True,
        )
        groups_synced += 1

    if stale_count > 0:
        try:
            from notifier import dispatch
            await dispatch("stale_accounts_found", {
                "count": stale_count, "stale_days": STALE_DAYS, "url": "/directory",
            }, db)
        except Exception:
            logger.exception("stale_accounts_found dispatch failed")

    return {
        "users_synced": users_synced, "groups_synced": groups_synced,
        "stale_accounts": stale_count, "disabled_accounts": disabled_count,
        "signin_data_available": signin_data_available,
        "synced_at": now_iso,
    }
