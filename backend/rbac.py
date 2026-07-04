"""Role-based module access control -- lets an admin decide which modules/pages each
role can see and use, instead of the admin/manager/analyst/executive role split having
one fixed, hardcoded set of capabilities. Every org draws these lines differently (who
counts as a "manager" and what they should see varies a lot) -- same philosophy as
criticality.py's scoring rules: the mapping below is a sensible starting point that's
fully editable from Reports & Admin -> Role Access, not a fixed policy.

A module's "key" is literally the frontend route path (e.g. "/findings",
"/admin/users") -- there's exactly one place (this registry) that needs to agree with
the Sidebar/App.js route list on what a "module" is, instead of a separate id that can
drift out of sync with the actual page.

Enforcement happens in two places:
  - Frontend: Sidebar hides nav items for modules a role can't access, and every Route
    is wrapped in a guard that shows a plain "access restricted" message for direct/
    typed URLs to a module the current user's role doesn't have.
  - Backend: `require_module(key)` gates each module's primary data endpoint, so this
    is real access control, not just a UI hint -- calling the API directly with a
    valid token doesn't bypass it. Coverage note: this is applied to one representative
    "main load" endpoint per module (the one the page's initial data fetch hits), not
    to every single sub-endpoint that module's page might also call -- doing that
    exhaustively across ~150 endpoints was out of scope for this pass. Treat this as
    real, but not yet total, backend enforcement.

"admin" always has access to everything, unconditionally -- this can't be configured
away, specifically so there's no way to lock every admin out of the one page (Role
Access) that could undo a mistake here.
"""
from fastapi import Depends, HTTPException

from auth_utils import get_current_user

ALL_ROLES = ["admin", "manager", "analyst", "executive"]
CONFIGURABLE_ROLES = [r for r in ALL_ROLES if r != "admin"]

MODULE_REGISTRY = [
    # --- Operations ---
    {"key": "/", "label": "Dashboard", "group": "Operations"},
    {"key": "/operational", "label": "Team Dashboards", "group": "Operations"},
    {"key": "/findings", "label": "Findings", "group": "Operations"},
    {"key": "/attack-paths", "label": "Attack Paths", "group": "Operations"},
    {"key": "/exposure", "label": "Exposure", "group": "Operations"},
    {"key": "/admin/tls-certs", "label": "TLS Certificates", "group": "Operations"},
    {"key": "/easm", "label": "Attack Surface", "group": "Operations"},
    {"key": "/tickets", "label": "Tickets", "group": "Operations"},
    {"key": "/exceptions", "label": "Exceptions", "group": "Operations"},
    {"key": "/admin/playbooks", "label": "Playbooks", "group": "Operations"},
    {"key": "/automation", "label": "Automation", "group": "Operations"},
    # --- Inventory ---
    {"key": "/assets", "label": "Assets", "group": "Inventory"},
    {"key": "/products", "label": "Products", "group": "Inventory"},
    {"key": "/engagements", "label": "Engagements", "group": "Inventory"},
    # --- Integrations ---
    {"key": "/integrations", "label": "Connectors", "group": "Integrations"},
    {"key": "/imports", "label": "Import Jobs", "group": "Integrations"},
    {"key": "/admin/web-scans", "label": "Web Scan Uploads", "group": "Integrations"},
    {"key": "/admin/nmap-scans", "label": "Nmap Scan Uploads", "group": "Integrations"},
    {"key": "/admin/nikto-scans", "label": "Web App Scans (Nikto)", "group": "Integrations"},
    {"key": "/admin/recon-osint", "label": "Recon & OSINT", "group": "Integrations"},
    {"key": "/admin/criticality-scoring", "label": "Criticality Scoring", "group": "Integrations"},
    {"key": "/admin/sbom", "label": "SBOM / Dependencies", "group": "Integrations"},
    {"key": "/admin/yara", "label": "YARA Scanning", "group": "Integrations"},
    # --- Reports & Admin ---
    {"key": "/reports", "label": "Reports", "group": "Reports & Admin"},
    {"key": "/compliance", "label": "Compliance", "group": "Reports & Admin"},
    {"key": "/admin", "label": "Admin", "group": "Reports & Admin"},
    {"key": "/admin/users", "label": "Users", "group": "Reports & Admin"},
    {"key": "/admin/teams", "label": "Teams", "group": "Reports & Admin"},
    {"key": "/admin/notifications", "label": "Notifications", "group": "Reports & Admin"},
    {"key": "/admin/chatops", "label": "ChatOps", "group": "Reports & Admin"},
    {"key": "/admin/health", "label": "System Health", "group": "Reports & Admin"},
    {"key": "/admin/backups", "label": "Backups", "group": "Reports & Admin"},
    {"key": "/admin/audit-log", "label": "Audit Log", "group": "Reports & Admin"},
    {"key": "/admin/assignment-rules", "label": "Assignment Rules", "group": "Reports & Admin"},
    {"key": "/admin/ownership", "label": "Ownership Map", "group": "Reports & Admin"},
    {"key": "/admin/sla-policies", "label": "SLA Policies", "group": "Reports & Admin"},
    {"key": "/admin/approval-routing", "label": "Approval Routing", "group": "Reports & Admin"},
    {"key": "/admin/rbac", "label": "Role Access", "group": "Reports & Admin"},
]
MODULE_KEYS = [m["key"] for m in MODULE_REGISTRY]

# Modules that default to admin-only until an admin opts other roles in -- mostly the
# sensitive/config-heavy corners of Reports & Admin. Everything else defaults to
# available for manager/analyst so turning this feature on doesn't immediately break
# anyone's current workflow; "executive" defaults to a small, read-oriented set since
# that's the role most orgs actually want restricted out of the box.
_ADMIN_ONLY_BY_DEFAULT = {
    "/admin/users", "/admin/notifications", "/admin/chatops", "/admin/health",
    "/admin/backups", "/admin/audit-log", "/admin/assignment-rules", "/admin/sla-policies",
    "/admin/approval-routing", "/admin/rbac",
}


def _default_access() -> dict:
    everyone = [m["key"] for m in MODULE_REGISTRY if m["key"] not in _ADMIN_ONLY_BY_DEFAULT]
    executive_view = ["/", "/operational", "/reports", "/compliance", "/exposure", "/findings", "/assets"]
    return {
        "manager": list(everyone),
        "analyst": list(everyone),
        "executive": executive_view,
    }


async def get_access_config(db) -> dict:
    doc = await db.rbac_config.find_one({}, {"_id": 0})
    return (doc or {}).get("access") or _default_access()


async def allowed_modules_for_role(db, role: str) -> list:
    if role == "admin":
        return list(MODULE_KEYS)
    cfg = await get_access_config(db)
    return cfg.get(role, [])


def require_module(module_key: str):
    """FastAPI dependency, same calling convention as auth_utils.require_role -- gates
    one endpoint behind a module key instead of a fixed role list, so the admin-editable
    Role Access mapping is what decides who gets through, not a hardcoded role check."""
    async def checker(user: dict = Depends(get_current_user)):
        if user.get("role") == "admin":
            return user
        from db import db
        allowed = await allowed_modules_for_role(db, user.get("role"))
        if module_key not in allowed:
            raise HTTPException(status_code=403, detail="Your role doesn't have access to this module. Ask an admin to grant it under Reports & Admin -> Role Access.")
        return user
    return checker
