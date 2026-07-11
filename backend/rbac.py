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

Access per (role, module) is one of two levels:
  - "view": can see the module and its data.
  - "edit": can see it AND use its create/update/delete actions.
Not present at all == no access, module is hidden entirely. "edit" implies "view" --
there's no such thing as edit-without-view here.

Enforcement happens in two places:
  - Frontend: Sidebar hides nav items for modules a role can't at least view, every
    Route is wrapped with a guard that shows a plain "access restricted" message for
    direct/typed URLs, and a handful of pages hide their create/edit/delete controls
    behind `canEdit()` (see frontend/src/lib/auth.jsx) -- not yet every page that has
    one, see the coverage note below.
  - Backend: `require_module(key)` (view) and `require_module(key, level="edit")`
    gate real endpoints, so this is actual access control, not just a UI hint --
    calling the API directly with a valid token doesn't bypass it. Coverage note:
    "view" is applied to one representative "main load" endpoint per module; "edit" is
    applied to a representative set of mutating endpoints (the ones already gated by
    require_role("admin", "manager") -- i.e. where a manager's role alone would
    otherwise be sufic to act, so the module-level "edit" grant is the thing that
    still adds a real restriction). Doing this exhaustively across every one of the
    ~150 routes in the app was out of scope for this pass. Treat this as real, but not
    yet total, enforcement.

"admin" always has access to everything, unconditionally, at "edit" level -- this
can't be configured away, specifically so there's no way to lock every admin out of
the one page (Role Access) that could undo a mistake here.
"""
from fastapi import Depends, HTTPException

from auth_utils import get_current_user

# The 4 roles this app shipped with. An admin can add more from Reports & Admin ->
# Role Access ("Manage Roles") -- those are stored in db.roles and layered on top of
# this fixed base list. Kept as BUILTIN_ROLES (rather than folding everything into
# the DB) so the starter defaults below, and every `require_role("admin", ...)` call
# scattered through the route files, keep meaning exactly what they always have --
# adding a custom role never silently changes what those specific hardcoded checks
# grant; a custom role only gets in through the module-level Role Access grid.
BUILTIN_ROLES = ["admin", "manager", "analyst", "executive"]
LEVELS = ["view", "edit"]


async def custom_roles(db) -> list:
    """Admin-created roles beyond the 4 built-in ones, alphabetically."""
    docs = await db.roles.find({}, {"_id": 0, "name": 1}).to_list(None)
    return sorted({d["name"] for d in docs if d.get("name") and d["name"] not in BUILTIN_ROLES})


async def all_roles(db) -> list:
    """Every role that exists, builtins first (in their fixed order) then custom
    roles alphabetically -- the full universe a user's `role` field can be set to."""
    return list(BUILTIN_ROLES) + await custom_roles(db)


async def configurable_roles(db) -> list:
    """Every role Role Access can grant module access to -- everything except
    admin, which always has unconditional edit access (see module docstring)."""
    return [r for r in await all_roles(db) if r != "admin"]

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
    {"key": "/admin/scan-schedule", "label": "Scan Schedule", "group": "Integrations"},
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
    # --- Incident Response ---
    {"key": "/ir/wizard", "label": "Triage Wizard", "group": "Incident Response"},
    {"key": "/ir/cases", "label": "IR Cases", "group": "Incident Response"},
    {"key": "/ir/case-approval", "label": "IR Case Approval", "group": "Incident Response"},
    {"key": "/admin/ir-setup", "label": "IR Setup", "group": "Incident Response"},
]
MODULE_KEYS = [m["key"] for m in MODULE_REGISTRY]

# Modules that default to admin-only until an admin opts other roles in -- mostly the
# sensitive/config-heavy corners of Reports & Admin. Everything else defaults to
# "edit" for manager/analyst so turning this feature on doesn't immediately downgrade
# anyone's current day-to-day capability; "executive" defaults to a small, view-only
# set since that's the role most orgs actually want restricted out of the box.
_ADMIN_ONLY_BY_DEFAULT = {
    "/admin/users", "/admin/notifications", "/admin/chatops", "/admin/health",
    "/admin/backups", "/admin/audit-log", "/admin/assignment-rules", "/admin/sla-policies",
    "/admin/approval-routing", "/admin/rbac", "/admin/ir-setup",
    # IR case closure approval is deliberately admin-only by default -- the org's
    # designated security admins, not every manager, sign off that a case is truly
    # closed. An admin can still opt specific managers into this from Role Access.
    "/ir/case-approval",
}


def _default_access() -> dict:
    everyone_edit = {m["key"]: "edit" for m in MODULE_REGISTRY if m["key"] not in _ADMIN_ONLY_BY_DEFAULT}
    executive_view = {k: "view" for k in ["/", "/operational", "/reports", "/compliance", "/exposure", "/findings", "/assets", "/ir/cases"]}
    return {
        "manager": dict(everyone_edit),
        "analyst": dict(everyone_edit),
        "executive": executive_view,
    }


def _normalize_access(cfg: dict) -> dict:
    """Upgrades the pre-view/edit config shape (role -> [module_key, ...], meaning
    plain "has access") to the current shape (role -> {module_key: level}) -- treating
    every legacy entry as "edit" so migrating to this feature never silently downgrades
    someone's existing capability without an admin deciding to."""
    out = {}
    for role, val in (cfg or {}).items():
        if isinstance(val, list):
            out[role] = {k: "edit" for k in val}
        elif isinstance(val, dict):
            out[role] = {k: (lvl if lvl in LEVELS else "view") for k, lvl in val.items()}
        else:
            out[role] = {}
    return out


async def get_access_config(db) -> dict:
    doc = await db.rbac_config.find_one({}, {"_id": 0})
    raw = (doc or {}).get("access")
    if not raw:
        return _default_access()
    return _normalize_access(raw)


async def allowed_modules_for_role(db, role: str) -> list:
    """Back-compat helper: flat list of module keys this role can at least view."""
    if role == "admin":
        return list(MODULE_KEYS)
    cfg = await get_access_config(db)
    return list(cfg.get(role, {}).keys())


async def access_map_for_role(db, role: str) -> dict:
    """{module_key: "view"|"edit"} for this role -- what the frontend needs to also
    know edit permission, not just visibility."""
    if role == "admin":
        return {k: "edit" for k in MODULE_KEYS}
    cfg = await get_access_config(db)
    return cfg.get(role, {})


def _meets(level_required: str, level_granted: str) -> bool:
    if level_granted == "edit":
        return True  # edit satisfies both "view" and "edit" requirements
    return level_required == "view" and level_granted == "view"


def require_module(module_key: str, level: str = "view"):
    """FastAPI dependency, same calling convention as auth_utils.require_role -- gates
    one endpoint behind a module key (+ required level) instead of a fixed role list,
    so the admin-editable Role Access mapping is what decides who gets through."""
    async def checker(user: dict = Depends(get_current_user)):
        if user.get("role") == "admin":
            return user
        from db import db
        granted = (await access_map_for_role(db, user.get("role"))).get(module_key)
        if not granted or not _meets(level, granted):
            verb = "edit" if level == "edit" else "access"
            raise HTTPException(status_code=403, detail=f"Your role doesn't have {verb} permission on this module. Ask an admin under Reports & Admin -> Role Access.")
        return user
    return checker
