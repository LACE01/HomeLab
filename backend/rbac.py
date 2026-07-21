"""Role-based module access control -- lets an admin decide which modules/pages each
role can see and use, instead of the admin/manager/analyst/executive role split having
one fixed, hardcoded set of capabilities. Every org draws these lines differently (who
counts as a "manager" and what they should see varies a lot) -- same philosophy as
criticality.py's scoring rules: the mapping below is a sensible starting point that's
fully editable from Administration -> Role Access, not a fixed policy.

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

# The 4 roles this app shipped with. An admin can add more from Administration ->
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
    # --- Overview (landing dashboards) ---
    {"key": "/", "label": "Dashboard", "group": "Overview"},
    {"key": "/soc", "label": "SOC Overview", "group": "Overview"},
    {"key": "/operational", "label": "Team Dashboards", "group": "Overview"},
    # --- Vulnerability Management ---
    {"key": "/findings", "label": "Findings", "group": "Vulnerability Management"},
    {"key": "/attack-paths", "label": "Attack Paths", "group": "Vulnerability Management"},
    {"key": "/exposure", "label": "Exposure", "group": "Vulnerability Management"},
    {"key": "/admin/tls-certs", "label": "TLS Certificates", "group": "Vulnerability Management"},
    {"key": "/admin/email-auth", "label": "Email Authentication (SPF/DKIM/DMARC)", "group": "Vulnerability Management"},
    {"key": "/admin/eol-tracking", "label": "End-of-Life Software", "group": "Vulnerability Management"},
    {"key": "/admin/container-scan", "label": "Container Image Scanning", "group": "Vulnerability Management"},
    {"key": "/easm", "label": "Attack Surface", "group": "Vulnerability Management"},
    {"key": "/tickets", "label": "Tickets", "group": "Vulnerability Management"},
    {"key": "/exceptions", "label": "Exceptions", "group": "Vulnerability Management"},
    {"key": "/admin/playbooks", "label": "Playbooks", "group": "Vulnerability Management"},
    {"key": "/automation", "label": "Automation", "group": "Vulnerability Management"},
    # --- Detection & Response (merges the former "Detection & Alerts" and
    # "Incident Response" groups -- alerting and incident handling are the same
    # workflow, splitting them into two nav groups never made sense) ---
    {"key": "/alerts", "label": "Security Alerts", "group": "Detection & Response"},
    {"key": "/admin/threat-intel", "label": "Threat Intel Watchlist", "group": "Detection & Response"},
    {"key": "/admin/albert", "label": "Albert Network Monitoring", "group": "Detection & Response"},
    {"key": "/ir/wizard", "label": "Triage Wizard", "group": "Detection & Response"},
    {"key": "/ir/cases", "label": "IR Cases", "group": "Detection & Response"},
    {"key": "/ir/case-approval", "label": "IR Case Approval", "group": "Detection & Response"},
    {"key": "/admin/ir-setup", "label": "IR Setup", "group": "Detection & Response"},
    # --- Asset Inventory ---
    {"key": "/assets", "label": "Assets", "group": "Asset Inventory"},
    {"key": "/products", "label": "Products", "group": "Asset Inventory"},
    {"key": "/engagements", "label": "Engagements", "group": "Asset Inventory"},
    {"key": "/directory", "label": "Directory (Users & Groups)", "group": "Asset Inventory"},
    # --- Scanning & Integrations ---
    {"key": "/integrations", "label": "Connectors", "group": "Scanning & Integrations"},
    {"key": "/imports", "label": "Import Jobs", "group": "Scanning & Integrations"},
    {"key": "/admin/web-scans", "label": "Web Scan Uploads", "group": "Scanning & Integrations"},
    {"key": "/admin/nmap-scans", "label": "Nmap Scan Uploads", "group": "Scanning & Integrations"},
    {"key": "/admin/nikto-scans", "label": "Web App Scans (Nikto)", "group": "Scanning & Integrations"},
    {"key": "/admin/recon-osint", "label": "Recon & OSINT", "group": "Scanning & Integrations"},
    {"key": "/admin/criticality-scoring", "label": "Criticality Scoring", "group": "Scanning & Integrations"},
    {"key": "/admin/sbom", "label": "SBOM / Dependencies", "group": "Scanning & Integrations"},
    {"key": "/admin/yara", "label": "YARA Scanning", "group": "Scanning & Integrations"},
    {"key": "/admin/scan-schedule", "label": "Scan Schedule", "group": "Scanning & Integrations"},
    {"key": "/admin/splunk", "label": "Splunk", "group": "Scanning & Integrations"},
    {"key": "/admin/wazuh", "label": "Wazuh", "group": "Scanning & Integrations"},
    {"key": "/admin/ticketing", "label": "Ticketing / SOAR", "group": "Scanning & Integrations"},
    # --- Reports & Compliance ---
    {"key": "/reports", "label": "Reports", "group": "Reports & Compliance"},
    {"key": "/compliance", "label": "Compliance", "group": "Reports & Compliance"},
    {"key": "/risk-register", "label": "Risk Register", "group": "Reports & Compliance"},
    {"key": "/vendors", "label": "Vendor & Third-Party Risk", "group": "Reports & Compliance"},
    # --- Administration ---
    {"key": "/admin", "label": "Admin", "group": "Administration"},
    {"key": "/admin/users", "label": "Users", "group": "Administration"},
    {"key": "/admin/teams", "label": "Teams", "group": "Administration"},
    {"key": "/admin/notifications", "label": "Notifications", "group": "Administration"},
    {"key": "/admin/chatops", "label": "ChatOps", "group": "Administration"},
    {"key": "/admin/health", "label": "System Health", "group": "Administration"},
    {"key": "/admin/backups", "label": "Backups", "group": "Administration"},
    {"key": "/admin/retention", "label": "Data Retention", "group": "Administration"},
    {"key": "/admin/audit-log", "label": "Audit Log", "group": "Administration"},
    {"key": "/admin/assignment-rules", "label": "Assignment Rules", "group": "Administration"},
    {"key": "/admin/ownership", "label": "Ownership Map", "group": "Administration"},
    {"key": "/admin/sla-policies", "label": "SLA Policies", "group": "Administration"},
    {"key": "/admin/approval-routing", "label": "Approval Routing", "group": "Administration"},
    {"key": "/admin/rbac", "label": "Role Access", "group": "Administration"},
]
MODULE_KEYS = [m["key"] for m in MODULE_REGISTRY]

# Modules that default to admin-only until an admin opts other roles in -- mostly the
# sensitive/config-heavy corners of Administration. Everything else defaults to
# "edit" for manager/analyst so turning this feature on doesn't immediately downgrade
# anyone's current day-to-day capability; "executive" defaults to a small, view-only
# set since that's the role most orgs actually want restricted out of the box.
_ADMIN_ONLY_BY_DEFAULT = {
    "/admin/users", "/admin/notifications", "/admin/chatops", "/admin/health",
    "/admin/backups", "/admin/retention", "/admin/audit-log", "/admin/assignment-rules", "/admin/sla-policies",
    "/admin/approval-routing", "/admin/rbac", "/admin/ir-setup",
    # IR case closure approval is deliberately admin-only by default -- the org's
    # designated security admins, not every manager, sign off that a case is truly
    # closed. An admin can still opt specific managers into this from Role Access.
    "/ir/case-approval",
}


def _default_access() -> dict:
    everyone_edit = {m["key"]: "edit" for m in MODULE_REGISTRY if m["key"] not in _ADMIN_ONLY_BY_DEFAULT}
    executive_view = {k: "view" for k in ["/", "/operational", "/reports", "/compliance", "/exposure", "/findings", "/assets", "/ir/cases", "/alerts", "/admin/threat-intel", "/soc"]}
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
            raise HTTPException(status_code=403, detail=f"Your role doesn't have {verb} permission on this module. Ask an admin under Administration -> Role Access.")
        return user
    return checker
