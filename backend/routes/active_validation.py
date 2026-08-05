"""Routes for the active single-finding validation workflow.

Thin HTTP layer over exploit_authorization. The safety lives in that module and
is re-checked there; these endpoints add the role gates and pass the acting
human's identity through so dual control and audit are real.

Deliberately minimal, and deliberately without any 'run against all findings' or
'auto-validate' surface -- there is one authorization, for one finding, requested
and approved by two different people, run once.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
import exploit_authorization as ea

router = APIRouter()


def _actor(user: dict) -> str:
    return user.get("email") or user.get("id")


@router.get("/v1/active-validation/status")
async def status(user: dict = Depends(get_current_user)):
    """Whether the capability is enabled, and whether an executor is wired.
    Both are usually 'no', and that is the safe, expected state."""
    return {
        "feature_enabled": await ea.feature_enabled(db),
        "executor_registered": ea.has_executor(),
        "note": ("Active validation is a manual, dual-control, allowlist-gated workflow for "
                  "validating one finding at a time. The platform ships with the capability "
                  "DISABLED and no executor; enabling it and wiring an executor are deliberate "
                  "decisions that require the organization's authorization."),
    }


# ---- allowlist (admin only) ----
class AllowlistBody(BaseModel):
    value: str
    reason: str


@router.get("/v1/active-validation/allowlist")
async def get_allowlist(user: dict = Depends(require_role("admin"))):
    rows = await db.validation_allowlist.find({"active": {"$ne": False}}, {"_id": 0}).to_list(500)
    return {"items": rows}


@router.post("/v1/active-validation/allowlist")
async def add_allow(body: AllowlistBody, user: dict = Depends(require_role("admin"))):
    try:
        return await ea.add_allowlist(db, value=body.value, reason=body.reason, actor=_actor(user))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/v1/active-validation/allowlist/{entry_id}")
async def remove_allow(entry_id: str, user: dict = Depends(require_role("admin"))):
    ok = await ea.remove_allowlist(db, entry_id=entry_id, actor=_actor(user))
    if not ok:
        raise HTTPException(404, "No such allowlist entry")
    return {"removed": True}


# ---- authorizations ----
class RequestBody(BaseModel):
    finding_id: str
    target: str
    justification: str


@router.get("/v1/active-validation/authorizations")
async def list_auths(status: str = None, user: dict = Depends(require_role("admin", "manager"))):
    return {"items": await ea.list_authorizations(db, status=status)}


@router.post("/v1/active-validation/authorizations")
async def request_auth(body: RequestBody, user: dict = Depends(require_role("admin", "manager"))):
    try:
        return await ea.request_authorization(
            db, finding_id=body.finding_id, target=body.target,
            requested_by=_actor(user), justification=body.justification)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/v1/active-validation/authorizations/{auth_id}/approve")
async def approve_auth(auth_id: str, user: dict = Depends(require_role("admin", "manager"))):
    try:
        return await ea.approve(db, auth_id=auth_id, approver=_actor(user))
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


class DenyBody(BaseModel):
    reason: str = ""


@router.post("/v1/active-validation/authorizations/{auth_id}/deny")
async def deny_auth(auth_id: str, body: DenyBody, user: dict = Depends(require_role("admin", "manager"))):
    try:
        return await ea.deny(db, auth_id=auth_id, approver=_actor(user), reason=body.reason)
    except (PermissionError, ValueError) as e:
        raise HTTPException(400, str(e))


@router.post("/v1/active-validation/authorizations/{auth_id}/revoke")
async def revoke_auth(auth_id: str, body: DenyBody, user: dict = Depends(require_role("admin", "manager"))):
    try:
        return await ea.revoke(db, auth_id=auth_id, actor=_actor(user), reason=body.reason)
    except (PermissionError, ValueError) as e:
        raise HTTPException(400, str(e))


@router.post("/v1/active-validation/authorizations/{auth_id}/run")
async def run_auth(auth_id: str, user: dict = Depends(require_role("admin"))):
    """Attempt validation. Requires admin AND passes through every guard in
    exploit_authorization.run_validation. Returns 'no_executor' on a stock
    deployment, having done nothing."""
    try:
        return await ea.run_validation(db, auth_id=auth_id, actor=_actor(user))
    except PermissionError as e:
        raise HTTPException(403, str(e))


@router.get("/v1/active-validation/audit")
async def audit(authorization_id: str = None, user: dict = Depends(require_role("admin", "manager"))):
    return {"items": await ea.audit_trail(db, authorization_id)}
