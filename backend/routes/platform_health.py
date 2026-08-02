"""Platform health, one screen.

All of this existed in pieces before. None of it was anywhere a person would look
during an incident, which is why an outage took four rounds of debugging to
locate.
"""
from fastapi import APIRouter, Depends, HTTPException

from db import db
from auth_utils import get_current_user, require_role
import platform_health as ph

router = APIRouter()


@router.get("/v1/health/platform")
async def platform_status(user: dict = Depends(get_current_user)):
    """Database, loops, connectors, queue and data freshness in one answer."""
    return await ph.snapshot(db)


@router.get("/v1/health/connectors")
async def connector_states(user: dict = Depends(get_current_user)):
    """Per-connector state including the ACTUAL last error.

    'It failed' sends you to the logs. 'It failed 47 times with DNS resolution
    failure' is the answer.
    """
    rows = await db.connector_state.find({}, {"_id": 0}).to_list(200)
    rows.sort(key=lambda r: (r.get("state") != "degraded", r.get("integration") or ""))
    return {"items": rows, "breaker_threshold": ph.BREAKER_THRESHOLD}


@router.post("/v1/health/connectors/{integration}/reset")
async def reset_connector(integration: str, user: dict = Depends(require_role("admin"))):
    """Close a tripped circuit breaker.

    Deliberately manual. Auto-closing would let a permanently broken integration
    cycle between degraded and retrying forever, looking busy while never
    working.
    """
    return await ph.reset_breaker(db, integration)


@router.post("/v1/health/self-check")
async def self_check(user: dict = Depends(require_role("admin"))):
    """Run the platform's checks on itself and raise its failures as findings."""
    return await ph.run_self_check(db)
