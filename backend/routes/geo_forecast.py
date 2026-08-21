"""Item 51 (PYTHIA forecasting half) — a SEPARATE, experimental surface.

Kept apart from /v1/world-monitor on purpose: forecasts must never be served in
the same payload as observed KEV/findings/world-monitor data. The status endpoint
is always reachable (so the UI can explain what this is and that it's off); the
forecast endpoint fails closed unless the feature flag is explicitly enabled.
"""
from fastapi import APIRouter, Depends, HTTPException

from db import db
from auth_utils import get_current_user
import geo_forecast as gf

router = APIRouter()


@router.get("/v1/geo-forecast/status")
async def geo_forecast_status(user: dict = Depends(get_current_user)):
    """Always safe to call: says what this is, that it's experimental and off by
    default, and whether a vetted source has been registered. Never a forecast."""
    return await gf.status(db)


@router.get("/v1/geo-forecast")
async def geo_forecast(user: dict = Depends(get_current_user)):
    """Experimental forecasts. Fails CLOSED: 404 unless the feature is explicitly
    enabled. Even when enabled, returns nothing unless a vetted source has been
    registered -- the shipped state -- and everything is stamped experimental and
    non-decision-bearing with a disclaimer."""
    if not await gf.feature_enabled(db):
        raise HTTPException(404, "The experimental geopolitical forecast feature is disabled.")
    return await gf.forecasts(db)
