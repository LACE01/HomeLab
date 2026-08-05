"""Global-events situational-awareness board."""
from fastapi import APIRouter, Depends, Query
from typing import Optional, List

from db import db
from auth_utils import get_current_user
import world_monitor as wm

router = APIRouter()


@router.get("/v1/world-monitor")
async def world_board(
    days: int = Query(7, ge=1, le=90),
    relevance: Optional[str] = Query(None, pattern="^(affects_us|watched|global)$"),
    categories: Optional[List[str]] = Query(None),
    user: dict = Depends(get_current_user),
):
    """Every global security event the platform already collects, each tagged
    with whether it touches your environment. relevance=affects_us collapses it
    to only what needs action."""
    return await wm.board(db, days=days, relevance=relevance, categories=categories)
