"""System health -- background loop status + basic DB connectivity check."""
from fastapi import APIRouter, Depends

from db import db
from rbac import require_module
from auth_utils import get_current_user

router = APIRouter()


@router.get("/v1/admin/health")
async def health_summary(user: dict = Depends(get_current_user), _rbac: dict = Depends(require_module("/admin/health"))):
    from heartbeat import get_health_summary
    summary = await get_health_summary(db)
    try:
        await db.command("ping")
        summary["database"] = {"status": "ok"}
    except Exception as e:
        summary["database"] = {"status": "error", "error": str(e)}
    return summary


# Unauthenticated liveness probe for docker-compose healthcheck / external monitoring --
# intentionally minimal (no loop detail, no auth) since it just needs to answer
# "is the API process up and can it reach Mongo". Lives under /v1 (so the full path
# is /api/v1/healthz) rather than a bare /healthz, since this router is mounted on
# the same /api-prefixed parent as everything else in the app.
@router.get("/v1/healthz")
async def healthz():
    try:
        await db.command("ping")
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
