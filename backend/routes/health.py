"""System health -- background loop status + basic DB connectivity check."""
import os
from fastapi import APIRouter, Depends, Response, Request, HTTPException

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
async def healthz(response: Response):
    try:
        await db.command("ping")
        return {"status": "ok"}
    except Exception as e:
        # 503 so external monitors / load balancers that key on the HTTP status
        # (not the body) also see the outage. The docker-compose healthcheck reads
        # the body and stays correct either way.
        response.status_code = 503
        return {"status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# Prometheus metrics. Unauthenticated by default (standard for a scrape target on
# an internal network); set METRICS_TOKEN to require Authorization: Bearer <token>.
# Exposes operational gauges only -- process up, Mongo reachability, active driver,
# and a few coarse aggregate counts -- nothing per-finding or sensitive.
@router.get("/v1/metrics")
async def metrics(request: Request):
    token = os.environ.get("METRICS_TOKEN")
    if token:
        auth = request.headers.get("authorization", "")
        if auth != f"Bearer {token}":
            raise HTTPException(401, "metrics token required")
    try:
        from db import DRIVER
    except Exception:
        DRIVER = "unknown"
    mongo_up = 1
    open_findings = active_campaigns = open_events = -1
    try:
        await db.command("ping")
    except Exception:
        mongo_up = 0
    if mongo_up:
        open_states = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
        try:
            open_findings = await db.findings.count_documents({"status": {"$in": open_states}})
        except Exception:
            pass
        try:
            active_campaigns = await db.remediation_campaigns.count_documents({"status": {"$ne": "closed"}})
        except Exception:
            pass
        try:
            open_events = await db.security_events.count_documents({"status": {"$nin": ["closed", "resolved"]}})
        except Exception:
            pass
    lines = [
        "# HELP nightwatch_up 1 if the API process is serving.",
        "# TYPE nightwatch_up gauge",
        "nightwatch_up 1",
        "# HELP nightwatch_mongo_up 1 if MongoDB responded to ping.",
        "# TYPE nightwatch_mongo_up gauge",
        f"nightwatch_mongo_up {mongo_up}",
        "# HELP nightwatch_driver_info Active MongoDB driver (label only).",
        "# TYPE nightwatch_driver_info gauge",
        f'nightwatch_driver_info{{driver="{DRIVER}"}} 1',
        "# HELP nightwatch_open_findings Open findings.",
        "# TYPE nightwatch_open_findings gauge",
        f"nightwatch_open_findings {open_findings}",
        "# HELP nightwatch_active_campaigns Non-closed remediation campaigns.",
        "# TYPE nightwatch_active_campaigns gauge",
        f"nightwatch_active_campaigns {active_campaigns}",
        "# HELP nightwatch_open_security_events Open security events.",
        "# TYPE nightwatch_open_security_events gauge",
        f"nightwatch_open_security_events {open_events}",
    ]
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
