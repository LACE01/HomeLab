"""Job handlers: the scans that used to run inside the API process.

Each wraps an EXISTING scan function unchanged. The scanning logic was never the
problem -- where it ran was. `routes/nmap.py` and `routes/nikto.py` already had
`_execute_scan(config_id)` helpers that were handed to `asyncio.create_task`
directly from a request handler; those same helpers are now invoked by a worker
in a separate process, so a wedged nmap run can no longer take the login page
down with it.

Imported by both the API (so `enqueue` can reject an unknown kind at request
time rather than at execution time) and the worker (which runs them).
"""
import logging

from jobqueue import handler

logger = logging.getLogger("vulnops.jobs")


@handler("nmap_scan")
async def _nmap(db, payload, heartbeat):
    from routes.nmap import _execute_scan
    await heartbeat({"stage": "scanning", "config_id": payload.get("config_id")})
    await _execute_scan(payload["config_id"])
    return {"ok": True, "config_id": payload.get("config_id")}


@handler("nikto_scan")
async def _nikto(db, payload, heartbeat):
    from routes.nikto import _execute_scan
    await heartbeat({"stage": "scanning", "config_id": payload.get("config_id")})
    await _execute_scan(payload["config_id"])
    return {"ok": True, "config_id": payload.get("config_id")}


@handler("container_scan")
async def _container(db, payload, heartbeat):
    from container_scan import scan_container_image
    await heartbeat({"stage": "pulling", "image": payload.get("image_ref")})
    return await scan_container_image(db, payload["image_ref"],
                                       asset_id=payload.get("asset_id"),
                                       label=payload.get("label"))


@handler("secrets_scan")
async def _secrets(db, payload, heartbeat):
    from secrets_scan import run_repo_scan
    await heartbeat({"stage": "cloning", "repo": payload.get("repo_url")})
    return await run_repo_scan(db, payload["repo_url"],
                                branch=payload.get("branch"),
                                token=payload.get("token"))


@handler("easm_scan")
async def _easm(db, payload, heartbeat):
    from easm import run_easm_scan
    await heartbeat({"stage": "enumerating", "domain": payload.get("domain")})
    return await run_easm_scan(db, payload["domain"])


@handler("correlation_run")
async def _correlation(db, payload, heartbeat):
    """CPU-bound over the whole asset table -- exactly the kind of work that
    should not share an event loop with request handling."""
    import correlation as cx
    await heartbeat({"stage": "evaluating"})
    return await cx.run(db)


@handler("posture_snapshot")
async def _posture(db, payload, heartbeat):
    import posture_history as ph
    return await ph.take_snapshot(db)
