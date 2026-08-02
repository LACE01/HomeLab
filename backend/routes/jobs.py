"""The job queue, made visible.

Work that runs invisibly is work nobody can tell has stopped. Before this, a scan
was an anonymous asyncio task: you could not see it running, could not tell a slow
one from a dead one, and a deploy silently discarded it. These endpoints exist so
"is anything actually happening?" has an answer.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from db import db
from auth_utils import get_current_user, require_role
import jobqueue
import job_handlers  # noqa: F401 -- registers handlers so kinds validate here too

router = APIRouter()


@router.get("/v1/jobs/stats")
async def job_stats(user: dict = Depends(get_current_user)):
    """Queue health. A growing queued count with nothing running is the signal
    that no worker is connected -- the failure that is otherwise invisible."""
    return await jobqueue.stats(db)


@router.get("/v1/jobs")
async def list_jobs(status: str = None, kind: str = None, limit: int = 50,
                     user: dict = Depends(get_current_user)):
    q = {}
    if status:
        q["status"] = status
    if kind:
        q["kind"] = kind
    rows = await db.jobs.find(q, {"_id": 0}).sort("enqueued_at", -1).to_list(limit)
    return {"items": rows}


@router.get("/v1/jobs/{job_id}")
async def get_job(job_id: str, user: dict = Depends(get_current_user)):
    job = await db.jobs.find_one({"id": job_id}, {"_id": 0})
    if not job:
        raise HTTPException(404, "No such job")
    return job


class EnqueueBody(BaseModel):
    kind: str
    payload: dict = {}
    priority: int = 0


@router.post("/v1/jobs")
async def create_job(body: EnqueueBody, user: dict = Depends(require_role("admin"))):
    try:
        return await jobqueue.enqueue(db, body.kind, body.payload, priority=body.priority,
                                       requested_by=user.get("email") or user.get("id"))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/v1/jobs/{job_id}/cancel")
async def cancel_job(job_id: str, user: dict = Depends(require_role("admin"))):
    """Cancels a QUEUED job. A running one cannot be interrupted from here --
    saying so is better than pretending, which would leave the operator believing
    a scan had stopped when it had not."""
    job = await db.jobs.find_one({"id": job_id}, {"_id": 0})
    if not job:
        raise HTTPException(404, "No such job")
    if job["status"] != jobqueue.QUEUED:
        raise HTTPException(400, f"Only queued jobs can be cancelled; this one is {job['status']}. "
                                  "A running job will stop at its next lease expiry if its worker "
                                  "has died.")
    await db.jobs.update_one({"id": job_id}, {"$set": {
        "status": jobqueue.CANCELLED, "finished_at": jobqueue._now_iso(),
        "cancelled_by": user.get("email") or user.get("id")}})
    return {"cancelled": True}


@router.post("/v1/jobs/reap")
async def reap(user: dict = Depends(require_role("admin"))):
    """Requeue jobs whose worker stopped reporting."""
    return {"requeued": await jobqueue.reap_expired(db)}
