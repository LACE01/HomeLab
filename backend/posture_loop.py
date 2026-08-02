"""Nightly posture snapshot.

Runs early rather than late so the change feed is ready before the working day,
and so "what changed since yesterday" compares two full days rather than a full
day against a partial one.
"""
import asyncio
import logging

logger = logging.getLogger("vulnops.posture")


async def posture_snapshot_loop(db, interval_hours: int = 24):
    from heartbeat import record_heartbeat
    await asyncio.sleep(120)
    while True:
        ok, detail = True, {}
        try:
            import posture_history as ph
            detail = await ph.take_snapshot(db)
            logger.info("Posture snapshot %s: %s open findings",
                         detail["day"], detail["counts"]["open_findings"])
        except Exception as e:
            logger.exception("Posture snapshot failed: %s", e)
            ok, detail = False, {"error": str(e)}
        await record_heartbeat(db, "posture_snapshot_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)
