"""Hourly self-check.

Hourly rather than daily because the things it catches -- a dead feed, a blocked
loop, a queue with no worker -- are conditions you want to hear about while
they're happening, not the next morning. It is cheap: five aggregate queries.
"""
import asyncio
import logging

logger = logging.getLogger("vulnops.selfcheck")


async def self_check_loop(db, interval_hours: int = 1):
    from heartbeat import record_heartbeat
    await asyncio.sleep(180)   # let the other loops record at least one pass first
    while True:
        ok, detail = True, {}
        try:
            import platform_health as ph
            detail = await ph.run_self_check(db)
            if detail["status"] != "ok":
                logger.warning("Self-check: %s (%d finding(s) raised)",
                                detail["status"], detail["findings_created"])
        except Exception as e:
            logger.exception("Self-check failed: %s", e)
            ok, detail = False, {"error": str(e)}
        await record_heartbeat(db, "self_check_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)
