"""Background evaluation of the correlation rules.

Every 6 hours rather than nightly: the rules that matter most key off IDS
activity inside a 7-day window, and a once-a-day cadence would routinely mean
finding out about active scanning against a known-exploited, internet-facing host
some 20 hours after the sensor saw it.
"""
import asyncio
import logging

logger = logging.getLogger("vulnops.correlation")


async def correlation_loop(db, interval_hours: int = 6):
    from heartbeat import record_heartbeat
    await asyncio.sleep(90)  # let the ingest loops populate first
    while True:
        ok, detail = True, {}
        try:
            import correlation as cx
            detail = await cx.run(db)
            logger.info("Correlation: %s new, %s refreshed, %s resolved, %s rules not evaluated",
                         detail["new_hits"], detail["refreshed_hits"],
                         detail["auto_resolved"], len(detail["not_evaluated"]))
        except Exception as e:
            logger.exception("Correlation run failed: %s", e)
            ok, detail = False, {"error": str(e)}
        await record_heartbeat(db, "correlation_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)
