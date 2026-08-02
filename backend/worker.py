"""Worker entrypoint. Runs in its OWN container.

    python worker.py

The whole point is the process boundary. Everything here could technically run
inside the API process -- it did, until an nmap sweep and a WHOIS lookup between
them made the login page stop answering. A separate process means a scan that
wedges, leaks memory, or gets OOM-killed takes down scanning and nothing else,
and the queue simply requeues its job when the lease expires.
"""
import asyncio
import logging
import os
import sys

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("vulnops.worker")


async def main():
    from db import db
    import job_handlers  # noqa: F401  -- registers the handlers
    import jobqueue

    kinds = [k.strip() for k in (os.environ.get("WORKER_KINDS") or "").split(",") if k.strip()]
    concurrency = int(os.environ.get("WORKER_CONCURRENCY", "2"))
    logger.info("Starting worker: kinds=%s concurrency=%d registered=%s",
                 kinds or "all", concurrency, jobqueue.registered_kinds())
    await jobqueue.worker(db, kinds=kinds or None, concurrency=concurrency)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
