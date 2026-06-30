"""VulnOps — Vulnerability Operations Platform backend.

Thin wiring layer:
  - Creates FastAPI app + master /api APIRouter
  - Includes per-domain APIRouter modules from /app/backend/routes/
  - Mounts CORS middleware and startup hook (index creation, seeding, nightly loop)

All business-logic endpoints live under routes/.
"""
import os
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

from fastapi import FastAPI, APIRouter
from starlette.middleware.cors import CORSMiddleware

from db import db
from seed import seed_all

from routes.auth import router as auth_router
from routes.findings import router as findings_router
from routes.inventory import router as inventory_router
from routes.workflows import router as workflows_router
from routes.integrations import router as integrations_router
from routes.dashboards import router as dashboards_router
from routes.reports_routes import router as reports_router
from routes.admin import router as admin_router
from routes.preferences import router as preferences_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnops")


app = FastAPI(title="VulnOps API", version="1.0.0")
api = APIRouter(prefix="/api")


# Register each domain router (order does not matter — APIRouter merges routes safely).
api.include_router(auth_router)
api.include_router(findings_router)
api.include_router(inventory_router)
api.include_router(workflows_router)
api.include_router(integrations_router)
api.include_router(dashboards_router)
api.include_router(reports_router)
api.include_router(admin_router)
api.include_router(preferences_router)


@api.get("/")
async def root():
    return {"name": "VulnOps API", "version": "1.0.0", "status": "ok"}


# Mount the master /api router onto the app.
app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    await db.users.create_index("email", unique=True)
    await db.findings.create_index("canonical_key")
    await db.findings.create_index("asset_id")
    await db.findings.create_index("status")
    await db.findings.create_index("severity")
    await db.observations.create_index("finding_id")
    await db.api_keys.create_index("key", unique=True)
    try:
        await seed_all(db)
        logger.info("Seed completed.")
    except Exception as e:
        logger.exception(f"Seed failed: {e}")
    # Nightly rescore loop (24h)
    import asyncio as _a
    from nightly import nightly_loop
    from qualys_sync import qualys_poll_loop
    _a.create_task(nightly_loop(db, interval_hours=24))
    # Qualys live sync loop (60min) — skips when integration is not configured
    _a.create_task(qualys_poll_loop(db, interval_minutes=60))
