"""Job handlers: the scans that must NOT run inside the API process.

Every scanner here is memory- or CPU-heavy -- recon-ng clones module data,
trivy pulls whole container images, EASM enumerates certificate transparency,
detect-secrets clones repos. Running any of them inside the container that
serves requests risks an OOM kill of the WHOLE API, which is exactly the crash
that took the platform down: a manual "scan now" spiked memory in the backend and
the process was killed.

So each handler is fully self-contained -- it fetches its own target, runs the
scan, and records the engagement -- and runs in the separate `worker` container.
If a scan OOMs now, the worker dies and its job is requeued; the API keeps
serving. The routes that used to `await` these just enqueue a job id.
"""
import logging

from jobqueue import handler

logger = logging.getLogger("vulnops.jobs")


def _now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


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
    from routes.common import record_engagement
    t = await db.container_image_watch_targets.find_one({"id": payload["target_id"]}, {"_id": 0})
    if not t:
        return {"ok": False, "error": "target not found"}
    started = _now_iso()
    await heartbeat({"stage": "pulling image", "image": t.get("image_ref")})
    try:
        result = await scan_container_image(db, t["image_ref"], t.get("asset_id"), t.get("label"))
    except Exception as e:
        await record_engagement(db, name=t.get("label") or t["image_ref"],
                                 scanner="Container Image Scan", scan_type="manual",
                                 scan_method="trivy_sbom", status="failed",
                                 started_at=started, error=str(e))
        raise
    await record_engagement(
        db, name=t.get("label") or t["image_ref"], scanner="Container Image Scan",
        scan_type="manual", scan_method="trivy_sbom", status="completed",
        assets_scanned=result.get("components_parsed", 0),
        findings_created=result.get("findings_created", 0),
        findings_updated=result.get("findings_updated", 0), started_at=started)
    return result


@handler("secrets_scan")
async def _secrets(db, payload, heartbeat):
    from secrets_scan import run_repo_scan
    from routes.common import record_engagement
    t = await db.secrets_scan_targets.find_one({"id": payload["target_id"]}, {"_id": 0})
    if not t:
        return {"ok": False, "error": "target not found"}
    started = _now_iso()
    await heartbeat({"stage": "cloning", "repo": t.get("repo_url")})
    try:
        result = await run_repo_scan(db, t["repo_url"], t.get("branch"), t.get("token"),
                                      t.get("asset_id"), t.get("label"))
    except Exception as e:
        await record_engagement(db, name=t.get("label") or t["repo_url"],
                                 scanner="Secrets Scan (detect-secrets)", scan_type="manual",
                                 scan_method="git_clone", status="failed",
                                 started_at=started, error=str(e))
        raise
    await record_engagement(
        db, name=t.get("label") or t["repo_url"], scanner="Secrets Scan (detect-secrets)",
        scan_type="manual", scan_method="git_clone", status="completed",
        findings_created=result.get("findings_created", 0),
        findings_updated=result.get("findings_updated", 0), started_at=started)
    return result


@handler("easm_scan")
async def _easm(db, payload, heartbeat):
    from easm import run_easm_scan
    from routes.common import record_engagement
    d = await db.easm_domains.find_one({"id": payload["domain_id"]}, {"_id": 0})
    if not d:
        return {"ok": False, "error": "domain not found"}
    started = _now_iso()
    await heartbeat({"stage": "enumerating", "domain": d.get("domain")})
    try:
        result = await run_easm_scan(db, d["domain"])
    except Exception as e:
        await record_engagement(db, name=f"EASM sweep — {d['domain']}", scanner="EASM (crt.sh)",
                                 scan_type="on_demand", scan_method="passive_discovery",
                                 status="failed", started_at=started, error=str(e))
        raise
    await record_engagement(
        db, name=f"EASM sweep — {d['domain']}", scanner="EASM (crt.sh)", scan_type="on_demand",
        scan_method="passive_discovery", status="completed",
        assets_scanned=result.get("hostnames_found", 0), findings_created=0,
        findings_updated=result.get("new_candidates", 0), started_at=started)
    return result


@handler("recon_run")
async def _recon(db, payload, heartbeat):
    from routes.reconng import _execute_run
    await heartbeat({"stage": "running modules", "run_id": payload.get("run_id")})
    await _execute_run(payload["run_id"])
    return {"ok": True, "run_id": payload.get("run_id")}


@handler("backup_create")
async def _backup(db, payload, heartbeat):
    """Create a database backup in the worker, off the request path.

    Inline backups 500'd/520'd on a large database: dumping every collection took
    longer than Cloudflare's ~100s proxy timeout. This runs it in the worker and
    the API polls the job.

    The passphrase for an encrypted backup is moved into the read-once vault and
    stripped from the returned result -- the result is persisted on the job row,
    and the passphrase must never be.
    """
    from backup import create_backup, stash_passphrase, memory_snapshot
    await heartbeat({"stage": "starting", "memory": memory_snapshot()})
    rec = await create_backup(db, label=payload.get("label"),
                              encrypt=bool(payload.get("encrypt")))
    passphrase = rec.pop("passphrase", None)
    rec.pop("passphrase_notice", None)
    if passphrase:
        await stash_passphrase(db, rec["id"], passphrase)
        rec["passphrase_available"] = True   # a flag, never the value
    rec["memory"] = memory_snapshot()
    return rec


@handler("backup_restore")
async def _restore(db, payload, heartbeat):
    """Restore a database backup in the worker, off the request path.

    Inline restore had the same failure as inline backup: on a large database it
    exceeded Cloudflare's ~100s proxy timeout (520) and could OOM the 1g API. The
    API stashes the uploaded file on the shared backups volume and enqueues this;
    the worker restores it and the API polls the job.

    The restore passphrase (for an encrypted backup) is user-supplied and must not
    be persisted on the job row, so it rides the same read-once vault the create
    path uses, keyed by restore_id. A user-caused failure (wrong passphrase, bad
    file) is returned as a terminal {ok: False, error} result rather than raised,
    so the queue doesn't pointlessly retry an unrecoverable input.
    """
    import os
    from backup import restore_from_path, claim_passphrase, memory_snapshot
    restore_file = payload.get("restore_file")
    restore_id = payload.get("restore_id")
    passphrase = None
    if payload.get("has_passphrase") and restore_id:
        got = await claim_passphrase(db, restore_id)
        passphrase = got.get("passphrase") if got.get("available") else None
    await heartbeat({"stage": "restoring", "memory": memory_snapshot()})
    try:
        result = await restore_from_path(db, restore_file, passphrase=passphrase)
        result["ok"] = True
    except ValueError as e:
        # bad passphrase / corrupt or invalid file -- terminal, do not retry.
        # Log the real reason so it's in the container logs (the UI only shows a
        # short message); stage-then-swap means the live DB is untouched here.
        logger.warning("Restore rejected (live data untouched): %s", e)
        result = {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("Restore failed unexpectedly")
        result = {"ok": False, "error": f"Restore failed: {e}"}
    finally:
        # the stashed upload is a full transient copy of the database -- never
        # leave it on the volume after the attempt, success or failure
        try:
            if restore_file and os.path.exists(restore_file):
                os.remove(restore_file)
        except OSError:
            pass
    result["memory"] = memory_snapshot()
    return result


@handler("correlation_run")
async def _correlation(db, payload, heartbeat):
    import correlation as cx
    await heartbeat({"stage": "evaluating"})
    return await cx.run(db)


@handler("posture_snapshot")
async def _posture(db, payload, heartbeat):
    import posture_history as ph
    return await ph.take_snapshot(db)
