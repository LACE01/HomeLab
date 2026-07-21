"""Container image vulnerability scanning.

Reuses the SBOM import pipeline (see sbom.py) rather than bundling Trivy's
full vulnerability-scanning mode with its own multi-hundred-MB vulnerability
database -- sbom.py's own docstring already explains why this app queries
OSV.dev directly instead of mirroring a scanner database inside a single
self-hosted container, and that reasoning applies identically here.

Trivy is used ONLY in its `--format cyclonedx` SBOM-generation mode, which
enumerates an image's installed packages without downloading any
vulnerability database at all -- confirmed against Trivy's own docs
(trivy.dev/docs/latest/supply-chain/sbom/): "By default, --format cyclonedx
represents SBOM and doesn't include vulnerabilities... avoids the need to
download the vulnerability database." The resulting CycloneDX JSON is handed
straight to sbom.import_sbom(), which already knows how to match components
against OSV.dev and create/update/dedup findings -- this module only adds
"produce that SBOM from a container image reference" on top, plus the same
watch-target CRUD/scheduling shape as cert_monitor.py/domain_email_security.py/
eol_tracking.py.

Trivy pulls the image itself directly from its registry (Docker Hub, GHCR, a
private registry, etc.) over the network -- it does NOT need a local Docker
daemon or the host's docker.sock, so scanning doesn't require mounting any
Docker socket into this container (a real privilege-escalation risk this app
avoids elsewhere too: nmap/nikto run with only the specific NET_RAW/NET_ADMIN
capabilities they need, never --privileged).

A note on findings and canonical_key: sbom.import_sbom() keys findings by
`ecosystem:name@version:vuln_id`, not by which asset/image they came from.
For container images this is actually the right behavior, not a limitation --
many running containers sharing the same image share the exact same
vulnerable package+version+CVE, and the fix action is "rebuild from a patched
base image," not something per-container. One finding per real vulnerability
is correct here.
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("vulnops")

TRIVY_BIN = "trivy"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def generate_image_sbom(image_ref: str, timeout_sec: int = 300) -> bytes:
    """Runs `trivy image --format cyclonedx` against an image reference (pulled
    directly from its registry by Trivy) and returns the raw CycloneDX JSON
    bytes. Raises ValueError with Trivy's own stderr on failure (bad image
    reference, registry unreachable, auth required, image too large, etc.)
    instead of a raw subprocess/timeout error -- these are common, expected
    first-run mistakes, not exceptional conditions."""
    try:
        proc = await asyncio.create_subprocess_exec(
            TRIVY_BIN, "image", "--format", "cyclonedx", "--quiet", image_ref,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except FileNotFoundError:
        raise ValueError("Trivy isn't installed in this container -- rebuild the backend image to pick it up")
    except asyncio.TimeoutError:
        raise ValueError(f"Scanning '{image_ref}' took longer than {timeout_sec}s and was aborted")

    if proc.returncode != 0:
        detail = (stderr or b"").decode("utf-8", "replace").strip() or f"trivy exited with code {proc.returncode}"
        raise ValueError(f"Couldn't scan '{image_ref}': {detail}")
    if not stdout:
        raise ValueError(f"Trivy produced no output for '{image_ref}'")
    return stdout


async def scan_container_image(db, image_ref: str, asset_id: str = None, label: str = None) -> dict:
    """Generates an SBOM for the given image and runs it through the existing
    SBOM/OSV.dev import pipeline -- same finding creation, dedup, and severity
    mapping every manual SBOM upload gets. Also records a lightweight
    scan-history entry keyed by image_ref so a watch target can show "last
    scanned"/"packages found" without re-deriving it from the findings
    collection each time."""
    from sbom import import_sbom
    sbom_bytes = await generate_image_sbom(image_ref)
    result = await import_sbom(
        db, sbom_bytes, filename=f"{image_ref}.cdx.json", label=label or image_ref, asset_id=asset_id,
        source_tool="Container Image Scan", detection_channel="Scheduled/manual image scan (Trivy SBOM + OSV.dev)",
    )

    record = {
        "id": image_ref, "image_ref": image_ref, "label": label, "asset_id": asset_id,
        **result, "scanned_at": _now_iso(),
    }
    await db.container_image_scans.update_one({"id": image_ref}, {"$set": record}, upsert=True)
    return record


async def container_scan_loop(db, interval_hours: int = 24):
    """Background poll -- scans all enabled watch targets once per interval.
    Gated by the container_image_nightly_scan feature flag (default on) --
    manual "Scan now"/"Scan all" actions from the UI are never gated, only
    this automatic sweep, same convention as the other Scheduled Syncs flags.
    A daily cadence matches this app's other periodic scanners; new CVEs get
    published against existing, unchanged image tags constantly, so this is
    one case where even a pinned/unchanged image is worth re-checking on a
    schedule, not just on push."""
    from heartbeat import record_heartbeat
    from feature_flags import is_enabled
    await asyncio.sleep(60)  # let other startup tasks settle first
    while True:
        ok, detail = True, {}
        try:
            if await is_enabled(db, "container_image_nightly_scan"):
                result = await run_all_container_scans(db)
                logger.info(f"Container image scan sweep: {result}")
                detail = result
            else:
                detail = {"skipped": "disabled in Settings"}
        except Exception as e:
            logger.exception(f"Container image scan sweep failed: {e}")
            ok, detail["error"] = False, str(e)
        await record_heartbeat(db, "container_scan_loop", "ok" if ok else "error", detail)
        await asyncio.sleep(interval_hours * 3600)


async def run_all_container_scans(db) -> dict:
    """Scans every enabled watch target. Concurrency-capped and deliberately
    low (3) -- unlike a DNS lookup or TLS handshake, each of these pulls a
    full container image and runs a filesystem walk, real CPU/network/disk
    work, so a home-lab-scale host shouldn't be asked to do many at once."""
    targets = await db.container_image_watch_targets.find({"enabled": True}, {"_id": 0}).to_list(200)
    sem = asyncio.Semaphore(3)

    async def _one(t):
        async with sem:
            try:
                return await scan_container_image(db, t["image_ref"], t.get("asset_id"), t.get("label"))
            except Exception as e:
                return {"image_ref": t["image_ref"], "error": str(e)}

    results = await asyncio.gather(*[_one(t) for t in targets])
    scanned = len(results)
    failed = len([r for r in results if "error" in r])
    findings_created = sum(r.get("findings_created", 0) for r in results if "error" not in r)
    return {"scanned": scanned, "failed": failed, "findings_created": findings_created, "synced_at": _now_iso()}
