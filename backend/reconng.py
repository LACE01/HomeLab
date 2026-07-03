"""recon-ng OSINT module runner -- broader threat-intel + passive-recon module support
on top of the existing EASM (crt.sh subdomain discovery) and Nmap/Nikto active-scan
integrations.

Architecture note up front, since this is the most "glue code shells out to a
whole external framework" integration in the app: recon-ng is a large, separately
versioned OSINT tool whose exact module catalog / CLI flags can drift release to
release, and it isn't installed in the sandbox this was built in -- so unlike the
Nmap/Nikto integrations (which reuse a pattern already proven against real running
containers in this app), the actual subprocess execution here has only been verified
with a mocked recon-cli, not a real one. The module catalog below is deliberately kept
to recon-ng's longest-standing, most commonly documented modules; treat the first
real run on your server as a smoke test, and check `recon-cli -m <module> --show`
inside the container if a specific module errors out, since the exact option name
recon-ng expects can vary by version.

Every module run happens in its own disposable workspace (named after the run id),
scripted via a one-shot .rc resource file so nothing depends on interactive prompts:
  1. (optional) `keys add <name> <value>` for any API keys the module needs
  2. `modules load <module_path>`
  3. `options set SOURCE <target>`
  4. `run`
  5. `modules load reporting/json` + `options set FILENAME <path>` + `run` -- dumps
     the whole workspace db (hosts/contacts/credentials/etc.) to JSON
The workspace is deleted after the report is read back, win or lose.

Results get routed by which recon-ng db table the module populates:
  - "hosts"  -> fed into the same easm_candidates queue as the existing crt.sh-based
                EASM discovery, so a new subdomain shows up in one place to review/
                promote regardless of which tool found it.
  - "credentials"/"contacts" -> stored in db.osint_findings; a genuine breach/paste
                hit also dispatches the osint_exposure_found notification trigger,
                since that's actionable in a way "we found a WHOIS contact" isn't.
"""
import asyncio
import json
import os
import re
import shlex
import tempfile
import uuid
from datetime import datetime, timezone

MODULE_CATALOG = [
    {
        "id": "hackertarget", "module": "recon/domains-hosts/hackertarget",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "HackerTarget Host Search",
        "description": "Passive subdomain/host discovery via HackerTarget's free API.",
    },
    {
        "id": "bing_domain_web", "module": "recon/domains-hosts/bing_domain_web",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "Bing Domain Search",
        "description": "Subdomain discovery by scraping Bing search results for the domain.",
    },
    {
        "id": "resolve", "module": "recon/hosts-hosts/resolve",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "Resolve Hosts",
        "description": "Resolves hostnames already in the workspace to IP addresses.",
    },
    {
        "id": "whois_pocs", "module": "recon/domains-contacts/whois_pocs",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "contacts", "label": "WHOIS Contacts",
        "description": "Harvests point-of-contact names/emails from WHOIS registration records.",
    },
    {
        "id": "hibp_breach", "module": "recon/contacts-credentials/hibp_breach",
        "category": "threat-intel", "target_type": "email", "requires_keys": ["hibp_api_key"],
        "result_table": "credentials", "label": "HaveIBeenPwned — Breaches",
        "description": "Checks a contact email against known breach databases via the HIBP API.",
    },
    {
        "id": "hibp_paste", "module": "recon/contacts-credentials/hibp_paste",
        "category": "threat-intel", "target_type": "email", "requires_keys": ["hibp_api_key"],
        "result_table": "credentials", "label": "HaveIBeenPwned — Pastes",
        "description": "Checks a contact email against public paste-site exposure via the HIBP API.",
    },
]

MODULE_BY_ID = {m["id"]: m for m in MODULE_CATALOG}
ALL_REQUIRED_KEYS = sorted({k for m in MODULE_CATALOG for k in m["requires_keys"]})

TARGET_RE = re.compile(r"^[a-zA-Z0-9.@_\-]{1,255}$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("Target is required")
    if not TARGET_RE.match(target):
        raise ValueError(f"'{target}' doesn't look like a valid domain/email/hostname")
    return target


async def _run_recon_cli(workspace: str, rc_lines: list, timeout_sec: int = 300) -> None:
    """The one function that actually shells out to recon-ng. Kept tiny and isolated
    so tests can mock just this and exercise the real parsing/routing logic around it."""
    with tempfile.NamedTemporaryFile("w", suffix=".rc", delete=False) as f:
        f.write("\n".join(rc_lines) + "\n")
        rc_path = f.name
    try:
        cmd = ["recon-cli", "-w", workspace, "-r", rc_path]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise TimeoutError(f"recon-ng module exceeded {timeout_sec}s and was killed")
        if proc.returncode not in (0, None):
            # recon-ng returns non-zero on plenty of benign conditions (module warns,
            # zero results) -- only surface this as a hint, don't hard-fail on it,
            # since the real signal is whether the report file below is readable.
            pass
    finally:
        try:
            os.unlink(rc_path)
        except OSError:
            pass


async def _cleanup_workspace(workspace: str) -> None:
    try:
        cmd = ["recon-cli", "-C", f"workspaces remove {shlex.quote(workspace)}"]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=30)
    except Exception:
        pass  # best-effort -- a leftover workspace is harmless clutter, not a failure


async def run_module(db, module_id: str, target: str, timeout_sec: int = 300) -> dict:
    """Runs one recon-ng module against `target`, routes the results, and returns a
    summary dict. Raises ValueError for bad input, RuntimeError/TimeoutError for
    execution problems."""
    mod = MODULE_BY_ID.get(module_id)
    if not mod:
        raise ValueError(f"Unknown module '{module_id}'")
    target = validate_target(target)

    integration = await db.integrations.find_one({"name": "recon-ng"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    missing_keys = [k for k in mod["requires_keys"] if not cfg.get(k)]
    if missing_keys:
        raise ValueError(f"Missing required API key(s) for this module: {', '.join(missing_keys)} — set them under Recon & OSINT → API Keys.")

    workspace = f"vulnops-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, "report.json")
        rc_lines = []
        for key_name in mod["requires_keys"]:
            rc_lines.append(f"keys add {key_name} {shlex.quote(cfg[key_name])}")
        rc_lines += [
            f"modules load {mod['module']}",
            f"options set SOURCE {shlex.quote(target)}",
            "run",
            "modules load reporting/json",
            f"options set FILENAME {shlex.quote(report_path)}",
            "run",
            "exit",
        ]
        try:
            await _run_recon_cli(workspace, rc_lines, timeout_sec=timeout_sec)
            if not os.path.exists(report_path):
                raise RuntimeError("recon-ng did not produce a report file -- the module may not be installed (try `marketplace install` for it inside the container) or produced no results.")
            with open(report_path) as f:
                report = json.load(f)
        finally:
            await _cleanup_workspace(workspace)

    return await _route_results(db, mod, target, report)


async def _route_results(db, mod: dict, target: str, report) -> dict:
    """recon-ng's JSON report export is a flat list of table rows tagged with which
    table they came from in real installs; to stay robust to minor shape differences
    across versions, this accepts either {"hosts": [...], "contacts": [...], ...} or a
    flat list of {"table": "...", ...} rows and normalizes both."""
    tables: dict = {}
    if isinstance(report, dict):
        tables = {k: v for k, v in report.items() if isinstance(v, list)}
    elif isinstance(report, list):
        for row in report:
            t = row.get("table") if isinstance(row, dict) else None
            if t:
                tables.setdefault(t, []).append(row)

    rows = tables.get(mod["result_table"], [])
    summary = {"module": mod["id"], "target": target, "result_table": mod["result_table"], "row_count": len(rows)}

    if mod["result_table"] == "hosts":
        created = await _ingest_hosts(db, rows, target)
        summary["easm_candidates_created"] = created
    elif mod["result_table"] in ("credentials", "contacts"):
        hits = await _ingest_osint_rows(db, mod, target, rows)
        summary["osint_findings_created"] = hits
    return summary


async def _ingest_hosts(db, rows: list, domain: str) -> int:
    """Feeds discovered hostnames into the same easm_candidates queue the crt.sh-based
    EASM discovery already uses, so review/promote works the same way regardless of
    which tool found the subdomain."""
    now = _now_iso()
    created = 0
    for row in rows:
        hostname = (row.get("host") or row.get("hostname") or "").strip().lower()
        if not hostname:
            continue
        existing = await db.easm_candidates.find_one({"hostname": hostname}, {"_id": 0})
        ip = row.get("ip_address") or row.get("ip")
        if existing:
            await db.easm_candidates.update_one({"id": existing["id"]}, {"$set": {
                "resolved_ip": ip or existing.get("resolved_ip"), "last_seen_at": now,
            }})
            continue
        await db.easm_candidates.insert_one({
            "id": str(uuid.uuid4()), "hostname": hostname, "domain": domain,
            "resolved_ip": ip, "live": bool(ip), "status": "new",
            "first_seen_at": now, "last_seen_at": now, "source": "recon-ng",
        })
        created += 1
    return created


BREACH_KEYWORDS = ("breach", "pwned", "compromise", "leak", "paste")


async def _ingest_osint_rows(db, mod: dict, target: str, rows: list) -> int:
    from notifier import dispatch
    now = _now_iso()
    created = 0
    for row in rows:
        label = row.get("name") or row.get("resource") or row.get("email") or mod["label"]
        detail = row.get("password") and "credential exposed" or row.get("resource") or json.dumps(row)[:200]
        key = f"{mod['id']}:{target}:{label}"
        existing = await db.osint_findings.find_one({"key": key}, {"_id": 0})
        if existing:
            continue
        doc = {
            "id": str(uuid.uuid4()), "key": key, "module": mod["id"], "module_label": mod["label"],
            "target": target, "label": label, "detail": detail, "raw": row,
            "found_at": now, "acknowledged": False,
        }
        await db.osint_findings.insert_one(doc)
        created += 1
        is_breach = mod["category"] == "threat-intel" or any(k in (label or "").lower() for k in BREACH_KEYWORDS)
        if is_breach:
            await dispatch("osint_exposure_found", {
                "module": mod["label"], "target": target, "label": label,
                "detail": detail, "url": "/admin/recon-osint",
            }, db)
    return created
