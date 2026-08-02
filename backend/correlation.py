"""Findings that only exist in the JOIN.

Every module here is individually correct and individually blind. Qualys knows a
host is unpatched. Albert knows someone is scanning it. Entra knows an admin
signs in from it. HIBP knows that admin's password leaked. Not one of those is an
alert on its own -- and the four together are an incident that nobody currently
sees, because no screen puts them next to each other.

That gap is the product. These rules are the only thing in the platform whose
input is other modules' output.

DESIGN RULES

  * A HIT IS A NARRATIVE, NOT A SCORE. Each rule emits the sentence a human would
    say: "X, and Y, therefore Z." A number would be smaller and would throw away
    the only thing that makes a correlation actionable -- the chain of reasoning
    that can be checked and disagreed with.

  * EVERY CLAUSE CARRIES ITS EVIDENCE, with ids, so the hit can be verified from
    the source records rather than believed.

  * A RULE THAT CANNOT CHECK ITS INPUTS SAYS SO. If the IDS has no data for a
    segment, the rule reports "could not evaluate", not "no hit". Silent
    non-evaluation is how correlation engines become decorative: they look calm
    for months because a feed died.

  * RULES ARE DATA, NOT CODE PATHS. Each is a small object with a predicate over
    a prepared context. Adding one is adding an entry, and each is independently
    testable.
"""
import asyncio
import uuid
from datetime import datetime, timezone, timedelta

WINDOW_DAYS = 7
OPEN_STATUSES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

SEVERITY = ["Info", "Low", "Medium", "High", "Critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITY)}


def _now():
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _since(days: int) -> str:
    return (_now() - timedelta(days=days)).isoformat()


class Rule:
    """One correlation. `evaluate` returns a hit dict, None, or an
    'unevaluable' marker when its inputs are missing."""

    def __init__(self, *, key, title, severity, requires, evaluate, why_it_matters):
        self.key = key
        self.title = title
        self.severity = severity
        self.requires = requires      # data sources this rule needs to mean anything
        self.evaluate = evaluate
        self.why_it_matters = why_it_matters


def _hit(rule, *, subject, narrative, evidence, severity=None):
    return {
        "id": str(uuid.uuid4()),
        "rule_key": rule.key,
        "rule_title": rule.title,
        "severity": severity or rule.severity,
        "subject": subject,           # {type, id, label}
        "narrative": narrative,
        "why_it_matters": rule.why_it_matters,
        "evidence": evidence,
        "detected_at": _now_iso(),
        "status": "open",
    }


# ---------------------------------------------------------------------------
# The rules. Each takes the prepared per-asset context built in `_context_for`.
# ---------------------------------------------------------------------------
def _r_kev_exposed_and_scanned(rule, c):
    """The one that should wake someone up."""
    kev = [f for f in c["findings"] if f.get("kev_flag")]
    if not kev:
        return None
    if not c["asset"].get("internet_facing"):
        return None
    ports = c["alert_ports"]
    hit_ports = sorted({f.get("port") for f in kev if f.get("port") and f["port"] in ports})
    if not c["alerts"]:
        return None
    cves = [f.get("cve") for f in kev if f.get("cve")][:4]
    narrative = (
        f"{c['asset'].get('hostname')} is internet-facing and carries "
        f"{len(kev)} vulnerability(ies) CISA lists as actively exploited "
        f"({', '.join(cves) or 'no CVE recorded'}). "
        f"The IDS has logged {len(c['alerts'])} alerts against this host in the last "
        f"{WINDOW_DAYS} days"
        + (f", including traffic to port {hit_ports[0]} — the port one of those "
           "vulnerabilities is on. " if hit_ports else ". ")
        + "That is a known-exploited weakness, reachable from the internet, with "
          "someone already sending traffic at it."
    )
    return _hit(rule, subject={"type": "asset", "id": c["asset"]["id"],
                                "label": c["asset"].get("hostname")},
                 narrative=narrative,
                 severity="Critical" if hit_ports else "High",
                 evidence={"kev_finding_ids": [f["id"] for f in kev][:10],
                            "cves": cves, "alert_count": len(c["alerts"]),
                            "targeted_ports": hit_ports})


def _r_no_edr_privileged(rule, c):
    if "defender" in c["sources"]:
        return None
    if not c["privileged_users"]:
        return None
    names = [u.get("display_name") or u.get("user_principal_name")
             for u in c["privileged_users"]][:3]
    return _hit(rule, subject={"type": "asset", "id": c["asset"]["id"],
                                "label": c["asset"].get("hostname")},
                 narrative=(
                     f"{c['asset'].get('hostname')} has no endpoint detection on it — no EDR "
                     f"product has ever reported this machine — and {len(c['privileged_users'])} "
                     f"privileged account(s) use it as their primary device ({', '.join(names)}). "
                     "If this machine is compromised, nothing would detect it, and what an "
                     "attacker would find is administrative credentials."),
                 evidence={"privileged_user_ids": [u.get("id") for u in c["privileged_users"]],
                            "sources_seen": sorted(c["sources"])})


def _r_leaked_credential_with_foothold(rule, c):
    if not c["breached_users"]:
        return None
    exploitable = [f for f in c["findings"]
                   if SEV_RANK.get(f.get("severity"), 0) >= SEV_RANK["High"]]
    if not exploitable:
        return None
    who = [b.get("email") or b.get("user_principal_name") for b in c["breached_users"]][:3]
    return _hit(rule, subject={"type": "asset", "id": c["asset"]["id"],
                                "label": c["asset"].get("hostname")},
                 narrative=(
                     f"Credentials for {len(c['breached_users'])} user(s) of "
                     f"{c['asset'].get('hostname')} appear in known breach data "
                     f"({', '.join(who)}), and the machine itself carries "
                     f"{len(exploitable)} High/Critical vulnerability(ies). "
                     "Either alone is routine. Together they are a way in and a way up: "
                     "a working credential and a host that can be escalated on."),
                 evidence={"breached": who,
                            "finding_ids": [f["id"] for f in exploitable][:10]})


def _r_crown_jewel_path_all_unpatched(rule, c):
    paths = c["attack_paths"]
    if not paths:
        return None
    worst = paths[0]
    return _hit(rule, subject={"type": "attack_path", "id": worst.get("id"),
                                "label": worst.get("target_label")},
                 narrative=(
                     f"There is a {worst.get('hop_count')}-hop path from "
                     f"{c['asset'].get('hostname')} to "
                     f"{worst.get('target_label') or 'a crown jewel'} "
                     f"(score {worst.get('score')}), and this asset is on it while carrying open "
                     f"findings. {worst.get('narrative') or ''}").strip(),
                 evidence={"path_id": worst.get("id"),
                            "finding_ids": [f["id"] for f in c["findings"]][:10]})


def _r_expiring_cert_on_critical(rule, c):
    certs = c["expiring_certs"]
    if not certs:
        return None
    if (c["asset"].get("criticality") or "").lower() not in ("high", "critical", "crown_jewel"):
        return None
    soonest = certs[0]
    return _hit(rule, subject={"type": "asset", "id": c["asset"]["id"],
                                "label": c["asset"].get("hostname")},
                 narrative=(
                     f"The TLS certificate on {c['asset'].get('hostname')} expires in "
                     f"{soonest.get('days_left')} days, and this is a "
                     f"{c['asset'].get('criticality')}-criticality asset"
                     + (" that is internet-facing" if c["asset"].get("internet_facing") else "")
                     + ". An expiry here is an outage with a countdown already running."),
                 evidence={"cert": soonest})


def _r_unmanaged_and_vulnerable(rule, c):
    if "intune" in c["sources"]:
        return None
    crit = [f for f in c["findings"]
            if SEV_RANK.get(f.get("severity"), 0) >= SEV_RANK["High"]]
    if len(crit) < 3:
        return None
    return _hit(rule, subject={"type": "asset", "id": c["asset"]["id"],
                                "label": c["asset"].get("hostname")},
                 narrative=(
                     f"{c['asset'].get('hostname')} is not enrolled in device management and "
                     f"has {len(crit)} High/Critical findings open. There is no automated way to "
                     "push a fix to this machine, so every one of those has to be remediated by "
                     "hand — which is why they accumulate here and not elsewhere."),
                 evidence={"finding_ids": [f["id"] for f in crit][:10]})


def _r_vendor_incident_touches_us(rule, c):
    """Vendor-scoped, evaluated once rather than per asset."""
    return None  # handled in run(); kept here so the key is registered


RULES = [
    Rule(key="kev_exposed_scanned", title="Known-exploited flaw, internet-facing, under active scanning",
         severity="Critical",
         requires=["findings", "asset_exposure", "ids"],
         evaluate=_r_kev_exposed_and_scanned,
         why_it_matters=("Each part is common. All three at once describes a host an attacker has "
                          "already found and has a working exploit for.")),
    Rule(key="no_edr_privileged", title="Privileged user's device has no EDR",
         severity="High",
         requires=["identity", "directory"],
         evaluate=_r_no_edr_privileged,
         why_it_matters=("Detection gaps matter most where the consequences are worst. This is the "
                          "intersection.")),
    Rule(key="leaked_cred_plus_foothold", title="Breached credential on a vulnerable host",
         severity="High",
         requires=["breach_data", "findings"],
         evaluate=_r_leaked_credential_with_foothold,
         why_it_matters="A way in and a way up, on the same machine."),
    Rule(key="crown_jewel_path", title="Open findings on a path to a crown jewel",
         severity="High",
         requires=["attack_paths", "findings"],
         evaluate=_r_crown_jewel_path_all_unpatched,
         why_it_matters=("A vulnerability's importance is mostly a function of what it leads to.")),
    Rule(key="cert_expiry_critical", title="Certificate expiring on a critical asset",
         severity="Medium",
         requires=["certs"],
         evaluate=_r_expiring_cert_on_critical,
         why_it_matters="A self-inflicted outage with a known date."),
    Rule(key="unmanaged_vulnerable", title="Unmanaged device accumulating serious findings",
         severity="Medium",
         requires=["identity", "findings"],
         evaluate=_r_unmanaged_and_vulnerable,
         why_it_matters=("Explains WHY a host stays broken: nothing can push it a fix.")),
]

RULES_BY_KEY = {r.key: r for r in RULES}


# ---------------------------------------------------------------------------
async def _prefetch(db, assets: list) -> dict:
    """Load everything the rules need in a handful of queries, not six per asset.

    The first version did ~6 round trips PER ASSET. On a few hundred assets that
    is thousands of sequential queries every run, which does not block the loop
    (they are awaits) but does monopolise the database and the scheduler for
    minutes at a time -- and it grows linearly with the estate, so it gets worse
    exactly as the platform becomes more useful.
    """
    asset_ids = [a["id"] for a in assets]
    ips = [a.get("ip") for a in assets if a.get("ip")]
    intune_ids = [a.get("intune_device_id") for a in assets if a.get("intune_device_id")]

    findings_by_asset: dict = {}
    for f in await db.findings.find(
            {"asset_id": {"$in": asset_ids}, "status": {"$in": OPEN_STATUSES}},
            {"_id": 0, "id": 1, "asset_id": 1, "cve": 1, "severity": 1, "kev_flag": 1,
             "port": 1, "title": 1}).to_list(200000):
        findings_by_asset.setdefault(f["asset_id"], []).append(f)

    sources_by_asset: dict = {}
    for row in await db.asset_identifiers.find(
            {"asset_id": {"$in": asset_ids}}, {"_id": 0, "asset_id": 1, "source": 1}
    ).to_list(200000):
        sources_by_asset.setdefault(row["asset_id"], set()).add(row["source"])

    alerts_by_ip: dict = {}
    if ips:
        for a in await db.albert_alerts.find(
                {"time_gmt": {"$gte": _since(WINDOW_DAYS)},
                 "$or": [{"destination_ip": {"$in": ips}}, {"source_ip": {"$in": ips}}]},
                {"_id": 0, "destination_ip": 1, "source_ip": 1, "destination_port": 1,
                 "category": 1}).to_list(100000):
            for ip in (a.get("destination_ip"), a.get("source_ip")):
                if ip:
                    alerts_by_ip.setdefault(ip, []).append(a)

    users_by_device: dict = {}
    emails: list = []
    if intune_ids:
        for u in await db.directory_users.find(
                {"primary_device_id": {"$in": intune_ids}}, {"_id": 0}).to_list(50000):
            users_by_device.setdefault(u["primary_device_id"], []).append(u)
            upn = u.get("user_principal_name") or u.get("email")
            if upn:
                emails.append(upn)

    breaches_by_email: dict = {}
    if emails:
        for b in await db.breach_exposures.find(
                {"email": {"$in": emails}}, {"_id": 0}).to_list(50000):
            breaches_by_email.setdefault(b["email"], []).append(b)

    paths_by_asset: dict = {}
    for p in await db.attack_paths.find(
            {"status": {"$ne": "resolved"}, "node_asset_ids": {"$in": asset_ids}},
            {"_id": 0}).to_list(20000):
        for nid in (p.get("node_asset_ids") or []):
            paths_by_asset.setdefault(nid, []).append(p)
    for lst in paths_by_asset.values():
        lst.sort(key=lambda x: -(x.get("score") or 0))

    certs_by_asset: dict = {}
    for c in await db.cert_checks.find(
            {"asset_id": {"$in": asset_ids}, "days_left": {"$lte": 30, "$gte": 0}},
            {"_id": 0}).to_list(20000):
        certs_by_asset.setdefault(c["asset_id"], []).append(c)
    for lst in certs_by_asset.values():
        lst.sort(key=lambda x: x.get("days_left", 999))

    return {"findings": findings_by_asset, "sources": sources_by_asset,
            "alerts": alerts_by_ip, "users": users_by_device,
            "breaches": breaches_by_email, "paths": paths_by_asset,
            "certs": certs_by_asset}


def _context_for(asset: dict, pre: dict) -> dict:
    """Assemble one asset's context from the prefetched maps. No I/O."""
    alerts = pre["alerts"].get(asset.get("ip"), []) if asset.get("ip") else []
    users = pre["users"].get(asset.get("intune_device_id"), []) \
        if asset.get("intune_device_id") else []
    breached = []
    for u in users:
        upn = u.get("user_principal_name") or u.get("email")
        breached.extend(pre["breaches"].get(upn, []) if upn else [])
    return {
        "asset": asset,
        "findings": pre["findings"].get(asset["id"], []),
        "sources": pre["sources"].get(asset["id"], set()),
        "alerts": alerts,
        "alert_ports": {a.get("destination_port") for a in alerts if a.get("destination_port")},
        "privileged_users": [u for u in users if u.get("is_privileged") or u.get("admin_roles")],
        "breached_users": breached,
        "attack_paths": pre["paths"].get(asset["id"], []),
        "expiring_certs": pre["certs"].get(asset["id"], []),
    }


async def _availability(db) -> dict:
    """Which inputs actually have data.

    A rule whose inputs are empty must report that it could not be evaluated. A
    correlation engine that silently returns "no hits" when a feed has died looks
    calm for months and is the most dangerous shape this feature can take.
    """
    async def any_docs(coll, q=None):
        return await db[coll].count_documents(q or {}) > 0

    return {
        "findings": await any_docs("findings"),
        "asset_exposure": await any_docs("assets"),
        "ids": await any_docs("albert_alerts", {"time_gmt": {"$gte": _since(30)}}),
        "identity": await any_docs("asset_identifiers"),
        "directory": await any_docs("directory_users"),
        "breach_data": await any_docs("breach_exposures"),
        "attack_paths": await any_docs("attack_paths"),
        "certs": await any_docs("cert_checks"),
    }


async def run(db, *, asset_limit: int = 5000) -> dict:
    """Evaluate every rule against every active asset.

    Hits are upserted by (rule, subject) so a persisting condition stays one hit
    with a growing history rather than a new alert every run -- the difference
    between a signal and a noise generator.
    """
    available = await _availability(db)
    unevaluable = []
    for rule in RULES:
        missing = [r for r in rule.requires if not available.get(r, False)]
        if missing:
            unevaluable.append({
                "rule_key": rule.key, "rule_title": rule.title, "missing_inputs": missing,
                "note": (f"Not evaluated: no data in {', '.join(missing)}. This rule is not "
                          "reporting 'no problems' — it is reporting that it could not look."),
            })
    runnable = [r for r in RULES
                if all(available.get(x, False) for x in r.requires)]

    assets = await db.assets.find(
        {"status": {"$nin": ["merged", "decommissioned"]}}, {"_id": 0}).to_list(asset_limit)

    pre = await _prefetch(db, assets)

    new_hits, refreshed = 0, 0
    seen_keys = set()
    for i, asset in enumerate(assets):
        # Yield periodically. Rule evaluation is pure CPU over the prefetched
        # maps, so without this a large estate would hold the loop for the whole
        # sweep -- the same defect as the coverage endpoint, one layer down.
        if i % 200 == 0:
            await asyncio.sleep(0)
        ctx = _context_for(asset, pre)
        for rule in runnable:
            try:
                hit = rule.evaluate(rule, ctx)
            except Exception:
                continue
            if not hit:
                continue
            dedupe = f"{hit['rule_key']}::{hit['subject']['type']}::{hit['subject']['id']}"
            seen_keys.add(dedupe)
            existing = await db.correlation_hits.find_one({"dedupe_key": dedupe}, {"_id": 0})
            if existing:
                await db.correlation_hits.update_one({"dedupe_key": dedupe}, {"$set": {
                    "narrative": hit["narrative"], "evidence": hit["evidence"],
                    "severity": hit["severity"], "last_seen_at": _now_iso(),
                    "status": existing.get("status", "open")}})
                refreshed += 1
            else:
                await db.correlation_hits.insert_one({
                    **hit, "dedupe_key": dedupe, "first_seen_at": _now_iso(),
                    "last_seen_at": _now_iso()})
                new_hits += 1

    # Conditions that no longer hold are resolved, not deleted: "this was true
    # last week and isn't now" is exactly what a change feed needs.
    stale = await db.correlation_hits.find(
        {"status": "open", "dedupe_key": {"$nin": list(seen_keys)}}, {"_id": 0}).to_list(1000)
    for s in stale:
        await db.correlation_hits.update_one({"dedupe_key": s["dedupe_key"]}, {"$set": {
            "status": "resolved", "resolved_at": _now_iso(),
            "resolved_reason": "The combination of conditions that triggered this no longer holds."}})

    return {
        "assets_evaluated": len(assets),
        "rules_run": [r.key for r in runnable],
        "new_hits": new_hits,
        "refreshed_hits": refreshed,
        "auto_resolved": len(stale),
        "not_evaluated": unevaluable,
        "input_availability": available,
    }
