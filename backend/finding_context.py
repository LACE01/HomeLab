"""Why does THIS finding matter on THIS asset?

The question a severity label cannot answer. "Critical" is a property of the
vulnerability in the abstract; whether it matters here depends on where the asset
sits, what is on it, whether anyone is currently attacking it, and what the
organization already decided about it. All of that is in this database, in eight
different modules, and until now nobody joined it.

This module assembles one answer from every module that knows something:

    reachability   is it internet-facing, and does anything corroborate that
    attack path    does it sit on a path to a crown jewel, and does fixing it
                   break the path
    active         has the IDS seen scanning or exploit traffic at this asset,
                   on this port, recently
    exploit        KEV, EPSS, ransomware actor usage, CTI reporting
    identity       do privileged accounts sign in from this machine
    controls       EDR present, patch-managed, encrypted -- and what is MISSING
    corroboration  did more than one scanner confirm it
    governance     accepted exception, open risk-register entry, security review

TWO RULES THIS FOLLOWS

  1. EVERY LINE CITES ITS SOURCE. A context panel that asserts things without
     saying where they came from is worse than no panel: it is unfalsifiable, and
     an analyst who cannot check it will eventually stop believing all of it.

  2. ABSENCE IS REPORTED, NOT HIDDEN. "No EDR on this machine" and "no IDS
     coverage for this segment" are among the most important things the panel can
     say. A section that renders nothing when data is missing quietly converts a
     blind spot into apparent safety.

The verdict at the end is deliberately a SENTENCE, not a score. The platform
already has a risk score; what it lacked was the reasoning, and a second number
would not have supplied it.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional

ACTIVE_WINDOW_DAYS = 7
OPEN_STATUSES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]


def _now():
    return datetime.now(timezone.utc)


def _iso_days_ago(days: int) -> str:
    return (_now() - timedelta(days=days)).isoformat()


def _item(*, key: str, headline: str, detail: str = "", weight: str = "neutral",
           source: str = "", link: Optional[str] = None, evidence: Optional[dict] = None) -> dict:
    """One statement, with where it came from.

    `weight` is aggravating / mitigating / neutral / missing -- not a number. The
    panel is an argument, and an argument is made of claims that push in a
    direction, not of addends.
    """
    return {"key": key, "headline": headline, "detail": detail, "weight": weight,
            "source": source, "link": link, "evidence": evidence or {}}


# --------------------------------------------------------------------------
async def _reachability(db, finding: dict, asset: dict) -> list:
    if not asset:
        # A finding with no resolvable asset is itself worth saying out loud --
        # it means nothing about its environment can be assessed at all.
        return [_item(
            key="no_asset", weight="missing",
            headline="This finding is not linked to an asset, so none of its environment "
                     "could be assessed.",
            detail="Reachability, attack paths, IDS traffic and controls all require an asset.",
            source="Asset inventory")]
    out = []
    exposure = asset.get("exposure")
    if (asset or {}).get("internet_facing") or exposure in ("internet", "external"):
        out.append(_item(
            key="internet_facing", weight="aggravating",
            headline="This asset is reachable from the internet.",
            detail="An attacker does not need a foothold anywhere else to reach it.",
            source="Asset inventory", link=f"/assets/{asset.get('id')}"))
    else:
        out.append(_item(
            key="internal_only", weight="mitigating",
            headline=f"Not internet-facing (exposure: {exposure or 'unknown'}).",
            detail="Reaching it requires a foothold inside the network first.",
            source="Asset inventory", link=f"/assets/{asset.get('id')}"))

    # Independent corroboration from the external attack-surface scan beats the
    # inventory's own field, which is frequently a stale manual classification.
    easm = await db.easm_assets.find_one(
        {"$or": [{"hostname": asset.get("hostname")}, {"ip": asset.get("ip")}]},
        {"_id": 0}) if asset else None
    if easm:
        out.append(_item(
            key="easm_confirmed", weight="aggravating",
            headline="Confirmed externally visible by attack-surface scanning.",
            detail=(f"Discovered as {easm.get('hostname') or easm.get('ip')}"
                     + (f" with ports {', '.join(str(p) for p in easm['open_ports'])}"
                        if easm.get("open_ports") else "")
                     + ". This is observed from outside, not inferred from the inventory."),
            source="EASM", link="/attack-surface", evidence=easm))
    return out


async def _attack_path(db, finding: dict, asset: dict) -> list:
    if not asset:
        return []
    paths = await db.attack_paths.find(
        {"status": {"$ne": "resolved"}, "node_asset_ids": asset["id"]},
        {"_id": 0}).sort("score", -1).to_list(5)
    if not paths:
        return [_item(
            key="no_attack_path", weight="mitigating",
            headline="This asset is not on any known path to a crown jewel.",
            detail=("Attack path analysis found no chain from an entry point through this asset "
                     "to anything designated crown-jewel."),
            source="Attack path analysis", link="/attack-paths")]
    out = []
    for p in paths[:3]:
        breaks = finding.get("id") in (p.get("breaking_finding_ids") or [])
        out.append(_item(
            key="attack_path", weight="aggravating",
            headline=(f"On the path to {p.get('target_label') or 'a crown jewel'} "
                       f"(score {p.get('score')})."),
            detail=((("Fixing THIS finding breaks that path. " if breaks else "")
                      + (p.get("narrative") or ""))).strip(),
            source="Attack path analysis", link=f"/attack-paths/{p.get('id')}",
            evidence={"path_id": p.get("id"), "hops": p.get("hop_count"),
                       "breaks_path": breaks}))
    return out


async def _active_attack(db, finding: dict, asset: dict) -> list:
    """Is anyone actually poking at this, right now?

    The single most decision-changing piece of context available, and the one
    that is hardest to get: it needs the IDS alert and the vulnerability to be
    tied to the same machine, which only became possible once identity was
    resolved.
    """
    if not asset:
        return []
    since = _iso_days_ago(ACTIVE_WINDOW_DAYS)
    ips = [ip for ip in [asset.get("ip")] if ip]
    if not ips:
        return [_item(key="no_ids_data", weight="missing",
                       headline="No IP recorded for this asset, so IDS traffic can't be correlated.",
                       source="Albert / IDS")]
    alerts = await db.albert_alerts.find(
        {"$or": [{"destination_ip": {"$in": ips}}, {"source_ip": {"$in": ips}}],
         "time_gmt": {"$gte": since}},
        {"_id": 0}).sort("time_gmt", -1).to_list(50)
    if not alerts:
        return [_item(
            key="no_active_attack", weight="mitigating",
            headline=f"No IDS alerts involving this host in the last {ACTIVE_WINDOW_DAYS} days.",
            detail="Nothing is currently probing it, as far as the sensor can see.",
            source="Albert / IDS", link="/albert")]

    ports = sorted({a.get("destination_port") for a in alerts if a.get("destination_port")})
    cats = sorted({a.get("category") for a in alerts if a.get("category")})
    out = [_item(
        key="active_attack", weight="aggravating",
        headline=(f"{len(alerts)} IDS alerts involving this host in the last "
                   f"{ACTIVE_WINDOW_DAYS} days."),
        detail=(("Categories: " + ", ".join(cats[:4]) + ". " if cats else "")
                 + ("Targeted ports: " + ", ".join(str(p) for p in ports[:8]) + "." if ports else "")),
        source="Albert / IDS", link=f"/albert?ip={ips[0]}",
        evidence={"alert_count": len(alerts), "ports": ports[:8], "categories": cats[:6]})]

    # The strongest form: traffic aimed at the very port this finding is on.
    fport = finding.get("port") or finding.get("destination_port")
    if fport and fport in ports:
        out.append(_item(
            key="active_attack_same_port", weight="aggravating",
            headline=f"Traffic is targeting port {fport} — the port this finding is on.",
            detail=("This is no longer a theoretical exposure. Someone is sending traffic to the "
                     "exact service this vulnerability affects."),
            source="Albert / IDS", link=f"/albert?ip={ips[0]}&port={fport}"))
    return out


async def _exploit_reality(db, finding: dict) -> list:
    out = []
    if finding.get("kev_flag"):
        out.append(_item(
            key="kev", weight="aggravating",
            headline="Listed in CISA's Known Exploited Vulnerabilities catalogue.",
            detail="Confirmed exploited in the wild — this is not a theoretical risk.",
            source="CISA KEV", link=f"/findings/{finding.get('id')}"))
    epss = finding.get("epss_score") or 0
    if epss:
        pct = round(epss * 100, 1)
        out.append(_item(
            key="epss", weight="aggravating" if epss >= 0.1 else "neutral",
            headline=f"EPSS {pct}% — probability of exploitation in the next 30 days.",
            detail=("Well above the typical CVE, which sits below 1%." if epss >= 0.1
                     else "Low, relative to the CVE population."),
            source="FIRST EPSS"))
    cve = finding.get("cve")
    if cve:
        intel = await db.cti_reports.find({"cves": cve}, {"_id": 0}).sort(
            "published", -1).to_list(3)
        for r in intel:
            out.append(_item(
                key="cti", weight="aggravating",
                headline=f"Named in threat intel: {(r.get('title') or '').rstrip('.')}.",
                detail=(r.get("summary") or "")[:240],
                source=r.get("source") or "CTI", link=r.get("url")))
        ransom = await db.ransomware_events.find_one({"cves": cve}, {"_id": 0})
        if ransom:
            out.append(_item(
                key="ransomware", weight="aggravating",
                headline=f"Associated with ransomware activity ({ransom.get('group')}).",
                source="ransomware.live", link=ransom.get("url")))
    if not out:
        out.append(_item(
            key="no_exploit_signal", weight="mitigating",
            headline="No public exploitation signal.",
            detail="Not in KEV, no threat-intel reporting, and no ransomware association on record.",
            source="KEV / EPSS / CTI"))
    return out


async def _identity_exposure(db, asset: dict) -> list:
    if not asset:
        return []
    users = await db.directory_users.find(
        {"primary_device_id": asset.get("intune_device_id")}, {"_id": 0}).to_list(20) \
        if asset.get("intune_device_id") else []
    privileged = [u for u in users if u.get("is_privileged") or u.get("admin_roles")]
    if privileged:
        return [_item(
            key="privileged_user", weight="aggravating",
            headline=(f"{len(privileged)} privileged account(s) use this as their primary device."),
            detail=("Compromising this machine puts those accounts' sessions and tokens within "
                     "reach: " + ", ".join(u.get("display_name") or u.get("user_principal_name")
                                            for u in privileged[:4])),
            source="Entra ID / Intune", link="/directory")]
    if users:
        return [_item(
            key="standard_user", weight="neutral",
            headline=f"{len(users)} standard (non-privileged) user(s) use this device.",
            source="Entra ID / Intune", link="/directory")]
    return []


async def _controls(db, asset: dict) -> list:
    """What is protecting this machine -- and what is not.

    The gaps matter more than the presences, and they are only knowable because
    identity resolution records WHICH systems have ever seen this asset. Before
    that, "no Defender data" was indistinguishable from "the name didn't match".
    """
    if not asset:
        return []
    import entity_resolution as er
    identity = await er.identity_of(db, asset["id"])
    seen = set(identity.get("sources") or [])
    out = []

    if "defender" in seen:
        risk = asset.get("defender_risk_score")
        out.append(_item(
            key="edr_present", weight="mitigating",
            headline=f"EDR is installed and reporting (Defender risk: {risk or 'unknown'}).",
            detail="Exploitation attempts have a chance of being detected and blocked.",
            source="Microsoft Defender", link=f"/assets/{asset['id']}"))
    else:
        out.append(_item(
            key="edr_missing", weight="aggravating",
            headline="No EDR has ever reported on this machine.",
            detail=("Nothing would detect exploitation of this vulnerability on this host. "
                     "This is a control gap in its own right, independent of the finding."),
            source="Identity coverage", link=f"/assets/{asset['id']}"))

    if "intune" in seen:
        state = asset.get("intune_compliance_state")
        out.append(_item(
            key="managed", weight="mitigating" if state == "compliant" else "aggravating",
            headline=f"Device management: {state or 'enrolled'}.",
            detail=("Patches can be pushed to this machine." if state == "compliant"
                     else "Enrolled but NOT compliant, so patch delivery is not assured."),
            source="Microsoft Intune", link=f"/patch-compliance"))
    else:
        out.append(_item(
            key="unmanaged", weight="aggravating",
            headline="Not enrolled in device management.",
            detail="There is no automated way to push the fix; remediation will be manual.",
            source="Identity coverage"))
    return out


async def _corroboration(db, finding: dict) -> list:
    import corroboration as corr
    if not finding.get("asset_id"):
        return []
    covering = await corr.tools_covering(db, finding["asset_id"])
    v = corr.assess(finding, tools_covering_asset=covering)
    weight = {"corroborated": "aggravating",
              "single_source_disputed": "mitigating"}.get(v["status"], "neutral")
    return [_item(
        key=f"corroboration_{v['status']}", weight=weight,
        headline={"corroborated": f"Confirmed independently by {v['source_count']} scanners.",
                   "single_source_disputed": "Only one scanner reports this; others that cover "
                                              "this asset did not.",
                   "single_source_uncorroborated": "Only one scanner covers this asset, so "
                                                    "nothing can corroborate this.",
                   }.get(v["status"], "Source attribution unclear."),
        detail=v["note"], source="Scanner corroboration",
        link=f"/findings/{finding.get('id')}", evidence={"tools": v["tools"]})]


async def _governance(db, finding: dict, asset: dict) -> list:
    out = []
    exc = await db.exceptions.find_one(
        {"status": "active",
         "$or": [{"finding_ids": finding.get("id")}, {"asset_ids": (asset or {}).get("id")}]},
        {"_id": 0})
    if exc:
        out.append(_item(
            key="exception", weight="mitigating",
            headline="An active risk exception covers this.",
            detail=(f"Approved by {exc.get('approved_by') or 'unknown'}"
                     + (f", expires {exc['expires_at'][:10]}" if exc.get("expires_at") else "")
                     + ". " + (exc.get("justification") or "")),
            source="Exceptions", link=f"/exceptions/{exc.get('id')}", evidence=exc))
    risks = await db.risk_register.find(
        {"status": {"$ne": "closed"},
         "$or": [{"linked_finding_ids": finding.get("id")},
                  {"linked_asset_ids": (asset or {}).get("id")}]},
        {"_id": 0}).to_list(5)
    for r in risks:
        out.append(_item(
            key="risk_register", weight="neutral",
            headline=f"Tracked on the risk register: {(r.get('title') or '').rstrip('.')}.",
            detail=f"Owner {r.get('owner') or 'unassigned'}, status {r.get('status')}.",
            source="Risk register", link=f"/risk-register/{r.get('id')}"))
    reviews = await db.security_reviews.find(
        {"linked_asset_ids": (asset or {}).get("id")},
        {"_id": 0, "id": 1, "title": 1, "decision": 1, "review_number": 1}).to_list(3)
    for rv in reviews:
        out.append(_item(
            key="security_review", weight="neutral",
            headline=(f"In scope of security review {rv.get('review_number')}: "
                       f"{(rv.get('title') or '').rstrip('.')}."),
            detail=f"Decision: {rv.get('decision') or 'pending'}.",
            source="Security reviews", link=f"/security-reviews/{rv.get('id')}"))
    return out


def _verdict(sections: dict) -> dict:
    """One paragraph a human can act on, built from the strongest claims.

    Not a score. The platform already has a risk score; what it was missing was
    the reasoning behind it, and a second number would not have supplied that.

    The distinction that drives this: some aggravating facts are properties of
    the VULNERABILITY (it is in KEV, threat actors are using it) and are true
    everywhere it is installed. Others are properties of THIS DEPLOYMENT (it is
    internet-facing, someone is scanning it, no EDR watches it). Only the second
    kind can make one instance more urgent than another, so only the second kind
    drives the headline -- otherwise every instance of a famous CVE reads as
    urgent, including the one sitting on an isolated lab box behind an approved
    exception, and the panel stops discriminating exactly where it is needed.
    """
    items = [i for group in sections.values() for i in group]
    agg = [i for i in items if i["weight"] == "aggravating"]
    mit = [i for i in items if i["weight"] == "mitigating"]

    # Environmental aggravators, strongest first.
    ENV_KEYS = ["active_attack_same_port", "active_attack", "attack_path", "internet_facing",
                "easm_confirmed", "privileged_user", "edr_missing", "unmanaged", "managed"]
    lead = [i for k in ENV_KEYS for i in agg if i["key"] == k]
    intrinsic = [i for i in agg if i not in lead]
    accepted = any(i["key"] == "exception" for i in mit)

    if accepted and not lead:
        headline = "Already accepted as a known risk."
        body = ("An approved exception covers this and nothing about where it sits contradicts "
                 "that decision. ")
    elif not lead:
        headline = "Low urgency in this environment."
        body = ("Nothing about this deployment raises it above its base severity: "
                 + ("; ".join(i["headline"].rstrip(".") for i in mit[:3])
                    or "no environmental aggravating factors found") + ". ")
    elif len(lead) >= 3:
        headline = "Act on this before other findings of the same severity."
        body = ("What makes it worse HERE: "
                 + "; ".join(i["headline"].rstrip(".") for i in lead[:4]) + ". ")
    else:
        headline = "Context raises the urgency of this finding."
        body = ("What makes it worse here: "
                 + "; ".join(i["headline"].rstrip(".") for i in lead[:3]) + ". ")

    if intrinsic:
        body += ("The vulnerability itself: "
                  + "; ".join(i["headline"].rstrip(".") for i in intrinsic[:3])
                  + " — true wherever it is installed, so it raises the base severity rather than "
                    "distinguishing this instance. ")
    if lead and mit:
        body += ("Offsetting that: "
                  + "; ".join(i["headline"].rstrip(".") for i in mit[:2]) + ". ")

    missing = [i for i in items if i["weight"] == "missing"]
    if missing:
        body += ("Note the gaps in what we could check: "
                  + "; ".join(i["headline"].rstrip(".") for i in missing[:2]) + ".")

    return {"headline": headline, "body": body.strip(),
            "environmental_aggravators": len(lead),
            "intrinsic_aggravators": len(intrinsic),
            "aggravating_count": len(agg), "mitigating_count": len(mit),
            "unknown_count": len(missing)}


async def build(db, finding: dict) -> dict:
    """The whole context panel for one finding."""
    asset = await db.assets.find_one({"id": finding.get("asset_id")}, {"_id": 0}) \
        if finding.get("asset_id") else None

    sections = {
        "reachability": await _reachability(db, finding, asset),
        "attack_path": await _attack_path(db, finding, asset),
        "active_attack": await _active_attack(db, finding, asset),
        "exploit_reality": await _exploit_reality(db, finding),
        "identity": await _identity_exposure(db, asset),
        "controls": await _controls(db, asset),
        "corroboration": await _corroboration(db, finding),
        "governance": await _governance(db, finding, asset),
    }
    return {
        "finding_id": finding.get("id"),
        "asset_id": (asset or {}).get("id"),
        "asset_hostname": (asset or {}).get("hostname"),
        "verdict": _verdict(sections),
        "sections": sections,
        "section_labels": {
            "reachability": "Can it be reached?",
            "attack_path": "Does it lead anywhere?",
            "active_attack": "Is anyone attacking it now?",
            "exploit_reality": "Is it actually being exploited?",
            "identity": "Who is on this machine?",
            "controls": "What is protecting it?",
            "corroboration": "How sure are we it's real?",
            "governance": "What have we already decided?",
        },
    }
