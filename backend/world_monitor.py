"""A global-events situational-awareness board, contextualized against YOUR estate.

The reference boards this is modelled on (Glint Terminal, Worldwatch, SitDeck and
the rest) are news tickers: a firehose of global security events with no idea
whether any of it touches you. That is exactly the gap this platform is built to
close. So this board is not a ticker -- it is every global event the platform
ALREADY pulls, each tagged with whether it intersects your findings, your
vendors, or your watchlist.

A KEV addition is interesting. A KEV addition for a CVE you have open on an
internet-facing host is an action item. A ransomware group is a headline. A
ransomware group that just hit a vendor you route payments through is a phone
call. The board's whole job is to tell those apart, and it can only do it because
the finding/vendor/watchlist data lives in the same system.

BUILT ENTIRELY FROM FEEDS ALREADY COLLECTED -- no new external dependency:

    cti_articles      RSS/news from the CTI feeds, with keyword matches
    kev_catalog       CISA KEV additions
    cti_ransomware    ransomware.live victims (carries a country)
    security_events   the platform's own detections
    correlation_hits  cross-signal incidents this platform raised
    osint_findings    recon / OSINT hits

Every event is normalized to one shape so the board can order, filter and score
them together, and each carries a `relevance` -- 'affects_us' / 'watched' /
'global' -- which is the only field that makes this worth looking at.
"""
from datetime import datetime, timezone, timedelta

CATEGORIES = {
    "kev": "Known-Exploited Vulnerability",
    "ransomware": "Ransomware Activity",
    "news": "Threat Intel / News",
    "detection": "Our Detections",
    "incident": "Correlated Incidents",
    "osint": "OSINT",
}

# Relevance, strongest first. This is the axis the board sorts and colours on.
AFFECTS_US = "affects_us"      # intersects an open finding / a vendor we use / our own env
WATCHED = "watched"           # matches a watchlist keyword or a tracked entity
GLOBAL = "global"             # happening in the world, no established link to us
RELEVANCE_RANK = {AFFECTS_US: 0, WATCHED: 1, GLOBAL: 2}

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _now():
    return datetime.now(timezone.utc)


def _iso(dt=None):
    return (dt or _now()).isoformat()


def _parse(ts):
    """Parse a timestamp to an ALWAYS-timezone-aware datetime (assume UTC if the
    stored value has none).

    This is load-bearing: the sources have mixed formats -- KEV's date_added is
    date-only ('2026-08-01', which parses NAIVE) while CTI timestamps carry an
    offset (aware). Sorting a mix of naive and aware datetimes raises
    'can't compare offset-naive and offset-aware', which 500'd the whole board.
    Normalizing every parsed value to aware makes them comparable.
    """
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        # Also accept a bare date like '2026-08-01'.
        try:
            dt = datetime.strptime(str(ts)[:10], "%Y-%m-%d")
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _event(*, id, when, category, severity, title, summary="", source="",
           link=None, relevance=GLOBAL, why="", country=None, entities=None):
    return {
        "id": id, "when": when, "category": category,
        "category_label": CATEGORIES.get(category, category),
        "severity": severity, "title": title, "summary": (summary or "")[:400],
        "source": source, "link": link,
        "relevance": relevance, "why": why,     # why it's relevant, in words
        "country": country, "entities": entities or [],
    }


# ---------------------------------------------------------------------------
# Building the picture of "us" once, so each event can be checked cheaply.
# ---------------------------------------------------------------------------
async def _our_context(db):
    open_cves = set()
    async for f in db.findings.find(
            {"status": {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]},
             "cve": {"$ne": None}},
            {"_id": 0, "cve": 1, "internet_facing": 1}):
        if f.get("cve"):
            open_cves.add(f["cve"].upper())

    exposed_cves = set()
    async for f in db.findings.find(
            {"status": {"$in": ["New", "Valid", "Reopened"]}, "internet_facing": True,
             "cve": {"$ne": None}}, {"_id": 0, "cve": 1}):
        if f.get("cve"):
            exposed_cves.add(f["cve"].upper())

    vendor_names = set()
    async for v in db.vendors.find({}, {"_id": 0, "name": 1}):
        if v.get("name"):
            vendor_names.add(v["name"].lower())

    watch_terms = set()
    async for k in db.cti_keywords.find({}, {"_id": 0, "term": 1, "keyword": 1}):
        term = (k.get("term") or k.get("keyword") or "").lower().strip()
        if term:
            watch_terms.add(term)

    return {"open_cves": open_cves, "exposed_cves": exposed_cves,
            "vendor_names": vendor_names, "watch_terms": watch_terms}


def _vendor_hit(text, vendor_names):
    low = (text or "").lower()
    return next((v for v in vendor_names if v and len(v) > 3 and v in low), None)


def _term_hit(text, terms):
    low = (text or "").lower()
    return next((t for t in terms if t and t in low), None)


# ---------------------------------------------------------------------------
# One collector per source. Each returns normalized events.
# ---------------------------------------------------------------------------
async def _kev_events(db, ctx, since):
    out = []
    for k in await db.kev_catalog.find(
            {"date_added": {"$gte": since[:10]}}, {"_id": 0}).sort("date_added", -1).to_list(200):
        cve = (k.get("cve_id") or "").upper()
        affects = cve in ctx["open_cves"]
        exposed = cve in ctx["exposed_cves"]
        rel = AFFECTS_US if affects else GLOBAL
        why = ""
        if exposed:
            why = f"You have {cve} open on an INTERNET-FACING asset — this is now confirmed exploited."
        elif affects:
            why = f"You have {cve} open in your environment — CISA now lists it as actively exploited."
        out.append(_event(
            id=f"kev:{cve}", when=k.get("date_added"), category="kev",
            severity="Critical" if exposed else ("High" if affects else "Medium"),
            title=f"CISA added {cve} to the KEV catalogue"
                  + (f" — {k.get('name')}" if k.get("name") else ""),
            summary=f"{k.get('vendor','')} {k.get('product','')}: {k.get('required_action','')}".strip(),
            source="CISA KEV", link=f"https://nvd.nist.gov/vuln/detail/{cve}",
            relevance=rel, why=why, entities=[cve]))
    return out


async def _ransomware_events(db, ctx, since):
    out = []
    for coll in ("cti_ransomware", "ransomware_events"):
        for r in await db[coll].find({}, {"_id": 0}).sort("discovered", -1).to_list(200):
            when = r.get("discovered") or r.get("published") or r.get("date") or r.get("attackdate")
            if _parse(when) and _parse(when) < _parse(since):
                continue
            victim = r.get("victim") or r.get("post_title") or r.get("name") or "an organization"
            group = r.get("group") or r.get("group_name") or "a ransomware group"
            vendor = _vendor_hit(victim, ctx["vendor_names"])
            rel = AFFECTS_US if vendor else GLOBAL
            why = (f"'{victim}' matches a vendor you use — a supplier compromise is your incident too."
                   if vendor else "")
            out.append(_event(
                id=f"ransom:{coll}:{r.get('id') or victim}", when=when, category="ransomware",
                severity="High" if vendor else "Medium",
                title=f"{group} claimed {victim}",
                summary=r.get("description") or r.get("summary") or "",
                source="ransomware.live", link=r.get("url") or r.get("link"),
                relevance=rel, why=why, country=r.get("country"),
                entities=[group, victim]))
    return out


async def _news_events(db, ctx, since):
    out = []
    for a in await db.cti_articles.find(
            {}, {"_id": 0}).sort("published_at", -1).to_list(300):
        when = a.get("published_at") or a.get("fetched_at")
        if _parse(when) and _parse(when) < _parse(since):
            continue
        text = f"{a.get('title','')} {a.get('summary','')}"
        matches = a.get("matches") or []
        term = _term_hit(text, ctx["watch_terms"])
        vendor = _vendor_hit(text, ctx["vendor_names"])
        if vendor:
            rel, why = AFFECTS_US, f"Mentions '{vendor}', a vendor you use."
        elif matches or term:
            rel = WATCHED
            m = matches[0].get("term") if matches else term
            why = f"Matches a term on your CTI watchlist: '{m}'."
        else:
            rel, why = GLOBAL, ""
        out.append(_event(
            id=f"news:{a.get('id')}", when=when, category="news",
            severity="Medium" if rel != GLOBAL else "Info",
            title=a.get("title") or "(untitled)", summary=a.get("summary") or "",
            source=a.get("source") or "CTI feed", link=a.get("link"),
            relevance=rel, why=why,
            entities=[m.get("term") for m in matches if m.get("term")]))
    return out


async def _detection_events(db, ctx, since):
    out = []
    for e in await db.security_events.find(
            {"status": "open", "last_seen_at": {"$gte": since}}, {"_id": 0}
    ).sort("last_seen_at", -1).to_list(200):
        # Our own detections are always about us.
        out.append(_event(
            id=f"det:{e.get('id')}", when=e.get("last_seen_at") or e.get("created_at"),
            category="detection", severity=e.get("severity") or "Medium",
            title=e.get("title") or e.get("event_type") or "Security event",
            summary=e.get("description") or "", source=e.get("source") or "Detection",
            relevance=AFFECTS_US,
            why="Raised by your own detection pipeline.",
            entities=[e.get("entity_label")] if e.get("entity_label") else []))
    return out


async def _incident_events(db, ctx, since):
    out = []
    for h in await db.correlation_hits.find(
            {"status": "open", "last_seen_at": {"$gte": since}}, {"_id": 0}
    ).sort("last_seen_at", -1).to_list(100):
        out.append(_event(
            id=f"corr:{h.get('id')}", when=h.get("last_seen_at") or h.get("detected_at"),
            category="incident", severity=h.get("severity") or "High",
            title=h.get("rule_title") or "Correlated incident",
            summary=h.get("narrative") or "", source="Correlation engine",
            relevance=AFFECTS_US,
            why="A cross-signal condition the platform correlated in your environment.",
            entities=[(h.get("subject") or {}).get("label")] if h.get("subject") else []))
    return out


COLLECTORS = {
    "kev": _kev_events,
    "ransomware": _ransomware_events,
    "news": _news_events,
    "detection": _detection_events,
    "incident": _incident_events,
}


async def board(db, *, days: int = 7, categories=None, relevance=None, limit: int = 200):
    """The unified, time-ordered situational board.

    `relevance='affects_us'` collapses the firehose to only what touches you --
    which is the view an operator actually wants on a busy day.
    """
    since = _iso(_now() - timedelta(days=days))
    ctx = await _our_context(db)

    want = set(categories) if categories else set(COLLECTORS)
    events = []
    for name, collect in COLLECTORS.items():
        if name in want:
            try:
                events.extend(await collect(db, ctx, since))
            except Exception:
                # A single source failing must not blank the whole board -- the
                # point of an aggregator is resilience to any one feed.
                continue

    if relevance:
        events = [e for e in events if e["relevance"] == relevance]

    # Sort: relevance to us first, then severity, then recency. A Critical KEV
    # that affects us outranks a fresher but purely-global headline.
    def key(e):
        return (RELEVANCE_RANK.get(e["relevance"], 3),
                -SEVERITY_RANK.get(e["severity"], 0),
                _parse(e["when"]) or datetime.min.replace(tzinfo=timezone.utc))
    events.sort(key=lambda e: (key(e)[0], key(e)[1]))
    events.sort(key=lambda e: _parse(e["when"]) or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True)
    events.sort(key=lambda e: (RELEVANCE_RANK.get(e["relevance"], 3),
                                -SEVERITY_RANK.get(e["severity"], 0)))

    events = events[:limit]

    counts = {"affects_us": 0, "watched": 0, "global": 0}
    by_category = {}
    countries = {}
    for e in events:
        counts[e["relevance"]] = counts.get(e["relevance"], 0) + 1
        by_category[e["category"]] = by_category.get(e["category"], 0) + 1
        if e.get("country"):
            countries[e["country"]] = countries.get(e["country"], 0) + 1

    top = [e for e in events if e["relevance"] == AFFECTS_US][:5]
    return {
        "window_days": days,
        "generated_at": _iso(),
        "events": events,
        "counts": counts,
        "by_category": by_category,
        "countries": [{"country": c, "count": n}
                       for c, n in sorted(countries.items(), key=lambda x: -x[1])],
        "headline": _headline(counts, top),
        "priority": top,
    }


def _headline(counts, top):
    if counts["affects_us"] == 0:
        return ("Nothing in the last window is linked to your environment. "
                f"{counts['watched']} watched, {counts['global']} global events.")
    lead = top[0]["title"] if top else ""
    return (f"{counts['affects_us']} event(s) touch your environment"
            + (f" — top: {lead}" if lead else "") + ".")
