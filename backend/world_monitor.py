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


# ---------------------------------------------------------------------------
# Item 51 (PYTHIA, situational-awareness half): give each event that carries a
# country a coarse map location, so the board can drive a global activity map /
# globe. This is the ONLY half of PYTHIA folded in here, and it is built from the
# country data the feeds ALREADY carry (e.g. ransomware.live victims) -- no new
# external dependency, same principle as the rest of this board. The AI-forecasting
# half is deliberately NOT here; it is walled off in geo_forecast.py as an
# off-by-default experiment and must never be rendered next to this real data.
#
# Centroids are approximate country centers, only precise enough to place a dot on
# a world map. Accepts ISO-3166 alpha-2 codes and common country names.
COUNTRY_CENTROIDS = {
    "US": (39.8, -98.6), "USA": (39.8, -98.6), "UNITED STATES": (39.8, -98.6),
    "CA": (56.1, -106.3), "CANADA": (56.1, -106.3),
    "MX": (23.6, -102.5), "MEXICO": (23.6, -102.5),
    "BR": (-14.2, -51.9), "BRAZIL": (-14.2, -51.9),
    "GB": (54.0, -2.0), "UK": (54.0, -2.0), "UNITED KINGDOM": (54.0, -2.0),
    "FR": (46.2, 2.2), "FRANCE": (46.2, 2.2),
    "DE": (51.2, 10.4), "GERMANY": (51.2, 10.4),
    "ES": (40.5, -3.7), "SPAIN": (40.5, -3.7),
    "IT": (41.9, 12.6), "ITALY": (41.9, 12.6),
    "NL": (52.1, 5.3), "NETHERLANDS": (52.1, 5.3),
    "SE": (60.1, 18.6), "SWEDEN": (60.1, 18.6),
    "NO": (60.5, 8.5), "NORWAY": (60.5, 8.5),
    "PL": (51.9, 19.1), "POLAND": (51.9, 19.1),
    "UA": (48.4, 31.2), "UKRAINE": (48.4, 31.2),
    "RU": (61.5, 105.3), "RUSSIA": (61.5, 105.3),
    "TR": (38.9, 35.2), "TURKEY": (38.9, 35.2),
    "IL": (31.0, 34.9), "ISRAEL": (31.0, 34.9),
    "SA": (23.9, 45.1), "SAUDI ARABIA": (23.9, 45.1),
    "AE": (23.4, 53.8), "UAE": (23.4, 53.8),
    "IN": (22.6, 78.9), "INDIA": (22.6, 78.9),
    "CN": (35.9, 104.2), "CHINA": (35.9, 104.2),
    "JP": (36.2, 138.3), "JAPAN": (36.2, 138.3),
    "KR": (35.9, 127.8), "SOUTH KOREA": (35.9, 127.8),
    "KP": (40.3, 127.5), "NORTH KOREA": (40.3, 127.5),
    "AU": (-25.3, 133.8), "AUSTRALIA": (-25.3, 133.8),
    "NZ": (-41.8, 172.0), "NEW ZEALAND": (-41.8, 172.0),
    "ZA": (-30.6, 22.9), "SOUTH AFRICA": (-30.6, 22.9),
    "NG": (9.1, 8.7), "NIGERIA": (9.1, 8.7),
    "EG": (26.8, 30.8), "EGYPT": (26.8, 30.8),
    "AR": (-38.4, -63.6), "ARGENTINA": (-38.4, -63.6),
    "CL": (-35.7, -71.5), "CHILE": (-35.7, -71.5),
    "CO": (4.6, -74.3), "COLOMBIA": (4.6, -74.3),
    "SG": (1.35, 103.8), "SINGAPORE": (1.35, 103.8),
    "TW": (23.7, 121.0), "TAIWAN": (23.7, 121.0),
    "ID": (-0.8, 113.9), "INDONESIA": (-0.8, 113.9),
    "TH": (15.9, 100.9), "THAILAND": (15.9, 100.9),
    "VN": (14.1, 108.3), "VIETNAM": (14.1, 108.3),
    "IE": (53.4, -8.2), "IRELAND": (53.4, -8.2),
    "CH": (46.8, 8.2), "SWITZERLAND": (46.8, 8.2),
    "BE": (50.5, 4.5), "BELGIUM": (50.5, 4.5),
}


def geo_for(country):
    """Coarse map location for a country name/ISO2 code, or None if unknown."""
    if not country:
        return None
    key = str(country).strip().upper()
    latlon = COUNTRY_CENTROIDS.get(key)
    if not latlon:
        return None
    return {"country": country, "lat": latlon[0], "lon": latlon[1]}


def _event(*, id, when, category, severity, title, summary="", source="",
           link=None, relevance=GLOBAL, why="", country=None, entities=None):
    return {
        "id": id, "when": when, "category": category,
        "category_label": CATEGORIES.get(category, category),
        "severity": severity, "title": title, "summary": (summary or "")[:400],
        "source": source, "link": link,
        "relevance": relevance, "why": why,     # why it's relevant, in words
        "country": country, "geo": geo_for(country), "entities": entities or [],
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
    map_agg = {}   # country -> {lat, lon, count, affects_us}
    for e in events:
        counts[e["relevance"]] = counts.get(e["relevance"], 0) + 1
        by_category[e["category"]] = by_category.get(e["category"], 0) + 1
        if e.get("country"):
            countries[e["country"]] = countries.get(e["country"], 0) + 1
        g = e.get("geo")
        if g:
            slot = map_agg.setdefault(g["country"], {"country": g["country"], "lat": g["lat"],
                                                     "lon": g["lon"], "count": 0, "affects_us": 0})
            slot["count"] += 1
            if e["relevance"] == AFFECTS_US:
                slot["affects_us"] += 1

    top = [e for e in events if e["relevance"] == AFFECTS_US][:5]
    return {
        "window_days": days,
        "generated_at": _iso(),
        "events": events,
        "counts": counts,
        "by_category": by_category,
        "countries": [{"country": c, "count": n}
                       for c, n in sorted(countries.items(), key=lambda x: -x[1])],
        # Item 51: located events for the global activity map (situational
        # awareness only -- these are real observed events, never forecasts).
        "map_points": sorted(map_agg.values(), key=lambda m: -m["count"]),
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
