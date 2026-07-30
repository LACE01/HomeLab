"""CTI / OSINT additions layered onto the existing Compromise Monitoring & OSINT
area rather than shipped as standalone tools (per the task's general principle:
automate and reuse existing platform data).

What's here and what each one reuses:

  custom RSS/website monitoring   -- extends security_news.py's feed parser to
                                     user-added feeds (db.cti_feeds), with
                                     keyword watchlists that raise a security
                                     event when an article matches something we
                                     own (owned domain, vendor name, or an
                                     analyst-supplied keyword).
  ransomware.live                 -- pulls recent ransomware victim postings and
                                     matches them against tracked vendors and
                                     owned domains; a match fires the existing
                                     vendor_compromise_found / a new
                                     ransomware_victim_match event.
  CISA KEV reporting              -- enrichers.sync_kev already flags findings;
                                     this adds the REPORTING view (which KEV
                                     CVEs are actually present in our
                                     environment, on which assets, with due
                                     dates from the KEV catalog).
  certificate transparency        -- monitors crt.sh per owned domain and flags
                                     NEWLY-seen certificates (a cert issued for
                                     your domain that you didn't request is a
                                     real signal), feeding hostnames into the
                                     same easm_candidates queue the EASM page
                                     already reads.
  Shodan enrichment               -- shodan_sync.py already enriches asset IPs;
                                     this surfaces the aggregate exposure view
                                     (open ports/services/vulns across owned
                                     assets) in the hub.
  domain monitoring / discovery   -- the CT sweep above doubles as asset
                                     discovery; new hostnames land in
                                     easm_candidates.
  ad-hoc investigation            -- one submit, every configured source
                                     (OpenCTI/GreyNoise/OTX/abuse.ch/VirusTotal,
                                     plus KEV/watchlist/internal-inventory
                                     checks) run against a domain/URL/IP/hash.
  typosquat detection             -- generates plausible lookalikes of owned
                                     domains and checks which actually resolve
                                     (registered), which is the signal that
                                     matters -- a permutation nobody registered
                                     isn't a threat.

Everything writes through existing collections/events where one already exists
(easm_candidates, security_events, osint_findings) instead of inventing a
parallel store.
"""
import asyncio
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

RANSOMWARE_LIVE_BASE = "https://api.ransomware.live"
CRTSH_URL = "https://crt.sh/"

# Keyboard-adjacency and common-confusion substitutions used for typosquat
# permutation generation. Deliberately a focused set (the classic high-yield
# families) rather than an exhaustive dnstwist clone -- every extra permutation
# is another DNS lookup, and these cover what actually gets registered.
_HOMOGLYPHS = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["l", "1"], "1": ["l", "i"],
               "e": ["3"], "a": ["4"], "s": ["5", "z"], "m": ["rn"], "n": ["m"],
               "b": ["6"], "g": ["9", "q"], "c": ["k"], "k": ["c"]}
_TLD_SWAPS = ["com", "net", "org", "co", "io", "info", "biz", "us", "online", "site"]
_PREFIX_SUFFIX = ["secure", "login", "mail", "portal", "support", "account", "verify", "my"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def owned_domains(db) -> list:
    """The registry of domains we own -- reuses db.domain_watch_targets (the same
    list the SPF/DKIM/DMARC monitoring already watches) so there's one place to
    add a domain, not four."""
    targets = await db.domain_watch_targets.find({}, {"_id": 0, "domain": 1}).to_list(500)
    return sorted({(t.get("domain") or "").strip().lower() for t in targets if t.get("domain")})


# =========================================================================
# Custom RSS / website monitoring
# =========================================================================

async def sync_cti_feeds(db) -> dict:
    """Fetch every user-added feed in db.cti_feeds, upsert articles into
    db.cti_articles (dedup by link), and raise a security event for any article
    matching a keyword watchlist entry, an owned domain, or a tracked vendor
    name. Best-effort per feed -- one dead feed never blocks the rest."""
    import httpx
    from security_news import _parse_feed

    feeds = await db.cti_feeds.find({"enabled": True}, {"_id": 0}).to_list(200)
    domains = await owned_domains(db)
    vendors = await db.vendors.find({}, {"_id": 0, "id": 1, "name": 1}).to_list(500)
    keywords = await db.cti_keywords.find({}, {"_id": 0, "keyword": 1}).to_list(200)
    terms = [(k["keyword"].lower(), "keyword", k["keyword"]) for k in keywords]
    terms += [(d.lower(), "owned_domain", d) for d in domains]
    terms += [(v["name"].lower(), "vendor", v["name"]) for v in vendors if len(v.get("name", "")) >= 4]

    created, matched, errors = 0, 0, []
    for feed in feeds:
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                          headers={"User-Agent": "Nightwatch-CTI/1.0 (self-hosted security platform)"}) as c:
                r = await c.get(feed["url"])
            if r.status_code != 200:
                errors.append(f"{feed['name']}: HTTP {r.status_code}")
                continue
            articles = _parse_feed(feed["name"], r.content)
        except Exception as e:
            errors.append(f"{feed['name']}: {type(e).__name__}")
            continue

        for a in articles:
            link = a.get("link")
            if not link:
                continue
            if await db.cti_articles.find_one({"link": link}, {"_id": 0, "id": 1}):
                continue
            haystack = f"{a.get('title', '')} {a.get('summary', '')}".lower()
            hits = [{"term": label, "kind": kind} for needle, kind, label in terms if needle in haystack]
            doc = {
                "id": str(uuid.uuid4()), "feed_id": feed["id"], "source": feed["name"],
                "title": a.get("title"), "link": link, "summary": a.get("summary"),
                "published_at": a.get("published_at"), "fetched_at": _now_iso(),
                "matches": hits,
            }
            await db.cti_articles.insert_one(doc)
            created += 1
            if hits:
                matched += 1
                from security_events import emit_event
                await emit_event(
                    db, source="cti", event_type="threat_news_match", severity="Medium",
                    title=f"Threat news mentions {hits[0]['term']}: {a.get('title', '')[:90]}",
                    entity_type="feed_article", entity_id=doc["id"], entity_label=feed["name"],
                    description=f"{feed['name']} published an article matching {', '.join(h['term'] for h in hits)}. {link}",
                    raw={"link": link, "matches": hits},
                )
        await db.cti_feeds.update_one({"id": feed["id"]}, {"$set": {"last_synced_at": _now_iso()}})

    # prune old articles -- the feed is a rolling window, not an archive
    cutoff = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
    await db.cti_articles.delete_many({"fetched_at": {"$lt": cutoff}, "matches": []})
    return {"ok": True, "feeds": len(feeds), "articles_created": created,
            "articles_matched": matched, "errors": errors}


# =========================================================================
# ransomware.live
# =========================================================================

async def sync_opencti_reports(db, limit: int = 100) -> dict:
    """Pull OpenCTI's own Reports (its analyst-written and feed-ingested
    intelligence articles) into the same Threat News stream as the RSS feeds.

    An OpenCTI instance is usually the richest source an org already has -- it
    aggregates the feeds it's connected to plus whatever its analysts write --
    so treating it as one more "feed" here means the keyword/domain/vendor
    matching, alerting and drill-down all work identically to the RSS path
    instead of living in a separate silo. Reuses the endpoint/api_key (+ optional
    CF-Access tokens) already configured under Integrations -> OpenCTI."""
    import httpx
    integration = await db.integrations.find_one({"name": "OpenCTI"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint, api_key = cfg.get("endpoint"), cfg.get("api_key")
    if not endpoint or not api_key:
        raise ValueError("OpenCTI isn't configured yet -- add endpoint + api_key under "
                          "Integrations -> OpenCTI first.")

    query = (
        "query($first: Int) { reports(first: $first, orderBy: published, orderMode: desc) { "
        "edges { node { id name description published createdBy { ... on Identity { name } } "
        "objectLabel { value } externalReferences { edges { node { url source_name } } } } } } }"
    )
    from cf_diagnostics import classify_response, classify_exception, summary_line
    import opencti_client
    # URL + headers come from the shared client so every OpenCTI caller talks to
    # the same path -- Test Connection passing while syncs 404 was exactly this.
    headers = opencti_client.headers({**cfg, "api_key": api_key})
    token_sent = opencti_client.token_sent(cfg)

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as c:
            r = await c.post(opencti_client.graphql_url(endpoint), headers=headers,
                              json={"query": query, "variables": {"first": limit}})
    except httpx.HTTPError as e:
        raise RuntimeError(summary_line(classify_exception(e, service_name="OpenCTI")))
    # Name the layer that refused us instead of pasting a Cloudflare HTML page
    # into the error -- "Just a moment..." means the CDN edge blocked this before
    # Access or OpenCTI ever saw it, which is a completely different fix.
    verdict = classify_response(r, service_name="OpenCTI", token_sent=token_sent,
                                 client_id=cfg.get("cf_access_client_id"))
    if not verdict["ok"]:
        raise RuntimeError(summary_line(verdict))
    data = r.json()
    if data.get("errors"):
        raise RuntimeError(f"OpenCTI GraphQL error: {data['errors'][0].get('message', data['errors'])}")

    edges = ((data.get("data") or {}).get("reports") or {}).get("edges") or []
    domains = await owned_domains(db)
    vendors = await db.vendors.find({}, {"_id": 0, "id": 1, "name": 1}).to_list(500)
    keywords = await db.cti_keywords.find({}, {"_id": 0, "keyword": 1}).to_list(200)
    terms = [(k["keyword"].lower(), "keyword", k["keyword"]) for k in keywords]
    terms += [(d.lower(), "owned_domain", d) for d in domains]
    terms += [(v["name"].lower(), "vendor", v["name"]) for v in vendors if len(v.get("name", "")) >= 4]

    created, matched = 0, 0
    for e in edges:
        node = e.get("node") or {}
        title = node.get("name")
        if not title:
            continue
        refs = [(x.get("node") or {}) for x in ((node.get("externalReferences") or {}).get("edges") or [])]
        link = next((x.get("url") for x in refs if x.get("url")),
                    f"{endpoint.rstrip('/')}/dashboard/analyses/reports/{node.get('id')}")
        if await db.cti_articles.find_one({"link": link}, {"_id": 0, "id": 1}):
            continue
        summary_text = (node.get("description") or "")[:2000]
        haystack = f"{title} {summary_text}".lower()
        hits = [{"term": label, "kind": kind} for needle, kind, label in terms if needle in haystack]
        author = ((node.get("createdBy") or {}) or {}).get("name")
        labels = [l.get("value") for l in (node.get("objectLabel") or []) if l.get("value")]
        doc = {
            "id": str(uuid.uuid4()), "feed_id": "opencti", "source": "OpenCTI"
            + (f" · {author}" if author else ""),
            "title": title, "link": link, "summary": summary_text,
            "published_at": node.get("published"), "fetched_at": _now_iso(),
            "matches": hits, "labels": labels, "opencti_report_id": node.get("id"),
        }
        await db.cti_articles.insert_one(doc)
        created += 1
        if hits:
            matched += 1
            from security_events import emit_event
            await emit_event(
                db, source="cti", event_type="threat_news_match", severity="Medium",
                title=f"OpenCTI report mentions {hits[0]['term']}: {title[:90]}",
                entity_type="feed_article", entity_id=doc["id"], entity_label="OpenCTI",
                description=f"An OpenCTI report matched {', '.join(h['term'] for h in hits)}. {link}",
                raw={"link": link, "matches": hits, "opencti_report_id": node.get("id")},
            )
    return {"ok": True, "reports_seen": len(edges), "articles_created": created,
            "articles_matched": matched}


async def sync_ransomware_live(db, limit: int = 200) -> dict:
    """Pull recent ransomware victim postings and match them against tracked
    vendors and owned domains. Public API, no key required. A match is a real
    "your third party is on a leak site" signal, so it emits an event."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
            r = await c.get(f"{RANSOMWARE_LIVE_BASE}/recentvictims")
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach ransomware.live: {e}")
    if r.status_code != 200:
        raise RuntimeError(f"ransomware.live HTTP {r.status_code}")
    victims = r.json()
    if not isinstance(victims, list):
        return {"ok": True, "seen": 0, "created": 0, "matched": 0}
    victims = victims[:limit]

    domains = set(await owned_domains(db))
    vendors = await db.vendors.find({}, {"_id": 0, "id": 1, "name": 1, "domain": 1}).to_list(500)
    vendor_by_domain = {(v.get("domain") or "").lower(): v for v in vendors if v.get("domain")}
    vendor_by_name = {v["name"].lower(): v for v in vendors if v.get("name")}

    created, matched = 0, 0
    for v in victims:
        name = (v.get("post_title") or v.get("victim") or "").strip()
        if not name:
            continue
        vdomain = (v.get("website") or v.get("domain") or "").strip().lower()
        vdomain = re.sub(r"^https?://", "", vdomain).split("/")[0]
        key = f"{v.get('group_name', '?')}:{name}"
        if await db.cti_ransomware_victims.find_one({"key": key}, {"_id": 0, "id": 1}):
            continue

        match = None
        if vdomain and vdomain in domains:
            match = {"kind": "owned_domain", "label": vdomain}
        elif vdomain and vdomain in vendor_by_domain:
            match = {"kind": "vendor", "label": vendor_by_domain[vdomain]["name"],
                     "vendor_id": vendor_by_domain[vdomain]["id"]}
        elif name.lower() in vendor_by_name:
            match = {"kind": "vendor", "label": vendor_by_name[name.lower()]["name"],
                     "vendor_id": vendor_by_name[name.lower()]["id"]}

        doc = {
            "id": str(uuid.uuid4()), "key": key, "victim": name, "victim_domain": vdomain or None,
            "group": v.get("group_name"), "discovered": v.get("discovered") or v.get("published"),
            "description": (v.get("description") or "")[:1000],
            "post_url": v.get("post_url") or v.get("screenshot"),
            "match": match, "fetched_at": _now_iso(),
        }
        await db.cti_ransomware_victims.insert_one(doc)
        created += 1
        if match:
            matched += 1
            from security_events import emit_event
            await emit_event(
                db, source="cti", event_type="ransomware_victim_match",
                severity="Critical" if match["kind"] == "owned_domain" else "High",
                title=f"Ransomware leak site lists {match['label']} ({doc['group']})",
                entity_type=match["kind"], entity_id=match.get("vendor_id") or match["label"],
                entity_label=match["label"],
                description=f"{doc['group']} posted \"{name}\" on their leak site"
                            + (f" ({vdomain})" if vdomain else "")
                            + f". Matched our {match['kind'].replace('_', ' ')}.",
                raw={"victim": name, "group": doc["group"], "post_url": doc["post_url"]},
            )
    return {"ok": True, "seen": len(victims), "created": created, "matched": matched}


# =========================================================================
# CISA KEV reporting (the catalog is already synced by enrichers.sync_kev)
# =========================================================================

async def kev_report(db) -> dict:
    """Which KEV CVEs are actually present in OUR environment -- the reporting
    layer over the kev_catalog + findings that enrichers.sync_kev already
    maintains. Sorted by KEV due date (CISA's remediation deadline) because
    that's the thing with an actual clock on it."""
    OPEN = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]
    catalog = await db.kev_catalog.find({}, {"_id": 0}).to_list(5000)
    by_cve = {c.get("cveID"): c for c in catalog if c.get("cveID")}
    findings = await db.findings.find(
        {"kev_flag": True, "status": {"$in": OPEN}},
        {"_id": 0, "id": 1, "cve": 1, "asset_id": 1, "asset_hostname": 1, "severity": 1,
         "title": 1, "due_at": 1, "status": 1},
    ).to_list(5000)

    grouped: dict = {}
    for f in findings:
        cve = f.get("cve")
        if not cve:
            continue
        g = grouped.setdefault(cve, {
            "cve": cve, "findings": [], "assets": set(),
            "vendor_project": (by_cve.get(cve) or {}).get("vendorProject"),
            "product": (by_cve.get(cve) or {}).get("product"),
            "vulnerability_name": (by_cve.get(cve) or {}).get("vulnerabilityName"),
            "kev_due_date": (by_cve.get(cve) or {}).get("dueDate"),
            "known_ransomware": (by_cve.get(cve) or {}).get("knownRansomwareCampaignUse"),
            "required_action": (by_cve.get(cve) or {}).get("requiredAction"),
        })
        g["findings"].append({"id": f["id"], "asset_hostname": f.get("asset_hostname"),
                              "severity": f.get("severity"), "status": f.get("status"),
                              "due_at": f.get("due_at")})
        if f.get("asset_id"):
            g["assets"].add(f["asset_id"])
    items = []
    for g in grouped.values():
        g["asset_count"] = len(g["assets"])
        g["finding_count"] = len(g["findings"])
        del g["assets"]
        items.append(g)
    items.sort(key=lambda x: (x.get("kev_due_date") or "9999", -x["finding_count"]))
    today = datetime.now(timezone.utc).date().isoformat()
    return {
        "catalog_size": len(catalog),
        "kev_in_environment": len(items),
        "open_kev_findings": len(findings),
        "past_kev_due_date": len([i for i in items if (i.get("kev_due_date") or "9999") < today]),
        "ransomware_linked": len([i for i in items if str(i.get("known_ransomware", "")).lower() == "known"]),
        "items": items,
    }


# =========================================================================
# Certificate Transparency monitoring
# =========================================================================

async def _crtsh_certs(domain: str) -> list:
    """Item 35: delegates to the shared ct_service (retry/backoff, certspotter
    fallback, empty-is-clean, full error text) instead of a second bespoke
    crt.sh client."""
    from ct_service import fetch_certificates
    return await fetch_certificates(domain)


async def sync_ct_logs(db, domain: Optional[str] = None) -> dict:
    """Sweep crt.sh for each owned domain. NEW certificates (crt.sh entry ids we
    haven't recorded) are the signal -- a certificate issued for your domain that
    you didn't request is worth a human look. Also feeds every discovered
    hostname into the existing easm_candidates queue (this is the "domain
    monitoring for asset discovery" half)."""
    domains = [domain.lower()] if domain else await owned_domains(db)
    if not domains:
        return {"ok": True, "domains": 0, "new_certs": 0, "new_hostnames": 0,
                "note": "No owned domains registered -- add them under Email Auth monitoring."}

    new_certs, new_hosts, errors = 0, 0, []
    for dom in domains:
        try:
            certs = await _crtsh_certs(dom)
        except Exception as e:
            errors.append(f"{dom}: {e}")
            continue
        first_sweep = await db.cti_certificates.count_documents({"domain": dom}) == 0
        for c in certs[:500]:
            crt_id = str(c.get("id") or "")
            if not crt_id:
                continue
            if await db.cti_certificates.find_one({"crt_id": crt_id}, {"_id": 0, "id": 1}):
                continue
            names = [n.strip().lower() for n in (c.get("name_value") or "").split("\n") if n.strip()]
            doc = {
                "id": str(uuid.uuid4()), "crt_id": crt_id, "domain": dom,
                "common_name": c.get("common_name"), "names": names,
                "issuer": c.get("issuer_name"), "not_before": c.get("not_before"),
                "not_after": c.get("not_after"),
                "first_seen_at": _now_iso(),
                # On the very first sweep everything is "new" to us but not new in
                # the world -- flag only subsequent discoveries as newly issued, so
                # the first run doesn't fire hundreds of pointless alerts.
                "newly_issued": not first_sweep,
            }
            await db.cti_certificates.insert_one(doc)
            new_certs += 1
            if not first_sweep:
                from security_events import emit_event
                await emit_event(
                    db, source="cti", event_type="new_certificate_issued", severity="Medium",
                    title=f"New certificate issued for {dom}: {c.get('common_name')}",
                    entity_type="domain", entity_id=dom, entity_label=dom,
                    description=f"crt.sh shows a certificate issued by {c.get('issuer_name')} "
                                f"covering {', '.join(names[:5])}. Confirm this was requested by us.",
                    raw={"crt_id": crt_id, "names": names[:20], "issuer": c.get("issuer_name")},
                )
            for host in names:
                host = host.lstrip("*.")
                if not host.endswith(dom) or host == dom:
                    continue
                existing = await db.easm_candidates.find_one({"hostname": host}, {"_id": 0, "id": 1})
                if existing:
                    await db.easm_candidates.update_one({"id": existing["id"]},
                                                         {"$set": {"last_seen_at": _now_iso()}})
                    continue
                await db.easm_candidates.insert_one({
                    "id": str(uuid.uuid4()), "hostname": host, "domain": dom,
                    "resolved_ip": None, "live": False, "status": "new",
                    "first_seen_at": _now_iso(), "last_seen_at": _now_iso(),
                    "source": "certificate-transparency",
                })
                new_hosts += 1
    return {"ok": True, "domains": len(domains), "new_certs": new_certs,
            "new_hostnames": new_hosts, "errors": errors}


# =========================================================================
# Typosquat detection
# =========================================================================

def typosquat_permutations(domain: str) -> list:
    """Generate plausible lookalikes: character omission, doubling, transposition,
    homoglyph substitution, hyphen insertion, TLD swap, and prefix/suffix
    additions. Deduped, capped -- every candidate costs a DNS lookup."""
    domain = domain.lower().strip()
    if "." not in domain:
        return []
    label, tld = domain.split(".", 1)
    out = set()

    for i in range(len(label)):                                   # omission
        if len(label) > 3:
            out.add(f"{label[:i]}{label[i+1:]}.{tld}")
    for i, ch in enumerate(label):                                # doubling
        out.add(f"{label[:i]}{ch}{ch}{label[i:]}.{tld}")
    for i in range(len(label) - 1):                               # transposition
        out.add(f"{label[:i]}{label[i+1]}{label[i]}{label[i+2:]}.{tld}")
    for i, ch in enumerate(label):                                # homoglyphs
        for sub in _HOMOGLYPHS.get(ch, []):
            out.add(f"{label[:i]}{sub}{label[i+1:]}.{tld}")
    for i in range(1, len(label)):                                # hyphenation
        out.add(f"{label[:i]}-{label[i:]}.{tld}")
    for t in _TLD_SWAPS:                                          # TLD swap
        if t != tld:
            out.add(f"{label}.{t}")
    for p in _PREFIX_SUFFIX:                                      # prefix/suffix
        out.add(f"{p}-{label}.{tld}")
        out.add(f"{label}-{p}.{tld}")

    out.discard(domain)
    return sorted(out)[:300]


async def scan_typosquats(db, domain: str, max_checks: int = 300) -> dict:
    """Generate permutations of an owned domain and resolve each -- a permutation
    nobody registered isn't a threat, so only REGISTERED lookalikes are recorded.
    Newly-registered ones (not seen on a previous scan) raise an event."""
    import dns.resolver
    domain = domain.lower().strip()
    candidates = typosquat_permutations(domain)[:max_checks]
    resolver = dns.resolver.Resolver()
    resolver.timeout, resolver.lifetime = 3, 3

    def _resolve(name: str):
        try:
            answers = resolver.resolve(name, "A")
            return [a.to_text() for a in answers]
        except Exception:
            return None

    registered, new_hits = [], 0
    sem = asyncio.Semaphore(20)

    async def check(name):
        nonlocal new_hits
        async with sem:
            ips = await asyncio.to_thread(_resolve, name)
        if not ips:
            return
        existing = await db.cti_typosquats.find_one({"domain_candidate": name}, {"_id": 0})
        doc = {"domain": domain, "domain_candidate": name, "ips": ips,
               "last_seen_at": _now_iso(), "resolves": True}
        if existing:
            await db.cti_typosquats.update_one({"domain_candidate": name}, {"$set": doc})
            registered.append({**existing, **doc})
            return
        doc.update({"id": str(uuid.uuid4()), "first_seen_at": _now_iso(), "status": "new"})
        await db.cti_typosquats.insert_one(dict(doc))
        registered.append(doc)
        new_hits += 1
        from security_events import emit_event
        await emit_event(
            db, source="cti", event_type="typosquat_registered", severity="High",
            title=f"Lookalike domain registered: {name}",
            entity_type="domain", entity_id=name, entity_label=name,
            description=f"{name} resolves to {', '.join(ips)} and is a plausible lookalike of our domain {domain}. "
                        f"Common precursor to phishing/BEC against this domain's users.",
            raw={"domain": domain, "candidate": name, "ips": ips},
        )

    await asyncio.gather(*[check(c) for c in candidates])
    return {"ok": True, "domain": domain, "checked": len(candidates),
            "registered": len(registered), "new": new_hits,
            "items": sorted(registered, key=lambda x: x["domain_candidate"])}


# =========================================================================
# Ad-hoc investigation (one submit -> every configured source)
# =========================================================================

def classify_indicator(value: str) -> str:
    v = (value or "").strip()
    if re.match(r"^https?://", v, re.I):
        return "url"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", v):
        return "hash"
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", v, re.I):
        return "domain"
    return "unknown"


async def investigate(db, value: str) -> dict:
    """Run every applicable source against one indicator in parallel: the OSINT
    lookups already implemented in reconng.py (OpenCTI/GreyNoise/OTX/abuse.ch/
    VirusTotal), plus purely-internal checks (IOC watchlist, KEV, our own asset
    inventory / findings / OSINT history) which need no API key at all. Each
    source reports its own status so a missing key degrades that source only."""
    import reconng
    value = (value or "").strip()
    kind = classify_indicator(value)
    if kind == "unknown":
        raise ValueError(f"Could not classify \"{value}\" as an IP, domain, URL, or file hash.")

    results = []

    async def _run(label, coro):
        try:
            rows = await coro
            return {"source": label, "status": "found" if rows else "clean",
                    "rows": rows or []}
        except ValueError as e:
            return {"source": label, "status": "not_configured", "rows": [], "message": str(e)}
        except Exception as e:
            return {"source": label, "status": "error", "rows": [], "message": str(e)}

    tasks = []
    if kind in ("domain", "ip"):
        tasks.append(_run("OpenCTI", reconng.run_opencti_lookup(value)))
        tasks.append(_run("AlienVault OTX", reconng.run_otx_lookup(value, kind)))
        tasks.append(_run("abuse.ch ThreatFox", reconng.run_abusech_lookup(value)))
    if kind == "ip":
        tasks.append(_run("GreyNoise", reconng.run_greynoise_lookup(value)))
    if hasattr(reconng, "run_virustotal_lookup") and kind in ("domain", "ip", "hash", "url"):
        tasks.append(_run("VirusTotal", reconng.run_virustotal_lookup(value, kind)))
    if tasks:
        results.extend(await asyncio.gather(*tasks))

    # --- internal checks: always available, no API key ---
    watch = await db.ioc_watchlist.find_one({"value": value.lower()}, {"_id": 0})
    results.append({
        "source": "IOC Watchlist (internal)",
        "status": "found" if watch else "clean",
        "rows": [{"name": f"Watchlisted {watch['ioc_type']}", "detail": watch.get("notes") or "",
                  "resource": watch["value"], "watchlist_id": watch["id"]}] if watch else [],
    })

    osint_hist = await db.osint_findings.find({"target": value.lower()}, {"_id": 0}).sort("found_at", -1).to_list(20)
    results.append({
        "source": "OSINT history (internal)",
        "status": "found" if osint_hist else "clean",
        "rows": [{"name": o.get("module_label") or o.get("module"), "detail": o.get("detail") or o.get("label"),
                  "resource": o.get("target")} for o in osint_hist],
    })

    inv_rows = []
    if kind in ("ip", "domain"):
        assets = await db.assets.find(
            {"$or": [{"ip": value}, {"hostname": {"$regex": f"^{re.escape(value)}$", "$options": "i"}}]},
            {"_id": 0, "id": 1, "hostname": 1, "ip": 1, "owner_team": 1, "criticality": 1}).to_list(20)
        for a in assets:
            open_findings = await db.findings.count_documents(
                {"asset_id": a["id"], "status": {"$in": ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]}})
            inv_rows.append({"name": f"Asset {a['hostname']}", "resource": a.get("ip"),
                             "detail": f"team {a.get('owner_team') or '—'}, criticality {a.get('criticality') or '—'}, "
                                       f"{open_findings} open finding(s)", "asset_id": a["id"]})
    if kind == "hash":
        yara = await db.yara_scan_results.count_documents({"sha256": value.lower()}) if hasattr(db, "yara_scan_results") else 0
        if yara:
            inv_rows.append({"name": "Seen in a YARA scan", "resource": value, "detail": f"{yara} scan result(s)"})
    results.append({"source": "Internal inventory", "status": "found" if inv_rows else "clean", "rows": inv_rows})

    if kind == "domain":
        squats = await db.cti_typosquats.find({"domain_candidate": value}, {"_id": 0}).to_list(5)
        if squats:
            results.append({"source": "Typosquat registry (internal)", "status": "found",
                            "rows": [{"name": f"Lookalike of {s['domain']}", "resource": value,
                                      "detail": f"resolves to {', '.join(s.get('ips') or [])}"} for s in squats]})

    record = {
        "id": str(uuid.uuid4()), "value": value, "kind": kind, "results": results,
        "ran_at": _now_iso(),
        "verdict_counts": {
            "found": len([r for r in results if r["status"] == "found"]),
            "clean": len([r for r in results if r["status"] == "clean"]),
            "not_configured": len([r for r in results if r["status"] == "not_configured"]),
            "error": len([r for r in results if r["status"] == "error"]),
        },
    }
    await db.cti_investigations.insert_one(dict(record))
    return record


# =========================================================================
# Shodan exposure rollup (shodan_sync.py does the enrichment)
# =========================================================================

async def shodan_exposure_summary(db, limit: int = 100) -> dict:
    """Aggregate view of what Shodan sees on our own assets -- top exposed
    ports/services and the assets carrying them. Reads the fields shodan_sync.py
    already writes onto assets; no extra API calls."""
    assets = await db.assets.find(
        {"shodan_ports": {"$exists": True, "$ne": []}},
        {"_id": 0, "id": 1, "hostname": 1, "ip": 1, "shodan_ports": 1, "shodan_vulns": 1,
         "shodan_os": 1, "shodan_org": 1, "shodan_synced_at": 1, "owner_team": 1},
    ).to_list(1000)
    port_counts: dict = {}
    vuln_counts: dict = {}
    for a in assets:
        for p in a.get("shodan_ports") or []:
            port_counts[str(p)] = port_counts.get(str(p), 0) + 1
        for v in a.get("shodan_vulns") or []:
            vuln_counts[v] = vuln_counts.get(v, 0) + 1
    return {
        "assets_with_exposure": len(assets),
        "top_ports": sorted(({"port": k, "count": v} for k, v in port_counts.items()),
                             key=lambda x: -x["count"])[:20],
        "top_vulns": sorted(({"cve": k, "count": v} for k, v in vuln_counts.items()),
                             key=lambda x: -x["count"])[:20],
        "assets": sorted(assets, key=lambda a: -len(a.get("shodan_ports") or []))[:limit],
    }


# =========================================================================
# Background loop
# =========================================================================

async def cti_loop(db, interval_hours: float = 12):
    """Periodic sweep of the always-available sources (custom feeds,
    ransomware.live, CT logs). Typosquat scans stay on-demand -- they're a few
    hundred DNS lookups per domain and the answer changes slowly."""
    import logging
    logger = logging.getLogger("cti_loop")
    await asyncio.sleep(150)  # stagger past the other startup loops
    while True:
        for label, fn in (("custom CTI feeds", sync_cti_feeds),
                           ("OpenCTI reports", sync_opencti_reports),
                           ("ransomware.live", sync_ransomware_live),
                           ("certificate transparency", sync_ct_logs)):
            try:
                result = await fn(db)
                logger.info(f"{label} sync: {result}")
            except Exception as e:
                logger.warning(f"{label} sync failed: {e}")
        await asyncio.sleep(interval_hours * 3600)
