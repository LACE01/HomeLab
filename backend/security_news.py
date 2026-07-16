"""Vendor compromise/breach context from real security journalism -- pulls recent
articles from a curated list of reputable, editorially-independent security news
outlets' public RSS feeds (no API key, no paid news-search API needed) and matches
them against a vendor's name/match_terms, so the Vendor Detail page's compromise
panel can show "here's what BleepingComputer/Krebs/etc. actually reported about
this vendor recently" instead of staying empty for any vendor that hasn't set a
domain (which the existing OTX/abuse.ch/OpenCTI/certificate-transparency monitoring
in vendor_management.check_vendor_compromise requires).

This is a SEPARATE, complementary signal to that domain-based OSINT monitoring --
it works for every vendor regardless of whether a domain is set, since it matches
on vendor NAME against news article text, not domain lookups. A vendor showing up
here doesn't mean a confirmed incident -- it means a reputable outlet published
something mentioning them recently, which is exactly the kind of extra context a
human analyst can apply their own judgment to, same honest-substring-matching spirit
as the rest of this app (see vendor_management.py's own docstring on that).

Feeds (RSS 2.0), each verified against the outlet's real, currently-live feed URL
before being added here -- not guessed:
  - BleepingComputer, Krebs on Security, The Hacker News, Dark Reading, SecurityWeek
"""
import logging
import re
import uuid
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
import xml.etree.ElementTree as ET

import httpx

logger = logging.getLogger("vulnops.security_news")

NEWS_FEEDS = [
    {"source": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"source": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"source": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"source": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
    {"source": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
]

RETENTION_DAYS = 120  # keep a while so a vendor's news history isn't just "since we last synced"
ATOM_NS = "{http://www.w3.org/2005/Atom}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "").strip()


def _parse_feed(source: str, xml_bytes: bytes) -> list:
    """Handles standard RSS 2.0 (<channel><item>...) -- every feed in NEWS_FEEDS is
    RSS 2.0 -- with a minimal Atom (<feed><entry>...) fallback in case an outlet
    switches formats later without this list being updated."""
    items = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise RuntimeError(f"could not parse feed XML: {e}")

    channel = root.find("channel")
    if channel is not None:
        entries = channel.findall("item")
        is_atom = False
    else:
        entries = root.findall(f"{ATOM_NS}entry")
        is_atom = True

    for entry in entries:
        if is_atom:
            title = (entry.findtext(f"{ATOM_NS}title") or "").strip()
            link_el = entry.find(f"{ATOM_NS}link")
            link = (link_el.get("href") if link_el is not None else "") or ""
            pub_raw = entry.findtext(f"{ATOM_NS}published") or entry.findtext(f"{ATOM_NS}updated")
            summary = _strip_html(entry.findtext(f"{ATOM_NS}summary") or entry.findtext(f"{ATOM_NS}content") or "")[:500]
            guid = link
        else:
            title = (entry.findtext("title") or "").strip()
            link = (entry.findtext("link") or "").strip()
            guid = (entry.findtext("guid") or link).strip()
            pub_raw = entry.findtext("pubDate")
            summary = _strip_html(entry.findtext("description") or "")[:500]

        if not title or not link:
            continue

        published_at = None
        if pub_raw:
            try:
                published_at = parsedate_to_datetime(pub_raw).astimezone(timezone.utc).isoformat()
            except Exception:
                try:
                    published_at = datetime.fromisoformat(pub_raw.replace("Z", "+00:00")).isoformat()
                except Exception:
                    published_at = None

        items.append({
            "source": source, "title": title, "link": link, "guid": guid or link,
            "summary": summary, "published_at": published_at,
        })
    return items


async def sync_security_news(db) -> dict:
    """Fetches every feed, upserts new articles (dedup by guid), and prunes
    anything older than RETENTION_DAYS. Best-effort per feed -- one outlet being
    unreachable or changing its feed format shouldn't block the others."""
    now = _now_iso()
    fetched = 0
    created = 0
    errors = []
    for feed in NEWS_FEEDS:
        try:
            async with httpx.AsyncClient(timeout=20, headers={"User-Agent": "Nightwatch-VulnMgmt/1.0 (self-hosted security platform)"}) as c:
                r = await c.get(feed["url"])
            if r.status_code != 200:
                errors.append(f"{feed['source']}: HTTP {r.status_code}")
                continue
            articles = _parse_feed(feed["source"], r.content)
        except Exception as e:
            logger.warning(f"security news fetch failed for {feed['source']}: {e}")
            errors.append(f"{feed['source']}: {e}")
            continue

        for a in articles:
            fetched += 1
            existing = await db.security_news_articles.find_one({"guid": a["guid"]}, {"_id": 0, "id": 1})
            if existing:
                continue
            await db.security_news_articles.insert_one({"id": str(uuid.uuid4()), **a, "synced_at": now})
            created += 1

    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
    prune_result = await db.security_news_articles.delete_many({"published_at": {"$lt": cutoff}})

    return {
        "feeds_checked": len(NEWS_FEEDS), "articles_seen": fetched, "articles_created": created,
        "errors": errors, "pruned": getattr(prune_result, "deleted_count", 0), "synced_at": now,
    }


async def get_vendor_news(db, vendor_name: str, match_terms: list | None = None, days: int = 180, limit: int = 20) -> list:
    """Matches cached news articles against a vendor's name + match_terms -- same
    honest substring-matching approach used everywhere else in this app (title OR
    summary, case-insensitive). Terms shorter than 3 characters are skipped: a
    generic short vendor name/abbreviation would otherwise match all sorts of
    unrelated articles by coincidence, which isn't a useful signal. Not a perfect
    NER-based approach, but transparent and editable via the same match_terms a
    vendor's other linkage already uses."""
    terms = [t.strip() for t in ([vendor_name] + (match_terms or [])) if t and len(t.strip()) >= 3]
    if not terms:
        return []
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    ors = []
    for t in terms:
        pattern = re.escape(t)
        ors.append({"title": {"$regex": pattern, "$options": "i"}})
        ors.append({"summary": {"$regex": pattern, "$options": "i"}})
    items = await db.security_news_articles.find(
        {"$or": ors, "published_at": {"$gte": cutoff}}, {"_id": 0},
    ).sort("published_at", -1).to_list(limit)
    return items
