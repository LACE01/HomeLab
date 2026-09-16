"""Item 54 -- Software / SaaS Application Inventory.

An application-level inventory (as opposed to the host-level asset inventory) for
two jobs: incident response ("which hosts run app X?") and shadow-IT discovery
("what is installed/in use that never went through a Security Review?").

It is AUTO-POPULATED by aggregating sources the platform already collects, so it
stays current without manual entry:

    software_inventory   OS-level installed software from the Microsoft Defender
                         for Endpoint EDR connector and Qualys GAV/CSAM
    findings (SCA)       SBOM-scanned application dependencies (sbom.py)
    reviewed_entities    the vendor/system/product catalog written when a Security
                         Review is completed -- i.e. what has been vetted
    Google Workspace     OAuth-authorized third-party apps -- PLUGGABLE: there is
                         no Workspace connector yet, so this source is reported as
                         "not configured" until one is added, rather than faked

Shadow IT is the key inference: an application DISCOVERED on endpoints (or, once
wired, in Workspace) that has NO matching completed Security Review is flagged --
that is precisely the unsanctioned software/SaaS a county wants surfaced.
"""
import hashlib
from datetime import datetime, timezone

# Sources that count as "discovered in the environment" for shadow-IT purposes.
# SBOM dependencies are libraries, not installed apps/SaaS, so they don't make
# something shadow IT on their own.
DISCOVERY_SOURCES = {"edr", "qualys", "endpoint", "google_workspace"}
GOOGLE_WORKSPACE_CONFIGURED = False   # no Workspace connector yet -- pluggable stub


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _app_id(key: str) -> str:
    return "app-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


def _source_tag(raw_source: str) -> str:
    s = (raw_source or "").lower()
    if s.startswith("defender"):
        return "edr"
    if "qualys" in s:
        return "qualys"
    return "endpoint"


def _category(sources: set) -> str:
    if sources & {"edr", "qualys", "endpoint"}:
        return "installed_software"
    if "google_workspace" in sources:
        return "saas"
    if "sbom" in sources:
        return "dependency"
    return "reviewed"


async def rebuild_inventory(db, *, max_software: int = 50000, max_components: int = 20000) -> dict:
    """Rebuild db.application_inventory from all sources. Bounded reads so a large
    estate can't turn this into a runaway (same discipline as the rest of the
    platform's aggregations)."""
    now = _now_iso()
    apps: dict = {}

    def get(name: str, vendor, category: str) -> dict:
        key = name.strip().lower()
        if key not in apps:
            apps[key] = {
                "key": key, "name": name.strip(), "vendor": (vendor or None),
                "category": category, "sources": set(), "hosts": set(),
                "versions": set(), "reviewed": False, "review_rating": None,
                "review_id": None,
            }
        return apps[key]

    # --- 1) reviewed_entities: the vetted set (and names to match against) ---
    reviewed_names: dict = {}
    async for e in db.reviewed_entities.find({}, {"_id": 0}):
        nm = (e.get("name") or "").strip()
        if not nm:
            continue
        reviewed_names[nm.lower()] = e
        app = get(nm, e.get("domain"), "reviewed")
        app["sources"].add("security_review")
        app["reviewed"] = True
        app["review_rating"] = e.get("current_rating")
        app["review_id"] = e.get("last_review_id")

    # --- 2) EDR / Qualys installed software ---
    seen = 0
    async for s in db.software_inventory.find({}, {"_id": 0}):
        seen += 1
        if seen > max_software:
            break
        nm = (s.get("name") or "").strip()
        if not nm:
            continue
        app = get(nm, s.get("vendor"), "installed_software")
        app["sources"].add(_source_tag(s.get("source", "")))
        if s.get("asset_id"):
            app["hosts"].add(s["asset_id"])
        if s.get("version"):
            app["versions"].add(str(s["version"]))

    # --- 3) SBOM components (application dependencies) ---
    seen = 0
    async for f in db.findings.find(
            {"source_tool_type": "Software Composition Analysis"},
            {"_id": 0, "component_name": 1, "component_ecosystem": 1, "component_version": 1}):
        seen += 1
        if seen > max_components:
            break
        nm = (f.get("component_name") or "").strip()
        if not nm:
            continue
        app = get(nm, f.get("component_ecosystem"), "dependency")
        app["sources"].add("sbom")
        if f.get("component_version"):
            app["versions"].add(str(f["component_version"]))

    # --- 4) Google Workspace OAuth apps: pluggable, not configured yet ---
    google_workspace = {"configured": GOOGLE_WORKSPACE_CONFIGURED, "apps": 0}

    # --- finalize: category, shadow-IT, review-matching by name/vendor ---
    docs = []
    for key, a in apps.items():
        sources = a["sources"]
        reviewed = a["reviewed"]
        rating = a["review_rating"]
        review_id = a["review_id"]
        # link a discovered app to a review by name OR vendor match
        if not reviewed:
            match = reviewed_names.get(key) or (
                reviewed_names.get((a["vendor"] or "").lower()) if a["vendor"] else None)
            if match:
                reviewed = True
                rating = match.get("current_rating")
                review_id = match.get("last_review_id")
        discovered = bool(sources & DISCOVERY_SOURCES)
        docs.append({
            "id": _app_id(key), "key": key, "name": a["name"], "vendor": a["vendor"],
            "category": _category(sources),
            "sources": sorted(sources),
            "install_count": len(a["hosts"]),
            "hosts": sorted(a["hosts"])[:50],
            "versions": sorted(a["versions"])[:20],
            "reviewed": reviewed, "review_rating": rating, "review_id": review_id,
            "sanctioned": reviewed,
            "shadow_it": discovered and not reviewed,
            "updated_at": now,
        })

    await db.application_inventory.delete_many({})
    if docs:
        await db.application_inventory.insert_many([dict(d) for d in docs])

    by_source: dict = {}
    for d in docs:
        for s in d["sources"]:
            by_source[s] = by_source.get(s, 0) + 1
    return {
        "applications": len(docs),
        "shadow_it": sum(1 for d in docs if d["shadow_it"]),
        "reviewed": sum(1 for d in docs if d["reviewed"]),
        "by_category": {c: sum(1 for d in docs if d["category"] == c)
                        for c in {d["category"] for d in docs}},
        "by_source": by_source,
        "google_workspace": google_workspace,
        "generated_at": now,
    }


async def stats(db) -> dict:
    total = await db.application_inventory.count_documents({})
    shadow = await db.application_inventory.count_documents({"shadow_it": True})
    reviewed = await db.application_inventory.count_documents({"reviewed": True})
    top = await db.application_inventory.find({}, {"_id": 0, "name": 1, "vendor": 1, "install_count": 1}) \
        .sort("install_count", -1).to_list(10)
    last = await db.application_inventory.find_one({}, {"_id": 0, "updated_at": 1}, sort=[("updated_at", -1)])
    return {
        "total": total, "shadow_it": shadow, "reviewed": reviewed,
        "top_by_install": top,
        "last_rebuilt_at": (last or {}).get("updated_at"),
        "google_workspace_configured": GOOGLE_WORKSPACE_CONFIGURED,
    }
