"""CWE repair: normalize stored CWE values to canonical "CWE-<n>" and fill
CWE-less findings from another finding with the same CVE (#33). Shared by the
admin "Repair CWEs" button and the one-time boot migration."""


async def repair_cwes(db) -> dict:
    from mitre_mapping import normalize_cwe
    updated = 0
    cursor = db.findings.find({"cwe": {"$nin": [None, ""]}}, {"_id": 0, "id": 1, "cwe": 1})
    async for f in cursor:
        canonical = normalize_cwe(f.get("cwe"))
        if canonical and canonical != f.get("cwe"):
            await db.findings.update_one({"id": f["id"]}, {"$set": {"cwe": canonical}})
            updated += 1
        elif not canonical and f.get("cwe"):
            # placeholder values like NVD-CWE-noinfo aren't real CWEs
            await db.findings.update_one({"id": f["id"]}, {"$set": {"cwe": None}})
            updated += 1
    # #33 -- propagate a known CWE to CWE-less findings sharing the same CVE.
    # Until 5424e73 every scanner rescan nulled the NVD-sourced CWE on the rows
    # it touched, while rows not rescanned kept theirs; this repairs that split
    # without waiting for (or needing) an NVD key.
    propagated = 0
    by_cve = {}
    async for r in db.findings.aggregate([
        {"$match": {"cve": {"$nin": [None, ""]}, "cwe": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$cve", "cwe": {"$first": "$cwe"}}},
    ]):
        canonical = normalize_cwe(r.get("cwe"))
        if canonical:
            by_cve[r["_id"]] = canonical
    for cve, cwe in by_cve.items():
        res = await db.findings.update_many(
            {"cve": cve, "$or": [{"cwe": None}, {"cwe": ""}, {"cwe": {"$exists": False}}]},
            {"$set": {"cwe": cwe}})
        propagated += res.modified_count
    if updated or propagated:
        from aggregate_cache import invalidate
        await invalidate(db, "mitre_coverage")
    return {"ok": True, "updated": updated, "propagated_by_cve": propagated}
