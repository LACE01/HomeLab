# NOTE: this test depends on a real Albert (CIS/MS-ISAC) export file from a
# specific local session upload, which is intentionally NOT committed to the repo
# (it's a real org's exported network telemetry, not synthetic fixture data).
# It will fail with FileNotFoundError in a clean checkout / CI -- kept here for
# local reference only. The same ingestion/dedup/severity/stats logic is covered
# with synthetic data by test_albert_gaps2.py, test_albert_ports.py, and
# test_asset_albert_link.py, which ARE part of the CI suite.
import sys, asyncio
sys.path.insert(0, "/tmp/repo/backend")

from mongomock_motor import AsyncMongoMockClient
from albert_ingest import import_albert_export, compute_albert_stats, parse_albert_xlsx

async def main():
    client = AsyncMongoMockClient()
    db = client["vulnops_test"]

    with open("/sessions/youthful-dazzling-pasteur/mnt/uploads/EagleCo_Albert_Allowlist_Alert_Report-2026-07-14T13_02_35 (1).xlsx", "rb") as f:
        content = f.read()

    # sanity: raw parser
    sheet_name, rows = parse_albert_xlsx(content)
    print("sheet_name:", sheet_name, "rows:", len(rows))
    assert sheet_name == "Whitelisted_Albert_Alert_Detail"
    assert len(rows) == 954, len(rows)

    # seed a threat-intel watchlist IOC that WILL match the file's dominant
    # public destination IP, to prove the cross-check wiring works end to end
    await db.ioc_watchlist.insert_one({
        "id": "seed-1", "ioc_type": "ip", "value": "104.18.23.204", "source": "manual",
        "severity": "High", "notes": "test seed", "added_at": "2026-01-01T00:00:00+00:00", "hits": 0, "last_hit_at": None,
    })

    result = await import_albert_export(db, content, "EagleCo_Albert_Allowlist_Alert_Report.xlsx", uploaded_by="luisarce353@gmail.com")
    print("import result:", result)
    # This fixture file itself has 366 duplicate rows within it (same time/device/
    # message/IPs/ports) -- confirms the dedup feature is catching a real, not just
    # theoretical, pattern in actual CIS Albert exports.
    assert result["rows_parsed"] == 588
    assert result["duplicates_merged"] == 366
    assert result["disposition"] == "allowlisted"
    assert result["watchlist_matches"] >= 1, "expected at least the seeded IOC to match"

    stored = await db.albert_alerts.count_documents({})
    assert stored == 588, stored

    # spot-check severity mapping on the dominant signature
    sample = await db.albert_alerts.find_one({"alert_message": {"$regex": "PowerShell", "$options": "i"}})
    print("sample powershell alert:", sample["alert_message"], sample["severity"], sample["mitre_technique"])
    assert sample["severity"] == "High"
    assert "T1021.002" in sample["mitre_technique"]

    ff = await db.albert_alerts.find_one({"alert_message": {"$regex": "Firefox", "$options": "i"}})
    assert ff["severity"] == "Low"
    assert "T1036" in ff["mitre_technique"]

    stats = await compute_albert_stats(db, days=30)
    print("stats keys:", list(stats.keys()))
    print("severity_counts:", stats["severity_counts"])
    print("category_counts:", stats["category_counts"])
    print("device_counts:", stats["device_counts"])
    print("daily_trend:", stats["daily_trend"])
    print("top_source_ips[:3]:", stats["top_source_ips"][:3])
    print("top_destination_ips[:3]:", stats["top_destination_ips"][:3])
    print("anomalies:", stats["anomalies"])
    assert stats["total_alerts"] == 588
    assert stats["device_counts"].get("co-eagle-PRO-Albert-2") == 423
    assert stats["device_counts"].get("co-eagle-PRO-Albert-1") == 165
    assert stats["top_destination_ips"][0]["value"] == "10.100.1.95"
    assert stats["top_destination_ips"][0]["count"] == 397

    # second import of the SAME file should now be recognized as entirely
    # duplicate -- dedup collapses on (time, device, message, IPs, ports) both
    # within a file and against everything already stored, so re-uploading the
    # same or an overlapping-window export doesn't create duplicate alert docs.
    result2 = await import_albert_export(db, content, "reupload.xlsx", uploaded_by="luisarce353@gmail.com")
    assert result2["rows_parsed"] == 0
    assert result2["duplicates_merged"] == 954  # 366 in-file + 588 against the first import
    stored2 = await db.albert_alerts.count_documents({})
    assert stored2 == 588

    imports = await db.albert_imports.find({}, {"_id": 0}).to_list(10)
    assert len(imports) == 2

    print("ALL ALBERT TESTS PASSED")

asyncio.run(main())
