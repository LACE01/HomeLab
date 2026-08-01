"""One identity per real machine — and, just as importantly, NOT one identity for
two machines that happen to share a name.

Every join in this platform (context panels, correlation rules, blast radius,
attack paths) is only as good as this. A join over unreliable identity produces
confident wrong answers, which is worse than no answer, so these tests spend as
much effort on the merges that must NOT happen as on the ones that must.
"""
import os, sys, asyncio
from datetime import datetime, timezone, timedelta
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_entity_resolution"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_entity_resolution"]
db = db_module.db

import entity_resolution as er

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


def reset():
    run(db.asset_identifiers.delete_many({}))
    run(db.assets.delete_many({}))
    run(db.findings.delete_many({}))
    run(db.asset_identity_links.delete_many({}))
    run(db.asset_merges.delete_many({}))


def seed_asset(asset_id, record, source):
    run(db.assets.insert_one({"id": asset_id, "hostname": record.get("hostname"),
                               "status": "active", **{k: v for k, v in record.items()
                                                       if k != "hostname"}}))
    run(er.record_identifiers(db, asset_id, er.identifiers_from(record), source))


# ============ normalization: junk must never become an identifier ============

assert er.normalize("mac", "00-1A-2B-3C-4D-5E") == "00:1a:2b:3c:4d:5e"
assert er.normalize("mac", "001A.2B3C.4D5E") == "00:1a:2b:3c:4d:5e"
assert er.normalize("mac", "00:00:00:00:00:00") is None
assert er.normalize("mac", "not-a-mac") is None
print("PASS: MACs normalize across every vendor's punctuation, and the all-zero MAC is rejected")

# These are the placeholders that, stored as real identifiers, would merge every
# asset carrying them into a single record.
for junk in ("Unknown", "N/A", "To Be Filled By O.E.M.", "Default string",
              "System Serial Number", "00000000-0000-0000-0000-000000000000", "  "):
    assert er.normalize("serial", junk) is None, junk
print("PASS: BIOS/vendor placeholder serials are rejected — storing one would collapse every "
      "machine that ships with it into a single asset")

assert er.normalize("ip", "127.0.0.1") is None
assert er.normalize("ip", "0.0.0.0") is None
assert er.normalize("ip", "169.254.10.5") is None
assert er.normalize("ip", "10.1.2.3") == "10.1.2.3"
print("PASS: loopback, unspecified and link-local addresses identify no particular machine and "
      "are rejected as identifiers")

assert er.normalize("hostname", "LAPTOP-7.corp.example.com") == "laptop-7"
assert er.normalize("fqdn", "LAPTOP-7.CORP.example.com.") == "laptop-7.corp.example.com"
assert er.normalize("fqdn", "laptop-7") is None, "a short name is not an FQDN"
assert er.normalize("hostname", "10.1.2.3") is None, "an IP in the hostname field is not a name"
assert er.normalize("hostname", "a") is None, "a single character is not identifying"
# But short names ARE kept: "dc1", "fw2", "h1" are real hosts, and rejecting them
# on length would guarantee a miss to avoid a rare collision that the resolver
# already handles by other means (see the SERVER1 cases below).
assert er.normalize("hostname", "dc1") == "dc1"
print("PASS: hostname vs FQDN are kept distinct, and an IP sitting in a hostname field is not "
      "mistaken for a name")


# ============ the miss that started this: FQDN vs short name ============

reset()
# Qualys created the asset from a scan target with only the short name.
seed_asset("a1", {"hostname": "laptop-7", "ip": "10.1.2.3",
                   "qualys_host_id": "Q-1001"}, "qualys")

# Defender reports the same machine as an FQDN. Under hostname-string matching
# this found nothing and the EDR data silently never landed.
v = run(er.resolve(db, {"computerDnsName": "LAPTOP-7.corp.eaglecounty.us",
                         "defender_device_id": "D-77"}, source="defender"))
assert v["asset_id"] == "a1", v
assert v["matched_on"]["kind"] == "hostname"
print("PASS: Defender's FQDN now resolves to the asset Qualys created from the short name — the "
      "silent miss that made 'devices_matched: 0' look like a permissions problem")

# and once linked, the strong Defender ID resolves it directly next time
run(er.record_identifiers(db, "a1", er.identifiers_from(
    {"computerDnsName": "LAPTOP-7.corp.eaglecounty.us", "defender_device_id": "D-77"}), "defender"))
v = run(er.resolve(db, {"defender_device_id": "D-77"}, source="defender"))
assert v["asset_id"] == "a1" and v["confidence"] == 1.0
assert "Defender device ID" in v["reason"]
print("PASS: identity accumulates — the next sync matches on the strong Defender ID at full "
      "confidence instead of re-deriving it from a name")


# ============ the merge that must NOT happen ============

reset()
# Two genuinely different machines, both imaged as "SERVER1", in different domains.
seed_asset("east", {"hostname": "server1", "fqdn": "server1.east.example.com",
                     "serial": "SN-AAA-111"}, "qualys")
seed_asset("west", {"hostname": "server1", "fqdn": "server1.west.example.com",
                     "serial": "SN-BBB-222"}, "qualys")

v = run(er.resolve(db, {"hostname": "SERVER1", "serial": "SN-AAA-111"}, source="intune"))
assert v["asset_id"] == "east", v
print("PASS: with a serial present, the right SERVER1 is chosen — the strong key decides, not the "
      "ambiguous name")

# A record whose serial matches NEITHER must not attach to either of them just
# because the name lines up. Conflict beats agreement.
v = run(er.resolve(db, {"hostname": "SERVER1", "serial": "SN-CCC-333"}, source="intune"))
assert v["asset_id"] is None, f"a third SERVER1 was wrongly merged into {v['asset_id']}"
print("PASS: a THIRD machine named SERVER1 with its own serial is not merged into either existing "
      "one — disagreement on a strong key vetoes a weak-key match")

# A name shared by two assets is not identifying at all, so it decides nothing.
v = run(er.resolve(db, {"hostname": "SERVER1"}, source="albert"))
assert v["asset_id"] is None
print("PASS: an identifier pointing at more than one asset is treated as non-identifying rather "
      "than resolved to an arbitrary one of them")


# ============ weak keys need corroboration ============

reset()
seed_asset("w1", {"hostname": "printer-3", "ip": "10.0.0.9"}, "nmap")

v = run(er.resolve(db, {"hostname": "printer-3"}, source="albert"))
assert v["asset_id"] == "w1" and v["confidence"] == 0.5
assert "low confidence" in v["reason"] and "worth" in v["reason"]
print("PASS: a lone short-hostname match resolves but is marked low confidence and says why")

v = run(er.resolve(db, {"hostname": "printer-3", "ip": "10.0.0.9"}, source="albert"))
assert v["asset_id"] == "w1" and v["confidence"] == 0.75
assert "two independent weak ones agree" in v["reason"]
print("PASS: two independent weak identifiers agreeing raises confidence above either alone")


# ============ an IP is only evidence while the lease holds ============

reset()
run(db.assets.insert_one({"id": "dhcp1", "hostname": "old-host", "status": "active"}))
stale = (datetime.now(timezone.utc) - timedelta(days=9)).isoformat()
run(db.asset_identifiers.insert_one({
    "id": "i1", "asset_id": "dhcp1", "kind": "ip", "value": "10.5.5.5",
    "source": "nmap", "strength": "weak", "first_seen_at": stale, "last_seen_at": stale}))

v = run(er.resolve(db, {"ip": "10.5.5.5"}, source="albert"))
assert v["asset_id"] is None, "a 9-day-old IP observation was treated as identity"
print("PASS: an IP seen 9 days ago no longer identifies a machine — DHCP will have moved it, and "
      "matching on it would attribute one host's findings to another")

run(db.asset_identifiers.update_one({"id": "i1"},
                                     {"$set": {"last_seen_at": er._now_iso()}}))
v = run(er.resolve(db, {"ip": "10.5.5.5"}, source="albert"))
assert v["asset_id"] == "dhcp1"
print("PASS: a current IP observation does resolve, inside the lease window")


# ============ resolve_and_link: create only when nothing matched ============

reset()
created_calls = []


async def make_asset():
    doc = {"id": "new-1", "hostname": "brand-new", "status": "active"}
    await db.assets.insert_one(dict(doc))
    created_calls.append(doc["id"])
    return doc

r = run(er.resolve_and_link(db, {"hostname": "brand-new", "serial": "SN-NEW"},
                             source="qualys", create=make_asset))
assert r["created"] is True and r["asset_id"] == "new-1"
r2 = run(er.resolve_and_link(db, {"serial": "SN-NEW", "ip": "10.9.9.9"},
                              source="defender", create=make_asset))
assert r2["created"] is False and r2["asset_id"] == "new-1"
assert created_calls == ["new-1"], "a second source created a duplicate asset"
print("PASS: a second source describing the same machine links to it instead of creating a "
      "duplicate — this is the behaviour that stops the asset count inflating with every connector")

ident = run(er.identity_of(db, "new-1"))
assert set(ident["sources"]) == {"qualys", "defender"}
kinds = {i["kind"] for i in ident["identifiers"]}
assert {"serial", "hostname", "ip"} <= kinds
assert ident["identifiers"][0]["strength"] == "strong", "strongest identifier should sort first"
print("PASS: the asset's identity shows every identifier and which systems have seen it — which "
      "doubles as coverage: no Defender identifier means no EDR on that machine")


# ============ merging is real, and reversible ============

reset()
seed_asset("keep", {"hostname": "dup-host", "serial": "SN-DUP"}, "qualys")
run(db.assets.update_one({"id": "keep"}, {"$set": {"owner_team": "Infra", "criticality": "high"}}))
seed_asset("dupe", {"hostname": "dup-host", "ip": "10.2.2.2"}, "defender")
run(db.assets.update_one({"id": "dupe"}, {"$set": {"operating_system": "Windows 11",
                                                    "owner_team": None}}))
run(db.findings.insert_many([{"id": "f1", "asset_id": "dupe"}, {"id": "f2", "asset_id": "dupe"}]))

dups = run(er.find_duplicate_candidates(db))
assert any(d["value"] == "dup-host" and set(d["asset_ids"]) == {"keep", "dupe"} for d in dups)
print("PASS: assets sharing an identifier are surfaced as duplicate candidates — this is what "
      "exposes the damage hostname-only matching already did")

m = run(er.merge_assets(db, "keep", "dupe", actor="luis", reason="same machine"))
assert m["findings_moved"] == 2
assert run(db.findings.count_documents({"asset_id": "keep"})) == 2
kept = run(db.assets.find_one({"id": "keep"}, {"_id": 0}))
assert kept["owner_team"] == "Infra", "an existing value must not be overwritten by the merge"
assert kept["operating_system"] == "Windows 11", "a blank on the survivor should be filled"
tomb = run(db.assets.find_one({"id": "dupe"}, {"_id": 0}))
assert tomb["status"] == "merged" and tomb["merged_into"] == "keep"
print("PASS: a merge moves findings, fills only the survivor's blanks, and leaves a tombstone "
      "rather than deleting — asset ids appear in findings, IR cases and reports, so a dangling "
      "reference would be worse than a redirect")

undo = run(er.undo_merge(db, m["id"], actor="luis"))
assert undo["restored"] == "dupe"
restored = run(db.assets.find_one({"id": "dupe"}, {"_id": 0}))
assert restored["status"] == "active" and restored.get("merged_into") is None
assert restored["operating_system"] == "Windows 11"
print("PASS: the merge is reversible from a stored snapshot — an automated join you cannot undo "
      "would have to be perfect, and none is")

try:
    run(er.undo_merge(db, m["id"]))
    raise AssertionError("expected a refusal")
except ValueError as e:
    assert "already undone" in str(e)
print("PASS: undoing twice is refused rather than silently corrupting state")


# ============ identifier extraction handles each connector's real shape ============

shapes = [
    ({"computerDnsName": "h1.corp.local", "id": "D-1"}, "defender", {"fqdn", "hostname"}),
    ({"deviceName": "H1", "azureADDeviceId": "aad-guid-1",
      "wiFiMacAddress": "AA:BB:CC:DD:EE:FF"}, "intune", {"hostname", "aad_device_id", "mac"}),
    ({"hostname": "h1", "ip": "10.0.0.1", "qualys_host_id": "Q1"}, "qualys",
     {"hostname", "ip", "qualys_host_id"}),
    ({"InstanceId": "i-0abc", "ip_address": "10.0.0.2"}, "aws", {"cloud_instance_id", "ip"}),
]
for record, source, expected in shapes:
    kinds = {i["kind"] for i in er.identifiers_from(record)}
    assert expected <= kinds, f"{source}: got {kinds}, expected at least {expected}"
print("PASS: identifiers are extracted from each connector's native field names — no connector has "
      "to reshape its payload before resolving")

# multiple MACs / IPs on one device all become identifiers
ids = er.identifiers_from({"hostname": "multi", "mac": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"],
                            "ip": ["10.0.0.5", "10.0.0.6"]})
assert len([i for i in ids if i["kind"] == "mac"]) == 2
assert len([i for i in ids if i["kind"] == "ip"]) == 2
print("PASS: a dual-homed or multi-NIC device contributes all of its MACs and IPs, so a later "
      "sighting on any interface still resolves")


# ============ undo must restore identity AND findings, not just the record ============

reset()
seed_asset("survivor", {"hostname": "box-a", "serial": "SN-A"}, "qualys")
seed_asset("absorbed", {"hostname": "box-a", "defender_device_id": "D-9"}, "defender")
run(db.findings.insert_many([{"id": "fa", "asset_id": "absorbed"},
                              {"id": "fb", "asset_id": "survivor"}]))

m = run(er.merge_assets(db, "survivor", "absorbed"))
assert run(db.findings.find_one({"id": "fa"}))["asset_id"] == "survivor"
run(er.undo_merge(db, m["id"]))

# The original bug: undo restored the asset document but left its identifiers and
# findings on the survivor, so the pair silently never re-appeared as duplicates
# and the finding stayed misattributed.
assert run(db.findings.find_one({"id": "fa"}))["asset_id"] == "absorbed", \
    "undo left the absorbed asset's finding attributed to the survivor"
assert run(db.findings.find_one({"id": "fb"}))["asset_id"] == "survivor", \
    "undo moved a finding that never belonged to the absorbed asset"
ids = run(db.asset_identifiers.find({"asset_id": "absorbed"}, {"_id": 0}).to_list(50))
assert any(i["kind"] == "defender_device_id" for i in ids), \
    "undo left the absorbed asset's identifiers on the survivor"
dups = run(er.find_duplicate_candidates(db))
assert any(d["value"] == "box-a" for d in dups), \
    "after undo the pair must be offered as duplicates again"
print("PASS: undo restores exactly the identifiers and findings the merge moved — by id, not by "
      "source, which was unanswerable once everything pointed at the survivor")


# ============ backfill attributes identifiers to the connector that produced them ============

grouped = er.attribute_sources({
    "id": "x", "hostname": "srv-1", "ip": "10.0.0.1",
    "qualys_host_id": "Q-1", "defender_device_id": "D-1"})
assert "qualys" in grouped and "defender" in grouped
assert any(i["kind"] == "qualys_host_id" for i in grouped["qualys"])
assert any(i["kind"] == "defender_device_id" for i in grouped["defender"])
assert any(i["kind"] == "ip" for i in grouped["backfill"])
print("PASS: an existing asset's identifiers are attributed to the connector each must have come "
      "from — recording them all as 'backfill' would make the coverage answer ('no Defender "
      "identifier means no EDR') wrong for every asset that predates this system")

# an asset only Qualys ever saw must NOT look like Defender has seen it
grouped = er.attribute_sources({"id": "y", "hostname": "srv-2", "qualys_host_id": "Q-2"})
assert set(grouped) == {"qualys", "backfill"}, grouped
print("PASS: a machine no EDR has ever reported does not acquire an EDR source from the backfill")
