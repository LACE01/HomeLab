"""#51 PYTHIA split adoption.

Two halves, adopted very differently:
  * The situational-awareness / globe half is folded into world_monitor: events
    that carry a country get a coarse map location, and the board exposes
    map_points -- all built from feeds already collected, no new dependency.
  * The AI-forecasting half is WALLED OFF: off by default (fails closed), ships
    with no vetted source so it can emit nothing, every payload is stamped
    experimental + non-decision-bearing, and it lives on its own route so it can
    never be served next to real KEV/findings data.
"""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_pythia_split"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_pythia_split"]
db = db_module.db

import world_monitor as wm
import geo_forecast as gf

run = lambda c: asyncio.get_event_loop().run_until_complete(c)
def a(c, m=""): assert c, m


# ============ globe half: events get geolocated, board exposes map_points ============

ev = wm._event(id="x", when=wm._iso(), category="ransomware", severity="High",
               title="Group hit Acme", country="US")
a(ev["geo"] and ev["geo"]["lat"] and ev["geo"]["lon"], "a US event should be geolocated")
a(wm._event(id="y", when=wm._iso(), category="news", severity="Low", title="t")["geo"] is None,
  "an event with no country has no geo")
a(wm.geo_for("gb")["country"] == "gb" and wm.geo_for("United Kingdom"), "code and name both resolve")
a(wm.geo_for("Atlantis") is None, "an unknown country resolves to None, not a fake point")
print("PASS: world-monitor events with a country get a coarse map location (globe half); unknown or "
      "absent countries produce no fake point")

# seed a ransomware event with a country and confirm the board surfaces map_points
run(db.cti_ransomware.insert_one({
    "id": "r1", "victim": "Some Bank", "group": "LockBit", "country": "DE",
    "discovered": wm._iso()}))
board = run(wm.board(db, days=30))
a("map_points" in board, "the board must expose map_points for the map")
de = [m for m in board["map_points"] if m["country"] == "DE"]
a(de and de[0]["lat"] and de[0]["count"] >= 1, "the German event should appear as a map point")
print("PASS: board() exposes map_points aggregated from located events — enough to drive a global "
      "activity map without any new external feed")


# ============ forecasting half: OFF by default, fails closed ============

a(run(gf.feature_enabled(db)) is False, "forecasting must be disabled by default")
# malformed/truthy-but-not-boolean flag still reads OFF
run(db.feature_flags.insert_one({"key": gf.FEATURE_FLAG}))            # no 'enabled'
a(run(gf.feature_enabled(db)) is False)
run(db.feature_flags.update_one({"key": gf.FEATURE_FLAG}, {"$set": {"enabled": "yes"}}))
a(run(gf.feature_enabled(db)) is False, "only real boolean True enables it")
print("PASS: the forecasting feature is OFF by default and its gate fails CLOSED (absence, missing "
      "field, or a non-boolean all read as off)")


# ============ ships inert: no source, so no forecast can be produced ============

a(gf.has_source() is False, "the module must ship with NO vetted forecast source")
run(db.feature_flags.update_one({"key": gf.FEATURE_FLAG}, {"$set": {"enabled": True}}))
out = run(gf.forecasts(db))
a(out["items"] == [] and out["decision_bearing"] is False and out["experimental"] is True)
a("No vetted forecast source" in out["message"], out["message"])
print("PASS: even with the flag ON, with no vetted source registered the module emits NO forecasts — "
      "it cannot fabricate one, by construction")


# ============ status is always safe and carries the disclaimer ============

st = run(gf.status(db))
a(st["experimental"] is True and st["decision_bearing"] is False)
a("NOT AN INTELLIGENCE PRODUCT" in st["disclaimer"])
a("never be shown next to KEV" in st["separation_policy"])
print("PASS: status() always reports experimental + non-decision-bearing with a plain-language "
      "disclaimer and the separation-from-real-data policy")


# ============ a registered source is re-stamped with the guardrails ============

async def fake_source(_db):
    # a source might naively omit the guardrail fields, or even try to claim
    # decision_bearing -- the module must overwrite them
    return [{"region": "Testland", "note": "elevated", "decision_bearing": True}]
gf.register_forecast_source(fake_source)
out2 = run(gf.forecasts(db))
a(len(out2["items"]) == 1)
a(out2["items"][0]["experimental"] is True and out2["items"][0]["decision_bearing"] is False,
  "the module must re-stamp every item as experimental + non-decision-bearing")
gf.register_forecast_source(None)   # reset to inert
a(gf.has_source() is False)
print("PASS: even a registered source's items are force-stamped experimental + non-decision-bearing — "
      "a source can't strip the guardrails, and the module resets to inert")


# ============ separation: forecasting is NOT part of the world-monitor board ============

import inspect
import re as _re
a(not _re.search(r"^\s*(import|from)\s+geo_forecast", inspect.getsource(wm), _re.M),
  "world_monitor must not import the forecast module")
a(not _re.search(r"^\s*(import|from)\s+world_monitor", inspect.getsource(gf), _re.M),
  "the forecast module must not import observed world-monitor data")
a("map_points" not in inspect.getsource(gf.forecasts))
print("PASS: the observed board and the experimental forecast live in separate modules/surfaces — "
      "forecasts can never be rendered in the same payload as KEV/findings/world-monitor data")

print("\nALL PYTHIA SPLIT-ADOPTION TESTS PASSED")
