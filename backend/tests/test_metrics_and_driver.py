"""/metrics Prometheus endpoint (format, counts, optional token gate) and the
env-gated DB driver selection defaulting to motor."""
import os, sys, asyncio, importlib
os.environ.update(MONGO_URL="x", DB_NAME="t", JWT_SECRET="x")
sys.path.insert(0, ".")
from mongomock_motor import AsyncMongoMockClient
import db as dbm; dbm.client=AsyncMongoMockClient(); dbm.db=dbm.client["t"]; db=dbm.db
import server
from fastapi.testclient import TestClient
run=lambda x: asyncio.get_event_loop().run_until_complete(x)
def a(c,m=""): assert c,m

# driver defaults to motor
a(dbm.DRIVER == "motor", f"default driver should be motor, got {dbm.DRIVER}")
print("PASS: DB driver defaults to motor (pymongo path is opt-in via USE_PYMONGO_ASYNC)")

run(db.findings.insert_many([{"id":"1","status":"New"},{"id":"2","status":"Fixed validated"}]))
run(db.remediation_campaigns.insert_one({"id":"c1","status":"active"}))
c=TestClient(server.app)
r=c.get("/api/v1/metrics")
a(r.status_code==200 and r.headers["content-type"].startswith("text/plain"), "metrics content-type")
body=r.text
a("nightwatch_up 1" in body, "up gauge")
a("nightwatch_mongo_up 1" in body, "mongo up gauge")
a('nightwatch_driver_info{driver="motor"} 1' in body, "driver info label")
a("nightwatch_open_findings 1" in body, "open findings counted (1 of 2)")
a("nightwatch_active_campaigns 1" in body, "active campaigns counted")
print("PASS: /metrics emits valid Prometheus gauges with correct counts")

# token gate
os.environ["METRICS_TOKEN"]="secret"
a(c.get("/api/v1/metrics").status_code==401, "no token rejected when METRICS_TOKEN set")
a(c.get("/api/v1/metrics", headers={"authorization":"Bearer nope"}).status_code==401, "bad token rejected")
a(c.get("/api/v1/metrics", headers={"authorization":"Bearer secret"}).status_code==200, "good token accepted")
del os.environ["METRICS_TOKEN"]
print("PASS: METRICS_TOKEN gate enforces bearer auth when set")

print("\nALL METRICS + DRIVER TESTS PASSED")
