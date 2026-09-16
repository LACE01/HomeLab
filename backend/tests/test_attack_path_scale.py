"""Attack Path analysis must not explode on a large flat segment.

The reported crash: "Run Analysis" kills the container. Root cause is quadratic
graph construction -- same-segment edges were built all-pairs, so one big flat
segment (hundreds/thousands of hosts that all resolve to one segment) produced
millions of edge dicts and OOM'd the API before enumeration even ran -- compounded
by an unbounded BFS frontier. These tests lock in the bounds.
"""
import os, sys, asyncio, time
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_attack_path_scale"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_attack_path_scale"]
db = db_module.db

import attack_path_engine as ape
run = lambda c: asyncio.get_event_loop().run_until_complete(c)
def a(c, m=""): assert c, m


# ---- a large, flat segment: the pathological all-in-one-subnet case ----
N = 900
assets = []
for i in range(N):
    assets.append({
        "id": f"h{i}", "hostname": f"host-{i}", "ip": f"10.0.{i // 256}.{i % 256}",
        "segment": "flat", "owner_team": "IT",           # same team -> would be all-pairs
        "open_ports": [3389] if i % 50 == 0 else [80],   # a few RDP pivots
        "criticality": "critical" if i < 3 else "medium",
    })
run(db.assets.insert_many(assets))
# one internet-facing, exploitable entry host
run(db.assets.update_one({"id": "h0"}, {"$set": {"internet_facing": True, "open_ports": [443, 3389]}}))
run(db.findings.insert_many([
    {"id": "f1", "asset_id": "h0", "severity": "Critical", "kev_flag": True, "status": "New",
     "title": "RCE", "cve": "CVE-2024-1"},
]))

# Naive all-pairs would be ~900*899 ≈ 800k+ edges for this ONE segment. Bounded
# construction must keep it far below that.
t0 = time.time()
graph = run(ape.build_environment_graph(db))
build_secs = time.time() - t0
a(len(graph["edges"]) <= ape.MAX_TOTAL_EDGES,
  f"edges {len(graph['edges'])} exceeded the global cap {ape.MAX_TOTAL_EDGES}")
# per-source fan-out is capped, so total host->host edges << N*(N-1)
a(len(graph["edges"]) < N * ape.SEGMENT_FANOUT_CAP + N,
  f"fan-out not bounded: {len(graph['edges'])} edges")
a(build_secs < 20, f"graph build took too long ({build_secs:.1f}s) — likely still quadratic")
print(f"PASS: a {N}-host flat segment builds a BOUNDED graph ({len(graph['edges'])} edges, "
      f"{build_secs:.1f}s) instead of ~{N*(N-1)} all-pairs edges that OOM'd the container")


# ---- enumeration is bounded in time on that dense graph ----
t0 = time.time()
paths = ape.enumerate_paths(graph, max_hops=8, max_paths=200)   # max_hops=8 is the worst case
enum_secs = time.time() - t0
a(enum_secs < 20, f"enumeration took too long ({enum_secs:.1f}s) — BFS frontier not bounded")
a(len(paths) <= 200, "path cap respected")
print(f"PASS: path enumeration on the dense graph at max_hops=8 stays bounded "
      f"({len(paths)} paths, {enum_secs:.1f}s) — the BFS frontier can't balloon")


# ---- the full run completes and persists ----
t0 = time.time()
res = run(ape.run_attack_path_analysis(db, max_hops=6, max_paths=200))
a(time.time() - t0 < 30, "full analysis too slow")
a("summary" in res and "paths_found" in res["summary"], list(res.keys()))
print(f"PASS: run_attack_path_analysis completes end to end on a large environment "
      f"({res['summary']['paths_found']} paths) without exhausting memory or time")

print("\nALL ATTACK PATH SCALE TESTS PASSED")
