"""recon-ng preflight: turn 'first run is a smoke test' into an observable status.

The recon-ng integration is native (shells out to recon-cli) but its own header
warns it had only ever been verified against a mocked recon-cli. A native tool
that silently isn't installed fails every run with a confusing error. This makes
the tool's presence a status the page and the self-check can read.
"""
import os, sys, asyncio
os.environ["MONGO_URL"] = "mongodb://localhost:27017"
os.environ["DB_NAME"] = "test_recon_preflight"
os.environ["JWT_SECRET"] = "testsecret"
sys.path.insert(0, ".")

from mongomock_motor import AsyncMongoMockClient
import db as db_module
db_module.client = AsyncMongoMockClient()
db_module.db = db_module.client["test_recon_preflight"]

import reconng

run = lambda c: asyncio.get_event_loop().run_until_complete(c)


# ============ recon-cli absent: that IS the answer, no exception ============

import shutil
_real_which = shutil.which
shutil.which = lambda name: None  # simulate a container without recon-cli

res = run(reconng.preflight())
shutil.which = _real_which

assert res["available"] is False
assert res["error"] and "not on PATH" in res["error"]
assert res["installed_modules"] == [] and res["version"] is None
print("PASS: with recon-cli absent, preflight reports available=false with a clear reason and "
      "raises nothing — a missing native tool is a status, not a crash")


# ============ recon-cli present: reports version + which modules are installed ============

FAKE_MARKETPLACE = """
recon-ng v5.1.2

  Path                                         Version  Status
  -------------------------------------------  -------  ---------
* recon/domains-hosts/hackertarget            1.1      installed
* recon/domains-hosts/certificate_transparency 1.0     installed
  recon/domains-hosts/bing_domain_web          1.0      not installed
"""

shutil.which = lambda name: "/usr/local/bin/recon-cli"
_real_cli = reconng._run_recon_cli


async def _fake_cli(args, timeout_sec=30):
    return FAKE_MARKETPLACE


reconng._run_recon_cli = _fake_cli
res = run(reconng.preflight())
reconng._run_recon_cli = _real_cli
shutil.which = _real_which

assert res["available"] is True
assert res["version"] == "5.1.2", res["version"]
assert "recon/domains-hosts/hackertarget" in res["installed_modules"]
assert "recon/domains-hosts/certificate_transparency" in res["installed_modules"]
assert "recon/domains-hosts/bing_domain_web" in res["missing_modules"]
print("PASS: with recon-cli present, preflight reports the framework version and splits catalogued "
      "modules into installed vs missing — so the page can say 'recon-ng ready, N/M modules "
      "installed' instead of failing a run to find out")

# only REAL recon-ng modules are checked -- the OpenCTI/GreyNoise entries are
# native-Python (module=None) and depend on their connector, not recon-cli
checked = set(res["installed_modules"]) | set(res["missing_modules"])
native_python = [m["module"] for m in reconng.MODULE_CATALOG if m.get("module") is None]
assert not (set(native_python) & checked)  # they're None anyway, but assert intent
opencti_ids = [m["id"] for m in reconng.MODULE_CATALOG if m.get("source") == "opencti"]
assert opencti_ids, "sanity: there are native-Python sources in the catalog"
assert all(not c.startswith("opencti") for c in checked)
print("PASS: preflight only inspects genuine recon-ng modules — the native-Python sources "
      "(OpenCTI, GreyNoise) depend on their own connector config, not on recon-cli being present")


# ============ a failed preflight command degrades to a message, not a crash ============

shutil.which = lambda name: "/usr/local/bin/recon-cli"


async def _boom_cli(args, timeout_sec=30):
    raise RuntimeError("recon-cli database locked")


reconng._run_recon_cli = _boom_cli
res = run(reconng.preflight())
reconng._run_recon_cli = _real_cli
shutil.which = _real_which

assert res["available"] is True   # the binary IS there
assert res["error"] and "preflight command failed" in res["error"]
print("PASS: recon-cli present but erroring reports available=true WITH the error — 'installed but "
      "not working' is a different state from 'not installed', and both are distinguishable")
