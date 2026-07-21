# Backend tests

Plain async Python scripts (not pytest-collected test functions) -- each one
seeds a `mongomock_motor` in-memory database, exercises the module/route
under test with real assertions, and prints `PASS: ...` lines ending in
`ALL ... TESTS PASSED`. Run one directly:

```
cd backend
python3 tests/test_feature_flags.py
```

No real MongoDB, network access, or external API keys are required -- every
external HTTP call (VirusTotal, HaveIBeenPwned, etc.) is mocked with a fake
`httpx.AsyncClient` where relevant.

## CI-eligible vs. reference-only

`.github/workflows/ci.yml` runs an explicit list of test files, not a blind
`test_*.py` glob, because this directory also has two kinds of tests that
can't run in a clean checkout / CI runner:

- `test_albert.py`, `test_albert_routes.py` -- depend on a real Albert
  (CIS/MS-ISAC) network-monitoring export uploaded during a local session.
  That file is real organizational telemetry, not synthetic fixture data, so
  it's intentionally not committed to the repo. The same ingestion/dedup/
  severity/stats logic they exercise is covered with synthetic data by
  `test_albert_gaps2.py`, `test_albert_ports.py`, and
  `test_asset_albert_link.py`, which ARE in the CI list.
- `test_integrations.py`, `test_iter3_admin_notif.py`, `test_iter3c.py`,
  `test_iter8.py`, `test_iter9.py`, `test_reports_iter2.py` -- older
  live-environment E2E tests that hit a real deployed URL over HTTP with
  hardcoded staging credentials (`requests` + `BASE_URL`), predating the
  self-hosted Nightwatch branch. Kept for historical reference; not runnable
  against a fresh checkout.

When adding a new test, prefer the `mongomock_motor` + direct function/route
call pattern used by the CI-eligible files, and add its filename to the
`test_files` list in `.github/workflows/ci.yml`.
