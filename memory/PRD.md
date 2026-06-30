# VulnOps — Vulnerability Operations Platform

## Original Problem Statement (summarized)
Build an enterprise vulnerability tracking and remediation platform inspired by DefectDojo. Multi-source finding ingestion (Qualys, Nessus, CrowdStrike, Wiz, GitHub, etc.), canonical normalization, dedup, triage workflow, remediation tracking, exception management, dashboards, reports, RBAC, API ingestion. Must preserve host history, support reopen-on-regression, risk scoring with breakdown, ownership confidence, SLA policies.

## Architecture
- Backend: FastAPI + Motor (MongoDB). All routes under /api. Modeled equivalently to specified Postgres schema (collections: users, assets, products, findings, observations, tickets, exceptions, engagements, integrations, import_jobs, api_keys, comments, activity_log, score_snapshots).
- Frontend: React 19 + Tailwind + Shadcn UI. Dark "Command Center" theme (IBM Plex Sans + JetBrains Mono). Routes under `/`, `/findings`, `/assets`, `/products`, etc.
- Auth: JWT + bcrypt. Roles: admin / analyst / manager / executive.

## Implemented (Feb 2026)
- Auth: JWT login, /me, logout. Cookie + Bearer support. RBAC dependency.
- Findings: list with rich filters (q, severity, status, kev, internet_facing, owner_team, product_id, asset_id, cve, view), saved views (highest_risk, kev, internet_facing_critical, overdue, reopened, patch_unavailable), bulk status, bulk assign, detail, timeline, observations, comments, status updates, prioritization preview.
- Risk scoring engine: severity baseline + CVSS + EPSS + KEV + RTI (active_attacks/zero_day/wormable/public_exploit/easy_exploit/RCE) + asset criticality + exposure + internet_facing + age + recurrence + patch unavailability, with transparent breakdown.
- Assets: list with open + critical counts, search, filters, detail with vulnerabilities + detection history + ownership confidence.
- Products: list with open/critical/asset counts, detail with assets + findings.
- Engagements / scan runs list.
- Tickets list (Jira/ServiceNow/GitHub linked to findings).
- Exceptions: list + create (auto-sets finding to "Accepted risk").
- Integrations: connector health cards (Qualys, Nessus, CrowdStrike, Defender, Wiz, GHAS, Snyk, Jira, ServiceNow, GitHub, GitLab, Azure DevOps).
- Import jobs: full ingestion log.
- Dashboards: analyst (10 stat tiles + top risk + recent imports), manager (trend + team table), executive (security score + narrative + drivers + product/env breakdown + trend chart).
- Reports: Executive PDF (reportlab), Findings CSV, Critical CSV.
- Ingestion API: POST /api/v1/ingest/universal with X-API-Key. Creates/updates findings, observations, assets (auto-create), recomputes risk, reopens on regression, preserves first_seen, writes import job. Idempotency keys supported.
- Admin: users, API keys, SLA policies view.
- Seeded ~120 findings on 12 hosts across 5 products with 30 days of trend snapshots.

## Test Credentials
See /app/memory/test_credentials.md.

## Backlog (P1 / future iterations)
- Jira/ServiceNow real sync (currently linked-only)
- Source-specific adapters: /ingest/qualys, /ingest/nessus (universal works today)
- SAML/OAuth/MFA
- Custom fields, saved filters per user
- Notification policies (email/Slack)
- Per-product SLA overrides (UI editor; backend already returns table)
- Maintenance window tracking, validation re-scan workflow
- Excel export (.xlsx) — CSV implemented

## Next Tasks
1. ~~**P2 Refactor**: Split server.py~~ **DONE**
2. ~~Replace native `<input type='date'>` in TimeRangeSelector with shadcn Calendar/Popover~~ **DONE**
3. ~~Add request debouncing on TimeRangeSelector rapid-clicks~~ **DONE** (300ms debounce, Promise.all batches the 5 reads)
4. ~~Toast feedback when `PUT /v1/me/preferences` fails~~ **DONE**
5. ~~Wipe demo data + remove example connectors + go live with Qualys VMDR~~ **DONE**
6. Adapter-specific ingestion endpoints (Tenable / CrowdStrike / Wiz / GHAS / Snyk live) — currently only Qualys is live
7. SLA editor UI
8. Notification policies (email policies; Discord already live)
9. Live OpenCTI key once user provides it
10. Fix stale credential references in `/app/backend/tests/test_reports_iter2.py`

## Qualys VMDR Live Sync (Feb 2026) — COMPLETE
- `backend/qualys_sync.py` calls `POST /api/2.0/fo/asset/host/vm/detection/?action=list` and the knowledge-base API to enrich QID → title/CVE/CVSS/CWE/solution
- Default scope: severities 4-5, status Active/Re-Opened (override via integration `config.sync_scope`)
- Auth: HTTP Basic via username + api_key (stored on Qualys VMDR integration config)
- Admin endpoints:
  - `POST /api/v1/admin/qualys/sync/run` — one-shot sync (button)
  - `GET /api/v1/admin/qualys/sync/runs` — history
  - `POST /api/v1/admin/wipe-demo-data` — delete all operational data (used once to flush seeded demo)
- Background loop: 60-min poll started in `server.on_startup`; auto-skips when integration is not configured
- Auto-creates assets on first detection (low ownership confidence so the assignment-rules engine can pick them up)
- Surfaces every run in both `qualys_sync_runs` and the standard `import_jobs` collection so the dashboard's Recent Imports panel shows live progress
- **First live run (June 30, 2026)**: 11 detections pulled, 5 real Eagle County assets created, 10 findings ingested with real CVEs (CVE-2026-21218, CVE-2026-26130, CVE-2024-34116, etc.)

## Demo-data cleanup (Feb 2026) — COMPLETE
- `seed.py` rewritten as minimal operational scaffolding (users, assignment_rules, Discord channel, API key, integration cards only)
- Other connectors (Tenable, CrowdStrike, Defender, Wiz, GHAS, Snyk, Jira, ServiceNow, GitHub, GitLab, Azure DevOps, OpenCTI) now show `not_configured` status with a grey gear icon in the Integrations UI; "Sync now" button appears only on connectors with valid credentials
- Dashboard overlap fixed: `Top Risk Findings` panel now uses `table-fixed` + `overflow-x-auto` + `min-w-0` grid children so cells truncate cleanly instead of bleeding into the right-hand `Recent Imports` panel

## P2 Refactor — server.py split (Feb 2026) — COMPLETE
Split the 1640-line `server.py` into 9 APIRouter modules under `/app/backend/routes/` to eliminate the route-placement footgun and isolate concerns:

| Module | Lines | Owns |
|---|---|---|
| `routes/common.py` | 48 | `now_iso`, `_clean`, `parse_time_range`, `finding_ctx`, `deep_merge` |
| `routes/auth.py` | 104 | login, logout, /me, Google OAuth session exchange |
| `routes/findings.py` | 442 | findings list/stats/detail/KRI/timeline/observations/tickets/comments/status/bulk + attack-paths + CWE prevalence + threat-intel + findings-groups + prioritization |
| `routes/inventory.py` | 97 | assets, products |
| `routes/workflows.py` | 66 | engagements, tickets, exceptions |
| `routes/integrations.py` | 226 | integrations CRUD + import-jobs + universal ingestion |
| `routes/dashboards.py` | 205 | analyst, manager, executive, operational |
| `routes/reports_routes.py` | 133 | CSV, PDF, catalog, prebuilt + custom runner |
| `routes/admin.py` | 299 | users, notifications, assignment-rules, ownership, SLA, API keys, nightly-rescore |
| `routes/preferences.py` | 49 | `GET/PUT /v1/me/preferences` |
| `server.py` | **87** | thin wiring — creates app, includes routers, mounts CORS + startup hook |

Verified by:
- 13/13 `test_iter3c.py` pytest suite green
- 28/28 endpoint smoke curl returns HTTP 200
- Frontend dashboard renders identically post-refactor

## Iteration 3c (Feb 2026) — COMPLETE
**P0 fix**: nightly-rescore + CWE prevalence routes were defined AFTER `app.include_router(api)` → moved above. All endpoints return 200.

**Configurable dashboards**:
- All three dashboard endpoints (`/v1/dashboards/analyst|manager|executive`) accept `range` query param (7d / 30d / 90d / 4mo / 6mo / 12mo / custom with start+end).
- New helper `parse_time_range()` in server.py.

**Tile picker & saved layouts (per-user)**:
- New endpoints: `GET /v1/me/preferences`, `PUT /v1/me/preferences`. MongoDB collection `user_preferences` stores `{dashboard:{range,tiles}, findings:{group_by,view_mode}}`.
- New frontend components: `TimeRangeSelector`, `TilePicker`, `usePreferences` hook (debounced auto-save).

**Findings grouping**:
- New endpoint `GET /v1/findings-groups?group_by={none|cve|os|title|severity|asset}&view_mode={by_asset|by_vulnerability}`.
- Findings page renders grouped accordion when `group_by !== "none"`; clicking a group expands to list its child findings.
- View mode toggle differentiates "by asset" (rows = asset×CVE) vs "by vulnerability" (rows = CVE, with `asset_count`).

**Test coverage**: `/app/backend/tests/test_iter3c.py` — 13/13 backend tests + 8/8 frontend scenarios green (see `/app/test_reports/iteration_7.json`).
