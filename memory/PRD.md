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
1. User feedback round
2. Add adapter ingestion endpoints (Qualys / Nessus specific)
3. SLA editor UI
4. Notification policies
