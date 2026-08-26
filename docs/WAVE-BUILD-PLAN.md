# KingPhisher-Phoenix — Human-Usable Wave Build Plan

> **STATUS SUPERSEDED — see `/RESUME-HERE.md`** for current per-task status (Wave 1 done+gated;
> Wave 2 4/5 done, T-06 not implemented), remaining specs, and resume commands. This file is the
> original plan of record.

Base: clean tree at `0423079` (2026-08-26). Authorization: operator instructed autonomous
wave execution until "human usable". No commits — all work lands in the working tree,
gated serially after each wave (`make lint && make typecheck && make test`).
Conflict model: per-wave exclusive file allowlists; hotspot files (routers.py, jobs.py,
app.js, models.py, .env.example, uv.lock) have exactly one owner per wave.

## Design decisions (made under the broad grant, flagged RED for operator review)

- **D1 Approval policy** (resolves NEW-2): new `OPERATOR_APPROVAL_POLICY` = `enforce` (default
  in OIDC/production mode) | `single-admin` (allowed ONLY in dev-auth mode). `enforce` blocks
  scheduling a DRAFT without security+privacy approvals; delivery double-checks.
- **D2 Recipient-domain allowlist** (resolves NEW-4): `KP_ALLOWED_RECIPIENT_DOMAINS` enforced at
  CSV import AND at delivery. OIDC mode: fail-closed if unset. Dev-auth mode: allow-all with an
  audited warning (keeps the offline demo usable).
- **D3 Validator hardening**: zero-width/bidi neutralization wired into safety validation
  (pattern logic shared with kp_sanitization.neutralize).
- **D4 Generation contract**: AI `/propose` request enriched with sanitized pattern context
  (neutralized first), schema defined in kp-contracts; mock AI updated to match.

## Task registry

| ID | Title | Lane | Files (exclusive) | Wave |
|----|-------|------|-------------------|------|
| T-01 | Validator ZW/bidi bypass fix | RED* | packages/safety-validation/** (+uv.lock only if dep added) | 1 |
| T-02 | Tracking body cap, headers, body limits, race-safe click dedup (+unique index migration) | AMBER | apps/tracking-api/**, packages/database/src/kp_database/models.py, packages/database/alembic/versions/0006_* | 1 |
| T-03 | Hygiene + test infra (markers, testpaths, .env.example binds, rm .env.bak-qa, dead CORS) | GREEN | Makefile, pyproject.toml, .env.example | 1 |
| T-04 | Zero-coverage package tests (authorization, campaign-patterns) | GREEN | packages/authorization/tests/**, packages/campaign-patterns/tests/** | 1 |
| T-05 | Non-UUID principal guard (fail-closed 403) | RED* | apps/operator-api/src/kp_operator_api/auth.py, apps/operator-api/tests/test_auth.py | 1 |
| T-06 | Approval policy + domain allowlist + delivery batching + reconcile requeue + source failure counter | RED | apps/operator-api/src/kp_operator_api/{routers.py,config.py}, apps/operator-api/tests/*, apps/workers/** | 2 |
| T-07 | Pattern enrichment: ATT&CK IDs, difficulty, freshness | GREEN | packages/campaign-patterns/** (src+tests) | 2 |
| T-08 | Real RSS parsing (feedparser) + www-redirect tolerance | AMBER | packages/source-adapters/**, packages/sanitization/src/kp_sanitization/fetcher.py, uv.lock | 2 |
| T-09 | Audit: revoke app-role DML on audit_events + scheduled chain verification + alert | RED | packages/database/src/kp_database/audit_store.py, packages/database/alembic/versions/0007_*, apps/operator-api/src/kp_operator_api/main.py, infrastructure/containers/postgres-init/001-roles.sql | 2 |
| T-10 | Redis persistence in compose | GREEN | docker-compose.yml | 2 |
| T-11 | Generation pipeline E2E: template approve/reject endpoints, generate producer on pattern approval, enriched AI contract + neutralizer wiring, contracts schema, mock_ai update | RED | apps/operator-api/src/kp_operator_api/routers.py, apps/workers/**, packages/contracts/**, packages/authorization/src/**, packages/sanitization/src/kp_sanitization/neutralize.py (wire-only), infrastructure/mock-services/mock_ai.py, infrastructure/mock-services/test_mock_ai.py | 3 |
| T-12 | UI core: campaign detail/results view, approval lifecycle UI, stop/restart confirms, modals (no prompt()), CSV file picker, polling, lockout hint | AMBER | apps/operator-ui/src/console/{app.js,styles.css,index.html} | 3 |
| T-13 | Seed: second admin + demo approval flow | GREEN | scripts/seed.py | 3 |
| T-14 | UI finish: template approve + preview, connection-test failure categories | AMBER | apps/operator-ui/src/console/app.js, apps/operator-api/src/kp_operator_api/console.py | 4 |
| T-15 | Docs refresh (README/RUNBOOK/architecture role counts, new settings) | GREEN | README.md, RUNBOOK.md, docs/** | 4 |

*RED items are implemented in-tree but MUST get operator review before any commit/deploy.

## Waves

- **Wave 1** (parallel): T-01, T-02, T-03, T-04, T-05 → central gate.
- **Wave 2** (parallel): T-06, T-07, T-08, T-09, T-10 → central gate. (T-06/T-09 both touch
  operator-api but disjoint files: routers/config vs main.py.)
- **Wave 3** (parallel): T-11, T-12 (app.js only UI), T-13 → central gate. T-12 depends only on
  existing endpoints; T-14 (template-approve UI) follows T-11.
- **Wave 4**: T-14, T-15 → final full gate + e2e readiness check.

## Verification (central, serial, every wave)

`ruff check . && ruff format --check .` → `mypy` → `pytest` full suite → targeted review of
`git diff --stat` for unrelated changes. RED-lane diffs flagged in the final operator report.

## Done = "human usable"

Wizard → campaign create → (approval legible per policy) → schedule → delivery → results
funnel + per-recipient + CSV + reported/training counts; validator bypass closed; allowlist
enforced; generation pipeline produces approvable threat-informed templates (ATT&CK/difficulty/
freshness populated); all gates green.
