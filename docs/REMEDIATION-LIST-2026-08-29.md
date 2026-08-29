# Remediation & Optimization List — 2026-08-29

Findings from a fresh review of the current tree (`main`, local head
`4ac0e9a`, 2 commits ahead of `origin/main`). Evidence lines verified in code.
Lint/format/typecheck are green (ruff 0 findings, 361 files formatted, strict
mypy 133 source files). This list is for subsequent remediation; nothing here
is a new production/RSA gate.

---

## A. Doc drift (stale facts that mislead the next session — HANDOFF-005 class)

| # | Location | Stale claim | Actual |
|---|---|---|---|
| A1 | `RESUME-HERE.md:325` | `origin/main is 8f02191` | `origin/main` is `5ab56e6`; local is ahead 2 (`506b716`, `4ac0e9a`) |
| A2 | `RESUME-HERE.md:331` | typo "model selection/**deplyment**" | should read "deployment" |
| A3 | `docs/NEXT_SESSION_HANDOFF.md:106` | `origin/main is 8f02191` | `5ab56e6`, ahead 2 |
| A4 | `docs/WAVE-BUILD-PLAN.md:179` | "At checked-in head `0032_source_explicit_curation`, `make test` passed 2,620… mypy (131 source files)" | head is `0033_training_knowledge_check`; hermetic **2,683**/103; mypy **133** source files |
| A5 | `docs/WAVE-BUILD-PLAN.md:180` | "Current-head `0032` results… hermetic 2,620" | Current-head is `0033`; hermetic 2,683 |
| A6 | `docs/WAVE-BUILD-PLAN.md:183` | "Current-head `0032` migration gate" | Fresh-install/historical migration passed at head `0033` |
| A7 | `docs/WAVE-BUILD-PLAN.md:193` | "Current-head `0032` evidence… hermetic 2,620" | Same as A4/A5 |

Fix: one pass over RESUME-HERE + NEXT_SESSION_HANDOFF + WAVE-BUILD-PLAN updating
SHA, head, and counts; re-run the handoff contract (`tests/test_external_worker_handoff_contract.py`, 17 tests) and the doc-pinning tests.

## B. Bugs / behavioral issues (verified, low severity)

| # | Finding | Evidence | Suggested fix |
|---|---|---|---|
| B1 | Tracking rate-limit backend defaults to `memory`; the **global 3,000/min limit is per-replica** in a multi-replica managed deployment, weakening linearly with replica count | `apps/tracking-api/src/kp_tracking_api/config.py:59` | Default `redis` in managed runtime modes, or document the per-replica consequence |
| B2 | `_ip_rate_limited` uses `_client_ip(request) or "unknown"` as a limiter key — all IP-unresolvable requests share one 60/min bucket | `apps/tracking-api/src/kp_tracking_api/routers.py:177` | Acceptable today (can't spoof trusted-proxy chain); document the collapse or reject unresolvable IPs |
| B3 | `email_provider == "azure_communication_services"` string fork appears **9×** across `config.py` + `jobs.py`; provider selection is string-typed at call sites, not a resolved strategy | `apps/workers/src/kp_workers/jobs.py:623,977,1465,1479,2274,2741`; `config.py:273,366,448` | Introduce a resolved `EmailProvider` strategy object; kills the F-1-class drift risk |
| B4 | `ACS delivery pacing is not configured` raises bare `RuntimeError` | `apps/workers/src/kp_workers/jobs.py:898` | Dedicated `DeliveryConfigurationError` for greppable logs |
| B5 | `views["azure-deployment"]` uses bracket notation while all other views use dot notation | `apps/operator-ui/src/console/app.js:1327` | Cosmetic; normalize for a future nav lint |
| B6 | 284 `type: ignore` + 159 `noqa` across apps/packages (128+78 in operator-api alone) | grep audit | Mostly legitimate (ssl/bleach arg-type pins, documented fail-closed BLE001); periodic audit to confirm none mask a real defect |

## C. Dead / unwired / unused (verified clear — no action required, listed for the record)

- All 13 packages have live consumers (verified per-package: source-adapters →
  workers; domain-verification → operator API; campaign-patterns →
  threat_routes + workers; safety-validation/sanitization/telemetry → apps).
- All 10 `kp_database` modules have ≥1 consumer; `training_builder` (1),
  `privacy` (12), `audit_store` (16) all wired.
- `scripts/azure_preflight.sh`, `azure_bootstrap.sh`, `azure_mail_check.sh`,
  `entra_graph_preflight.sh` are **not dead** — documented manual operator
  tools in `docs/AZURE_DEPLOYMENT.md` (lines 228, 252, 785, 605); `azure_release.sh`
  invoked by `azure-deploy.yml:2310`; `azure_migrate.py` invoked by
  `infrastructure/terraform/main.tf:1537`.
- `scripts/supervisor.py` wired via `scripts/run_console.sh:200` + launcher
  contract tests; mock services wired via `docker-compose.yml` (idp 8443,
  graph 8181, ai 8282); `content_library.py` consumed by `routers.py`.
- No tracked `__pycache__`/`.pyc`; no empty tracked dirs; no TODO/FIXME/XXX/HACK
  markers; no duplicate route paths (the two `@router.get("")` are
  router-prefix roots in `threat_routes.py` and `program_routes.py`).
- `sanitize_html` consumed via `source-adapters/common.py`; `strip_tracking`
  used internally + tested — not orphaned.

## D. Known debt carried from `docs/REVIEW-2026-08-29.md` (unchanged, still open)

| # | Item | Status |
|---|---|---|
| D1 | Monolith modules: `routers.py` 5,418 / `console.py` 4,154 / `deployment_orchestration.py` 3,112 / `jobs.py` 2,809 / `app.js` 6,792 | Open — split at file level into domain packages |
| D2 | No behavioral UI test harness (only string-contract tests) | Open — minimal DOM/Playwright smoke first |
| D3 | Ledger/trend data rendered as tables, no chart | Open — accessible SVG + table fallback |
| D4 | 8 qualification lanes (images → registry → E2E → browser/WCAG → Azure → recovery → witness → acceptance) all NO-GO | Open — external, recorded order |
| D5 | CSP question: **resolved** (five inline styles fixed + `test_console_csp_contract.py`) | Closed — browser lane remains a confirmation |

## E. Optimization opportunities (non-blocking)

| # | Opportunity | Notes |
|---|---|---|
| E1 | Un-defer UX-010 navigation grouping (17 nav items → ~5 clusters) | Serves the two-IT-staff objective directly |
| E2 | Scheduled report delivery on existing alert/webhook infra | "Email me the monthly trend CSV" |
| E3 | Cache SPF pre-flight per campaign (verify — currently runs per `process_delivery`, not per recipient; check placement in batch loop) | Verify at `jobs.py:1461` is pre-batch; if per-message in a large batch, hoist |
| E4 | `_CountingResponse` (AI-010) — acceptable; fold byte-counting into the base reader next time | Design note, not an action |
| E5 | Re-verify `rate_limit_backend` default once managed topology is qualified (ties to B1) | Ties to B1 |

## Suggested execution order

1. **A1–A7 doc drift** (fast, low-risk, high value — READ ORDER correctness).
2. **B3 provider strategy refactor** (largest risk-reduction code change).
3. **B1/B2 rate-limit posture** decision (one line + doc).
4. **D1 modularization** (file-level splits, no behavior change; do with the
   next feature touch to avoid churn).
5. **D2 first behavioral UI test**, then **D3 chart**.
6. E1/E2 opportunistically; D4 only when external environments are available.

Gates after this list: lint ✓, format ✓, mypy ✓ (133), hermetic 2,683,
PostgreSQL 92, Redis 2, fresh-migration 1 — re-run any touched suite with the
fix.
