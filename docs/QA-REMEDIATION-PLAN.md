# QA Remediation Plan — response to QA-REVIEW-2026-09-27

Companion to `docs/QA-REVIEW-2026-09-27.md`. That report's findings were
spot-verified against live code before this plan was written — F1
(`main.py:660` TODO + `providers/alerts.py` exists), F2 (`config.py`
`default=False`), F9 (`api()` has no `AbortSignal`) and H5
(`OPERATOR-GUIDE.md` stated two-person approval as unconditional) were all
confirmed true. The report is accurate.

Prioritisation here is re-ordered against the operator's standing directive —
**get on-prem ready for human use first; deprioritise overengineering** — not
adopted from the report's ordering wholesale. Nothing changes the **NO-GO**
status or the rules in `AGENTS.md`; all work is additive and gate-tested.

## Tier 1 — safety-critical + trivially correct (in progress)

| Item | Finding | Status |
| --- | --- | --- |
| Correct the OPERATOR-GUIDE approval rule to be mode-aware (and fix a second contradiction the report missed: the allowlist "fails closed" claim, changed by PR #68 for single-operator) | H5 | **this PR** |
| Wire the AUD-003 anchor-staleness gate to the existing alert provider, with a hermetic test | F1 | Tier 1 |
| Add a fetch timeout + one idempotent-GET retry to the console `api()` helper | F9 | Tier 1 |

## Tier 2 — human-usable for the 1–2 operator case

| Item | Finding |
| --- | --- |
| Surface aggregation scheduler / data-staleness state in the Aggregation view | F2 |
| Consolidate stop controls (one Stop, two scopes) and launch verbs ("Send test to canary" / "Send to everyone") | H3, H4 |
| First-campaign "what's missing" checklist as the landing view until first publish | §2.2-1 |
| Combined pattern + draft review on one screen in single-operator mode | §2.2-3 |
| **CI-able console behavioural smoke test** — elevated: the 2026-09-26 browser pass found two real bugs (badge glue, More-wrap) that all ~25 string-grep contract tests missed, so the behavioural-coverage gap is proven, not theoretical | F10 |

Do the console smoke test first in this tier; it de-risks every subsequent UI change.

## Tier 3 — real features, bigger, gate each

Status (2026-09-27):
- **H8** system-alert channel + decision-needed nudge — DONE (settings-based; no migration).
- **H11** post-publish closure banner — DONE.
- **H12** recipient free-text search — **descoped as specified.** The report wanted a
  server-side `?q=` prefix filter, but `recipients.mailbox`, `.display_name` and
  `.department` are all `CipherText` (encrypted at rest), so the database cannot
  search them; only exact mailbox lookup (via `mailbox_sha256`) is possible, and
  it already exists. A client-side filter over the loaded page is feasible but
  marginal at the 125-recipient target where department filtering already exists.
  Recorded rather than half-built.
- **H10** weekly digest — DONE (reuses the H8 channel).
- **H9** send-time spread — DONE. Opt-in `campaigns.spread_over_hours` (migration
  `0040`, nullable, bounded 1..168; null = the original single burst, so every
  existing campaign is unchanged). The spread is applied at publish time in
  `_publish_delivery_batches`: when set, only the **full** phase subdivides the
  audience into smaller, time-slotted batches whose `available_at` is staggered
  evenly across the window from the start time. This changes only *when* each
  batch becomes claimable — the delivery worker's gate order (emergency stop →
  state → launch → template → manifest → approval → RoE → per-recipient →
  capacity) is untouched and runs in full for every batch. The **canary** phase
  is never spread (evidence must land promptly), and batch size never exceeds
  the configured cap, so the 1 MiB queue-payload guarantee holds. Console
  exposes an optional "Send-time spread (hours)" field on campaign create.
  Tests: `apps/operator-api/tests/test_send_time_spread.py`.


Decision-needed notifications (H8 — reuses the F1 alert wiring), post-publish
closure banner (H11), recipient free-text search (H12), send-time spread
(H9, per UX-011 §6), weekly digest (H10).

## Cheap wins — status (2026-09-27)

- **F4** bundle "generated" banner — **DONE.** `build-console.mjs` now emits a
  three-line `GENERATED FILE — DO NOT EDIT` banner via esbuild `banner.js`; the
  drift gate mirrors the same string in its direct esbuild invocation, so the
  banner can never go stale.
- **F6** stale-handoff archive — **PARTIAL (done for the 8 that were safe).**
  `git mv`'d the six dated `AI_HANDOFF_2026-09-*.md`, `AUDIT_REPORT_2026-09-14.md`
  and `NEXT_AI_PROMPT.md` into `docs/archive/` (history preserved) with a pointer
  README. **`RESUME-HERE.md` and `QA_TASKS.md` were deliberately left at the root**:
  `tests/test_external_worker_handoff_contract.py` pins them as *current-state
  handoffs* that must carry the external-worker/.140 boundary truth. That guard
  belongs to the DR/external-worker workstream, so relocating those two is out of
  this lane; archiving them would require changing that contract.
- **F3** otel-collector removal — **DONE.** Gated behind an opt-in
  `observability` compose profile (mirrors `ai-gateway`'s `ai` profile) and
  removed from every default bring-up and the readiness contract:
  `docker-compose.yml`, `operational_readiness.sh`, `run_console.sh`,
  `install.sh`, `verify_install.sh`, `Makefile` (dev + mock-stack) and the
  readiness test mock (`test_readiness_harness.py`). Start it explicitly once a
  real OTLP exporter is wired: `docker compose --profile observability up -d
  otel-collector`. Reversible — nothing deleted.

## Dropped or deferred (over-engineering / low value for this tenant)

- **F13** app.js module split — pure maintainability churn; skip unless it starts hurting.
- **F8** test-date semgrep, **F5** supervise per-role DB env, **F12** `_as_utc` writer discipline — CI/edge hygiene, low value for a single-tenant on-prem deploy. Backlog.
- **F10** — the nav smoke spec was made robust to live state (badge-independent
  `data-nav` locator; onboarding-aware §2.2-1 landing assertion) and all four
  specs pass against the live .105 console. The remaining backlog piece is a
  *tunnel-free* CI target (`docker-compose.e2e.yml`-based `make` target) so the
  behavioural net runs without a manual tunnel; the specs themselves are sound.
- **F7** AI model-pin self-check, **F11** remaining `slice(0,8)` UUID label sites — backlog.
- **H1** Azure console surface reduction, **H2** Mailpit-first onboarding finish, **H6** sidebar count, **H7** Program Planner vocabulary — UX polish; H1 deferred with Azure itself.

## Sequencing

Tier 1 (3 small PRs) → Tier 2 console smoke first → Tier 2 UI changes →
Tier 3 interleaved by gate-review capacity. The alert wiring (F1) is a shared
dependency of H8, so it lands early.
