# RESUME-HERE — KingPhisher-Phoenix wave build: findings + remaining work

**Written:** 2026-08-26. **For:** any AI/engineer picking this up cold with zero prior context.
**Repo:** /Users/edierks/projects/codex-test/phishing-awareness-platform (defensive phishing-awareness
platform; NOT the offensive upstream King Phisher).
**Base commit:** `0423079` — the working tree carries ALL wave-build changes UNCOMMITTED on top of it.
No commits were made (operator will review + commit). `git diff` shows the full work; `git restore`
per-file is the rollback.

## 1. Standing authorization envelope (operator-granted)

- Operator instructed: "launch subagents to work on non-overlapping tasks and implement the
  recommendations in waves. Continue until the system is human usable." That grant stands.
- **Never commit, stage, push, or create PRs** unless the operator explicitly asks.
- **Never print values from `.env`** (real secrets live there; key names only). `.env.bak-qa` was deleted.
- Fail-closed everywhere; no AI may approve/schedule/send campaigns autonomously (platform rule).
- RED-lane items (auth/policy/crypto/audit) may be IMPLEMENTED in-tree but are flagged for operator
  review before any commit or deploy.
- Design decisions already authorized (do not re-ask): D1 approval policy, D2 domain allowlist,
  D3 hidden-char neutralization in validator, D4 enriched AI contract — specs in §5.

## 2. Where work stopped

**Updated 2026-08-26 (second pass).** Everything below is COMMITTED and PUSHED
to `origin/main`; the "no commits" rule in §1 was lifted by an explicit operator
instruction to land the work.

- **Waves 1-2 — COMPLETE, gate green.** T-01..T-05, T-07..T-10 landed.
- **T-06 — COMPLETE.** Approval policy, recipient-domain allowlist, delivery
  batching with connection reuse, stale-QUEUED reconcile, source circuit
  breaker. Also fixed an inverted `test_send` flag that let scheduled campaigns
  skip the approved-template check.
- **Wave 3 — COMPLETE.** T-11 (generation pipeline end to end + injection guard
  armed), T-12 (report view, approval lifecycle, real dialogs, live refresh),
  T-13 (distinct approvers enforced + pending demo campaign).
- **Wave 4 — COMPLETE.** T-14 (template review UI, categorised connection
  failures), T-15 (docs).
- **Azure standup — COMPLETE.** `scripts/azure_bootstrap.sh` removes day zero;
  `network_mode=starter` allows a hosted-runner first deploy; `az acr build`
  removes the Docker-daemon requirement; P-3 console honesty on Container Apps.
- **Sender-realism workstream — COMPLETE** (landed 2026-08-26, all pushed):
  sender personas (display name + local part + pool domain), DNS-challenge
  domain verification (`kp-domain-verification`), VerifiedDomain +
  RulesOfEngagement models (migration 0013), unconditional RoE gate at schedule
  and delivery, lookalike generator with ready-to-paste DNS records,
  relay-agnostic SMTP send path, onboarding wizard endpoints, and the
  neutralizer brand allowlist. New env keys: `KP_ROE_SIGNING_KEY`,
  `OPERATOR_API_DOMAIN_VERIFY_KEY`, `KP_SENDING_DOMAINS`, `KP_BRAND_ALLOWLIST`
  (generate via `scripts/bootstrap_env.sh`, then `make db-migrate` + `make seed`).

  **Safety architecture that now gates ALL delivery** (do not regress):
  recipients may only be in DNS-verified, RoE-covered target domains; a
  campaign cannot be scheduled or delivered without an active, validly-signed
  RoE; revocation fails delivery closed; a self-asserted config string is
  never proof of domain ownership. See `README.md → Sender realism` and
  `RUNBOOK.md §2.10`.

**Live dev stack state (2026-08-27):** the local stack is on `origin/main`,
migrated to head `0013` and seeded (verified example.com + signed demo RoE).
Two defects found by live verification and fixed since: migration `0009`
used `min(uuid)` (invalid SQL — no DB could upgrade past `0008`); and
`schedule_campaign` never committed `campaign.roe_id`, so deliveries failed
closed with `no_roe` despite a 200 schedule. The console now has the
persona display-name field and a full "Domains & RoE" screen (wizard,
lookalike generator, RoE sign/list/revoke). Live E2E verified: schedule
refuses out-of-RoE recipients per recipient (`refused_roe`), and a test-send
delivered `Account Security <alerts@corp-benefits.example>` through Mailpit.

Gate at the time of writing: lint clean, mypy clean on 87 source files,
541 passed / 7 skipped.

Remaining known-open items are listed at the end of
`docs/REMEDIATION_PLAN.md`; the significant one is **ARCH-7** (rate limits are
per-replica on Container Apps and need a shared store).

## 3. Findings register (consolidated 3-perspective review, 2026-08-26, HEAD 0423079)

Source reviews: `~/Downloads/kingphisher_four_perspective_review.md` (Aug-3, 8 Crit/19 High),
`~/Downloads/kingphisher_remediation_plan.md`, CROW eval
`/Users/edierks/crow/docs/audit/KINGPHISHER-PHOENIX-INTEGRATION-EVAL.md` (conditional-go, gated on
security remediation). Aug-3 findings were re-verified against current code: 19 of 27 Crit/High
already fixed by prior commits. The NEW findings below drove this build.

### Headline problems
- **P-1 (Critical, partially open):** AI-curation pipeline dead code — nothing publishes `generate`;
  no template-approval endpoint (only seed pre-approves); AI contract sends only `pattern_id`
  (no threat context); reminder/mailbox workers idle. → fixed by T-11 (Wave 3). Pattern-side
  context now exists (T-07: ATT&CK, difficulty, freshness).
- **P-2 (Critical, open → T-06):** single-admin weaponization path — DRAFT schedulable without
  approvals (routers.py ~:246), no external-recipient blocking (import ~:619-637, delivery
  ~:227-241), validator bypassable via zero-width/bidi chars (FIXED by T-01).
- **P-3 (High, deferred):** console backend writes `.env` + reads pid files (console.py) —
  meaningless on Azure Container Apps. Wizard-in-Azure story is Terraform, not console. NOT in
  this build's scope; document/flag only (T-15).

### Review findings and disposition
| ID | Finding | Disposition |
|----|---------|-------------|
| NEW-1 | ZW/bidi validator bypass | **FIXED** (T-01; 23 tests incl. 5 new) |
| NEW-2 | Two-person approval not enforced | **T-06 (open)** |
| NEW-3 | No template-approval endpoint; generation dead-end | **T-11 (open)** |
| NEW-4 | No external-recipient blocking | **T-06 (open)** |
| NEW-5 | Tracking API no body cap | **FIXED** (T-02: 64KiB cap, headers, max_length) |
| NEW-6 | Prompt-injection neutralizer dormant | **T-11 (wire into AI call path)** |
| NEW-7 | Audit verification on-demand only | **FIXED** (T-09: scheduled verify + revoke DML) |
| NEW-8 | `.env.bak-qa` stale secrets | **FIXED** (T-03: deleted) |
| NEW-9 | `.env.example` binds 0.0.0.0; dead CORS key | **FIXED** (T-03) |
| NEW-10 | `Source.consecutive_failures` dead | **T-06 (open)** |
| NEW-11 | Global kill switch advisory-only | OPEN (accepted for now; per-campaign recall is enforced) |
| NEW-12 | Pattern self-approval vacuous | OPEN (minor; T-11 may address via approved_by population) |
| ARCH-1 | Deliver message >1MB at scale; per-recipient SMTP connection | **T-06 (open)** |
| ARCH-2 | Stuck-QUEUED assignments never reconciled | **T-06 (open)** |
| ARCH-3 | Redis persistence disabled | **FIXED** (T-10: AOF + named volume) |
| ARCH-4 | RSS placeholder parser; www-redirect feeds fail | **FIXED** (T-08: feedparser + host tolerance) |
| ARCH-5 | Contracts package decorative | Partially addressed by T-11 (AI schema); full decision deferred |
| ARCH-6 | Race in open/click dedup | **FIXED** (T-02: partial unique index `uq_events_open_click_dedup`, ON CONFLICT) |
| ARCH-7 | In-memory rate limits vs multi-replica | OPEN (deferred; Azure scaling note) |
| ARCH-8 | testpaths excluded tests/; zero-marker test-contract | **FIXED** (T-03) |
| ARCH-9 | Zero tests: authorization/campaign-patterns | **FIXED** (T-04: 88 tests) |
| HIGH-02res | Non-UUID OIDC subs 500 | **FIXED** (T-05: fail-closed 403 at principal construction) |
| HIGH-13res | RSS ingestion | **FIXED** (T-08) |
| UI U-1..U-4 | Approval lifecycle invisible; stop-services no confirm; results=toast; flat connection-test errors | **T-12/T-14 (open)** |
| UI U-5..U-12 | Monitoring, CSV picker, prompt() modals, i18n, god-file | **T-12/T-14 (open)** |
| APT-1..4 | No real feeds / ATT&CK / difficulty / freshness in patterns | **FIXED pattern-side (T-07)**; source-side feeds + AI wiring = **T-11** |

### Strengths to preserve (do not regress)
Constant-time compares; JWT alg allowlists; hashed-only tracking tokens; DNS-pinned fetcher
(SSRF-safe); AES-GCM PII; hash-chained+HMAC audit; sandboxed Jinja2; zero innerHTML in SPA;
clean apps→packages DAG; production-shaped Terraform (Key Vault, managed identity, ACS).

## 4. Task registry status

| ID | Title | Status | Files (exclusive allowlist) |
|----|-------|--------|------------------------------|
| T-01 | Validator ZW/bidi fix | **DONE+verified** | packages/safety-validation/**, uv.lock |
| T-02 | Tracking body cap/headers/dedup | **DONE+verified** | apps/tracking-api/**, models.py, migration 0009 |
| T-03 | Hygiene + test infra | **DONE+verified** | Makefile, pyproject.toml, .env.example; deleted .env.bak-qa |
| T-04 | Zero-coverage package tests | **DONE+verified** | packages/{authorization,campaign-patterns}/tests/** |
| T-05 | Non-UUID principal guard | **DONE+verified** | operator auth.py, test_auth.py |
| T-06 | Approval policy + allowlist + batching + reconcile + circuit breaker | **NOT IMPLEMENTED — DO NEXT** | operator routers.py+config.py, apps/workers/**, .env.example (append), new tests |
| T-07 | Pattern enrichment (ATT&CK/difficulty/freshness + 3 bug fixes) | **DONE** (90 tests) | packages/campaign-patterns/** |
| T-08 | RSS feedparser + fetcher www-tolerance | **DONE** (40 tests) | source-adapters/**, fetcher.py, uv.lock |
| T-09 | Audit ownership + scheduled verify | **DONE+verified** (13 tests) | audit migration 0010, operator main.py, 001-roles.sh, database tests |
| T-10 | Redis persistence | **DONE** | docker-compose.yml |
| T-11 | Generation pipeline E2E | PENDING (Wave 3) | operator routers.py, apps/workers/**, packages/contracts/**, packages/authorization/src/**, sanitization neutralize.py (wire-only), infrastructure/mock-services/mock_ai.py + test |
| T-12 | UI core | PENDING (Wave 3) | apps/operator-ui/src/console/{app.js,styles.css,index.html} |
| T-13 | Seed second admin + demo approval flow | PENDING (Wave 3) | scripts/seed.py |
| T-14 | UI finish (template approve+preview, connection-test categories) | PENDING (Wave 4, after T-11) | app.js, operator console.py |
| T-15 | Docs refresh | PENDING (Wave 4) | README.md, RUNBOOK.md, docs/** |

Conflict rules: hotspots routers.py / jobs.py / app.js / models.py / .env.example / uv.lock get
ONE owner per wave. Central serial gate after every wave (§6).

## 5. Specs for remaining work

### T-06 — implement FIRST (spec was pre-authorized; see decisions D1/D2)
1. `approval_policy` setting in operator AND worker config (env `OPERATOR_APPROVAL_POLICY`,
   `enforce`|`single-admin`). oidc auth mode → effective always `enforce` (requesting single-admin
   under oidc = startup SettingsError). dev-auth default `single-admin`. When `enforce`:
   `schedule_campaign` (routers.py ~:246) rejects 409 campaigns lacking security+privacy approvals
   (routers.py ~:222 defines them); delivery (jobs.py ~:195-209) double-checks per batch, fails
   batch + audit event. Audit both paths. When `single-admin`: current behavior.
2. `allowed_recipient_domains` list (env `KP_ALLOWED_RECIPIENT_DOMAINS`) in operator+worker config.
   CSV import (~:619-637): out-of-list rows → per-row errors; oidc + empty list → refuse all imports
   (422, configure-first message); dev-auth + empty → allow-all + one audited warning per import.
   Delivery (~:227-241): out-of-list recipient → skip, mark send_failed reason `domain_not_allowed`,
   audit in batch summary. Never crash.
3. Batching: schedule path chunks assignment_ids into ≤200-id messages (routers.py ~:260-270
   currently publishes ALL ids; queue cap 1MB at packages/contracts queue.py:68); delivery worker
   reuses ONE SMTP/ACS connection per message batch (jobs.py ~:719-729 currently connects+logs in
   per recipient); per-recipient failure isolation preserved (~:172-194 semantics).
4. Reconcile: in `reconcile_campaign_lifecycle` (jobs.py ~:347-373), QUEUED assignments older than
   `KP_WORKER_QUEUED_STALE_HOURS` (default 24) on campaigns past lifecycle bounds → send_failed
   reason `stale_queued_reconcile` + audit. NO auto-resend.
5. Circuit breaker: increment `consecutive_failures` (jobs.py ~:133-135); at
   `KP_WORKER_SOURCE_FAILURE_THRESHOLD` (default 10) disable source + audit; reset on success.
6. Tests: all behaviors + failure paths; read apps/workers/tests for mock-sender fixtures.
   Append new keys to .env.example (preserve existing content). Keep
   apps/operator-api/tests/test_audit_verify_schedule.py untouched (T-09's).

### T-11 — generation pipeline E2E (Wave 3; after T-06 merges — shares routers/jobs)
1. Template approval endpoints in operator routers.py: POST approve/reject for TemplateVersion
   (DRAFT→APPROVED/REJECTED), RBAC-gated (add APPROVE_TEMPLATE capability to
   packages/authorization), audit events, no self-approval of AI-generated content by the same
   principal that requested generation where determinable.
2. Producer: on pattern approval, publish to `generate` topic (jobs/queue conventions as in
   retention self-tick, jobs.py ~:376-390).
3. Enriched AI contract (D4): `_call_ai` (jobs.py ~:629-639) currently sends only pattern_id —
   widen request to include sanitized pattern context (lure category, triggers, attack_mapping
   incl. ATT&CK/difficulty/freshness from T-07, sanitized source excerpts) run through
   kp_sanitization.neutralize (NEW-6) BEFORE leaving the process. Define request/response schema in
   packages/contracts (registry-enforced). Pass `as_of` for freshness. Response → SafetyValidator →
   TemplateVersion(DRAFT) → human approval via (1).
4. mock_ai.py: accept enriched payload; return plausible per-pattern template (subject/plain/safe_html
   honoring lure category + impersonation target); update test_mock_ai.py.
5. Tests end-to-end at unit level: pattern approve → generate publish → mock AI → validator →
   template DRAFT → approve → schedulable under `enforce` policy.

### T-12 — UI core (Wave 3; app.js/styles.css/index.html ONLY; parallel-safe with T-11/T-13)
Priority order: (1) campaign detail/report view replacing the results toast — funnel
delivered→opened→clicked→reported→training (data from existing report endpoint routers.py ~:391-427),
send-state breakdown incl. failed, per-recipient table (privacy-respecting), Download-CSV button
(existing `GET /campaigns/{id}/report.csv` ~:439-461); (2) approval lifecycle UI — "Submit for
approval" (existing `/submit` ~:151), security/privacy checklist with approver+rationale, inline
explanation of self-approval rule + policy mode; (3) confirm() on Stop/Restart services
(app.js ~:1135-1150); (4) replace prompt() modals (alert subscribe ~:760-776, rationale, evidence)
with real dialogs incl. copyable one-time signing secret; (5) CSV file-picker import with per-row
errors (API returns them); (6) 30s dashboard/campaign polling w/ last-updated; (7) login 429 shows
lockout duration + "where is my password" hint (RUNBOOK §2.1). Vanilla JS, textContent only (no
innerHTML — ever), keep CSP-self compatibility, split app.js into per-view modules only if trivially
safe (no build step). Keep everything ruff-lintable via `node --check` (Makefile lint does this).

### T-13 — seed demo (Wave 3; scripts/seed.py ONLY)
Add a second seeded admin + a pre-created pending_approval demo campaign so the two-person
approval flow is demonstrable out of the box (works under both policies). Idempotent (seed re-run
safe — existing pattern).

### T-14 — UI finish (Wave 4, after T-11): template list/approve UI + preview via existing
`/templates/preview` (~:824-869); connection-test failure categories in console.py
(`_test_smtp`/`_test_http` ~:1470-1506 currently swallow all exceptions into False — return
error_kind auth/dns/tls/timeout) rendered with specific next-step guidance (Azure SMTP auth vs
firewall). Filter pattern/template dropdowns to approved items.

### T-15 — docs (Wave 4): README/RUNBOOK — new env keys (OPERATOR_APPROVAL_POLICY,
KP_ALLOWED_RECIPIENT_DOMAINS, KP_WORKER_QUEUED_STALE_HOURS, KP_WORKER_SOURCE_FAILURE_THRESHOLD,
OPERATOR_API_AUDIT_VERIFY_INTERVAL_SECONDS), approval-policy modes + demo credentials, updated
architecture role count (8 workers), docs/architecture accuracy pass. Update
docs/REMEDIATION_PLAN.md statuses.

## 6. Verification procedure (run SERIALLY after each wave, from repo root)

```
make lint          # ruff check + format check (+ node --check on console JS)
make typecheck     # mypy strict
make test          # full pytest (some DB tests skip if Postgres down)
git diff --stat    # review for unrelated changes / secrets / debug leftovers
```
Wave-1 gate result for reference: 296 passed / 7 skipped, lint+mypy clean. Per-task suites already
green post-Wave-2: campaign-patterns 90, source-adapters+sanitization 40, T-09 13, plus Wave-1
suites. **The combined Wave-2 central gate is the first thing to run** (after T-06 lands).
Postgres/Redis/Mailpit containers may already be running (`docker ps | grep phishing-awareness`);
do not start/stop them without need. `make test` refuses if DATABASE_URL_TEST == app DB (safety).
Note: after any dependency edit, use `uv sync --all-packages` (plain sync strips workspace members).

## 7. Pending operator decisions (batch at the end; do not block implementation)

1. Review RED-lane diffs before any commit: T-01 (validator), T-05 (auth guard), T-06 (policy),
   T-09 (audit ownership), T-11 (AI contract). Nothing is committed yet — operator commits.
2. Confirm D1 default (`single-admin` in dev-auth, always `enforce` under OIDC) matches intent.
3. Deferred items NOT in this build (flag only): P-3 console/Azure .env split (deployment_mode
   gating), Redis Streams migration, shared rate-limit store, ARCH-5 contracts decision,
   NEW-11 global kill-switch persistence, app.js module split, i18n, 8-Container-Apps cost
   right-sizing, writing the empty security/ threat-model + policies/ dirs.

## 8. Context pointers

- Build plan/registry: docs/WAVE-BUILD-PLAN.md (this file supersedes its statuses)
- Prior review: ~/Downloads/kingphisher_four_perspective_review.md + kingphisher_remediation_plan.md
- CROW integration eval (gates on this remediation): /Users/edierks/crow/docs/audit/KINGPHISHER-PHOENIX-INTEGRATION-EVAL.md
- Done criteria ("human usable"): wizard → campaign create → approval legible per policy → schedule
  → delivery → results funnel + per-recipient + CSV + reported/training counts; validator bypass
  closed; allowlist enforced; generation pipeline produces approvable threat-informed templates;
  all gates green.
