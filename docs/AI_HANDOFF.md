# Kingphisher-Phoenix — AI Handoff (Architecture · Functionality · Coding)

Written for a fresh AI engineer to start enhancing the codebase immediately,
without human Q&A. Read `README.md` and this file end to end, then run the
verification commands in §9 to confirm the environment. Everything stated here
is verified against the current `main`.

---

## 0. One-paragraph summary

A production-oriented, explicitly single-tenant phishing-awareness platform: an operator drives campaigns
through a browser-only console (vanilla-JS SPA served by the operator API), the
backend ingests threat intel from sources, deterministically generates/sanitizes
campaign content, delivers personalized HTML mail with tracking tokens through a
local SMTP relay, tracks opens/clicks via a stateless pixel API, and logs every
mutation into an append-only hash-chained audit. It is GUI-only, offline-first
(Postgres/Redis/Mailpit/mocks in Docker), Python 3.13 + FastAPI + SQLAlchemy 2 +
uv workspaces, with eight Redis-queue workers and a fail-closed security model.
Azure deployment is automated through Terraform and a protected GitHub workflow;
the console includes non-secret, optionally AI-assisted integration and Azure
deployment wizards.

---

## 1. Repository layout & dependency order

```
apps/operator-api/   FastAPI :8000 — control plane + console endpoints + SPA mount (/console)
apps/operator-ui/    Vanilla-JS console (NO build step — edit app.js/styles.css directly)
apps/tracking-api/   FastAPI :8001 — stateless pixel/click/correction endpoints
apps/workers/        kp-worker CLI, eight roles: ingestion, generation, delivery,
                     retention, mailbox, reminder, alert, directory
packages/            domain-models, contracts, database, auditing, authorization,
                     sanitization, safety-validation, templating, source-adapters,
                     campaign-patterns, telemetry, test-fixtures
scripts/             install.sh, run_console.sh, verify_install.sh, supervisor.py,
                     bootstrap_env.sh, seed.py, verify_audit.py, build_launcher_app.sh
infrastructure/      Docker services, Azure Terraform, Postgres bootstrap, mocks, otel
docs/                architecture/ (service/zone matrix), AI_HANDOFF.md (this file)
RUNBOOK.md           operator runbook (install/ops/troubleshoot)
QA_TASKS.md          QA findings from the 2026-08-04 console pass (bugs, all fixed)
```

Package dependency order (packages import only from earlier ones):

```
domain-models → contracts → database → auditing → authorization → sanitization
→ safety-validation → templating → source-adapters → campaign-patterns → telemetry
→ test-fixtures
```

Apps depend only on packages — **never import across apps**. Keep it that way.

---

## 2. Stack & tools

- Python 3.13, managed by **uv** (`uv sync --all-packages`, `.venv` at repo root).
- FastAPI + pydantic v2 (`pydantic-settings`, env-prefixed: `OPERATOR_API_*`,
  `TRACKING_API_*`, `KP_WORKER_*`, `KP_CONSOLE_*`).
- SQLAlchemy 2 (typed `Mapped[]` ORM), Alembic migrations, one head.
- Postgres 16 (roles: `kingphisher` app owner, `audit_writer` insert-only for
  audit, created by `infrastructure/containers/postgres-init/`).
- Redis 7 as the job queue (see `packages/contracts` for the queue registry).
- structlog (telemetry), Jinja2 (sandboxed templating), PyJWT (console HS256).
- Docker Compose: postgres, redis, mailpit (SMTP relay + UI), otel-collector,
  mock-idp :8443, mock-graph :8181, mock-ai :8282.
- Gate: `uv run pytest -q` (183 tests), `make lint` (Ruff plus console syntax),
  `make typecheck` (mypy strict, 74 files), `make security-scan`, and
  `make operational-readiness` (7 live tests at the 2026-08-18 full gate).

---

## 3. Core domain model (`packages/domain-models` + `packages/database`)

Enums (`kp_domain_models/models.py`): `SourceType`
(`advisory|rss|stix|bulk_download|curated`), `LureCategory`, `CampaignState`
(`draft|pending_approval|scheduled|active|completed|expired`), `ApprovalType`
(security/privacy), `RecipientStatus`, `SendState`, `TokenStatus`, `EventType`,
`PrivacyRequestType` (`search|access_export|correction|deletion|exception`),
`AuditOutcome`.

ORM entities (`kp_database/models.py`):

| Entity | Notes |
|---|---|
| `Source`, `SourceTerms`, `SourceItem` | threat intel; items flow to generation |
| `CampaignPattern` | lure pattern (category, review state) |
| `TemplateVersion` | sandboxed campaign templates (versioned) |
| `Campaign` | direct operator lifecycle + pattern link; legacy approval states remain readable |
| `CampaignApproval` | compatibility record for legacy security/privacy review routes |
| `Recipient` | identity fields AES-256-GCM encrypted via `CipherText` type; `mailbox_sha256` = salted hash (`hash_mailbox`) |
| `RecipientExclusion`, `TrainingAssignment` | suppression / training links |
| `TrackingToken` | 256-bit token stored hashed; `status`, `revoked_at/reason`; `recipient_assignment_id` |
| `RecipientAssignment` | campaign→recipient join, `send_state`, delivered data purge by retention |
| `TrackingEvent` | pixel/click rows keyed by token hash (minimized) |
| `PrivacyRequest`, `PrivacyNotice`, `RetentionPolicy`, `RetentionAction` | CCPA + retention (0005) |
| `AuditEvent` | append-only hash chain; INSERT-only role `audit_writer` |

Migrations: `packages/database/alembic/versions/0001..0008_source_fetch_path.py`.
`0001` is `Base.metadata.create_all` (fresh installs already contain later
objects), so every later migration is written **idempotently** with inspector
guards (`_has_table/_has_column/_has_constraint/_has_fk_to/_has_index`) and
`_recreate_fk_cascade`. Follow that pattern for 0006+.

---

## 4. API surface

### 4.1 Operator API (`apps/operator-api/src/kp_operator_api/`, prefix `/api/v1`)

Auth: bearer JWT (OIDC or console password session). Dependency pattern used by
every route:

```python
@router.post("/things", status_code=status.HTTP_201_CREATED)
def create_thing(
    body: ThingCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_THINGS)),
) -> dict[str, Any]:
    # ...mutate, then:
    audit.record(
        actor=principal.principal_id,
        action="thing.create",
        object_type="thing",
        object_id=str(thing.id),
        detail={...},
    )
    session.commit()
    return {...}
```

Capabilities: `Capability` enum in `kp_operator_api.auth`; multi-role routes use
`require_any_capability(...)`. Errors use the fail-closed taxonomy `KP-001..010`
(`kp_operator_api` error module) — `NotFoundError`, `ConflictError`,
`AuthenticationError`, `ValidationError_`, etc. Never raise HTTPException raw.

Routes (all under `/api/v1`): `/console/session|config|status|restart|stop`,
`/console/onboarding` (GET state, PUT allowlisted wiring) and
`/console/onboarding/test` (bounded transient connection checks),
`/console/help` (curated glossary/topics), and `/console/onboarding/assist`
(privacy-filtered advisory AI with deterministic fallback);
`/campaigns` (CRUD + preview + send); `/campaigns/{id}/approve` patterns;
`/recipients`, `/recipients/import` (CSV text body),
`/recipients/sync-directory` (queue bounded Graph-compatible sync); `/recipients/{id}` DELETE
(DSR path); `/sources` (**POST-only**, create); `/patterns`,
`/patterns/{campaign_pattern_id}/approve`; `/templates`; `/privacy/notice`,
`/privacy/requests` (submit, list, `/{id}/verify`, `/{id}/export` **GET**,
`/{id}/fulfill` POST body `{}` or `{"note": ...}`); `/audit` (list),
`/audit/verify` (**POST, no body** — whole-chain check → `{"ok", "problems"}`);
`/kill-switch` **POST** (body `{"confirm": true[, "campaign_id"]}`; global or
scoped) **and GET** (state readback from latest global `kill-switch.engage`
audit event → `{engaged, engaged_at, actor, last_cancelled, last_tokens_revoked}`).

### 4.2 Console endpoints (`kp_operator_api/console.py`)

- `POST /api/v1/console/session` — password (from on-disk `.env`
  `KP_CONSOLE_PASSWORD`, constant-time compare, login throttling) → 8h HS256
  JWT with `realm_access: ["administrator"]`.
- `GET /api/v1/console/config` — masked `.env` read (secrets blanked + `masked`
  map); `PUT` — allowlist-only keys (`_ALLOWED_KEYS`).
- `GET/PUT /api/v1/console/onboarding` — secret-safe connector metadata and
  allowlisted persistence; `POST /onboarding/test` — bounded OIDC, Graph, AI,
  SMTP, mailbox, training, and webhook checks.
- `GET /api/v1/console/help` — curated plain-language terminology and setup
  topics. `POST /onboarding/assist` — sends only allowlisted non-secret values
  to the configured `/setup-assist` provider, validates its bounded response,
  filters cross-step/credential suggestions, and falls back to local guidance.
  It never persists prompts, answers, or suggestions and never applies changes.
- `GET /api/v1/console/azure-deployment` — four-stage non-secret Azure setup
  schema with prerequisites and per-field source guidance; `POST
  /azure-deployment/validate` — deterministic validation for Azure, Entra, DNS,
  AI gateway, webhook-domain, runner, and Terraform-state values. Neither route
  persists configuration or starts a deployment.
- `GET /api/v1/console/status` — pidfile-based alive flags for the APIs +
  eight workers; `POST /restart` / `POST /stop` — marker files in `data/run/`.

### 4.3 Tracking API (`kp_tracking_api/`)

Pixel/click endpoints keyed by **hashed token only** (no plaintext tokens), with
per-IP/per-token rate limits and a corrections endpoint guarded by
`TRACKING_API_CORRECTIONS_SECRET` (bearer). Trusted proxies parsed from
`TRACKING_API_TRUSTED_PROXIES`.

---

## 5. Console SPA (`apps/operator-ui/src/console/`)

- Vanilla JS, `"use strict"`, no framework, no build step. Helpers: `el(tag,
  attrs, children)`, `api(path, opts)` (JSON + bearer), `toast(msg, kind)`,
  `views.<name>(root)` registry, sessionStorage JWT.
- CSP served by operator-api: `default-src 'none'; script-src 'self';
  style-src 'self'; connect-src 'self'; img-src 'self'` + `X-Frame-Options:
  DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
  **No external assets, no inline scripts/styles** — future UI code must obey.
- The API field for privacy requests is `privacy_request_id` (fix BUG-3);
  kill-switch state is read via GET `/kill-switch` (BUG-2) — do not re-add
  `r.request_id` or a PUT kill-switch.
- `node --check apps/operator-ui/src/console/app.js` is NOT part of the gate
  yet (BUG-4 happened because of it) — run it manually and consider adding it
  to `make lint`.

---

## 6. Workers & queues (`apps/workers/`)

`kp-worker <role>` consumes Redis queues (registry in `packages/contracts`).
Roles:

- `ingestion` — source adapters (RSS/Graph) via `SecureFetcher` (allowlisted
  HTTPS, size/content-type caps, blocked-network denial) → sanitize → source_items.
- `generation` — builds campaign content with sandboxed Jinja2 from approved
  patterns/templates; content must pass the deterministic safety validator
  (GEN-004: rejects external links, shorteners, credential/MFA/install/command
  patterns, executables) before delivery.
- `delivery` — sends personalized HTML mail via Mailpit SMTP (`localhost:1025`),
  SPF-checked; marks assignments DELIVERED; appends audit events.
- `retention` — policy-driven purge of delivered assignments/tokens per
  `RetentionPolicy`; self-publishes default policy if absent
  (`maybe_publish_retention`).
- `mailbox` — simulated inbox behavior for mocks; `reminder` — nudges.
- Worker settings all `KP_WORKER_*` (DSNs, HMAC key, KEK, SMTP, base URLs,
  poll seconds). Test pattern in `apps/workers/tests/test_retention.py`.
- `alert` — validates allowlisted webhook destinations, signs deliveries,
  retries transient failures, and dead-letters exhausted messages. ntfy works
  through the same generic HTTPS webhook contract.
- `directory` — performs bounded Graph-compatible directory synchronization.

Worker logs are size-bounded, rotated, and compressed by the supervisor.
Redis/provider connection failures back off; do not reintroduce tight-loop
exception logging. Treat manual log deletion as destructive and obtain explicit
authorization first.

---

## 7. Security model — non-negotiable invariants

1. **Audit** — INSERT-only (`audit_writer` role), SHA-256 hash chain + HMAC head
   (`kp_auditing`, `AuditStore`); verify via `make verify-audit` /
   `POST /audit/verify`. Never add UPDATE/DELETE paths to `audit_events`.
2. **RBAC** — capability checks restrict campaign scheduling and administration.
   The normal SMB console path allows one authorized administrator to create and
   schedule a draft directly; legacy approval routes remain for compatibility.
3. **Safety** — deterministic validation outside any AI model
   (`kp_safety_validation`); gates save and pre-delivery.
4. **Sanitization** — allowlisted fetching + HTML→plain-text + instruction/
   Unicode neutralization (`kp_sanitization`).
5. **Secrets** — only in `.env` (gitignored), generated once by
   `bootstrap_env.sh`; KEK/HMAC/JWT must be **64 hex chars**; console JWT in
   `sessionStorage` only; `KP_CONSOLE_PASSWORD` never echoed to stdout.
6. **Encryption at rest** — AES-256-GCM `CipherText` column type (KEK from
   `.env`); tokens stored hashed.
7. **Fail-closed errors** — `KP-001..010` taxonomy; no raw HTTPException.

---

## 8. Testing & gate

```bash
make test            # 183 passed at the 2026-08-18 full gate
make lint            # ruff check + format plus node --check for console JavaScript
make typecheck       # mypy strict (74 files at handoff)
make verify-audit    # recompute audit chain
make verify-install  # health-check a live install (infra, APIs, console auth, pidfiles)
make operational-readiness # disposable-local full gate plus live HTTP E2E smoke
make security-scan   # Semgrep plus Trivy dependency/secret scanning
terraform fmt -check -recursive infrastructure/terraform
terraform -chdir=infrastructure/terraform validate
trivy config --exit-code 1 --severity HIGH,CRITICAL infrastructure/terraform
```

The readiness E2E is dependency-free HTTP coverage. It logs in, validates
assets/auth/provider status, then (only on loopback dev auth) uses the local
administrator to create, alert-subscribe, and future-schedule a one-recipient
campaign directly from DRAFT. It requires seeded approved
pattern/template records and intentionally leaves the uniquely named campaign
as audit evidence in the disposable local database.

Test DB: `DATABASE_URL_TEST` (`kingphisher_test`). **After any `drop schema
public cascade` reset, re-grant `audit_writer`** (USAGE/CREATE on schema,
ALTER DEFAULT PRIVILEGES on tables) or audit tests fail. Worker tests use
module-scope `drop_all/create_all` + a skip-if-no-DB guard.

---

## 9. Environment quirks & gotchas (verified through 2026-08-20)

1. **Docker CLI wedge (macOS Docker Desktop) — RESOLVED via context**
   The default `~/.docker/run/docker.sock` wedged (proxy held ~10 leaked
   connections; engine fine on `docker.raw.sock`).
   **Permanent fix:** created context `kp-engine` pointing at the live engine
   socket and made it default (`docker context use kp-engine`). All docker/
   compose commands now work instantly with no hang, no env vars needed.
   The `bootstrap_docker_host` + `bounded` helpers in `bootstrap_env.sh` remain
   in the launchers as a safety net — they auto-skip when the default context
   works.
2. **Mailpit healthcheck** needs 10s timeout + start_period under gvisor
   (docker-compose.yml already fixed).
3. **Compose interpolation** requires non-empty `POSTGRES_PASSWORD`,
   `REDIS_PASSWORD`, `AUDIT_WRITER_PASSWORD`, `MAILPIT_API_PASSWORD`.
4. `OPERATOR_API_CONSOLE_STATIC_DIR` must be absolute or root-relative.
5. Rotating the KEK invalidates encrypted recipient data — pair with a DB reset.
6. Console SPA syntax is gated by `node --check` in `make lint`.
7. Killing the supervisor or services: `scripts/supervisor.py` does **not**
   auto-restart dead children — only on the `data/run/restart` marker.
8. `.env` DSNs embed the rotated credentials — editing `.env` by hand must keep
   `OPERATOR_API_*`/`KP_WORKER_*`/`TRACKING_API_*` DSNs in sync (bootstrap_env
   does this; prefer it over manual edits).
9. Docker's default CLI socket may not respond even while the engine socket is
   healthy. Repository scripts detect and use Docker Desktop's engine socket;
   `verify_install.sh` reports this fallback explicitly.
10. Azure production applies require the protected GitHub environment, its
    required reviewers, workload identity, an initialized remote-state backend,
    and a private runner with VNet access. The console wizard exports non-secret
    inputs only and intentionally cannot apply infrastructure.
11. Visual Azure-wizard qualification remains pending because the in-app Browser
    plugin updated during the previous agent session. Retry it in a fresh Codex
    session and report controller attachment failures separately from app bugs.

---

## 10. Suggested next enhancements (roughly ordered)

1. Complete in-app-browser visual qualification of the Azure deployment wizard,
   including help, AI privacy filtering, keyboard focus, validation, and exports.
2. Console: tracking-events drill-down per campaign (assignments → opens/clicks
   from `TrackingEvent`), export-to-CSV.
3. Console: retention policy + privacy notice editing UI (models exist; only
   read-only view today), and an Export affordance for completed
   `access_export` DSRs.
4. `mailbox`/`reminder` workers: flesh out mock inbox handling and reminder
   cadence (currently minimal).
5. Source adapters: add STIX/bulk_download importers (enum values exist).
6. Perform organization-specific Azure production qualification: identity/DNS,
   private networking, backups/restore, legal/vendor review, and release approval.
7. OTel collector wiring: confirm worker/API traces reach :4317 and add a
   dashboard note.

Follow §7 invariants for anything security-adjacent, keep the idempotent
migration + insert-only audit patterns, and re-run the full gate before
landing. Good luck.
