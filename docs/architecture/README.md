# Architecture

## Topology

- **Infrastructure (docker compose):** Postgres `:5432`, Redis `:6379`, Mailpit SMTP relay/UI `:1025/:8025`, OTel collector `:4317/:4318`, mock services `mock-idp :8443`, `mock-graph :8181`, `mock-ai :8282`.
- **Applications (uv workspaces, run under `scripts/supervisor.py`):**
  - `kp-operator-api` — FastAPI, `:8000`. Control plane: campaign/recipient/source/pattern/approval/audit/console-config routes plus the operator SPA at `/console`.
  - `kp-tracking-api` — FastAPI, `:8001`. Stateless open/click/correction ingestion; SHA-256-hashed token lookups only.
  - `kp-worker` (single binary, six roles) — `ingestion`, `generation`, `delivery`, `retention`, `mailbox`, `reminder`. Consume Redis job queues.
- **Console:** vanilla-JS SPA served by operator-api. Session token: 8h HS256 JWT.

## Packages (dependency order)

`domain-models` (enums/schemas) → `contracts` (event registry, queue) → `database` (ORM, sessions, audit store) → `auditing` (hash chain) → `authorization` (RBAC) → `sanitization` (SecureFetcher) → `safety-validation` (deterministic GEN-004 gate) → `templating` (sandboxed Jinja2 + SPF + ICS) → `source-adapters` (RSS/Graph ingestion) → `campaign-patterns` → `telemetry` (structlog redaction) → `test-fixtures`.

Apps depend only on packages (no cross-app imports).

## Key data flows

1. **Ingestion:** source adapters pull threat intel via `SecureFetcher` (allowlisted HTTPS, size/content-type caps, blocked-network denial) → sanitize → `source_items`.
2. **Generation:** `generation` worker builds campaign content via sandboxed Jinja2; safety validator gates at save (operator-api) and before delivery.
3. **Delivery:** `delivery` worker sends personalized HTML mail (tracking pixel + click-redirect containing hashed token) via SMTP relay; SPF-checked; assignments marked `DELIVERED`; audit event appended.
4. **Tracking:** pixel/click hit tracking-api → deduped `TrackingEvent` rows keyed by token hash.
5. **Audit:** all mutations append hash-chained rows through the INSERT-only `audit_writer` engine; `verify_audit.py` recomputes and compares.

## Security model

- Recipient identity (employee_key, mailbox, display_name, department) AES-256-GCM envelope-encrypted per value (KEK in `.env`).
- Tracking tokens: 256-bit, stored hashed; pixels/links carry the hash.
- Console: single shared password (constant-time compare) minting an admin JWT; config PUT allowlisted.
- Deterministic safety validator (GEN-004) rejects external links, shorteners, credential/MFA/install/command patterns, executables.
- Audit: SHA-256 hash chain + HMAC head; app-role insert-only enforcement; verify command.

## Data lifecycle

- Campaign lifecycle: DRAFT → SCHEDULED → ACTIVE → COMPLETED/EXPIRED; an authorized operator can schedule directly, and the kill-switch revokes queued sends + tokens.
- Retention: policy-driven purge of delivered assignments, tokens, and (per DSR) recipient/event data (see `privacy_requests`).
- DSR pipeline: RECEIVED → VERIFYING → IN_PROGRESS → COMPLETED with 45-day SLA fields; export + delete fulfilled by operator-api, audited.

## Configuration

All settings from environment/`.env` via pydantic-settings (`OPERATOR_API_*`, `TRACKING_API_*`, `KP_WORKER_*`, `KP_CONSOLE_*`). Secrets (JWT signing, audit HMAC, ciphertext KEK, console password) are generated on first `scripts/install.sh`/`run_console.sh` run and never committed. `.env` is gitignored.
