# Kingphisher-Phoenix — Operator Runbook

Operational runbook for the threat-informed phishing-awareness platform. Covers
installation (all dependencies), daily operation, monitoring, troubleshooting,
and recovery. The console is the only control plane — there is no CLI workflow.

Quick links: [Architecture](docs/architecture/README.md) ·
[AI handoff](docs/AI_HANDOFF.md) · [QA findings](QA_TASKS.md)

---

## 1. Installation

### 1.1 Prerequisites

- 64-bit **macOS** (Apple Silicon or Intel) or **Debian/Ubuntu Linux**.
- A working internet connection (package downloads, Docker images, PyPI).
- For `git clone` over SSH: an SSH key added to your GitHub account.

### 1.2 Dependencies installed by `scripts/install.sh`

The installer installs **everything** itself (no manual dependency steps):

| Dependency | Where | Notes |
|---|---|---|
| `git`, `curl`, `openssl` | Homebrew (macOS) / apt (Linux) | base tooling, checked first |
| `uv` | astral.sh installer | Python package + interpreter manager |
| Python 3.13 | via `uv` | pinned by the project, installed into `.venv` |
| Docker CLI + Compose plugin | `brew install docker docker-compose colima` (macOS) / `apt install docker.io docker-compose-plugin` (Linux) | required for local infrastructure |
| Docker daemon | Colima VM (macOS) / `docker.io` systemd service (Linux) | started automatically; first Colima start downloads a VM image |
| All Python packages | `uv sync --all-packages` | uv workspaces (`apps/*`, `packages/*`) |
| Infrastructure images | `docker compose up -d` | postgres:16-alpine, redis:7-alpine, mailpit:v1.20, otel-collector-contrib, mocks (built locally) |
| macOS launcher app | `scripts/build_launcher_app.sh` | creates `Kingphisher Launcher.app` (double-clickable) |

On macOS with an existing Docker Desktop install the daemon check passes and
Colima is skipped. If Docker Desktop is present but wedged, see §6.1 — the
launchers now self-heal via `bootstrap_docker_host` + `bounded` in
`scripts/bootstrap_env.sh`.

### 1.3 Fresh install

```bash
git clone git@github.com:ELDSRQ/kingphisher-phoenix.git
# or: git clone https://github.com/ELDSRQ/kingphisher-phoenix.git
cd kingphisher-phoenix
./scripts/install.sh
```

What runs, end to end:

1. Detect OS; install missing dependencies (see §1.2).
2. Create the project virtualenv (`uv sync --all-packages`).
3. Generate `.env` secrets once (`.env` is gitignored; never commit it):
   `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `AUDIT_WRITER_PASSWORD`,
   `OPERATOR_API_AUDIT_HMAC_KEY`, `OPERATOR_API_CIPHERTEXT_KEK`,
   `OPERATOR_API_CONSOLE_JWT_SECRET`, `OPERATOR_API_RECIPIENT_HASH_SALT`,
   `TRACKING_API_CORRECTIONS_SECRET`, `MAILPIT_API_PASSWORD`,
   `KP_CONSOLE_PASSWORD`. DSN/REDIS_URL lines are rewritten to embed them.
   Existing values are preserved on re-runs (idempotent).
4. Start infrastructure: Postgres `:5432`, Redis `:6379`, Mailpit `:1025/:8025`,
   mock-idp `:8443`, mock-graph `:8181`, mock-ai `:8282`, OTel `:4317/:4318`.
5. Apply DB migrations (`alembic upgrade head`) and seed a reproducible demo
   dataset (idempotent).
6. Build `Kingphisher Launcher.app` (macOS only).
7. Start the operator API `:8000`, tracking API `:8001`, and eight workers under
   `scripts/supervisor.py`.
8. Print the console URL and password, then open the console.

> The console password is printed once at the end of install and stored in
> `.env` (`KP_CONSOLE_PASSWORD`). Treat it like a root password — anyone with it
> can operate (and audit-trail) the platform.

### 1.4 Re-runs and manual starts

- `./scripts/install.sh --skip-deps` — re-provision on an already-provisioned
  machine (skips OS-level dependency install).
- `./scripts/run_console.sh` — GUI path without the installer: sources
  `.env`, starts infra, migrates, seeds, starts the stack, opens the console.
  Refuses to double-launch if the supervisor is already running.
- Make targets (dependencies already present):

  ```bash
  make bootstrap        # uv sync + compose infra + db init
  make seed             # idempotent demo dataset
  make dev              # operator-api + tracking-api in the foreground
  make verify-install   # health-check a running install
  ```

### 1.5 Verifying an install

```bash
./scripts/verify_install.sh   # infra health, API healthz, console auth, worker pidfiles, audit chain
make verify-audit             # recompute and compare the audit hash chain
make operational-readiness    # complete disposable-local release/readiness gate
```

`operational-readiness` is intended for a provisioned, disposable local stack.
It validates Compose configuration and migration heads, runs lint (including
console JavaScript syntax), type checking and tests, verifies the audit chain,
checks live services/workers, and performs an authenticated HTTP smoke of the
console. Outside its isolated lifecycle campaign, it does not migrate, seed,
deliver, delete, restart, or stop services. The gate requires `uv`,
Docker/Compose, curl, Node, a populated `.env`,
and the full stack already running. Tests must use a separate
`DATABASE_URL_TEST`; the script fails if it matches the application database.
The E2E stage uses seeded approved pattern/template records and creates one
uniquely named campaign with distinct author, security, privacy, and operator
principals. It adds a local web-alert subscription and schedules the campaign
24 hours ahead with `max_recipients=1`; it never contacts an external alert
provider. Lifecycle mutation is hard-limited to loopback, `dev` authentication,
and `single_tenant` deployment mode, so run the gate on a disposable local DB.

---

## 2. Operating the platform

### 2.1 Launch

- macOS: double-click `Kingphisher Launcher.app`.
- Any platform: `./scripts/run_console.sh` (or the installer).

Open `http://127.0.0.1:8000/console` and log in with `KP_CONSOLE_PASSWORD`
from `.env`.

### 2.2 Console screens

| Screen | What you can do |
|---|---|
| Dashboard | live status pills (operator/tracking API, Postgres, Redis, each worker), campaigns, audit verify |
| Campaigns | create/edit campaigns from a pattern, preview, approve workflow, scoped per-campaign kill switch on active campaigns |
| Recipients | list, CSV import (see §2.4), department tagging |
| Sources | create threat-intel sources — types: `advisory`, `rss`, `stix`, `bulk_download`, `curated` (only these; the dropdown matches the API) |
| Patterns | list lure patterns, approve for use |
| Privacy | view current privacy notice, submit data-subject requests (CCPA), verify, export (`access_export`), fulfill (`deletion`) |
| Audit | hash-chained event log, "Verify chain", global kill switch with engaged-state indicator |
| Setup wizard | guided OIDC, Graph-compatible directory, SMTP, reported mailbox, AI, training, and webhook wiring with connection tests |
| Help | searchable plain-language setup topics and definitions for terms such as OIDC, SMTP, and webhooks |
| Settings | masked `.env` editor (blank a secret to keep it), Reload, Restart services, Stop services |

### 2.3 First-run setup wizard

The console redirects administrators to **Setup wizard** until required local
or production connections are configured and the review step is completed.
The wizard explains why each connection is needed, labels required and optional
fields, provides examples, and includes contextual help. The searchable **Help**
view defines provider terminology; for example, OIDC (OpenID Connect) is the
standard used to sign operators in through the organization's identity provider.
Non-secret values are prefilled from `.env`; secret fields are always blank and
leaving an existing secret blank preserves it. Connection tests use three-second
bounds, do not follow redirects, never include response bodies in results, and
do not persist transient values. The wizard automatically mirrors training URL
and domain settings into both operator and worker namespaces.

Each step also offers an AI setup assistant. It is advisory: secret fields and
credential-like text are removed before a request leaves the operator API,
suggestions are constrained to non-secret fields in the current step, and the
operator must explicitly apply, test, and save every suggestion. If the configured
AI provider is unavailable, the API returns deterministic local guidance. Prompts
and answers are neither persisted nor written to the audit log.

Optional Graph directory sync is available afterward from **Recipients → Sync
connected directory**. The directory worker bounds pages/users, validates the
Graph-style schema, salted-hashes mailbox lookup keys, encrypts identity fields,
and audits counts without recording identities.

The local fallbacks require no external credentials. Production values normally
needed later are OIDC client details, SMTP authentication, and provider-specific
Graph/AI/mailbox tokens. Restart services from the wizard after changing them.

### 2.4 Campaign lifecycle (as an operator)

1. **Create** a campaign from an approved pattern (DRAFT).
2. **Approve** — needs security + privacy approvals; self-approval is blocked.
3. **Schedule / send** — becomes SCHEDULED → ACTIVE; the delivery worker sends
   personalized HTML mail through Mailpit's SMTP relay (local) with tracking
   pixel + click-redirect tokens.
4. **Monitor** the dashboard; use the **kill switch** (global, or scoped to a
   campaign) to revoke queued deliveries and tracking tokens immediately.
5. Outcomes are COMPLETED / EXPIRED; delivered data is purged per the active
   retention policy (default 365 days).

### 2.5 Recipient CSV import format

`POST /api/v1/recipients/import` with `{"csv_text": "...", "department": "..."}`
(what the console sends):

```
mailbox,display name,department
alice@example.com,Alice Example,Engineering
bob@example.com,Bob Example,
```

- Column 1 (required): mailbox; invalid rows are reported per-row, the rest import.
- Column 2: display name (falls back to mailbox). Column 3: department (falls
  back to the `department` field).
- Mailboxes are salted-hashed (`OPERATOR_API_RECIPIENT_HASH_SALT`); identity
  fields are AES-256-GCM envelope-encrypted with `OPERATOR_API_CIPHERTEXT_KEK`.

### 2.6 Data-subject requests (CCPA)

Privacy screen → submit request (type, requester mailbox, optional campaign).
State machine: **opened → in_progress → completed** (45-day SLA deadline shown).

- `access_export` → Export button downloads the subject's record set.
- `deletion` → Fulfill deletes the subject's data and marks it completed.
- Every transition is audit-logged; deletion fulfills also purge tracking events.

### 2.7 Kill switch

- **Global:** Audit screen → "Engage kill switch" (requires confirm). Cancels
  every queued assignment and revokes every active tracking token. One-shot by
  design — the button flips to "Kill switch engaged" (disabled) and the console
  shows who/when and the last counts (read from the audit chain).
- **Scoped:** Campaigns screen → Kill switch on `scheduled`/`sending`/`active`
  campaigns cancels only that campaign.
- Recovery after engagement: reset the dev DB and re-seed (§5.2) or
  `docker compose down -v && up -d` then migrate + seed.

---

## 3. Monitoring

- `curl http://127.0.0.1:8000/healthz` and `:8001/healthz` → 200 when up.
- Console `/api/v1/console/status` (authenticated) → per-service + per-worker
  alive flags from pidfiles.
- Worker/API logs: `data/logs/*.log` (per-process), supervisor:
  `data/run/supervisor-qa.log` style files (see `data/run/`).
- Mailpit web UI: `http://127.0.0.1:8025` (password `MAILPIT_API_PASSWORD`;
  admin username is arbitrary under HTTP Basic). SMTP relay `127.0.0.1:1025`.
- OTel collector: `:4317/:4318`.

---

## 4. Stopping, restarting, upgrading

- GUI-only: console Settings → **Restart services** (touch
  `data/run/restart`; supervisor restarts everything) or **Stop services**
  (touch `data/run/stop`; supervisor shuts down).
- Relaunch later with `Kingphisher Launcher.app` or `./scripts/run_console.sh`.
- Upgrade a clone: `git pull && ./scripts/install.sh --skip-deps` — migrations
  apply automatically. If `docker-compose.yml` changed, run
  `docker compose up -d` once (bounded automatically) to recreate containers.

---

## 5. Recovery

### 5.1 Database reset to a known-good demo state

```bash
set -a; source .env; set +a
# 1) reset schema (drop all objects)
python - <<'EOF'
from sqlalchemy import create_engine, text
e = create_engine('postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher')
with e.begin() as c:
    c.execute(text('drop schema public cascade; create schema public;'))
    # audit_writer needs its grants back after a schema reset
    c.execute(text('GRANT USAGE, CREATE ON SCHEMA public TO audit_writer'))
    c.execute(text('GRANT ALL ON ALL TABLES IN SCHEMA public TO audit_writer'))
    c.execute(text('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO audit_writer'))
print('reset ok')
EOF
# 2) migrate + seed
uv run alembic -c packages/database/alembic.ini upgrade head
uv run python scripts/seed.py
```

> Always re-grant `audit_writer` after a schema reset — without the grants the
> audit store fails with `relation audit_events does not exist`.

### 5.2 Password/secret rotation on an existing stack

`bootstrap_env.sh` preserves existing values. To rotate:
- Postgres/Redis/audit-writer passwords: change the three values in `.env`,
  then recreate infra so initdb re-runs on the role bootstrap:
  `docker compose down -v && docker compose up -d` (destroys the Postgres
  data volume — re-migrate + re-seed afterwards).
- KEK/HMAC/JWT: replace the value with 64 hex chars (256-bit). Rotating the KEK
  invalidates previously encrypted recipient fields — pair with §5.1.
- `OPERATOR_API_CONSOLE_JWT_SECRET` must be **64 hex chars** (the app rejects
  shorter values).

---

## 6. Troubleshooting

### 6.1 Docker CLI hangs ("the pause") — macOS Docker Desktop — RESOLVED

**Root cause (verified 2026-08-04):** The Docker Desktop CLI proxy socket
(`~/.docker/run/docker.sock`) was wedged — `com.docker.backend` held ~10
accumulated open connections (leaked from hung `docker` invocations) and the
proxy stopped servicing new connections. The engine itself
(`~/Library/Containers/com.docker.docker/Data/docker.raw.sock`) was healthy.

**Permanent fix:** Created a dedicated docker context `kp-engine` pointing at the
live engine socket and made it the default. All `docker` / `docker compose`
commands now bypass the wedged proxy entirely.

```bash
# One-time setup (already done on this machine):
export DOCKER_HOST=unix://$HOME/Library/Containers/com.docker.docker/Data/docker.raw.sock
docker context create kp-engine --docker "host=unix://$HOME/Library/Containers/com.docker.docker/Data/docker.raw.sock"
docker context use kp-engine
```

After this, `docker ps`, `docker compose up`, etc. work instantly with no hang,
and the fix persists across shell restarts. To revert:
`docker context use desktop-linux`.

The repo launchers (`run_console.sh`, `install.sh`, `verify_install.sh`) still
include the `bootstrap_docker_host` + `bounded` helpers as a safety net — they
detect a working default context and skip the workaround automatically.

### 6.2 Mailpit shows unhealthy

The healthcheck (`wget` on the API) needs ~10 s under gvisor networking —
`docker-compose.yml` now uses `timeout: 10s` + `start_period: 10s`. If it still
shows unhealthy after a recreate, `docker compose up -d mailpit` and confirm the
API answers: `curl -u admin:$MAILPIT_API_PASSWORD http://127.0.0.1:8025/api/v1/info`.

### 6.3 Compose fails with "required variable X is missing a value"

`.env` is missing a key the compose file interpolates (`:?`). All required:
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `AUDIT_WRITER_PASSWORD`,
`MAILPIT_API_PASSWORD`. Re-run `scripts/run_console.sh` (bootstrap fills them)
or copy the values from a known-good `.env`.

### 6.4 `/console/` 404s or assets don't load

`OPERATOR_API_CONSOLE_STATIC_DIR` must be absolute or repo-root-relative
(`apps/operator-ui/src/console`). Check the console loads `app.js` with a
Content-Security-Policy that only allows `'self'` assets — do not inline
scripts/styles.

### 6.5 Audit tests fail with "relation audit_events does not exist"

Schema was reset without re-granting `audit_writer` — see §5.1.

### 6.6 Errors are reported as KP-001..KP-010

The fail-closed error taxonomy is enforced in the API (auth, capability,
validation, not-found, conflict, deadlock, rate-limit, upstream, internal,
generic). Look up the code in `kp_operator_api` error handling before changing
behavior.

---

## 7. Security notes (non-negotiables)

- **Never commit `.env`.** It is gitignored; secrets live only on the machine.
- Audit is append-only and hash-chained (`make verify-audit`); do not add
  UPDATE/DELETE paths to `audit_events`.
- RBAC enforces a hard no-self-approval rule; do not weaken it.
- Safety validation is deterministic and outside any AI model (GEN-004 gate);
  campaign content must pass it at save and before delivery.
- The console JWT lives in `sessionStorage` (never `localStorage`) and expires
  in 8 hours.
- Encryption at rest: AES-256-GCM envelope encryption with the KEK in `.env`;
  tracking tokens are stored hashed, never plaintext.
