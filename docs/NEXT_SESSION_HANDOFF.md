# Next AI Session Handoff — 2026-08-18

## Start here

Repository: `/Users/edierks/projects/codex-test/phishing-awareness-platform`

Branch: `main`

Expected head after this handoff is committed: see the newest `git log -1 --oneline` entry titled
`Update session handoff documentation`.

The worktree was clean before this documentation update. First inspect `git status`, preserve any user changes, then read this file,
`README.md`, `RUNBOOK.md`, `docs/AI_HANDOFF.md`, `docs/REMEDIATION_PLAN.md`, and `docs/AZURE_DEPLOYMENT.md` completely.

## Current outcome

The platform is operational locally and now includes:

- An expedited SMB campaign lifecycle: one authorized administrator can create a
  draft and schedule it directly. Deterministic content safety, recipient caps,
  append-only audit, recall, and the scoped kill switch remain enforced.
- A complete no-credential local simulation path. Mailpit captures messages,
  per-recipient tracking URLs record clicks, and the tracking API serves a local
  awareness landing page without requiring DNS or a separate training service.
- Accessible, human-friendly integration onboarding with searchable Help, contextual field guidance, privacy-filtered advisory AI,
  connection tests, review, and explicit saving.
- A native ntfy-compatible signed alert-webhook integration with bounded retry and DLQ behavior.
- Bounded worker logging. The former roughly 16 GB growth was caused by tight-loop Redis connection-error logging; supervisors now
  rotate logs and workers back off. Current `data/logs` size was about 180 KB on 2026-08-18. Do not delete logs without explicit
  authorization.
- Automated, production-oriented, single-tenant Azure infrastructure in `infrastructure/terraform`, container publication and a
  protected `.github/workflows/azure-deploy.yml` workflow.
- A four-stage **Azure deployment** GUI wizard that gathers only non-secret Azure, Entra, DNS, integration, runner, and Terraform
  backend values; explains where each value is found; validates them; and exports Terraform/GitHub configuration files.
- Optional AI assistance in every Azure stage. Only current-step non-secret values are eligible. AI cannot save, deploy, bypass
  validation, or approve a release.

Relevant commits immediately preceding this handoff:

- The newest commit — simplify the SMB campaign flow and fix local tracked training links
- `44afb4a` — bound worker log growth
- `73e6827` — improve guided integration setup
- `d4d01ce` — fix setup assistant field guidance
- `90ed2a4` — add ntfy alert integration
- `f183fbb` — fix dashboard audit verification request
- `6013a89` — automate secure Azure deployment
- `f97bb56` — add guided Azure deployment wizard

## Verified runtime state

Docker Desktop and all local services were healthy on 2026-08-18. The application is available at
`http://localhost:8000/console/`. The supervisor was running:

- operator API and tracking API
- ingestion, generation, delivery, retention, mailbox, reminder, alert, and directory workers
- Postgres, Redis, Mailpit, mock IdP, mock Graph, and rebuilt mock AI containers

The following passed against the current implementation:

```bash
node --check apps/operator-ui/src/console/app.js
make lint
make typecheck
uv run pytest -q                         # 183 passed
make security-scan                       # Semgrep 0; dependency/secret scan 0
terraform fmt -check -recursive infrastructure/terraform
terraform -chdir=infrastructure/terraform validate
trivy config --exit-code 1 --severity HIGH,CRITICAL infrastructure/terraform
./scripts/verify_install.sh
make operational-readiness               # 7 live tests passed
```

The readiness gate intentionally leaves uniquely named local campaign evidence. The audit chain verified successfully.

## Work completed in this session

- Removed the development-identity warning and separate security/privacy approval
  buttons from the normal campaign path.
- Allowed an administrator with campaign-scheduling capability to schedule a
  DRAFT directly. Legacy approval routes and database records remain readable for
  compatibility but do not block the normal console workflow.
- Updated the live lifecycle smoke to exercise create → schedule using one
  administrator identity.
- Fixed the seeded campaign template, which had linked directly to
  `https://training.local/awareness` and therefore bypassed click attribution.
  New seeded messages now use `{{ tracking.click_url }}`.
- Added `GET /v1/training/awareness` to the tracking API and changed local
  operator, worker, and tracking defaults to
  `http://127.0.0.1:8001/v1/training/awareness`.
- Made the seed idempotently upgrade the existing local seed template. Messages
  already delivered to Mailpit retain their old embedded URL; create a new
  campaign to exercise the corrected flow.
- The user manually exercised the simulator successfully. After the fix, the
  local awareness endpoint and full install health were also verified live.

## Expedited delivery path

1. Use local Mailpit (`http://127.0.0.1:8025/`) for complete campaign, delivery,
   tracking, monitoring, report, recall, and kill-switch qualification without
   sending internet email.
2. For a small real-mail pilot that does not use the company domain, use Azure
   Communication Services Email with an Azure-managed test domain and only
   disposable/test-tenant recipients. Respect its low test-domain quotas.
3. For an authorized employee pilot, use a separately owned simulation domain
   with SPF, DKIM, DMARC, conservative sending limits, and Microsoft 365 Advanced
   Delivery configuration. Do not spoof or send from the operational company
   domain.

No external email provider was configured and no internet email was sent during
this session.

## Remaining qualification item

Visual browser automation of the Azure wizard remains outstanding because the Codex Browser plugin updated while the prior agent
session was active. The user opened the in-app Browser, but that session did not expose the updated controller. This is an agent-tool
attachment issue, not an application defect. The plugin moved from cached version `26.623.141536` to `26.727.51351`.

In a fresh Codex session:

1. Confirm `git status` is clean and the local app is still healthy with `./scripts/verify_install.sh`.
2. Use the in-app Browser skill and the already-open or newly opened `http://localhost:8000/console/` tab.
3. Test login, **Azure deployment**, all four stages, each contextual “Where do I find this?” disclosure, searchable Azure Help,
   keyboard/focus behavior, AI questions, validation errors, successful validation, and both downloads.
4. Use disposable fake credential text to reconfirm filtering. Never use a real secret or connection string.
5. Confirm AI guidance never changes a field, saves configuration, starts Azure work, or bypasses protected workflow approval.
6. Fix genuine application defects with regression tests; report browser/tool failures separately.

No real Azure deployment has been executed. Production qualification still requires organization-owned Azure/Entra/DNS values,
approved GitHub environment reviewers, a private runner with VNet access, vendor/legal review, backup/restore evidence, and an
authorized deployment window.

## Important locations

- Azure wizard UI: `apps/operator-ui/src/console/app.js`
- Azure wizard schema, validation, Help, and AI filtering: `apps/operator-api/src/kp_operator_api/console.py`
- Azure infrastructure and validation: `infrastructure/terraform/`
- Deployment workflow: `.github/workflows/azure-deploy.yml`
- Deployment documentation: `docs/AZURE_DEPLOYMENT.md`
- Console/API regression tests: `apps/operator-api/tests/test_console.py`
- Live console tests: `tests/e2e/test_live_console_smoke.py`
- Local training landing and click redirect: `apps/tracking-api/src/kp_tracking_api/routers.py`
- Seeded tracked template: `scripts/seed.py`
- ntfy/webhook worker: `apps/workers/src/kp_workers/alert.py`
- Log bounding: `scripts/supervisor.py`, worker runtime/backoff code, and `RUNBOOK.md`

## Safety invariants

- Never send secrets, credentials, or raw connection strings to AI.
- AI suggestions are advisory and require explicit operator review; AI never saves or deploys.
- Preserve capability checks on scheduling and administration; the supported SMB
  path intentionally permits one authorized administrator to create and schedule.
- Do not log tracking tokens or client IP addresses.
- Keep tracking rate-limit storage bounded and validate token hashes before lookup.
- Keep DSR fulfillment evidence-based; exception requests require legal review.
- Do not weaken single-tenant enforcement without complete tenant isolation across data, auth, queues, encryption, and tests.
- Do not delete logs, state, infrastructure, or user data without explicit authorization.
