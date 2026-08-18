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

- The remediated security/privacy campaign lifecycle, dual security and privacy approval, and no self-approval.
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
uv run pytest -q                         # 182 passed
make security-scan                       # Semgrep 0; dependency/secret scan 0
terraform fmt -check -recursive infrastructure/terraform
terraform -chdir=infrastructure/terraform validate
trivy config --exit-code 1 --severity HIGH,CRITICAL infrastructure/terraform
./scripts/verify_install.sh
make operational-readiness               # 7 live tests passed
```

The readiness gate intentionally leaves uniquely named local campaign evidence. The audit chain verified successfully.

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
- ntfy/webhook worker: `apps/workers/src/kp_workers/alert.py`
- Log bounding: `scripts/supervisor.py`, worker runtime/backoff code, and `RUNBOOK.md`

## Safety invariants

- Never send secrets, credentials, or raw connection strings to AI.
- AI suggestions are advisory and require explicit operator review; AI never saves or deploys.
- Preserve dual security/privacy approval and prohibit creator self-approval.
- Do not log tracking tokens or client IP addresses.
- Keep tracking rate-limit storage bounded and validate token hashes before lookup.
- Keep DSR fulfillment evidence-based; exception requests require legal review.
- Do not weaken single-tenant enforcement without complete tenant isolation across data, auth, queues, encryption, and tests.
- Do not delete logs, state, infrastructure, or user data without explicit authorization.
