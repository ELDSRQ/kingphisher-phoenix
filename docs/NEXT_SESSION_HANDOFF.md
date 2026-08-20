# Next AI Session Handoff — 2026-08-20

## Start here

Repository: `/Users/edierks/projects/codex-test/phishing-awareness-platform`

Branch: `main`

Expected head after this handoff is committed: see the newest `git log -1 --oneline` entry titled
`Refresh build continuation handoff`.

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

- `3789943` — simplify the SMB campaign flow and fix local tracked training links
- `44afb4a` — bound worker log growth
- `73e6827` — improve guided integration setup
- `d4d01ce` — fix setup assistant field guidance
- `90ed2a4` — add ntfy alert integration
- `f183fbb` — fix dashboard audit verification request
- `6013a89` — automate secure Azure deployment
- `f97bb56` — add guided Azure deployment wizard

## Verified runtime state

Docker Desktop and all local services were reverified healthy on 2026-08-20. The application is available at
`http://localhost:8000/console/`. The supervisor was running:

- operator API and tracking API
- ingestion, generation, delivery, retention, mailbox, reminder, alert, and directory workers
- Postgres, Redis, Mailpit, mock IdP, mock Graph, and rebuilt mock AI containers

The following full gate was re-run end to end and passed against the current
implementation on 2026-08-20 (exact observed results in the trailing comments):

```bash
node --check apps/operator-ui/src/console/app.js   # OK
make lint                                # All checks passed; 122 files formatted
make typecheck                           # Success: no issues in 74 source files
uv run pytest -q                         # 184 passed (was 183; +1 regression test this session)
make security-scan                       # Bandit/Semgrep/Trivy fs: 0 findings
terraform fmt -check -recursive infrastructure/terraform      # exit 0
terraform -chdir=infrastructure/terraform validate            # Success! The configuration is valid.
trivy config --exit-code 1 --severity HIGH,CRITICAL infrastructure/terraform   # 0 HIGH/CRITICAL
./scripts/verify_install.sh              # 21 ok, 0 FAIL
make operational-readiness               # All checks passed; 7 live lifecycle tests passed
```

The readiness gate intentionally leaves uniquely named local campaign evidence. The audit chain verified successfully.

## Work completed in the 2026-08-20 continuation session

- Restarted the full local stack (infra was already up; supervisor + APIs +
  eight workers were not running) with `./scripts/run_console.sh` and reverified
  health: `verify_install.sh` reports 21 ok / 0 FAIL.
- Attempted the primary task — in-app Browser visual qualification of the Azure
  wizard. **The browser controller is still not attachable** in this session:
  the Claude-in-Chrome / in-app Browser extension is not set up, so no
  `mcp__*browser*` controller is exposed. This is the same environmental blocker
  carried since the plugin update; it is **not** an application defect.
- Qualified every layer the browser would exercise that is reachable without a
  live browser, and found **no application defects**:
  - Wizard schema (`GET /console/azure-deployment`): 4 non-secret steps, every
    field carries `where_to_find` guidance and `secret: false`.
  - Validation (`POST /console/azure-deployment/validate`): success, field-level
    errors (bad hostnames, credential-bearing URLs), unknown-key rejection (403),
    and — newly covered — the structurally-valid **warnings** branch.
  - Privacy-filtered AI assist (`POST /console/onboarding/assist`): current-step
    non-secret fields only; disposable credential-shaped text is stripped;
    suggestions are constrained to step-owned non-secret keys; never persists,
    saves, deploys, or audits.
  - Help (`GET /console/help`): glossary + topics including `azure-deployment`;
    the searchable filter is client-side over that payload.
  - **Terraform export correctness (verified):** every key the review step writes
    into `<env>.auto.tfvars` (`subscription_id`, `environment`, `location`,
    `name_prefix`, `operator_fqdn`, `tracking_fqdn`, `entra_tenant_id`,
    `entra_client_id`, `communication_data_location`, `ai_endpoint`,
    `alert_webhook_domains`) matches a real variable in
    `infrastructure/terraform/variables.tf`. The GitHub-variables JSON matches
    the workflow's expected environment variables.
  - Front-end interaction behavior confirmed by reading `app.js` (browser needed
    only to see it render): per-step focus moves to the `#azure-wizard-title`
    heading (`tabindex="-1"`); each field shows an explicit Required/Optional
    badge and a native `required` attribute; Back/continue navigation preserves
    `collected` values across steps; both downloads use `Blob` +
    `createObjectURL`/`revokeObjectURL`; downloads appear only after a successful
    validation and are cleared on re-validate.
- Added one regression test —
  `test_azure_deployment_validation_surfaces_advisory_warnings` in
  `apps/operator-api/tests/test_console.py` — pinning the `ok: True` +
  advisory-warnings validate branch (empty AI gateway, non-`azure-vnet` runner
  label), the one validate output state that had zero automated coverage and
  which backs the console's success-with-warnings rendering. Suite: 183 → 184.

## Work completed in the prior session

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

**Only the pixel-level/interaction visual pass remains, and it is environmentally
blocked — not an application defect.** In the 2026-08-20 continuation session the
in-app Browser controller was again unavailable: the Claude-in-Chrome / Browser
extension is not connected in this environment, so no browser MCP tools are
exposed (the skill reports "Browser tools are not available in this session").
The backend behavior the browser drives (schema, validation incl. errors +
success + warnings, Help content, privacy-filtered AI assist, and the exact
Terraform/GitHub export mapping) was fully qualified without a browser via the
test suite (184 passed) and code inspection, with no defects found. What is still
unverified is only the rendered visual/keyboard interaction: on-screen focus
movement, the Required/Optional badges as drawn, back/forward navigation feel,
native validation-error surfacing, and the two actual file downloads landing on
disk.

To finish it, a session with a working browser controller (connect the extension
from https://claude.ai/chrome, or run in Codex with the in-app Browser attached)
should:

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

## Recommended continuation order

1. Complete the outstanding in-app Browser visual qualification of the Azure
   deployment wizard. Treat controller attachment failures as environmental.
2. Improve the core SMB operator experience only where testing finds concrete
   friction; do not restore separate campaign-approval gates.
3. Prepare an isolated Azure Communication Services Email pilot using an
   Azure-managed test domain and test-tenant recipients. Do not configure or
   send through an external provider without explicit user authorization.
4. After the local and isolated-mail paths are qualified, consider the next
   product enhancements in `docs/AI_HANDOFF.md` section 10.

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

## Ready-to-paste next-session prompt

```text
Continue development of the phishing-awareness platform at:

/Users/edierks/projects/codex-test/phishing-awareness-platform

Use branch main. Begin by running git status and verifying HEAD matches
origin/main; preserve any user changes. Read these files completely, in order:

1. docs/NEXT_SESSION_HANDOFF.md
2. README.md
3. RUNBOOK.md
4. docs/AI_HANDOFF.md
5. docs/REMEDIATION_PLAN.md
6. docs/AZURE_DEPLOYMENT.md

Run ./scripts/verify_install.sh before making changes. The local console should
be available at http://127.0.0.1:8000/console/, Mailpit at
http://127.0.0.1:8025/, and the local training page at
http://127.0.0.1:8001/v1/training/awareness.

The supported SMB workflow intentionally lets one authorized administrator
create and schedule a DRAFT directly. Do not restore separate security/privacy
campaign approvals. Preserve deterministic content safety, recipient caps,
append-only audit, recall, the scoped kill switch, bounded rate limits, privacy
controls, and single-tenant enforcement.

Primary task: complete visual qualification of all four Azure deployment wizard
stages with the in-app Browser, including field guidance, searchable Help,
keyboard/focus behavior, validation errors and success, privacy-filtered AI help,
and both configuration downloads. Use disposable fake credential-shaped text
only. Browser-controller failures are environmental blockers, not application
defects. Do not perform a real Azure deployment or configure external email or
infrastructure without explicit authorization.

If genuine defects are found, fix them with regression tests. Before handoff,
run the full gates listed in this document, update the handoff files with exact
results and remaining blockers, commit, push main, and leave the worktree clean.
```
