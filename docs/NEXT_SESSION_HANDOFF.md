# Next AI Session Handoff — 2026-08-17

## Start here

Repository: `/Users/edierks/projects/codex-test/phishing-awareness-platform`

Branch: `main`

Current head: `ad7e557 Improve setup guidance and AI assistance`

The worktree was clean when this handoff was written. Read `README.md`,
`RUNBOOK.md`, and `docs/AI_HANDOFF.md` before changing architecture or operator
behavior. Preserve unrelated user changes if the tree is no longer clean.

## Current outcome

The original security-analyst, red-team, and CCPA review findings have been
remediated in four commits:

- `d9c800a` — security, privacy, and operator workflow remediation
- `37b41bc` — operational security and provider integration remediation
- `3c0117a` — guided external-service onboarding
- `ad7e557` — friendlier help and privacy-safe AI setup assistance

The browser console now supports a complete campaign approval lifecycle with
distinct OIDC principals, dual security/privacy approval, directory ingestion,
SMTP delivery, reported-message intake, reminders, training completion,
retention/DSR workflows, alerts, and a first-run integration wizard.

The setup wizard now provides:

- Plain-language explanations, examples, and required/optional labels.
- Contextual help and a searchable Help center defining OIDC, issuer, audience,
  SMTP, STARTTLS, Graph, API keys, and webhooks.
- Per-step connection tests and explicit save/restart behavior.
- Advisory AI guidance through `/api/v1/console/onboarding/assist`.
- Strict removal of secrets and credential-like prompt text before an AI call.
- Suggestions restricted to non-secret fields owned by the current step.
- Explicit operator review and **Apply to form**; AI never saves automatically.
- Deterministic local guidance if the configured AI service is unavailable.

The local mock AI implements the bounded `/setup-assist` contract. Prompts,
answers, and suggestions are not persisted or written to the audit log.

## Last verification

The following passed on 2026-08-17:

```bash
node --check apps/operator-ui/src/console/app.js
uv run ruff check .
uv run ruff format --check .
uv run mypy apps/operator-api/src infrastructure/mock-services/mock_ai.py
uv run pytest -q
make security-scan
```

The full pytest suite passed; only opt-in/live tests were skipped. Semgrep
reported zero findings and Trivy reported zero vulnerabilities. The authenticated
live `test_setup_help_and_assistant` test passed against the restarted local API.

`Makefile` now excludes generated `data/logs` from Trivy. Do not revert that:
the existing worker logs total about 16 GB and caused filesystem scanning to
stall. No logs were deleted during the previous session.

## Runtime state and known environmental limitation

At handoff time, the operator API responded on `127.0.0.1:8000` and had been
restarted after the latest code changes. Docker Desktop was not running:

```text
Cannot connect to the Docker daemon at unix:///Users/edierks/.docker/run/docker.sock
```

Consequently, the updated mock-AI image and the full live connector test were
not rebuilt/executed. This is an environment limitation, not a failing contract:
the mock-AI tests, operator API tests, worker/provider tests, and focused live
Help/assistant test passed.

When Docker becomes available, run:

```bash
docker compose build mock-ai
docker compose up -d --force-recreate mock-ai
./scripts/verify_install.sh
make operational-readiness
```

The operational-readiness gate expects a disposable seeded local database and
may create a uniquely named future campaign as audit evidence. Read its guard
messages before enabling the lifecycle option.

## Suggested next actions

1. Start Docker Desktop and run the four commands above.
2. Exercise the wizard visually at `http://127.0.0.1:8000/console`:
   search Help for “OIDC,” open contextual help, ask the assistant a provider
   question, apply a non-secret suggestion, test the connection, and confirm no
   value is saved until the explicit save action.
3. Verify that secret-looking text is removed by asking a question containing a
   disposable fake credential; do not use real credentials in testing.
4. Investigate and rotate/compress the 2 GB-per-worker runtime logs. Treat
   deletion as a separate, explicitly authorized operational action.
5. If production deployment is next, supply real OIDC, SMTP, directory,
   reported-mailbox, AI, training, and webhook configuration through the wizard,
   then complete external security/privacy/legal review. The repository cannot
   certify vendor contracts, production TLS/DNS, backups, incident response, or
   organization-specific CCPA decisions by itself.

## Important implementation locations

- Wizard and Help UI: `apps/operator-ui/src/console/app.js`, `styles.css`
- Onboarding/help/AI API: `apps/operator-api/src/kp_operator_api/console.py`
- Mock setup assistant: `infrastructure/mock-services/mock_ai.py`
- API tests: `apps/operator-api/tests/test_console.py`
- Mock-AI tests: `infrastructure/mock-services/test_mock_ai.py`
- Live setup smoke: `tests/e2e/test_live_console_smoke.py`
- Operator instructions: `RUNBOOK.md`
- Remediation task ledger: `docs/REMEDIATION_PLAN.md`

## Safety invariants to preserve

- Never send secret fields, credentials, or raw connection strings to AI.
- AI output remains advisory and outside deterministic validation/safety gates.
- Never let AI suggestions persist without explicit operator review and save.
- Keep dual security/privacy approval and creator self-approval prohibition.
- Keep tracking-token paths and client IPs out of access logs.
- Keep tracking rate-limit storage bounded and validate hashes before lookup.
- Keep DSR completion evidence-based; exception requests require legal review.
- Maintain single-tenant enforcement unless tenant isolation is implemented
  across schema, tokens, queues, authorization, encryption, and tests.
- Do not delete runtime logs or other user data without explicit authorization.
