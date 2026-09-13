# DEP-010 — Simplified GUI Azure/mail deployment (build plan)

Status: in progress (2026-09-13). Matrix item DEP-010 (P1). Reconciliation:
`[[task-matrix-reconciled-2026-09-13]]` — the wizard already has
schema/validate/plan/apply/retry/advance; the gaps are (1) no browser discovery,
(2) rollback `unsupported` / backup-restore `external_unverified`, (3) cost =
time-only.

## Acceptance (matrix)
"Browser discovery supplies tenant/subscription/regions/DNS/groups; strong
defaults; Advanced-only internals; GUI progress/retry/rollback/recovery/cost."

## Confirmed design decisions (operator, 2026-09-13)
- **D1 — discovery runs CLIENT-SIDE in the browser.** MSAL.js acquires a
  delegated `https://management.azure.com` token; the browser calls ARM
  read-only and pre-fills the wizard. The server never gains an ARM path. CSP is
  relaxed for two Azure origins; `@azure/msal-browser` is bundled via esbuild
  (script-src stays `'self'`). Fail-closed to manual entry.
- **D3 — rollback = "roll forward to last-green"**: re-dispatch the last
  successfully-applied reviewed `deployment_config` + `reviewed_commit_sha`
  through the SAME reviewed dispatch + human-approval gate. Non-destructive.
  Optional add-on: per-Container-App revision rollback.
- **Cost = bounded static SKU spend model** (no live pricing API).

## Invariants (never relaxed)
- Server never gains ARM **mutation**; discovery is browser-side, read-only.
- Rollback reuses the reviewed dispatch + approval gate (no bypass path).
- The two workflow-SHA pins (`deployment_common.py` `EXPECTED_WORKFLOW_SHA256`
  and `tests/test_azure_idle_workflow_contract.py` `EXPECTED_DEPLOY_WORKFLOW_SHA256`)
  and the reviewed `deployment_config` contract stay intact.
- No Azure credentials stored server-side. Everything behind
  `deploy_connector_enabled`, staging-first.

## Delivery — sequential stacked PRs (conflict matrix ⇒ mostly sequential)
The three phases all write the same hotspots — `console-js/app.js` (+ built
`console/app.js`), `azure_deployment_routes.py`, `deployment_orchestration.py` —
so they are single-owner and cannot be parallelized across agents. Build order:

### P1 — Browser discovery (this branch)
Ordering: reversible/net-new first, then the security-touching wiring.
1. (reversible) `docs/design/DEP-010-BUILD-PLAN.md` — this file.
2. (reversible, net-new) ARM discovery module: pure functions that, given an ARM
   access token, read subscriptions/tenants/locations/resource-groups/DNS
   zones/ACS resources and normalize them. Unit-tested with mocked fetch.
3. (security) MSAL browser auth to acquire the ARM-scoped delegated token.
4. (security) Wizard "Discover from Azure" hook that pre-fills subscription_id /
   entra_tenant_id / location / acs_dns_zone_id / resource group; fail-closed to
   manual entry.
5. (security, RED) CSP relaxation in `main.py`: connect-src += login.microsoftonline.com
   + management.azure.com; frame-src += login.microsoftonline.com. Update the CSP test.
6. (build) add `@azure/msal-browser` dependency + rebuild `console/app.js` via esbuild.
7. Tests: discovery module unit tests; CSP contract; wizard prefill.

### P2 — GUI progress + static cost
- Surface live deploy phase/step and the partial-apply state from orchestration.
- Static SKU spend model (container apps, Postgres flexible, Redis, ACS, KV,
  storage, runner VM) → monthly range + disclaimer. Standalone module + tests
  (the one genuinely parallelizable sub-task).

### P3 — Rollback + recovery
- "Roll forward to last-green" re-dispatch through the reviewed gate; record the
  last-green (config, commit) in orchestration state.
- Flip the readiness stubs `rollback` (unsupported→supported) and
  `backup_restore`; update `deployment_orchestration.py` + tests.

## RED-lane items (operator reviews at merge)
Browser MSAL auth path · CSP connect-src/frame-src relaxation · rollback dispatch.
Each rides inside its phase's PR; the operator merges every PR (the auto-mode
classifier blocks the assistant from merging to `main`).

## Test/CI notes
Run suites with `KP_DISABLE_DOTENV=1`. Branch protection is strict (each stacked
PR must be up to date with main before merge). CI is the only Azure deploy path.
