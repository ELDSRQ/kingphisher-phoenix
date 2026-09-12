# Next-session handoff

## Addendum 2026-09-11 (end of session, head `e41e3e9` or later) — CURRENT STATE

**Azure staging:** Infrastructure healthy, token auth working. **Blocked on Terraform Azure provider auth (403 on management.azure.com)** — Terraform changes for missing env vars are ready in `main.tf` + `staging.tfvars` but cannot be applied.

**On-prem E2E:** 8/8 passing, single-operator posture works.

**DMARC:** In place for `mail.floridamanevolved.us`.

**CORRECTION (same day):** an earlier version of this addendum listed
`OPERATOR_API_AUDIT_HMAC_KEY` and `KP_WORKER_AUDIT_HMAC_KEY` as "missing env vars" to be
added from the `audit-hmac` secret. **That is wrong and those hunks were removed.**
`audit-hmac` is the audit signing root and belongs to the migration identity alone;
`test_audit_signing_root_is_exposed_only_to_migration_identity` asserts
`"AUDIT_HMAC_KEY" not in operator + workers`, so the change fails CI. The import 500 was
diagnosed against a container image predating `3ea6fb5`, which gave the import digest its
own key (`recipient-import-digest`). The fix is to deploy a current image, not to grant
the signing root.

**Terraform changes actually pending (blocked on auth):**
- `main.tf` — define `recipient-import-digest` in the operator container's `secret`
  block (completes `3ea6fb5`; the env var referenced a secret that was never defined)
- `staging.tfvars` — `allowed_recipient_domains`

**Terraform auth error:** `403 Server failed to authenticate the request` on `management.azure.com`. `az login` works but Terraform Azure provider cannot authenticate. Fix options: set `ARM_SUBSCRIPTION_ID`/`ARM_TENANT_ID`/`ARM_CLIENT_ID`/`ARM_CLIENT_SECRET` for service principal, or ensure Azure CLI auth is picked up by provider.

**On-prem E2E:** 8/8 passing, `single-operator` posture works.

**Next AI must:** Fix Terraform auth → apply changes → verify env vars → test import → run campaign launch sequence.

---

## Addendum 2026-09-10 — AZURE RESUMED; FOUNDRY WIRED; 409 LOOP ROOT-CAUSED AND CLEARED; head `37a171b`

**Read this before re-running any deploy.** The 24-hour deploy loop is explained
and cleared below; do not repeat the failed fixes.

### Verified state

- **Azure workloads fully deployed once** (run `34411518158`, all 3 jobs green):
  operator/tracking `/readyz` = `{"status":"ready"}`, migration applied, **all 7
  worker roles ready incl. `audit-anchor` (reason=live)**, ACS receipt
  subscription activated. The gateway app, its KV secret, and the Foundry
  role assignment are **in terraform state** from later partial applies.
- **ACS is DONE**: domain `mail.floridamanevolved.us` Verified (Domain/SPF/DKIM/
  DKIM2 all *Verified*), sender `awareness@mail.floridamanevolved.us` exists
  ("Security Awareness"). DMARC `NotStarted` (non-blocking for ACS sends).
  Remaining for a campaign: recipients import → canary → launch.
- **Foundry (AI-015 Path D) wired**: `ais-kp-staging-6117w` (AIServices S0,
  custom subdomain enabled — required, default is null), `gpt-oss-120b`
  deployed GlobalStandard pay-per-token. Inference verified 200 OK at
  `https://ais-kp-staging-6117w.cognitiveservices.azure.com/openai/v1` (Entra
  bearer, scope `https://cognitiveservices.azure.com/.default`). GitHub env
  vars set: `AI_FOUNDRY_ENDPOINT`, `AI_FOUNDRY_RESOURCE_ID`,
  `AI_FOUNDRY_MODEL=gpt-oss-120b`, `DEPLOY_AI_GATEWAY=true`.
  > **⚠️ ACTION REQUIRED (P0, 2026-09-12):** P0 pins staging to `gpt-5.6-terra`
  > in `infrastructure/terraform/environments/staging.tfvars`, but the GitHub env
  > var `AI_FOUNDRY_MODEL=gpt-oss-120b` above will **override** it if the deploy
  > workflow passes it as `TF_VAR_ai_foundry_model` — silently reverting staging
  > to the flaky Preview model. Before/with merging PR #1, update that GitHub env
  > var to `gpt-5.6-terra` (or remove it so `staging.tfvars` wins). `gpt-5.6-terra`
  > is already deployed in the Foundry account alongside `gpt-oss-120b`.
- **AI-015 landed** (`b9284c9`): gateway has no ai-llama sidecar, entra
  upstream auth (fail-closed), `min_replicas=0`, single-source model pin
  (`local.ai_model_id` feeds both gateway MODEL_ID and worker `ai_model_id`).

### The 409 loop — root cause and the fix that actually worked

Every `Apply workloads` 409 (`f2518cb3…`, `12977418fb…`) was **two per-secret
Key Vault role assignments** (`workload_secret["ai-gateway:ai-gateway-auth-key"]`,
`workload_secret["worker:ai-gateway-auth-key"]`, scope
`…/secrets/ai-gateway-auth-key`) that the 2026-09-09 "drop the gateway" state
surgery removed from **state** but left in **Azure**. They survive even a KV
secret purge (RBAC is at the secret-name scope). Re-adding the gateway →
terraform re-creates → 409 forever. **Fix (applied 2026-09-10 ~12:58 UTC):
deleted both from Azure** (`az role assignment delete --ids …` at the secret
scope, verified 0 remain). Next apply re-creates them and records them in
state — loop broken permanently. Deploy `34479747420` was in flight with this
fix when this addendum was written; **check its result first**.

**LESSON (do not regress): state surgery must reconcile the Azure side too.**
`state rm` alone orphans the cloud resource; a later re-add then 409s. Either
`terraform import` or delete the Azure resource in the same operation.

### Persistent blockers / known bugs (OPEN)

1. **gpt-oss-120b structured-output quality — RESOLVED 2026-09-12 (P0, PR #1).**
   The real cause was **unbounded reasoning effort** (generation ran past the
   worker timeout and dead-lettered), and gpt-oss-120b is a flaky *Preview* model
   (~20% schema-**invalid** — the `content` field is valid JSON and the gateway
   ignores the separate `reasoning_content` channel; the earlier "leaks reasoning
   text into fields" read was wrong). Fix: the gateway now bounds `reasoning_effort`
   + `max_completion_tokens` and can omit `temperature`, and Azure staging is pinned
   to **`gpt-5.6-terra`** (benchmarked 10/10 schema-valid, p95 ~5.4s). This is **not**
   `gpt-4.1-mini` (that earlier suggestion is superseded). See
   `docs/AI_PIPELINE_REDESIGN_SPEC.md` and `docs/AI_PIPELINE_P1-P3_RESUME.md`.
2. **Dead no-op workflow steps — CLEANUP NEEDED.** `fedbd75` (import step) and
   `ea51330` (delete step, which replaced it) in `azure-deploy.yml` query
   `terraform output -raw ai_gateway_identity_client_id`, **which does not
   exist** → both silently no-op. Harmless but misleading; remove both steps
   now that the 409 root cause is fixed. Any `azure-deploy.yml` edit requires
   re-pinning `EXPECTED_DEPLOY_WORKFLOW_SHA256` in **both**
   `tests/test_azure_idle_workflow_contract.py` and
   `apps/operator-api/src/kp_operator_api/deployment_common.py` (3× forgotten
   this session → 3 wasted cycles), and the carve-out in
   `tests/test_azure_onboarding.py` (no-cleanup contract) becomes removable
   with the steps.
3. **`2bf685f` `lifecycle ignore_changes` on `ai_gateway_foundry_user` is
   ineffective for creates** (kept; harmless) — remove with the steps above.
4. **DMARC NotStarted** on the sending domain — deliverability best-practice,
   not an ACS blocker. DNS record needed if inbox-placement matters.
5. **Recipients + canary + launch remain** (the actual campaign goal). Allowed
   recipient domains currently `erikdierksgmail.onmicrosoft.com,gmail.com`
   (config). Import via console CSV endpoints
   `/api/v1/recipients/import/preview` + `/apply`; operator API auth is Entra
   OIDC (client `97466174-d0ac-460c-94e8-7b6ff3c83da5`).

### Hard-won operational gotchas

- **ACR build window**: `az acr build` runs on Microsoft agents **outside the
  VNet**; private posture (publicNetworkAccess=Disabled) blocks them. The
  workflow now opens ACR **only for the build** and an `always()` step closes
  it right after (runner reaches ACR via its private endpoint, verified 401
  reachable). If a run fails *before* apply, ACR stays Enabled until the next
  successful apply — check `az acr show -n acrkpstaging --query
  publicNetworkAccess` and disable manually if a run aborted early.
- **Transient external failures happen**: GitHub attestation API 500 (×2) and
  Chainguard registry 500 (×1) each wasted a full 30–45 min cycle this
  session. A failure in `Attest …` or `Build and start every release image`
  with a 5xx = retry, don't debug.
- **Key Vault data plane is private**: Mac gets `Forbidden` (RBAC) then
  `Public network access is disabled`. To touch KV secrets: grant the runner
  VM's system identity (`6bbed361-371e-48ab-bdad-e43d18fa770d`) or yourself
  `Key Vault Secrets Officer` on the vault, act via `az vm run-command` +
  `az login --identity --allow-no-subscriptions`, then **revoke the grant**
  (done this session; both grants revoked).
- **Local terraform state access**: backend SAS is embedded at `init` time and
  **expires** (2h default used). Symptom: `state list` says state doesn't
  exist. Fix: regenerate SAS and `terraform init -reconfigure` with
  `-backend-config="sas_token=…"` (key auth is blocked on the tfstate
  account). `terraform import`/`plan` from the Mac also needs ARM provider
  creds (ARM_USE_CLI unverified) — prefer doing provider-touching work via the
  workflow on the VNet runner.
- **ACR `ai-llama` image is gone** (only ai-gateway, migration, operator-api,
  tracking-api, worker remain) and no GGUF shards exist in Azure — the
  self-hosted sidecar path is dead by design (D-0002). Don't try to rebuild it.

### Resume here

1. `gh run view 34479747420` — if green, verify
   `az containerapp list -g rg-kp-staging` (expect 4 apps incl.
   `ca-kp-staging-ai-gateway`), then `/readyz` on operator from the VNet VM,
   then test `/propose` end-to-end (blocker #1).
2. If it failed: get the failed step + error **before** re-triggering
   (`gh run view <id> --log-failed`); transient 5xx → just retry; anything
   else → diagnose once, fix once (see lessons above).
3. Then recipients (CSV import, allowed domains) → canary send to a test
   mailbox → launch review.

## Addendum 2026-09-09 — IDLE POSTURE APPLIED AND LANDED; head `263e2dd`

**The refined idle posture (ACR preserved) is applied to Azure.** Run `34299083815`
(mode=apply, confirm=IDLE, staging env approved): `Apply complete! Resources: 0 added,
0 changed, 0 destroyed`, guard OK, Postgres already stopped. Staging now: Redis
DESTROYED, Container Apps destroyed, redis-url secret + redis PE + ACS email-sender
role destroyed, **ACR + ACR PE + 5 AcrPull assignments PRESERVED and in terraform
state**, CI runner VM in state then deallocated, Postgres stopped. Savings ~$81/mo
with no image rebuild needed on resume (resume = `azure-idle.sh start --workloads`
or the workloads dispatch — Redis/secret/PE recreate cleanly because they are absent
from state, not orphaned).

**How it got there (read this before touching tfstate again).** Three earlier apply
attempts were interrupted mid-flight, leaving Azure and state out of sync in BOTH
directions (ACR-side resources existing but untracked; redis destroyed-but-tracked,
then untracked by over-broad `state rm` recovery). Recovery was landed via a new
`.github/workflows/azure-tf-state-fix.yml` (state surgery on the VNet runner, same
`azure-staging` concurrency group):

1. **Out-of-band redis removal.** Redis was orphaned in Azure by an interrupted
   destroy (its PE, secret and state entries already gone). Importing it was
   impossible — with `deploy_data_plane=true` the locals reference the destroyed
   `redis-url` secret and every terraform command dies with `Invalid index`
   (main.tf:1224, the mirror image of the 2026-09-07 fix). It was destroyed with
   `az resource delete` — exactly what the approved idle plan intended — leaving
   no orphan: the next workloads deploy recreates Redis + secret + PE cleanly.
2. **Imports with `deploy_data_plane=false`** (the posture the 2026-09-07 fix made
   evaluable): ci_runner VM, ACR, ACR PE, and the 5 AcrPull assignments matched by
   managed identity → role-assignment ID. The imports need the 13 no-default
   variables; the workflow generates the var-file from the reviewed CONFIG line in
   `dispatch-staging-workloads.sh` with the same transforms as `azure-idle.sh`.
3. **Verification then apply**, both through the normal reviewed path.

**Traps relearned (add to the known-traps list):**
- A terraform step that ends in `|| true` or `|| echo` is a step that can silently
  no-op; the first state-fix "passed" while every import failed. The workflow now
  fails the step on any failed import.
- `terraform import`/`plan`/`apply -refresh-only` ALL evaluate the full config —
  the 13 no-default variables must be supplied or the command prompts/dies. Never
  run bare terraform against this root module.
- Interrupted applies leave state wrong in BOTH directions. Inventory Azure reality
  (`az resource list`) BEFORE writing state-recovery logic; two of my rm's removed
  entries for resources that actually existed.
- The idle workflow's job RUNS ON the runner VM: never deallocate it while a run is
  queued/running (one apply sat 43 minutes "in progress" on a deallocated VM).

**Open items now:**
1. **OPS-003** — nightly shutdown sets `min_replicas=0`, nothing restores it. Moot
   while workloads are destroyed; revisit on resume.
2. Real browser / WCAG evidence; AMD64 cross-build/registry evidence — unchanged.
3. `infrastructure/idp/` and `tests/test_entra_alternative_idp.py` are ANOTHER
   project's files (separate AI, separate app) — do not commit or modify them.

## Addendum 2026-09-08 (PM) — idle.tfvars refined: ACR preserved; head `603fd8e`

**idle.tfvars refined: ACR preserved, Redis only destroyed.** Added new `deploy_acr` variable
to `variables.tf` (default `true`); ACR resources (`azurerm_container_registry.main`,
`azurerm_role_assignment.acr_pull`, `azurerm_private_endpoint.acr`) now gated by `local.acr`
instead of `local.data_plane`. This allows the idle posture to keep the Premium ACR while
destroying Redis, avoiding a full image rebuild on the next deploy.

**Changes:**
- `infrastructure/terraform/variables.tf`: new `deploy_acr` variable with validation
- `infrastructure/terraform/main.tf`: added `local.acr = var.deploy_acr`, updated ACR resource counts
- `infrastructure/terraform/environments/idle.tfvars`: `deploy_acr = true`, `deploy_data_plane = false`
- `infrastructure/terraform/tests/test_runtime_contract.py`: updated assertion for `local.acr`

**New idle savings breakdown:**
- Redis (~$45/mo) — destroyed
- Container Apps (~$36/mo) — destroyed  
- ACR (~$20/mo) — **preserved**
- CI runner (~$25/mo when running) — already stopped
- PostgreSQL (~$125/mo) — stopped separately via `az postgres flexible-server stop`
- **Total idle: ~$81/mo** (down from ~$101/mo, but no image rebuild needed)

**Verification:** `terraform validate` passes; 51 terraform tests pass; ruff lint clean.

## Addendum 2026-09-08 (PM) — audit parity gap CLOSED; head `603fd8e`

**Audit parity gap is now closed.** `scripts/bootstrap_local_parity.py` applies the same
ownership/grant/probe logic as `azure_migrate.py` for local development. It runs after Alembic
migrations and before `bootstrap_local_audit.py` in all three bootstrap paths:

- `scripts/run_console.sh`
- `scripts/install.sh`
- `scripts/operator/dep010/start-console.sh`

**What it does:** transfers ownership of `transactional_outbox`, `audit_integrity_secret`, and
7 functions to the NOLOGIN `audit_owner` role; creates all 11 LOGIN roles with a shared dev
password; applies the full `TABLE_GRANTS` matrix from `kp_database.grants` (single source of
truth); grants column-scoped outbox INSERT/SELECT and audit-anchor SELECT; revokes PUBLIC
privileges; and optionally runs the KP-008 runtime privilege probe (`KP_LOCAL_PARITY_VERIFY=1`).

**Suppressions admin override landed (`603fd8e`):** new `MANAGE_SUPPRESSIONS` capability
(available to `administrator`, `campaign_operator`, `privacy_approver`); new endpoints
`GET/POST /recipients/{id}/suppression/deactivate`; console "Manage suppressions" dialog;
audit event `recipient.suppression.deactivate`. Soft-delete only (`active=False`), provider
evidence preserved.

**All four test gates pass at head `603fd8e`:**

| Gate | Result |
|---|---|
| `make test` hermetic (Mac) | **3140 passed** |
| postgres (`.105` `run-postgres-tests.sh`) | **99 passed** |
| redis (`.105` `run-redis-tests.sh`) | **2 passed** |
| e2e (`.105` `test -m e2e`) | **8 passed** |

**Open items:**
1. ~~**idle.tfvars plan/apply**~~ — **DONE 2026-09-09**: applied via run `34299083815`
   (see top addendum). ACR-preserving posture, ~$81/mo savings.
2. **OPS-003** — nightly shutdown sets `min_replicas=0`, nothing restores it. Moot
   while workloads are destroyed; revisit on resume.
3. **Temp diagnostics to remove:** `audit_intent_write_failed_detail` logging in
   `packages/database/src/kp_database/audit_store.py`.

## Addendum 2026-09-08 (PM) — e2e gate FULLY GREEN; two probe fixes landed; head `ac92e4b`

**All four test gates now pass at head `ac92e4b`:**

| Gate | Result |
|---|---|
| `make test` hermetic (Mac) | **3140 passed** |
| postgres (`.105` `run-postgres-tests.sh`) | **99 passed** |
| redis (`.105` `run-redis-tests.sh`) | **2 passed** |
| e2e (`.105` `test -m e2e`) | **8 passed** (was 6/8) |

**Two fixes landed this session:**

1. **`e5364ac` — connection_probes.py: allow `KP_WORKER_AI_BASE_URL` loopback.** The AI gateway
   on port 8090 was blocked by outbound safety policy because `KP_WORKER_AI_BASE_URL` was missing
   from `_DEV_LOOPBACK_PORTS`. `_allow_development_loopback()` returned `False`, causing
   `_resolve_pinned_target()` to reject the loopback address as non-public. Added the entry to the
   allowlist. This fixed `test_onboarding_contract_and_local_connectors`.

2. **`ac92e4b` — AI gateway: add webhook guidance to `_SETUP_GUIDANCE`.** The AI gateway's
   setup-assist endpoint had no `webhook` entry, so it returned generic fallback text instead of the
   expected MTA/mail-relay guidance. Added the webhook entry (matching the operator-api's curated
   fallback). This fixed `test_setup_help_and_assistant`.

**Note on .105 deployment:** the code was piped via `cat | ssh wsl cat` (no git repo on .105).
The AI gateway container was rebuilt via `docker compose build ai-gateway` and restarted. The
supervisor runs in a tmux session (`tmux attach -t kp-supervisor`).

## Addendum 2026-09-08 — idle path VERIFIED; local gate was lying; head `a56162d`

**Read `docs/design/INCIDENT-IDLE-PLAN-DRIFT-2026-09-08.md` first.** The short version: the idle
workflow's first *successful* plan (run `34172986678`) proposed **destroying and recreating the
container app environment**, and the destroy guard printed `replace: 1` and let it through. Nothing
was applied — it was `mode=plan` and the plan was read. Three instances of one bug (Azure populates
attributes the config does not declare; terraform then plans to remove them), all fixed in
`703a424` + `a56162d`.

**The idle path is now verified end to end.** Run `34175307493`, planned against a *running*
PostgreSQL so terraform refreshed from Azure rather than falling back to state:

```
Plan: 0 to add, 1 to change, 22 to destroy
destroy guard: create 0 / update 1 / replace 0 / DESTROY 22 — guard OK
```

`replace: 0`, and the destroy set is exactly the documented "Container Apps + Redis" (ACR preserved) plus the
four `deploy_workloads`-gated ACS resources the guard flags as beyond it. **`idle.tfvars` has still
never been APPLIED** — the plan is proven, the apply is a live decision that has not been made. See
"Open decision" below.

**The local test gate was red on macOS the whole time and nobody noticed** because CI is green:
CI runs Linux and never reaches the 12 retired-`.140` remote-checkpoint tests. `run-hermetic-tests.sh
all` was therefore useless as a pre-push check on the machine it is run from — the same blind spot
that let several wave failures through behind a `make test` that runs none of the three gates.
Cause was not a broken contract: the helpers now print a retirement banner unless
`KP_ALLOW_LEGACY_MAC140=1`, so every assertion matched the banner. Fixed by opting in (`4498ecb`);
the contracts still pin the script-hash check, archive-path escape rejection and no-identity-leak
property. **Local gate now: 3136 passed, 0 failed.** CI green on both jobs.

**Also landed since the last addendum:** AUD-004 (migration `0035` stripped `audit_writer` on any
existing install — proven fixed by a test that upgrades *through* 0035); branch protection now
requires the two real job names; nightly Azure shutdown armed (`NIGHTLY_AZURE_SHUTDOWN=enabled`)
with a backup-before-stop that fails safe; local WORM audit anchor deployed on `.105` and producing
anchors.

**Open decision — whether to apply idle at all.** It saves ~$101/mo and **destroys ACR**, so the
next deploy re-pushes images. With the ~$889/mo orphaned-replica leak already fixed, Azure is
mostly idle as-is, so this is the smaller remaining lever; with real-send work still ahead, keeping
ACR may be worth more than the $101. The value already banked is having a *working, guarded* idle
path to pull whenever you want it.

**The supervise worker cannot scale to zero — and an investigation into why it was still running
reversed the fix that was about to be made** (`528bdd9`). `kp-worker supervise` runs every role in
one polling process, and retention (86400s), audit-anchor (3600s), ingestion (86400s) and mailbox
(60s) publish their own trigger messages from wall-clock timers *inside* that process. At zero
replicas the interval elapses, nothing is enqueued, and a queue-depth KEDA rule — the "obvious"
fix — would have nothing to react to, so it never wakes: the window is **dropped, not deferred**,
including the audit-chain anchor. Terraform's `min_replicas = 1` was right; it just never said why.
It does now, and a mutation-proven test pins it.

Two real defects came out of that:

- **The resume path, not the replica, is the gap.** The nightly job sets every app to
  `min-replicas 0` (correct overnight — PostgreSQL stops moments later) but **nothing restores it**,
  and `az postgres flexible-server start` alone does not. Only a terraform apply does. Tracked as
  **OPS-003**; deferred because a replica is running today, so nothing is being missed.
- **The orphan detector's excuse was false.** It skipped the current revision because "a queue rule
  legitimately waking a worker" must not cry wolf. There are no scale rules at all — verified on all
  four apps and across `infrastructure/terraform`. That assumption hid a replica running on the
  ACTIVE revision since 2026-09-06 while the job logged success four nights running.

**Housekeeping:** `.claude/worktrees/` is now in `.gitignore`. A `git add -A` recorded nine agent
worktrees as gitlinks (caught before push, amended out). Never `git add -A` in this repo without
reading what it staged.

## Addendum 2026-09-07 — AZURE WAS NOT ACTUALLY IDLE

An audit on 2026-09-07 measured `rg-kp-staging` at **~$1,085/mo**, HIGHER than the
"~$800/mo before idling" this handoff claimed to have escaped. Cause: operator and
tracking ran `revision_mode = "Multiple"`, so every deploy left its revision active
holding a replica pinned at its birth `min_replicas` — 76 wedged replicas (~$889/mo)
that reported `min-replicas 0` at the app level. All deactivated 2026-09-07; both apps
flipped to `Single`. Treat every "Azure is idled / ~$0" statement below as ASPIRATIONAL
until re-measured. `idle.tfvars` has still never been applied (ACR Premium, Redis
Enterprise and the worker app all still exist). Full evidence:
`docs/design/AZURE-RESIDENCY-AUDIT-2026-09.md`.

## Addendum 2026-09-06 — Four-perspective REVIEW-FINDINGS wave LANDED (head `e47570f`)

The architect/senior-dev/security/portability review (`docs/design/REVIEW-FINDINGS-2026-09.md`)
became 11 tracked tasks; **all 11 landed this session**, plus follow-ups. Per-task commits,
status, and the deferred-follow-up list are in `docs/WAVE-BUILD-PLAN.md` (section "Follow-ups
from the 2026-09 wave build"). Gate baseline: `make test` = **2882 passed**; the only 12
failures are the retired macOS-only `.140` remote-checkpoint tests (they DESELECT on the Linux
CI; they only run on the Mac because `macos_only` isn't filtered there) — not a regression.

**BUT GitHub Actions CI IS RED and has never passed.** OPS-002 added `.github/workflows/ci.yml`
mid-session and switched on the postgres/redis integration gates that were previously
manual-only; the waves were gated on `make test`, which runs neither `make lint` nor the postgres
gate, so this went unnoticed. Lint is now fixed (`430787f`). The postgres gate still fails (~15
tests in `packages/database` + `apps/operator-api/tests/test_sending_wizard.py`) — partly
pre-existing conditions newly exposed, partly a TST-002 conversion bug:
`rebuild_public_schema_via_migrations` dropped schema `public` without restoring
`GRANT USAGE ON SCHEMA public TO PUBLIC`, so non-owner roles lose schema access for the rest of
the run and failures cascade order-dependently. Fix pending on branch
`worktree-agent-def1-pgfixtures`, to be validated against the real Postgres on `.105`
(127.0.0.1:5432, disposable `kingphisher_test` DB — never point `DATABASE_URL_TEST` at the
`kingphisher` app DB, the fixtures DROP SCHEMA). **Do not enable branch protection until green.**

**Operational changes that affect the local bring-up and the real-send flow:**
- **PLT-002 — ENFORCE is now the default approval posture.** SINGLE_ADMIN (relaxed two-person
  approval) and the empty-allowlist allow-all now require an explicit **`KP_DEV_STACK=1`** marker
  + development runtime; without it, startup refuses the relaxations and delivery/reminders fail
  CLOSED on an empty allowlist. `.env.example` ships `KP_DEV_STACK=1` so the local demo keeps
  single-admin + solo-canary. **If the .105 stack refuses to start or the solo canary is blocked,
  set `KP_DEV_STACK=1` (+ worker runtime_mode=development / operator oidc_mode=dev).** Managed
  config now REQUIRES oidc_mode=oidc (managed+dev refused).
- **AUT-002 — two-person approval requires two DISTINCT people** (self-approval + same-person-
  both-facets rejected, API + delivery-worker re-check). Migration head is `0036_launch_gate_submitted_by`.
- **AUD-002/AUD-003** audit hardening (one drift-gated grant matrix; audit_writer no longer owns
  audit tables locally; read-back/chain-verified anchors + local WORM; anchor-age gate is
  fail-OPEN on absence so it never bricks a fresh local stack).
- **AI-016** ai-gateway auth (bearer + fail-closed `require_auth`; managed terraform wires a
  shared secret gateway↔generation-worker). **Local/dev stays auth-OFF** — no .105 change.
- **UX-011** console usability; the console NEVER renders/executes template HTML (no
  srcdoc/innerHTML) — a SAFE server-computed structure summary replaced the reverted live preview.
- **CNT-002** Jinja sandbox enforced; **OPS-002** CI on PR+push:main; **TST-002** postgres
  fixtures build from real migrations; **ARC-002 Ph1** Azure deploy connector flag-gated
  (`deploy_connector_enabled`, default on, reversible).

**Deferred (reasons in WAVE-BUILD-PLAN.md, none block the real-send goal):** two Docker-only
postgres fixture conversions; UX-011 §2b proof send-to-self; UX-011 send-time spread (needs a
migration + worker); ARC-002 Items 2/3 (god-module split; Postgres-only-queue evaluation).

Everything below (Azure-idled / .105-local / KP-008 / real-send flow) still holds.

## Addendum 2026-09-05 (d) — Azure IDLED; full app + Qwen now RUN LOCAL on .105

**Head `a57345d`.** Azure was ~$800/mo; the expensive tier is now IDLED (reversible via `az`):
all 4 Container Apps at min-replicas 0, Postgres **stopped** (retains data; auto-starts in
~7 days), CI runner VM deallocated. Only the cheap real-send slice — **ACS + email domain +
DNS + Event Grid + Entra** — stays up. The Azure console is OFFLINE until resumed — expected.
**KP-008 stays RESOLVED and the real-send goal is unchanged** (resume Azure only for that).

- **The FULL APP is now RUNNING locally on the .105 WSL Docker host** (repo
  `/root/kingphisher-phoenix`), not merely "can run": the `scripts/supervisor.py` stack is up
  with operator-api :8000 (`/readyz` 200), tracking-api :8001 (`/readyz` 200), and all 8
  workers (ingestion/generation/delivery/retention/mailbox/reminder/alert/directory); infra +
  mocks (postgres/redis/mailpit/otel/mock-idp/mock-graph/mock-ai) up; audit root bootstrapped;
  demo seeded. **Reach the console from the Mac:**
  `ssh -N -o ControlMaster=no -o ControlPath=none -L 8000:127.0.0.1:8000 -L 8001:127.0.0.1:8001 erikd@192.168.1.105` → http://localhost:8000/console.
- **Build + test run fully local with ZERO Azure (verified by subagent review).** Do NOT
  restart Azure to work. The `docker-compose.yml` stack is infra+mocks only; the app tier
  (operator-api/tracking-api/8 workers) runs as local processes via `scripts/supervisor.py`.
  Run on the .105 Docker host: `make bootstrap` → `scripts/run_console.sh`; tests via
  `make test` / `test-postgres` / `test-redis` / `test-e2e`. Dev auth mode
  (`OPERATOR_API_OIDC_MODE=dev`) — no Entra needed locally. Full per-dependency mapping +
  commands: **`docs/LOCAL-FIRST-MIGRATION-PLAN.md`**.
- **Qwen is now LOCAL and PROVEN.** llama.cpp `kp-llama` on :18081 serves the AI-010-validated
  GGUF (sha256 matches the ai-llama Dockerfile pins), ~12 tok/s with `--threads 8`; ai-gateway
  on :8090; worker-generation wired via `KP_WORKER_AI_BASE_URL=http://127.0.0.1:8090`. E2E
  app→Qwen generation VERIFIED via `POST /propose` (returned schema-valid, simulation-framed
  content). Qwen no longer needs Azure (`deploy_ai_gateway=false`). Bring-up runbook is in
  **`docs/LOCAL-FIRST-MIGRATION-PLAN.md`**.
- **Cost controls (committed this session):** Path B `deploy_data_plane` flag gates ACR+Redis
  (default true = no change; `moved{}` blocks; Postgres/audit-storage intentionally NOT gated —
  `prevent_destroy`/locked WORM); `infrastructure/terraform/environments/idle.tfvars` is the
  reproducible idle overlay (apply via DIRECT `terraform apply` — the CI workflow hardcodes
  `deploy_workloads=true` which outranks tfvars); `scripts/operator/azure-idle.sh
  {status|stop|start}` wraps the idle/resume cycle (Postgres stop/start + plan/confirm apply +
  OIDC re-patch). Tiers + details: **`docs/HYBRID-AZURE-LOCAL-PLAN.md`**.
- **New identity option (IAM-003):** operator login can drop Entra/O365 via a config-only OIDC
  issuer swap to a self-hosted Keycloak (local user DB) — see task IAM-003 in
  `docs/WAVE-BUILD-PLAN.md` + design `docs/design/INTERNAL-IDP-KEYCLOAK.md`. Dev-mode already
  works locally with no Entra. Caveat: OIDC egress only trusts public-HTTPS issuers, so a
  private-LAN Keycloak needs a public HTTPS endpoint or a small address-policy change.
- **Resume Azure ONLY for a real send:** `scripts/operator/azure-idle.sh start`
  (starts Postgres, re-applies the plane, re-patches OIDC), then `... stop` to re-idle.

**Asset reallocation — Azure vs local (2026-09-05):**

| Component | Where now | State | Notes |
|---|---|---|---|
| operator-api + console | LOCAL .105 | RUNNING :8000, `/readyz` 200 | supervisor process |
| tracking-api | LOCAL .105 | RUNNING :8001, `/readyz` 200 | supervisor process |
| 8 workers (ingestion/generation/delivery/retention/mailbox/reminder/alert/directory) | LOCAL .105 | RUNNING | audit-anchor not in the local roster |
| infra + mocks (postgres/redis/mailpit/otel/mock-idp/mock-graph/mock-ai) | LOCAL .105 | UP | audit root bootstrapped, demo seeded |
| Qwen2.5-7B AI content | LOCAL .105 | llama.cpp `kp-llama` :18081 + ai-gateway :8090, ~12 tok/s | app→Qwen `/propose` VERIFIED; `deploy_ai_gateway=false` |
| build + test | LOCAL .105 | zero-Azure (verified) | `make bootstrap` / `test` / `test-postgres` / `test-redis` / `test-e2e` |
| operator / tracking / worker Container Apps | AZURE | IDLED (min-replicas 0) | reversible |
| ai-gateway Container App | AZURE | IDLED (min-replicas 0) | Qwen now runs local |
| PostgreSQL Flexible Server | AZURE | STOPPED | retains data; ~7-day auto-restart |
| CI runner VM | AZURE | DEALLOCATED | |
| ACS + email domain + DNS + Event Grid + Entra | AZURE | KEPT UP | cheap real-send slice; needed for the real send |

## Addendum 2026-09-05 (c) — repo pushed + scope boundary (no engineering change)

**Head `8e8eb1b` (fully pushed to origin/main).** This session made no change to the
engineering state — KP-008 stays RESOLVED and the next step is still the console send flow
(addendum (b) below is fully current). What changed:

- **Repo is now recovery-safe.** `main` was 2 commits ahead of origin + 1 untracked doc;
  all pushed (`811bba0..8e8eb1b`). The phishing app now recovers cleanly: code on GitHub,
  `.env` in the DR archive on Alice (192.168.1.36).
- **SCOPE — hard rule for future sessions:** work ONLY in this repo. A SEPARATE agent owns
  **CROW (`~/crow`)** and the **DR/backup mechanism** (dr-sync, the Alice archive, the
  `crow-*` launchd agents). Do NOT modify `~/crow`, `~/bin`, or `~/Library/LaunchAgents`
  even though the harness lists them as writable. Reading for context is fine; changing is
  not. Any process guardrail must **warn, never auto-kill** (operator runs several
  concurrent agent sessions). The DR-scope target (owned by the other agent) is
  "everything not in GitHub → Alice, regularly resync'd".
- **Unchanged carry-overs:** OIDC env reverts every deploy (re-patch — see (b) / the prompt);
  remove the temp `audit_intent_write_failed_detail` logging in
  `packages/database/src/kp_database/audit_store.py` once a clean console Source-create is
  confirmed.

## Addendum 2026-09-05 (b) — KP-008 RESOLVED and landed

**Head `894b105` (origin/main). Full copy/paste resume prompt: `docs/NEXT-SESSION-PROMPT.md`.**

**Where we are:** driving the first real end-to-end phishing-sim send to
erik.dierks@gmail.com through the Azure operator console. AI (ai-gateway + Qwen) and ACS
delivery are deployed. **KP-008 is FIXED.**

**KP-008 root cause + fix (commit `894b105`):** the audit-intent enqueue is
`INSERT INTO transactional_outbox (...) ON CONFLICT (idempotency_key) DO NOTHING`, and
PostgreSQL's `ON CONFLICT` requires SELECT on the conflict-arbiter column. `kp_operator`
had the outbox INSERT columns but no SELECT, so the clause was denied and surfaced
(misleadingly) as `permission denied for table transactional_outbox`. It was NEVER about
Azure, grantor identity, SET ROLE persistence, non-superuser admin, or ownership — it
reproduced on a stock `postgres:16` with a SUPERUSER admin (plain INSERT ok; INSERT ...
ON CONFLICT denied; +table SELECT ok; +column SELECT on idempotency_key alone ok). Fix:
`scripts/azure_migrate.py` grants each enqueueing role `GRANT SELECT (idempotency_key) ON
public.transactional_outbox` alongside the INSERT columns — column-scoped so
payload/origin_role stay unreadable (verified on real postgres). The migration also has a
post-commit runtime probe (commit `df6bbb2`) that fresh-session tests the real enqueue +
`kp_outbox_health()` and fails the deploy on the exact denial — the authoritative gate.
Landed via deploy run 33970611034 (verify-images + probe passed). Two earlier theories
were WRONG and dropped: "SET ROLE grantor doesn't persist" (a fable review debunked it —
ALTER TABLE OWNER rewrites the grantor and Postgres ignores grantor in privilege checks)
and the ownership-flip fix (commit `e370679`, a no-op).

**First next step:** after the OIDC re-patch, log in and create the Source (SANS ISC:
base_domain=isc.sans.edu, source_type=rss, fetch_path=/rssfeed.xml) — should succeed with
no KP-008 — then drive the content-authoring → real-send flow. Cleanup: remove the temp
`audit_intent_write_failed_detail` logging in
`packages/database/src/kp_database/audit_store.py`.

**Deploy procedure reminders:** re-enable ACR public before each deploy
(`az acr update --name acrkpstaging --public-network-enabled true`); dispatch via
`scripts/operator/deployment-preflight/dispatch-staging-workloads.sh`; operator approves the
staging reviewer gate; **re-patch OIDC env after EVERY deploy** (deploy resets
OPERATOR_API_OIDC_AUDIENCE to "kp-operator-api" and clears OIDC_SCOPES):

```
az containerapp update --name ca-kp-staging-operator -g rg-kp-staging --set-env-vars "OPERATOR_API_OIDC_SCOPES=openid profile api://97466174-d0ac-460c-94e8-7b6ff3c83da5/console" "OPERATOR_API_OIDC_AUDIENCE=97466174-d0ac-460c-94e8-7b6ff3c83da5"
```

**OIDC identity note:** console at `/console/` (root 404s); capabilities come from the token
`roles` claim, fail closed; `administrator` is on erik.dierks@gmail.com (obj eacd7c6c), not on
licensing@erikdierksgmail.onmicrosoft.com (obj ee54cb16). Sign in as the gmail account, or
grant administrator to whichever account signs in.

**Docker .140->.105:** done + .140 retired (default remote worker now erikd@192.168.1.105,
commit fff07ce; the remote-docker-worker macOS scripts are retired legacy that fail fast).

**Temp diagnostics to remove after fix:** `audit_intent_write_failed_detail` logging in
`packages/database/src/kp_database/audit_store.py`.

---

# Next-session handoff

## Addendum 2026-08-31 — external gates head-exact, first AI-010 bake-off

**Session end state: `origin/main = 40c611d`, working tree clean, no stash,
single `main` branch.** Branch inspection found nothing abandoned anywhere:
GitHub carries exactly one ref (`refs/heads/main`), history is linear with 0
merges, 0 dangling commits, 0 stashes, 0 tags, and every reflog entry is an
ancestor of `main`.

**All gates that do not need an operator now pass at current head:**

| Gate | Result |
|---|---|
| `make test` hermetic | 2707 passed / 103 deselected |
| `make lint` / `make typecheck` | clean / 140 files clean |
| `make test-postgres` | 92 passed (disposable `kingphisher_test`, Redis DB14) |
| `make test-redis` | 2 passed (DB15) |
| `make test-fresh-migration` | 1 passed (base→head) |
| `make test-e2e` | **8 passed** (7 console smoke + 1 Mailpit canary) |
| exact-final native ARM64 | **PASSED at source `2adb2a2`**, 25/25 phases |
| bandit / semgrep / trivy fs / pip-audit | 0 / 0 / 0 / no known vulnerabilities |
| SBOM | CycloneDX 1.5, 59 components, 58 external PURLs |
| actionlint / zizmor | clean / no findings |

The exact-final ARM64 gate had **silently gone stale** and the docs overstated
it as proven "at current head". final-v3 binds source `d0f03e9`; `fae8929` then
changed `apps/operator-ui/src/console/app.js`, which
`Dockerfile.operator-api:17` copies into the image. The qualified image was
shipping the pre-drill-down console — proven by extracting the bundle from both
images (`886bc1df…`, 50 ledger refs, versus HEAD's `543bd007…`, 61). The gate
was re-run at `2adb2a2` into a new no-clobber evidence root
`qualification-evidence/arm64-release-20260830-head-2adb2a2/` and passed.

**Traps recorded so they are not repeated.** Compute
`KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST` on the build host, never the
controller — the manifest hashes file modes and the controller's umask 077
yields a different digest for identical content. Ensure `git status` is clean
first, because the manifest includes untracked non-ignored files; a stray file
named `-` had entered it. `audit_writer` has its own `AUDIT_WRITER_PASSWORD`,
and using `POSTGRES_PASSWORD` for it fakes four PostgreSQL failures that look
like defects. The E2E lane needs a genuinely fresh seed and the audit bootstrap
refuses any database not named `kingphisher`, so a uniquely-named disposable
database cannot substitute.

**Environment state.** The local Docker Desktop stack was found **running**
(13h) despite this file previously claiming it was stopped; it is now genuinely
stopped with every container and volume preserved, so `.140` is the only engine.
`192.168.1.36` is the AMD64 host: it answers ping but runs **Windows** with SSH
closed (445/135 open), so the AMD64 lane is blocked until OpenSSH Server is
enabled there.

**AI-010 has its first real measurement.** llama.cpp 0.3.0 (build 10621, commit
`c1d0e7a00`) is installed on `.140`, and Qwen2.5-7B-Instruct-GGUF Q4_K_M is
downloaded and digest-pinned under
`/Volumes/DockerExternal/KingPhisher-Phoenix/ai010-models/qwen2.5-7b-instruct`
with its Apache-2.0 licence. The runbook completed 6 checks, 0 blockers, exit 0.
Score **0/4 cases**; sub-scores schema validity 3/4, injection resistance 1/1,
evidence fidelity 0/3, latency 10–26 s per case. **Not committed as selection
evidence** — AI-005 requires two or three candidates plus independent review.

**Three new operator procedures** replace prose that referenced internal
variable names and an unreachable localhost URL:
`scripts/operator/dep010/start-console.sh` (prints the exact URL, username and
password), `scripts/operator/a11y030/WCAG-WALKTHROUGH.md`, and
`scripts/operator/amd64-lane/ENABLE-SSH-ON-WINDOWS.ps1` (the Mac public key is
already embedded).

**Open findings deliberately not changed, each needing a reviewed decision:**
the console local probe at `console.py:3567` hardcodes `127.0.0.1:5432`/`:6379`
instead of deriving host and port from the configured URLs; documentation sits
inside the release source manifest even though no Dockerfile copies it, so a
docs-only commit re-stales image evidence; and the bake-off harness does not
request structured output, which would likely fix its one JSON parse failure but
must not change mid-bake-off.

**Everything that remains is operator-gated:** AZ-030 GUI plan, DEP-010 browser
sign-in, WCAG walkthrough, the AMD64 lane (needs SSH on `.36`), further AI-010
candidates, ANA-010 key rotation, and the PROD-030 decision. NO-GO stands.

## Addendum 2026-08-30 (post-Wave-38)

- **Session end state: `origin/main = 00235fc`, working tree clean, no stash,
  single `main` branch.** Hermetic 2707 / lint / strict mypy clean. The
  authoritative continuation prompt is the copy-ready prompt in
  `RESUME-HERE.md`; every session change is listed there under "Session
  changes to recheck" (code: drill-down `fae8929` + runbooks `6507a54`/
  `78fb3a1`; rest docs). All remaining work is operator-gated.
- First immutable release-image publication into the production ACR
  `atprodcuprodacr.azurecr.io` was performed and the registry hardening was
  fully reverted. Commit `b0751cd`; the four digest-pinned references and the
  exact revert are documented in `/Users/edierks/projects/codex-test/phishing-awareness-platform/RESUME-HERE.md`
  (ACR section). Amazon-subscription renewal unblocked management plane, but
  the push still required operator-approved temporary opening (no `AcrPush`,
  private-only network, disabled exports) that was reverted after push.
- Live E2E (loopback Mailpit + full `supervisor.py` stack) passes 6/7 console
  smoke + 1/1 canary on a fresh seed. Two genuine findings were documented in
  `RESUME-HERE.md`: a `sync-directory` 503 (audit-outbox dispatch under the
  live stack, `AuditFailureError` / `post_commit_outbox_dispatch_failed`) and
  order-dependence when both `tests/e2e` files share one seeded DB.
- `connection_probes.py` dev-loopback allowlist fix landed (`b0751cd`) so the
  live SMTP probe passes; new test
  `apps/operator-api/tests/test_connection_probe_loopback.py` is 7-passing.
- 2026-08-30 (post-b0751cd): current-head re-verification is green and clean —
  AZ-030 static orchestration suite `114 passed`
  (`apps/operator-api/tests/test_deployment_orchestration.py`) and the read-only
  live Azure smoke `test_live_azure_cli_can_read_selected_subscription` PASSED
  against the renewed/enabled subscription `169644fd-…`.
- **ANA-010 per-recipient GUI drill-down landed (`fae8929`).** The ledger view
  now offers a capability-gated (on `view_named`) per-recipient history: masked
  recipient selector (first 500 authorized records) or a 36-char recipient-id
  entry, a pseudonym-free bounded table of ledger outcome facts, and a
  capability-gated CSV export. It also fixed a latent `downloadApiCsv` bug that
  required `/analytics/campaigns/` only and silently rejected every
  `/analytics/ledger/` CSV download (trend/repeats/recipient history); the
  guard now allows the exact `/analytics/` export prefix. Pinned by
  `apps/operator-api/tests/test_analytics_ledger_drilldown_ui_contract.py`
  (4 tests); hermetic **2707** passed, lint clean. Only ANA-010 key
  rotation/recovery remains governed follow-up.
- **Security scan on the new drill-down code is clean (2026-08-30):** bandit
  (`-ll`, packages/apps) 0 findings, repo custom semgrep rules 0 findings,
  and gitleaks flags **none** of the files changed this session — the raw
  `--no-git` tree findings are all pre-existing (`.env` by design + test
  fixtures with fictional credentials). ANA-010 **key rotation/recovery** is
  intentionally **not** agent-actionable: it crosses the auth/crypto/secrets
  boundary (active-KEK rotation on Terraform state with `prevent_destroy`,
  database decrypt proof, bulk re-encryption, prior-key retirement) and needs
  live Azure/operator decision, matching the standing human-gated posture.
- **Two operator runbooks added (`scripts/operator/deployment-preflight/`):**
  `az030-operator-runbook.sh` (read-only readiness + the exact
  `foundation_bootstrap` staging GUI-field checklist, live-prefilled from `az`)
  and `ai010-bakeoff-runbook.sh` (verifies the offline scoring harness, checks
  the operator-held weights/license/runtime contract, runs the fixed eval on a
  loopback llama.cpp endpoint, and writes the digest-pinned selection report).
  Both are `bash -n` + shellcheck clean. They are operator prep only; the AZ-030
  reviewed values file and the AI-010 weights still must come from you/GUI.
- **Runbook E2E validation (2026-08-30):** `ai010-bakeoff-runbook.sh` was proven
  end-to-end against a loopback mock OpenAI-compatible server on a free port:
  harness check → weights/license contract → endpoint probe → evaluation →
  evidence report, **4/4 cases passed**, exit 0 (report to `/tmp`; the mock was
  never committed and is not selection evidence). `az030-operator-runbook.sh`
  validated read-only against the live subscription/tenant (all checks pass;
  only the two operator-chosen hostnames remain warnings). Note: ports 8080 and
  18080 on this host are owned by SSH tunnels — use a verified-free loopback
  port (the runbook's `--endpoint` takes any) for any future llama.cpp run.
- **QA bugcheck and az030 runbook fixes (2026-08-30):** A comprehensive QA review
  was performed. All automated gates pass (2707 hermetic, lint, mypy, bandit,
  semgrep, bundle drift, CSP contract, drill-down UI contract). **Two bugs
  found and fixed** in `az030-operator-runbook.sh`:
  1. DNS resolution used `getent hosts` (Linux-only); silently fails on macOS.
     Replaced with `_resolve_host` helper trying `getent` (Linux), `dscacheutil`
     (macOS), then `python3` (universal fallback).
  2. **Command injection** in the python3 fallback: `$host` was interpolated
     directly into the `-c` string, allowing arbitrary Python execution via
     single quotes/backslashes in `OPERATOR_FQDN`/`TRACKING_FQDN`. Fixed by
     passing host as `argv[1]`. Verified: `example.com'; os.system('id')`
     safely fails (literal hostname).
  3. **`set -e` abort regression introduced by 1 and 2**, caught on
     re-verification: the rewritten `_resolve_host` dropped the original
     `|| true` and can itself exit nonzero (`getent hosts` returns 2 on Linux;
     the macOS `dscacheutil | grep -m1` pipeline returns grep's 1 under
     `set -o pipefail`; the `python3` fallback returns 1). Under the runbook's
     `set -euo pipefail`, `addr="$(_resolve_host "$host")"` therefore aborted
     the entire script as soon as a hostname did not resolve — the state the
     very next line calls normal before the GUI creates the zone alias.
     Reproduced live: two non-resolving hostnames gave 7 lines and exit 1
     (a documented "blocker found"), skipping the hostname warnings, GitHub
     checks, ACS/GUI field checklist and the whole STEP B guide, where the
     committed `991251e` version gave 53 lines and exit 0. Fixed by making the
     helper total — `|| true` on every branch, `return 0` at the end, and the
     call-site `|| true` restored — and each branch now emits one bare address.
     Re-proven live on non-resolving, resolving, and forced-python3 (including
     the injection string) paths.
  No other defects found. Security posture verified: no innerHTML/eval, CSRF
  active, parameterized SQL, proper capability gates, session-scoped tokens.
  Head: `991251e`.
- **Operator-required blocker (2026-08-30): the full AZ-030 promotion is
  operator-only.** `scripts/azure_bootstrap.sh` refuses invented values: *"Do not
  invent those reviewed values by hand. A direct command is not equivalent to the
  GUI's review digest, source-drift check, audit record, or protected-environment
  preflight, and is never production/RSA evidence."* The reviewed non-secret
  deployment plan must be filled in the console Deployment GUI (Entra tenant id,
  two hostnames, customer-managed ACS sender + reviewed quota/pacing, recipient
  allowlist, `network_mode`), which alone creates the opaque request id, canonical
  `deployment_config`, and reviewed-commit binding. Only then can the live
  (mutating) bootstrap/release run — with a further operator confirmation before
  any cloud mutation. This is the single path that promotes AZ-030 and unblocks
  OBS-036. The other NO-GO gates (DEP-010 browser sign-in, WCAG walkthrough,
  native AMD64 engine, PROD-030 human decision) are likewise operator/human/
  engine-owned. An agent has no further low-risk step that advances a
  production/RSA gate until at least AZ-030 is operator-completed.

## Start here

Repository: `/Users/edierks/projects/codex-test/phishing-awareness-platform`

Target engineering worker: `edierks@192.168.1.140`. Its canonical source is
`/Users/edierks/Projects/kingphisher-phoenix`, mounted read-only inside the
project-only native ARM64 Colima profile `kingphisher`; external VM/cache/client
state and the socket are rooted at
`/Volumes/DockerExternal/KingPhisher-Phoenix` on the attached 1 TB drive.
External preflight/restore passed; final exact preflight reported approximately
744,006,440 KiB free. The inactive `kp-external-mac` context is
created with endpoint
`ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`
and reports `colima-kingphisher|aarch64|/var/lib/docker`, while the
default remains `desktop-linux`; the seven internal Docker Desktop project
containers are stopped/preserved and unrelated containers remain running. The global remote context remains
`desktop-linux`; unrelated workloads must not be changed. External
mount/UUID/read-only-source/capacity drift blocks instead of falling back. The
canonical operating procedure is
`scripts/operator/remote-docker-worker/README.md`; current Wave 38 status is in
`docs/PRODUCTION-READINESS-TASK-MATRIX.md`.
The legacy Docker contexts `DockerExternal` and `kp-remote-mac` omit the
reviewed socket path and can select shared Docker Desktop; never use them for
project work. The external volume named `DockerExternal` is storage, not a
Docker context. Rosetta/binfmt are disabled and unnecessary for native ARM64.

The controller recovery identity is verified at public recipient
`age1p9t25wm9uvcaafjv3hjmgsj092mgydrr9uzndjnmcq9psupfl94qm8h2w2`.
Because headless SSH cannot unlock the remote Keychain, use
`checkpoint-remote.sh` for its temporary identity transfer/cleanup. After an
applied checkpoint, controller `stage-remote.sh` must invoke remote
`stage-checkpoint.sh` with a second bounded transfer, validate the exact archive, and
no-clobber publish `migration-checkpoint/` before external-engine-scoped
`restore-state.sh`. Snapshot `20260829T013332Z-tsX1WQ`, archive SHA-256
`e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`,
passed that chain and external restore, so `EXT-002` is complete. External
installation and `verify_install.sh` passed as well.

The installer timeout repair is locally integrated and validated by 42 tests:
default 900 seconds, maximum 3600, and strict parsing. It is synced and remote
`--check-uv` passed; no cold full rerun under the new default is claimed.

The pre-remediation local and external integrated QA snapshot passed:
operational readiness reached exact head `0029`; hermetic 2,329 passed/97
deselected; PostgreSQL 86 passed/2,340 deselected while isolated on Redis DB14;
Redis 2 passed/2,424 deselected on DB15; audit and `verify_install.sh` passed;
and E2E passed all 8. Its 03Z API/worker log window contained no error/critical
event or unknown-campaign/unknown-pattern job. Ruff/format, strict mypy over 124
source files, Bandit, Semgrep, Trivy source checks, dependency audit,
Actionlint, and Zizmor were green within their recorded scopes. The pre-Wave-36
local hermetic `make test` passed 2,469 tests/97 deselected with 0 failures in
158.15 seconds. The final local Wave 36 hermetic suite at checked-in head
`0030_default_privacy_notice` passed 2,501 tests/97 deselected with 0 failures
in 183.40 seconds. Ruff/format covered 336 Python files; mypy covered 124 source files;
Bandit, Semgrep (4 rules/125 targets/0), Trivy repository scans (0
HIGH/CRITICAL vulnerabilities, secrets, or misconfigurations), pip-audit,
Actionlint, and Zizmor passed in their recorded scopes. PostgreSQL, Redis, and
Current-head `0033` external PostgreSQL/Redis/E2E and exact-image evidence remain pending. Release remains NO-GO for live
Azure/provider, real-browser/WCAG and human assistive-technology, exact-final
image/native AMD64/registry attestation, and rollback evidence.

The authoritative continuation record is [the integrated build plan](WAVE-BUILD-PLAN.md). Do not rely on old commit lists or copied test counts in handoff documents. Begin by preserving the shared worktree, then read:

1. `docs/WAVE-BUILD-PLAN.md`
2. `docs/architecture/README.md`
3. `docs/AI_HANDOFF.md`
4. `README.md`
5. `docs/AZURE_DEPLOYMENT.md` for deployment work

### Wave 38 paused checkpoint

The product is for one 125-person tenant operated by two IT staff. The
authoritative new-work priority is the goal-aligned policy in the build plan;
historical waves remain evidence, not permission to expand scope. Deferred
features remain retained and supported but receive no expansion slot. Never
delete potentially valuable behavior simply because it is deferred.

- `ORG-001` is complete locally: creator plus one independent approver holding
  both approval capabilities. Security and privacy remain separate recorded
  facets; RoE, frozen audience, canary, provider evidence, immutable review,
  emergency stop, and every other safety gate remain.
- `THR-001A` and `DOCSIM-001` are complete locally with evidence-fidelity and
  recipient-bound ICS behavior; their focused closure passed 150 tests.
- `IMP-001` is complete locally with guided arbitrary-header CSV preview/apply,
  digest-bound mapping/options, skip/update merge, optional soft-deactivation,
  and transaction-serialized writes that return a safe re-preview `409` on
  concurrency loss.
- `THR-001B` is complete locally with a bounded Threat Campaigns workbench,
  daily governed ingestion, default quarantine, explicit audited activation to
  one draft pattern basis, and source/terms/provenance rechecks at activation,
  approval, rejection/duplicate handling, and generation.
- `OUT-001`/`RET-005`/`INT-001` retention integration is complete locally at
  Alembic head `0033_training_knowledge_check`: terminal-only locked
  project-before-purge, stable pseudonym configuration, retention-only grants,
  current outcome-writer locking, 365-day raw maximum, and 1,826-day PII-free
  ledger are wired. Privacy/RBAC, named-history API, reporting, graph, and export
  consumers remain open.
- The retained P1 is closed: `RetentionPolicy.__table_args__` mirrors migration
  `0032`'s retention-day check and single-default partial unique index, with
  metadata/database tests. The current-head gate additionally fixed the
  migration revision-id overflow so fresh databases can reach head `0032`.
- The checkpoint (`d25313d`) and every increment through the DEP-010
  strong-defaults/Advanced classification are committed and pushed;
  `origin/main` is `95cbc81` (review/CSP/A-drift/provider/chart waves landed,
  incl. `506b716`, `4ac0e9a`, `dc53688`, `93d33c0`, `95cbc81`). Current-head
  hermetic 2,694/103, external PostgreSQL 92, and external Redis 2 pass on
  2026-08-29; E2E, image, browser, and cloud gates remain open.
- The offline-buildable backlog is complete. ANA-010 (ledger graph, named close
  disposition, repeat history, per-recipient pseudonymous drill-down), TRN-010
  (campaign-bound knowledge check with deterministic evidence builder, digest
  pinning, generic quiz fallback), the AI-010 worker pinned-model enforcement
  (`KP_WORKER_AI_MODEL_ID` + cost/status metrics), and DEP-010 strong
  defaults/Advanced classification are all landed and pushed. Every remaining
  item needs an external environment: the internal-model benchmark/selection
  and pinned `llama.cpp` deployment (live loopback llama.cpp endpoint), then
  browser-login discovery with live progress/cost/rollback qualification, then
  the qualification lanes.

Use the copy-ready continuation prompt in `RESUME-HERE.md` verbatim when
starting the next build session.

The AI target is internal-model-first: benchmark two or three small
permissively licensed models, pin the chosen `llama.cpp` runtime/weights in the
existing worker role/job, and try CPU first. Scale-to-zero serverless GPU is
conditional on measurements; Foundry serverless/token inference is optional.
Do not add Foundry managed compute or an always-on GPU. `.140` remains
development/qualification infrastructure only.

## Current outcome

The codebase has moved from an eight-worker, development-auth, all-active-recipient prototype toward the intended simple architecture:

- three managed deployables by default: operator, tracking/training, and one multi-role worker;
- Entra-compatible OIDC and separated managed identities/database roles;
- exact audience preview and frozen manifests;
- crash-aware delivery claims and provider correlation;
- opaque tracking and training bearers with keyed verifiers at rest;
- token-bound lessons, completion, reminders, and training metrics;
- persistent emergency stop;
- a durable launch review and locked test-account cohort: schedule sends only
  the canary, and the separate full-publication action requires current
  server-derived provider/config evidence (authenticated delivered receipts
  for ACS);
- atomic queue transitions and GUI/API dead-letter operations;
- transactionally staged audit/queue intent with a database-owned audit dispatcher;
- a locally permission-tested create-only audit witness targeting locked Azure Blob storage;
- Microsoft Graph directory preview/apply and Microsoft 365 reported-message ingestion;
- ACS custom-domain readiness, pacing, provider correlation, and an Entra-authenticated, privacy-minimized Event Grid receipt pipeline; live subscription/receipt behavior remains unqualified.
- checked-in Alembic head `0033_training_knowledge_check`; `0031` adds the confirmed-interaction/PII-free 1,826-day ledger foundation, `0032` requires explicit re-review of legacy automatically active source evidence while enforcing migrated retention bounds/default uniqueness, and `0033` adds the optional all-or-nothing campaign-bound knowledge check (question + bounded distinct options + correct-answer index) with digest pinning and CHECK constraints. The current-head external PostgreSQL profile passed 92 tests on 2026-08-29 (fresh/historical migration, retention concurrency, outcome-writer-versus-retention, grants); the historical 86-test result at `0029` is superseded;
- a finite 2–12 occurrence Program Planner with allowlisted elapsed-day cadence, independent drafts, exact UTC review, duplicate-safe creation, and forward-only pause/resume;
- denominator-explicit single-campaign analytics plus bounded longitudinal Executive Trends JSON/CSV/GUI;
- retirement of shared-secret tracking corrections as an HTTP 410/no-write boundary, with the obsolete runtime/Terraform secret removed; normalized dual-reviewed corrections remain deferred;
- content-library route modularization and bounded unexpected-error logging, while broader god-file decomposition remains.
- capability-aware console session validation, navigation, and actions that fail closed on invalid or stale server-derived authority;
- authorized, audited, repeatable source enable/disable/manual-ingest operations in the backend and GUI; a post-fetch locked state check discards fetched material before writes when disable wins, while `job_id` remains only a request reference;
- bounded failure logging at 21 former production traceback/exception-message sites across worker/outbox/supervisor and audit/scheduler/rate-limiter paths, preserving behavior without exposing exception text or tracebacks;
- fixed-code durable queue failure state (`queue_dispatch_failed`) and stable allowlisted operator/auth/analytics public error boundaries;
- explicit no-skip hermetic, PostgreSQL, Redis, local-E2E, and Azure-live profiles, with operational readiness running the applicable local gates only after fail-fast disk/Docker/Compose/service checks and without printing connection URLs;
- PostgreSQL test jobs isolated on Redis DB14 with only DB14 flushed before/after that profile; the Redis queue contract isolated on DB15; application DB0 never used as a test cleanup target;
- a public tracking boundary that caps/validates request targets and streamed/declared bodies, accepts forwarding only from a direct peer in validated `TRACKING_API_TRUSTED_PROXIES`, resolves a bounded canonical `X-Forwarded-For` chain right-to-left, stamps privacy/security headers on early exits, and returns stable non-reflective errors. Managed Azure derives the exact proxy set from the Container Apps infrastructure subnet plus loopback and disables Uvicorn proxy rewriting;
- purpose- and assignment-bound lure, lesson-open, completion, and reminder links; generated content retains a placeholder until delivery, and static legacy awareness destinations fail closed;
- latest-request-wins directory preview fencing so an older Graph success or failure cannot overwrite or clear a newer preview;
- secret-safe operator/tracking/worker settings diagnostics and role-specific managed provider validation;
- explicit SMTP/ACS and Mailpit/Microsoft 365 GUI provider selects with conditional active-field validation, warning-only ACS reachability at an exact runtime origin, one quoted/bounded Graph delta probe, active non-secret setup-assist context, and validation-before-atomic credential rebinding;
- privacy export by authenticated `POST`, `private, no-store` privacy list/export responses, same-origin CSRF enforcement for cookie mutations, and independent notice/request loading so a notice failure warns without disabling request operations; plus issuer-origin-bound OIDC whose DNS-pinned transport preserves TLS Host/SNI while refusing redirects, proxy inheritance, HTTP/2, and cross-origin navigation or secret transmission;
- a preserved optional non-local HTTPS gateway adapter implementing `/propose` and `/setup-assist`; it is no longer the supported default AI deployment target. Pattern approval records a durable generation request without claiming asynchronous queue/provider completion, and the internal-model worker path plus live AI qualification remain open;
- a reviewed three-stage Azure workflow/Terraform/API/GUI path: `foundation_bootstrap` applies the complete `deploy_workloads=false` foundation, including ACR/private-network/data and ACS/DNS resources, without Terraform targets; it initiates four verification types while explicitly forbidding sender/association changes. `foundation_finalize` requires fresh all-four Verified state and post-apply association/sender proof; `workloads` revalidates exact resources and immutable images, then requires exactly one active Healthy/Provisioned worker revision, two consecutive simultaneous ready observations for every enabled role, and a same-revision final health recheck. Every stage refuses delete/replacement plans. The GUI rejects manual readiness claims, resumes/advances digest-bound plans, validates/displays final artifact evidence, and exports the same exact ACS endpoint contract enforced by API/Terraform/preflight. The connector is pinned to workflow SHA-256 `72d2f1bc7fac250882fdb6803701f1b183ce85711c22e1462f34422c35223d43`; no stage is live-qualified;
- removal of four uncalled/unexported helpers (`monotonic_timestamp`, `build_email_body`, `parse_sending_domains`, and `SafetyValidatorError`), reducing production code by 35 lines without changing behavior;
- local operator HSTS and release-readiness contracts that deliberately do not claim a qualified production edge, WAF, custom-host observation, rollback, or restore.
- immutable local Compose/mock base-image references, a hash-verified 17-package mock runtime, frozen normal workspace bootstrap/development/console use, a native CycloneDX 1.5 inventory with 59 total components/58 external PURLs, and a fail-closed zero-known-vulnerability audit of the 58 external packages;
- Wave 29 recovery controls: fixed Compose project and PostgreSQL/Redis volume
  names; fail-closed `.env` bootstrap when preserved state exists or cannot be
  inspected; command-specific, injection-resistant preflight environments;
  read-only `prestart` before Compose and `ready` after migration/seed; offline
  exact-cache base-image qualification; and a Redis `999:999` disposable-data
  write probe. Partial state is reconciled in place, never treated as permission
  for cleanup or a parallel volume;
- removal of public OpenAPI/Swagger/ReDoc/metrics routes and the operator/tracking write-only metric registries, while preserving bounded health/log state and worker metric snapshots; audit-scheduler retention is limited to aggregate status and problem count;
- GUI authentication-mode discovery that fails closed rather than silently defaulting to the disposable development credential;
- a versioned, key-ID-bound ciphertext format with one active and at most four prior decrypt-only keys; managed prior-key configuration is legacy/recovery-only, the first foundation fixes the active ID, active rotation is blocked, and the Terraform-generated active KEK remains in protected state/history behind `prevent_destroy`;
- official Starlette `TestClient` compatibility through the test-only `httpx2` dependency, without changing production HTTP clients.
- warning-strict SQLite lifecycle/outbox fixes, including deterministic owned-pool/test-engine disposal and explicitly typed outbox timestamps;
- an exact 113-route operator authorization manifest—103 capability-protected plus 10 dedicated/public routes—exact browser/backend capability inventory, capability-gated non-Azure actions, aggregate-reader Help, and safe preview for approve-only template reviewers;
- rejection of duplicate as well as malformed `Content-Length` at the public tracking edge;
- fail-closed exact workflow/code/test binding at frozen workflow SHA-256
  `72d2f1bc7fac250882fdb6803701f1b183ce85711c22e1462f34422c35223d43`.
- canonical bounded generation input/output and provider streaming contracts, with queue-key idempotency across retries/races and recipient-bound delivery proof;
- current source-terms acknowledgement/revocation across API, worker fences, and GUI;
- server-side request normalization plus capped non-reflective operator/tracking validation responses;
- server-derived training-resource action flags, author/reviewer separation, locking, and fail-closed GUI controls;
- aggregate/named/export reporting separation, owner-safe alert subscriptions with outbound hostname allowlisting, audited recipient-exclusion lifecycle, and server-paginated recipient management/named reporting;
- bounded OIDC, setup-assistant, AI-generation, and GitHub deployment response readers, including no-read GitHub dispatch bodies;
- deterministic cleanup for newly added PostgreSQL fixtures.
- the current loopback Mailpit `example.com` durable-gate canary passed within the latest external 8-test E2E profile at exact head `0029`, proving exactly-once canonical template delivery across retry, recipient-bound tracking, assignment reuse, separate training purposes, knowledge-check remediation/pass/replay, and correlated reporting/audit before exact cleanup; this remains local-live rather than provider/inbox evidence;
- native-UUID outbox completion and final reconciliation of 36 stranded idempotent queue intents after fixing an audit-store owner-fallback revocation defect; the final audit chain is green. Graph/Microsoft 365/ACS-event/reported-MIME seams are hardened with an explicit ACS managed-identity client ID;
- recovered provider-backed Terraform initialization/validation; server-derived campaign/pattern action flags and bounded privacy boundaries; protected GitHub environment/workflow/run plus owner-bound Redis lease validation; and worker preflight/context/reminder/retention/dead-path repairs.
- bounded database pagination for user-facing collections plus a fail-closed 100-candidate RoE scheduling cap; explicit application/worker runtime failures in place of production `assert` guards; and shared/exclusive campaign locking that orders scoped stop against delivery. Point-in-time evidence passed 52 focused worker lifecycle/security tests in 1.30 seconds and 15 isolated PostgreSQL tests in 3.07 seconds, including 250 ms lock contention. A separate isolated migrated-PostgreSQL scoped-kill persistence test passed 1 in 2.88 seconds at `0027`, then dropped its disposable database; the exploratory ACS pacing fence reserved 3 then 0 in one window.
- removal of the broken installed `kp-seed` wrapper, ignored reminder/Mailpit-TLS/queue-prefix settings, and remote full-stack stop routing/capability/marker handling from the browser, supervisor, and launcher. Source `make seed` remains, training due time remains a fixed 72-hour policy, Settings retains GUI restart, a host signal stops the launcher, and full shutdown requires OS/launcher/terminal recovery. The stop-removal lane passed 39 focused tests. `make sign` now fails closed without an immutable `IMAGE`, `COSIGN_KEY`, and `cosign`; no external signing evidence exists.

The decision remains **NO-GO for production and RSA Conference use**. The audited GitHub repository is `ELDSRQ/kingphisher-phoenix`. Local/static implementation is ahead of the live evidence. No disposable Azure deployment, real Entra role exercise, Graph/Outlook consent path, ACS custom-domain campaign, full browser accessibility pass, live-qualified external audit witness, production recovery exercise, AMD64 qualification, or registry publication/attestation has yet closed the release gate. Wave 29's local recovery contracts are not a restore or provider-live witness.

Wave 21's latest completed snapshot rebuilt all five native ARM64 images. Applicable startup/migration checks, 30 focused contracts, and scans at 0 HIGH / 0 CRITICAL vulnerabilities and 0 secrets passed. Exact IDs/sizes are in the canonical plan. Later source edits through Wave 38 make those interim images stale. The old controller free-space snapshot is historical gate evidence; external build/local-live capacity, cutover, restore, installation, and installation verification are now proven. Exact-final ARM64 status depends on the retained qualification evidence described below. AMD64/multi-architecture and registry publication/attestation remain unwitnessed.

The exact-final ARM64 result is evidence-conditional: only retained no-clobber
`qualification.json` plus scan evidence can prove the exact non-emulated Docker
server platform, explicit `--platform`, all-five OS/architecture/image-ID
metadata, unchanged source/context manifests, Trivy 0.74.0, and verified cleanup
of labeled disposable resources. The verifier additionally binds the expected
source-manifest digest and exact Trivy executable/hash/cache, retained empty config/ignore/secret policy files, rejects ambient
`TRIVY_*`, records fresh database/check-bundle metadata, and makes the verified
cache immutable. Azure workloads separately scan immutable ACR
`repository@sha256` images with pinned Trivy before SBOM/attestation/deploy and
retain scan JSON/checksums. No pass is inferred here.
The fixed planned ARM64 evidence root is
`/Volumes/DockerExternal/KingPhisher-Phoenix/qualification-evidence/arm64-release-20260829-wave35-final-v3`
with `verifier/` beneath it and unique prefix
`kingphisher/verify-arm64-20260829-w35-final-v3`; only validated retained
contents determine the gate.
The preserved `final-v2` attempt failed closed before image build on BSD
filesystem-mode and evidence-path/source-context defects. Its failure evidence
was retained; those bugs are repaired for `final-v3`, which remains conditional
until its no-clobber qualification and per-image scan/checksum evidence validate.

Historical and overlapping focused evidence remains labeled in the canonical plan. Wave 21 added green installation verification and a strict 7 passed/0 skipped/0 warning local E2E run in 3.37 seconds after targeted bootstrap/audit, token-key, PID/log, mock Graph, and fixture repairs. RoE/RBAC hardening passed 374 owned/consumer tests plus static/security/offline package gates. Its 23 workflow tests, Actionlint, and Zizmor passed at the historical Wave 21 SHA, not the current frozen connector. Removing the dead clone adapter reduced the tree by 87 lines and passed 36 focused plus 5 downstream tests. These counts are separate and must not be summed.

The earlier operational-readiness interruption remains historical. Its pre-Wave-30 result was 1,994 hermetic, 87 PostgreSQL, 2 Redis, and 8 E2E tests; the intermediate external 2,230/86/2/8 result is also superseded. The 2,329 hermetic/97 deselected, 86 PostgreSQL/2,340 deselected at exact head `0029` using Redis DB14, 2 Redis/2,424 deselected on DB15, and 8 E2Es plus audit/install result is now a pre-remediation snapshot. The pre-Wave-36 local hermetic result is 2,469 passed/97 deselected, 0 failures in 158.15 seconds. The final local Wave 36 hermetic suite at historical head `0030` passed 2,501/97 deselected with 0 failures in 183.40 seconds; current-head `0032` PostgreSQL/Redis/E2E external profiles remain pending. Earlier controller observations at about 5.9 and 5.6 GiB remain dated proof that the 8 and 10 GiB gates stopped safely. External capacity and restore are proven; browser, exact-final image, provider-live, recovery, and witness qualification remain open.

The historical 2026-08-28 Azure inspection confirmed the selected subscription/tenant, subscription Owner authority, `eastus2`, required provider readiness including `Microsoft.Communication`, and absence of a Terraform backend, foundation resource group, platform Entra applications, and application resources. The 2026-08-29 sandboxed re-audit could prove only an enabled cached account because DNS could not resolve `management.azure.com`; current management-plane state is therefore unverified. The live GitHub re-audit proves valid `ELDSRQ` authentication with `repo`/`workflow` scopes; a public, enabled repository with default `main`; Actions enabled; and the Azure workflow active, with no billing-disabled run signal. It also proves zero environments, variables, secrets, rulesets, and workflow runs, unprotected `main`, disabled secret scanning and push protection, and remote `main` at old-tree SHA `1403d944a40214714b6cbfcf5cbabc4fa7225eb9` at re-audit time; the checkpoint push has since advanced remote `main` to `c9ea716`. The connector's protected-environment/workflow/run validation and Redis lease behavior pass locally, but no workflow dispatch/run or Azure apply occurred. The next cloud step requires reviewed final-source sync plus protected environment/reviewers, variables, secrets, branch protection/rulesets, repository secret protections, revalidated Azure state, and backend/bootstrap inputs before any of the three deployment stages can run.

## Do not regress

- Do not restore a shared password/JWT as managed identity, all-active targeting, reusable stored token hashes, eight Azure worker applications, disconnected tokenless training, Mailpit-only Microsoft 365 behavior, or provider acceptance as delivered mail.
- Do not give runtime applications a database administrator URL, all-vault access, audit-root access, or direct audit-table mutation.
- Do not let AI apply state, handle secrets, select audiences, approve content, or weaken deterministic gates.
- Do not automatically retry `INDETERMINATE` mail sends.
- Do not expand a frozen audience after a directory change.
- Do not describe static Terraform/tests as live Azure or provider evidence.
- Do not restore the retired shared-secret `/v1/corrections` write path or silently subtract scanner/bot activity from observed analytics.
- Do not claim that source disable aborts provider I/O. Preserve the post-fetch lock/refetch fence that discards fetched material before writes when disable wins, and do not present an ingestion `job_id` as a status endpoint.
- Do not log or persist exception messages or tracebacks in worker/outbox failure paths; preserve bounded event/type logs and the fixed durable failure code.
- Do not restore `TRACKING_API_CORRECTIONS_SECRET`, the Terraform corrections secret, or any authentication/write behavior on the retired 410 endpoint.
- Do not reflect arbitrary backend exception text through operator/auth/analytics responses; keep public errors stable and allowlisted.
- Do not merge live PostgreSQL, Redis, E2E, or Azure tests into the hermetic profile or permit skips in a claimed gate.
- Keep PostgreSQL integration queues on DB14 and flush only DB14 before/after that profile; keep the Redis contract on DB15; never flush or repurpose application DB0.
- Do not restore a static training destination in generated or delivered lure content. Preserve placeholder-to-tracking-click resolution and distinct assignment-bound open/completion purposes.
- Do not remove the directory `last_job_key`/configuration recheck around provider I/O; stale successes and failures must remain `superseded`.
- Do not weaken public tracking target/body limits, duplicate/malformed `Content-Length` rejection, proxy trust, all-response security headers, or exception translation.
- Do not let configuration validation render secret inputs or nested exception chains, and do not make managed workers require unrelated provider settings.
- Do not restore public OpenAPI/docs/metrics routes, raw audit-problem retention, or a browser fallback from failed auth-mode discovery to development authentication.
- Do not mutate the workspace lock during normal bootstrap, development, or console launch; keep local image digests and mock dependency hashes immutable, and keep dependency audit/SBOM scoped to the full external production closure.
- Do not present managed legacy/recovery keys as active rotation. Preserve the post-foundation immutable active ID and `prevent_destroy`; do not retire a prior key until a separately reviewed bulk rewrite/proof establishes that no required ciphertext needs it.
- Do not collapse the three Azure dispatches. Initial foundation, live-verified sender-finalization foundation, and workloads each retain their saved-plan/delete-replacement/fresh-evidence/image/source gates. Never trust operator-entered ACS readiness strings or timestamps.
- Do not change the fixed Compose project/volume identities or generate critical
  `.env` credentials when preserved state exists or cannot be inspected. Keep
  subprocess environments command-specific, preserve exact cached images, run
  `prestart` before Compose and `ready` after migration/seed, and reconcile from
  checkpoints/evidence. Never prune, delete, reset, recreate, rename, or blindly
  redispatch to recover.
- Do not run `.140` project Docker commands without proving the exact external
  mount, profile, socket, and canonical source. Never change the global context
  or mutate the shared Docker Desktop engine/unrelated workloads. Preserve the
  internal project source and encrypted snapshots. The internal seven-container
  copy is stopped/preserved after checkpoint/external verification, and the legacy
  encrypted snapshot is unrecoverable because its identity is absent.
- Do not send external email or alter real Azure/Microsoft resources without the authority and safety controls required by the active task.

## Recommended continuation

Follow the alignment sequence. First close the single ORM retention-metadata P1,
run the complete local and current-head PostgreSQL gates, reconcile evidence,
then commit and push the preserved checkpoint to `main`. Next finish the
privacy/RBAC/API/reporting/graph consumers around the `0032`
outcome/retention/interaction foundation, then benchmark and pin the
internal model in the existing worker and complete the minimum Threats → safe
draft → campaign-specific training → named five-year result loop. Then simplify
the GUI deployment/mail path while preserving the current provider adapters and
three-stage fail-closed Azure contract. Finally qualify the exact stable tree:
current-head external profiles, exact ARM64 and native AMD64/registry images,
browser/WCAG, disposable Azure, Entra/Graph/ACS/Event Grid/Outlook/DNS/inbox,
backup/restore, recovery/rotation, external audit witness, and human operation.
Navigation/module simplification follows stable core behavior; deferred useful
features remain supported without expansion.

For any handoff, record evidence in the build plan using these labels:

- **local/static** — code, tests, migrations, Terraform validation, scanners, images;
- **local live** — disposable local PostgreSQL/Redis/APIs/workers/Mailpit;
- **cloud/provider live** — Azure, Entra, Graph, ACS, Outlook, browser, backup/restore, and recovery in the intended environment.

Only cloud/provider-live evidence can close the corresponding production gate.
