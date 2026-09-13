# AI Handoff — 2026-09-13 (P0–P3 + P3 consumer deployed; DEP-010 complete; staging idled)

**Supersedes** `AI_HANDOFF_2026-09-12.md`. Design reference: `docs/AI_PIPELINE_REDESIGN_SPEC.md`,
`docs/AI_PIPELINE_P1-P3_RESUME.md`, and `docs/design/DEP-010-BUILD-PLAN.md`.

**Repo:** `/Users/edierks/projects/codex-test/phishing-awareness-platform`
**Head:** `main` clean, nothing unpushed, CI green. Verify state, not a sha:
`git log --oneline -5` (a later docs commit will be newer than any sha named below).

---

## 0. TL;DR — where things stand

- **P0–P3 AI pipeline: merged + deployed to Azure staging** (bounded generation, `gpt-5.6-terra`
  generation, `gpt-5.6-luna` extract/discover).
- **P3 consumer (console `/discover` route): DEPLOYED + verified** on staging (was the one open
  item in the prior handoff). The first deploy failed on a missing `ai-gateway-auth-key` secret
  block on the operator container app; fixed in PR #6 (`azurerm_container_app.operator` now declares
  the secret) and re-deployed green. `POST /api/v1/console/discover/search` → 200 with
  `model_id: gpt-5.6-luna`; a query containing `@` → 422 (PII gate).
- **DEP-010 (simplified GUI Azure/mail deployment): COMPLETE** — all three phases merged:
  - **P1** browser Azure discovery (client-side PKCE popup, no npm dep) — PR #9
  - **P2** static monthly cost estimate — PR #10
  - **P3** roll-forward-to-last-green rollback + recovery — PR #11
- **MAIL-005** (ACS positioned as recommended managed send) — PR #7. **DOC-030** (worker docs
  reconciled to the `.105` WSL2 worker) — PR #8.
- **Task matrix reconciled** against live code (see §5): most items COMPLETE or live/human-gated;
  the buildable, non-gated backlog is now **empty**.
- **⚠️ Azure staging is currently POWERED OFF to save cost** (operator request, end of session).
  See §2 to bring it back before any staging work.

---

## 1. What shipped this session (all merged to `main`)

| PR | Item |
|----|------|
| #6 | Fix: declare `ai-gateway-auth-key` secret on the operator container app (unblocked the P3 consumer deploy) |
| #7 | MAIL-005: ACS = recommended managed send, SMTP = advanced (onboarding UI) |
| #8 | DOC-030: reconcile README/RUNBOOK/architecture/AGENTS/remote-docker-worker docs to the `.105` WSL2 worker (additive; contract guard preserved) |
| #9 | DEP-010 P1: client-side browser Azure discovery (PKCE popup) pre-filling the wizard |
| #10 | DEP-010 P2: static monthly cost estimate in the wizard |
| #11 | DEP-010 P3: roll-forward-to-last-green rollback + recovery |

Also: the staging `workloads` deploy that put the P3 consumer live; the task-matrix reconciliation;
and repo cleanup (stale P0–P3 branches + 9 finished agent worktrees removed — all their work was
already on `main`).

---

## 2. ⚠️ Azure staging is powered off — bring it back before staging work

Powered off at end of session (RG `rg-kp-staging`, operator identity in `$HOME/.azure`):
`vm-kp-staging-runner` **deallocated**; `psql-kp-staging-6117w` **stopped**; container apps
`ca-kp-staging-{operator,tracking,worker}` **min-replicas 0** (ai-gateway was already scale-to-zero).
Residual charges remain only for storage/disks, the Container App Environment, Key Vault, and Log
Analytics (those stop only on deletion, which was deliberately NOT done — this is a pause).

To resume (operator identity — the shell default `AZURE_CONFIG_DIR` is the subscription-less
`licensing@` dir, so export the real one):

```bash
export AZURE_CONFIG_DIR="$HOME/.azure"        # erik.dierks@gmail.com, sub 169644fd, rg-kp-staging
az vm start                    -g rg-kp-staging -n vm-kp-staging-runner
az postgres flexible-server start -g rg-kp-staging -n psql-kp-staging-6117w
# Restore container-app replicas either with a workloads deploy (§3) or directly:
for a in ca-kp-staging-operator ca-kp-staging-tracking ca-kp-staging-worker; do
  az containerapp update -g rg-kp-staging -n "$a" --min-replicas 1; done
```

Postgres auto-restarts ~7 days after being stopped. The nightly-shutdown workflow will re-idle
compute overnight; a `network_mode=private` deploy needs the runner VM up first or it queues for
hours (learned the hard way — start the VM before dispatching).

---

## 3. Remaining work (priority order) — all needs an operator decision, nothing is un-built

1. **DEP-010 discovery, to actually use it on staging** (Azure-side config, not code): register an
   Entra SPA app (the wizard's `entra_client_id`) with delegated **Azure Service Management
   (user_impersonation)** permission and `/console/azure-redirect.html` as a **SPA redirect URI**.
   Until then the "Discover from Azure" button explains what's missing and manual entry works.
2. **Production generation model** — `environments/production.tfvars` still defaults to
   `gpt-oss-120b` bounded (coherent, no regression). Moving prod to `gpt-5.6-terra` is a one-file
   tfvars edit (`ai_foundry_model`/`ai_reasoning_effort=""`/`ai_send_temperature=false`) + a prod
   deploy. Operator chose to keep gpt-oss-120b for now.
3. **RET-005** pseudonym-key rotation/recovery — the ledger substrate is complete; only key
   rotation/recovery is unbuilt, and it is **operator/governance-gated** (needs a rotation policy
   decision before building).
4. **UX-010** five-area navigation IA — **DEFERRED** per the goal-aligned priority policy; do not
   build without an explicit scope change.
5. **Live campaign** — still gated on a **distinct second identity** to approve a pattern (the
   self-approval bar is unconditional). Pattern `7e0d6ece-8c94-5a6a-8775-971094a99729` was approved
   last session via `licensing@` (do not re-approve — 409). `single-operator` posture is live.
6. **Live/human-gated evidence** (code done, only live proof pending): SAFE-030 (provider-live
   delivery receipt), AZ-030 (live ACS/inbox/human-mailbox), AI-010 (live Foundry run), A11Y-030
   (real-browser/WCAG walkthrough).

---

## 4. Hard-won facts (do not relearn)

- **Two workflow-SHA pins** must both be re-pinned on any `azure-deploy.yml` edit:
  `EXPECTED_WORKFLOW_SHA256` in `apps/operator-api/src/kp_operator_api/deployment_common.py` AND
  `EXPECTED_DEPLOY_WORKFLOW_SHA256` in `tests/test_azure_idle_workflow_contract.py`.
- **A Container App env `secretRef` needs a matching `secret {}` block on that same app** or the
  apply 400s `ContainerAppSecretRefNotFound` — `terraform plan`/`validate` cannot catch it (this was
  the P3-consumer deploy failure; regression test added in `test_runtime_contract.py`).
- **The handoff docs are guarded** by `tests/test_external_worker_handoff_contract.py`, which pins
  the retired-`.140`-worker strings across ~13 docs. Update those docs **additively** (keep every
  pinned string; the `.140` engine is RETIRED, the `.105` WSL2 host is current) or the hermetic gate
  goes red. `AI_HANDOFF_2026-09-13.md` (this file) and `NEXT_AI_PROMPT.md` are NOT guarded.
- **Test suites need `KP_DISABLE_DOTENV=1`** or the local `.env` pollutes settings-driven tests.
- **The operator console is CSP-hardened** (`default-src 'none'`, self-only). DEP-010 P1 widened
  `connect-src` to `login.microsoftonline.com` + `management.azure.com` for browser discovery (popup,
  no frame-src). The frontend is deliberately near-zero-dependency with a byte-exact bundle drift
  gate (`test_console_bundle_drift.py`) — rebuild `apps/operator-ui` (`npm run build`) and commit the
  bundle after any `console-js/` edit; avoid adding npm deps (DEP-010 used hand-rolled PKCE to keep
  it dependency-free).
- **Terraform local apply is blocked** (backend SAS 403 + missing KV role). CI applies via OIDC.
  Locally: `terraform fmt`, `init -backend=false` + `validate`, then `git checkout` the lock.
- **Pattern self-approval is unconditional**; a single operator cannot approve their own pattern.
- **Reviewed deployment_config**: recover from any green `azure-deploy.yml` run log via
  `grep -m1 "REVIEWED_DEPLOYMENT_CONFIG:"`; it carries the 38-key contract and its
  `allowed_recipient_domains` overrides `staging.tfvars`.
- **Deploy needs the VNet runner UP**: a private-mode deploy dispatched while `vm-kp-staging-runner`
  is deallocated (e.g. by the nightly shutdown) queues indefinitely — `az vm start` it first.

---

## 5. Reconciled task-matrix status (verified against live code 2026-09-13)

COMPLETE (in code): ORG-001, OUT-001, INT-001, UX-030, THR-001A, THR-001B, TRN-010, AI-005,
ANA-010, IMP-001, DOCSIM-001, SEC-030, SEC-031, REL-031, REL-030, **MAIL-005, DOC-030, DEP-010**.
LIVE/HUMAN-GATED (code done): SAFE-030, AZ-030, AI-010, A11Y-030.
SUPERSEDED (matrix stale): EXT-001/EXT-002 (the `.140` engine is retired → `.105` WSL2).
GATED/DEFERRED: RET-005 (key rotation, operator-gated), UX-010 (deferred).
The `docs/PRODUCTION-READINESS-TASK-MATRIX.md` self-reconciled date is 2026-08-30 and predates all
of the above — trust this section over stale rows.

---

## 6. Verify state first (run before acting)

```bash
git log --oneline -5 && git status --short           # expect clean
gh run list --branch main --limit 1                  # expect green
gh pr list                                            # expect empty

KP_DISABLE_DOTENV=1 uv run --frozen python -m pytest \
  packages/contracts/tests/test_discovery.py \
  infrastructure/terraform/tests/ \
  apps/operator-api/tests/test_deployment_orchestration.py \
  apps/operator-api/tests/test_dep010_discovery_contract.py \
  apps/operator-api/tests/test_deployment_cost.py -q

make lint && make typecheck
```

---

## 7. Reference values (Azure staging)

```
RG="rg-kp-staging"   FOUNDRY="ais-kp-staging-6117w"
SUBSCRIPTION_ID="169644fd-c81d-4935-af55-5770f8271022"   TENANT_ID="808f2f63-5b2c-46e6-ace7-d133a2df35f8"
OPERATOR_URL="https://ca-kp-staging-operator.calmflower-9463bfc2.eastus2.azurecontainerapps.io"
Deployed Foundry models (out-of-band): gpt-oss-120b, gpt-5.6-terra, gpt-5.6-luna
Second approver: licensing@erikdierksgmail.onmicrosoft.com (AZURE_CONFIG_DIR="$HOME/.azure-licensing")
Infra ops identity: erik.dierks@gmail.com (AZURE_CONFIG_DIR="$HOME/.azure")
Docker worker: erikd@192.168.1.105 (WSL2; scripts/operator/wsl2-docker-worker/; .140 retired)
```
