# AI Handoff — 2026-09-13 (P0–P3 merged + deployed; P3 consumer built, deploy pending)

**Supersedes** `AI_HANDOFF_2026-09-12.md`. Design reference: `docs/AI_PIPELINE_REDESIGN_SPEC.md`
and `docs/AI_PIPELINE_P1-P3_RESUME.md`. Longer history: `docs/NEXT_SESSION_HANDOFF.md`.

**Repo:** `/Users/edierks/projects/codex-test/phishing-awareness-platform`
**Head:** `5e71837` on `main` — tree clean, nothing unpushed, CI green. Verify state, not a sha:
`git log --oneline -3` (a docs commit here will be newer than any sha named below).

---

## 0. TL;DR — where things stand

The four stacked AI-pipeline PRs are **merged** and **deployed** to Azure staging. The
P3 consumer (the on-demand console route that pulls web-search leads) is **built and on
`main` (`5e71837`), but NOT yet deployed** — it needs one more `azure-deploy.yml`
workloads dispatch (and the usual human approval) to take effect.

Two decisions are still open and should be resolved before/with the next deploy:

1. **Deploy the P3 consumer now?** (needs a workloads dispatch + staging-approval click).
2. **Production generation model** — `production.tfvars` still defaults to `gpt-oss-120b`
   (bounded); deciding to move production to `gpt-5.6-terra` is a one-file tfvars change.

And the live-campaign goal still needs a **distinct second identity** to approve a pattern
(§8); `single-operator` posture is already live on staging, which removes the 3-approver
publish deadlock but does **not** relax the pattern self-approval bar.

---

## 1. What changed this session

| Item | Status |
|------|--------|
| Merge PRs #1 → #4 (P0 reliability, P1 extraction, P2 sanitizer, P3 discovery) | ✅ merged bottom-up to `main` |
| Deploy P0–P3 to staging | ✅ run `34728845782` (at `0719c46`) |
| Build P3 consumer (console `/discover` route + Terraform secret grant) | ✅ committed `5e71837`, CI green, **not deployed** |

### 1.1 Why the merge needed care (do not forget)

- **Missing second workflow SHA pin.** PR #1 re-pinned `EXPECTED_WORKFLOW_SHA256` in
  `deployment_common.py` but **not** the second pin in
  `tests/test_azure_idle_workflow_contract.py` (`EXPECTED_DEPLOY_WORKFLOW_SHA256`). The
  hermetic gate failed on #1 and every stacked PR inherited it. Fixed in `b3ee319` (one
  line). Any future `azure-deploy.yml` edit must re-pin **both**.
- **Strict branch protection** (`strict: true` on `main`). Each stacked PR went
  `mergeStateStatus=BEHIND` and had to be updated with main (local `git merge origin/main`
  + push) before `--auto` would merge. Merge bottom-up: #1 → (auto-retarget) → #2 → … → #4.

### 1.2 What is LIVE on staging (post `34728845782`)

```
ca-kp-staging-worker:    KP_WORKER_AI_MODEL_ID          = gpt-5.6-terra
                         KP_WORKER_PROVIDER_TIMEOUT_SECONDS = 30   (supersedes the 45s hotfix)
ca-kp-staging-operator:  OPERATOR_APPROVAL_POLICY        = single-operator
                         OPERATOR_API_AI_MODEL_ID        = gpt-5.6-terra
ca-kp-staging-ai-gateway:KP_AI_GATEWAY_MODEL_ID           = gpt-5.6-terra
                         KP_AI_GATEWAY_EXTRACT_MODEL_ID    = gpt-5.6-luna   (reasoning=none)
                         KP_AI_GATEWAY_DISCOVER_MODEL_ID   = gpt-5.6-luna   (Responses web_search)
                         KP_AI_GATEWAY_REASONING_EFFORT    = ""            (terra 400s on it)
                         KP_AI_GATEWAY_SEND_TEMPERATURE    = false         (terra 400s on explicit temp)
                         KP_AI_GATEWAY_MAX_COMPLETION_TOKENS = 2000
                         KP_AI_GATEWAY_RESPONSES_BASE_URL  = https://ais-kp-staging-6117w.services.ai.azure.com/openai/v1
```

### 1.3 What the P3 consumer adds (commit `5e71837`, NOT yet on staging)

- `POST /api/v1/console/discover/search` and `GET /api/v1/console/discover/allowed-domains`
  under capability `manage:source` (new file `apps/operator-api/src/kp_operator_api/console/discovery_routes.py`).
- `OperatorApiSettings` gains `ai_gateway_url` (`OPERATOR_API_AI_GATEWAY_URL`) and
  `ai_gateway_api_key` (`OPERATOR_API_AI_GATEWAY_API_KEY`).
- Terraform (`infrastructure/terraform/main.tf`): operator container gets
  `OPERATOR_API_AI_GATEWAY_URL = var.ai_endpoint` and (conditionally) the
  `ai-gateway-auth-key` secret grant, gated on `deploy_workloads && deploy_ai_gateway`.
- Route fails closed `503` when `ai_gateway_url` is unset → on-prem stays offline.
- Tests: `apps/operator-api/tests/test_discovery_routes.py` + entries in
  `test_route_authorization_inventory.py` + one contract-test string update in
  `infrastructure/terraform/tests/test_runtime_contract.py`.

---

## 2. Remaining work (priority order)

### 2.1 Deploy the P3 consumer (one workloads dispatch + approval)

Same path as every deploy — CI is the only mutation path (local Terraform apply stays
blocked: state-backend SAS 403 + a KV data-plane role the human lacks).

```bash
# Rebuild the reviewed deployment config if lost (see §6.2), then:
REQ_ID="kp-$(openssl rand -hex 16)-1"
gh workflow run azure-deploy.yml --ref main \
  -f environment=staging -f network_mode=private -f deployment_phase=workloads \
  -f deployment_config="$CONFIG" \
  -f deployment_request_id="$REQ_ID" \
  -f reviewed_commit_sha=$(git rev-parse HEAD)
# Wait for the "waiting" state, then the operator approves at the run page:
#   https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/<id>
```

Post-deploy verify:

```bash
# operator should now carry the gateway URL + a secret-backed API key:
az containerapp show -g rg-kp-staging -n ca-kp-staging-operator \
  --query "properties.template.containers[0].env[?name=='OPERATOR_API_AI_GATEWAY_URL']" -o json
az containerapp show -g rg-kp-staging -n ca-kp-staging-operator \
  --query "properties.template.containers[0].env[?name=='OPERATOR_API_AI_GATEWAY_API_KEY']" -o json   # secretRef: ai-gateway-auth-key
```

Then exercise it (the operator's own `manage:source` identity, not `licensing`):

```bash
TOKEN=$(az account get-access-token --resource "api://97466174-d0ac-460c-94e8-7b6ff3c83da5" --query accessToken -o tsv | tr -d '\n\r')
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://ca-kp-staging-operator.calmflower-9463bfc2.eastus2.azurecontainerapps.io/api/v1/console/discover/search" \
  -d '{"query":"credential phishing campaigns targeting finance"}'
# Expect 200 with {"leads":[...], "model_id":"gpt-5.6-luna"}. A query with "@" -> 422 (PII gate).
```

### 2.2 Decide the production generation model

`environments/production.tfvars` sets none of the AI vars → defaults to `gpt-oss-120b`
bounded (reasoning `low`, temp on, 2000-cap, 30s): coherent, no regression. To move
production to terra (matches staging), add to `production.tfvars`:

```hcl
ai_foundry_model      = "gpt-5.6-terra"
ai_reasoning_effort   = ""
ai_send_temperature   = false
```

`gpt-5.6-terra` / `-luna` are already deployed out-of-band in Foundry (§3). This needs no
code change — just the tfvars edit + a production deploy (its own review/approval path).

### 2.3 Live Azure campaign (blocked on human second-identity action, not code)

- `single-operator` posture is already live, so submit → `APPROVED` and publish under one
  identity works. The remaining hard stop is the **pattern self-approval bar**, which is
  unconditional (§3): the pattern `7e0d6ece-8c94-5a6a-8775-971094a99729` is already
  APPROVED (approved via `licensing` last session — do **not** re-approve, 409), which
  means generation is unblocked. Resume the seed/launch from there, or re-run the
  source→activate→approve flow (a freshly activated pattern must be approved by a
  *different* identity than the activator; template and training-resource approval have the
  same author≠reviewer rule). The full campaign launch sequence (import → create →
  audience/freeze → submit → schedule → canary → publish) is unchanged.

---

## 3. Hard-won facts (accumulated; do not relearn)

- `gpt-5.6-terra` rejects an explicit `temperature` **and** `reasoning_effort` (400) —
  run it with temperature omitted (`send_temperature=false`) and no reasoning effort.
- `gpt-5.6-luna` rejects an explicit `temperature`; accepts `reasoning_effort` incl. `none`
  (extraction/discovery use `none`). `none` is an allowed gateway reasoning value.
- For reasoning models `max_completion_tokens` includes reasoning tokens (cap truncates JSON).
- **Foundry account + model deployments are NOT Terraform-managed.** They liveout-of-band
  in `ais-kp-staging-6117w`: `gpt-oss-120b`, `gpt-5.6-terra`, `gpt-5.6-luna` (cap 200).
  `Microsoft.Bing` provider is Registered — that alone enabled Responses-API `web_search`;
  no separate Bing-grounding resource was needed.
- **Model comes from `environments/<env>.tfvars`** (CI no longer passes `-var`).
- Editing `.github/workflows/azure-deploy.yml` **requires re-pinning `EXPECTED_WORKFLOW_SHA256`
  in `deployment_common.py` AND `EXPECTED_DEPLOY_WORKFLOW_SHA256` in
  `tests/test_azure_idle_workflow_contract.py`** (two pins — one was missed and broke the
  gate; `test_deployment_orchestration` / `test_azure_idle_workflow_contract` enforce them).
- The **ai-gateway is its own uv workspace**: `cd apps/ai-gateway && KP_DISABLE_DOTENV=1 uv run --frozen python -m pytest tests/test_gateway.py -q`
- **Terraform local apply is blocked** (backend SAS 403 + missing KV data-plane role). CI
  applies via OIDC. Locally: `terraform fmt`, `terraform init -backend=false` + `validate`,
  then `git checkout infrastructure/terraform/.terraform.lock.hcl` (never commit lock churn).
- **Pattern self-approval is unconditional** — a single operator cannot approve their own
  pattern (also true for template/training-resource "author ≠ reviewer"). Use `licensing@`
  (§8) for the second identity. This is NOT relaxed by `single-operator`.
- **Testing gotcha:** run the operator-api / terraform contract test suites with
  `KP_DISABLE_DOTENV=1`. Without it, the local `.env` (which sets
  `OPERATOR_API_APPROVAL_POLICY=single-operator`) pollutes `test_send_policy.py` and makes
  it *look* like a config regression when the code is fine.

---

## 4. Security boundaries (unchanged — never cross)

- Never grant operator API or workers the `audit-hmac` signing root.
- Never change the shared Entra audience default (`kp-operator-api` is correct for on-prem Keycloak).
- Docker only on `.105` (never the Mac). Pinned worker: `KP_DOCKER_WORKER=erikd@192.168.1.105`.
- On-prem stays fully offline — P3 `/discover` is OFF on-prem (no web egress); keep it that way.
- Never `git add -A`; never commit secrets or `.terraform.lock.hcl` churn.
- The AI-gateway's shared bearer (`ai-gateway-auth-key`) is a *gateway auth* secret, distinct
  from the audit signing root; granting it to the operator API (for /discover) is **not**
  a boundary violation — but never extend the audit-hmac line.

---

## 5. Verify state first (run before acting)

```bash
git log --oneline -3 && git status --short        # expect clean, HEAD 5e71837 or newer
gh run list --branch main --limit 1                # expect green
gh pr list                                          # expect empty (all merged)

KP_DISABLE_DOTENV=1 uv run --frozen python -m pytest \
  packages/contracts/tests/test_discovery.py \
  infrastructure/terraform/tests/ \
  apps/operator-api/tests/test_discovery_routes.py -q

make lint && make typecheck
```

Then read `docs/AI_PIPELINE_REDESIGN_SPEC.md` and `docs/AI_PIPELINE_P1-P3_RESUME.md` in full.

---

## 6. Operational notes

### 6.1 Staging approval is a required-reviewer gate

The `staging` GitHub environment has `required_reviewers` (user `ELDSRQ`). Every workloads
deploy hands at the "Deploy reviewed Azure phase" until the operator clicks **Approve
deployment** on the run page. State is observable via:

```bash
gh api "repos/{owner}/{repo}/deployments?environment=staging&per_page=1" --jq '.[0].id'
gh api "repos/{owner}/{repo}/deployments/<id>/statuses" --jq '.[0].state'   # waiting / in_progress
```

### 6.2 Rebuild the reviewed deployment config (if it is lost)

`/tmp/kp-deploy-config.json` was the reviewed config from a prior green run; it may not
survive to the next session. Recover it from any green `azure-deploy.yml` run's log:

```bash
gh run view <green-run-id> --log 2>/dev/null | grep -m1 "REVIEWED_DEPLOYMENT_CONFIG:" | sed 's/.*REVIEWED_DEPLOYMENT_CONFIG: //'
```

Facts about that JSON: it carries exactly the 38-key reviewed contract, and its
`allowed_recipient_domains` **overrides** `staging.tfvars` (a later `-var-file` wins). The
last green run used `erikdierksgmail.onmicrosoft.com,gmail.com` — so `floridamanevolved.us`
is **not** in the live recipient allowlist despite being pinned in tfvars. If the campaign
must mail a `floridamanevolved.us` recipient, update `allowed_recipient_domains` in the
dispatching config. `acs_*_verification_status` fields are overwritten to
`pending_live_readback` and re-verified live each run, so their values in the JSON don't matter.

---

## 7. Repository layout (relevant to this work)

```
apps/operator-api/src/kp_operator_api/console/discovery_routes.py   # P3 consumer (new)
apps/operator-api/src/kp_operator_api/config.py                     # ai_gateway_url/api_key fields
apps/operator-api/tests/test_discovery_routes.py                     # P3 consumer tests
infrastructure/terraform/main.tf                                     # operator env + ai-gateway-auth-key grant
infrastructure/terraform/environments/{staging,production}.tfvars    # model ownership + approval posture
apps/ai-gateway/src/kp_ai_gateway/main.py                            # /propose /extract /discover
packages/contracts/src/kp_contracts/discovery.py                     # PII-free + citation-allowlist gates
docs/AI_PIPELINE_REDESIGN_SPEC.md, docs/AI_PIPELINE_P1-P3_RESUME.md  # design + lesson record
```

---

## 8. Reference values (Azure staging)

```
RG="rg-kp-staging"
FOUNDRY="ais-kp-staging-6117w"
FOUNDRY_CHAT_BASE="https://ais-kp-staging-6117w.cognitiveservices.azure.com/openai/v1"     # /chat/completions (propose, extract)
FOUNDRY_RESPONSES_BASE="https://ais-kp-staging-6117w.services.ai.azure.com/openai/v1"      # /responses (discover, web_search)
CONSOLE_CLIENT_ID="97466174-d0ac-460c-94e8-7b6ff3c83da5"
TENANT_ID="808f2f63-5b2c-46e6-ace7-d133a2df35f8"
SUBSCRIPTION_ID="169644fd-c81d-4935-af55-5770f8271022"
OPERATOR_URL="https://ca-kp-staging-operator.calmflower-9463bfc2.eastus2.azurecontainerapps.io"
# Deployed models (out-of-band): gpt-oss-120b, gpt-5.6-terra, gpt-5.6-luna (cap 200)
# Second approver: licensing@erikdierksgmail.onmicrosoft.com (oid ee54cb16-6028-45c7-b37f-059aa2f95e8e)
#   login: AZURE_CONFIG_DIR="$HOME/.azure-licensing" az login --tenant 808f2f63-... --allow-no-subscriptions
```
