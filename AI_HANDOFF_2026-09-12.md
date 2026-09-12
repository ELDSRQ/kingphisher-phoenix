# AI Handoff — 2026-09-12 (AI generation pipeline redesign, P0–P3)

**Supersedes** `AI_HANDOFF_2026-09-11.md`. Full design + per-phase as-built notes:
`docs/AI_PIPELINE_REDESIGN_SPEC.md`. Resume/lessons: `docs/AI_PIPELINE_P1-P3_RESUME.md`.

This handoff exists because a prior session got stuck in an infinite, no-timeout
poll of a campaign-pattern approval state. Diagnosing that uncovered the real
blocker (generation dead-lettering) and led to a four-phase AI-pipeline redesign
shipped as **four stacked, not-yet-merged PRs**. Read this fully before acting.

---

## 1. Why the previous session was stuck, and what was actually wrong

It polled pattern `7e0d6ece-8c94-5a6a-8775-971094a99729` for `approval_state=="approved"`
with a no-timeout `curl`. Two problems:

1. **Hung and futile.** The loop had no `--max-time` and the az token had expired,
   so it blocked forever. It was also futile: that pattern was **authored by
   Erik's identity**, and the platform **bars a pattern's creator from approving
   it** (`apps/operator-api/src/kp_operator_api/routes/patterns.py:131`) —
   **unconditional, not relaxed by `single-operator`**. A *distinct* Entra identity
   must approve.
   - Resolved using `licensing@erikdierksgmail.onmicrosoft.com`
     (oid `ee54cb16-6028-45c7-b37f-059aa2f95e8e`):
     `AZURE_CONFIG_DIR="$HOME/.azure-licensing" az login --tenant 808f2f63-5b2c-46e6-ace7-d133a2df35f8 --allow-no-subscriptions`
     (pick "Use another account"), then verify by the **token's `oid` claim**, not
     `az account show`. The pattern is now **approved** — do NOT re-approve (409).

2. **The real blocker:** template generation dead-lettered because of **UNBOUNDED
   reasoning effort** on `gpt-oss-120b` (a flaky *Preview* model, ~20% schema-invalid)
   running past the worker's 10s provider timeout. This is **NOT** the old
   "audit-hmac / recipient-import 500" theory and **NOT** a "reasoning-channel leak."
   Both earlier diagnoses were wrong; do not act on them.

---

## 2. What changed — P0–P3 (four stacked PRs, NOT yet merged)

| PR | Branch | Base | Phase | Outcome |
|----|--------|------|-------|---------|
| #1 | `feat/p0-ai-reliability-bounded-reasoning` | `main` | P0 reliability | Gateway sends optional `reasoning_effort` + `max_completion_tokens` + a `send_temperature` omit-control; staging generation → `gpt-5.6-terra`; durable worker timeout 30s; benchmark harness; **removed the CI `-var ai_foundry_model` override** so the model is owned by `environments/<env>.tfvars`; **re-pinned `EXPECTED_WORKFLOW_SHA256`**. |
| #2 | `feat/p1-campaign-extraction` | #1 | P1 effectiveness | Gateway `POST /extract` (`gpt-5.6-luna`) → strict `CampaignRecord`, folded into generation. **Fail-closed**: any error/disable/mismatch → deterministic pattern, unchanged. |
| #3 | `feat/p2-html-sanitizer` | #2 | P2 robustness | Allow-list HTML sanitizer (`packages/sanitization/.../safe_html.py`, BeautifulSoup — **not** nh3) runs **before** `SafetyValidator` at generation time; salvages drafts with a stray form/pixel/off-allowlist link; persists cleaned HTML + `raw_proposal["sanitizer"]`. Validator stays the authority. |
| #4 | `feat/p3-web-discovery` | #3 | P3 freshness | Gateway `POST /discover` (Responses API `web_search`, `gpt-5.6-luna`) → cited `CampaignLead`s. Two in-code gates: PII-free query + citation allow-list. **Enabled in staging**; OFF (503) anywhere without web egress (all on-prem). |

### Merge order (bottom-up; wait for green CI on each)

    gh pr merge 1 --merge      # after CI green; GitHub auto-retargets #2 → main
    gh pr merge 2 --merge      # repeat for #3, #4 once each retargets to main
    gh pr merge 3 --merge
    gh pr merge 4 --merge

Each lower PR must merge first so the next retargets to `main`. **Do not bypass
branch protection** (a prior session's bypass once landed a broken workflow on main).

---

## 3. Hard-won facts — do not relearn these

- `gpt-5.6-terra` **rejects an explicit temperature** (400) **and** `reasoning_effort` (400).
  It runs with temperature omitted (`send_temperature=false`) and no reasoning effort.
- `gpt-5.6-luna` **rejects an explicit temperature**; **accepts `reasoning_effort` incl. `none`**
  (extraction uses `none`). `none` is an allowed gateway reasoning value.
- For reasoning models, `max_completion_tokens` **includes reasoning tokens** — too low a cap truncates JSON.
- **Foundry account + model deployments are NOT Terraform-managed.** Deployed out-of-band
  (`az cognitiveservices account deployment create`) in `ais-kp-staging-6117w`:
  `gpt-oss-120b` (kept for rollback/A-B), `gpt-5.6-terra`, `gpt-5.6-luna` (capacity 200 for web_search headroom).
  `Microsoft.Bing` provider is **Registered** — that alone enabled the Responses-API `web_search`
  tool; **no separate Bing-grounding resource/connection was needed**.
- **Model now comes from `environments/<env>.tfvars`** (CI no longer passes `-var`). `staging.tfvars`
  = terra (generation) + luna (extract + discover). `production.tfvars` sets none → defaults to
  `gpt-oss-120b` **bounded** (reasoning low, temp on, 2000-cap, 30s) — coherent, no regression; opt
  production into terra/luna by adding the vars.
- Any edit to `.github/workflows/azure-deploy.yml` **requires re-pinning** `EXPECTED_WORKFLOW_SHA256`
  in `apps/operator-api/src/kp_operator_api/deployment_common.py` (the reviewed-workflow gate;
  `test_deployment_orchestration` enforces it).
- The **ai-gateway is its own uv workspace** — run its tests from `apps/ai-gateway`:
  `cd apps/ai-gateway && KP_DISABLE_DOTENV=1 uv run --frozen python -m pytest tests/test_gateway.py -q`
- **Terraform local apply is blocked** (backend SAS 403); CI applies via OIDC. Locally: `fmt`,
  then `init -backend=false` + `validate`, plus the python contract tests; `git checkout` the
  `.terraform.lock.hcl` afterward — never commit lock churn.
- **Pattern self-approval is barred unconditionally** — a single operator cannot approve their own
  pattern. Use a distinct second identity (`licensing@`, §1). This still blocks a single-operator
  Azure live campaign at the pattern-approval step.

---

## 4. What is LIVE vs PENDING

- **Nothing is deployed yet.** The gateway/worker images and the Terraform config changes take
  effect only when **CI builds + deploys on merge** (Docker builds are `.105`-only; CI is the
  deploy path). Until then staging still runs `gpt-oss-120b`.
- A live `az containerapp update` hotfix set `KP_WORKER_PROVIDER_TIMEOUT_SECONDS=45` on the worker;
  it is superseded by the pinned 30s on the next deploy.

Post-merge, verify the deploy took:

    az containerapp show -g rg-kp-staging -n ca-kp-staging-worker \
      --query "properties.template.containers[0].env[?name=='KP_WORKER_AI_MODEL_ID'].value" -o tsv   # expect gpt-5.6-terra

---

## 5. Immediate next work (priority order)

1. Get PRs **#1 → #4** reviewed + merged bottom-up; confirm CI deploys the new images and applies the tfvars.
2. Build **P3's consumer** (the only remaining increment): an **on-demand operator console route** to
   pull/review `/discover` leads — preferred over a scheduled worker (each `/discover` runs many
   billable web searches; on-demand keeps a human controlling cost + egress). **Nothing auto-promotes
   a lead**; human review + existing operator activation stays the gate to a pattern.
3. Decide the **production generation model** (`production.tfvars`).
4. For a **live Azure campaign end-to-end**: add a 3rd Entra approver identity or keep single-operator
   posture — and remember patterns always need a distinct second approver (§1, §3).

---

## 6. Security boundaries (unchanged — never cross)

- Never grant operator API or workers the `audit-hmac` signing root.
- Never change the shared Entra audience default (`kp-operator-api` is correct for on-prem Keycloak).
- Docker only on `.105`.
- On-prem must stay fully offline — **P3 `/discover` is OFF on-prem** (no web egress); keep it that way.
- Never `git add -A`; never commit secrets or the `.terraform.lock.hcl` churn.

---

## 7. Verify state first

    git log --oneline -8 ; git branch -a | grep feat/p
    gh pr list
    KP_DISABLE_DOTENV=1 uv run --frozen python -m pytest \
      packages/contracts/tests/test_discovery.py \
      infrastructure/terraform/tests/test_ai_foundry_backend_contract.py -q

Then read `docs/AI_PIPELINE_REDESIGN_SPEC.md` and `docs/AI_PIPELINE_P1-P3_RESUME.md` in full
before changing anything.

---

## 8. Reference values (Azure staging)

    RG="rg-kp-staging"
    FOUNDRY="ais-kp-staging-6117w"
    FOUNDRY_CHAT_BASE="https://ais-kp-staging-6117w.cognitiveservices.azure.com/openai/v1"   # /chat/completions (propose, extract)
    FOUNDRY_RESPONSES_BASE="https://ais-kp-staging-6117w.services.ai.azure.com/openai/v1"      # /responses (discover, web_search)
    CONSOLE_CLIENT_ID="97466174-d0ac-460c-94e8-7b6ff3c83da5"
    TENANT_ID="808f2f63-5b2c-46e6-ace7-d133a2df35f8"
    SUBSCRIPTION_ID="169644fd-c81d-4935-af55-5770f8271022"
    # Deployed models (out-of-band): gpt-oss-120b, gpt-5.6-terra, gpt-5.6-luna (cap 200)
    # Second approver identity: licensing@erikdierksgmail.onmicrosoft.com (oid ee54cb16-6028-45c7-b37f-059aa2f95e8e)
