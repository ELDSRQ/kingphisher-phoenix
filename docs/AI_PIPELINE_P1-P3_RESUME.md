# AI Pipeline Redesign — Resume Handoff (P1 / P2 / P3)

**Date:** 2026-09-12
**Read first:** `docs/AI_PIPELINE_REDESIGN_SPEC.md` (the full design + per-task breakdown). This doc is the *state + lessons + resume steps* layered on top of it. P0 is landed; P1–P3 remain.

---

## 0. Where things stand

- **P0 landed** → **PR #1** (`feat/p0-ai-reliability-bounded-reasoning`). Bounds reasoning/tokens, temperature-omit control, Azure staging → `gpt-5.6-terra`, bounded on-prem gateway, benchmark harness, and (re-pinned) the azure-deploy.yml workflow digest. `gpt-5.6-terra` = 10/10 valid, p95 5.4s.
- **P1 landed** → **PR #2** (`feat/p1-campaign-extraction`, stacked on #1). Model-based extraction: gateway `/extract` + worker enrichment with `gpt-5.6-luna`, fail-closed to the deterministic pattern. `gpt-5.6-luna` extraction = 8/8 valid, p95 2.5s. See the P1 as-built note in `docs/AI_PIPELINE_REDESIGN_SPEC.md`.
- **P2 landed** → **PR #3** (`feat/p2-html-sanitizer`, stacked on #2). Allow-list HTML sanitizer (`sanitize_safe_html`, BeautifulSoup — not nh3) runs before `SafetyValidator` at generation time; salvages drafts with a stray form/pixel/off-allowlist link, persists the cleaned HTML, records a `raw_proposal["sanitizer"]` provenance. See the P2 as-built note in `docs/AI_PIPELINE_REDESIGN_SPEC.md`.
- **P3 landed** → **PR #4** (`feat/p3-web-discovery`, stacked on #3; operator signed off on live web egress + staging enablement). Gateway `/discover` (Responses API `web_search`, PII-free + citation-allowlist gates), enabled in staging on `gpt-5.6-luna`, validated live. See the P3 as-built note in `docs/AI_PIPELINE_REDESIGN_SPEC.md`.
- **P0–P3 complete.** The one remaining increment is P3's **consumer**: an on-demand operator console route to pull/review `/discover` leads (preferred over a scheduled worker — each call runs many billable web searches). Nothing auto-promotes a lead; human review + existing operator activation stays the gate. Build that next; `/discover` is live and validated.
- **luna learned (for P2/P3 reuse):** like terra it **rejects an explicit temperature**; it **accepts `reasoning_effort=none`** (terra rejects reasoning_effort entirely). `none` is now an allowed gateway reasoning value.

### Post-merge live checks (do these before P1)
```bash
az account show --query user.name -o tsv   # expect erik.dierks@gmail.com
# model deployed (already created out-of-band):
az cognitiveservices account deployment list -g rg-kp-staging -n ais-kp-staging-6117w -o table
# after CI deploy, confirm the live gateway/worker carry the new env + matching model id:
az containerapp show -g rg-kp-staging -n ca-kp-staging-operator --query "properties.template.containers[0].env[?name=='KP_WORKER_AI_MODEL_ID'].value" -o tsv  # (worker app)
```
**Model is now owned by `environments/<env>.tfvars` (fixed in PR #1).** The CI
workflow previously passed `-var="ai_foundry_model=..."` (which overrides
`-var-file`); that line was removed from both plan steps in `azure-deploy.yml`,
so the model comes from tfvars like the other P0 knobs. Result:
- **staging** → `gpt-5.6-terra` (set in `staging.tfvars`, with `ai_reasoning_effort=""`, `ai_send_temperature=false`, 2000-token cap).
- **production** → variable defaults: `gpt-oss-120b` **bounded** (reasoning `low`, temperature on, 2000-token cap, 30s timeout) — coherent and no regression, but NOT terra. To move production to terra, add to `environments/production.tfvars`: `ai_foundry_model = "gpt-5.6-terra"`, `ai_reasoning_effort = ""`, `ai_send_temperature = false`.
- The GitHub Actions var `AI_FOUNDRY_MODEL` is now unused by the model path (safe to leave or delete).

---

## 1. Hard-won facts the next AI must not relearn

- **`gpt-5.6-terra` rejects `reasoning_effort`** (400) — it is a GA generation model, not a reasoning model. Leave reasoning unset for it. `gpt-5.6-luna`/`-sol` may differ — benchmark before assuming.
- **`gpt-5.6-terra` rejects any explicit `temperature`** (400 "only the default (1) is supported"). The gateway omits it via `KP_AI_GATEWAY_SEND_TEMPERATURE=false`. Expect the same for other gpt-5.x models.
- **For reasoning models, `max_completion_tokens` includes reasoning tokens** — too low a cap truncates the visible JSON (seen on gpt-oss-120b at 2000). Budget accordingly.
- **Token-cap wire key differs by backend:** Foundry wants `max_completion_tokens`; local llama.cpp wants `max_tokens`. The gateway picks via `_completion_token_param()` (keyed on `upstream_auth_mode`).
- **AI-010 model-id pin:** `KP_WORKER_AI_MODEL_ID` must equal `KP_AI_GATEWAY_MODEL_ID`. In Terraform both read `local.ai_model_id` (one `var.ai_foundry_model`). Any new stage that pins a model must follow the same pattern or generation fails closed.
- **Foundry account + model deployments are NOT Terraform-managed** — created out-of-band via `az cognitiveservices account deployment create` (both `gpt-oss-120b` and now `gpt-5.6-terra`). Deploy luna the same way for P1. Bringing the account into IaC is a separate improvement.
- **Terraform local apply is blocked** (backend SAS 403); CI applies via OIDC. Locally you can `terraform fmt` / `validate` (after `init -backend=false` — this rewrites `.terraform.lock.hcl`, so `git checkout` it afterward) and run the Python contract tests. **Never commit the lock-file churn.**
- **Gateway is its own uv workspace.** Run its tests from `apps/ai-gateway`: `cd apps/ai-gateway && KP_DISABLE_DOTENV=1 uv run --frozen python -m pytest tests/test_gateway.py -q`. The root `make test-unit` does not cover it.
- **Pattern approval needs a second Entra identity** (creator can't self-approve, any posture). On Azure use `licensing@erikdierksgmail.onmicrosoft.com` via `AZURE_CONFIG_DIR="$HOME/.azure-licensing" az login --tenant 808f2f63-... --allow-no-subscriptions`; verify by token `oid` (`ee54cb16-...`), not `az account show`. You need this to drive generation end-to-end for testing (approve a pattern → enqueues generate).
- **Contract tests pin manifest text.** `infrastructure/terraform/tests/test_ai_foundry_backend_contract.py` asserts on `main.tf`/`variables.tf` strings — update it when you change the wiring, and keep `test_runtime_contract.py`'s audit-hmac boundary intact (never grant operator/workers the `audit-hmac` root).

---

## 2. The benchmark harness (use it as the P1–P3 acceptance gate)

`scripts/operator/ai/benchmark_generation.py` replays the gateway's exact Foundry call for any model+params and reports p50/p95, timeout rate, schema-validity, and a PASS/REVIEW verdict.

```bash
# generation model check (terra):
python3 scripts/operator/ai/benchmark_generation.py \
  --endpoint https://ais-kp-staging-6117w.cognitiveservices.azure.com/openai/v1 \
  --model gpt-5.6-terra --max-completion-tokens 2000 --no-temperature --runs 10 --timeout-budget 30
```
Extend it (don't fork it) for P1 by adding an extraction schema + a `--task extract` mode, so luna extraction is benchmarked the same way before wiring.

---

## 3. P1 — model-based campaign extraction/enrichment (`gpt-5.6-luna`) ✅ DONE (PR #2)

> **Shipped in PR #2** — kept below as the record of intent. What actually landed (and a couple of corrections to the plan) is in the **P1 as-built note** in `docs/AI_PIPELINE_REDESIGN_SPEC.md`: extraction runs in the worker (not activation), `gpt-5.6-luna` takes `reasoning_effort=none` and rejects temperature, and the extract model id is owned by `environments/<env>.tfvars`.

**Goal:** richer, more faithful campaign records → more realistic generation than the deterministic keyword builder alone. Deterministic `build_pattern_candidate` stays the fail-closed fallback.

**Pre-work:** deploy luna (out-of-band, like terra):
```bash
az cognitiveservices account deployment create -g rg-kp-staging -n ais-kp-staging-6117w \
  --deployment-name gpt-5.6-luna --model-name gpt-5.6-luna --model-version 2026-07-09 \
  --model-format OpenAI --sku-name GlobalStandard --sku-capacity 10
```
Then benchmark luna for `reasoning_effort`/`temperature` acceptance (do NOT assume it matches terra — luna is the "discovery/extraction" model and may accept reasoning).

**Tasks** (detailed in spec §3 P1): `CampaignRecord` contract in `packages/contracts` (strict, no PII fields) → gateway `/extract` endpoint (own model id `KP_AI_GATEWAY_EXTRACT_MODEL_ID`, structured output, bounded; disabled when the id is unset so single-model/on-prem is unaffected) → wire enrichment into `build_pattern_candidate`/`threat_routes.activate_threat`, **deterministic fallback on any failure/low-confidence**, carry the record into `_build_generation_request` as bounded, neutralized evidence (reuse `kp_sanitization.neutralize`) → pin/audit the extract model id AI-010-style; persist in `raw_proposal.generation_evidence`.

**Both deployments:** Azure uses luna; on-prem uses the local model for `/extract` OR leaves the extract model id unset to stay deterministic-only (single local model, no second process — see spec §5). The `/extract` endpoint is shared code; profile selects the model.

**Land:** gateway unit tests (from `apps/ai-gateway`), worker tests for enrichment + fallback, contract-test updates, benchmark luna extraction ≥99% valid. Drive a live end-to-end generation via the `licensing` approval flow to confirm a richer template.

---

## 4. P2 — HTML allow-list sanitizer (transform/salvage) ✅ DONE (PR #3)

> **Shipped in PR #3** — kept below as the record of intent. As-built (with deviations: BeautifulSoup not nh3; generation-time only; provenance in `raw_proposal["sanitizer"]`) is in the **P2 as-built note** in `docs/AI_PIPELINE_REDESIGN_SPEC.md`.

**Goal:** stop discarding otherwise-good generations on a single stray element; explicitly strip forms + tracking pixels; rewrite/neutralize off-allowlist links. Currently the `SafetyValidator` only **rejects** (see `packages/safety-validation`), so one bad element wastes a whole generation.

**Tasks** (spec §3 P2): add an allow-list sanitizer in `packages/sanitization` using **`nh3`/ammonia** (Rust, no network — important for the offline on-prem guarantee), run it **before** `SafetyValidator` in the generation save path and in delivery render; keep reject-on-fail as the backstop. Persist the sanitizer verdict (what it removed/transformed) as structured provenance on `TemplateVersion`.

**Security:** additive, never a replacement for the existing deny-list validator. Add adversarial tests (mutation XSS, broken/nested markup, homoglyph/zero-width, `data:`/`javascript:` in attributes). Preserve the `TRAINING_URL_PLACEHOLDER` through sanitization (delivery-time per-recipient binding must still work — see `jobs.py` `_send_email`).

**Both deployments:** pure app code, no network → applies identically to Azure and on-prem; strengthens on-prem most (weaker local models).

---

## 5. P3 — Web Search research (optional, Azure-only, flag-gated) ✅ DONE (PR #4)

> **Shipped in PR #4** — kept below as the record of intent. As-built (Responses API `web_search`, no separate Bing resource needed, PII + citation gates, enabled in staging on luna, consumer route as follow-on) is in the **P3 as-built note** in `docs/AI_PIPELINE_REDESIGN_SPEC.md`.

**Goal:** freshness/breadth beyond the registered feeds. **Do not start without explicit operator sign-off** (cost + data-egress/compliance).

**Tasks** (spec §3 P3): a research path using luna + **Foundry Web Search** (Agents/Responses API — the ONLY place that API is introduced; the rest stays chat/completions). Domain-restrict to vetted threat-intel sources (spec §1 list). Require citations/dates; no-source → no campaign.

**Compliance (spec §10) — enforce in code, not convention:** web-search queries may contain ONLY public threat terms, never recipient names/emails, internal results, or any PII. Gate behind `..._WEB_SEARCH_ENABLED` (default false; **forced false** in the on-prem profile — a disconnected box has no egress and must stay offline).

**Both deployments:** Azure-only. On-prem keeps curated-feed ingestion (already live) as its "current in the wild" source — the retrieval-grounded principle holds; the source differs.

---

## 6. Definition of done (per phase)

Each phase: gates green (`make lint`, `make typecheck`, `make test-unit`, gateway tests from its workspace, `terraform fmt`/`validate` + contract tests), benchmark ≥99% valid where a model is involved, both deployment profiles covered, one PR off `main`, CI green before merge (do not bypass branch protection), commit trailer as in P0. Then drive a live end-to-end generation (approve a pattern as `licensing`) to confirm the real pipeline, and update `docs/AI_PIPELINE_REDESIGN_SPEC.md` acceptance checkboxes.
