# AI Generation Pipeline — Redesign Build Spec

**Date:** 2026-09-12
**Inputs:** `~/Downloads/Phishing_AI_Model_Design_Recommendation.md` (external recommendation), live Azure staging (`rg-kp-staging`, Foundry `ais-kp-staging-6117w`), and a full architecture map of the current build (see §2).
**Scope:** `phishing-awareness-platform` only. Both deployment paths (Azure-integrated AND on-prem/disconnected) stay first-class (standing requirement).

---

## 0. Verdict — is the recommendation superior?

**Partially, and its best idea is not the one it leads with.** The recommendation is architecturally sound, its model names are real and deployable (`gpt-5.6-luna`, `gpt-5.6-terra`, `gpt-5.6-sol`, all v`2026-07-09`, GlobalStandard, in `ais-kp-staging-6117w`). But roughly 60% of what it recommends **already exists** in this platform (deterministic safety, grounding-on-evidence, dual-approval, audit provenance, live threat feeds, the training-URL placeholder + delivery-time binding, the end-to-end model-id pin). Do **not** rebuild those.

The decisive finding, proven against the live Foundry endpoint, is narrower and cheaper than the recommendation's headline "swap to new models":

> Adding **`reasoning_effort: "low"`** and **`max_completion_tokens: 2000`** to the gateway's chat/completions payload took the *existing* `gpt-oss-120b` from ~7.2s (trivial) / >45s (real, timing out) to **1.69s**, output still valid strict-schema JSON. The timeout problem was unbounded reasoning effort — a payload the gateway never set — not model capability.

So reliability is a **two-parameter gateway fix**, available today, independent of any model change. The model change (to a current, non-preview model) and the richer-extraction work are **effectiveness** plays layered on top.

What to adopt, ranked by value/risk:

| # | Change | Type | Value | Risk | Phase |
|---|---|---|---|---|---|
| 1 | Gateway sends `reasoning_effort` + `max_completion_tokens` | Reliability | **Decisive** | Low | P0 |
| 2 | Durably pin worker `provider_timeout_seconds` (supersede the live hotfix) | Reliability | High | Low | P0 |
| 3 | Move generation off the `gpt-oss-120b` *preview* model onto a current model (`gpt-5.6-terra`), keep oss for A/B | Effectiveness + currency | High | Low–Med | P0 |
| 4 | Model-based campaign **extraction/enrichment** (`gpt-5.6-luna`) feeding richer evidence into generation | Effectiveness | High | Med | P1 |
| 5 | HTML **allow-list sanitizer** (transform/salvage) + explicit form/tracking-pixel stripping; persist sanitizer verdict in audit | Robustness + effectiveness (fewer wasted generations) | Med | Med (security-sensitive) | P2 |
| 6 | Web Search research component for freshness/breadth beyond registered feeds | Effectiveness | Med | High (cost + PII/compliance) | P3, Azure-only, flagged |

What to **push back on** from the recommendation:
- **Full Responses-API migration is unnecessary** for items 1–5. The platform's gateway + worker contract is chat/completions + strict `json_schema` and it works. Confine Responses/Agents API to the Web Search component (P3) only.
- **Open Web Search is lower-signal and higher-risk than the curated vendor feeds already ingested.** Your existing live feeds (RSS/STIX/bulk from allowlisted vendor/CERT domains, daily, governance-gated) are arguably *better* grounding than open web for a safety-critical simulator. Treat Web Search as additive and optional, not as a replacement for feeds.

---

## 1. Target architecture — one contract, two profiles

Keep a **single pipeline contract** and select behavior by **deployment profile**, so Azure and on-prem never fork:

```
                 ┌─────────────────────────────────────────────────────────┐
                 │  EVIDENCE SOURCING (current "in the wild")                │
   Azure profile │   • live allowlisted feeds (RSS/STIX/bulk)  [EXISTS]      │
                 │   • [P3, optional] Web Search research (luna+web_search)  │
  on-prem profile│   • live/curated feeds only (no web search)               │
                 └───────────────────────────────┬─────────────────────────┘
                                                  ▼
                 ┌─────────────────────────────────────────────────────────┐
                 │  EXTRACTION / NORMALIZATION → CampaignRecord              │
                 │   • deterministic keyword builder           [EXISTS]      │
                 │   • [P1] model enrichment (luna, reasoning=none)          │
                 │     deterministic output is the fail-closed fallback      │
                 └───────────────────────────────┬─────────────────────────┘
                                                  ▼ (human activates pattern; approves)
                 ┌─────────────────────────────────────────────────────────┐
                 │  GENERATION (single model call)             [EXISTS]      │
                 │   • gateway /propose, strict json_schema    [EXISTS]      │
                 │   • [P0] + reasoning_effort + max_completion_tokens       │
                 │   • [P0] model = gpt-5.6-terra (Azure) / local (on-prem)  │
                 └───────────────────────────────┬─────────────────────────┘
                                                  ▼
                 ┌─────────────────────────────────────────────────────────┐
                 │  DETERMINISTIC SAFETY (app code, no AI)     [EXISTS]      │
                 │   • SafetyValidator reject-on-fail          [EXISTS]      │
                 │   • [P2] allow-list HTML sanitizer (transform/salvage):   │
                 │     strip forms+pixels, neutralize off-allowlist links    │
                 │   • placeholder → per-recipient tracking URL at delivery  [EXISTS]
                 └───────────────────────────────┬─────────────────────────┘
                                                  ▼
                     HUMAN APPROVAL [EXISTS] → SEND → track → train  [EXISTS]
```

**Profiles** (new `KP_PROFILE`-style presets already exist per `beebba5`; extend them):
- `azure-staging` / `azure`: generation=`gpt-5.6-terra`, extraction=`gpt-5.6-luna`, web_search=flag (default off until P3 accepted).
- `onprem` / `standalone`: generation=local model, extraction=local model (or deterministic-only), web_search=**forced off**.

---

## 2. Current build — what already exists (DO NOT REBUILD)

Condensed from the architecture map (file:line references verified):

- **Live threat sourcing:** `process_ingestion` (`apps/workers/src/kp_workers/jobs.py:293`) fetches allowlisted RSS/STIX/bulk feeds daily via `SecureFetcher` (allowlist-HTTPS, anti-rebinding, size/redirect limits — `packages/sanitization/.../fetcher.py`). New `SourceItem`s are force-quarantined pending operator review (`jobs.py:422-428`). Governance/license/quarantine gating throughout.
- **Deterministic extraction:** `build_pattern_candidate` (`packages/campaign-patterns/.../builder.py:242`) — pure keyword/heuristic classification (lure, sector, ATT&CK, 1–5 difficulty, freshness), provenance embedded in `attack_mapping`. **No model.**
- **Pattern creation:** only via audited operator activation (`apps/operator-api/.../threat_routes.py:478 activate_threat`, cap `MANAGE_SOURCES`), governance locked.
- **Generation:** single model call `process_generation` (`jobs.py:456`) → `_build_generation_request` (neutralizes every free-text field, bounds sizes, pins `training_url=TRAINING_URL_PLACEHOLDER`) → `_call_ai` (`jobs.py:2573`) POST `/propose`, strict-schema validate via `GenerationResponse` (`extra="forbid"`), **AI-010 model-id pin** (`jobs.py:2611-2621`), persist `TemplateVersion` DRAFT with full provenance, re-run SafetyValidator. *(P1 added an optional pre-generation `/extract` enrichment step in the worker — see the P1 as-built note; this baseline is the pre-redesign state.)*
- **Gateway:** `apps/ai-gateway/.../main.py` — chat/completions, strict `json_schema`, `temperature`. **Sets no `max_tokens`/`max_completion_tokens`/`reasoning_effort`; no tools/web search; single model.** Backend by config: local `llama.cpp` (`none` auth) or Foundry (`entra` managed identity).
- **Deterministic safety (`packages/safety-validation/.../validator.py`):** reject-on-fail; blocks script/iframe/object/embed, `on*` handlers, dangerous URI schemes; URL allow-list (training domains); attachment/exe/macro restriction; anti-evasion (NFKC, homoglyph fold, zero-width strip); credential/financial/QR/macro content blocks. **Reject-only — no allow-list HTML rewriter (no bleach/nh3).** `<form>` and tracking pixels not explicitly stripped (only rejected if their URL is off-allowlist).
- **Placeholder/delivery:** `TRAINING_URL_PLACEHOLDER` required in both bodies at generation; per-recipient `click_url` bound at **delivery** (`jobs.py:2733,2748-2758`); re-validated before send.
- **Audit:** hash-chained (`packages/auditing`), records `ingest.*`, `pattern.approve`, `template.generate`, `template.approve/reject`; provenance on `TemplateVersion` (`model_id`, `input_hash`, `generation_evidence`, `requested_by`, `neutralization_reasons`). Dual approval (requester ≠ approver; pattern self-approval barred).
- **Model pin end-to-end (AI-010):** `KP_WORKER_AI_MODEL_ID` must equal `KP_AI_GATEWAY_MODEL_ID`; gateway returns its configured id, worker constant-time compares, fails closed on mismatch.

---

## 3. Phased build plan

Conventions for **every** task (the "land" checklist):
- Branch off `main` (never work on `main`; never `git add -A` — it records worktree gitlinks). One task = one focused commit (or a small series).
- Gates before commit: `make lint && make typecheck && make test-unit`; for Terraform: `terraform -chdir=infrastructure/terraform fmt -check && terraform ... validate` + `uv run python -m pytest infrastructure/terraform/tests/ -q`.
- Security boundaries (unchanged, never cross): never grant operator/worker the `audit-hmac` signing root; never change the shared Entra audience default; Docker only on `.105`; preserve `.env`, `data/`, DB volumes, audit state.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` + the session line.
- CI must be green on the PR *before* merge (the handoff notes prior pushes bypassed branch protection — do not).

### Phase 0 — Reliability (do first; fixes the live dead-lettering)

> **✅ P0 AS-BUILT (2026-09-12, PR #1) — corrections to the tasks below, learned by benchmarking live Foundry:**
> - **`gpt-oss-120b` bounds fix *latency* but not *correctness*:** even bounded it is ~20% schema-**invalid** (flaky Preview model). So the model swap is required, not optional — the T0.1 "1.69s valid JSON" grounding proof was a single lucky call.
> - **`gpt-5.6-terra` config is different from what T0.3 assumed:** terra **rejects `reasoning_effort`** (400) and **rejects any explicit `temperature`** (400). So staging runs terra with `ai_reasoning_effort=""`, `ai_send_temperature=false`, `ai_max_completion_tokens=2000` — **not** `reasoning_effort=low`. A third gateway control, **`KP_AI_GATEWAY_SEND_TEMPERATURE`**, was added to T0.1 to omit temperature. (`reasoning_effort=low` is correct only for gpt-oss-120b, which production still uses via defaults.)
> - **Benchmarked:** terra (no-temp, 2000-cap) 10/10 valid, p50 4.5s / p95 5.4s, zero timeouts; durable worker timeout pinned at **30s**.
> - **Model ownership moved to `environments/<env>.tfvars`:** `azure-deploy.yml` passed `-var="ai_foundry_model=..."` which overrides `-var-file`; that line was removed from both plan steps so tfvars owns the model (the `AI_FOUNDRY_MODEL` GitHub var is now unused). The reasoning/token/temperature/timeout vars were never `-var`-passed, so tfvars owns them too.
> - **Foundry model deployments are out-of-band** (`az cognitiveservices account deployment create`), not Terraform-managed — `gpt-5.6-terra` is already deployed alongside `gpt-oss-120b`. (T0.2's "Terraform" framing is aspirational; the account isn't in IaC.)

**T0.1 — Gateway: add bounded reasoning + output tokens.**
- Files: `apps/ai-gateway/src/kp_ai_gateway/config.py`, `apps/ai-gateway/src/kp_ai_gateway/main.py`, `apps/ai-gateway/tests/test_gateway.py`.
- Add `GatewaySettings` fields: `max_completion_tokens: int | None = None` (env `KP_AI_GATEWAY_MAX_COMPLETION_TOKENS`), `reasoning_effort: str | None = None` (env `KP_AI_GATEWAY_REASONING_EFFORT`, validated to one of `minimal|low|medium|high` when set). Keep both optional so the local `llama.cpp` path (which may not accept them) is unchanged when unset.
- In `propose` payload (`main.py:281-289`), conditionally include `max_completion_tokens` and `reasoning_effort` only when configured. Note: reasoning models use `max_completion_tokens`, **not** `max_tokens` — use the former.
- Tests: payload includes params when set, omits when unset; 200-path unchanged; existing strict-schema test still passes.
- Commit: `feat(ai-gateway): bound reasoning effort and completion tokens on /propose`.
- **Grounding proof:** `reasoning_effort:low` + `max_completion_tokens:2000` on `gpt-oss-120b` → 1.69s, valid JSON (measured 2026-09-12).

**T0.2 — Deploy the current generation model in Foundry (Terraform).**
- Files: `infrastructure/terraform/*.tf` (Foundry/cognitive-services deployments), `environments/staging.tfvars`.
- Add a `gpt-5.6-terra` (v`2026-07-09`, GlobalStandard) model deployment on `ais-kp-staging-6117w`. Keep `gpt-oss-120b` deployed (A/B + rollback).
- Tests: terraform fmt/validate + contract tests green.
- Commit: `feat(terraform): deploy gpt-5.6-terra for simulation generation`.

**T0.3 — Point the pipeline at the current model + set the bounds (Terraform, both sides of the pin).**
- Files: `infrastructure/terraform/*.tf` (worker + gateway container env), `environments/staging.tfvars`.
- Set `KP_AI_GATEWAY_MODEL_ID = gpt-5.6-terra` **and** `KP_WORKER_AI_MODEL_ID = gpt-5.6-terra` together (AI-010 pin — they must match; both read `local.ai_model_id`). For terra set `KP_AI_GATEWAY_REASONING_EFFORT=""` (terra 400s on it) and `KP_AI_GATEWAY_SEND_TEMPERATURE=false` (terra 400s on an explicit temperature), plus `KP_AI_GATEWAY_MAX_COMPLETION_TOKENS=2000`. (`reasoning_effort=low` applies only to a reasoning model like gpt-oss-120b — see the as-built note above.)
- **Durably pin** `KP_WORKER_PROVIDER_TIMEOUT_SECONDS` (supersedes the live `az containerapp update` hotfix, which reverts on deploy). With bounded reasoning, ~20s is ample; keep headroom under the 60s code cap.
- Tests: terraform gates; post-apply assert both ids equal and reasoning/token envs present.
- Commit: `feat(terraform): pin generation to gpt-5.6-terra with bounded reasoning and timeout`.

**T0.4 — Benchmark harness + acceptance gate (terra vs gpt-oss-120b).**
- Files: new `scripts/operator/ai/benchmark_generation.py` (or under `tests/e2e/`).
- Measure over a fixed prompt set: p50/p95 latency, timeout rate, schema-compliance rate, pin-match, SafetyValidator pass rate. Compare terra vs oss.
- Land criterion: terra meets §4 Reliability before removing oss from the path.
- Commit: `test(ai): generation latency/compliance benchmark harness`.

### Phase 1 — Effectiveness: model-based extraction/enrichment

> **✅ P1 AS-BUILT (2026-09-12, PR #2, stacked on #1):**
> - **Integration point:** the extraction runs in the **generation worker** before `/propose` (async, retryable), not in the synchronous operator activation path — so a slow/flaky model never slows operator APIs. The deterministic `build_pattern_candidate` is untouched and remains the fail-closed baseline.
> - **Fail-closed, always:** extraction is pure enrichment. Unconfigured / error / timeout / off-contract / extract-pin mismatch ⇒ `None` ⇒ generation proceeds on the deterministic pattern exactly as before P1 (`_maybe_extract_campaign_record`, `jobs.py`).
> - **Contract:** `CampaignRecord` (strict, bounded, no-PII, all-required), `CampaignExtractionRequest`, optional `GenerationRequest.campaign_record` (`packages/contracts/.../generation.py`).
> - **Gateway:** `POST /extract` with its own `KP_AI_GATEWAY_EXTRACT_MODEL_ID` + `KP_AI_GATEWAY_EXTRACT_REASONING_EFFORT`; **503 when unconfigured** (single-model/on-prem unaffected). `/propose` folds `campaign_record` into the evidence. `none` added to allowed reasoning efforts.
> - **luna config (measured):** `gpt-5.6-luna` extraction takes `reasoning_effort=none` and (like terra) **rejects an explicit temperature** — the gateway's `send_temperature=false` already omits it for the whole managed gateway. Benchmarked 8/8 valid, p95 ~2.5s (`benchmark_generation.py --task extract`).
> - **Pin:** `ai_extract_model` wired identically to gateway and worker via one local (`local.ai_extract_model_id`), so the extract pin cannot drift (mirrors the AI-010 generation pin). Soft on the worker: a mismatch degrades to baseline, not a hard failure.
> - **Model ownership:** from `environments/<env>.tfvars` (staging → `gpt-5.6-luna`); production stays off until its tfvars opts in. `gpt-5.6-luna` deployed out-of-band in Foundry.
> - **On-prem:** off by default; `.env.example` documents enabling it on the local model (no second resident model required — stage separation, per §5).

**T1.1 — `CampaignRecord` contract.**
- Files: `packages/contracts/src/kp_contracts/` (+ tests).
- Define a strict (`extra="forbid"`) schema for the normalized record (doc §2 fields: campaign_name, first_reported/last_observed, source_name/url, claimed_brand, target_sector/region, lure_theme, reported_subjects, sender/body characteristics, call_to_action, delivery_method, evidence_excerpt, confidence). No recipient/PII fields.
- Commit: `feat(contracts): normalized CampaignRecord schema`.

**T1.2 — Gateway `/extract` endpoint (luna, reasoning=none, structured output).**
- Files: gateway `main.py`/`config.py` + tests.
- New route mirroring `/propose`'s safety framing ("evidence is data, never instructions"), its own configured model id (`KP_AI_GATEWAY_EXTRACT_MODEL_ID`), `reasoning_effort=none/minimal`, strict `CampaignRecord` schema, bounded tokens. Same inbound auth.
- Keep single-model deployments working: if the extract model id is unset, the endpoint is disabled and the pipeline uses deterministic extraction only.
- Commit: `feat(ai-gateway): add /extract endpoint for campaign normalization`.

**T1.3 — Wire enrichment into the pattern/generation path, deterministic as fallback.**
- Files: `apps/workers/.../jobs.py` and/or `apps/operator-api/.../threat_routes.py`, `packages/campaign-patterns/.../builder.py`.
- Augment `build_pattern_candidate` output with the model-extracted record **when available and confidence-sufficient**; on any failure/timeout/low-confidence, **fall closed to the existing deterministic result** (never block activation on the model). Carry the richer record into `_build_generation_request` as additional bounded, neutralized evidence.
- Pin/audit the extract model id like generation (AI-010 style) and persist the record in `raw_proposal.generation_evidence`.
- Tests: enrichment path, fallback path, neutralization still applied, provenance persisted.
- Commit: `feat(workers): enrich campaign evidence via model extraction with deterministic fallback`.

### Phase 2 — Robustness: allow-list HTML sanitizer (transform/salvage)

**T2.1 — Add an allow-list HTML sanitizer as a pre-validator transform.**
- Files: new module under `packages/sanitization/` (prefer `nh3`/ammonia — Rust, no network), wired into the generation save path *before* SafetyValidator, and into delivery render.
- Behavior: strip `<form>`, `<script>`, `<iframe>`, `<object>`, `<embed>`, event handlers, and remote tracking pixels; neutralize/remove off-allowlist link destinations; keep the training placeholder intact; enforce an element/attribute allow-list; then run SafetyValidator on the cleaned output. This **salvages** otherwise-good generations instead of discarding them (fewer wasted model calls) while keeping reject-on-fail as the backstop.
- Security: additive to, never a replacement for, the existing reject-on-fail validator. Add adversarial tests (mutation XSS, nested/broken markup, homoglyph/zero-width, data:/javascript: in attributes).
- Commit: `feat(sanitization): allow-list HTML sanitizer with form/pixel stripping`.

**T2.2 — Persist sanitizer verdict as a structured audit field.**
- Files: `packages/database/` (TemplateVersion), worker persist path.
- Store what the sanitizer removed/transformed (counts + reasons) as structured provenance, not just a pass/fail gate.
- Commit: `feat(db): record sanitizer transformations on template provenance`.

### Phase 3 — Effectiveness (optional, Azure-only, flag-gated): Web Search research

**T3.1 — Research component (luna + Foundry Web Search).**
- Files: a new research path (Agents/Responses API — the **only** place that API is introduced), behind `KP_..._WEB_SEARCH_ENABLED` (default **false**; **forced false** in the on-prem profile).
- Domain-restrict to vetted threat-intel sources (doc §1 list). Output must carry citations/dates; no-source → no campaign.
- **Compliance guardrail (doc §10):** queries may contain ONLY public threat terms — never recipient names/emails, internal results, or any PII. Enforce in code (allowlist of query inputs), not by convention.
- Commit: `feat(research): flag-gated web-search threat discovery (Azure-only)`.
- **Gate:** requires explicit operator sign-off (cost + data-egress/compliance review) before enabling in any environment.

---

## 4. Acceptance criteria (adapted from doc §9)

- **Reliability:** ≥99% of generations complete without manual retry on the test set; p95 latency comfortably under the worker timeout; timeouts fail cleanly (no partial template persisted). (P0 target.)
- **Grounding:** every generated simulation traces to ≥1 active, governance-current source; extraction rejects insufficiently-sourced campaigns; dates captured. (Largely EXISTS; P1 strengthens.)
- **Generation:** output conforms to the strict schema; reflects the retrieved campaign; no invented campaign facts beyond evidence.
- **Safety:** no original/off-allowlist URL, active HTML, or executable attachment survives to the final email; every clickable link is app-generated; every message requires operator approval. (EXISTS; P2 hardens via transform.)
- **Auditability:** reconstructable chain — what campaign, where found, what evidence, what AI produced, what safety transforms ran, who approved, when sent. (Mostly EXISTS; P2.2 adds sanitizer verdict.)

---

## 5. On-prem / disconnected applicability

**Adopt P0, P1, P2; exclude P3.** The pipeline contract is identical; only the profile differs.

- **P0 (reliability) applies directly.** The gateway already abstracts the backend; add the same `reasoning_effort`/`max_completion_tokens` knobs. A local `llama.cpp` server may ignore or reject them, so they stay optional/unset in the on-prem profile unless the local server supports them (llama.cpp supports `n_predict`/token caps; map accordingly). Bounded output helps local latency too.
- **P1 (model extraction) applies with one model, not many.** On one on-prem host (single `llama.cpp`, Qwen2.5-7B today), **do not run N dedicated model processes** — VRAM, cold-starts, and ops burden on a 2-person-IT box outweigh the benefit. Get the reliability/quality win from **stage separation (distinct prompts/contracts against one capable local model)**, optionally a *second* small model only if the host has headroom. The deterministic extractor remains the fail-closed fallback, which matters more offline.
- **P2 (sanitizer) applies directly** — `nh3`/ammonia is local, no network; strengthens on-prem where models are weaker.
- **P3 (Web Search) does NOT apply** — disconnected deployments have no Bing/web egress, and it would violate the offline guarantee. On-prem "current in the wild" = operator-curated live/periodic feeds ingested into the existing Source store. The "retrieval-grounded, no-source→no-campaign" *principle* holds; the *source* is feeds, not search.

**Answer to "would on-prem benefit from multiple smaller dedicated AIs?":** It benefits from the *staged-pipeline* redesign (separation, bounding, deterministic safety, retrieval-grounding) — yes. It does **not** clearly benefit from multiple *resident* models on one constrained box; prefer stage separation on one (at most two) local model(s). Keep model/tool selection a per-profile config, not a code fork.

---

## 6. Risks, cost, rollback

- **Cost:** deploying `gpt-5.6-terra` (and `-luna` for P1) adds pay-per-token GlobalStandard usage; Web Search (P3) adds Bing grounding cost + data egress. Keep `gpt-oss-120b` deployed through P0 for rollback/A-B.
- **Rollback:** every model/param change is env-var + Terraform; revert the id pins (both sides together) and reasoning/token envs to return to `gpt-oss-120b`. No schema/data migration in P0.
- **Pin hazard:** `KP_WORKER_AI_MODEL_ID` and `KP_AI_GATEWAY_MODEL_ID` must change **together** or generation fails closed on the AI-010 mismatch — change them in one Terraform apply.
- **Web Search compliance (P3):** data can leave the Azure boundary; enforce the PII-free-query guardrail in code and require operator sign-off before enabling.
- **Do not** adopt the recommendation's full Responses-API migration or open web search for P0–P2; they are unnecessary for the reliability/effectiveness wins and add risk.

---

## 7. Suggested landing order

P0.T0.1 → P0.T0.2 → P0.T0.3 → P0.T0.4 (reliability fully landed + benchmarked; live campaign unblocked reliably) → P1 (richer, more realistic generation) → P2 (safety-transform hardening) → P3 (optional, gated). Each phase is independently shippable and independently valuable.
