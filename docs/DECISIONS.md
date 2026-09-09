# Architecture Decisions

This log records point-in-time architecture decisions for the Phishing Awareness
Platform. Each entry is immutable once recorded; a later decision supersedes an
earlier one by reference rather than by silent edit. It complements the
goal-aligned priority policy and conflict-aware task matrix in
`docs/WAVE-BUILD-PLAN.md` and the architecture overview in
`docs/architecture/README.md`. Decision ids are `D-NNNN`, assigned in order.

## D-0001 — Production Azure AI uses Foundry Serverless (pay-per-token); local stays self-hosted Qwen

- **Date:** 2026-09-05
- **Status:** Accepted (operator direction). Sharpens the existing `AI-005`
  "Foundry serverless/token inference as a measured fallback" clause into the
  **preferred production path**; does not change local development.
- **Deciders:** operator
- **Relates to:** `AI-005`, `AI-010`, `AI-015` (`docs/WAVE-BUILD-PLAN.md`);
  `docs/design/AI-GATEWAY-WORKLOAD-PLAN.md`.

### Context

Producing awareness-training drafts requires an LLM behind the `/propose`
contract. Two hosting shapes were on the table for **production Azure**:

1. **Self-host the model in Azure** (the previous `AI-GATEWAY-WORKLOAD-PLAN.md`
   Path A/B): a digest-pinned `llama.cpp` server serving the Qwen GGUF as a
   sidecar (or from an Azure Files mount), reached by the ai-gateway. This bills
   for (a) the model weights in blob/registry storage, (b) an always-on
   inference container, and (c) GPU/CPU compute — all charged **at idle**, for a
   workload that is bursty (an operator drafting a campaign occasionally), not
   continuous.
2. **Foundry Serverless** (an Azure AI Foundry pay-per-token model endpoint): an
   OpenAI-compatible endpoint billed per token with **zero idle cost**.

### Decision

Production Azure AI uses an **Azure AI Foundry Serverless** (pay-per-token)
model behind the ai-gateway. **Local development and qualification keep the
self-hosted Qwen** (`llama.cpp` on the operator's own hardware — free). This is
therefore a hybrid: *local = self-hosted; production Azure = Foundry
Serverless.*

### Why the app does not change — the ai-gateway seam

The application is already decoupled from the model backend, so the backend is
swappable **without touching the app**:

- The generation worker calls only `POST /propose` on the ai-gateway — it never
  talks to a model directly (`apps/workers/src/kp_workers/jobs.py:2086`, using
  the `effective_ai_base_url` seam at
  `apps/workers/src/kp_workers/config.py:570-571`).
- The ai-gateway is what calls the model backend, at
  `llama_base_url + /chat/completions`
  (`apps/ai-gateway/src/kp_ai_gateway/main.py:157`, posted at `:159`; backend
  URL from `apps/ai-gateway/src/kp_ai_gateway/config.py:22`).

So local → self-hosted `llama.cpp`; production → a Foundry Serverless
OpenAI-compatible endpoint, changing only the ai-gateway's backend config, not
the worker or the operator-api.

### Kept vs dropped for production

- **Kept:** the ai-gateway itself. It is the cheap governance layer that frames
  content as a simulation, enforces the verbatim training-placeholder contract,
  refuses to follow instructions found inside evidence, and pins the returned
  `model_id` rather than trusting the model's self-report
  (`apps/ai-gateway/src/kp_ai_gateway/main.py:100-176`); it also decodes under
  the exact `GenerationResponse` json-schema (`main.py:152-156`). This layer
  stays in front of every backend, local or production.
- **Dropped for production:** the self-hosted `ai-llama` sidecar, the
  weights-in-blob / model-storage, and any GPU/CPU inference compute (the
  `docs/design/AI-GATEWAY-WORKLOAD-PLAN.md` Path A/B mechanisms). Production runs
  only the lightweight ai-gateway (`deploy_ai_gateway` true, no ai-llama
  sidecar), plus the ai-models blob upload and GPU/model-storage removed.

### Consequences

- **Zero idle AI cost** in production; cost scales with actual drafting volume.
- The ai-gateway must learn an **authenticated** backend mode: Foundry needs an
  API key or Entra bearer plus the deployed model name; `llama.cpp` needs
  neither. Config must select the backend (llama vs Foundry endpoint/key/model).
  The chosen Foundry model must support the json-schema structured output the
  `/propose` decoder relies on (`main.py:152-156`); a model that cannot forces a
  change to the contract or the model choice. This code + deploy work is tracked
  as `AI-015`.
- Deployment drops the ai-models blob upload and any GPU/model-storage; the
  `workloads` phase provisions only the gateway.
- **No change to local dev:** the self-hosted Qwen path (`.105`/`.140`
  `llama.cpp` + ai-gateway) stays as-is and remains the free development and
  qualification path. `.140`/`.105` are never a production Azure dependency.
- The self-hosted-in-Azure sidecar/GPU direction (previously the recommended
  Path A) is deprioritized for production but **retained as a documented
  fallback** if Foundry cost, quality, or json-schema support proves
  unacceptable.

## D-0002 — AI-015 (Path D) implementation: Foundry model is a Terraform variable, outbound auth is Entra managed identity

- **Date:** 2026-09-09
- **Status:** Accepted (implemented). Refines `D-0001`; does not change local
  development.
- **Deciders:** operator
- **Relates to:** `D-0001`, `AI-015` (`docs/WAVE-BUILD-PLAN.md`);
  `docs/design/AI-GATEWAY-WORKLOAD-PLAN.md`.

### Context

`D-0001` chose Azure AI Foundry Serverless (pay-per-token) as the production
backend but left two implementation choices open: how the gateway authenticates
outbound, and how the deployed model name is supplied.

### Decision

1. **Outbound auth is Entra managed identity only.** The gateway's
   user-assigned managed identity is granted `Cognitive Services User` on the
   Foundry resource and mints a bearer for
   `https://cognitiveservices.azure.com/.default`. **No API key** is supported
   or stored, so there is no model credential to rotate, commit, or leak. Local
   `llama.cpp` sends no `Authorization` header at all —
   `KP_AI_GATEWAY_UPSTREAM_AUTH_MODE` defaults to `none` and that path is
   unchanged.
2. **The model is a Terraform variable, not a literal.** `ai_foundry_model`
   defaults to `gpt-oss-120b`. Terraform wires the same value to
   `KP_AI_GATEWAY_MODEL_ID` (what the gateway returns) and to the generation
   worker's `KP_WORKER_AI_MODEL_ID` pin, so the pin and the gateway can never
   drift.
3. **No endpoint means no gateway.** `ai_foundry_endpoint` defaults to empty;
   with no endpoint the gateway container app is not created (and an opted-in
   `deploy_ai_gateway` without one fails the plan), so a deployment can never
   produce a gateway with no reachable backend. The gateway scales
   `min_replicas = 0`, which is what makes the managed path true zero-idle-cost.
4. The outbound auth mode is a **separate axis** from the AI-016 inbound
   caller secret (`api_key` / `require_auth`). The two are never conflated.

### Consequences

- Managed deployments bill per token with zero idle cost; the ai-llama sidecar,
  its image, and the weights are no longer part of the managed path (the image
  variable is retained but unused, so the documented fallback and existing
  tfvars keep working).
- **Open verification item:** the selected Foundry model must be confirmed to
  honor the `/propose` JSON-schema structured output
  (`apps/ai-gateway/src/kp_ai_gateway/main.py`, the `response_format`
  `json_schema` block) before `deploy_ai_gateway` is enabled in production. This
  is unverified — no live Foundry call was made as part of this change. A model
  that ignores the schema returns a clean 502 and must not be papered over by
  loosening the contract.
- Also unverified: the exact Foundry endpoint path shape for the chosen
  deployment, that `gpt-oss-120b` is deployed in the target Foundry resource,
  and live IMDS token acquisition from a Container App.
