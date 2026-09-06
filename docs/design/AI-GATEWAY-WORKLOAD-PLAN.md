# AI-gateway workloads deployment — design plan

Goal: deploy the Qwen generation gateway (`kp-ai-gateway`, now a release image)
as an Azure Container App in the `workloads` phase, so worker `/propose` and
operator-api `/setup-assist` reach real Qwen in Azure instead of the mock.

Status: PLAN. Terraform not yet written pending the backend decision below.
Building the terraform is agent-runnable; the live `workloads` deploy stays
operator-gated.

## Fixed pieces (decision-independent, mirror existing pattern)

- New `variable "ai_gateway_image"` (mirrors `operator_image`), consumed by the
  new `azurerm_container_app.ai_gateway` (count = `var.deploy_workloads ? 1 : 0`).
- Add `"ai-gateway"` to `local.workload_identities` and
  `local.image_pull_identities` so it gets a user-assigned identity and ACR
  pull, exactly like operator/tracking.
- The gateway container: image `var.ai_gateway_image`, env
  `KP_AI_GATEWAY_HOST=0.0.0.0`, `KP_AI_GATEWAY_PORT=8090`,
  `KP_AI_GATEWAY_MODEL_ID=llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M`,
  `APPLICATIONINSIGHTS_CONNECTION_STRING`; liveness `/livez`, readiness `/readyz`
  on 8090.
- **Internal ingress** (`external_enabled = false`, target_port 8090) — only the
  worker/operator-api call it, in-cluster. Its internal FQDN is wired into the
  worker + operator-api env as `KP_WORKER_AI_BASE_URL=http://<gateway-fqdn>`
  (replacing the mock default), and the worker's `KP_WORKER_AI_MODEL_ID` guard
  already matches the pinned id.

## The decision: how llama.cpp serves Qwen in Azure

The gateway is a proxy to an OpenAI-compatible llama.cpp server
(`KP_AI_GATEWAY_LLAMA_BASE_URL`). There is **no volume/Azure Files mechanism in
the terraform today**, and we never auto-download weights (the GGUF is
digest-pinned in `docs/ai010-selection/`). Three ways to serve it, each shaping
the terraform very differently:

- **Path A — model baked into a digest-pinned llama.cpp image (recommended).**
  Build `Dockerfile.ai-llama` in ACR: a pinned `llama.cpp` server base + the
  digest-verified `Qwen2.5-7B-Instruct-Q4_K_M.gguf` (~4.7 GB) copied in, its
  sha256 checked at build. Runs as a **sidecar container** in the ai-gateway
  app; the gateway reaches it at `http://localhost:18081/v1`. Most aligned with
  the project's supply-chain discipline (the RUNBOOK's "digest-pinned llama.cpp
  model") — the weights are immutable, attested, no runtime fetch. Cost: a
  ~5 GB image and a large container-app (llama.cpp 7B Q4 CPU needs ~6–8 GiB RAM,
  ~2–4 vCPU); the app runs 24/7 unless scaled to zero. Adds a 6th release image.

- **Path B — model on an Azure Files share, mounted into a stock llama.cpp
  sidecar.** Net-new terraform: storage account + file share +
  `azurerm_container_app_environment_storage` + a volume mount; the operator
  uploads the pinned GGUF to the share once. Smaller image, but introduces
  mutable runtime state (the share) and a stock (still digest-pinned) llama.cpp
  image outside the release set. More moving parts.

- **Path C — external llama.cpp endpoint.** Gateway points at an
  operator-run/managed llama.cpp URL via `var.ai_gateway_llama_base_url`. Least
  new infra, but no in-Azure inference — defers the actual serving.

- **Path D — Azure AI Foundry Serverless backend (production, preferred per
  D-0001).** The gateway points at a Foundry Serverless (pay-per-token)
  OpenAI-compatible model endpoint instead of a `llama.cpp` server. No model
  weights, no inference container, no GPU/CPU compute — **zero idle cost**; the
  bill scales with actual drafting volume. Requires teaching the gateway an
  authenticated backend mode (Foundry API key or Entra bearer + the deployed
  model name; llama.cpp needs neither) and confirming the chosen Foundry model
  honors the `/propose` json-schema structured output
  (`apps/ai-gateway/src/kp_ai_gateway/main.py:152-156`). The gateway governance
  layer is unchanged. Tracked as `AI-015`.

## Recommendation

**Superseded for production by decision `D-0001` (`docs/DECISIONS.md`,
2026-09-05): production Azure AI uses Path D (Foundry Serverless, pay-per-token,
zero idle cost).** Production therefore runs only the lightweight ai-gateway
(`deploy_ai_gateway=true`) with a Foundry backend — **no ai-llama sidecar, no
weights-in-blob, no GPU/model-storage.** Local development and qualification
keep the self-hosted Qwen (Path A/C on the operator's own hardware — free), so
the seam serves both: local → `llama.cpp`, production → Foundry, changing only
the gateway's backend config.

The Path A analysis below is retained as the documented **fallback** if Foundry
cost, quality, or json-schema support proves unacceptable. It matched the
established digest-pinned/attested posture and needed no new stateful storage,
but its cost — a large image and a memory-heavy always-on (or scale-to-zero)
container app billed at idle — is exactly what `D-0001` avoids for a bursty,
occasional drafting workload.

## Phasing once the backend is chosen

1. Variable + identity wiring + the ai-gateway container app (internal ingress),
   backend URL parameterized. `terraform validate` + runtime-contract test.
2. Backend per the chosen path (A: image + sidecar; B: storage + mount; C: var).
3. Wire worker/operator-api `KP_WORKER_AI_BASE_URL` to the gateway FQDN.
4. Runtime-contract test updates; no live deploy (operator-gated).
