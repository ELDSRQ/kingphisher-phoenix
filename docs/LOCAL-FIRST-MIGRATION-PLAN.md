# Local-first migration plan (cut Azure cost; Qwen first)

**Goal:** move everything that can run locally to local Docker, without impacting the
build or current functionality, and keep only the irreducible **real-send slice** in
Azure. Build/testing already runs locally (compose on .105/.140) and the code is on
GitHub — so idling Azure does **not** set back progress; it only pauses the ability to do
a *real* send. Written 2026-09-05.

## Done today (immediate cost stop, all reversible)
- **ai-gateway (Qwen) scaled to min‑replicas 0** — the always-on 7B charge stops.
- operator / tracking / worker Container Apps scaled to **min‑replicas 0**.
- **Postgres stopped** (`psql-kp-staging-6117w`) — retains data; Azure auto-starts it in
  ~7 days unless you start it sooner.
- **CI runner VM deallocated** (`vm-kp-staging-runner`).
- Untouched (cheap, needed for a real send): **ACS + email domain + DNS + Event Grid + Entra**.

> ⚠️ These `az` changes are **undone by any `terraform apply` / redeploy**. To make them
> stick, use the deploy toggles in each priority below (the *permanent* line).

## Priority 1 — Qwen / ai-gateway → LOCAL (biggest cost)
**Why it's here:** a 7B model held always-on in a Container App is the single biggest line
item, and it is **not needed in Azure** — Qwen2.5-7B runs locally via llama.cpp (that's how
the AI-010 bake-off measured it on .105/.140 CPU), and the compose stack already has an
`ai-gateway` service.
- **Now (done):** scaled to 0 in Azure.
- **Local runtime:** run the local `ai-gateway` (llama.cpp) on .105/.140 with the staged
  Qwen GGUF (`infrastructure/containers/ai-llama/models/`); the local operator/worker point
  at it (compose already wires this). Content generation + authoring work locally.
- **Permanent:** deploy with **`deploy_ai_gateway=false`** so Azure never brings Qwen back.
- **Real send later:** author/generate content locally (or bring the Azure ai-gateway up
  only briefly during authoring); the *send* itself uses ACS, not the model.
- **Build/functionality impact:** none — hermetic tests already mock AI; real generation is
  served by the local ai-gateway.

## Priority 2 — App tier + Postgres + Redis → LOCAL
**Already local:** `docker-compose.yml` runs `postgres:16`, `redis:7`, and the four app
images with mocks; this is the working build/test environment.
- **Now (done):** Azure apps at min‑0; Azure Postgres stopped.
- **Permanent:** deploy with **`deploy_workloads=false`** (drops Container Apps) and
  **`deploy_data_plane=false`** (drops Redis + ACR — Path B). Keep Azure Postgres **stopped**
  (it carries `prevent_destroy`; don't destroy it) or leave it stopped between sends.
- **Impact:** none — local uses its own DB/cache; Azure DB data is retained for real sends.

## Priority 3 — CI runner → LOCAL
**Already local:** builds/qualification run on the `.105` worker.
- **Now (done):** Azure VM deallocated.
- **Permanent:** deploy with **`deploy_ci_runner=false`**.

## Priority 4 — Observability → LOCAL
- Local `otel-collector` is already in compose; add Grafana/Loki/Tempo or Jaeger if you want
  dashboards. Reduce or drop Azure Log Analytics/App Insights retention (idle-time cost).

## Priority 5 — Registry + private networking → OFF in Azure
- **ACR:** not needed locally (build images directly). Dropped by `deploy_data_plane=false`.
- **Private endpoints + NAT gateway + public IP + 5 private DNS zones:** dropped by
  **`network_mode="starter"`** (public + firewall) or when workloads are idled. These need a
  `terraform plan` review before applying.

## Stays in Azure (cannot be local — the real-send slice)
ACS Communication + Email + **verified domain** + **public DNS** + Event Grid receipts +
**Entra OIDC**. These are ~$0 idle (ACS is per-message; domain/DNS/Entra ~free). Keep them so
a real send skips re-verification. When O365/Entra lapses, swap Entra→local OIDC issuer and
ACS→SMTP (see docs/HYBRID-AZURE-LOCAL-PLAN.md Phase 3) and Azure goes to zero.

## Make the idle permanent (one deploy)
Today's `az` idle is temporary. To lock it in, the next deploy should carry:
`deploy_ai_gateway=false, deploy_workloads=false, deploy_data_plane=false,
deploy_ci_runner=false` (a "cost-idle" var set). Then Azure holds only the real-send slice
until you deliberately resume for a send.

## Resume for a real send (later, when ready)
`scripts/operator/azure-idle.sh start` — starts Postgres and re-applies the workloads/data
plane (with `deploy_ai_gateway=true` only if you want Azure-side generation), then re-patches
OIDC. Everything else stays local.
