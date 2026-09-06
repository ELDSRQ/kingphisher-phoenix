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

## Keep building/testing locally — VERIFIED zero-Azure (2026-09-05)

**You do NOT restart Azure to build/test.** A subagent review confirmed the full
build/test loop runs on local Docker with **zero Azure dependency** — you restart the
*local* Postgres + local app, never the Azure ones, and Azure billing stays off. Azure is
reached only by two explicit opt-in targets (`make test-live-azure`, the e2e live send),
never by routine build/test.

How the local stack is shaped: `docker-compose.yml` provides **infra + mocks only**
(postgres, redis, mailpit, otel, mock-idp/graph/ai). The **app tier (operator-api,
tracking-api, 8 workers) runs as local `uv`/uvicorn processes** via `scripts/supervisor.py`
/ `make dev` — not containers. So the full testable app = local Postgres up **plus** the
supervisor (the mocks-only subset seen running on .105 is not the whole app).

```bash
# Full local app (runs on the .105/.140 Docker host):
make bootstrap        # uv sync + compose up postgres/redis/otel/mocks/mailpit + db-init
make seed             # optional demo data
bash scripts/run_console.sh    # supervisor: operator-api + tracking-api + all 8 workers

# Lighter dev loop (APIs only, no workers): make dev

# Tests (all local, zero Azure):
make test             # hermetic (marker filter: not postgres and not redis and not e2e and not azure_live)
make test-postgres    # needs local Postgres + *_TEST env vars
make test-redis       # needs local Redis (reserved db 15)
make test-e2e         # local campaign lifecycle (KP_E2E_PASSWORD, KP_E2E_LIFECYCLE=1)
make lint typecheck security-scan
```

Every external dependency is satisfied locally: DB/cache → local postgres/redis containers
(own volumes); email → Mailpit (SMTP default); identity/directory/AI → mock-idp/mock-graph/
mock-ai (or local llama.cpp); secrets → `.env`; audit chain → Postgres (the Azure Blob
audit-anchor worker is not in the local roster, so it's never invoked). Only validating the
*genuine* Azure integrations (real ACS/Entra/Blob) needs Azure — the final live validation,
not routine build/test.

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

### Local Qwen bring-up — WORKING runbook (verified end-to-end 2026-09-05 on .105/WSL)

Runs on the WSL Docker host (`ssh erikd@192.168.1.105`, then `wsl`). Repo at
`/root/kingphisher-phoenix`. Verified: real `/propose` generation returned schema-valid,
simulation-framed content in ~15s at ~12 tok/s.

1. **Stage the validated GGUF shards** at `infrastructure/containers/ai-llama/models/`
   (`qwen2.5-7b-instruct-q4_k_m-00001/00002-of-00002.gguf`). Get them from Qwen's official
   HF repo `Qwen/Qwen2.5-7B-Instruct-GGUF` OR copy the operator's staged Mac weights.
   **Verify sha256 == the digests pinned in `infrastructure/containers/ai-llama/Dockerfile`**
   (the HF `00001` shard has drifted; the Mac copy matches — use the matching one).

2. **Run llama.cpp serving Qwen** (note `--threads` — the default is far slower: 1.3 → 12 tok/s):
   ```bash
   D=/root/kingphisher-phoenix/infrastructure/containers/ai-llama/models
   docker run -d --name kp-llama --restart unless-stopped -p 18081:18081 -v "$D":/models:ro \
     ghcr.io/ggml-org/llama.cpp:server \
     --model /models/qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf \
     --host 0.0.0.0 --port 18081 --temp 0 --ctx-size 8192 --parallel 1 --threads 8
   # sanity: curl -s http://127.0.0.1:18081/health   # -> {"status":"ok"} once loaded (~9s)
   ```

3. **Start the ai-gateway** (compose, `ai` profile):
   ```bash
   cd /root/kingphisher-phoenix && export PATH=/root/.local/bin:$PATH
   docker compose --profile ai up -d --build ai-gateway
   ```

4. **WSL NETWORKING FIX (required):** `host.docker.internal` does NOT reach the host's
   published port from a container on this WSL Docker setup, so the gateway's default
   `KP_AI_GATEWAY_LLAMA_BASE_URL=http://host.docker.internal:18081/v1` yields
   `/readyz` = 503 "backend unreachable". Put llama.cpp on the compose network and address
   it by container name instead:
   ```bash
   docker network connect phishing-awareness-platform_default kp-llama
   # in .env: KP_AI_GATEWAY_LLAMA_BASE_URL=http://kp-llama:18081/v1
   docker compose --profile ai up -d --force-recreate ai-gateway
   ```

5. **Point the app at local Qwen:** set `KP_WORKER_AI_BASE_URL=http://127.0.0.1:8090` in
   `.env` (blank = fast `mock-ai`; set = real Qwen). The worker calls
   `POST {KP_WORKER_AI_BASE_URL}/propose`.

6. **Verify e2e:**
   ```bash
   curl -s http://127.0.0.1:8090/readyz            # -> {"status":"ready"}
   curl -s http://127.0.0.1:8090/propose -H 'Content-Type: application/json' \
     -d '{"pattern":{"pattern_id":"t1","lure_category":"credential-harvest","requested_action":"verify your password","delivery_method":"email","emotional_triggers":["urgency"],"source_excerpts":["urgent password reset email"]},"training_url":"https://awareness.example.com/learn"}'
   # -> {"subject":"Phishing Simulation: ...","plain_text":"...","safe_html":"...","model_id":"llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M"}
   ```

Both containers are `restart: unless-stopped`. To revert to fast mock-ai: blank
`KP_WORKER_AI_BASE_URL` in `.env`. `.env` backups: `.env.bak-qwen-*`, `.env.bak-llamaurl-*`.

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
