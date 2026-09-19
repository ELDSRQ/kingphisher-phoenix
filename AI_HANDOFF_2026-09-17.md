# AI Handoff — 2026-09-17

Canonical current-state handoff. Supersedes `AI_HANDOFF_2026-09-13.md`. The
project's auto-memory (loaded each session) holds the fine-grained detail; this
doc is the self-contained map. Read the memory index too.

---

## What this product is
`phishing-awareness-platform` (repo `ELDSRQ/kingphisher-phoenix`, working dir
`/Users/edierks/projects/codex-test/phishing-awareness-platform`) — a GUI-driven
phishing-**awareness training** platform. Safe simulations only; no real
credential capture. Dual-deployment, first-class both ways: **on-prem** and
**Azure**.

## Standing scope constraints (do not violate)
- **Work only on this repo.** Never modify another project. Reading is fine.
- A **separate agent owns CROW (`~/crow`) + the DR mechanism** (dr-sync, launchd
  `com.kingphisher.dr-sync`, `~/bin`). Do NOT touch those. BUT the **hardware
  (Alice `192.168.1.36` RTX 3090; the Strix Halo `192.168.1.24`) is the
  operator's, not reserved** — using it for this platform's model hosting is in
  scope when the operator directs it. Don't disturb `phishing-platform-DR/`.
- **Classifier blocks (system-level, not overridable):** PR merges ("Merge
  Without Review" — operator merges via `! gh pr merge N --merge`), credential/
  SSH *setup* ("Credential Exploration"), and Windows/mac **boot-persistence**
  creation (schtasks / launchd load) — operator runs those; you provide the
  commands. Using an *existing* SSH connection to run commands is fine.
- **Docker builds only on `.105`**; the Mac has no daemon.
- **Second-identity approval is unconditionally barred for self** (pattern +
  template approval) — you cannot complete a campaign launch solo.
- **AZURE_CONFIG_DIR:** infra ops need `export AZURE_CONFIG_DIR="$HOME/.azure"`
  (erik.dierks@gmail.com, sub 169644fd). `KP_DISABLE_DOTENV=1` for test suites.
- **CI gate (`make lint`) runs `ruff check .` AND `ruff format .` repo-wide and
  is NOT merge-blocking** — a format-only miss can land red on main. Run the
  full repo-wide `ruff check . && ruff format --check .` before every PR, and
  the whole console suite (incl. `test_console_non_azure_wiring_contract`,
  `test_console_bundle_drift` + `npm run build`) before any UI PR.
- **Attribution:** commits end with
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` +
  `Claude-Session: https://claude.ai/code/session_01FqPVAcrzBBuiAbNmtJryUF`;
  PR footers `🤖 Generated with [Claude Code](https://claude.com/claude-code)` +
  the session URL.

## What was built + merged this session (all on `main`, CI green)
The **M3 on-prem current-campaign aggregation** feature, end to end:
- **#14–#16** roadmap / Z8 bring-your-own KV / bake-off larger+reasoning candidates.
- **#17** aggregation contract (`kp_contracts.aggregation`) + gateway `POST
  /aggregate` (own long-timeout tier, 503-gated, pins model_id) + feed manifest
  `scripts/seed/threat_feeds.yaml`.
- **#18** ingestion bridge (`kp_workers/aggregation_source.py` — later removed).
- **#19** ruff-format fix.
- **#20** `aggregation_candidates` store (migration 0039) + `kp_database.
  aggregation_candidates` service + operator-api `console/aggregation_routes.py`
  (run/list/promote/dismiss, MANAGE_SOURCES). **Design pivot:** aggregation is
  **operator-console-triggered** (FastAPI BackgroundTask), NOT a worker cron —
  no new Postgres role/supervisor/bootstrap needed. Promote reuses the existing
  activate→pattern path.
- **#21** console "Threat aggregation" view.
- **#22** removed the now-orphaned worker-side aggregation (operator-api owns it).
- **#23** enum-label fix (`aggregation_review_state` must be UPPERCASE — SQLAlchemy
  default name-based mapping; SQLite tests missed it, live Postgres enforced it).
- **#24** promote returns the *actual* linked pattern id (not the computed one).

The full vertical works: feeds → hardened ingestion (`source_items`) →
governance-filtered read → gateway `/aggregate` (RTX model) → ranked candidate →
operator promote → pattern → RTX-generated safe simulation email w/ click marker.

## On-prem is LIVE on Alice (192.168.1.36) — the operator's RTX 3090
Reached via existing `ssh alice` (config alias, key `~/.ssh/alice_dr_ed25519`,
user `erikd`). Windows 11 + WSL2 Ubuntu-24.04 (home `/root`, runs as root).
- **Model:** gpt-oss-20b (bake-off-passing) served by a **CUDA llama.cpp** build
  I compiled (`/opt/kp-ai010/llama.cpp/build-cuda/bin/llama-server`) on
  `0.0.0.0:18082`, OpenAI-compatible + json_schema, ~183 tok/s on the GPU.
  Persistent via Windows Scheduled Task **KP-Aggregate-Model** (script
  `/root/kp-aggregate-start.sh`).
- **App stack:** `scripts/install.sh` in `/opt/kp-amd64/src` (checked out to
  current main) — Docker infra (postgres/redis/mailpit/mocks) + supervisor
  (operator-api :8000, tracking-api :8001, workers). Console at
  `http://127.0.0.1:8000/console` (password `KP_CONSOLE_PASSWORD` in
  `/opt/kp-amd64/src/.env`; currently `eTQhmZL7tMAWANryFU`).
- **ai-gateway:** native `uv run python -m kp_ai_gateway` on `:8090`
  (`/root/kp-gateway-start.sh`), both generation + aggregate tiers point at the
  RTX (`:18082`). `.env` `OPERATOR_API_AI_GATEWAY_URL=http://127.0.0.1:8090`,
  `KP_WORKER_AI_BASE_URL=http://127.0.0.1:8090`, model id
  `llama.cpp/gpt-oss-20b-MXFP4`.
- **Mac access:** permanent launchd tunnel `com.kingphisher.console-tunnel`
  (`-L 8800:127.0.0.1:8000`) → **`http://127.0.0.1:8800/console`** on the Mac
  (Mac :8000 is taken by a local Django app). Mailpit demo tunnel:
  `ssh -N -o IdentitiesOnly=yes -i ~/.ssh/alice_dr_ed25519 -L 8025:127.0.0.1:8025 erikd@192.168.1.36`.

DB creds on Alice: user/db both `kingphisher` (NOT `postgres`); `docker exec -i`
for piped psql. Nested ssh→wsl→bash quoting: use `\"…\"` and CMD eats `>`/`$()`
— write scripts to files and pipe them.

## Reboot persistence status
- Auto-start on reboot: **model (KP-Aggregate-Model)** ✅ + **Mac tunnel
  (launchd)** ✅. **App stack: NOT yet** — boot script `/root/kp-stack-start.sh`
  exists; operator must still register task **KP-App-Stack** (schtasks command
  handed to them). Without it, a reboot brings the model back but not the app.

## Azure (cost-minimized, nothing critical deleted)
`rg-kp-staging` was re-created since the 2026-09-14 teardown. Now trimmed to the
floor **non-destructively**: Postgres **Stopped** (auto-restarts after 7 days),
Foundry AI account gone ($0). **Deleted 2026-09-17** (all Terraform-defined,
recreated by the GUI wizard on next apply): NAT gateway, public IP, private
endpoint. **Remaining ~$10/mo:** VNet+NSG (free), stopped Postgres (storage +
data kept), audit storage (data kept). **Terraform state `rg-kp-tfstate-staging`
untouched** — the only unrecreatable piece. The DEP-010 GUI wizard drives
`terraform apply` via `.github/workflows/azure-deploy.yml`, so a greenfield
Azure setup rebuilds everything. Other RGs (`raven-*`, `atprod*`) are OTHER
projects — never touch.

## Where we are RIGHT NOW / next steps
- **Campaign walkthrough in progress.** Seeded campaign **"Q3 Invoice Lure Drill"**
  (`f25ef7e4`) is launch-gate state `reviewed`, with a locked canary cohort of 2,
  audience, verified domain `example.com`, 5 recipients, mailer → Mailpit
  (`localhost:1025`). Console flow: **Review & run canary** (a `POST
  /campaigns/{id}/proof-send` to the canary cohort → Mailpit) → click the link in
  Mailpit (records a click) → **Publish** (full send, gated on canary evidence) →
  Dashboard shows sent/opened/clicked. `test-send` is intentionally disabled. The
  operator was about to run this in the console; offer to drive the canary via API
  or guide them.
- **Deferred (nice-to-have):** unattended periodic aggregation schedule;
  aggregation-quality eval cases in `scripts/ai-bakeoff/evaluation_set.yaml`;
  swap in a larger reasoning model (QwQ-32B / DeepSeek-R1-Distill-Qwen-32B) —
  bake-off harness + candidates.yaml ready. Optionally reconcile the two
  governed-read copies (operator-api `_load_governed_items`).

## Fast health check
`ssh alice "wsl -d Ubuntu-24.04 -e bash -lc \"curl -sf http://127.0.0.1:8000/readyz; curl -sf http://127.0.0.1:8090/livez; curl -sf http://127.0.0.1:18082/health\""`
