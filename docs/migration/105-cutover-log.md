# `.105` migration — cutover log

Running record of the `.140` → `.105` worker migration. Newest entries on top.
Plan: `docs/migration/WSL2-105-MIGRATION-PLAN.md`.

## Rollback anchor
- `.140` is **untouched** by this migration and remains the source of truth /
  hot rollback. Reverting = keep `KP_DOCKER_WORKER` default at
  `edierks@192.168.1.140` (its Colima engine is unchanged).
- Repo state driving the migration: branch `migrate/wsl2-105-docker-worker`.
- The console/e2e data is reproducible (seed + migrations), so no DB checkpoint
  is required to migrate; `.140`'s encrypted checkpoint tooling remains available
  as extra insurance (plan Phase 0).

## 2026-09-03 — Phase 1 executed on `.105` (erikd@192.168.1.105)
All steps driven read/write over `ssh … wsl -e bash`. No changes to `.105`'s
Docker engine or the other agent's containers; installs are WSL2 host-side (root).

- **Toolchain:** uv 0.12.9 installed (`/root/.local/bin`); Python **3.13.15** via
  `uv python install 3.13`.
- **Repo:** branch tree transferred via `git archive | wsl -e tar -x` to
  `/root/kingphisher-phoenix` (530 files, exact match). No GitHub creds needed.
- **Venv:** `uv sync --frozen --all-packages` → 87 packages; core imports OK
  (fastapi, sqlalchemy, psycopg, redis, kp_telemetry).
- **Operator tools:** installed `make` (GNU Make 4.3), `node` (v24.20.0) + `npm`
  (11.19.0), `jq` (1.7), `shellcheck`. (These were the only gaps: the sole
  hermetic failures were `shutil.which("make")` / `operational_readiness.sh`
  requiring `node`.)

### Qualification: `scripts/run-hermetic-tests.sh all`
- First run (pre-tools): **2695 passed, 15 failed, 143 deselected** (828s). All 15
  failures were the missing `make`/`node`, confirmed by traceback — not code.
- After installing make+node: the two affected files
  (`test_readiness_harness.py`, `test_release_packaging.py`) **pass** (56 tests,
  exit 0).
- Full authoritative re-run (after make+node): **EXIT=0 — 2711 passed, 0
  failed, 142 deselected (858s / 14:18)**. `.105` matches `.140`'s hermetic pass
  set. Slow cluster ~34% (container-hardening/subprocess) is expected, not a hang.

### Still to do
- ~~Full hermetic re-run~~ ✅ 2711 passed (see above).
- ~~`base-image-qualification/run.sh`~~ ✅ postgres+redis QUALIFIED on
  linux/amd64 with the exact reviewed digests (EXIT=0).
- **e2e gate** (`KP_DOCKER_WORKER=erikd@192.168.1.105 run-e2e.sh`): needs `.env`
  secrets + weights on `.105` — secret transfer is operator-gated; schedule
  separately.
- Cutover (flip `KP_DOCKER_WORKER` default) only after e2e parity — plan Phase 4.
### E2E gate on `.105` (self-contained, local profile) — ✅ 8 passed
Driven with `KP_DOCKER_WORKER=local`. The stack runs entirely on `.105`: fresh
`.env` via `bootstrap_env`, `docker compose up -d postgres redis mailpit
otel-collector mock-graph mock-ai mock-idp`, then `scripts/operator/e2e/run-e2e.sh`.
The local profile brought up the console (no tunnel), operator+tracking readyz
200, all 8 workers registered, and `make test-e2e` = **8 passed**.

**Three `.env` adjustments were needed on `.105` (reproducible) — the fresh
`bootstrap_env` `.env` surfaced two latent `.env.example` issues:**
1. `KP_WORKER_SMTP_STARTTLS=false` — `.env.example` ships it empty; pydantic
   rejects `""` as a bool, crashing the ingestion worker.
2. Remove empty `KP_WORKER_SMTP_USERNAME=`/`KP_WORKER_SMTP_PASSWORD=` — empty `""`
   is `not None`, so smtp.py:213 attempts SMTP AUTH against mailpit (which
   rejects it: `SMTPNotSupportedError`). They must be UNSET, not empty.
3. DB DSNs → port **5434** (the local console Postgres). In the tunnel model the
   app funnels through 5432→5434; in local mode there is no tunnel, so the e2e
   suite's direct DB access must target the migrated console DB on 5434.

**Recommended repo follow-up (not done here — needs config-test validation):**
set `env_ignore_empty=True` on the worker settings (or drop the empty optional
lines from `.env.example`) so a fresh bootstrap works unmodified. #1 and #2 are
latent bugs independent of this migration.

### `.105` qualification: COMPLETE
- hermetic: 2711 passed ✅  · base-image: ✅  · e2e: 8 passed ✅
- Full stack (console + operator + tracking + 8 workers) healthy in local mode.
`.105` is a proven self-contained worker; the `.140` runtime dependency is
removed (KP_DOCKER_WORKER selects the worker; `local` = self-contained `.105`).

### Remaining
- Phase 4 cutover: make `.105`/local the operator default + update docs (plan).
- Phase 0 backup of `.140` remains available (it is untouched and is the rollback).



## 2026-09-03 — REMEDIATED + LANDED (main e1bbf18)
- **env_ignore_empty=True** added to worker/operator/tracking/ai-gateway settings
  → empty `.env` values are treated as unset. Fixes the two latent bugs; a fresh
  `bootstrap_env` `.env` now works unmodified. Regression tests added.
- **Autodetection**: with `KP_DOCKER_WORKER` unset the docker-worker lib runs
  `local` when a Docker daemon is reachable, else the remote worker (default
  `.140`). `KP_DOCKER_WORKER_AUTODETECT=0` forces remote. Library tests cover it.
- **Local-mode DB on 5432**: the disposable console DB publishes on 5432 in local
  mode (no tunnel, no compose postgres), so a fresh `.env` needs no port edit.
- **Fresh-bootstrap proof on `.105`**: deleted `.env`, re-ran `bootstrap_env`
  (empty SMTP values), brought up the stack without postgres, ran `run-e2e.sh`
  with `KP_DOCKER_WORKER` UNSET → `E2E docker worker: local (local)` →
  **8 passed, EXIT=0**. No manual `.env` edits.

### Cutover complete
On `.105` the operator runs the console/e2e with no env at all (autodetect →
local, self-contained). The Mac controller still autodetects to `.140` (no local
daemon) until `.140` is retired. The `.140` runtime dependency is removed; `.140`
stays untouched as the rollback (plan Phase 0/5).
