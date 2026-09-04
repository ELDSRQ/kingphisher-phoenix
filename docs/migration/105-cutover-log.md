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
- `base-image-qualification/run.sh` on `.105` (docker present).
- **e2e gate** (`KP_DOCKER_WORKER=erikd@192.168.1.105 run-e2e.sh`): needs `.env`
  secrets + weights on `.105` — secret transfer is operator-gated; schedule
  separately.
- Cutover (flip `KP_DOCKER_WORKER` default) only after e2e parity — plan Phase 4.
