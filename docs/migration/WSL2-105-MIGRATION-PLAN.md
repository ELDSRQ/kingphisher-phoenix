# Migrating the local Docker qualification worker: `.140` (macOS/ARM64/Colima) → `.105` (Windows 11 / WSL2 / AMD64)

**Status:** planning + additive tooling landed on branch `migrate/wsl2-105-docker-worker`.
**Owner:** operator (`edierks`).
**Scope:** the *local engineering & qualification* Docker worker only. This does
**not** touch Azure staging (Container Apps / AMD64), `az acr build` (server-side),
or the self-hosted CI runner (Azure VNet). Migrating this worker cannot break the
live platform.

---

## 0. What is actually moving

| | Source `.140` | Target `.105` |
|---|---|---|
| Host OS | macOS (Apple Silicon) | Windows 11 + WSL2 (Ubuntu) |
| CPU arch | ARM64 (`aarch64`) | AMD64 (`x86_64`) |
| Engine | Colima VM `kingphisher` on `/Volumes/DockerExternal` | Docker Engine native in WSL2 |
| Reached by | SSH `edierks@192.168.1.140` + project-isolated socket | SSH into WSL2 (OpenSSH), default socket |
| Role | hermetic tests, e2e, local image builds | same |
| RAM / disk | — | 64 GB / 2 TB |

**Why the arch change is low-risk:** Azure already runs this exact stack on AMD64;
`docker-compose.yml` pins only multi-arch public images (postgres/redis/mailpit/otel)
with **no `platform:` locks**; and the data path is **logical dumps**
(`pg_restore` + Redis RDB→AOF), which are architecture-independent. `.36` was
already the designated AMD64 lane in the handoff docs — `.105` realizes that plan
on a better box.

**Where the real work is:** the `scripts/operator/remote-docker-worker/` layer is
macOS/Colima/Apple-Silicon-specific (`external-engine.sh` *hard-fails on x86*).
We do **not** edit it. We add a parallel `scripts/operator/wsl2-docker-worker/`
layer that reuses the portable checkpoint archives.

---

## 1. Guiding safety invariants (never relaxed)

1. **`.140` stays the untouched source of truth** through Phase 5. Every phase
   before cutover is additive on `.105`; if it fails, discard `.105` and lose nothing.
2. **No edits to the working `.140`/Colima scripts.** All new tooling is additive
   (new directory), so the current qualification path is byte-for-byte unchanged.
3. **A fresh, verified backup exists before any cutover** (Phase 0) and `.140`
   remains recoverable (frozen, not decommissioned) through Phase 6.
4. **Restore only ever targets a CLEAN engine.** The WSL2 restore refuses to run
   if the target already holds project containers/volumes/networks, and refuses to
   run against the `.140` Colima engine (guard by engine name).
5. **Cutover is gated on `.105` passing the *identical* qualification gates** that
   `.140` passes today — not a subset.

---

## 2. Risk-ordered phases (low risk first)

### Phase 0 — Backup & baseline `.140` **(do first; non-destructive, on `.140`)**
Lowest risk, highest value. Uses the **existing proven** checkpoint tooling.

1. On the controller (this Mac), create a fresh encrypted checkpoint of `.140`:
   ```
   scripts/operator/remote-docker-worker/checkpoint-remote.sh            # dry-run first
   scripts/operator/remote-docker-worker/checkpoint-remote.sh --apply    # logical DB snapshots + additive files only
   ```
   This performs **only** logical `postgres.dump` + `redis.rdb` snapshots and
   additive file creation on `/Volumes/DockerExternal/.../migration-snapshots`.
   It never stops/removes/recreates any container, volume, image, or unrelated
   resource.
2. Stage + validate the snapshot (decrypt-verify without mutating it):
   ```
   scripts/operator/remote-docker-worker/stage-remote.sh
   ```
3. Record the **rollback anchor** in `docs/migration/105-cutover-log.md`:
   git HEAD, engine identity (`colima-kingphisher|aarch64|/var/lib/docker`),
   snapshot archive name + SHA-256, and the date.

**Recovery guarantee after Phase 0:** the encrypted snapshot restores the DB/Redis
state onto any clean engine, and `.140` itself is still fully live. Nothing here
can degrade the current build.

### Phase 1 — Stand up `.105` foundation **(low risk; additive, parallel to `.140`)**
Operator runs the bring-up runbook: `scripts/operator/wsl2-docker-worker/README.md`.
Installs WSL2 Ubuntu, Docker Engine in WSL2, `uv`+Python 3.13, OpenSSH server into
WSL2, `.wslconfig` memory cap, repo cloned onto the **ext4** filesystem (never
`/mnt/c`). `.140` is untouched; a failure here costs nothing.

### Phase 2 — Qualify the `.105` host (read-only) **(low risk)**
From the controller:
```
KP_WSL2_HOST=edierks@192.168.1.105 scripts/operator/wsl2-docker-worker/preflight-105.sh
```
Confirms SSH reachability, a **linux/x86_64** Docker engine, ≥100 GiB free, and a
**clean** target (no pre-existing project containers/volumes). Read-only: it
creates and mutates nothing.

### Phase 3 — Restore data onto `.105` **(medium risk; fully reversible)**
Copy the Phase 0 encrypted checkpoint to `.105`, decrypt into `migration-checkpoint/`,
then run the clean-engine restore inside WSL2:
```
scripts/operator/wsl2-docker-worker/restore-state-wsl2.sh          # preflight (clean-target + archive integrity)
scripts/operator/wsl2-docker-worker/restore-state-wsl2.sh --apply  # create the two project volumes + verified restore
```
The restore mirrors the proven `.140` restore: disposable verify-DB `pg_restore`,
public-table-count assertion, Redis RDB→AOF materialization with DB-0/DB-15
key-count invariants, and AOF-durability check. **If anything fails it aborts
without touching `.140`;** discard the `.105` engine and retry.

### Phase 4 — Qualify `.105` against the identical gates **(medium risk)**
On `.105` (or driven over SSH), run the same gates `.140` passes:
```
scripts/run-hermetic-tests.sh all          # macos_only tests auto-deselected on Linux
scripts/operator/base-image-qualification/run.sh --timeout-seconds 300
scripts/operator/e2e/run-e2e.sh            # pointed at .105 via KP_E2E_DOCKER_HOST (see runbook)
# plus the five container image builds (az acr build is unaffected; local build parity check only)
```
Record results next to the `.140` baseline. **Gate:** `.105` must match `.140`'s
pass set. Any divergence blocks cutover.

### Phase 5 — Cutover **(highest risk; gated + reversible)**
Only after Phase 4 is green. Repoint the controller default host/engine profile to
`.105` (config file, not code), update the runbooks. **Freeze `.140` (stop the
project engine, do NOT delete)** so it is a hot rollback for the soak window.
Rollback = flip the host profile back to `.140` and restart its engine.

### Phase 6 — Decommission `.140` **(final; after a clean soak)**
After an agreed soak (e.g. 2 weeks of green `.105` qualification), retire `.140`'s
project engine. Keep the Phase 0 encrypted snapshot archived off-box. Reversible
until this step.

---

## 3. Rollback matrix

| Failing phase | Blast radius | Rollback |
|---|---|---|
| 0 backup | none (read-only + additive) | re-run; `.140` unaffected |
| 1 foundation | `.105` only | reinstall / discard WSL2 distro |
| 2 preflight | none (read-only) | fix `.105`, re-run |
| 3 restore | `.105` engine only | `docker compose down -v` on `.105`; re-copy snapshot; `.140` untouched |
| 4 qualify | `.105` only | keep using `.140`; debug `.105` offline |
| 5 cutover | controller default | flip host profile back to `.140`, restart its engine |
| 6 decommission | `.140` retired | restore Phase 0 snapshot onto a fresh clean engine |

The build is only ever served by a **fully qualified** engine; `.140` is never
removed before `.105` proves itself and a soak passes.

---

## 4. Known WSL2 gotchas (addressed in the runbook)
- Repo on WSL2 **ext4**, not `/mnt/c` (bind-mount perf).
- `.wslconfig`: give Docker generous memory (host has 64 GB); enable **systemd**.
- Reaching `.105` services **from the Mac** needs the Windows host IP + WSL2 port
  proxy (or mirrored networking) — the WSL2 analogue of today's `.140` SSH tunnel.
- The **llama.cpp AI-gateway** (Qwen2.5-7B-Q4_K_M, CPU inference) is the only
  perf-sensitive image; 64 GB RAM is ample, but re-measure throughput on AMD64.
- Dev volumes are reproducible; the **only** state that migrates is the Phase 0
  logical dumps.

---

## 5. Test status of the tooling in this branch
See `docs/migration/105-cutover-log.md` for the live checklist. Static tests
(`bash -n`, `shellcheck`, compose-YAML parse, mock-engine guard) run in
`scripts/operator/wsl2-docker-worker/test-tooling.sh` and pass locally without a
Docker daemon. Live verification of the restore + gates is Phase 3/4 on `.105`.
