# Removing the `.140` dependency: relocating the local Docker qualification worker to `.105`

**Goal (reframed):** eliminate every dependency the repo/tooling has on the
`.140` macOS/Colima worker so `.140` can be freed. **Nothing in Azure moves** —
Azure staging (Container Apps/AMD64), `az acr build` (server-side), and the
self-hosted CI runner (Azure VNet) have no dependency on `.140` or `.105` and are
out of scope.

**Status:** `.105` reviewed and preflight-qualified (read-only). Additive tooling
on branch `migrate/wsl2-105-docker-worker`. Existing `.140` tooling untouched.

**Concurrency constraint (current):** another agent is actively moving its own
containers onto `.105`. **Do not reboot `.105`, and do not change its Docker
engine / WSL config right now.** All work here is either on repo files (this Mac)
or strictly read-only against `.105` until that agent is done and we coordinate
Phase 1 host changes.

---

## 1. Reviewed state of `.105` (read-only, 2026-09-03)

| Property | Value |
|---|---|
| Reach | `ssh erikd@192.168.1.105` → **lands in Windows cmd**; Docker is in WSL2, reached via `wsl -e bash` |
| OS | Ubuntu 24.04.4 LTS, WSL2 (kernel 6.18), distro `Ubuntu-24.04`, interop on |
| Arch | **x86_64** (the AMD64 lane) |
| RAM / CPU | ~48 GB to WSL2 / 12 vCPU |
| Disk | **952 GB free** of ~1 TB on `$HOME` |
| Docker | **29.8.0** client+server, native linux engine, `root=/var/lib/docker`, name `Docker` |
| Current load | 0 `phishing-awareness-platform` containers/volumes (other agent's workload is separate) |
| Toolchain gaps | **uv absent**, **python 3.12** (repo wants 3.13), repo not cloned |

`preflight-105.sh` passes against the live host today. The clean-target check is
scoped to the `phishing-awareness-platform` compose project, so **`.105` is a
shared host** and our worker coexists with the other agent's containers without
collision.

### Access pattern (important)
Windows OpenSSH drops into `cmd`, so tooling reaches the engine as
`ssh erikd@192.168.1.105 "wsl -e bash -s" < script.sh`. Two cleaner options for
later (both are Phase-1 host changes, deferred, need coordination):
- **(recommended)** run an sshd **inside WSL2** on e.g. port 2222 → `ssh -p 2222`
  lands directly in bash; set `KP_WSL_LAUNCH=` empty and target `:2222`.
- set the Windows OpenSSH default shell to `wsl.exe`.

Until then, all tooling uses the `wsl -e bash` hop (already wired via
`KP_WSL_LAUNCH`).

---

## 2. The `.140` dependency inventory (what must be cut)

Enumerated from `grep` over `scripts/` + `.github/` (docs references are cosmetic).

**A. Runtime (breaks when `.140` is gone) — the real work:**
1. `scripts/operator/dep010/start-console.sh` & `stop-console.sh` — hardcode
   `edierks@192.168.1.140`, SSH-tunnel to it, run the disposable console DB on its
   Colima socket. **Primary functional dependency** (used by e2e).
2. `scripts/operator/e2e/run-e2e.sh` — drives start/stop-console → `.140`.
3. `scripts/operator/deployment-preflight/build-ai-llama-image.sh` — builds the
   llama.cpp AI-gateway image on `.140`.

**B. Worker plumbing (macOS/Colima-specific; replace, don't port):**
4. `scripts/operator/remote-docker-worker/*` — Colima engine, external volume,
   checkpoint/restore, `bootstrap-macos.command`. Superseded by the additive
   `scripts/operator/wsl2-docker-worker/` layer.
5. `scripts/install.sh` — macOS/Colima install path; add a WSL2/Linux path.

**C. Cosmetic:** `.140` mentions across `docs/*`, `README.md`, `RUNBOOK.md` —
updated last, non-blocking.

Everything above is **local qualification/e2e tooling**. None of it touches Azure.

---

## 3. Risk-ordered phases (low risk first; never jeopardize the build)

### Phase 0 — Back up `.140` **(do first; non-destructive; on `.140`, unchanged)**
`.140` is untouched by this migration, so it remains the source of truth and the
rollback target. Still, capture a fresh verified snapshot before any cutover using
the **existing proven** tooling:
```
scripts/operator/remote-docker-worker/checkpoint-remote.sh            # dry-run
scripts/operator/remote-docker-worker/checkpoint-remote.sh --apply    # logical dumps + additive files only
scripts/operator/remote-docker-worker/stage-remote.sh                 # decrypt-verify without mutating
```
Record git HEAD, `.140` engine identity, and the snapshot SHA-256 in
`docs/migration/105-cutover-log.md`. Non-destructive; cannot degrade the build.

### Phase 1 — Finish `.105` toolchain **(low risk; host change; COORDINATE — not now)**
Blocked on the other agent finishing and on your go-ahead (no `.105` changes yet).
Inside WSL2 on `.105` (see `scripts/operator/wsl2-docker-worker/README.md`):
add `uv`, Python **3.13**, clone the repo on **ext4** (never `/mnt/c`), and
(recommended) an sshd inside WSL2 on port 2222. Purely additive; does not touch
the other agent's containers or `.140`.

### Phase 2 — Host-parametrize the runtime `.140` scripts **(low risk; repo only; testable)**
Make the dependency-A scripts host-agnostic instead of hardcoding `.140`:
- Introduce a single host descriptor, e.g. `KP_DOCKER_WORKER` (default keeps
  `.140` until cutover) + a launch shim (`ssh … wsl -e bash` for `.105`, direct
  ssh for `.140`).
- `start-console.sh`/`stop-console.sh`/`run-e2e.sh`/`build-ai-llama-image.sh` read
  that descriptor. Add unit-level tests (mocked ssh) to the existing
  `wsl2-docker-worker/test-tooling.sh` harness. No live host needed to land this.

### Phase 3 — Restore + qualify on `.105` **(medium risk; reversible; `.105` only)**
After Phase 1: copy the Phase 0 checkpoint to `.105`, decrypt into
`migration-checkpoint/`, then inside WSL2:
```
scripts/operator/wsl2-docker-worker/restore-state-wsl2.sh           # clean-target preflight
scripts/operator/wsl2-docker-worker/restore-state-wsl2.sh --apply   # verified restore
```
Then run the **identical** gates `.140` passes:
```
scripts/run-hermetic-tests.sh all                                   # macos_only auto-deselected on Linux
scripts/operator/base-image-qualification/run.sh --timeout-seconds 300
KP_DOCKER_WORKER=erikd@192.168.1.105 scripts/operator/e2e/run-e2e.sh
```
Restore refuses a dirty target and refuses the `.140` engine; a failure discards
`.105` state and leaves `.140` untouched.

### Phase 4 — Cut the default over to `.105` **(higher risk; gated; reversible)**
Only after Phase 3 matches `.140`'s pass set. Flip the `KP_DOCKER_WORKER` default
to `.105`, update runbooks. Keep `.140` **frozen (not deleted)** as a hot rollback.
Rollback = flip the default back.

### Phase 5 — Confirm `.140` is dependency-free & retire **(final; after soak)**
`grep` proves no runtime script targets `.140`; update cosmetic docs; retire the
`remote-docker-worker/` layer (or leave it inert). Keep the Phase 0 snapshot
archived. Reversible until decommission.

---

## 4. Rollback matrix

| Failing phase | Blast radius | Rollback |
|---|---|---|
| 0 backup | none (read-only + additive) | re-run; `.140` unaffected |
| 1 toolchain | `.105` only | remove uv/repo; other agent + `.140` unaffected |
| 2 parametrize | repo branch only | default still `.140`; revert commit |
| 3 restore/qualify | `.105` project scope only | `docker compose -p … down -v` on `.105`; `.140` untouched |
| 4 cutover | controller default | flip `KP_DOCKER_WORKER` back to `.140` |
| 5 retire | `.140` freed | restore Phase 0 snapshot onto a clean engine |

Invariants: `.140` stays the untouched source of truth until Phase 4 and frozen
through Phase 5; every new tool is scoped to the `phishing-awareness-platform`
project so it can never disturb the other agent's containers on `.105`; no reboot
or Docker/WSL change is made to `.105` while the other agent is active.

---

## 5. Tooling status (branch `migrate/wsl2-105-docker-worker`)
- `scripts/operator/wsl2-docker-worker/preflight-105.sh` — read-only host qualify;
  **run live against `.105` and passed** (routes through `wsl -e bash`).
- `restore-state-wsl2.sh` — clean-engine restore; guard unit-tested (accepts
  wsl2 amd64; rejects `.140` Colima / arm64 / windows engines).
- `test-tooling.sh` — daemon-free static tests, all passing.
- README — operator runbook.

Still to build (Phase 2): the `KP_DOCKER_WORKER` host descriptor + parametrized
console/e2e/llama scripts with mocked-ssh tests. Live restore + gates are Phase 3
on `.105` after the other agent finishes and Phase 1 lands.
