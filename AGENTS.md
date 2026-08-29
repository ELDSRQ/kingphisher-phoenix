# Project preservation rules

These rules apply to every agent working in this repository.

- Treat the working tree, `.venv`, Terraform provider/cache directories, Docker
  images, Compose containers, BuildKit cache, named volumes, databases, local
  runtime state, and qualification evidence as preservation-required project
  assets.
- Never delete, prune, reset, remove, recreate, or compact those assets to save
  disk space or simplify troubleshooting.
- Never run project-scoped cleanup such as `docker compose down`, image removal,
  builder pruning, volume pruning, cache deletion, or environment deletion
  unless the user explicitly authorizes the exact targets after being told the
  development and evidence-rebuild cost.
- Preserve `.env`, `data/`, `data/recovery/`, database volumes, audit state, and
  all user changes. Never use broad destructive paths, globs, or unresolved
  variables.
- Treat the native ARM64 worker at `192.168.1.140`,
  `/Volumes/DockerExternal/KingPhisher-Phoenix`, its fixed-volume identity, the
  `kingphisher` Colima profile, encrypted migration snapshots, qualification
  evidence, and the preserved Docker Desktop rollback copy as project assets.
  Absence, read-only state, or identity drift of the external mount must fail
  closed; it must never trigger fallback to Docker Desktop or an internal
  default Colima profile.
- Current handoff state is post-cutover: the external socket/engine and
  inactive `kp-external-mac` context are qualified at exact endpoint
  `ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`;
  the global default remains `desktop-linux`; context evidence is
  `colima-kingphisher|aarch64|/var/lib/docker`. The seven internal project containers are stopped and
  preserved on shared Docker Desktop; unrelated containers remain running. The canonical remote
  source is `/Users/edierks/Projects/kingphisher-phoenix` and its target Colima
  mount is read-only. The legacy encrypted snapshot is unrecoverable because
  its identity is absent and does not satisfy `EXT-002`.
- The legacy Docker contexts named `DockerExternal` and `kp-remote-mac` omit
  the reviewed external socket path and can resolve to the shared Docker
  Desktop engine. Never use them for project operations. The external volume
  named `DockerExternal` is the required storage target, not a Docker context.
- Controller recovery uses `checkpoint-remote.sh` for a temporary identity
  transfer because headless SSH cannot unlock the remote Keychain. A new
  archive must pass controller `stage-remote.sh`, remote
  `stage-checkpoint.sh`, and no-clobber publication to the
  reserved `migration-checkpoint/` path before external-engine-scoped
  `restore-state.sh`. Snapshot `20260829T013332Z-tsX1WQ`, archive SHA-256
  `e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`,
  passed that chain and restore. External installation and `verify_install.sh`
  also passed; this does not qualify later full-suite/image/browser/cloud gates.
- Docker Desktop on `.140` is shared. Never mutate, stop, restart, move, prune,
  or inspect secrets from unrelated containers, volumes, images, builders, or
  cache. Project commands must select the reviewed external socket explicitly;
  never change the global/default Docker context from `desktop-linux`.
- Rosetta, binfmt, and Kubernetes are disabled for the native ARM64 project
  engine; their absence is not a repair condition.
- Production and RSA Conference use remain `NO-GO` until the current
  full-suite, exact-final-image, native AMD64/registry, browser/WCAG,
  cloud/provider, recovery, and human-acceptance gates are proven. External
  restore/install verification is necessary evidence, not production approval.
- Campaign launch review is immutable and evidence-bound. Scheduling queues
  only the exact server-designated test-account cohort from that review. Full
  publication is a separate action and requires current provider/config-bound
  canary evidence; ACS evidence requires authenticated delivered receipts.
  Never restore direct full-audience preparation, ad-hoc test-send bypasses, or
  operator-asserted canary success.
- A uniquely named disposable database or container created during the current
  task may be removed after its result is recorded, but it must never share a
  name or volume with the normal development stack.
- Prefer additive repairs and bounded diagnostics. If disk pressure blocks
  work, report an inventory and stop; do not reclaim project storage.
