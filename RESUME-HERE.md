# RESUME HERE — current engineering handoff

**Reconciled:** 2026-08-29

**Repository:** `/Users/edierks/projects/codex-test/phishing-awareness-platform`

**Decision:** **NO-GO for production and RSA Conference use.**

**Engineering topology:** the controller retains this workspace. The current worker is
the native ARM64 worker `edierks@192.168.1.140`, canonical source
`/Users/edierks/Projects/kingphisher-phoenix`, and a read-only source mount in
the project-only `kingphisher` Colima VM. Its VM disks, cache, client metadata,
and socket are rooted under `/Volumes/DockerExternal/KingPhisher-Phoenix`.
External preflight and restore passed; the final preflight re-proved the exact
engine/volume identity with approximately 744,006,440 KiB free. The inactive `kp-external-mac` context
has endpoint
`ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`
and reports `colima-kingphisher|aarch64|/var/lib/docker`; the global
context remains `desktop-linux`. The seven internal Docker Desktop project
containers are stopped and preserved; unrelated containers remain running.
If the exact external volume is absent, read-only, wrong-UUID, or low on
space, stop—never fall back internally. See
`scripts/operator/remote-docker-worker/README.md` and
`docs/PRODUCTION-READINESS-TASK-MATRIX.md`.
The legacy Docker contexts `DockerExternal` and `kp-remote-mac` do not select
the reviewed socket and must never be used for project work. `DockerExternal`
as a volume name is not a Docker context. Rosetta and binfmt are disabled and
unnecessary for this native ARM64 engine.

Cutover evidence is snapshot `20260829T013332Z-tsX1WQ`, archive SHA-256
`e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`;
it passed staging and external restore and completes `EXT-002`.

This is a concise navigation aid. The authoritative status, evidence, findings, task dependencies, and acceptance gates are in [the integrated build plan](docs/WAVE-BUILD-PLAN.md). Read [the architecture](docs/architecture/README.md) before changing a trust boundary and [the engineering handoff](docs/AI_HANDOFF.md) before implementation.

## Product direction

Build for one 125-person organization operated by two IT staff: one
single-tenant browser console, three managed deployables by default (operator,
tracking/training, and one multi-role worker), and a bounded one-time bootstrap.
Routine deployment, mail/directory integration, campaign operation, recovery,
and evidence export should become GUI-driven.

AI may advise and draft. Deterministic code must enforce identity, authorization, recipient scope, RoE, approvals, content safety, delivery controls, and audit. AI must never apply infrastructure, grant consent, save secrets, choose audiences, approve campaigns, or send mail.

The supported AI direction is internal-model-first. Benchmark two or three
small permissively licensed instruction models on the fixed sanitized
evaluation set, then digest-pin the selected weights, license, runtime, prompt,
and result. Prefer a pinned `llama.cpp` role/job in the existing worker image,
CPU first; use scale-to-zero serverless GPU only when measurement requires it.
Foundry serverless/token inference is an optional measured fallback. Foundry
managed compute and always-on GPU capacity are out of scope. The `.140` worker
is development/qualification infrastructure only, never a production Azure
dependency.

Deferred means retain and support useful existing behavior but do not expand it
or give it an implementation slot. Never delete a potentially valuable feature
merely because the new priority policy defers it; remove product claims for
rejected behavior and require a separate reviewed decision before retiring
functionality or data.

### Wave 38 checkpoint — landed and pushed

- `ORG-001` is complete locally: a campaign creator cannot self-approve, while
  one independent operator who holds both approval capabilities may complete
  the separate security and privacy facets. Signed RoE, frozen audience,
  reviewed canary, provider evidence, emergency stop, immutable review, and all
  other safety gates remain unchanged.
- `THR-001A` and `DOCSIM-001` are complete locally. Reviewed generation context
  now preserves evidence fidelity, and ICS behavior is recipient-bound rather
  than promising an absent tracked URL. Their focused closure passed 150 tests.
- `IMP-001` is complete locally: guided CSV preview/apply supports explicit
  header modes, arbitrary bounded header labels, mapping, skip/update merge,
  optional soft-deactivation, digest-bound confirmation, and serialized writes.
  Preview remains recipient-nonmutating; concurrent applies return `409` and
  require a new preview.
- `THR-001B` is complete locally: bounded daily ingestion now quarantines new
  evidence, the GUI exposes the bounded Threat Campaigns workbench, and audited
  activation alone creates or retains one deterministic draft pattern basis.
  Rejection/duplicate decisions, current source terms, approval, and generation
  are rechecked without deleting legacy evidence or human review state.
- The `OUT-001`/`RET-005`/`INT-001` foundation and retention integration are
  complete locally at Alembic head `0032_source_explicit_curation`:
  confirmed interaction is distinct from scanner-observable events; the PII-free
  ledger retains 1,826 days; raw outcomes remain capped at 365 days; outcome
  writers and terminal-only project-before-purge share a lock boundary; the
  pseudonym key, grants, policy bounds, and legacy threat re-review migration are
  wired. Privacy/RBAC, named-history API, reporting, graph, and export consumers
  remain open.
- The retained P1 was closed: `RetentionPolicy.__table_args__` now mirrors
  migration `0032`'s 1–365-day check and PostgreSQL partial unique single-default
  index, with ORM-metadata assertions and direct-database rejection tests.
- The current-head gate then exposed and fixed a pre-existing defect: revision
  id `0032_source_item_explicit_curation` (34 chars) overflowed Alembic's fixed
  `VARCHAR(32)` version column, so **no fresh database could upgrade to head**.
  It was renamed to `0032_source_explicit_curation` (29 chars), the constraint
  name was aligned to the codebase's short-name convention, and the
  upgrade/downgrade round-trip was proven on live PostgreSQL. Two UI-contract
  tests referencing a renamed `app.js` marker, a `RESUME-HERE.md` GitHub
  read-only-boundary gap, and a shared-DB collision in the new retention tests
  were also repaired.
- The checkpoint was committed as `d25313d` and pushed; `origin/main` advanced
  `1403d94` → `c9ea716` with the ANA-010 ledger-trend (`aa67c17`) and named
  close-disposition (`c9ea716`) increments. Worktree is clean; do not reset or
  clean it.
- Current-head gates (all 2026-08-29, after the checkpoint): hermetic 2,620/103
  deselected with 0 failures in 180.45s; external PostgreSQL 92 passed
  (fresh-install/historical migration to `0032`, retention concurrency,
  outcome-writer-versus-retention, grants); external Redis 2 passed on DB15;
  `make lint` and strict mypy (131 files) clean. E2E, exact-image, browser, and
  cloud gates remain open.

## Current engineering truth

Completed local/static closures include:

- local Compose and mock-service base images pinned by tag plus immutable manifest digest;
- recovery-safe local deployment now freezes the Compose project as
  `phishing-awareness-platform` and the stateful volumes as
  `phishing-awareness-platform_postgres_data` and
  `phishing-awareness-platform_redis_data`. A missing or incomplete `.env`
  cannot cause replacement credentials to be generated when those preserved
  volumes exist or Docker inventory cannot be read; the launcher stops and
  requires protected recovery material instead;
- local startup requires 8 GiB of disk by default, then runs the read-only
  `prestart` phase before Compose, stateful base-image qualification, controlled
  service start, migrations/audit bootstrap/seed, and the read-only `ready`
  phase before application processes. Preflight parses `.env` as inert data and
  supplies only the four Compose credentials to Compose, only `DATABASE_URL` to
  migration inspection, and no dotenv secrets to Docker/volume inspection;
- base-image qualification first proves an exact cached image's reviewed digest
  and platform and uses `--pull=never`, so preserved installations can qualify
  offline. A cache miss uses the reviewed remote index and exact digest. The
  hardened probes attach no project volume; Redis additionally runs as
  `999:999` and must write a disposable `/data` tmpfs before it is qualified;
- the mock Python runtime locked as a fully pinned, hash-verified 17-package closure;
- normal workspace bootstrap, development, and console launch consuming the frozen `uv.lock` without lock mutation;
- `make security-scan` failing closed on export/audit failure and auditing the hash-verified 58-package external production workspace closure in strict no-resolution mode;
- pinned `pip-audit` 2.10.1 reporting zero known vulnerabilities for that closure on 2026-08-27;
- `make sbom` emitting native CycloneDX 1.5 with 59 total components, including 58 external package PURLs;
- operator and tracking public OpenAPI, Swagger, ReDoc, and HTTP metrics routes removed, along with their write-only internal metric registries; bounded health/log state and worker snapshots remain;
- audit verification retaining only aggregate status and a bounded problem count, never raw problem details in scheduler state, health output, or logs;
- browser authentication-mode discovery failing closed instead of assuming development authentication;
- official Starlette `TestClient` compatibility through a test-only `httpx2` dependency; production clients remain on the normal runtime `httpx` dependency;
- a versioned, key-ID-bound AES-GCM ciphertext format with one active key, at most four prior decrypt-only keys, and bounded legacy-unversioned reads;
- a complete 113-route operator authorization manifest—103 capability-protected plus 10 dedicated/public routes—exact browser/backend capability inventory, capability-aware non-Azure GUI actions, aggregate-reader Help access, and approve-only safe template preview;
- warning-strict SQLite lifecycle/outbox cleanup and duplicate `Content-Length` rejection at the public tracking edge.
- the current loopback Mailpit canary using an explicit seeded `example.com` account passed within the 8-test external E2E profile at exact head `0029`. It proved one canonical approved-template delivery, retry suppression, recipient-bound tracking, assignment reuse, separate training purposes, knowledge-check remediation/pass/replay, and correlated report/audit state before exact cleanup. This is local-live evidence, not provider or inbox proof;
- native-UUID outbox completion and bounded reconciliation; final local acceptance fixed an audit-store owner-fallback revocation defect, drained 36 stranded idempotent queue intents, and left the audit chain green. Graph/Microsoft 365/ACS-event/reported-MIME seams remain bounded with an explicit ACS managed-identity client ID;
- a recovered Terraform provider tree that passes provider-backed local initialization and validation, without a remote backend or Azure plan/apply;
- server-derived campaign/pattern action flags and bounded campaign/pattern/privacy boundaries; protected GitHub environment/workflow/run and owner-bound Redis lease validation; and worker preflight/context/reminder/retention/dead-path repairs.
- Wave 24 bounded user-facing collection queries and browser paging, including a 100-candidate fail-closed RoE scheduling cap; replaced application/worker runtime `assert` guards with explicit failures; and ordered scoped campaign stops against delivery with a shared/exclusive database lock. The focused worker lifecycle/security lane passed 52 tests in 1.30 seconds, and the isolated PostgreSQL lane passed 15 in 3.07 seconds, including a 250 ms lock-contention proof. A separate isolated migrated-PostgreSQL scoped-kill persistence test passed 1 in 2.88 seconds at head `0027`, then dropped its disposable database. An exploratory PostgreSQL ACS pacing check printed `acs_pacing_upsert_and_durable_fence=ok` after reserving 3 and then 0 sends in one window. These are overlapping point-in-time lanes.
- final dead-path cleanup removed the broken installed `kp-seed` command while retaining source `make seed`; made `make sign` require an immutable `IMAGE`, `COSIGN_KEY`, and `cosign` and fail closed otherwise, without claiming an external signature; retired ignored reminder/Mailpit-TLS/queue-prefix settings while retaining the fixed 72-hour training due policy; and removed remote full-stack stop routing, capability, and marker handling from the browser application, supervisor, and launcher. Settings still provides GUI restart; a host signal stops the launcher, and full shutdown remains an OS/launcher/terminal recovery operation. The focused stop-removal lane passed 39 tests.
- one canonical bounded generation contract through queue, provider, storage, review, and delivery, plus durable idempotency that converges retries/races without duplicate provider calls or drafts;
- current source-terms acknowledgement enforced by API and worker, with audited acknowledge/inspect/revoke GUI lifecycle and a post-fetch terms fence;
- server-side validation and normalization for campaign, source, privacy, correction, approval, exclusion, and rationale inputs, with capped non-reflective validation output at operator and tracking boundaries;
- checked-in migration head `0032_source_explicit_curation`: `0031` adds the PII-free confirmed-interaction/1,826-day awareness-ledger foundation; `0032` quarantines legacy automatically active threat evidence for explicit review and enforces migrated retention-policy bounds/default uniqueness. The current-head external PostgreSQL profile passed 92 tests on 2026-08-29 (fresh/historical migration, retention concurrency, outcome-writer-versus-retention, grants); the historical 86-test result at `0029` is superseded;
- server-derived per-resource training `can_submit`/`can_review` flags, independent-review locking, and a GUI that refuses missing or malformed flags instead of reconstructing authority;
- aggregate and named reporting with separate capability gates, owner-safe alert subscription lifecycle, GUI recipient exclusions, and server-paginated global/campaign recipient results;
- streamed, bounded, schema-checked OIDC, setup-assistant, AI-generation, and GitHub deployment responses, including duplicate/malformed length rejection and no buffering of GitHub dispatch bodies. The approved non-local HTTPS `/propose` and `/setup-assist` gateway remains a preserved optional adapter; it is not the supported default AI deployment path. Pattern approval records a durable generation request without claiming asynchronous queue/provider completion, and the internal-model worker path plus live AI qualification remain open;
- provider-aware GUI configuration with explicit SMTP/ACS and Mailpit/Microsoft 365 selects; only active non-secret fields reach setup assistance, inactive controls are hidden/disabled/excluded while saved values remain preserved, and provider or destination changes validate before atomic credential rebinding. ACS testing is non-sending reachability-only at an exact HTTPS `*.communication.azure.com:443` origin; Microsoft 365 tests one quoted, bounded Graph delta path and fail closed on bearer authentication or redirect failures;
- privacy export is authenticated `POST`, privacy list/export responses are `private, no-store`, and cookie-authenticated mutations require trusted same-origin CSRF metadata. Privacy request operations load independently from the current notice and remain usable with a visible warning if that notice read fails. OIDC discovery, authorization, token, and JWKS endpoints are issuer-origin bound; DNS is pinned for each request with TLS Host/SNI preserved, redirects/proxy inheritance/HTTP2 are disabled, and cross-origin navigation or secret transmission fails closed;
- managed tracking receives exact bounded `TRACKING_API_TRUSTED_PROXIES` CIDRs derived from the Container Apps infrastructure subnet plus loopback. It accepts forwarding only from a trusted direct peer and resolves the canonical bounded `X-Forwarded-For` chain right-to-left with Uvicorn proxy rewriting disabled;
- deterministic cleanup for newly added PostgreSQL fixtures so focused database suites do not leak schemas, tables, roles, or engines across runs.
- a fail-closed integration-test queue boundary: PostgreSQL jobs use Redis DB14 and flush only DB14 before and after their profile; the Redis queue contract uses DB15; application DB0 is never a test cleanup target.

Managed prior keys are intentionally limited to metadata-bound legacy/recovery use. The active key ID is fixed after the first foundation dispatch, active rotation is deliberately blocked, and `prevent_destroy` protects the Terraform-generated active key while also complicating teardown. The active KEK remains in protected Terraform state/history. Safe pre-stage/prove/promote rotation, database decrypt proof, bulk re-encryption, and prior-key retirement remain unimplemented debt.

The reviewed deployment workflow, Terraform, API, and GUI now agree on exactly
three execution stages: `foundation_bootstrap`, `foundation_finalize`, and
`workloads`. The connector is frozen to workflow SHA-256
`6868067ef5d58c799bc4a07dd832d4852d38dee73e6ff1af9a58c701ce85a4d3`.
`foundation_bootstrap` plans/applies the complete `deploy_workloads=false`
foundation—including ACR, private-network, data, ACS/email/domain, and DNS
resources—without Terraform targets. It initiates four ACS DNS verification
types but explicitly forbids sender/association changes. `foundation_finalize`
permits only those exact changes after fresh verification, and every stage
refuses delete/replacement plans. GUI export, API validation, Terraform, and
preflight share the exact one-label HTTPS `*.communication.azure.com:443`
contract. `workloads` requires exactly one active Healthy/Provisioned worker
revision, two consecutive simultaneous ready observations for every enabled
role, and a final health check of that same revision before environment health
can pass.
The five configuration pages are not execution phases, and the two Event Grid
passes inside `workloads` are internal workload steps, not extra stages. No
stage has live GitHub/Azure/provider qualification.
The 2026-08-29 read-only GitHub re-audit of `ELDSRQ/kingphisher-phoenix` proves
valid `ELDSRQ` authentication with `repo`/`workflow` scopes; a public, enabled
repository with default `main`; Actions enabled; and the Azure workflow active,
with no billing-disabled run signal. It also proves zero environments,
variables, secrets, rulesets, and workflow runs, unprotected `main`, disabled
secret scanning and push protection, and remote `main` still at old-tree SHA
`1403d944a40214714b6cbfcf5cbabc4fa7225eb9` at re-audit time; the checkpoint push has since advanced remote `main` to `c9ea716`. No workflow dispatch/run or Azure
plan/apply occurred; current Azure management-plane state remains unverified.

Wave 29 makes recovery preservation-first rather than cleanup-driven. Local
preflight reports `mutation_performed=false` and
`automatic_cleanup_allowed=false`; partial or drifted state blocks instead of
creating a parallel volume. Reviewed deployment requests retain append-only,
hash-chained checkpoints and reconcile an interrupted or indeterminate attempt
against the same request and provider evidence. Do not delete, prune, reset,
rename, recreate, or blindly redispatch to obtain a green gate.

The closing recovery audit also prevents Compose recreation, validates all
preserved recovery credentials and key mirrors before dependency sync or
`.env` writes, rejects malformed/truncated/duplicate Docker evidence, and
requires both the supervised PID and `/readyz` for an already-running fast
path. Release verification refuses pre-existing image tags and removes only
ephemeral resources it proved it created. Supervisor/launcher publication is
atomic and recoverable. Azure bootstrap uniquely validates an existing console
application's exact eight-role contract before its first cloud mutation and
again at point of use.

Exact-final ARM64 status is evidence-conditional and requires the exact Docker server platform
without emulation, explicit `--platform`, all-five OS/architecture/image-ID
metadata, unchanged source/context manifests, Trivy 0.74.0, retained no-clobber
`qualification.json` plus scan evidence, labeled-disposable cleanup verification,
the expected source-manifest digest, exact Trivy executable/hash/cache, retained empty config/ignore/secret policy files,
ambient-`TRIVY_*` rejection, fresh database/check-bundle metadata, and an
immutable verified cache. Azure
workloads must scan exact immutable ACR `repository@sha256` images with pinned
Trivy before SBOM/attestation/deploy and retain scan JSON and checksums. These
are implemented gates; only their retained evidence can establish a pass.
The fixed planned evidence root is
`/Volumes/DockerExternal/KingPhisher-Phoenix/qualification-evidence/arm64-release-20260829-wave35-final-v3`
with `verifier/` beneath it and unique prefix
`kingphisher/verify-arm64-20260829-w35-final-v3`; its validated contents, not
the path's existence, determine the ARM64 result.
The preserved `final-v2` attempt failed closed before image build because BSD
filesystem-mode and evidence-path/source-context handling violated the verifier
contract. Those failure artifacts were not clobbered; the defects were repaired
for `final-v3`, whose retained evidence remains conditional and unvalidated.

Wave 21 historically added a green local installation check and a strict 7-test E2E result after targeted local bootstrap/audit, token-key, PID/log, mock Graph, and fixture repairs. Shared RoE/RBAC hardening passed 374 owned/consumer tests plus Ruff/mypy, 0-finding Bandit/Semgrep, and offline package build/import. Its 23 CI workflow tests, Actionlint, and Zizmor result belongs to the historical Wave 21 workflow SHA, not the current frozen connector. The dead clone adapter was removed for a net 87-line reduction with 36 focused plus 5 downstream tests passing. The historical pre-Wave-30 result was 1,994 hermetic/87 PostgreSQL/2 Redis/8 E2E, the superseded intermediate external result was 2,230/86/2/8, and the now pre-remediation local/external snapshot was 2,329 hermetic/97 deselected, 86 PostgreSQL/2,340 deselected using Redis DB14, 2 Redis/2,424 deselected using DB15, and 8 E2Es plus audit and `verify_install`; its 03Z API/worker log window was clean. The pre-Wave-36 local hermetic `make test` passed 2,469 tests with 97 deselected and 0 failures in 158.15 seconds. The final local Wave 36 hermetic suite at historical head `0030` passed 2,501 tests/97 deselected with 0 failures in 183.40 seconds. Ruff/format, mypy, and security results remain bounded to their separately recorded scopes. Current-head `0032` PostgreSQL/Redis/E2E external profiles, exact-image evidence, and all external release gates remain pending.

## Evidence boundary

All five native ARM64 images passed the latest completed startup/hardening snapshot, but later source edits make those interim images stale. External capacity/restore and the historical final local Wave 36 hermetic suite are proven; current-head `0032` PostgreSQL/Redis/E2E external profiles remain pending. The internal seven Docker Desktop project containers are stopped/preserved; unrelated containers remain running. Validated snapshot `20260829T013332Z-tsX1WQ` completes `EXT-002`; older invalid/unrecoverable snapshots remain preserved. Exact-final images, browser/WCAG, Azure/providers, AMD64/registry, rotation, production recovery, and human-witness evidence remain open. No KnowBe4 parity or production readiness is claimed.

The exact five image IDs and sizes are recorded in the canonical build plan. They are point-in-time evidence because later source edits changed image inputs.

For an RSA-controlled pilot, require a written RSA-controlled RoE and an exact RSA-controlled population and domains. Conference attendance, exhibitor status, or public contact information is not authorization.

## Do not regress

- Preserve Entra OIDC and server-derived fail-closed roles/capabilities; the shared credential is loopback development compatibility only.
- Preserve exact previewed/frozen audiences, separate security/privacy approval facets completed by one independent dual-capability approver, signed RoE, verified domains, recipient caps, deterministic rendered-content validation, and the persistent emergency stop. Never restore self-approval.
- Never blindly retry an `INDETERMINATE` provider send or represent provider acceptance/MTA handoff as inbox placement or reading.
- Preserve purpose- and assignment-bound tracking/training links and keyed verifiers at rest.
- Preserve role-specific managed identities/database URLs, the database-owned audit dispatcher, append-only witness boundary, and fixed `queue_dispatch_failed` durable failure code.
- Keep public OpenAPI/docs/metrics routes absent and audit health aggregate-only.
- Keep auth-mode discovery fail closed; never default a failed discovery to development login.
- Keep training actions bound to exact server `can_submit`/`can_review` booleans, source ingestion bound to current terms, recipient results paginated, and ordinary exclusion revocation append-only.
- Keep provider and identity JSON responses streamed and bounded before decoding; never echo or log provider bodies, tokens, or low-level errors.
- Keep local image digests, mock dependency hashes, and frozen workspace dependency resolution reproducible. Audit and SBOM must cover the full external production closure.
- Keep the fixed Compose project/volume identities, preservation-aware `.env`
  refusal, command-specific preflight environments, `prestart`/`ready` order,
  and exact-cache base-image probes. Recovery is inspect, checkpoint, and
  reconcile in place—never automatic deletion, pruning, reset, recreation, or
  credential regeneration over preserved state.
- Keep every `.140` project Docker command bound to the exact external volume,
  profile, socket, and canonical source. Never change the global context or
  mutate the shared Docker Desktop engine/unrelated workloads. Preserve the
  internal project copy, external profile, and encrypted snapshots.
- Keep managed prior keys recovery-only, preserve the immutable active ID and `prevent_destroy`, and do not retire a prior key until bulk migration/proof establishes that no required ciphertext still needs it.
- Never turn local/static tests, Terraform validation, or dependency audit into Azure/provider/browser/recovery evidence.

## Next execution order

1. Deliver the minimum complete product: ANA-010 and TRN-010 are complete
   locally (five-year ledger graph, named close disposition, repeat history,
   and named per-recipient pseudonymous drill-down with a shared governed
   pseudonym key — GUI drill-down wiring and key rotation/recovery remain
   governed follow-up; and the campaign-bound knowledge check: optional
   all-or-nothing question/options/answer on training lessons, deterministic
   evidence builder, digest-pinned, generic quiz fallback, GUI authoring/
   preview/review). The remaining minimum-product item is: benchmark/select
   the internal model against the landed AI-010 bake-off foundation
   (`scripts/ai-bakeoff/`: fixed sanitized evaluation set + deterministic
   offline scorer + bounded loopback runner) and wire `AI-010` into the
   existing worker role/job. Deterministic
   fallback and human approval remain mandatory. Do not reopen locally
   complete `ORG-001`, `THR-001A/B`, `IMP-001`, `DOCSIM-001`, `ANA-010`, or
   `TRN-010` without a regression.
2. Simplify the normal Azure/mail path through the GUI after those interfaces
   stabilize; keep the existing secure three-stage deployment contract and
   provider adapters supported while hiding engineering internals.
3. Qualify the exact resulting product: current-head external E2E,
   all five exact-final native ARM64 images, native AMD64/registry/attestation,
   real browser/WCAG, disposable Azure, Entra/Graph/Outlook/ACS/DNS/inbox,
   recovery/rotation, alert/audit witness, and human operator acceptance.
4. Only after the core is stable, simplify navigation/modules without deleting
   useful deferred features or weakening stable APIs and safety gates.

Label evidence as **local/static**, **local live**, or **cloud/provider live**. Only the last category can close the corresponding production/RSA gate.

## Copy-ready continuation prompt

```text
Resume the phishing-awareness-platform build in
/Users/edierks/projects/codex-test/phishing-awareness-platform.
Read AGENTS.md, RESUME-HERE.md, docs/WAVE-BUILD-PLAN.md,
docs/PRODUCTION-READINESS-TASK-MATRIX.md, docs/NEXT_SESSION_HANDOFF.md, and
docs/AI_HANDOFF.md before editing. Preserve the worktree and every
project/recovery/Docker asset; do not reset, clean, prune, delete, recreate, or
touch unrelated Docker Desktop workloads. The project-only ARM64 engine remains
on 192.168.1.140 under /Volumes/DockerExternal/KingPhisher-Phoenix.

origin/main is 6abe1a1 (Wave 38 checkpoint + ANA-010 increments + AI-010
bake-off foundation + TRN-010 campaign-bound knowledge check); the worktree
is clean. Alembic head is 0033_training_knowledge_check. Current-head gates
pass: hermetic 2,681, external PostgreSQL 92, fresh-migration 1, external
Redis 2, lint, strict mypy. The retention P1 is closed, the migration
revision-id defect is fixed, and ANA-010/TRN-010 are complete locally. Do
not reopen locally complete ORG-001, THR-001A/B, IMP-001, DOCSIM-001,
ANA-010, or TRN-010 without a regression.

Continue the goal-aligned backlog without removing useful deferred features:
ANA-010 and TRN-010 are complete locally (ledger graph, named disposition,
repeat history, named per-recipient pseudonymous drill-down; campaign-bound
knowledge check with deterministic evidence builder, digest pinning, and
generic quiz fallback), and the AI-010 path is nearly complete: the bake-off
foundation has landed (`scripts/ai-bakeoff/`), the generation worker
enforces a pinned model identity (`KP_WORKER_AI_MODEL_ID`, constant-time
compare, fail-closed in managed mode) with cost/status metrics, and DEP-010's
strong-defaults + Advanced-field classification has landed (azure-deployment
wizard collapses resource-ID/GitHub/Terraform internals and seeds suggested
defaults). The remaining items that need an external environment (no offline
build remains): benchmark/select the actual model against the bake-off set and
deploy the pinned llama.cpp image/endpoint, then browser-login discovery with
live progress/cost/rollback qualification for DEP-010. AI may draft/advise but
never approve, target, apply infrastructure, handle consent, or launch.
Prefer simplicity and the existing three-deployable modular-monolith
architecture.

Do not claim production/RSA readiness: current-head external E2E, exact-final
ARM64 images, AMD64/registry, browser/WCAG, Azure/Entra/Graph/ACS/Outlook/DNS/
inbox, recovery, audit witness, and human acceptance remain NO-GO.
```
