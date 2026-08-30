# Next-session handoff

## Addendum 2026-08-30 (post-Wave-38)

- First immutable release-image publication into the production ACR
  `atprodcuprodacr.azurecr.io` was performed and the registry hardening was
  fully reverted. Commit `b0751cd`; the four digest-pinned references and the
  exact revert are documented in `/Users/edierks/projects/codex-test/phishing-awareness-platform/RESUME-HERE.md`
  (ACR section). Amazon-subscription renewal unblocked management plane, but
  the push still required operator-approved temporary opening (no `AcrPush`,
  private-only network, disabled exports) that was reverted after push.
- Live E2E (loopback Mailpit + full `supervisor.py` stack) passes 6/7 console
  smoke + 1/1 canary on a fresh seed. Two genuine findings were documented in
  `RESUME-HERE.md`: a `sync-directory` 503 (audit-outbox dispatch under the
  live stack, `AuditFailureError` / `post_commit_outbox_dispatch_failed`) and
  order-dependence when both `tests/e2e` files share one seeded DB.
- `connection_probes.py` dev-loopback allowlist fix landed (`b0751cd`) so the
  live SMTP probe passes; new test
  `apps/operator-api/tests/test_connection_probe_loopback.py` is 7-passing.
- 2026-08-30 (post-b0751cd): current-head re-verification is green and clean —
  AZ-030 static orchestration suite `114 passed`
  (`apps/operator-api/tests/test_deployment_orchestration.py`) and the read-only
  live Azure smoke `test_live_azure_cli_can_read_selected_subscription` PASSED
  against the renewed/enabled subscription `169644fd-…`.
- **ANA-010 per-recipient GUI drill-down landed (`fae8929`).** The ledger view
  now offers a capability-gated (on `view_named`) per-recipient history: masked
  recipient selector (first 500 authorized records) or a 36-char recipient-id
  entry, a pseudonym-free bounded table of ledger outcome facts, and a
  capability-gated CSV export. It also fixed a latent `downloadApiCsv` bug that
  required `/analytics/campaigns/` only and silently rejected every
  `/analytics/ledger/` CSV download (trend/repeats/recipient history); the
  guard now allows the exact `/analytics/` export prefix. Pinned by
  `apps/operator-api/tests/test_analytics_ledger_drilldown_ui_contract.py`
  (4 tests); hermetic **2707** passed, lint clean. Only ANA-010 key
  rotation/recovery remains governed follow-up.
- **Operator-required blocker (2026-08-30): the full AZ-030 promotion is
  operator-only.** `scripts/azure_bootstrap.sh` refuses invented values: *"Do not
  invent those reviewed values by hand. A direct command is not equivalent to the
  GUI's review digest, source-drift check, audit record, or protected-environment
  preflight, and is never production/RSA evidence."* The reviewed non-secret
  deployment plan must be filled in the console Deployment GUI (Entra tenant id,
  two hostnames, customer-managed ACS sender + reviewed quota/pacing, recipient
  allowlist, `network_mode`), which alone creates the opaque request id, canonical
  `deployment_config`, and reviewed-commit binding. Only then can the live
  (mutating) bootstrap/release run — with a further operator confirmation before
  any cloud mutation. This is the single path that promotes AZ-030 and unblocks
  OBS-036. The other NO-GO gates (DEP-010 browser sign-in, WCAG walkthrough,
  native AMD64 engine, PROD-030 human decision) are likewise operator/human/
  engine-owned. An agent has no further low-risk step that advances a
  production/RSA gate until at least AZ-030 is operator-completed.

## Start here

Repository: `/Users/edierks/projects/codex-test/phishing-awareness-platform`

Target engineering worker: `edierks@192.168.1.140`. Its canonical source is
`/Users/edierks/Projects/kingphisher-phoenix`, mounted read-only inside the
project-only native ARM64 Colima profile `kingphisher`; external VM/cache/client
state and the socket are rooted at
`/Volumes/DockerExternal/KingPhisher-Phoenix` on the attached 1 TB drive.
External preflight/restore passed; final exact preflight reported approximately
744,006,440 KiB free. The inactive `kp-external-mac` context is
created with endpoint
`ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`
and reports `colima-kingphisher|aarch64|/var/lib/docker`, while the
default remains `desktop-linux`; the seven internal Docker Desktop project
containers are stopped/preserved and unrelated containers remain running. The global remote context remains
`desktop-linux`; unrelated workloads must not be changed. External
mount/UUID/read-only-source/capacity drift blocks instead of falling back. The
canonical operating procedure is
`scripts/operator/remote-docker-worker/README.md`; current Wave 38 status is in
`docs/PRODUCTION-READINESS-TASK-MATRIX.md`.
The legacy Docker contexts `DockerExternal` and `kp-remote-mac` omit the
reviewed socket path and can select shared Docker Desktop; never use them for
project work. The external volume named `DockerExternal` is storage, not a
Docker context. Rosetta/binfmt are disabled and unnecessary for native ARM64.

The controller recovery identity is verified at public recipient
`age1p9t25wm9uvcaafjv3hjmgsj092mgydrr9uzndjnmcq9psupfl94qm8h2w2`.
Because headless SSH cannot unlock the remote Keychain, use
`checkpoint-remote.sh` for its temporary identity transfer/cleanup. After an
applied checkpoint, controller `stage-remote.sh` must invoke remote
`stage-checkpoint.sh` with a second bounded transfer, validate the exact archive, and
no-clobber publish `migration-checkpoint/` before external-engine-scoped
`restore-state.sh`. Snapshot `20260829T013332Z-tsX1WQ`, archive SHA-256
`e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`,
passed that chain and external restore, so `EXT-002` is complete. External
installation and `verify_install.sh` passed as well.

The installer timeout repair is locally integrated and validated by 42 tests:
default 900 seconds, maximum 3600, and strict parsing. It is synced and remote
`--check-uv` passed; no cold full rerun under the new default is claimed.

The pre-remediation local and external integrated QA snapshot passed:
operational readiness reached exact head `0029`; hermetic 2,329 passed/97
deselected; PostgreSQL 86 passed/2,340 deselected while isolated on Redis DB14;
Redis 2 passed/2,424 deselected on DB15; audit and `verify_install.sh` passed;
and E2E passed all 8. Its 03Z API/worker log window contained no error/critical
event or unknown-campaign/unknown-pattern job. Ruff/format, strict mypy over 124
source files, Bandit, Semgrep, Trivy source checks, dependency audit,
Actionlint, and Zizmor were green within their recorded scopes. The pre-Wave-36
local hermetic `make test` passed 2,469 tests/97 deselected with 0 failures in
158.15 seconds. The final local Wave 36 hermetic suite at checked-in head
`0030_default_privacy_notice` passed 2,501 tests/97 deselected with 0 failures
in 183.40 seconds. Ruff/format covered 336 Python files; mypy covered 124 source files;
Bandit, Semgrep (4 rules/125 targets/0), Trivy repository scans (0
HIGH/CRITICAL vulnerabilities, secrets, or misconfigurations), pip-audit,
Actionlint, and Zizmor passed in their recorded scopes. PostgreSQL, Redis, and
Current-head `0033` external PostgreSQL/Redis/E2E and exact-image evidence remain pending. Release remains NO-GO for live
Azure/provider, real-browser/WCAG and human assistive-technology, exact-final
image/native AMD64/registry attestation, and rollback evidence.

The authoritative continuation record is [the integrated build plan](WAVE-BUILD-PLAN.md). Do not rely on old commit lists or copied test counts in handoff documents. Begin by preserving the shared worktree, then read:

1. `docs/WAVE-BUILD-PLAN.md`
2. `docs/architecture/README.md`
3. `docs/AI_HANDOFF.md`
4. `README.md`
5. `docs/AZURE_DEPLOYMENT.md` for deployment work

### Wave 38 paused checkpoint

The product is for one 125-person tenant operated by two IT staff. The
authoritative new-work priority is the goal-aligned policy in the build plan;
historical waves remain evidence, not permission to expand scope. Deferred
features remain retained and supported but receive no expansion slot. Never
delete potentially valuable behavior simply because it is deferred.

- `ORG-001` is complete locally: creator plus one independent approver holding
  both approval capabilities. Security and privacy remain separate recorded
  facets; RoE, frozen audience, canary, provider evidence, immutable review,
  emergency stop, and every other safety gate remain.
- `THR-001A` and `DOCSIM-001` are complete locally with evidence-fidelity and
  recipient-bound ICS behavior; their focused closure passed 150 tests.
- `IMP-001` is complete locally with guided arbitrary-header CSV preview/apply,
  digest-bound mapping/options, skip/update merge, optional soft-deactivation,
  and transaction-serialized writes that return a safe re-preview `409` on
  concurrency loss.
- `THR-001B` is complete locally with a bounded Threat Campaigns workbench,
  daily governed ingestion, default quarantine, explicit audited activation to
  one draft pattern basis, and source/terms/provenance rechecks at activation,
  approval, rejection/duplicate handling, and generation.
- `OUT-001`/`RET-005`/`INT-001` retention integration is complete locally at
  Alembic head `0033_training_knowledge_check`: terminal-only locked
  project-before-purge, stable pseudonym configuration, retention-only grants,
  current outcome-writer locking, 365-day raw maximum, and 1,826-day PII-free
  ledger are wired. Privacy/RBAC, named-history API, reporting, graph, and export
  consumers remain open.
- The retained P1 is closed: `RetentionPolicy.__table_args__` mirrors migration
  `0032`'s retention-day check and single-default partial unique index, with
  metadata/database tests. The current-head gate additionally fixed the
  migration revision-id overflow so fresh databases can reach head `0032`.
- The checkpoint (`d25313d`) and every increment through the DEP-010
  strong-defaults/Advanced classification are committed and pushed;
  `origin/main` is `95cbc81` (review/CSP/A-drift/provider/chart waves landed,
  incl. `506b716`, `4ac0e9a`, `dc53688`, `93d33c0`, `95cbc81`). Current-head
  hermetic 2,694/103, external PostgreSQL 92, and external Redis 2 pass on
  2026-08-29; E2E, image, browser, and cloud gates remain open.
- The offline-buildable backlog is complete. ANA-010 (ledger graph, named close
  disposition, repeat history, per-recipient pseudonymous drill-down), TRN-010
  (campaign-bound knowledge check with deterministic evidence builder, digest
  pinning, generic quiz fallback), the AI-010 worker pinned-model enforcement
  (`KP_WORKER_AI_MODEL_ID` + cost/status metrics), and DEP-010 strong
  defaults/Advanced classification are all landed and pushed. Every remaining
  item needs an external environment: the internal-model benchmark/selection
  and pinned `llama.cpp` deployment (live loopback llama.cpp endpoint), then
  browser-login discovery with live progress/cost/rollback qualification, then
  the qualification lanes.

Use the copy-ready continuation prompt in `RESUME-HERE.md` verbatim when
starting the next build session.

The AI target is internal-model-first: benchmark two or three small
permissively licensed models, pin the chosen `llama.cpp` runtime/weights in the
existing worker role/job, and try CPU first. Scale-to-zero serverless GPU is
conditional on measurements; Foundry serverless/token inference is optional.
Do not add Foundry managed compute or an always-on GPU. `.140` remains
development/qualification infrastructure only.

## Current outcome

The codebase has moved from an eight-worker, development-auth, all-active-recipient prototype toward the intended simple architecture:

- three managed deployables by default: operator, tracking/training, and one multi-role worker;
- Entra-compatible OIDC and separated managed identities/database roles;
- exact audience preview and frozen manifests;
- crash-aware delivery claims and provider correlation;
- opaque tracking and training bearers with keyed verifiers at rest;
- token-bound lessons, completion, reminders, and training metrics;
- persistent emergency stop;
- a durable launch review and locked test-account cohort: schedule sends only
  the canary, and the separate full-publication action requires current
  server-derived provider/config evidence (authenticated delivered receipts
  for ACS);
- atomic queue transitions and GUI/API dead-letter operations;
- transactionally staged audit/queue intent with a database-owned audit dispatcher;
- a locally permission-tested create-only audit witness targeting locked Azure Blob storage;
- Microsoft Graph directory preview/apply and Microsoft 365 reported-message ingestion;
- ACS custom-domain readiness, pacing, provider correlation, and an Entra-authenticated, privacy-minimized Event Grid receipt pipeline; live subscription/receipt behavior remains unqualified.
- checked-in Alembic head `0033_training_knowledge_check`; `0031` adds the confirmed-interaction/PII-free 1,826-day ledger foundation, `0032` requires explicit re-review of legacy automatically active source evidence while enforcing migrated retention bounds/default uniqueness, and `0033` adds the optional all-or-nothing campaign-bound knowledge check (question + bounded distinct options + correct-answer index) with digest pinning and CHECK constraints. The current-head external PostgreSQL profile passed 92 tests on 2026-08-29 (fresh/historical migration, retention concurrency, outcome-writer-versus-retention, grants); the historical 86-test result at `0029` is superseded;
- a finite 2–12 occurrence Program Planner with allowlisted elapsed-day cadence, independent drafts, exact UTC review, duplicate-safe creation, and forward-only pause/resume;
- denominator-explicit single-campaign analytics plus bounded longitudinal Executive Trends JSON/CSV/GUI;
- retirement of shared-secret tracking corrections as an HTTP 410/no-write boundary, with the obsolete runtime/Terraform secret removed; normalized dual-reviewed corrections remain deferred;
- content-library route modularization and bounded unexpected-error logging, while broader god-file decomposition remains.
- capability-aware console session validation, navigation, and actions that fail closed on invalid or stale server-derived authority;
- authorized, audited, repeatable source enable/disable/manual-ingest operations in the backend and GUI; a post-fetch locked state check discards fetched material before writes when disable wins, while `job_id` remains only a request reference;
- bounded failure logging at 21 former production traceback/exception-message sites across worker/outbox/supervisor and audit/scheduler/rate-limiter paths, preserving behavior without exposing exception text or tracebacks;
- fixed-code durable queue failure state (`queue_dispatch_failed`) and stable allowlisted operator/auth/analytics public error boundaries;
- explicit no-skip hermetic, PostgreSQL, Redis, local-E2E, and Azure-live profiles, with operational readiness running the applicable local gates only after fail-fast disk/Docker/Compose/service checks and without printing connection URLs;
- PostgreSQL test jobs isolated on Redis DB14 with only DB14 flushed before/after that profile; the Redis queue contract isolated on DB15; application DB0 never used as a test cleanup target;
- a public tracking boundary that caps/validates request targets and streamed/declared bodies, accepts forwarding only from a direct peer in validated `TRACKING_API_TRUSTED_PROXIES`, resolves a bounded canonical `X-Forwarded-For` chain right-to-left, stamps privacy/security headers on early exits, and returns stable non-reflective errors. Managed Azure derives the exact proxy set from the Container Apps infrastructure subnet plus loopback and disables Uvicorn proxy rewriting;
- purpose- and assignment-bound lure, lesson-open, completion, and reminder links; generated content retains a placeholder until delivery, and static legacy awareness destinations fail closed;
- latest-request-wins directory preview fencing so an older Graph success or failure cannot overwrite or clear a newer preview;
- secret-safe operator/tracking/worker settings diagnostics and role-specific managed provider validation;
- explicit SMTP/ACS and Mailpit/Microsoft 365 GUI provider selects with conditional active-field validation, warning-only ACS reachability at an exact runtime origin, one quoted/bounded Graph delta probe, active non-secret setup-assist context, and validation-before-atomic credential rebinding;
- privacy export by authenticated `POST`, `private, no-store` privacy list/export responses, same-origin CSRF enforcement for cookie mutations, and independent notice/request loading so a notice failure warns without disabling request operations; plus issuer-origin-bound OIDC whose DNS-pinned transport preserves TLS Host/SNI while refusing redirects, proxy inheritance, HTTP/2, and cross-origin navigation or secret transmission;
- a preserved optional non-local HTTPS gateway adapter implementing `/propose` and `/setup-assist`; it is no longer the supported default AI deployment target. Pattern approval records a durable generation request without claiming asynchronous queue/provider completion, and the internal-model worker path plus live AI qualification remain open;
- a reviewed three-stage Azure workflow/Terraform/API/GUI path: `foundation_bootstrap` applies the complete `deploy_workloads=false` foundation, including ACR/private-network/data and ACS/DNS resources, without Terraform targets; it initiates four verification types while explicitly forbidding sender/association changes. `foundation_finalize` requires fresh all-four Verified state and post-apply association/sender proof; `workloads` revalidates exact resources and immutable images, then requires exactly one active Healthy/Provisioned worker revision, two consecutive simultaneous ready observations for every enabled role, and a same-revision final health recheck. Every stage refuses delete/replacement plans. The GUI rejects manual readiness claims, resumes/advances digest-bound plans, validates/displays final artifact evidence, and exports the same exact ACS endpoint contract enforced by API/Terraform/preflight. The connector is pinned to workflow SHA-256 `6868067ef5d58c799bc4a07dd832d4852d38dee73e6ff1af9a58c701ce85a4d3`; no stage is live-qualified;
- removal of four uncalled/unexported helpers (`monotonic_timestamp`, `build_email_body`, `parse_sending_domains`, and `SafetyValidatorError`), reducing production code by 35 lines without changing behavior;
- local operator HSTS and release-readiness contracts that deliberately do not claim a qualified production edge, WAF, custom-host observation, rollback, or restore.
- immutable local Compose/mock base-image references, a hash-verified 17-package mock runtime, frozen normal workspace bootstrap/development/console use, a native CycloneDX 1.5 inventory with 59 total components/58 external PURLs, and a fail-closed zero-known-vulnerability audit of the 58 external packages;
- Wave 29 recovery controls: fixed Compose project and PostgreSQL/Redis volume
  names; fail-closed `.env` bootstrap when preserved state exists or cannot be
  inspected; command-specific, injection-resistant preflight environments;
  read-only `prestart` before Compose and `ready` after migration/seed; offline
  exact-cache base-image qualification; and a Redis `999:999` disposable-data
  write probe. Partial state is reconciled in place, never treated as permission
  for cleanup or a parallel volume;
- removal of public OpenAPI/Swagger/ReDoc/metrics routes and the operator/tracking write-only metric registries, while preserving bounded health/log state and worker metric snapshots; audit-scheduler retention is limited to aggregate status and problem count;
- GUI authentication-mode discovery that fails closed rather than silently defaulting to the disposable development credential;
- a versioned, key-ID-bound ciphertext format with one active and at most four prior decrypt-only keys; managed prior-key configuration is legacy/recovery-only, the first foundation fixes the active ID, active rotation is blocked, and the Terraform-generated active KEK remains in protected state/history behind `prevent_destroy`;
- official Starlette `TestClient` compatibility through the test-only `httpx2` dependency, without changing production HTTP clients.
- warning-strict SQLite lifecycle/outbox fixes, including deterministic owned-pool/test-engine disposal and explicitly typed outbox timestamps;
- an exact 113-route operator authorization manifest—103 capability-protected plus 10 dedicated/public routes—exact browser/backend capability inventory, capability-gated non-Azure actions, aggregate-reader Help, and safe preview for approve-only template reviewers;
- rejection of duplicate as well as malformed `Content-Length` at the public tracking edge;
- fail-closed exact workflow/code/test binding at frozen workflow SHA-256
  `6868067ef5d58c799bc4a07dd832d4852d38dee73e6ff1af9a58c701ce85a4d3`.
- canonical bounded generation input/output and provider streaming contracts, with queue-key idempotency across retries/races and recipient-bound delivery proof;
- current source-terms acknowledgement/revocation across API, worker fences, and GUI;
- server-side request normalization plus capped non-reflective operator/tracking validation responses;
- server-derived training-resource action flags, author/reviewer separation, locking, and fail-closed GUI controls;
- aggregate/named/export reporting separation, owner-safe alert subscriptions with outbound hostname allowlisting, audited recipient-exclusion lifecycle, and server-paginated recipient management/named reporting;
- bounded OIDC, setup-assistant, AI-generation, and GitHub deployment response readers, including no-read GitHub dispatch bodies;
- deterministic cleanup for newly added PostgreSQL fixtures.
- the current loopback Mailpit `example.com` durable-gate canary passed within the latest external 8-test E2E profile at exact head `0029`, proving exactly-once canonical template delivery across retry, recipient-bound tracking, assignment reuse, separate training purposes, knowledge-check remediation/pass/replay, and correlated reporting/audit before exact cleanup; this remains local-live rather than provider/inbox evidence;
- native-UUID outbox completion and final reconciliation of 36 stranded idempotent queue intents after fixing an audit-store owner-fallback revocation defect; the final audit chain is green. Graph/Microsoft 365/ACS-event/reported-MIME seams are hardened with an explicit ACS managed-identity client ID;
- recovered provider-backed Terraform initialization/validation; server-derived campaign/pattern action flags and bounded privacy boundaries; protected GitHub environment/workflow/run plus owner-bound Redis lease validation; and worker preflight/context/reminder/retention/dead-path repairs.
- bounded database pagination for user-facing collections plus a fail-closed 100-candidate RoE scheduling cap; explicit application/worker runtime failures in place of production `assert` guards; and shared/exclusive campaign locking that orders scoped stop against delivery. Point-in-time evidence passed 52 focused worker lifecycle/security tests in 1.30 seconds and 15 isolated PostgreSQL tests in 3.07 seconds, including 250 ms lock contention. A separate isolated migrated-PostgreSQL scoped-kill persistence test passed 1 in 2.88 seconds at `0027`, then dropped its disposable database; the exploratory ACS pacing fence reserved 3 then 0 in one window.
- removal of the broken installed `kp-seed` wrapper, ignored reminder/Mailpit-TLS/queue-prefix settings, and remote full-stack stop routing/capability/marker handling from the browser, supervisor, and launcher. Source `make seed` remains, training due time remains a fixed 72-hour policy, Settings retains GUI restart, a host signal stops the launcher, and full shutdown requires OS/launcher/terminal recovery. The stop-removal lane passed 39 focused tests. `make sign` now fails closed without an immutable `IMAGE`, `COSIGN_KEY`, and `cosign`; no external signing evidence exists.

The decision remains **NO-GO for production and RSA Conference use**. The audited GitHub repository is `ELDSRQ/kingphisher-phoenix`. Local/static implementation is ahead of the live evidence. No disposable Azure deployment, real Entra role exercise, Graph/Outlook consent path, ACS custom-domain campaign, full browser accessibility pass, live-qualified external audit witness, production recovery exercise, AMD64 qualification, or registry publication/attestation has yet closed the release gate. Wave 29's local recovery contracts are not a restore or provider-live witness.

Wave 21's latest completed snapshot rebuilt all five native ARM64 images. Applicable startup/migration checks, 30 focused contracts, and scans at 0 HIGH / 0 CRITICAL vulnerabilities and 0 secrets passed. Exact IDs/sizes are in the canonical plan. Later source edits through Wave 38 make those interim images stale. The old controller free-space snapshot is historical gate evidence; external build/local-live capacity, cutover, restore, installation, and installation verification are now proven. Exact-final ARM64 status depends on the retained qualification evidence described below. AMD64/multi-architecture and registry publication/attestation remain unwitnessed.

The exact-final ARM64 result is evidence-conditional: only retained no-clobber
`qualification.json` plus scan evidence can prove the exact non-emulated Docker
server platform, explicit `--platform`, all-five OS/architecture/image-ID
metadata, unchanged source/context manifests, Trivy 0.74.0, and verified cleanup
of labeled disposable resources. The verifier additionally binds the expected
source-manifest digest and exact Trivy executable/hash/cache, retained empty config/ignore/secret policy files, rejects ambient
`TRIVY_*`, records fresh database/check-bundle metadata, and makes the verified
cache immutable. Azure workloads separately scan immutable ACR
`repository@sha256` images with pinned Trivy before SBOM/attestation/deploy and
retain scan JSON/checksums. No pass is inferred here.
The fixed planned ARM64 evidence root is
`/Volumes/DockerExternal/KingPhisher-Phoenix/qualification-evidence/arm64-release-20260829-wave35-final-v3`
with `verifier/` beneath it and unique prefix
`kingphisher/verify-arm64-20260829-w35-final-v3`; only validated retained
contents determine the gate.
The preserved `final-v2` attempt failed closed before image build on BSD
filesystem-mode and evidence-path/source-context defects. Its failure evidence
was retained; those bugs are repaired for `final-v3`, which remains conditional
until its no-clobber qualification and per-image scan/checksum evidence validate.

Historical and overlapping focused evidence remains labeled in the canonical plan. Wave 21 added green installation verification and a strict 7 passed/0 skipped/0 warning local E2E run in 3.37 seconds after targeted bootstrap/audit, token-key, PID/log, mock Graph, and fixture repairs. RoE/RBAC hardening passed 374 owned/consumer tests plus static/security/offline package gates. Its 23 workflow tests, Actionlint, and Zizmor passed at the historical Wave 21 SHA, not the current frozen connector. Removing the dead clone adapter reduced the tree by 87 lines and passed 36 focused plus 5 downstream tests. These counts are separate and must not be summed.

The earlier operational-readiness interruption remains historical. Its pre-Wave-30 result was 1,994 hermetic, 87 PostgreSQL, 2 Redis, and 8 E2E tests; the intermediate external 2,230/86/2/8 result is also superseded. The 2,329 hermetic/97 deselected, 86 PostgreSQL/2,340 deselected at exact head `0029` using Redis DB14, 2 Redis/2,424 deselected on DB15, and 8 E2Es plus audit/install result is now a pre-remediation snapshot. The pre-Wave-36 local hermetic result is 2,469 passed/97 deselected, 0 failures in 158.15 seconds. The final local Wave 36 hermetic suite at historical head `0030` passed 2,501/97 deselected with 0 failures in 183.40 seconds; current-head `0032` PostgreSQL/Redis/E2E external profiles remain pending. Earlier controller observations at about 5.9 and 5.6 GiB remain dated proof that the 8 and 10 GiB gates stopped safely. External capacity and restore are proven; browser, exact-final image, provider-live, recovery, and witness qualification remain open.

The historical 2026-08-28 Azure inspection confirmed the selected subscription/tenant, subscription Owner authority, `eastus2`, required provider readiness including `Microsoft.Communication`, and absence of a Terraform backend, foundation resource group, platform Entra applications, and application resources. The 2026-08-29 sandboxed re-audit could prove only an enabled cached account because DNS could not resolve `management.azure.com`; current management-plane state is therefore unverified. The live GitHub re-audit proves valid `ELDSRQ` authentication with `repo`/`workflow` scopes; a public, enabled repository with default `main`; Actions enabled; and the Azure workflow active, with no billing-disabled run signal. It also proves zero environments, variables, secrets, rulesets, and workflow runs, unprotected `main`, disabled secret scanning and push protection, and remote `main` at old-tree SHA `1403d944a40214714b6cbfcf5cbabc4fa7225eb9` at re-audit time; the checkpoint push has since advanced remote `main` to `c9ea716`. The connector's protected-environment/workflow/run validation and Redis lease behavior pass locally, but no workflow dispatch/run or Azure apply occurred. The next cloud step requires reviewed final-source sync plus protected environment/reviewers, variables, secrets, branch protection/rulesets, repository secret protections, revalidated Azure state, and backend/bootstrap inputs before any of the three deployment stages can run.

## Do not regress

- Do not restore a shared password/JWT as managed identity, all-active targeting, reusable stored token hashes, eight Azure worker applications, disconnected tokenless training, Mailpit-only Microsoft 365 behavior, or provider acceptance as delivered mail.
- Do not give runtime applications a database administrator URL, all-vault access, audit-root access, or direct audit-table mutation.
- Do not let AI apply state, handle secrets, select audiences, approve content, or weaken deterministic gates.
- Do not automatically retry `INDETERMINATE` mail sends.
- Do not expand a frozen audience after a directory change.
- Do not describe static Terraform/tests as live Azure or provider evidence.
- Do not restore the retired shared-secret `/v1/corrections` write path or silently subtract scanner/bot activity from observed analytics.
- Do not claim that source disable aborts provider I/O. Preserve the post-fetch lock/refetch fence that discards fetched material before writes when disable wins, and do not present an ingestion `job_id` as a status endpoint.
- Do not log or persist exception messages or tracebacks in worker/outbox failure paths; preserve bounded event/type logs and the fixed durable failure code.
- Do not restore `TRACKING_API_CORRECTIONS_SECRET`, the Terraform corrections secret, or any authentication/write behavior on the retired 410 endpoint.
- Do not reflect arbitrary backend exception text through operator/auth/analytics responses; keep public errors stable and allowlisted.
- Do not merge live PostgreSQL, Redis, E2E, or Azure tests into the hermetic profile or permit skips in a claimed gate.
- Keep PostgreSQL integration queues on DB14 and flush only DB14 before/after that profile; keep the Redis contract on DB15; never flush or repurpose application DB0.
- Do not restore a static training destination in generated or delivered lure content. Preserve placeholder-to-tracking-click resolution and distinct assignment-bound open/completion purposes.
- Do not remove the directory `last_job_key`/configuration recheck around provider I/O; stale successes and failures must remain `superseded`.
- Do not weaken public tracking target/body limits, duplicate/malformed `Content-Length` rejection, proxy trust, all-response security headers, or exception translation.
- Do not let configuration validation render secret inputs or nested exception chains, and do not make managed workers require unrelated provider settings.
- Do not restore public OpenAPI/docs/metrics routes, raw audit-problem retention, or a browser fallback from failed auth-mode discovery to development authentication.
- Do not mutate the workspace lock during normal bootstrap, development, or console launch; keep local image digests and mock dependency hashes immutable, and keep dependency audit/SBOM scoped to the full external production closure.
- Do not present managed legacy/recovery keys as active rotation. Preserve the post-foundation immutable active ID and `prevent_destroy`; do not retire a prior key until a separately reviewed bulk rewrite/proof establishes that no required ciphertext needs it.
- Do not collapse the three Azure dispatches. Initial foundation, live-verified sender-finalization foundation, and workloads each retain their saved-plan/delete-replacement/fresh-evidence/image/source gates. Never trust operator-entered ACS readiness strings or timestamps.
- Do not change the fixed Compose project/volume identities or generate critical
  `.env` credentials when preserved state exists or cannot be inspected. Keep
  subprocess environments command-specific, preserve exact cached images, run
  `prestart` before Compose and `ready` after migration/seed, and reconcile from
  checkpoints/evidence. Never prune, delete, reset, recreate, rename, or blindly
  redispatch to recover.
- Do not run `.140` project Docker commands without proving the exact external
  mount, profile, socket, and canonical source. Never change the global context
  or mutate the shared Docker Desktop engine/unrelated workloads. Preserve the
  internal project source and encrypted snapshots. The internal seven-container
  copy is stopped/preserved after checkpoint/external verification, and the legacy
  encrypted snapshot is unrecoverable because its identity is absent.
- Do not send external email or alter real Azure/Microsoft resources without the authority and safety controls required by the active task.

## Recommended continuation

Follow the alignment sequence. First close the single ORM retention-metadata P1,
run the complete local and current-head PostgreSQL gates, reconcile evidence,
then commit and push the preserved checkpoint to `main`. Next finish the
privacy/RBAC/API/reporting/graph consumers around the `0032`
outcome/retention/interaction foundation, then benchmark and pin the
internal model in the existing worker and complete the minimum Threats → safe
draft → campaign-specific training → named five-year result loop. Then simplify
the GUI deployment/mail path while preserving the current provider adapters and
three-stage fail-closed Azure contract. Finally qualify the exact stable tree:
current-head external profiles, exact ARM64 and native AMD64/registry images,
browser/WCAG, disposable Azure, Entra/Graph/ACS/Event Grid/Outlook/DNS/inbox,
backup/restore, recovery/rotation, external audit witness, and human operation.
Navigation/module simplification follows stable core behavior; deferred useful
features remain supported without expansion.

For any handoff, record evidence in the build plan using these labels:

- **local/static** — code, tests, migrations, Terraform validation, scanners, images;
- **local live** — disposable local PostgreSQL/Redis/APIs/workers/Mailpit;
- **cloud/provider live** — Azure, Entra, Graph, ACS, Outlook, browser, backup/restore, and recovery in the intended environment.

Only cloud/provider-live evidence can close the corresponding production gate.
